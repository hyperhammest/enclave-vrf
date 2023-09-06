package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	secp256k1 "github.com/btcsuite/btcd/btcec"
	"github.com/edgelesssys/ego/ecrypto"
	"github.com/edgelesssys/ego/enclave"
	"github.com/smartbch/egvm/keygrantor"
	vrf "github.com/vechain/go-ecvrf"

	"github.com/smartbch/enclave-vrf/sgx-rand/utils"
)

// #include "util.h"
import "C"

type vrfResult struct {
	PI   string
	Beta string
}

var listenURL string
var keyGrantorUrl string
var vrfPubkey []byte //compressed pubkey
var vrfPrivKey *secp256k1.PrivateKey

var blockHash2Beta map[string][]byte = make(map[string][]byte)
var blockHash2PI map[string][]byte = make(map[string][]byte)
var blockHash2Timestamp map[string]uint64 = make(map[string]uint64)
var blockHashSet []string
var lock sync.RWMutex

var keyFile = "/data/key.txt"

const serverName = "SGX-VRF-PUBKEY"
const attestationProviderURL = "https://shareduks.uks.attest.azure.net"

// start slave first, then start master to send key to them
// master must be sure slave is our own enclave app
// slave no need to be sure master is enclave app because the same vrf pubkey provided by all slave and master owned, it can check outside.
func main() {
	initConfig()
	recoveryPrivateKeyFromFile()
	go createAndStartHttpsServer()
	select {}
}

func initConfig() {
	keyGrantorUrlP := flag.String("g", "0.0.0.0:8084", "keygrantor url")
	listenURLP := flag.String("l", "0.0.0.0:8082", "listen address")
	flag.Parse()
	listenURL = *listenURLP
	fmt.Println(listenURL)
	keyGrantorUrl = *keyGrantorUrlP
}

func generateRandom32Bytes() []byte {
	var out []byte
	var x C.uint16_t
	var retry C.int = 1
	for i := 0; i < 32; i++ {
		C.rdrand_16(&x, retry)
		out = append(out, byte(x))
	}
	return out
}

// IntelCPUFreq /proc/cpuinfo model name
const intelCPUFreq = 2800_000000

func getTimestampFromTSC() uint64 {
	cycleNumber := uint64(C.get_tsc())
	return cycleNumber / intelCPUFreq
}

func createAndStartHttpsServer() {
	// Create a TLS config with a self-signed certificate and an embedded report.
	//tlsCfg, err := enclave.CreateAttestationServerTLSConfig()
	cert, _, tlsCfg := utils.CreateCertificate(serverName)
	certHash := sha256.Sum256(cert)

	// init handler for remote attestation
	http.HandleFunc("/cert", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(hex.EncodeToString(cert))) })
	http.HandleFunc("/peer-report", func(w http.ResponseWriter, r *http.Request) {
		peerReport, err := enclave.GetRemoteReport(certHash[:])
		if err != nil {
			panic(err)
		}
		w.Write([]byte(hex.EncodeToString(peerReport)))
	})

	initVrfHttpHandlers()

	server := http.Server{Addr: listenURL, TLSConfig: &tlsCfg, ReadTimeout: 3 * time.Second, WriteTimeout: 5 * time.Second}
	fmt.Println("listening ...")
	err := server.ListenAndServeTLS("", "")
	fmt.Println(err)
}

func initVrfHttpHandlers() {
	// look up secp256k1 pubkey
	http.HandleFunc("/pubkey", func(w http.ResponseWriter, r *http.Request) {
		if len(vrfPubkey) == 0 {
			return
		}
		w.Write([]byte(hex.EncodeToString(vrfPubkey)))
		return
	})

	// not check the block hash correctness
	http.HandleFunc("/blockhash", func(w http.ResponseWriter, r *http.Request) {
		if len(vrfPubkey) == 0 {
			return
		}
		hash := r.URL.Query()["b"]
		if len(hash) == 0 {
			return
		}
		blkHash := hash[0]
		lock.Lock()
		defer lock.Unlock()

		if blockHash2Timestamp[blkHash] != 0 {
			w.Write([]byte("this blockhash already here"))
			return
		}
		hashBytes, err := hex.DecodeString(blkHash)
		if err != nil {
			return
		}
		beta, pi, err := vrf.NewSecp256k1Sha256Tai().Prove((*ecdsa.PrivateKey)(vrfPrivKey), hashBytes)
		if err != nil {
			fmt.Printf("do vrf failed: %s\n", err.Error())
			w.Write([]byte(err.Error()))
			return
		}
		blockHash2Beta[blkHash] = beta
		blockHash2PI[blkHash] = pi
		blockHash2Timestamp[blkHash] = getTimestampFromTSC()
		blockHashSet = append(blockHashSet, blkHash)
		clearOldBlockHash()
		fmt.Printf("%v sent block hash to me %v\n", r.RemoteAddr, r.URL.Query()["b"])
	})

	http.HandleFunc("/vrf", func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("%v sent block hash to get vrf %v\n", r.RemoteAddr, r.URL.Query()["b"])
		hash := r.URL.Query()["b"]
		if len(hash) == 0 {
			return
		}
		blkHash := hash[0]
		lock.RLock()
		defer lock.RUnlock()

		vrfTimestamp := blockHash2Timestamp[blkHash]
		if vrfTimestamp == 0 {
			w.Write([]byte("not has this blockhash"))
			return
		}
		if vrfTimestamp+5 > getTimestampFromTSC() {
			w.Write([]byte("please get vrf later, the blockhash not mature"))
			return
		}
		res := vrfResult{
			PI:   hex.EncodeToString(blockHash2PI[blkHash]),
			Beta: hex.EncodeToString(blockHash2Beta[blkHash]),
		}
		out, _ := json.Marshal(res)
		w.Write(out)
		return
	})

	http.HandleFunc("/report", func(w http.ResponseWriter, r *http.Request) {
		if len(vrfPubkey) == 0 {
			return
		}
		hash := sha256.Sum256(vrfPubkey)
		report, err := enclave.GetRemoteReport(hash[:])
		if err != nil {
			w.Write([]byte(err.Error()))
			return
		}
		w.Write([]byte(hex.EncodeToString(report)))
	})

	// send jwt token
	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if len(vrfPubkey) == 0 {
			return
		}
		token, err := enclave.CreateAzureAttestationToken(vrfPubkey, attestationProviderURL)
		if err != nil {
			w.Write([]byte(err.Error()))
			return
		}
		w.Write([]byte(token))
	})
}

const maxBlockHashCount = 5000

func clearOldBlockHash() {
	nums := len(blockHashSet)
	if nums > maxBlockHashCount*1.5 {
		for _, bh := range blockHashSet[:nums-maxBlockHashCount] {
			delete(blockHash2Timestamp, bh)
			delete(blockHash2PI, bh)
			delete(blockHash2Beta, bh)
		}
		var tmpSet = make([]string, maxBlockHashCount)
		copy(tmpSet, blockHashSet[nums-maxBlockHashCount:])
		blockHashSet = tmpSet
	}
}

func getKeyFromKeyGrantor() {
	outKey, err := keygrantor.GetKeyFromKeyGrantor(keyGrantorUrl, [32]byte{})
	if err != nil {
		fmt.Println("failed to deserialize the key from server")
		panic(err)
	}
	vrfPrivKey, _ = secp256k1.PrivKeyFromBytes(secp256k1.S256(), outKey.Key)
	vrfPubkey = vrfPrivKey.PubKey().SerializeCompressed()
	fmt.Printf("get enclave vrf private key from keygrantor, its pubkey is: %s\n", hex.EncodeToString(vrfPubkey))
	sealKeyToFile()
	return
}

func recoveryPrivateKeyFromFile() {
	fileData, err := os.ReadFile(keyFile)
	if err != nil {
		fmt.Printf("read file failed, %s\n", err.Error())
		if os.IsNotExist(err) {
			// maybe first run this enclave app
			getKeyFromKeyGrantor()
		}
		return
	}
	rawData, err := ecrypto.Unseal(fileData, nil)
	if err != nil {
		fmt.Printf("unseal file data failed, %s\n", err.Error())
		return
	}
	vrfPrivKey, _ = secp256k1.PrivKeyFromBytes(secp256k1.S256(), rawData)
	vrfPubkey = vrfPrivKey.PubKey().SerializeCompressed()
	fmt.Println("recover vrf keys")
}

func sealKeyToFile() {
	out, err := ecrypto.SealWithUniqueKey(vrfPrivKey.Serialize(), nil)
	if err != nil {
		panic(err)
	}
	err = os.WriteFile(keyFile, out, 0600)
	if err != nil {
		panic(err)
	}
}
