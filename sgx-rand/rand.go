package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	secp256k1 "github.com/btcsuite/btcd/btcec"
	"github.com/edgelesssys/ego/ecrypto"
	"github.com/edgelesssys/ego/enclave"
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
var slaves []string
var slaveUniqueIDs [][]byte
var vrfPubkey []byte //compressed pubkey
var vrfPrivKey *secp256k1.PrivateKey

var blockHash2Beta map[string][]byte = make(map[string][]byte)
var blockHash2PI map[string][]byte = make(map[string][]byte)
var blockHash2Timestamp map[string]uint64 = make(map[string]uint64)
var blockHashSet []string
var lock sync.RWMutex

var keyFile = "/data/key.txt"

var signer []byte
var isMaster bool

const serverName = "SGX-VRF-PUBKEY"
const attestationProviderURL = "https://shareduks.uks.attest.azure.net"

// start slave first, then start master to send key to them
// master must be sure slave is our own enclave app
// slave no need to be sure master is enclave app because the same vrf pubkey provided by all slave and master owned, it can check outside.
func main() {
	initConfig()
	recoveryPrivateKeyFromFile()
	go createAndStartHttpsServer()
	time.Sleep(time.Second)
	if isMaster {
		go slaveHandshake()
	}
	select {}
}

func initConfig() {
	isMasterP := flag.Bool("m", false, "is master or not")
	listenURLP := flag.String("l", "0.0.0.0:8082", "listen address")
	signerArg := flag.String("s", "", "signer ID")
	slaveString := flag.String("p", "", "slave address list seperated by comma")
	slaveUniqIDArgs := flag.String("u", "", "slave unique id seperated by comma")
	flag.Parse()
	isMaster = *isMasterP
	listenURL = *listenURLP
	fmt.Println(isMaster)
	fmt.Println(listenURL)
	// get slaves
	if *slaveString != "" {
		slaves = strings.Split(*slaveString, ",")
	}
	if *slaveUniqIDArgs != "" {
		slaveUniqueIDStrings := strings.Split(*slaveUniqIDArgs, ",")
		for _, str := range slaveUniqueIDStrings {
			id, err := hex.DecodeString(str)
			if err != nil {
				panic(err)
			}
			slaveUniqueIDs = append(slaveUniqueIDs, id)
		}
	}
	if !isMaster && len(slaves) != 0 {
		panic("slave should has no slaves")
	}
	if len(slaveUniqueIDs) != len(slaves) {
		panic("number of slave address not match number of slave uniqueID")
	}
	if isMaster {
		// get signer command line argument
		var err error
		signer, err = hex.DecodeString(*signerArg)
		if err != nil {
			panic(err)
		}
		if len(signer) == 0 {
			flag.Usage()
			return
		}
	}
}

func slaveHandshake() {
	for i, slave := range slaves {
		verifySlaveAndSendKey(slave, slaveUniqueIDs[i])
	}
}

func verifySlaveAndSendKey(slaveAddress string, uniqID []byte) {
	certBytes := utils.VerifyServer(slaveAddress, signer, uniqID, verifyReport)

	// Create a TLS config that uses the server certificate as root
	// CA so that future connections to the server can be verified.
	if len(vrfPubkey) != 0 {
		cert, _ := x509.ParseCertificate(certBytes)
		tlsConfig := &tls.Config{RootCAs: x509.NewCertPool(), ServerName: serverName}
		tlsConfig.RootCAs.AddCert(cert)

		utils.HttpGet(tlsConfig, "https://"+slaveAddress+fmt.Sprintf("/key?k=%s", hex.EncodeToString(vrfPrivKey.Serialize())))
		fmt.Printf("send key to slave:%s passed\n", slaveAddress)
	}
}

func generateRandom64Bytes() []byte {
	var out []byte
	var x C.uint16_t
	var retry C.int = 1
	for i := 0; i < 64; i++ {
		C.rdrand_16(&x, retry)
		out = append(out, byte(x))
	}
	return out
}

func verifyReport(reportBytes, certBytes, signer, uniqueID []byte) error {
	report, err := enclave.VerifyRemoteReport(reportBytes)
	if err != nil {
		return err
	}
	return utils.CheckReport(report, certBytes, signer, uniqueID)
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

	if !isMaster {
		http.HandleFunc("/key", func(w http.ResponseWriter, r *http.Request) {
			fmt.Printf("%v sent key to me\n", r.RemoteAddr)
			if len(vrfPubkey) != 0 {
				return
			}
			keys := r.URL.Query()["k"]
			if len(keys) == 0 {
				return
			}
			key := keys[0]
			keyBytes, err := hex.DecodeString(key)
			if err != nil {
				return
			}
			priv, pubkey := secp256k1.PrivKeyFromBytes(secp256k1.S256(), keyBytes)
			vrfPrivKey = priv
			vrfPubkey = pubkey.SerializeCompressed()
			sealKeyToFile()
			return
		})
	}

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

func recoveryPrivateKeyFromFile() {
	fileData, err := os.ReadFile(keyFile)
	if err != nil {
		fmt.Printf("read file failed, %s\n", err.Error())
		if os.IsNotExist(err) {
			// maybe first run this enclave app
			if isMaster {
				generateVRFPrivateKey()
			}
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

func generateVRFPrivateKey() {
	priv, _ := secp256k1.PrivKeyFromBytes(secp256k1.S256(), generateRandom64Bytes())
	vrfPrivKey = priv
	vrfPubkey = vrfPrivKey.PubKey().SerializeCompressed()

	fmt.Printf("generate enclave vrf private key, its pubkey is: %s\n", hex.EncodeToString(vrfPubkey))
	sealKeyToFile()
	return
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
