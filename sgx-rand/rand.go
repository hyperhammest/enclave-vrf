package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"io/ioutil"
	"os"
	"sync"

	"github.com/edgelesssys/ego/ecrypto"
	"github.com/smartbch/egvm/keygrantor"
	vrf "github.com/vechain/go-ecvrf"
	tmtypes "github.com/tendermint/tendermint/types"
)

// #include "util.h"
import "C"

type vrfResult struct {
	PI   string
	Beta string
}

var listenURL string
var keyGrantorUrl string

var randClient *keygrantor.SimpleClient

var blockHash2Beta = make(map[string][]byte)
var blockHash2PI = make(map[string][]byte)
var blockHash2Timestamp = make(map[string]int64)
var blockHashSet []string
var lock sync.RWMutex
var intelCPUFreq int64

const (
	maxBlockHashCount = 5000
	serverName        = "SGX-VRF-PUBKEY"
	// IntelCPUFreq /proc/cpuinfo model name
	keyFile      = "/data/key.txt"
	delayMargin  = 4
)

type Headers struct {
	LastHeader tmtypes.Header `json:"last_header"`
	CurrHeader tmtypes.Header `json:"curr_header"`
}

func getDelay(headers Headers, blkHash []byte) int64 {
	hash := headers.CurrHeader.Hash()
	if !bytes.Equal(hash, blkHash) {
		return -1
	}
	hash = headers.LastHeader.Hash()
	if !bytes.Equal(hash, headers.CurrHeader.LastBlockID.Hash) {
		return -1
	}
	return (headers.LastHeader.Time.UnixNano() - headers.LastHeader.Time.UnixNano()) / 1e9 + delayMargin
}

// start slave first, then start master to send key to them
// master must be sure slave is our own enclave app
// slave no need to be sure master is enclave app because the same vrf pubkey provided by all slave and master owned, it can check outside.
func main() {
	intelCPUFreq = int64(C.getFreq())
	initConfig()
	randClient = &keygrantor.SimpleClient{}
	_, err := os.ReadFile(keyFile)
	if err != nil {
		if os.IsNotExist(err) {
			randClient.InitKeys(keyGrantorUrl, [32]byte{}, false)
			fmt.Printf("get enclave vrf private key from keygrantor, its pubkey is: %s\n", hex.EncodeToString(randClient.PubKeyBz))
			sealKeyToFile()
		} else {
			panic(err)
		}
	} else {
		randClient.InitKeys(keyFile, [32]byte{}, true)
	}
	handlers := make(map[string]func(w http.ResponseWriter, r *http.Request))
	handlers["/blockhash"] = func(w http.ResponseWriter, r *http.Request) {
		if len(randClient.PubKeyBz) == 0 {
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
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Invalid BlockHash"))
			return
		}

		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("failed to read request body"))
			return
		}
		var headers Headers
		err = json.Unmarshal(body, &headers)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("failed to unmarshal headers"))
			return
		}
		
		delay := getDelay(headers, hashBytes)

		if delay <= 0 {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Invalid Headers"))
		}

		beta, pi, err := vrf.Secp256k1Sha256Tai.Prove(randClient.PrivKey.ToECDSA(), hashBytes)
		if err != nil {
			fmt.Printf("do vrf failed: %s\n", err.Error())
			w.Write([]byte(err.Error()))
			return
		}
		blockHash2Beta[blkHash] = beta
		blockHash2PI[blkHash] = pi
		blockHash2Timestamp[blkHash] = getTimestampFromTSC() + delay
		blockHashSet = append(blockHashSet, blkHash)
		clearOldBlockHash()
		fmt.Printf("%v sent block hash to me %v\n", r.RemoteAddr, r.URL.Query()["b"])
	}
	handlers["/vrf"] = func(w http.ResponseWriter, r *http.Request) {
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
		if vrfTimestamp > getTimestampFromTSC() {
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
	}
	go randClient.CreateAndStartHttpsServer(serverName, listenURL, handlers)
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

func getTimestampFromTSC() int64 {
	cycleNumber := int64(C.get_tsc())
	return cycleNumber / intelCPUFreq
}

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

func sealKeyToFile() {
	out, err := ecrypto.SealWithUniqueKey(randClient.PrivKey.Serialize(), nil)
	if err != nil {
		panic(err)
	}
	err = os.WriteFile(keyFile, out, 0600)
	if err != nil {
		panic(err)
	}
}
