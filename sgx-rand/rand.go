package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/smartbch/egvm/keygrantor"
	tmjson "github.com/tendermint/tendermint/libs/json"
	"github.com/tendermint/tendermint/light"
	tmtypes "github.com/tendermint/tendermint/types"
	vrf "github.com/vechain/go-ecvrf"
)

// #include "util.h"
import "C"

type vrfResult struct {
	PI   string
	Beta string
	Sig  []byte
}

var listenURL string
var keyGrantorUrl string

var randClient *keygrantor.SimpleClient

type vrfInfo struct {
	Beta      []byte
	Pi        []byte
	Timestamp int64
	Height    int64
}

var blockHash2VrfInfo = make(map[string]vrfInfo)
var blockHashSet []string
var lock sync.RWMutex
var intelCPUFreq int64

var LatestTrustedHeader *tmtypes.SignedHeader

const (
	maxBlockHashCount = 5000
	serverName        = "SGX-VRF-PUBKEY"
	// IntelCPUFreq /proc/cpuinfo model name
	keyFile     = "/data/key.txt"
	delayMargin = 4000
)

type Params struct {
	UntrustedHeader tmtypes.SignedHeader  `json:"last_header"`
	Validators      *tmtypes.ValidatorSet `json:"validators"`
}

func (p Params) verify(blkHash []byte) bool {
	if !bytes.Equal(p.Validators.Hash(), p.UntrustedHeader.ValidatorsHash) {
		return false
	}
	hash := p.UntrustedHeader.Hash()
	if !bytes.Equal(hash, blkHash) {
		return false
	}
	err := light.VerifyAdjacent(LatestTrustedHeader, &p.UntrustedHeader, p.Validators, 168*time.Hour, time.Now(), 10*time.Second)
	if err != nil {
		return false
	}
	return true
}

func initLatestTrustedHeader() {
	//todo: recovery LatestTrustedHeader from file, if err hit, set LatestTrustedHeader from initial json string.
	initHeaderStr := ""
	err := tmjson.Unmarshal([]byte(initHeaderStr), LatestTrustedHeader)
	if err != nil {
		panic(err)
	}
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
	initLatestTrustedHeader()
	handlers := make(map[string]func(w http.ResponseWriter, r *http.Request))
	handlers["/height"] = func(w http.ResponseWriter, r *http.Request) {
		var height [8]byte
		binary.BigEndian.PutUint64(height[:], uint64(LatestTrustedHeader.Height))
		w.Write(height[:])
	}
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

		if blockHash2VrfInfo[blkHash].Timestamp != 0 {
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
		var params Params
		fmt.Println()
		err = tmjson.Unmarshal(body, &params)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("failed to unmarshal params"))
			return
		}

		if !params.verify(hashBytes) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Invalid Headers"))
		}

		beta, pi, err := vrf.Secp256k1Sha256Tai.Prove(randClient.PrivKey.ToECDSA(), hashBytes)
		if err != nil {
			fmt.Printf("do vrf failed: %s\n", err.Error())
			w.Write([]byte(err.Error()))
			return
		}
		blockHash2VrfInfo[blkHash] = vrfInfo{
			Beta:      beta,
			Pi:        pi,
			Timestamp: getTimestampFromTSC() + delayMargin,
			Height:    params.UntrustedHeader.Height,
		}
		blockHashSet = append(blockHashSet, blkHash)
		LatestTrustedHeader = &params.UntrustedHeader
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

		vrfTimestamp := blockHash2VrfInfo[blkHash].Timestamp
		if vrfTimestamp == 0 {
			w.Write([]byte("not has this blockhash"))
			return
		}
		if vrfTimestamp > getTimestampFromTSC() {
			w.Write([]byte("please get vrf later, the blockhash not mature"))
			return
		}
		vrfInfo := blockHash2VrfInfo[blkHash]
		res := vrfResult{
			PI:   hex.EncodeToString(vrfInfo.Pi),
			Beta: hex.EncodeToString(vrfInfo.Beta),
		}
		var vrfData []byte
		vrfData = append(vrfData, vrfInfo.Pi...)
		vrfData = append(vrfData, vrfInfo.Beta...)
		var height [8]byte
		binary.BigEndian.PutUint64(height[:], uint64(vrfInfo.Height))
		vrfData = append(vrfData, height[:]...)
		h := sha256.Sum256(vrfData)
		sig, err := crypto.Sign(h[:], randClient.PrivKey.ToECDSA())
		if err != nil {
			panic(err)
		}
		res.Sig = sig
		out, _ := json.Marshal(res)
		w.Write(out)
		return
	}
	go randClient.CreateAndStartHttpsServer(serverName, listenURL, handlers)
	select {}
}

func initConfig() {
	keyGrantorUrlP := flag.String("g", "http://0.0.0.0:8084", "keygrantor url")
	listenURLP := flag.String("l", "0.0.0.0:8082", "listen address")
	flag.Parse()
	listenURL = *listenURLP
	fmt.Println(listenURL)
	keyGrantorUrl = *keyGrantorUrlP
}

func getTimestampFromTSC() int64 {
	cycleNumber := int64(C.get_tsc())
	return cycleNumber * 1000 / intelCPUFreq
}

func clearOldBlockHash() {
	nums := len(blockHashSet)
	if nums > maxBlockHashCount*1.5 {
		for _, bh := range blockHashSet[:nums-maxBlockHashCount] {
			delete(blockHash2VrfInfo, bh)
		}
		var tmpSet = make([]string, maxBlockHashCount)
		copy(tmpSet, blockHashSet[nums-maxBlockHashCount:])
		blockHashSet = tmpSet
	}
}

func sealKeyToFile() {
	keygrantor.SealKeyToFile(keyFile, randClient.ExtPrivKey)
}
