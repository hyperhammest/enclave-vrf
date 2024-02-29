package main

import (
	"bytes"
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

	"github.com/edgelesssys/ego/ecrypto"
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
	S    string
	R    string
	V    byte
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

var LatestTrustedHeader tmtypes.SignedHeader
var latestStoreHeaderTimestamp int64

const (
	maxBlockHashCount = 50_000
	serverName        = "SGX-VRF-PUBKEY"
	// IntelCPUFreq /proc/cpuinfo model name
	keyFile     = "/data/key.txt"
	delayMargin = 4000
	headerFile  = "/data/header.txt"
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
	err := light.VerifyAdjacent(&LatestTrustedHeader, &p.UntrustedHeader, p.Validators, 168*time.Hour, time.Now(), 10*time.Second)
	if err != nil {
		return false
	}
	return true
}

func initLatestTrustedHeader() {
	fileExist := recoveryLatestTrustedHeaderFromFile()
	if fileExist {
		return
	}
	initHeaderStr := `{
      "header": {
        "version": {
          "block": "11"
        },
        "chain_id": "0x2710",
        "height": "14028518",
        "time": "2024-02-28T09:02:23.475693096Z",
        "last_block_id": {
          "hash": "54D3F907F0AE0F2C2376A723EE11883429059B25B57D743C50D0D1A5C63B2D69",
          "parts": {
            "total": 1,
            "hash": "60C6BB70A5DA4104AA02B84CEF8FF6F6B08528699691F440D87C6226F5D8F34C"
          }
        },
        "last_commit_hash": "4F04A7F3C3326811114412B1E3C0D0DD588D88C512AEFF974B2D215984C3D434",
        "data_hash": "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
        "validators_hash": "287F01AC202D20C8A88EE89CFA51D303DA11BEFA7FB69C147EDA69D98B112114",
        "next_validators_hash": "287F01AC202D20C8A88EE89CFA51D303DA11BEFA7FB69C147EDA69D98B112114",
        "consensus_hash": "DB82A3E5EC7A0994F3B78B258907CFF68320368782642AA9255985A28C938678",
        "app_hash": "F90EBA285576CB736954E6416D8CBC15EEA2C3BDA4F74AB39F38DBF0D807B6B1",
        "last_results_hash": "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
        "evidence_hash": "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
        "proposer_address": "A928A5794D9852389FF572B1941A672274C6C44A"
      },
      "commit": {
        "height": "14028518",
        "round": 0,
        "block_id": {
          "hash": "F02172AAEAA3A42979B7BAC229A89F4994DF7A42D4B221CB18E8E5C874BFFFE1",
          "parts": {
            "total": 1,
            "hash": "1E16BE24C6E5414D87334A46BE97B3ED1DE4A1AE448324B05416177555AF06EC"
          }
        },
        "signatures": [
          {
            "block_id_flag": 2,
            "validator_address": "2FEB93041FC652B1326A2F07BAEC5CAA8D2353A9",
            "timestamp": "2024-02-28T09:02:29.127538552Z",
            "signature": "EgAB9GaOBWa2FIGTLDhFF8i1jWumRxCVxp66+BXeA9voZWys+B2Qhi3Vu70KxmJIQXqzD6Z2RDEk/k+s+s0SCA=="
          },
          {
            "block_id_flag": 2,
            "validator_address": "32E716DAA7C8C2A8AF5759BDB2DF28DF74BBF627",
            "timestamp": "2024-02-28T09:02:29.135788679Z",
            "signature": "RyBvk00eKnDOTiRvsArBSYbjJpPOjHMX7DBGD6ND1jU2RgFqnbIPOEZYD2NKb8x+McbQHFDIzOrxMfpvlHkIAA=="
          },
          {
            "block_id_flag": 2,
            "validator_address": "930C23CE7536B0EDE6AFE7754134D4011217D6AA",
            "timestamp": "2024-02-28T09:02:29.153485525Z",
            "signature": "Mvcd0JT/LPvF9MRhovLaUmQfoj2r6Op7yLmwc6igYldjTV/LLka109kuQyiLk0vq2FQ9k/EiiF2ZL3XLrOz+Cw=="
          },
          {
            "block_id_flag": 2,
            "validator_address": "A928A5794D9852389FF572B1941A672274C6C44A",
            "timestamp": "2024-02-28T09:02:29.029890566Z",
            "signature": "OYwr7lmXeTsjUApV+HdvZDwcY3tn6awk/1k7az84ZICIHIxTwSsriDkYWQf/GXhkagRufZXgRnboQZbO9gZwDQ=="
          },
          {
            "block_id_flag": 2,
            "validator_address": "F22A003226B2221B00906C7435C2EB582223C5C2",
            "timestamp": "2024-02-28T09:02:29.125203847Z",
            "signature": "C43doTwTm74CaOdKdtXmoM0KRjbMkg3Z+HBG5ZbiVZb3esFOgRR0Mz/rB1QKKe/Cc170iNzJA+snF3jM1bwwAw=="
          },
          {
            "block_id_flag": 2,
            "validator_address": "FAC3A668D5BED3DDBD854B647E3113946BE3306A",
            "timestamp": "2024-02-28T09:02:29.173507445Z",
            "signature": "7bpyV5IuS541HGfRuEFKziBNCZi+/VpTqULLycJcTzu9CMmaNbRSzpiKXYSz+ZQwZNPG0mBpqPDYs4LbklcGDg=="
          },
          {
            "block_id_flag": 2,
            "validator_address": "FD46D618D0CD459F791F44D9C6E54302658AD142",
            "timestamp": "2024-02-28T09:02:29.175545726Z",
            "signature": "WzrC1ldng/Y2+pwX8mC+Iad1+G0l0F9VfNxGVZmLPUgdDs6PntRNUBdhZG+CNYSs634q5hjgBzwabtm4exYaCw=="
          }
        ]
      }
    }`
	err := tmjson.Unmarshal([]byte(initHeaderStr), &LatestTrustedHeader)
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
	latestStoreHeaderTimestamp = getTimestampFromTSC()
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
		now := getTimestampFromTSC()
		blockHash2VrfInfo[blkHash] = vrfInfo{
			Beta:      beta,
			Pi:        pi,
			Timestamp: now + delayMargin,
			Height:    params.UntrustedHeader.Height,
		}
		blockHashSet = append(blockHashSet, blkHash)
		LatestTrustedHeader = params.UntrustedHeader
		if now >= latestStoreHeaderTimestamp+3600000 {
			sealLatestTrustedHeaderToFile()
			latestStoreHeaderTimestamp = now
		}
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
		//keccak256(abi.encodePacked(PREFIX, randSeedBlock, beta)
		var vrfData []byte
		vrfData = append(vrfData, []byte("\x19Ethereum Signed Message:\n40")...)
		var height [8]byte
		binary.BigEndian.PutUint64(height[:], uint64(vrfInfo.Height))
		vrfData = append(vrfData, height[:]...)
		vrfData = append(vrfData, vrfInfo.Beta...)
		h := crypto.Keccak256(vrfData)
		sig, err := crypto.Sign(h[:], randClient.PrivKey.ToECDSA())
		if err != nil {
			panic(err)
		}
		res.R = hex.EncodeToString(sig[:32])
		res.S = hex.EncodeToString(sig[32:64])
		res.V = sig[64] + 27
		//		fmt.Printf(`
		//vrfData:%s,
		//hash:%s,
		//sig:%s
		//`, hex.EncodeToString(vrfData), hex.EncodeToString(h[:]), hex.EncodeToString(sig))
		out, _ := json.Marshal(res)
		w.Write(out)
		return
	}
	handlers["/address"] = func(w http.ResponseWriter, r *http.Request) {
		address := crypto.PubkeyToAddress(randClient.PrivKey.ToECDSA().PublicKey)
		w.Write([]byte(address.String()))
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

func recoveryLatestTrustedHeaderFromFile() (fileExist bool) {
	fileData, err := os.ReadFile(headerFile)
	if err != nil {
		fmt.Printf("read file failed, %s\n", err.Error())
		if os.IsNotExist(err) {
			return false
		}
		panic(err)
	}
	rawData, err := ecrypto.Unseal(fileData, nil)
	if err != nil {
		fmt.Printf("unseal file data failed, %s\n", err.Error())
		panic(err)
	}
	err = tmjson.Unmarshal(rawData, &LatestTrustedHeader)
	if err != nil {
		panic(err)
	}
	return true
}

func sealLatestTrustedHeaderToFile() {
	bz, err := tmjson.Marshal(LatestTrustedHeader)
	if err != nil {
		panic(err)
	}
	out, err := ecrypto.SealWithUniqueKey(bz, nil)
	if err != nil {
		panic(err)
	}
	err = os.WriteFile(headerFile, out, 0600)
	if err != nil {
		panic(err)
	}
}
