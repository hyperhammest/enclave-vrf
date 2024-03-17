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
	maxBlockHashCount = 2_000
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
	trustingPeriod := 100000 * 24 * time.Hour
	err := light.VerifyAdjacent(&LatestTrustedHeader, &p.UntrustedHeader, p.Validators, trustingPeriod, time.Now(), 10*time.Second)
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
        "height": "14099517",
        "time": "2024-03-04T04:13:21.304177301Z",
        "last_block_id": {
          "hash": "084300657CB6277550ED194D2934D6C13FC8AA598804670431EF231AB00A4CB7",
          "parts": {
            "total": 1,
            "hash": "A1BA82DD3DC06CE2E9F2BBDEE1D456BFED7B983C2DBD2C942AD1C317031DF25C"
          }
        },
        "last_commit_hash": "5150B4DC110E32A560A69C47925A810DEB7D388862E8C1C0663B38CC39819F96",
        "data_hash": "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
        "validators_hash": "BB17790D9CC8E02C45E70307BEF1B80A7E5F635705B1421975565AFB5C9DC5BF",
        "next_validators_hash": "BB17790D9CC8E02C45E70307BEF1B80A7E5F635705B1421975565AFB5C9DC5BF",
        "consensus_hash": "DB82A3E5EC7A0994F3B78B258907CFF68320368782642AA9255985A28C938678",
        "app_hash": "F20D1D2F8A6FB3694CF04323D6C54D3DF5F2314BC391783FFCFD359857C8B747",
        "last_results_hash": "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
        "evidence_hash": "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
        "proposer_address": "930C23CE7536B0EDE6AFE7754134D4011217D6AA"
      },
      "commit": {
        "height": "14099517",
        "round": 0,
        "block_id": {
          "hash": "F21EF2D1D47D85E80DC28ED472CF018FC64CF1D74463021EC0318F5C636EC74D",
          "parts": {
            "total": 1,
            "hash": "BD4FF9D662BE87C2C9997200BA02BF951672711242D72A0F2D8533B0758ED93D"
          }
        },
        "signatures": [
          {
            "block_id_flag": 2,
            "validator_address": "2FEB93041FC652B1326A2F07BAEC5CAA8D2353A9",
            "timestamp": "2024-03-04T04:13:27.065227089Z",
            "signature": "GftyuTCa7s8Hf/MsrU+MCFcik2daGjsjQTgVJR9MjiVO6ebkHNglgK0+gMV8OMxoKuCY18dV036/CaCxyJ7WAA=="
          },
          {
            "block_id_flag": 2,
            "validator_address": "32E716DAA7C8C2A8AF5759BDB2DF28DF74BBF627",
            "timestamp": "2024-03-04T04:13:27.067893711Z",
            "signature": "w3Jq0/gPbhzL5NFXIuSfiKgO7bR5uy7SS5JdnZgH3DMQffmmQDLGqJrOPJX4TLOx3Rf5zChtNe/lnDiFnk21Aw=="
          },
          {
            "block_id_flag": 2,
            "validator_address": "8BCE68C4092C2D0DC369682520BA31F833518036",
            "timestamp": "2024-03-04T04:13:27.045886961Z",
            "signature": "fH0LK4PwxX0qn6Q+RsbXybAVuWL6xX8u+cb90S1/IOuedtXFNFhU5hw31BNiHM+D6SFZ76NfptPjUAUQEX3ZBQ=="
          },
          {
            "block_id_flag": 2,
            "validator_address": "930C23CE7536B0EDE6AFE7754134D4011217D6AA",
            "timestamp": "2024-03-04T04:13:27.047890819Z",
            "signature": "eN7YWKK966L3mzVn0CS7DBZ/MAB/tnoCUSDRNxYbzx+Lhlwf1IDu5Q99D8woFr9XI6IqcI54EsoqbQ/ZxSChCw=="
          },
          {
            "block_id_flag": 2,
            "validator_address": "A928A5794D9852389FF572B1941A672274C6C44A",
            "timestamp": "2024-03-04T04:13:27.060385431Z",
            "signature": "/6xOdVpK4L35nLnhca5FL7Li+bNPt/VnJp6p2mTZzjjJQqUPqG7dc8b/d8TYVxAa+jlkHVObGXoBADiZs+T7CA=="
          },
          {
            "block_id_flag": 2,
            "validator_address": "F22A003226B2221B00906C7435C2EB582223C5C2",
            "timestamp": "2024-03-04T04:13:27.049958558Z",
            "signature": "Bq2V6VCsLjdkTkd5fcRxbF23nI8QU9NIVS411jA6tOyiN94T/oQNTRvnWKUK7p/Vof83CSTCGLyNxIdjRZ8dDw=="
          },
          {
            "block_id_flag": 2,
            "validator_address": "FAC3A668D5BED3DDBD854B647E3113946BE3306A",
            "timestamp": "2024-03-04T04:13:27.102867018Z",
            "signature": "OzQnRR+qVsx0C52Eqyi04fO7Nf6ACmnvZCKGQZB0Ul+dPNkJuGtACvwFukSk5rW//lHS+GD+RjDgAayqemJtCw=="
          },
          {
            "block_id_flag": 2,
            "validator_address": "FD46D618D0CD459F791F44D9C6E54302658AD142",
            "timestamp": "2024-03-04T04:13:27.145687993Z",
            "signature": "TP0qPg1ERrftPKjLEvYpNtz/YKKpkt+dtCxPjLV41gwMOMLhfcKRNGcIp6RcKUrTIbBGFLqiBqEl6cFbfWKpCw=="
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
	// intelCPUFreq is the cpu frequency decrease 1000x
	intelCPUFreq = 2800_000
	// intelCPUFreq = int64(C.getFreq()) // cpu not support, using hardcode again.
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
			// response ok status, allow reaccess this endpoint with same blockhash
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
		fmt.Printf("now:%d,blkHash:%s\n", now, blkHash)
		blockHash2VrfInfo[blkHash] = vrfInfo{
			Beta:      beta,
			Pi:        pi,
			Timestamp: now + delayMargin,
			Height:    params.UntrustedHeader.Height,
		}
		blockHashSet = append(blockHashSet, blkHash)
		LatestTrustedHeader = params.UntrustedHeader
		if now >= latestStoreHeaderTimestamp+18000 {
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
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("not has this blockhash"))
			return
		}
		now := getTimestampFromTSC()
		fmt.Printf("vrfTimestamp:%d,now:%d,hash:%s\n", vrfTimestamp, now, blkHash)
		if vrfTimestamp > now {
			w.WriteHeader(http.StatusBadRequest)
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
	return cycleNumber / intelCPUFreq
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
	if len(fileData) <= 65 {
		panic("header file length incorrect!")
	}
	sig := fileData[:65]
	rawData := fileData[65:]
	hash := sha256.Sum256(rawData)
	ok := crypto.VerifySignature(randClient.PubKeyBz, hash[:], sig[:64])
	if !ok {
		panic("verify sig failed!")
	}
	err = tmjson.Unmarshal(rawData, &LatestTrustedHeader)
	if err != nil {
		panic(err)
	}
	fmt.Printf("recovery latest trusted header from file, height is :%d\n", LatestTrustedHeader.Height)
	return true
}

func sealLatestTrustedHeaderToFile() {
	h := LatestTrustedHeader
	bz, err := tmjson.Marshal(h)
	if err != nil {
		panic(err)
	}
	hash := sha256.Sum256(bz)
	sig, err := crypto.Sign(hash[:], randClient.PrivKey.ToECDSA())
	if err != nil {
		panic(err)
	}
	out := append(sig, bz...)
	err = os.WriteFile(headerFile, out, 0600)
	if err != nil {
		panic(err)
	}
	fmt.Printf("store latest trusted header to file, its height: %d\n", h.Height)
}
