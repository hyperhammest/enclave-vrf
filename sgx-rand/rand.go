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

const (
	maxBlockHashCount = 50_000
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
	err := light.VerifyAdjacent(&LatestTrustedHeader, &p.UntrustedHeader, p.Validators, 168*time.Hour, time.Now(), 10*time.Second)
	if err != nil {
		return false
	}
	return true
}

func initLatestTrustedHeader() {
	//todo: recovery LatestTrustedHeader from file, if err hit, set LatestTrustedHeader from initial json string.
	initHeaderStr := `{
      "header": {
        "version": {
          "block": "11"
        },
        "chain_id": "0x2710",
        "height": "14023800",
        "time": "2024-02-28T01:28:28.666558359Z",
        "last_block_id": {
          "hash": "CCF603962753CC55EACE77184AC3B336A377AB77777DCF2137624F6139862245",
          "parts": {
            "total": 1,
            "hash": "5C4E745143F435B46E40CE590298503ADC2191C5C172C5F33059EBF2CB702CCE"
          }
        },
        "last_commit_hash": "80432E77ED19D72E009F432EC397C505A0F77F9524C7E9BF303FF7DFC912D44E",
        "data_hash": "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
        "validators_hash": "287F01AC202D20C8A88EE89CFA51D303DA11BEFA7FB69C147EDA69D98B112114",
        "next_validators_hash": "287F01AC202D20C8A88EE89CFA51D303DA11BEFA7FB69C147EDA69D98B112114",
        "consensus_hash": "DB82A3E5EC7A0994F3B78B258907CFF68320368782642AA9255985A28C938678",
        "app_hash": "43204A49FAB84A746968319C6C048F4F8F3155F077156574B7C34CB65A96C4CD",
        "last_results_hash": "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
        "evidence_hash": "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
        "proposer_address": "A928A5794D9852389FF572B1941A672274C6C44A"
      },
      "commit": {
        "height": "14023800",
        "round": 0,
        "block_id": {
          "hash": "1421BE28F1022930408F2E7A80B4357767D1630BA2409027A31A8CEEA2914E67",
          "parts": {
            "total": 1,
            "hash": "BC642D9832BB3C83E914A002CB700DE539087A8B47CCF51FEC5AD2BEE01B2036"
          }
        },
        "signatures": [
          {
            "block_id_flag": 2,
            "validator_address": "2FEB93041FC652B1326A2F07BAEC5CAA8D2353A9",
            "timestamp": "2024-02-28T01:28:34.446377066Z",
            "signature": "oMWhOhIa/KinACL8WB4k4CBVraP27Q1aJG3htBo6+PK7R5UWIZuRhjcLsJKgAnwy1El7otFLXhxIFvs0qS1kBA=="
          },
          {
            "block_id_flag": 2,
            "validator_address": "32E716DAA7C8C2A8AF5759BDB2DF28DF74BBF627",
            "timestamp": "2024-02-28T01:28:34.45912977Z",
            "signature": "E6fxOZgVmqKp5i7NPp8d+3/DKQZaXb04srK0zeaPguFzHd5b17niMiWeTNUml6N20nab2Gro2FBLp1XtvBlCDw=="
          },
          {
            "block_id_flag": 2,
            "validator_address": "930C23CE7536B0EDE6AFE7754134D4011217D6AA",
            "timestamp": "2024-02-28T01:28:34.436589239Z",
            "signature": "tglqGp0j8HtqIkvc5Ay3RlaLL3hdtAMRKObPEzYGy/d7SDFiasDKcongVjah3/qEGIx6/mzP5hs/F4ib78j6BA=="
          },
          {
            "block_id_flag": 2,
            "validator_address": "A928A5794D9852389FF572B1941A672274C6C44A",
            "timestamp": "2024-02-28T01:28:34.399912288Z",
            "signature": "+RGSayVLaNQYKcUpt0leSkruNsHRIQjDjIpQvlVFoVvOJL93rV+25pmjiTyfg2rhRlVLgMy+EALO8ZG58AnLBw=="
          },
          {
            "block_id_flag": 2,
            "validator_address": "F22A003226B2221B00906C7435C2EB582223C5C2",
            "timestamp": "2024-02-28T01:28:34.442114711Z",
            "signature": "aNTmDqq7DrZZosZvEBt1SQnbJA/Auot55sJ0PwvZGRnXCLDqbYfbb2YYnRryUiLBrsEX9cgoEOANoUKqINxsAg=="
          },
          {
            "block_id_flag": 2,
            "validator_address": "FAC3A668D5BED3DDBD854B647E3113946BE3306A",
            "timestamp": "2024-02-28T01:28:34.493749796Z",
            "signature": "6AxscUV2EYC3NPJf5nRTQ7K9J5vhqi3csYXFanD1IoA2iq+i+C3rYYZdylMd2FY4lAFUVNgJ6zZvp9AS0SNwDw=="
          },
          {
            "block_id_flag": 2,
            "validator_address": "FD46D618D0CD459F791F44D9C6E54302658AD142",
            "timestamp": "2024-02-28T01:28:34.485791846Z",
            "signature": "UzxxjQinVggTRv9EkRu0JbuqfIG3CAvxMl5v6KtOvsvGYdlk2p8+fu1+QjJLQ4gXmIz5MfxADMiHSbaHGao2Cw=="
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
		LatestTrustedHeader = params.UntrustedHeader
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
		//keccak256(abi.encodePacked(PREFIX, randSeedBlock, rdm)
		var vrfData []byte
		vrfData = append(vrfData, []byte("\x19Ethereum Signed Message:\n40")...)
		var height [8]byte
		binary.BigEndian.PutUint64(height[:], uint64(vrfInfo.Height))
		vrfData = append(vrfData, height[:]...)
		var blockHash []byte
		blockHash, err = hex.DecodeString(blkHash)
		if err != nil {
			w.Write([]byte("Invalid block hash format"))
			return
		}
		vrfData = append(vrfData, blockHash...)
		h := crypto.Keccak256Hash(vrfData)
		sig, err := crypto.Sign(h[:], randClient.PrivKey.ToECDSA())
		if err != nil {
			panic(err)
		}
		res.R = hex.EncodeToString(sig[:32])
		res.S = hex.EncodeToString(sig[32:64])
		res.V = sig[64] + 27
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
