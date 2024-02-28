package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/edgelesssys/ego/eclient"
	tmjson "github.com/tendermint/tendermint/libs/json"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/smartbch/enclave-vrf/sgx-rand/utils"
)

var listenURL *string
var serverAddr *string

var smartBCHAddrList []string

var vrfPubkey string
var vrfAddress string

var blockHashSet []string
var blockHash2Time = make(map[string]int64)
var blockHash2Height = make(map[string]uint64)

var vrfLock sync.RWMutex
var blockHash2VrfResult = make(map[string]string)

var blockHashCacheWaitingVrf []string

var report []byte
var reportCacheTimestamp int64

var cert []byte
var token []byte
var tokenCacheTimestamp int64

var latestHeightSentToRand uint64
var latestVrfBlockNumber uint64
var randInitHeight = 14023800

const serverName = "SGX-VRF-PUBKEY"
const maxBlockHashCount = 500_000
const prevFetchNum = 1000

var serverTlsConfig *tls.Config

const certFile = "./cert.pem"
const keyFile = "./key.pem"

type ErrResult struct {
	Error string `json:"error,omitempty"`
}

func main() {
	signerArg := flag.String("s", "", "signer ID")
	serverAddr = flag.String("r", "localhost:8082", "sgx-rand address")
	listenURL = flag.String("l", "localhost:8081", " listen address")
	uniqueIDArd := flag.String("u", "", "unique ID")
	smartBCHAddrListArg := flag.String("b", "http://13.212.74.236:8545,http://13.212.109.6:8545,http://18.119.124.186:8545,https://smartbch.fountainhead.cash/mainnet,https://global.uat.cash", "smartbch address list, seperated by comma")
	flag.Parse()

	// get signer command line argument
	signer, err := hex.DecodeString(*signerArg)
	if err != nil {
		panic(err)
	}
	if len(signer) == 0 {
		flag.Usage()
		return
	}
	uniqueID, err := hex.DecodeString(*uniqueIDArd)
	if err != nil {
		panic(err)
	}
	if len(uniqueID) == 0 {
		flag.Usage()
		return
	}
	parseSmartBchAddressList(*smartBCHAddrListArg)

	verifyServerAndGetCert(*serverAddr, signer, uniqueID)
	getBlockHashAndVRFsAndClearOldData()

	initVrfHttpHandlers()
	server := http.Server{Addr: *listenURL, ReadTimeout: 3 * time.Second, WriteTimeout: 5 * time.Second}
	fmt.Println("listening ...")
	err = server.ListenAndServeTLS(certFile, keyFile)
	fmt.Println(err)
}

func parseSmartBchAddressList(list string) {
	smartBCHAddrList = strings.Split(list, ",")
	if len(smartBCHAddrList) <= 1 {
		panic("smartbch addresses should at least has two")
	}
}

func getBlockHashAndVRFsAndClearOldData() {
	go func() {
		for {
			latestTrustedHeight := getLatestTrustedHeight()
			latestBlockNumber, _ := getBlockNumAndHash(smartBCHAddrList)
			fmt.Printf("latest number: %d, latest trusted number from rand-sgx:%d\n", latestBlockNumber, latestTrustedHeight)
			startHeight := latestTrustedHeight + 1
			if latestHeightSentToRand == 0 {
				startHeight = uint64(math.Max(float64(latestTrustedHeight-prevFetchNum), float64(randInitHeight+1)))
			} else if latestHeightSentToRand < latestTrustedHeight {
				startHeight = latestHeightSentToRand + 1
			}
			for i := startHeight; i <= latestBlockNumber; i++ {
				sendBlockHash2SGX(i)
			}
			getVrf()
			if len(blockHashSet) > maxBlockHashCount*1.5 {
				fmt.Println("clear blockHashSet")
				for _, hash := range blockHashSet[:len(blockHashSet)-maxBlockHashCount] {
					delete(blockHash2Time, hash)
					delete(blockHash2Height, hash)
					vrfLock.Lock()
					delete(blockHash2VrfResult, hash)
					vrfLock.Unlock()
				}
				var tmpSet = make([]string, maxBlockHashCount)
				copy(tmpSet, blockHashSet[len(blockHashSet)-maxBlockHashCount:])
				blockHashSet = tmpSet
			}
			time.Sleep(200 * time.Millisecond)
			fmt.Println("next loop for getting new block and vrf result")
		}
	}()
}

type Params struct {
	UntrustedHeader tmtypes.SignedHeader  `json:"last_header"`
	Validators      *tmtypes.ValidatorSet `json:"validators"`
}

func sendBlockHash2SGX(height uint64) {
	currBlkHeader := getSignedHeader(smartBCHAddrList, height)
	blkHash := strings.ToLower(currBlkHeader.Hash().String())
	fmt.Printf("blockheight:%d,blockHash:%s\n", height, blkHash)
	var params Params
	if currBlkHeader == nil {
		panic("block must not nil")
	}
	params.UntrustedHeader = *currBlkHeader
	vals := getValidators(smartBCHAddrList, height)
	valSet, err := tmtypes.ValidatorSetFromExistingValidators(vals)
	params.Validators = valSet
	jsonBody, err := tmjson.Marshal(params)
	if err != nil {
		panic(err)
	}
	bodyReader := bytes.NewReader(jsonBody)
	//todo: add response verify, make sure blockHash sent to server
	utils.HttpPost(serverTlsConfig, fmt.Sprintf("https://"+*serverAddr+"/blockhash?b=%s", blkHash), bodyReader)
	blockHash2Time[blkHash] = time.Now().Unix()
	blockHash2Height[strings.ToLower(blkHash)] = height
	blockHashSet = append(blockHashSet, blkHash)
	latestHeightSentToRand = height
	fmt.Printf("sent block %d to sgx-rand\n", height)
	blockHashCacheWaitingVrf = append(blockHashCacheWaitingVrf, blkHash)
}

func getVrf() {
	var newCache []string
	now := time.Now().Unix()
	for _, blkHash := range blockHashCacheWaitingVrf {
		if blockHash2Time[blkHash]+5 >= now {
			newCache = append(newCache, blkHash)
			continue
		}
		res := utils.HttpGet(serverTlsConfig, fmt.Sprintf("https://"+*serverAddr+"/vrf?b=%s", blkHash))
		fmt.Printf("get vrf, res:%s\n", res)
		if len(res) != 0 {
			vrfLock.Lock()
			blockHash2VrfResult[blkHash] = string(res)
			latestVrfBlockNumber = blockHash2Height[blkHash]
			vrfLock.Unlock()
		} else {
			newCache = append(newCache, blkHash)
		}
	}
	blockHashCacheWaitingVrf = newCache
}

func getLatestTrustedHeight() uint64 {
	res := utils.HttpGet(serverTlsConfig, fmt.Sprintf("https://"+*serverAddr+"/height"))
	return binary.BigEndian.Uint64(res)
}

func enableCors(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
}

func initVrfHttpHandlers() {
	http.HandleFunc("/pubkey", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)
		if len(vrfPubkey) == 0 {
			vrfPubkey = string(utils.HttpGet(serverTlsConfig, fmt.Sprintf("https://"+*serverAddr+"/pubkey")))
		}
		if len(vrfPubkey) != 0 {
			_, _ = w.Write([]byte(vrfPubkey))
		}
		return
	})
	http.HandleFunc("/address", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)
		if len(vrfAddress) == 0 {
			vrfAddress = string(utils.HttpGet(serverTlsConfig, fmt.Sprintf("https://"+*serverAddr+"/address")))
		}
		if len(vrfAddress) != 0 {
			_, _ = w.Write([]byte(vrfAddress))
		}
	})
	http.HandleFunc("/vrf", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)
		hash := r.URL.Query()["b"]
		if len(hash) == 0 {
			return
		}
		blkHash := hash[0]
		vrfLock.RLock()
		vrf := blockHash2VrfResult[blkHash]
		vrfLock.RUnlock()
		if len(vrf) == 0 {
			e, _ := json.Marshal(ErrResult{Error: "not get the vrf of this block hash"})
			w.Write(e)
			return
		}
		w.Write([]byte(vrf))
		return
	})

	// remote report not same
	http.HandleFunc("/report", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)
		now := time.Now().Unix()
		if len(report) == 0 || now > reportCacheTimestamp+5 {
			report = utils.HttpGet(serverTlsConfig, "https://"+*serverAddr+"/report")
			reportCacheTimestamp = now
		}
		if len(report) != 0 {
			w.Write(report)
		}
		return
	})

	http.HandleFunc("/cert", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)
		if len(cert) == 0 {
			cert = utils.HttpGet(serverTlsConfig, "https://"+*serverAddr+"/cert")
		}
		if len(cert) != 0 {
			w.Write(cert)
		}
		return
	})

	// token not same every time calling enclave.CreateAzureAttestationToken， token expiration time is 1 min
	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)
		now := time.Now().Unix()
		if len(token) == 0 || now > tokenCacheTimestamp+5 {
			token = utils.HttpGet(serverTlsConfig, "https://"+*serverAddr+"/token")
			tokenCacheTimestamp = now
		}
		if len(token) != 0 {
			w.Write(token)
		}
		return
	})

	http.HandleFunc("/height", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)
		vrfLock.RLock()
		w.Write([]byte(strconv.FormatInt(int64(latestVrfBlockNumber), 16)))
		vrfLock.RUnlock()
		return
	})
}

func verifyServerAndGetCert(address string, signer, uniqueID []byte) {
	certBytes := utils.VerifyServer(address, signer, uniqueID, verifyReport)
	cert, _ := x509.ParseCertificate(certBytes)
	serverTlsConfig = &tls.Config{RootCAs: x509.NewCertPool(), ServerName: serverName}
	serverTlsConfig.RootCAs.AddCert(cert)
}

func verifyReport(reportBytes, certBytes, pubkeyHashBytes, signer, uniqueID []byte) error {
	report, err := eclient.VerifyRemoteReport(reportBytes)
	if err != nil {
		return err
	}
	return utils.CheckReport(report, certBytes, pubkeyHashBytes, signer, uniqueID)
}
