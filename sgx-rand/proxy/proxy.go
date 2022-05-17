package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/edgelesssys/ego/eclient"

	"github.com/smartbch/enclave-vrf/sgx-rand/utils"
)

var listenURL *string
var serverAddr *string

var smartBCHAddrList []string

var vrfPubkey string

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

var latestBlockNumber uint64
var latestVrfBlockNumber uint64

const serverName = "SGX-VRF-PUBKEY"
const maxBlockHashCount = 5000

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
	smartBCHAddrListArg := flag.String("b", "13.212.74.236:8545,13.212.109.6:8545,18.119.124.186:8545", "smartbch address list, seperated by comma")
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

	getBlockHashAndVRFsAndClearOldData(signer, uniqueID)

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

func getBlockHashAndVRFsAndClearOldData(signer, uniqueID []byte) {
	verifyServerAndGetCert(*serverAddr, signer, uniqueID)
	go func() {
		for {
			blockHashConsume()
			fmt.Printf("latest number: %d\n", latestBlockNumber)
			if len(blockHashSet) < 256 {
				getLatest256BlockHash()
				fmt.Printf("blockHash count:%d\n", len(blockHashSet))
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
			fmt.Println("next loop for getting blockHash")
		}
	}()
}

func getLatest256BlockHash() {
	if latestBlockNumber != 0 {
		for i := uint64(1); i <= 256; i++ {
			hash := getBlockHashByNum(smartBCHAddrList, latestBlockNumber-i)
			sendBlockHash2SGX(hash)
		}
	}
}

func sendBlockHash2SGX(blkHash string) {
	blockHash2Time[blkHash] = time.Now().Unix()
	blockHashSet = append(blockHashSet, blkHash)
	fmt.Println("send blockHash to sgx-rand")
	//todo: add response verify, make sure blockHash sent to server
	utils.HttpGet(serverTlsConfig, fmt.Sprintf("https://"+*serverAddr+"/blockhash?b=%s", blkHash))
	fmt.Println("sent blockHash to sgx-rand")
	blockHashCacheWaitingVrf = append(blockHashCacheWaitingVrf, blkHash)
}

func blockHashConsume() (exist bool) {
	blkNum, blkHash := getBlockNumAndHash(smartBCHAddrList)
	fmt.Println(blkHash)
	latestBlockNumber = blkNum
	if blockHash2Time[blkHash] != 0 {
		time.Sleep(200 * time.Millisecond)
		fmt.Println("blockHash already exist")
		return true
	}
	fmt.Println("new blockHash")
	blockHash2Height[blkHash] = blkNum
	sendBlockHash2SGX(blkHash)
	return false
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
	certBytes := utils.VerifySever(address, signer, uniqueID, verifyReport)
	cert, _ := x509.ParseCertificate(certBytes)
	serverTlsConfig = &tls.Config{RootCAs: x509.NewCertPool(), ServerName: serverName}
	serverTlsConfig.RootCAs.AddCert(cert)
}

func verifyReport(reportBytes, certBytes, signer, uniqueID []byte) error {
	report, err := eclient.VerifyRemoteReport(reportBytes)
	if err != nil {
		return err
	}
	return utils.CheckReport(report, certBytes, signer, uniqueID)
}
