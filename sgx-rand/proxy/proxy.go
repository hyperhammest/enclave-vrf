package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/edgelesssys/ego/eclient"

	"github.com/smartbch/enclave-vrf/sgx-rand/utils"
)

var signer []byte
var uniqueID []byte
var listenURL *string
var serverAddr *string

var smartBCHAddrList []string

var vrfPubkey string

var blockHashSet []string
var blockHash2Time = make(map[string]int64)

var vrfLock sync.RWMutex
var blockHash2VrfResult = make(map[string]string)

var blockHashCacheWaitingVrf []string

var report []byte

var cert []byte
var token []byte
var tokenCacheTimestamp int64

var latestBlockNumber uint64

const serverName = "SGX-VRF-PUBKEY"
const maxBlockHashCount = 5000

var serverTlsConfig *tls.Config

func main() {
	signerArg := flag.String("s", "", "signer ID")
	serverAddr = flag.String("r", "localhost:8081", "sgx-rand address")
	listenURL = flag.String("l", "localhost:8082", " listen address")
	uniqueIDArd := flag.String("u", "", "unique ID")
	smartBCHAddrListArg := flag.String("b", "13.212.74.236:8545,13.212.109.6:8545,18.119.124.186:8545", "smartbch address list, seperated by comma")
	flag.Parse()

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
	uniqueID, err = hex.DecodeString(*uniqueIDArd)
	if err != nil {
		panic(err)
	}
	if len(uniqueID) == 0 {
		flag.Usage()
		return
	}
	parseSmartBchAddressList(*smartBCHAddrListArg)

	getBlockHashAndVRFsAndClearOldData()

	_, _, tlsCfg := utils.CreateCertificate(serverName)

	initVrfHttpHandlers()

	server := http.Server{Addr: *listenURL, TLSConfig: &tlsCfg, ReadTimeout: 3 * time.Second, WriteTimeout: 5 * time.Second}
	fmt.Println("listening ...")
	err = server.ListenAndServeTLS("", "")
	fmt.Println(err)
}

func parseSmartBchAddressList(list string) {
	smartBCHAddrList = strings.Split(list, ",")
	if len(smartBCHAddrList) <= 1 {
		panic("smartbch addresses should at least has two")
	}
}

func getBlockHashAndVRFsAndClearOldData() {
	verifyServer(*serverAddr)
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
					vrfLock.Lock()
					delete(blockHash2VrfResult, hash)
					vrfLock.Unlock()
				}
				var tmpSet = make([]string, len(blockHashSet)-maxBlockHashCount)
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
			vrfLock.Unlock()
		} else {
			newCache = append(newCache, blkHash)
		}
	}
	blockHashCacheWaitingVrf = newCache
}

func initVrfHttpHandlers() {
	http.HandleFunc("/pubkey", func(w http.ResponseWriter, r *http.Request) {
		if len(vrfPubkey) == 0 {
			vrfPubkey = string(utils.HttpGet(serverTlsConfig, fmt.Sprintf("https://"+*serverAddr+"/pubkey")))
		}
		if len(vrfPubkey) != 0 {
			_, _ = w.Write([]byte(vrfPubkey))
		}
		return
	})

	http.HandleFunc("/vrf", func(w http.ResponseWriter, r *http.Request) {
		hash := r.URL.Query()["b"]
		if len(hash) == 0 {
			return
		}
		blkHash := hash[0]
		vrfLock.RLock()
		vrf := blockHash2VrfResult[blkHash]
		vrfLock.RUnlock()
		if len(vrf) == 0 {
			return
		}
		w.Write([]byte(vrf))
		return
	})

	// remote report always same
	http.HandleFunc("/report", func(w http.ResponseWriter, r *http.Request) {
		if len(report) == 0 {
			report = utils.HttpGet(serverTlsConfig, "https://"+*serverAddr+"/report")
		}
		if len(report) != 0 {
			w.Write(report)
		}
		return
	})

	http.HandleFunc("/cert", func(w http.ResponseWriter, r *http.Request) {
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
}

func verifyServer(peerAddress string) {
	url := "https://" + peerAddress

	tlsConfig := &tls.Config{InsecureSkipVerify: true}

	var certStr string
	var reportStr string
	var certBytes []byte
	var reportBytes []byte
	var err error

	certStr = string(utils.HttpGet(tlsConfig, url+"/cert"))
	reportStr = string(utils.HttpGet(tlsConfig, url+"/peer-report"))
	time.Sleep(5 * time.Second)

	certBytes, err = hex.DecodeString(certStr)
	if err != nil {
		panic(err)
	}
	reportBytes, err = hex.DecodeString(reportStr)
	if err != nil {
		panic(err)
	}
	if err := verifyReport(reportBytes, certBytes, signer); err != nil {
		panic(err)
	}
	fmt.Printf("verify peer:%s passed\n", peerAddress)

	cert, _ := x509.ParseCertificate(certBytes)
	serverTlsConfig = &tls.Config{RootCAs: x509.NewCertPool(), ServerName: serverName}
	serverTlsConfig.RootCAs.AddCert(cert)
}

func verifyReport(reportBytes, certBytes, signer []byte) error {
	report, err := eclient.VerifyRemoteReport(reportBytes)
	if err != nil {
		return err
	}
	return utils.CheckReport(report, certBytes, signer, uniqueID)
}
