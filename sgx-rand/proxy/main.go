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
	"github.com/syndtr/goleveldb/leveldb"

	"github.com/smartbch/enclave-vrf/sgx-rand/utils"
)

const (
	serverName              = "SGX-VRF-PUBKEY"
	maxHeightCachedInMemory = 120_000 // about 7 days

	certFile = "./cert.pem"
	keyFile  = "./key.pem"
	dbDir    = "./db"
)

type ErrResult struct {
	Error string `json:"error,omitempty"`
}

type Proxy struct {
	// blockHash related
	blockHashLock       sync.RWMutex
	heightToBlockHash   map[uint64]string
	latestHeightCleaned uint64

	// vrf related
	vrfLock                 sync.RWMutex
	blockHash2VrfResult     map[string]string
	latestVrfGotBlockNumber uint64

	// config
	smartBCHAddrList []string

	// rand related
	randTlsConfig  *tls.Config
	randAddr       string
	randInitHeight int64
	// randInitHeight = 14099517

	// cache rand infos
	vrfPubkey            string
	vrfAddress           string
	cert                 []byte
	token                []byte
	tokenCacheTimestamp  int64
	report               []byte
	reportCacheTimestamp int64

	// db
	db *leveldb.DB
}

func main() {
	proxy := Proxy{randInitHeight: 14306120}
	proxy.heightToBlockHash = make(map[uint64]string)
	proxy.blockHash2VrfResult = make(map[string]string)

	listenAddr := flag.String("l", "localhost:8081", " listen address")
	randAddr := flag.String("r", "localhost:8082", "sgx-rand address")
	randSignerArg := flag.String("s", "", "signer ID")
	randUniqueIDArd := flag.String("u", "", "unique ID")
	smartBCHAddrListArg := flag.String("b", "http://13.212.74.236:8545,http://13.212.109.6:8545,http://18.119.124.186:8545,https://smartbch.fountainhead.cash/mainnet,https://global.uat.cash", "smartbch address list, seperated by comma")
	flag.Parse()

	// get signer command line argument
	signer, err := hex.DecodeString(*randSignerArg)
	if err != nil {
		panic(err)
	}
	if len(signer) == 0 {
		flag.Usage()
		return
	}
	uniqueID, err := hex.DecodeString(*randUniqueIDArd)
	if err != nil {
		panic(err)
	}
	if len(uniqueID) == 0 {
		flag.Usage()
		return
	}
	db, err := leveldb.OpenFile(dbDir, nil)
	if err != nil {
		panic(err)
	}
	defer db.Close()
	proxy.db = db
	proxy.randAddr = *randAddr
	proxy.randTlsConfig = verifyRandAndGetTlsConfig(proxy.randAddr, signer, uniqueID)
	proxy.smartBCHAddrList = getSmartBchNodeUrls(*smartBCHAddrListArg)
	n, err := proxy.getLatestVrfGotBlockNumber()
	if err != nil {
		if err == leveldb.ErrNotFound {
			proxy.latestVrfGotBlockNumber = proxy.getLatestTrustedHeight()
		} else {
			panic(err)
		}
	} else {
		proxy.latestVrfGotBlockNumber = n
	}
	fmt.Printf("proxy start with proxy.latestVrfGotBlockNumber:%d\n", proxy.latestVrfGotBlockNumber)
	proxy.latestHeightCleaned = proxy.latestVrfGotBlockNumber
	proxy.work()
	proxy.initVrfHttpHandlers()
	server := http.Server{Addr: *listenAddr, ReadTimeout: 3 * time.Second, WriteTimeout: 5 * time.Second}
	fmt.Println("listening ...")
	err = server.ListenAndServeTLS(certFile, keyFile)
	fmt.Println(err)
}

func getSmartBchNodeUrls(listStr string) []string {
	smartBCHAddrList := strings.Split(listStr, ",")
	if len(smartBCHAddrList) <= 1 {
		panic("smartbch addresses should at least has two")
	}
	return smartBCHAddrList
}

func verifyRandAndGetTlsConfig(address string, signer, uniqueID []byte) *tls.Config {
	certBytes := utils.VerifyServer(address, signer, uniqueID, verifyReport)
	cert, _ := x509.ParseCertificate(certBytes)
	randTlsConfig := &tls.Config{RootCAs: x509.NewCertPool(), ServerName: serverName}
	randTlsConfig.RootCAs.AddCert(cert)
	return randTlsConfig
}

func verifyReport(reportBytes, certBytes, pubkeyHashBytes, signer, uniqueID []byte) error {
	report, err := eclient.VerifyRemoteReport(reportBytes)
	if err != nil {
		return err
	}
	return utils.CheckReport(report, certBytes, pubkeyHashBytes, signer, uniqueID)
}
