package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/edgelesssys/ego/eclient"
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
const maxBlockHashCount = 2000_000

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

	cert, priv := createCertificate()
	tlsCfg := tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{cert},
				PrivateKey:  priv,
			},
		},
	}

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

func getBlockHash() string {
	for _, addr := range smartBCHAddrList {
		blkHash := getLatestBlockHash("http://" + addr)
		if blkHash != "" {
			return blkHash
		}
	}
	panic("all smartbch node disconnect!!!")
}

func getLatest256BlockHash() {
	if latestBlockNumber != 0 {
		for i := uint64(1); i <= 256; i++ {
			var hash string
			for _, addr := range smartBCHAddrList {
				reqStrBlockHashByNumber := fmt.Sprintf("{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBlockByNumber\",\"params\":[\"%s\",false],\"id\":1}", "0x"+fmt.Sprintf("%x", latestBlockNumber-i))
				hashRes := sendRequest("http://"+addr, reqStrBlockHashByNumber)
				fmt.Println(hashRes)
				if len(hashRes) == 0 {
					continue
				}
				var hashR hRes
				json.Unmarshal([]byte(hashRes), &hashR)
				hash = hashR.Result.Hash[2:]
				blockHashSet = append(blockHashSet, hash)
				blockHash2Time[hash] = time.Now().Unix()
				blockHashCacheWaitingVrf = append(blockHashCacheWaitingVrf, hash)
				break
			}
			if len(hash) == 0 {
				panic("all smartbch node disconnect!!!")
			}
		}
	}
}

func sendBlockHash2SGX(blkHash string) {
	blockHash2Time[blkHash] = time.Now().Unix()
	blockHashSet = append(blockHashSet, blkHash)
	fmt.Println("send blockHash to sgx-rand")
	//todo: add response verify, make sure blockHash sent to server
	httpGet(serverTlsConfig, fmt.Sprintf("https://"+*serverAddr+"/blockhash?b=%s", blkHash))
	fmt.Println("sent blockHash to sgx-rand")
	blockHashCacheWaitingVrf = append(blockHashCacheWaitingVrf, blkHash)
}

func blockHashConsume() (exist bool) {
	blkHash := getBlockHash()
	fmt.Println(blkHash)
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
		res := httpGet(serverTlsConfig, fmt.Sprintf("https://"+*serverAddr+"/vrf?b=%s", blkHash))
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
			vrfPubkey = string(httpGet(serverTlsConfig, fmt.Sprintf("https://"+*serverAddr+"/pubkey")))
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
			report = httpGet(serverTlsConfig, "https://"+*serverAddr+"/report")
		}
		if len(report) != 0 {
			w.Write(report)
		}
		return
	})

	http.HandleFunc("/cert", func(w http.ResponseWriter, r *http.Request) {
		if len(cert) == 0 {
			cert = httpGet(serverTlsConfig, "https://"+*serverAddr+"/cert")
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
			token = httpGet(serverTlsConfig, "https://"+*serverAddr+"/token")
			tokenCacheTimestamp = now
		}
		if len(token) != 0 {
			w.Write(token)
		}
		return
	})
}

type res struct {
	Result string
}

type hRes struct {
	Result struct {
		Hash string
	}
}

func getLatestBlockHash(url string) string {
	//ReqStrNodeInfo := `{"jsonrpc":"2.0","method":"debug_nodeInfo","params":[],"id":1}`
	reqStrLatestBlock := `{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}`
	blockNumberRes := sendRequest(url, reqStrLatestBlock)
	if blockNumberRes == "" {
		return ""
	}
	var r res
	json.Unmarshal([]byte(blockNumberRes), &r)
	fmt.Println(r.Result)
	var err error
	latestBlockNumber, err = strconv.ParseUint(r.Result[2:], 16, 64)
	if err != nil {
		panic(err)
	}
	reqStrBlockHashByNumber := fmt.Sprintf("{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBlockByNumber\",\"params\":[\"%s\",false],\"id\":1}", r.Result)
	fmt.Println(reqStrBlockHashByNumber)
	hashRes := sendRequest(url, reqStrBlockHashByNumber)
	fmt.Println(hashRes)
	var hashR hRes
	json.Unmarshal([]byte(hashRes), &hashR)
	return hashR.Result.Hash[2:]
}

func sendRequest(url, bodyStr string) string {
	body := strings.NewReader(bodyStr)
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return ""
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	respData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	return string(respData)
}

func verifyServer(peerAddress string) {
	url := "https://" + peerAddress

	tlsConfig := &tls.Config{InsecureSkipVerify: true}

	var certStr string
	var reportStr string
	var certBytes []byte
	var reportBytes []byte
	var err error

	certStr = string(httpGet(tlsConfig, url+"/cert"))
	reportStr = string(httpGet(tlsConfig, url+"/peer-report"))
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
	hash := sha256.Sum256(certBytes)
	if !bytes.Equal(report.Data[:len(hash)], hash[:]) {
		return errors.New("report data does not match the certificate's hash")
	}
	if !bytes.Equal(report.UniqueID, uniqueID) {
		return errors.New("invalid unique id")
	}
	if report.SecurityVersion < 2 {
		return errors.New("invalid security version")
	}
	if binary.LittleEndian.Uint16(report.ProductID) != 0x001 {
		return errors.New("invalid product")
	}
	if !bytes.Equal(report.SignerID, signer) {
		return errors.New("invalid signer")
	}
	if report.Debug {
		return errors.New("should not open debug")
	}

	return nil
}

func createCertificate() ([]byte, crypto.PrivateKey) {
	template := &x509.Certificate{
		SerialNumber: &big.Int{},
		Subject:      pkix.Name{CommonName: serverName},
		NotAfter:     time.Now().Add(10 * 365 * time.Hour), // 10 years
		DNSNames:     []string{serverName},
	}
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	cert, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	return cert, priv
}

func httpGet(tlsConfig *tls.Config, url string) []byte {
	client := http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}, Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Println(resp.Status)
		return nil
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	return body
}
