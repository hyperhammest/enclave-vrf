package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	secp256k1 "github.com/btcsuite/btcd/btcec"
	"github.com/edgelesssys/ego/ecrypto"
	"github.com/edgelesssys/ego/enclave"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum"
	vrf "github.com/vechain/go-ecvrf"

	"github.com/smartbch/enclave-vrf/sgx-rand/utils"
)

// #include "util.h"
import "C"

var (
	listenURL  string
	slaves     []string
	slaveUniqueIDs [][]byte
	vrfPrivKey *secp256k1.PrivateKey
	vrfPubkey []byte //compressed pubkey

)

var signer []byte
var isMaster bool

const (
	httpsCertFile = "./cert.pem"
	httpsKeyFile  = "./key.pem"
	keyFile = "/data/key.txt"
	serverName = "SGX-VRF-ACCESS-CONTROL"
)

func main() {
	initConfig()
	recoveryPrivateKeyFromFile()
	go createAndStartHttpsServer()
	time.Sleep(time.Second)
	if isMaster {
		go slaveHandshake()
	}
	select {}
}

func initConfig() {
	isMasterP := flag.Bool("m", false, "is master or not")
	listenURLP := flag.String("l", "0.0.0.0:8082", "listen address")
	signerArg := flag.String("s", "", "signer ID")
	slaveString := flag.String("p", "", "slave address list seperated by comma")
	slaveUniqIDArgs := flag.String("u", "", "slave unique id seperated by comma")
	flag.Parse()
	isMaster = *isMasterP
	listenURL = *listenURLP
	fmt.Println(isMaster)
	fmt.Println(listenURL)
	// get slaves
	if *slaveString != "" {
		slaves = strings.Split(*slaveString, ",")
	}
	if *slaveUniqIDArgs != "" {
		slaveUniqueIDStrings := strings.Split(*slaveUniqIDArgs, ",")
		for _, str := range slaveUniqueIDStrings {
			id, err := hex.DecodeString(str)
			if err != nil {
				panic(err)
			}
			slaveUniqueIDs = append(slaveUniqueIDs, id)
		}
	}
	if !isMaster && len(slaves) != 0 {
		panic("slave should has no slaves")
	}
	if len(slaveUniqueIDs) != len(slaves) {
		panic("number of slave address not match number of slave uniqueID")
	}
	if isMaster {
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
	}
}

func enableCors(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
	(*w).Header().Set("Access-Control-Allow-Methods", "*")
	(*w).Header().Set("Access-Control-Allow-Headers", "origin, content-type, accept")
}

func createAndStartHttpsServer() {

	initHttpHandlers()
	certificate, err := tls.LoadX509KeyPair(httpsCertFile, httpsKeyFile)
	if err != nil {
		panic(err)
	}
	cert := certificate.Certificate[0]
	certHash := sha256.Sum256(cert)
	// init handler for remote attestation
	http.HandleFunc("/cert", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)
		w.Write([]byte(hex.EncodeToString(cert)))
	})
	http.HandleFunc("/peer-report", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)
		report, err := enclave.GetRemoteReport(certHash[:])
		if err != nil {
			panic(err)
		}
		w.Write([]byte(hex.EncodeToString(report)))
	})
	tlsCfg := tls.Config{
		Certificates: []tls.Certificate{
			certificate,
		},
	}
	server := http.Server{Addr: listenURL, TLSConfig: &tlsCfg, ReadTimeout: 3 * time.Second, WriteTimeout: 5 * time.Second}
	fmt.Println("listening ...")
	err = server.ListenAndServeTLS("", "")
	fmt.Println(err)

}

func initHttpHandlers() {
	http.HandleFunc("/key", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)
		fmt.Printf("%v sent key to me\n", r.RemoteAddr)
		if vrfPrivKey != nil {
			return
		}
		keys := r.URL.Query()["k"]
		if len(keys) == 0 {
			return
		}
		key := keys[0]
		authPrivKeyHex := strings.TrimPrefix(key, "0x")
		keyBytes, err := hex.DecodeString(authPrivKeyHex)
		if err != nil {
			return
		}

		priv, pubkey := secp256k1.PrivKeyFromBytes(secp256k1.S256(), keyBytes)
		vrfPrivKey = priv
		vrfPubkey = pubkey.SerializeCompressed()
		sealKeyToFile()
		return
	})

//#### `/skey?contract=<contract-address>&data=<calldata>&sig=<from-account-signature>`
	http.HandleFunc("/skey", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)

		contractAddrBz, errResult := readParam(r.URL.Query(), "contract")
		if errResult != nil {
			ret, _ := json.Marshal(errResult)
			w.Write(ret)
			return
		}
		var contractAddr common.Address
		copy(contractAddr[:], contractAddrBz)

		callData, errResult := readParam(r.URL.Query(), "data")
		if errResult != nil {
			ret, _ := json.Marshal(errResult)
			w.Write(ret)
			return
		}

		sig, errResult := readParam(r.URL.Query(), "sig")
		if errResult != nil {
			ret, _ := json.Marshal(errResult)
			w.Write(ret)
			return
		}

		result := GetSymmetricKey(contractAddr, callData, sig, vrfPrivKey)
		ret, _ := json.Marshal(result)
		w.Write(ret)
	})

	http.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)
		w.WriteHeader(200)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		type pong struct {
			IsSuccess bool   `json:"isSuccess"`
			Message   string `json:"message"`
		}
		p := pong{
			IsSuccess: true,
			Message:   "pong",
		}
		out, _ := json.Marshal(p)
		w.Write(out)
		return
	})
}

func readParam(query map[string][]string, key string) (param []byte, errResult *Result) {
	values := query[key]
	if len(values) == 0 {
		return nil, nil
	}
	if len(values) > 1 {
		errResult = &Result{
			IsSuccess: false,
			Message:   key+" is not unique",
		}
		return
	}

	value := strings.TrimPrefix(values[0], "0x")
	bz, err := hex.DecodeString(value)
	if err != nil {
		errResult = &Result{
			IsSuccess: false,
			Message:   "cannot decode "+value,
		}
		return
	}
	return bz, nil
}

func slaveHandshake() {
	for i, slave := range slaves {
		verifySlaveAndSendKey(slave, slaveUniqueIDs[i])
	}
}

func verifySlaveAndSendKey(slaveAddress string, uniqID []byte) {
	certBytes := utils.VerifySever(slaveAddress, signer, uniqID, verifyReport)

	// Create a TLS config that uses the server certificate as root
	// CA so that future connections to the server can be verified.
	if len(vrfPubkey) != 0 {
		cert, _ := x509.ParseCertificate(certBytes)
		tlsConfig := &tls.Config{RootCAs: x509.NewCertPool(), ServerName: serverName}
		tlsConfig.RootCAs.AddCert(cert)

		utils.HttpGet(tlsConfig, "https://"+slaveAddress+fmt.Sprintf("/key?k=%s", hex.EncodeToString(vrfPrivKey.Serialize())))
		fmt.Printf("send key to slave:%s passed\n", slaveAddress)
	}
}

func generateRandom64Bytes() []byte {
	var out []byte
	var x C.uint16_t
	var retry C.int = 1
	for i := 0; i < 64; i++ {
		C.rdrand_16(&x, retry)
		out = append(out, byte(x))
	}
	return out
}

func verifyReport(reportBytes, certBytes, signer, uniqueID []byte) error {
	report, err := enclave.VerifyRemoteReport(reportBytes)
	if err != nil {
		return err
	}
	return utils.CheckReport(report, certBytes, signer, uniqueID)
}

func recoveryPrivateKeyFromFile() {
	fileData, err := os.ReadFile(keyFile)
	if err != nil {
		fmt.Printf("read file failed, %s\n", err.Error())
		if os.IsNotExist(err) {
			// maybe first run this enclave app
			if isMaster {
				generateVRFPrivateKey()
			}
		}
		return
	}
	rawData, err := ecrypto.Unseal(fileData, nil)
	if err != nil {
		fmt.Printf("unseal file data failed, %s\n", err.Error())
		return
	}
	vrfPrivKey, _ = secp256k1.PrivKeyFromBytes(secp256k1.S256(), rawData)
	vrfPubkey = vrfPrivKey.PubKey().SerializeCompressed()
	fmt.Println("recover vrf keys")
}

func generateVRFPrivateKey() {
	priv, _ := secp256k1.PrivKeyFromBytes(secp256k1.S256(), generateRandom64Bytes())
	vrfPrivKey = priv
	vrfPubkey = vrfPrivKey.PubKey().SerializeCompressed()

	fmt.Printf("generate enclave vrf private key, its pubkey is: %s\n", hex.EncodeToString(vrfPubkey))
	sealKeyToFile()
	return
}

func sealKeyToFile() {
	out, err := ecrypto.SealWithUniqueKey(vrfPrivKey.Serialize(), nil)
	if err != nil {
		panic(err)
	}
	err = os.WriteFile(keyFile, out, 0600)
	if err != nil {
		panic(err)
	}
}

// ----------------------------------------------

const (
	totalRpcTimeoutTime = 10 * time.Second
)

var rpcUrlList = []string{
	"https://smartbch.fountainhead.cash/mainnet",
	"https://global.uat.cash",
	"https://sbch-mainnet.paralinker.com/api/v1/d9903215ca7eb50c7ac278fc6bcf19c6",
}

type Result struct {
	IsSuccess    bool
	Message      string
	SymmetricKey string
	Proof        string
}

func GetSymmetricKey(contractAddr common.Address, callData, sig []byte, vrfKey *secp256k1.PrivateKey) Result {
	if len(callData) < 4 {
		return Result{Message: "Calldata Too Short"}
	}
	var from common.Address
	if len(sig) != 0 {
		hexCallData := hex.EncodeToString(callData)
		txt := fmt.Sprintf("To vrf.cash: contract=%s, data=0x%s", contractAddr, hexCallData)
		ethMsg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(txt), txt)
		ethMsgHash := crypto.Keccak256([]byte(ethMsg))
		pubkeyBz, err := crypto.Ecrecover(ethMsgHash, sig)
		if err != nil {
			return Result{Message: err.Error()}
		}
		pubkey, err := crypto.UnmarshalPubkey(pubkeyBz)
		if err != nil {
			return Result{Message: err.Error()}
		}
		from = crypto.PubkeyToAddress(*pubkey)
	}

	res, err := callContractFromNodes(rpcUrlList, contractAddr, from, callData)
	if err != nil {
		return Result{Message: err.Error()}
	}

	h := sha256.New()
	h.Write(contractAddr[:])
	h.Write(callData[:4])
	hashBytes := h.Sum(res)

	beta, pi, err := vrf.NewSecp256k1Sha256Tai().Prove((*ecdsa.PrivateKey)(vrfPrivKey), hashBytes)
	if err != nil {
		return Result{Message: err.Error()}
	}
	return Result{
		IsSuccess:    true,
		SymmetricKey: "0x"+hex.EncodeToString(beta),
		Proof:        "0x"+hex.EncodeToString(pi),
	}
}

func callContractFromNodes(rpcUrlList []string, contractAddr, from common.Address, callData []byte) ([]byte, error) {
	return getFromAllServers(func(rpcUrl string) ([]byte, error) {
		return callContractFromOneNode(rpcUrl, contractAddr, from, callData)
	})
}

func getFromAllServers(getter func(rpcUrl string) ([]byte, error)) ([]byte, error) {
	if len(rpcUrlList) == 0 {
		panic("empty rpcUrlList")
	}
	resList := make([][]byte, len(rpcUrlList))
	errList := make([]error, len(rpcUrlList))
	wg := sync.WaitGroup{}
	wg.Add(len(rpcUrlList))
	for i, rpcUrl := range rpcUrlList {
		go func(idx int, url string) {
			resList[idx], errList[idx] = getter(url)
			wg.Done()
		}(i, rpcUrl)
	}
	wg.Wait()

	// fail if one of nodes return error
	for idx, err := range errList {
		if err != nil {
			return nil, fmt.Errorf("failed to query %s: %s", rpcUrlList[idx], err.Error())
		}
	}

	// the results must be all equal
	firstRes := resList[0]
	for i := 1; i < len(resList); i++ {
		if !bytes.Equal(firstRes, resList[i]) {
			return nil, fmt.Errorf("result mismatch between %s and %s", rpcUrlList[0], rpcUrlList[i])
		}
	}
	return firstRes, nil
}

func callContractFromOneNode(rpcUrl string, contractAddr, from common.Address, callData []byte) ([]byte, error) {
	//fmt.Println(rpcUrl)
	ctx, cancelFn := context.WithTimeout(context.Background(), totalRpcTimeoutTime)
	defer cancelFn()

	ethClient, err := ethclient.DialContext(ctx, rpcUrl)
	if err != nil {
		return nil, err
	}
	defer ethClient.Close()

	msg := ethereum.CallMsg {
		From:     from,
		To:       &contractAddr,
		GasPrice: big.NewInt(1),
		Value:    big.NewInt(0),
		Data:     callData,
	}

	out, err := ethClient.CallContract(ctx, msg, nil)
	return out, err
}

