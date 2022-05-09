package main

import (
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"

	"github.com/edgelesssys/ego/eclient"
	"github.com/smartbch/enclave-vrf/sgx-rand/utils"
)

var signer []byte
var proxyAddr *string
var uniqueID []byte
var pubkey string

func main() {
	parseCmdFlags()
	fmt.Printf("verify enclave-rand server through proxy success? %v, the vrf pubkey is: %s\n", verifyRandServer(), pubkey)
}

func verifyRandServer() bool {
	url := "https://" + *proxyAddr
	tlsConfig := &tls.Config{InsecureSkipVerify: true}

	var reportStr string
	var pubkeyBytes []byte
	var reportBytes []byte
	var err error

	pubkey = string(utils.HttpGet(tlsConfig, url+"/pubkey"))
	reportStr = string(utils.HttpGet(tlsConfig, url+"/report"))

	pubkeyBytes, err = hex.DecodeString(pubkey)
	if err != nil {
		panic(err)
	}
	reportBytes, err = hex.DecodeString(reportStr)
	if err != nil {
		panic(err)
	}
	report, err := eclient.VerifyRemoteReport(reportBytes)
	if err != nil {
		return false
	}
	return utils.CheckReport(report, pubkeyBytes, signer, uniqueID) == nil
}

func parseCmdFlags() {
	signerArg := flag.String("s", "", "signer ID")
	uniqueIDArd := flag.String("u", "", "unique ID")
	proxyAddr = flag.String("p", "localhost:8081", "proxy address")

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
}
