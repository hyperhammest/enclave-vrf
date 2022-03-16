package main

import (
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"time"

	secp256k1 "github.com/btcsuite/btcd/btcec"
	"github.com/edgelesssys/ego/attestation"
	"github.com/edgelesssys/ego/eclient"

	"github.com/smartbch/enclave-vrf/sgx-rand/utils"
)

var signer []byte
var privateKey *secp256k1.PrivateKey
var serverAddr *string

func main() {
	signerArg := flag.String("s", "", "signer ID")
	serverAddr = flag.String("a", "localhost:8081", "server address")
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

	// Init private key
	pBytes, _ := hex.DecodeString("0x09b251bef6c6e5eb8ba39f2605c02899d21e5de0510a82879147f6f50f1c0cb0")
	privateKey, _ = secp256k1.PrivKeyFromBytes(secp256k1.S256(), pBytes)
	if hex.EncodeToString(privateKey.Serialize()) != "09b251bef6c6e5eb8ba39f2605c02899d21e5de0510a82879147f6f50f1c0cb0" {
		fmt.Printf("private key :%s\n", hex.EncodeToString(privateKey.Serialize()))
		panic("private key not recover")
	}

	// Create a TLS config that verifies a certificate with embedded report.
	tlsConfig := eclient.CreateAttestationClientTLSConfig(verifyReport)

	testBlockHashVRF(tlsConfig)

	utils.HttpGet(tlsConfig, "https://"+*serverAddr+"/test?t=hello")
	fmt.Println("Sent hello over attested TLS channel.")
}

func testBlockHashVRF(tlsConfig *tls.Config) {
	//secret := "11"
	//secretBytes, _ := hex.DecodeString(secret)
	//hash := sha256.Sum256(secretBytes)
	//sig, err := secp256k1.SignCompact(secp256k1.S256(), privateKey, hash[:], true)
	//if err != nil {
	//	panic(err)
	//}
	//httpGet(tlsConfig, fmt.Sprintf("https://"+*serverAddr+"/secret?s=%s&sig=%s", secret, hex.EncodeToString(sig)))

	blockHash := "01"
	utils.HttpGet(tlsConfig, fmt.Sprintf("https://"+*serverAddr+"/blockhash?b=%s", blockHash))

	time.Sleep(6 * time.Second)
	res := utils.HttpGet(tlsConfig, fmt.Sprintf("https://"+*serverAddr+"/vrf?b=%s", blockHash))
	fmt.Printf("vrf result:%s\n", string(res))

	pubkey := utils.HttpGet(tlsConfig, fmt.Sprintf("https://"+*serverAddr+"/pubkey"))
	fmt.Printf("vrf result:%s\n", hex.EncodeToString(pubkey))
}

func verifyReport(report attestation.Report) error {
	return nil
}
