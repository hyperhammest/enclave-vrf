package utils

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/edgelesssys/ego/attestation"
)

func CheckReport(report attestation.Report, certBytes, pubkeyBytes, signer, uniqueID []byte) error {
	certHash := sha256.Sum256(certBytes)
	hash := append(certHash[:], pubkeyBytes[:]...)
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

func VerifyServer(address string, signer, uniqueID []byte, verifyReport func(reportBytes, certBytes, pubkeyHashBytes, signer, uniqueID []byte) error) []byte {
	url := "https://" + address
	tlsConfig := &tls.Config{InsecureSkipVerify: true}

	var certStr string
	var pubkeyStr string
	var reportStr string
	var certBytes []byte
	var pubkeyHashBytes []byte
	var reportBytes []byte
	var err error

	certStr = string(HttpGet(tlsConfig, url+"/cert"))
	pubkeyStr = string(HttpGet(tlsConfig, url+"/pubkey"))
	reportStr = string(HttpGet(tlsConfig, url+"/report"))

	certBytes, err = hex.DecodeString(certStr)
	if err != nil {
		panic(err)
	}
	pubkeyHashBytes, err = hex.DecodeString(pubkeyStr)
	if err != nil {
		panic(err)
	}
	reportBytes, err = hex.DecodeString(reportStr)
	if err != nil {
		panic(err)
	}
	if err := verifyReport(reportBytes, certBytes, pubkeyHashBytes, signer, uniqueID); err != nil {
		panic(err)
	}
	fmt.Printf("verify server:%s passed\n", address)
	return certBytes
}
