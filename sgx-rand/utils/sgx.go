package utils

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/edgelesssys/ego/attestation"
)

func CheckReport(report attestation.Report, certBytes, signer, uniqueID []byte) error {
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
