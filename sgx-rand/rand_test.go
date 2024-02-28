package main

import (
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ethereum/go-ethereum/crypto"
)

func TestHash(t *testing.T) {
	var testHeight = 14024081
	var testBlkHashS = "704249ef93cb233e0008a03ea6041e93e98a3d8a5dfd5071bcb29fd4cc2db203"
	var testHash []byte
	testHash, _ = hex.DecodeString(testBlkHashS)
	var vrfData []byte
	vrfData = append(vrfData, []byte("\x19Ethereum Signed Message:\n40")...)
	var height [8]byte
	binary.BigEndian.PutUint64(height[:], uint64(testHeight))
	vrfData = append(vrfData, height[:]...)
	vrfData = append(vrfData, testHash[:]...)
	h := crypto.Keccak256Hash(vrfData)
	//fmt.Println(hex.EncodeToString(h[:]))
	require.Equal(t, "46c2c8e443bc7e5afc8ba4126c04b11c20de1dd967ae8d707e221e7c7876db71", hex.EncodeToString(h[:]))
}
