package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"

	secp256k1 "github.com/btcsuite/btcd/btcec"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
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
	h := crypto.Keccak256(vrfData)
	var key *secp256k1.PrivateKey
	keyBz, _ := hex.DecodeString("eb7865c84dfa0ad5b8d283ab2679eb61898617796024d27e2a56ab4c6b6442ad")
	key, _ = secp256k1.PrivKeyFromBytes(secp256k1.S256(), keyBz)
	fmt.Println(hex.EncodeToString(crypto.FromECDSAPub(&key.ToECDSA().PublicKey)))
	sig, err := crypto.Sign(h[:], key.ToECDSA())
	if err != nil {
		panic(err)
	}
	//sig[64] += 27
	fmt.Println(sig[64])
	fmt.Println(len(sig))
	pubkey, err := crypto.Ecrecover(h[:], sig)
	if err != nil {
		panic(err)
	}
	fmt.Println(hex.EncodeToString(pubkey))
	fmt.Printf("R:%s\n", hex.EncodeToString(sig[:32]))
	fmt.Printf("S:%s\n", hex.EncodeToString(sig[32:64]))
	fmt.Printf("address:%s\n", crypto.PubkeyToAddress(key.PublicKey).String())
	require.Equal(t, "46c2c8e443bc7e5afc8ba4126c04b11c20de1dd967ae8d707e221e7c7876db71", hex.EncodeToString(h[:]))
}
