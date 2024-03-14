package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	tmjson "github.com/tendermint/tendermint/libs/json"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/smartbch/enclave-vrf/sgx-rand/utils"
)

func (p *Proxy) work() {
	go p.feedRandBlockHashes()
	go p.getVRFsFromRand()
	go p.clearOldCache()
}

func (p *Proxy) feedRandBlockHashes() {
	func() {
		latestSmartBchHeight, _ := getBlockNumAndHash(p.smartBCHAddrList)
		latestTrustedHeight := p.getLatestTrustedHeight()
		nextHeightToSend := latestTrustedHeight + 1
		if latestTrustedHeight > p.latestVrfGotBlockNumber {
			fmt.Printf("This is happen when proxy exit without get the newest vrf result, latestTrustedHeight:%d, latestVrfGotBlockNumber:%d\n", latestTrustedHeight, p.latestVrfGotBlockNumber)
			nextHeightToSend = p.latestVrfGotBlockNumber + 1
		}
		for i := 0; ; i++ {
			// adjust nextHeightToSend to latestTrustedHeight every 1000 blocks
			if i%1000 == 999 {
				nextHeightToSend = p.getLatestTrustedHeight() + 1
			}
			err := p.feed(nextHeightToSend)
			// delay only catch up the chain tip
			if nextHeightToSend >= latestSmartBchHeight {
				time.Sleep(200 * time.Millisecond)
			}
			if err == nil {
				if nextHeightToSend%100 == 0 {
					fmt.Printf("feed rand height:%d success!\n", nextHeightToSend)
				}
				nextHeightToSend++
			}
		}
	}()
}

func (p *Proxy) getVRFsFromRand() {
	nextHeightToGotVrf := p.latestVrfGotBlockNumber + 1
	for {
		p.blockHashLock.RLock()
		blkHash, exist := p.heightToBlockHash[nextHeightToGotVrf]
		p.blockHashLock.RUnlock()
		if !exist {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		res := utils.HttpGet(p.randTlsConfig, fmt.Sprintf("https://"+p.randAddr+"/vrf?b=%s", blkHash))
		fmt.Printf("get vrf, res:%s\n", res)
		if len(res) != 0 {
			p.vrfLock.Lock()
			p.blockHash2VrfResult[blkHash] = string(res)
			p.latestVrfGotBlockNumber = nextHeightToGotVrf
			p.vrfLock.Unlock()
			p.saveVrfResultByBlockHash(blkHash, string(res))
			p.saveLatestVrfGotBlockNumber(nextHeightToGotVrf)
			nextHeightToGotVrf++
		} else {
			time.Sleep(200 * time.Second)
		}
	}
}

func (p *Proxy) clearOldCache() {
	for {
		p.vrfLock.RLock()
		latestVrfGotBlockNumber := p.latestVrfGotBlockNumber
		p.vrfLock.RUnlock()
		if latestVrfGotBlockNumber > p.latestHeightCleaned+maxHeightCachedInMemory {
			height := p.latestHeightCleaned + 1
			fmt.Printf("clear old cache since %d\n", height)
			p.blockHashLock.Lock()
			p.vrfLock.Lock()
			for i := uint64(0); i < 1000; i++ {
				hash := p.heightToBlockHash[height]
				delete(p.heightToBlockHash, height)
				delete(p.blockHash2VrfResult, hash)
				height++
			}
			p.blockHashLock.Unlock()
			p.vrfLock.Unlock()
			p.latestHeightCleaned = height - 1
		}
		time.Sleep(1 * time.Minute)
	}
}

type Params struct {
	UntrustedHeader tmtypes.SignedHeader  `json:"last_header"`
	Validators      *tmtypes.ValidatorSet `json:"validators"`
}

func (p *Proxy) feed(height uint64) error {
	currBlkHeader := getSignedHeader(p.smartBCHAddrList, height)
	blkHash := strings.ToLower(currBlkHeader.Hash().String())
	var params Params
	if currBlkHeader == nil {
		panic("block must not nil")
	}
	params.UntrustedHeader = *currBlkHeader
	vals := getValidators(p.smartBCHAddrList, height)
	valSet, err := tmtypes.ValidatorSetFromExistingValidators(vals)
	params.Validators = valSet
	jsonBody, err := tmjson.Marshal(params)
	if err != nil {
		panic(err)
	}
	bodyReader := bytes.NewReader(jsonBody)
	// resend blockhash is allowed, and not return error, code can go through
	err = utils.HttpPost(p.randTlsConfig, fmt.Sprintf("https://"+p.randAddr+"/blockhash?b=%s", blkHash), bodyReader)
	if err != nil {
		return err
	}
	p.blockHashLock.Lock()
	p.heightToBlockHash[height] = strings.ToLower(blkHash)
	p.blockHashLock.Unlock()
	return nil
}

func (p *Proxy) getLatestTrustedHeight() uint64 {
	for {
		res := utils.HttpGet(p.randTlsConfig, "https://"+p.randAddr+"/height")
		if len(res) == 8 {
			return binary.BigEndian.Uint64(res)
		}
		time.Sleep(1 * time.Second)
		fmt.Println("try to get height from sgx-rand again!")
	}
}
