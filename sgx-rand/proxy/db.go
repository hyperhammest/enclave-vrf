package main

import (
	"encoding/binary"
)

var (
	latestVrfGotBlockNumberKey = []byte{0x01}
	vrfResultKey               = []byte{0x02}
)

func (p *Proxy) getLatestVrfGotBlockNumber() (uint64, error) {
	data, err := p.db.Get(latestVrfGotBlockNumberKey, nil)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(data), nil
}

func (p *Proxy) saveLatestVrfGotBlockNumber(height uint64) {
	var h [8]byte
	binary.BigEndian.PutUint64(h[:], height)
	err := p.db.Put(latestVrfGotBlockNumberKey, h[:], nil)
	if err != nil {
		panic(err)
	}
}

func (p *Proxy) getVrfResultByBlockHash(hash string) (string, error) {
	k := append(vrfResultKey, hash...)
	data, err := p.db.Get(k, nil)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (p *Proxy) saveVrfResultByBlockHash(hash string, vrfResult string) {
	k := append(vrfResultKey, hash...)
	err := p.db.Put(k, []byte(vrfResult), nil)
	if err != nil {
		panic(err)
	}
}
