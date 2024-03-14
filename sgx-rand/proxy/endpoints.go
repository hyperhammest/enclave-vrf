package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/smartbch/enclave-vrf/sgx-rand/utils"
)

func (p *Proxy) initVrfHttpHandlers() {
	http.HandleFunc("/pubkeyhash", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)
		if len(p.vrfPubkey) == 0 {
			p.vrfPubkey = string(utils.HttpGet(p.randTlsConfig, "https://"+p.randAddr+"/pubkey"))
		}
		if len(p.vrfPubkey) != 0 {
			_, _ = w.Write([]byte(p.vrfPubkey))
		}
		return
	})
	http.HandleFunc("/address", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)
		if len(p.vrfAddress) == 0 {
			p.vrfAddress = string(utils.HttpGet(p.randTlsConfig, "https://"+p.randAddr+"/address"))
		}
		if len(p.vrfAddress) != 0 {
			_, _ = w.Write([]byte(p.vrfAddress))
		}
		return
	})
	http.HandleFunc("/vrf", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)
		hash := r.URL.Query()["b"]
		if len(hash) == 0 {
			return
		}
		blkHash := hash[0]
		p.vrfLock.RLock()
		vrf := p.blockHash2VrfResult[blkHash]
		p.vrfLock.RUnlock()
		if len(vrf) == 0 {
			res, err := p.getVrfResultByBlockHash(blkHash)
			if err != nil {
				e, _ := json.Marshal(ErrResult{Error: "not get the vrf of this block hash"})
				w.Write(e)
				return
			}
			vrf = res
		}
		w.Write([]byte(vrf))
		return
	})
	// remote report not same
	http.HandleFunc("/report", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)
		now := time.Now().Unix()
		if len(p.report) == 0 || now > p.reportCacheTimestamp+5 {
			p.report = utils.HttpGet(p.randTlsConfig, "https://"+p.randAddr+"/report")
			p.reportCacheTimestamp = now
		}
		if len(p.report) != 0 {
			w.Write(p.report)
		}
		return
	})

	http.HandleFunc("/cert", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)
		if len(p.cert) == 0 {
			p.cert = utils.HttpGet(p.randTlsConfig, "https://"+p.randAddr+"/cert")
		}
		if len(p.cert) != 0 {
			w.Write(p.cert)
		}
		return
	})

	// token not same every time calling enclave.CreateAzureAttestationToken， token expiration time is 1 min
	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)
		now := time.Now().Unix()
		if len(p.token) == 0 || now > p.tokenCacheTimestamp+5 {
			p.token = utils.HttpGet(p.randTlsConfig, "https://"+p.randAddr+"/token")
			p.tokenCacheTimestamp = now
		}
		if len(p.token) != 0 {
			w.Write(p.token)
		}
		return
	})

	http.HandleFunc("/height", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)
		p.vrfLock.RLock()
		w.Write([]byte(strconv.FormatInt(int64(p.latestVrfGotBlockNumber), 16)))
		p.vrfLock.RUnlock()
		return
	})
}

func enableCors(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
}
