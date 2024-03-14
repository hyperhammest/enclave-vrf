package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

type tester struct {
	proxyAddr           string
	nodeAddr            string
	startHeight         uint64
	endHeight           uint64
	testMode            string
	blockHeightToHashes map[uint64]string
	blockHashToResult   map[string]string
}

func main() {
	proxyAddrP := flag.String("p", "localhost:8096", "proxy address")
	startHeightP := flag.Uint64("s", 14099517, "start height")
	endHeightP := flag.Uint64("s", 14249869, "end height")
	testModeP := flag.String("m", "H", "query proxy speed, in three mode: H(High speed), M(middle speed), L(low speed)")
	smartBCHAddrP := flag.String("b", "http://13.212.74.236:8545", "smartbch address")
	flag.Parse()
	var t tester
	t.proxyAddr = *proxyAddrP
	t.startHeight = *startHeightP
	t.endHeight = *endHeightP
	t.nodeAddr = *smartBCHAddrP
	t.testMode = *testModeP
	t.blockHeightToHashes = make(map[uint64]string)
	t.blockHashToResult = make(map[string]string)
	t.catchBlockHashes()
	fmt.Println("catch up all blockHash!!!")
	t.getVrfResults()
}

func (t *tester) catchBlockHashes() {
	for h := t.startHeight + 1; h < t.endHeight; h++ {
		hash := getBlockHashByNum(t.nodeAddr, h)
		if hash != "" {
			t.blockHeightToHashes[h] = hash
		}
		if h%1000 == 0 {
			fmt.Printf("catch the blockHash, height:%d\n", h)
		}
	}
}

func (t *tester) getVrfResults() {
	for h, hash := range t.blockHeightToHashes {
		res := getVrf(t.proxyAddr, hash)
		if res != "" {
			t.blockHashToResult[hash] = res
			fmt.Printf("get vrf at height:%d, res is %s\n", h, res)
		}
	}
}

type blockByNumberRes struct {
	Result struct {
		Hash string
	}
}

func getBlockHashByNum(addr string, num uint64) string {
	reqStrBlockHashByNumber := fmt.Sprintf("{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBlockByNumber\",\"params\":[\"%s\",false],\"id\":1}", "0x"+fmt.Sprintf("%x", num))
	hashRes := sendRequest(addr, reqStrBlockHashByNumber)
	fmt.Println(hashRes)
	if len(hashRes) == 0 {
		return ""
	}
	var hashR blockByNumberRes
	json.Unmarshal([]byte(hashRes), &hashR)
	return hashR.Result.Hash[2:]

}

func sendRequest(url, bodyStr string) string {
	body := strings.NewReader(bodyStr)
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return ""
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	respData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	return string(respData)
}

func getVrf(proxyAddr string, hash string) string {
	resp, err := http.Get(fmt.Sprintf("http://"+proxyAddr+"/vrf?b=%s", hash))
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Println(resp.Status)
		return ""
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return ""
	}
	return string(body)
}
