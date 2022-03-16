package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
)

type res struct {
	Result string
}

type hRes struct {
	Result struct {
		Hash string
	}
}

func getBlockHashByNum(addrs []string, num uint64) string {
	for _, addr := range addrs {
		reqStrBlockHashByNumber := fmt.Sprintf("{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBlockByNumber\",\"params\":[\"%s\",false],\"id\":1}", "0x"+fmt.Sprintf("%x", num))
		hashRes := sendRequest("http://"+addr, reqStrBlockHashByNumber)
		fmt.Println(hashRes)
		if len(hashRes) == 0 {
			continue
		}
		var hashR hRes
		json.Unmarshal([]byte(hashRes), &hashR)
		return hashR.Result.Hash[2:]
	}
	panic("all smartbch node disconnect!!!")
}

func getBlockNumAndHash(addrs []string) (uint64, string) {
	for _, addr := range addrs {
		blkNum, blkHash := getLatestBlockNumAndHash("http://" + addr)
		if blkHash != "" {
			return blkNum, blkHash
		}
	}
	panic("all smartbch node disconnect!!!")
}

func getLatestBlockNumAndHash(url string) (uint64, string) {
	//ReqStrNodeInfo := `{"jsonrpc":"2.0","method":"debug_nodeInfo","params":[],"id":1}`
	reqStrLatestBlock := `{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}`
	blockNumberRes := sendRequest(url, reqStrLatestBlock)
	if blockNumberRes == "" {
		return 0, ""
	}
	var r res
	json.Unmarshal([]byte(blockNumberRes), &r)
	fmt.Println(r.Result)
	var err error
	blockNumber, err := strconv.ParseUint(r.Result[2:], 16, 64)
	if err != nil {
		panic(err)
	}
	reqStrBlockHashByNumber := fmt.Sprintf("{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBlockByNumber\",\"params\":[\"%s\",false],\"id\":1}", r.Result)
	fmt.Println(reqStrBlockHashByNumber)
	hashRes := sendRequest(url, reqStrBlockHashByNumber)
	fmt.Println(hashRes)
	var hashR hRes
	json.Unmarshal([]byte(hashRes), &hashR)
	return blockNumber, hashR.Result.Hash[2:]
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
