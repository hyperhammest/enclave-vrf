package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

type blockByNumberRes struct {
	Result struct {
		Hash string
	}
}

type nodeInfoRes struct {
	Result struct {
		NextBlock struct {
			Number    int    `json:"number"`
			Timestamp int    `json:"timestamp"`
			Hash      string `json:"hash"`
		} `json:"next_block"`
	}
}

func getBlockHashByNum(addrs []string, num uint64) string {
	for {
		for _, addr := range addrs {
			reqStrBlockHashByNumber := fmt.Sprintf("{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBlockByNumber\",\"params\":[\"%s\",false],\"id\":1}", "0x"+fmt.Sprintf("%x", num))
			hashRes := sendRequest(addr, reqStrBlockHashByNumber)
			fmt.Println(hashRes)
			if len(hashRes) == 0 {
				continue
			}
			var hashR blockByNumberRes
			json.Unmarshal([]byte(hashRes), &hashR)
			return hashR.Result.Hash[2:]
		}
		fmt.Printf("retry getBlockHashByNum:%d\n", num)
		time.Sleep(10 * time.Second)
	}
}

func getBlockNumAndHash(addrs []string) (uint64, string) {
	for {
		for _, addr := range addrs {
			blkNum, blkHash := getLatestBlockNumAndHash(addr)
			if blkHash != "" {
				return blkNum, blkHash
			}
		}
		fmt.Println("retry getBlockNumAndHash")
		time.Sleep(10 * time.Second)
	}
}

func getLatestBlockNumAndHash(url string) (uint64, string) {
	reqStrNodeInfo := `{"jsonrpc":"2.0","method":"debug_nodeInfo","params":[],"id":1}`
	infoRes := sendRequest(url, reqStrNodeInfo)
	if infoRes == "" {
		return 0, ""
	}
	var info nodeInfoRes
	json.Unmarshal([]byte(infoRes), &info)
	return uint64(info.Result.NextBlock.Number), info.Result.NextBlock.Hash[2:]
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
