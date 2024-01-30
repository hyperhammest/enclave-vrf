package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	ctypes "github.com/tendermint/tendermint/rpc/core/types"
	rpctypes "github.com/tendermint/tendermint/rpc/jsonrpc/types"
	"github.com/tendermint/tendermint/types"
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
	fmt.Println(info.Result.NextBlock.Hash)
	return uint64(info.Result.NextBlock.Number), info.Result.NextBlock.Hash[2:]
}

func getHeader(addrs []string, height uint64) types.Header {
	for {
		for _, addr := range addrs {
			if !strings.Contains(addr, "8545") {
				continue
			}
			addr = strings.ReplaceAll(addr, "8545", "26657")
			header, err := getBlockHeaderByNumber(addr, height)
			if err == nil {
				return header
			}
		}
		fmt.Println("retry getHeader")
		time.Sleep(10 * time.Second)
	}
}

func getBlockHeaderByNumber(url string, height uint64) (types.Header, error) {
	reqUrl := fmt.Sprintf("%s/block?height=%d", url, height)
	resp, err := http.Get(reqUrl)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Println(resp.Status)
		return types.Header{}, errors.New(fmt.Sprintf("response status not wanted:%s", resp.Status))
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return types.Header{}, err
	}
	var r rpctypes.RPCResponse
	err = r.UnmarshalJSON(body)
	if err != nil {
		return types.Header{}, err
	}
	var b ctypes.ResultBlock
	err = json.Unmarshal(r.Result, &b)
	if err != nil {
		return types.Header{}, err
	}
	fmt.Println(b.Block.Header.Height)
	return b.Block.Header, nil
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
