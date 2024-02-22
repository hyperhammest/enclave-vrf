package utils

import (
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"
)

func HttpGet(tlsConfig *tls.Config, url string) []byte {
	client := http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}, Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Println(resp.Status)
		return nil
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	return body
}

func HttpPost(tlsConfig *tls.Config, url string, bodyReader io.Reader) []byte {
	client := http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}, Timeout: 3 * time.Second}
	req, err := http.NewRequest(http.MethodPost, url, bodyReader)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		fmt.Println(resp.Status)
		return nil
	}
	return body
}
