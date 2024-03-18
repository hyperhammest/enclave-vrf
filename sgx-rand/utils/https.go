package utils

import (
	"crypto/tls"
	"errors"
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
		//fmt.Println(err)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		//fmt.Println(resp.Status)
		return nil
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		//fmt.Println(err)
		return nil
	}
	return body
}

func HttpPost(tlsConfig *tls.Config, url string, bodyReader io.Reader) error {
	client := http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}, Timeout: 3 * time.Second}
	req, err := http.NewRequest(http.MethodPost, url, bodyReader)
	if err != nil {
		//fmt.Println(err)
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		//fmt.Println(err)
		return err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		//fmt.Println(err)
		return err
	}
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("post get bad response, status:%s, body:%s\n", resp.Status, string(body))
		return errors.New("status code not ok")
	}
	return nil
}
