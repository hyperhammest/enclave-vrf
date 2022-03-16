**sgx-rand is a sgx-enclave app which generate and hold a secret private key using for blockhash vrf generate.**

sgx-rand export endpoints below:

```
/pubkey
/blockhash?b={smartbch chain blockhash hex-string}
/vrf?b={smartbch chain blockhash hex-string}
/cert
/report
/token
```

sgx-rand has some flags:

```
Usage of ./rand:
  -l string
    	listen address (default "0.0.0.0:8081")
  -m	is master or not
  -p string
    	peer address list seperated by comma
  -s string
    	signer ID
```

sgx-rand can be master or slave in a cluster, master will generate key and send it to slave. slave receive key from master and store it.

#### setup commands:

1. build rand

```
 ego-go build rand.go
 ego-sign rand
```

Copy the `private.pem` and `public.pem` to slave work directory, this represents the app author.

2. modify enclave.json

```
modify mounts.source to pwd
```

3. get signerid with `ego signerid rand`

4. setup master first

```
nohup ego run rand -m=true -l=0.0.0.0:8081 -p=0.0.0.0:8082,0.0.0.0:8083 -s={signerid} &
```

5. setup slave

```
nohup ego run rand -m=false -l=0.0.0.0:8082 -p=0.0.0.0:8081 -s={signerid} &
nohup ego run rand -m=false -l=0.0.0.0:8083 -p=0.0.0.0:8081 -s={signerid} &
```

#### Attestation

rand get report and cert from peer, verify the report through `enclave.VerifyRemoteReport`. Then rand using the verified `cert` to establish a new ssl connection with peer. Finally, rand can confidence that the connection is secured and the peer is running on enclave, so secret can be shared.



#### Proxy is a proxy for rand

Build proxy using command

```
EGOPATH=/snap/ego-dev/current/opt/ego CGO_CFLAGS=-I$EGOPATH/include CGO_LDFLAGS=-L$EGOPATH/lib go build  proxy.go
```

Running proxy using command

```
nohup ./proxy -s=[singer_id] -r=[sgx-rand-ur] -l=0.0.0.0:8082
```

proxy export endpoints below:

```
/pubkey
/vrf?b={smartbch chain blockhash hex-string}
/cert
/report
/token
```

