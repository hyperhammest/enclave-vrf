**Rand is a sgx-enclave app which generate and hold a secret private key using for blockhash vrf generate.**

rand export endpoints below:

```
/pubkey
/blockhash?b={smartbch chain blockhash hex-string}
/vrf?b={smartbch chain blockhash hex-string}
/cert
/report
/token
```

rand has some flags:

```
Usage of ./rand:
  -l string
    	listen address (default "0.0.0.0:8081")
  -m	is master or not
  -p string
    	slave address list seperated by comma
  -s string
    	signer ID
  -u string
    	slave unique id seperated by comma
```

rand can be master or slave in a cluster, master will generate key and send it to slave. slave receive key from master and store it.

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

4. setup slave first

   ```
   nohup ego run rand -l=0.0.0.0:8082 &
   nohup ego run rand -l=0.0.0.0:8083 &
   ```

5. setup master

```
nohup ego run rand -m=true -l=0.0.0.0:8081 -p=0.0.0.0:8082,0.0.0.0:8083 -s={slave_signerid} -u={slave_uniqueid} &
```

#### Attestation

rand get report and cert from peer, verify the report through `enclave.VerifyRemoteReport`. Then rand using the verified `cert` to establish a new ssl connection with peer. Finally, rand can confidence that the connection is secured and the peer is running on enclave, so secret can be shared.



## Proxy is a proxy for rand

Build proxy using command

```
EGOPATH=/snap/ego-dev/current/opt/ego CGO_CFLAGS=-I$EGOPATH/include CGO_LDFLAGS=-L$EGOPATH/lib go build ./...
```

Running proxy using command

```
nohup ./proxy -s=[rand-singer-id] -r=[rand-ur] -l=0.0.0.0:8084 -u=[rand-uniqueid]
```

proxy export endpoints below:

```
/pubkey
/vrf?b={smartbch chain blockhash hex-string}
/cert
/report
/token
```



#### Verifier is a glang app run in enclave enabled machine to verify `Rand` through `Proxy`

```
cd verifier
CGO_CFLAGS=-I/opt/ego/include CGO_LDFLAGS=-L/opt/ego/lib go build ./...
./verify -s=[rand-singer-id] -p=[proxy_ip_address] -u=[rand-uniqueid]
```

if it print like below, it mean verify success:

```
verify enclave-rand server through proxy success? true, the vrf pubkey is: 03190e58f4bb755fb8c04ff0a0ce9f970f22376c718a338bba280cc92c18109c05
```



## Design Principle

The master is responsible for generating the vrf private key and passing it to the slaves. so the master must verify the identity of the slave through remote attestation of enclave-sgx. 

The slave doesn't verify master identity, it receive the key and we can verify it by comparing its corresponding public key with the master's.

About remote attestation, we should verify the uniqueID of rand, because It corresponds to the code one-to-one, If the uniqueID in remote report is same with uniqueID which master rand has, then we have reason to believe that the code running in the app is the one that was originally deployed by developer of master.

The proxy keeps grabbing blocks from the smartbch mainnet and send them to the rand. Get the corresponding vrf result from rand later. The user is directly facing the proxy, not rand.

```
-----> means https connection after remote enclave attestation
~~~~~> means normal http(s) connection

                                           ___________
                                          /  enclave  \
                  +-------+  block hash  +-------------+
                  | proxy |------------->| rand master | send key once
                  |       |------------->|  (vrf key)  |-------+
                  +-------+   get vrf    +-------------+       |
                                                               |
                                           ___________         |
           get                            /  enclave  \        |
+------+  block   +-------+  block hash  +-------------+       |
| sbch |   hash   | proxy |------------->| rand slave  |<------+
| node |<~~~~~~~~~|       |------------->|  (vrf key)  |       |
+------+          +-------+   get vrf    +-------------+       |
                                                               |
                                           ___________         |
                                          /  enclave  \        |
+------+          +-------+  block hash  +-------------+       |
|client| get vrf  | proxy |------------->| rand slave  |<------+
|      |~~~~~~~~~>|       |------------->|  (vrf key)  |
+------+          +-------+   get vrf    +-------------+

```
