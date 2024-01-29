module github.com/smartbch/enclave-vrf

go 1.18

require (
	github.com/edgelesssys/ego v1.2.0
	github.com/ethereum/go-ethereum v1.11.0
	github.com/smartbch/egvm v0.0.0-20230906040909-2bfbba098907
	github.com/vechain/go-ecvrf v0.0.0-20220525125849-96fa0442e765
)

replace github.com/smartbch/egvm => ./../../hyperhammest/egvm

require (
	github.com/FactomProject/basen v0.0.0-20150613233007-fe3947df716e // indirect
	github.com/FactomProject/btcutilecc v0.0.0-20130527213604-d3a63a5752ec // indirect
	github.com/StackExchange/wmi v0.0.0-20180116203802-5d049714c4a6 // indirect
	github.com/btcsuite/btcd/btcec/v2 v2.2.0 // indirect
	github.com/deckarep/golang-set/v2 v2.1.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.1.0 // indirect
	github.com/ecies/go/v2 v2.0.5 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/go-stack/stack v1.8.1 // indirect
	github.com/gorilla/websocket v1.5.0 // indirect
	github.com/shirou/gopsutil v3.21.4-0.20210419000835-c7a38de76ee5+incompatible // indirect
	github.com/tklauser/go-sysconf v0.3.10 // indirect
	github.com/tklauser/numcpus v0.4.0 // indirect
	github.com/tyler-smith/go-bip32 v1.0.0 // indirect
	golang.org/x/sys v0.7.0 // indirect
	gopkg.in/natefinch/npipe.v2 v2.0.0-20160621034901-c1b8fa8bdcce // indirect
)

require (
	github.com/btcsuite/btcd v0.22.0-beta
	golang.org/x/crypto v0.7.0 // indirect
	gopkg.in/square/go-jose.v2 v2.6.0 // indirect
)
