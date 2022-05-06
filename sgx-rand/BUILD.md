
To build the 'rand' binary in this directory, please following these steps:

0. Get a `DC1s_v3` instance from Azure, with Ubuntu 20.04

1. Install OpenEnclave [reference](https://github.com/openenclave/openenclave/blob/master/docs/GettingStartedDocs/install_oe_sdk-Ubuntu_20.04.md) :

```
echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list
wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -

echo "deb http://apt.llvm.org/focal/ llvm-toolchain-focal-10 main" | sudo tee /etc/apt/sources.list.d/llvm-toolchain-focal-10.list
wget -qO - https://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -

echo "deb [arch=amd64] https://packages.microsoft.com/ubuntu/20.04/prod focal main" | sudo tee /etc/apt/sources.list.d/msprod.list
wget -qO - https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -

sudo apt update

sudo apt -y install dkms
wget https://download.01.org/intel-sgx/sgx-linux/2.16/distro/ubuntu20.04-server/sgx_linux_x64_driver_2.11.054c9c4c.bin
chmod +x sgx_linux_x64_driver_2.11.054c9c4c.bin
sudo ./sgx_linux_x64_driver_2.11.054c9c4c.bin

sudo apt -y install clang-10 libssl-dev gdb libsgx-enclave-common libsgx-quote-ex libprotobuf17 libsgx-dcap-ql libsgx-dcap-ql-dev az-dcap-client open-enclave

```

2. Install ego:

```
wget -qO- https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add
sudo add-apt-repository "deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu `lsb_release -cs` main"
wget https://github.com/edgelesssys/ego/releases/download/v0.5.0/ego_0.5.0_amd64.deb
sudo apt install -y ./ego_0.5.0_amd64.deb build-essential libssl-dev
```

3. Get the source code and build `rand`

mkdir $HOME/rand
cd $HOME/rand
wget -c https://github.com/smartbch/enclave-vrf/archive/refs/tags/v0.1.0.tar.gz | tar zxvf -
cd enclave-vrf/sgx-rand
ego-go build rand.go



