# cloudhsm

## re-generate from swig

`mkdir build`  
`cd build`  
`cmake ..`  
`make`  
`cd ..`  
`swig -go -c++ -cgo -intgosize 32 -o cloudhsm.cxx swig.i`  

## build and install

```
cd cloudhsm
git checkout feature/swig_go_dev_2
mkdir build
cd build
cmake .. -D ENABLE_SHARED=on
make
sudo make install
```

## go execute sample
```
git cloud https://github.com/cryptogarageinc/cloudhsm.git
cd cloudhsm
git checkout feature/swig_go_dev_2
mkdir build
cd build
cmake .. -D ENABLE_SHARED=on
make
cp Release/libcloudhsmpkcs11.dylib /usr/local/lib/
cd ../../
mkdir cloudsign
cd cloudsign
go mod init cloudsign
go get https://github.com/cryptogarageinc/cloudhsm.git@feature/swig_go_dev_2
```
