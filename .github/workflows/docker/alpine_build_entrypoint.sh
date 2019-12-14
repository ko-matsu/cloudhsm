#!/bin/sh -l

apk add --update --no-cache musl gcc g++ make git cmake

cd /github/workspace
ls

mkdir -p dist/usr/local/lib64
cd cloudhsm
mkdir build
cd build
cmake --version
cmake .. -DENABLE_SHARED=on -DCMAKE_BUILD_TYPE=Release -DTARGET_RPATH="/usr/local/lib;/usr/local/lib64"
make
cp ./src/pkcs11/libcloudhsmpkcs11.* /github/workspace/dist/usr/local/lib64
ls /github/workspace/dist
ls /github/workspace/dist/usr
ls /github/workspace/dist/usr/local
ls /github/workspace/dist/usr/local/lib64
