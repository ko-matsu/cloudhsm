if [ -z "$GO_EXEC_PATH" ]; then
GO_EXEC_PATH=go
fi
LD_LIBRARY_PATH="$LD_LIBRARY_PATH:./build/src/pkcs11:/usr/lib:/usr/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu/engines-1.1:/usr/lib/x86_64-linux-gnu/pkcs11" $GO_EXEC_PATH test
