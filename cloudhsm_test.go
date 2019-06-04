package cloudhsm

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSigning(t *testing.T) {
	libPath := "/your/library/path"
	pin := []byte("user:password")
	privkey := uint64(0)
	mechType := uint64(0x00001041) // ECDSA
	data := [32]byte{0x1e, 0xc5, 0x10, 0x2e, 0x93, 0xc6, 0xf2, 0xf8, 0xf7, 0x57, 0x7b, 0x40, 0x95, 0x28, 0x86, 0x08, 0xef, 0x3a, 0xb2, 0x0c, 0xe2, 0x93, 0xea, 0x1c, 0x9b, 0x14, 0xd4, 0x66, 0xcf, 0xd7, 0xdc, 0xd0}

	ok := uint8(0x00)

	Pkcs11Initialize(libPath)

	sessionHandle, ret := Pkcs11OpenSession(string(pin))
	assert.Equal(t, ok, ret)

	signature, ret := GenerateSignature(sessionHandle, privkey, mechType, data[:])
	assert.Equal(t, ok, ret)

	pubkey := uint64(0)
	ret = VerifySignature(sessionHandle, pubkey, mechType, data[:], signature[:])
	assert.Equal(t, ok, ret)

	Pkcs11FinalizeSession(sessionHandle)
}
