%module cloudhsm
%{
#include "src/pkcs11/common.h"
#include "src/pkcs11/sign.h"
%}
%insert(cgo_comment_typedefs) %{
#cgo CPPFLAGS: -I${SRCDIR}/include/pkcs11/v2.40
#cgo LDFLAGS: -L${SRCDIR}/build/Release -L/usr/local/lib -L/usr/local/lib64 -lcloudhsmpkcs11 -ldl
%}
%include "src/pkcs11/common.h"
%include "src/pkcs11/sign.h"
%go_import("unsafe")
%insert(go_wrapper) %{
func convertRVtoByte(rv CK_RV) uint64 {
        return *(*uint64)(unsafe.Pointer(rv.Swigcptr()))
}

func Pkcs11Initialize(path string) uint64 {
        rv := Pkcs11_initialize(path)
        return convertRVtoByte(rv)
}

func Pkcs11OpenSession(pin string) (sessionHandler uint64, ret uint64) {
        pinPtr := SwigcptrCK_UTF8CHAR_PTR(uintptr(unsafe.Pointer(&pin)))
        session := uint64(0)
        sessionHandlePtr := SwigcptrCK_SESSION_HANDLE(uintptr(unsafe.Pointer(&session)))
        sessionPtr := SwigcptrCK_SESSION_HANDLE_PTR(uintptr(unsafe.Pointer(&sessionHandlePtr)))

        rv := Pkcs11_open_session(pinPtr, sessionPtr)
        ret = convertRVtoByte(rv)
        if ret == uint64(0) {
                sessionHandler = session
        }
        return
}

func Pkcs11FinalizeSession(session uint64) {
        if session == uint64(0) {
                // for disable Go-Compiler optimization
                sessionObj := SwigcptrCK_SESSION_HANDLE(uintptr(unsafe.Pointer(&session)))
                Pkcs11_finalize_session(sessionObj)
        } else {
                sessionObj := SwigcptrCK_SESSION_HANDLE(uintptr(unsafe.Pointer(&session)))
                Pkcs11_finalize_session(sessionObj)
        }
        return
}

func GenerateSignature(sessionHandle uint64, privkey uint64, mechType uint64, data []byte) (signature [64]byte, ret uint64) {
        sessionHandleObj := SwigcptrCK_SESSION_HANDLE(uintptr(unsafe.Pointer(&sessionHandle)))
        privkeyObj := SwigcptrCK_OBJECT_HANDLE(uintptr(unsafe.Pointer(&privkey)))
        mechTypeObj := SwigcptrCK_MECHANISM_TYPE(uintptr(unsafe.Pointer(&mechType)))

        dataPtr := uintptr(unsafe.Pointer(&data[0]))
        dataObj := SwigcptrCK_BYTE_PTR(uintptr(unsafe.Pointer(&dataPtr)))

        dataLen := uint64(len(data))
        dataLenObj := SwigcptrCK_ULONG(unsafe.Pointer(&dataLen))

        sigPtr := uintptr(unsafe.Pointer(&signature[0]))
        sigObj := SwigcptrCK_BYTE_PTR(uintptr(unsafe.Pointer(&sigPtr)))

        // 64 bytes signature
        written := uint64(64)
        sigLen := uintptr(unsafe.Pointer(&written))
        sigLenPtrObj := SwigcptrCK_ULONG_PTR(uintptr(unsafe.Pointer(&sigLen)))

        rv := Generate_signature(
                sessionHandleObj,
                privkeyObj,
                mechTypeObj,
                dataObj,
                dataLenObj,
                sigObj,
                sigLenPtrObj)

        ret = convertRVtoByte(rv)
        return
}

func VerifySignature(sessionHandle uint64, pubkey uint64, mechType uint64, data []byte, signature []byte) uint64 {
        sessionHandleObj := SwigcptrCK_SESSION_HANDLE(uintptr(unsafe.Pointer(&sessionHandle)))
        pubkeyObj := SwigcptrCK_OBJECT_HANDLE(uintptr(unsafe.Pointer(&pubkey)))
        mechTypeObj := SwigcptrCK_MECHANISM_TYPE(uintptr(unsafe.Pointer(&mechType)))

        dataPtr := uintptr(unsafe.Pointer(&data[0]))
        dataObj := SwigcptrCK_BYTE_PTR(uintptr(unsafe.Pointer(&dataPtr)))

        dataLen := uint64(len(data))
        dataLenObj := SwigcptrCK_ULONG(uintptr(unsafe.Pointer(&dataLen)))

        sigPtr := uintptr(unsafe.Pointer(&signature[0]))
        sigObj := SwigcptrCK_BYTE_PTR(uintptr(unsafe.Pointer(&sigPtr)))

        sigLen := uint64(len(signature))
        sigLenObj := SwigcptrCK_ULONG(uintptr(unsafe.Pointer(&sigLen)))

        rv := Verify_signature(
                sessionHandleObj,
                pubkeyObj,
                mechTypeObj,
                dataObj,
                dataLenObj,
                sigObj,
                sigLenObj)
        return convertRVtoByte(rv)
}

func GetPubkey(sessionHandle uint64, pubkey uint64) (pubkeyBytes []byte, ret uint64) {
        sessionHandleObj := SwigcptrCK_SESSION_HANDLE(uintptr(unsafe.Pointer(&sessionHandle)))
        pubkeyObj := SwigcptrCK_OBJECT_HANDLE(uintptr(unsafe.Pointer(&pubkey)))

        var data [256]byte
        dataPtr := uintptr(unsafe.Pointer(&data[0]))
        dataObj := SwigcptrCK_BYTE_PTR(uintptr(unsafe.Pointer(&dataPtr)))

        written := uint64(256)
        dataLen := uintptr(unsafe.Pointer(&written))
        dataLenPtrObj := SwigcptrCK_ULONG_PTR(uintptr(unsafe.Pointer(&dataLen)))

        rv := Get_ec_pubkey(
                sessionHandleObj,
                pubkeyObj,
                dataObj,
                dataLenPtrObj)

        ret = convertRVtoByte(rv)
        if ret == uint64(0) {
                pubkeyBytes = data[:written]
        }
        return
}
%}
