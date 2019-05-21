%module cloudhsm
%{
#include "src/pkcs11/common.h"
#include "src/pkcs11/sign.h"
%}
%insert(cgo_comment_typedefs) %{
#cgo CPPFLAGS: -I${SRCDIR}/include/pkcs11/v2.40
#cgo LDFLAGS: -L${SRCDIR}/build/src/pkcs11 -lcloudhsmpkcs11 -ldl
%}
%include "src/pkcs11/common.h"
%include "src/pkcs11/sign.h"
%go_import("unsafe")
%insert(go_wrapper) %{
func convertRVtoByte(rv CK_RV) byte {
        return *(*byte)(unsafe.Pointer(rv.Swigcptr()))
}

func Pkcs11Initialize(path string) byte {
        rv := Pkcs11_initialize(path)
        return convertRVtoByte(rv)
}

func Pkcs11OpenSession(pin string) (sessionHandler SwigcptrCK_SESSION_HANDLE, ret byte) {
        pinPtr := SwigcptrCK_UTF8CHAR_PTR(uintptr(unsafe.Pointer(&pin)))
        session := uint64(0)
        sessionHandler = SwigcptrCK_SESSION_HANDLE(uintptr(unsafe.Pointer(&session)))
        sessionPtr := SwigcptrCK_SESSION_HANDLE_PTR(uintptr(unsafe.Pointer(&sessionHandler)))

        rv := Pkcs11_open_session(pinPtr, sessionPtr)
        ret = convertRVtoByte(rv)
        return
}

func Pkcs11FinalizeSession(session CK_SESSION_HANDLE) {
        Pkcs11_finalize_session(session)
}

func GenerateSignature(sessionHandle CK_SESSION_HANDLE, privkey uint64, mechType uint64, data []byte) (signature [64]byte, ret byte) {
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
                sessionHandle,
                privkeyObj,
                mechTypeObj,
                dataObj,
                dataLenObj,
                sigObj,
                sigLenPtrObj)

        ret = convertRVtoByte(rv)
        return
}

func VerifySignature(sessionHandle CK_SESSION_HANDLE, pubkey uint64, mechType uint64, data []byte, signature []byte) byte {
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
                sessionHandle,
                pubkeyObj,
                mechTypeObj,
                dataObj,
                dataLenObj,
                sigObj,
                sigLenObj)
        return convertRVtoByte(rv)
}
%}
