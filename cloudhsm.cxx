/* ----------------------------------------------------------------------------
 * This file was automatically generated by SWIG (http://www.swig.org).
 * Version 3.0.12
 *
 * This file is not intended to be easily readable and contains a number of
 * coding conventions designed to improve portability and efficiency. Do not make
 * changes to this file unless you know what you are doing--modify the SWIG
 * interface file instead.
 * ----------------------------------------------------------------------------- */

// source: swig.i

#define SWIGMODULE cloudhsm

#ifdef __cplusplus
/* SwigValueWrapper is described in swig.swg */
template<typename T> class SwigValueWrapper {
  struct SwigMovePointer {
    T *ptr;
    SwigMovePointer(T *p) : ptr(p) { }
    ~SwigMovePointer() { delete ptr; }
    SwigMovePointer& operator=(SwigMovePointer& rhs) { T* oldptr = ptr; ptr = 0; delete oldptr; ptr = rhs.ptr; rhs.ptr = 0; return *this; }
  } pointer;
  SwigValueWrapper& operator=(const SwigValueWrapper<T>& rhs);
  SwigValueWrapper(const SwigValueWrapper<T>& rhs);
public:
  SwigValueWrapper() : pointer(0) { }
  SwigValueWrapper& operator=(const T& t) { SwigMovePointer tmp(new T(t)); pointer = tmp; return *this; }
  operator T&() const { return *pointer.ptr; }
  T *operator&() { return pointer.ptr; }
};

template <typename T> T SwigValueInit() {
  return T();
}
#endif

/* -----------------------------------------------------------------------------
 *  This section contains generic SWIG labels for method/variable
 *  declarations/attributes, and other compiler dependent labels.
 * ----------------------------------------------------------------------------- */

/* template workaround for compilers that cannot correctly implement the C++ standard */
#ifndef SWIGTEMPLATEDISAMBIGUATOR
# if defined(__SUNPRO_CC) && (__SUNPRO_CC <= 0x560)
#  define SWIGTEMPLATEDISAMBIGUATOR template
# elif defined(__HP_aCC)
/* Needed even with `aCC -AA' when `aCC -V' reports HP ANSI C++ B3910B A.03.55 */
/* If we find a maximum version that requires this, the test would be __HP_aCC <= 35500 for A.03.55 */
#  define SWIGTEMPLATEDISAMBIGUATOR template
# else
#  define SWIGTEMPLATEDISAMBIGUATOR
# endif
#endif

/* inline attribute */
#ifndef SWIGINLINE
# if defined(__cplusplus) || (defined(__GNUC__) && !defined(__STRICT_ANSI__))
#   define SWIGINLINE inline
# else
#   define SWIGINLINE
# endif
#endif

/* attribute recognised by some compilers to avoid 'unused' warnings */
#ifndef SWIGUNUSED
# if defined(__GNUC__)
#   if !(defined(__cplusplus)) || (__GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 4))
#     define SWIGUNUSED __attribute__ ((__unused__))
#   else
#     define SWIGUNUSED
#   endif
# elif defined(__ICC)
#   define SWIGUNUSED __attribute__ ((__unused__))
# else
#   define SWIGUNUSED
# endif
#endif

#ifndef SWIG_MSC_UNSUPPRESS_4505
# if defined(_MSC_VER)
#   pragma warning(disable : 4505) /* unreferenced local function has been removed */
# endif
#endif

#ifndef SWIGUNUSEDPARM
# ifdef __cplusplus
#   define SWIGUNUSEDPARM(p)
# else
#   define SWIGUNUSEDPARM(p) p SWIGUNUSED
# endif
#endif

/* internal SWIG method */
#ifndef SWIGINTERN
# define SWIGINTERN static SWIGUNUSED
#endif

/* internal inline SWIG method */
#ifndef SWIGINTERNINLINE
# define SWIGINTERNINLINE SWIGINTERN SWIGINLINE
#endif

/* exporting methods */
#if defined(__GNUC__)
#  if (__GNUC__ >= 4) || (__GNUC__ == 3 && __GNUC_MINOR__ >= 4)
#    ifndef GCC_HASCLASSVISIBILITY
#      define GCC_HASCLASSVISIBILITY
#    endif
#  endif
#endif

#ifndef SWIGEXPORT
# if defined(_WIN32) || defined(__WIN32__) || defined(__CYGWIN__)
#   if defined(STATIC_LINKED)
#     define SWIGEXPORT
#   else
#     define SWIGEXPORT __declspec(dllexport)
#   endif
# else
#   if defined(__GNUC__) && defined(GCC_HASCLASSVISIBILITY)
#     define SWIGEXPORT __attribute__ ((visibility("default")))
#   else
#     define SWIGEXPORT
#   endif
# endif
#endif

/* calling conventions for Windows */
#ifndef SWIGSTDCALL
# if defined(_WIN32) || defined(__WIN32__) || defined(__CYGWIN__)
#   define SWIGSTDCALL __stdcall
# else
#   define SWIGSTDCALL
# endif
#endif

/* Deal with Microsoft's attempt at deprecating C standard runtime functions */
#if !defined(SWIG_NO_CRT_SECURE_NO_DEPRECATE) && defined(_MSC_VER) && !defined(_CRT_SECURE_NO_DEPRECATE)
# define _CRT_SECURE_NO_DEPRECATE
#endif

/* Deal with Microsoft's attempt at deprecating methods in the standard C++ library */
#if !defined(SWIG_NO_SCL_SECURE_NO_DEPRECATE) && defined(_MSC_VER) && !defined(_SCL_SECURE_NO_DEPRECATE)
# define _SCL_SECURE_NO_DEPRECATE
#endif

/* Deal with Apple's deprecated 'AssertMacros.h' from Carbon-framework */
#if defined(__APPLE__) && !defined(__ASSERT_MACROS_DEFINE_VERSIONS_WITHOUT_UNDERSCORES)
# define __ASSERT_MACROS_DEFINE_VERSIONS_WITHOUT_UNDERSCORES 0
#endif

/* Intel's compiler complains if a variable which was never initialised is
 * cast to void, which is a common idiom which we use to indicate that we
 * are aware a variable isn't used.  So we just silence that warning.
 * See: https://github.com/swig/swig/issues/192 for more discussion.
 */
#ifdef __INTEL_COMPILER
# pragma warning disable 592
#endif


#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>



typedef int intgo;
typedef unsigned int uintgo;


# if !defined(__clang__) && (defined(__i386__) || defined(__x86_64__))
#   define SWIGSTRUCTPACKED __attribute__((__packed__, __gcc_struct__))
# else
#   define SWIGSTRUCTPACKED __attribute__((__packed__))
# endif



typedef struct { char *p; intgo n; } _gostring_;
typedef struct { void* array; intgo len; intgo cap; } _goslice_;




#define swiggo_size_assert_eq(x, y, name) typedef char name[(x-y)*(x-y)*-2+1];
#define swiggo_size_assert(t, n) swiggo_size_assert_eq(sizeof(t), n, swiggo_sizeof_##t##_is_not_##n)

swiggo_size_assert(char, 1)
swiggo_size_assert(short, 2)
swiggo_size_assert(int, 4)
typedef long long swiggo_long_long;
swiggo_size_assert(swiggo_long_long, 8)
swiggo_size_assert(float, 4)
swiggo_size_assert(double, 8)

#ifdef __cplusplus
extern "C" {
#endif
extern void crosscall2(void (*fn)(void *, int), void *, int);
extern char* _cgo_topofstack(void) __attribute__ ((weak));
extern void _cgo_allocate(void *, int);
extern void _cgo_panic(void *, int);
#ifdef __cplusplus
}
#endif

static char *_swig_topofstack() {
  if (_cgo_topofstack) {
    return _cgo_topofstack();
  } else {
    return 0;
  }
}

static void _swig_gopanic(const char *p) {
  struct {
    const char *p;
  } SWIGSTRUCTPACKED a;
  a.p = p;
  crosscall2(_cgo_panic, &a, (int) sizeof a);
}




#define SWIG_contract_assert(expr, msg) \
  if (!(expr)) { _swig_gopanic(msg); } else


static _gostring_ Swig_AllocateString(const char *p, size_t l) {
  _gostring_ ret;
  ret.p = (char*)malloc(l);
  memcpy(ret.p, p, l);
  ret.n = l;
  return ret;
}


static void Swig_free(void* p) {
  free(p);
}

static void* Swig_malloc(int c) {
  return malloc(c);
}


#include "src/pkcs11/common.h"
#include "src/pkcs11/sign.h"

#ifdef __cplusplus
extern "C" {
#endif

void _wrap_Swig_free_cloudhsm_5b4e555383e99e36(void *_swig_go_0) {
  void *arg1 = (void *) 0 ;
  
  arg1 = *(void **)&_swig_go_0; 
  
  Swig_free(arg1);
  
}


void *_wrap_Swig_malloc_cloudhsm_5b4e555383e99e36(intgo _swig_go_0) {
  int arg1 ;
  void *result = 0 ;
  void *_swig_go_result;
  
  arg1 = (int)_swig_go_0; 
  
  result = (void *)Swig_malloc(arg1);
  *(void **)&_swig_go_result = (void *)result; 
  return _swig_go_result;
}


void _wrap_funcs_set_cloudhsm_5b4e555383e99e36(CK_FUNCTION_LIST *_swig_go_0) {
  CK_FUNCTION_LIST *arg1 = (CK_FUNCTION_LIST *) 0 ;
  
  arg1 = *(CK_FUNCTION_LIST **)&_swig_go_0; 
  
  funcs = arg1;
  
}


CK_FUNCTION_LIST *_wrap_funcs_get_cloudhsm_5b4e555383e99e36() {
  CK_FUNCTION_LIST *result = 0 ;
  CK_FUNCTION_LIST *_swig_go_result;
  
  
  result = (CK_FUNCTION_LIST *)funcs;
  *(CK_FUNCTION_LIST **)&_swig_go_result = (CK_FUNCTION_LIST *)result; 
  return _swig_go_result;
}


void _wrap_true_val_set_cloudhsm_5b4e555383e99e36(CK_BBOOL *_swig_go_0) {
  CK_BBOOL arg1 ;
  CK_BBOOL *argp1 ;
  
  
  argp1 = (CK_BBOOL *)_swig_go_0;
  if (argp1 == NULL) {
    _swig_gopanic("Attempt to dereference null CK_BBOOL");
  }
  arg1 = (CK_BBOOL)*argp1;
  
  
  true_val = arg1;
  
}


CK_BBOOL *_wrap_true_val_get_cloudhsm_5b4e555383e99e36() {
  CK_BBOOL result;
  CK_BBOOL *_swig_go_result;
  
  
  result = true_val;
  *(CK_BBOOL **)&_swig_go_result = new CK_BBOOL(result); 
  return _swig_go_result;
}


void _wrap_false_val_set_cloudhsm_5b4e555383e99e36(CK_BBOOL *_swig_go_0) {
  CK_BBOOL arg1 ;
  CK_BBOOL *argp1 ;
  
  
  argp1 = (CK_BBOOL *)_swig_go_0;
  if (argp1 == NULL) {
    _swig_gopanic("Attempt to dereference null CK_BBOOL");
  }
  arg1 = (CK_BBOOL)*argp1;
  
  
  false_val = arg1;
  
}


CK_BBOOL *_wrap_false_val_get_cloudhsm_5b4e555383e99e36() {
  CK_BBOOL result;
  CK_BBOOL *_swig_go_result;
  
  
  result = false_val;
  *(CK_BBOOL **)&_swig_go_result = new CK_BBOOL(result); 
  return _swig_go_result;
}


CK_RV *_wrap_pkcs11_initialize_cloudhsm_5b4e555383e99e36(_gostring_ _swig_go_0) {
  char *arg1 = (char *) 0 ;
  CK_RV result;
  CK_RV *_swig_go_result;
  
  
  arg1 = (char *)malloc(_swig_go_0.n + 1);
  memcpy(arg1, _swig_go_0.p, _swig_go_0.n);
  arg1[_swig_go_0.n] = '\0';
  
  
  result = pkcs11_initialize(arg1);
  *(CK_RV **)&_swig_go_result = new CK_RV(result); 
  free(arg1); 
  return _swig_go_result;
}


CK_RV *_wrap_pkcs11_open_session_cloudhsm_5b4e555383e99e36(CK_UTF8CHAR_PTR *_swig_go_0, CK_SESSION_HANDLE_PTR *_swig_go_1) {
  CK_UTF8CHAR_PTR arg1 ;
  CK_SESSION_HANDLE_PTR arg2 ;
  CK_UTF8CHAR_PTR const *argp1 ;
  CK_SESSION_HANDLE_PTR *argp2 ;
  CK_RV result;
  CK_RV *_swig_go_result;
  
  
  argp1 = (CK_UTF8CHAR_PTR *)_swig_go_0;
  if (argp1 == NULL) {
    _swig_gopanic("Attempt to dereference null CK_UTF8CHAR_PTR const");
  }
  arg1 = (CK_UTF8CHAR_PTR)*argp1;
  
  
  argp2 = (CK_SESSION_HANDLE_PTR *)_swig_go_1;
  if (argp2 == NULL) {
    _swig_gopanic("Attempt to dereference null CK_SESSION_HANDLE_PTR");
  }
  arg2 = (CK_SESSION_HANDLE_PTR)*argp2;
  
  
  result = pkcs11_open_session(arg1,arg2);
  *(CK_RV **)&_swig_go_result = new CK_RV(result); 
  return _swig_go_result;
}


CK_RV *_wrap_pkcs11_get_slot_cloudhsm_5b4e555383e99e36(CK_SLOT_ID *_swig_go_0) {
  CK_SLOT_ID *arg1 = (CK_SLOT_ID *) 0 ;
  CK_RV result;
  CK_RV *_swig_go_result;
  
  arg1 = *(CK_SLOT_ID **)&_swig_go_0; 
  
  result = pkcs11_get_slot(arg1);
  *(CK_RV **)&_swig_go_result = new CK_RV(result); 
  return _swig_go_result;
}


void _wrap_pkcs11_finalize_session_cloudhsm_5b4e555383e99e36(CK_SESSION_HANDLE *_swig_go_0) {
  CK_SESSION_HANDLE arg1 ;
  CK_SESSION_HANDLE *argp1 ;
  
  
  argp1 = (CK_SESSION_HANDLE *)_swig_go_0;
  if (argp1 == NULL) {
    _swig_gopanic("Attempt to dereference null CK_SESSION_HANDLE");
  }
  arg1 = (CK_SESSION_HANDLE)*argp1;
  
  
  pkcs11_finalize_session(arg1);
  
}


void _wrap_pkcs_arguments_pin_set_cloudhsm_5b4e555383e99e36(pkcs_arguments *_swig_go_0, _gostring_ _swig_go_1) {
  pkcs_arguments *arg1 = (pkcs_arguments *) 0 ;
  char *arg2 = (char *) 0 ;
  
  arg1 = *(pkcs_arguments **)&_swig_go_0; 
  
  arg2 = (char *)malloc(_swig_go_1.n + 1);
  memcpy(arg2, _swig_go_1.p, _swig_go_1.n);
  arg2[_swig_go_1.n] = '\0';
  
  
  {
    delete [] arg1->pin;
    if (arg2) {
      arg1->pin = (char *) (new char[strlen((const char *)arg2)+1]);
      strcpy((char *)arg1->pin, (const char *)arg2);
    } else {
      arg1->pin = 0;
    }
  }
  
  free(arg2); 
}


_gostring_ _wrap_pkcs_arguments_pin_get_cloudhsm_5b4e555383e99e36(pkcs_arguments *_swig_go_0) {
  pkcs_arguments *arg1 = (pkcs_arguments *) 0 ;
  char *result = 0 ;
  _gostring_ _swig_go_result;
  
  arg1 = *(pkcs_arguments **)&_swig_go_0; 
  
  result = (char *) ((arg1)->pin);
  _swig_go_result = Swig_AllocateString((char*)result, result ? strlen((char*)result) : 0); 
  return _swig_go_result;
}


void _wrap_pkcs_arguments_library_set_cloudhsm_5b4e555383e99e36(pkcs_arguments *_swig_go_0, _gostring_ _swig_go_1) {
  pkcs_arguments *arg1 = (pkcs_arguments *) 0 ;
  char *arg2 = (char *) 0 ;
  
  arg1 = *(pkcs_arguments **)&_swig_go_0; 
  
  arg2 = (char *)malloc(_swig_go_1.n + 1);
  memcpy(arg2, _swig_go_1.p, _swig_go_1.n);
  arg2[_swig_go_1.n] = '\0';
  
  
  {
    delete [] arg1->library;
    if (arg2) {
      arg1->library = (char *) (new char[strlen((const char *)arg2)+1]);
      strcpy((char *)arg1->library, (const char *)arg2);
    } else {
      arg1->library = 0;
    }
  }
  
  free(arg2); 
}


_gostring_ _wrap_pkcs_arguments_library_get_cloudhsm_5b4e555383e99e36(pkcs_arguments *_swig_go_0) {
  pkcs_arguments *arg1 = (pkcs_arguments *) 0 ;
  char *result = 0 ;
  _gostring_ _swig_go_result;
  
  arg1 = *(pkcs_arguments **)&_swig_go_0; 
  
  result = (char *) ((arg1)->library);
  _swig_go_result = Swig_AllocateString((char*)result, result ? strlen((char*)result) : 0); 
  return _swig_go_result;
}


pkcs_arguments *_wrap_new_pkcs_arguments_cloudhsm_5b4e555383e99e36() {
  pkcs_arguments *result = 0 ;
  pkcs_arguments *_swig_go_result;
  
  
  result = (pkcs_arguments *)new pkcs_arguments();
  *(pkcs_arguments **)&_swig_go_result = (pkcs_arguments *)result; 
  return _swig_go_result;
}


void _wrap_delete_pkcs_arguments_cloudhsm_5b4e555383e99e36(pkcs_arguments *_swig_go_0) {
  pkcs_arguments *arg1 = (pkcs_arguments *) 0 ;
  
  arg1 = *(pkcs_arguments **)&_swig_go_0; 
  
  delete arg1;
  
}


intgo _wrap_get_pkcs_args_cloudhsm_5b4e555383e99e36(intgo _swig_go_0, _gostring_* _swig_go_1, pkcs_arguments *_swig_go_2) {
  int arg1 ;
  char **arg2 = (char **) 0 ;
  pkcs_arguments *arg3 = (pkcs_arguments *) 0 ;
  int result;
  intgo _swig_go_result;
  
  arg1 = (int)_swig_go_0; 
  arg2 = *(char ***)&_swig_go_1; 
  arg3 = *(pkcs_arguments **)&_swig_go_2; 
  
  result = (int)get_pkcs_args(arg1,arg2,arg3);
  _swig_go_result = result; 
  return _swig_go_result;
}


intgo _wrap_bytes_to_new_hexstring_cloudhsm_5b4e555383e99e36(_gostring_ _swig_go_0, long long _swig_go_1, char **_swig_go_2) {
  char *arg1 = (char *) 0 ;
  size_t arg2 ;
  unsigned char **arg3 = (unsigned char **) 0 ;
  int result;
  intgo _swig_go_result;
  
  
  arg1 = (char *)malloc(_swig_go_0.n + 1);
  memcpy(arg1, _swig_go_0.p, _swig_go_0.n);
  arg1[_swig_go_0.n] = '\0';
  
  arg2 = (size_t)_swig_go_1; 
  arg3 = *(unsigned char ***)&_swig_go_2; 
  
  result = (int)bytes_to_new_hexstring(arg1,arg2,arg3);
  _swig_go_result = result; 
  free(arg1); 
  return _swig_go_result;
}


intgo _wrap_print_bytes_as_hex_cloudhsm_5b4e555383e99e36(_gostring_ _swig_go_0, long long _swig_go_1) {
  char *arg1 = (char *) 0 ;
  size_t arg2 ;
  int result;
  intgo _swig_go_result;
  
  
  arg1 = (char *)malloc(_swig_go_0.n + 1);
  memcpy(arg1, _swig_go_0.p, _swig_go_0.n);
  arg1[_swig_go_0.n] = '\0';
  
  arg2 = (size_t)_swig_go_1; 
  
  result = (int)print_bytes_as_hex(arg1,arg2);
  _swig_go_result = result; 
  free(arg1); 
  return _swig_go_result;
}


CK_RV *_wrap_generate_signature_cloudhsm_5b4e555383e99e36(CK_SESSION_HANDLE *_swig_go_0, CK_OBJECT_HANDLE *_swig_go_1, CK_MECHANISM_TYPE *_swig_go_2, CK_BYTE_PTR *_swig_go_3, CK_ULONG *_swig_go_4, CK_BYTE_PTR *_swig_go_5, CK_ULONG_PTR *_swig_go_6) {
  CK_SESSION_HANDLE arg1 ;
  CK_OBJECT_HANDLE arg2 ;
  CK_MECHANISM_TYPE arg3 ;
  CK_BYTE_PTR arg4 ;
  CK_ULONG arg5 ;
  CK_BYTE_PTR arg6 ;
  CK_ULONG_PTR arg7 ;
  CK_SESSION_HANDLE *argp1 ;
  CK_OBJECT_HANDLE *argp2 ;
  CK_MECHANISM_TYPE *argp3 ;
  CK_BYTE_PTR *argp4 ;
  CK_ULONG *argp5 ;
  CK_BYTE_PTR *argp6 ;
  CK_ULONG_PTR *argp7 ;
  CK_RV result;
  CK_RV *_swig_go_result;
  
  
  argp1 = (CK_SESSION_HANDLE *)_swig_go_0;
  if (argp1 == NULL) {
    _swig_gopanic("Attempt to dereference null CK_SESSION_HANDLE");
  }
  arg1 = (CK_SESSION_HANDLE)*argp1;
  
  
  argp2 = (CK_OBJECT_HANDLE *)_swig_go_1;
  if (argp2 == NULL) {
    _swig_gopanic("Attempt to dereference null CK_OBJECT_HANDLE");
  }
  arg2 = (CK_OBJECT_HANDLE)*argp2;
  
  
  argp3 = (CK_MECHANISM_TYPE *)_swig_go_2;
  if (argp3 == NULL) {
    _swig_gopanic("Attempt to dereference null CK_MECHANISM_TYPE");
  }
  arg3 = (CK_MECHANISM_TYPE)*argp3;
  
  
  argp4 = (CK_BYTE_PTR *)_swig_go_3;
  if (argp4 == NULL) {
    _swig_gopanic("Attempt to dereference null CK_BYTE_PTR");
  }
  arg4 = (CK_BYTE_PTR)*argp4;
  
  
  argp5 = (CK_ULONG *)_swig_go_4;
  if (argp5 == NULL) {
    _swig_gopanic("Attempt to dereference null CK_ULONG");
  }
  arg5 = (CK_ULONG)*argp5;
  
  
  argp6 = (CK_BYTE_PTR *)_swig_go_5;
  if (argp6 == NULL) {
    _swig_gopanic("Attempt to dereference null CK_BYTE_PTR");
  }
  arg6 = (CK_BYTE_PTR)*argp6;
  
  
  argp7 = (CK_ULONG_PTR *)_swig_go_6;
  if (argp7 == NULL) {
    _swig_gopanic("Attempt to dereference null CK_ULONG_PTR");
  }
  arg7 = (CK_ULONG_PTR)*argp7;
  
  
  result = generate_signature(arg1,arg2,arg3,arg4,arg5,arg6,arg7);
  *(CK_RV **)&_swig_go_result = new CK_RV(result); 
  return _swig_go_result;
}


CK_RV *_wrap_verify_signature_cloudhsm_5b4e555383e99e36(CK_SESSION_HANDLE *_swig_go_0, CK_OBJECT_HANDLE *_swig_go_1, CK_MECHANISM_TYPE *_swig_go_2, CK_BYTE_PTR *_swig_go_3, CK_ULONG *_swig_go_4, CK_BYTE_PTR *_swig_go_5, CK_ULONG *_swig_go_6) {
  CK_SESSION_HANDLE arg1 ;
  CK_OBJECT_HANDLE arg2 ;
  CK_MECHANISM_TYPE arg3 ;
  CK_BYTE_PTR arg4 ;
  CK_ULONG arg5 ;
  CK_BYTE_PTR arg6 ;
  CK_ULONG arg7 ;
  CK_SESSION_HANDLE *argp1 ;
  CK_OBJECT_HANDLE *argp2 ;
  CK_MECHANISM_TYPE *argp3 ;
  CK_BYTE_PTR *argp4 ;
  CK_ULONG *argp5 ;
  CK_BYTE_PTR *argp6 ;
  CK_ULONG *argp7 ;
  CK_RV result;
  CK_RV *_swig_go_result;
  
  
  argp1 = (CK_SESSION_HANDLE *)_swig_go_0;
  if (argp1 == NULL) {
    _swig_gopanic("Attempt to dereference null CK_SESSION_HANDLE");
  }
  arg1 = (CK_SESSION_HANDLE)*argp1;
  
  
  argp2 = (CK_OBJECT_HANDLE *)_swig_go_1;
  if (argp2 == NULL) {
    _swig_gopanic("Attempt to dereference null CK_OBJECT_HANDLE");
  }
  arg2 = (CK_OBJECT_HANDLE)*argp2;
  
  
  argp3 = (CK_MECHANISM_TYPE *)_swig_go_2;
  if (argp3 == NULL) {
    _swig_gopanic("Attempt to dereference null CK_MECHANISM_TYPE");
  }
  arg3 = (CK_MECHANISM_TYPE)*argp3;
  
  
  argp4 = (CK_BYTE_PTR *)_swig_go_3;
  if (argp4 == NULL) {
    _swig_gopanic("Attempt to dereference null CK_BYTE_PTR");
  }
  arg4 = (CK_BYTE_PTR)*argp4;
  
  
  argp5 = (CK_ULONG *)_swig_go_4;
  if (argp5 == NULL) {
    _swig_gopanic("Attempt to dereference null CK_ULONG");
  }
  arg5 = (CK_ULONG)*argp5;
  
  
  argp6 = (CK_BYTE_PTR *)_swig_go_5;
  if (argp6 == NULL) {
    _swig_gopanic("Attempt to dereference null CK_BYTE_PTR");
  }
  arg6 = (CK_BYTE_PTR)*argp6;
  
  
  argp7 = (CK_ULONG *)_swig_go_6;
  if (argp7 == NULL) {
    _swig_gopanic("Attempt to dereference null CK_ULONG");
  }
  arg7 = (CK_ULONG)*argp7;
  
  
  result = verify_signature(arg1,arg2,arg3,arg4,arg5,arg6,arg7);
  *(CK_RV **)&_swig_go_result = new CK_RV(result); 
  return _swig_go_result;
}


CK_RV *_wrap_get_ec_pubkey_cloudhsm_5b4e555383e99e36(CK_SESSION_HANDLE *_swig_go_0, CK_OBJECT_HANDLE *_swig_go_1, CK_BYTE_PTR *_swig_go_2, CK_ULONG_PTR *_swig_go_3) {
  CK_SESSION_HANDLE arg1 ;
  CK_OBJECT_HANDLE arg2 ;
  CK_BYTE_PTR arg3 ;
  CK_ULONG_PTR arg4 ;
  CK_SESSION_HANDLE *argp1 ;
  CK_OBJECT_HANDLE *argp2 ;
  CK_BYTE_PTR *argp3 ;
  CK_ULONG_PTR *argp4 ;
  CK_RV result;
  CK_RV *_swig_go_result;
  
  
  argp1 = (CK_SESSION_HANDLE *)_swig_go_0;
  if (argp1 == NULL) {
    _swig_gopanic("Attempt to dereference null CK_SESSION_HANDLE");
  }
  arg1 = (CK_SESSION_HANDLE)*argp1;
  
  
  argp2 = (CK_OBJECT_HANDLE *)_swig_go_1;
  if (argp2 == NULL) {
    _swig_gopanic("Attempt to dereference null CK_OBJECT_HANDLE");
  }
  arg2 = (CK_OBJECT_HANDLE)*argp2;
  
  
  argp3 = (CK_BYTE_PTR *)_swig_go_2;
  if (argp3 == NULL) {
    _swig_gopanic("Attempt to dereference null CK_BYTE_PTR");
  }
  arg3 = (CK_BYTE_PTR)*argp3;
  
  
  argp4 = (CK_ULONG_PTR *)_swig_go_3;
  if (argp4 == NULL) {
    _swig_gopanic("Attempt to dereference null CK_ULONG_PTR");
  }
  arg4 = (CK_ULONG_PTR)*argp4;
  
  
  result = get_ec_pubkey(arg1,arg2,arg3,arg4);
  *(CK_RV **)&_swig_go_result = new CK_RV(result); 
  return _swig_go_result;
}


#ifdef __cplusplus
}
#endif

