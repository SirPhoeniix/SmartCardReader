#ifndef PKCS11WRAPPER_H
#define PKCS11WRAPPER_H

#include "stdafx.h"
#include "stdlib.h"
#include "cryptoki.h"
#include <wincrypt.h>
#include "openssl\sha.h"

typedef int(*C_GetFunctionList_decl)(CK_FUNCTION_LIST_PTR_PTR);

#define		PKCS_OK						0x00000000UL
#define		PKCS_DLL_NOT_LOADED			0x00000100UL
#define		PKCS_FUNCTION_NOT_LOADED	0x00000101UL

#define		PKCS_INITIALIZATION_FAILED	0x00000400UL

class CPKCS11Wrapper
{
public:
	CPKCS11Wrapper();
	CPKCS11Wrapper(CString szDll);
	~CPKCS11Wrapper();
	HRESULT loadPKCS11Library(CString szDll);

	HRESULT getLastExtErr();
	CString getLastError();

	BOOL initialize();
	BOOL login(CString szPIN);
	BOOL getUPN(CString& szUPN);
	BOOL getPrivateKey(CString& szPrivateKey);
	BOOL getCertLabel();
	CString hash(void* pClear, int nLen);
	CString getPKCSErrorMsg(CK_RV rv);

	void cleanup();

private:
	CString m_szError;
	HINSTANCE m_hLib;
	HRESULT m_hrExtErr;

	CK_SESSION_HANDLE hSession;
	CK_SLOT_ID_PTR pSlotList;
	CStringArray szArrLabel;
	CString szLabel;

	CK_FUNCTION_LIST_PTR m_pckFuncList = NULL;
	C_GetFunctionList_decl C_GetFunctionList;

	HRESULT checkState();
	HRESULT loadPKCS11Funcs();
	void* loadProc(const char* func);
	void init();
};

#endif