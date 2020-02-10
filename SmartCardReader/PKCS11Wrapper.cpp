#include "stdafx.h"
#include "PKCS11Wrapper.h"
//#include "Registry.h"


CPKCS11Wrapper::CPKCS11Wrapper()
{
	init();
}

CPKCS11Wrapper::CPKCS11Wrapper(CString szDll)
{
	init();
	loadPKCS11Library(szDll);
}

CPKCS11Wrapper::~CPKCS11Wrapper()
{
	cleanup();
}

HRESULT CPKCS11Wrapper::loadPKCS11Library(CString szDll)
{
	m_hLib = LoadLibrary(szDll);
	HRESULT hRet = PKCS_OK;
	if (!m_hLib)
	{
		m_hrExtErr = GetLastError();
		m_szError.Format(_T("Failed to load DLL %s"), szDll);
		return PKCS_DLL_NOT_LOADED;
	}
	else
	{
		hRet = loadPKCS11Funcs();
		if (hRet == PKCS_OK)
		{
			CK_RV rv = m_pckFuncList->C_Initialize(NULL_PTR);
			if (rv != CKR_OK)
			{
				hRet = PKCS_INITIALIZATION_FAILED;
			}
		}
	}
	return hRet;
}

HRESULT CPKCS11Wrapper::getLastExtErr()
{
	return m_hrExtErr;
}

CString CPKCS11Wrapper::getLastError()
{
	return m_szError;
}

HRESULT CPKCS11Wrapper::checkState()
{
	if (!m_hLib)
	{
		return PKCS_DLL_NOT_LOADED;
	}
	return PKCS_OK;
}

void* CPKCS11Wrapper::loadProc(const char* func)
{
	void *pFunc = (void *)GetProcAddress(m_hLib, func);
	if (!pFunc)
	{
		m_hrExtErr = GetLastError();
		m_szError.Format(_T("Failed to load function '%s'"), func);
	}
	return pFunc;
}

HRESULT CPKCS11Wrapper::loadPKCS11Funcs()
{

	if (!(void*)(C_GetFunctionList = (C_GetFunctionList_decl)loadProc("C_GetFunctionList")))
	{
		cleanup();
		return PKCS_FUNCTION_NOT_LOADED;
	}
	C_GetFunctionList(&m_pckFuncList);

	return PKCS_OK;
}

void CPKCS11Wrapper::init()
{
	m_szError = _T("");
	m_hrExtErr = NULL;
	m_hLib = NULL;
}

void CPKCS11Wrapper::cleanup()
{
	m_pckFuncList = NULL;
	if (m_hLib)
	{
		FreeLibrary(m_hLib);
	}
	pSlotList = NULL;
	free(pSlotList);
}

BOOL CPKCS11Wrapper::initialize()
{
#ifdef _WIN64
	loadPKCS11Library(_T("C:\\Windows\\System32\\cardos11_64.dll"));
#else
	loadPKCS11Library(_T("C:\\Windows\\System32\\cardos11.dll"));
#endif

	CK_RV rv;
	CK_ULONG ulCount;
	rv = m_pckFuncList->C_GetSlotList(TRUE, NULL_PTR, &ulCount);

	if ((rv == CKR_OK) && (ulCount > 0))
	{
		pSlotList = (CK_SLOT_ID_PTR)malloc(ulCount*sizeof(CK_SLOT_ID));
		rv = m_pckFuncList->C_GetSlotList(TRUE, pSlotList, &ulCount);
		
		CK_RV rv;
		rv = m_pckFuncList->C_OpenSession(pSlotList[0], CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession);
		if (rv == CKR_OK)
		{
			return TRUE;
		}
		m_szError.Format(_T("Failed to open session. %s"), getPKCSErrorMsg(rv));
		return FALSE;
	}
	else if (rv != CKR_OK)
	{
		m_szError.Format(_T("Failed to get slot list. %s"), getPKCSErrorMsg(rv));
		return FALSE;
	}
	m_szError.Format(_T("No token present"));
	return FALSE;
}

BOOL CPKCS11Wrapper::login(CString szPIN)
{
	CK_RV rv;
	const TCHAR* pcPIN = (LPCTSTR)szPIN;
	CK_UTF8CHAR userPIN[] = { "00000000" };
	for (int i = 0; i < sizeof(pcPIN); i++)
	{
		userPIN[i] = pcPIN[i];
	}
	int nLen = (int)strlen((const char*)userPIN);
	rv = m_pckFuncList->C_Login(hSession, CKU_USER, userPIN, nLen);
	if (rv == CKR_OK)
	{
		return TRUE;
	}
	m_szError.Format(_T("Failed to login. %s"), getPKCSErrorMsg(rv));
	return FALSE;
}

BOOL CPKCS11Wrapper::getUPN(CString& szUPN)
{
	if (!getCertLabel())
	{
		return FALSE;
	}

	CK_RV rv;
	CK_ULONG nObjectCount;
	CK_OBJECT_HANDLE hObject;
	CK_OBJECT_CLASS keyClass = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE certType = CKC_X_509;

	if (szArrLabel.GetCount() == 0)
	{
		m_szError.Format(_T("Failed to find certificate on token"));
	}

	for (int k = 0; k < szArrLabel.GetCount(); k++)
	{
		CString szCurrentLabel = szArrLabel.GetAt(k);

		CK_ATTRIBUTE pFindTemplate[] = {
			{ CKA_CLASS, &keyClass, sizeof(keyClass) }
		};

		rv = m_pckFuncList->C_FindObjectsInit(hSession, pFindTemplate, 1);
		if (rv == CKR_OK)
		{
			while (1)
			{
				char* pcValue;
				CK_ATTRIBUTE pAttrTemplate[] =
				{
					{ CKA_VALUE, NULL_PTR, 0 }
				};

				rv = m_pckFuncList->C_FindObjects(hSession, &hObject, 1, &nObjectCount);
				if (nObjectCount == 0)
				{
					break;
				}
				if (rv != CKR_OK)
				{
					m_szError.Format(_T("%s"), getPKCSErrorMsg(rv));
					return FALSE;
				}
				else
				{
					szLabel = szCurrentLabel;
					rv = m_pckFuncList->C_GetAttributeValue(hSession, hObject, pAttrTemplate, 1);
					if (rv == CKR_OK)
					{
						pAttrTemplate[0].pValue = (CK_BYTE_PTR)malloc(pAttrTemplate[0].ulValueLen);

						rv = m_pckFuncList->C_GetAttributeValue(hSession, hObject, pAttrTemplate, 1);
						if (rv == CKR_OK)
						{
							pcValue = (char*)calloc(pAttrTemplate[0].ulValueLen + 1, sizeof(char));
							memcpy(pcValue, pAttrTemplate[0].pValue, pAttrTemplate[0].ulValueLen);
							PCCERT_CONTEXT pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, (const BYTE*)pcValue, pAttrTemplate[0].ulValueLen);
							BYTE* pCertKeyUsage = new BYTE[1];
							BOOL bRet = CertGetIntendedKeyUsage(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, pCertContext->pCertInfo, pCertKeyUsage, 1);
							if (bRet)
							{
								//Registry* reg = new Registry(HKEY_CURRENT_USER, _T("Software\\SmartCardReader"), KEY_ALL_ACCESS | KEY_WOW64_64KEY, TRUE);
								//CString szExpKeyUsage = reg->GetString(_T("SCFilterKeyUsage "), _T(""));
								CString szExpKeyUsage = _T("a0");
								wchar_t* end = NULL;
								BYTE bExpKeyUsage = wcstol(szExpKeyUsage, &end, 16);

								if (pCertKeyUsage[0] == bExpKeyUsage)
								{
									DWORD pCertNameString = NULL;
									char pszNameString[256];
									pCertNameString = CertGetNameString(pCertContext, CERT_NAME_UPN_TYPE, NULL, 0, (LPTSTR)pszNameString, 256);
									CString szRet = _T("");
									szRet.Format(_T("%s"), pszNameString);
									rv = m_pckFuncList->C_FindObjectsFinal(hSession);
									szUPN = szRet;
									return TRUE;
								}
							}
							m_szError.Format(_T("Failed to get IntendedKeyUsage"));
							return FALSE;
						}
						m_szError.Format(_T("%s"), getPKCSErrorMsg(rv));
						return FALSE;
					}
					m_szError.Format(_T("%s"), getPKCSErrorMsg(rv));
					return FALSE;
				}
			}
			rv = m_pckFuncList->C_FindObjectsFinal(hSession);
		}
		m_szError.Format(_T("%s"), getPKCSErrorMsg(rv));
	}
	return FALSE;
}

BOOL CPKCS11Wrapper::getPrivateKey(CString& szPrivateKey)
{
	CK_RV rv;
	CK_ULONG nObjectCount;
	CK_OBJECT_HANDLE hObject;
	CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
	CK_ATTRIBUTE pFindTemplate[] = {
		{ CKA_CLASS, &keyClass, sizeof(keyClass) }
	};
	CString szUPN = _T("");
	getUPN(szUPN);

	rv = m_pckFuncList->C_FindObjectsInit(hSession, pFindTemplate, 1);
	if (rv == CKR_OK)
	{
		while (1)
		{
			rv = m_pckFuncList->C_FindObjects(hSession, &hObject, 1, &nObjectCount);
			if (nObjectCount == 0)
			{
				break;
			}
			if (rv != CKR_OK)
			{
				m_szError.Format(_T("%s"), getPKCSErrorMsg(rv));
				return FALSE;
			}
			else
			{
				CK_BYTE_PTR pPart = new CK_BYTE[8192];
				CK_MECHANISM mechanism = {
					CKM_RSA_PKCS, NULL_PTR, 0
				};

				CK_ATTRIBUTE pAttrTemplate[] = {
					{ CKA_LABEL, NULL_PTR, 0 }
				};
				char* pcLabel;
				rv = m_pckFuncList->C_GetAttributeValue(hSession, hObject, pAttrTemplate, 1);
				if (rv == CKR_OK)
				{
					pAttrTemplate[0].pValue = (CK_BYTE_PTR)malloc(pAttrTemplate[0].ulValueLen);
					rv = m_pckFuncList->C_GetAttributeValue(hSession, hObject, pAttrTemplate, 1);
					if (rv == CKR_OK)
					{
						pcLabel = (char*)calloc(pAttrTemplate[0].ulValueLen + 1, sizeof(char));
						memcpy(pcLabel, pAttrTemplate[0].pValue, pAttrTemplate[0].ulValueLen);

						for (int i = 0; i < szArrLabel.GetCount(); i++)
						{
							if (szArrLabel.GetAt(i) == (CString)pcLabel && szUPN.GetLength() > 0)
							{
								int nAllocLen = szUPN.GetLength() * sizeof(szUPN.GetAt(0));
								CK_BYTE_PTR pszUPN = new BYTE[nAllocLen];
								memcpy_s(pszUPN, nAllocLen, szUPN.GetBuffer(szUPN.GetLength()), nAllocLen);
								rv = m_pckFuncList->C_SignInit(hSession, &mechanism, hObject);
								if (rv == CKR_OK)
								{
									CK_ULONG ulSignLen;
									rv = m_pckFuncList->C_Sign(hSession, pszUPN, nAllocLen, pPart, &ulSignLen);

									CString szHash = hash((void*)pPart, ulSignLen);
									szPrivateKey = szHash;
								}
							}
						}
					}
					else
					{
						m_szError.Format(_T("%s"), getPKCSErrorMsg(rv));
						return FALSE;
					}
				}
				else
				{
					m_szError.Format(_T("%s"), getPKCSErrorMsg(rv));
					return FALSE;
				}
			}
		}
		rv = m_pckFuncList->C_FindObjectsFinal(hSession);
	}
	if (szPrivateKey.GetLength() == 0)
	{
		m_szError.Format(_T("Failed to find private key"));
		return FALSE;
	}
	return TRUE;
}

BOOL CPKCS11Wrapper::getCertLabel()
{
	CK_RV rv;
	CK_ULONG nObjectCount;
	CK_OBJECT_HANDLE hObject;
	CK_OBJECT_CLASS keyClass = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE certType = CKC_X_509;
	CK_ATTRIBUTE pFindTemplate[] = {
		{ CKA_CLASS, &keyClass, sizeof(keyClass) },
		{ CKA_CERTIFICATE_TYPE, &certType, sizeof(certType) }
	};

	rv = m_pckFuncList->C_FindObjectsInit(hSession, pFindTemplate, 2);
	if (rv == CKR_OK)
	{
		while (1)
		{
			char* pcLabel;
			CK_ATTRIBUTE pAttrTemplate[] =
			{
				{ CKA_LABEL, NULL_PTR, 0 }
			};

			rv = m_pckFuncList->C_FindObjects(hSession, &hObject, 1, &nObjectCount);
			if (nObjectCount == 0)
			{
				break;
			}
			else if (rv != CKR_OK)
			{
				m_szError.Format(_T("%s"), getPKCSErrorMsg(rv));
				return FALSE;
			}
			else
			{
				rv = m_pckFuncList->C_GetAttributeValue(hSession, hObject, pAttrTemplate, 1);
				if (rv == CKR_OK)
				{
					pAttrTemplate[0].pValue = (CK_BYTE_PTR)malloc(pAttrTemplate[0].ulValueLen);
					rv = m_pckFuncList->C_GetAttributeValue(hSession, hObject, pAttrTemplate, 1);
					if (rv == CKR_OK)
					{
						pcLabel = (char*)calloc(pAttrTemplate[0].ulValueLen + 1, sizeof(char));
						memcpy(pcLabel, pAttrTemplate[0].pValue, pAttrTemplate[0].ulValueLen);
						szArrLabel.Add((CString)pcLabel);
					}
					else
					{
						m_szError.Format(_T("%s"), getPKCSErrorMsg(rv));
						return FALSE;
					}

				}
				else
				{
					m_szError.Format(_T("%s"), getPKCSErrorMsg(rv));
					return FALSE;
				}
			}
		}
		rv = m_pckFuncList->C_FindObjectsFinal(hSession);
	}
	else
	{
		m_szError.Format(_T("%s"), getPKCSErrorMsg(rv));
		return FALSE;
	}
	return TRUE;
}

CString CPKCS11Wrapper::hash(void* pClear, int nLen)
{
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, pClear, nLen);
	SHA256_Final(hash, &sha256);
	CString szHash = _T("");
	CString szTemp = _T("");

	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
	{
		szTemp.Format(_T("%02x"), hash[i]);
		szHash += szTemp;
	}
	szHash.MakeUpper();
	return szHash;
}

CString CPKCS11Wrapper::getPKCSErrorMsg(CK_RV rv)
{
	CString szError = _T("");
	if (rv == CKR_PIN_EXPIRED)
	{
		szError.Format(_T("An error occured while accessing the smart card. Pin expired. Error code 0x%08x"), rv);
	}
	else if (rv == CKR_PIN_INCORRECT)
	{
		szError.Format(_T("An error occured while accessing the smart card. Pin incorrect. Error code 0x%08x"), rv);
	}
	else if (rv == CKR_PIN_INVALID)
	{
		szError.Format(_T("An error occured while accessing the smart card. Pin invalid. Error code 0x%08x"), rv);
	}
	else if (rv == CKR_PIN_LOCKED)
	{
		szError.Format(_T("An error occured while accessing the smart card. Pin locked. Error code 0x%08x"), rv);
	}
	else if (rv == CKR_SLOT_ID_INVALID)
	{
		szError.Format(_T("An error occured while accessing the smart card. Slot ID invalid. Error code 0x%08x"), rv);
	}
	else
	{
		szError.Format(_T("An error occured while accessing the smart card. Error code 0x%08x"), rv);
	}
	return szError;
}