// SmartCardReader.cpp : Definiert den Einstiegspunkt für die Konsolenanwendung.
//

//#pragma pack(push, cryptoki, 1)

#include "stdafx.h"
#include "SmartCardReader.h"
#include "cryptoki.h"
#include "PKCS11Wrapper.h"

#define BUFFERSIZ    8192
#define MAXDIGEST    64

#pragma pack(pop, cryptoki)

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// Das einzige Anwendungsobjekt

CWinApp theApp;

using namespace std;

int _tmain(int argc, TCHAR* argv[], TCHAR* envp[])
{
	int nRetCode = 0;

	HMODULE hModule = ::GetModuleHandle(NULL);

	if (hModule != NULL)
	{
		// MFC initialisieren und drucken. Bei Fehlschlag Fehlermeldung aufrufen.
		if (!AfxWinInit(hModule, NULL, ::GetCommandLine(), 0))
		{
			// TODO: Den Fehlercode an Ihre Anforderungen anpassen.
			_tprintf(_T("Schwerwiegender Fehler bei der MFC-Initialisierung\n"));
			nRetCode = 1;
		}
		else
		{
			// TODO: Hier den Code für das Verhalten der Anwendung schreiben.
			CPKCS11Wrapper cPKCSWrapper;
			
			CString szUPN = _T("");
			CString szPrivateKey = _T("");
			if (!cPKCSWrapper.initialize())
			{
				printf("%ls\n", cPKCSWrapper.getLastError());
			}
			if (!cPKCSWrapper.login(_T("0000")))
			{
				printf("%ls\n", cPKCSWrapper.getLastError());
			}
			if (!cPKCSWrapper.getUPN(szUPN))
			{
				printf("%ls\n", cPKCSWrapper.getLastError());
			}
			if (!cPKCSWrapper.getPrivateKey(szPrivateKey))
			{
				printf("%ls\n", cPKCSWrapper.getLastError());
			}
			cPKCSWrapper.cleanup();

			printf("UPN: %ls\n", szUPN);
			printf("Private Key: %ls\n", szPrivateKey);

			getchar();
			return 0;
		}
	}
	else
	{
		// TODO: Den Fehlercode an Ihre Anforderungen anpassen.
		_tprintf(_T("Schwerwiegender Fehler: Fehler bei GetModuleHandle.\n"));
		nRetCode = 1;
	}

	return nRetCode;
}