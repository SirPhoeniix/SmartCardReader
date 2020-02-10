# SmartCardReader
## PKCS #11 Library

You have to provide the full path to your PKCS #11 library in the PKCS11Wrapper.cpp file
```c++
BOOL CPKCS11Wrapper::initialize()
{
#ifdef _WIN64
	loadPKCS11Library(_T("C:\\Windows\\System32\\cardos11_64.dll"));
#else
	loadPKCS11Library(_T("C:\\Windows\\System32\\cardos11.dll"));
#endif

...

}
