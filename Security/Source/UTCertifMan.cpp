//=================================================================
//  class: CUT_CertificateManager
//  File:  UTCertifMan.cpp
//
//  Purpose:
//
//	  Certificate managment class
//       
// ===================================================================
// Ultimate TCP/IP v4.2
// This software along with its related components, documentation and files ("The Libraries")
// is © 1994-2007 The Code Project (1612916 Ontario Limited) and use of The Libraries is
// governed by a software license agreement ("Agreement").  Copies of the Agreement are
// available at The Code Project (www.codeproject.com), as part of the package you downloaded
// to obtain this file, or directly from our office.  For a copy of the license governing
// this software, you may contact us at legalaffairs@codeproject.com, or by calling 416-849-8900.
// ===================================================================

#include "stdafx.h"

// Suppress warnings for non-safe str fns. Transitional, for VC6 support.
#pragma warning (push)
#pragma warning (disable : 4996)

#ifdef CUT_SECURE_SOCKET
#include <atlbase.h>
#include <xenroll.h>
#include <certsrv.h> 

#include "UTCertifMan.h"
#include "UTDataSource.h"
#include "UTErr.h"

#include "ut_strop.h"

// ===================================================================
// CUT_CertificateManager class
// ===================================================================


/***********************************************
CUT_CertificateManager
    Constructor
Params
    none
Return
    none
************************************************/
CUT_CertificateManager::CUT_CertificateManager()
{
}

/***********************************************
~CUT_CertificateManager
    Destructor
Params
    none
Return
    none
************************************************/
CUT_CertificateManager::~CUT_CertificateManager()
{
}

/***********************************************
CertificateInstall
	Install cerificate from the file or buffer	    
Params
	lpszData		- pointer to the buffer
	bFileName		- if TRUE lpszData points to the file anme
						otherwise lpszData points to the certificate data
Return
	UTE_SUCCESS
	UTE_ERROR
	UTE_FAILED_CREATE_ICENROLL
	UTE_NULL_PARAM
************************************************/
int CUT_CertificateManager::CertificateInstall(_TCHAR *lpszData, BOOL bFileName)
{
	ICEnroll	*pEnroll = NULL;
	CComBSTR	bstrString(lpszData);
    HRESULT		hr;
	int			nResult = UTE_SUCCESS;

	// Check parameter
	if(lpszData == NULL)
		return UTE_NULL_PARAM;

    // Initialize COM
    hr = CoInitialize( NULL );
    if(FAILED(hr))
        return UTE_ERROR;

    // Create an instance of the Certificate Enrollment object
    hr = CoCreateInstance( CLSID_CEnroll,
                           NULL,
                           CLSCTX_INPROC_SERVER,
                           IID_ICEnroll4,
                           (void **)&pEnroll);


	// If failed try to get the third version of the control
   if(FAILED(hr) || pEnroll == NULL) {
	    hr = CoCreateInstance( CLSID_CEnroll,
                           NULL,
                           CLSCTX_INPROC_SERVER,
                           IID_ICEnroll3,
                           (void **)&pEnroll);
	}
	// If failed try to get the second version of the control
    if(FAILED(hr) || pEnroll == NULL) {
		hr = CoCreateInstance( CLSID_CEnroll,
							   NULL,
							   CLSCTX_INPROC_SERVER,
							   IID_ICEnroll2,
							   (void **)&pEnroll);
	}

	// If failed try to get the first version of the control
    if(FAILED(hr) || pEnroll == NULL)
	{
		hr = CoCreateInstance( CLSID_CEnroll,
							   NULL,
							   CLSCTX_INPROC_SERVER,
							   IID_ICEnroll,
							   (void **)&pEnroll);
	}

    // Check status
    if(FAILED(hr) || pEnroll == NULL)
	{
		// Free COM resources
	    CoUninitialize();
        return UTE_FAILED_CREATE_ICENROLL;
	}

	// Accept certificate from file
	if(bFileName)
		hr = pEnroll->acceptFilePKCS7(bstrString);
	// Accept certificate from buffer
	else
		hr = pEnroll->acceptPKCS7(bstrString);

    // Check status
    if(FAILED(hr))
        nResult = UTE_ERROR;
	
    // Release Certificate Enrollment object
	pEnroll->Release();

    // Free COM resources
    CoUninitialize();

	return nResult;
}

/***********************************************
CertificateRequest
	Prepares the certificate request data and 
	returns it through the buffer or saves it 
	into the file.
Params
	lpszKeyContainerName	- security key container name
    dwStoreLocation			- system store location to look in
								Can be one of:	
								CERT_SYSTEM_STORE_CURRENT_USER 
								CERT_SYSTEM_STORE_CURRENT_SERVICE 
								CERT_SYSTEM_STORE_LOCAL_MACHINE
								CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY
								CERT_SYSTEM_STORE_CURRENT_MACHINE_GROUP_POLICY
								CERT_SYSTEM_STORE_SERVICES 
								CERT_SYSTEM_STORE_USERS
	dwKeySize				- public key size (PUBLIC_KEY_512, PUBLIC_KEY_1024,	PUBLIC_KEY_2048)

	CSR parameters:
	===============
	lpszCommonName			- common name
	lpszOrganization		- organization
	lpszOrganizationUnit	- organization unit
	lpszCountry				- country 

	lpszState				- state
	lpszCity				- city
	lpszGivenName			- given name
	lpszEMail				- email address
	lpszPhone				- phone

	lpszRequestBuffer		- if not NULL return buffer with CSR
  NOTE: this buffer must be delted later using LocalFree function

	lpszFileName			- if not NULL save CSR in specified file

  NOTE:
	Either lpszFileName or lpszRequestBuffer parameters must be not NULLs

Return
    UTE_SUCCESS
	UTE_ERROR
	UTE_NULL_PARAM
	UTE_PARAMETER_TOO_LONG
	UTE_INVALID_CHARS_IN_STRING_PARAM
	UTE_FAILED_CREATE_ICENROLL
	UTE_FILE_OPEN_ERROR
	UTE_FILE_WRITE_ERROR
	UTE_UNSUPPORTED_KEY_SIZE
************************************************/
int CUT_CertificateManager::CertificateRequest(
			_TCHAR	*lpszKeyContainerName,
			DWORD	dwStoreLocation,
			enumPublicKeySize	dwKeySize,
			_TCHAR	*lpszCommonName,
			_TCHAR	*lpszOrganization,
			_TCHAR	*lpszOrganizationUnit,
			_TCHAR	*lpszCountry,
			_TCHAR	*lpszState,
			_TCHAR	*lpszCity,
			_TCHAR	*lpszGivenName,
			_TCHAR	*lpszEMail,
			_TCHAR	*lpszPhone,
			_TCHAR	**lpszRequestBuffer,
			_TCHAR	*lpszFileName)
{
	DWORD		dwKeySizeFlag = 0;
	int			nError = UTE_SUCCESS;
	ICEnroll	*pEnroll = NULL;
	CComBSTR    bstrAttrib(L"");
	CComBSTR	bstrDN;
	HRESULT		hr;

	// ***********************************************
	// ** Test input parameters
	// ***********************************************

	// Key container name is not optional
	if(lpszKeyContainerName == NULL || *lpszKeyContainerName == NULL)
		return UTE_NULL_PARAM;

	// Common name is not optional
	if(lpszCommonName == NULL || *lpszCommonName == NULL)
		return UTE_NULL_PARAM;

	// Buffer pointer or filename must be specified
	if(lpszRequestBuffer == NULL && (lpszFileName == NULL || *lpszFileName == NULL))
		return UTE_NULL_PARAM;

	// Check invalid chars and the length of the parameters
	if(lpszCommonName)
	{
		if(_tcslen(lpszCommonName) > 64)
			return UTE_PARAMETER_TOO_LONG;
		if(!CheckValidChars(lpszCommonName))
			return UTE_INVALID_CHARS_IN_STRING_PARAM;
	}
	if(lpszOrganization)
	{
		if(_tcslen(lpszOrganization) > 64)
			return UTE_PARAMETER_TOO_LONG;
		if(!CheckValidChars(lpszOrganization))
			return UTE_INVALID_CHARS_IN_STRING_PARAM;
	}
	if(lpszOrganizationUnit)
	{
		if(_tcslen(lpszOrganizationUnit) > 64)
			return UTE_PARAMETER_TOO_LONG;
		if(!CheckValidChars(lpszOrganizationUnit))
			return UTE_INVALID_CHARS_IN_STRING_PARAM;
	}
	if(lpszCity)
	{
		if(_tcslen(lpszCity) > 128)
			return UTE_PARAMETER_TOO_LONG;
		if(!CheckValidChars(lpszCity))
			return UTE_INVALID_CHARS_IN_STRING_PARAM;
	}
	if(lpszState)
	{
		if(_tcslen(lpszState) > 128)
			return UTE_PARAMETER_TOO_LONG;
		if(!CheckValidChars(lpszState))
			return UTE_INVALID_CHARS_IN_STRING_PARAM;
	}
	if(lpszCountry)
	{
		if(_tcslen(lpszCountry) > 2)
			return UTE_PARAMETER_TOO_LONG;
		if(!CheckValidChars(lpszCountry))
			return UTE_INVALID_CHARS_IN_STRING_PARAM;
	}


	// ***********************************************
	// ** Create the Certificate Enrollment object
	// ***********************************************

    // Initialize COM
    hr = CoInitialize( NULL );
    if(FAILED(hr))
		return UTE_ERROR;

	
    // Create an instance of the Certificate Enrollment object
    hr = CoCreateInstance( CLSID_CEnroll,
                           NULL,
                           CLSCTX_INPROC_SERVER,
                           IID_ICEnroll4,
                           (void **)&pEnroll);

	// If failed try to get the third version of the control
    if(FAILED(hr) || pEnroll == NULL) {
	    hr = CoCreateInstance( CLSID_CEnroll,
                           NULL,
                           CLSCTX_INPROC_SERVER,
                           IID_ICEnroll3,
                           (void **)&pEnroll);
	}

 	// If failed try to get the second version of the control
    if(FAILED(hr) || pEnroll == NULL) {
		hr = CoCreateInstance( CLSID_CEnroll,
							   NULL,
							   CLSCTX_INPROC_SERVER,
							   IID_ICEnroll2,
							   (void **)&pEnroll);
	}

	// If failed try to get the first version of the control
    if(FAILED(hr) || pEnroll == NULL)
	{
		hr = CoCreateInstance( CLSID_CEnroll,
							   NULL,
							   CLSCTX_INPROC_SERVER,
							   IID_ICEnroll,
							   (void **)&pEnroll);
	}


	// Check status
    if(FAILED(hr) || pEnroll == NULL)
	{
		// Free COM resources 
	    CoUninitialize();
        return UTE_FAILED_CREATE_ICENROLL;
	}

	// ***********************************************
	// ** Set certificate store location
	// ***********************************************
	pEnroll->put_CAStoreFlags(dwStoreLocation);
	pEnroll->put_MyStoreFlags(dwStoreLocation);
	pEnroll->put_RootStoreFlags(dwStoreLocation);

	// ***********************************************
	// ** Create the data for the request.
	// ***********************************************
	bstrDN += L"CN=";
	bstrDN += CComBSTR(lpszCommonName);
	if(lpszOrganization)
		{	bstrDN += L",O=";	bstrDN += CComBSTR(lpszOrganization); }
	if(lpszOrganizationUnit)
		{	bstrDN += L",OU=";	bstrDN += CComBSTR(lpszOrganizationUnit); }
	if(lpszCountry)
		{	bstrDN += L",C=";	bstrDN += CComBSTR(lpszCountry); }
	if(lpszState)
		{	bstrDN += L",S=";	bstrDN += CComBSTR(lpszState); }	
	if(lpszCity)
		{	bstrDN += L",L=";	bstrDN += CComBSTR(lpszCity); }
	if(lpszEMail)
		{	bstrDN += L",E=";	bstrDN += CComBSTR(lpszEMail); }
	if(lpszGivenName)
		{	bstrDN += L",G=";	bstrDN += CComBSTR(lpszGivenName); }
	if(lpszPhone)
		{	
			bstrDN += L",";	
			bstrDN += szOID_TELEPHONE_NUMBER;	
			bstrDN += L"=";	
			bstrDN += CComBSTR(lpszPhone); 
		}

	// Set friendly name
	bstrDN += L",";	
	bstrDN += szOID_PKCS_12_FRIENDLY_NAME_ATTR;	
	bstrDN += L"=";	
	bstrDN += CComBSTR(lpszKeyContainerName); 

	// ***********************************************
	// ** Check available providers
	// ***********************************************
	BOOL	bBaseProviderOnly = TRUE;
	BSTR	bstrProvName = NULL;
	int		nProviderIndex = 0;
	hr = S_OK;
	while(hr == S_OK)
	{
		hr = pEnroll->enumProviders(nProviderIndex, 0, &bstrProvName);
        if( bstrProvName != NULL)
        {
			// Find Enhaced or strong provider
			if(	stricmp(MS_ENHANCED_PROV_A, _bstr_t(bstrProvName)) == 0 ||
				stricmp(MS_STRONG_PROV_A, _bstr_t(bstrProvName)) == 0 	)
			{
				bBaseProviderOnly = FALSE;
			}

			// Free string, so it can be re-used.
			SysFreeString(bstrProvName);
            bstrProvName = NULL;
        }
    
		// Increase provider index
		++nProviderIndex;
	}

	// ***********************************************
	// ** Set key flags
	// ***********************************************

	// Set the public key length
	switch(dwKeySize)
	{	
		case(PUBLIC_KEY_512):	dwKeySizeFlag = 0x02000000;	break;
		case(PUBLIC_KEY_1024):	dwKeySizeFlag = 0x04000000;	break;
		case(PUBLIC_KEY_2048):	dwKeySizeFlag = 0x08000000;	break;
	}
	pEnroll->put_GenKeyFlags(CRYPT_EXPORTABLE | dwKeySizeFlag);

	pEnroll->put_KeySpec(AT_KEYEXCHANGE);

	// ***********************************************
	// ** Set container name
	// ***********************************************
	pEnroll->put_ContainerName(CComBSTR(lpszKeyContainerName));

	// ***********************************************
	// ** Create the certificate request 
	// ***********************************************
	// Create the PKCS #10 in memory1
	BSTR	bstrResult = NULL;
	hr = pEnroll->createPKCS10(bstrDN, CComBSTR(_T("1.3.6.1.5.5.7.3.1")), &bstrResult);
	if(SUCCEEDED(hr))
	{
		_TCHAR	*lpszBuffer = (_TCHAR *)LocalAlloc(LMEM_FIXED, (SysStringLen(bstrResult) + 1024)*sizeof(_TCHAR));
		
		// Add request header
		_tcscpy(lpszBuffer, _T("-----BEGIN NEW CERTIFICATE REQUEST-----\r\n"));
   
		// Copy the request data into the buffer
		_tcscat(lpszBuffer, _bstr_t(bstrResult));

		// Add request footer
		_tcscat(lpszBuffer, _T("-----END NEW CERTIFICATE REQUEST-----"));

		// Save request into the file if needed
		if(lpszFileName != NULL && *lpszFileName != NULL)
		{
			// v4.2 certificate requests will be saved as ANSI
			CUT_File	file;
			if(-1 != file.Open(lpszFileName, GENERIC_WRITE, CREATE_ALWAYS))
			{
				size_t size = _tcslen(lpszBuffer);
				char * lpszAnsiBuffer = new char[size+1];
				CUT_Str::cvtcpy(lpszAnsiBuffer, size+1, lpszBuffer);
				if(file.Write(lpszAnsiBuffer, (DWORD) size) != (DWORD) size)
					nError = UTE_FILE_WRITE_ERROR;
				delete [] lpszAnsiBuffer;
			}
			else
			{
				nError = UTE_FILE_OPEN_ERROR; 
			}
		}

		// Copy data to the memory buffer
		if(lpszRequestBuffer != NULL)
			*lpszRequestBuffer = lpszBuffer;
		else
			delete [] lpszBuffer;

		// Free allocated memory
		if(bstrResult != NULL)
			SysFreeString(bstrResult);
	}
	else
	{
		if(bBaseProviderOnly && dwKeySize != PUBLIC_KEY_512)
			nError = UTE_UNSUPPORTED_KEY_SIZE;
		else
			// v4.2 could improve this with a message based on hr - i.e. object already exists
			nError = UTE_ERROR;
	}

	// Clean up
    pEnroll->Release();

    // Free COM resources
    CoUninitialize();

 	return nError;
}

/***************************************************
CheckValidChars
    Helper function, which checks the valid characters
	in the CSR parameters
PARAM
    string - string to check
RETURN 
    TRUE if all characters are valid
****************************************************/
BOOL CUT_CertificateManager::CheckValidChars(_TCHAR *string)
{
	size_t nPosition = _tcscspn(string, _T("*?;!@#$%^()><&/\\"));
	return (nPosition == _tcslen(string));
}

/***************************************************
GetSystemStoreList
    Get the list of the machine/user system 
	certificates stores
PARAM
    listResult		- return string list of the system stores
	dwStoreLocation	- system store location to look in
						Can be one of:	
						CERT_SYSTEM_STORE_CURRENT_USER 
						CERT_SYSTEM_STORE_CURRENT_SERVICE 
						CERT_SYSTEM_STORE_LOCAL_MACHINE
						CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY
						CERT_SYSTEM_STORE_CURRENT_MACHINE_GROUP_POLICY
						CERT_SYSTEM_STORE_SERVICES 
						CERT_SYSTEM_STORE_USERS
RETURN 
    TRUE if succeded
****************************************************/
BOOL CUT_CertificateManager::GetSystemStoreList(CUT_TStringList &listResult, DWORD dwStoreLocation)
{
	// Clear the resulting list first
	listResult.ClearList();

	// Enumerate the system stores
	return CertEnumSystemStore(dwStoreLocation, NULL, (void *)&listResult, CertEnumSystemStoreCallback);
}

/***************************************************
CertEnumSystemStoreCallback
    System store enumeration callback function.
PARAM
	pvSystemStore	- store name
RETURN 
    TRUE
****************************************************/
BOOL WINAPI CUT_CertificateManager::CertEnumSystemStoreCallback(
			const void *pvSystemStore,           // in
			DWORD /* dwFlags */,                       // in
			PCERT_SYSTEM_STORE_INFO /* pStoreInfo */,  // in
			void * /* pvReserved */,                   // in, optional
			void *pvArg)                         // in, optional
{
	if(pvArg)
	{
// v4.2 changes - previous code all ansi
#if !defined _UNICODE
		// Covert from Unicode to ANSI
		int				nStringSize;
		_TCHAR			*lpszString;
		nStringSize = WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)pvSystemStore, -1, NULL, 0, NULL, NULL);
		lpszString = new char [nStringSize + 1];
		if(WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)pvSystemStore, -1, lpszString, nStringSize, NULL, NULL))
			// Add item into the list
			((CUT_TStringList *)pvArg)->AddString(lpszString);

		// Free memory
		delete [] lpszString;
#else
		((CUT_TStringList *)pvArg)->AddString((LPCWSTR)pvSystemStore);
#endif
	}
	return TRUE;
}


// ===================================================================
// CUT_CertificateStore class
// ===================================================================

/***********************************************
CUT_CertificateStore
    Constructor
Params
    none
Return
    none
************************************************/
CUT_CertificateStore::CUT_CertificateStore() : 
	m_hCertStore(NULL),
	m_dwLocation(0),
	m_lpszName(NULL)
{
	// Open "MY" store on the local machine
	Open(_T("MY"), CERT_SYSTEM_STORE_LOCAL_MACHINE);
}

/***********************************************
CUT_CertificateStore
    Constructor
Params
    lpszStoreName	- store name to open
	dwStoreLocation	- store location
Return
    none
************************************************/
CUT_CertificateStore::CUT_CertificateStore(const _TCHAR *lpszStoreName, DWORD dwStoreLocation) :
	m_hCertStore(NULL),
	m_dwLocation(0),
	m_lpszName(NULL)
{
	// Open specified store
	Open(lpszStoreName, dwStoreLocation);
}

/***********************************************
~CUT_CertificateStore
    Destructor
Params
    none
Return
    none
************************************************/
CUT_CertificateStore::~CUT_CertificateStore()
{
	Close();
}

/***********************************************
Close
    Close opened certificate store
Params
    none
Return
    UTE_SUCCESS
************************************************/
int CUT_CertificateStore::Close()
{
	// Clear certificates list
	CERTCONTEXTVECTOR::iterator it;
	for(it = m_vecCertificates.begin(); it != m_vecCertificates.end(); it++)
		CertFreeCertificateContext(*it);
	m_vecCertificates.clear();

	// Close certificate store
	if(m_hCertStore)
		CertCloseStore(m_hCertStore, 0);
	m_hCertStore = NULL;

	// Free memory
	delete [] m_lpszName;
	m_lpszName = NULL;

	// Clear location
	m_dwLocation = 0;

	return UTE_SUCCESS;
}

/***********************************************
Open
    Close existing and open new certificate store
Params
    lpszStoreName	- store name to open
	dwStoreLocation	- store location
Return
    UTE_SUCCESS
	UTE_PARAMETER_INVALID_VALUE
	UTE_OUT_OF_MEMORY
	UTE_OPEN_CERTIFICATE_STORE_FAILED
************************************************/
int CUT_CertificateStore::Open(const _TCHAR *lpszStoreName, DWORD dwStoreLocation)
{
	PWSTR			pwszStoreName;

	// Close opened store
	Close();

// v4.2 changes - previous code ascii based
#if !defined _UNICODE
	// Convert store name to Unicode
	DWORD			dwStoreNameSize;
	dwStoreNameSize = MultiByteToWideChar(CP_ACP, 0, lpszStoreName, -1, NULL, 0);
	pwszStoreName = (PWSTR)LocalAlloc(LMEM_FIXED, dwStoreNameSize * sizeof(WCHAR));
	if(dwStoreNameSize == NULL)
		return UTE_OUT_OF_MEMORY;
	dwStoreNameSize = MultiByteToWideChar(CP_ACP, 0, lpszStoreName, -1, pwszStoreName, dwStoreNameSize);
	if(dwStoreNameSize == 0) {
		LocalFree(pwszStoreName);
		return UTE_PARAMETER_INVALID_VALUE;
	}
#else
	pwszStoreName = (PWSTR)LocalAlloc(LMEM_FIXED, _tcslen(lpszStoreName) * sizeof(WCHAR) + sizeof(WCHAR));
	_tcscpy(pwszStoreName, lpszStoreName);
#endif

	// Open certificate store
    m_hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, MAKELONG(CERT_STORE_OPEN_EXISTING_FLAG, HIWORD(dwStoreLocation)), pwszStoreName);

	// Free memory
	LocalFree(pwszStoreName);

	// Failed to open the store
    if(!m_hCertStore)
        return UTE_OPEN_CERTIFICATE_STORE_FAILED;

	// Save store name and location
	m_dwLocation = dwStoreLocation;
	m_lpszName = new _TCHAR[_tcslen(lpszStoreName) + 1];
	_tcscpy(m_lpszName, lpszStoreName);

	return UTE_SUCCESS;
}

/***************************************************
DeleteCertificate
    Delete specified certificate from the store.
PARAM
	cert	- certificate to delete
RETURN 
    UTE_SUCCESS
	UTE_ERROR
	UTE_OPEN_CERTIFICATE_STORE_FIRST
	UTE_NULL_PARAM
****************************************************/
int	CUT_CertificateStore::DeleteCertificate(CUT_Certificate *cert)
{
	PCCERT_CONTEXT CertContext = cert->m_CertContext;

	if(cert == NULL)
		return UTE_NULL_PARAM;

	// Check if the certificate store is opened
	if(!m_hCertStore)
		return UTE_OPEN_CERTIFICATE_STORE_FIRST;

	// No certificate context
	if(!CertContext)
		return UTE_ERROR;

	// Clear the certificate 
	cert->m_CertContext = NULL;
	cert->CleanUp();

	// Delete context
	if(!CertDeleteCertificateFromStore(CertContext))
		return UTE_ERROR;

	return UTE_SUCCESS;
}

/***************************************************
ListCertificates
    List the certificates in the store.
	You can use GetCertListSize and GetCertListItem
	functions to access the results
PARAM
	none
RETURN 
    UTE_SUCCESS
	UTE_OPEN_CERTIFICATE_STORE_FIRST
****************************************************/
int	CUT_CertificateStore::ListCertificates()
{
	// Check if the certificate store is opened
	if(!m_hCertStore)
		return UTE_OPEN_CERTIFICATE_STORE_FIRST;

	// Open the certificate store
	PCCERT_CONTEXT	pCertContext = NULL;
	
	// Clear the internal list of certificates
	CERTCONTEXTVECTOR::iterator it;
	for(it = m_vecCertificates.begin(); it != m_vecCertificates.end(); it++)
		CertFreeCertificateContext(*it);
	m_vecCertificates.clear();

	// Fill the internal list of certificates
	do 
	{
		// Enumerate the certificates in the store
		pCertContext = CertEnumCertificatesInStore(m_hCertStore, pCertContext);

		// Add a duplicated copy of the context into the vector
		if(pCertContext)
			m_vecCertificates.push_back(CertDuplicateCertificateContext(pCertContext));

	} while(pCertContext != NULL);

	return UTE_SUCCESS;
}

/***************************************************
GetCertListSize
	Return the size of the internal certificates list
	which was created by ListCertificates function
PARAM
	none
RETURN 
    Certificate list size
****************************************************/
int	CUT_CertificateStore::GetCertListSize()
{
	return (int)m_vecCertificates.size();
}

/***************************************************
GetCertListItem
	Gets an item from the internal certificates list
	which was created by ListCertificates function
PARAM
	nIndex		- item index
	certResult	- certificate list item
RETURN 
    UTE_SUCCESS
	UTE_ERROR
	UTE_OPEN_CERTIFICATE_STORE_FIRST
****************************************************/
int	CUT_CertificateStore::GetCertListItem(int nIndex, CUT_Certificate	&certResult)
{
	// Check if the certificate store is opened
	if(!m_hCertStore)
		return UTE_OPEN_CERTIFICATE_STORE_FIRST;

	if(nIndex >= GetCertListSize())
		return UTE_ERROR;

	certResult.CleanUp();
	certResult.m_CertContext = CertDuplicateCertificateContext(m_vecCertificates[nIndex]);
	return UTE_SUCCESS;
}

/***************************************************
FindCertificate
    Finds unique certificate in store by Serial 
	Number and Issuer
PARAM
	certResult			- certificate class (can have previous result to find next)
	lpszIssuer			- certificate issuer
	lpszSerialNumber	- certificate serial number
RETURN 
    UTE_SUCCESS
	UTE_ERROR
	UTE_OUT_OF_MEMORY
	UTE_PARAMETER_INVALID_VALUE
	UTE_OPEN_CERTIFICATE_STORE_FAILED
	UTE_OPEN_CERTIFICATE_STORE_FIRST
****************************************************/
int	CUT_CertificateStore::FindCertificate(
		CUT_Certificate	&certResult,
		const _TCHAR		*lpszIssuer, 
		const _TCHAR		*lpszSerialNumber)
{
	PCCERT_CONTEXT	pCertContext = NULL;

	// Check if the certificate store is opened
	if(!m_hCertStore)
		return UTE_OPEN_CERTIFICATE_STORE_FIRST;

	// Look through all the certificates
	do 
	{
		// Enumerate the certificates in the store
		pCertContext = CertEnumCertificatesInStore(m_hCertStore, pCertContext);
		if(pCertContext != NULL)
		{
			// Check the certificate serial number & issuer
			CUT_Certificate	cert(pCertContext);
			if(_tcscmp(lpszIssuer, cert.GetIssuer()) == 0 && _tcscmp(lpszSerialNumber, cert.GetSerialNumber()) == 0 )
			{
				certResult.SetContext(pCertContext);
				cert.m_CertContext = NULL;
				return UTE_SUCCESS;
			}

			// Do not release contexr in the certificate class.
			// It will be done in the next call to the CertEnumCertificatesInStore function
			cert.m_CertContext = NULL;
		}
	} while(pCertContext != NULL);

	return UTE_ERROR;
}

/***************************************************
FindCertificate
    Finds first/next certificate context that 
	matches a search criteria
PARAM
	certResult			- certificate class (can have previous result to find next)
	lpszFindParam		- certificate find parameter 
	[dwFindType]		- certificate find type (DEFAULT = CERT_FIND_SUBJECT_STR_A)
RETURN 
    UTE_SUCCESS
	UTE_FAILED
	UTE_OUT_OF_MEMORY
	UTE_PARAMETER_INVALID_VALUE
	UTE_OPEN_CERTIFICATE_STORE_FAILED
	UTE_OPEN_CERTIFICATE_STORE_FIRST
****************************************************/
int	CUT_CertificateStore::FindCertificate(
			CUT_Certificate	&certResult,
			const _TCHAR	*lpszFindParam, 
			DWORD			dwFindType)
{
	PCCERT_CONTEXT	pCertContext = NULL;
	int				nResult = UTE_SUCCESS;

	// Check if the certificate store is opened
	if(!m_hCertStore)
		return UTE_OPEN_CERTIFICATE_STORE_FIRST;

	// Initialize certificate context of the previous call
	PCCERT_CONTEXT	pPrevCertContext = NULL;
	if(certResult.GetContext())
		pPrevCertContext = CertDuplicateCertificateContext(certResult.GetContext());

    // Find certificate.
    pCertContext = CertFindCertificateInStore(m_hCertStore, 
                                              X509_ASN_ENCODING, 
                                              0,
                                              dwFindType,
                                              lpszFindParam,
                                              pPrevCertContext);
	// Certificate not found 
	if(!pCertContext)
		nResult = UTE_ERROR;
	else
		certResult.SetContext(pCertContext);

	return nResult;
}

// ===================================================================
// CUT_Certificate class
// ===================================================================

/***********************************************
CUT_Certificate
    Constructor
Params
    none
Return
    none
************************************************/
CUT_Certificate::CUT_Certificate() : 
	m_CertContext(NULL),
	m_lpszSerialNumber(NULL),
	m_lpszIssuer(NULL),
	m_lpszIssuedTo(NULL),
	m_lpszSubject(NULL),
	m_lpszKeyAlgId(NULL),
	m_lpszKey(NULL),
	m_lpszSignatureAlgId(NULL)
{
	// Initialize empty string
	m_szEmptyString[0] = NULL;
	m_szEmptyKey[0] = NULL;

}


/***********************************************
CUT_Certificate
    Constructor
Params
    none
Return
    none
************************************************/
CUT_Certificate::CUT_Certificate(PCCERT_CONTEXT CertContext) : 
	m_CertContext(CertContext),
	m_lpszSerialNumber(NULL),
	m_lpszIssuer(NULL),
	m_lpszIssuedTo(NULL),
	m_lpszSubject(NULL),
	m_lpszKeyAlgId(NULL),
	m_lpszKey(NULL),
	m_lpszSignatureAlgId(NULL)
{
	// Initialize empty string
	m_szEmptyString[0] = NULL;
	m_szEmptyKey[0] = NULL;

}

/***********************************************
CUT_Certificate
    Copy constructor
Params
    none
Return
    none
************************************************/
CUT_Certificate::CUT_Certificate(const CUT_Certificate &cert) : 
	m_CertContext(NULL),
	m_lpszSerialNumber(NULL),
	m_lpszIssuer(NULL),
	m_lpszIssuedTo(NULL),
	m_lpszSubject(NULL),
	m_lpszKeyAlgId(NULL),
	m_lpszKey(NULL),
	m_lpszSignatureAlgId(NULL)
{
	// Initialize empty string
	m_szEmptyString[0] = NULL;
	m_szEmptyKey[0] = NULL;

	// Duplicate certificate context
	m_CertContext = CertDuplicateCertificateContext(cert.m_CertContext);
}

/***********************************************
operator=
    Assignment operator
Params
    const CUT_Certificate &
Return
	CUT_Certificate &    
************************************************/
CUT_Certificate &CUT_Certificate::operator=(const CUT_Certificate &cert)
{
	// Check foe self assignment
	if(&cert == this)
		return *this;

	// Release all memory and handles
	CleanUp();

	// Duplicate certificate context
	m_CertContext = CertDuplicateCertificateContext(cert.m_CertContext);

	return *this;
}
/***********************************************
~CUT_Certificate
    Destructor
Params
    none
Return
    none
************************************************/
CUT_Certificate::~CUT_Certificate()
{
	CleanUp();
}

/***********************************************
CleanUp
    Frees allocated memory and handles
Params
    none
Return
    none
************************************************/
void CUT_Certificate::CleanUp()
{
	// Delete allocated strings memory
	if(m_lpszSerialNumber)	{	delete [] m_lpszSerialNumber;	m_lpszSerialNumber = NULL;	}
	if(m_lpszIssuer)		{	delete [] m_lpszIssuer;			m_lpszIssuer = NULL;		}
	if(m_lpszSubject)		{	delete [] m_lpszSubject;		m_lpszSubject = NULL;		}
	if(m_lpszKeyAlgId)		{	delete [] m_lpszKeyAlgId;		m_lpszKeyAlgId = NULL;		}
	if(m_lpszKey)			{	delete [] m_lpszKey;			m_lpszKey = NULL;			}
	if(m_lpszIssuedTo)		{	delete [] m_lpszIssuedTo;		m_lpszIssuedTo = NULL;		}
	if(m_lpszSignatureAlgId){	delete [] m_lpszSignatureAlgId;	m_lpszSignatureAlgId = NULL;}
	
	// Free certificate context
	if(m_CertContext != NULL)
	{
		CertFreeCertificateContext(m_CertContext);
		m_CertContext = NULL;
	}
}

/***********************************************
VerifyTime
    Verifies the time validity of a certificate
Params
    [pTimeToVerify]	- Optional comparison time. 
					If NULL, the current time is used
Return
	0	- valid
	-1	- certificate is not valid yet ( < ValidFrom)
	+1	- certificate already not valid  ( > ValidTo)
************************************************/
int CUT_Certificate::VerifyTime(LPFILETIME pTimeToVerify)
{
	if(m_CertContext == NULL) return -1;
	return CertVerifyTimeValidity(pTimeToVerify, m_CertContext->pCertInfo);
}

/***********************************************
BinaryToString
    Returns the certificate security context
Params
    ptrData		- pointer to the data
	dwDataSize	- size of the data to convert
Return
    Pointer to the converted string format
	12 A4 FF ...
************************************************/
_TCHAR *CUT_Certificate::BinaryToString(void *ptrData, DWORD dwDataSize)
{
	TCHAR	*lpszResultString = new _TCHAR[dwDataSize*3 + 1];
	DWORD	dwCurInPos = 0, dwCurOutPos = 0;

	*lpszResultString = NULL;

	for(dwCurInPos = 0; dwCurInPos < dwDataSize; dwCurInPos)
	{
		// Add space between numbers
		if(dwCurInPos != 0)
			*(lpszResultString + (dwCurOutPos++)) = _T(' ');

		unsigned char	c = *(((char*)ptrData) + dwCurInPos);
		_stprintf((lpszResultString + dwCurOutPos), _T("%02X"), c); 
		++dwCurInPos;
		dwCurOutPos += 2;
	}

	return lpszResultString;
}

/***********************************************
GetContext
    Returns the certificate security context
Params
    none
Return
    certificate security context pointer or
	NULL if we don't have any
************************************************/
PCCERT_CONTEXT CUT_Certificate::GetContext()
{
	return m_CertContext;
}

/***********************************************
SetContext
    Sets new certificate context. Frees the 
	previous certificate context.
Params
    newCertContext - new certificate context 
Return
    none
************************************************/
void CUT_Certificate::SetContext(PCCERT_CONTEXT newCertContext)
{
	// Free memory and context
	CleanUp();

	// Set new context
	m_CertContext = newCertContext;
}

/***********************************************
GetVersion
    Returns the certificate version number
Params
    none
Return
	Version number CERT_V1, CERT_V2, CERT_V3 or
	-1 if error
************************************************/
DWORD CUT_Certificate::GetVersion()
{
	return (m_CertContext != NULL) ? m_CertContext->pCertInfo->dwVersion : -1;
}

/***********************************************
GetSerialNumber
    Returns the certificate serial number
Params
    none
Return
	Pointer to the serial number string
************************************************/
const _TCHAR *CUT_Certificate::GetSerialNumber() 
{ 
	// Return empty string if the certificate context is not set
	if(!m_CertContext)
		return m_szEmptyString;

	// Check if we already have the serial number string
	if(m_lpszSerialNumber)
		return m_lpszSerialNumber;

	// Convert binary serial number to the hex string
	m_lpszSerialNumber = BinaryToString(m_CertContext->pCertInfo->SerialNumber.pbData, m_CertContext->pCertInfo->SerialNumber.cbData);
	return m_lpszSerialNumber;
}

/***********************************************
GetIssuer
    Returns the certificate issuer
Params
    none
Return
	Pointer to the issuer string
************************************************/
const _TCHAR *CUT_Certificate::GetIssuer()
{ 
	// Return empty string if the certificate context is not set
	if(!m_CertContext)
		return m_szEmptyString;

	// Check if we already have this data
	if(m_lpszIssuer)
		return m_lpszIssuer;

	// Allocate memory and convert string
	DWORD dwSize = CertGetNameString(m_CertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG , 0, 0, 0);
	m_lpszIssuer = new _TCHAR[dwSize + 1];
	CertGetNameString(	m_CertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE,
						CERT_NAME_ISSUER_FLAG , 0, m_lpszIssuer, dwSize);

	return m_lpszIssuer;
}

/***********************************************
GetIssuedTo
    Returns the certificate issued to
Params
    none
Return
	Pointer to the issuer string
************************************************/
const _TCHAR *CUT_Certificate::GetIssuedTo()
{ 
	// Return empty string if the certificate context is not set
	if(!m_CertContext)
		return m_szEmptyString;

	// Check if we already have this data
	if(m_lpszIssuedTo)
		return m_lpszIssuedTo;

	// Allocate memory and convert string
	DWORD dwSize = CertGetNameString(m_CertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, 0, 0, 0);
	m_lpszIssuedTo = new _TCHAR[dwSize + 1];
	CertGetNameString(	m_CertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE,
						0, 0, m_lpszIssuedTo, dwSize);

	return m_lpszIssuedTo;
}

/***********************************************
GetSubject
    Returns the certificate subject
Params
    none
Return
	Pointer to the issuer string
************************************************/
const _TCHAR *CUT_Certificate::GetSubject()
{ 
	// Return empty string if the certificate context is not set
	if(!m_CertContext)
		return m_szEmptyString;

	// Check if we already have this data
	if(m_lpszSubject)
		return m_lpszSubject;

	// Allocate memory and convert string
	m_lpszSubject = new _TCHAR[1024];
	CertNameToStr(	m_CertContext->dwCertEncodingType, 
					&m_CertContext->pCertInfo->Subject,
					CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG | CERT_NAME_STR_REVERSE_FLAG,
					m_lpszSubject, 1024);

	return m_lpszSubject;
}

/***********************************************
GetValidFrom
    Get certificate valid from time
Params
    none
Return
	FILETIME structure
************************************************/
FILETIME CUT_Certificate::GetValidFrom()
{ 
	FILETIME	none = { 0, 0 };
	return (m_CertContext != NULL) ? m_CertContext->pCertInfo->NotBefore : none;
}

/***********************************************
GetValidTo
    Get certificate valid to time
Params
    none
Return
	FILETIME structure
************************************************/
FILETIME CUT_Certificate::GetValidTo()
{ 
	FILETIME	none = { 0, 0 };
	return (m_CertContext != NULL) ? m_CertContext->pCertInfo->NotAfter : none;
}

/***********************************************
GetKeySize
    Get certificate key size
Params
    none
Return
	Key size in bits
************************************************/
DWORD CUT_Certificate::GetKeySize()
{ 
	return (m_CertContext != NULL) ? CertGetPublicKeyLength(X509_ASN_ENCODING, &m_CertContext->pCertInfo->SubjectPublicKeyInfo) : 0;
}

/***********************************************
GetKeyUsage 
    Get certificate key usage
Params
    none
Return
	Key usage byte. Can be one or many of:
	
		CERT_DIGITAL_SIGNATURE_KEY_USAGE     
		CERT_NON_REPUDIATION_KEY_USAGE       
		CERT_KEY_ENCIPHERMENT_KEY_USAGE      
		CERT_DATA_ENCIPHERMENT_KEY_USAGE     
		CERT_KEY_AGREEMENT_KEY_USAGE         
		CERT_KEY_CERT_SIGN_KEY_USAGE         
		CERT_OFFLINE_CRL_SIGN_KEY_USAGE      
		CERT_CRL_SIGN_KEY_USAGE              
		CERT_ENCIPHER_ONLY_KEY_USAGE         

	Enhanced Key Usage Purpose:

	szOID_PKIX_KP_SERVER_AUTH		DIGITAL_SIGNATURE and KEY_ENCIPHERMENT and KEY_AGREEMENT
	szOID_PKIX_KP_CLIENT_AUTH		DIGITAL_SIGNATURE
	szOID_PKIX_KP_CODE_SIGNING		DIGITAL_SIGNATURE
	szOID_PKIX_KP_EMAIL_PROTECTION	DIGITAL_SIGNATURE, NON_REPUDIATION and/or (KEY_ENCIPHERMENT or KEY_AGREEMENT)
	szOID_PKIX_KP_IPSEC_END_SYSTEM	DIGITAL_SIGNATURE and/or (KEY_ENCIPHERMENT or KEY_AGREEMENT)
	szOID_PKIX_KP_IPSEC_TUNNEL		DIGITAL_SIGNATURE and/or (KEY_ENCIPHERMENT or KEY_AGREEMENT)
	szOID_PKIX_KP_IPSEC_USER		DIGITAL_SIGNATURE and/or (KEY_ENCIPHERMENT or KEY_AGREEMENT)
	szOID_PKIX_KP_TIMESTAMP_SIGNING	DIGITAL_SIGNATURE or NON_REPUDIATION

************************************************/
BYTE CUT_Certificate::GetKeyUsage()
{ 
	BYTE	byteResult = 0;
	if(m_CertContext)
		CertGetIntendedKeyUsage(X509_ASN_ENCODING, m_CertContext->pCertInfo, &byteResult, 1);
	return byteResult;
}

/***********************************************
GetKeyAlgId
    Get certificate key algoritm ID string
Params
    none
Return
	Key algorithm ID
************************************************/
const _TCHAR *CUT_Certificate::GetKeyAlgId()
{ 
	// Return empty string if the certificate context is not set
	if(!m_CertContext)
		return m_szEmptyString;

	// Check if we already have the serial number string
	if(m_lpszKeyAlgId)
		return m_lpszKeyAlgId;

	// Get algoritm information
	PCCRYPT_OID_INFO pInfo = CryptFindOIDInfo(	CRYPT_OID_INFO_OID_KEY, 
				m_CertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId, 
				0);

	if(pInfo)
	{
// v4/2 changes - previous code all ascii
#if !defined _UNICODE
		// Convert name from unicode to ansi
		int nStringSize = WideCharToMultiByte(CP_ACP, 0, pInfo->pwszName, -1, NULL, 0, NULL, NULL);
		m_lpszKeyAlgId = new _TCHAR [nStringSize + 1];
		*m_lpszKeyAlgId = NULL;
		WideCharToMultiByte(CP_ACP, 0, pInfo->pwszName, -1, m_lpszKeyAlgId, nStringSize, NULL, NULL);
#else
		m_lpszKeyAlgId = new _TCHAR [_tcslen(pInfo->pwszName) + 1];
		_tcscpy(m_lpszKeyAlgId, pInfo->pwszName);
#endif
	}
	else
	{
		return m_szEmptyString;
	}
		
	return m_lpszKeyAlgId;
}

/***********************************************
GetSignatureAlgId
    Get certificate Signature algoritm ID string
Params
    none
Return
	Key algorithm ID
************************************************/
const _TCHAR *CUT_Certificate::GetSignatureAlgId()
{ 
	// Return empty string if the certificate context is not set
	if(!m_CertContext)
		return m_szEmptyString;

	// Check if we already have the serial number string
	if(m_lpszSignatureAlgId)
		return m_lpszSignatureAlgId;

	// Get algoritm information
	PCCRYPT_OID_INFO pInfo = CryptFindOIDInfo(	CRYPT_OID_INFO_OID_KEY, 
				m_CertContext->pCertInfo->SignatureAlgorithm.pszObjId, 
				0);

	if(pInfo)
	{
// v4.2 changes - previous code ascii
#if !defined _UNICODE
		// Convert name from unicode to ansi
		int nStringSize = WideCharToMultiByte(CP_ACP, 0, pInfo->pwszName, -1, NULL, 0, NULL, NULL);
		m_lpszSignatureAlgId = new _TCHAR [nStringSize + 1];
		*m_lpszSignatureAlgId = NULL;
		WideCharToMultiByte(CP_ACP, 0, pInfo->pwszName, -1, m_lpszSignatureAlgId, nStringSize, NULL, NULL);
#else
		m_lpszSignatureAlgId = new _TCHAR [_tcslen(pInfo->pwszName) + 1];
		_tcscpy(m_lpszSignatureAlgId, pInfo->pwszName);
#endif
	}
	else
	{
		return m_szEmptyString;
	}
		
	return m_lpszSignatureAlgId;
}

/***********************************************
GetKey
    Get certificate key 
Params
    none
Return
	Certificate key ("3A 7F 68 A5 ...")
************************************************/
const _TCHAR *CUT_Certificate::GetKey()
{ 
	// Return empty string if the certificate context is not set
	if(!m_CertContext)
		return m_szEmptyKey;

	// Check if we already have the serial number string
	if(m_lpszKey)
		return m_lpszKey;

	// Convert binary serial number to the hex string
	m_lpszKey = BinaryToString(m_CertContext->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData, m_CertContext->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData);
	return m_lpszKey;
}

#endif // CUT_SECURE_SOCKET

#pragma warning (pop)