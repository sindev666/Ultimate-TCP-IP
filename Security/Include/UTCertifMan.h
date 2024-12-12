// =================================================================
//  class: CUT_CertificateManager
//  File:  UTCertifMan.h
//  
//  Purpose:
//
//	  Certificate, certificate store and certificate managment classes
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

#ifndef INCLUDECUT_SERTIFMAN
#define INCLUDECUT_SERTIFMAN

#ifdef CUT_SECURE_SOCKET

#define SECURITY_WIN32

#include <sspi.h>

// Check if the required SDK installed
#ifndef AddCredentials
	#error Ultimate TCP/IP: Correct Platform SDK must be installed first and appropriate environment variables must be set
#endif

#include <wincrypt.h>
#include <wintrust.h>
#include <Schnlsp.h>
#include <security.h>

#pragma warning ( push, 3 )
#include <vector>
#pragma warning ( pop )

#include <atlbase.h>

#include <comdef.h>
#include <utstrlst.h>

// Link to the CryptoAPI library
#pragma comment(lib, "Crypt32.lib")
#pragma warning( disable : 4251; disable : 4275 )        

#ifdef UTSECURELAYER_EXPORTS
	#define UTSECURELAYER_API __declspec(dllexport)
#else
	#define UTSECURELAYER_API __declspec(dllimport)
#endif

#ifndef MS_STRONG_PROV_A
	#define MS_STRONG_PROV_A       "Microsoft Strong Cryptographic Provider"
#endif

//Uncomment these lines if required
/*
#ifndef IID_ICEnroll3
	const IID IID_ICEnroll3 = {0xC28C2D95, 0xB7DE, 0x11D2,{0xA4,0x21,0x00,0xC0,0x4F,0x79,0xFE,0x8E}};
#endif
*/

class CUT_Certificate;

using namespace std;
typedef vector<PCCERT_CONTEXT> CERTCONTEXTVECTOR;


typedef UTSECURELAYER_API enum enumPublicKeySize {
	PUBLIC_KEY_512,
	PUBLIC_KEY_1024,
	PUBLIC_KEY_2048
} enumPublicKeySize;


// ===================================================================
// CUT_CertificateManager class
// ===================================================================

class UTSECURELAYER_API CUT_CertificateManager
{
public:
	// Constructor/Destructor
	CUT_CertificateManager();
	virtual ~CUT_CertificateManager();

// Public static methods
public:

	// Gets the list of the machine/user system certificates stores
	static BOOL GetSystemStoreList(CUT_TStringList &Result, DWORD dwStoreLocation = CERT_SYSTEM_STORE_CURRENT_USER);

	// Installs the certificate requested by CertificateRequest function
	static int CertificateInstall(
		_TCHAR *lpszData, 
		BOOL bFileName = FALSE);

	// Prepares the certificate request data
	static int CertificateRequest(
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
		_TCHAR	*lpszFileName);

private:

	// Parameters checking helper function
	static BOOL CheckValidChars(_TCHAR *string);

	// System store enumeration callback function.
	static BOOL  WINAPI CUT_CertificateManager::CertEnumSystemStoreCallback(
		const void *pvSystemStore,           
		DWORD dwFlags,                       
		PCERT_SYSTEM_STORE_INFO pStoreInfo,  
		void *pvReserved,                    
		void *pvArg);                        

};

// ===================================================================
// CUT_CertificateStore class
// ===================================================================

class UTSECURELAYER_API CUT_CertificateStore
{
public:
	// Constructor/Destructor
	CUT_CertificateStore();
	CUT_CertificateStore(const _TCHAR *lpszStoreName, DWORD dwStoreLocation = CERT_SYSTEM_STORE_CURRENT_USER);
	virtual ~CUT_CertificateStore();

	// Close existing and open new certificate store
	virtual int	Open(const _TCHAR *lpszStoreName, DWORD dwStoreLocation = CERT_SYSTEM_STORE_CURRENT_USER);

	// Close opened certificate store
	virtual int	Close();

	// List certificates in store
	virtual int	ListCertificates();

	// Return the size of the internal certificates list
	// which was created by ListCertificates function
	virtual int	GetCertListSize();

	// Gets an item from the internal certificates list
	// which was created by ListCertificates function
	virtual int	GetCertListItem(int nIndex, CUT_Certificate	&certResult);

	// Deletes the certificate from the system store
	virtual int	DeleteCertificate(CUT_Certificate *cert);
	
	// Finds first/next certificate in store. By subject or any other attribute
	virtual int	FindCertificate(
		CUT_Certificate	&certResult,
		const _TCHAR		*lpszFindParam, 
		DWORD			dwFindType = CERT_FIND_SUBJECT_STR_A);

	// Finds unique certificate in store by Serial Number and Issuer
	virtual int	FindCertificate(
		CUT_Certificate	&certResult,
		const _TCHAR		*lpszIssuer, 
		const _TCHAR		*lpszSerialNumber);

	// Return store name or NULL if not opened
	virtual const _TCHAR *GetStoreName()
		{ return m_lpszName; }

	// Return store location or NULL if not opened
	virtual const DWORD GetStoreLocation()
		{ return m_dwLocation; }

	// Protected data members
protected:

	CERTCONTEXTVECTOR	m_vecCertificates;	// Internal list of certificates
	HCERTSTORE			m_hCertStore;		// Certificate store handle
	DWORD				m_dwLocation;		// Store location
	_TCHAR				*m_lpszName;		// Store name
};


// ===================================================================
// CUT_Certificate class
// ===================================================================

class UTSECURELAYER_API CUT_Certificate
{
friend CUT_CertificateStore;

public:
	// Constructor/Destructor
	CUT_Certificate();
	CUT_Certificate(PCCERT_CONTEXT CertContext);
	CUT_Certificate(const CUT_Certificate &cert);
	virtual ~CUT_Certificate();

	// Assignment operator
	CUT_Certificate &operator=(const CUT_Certificate &cert);

	// Get security context
	PCCERT_CONTEXT GetContext();

	// Set security context
	void		SetContext(PCCERT_CONTEXT newCertContext);

	// Verifies the time validity of a certificate
	int			VerifyTime(LPFILETIME pTimeToVerify = NULL);

	// Certificate properties methods
	DWORD			GetVersion();			// Get certificate version 
	const _TCHAR	*GetSerialNumber();		// Get certificate serial number
	const _TCHAR	*GetIssuer();			// Get certificate issuer
	const _TCHAR	*GetIssuedTo();			// Get certificate issued to
	const _TCHAR	*GetSubject();			// Get certificate subject
	FILETIME		GetValidFrom();			// Get certificate valid from date
	FILETIME		GetValidTo();			// Get certificate valid to date
	DWORD			GetKeySize();			// Get certificate key size
	BYTE			GetKeyUsage();			// Get certificate key usage
	const _TCHAR	*GetKeyAlgId();			// Get certificate key algorithm id
	const _TCHAR	*GetSignatureAlgId();	// Get certificate signature algorithm id
	const _TCHAR	*GetKey();				// Get certificate key 

protected:
	
	// Frees all memory and handles
	void	CleanUp();

	// Converts binary data into the string "3A 7F 68 A5 ..."
	_TCHAR	*BinaryToString(void *ptrData, DWORD dwDataSize);

protected:

	PCCERT_CONTEXT	m_CertContext;		// Certificate context
	_TCHAR	m_szEmptyString[2];			// Empty string (returned in case of errors)
	_TCHAR	*m_lpszSerialNumber;		// Serial number ("3A 7F 68 A5 ...")
	_TCHAR	*m_lpszIssuer;				// Issuer of the certificate
	_TCHAR	*m_lpszIssuedTo;			// Issuer of the certificate issued to
	_TCHAR	*m_lpszSubject;				// Subject of the certificate
	_TCHAR	*m_lpszKeyAlgId;			// Certificate key algorithm ID
	_TCHAR	*m_lpszSignatureAlgId;		// Certificate key algorithm ID
	_TCHAR	*m_lpszKey;					// Certificate key ("3A 7F 68 A5 ...")
	_TCHAR	m_szEmptyKey[2];
};

#pragma warning( default : 4251; default : 4275 )        

#endif // CUT_SECURE_SOCKET

#endif // INCLUDECUT_SERTIFMAN