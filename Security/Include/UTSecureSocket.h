// =================================================================
//  class: CUT_SecureSocket
//  File:  CUT_SecureSocket.h
//  
//  Purpose:
//
//	  Security socket layer 
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

#ifndef INCLUDECUT_SECURESOCKET
#define INCLUDECUT_SECURESOCKET

// Suppress warnings for non-safe str fns. Transitional, for VC6 support.
#pragma warning (push)
#pragma warning (disable : 4996)

#ifdef CUT_SECURE_SOCKET

#define SECURITY_WIN32

#pragma warning ( disable : 4018 )

#include <wincrypt.h>
#include <wintrust.h>
#include <Schnlsp.h>
#include <security.h>
#include <sspi.h>

#include "UTCertifMan.h"

// Link to the CryptoAPI library
#pragma comment(lib, "Crypt32.lib")

#define NT_SECURITY_DLL_NAME	_T("security.dll")
#define NT_SECURITY_DLL_NAME_98	_T("secur32.dll")
#define	IO_BUFFER_SIZE			0x10000

typedef UTSECURELAYER_API enum enumCertVerifyType {
	CERT_VERIFY,
	CERT_VERIFY_AND_ASK,
	CERT_DONOT_VERIFY
} enumCertVerifyType;


// ===================================================================
// CUT_SecureSocket class
// ===================================================================
#pragma warning (disable : 4275)
class UTSECURELAYER_API CUT_SecureSocket : public CUT_Socket
{
public:
	// Constructor/Destructor
	CUT_SecureSocket();
	virtual ~CUT_SecureSocket();

	// Receive data from the secured socket connection
	virtual int SocketRecv(SOCKET s, char FAR* buf, int len, int flags);

	// Send data to the secured socket connection
	virtual int SocketSend(SOCKET s, char FAR* buf, int len, int flags);

	// Called after establishing socket connection to initialize
	// security libraries, create security credentials, perform 
	// handshake and verify the security sertificate
	virtual int SocketOnConnected(SOCKET s, const char *lpszName);

	// Close the secured socket connection
	virtual int SocketClose(SOCKET s);

	// Shut down the secured socket connection
	virtual int SocketShutDown(SOCKET s, int how);

	// Check if data waiting on the secured socket connection
	virtual BOOL SocketIsDataWaiting(SOCKET s) const;

	// Wait for data on the secured socket connection
	virtual int SocketWaitForReceive(SOCKET s, long secs, long uSecs);

// Security related methods
public:
	// Set security enabled flag. Must be called prior to the connection,
	virtual void SetSecurityEnabled(BOOL bFlag = TRUE)
		{ m_bSecureConnection = bFlag; }

	// Get security enabled flag. 
	virtual BOOL GetSecurityEnabled()
		{ return m_bSecureConnection; }

	// Set the security certificate by subject
	virtual void SetCertSubjStr(_TCHAR *lpszCertSubjStr) 
		{ _tcsncpy(m_szCertSubjStr, lpszCertSubjStr, sizeof(m_szCertSubjStr)/sizeof(_TCHAR) - 1); }

	// Set sub system protocol used while opening system sertificates
	// Some examples of predefined store names are: 
	//	"MY"	A Certificate store holding "My" certificates with their associated private keys. 
	//	"CA"	Certifying Authority certificates. 
	//	"ROOT"	Root certificates. 
	//	"SPC"	Software publisher certificates. 
	virtual void SetCertStoreName(_TCHAR *lpszProtocol) 
		{ _tcsncpy(m_szCertStoreName, lpszProtocol, sizeof(m_szCertStoreName)/sizeof(_TCHAR) - 1); }

	// Set the security certificate using CUT_Certificate class
	virtual void SetCertificate(CUT_Certificate &cert)
		{ m_Certificate.SetContext(CertDuplicateCertificateContext(cert.GetContext())); }

	// Set security protocol. Possible values defined in SChannel.h:
	// SP_PROT_PCT1, SP_PROT_SSL2, SP_PROT_SSL3, SP_PROT_TLS1, ...
	virtual void SetSecurityProtocol(DWORD dwProtocol) 
		{ m_dwProtocol = dwProtocol; }

	// Set encryption cipher strength (0 - default)
	virtual void SetMinCipherStrength(DWORD dwCipherStrength)
		{ m_dwMinCipherStrength = dwCipherStrength; }

	// Set encryption cipher strength (0 - default)
	virtual void SetMaxCipherStrength(DWORD dwCipherStrength)
		{ m_dwMaxCipherStrength = dwCipherStrength; }

	// Set certificate validation type
	virtual void SetCertValidation(enumCertVerifyType Validation)
		{ m_CertValidation = Validation; }

protected:
	// Function can be overwritten to handle security errors
	virtual void HandleSecurityError(_TCHAR *lpszErrorDescription);
	
	// Function can be overwritten to handle certificate verifications errors
	virtual BOOL OnCertVerifyError(CUT_Certificate &certServer, int nError, _TCHAR *lpszServerName);

	// Load security libraries and initialize buffers
	virtual BOOL LoadSecurityLibrary(void);

	// Free security libraries and buffers
	virtual void FreeSecurityLibrary(void);

	// Get verification error description
	virtual void DisplayWinVerifyTrustError(DWORD Status);

	// Notify about disconnection
	virtual int DisconnectNotify(SOCKET Socket);

	// Receive encrypted data (messages) from the socket and decrypt them
	virtual int MessageRecv(SOCKET s);

	// Create security credentials
	virtual int CreateCredentials() = 0;

	// Perform handshake
	virtual int PerformHandshake(SOCKET Socket, const _TCHAR *lpszServerName, SecBuffer *pExtraData) = 0;

	// Helper function used in the handshake
	virtual int HandshakeLoop(SOCKET Socket, BOOL fDoInitialRead, SecBuffer *pExtraData) = 0;

	// Verify sertificate
	virtual int VerifyCertificate(PTSTR pszServerName, DWORD dwCertFlags) = 0;

protected:

	SecurityFunctionTable	m_SecurityFunc;			// Dispatch table that contains pointers 
													//  to the functions defined in SSPI
	HMODULE					m_hSecurity;			// Security DLL handle
	BOOL					m_bSecureConnection;	// Secure socket enabled flag
	HCERTSTORE				m_hCertStore;			// System certificate store handle
	_TCHAR					m_szCertSubjStr[100];	// Client sertificate user name
	SCHANNEL_CRED			m_SchannelCred;			// Schannel credential structure
	DWORD					m_dwProtocol;			// Security protocol
	CredHandle				*m_phCreds;				// SSPI credentials handle
	CtxtHandle				*m_phContext;			// Security context handle
	_TCHAR					m_szCertStoreName[100];	// String describing a system cert. store name
	SecPkgContext_StreamSizes m_StreamSizes;		// Secure stream sizes
	DWORD					m_dwIoBufferLength;		// IO buffer size
	char					*m_lpszIoBuffer;		// IO buffer
	char					*m_lpszMessageBuffer;	// IO message pointer
	char					*m_lpszExtraReceivedData;	// Extar data received from the socket
	DWORD					m_dwExtraReceivedDataSize;	// Extar data size 
	char					*m_lpszDecodedData;		// Received and decoded data buffer
	DWORD					m_dwDecodedDataSize;	// Received and decoded data buffer size
	DWORD					m_dwDecodedDataMaxSize;	// Received and decoded data buffer max size
	DWORD					m_dwMaxCipherStrength;	// Max encryption cipher strength (0 - default)
	DWORD					m_dwMinCipherStrength;	// Min encryption cipher strength (0 - default)
	enumCertVerifyType		m_CertValidation;		// Certificate validation type
	CUT_Certificate			m_Certificate;			// Certificate class
	BOOL					m_bCloseStore;			// Flag to close the certificate store
};



// ===================================================================
// CUT_SecureSocketClient class
// ===================================================================
class UTSECURELAYER_API CUT_SecureSocketClient : public CUT_SecureSocket
{
public:
	// Constructor/Destructor
	CUT_SecureSocketClient();
	virtual ~CUT_SecureSocketClient();

protected:
	// Create security credentials
	virtual int CreateCredentials();

	// Get ne client credentials
	virtual void GetNewCredentials();

	// Perform client handshake
	virtual int PerformHandshake(SOCKET Socket, const _TCHAR *lpszServerName, SecBuffer *pExtraData);

	// Helper function used in the handshake
	virtual int HandshakeLoop(SOCKET Socket, BOOL fDoInitialRead, SecBuffer *pExtraData);

	// Verify sertificate
	virtual int VerifyCertificate(PTSTR pszServerName, DWORD dwCertFlags);

public:

	// Set security algorithm. Possible values defined in WinCrypt.h:
	// CALG_RSA_KEYX, CALG_DH_EPHEM, ...
	virtual void SetSecurityAlgorithmID(ALG_ID aiKeyExch) 
		{ m_aiKeyExch = aiKeyExch; }

protected:
	ALG_ID					m_aiKeyExch;			// Security algorithm ID
};


// ===================================================================
// CUT_SecureSocketServer class
// ===================================================================
class UTSECURELAYER_API CUT_SecureSocketServer : public CUT_SecureSocket
{
public:
	// Constructor/Destructor
	CUT_SecureSocketServer();
	virtual ~CUT_SecureSocketServer();

protected:
	// Create security credentials
	virtual int CreateCredentials();

	// Get ne client credentials
	virtual void GetNewCredentials();

	// Perform client handshake
	virtual int PerformHandshake(SOCKET Socket, const _TCHAR *lpszServerName, SecBuffer *pExtraData);

	// Helper function used in the handshake
	virtual int HandshakeLoop(SOCKET Socket, BOOL fDoInitialRead, SecBuffer *pExtraData);

	// Verify sertificate
	virtual int VerifyCertificate(PTSTR pszServerName, DWORD dwCertFlags);

public:

	// Set the machine store flag
	virtual void SetMachineStore(BOOL bFlag)
		{ m_bMachineStore = bFlag; }

	// Set authentication flag
	virtual void SetClientAuth(BOOL bFlag)
		{ m_bClientAuth = bFlag; }

protected:
	BOOL					m_bMachineStore;		// Machine store flag
	BOOL					m_bClientAuth;			// Client authentication flag
};

#endif // CUT_SECURE_SOCKET

#pragma warning ( pop )

#endif // INCLUDECUT_SECURESOCKET