//=================================================================
//  class: CUT_SecureSocket
//  File:  CUT_SecureSocket.cpp
//
//  Purpose:
//
//	  Security socket layer implementation
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

#ifdef _WINSOCK_2_0_
    #define _WINSOCKAPI_	/* Prevent inclusion of winsock.h in windows.h   */
	    					/* Remove this line if you are using WINSOCK 1.1 */
#endif

#include "stdafx.h"

#include "ut_strop.h"

// Suppress warnings for non-safe str fns. Transitional, for VC6 support.
#pragma warning (push)
#pragma warning (disable : 4996)


#ifdef CUT_SECURE_SOCKET

#include "ut_clnt.h"
#include "UTSecureSocket.h"
#include "UTCertifMan.h"

#ifndef SEC_I_CONTEXT_EXPIRED
//
// this can be removed when it the error code is added to WinError.h
//
#define SEC_I_CONTEXT_EXPIRED            ((HRESULT)0x00090317L)

#endif


// ===================================================================
// CUT_SecureSocket class
// ===================================================================

/***********************************************
CUT_SecureSocket
    Constructor
Params
    none
Return
    none
************************************************/
CUT_SecureSocket::CUT_SecureSocket() : 
		m_bSecureConnection(FALSE),
		m_hSecurity(NULL),
		m_hCertStore(NULL),
		m_dwProtocol(0),
		m_phCreds(NULL),
		m_phContext(NULL),
		m_dwIoBufferLength(0),
		m_lpszIoBuffer(NULL),
		m_lpszExtraReceivedData(NULL),
		m_dwExtraReceivedDataSize(0),
		m_lpszDecodedData(NULL),
		m_dwDecodedDataSize(0),
		m_dwDecodedDataMaxSize(0),
		m_lpszMessageBuffer(NULL),
		m_dwMaxCipherStrength(0),
		m_dwMinCipherStrength(0),
		m_CertValidation(CERT_VERIFY_AND_ASK),
		m_bCloseStore(FALSE)
{
	// Initialize user name
	ZeroMemory(m_szCertSubjStr, sizeof(m_szCertSubjStr));

	// Initialize store name
	ZeroMemory(m_szCertStoreName, sizeof(m_szCertStoreName));
	_tcscpy(m_szCertStoreName, _T("MY"));

	// Allocate decoded data buffer
	m_lpszDecodedData = (char *)LocalAlloc(LMEM_FIXED, IO_BUFFER_SIZE);
	m_dwDecodedDataMaxSize = IO_BUFFER_SIZE - 1;
}

/***********************************************
~CUT_SecureSocket
    Destructor
Params
    none
Return
    none
************************************************/
CUT_SecureSocket::~CUT_SecureSocket() 
{
	// Free security library if loaded
	FreeSecurityLibrary();

	// Free extra read data
	if(m_lpszExtraReceivedData != NULL)
		LocalFree(m_lpszExtraReceivedData);

	// Free decoded data buffer
	LocalFree(m_lpszDecodedData);
	
}

/***********************************************
SocketRecv
	Receives data from the connected secure/nonsecure socket
Params
	s		- socket to receive data from
	buf		- data buffer for reading
	len		- data buffer size
	flags	- a flag specifying the way in which the call is made. 
Return
    SOCKET_ERROR or number of bytes received
************************************************/
int CUT_SecureSocket::SocketRecv(SOCKET s, char FAR* buf, int len, int flags)
{ 
	DWORD	dwBytesToCopy = 0;

	// Call non secure socket function
	if(m_bSecureConnection == FALSE)
		return CUT_Socket::SocketRecv(s, buf, len, flags); 

	// Check the security context
	if(m_phContext == NULL)
		return SOCKET_ERROR;

	// If no data in the buffer - receive more messages
	if(m_dwDecodedDataSize == 0)
	{
		if(MessageRecv(s) != UTE_SUCCESS)
			return SOCKET_ERROR;
	}

	// Copy data from the decrypted data buffer
	if(m_dwDecodedDataSize > 0)
	{
		dwBytesToCopy = min((int)m_dwDecodedDataSize, len);
		MoveMemory(buf, m_lpszDecodedData, dwBytesToCopy);
		if((flags & MSG_PEEK) == FALSE)
		{
			// Remove data from the buffer
			MoveMemory(m_lpszDecodedData, m_lpszDecodedData + dwBytesToCopy, m_dwDecodedDataSize - dwBytesToCopy);
			m_dwDecodedDataSize -= dwBytesToCopy;
		}
	}

	return dwBytesToCopy;
}

/***********************************************
SocketSend
	Sends data to the connected secure/nonsecure socket
Params
	s		- socket to receive data from
	buf		- data buffer for sending
	len		- data size
	flags	- a flag specifying the way in which the call is made. 
Return
    SOCKET_ERROR or number of bytes sent
************************************************/
int CUT_SecureSocket::SocketSend(SOCKET s, char FAR* buf, int len, int flags)
{ 
	// Call non secure socket function
	if(!m_bSecureConnection)
		return CUT_Socket::SocketSend(s, buf, len, flags); 

	// Check the security context
	if(m_phContext == NULL)
		return SOCKET_ERROR;

	DWORD			dwMessageSize = 0;
    SecBufferDesc   Message;
    SecBuffer       Buffers[4];
	SECURITY_STATUS	Status;
	DWORD			dwData;
	DWORD			dwBytesSent = 0;

	// Check parameters
	if(buf == NULL)
		return SOCKET_ERROR;

	// Split data into the smaller chunks if nessesary
	while(dwBytesSent < (DWORD)len)
	{
		// Set message size
		dwMessageSize = min(len - dwBytesSent, m_StreamSizes.cbMaximumMessage);

		// Copy data into the buffer
		MoveMemory(m_lpszMessageBuffer, buf + dwBytesSent, dwMessageSize);

		// Encrypt data before sending
		Buffers[0].pvBuffer     = m_lpszIoBuffer;
		Buffers[0].cbBuffer     = m_StreamSizes.cbHeader;
		Buffers[0].BufferType   = SECBUFFER_STREAM_HEADER;

		Buffers[1].pvBuffer     = m_lpszMessageBuffer;
		Buffers[1].cbBuffer     = dwMessageSize;
		Buffers[1].BufferType   = SECBUFFER_DATA;

		Buffers[2].pvBuffer     = m_lpszMessageBuffer + dwMessageSize;
		Buffers[2].cbBuffer     = m_StreamSizes.cbTrailer;
		Buffers[2].BufferType   = SECBUFFER_STREAM_TRAILER;

		Buffers[3].BufferType   = SECBUFFER_EMPTY;

		Message.ulVersion       = SECBUFFER_VERSION;
		Message.cBuffers        = 4;
		Message.pBuffers        = Buffers;

		Status = m_SecurityFunc.EncryptMessage(m_phContext, 0, &Message, 0);
		if(FAILED(Status))
		{
			HandleSecurityError(_T("Failed to encrypt security message."));
			return SOCKET_ERROR;
		}

		// Send the encrypted data to the server.
		dwData = send(s, m_lpszIoBuffer,
					  Buffers[0].cbBuffer + Buffers[1].cbBuffer + Buffers[2].cbBuffer,
					  0);
		if(dwData == SOCKET_ERROR || dwData == 0)
		{
			HandleSecurityError(_T("Error sending secure data to the server."));
			return dwData;
		}

		// Increase the number of bytes sent
		dwBytesSent += dwMessageSize;
	}

	return len;
}

/***********************************************
SocketOnConnected
	Negotiates a secure connection on the specified
	socket.
Params
	s			- a descriptor identifying a socket
	lpszName	- server name 
Return
	UTE_SUCCESS
	UTE_LOAD_SECURITY_LIBRARIES_FAILED
	UTE_OUT_OF_MEMORY
	UTE_NULL_PARAM
	UTE_FAILED_TO_GET_SECURITY_STREAM_SIZE
	UTE_FAILED_TO_CREATE_SECURITY_CREDENTIALS
	UTE_HANDSHAKE_FAILED
************************************************/
int CUT_SecureSocket::SocketOnConnected(SOCKET s, const char *lpszName)
{ 
	SecBuffer		ExtraData;
	int				nError = UTE_SUCCESS;

	// Call non secure socket function
	if(!m_bSecureConnection) {
		return CUT_Socket::SocketOnConnected(s, lpszName); 
	}

	// Check parameter
	if(lpszName == NULL)
		return UTE_NULL_PARAM;

	// Load security library
	if(!LoadSecurityLibrary())
		return UTE_LOAD_SECURITY_LIBRARIES_FAILED;

	// Create security credentials
	if((nError = CreateCredentials()) != UTE_SUCCESS)
		return UTE_FAILED_TO_CREATE_SECURITY_CREDENTIALS;

	// Perform handshake
	// v4.2 Using WC here. lpszname is char in core code, and doing this here avoids messy overload of protected PerformHandshake")
	if((nError = PerformHandshake(s, WC(lpszName), &ExtraData)) != UTE_SUCCESS)
	{
		delete m_phContext;
		m_phContext = NULL;
		return UTE_HANDSHAKE_FAILED;
	}

	//************************************************
	//**  Allocate a working IO buffer
	//************************************************

    // Read stream encryption properties.
    if(m_SecurityFunc.QueryContextAttributes(m_phContext, SECPKG_ATTR_STREAM_SIZES, &m_StreamSizes) != SEC_E_OK)
    {
        HandleSecurityError(_T("Error reading security stream sizes."));
        return UTE_FAILED_TO_GET_SECURITY_STREAM_SIZE;
    }

	// Free previous IO buffer memory
	if(m_lpszIoBuffer != NULL)
		LocalFree(m_lpszIoBuffer);

    // Allocate a working buffer. The plaintext sent to EncryptMessage
    // should never be more than 'm_StreamSizes.cbMaximumMessage', so a buffer 
    // size of this plus the header and trailer m_StreamSizes should be safe enough.
    m_dwIoBufferLength = m_StreamSizes.cbHeader + m_StreamSizes.cbMaximumMessage + m_StreamSizes.cbTrailer;
   	if(m_dwIoBufferLength * 2 < 0x10000) // AB: ensure doubling will not exceed 64k
		m_dwIoBufferLength *= 2;
	else
		m_dwIoBufferLength = 0xFFFF;

    m_lpszIoBuffer = (char *)LocalAlloc(LMEM_FIXED, m_dwIoBufferLength); //AB: + 10);
    if(m_lpszIoBuffer == NULL)
    {
        HandleSecurityError(_T("Out of memory."));
        return UTE_OUT_OF_MEMORY;
    }

	// Initialize pointer to the message data
	m_lpszMessageBuffer = m_lpszIoBuffer + m_StreamSizes.cbHeader;

	// Clear received data buffer
	m_dwDecodedDataSize = 0;

	// Free extra read data buffer
	if(m_lpszExtraReceivedData != NULL)
	{
		LocalFree(m_lpszExtraReceivedData);
		m_lpszExtraReceivedData = NULL;
		m_dwExtraReceivedDataSize = 0;
	}

	//************************************************
	//**  Verify sertificate
	//************************************************
    if((nError = VerifyCertificate((PTSTR)lpszName, 0)) != UTE_SUCCESS)
    {
        HandleSecurityError(_T("Error authenticating security credentials."));
        return nError;
    }

	return UTE_SUCCESS;
}

/***********************************************
SocketClose
	Close a secure/nonsecure connection to a 
	specifed socket.
Params
	s		- a descriptor identifying connected socket
Return
    Socket error or 0
************************************************/
int CUT_SecureSocket::SocketClose(SOCKET s)
{
	// Notify server about disconnection
	if(m_bSecureConnection)
		DisconnectNotify(s);

	// Close socket connection
	return CUT_Socket::SocketClose(s); 
}

/***********************************************
SocketShutDown
	Shuts down a secure/nonsecure connection to a 
	specifed socket.
Params
	s		- a descriptor identifying connected socket
	how		- SD_RECEIVE, SD_SEND, SD_BOTH
Return
    Socket error or 0
************************************************/
int CUT_SecureSocket::SocketShutDown(SOCKET s, int how)
{
	// Notify server about disconnection
	if(m_bSecureConnection)
		DisconnectNotify(s);

	return CUT_Socket::SocketShutDown(s, how); 
}

/***********************************************
SocketIsDataWaiting
	Checks if data waiting on the connected socket
Params
	s		- a descriptor identifying connected socket
Return
    TRUE if data is waiting to be read
************************************************/
BOOL CUT_SecureSocket::SocketIsDataWaiting(SOCKET s) const
{
	// Call non secure socket function
	if(!m_bSecureConnection)
		return CUT_Socket::SocketIsDataWaiting(s); 

	BOOL	bResult = CUT_Socket::SocketIsDataWaiting(s); 

	// If there is something in the decoded data buffer
	if(	m_dwDecodedDataSize > 0)
		bResult = TRUE;

	return bResult;
}

/***********************************************
SocketWaitForReceive
	Waits specified amount of time for the incoming
	data
Params
	s		- a descriptor identifying connected socket
	secs	- seconds to wait
	uSecs	- milliseconds to wait
Return
    UTE_SUCCESS	- success
	UTE_ERROR	- failure
************************************************/
int CUT_SecureSocket::SocketWaitForReceive(SOCKET s, long secs, long uSecs)
{
	// Call non secure socket function
	if(!m_bSecureConnection)
		return CUT_Socket::SocketWaitForReceive(s, secs, uSecs);

	if(	m_dwDecodedDataSize > 0)
		return UTE_SUCCESS;

	if(MessageRecv(s) == UTE_SUCCESS)
		return UTE_SUCCESS;
	
	if (CUT_Socket::SocketWaitForReceive(s, secs, uSecs)== UTE_SUCCESS)
		return UTE_SUCCESS;
//
	return UTE_ERROR;

//	return CUT_Socket::SocketWaitForReceive(s, secs, uSecs);
}

/***********************************************
HandleError
	Virtual function which receives the security 
    errors descriptions. 
Params
    lpszErrorDescription - error description string
Return
    none
************************************************/
void CUT_SecureSocket::HandleSecurityError(_TCHAR *lpszErrorDescription)
{
#ifdef _DEBUG
	MessageBox(NULL,lpszErrorDescription, _T("HandleSecurityError Error") , MB_OK);
#else
	UNREFERENCED_PARAMETER(lpszErrorDescription);
#endif

} 

/***********************************************
OnCertVerifyError
	Function can be overwritten to handle certificate verifications errors
Params
	certServer		- remote certificate
	lpszServerName	- remote name
	nError			- error code
		CERT_E_EXPIRED
		CERT_E_VALIDITYPERIODNESTING
		CERT_E_ROLE
		CERT_E_PATHLENCONST
		CERT_E_CRITICAL
		CERT_E_PURPOSE
		CERT_E_ISSUERCHAINING
		CERT_E_MALFORMED
		CERT_E_UNTRUSTEDROOT
		CERT_E_CHAINING
		TRUST_E_FAIL
		CERT_E_REVOKED
		CERT_E_UNTRUSTEDTESTROOT
		CERT_E_REVOCATION_FAILURE
		CERT_E_CN_NO_MATCH
		CERT_E_WRONG_USAGE

Return
	TRUE  - accept the certificate
	FALSE - do not accept the certificate
************************************************/
// v4.2 Should server name be included in message?
BOOL CUT_SecureSocket::OnCertVerifyError(CUT_Certificate &certServer, int nError, _TCHAR * /* lpszServerName */)
{
	// Show dialog with the remote certificate information and 
	// ask if we should trust it
	if(m_CertValidation == CERT_VERIFY_AND_ASK && certServer.GetContext() != NULL)
	{
			// Prepare message text
		LPCTSTR	lpszIssuedTo = certServer.GetIssuedTo();
		LPCTSTR	lpszIssuer = certServer.GetIssuer();

			

		_TCHAR	*lpszBuffer = new _TCHAR[500 + _tcslen(lpszIssuedTo) + _tcslen(lpszIssuer)];
		switch (nError)
		{
		case 	TRUST_E_PROVIDER_UNKNOWN: //	#define TRUST_E_PROVIDER_UNKNOWN         _HRESULT_TYPEDEF_(0x800B0001L)
			_tcscpy(lpszBuffer, _T("The specified trust provider is not known on this system.\r\n\r\n"));
			break;
		
			//  
			//
		case  TRUST_E_ACTION_UNKNOWN://
			_tcscpy(lpszBuffer, _T("The trust verification action specified is not supported by the specified trust provider.\r\n\r\n"));
			break;
			//  
			//
		case  TRUST_E_SUBJECT_FORM_UNKNOWN://
			_tcscpy(lpszBuffer, _T("The form specified for the subject is not one supported or known by the specified trust provider..\r\n\r\n"));
			break;
			//  
			//
		case  TRUST_E_SUBJECT_NOT_TRUSTED://
			_tcscpy(lpszBuffer, _T("The subject is not trusted for the specified action..\r\n\r\n"));
			break;
			//  
			//
		case  DIGSIG_E_ENCODE ://
			_tcscpy(lpszBuffer, _T("Error due to problem in ASN.1 encoding process.\r\n\r\n"));
			break;
			//  
			//
		case  DIGSIG_E_DECODE://
			_tcscpy(lpszBuffer, _T("Error due to problem in ASN.1 decoding process.\r\n\r\n"));
			break;

			// 
			//
		case  DIGSIG_E_EXTENSIBILITY://
			_tcscpy(lpszBuffer, _T(" Reading / writing Extensions where Attributes are appropriate, and visa versa.\r\n\r\n"));
			break;
			//  
			//
		case  DIGSIG_E_CRYPTO ://
			_tcscpy(lpszBuffer, _T("Unspecified cryptographic failure.\r\n\r\n"));
			break;
			//  
			//
		case  PERSIST_E_SIZEDEFINITE://
			_tcscpy(lpszBuffer, _T("The size of the data could not be determined.\r\n\r\n"));
			break;
			//  
			//
		case  PERSIST_E_SIZEINDEFINITE: //
			_tcscpy(lpszBuffer, _T("The size of the indefinite-sized data could not be determined.\r\n\r\n"));
			break;
			//
			//  
			//
		case  PERSIST_E_NOTSELFSIZING://
			_tcscpy(lpszBuffer, _T("This object does not read and write self-sizing data.\r\n\r\n"));
			break;
			//
			//  
			//
		case  TRUST_E_NOSIGNATURE://
			_tcscpy(lpszBuffer, _T("No signature was present in the subject.\r\n\r\n"));
			break;
			//
			//  
			//
		case  CERT_E_EXPIRED://
			_tcscpy(lpszBuffer, _T("A required certificate is not within its validity period.\r\n\r\n"));
			break;
			//  
			//
		case  CERT_E_VALIDITYPERIODNESTING://
			_tcscpy(lpszBuffer, _T("The validity periods of the certification chain do not nest correctly.\r\n\r\n"));
			break;
			//  
			//
			case  CERT_E_ROLE://
				_tcscpy(lpszBuffer, _T("A certificate that can only be used as an end-entity is being used as a CA or visa versa.\r\n\r\n"));
				break;
				//  
				//
			case  CERT_E_PATHLENCONST://
				_tcscpy(lpszBuffer, _T("A path length constraint in the certification chain has been violated.\r\n\r\n"));
				break;
				//  
				//
			case  CERT_E_CRITICAL ://
				_tcscpy(lpszBuffer, _T("An extension of unknown type that is labeled 'critical' is present in a certificate.\r\n\r\n"));
				break;

				//
			case  CERT_E_PURPOSE ://
				_tcscpy(lpszBuffer, _T("A certificate is being used for a purpose other than that for which it is permitted.\r\n\r\n"));
			break;
			//  
			//
			case  CERT_E_ISSUERCHAINING ://
				_tcscpy(lpszBuffer, _T("A parent of a given certificate in fact did not issue that child certificate.\r\n\r\n"));
				break;
				//  
				//
			case  CERT_E_MALFORMED://
				_tcscpy(lpszBuffer, _T("A certificate is missing or has an empty value for an important field, such as a subject or issuer name.\r\n\r\n"));
				break;
				//  
				//
			case  CERT_E_UNTRUSTEDROOT://
				_tcscpy(lpszBuffer, _T("A certification chain processed correctly, but terminated in a root certificate which isn't trusted by the trust provider.\r\n\r\n"));
				break;
				//  
				//
			case  CERT_E_CHAINING://
				_tcscpy(lpszBuffer, _T("A chain of certs didn't chain as they should in a certain application of chaining.\r\n\r\n"));
				break;
				//  
				//
			case  TRUST_E_FAIL://
				_tcscpy(lpszBuffer, _T("Generic Trust Failure.\r\n\r\n"));
				break;
				//  
			case  CERT_E_REVOKED://
				_tcscpy(lpszBuffer, _T("A certificate was explicitly revoked by its issuer.\r\n\r\n"));
				break;

				//
			case  CERT_E_UNTRUSTEDTESTROOT ://
				_tcscpy(lpszBuffer, _T("The root certificate is a testing certificate and the policy settings disallow test certificates.\r\n\r\n"));
				break;

				//
			case  CERT_E_REVOCATION_FAILURE ://
				_tcscpy(lpszBuffer, _T("The revocation process could not continue - the certificate(s) could not be checked.\r\n\r\n"));
				break;

			case  CERT_E_CN_NO_MATCH://
				_tcscpy(lpszBuffer, _T("The certificate's CN name does not match the passed value.\r\n\r\n"));
				break;


			case  CERT_E_WRONG_USAGE://
				_tcscpy(lpszBuffer, _T("The certificate is not valid for the requested usage.\r\n\r\n"));
				break;
				
			default:
				_tcscpy(lpszBuffer, _T("The certificate veryfication failed.\r\n\r\n"));
				break;


		}
		
		_tcscat(lpszBuffer, _T("Certificate issued to: "));
		_tcscat(lpszBuffer, lpszIssuedTo);
		_tcscat(lpszBuffer, _T("\r\nCertificate issued by: "));
		_tcscat(lpszBuffer, lpszIssuer);
		_tcscat(lpszBuffer, _T("\r\n\r\nDo you want to proceed with the connection?"));
		int nResult = MessageBox(NULL, lpszBuffer, _T("Non trusted certificate"), MB_YESNO | MB_DEFBUTTON2 | MB_SYSTEMMODAL);
	

		// Free memory
		delete [] lpszBuffer;

		// Accept connection
		if(nResult == IDYES)
			return TRUE;
	}

	return FALSE;
}

/***********************************************
LoadSecurityLibrary
	Load and initialize the security library .
Params
    none
Return
    TRUE	- if success
************************************************/
BOOL CUT_SecureSocket::LoadSecurityLibrary(void)
{
    PSecurityFunctionTable	pSecurityFunc;
    INIT_SECURITY_INTERFACE	pInitSecurityInterface;

	// Check if the library was already initialized
	if(m_hSecurity != NULL)
		return TRUE;

	// Load security libarary
    m_hSecurity = LoadLibrary(NT_SECURITY_DLL_NAME);
    if(m_hSecurity == NULL)
    {
		// Try to load security DLL for 95/98/ME
		m_hSecurity = LoadLibrary(NT_SECURITY_DLL_NAME_98);
		if(m_hSecurity == NULL)
		{
			HandleSecurityError(_T("Error loading security.dll."));
			FreeSecurityLibrary();
			return FALSE;
		}
    }
	
	// Get security entry point function
// v4.2 changes - note SECURITY_ENTRYPOINT_ANSIW vs SECURITY_ENTRYPOINT_ANSIA
#if defined _UNICODE
    pInitSecurityInterface = (INIT_SECURITY_INTERFACE)GetProcAddress(m_hSecurity, SECURITY_ENTRYPOINT_ANSIW);
#else
    pInitSecurityInterface = (INIT_SECURITY_INTERFACE)GetProcAddress(m_hSecurity, SECURITY_ENTRYPOINT_ANSIA);
#endif

    if(pInitSecurityInterface == NULL)
    {
        HandleSecurityError(_T("Error reading InitSecurityInterface entry point."));
		FreeSecurityLibrary();
        return FALSE;
    }
	
	// Get dispatch table that contains pointers to the functions defined in SSPI
    pSecurityFunc = pInitSecurityInterface();
    if(pSecurityFunc == NULL)
    {
        HandleSecurityError(_T("Error reading security interface."));
		FreeSecurityLibrary();
        return FALSE;
    }
	
	// Copy the dispatch table
    CopyMemory(&m_SecurityFunc, pSecurityFunc, sizeof(m_SecurityFunc));

    return TRUE;
}

/***********************************************
FreeSecurityLibrary
	Unload the security library .
Params
    none
Return
    none
************************************************/
void CUT_SecureSocket::FreeSecurityLibrary(void)
{
    // Free security context handle.
	if(m_phContext != NULL)
	{
		m_SecurityFunc.DeleteSecurityContext(m_phContext);
		delete m_phContext;
		m_phContext = NULL;
	}

    // Free SSPI credentials handle.
	if(m_phCreds != NULL)
	{
		m_SecurityFunc.FreeCredentialsHandle(m_phCreds);
		delete m_phCreds;
		m_phCreds = NULL;
	}
	
	// Free security library
	if(m_hSecurity != NULL)
	{
		FreeLibrary(m_hSecurity);
		m_hSecurity = NULL;
	}

    // Close certificate store.
    if(m_hCertStore != NULL)
    {
		if(m_bCloseStore)
			CertCloseStore(m_hCertStore, 0);
		m_hCertStore = NULL;
    }

	// Free IO buffer memory
	if(m_lpszIoBuffer != NULL)
	{
		LocalFree(m_lpszIoBuffer);
		m_lpszIoBuffer = NULL;
	}
}

/***********************************************
DisplayWinVerifyTrustError
	Get error Process error by code
Params
	Status	- error code
Return
    none
************************************************/
void CUT_SecureSocket::DisplayWinVerifyTrustError(DWORD Status)
{
    LPTSTR	pszName = NULL;
	_TCHAR	szBuffer[1024];

    switch(Status)
    {
		case CERT_E_EXPIRED:                pszName = _T("CERT_E_EXPIRED");                 break;
		case CERT_E_VALIDITYPERIODNESTING:  pszName = _T("CERT_E_VALIDITYPERIODNESTING");   break;
		case CERT_E_ROLE:                   pszName = _T("CERT_E_ROLE");                    break;
		case CERT_E_PATHLENCONST:           pszName = _T("CERT_E_PATHLENCONST");            break;
		case CERT_E_CRITICAL:               pszName = _T("CERT_E_CRITICAL");                break;
		case CERT_E_PURPOSE:                pszName = _T("CERT_E_PURPOSE");                 break;
		case CERT_E_ISSUERCHAINING:         pszName = _T("CERT_E_ISSUERCHAINING");          break;
		case CERT_E_MALFORMED:              pszName = _T("CERT_E_MALFORMED");               break;
		case CERT_E_UNTRUSTEDROOT:          pszName = _T("CERT_E_UNTRUSTEDROOT");           break;
		case CERT_E_CHAINING:               pszName = _T("CERT_E_CHAINING");                break;
		case TRUST_E_FAIL:                  pszName = _T("TRUST_E_FAIL");                   break;
		case CERT_E_REVOKED:                pszName = _T("CERT_E_REVOKED");                 break;
		case CERT_E_UNTRUSTEDTESTROOT:      pszName = _T("CERT_E_UNTRUSTEDTESTROOT");       break;
		case CERT_E_REVOCATION_FAILURE:     pszName = _T("CERT_E_REVOCATION_FAILURE");      break;
		case CERT_E_CN_NO_MATCH:            pszName = _T("CERT_E_CN_NO_MATCH");             break;
		case CERT_E_WRONG_USAGE:            pszName = _T("CERT_E_WRONG_USAGE");             break;
		default:                            pszName = _T("(unknown)");                      break;
    }

    _sntprintf(szBuffer,sizeof(szBuffer)/sizeof(_TCHAR)-1, _T("Error 0x%x (%s) returned by CertVerifyCertificateChainPolicy!\n"), Status, pszName);
	HandleSecurityError(szBuffer);
}

/***********************************************
DisconnectNotify
	Notify schannel that we are about to close the connection.
Params
	Socket	- connected socket
Return
    UTE_SUCCESS
	UTE_FAILED_TO_APPLY_CONTROL_TOKEN
	UTE_FAILED_TO_INITIALIZE_SECURITY_CONTEXT
	UTE_SOCK_SEND_ERROR
************************************************/
int CUT_SecureSocket::DisconnectNotify(SOCKET Socket)
{
    DWORD           dwType;
    PBYTE           pbMessage;
    DWORD           cbMessage;
    DWORD           cbData;

    SecBufferDesc   OutBuffer;
    SecBuffer       OutBuffers[1];
    DWORD           dwSSPIFlags;
    DWORD           dwSSPIOutFlags;
    TimeStamp       tsExpiry;
    DWORD           Status;
	int				nError = UTE_SUCCESS;

	// Check if we already notified the server
	if(m_phContext == NULL)
		return UTE_SUCCESS;		

    // Notify schannel that we are about to close the connection.
    dwType = SCHANNEL_SHUTDOWN;

    OutBuffers[0].pvBuffer   = &dwType;
    OutBuffers[0].BufferType = SECBUFFER_TOKEN;
    OutBuffers[0].cbBuffer   = sizeof(dwType);

    OutBuffer.cBuffers  = 1;
    OutBuffer.pBuffers  = OutBuffers;
    OutBuffer.ulVersion = SECBUFFER_VERSION;

    Status = m_SecurityFunc.ApplyControlToken(m_phContext, &OutBuffer);
    if(FAILED(Status)) 
    {
		nError = UTE_FAILED_TO_APPLY_CONTROL_TOKEN;
        HandleSecurityError(_T("Error returned by ApplyControlToken."));
    }
	else
	{
		// Build an SSL close notify message.
		dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT   |
					  ISC_REQ_REPLAY_DETECT     |
					  ISC_REQ_CONFIDENTIALITY   |
					  ISC_RET_EXTENDED_ERROR    |
					  ISC_REQ_ALLOCATE_MEMORY   |
					  ISC_REQ_STREAM;

		OutBuffers[0].pvBuffer   = NULL;
		OutBuffers[0].BufferType = SECBUFFER_TOKEN;
		OutBuffers[0].cbBuffer   = 0;

		OutBuffer.cBuffers  = 1;
		OutBuffer.pBuffers  = OutBuffers;
		OutBuffer.ulVersion = SECBUFFER_VERSION;

		Status = m_SecurityFunc.InitializeSecurityContext(
						m_phCreds,
						m_phContext,
						NULL,
						dwSSPIFlags,
						0,
						SECURITY_NATIVE_DREP,
						NULL,
						0,
						m_phContext,
						&OutBuffer,
						&dwSSPIOutFlags,
						&tsExpiry);

		if(FAILED(Status)) 
		{
			nError = UTE_FAILED_TO_INITIALIZE_SECURITY_CONTEXT;
			HandleSecurityError(_T("Failed to initialize the security context."));
		}
		else
		{
			pbMessage = (PBYTE)OutBuffers[0].pvBuffer;
			cbMessage = OutBuffers[0].cbBuffer;

			// Send the close notify message
			if(pbMessage != NULL && cbMessage != 0)
			{
				cbData = send(Socket, (const char *)pbMessage, cbMessage, 0);
				if(cbData == SOCKET_ERROR || cbData == 0)
				{
					Status = WSAGetLastError();
					nError = UTE_SOCK_SEND_ERROR;
				}

				// Free output buffer.
				m_SecurityFunc.FreeContextBuffer(pbMessage);
			}
		}
	}
    

    // Free the security context.
    m_SecurityFunc.DeleteSecurityContext(m_phContext);
	delete m_phContext;
	m_phContext = NULL;

    return nError;
}

/***********************************************
MessageRecv
	Receive message from the secure socket
Params
	s		- socket to receive data from
Return
    UTE_SUCCESS
	UTE_SOCK_RECEIVE_ERROR
	UTE_FAILED_TO_RECEIVE_SECURITY_MESSAGE
	UTE_SECURITY_CONTEXT_EXPIRED
	UTE_FAILED_TO_DECRYPT_SECURITY_MESSAGE
************************************************/
int CUT_SecureSocket::MessageRecv(SOCKET s)
{ 
	DWORD			dwIoBuffer = 0;
    SecBufferDesc   Message;
    SecBuffer       Buffers[4];
	SECURITY_STATUS	Status = SEC_E_OK;
	DWORD			dwData;
    SecBuffer *     pDataBuffer;
    SecBuffer *     pExtraBuffer;
    SecBuffer       ExtraBuffer;
	BOOL			bCanReadMore = TRUE;
	int				nError = UTE_SUCCESS;

	// Copy extra read data from the previous calls to the function
	if(m_lpszExtraReceivedData != NULL)
	{
		MoveMemory(m_lpszIoBuffer, m_lpszExtraReceivedData, m_dwExtraReceivedDataSize);
		dwIoBuffer = m_dwExtraReceivedDataSize;

		// Free extra read data
		LocalFree(m_lpszExtraReceivedData);
		m_lpszExtraReceivedData = NULL;
		m_dwExtraReceivedDataSize = 0;
	}

    // Read data from the socket
	// v4.2 changed - was while(TRUE)
    for (;;)
    {
        // Read some data.
        if(0 == dwIoBuffer || Status == SEC_E_INCOMPLETE_MESSAGE)
        {
			// Check if we need to read more data
			if(!bCanReadMore)
			{
				// Save extra read data
				if(m_lpszExtraReceivedData != NULL)
					LocalFree(m_lpszExtraReceivedData);
				m_lpszExtraReceivedData = (char *)LocalAlloc(LMEM_FIXED, dwIoBuffer + 10);
				MoveMemory(m_lpszExtraReceivedData, m_lpszIoBuffer, dwIoBuffer);
				m_dwExtraReceivedDataSize = dwIoBuffer;
				return UTE_SUCCESS;
			}

			// Read more data
            dwData = recv(s, m_lpszIoBuffer + dwIoBuffer, 
                          m_dwIoBufferLength - dwIoBuffer, 0);
            if(dwData == SOCKET_ERROR)
            {
                HandleSecurityError(_T("Error reading secure data from the server."));
                return UTE_SOCK_RECEIVE_ERROR;
            }
            else if(dwData == 0)
            {
                // Server disconnected.
                if(dwIoBuffer)
                {
                    HandleSecurityError(_T("Server unexpectedly disconnected."));
                    return UTE_FAILED_TO_RECEIVE_SECURITY_MESSAGE;
                }
                else
                {
                    break;
                }
            }
            else
            {
                dwIoBuffer += dwData;
            }
        }

        // Attempt to decrypt the received data.
        Buffers[0].pvBuffer     = m_lpszIoBuffer;
        Buffers[0].cbBuffer     = dwIoBuffer;
        Buffers[0].BufferType   = SECBUFFER_DATA;

        Buffers[1].BufferType   = SECBUFFER_EMPTY;
        Buffers[2].BufferType   = SECBUFFER_EMPTY;
        Buffers[3].BufferType   = SECBUFFER_EMPTY;

        Message.ulVersion       = SECBUFFER_VERSION;
        Message.cBuffers        = 4;
        Message.pBuffers        = Buffers;

        Status = m_SecurityFunc.DecryptMessage(m_phContext, &Message, 0, NULL);

        if(Status == SEC_E_INCOMPLETE_MESSAGE)
        {
            // The input buffer contains only a fragment of an
            // encrypted record. Loop around and read some more data.
            continue;
        }
	
        // Server signalled end of session
        if( Status == SEC_I_CONTEXT_EXPIRED || Status == SEC_E_CONTEXT_EXPIRED )
		{
		//	nError = UTE_SECURITY_CONTEXT_EXPIRED;
            break;
		}

        if( Status != SEC_E_OK && 
            Status != SEC_I_RENEGOTIATE && 
            Status != SEC_E_CONTEXT_EXPIRED &&
			Status != SEC_I_CONTEXT_EXPIRED 
			)
        {
            HandleSecurityError(_T("Failed to decrypt security message."));
			return UTE_FAILED_TO_DECRYPT_SECURITY_MESSAGE;
        }


        // Locate data and (optional) extra buffers.
        pDataBuffer  = NULL;
        pExtraBuffer = NULL;
        for(int i = 1; i < 4; i++)
        {
            if(pDataBuffer == NULL && Buffers[i].BufferType == SECBUFFER_DATA)
            {
                pDataBuffer = &Buffers[i];
            }
            if(pExtraBuffer == NULL && Buffers[i].BufferType == SECBUFFER_EXTRA)
            {
                pExtraBuffer = &Buffers[i];
            }
        }

		// Check decoded data buffer size
		if(pDataBuffer->cbBuffer > (m_dwDecodedDataMaxSize - m_dwDecodedDataSize))
		{
            HandleSecurityError(_T("Decrypted data buffer overflow."));
            return UTE_FAILED_TO_DECRYPT_SECURITY_MESSAGE;
		}

		// Move received and decoded data into the buffer
		MoveMemory( m_lpszDecodedData + m_dwDecodedDataSize, 
					pDataBuffer->pvBuffer, 
					pDataBuffer->cbBuffer);
		m_dwDecodedDataSize += pDataBuffer->cbBuffer;

		// Do not read any more data from the socket
		// We'll do it only on the next call to the MessageRecv
		bCanReadMore = FALSE;

        // Move any "extra" data to the input buffer.
        if(pExtraBuffer)
        {
            MoveMemory(m_lpszIoBuffer, pExtraBuffer->pvBuffer, pExtraBuffer->cbBuffer);
            dwIoBuffer = pExtraBuffer->cbBuffer;
        }
        else
        {
            dwIoBuffer = 0;
        }

		// The server wants to perform another handshake sequence.
        if(Status == SEC_I_RENEGOTIATE)
        {
			int nError = HandshakeLoop(s, FALSE, &ExtraBuffer);
            if(nError != UTE_SUCCESS)
                return nError;

            // Move any "extra" data to the input buffer.
            if(ExtraBuffer.pvBuffer)
            {
                MoveMemory(m_lpszIoBuffer, ExtraBuffer.pvBuffer, ExtraBuffer.cbBuffer);
                dwIoBuffer = ExtraBuffer.cbBuffer;
            }
        }
    }

	return nError;
}


// ===================================================================
// CUT_SecureSocketClient class
// ===================================================================

/***********************************************
CUT_SecureSocketClient
    Constructor
Params
    none
Return
    none
************************************************/
CUT_SecureSocketClient::CUT_SecureSocketClient() :
	m_aiKeyExch(0)
{
}

/***********************************************
~CUT_SecureSocketClient
    Destructor
Params
    none
Return
    none
************************************************/
CUT_SecureSocketClient::~CUT_SecureSocketClient() 
{
}

/***********************************************
CreateCredentials
	Create security credentials
Params
	Credentials are Data used by a principal to establish its own identity, such as 
	a password, or a Kerberos protocol ticket

	SSPI credential functions enable applications to gain access
	to the credentials of a principal and to free such access.
	Schannel credentials are based on the X.509 certificate. 
	Schannel still supports version 1 certificates, but using version 3
	certificates is recommended. Schannel does not perform certificate management.
	It relies on the application to perform certificate management using 
	CryptoAPI functions.
Return
    UTE_SUCCESS
	UTE_OPEN_CERTIFICATE_STORE_FAILED
	UTE_OUT_OF_MEMORY
	UTE_PARAMETER_INVALID_VALUE
	UTE_FAILED_TO_FIND_CERTIFICATE
	UTE_FAILED_TO_CREATE_SECURITY_CREDENTIALS
************************************************/
int CUT_SecureSocketClient::CreateCredentials()
{
    TimeStamp       tsExpiry;
    SECURITY_STATUS Status;
    DWORD           dwSupportedAlgs = 0;
    ALG_ID          rgbSupportedAlgs[16];
    PCCERT_CONTEXT  pCertContext = NULL;
	
	// If certificate context was set
	if(m_Certificate.GetContext() != NULL)
	{
		pCertContext = CertDuplicateCertificateContext(m_Certificate.GetContext());
		if(m_bCloseStore)
			CertCloseStore(m_hCertStore, 0);
		m_hCertStore = pCertContext->hCertStore;
		m_bCloseStore = FALSE;
	}
	else
	{
		// Open the certificate store, which is where Internet Explorer
		// stores its client certificates.
		if(m_hCertStore == NULL)
		{
			// Open the system certificate store		
			m_hCertStore = CertOpenSystemStore(0, m_szCertStoreName);
			if(m_hCertStore == NULL)
			{
				HandleSecurityError(_T("Failed to open system certificate store.")); 
				return UTE_OPEN_CERTIFICATE_STORE_FAILED;
			}

			m_bCloseStore = TRUE;
		}
		
		// If a user name is specified, then attempt to find a client
		// certificate. Otherwise, just create a NULL credential.
		if(*m_szCertSubjStr != NULL)
		{
			// Find client certificate.
			pCertContext = CertFindCertificateInStore(m_hCertStore, 
				X509_ASN_ENCODING, 
				0,
				CERT_FIND_SUBJECT_STR_A,
				m_szCertSubjStr,
				NULL);

			if(pCertContext == NULL)
			{
				HandleSecurityError(_T("Failed to find the certificate."));
				return UTE_FAILED_TO_FIND_CERTIFICATE;
			}
		}
	}

	// Check if certificate valid
	if(pCertContext && CertVerifyTimeValidity(NULL, pCertContext->pCertInfo) != 0)
	{
		// Free the certificate context. 
		if(pCertContext)
			CertFreeCertificateContext(pCertContext);

		HandleSecurityError(_T("Security certificate date is not valid."));
		return UTE_CERTIFICATE_INVALID_DATE;
	}

	
    // Build Schannel credential structure.
    ZeroMemory(&m_SchannelCred, sizeof(m_SchannelCred));
    m_SchannelCred.dwVersion  = SCHANNEL_CRED_VERSION;

	// Set credential certificate
    if(pCertContext)
    {
        m_SchannelCred.cCreds     = 1;
        m_SchannelCred.paCred     = &pCertContext;
    }
	
	// Set the protocol
    m_SchannelCred.grbitEnabledProtocols = m_dwProtocol;
	
	// Set the algorithm ID
    if(m_aiKeyExch)
	{
        rgbSupportedAlgs[dwSupportedAlgs++] = m_aiKeyExch;
        m_SchannelCred.cSupportedAlgs		= dwSupportedAlgs;
        m_SchannelCred.palgSupportedAlgs	= rgbSupportedAlgs;
    }
	
    m_SchannelCred.dwFlags |= SCH_CRED_NO_DEFAULT_CREDS;
    m_SchannelCred.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION;

	// Set cipher strength
	m_SchannelCred.dwMaximumCipherStrength = m_dwMaxCipherStrength;
	m_SchannelCred.dwMinimumCipherStrength = m_dwMinCipherStrength;

    // Free SSPI credentials handle (if we create it before) or create a new one
	if(m_phCreds != NULL)
		m_SecurityFunc.FreeCredentialsHandle(m_phCreds);
	else
		m_phCreds = new CredHandle;

	
    // Create an SSPI credential.
    //
	// Data used by a principal to establish its own identity, such as 
	// a password, or a Kerberos protocol ticket
	// SSPI credential functions enable applications to gain access
	// to the credentials of a principal and to free such access.
	// Schannel credentials are based on the X.509 certificate. 
	// Schannel still supports version 1 certificates, but using version 3
	// certificates is recommended. Schannel does not perform certificate management.
	// It relies on the application to perform certificate management using CryptoAPI functions
    Status = m_SecurityFunc.AcquireCredentialsHandle(
		NULL,                   // Name of principal    
		UNISP_NAME,             // Name of package
		SECPKG_CRED_OUTBOUND,   // Flags indicating use
		NULL,                   // Pointer to logon ID
		&m_SchannelCred,        // Package specific data
		NULL,                   // Pointer to GetKey() func
		NULL,                   // Value to pass to GetKey()
		m_phCreds,              // (out) Cred Handle
		&tsExpiry);             // (out) Lifetime (optional)

	// Free the certificate context. 
	if(pCertContext)
		CertFreeCertificateContext(pCertContext);

	// Check status
	if(Status != SEC_E_OK)
    {
	   HandleSecurityError(_T("Failed to acquire credentials handle."));
		delete m_phCreds;
		m_phCreds = NULL;
        return UTE_FAILED_TO_CREATE_SECURITY_CREDENTIALS;
    }
   
    return UTE_SUCCESS;
}

/***********************************************
PerformHandshake
	Perform client handshake	
Params
	Socket			- connected socket
	le	- server name
	pExtraData		- extra data returned by handshake
Return
    UTE_SUCCESS
	UTE_FAILED_TO_INITIALIZE_SECURITY_CONTEXT
	UTE_SOCK_SEND_ERROR
************************************************/
int CUT_SecureSocketClient::PerformHandshake(
    SOCKET          Socket,         // in
    const _TCHAR *	lpszServerName, // in
    SecBuffer *     pExtraData)     // out
{
    SecBufferDesc   OutBuffer;
    SecBuffer       OutBuffers[1];
    DWORD           dwSSPIFlags;
    DWORD           dwSSPIOutFlags;
    TimeStamp       tsExpiry;
    SECURITY_STATUS scRet;
    DWORD           cbData;

    dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT   |
                  ISC_REQ_REPLAY_DETECT     |
                  ISC_REQ_CONFIDENTIALITY   |
                  ISC_RET_EXTENDED_ERROR    |
                  ISC_REQ_ALLOCATE_MEMORY   |
                  ISC_REQ_STREAM;

    //  Initiate a ClientHello message and generate a token.
    OutBuffers[0].pvBuffer   = NULL;
    OutBuffers[0].BufferType = SECBUFFER_TOKEN;
    OutBuffers[0].cbBuffer   = 0;

    OutBuffer.cBuffers = 1;
    OutBuffer.pBuffers = OutBuffers;
    OutBuffer.ulVersion = SECBUFFER_VERSION;

	// Create new or delete old context
	if(m_phContext != NULL)
		m_SecurityFunc.DeleteSecurityContext(m_phContext);
	else
		m_phContext = new CtxtHandle;

    scRet = m_SecurityFunc.InitializeSecurityContext(
                    m_phCreds,
                    NULL,
                    (_TCHAR*)lpszServerName,
                    dwSSPIFlags,
                    0,
                    SECURITY_NATIVE_DREP,
                    NULL,
                    0,
                    m_phContext,
                    &OutBuffer,
                    &dwSSPIOutFlags,
                    &tsExpiry);

    if(scRet != SEC_I_CONTINUE_NEEDED)
    {
        HandleSecurityError(_T("Failed to initialize security context."));
		delete m_phCreds;
		m_phCreds = NULL;
        return UTE_FAILED_TO_INITIALIZE_SECURITY_CONTEXT;
    }

    // Send response to server if there is one.
    if(OutBuffers[0].cbBuffer != 0 && OutBuffers[0].pvBuffer != NULL)
    {
        cbData = send(Socket, (const char *)OutBuffers[0].pvBuffer, OutBuffers[0].cbBuffer, 0);
        if(cbData == SOCKET_ERROR || cbData == 0)
        {
            HandleSecurityError(_T("Error sending secure data to the server."));
            m_SecurityFunc.FreeContextBuffer(OutBuffers[0].pvBuffer);
            m_SecurityFunc.DeleteSecurityContext(m_phContext);
            return UTE_SOCK_SEND_ERROR;
        }

        // Free output buffer.
        m_SecurityFunc.FreeContextBuffer(OutBuffers[0].pvBuffer);
        OutBuffers[0].pvBuffer = NULL;
    }

    return HandshakeLoop(Socket, TRUE, pExtraData);
}

/***********************************************
HandshakeLoop
	Helper function used in the handshake
Params
	Socket			- connected socket
	fDoInitialRead	- should read first
	pExtraData		- extra data returned by handshake
Return
	UTE_SUCCESS
	UTE_OUT_OF_MEMORY    
	UTE_SOCK_RECEIVE_ERROR
	UTE_SOCK_SEND_ERROR
	UTE_FAILED_TO_INITIALIZE_SECURITY_CONTEXT
************************************************/
int CUT_SecureSocketClient::HandshakeLoop(
    SOCKET          Socket,         // in
    BOOL            fDoInitialRead, // in
    SecBuffer *     pExtraData)     // out
{
    SecBufferDesc   InBuffer;
    SecBuffer       InBuffers[2];
    SecBufferDesc   OutBuffer;
    SecBuffer       OutBuffers[1];
    DWORD           dwSSPIFlags;
    DWORD           dwSSPIOutFlags;
    TimeStamp       tsExpiry;
    SECURITY_STATUS scRet;
    DWORD           cbData;

    PUCHAR          IoBuffer;
    DWORD           dwIoBuffer;
    BOOL            bDoRead;

	int				nError = UTE_SUCCESS;


    dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT   |
                  ISC_REQ_REPLAY_DETECT     |
                  ISC_REQ_CONFIDENTIALITY   |
                  ISC_RET_EXTENDED_ERROR    |
                  ISC_REQ_ALLOCATE_MEMORY   |
                  ISC_REQ_STREAM;

    // Allocate data buffer.
    IoBuffer = (PUCHAR)LocalAlloc(LMEM_FIXED, IO_BUFFER_SIZE);
    if(IoBuffer == NULL)
        return UTE_OUT_OF_MEMORY;
    
    dwIoBuffer = 0;

    bDoRead = fDoInitialRead;

    // Loop until the handshake is finished or an error occurs.
    scRet = SEC_I_CONTINUE_NEEDED;
    while(scRet == SEC_I_CONTINUE_NEEDED        ||
          scRet == SEC_E_INCOMPLETE_MESSAGE     ||
          scRet == SEC_I_INCOMPLETE_CREDENTIALS) 
	{
        // Read data from server.
        if(dwIoBuffer == 0 || scRet == SEC_E_INCOMPLETE_MESSAGE)
        {
            if(bDoRead)
            {
                cbData = recv(Socket, (char *)IoBuffer + dwIoBuffer, IO_BUFFER_SIZE - dwIoBuffer, 0);
                if(cbData == SOCKET_ERROR || cbData == 0)
                {
                    HandleSecurityError(_T("Error reading secure data from the server."));
                    nError = UTE_SOCK_RECEIVE_ERROR;
                    break;
                }

                dwIoBuffer += cbData;
            }
            else
            {
                bDoRead = TRUE;
            }
        }

        // Set up the input buffers. Buffer 0 is used to pass in data
        // received from the server. Schannel will consume some or all
        // of this. Leftover data (if any) will be placed in buffer 1 and
        // given a buffer type of SECBUFFER_EXTRA.
        InBuffers[0].pvBuffer   = IoBuffer;
        InBuffers[0].cbBuffer   = dwIoBuffer;
        InBuffers[0].BufferType = SECBUFFER_TOKEN;

        InBuffers[1].pvBuffer   = NULL;
        InBuffers[1].cbBuffer   = 0;
        InBuffers[1].BufferType = SECBUFFER_EMPTY;

        InBuffer.cBuffers       = 2;
        InBuffer.pBuffers       = InBuffers;
        InBuffer.ulVersion      = SECBUFFER_VERSION;

        // Set up the output buffers. These are initialized to NULL
        // so as to make it less likely we'll attempt to free random
        // garbage later.
        OutBuffers[0].pvBuffer  = NULL;
        OutBuffers[0].BufferType= SECBUFFER_TOKEN;
        OutBuffers[0].cbBuffer  = 0;

        OutBuffer.cBuffers      = 1;
        OutBuffer.pBuffers      = OutBuffers;
        OutBuffer.ulVersion     = SECBUFFER_VERSION;

        // Call InitializeSecurityContext.
        scRet = m_SecurityFunc.InitializeSecurityContext(m_phCreds,
                                          m_phContext,
                                          NULL,
                                          dwSSPIFlags,
                                          0,
                                          SECURITY_NATIVE_DREP,
                                          &InBuffer,
                                          0,
                                          NULL,
                                          &OutBuffer,
                                          &dwSSPIOutFlags,
                                          &tsExpiry);

        // If InitializeSecurityContext was successful (or if the error was 
        // one of the special extended ones), send the contends of the output
        // buffer to the server.
        if(scRet == SEC_E_OK                ||
           scRet == SEC_I_CONTINUE_NEEDED   ||
           FAILED(scRet) && (dwSSPIOutFlags & ISC_RET_EXTENDED_ERROR))
        {
            if(OutBuffers[0].cbBuffer != 0 && OutBuffers[0].pvBuffer != NULL)
            {
                cbData = send(Socket, (const char *)OutBuffers[0].pvBuffer, OutBuffers[0].cbBuffer, 0);
                if(cbData == SOCKET_ERROR || cbData == 0)
                {
                    HandleSecurityError(_T("Error secure sending data to the server."));
                    m_SecurityFunc.FreeContextBuffer(OutBuffers[0].pvBuffer);
                    m_SecurityFunc.DeleteSecurityContext(m_phContext);
                    return UTE_SOCK_SEND_ERROR;
                }

                // Free output buffer.
                m_SecurityFunc.FreeContextBuffer(OutBuffers[0].pvBuffer);
                OutBuffers[0].pvBuffer = NULL;
            }
        }

        // If InitializeSecurityContext returned SEC_E_INCOMPLETE_MESSAGE,
        // then we need to read more data from the server and try again.
        if(scRet == SEC_E_INCOMPLETE_MESSAGE)
        {
            continue;
        }

        // If InitializeSecurityContext returned SEC_E_OK, then the 
        // handshake completed successfully.
        if(scRet == SEC_E_OK)
        {
            // If the "extra" buffer contains data, this is encrypted application
            // protocol layer stuff. It needs to be saved. The application layer
            // will later decrypt it with DecryptMessage.
            if(InBuffers[1].BufferType == SECBUFFER_EXTRA)
            {
                pExtraData->pvBuffer = LocalAlloc(LMEM_FIXED, InBuffers[1].cbBuffer);
                if(pExtraData->pvBuffer == NULL)
                {
                    HandleSecurityError(_T("Out of memory."));
                    return UTE_OUT_OF_MEMORY;
                }

                MoveMemory(pExtraData->pvBuffer,
                           IoBuffer + (dwIoBuffer - InBuffers[1].cbBuffer),
                           InBuffers[1].cbBuffer);

                pExtraData->cbBuffer   = InBuffers[1].cbBuffer;
                pExtraData->BufferType = SECBUFFER_TOKEN;
            }
            else
            {
                pExtraData->pvBuffer   = NULL;
                pExtraData->cbBuffer   = 0;
                pExtraData->BufferType = SECBUFFER_EMPTY;
            }

			// Quit
			nError = UTE_SUCCESS;
            break;
        }

        // Check for fatal error.
        if(FAILED(scRet))
        {
            HandleSecurityError(_T("Failed to initialize security context."));
			nError = UTE_FAILED_TO_INITIALIZE_SECURITY_CONTEXT;
            break;
        }

        // If InitializeSecurityContext returned SEC_I_INCOMPLETE_CREDENTIALS,
        // then the server just requested client authentication. 
        if(scRet == SEC_I_INCOMPLETE_CREDENTIALS)
        {
            // Display trusted issuers info. 
            GetNewCredentials();

            // Go around again.
            bDoRead = FALSE;
            scRet = SEC_I_CONTINUE_NEEDED;
            continue;
        }

        // Copy any leftover data from the "extra" buffer, and go around again
        if ( InBuffers[1].BufferType == SECBUFFER_EXTRA )
        {
            MoveMemory(IoBuffer,
                       IoBuffer + (dwIoBuffer - InBuffers[1].cbBuffer),
                       InBuffers[1].cbBuffer);

            dwIoBuffer = InBuffers[1].cbBuffer;
        }
        else
        {
            dwIoBuffer = 0;
        }
    }

    // Delete the security context in the case of a fatal error.
    if(FAILED(scRet))
        m_SecurityFunc.DeleteSecurityContext(m_phContext);

    LocalFree(IoBuffer);

    return nError;
}

/***********************************************
GetNewCredentials
	Helper function used in the handshake
Params
	none
Return
    SECURITY_STATUS
************************************************/
void CUT_SecureSocketClient::GetNewCredentials()
{
	SecPkgContext_IssuerListInfoEx IssuerListInfo;
	CERT_CHAIN_FIND_BY_ISSUER_PARA FindByIssuerPara;
	PCCERT_CHAIN_CONTEXT	pChainContext;
    CredHandle				hCreds;
    PCCERT_CONTEXT			pCertContext;
    TimeStamp				tsExpiry;
    SECURITY_STATUS			Status;

    // Read list of trusted issuers from schannel.
    Status = m_SecurityFunc.QueryContextAttributes(m_phContext,
                                    SECPKG_ATTR_ISSUER_LIST_EX,
                                    (PVOID)&IssuerListInfo);
    if(Status != SEC_E_OK)
    {
		m_SecurityFunc.FreeContextBuffer((PVOID)&IssuerListInfo);
	       HandleSecurityError(_T("Error querying issuer list info."));
        return;
    }

    // Enumerate the client certificates.
    ZeroMemory(&FindByIssuerPara, sizeof(FindByIssuerPara));

    FindByIssuerPara.cbSize = sizeof(FindByIssuerPara);
    FindByIssuerPara.pszUsageIdentifier = szOID_PKIX_KP_CLIENT_AUTH;
    FindByIssuerPara.dwKeySpec = 0;
    FindByIssuerPara.cIssuer   = IssuerListInfo.cIssuers;
    FindByIssuerPara.rgIssuer  = IssuerListInfo.aIssuers;

    pChainContext = NULL;

	// v4.2 changed - was while(TRUE)
    for (;;)
    {
        // Find a certificate chain.
        pChainContext = CertFindChainInStore(m_hCertStore,
                                             X509_ASN_ENCODING,
                                             0,
                                             CERT_CHAIN_FIND_BY_ISSUER,
                                             &FindByIssuerPara,
                                             pChainContext);
        if(pChainContext == NULL)
        {
            HandleSecurityError(_T("Error finding certificate chain."));
            break;
        }

        // Get pointer to leaf certificate context.
        pCertContext = pChainContext->rgpChain[0]->rgpElement[0]->pCertContext;

        // Create schannel credential.
        m_SchannelCred.cCreds = 1;
        m_SchannelCred.paCred = &pCertContext;

		// Set cipher strength
		m_SchannelCred.dwMaximumCipherStrength = m_dwMaxCipherStrength;
		m_SchannelCred.dwMinimumCipherStrength = m_dwMinCipherStrength;

        Status = m_SecurityFunc.AcquireCredentialsHandle(
                            NULL,                   // Name of principal
                            UNISP_NAME,           // Name of package
                            SECPKG_CRED_OUTBOUND,   // Flags indicating use
                            NULL,                   // Pointer to logon ID
                            &m_SchannelCred,        // Package specific data
                            NULL,                   // Pointer to GetKey() func
                            NULL,                   // Value to pass to GetKey()
                            &hCreds,                // (out) Cred Handle
                            &tsExpiry);             // (out) Lifetime (optional)
        if(Status != SEC_E_OK)
        {
            HandleSecurityError(_T("Failed to acquire credentials handle."));
            continue;
        }

        // Destroy the old credentials.
        m_SecurityFunc.FreeCredentialsHandle(m_phCreds);

        *m_phCreds = hCreds;

        break;
    }
	
	m_SecurityFunc.FreeContextBuffer((PVOID)&IssuerListInfo);
		
}

/***********************************************
VerifyCertificate
	Verifies server's sertificate
Params
	pszServerName	- server's name
	dwCertFlags		- sertificate flags
Return
	UTE_SUCCESS    
	UTE_OUT_OF_MEMORY
	UTE_FAILED_TO_QUERY_CERTIFICATE
	UTE_NULL_PARAM
	UTE_PARAMETER_INVALID_VALUE
	UTE_FAILED_TO_GET_CERTIFICATE_CHAIN
	UTE_FAILED_TO_VERIFY_CERTIFICATE_CHAIN
	UTE_FAILED_TO_VERIFY_CERTIFICATE_TRUST
************************************************/
int CUT_SecureSocketClient::VerifyCertificate(
    PTSTR           pszServerName,
    DWORD           dwCertFlags)
{
    HTTPSPolicyCallbackData  polHttps;
    CERT_CHAIN_POLICY_PARA   PolicyPara;
    CERT_CHAIN_POLICY_STATUS PolicyStatus;
    CERT_CHAIN_PARA          ChainPara;
    PCCERT_CHAIN_CONTEXT     pChainContext = NULL;
	PCCERT_CONTEXT           pRemoteCertContext = NULL;

    DWORD   Status;
    PWSTR   pwszServerName;
	int		nError = UTE_SUCCESS;

	// Client authentication flag not set 
	if(m_CertValidation == CERT_DONOT_VERIFY)
		return UTE_SUCCESS;

    // Get server's certificate.
    Status = m_SecurityFunc.QueryContextAttributes(m_phContext,
                                    SECPKG_ATTR_REMOTE_CERT_CONTEXT,
                                    (PVOID)&pRemoteCertContext);
    if(Status != SEC_E_OK)
    {
        HandleSecurityError(_T("Error querying remote certificate."));
		CertFreeCertificateContext(pRemoteCertContext);
		pRemoteCertContext = NULL;

        return UTE_FAILED_TO_QUERY_CERTIFICATE;
    }

    if(pszServerName == NULL || _tcslen(pszServerName) == 0)
        return UTE_NULL_PARAM;

// v4.2 changes - previous code all ascii
#if !defined _UNICODE
    // Convert server name to unicode.
    DWORD   cchServerName;
    cchServerName = MultiByteToWideChar(CP_ACP, 0, pszServerName, -1, NULL, 0);
    pwszServerName = (PWSTR)LocalAlloc(LMEM_FIXED, cchServerName * sizeof(WCHAR));
    if(pwszServerName == NULL)
	{
		if (pRemoteCertContext)
		{
			CertFreeCertificateContext(pRemoteCertContext);
			pRemoteCertContext = NULL;
		}

        return UTE_OUT_OF_MEMORY;
	}
    cchServerName = MultiByteToWideChar(CP_ACP, 0, pszServerName, -1, pwszServerName, cchServerName);
    if(cchServerName == 0)
	{
		// Free memory
		LocalFree(pwszServerName);
		if (pRemoteCertContext)
		{
		CertFreeCertificateContext(pRemoteCertContext);
		pRemoteCertContext = NULL;
		}

        return UTE_PARAMETER_INVALID_VALUE;
	}
#else
	pwszServerName = (PWSTR)LocalAlloc(LMEM_FIXED, _tcslen(pszServerName) * sizeof(WCHAR) + sizeof(WCHAR));
	_tcscpy(pwszServerName, pszServerName);
#endif

    // Build certificate chain.
    ZeroMemory(&ChainPara, sizeof(ChainPara));
    ChainPara.cbSize = sizeof(ChainPara);

    if(!CertGetCertificateChain(
                            NULL,
                            pRemoteCertContext,
                            NULL,
                            pRemoteCertContext->hCertStore,
                            &ChainPara,
                            0,
                            NULL,
                            &pChainContext))
    {
        Status = GetLastError();
		nError = UTE_FAILED_TO_GET_CERTIFICATE_CHAIN;
        HandleSecurityError(_T("Failed to get the certificate chain."));
    }
	else
	{
		// Validate certificate chain.
		ZeroMemory(&polHttps, sizeof(HTTPSPolicyCallbackData));
		polHttps.cbStruct           = sizeof(HTTPSPolicyCallbackData);
		polHttps.dwAuthType         = AUTHTYPE_SERVER;
		polHttps.fdwChecks          = dwCertFlags;
		polHttps.pwszServerName     = pwszServerName;

		memset(&PolicyPara, 0, sizeof(PolicyPara));
		PolicyPara.cbSize            = sizeof(PolicyPara);
		PolicyPara.pvExtraPolicyPara = &polHttps;

		memset(&PolicyStatus, 0, sizeof(PolicyStatus));
		PolicyStatus.cbSize = sizeof(PolicyStatus);

		if(!CertVerifyCertificateChainPolicy(
								CERT_CHAIN_POLICY_SSL,
								pChainContext,
								&PolicyPara,
								&PolicyStatus))
		{
			Status = GetLastError();
			nError = UTE_FAILED_TO_VERIFY_CERTIFICATE_CHAIN;
			HandleSecurityError(_T("Failed to verify certificate chain policy."));
		}
		else
		{
			nError = UTE_SUCCESS;
			if(PolicyStatus.dwError)
			{
//				if(!OnCertVerifyError(CUT_Certificate(pRemoteCertContext), PolicyStatus.dwError, pszServerName))
				// v4.2 changed to avert warning")
				CUT_Certificate cert(pRemoteCertContext);
				if(!OnCertVerifyError(cert, PolicyStatus.dwError, pszServerName))
				{
					Status = PolicyStatus.dwError;
					nError = UTE_FAILED_TO_VERIFY_CERTIFICATE_TRUST;
					DisplayWinVerifyTrustError(Status); 
				}
			}
		}

		// Free memory
		LocalFree(pwszServerName);
	}

  
	//  Prevent Memory leak of LSAHost of Win2000
	if (pRemoteCertContext)
	{
		CertFreeCertificateContext(pRemoteCertContext);
		pRemoteCertContext = NULL;
	}


    return nError;
}


// ===================================================================
// CUT_SecureSocketServer class
// ===================================================================

/***********************************************
CUT_SecureSocketServer
    Constructor
Params
    none
Return
    none
************************************************/
CUT_SecureSocketServer::CUT_SecureSocketServer() :
	m_bMachineStore(FALSE),
	m_bClientAuth(FALSE)
{
	// No certificate validation on the server by default
	m_CertValidation = CERT_DONOT_VERIFY;
}

/***********************************************
~CUT_SecureSocketServer
    Destructor
Params
    none
Return
    none
************************************************/
CUT_SecureSocketServer::~CUT_SecureSocketServer() 
{
}

/***********************************************
CreateCredentials
	Create security credentials
Params
	Credentials are Data used by a principal to establish its own identity, such as 
	a password, or a Kerberos protocol ticket

	SSPI credential functions enable applications to gain access
	to the credentials of a principal and to free such access.
	Schannel credentials are based on the X.509 certificate. 
	Schannel still supports version 1 certificates, but using version 3
	certificates is recommended. Schannel does not perform certificate management.
	It relies on the application to perform certificate management using 
	CryptoAPI functions.
Return
    UTE_SUCCESS
	UTE_NULL_PARAM
	UTE_OPEN_CERTIFICATE_STORE_FAILED
	UTE_OUT_OF_MEMORY
	UTE_FAILED_TO_CREATE_SECURITY_CREDENTIALS
	UTE_CERTIFICATE_INVALID_DATE
************************************************/
int CUT_SecureSocketServer::CreateCredentials()
{
    SCHANNEL_CRED   SchannelCred;
    TimeStamp       tsExpiry;
    SECURITY_STATUS Status;
    PCCERT_CONTEXT  pCertContext = NULL;

	// Already created
	if(m_phCreds != NULL)
		return UTE_SUCCESS;

	// If certificate context was set
	if(m_Certificate.GetContext() != NULL)
	{
		pCertContext = CertDuplicateCertificateContext(m_Certificate.GetContext());
		if(m_bCloseStore)
			CertCloseStore(m_hCertStore, 0);
		m_hCertStore = pCertContext->hCertStore;
		m_bCloseStore = FALSE;
	}
	else
	{
		// Check parameters
		if(m_szCertSubjStr == NULL || _tcslen(m_szCertSubjStr) == 0)
		{
			HandleSecurityError(_T("No certificate specified!"));
			return UTE_NULL_PARAM;
		}

		// Open the certificate store
		if(m_hCertStore == NULL)
		{
			PWSTR   pwszCertStoreName;

// v4.2 changes - previous code all ascii
#if !defined _UNICODE
			// Convert store name protocol name to Unicode
			DWORD   dwCertStoreName;
			dwCertStoreName = MultiByteToWideChar(CP_ACP, 0, m_szCertStoreName, -1, NULL, 0);
			pwszCertStoreName = (PWSTR)LocalAlloc(LMEM_FIXED, dwCertStoreName * sizeof(WCHAR));
			if(dwCertStoreName == NULL)
				return UTE_OUT_OF_MEMORY;
			dwCertStoreName = MultiByteToWideChar(CP_ACP, 0, m_szCertStoreName, -1, pwszCertStoreName, dwCertStoreName);
			if(dwCertStoreName == 0)
			{
				// Free memory
				LocalFree(pwszCertStoreName);
				return UTE_PARAMETER_INVALID_VALUE;
			}
#else
	pwszCertStoreName = (PWSTR)LocalAlloc(LMEM_FIXED, _tcslen(m_szCertStoreName) * sizeof(WCHAR) + sizeof(WCHAR));
	_tcscpy(pwszCertStoreName, m_szCertStoreName);
#endif
			m_hCertStore = CertOpenStore(
				CERT_STORE_PROV_SYSTEM,
				X509_ASN_ENCODING , 
				0,
				(m_bMachineStore) ? CERT_SYSTEM_STORE_LOCAL_MACHINE : CERT_SYSTEM_STORE_CURRENT_USER, 
				pwszCertStoreName);

			// Free memory
			LocalFree(pwszCertStoreName);

			if(!m_hCertStore)
			{
				HandleSecurityError(_T("Failed to open certificate store."));
				return UTE_OPEN_CERTIFICATE_STORE_FAILED;
			}

			m_bCloseStore = TRUE;
		}

		// Find certificate.
		pCertContext = CertFindCertificateInStore(m_hCertStore, 
												  X509_ASN_ENCODING, 
												  0,
												  CERT_FIND_SUBJECT_STR,
												  m_szCertSubjStr,
												  NULL);
		if(pCertContext == NULL)
		{
			HandleSecurityError(_T("Failed to find the certificate."));
			return UTE_FAILED_TO_FIND_CERTIFICATE;
		}
	}

	// Check if certificate valid
	if(CertVerifyTimeValidity(NULL, pCertContext->pCertInfo) != 0)
	{
		// Free the certificate context. 
		if(pCertContext)
			CertFreeCertificateContext(pCertContext);

		HandleSecurityError(_T("Security certificate date is not valid."));
		return UTE_CERTIFICATE_INVALID_DATE;
	}

    // Build Schannel credential structure.
    ZeroMemory(&SchannelCred, sizeof(SchannelCred));
    SchannelCred.dwVersion = SCHANNEL_CRED_VERSION;
    SchannelCred.cCreds = 1;
    SchannelCred.paCred = &pCertContext;
    SchannelCred.grbitEnabledProtocols = m_dwProtocol;

	// Set cipher strength
	SchannelCred.dwMaximumCipherStrength = m_dwMaxCipherStrength;
	SchannelCred.dwMinimumCipherStrength = m_dwMinCipherStrength;

    // Free SSPI credentials handle (if we create it before) or create a new one
	if(m_phCreds != NULL)
		m_SecurityFunc.FreeCredentialsHandle(m_phCreds);
	else
		m_phCreds = new CredHandle;

    // Create an SSPI credential.
    Status = m_SecurityFunc.AcquireCredentialsHandle( 
                        NULL,                   // Name of principal
                        UNISP_NAME,             // Name of package
                        SECPKG_CRED_INBOUND,    // Flags indicating use
                        NULL,                   // Pointer to logon ID
                        &SchannelCred,          // Package specific data
                        NULL,                   // Pointer to GetKey() func
                        NULL,                   // Value to pass to GetKey()
                        m_phCreds,              // (out) Cred Handle
                        &tsExpiry);             // (out) Lifetime (optional)

	// Free the certificate context. 
	if(pCertContext)
		CertFreeCertificateContext(pCertContext);

	// Check status
	if(Status != SEC_E_OK)
    {
        HandleSecurityError(_T("Failed to acquire credentials handle."));
		delete m_phCreds;
		m_phCreds = NULL;
        return UTE_FAILED_TO_CREATE_SECURITY_CREDENTIALS;
    }

    return UTE_SUCCESS;
}

/***********************************************
PerformHandshake
	Perform client handshake	
Params
	Socket			- connected socket
	lpszServerName	- server name
	pExtraData		- extra data returned by handshake
Return
    UTE_SUCCESS
	UTE_OUT_OF_MEMORY
	UTE_SOCK_RECEIVE_ERROR
	UTE_FAILED_TO_ACCEPT_SECURITY_CONTEXT
	UTE_HANDSHAKE_FAILED
************************************************/
int CUT_SecureSocketServer::PerformHandshake(
    SOCKET          Socket,         // in
    const TCHAR *	/* lpszServerName */, // in
    SecBuffer *     /* pExtraData */)     // out
{
    TimeStamp            tsExpiry;
    SECURITY_STATUS      scRet = SEC_E_SECPKG_NOT_FOUND;	// default error if we run out of packages
    SecBufferDesc        InBuffer;
    SecBufferDesc        OutBuffer;
    SecBuffer            InBuffers[2];
    SecBuffer            OutBuffers[1];
    DWORD                err = 0;
    BOOL                 bDoRead = TRUE;
    BOOL                 bInitContext = TRUE;
    DWORD                dwIoBuffer = 0, dwSSPIFlags, dwSSPIOutFlags;


    dwSSPIFlags =   ASC_REQ_SEQUENCE_DETECT        |
                    ASC_REQ_REPLAY_DETECT      |
                    ASC_REQ_CONFIDENTIALITY  |
                    ASC_REQ_EXTENDED_ERROR    |
                    ASC_REQ_ALLOCATE_MEMORY  |
                    ASC_REQ_STREAM;

    if(m_bClientAuth)
        dwSSPIFlags |= ASC_REQ_MUTUAL_AUTH;

	// Allocate temp IO buffer memory
	if(m_lpszIoBuffer == NULL)
	{
		// Allocate a working buffer. 
		m_dwIoBufferLength = IO_BUFFER_SIZE;
		m_lpszIoBuffer = (char *)LocalAlloc(LMEM_FIXED, m_dwIoBufferLength + 10);
		if(m_lpszIoBuffer == NULL)
			return UTE_OUT_OF_MEMORY;
	}

    // Set OutBuffer for InitializeSecurityContext call
    OutBuffer.cBuffers = 1;
    OutBuffer.pBuffers = OutBuffers;
    OutBuffer.ulVersion = SECBUFFER_VERSION;

    // Check to see if we've done 
    scRet = SEC_I_CONTINUE_NEEDED;

    while( scRet == SEC_I_CONTINUE_NEEDED ||
            scRet == SEC_E_INCOMPLETE_MESSAGE ||
            scRet == SEC_I_INCOMPLETE_CREDENTIALS) 
    {
        if(0 == dwIoBuffer || scRet == SEC_E_INCOMPLETE_MESSAGE)
        {
            if(bDoRead)
            {
                err = recv(Socket, m_lpszIoBuffer+dwIoBuffer, IO_BUFFER_SIZE, 0);
                if (err == SOCKET_ERROR || err == 0)
                {
                    HandleSecurityError(_T("Failed to receive secure data."));
                    return UTE_SOCK_RECEIVE_ERROR;
                }
                else
                {
                    dwIoBuffer += err;
                }
            }
            else
            {
                bDoRead = TRUE;
            }
        }

        // InBuffers[1] is for getting extra data that
        // SSPI/SCHANNEL doesn't proccess on this
        // run around the loop.
        InBuffers[0].pvBuffer = m_lpszIoBuffer;
        InBuffers[0].cbBuffer = dwIoBuffer;
        InBuffers[0].BufferType = SECBUFFER_TOKEN;

        InBuffers[1].pvBuffer   = NULL;
        InBuffers[1].cbBuffer   = 0;
        InBuffers[1].BufferType = SECBUFFER_EMPTY;

        InBuffer.cBuffers        = 2;
        InBuffer.pBuffers        = InBuffers;
        InBuffer.ulVersion       = SECBUFFER_VERSION;

        // Initialize these so if we fail, pvBuffer contains NULL,
        // so we don't try to free random garbage at the quit
        OutBuffers[0].pvBuffer   = NULL;
        OutBuffers[0].BufferType = SECBUFFER_TOKEN;
        OutBuffers[0].cbBuffer   = 0;

		// Create new context
		if(m_phContext == NULL)
		{
			m_phContext = new CtxtHandle;
			m_phContext->dwLower = NULL;
			m_phContext->dwUpper = NULL;
			bInitContext = TRUE;
		}
		else
		{
			bInitContext = FALSE;
		}

        scRet = m_SecurityFunc.AcceptSecurityContext(
                        m_phCreds,
                        (bInitContext)?NULL:m_phContext,
                        &InBuffer,
                        dwSSPIFlags,
                        SECURITY_NATIVE_DREP,
                        (bInitContext)?m_phContext:NULL,
                        &OutBuffer,
                        &dwSSPIOutFlags,
                        &tsExpiry);

        if ( scRet == SEC_E_OK ||
             scRet == SEC_I_CONTINUE_NEEDED ||
             (FAILED(scRet) && (0 != (dwSSPIOutFlags & ISC_RET_EXTENDED_ERROR))))
        {
            if  (OutBuffers[0].cbBuffer != 0    &&
                 OutBuffers[0].pvBuffer != NULL )
            {
                // Send response if there is one
                err = send( Socket,
                            (const char *)OutBuffers[0].pvBuffer,
                            OutBuffers[0].cbBuffer,
                            0 );

                m_SecurityFunc.FreeContextBuffer( OutBuffers[0].pvBuffer );
                OutBuffers[0].pvBuffer = NULL;
            }
        }


        if ( scRet == SEC_E_OK )
        {
            if ( InBuffers[1].BufferType == SECBUFFER_EXTRA )
            {
                    memcpy(m_lpszIoBuffer,
                           (LPBYTE) (m_lpszIoBuffer + (dwIoBuffer - InBuffers[1].cbBuffer)),
                            InBuffers[1].cbBuffer);
                    dwIoBuffer = InBuffers[1].cbBuffer;
            }
            else
            {
                dwIoBuffer = 0;
            }

            return UTE_SUCCESS;
        }
        else if (FAILED(scRet) && (scRet != SEC_E_INCOMPLETE_MESSAGE))
        {
            HandleSecurityError(_T("Failed to accept security context."));
            return UTE_FAILED_TO_ACCEPT_SECURITY_CONTEXT;
        }

        if ( scRet != SEC_E_INCOMPLETE_MESSAGE &&
             scRet != SEC_I_INCOMPLETE_CREDENTIALS)
        {
            if ( InBuffers[1].BufferType == SECBUFFER_EXTRA )
            {
                memcpy(m_lpszIoBuffer,
                       (LPBYTE) (m_lpszIoBuffer + (dwIoBuffer - InBuffers[1].cbBuffer)),
                        InBuffers[1].cbBuffer);
                dwIoBuffer = InBuffers[1].cbBuffer;
            }
            else
            {
                // Prepare for next receive
                dwIoBuffer = 0;
            }
        }
    }

    return UTE_HANDSHAKE_FAILED;
}

/***********************************************
HandshakeLoop
	Helper function used in the handshake
Params
	Socket			- connected socket
	fDoInitialRead	- should read first
	pExtraData		- extra data returned by handshake
Return
    UTE_HANDSHAKE_FAILED
************************************************/
int CUT_SecureSocketServer::HandshakeLoop(
    SOCKET          /* Socket */,         // in
    BOOL            /* fDoInitialRead */, // in
    SecBuffer *     /* pExtraData */)     // out
{
	return UTE_HANDSHAKE_FAILED;
}

/***********************************************
GetNewCredentials
	Helper function used in the handshake
Params
	none
Return
    SECURITY_STATUS
************************************************/
void CUT_SecureSocketServer::GetNewCredentials()
{
}

/***********************************************
VerifyCertificate
	Verifies server's sertificate
Params
	pszServerName	- server's name
	dwCertFlags		- sertificate flags
Return
	UTE_SUCCESS
	UTE_FAILED_TO_QUERY_CERTIFICATE
	UTE_FAILED_TO_GET_CERTIFICATE_CHAIN
	UTE_FAILED_TO_VERIFY_CERTIFICATE_CHAIN
	UTE_FAILED_TO_VERIFY_CERTIFICATE_TRUST
************************************************/
int CUT_SecureSocketServer::VerifyCertificate(
    PTSTR           pszServerName,
    DWORD           dwCertFlags) 
{
    HTTPSPolicyCallbackData		polHttps;
    CERT_CHAIN_POLICY_PARA		PolicyPara;
    CERT_CHAIN_POLICY_STATUS	PolicyStatus;
    CERT_CHAIN_PARA				ChainPara;
    PCCERT_CHAIN_CONTEXT		pChainContext = NULL;
	PCCERT_CONTEXT				pRemoteCertContext = NULL;
    SECURITY_STATUS				Status;
	int							nError = UTE_SUCCESS;

	// Client authentication flag not set 
	if(!m_bClientAuth && m_CertValidation == CERT_DONOT_VERIFY)
		return UTE_SUCCESS;

    // Read the client certificate.
    Status = m_SecurityFunc.QueryContextAttributes(m_phContext,
                                    SECPKG_ATTR_REMOTE_CERT_CONTEXT,
                                    (PVOID)&pRemoteCertContext);
    if(Status != SEC_E_OK)
    {
        HandleSecurityError(_T("Error querying client certificate."));
		return UTE_FAILED_TO_QUERY_CERTIFICATE;
    }

    // Build certificate chain.
    ZeroMemory(&ChainPara, sizeof(ChainPara));
    ChainPara.cbSize = sizeof(ChainPara);

    if(!CertGetCertificateChain(
                            NULL,
                            pRemoteCertContext,
                            NULL,
                            pRemoteCertContext->hCertStore,
                            &ChainPara,
                            0,
                            NULL,
                            &pChainContext))
    {
        Status = GetLastError();
		nError = UTE_FAILED_TO_GET_CERTIFICATE_CHAIN;
        HandleSecurityError(_T("Failed to get the certificate chain."));
    }
	else
	{
		// Validate certificate chain.
		ZeroMemory(&polHttps, sizeof(HTTPSPolicyCallbackData));
		polHttps.cbStruct           = sizeof(HTTPSPolicyCallbackData);
		polHttps.dwAuthType         = AUTHTYPE_CLIENT;
		polHttps.fdwChecks          = dwCertFlags;
		polHttps.pwszServerName     = NULL;

		memset(&PolicyPara, 0, sizeof(PolicyPara));
		PolicyPara.cbSize            = sizeof(PolicyPara);
		PolicyPara.pvExtraPolicyPara = &polHttps;

		memset(&PolicyStatus, 0, sizeof(PolicyStatus));
		PolicyStatus.cbSize = sizeof(PolicyStatus);

		if(!CertVerifyCertificateChainPolicy(
								CERT_CHAIN_POLICY_SSL,
								pChainContext,
								&PolicyPara,
								&PolicyStatus))
		{
			Status = GetLastError();
			nError = UTE_FAILED_TO_VERIFY_CERTIFICATE_CHAIN;
			HandleSecurityError(_T("Failed to verify certificate chain policy."));
		}
		else
		{
			nError = UTE_SUCCESS;
			if(PolicyStatus.dwError)
			{
//				if(!OnCertVerifyError(CUT_Certificate(pRemoteCertContext), PolicyStatus.dwError, pszServerName))
				// v4.2 changed to avert warning
				CUT_Certificate cert(pRemoteCertContext);
				if(!OnCertVerifyError(cert, PolicyStatus.dwError, pszServerName))
				{
					Status = PolicyStatus.dwError;
					nError = UTE_FAILED_TO_VERIFY_CERTIFICATE_TRUST;
					DisplayWinVerifyTrustError(Status); 
				}
			}
		}
	}

    if(pChainContext)
        CertFreeCertificateChain(pChainContext);

	if (pRemoteCertContext)
		CertFreeCertificateContext(pRemoteCertContext);
	

    return nError;
}


#endif // CUT_SECURE_SOCKET

#pragma warning ( pop )