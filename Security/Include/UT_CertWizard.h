// =================================================================
//  class: CUT_CertRequestWizard
//  File:  UT_CertWizard.h
//  
//  Purpose:
//
//	  Certificate request wizard
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

#ifndef UT_CERTWIZARD
#define UT_CERTWIZARD

#ifdef CUT_SECURE_SOCKET

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <windows.h>
#include <windowsx.h>
#include <prsht.h>
#include <tchar.h>
#include <windef.h>


#include "UTCertifMan.h"

extern HANDLE hDllHandle;
#pragma comment(lib, "comctl32.lib")

class UTSECURELAYER_API CUT_CertRequestWizard  
{
public:
	// Constructor/Destructor
	CUT_CertRequestWizard();
	virtual ~CUT_CertRequestWizard();

	// Display the certificate request wizard
	virtual int DisplayWizard(DWORD dwStoreLocation =  CERT_SYSTEM_STORE_CURRENT_USER);
	
	// Return the certificate request data
	virtual LPCSTR GetCertRequest()
		{ return (LPCSTR) m_lpszRequestBuffer; }

	// Set flag to save the request into the buffer only (No saving to file)
	virtual void SetSaveToMemoryOnly(BOOL bFlag)
		{ m_bSaveToBufferOnly = bFlag; }

protected:

	_TCHAR		*m_lpszKeyContainerName;// Name of the key container
	enumPublicKeySize	m_dwKeySize;	// Certificate public key length
	_TCHAR		*m_lpszCommonName;		// Common Name 
	_TCHAR		*m_lpszOrganization;	// Organization Name
	_TCHAR		*m_lpszOrganizationUnit;// Name of the organization unit
	_TCHAR		m_lpszCountry[4];		// Two letter code for the country
	_TCHAR		*m_lpszState;			// Name of the state or province
	_TCHAR		*m_lpszCity;			// Locality 
	_TCHAR		*m_lpszGivenName;		// Given Name 
	_TCHAR		*m_lpszEMail;			// Email 
	_TCHAR		*m_lpszPhone;			// Phone Number
	_TCHAR		*m_lpszRequestBuffer;	// A buffer to hold the returned request
	_TCHAR		*m_lpszFileName;		// Name of the file to save the request data to
	BOOL		m_bOpenWithNotePad;		// Flag to open the file with notepad
	DWORD		m_dwStoreLocation;		// Store location
	HINSTANCE	m_hInstance;			// Application Instance
	int			m_nWizardResult;		// Wizard result error code
	BOOL		m_bSaveToBufferOnly;	// Do not save request to file.

protected:

	// Key name and strength dialog
	static INT CALLBACK KeyStrengthDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
	
	// Error dialog Proc
	static BOOL CALLBACK ErrorDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
	
	// Organization dialog Proc
	static INT CALLBACK OrganizationDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
	
	// Common Name Dialog
	static INT CALLBACK CommonNameDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

	// Geographic Location Dialog
	static INT CALLBACK GeographicInfoDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
	
	// Contact Information Dialog
	static INT CALLBACK ContactInfoDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
	
	// Request File Name Dialog
	static INT CALLBACK RequestFileDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

	// Preview Dialog
	static INT CALLBACK PreviewDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

	// Set the page style based on I.E.  version
	void SetPageStyle(PROPSHEETPAGE     *psp, LPTSTR szTitle, LPTSTR szSubTitle);


};

#endif // #ifdef CUT_SECURE_SOCKET

#endif // #ifndef UT_CERTWIZARD
