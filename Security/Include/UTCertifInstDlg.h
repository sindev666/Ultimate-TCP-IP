// =================================================================
//  class: CUT_CertificateInstallDlg
//  File:  UTCertifInstDlg.h
//  
//  Purpose:
//
//	  Certificate installation dialog class
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

#ifndef INCLUDECUT_CERTIFINSTAL_DIALOG
#define INCLUDECUT_CERTIFINSTAL_DIALOG

#ifdef CUT_SECURE_SOCKET

#include "UTCertifMan.h"
#include "COMMDLG.H"

extern HANDLE hDllHandle;

// ===================================================================
// CUT_CertificateInstallDlg class
// ===================================================================

class UTSECURELAYER_API CUT_CertificateInstallDlg
{
public:
	// Constructors/Destructor
	CUT_CertificateInstallDlg();
	virtual ~CUT_CertificateInstallDlg();

	// Displays certificate install dialog
	virtual int OpenDlg(HWND hWndParent = NULL);


// Protected functions
protected:

	// Window message functions

	virtual void OnInit();

	virtual void OnClose(int nCommandID);

	virtual void OnBrowse();

	virtual void OnInstallType(WORD wParam);

	virtual void SetInstallBtnState();

	// Window function
	static BOOL CALLBACK CertInstallDlgProc(HWND hwndDlg, UINT message, WPARAM wParam, LPARAM lParam);	

// Protected data members
protected:

	HINSTANCE	m_hInst;				// Module instance
	HWND		m_hDlg;					// Dialog handle
	WORD		m_wInstallType;			// Type of installation
};

#endif	// #ifdef CUT_SECURE_SOCKET
#endif	// #ifndef INCLUDECUT_CERTIFINSTAL_DIALOG