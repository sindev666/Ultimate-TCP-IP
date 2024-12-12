// =================================================================
//  class: CUT_CertificateInstallDlg
//  File:  UTCertifInstDlg.cpp
//  
//  Purpose:
//
//	  Certificate list dialog class
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
#include "..\\Res\\SecurityRes.h"

#ifdef CUT_SECURE_SOCKET

#include "UTCertifInstDlg.h"

// ===================================================================
// CUT_CertificateInstallDlg class
// ===================================================================

/***********************************************
CUT_CertificateInstallDlg
    Constructor
Params
    none
Return
    none
************************************************/
CUT_CertificateInstallDlg::CUT_CertificateInstallDlg() :
	m_hInst((HINSTANCE)hDllHandle),
	m_hDlg(NULL),
	m_wInstallType(IDC_RADIO_FILE)
{
}

/***********************************************
~CUT_CertificateInstallDlg
    Destructor
Params
    none
Return
    none
************************************************/
CUT_CertificateInstallDlg::~CUT_CertificateInstallDlg()
{
}

/***********************************************
OpenDlg
    Displays certificate install dialog
Params
    [hWnd]	- parent window of the list
Return
	-1		- in case of error
    IDOK
	IDCANCEL
************************************************/
int CUT_CertificateInstallDlg::OpenDlg(HWND hWndParent)
{
	return (int)DialogBoxParam((HINSTANCE)hDllHandle, MAKEINTRESOURCE(IDD_CERT_INSTALL_DIALOG), hWndParent, (DLGPROC)CertInstallDlgProc, (LPARAM)this);
}

/***********************************************
OnInit
    Called when the dialog is initialized
Params
    none
Return
	none
************************************************/
void CUT_CertificateInstallDlg::OnInit()
{
	// Install from file
	SendDlgItemMessage(m_hDlg, IDC_RADIO_FILE, BM_SETCHECK, 1, 0L);
	OnInstallType(m_wInstallType);
}

/***********************************************
OnBrowse
    Browse button was clicked
Params
    none
Return
	none
************************************************/
void CUT_CertificateInstallDlg::OnBrowse()
{
	_TCHAR			szFile[MAX_PATH + 1] = {_T("")};
	OPENFILENAME	of;

	of.lStructSize       = sizeof(OPENFILENAME);     
	of.hwndOwner         = m_hDlg;     
	of.hInstance         = m_hInst;     
	of.lpstrFilter       = _T("Certificate Files (*.cer)\0*.cer\0All Files (*.*)\0*.*\0");
	of.lpstrCustomFilter = (LPTSTR) NULL;     
	of.nMaxCustFilter    = 0L;     
	of.nFilterIndex      = 1L;     
	of.lpstrFile         = szFile;     
	of.nMaxFile          = sizeof(szFile);     
	of.lpstrFileTitle    = NULL;     
	of.nMaxFileTitle     = 0;     
	of.lpstrInitialDir   = NULL;     
	of.lpstrTitle        = _T("Select Certificate to Install");     
	of.nFileOffset       = 0;     
	of.nFileExtension    = 0;     
	of.lpstrDefExt       = NULL;  
	of.lCustData         = 0;      
	of.Flags			 =	OFN_PATHMUSTEXIST | 
							OFN_FILEMUSTEXIST | OFN_HIDEREADONLY | 
							OFN_EXPLORER | OFN_LONGNAMES;

	// Show open file dialog
	if(GetOpenFileName(&of) && *of.lpstrFile != NULL)
		SetDlgItemText(m_hDlg, IDC_EDIT_FILE, of.lpstrFile);

	// Check if Install button must be enabled
	SetInstallBtnState();
}

/***********************************************
SetInstallBtnState
    Helper function which checks if the install 
	button must be enabled
Params
    none
Return
	none
************************************************/
void CUT_CertificateInstallDlg::SetInstallBtnState()
{
	BOOL	bFlag = FALSE;

	// Check if there is text entered in required fields
	if(m_wInstallType == IDC_RADIO_FILE && SendDlgItemMessage(m_hDlg, IDC_EDIT_FILE, WM_GETTEXTLENGTH , 0, 0L))
		bFlag = TRUE;
	if(m_wInstallType == IDC_RADIO_TEXT && SendDlgItemMessage(m_hDlg, IDC_EDIT_TEXT, WM_GETTEXTLENGTH , 0, 0L))
		bFlag = TRUE;

	// Enable/Disable Install button
	EnableWindow(GetDlgItem(m_hDlg, IDOK), bFlag);
}

/***********************************************
OnInstallType
    From file or text radio button clicked
Params
    wParam	- IDC_RADIO_FILE or IDC_RADIO_TEXT
Return
	none
************************************************/
void CUT_CertificateInstallDlg::OnInstallType(WORD wParam)
{
	// Disable/Enable windows
	EnableWindow(GetDlgItem(m_hDlg, IDC_EDIT_FILE), (wParam == IDC_RADIO_FILE) ? TRUE : FALSE);
	EnableWindow(GetDlgItem(m_hDlg, IDC_BUTTON_BROWSE), (wParam == IDC_RADIO_FILE) ? TRUE : FALSE);
	EnableWindow(GetDlgItem(m_hDlg, IDC_EDIT_TEXT), (wParam == IDC_RADIO_FILE) ? FALSE : TRUE);
	m_wInstallType = wParam;

	// Check if Install button must be enabled
	SetInstallBtnState();
}

/***********************************************
OnClose
    Called when dialog is closed
Params
	none
Return
	none
************************************************/
void CUT_CertificateInstallDlg::OnClose(int nCommandID)
{
	// Install certificate
	if(nCommandID == IDOK)
	{
		CUT_CertificateManager	man;
		_TCHAR	*lpszData;
		int		nEditID = (m_wInstallType == IDC_RADIO_FILE) ? IDC_EDIT_FILE : IDC_EDIT_TEXT;

		// Get certificate data
		int nDataSize = (int)SendDlgItemMessage(m_hDlg, nEditID, WM_GETTEXTLENGTH, 0, 0L) + 1;
		lpszData = new _TCHAR[nDataSize + 1];
		SendDlgItemMessage(m_hDlg, nEditID, WM_GETTEXT, nDataSize, (LPARAM)lpszData);

		// Install certificate
		if(UTE_SUCCESS == man.CertificateInstall(lpszData, (m_wInstallType == IDC_RADIO_FILE) ? TRUE : FALSE))
			MessageBox(m_hDlg, _T("Certificate was successfully installed."), _T("Certificate Installation"), MB_OK);
		else
			MessageBox(m_hDlg, _T("Failed to install the certificate."), _T("Certificate Installation"), MB_OK | MB_ICONERROR);

		// Free memory
		delete [] lpszData;
	}

	// Close dialog
	EndDialog(m_hDlg, nCommandID);
}

/***********************************************
CertListDlgProc
    Certificate list dialog function
************************************************/
BOOL CALLBACK CUT_CertificateInstallDlg::CertInstallDlgProc(HWND hwndDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	CUT_CertificateInstallDlg	*pCertInstallDlg = NULL;

	// *****************************************************
	// ** Get pointer to the CUT_CertificateListDlg class
	// *****************************************************
	if(message == WM_INITDIALOG)
	{
		// Save parameter as window long
		pCertInstallDlg = (CUT_CertificateInstallDlg *) lParam;
		SetWindowLong(hwndDlg, GWL_USERDATA, (LONG)lParam);
		pCertInstallDlg->m_hDlg = hwndDlg;
	}
	else
		pCertInstallDlg = (CUT_CertificateInstallDlg *) (ULONG_PTR)GetWindowLong(hwndDlg, GWL_USERDATA);

	// Don't do anything if the pointer to the CUT_CertificateListDlg class is not set
	if(pCertInstallDlg == NULL)
		return 0;


	// *****************************************************
	// ** Main window messages switch
	// *****************************************************
	switch(message) 
	{
		case WM_INITDIALOG:
			pCertInstallDlg->OnInit();
			return 1;

		case WM_COMMAND:
		
			if(wParam == IDCANCEL || wParam == IDOK)
				pCertInstallDlg->OnClose((int)wParam);

			else if(wParam == IDC_BUTTON_BROWSE)
				pCertInstallDlg->OnBrowse();

			else if(wParam == IDC_RADIO_FILE || wParam == IDC_RADIO_TEXT)
				pCertInstallDlg->OnInstallType((WORD)wParam);

			else if(HIWORD(wParam) == EN_CHANGE)
				pCertInstallDlg->SetInstallBtnState();

			break;

		case WM_CLOSE:
			pCertInstallDlg->OnClose(IDCANCEL);
			break;
	}

	return 0;
}

#endif	// #ifdef CUT_SECURE_SOCKET