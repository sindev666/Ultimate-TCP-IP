// =================================================================
//  class: CUT_CertificateListDlg
//  File:  UTCertifListDlg.h
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

#ifndef INCLUDECUT_CERTIFLISTDIALOG
#define INCLUDECUT_CERTIFLISTDIALOG

// Suppress warnings for non-safe str fns. Transitional, for VC6 support.
#pragma warning (push)
#pragma warning (disable : 4996)

#ifdef CUT_SECURE_SOCKET

#include "CommCtrl.h"
#include "UTCertifMan.h"

#pragma comment(lib, "comctl32.lib")

extern HANDLE hDllHandle;

typedef UTSECURELAYER_API enum enumStoreLocation {
	STORE_LOCATION_CURRENT_USER					= 1,
	STORE_LOCATION_LOCAL_MACHINE				= 2,
	STORE_LOCATION_CURRENT_SERVICE				= 4,
	STORE_LOCATION_SERVICES						= 8,
	STORE_LOCATION_USERS						= 16,
	STORE_LOCATION_CURRENT_USER_GROUP_POLICY	= 32,
	STORE_LOCATION_LOCAL_MACHINE_GROUP_POLICY	= 64,

	STORE_LOCATION_ALL = 	STORE_LOCATION_CURRENT_USER |
							STORE_LOCATION_LOCAL_MACHINE |
							STORE_LOCATION_CURRENT_SERVICE |
							STORE_LOCATION_SERVICES |
							STORE_LOCATION_USERS |
							STORE_LOCATION_CURRENT_USER_GROUP_POLICY |
							STORE_LOCATION_LOCAL_MACHINE_GROUP_POLICY

} enumStoreLocation;

// ===================================================================
// CUT_CertificateListDlg class
// ===================================================================

class UTSECURELAYER_API CUT_CertificateListDlg
{
public:
	// Constructors/Destructor
	CUT_CertificateListDlg();
	virtual ~CUT_CertificateListDlg();

	// Displays certificate list dialog
	virtual int OpenDlg(HWND hWndParent = NULL);

// Public functions
public:

	// Set main window title 
	void SetTitle(const _TCHAR *lpszNewTitle)
		{ _tcsncpy(m_szDlgTitle, lpszNewTitle, sizeof(m_szDlgTitle)/sizeof(_TCHAR)); }

	// Set the flag to show the store tree window
	void SetShowStoreList(BOOL bFlag = TRUE)
		{ m_bShowStoreList = bFlag; }

	// Set store location flags (can OR several of enumStoreLocation)
	void SetStoreLocations(DWORD dwLocations)
		{ m_dwStoreLocations = dwLocations; }

	// Set list of store names to show. Default "MY,ROOT,TRUST,CA".
	// If set to "" all sotes are shown. Store is shown only if it exsits.
	void SetStoreNames(const _TCHAR *lpszStoreNames)
		{ _tcsncpy(m_szStoreNames, lpszStoreNames, sizeof(m_szStoreNames)/sizeof(_TCHAR)); }

	// Set the flag to view certificates when user double clicks in the certificate list
	void SetViewCertOnDblClk(BOOL bFlag = TRUE)
		{ m_bViewCertOnDblClk = bFlag; }

	// Set list of store names where you can delete sertificates. Default "MY".
	// Empty string ("") means all. Dash ("-") means none.
	void SetDeleteStoreNames(const _TCHAR *lpszDeleteStoreNames)
		{ 
			// Copy string
			_tcsncpy(m_szDeleteStoreNames, lpszDeleteStoreNames, sizeof(m_szDeleteStoreNames)/sizeof(_TCHAR)); 
	
			// Convert to upper case
			_tcsupr(m_szDeleteStoreNames);

			// String must end with the ','
			if(*m_szDeleteStoreNames != NULL && *(m_szDeleteStoreNames+ _tcslen(m_szDeleteStoreNames) - 1) != _T(','))
				_tcscat(m_szDeleteStoreNames, _T(","));
		}

	// Set list of store names where you can request\install sertificates. Default "MY".
	// Empty string ("") means all. Dash ("-") means none.
	void SetReqInstallStoreNames(const _TCHAR *lpszReqInstallStoreNames)
		{ 
			// Copy string
			_tcsncpy(m_szReqInstallStoreNames, lpszReqInstallStoreNames, sizeof(m_szReqInstallStoreNames)/sizeof(_TCHAR)); 
	
			// Convert to upper case
			_tcsupr(m_szReqInstallStoreNames);

			// String must end with the ','
			if(*m_szReqInstallStoreNames != NULL && *(m_szReqInstallStoreNames + _tcslen(m_szReqInstallStoreNames) - 1) != _T(','))
				_tcscat(m_szReqInstallStoreNames, _T(","));
		}

	// Set certificate usage filter. Default = 0 (None)
	void SetCertUsageFilter(BYTE usage)
		{ m_bCertUsage = usage; }

	// Returns the selected certificate class. 
	// Check the result of GetContext() function 
	// for NULL to make sure that certificate was selected
	CUT_Certificate *GetSelectedCertificate()
		{ return &m_SelectedCert; }

	// Returns the selected store class. 
	CUT_CertificateStore *GetSelectedStore()
		{ return &m_CertStore; }

// Protected functions
protected:

	// Window message functions

	virtual void OnSize(int nWidth, int nHeight);

	virtual void OnInit();

	virtual void OnMouseMove(int fwKeys, int xPos, int yPos);

	virtual void OnLButtonDown(int fwKeys, int xPos, int yPos);

	virtual void OnLButtonUp(int fwKeys, int xPos, int yPos);

	virtual void OnTreeSelChange(LPNMTREEVIEW pnmtv);

	virtual void OnColumnClick(LPNMLISTVIEW pnmv);

	virtual void OnRightClick(LPNMLISTVIEW pnmv);

	virtual void OnDblClick(LPNMLISTVIEW pnmv);

	virtual void OnClose(int nCommandID);


	// Helper functions

	static BOOL CALLBACK CertListDlgProc(HWND hwndDlg, UINT message, WPARAM wParam, LPARAM lParam);	

	static int CALLBACK CompareFunc(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort);

	virtual BOOL IsCursorInSplitter();

	virtual void StoreListRefresh();

	virtual void CertListRefresh(TVITEM newItem);

	virtual HTREEITEM AddItemToTree(LPTSTR lpszItem, int nLevel, LPARAM lParam = 0);

	virtual BOOL InitImageLists();

	virtual BOOL InitListColumns();

	virtual BOOL ViewCertificate(BOOL bFromMenu = FALSE);

	virtual const _TCHAR *GetStoreParams(enumStoreLocation Location, DWORD &dwFlag);

	virtual const _TCHAR *GetStoreExtName(const _TCHAR *szName);

// Protected data members
protected:

	HINSTANCE	m_hInst;				// Module instance
	HWND		m_hDlg;					// Dialog handle
	HWND		m_hCertList;			// Certificate list window
	HWND		m_hStoresList;			// Stores list window
	DWORD		m_dwStoreListWidth;		// Min width of the store list in pixels
	BOOL		m_bResizing;			// If TRUE we are using the splitter
	int			m_nResizeXPos;			// Original position of resizing
	int			m_nResizeOrigWidth;		// Original list width before resizing
	CUT_CertificateStore	m_CertStore;// Current certificate store 
	DWORD		m_nLastColumnSorted;	// Index of the last sorted column
	int			m_nSortingOrder;		// Sorting order 1 or 0
	HIMAGELIST	m_StoresImageList;		// Handle to the stores image list 
	HIMAGELIST	m_CertImageList;		// Handle to the cert image list 
	HICON		m_hSmallIcon;			// Small dialog icon
	HICON		m_hLargeIcon;			// Large dialog icon
	
	_TCHAR		m_szDlgTitle[200];		// Dialog title
	BOOL		m_bShowStoreList;		// If TRUE store list is shown
	DWORD		m_dwStoreLocations;		// Store location flags (can OR several of them)
	BYTE		m_bCertUsage;			// Certificate usage filter
	_TCHAR		m_szStoreNames[200];	// Stores to show
	_TCHAR		m_szDeleteStoreNames[200];		// Certificate deletion is enabled only in this stores
	_TCHAR		m_szReqInstallStoreNames[200];	// Certificate request/installation is enabled only in this stores
	BOOL		m_bViewCertOnDblClk;	// View certificate when user double click in the list, otherwise select it and close the dialog
	CUT_Certificate m_SelectedCert;		// Selected certificate
};

#endif	// #ifdef CUT_SECURE_SOCKET

#pragma warning (pop)
#endif	// #ifndef INCLUDECUT_CERTIFLISTDIALOG