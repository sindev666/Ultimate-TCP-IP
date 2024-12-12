// =================================================================
//  class: CUT_CertificateListDlg
//  File:  UTCertifListDlg.cpp
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

// Suppress warnings for non-safe str fns. Transitional, for VC6 support.
#pragma warning (push)
#pragma warning (disable : 4996)


#ifdef CUT_SECURE_SOCKET

#include "UTCertifListDlg.h"
#include "UT_CertWizard.h"
#include "UTCertifInstDlg.h"
#include "UTFile.h"
#include "shellapi.h"

#define LIST_SPACER		3
#define BORDER_SPACER	5
#define BITMAP_CX		16
#define BITMAP_CY		15

#define	CMD_REFRESH		WM_USER + 101
#define	CMD_VIEW		WM_USER + 102
#define	CMD_DELETE		WM_USER + 103
#define	CMD_REQUEST		WM_USER + 104
#define	CMD_INSTALL		WM_USER + 105

// ===================================================================
// CUT_CertificateListDlg class
// ===================================================================

/***********************************************
CUT_CertificateListDlg
    Constructor
Params
    none
Return
    none
************************************************/
CUT_CertificateListDlg::CUT_CertificateListDlg() :
	m_dwStoreLocations(STORE_LOCATION_CURRENT_USER | STORE_LOCATION_LOCAL_MACHINE),
	m_hInst((HINSTANCE)hDllHandle),
	m_hDlg(NULL),
	m_dwStoreListWidth(0),
	m_bShowStoreList(TRUE),
	m_bResizing(FALSE),
	m_nResizeXPos(0),
	m_nResizeOrigWidth(0),
	m_nSortingOrder(1),
	// v4.2 - changed - was using -1
	m_nLastColumnSorted(0xFFFFFFFF),
	m_StoresImageList(NULL),
	m_CertImageList(NULL),
	m_bViewCertOnDblClk(TRUE),
	m_hSmallIcon(NULL),
	m_hLargeIcon(NULL),
	m_bCertUsage(0)
{
	// Initialize
	_tcscpy(m_szDlgTitle, _T("Certificate list"));
	_tcscpy(m_szStoreNames, _T("MY,ROOT,TRUST,CA,"));
	_tcscpy(m_szReqInstallStoreNames, _T("MY,"));
	_tcscpy(m_szDeleteStoreNames, _T("MY,"));
}

/***********************************************
~CUT_CertificateListDlg
    Destructor
Params
    none
Return
    none
************************************************/
CUT_CertificateListDlg::~CUT_CertificateListDlg()
{
	// Delete image lists
	ImageList_Destroy(m_CertImageList);
	ImageList_Destroy(m_StoresImageList);

	// Destroy dialog icons
	if(m_hSmallIcon)
		DestroyIcon(m_hSmallIcon);
	if(m_hLargeIcon)
		DestroyIcon(m_hLargeIcon);
}

/***********************************************
OpenDlg
    Displays certificate list dialog
Params
    [hWnd]	- parent window of the list
Return
	-1		- in case of error
    IDOK
	IDCANCEL
************************************************/
int CUT_CertificateListDlg::OpenDlg(HWND hWndParent)
{
	return (int)DialogBoxParam((HINSTANCE)hDllHandle, MAKEINTRESOURCE(IDD_CERT_LIST_DIALOG), hWndParent, (DLGPROC)CertListDlgProc, (LPARAM)this);
}

/***********************************************
OnSize
    Called when the dialog size is changed
Params
    nWidth	- new width
	nHeight	- new Height
Return
	none
************************************************/
void CUT_CertificateListDlg::OnSize(int nWidth, int nHeight)
{
	// *****************************************************
	// ** Adjust position of the stores list
	// *****************************************************
	RECT	rectNewStorePos = {0,0,0,0};

	// Initialize window rect in dialog units
	rectNewStorePos.left = BORDER_SPACER;
	rectNewStorePos.top = BORDER_SPACER;

	// Convert from dialog units
	MapDialogRect(m_hDlg, &rectNewStorePos);

	// Get rect bottom and right position
	rectNewStorePos.bottom = nHeight - rectNewStorePos.top;
	rectNewStorePos.right = rectNewStorePos.left + m_dwStoreListWidth;

	// Move stores list
	int nListWidth = rectNewStorePos.right - rectNewStorePos.left;
	MoveWindow(	m_hStoresList, 
				rectNewStorePos.left, 
				rectNewStorePos.top, 
				(m_bShowStoreList && nListWidth > 4) ? nListWidth : 0,
				(m_bShowStoreList) ? rectNewStorePos.bottom - rectNewStorePos.top : 0, 
				TRUE);

	// *****************************************************
	// ** Adjust position of the certificates list
	// *****************************************************
	RECT	rectNewCertPos = {0,0,0,0};

	// Convert spacer from dialog units
	rectNewCertPos.left = LIST_SPACER;
	MapDialogRect(m_hDlg, &rectNewCertPos);
	
	// Initialize window rect 
	rectNewCertPos.left = (m_bShowStoreList) ? rectNewStorePos.right + rectNewCertPos.left : rectNewCertPos.left;
	rectNewCertPos.top = rectNewStorePos.top;
	rectNewCertPos.right = nWidth - rectNewStorePos.left;
	rectNewCertPos.bottom = rectNewStorePos.bottom;

	// Move certificate list
	nListWidth = rectNewCertPos.right - rectNewCertPos.left;
	MoveWindow(	m_hCertList, 
				rectNewCertPos.left, 
				rectNewCertPos.top, 
				(nListWidth > 4) ? nListWidth : 0, 
				rectNewCertPos.bottom - rectNewCertPos.top, 
				TRUE);

	// *****************************************************
	// ** Adjust position of the splitter
	// *****************************************************
	RECT	rectNewSplitPos;

	// Initialize window rect 
	rectNewSplitPos.left = rectNewStorePos.right;
	rectNewSplitPos.top = rectNewStorePos.top;
	rectNewSplitPos.right = rectNewCertPos.left;
	rectNewSplitPos.bottom = rectNewStorePos.bottom;

	// Move stores list
	MoveWindow(	GetDlgItem(m_hDlg, IDC_STATIC_SPLIT), 
				rectNewSplitPos.left, 
				rectNewSplitPos.top, 
				rectNewSplitPos.right - rectNewSplitPos.left, 
				rectNewSplitPos.bottom - rectNewSplitPos.top, 
				TRUE);

}

/***********************************************
IsCursorInSplitter
    Checks if we support splitter an cursor is
	located in splitter area
Params
    none
Return
	TRUE if yes
************************************************/
BOOL CUT_CertificateListDlg::IsCursorInSplitter()
{
	POINT	pt;
	RECT	rect;

	// We don't have splitter
	if(!m_bShowStoreList)
		return FALSE;

	// Get cursor position
	GetCursorPos(&pt);

	// Get splitter window position
	GetWindowRect(GetDlgItem(m_hDlg, IDC_STATIC_SPLIT), &rect);

	// Check if cursor is in the splitter
	return PtInRect(&rect, pt);
}

/***********************************************
OnInit
    Called when the dialog is initialized
Params
    none
Return
	none
************************************************/
void CUT_CertificateListDlg::OnInit()
{
	// Set dialog window text
	SetWindowText(m_hDlg, m_szDlgTitle);

	// Set store list size
	RECT	rect = {0,0,0,0};
	rect.left = 140;
	MapDialogRect(m_hDlg, &rect);
	m_dwStoreListWidth = rect.left;

	// Adjust windows size
	GetClientRect(m_hDlg, &rect);
	OnSize(rect.right, rect.bottom);

	// Set tree control images
	InitImageLists();

	// Set list columns
	InitListColumns();

	// Set dialog window icons
	m_hSmallIcon = LoadIcon(m_hInst, MAKEINTRESOURCE(IDI_ICON_CERT_LIST_SMALL));
	m_hLargeIcon = LoadIcon(m_hInst, MAKEINTRESOURCE(IDI_ICON_CERT_LIST_LARGE));
	SendMessage(m_hDlg, WM_SETICON, ICON_SMALL, (LPARAM)m_hSmallIcon);
	SendMessage(m_hDlg, WM_SETICON, ICON_BIG, (LPARAM)m_hLargeIcon);

	// Fill the list of certificate stores
	StoreListRefresh();
}

/***********************************************
StoreListRefresh
    Fill/Refresh the store list
Params
    none
Return
	none
************************************************/
void CUT_CertificateListDlg::StoreListRefresh()
{
	HTREEITEM		hFirstItem = NULL;
	CUT_TStringList	pListStores;
	DWORD			dwFlag = 0;

	// Delete all items first
	TreeView_DeleteAllItems(m_hStoresList);

	// Convert available store name string to upper case
	_tcsupr(m_szStoreNames);

	// String must end with the ','
	if(*m_szStoreNames != NULL && *(m_szStoreNames + _tcslen(m_szStoreNames) - 1) != _T(','))
		_tcscat(m_szStoreNames, _T(","));

	// Loop through all store locations
	for(int i = STORE_LOCATION_CURRENT_USER; i <= STORE_LOCATION_LOCAL_MACHINE_GROUP_POLICY; i *= 2)
	{
		// Should we display this one ?
		if(m_dwStoreLocations & i)
		{
			// Add location item to the tree
			AddItemToTree((_TCHAR *)GetStoreParams((enumStoreLocation)i, dwFlag), 1);

			// Get the list of stores in the location
			CUT_CertificateManager::GetSystemStoreList(pListStores, dwFlag);

			// Add store names to the tree control
			for(int j = 0; j < pListStores.GetCount(); j++)
			{
				// Convert store name string to upper case
				_TCHAR	szName[100];
				_tcscpy(szName, pListStores.GetString(j));
				_tcsupr(szName);
				_tcscat(szName, _T(","));

				// Check what store names we should show
				if(*m_szStoreNames == NULL || _tcsstr(m_szStoreNames, szName))
				{
					HTREEITEM hItem = AddItemToTree((_TCHAR *)GetStoreExtName(pListStores.GetString(j)), 2, dwFlag);
					if(hFirstItem == NULL)
						hFirstItem = hItem;
				}
			}
		}
	}

	// Select first store in the list 
	TreeView_SelectItem(m_hStoresList, hFirstItem);
}

/***********************************************
CertListRefresh
    Fill/Refresh the certificates list
Params
    TVITEM	- new item structure
Return
	none
************************************************/
void CUT_CertificateListDlg::CertListRefresh(TVITEM newItem)
{
	LVITEM	lvi;
	_TCHAR	szBuffer[300];

	// Close current certificate store
	m_CertStore.Close();

	// Delete all certificate list items first
	for(int index = 0; index < ListView_GetItemCount(m_hCertList); index++)
	{
		LVITEM	lvi;
		lvi.iItem = index;
		lvi.mask = LVIF_PARAM;
		if(ListView_GetItem(m_hCertList, &lvi))
		{
			if(lvi.lParam != NULL)
				delete ((CUT_Certificate *)lvi.lParam);
		}
	}
	ListView_DeleteAllItems(m_hCertList);

    // Initialize LVITEM members that are common to all items. 
    lvi.mask = LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM | LVIF_STATE; 
    lvi.state = 0; 
    lvi.stateMask = 0; 
    lvi.iImage = 0;                     // image list index 
	lvi.iSubItem = 0;

	// Store location item selected
	if(newItem.lParam == 0)
		return;

	// Get item data
	TVITEM	tvi;
	tvi.hItem = newItem.hItem;
	tvi.mask = TVIF_TEXT;
	tvi.pszText = szBuffer;
	tvi.cchTextMax = sizeof(szBuffer);
	TreeView_GetItem(m_hStoresList, &tvi);

	// Remove extended name
	_TCHAR *lpszExtname = _tcsstr(szBuffer, _T(" - "));
	if(lpszExtname != NULL)
		*lpszExtname = NULL;

	// List all certificates in store
	m_CertStore.Open(szBuffer, (DWORD)newItem.lParam);
	m_CertStore.ListCertificates();
	for(int i = 0; i < m_CertStore.GetCertListSize(); i++)
	{
		_TCHAR	szBuffer[100];
		CUT_Certificate	*tmpCert = new CUT_Certificate();
		m_CertStore.GetCertListItem(i, *tmpCert);

		// Filter certificates by usage
		if(m_bCertUsage == 0 || tmpCert->GetKeyUsage() & m_bCertUsage)
		{
			// Add item into the list
			lvi.iItem = i;
			lvi.lParam = (LPARAM)tmpCert;
			lvi.pszText = (_TCHAR *)tmpCert->GetIssuedTo();
			lvi.cchTextMax = (int)strlen((char *)tmpCert->GetIssuedTo());
			ListView_InsertItem(m_hCertList, &lvi);
			
			// Add issuer
			ListView_SetItemText(m_hCertList, i, 1, (_TCHAR *)tmpCert->GetIssuer());

			// Add expiry date
			FILETIME	ft = tmpCert->GetValidTo();
			SYSTEMTIME	st;
			FileTimeToSystemTime(&ft, &st);
			_sntprintf(szBuffer, sizeof(szBuffer)/sizeof(_TCHAR)-1, _T("%d/%d/%d"), st.wMonth, st.wDay, st.wYear);
			ListView_SetItemText(m_hCertList, i, 2, szBuffer);

			// Add public key
			_sntprintf(szBuffer, sizeof(szBuffer)/sizeof(_TCHAR)-1, _T("%s (%d)"), tmpCert->GetKeyAlgId(), tmpCert->GetKeySize());
			ListView_SetItemText(m_hCertList, i, 3, szBuffer);
		}
	}
}

/***********************************************
GetStoreExtName
    Gets store extended name
	Replace "MY" with "Personel" ...
Params
    szName	- short name 
Return
	return store extended name
************************************************/
const _TCHAR *CUT_CertificateListDlg::GetStoreExtName(const _TCHAR *szName)
{
	const _TCHAR	*lpszResult = szName;
	static _TCHAR	*szStoreName[] = {	_T("My - Personal"),
										_T("Root - Trusted Root Certification Authorities"),
										_T("Trust - Enterprise Trust"),
										_T("CA - Intermediate Certification Authorities") };

	if(_tcsicmp(szName, _T("MY")) == 0)
		lpszResult = szStoreName[0];
	else if(_tcsicmp(szName, _T("ROOT")) == 0)
		lpszResult = szStoreName[1];
	else if(_tcsicmp(szName, _T("TRUST")) == 0)
		lpszResult = szStoreName[2];
	else if(_tcsicmp(szName, _T("CA")) == 0)
		lpszResult = szStoreName[3];

	return lpszResult;
}

/***********************************************
GetStoreParams
    Gets store location name and flag
Params
    Location	- store location type
	dwFlag		- return flag
Return
	return store location name
************************************************/
const _TCHAR *CUT_CertificateListDlg::GetStoreParams(enumStoreLocation Location, DWORD &dwFlag)
{
	_TCHAR			*lpszResult = NULL;
	static _TCHAR	*szLocationName[] = {	_T("Current User"),
										_T("Local Machine"),
										_T("Current Service"),
										_T("Services"),
										_T("Users"),
										_T("User Group Policy"),
										_T("Machine Group Policy") };
	dwFlag = 0;
	switch(Location)
	{
		case(STORE_LOCATION_CURRENT_USER):
			dwFlag = CERT_SYSTEM_STORE_CURRENT_USER;
			lpszResult = szLocationName[0];
			break;
		case(STORE_LOCATION_LOCAL_MACHINE):
			dwFlag = CERT_SYSTEM_STORE_LOCAL_MACHINE;
			lpszResult = szLocationName[1];
			break;
		case(STORE_LOCATION_CURRENT_SERVICE):
			dwFlag = CERT_SYSTEM_STORE_CURRENT_SERVICE;
			lpszResult = szLocationName[2];
			break;
		case(STORE_LOCATION_SERVICES):
			dwFlag = CERT_SYSTEM_STORE_SERVICES;
			lpszResult = szLocationName[3];
			break;
		case(STORE_LOCATION_USERS):
			dwFlag = CERT_SYSTEM_STORE_USERS;
			lpszResult = szLocationName[4];
			break;
		case(STORE_LOCATION_CURRENT_USER_GROUP_POLICY):
			dwFlag = CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY;
			lpszResult = szLocationName[5];
			break;
		case(STORE_LOCATION_LOCAL_MACHINE_GROUP_POLICY):
			dwFlag = CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY;
			lpszResult = szLocationName[6];
			break;
	}
	
	return lpszResult;
}

/***********************************************
AddItemToTree
    Adds item to the store tree
Params
	lpszItem	- item name
	nLevel		- item level
Return
	HTREEITEM	- item added
************************************************/
HTREEITEM CUT_CertificateListDlg::AddItemToTree(LPTSTR lpszItem, int nLevel, LPARAM lParam)
{ 
    TVITEM tvi; 
    TVINSERTSTRUCT tvins; 
    static HTREEITEM hPrev = (HTREEITEM) TVI_FIRST; 
    static HTREEITEM hPrevRootItem = NULL; 
    static HTREEITEM hPrevLev2Item = NULL; 
 
    tvi.mask = TVIF_TEXT | TVIF_IMAGE | TVIF_SELECTEDIMAGE | TVIF_PARAM; 
 
    // Set the text of the item. 
    tvi.pszText = lpszItem; 
    tvi.cchTextMax = (int)_tcslen(lpszItem); 
 
    // Assume the item is not a parent item, so give it a document image. 
    tvi.iImage = nLevel - 1;
    tvi.iSelectedImage = (nLevel == 1) ? nLevel + 1 : nLevel - 1;
 
    // Save the parameter
    tvi.lParam = lParam; 
 
    tvins.item = tvi; 
    tvins.hInsertAfter = hPrev; 
 
    // Set the parent item based on the specified level. 
    if (nLevel == 1) 
        tvins.hParent = TVI_ROOT; 
    else if (nLevel == 2) 
        tvins.hParent = hPrevRootItem; 
    else 
        tvins.hParent = hPrevLev2Item; 

    // Add the item to the tree view control. 
    hPrev = (HTREEITEM) SendMessage(m_hStoresList, TVM_INSERTITEM, 0, (LPARAM) (LPTVINSERTSTRUCT) &tvins); 
 
    // Save the handle to the item. 
    if (nLevel == 1) 
        hPrevRootItem = hPrev; 
    else if (nLevel == 2) 
        hPrevLev2Item = hPrev; 
 
    return hPrev; 
} 
/***********************************************
InitListColumns
    Initialize certificates	list columns
Params
	none
Return
	TRUE if success
************************************************/
BOOL CUT_CertificateListDlg::InitListColumns() 
{
	LVCOLUMN	lvc; 
    int			iCol; 
	int			nSize[4];
	_TCHAR		*szNames[] = {	_T("Issued To"),
								_T("Issued By"),
								_T("Expiry Date"),
								_T("Public Key"});
 
	// Initialize columns size
	RECT	rect;
	int		nUnit;
	GetClientRect(m_hCertList, &rect);
	nUnit = (rect.right - rect.left) / 10;
	nSize[0] = 3 * nUnit;
	nSize[1] = 3 * nUnit;
	nSize[2] = 2 * nUnit;
	nSize[3] = 2 * nUnit;

    // Initialize the LVCOLUMN structure. 
    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM; 
    lvc.fmt = LVCFMT_LEFT; 
    lvc.pszText = _T("Hi there!"); 
 
    // Add the columns. 
    for (iCol = 0; iCol < 4; iCol++) 
	{ 
        lvc.iSubItem = iCol; 
		lvc.cx = nSize[iCol]; 
		lvc.pszText = szNames[iCol]; 
        if (ListView_InsertColumn(m_hCertList, iCol, &lvc) == -1) 
            return FALSE; 
    } 

	// Set extended list style
	ListView_SetExtendedListViewStyle(m_hCertList, LVS_EX_FULLROWSELECT);
	
	return TRUE;
}
 
/***********************************************
InitImageLists
    Initialize store tree control and certificates
	list image lists
Params
	none
Return
	TRUE if success
************************************************/
BOOL CUT_CertificateListDlg::InitImageLists() 
{
    HBITMAP		hbmp;	// handle to bitmap 
	HBITMAP		hmask;	// handle to mask bitmap 

	// *****************************************************
	// ** Storage tree
	// *****************************************************

    // Create the image list. 
    if ((m_StoresImageList = ImageList_Create(BITMAP_CX, BITMAP_CY, ILC_MASK, 2, 0)) == NULL) 
        return FALSE; 

    // Add bitmaps to the image list
    hbmp = LoadBitmap(m_hInst, MAKEINTRESOURCE(IDB_BITMAP_STORE_LOCATION)); 
	hmask = LoadBitmap(m_hInst, MAKEINTRESOURCE(IDB_BITMAP_STORE_LOCATION_MASK)); 
    ImageList_Add(m_StoresImageList, hbmp, hmask); 
    DeleteObject(hbmp); 
	DeleteObject(hmask); 

    hbmp = LoadBitmap(m_hInst, MAKEINTRESOURCE(IDB_BITMAP_STORE)); 
	hmask = LoadBitmap(m_hInst, MAKEINTRESOURCE(IDB_BITMAP_STORE_MASK)); 
    ImageList_Add(m_StoresImageList, hbmp, hmask); 
    DeleteObject(hbmp); 
	DeleteObject(hmask); 

    hbmp = LoadBitmap(m_hInst, MAKEINTRESOURCE(IDB_BITMAP_STORE_LOCATION_SEL)); 
	hmask = LoadBitmap(m_hInst, MAKEINTRESOURCE(IDB_BITMAP_STORE_LOCATION_SEL_MASK)); 
    ImageList_Add(m_StoresImageList, hbmp, hmask); 
    DeleteObject(hbmp); 
	DeleteObject(hmask); 

    // Associate the image list with the tree view control. 
    TreeView_SetImageList(m_hStoresList, m_StoresImageList, TVSIL_NORMAL); 

	// *****************************************************
	// ** Certificates list
	// *****************************************************

    // Create the image list. 
    if ((m_CertImageList = ImageList_Create(BITMAP_CX, BITMAP_CY, ILC_MASK, 1, 0)) == NULL) 
        return FALSE; 

    // Add bitmap to the image list
    hbmp = LoadBitmap(m_hInst, MAKEINTRESOURCE(IDB_BITMAP_CERTIFICATE)); 
	hmask = LoadBitmap(m_hInst, MAKEINTRESOURCE(IDB_BITMAP_CERTIFICATE_MASK)); 
    ImageList_Add(m_CertImageList, hbmp, hmask); 
    DeleteObject(hbmp); 
	DeleteObject(hmask); 

    // Associate the image list with the tree view control. 
    ListView_SetImageList(m_hCertList, m_CertImageList, LVSIL_SMALL); 

	return TRUE; 
} 

/***********************************************
OnMouseMove
    Called on WM_MOUSEMOVE
Params
	fwKeys	- key flags 
    xPos	- horizontal position of cursor 
	yPos	- vertical position of cursor 
Return
	none
************************************************/
void CUT_CertificateListDlg::OnMouseMove(int /* fwKeys */, int xPos, int /* yPos */)
{
	// If store list is shown change the shape of the cursor in splitter area
	if(IsCursorInSplitter())
		SetCursor(LoadCursor(NULL, IDC_SIZEWE));
	else
		SetCursor(LoadCursor(NULL, IDC_ARROW));

	// Change splitter position and readjust windows
	if(m_bResizing)
	{
		// Get dialog client window
		RECT	rect, rect2 = {0,0,0,0};
		GetClientRect(m_hDlg, &rect);

		// Check if we are in the boundary of resizing area
		rect2.left = BORDER_SPACER;
		MapDialogRect(m_hDlg, &rect2);
		rect.left += rect2.left;
		rect.right -= rect2.left;
		if(xPos >= rect.left && xPos <= rect.right)
		{
			// Set new width of the stores list
			m_dwStoreListWidth = m_nResizeOrigWidth - (m_nResizeXPos - xPos);

			// Readjust windows
			GetClientRect(m_hDlg, &rect);
			OnSize(rect.right, rect.bottom);
		}
	}	

}

/***********************************************
OnLButtonDown
    Called on WM_LBUTTONDOWN
Params
	fwKeys	- key flags 
    xPos	- horizontal position of cursor 
	yPos	- vertical position of cursor 
Return
	none
************************************************/
void CUT_CertificateListDlg::OnLButtonDown(int /* fwKeys */, int xPos, int /* yPos */)
{
	// If button was clicked in splitter
	if(IsCursorInSplitter())
	{
		// Set splitter resizing flag
		m_bResizing = TRUE;

		// Capture mouse
		SetCapture(m_hDlg);

		// Save the horizontal position of cursor and original list width
		m_nResizeXPos = xPos;
		m_nResizeOrigWidth = m_dwStoreListWidth;
	}
}

/***********************************************
OnLButtonUp
    Called on WM_LBUTTONUP
Params
	fwKeys	- key flags 
    xPos	- horizontal position of cursor 
	yPos	- vertical position of cursor 
Return
	none
************************************************/
void CUT_CertificateListDlg::OnLButtonUp(int /* fwKeys */, int /* xPos */, int /* yPos */)
{
	// Release mouse capture 
	if(m_bResizing)
	{
		ReleaseCapture();
		m_bResizing = FALSE;
	}
}

/***********************************************
OnTreeSelChange
    Called when selection is changed in store list
Params
	pnmtv	- address of an NMTREEVIEW structure. 
Return
	none
************************************************/
void CUT_CertificateListDlg::OnTreeSelChange(LPNMTREEVIEW pnmtv)
{
	// Refresh certificates list
	CertListRefresh(pnmtv->itemNew);
}

/***********************************************
OnColumnClick
    Called when the column is clicked in the 
	certificate list
Params
	pnmv	- address of an NMLISTVIEW structure. 
Return
	none
************************************************/
void CUT_CertificateListDlg::OnColumnClick(LPNMLISTVIEW pnmv)
{
	// Change sorting order
	if(m_nLastColumnSorted == (DWORD)pnmv->iSubItem)
		m_nSortingOrder = m_nSortingOrder * (-1);
	
	// Sort items in the list
	ListView_SortItems(m_hCertList, (PFNLVCOMPARE)CompareFunc, MAKELONG(pnmv->iSubItem, m_nSortingOrder));

	// Remember last sorted column
	m_nLastColumnSorted = pnmv->iSubItem;
}

/***********************************************
OnDblClick
    Called on double click in the certificate list 
Params
	pnmv	- address of an NMLISTVIEW structure. 
Return
	none
************************************************/
void CUT_CertificateListDlg::OnDblClick(LPNMLISTVIEW pnmv)
{
	if(pnmv->hdr.hwndFrom == m_hCertList)
	{
		// View certificate and close dialog
		if(ViewCertificate() && !m_bViewCertOnDblClk)
			EndDialog(m_hDlg, IDOK);
	}
}

/***********************************************
OnRightClick
    Called when right mouse button is clicked
	in the certificate list 
Params
	pnmv	- address of an NMLISTVIEW structure. 
Return
	none
************************************************/
void CUT_CertificateListDlg::OnRightClick(LPNMLISTVIEW pnmv)
{
	if(pnmv->hdr.hwndFrom == m_hCertList)
	{
		// *****************************************************
		// ** Find selected item in the stores tree control
		// *****************************************************
		TVITEM		tviStore;
		// v4.2 added this memset to initialize - avoids warning
		memset(&tviStore, 0, sizeof(tviStore));
		tviStore.hItem = TreeView_GetSelection(m_hStoresList);
		tviStore.mask = TVIF_PARAM ;
		if(tviStore.hItem)
			TreeView_GetItem(m_hStoresList, &tviStore);

		// Don't show the menu if store name not selected
		if(tviStore.lParam == 0)
			return;

		// *****************************************************
		// ** Find selected item in the certificate list
		// *****************************************************
		LVITEM	lvi;
		lvi.lParam = NULL;
		lvi.iItem = ListView_GetSelectionMark(m_hCertList);
		if(lvi.iItem >= 0)
		{
			lvi.mask = LVIF_PARAM;
			ListView_GetItem(m_hCertList, &lvi);
		}

		// *****************************************************
		// ** Create pop-up menu
		// *****************************************************
		HMENU hMenu = CreatePopupMenu();

		// Get current store name
		_TCHAR	szStoreName[200] = {_T("")};
		if(m_CertStore.GetStoreName())
		{
			_tcsncpy(szStoreName, m_CertStore.GetStoreName(), sizeof(szStoreName)/sizeof(_TCHAR) - 2);
			_tcsupr(szStoreName);
			_tcscat(szStoreName, _T(","));
		}

		// Add Refresh menu item
		AppendMenu(hMenu, MF_STRING, CMD_REFRESH, _T("&Refresh"));
		AppendMenu(hMenu, MF_SEPARATOR, NULL, NULL);

		// Add View menu item
		AppendMenu(hMenu, ((lvi.lParam == NULL) ? MF_GRAYED : NULL) | MF_STRING, CMD_VIEW, _T("&View"));

		// Add Delete menu item
		if(	*m_szDeleteStoreNames != '-' &&
			(*m_szDeleteStoreNames == NULL || _tcsstr(m_szDeleteStoreNames, szStoreName)))
		{
			AppendMenu(hMenu, ((lvi.lParam == NULL) ? MF_GRAYED : NULL) | MF_STRING, CMD_DELETE, _T("&Delete"));
		}

		// Add Request/Install menu item
		if(	*m_szReqInstallStoreNames != '-' &&
			(*m_szReqInstallStoreNames == NULL || _tcsstr(m_szReqInstallStoreNames, szStoreName)))
		{
			AppendMenu(hMenu, MF_SEPARATOR, NULL, NULL);
			AppendMenu(hMenu, MF_STRING, CMD_REQUEST, _T("&Certificate Request"));
			AppendMenu(hMenu, MF_STRING, CMD_INSTALL, _T("&Install Certificate"));
		}


		// *****************************************************
		// ** Show menu and process commands
		// *****************************************************
		POINT	point;
		GetCursorPos(&point);
		int		nCmd = TrackPopupMenu(hMenu, TPM_NONOTIFY | TPM_RETURNCMD| TPM_LEFTALIGN | TPM_TOPALIGN, point.x, point.y, 0, m_hDlg, NULL);
		switch(nCmd)
		{
			// View certificate
			case(CMD_VIEW):
				ViewCertificate(TRUE);
				break;

			// Request new certificate
			case(CMD_REQUEST):
				if(m_CertStore.GetStoreName())
				{
					CUT_CertRequestWizard	wizard;
					wizard.DisplayWizard(m_CertStore.GetStoreLocation());
				}
				break;

			// Delete certificate from the list
			case(CMD_DELETE):
				if(MessageBox(m_hDlg, _T("Warning: This will permanantly delete the certificate. You will not be able to re-install it later.\r\n\r\nAre you sure you want to delete the certificate?"), _T("Delete Certificate"), MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) == IDYES)
				{
					// Delete certificate 
					CUT_Certificate *pCert = (CUT_Certificate *)lvi.lParam;
					if(pCert != NULL) 
					{
						// Delete item from the list
						ListView_DeleteItem(m_hCertList, lvi.iItem);

						// Delete the certificate
						m_CertStore.DeleteCertificate(pCert);

						// Delet certificate object
						delete pCert;

					}
				}
				break;

			// Install new certificate
			case(CMD_INSTALL):
				if(nCmd != CMD_DELETE && m_CertStore.GetStoreName())
				{
					CUT_CertificateInstallDlg	dlg;
					dlg.OpenDlg();
				}
				// NOTE !!! 
				// There is no break in this case.
				// After installing the certificate - refreshing

			// Refresh certificate list
			case(CMD_REFRESH):
			{
				TVITEM		tvi;
				tvi.hItem = TreeView_GetSelection(m_hStoresList);
				tvi.mask = TVIF_PARAM ;
				if(tvi.hItem)
				{
					TreeView_GetItem(m_hStoresList, &tvi);
					CertListRefresh(tvi);
				}
				break;
			}
		}

		// Destroy the menu
		DestroyMenu(hMenu);
	}
}

/***********************************************
CompareFunc
    The comparison function used in column sorting
Params
	lParam1		- first item parameter
	lParam2		- second item parameter
	lParamSort	- sort items function parameter (column number)
Return
	The comparison function must return a negative 
	value if the first item should precede the 
	second, a positive value if the first item 
	should follow the second, or zero if the two 
	items are equivalent. 
************************************************/
int CALLBACK CUT_CertificateListDlg::CompareFunc(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort)
{
	CUT_Certificate	*cert1 = (CUT_Certificate *)lParam1, *cert2 = (CUT_Certificate *)lParam2;
	_TCHAR	szBuffer1[300], szBuffer2[300];
	int		nColumn = LOWORD(lParamSort);
	int		nOrder = (HIWORD(lParamSort) == 1) ? 1 : -1;
	
	if(cert1 == NULL || cert2 == NULL)
		return 0;

	// Get comparable data depending on the column
	switch(nColumn)
	{
		// Issued To
		case(0):
			_tcscpy(szBuffer1, cert1->GetIssuedTo());
			_tcscpy(szBuffer2, cert2->GetIssuedTo());
			break;
		// Issuer
		case(1):
			_tcscpy(szBuffer1, cert1->GetIssuer());
			_tcscpy(szBuffer2, cert2->GetIssuer());
			break;
		// Valid To
		case(2):
			{
			FILETIME	ft = cert1->GetValidTo();
			SYSTEMTIME	st;
			FileTimeToSystemTime(&ft, &st);
			_sntprintf(szBuffer1, sizeof(szBuffer1)/sizeof(TCHAR)-1, _T("%d/%d/%d"), st.wMonth, st.wDay, st.wYear);
			ft = cert2->GetValidTo();
			FileTimeToSystemTime(&ft, &st);
			_sntprintf(szBuffer2, sizeof(szBuffer2)/sizeof(TCHAR)-1, _T("%d/%d/%d"), st.wMonth, st.wDay, st.wYear);
			break;
			}
		// Key type & size
		case(3):
			_sntprintf(szBuffer1, sizeof(szBuffer1)/sizeof(TCHAR)-1, _T("%s (%d)"), cert1->GetKeyAlgId(), cert1->GetKeySize());
			_sntprintf(szBuffer2, sizeof(szBuffer2)/sizeof(TCHAR)-1, _T("%s (%d)"), cert2->GetKeyAlgId(), cert2->GetKeySize());
			break;

		default:
			return 0;
	}


	// Compare items
	return (_tcscmp(szBuffer1, szBuffer2)) * nOrder;
}

/***********************************************
OnClose
    Called when dialog is closed
Params
	none
Return
	none
************************************************/
void CUT_CertificateListDlg::OnClose(int nCommandID)
{
	// Get the selected certificate
	if(nCommandID == IDOK)
	{
		// Find selected item in the certificate list
		LVITEM	lvi;
		lvi.lParam = NULL;
		lvi.iItem = ListView_GetSelectionMark(m_hCertList);
		if(lvi.iItem >= 0)
		{
			// Get item data
			lvi.mask = LVIF_PARAM;
			ListView_GetItem(m_hCertList, &lvi);
			if(lvi.lParam != NULL)
				m_SelectedCert = *(CUT_Certificate *)lvi.lParam;
		}
	}

	// Delete all certificate list items first
	for(int i = 0; i < ListView_GetItemCount(m_hCertList); i++)
	{
		LVITEM	lvi;
		lvi.iItem = i;
		lvi.mask = LVIF_PARAM;
		if(ListView_GetItem(m_hCertList, &lvi))
		{
			if(lvi.lParam != NULL)
				delete ((CUT_Certificate *)lvi.lParam);
		}
	}
	ListView_DeleteAllItems(m_hCertList);

	// Close dialog
	EndDialog(m_hDlg, nCommandID);
}

/***********************************************
ViewCertificate
    View certificate data
Params
	bFromMenu	- TRUE if called from the menu
Return
	TRUE if certificate was found
************************************************/
BOOL CUT_CertificateListDlg::ViewCertificate(BOOL bFromMenu)
{
	BOOL	bResult = FALSE;

	// Find selected item in the certificate list
	LVITEM	lvi;
	lvi.lParam = NULL;
	lvi.iItem = ListView_GetSelectionMark(m_hCertList);
	if(lvi.iItem >= 0)
	{
		// Get item data
		lvi.mask = LVIF_PARAM;
		ListView_GetItem(m_hCertList, &lvi);
		CUT_Certificate *cert = (CUT_Certificate *)lvi.lParam;
		if(cert != NULL && cert->GetContext() != NULL)
		{
			bResult = TRUE;

			// Show certificate data
			if(m_bViewCertOnDblClk || bFromMenu)
			{
				// Get temp file name
				_TCHAR	szFileName[MAX_PATH + 1];
				GetTempPath(MAX_PATH, szFileName);
				_tcscat(szFileName, _T("Temp.cer"));

				// Save certificate into the temp file
				CUT_File	file;
				if(file.Open(szFileName, GENERIC_WRITE, CREATE_ALWAYS) == 0)
				{
					if(file.Write(cert->GetContext()->pbCertEncoded, cert->GetContext()->cbCertEncoded) == cert->GetContext()->cbCertEncoded)
					{
						// Close file
						file.Close();

						// Open the certificate file for viewing
						ShellExecute(m_hDlg, _T("open"), szFileName, NULL, NULL, SW_SHOWNORMAL);
					}
				}

				// Close file
				file.Close();

			}
			// Set selected certificate
			else
			{
				m_SelectedCert = *cert;
			}
		}
	}

	return bResult;
}

/***********************************************
CertListDlgProc
    Certificate list dialog function
************************************************/
BOOL CALLBACK CUT_CertificateListDlg::CertListDlgProc(HWND hwndDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	CUT_CertificateListDlg	*pCertListDlg = NULL;

	// *****************************************************
	// ** Get pointer to the CUT_CertificateListDlg class
	// *****************************************************
	if(message == WM_INITDIALOG)
	{
		// Save parameter as window long
		pCertListDlg = (CUT_CertificateListDlg *) lParam;
		SetWindowLong(hwndDlg, GWL_USERDATA, (LONG)lParam);
		pCertListDlg->m_hDlg = hwndDlg;
		pCertListDlg->m_hCertList = GetDlgItem(hwndDlg, IDC_CERT_LIST);
		pCertListDlg->m_hStoresList = GetDlgItem(hwndDlg, IDC_STORE_TREE);
	}
	else
		pCertListDlg = (CUT_CertificateListDlg *) (ULONG_PTR)GetWindowLong(hwndDlg, GWL_USERDATA);

	// Don't do anything if the pointer to the CUT_CertificateListDlg class is not set
	if(pCertListDlg == NULL)
		return 0;


	// *****************************************************
	// ** Main window messages switch
	// *****************************************************
	switch(message) 
	{
		case WM_INITDIALOG:
			pCertListDlg->OnInit();
			return 1;
		case WM_COMMAND:
			if(wParam == IDCANCEL || wParam == IDOK)
				pCertListDlg->OnClose((int)wParam);
			break;
		case WM_CLOSE:
			pCertListDlg->OnClose(IDCANCEL);
			break;
		case WM_SIZE:
			pCertListDlg->OnSize(LOWORD(lParam), HIWORD(lParam));
			break;
		case WM_MOUSEMOVE :
			pCertListDlg->OnMouseMove((int)wParam, LOWORD(lParam), HIWORD(lParam));
			break;
		case WM_LBUTTONDOWN:
			pCertListDlg->OnLButtonDown((int)wParam, LOWORD(lParam), HIWORD(lParam));
			break;
		case WM_LBUTTONUP:
			pCertListDlg->OnLButtonUp((int)wParam, LOWORD(lParam), HIWORD(lParam));
			break;
		case WM_NOTIFY:
		{
			LPNMHDR pnmh = (LPNMHDR) lParam;
			if(pnmh != NULL)
			{
				if(pnmh->code == TVN_SELCHANGED)
					pCertListDlg->OnTreeSelChange((LPNMTREEVIEW)lParam);
				else if(pnmh->code == LVN_COLUMNCLICK)
					pCertListDlg->OnColumnClick((LPNMLISTVIEW)lParam);
				else if(pnmh->code == NM_RCLICK )
					pCertListDlg->OnRightClick((LPNMLISTVIEW)lParam);
				else if(pnmh->code == NM_DBLCLK)
					pCertListDlg->OnDblClick((LPNMLISTVIEW)lParam);
			}
			break;
		}

	}

	return 0;
}

 
#endif	// #ifdef CUT_SECURE_SOCKET

#pragma warning ( pop )