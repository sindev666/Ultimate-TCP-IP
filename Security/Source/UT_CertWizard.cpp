// =================================================================
//  class: CUT_CertRequestWizard
//  File:  UT_CertWizard.cpp
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

#include "stdafx.h"

#ifdef CUT_SECURE_SOCKET

#include "..\\Res\\SecurityRes.h"
#include "UT_CertWizard.h"
#include "UTCertifMan.h"

#include <commctrl.h>
#include <shlwapi.h>
#include <xenroll.h>
#include "ut_strop.h"

// Suppress warnings for non-safe str fns. Transitional, for VC6 support.
#pragma warning (push)
#pragma warning (disable : 4996)

#define PACKVERSION(major,minor) MAKELONG(minor,major)
/*****************************************************
		Since we are going to use wizard97 style 
		we need to make sure that 
		the correct version number is installed 
		this function will do just about that
PARAM:
	LPCTSTR		lpszDllName - The name of the DLL to look up the version number 
	for
RETURN:
	DWORD		- The version number concatinated as minor is  the low-order word
				and major number of the version is the  high-order word . 
*****************************************************/
DWORD GetDllVersion(LPCTSTR lpszDllName)
{

    HINSTANCE hinstDll;
    DWORD dwVersion = 0;

    hinstDll = LoadLibrary(lpszDllName);
	
    if(hinstDll)
    {
        DLLGETVERSIONPROC pDllGetVersion;

        pDllGetVersion = (DLLGETVERSIONPROC) GetProcAddress(hinstDll, "DllGetVersion");

		//Because some DLLs may not implement this function, you
		//must test for it explicitly. Depending on the particular 
		//DLL, the lack of a DllGetVersion function may
		//be a useful indicator of the version.
		//
        if(pDllGetVersion)
        {
            DLLVERSIONINFO dvi;
            HRESULT hr;

            ZeroMemory(&dvi, sizeof(dvi));
            dvi.cbSize = sizeof(dvi);

            hr = (*pDllGetVersion)(&dvi);

            if(SUCCEEDED(hr))
            {
                dwVersion = PACKVERSION(dvi.dwMajorVersion, dvi.dwMinorVersion);
            }
        }
        
        FreeLibrary(hinstDll);
    }
    return dwVersion;
}
/***********************************************
CUT_CertRequestWizard
    Constructor
Params
    none
Return
    none
************************************************/
CUT_CertRequestWizard::CUT_CertRequestWizard() :
	m_lpszKeyContainerName(NULL),
	m_lpszOrganization(NULL),
	m_lpszOrganizationUnit(NULL),
	m_lpszState(NULL),
	m_lpszCity(NULL),
	m_lpszEMail(NULL),
	m_lpszGivenName(NULL),
	m_lpszPhone(NULL),
	m_lpszCommonName(NULL),
	m_lpszFileName(NULL),
	m_lpszRequestBuffer(NULL),
	m_hInstance((HINSTANCE)hDllHandle),
	m_bSaveToBufferOnly(FALSE),
	m_nWizardResult(UTE_ERROR),
	m_bOpenWithNotePad(FALSE)
{
}

/***********************************************
~CUT_CertRequestWizard
    Destructor
Params
    none
Return
    none
************************************************/
CUT_CertRequestWizard::~CUT_CertRequestWizard()
{
	// Free allocated memory
	if(m_lpszRequestBuffer)
		LocalFree(m_lpszRequestBuffer);

	delete [] m_lpszKeyContainerName;
	delete [] m_lpszOrganization;
	delete [] m_lpszOrganizationUnit;
	delete [] m_lpszState;
	delete [] m_lpszCity;
	delete [] m_lpszEMail;
	delete [] m_lpszGivenName;
	delete [] m_lpszPhone;
	delete [] m_lpszCommonName;
	delete [] m_lpszFileName;
}




/***********************************************
DisplayWizard
	Show the first page of the certificate
	request wizard.
Params
    [dwStoreLocation] - certificate store location
Return
	UTE_SUCCESS
    UTE_ERROR
************************************************/
int CUT_CertRequestWizard::DisplayWizard(DWORD dwStoreLocation)
{
	// Set certificate store location
	m_dwStoreLocation = dwStoreLocation;

	// Initialize error code
	m_nWizardResult = UTE_ERROR;

	PROPSHEETPAGE	psp =		{0}; // Defines the property sheet pages
    HPROPSHEETPAGE  ahpsp[9] =	{0}; // Array to hold the page's HPROPSHEETPAGE handles
    PROPSHEETHEADER psh =		{0}; // Defines the property sheet
	int				nPageIndex = 0;



	// ***********************************************
	// ** Initialize page information
	// ***********************************************
    psp.dwSize =        sizeof(psp);
	
	SetPageStyle(&psp,MAKEINTRESOURCE(IDS_TITLE1) , MAKEINTRESOURCE(IDS_SUBTITLE1) );

    psp.hInstance =     m_hInstance;
    psp.lParam =        (LPARAM)this; 

	// The name and key strength page
    psp.pszTemplate =       MAKEINTRESOURCE(IDD_KEY_STRENGTH);
    psp.pfnDlgProc =        KeyStrengthDlgProc;
    ahpsp[nPageIndex++]	=	CreatePropertySheetPage(&psp);


	// Common Name Info
	SetPageStyle(&psp,MAKEINTRESOURCE(IDS_TITLE3) ,MAKEINTRESOURCE(IDS_SUBTITLE3) );

    psp.pszTemplate =       MAKEINTRESOURCE(IDD_COMMON_NAME);
    psp.pfnDlgProc =        CommonNameDlgProc;
    ahpsp[nPageIndex++]	=	CreatePropertySheetPage(&psp);

   	// Organization information
	SetPageStyle(&psp,MAKEINTRESOURCE(IDS_TITLE2) ,MAKEINTRESOURCE(IDS_SUBTITLE2) );
    psp.pszTemplate =       MAKEINTRESOURCE(IDD_ORG_DLG);
    psp.pfnDlgProc =        OrganizationDlgProc;
    ahpsp[nPageIndex++]	=	CreatePropertySheetPage(&psp);
	
	// Geographic Info
	SetPageStyle(&psp,MAKEINTRESOURCE(IDS_TITLE4) ,MAKEINTRESOURCE(IDS_SUBTITLE4) );
    psp.pszTemplate =       MAKEINTRESOURCE(IDD_GEOGRAPHIC_DLG);
    psp.pfnDlgProc =        GeographicInfoDlgProc;
    ahpsp[nPageIndex++]	=	CreatePropertySheetPage(&psp);

	// Contact Info
	SetPageStyle(&psp,MAKEINTRESOURCE(IDS_TITLE5) ,MAKEINTRESOURCE(IDS_SUBTITLE5) );

    psp.pszTemplate =       MAKEINTRESOURCE(IDD_CONTACT_DLG);
    psp.pfnDlgProc =        ContactInfoDlgProc;
    ahpsp[nPageIndex++]	=	CreatePropertySheetPage(&psp);

	// Skip the File Name property page if saving to buffer only
	if(!m_bSaveToBufferOnly)
	{
		// File name page
		SetPageStyle(&psp,MAKEINTRESOURCE(IDS_TITLE6) ,MAKEINTRESOURCE(IDS_SUBTITLE6) );
		psp.pszTemplate =       MAKEINTRESOURCE(IDD_REQUEST_FILE_DLG);
		psp.pfnDlgProc =        RequestFileDlgProc;
		ahpsp[nPageIndex++]	=	CreatePropertySheetPage(&psp);
	}

	// Preview Page
	SetPageStyle(&psp,MAKEINTRESOURCE(IDS_TITLE7) ,MAKEINTRESOURCE(IDS_SUBTITLE7) );
    psp.pszTemplate =       MAKEINTRESOURCE(IDD_PREVIEW_DLG);
    psp.pfnDlgProc =        PreviewDlgProc;
	ahpsp[nPageIndex++]	=	CreatePropertySheetPage(&psp);

	// Error Page
	SetPageStyle(&psp,MAKEINTRESOURCE(IDS_TITLE9) ,MAKEINTRESOURCE(IDS_SUBTITLE9) );
    psp.pszTemplate =       MAKEINTRESOURCE(IDD_ERROR_DLG);
    psp.pfnDlgProc =        ErrorDlgProc;
	ahpsp[nPageIndex++]	=	CreatePropertySheetPage(&psp);

    // Create the property sheet
    psh.dwSize =            sizeof(psh);
    psh.hInstance =         m_hInstance;
    psh.hwndParent =        NULL;
    psh.phpage =            ahpsp;

	if(GetDllVersion(TEXT("comctl32.dll")) >= PACKVERSION(5,80))
		{
		psh.dwFlags =           PSH_WIZARD97|PSH_WATERMARK|PSH_HEADER;
		psh.pszbmWatermark =    MAKEINTRESOURCE(IDB_BITMAP_KEY);
		psh.pszbmHeader =       MAKEINTRESOURCE(IDB_BITMAP_KEY);

	}else
	{
		psh.dwFlags =           PSH_WIZARD ;
	}

    psh.pszbmWatermark =    MAKEINTRESOURCE(IDB_BITMAP_KEY);
    psh.pszbmHeader =       MAKEINTRESOURCE(IDB_BITMAP_KEY);

	psh.nStartPage =        0;
    psh.nPages =            nPageIndex;

	// ***********************************************
	// ** Display the wizard
	// ***********************************************
	PropertySheet(&psh);
   
	return m_nWizardResult;
}

/***********************************************
KeyStrengthDlgProc
	Dialog function of the key container name
	property page
************************************************/
BOOL CALLBACK CUT_CertRequestWizard::KeyStrengthDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	// Get pointer to the CUT_CertRequestWizard class
    CUT_CertRequestWizard *ptrWizard = NULL;
	if(uMsg == WM_INITDIALOG)
	{
		ptrWizard = (CUT_CertRequestWizard *)((LPPROPSHEETPAGE)lParam)->lParam;

		// Save pointer to the CUT_CertRequestWizard class as dialog param
		SetWindowLong(hwndDlg, GWL_USERDATA, (LONG)(ULONG_PTR)ptrWizard);
	}
	else
		ptrWizard = (CUT_CertRequestWizard *)(ULONG_PTR)GetWindowLong(hwndDlg, GWL_USERDATA);
	
	// Check class pointer for NULL
	if(ptrWizard == NULL)
		return 0;


	// ***********************************************
	// ** Dialog messages switch
	// ***********************************************
    switch(uMsg)
    {
		case WM_INITDIALOG:
		{ 
			// ***********************************************
			// ** We will add the allowable keys length for the wizard
			// ***********************************************
			HWND hWndCombo = GetDlgItem(hwndDlg, IDC_COMBOKEYLENGTH);
			SendMessage (hWndCombo, CB_ADDSTRING, 0, (LPARAM)_T("512"));
			SendMessage (hWndCombo, CB_ADDSTRING, 0, (LPARAM)_T("1024"));
			SendMessage (hWndCombo, CB_ADDSTRING, 0, (LPARAM)_T("2048"));

			// ***********************************************
			// ** Create Enrollment control
			// ***********************************************
			ICEnroll	*pEnroll = NULL;
			HRESULT		hr;
			BOOL		bBaseProviderOnly = FALSE;

			// Initialize COM
			hr = CoInitialize( NULL );
			if(SUCCEEDED(hr))
			{

				// Create an instance of the Certificate Enrollment object
//				hr = CoCreateInstance( CLSID_CEnroll,
//									   NULL,
//									   CLSCTX_INPROC_SERVER,
//									   IID_ICEnroll4,
//									   (void **)&pEnroll);

				// If failed try to get the third version of the control
//				if(FAILED(hr) || pEnroll == NULL)
//				{
//					hr = CoCreateInstance( CLSID_CEnroll,
//										   NULL,
//										   CLSCTX_INPROC_SERVER,
//										   IID_ICEnroll3,
//										   (void **)&pEnroll);
//				}
				// If failed try to get the second version of the control
//				if(FAILED(hr) || pEnroll == NULL) {
					hr = CoCreateInstance( CLSID_CEnroll,
										   NULL,
										   CLSCTX_INPROC_SERVER,
										   IID_ICEnroll2,
										   (void **)&pEnroll);
//				}

				// If failed try to get the first version of the control
				if(FAILED(hr) || pEnroll == NULL)
				{
					// Create an instance of the Certificate Enrollment object.
					hr = CoCreateInstance( CLSID_CEnroll,
										   NULL,
										   CLSCTX_INPROC_SERVER,
										   IID_ICEnroll,
										   (void **)&pEnroll);
				}
				
				// ***********************************************
				// ** Check available providers
				// ***********************************************
				if(pEnroll != NULL)
				{
					BSTR	bstrProvName = NULL;
					int		nProviderIndex = 0;
					bBaseProviderOnly = TRUE;
					while(pEnroll->enumProviders(nProviderIndex, 0, &bstrProvName) == S_OK)
					{
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
				
				// Release Certificate Enrollment object
				pEnroll->Release();
				}

				// Free COM resources
				CoUninitialize();
			}

			// Select the default key length depending on the available providers
			if(bBaseProviderOnly)
			{
				// Show note message in the dialog
				SetDlgItemText(hwndDlg, IDC_STATIC_NOTE, _T("NOTE: To use the Key Length more than 512 Microsoft Enhanced or Strong Cryptographic Provider must be installed."));

				// Make the default key 512 length
				SendMessage(hWndCombo, CB_SETCURSEL, 0, 0);
			}
			else
			{
				// Make the default key 1024 length
				SendMessage(hWndCombo, CB_SETCURSEL, 1, 0);
			}

			break;
		}
        
		case WM_COMMAND:
		{
			// Edit control content changed. Check if the Next button must be enabled
			if(HIWORD(wParam) == EN_CHANGE)
			{
				if(SendDlgItemMessage(hwndDlg, IDC_CERTNAME, WM_GETTEXTLENGTH, 0, 0L) > 0)
					PropSheet_SetWizButtons(GetParent(hwndDlg), PSWIZB_NEXT);
				else
					PropSheet_SetWizButtons(GetParent(hwndDlg), 0);
			}
			break;
		}
			
		case WM_NOTIFY :
		{
			LPNMHDR lpnm = (LPNMHDR) lParam;
			switch (lpnm->code)
			{
				// Enable the Next and Back buttons
				case PSN_SETACTIVE: 
					if(SendDlgItemMessage(hwndDlg, IDC_CERTNAME, WM_GETTEXTLENGTH, 0, 0L) > 0)
						PropSheet_SetWizButtons(GetParent(hwndDlg), PSWIZB_NEXT);
					else
						PropSheet_SetWizButtons(GetParent(hwndDlg), 0);

					// Hide Prev button
					ShowWindow(GetDlgItem(GetParent(hwndDlg), 0x3023), SW_HIDE);
					break;
				case PSN_WIZNEXT:
				{
					// Get container name
					delete [] ptrWizard->m_lpszKeyContainerName;
					ptrWizard->m_lpszKeyContainerName = new _TCHAR[SendDlgItemMessage(hwndDlg, IDC_CERTNAME, WM_GETTEXTLENGTH, 0, 0L) + 1];
					GetDlgItemText(hwndDlg, IDC_CERTNAME, ptrWizard->m_lpszKeyContainerName, (int)SendDlgItemMessage(hwndDlg, IDC_CERTNAME, WM_GETTEXTLENGTH, 0, 0L) + 1);
					
					// Save the length of the key
					ptrWizard->m_dwKeySize = (enumPublicKeySize)SendDlgItemMessage(hwndDlg, IDC_COMBOKEYLENGTH, CB_GETCURSEL, 0, 0L);
					
					break;	
				}
			}
			break;
		}
    }
    return 0;
}

/***********************************************
OrganizationDlgProc
	Dialog function of the organization
	property page
************************************************/
BOOL CALLBACK CUT_CertRequestWizard::OrganizationDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	// Get pointer to the CUT_CertRequestWizard class
    CUT_CertRequestWizard *ptrWizard = NULL;
	if(uMsg == WM_INITDIALOG)
	{
		ptrWizard = (CUT_CertRequestWizard *)((LPPROPSHEETPAGE)lParam)->lParam;

		// Save pointer to the CUT_CertRequestWizard class as dialog param
		SetWindowLong(hwndDlg, GWL_USERDATA, (LONG)(ULONG_PTR)ptrWizard);
	}
	else
		ptrWizard = (CUT_CertRequestWizard *)(ULONG_PTR)GetWindowLong(hwndDlg, GWL_USERDATA);
	
	// Check class pointer for NULL
	if(ptrWizard == NULL)
		return 0;


	// ***********************************************
	// ** Dialog messages switch
	// ***********************************************
    switch (uMsg)
    {
		case WM_COMMAND:
		{
			// Edit control content changed. Check if the Next button must be enabled
			if(HIWORD(wParam) == EN_CHANGE)
			{
				// Enable Next/Back buttons
				if(	SendDlgItemMessage(hwndDlg, IDC_ORGANIZATION, WM_GETTEXTLENGTH, 0, 0L) &&
					SendDlgItemMessage(hwndDlg, IDC_ORGANIZATION_UNIT, WM_GETTEXTLENGTH, 0, 0L))
				{
					PropSheet_SetWizButtons(GetParent(hwndDlg), PSWIZB_BACK | PSWIZB_NEXT);
				}
				else
				{
					PropSheet_SetWizButtons(GetParent(hwndDlg), PSWIZB_BACK);
				}
			}

	        break;
		}

		case WM_NOTIFY :
		{
			LPNMHDR lpnm = (LPNMHDR) lParam;
			switch (lpnm->code)
			{
				// Enable the Next and Back buttons
				case PSN_SETACTIVE: 
					if(	SendDlgItemMessage(hwndDlg, IDC_ORGANIZATION, WM_GETTEXTLENGTH, 0, 0L) &&
						SendDlgItemMessage(hwndDlg, IDC_ORGANIZATION_UNIT, WM_GETTEXTLENGTH, 0, 0L))
					{
						PropSheet_SetWizButtons(GetParent(hwndDlg), PSWIZB_BACK | PSWIZB_NEXT);
					}
					else
					{
						PropSheet_SetWizButtons(GetParent(hwndDlg), PSWIZB_BACK);
					}
					break;

				case PSN_WIZNEXT:
				{	
					// Get Organization from the property page
					int nSize = (int)SendDlgItemMessage(hwndDlg, IDC_ORGANIZATION, WM_GETTEXTLENGTH, 0, 0L) + 1;
					delete [] ptrWizard->m_lpszOrganization;
					ptrWizard->m_lpszOrganization = new _TCHAR [nSize];
					GetDlgItemText(hwndDlg, IDC_ORGANIZATION, ptrWizard->m_lpszOrganization, nSize);

					// Get Organization Unit from the property page
					nSize = (int)SendDlgItemMessage(hwndDlg, IDC_ORGANIZATION_UNIT, WM_GETTEXTLENGTH, 0, 0L) + 1;
					delete [] ptrWizard->m_lpszOrganizationUnit;
					ptrWizard->m_lpszOrganizationUnit = new _TCHAR [nSize];
					GetDlgItemText(hwndDlg, IDC_ORGANIZATION_UNIT, ptrWizard->m_lpszOrganizationUnit, nSize);
					break;
				}
			}
		}
        break;
    }
    return 0;
}

/***********************************************
CommonNameDlgProc
	Dialog function of the common name
	property page
************************************************/
BOOL CALLBACK CUT_CertRequestWizard::CommonNameDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	// Get pointer to the CUT_CertRequestWizard class
    CUT_CertRequestWizard *ptrWizard = NULL;
	if(uMsg == WM_INITDIALOG)
	{
		ptrWizard = (CUT_CertRequestWizard *)((LPPROPSHEETPAGE)lParam)->lParam;

		// Save pointer to the CUT_CertRequestWizard class as dialog param
		SetWindowLong(hwndDlg, GWL_USERDATA, (LONG)(ULONG_PTR)ptrWizard);
	}
	else
		ptrWizard = (CUT_CertRequestWizard *)(ULONG_PTR)GetWindowLong(hwndDlg, GWL_USERDATA);
	
	// Check class pointer for NULL
	if(ptrWizard == NULL)
		return 0;


	// ***********************************************
	// ** Dialog messages switch
	// ***********************************************
    switch (uMsg)
    {
		case WM_COMMAND:
		{
			// Edit control content changed. Check if the Next button must be enabled
			if(HIWORD(wParam) == EN_CHANGE)
			{
				// Enable Next/Back buttons
				if(SendDlgItemMessage(hwndDlg, IDC_COMMON_NAME, WM_GETTEXTLENGTH, 0, 0L))
					PropSheet_SetWizButtons(GetParent(hwndDlg), PSWIZB_BACK | PSWIZB_NEXT);
				else
					PropSheet_SetWizButtons(GetParent(hwndDlg), PSWIZB_BACK);
			}
	        break;
		}
		case WM_NOTIFY :
		{
			LPNMHDR lpnm = (LPNMHDR) lParam;

			switch (lpnm->code)
			{
				//Enable the Next and Back buttons
				case PSN_SETACTIVE : 
					// Show Prev button
					ShowWindow(GetDlgItem(GetParent(hwndDlg), 0x3023), SW_SHOW);

					if(SendDlgItemMessage(hwndDlg, IDC_COMMON_NAME, WM_GETTEXTLENGTH, 0, 0L))
						PropSheet_SetWizButtons(GetParent(hwndDlg), PSWIZB_BACK | PSWIZB_NEXT);
					else
						PropSheet_SetWizButtons(GetParent(hwndDlg), PSWIZB_BACK);
					break;

				case PSN_WIZNEXT :
					{
					// Get Common Name from the property page
					int nSize = (int)SendDlgItemMessage(hwndDlg, IDC_COMMON_NAME, WM_GETTEXTLENGTH, 0, 0L) + 1;
					delete [] ptrWizard->m_lpszCommonName;
					ptrWizard->m_lpszCommonName = new _TCHAR [nSize];
					GetDlgItemText(hwndDlg, IDC_COMMON_NAME, ptrWizard->m_lpszCommonName, nSize);
					break;
					}
			}
		}
        break;
    }
    return 0;
}

/***********************************************
GeographicInfoDlgProc
	Dialog function of the geographic info
	property page
************************************************/
BOOL CALLBACK CUT_CertRequestWizard::GeographicInfoDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	// Get pointer to the CUT_CertRequestWizard class
    CUT_CertRequestWizard *ptrWizard = NULL;
	if(uMsg == WM_INITDIALOG)
	{
		ptrWizard = (CUT_CertRequestWizard *)((LPPROPSHEETPAGE)lParam)->lParam;

		// Save pointer to the CUT_CertRequestWizard class as dialog param
		SetWindowLong(hwndDlg, GWL_USERDATA, (LONG)(ULONG_PTR)ptrWizard);
	}
	else
		ptrWizard = (CUT_CertRequestWizard *)(ULONG_PTR)GetWindowLong(hwndDlg, GWL_USERDATA);
	
	// Check class pointer for NULL
	if(ptrWizard == NULL)
		return 0;


	// ***********************************************
	// ** Dialog messages switch
	// ***********************************************
    switch (uMsg)
    {
		case WM_INITDIALOG:
			SetDlgItemText(hwndDlg, IDC_COMBO_COUNTRY, _T("US"));
			break;

	   	case WM_COMMAND:
		{
			// Edit control content changed. Check if the Next button must be enabled
			if(HIWORD(wParam) == EN_CHANGE)
			{
				// Enable Next/Back buttons
				if(	SendDlgItemMessage(hwndDlg, IDC_STAT_PROVINCE, WM_GETTEXTLENGTH, 0, 0L) &&
					SendDlgItemMessage(hwndDlg, IDC_CITY_LOCALITY, WM_GETTEXTLENGTH, 0, 0L))
				{
					PropSheet_SetWizButtons(GetParent(hwndDlg), PSWIZB_BACK | PSWIZB_NEXT);
				}

				else
				{
					PropSheet_SetWizButtons(GetParent(hwndDlg), PSWIZB_BACK);
				}
			}
			break;
		}

		case WM_NOTIFY:
			{
			LPNMHDR lpnm = (LPNMHDR) lParam;
			switch (lpnm->code)
				{
				// Enable the Next and Back buttons
				case PSN_SETACTIVE:
					if(	SendDlgItemMessage(hwndDlg, IDC_STAT_PROVINCE, WM_GETTEXTLENGTH, 0, 0L) &&
						SendDlgItemMessage(hwndDlg, IDC_CITY_LOCALITY, WM_GETTEXTLENGTH, 0, 0L))
					{
						PropSheet_SetWizButtons(GetParent(hwndDlg), PSWIZB_BACK | PSWIZB_NEXT);
					}

					else
					{
						PropSheet_SetWizButtons(GetParent(hwndDlg), PSWIZB_BACK);
					}

					break;

				case PSN_WIZNEXT:
					{
					// Get Country from the property page
					GetDlgItemText(hwndDlg, IDC_EDIT_COUNTRY, ptrWizard->m_lpszCountry, 3);

					// Get State from the property page
					int nSize = (int)SendDlgItemMessage(hwndDlg, IDC_STAT_PROVINCE, WM_GETTEXTLENGTH, 0, 0L) + 1;
					delete [] ptrWizard->m_lpszState;
					ptrWizard->m_lpszState = new _TCHAR [nSize];
					GetDlgItemText(hwndDlg, IDC_STAT_PROVINCE, ptrWizard->m_lpszState, nSize);

					// Get City from the property page
					nSize = (int)SendDlgItemMessage(hwndDlg, IDC_CITY_LOCALITY, WM_GETTEXTLENGTH, 0, 0L) + 1;
					delete [] ptrWizard->m_lpszCity;
					ptrWizard->m_lpszCity = new _TCHAR [nSize];
					GetDlgItemText(hwndDlg, IDC_CITY_LOCALITY, ptrWizard->m_lpszCity, nSize);

					break;
					}
				}
			}
        break;
    }
    return 0;
}

/***********************************************
ContactInfoDlgProc
	Dialog function of the contact info
	property page
************************************************/
BOOL CALLBACK CUT_CertRequestWizard::ContactInfoDlgProc(HWND hwndDlg, UINT uMsg, WPARAM /* wParam */, LPARAM lParam)
{
	// Get pointer to the CUT_CertRequestWizard class
    CUT_CertRequestWizard *ptrWizard = NULL;
	if(uMsg == WM_INITDIALOG)
	{
		ptrWizard = (CUT_CertRequestWizard *)((LPPROPSHEETPAGE)lParam)->lParam;

		// Save pointer to the CUT_CertRequestWizard class as dialog param
		SetWindowLong(hwndDlg, GWL_USERDATA, (LONG)(ULONG_PTR)ptrWizard);
	}
	else
		ptrWizard = (CUT_CertRequestWizard *)(ULONG_PTR)GetWindowLong(hwndDlg, GWL_USERDATA);
	
	// Check class pointer for NULL
	if(ptrWizard == NULL)
		return 0;


	// ***********************************************
	// ** Dialog messages switch
	// ***********************************************
    switch (uMsg)
    {
		case WM_NOTIFY:
        {
			LPNMHDR lpnm = (LPNMHDR) lParam;
			switch (lpnm->code)
			{
				// Enable the Next and Back buttons
				case PSN_SETACTIVE:
					PropSheet_SetWizButtons(GetParent(hwndDlg), PSWIZB_BACK | PSWIZB_NEXT);
					break;

				case PSN_WIZNEXT:
				{
					// Get E-mail address from the property page
					int nSize = (int)SendDlgItemMessage(hwndDlg, IDC_EMAIL, WM_GETTEXTLENGTH, 0, 0L) + 1;
					delete [] ptrWizard->m_lpszEMail;
					ptrWizard->m_lpszEMail = new _TCHAR [nSize];
					GetDlgItemText(hwndDlg, IDC_EMAIL, ptrWizard->m_lpszEMail, nSize);

					// Get full name from the property page
					nSize = (int)SendDlgItemMessage(hwndDlg, IDC__FULL_NAME, WM_GETTEXTLENGTH, 0, 0L) + 1;
					delete [] ptrWizard->m_lpszGivenName;
					ptrWizard->m_lpszGivenName = new _TCHAR [nSize];
					GetDlgItemText(hwndDlg, IDC__FULL_NAME, ptrWizard->m_lpszGivenName, nSize);

					// Get phone number from the property page
					nSize = (int)SendDlgItemMessage(hwndDlg, IDC_PHONE_NUMBER, WM_GETTEXTLENGTH, 0, 0L) + 1;
					delete [] ptrWizard->m_lpszPhone;
					ptrWizard->m_lpszPhone = new _TCHAR [nSize];
					GetDlgItemText(hwndDlg, IDC_PHONE_NUMBER, ptrWizard->m_lpszPhone, nSize);
			
					break;
				}
			}
		}
		break;
	}
    return 0;
}

/***********************************************
RequestFileDlgProc
	Dialog function of the request file name
	property page
************************************************/
BOOL CALLBACK CUT_CertRequestWizard::RequestFileDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	// Get pointer to the CUT_CertRequestWizard class
    CUT_CertRequestWizard *ptrWizard = NULL;
	if(uMsg == WM_INITDIALOG)
	{
		ptrWizard = (CUT_CertRequestWizard *)((LPPROPSHEETPAGE)lParam)->lParam;

		// Save pointer to the CUT_CertRequestWizard class as dialog param
		SetWindowLong(hwndDlg, GWL_USERDATA, (LONG)(ULONG_PTR)ptrWizard);
	}
	else
		ptrWizard = (CUT_CertRequestWizard *)(ULONG_PTR)GetWindowLong(hwndDlg, GWL_USERDATA);
	
	// Check class pointer for NULL
	if(ptrWizard == NULL)
		return 0;


	// ***********************************************
	// ** Dialog messages switch
	// ***********************************************
    switch (uMsg)
    {
	    case WM_INITDIALOG:
			SendDlgItemMessage(hwndDlg, IDC_OPEN_WITH, BM_SETCHECK, BST_CHECKED, 0);
			SetDlgItemText(hwndDlg, IDC_FILE_NAME, _T("C:\\CertReq.txt"));
            break;

		case WM_COMMAND:
		{
			// Edit control content changed. Check if the Next button must be enabled
			if(HIWORD(wParam) == EN_CHANGE)
			{
				// Enable Next/Back buttons
				if(SendDlgItemMessage(hwndDlg, IDC_FILE_NAME, WM_GETTEXTLENGTH, 0, 0L))
				{
					EnableWindow(GetDlgItem(hwndDlg, IDC_OPEN_WITH), TRUE);
					PropSheet_SetWizButtons(GetParent(hwndDlg), PSWIZB_BACK | PSWIZB_NEXT);
				}
				else
				{
					EnableWindow(GetDlgItem(hwndDlg, IDC_OPEN_WITH), FALSE);
					PropSheet_SetWizButtons(GetParent(hwndDlg), PSWIZB_BACK);
				}
			}
			break;
		}

		case WM_NOTIFY:
		{
			LPNMHDR lpnm = (LPNMHDR) lParam;
			switch (lpnm->code)
			{
				// Enable the Next and Back buttons
				case PSN_SETACTIVE:
					if(SendDlgItemMessage(hwndDlg, IDC_FILE_NAME, WM_GETTEXTLENGTH, 0, 0L))
						PropSheet_SetWizButtons(GetParent(hwndDlg), PSWIZB_BACK | PSWIZB_NEXT);
					else
						PropSheet_SetWizButtons(GetParent(hwndDlg), PSWIZB_BACK);
					break;

				case PSN_WIZNEXT:
				{
					// Get E-mail address from the property page
					int nSize = (int)SendDlgItemMessage(hwndDlg, IDC_FILE_NAME, WM_GETTEXTLENGTH, 0, 0L) + 1;
					delete [] ptrWizard->m_lpszFileName;
					ptrWizard->m_lpszFileName = new _TCHAR [nSize];
					GetDlgItemText(hwndDlg, IDC_FILE_NAME, ptrWizard->m_lpszFileName, nSize);

					// Get open with Notepad flag
					ptrWizard->m_bOpenWithNotePad = IsDlgButtonChecked(hwndDlg, IDC_OPEN_WITH);

					break;
				}

			}
		}
		break;
    }
    return 0;
}

/***********************************************
PreviewDlgProc
	Dialog function of the preview property page
************************************************/
BOOL CALLBACK CUT_CertRequestWizard::PreviewDlgProc(HWND hwndDlg, UINT uMsg, WPARAM /* wParam */, LPARAM lParam)
{
	// Get pointer to the CUT_CertRequestWizard class
    CUT_CertRequestWizard *ptrWizard = NULL;
	if(uMsg == WM_INITDIALOG)
	{
		ptrWizard = (CUT_CertRequestWizard *)((LPPROPSHEETPAGE)lParam)->lParam;

		// Save pointer to the CUT_CertRequestWizard class as dialog param
		SetWindowLong(hwndDlg, GWL_USERDATA, (LONG)(ULONG_PTR)ptrWizard);
	}
	else
		ptrWizard = (CUT_CertRequestWizard *)(ULONG_PTR)GetWindowLong(hwndDlg, GWL_USERDATA);
	
	// Check class pointer for NULL
	if(ptrWizard == NULL)
		return 0;


	// ***********************************************
	// ** Dialog messages switch
	// ***********************************************
    switch (uMsg)
    {
	    case WM_NOTIFY:
        {
	        LPNMHDR lpnm = (LPNMHDR) lParam;
		    switch (lpnm->code)
			{
				// Enable the Next and Back buttons and initialize entered data
	            case PSN_SETACTIVE:
				{
					switch (ptrWizard->m_dwKeySize )
					{
						case PUBLIC_KEY_512:
							SetDlgItemText(hwndDlg, IDC_PREV_KEY_STRENGTH, _T("512"));		
							break;
						case PUBLIC_KEY_1024: 
							SetDlgItemText(hwndDlg, IDC_PREV_KEY_STRENGTH, _T("1024"));
							break;
						case PUBLIC_KEY_2048:
							SetDlgItemText(hwndDlg, IDC_PREV_KEY_STRENGTH, _T("2048"));
							break;
					}

					SetDlgItemText(hwndDlg, IDC_PREV_KEY_NAME, ptrWizard->m_lpszKeyContainerName);
					SetDlgItemText(hwndDlg, IDC_PREV_COMMON_NAME, ptrWizard->m_lpszCommonName);
					SetDlgItemText(hwndDlg, IDC_PREV_EMAIL, ptrWizard->m_lpszEMail);
					SetDlgItemText(hwndDlg, IDC_PREV_ORG, ptrWizard->m_lpszOrganization);
					SetDlgItemText(hwndDlg, IDC_PREV_ORG_UNIT, ptrWizard->m_lpszOrganizationUnit);
					SetDlgItemText(hwndDlg, IDC_PREV_PHONE, ptrWizard->m_lpszPhone);
					SetDlgItemText(hwndDlg, IDC_PREV_COUNTRY, ptrWizard->m_lpszCountry);
					SetDlgItemText(hwndDlg, IDC_PREV_STATE, ptrWizard->m_lpszState );
					SetDlgItemText(hwndDlg, IDC_PREV_FILE_NAME, ptrWizard->m_lpszFileName);
					SetDlgItemText(hwndDlg, IDC_ISSUED_TO, ptrWizard->m_lpszGivenName);

					PropSheet_SetWizButtons(GetParent(hwndDlg), PSWIZB_BACK | PSWIZB_FINISH);
					break;
				}

				case PSN_WIZFINISH:
				{
					// Generate cerificate request
					CUT_CertificateManager mngr;

					// Delete any data in the request buffer
					if(ptrWizard->m_lpszRequestBuffer)
					{
						LocalFree(ptrWizard->m_lpszRequestBuffer);
						ptrWizard->m_lpszRequestBuffer  = NULL;
					}

					// Call the Certificate Manager to regenerate a CSR
					ptrWizard->m_nWizardResult = mngr.CertificateRequest(
								ptrWizard->m_lpszKeyContainerName,
								ptrWizard->m_dwStoreLocation,
								ptrWizard->m_dwKeySize,
								ptrWizard->m_lpszCommonName,
								ptrWizard->m_lpszOrganization,
								ptrWizard->m_lpszOrganizationUnit,
								ptrWizard->m_lpszCountry,
								ptrWizard->m_lpszState,
								ptrWizard->m_lpszCity,
								ptrWizard->m_lpszGivenName,
								ptrWizard->m_lpszEMail,
								ptrWizard->m_lpszPhone, 
								&ptrWizard->m_lpszRequestBuffer,
								ptrWizard->m_lpszFileName);

					// Check the result
					if(ptrWizard->m_nWizardResult == UTE_SUCCESS)
					{
						MessageBox(hwndDlg, _T("Certificate Request was successfully created."), _T("Certificate Request Wizard"), MB_OK);

						HWND  hwndCancel = GetDlgItem(GetParent(hwndDlg), IDCANCEL);
						ShowWindow(hwndCancel, SW_HIDE);
						if(ptrWizard->m_bOpenWithNotePad)
						{
							// Open certificate request file in the notepad
							_TCHAR	szBuffer[1024];
							_sntprintf(szBuffer, sizeof(szBuffer)-1, _T("notepad.exe %s"), ptrWizard->m_lpszFileName);
							WinExec(AC(szBuffer), SW_SHOWNORMAL);
						}
					}
					else
					{
						// Show error message
						MessageBox(hwndDlg, CUT_ERR::GetErrorString(ptrWizard->m_nWizardResult), _T("Certificate Request Wizard"), MB_OK);
					}
        
					break;
				}
            }
        }
        break;
    }
    return 0;
}

/***********************************************
ErrorDlgProc
	Dialog function of the error property page
************************************************/
BOOL CALLBACK CUT_CertRequestWizard::ErrorDlgProc(HWND hwndDlg, UINT uMsg, WPARAM /* wParam */, LPARAM lParam)
{
	// Get pointer to the CUT_CertRequestWizard class
    CUT_CertRequestWizard *ptrWizard = NULL;
	if(uMsg == WM_INITDIALOG)
	{
		ptrWizard = (CUT_CertRequestWizard *)((LPPROPSHEETPAGE)lParam)->lParam;

		// Save pointer to the CUT_CertRequestWizard class as dialog param
		SetWindowLong(hwndDlg, GWL_USERDATA, (LONG)(ULONG_PTR)ptrWizard);
	}
	else
		ptrWizard = (CUT_CertRequestWizard *)(ULONG_PTR)GetWindowLong(hwndDlg, GWL_USERDATA);
	
	// Check class pointer for NULL
	if(ptrWizard == NULL)
		return 0;


	// ***********************************************
	// ** Dialog messages switch
	// ***********************************************
    switch (uMsg)
    {
	    case WM_NOTIFY:
        {
		    LPNMHDR lpnm = (LPNMHDR) lParam;
			switch (lpnm->code)
            {
				// Enable the correct buttons on for the active page
	            case PSN_SETACTIVE:
				{
					HWND  hwndTextStatic = GetDlgItem(hwndDlg,IDC_ERRRO_CODE);
					SetWindowText(hwndTextStatic, CUT_ERR::GetErrorString(ptrWizard->m_nWizardResult));
				
					PropSheet_SetWizButtons(GetParent(hwndDlg), PSWIZB_BACK );
					break;
					}

	            case PSN_WIZBACK:
				{
					HWND  hwndCancel = GetDlgItem(GetParent(hwndDlg),IDCANCEL);
					ShowWindow(hwndCancel,SW_SHOW);
          			break;
				}
            }
        }
	    break;
    }
    return 0;
}
/*********************************************************
Set the style for each page based on the version number of the 
common control DLL.
This is needed since the wizard is using the win97 wizard style
this style is only available with version 5.8 of the common control dll

Param:
		PROPSHEETPAGE     *psp - the page sheet to set the style for
		LPTSTR				szTitle  - The title of the page 
		LPTSTR				szSubTitle - THe sub-title
**********************************************************/
void CUT_CertRequestWizard::SetPageStyle(PROPSHEETPAGE     *psp, LPTSTR szTitle, LPTSTR szSubTitle)
{
	if(GetDllVersion(TEXT("comctl32.dll")) >= PACKVERSION(5,80))
	{
		psp->dwFlags =       PSP_DEFAULT|PSP_USEHEADERTITLE|PSP_USEHEADERSUBTITLE;
		psp->pszHeaderTitle =    szTitle;
		psp->pszHeaderSubTitle = szSubTitle;
	}
	else
	{
		psp->dwFlags =       PSP_DEFAULT|PSP_USETITLE ;
		psp->pszTitle =			szTitle;
	}
	
}


#endif // #ifdef CUT_SECURE_SOCKET

#pragma warning (pop)