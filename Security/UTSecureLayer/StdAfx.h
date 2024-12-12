// stdafx.h : include file for standard system include files,
//  or project specific include files that are used frequently, but
//      are changed infrequently
//

#if !defined(AFX_STDAFX_H__FE052E37_FF9B_4B4F_9BAF_A61AE095180C__INCLUDED_)
#define AFX_STDAFX_H__FE052E37_FF9B_4B4F_9BAF_A61AE095180C__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000


// Insert your headers here
#define WIN32_LEAN_AND_MEAN		// Exclude rarely-used stuff from Windows headers

#include "stdutfx.h"	// standard ultimate TCP macros etc



// v4.2 build notes


// VC 6.0 compilation notes:

// The 2003 Platform SDK is in some respects incompatible with VC6, and no longer
// includes the xenroll.h file needed for the IEnroll interfaces.

// The PSDK files included with VS2005 can be used, This is a hack, since the .pdb debug formats 
// will be incompatible, so only release builds may be possible against uuid.lib(xenroll_i.obj).

// After deciding on the PSDK of choice, remember to move that include and lib dir to the top of 
// the lists in Tools | Options | Directories.

// If possible, try to obtain the February 2003 version of the PSDK - this is the last available
// VC6 compatible version, and will contain the IID_ICEnroll4 interface




#include <windows.h>

// TODO: reference additional headers your program requires here

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_STDAFX_H__FE052E37_FF9B_4B4F_9BAF_A61AE095180C__INCLUDED_)
