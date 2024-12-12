# Microsoft Developer Studio Project File - Name="UTSecureLayer" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=UTSecureLayer - Win32 Unicode Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "UTSecureLayer.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "UTSecureLayer.mak" CFG="UTSecureLayer - Win32 Unicode Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "UTSecureLayer - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "UTSecureLayer - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "UTSecureLayer - Win32 Unicode Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "UTSecureLayer - Win32 Unicode Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "UTSecureLayer - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "UTSECURELAYER_EXPORTS" /Yu"stdafx.h" /FD /c
# ADD CPP /nologo /MD /W4 /GX /O2 /I "..\Include" /I "..\..\Include" /I "C:\Program Files\Microsoft Platform SDK for Windows Server 2003 R2\Include" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "UTSECURELAYER_EXPORTS" /D "CUT_SECURE_SOCKET" /Yu"stdafx.h" /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib comctl32.lib /nologo /dll /machine:I386 /out:"../Lib/UTSecureLayer.dll" /implib:"../Lib/UTSecureLayer.lib"
# SUBTRACT LINK32 /pdb:none

!ELSEIF  "$(CFG)" == "UTSecureLayer - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "UTSECURELAYER_EXPORTS" /Yu"stdafx.h" /FD /GZ /c
# ADD CPP /nologo /MTd /W4 /Gm /GX /ZI /Od /I "C:\Program Files\Microsoft Visual Studio .NET 2003\Vc7\PlatformSDK\Include" /I "..\Include" /I "..\..\Include" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "UTSECURELAYER_EXPORTS" /D "CUT_SECURE_SOCKET" /FR /Yu"stdafx.h" /FD /GZ /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /debug /machine:I386 /pdbtype:sept
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib comctl32.lib /nologo /dll /debug /machine:I386 /out:"../Lib/UTSecureLayerD.dll" /implib:"../Lib/UTSecureLayerD.lib" /pdbtype:sept
# SUBTRACT LINK32 /pdb:none

!ELSEIF  "$(CFG)" == "UTSecureLayer - Win32 Unicode Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "UTSecureLayer___Win32_Unicode_Debug"
# PROP BASE Intermediate_Dir "UTSecureLayer___Win32_Unicode_Debug"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Unicode_Debug"
# PROP Intermediate_Dir "Unicode_Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /I "C:\Program Files\Microsoft Visual Studio .NET 2003\Vc7\PlatformSDK\Include" /I "..\Include" /I "..\..\Include" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "UTSECURELAYER_EXPORTS" /D "CUT_SECURE_SOCKET" /FR /Yu"stdafx.h" /FD /GZ /c
# ADD CPP /nologo /MTd /W4 /Gm /GX /ZI /Od /I "C:\Program Files\Microsoft Visual Studio .NET 2003\Vc7\PlatformSDK\Include" /I "..\Include" /I "..\..\Include" /D "UNICODE" /D "_UNICODE" /D "_USRDLL" /D "UTSECURELAYER_EXPORTS" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "CUT_SECURE_SOCKET" /FR /Yu"stdafx.h" /FD /GZ /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib comctl32.lib /nologo /dll /debug /machine:I386 /out:"../Lib/UTSecureLayer.dll" /implib:"../Lib/UTSecureLayer.lib" /pdbtype:sept /libpath:"C:\Program Files\Microsoft Visual Studio .NET 2003\Vc7\PlatformSDK\Lib\\"
# SUBTRACT BASE LINK32 /pdb:none
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib comctl32.lib /nologo /dll /debug /machine:I386 /out:"../Lib/UTSecureLayerUD.dll" /implib:"../Lib/UTSecureLayerUD.lib" /pdbtype:sept
# SUBTRACT LINK32 /pdb:none

!ELSEIF  "$(CFG)" == "UTSecureLayer - Win32 Unicode Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "UTSecureLayer___Win32_Unicode_Release"
# PROP BASE Intermediate_Dir "UTSecureLayer___Win32_Unicode_Release"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Unicode_Release"
# PROP Intermediate_Dir "Unicode_Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MD /W3 /GX /O2 /I "..\Include" /I "..\..\Include" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "UTSECURELAYER_EXPORTS" /D "CUT_SECURE_SOCKET" /Yu"stdafx.h" /FD /c
# ADD CPP /nologo /MD /W4 /GX /O2 /I "..\Include" /I "..\..\Include" /D "UNICODE" /D "_UNICODE" /D "_USRDLL" /D "UTSECURELAYER_EXPORTS" /D "CUT_SECURE_SOCKET" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /Yu"stdafx.h" /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib comctl32.lib /nologo /dll /machine:I386 /out:"../Lib/UTSecureLayer.dll" /implib:"../Lib/UTSecureLayer.lib"
# SUBTRACT BASE LINK32 /pdb:none /debug
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib comctl32.lib /nologo /dll /machine:I386 /out:"../Lib/UTSecureLayerU.dll" /implib:"../Lib/UTSecureLayerU.lib"
# SUBTRACT LINK32 /pdb:none

!ENDIF 

# Begin Target

# Name "UTSecureLayer - Win32 Release"
# Name "UTSecureLayer - Win32 Debug"
# Name "UTSecureLayer - Win32 Unicode Debug"
# Name "UTSecureLayer - Win32 Unicode Release"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=.\StdAfx.cpp
# ADD CPP /Yc"stdafx.h"
# End Source File
# Begin Source File

SOURCE=..\Source\UT_CertWizard.cpp
# End Source File
# Begin Source File

SOURCE=..\..\source\UT_StrOp.cpp
# End Source File
# Begin Source File

SOURCE=..\Source\UTCertifInstDlg.cpp
# End Source File
# Begin Source File

SOURCE=..\Source\UTCertifListDlg.cpp
# End Source File
# Begin Source File

SOURCE=..\Source\UTCertifMan.cpp
# End Source File
# Begin Source File

SOURCE=..\..\source\utfile.cpp
# End Source File
# Begin Source File

SOURCE=.\UTSecureLayer.cpp
# End Source File
# Begin Source File

SOURCE=..\Source\UTSecureSocket.cpp
# End Source File
# Begin Source File

SOURCE=..\..\source\utstrlst.cpp
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=.\StdAfx.h
# End Source File
# Begin Source File

SOURCE=..\Include\UT_CertWizard.h
# End Source File
# Begin Source File

SOURCE=..\..\Include\ut_strop.h
# End Source File
# Begin Source File

SOURCE=..\Include\UTCertifInstDlg.h
# End Source File
# Begin Source File

SOURCE=..\Include\UTCertifListDlg.h
# End Source File
# Begin Source File

SOURCE=..\Include\UTCertifMan.h
# End Source File
# Begin Source File

SOURCE=..\..\Include\utfile.h
# End Source File
# Begin Source File

SOURCE=..\Include\UTSecureSocket.h
# End Source File
# Begin Source File

SOURCE=..\..\Include\utstrlst.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# Begin Source File

SOURCE=..\Res\icon_cer_l.ico
# End Source File
# Begin Source File

SOURCE=..\Res\icon_cer_s.ico
# End Source File
# Begin Source File

SOURCE=..\Res\SecurityRes.h
# End Source File
# Begin Source File

SOURCE=..\Res\SecurityRes.rc
# End Source File
# Begin Source File

SOURCE=..\..\Include\ut_clnt.h
# End Source File
# End Group
# Begin Source File

SOURCE=.\ReadMe.txt
# End Source File
# End Target
# End Project
