/* =================================================================
//  class: CBase64
//  File:  Base64.cpp
//  
//  Purpose:
//  
//  several Internet protocols uses Base64 mechanism  
//  This mecahnism:
//	1)  enables the transfer of binarry data over a UTF-8 
//  compatible media.
//	2) The data transfered is  not humannly readable which may add 
//  some sence of privacy to the comunication (Notice this is not a secure implementation)
//
//	The MIME (Multipurpose Internet Mail Extensions) specification
//	(RFC 1341 and successors e.g 2045-49) defines a mechanism for encoding 
//	arbitrary binary information for transmission by electronic mail.
//	Triplets of 8-bit octets are encoded as groups of four characters,
//	each representing 6 bits of the source 24 bits. 
//	Only characters present in all variants of ASCII and EBCDIC are used,
//	avoiding incompatibilities in other forms of encoding such as uuencode/uudecode
//
//	The Base64 Content-Transfer-Encoding is designed to represent arbitrary 
//	sequences of octets in a form that is not humanly readable. 
//	The encoding and decoding algorithms are simple, but the encoded 
//	data are consistently only about 33 percent larger than the unencoded data.
//	 This encoding is based on the one used in Privacy Enhanced Mail applications,
//	 as defined in RFC 1113. The base64 encoding is adapted from RFC 1113, 
//	with one change: base64 eliminates the "*" mechanism for embedded clear text
// See RFC 1341
// 
// ===================================================================
// Ultimate TCP/IP v4.2
// This software along with its related components, documentation and files ("The Libraries")
// is � 1994-2007 The Code Project (1612916 Ontario Limited) and use of The Libraries is
// governed by a software license agreement ("Agreement").  Copies of the Agreement are
// available at The Code Project (www.codeproject.com), as part of the package you downloaded
// to obtain this file, or directly from our office.  For a copy of the license governing
// this software, you may contact us at legalaffairs@codeproject.com, or by calling 416-849-8900.
// 
// =================================================================*/
#include "stdafx.h"
#include <windows.h>
#include "Base64.h"

/***********************************************************
Con
************************************************************/
CBase64::CBase64()
{

}

/***********************************************************
tor
************************************************************/
CBase64::~CBase64()
{

}

/***********************************************************
Decode each character using it's four degits presentation
PARAM
	in - string of 4 characters
	out - output buffer (must be at least chars 3 long)
RET
 - number of bytes out
************************************************************/
int CBase64::DecodeChars(LPCSTR in, char *out){

	UCHAR c1, c2, c3, c4;
    
    c1 = FindBase64Val(in[0]);
    c2 = FindBase64Val(in[1]);      
    c3 = FindBase64Val(in[2]);
    c4 = FindBase64Val(in[3]);
    
    out[0] = (UCHAR)(((c1 & 63)<<2) | ((c2 & 48)>>4));
    
    out[1] = (UCHAR)(((c2 & 15)<<4) | ((c3 & 60)>>2));
    
    out[2] = (UCHAR)(((c3 & 3)<<6) | (c4 & 63));
    
    // c1 and c2 were used (the mimimum number possible)
    // and resulted in one 8bit byte.
    if (in[2] == '=')
        return 1;
    
    // c1, c2 and c3 were used, resuting in 2 8bit bytes.
    if (in[3] == '=')
        return 2;
    
    // all bytes were used.
    return 3;
}

/***********************************************************
	The encoding process represents 24-bit groups of input 
	bits as output strings of 4 encoded characters. 
	Proceeding from left to right, a 24-bit input group is 
	formed by concatenating 3 8-bit input groups. 
	These 24 bits are then treated as 4 concatenated 6-bit 
	groups, each of which is translated into a single digit
	in the base64 alphabet. When encoding a bit stream via 
	the base64 encoding, the bit stream must be presumed to 
	be ordered with the most- significant-bit first.
	That is, the first bit in the stream will be the 
	high-order bit in the first byte, and the eighth bit will
	be the low-order bit in the first byte, and so on.


************************************************************/
void CBase64::EncodeChars(LPCSTR in, char *out, int count){
    
    static char m_szBase64Table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	int index1 = ((in[0] >> 2) & 63);
    int index2 = (((in[0] << 4) & 48) | ((in[1] >> 4) & 15));
    int index3 = (((in[1] << 2) & 60) | ((in[2] >> 6) & 3));
    int index4 = (in[2] & 63);
    
    out[0] = m_szBase64Table[index1];
    out[1] = m_szBase64Table[index2];
    out[2] = m_szBase64Table[index3];
    out[3] = m_szBase64Table[index4];
    
	// Since all base64 input is an integral number of octets, 
	// only the following cases can arise: 
	// (1) the final quantum of encoding input is an integral multiple 
	// of 24 bits; here, the final unit of encoded output will be an 
	// integral multiple of 4 characters with no "=" padding,
	// The count variable will be 3

	// (2) the final quantum of encoding input is exactly 8 bits;
	// here, the final unit of encoded output will be two characters
	// followed by two "=" padding characters, or 
	// the count variable will be 1 so the case 1 below will fall through to case 2
	// 
	// (3) the final quantum of encoding input is exactly 
	// 16 bits; here, the final unit of encoded output will 
	// be three characters followed by one "=" padding character. 
	// the count will be 2

    switch(count){
	 case 1:
        out[2]='=';  // fall through to fill in the next character too
    case 2:
        out[3]='=';
    }
}

/***********************************************************

************************************************************/
int CBase64::DecodeBytes(LPCSTR in, LPBYTE out){
	UCHAR c1, c2, c3, c4;
    
    c1 = FindBase64Val(in[0]);
    c2 = FindBase64Val(in[1]);      
    c3 = FindBase64Val(in[2]);
    c4 = FindBase64Val(in[3]);
    
    out[0] = (UCHAR)(((c1 & 63)<<2) | ((c2 & 48)>>4));
    
    out[1] = (UCHAR)(((c2 & 15)<<4) | ((c3 & 60)>>2));
    
    out[2] = (UCHAR)(((c3 & 3)<<6) | (c4 & 63));
    
    // c1 and c2 were used (the mimimum number possible)
    // and resulted in one 8bit byte.
    if (in[2] == '=')
        return 1;
    
    // c1, c2 and c3 were used, resuting in 2 8bit bytes.
    if (in[3] == '=')
        return 2;
    
    // all bytes were used.
    return 3;
}

/***********************************************************
	The encoding process represents 24-bit groups of input 
	bits as output strings of 4 encoded characters. 
	Proceeding from left to right, a 24-bit input group is 
	formed by concatenating 3 8-bit input groups. 
	These 24 bits are then treated as 4 concatenated 6-bit 
	groups, each of which is translated into a single digit
	in the base64 alphabet. When encoding a bit stream via 
	the base64 encoding, the bit stream must be presumed to 
	be ordered with the most- significant-bit first.
	That is, the first bit in the stream will be the 
	high-order bit in the first byte, and the eighth bit will
	be the low-order bit in the first byte, and so on.

PARAM
	LPCBYTE	-	in a constant pointer to the bytes being encoded
	LPTSTR	-   A pointer to the buffer that will hold the resulted data
	int		-   count	The number of bytes being encoded (1, 2, 3)
************************************************************/
void CBase64::EncodeBytes(LPCBYTE in, LPSTR out, int count){

    static char m_szBase64Table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	int index1 = ((in[0] >> 2) & 63);
    int index2 = (((in[0] << 4) & 48) | ((in[1] >> 4) & 15));
    int index3 = (((in[1] << 2) & 60) | ((in[2] >> 6) & 3));
    int index4 = (in[2] & 63);
    
    out[0] = m_szBase64Table[index1];
    out[1] = m_szBase64Table[index2];
    out[2] = m_szBase64Table[index3];
    out[3] = m_szBase64Table[index4];

	// Since all base64 input is an integral number of octets, 
	// only the following cases can arise: 
	// (1) the final quantum of encoding input is an integral multiple 
	// of 24 bits; here, the final unit of encoded output will be an 
	// integral multiple of 4 characters with no "=" padding,
	// The count variable will be 3

	// (2) the final quantum of encoding input is exactly 8 bits;
	// here, the final unit of encoded output will be two characters
	// followed by two "=" padding characters, or 
	// the count variable will be 1 so the case 1 below will fall through to case 2
	// 
	// (3) the final quantum of encoding input is exactly 
	// 16 bits; here, the final unit of encoded output will 
	// be three characters followed by one "=" padding character. 
	// the count will be 2
    switch(count){
    case 1:
        out[2]='=';
    case 2:
        out[3]='=';
    }
}

/***********************************************************
	Each 6-bit group is used as an index into an array of 64
	printable characters. 
	The character referenced by the index is placed in the 
	output string. These characters, identified in Table m_szBase64Table,
	below, are selected so as to be universally representable,
	and the set excludes characters with particular significance 
	to SMTP (e.g., ".", "CR", "LF") and to the encapsulation 
	boundaries defined in this document (e.g., "-"). 
PARAM:
	TCHAR character - The character to find the corresponding 
						base64 presentation for
RET:
	UCHAR	- The base64 presentation of the character
************************************************************/
UCHAR CBase64::FindBase64Val(const char character){
	
	static char m_szBase64Table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    for (UCHAR pos = 0; pos <64; pos ++)
        if (m_szBase64Table[pos] == character)
            return pos;
        
        return (UCHAR)-1;
}

/***********************************************************
Decode a base64 encoded string to oreginal presentations
PARAM:
	LPCTSTR szIn -  a constant pointer to the base64 encoded string
	szOut - a buffer to hold the result string
	nOutLen - Maximum length of the output
			Notice that usually a base64 data is 33 percent larger than the oregional
RET:
	TRUE -	 Data was decoded correctly
	FALSE-	 Input errors 
************************************************************/
BOOL CBase64::DecodeString(LPCSTR szIn, LPSTR szOut, int nOutLen){

		// make sure we have data in
	if (szIn[0] == 0)
		return FALSE;

	if (nOutLen <= 0)
		return FALSE;

	int len = (int)strlen(szIn);
	int cnt = 0;

	for(int loop = 0; loop < len;loop+=4){
		cnt += DecodeChars(&szIn[loop],&szOut[cnt]);
		if((cnt+4) > nOutLen)
			return FALSE;
	}
	szOut[cnt] = 0;

	return TRUE;
}

/***********************************************************
Encode a string to it's base64 equivelant.
PARAM:
	LPCTSTR szIn -  a constant pointer to the base64 encoded string
	szOut - a buffer to hold the result string
	nOutLen - Maximum length of the output
			Notice that usually a base64 data is 33 percent larger than the oregional
************************************************************/
BOOL CBase64::EncodeString(LPCSTR szIn, LPSTR szOut, int nOutLen){
	
	// make sure we have data in
	if (szIn[0] == 0)
		return FALSE;

	if (nOutLen <= 0)
		return FALSE;


	int len = (int)strlen(szIn);
	int cnt = 0;
	int cnt2 = 0;

	for(int loop = 0; loop < len;loop+=3){
		cnt = 3;
		if((loop+3) >= len)
			cnt = (len - loop);
		
		if((cnt2+4) > nOutLen)
			return FALSE;

		EncodeChars(&szIn[loop],&szOut[cnt],cnt);

		cnt2+=4;
	}
	szOut[cnt2] = 0;

	return TRUE;
}
/***********************************************************

************************************************************/
BOOL CBase64::DecodeData(LPCSTR szIn, LPBYTE szOut, int* nOutLen){

	int len = (int)strlen(szIn);
	int cnt = 0;

	for(int loop = 0; loop < len;loop+=4){
		cnt += DecodeBytes(&szIn[loop],&szOut[cnt]);
		if((cnt+4) > *nOutLen)
			return FALSE;
	}
	*nOutLen = cnt;
	return TRUE;
}
/***********************************************************

************************************************************/
BOOL CBase64::EncodeData(LPCBYTE szIn, int nInLen, LPSTR szOut, int nOutLen){
	
	int len = nInLen;
	int cnt = 0;
	int cnt2 = 0;

	for(int loop = 0; loop < len;loop+=3){
		cnt = 3;
		if((loop+3) >= len)
			cnt = (len - loop);
		
		if((cnt2+4) > nOutLen)
			return FALSE;

		EncodeBytes(&szIn[loop],&szOut[cnt2],cnt);

		cnt2+=4;
	}
	szOut[cnt2] = 0;

	return TRUE;
}
