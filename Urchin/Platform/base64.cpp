/*
UrchinTSS

Copyright (c) Microsoft Corporation

All rights reserved.

MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "stdafx.h"

BOOL
Base64encodeW(
TPM2B_AUTH *auth,
__out_ecount_opt(cchEncodedStringSize) PWSTR pszEncodedString,
DWORD cchEncodedStringSize,
PDWORD pcchEncoded
)
{
    static WCHAR rgchEncodeTable[64] = {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
        'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
        'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
    };

    DWORD   ib;
    DWORD   ich;
    DWORD  cchEncoded;
    BYTE    b0, b1, b2;
    BYTE *  pbDecodedBuffer = auth->t.buffer;

    if((pszEncodedString == NULL) || (auth == NULL) || (cchEncodedStringSize == 0) || (pcchEncoded == NULL))
    {
        return FALSE;
    }

    // Calculate encoded string size.
    cchEncoded = (1 + (auth->t.size + 2) / 3 * 4);

    if (NULL != pcchEncoded) {
        *pcchEncoded = cchEncoded;
    }

    if (cchEncodedStringSize < cchEncoded) {
        // Given buffer is too small to hold encoded string.
        return FALSE;
    }

    // Encode data byte triplets into four-byte clusters.
    ib = ich = 0;
    while(ib < auth->t.size
        && ich <= cchEncodedStringSize-4)// For prefast's benefit
    {
        b0 = pbDecodedBuffer[ib++];
        b1 = (ib < auth->t.size) ? pbDecodedBuffer[ib++] : 0;
        b2 = (ib < auth->t.size) ? pbDecodedBuffer[ib++] : 0;

        pszEncodedString[ich++] = rgchEncodeTable[b0 >> 2];
        pszEncodedString[ich++] = rgchEncodeTable[((b0 << 4) & 0x30) |
                                                  ((b1 >> 4) & 0x0f)];
        pszEncodedString[ich++] = rgchEncodeTable[((b1 << 2) & 0x3c) |
                                                  ((b2 >> 6) & 0x03)];
        pszEncodedString[ich++] = rgchEncodeTable[b2 & 0x3f];
    }

    // Pad the last cluster as necessary to indicate the number of data bytes
    // it represents.
    switch(auth->t.size % 3)
    {
    case 0:
        break;
    case 1:
        pszEncodedString[ich - 2] = '=';
        // fall through
    case 2:
        pszEncodedString[ich - 1] = '=';
        break;
    }

    // Null-terminate the encoded string.
    if (ich >= cchEncodedStringSize)
    {
        // Should never get here, but prefast can't figure that out
        return FALSE;
    }

    pszEncodedString[ich++] = '\0';

    return TRUE;
}

BOOL
Base64decodeW(
_In_z_ PWSTR pszEncodedString,
_Inout_ TPM2B_AUTH *auth
)
{
#define NA (255)
#define DECODE(x) \
    (((int)(x) < sizeof(rgbDecodeTable)) ? rgbDecodeTable[x] : NA)

    static BYTE rgbDecodeTable[128] = {
       NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,//0-15
       NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA,//16-31
       NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, NA, 62, NA, NA, NA, 63,//32-47
       52, 53, 54, 55, 56, 57, 58, 59, 60, 61, NA, NA, NA,  0, NA, NA,//48-63
       NA,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,//64-79
       15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, NA, NA, NA, NA, NA,//80-95
       NA, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,//96-111
       41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, NA, NA, NA, NA, NA,//112-127
    };

    DWORD   cbDecoded;
    DWORD   cchEncodedSize;
    DWORD   ich;
    DWORD   ib;
    BYTE    b0, b1, b2, b3;
    BYTE *  pbDecodeBuffer = auth->t.buffer;

    if((pszEncodedString == NULL) || (auth == NULL))
    {
        return FALSE;
    }

    cchEncodedSize = (DWORD)wcslen(pszEncodedString);

    if ((0 == cchEncodedSize) || (0 != (cchEncodedSize % 4)))
    {
        // Input string is not sized correctly to be base64.
        return FALSE;
    }

    // Calculate decoded buffer size.
    cbDecoded = (cchEncodedSize + 3) / 4 * 3;
    if (pszEncodedString[cchEncodedSize-1] == '=') {
        if (pszEncodedString[cchEncodedSize-2] == '=') {
            // Only one data byte is encoded in the last cluster.
            cbDecoded -= 2;
        }
        else {
            // Only two data bytes are encoded in the last cluster.
            cbDecoded -= 1;
        }
    }

    if(cbDecoded > sizeof(auth->t.buffer))
    {
        // Supplied buffer is too small.
        return FALSE;
    }
    auth->t.size = (UINT16)cbDecoded;

    // Decode each four-byte cluster into the corresponding three data bytes.
    ich = ib = 0;
    while (ich < cchEncodedSize)
    {
        b0 = (ich < cchEncodedSize) ? DECODE(pszEncodedString[ich]) : NA; ++ich;
        b1 = (ich < cchEncodedSize) ? DECODE(pszEncodedString[ich]) : NA; ++ich;
        b2 = (ich < cchEncodedSize) ? DECODE(pszEncodedString[ich]) : NA; ++ich;
        b3 = (ich < cchEncodedSize) ? DECODE(pszEncodedString[ich]) : NA; ++ich;

        if ((NA == b0) || (NA == b1) || (NA == b2) || (NA == b3)) {
            // Contents of input string are not base64.
            return FALSE;
        }

        pbDecodeBuffer[ib++] = (b0 << 2) | (b1 >> 4);

        if (ib < cbDecoded) {
            pbDecodeBuffer[ib++] = (b1 << 4) | (b2 >> 2);
    
            if (ib < cbDecoded) {
                pbDecodeBuffer[ib++] = (b2 << 6) | b3;
            }
        }
    }

    return TRUE;
}


