/* 
UrchinTSS

Copyright (c) Microsoft Corporation

All rights reserved. 

MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.  
*/

// Note: This code was derived from the TCG TPM 2.0 Library Specification at
// http://www.trustedcomputinggroup.org/resources/tpm_library_specification

//** Introduction
//
// This file contains the implementation of the symmetric block cipher modes
// allowed for a TPM. These function only use the single block encryption and
// decryption functions of OpesnSSL.
//
// Currently, this module only supports AES encryption. The SM4 code actually calls
// an AES routine

//** Includes, Defines, and Typedefs

#include    "stdafx.h"

//CRYPT_RESULT
//AES_create_key(
//    const unsigned char *userKey,
//    const int bits,
//    PVOID *key
//);
//
//CRYPT_RESULT
//AES_destroy_key(
//    PVOID key
//);
//
//CRYPT_RESULT
//AES_encrypt(
//    const unsigned char *in,
//    unsigned char *out,
//    PVOID key
//);
//
//CRYPT_RESULT
//AES_decrypt(
//    const unsigned char *in,
//    unsigned char *out,
//    PVOID key
//);

//*** _cpri__GetSymmetricBlockSize()
// This function returns the block size of the algorithm.
// return type: INT16
//   <= 0     cipher not supported
//   > 0      the cipher block size in bytes
INT16
_cpri__GetSymmetricBlockSize(
    TPM_ALG_ID      symmetricAlg,   // IN: the symmetric algorithm
    UINT16          keySizeInBits   // IN: the key size
)
{
    switch (symmetricAlg)
    {
#ifdef TPM_ALG_AES
    case TPM_ALG_AES:
#endif
#ifdef TPM_ALG_SM4 // Both AES and SM4 use the same block size
    case TPM_ALG_SM4:
#endif
        if(keySizeInBits != 0)  // This is mostly to have a reference to
            // keySizeInBits for the compiler
            return  16;
        else
            return 0;
        break;

    default:
        return 0;
    }
}
