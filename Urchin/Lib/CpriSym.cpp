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

CRYPT_RESULT
AES_create_key(
    const unsigned char *userKey,
    const int bits,
    PVOID *key
);

CRYPT_RESULT
AES_destroy_key(
    PVOID key
);

CRYPT_RESULT
AES_encrypt(
    const unsigned char *in,
    unsigned char *out,
    PVOID key
);

CRYPT_RESULT
AES_decrypt(
    const unsigned char *in,
    unsigned char *out,
    PVOID key
);

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


//** AES Encryption

//*** _cpri__AESEncryptCBC()
// This function performs AES encryption in CBC chain mode.
// The input 'dIn' buffer is encrypted into 'dOut'.
//
// The input iv buffer is required to have a size equal to the block size 
// (16 bytes). The 'dInSize' is required to be a multiple of the block size.
//
// return type: CRYPT_RESULT
//      CRYPT_SUCCESS               if success
//      CRYPT_PARAMETER             'dInSize' is not a multiple of the block size
//
CRYPT_RESULT
_cpri__AESEncryptCBC(
    BYTE        *dOut,          // OUT:
    UINT32       keySizeInBits, // IN: key size in bits
    BYTE        *key,           // IN: key buffer. The size of this buffer
                                //     in bytes is (keySizeInBits + 7) / 8
    BYTE        *iv,            // IN/OUT: IV for decryption.
    UINT32       dInSize,       // IN: data size (is required to be a multiple
                                //     of 16 bytes
    BYTE        *dIn            // IN/OUT: data buffer
)
{
    PVOID  AesKey;
    BYTE  *pIv;
    INT32  dSize;         // Need a signed version
    int    i;

    pAssert(dOut != NULL && key != NULL && iv != NULL && dIn != NULL);

    if(dInSize == 0)
        return CRYPT_SUCCESS;

    pAssert(dInSize <= INT32_MAX);
    dSize = (INT32)dInSize;

    // For CBC, the data size must be an even multiple of the
    // cipher block size
    if((dSize % 16) != 0)
        return CRYPT_PARAMETER;

    // Create AES encrypt key schedule
    if(AES_create_key(key, keySizeInBits, &AesKey) != 0)
        FAIL(FATAL_ERROR_INTERNAL);

    // XOR the data block into the IV, encrypt the IV into the IV
    // and then copy the IV to the output
    #pragma warning( disable: 26014 )  //buffer dOut is deterministic and inside the range
    #pragma warning( disable: 22103 )  //buffer dOut is deterministic and inside the range
    for(; dSize > 0; dSize -= 16)
    {
        pIv = iv;
        for(i = 16; i > 0; i--)
            *pIv++ ^= *dIn++;
        AES_encrypt(iv, iv, AesKey);
        pIv = iv;
        for(i = 16; i > 0; i--)
            *dOut++ = *pIv++;
    }
    #pragma warning( default: 26014 ) 
    #pragma warning( default: 22103 ) 

    // destroy AES encrypt key schedule
    if(AES_destroy_key(AesKey) != 0)
        FAIL(FATAL_ERROR_INTERNAL);

    return CRYPT_SUCCESS;
}

//*** _cpri__AESDecryptCBC()
// This function performs AES decryption in CBC chain mode.
// The input 'dIn' buffer is decrypted into 'dOut'.
//
// The input iv buffer is required to have a size equal to the block size 
// (16 bytes). The 'dInSize' is required to be a multiple of the block size.
//
// return type: CRYPT_RESULT
//      CRYPT_SUCCESS               if success
//      CRYPT_PARAMETER             'dInSize' is not a multiple of the block size
//
CRYPT_RESULT
_cpri__AESDecryptCBC(
    BYTE       *dOut,           // OUT: the decrypted data
    UINT32      keySizeInBits,  // IN: key size in bits
    BYTE       *key,            // IN: key buffer. The size of this buffer
                                //     in bytes is (keySizeInBits + 7) / 8
    __in_ecount(16) BYTE       *iv,             // IN/OUT: IV for decryption. The size of
                                // this buffer if 16 byte.
    UINT32      dInSize,        // IN: data size
    BYTE       *dIn             // IN: data buffer
)
{
    PVOID  AesKey;
    BYTE  *pIv;
    int    i;
    BYTE   tmp[16];
    BYTE  *pT = NULL;
    INT32  dSize;

    pAssert(dOut != NULL && key != NULL && iv != NULL && dIn != NULL);

    if(dInSize == 0)
        return CRYPT_SUCCESS;

    pAssert(dInSize <= INT32_MAX);
    dSize = (INT32)dInSize;

    // For CBC, the data size must be an even multiple of the
    // cipher block size
    if((dSize % 16) != 0)
        return CRYPT_PARAMETER;

    // Create AES key schedule
    if (AES_create_key(key, keySizeInBits, &AesKey) != 0)
        FAIL(FATAL_ERROR_INTERNAL);

    // Copy the input data to a temp buffer, decrypt the buffer into the output;
    // XOR in the IV, and copy the temp buffer to the IV and repeat.
    for(; dSize > 0; dSize -= 16)
    {
        pT = tmp;
        for(i = 16; i> 0; i--)
            *pT++ = *dIn++;
        AES_decrypt(tmp, dOut, AesKey);
        pIv = iv;
        pT = tmp;
        for(i = 16; i> 0; i--)
        {
            *dOut++ ^= *pIv;
            *pIv++ = *pT++;
        }
    }

    // destroy AES encrypt key schedule
    if(AES_destroy_key(AesKey) != 0)
        FAIL(FATAL_ERROR_INTERNAL);

    return CRYPT_SUCCESS;
}


//*** _cpri__AESEncryptCFB()
// This function performs AES encryption in CFB chain mode. The 'dOut' buffer 
// receives the values encrypted 'dIn'. The input 'iv' is assumed to
// be the size of an encryption block (16 bytes). The 'iv' buffer will be
// modified to contain the last encrypted block.
//
// return type: CRYPT_RESULT
//      CRYPT_SUCCESS          no non-fatal errors
//
CRYPT_RESULT
_cpri__AESEncryptCFB(
    __in_ecount(dInSize) BYTE        *dOut,          // OUT: the encrypted
    UINT32       keySizeInBits, // IN: key size in bit
    BYTE        *key,           // IN: key buffer. The size of this buffer
                                //     in bytes is (keySizeInBits + 7) / 8
    BYTE        *iv,            // IN/OUT: IV for decryption.
    UINT32       dInSize,       // IN: data size
    BYTE        *dIn            // IN/OUT: data buffer
)
{
    BYTE        *pIv = NULL;
    PVOID        AesKey;
    INT32        dSize;         // Need a signed version of dInSize
    int          i;

    pAssert(dOut != NULL && key != NULL && iv != NULL && dIn != NULL);

    if(dInSize == 0)
        return CRYPT_SUCCESS;

    pAssert(dInSize <= INT32_MAX);
    dSize = (INT32)dInSize;

    // Create AES encryption key schedule
    if (AES_create_key(key, keySizeInBits, &AesKey) != 0)
        FAIL(FATAL_ERROR_INTERNAL);

    // Encrypt the IV into the IV, XOR in the data, and copy to output
    for(; dSize > 0; dSize -= 16)
    {
        // Encrypt the current value of the IV
        AES_encrypt(iv, iv, AesKey);
        pIv = iv;
        for(i = (int)(dSize < 16) ? dSize : 16; i > 0; i--)
            // XOR the data into the IV to create the cipher text
            // and put into the output
            *dOut++ = *pIv++ ^= *dIn++;
    }
    // If the inner loop (i loop) was smaller than 16, then dSize would have been
    // smaller than 16 and it is now negative. If it is negative, then it indicates
    // how many bytes are needed to pad out the IV for the next round.
    for(; dSize < 0; dSize++)
        *pIv++ = 0;

    // destroy AES encrypt key schedule
    if(AES_destroy_key(AesKey) != 0)
        FAIL(FATAL_ERROR_INTERNAL);

    return CRYPT_SUCCESS;
}


//*** _cpri__AESDecryptCFB()
// This function performs AES decrypt in CFB chain mode. 
// The 'dOut' buffer receives the values decrypted from 'dIn'. 
//
// The input 'iv' is assumed to be the size of an encryption block (16 bytes). 
// The 'iv' buffer will be modified to contain the last decoded block, padded 
// with zeros
//
// return type: CRYPT_RESULT
//      CRYPT_SUCCESS          no non-fatal errors
//
CRYPT_RESULT
_cpri__AESDecryptCFB(
    __in_ecount(dInSize) BYTE        *dOut,          // OUT: the decrypted data
    UINT32       keySizeInBits, // IN: key size in bit
    BYTE        *key,           // IN: key buffer. The size of this buffer
                                //     in bytes is (keySizeInBits + 7) / 8
    __in_ecount(16) BYTE        *iv,            // IN/OUT: IV for decryption.
    UINT32       dInSize,       // IN: data size
    BYTE        *dIn            // IN/OUT: data buffer
)
{
    BYTE        *pIv = NULL;
    BYTE         tmp[16];
    int          i;
    BYTE        *pT;
    PVOID      AesKey;
    INT32        dSize;

    pAssert(dOut != NULL && key != NULL && iv != NULL && dIn != NULL);

    if(dInSize == 0)
        return CRYPT_SUCCESS;

    pAssert(dInSize <= INT32_MAX);
    dSize = (INT32)dInSize;

    // Create AES encryption key schedule
    if (AES_create_key(key, keySizeInBits, &AesKey) != 0)
        FAIL(FATAL_ERROR_INTERNAL);

    for(; dSize > 0; dSize -= 16)
    {
        // Encrypt the IV into the temp buffer
        AES_encrypt(iv, tmp, AesKey);
        pT = tmp;
        pIv = iv;
        for(i = (dSize < 16) ? dSize : 16; i > 0; i--)
            // Copy the current cipher text to IV, XOR
            // with the temp buffer and put into the output
            *dOut++ = *pT++ ^ (*pIv++ = *dIn++);
    }
    // If the inner loop (i loop) was smaller than 16, then dSize
    // would have been smaller than 16 and it is now negative
    // If it is negative, then it indicates how may fill bytes
    // are needed to pad out the IV for the next round.
    for(; dSize < 0; dSize++)
        *pIv++ = 0;

    // destroy AES encrypt key schedule
    if(AES_destroy_key(AesKey) != 0)
        FAIL(FATAL_ERROR_INTERNAL);

    return CRYPT_SUCCESS;
}

//*** _cpri__AESEncryptCTR()
// This function performs AES encryption/decryption in CTR chain mode.
// The dIn buffer is encrypted into dOut. 
// The input iv buffer is assumed to have a size equal to the AES block 
// size (16 bytes). The iv will be incremented by the number of blocks
// (full and partial) that were encrypted. 
//
// return type: CRYPT_RESULT
//      CRYPT_SUCCESS          no non-fatal errors
//
CRYPT_RESULT
_cpri__AESEncryptCTR(
    __in_ecount(dInSize) BYTE        *dOut,          // OUT: the encrypted data
    UINT32       keySizeInBits, // IN: key size in bits
    BYTE        *key,           // IN: key buffer. The size of this buffer
                                //     in bytes is (keySizeInBits + 7) / 8
    BYTE        *iv,            // IN/OUT: IV for decryption.
    UINT32       dInSize,       // IN: data size
    BYTE        *dIn            // IN: data buffer
)
{
    BYTE         tmp[16];
    BYTE        *pT;
    PVOID        AesKey;
    int          i;
    INT32        dSize;

    pAssert(dOut != NULL && key != NULL && iv != NULL && dIn != NULL);

    if(dInSize == 0)
        return CRYPT_SUCCESS;

    pAssert(dInSize <= INT32_MAX);
    dSize = (INT32)dInSize;

    // Create AES encryption schedule
    if (AES_create_key(key, keySizeInBits, &AesKey) != 0)
        FAIL(FATAL_ERROR_INTERNAL);

    for(; dSize > 0; dSize -= 16)
    {
        // Encrypt the current value of the IV(counter)
        AES_encrypt(iv, (BYTE *)tmp, AesKey);

        //increment the counter (counter is big-endian so start at end)
        for(i = 15; i >= 0; i--)
            if((iv[i] += 1) != 0)
                break;

        // XOR the encrypted counter value with input and put into output
        pT = tmp;
        for(i = (dSize < 16) ? dSize : 16; i > 0; i--)
            *dOut++ = *dIn++ ^ *pT++;
    }

    // destroy AES encrypt key schedule
    if(AES_destroy_key(AesKey) != 0)
        FAIL(FATAL_ERROR_INTERNAL);

    return CRYPT_SUCCESS;
}


//*** _cpri__AESDecryptCTR()
// Counter mode decryption uses the same algorithm as encryption.
// The _cpri__AESDecryptCTR function is implemented as a macro call
// to _cpri__AESEncryptCTR.
//(skip)
//% #define _cpri__AESDecryptCTR(dOut, keySize, key, iv, dInSize, dIn) \
//%         _cpri__AESEncryptCTR(                           \
//%                              ((BYTE *)dOut),            \
//%                              ((UINT32)keySize),         \
//%                              ((BYTE *)key),             \
//%                              ((BYTE *)iv),              \
//%                              ((UINT32)dInSize),         \
//%                              ((BYTE *)dIn)              \
//%                             )
//%
// The //% is used by the prototype extraction program to cause it to include the
// line in the prototype file after removing the //%.  Need an extra line with
// nothing on it so that a blank line will separate this macro from the next
// definition.


//*** _cpri__AESEncryptECB()
// AES encryption in ECB mode.
// The 'data' buffer is modified to contain the cipher text.
//
// return type: CRYPT_RESULT
//      CRYPT_SUCCESS          no non-fatal errors
//
CRYPT_RESULT
_cpri__AESEncryptECB(
    BYTE        *dOut,          // OUT: encrypted data
    UINT32       keySizeInBits, // IN: key size in bit
    BYTE        *key,           // IN: key buffer. The size of this buffer
                                //     in bytes is (keySizeInBits + 7) / 8
    UINT32       dInSize,       // IN: data size
    BYTE        *dIn            // IN: clear text buffer
)
{
    PVOID      AesKey;
    INT32        dSize;

    pAssert(dOut != NULL && key != NULL && dIn != NULL);

    if(dInSize == 0)
        return CRYPT_SUCCESS;

    pAssert(dInSize <= INT32_MAX);
    dSize = (INT32)dInSize;

    // For ECB, the data size must be an even multiple of the
    // cipher block size
    if((dSize % 16) != 0)
        return CRYPT_PARAMETER;
    // Create AES encrypting key schedule
    if (AES_create_key(key, keySizeInBits, &AesKey) != 0)
        FAIL(FATAL_ERROR_INTERNAL);

    for(; dSize > 0; dSize -= 16)
    {
        AES_encrypt(dIn, dOut, AesKey);
        dIn = &dIn[16];
        dOut = &dOut[16];
    }

    // destroy AES encrypt key schedule
    if(AES_destroy_key(AesKey) != 0)
        FAIL(FATAL_ERROR_INTERNAL);

    return CRYPT_SUCCESS;
}


//*** _cpri__AESDecryptECB()
// This function performs AES decryption using ECB (not recommended). 
// The cipher text 'dIn' is decrypted into 'dOut'.
//
// return type: CRYPT_RESULT
//      CRYPT_SUCCESS          no non-fatal errors
//
CRYPT_RESULT
_cpri__AESDecryptECB(
    BYTE       *dOut,           // OUT: the clear text data
    UINT32      keySizeInBits,  // IN: key size in bit
    BYTE       *key,            // IN: key buffer. The size of this buffer
                                //     in bytes is (keySizeInBits + 7) / 8
    UINT32      dInSize,        // IN: data size
    BYTE       *dIn             // IN: cipher text buffer
)
{
    PVOID      AesKey;
    INT32        dSize;

    pAssert(dOut != NULL && key != NULL && dIn != NULL);

    if(dInSize == 0)
        return CRYPT_SUCCESS;

    pAssert(dInSize <= INT32_MAX);
    dSize = (INT32)dInSize;

    // For ECB, the data size must be an even multiple of the
    // cipher block size
    if((dSize % 16) != 0)
        return CRYPT_PARAMETER;

    // Create AES decryption key schedule
    if (AES_create_key(key, keySizeInBits, &AesKey) != 0)
        FAIL(FATAL_ERROR_INTERNAL);

    for(; dSize > 0; dSize -= 16)
    {
        AES_decrypt(dIn, dOut, AesKey);
        dIn = &dIn[16];
        dOut = &dOut[16];
    }

    // destroy AES encrypt key schedule
    if(AES_destroy_key(AesKey) != 0)
        FAIL(FATAL_ERROR_INTERNAL);

    return CRYPT_SUCCESS;
}


//*** _cpri__AESEncryptOFB()
// This function performs AES encryption/decryption in OFB chain mode.
// The 'dIn' buffer is modified to contain the encrypted/decrypted text.
//
// The input iv buffer is assumed to have a size equal to the block
// size (16 bytes). The returned value of 'iv' will be the nth encryption
// of the IV, where n is the number of blocks (full or partial) in the
// data stream.
//
// return type: CRYPT_RESULT
//      CRYPT_SUCCESS          no non-fatal errors
//
CRYPT_RESULT
_cpri__AESEncryptOFB(
    __in_ecount(dInSize) BYTE        *dOut,          // OUT: the encrypted/decrypted data
    UINT32       keySizeInBits, // IN: key size in bit
    BYTE        *key,           // IN: key buffer. The size of this buffer
                                //     in bytes is (keySizeInBits + 7) / 8
    BYTE        *iv,            // IN/OUT: IV for decryption. The size of
                                //     this buffer if 16 byte.
    UINT32       dInSize,       // IN: data size
    BYTE        *dIn            // IN: data buffer
)
{
    BYTE        *pIv;
    PVOID      AesKey;
    INT32        dSize;
    int          i;

    pAssert(dOut != NULL && key != NULL && iv != NULL && dIn != NULL);

    if(dInSize == 0)
        return CRYPT_SUCCESS;

    pAssert(dInSize <= INT32_MAX);
    dSize = (INT32)dInSize;

    // Create AES key schedule
    if (AES_create_key(key, keySizeInBits, &AesKey) != 0)
        FAIL(FATAL_ERROR_INTERNAL);

    // This is written so that dIn and dOut may be the same

    for(; dSize > 0; dSize -= 16)
    {
        // Encrypt the current value of the "IV"
        AES_encrypt(iv, iv, AesKey);

        // XOR the encrypted IV into dIn to create the cipher text (dOut)
        pIv = iv;
        for(i = (dSize < 16) ? dSize : 16; i > 0; i--)
            *dOut++ = (*pIv++ ^ *dIn++);
    }

    // destroy AES encrypt key schedule
    if(AES_destroy_key(AesKey) != 0)
        FAIL(FATAL_ERROR_INTERNAL);

    return CRYPT_SUCCESS;
}

