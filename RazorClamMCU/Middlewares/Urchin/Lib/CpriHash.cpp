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

#include    "stdafx.h"

const HASH_INFO g_hashData[HASH_COUNT + 1] = {
#if   ALG_SHA1 == YES
    { TPM_ALG_SHA1, SHA1_DIGEST_SIZE, SHA1_BLOCK_SIZE, SHA1_DER_SIZE, SHA1_DER},
#endif
#if   ALG_SHA256 == YES
    { TPM_ALG_SHA256, SHA256_DIGEST_SIZE, SHA256_BLOCK_SIZE, SHA256_DER_SIZE, SHA256_DER},
#endif
#if   ALG_SHA384 == YES
    { TPM_ALG_SHA384, SHA384_DIGEST_SIZE, SHA384_BLOCK_SIZE, SHA384_DER_SIZE, SHA384_DER},
#endif
#if   ALG_SHA512 == YES
    { TPM_ALG_SHA512, SHA512_DIGEST_SIZE, SHA512_BLOCK_SIZE, SHA512_DER_SIZE, SHA512_DER},
#endif
#if   ALG_SM3_256 == YES
    { TPM_ALG_SM3_256, SM3_256_DIGEST_SIZE, SM3_256_BLOCK_SIZE, SM3_256_DER_SIZE, SM3_256_DER},
#endif
    { TPM_ALG_NULL, 0, 0, 0, { 0 }}
};

UINT32
GetHashIndex(
TPM_ALG_ID   hashAlg
)
{
    UINT32 i, tableSize;

    // Get the table size of g_hashData
    tableSize = sizeof(g_hashData) / sizeof(g_hashData[0]);

    for (i = 0; i < tableSize - 1; i++)
    {
        if (g_hashData[i].alg == hashAlg)
            return i;
    }
    return tableSize - 1;
}

//*** GetHashInfoPointer()
// This function returns a pointer to the hash info for the algorithm. If the 
// algorithm is not supported, function returns a pointer to the data block
// associated with TPM_ALG_NULL.
const HASH_INFO *
GetHashInfoPointer(
    TPM_ALG_ID   hashAlg
)
{
    return &g_hashData[GetHashIndex(hashAlg)];
}

//** Hash Functions

//*** _cpri__GetHashAlgByIndex()
// This function is used to iterate through the hashes. TPM_ALG_NULL
// is returned for all indexes that are not valid hashes.
// If the TPM implements 3 hashes, then an 'index' value of 0 will
// return the first implemented hash and and 'index' of 2 will return the
// last. All other index values will return TPM_ALG_NULL.
//
// return type: TPM_ALG_ID
//  TPM_ALG_xxx         a hash algorithm
//  TPM_ALG_NULL        this can be used as a stop value
TPM_ALG_ID
_cpri__GetHashAlgByIndex(
    UINT32      index       // IN: the index
)
{
    if(index >= HASH_COUNT)
        return TPM_ALG_NULL;
    return g_hashData[index].alg;
}

//*** _cpri__GetHashBlockSize()
// Returns the size of the block used for the hash
//
// return type: CRYPT_RESULT
//  < 0     the algorithm is not a supported hash
//  >=      the digest size (0 for TPM_ALG_NULL)
//
UINT16
_cpri__GetHashBlockSize(
    TPM_ALG_ID  hashAlg     // IN: hash algorithm to look up
)
{
    return GetHashInfoPointer(hashAlg)->blockSize;
}

//*** _cpri__GetDigestSize()
// Gets the digest size of the algorithm. The algorithm is required to be 
// supported.
//
// return type: UINT16
//  =0      the digest size for TPM_ALG_NULL
//  >0      the digest size of a hash algorithm
//
UINT16
_cpri__GetDigestSize(
    TPM_ALG_ID  hashAlg     // IN: hash algorithm to look up
)
{
    return GetHashInfoPointer(hashAlg)->digestSize;
}

//*** _cpri__GetContextAlg()
// This function returns the algorithm associated with a hash context
TPM_ALG_ID
_cpri__GetContextAlg(
    CPRI_HASH_STATE         *hashState  // IN: the hash context
)
{
    return hashState->hashAlg;
}
