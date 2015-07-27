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


//*** _cpri__GetHashDER
// This function returns a pointer to the DER string for the algorithm and
// indicates its size.
UINT16
_cpri__GetHashDER(
    TPM_ALG_ID             hashAlg,    // IN: the algorithm to look up
    const BYTE           **p
)
{
    const HASH_INFO       *q;
    q = GetHashInfoPointer(hashAlg);
    *p = &q->der[0];
    return q->derSize;
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

//** HMAC Functions

//*** _cpri__StartHMAC
// This function is used to start an HMAC using a temp
// hash context. The function does the initialization
// of the hash with the HMAC key XOR iPad and updates the
// HMAC key XOR oPad.
//
// The function returns the number of bytes in a digest produced by 'hashAlg'.
// return type: UINT16
//  >= 0        number of bytes in digest produced by 'hashAlg' (may be zero)
//
UINT16
_cpri__StartHMAC(
    TPM_ALG_ID       hashAlg,   // IN: the algorithm to use
    BOOL             sequence,  // IN: indicates if the state should be saved
    CPRI_HASH_STATE *state,     // IN/OUT: the state buffer
    UINT16           keySize,   // IN: the size of the HMAC key
    BYTE            *key,       // IN: the HMAC key
    TPM2B           *oPadKey    // OUT: the key prepared for the oPad round
)
{
    CPRI_HASH_STATE  localState;
    UINT16           blockSize = _cpri__GetHashBlockSize(hashAlg);
    UINT16           digestSize;
    BYTE            *pb;        // temp pointer
    UINT32           i;

    // If the key size is larger than the block size, then the hash of the key
    // is used as the key
    if(keySize > blockSize)
    {
        // large key so digest
        if((digestSize = _cpri__StartHash(hashAlg, FALSE, &localState)) == 0)
            return 0;
        _cpri__UpdateHash(&localState, keySize, key);
        _cpri__CompleteHash(&localState, digestSize, oPadKey->buffer);
        oPadKey->size = digestSize;
    }
    else
    {
        // key size is ok
        memcpy(oPadKey->buffer, key, keySize);
        oPadKey->size = keySize;
    }
    // XOR the key with iPad (0x36)
    pb = oPadKey->buffer;
    for(i = oPadKey->size; i > 0; i--)
        *pb++ ^= 0x36;

    // if the keySize is smaller than a block, fill the rest with 0x36
    for(i = blockSize - oPadKey->size; i >  0; i--)
        *pb++ = 0x36;

    // Increase the oPadSize to a full block
    oPadKey->size = blockSize;

    // Start a new hash with the HMAC key
    // This will go in the caller's state structure and may be a sequence or not

    if((digestSize = _cpri__StartHash(hashAlg, sequence, state)) > 0)
    {

        _cpri__UpdateHash(state, oPadKey->size, oPadKey->buffer);

        // XOR the key block with 0x5c ^ 0x36
        for(pb = oPadKey->buffer, i = blockSize; i > 0; i--)
            *pb++ ^= (0x5c ^ 0x36);
    }

    return digestSize;
}

//*** _cpri_CompleteHMAC()
// This function is called to complete an HMAC. It will finish the current
// digest, and start a new digest. It will then add the oPadKey and the
// completed digest and return the results in dOut. It will not return more
// than dOutSize bytes.
// return type: UINT16
//  >= 0        number of bytes in 'dOut' (may be zero)
UINT16
_cpri__CompleteHMAC(
    CPRI_HASH_STATE     *hashState,     // IN: the state of hash stack
    TPM2B               *oPadKey,       // IN: the HMAC key in oPad format
    UINT32               dOutSize,      // IN: size of digest buffer
    BYTE                *dOut           // OUT: hash digest
)
{
    BYTE             digest[MAX_DIGEST_SIZE];
    CPRI_HASH_STATE *state = (CPRI_HASH_STATE *)hashState;
    CPRI_HASH_STATE  localState;
    UINT16           digestSize = _cpri__GetDigestSize(state->hashAlg);


    _cpri__CompleteHash(hashState, digestSize, digest);

    // Using the local hash state, do a hash with the oPad
    if(_cpri__StartHash(state->hashAlg, FALSE, &localState) != digestSize)
        return 0;

    _cpri__UpdateHash(&localState, oPadKey->size, oPadKey->buffer);
    _cpri__UpdateHash(&localState, digestSize, digest);
    return _cpri__CompleteHash(&localState, dOutSize, dOut);
}


//** Mask and Key Generation Functions
//*** _crypi_MGF1()
// This function performs MGF1 using the selected hash. MGF1 is
// T(n) = T(n-1) || H(seed || counter).
// This function returns the length of the mask produced which
// could be zero if the digest algorithm is not supported
// return type: CRYPT_RESULT
//      0       hash algorithm not supported
//    > 0       should be the same as 'mSize'
CRYPT_RESULT
_cpri__MGF1(
    UINT32      mSize,     // IN: length of the mask to be produced
    __in_ecount(mSize) BYTE       *mask,      // OUT: buffer to receive the mask
    TPM_ALG_ID  hashAlg,   // IN: hash to use
    UINT32      sSize,     // IN: size of the seed
    BYTE       *seed       // IN: seed size
)
{
    CPRI_HASH_STATE      hashState = { 0 };
    CRYPT_RESULT         retVal = 0;
    BYTE                 b[MAX_DIGEST_SIZE]; // temp buffer in case mask is not an
    // even multiple of a full digest
    CRYPT_RESULT         dSize = _cpri__GetDigestSize(hashAlg);
    unsigned int         digestSize = (UINT32)dSize;
    UINT32               remaining;
    UINT32               counter;
    BYTE                 swappedCounter[4];

    // Parameter check
    if(mSize > (1024*16)) // Semi-arbitrary maximum
        FAIL(FATAL_ERROR_INTERNAL);

    // If there is no digest to compute return
    if(dSize <= 0)
        return 0;

    for(counter = 0, remaining = mSize; remaining > 0; counter++)
    {
        // Because the system may be either Endian...
        UINT32_TO_BYTE_ARRAY(counter, swappedCounter);

        // Start the hash and include the seed and counter
        if(_cpri__StartHash(hashAlg, FALSE, &hashState) == 0)
            FAIL(FATAL_ERROR_INTERNAL);
        _cpri__UpdateHash(&hashState, sSize, seed);
        _cpri__UpdateHash(&hashState, 4, swappedCounter);

        // Handling the completion depends on how much space remains in the mask
        // buffer. If it can hold the entire digest, put it there. If not
        // put the digest in a temp buffer and only copy the amount that
        // will fit into the mask buffer.
        if(remaining < (unsigned)dSize)
        {
            if ((digestSize = _cpri__CompleteHash(&hashState, sizeof(b), b)) == 0)
                FAIL(FATAL_ERROR_INTERNAL);
            #pragma prefast(suppress: 26000, "Validated that remaining < sizeof(b).")
            memcpy(mask, b, remaining);
            break;
        }
        else
        {
            if ((digestSize = _cpri__CompleteHash(&hashState, remaining, mask)) == 0)
                FAIL(FATAL_ERROR_INTERNAL);
            remaining -= dSize;
            mask = &mask[dSize];
        }
        retVal = (CRYPT_RESULT)mSize;
    }

    return retVal;
}


//*** _cpri_KDFa()
// This function performs the key generation according to Part 1 of the
// TPM specification.
//
// This function returns the number of bytes generated which may be zero.
//
// The 'key' and 'keyStream' pointers are not allowed to be NULL. The other
// pointer values may be NULL. The value of 'sizeInBits' must be no larger
// than (2^18)-1 = 256K bits (32385 bytes).
//
// The "once" parameter is set to allow incremental generation of a large
// value. If this flag is TRUE, "sizeInBits" will be used in the HMAC computation
// but only one iteration of the KDF is performed. This would be used for
// XOR obfuscation so that the mask value can be generated in digest-sized
// chunks rather than having to be generated all at once in an arbitrarily
// large buffer and then XORed into the result. If "once" is TRUE, then
// "sizeInBits" must be a multiple of 8.
//
// Any error in the processing of this command is considered fatal.
//  return type: CRYPT_RESULT
//     0            hash algorithm is not supported or is TPM_ALG_NULL
//    > 0           the number of bytes in the 'keyStream' buffer
UINT16
_cpri__KDFa(
    TPM_ALG_ID   hashAlg,       // IN: hash algorithm used in HMAC
    TPM2B       *key,           // IN: HMAC key
    const char  *label,         // IN: a 0-byte terminated label used in KDF
    TPM2B       *contextU,      // IN: context U
    TPM2B       *contextV,      // IN: context V
    UINT32       sizeInBits,    // IN: size of generated key in bits
    BYTE        *keyStream,     // OUT: key buffer
    UINT32      *counterInOut,  // IN/OUT: caller may provide the iteration counter
                                //         for incremental operations to avoid
                                //         large intermediate buffers.
    BOOL         once           // IN: TRUE if only one iteration is performed
                                //     FALSE if iteration count determined by
                                //     "sizeInBits"
)
{
    UINT32                   counter = 0;    // counter value
    INT32                    lLen = 0;       // length of the label
    INT16                    hLen;           // length of the hash
    INT16                    bytes;          // number of bytes to produce
    BYTE                    *stream = keyStream;
    BYTE                     marshaledUint32[4];
    CPRI_HASH_STATE          hashState;
    TPM2B_MAX_HASH_BLOCK     hmacKey;

    pAssert(key != NULL && keyStream != NULL);
    pAssert(once == FALSE || (sizeInBits & 7) == 0);

    if(counterInOut != NULL)
        counter = *counterInOut;

    // Prepare label buffer.  Calculate its size and keep the last 0 byte
    if(label != NULL)
        for(lLen = 0; label[lLen++] != 0; );

    // Get the hash size.  If it is less than or 0, either the
    // algorithm is not supported or the hash is TPM_ALG_NULL
    // In either case the digest size is zero.  This is the only return
    // other than the one at the end. All other exits from this function
    // are fatal errors. After we check that the algorithm is supported
    // anything else that goes wrong is an implementation flaw.
    if((hLen = (INT16) _cpri__GetDigestSize(hashAlg)) == 0)
        return 0;

    // If the size of the request is larger than the numbers will handle,
    // it is a fatal error.
    pAssert(((sizeInBits + 7)/ 8) <= INT16_MAX);

    bytes = once ? hLen : (INT16)((sizeInBits + 7) / 8);

    // Generate required bytes
    for (; bytes > 0; stream = &stream[hLen], bytes = bytes - hLen)
    {
        if(bytes < hLen)
            hLen = bytes;

        counter++;
        // Start HMAC
        if(_cpri__StartHMAC(hashAlg,
                            FALSE,
                            &hashState,
                            key->size,
                            &key->buffer[0],
                            &hmacKey.b)         <= 0)
            FAIL(FATAL_ERROR_INTERNAL);

        // Adding counter
        UINT32_TO_BYTE_ARRAY(counter, marshaledUint32);
        _cpri__UpdateHash(&hashState, sizeof(UINT32), marshaledUint32);

        // Adding label
        if(label != NULL)
            _cpri__UpdateHash(&hashState,  lLen, (BYTE *)label);

        // Adding contextU
        if(contextU != NULL)
            _cpri__UpdateHash(&hashState, contextU->size, contextU->buffer);

        // Adding contextV
        if(contextV != NULL)
            _cpri__UpdateHash(&hashState, contextV->size, contextV->buffer);

        // Adding size in bits
        UINT32_TO_BYTE_ARRAY(sizeInBits, marshaledUint32);
        _cpri__UpdateHash(&hashState, sizeof(UINT32), marshaledUint32);

        // Compute HMAC. At the start of each iteration, hLen is set
        // to the smaller of hLen and bytes. This causes bytes to decrement
        // exactly to zero to complete the loop
        _cpri__CompleteHMAC(&hashState, &hmacKey.b, hLen, stream);
    }

    // Mask off bits if the required bits is not a multiple of byte size
    if((sizeInBits % 8) != 0)
        keyStream[0] &= ((1 << (sizeInBits % 8)) - 1);
    if(counterInOut != NULL)
        *counterInOut = counter;
    return (CRYPT_RESULT)((sizeInBits + 7)/8);
}


//*** _cpri__KDFe()
// KDFe as defined in TPM specification part 1.
//
// This function returns the number of bytes generated which may be zero.
//
// The 'Z' and 'keyStream' pointers are not allowed to be NULL. The other
// pointer values may be NULL. The value of 'sizeInBits' must be no larger
// than (2^18)-1 = 256K bits (32385 bytes).
// Any error in the processing of this command is considered fatal.
//  return type: CRYPT_RESULT
//     0            hash algorithm is not supported or is TPM_ALG_NULL
//    > 0           the number of bytes in the 'keyStream' buffer
//
UINT16
_cpri__KDFe(
    TPM_ALG_ID       hashAlg,           // IN: hash algorithm used in HMAC
    TPM2B           *Z,                 // IN: Z
    const char      *label,             // IN: a 0 terminated label using in KDF
    TPM2B           *partyUInfo,        // IN: PartyUInfo
    TPM2B           *partyVInfo,        // IN: PartyVInfo
    UINT32           sizeInBits,        // IN: size of generated key in bits
    BYTE            *keyStream          // OUT: key buffer
)
{
    UINT32       counter = 0;       // counter value
    UINT32       lSize = 0;
    BYTE        *stream = keyStream;
    CPRI_HASH_STATE         hashState;
    INT16        hLen = (INT16) _cpri__GetDigestSize(hashAlg);
    INT16        bytes;             // number of bytes to generate
    BYTE         marshaledUint32[4];

    pAssert(   keyStream != NULL
               && Z != NULL
               && ((sizeInBits + 7) / 8) < INT16_MAX);

    if(hLen == 0)
        return 0;

    bytes = (INT16)((sizeInBits + 7) / 8);

    // Prepare label buffer.  Calculate its size and keep the last 0 byte
    if(label != NULL)
        for(lSize = 0; label[lSize++] != 0;);

    // Generate required bytes
    //The inner loop of that KDF uses:
    //  Hashi := H(counter | Z | OtherInfo) (5)
    // Where:
    //  Hashi   the hash generated on the i-th iteration of the loop.
    //  H()     an approved hash function
    //  counter a 32-bit counter that is initialized to 1 and incremented
    //          on each iteration
    //  Z       the X coordinate of the product of a public ECC key and a
    //          different private ECC key.
    //  OtherInfo   a collection of qualifying data for the KDF defined below.
    //  In this specification, OtherInfo will be constructed by:
    //      OtherInfo := Use | PartyUInfo  | PartyVInfo
    for (; bytes > 0; stream = &stream[hLen], bytes = bytes - hLen)
    {
        if(bytes < hLen)
            hLen = bytes;

        counter++;
        // Start hash
        if(_cpri__StartHash(hashAlg, FALSE,  &hashState) == 0)
            return 0;

        // Add counter
        UINT32_TO_BYTE_ARRAY(counter, marshaledUint32);
        _cpri__UpdateHash(&hashState, sizeof(UINT32), marshaledUint32);

        // Add Z
        if(Z != NULL)
            _cpri__UpdateHash(&hashState, Z->size, Z->buffer);

        // Add label
        if(label != NULL)
            _cpri__UpdateHash(&hashState, lSize, (BYTE *)label);
        else

            // The SP800-108 specification requires a zero between the label
            // and the context.
            _cpri__UpdateHash(&hashState, 1, (BYTE *)"");

        // Add PartyUInfo
        if(partyUInfo != NULL)
            _cpri__UpdateHash(&hashState, partyUInfo->size, partyUInfo->buffer);

        // Add PartyVInfo
        if(partyVInfo != NULL)
            _cpri__UpdateHash(&hashState, partyVInfo->size, partyVInfo->buffer);

        // Compute Hash. hLen was changed to be the smaller of bytes or hLen
        // at the start of each iteration.
        _cpri__CompleteHash(&hashState, hLen, stream);
    }

    // Mask off bits if the required bits is not a multiple of byte size
    if((sizeInBits % 8) != 0)
        keyStream[0] &= ((1 << (sizeInBits % 8)) - 1);

    return (CRYPT_RESULT)((sizeInBits + 7) / 8);

}
