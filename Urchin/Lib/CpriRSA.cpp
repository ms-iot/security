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
// This file contains implementation of crypto primitives for RSA. This is a
// simulator of a crypto engine.
// Vendors may replace the implementation in this file with their own library
// functions.
//
// Integer format: the big integers passed in/out to the function interfaces in
// this library adopt the same format used
// in TPM 2.0 specification: Integer values are considered to be an array of
// one or more bytes.  The byte at offset zero within the array is the most
// significant byte of the integer. The interface uses TPM2B as a  big number
// format for numeric values passed to/from CryptUtil.
//

//**  Includes
#include "stdafx.h"

CRYPT_RESULT
RSAEP(
    UINT32       dInOutSize,  // OUT size of the encrypted block
    BYTE        *dInOut,      // OUT: the encrypted data
    RSA_KEY     *key          // IN: the key to use
);

CRYPT_RESULT
RSADP(
    UINT32           dInOutSize,    // IN/OUT: size of decrypted data
    BYTE            *dInOut,        // IN/OUT: the decrypted data
    RSA_KEY         *key            // IN: the key
);

//*** OaepEncode()
// This function performs OAEP padding. The size of the buffer to receive the
// OAEP padded data must equal the size of the modulus
//
// return type: CRYPT_RESULT
//  CRYPT_SUCCESS       encode successful
//  CRYPT_PARAMETER     'hashAlg' is not valid
//  CRYPT_FAIL          message size is too large
//
static CRYPT_RESULT
OaepEncode(
    UINT32       paddedSize,    // IN: pad value size
    BYTE        *padded,        // OUT: the pad data
    TPM_ALG_ID   hashAlg,       // IN: algorithm to use for padding
    const char  *label,         // IN: null-terminated string (may be NULL)
    UINT32       messageSize,   // IN: the message size
    BYTE        *message        // IN: the message being padded
#ifdef  TEST_RSA                //
    ,  BYTE        *testSeed    // IN: optional seed used for testing.
#endif  // TEST_RSA             //
)
{
    UINT32       padLen;
    UINT32       dbSize;
    UINT32       i;
    BYTE         mySeed[MAX_DIGEST_SIZE];
    BYTE        *seed = mySeed;
    INT32        hLen = _cpri__GetDigestSize(hashAlg);
    BYTE         mask[MAX_RSA_KEY_BYTES];
    BYTE        *pp;
    BYTE        *pm;
    UINT32       lSize = 0;
    CRYPT_RESULT retVal = CRYPT_SUCCESS;


    pAssert(padded != NULL && message != NULL);

    // A value of zero is not allowed because the KDF can't produce a result
    // if the digest size is zero.
    if(hLen <= 0)
        return CRYPT_PARAMETER;

    // If a label is provided, get the length of the string, including the 
    // terminator
    if(label != NULL)
        lSize = (UINT32)strlen(label) + 1;

    // Basic size check
    // messageSize <= k  2hLen  2
    if(messageSize > paddedSize - 2 * hLen - 2)
        return CRYPT_FAIL;

    // Hash L even if it is null
    // Offset into padded leaving room for masked seed and byte of zero
    pp = &padded[hLen + 1];
    retVal = _cpri__HashBlock(hashAlg, lSize, (BYTE *)label, hLen, pp);

    // concatenate PS of k  mLen  2hLen  2
    padLen = paddedSize - messageSize - (2 * hLen) - 2;
    memset(&pp[hLen], 0, padLen);
    pp[hLen+padLen] = 0x01;
    padLen += 1;
    memcpy(&pp[hLen+padLen], message, messageSize);

    // The total size of db = hLen + pad + mSize;
    dbSize = hLen+padLen+messageSize;

    // If testing, then use the provided seed. Otherwise, use values
    // from the RNG
#ifdef  TEST_RSA
    if(testSeed != NULL)
        seed = testSeed;
    else
#endif  // TEST_RSA
        _cpri__GenerateRandom(hLen, mySeed);

    // mask = MGF1 (seed, nSize  hLen  1)
    if((retVal = _cpri__MGF1(dbSize, mask,  hashAlg, hLen, seed)) < 0)
        return retVal; // Don't expect an error because hash size is not zero
                       // was detected in the call to _cpri__HashBlock() above.

    // Create the masked db
    pm = mask;
    for(i = dbSize; i > 0; i--)
        *pp++ ^= *pm++;
    pp = &padded[hLen + 1];

    // Run the masked data through MGF1
    if((retVal = _cpri__MGF1(hLen, &padded[1],  hashAlg, dbSize, pp)) < 0)
        return retVal; // Don't expect zero here as the only case for zero
                       // was detected in the call to _cpri__HashBlock() above.

    // Now XOR the seed to create masked seed
    pp = &padded[1];
    pm = seed;
    for(i = hLen; i > 0; i--)
        *pp++ ^= *pm++;

    // Set the first byte to zero
    *padded = 0x00;
    return CRYPT_SUCCESS;
}

//*** OaepDecode()
// This function performs OAEP padding checking. The size of the buffer to receive
// the recovered data. If the padding is not valid, the 'dSize' size is set to zero
// and the function returns CRYPT_NO_RESULTS.
//
// The 'dSize' parameter is used as an input to indicate the size available in the
// buffer.

// If insufficient space is available, the size is not changed and the return code
// is CRYPT_FAIL.
//
//  return type:    CRYPT_RESULT
//      CRYPT_SUCCESS       decode complete
//      CRYPT_PARAMETER     the value to decode was larger than the modulus
//      CRYPT_FAIL          the padding is wrong or the buffer to receive the
//                          results is too small
//
//
static CRYPT_RESULT
OaepDecode(
    UINT32      *dataOutSize,   // IN/OUT: the recovered data size
    BYTE        *dataOut,       // OUT: the recovered data
    TPM_ALG_ID   hashAlg,       // IN: algorithm to use for padding
    const char  *label,         // IN: null-terminated string (may be NULL)
    UINT32       paddedSize,    // IN: the size of the padded data
    BYTE        *padded         // IN: the padded data
)
{
    UINT32       dSizeSave;
    UINT32       i;
    BYTE         seedMask[MAX_DIGEST_SIZE];
    INT32        hLen = _cpri__GetDigestSize(hashAlg);

    BYTE         mask[MAX_RSA_KEY_BYTES];
    BYTE        *pp;
    BYTE        *pm;
    UINT32       lSize = 0;
    CRYPT_RESULT retVal = CRYPT_SUCCESS;

    // Unknown hash
    pAssert(hLen > 0 && dataOutSize != NULL && dataOut != NULL && padded != NULL);

    // If there is a label, get its size including the terminating 0x00
    if(label != NULL)
        lSize = (UINT32)strlen(label) + 1;

    // Set the return size to zero so that it doesn't have to be done on each
    // failure
    dSizeSave = *dataOutSize;
    *dataOutSize = 0;

    // Strange size (anything smaller can't be an OAEP padded block)
    // Also check for no leading 0
    if(paddedSize < (unsigned)((2 * hLen) + 2) || *padded != 0)
        return CRYPT_FAIL;

    // Use the hash size to determine what to put through MGF1 in order
    // to recover the seedMask
    if((retVal = _cpri__MGF1(hLen, seedMask,  hashAlg,
                             paddedSize-hLen-1, &padded[hLen+1])) < 0)
        return retVal;

    // Recover the seed into seedMask
    pp = &padded[1];
    pm = seedMask;
    for(i = hLen; i > 0; i--)
        *pm++ ^= *pp++;

    // Use the seed to generate the data mask
    if((retVal = _cpri__MGF1(paddedSize-hLen-1, mask,  hashAlg,
                             hLen, seedMask)) < 0)
        return retVal;

    // Use the mask generated from seed to recover the padded data
    pp = &padded[hLen+1];
    pm = mask;
    for(i = paddedSize-hLen-1; i > 0; i--)
        *pm++ ^= *pp++;

    // Make sure that the recovered data has the hash of the label
    // Put trial value in the seed mask
    if((retVal=_cpri__HashBlock(hashAlg, lSize,(BYTE *)label, hLen, seedMask)) < 0)
        return retVal;

    if(memcmp(seedMask, mask, hLen) != 0)
        return CRYPT_FAIL;


    // find the start of the data
    pm = &mask[hLen];
    for(i = paddedSize-(2*hLen)-1; i > 0; i--)
    {
        if(*pm++ != 0)
            break;
    }
    if(i == 0)
        return CRYPT_PARAMETER;

    // pm should be pointing at the first part of the data
    // and i is one greater than the number of bytes to move
    i--;
    if(i > dSizeSave)
    {
        // Restore dSize
        *dataOutSize = dSizeSave;
        return CRYPT_FAIL;
    }
    memcpy(dataOut, pm, i);
    *dataOutSize = i;
    return CRYPT_SUCCESS;
}


//*** PKSC1v1_5Encode()
// This function performs the encoding for RSAES-PKCS1-V1_5-ENCRYPT as defined in
// PKCS#1V2.1
//
//  return type:    CRYPT_RESULT
//  CRYPT_SUCCESS       data encoded
//  CRYPT_PARAMETER     message size is too large
//
static CRYPT_RESULT
RSAES_PKSC1v1_5Encode(
    UINT32       paddedSize,    // IN: pad value size
    BYTE        *padded,        // OUT: the pad data
    UINT32       messageSize,   // IN: the message size
    BYTE        *message        // IN: the message being padded
)
{
    UINT32      ps = paddedSize - messageSize - 3;
    if(messageSize > paddedSize - 11)
        return CRYPT_PARAMETER;

    // move the message to the end of the buffer
    memcpy(&padded[paddedSize - messageSize], message, messageSize);

    // Set the first byte to 0x00 and the second to 0x02
    *padded = 0;
    padded[1] = 2;
    
    // Fill with random bytes
    _cpri__GenerateRandom(ps, &padded[2]);

    // Set the delimiter for the random field to 0
    padded[2+ps] = 0;

    // Now, the only messy part. Make sure that all the ps bytes are non-zero
    // In this implementation, use the value of the current index
    for(ps++; ps > 1; ps--)
    {
        if(padded[ps] == 0)
            padded[ps] = 0x55;    // In the < 0.5% of the cases that the random
                                  // value is 0, just pick a value to put into
                                  // the spot.
    }
    return CRYPT_SUCCESS;
}

//*** RSAES_Decode()
// This function performs the decoding for RSAES-PKCS1-V1_5-ENCRYPT as defined in
// PKCS#1V2.1
//
//  return type:    CRYPT_RESULT
//      CRYPT_SUCCESS   decode successful
//      CRYPT_FAIL      decoding error or results would no fit into provided buffer
//
static CRYPT_RESULT
RSAES_Decode(
    UINT32      *messageSize,    // IN/OUT: recovered message size
    BYTE        *message,        // OUT: the recovered message
    UINT32       codedSize,      // IN: the encoded message size
    BYTE        *coded           // IN: the encoded message
)
{
    BOOL        fail = FALSE;
    UINT32      ps;

    fail = (codedSize < 11);
    fail |= (coded[0] != 0x00) || (coded[1] != 0x02);
    for(ps = 2; ps < codedSize; ps++)
    {
        if(coded[ps] == 0)
            break;
    }
    ps++;

    // Make sure that ps has not gone over the end and that there are at least 8
    // bytes of pad data.
    fail |= ((ps >= codedSize) || ((ps-2) < 8));
    if((*messageSize < codedSize - ps) || fail)
        return CRYPT_FAIL;

    *messageSize = codedSize - ps;
    memcpy(message, &coded[ps], codedSize - ps);
    return CRYPT_SUCCESS;
}

//*** PssEncode()
// This function creates an encoded block of data that is the size of modulus.
// The function uses the maximum salt size that will fit in the encoded block.
//
//  return type:    CRYPT_RESULT
//      CRYPT_SUCCESS       encode successful
//      CRYPT_PARAMETER     "hashAlg" is not a supported hash algorithm
//
static CRYPT_RESULT
PssEncode   (
    UINT32       eOutSize,       // IN: size of the encode data buffer
    BYTE        *eOut,           // OUT: encoded data buffer
    TPM_ALG_ID   hashAlg,        // IN: hash algorithm to use for the encoding
    UINT32       hashInSize,     // IN: size of digest to encode
    BYTE        *hashIn          // IN: the digest
#ifdef TEST_RSA                  //
    ,  BYTE        *saltIn       // IN: optional parameter for testing
#endif // TEST_RSA               //
)
{
    INT32                hLen = _cpri__GetDigestSize(hashAlg);
    BYTE                 salt[MAX_RSA_KEY_BYTES - 1];
    UINT16               saltSize;
    BYTE                *ps = salt;
    CRYPT_RESULT         retVal;
    UINT16               mLen;
    CPRI_HASH_STATE      hashState;

    // These are fatal errors indicating bad TPM firmware
    pAssert(eOut != NULL && hLen > 0 && hashIn != NULL );

    // Get the size of the mask
    mLen = (UINT16)(eOutSize - hLen - 1);

    // Use the maximum salt size
    saltSize = mLen - 1;

//using eOut for scratch space
    // Set the first 8 bytes to zero
    memset(eOut, 0, 8);


    // Get set the salt
#ifdef  TEST_RSA
    if(saltIn != NULL)
    {
        saltSize = hLen;
        memcpy(salt, saltIn, hLen);
    }
    else
#endif  // TEST_RSA
        _cpri__GenerateRandom(saltSize, salt);

    // Create the hash of the pad || input hash || salt
    _cpri__StartHash(hashAlg, FALSE, &hashState);
    _cpri__UpdateHash(&hashState, 8, eOut);
    _cpri__UpdateHash(&hashState, hashInSize, hashIn);
    _cpri__UpdateHash(&hashState, saltSize, salt);
    _cpri__CompleteHash(&hashState, hLen, &eOut[eOutSize - hLen - 1]);

    // Create a mask
    if((retVal = _cpri__MGF1(mLen, eOut, hashAlg, hLen, &eOut[mLen])) < 0)
    {
        // Currently _cpri__MGF1 is not expected to return a CRYPT_RESULT error.
        pAssert(0);
        return retVal;
    }
    // Since this implementation uses key sizes that are all even multiples of
    // 8, just need to make sure that the most significant bit is CLEAR
    eOut[0] &= 0x7f;

    // Before we mess up the eOut value, set the last byte to 0xbc
    eOut[eOutSize - 1] = 0xbc;

    // XOR a byte of 0x01 at the position just before where the salt will be XOR'ed
    eOut = &eOut[mLen - saltSize - 1];
    *eOut++ ^= 0x01;

    // XOR the salt data into the buffer
    for(; saltSize > 0; saltSize--)
        *eOut++ ^= *ps++;

    // and we are done
    return CRYPT_SUCCESS;
}

//*** PssDecode()
// This function checks that the PSS encoded block was built from the
// provided digest. If the check is successful, CRYPT_SUCCESS is returned.
// Any other value indicates an error.
//
// This implementation of PSS decoding is intended for the reference TPM
// implementation and is not at all generalized.  It is used to check
// signatures over hashes and assumptions are made about the sizes of values.
// Those assumptions are enforce by this implementation.
// This implementation does allow for a variable size salt value to have been
// used by the creator of the signature.
//
//  return type:    CRYPT_RESULT
//      CRYPT_SUCCESS       decode successful
//      CRYPT_SCHEME        'hashAlg' is not a supported hash algorithm
//      CRYPT_FAIL          decode operation failed
//
static CRYPT_RESULT
PssDecode(
    TPM_ALG_ID   hashAlg,        // IN: hash algorithm to use for the encoding
    UINT32       dInSize,        // IN: size of the digest to compare
    BYTE        *dIn,            // In: the digest to compare
    UINT32       eInSize,        // IN: size of the encoded data
    BYTE        *eIn,            // IN: the encoded data
    UINT32       saltSize        // IN: the expected size of the salt
)
{
    INT32            hLen = _cpri__GetDigestSize(hashAlg);
    BYTE             mask[MAX_RSA_KEY_BYTES];
    BYTE            *pm = mask;
    BYTE             pad[8] = {0};
    UINT32           i;
    UINT32           mLen;
    BOOL             fail = FALSE;
    CRYPT_RESULT     retVal;
    CPRI_HASH_STATE  hashState;

    // These errors are indicative of failures due to programmer error
    pAssert(dIn != NULL && eIn != NULL);
    
    // check the hash scheme
    if(hLen == 0)
        return CRYPT_SCHEME;

    // most significant bit must be zero
    fail = ((eIn[0] & 0x80) != 0);

    // last byte must be 0xbc
    fail |= (eIn[eInSize - 1] != 0xbc);

    // Use the hLen bytes at the end of the buffer to generate a mask
    // Doesn't start at the end which is a flag byte
    mLen = eInSize - hLen - 1;
    if((retVal = _cpri__MGF1(mLen, mask, hashAlg, hLen, &eIn[mLen])) < 0)
        return retVal;
    if(retVal == 0)
        return CRYPT_FAIL;

    // Clear the MSO of the mask to make it consistent with the encoding.
    mask[0] &= 0x7F;

    // XOR the data into the mask to recover the salt. This sequence
    // advances eIn so that it will end up pointing to the seed data
    // which is the hash of the signature data
    for(i = mLen; i > 0; i--)
        *pm++ ^= *eIn++;

    // Find the first byte of 0x01 after a string of all 0x00
    for(pm = mask, i = mLen; i > 0; i--)
    {
        if(*pm == 0x01)
            break;
        else
            fail |= (*pm++ != 0);
    }
    fail |= (i == 0);

    // if we have failed, will continue using the entire mask as the salt value so
    // that the timing attacks will not disclose anything (I don't think that this
    // is a problem for TPM applications but, usually, we don't fail so this
    // doesn't cost anything).
    if(fail)
    {
        i = mLen;
        pm = mask;
    }
    else
    {
        pm++;
        i--;
    }
    // If the salt size was provided, then the recovered size must match
    fail |= (saltSize != 0 && i != saltSize);

    // i contains the salt size and pm points to the salt. Going to use the input
    // hash and the seed to recreate the hash in the lower portion of eIn.
    _cpri__StartHash(hashAlg, FALSE, &hashState);

    // add the pad of 8 zeros
    _cpri__UpdateHash(&hashState, 8, pad);

    // add the provided digest value
    _cpri__UpdateHash(&hashState, dInSize, dIn);

    // and the salt
    _cpri__UpdateHash(&hashState, i, pm);

    // get the result
    retVal = _cpri__CompleteHash(&hashState, MAX_DIGEST_SIZE, mask);

    // retVal will be the size of the digest or zero. If not equal to the indicated
    // digest size, then the signature doesn't match
    fail |= (retVal != hLen);
    fail |= (memcmp(mask, eIn, hLen) != 0);
    if(fail)
        return CRYPT_FAIL;
    else
        return CRYPT_SUCCESS;
}


//*** PKSC1v1_5SignEncode()
// Encode a message using PKCS1v1.5 method.
//
//  return type:    CRYPT_RESULT
//      CRYPT_SUCCESS       encode complete
//      CRYPT_SCHEME        'hashAlg' is not a supported hash algorithm
//      CRYPT_PARAMETER     'eOutSize' is not large enough or 'hInSize' does not
//                          match the digest size of hashAlg
//
static CRYPT_RESULT
RSASSA_Encode(
    UINT32           eOutSize,      // IN: the size of the resulting block
    BYTE            *eOut,          // OUT: the encoded block
    TPM_ALG_ID       hashAlg,       // IN: hash algorithm for PKSC1v1_5
    UINT32           hInSize,       // IN: size of hash to be signed
    BYTE            *hIn            // IN: hash buffer
)
{
    BYTE            *der;
    INT32            derSize = _cpri__GetHashDER(hashAlg, (const BYTE**)&der);
    INT32            fillSize;

    pAssert(eOut != NULL && hIn != NULL);

    // Can't use this scheme if the algorithm doesn't have a DER string defined.
    if(derSize == 0 )
        return CRYPT_SCHEME;

    // If the digest size of 'hashAl' doesn't match the input digest size, then 
    // the DER will misidentify the digest so return an error
    if((unsigned)_cpri__GetDigestSize(hashAlg) != hInSize)
        return CRYPT_PARAMETER;

    fillSize = eOutSize - derSize - hInSize - 3;

    // Make sure that this combination will fit in the provided space
    if(fillSize < 8)
        return CRYPT_PARAMETER;
    // Start filling
    *eOut++ = 0; // initial byte of zero
    *eOut++ = 1; // byte of 0x01
    for(; fillSize > 0; fillSize--)
        *eOut++ = 0xff; // bunch of 0xff
    *eOut++ = 0; // another 0
    for(; derSize > 0; derSize--)
        *eOut++ = *der++;   // copy the DER
    for(; hInSize > 0; hInSize--)
        *eOut++ = *hIn++;   // copy the hash
    return CRYPT_SUCCESS;
}


//*** RSASSA_Decode()
// This function performs the RSASSA decoding of a signature.
//
//  return type:    CRYPT_RESULT
//      CRYPT_SUCCESS       decode successful
//      CRYPT_FAIL          decode unsuccessful
//      CRYPT_SCHEME        'haslAlg' is not supported
//
static CRYPT_RESULT
RSASSA_Decode(
    TPM_ALG_ID       hashAlg,        // IN: hash algorithm to use for the encoding
    UINT32           hInSize,        // IN: size of the digest to compare
    BYTE            *hIn,            // In: the digest to compare
    UINT32           eInSize,        // IN: size of the encoded data
    BYTE            *eIn             // IN: the encoded data
)
{
    BOOL             fail = FALSE;
    BYTE            *der;
    INT32            derSize = _cpri__GetHashDER(hashAlg, (const BYTE**)&der);
    INT32            hashSize = _cpri__GetDigestSize(hashAlg);
    INT32            fillSize;

    pAssert(hIn != NULL && eIn != NULL);

    // Can't use this scheme if the algorithm doesn't have a DER string
    // defined or if the provided hash isn't the right size
    if(derSize == 0 || (unsigned)hashSize != hInSize)
        return CRYPT_SCHEME;

    // Make sure that this combination will fit in the provided space
    // Since no data movement takes place, can just walk though this
    // and accept nearly random values. This can only be called from
    // _cpri__ValidateSignature() so eInSize is known to be in range.
    fillSize = eInSize - derSize - hashSize - 3;

    // Start checking
    fail |= (*eIn++ != 0); // initial byte of zero
    fail |= (*eIn++ != 1); // byte of 0x01
    for(; fillSize > 0; fillSize--)
        fail |= (*eIn++ != 0xff); // bunch of 0xff
    fail |= (*eIn++ != 0); // another 0
    for(; derSize > 0; derSize--)
        fail |= (*eIn++ != *der++); // match the DER
    for(; hInSize > 0; hInSize--)
        fail |= (*eIn++ != *hIn++); // match the hash
    if(fail)
        return CRYPT_FAIL;
    return CRYPT_SUCCESS;
}


//**  Externally Accessible Functions

//*** _cpri__EncryptRSA()
// This is the entry point for encryption using RSA. Encryption is
// use of the public exponent. The padding parameter determines what
// padding will be used.
//
// The 'cOutSize' parameter must be at least as large as the size of the key.
//
// If the padding is RSA_PAD_NONE, 'dIn' is treaded as a number. It must be
// lower in value than the key modulus.
// NOTE: If dIn has fewer bytes than cOut, then we don't add low-order zeros to
//       dIn to make it the size of the RSA key for the call to RSAEP. This is 
//       because the high order bytes of dIn might have a numeric value that is 
//       greater than the value of the key modulus. If this had low-order zeros
//       added, it would have a numeric value larger than the modulus even though
//       it started out with a lower numeric value.
//
//  return type:    CRYPT_RESULT
//      CRYPT_SUCCESS       encryption complete
//      CRYPT_PARAMETER     'cOutSize' is too small (must be the size 
//                          of the modulus)
//      CRYPT_SCHEME        'padType' is not a supported scheme
//
CRYPT_RESULT
_cpri__EncryptRSA(
    UINT32      *cOutSize,      // OUT: the size of the encrypted data
    BYTE        *cOut,          // OUT: the encrypted data
    RSA_KEY     *key,           // IN: the key to use for encryption
    TPM_ALG_ID   padType,       // IN: the type of padding
    UINT32       dInSize,       // IN: the amount of data to encrypt
    BYTE        *dIn,           // IN: the data to encrypt
    TPM_ALG_ID   hashAlg,       // IN: in case this is needed
    const char  *label          // IN: in case it is needed
)
{
    CRYPT_RESULT    retVal = CRYPT_SUCCESS;

    pAssert(cOutSize != NULL);

    // All encryption schemes return the same size of data
    if(*cOutSize < key->publicKey->size)
        return CRYPT_PARAMETER;
    *cOutSize = key->publicKey->size;

    switch (padType)
    {
    case TPM_ALG_NULL:  // 'raw' encryption
        {
            // dIn can have more bytes than cOut as long as the extra bytes
            // are zero
            for(; dInSize > *cOutSize; dInSize--)
            {
                if(*dIn++ != 0)
                    return CRYPT_PARAMETER;

            }
            // If dIn is smaller than cOut, fill cOut with zeros
            if(dInSize < *cOutSize)
                memset(cOut, 0, *cOutSize - dInSize);

            // Copy the rest of the value
            memcpy(&cOut[*cOutSize-dInSize], dIn, dInSize);
            // If the size of dIn is the same as cOut dIn could be larger than
            // the modulus. If it is, then RSAEP() will catch it.
        }
        break;
    case TPM_ALG_RSAES:
        retVal = RSAES_PKSC1v1_5Encode(*cOutSize, cOut, dInSize, dIn);
        break;
    case TPM_ALG_OAEP:
        retVal = OaepEncode(*cOutSize, cOut, hashAlg, label, dInSize, dIn
#ifdef  TEST_RSA
                            ,NULL
#endif
                           );
        break;
    default:
        return CRYPT_SCHEME;
    }
    // All the schemes that do padding will come here for the encryption step
    // Check that the Encoding worked
    if(retVal != CRYPT_SUCCESS)
        return retVal;

    // Padding OK so do the encryption
    return RSAEP(*cOutSize, cOut, key);
}


//*** _cpri__DecryptRSA()
// This is the entry point for decryption using RSA. Decryption is
// use of the private exponent. The "padType" parameter determines what
// padding was used.
//
//  return type:    CRYPT_RESULT
//      CRYPT_SUCCESS       successful completion
//      CRYPT_PARAMETER     'cInSize' is not the same as the size of the public
//                          modulus of 'key'; or numeric value of the encrypted
//                          data is greater than the modulus
//      CRYPT_FAIL          'dOutSize' is not large enough for the result
//      CRYPT_SCHEME        'padType' is not supported
//
CRYPT_RESULT
_cpri__DecryptRSA(
    UINT32      *dOutSize,      // OUT: the size of the decrypted data
    BYTE        *dOut,          // OUT: the decrypted data
    RSA_KEY     *key,           // IN: the key to use for decryption
    TPM_ALG_ID   padType,       // IN: the type of padding
    UINT32       cInSize,       // IN: the amount of data to decrypt
    BYTE        *cIn,           // IN: the data to decrypt
    TPM_ALG_ID   hashAlg,       // IN: in case this is needed for the scheme
    const char  *label          // IN: in case it is needed for the scheme
)
{
    CRYPT_RESULT    retVal;

    // Make sure that the necessary parameters are provided
    pAssert(cIn != NULL && dOut != NULL && dOutSize != NULL && key != NULL);

    // Size is checked to make sure that the decryption works properly
    if(cInSize != key->publicKey->size)
        return CRYPT_PARAMETER;

    // For others that do padding, do the decryption in place and then
    // go handle the decoding.
    if((retVal = RSADP(cInSize, cIn, key)) != CRYPT_SUCCESS)
        return retVal;      // Decryption failed

    // Remove padding
    switch (padType)
    {
    case TPM_ALG_NULL:
        if(*dOutSize < key->publicKey->size)
            return CRYPT_FAIL;
        *dOutSize = key->publicKey->size;
        memcpy(dOut, cIn, *dOutSize);
        return CRYPT_SUCCESS;
    case TPM_ALG_RSAES: 
        return RSAES_Decode(dOutSize, dOut, cInSize, cIn);
        break;
    case TPM_ALG_OAEP:
        return OaepDecode(dOutSize, dOut, hashAlg, label, cInSize, cIn);
        break;
    default:
        return CRYPT_SCHEME;
        break;
    }
}


//*** _cpri__SignRSA()
// This function is used to generate an RSA signature of the type indicated in
// 'scheme'.
//
//  return type: CRYPT_RESULT
//      CRYPT_SUCCESS       sign operation completed normally
//      CRYPT_SCHEME        'scheme' or 'hashAlg' are not supported
//      CRYPT_PARAMETER     'hInSize' does not match 'hashAlg' (for RSASSA)
//
CRYPT_RESULT
_cpri__SignRSA(
    UINT32          *sigOutSize,    // OUT: size of signature
    BYTE            *sigOut,        // OUT: signature
    RSA_KEY         *key,           // IN: key to use
    TPM_ALG_ID       scheme,        // IN: the scheme to use
    TPM_ALG_ID       hashAlg,       // IN: hash algorithm for PKSC1v1_5
    UINT32           hInSize,       // IN: size of digest to be signed
    BYTE            *hIn            // IN: digest buffer
)
{
    CRYPT_RESULT    retVal;

    // Parameter checks
    pAssert(sigOutSize != NULL && sigOut != NULL && key != NULL && hIn != NULL);


    // For all signatures the size is the size of the key modulus
    *sigOutSize = key->publicKey->size;
    switch (scheme)
    {
    case TPM_ALG_NULL:
        *sigOutSize = 0;
        return CRYPT_SUCCESS;
    case TPM_ALG_RSAPSS:
        // PssEncode can return CRYPT_PARAMETER
        retVal = PssEncode(*sigOutSize, sigOut, hashAlg, hInSize, hIn
#ifdef  TEST_RSA
                           , NULL
#endif
                          );
        break;
    case TPM_ALG_RSASSA:
        // RSASSA_Encode can return CRYPT_PARAMETER or CRYPT_SCHEME
        retVal = RSASSA_Encode(*sigOutSize, sigOut, hashAlg, hInSize, hIn);
        break;
    default:
        return CRYPT_SCHEME;
    }
    if(retVal != CRYPT_SUCCESS)
        return retVal;
    // Do the encryption using the private key
    // RSADP can return CRYPT_PARAMETR
    return RSADP(*sigOutSize,sigOut, key);
}

//*** _cpri__ValidateSignatureRSA()
// This function is used to validate an RSA signature. If the signature is valid
// CRYPT_SUCCESS is returned. If the signature is not valid, CRYPT_FAIL is
// returned. Other return codes indicate either parameter problems or fatal errors.
//
// return type: CRYPT_RESULT
//      CRYPT_SUCCESS       the signature checks
//      CRYPT_FAIL          the signature does not check
//      CRYPT_SCHEME        unsupported scheme or hash algorithm
//      
CRYPT_RESULT
_cpri__ValidateSignatureRSA(
    RSA_KEY         *key,           // IN: key to use
    TPM_ALG_ID       scheme,        // IN: the scheme to use
    TPM_ALG_ID       hashAlg,       // IN: hash algorithm
    UINT32           hInSize,       // IN: size of digest to be checked
    BYTE            *hIn,           // IN: digest buffer
    UINT32           sigInSize,     // IN: size of signature
    BYTE            *sigIn,         // IN: signature
    UINT16           saltSize       // IN: salt size for PSS
)
{
    CRYPT_RESULT     retVal;

    // Fatal programming errors
    pAssert(key != NULL && sigIn != NULL && hIn != NULL);

    // Errors that might be caused by calling parameters
    if(sigInSize != key->publicKey->size)
        return CRYPT_FAIL;
    // Decrypt the block
    if((retVal = RSAEP(sigInSize, sigIn, key)) != CRYPT_SUCCESS)
        return CRYPT_FAIL;
    switch (scheme)
    {
    case TPM_ALG_NULL:
        return CRYPT_SCHEME;
        break;
    case TPM_ALG_RSAPSS:
        return PssDecode(hashAlg, hInSize, hIn, sigInSize, sigIn, saltSize);
        break;
    case TPM_ALG_RSASSA:
        return RSASSA_Decode(hashAlg, hInSize, hIn, sigInSize, sigIn);
        break;
    default:
        break;
    }
    return CRYPT_SCHEME;
}
