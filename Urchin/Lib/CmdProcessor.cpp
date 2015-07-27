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

#define REQUEST_HEADER_BUFFER_SIZE (sizeof(TPMI_ST_COMMAND_TAG) + sizeof(UINT32) + sizeof(TPM_CC) + sizeof(TPM_HANDLE) * MAX_HANDLE_NUM)
#define REQUEST_SESSION_BUFFER_SIZE (sizeof(UINT32) + (MAX_SESSION_NUM * (sizeof(TPMI_SH_AUTH_SESSION) + sizeof(TPM2B_NONCE) + sizeof(TPMA_SESSION) + sizeof(TPM2B_AUTH))))
#define REQUEST_PARAMETER_BUFFER_SIZE (2048)
#define REQUEST_BUFFER_SIZE (REQUEST_HEADER_BUFFER_SIZE + REQUEST_SESSION_BUFFER_SIZE + REQUEST_PARAMETER_BUFFER_SIZE)
#define RESPONSE_HEADER_BUFFER_SIZE (sizeof(TPMI_ST_COMMAND_TAG) + sizeof(UINT32) + sizeof(TPM_RC) + sizeof(TPM_HANDLE) * MAX_HANDLE_NUM)
#define RESPONSE_SESSION_BUFFER_SIZE (sizeof(UINT32) + (MAX_SESSION_NUM * (sizeof(TPM2B_NONCE) + sizeof(TPMA_SESSION) + sizeof(TPM2B_AUTH))))
#define RESPONSE_PARAMETER_BUFFER_SIZE (2048)
#define RESPONSE_BUFFER_SIZE (RESPONSE_HEADER_BUFFER_SIZE + RESPONSE_PARAMETER_BUFFER_SIZE + RESPONSE_SESSION_BUFFER_SIZE)

#define UNDEFINED_INDEX (-1)

//*** PolicyUpdate()
// Update policy hash
//      Update the policyDigest in policy session by extending policyRef and
//      objectName to it.
// return type: void
void
PolicyUpdate(
TPM_ALG_ID           authHashAlg,       // IN: SessionAlg
TPM_CC               commandCode,       // IN: command code
TPM2B_NAME          *name,              // IN: name of entity
TPM2B_NONCE         *ref,               // IN: the reference data
TPM2B_DIGEST        *policyDigest       // IN/OUT: policy digest to be updated
)
{
    HASH_STATE           hashState;
    UINT16               policyDigestSize;

    // Start hash
    policyDigestSize = CryptStartHash(authHashAlg, &hashState);

    // policyDigest size should always be the digest size of session hash alg.
    pAssert(policyDigest->t.size == policyDigestSize);

    // add old digest
    CryptUpdateDigest2B(&hashState, &policyDigest->b);

    // add commandCode
    CryptUpdateDigestInt(&hashState, sizeof(commandCode), &commandCode);

    // add name if applicable
    if(name != NULL)
        CryptUpdateDigest2B(&hashState, &name->b);

    // Complete the digest and get the results
    CryptCompleteHash2B(&hashState, &policyDigest->b);

    // Start second hash computation
    CryptStartHash(authHashAlg, &hashState);

    // add policyDigest
    CryptUpdateDigest2B(&hashState, &policyDigest->b);

    // add policyRef
    if(ref != NULL)
        CryptUpdateDigest2B(&hashState, &ref->b);

    // Complete second digest
    CryptCompleteHash2B(&hashState, &policyDigest->b);

    return;
}

//*** GetIV2BSize()
// Get the size of TPM2B_IV in canonical form that will be append to the start of
// the sensitive data.  It includes both size of size field and size of iv data
// return type: UINT15
static UINT16
GetIV2BSize(
ANY_OBJECT              *protector         // IN: the protector
)
{
    TPM_ALG_ID          symAlg;
    UINT16              keyBits;

    // Determine the symmetric algorithm and size of key
    if(protector == NULL)
    {
        // Use the context encryption algorithm and key size
        symAlg = CONTEXT_ENCRYPT_ALG;
        keyBits = CONTEXT_ENCRYPT_KEY_BITS;
    }
    else
    {
        symAlg = protector->obj.publicArea.t.publicArea.parameters.asymDetail.symmetric.algorithm;
        keyBits = protector->obj.publicArea.t.publicArea.parameters.asymDetail.symmetric.keyBits.sym;
    }

    // The IV size is a UINT16 size field plus the block size of the symmetric
    // algorithm
    return sizeof(UINT16)+CryptGetSymmetricBlockSize(symAlg, keyBits);
}

//*** GetSeedForKDF()
// Get a seed for KDF.  The KDF for encryption and HMAC key use the same seed.
// It returns a pointer to the seed
TPM2B_SEED*
GetSeedForKDF(
ANY_OBJECT          *protector,         // IN: the protector
TPM2B_SEED          *seedIn             // IN: the optional input seed
)
{
    UNREFERENCED_PARAMETER(protector);
    // Get seed for encryption key.  Use input seed if provided.
    // Otherwise, using protector object's seedValue.  TPM_RH_NULL is the only
    // exception that we may not have a loaded object as protector.  In such a
    // case, use nullProof as seed.
    if(seedIn != NULL)
    {
        return seedIn;
    }
    else
    {
        // This is not implemented, since we will never hace access to the parents seed
        pAssert(seedIn != NULL);
        return NULL;
    }
}

//*** ComputeProtectionKeyParms()
// This function retrieves the symmetric protection key parameters for
// the sensitive data
// The parameters retrieved from this function include encryption algorithm,
// key size in bit, and a TPM2B_SYM_KEY containing the key material as well as
// the key size in bytes
// This function is used for any action that requires encrypting or decrypting of
// the sensitive area of an object or a credential blob
//
/*(See part 1 specification)
KDF for generating the protection key material:
KDFa(hashAlg, seed, "STORAGE", Name, NULL , bits)
where
hashAlg     for a Primary Object, an algorithm chosen by the TPM vendor
for derivations from Primary Seeds. For all other objects,
the nameAlg of the object's parent.
seed        for a Primary Object in the Platform Hierarchy, the PPS.
For Primary Objects in either Storage or Endorsement Hierarchy,
the SPS. For Temporary Objects, the context encryption seed.
For all other objects, the symmetric seed value in the
sensitive area of the object's parent.
STORAGE     label to differentiate use of KDFa() (see 4.7)
Name        the Name of the object being encrypted
bits        the number of bits required for a  symmetric key and IV
*/
// return type: void
static void
ComputeProtectionKeyParms(
ANY_OBJECT          *protector,         // IN: the protector
TPM_ALG_ID           hashAlg,           // IN: hash algorithm for KDFa
TPM2B_NAME          *name,              // IN: name of the object
TPM2B_SEED          *seedIn,            // IN: optional seed for duplication
//     blob.  For non duplication blob,
//     this parameter should be NULL
TPM_ALG_ID          *symAlg,            // OUT: the symmetric algorithm
UINT16              *keyBits,           // OUT: the symmetric key size in bits
TPM2B_SYM_KEY       *symKey             // OUT: the symmetric key
)
{
    TPM2B_SEED          *seed = NULL;

    // Determine the algorithms for the KDF and the encryption/decryption
    // For TPM_RH_NULL, using context settings
    if(protector == NULL)
    {
        // Use the context encryption algorithm and key size
        *symAlg = CONTEXT_ENCRYPT_ALG;
        symKey->t.size = CONTEXT_ENCRYPT_KEY_BYTES;
        *keyBits = CONTEXT_ENCRYPT_KEY_BITS;
    }
    else
    {
        TPMT_SYM_DEF_OBJECT *symDef;
        symDef = &protector->obj.publicArea.t.publicArea.parameters.asymDetail.symmetric;
        *symAlg = symDef->algorithm;
        *keyBits = symDef->keyBits.sym;
        symKey->t.size = (*keyBits + 7) / 8;
    }

    // Get seed for KDF
    seed = GetSeedForKDF(protector, seedIn);

    // KDFa to generate symmetric key and IV value
    KDFa(hashAlg, (TPM2B *)seed, "STORAGE", (TPM2B *)name, NULL,
        symKey->t.size * 8, symKey->t.buffer, NULL);

    return;
}

//***ComputeOuterIntegrity()
// The sensitive area parameter is a buffer that holds a space for
// the integrity value and the marshaled sensitive area. The caller should
// skip over the area set aside for the integrity value
// and compute the hash of the remainder of the object.
// The size field of sensitive is in unmarshaled form and the
// sensitive area contents is an array of bytes.
/*(See part 1 specification)
KDFa(hashAlg, seed, "INTEGRITY", NULL, NULL , bits)   (38)
where
hashAlg     for a Primary Object, the nameAlg of the object. For all other
objects the nameAlg of the object's parent.
seed        for a Primary Object in the Platform Hierarchy, the PPS. For
Primary Objects in either Storage or Endorsement Hierarchy,
the SPS. For a Temporary Object, the context encryption key.
For all other objects, the symmetric seed value in the sensitive
area of the object's parent.
"INTEGRITY" a value used to differentiate the uses of the KDF.
bits        the number of bits in the digest produced by hashAlg.
Key is then used in the integrity computation.
HMACnameAlg(HMACkey, encSensitive || Name )
where
HMACnameAlg()   the HMAC function using nameAlg of the object's parent
HMACkey         value derived from the parent symmetric protection value
encSensitive    symmetrically encrypted sensitive area
Name            the Name of the object being protected
*/
// return type: void
static void
ComputeOuterIntegrity(
TPM2B_NAME          *name,              // IN: the name of the object
ANY_OBJECT          *protector,         // IN: The object
//     that provides protection.  For
//     object, it is the parent.
//     For credential, it is the
//     encrypt object.  For a 
//     Temporary Object, it is 
//     NULL
TPMI_ALG_HASH        hashAlg,           // IN: algorithm to use for integrity
TPM2B_SEED          *seedIn,            // IN: an external seed may be
//     provided for duplication blob.
//     For non duplication blob, this
//     parameter should be NULL
UINT32               sensitiveSize,     // IN: size of the marshaled sensitive
//     data
BYTE                *sensitiveData,     // IN: sensitive area
TPM2B_DIGEST        *integrity          // OUT: integrity
)
{
    HMAC_STATE          hmacState;

    TPM2B_DIGEST        hmacKey;
    TPM2B_SEED          *seed = NULL;

    // Get seed for KDF
    seed = GetSeedForKDF(protector, seedIn);

    // Determine the HMAC key bits
    hmacKey.t.size = CryptGetHashDigestSize(hashAlg);

    // KDFa to generate HMAC key
    KDFa(hashAlg, (TPM2B *)seed, "INTEGRITY", NULL, NULL,
        hmacKey.t.size * 8, hmacKey.t.buffer, NULL);

    // Start HMAC and get the size of the digest which will become the integrity
    integrity->t.size = CryptStartHMAC2B(hashAlg, &hmacKey.b, &hmacState);

    // Adding the marshaled sensitive area to the integrity value
    CryptUpdateDigest(&hmacState, sensitiveSize, sensitiveData);

    // Adding name
    CryptUpdateDigest2B(&hmacState, (TPM2B *)name);

    // Compute HMAC
    CryptCompleteHMAC2B(&hmacState, &integrity->b);

    return;
}

//*** ComputeInnerIntegrity()
// This function computes the integrity of an inner wrap
static void
ComputeInnerIntegrity(
TPM_ALG_ID              hashAlg,        // IN: hash algorithm for inner wrap
TPM2B_NAME              *name,          // IN: the name of the object
UINT16                  dataSize,       // IN: the size of sensitive data
BYTE                    *sensitiveData, // IN: sensitive data
TPM2B_DIGEST            *integrity      // OUT: inner integrity
)
{
    HASH_STATE      hashState;

    // Start hash and get the size of the digest which will become the integrity
    integrity->t.size = CryptStartHash(hashAlg, &hashState);

    // Adding the marshaled sensitive area to the integrity value
    CryptUpdateDigest(&hashState, dataSize, sensitiveData);

    // Adding name
    CryptUpdateDigest2B(&hashState, &name->b);

    // Compute hash
    CryptCompleteHash2B(&hashState, &integrity->b);

    return;

}

//*** ProduceInnerIntegrity()
// This function produces an inner integrity for regular private, credential or
// duplication blob
// It requires the sensitive data being marshaled to the innerBuffer, with the
// leading bytes reserved for integrity hash.  It assume the sensitive data
// starts at address (innerBuffer + integrity size).
// This function integrity at the beginning of the inner buffer
// It returns the total size of buffer with the inner wrap
static UINT16
ProduceInnerIntegrity(
TPM2B_NAME              *name,          // IN: the name of the object
TPM_ALG_ID              hashAlg,        // IN: hash algorithm for inner wrap
UINT16                  dataSize,       // IN: the size of sensitive data,
//     excluding the leading integrity
//     buffer size
BYTE                    *innerBuffer    // IN/OUT: inner buffer with
//         sensitive data in it.  At 
//         input, the leading bytes of 
//         this buffer is reserved for 
//         integrity
)
{
    BYTE                *sensitiveData; // pointer to the sensitive data

    TPM2B_DIGEST        integrity;
    UINT16              integritySize;
    BYTE                *buffer;        // Auxiliary buffer pointer

    // sensitiveData points to the beginning of sensitive data in innerBuffer
    integritySize = sizeof(UINT16)+CryptGetHashDigestSize(hashAlg);
    sensitiveData = innerBuffer + integritySize;

    ComputeInnerIntegrity(hashAlg, name, dataSize, sensitiveData, &integrity);

    // Add integrity at the beginning of inner buffer
    buffer = innerBuffer;
    TPM2B_DIGEST_Marshal(&integrity, &buffer, NULL);

    return dataSize + integritySize;
}

//*** CheckInnerIntegrity()
// This function check integrity of inner blob
// return type: TPM_RC
//      TPM_RC_INTEGRITY        if the outer blob integrity is bad
//      unmarshal errors        unmarshal errors while unmarshaling integrity
static TPM_RC
CheckInnerIntegrity(
TPM2B_NAME              *name,          // IN: the name of the object
TPM_ALG_ID              hashAlg,        // IN: hash algorithm for inner wrap
UINT16                  dataSize,       // IN: the size of sensitive data,
//     including the leading integrity
//     buffer size
BYTE                    *innerBuffer    // IN/OUT: inner buffer with
//     sensitive data in it
)
{
    TPM_RC          result;

    TPM2B_DIGEST    integrity;
    TPM2B_DIGEST    integrityToCompare;
    BYTE            *buffer;                // Auxiliary buffer pointer
    INT32           size;

    // Unmarshal integrity
    buffer = innerBuffer;
    size = (INT32)dataSize;
    result = TPM2B_DIGEST_Unmarshal(&integrity, &buffer, &size);
    if(result == TPM_RC_SUCCESS)
    {
        // Compute integrity to compare
        ComputeInnerIntegrity(hashAlg, name, (UINT16)size, buffer,
            &integrityToCompare);

        // Compare outer blob integrity
        if(!Memory2BEqual(&integrity.b, &integrityToCompare.b))
            result = TPM_RC_INTEGRITY;
    }
    return result;
}

//*** ProduceOuterWrap()
// This function produce outer wrap for a buffer containing the sensitive data.
// It requires the sensitive data being marshaled to the outerBuffer, with the
// leading bytes reserved for integrity hash.  If iv is used, iv space should
// be reserved at the beginning of the buffer.  It assumes the sensitive data
// starts at address (outerBuffer + integrity size {+ iv size}).
// This function performs:
//  1. Add IV before sensitive area if required
//  2. encrypt sensitive data, if iv is required, encrypt by iv.  otherwise,
//     encrypted by a NULL iv
//  3. add HMAC integrity at the beginning of the buffer
// It returns the total size of blob with outer wrap
UINT16
ProduceOuterWrap(
ANY_OBJECT      *protector,              // IN: The  object
//     that provides protection.  For
//     object, it is parent.
//     For credential, it is the
//     encrypt object.
TPM2B_NAME      *name,                  // IN: the name of the object
TPM_ALG_ID      hashAlg,                // IN: hash algorithm for outer wrap
TPM2B_SEED      *seed,                  // IN: an external seed may be
//     provided for duplication blob.
//     For non duplication blob, this
//     parameter should be NULL
BOOL            useIV,                  // IN: indicate if an IV is used
UINT16          dataSize,               // IN: the size of sensitive data,
//     excluding the leading integrity
//     buffer size or the optional iv
//     size
BYTE            *outerBuffer            // IN/OUT: outer buffer with
//         sensitive data in it
)
{
    TPM_ALG_ID      symAlg;
    UINT16          keyBits;
    TPM2B_SYM_KEY   symKey;
    TPM2B_IV        ivRNG;          // IV from RNG
    TPM2B_IV        *iv = NULL;
    UINT16          ivSize = 0;     // size of iv area, including the size field

    BYTE            *sensitiveData; // pointer to the sensitive data

    TPM2B_DIGEST    integrity;
    UINT16          integritySize;
    BYTE            *buffer;        // Auxiliary buffer pointer

    // Compute the beginning of sensitive data.  The outer integrity should
    // always exist if this function function is called to make an outer wrap
    integritySize = sizeof(UINT16)+CryptGetHashDigestSize(hashAlg);
    sensitiveData = outerBuffer + integritySize;

    // If iv is used, adjust the pointer of sensitive data and add iv before it
    if(useIV)
    {
        ivSize = GetIV2BSize(protector);

        // Generate IV from RNG.  The iv data size should be the total IV area
        // size minus the size of size field
        ivRNG.t.size = ivSize - sizeof(UINT16);
        CryptGenerateRandom(ivRNG.t.size, ivRNG.t.buffer);

        // Marshal IV to buffer
        buffer = sensitiveData;
        TPM2B_IV_Marshal(&ivRNG, &buffer, NULL);

        // adjust sensitive data starting after IV area
        sensitiveData += ivSize;

        // Use iv for encryption
        iv = &ivRNG;
    }

    // Compute symmetric key parameters for outer buffer encryption
    ComputeProtectionKeyParms(protector, hashAlg, name, seed,
        &symAlg, &keyBits, &symKey);
    // Encrypt inner buffer in place
    CryptSymmetricEncrypt(sensitiveData, symAlg, keyBits,
        TPM_ALG_CFB, symKey.t.buffer, iv, dataSize,
        sensitiveData);

    // Compute outer integrity.  Integrity computation includes the optional IV
    // area
    ComputeOuterIntegrity(name, protector, hashAlg, seed, dataSize + ivSize,
        outerBuffer + integritySize, &integrity);

    // Add integrity at the beginning of outer buffer
    buffer = outerBuffer;
    TPM2B_DIGEST_Marshal(&integrity, &buffer, NULL);

    // return the total size in outer wrap
    return dataSize + integritySize + ivSize;

}

//*** UnwrapOuter()
// This function remove the outer wrap of a blob containing sensitive data
// This function performs:
//  1. check integrity of outer blob
//  2. decrypt outer blob
//
// return type: TPM_RC
//   TPM_RC_INSUFFICIENT         error during sensitive data unmarshaling
//   TPM_RC_INTEGRITY            sensitive data integrity is broken
//   TPM_RC_SIZE                 error during sensitive data unmarshaling
//   TPM_RC_VALUE                IV size for CFB does not match the encryption
//                               algorithm block size
TPM_RC
UnwrapOuter(
ANY_OBJECT      *protector,             // IN: The object
//     that provides protection.  For
//     object, it is parent.
//     For credential, it is the encrypt object.
TPM2B_NAME      *name,                  // IN: the name of the object
TPM_ALG_ID       hashAlg,               // IN: hash algorithm for outer wrap
TPM2B_SEED      *seed,                  // IN: an external seed may be
//     provided for duplication blob.
//     For non duplication blob, this
//     parameter should be NULL.
BOOL             useIV,                 // IN: indicates if an IV is used
UINT16           dataSize,              // IN: size of sensitive data in
//     outerBuffer, including the
//     leading integrity buffer size,
//     and an optional iv area
BYTE            *outerBuffer            // IN/OUT: sensitive data
)
{
    TPM_RC          result;
    TPM_ALG_ID      symAlg = TPM_ALG_NULL;
    TPM2B_SYM_KEY   symKey;
    UINT16          keyBits = 0;
    TPM2B_IV        ivIn;               // input IV retrieved from input buffer
    TPM2B_IV        *iv = NULL;

    BYTE            *sensitiveData;     // pointer to the sensitive data

    TPM2B_DIGEST    integrityToCompare;
    TPM2B_DIGEST    integrity;
    INT32           size;

    // Unmarshal integrity
    sensitiveData = outerBuffer;
    size = (INT32)dataSize;
    result = TPM2B_DIGEST_Unmarshal(&integrity, &sensitiveData, &size);
    if(result == TPM_RC_SUCCESS)
    {
        // Compute integrity to compare
        ComputeOuterIntegrity(name, protector, hashAlg, seed,
            (UINT16)size, sensitiveData,
            &integrityToCompare);

        // Compare outer blob integrity
        if(!Memory2BEqual(&integrity.b, &integrityToCompare.b))
            return TPM_RC_INTEGRITY;

        // Get the symmetric algorithm parameters used for encryption
        ComputeProtectionKeyParms(protector, hashAlg, name, seed,
            &symAlg, &keyBits, &symKey);

        // Retrieve IV if it is used
        if(useIV)
        {
            result = TPM2B_IV_Unmarshal(&ivIn, &sensitiveData, &size);
            if(result == TPM_RC_SUCCESS)
            {
                // The input iv size for CFB must match the encryption algorithm 
                // block size
                if(ivIn.t.size != CryptGetSymmetricBlockSize(symAlg, keyBits))
                    result = TPM_RC_VALUE;
                else
                    iv = &ivIn;
            }
        }
    }
    // If no errors, decrypt private in place    
    if(result == TPM_RC_SUCCESS)
        CryptSymmetricDecrypt(sensitiveData, symAlg, keyBits,
        TPM_ALG_CFB, symKey.t.buffer, iv,
        (UINT16)size, sensitiveData);

    return result;
}

//***DuplicateToSensitive()
// Unwrap a duplication blob.  Check the integrity, decrypt and retrieve data
// to a sensitive structure.
// The operations in this function:
//  1. check the integrity HMAC of the input private area
//  2. decrypt the private buffer
//  3. unmarshal TPMT_SENSITIVE structure into the buffer of TPMT_SENSITIVE
//
// return type: TPM_RC
//   TPM_RC_INSUFFICIENT         unmarshaling sensitive data from 'inPrivate' failed
//   TPM_RC_INTEGRITY            'inPrivate' data integrity is broken
//   TPM_RC_SIZE                 unmarshaling sensitive data from 'inPrivate' failed
TPM_RC
DuplicateToSensitive(
TPM2B_PRIVATE           *inPrivate,     // IN: input private structure
TPM2B_NAME              *name,          // IN: the name of the object
ANY_OBJECT              *parent,        // IN: The new parent
TPM_ALG_ID              nameAlg,        // IN: hash algorithm in public
//     area.
TPM2B_SEED              *seed,          // IN: an external seed may be
//     provided.
//     If external seed is provided
//     with size of 0, no outer wrap
//     is applied
TPMT_SYM_DEF_OBJECT     *symDef,        // IN: Symmetric key definition.
//     If the symmetric key algorithm
//     is NULL, no inner wrap is 
//     applied
TPM2B_DATA              *innerSymKey,   // IN: a symmetric key may be
//     provided to decrypt the inner
//     wrap of a duplication blob.
TPMT_SENSITIVE          *sensitive      // OUT: sensitive structure
)
{
    TPM_RC          result;

    BYTE            *buffer;
    INT32           size;
    BYTE            *sensitiveData; // pointer to the sensitive data
    UINT16          dataSize;
    UINT16          dataSizeInput;

    // Make sure that name is provided
    pAssert(name != NULL && name->t.size != 0);

    // Make sure symDef and innerSymKey are not NULL
    pAssert(symDef != NULL && innerSymKey != NULL);

    // Starting of sensitive data
    sensitiveData = inPrivate->t.buffer;
    dataSize = inPrivate->t.size;

    // Find out if inner wrap is applied
    if(seed->t.size != 0)
    {
        TPMI_ALG_HASH   outerHash = TPM_ALG_NULL;

        // Use parent nameAlg as outer hash algorithm
        outerHash = parent->obj.publicArea.t.publicArea.nameAlg;
        result = UnwrapOuter(parent, name, outerHash, seed, FALSE,
            dataSize, sensitiveData);
        if(result != TPM_RC_SUCCESS)
            return result;

        // Adjust sensitive data pointer and size
        sensitiveData += sizeof(UINT16)+CryptGetHashDigestSize(outerHash);
        dataSize -= sizeof(UINT16)+CryptGetHashDigestSize(outerHash);
    }
    // Find out if inner wrap is applied
    if(symDef->algorithm != TPM_ALG_NULL)
    {
        TPMI_ALG_HASH   innerHash = TPM_ALG_NULL;

        // assume the input key size should matches the symmetric definition
        pAssert(innerSymKey->t.size == (symDef->keyBits.sym + 7) / 8);

        // Decrypt inner buffer in place
        CryptSymmetricDecrypt(sensitiveData, symDef->algorithm,
            symDef->keyBits.sym, TPM_ALG_CFB,
            innerSymKey->t.buffer, NULL, dataSize,
            sensitiveData);

        // Use self nameAlg as inner hash algorithm
        innerHash = nameAlg;

        // Check inner integrity
        result = CheckInnerIntegrity(name, innerHash, dataSize, sensitiveData);
        if(result != TPM_RC_SUCCESS)
            return result;

        // Adjust sensitive data pointer and size
        sensitiveData += sizeof(UINT16)+CryptGetHashDigestSize(innerHash);
        dataSize -= sizeof(UINT16)+CryptGetHashDigestSize(innerHash);
    }

    // Unmarshal input data size
    buffer = sensitiveData;
    size = (INT32)dataSize;
    result = UINT16_Unmarshal(&dataSizeInput, &buffer, &size);
    if(result == TPM_RC_SUCCESS)
    {
        if((dataSizeInput + sizeof(UINT16)) != dataSize)
            result = TPM_RC_SIZE;
        else
        {
            // Unmarshal sensitive buffer to sensitive structure
            result = TPMT_SENSITIVE_Unmarshal(sensitive, &buffer, &size);
            // if the results is OK make sure that all the data was unmarshaled
            if(result == TPM_RC_SUCCESS && size != 0)
                result = TPM_RC_SIZE;
        }
    }
    // Always remove trailing zeros at load so that it is not necessary to check
    // each time auth is checked.
    if(result == TPM_RC_SUCCESS)
        MemoryRemoveTrailingZeros(&(sensitive->authValue));
    return result;
}

//*** SensitiveToDuplicate()
// This function prepare the duplication blob from the sensitive area.
// The operations in this function:
//  1. marshal TPMT_SENSITIVE structure into the buffer of TPM2B_PRIVATE
//  2. apply inner wrap to the sensitive area if required
//  3. apply outer wrap if required
void
SensitiveToDuplicate(
TPMT_SENSITIVE          *sensitive,     // IN: sensitive structure
TPM2B_NAME              *name,          // IN: the name of the object
ANY_OBJECT              *parent,        // IN: The new parent
TPM_ALG_ID              nameAlg,        // IN: hash algorithm in public
//     area.  It is passed separately
//     because we only pass name,
//     rather than the whole public
//     area of the object.
TPM2B_SEED              *seed,          // IN: the external seed.
//     If external seed is provided
//     with size of 0, no outer wrap
//     should be applied to duplication
//     blob.
TPMT_SYM_DEF_OBJECT     *symDef,        // IN: Symmetric key definition.
//     If the symmetric key algorithm
//     is NULL, no inner wrap should be
//     applied
TPM2B_DATA              *innerSymKey,   // IN: a symmetric key may be
//     provided to encrypt the inner
//     wrap of a duplication blob.
TPM2B_PRIVATE           *outPrivate     // OUT: output private structure
)
{
    BYTE            *buffer;        // Auxiliary buffer pointer
    BYTE            *sensitiveData; // pointer to the sensitive data
    TPMI_ALG_HASH   outerHash = TPM_ALG_NULL;// The hash algorithm for outer wrap
    TPMI_ALG_HASH   innerHash = TPM_ALG_NULL;// The hash algorithm for inner wrap
    UINT16          dataSize;       // data blob size
    BOOL            doInnerWrap = FALSE;
    BOOL            doOuterWrap = FALSE;

    // Make sure that name is provided
    pAssert(name != NULL && name->t.size != 0);

    // Make sure symDef and innerSymKey are not NULL
    pAssert(symDef != NULL && innerSymKey != NULL);

    // Starting of sensitive data without wrappers
    sensitiveData = outPrivate->t.buffer;

    // Find out if inner wrap is required
    if(symDef->algorithm != TPM_ALG_NULL)
    {
        doInnerWrap = TRUE;
        // Use self nameAlg as inner hash algorithm
        innerHash = nameAlg;
        // Adjust sensitive data pointer
        sensitiveData += sizeof(UINT16)+CryptGetHashDigestSize(innerHash);
    }

    // Find out if outer wrap is required
    if(seed->t.size != 0)
    {
        doOuterWrap = TRUE;
        // Use parent nameAlg as outer hash algorithm
        outerHash = parent->obj.publicArea.t.publicArea.nameAlg;
        // Adjust sensitive data pointer
        sensitiveData += sizeof(UINT16)+CryptGetHashDigestSize(outerHash);
    }

    // Marshal sensitive area, leaving the leading 2 bytes for size
    buffer = sensitiveData + sizeof(UINT16);
    dataSize = TPMT_SENSITIVE_Marshal(sensitive, &buffer, NULL);

    // Adding size before the data area
    buffer = sensitiveData;
    UINT16_Marshal(&dataSize, &buffer, NULL);

    // Adjust the dataSize to include the size field
    dataSize += sizeof(UINT16);

    // Apply inner wrap for duplication blob.  It includes both integrity and
    // encryption
    if(doInnerWrap)
    {
        BYTE            *innerBuffer = NULL;
        BOOL            symKeyInput = TRUE;
        innerBuffer = outPrivate->t.buffer;
        // Skip outer integrity space
        if(doOuterWrap)
            innerBuffer += sizeof(UINT16)+CryptGetHashDigestSize(outerHash);
        dataSize = ProduceInnerIntegrity(name, innerHash, dataSize,
            innerBuffer);

        // Generate inner encryption key if needed
        if(innerSymKey->t.size == 0)
        {
            innerSymKey->t.size = (symDef->keyBits.sym + 7) / 8;
            CryptGenerateRandom(innerSymKey->t.size, innerSymKey->t.buffer);

            // TPM generates symmetric encryption.  Set the flag to FALSE
            symKeyInput = FALSE;
        }
        else
        {
            // assume the input key size should matches the symmetric definition
            pAssert(innerSymKey->t.size == (symDef->keyBits.sym + 7) / 8);

        }

        // Encrypt inner buffer in place
        CryptSymmetricEncrypt(innerBuffer, symDef->algorithm,
            symDef->keyBits.sym, TPM_ALG_CFB,
            innerSymKey->t.buffer, NULL, dataSize,
            innerBuffer);

        // If the symmetric encryption key is imported, clear the buffer for
        // output
        if(symKeyInput)
            innerSymKey->t.size = 0;
    }

    // Apply outer wrap for duplication blob.  It includes both integrity and
    // encryption
    if(doOuterWrap)
    {
        dataSize = ProduceOuterWrap(parent, name, outerHash, seed, FALSE,
            dataSize, outPrivate->t.buffer);
    }

    // Data size for output
    outPrivate->t.size = dataSize;

    return;
}

//*** SecretToCredential
// This function prepare the credential blob from a secret (a TPM2B_DIGEST)
// The operations in this function:
//  1. marshal TPM2B_DIGEST structure into the buffer of TPM2B_ID_OBJECT
//  2. encrypt the private buffer, excluding the leading integrity HMAC area
//  3. compute integrity HMAC and append to the beginning of the buffer.
//  4. Set the total size of TPM2B_ID_OBJECT buffer
void
SecretToCredential(
TPM2B_DIGEST        *secret,        // IN: secret information
TPM2B_NAME          *name,          // IN: the name of the object
TPM2B_SEED          *seed,          // IN: an external seed.
ANY_OBJECT          *protector,     // IN: The protector
TPM2B_ID_OBJECT     *outIDObject    // OUT: output credential
)
{
    BYTE                *buffer;        // Auxiliary buffer pointer
    BYTE                *sensitiveData; // pointer to the sensitive data
    TPMI_ALG_HASH        outerHash;     // The hash algorithm for outer wrap
    UINT16               dataSize;      // data blob size

    pAssert(secret != NULL && outIDObject != NULL);

    // use protector's name algorithm as outer hash
    outerHash = protector->obj.publicArea.t.publicArea.nameAlg;

    // Marshal secret area to credential buffer, leave space for integrity
    sensitiveData = outIDObject->t.credential
        + sizeof(UINT16)+CryptGetHashDigestSize(outerHash);

    // Marshal secret area
    buffer = sensitiveData;
    dataSize = TPM2B_DIGEST_Marshal(secret, &buffer, NULL);

    // Apply outer wrap
    outIDObject->t.size = ProduceOuterWrap(protector,
        name,
        outerHash,
        seed,
        FALSE,
        dataSize,
        outIDObject->t.credential);
    return;
}

// Windows8 defined TPM 2.0 default Template
void SetEkTemplate(
    TPM2B_PUBLIC *publicArea
    )
{
    const BYTE TPM_20_EK_AUTH_POLICY[] =  // 'PolicySecret(TPM_RH_ENDORSEMENT)'
    {
        0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8,
        0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7, 0x24,
        0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64,
        0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa,
    };
    if (publicArea == NULL) return;
    MemoryCopy(publicArea->t.publicArea.authPolicy.t.buffer,
               TPM_20_EK_AUTH_POLICY,
               sizeof(TPM_20_EK_AUTH_POLICY),
               sizeof(publicArea->t.publicArea.authPolicy.t.buffer));
    publicArea->t.publicArea.authPolicy.t.size = sizeof(TPM_20_EK_AUTH_POLICY);
    publicArea->t.publicArea.unique.rsa.t.size = MAX_RSA_KEY_BITS / 8;
    publicArea->t.publicArea.type = TPM_ALG_RSA;
    publicArea->t.publicArea.nameAlg = TPM_ALG_SHA256;
    publicArea->t.publicArea.objectAttributes.fixedTPM = SET;
    publicArea->t.publicArea.objectAttributes.fixedParent = SET;
    publicArea->t.publicArea.objectAttributes.sensitiveDataOrigin = SET;
    publicArea->t.publicArea.objectAttributes.adminWithPolicy = SET;
    publicArea->t.publicArea.objectAttributes.restricted = SET;
    publicArea->t.publicArea.objectAttributes.decrypt = SET;
    publicArea->t.publicArea.parameters.rsaDetail.keyBits = MAX_RSA_KEY_BITS;
    publicArea->t.publicArea.parameters.rsaDetail.exponent = 0;
    publicArea->t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
    publicArea->t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
    publicArea->t.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
    publicArea->t.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
};

//*** ObjectComputeName()
// This function computes the Name of an object from its public area.
void
ObjectComputeName(
    TPMT_PUBLIC         *publicArea,        // IN: public area of an object
    TPM2B_NAME          *name               // OUT: name of the object
)
{
    TPM2B_PUBLIC         marshalBuffer;
    BYTE                *buffer;            // auxiliary marshal buffer pointer
    HASH_STATE           hashState;         // hash state

    // if the nameAlg is NULL then there is no name.
    if(publicArea->nameAlg == TPM_ALG_NULL)
    {
        name->t.size = 0;
        return;
    }
    // Start hash stack
    name->t.size = CryptStartHash(publicArea->nameAlg, &hashState);

    // Marshal the public area into its canonical form
    buffer = marshalBuffer.b.buffer;

    marshalBuffer.t.size = TPMT_PUBLIC_Marshal(publicArea, &buffer, NULL);
 
    // Adding public area
    CryptUpdateDigest2B(&hashState, &marshalBuffer.b);

    // Complete hash leaving room for the name algorithm
    CryptCompleteHash(&hashState, name->t.size, &name->t.name[2]);

    // set the nameAlg
    UINT16_TO_BYTE_ARRAY(publicArea->nameAlg, name->t.name);
    name->t.size += 2;
    return;
}

//*** HandleGetType()
// This function returns the type of a handle which is the MSO of the handle.
TPM_HT
HandleGetType(
TPM_HANDLE      handle      //IN: a handle to be checked
)
{
    // return the upper bytes of input data
    return (TPM_HT)((handle & HR_RANGE_MASK) >> HR_SHIFT);
}

//*** ComputeCommandHMAC()
// This function computes the HMAC for an authorization session in a command.
/*(See part 1 specification -- this tag keeps this comment from showing up in
// merged document which is probably good because this comment doesn't look right.
//      The sessionAuth value
//      authHMAC := HMACsHash((sessionKey | authValue),
//                  (pHash | nonceNewer | nonceOlder  | nonceTPMencrypt-only
//                   | nonceTPMaudit   | sessionAttributes))
// Where:
//      HMACsHash()     The HMAC algorithm using the hash algorithm specified
//                      when the session was started.
//
//      sessionKey      A value that is computed in a protocol-dependent way,
//                      using KDFa. When used in an HMAC or KDF, the size field
//                      for this value is not included.
//
//      authValue       A value that is found in the sensitive area of an entity.
//                      When used in an HMAC or KDF, the size field for this
//                      value is not included.
//
//      pHash           Hash of the command (cpHash) using the session hash.
//                      When using a pHash in an HMAC computation, only the
//                      digest is used.
//
//      nonceNewer      A value that is generated by the entity using the
//                      session. A new nonce is generated on each use of the
//                      session. For a command, this will be nonceCaller.
//                      When used in an HMAC or KDF, the size field is not used.
//
//      nonceOlder      A TPM2B_NONCE that was received the previous time the
//                      session was used. For a command, this is nonceTPM.
//                      When used in an HMAC or KDF, the size field is not used.
//
//      nonceTPMdecrypt     The nonceTPM of the decrypt session is included in
//                          the HMAC, but only in the command.
//
//      nonceTPMencrypt     The nonceTPM of the encrypt session is included in
//                          the HMAC but only in the command.
//
//      sessionAttributes   A byte indicating the attributes associated with the
//                          particular use of the session.
*/
static void
ComputeCommandHMAC(
    UINT32           sessionIndex,
    SESSION         *sessionTable,
    UINT32           sessionCnt,
    Marshal_Parms   *parms,
    TPM2B_DIGEST    *cpHash,            // IN: cpHash
    TPM2B_DIGEST    *hmac               // OUT: authorization HMAC
)
{
    TPM2B_TYPE(KEY, (sizeof(AUTH_VALUE)* 2));
    TPM2B_KEY        key;
    BYTE             marshalBuffer[sizeof(TPMA_SESSION)];
    BYTE            *buffer;
    UINT32           marshalSize;
    HMAC_STATE       hmacState;
    TPM2B_NONCE     *nonceDecrypt = (TPM2B_NONCE*)NULL;
    TPM2B_NONCE     *nonceEncrypt = (TPM2B_NONCE*)NULL;
    UINT32           decryptSessionIndex = (UINT32)UNDEFINED_INDEX;
    UINT32           encryptSessionIndex = (UINT32)UNDEFINED_INDEX;

    // Find if there are decrypt or encrypt sessions
    for (UINT32 n = 0; n < sessionCnt; n++)
    {
        if (sessionTable[n].attributes.decrypt != CLEAR)
        {
            decryptSessionIndex = n;
        }
        if (sessionTable[n].attributes.encrypt != CLEAR)
        {
            encryptSessionIndex = n;
        }
    }

    // Determine if extra nonceTPM values are going to be required.
    // If this is the first session (sessionIndex = 0) and it is an authorization
    // session that uses an HMAC, then check if additional session nonces are to be
    // included.
    if((sessionIndex == 0) && (parms->objectCntIn > 0))
    {
        // If there is a decrypt session and if this is not the decrypt session,
        // then an extra nonce may be needed.
        if (decryptSessionIndex != UNDEFINED_INDEX
            && decryptSessionIndex != sessionIndex)
        {
            // Will add the nonce for the decrypt session.
            nonceDecrypt = &sessionTable[decryptSessionIndex].nonceTPM;
        }
        // Now repeat for the encrypt session.
        if (encryptSessionIndex != UNDEFINED_INDEX
            && encryptSessionIndex != sessionIndex
            && encryptSessionIndex != decryptSessionIndex)
        {
            // Have to have the nonce for the encrypt session.
            nonceEncrypt = &sessionTable[encryptSessionIndex].nonceTPM;
        }
    }

    // Generate HMAC key.
    MemoryCopy2B(&key.b, &sessionTable[sessionIndex].sessionKey.b, sizeof(key.t.buffer));

    // Check if the session has an associated handle and if the associated entity
    // is the one to which the session is bound. If not, add the authValue of
    // this entity to the HMAC key.
    // If the session is bound to the object or the session is a policy session
    // with no authValue required, do not include the authValue in the HMAC key.
    // Note: For a policy session, its isBound attribute is CLEARED.
    if((sessionIndex < parms->objectCntIn)
        && (!Memory2BEqual((TPM2B*)&parms->objectTableIn[sessionIndex].obj.name, (TPM2B*)&sessionTable[sessionIndex].u1.boundEntity))
        && (!((HandleGetType(sessionTable[sessionIndex].handle) == TPM_HT_POLICY_SESSION)
           && (sessionTable[sessionIndex].sessionAttributes.isAuthValueNeeded == CLEAR)
           && (sessionTable[sessionIndex].sessionAttributes.isBound == CLEAR))))
    {
        pAssert((sizeof(AUTH_VALUE)+key.t.size) <= sizeof(key.t.buffer));
        MemoryConcat2B((TPM2B*)&key, (TPM2B*)&parms->objectTableIn[sessionIndex].obj.authValue, sizeof(key.t.buffer));
    }

    // if the HMAC key size for a policy session is 0, a NULL string HMAC is
    // allowed.
    if ((HandleGetType(sessionTable[sessionIndex].handle) == TPM_HT_POLICY_SESSION)
        && (key.t.size == 0))
    {
        hmac->t.size = 0;
        return;
    }

    // Start HMAC
    hmac->t.size = CryptStartHMAC2B(sessionTable[sessionIndex].authHashAlg, &key.b, &hmacState);

    //  Add cpHash
    CryptUpdateDigest2B(&hmacState, &cpHash->b);

    //  Add nonceCaller
    CryptUpdateDigest2B(&hmacState, &sessionTable[sessionIndex].nonceCaller.b);

    //  Add nonceTPM
    CryptUpdateDigest2B(&hmacState, &sessionTable[sessionIndex].nonceTPM.b);

    //  If needed, add nonceTPM for decrypt session
    if (nonceDecrypt != NULL)
        CryptUpdateDigest2B(&hmacState, &nonceDecrypt->b);

    //  If needed, add nonceTPM for encrypt session
    if (nonceEncrypt != NULL)
        CryptUpdateDigest2B(&hmacState, &nonceEncrypt->b);

    //  Add sessionAttributes
    buffer = marshalBuffer;
    marshalSize = TPMA_SESSION_Marshal(&(sessionTable[sessionIndex].attributes), &buffer, (INT32*)NULL);
    CryptUpdateDigest(&hmacState, marshalSize, marshalBuffer);

    // Complete the HMAC computation
    CryptCompleteHMAC2B(&hmacState, &hmac->b);

    return;
}

//*** CheckPWAuthSession()
// This function validates the authorization provided in a PWAP session.  It
// compares the input value to authValue of the authorized entity. Argument
// sessionIndex is used to get handles handle of the referenced entities from
// s_inputAuthValues[] and s_associatedHandles[].
//
// return type: TPM_RC
//        TPM_RC_AUTH_FAIL          auth fails and increments DA failure count
//        TPM_RC_BAD_AUTH           auth fails but DA does not apply
//
static void
CopyPWAuthSession(
UINT32      objectIndex,                // IN: associated object
ANY_OBJECT *objectTable,
UINT32 objectCnt,
TPM2B_DIGEST    *authSignature
)
{
    pAssert(objectIndex <= objectCnt);
    MemoryCopy2B((TPM2B*)authSignature, (TPM2B*)&objectTable[objectIndex].obj.authValue, sizeof((*authSignature).t.buffer));
}

//*** CheckAuthSession()
// This function checks that the authorization session properly authorizes the
// use of the associated handle.
static void
SignAuthSession(
    UINT32           sessionIndex,               // IN: index of session to be processed
    SESSION         *sessionTable,
    UINT32           sessionCnt,
    Marshal_Parms   *parms,
    TPM2B_DIGEST    *cpHash,                // IN: cpHash
    TPM2B_DIGEST    *nameHash,              // IN: nameHash
    TPM2B_DIGEST    *authSignature          // OUT: authorization signature
)
{
    TPM_HT           sessionHandleType = HandleGetType(sessionTable[sessionIndex].handle);

    UNREFERENCED_PARAMETER(nameHash);

    // If this is a PW authorization, check it and return
    // or if it is a policy session that requires a password
    if ((sessionTable[sessionIndex].handle == TPM_RS_PW)
        || (((sessionHandleType == TPM_HT_POLICY_SESSION
        && sessionTable[sessionIndex].sessionAttributes.isPasswordNeeded == SET))))
    {
        // For policy session that requires a password, check it as PWAP session.
        CopyPWAuthSession(sessionIndex, parms->objectTableIn, parms->objectCntIn, authSignature);
    }
    else
    {
        // For other policy or HMAC sessions, have its HMAC checked.
        ComputeCommandHMAC(sessionIndex, sessionTable, sessionCnt, parms, cpHash, authSignature);
    }
}

//*** EntityGetName()
// This function returns the Name associated with a handle.
// It will set 'name' to the Name and return the size of the Name string.
UINT16
EntityGetName(
ANY_OBJECT *object,
TPM2B_NAME *name        // OUT: name of entity
)
{
    switch (HandleGetType(object->generic.handle))
    {
    case TPM_HT_TRANSIENT:
    case TPM_HT_NV_INDEX:
    case TPM_HT_PERSISTENT:
        // Name for a key or NV index
        *name = object->generic.name;
        break;
    default:
        // For all other types, the handle is the Name
        BYTE *buffer = name->t.name;
        INT32 size = sizeof(name->t.name);
        name->t.size = TPM_HANDLE_Marshal(&object->generic.handle, &buffer, &size);
        break;
    }
    return name->t.size;
}

//*** ComputeCpHash()
// This function computes the cpHash as defined in Part 2 and described in Part 1.
void
ComputeCpHash(
TPMI_ALG_HASH    hashAlg,           // IN: hash algorithm
TPM_CC           commandCode,       // IN: command code
Marshal_Parms   *parms,
UINT32           parmBufferSize,    // IN: size of input parameter area
const BYTE      *parmBuffer,        // IN: input parameter area
TPM2B_DIGEST    *cpHash,            // OUT: cpHash
TPM2B_DIGEST    *nameHash           // OUT: name hash of command
)
{
    UINT32           i;
    HASH_STATE       hashState;
    TPM2B_NAME       name;

    // cpHash = hash(commandCode [ || authName1
    //                           [ || authName2
    //                           [ || authName 3 ]]]
    //                           [ || parameters])
    // A cpHash can contain just a commandCode only if the lone session is 
    // an audit session.

    // Start cpHash.
    cpHash->t.size = CryptStartHash(hashAlg, &hashState);

    //  Add commandCode.
    CryptUpdateDigestInt(&hashState, sizeof(TPM_CC), &commandCode);

    //  Add authNames for each of the handles.
    for (i = 0; i < parms->objectCntIn; i++)
    {
        name.t.size = EntityGetName(&parms->objectTableIn[i], &name);
        CryptUpdateDigest2B(&hashState, &name.b);
    }

    //  Add the parameters.
    CryptUpdateDigest(&hashState, parmBufferSize, (BYTE*)parmBuffer);

    //  Complete the hash.
    CryptCompleteHash2B(&hashState, &cpHash->b);

    // If the nameHash is needed, compute it here.
    if (nameHash != NULL)
    {
        // Start name hash. hashState may be reused.
        nameHash->t.size = CryptStartHash(hashAlg, &hashState);

        //  Adding names.
        for(i = 0; i < parms->objectCntIn; i++)
        {
            name.t.size = EntityGetName(&parms->objectTableIn[i], &name);
            CryptUpdateDigest2B(&hashState, &name.b);
        }
        //  Complete hash.
        CryptCompleteHash2B(&hashState, &nameHash->b);
    }
    return;
}

//*** UpdateTPMNonce()
// Updates TPM nonce in both internal session or response if applicable.
static void
UpdateCallerNonce(
    SESSION *sessionTable,
    UINT32 sessionCnt
)
{
    UINT32      i;
    for (i = 0; i < sessionCnt; i++)
    {
        // For PW session, nonce is 0.
        if (sessionTable[i].handle == TPM_RS_PW)
        {
            sessionTable[i].nonceCaller.t.size = 0;
            continue;
        }
        // Update nonceCaller.
        CryptGenerateRandom(sessionTable[i].nonceCaller.t.size, sessionTable[i].nonceCaller.t.buffer);
    }
    return;
}

//*** BuildResponseSession()
// Function to build Session buffer in a response.
UINT16
InsertSessionBuffer(
    TPM_ST tag,                    // IN: tag
    TPM_CC commandCode,            // IN: commandCode
    SESSION *sessionTable,
    UINT32 sessionCnt,
    Marshal_Parms *parms,
    const BYTE *parmBuffer,
    UINT32 parmSize,            // IN: size of response parameter buffer
    BYTE **buffer,
    INT32 *size
    )
{
    UINT32 sessionSize = 0;
    BYTE *sessionPtr = *buffer;
    INT32 sessionRemaining = *size;
    UINT32 i;
    TPM2B_DIGEST cpHash = {0};
    TPM2B_DIGEST nameHash = {0};
    TPM_ALG_ID cpHashAlg = TPM_ALG_NULL;
    TPM2B_DIGEST cmdAuths[MAX_SESSION_NUM];

    UNREFERENCED_PARAMETER(tag);

    // Do we have sufficient space to encode the session?
    if (*size < (INT32)(sizeof(UINT32) + sessionCnt * (sizeof(TPM_HANDLE) + sizeof(TPM2B_NONCE) + sizeof(TPMA_SESSION) + sizeof(TPM2B_DIGEST))))
    {
        return 0;
    }

    // For TPM_ST_SESSIONS, there is sessionSize field. Use a dummy for now.
    UINT32_Marshal(&sessionSize, &sessionPtr, &sessionRemaining);

    // Audit session should be updated first regardless of the tag.
    // A command with no session may trigger a change of the exclusivity state.
//    UpdateAuditSessionStatus(commandCode, resParmSize, resParmBuffer);

    // Audit command.
//    CommandAudit(commandCode, resParmSize, resParmBuffer);

    // Process command with sessions.
    pAssert(sessionCnt > 0);

    // Iterate over each session in the command session area, and create
    // corresponding sessions for response.
    for (i = 0; i < sessionCnt; i++)
    {
        // Make sure that continueSession is SET on any Password session.
        // This makes it marginally easier for the management software
        // to keep track of the closed sessions.
        if ((sessionTable[i].attributes.continueSession == CLEAR)
            && (sessionTable[i].handle == TPM_RS_PW))
        {
            sessionTable[i].attributes.continueSession = SET;
        }

        // If the current cpHash is the right one, don't re-compute.
        if ((sessionTable[i].handle != TPM_RS_PW)
            && (cpHashAlg != sessionTable[i].authHashAlg))   // different so compute
        {
            cpHashAlg = sessionTable[i].authHashAlg;   // save this new algID
            ComputeCpHash(cpHashAlg, commandCode, parms, parmSize, parmBuffer, &cpHash, &nameHash);
        }

        // If the session is an audit session, remember the cpHash
        if(sessionTable[i].attributes.audit == SET)
        {
            sessionTable[i].u1.cpHash = cpHash;
        }

        SignAuthSession(i, sessionTable, sessionCnt, parms, &cpHash, &nameHash, &cmdAuths[i]);
    }

    // Assemble Request Sessions.
    for (i = 0; i < sessionCnt; i++)
    {
        sessionSize += TPM_HANDLE_Marshal(&sessionTable[i].handle, &sessionPtr, &sessionRemaining);
        sessionSize += TPM2B_NONCE_Marshal(&sessionTable[i].nonceCaller, &sessionPtr, &sessionRemaining);
        sessionSize += TPMA_SESSION_Marshal(&sessionTable[i].attributes, &sessionPtr, &sessionRemaining);
        sessionSize += TPM2B_DIGEST_Marshal(&cmdAuths[i], &sessionPtr, &sessionRemaining);
    }

    // Fill in the correct session size at the beginning
    sessionPtr = *buffer;
    sessionRemaining = sizeof(UINT32);
    UINT32_Marshal(&sessionSize, &sessionPtr, &sessionRemaining);

    // Fix up the return parameters
    *buffer += sessionSize + sizeof(UINT32);
    *size -= sessionSize + sizeof(UINT32);
    pAssert(*size >= 0);

    return (UINT16)(sessionSize + sizeof(UINT32));
}

//*** ComputeRpHash()
// Function to compute rpHash (Response Parameter Hash). The rpHash is only 
// computed if there is an HMAC authorization session and the return code is 
// TPM_RC_SUCCESS.
static void
ComputeRpHash(
TPM_ALG_ID      hashAlg,            // IN: hash algorithm to compute rpHash
TPM_CC          commandCode,        // IN: commandCode
UINT32          resParmBufferSize,  // IN: size of response parameter buffer
const BYTE     *resParmBuffer,     // IN: response parameter buffer
TPM2B_DIGEST   *rpHash             // OUT: rpHash
)
{
    // The command result in rpHash is always TPM_RC_SUCCESS.
    TPM_RC      responseCode = TPM_RC_SUCCESS;
    HASH_STATE  hashState;

    //   rpHash := hash(responseCode || commandCode || parameters)

    // Initiate hash creation.
    rpHash->t.size = CryptStartHash(hashAlg, &hashState);

    // Add hash constituents.
    CryptUpdateDigestInt(&hashState, sizeof(TPM_RC), &responseCode);
    CryptUpdateDigestInt(&hashState, sizeof(TPM_CC), &commandCode);
    CryptUpdateDigest(&hashState, resParmBufferSize, (BYTE*)resParmBuffer);

    // Complete hash computation.
    CryptCompleteHash2B(&hashState, &rpHash->b);

    return;
}

static TPM_RC
CheckResponseHMAC(
    TPM_CC         commandCode,            // IN: commandCode
    UINT32         sessionIndex,          // IN: session index to be processed
    SESSION       *sessionTable,
    UINT32         sessionCnt,
    Marshal_Parms *parms,
    UINT32         resParmBufferSize,      // IN: size of response parameter buffer
    const BYTE    *resParmBuffer,         // IN: response parameter buffer
    TPM2B_DIGEST  *hmac                   // IN: authHMAC
    )
{
    TPM2B_TYPE(KEY, (sizeof(AUTH_VALUE)* 2));
    TPM2B_KEY        key;       // HMAC key
    BYTE             marshalBuffer[sizeof(TPMA_SESSION)];
    BYTE            *buffer;
    UINT32           marshalSize;
    HMAC_STATE       hmacState;
    TPM2B_DIGEST     rp_hash;
    TPM2B_DIGEST     hmacReference = { 0 };

    UNREFERENCED_PARAMETER(sessionCnt);

    // Compute rpHash.
    ComputeRpHash(sessionTable[sessionIndex].authHashAlg, commandCode, resParmBufferSize,
        resParmBuffer, &rp_hash);

    // Update the audit digest
    if(sessionTable[sessionIndex].attributes.auditReset == SET)
    {
        switch(sessionTable[sessionIndex].authHashAlg)
        {
#if ALG_SHA1 == YES
        case TPM_ALG_SHA1:
            MemorySet(&sessionTable[sessionIndex].u2.auditDigest, 0x00, sizeof(sessionTable[sessionIndex].u2.auditDigest));
            sessionTable[sessionIndex].u2.auditDigest.t.size = SHA1_DIGEST_SIZE;
            break;
#endif
#if ALG_SHA256 == YES
        case TPM_ALG_SHA256:
            MemorySet(&sessionTable[sessionIndex].u2.auditDigest, 0x00, sizeof(sessionTable[sessionIndex].u2.auditDigest));
            sessionTable[sessionIndex].u2.auditDigest.t.size = SHA256_DIGEST_SIZE;
            break;
#endif
#if ALG_SHA384 == YES
        case TPM_ALG_SHA384:
            MemorySet(&sessionTable[sessionIndex].u2.auditDigest, 0x00, sizeof(sessionTable[sessionIndex].u2.auditDigest));
            sessionTable[sessionIndex].u2.auditDigest.t.size = SHA384_DIGEST_SIZE;
            break;
#endif
#if ALG_SHA512 == YES
        case TPM_ALG_SHA512:
            MemorySet(&sessionTable[sessionIndex].u2.auditDigest, 0x00, sizeof(sessionTable[sessionIndex].u2.auditDigest));
            sessionTable[sessionIndex].u2.auditDigest.t.size = SHA512_DIGEST_SIZE;
            break;
#endif
        }
    }
    if(sessionTable[sessionIndex].attributes.audit == SET)
    {
        HASH_STATE  hashState = { 0 };
        sessionTable[sessionIndex].u2.auditDigest.t.size = CryptStartHash(sessionTable[sessionIndex].authHashAlg, &hashState);

        // Add hash constituents.
        CryptUpdateDigest(&hashState, sessionTable[sessionIndex].u2.auditDigest.t.size, sessionTable[sessionIndex].u2.auditDigest.t.buffer);
        CryptUpdateDigest(&hashState, sessionTable[sessionIndex].u1.cpHash.t.size, sessionTable[sessionIndex].u1.cpHash.t.buffer);
        CryptUpdateDigest(&hashState, rp_hash.t.size, rp_hash.t.buffer);

        // Complete hash computation.
        CryptCompleteHash2B(&hashState, &sessionTable[sessionIndex].u2.auditDigest.b);
    }

    // Generate HMAC key
    MemoryCopy2B(&key.b, &sessionTable[sessionIndex].sessionKey.b, sizeof(key.t.buffer));

    // Check if the session has an associated handle and the associated entity is
    // the one that the session is bound to.
    // If not bound, add the authValue of this entity to the HMAC key.
    if((sessionIndex < parms->objectCntIn)
        && (!Memory2BEqual((TPM2B*)&parms->objectTableIn[sessionIndex].obj.name, (TPM2B*)&sessionTable[sessionIndex].u1.boundEntity))
        && (!((HandleGetType(sessionTable[sessionIndex].handle) == TPM_HT_POLICY_SESSION)
           && (sessionTable[sessionIndex].sessionAttributes.isAuthValueNeeded == CLEAR)
           && (sessionTable[sessionIndex].sessionAttributes.isBound == CLEAR))))
    {
        pAssert((sizeof(AUTH_VALUE) + key.t.size) <= sizeof(key.t.buffer));
        MemoryConcat2B((TPM2B*)&key, (TPM2B*)&parms->objectTableIn[sessionIndex].obj.authValue, sizeof(key.t.buffer));
    }

    // if the HMAC key size for a policy session is 0, the response HMAC is 
    // computed according to the input HMAC
    if ((HandleGetType(sessionTable[sessionIndex].handle) == TPM_HT_POLICY_SESSION)
        && (key.t.size == 0)
        && (hmac->t.size == 0))
    {
        return TPM_RC_SUCCESS;
    }

    // Start HMAC computation.
    hmacReference.t.size = CryptStartHMAC2B(sessionTable[sessionIndex].authHashAlg, &key.b, &hmacState);

    // Add hash components.
    CryptUpdateDigest2B(&hmacState, &rp_hash.b);
    CryptUpdateDigest2B(&hmacState, &(sessionTable[sessionIndex].nonceTPM.b));
    CryptUpdateDigest2B(&hmacState, &(sessionTable[sessionIndex].nonceCaller.b));

    // Add session attributes.
    buffer = marshalBuffer;
    marshalSize = TPMA_SESSION_Marshal(&sessionTable[sessionIndex].attributes, &buffer, (INT32*)NULL);
    CryptUpdateDigest(&hmacState, marshalSize, marshalBuffer);

    // Finalize HMAC.
    CryptCompleteHMAC2B(&hmacState, &hmacReference.b);

    return (Memory2BEqual((TPM2B*)hmac, (TPM2B*)&hmacReference)) ? TPM_RC_SUCCESS : TPM_RC_AUTH_FAIL;
}

//*** BuildSingleResponseAuth()
//   Function to compute response for an authorization session.
static TPM_RC
CheckSingleResponseAuth(
    TPM_CC         commandCode,           // IN: commandCode
    UINT32         sessionIndex,          // IN: session index to be processed
    SESSION       *sessionTable,
    UINT32         sessionCnt,
    Marshal_Parms *parms,
    UINT32         resParmBufferSize,     // IN: size of response parameter buffer
    const BYTE    *resParmBuffer,         // IN: response parameter buffer
    TPM2B_AUTH    *auth                   // IN: authHMAC
)
{
    // For password authorization, field is empty.
    if (sessionTable[sessionIndex].handle == TPM_RS_PW)
    {
        if (auth->t.size == 0) return TPM_RC_SUCCESS;
    }
    else
    {
        // If the session is a policy session with isPasswordNeeded SET, the auth
        // field is empty.
        if ((HandleGetType(sessionTable[sessionIndex].handle) == TPM_HT_POLICY_SESSION)
            && (sessionTable[sessionIndex].sessionAttributes.isPasswordNeeded == SET)
            && (auth->t.size == 0)) return TPM_RC_SUCCESS;
        // Compute response HMAC.
        return CheckResponseHMAC(commandCode,
                                 sessionIndex,
                                 sessionTable,
                                 sessionCnt,
                                 parms,
                                 resParmBufferSize,
                                 resParmBuffer,
                                 auth);
    }

    return TPM_RC_AUTH_FAIL;
}

static TPM_RC
ParseSessionBuffer(
    TPM_ST tag,                    // IN: tag
    TPM_CC commandCode,            // IN: commandCode
    SESSION *sessionTable,
    UINT32 sessionCnt,
    Marshal_Parms *parms,
    const BYTE *resParmBuffer,
    UINT32 resParmSize,            // IN: size of response parameter buffer
    BYTE **buffer,
    INT32 *size
    )
{
    TPM_RC           result = TPM_RC_SUCCESS;
    UINT32           i;
    TPM2B_DIGEST     responseAuths[MAX_SESSION_NUM];

    // Read the session data
    if (tag == TPM_ST_SESSIONS)
    {
        for (i = 0; i < sessionCnt; i++)
        {
            result = TPM2B_NONCE_Unmarshal(&sessionTable[i].nonceTPM, buffer, size);
            if (result != TPM_RC_SUCCESS) return result;
            result = TPMA_SESSION_Unmarshal(&sessionTable[i].attributes, buffer, size);
            if (result != TPM_RC_SUCCESS) return result;
            result = TPM2B_DIGEST_Unmarshal(&responseAuths[i], buffer, size);
            if (result != TPM_RC_SUCCESS) return result;
        }
    }

    // Process command with sessions.
    if (tag == TPM_ST_SESSIONS)
    {
        pAssert(sessionCnt > 0);

        // Iterate over each session in the response session area, and check
        // corresponding sessions.
        for (i = 0; i < sessionCnt; i++)
        {
            result = CheckSingleResponseAuth(commandCode, i, sessionTable, sessionCnt, parms, resParmSize, resParmBuffer, &responseAuths[i]);
            if (result != TPM_RC_SUCCESS) return result;
        }
    }

    return result;

}

//*** IsWriteOperation()
// This function indicates if a command is a write operation for an NV Index. 
// It is only used in the context of NV commands. For other commands, the 
// return value of this function has no meaning. The reason for checking on NV 
// Index writes is that an NV Index has separate read and write authorizations.
//
// return type: BOOL
//        TRUE          the command is an NV write operation
//        FALSE         the command is not an NV write operation
static BOOL
    IsWriteOperation(
    TPM_CC command_code
    )
{
    switch(command_code)
    {
    case TPM_CC_NV_Write:
    case TPM_CC_NV_Increment:
    case TPM_CC_NV_SetBits:
    case TPM_CC_NV_Extend:
        return TRUE;
    default:
        return FALSE;
    }
}

//*** IsAuthValueAvailable()
// This function indicates if authValue is available and allowed for USER role
// authorization of an entity.
//
// This function is similar to IsAuthPolicyAvailable() except that it does not
// check the size of the authValue as IsAuthPolicyAvailable() does (a null
// authValue is a valid auth, but a null policy is not a valid policy).
//
// This function does not check that the handle reference is valid or if the entity
// is in an enabled hierarchy. Those checks are assumed to have been performed
// during the handle unmarshaling.
//
// return type: BOOL
//        TRUE          authValue is available
//        FALSE         authValue is not available
static BOOL
    IsAuthValueAvailable(
    ANY_OBJECT     *object,             // IN: associated object
    TPM_CC          commandCode        // IN: commandCode
    )
{
    BOOL             result = FALSE;
    // If a policy session is required, the entity can not be authorized by
    // authValue. However, at this point, the policy session requirement should
    // already have been checked.
//    pAssert(!IsPolicySessionRequired(commandCode, sessionIndex));

    switch(HandleGetType(object->generic.handle))
    {
    case TPM_HT_PERMANENT:
        switch(object->generic.handle)
        {
            // At this point hierarchy availability has already been 
            // checked so primary seed handles are always available here
        case TPM_RH_OWNER:
        case TPM_RH_ENDORSEMENT:
        case TPM_RH_PLATFORM:
            result = TRUE;
            break;
        case TPM_RH_LOCKOUT:
            // At the point when authValue availability is checked, control
            // path has already passed the DA check so LockOut auth is
            // always available here
            result = TRUE;
            break;
        case TPM_RH_NULL:
            // NullAuth is always available.
            result = TRUE;
            break;
        default:
            // Otherwise authValue is not available.
            break;
        }
        break;
    case TPM_HT_TRANSIENT:
    case TPM_HT_PERSISTENT:
        // A persistent object has already been loaded and the internal
        // handle changed.
    {
        // authValue is available for an object if it has its sensitive
        // portion loaded and
        //  1. userWithAuth bit is SET, or
        //  2. ADMIN role is required
        if((object->obj.publicArea.t.publicArea.objectAttributes.userWithAuth == SET) ||
           (object->obj.publicArea.t.publicArea.objectAttributes.adminWithPolicy == CLEAR))
            result = TRUE;
    }
        break;
    case TPM_HT_NV_INDEX:
        // NV Index.
    {
        if(IsWriteOperation(commandCode))
        {
            if(object->nv.nvPublic.t.nvPublic.attributes.TPMA_NV_AUTHWRITE == SET)
                result = TRUE;

        }
        else
        {
            if(object->nv.nvPublic.t.nvPublic.attributes.TPMA_NV_AUTHREAD == SET)
                result = TRUE;
        }
    }
        break;
    case TPM_HT_PCR:
        // PCR handle.
        // authValue is always allowed for PCR
        result = TRUE;
        break;
    default:
        // Otherwise, authValue is not available
        break;
    }
    return result;
}

//*** DecryptSize()
// This function returns the size of the decrypt size field. If command 
// parameter decryption is not allowed, the function returns 0.
// return type: int
//	0		parameter decryption is not allowed
//  2		parameter decryptoin is allowed and buffer ia a TPM2B
//  4		parameter decryption is allowed and buffer is a TPM4B
int
DecryptSize(
TPM_CC      commandCode     // IN: commandCode
)
{
    // This code is written so that there can be full test coverage even though there
    // is currently no command that uses a 4 byte size field in the buffer
    int retVal = 0;
    commandCode -= TPM_CC_FIRST;
    if((s_commandAttributes[commandCode] & DECRYPT_2) != 0)
        retVal = 2;
    else if((s_commandAttributes[commandCode] & DECRYPT_4) != 0)
        retVal = 4;
    return retVal;
}

//*** EncryptSize()
// This function returns the size of the encrypt size field. If response 
// parameter decryption is not allowed, the function returns 0.
// return type: int
//	0		parameter encryption is not allowed
//  2		parameter encryptoin is allowed and buffer ia a TPM2B
//  4		parameter encryption is allowed and buffer is a TPM4B
int
EncryptSize (
    TPM_CC      commandCode     // IN: commandCode
    )
{
    // This code is written so that there can be full test coverage even though there
    // is currently no command that uses a 4 byte size field int he buffer
    int retVal = 0;

    commandCode -= TPM_CC_FIRST;
    if((s_commandAttributes[commandCode] & ENCRYPT_2) != 0)
        retVal = 2;
    else if((s_commandAttributes[commandCode] & ENCRYPT_4) != 0)
        retVal = 4;
    return retVal;
}

//***IsHandleInResponse()
//
// This function indicates if the response has a handle.
//
// This function must not be called if the command is not known to be implemented.
//  
//  return type:        BOOL
//  TRUE                response has a handle
//  FALSE               response does not have a handle
BOOL
IsHandleInResponse(
    TPM_CC      commandCode     // IN: the command to be checked
    )
{
    BOOL retVal;

    commandCode -= TPM_CC_FIRST;

    retVal = (0 != (s_commandAttributes[commandCode] & RESPONSE_HANDLE));
    return retVal;
}

//***IsSessionAllowed()
//
// This function indicates if the command is allowed to have sessions.
//
// This function must not be called if the command is not known to be implemented.
//  
//  return type:        BOOL
//  TRUE                session is allowed with this command
//  FALSE               session is not allowed with this command
BOOL
IsSessionAllowed(
    TPM_CC      commandCode     // IN: the command to be checked
    )
{
    BOOL retVal;
    
    commandCode -= TPM_CC_FIRST;

    retVal = (0 == (s_commandAttributes[commandCode] & NO_SESSIONS));
    return retVal;
}

UINT16
Command_Marshal(
    TPM_CC command_code,
    SESSION *sessionTable,
    UINT32 sessionCnt,
    Parameter_Marshal_fp Parameter_Marshal,
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
    )
{
    BYTE request[REQUEST_BUFFER_SIZE] = {0};
    const BYTE* requestHeaderBuffer = &request[0];
    const BYTE* requestSessionBuffer = &request[REQUEST_HEADER_BUFFER_SIZE];
    const BYTE* requestParameterBuffer = &request[REQUEST_HEADER_BUFFER_SIZE + REQUEST_SESSION_BUFFER_SIZE];
    BYTE* headerPtr = (BYTE*)requestHeaderBuffer;
    BYTE* sessionPtr = (BYTE*)requestSessionBuffer;
    BYTE* parameterPtr = (BYTE*)requestParameterBuffer;
    INT32 headerRemaining = REQUEST_HEADER_BUFFER_SIZE;
    INT32 sessionRemaining = REQUEST_SESSION_BUFFER_SIZE;
    INT32 parameterRemaining = REQUEST_PARAMETER_BUFFER_SIZE;
    UINT32 headerSize = 0;
    UINT32 sessionSize = 0;
    UINT32 parameterSize = 0;
    UINT32 requestSize = 0;
    TPMI_ST_COMMAND_TAG tag = TPM_ST_NO_SESSIONS;

    // Are session allowed?
    if ((!IsSessionAllowed(command_code)) && (sessionCnt != 0)) return TPM_RC_FAILURE;

    // If the context contains sessions set the proper tag
    if (sessionCnt != 0)
    {
        tag = TPM_ST_SESSIONS;
    }

    // Fill in the beginning of the header
    headerSize += TPMI_ST_COMMAND_TAG_Marshal(&tag, &headerPtr, &headerRemaining);
    if(headerRemaining < 0) return TPM_RC_SIZE;
    headerSize += UINT32_Marshal(&requestSize, &headerPtr, &headerRemaining); // Dummy value for now
    if(headerRemaining < 0) return TPM_RC_SIZE;
    headerSize += TPM_CC_Marshal(&command_code, &headerPtr, &headerRemaining);
    if(headerRemaining < 0) return TPM_RC_SIZE;

    // Complete the header with the handles if we have any
    for(UINT32 n = 0; n < parms->objectCntIn; n++)
    {
        headerSize += TPM_HANDLE_Marshal(&parms->objectTableIn[n].generic.handle, &headerPtr, &headerRemaining);
        if (headerRemaining < 0) return TPM_RC_SIZE;
    }

    // Fill in the command parameters
    if(parms->parmIn != NULL)
    {
        parameterSize += Parameter_Marshal(parms, &parameterPtr, &parameterRemaining);
        if(parameterRemaining < 0) return TPM_RC_SIZE;
    }

    // Session nonces should be updated before parameter encryption
    UpdateCallerNonce(sessionTable, sessionCnt);

    // Do parameter encryption if requested
    for(UINT32 i = 0; i < sessionCnt; i++)
    {
        // Decrypt the first parameter if applicable. This should be the last operation
        // in session processing.
        // If the encrypt session is associated with a handle and the handle's 
        // authValue is available, then authValue is concatenated with sessionAuth to 
        // generate encryption key, no matter if the handle is the session bound entity
        // or not.
        if(sessionTable[i].attributes.decrypt == SET)
        {
            TPM2B_AUTH extraKey = {0};

            if((i < parms->objectCntIn) // Session associated to object
                && (IsAuthValueAvailable(&parms->objectTableIn[i], command_code)))
            {
                MemoryCopy2B((TPM2B*)&extraKey, (TPM2B*)&parms->objectTableIn[i].obj.authValue, sizeof(extraKey.t.buffer));
                MemoryRemoveTrailingZeros(&extraKey);
            }

            // Encrypt the first parameter
            CryptParameterEncryption(&sessionTable[i],
                                     (TPM2B*)&sessionTable[i].nonceCaller,
                                     (UINT16)DecryptSize(command_code),
                                     &extraKey,
                                     (BYTE*)requestParameterBuffer);

            // Only one encryption session is defined - we are done after the first one
            break;
        }
    }

    // Fill in the session buffer
    if(tag == TPM_ST_SESSIONS)
    {
        sessionSize = InsertSessionBuffer(tag, command_code, sessionTable, sessionCnt, parms, requestParameterBuffer, parameterSize, &sessionPtr, &sessionRemaining);
    }

    // Write the correct command size
    headerPtr = (BYTE*)&requestHeaderBuffer[sizeof(TPMI_ST_COMMAND_TAG)];
    requestSize = headerSize + sessionSize + parameterSize;
    UINT32_Marshal(&requestSize, &headerPtr, (INT32*)NULL);

    // Marshal the 3 parts out into one contigous piece

    if (buffer != NULL)
    {
        if ((size == 0) || ((*size -= (headerSize + sessionSize + parameterSize)) >= 0))
        {
            MemoryMove(*buffer, requestHeaderBuffer, headerSize, headerSize);
            *buffer += headerSize;
            MemoryMove(*buffer, requestSessionBuffer, sessionSize, sessionSize);
            *buffer += sessionSize;
            MemoryMove(*buffer, requestParameterBuffer, parameterSize, parameterSize);
            *buffer += parameterSize;
        }
        pAssert((size == NULL) || (*size >= 0));
    }
    return (UINT16)(headerSize + sessionSize + parameterSize);
}

TPM_RC
Command_Unmarshal(
    TPM_CC command_code,
    SESSION *sessionTable,
    UINT32 sessionCnt,
    Parameter_Unmarshal_fp Parameter_Unmarshal,
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
)
{
    TPM_RC result = TPM_RC_SUCCESS;
    TPMI_ST_COMMAND_TAG tag = TPM_ST_NO_SESSIONS;
    UINT32 returnedResponseSize = 0;
    TPM_RC responseCode = 0;

//    BYTE* headerPtr = *buffer;
    BYTE* sessionPtr = NULL;
    BYTE* parameterPtr = NULL;
    INT32 headerRemaining = sizeof(TPMI_ST_COMMAND_TAG)+sizeof(UINT32)+sizeof(TPM_RC);
    INT32 sessionRemaining = 0;
    INT32 parameterRemaining = 0;
    UINT32 headerSize = sizeof(TPMI_ST_COMMAND_TAG)+sizeof(UINT32)+sizeof(TPM_RC);
    UINT32 sessionSize = 0;
    UINT32 parameterSize = 0;

    // Are session allowed?
    if ((!IsSessionAllowed(command_code)) && (sessionCnt != 0)) return TPM_RC_FAILURE;

    // Make sure we can alt least read the header
    if(*size < headerRemaining) return TPM_RC_SIZE;

    // Process response tag and size
    result = TPMI_ST_COMMAND_TAG_Unmarshal(&tag, buffer, &headerRemaining);
    if (result != TPM_RC_SUCCESS) return result;
    result = UINT32_Unmarshal(&returnedResponseSize, buffer, &headerRemaining);
    if (result != TPM_RC_SUCCESS) return result;
    if (returnedResponseSize != (UINT32)*size) return TPM_RC_SIZE;
    result = UINT32_Unmarshal(&responseCode, buffer, &headerRemaining);
    if (result != TPM_RC_SUCCESS) return result;
    if (responseCode != TPM_RC_SUCCESS) return responseCode;

    // Add the response handle size to the header
    if(IsHandleInResponse(command_code))
    {
        headerRemaining += sizeof(TPM_HANDLE);
        headerSize += sizeof(TPM_HANDLE);
        if(parms->objectCntOut != 1) return TPM_RC_FAILURE;
    }
    else
    {
        if(parms->objectCntOut != 0) return TPM_RC_FAILURE;
    }

    // Retrieve the return handles
    for(UINT32 n = 0; n < parms->objectCntOut; n++)
    {
        result = TPM_HANDLE_Unmarshal(&parms->objectTableOut[n].generic.handle, buffer, &headerRemaining);
        if (result != TPM_RC_SUCCESS) return result;
    }

    // Header should be empty now
    if(headerRemaining != 0) return TPM_RC_FAILURE;
    *size -= headerSize;

    // Read and check the parameter size if present
    if (tag == TPM_ST_SESSIONS)
    {
        result = UINT32_Unmarshal(&parameterSize, buffer, size);
        if (result != TPM_RC_SUCCESS) return result;
        parameterRemaining = (INT32)parameterSize;
        if ((INT32)parameterSize > *size) return TPM_RC_SIZE;
        parameterPtr = *buffer;
        *size -= parameterSize;
        *buffer += parameterSize;

        sessionSize = *size;
        sessionRemaining = sessionSize;
        sessionPtr = &parameterPtr[parameterSize];

        // Jump ahead and verify the sessions at the end
        if (sessionSize < 5) return TPM_RC_SIZE;
        result = ParseSessionBuffer(tag, command_code, sessionTable, sessionCnt, parms, parameterPtr, parameterSize, buffer, &sessionRemaining);
        if (result != TPM_RC_SUCCESS) return result;
        if (sessionRemaining != 0) return TPM_RC_FAILURE;

        // Do parameter decryption if requested
        for(UINT32 i = 0; i < sessionCnt; i++)
        {
            // Decrypt the first parameter if applicable. This should be the last operation
            // in session processing.
            // If the encrypt session is associated with a handle and the handle's 
            // authValue is available, then authValue is concatenated with sessionAuth to 
            // generate encryption key, no matter if the handle is the session bound entity
            // or not.
            if(sessionTable[i].attributes.encrypt == SET)
            {
                TPM2B_AUTH extraKey = {0};

                if((i < parms->objectCntIn) // Session associated to object
                    && (IsAuthValueAvailable(&parms->objectTableIn[i], command_code)))
                {
                    MemoryCopy2B((TPM2B*)&extraKey, (TPM2B*)&parms->objectTableIn[i].obj.authValue, sizeof(extraKey.t.buffer));
                    MemoryRemoveTrailingZeros(&extraKey);
                }

                // Encrypt the first parameter
                CryptParameterDecryption(&sessionTable[i],
                                         (TPM2B*)&sessionTable[i].nonceCaller,
                                         parameterSize,
                                         (UINT16)EncryptSize(command_code),
                                         &extraKey,
                                         parameterPtr);

                // Only one encryption session is defined - we are done after the first one
                break;
            }
        }
    }
    else
    {
        parameterPtr = *buffer;
        parameterSize = *size;
        parameterRemaining = parameterSize;
        *size = 0;
    }

    // Read the parameters and make sure we consume all of them
    *buffer = parameterPtr;
    result = Parameter_Unmarshal(parms, buffer, &parameterRemaining);
    if (result != TPM_RC_SUCCESS) return result;
    if (parameterRemaining != 0) return TPM_RC_SIZE;

    // Move the pointer to the end of the processed area
    *buffer += sessionSize;
    *size = 0;

    // Sanitize the closed sessions
    for(UINT32 i = 0; i < sessionCnt; i++)
    {
        if(sessionTable[i].attributes.continueSession == CLEAR)
        {
            MemorySet(&sessionTable[i], 0x00, sizeof(sessionTable[i]));
        }
    }

    return TPM_RC_SUCCESS;
}
