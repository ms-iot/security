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

#include "stdafx.h"

typedef struct {
    BCRYPT_HASH_HANDLE hHash;
} OSSL_HASH_STATE;

TBS_HCONTEXT g_hTbs = NULL;
TPM2B_AUTH g_LockoutAuth = {0};
TPM2B_AUTH g_EndorsementAuth = {0};
TPM2B_AUTH g_StorageAuth = {0};

BCRYPT_ALG_HANDLE g_hRngAlg = NULL;
BCRYPT_ALG_HANDLE g_hAlg[HASH_COUNT + 1] = {0};
BCRYPT_ALG_HANDLE g_hRsaAlg = NULL;
BCRYPT_ALG_HANDLE g_hAesAlg = NULL;

//** Random Number Generation

BOOL
_cpri__RngStartup(
    void
    )
{
    return (BCryptOpenAlgorithmProvider(&g_hRngAlg, BCRYPT_RNG_ALGORITHM, NULL, 0) == ERROR_SUCCESS);
}

//***_cpri__StirRandom()
// Set random entropy
CRYPT_RESULT
_cpri__StirRandom(
    INT32      entropySize,
    BYTE       *entropy
    )
{
    UNREFERENCED_PARAMETER(entropySize);
    UNREFERENCED_PARAMETER(entropy);
    return CRYPT_SUCCESS;
}

//***_cpri__GenerateRandom()
// Generate a 'randomSize' number or random bytes.
UINT16
_cpri__GenerateRandom(
    INT32       randomSize,  
    BYTE       *buffer
    )
{
    //
    // We don't do negative sizes or ones that are too large
    if (randomSize < 0 || randomSize > UINT16_MAX)
        return 0;
    return (BCryptGenRandom(g_hRngAlg, buffer, randomSize, 0) == ERROR_SUCCESS) ? (UINT16)randomSize : 0;
}

//** Hash Functions
//*** _cpri__HashStartup()
// Function that is called to initialize the hash service. In this implementation,
// this function does nothing but it is called by the CryptUtilStartup() function
// and must be present.
BOOL
_cpri__HashStartup(
    void
    )
{
#pragma warning (disable:4127)
#pragma warning (disable:6237)
    if ((ALG_SHA1 == YES) &&
        (BCryptOpenAlgorithmProvider(&g_hAlg[0], BCRYPT_SHA1_ALGORITHM, NULL, 0 )) != 0)
    {
        return FALSE;
    }

    if ((ALG_SHA256 == YES) &&
        (BCryptOpenAlgorithmProvider(&g_hAlg[1], BCRYPT_SHA256_ALGORITHM, NULL, 0)) != 0)
    {
        return FALSE;
    }

    if ((ALG_SHA384 == YES) &&
        (BCryptOpenAlgorithmProvider(&g_hAlg[2], BCRYPT_SHA384_ALGORITHM, NULL, 0 )) != 0)
    {
        return FALSE;
    }

    if ((ALG_SHA512 == YES) && 
        (BCryptOpenAlgorithmProvider(&g_hAlg[3], BCRYPT_SHA512_ALGORITHM, NULL, 0)) != 0)
    {
        return FALSE;
    }
#pragma warning (default:4127)
#pragma warning (default:6237)

    return TRUE;
}

UINT32
GetHashIndex(
    TPM_ALG_ID hashAlg
);

const HASH_INFO *
GetHashInfoPointer(
    TPM_ALG_ID hashAlg
);

//*** _cpri__CopyHashState
// This function is used to "clone" a CPRI_HASH_STATE.
// The return value is the size of the state.
UINT16
_cpri__CopyHashState (
    CPRI_HASH_STATE *out,       // OUT: destination of the state
    CPRI_HASH_STATE *in         // IN: source of the state
    )
{
    OSSL_HASH_STATE *i = (OSSL_HASH_STATE *)&in->state;
    OSSL_HASH_STATE *o = (OSSL_HASH_STATE *)&out->state;
    UINT16 retVal = 0;

    if (BCryptDuplicateHash(i->hHash, &o->hHash, NULL, 0, 0) != 0)
    {
        goto Cleanup;
    }

    out->hashAlg = in->hashAlg;
    retVal = sizeof(CPRI_HASH_STATE);
Cleanup:
    return retVal;
}


//*** _cpri__StartHash()
// Functions starts a hash stack
// Start a hash stack and returns the digest size. As a side effect, the
// value of 'stateSize' in hashState is updated to indicate the number of bytes
// of state that were saved. This function calls GetHashServer() and that function
// will put the TPM into failure mode if the hash algorithm is not supported.
// return type:     CRTYP_RESULT
//  0           hash is TPM_ALG_NULL
// >0           digest size
UINT16
_cpri__StartHash(
    TPM_ALG_ID hashAlg,         // IN: hash algorithm
    BOOL sequence,              // IN: TRUE if the state should be saved
    CPRI_HASH_STATE *hashState  // OUT: the state of hash stack.
    )
{
    OSSL_HASH_STATE *state = (OSSL_HASH_STATE *)&hashState->state;
    const HASH_INFO *hashInfo = GetHashInfoPointer(hashAlg);
    UINT16 retVal = 0;

    // Not supported
    pAssert(sequence == FALSE);

    // Valid algorithm?
    if (hashInfo == NULL)
    {
        goto Cleanup;
    }

    if (BCryptCreateHash(g_hAlg[GetHashIndex(hashAlg)], &state->hHash, NULL, 0, NULL, 0, 0) != 0)
    {
        goto Cleanup;
    }

    retVal = _cpri__GetDigestSize(hashAlg);
    hashState->hashAlg = hashAlg;

Cleanup:
    return retVal;
}


//*** _cpri__UpdateHash()
// Add data to a hash or HMAC stack.
//
void
_cpri__UpdateHash(
    CPRI_HASH_STATE *hashState, // IN: the hash context information
    UINT32 dataSize,            // IN: the size of data to be added to the digest
    BYTE *data                  // IN: data to be hashed
    )
{
    OSSL_HASH_STATE *state = (OSSL_HASH_STATE *)&hashState->state;
    BCryptHashData(state->hHash, data, dataSize, 0);
}


//*** _cpri__CompleteHash()
// Complete a hash or HMAC computation. This function will place the smaller of
// 'digestSize' or the size of the digest in 'dOut'. The number of bytes in the
// placed in the buffer is returned. If there is a failure, the returned value
// is <= 0.
//  return type: UINT16
//       0      no data returned
//      > 0     the number of bytes in the digest
UINT16
_cpri__CompleteHash(
    CPRI_HASH_STATE *hashState,      // IN: the state of hash stack
    UINT32 dOutSize,                 // IN: size of digest buffer
    __in_ecount(dOutSize) BYTE *dOut // OUT: hash digest
    )
{
    OSSL_HASH_STATE *state = (OSSL_HASH_STATE *)&hashState->state;
    UINT16           retVal = 0;
    UINT32           hLen;
    UINT32           cbResult;
    BYTE             digest[64];

    if((BCryptGetProperty(state->hHash, BCRYPT_HASH_LENGTH, (PUCHAR)&hLen, sizeof(hLen), (ULONG*)&cbResult, 0) != 0) ||
       (sizeof(digest) < hLen))
    {
        goto Cleanup;
    }

    if(BCryptFinishHash(state->hHash, digest, hLen, 0) != 0)
    {
        goto Cleanup;
    }
    memcpy(dOut, digest, dOutSize);
    retVal = (UINT16)hLen;

Cleanup:
    return retVal;
}


//*** _cpri__HashBlock()
// Start a hash, hash a single block, update 'digest' and return the size of
// the results.
//
// The "digestSize" parameter can be smaller than the digest. If so, only the more
// significant bytes are returned.
// return type: UINT16
//  >= 0        number of bytes in 'digest' (may be zero)
UINT16
_cpri__HashBlock(
    TPM_ALG_ID hashAlg,   // IN: The hash algorithm
    UINT32 dataSize,      // IN: size of buffer to hash
    BYTE* data,           // IN: the buffer to hash
    UINT32 digestSize,    // IN: size of the digest buffer
    BYTE* digest          // OUT: hash digest
    )
{
    const HASH_INFO *hashInfo = GetHashInfoPointer(hashAlg);
    BCRYPT_HASH_HANDLE hHash = NULL;
    UINT16 retVal = 0;

    // Valid algorithm?
    if (hashInfo == NULL)
    {
        goto Cleanup;
    }

    if (BCryptCreateHash(g_hAlg[GetHashIndex(hashAlg)], &hHash, NULL, 0, NULL, 0, 0) != 0)
    {
        goto Cleanup;
    }
    if (BCryptHashData(hHash, data, dataSize, 0) != 0)
    {
        goto Cleanup;
    }
    if (BCryptFinishHash(hHash, digest, digestSize, 0) != 0)
    {
        goto Cleanup;
    }

    retVal = _cpri__GetDigestSize(hashAlg);
Cleanup:
    return retVal;
}

//*** _cpri__RsaStartup()
// Function that is called to initialize the hash service. In this implementation,
// this function does nothing but it is called by the CryptUtilStartup() function
// and must be present.
BOOL
_cpri__RsaStartup(
    void
    )
{
    return (BCryptOpenAlgorithmProvider(&g_hRsaAlg, BCRYPT_RSA_ALGORITHM, NULL, 0) == 0);
}

//*** _cpri__TestKeyRSA()
// This function computes the private exponent 'de' = 1 mod ('p'-1)*('q'-1)
// The inputs are the public modulus and one of the primes or two primes.
//
// If both primes are provided, the public modulus is computed. If only one
// prime is provided, the second prime is computed. In either case, a private
// exponent is produced and placed in 'd'.
//
// If no modular inverse exists, then CRYPT_PARAMETER is returned.
//
// return type: CRYPT_RESULT
//   CRYPT_SUCCESS           private exponent (d) was generated
//   CRYPT_PARAMETER         one or more parameters are invalid
//
CRYPT_RESULT
_cpri__TestKeyRSA(
    TPM2B* d,         // OUT: the address to receive the private exponent
    UINT32 exponent,  // IN: the public modulus
    TPM2B* publicKey, // IN: the public key
    TPM2B* prime1,    // IN: a first prime
    TPM2B* prime2     // IN: an optional second prime
    )
{
    CRYPT_RESULT        retVal = CRYPT_SUCCESS;
    BYTE                pbKey[sizeof(BCRYPT_RSAKEY_BLOB)+sizeof(UINT32)+(MAX_RSA_KEY_BITS / 8 * 2) + (MAX_RSA_KEY_BITS / 8 / 2 * 5)] = {0};
    ULONG               cbKey = sizeof(BCRYPT_RSAKEY_BLOB);
    BCRYPT_RSAKEY_BLOB *pKey = (BCRYPT_RSAKEY_BLOB *)pbKey;
    BCRYPT_KEY_HANDLE   hKey = NULL;

    pKey->Magic = BCRYPT_RSAPRIVATE_MAGIC;
    pKey->BitLength = publicKey->size * 8;
    if(exponent == RSA_DEFAULT_PUBLIC_EXPONENT)
    {
        BYTE exp[3] = {0x01, 0x00, 0x01};
        pKey->cbPublicExp = sizeof(exp);
        MemoryCopy(&pbKey[sizeof(BCRYPT_RSAKEY_BLOB)], exp, pKey->cbPublicExp, sizeof(pbKey) - cbKey);
    }
    else
    {
        BYTE exp[4] = {0};
        pKey->cbPublicExp = sizeof(exponent);
        UINT32_TO_BYTE_ARRAY(exponent, exp);
        MemoryCopy(&pbKey[sizeof(BCRYPT_RSAKEY_BLOB)], exp, pKey->cbPublicExp, sizeof(pbKey)-cbKey);
    }
    cbKey += pKey->cbPublicExp;
    pKey->cbModulus = publicKey->size;
    MemoryCopy(&pbKey[cbKey], publicKey->buffer, pKey->cbModulus, sizeof(pbKey)-cbKey);
    cbKey += pKey->cbModulus;
    pKey->cbPrime1 = prime1->size;
    MemoryCopy(&pbKey[cbKey], prime1->buffer, pKey->cbPrime1, sizeof(pbKey)-cbKey);
    cbKey += pKey->cbPrime1;
    pKey->cbPrime2 = prime2->size;
    MemoryCopy(&pbKey[cbKey], prime2->buffer, pKey->cbPrime2, sizeof(pbKey)-cbKey);
    cbKey += pKey->cbPrime2;

    if(BCryptImportKeyPair(g_hRsaAlg, NULL, BCRYPT_RSAPRIVATE_BLOB, &hKey, (PUCHAR)pbKey, cbKey, 0) != 0)
    {
        retVal = CRYPT_FAIL;
        goto Cleanup;
    }
    if(BCryptExportKey(hKey, NULL, BCRYPT_RSAFULLPRIVATE_BLOB, (PUCHAR)pbKey, sizeof(pbKey), &cbKey, 0) != 0)
    {
        retVal = CRYPT_FAIL;
        goto Cleanup;
    }

    d->size = (UINT16)pKey->cbModulus;
    MemoryCopy(d->buffer, &pbKey[sizeof(BCRYPT_RSAKEY_BLOB) + pKey->cbPublicExp + pKey->cbModulus + (3 * pKey->cbPrime1) + (2 * pKey->cbPrime2)], pKey->cbModulus, sizeof(d->buffer));

Cleanup:
    return retVal;
}

//*** RSAEP()
// This function performs the RSAEP operation defined in PKCS#1v2.1. It is
// an exponentiation of a value ('m') with the public exponent ('e'), modulo
// the public ('n').
//
//  return type: CRYPT_RESULT
//      CRYPT_SUCCESS       encryption complete
//      CRYPT_PARAMETER     number to exponentiate is larger than the modulus
//
CRYPT_RESULT
RSAEP(
    UINT32 dInOutSize,  // OUT size of the encrypted block
    BYTE* dInOut,       // OUT: the encrypted data
    RSA_KEY* key        // IN: the key to use
    )
{
    CRYPT_RESULT retVal = CRYPT_SUCCESS;
    BYTE         pbKey[sizeof(BCRYPT_RSAKEY_BLOB)+sizeof(UINT32)+(MAX_RSA_KEY_BITS / 8)] = {0};
    ULONG        cbKey = sizeof(BCRYPT_RSAKEY_BLOB);
    BCRYPT_RSAKEY_BLOB *pKey = (BCRYPT_RSAKEY_BLOB *)pbKey;
    BCRYPT_KEY_HANDLE hKey = NULL;


    pKey->Magic = BCRYPT_RSAPUBLIC_MAGIC;
    pKey->BitLength = key->publicKey->size * 8;
    if(key->exponent == RSA_DEFAULT_PUBLIC_EXPONENT)
    {
        BYTE exp[3] = {0x01, 0x00, 0x01};
        pKey->cbPublicExp = sizeof(exp);
        MemoryCopy(&pbKey[sizeof(BCRYPT_RSAKEY_BLOB)], exp, pKey->cbPublicExp, sizeof(pbKey)-cbKey);
    }
    else
    {
        BYTE exp[4] = {0};
        pKey->cbPublicExp = sizeof(key->exponent);
        UINT32_TO_BYTE_ARRAY(key->exponent, exp);
        MemoryCopy(&pbKey[sizeof(BCRYPT_RSAKEY_BLOB)], exp, pKey->cbPublicExp, sizeof(pbKey)-cbKey);
    }
    cbKey += pKey->cbPublicExp;
    pKey->cbModulus = key->publicKey->size;
    MemoryCopy(&pbKey[cbKey], key->publicKey->buffer, pKey->cbModulus, sizeof(pbKey)-cbKey);
    cbKey += pKey->cbModulus;
    pKey->cbPrime1 = 0;
    pKey->cbPrime2 = 0;

    if(BCryptImportKeyPair(g_hRsaAlg, NULL, BCRYPT_RSAPUBLIC_BLOB, &hKey, (PUCHAR)pbKey, cbKey, 0) != 0)
    {
        retVal = CRYPT_FAIL;
        goto Cleanup;
    }
    if(BCryptEncrypt(hKey, dInOut, dInOutSize, NULL, NULL, 0, dInOut, dInOutSize, (ULONG*)&dInOutSize, BCRYPT_PAD_NONE) != 0)
    {
        retVal = CRYPT_FAIL;
        goto Cleanup;
    }
    if(BCryptDestroyKey(hKey))
    {
        retVal = CRYPT_FAIL;
        goto Cleanup;
    }

Cleanup:
    return retVal;
}

//*** RSADP()
// This function performs the RSADP operation defined in PKCS#1v2.1. It is
// an exponentiation of a value ('c') with the private exponent ('d'), modulo
// the public modulus ('n'). The decryption is in place.
//
// This function also checks the size of the private key. If the size indicates 
// that only a prime value is present, the key is converted to being a private 
// exponent.
//
//  return type: CRYPT_RESULT
//      CRYPT_SUCCESS       decryption succeeded
//      CRYPT_PARAMETER     the value to decrypt is larger than the modulus
//
CRYPT_RESULT
RSADP(
    UINT32 dInOutSize,   // IN/OUT: size of decrypted data
    BYTE* dInOut,        // IN/OUT: the decrypted data
    RSA_KEY* key         // IN: the key
    )
{
    CRYPT_RESULT        retVal = CRYPT_SUCCESS;
    BYTE                pbKey[sizeof(BCRYPT_RSAKEY_BLOB)+sizeof(UINT32)+(MAX_RSA_KEY_BITS / 8 * 2) + (MAX_RSA_KEY_BITS / 8 / 2 * 5)] = {0};
    ULONG               cbKey = sizeof(BCRYPT_RSAKEY_BLOB);
    BCRYPT_RSAKEY_BLOB *pKey = (BCRYPT_RSAKEY_BLOB *)pbKey;
    BCRYPT_KEY_HANDLE   hKey = NULL;

    pKey->Magic = BCRYPT_RSAPRIVATE_MAGIC;
    pKey->BitLength = key->publicKey->size * 8;
    if(key->exponent == RSA_DEFAULT_PUBLIC_EXPONENT)
    {
        BYTE exp[3] = {0x01, 0x00, 0x01};
        pKey->cbPublicExp = sizeof(exp);
        MemoryCopy(&pbKey[sizeof(BCRYPT_RSAKEY_BLOB)], exp, pKey->cbPublicExp, sizeof(pbKey)-cbKey);
    }
    else
    {
        BYTE exp[4] = {0};
        pKey->cbPublicExp = sizeof(key->exponent);
        UINT32_TO_BYTE_ARRAY(key->exponent, exp);
        MemoryCopy(&pbKey[sizeof(BCRYPT_RSAKEY_BLOB)], exp, pKey->cbPublicExp, sizeof(pbKey)-cbKey);
    }
    cbKey += pKey->cbPublicExp;
    pKey->cbModulus = key->publicKey->size;
    MemoryCopy(&pbKey[cbKey], key->publicKey->buffer, pKey->cbModulus, sizeof(pbKey)-cbKey);
    cbKey += pKey->cbModulus;
    pKey->cbPrime1 = 0;
    pKey->cbPrime2 = 0;
    MemoryCopy(&pbKey[cbKey], key->privateKey->buffer, pKey->cbModulus, sizeof(pbKey)-cbKey);
    cbKey += pKey->cbModulus;

    if(BCryptImportKeyPair(g_hRsaAlg, NULL, BCRYPT_RSAFULLPRIVATE_BLOB, &hKey, (PUCHAR)pbKey, cbKey, 0) != 0)
    {
        retVal = CRYPT_FAIL;
        goto Cleanup;
    }
    if(BCryptDecrypt(hKey, dInOut, dInOutSize, NULL, NULL, 0, dInOut, dInOutSize, (ULONG*)&dInOutSize, BCRYPT_PAD_NONE) != 0)
    {
        retVal = CRYPT_FAIL;
        goto Cleanup;
    }
    if(BCryptDestroyKey(hKey))
    {
        retVal = CRYPT_FAIL;
        goto Cleanup;
    }

Cleanup:
    return retVal;
}

//*** _cpri_SymStartup()
BOOL
_cpri__SymStartup(
    void
    )
{
    return (BCryptOpenAlgorithmProvider(&g_hAesAlg, BCRYPT_AES_ALGORITHM, NULL, 0) == 0);
}

CRYPT_RESULT
AES_create_key(
    const unsigned char* userKey,
    const int bits,
    PVOID* key
    )
{
    CRYPT_RESULT                 retVal = CRYPT_SUCCESS;
    BYTE                         pbKey[sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + MAX_AES_KEY_BYTES] = {0};
    ULONG                        cbKey = sizeof(BCRYPT_KEY_DATA_BLOB_HEADER);
    BCRYPT_KEY_DATA_BLOB_HEADER *pKey = (BCRYPT_KEY_DATA_BLOB_HEADER *)pbKey;
    BCRYPT_KEY_HANDLE            hKey = NULL;

    pAssert((bits / 8) <= MAX_AES_KEY_BYTES);

    pKey->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
    pKey->dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;
    pKey->cbKeyData = bits / 8;
    #pragma prefast(suppress: 26000, "Validated that pbKey <= MAX_AES_KEY_BYTES.")
    memcpy(&pbKey[cbKey], userKey, pKey->cbKeyData);
    cbKey += pKey->cbKeyData;

    if(BCryptImportKey(g_hAesAlg, NULL, BCRYPT_KEY_DATA_BLOB, &hKey, NULL, 0, pbKey, cbKey, 0) != 0)
    {
        retVal = CRYPT_FAIL;
        goto Cleanup;
    }
    *key = (PVOID)hKey;
Cleanup:
    return retVal;
}

CRYPT_RESULT
AES_destroy_key(
    PVOID key
    )
{
    CRYPT_RESULT retVal = CRYPT_SUCCESS;
    if(BCryptDestroyKey((BCRYPT_KEY_HANDLE)key))
    {
        retVal = CRYPT_FAIL;
        goto Cleanup;
    }

Cleanup:
    return retVal;
}

CRYPT_RESULT
AES_encrypt(
    const unsigned char* in,
    unsigned char* out,
    PVOID key
    )
{
    CRYPT_RESULT retVal = CRYPT_SUCCESS;
    BCRYPT_KEY_HANDLE keyCopy = NULL;
    BYTE iv[16] = { 0 };
    ULONG cbResult = 0;

    if((BCryptDuplicateKey(key, &keyCopy, NULL, 0, 0) != 0) ||
       (BCryptEncrypt((BCRYPT_KEY_HANDLE)keyCopy, (PUCHAR)in, MAX_AES_BLOCK_SIZE_BYTES, NULL, iv, sizeof(iv), out, MAX_AES_BLOCK_SIZE_BYTES, &cbResult, 0) != 0))
    {
        retVal = CRYPT_FAIL;
        goto Cleanup;
    }
Cleanup:
    if(keyCopy != NULL)
    {
        BCryptDestroyKey(keyCopy);
        keyCopy = NULL;
    }
    return retVal;
}

CRYPT_RESULT
AES_decrypt(
    const unsigned char* in,
    unsigned char* out,
    PVOID key
    )
{
    CRYPT_RESULT retVal = CRYPT_SUCCESS;
    ULONG        cbResult = 0;
    if(BCryptDecrypt((BCRYPT_KEY_HANDLE)key, (PUCHAR)in, 16, NULL, NULL, 0, out, 16, &cbResult, 0) != 0)
    {
        retVal = CRYPT_FAIL;
        goto Cleanup;
    }
Cleanup:
    return retVal;
}

UINT32
PlatformSubmitTPM20Command(
    BOOL CloseContext,
    BYTE* pbCommand,
    UINT32 cbCommand,
    BYTE* pbResponse,
    UINT32 cbResponse,
    UINT32* pcbResponse
    )
{
    TBS_RESULT result = NULL;
    if (g_hTbs == NULL)
    {
        TBS_CONTEXT_PARAMS2 params = {TPM_VERSION_20, 0, 0, 1};
        if ((result = Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&params, &g_hTbs)) != TBS_SUCCESS)
        {
            return (UINT32)result;
        }
    }

    *pcbResponse = cbResponse;
    if ((result = Tbsip_Submit_Command(g_hTbs,
                                       TBS_COMMAND_LOCALITY_ZERO,
                                       TBS_COMMAND_PRIORITY_NORMAL,
                                       pbCommand,
                                       cbCommand,
                                       pbResponse,
                                       pcbResponse)) != TBS_SUCCESS)
    {
        return (UINT32)result;
    }

    if (CloseContext != FALSE)
    {
        Tbsip_Context_Close(g_hTbs);
        g_hTbs = NULL;
    }
    return (UINT32)result;
}

void
PlattformRetrieveAuthValues(
    void
    )
{
    WCHAR authValue[255] = L"";
    DWORD authValueSize = sizeof(authValue);
    DWORD allowedSize = sizeof(g_LockoutAuth.t.buffer);

    if((RegGetValueW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI\\Admin", L"OwnerAuthFull", RRF_RT_REG_SZ, NULL, authValue, &authValueSize) != ERROR_SUCCESS) ||
       (!CryptStringToBinaryW(authValue, 0, CRYPT_STRING_BASE64, g_LockoutAuth.t.buffer, &allowedSize, NULL, NULL)))
    {
        MemorySet(&g_LockoutAuth, 0x00, sizeof(g_LockoutAuth));
    }
    g_LockoutAuth.t.size = (UINT16)allowedSize;

    authValueSize = sizeof(authValue);
    allowedSize = sizeof(g_StorageAuth.t.buffer);
    if((RegGetValueW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI\\Admin", L"StorageOwnerAuth", RRF_RT_REG_SZ, NULL, authValue, &authValueSize) != ERROR_SUCCESS) ||
       (!CryptStringToBinaryW(authValue, 0, CRYPT_STRING_BASE64, g_StorageAuth.t.buffer, &allowedSize, NULL, NULL)))
    {
        MemorySet(&g_StorageAuth, 0x00, sizeof(g_StorageAuth));
    }
    g_StorageAuth.t.size = (UINT16)allowedSize;

    authValueSize = sizeof(authValue);
    allowedSize = sizeof(g_EndorsementAuth.t.buffer);
    if((RegGetValueW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI\\Endorsement", L"EndorsementAuth", RRF_RT_REG_SZ, NULL, authValue, &authValueSize) != ERROR_SUCCESS) ||
        (!CryptStringToBinaryW(authValue, 0, CRYPT_STRING_BASE64, g_EndorsementAuth.t.buffer, &allowedSize, NULL, NULL)))
    {
        MemorySet(&g_EndorsementAuth, 0x00, sizeof(g_EndorsementAuth));
    }
    g_EndorsementAuth.t.size = (UINT16)allowedSize;
}

int
TpmFail(
    const char* function,
    int line,
    int code
    )
{
    UNREFERENCED_PARAMETER(function);
    UNREFERENCED_PARAMETER(line);
    UNREFERENCED_PARAMETER(code);

    assert(0);
    return 0;
}

void
_cpri__PlatformRelease(
    void
    )
{
    if (g_hTbs != NULL)
    {
        Tbsip_Context_Close(g_hTbs);
        g_hTbs = NULL;
    }

    _cpri__PlatformReleaseCrypt();
}

void
_cpri__PlatformReleaseCrypt(
    void
    )
{
    if (g_hRngAlg != NULL)
    {
        BCryptCloseAlgorithmProvider(g_hRngAlg, 0);
        g_hRngAlg = NULL;
    }
    for (UINT32 n = 0; n < HASH_COUNT + 1; n++)
    {
        if (g_hAlg[n] != NULL)
        {
            BCryptCloseAlgorithmProvider(g_hAlg[n], 0);
            g_hAlg[n] = NULL;
        }
    }
    if (g_hRsaAlg != NULL)
    {
        BCryptCloseAlgorithmProvider(g_hRsaAlg, 0);
        g_hRsaAlg = NULL;
    }
    if (g_hAesAlg != NULL)
    {
        BCryptCloseAlgorithmProvider(g_hAesAlg, 0);
        g_hAesAlg = NULL;
    }
}
