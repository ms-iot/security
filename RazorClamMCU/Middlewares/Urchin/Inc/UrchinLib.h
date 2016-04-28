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

#ifndef __URCHINLIB_H__
#define __URCHINLIB_H__

#pragma once

#ifndef _BASETYPES_H
#define _BASETYPES_H

typedef uint8_t                  UINT8;
typedef uint8_t                  BYTE;
typedef int8_t                   INT8;
typedef int                      BOOL;
typedef uint16_t                 UINT16;
typedef int16_t                  INT16;
typedef uint32_t                 UINT32;
typedef int32_t                  INT32;
typedef uint64_t                 UINT64;
typedef int64_t                  INT64;
typedef void                     *PVOID;

#if defined(TRUE)
#undef TRUE
#endif

#if defined FALSE
#undef FALSE
#endif

#ifndef max
#define max(a,b)            (((a) > (b)) ? (a) : (b))
#endif

#ifndef min
#define min(a,b)            (((a) < (b)) ? (a) : (b))
#endif

typedef int BOOL;
#define FALSE   ((BOOL)0)
#define TRUE    ((BOOL)1)

typedef struct {
    UINT16        size;
    BYTE          buffer[1];
} TPM2B;

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(param) (void)param
#endif

#endif

#ifndef     _IMPLEMENTATION_H
#define     _IMPLEMENTATION_H

#ifndef     ALG_ALL
#define     ALG_ALL     NO
#endif

//
// Part2AnnexParser Generated (Jun 14, 2013 04:05:28 PM)
//
#ifdef TRUE
#undef TRUE
#endif

#ifdef FALSE
#undef FALSE
#endif

// Table 205 -- SHA1 Hash Values
#define    SHA1_DIGEST_SIZE    20
#define    SHA1_BLOCK_SIZE     64
#define    SHA1_DER_SIZE       15
#define    SHA1_DER            {\
    0x30,0x21,0x30,0x09,0x06,0x05,0x2B,0x0E,0x03,0x02,0x1A,0x05,0x00,0x04,0x14}

// Table 206 -- SHA256 Hash Values
#define    SHA256_DIGEST_SIZE    32
#define    SHA256_BLOCK_SIZE     64
#define    SHA256_DER_SIZE       19
#define    SHA256_DER            {\
    0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,\
    0x05,0x00,0x04,0x20}


// Table 207 -- SHA384 Hash Values
#define    SHA384_DIGEST_SIZE    48
#define    SHA384_BLOCK_SIZE     128
#define    SHA384_DER_SIZE       19
#define    SHA384_DER            {\
    0x30,0x41,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02,\
    0x05,0x00,0x04,0x30}


// Table 208 -- SHA512 Hash Values
#define    SHA512_DIGEST_SIZE    64
#define    SHA512_BLOCK_SIZE     128
#define    SHA512_DER_SIZE       19
#define    SHA512_DER            {\
    0x30,0x51,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03,\
    0x05,0x00,0x04,0x40}


// Table 209 -- SM3_256 Hash Values
#define    SM3_256_DIGEST_SIZE    32
#define    SM3_256_BLOCK_SIZE     64
#define    SM3_256_DER_SIZE       18
#define    SM3_256_DER            {\
    0x30,0x30,0x30,0x0c,0x06,0x08,0x2a,0x81,0x1c,0x81,0x45,0x01,0x83,0x11,0x05,\
    0x00,0x04,0x20}


// Table 210 -- Architectural Limits Values
#define    MAX_SESSION_NUMBER    3


// Table 211 -- Logic Values
#define    YES      1
#define    NO       0
#define    TRUE     1
#define    FALSE    0
#define    SET      1
#define    CLEAR    0


// Table 212 -- Processor Values
#define    BIG_ENDIAN_TPM       NO    // 0
#define    LITTLE_ENDIAN_TPM    YES    // 1
#define    NO_AUTO_ALIGN        NO    // 0


// Table 213 -- Implemented Algorithms
#define    ALG_RSA               YES    // 1
#define    ALG_SHA1              YES    // 1
#define    ALG_HMAC              YES    // 1
#define    ALG_AES               YES    // 1
#define    ALG_MGF1              YES    // 1
#define    ALG_XOR               YES    // 1
#define    ALG_KEYEDHASH         YES    // 1
#define    ALG_SHA256            YES    // 1
#define    ALG_SHA384            YES    // 0
#define    ALG_SHA512            YES    // 0
#define    ALG_SM3_256           YES    // 0
#define    ALG_SM4               NO    // 0
#define    ALG_RSASSA            YES    // 1
#define    ALG_RSAES             YES    // 1
#define    ALG_RSAPSS            YES    // 1
#define    ALG_OAEP              YES    // 1
#define    ALG_ECC               YES    // 1
#define    ALG_ECDH              YES    // 1
#define    ALG_ECDSA             YES    // 1
#define    ALG_ECDAA             YES    // 1
#define    ALG_SM2               NO    // 0
#define    ALG_ECSCHNORR         NO    // 0
#define    ALG_ECMQV             NO    // 0
#define    ALG_SYMCIPHER         YES    // 1
#define    ALG_KDF1_SP800_56a    YES    // 1
#define    ALG_KDF2              NO    // 0
#define    ALG_KDF1_SP800_108    YES    // 1
#define    ALG_CTR               YES    // 1
#define    ALG_OFB               YES    // 1
#define    ALG_CBC               YES    // 1
#define    ALG_CFB               YES    // 1
#define    ALG_ECB               YES    // 1


// Table 214 -- Implemented Commands
#define    CC_ActivateCredential            YES    // 1
#define    CC_Certify                       YES    // 1
#define    CC_CertifyCreation               YES    // 1
#define    CC_ChangeEPS                     YES    // 1
#define    CC_ChangePPS                     YES    // 1
#define    CC_Clear                         YES    // 1
#define    CC_ClearControl                  YES    // 1
#define    CC_ClockRateAdjust               YES    // 1
#define    CC_ClockSet                      YES    // 1
#define    CC_Commit                        ALG_ECC    // 1
#define    CC_ContextLoad                   YES    // 1
#define    CC_ContextSave                   YES    // 1
#define    CC_Create                        YES    // 1
#define    CC_CreatePrimary                 YES    // 1
#define    CC_DictionaryAttackLockReset     YES    // 1
#define    CC_DictionaryAttackParameters    YES    // 1
#define    CC_Duplicate                     YES    // 1
#define    CC_ECC_Parameters                ALG_ECC    // 1
#define    CC_ECDH_KeyGen                   ALG_ECC    // 1
#define    CC_ECDH_ZGen                     ALG_ECC    // 1
#define    CC_EncryptDecrypt                YES    // 1
#define    CC_EventSequenceComplete         YES    // 1
#define    CC_EvictControl                  YES    // 1
#define    CC_FieldUpgradeData              NO    // 0
#define    CC_FieldUpgradeStart             NO    // 0
#define    CC_FirmwareRead                  NO    // 0
#define    CC_FlushContext                  YES    // 1
#define    CC_GetCapability                 YES    // 1
#define    CC_GetCommandAuditDigest         YES    // 1
#define    CC_GetRandom                     YES    // 1
#define    CC_GetSessionAuditDigest         YES    // 1
#define    CC_GetTestResult                 YES    // 1
#define    CC_GetTime                       YES    // 1
#define    CC_Hash                          YES    // 1
#define    CC_HashSequenceStart             YES    // 1
#define    CC_HierarchyChangeAuth           YES    // 1
#define    CC_HierarchyControl              YES    // 1
#define    CC_HMAC                          YES    // 1
#define    CC_HMAC_Start                    YES    // 1
#define    CC_Import                        YES    // 1
#define    CC_IncrementalSelfTest           YES    // 1
#define    CC_Load                          YES    // 1
#define    CC_LoadExternal                  YES    // 1
#define    CC_MakeCredential                YES    // 1
#define    CC_NV_Certify                    YES    // 1
#define    CC_NV_ChangeAuth                 YES    // 1
#define    CC_NV_DefineSpace                YES    // 1
#define    CC_NV_Extend                     YES    // 1
#define    CC_NV_GlobalWriteLock            YES    // 1
#define    CC_NV_Increment                  YES    // 1
#define    CC_NV_Read                       YES    // 1
#define    CC_NV_ReadLock                   YES    // 1
#define    CC_NV_ReadPublic                 YES    // 1
#define    CC_NV_SetBits                    YES    // 1
#define    CC_NV_UndefineSpace              YES    // 1
#define    CC_NV_UndefineSpaceSpecial       YES    // 1
#define    CC_NV_Write                      YES    // 1
#define    CC_NV_WriteLock                  YES    // 1
#define    CC_ObjectChangeAuth              YES    // 1
#define    CC_PCR_Allocate                  YES    // 1
#define    CC_PCR_Event                     YES    // 1
#define    CC_PCR_Extend                    YES    // 1
#define    CC_PCR_Read                      YES    // 1
#define    CC_PCR_Reset                     YES    // 1
#define    CC_PCR_SetAuthPolicy             YES    // 1
#define    CC_PCR_SetAuthValue              YES    // 1
#define    CC_PolicyAuthorize               YES    // 1
#define    CC_PolicyAuthValue               YES    // 1
#define    CC_PolicyCommandCode             YES    // 1
#define    CC_PolicyCounterTimer            YES    // 1
#define    CC_PolicyCpHash                  YES    // 1
#define    CC_PolicyDuplicationSelect       YES    // 1
#define    CC_PolicyGetDigest               YES    // 1
#define    CC_PolicyLocality                YES    // 1
#define    CC_PolicyNameHash                YES    // 1
#define    CC_PolicyNV                      YES    // 1
#define    CC_PolicyOR                      YES    // 1
#define    CC_PolicyPassword                YES    // 1
#define    CC_PolicyPCR                     YES    // 1
#define    CC_PolicyPhysicalPresence        YES    // 1
#define    CC_PolicyRestart                 YES    // 1
#define    CC_PolicySecret                  YES    // 1
#define    CC_PolicySigned                  YES    // 1
#define    CC_PolicyTicket                  YES    // 1
#define    CC_PP_Commands                   YES    // 1
#define    CC_Quote                         YES    // 1
#define    CC_ReadClock                     YES    // 1
#define    CC_ReadPublic                    YES    // 1
#define    CC_Rewrap                        YES    // 1
#define    CC_RSA_Decrypt                   ALG_RSA    // 1
#define    CC_RSA_Encrypt                   ALG_RSA    // 1
#define    CC_SelfTest                      YES    // 1
#define    CC_SequenceComplete              YES    // 1
#define    CC_SequenceUpdate                YES    // 1
#define    CC_SetAlgorithmSet               YES    // 1
#define    CC_SetCommandCodeAuditStatus     YES    // 1
#define    CC_SetPrimaryPolicy              YES    // 1
#define    CC_Shutdown                      YES    // 1
#define    CC_Sign                          YES    // 1
#define    CC_StartAuthSession              YES    // 1
#define    CC_Startup                       YES    // 1
#define    CC_StirRandom                    YES    // 1
#define    CC_TestParms                     YES    // 1
#define    CC_Unseal                        YES    // 1
#define    CC_VerifySignature               YES    // 1
#define    CC_ZGen_2Phase                   YES    // 1
#define    CC_EC_Ephemeral                  YES    // 1


// Table 215 -- RSA Algorithm Constants
#define    RSA_KEY_SIZES_BITS    {1024, 2048}    // {1024,2048}
#define    MAX_RSA_KEY_BITS      2048
#define    MAX_RSA_KEY_BYTES     ((MAX_RSA_KEY_BITS + 7) / 8)    // 256


// Table 216 -- ECC Algorithm Constants
#define    ECC_CURVES            {\
    TPM_ECC_NIST_P256,TPM_ECC_BN_P256,TPM_ECC_SM2_P256}#define    ECC_KEY_SIZES_BITS    {256}
#define    MAX_ECC_KEY_BITS      256
#define    MAX_ECC_KEY_BYTES     ((MAX_ECC_KEY_BITS + 7) / 8)    // 32


// Table 217 -- AES Algorithm Constants
#define    AES_KEY_SIZES_BITS          {128}
#define    MAX_AES_KEY_BITS            128
#define    MAX_AES_BLOCK_SIZE_BYTES    16
#define    MAX_AES_KEY_BYTES           ((MAX_AES_KEY_BITS + 7) / 8)    // 16


// Table 218 -- SM4 Algorithm Constants
#define    SM4_KEY_SIZES_BITS          {128}
#define    MAX_SM4_KEY_BITS            128
#define    MAX_SM4_BLOCK_SIZE_BYTES    16
#define    MAX_SM4_KEY_BYTES           ((MAX_SM4_KEY_BITS + 7) / 8)    // 16


// Table 219 -- Symmetric Algorithm Constants
#define    MAX_SYM_KEY_BITS      MAX_AES_KEY_BITS    // 128
#define    MAX_SYM_KEY_BYTES     MAX_AES_KEY_BYTES    // 16
#define    MAX_SYM_BLOCK_SIZE    MAX_AES_BLOCK_SIZE_BYTES    // 16


// Table 220 -- Implementation Values
#define    FIELD_UPGRADE_IMPLEMENTED        NO    // 0
typedef    UINT16                           BSIZE;
#define    BUFFER_ALIGNMENT                 4
#define    IMPLEMENTATION_PCR               24
#define    PLATFORM_PCR                     24
#define    DRTM_PCR                         17
#define    NUM_LOCALITIES                   5
#define    MAX_HANDLE_NUM                   3
#define    MAX_ACTIVE_SESSIONS              0x01000000
typedef    UINT16                           CONTEXT_SLOT;
typedef    UINT64                           CONTEXT_COUNTER;
#define    MAX_LOADED_SESSIONS              3
#define    MAX_SESSION_NUM                  3
#define    MAX_LOADED_OBJECTS               0x01000000
#define    MIN_EVICT_OBJECTS                2
#define    PCR_SELECT_MIN                   ((PLATFORM_PCR+7)/8)    // 3
#define    PCR_SELECT_MAX                   ((IMPLEMENTATION_PCR+7)/8)    // 3
#define    NUM_POLICY_PCR_GROUP             1
#define    NUM_AUTHVALUE_PCR_GROUP          1
#define    MAX_CONTEXT_SIZE                 4000
#define    MAX_DIGEST_BUFFER                1024
#define    MAX_NV_INDEX_SIZE                1024
#define    MAX_CAP_BUFFER                   1024
#define    NV_MEMORY_SIZE                   16384
#define    NUM_STATIC_PCR                   16
#define    MAX_ALG_LIST_SIZE                64
#define    TIMER_PRESCALE                   100000
#define    PRIMARY_SEED_SIZE                32
#define    CONTEXT_ENCRYPT_ALG              TPM_ALG_AES
#define    CONTEXT_ENCRYPT_KEY_BITS         MAX_SYM_KEY_BITS    // 128
#define    CONTEXT_ENCRYPT_KEY_BYTES        ((CONTEXT_ENCRYPT_KEY_BITS+7)/8)
#define    CONTEXT_INTEGRITY_HASH_ALG       TPM_ALG_SHA256
#define    CONTEXT_INTEGRITY_HASH_SIZE      SHA256_DIGEST_SIZE    // 32
#define    PROOF_SIZE                       CONTEXT_INTEGRITY_HASH_SIZE    // 32
#define    NV_CLOCK_UPDATE_INTERVAL         12
#define    NUM_POLICY_PCR                   1
#define    MAX_COMMAND_SIZE                 4096
#define    MAX_RESPONSE_SIZE                4096
#define    ORDERLY_BITS                     8
#define    MAX_ORDERLY_COUNT                ((1 << ORDERLY_BITS) - 1)    // 255
#define    ALG_ID_FIRST                     TPM_ALG_FIRST
#define    ALG_ID_LAST                      TPM_ALG_LAST
#define    MAX_SYM_DATA                     128
#define    MAX_RNG_ENTROPY_SIZE             64
#define    RAM_INDEX_SPACE                  512
#define    RSA_DEFAULT_PUBLIC_EXPONENT      0x00010001
#define    ENABLE_PCR_NO_INCREMENT          YES    // 1
#define    CRT_FORMAT_RSA                   YES    // 1
#define    PRIVATE_VENDOR_SPECIFIC_BYTES    (\
    (MAX_RSA_KEY_BYTES/2)*(3+CRT_FORMAT_RSA*2))

#define TPM_MAX_HASH_BLOCK_SIZE 0
#define TPM_MAX_DIGEST_SIZE     0

#if (SHA1_BLOCK_SIZE * ALG_SHA1) > TPM_MAX_HASH_BLOCK_SIZE
#undef  TPM_MAX_HASH_BLOCK_SIZE
#define TPM_MAX_HASH_BLOCK_SIZE SHA1_BLOCK_SIZE
#endif

#if (SHA1_DIGEST_SIZE * ALG_SHA1) > TPM_MAX_DIGEST_SIZE
#undef  TPM_MAX_DIGEST_SIZE
#define TPM_MAX_DIGEST_SIZE SHA1_DIGEST_SIZE
#endif

#if (SHA256_BLOCK_SIZE * ALG_SHA256) > TPM_MAX_HASH_BLOCK_SIZE
#undef  TPM_MAX_HASH_BLOCK_SIZE
#define TPM_MAX_HASH_BLOCK_SIZE SHA256_BLOCK_SIZE
#endif

#if (SHA256_DIGEST_SIZE * ALG_SHA256) > TPM_MAX_DIGEST_SIZE
#undef  TPM_MAX_DIGEST_SIZE
#define TPM_MAX_DIGEST_SIZE SHA256_DIGEST_SIZE
#endif

#if (SHA384_BLOCK_SIZE * ALG_SHA384) > TPM_MAX_HASH_BLOCK_SIZE
#undef  TPM_MAX_HASH_BLOCK_SIZE
#define TPM_MAX_HASH_BLOCK_SIZE SHA384_BLOCK_SIZE
#endif

#if (SHA384_DIGEST_SIZE * ALG_SHA384) > TPM_MAX_DIGEST_SIZE
#undef  TPM_MAX_DIGEST_SIZE
#define TPM_MAX_DIGEST_SIZE SHA384_DIGEST_SIZE
#endif

#if (SHA512_BLOCK_SIZE * ALG_SHA512) > TPM_MAX_HASH_BLOCK_SIZE
#undef  TPM_MAX_HASH_BLOCK_SIZE
#define TPM_MAX_HASH_BLOCK_SIZE SHA512_BLOCK_SIZE
#endif

#if (SHA512_DIGEST_SIZE * ALG_SHA512) > TPM_MAX_DIGEST_SIZE
#undef  TPM_MAX_DIGEST_SIZE
#define TPM_MAX_DIGEST_SIZE SHA512_DIGEST_SIZE
#endif

#if (SM3_256_BLOCK_SIZE * ALG_SM3_256) > TPM_MAX_HASH_BLOCK_SIZE
#undef  TPM_MAX_HASH_BLOCK_SIZE
#define TPM_MAX_HASH_BLOCK_SIZE SM3_256_BLOCK_SIZE
#endif

#if (SM3_256_DIGEST_SIZE * ALG_SM3_256) > TPM_MAX_DIGEST_SIZE
#undef  TPM_MAX_DIGEST_SIZE
#define TPM_MAX_DIGEST_SIZE SM3_256_DIGEST_SIZE
#endif

#define HASH_COUNT (ALG_SHA1+ALG_SHA256+ALG_SHA384+ALG_SHA512+ALG_SM3_256)

//
// Part2Parser Generated (Jun 14, 2013 04:05:29 PM)
//

// Table 7 -- TPM_ALG_ID Constants <I/O,S>
typedef UINT16 TPM_ALG_ID;

#define    TPM_ALG_ERROR             (TPM_ALG_ID)(0x0000)        // a: ; D: 
#define    TPM_ALG_FIRST             (TPM_ALG_ID)(0x0001)        // a: ; D: 
#if ALG_RSA == YES || ALG_ALL == YES
#define    TPM_ALG_RSA               (TPM_ALG_ID)(0x0001)        // a: A O; D: 
#endif
#if ALG_SHA1 == YES || ALG_ALL == YES
#define    TPM_ALG_SHA               (TPM_ALG_ID)(0x0004)        // a: H; D: 
#endif
#if ALG_SHA1 == YES || ALG_ALL == YES
#define    TPM_ALG_SHA1              (TPM_ALG_ID)(0x0004)        // a: H; D: 
#endif
#if ALG_HMAC == YES || ALG_ALL == YES
#define    TPM_ALG_HMAC              (TPM_ALG_ID)(0x0005)        // a: H X; D: 
#endif
#if ALG_AES == YES || ALG_ALL == YES
#define    TPM_ALG_AES               (TPM_ALG_ID)(0x0006)        // a: S; D: 
#endif
#if ALG_MGF1 == YES || ALG_ALL == YES
#define    TPM_ALG_MGF1              (TPM_ALG_ID)(0x0007)        // a: H M; D: 
#endif
#if ALG_KEYEDHASH == YES || ALG_ALL == YES
#define    TPM_ALG_KEYEDHASH         (TPM_ALG_ID)(0x0008)        // a: H E X O; D: 
#endif
#if ALG_XOR == YES || ALG_ALL == YES
#define    TPM_ALG_XOR               (TPM_ALG_ID)(0x000A)        // a: H S; D: 
#endif
#if ALG_SHA256 == YES || ALG_ALL == YES
#define    TPM_ALG_SHA256            (TPM_ALG_ID)(0x000B)        // a: H; D: 
#endif
#if ALG_SHA384 == YES || ALG_ALL == YES
#define    TPM_ALG_SHA384            (TPM_ALG_ID)(0x000C)        // a: H; D: 
#endif
#if ALG_SHA512 == YES || ALG_ALL == YES
#define    TPM_ALG_SHA512            (TPM_ALG_ID)(0x000D)        // a: H; D: 
#endif
#define    TPM_ALG_NULL              (TPM_ALG_ID)(0x0010)        // a: ; D: 
#if ALG_SM3_256 == YES || ALG_ALL == YES
#define    TPM_ALG_SM3_256           (TPM_ALG_ID)(0x0012)        // a: H; D: 
#endif
//#if ALG_SM4 == YES || ALG_ALL == YES
#define    TPM_ALG_SM4               (TPM_ALG_ID)(0x0013)        // a: S; D: 
//#endif
#if ALG_RSASSA == YES || ALG_ALL == YES
#define    TPM_ALG_RSASSA            (TPM_ALG_ID)(0x0014)        // a: A X; D: RSA 
#endif
#if ALG_RSAES == YES || ALG_ALL == YES
#define    TPM_ALG_RSAES             (TPM_ALG_ID)(0x0015)        // a: A E; D: RSA 
#endif
#if ALG_RSAPSS == YES || ALG_ALL == YES
#define    TPM_ALG_RSAPSS            (TPM_ALG_ID)(0x0016)        // a: A X; D: RSA 
#endif
#if ALG_OAEP == YES || ALG_ALL == YES
#define    TPM_ALG_OAEP              (TPM_ALG_ID)(0x0017)        // a: A E; D: RSA 
#endif
#if ALG_ECDSA == YES || ALG_ALL == YES
#define    TPM_ALG_ECDSA             (TPM_ALG_ID)(0x0018)        // a: A X; D: ECC 
#endif
#if ALG_ECDH == YES || ALG_ALL == YES
#define    TPM_ALG_ECDH              (TPM_ALG_ID)(0x0019)        // a: A M; D: ECC 
#endif
#if ALG_ECDAA == YES || ALG_ALL == YES
#define    TPM_ALG_ECDAA             (TPM_ALG_ID)(0x001A)        // a: A X; D: ECC 
#endif
//#if ALG_SM2 == YES || ALG_ALL == YES
#define    TPM_ALG_SM2               (TPM_ALG_ID)(0x001B)        // a: A X E; D: ECC 
//#endif
#if ALG_ECSCHNORR == YES || ALG_ALL == YES
#define    TPM_ALG_ECSCHNORR         (TPM_ALG_ID)(0x001C)        // a: A X; D: ECC 
#endif
#if ALG_ECMQV == YES || ALG_ALL == YES
#define    TPM_ALG_ECMQV             (TPM_ALG_ID)(0x001D)        // a: A E; D: ECC 
#endif
#if ALG_KDF1_SP800_56a == YES || ALG_ALL == YES
#define    TPM_ALG_KDF1_SP800_56a    (TPM_ALG_ID)(0x0020)        // a: H M; D: ECC 
#endif
#if ALG_KDF2 == YES || ALG_ALL == YES
#define    TPM_ALG_KDF2              (TPM_ALG_ID)(0x0021)        // a: H M; D: 
#endif
#if ALG_KDF1_SP800_108 == YES || ALG_ALL == YES
#define    TPM_ALG_KDF1_SP800_108    (TPM_ALG_ID)(0x0022)        // a: H M; D: 
#endif
#if ALG_ECC == YES || ALG_ALL == YES
#define    TPM_ALG_ECC               (TPM_ALG_ID)(0x0023)        // a: A O; D: 
#endif
#if ALG_SYMCIPHER == YES || ALG_ALL == YES
#define    TPM_ALG_SYMCIPHER         (TPM_ALG_ID)(0x0025)        // a: O; D: 
#endif
#if ALG_CTR == YES || ALG_ALL == YES
#define    TPM_ALG_CTR               (TPM_ALG_ID)(0x0040)        // a: S E; D: 
#endif
#if ALG_OFB == YES || ALG_ALL == YES
#define    TPM_ALG_OFB               (TPM_ALG_ID)(0x0041)        // a: S E; D: 
#endif
#if ALG_CBC == YES || ALG_ALL == YES
#define    TPM_ALG_CBC               (TPM_ALG_ID)(0x0042)        // a: S E; D: 
#endif
#if ALG_CFB == YES || ALG_ALL == YES
#define    TPM_ALG_CFB               (TPM_ALG_ID)(0x0043)        // a: S E; D: 
#endif
#if ALG_ECB == YES || ALG_ALL == YES
#define    TPM_ALG_ECB               (TPM_ALG_ID)(0x0044)        // a: S E; D: 
#endif
#define    TPM_ALG_LAST              (TPM_ALG_ID)(0x0044)        // a: ; D: 

// Table 8 -- TPM_ECC_CURVE Constants <I/O,S>
typedef UINT16 TPM_ECC_CURVE;

#define    TPM_ECC_NONE         (TPM_ECC_CURVE)(0x0000)    
#define    TPM_ECC_NIST_P192    (TPM_ECC_CURVE)(0x0001)    
#define    TPM_ECC_NIST_P224    (TPM_ECC_CURVE)(0x0002)    
#define    TPM_ECC_NIST_P256    (TPM_ECC_CURVE)(0x0003)    
#define    TPM_ECC_NIST_P384    (TPM_ECC_CURVE)(0x0004)    
#define    TPM_ECC_NIST_P521    (TPM_ECC_CURVE)(0x0005)    
#define    TPM_ECC_BN_P256      (TPM_ECC_CURVE)(0x0010)    
#define    TPM_ECC_BN_P638      (TPM_ECC_CURVE)(0x0011)    
#define    TPM_ECC_SM2_P256     (TPM_ECC_CURVE)(0x0020)    

#endif //_IMPLEMENTATION_H

#ifndef _CAPABILITIES_H
#define _CAPABILITIES_H

#define    MAX_CAP_DATA         (MAX_CAP_BUFFER-sizeof(TPM_CAP)-sizeof(UINT32))
#define    MAX_CAP_ALGS         (MAX_CAP_DATA/sizeof(TPMS_ALG_PROPERTY))
#define    MAX_CAP_HANDLES      (MAX_CAP_DATA/sizeof(TPM_HANDLE))
#define    MAX_CAP_CC           (MAX_CAP_DATA/sizeof(TPM_CC))
#define    MAX_TPM_PROPERTIES   (MAX_CAP_DATA/sizeof(TPMS_TAGGED_PROPERTY))
#define    MAX_PCR_PROPERTIES   (MAX_CAP_DATA/sizeof(TPMS_TAGGED_PCR_SELECT))
#define    MAX_ECC_CURVES       (MAX_CAP_DATA/sizeof(TPM_ECC_CURVE))

#endif //_CAPABILITIES_H

#ifndef _TPM_TYPES_H
#define _TPM_TYPES_H

// Table 3 -- BaseTypes BaseTypes <I/O>

// Table 4 -- DocumentationClarity Types <I/O>
typedef UINT32    TPM_ALGORITHM_ID;
typedef UINT32    TPM_MODIFIER_INDICATOR;
typedef UINT32    TPM_AUTHORIZATION_SIZE;
typedef UINT32    TPM_PARAMETER_SIZE;
typedef UINT16    TPM_KEY_SIZE;
typedef UINT16    TPM_KEY_BITS;
typedef UINT32 TPM_SPEC;

#define    TPM_SPEC_FAMILY         (TPM_SPEC)(0x322E3000)    
#define    TPM_SPEC_LEVEL          (TPM_SPEC)(00)    
#define    TPM_SPEC_VERSION        (TPM_SPEC)(98)    
#define    TPM_SPEC_YEAR           (TPM_SPEC)(2013)    
#define    TPM_SPEC_DAY_OF_YEAR    (TPM_SPEC)(74)    




// Table 6 -- TPM_GENERATED Constants <O,S>
typedef UINT32 TPM_GENERATED;

#define    TPM_GENERATED_VALUE    (TPM_GENERATED)(0xff544347)    




// Table 11 -- TPM_CC Constants <I/O,S>
typedef UINT32 TPM_CC;

#define    TPM_CC_FIRST                         (TPM_CC)(0x0000011F)    
#define    TPM_CC_PP_FIRST                      (TPM_CC)(0x0000011F)    
#define    TPM_CC_NV_UndefineSpaceSpecial       (TPM_CC)(0x0000011F)    
#define    TPM_CC_EvictControl                  (TPM_CC)(0x00000120)    
#define    TPM_CC_HierarchyControl              (TPM_CC)(0x00000121)    
#define    TPM_CC_NV_UndefineSpace              (TPM_CC)(0x00000122)    
#define    TPM_CC_ChangeEPS                     (TPM_CC)(0x00000124)    
#define    TPM_CC_ChangePPS                     (TPM_CC)(0x00000125)    
#define    TPM_CC_Clear                         (TPM_CC)(0x00000126)    
#define    TPM_CC_ClearControl                  (TPM_CC)(0x00000127)    
#define    TPM_CC_ClockSet                      (TPM_CC)(0x00000128)    
#define    TPM_CC_HierarchyChangeAuth           (TPM_CC)(0x00000129)    
#define    TPM_CC_NV_DefineSpace                (TPM_CC)(0x0000012A)    
#define    TPM_CC_PCR_Allocate                  (TPM_CC)(0x0000012B)    
#define    TPM_CC_PCR_SetAuthPolicy             (TPM_CC)(0x0000012C)    
#define    TPM_CC_PP_Commands                   (TPM_CC)(0x0000012D)    
#define    TPM_CC_SetPrimaryPolicy              (TPM_CC)(0x0000012E)    
#define    TPM_CC_FieldUpgradeStart             (TPM_CC)(0x0000012F)    
#define    TPM_CC_ClockRateAdjust               (TPM_CC)(0x00000130)    
#define    TPM_CC_CreatePrimary                 (TPM_CC)(0x00000131)    
#define    TPM_CC_NV_GlobalWriteLock            (TPM_CC)(0x00000132)    
#define    TPM_CC_PP_LAST                       (TPM_CC)(0x00000132)    
#define    TPM_CC_GetCommandAuditDigest         (TPM_CC)(0x00000133)    
#define    TPM_CC_NV_Increment                  (TPM_CC)(0x00000134)    
#define    TPM_CC_NV_SetBits                    (TPM_CC)(0x00000135)    
#define    TPM_CC_NV_Extend                     (TPM_CC)(0x00000136)    
#define    TPM_CC_NV_Write                      (TPM_CC)(0x00000137)    
#define    TPM_CC_NV_WriteLock                  (TPM_CC)(0x00000138)    
#define    TPM_CC_DictionaryAttackLockReset     (TPM_CC)(0x00000139)    
#define    TPM_CC_DictionaryAttackParameters    (TPM_CC)(0x0000013A)    
#define    TPM_CC_NV_ChangeAuth                 (TPM_CC)(0x0000013B)    
#define    TPM_CC_PCR_Event                     (TPM_CC)(0x0000013C)    
#define    TPM_CC_PCR_Reset                     (TPM_CC)(0x0000013D)    
#define    TPM_CC_SequenceComplete              (TPM_CC)(0x0000013E)    
#define    TPM_CC_SetAlgorithmSet               (TPM_CC)(0x0000013F)    
#define    TPM_CC_SetCommandCodeAuditStatus     (TPM_CC)(0x00000140)    
#define    TPM_CC_FieldUpgradeData              (TPM_CC)(0x00000141)    
#define    TPM_CC_IncrementalSelfTest           (TPM_CC)(0x00000142)    
#define    TPM_CC_SelfTest                      (TPM_CC)(0x00000143)    
#define    TPM_CC_Startup                       (TPM_CC)(0x00000144)    
#define    TPM_CC_Shutdown                      (TPM_CC)(0x00000145)    
#define    TPM_CC_StirRandom                    (TPM_CC)(0x00000146)    
#define    TPM_CC_ActivateCredential            (TPM_CC)(0x00000147)    
#define    TPM_CC_Certify                       (TPM_CC)(0x00000148)    
#define    TPM_CC_PolicyNV                      (TPM_CC)(0x00000149)    
#define    TPM_CC_CertifyCreation               (TPM_CC)(0x0000014A)    
#define    TPM_CC_Duplicate                     (TPM_CC)(0x0000014B)    
#define    TPM_CC_GetTime                       (TPM_CC)(0x0000014C)    
#define    TPM_CC_GetSessionAuditDigest         (TPM_CC)(0x0000014D)    
#define    TPM_CC_NV_Read                       (TPM_CC)(0x0000014E)    
#define    TPM_CC_NV_ReadLock                   (TPM_CC)(0x0000014F)    
#define    TPM_CC_ObjectChangeAuth              (TPM_CC)(0x00000150)    
#define    TPM_CC_PolicySecret                  (TPM_CC)(0x00000151)    
#define    TPM_CC_Rewrap                        (TPM_CC)(0x00000152)    
#define    TPM_CC_Create                        (TPM_CC)(0x00000153)    
#define    TPM_CC_ECDH_ZGen                     (TPM_CC)(0x00000154)    
#define    TPM_CC_HMAC                          (TPM_CC)(0x00000155)    
#define    TPM_CC_Import                        (TPM_CC)(0x00000156)    
#define    TPM_CC_Load                          (TPM_CC)(0x00000157)    
#define    TPM_CC_Quote                         (TPM_CC)(0x00000158)    
#define    TPM_CC_RSA_Decrypt                   (TPM_CC)(0x00000159)    
#define    TPM_CC_HMAC_Start                    (TPM_CC)(0x0000015B)    
#define    TPM_CC_SequenceUpdate                (TPM_CC)(0x0000015C)    
#define    TPM_CC_Sign                          (TPM_CC)(0x0000015D)    
#define    TPM_CC_Unseal                        (TPM_CC)(0x0000015E)    
#define    TPM_CC_PolicySigned                  (TPM_CC)(0x00000160)    
#define    TPM_CC_ContextLoad                   (TPM_CC)(0x00000161)    
#define    TPM_CC_ContextSave                   (TPM_CC)(0x00000162)    
#define    TPM_CC_ECDH_KeyGen                   (TPM_CC)(0x00000163)    
#define    TPM_CC_EncryptDecrypt                (TPM_CC)(0x00000164)    
#define    TPM_CC_FlushContext                  (TPM_CC)(0x00000165)    
#define    TPM_CC_LoadExternal                  (TPM_CC)(0x00000167)    
#define    TPM_CC_MakeCredential                (TPM_CC)(0x00000168)    
#define    TPM_CC_NV_ReadPublic                 (TPM_CC)(0x00000169)    
#define    TPM_CC_PolicyAuthorize               (TPM_CC)(0x0000016A)    
#define    TPM_CC_PolicyAuthValue               (TPM_CC)(0x0000016B)    
#define    TPM_CC_PolicyCommandCode             (TPM_CC)(0x0000016C)    
#define    TPM_CC_PolicyCounterTimer            (TPM_CC)(0x0000016D)    
#define    TPM_CC_PolicyCpHash                  (TPM_CC)(0x0000016E)    
#define    TPM_CC_PolicyLocality                (TPM_CC)(0x0000016F)    
#define    TPM_CC_PolicyNameHash                (TPM_CC)(0x00000170)    
#define    TPM_CC_PolicyOR                      (TPM_CC)(0x00000171)    
#define    TPM_CC_PolicyTicket                  (TPM_CC)(0x00000172)    
#define    TPM_CC_ReadPublic                    (TPM_CC)(0x00000173)    
#define    TPM_CC_RSA_Encrypt                   (TPM_CC)(0x00000174)    
#define    TPM_CC_StartAuthSession              (TPM_CC)(0x00000176)    
#define    TPM_CC_VerifySignature               (TPM_CC)(0x00000177)    
#define    TPM_CC_ECC_Parameters                (TPM_CC)(0x00000178)    
#define    TPM_CC_FirmwareRead                  (TPM_CC)(0x00000179)    
#define    TPM_CC_GetCapability                 (TPM_CC)(0x0000017A)    
#define    TPM_CC_GetRandom                     (TPM_CC)(0x0000017B)    
#define    TPM_CC_GetTestResult                 (TPM_CC)(0x0000017C)    
#define    TPM_CC_Hash                          (TPM_CC)(0x0000017D)    
#define    TPM_CC_PCR_Read                      (TPM_CC)(0x0000017E)    
#define    TPM_CC_PolicyPCR                     (TPM_CC)(0x0000017F)    
#define    TPM_CC_PolicyRestart                 (TPM_CC)(0x00000180)    
#define    TPM_CC_ReadClock                     (TPM_CC)(0x00000181)    
#define    TPM_CC_PCR_Extend                    (TPM_CC)(0x00000182)    
#define    TPM_CC_PCR_SetAuthValue              (TPM_CC)(0x00000183)    
#define    TPM_CC_NV_Certify                    (TPM_CC)(0x00000184)    
#define    TPM_CC_EventSequenceComplete         (TPM_CC)(0x00000185)    
#define    TPM_CC_HashSequenceStart             (TPM_CC)(0x00000186)    
#define    TPM_CC_PolicyPhysicalPresence        (TPM_CC)(0x00000187)    
#define    TPM_CC_PolicyDuplicationSelect       (TPM_CC)(0x00000188)    
#define    TPM_CC_PolicyGetDigest               (TPM_CC)(0x00000189)    
#define    TPM_CC_TestParms                     (TPM_CC)(0x0000018A)    
#define    TPM_CC_Commit                        (TPM_CC)(0x0000018B)    
#define    TPM_CC_PolicyPassword                (TPM_CC)(0x0000018C)    
#define    TPM_CC_ZGen_2Phase                   (TPM_CC)(0x0000018D)    
#define    TPM_CC_EC_Ephemeral                  (TPM_CC)(0x0000018E)    
#define    TPM_CC_LAST                          (TPM_CC)(0x0000018E)    


// Table 15 -- TPM_RC Constants <O,S>
typedef UINT32 TPM_RCS;    // The 'safe' error codes
typedef UINT32 TPM_RC;

#define    TPM_RC_SUCCESS              (TPM_RC)(0x000)    
#define    TPM_RC_BAD_TAG              (TPM_RC)(0x01E)    
#define    RC_VER1                     (TPM_RC)(0x100)    
#define    TPM_RC_INITIALIZE           (TPM_RC)(RC_VER1 + 0x000)    
#define    TPM_RC_FAILURE              (TPM_RC)(RC_VER1 + 0x001)    
#define    TPM_RC_SEQUENCE             (TPM_RC)(RC_VER1 + 0x003)    
#define    TPM_RC_PRIVATE              (TPM_RC)(RC_VER1 + 0x00B)    
#define    TPM_RC_HMAC                 (TPM_RC)(RC_VER1 + 0x019)    
#define    TPM_RC_DISABLED             (TPM_RC)(RC_VER1 + 0x020)    
#define    TPM_RC_EXCLUSIVE            (TPM_RC)(RC_VER1 + 0x021)    
#define    TPM_RC_AUTH_TYPE            (TPM_RC)(RC_VER1 + 0x024)    
#define    TPM_RC_AUTH_MISSING         (TPM_RC)(RC_VER1 + 0x025)    
#define    TPM_RC_POLICY               (TPM_RC)(RC_VER1 + 0x026)    
#define    TPM_RC_PCR                  (TPM_RC)(RC_VER1 + 0x027)    
#define    TPM_RC_PCR_CHANGED          (TPM_RC)(RC_VER1 + 0x028)    
#define    TPM_RC_UPGRADE              (TPM_RC)(RC_VER1 + 0x02D)    
#define    TPM_RC_TOO_MANY_CONTEXTS    (TPM_RC)(RC_VER1 + 0x02E)    
#define    TPM_RC_AUTH_UNAVAILABLE     (TPM_RC)(RC_VER1 + 0x02F)    
#define    TPM_RC_REBOOT               (TPM_RC)(RC_VER1 + 0x030)    
#define    TPM_RC_UNBALANCED           (TPM_RC)(RC_VER1 + 0x031)    
#define    TPM_RC_COMMAND_SIZE         (TPM_RC)(RC_VER1 + 0x042)    
#define    TPM_RC_COMMAND_CODE         (TPM_RC)(RC_VER1 + 0x043)    
#define    TPM_RC_AUTHSIZE             (TPM_RC)(RC_VER1 + 0x044)    
#define    TPM_RC_AUTH_CONTEXT         (TPM_RC)(RC_VER1 + 0x045)    
#define    TPM_RC_NV_RANGE             (TPM_RC)(RC_VER1 + 0x046)    
#define    TPM_RC_NV_SIZE              (TPM_RC)(RC_VER1 + 0x047)    
#define    TPM_RC_NV_LOCKED            (TPM_RC)(RC_VER1 + 0x048)    
#define    TPM_RC_NV_AUTHORIZATION     (TPM_RC)(RC_VER1 + 0x049)    
#define    TPM_RC_NV_UNINITIALIZED     (TPM_RC)(RC_VER1 + 0x04A)    
#define    TPM_RC_NV_SPACE             (TPM_RC)(RC_VER1 + 0x04B)    
#define    TPM_RC_NV_DEFINED           (TPM_RC)(RC_VER1 + 0x04C)    
#define    TPM_RC_BAD_CONTEXT          (TPM_RC)(RC_VER1 + 0x050)    
#define    TPM_RC_CPHASH               (TPM_RC)(RC_VER1 + 0x051)    
#define    TPM_RC_PARENT               (TPM_RC)(RC_VER1 + 0x052)    
#define    TPM_RC_NEEDS_TEST           (TPM_RC)(RC_VER1 + 0x053)    
#define    TPM_RC_NO_RESULT            (TPM_RC)(RC_VER1 + 0x054)    
#define    TPM_RC_SENSITIVE            (TPM_RC)(RC_VER1 + 0x055)    
#define    RC_MAX_FM0                  (TPM_RC)(RC_VER1 + 0x07F)    
#define    RC_FMT1                     (TPM_RC)(0x080)    
#define    TPM_RC_ASYMMETRIC           (TPM_RC)(RC_FMT1 + 0x001)    
#define    TPM_RCS_ASYMMETRIC          (TPM_RCS)(RC_FMT1 + 0x001)
#define    TPM_RC_ATTRIBUTES           (TPM_RC)(RC_FMT1 + 0x002)    
#define    TPM_RCS_ATTRIBUTES          (TPM_RCS)(RC_FMT1 + 0x002)
#define    TPM_RC_HASH                 (TPM_RC)(RC_FMT1 + 0x003)    
#define    TPM_RCS_HASH                (TPM_RCS)(RC_FMT1 + 0x003)
#define    TPM_RC_VALUE                (TPM_RC)(RC_FMT1 + 0x004)    
#define    TPM_RCS_VALUE               (TPM_RCS)(RC_FMT1 + 0x004)
#define    TPM_RC_HIERARCHY            (TPM_RC)(RC_FMT1 + 0x005)    
#define    TPM_RCS_HIERARCHY           (TPM_RCS)(RC_FMT1 + 0x005)
#define    TPM_RC_KEY_SIZE             (TPM_RC)(RC_FMT1 + 0x007)    
#define    TPM_RCS_KEY_SIZE            (TPM_RCS)(RC_FMT1 + 0x007)
#define    TPM_RC_MGF                  (TPM_RC)(RC_FMT1 + 0x008)    
#define    TPM_RCS_MGF                 (TPM_RCS)(RC_FMT1 + 0x008)
#define    TPM_RC_MODE                 (TPM_RC)(RC_FMT1 + 0x009)    
#define    TPM_RCS_MODE                (TPM_RCS)(RC_FMT1 + 0x009)
#define    TPM_RC_TYPE                 (TPM_RC)(RC_FMT1 + 0x00A)    
#define    TPM_RCS_TYPE                (TPM_RCS)(RC_FMT1 + 0x00A)
#define    TPM_RC_HANDLE               (TPM_RC)(RC_FMT1 + 0x00B)    
#define    TPM_RCS_HANDLE              (TPM_RCS)(RC_FMT1 + 0x00B)
#define    TPM_RC_KDF                  (TPM_RC)(RC_FMT1 + 0x00C)    
#define    TPM_RCS_KDF                 (TPM_RCS)(RC_FMT1 + 0x00C)
#define    TPM_RC_RANGE                (TPM_RC)(RC_FMT1 + 0x00D)    
#define    TPM_RCS_RANGE               (TPM_RCS)(RC_FMT1 + 0x00D)
#define    TPM_RC_AUTH_FAIL            (TPM_RC)(RC_FMT1 + 0x00E)    
#define    TPM_RCS_AUTH_FAIL           (TPM_RCS)(RC_FMT1 + 0x00E)
#define    TPM_RC_NONCE                (TPM_RC)(RC_FMT1 + 0x00F)    
#define    TPM_RCS_NONCE               (TPM_RCS)(RC_FMT1 + 0x00F)
#define    TPM_RC_PP                   (TPM_RC)(RC_FMT1 + 0x010)    
#define    TPM_RCS_PP                  (TPM_RCS)(RC_FMT1 + 0x010)
#define    TPM_RC_SCHEME               (TPM_RC)(RC_FMT1 + 0x012)    
#define    TPM_RCS_SCHEME              (TPM_RCS)(RC_FMT1 + 0x012)
#define    TPM_RC_SIZE                 (TPM_RC)(RC_FMT1 + 0x015)    
#define    TPM_RCS_SIZE                (TPM_RCS)(RC_FMT1 + 0x015)
#define    TPM_RC_SYMMETRIC            (TPM_RC)(RC_FMT1 + 0x016)    
#define    TPM_RCS_SYMMETRIC           (TPM_RCS)(RC_FMT1 + 0x016)
#define    TPM_RC_TAG                  (TPM_RC)(RC_FMT1 + 0x017)    
#define    TPM_RCS_TAG                 (TPM_RCS)(RC_FMT1 + 0x017)
#define    TPM_RC_SELECTOR             (TPM_RC)(RC_FMT1 + 0x018)    
#define    TPM_RCS_SELECTOR            (TPM_RCS)(RC_FMT1 + 0x018)
#define    TPM_RC_INSUFFICIENT         (TPM_RC)(RC_FMT1 + 0x01A)    
#define    TPM_RCS_INSUFFICIENT        (TPM_RCS)(RC_FMT1 + 0x01A)
#define    TPM_RC_SIGNATURE            (TPM_RC)(RC_FMT1 + 0x01B)    
#define    TPM_RCS_SIGNATURE           (TPM_RCS)(RC_FMT1 + 0x01B)
#define    TPM_RC_KEY                  (TPM_RC)(RC_FMT1 + 0x01C)    
#define    TPM_RCS_KEY                 (TPM_RCS)(RC_FMT1 + 0x01C)
#define    TPM_RC_POLICY_FAIL          (TPM_RC)(RC_FMT1 + 0x01D)    
#define    TPM_RCS_POLICY_FAIL         (TPM_RCS)(RC_FMT1 + 0x01D)
#define    TPM_RC_INTEGRITY            (TPM_RC)(RC_FMT1 + 0x01F)    
#define    TPM_RCS_INTEGRITY           (TPM_RCS)(RC_FMT1 + 0x01F)
#define    TPM_RC_TICKET               (TPM_RC)(RC_FMT1 + 0x020)    
#define    TPM_RCS_TICKET              (TPM_RCS)(RC_FMT1 + 0x020)
#define    TPM_RC_RESERVED_BITS        (TPM_RC)(RC_FMT1 + 0x021)    
#define    TPM_RCS_RESERVED_BITS       (TPM_RCS)(RC_FMT1 + 0x021)
#define    TPM_RC_BAD_AUTH             (TPM_RC)(RC_FMT1 + 0x022)    
#define    TPM_RCS_BAD_AUTH            (TPM_RCS)(RC_FMT1 + 0x022)
#define    TPM_RC_EXPIRED              (TPM_RC)(RC_FMT1 + 0x023)    
#define    TPM_RCS_EXPIRED             (TPM_RCS)(RC_FMT1 + 0x023)
#define    TPM_RC_POLICY_CC            (TPM_RC)(RC_FMT1 + 0x024 )    
#define    TPM_RCS_POLICY_CC           (TPM_RCS)(RC_FMT1 + 0x024 )
#define    TPM_RC_BINDING              (TPM_RC)(RC_FMT1 + 0x025)    
#define    TPM_RCS_BINDING             (TPM_RCS)(RC_FMT1 + 0x025)
#define    TPM_RC_CURVE                (TPM_RC)(RC_FMT1 + 0x026)    
#define    TPM_RCS_CURVE               (TPM_RCS)(RC_FMT1 + 0x026)
#define    TPM_RC_ECC_POINT            (TPM_RC)(RC_FMT1 + 0x027)    
#define    TPM_RCS_ECC_POINT           (TPM_RCS)(RC_FMT1 + 0x027)
#define    RC_WARN                     (TPM_RC)(0x900)    
#define    TPM_RC_CONTEXT_GAP          (TPM_RC)(RC_WARN + 0x001)    
#define    TPM_RC_OBJECT_MEMORY        (TPM_RC)(RC_WARN + 0x002)    
#define    TPM_RC_SESSION_MEMORY       (TPM_RC)(RC_WARN + 0x003)    
#define    TPM_RC_MEMORY               (TPM_RC)(RC_WARN + 0x004)    
#define    TPM_RC_SESSION_HANDLES      (TPM_RC)(RC_WARN + 0x005)    
#define    TPM_RC_OBJECT_HANDLES       (TPM_RC)(RC_WARN + 0x006)    
#define    TPM_RC_LOCALITY             (TPM_RC)(RC_WARN + 0x007)    
#define    TPM_RC_YIELDED              (TPM_RC)(RC_WARN + 0x008)    
#define    TPM_RC_CANCELED             (TPM_RC)(RC_WARN + 0x009)    
#define    TPM_RC_TESTING              (TPM_RC)(RC_WARN + 0x00A)    
#define    TPM_RC_REFERENCE_H0         (TPM_RC)(RC_WARN + 0x010)    
#define    TPM_RC_REFERENCE_H1         (TPM_RC)(RC_WARN + 0x011)    
#define    TPM_RC_REFERENCE_H2         (TPM_RC)(RC_WARN + 0x012)    
#define    TPM_RC_REFERENCE_H3         (TPM_RC)(RC_WARN + 0x013)    
#define    TPM_RC_REFERENCE_H4         (TPM_RC)(RC_WARN + 0x014)    
#define    TPM_RC_REFERENCE_H5         (TPM_RC)(RC_WARN + 0x015)    
#define    TPM_RC_REFERENCE_H6         (TPM_RC)(RC_WARN + 0x016)    
#define    TPM_RC_REFERENCE_S0         (TPM_RC)(RC_WARN + 0x018)    
#define    TPM_RC_REFERENCE_S1         (TPM_RC)(RC_WARN + 0x019)    
#define    TPM_RC_REFERENCE_S2         (TPM_RC)(RC_WARN + 0x01A)    
#define    TPM_RC_REFERENCE_S3         (TPM_RC)(RC_WARN + 0x01B)    
#define    TPM_RC_REFERENCE_S4         (TPM_RC)(RC_WARN + 0x01C)    
#define    TPM_RC_REFERENCE_S5         (TPM_RC)(RC_WARN + 0x01D)    
#define    TPM_RC_REFERENCE_S6         (TPM_RC)(RC_WARN + 0x01E)    
#define    TPM_RC_NV_RATE              (TPM_RC)(RC_WARN + 0x020)    
#define    TPM_RC_LOCKOUT              (TPM_RC)(RC_WARN + 0x021)    
#define    TPM_RC_RETRY                (TPM_RC)(RC_WARN + 0x022)    
#define    TPM_RC_NV_UNAVAILABLE       (TPM_RC)(RC_WARN + 0x023)    
#define    TPM_RC_NOT_USED             (TPM_RC)(RC_WARN + 0x7F)    
#define    TPM_RC_H                    (TPM_RC)(0x000)    
#define    TPM_RC_P                    (TPM_RC)(0x040)    
#define    TPM_RC_S                    (TPM_RC)(0x800)    
#define    TPM_RC_1                    (TPM_RC)(0x100)    
#define    TPM_RC_2                    (TPM_RC)(0x200)    
#define    TPM_RC_3                    (TPM_RC)(0x300)    
#define    TPM_RC_4                    (TPM_RC)(0x400)    
#define    TPM_RC_5                    (TPM_RC)(0x500)    
#define    TPM_RC_6                    (TPM_RC)(0x600)    
#define    TPM_RC_7                    (TPM_RC)(0x700)    
#define    TPM_RC_8                    (TPM_RC)(0x800)    
#define    TPM_RC_9                    (TPM_RC)(0x900)    
#define    TPM_RC_A                    (TPM_RC)(0xA00)    
#define    TPM_RC_B                    (TPM_RC)(0xB00)    
#define    TPM_RC_C                    (TPM_RC)(0xC00)    
#define    TPM_RC_D                    (TPM_RC)(0xD00)    
#define    TPM_RC_E                    (TPM_RC)(0xE00)    
#define    TPM_RC_F                    (TPM_RC)(0xF00)    
#define    TPM_RC_N_MASK               (TPM_RC)(0xF00)    




// Table 16 -- TPM_CLOCK_ADJUST Constants <I>
typedef INT8 TPM_CLOCK_ADJUST;

#define    TPM_CLOCK_COARSE_SLOWER    (TPM_CLOCK_ADJUST)(-3)    
#define    TPM_CLOCK_MEDIUM_SLOWER    (TPM_CLOCK_ADJUST)(-2)    
#define    TPM_CLOCK_FINE_SLOWER      (TPM_CLOCK_ADJUST)(-1)    
#define    TPM_CLOCK_NO_CHANGE        (TPM_CLOCK_ADJUST)(0)    
#define    TPM_CLOCK_FINE_FASTER      (TPM_CLOCK_ADJUST)(1)    
#define    TPM_CLOCK_MEDIUM_FASTER    (TPM_CLOCK_ADJUST)(2)    
#define    TPM_CLOCK_COARSE_FASTER    (TPM_CLOCK_ADJUST)(3)    




// Table 17 -- TPM_EO Constants <I/O>
typedef UINT16 TPM_EO;

#define    TPM_EO_EQ             (TPM_EO)(0x0000)    
#define    TPM_EO_NEQ            (TPM_EO)(0x0001)    
#define    TPM_EO_SIGNED_GT      (TPM_EO)(0x0002)    
#define    TPM_EO_UNSIGNED_GT    (TPM_EO)(0x0003)    
#define    TPM_EO_SIGNED_LT      (TPM_EO)(0x0004)    
#define    TPM_EO_UNSIGNED_LT    (TPM_EO)(0x0005)    
#define    TPM_EO_SIGNED_GE      (TPM_EO)(0x0006)    
#define    TPM_EO_UNSIGNED_GE    (TPM_EO)(0x0007)    
#define    TPM_EO_SIGNED_LE      (TPM_EO)(0x0008)    
#define    TPM_EO_UNSIGNED_LE    (TPM_EO)(0x0009)    
#define    TPM_EO_BITSET         (TPM_EO)(0x000A)    
#define    TPM_EO_BITCLEAR       (TPM_EO)(0x000B)    




// Table 18 -- TPM_ST Constants <I/O,S>
typedef UINT16 TPM_ST;

#define    TPM_ST_RSP_COMMAND             (TPM_ST)(0x00C4)    
#define    TPM_ST_NULL                    (TPM_ST)(0X8000)    
#define    TPM_ST_NO_SESSIONS             (TPM_ST)(0x8001)    
#define    TPM_ST_SESSIONS                (TPM_ST)(0x8002)    
#define    TPM_ST_ATTEST_NV               (TPM_ST)(0x8014)    
#define    TPM_ST_ATTEST_COMMAND_AUDIT    (TPM_ST)(0x8015)    
#define    TPM_ST_ATTEST_SESSION_AUDIT    (TPM_ST)(0x8016)    
#define    TPM_ST_ATTEST_CERTIFY          (TPM_ST)(0x8017)    
#define    TPM_ST_ATTEST_QUOTE            (TPM_ST)(0x8018)    
#define    TPM_ST_ATTEST_TIME             (TPM_ST)(0x8019)    
#define    TPM_ST_ATTEST_CREATION         (TPM_ST)(0x801A)    
#define    TPM_ST_CREATION                (TPM_ST)(0x8021)    
#define    TPM_ST_VERIFIED                (TPM_ST)(0x8022)    
#define    TPM_ST_AUTH_SECRET             (TPM_ST)(0x8023)    
#define    TPM_ST_HASHCHECK               (TPM_ST)(0x8024)    
#define    TPM_ST_AUTH_SIGNED             (TPM_ST)(0x8025)    
#define    TPM_ST_FU_MANIFEST             (TPM_ST)(0x8029)    


// Table 19 -- TPM_SU Constants <I>
typedef UINT16 TPM_SU;

#define    TPM_SU_CLEAR     (TPM_SU)(0x0000)    
#define    TPM_SU_STATE     (TPM_SU)(0x0001)    




// Table 20 -- TPM_SE Constants <I>
typedef UINT8 TPM_SE;

#define    TPM_SE_HMAC      (TPM_SE)(0x00)    
#define    TPM_SE_POLICY    (TPM_SE)(0x01)    
#define    TPM_SE_TRIAL     (TPM_SE)(0x03)    




// Table 21 -- TPM_CAP Constants <I/O>
typedef UINT32 TPM_CAP;

#define    TPM_CAP_FIRST              (TPM_CAP)(0x00000000)    
#define    TPM_CAP_ALGS               (TPM_CAP)(0x00000000)    
#define    TPM_CAP_HANDLES            (TPM_CAP)(0x00000001)    
#define    TPM_CAP_COMMANDS           (TPM_CAP)(0x00000002)    
#define    TPM_CAP_PP_COMMANDS        (TPM_CAP)(0x00000003)    
#define    TPM_CAP_AUDIT_COMMANDS     (TPM_CAP)(0x00000004)    
#define    TPM_CAP_PCRS               (TPM_CAP)(0x00000005)    
#define    TPM_CAP_TPM_PROPERTIES     (TPM_CAP)(0x00000006)    
#define    TPM_CAP_PCR_PROPERTIES     (TPM_CAP)(0x00000007)    
#define    TPM_CAP_ECC_CURVES         (TPM_CAP)(0x00000008)    
#define    TPM_CAP_LAST               (TPM_CAP)(0x00000008)    
#define    TPM_CAP_VENDOR_PROPERTY    (TPM_CAP)(0x00000100)    




// Table 22 -- TPM_PT Constants <I/O,S>
typedef UINT32 TPM_PT;

#define    TPM_PT_NONE                   (TPM_PT)(0x00000000)    
#define    PT_GROUP                      (TPM_PT)(0x00000100)    
#define    PT_FIXED                      (TPM_PT)(PT_GROUP * 1)    
#define    TPM_PT_FAMILY_INDICATOR       (TPM_PT)(PT_FIXED + 0)    
#define    TPM_PT_LEVEL                  (TPM_PT)(PT_FIXED + 1)    
#define    TPM_PT_REVISION               (TPM_PT)(PT_FIXED + 2)    
#define    TPM_PT_DAY_OF_YEAR            (TPM_PT)(PT_FIXED + 3)    
#define    TPM_PT_YEAR                   (TPM_PT)(PT_FIXED + 4)    
#define    TPM_PT_MANUFACTURER           (TPM_PT)(PT_FIXED + 5)    
#define    TPM_PT_VENDOR_STRING_1        (TPM_PT)(PT_FIXED + 6)    
#define    TPM_PT_VENDOR_STRING_2        (TPM_PT)(PT_FIXED + 7)    
#define    TPM_PT_VENDOR_STRING_3        (TPM_PT)(PT_FIXED + 8)    
#define    TPM_PT_VENDOR_STRING_4        (TPM_PT)(PT_FIXED + 9)    
#define    TPM_PT_VENDOR_TPM_TYPE        (TPM_PT)(PT_FIXED + 10)    
#define    TPM_PT_FIRMWARE_VERSION_1     (TPM_PT)(PT_FIXED + 11)    
#define    TPM_PT_FIRMWARE_VERSION_2     (TPM_PT)(PT_FIXED + 12)    
#define    TPM_PT_INPUT_BUFFER           (TPM_PT)(PT_FIXED + 13)    
#define    TPM_PT_HR_TRANSIENT_MIN       (TPM_PT)(PT_FIXED + 14)    
#define    TPM_PT_HR_PERSISTENT_MIN      (TPM_PT)(PT_FIXED + 15)    
#define    TPM_PT_HR_LOADED_MIN          (TPM_PT)(PT_FIXED + 16)    
#define    TPM_PT_ACTIVE_SESSIONS_MAX    (TPM_PT)(PT_FIXED + 17)    
#define    TPM_PT_PCR_COUNT              (TPM_PT)(PT_FIXED + 18)    
#define    TPM_PT_PCR_SELECT_MIN         (TPM_PT)(PT_FIXED + 19)    
#define    TPM_PT_CONTEXT_GAP_MAX        (TPM_PT)(PT_FIXED + 20)    
#define    TPM_PT_NV_COUNTERS_MAX        (TPM_PT)(PT_FIXED + 22)    
#define    TPM_PT_NV_INDEX_MAX           (TPM_PT)(PT_FIXED + 23)    
#define    TPM_PT_MEMORY                 (TPM_PT)(PT_FIXED + 24)    
#define    TPM_PT_CLOCK_UPDATE           (TPM_PT)(PT_FIXED + 25)    
#define    TPM_PT_CONTEXT_HASH           (TPM_PT)(PT_FIXED + 26)    
#define    TPM_PT_CONTEXT_SYM            (TPM_PT)(PT_FIXED + 27)    
#define    TPM_PT_CONTEXT_SYM_SIZE       (TPM_PT)(PT_FIXED + 28)    
#define    TPM_PT_ORDERLY_COUNT          (TPM_PT)(PT_FIXED + 29)    
#define    TPM_PT_MAX_COMMAND_SIZE       (TPM_PT)(PT_FIXED + 30)    
#define    TPM_PT_MAX_RESPONSE_SIZE      (TPM_PT)(PT_FIXED + 31)    
#define    TPM_PT_MAX_DIGEST             (TPM_PT)(PT_FIXED + 32)    
#define    TPM_PT_MAX_OBJECT_CONTEXT     (TPM_PT)(PT_FIXED + 33)    
#define    TPM_PT_MAX_SESSION_CONTEXT    (TPM_PT)(PT_FIXED + 34)    
#define    TPM_PT_PS_FAMILY_INDICATOR    (TPM_PT)(PT_FIXED + 35)    
#define    TPM_PT_PS_LEVEL               (TPM_PT)(PT_FIXED + 36)    
#define    TPM_PT_PS_REVISION            (TPM_PT)(PT_FIXED + 37)    
#define    TPM_PT_PS_DAY_OF_YEAR         (TPM_PT)(PT_FIXED + 38)    
#define    TPM_PT_PS_YEAR                (TPM_PT)(PT_FIXED + 39)    
#define    TPM_PT_SPLIT_MAX              (TPM_PT)(PT_FIXED + 40)    
#define    TPM_PT_TOTAL_COMMANDS         (TPM_PT)(PT_FIXED + 41)    
#define    TPM_PT_LIBRARY_COMMANDS       (TPM_PT)(PT_FIXED + 42)    
#define    TPM_PT_VENDOR_COMMANDS        (TPM_PT)(PT_FIXED + 43) 
#define    TPM_PT_NV_BUFFER_MAX          (TPM_PT)(PT_FIXED + 44)   
#define    PT_VAR                        (TPM_PT)(PT_GROUP * 2)    
#define    TPM_PT_PERMANENT              (TPM_PT)(PT_VAR + 0)    
#define    TPM_PT_STARTUP_CLEAR          (TPM_PT)(PT_VAR + 1)    
#define    TPM_PT_HR_NV_INDEX            (TPM_PT)(PT_VAR + 2)    
#define    TPM_PT_HR_LOADED              (TPM_PT)(PT_VAR + 3)    
#define    TPM_PT_HR_LOADED_AVAIL        (TPM_PT)(PT_VAR + 4)    
#define    TPM_PT_HR_ACTIVE              (TPM_PT)(PT_VAR + 5)    
#define    TPM_PT_HR_ACTIVE_AVAIL        (TPM_PT)(PT_VAR + 6)    
#define    TPM_PT_HR_TRANSIENT_AVAIL     (TPM_PT)(PT_VAR + 7)    
#define    TPM_PT_HR_PERSISTENT          (TPM_PT)(PT_VAR + 8)    
#define    TPM_PT_HR_PERSISTENT_AVAIL    (TPM_PT)(PT_VAR + 9)    
#define    TPM_PT_NV_COUNTERS            (TPM_PT)(PT_VAR + 10)    
#define    TPM_PT_NV_COUNTERS_AVAIL      (TPM_PT)(PT_VAR + 11)    
#define    TPM_PT_ALGORITHM_SET          (TPM_PT)(PT_VAR + 12)    
#define    TPM_PT_LOADED_CURVES          (TPM_PT)(PT_VAR + 13)    
#define    TPM_PT_LOCKOUT_COUNTER        (TPM_PT)(PT_VAR + 14)    
#define    TPM_PT_MAX_AUTH_FAIL          (TPM_PT)(PT_VAR + 15)    
#define    TPM_PT_LOCKOUT_INTERVAL       (TPM_PT)(PT_VAR + 16)    
#define    TPM_PT_LOCKOUT_RECOVERY       (TPM_PT)(PT_VAR + 17)    
#define    TPM_PT_NV_WRITE_RECOVERY      (TPM_PT)(PT_VAR + 18)    
#define    TPM_PT_AUDIT_COUNTER_0        (TPM_PT)(PT_VAR + 19)    
#define    TPM_PT_AUDIT_COUNTER_1        (TPM_PT)(PT_VAR + 20)    


// Table 23 -- TPM_PT_PCR Constants <I/O,S>
typedef UINT32 TPM_PT_PCR;

#define    TPM_PT_PCR_FIRST           (TPM_PT_PCR)(0x00000000)    
#define    TPM_PT_PCR_SAVE            (TPM_PT_PCR)(0x00000000)    
#define    TPM_PT_PCR_EXTEND_L0       (TPM_PT_PCR)(0x00000001)    
#define    TPM_PT_PCR_RESET_L0        (TPM_PT_PCR)(0x00000002)    
#define    TPM_PT_PCR_EXTEND_L1       (TPM_PT_PCR)(0x00000003)    
#define    TPM_PT_PCR_RESET_L1        (TPM_PT_PCR)(0x00000004)    
#define    TPM_PT_PCR_EXTEND_L2       (TPM_PT_PCR)(0x00000005)    
#define    TPM_PT_PCR_RESET_L2        (TPM_PT_PCR)(0x00000006)    
#define    TPM_PT_PCR_EXTEND_L3       (TPM_PT_PCR)(0x00000007)    
#define    TPM_PT_PCR_RESET_L3        (TPM_PT_PCR)(0x00000008)    
#define    TPM_PT_PCR_EXTEND_L4       (TPM_PT_PCR)(0x00000009)    
#define    TPM_PT_PCR_RESET_L4        (TPM_PT_PCR)(0x0000000A)    
#define    TPM_PT_PCR_NO_INCREMENT    (TPM_PT_PCR)(0x00000011)    
#define    TPM_PT_PCR_DRTM_RESET      (TPM_PT_PCR)(0x00000012)    
#define    TPM_PT_PCR_POLICY          (TPM_PT_PCR)(0x00000013)    
#define    TPM_PT_PCR_AUTH            (TPM_PT_PCR)(0x00000014)    
#define    TPM_PT_PCR_LAST            (TPM_PT_PCR)(0x00000014)    


// Table 24 -- TPM_PS Constants <O,S>
typedef UINT32 TPM_PS;

#define    TPM_PS_MAIN              (TPM_PS)(0x00000000)    
#define    TPM_PS_PC                (TPM_PS)(0x00000001)    
#define    TPM_PS_PDA               (TPM_PS)(0x00000002)    
#define    TPM_PS_CELL_PHONE        (TPM_PS)(0x00000003)    
#define    TPM_PS_SERVER            (TPM_PS)(0x00000004)    
#define    TPM_PS_PERIPHERAL        (TPM_PS)(0x00000005)    
#define    TPM_PS_TSS               (TPM_PS)(0x00000006)    
#define    TPM_PS_STORAGE           (TPM_PS)(0x00000007)    
#define    TPM_PS_AUTHENTICATION    (TPM_PS)(0x00000008)    
#define    TPM_PS_EMBEDDED          (TPM_PS)(0x00000009)    
#define    TPM_PS_HARDCOPY          (TPM_PS)(0x0000000A)    
#define    TPM_PS_INFRASTRUCTURE    (TPM_PS)(0x0000000B)    
#define    TPM_PS_VIRTUALIZATION    (TPM_PS)(0x0000000C)    
#define    TPM_PS_TNC               (TPM_PS)(0x0000000D)    
#define    TPM_PS_MULTI_TENANT      (TPM_PS)(0x0000000E)    
#define    TPM_PS_TC                (TPM_PS)(0x0000000F)    




// Table 25 -- Handles Types <I/O>
typedef UINT32    TPM_HANDLE;
typedef UINT8 TPM_HT;

#define    TPM_HT_PCR               (TPM_HT)(0x00)    
#define    TPM_HT_NV_INDEX          (TPM_HT)(0x01)    
#define    TPM_HT_HMAC_SESSION      (TPM_HT)(0x02)    
#define    TPM_HT_LOADED_SESSION    (TPM_HT)(0x02)    
#define    TPM_HT_POLICY_SESSION    (TPM_HT)(0x03)    
#define    TPM_HT_ACTIVE_SESSION    (TPM_HT)(0x03)    
#define    TPM_HT_PERMANENT         (TPM_HT)(0x40)    
#define    TPM_HT_TRANSIENT         (TPM_HT)(0x80)    
#define    TPM_HT_PERSISTENT        (TPM_HT)(0x81)    




// Table 27 -- TPM_RH Constants <I,S>
typedef UINT32 TPM_RH;

#define    TPM_RH_FIRST          (TPM_RH)(0x40000000)    
#define    TPM_RH_SRK            (TPM_RH)(0x40000000)    
#define    TPM_RH_OWNER          (TPM_RH)(0x40000001)    
#define    TPM_RH_REVOKE         (TPM_RH)(0x40000002)    
#define    TPM_RH_TRANSPORT      (TPM_RH)(0x40000003)    
#define    TPM_RH_OPERATOR       (TPM_RH)(0x40000004)    
#define    TPM_RH_ADMIN          (TPM_RH)(0x40000005)    
#define    TPM_RH_EK             (TPM_RH)(0x40000006)    
#define    TPM_RH_NULL           (TPM_RH)(0x40000007)    
#define    TPM_RH_UNASSIGNED     (TPM_RH)(0x40000008)    
#define    TPM_RS_PW             (TPM_RH)(0x40000009)    
#define    TPM_RH_LOCKOUT        (TPM_RH)(0x4000000A)    
#define    TPM_RH_ENDORSEMENT    (TPM_RH)(0x4000000B)    
#define    TPM_RH_PLATFORM       (TPM_RH)(0x4000000C)    
#define    TPM_RH_PLATFORM_NV    (TPM_RH)(0x4000000D)
#define    TPM_RH_LAST           (TPM_RH)(0x4000000C)    


// Table 28 -- TPM_HC Constants <I,S>
typedef TPM_HANDLE TPM_HC;

#define    HR_HANDLE_MASK          (TPM_HC)(0x00FFFFFF)    
#define    HR_RANGE_MASK           (TPM_HC)(0xFF000000)    
#define    HR_SHIFT                (TPM_HC)(24)    
#define    HR_PCR                  (TPM_HC)((TPM_HC)TPM_HT_PCR << HR_SHIFT)    
#define    HR_HMAC_SESSION         (TPM_HC)((TPM_HC)TPM_HT_HMAC_SESSION << HR_SHIFT)    
#define    HR_POLICY_SESSION       (TPM_HC)((TPM_HC)TPM_HT_POLICY_SESSION << HR_SHIFT)    
#define    HR_TRANSIENT            (TPM_HC)((TPM_HC)TPM_HT_TRANSIENT << HR_SHIFT)    
#define    HR_PERSISTENT           (TPM_HC)((TPM_HC)TPM_HT_PERSISTENT << HR_SHIFT)    
#define    HR_NV_INDEX             (TPM_HC)((TPM_HC)TPM_HT_NV_INDEX << HR_SHIFT)    
#define    HR_PERMANENT            (TPM_HC)((TPM_HC)TPM_HT_PERMANENT << HR_SHIFT)    
#define    PCR_FIRST               (TPM_HC)(HR_PCR + 0)    
#define    PCR_LAST                (TPM_HC)(PCR_FIRST + IMPLEMENTATION_PCR-1)    
#define    HMAC_SESSION_FIRST      (TPM_HC)(HR_HMAC_SESSION + 0)    
#define    HMAC_SESSION_LAST       (TPM_HC)(HMAC_SESSION_FIRST + MAX_ACTIVE_SESSIONS - 1)    
#define    LOADED_SESSION_FIRST    (TPM_HC)(HMAC_SESSION_FIRST)    
#define    LOADED_SESSION_LAST     (TPM_HC)(HMAC_SESSION_LAST)    
#define    POLICY_SESSION_FIRST    (TPM_HC)(HR_POLICY_SESSION + 0)    
#define    POLICY_SESSION_LAST     (TPM_HC)(POLICY_SESSION_FIRST + MAX_ACTIVE_SESSIONS - 1)    
#define    TRANSIENT_FIRST         (TPM_HC)(HR_TRANSIENT + 0)    
#define    ACTIVE_SESSION_FIRST    (TPM_HC)(POLICY_SESSION_FIRST)    
#define    ACTIVE_SESSION_LAST     (TPM_HC)(POLICY_SESSION_LAST)    
#define    TRANSIENT_LAST          (TPM_HC)(TRANSIENT_FIRST + MAX_LOADED_OBJECTS - 1)    
#define    PERSISTENT_FIRST        (TPM_HC)(HR_PERSISTENT + 0)    
#define    PERSISTENT_LAST         (TPM_HC)(PERSISTENT_FIRST + 0x00FFFFFF)    
#define    PLATFORM_PERSISTENT     (TPM_HC)(PERSISTENT_FIRST + 0x00800000)    
#define    NV_INDEX_FIRST          (TPM_HC)(HR_NV_INDEX + 0)    
#define    NV_INDEX_LAST           (TPM_HC)(NV_INDEX_FIRST + 0x00FFFFFF)    
#define    PERMANENT_FIRST         (TPM_HC)(TPM_RH_FIRST)    
#define    PERMANENT_LAST          (TPM_HC)(TPM_RH_LAST)    


// Table 29 -- TPMA_ALGORITHM Bits <I/O>
typedef struct {
    unsigned int asymmetric : 1;
    unsigned int symmetric  : 1;
    unsigned int hash       : 1;
    unsigned int object     : 1;
    unsigned int reserved5  : 4;
    unsigned int signing    : 1;
    unsigned int encrypting : 1;
    unsigned int method     : 1;
    unsigned int reserved9  : 21;
} TPMA_ALGORITHM ;

// Table 30 -- TPMA_OBJECT Bits <I/O>
typedef struct {
    unsigned int reserved1            : 1;
    unsigned int fixedTPM             : 1;
    unsigned int stClear              : 1;
    unsigned int reserved4            : 1;
    unsigned int fixedParent          : 1;
    unsigned int sensitiveDataOrigin  : 1;
    unsigned int userWithAuth         : 1;
    unsigned int adminWithPolicy      : 1;
    unsigned int reserved9            : 1;
    unsigned int derivedDataOrigin    : 1;
    unsigned int noDA                 : 1;
    unsigned int encryptedDuplication : 1;
    unsigned int reserved12           : 4;
    unsigned int restricted           : 1;
    unsigned int decrypt              : 1;
    unsigned int sign                 : 1;
    unsigned int reserved16           : 13;
} TPMA_OBJECT ;

// Table 31 -- TPMA_SESSION Bits <I/O>
typedef struct {
    unsigned int continueSession : 1;
    unsigned int auditExclusive  : 1;
    unsigned int auditReset      : 1;
    unsigned int reserved4       : 2;
    unsigned int decrypt         : 1;
    unsigned int encrypt         : 1;
    unsigned int audit           : 1;
} TPMA_SESSION ;

// Table 32 -- TPMA_LOCALITY Bits <I/O>
typedef struct {
    unsigned int TPM_LOC_ZERO  : 1;
    unsigned int TPM_LOC_ONE   : 1;
    unsigned int TPM_LOC_TWO   : 1;
    unsigned int TPM_LOC_THREE : 1;
    unsigned int TPM_LOC_FOUR  : 1;
    unsigned int Extended      : 3;
} TPMA_LOCALITY ;

// Table 33 -- TPMA_PERMANENT Bits <O,S>
typedef struct {
    unsigned int ownerAuthSet       : 1;
    unsigned int endorsementAuthSet : 1;
    unsigned int lockoutAuthSet     : 1;
    unsigned int reserved4          : 5;
    unsigned int disableClear       : 1;
    unsigned int inLockout          : 1;
    unsigned int tpmGeneratedEPS    : 1;
    unsigned int reserved8          : 21;
} TPMA_PERMANENT ;

// Table 34 -- TPMA_STARTUP_CLEAR Bits <O,S>
typedef struct {
    unsigned int phEnable   : 1;
    unsigned int shEnable   : 1;
    unsigned int ehEnable   : 1;
    unsigned int phEnableNV : 1;
    unsigned int reserved5  : 27;
    unsigned int orderly    : 1;
} TPMA_STARTUP_CLEAR ;

// Table 35 -- TPMA_MEMORY Bits <O,S>
typedef struct {
    unsigned int sharedRAM         : 1;
    unsigned int sharedNV          : 1;
    unsigned int objectCopiedToRam : 1;
    unsigned int reserved4         : 29;
} TPMA_MEMORY ;

// Table 36 -- TPMA_CC Bits <O,S>
typedef struct {
    unsigned int commandIndex : 16;
    unsigned int reserved2    : 6;
    unsigned int nv           : 1;
    unsigned int extensive    : 1;
    unsigned int flushed      : 1;
    unsigned int cHandles     : 3;
    unsigned int rHandle      : 1;
    unsigned int V            : 1;
    unsigned int reserved9    : 2;
} TPMA_CC ;

// Table 37 -- TPMI_YES_NO Type <I/O>
typedef BYTE TPMI_YES_NO;


// Table 38 -- TPMI_DH_OBJECT Type <I/O>
typedef TPM_HANDLE TPMI_DH_OBJECT;


// Table 39 -- TPMI_DH_PERSISTENT Type <I/O>
typedef TPM_HANDLE TPMI_DH_PERSISTENT;


// Table 40 -- TPMI_DH_ENTITY Type <I>
typedef TPM_HANDLE TPMI_DH_ENTITY;


// Table 41 -- TPMI_DH_PCR Type <I>
typedef TPM_HANDLE TPMI_DH_PCR;


// Table 42 -- TPMI_SH_AUTH_SESSION Type <I/O>
typedef TPM_HANDLE TPMI_SH_AUTH_SESSION;


// Table 43 -- TPMI_SH_HMAC Type <I/O>
typedef TPM_HANDLE TPMI_SH_HMAC;


// Table 44 -- TPMI_SH_POLICY Type <I/O>
typedef TPM_HANDLE TPMI_SH_POLICY;


// Table 45 -- TPMI_DH_CONTEXT Type <I/O>
typedef TPM_HANDLE TPMI_DH_CONTEXT;


// Table 46 -- TPMI_RH_HIERARCHY Type <I/O>
typedef TPM_HANDLE TPMI_RH_HIERARCHY;


// Table 47 -- TPMI_RH_HIERARCHY_AUTH Type <I>
typedef TPM_HANDLE TPMI_RH_HIERARCHY_AUTH;


// Table 48 -- TPMI_RH_PLATFORM Type <I>
typedef TPM_HANDLE TPMI_RH_PLATFORM;


// Table 49 -- TPMI_RH_OWNER Type <I>
typedef TPM_HANDLE TPMI_RH_OWNER;


// Table 50 -- TPMI_RH_ENDORSEMENT Type <I>
typedef TPM_HANDLE TPMI_RH_ENDORSEMENT;


// Table 51 -- TPMI_RH_PROVISION Type <I>
typedef TPM_HANDLE TPMI_RH_PROVISION;


// Table 52 -- TPMI_RH_CLEAR Type <I>
typedef TPM_HANDLE TPMI_RH_CLEAR;


// Table 53 -- TPMI_RH_NV_AUTH Type <I>
typedef TPM_HANDLE TPMI_RH_NV_AUTH;


// Table 54 -- TPMI_RH_LOCKOUT Type <I>
typedef TPM_HANDLE TPMI_RH_LOCKOUT;


// Table 55 -- TPMI_RH_NV_INDEX Type <I/O>
typedef TPM_HANDLE TPMI_RH_NV_INDEX;


// Table 56 -- TPMI_ALG_HASH Type <I/O>
typedef TPM_ALG_ID TPMI_ALG_HASH;


// Table 57 -- TPMI_ALG_ASYM Type <I/O>
typedef TPM_ALG_ID TPMI_ALG_ASYM;


// Table 58 -- TPMI_ALG_SYM Type <I/O>
typedef TPM_ALG_ID TPMI_ALG_SYM;


// Table 59 -- TPMI_ALG_SYM_OBJECT Type <I/O>
typedef TPM_ALG_ID TPMI_ALG_SYM_OBJECT;


// Table 60 -- TPMI_ALG_SYM_MODE Type <I/O>
typedef TPM_ALG_ID TPMI_ALG_SYM_MODE;


// Table 61 -- TPMI_ALG_KDF Type <I/O>
typedef TPM_ALG_ID TPMI_ALG_KDF;


// Table 62 -- TPMI_ALG_SIG_SCHEME Type <I/O>
typedef TPM_ALG_ID TPMI_ALG_SIG_SCHEME;


// Table 63 -- TPMI_ECC_KEY_EXCHANGE Type <I/O>
typedef TPM_ALG_ID TPMI_ECC_KEY_EXCHANGE;


// Table 64 -- TPMI_ST_COMMAND_TAG Type <I/O>
typedef TPM_ST TPMI_ST_COMMAND_TAG;


// Table 65 -- TPMS_ALGORITHM_DESCRIPTION Structure <O,S>
typedef struct {
    TPM_ALG_ID        alg;
    TPMA_ALGORITHM    attributes;
} TPMS_ALGORITHM_DESCRIPTION;

// Table 66 -- TPMU_HA Union <I/O,S>
typedef union {
#ifdef TPM_ALG_SHA1
    BYTE  sha1[SHA1_DIGEST_SIZE];  
#endif
#ifdef TPM_ALG_SHA256
    BYTE  sha256[SHA256_DIGEST_SIZE];  
#endif
#ifdef TPM_ALG_SM3_256
    BYTE  sm3_256[SM3_256_DIGEST_SIZE];  
#endif
#ifdef TPM_ALG_SHA384
    BYTE  sha384[SHA384_DIGEST_SIZE];  
#endif
#ifdef TPM_ALG_SHA512
    BYTE  sha512[SHA512_DIGEST_SIZE];  
#endif

} TPMU_HA ;


// Table 67 -- TPMT_HA Structure <I/O>
typedef struct {
    TPMI_ALG_HASH    hashAlg;
    TPMU_HA          digest;
} TPMT_HA;

// Table 68 -- TPM2B_DIGEST Structure <I/O>
typedef struct {
    UINT16    size;
    BYTE      buffer[sizeof(TPMU_HA)];
} DIGEST_2B;

typedef union {
    DIGEST_2B    t;
    TPM2B        b;
} TPM2B_DIGEST;

// Table 69 -- TPM2B_DATA Structure <I/O>
typedef struct {
    UINT16    size;
    BYTE      buffer[sizeof(TPMT_HA)];
} DATA_2B;

typedef union {
    DATA_2B    t;
    TPM2B      b;
} TPM2B_DATA;

// Table 70 -- TPM2B_NONCE Types <I/O>
typedef TPM2B_DIGEST    TPM2B_NONCE;

// Table 71 -- TPM2B_AUTH Types <I/O>
typedef TPM2B_DIGEST    TPM2B_AUTH;

// Table 72 -- TPM2B_OPERAND Types <I/O>
typedef TPM2B_DIGEST    TPM2B_OPERAND;

// Table 73 -- TPM2B_EVENT Structure <I/O>
typedef struct {
    UINT16    size;
    BYTE      buffer[1024];
} EVENT_2B;

typedef union {
    EVENT_2B    t;
    TPM2B       b;
} TPM2B_EVENT;

// Table 74 -- TPM2B_MAX_BUFFER Structure <I/O>
typedef struct {
    UINT16    size;
    BYTE      buffer[MAX_DIGEST_BUFFER];
} MAX_BUFFER_2B;

typedef union {
    MAX_BUFFER_2B    t;
    TPM2B            b;
} TPM2B_MAX_BUFFER;

// Table 75 -- TPM2B_MAX_NV_BUFFER Structure <I/O>
typedef struct {
    UINT16    size;
    BYTE      buffer[MAX_NV_INDEX_SIZE];
} MAX_NV_BUFFER_2B;

typedef union {
    MAX_NV_BUFFER_2B    t;
    TPM2B               b;
} TPM2B_MAX_NV_BUFFER;

// Table 76 -- TPM2B_TIMEOUT Structure <I/O>
typedef struct {
    UINT16    size;
    BYTE      buffer[sizeof(UINT64)];
} TIMEOUT_2B;

typedef union {
    TIMEOUT_2B    t;
    TPM2B         b;
} TPM2B_TIMEOUT;

// Table 77 -- TPM2B_IV Structure <I/O>
typedef struct {
    UINT16    size;
    BYTE      buffer[MAX_SYM_BLOCK_SIZE];
} IV_2B;

typedef union {
    IV_2B    t;
    TPM2B    b;
} TPM2B_IV;
typedef union {
    TPMT_HA  digest;  
    TPM_HANDLE  handle;  

} TPMU_NAME ;


// Table 79 -- TPM2B_NAME Structure <I/O>
typedef struct {
    UINT16    size;
    BYTE      name[sizeof(TPMU_NAME)];
} NAME_2B;

typedef union {
    NAME_2B    t;
    TPM2B      b;
} TPM2B_NAME;

// Table 80 -- TPMS_PCR_SELECT Structure <I/O>
typedef struct {
    UINT8    sizeofSelect;
    BYTE     pcrSelect[PCR_SELECT_MAX];
} TPMS_PCR_SELECT;

// Table 81 -- TPMS_PCR_SELECTION Structure <I/O>
typedef struct {
    TPMI_ALG_HASH    hash;
    UINT8            sizeofSelect;
    BYTE             pcrSelect[PCR_SELECT_MAX];
} TPMS_PCR_SELECTION;

// Table 84 -- TPMT_TK_CREATION Structure <I/O>
typedef struct {
    TPM_ST               tag;
    TPMI_RH_HIERARCHY    hierarchy;
    TPM2B_DIGEST         digest;
} TPMT_TK_CREATION;

// Table 85 -- TPMT_TK_VERIFIED Structure <I/O>
typedef struct {
    TPM_ST               tag;
    TPMI_RH_HIERARCHY    hierarchy;
    TPM2B_DIGEST         digest;
} TPMT_TK_VERIFIED;

// Table 86 -- TPMT_TK_AUTH Structure <I/O>
typedef struct {
    TPM_ST               tag;
    TPMI_RH_HIERARCHY    hierarchy;
    TPM2B_DIGEST         digest;
} TPMT_TK_AUTH;

// Table 87 -- TPMT_TK_HASHCHECK Structure <I/O>
typedef struct {
    TPM_ST               tag;
    TPMI_RH_HIERARCHY    hierarchy;
    TPM2B_DIGEST         digest;
} TPMT_TK_HASHCHECK;

// Table 88 -- TPMS_ALG_PROPERTY Structure <O,S>
typedef struct {
    TPM_ALG_ID        alg;
    TPMA_ALGORITHM    algProperties;
} TPMS_ALG_PROPERTY;

// Table 89 -- TPMS_TAGGED_PROPERTY Structure <O,S>
typedef struct {
    TPM_PT    property;
    UINT32    value;
} TPMS_TAGGED_PROPERTY;

// Table 90 -- TPMS_TAGGED_PCR_SELECT Structure <O,S>
typedef struct {
    TPM_PT    tag;
    UINT8     sizeofSelect;
    BYTE      pcrSelect[PCR_SELECT_MAX];
} TPMS_TAGGED_PCR_SELECT;

// Table 91 -- TPML_CC Structure <I/O>
typedef struct {
    UINT32    count;
    TPM_CC    commandCodes[MAX_CAP_CC];
} TPML_CC;

// Table 92 -- TPML_CCA Structure <O,S>
typedef struct {
    UINT32     count;
    TPMA_CC    commandAttributes[MAX_CAP_CC];
} TPML_CCA;

// Table 93 -- TPML_ALG Structure <I/O>
typedef struct {
    UINT32        count;
    TPM_ALG_ID    algorithms[MAX_ALG_LIST_SIZE];
} TPML_ALG;

// Table 94 -- TPML_HANDLE Structure <O,S>
typedef struct {
    UINT32        count;
    TPM_HANDLE    handle[MAX_CAP_HANDLES];
} TPML_HANDLE;

// Table 95 -- TPML_DIGEST Structure <I/O>
typedef struct {
    UINT32          count;
    TPM2B_DIGEST    digests[8];
} TPML_DIGEST;

// Table 96 -- TPML_DIGEST_VALUES Structure <I/O>
typedef struct {
    UINT32     count;
    TPMT_HA    digests[HASH_COUNT];
} TPML_DIGEST_VALUES;

// Table 97 -- TPM2B_DIGEST_VALUES Structure <I/O>
typedef struct {
    UINT16    size;
    BYTE      buffer[sizeof(TPML_DIGEST_VALUES)];
} DIGEST_VALUES_2B;

typedef union {
    DIGEST_VALUES_2B    t;
    TPM2B               b;
} TPM2B_DIGEST_VALUES;

// Table 98 -- TPML_PCR_SELECTION Structure <I/O>
typedef struct {
    UINT32                count;
    TPMS_PCR_SELECTION    pcrSelections[HASH_COUNT];
} TPML_PCR_SELECTION;

// Table 99 -- TPML_ALG_PROPERTY Structure <O,S>
typedef struct {
    UINT32               count;
    TPMS_ALG_PROPERTY    algProperties[MAX_CAP_ALGS];
} TPML_ALG_PROPERTY;

// Table 100 -- TPML_TAGGED_TPM_PROPERTY Structure <O,S>
typedef struct {
    UINT32                  count;
    TPMS_TAGGED_PROPERTY    tpmProperty[MAX_TPM_PROPERTIES];
} TPML_TAGGED_TPM_PROPERTY;

// Table 101 -- TPML_TAGGED_PCR_PROPERTY Structure <O,S>
typedef struct {
    UINT32                    count;
    TPMS_TAGGED_PCR_SELECT    pcrProperty[MAX_PCR_PROPERTIES];
} TPML_TAGGED_PCR_PROPERTY;

// Table 102 -- TPML_ECC_CURVE Structure <O,S>
typedef struct {
    UINT32           count;
    TPM_ECC_CURVE    eccCurves[MAX_ECC_CURVES];
} TPML_ECC_CURVE;

// Table 103 -- TPMU_CAPABILITIES Union <O,S>
typedef union {
    TPML_ALG_PROPERTY  algorithms;  
    TPML_HANDLE  handles;  
    TPML_CCA  command;  
    TPML_CC  ppCommands;  
    TPML_CC  auditCommands;  
    TPML_PCR_SELECTION  assignedPCR;  
    TPML_TAGGED_TPM_PROPERTY  tpmProperties;  
    TPML_TAGGED_PCR_PROPERTY  pcrProperties;  
#ifdef TPM_ALG_ECC
    TPML_ECC_CURVE  eccCurves;  
#endif

} TPMU_CAPABILITIES ;


// Table 104 -- TPMS_CAPABILITY_DATA Structure <O,S>
typedef struct {
    TPM_CAP              capability;
    TPMU_CAPABILITIES    data;
} TPMS_CAPABILITY_DATA;

// Table 105 -- TPMS_CLOCK_INFO Structure <I/O>
typedef struct {
    UINT64         clock;
    UINT32         resetCount;
    UINT32         restartCount;
    TPMI_YES_NO    safe;
} TPMS_CLOCK_INFO;

// Table 106 -- TPMS_TIME_INFO Structure <I/O>
typedef struct {
    UINT64             time;
    TPMS_CLOCK_INFO    clockInfo;
} TPMS_TIME_INFO;

// Table 107 -- TPMS_TIME_ATTEST_INFO Structure <O,S>
typedef struct {
    TPMS_TIME_INFO    time;
    UINT64            firmwareVersion;
} TPMS_TIME_ATTEST_INFO;

// Table 108 -- TPMS_CERTIFY_INFO Structure <O,S>
typedef struct {
    TPM2B_NAME    name;
    TPM2B_NAME    qualifiedName;
} TPMS_CERTIFY_INFO;

// Table 109 -- TPMS_QUOTE_INFO Structure <O,S>
typedef struct {
    TPML_PCR_SELECTION    pcrSelect;
    TPM2B_DIGEST          pcrDigest;
} TPMS_QUOTE_INFO;

// Table 110 -- TPMS_COMMAND_AUDIT_INFO Structure <O,S>
typedef struct {
    UINT64          auditCounter;
    TPM_ALG_ID      digestAlg;
    TPM2B_DIGEST    auditDigest;
    TPM2B_DIGEST    commandDigest;
} TPMS_COMMAND_AUDIT_INFO;

// Table 111 -- TPMS_SESSION_AUDIT_INFO Structure <O,S>
typedef struct {
    TPMI_YES_NO     exclusiveSession;
    TPM2B_DIGEST    sessionDigest;
} TPMS_SESSION_AUDIT_INFO;

// Table 112 -- TPMS_CREATION_INFO Structure <O,S>
typedef struct {
    TPM2B_NAME      objectName;
    TPM2B_DIGEST    creationHash;
} TPMS_CREATION_INFO;

// Table 113 -- TPMS_NV_CERTIFY_INFO Structure <O,S>
typedef struct {
    TPM2B_NAME             indexName;
    UINT16                 offset;
    TPM2B_MAX_NV_BUFFER    nvContents;
} TPMS_NV_CERTIFY_INFO;

// Table 114 -- TPMI_ST_ATTEST Type <O,S>
typedef TPM_ST TPMI_ST_ATTEST;


// Table 115 -- TPMU_ATTEST Union <O,S>
typedef union {
    TPMS_CERTIFY_INFO  certify;  
    TPMS_CREATION_INFO  creation;  
    TPMS_QUOTE_INFO  quote;  
    TPMS_COMMAND_AUDIT_INFO  commandAudit;  
    TPMS_SESSION_AUDIT_INFO  sessionAudit;  
    TPMS_TIME_ATTEST_INFO  time;  
    TPMS_NV_CERTIFY_INFO  nv;  

} TPMU_ATTEST ;


// Table 116 -- TPMS_ATTEST Structure <O,S>
typedef struct {
    TPM_GENERATED      magic;
    TPMI_ST_ATTEST     type;
    TPM2B_NAME         qualifiedSigner;
    TPM2B_DATA         extraData;
    TPMS_CLOCK_INFO    clockInfo;
    UINT64             firmwareVersion;
    TPMU_ATTEST        attested;
} TPMS_ATTEST;

// Table 117 -- TPM2B_ATTEST Structure <O,S>
typedef struct {
    UINT16 size;
    TPMS_ATTEST attestationData;
} ATTEST_2B;

typedef union {
    ATTEST_2B    t;
    TPM2B        b;
} TPM2B_ATTEST;

// Table 118 -- TPMS_AUTH_COMMAND Structure <I>
typedef struct {
    TPMI_SH_AUTH_SESSION    sessionHandle;
    TPM2B_NONCE             nonce;
    TPMA_SESSION            sessionAttributes;
    TPM2B_AUTH              hmac;
} TPMS_AUTH_COMMAND;

// Table 119 -- TPMS_AUTH_RESPONSE Structure <O,S>
typedef struct {
    TPM2B_NONCE     nonce;
    TPMA_SESSION    sessionAttributes;
    TPM2B_AUTH      hmac;
} TPMS_AUTH_RESPONSE;

// Table 120 -- TPMI_AES_KEY_BITS Type <I/O>
typedef TPM_KEY_BITS TPMI_AES_KEY_BITS;


// Table 121 -- TPMI_SM4_KEY_BITS Type <I/O>
typedef TPM_KEY_BITS TPMI_SM4_KEY_BITS;


// Table 122 -- TPMU_SYM_KEY_BITS Union <I/O>
typedef union {
#ifdef TPM_ALG_AES
    TPMI_AES_KEY_BITS  aes;
#endif
#ifdef TPM_ALG_SM4
    TPMI_SM4_KEY_BITS  SM4;
#endif
    TPM_KEY_BITS  sym;
#ifdef TPM_ALG_XOR
    TPMI_ALG_HASH  xOr;
#endif

} TPMU_SYM_KEY_BITS ;


// Table 123 -- TPMU_SYM_MODE Union <I/O>
typedef union {
#ifdef TPM_ALG_AES
    TPMI_ALG_SYM_MODE  aes;  
#endif
#ifdef TPM_ALG_SM4
    TPMI_ALG_SYM_MODE  SM4;  
#endif
    TPMI_ALG_SYM_MODE  sym;  

} TPMU_SYM_MODE ;


// Table 125 -- TPMT_SYM_DEF Structure <I/O>
typedef struct {
    TPMI_ALG_SYM         algorithm;
    TPMU_SYM_KEY_BITS    keyBits;
    TPMU_SYM_MODE        mode;
} TPMT_SYM_DEF;

// Table 126 -- TPMT_SYM_DEF_OBJECT Structure <I/O>
typedef struct {
    TPMI_ALG_SYM_OBJECT    algorithm;
    TPMU_SYM_KEY_BITS      keyBits;
    TPMU_SYM_MODE          mode;
} TPMT_SYM_DEF_OBJECT;

// Table 127 -- TPM2B_SYM_KEY Structure <I/O>
typedef struct {
    UINT16    size;
    BYTE      buffer[MAX_SYM_KEY_BYTES];
} SYM_KEY_2B;

typedef union {
    SYM_KEY_2B    t;
    TPM2B         b;
} TPM2B_SYM_KEY;

// Table 128 -- TPMS_SYMCIPHER_PARMS Structure <I/O>
typedef struct {
    TPMT_SYM_DEF_OBJECT    sym;
} TPMS_SYMCIPHER_PARMS;

// Table 129 -- TPM2B_SENSITIVE_DATA Structure <I/O>
typedef struct {
    UINT16    size;
    BYTE      buffer[MAX_SYM_DATA];
} SENSITIVE_DATA_2B;

typedef union {
    SENSITIVE_DATA_2B    t;
    TPM2B                b;
} TPM2B_SENSITIVE_DATA;

// Table 130 -- TPMS_SENSITIVE_CREATE Structure <I>
typedef struct {
    TPM2B_AUTH              userAuth;
    TPM2B_SENSITIVE_DATA    data;
} TPMS_SENSITIVE_CREATE;

// Table 131 -- TPM2B_SENSITIVE_CREATE Structure <I,S>
typedef struct {
    UINT16                   size;
    TPMS_SENSITIVE_CREATE    sensitive;
} SENSITIVE_CREATE_2B;

typedef union {
    SENSITIVE_CREATE_2B    t;
    TPM2B                  b;
} TPM2B_SENSITIVE_CREATE;

// Table 132 -- TPMS_SCHEME_SIGHASH Structure <I/O>
typedef struct {
    TPMI_ALG_HASH    hashAlg;
} TPMS_SCHEME_SIGHASH;

// Table 133 -- TPMI_ALG_KEYEDHASH_SCHEME Type <I/O>
typedef TPM_ALG_ID TPMI_ALG_KEYEDHASH_SCHEME;


// Table 134 -- HMAC_SIG_SCHEME Types <I/O>
typedef TPMS_SCHEME_SIGHASH    TPMS_SCHEME_HMAC;

// Table 135 -- TPMS_SCHEME_XOR Structure <I/O>
typedef struct {
    TPMI_ALG_HASH    hashAlg;
    TPMI_ALG_KDF     kdf;
} TPMS_SCHEME_XOR;

// Table 136 -- TPMU_SCHEME_KEYEDHASH Union <I/O,S>
typedef union {
#ifdef TPM_ALG_HMAC
    TPMS_SCHEME_HMAC  hmac;  
#endif
#ifdef TPM_ALG_XOR
    TPMS_SCHEME_XOR  xOr;  
#endif

} TPMU_SCHEME_KEYEDHASH ;


// Table 137 -- TPMT_KEYEDHASH_SCHEME Structure <I/O>
typedef struct {
    TPMI_ALG_KEYEDHASH_SCHEME    scheme;
    TPMU_SCHEME_KEYEDHASH        details;
} TPMT_KEYEDHASH_SCHEME;

// Table 138 -- RSA_SIG_SCHEMES Types <I/O>
typedef TPMS_SCHEME_SIGHASH    TPMS_SCHEME_RSASSA;
typedef TPMS_SCHEME_SIGHASH    TPMS_SCHEME_RSAPSS;

// Table 139 -- ECC_SIG_SCHEMES Types <I/O>
typedef TPMS_SCHEME_SIGHASH    TPMS_SCHEME_ECDSA;
typedef TPMS_SCHEME_SIGHASH    TPMS_SCHEME_SM2;
typedef TPMS_SCHEME_SIGHASH    TPMS_SCHEME_ECSCHNORR;

// Table 140 -- TPMS_SCHEME_ECDAA Structure <I/O>
typedef struct {
    TPMI_ALG_HASH    hashAlg;
    UINT16           count;
} TPMS_SCHEME_ECDAA;

// Table 141 -- TPMU_SIG_SCHEME Union <I/O,S>
typedef union {
#ifdef TPM_ALG_RSASSA
    TPMS_SCHEME_RSASSA  rsassa;  
#endif
#ifdef TPM_ALG_RSAPSS
    TPMS_SCHEME_RSAPSS  rsapss;  
#endif
#ifdef TPM_ALG_ECDSA
    TPMS_SCHEME_ECDSA  ecdsa;  
#endif
#ifdef TPM_ALG_SM2
    TPMS_SCHEME_SM2  sm2;  
#endif
#ifdef TPM_ALG_ECDAA
    TPMS_SCHEME_ECDAA  ecdaa;  
#endif
#ifdef TPM_ALG_ECSCHNORR
    TPMS_SCHEME_ECSCHNORR  ecSchnorr;  
#endif
#ifdef TPM_ALG_HMAC
    TPMS_SCHEME_HMAC  hmac;  
#endif
    TPMS_SCHEME_SIGHASH  any;  

} TPMU_SIG_SCHEME ;


// Table 142 -- TPMT_SIG_SCHEME Structure <I/O>
typedef struct {
    TPMI_ALG_SIG_SCHEME    scheme;
    TPMU_SIG_SCHEME        details;
} TPMT_SIG_SCHEME;

// Table 143 -- TPMS_SCHEME_OAEP Structure <I/O>
typedef struct {
    TPMI_ALG_HASH    hashAlg;
} TPMS_SCHEME_OAEP;

// Table 144 -- TPMS_SCHEME_ECDH Structure <I/O>
typedef struct {
    TPMI_ALG_HASH    hashAlg;
} TPMS_SCHEME_ECDH;

// Table 145 -- TPMS_SCHEME_MGF1 Structure <I/O>
typedef struct {
    TPMI_ALG_HASH    hashAlg;
} TPMS_SCHEME_MGF1;

// Table 146 -- TPMS_SCHEME_KDF1_SP800_56a Structure <I/O>
typedef struct {
    TPMI_ALG_HASH    hashAlg;
} TPMS_SCHEME_KDF1_SP800_56a;

// Table 147 -- TPMS_SCHEME_KDF2 Structure <I/O>
typedef struct {
    TPMI_ALG_HASH    hashAlg;
} TPMS_SCHEME_KDF2;

// Table 148 -- TPMS_SCHEME_KDF1_SP800_108 Structure <I/O>
typedef struct {
    TPMI_ALG_HASH    hashAlg;
} TPMS_SCHEME_KDF1_SP800_108;

// Table 149 -- TPMU_KDF_SCHEME Union <I/O,S>
typedef union {
#ifdef TPM_ALG_MGF1
    TPMS_SCHEME_MGF1  mgf1;  
#endif
#ifdef TPM_ALG_KDF1_SP800_56a
    TPMS_SCHEME_KDF1_SP800_56a  kdf1_SP800_56a;  
#endif
#ifdef TPM_ALG_KDF2
    TPMS_SCHEME_KDF2  kdf2;  
#endif
#ifdef TPM_ALG_KDF1_SP800_108
    TPMS_SCHEME_KDF1_SP800_108  kdf1_sp800_108;  
#endif

} TPMU_KDF_SCHEME ;


// Table 150 -- TPMT_KDF_SCHEME Structure <I/O>
typedef struct {
    TPMI_ALG_KDF       scheme;
    TPMU_KDF_SCHEME    details;
} TPMT_KDF_SCHEME;
typedef TPM_ALG_ID TPMI_ALG_ASYM_SCHEME;


// Table 152 -- TPMU_ASYM_SCHEME Union <I/O>
typedef union {
#ifdef TPM_ALG_RSASSA
    TPMS_SCHEME_RSASSA  rsassa;  
#endif
#ifdef TPM_ALG_RSAPSS
    TPMS_SCHEME_RSAPSS  rsapss;  
#endif
#ifdef TPM_ALG_OAEP
    TPMS_SCHEME_OAEP  oaep;  
#endif
#ifdef TPM_ALG_ECDSA
    TPMS_SCHEME_ECDSA  ecdsa;  
#endif
#ifdef TPM_ALG_SM2
    TPMS_SCHEME_SM2  sm2;  
#endif
#ifdef TPM_ALG_ECDAA
    TPMS_SCHEME_ECDAA  ecdaa;  
#endif
#ifdef TPM_ALG_ECSCHNORR
    TPMS_SCHEME_ECSCHNORR  ecSchnorr;  
#endif
    TPMS_SCHEME_SIGHASH  anySig;  

} TPMU_ASYM_SCHEME ;

typedef struct {
    TPMI_ALG_ASYM_SCHEME    scheme;
    TPMU_ASYM_SCHEME        details;
} TPMT_ASYM_SCHEME;

// Table 154 -- TPMI_ALG_RSA_SCHEME Type <I/O>
typedef TPM_ALG_ID TPMI_ALG_RSA_SCHEME;


// Table 155 -- TPMT_RSA_SCHEME Structure <I/O>
typedef struct {
    TPMI_ALG_RSA_SCHEME    scheme;
    TPMU_ASYM_SCHEME       details;
} TPMT_RSA_SCHEME;

// Table 156 -- TPMI_ALG_RSA_DECRYPT Type <I/O>
typedef TPM_ALG_ID TPMI_ALG_RSA_DECRYPT;


// Table 157 -- TPMT_RSA_DECRYPT Structure <I/O>
typedef struct {
    TPMI_ALG_RSA_DECRYPT    scheme;
    TPMU_ASYM_SCHEME        details;
} TPMT_RSA_DECRYPT;

// Table 158 -- TPM2B_PUBLIC_KEY_RSA Structure <I/O>
typedef struct {
    UINT16    size;
    BYTE      buffer[MAX_RSA_KEY_BYTES];
} PUBLIC_KEY_RSA_2B;

typedef union {
    PUBLIC_KEY_RSA_2B    t;
    TPM2B                b;
} TPM2B_PUBLIC_KEY_RSA;

// Table 159 -- TPMI_RSA_KEY_BITS Type <I/O>
typedef TPM_KEY_BITS TPMI_RSA_KEY_BITS;


// Table 160 -- TPM2B_PRIVATE_KEY_RSA Structure <I/O>
typedef struct {
    UINT16    size;
    BYTE      buffer[MAX_RSA_KEY_BYTES/2];
} PRIVATE_KEY_RSA_2B;

typedef union {
    PRIVATE_KEY_RSA_2B    t;
    TPM2B                 b;
} TPM2B_PRIVATE_KEY_RSA;

// Table 161 -- TPM2B_ECC_PARAMETER Structure <I/O>
typedef struct {
    UINT16    size;
    BYTE      buffer[MAX_ECC_KEY_BYTES];
} ECC_PARAMETER_2B;

typedef union {
    ECC_PARAMETER_2B    t;
    TPM2B               b;
} TPM2B_ECC_PARAMETER;

// Table 162 -- TPMS_ECC_POINT Structure <I/O>
typedef struct {
    TPM2B_ECC_PARAMETER    x;
    TPM2B_ECC_PARAMETER    y;
} TPMS_ECC_POINT;

// Table 163 -- TPM2B_ECC_POINT Structure <I/O>
typedef struct {
    UINT16            size;
    TPMS_ECC_POINT    point;
} ECC_POINT_2B;

typedef union {
    ECC_POINT_2B    t;
    TPM2B           b;
} TPM2B_ECC_POINT;

// Table 164 -- TPMI_ALG_ECC_SCHEME Type <I/O>
typedef TPM_ALG_ID TPMI_ALG_ECC_SCHEME;


// Table 165 -- TPMI_ECC_CURVE Type <I/O>
typedef TPM_ECC_CURVE TPMI_ECC_CURVE;


// Table 166 -- TPMT_ECC_SCHEME Structure <I/O>
typedef struct {
    TPMI_ALG_ECC_SCHEME    scheme;
    TPMU_SIG_SCHEME        details;
} TPMT_ECC_SCHEME;

// Table 167 -- TPMS_ALGORITHM_DETAIL_ECC Structure <O,S>
typedef struct {
    TPM_ECC_CURVE          curveID;
    UINT16                 keySize;
    TPMT_KDF_SCHEME        kdf;
    TPMT_ECC_SCHEME        sign;
    TPM2B_ECC_PARAMETER    p;
    TPM2B_ECC_PARAMETER    a;
    TPM2B_ECC_PARAMETER    b;
    TPM2B_ECC_PARAMETER    gX;
    TPM2B_ECC_PARAMETER    gY;
    TPM2B_ECC_PARAMETER    n;
    TPM2B_ECC_PARAMETER    h;
} TPMS_ALGORITHM_DETAIL_ECC;

// Table 168 -- TPMS_SIGNATURE_RSASSA Structure <I/O>
typedef struct {
    TPMI_ALG_HASH           hash;
    TPM2B_PUBLIC_KEY_RSA    sig;
} TPMS_SIGNATURE_RSASSA;

// Table 169 -- TPMS_SIGNATURE_RSAPSS Structure <I/O>
typedef struct {
    TPMI_ALG_HASH           hash;
    TPM2B_PUBLIC_KEY_RSA    sig;
} TPMS_SIGNATURE_RSAPSS;

// Table 170 -- TPMS_SIGNATURE_ECDSA Structure <I/O>
typedef struct {
    TPMI_ALG_HASH          hash;
    TPM2B_ECC_PARAMETER    signatureR;
    TPM2B_ECC_PARAMETER    signatureS;
} TPMS_SIGNATURE_ECDSA;

// Table 171 -- TPMU_SIGNATURE Union <I/O,S>
typedef union {
#ifdef TPM_ALG_RSASSA
    TPMS_SIGNATURE_RSASSA  rsassa;  
#endif
#ifdef TPM_ALG_RSAPSS
    TPMS_SIGNATURE_RSAPSS  rsapss;  
#endif
#ifdef TPM_ALG_ECDSA
    TPMS_SIGNATURE_ECDSA  ecdsa;  
#endif
#ifdef TPM_ALG_SM2
    TPMS_SIGNATURE_ECDSA  sm2;  
#endif
#ifdef TPM_ALG_ECDAA
    TPMS_SIGNATURE_ECDSA  ecdaa;  
#endif
#ifdef TPM_ALG_ECSCHNORR
    TPMS_SIGNATURE_ECDSA  ecschnorr;  
#endif
#ifdef TPM_ALG_HMAC
    TPMT_HA  hmac;  
#endif
    TPMS_SCHEME_SIGHASH  any;  

} TPMU_SIGNATURE ;


// Table 172 -- TPMT_SIGNATURE Structure <I/O>
typedef struct {
    TPMI_ALG_SIG_SCHEME    sigAlg;
    TPMU_SIGNATURE         signature;
} TPMT_SIGNATURE;
typedef union {
#ifdef TPM_ALG_ECC
    BYTE  ecc[sizeof(TPMS_ECC_POINT)];  
#endif
#ifdef TPM_ALG_RSA
    BYTE  rsa[MAX_RSA_KEY_BYTES];  
#endif
#ifdef TPM_ALG_SYMCIPHER
    BYTE  symmetric[sizeof(TPM2B_DIGEST)];  
#endif
#ifdef TPM_ALG_KEYEDHASH
    BYTE  keyedHash[sizeof(TPM2B_DIGEST)];  
#endif

} TPMU_ENCRYPTED_SECRET ;


// Table 174 -- TPM2B_ENCRYPTED_SECRET Structure <I/O>
typedef struct {
    UINT16    size;
    BYTE      secret[sizeof(TPMU_ENCRYPTED_SECRET)];
} ENCRYPTED_SECRET_2B;

typedef union {
    ENCRYPTED_SECRET_2B    t;
    TPM2B                  b;
} TPM2B_ENCRYPTED_SECRET;

// Table 175 -- TPMI_ALG_PUBLIC Type <I/O>
typedef TPM_ALG_ID TPMI_ALG_PUBLIC;


// Table 176 -- TPMU_PUBLIC_ID Union <I/O,S>
typedef union {
#ifdef TPM_ALG_KEYEDHASH
    TPM2B_DIGEST  keyedHash;  
#endif
#ifdef TPM_ALG_SYMCIPHER
    TPM2B_DIGEST  sym;  
#endif
#ifdef TPM_ALG_RSA
    TPM2B_PUBLIC_KEY_RSA  rsa;  
#endif
#ifdef TPM_ALG_ECC
    TPMS_ECC_POINT  ecc;  
#endif

} TPMU_PUBLIC_ID ;


// Table 177 -- TPMS_KEYEDHASH_PARMS Structure <I/O>
typedef struct {
    TPMT_KEYEDHASH_SCHEME    scheme;
} TPMS_KEYEDHASH_PARMS;
typedef struct {
    TPMT_SYM_DEF_OBJECT    symmetric;
    TPMT_ASYM_SCHEME       scheme;
} TPMS_ASYM_PARMS;

// Table 179 -- TPMS_RSA_PARMS Structure <I/O>
typedef struct {
    TPMT_SYM_DEF_OBJECT    symmetric;
    TPMT_RSA_SCHEME        scheme;
    TPMI_RSA_KEY_BITS      keyBits;
    UINT32                 exponent;
} TPMS_RSA_PARMS;

// Table 180 -- TPMS_ECC_PARMS Structure <I/O>
typedef struct {
    TPMT_SYM_DEF_OBJECT    symmetric;
    TPMT_ECC_SCHEME        scheme;
    TPMI_ECC_CURVE         curveID;
    TPMT_KDF_SCHEME        kdf;
} TPMS_ECC_PARMS;

// Table 181 -- TPMU_PUBLIC_PARMS Union <I/O,S>
typedef union {
#ifdef TPM_ALG_KEYEDHASH
    TPMS_KEYEDHASH_PARMS  keyedHashDetail;  
#endif
#ifdef TPM_ALG_SYMCIPHER
    TPMT_SYM_DEF_OBJECT  symDetail;  
#endif
#ifdef TPM_ALG_RSA
    TPMS_RSA_PARMS  rsaDetail;  
#endif
#ifdef TPM_ALG_ECC
    TPMS_ECC_PARMS  eccDetail;  
#endif
    TPMS_ASYM_PARMS  asymDetail;  

} TPMU_PUBLIC_PARMS ;


// Table 182 -- TPMT_PUBLIC_PARMS Structure <I/O>
typedef struct {
    TPMI_ALG_PUBLIC      type;
    TPMU_PUBLIC_PARMS    parameters;
} TPMT_PUBLIC_PARMS;

// Table 183 -- TPMT_PUBLIC Structure <I/O>
typedef struct {
    TPMI_ALG_PUBLIC      type;
    TPMI_ALG_HASH        nameAlg;
    TPMA_OBJECT          objectAttributes;
    TPM2B_DIGEST         authPolicy;
    TPMU_PUBLIC_PARMS    parameters;
    TPMU_PUBLIC_ID       unique;
} TPMT_PUBLIC;

// Table 184 -- TPM2B_PUBLIC Structure <I/O>
typedef struct {
    UINT16         size;
    TPMT_PUBLIC    publicArea;
} PUBLIC_2B;

typedef union {
    PUBLIC_2B    t;
    TPM2B        b;
} TPM2B_PUBLIC;
typedef struct {
    UINT16    size;
    BYTE      buffer[PRIVATE_VENDOR_SPECIFIC_BYTES];
} PRIVATE_VENDOR_SPECIFIC_2B;

typedef union {
    PRIVATE_VENDOR_SPECIFIC_2B    t;
    TPM2B                         b;
} TPM2B_PRIVATE_VENDOR_SPECIFIC;

// Table 186 -- TPMU_SENSITIVE_COMPOSITE Union <I/O,S>
typedef union {
#ifdef TPM_ALG_RSA
    TPM2B_PRIVATE_KEY_RSA  rsa;  
#endif
#ifdef TPM_ALG_ECC
    TPM2B_ECC_PARAMETER  ecc;  
#endif
#ifdef TPM_ALG_KEYEDHASH
    TPM2B_SENSITIVE_DATA  bits;  
#endif
#ifdef TPM_ALG_SYMCIPHER
    TPM2B_SYM_KEY  sym;  
#endif
    TPM2B_PRIVATE_VENDOR_SPECIFIC  any;  

} TPMU_SENSITIVE_COMPOSITE ;


// Table 187 -- TPMT_SENSITIVE Structure <I/O>
typedef struct {
    TPMI_ALG_PUBLIC             sensitiveType;
    TPM2B_AUTH                  authValue;
    TPM2B_DIGEST                seedValue;
    TPMU_SENSITIVE_COMPOSITE    sensitive;
} TPMT_SENSITIVE;

// Table 188 -- TPM2B_SENSITIVE Structure <I/O>
typedef struct {
    UINT16            size;
    TPMT_SENSITIVE    sensitiveArea;
} SENSITIVE_2B;

typedef union {
    SENSITIVE_2B    t;
    TPM2B           b;
} TPM2B_SENSITIVE;
typedef struct {
    TPM2B_DIGEST      integrityOuter;
    TPM2B_DIGEST      integrityInner;
    TPMT_SENSITIVE    sensitive;
} _PRIVATE;

// Table 190 -- TPM2B_PRIVATE Structure <I/O,S>
typedef struct {
    UINT16    size;
    BYTE      buffer[sizeof(_PRIVATE)];
} PRIVATE_2B;

typedef union {
    PRIVATE_2B    t;
    TPM2B         b;
} TPM2B_PRIVATE;
typedef struct {
    TPM2B_DIGEST    integrityHMAC;
    TPM2B_DIGEST    encIdentity;
} _ID_OBJECT;

// Table 192 -- TPM2B_ID_OBJECT Structure <I/O>
typedef struct {
    UINT16    size;
    BYTE      credential[sizeof(_ID_OBJECT)];
} ID_OBJECT_2B;

typedef union {
    ID_OBJECT_2B    t;
    TPM2B           b;
} TPM2B_ID_OBJECT;
typedef struct {
    unsigned int index : 24;
    unsigned int RH_NV : 8;
} TPM_NV_INDEX ;

// Table 195 -- TPMA_NV Bits <I/O>
typedef struct {
    unsigned int TPMA_NV_PPWRITE        : 1;
    unsigned int TPMA_NV_OWNERWRITE     : 1;
    unsigned int TPMA_NV_AUTHWRITE      : 1;
    unsigned int TPMA_NV_POLICYWRITE    : 1;
    unsigned int TPMA_NV_COUNTER        : 1;
    unsigned int TPMA_NV_BITS           : 1;
    unsigned int TPMA_NV_EXTEND         : 1;
    unsigned int reserved8              : 3;
    unsigned int TPMA_NV_POLICY_DELETE  : 1;
    unsigned int TPMA_NV_WRITELOCKED    : 1;
    unsigned int TPMA_NV_WRITEALL       : 1;
    unsigned int TPMA_NV_WRITEDEFINE    : 1;
    unsigned int TPMA_NV_WRITE_STCLEAR  : 1;
    unsigned int TPMA_NV_GLOBALLOCK     : 1;
    unsigned int TPMA_NV_PPREAD         : 1;
    unsigned int TPMA_NV_OWNERREAD      : 1;
    unsigned int TPMA_NV_AUTHREAD       : 1;
    unsigned int TPMA_NV_POLICYREAD     : 1;
    unsigned int reserved19             : 5;
    unsigned int TPMA_NV_NO_DA          : 1;
    unsigned int TPMA_NV_ORDERLY        : 1;
    unsigned int TPMA_NV_CLEAR_STCLEAR  : 1;
    unsigned int TPMA_NV_READLOCKED     : 1;
    unsigned int TPMA_NV_WRITTEN        : 1;
    unsigned int TPMA_NV_PLATFORMCREATE : 1;
    unsigned int TPMA_NV_READ_STCLEAR   : 1;
} TPMA_NV ;

// Table 196 -- TPMS_NV_PUBLIC Structure <I/O>
typedef struct {
    TPMI_RH_NV_INDEX    nvIndex;
    TPMI_ALG_HASH       nameAlg;
    TPMA_NV             attributes;
    TPM2B_DIGEST        authPolicy;
    UINT16              dataSize;
} TPMS_NV_PUBLIC;

// Table 197 -- TPM2B_NV_PUBLIC Structure <I/O>
typedef struct {
    UINT16            size;
    TPMS_NV_PUBLIC    nvPublic;
} NV_PUBLIC_2B;

typedef union {
    NV_PUBLIC_2B    t;
    TPM2B           b;
} TPM2B_NV_PUBLIC;

// Table 198 -- TPM2B_CONTEXT_SENSITIVE Structure <I/O>
typedef struct {
    UINT16    size;
    BYTE      buffer[MAX_CONTEXT_SIZE];
} CONTEXT_SENSITIVE_2B;

typedef union {
    CONTEXT_SENSITIVE_2B    t;
    TPM2B                   b;
} TPM2B_CONTEXT_SENSITIVE;

// Table 199 -- TPMS_CONTEXT_DATA Structure <I/O,S>
typedef struct {
    TPM2B_DIGEST               integrity;
    TPM2B_CONTEXT_SENSITIVE    encrypted;
} TPMS_CONTEXT_DATA;

// Table 200 -- TPM2B_CONTEXT_DATA Structure <I/O>
typedef struct {
    UINT16    size;
    BYTE      buffer[sizeof(TPMS_CONTEXT_DATA)];
} CONTEXT_DATA_2B;

typedef union {
    CONTEXT_DATA_2B    t;
    TPM2B              b;
} TPM2B_CONTEXT_DATA;

// Table 201 -- TPMS_CONTEXT Structure <I/O>
typedef struct {
    UINT64                sequence;
    TPMI_DH_CONTEXT       savedHandle;
    TPMI_RH_HIERARCHY     hierarchy;
    TPM2B_CONTEXT_DATA    contextBlob;
} TPMS_CONTEXT;

// Table 203 -- TPMS_CREATION_DATA Structure <O,S>
typedef struct {
    TPML_PCR_SELECTION    pcrSelect;
    TPM2B_DIGEST          pcrDigest;
    TPMA_LOCALITY         locality;
    TPM_ALG_ID            parentNameAlg;
    TPM2B_NAME            parentName;
    TPM2B_NAME            parentQualifiedName;
    TPM2B_DATA            outsideInfo;
} TPMS_CREATION_DATA;

// Table 204 -- TPM2B_CREATION_DATA Structure <O,S>
typedef struct {
    UINT16                size;
    TPMS_CREATION_DATA    creationData;
} CREATION_DATA_2B;

typedef union {
    CREATION_DATA_2B    t;
    TPM2B               b;
} TPM2B_CREATION_DATA;
#endif //_TPM_TYPES_H

#ifndef _SWAP_H
#define _SWAP_H

#if    NO_AUTO_ALIGN == YES || LITTLE_ENDIAN_TPM == YES

// The aggregation macros for machines that do not allow unaligned access or for
// little-endian machines.

// Aggregate bytes into an UINT
#define BYTE_ARRAY_TO_UINT8(b)   (UINT8)((b)[0])

#define BYTE_ARRAY_TO_UINT16(b)  (UINT16)(  ((b)[0] <<  8) \
                                          +  (b)[1])

#define BYTE_ARRAY_TO_UINT32(b)  (UINT32)(  ((b)[0] << 24) \
                                          + ((b)[1] << 16) \
                                          + ((b)[2] << 8 ) \
                                          +  (b)[3])

#define BYTE_ARRAY_TO_UINT64(b)  (UINT64)(  ((UINT64)(b)[0] << 56) \
                                          + ((UINT64)(b)[1] << 48) \
                                          + ((UINT64)(b)[2] << 40) \
                                          + ((UINT64)(b)[3] << 32) \
                                          + ((UINT64)(b)[4] << 24) \
                                          + ((UINT64)(b)[5] << 16) \
                                          + ((UINT64)(b)[6] <<  8) \
                                          +  (UINT64)(b)[7])

// Disaggregate a UINT into a byte array
#define UINT8_TO_BYTE_ARRAY(i, b)     ((b)[0] = (BYTE)(i), i)

#define UINT16_TO_BYTE_ARRAY(i, b)    ((b)[0] = (BYTE)((i) >>  8), \
                                       (b)[1] = (BYTE) (i),        \
                                       (i))

#define UINT32_TO_BYTE_ARRAY(i, b)    ((b)[0] = (BYTE)((i) >> 24), \
                                       (b)[1] = (BYTE)((i) >> 16), \
                                       (b)[2] = (BYTE)((i) >>  8), \
                                       (b)[3] = (BYTE) (i),        \
                                       (i))

#define UINT64_TO_BYTE_ARRAY(i, b)    ((b)[0] = (BYTE)((i) >> 56), \
                                       (b)[1] = (BYTE)((i) >> 48), \
                                       (b)[2] = (BYTE)((i) >> 40), \
                                       (b)[3] = (BYTE)((i) >> 32), \
                                       (b)[4] = (BYTE)((i) >> 24), \
                                       (b)[5] = (BYTE)((i) >> 16), \
                                       (b)[6] = (BYTE)((i) >>  8), \
                                       (b)[7] = (BYTE) (i),        \
                                       (i))

#else

// the big-endian macros for machines that allow unaligned memory access
// Aggregate a byte array into a UINT
#define BYTE_ARRAY_TO_UINT8(b)        *((UINT8  *)(b))
#define BYTE_ARRAY_TO_UINT16(b)       *((UINT16 *)(b))
#define BYTE_ARRAY_TO_UINT32(b)       *((UINT32 *)(b))
#define BYTE_ARRAY_TO_UINT64(b)       *((UINT64 *)(b))

// Disaggregate a UINT into a byte array


#define UINT8_TO_BYTE_ARRAY(i, b)   (*((UINT8  *)(b)) = (i))
#define UINT16_TO_BYTE_ARRAY(i, b)  (*((UINT16 *)(b)) = (i))
#define UINT32_TO_BYTE_ARRAY(i, b)  (*((UINT32 *)(b)) = (i))
#define UINT64_TO_BYTE_ARRAY(i, b)  (*((UINT64 *)(b)) = (i))


#endif  // NO_AUTO_ALIGN == YES

#endif // _SWAP_H

#ifndef _TPM_ERROR_H
#define _TPM_ERROR_H

#include "assert.h"

#define     FATAL_ERROR_ALLOCATION  (1)
#define     FATAL_ERROR_DIVIDE_ZERO (2)
#define     FATAL_ERROR_INTERNAL    (3)
#define     FATAL_ERROR_PARAMETER   (4)

// These are the crypto assertion routines. When a function returns an unexpected
// and unrecoverable result, the assertion fails and the TpmFail() is called
int _plat__TpmFail(const char *function, int line, int code);
int TpmFail(
    const char* function,
    int line,
    int code
);

#ifdef EMPTY_ASSERT
    #define pAssert(a)
#else
    #define pAssert(a) (!!(a) || TpmFail(__FUNCTION__, \
                                         __LINE__,     \
                                         FATAL_ERROR_PARAMETER))
#endif

#define FAIL(a) (TpmFail(__FUNCTION__, __LINE__, a))

#endif //_TPM_ERROR_H

#ifndef _TPMB_H
#define _TPMB_H

// This macro helps avoid having to type in the structure in order to create
// a new TPM2B type that is used in a function.
#define TPM2B_TYPE(name, bytes)             \
    typedef union {                         \
        struct  {                           \
            UINT16  size;                   \
            BYTE    buffer[(bytes)];        \
        } t;                                \
        TPM2B   b;                          \
    } TPM2B_##name

// Macro to instance and initialize a TPM2B value
#define TPM2B_INIT(TYPE, name)  \
    TPM2B_##TYPE    name = {sizeof(name.t.buffer), {0}}

// A 2B structure for a seed
TPM2B_TYPE(SEED, PRIMARY_SEED_SIZE);

// A 2B hash block
TPM2B_TYPE(HASH_BLOCK, TPM_MAX_HASH_BLOCK_SIZE);

TPM2B_TYPE(RSA_PRIME, MAX_RSA_KEY_BYTES/2);

TPM2B_TYPE(1_BYTE_VALUE, 1);
TPM2B_TYPE(2_BYTE_VALUE, 2);
TPM2B_TYPE(4_BYTE_VALUE, 4);
TPM2B_TYPE(20_BYTE_VALUE, 20);
TPM2B_TYPE(32_BYTE_VALUE, 32);
TPM2B_TYPE(48_BYTE_VALUE, 48);
TPM2B_TYPE(64_BYTE_VALUE, 64);

TPM2B_TYPE(MAX_HASH_BLOCK, TPM_MAX_HASH_BLOCK_SIZE);

#endif //_TPMB_H

#ifndef         GLOBAL_H
#define         GLOBAL_H
//** Defines

// These definitions are for the types that can be in a hash state structure.
// These types are used in the crypto utilities
typedef BYTE    HASH_STATE_TYPE;
#define HASH_STATE_EMPTY        ((HASH_STATE_TYPE) 0)
#define HASH_STATE_HASH         ((HASH_STATE_TYPE) 1)
#define HASH_STATE_HMAC         ((HASH_STATE_TYPE) 2)

//** Hash State Structures

#ifndef CPRI_ALIGN
#   define CPRI_ALIGN
#endif

typedef union
{
    void *data;
} ALIGNED_HASH_STATE_ARRAY, *PALIGNED_HASH_STATE_ARRAY;

typedef struct _HASH_STATE
{
    ALIGNED_HASH_STATE_ARRAY    state;
    TPM_ALG_ID           hashAlg;
} CPRI_HASH_STATE, *PCPRI_HASH_STATE;

// A HASH_STATE structure contains an opaque hash stack state. A caller would
// use this structure when performing incremental hash operations. The state is
// updated on each call. If 'type' is an HMAC_STATE, or HMAC_STATE_SEQUENCE then
// state is followed by the HMAC key in oPad format.
typedef struct
{
    HASH_STATE_TYPE     type;               // type of the context
    CPRI_HASH_STATE     state;              // hash state
} HASH_STATE;

// An AUTH_VALUE is a BYTE array containing a digest (TPMU_HA)
typedef BYTE    AUTH_VALUE[sizeof(TPMU_HA)];  

// A TIME_INFO is a BYTE array that can contain a TPMS_TIME_INFO
typedef BYTE    TIME_INFO[sizeof(TPMS_TIME_INFO)];

// A NAME is a BYTE array that can contain a TPMU_NAME
typedef BYTE    NAME[sizeof(TPMU_NAME)];


// An HMAC_STATE structure contains an opaque HMAC stack state. A caller would
// use this structure when performing incremental HMAC operations. This structure
// contains a hash state and an HMAC key and allows slightly better stack
// optimization than adding an HMAC key to each hash state.

typedef struct
{
    HASH_STATE          hashState;          // the hash state
    TPM2B_HASH_BLOCK    hmacKey;            // the HMAC key
} HMAC_STATE;

//** Loaded Object Structures
//***Description
// The structures in this section define the object layout as it exists in TPM
// memory.
//
// Two types of objects are defined: an ordinary object such as a key, and a
// sequence object that may be a hash, HMAC, or event.
//
//***OBJECT_ATTRIBUTES
// An OBJECT_ATTRIBUTES structure contains the variable attributes of an object.
// These properties are not part of the public properties but are used by the
// TPM in managing the object. An OBJECT_ATTRIBUTES is used in the definition of
// the OBJECT data type.


typedef struct
{
    unsigned            publicOnly   : 1;   //0) SET if only the public portion of
                                            //   an object is loaded
    unsigned            epsHierarchy : 1;   //1) SET if the object belongs to EPS
                                            //   Hierarchy
    unsigned            ppsHierarchy : 1;   //2) SET if the object belongs to PPS
                                            //   Hierarchy
    unsigned            spsHierarchy : 1;   //3) SET f the object belongs to SPS
                                            //   Hierarchy
    unsigned            evict        : 1;   //4) SET if the object is a platform or
                                            //   owner evict object.  Platform-
                                            //   evict object belongs to PPS 
                                            //   hierarchy, owner-evict object 
                                            //   belongs to SPS or EPS hierarchy.
                                            //   This bit is also used to mark a
                                            //   completed sequence object so it 
                                            //   will be flush when the 
                                            //   SequenceComplete command succeeds.
    unsigned            primary     : 1;    //5) SET for a primary object
    unsigned            temporary   : 1;    //6) SET for a temporary object
    unsigned            stClear     : 1;    //7) SET for an stClear object
    unsigned            hmacSeq     : 1;    //8) SET for an HMAC sequence object
    unsigned            hashSeq     : 1;    //9) SET for a hash sequence object
    unsigned            eventSeq    : 1;    //10) SET for an event sequence object
    unsigned            ticketSafe  : 1;    //11) SET if a ticket is safe to create 
                                            //    for hash sequence object
    unsigned            firstBlock  : 1;    //12) SET if the first block of hash 
                                            //    data has been received.  It 
                                            //    works with ticketSafe bit
    unsigned            isParent    : 1;    //13) SET if the key has the proper 
                                            //    attributes to be a parent key
    unsigned            privateExp  : 1;    //14) SET when the private exponent 
                                            //    of an RSA key has been validated.
    unsigned        reserved    : 1;    //15) reserved bits. unused.
} OBJECT_ATTRIBUTES;


//*** OBJECT Structure
// An OBJECT structure holds the object public, sensitive, and meta-data
// associated. This structure is implementation dependent. For this
// implementation, the structure is not optimized for space but rather
// for clarity of the reference implementation. Other implementations
// may choose to overlap portions of the structure that are not used
// simultaneously. These changes would necessitate changes to the source
// code but those changes would be compatible with the reference
// implementation.

typedef struct
{
    // The attributes field is required to be first followed by the publicArea.
    // This allows the overlay of the object structure and a sequence structure
    OBJECT_ATTRIBUTES       attributes;         // object attributes
    TPMT_PUBLIC             publicArea;         // public area of an object
    TPMT_SENSITIVE          sensitive;          // sensitive area of an object

#ifdef  TPM_ALG_RSA
    TPM2B_PUBLIC_KEY_RSA    privateExponent;   // Additional field for the private
                                            // exponent of an RSA key.
#endif
    TPM2B_NAME              qualifiedName;      // object qualified name
    TPMI_DH_OBJECT          evictHandle;        // if the object is an evict object,
                                            // the original handle is kept here.
                                            // The 'working' handle will be the
                                            // handle of an object slot.

    TPM2B_NAME              name;               // Name of the object name. Kept here
                                            // to avoid repeatedly computing it.
} OBJECT;

//*** HASH_OBJECT Structure
// This structure holds a hash sequence object or an event sequence object.
//
// The first four components of this structure are manually set to be the same as
// the first four components of the object structure. This prevents the object
// from being inadvertently misused as sequence objects occupy the same memory as
// a regular object. A debug check is present to make sure that the offsets are
// what they are supposed to be.
typedef struct
{
    OBJECT_ATTRIBUTES   attributes;         // The attributes of the HASH object
    TPMI_ALG_PUBLIC         type;               // algorithm
    TPMI_ALG_HASH           nameAlg;            // name algorithm
    TPMA_OBJECT             objectAttributes;   // object attributes

    // The data below is unique to a sequence object
    TPM2B_AUTH              auth;               // auth for use of sequence
    union
    {
        HASH_STATE          hashState[HASH_COUNT];
        HMAC_STATE          hmacState;
    }                       state;
} HASH_OBJECT;

//**AUTH_DUP Types
// These values are used in the authorization processing.

typedef UINT32          AUTH_ROLE;
#define AUTH_NONE       ((AUTH_ROLE)(0))
#define AUTH_USER       ((AUTH_ROLE)(1))
#define AUTH_ADMIN      ((AUTH_ROLE)(2))
#define AUTH_DUP        ((AUTH_ROLE)(3))

//** Active Session Context
//*** Description
// The structures in this section define the internal structure of a session
// context.
//
//*** SESSION_ATTRIBUTES
// The attributes in the SESSION_ATTRIBUTES structure track the various properties
// of the session. It maintains most of the tracking state information for the
// policy session. It is used within the SESSION structure.

typedef struct
{
    unsigned            isPolicy : 1;       //1) SET if the session may only
                                            //   be used for policy
    unsigned            isAudit : 1;        //2) SET if the session is used
                                            //   for audit
    unsigned            isBound : 1;        //3) SET if the session is bound to
                                            //   with an entity.
                                            //   This attribute will be CLEAR if 
                                            //   either isPolicy or isAudit is SET.
    unsigned            iscpHashDefined : 1;//4) SET if the cpHash has been defined
                                            //   This attribute is not SET unless
                                            //   'isPolicy' is SET.
    unsigned            isAuthValueNeeded : 1;
                                            //5) SET if the authValue is required 
                                            //   for computing the session HMAC. 
                                            //   This attribute is not SET unless 
                                            //   isPolicy is SET.
    unsigned            isPasswordNeeded : 1;
                                            //6) SET if a password authValue is
                                            //   required for authorization
                                            //   This attribute is not SET unless
                                            //   isPolicy is SET.
    unsigned            isPPRequired : 1;   //7) SET if physical presence is 
                                            //   required to be asserted when the 
                                            //   authorization is checked.
                                            //   This attribute is not SET unless
                                            //   isPolicy is SET.
    unsigned            isTrialPolicy : 1;  //8) SET if the policy session is 
                                            //   created for trial of the policy's 
                                            //   policyHash generation.
                                            //   This attribute is not SET unless
                                            //   isPolicy is SET.
    unsigned            isDaBound : 1;      //9) SET if the bind entity had noDA
                                            //   CLEAR. If this is SET, then an
                                            //   auth failure using this session
                                            //   will count against lockout even 
                                            //   if the object being authorized is 
                                            //   exempt from DA.
    unsigned            isLockoutBound : 1; //10)SET if the session is bound to
                                            //   lockoutAuth.
} SESSION_ATTRIBUTES;

//*** SESSION Structure
// The SESION structure contains all the context of a session except for the
// associated contextID.
//
// Note: The contextID of a session is only relevant when the session context
// is stored off the TPM.

typedef struct
{
    TPM_HANDLE          handle;
    TPM2B_NAME          name;
    TPM_ALG_ID          authHashAlg;        // session hash algorithm
    TPM2B_NONCE         nonceTPM;           // last TPM-generated nonce for
                                            // this session
    TPM2B_NONCE         nonceCaller;

    TPMT_SYM_DEF        symmetric;          // session symmetric algorithm (if any)
    TPM2B_AUTH          sessionKey;         // session secret value used for
                                            // generating HMAC and encryption keys

    SESSION_ATTRIBUTES  sessionAttributes;  // session attributes
    TPM_CC              commandCode;        // command code (policy session)
    TPMA_LOCALITY       commandLocality;    // command locality (policy session)
    UINT32              pcrCounter;         // PCR counter value when PCR is
                                            // included (policy session)
                                            // If no PCR is included, this
                                            // value is 0.

    UINT64              startTime;          // value of TPMS_CLOCK_INFO.clock when
                                            // the session was started (policy
                                            // session)

    UINT64              timeOut;            // timeout relative to
                                            // TPMS_CLOCK_INFO.clock
                                            // There is no timeout if this value
                                            // is 0.
    union
    {
        TPM2B_NAME      boundEntity;         // value used to track the entity to
                                             // which the session is bound

        TPM2B_DIGEST    cpHash;              // the required cpHash value for the
                                             // command being authorized

    } u1;                                    // 'boundEntity' and 'cpHash' may 
                                             // share the same space to save memory

    union
    {
        TPM2B_DIGEST    auditDigest;        // audit session digest
        TPM2B_DIGEST    policyDigest;         // policyHash

    } u2;                                   // audit log and policyHash may
                                            // share space to save memory
    TPMA_SESSION        attributes;
} SESSION;

//***ANY_OBJECT
// This is the union for holding either a sequence object or a regular object.
typedef union
    {
        struct
        {
            TPM_HANDLE          handle;
            TPM2B_NAME          name;
        } generic;
        struct
        {
            TPM_HANDLE          handle;
            TPM2B_NAME          name;
            TPM2B_AUTH          authValue;
        } entity;
        struct
        {
            TPM_HANDLE          handle;
            TPM2B_NAME          name;
            TPM2B_AUTH          authValue;
            TPM2B_PUBLIC        publicArea;
            TPM2B_PRIVATE       privateArea;
        } obj;
        struct
        {
            TPM_HANDLE          handle;
            TPM2B_NAME          name;
            TPM2B_AUTH          authValue;
            TPM2B_NV_PUBLIC      nvPublic;
        } nv;
        struct
        {
            TPM_HANDLE          handle;
            TPM2B_NAME          name;
            TPM2B_AUTH          authValue;
        } sequence;
        SESSION session;
} ANY_OBJECT;

//*********************************************************************************
//** PCR
//*********************************************************************************
//***PCR_SAVE Structure
// The PCR_SAVE structure type contains the PCR data that are saved across power
// cycles. Only the static PCR are required to be saved across power cycles. The
// DRTM and resettable PCR are not saved. The number of static and resettable PCR
// is determined by the platform-specific specification to which the TPM is built.

typedef struct
{
#ifdef TPM_ALG_SHA1
    BYTE                sha1[NUM_STATIC_PCR][SHA1_DIGEST_SIZE];
#endif
#ifdef TPM_ALG_SHA256
    BYTE                sha256[NUM_STATIC_PCR][SHA256_DIGEST_SIZE];
#endif
#ifdef TPM_ALG_SHA384
    BYTE                sha384[NUM_STATIC_PCR][SHA384_DIGEST_SIZE];
#endif
#ifdef TPM_ALG_SHA512
    BYTE                sha512[NUM_STATIC_PCR][SHA512_DIGEST_SIZE];
#endif
#ifdef TPM_ALG_SM3_256
    BYTE                sm3_256[NUM_STATIC_PCR][SM3_256_DIGEST_SIZE];
#endif

    // This counter increments whenever the PCR are updated.
    // NOTE: A platform-specific specification may designate
    //       certain PCR changes as not causing this counter
    //       to increment.
    UINT32              pcrCounter;

} PCR_SAVE;

//***PCR_POLICY
// This structure holds the PCR policies, one for each group of PCR controlled
// by policy.
typedef struct
{
    TPMI_ALG_HASH       hashAlg[NUM_POLICY_PCR_GROUP];
    TPM2B_DIGEST        a;
    TPM2B_DIGEST        policy[NUM_POLICY_PCR_GROUP];
} PCR_POLICY;

//***PCR_AUTHVALUE
// This structure holds the PCR policies, one for each group of PCR controlled
// by policy.
typedef struct
{
    TPM2B_DIGEST        auth[NUM_AUTHVALUE_PCR_GROUP];
} PCR_AUTHVALUE;

//**Startup
//***SHUTDOWN_NONE
// Part 2 defines the two shutdown/startup types that may be used in
// TPM2_Shutdown() and TPM2_Starup(). This additional define is
// used by the TPM to indicate that no shutdown was received.
// NOTE: This is a reserved value.
#define SHUTDOWN_NONE   (TPM_SU)(0xFFFF)

//***STARTUP_TYPE
// This enumeration is the possible startup types. The type is determined
// by the combination of TPM2_ShutDown and TPM2_Startup.
typedef enum
{
    SU_RESET, 
    SU_RESTART, 
    SU_RESUME
} STARTUP_TYPE;

//**NV
//***NV_RESERVE
// This enumeration defines the master list of the elements of a reserved portion
// of NV. This list includes all the pre-defined data that takes space in NV,
// either as persistent data or as state save data. The enumerations are used
// as indexes into an array of offset values. The offset values then are used to
// index into NV. This is method provides an imperfect analog to an actual NV
// implementation.
//
typedef enum
{
// Entries below mirror the PERSISTENT_DATA structure. These values are written
// to NV as individual items.
    // hierarchy
    NV_DISABLE_CLEAR,
    NV_OWNER_ALG,
    NV_ENDORSEMENT_ALG,
    NV_OWNER_POLICY,
    NV_ENDORSEMENT_POLICY,
    NV_OWNER_AUTH,
    NV_ENDORSEMENT_AUTH,
    NV_LOCKOUT_AUTH,

    NV_EP_SEED,
    NV_SP_SEED,
    NV_PP_SEED,

    NV_PH_PROOF,
    NV_SH_PROOF,
    NV_EH_PROOF,

    // Time
    NV_TOTAL_RESET_COUNT,
    NV_RESET_COUNT,

    // PCR
    NV_PCR_POLICIES,
    NV_PCR_ALLOCATED,

    // Physical Presence
    NV_PP_LIST,

    // Dictionary Attack
    NV_FAILED_TRIES,
    NV_MAX_TRIES,
    NV_RECOVERY_TIME,
    NV_LOCKOUT_RECOVERY,
    NV_LOCKOUT_AUTH_ENABLED,

    // Orderly State flag
    NV_ORDERLY,

    // Command Audit
    NV_AUDIT_COMMANDS,
    NV_AUDIT_HASH_ALG,
    NV_AUDIT_COUNTER,

    // Algorithm Set
    NV_ALGORITHM_SET,

    NV_FIRMWARE_V1,
    NV_FIRMWARE_V2,

// The entries above are in PERSISTENT_DATA. The entries below represent
// structures that are read and written as a unit.

// ORDERLY_DATA data structure written on each orderly shutdown
    NV_CLOCK,

// STATE_CLEAR_DATA structure written on each Shutdown(STATE)
    NV_STATE_CLEAR,

// STATE_RESET_DATA structure written on each Shutdown(STATE)
    NV_STATE_RESET,

    NV_RESERVE_LAST             // end of NV reserved data list
} NV_RESERVE;

//***NV_INDEX
// The NV_INDEX structure defines the internal format for an NV index.
// The 'indexData' size varies according to the type of the index.
// In this implementation, all of the index is manipulated as a unit.
typedef struct
{
    TPMS_NV_PUBLIC      publicArea;
    TPM2B_AUTH          authValue;
} NV_INDEX;


//**COMMIT_INDEX_MASK
// This is the define for the mask value that is used when manipulating
// the bits in the commit bit array. The commit counter is a 64-bit
// value and the low order bits are used to index the commitArray.
// This mask value is applied to the commit counter to extract the
// bit number in the array.
#ifdef TPM_ALG_ECC

#define COMMIT_INDEX_MASK ((UINT16)((sizeof(gr.commitArray)*8)-1))

#endif

//*****************************************************************************
//*****************************************************************************
//** RAM Global Values
//*****************************************************************************
//*****************************************************************************
//*** Description
// The values in this section are only extant in RAM. They are defined here
// and instanced in Global.c.

//*** g_rcIndex[]
// This array is used to contain the array of values that are added to a return
// code when it is a parameter-, handle-, or session-related error.
// This is an implementation choice and the same result can be achieved by using
// a macro.
extern const UINT16     g_rcIndex[15]; 

//*** g_exclusiveAuditSession
// This location holds the session handle for the current exclusive audit
// session. If there is no exclusive audit session, the location is set to
// TPM_RH_UNASSIGNED.
extern TPM_HANDLE       g_exclusiveAuditSession;

//*** g_time
// This value is the count of milliseconds since the TPM was powered up. This value
// is initialized at _TPM_Init.
extern  UINT64          g_time;

//*** g_phEnable
// This is the platform hierarchy control and determines if the platform hierarchy
// is available. This value is SET on each TPM2_Startup(). The default value is
// SET.
extern BOOL             g_phEnable; 

//*** g_pceReConfig
// This value is SET if a TPM2_PCR_Allocate command successfully executed since
// the last TPM2_Startup(). If so, then the next shutdown is required to be
// Shutdown(CLEAR).
extern BOOL             g_pcrReConfig;

//*** g_DRTMHandle
// This location indicates the sequence object handle that holds the DRTM
// sequence data. When not used, it is set to TPM_RH_UNASSIGNED. A sequence
// DRTM sequence is started on either _TPM_Init or _TPM_Hash_Start.
extern TPMI_DH_OBJECT   g_DRTMHandle;

//*** g_DrtmPreStartup
// This value indicates that an H-CRTM occured after _TPM_Init but before
// TPM2_Startup()
extern  BOOL            g_DrtmPreStartup;

//*** g_updateNV
// This flag indicates if NV should be updated at the end of a command.
// This flag is set to FALSE at the beginning of each command in ExecuteCommand().
// This flag is checked in ExecuteCommand() after the detailed actions of a command
// complete. If the command execution was successful and this flag is SET, any
// pending NV writes will be committed to NV.
extern BOOL             g_updateNV;

//*** g_clearOrderly
// This flag indicates if the execution of a command should cause the orderly
// state to be cleared.  This flag is set to FALSE at the beginning of each
// command in ExecuteCommand() and is checked in ExecuteCommand() after the
// detailed actions of a command complete but before the check of
// 'g_updateNV'. If this flag is TRUE, and the orderly state is not
// SHUTDOWN_NONE, then the orderly state in NV memory will be changed to
// SHUTDOWN_NONE.
extern BOOL             g_clearOrderly;

//*** g_prevOrderlyState
// This location indicates how the TPM was shut down before the most recent
// TPM2_Startup(). This value, along with the startup type, determines if
// the TPM should do a TPM Reset, TPM Restart, or TPM Resume.
extern TPM_SU           g_prevOrderlyState;

//*********************************************************************************
//*********************************************************************************
//** Persistent Global Values
//*********************************************************************************
//*********************************************************************************
//*** Description
// The values in this section are global values that are persistent across power
// events. The lifetime of the values determines the structure in which the value
// is placed.

//*********************************************************************************
//*** PERSISTENT_DATA
//*********************************************************************************
// This structure holds the persistent values that only change as a consequence
// of a specific Protected Capability and are not affected by TPM power events
// (TPM2_Startup() or TPM2_Shutdown().
typedef struct
{
//*********************************************************************************
//          Hierarchy                                                      
//*********************************************************************************
// The values in this section are related to the hierarchies.
 
    BOOL                disableClear;       // TRUE if TPM2_Clear() using
                                            // lockoutAuth is disabled

    // Hierarchy authPolicies
    TPMI_ALG_HASH       ownerAlg;
    TPMI_ALG_HASH       endorsementAlg;
    TPM2B_DIGEST        ownerPolicy;
    TPM2B_DIGEST        endorsementPolicy;

    // Hierarchy authValues
    TPM2B_AUTH          ownerAuth;
    TPM2B_AUTH          endorsementAuth;
    TPM2B_AUTH          lockoutAuth;

    // Primary Seeds
    TPM2B_SEED          EPSeed;
    TPM2B_SEED          SPSeed;
    TPM2B_SEED          PPSeed;
    // Note there is a nullSeed in the state_reset memory.

    // Hierarchy proofs
    TPM2B_AUTH          phProof;
    TPM2B_AUTH          shProof;
    TPM2B_AUTH          ehProof;
    // Note there is a nullProof in the state_reset memory.

//*********************************************************************************
//          Reset Events
//*********************************************************************************
// A count that increments at each TPM reset and never get reset during the life
// time of TPM.  The value of this counter is initialized to 1 during TPM
// manufacture process.
    UINT64              totalResetCount;

// This counter increments on each TPM Reset. The counter is reset by
// TPM2_Clear().
    UINT32              resetCount;


//*********************************************************************************
//          PCR
//*********************************************************************************
// This structure hold the policies for those PCR that have an update policy.
// This implementation only supports a single group of PCR controlled by
// policy. If more are required, then this structure would be changed to
// an array.
    PCR_POLICY          pcrPolicies;

// This structure indicates the allocation of PCR. The structure contains a
// list of PCR allocations for each implemented algorithm. If no PCR are
// allocated for an algorithm, a list entry still exists but the bit map
// will contain no SET bits.
    TPML_PCR_SELECTION  pcrAllocated;

//*********************************************************************************
//          Physical Presence
//*********************************************************************************
// The PP_LIST type contains a bit map of the commands that require physical
// to be asserted when the authorization is evaluated. Physical presence will be
// checked if the corresponding bit in the array is SET and if the authorization
// handle is TPM_RH_PLATFORM.
//
// These bits may be changed with TPM2_PP_Commands().
    BYTE                ppList[((TPM_CC_PP_LAST - TPM_CC_PP_FIRST + 1) + 7)/8];

//*********************************************************************************
//          Dictionary attack values
//*********************************************************************************
// These values are used for dictionary attack tracking and control.
    UINT32              failedTries;        // the current count of unexpired
                                            // authorization failures

    UINT32              maxTries;           // number of unexpired authorization
                                            // failures before the TPM is in
                                            // lockout

    UINT32              recoveryTime;       // time between authorization failures
                                            // before failedTries is decremented

    UINT32              lockoutRecovery;    // time that must expire between
                                            // authorization failures associated
                                            // with lockoutAuth

    BOOL                lockOutAuthEnabled; // TRUE if use of lockoutAuth is
                                            // allowed

//*****************************************************************************
//            Orderly State
//*****************************************************************************
// The orderly state for current cycle
    TPM_SU              orderlyState;

//*****************************************************************************
//           Command audit values.
//*****************************************************************************
    BYTE                auditComands[((TPM_CC_LAST - TPM_CC_FIRST + 1) + 7) / 8];
    TPMI_ALG_HASH       auditHashAlg;
    UINT64              auditCounter;

//*****************************************************************************
//           Algorithm selection
//*****************************************************************************
//
// The 'algorithmSet' value indicates the collection of algorithms that are
// currently in used on the TPM.  The interpretation of value is vendor dependent.
    UINT32              algorithmSet;

//*****************************************************************************
//           Firmware version
//*****************************************************************************
// The firmwareV1 and firmwareV2 values are instanced in TimeStamp.c. This is
// a scheme used in development to allow determination of the linker build time
// of the TPM. An actual implementation would implement these values in a way that
// is consistent with vendor needs. The values are maintained in RAM for simplified
// access with a master version in NV.  These values are modified in a
// vendor-specific way.

// g_firmwareV1 contains the more significant 32-bits of the vendor version number.
// In the reference implementation, if this value is printed as a hex
// value, it will have the format of yyyymmdd
    UINT32              firmwareV1;

// g_firmwareV1 contains the less significant 32-bits of the vendor version number.
// In the reference implementation, if this value is printed as a hex
// value, it will have the format of 00 hh mm ss
    UINT32              firmwareV2;

} PERSISTENT_DATA;

extern PERSISTENT_DATA  gp;

//*********************************************************************************
//*********************************************************************************
//*** ORDERLY_DATA
//*********************************************************************************
//*********************************************************************************
// The data in this structure is saved to NV on each TPM2_Shutdown().
typedef struct orderly_data
{

//*****************************************************************************
//           TIME
//*****************************************************************************

// Clock has two parts. One is the state save part and one is the NV part. The
// state save version is updated on each command. When the clock rolls over, the
// NV version is updated. When the TPM starts up, if the TPM was shutdown in and
// orderly way, then the sClock value is used to initialize the clock. If the
// TPM shutdown was not orderly, then the persistent value is used and the safe
// attribute is clear.

    UINT64              clock;              // The orderly version of clock
    TPMI_YES_NO         clockSafe;          // Indicates if the clock value is 
                                            // safe.
} ORDERLY_DATA;

extern ORDERLY_DATA     go;

//*********************************************************************************
//*********************************************************************************
//*** STATE_CLEAR_DATA
//*********************************************************************************
//*********************************************************************************
// This structure contains the data that is saved on Shutdown(STATE).
// and restored on Startup(STATE).  The values are set to their default
// settings on any Startup(Clear). In other words the data is only persistent
// across TPM Resume.
//
// If the comments associated with a parameter indicate a default reset value, the
// value is applied on each Startup(CLEAR).

typedef struct state_clear_data
{
//*****************************************************************************
//           Hierarchy Control
//*****************************************************************************
    BOOL                shEnable;           // default reset is SET
    BOOL                ehEnable;           // default reset is SET
    TPMI_ALG_HASH       platformAlg;        // default reset is TPM_ALG_NULL
    TPM2B_DIGEST        platformPolicy;     // default reset is an Empty Buffer
    TPM2B_AUTH          platformAuth;       // default reset is an Empty Buffer

//*****************************************************************************
//           PCR
//*****************************************************************************
// The set of PCR to be saved on Shutdown(STATE)
    PCR_SAVE            pcrSave;            // default reset is 0...0

// This structure hold the authorization values for those PCR that have an
// update authorization.
// This implementation only supports a single group of PCR controlled by
// authorization. If more are required, then this structure would be changed to
// an array.
    PCR_AUTHVALUE       pcrAuthValues;

} STATE_CLEAR_DATA;

extern STATE_CLEAR_DATA gc;

//*********************************************************************************
//*********************************************************************************
//***  State Reset Data
//*********************************************************************************
//*********************************************************************************
// This structure contains data is that is saved on Shutdown(STATE) and restored on
// the subsequent Startup(ANY). That is, the data is preserved across TPM Resume
// and TPM Restart.
//
// If a default value is specified in the comments this value is applied on
// TPM Reset.

typedef struct state_reset_data
{
//*****************************************************************************
//          Hierarchy Control
//*****************************************************************************
    TPM2B_AUTH          nullProof;          // The proof value associated with 
                                            // the TPM_RH_NULL hierarchy. The 
                                            // default reset value is from the RNG.

    TPM2B_SEED          nullSeed;           // The seed value for the TPM_RN_NULL
                                            // hierarchy. The default reset value
                                            // is from the RNG.

//*****************************************************************************
//           Context
//*****************************************************************************
// The 'clearCount' counter is incremented each time the TPM successfully executes
// a TPM Resume. The counter is included in each saved context that has 'stClear'
// SET (including descendants of keys that have 'stClear' SET). This prevents these
// objects from being loaded after a TPM Resume.
// If 'clearCount' at its maximum value when the TPM receives a Shutdown(STATE),
// the TPM will return TPM_RC_RANGE and the TPM will only accept Shutdown(CLEAR).
    UINT32              clearCount;         // The default reset value is 0.

    UINT64              objectContextID;    // This is the context ID for a saved 
                                            //  object context. The default reset 
                                            //  value is 0.

    CONTEXT_SLOT        contextArray[MAX_ACTIVE_SESSIONS];
                                            // This is the value from which the 
                                            // 'contextID' is derived. The 
                                            // default reset value is {0}.


    CONTEXT_COUNTER     contextCounter;     // This array contains contains the 
                                            // values used to track the version 
                                            // numbers of saved contexts (see 
                                            // Session.c in for details). The 
                                            // default reset value is 0.

//*****************************************************************************
//           Command Audit
//*****************************************************************************
// When an audited command completes, ExecuteCommand() checks the return
// value.  If it is TPM_RC_SUCCESS, and the command is an audited command, the
// TPM will extend the cpHash and rpHash for the command to this value. If this
// digest was the Zero Digest before the cpHash was extended, the audit counter
// is incremented.

    TPM2B_DIGEST        commandAuditDigest; // This value is set to an Empty Digest
                                            // by TPM2_GetCommandAuditDigest() or a
                                            // TPM Reset.

//*****************************************************************************
//           Boot counter
//*****************************************************************************

    UINT32              restartCount;       // This counter counts TPM Restarts. 
                                            // The default reset value is 0.

//*********************************************************************************
//            PCR
//*********************************************************************************
// This counter increments whenever the PCR are updated. This counter is preserved
// across TPM Resume even though the PCR are not preserved. This is because
// sessions remain active across TPM Restart and the count value in the session
// is compared to this counter so this counter must have values that are unique
// as long as the sessions are active.
// NOTE: A platform-specific specification may designate that certain PCR changes
//       do not increment this counter to increment.
    UINT32              pcrCounter;         // The default reset value is 0.

#ifdef TPM_ALG_ECC

//*****************************************************************************
//         ECDAA
//*****************************************************************************
    UINT64              commitCounter;      // This counter increments each time 
                                            // TPM2_Commit() returns 
                                            // TPM_RC_SUCCESS. The default reset 
                                            // value is 0.


    TPM2B_NONCE         commitNonce;        // This random value is used to compute
                                            // the commit values. The default reset
                                            // value is from the RNG.

// This implementation relies on the number of bits in g_commitArray being a
// power of 2 (8, 16, 32, 64, etc.) and no greater than 64K.
    BYTE                 commitArray[16];   // The default reset value is {0}.

#endif //TPM_ALG_ECC

} STATE_RESET_DATA;

extern STATE_RESET_DATA gr;


//**Global Macro Definitions
// This macro is used to ensure that a handle, session, or parameter number is only
// added if the response code is FMT1.
#define RcSafeAddToResult(r, v) \
    ((r) + (((r) & RC_FMT1) ? (v) : 0))

// This macro is used when a parameter is not otherwise referenced in a function.
// This macro is normally not used by itself but is paired with a pAssert() within
// a #ifdef pAssert. If pAssert is not defined, then a paramter might not otherwise
// be referenced. This macro "uses" the parameter from the perspective of the
// compiler so it doesn't complain.

#define UNREFERENCED(a) ((void)(a))


//** Private data

#if defined SESSION_PROCESS_C || defined GLOBAL_C
//*****************************************************************************
// From SessionProcess.c
//*****************************************************************************
// The following arrays are used to save command sessions information so that the
// command handle/session buffer does not have to be preserved for the duration of
// the command. These arrays are indexed by the session index in accordance with
// the order of sessions in the session area of the command.
//
// Array of the authorization session handles
extern TPM_HANDLE       s_sessionHandles[MAX_SESSION_NUM];

// Array of authorization session attributes
extern TPMA_SESSION     s_attributes[MAX_SESSION_NUM];

// Array of handles authorized by the corresponding authorization sessions; 
// and if none, then TPM_RH_UNASSIGNED value is used
extern TPM_HANDLE       s_associatedHandles[MAX_SESSION_NUM];

// Array of nonces provided by the caller for the corresponding sessions
TPM2B_NONCE      s_nonceCaller[MAX_SESSION_NUM];

// Array of authorization values (HMAC's or passwords) for the corresponding 
// sessions
extern TPM2B_AUTH       s_inputAuthValues[MAX_SESSION_NUM];

// Special value to indicate an undefined session index
#define             UNDEFINED_INDEX     (0xFFFF)

// Index of the session used for encryption of a response parameter
extern UINT32           s_encryptSessionIndex;

// Index of the session used for decryption of a command parameter
extern UINT32           s_decryptSessionIndex;

// Index of a session used for audit
extern UINT32           s_auditSessionIndex;

// The cpHash for an audit session
extern TPM2B_DIGEST     s_cpHashForAudit;

// The cpHash for command audit
#ifdef  TPM_CC_GetCommandAuditDigest
extern TPM2B_DIGEST    s_cpHashForCommandAudit;
#endif

// Number of authorization sessions present in the command
extern UINT32           s_sessionNum;

// Flag indicating if NV update is pending for the lockOutAuthEnabled or 
// failedTries DA parameter
extern BOOL             s_DAPendingOnNV;

#endif // SESSION_PROCESS_C

#if defined DA_C || defined GLOBAL_C
//*****************************************************************************
// From DA.c
//*****************************************************************************
// This variable holds the accumulated time since the last time
// that 'failedTries' was decremented. This value is in millisecond.
extern UINT64       s_selfHealTimer;

// This variable holds the accumulated time that the lockoutAuth has been
// blocked.
UINT64       s_lockoutTimer;

#endif // DA_C


#if defined NV_C || defined GLOBAL_C
//*****************************************************************************
// From NV.c
//*****************************************************************************
// List of pre-defined address of reserved data
extern UINT32       s_reservedAddr[NV_RESERVE_LAST];

// List of pre-defined reserved data size in byte
extern UINT32       s_reservedSize[NV_RESERVE_LAST];

// Size of data in RAM index buffer
extern UINT32       s_ramIndexSize;

// Reserved RAM space for frequently updated NV Index.
// The data layout in ram buffer is {NV_handle, size of data, data} for each NV
// index data stored in RAM
extern BYTE      s_ramIndex[RAM_INDEX_SPACE];

// Address of size of RAM index space in NV
extern UINT32   s_ramIndexSizeAddr;

// Address of NV copy of RAM index space
extern UINT32   s_ramIndexAddr;

// Address of maximum counter value; an auxiliary variable to implement
// NV counters
extern UINT32   s_maxCountAddr;

// Beginning of NV dynamic area; starts right after the
// s_maxCountAddr and s_evictHandleMapAddr variables
extern UINT32   s_evictNvStart;

// Beginning of NV dynamic area; also the beginning of the predefined
// reserved data area.
extern UINT32   s_evictNvEnd;

// NV availability is sampled as the start of each command and stored here
// so that its value remains consistent during the command execution
extern TPM_RC   s_NvIsAvailable;

#endif


#if defined OBJECT_C || defined GLOBAL_C
//*****************************************************************************
// From Object.c
//*****************************************************************************
// This type is the container for an object.
typedef struct
{
    BOOL        occupied;
    ANY_OBJECT      object;
} OBJECT_SLOT;

// This is the memory that holds the loaded objects.
extern OBJECT_SLOT     s_objects[MAX_LOADED_OBJECTS];

#endif // OBJECT_C


#if defined PCR_C || defined GLOBAL_C
//*****************************************************************************
// From PCR.c
//*****************************************************************************
typedef struct
{
#ifdef TPM_ALG_SHA1
    // SHA1 PCR
    BYTE    sha1Pcr[SHA1_DIGEST_SIZE];
#endif
#ifdef TPM_ALG_SHA256
    // SHA256 PCR
    BYTE    sha256Pcr[SHA256_DIGEST_SIZE];
#endif
#ifdef TPM_ALG_SHA384
    // SHA384 PCR
    BYTE    sha384Pcr[SHA384_DIGEST_SIZE];
#endif
#ifdef TPM_ALG_SHA512
    // SHA512 PCR
    BYTE    sha512Pcr[SHA512_DIGEST_SIZE];
#endif
#ifdef TPM_ALG_SM3_256
    // SHA256 PCR
    BYTE    sm3_256Pcr[SM3_256_DIGEST_SIZE];
#endif
} PCR;

typedef struct
{
    unsigned int    stateSave : 1;              // if the PCR value should be
                                                // saved in state save
    unsigned int    resetLocality : 5;          // The locality that the PCR
                                                // can be reset
    unsigned int    extendLocality : 5;         // The locality that the PCR
                                                // can be extend
} PCR_Attributes;

extern PCR          s_pcrs[IMPLEMENTATION_PCR];

#endif // PCR_C


#if defined SESSION_C || defined GLOBAL_C
//*****************************************************************************
// From Session.c
//*****************************************************************************
// Container for HMAC or policy session tracking information
typedef struct
{
    BOOL                occupied;
    SESSION             session;        // session structure
} SESSION_SLOT;

extern SESSION_SLOT     s_sessions[MAX_LOADED_SESSIONS];

/*
    The index in conextArray that has the value of the oldest saved session 
    context. When no context is saved, this will have a value that is greater 
    than or equal to MAX_ACTIVE_SESSIONS.
*/
extern UINT32            s_oldestSavedSession;

// The number of available session slot openings.  When this is 1,
// a session can't be created or loaded if the GAP is maxed out.
// The exception is that the oldest saved session context can always
// be loaded (assuming that there is a space in memory to put it)
extern int               s_freeSessionSlots;

#endif // SESSION_C

#if defined MANUFACTURE_C || defined GLOBAL_C
//*****************************************************************************
// From Manufacture.c
//*****************************************************************************
extern BOOL              s_manufactured;

#endif // MANUFACTURE_C


#if defined POWER_C || defined GLOBAL_C
//*****************************************************************************
// From Power.c
//*****************************************************************************
// This value indicates if a TPM2_Startup commands has been
// receive since the power on event.  This flag is maintained in power
// simulation module because this is the only place that may reliably set this
// flag to FALSE.
extern BOOL              s_initialized;

#endif // POWER_C

#if defined MEMORY_LIB_C || defined GLOBAL_C
// The s_actionOutputBuffer should not be modifiable by the host system until
// the TPM has returned a response code. The s_actionOutputBuffer should not
// be accessible until response parameter encryption, if any, is complete.
extern UINT32   s_actionInputBuffer[1024];          // action input buffer
extern UINT32   s_actionOutputBuffer[1024];         // action output buffer
extern BYTE     s_responseBuffer[MAX_RESPONSE_SIZE];// response buffer
#endif // MEMORY_LIB_C

#endif // GLOBAL_H

#ifndef      _MARSHAL_H_
#define      _MARSHAL_H_

// Table 3 -- BaseTypes BaseTypes <I/O>
UINT16 
UINT8_Marshal(UINT8 *source, BYTE **buffer, INT32 *size);

TPM_RC  
UINT8_Unmarshal(UINT8 *target, BYTE **buffer, INT32 *size);

UINT16 
BYTE_Marshal(BYTE *source, BYTE **buffer, INT32 *size);

TPM_RC  
BYTE_Unmarshal(BYTE *target, BYTE **buffer, INT32 *size);

UINT16 
INT8_Marshal(INT8 *source, BYTE **buffer, INT32 *size);

TPM_RC  
INT8_Unmarshal(INT8 *target, BYTE **buffer, INT32 *size);

UINT16 
BOOL_Marshal(BOOL *source, BYTE **buffer, INT32 *size);

TPM_RC  
BOOL_Unmarshal(BOOL *target, BYTE **buffer, INT32 *size);

UINT16 
UINT16_Marshal(UINT16 *source, BYTE **buffer, INT32 *size);

TPM_RC  
UINT16_Unmarshal(UINT16 *target, BYTE **buffer, INT32 *size);

UINT16 
INT16_Marshal(INT16 *source, BYTE **buffer, INT32 *size);

TPM_RC  
INT16_Unmarshal(INT16 *target, BYTE **buffer, INT32 *size);

UINT16 
UINT32_Marshal(UINT32 *source, BYTE **buffer, INT32 *size);

TPM_RC  
UINT32_Unmarshal(UINT32 *target, BYTE **buffer, INT32 *size);

UINT16 
INT32_Marshal(INT32 *source, BYTE **buffer, INT32 *size);

TPM_RC  
INT32_Unmarshal(INT32 *target, BYTE **buffer, INT32 *size);

UINT16 
UINT64_Marshal(UINT64 *source, BYTE **buffer, INT32 *size);

TPM_RC  
UINT64_Unmarshal(UINT64 *target, BYTE **buffer, INT32 *size);

UINT16 
INT64_Marshal(INT64 *source, BYTE **buffer, INT32 *size);

TPM_RC  
INT64_Unmarshal(INT64 *target, BYTE **buffer, INT32 *size);



// Table 4 -- DocumentationClarity Types <I/O>
UINT16
TPM_ALGORITHM_ID_Marshal(TPM_ALGORITHM_ID *source, BYTE **buffer, INT32 *size);
TPM_RC
TPM_ALGORITHM_ID_Unmarshal(TPM_ALGORITHM_ID *target, BYTE **buffer, INT32 *size);
UINT16
TPM_MODIFIER_INDICATOR_Marshal(TPM_MODIFIER_INDICATOR *source, BYTE **buffer, INT32 *size);
TPM_RC
TPM_MODIFIER_INDICATOR_Unmarshal(TPM_MODIFIER_INDICATOR *target, BYTE **buffer, INT32 *size);
UINT16
TPM_AUTHORIZATION_SIZE_Marshal(TPM_AUTHORIZATION_SIZE *source, BYTE **buffer, INT32 *size);
TPM_RC
TPM_AUTHORIZATION_SIZE_Unmarshal(TPM_AUTHORIZATION_SIZE *target, BYTE **buffer, INT32 *size);
UINT16
TPM_PARAMETER_SIZE_Marshal(TPM_PARAMETER_SIZE *source, BYTE **buffer, INT32 *size);
TPM_RC
TPM_PARAMETER_SIZE_Unmarshal(TPM_PARAMETER_SIZE *target, BYTE **buffer, INT32 *size);
UINT16
TPM_KEY_SIZE_Marshal(TPM_KEY_SIZE *source, BYTE **buffer, INT32 *size);
TPM_RC
TPM_KEY_SIZE_Unmarshal(TPM_KEY_SIZE *target, BYTE **buffer, INT32 *size);
UINT16
TPM_KEY_BITS_Marshal(TPM_KEY_BITS *source, BYTE **buffer, INT32 *size);
TPM_RC
TPM_KEY_BITS_Unmarshal(TPM_KEY_BITS *target, BYTE **buffer, INT32 *size);




// Table 6 -- TPM_GENERATED Constants <O,S>
UINT16
TPM_GENERATED_Marshal(TPM_GENERATED *source, BYTE **buffer, INT32 *size);


// Table 7 -- TPM_ALG_ID Constants <I/O,S>
UINT16
TPM_ALG_ID_Marshal(TPM_ALG_ID *source, BYTE **buffer, INT32 *size);
TPM_RC
TPM_ALG_ID_Unmarshal(TPM_ALG_ID *target, BYTE **buffer, INT32 *size);


// Table 8 -- TPM_ECC_CURVE Constants <I/O,S>
UINT16
TPM_ECC_CURVE_Marshal(TPM_ECC_CURVE *source, BYTE **buffer, INT32 *size);
TPM_RC
TPM_ECC_CURVE_Unmarshal(TPM_ECC_CURVE *target, BYTE **buffer, INT32 *size);


// Table 11 -- TPM_CC Constants <I/O,S>
UINT16
TPM_CC_Marshal(TPM_CC *source, BYTE **buffer, INT32 *size);
TPM_RC
TPM_CC_Unmarshal(TPM_CC *target, BYTE **buffer, INT32 *size);


// Table 15 -- TPM_RC Constants <O,S>
UINT16
TPM_RC_Marshal(TPM_RC *source, BYTE **buffer, INT32 *size);
TPM_RC
TPM_RC_Unmarshal(TPM_RC *target, BYTE **buffer, INT32 *size);

// Table 16 -- TPM_CLOCK_ADJUST Constants <I>
TPM_RC
TPM_CLOCK_ADJUST_Unmarshal(TPM_CLOCK_ADJUST *target, BYTE **buffer, INT32 *size);
UINT16
TPM_CLOCK_ADJUST_Marshal(TPM_CLOCK_ADJUST *source, BYTE **buffer, INT32 *size);

// Table 17 -- TPM_EO Constants <I/O>
UINT16
TPM_EO_Marshal(TPM_EO *source, BYTE **buffer, INT32 *size);
TPM_RC
TPM_EO_Unmarshal(TPM_EO *target, BYTE **buffer, INT32 *size);


// Table 18 -- TPM_ST Constants <I/O,S>
UINT16
TPM_ST_Marshal(TPM_ST *source, BYTE **buffer, INT32 *size);
TPM_RC
TPM_ST_Unmarshal(TPM_ST *target, BYTE **buffer, INT32 *size);


// Table 19 -- TPM_SU Constants <I>
TPM_RC
TPM_SU_Unmarshal(TPM_SU *target, BYTE **buffer, INT32 *size);
UINT16
TPM_SU_Marshal(TPM_SU *source, BYTE **buffer, INT32 *size);

// Table 20 -- TPM_SE Constants <I>
TPM_RC
TPM_SE_Unmarshal(TPM_SE *target, BYTE **buffer, INT32 *size);
UINT16
TPM_SE_Marshal(TPM_SE *source, BYTE **buffer, INT32 *size);

// Table 21 -- TPM_CAP Constants <I/O>
UINT16
TPM_CAP_Marshal(TPM_CAP *source, BYTE **buffer, INT32 *size);
TPM_RC
TPM_CAP_Unmarshal(TPM_CAP *target, BYTE **buffer, INT32 *size);


// Table 22 -- TPM_PT Constants <I/O,S>
UINT16
TPM_PT_Marshal(TPM_PT *source, BYTE **buffer, INT32 *size);
TPM_RC
TPM_PT_Unmarshal(TPM_PT *target, BYTE **buffer, INT32 *size);


// Table 23 -- TPM_PT_PCR Constants <I/O,S>
UINT16
TPM_PT_PCR_Marshal(TPM_PT_PCR *source, BYTE **buffer, INT32 *size);
TPM_RC
TPM_PT_PCR_Unmarshal(TPM_PT_PCR *target, BYTE **buffer, INT32 *size);


// Table 24 -- TPM_PS Constants <O,S>
UINT16
TPM_PS_Marshal(TPM_PS *source, BYTE **buffer, INT32 *size);


// Table 25 -- Handles Types <I/O>
UINT16
TPM_HANDLE_Marshal(TPM_HANDLE *source, BYTE **buffer, INT32 *size);
TPM_RC
TPM_HANDLE_Unmarshal(TPM_HANDLE *target, BYTE **buffer, INT32 *size);




// Table 27 -- TPM_RH Constants <I,S>
TPM_RC
TPM_RH_Unmarshal(TPM_RH *target, BYTE **buffer, INT32 *size);


// Table 28 -- TPM_HC Constants <I,S>
TPM_RC
TPM_HC_Unmarshal(TPM_HC *target, BYTE **buffer, INT32 *size);


// Table 29 -- TPMA_ALGORITHM Bits <I/O>
UINT16
TPMA_ALGORITHM_Marshal(TPMA_ALGORITHM *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMA_ALGORITHM_Unmarshal(TPMA_ALGORITHM *target, BYTE **buffer, INT32 *size);


// Table 30 -- TPMA_OBJECT Bits <I/O>
UINT16
TPMA_OBJECT_Marshal(TPMA_OBJECT *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMA_OBJECT_Unmarshal(TPMA_OBJECT *target, BYTE **buffer, INT32 *size);


// Table 31 -- TPMA_SESSION Bits <I/O>
UINT16
TPMA_SESSION_Marshal(TPMA_SESSION *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMA_SESSION_Unmarshal(TPMA_SESSION *target, BYTE **buffer, INT32 *size);


// Table 32 -- TPMA_LOCALITY Bits <I/O>
UINT16
TPMA_LOCALITY_Marshal(TPMA_LOCALITY *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMA_LOCALITY_Unmarshal(TPMA_LOCALITY *target, BYTE **buffer, INT32 *size);


// Table 33 -- TPMA_PERMANENT Bits <O,S>
UINT16
TPMA_PERMANENT_Marshal(TPMA_PERMANENT *source, BYTE **buffer, INT32 *size);


// Table 34 -- TPMA_STARTUP_CLEAR Bits <O,S>
UINT16
TPMA_STARTUP_CLEAR_Marshal(TPMA_STARTUP_CLEAR *source, BYTE **buffer, INT32 *size);


// Table 35 -- TPMA_MEMORY Bits <O,S>
UINT16
TPMA_MEMORY_Marshal(TPMA_MEMORY *source, BYTE **buffer, INT32 *size);


// Table 36 -- TPMA_CC Bits <O,S>
UINT16
TPMA_CC_Marshal(TPMA_CC *source, BYTE **buffer, INT32 *size);


// Table 37 -- TPMI_YES_NO Type <I/O>
UINT16
TPMI_YES_NO_Marshal(TPMI_YES_NO *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMI_YES_NO_Unmarshal(TPMI_YES_NO *target, BYTE **buffer, INT32 *size);


// Table 38 -- TPMI_DH_OBJECT Type <I/O>
UINT16
TPMI_DH_OBJECT_Marshal(TPMI_DH_OBJECT *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMI_DH_OBJECT_Unmarshal(TPMI_DH_OBJECT *target, BYTE **buffer, INT32 *size, BOOL flag);


// Table 39 -- TPMI_DH_PERSISTENT Type <I/O>
UINT16
TPMI_DH_PERSISTENT_Marshal(TPMI_DH_PERSISTENT *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMI_DH_PERSISTENT_Unmarshal(TPMI_DH_PERSISTENT *target, BYTE **buffer, INT32 *size);


// Table 40 -- TPMI_DH_ENTITY Type <I>
TPM_RC
TPMI_DH_ENTITY_Unmarshal(TPMI_DH_ENTITY *target, BYTE **buffer, INT32 *size, BOOL flag);


// Table 41 -- TPMI_DH_PCR Type <I>
TPM_RC
TPMI_DH_PCR_Unmarshal(TPMI_DH_PCR *target, BYTE **buffer, INT32 *size, BOOL flag);
UINT16
TPMI_DH_PCR_Marshal(TPMI_DH_PCR *source, BYTE **buffer, INT32 *size);

// Table 42 -- TPMI_SH_AUTH_SESSION Type <I/O>
UINT16
TPMI_SH_AUTH_SESSION_Marshal(TPMI_SH_AUTH_SESSION *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMI_SH_AUTH_SESSION_Unmarshal(TPMI_SH_AUTH_SESSION *target, BYTE **buffer, INT32 *size, BOOL flag);


// Table 43 -- TPMI_SH_HMAC Type <I/O>
UINT16
TPMI_SH_HMAC_Marshal(TPMI_SH_HMAC *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMI_SH_HMAC_Unmarshal(TPMI_SH_HMAC *target, BYTE **buffer, INT32 *size);


// Table 44 -- TPMI_SH_POLICY Type <I/O>
UINT16
TPMI_SH_POLICY_Marshal(TPMI_SH_POLICY *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMI_SH_POLICY_Unmarshal(TPMI_SH_POLICY *target, BYTE **buffer, INT32 *size);


// Table 45 -- TPMI_DH_CONTEXT Type <I/O>
UINT16
TPMI_DH_CONTEXT_Marshal(TPMI_DH_CONTEXT *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMI_DH_CONTEXT_Unmarshal(TPMI_DH_CONTEXT *target, BYTE **buffer, INT32 *size);


// Table 46 -- TPMI_RH_HIERARCHY Type <I/O>
UINT16
TPMI_RH_HIERARCHY_Marshal(TPMI_RH_HIERARCHY *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMI_RH_HIERARCHY_Unmarshal(TPMI_RH_HIERARCHY *target, BYTE **buffer, INT32 *size, BOOL flag);


// Table 47 -- TPMI_RH_HIERARCHY_AUTH Type <I>
TPM_RC
TPMI_RH_HIERARCHY_AUTH_Unmarshal(TPMI_RH_HIERARCHY_AUTH *target, BYTE **buffer, INT32 *size);


// Table 48 -- TPMI_RH_PLATFORM Type <I>
TPM_RC
TPMI_RH_PLATFORM_Unmarshal(TPMI_RH_PLATFORM *target, BYTE **buffer, INT32 *size);


// Table 49 -- TPMI_RH_OWNER Type <I>
TPM_RC
TPMI_RH_OWNER_Unmarshal(TPMI_RH_OWNER *target, BYTE **buffer, INT32 *size, BOOL flag);


// Table 50 -- TPMI_RH_ENDORSEMENT Type <I>
TPM_RC
TPMI_RH_ENDORSEMENT_Unmarshal(TPMI_RH_ENDORSEMENT *target, BYTE **buffer, INT32 *size, BOOL flag);


// Table 51 -- TPMI_RH_PROVISION Type <I>
TPM_RC
TPMI_RH_PROVISION_Unmarshal(TPMI_RH_PROVISION *target, BYTE **buffer, INT32 *size);


// Table 52 -- TPMI_RH_CLEAR Type <I>
TPM_RC
TPMI_RH_CLEAR_Unmarshal(TPMI_RH_CLEAR *target, BYTE **buffer, INT32 *size);


// Table 53 -- TPMI_RH_NV_AUTH Type <I>
TPM_RC
TPMI_RH_NV_AUTH_Unmarshal(TPMI_RH_NV_AUTH *target, BYTE **buffer, INT32 *size);


// Table 54 -- TPMI_RH_LOCKOUT Type <I>
TPM_RC
TPMI_RH_LOCKOUT_Unmarshal(TPMI_RH_LOCKOUT *target, BYTE **buffer, INT32 *size);


// Table 55 -- TPMI_RH_NV_INDEX Type <I/O>
UINT16
TPMI_RH_NV_INDEX_Marshal(TPMI_RH_NV_INDEX *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMI_RH_NV_INDEX_Unmarshal(TPMI_RH_NV_INDEX *target, BYTE **buffer, INT32 *size);


// Table 56 -- TPMI_ALG_HASH Type <I/O>
UINT16
TPMI_ALG_HASH_Marshal(TPMI_ALG_HASH *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMI_ALG_HASH_Unmarshal(TPMI_ALG_HASH *target, BYTE **buffer, INT32 *size, BOOL flag);


// Table 57 -- TPMI_ALG_ASYM Type <I/O>
UINT16
TPMI_ALG_ASYM_Marshal(TPMI_ALG_ASYM *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMI_ALG_ASYM_Unmarshal(TPMI_ALG_ASYM *target, BYTE **buffer, INT32 *size, BOOL flag);


// Table 58 -- TPMI_ALG_SYM Type <I/O>
UINT16
TPMI_ALG_SYM_Marshal(TPMI_ALG_SYM *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMI_ALG_SYM_Unmarshal(TPMI_ALG_SYM *target, BYTE **buffer, INT32 *size, BOOL flag);


// Table 59 -- TPMI_ALG_SYM_OBJECT Type <I/O>
UINT16
TPMI_ALG_SYM_OBJECT_Marshal(TPMI_ALG_SYM_OBJECT *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMI_ALG_SYM_OBJECT_Unmarshal(TPMI_ALG_SYM_OBJECT *target, BYTE **buffer, INT32 *size, BOOL flag);


// Table 60 -- TPMI_ALG_SYM_MODE Type <I/O>
UINT16
TPMI_ALG_SYM_MODE_Marshal(TPMI_ALG_SYM_MODE *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMI_ALG_SYM_MODE_Unmarshal(TPMI_ALG_SYM_MODE *target, BYTE **buffer, INT32 *size, BOOL flag);


// Table 61 -- TPMI_ALG_KDF Type <I/O>
UINT16
TPMI_ALG_KDF_Marshal(TPMI_ALG_KDF *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMI_ALG_KDF_Unmarshal(TPMI_ALG_KDF *target, BYTE **buffer, INT32 *size, BOOL flag);


// Table 62 -- TPMI_ALG_SIG_SCHEME Type <I/O>
UINT16
TPMI_ALG_SIG_SCHEME_Marshal(TPMI_ALG_SIG_SCHEME *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMI_ALG_SIG_SCHEME_Unmarshal(TPMI_ALG_SIG_SCHEME *target, BYTE **buffer, INT32 *size, BOOL flag);


// Table 63 -- TPMI_ECC_KEY_EXCHANGE Type <I/O>
UINT16
TPMI_ECC_KEY_EXCHANGE_Marshal(TPMI_ECC_KEY_EXCHANGE *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMI_ECC_KEY_EXCHANGE_Unmarshal(TPMI_ECC_KEY_EXCHANGE *target, BYTE **buffer, INT32 *size, BOOL flag);


// Table 64 -- TPMI_ST_COMMAND_TAG Type <I/O>
UINT16
TPMI_ST_COMMAND_TAG_Marshal(TPMI_ST_COMMAND_TAG *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMI_ST_COMMAND_TAG_Unmarshal(TPMI_ST_COMMAND_TAG *target, BYTE **buffer, INT32 *size);


// Table 65 -- TPMS_ALGORITHM_DESCRIPTION Structure <O,S>
UINT16
TPMS_ALGORITHM_DESCRIPTION_Marshal(TPMS_ALGORITHM_DESCRIPTION *source, BYTE **buffer, INT32 *size);


// Table 66 -- TPMU_HA Union <I/O,S>
UINT16
TPMU_HA_Marshal(TPMU_HA *source, BYTE **buffer, INT32 *size, UINT32 selector);
TPM_RC
TPMU_HA_Unmarshal(TPMU_HA *target, BYTE **buffer, INT32 *size, UINT32 selector);


// Table 67 -- TPMT_HA Structure <I/O>
UINT16
TPMT_HA_Marshal(TPMT_HA *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMT_HA_Unmarshal(TPMT_HA *target, BYTE **buffer, INT32 *size, BOOL flag);


// Table 68 -- TPM2B_DIGEST Structure <I/O>
UINT16
TPM2B_DIGEST_Marshal(TPM2B_DIGEST *source, BYTE **buffer, INT32 *size);
TPM_RC
TPM2B_DIGEST_Unmarshal(TPM2B_DIGEST *target, BYTE **buffer, INT32 *size);


// Table 69 -- TPM2B_DATA Structure <I/O>
UINT16
TPM2B_DATA_Marshal(TPM2B_DATA *source, BYTE **buffer, INT32 *size);
TPM_RC
TPM2B_DATA_Unmarshal(TPM2B_DATA *target, BYTE **buffer, INT32 *size);


// Table 70 -- TPM2B_NONCE Types <I/O>
UINT16
TPM2B_NONCE_Marshal(TPM2B_NONCE *source, BYTE **buffer, INT32 *size);
TPM_RC
TPM2B_NONCE_Unmarshal(TPM2B_NONCE *target, BYTE **buffer, INT32 *size);



// Table 71 -- TPM2B_AUTH Types <I/O>
UINT16
TPM2B_AUTH_Marshal(TPM2B_AUTH *source, BYTE **buffer, INT32 *size);
TPM_RC
TPM2B_AUTH_Unmarshal(TPM2B_AUTH *target, BYTE **buffer, INT32 *size);



// Table 72 -- TPM2B_OPERAND Types <I/O>
UINT16
TPM2B_OPERAND_Marshal(TPM2B_OPERAND *source, BYTE **buffer, INT32 *size);
TPM_RC
TPM2B_OPERAND_Unmarshal(TPM2B_OPERAND *target, BYTE **buffer, INT32 *size);



// Table 73 -- TPM2B_EVENT Structure <I/O>
UINT16
TPM2B_EVENT_Marshal(TPM2B_EVENT *source, BYTE **buffer, INT32 *size);
TPM_RC
TPM2B_EVENT_Unmarshal(TPM2B_EVENT *target, BYTE **buffer, INT32 *size);


// Table 74 -- TPM2B_MAX_BUFFER Structure <I/O>
UINT16
TPM2B_MAX_BUFFER_Marshal(TPM2B_MAX_BUFFER *source, BYTE **buffer, INT32 *size);
TPM_RC
TPM2B_MAX_BUFFER_Unmarshal(TPM2B_MAX_BUFFER *target, BYTE **buffer, INT32 *size);


// Table 75 -- TPM2B_MAX_NV_BUFFER Structure <I/O>
UINT16
TPM2B_MAX_NV_BUFFER_Marshal(TPM2B_MAX_NV_BUFFER *source, BYTE **buffer, INT32 *size);
TPM_RC
TPM2B_MAX_NV_BUFFER_Unmarshal(TPM2B_MAX_NV_BUFFER *target, BYTE **buffer, INT32 *size);


// Table 76 -- TPM2B_TIMEOUT Structure <I/O>
UINT16
TPM2B_TIMEOUT_Marshal(TPM2B_TIMEOUT *source, BYTE **buffer, INT32 *size);
TPM_RC
TPM2B_TIMEOUT_Unmarshal(TPM2B_TIMEOUT *target, BYTE **buffer, INT32 *size);


// Table 77 -- TPM2B_IV Structure <I/O>
UINT16
TPM2B_IV_Marshal(TPM2B_IV *source, BYTE **buffer, INT32 *size);
TPM_RC
TPM2B_IV_Unmarshal(TPM2B_IV *target, BYTE **buffer, INT32 *size);



// Table 79 -- TPM2B_NAME Structure <I/O>
UINT16
TPM2B_NAME_Marshal(TPM2B_NAME *source, BYTE **buffer, INT32 *size);
TPM_RC
TPM2B_NAME_Unmarshal(TPM2B_NAME *target, BYTE **buffer, INT32 *size);


// Table 80 -- TPMS_PCR_SELECT Structure <I/O>
UINT16
TPMS_PCR_SELECT_Marshal(TPMS_PCR_SELECT *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMS_PCR_SELECT_Unmarshal(TPMS_PCR_SELECT *target, BYTE **buffer, INT32 *size);


// Table 81 -- TPMS_PCR_SELECTION Structure <I/O>
UINT16
TPMS_PCR_SELECTION_Marshal(TPMS_PCR_SELECTION *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMS_PCR_SELECTION_Unmarshal(TPMS_PCR_SELECTION *target, BYTE **buffer, INT32 *size);


// Table 84 -- TPMT_TK_CREATION Structure <I/O>
UINT16
TPMT_TK_CREATION_Marshal(TPMT_TK_CREATION *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMT_TK_CREATION_Unmarshal(TPMT_TK_CREATION *target, BYTE **buffer, INT32 *size);


// Table 85 -- TPMT_TK_VERIFIED Structure <I/O>
UINT16
TPMT_TK_VERIFIED_Marshal(TPMT_TK_VERIFIED *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMT_TK_VERIFIED_Unmarshal(TPMT_TK_VERIFIED *target, BYTE **buffer, INT32 *size);


// Table 86 -- TPMT_TK_AUTH Structure <I/O>
UINT16
TPMT_TK_AUTH_Marshal(TPMT_TK_AUTH *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMT_TK_AUTH_Unmarshal(TPMT_TK_AUTH *target, BYTE **buffer, INT32 *size);


// Table 87 -- TPMT_TK_HASHCHECK Structure <I/O>
UINT16
TPMT_TK_HASHCHECK_Marshal(TPMT_TK_HASHCHECK *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMT_TK_HASHCHECK_Unmarshal(TPMT_TK_HASHCHECK *target, BYTE **buffer, INT32 *size);


// Table 88 -- TPMS_ALG_PROPERTY Structure <O,S>
UINT16
TPMS_ALG_PROPERTY_Marshal(TPMS_ALG_PROPERTY *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMS_ALG_PROPERTY_Unmarshal(TPMS_ALG_PROPERTY *target, BYTE **buffer, INT32 *size);


// Table 89 -- TPMS_TAGGED_PROPERTY Structure <O,S>
TPM_RC
TPMS_TAGGED_PROPERTY_Unmarshal(TPMS_TAGGED_PROPERTY *target, BYTE **buffer, INT32 *size);
UINT16
TPMS_TAGGED_PROPERTY_Marshal(TPMS_TAGGED_PROPERTY *source, BYTE **buffer, INT32 *size);


// Table 90 -- TPMS_TAGGED_PCR_SELECT Structure <O,S>
TPM_RC
TPMS_TAGGED_PCR_SELECT_Unmarshal(TPMS_TAGGED_PCR_SELECT *target, BYTE **buffer, INT32 *size);
UINT16
TPMS_TAGGED_PCR_SELECT_Marshal(TPMS_TAGGED_PCR_SELECT *source, BYTE **buffer, INT32 *size);


// Table 91 -- TPML_CC Structure <I/O>
UINT16
TPML_CC_Marshal(TPML_CC *source, BYTE **buffer, INT32 *size);
TPM_RC
TPML_CC_Unmarshal(TPML_CC *target, BYTE **buffer, INT32 *size);


// Table 92 -- TPML_CCA Structure <O,S>
UINT16
TPML_CCA_Marshal(TPML_CCA *source, BYTE **buffer, INT32 *size);


// Table 93 -- TPML_ALG Structure <I/O>
UINT16
TPML_ALG_Marshal(TPML_ALG *source, BYTE **buffer, INT32 *size);
TPM_RC
TPML_ALG_Unmarshal(TPML_ALG *target, BYTE **buffer, INT32 *size);


// Table 94 -- TPML_HANDLE Structure <O,S>
UINT16
TPML_HANDLE_Marshal(TPML_HANDLE *source, BYTE **buffer, INT32 *size);


// Table 95 -- TPML_DIGEST Structure <I/O>
UINT16
TPML_DIGEST_Marshal(TPML_DIGEST *source, BYTE **buffer, INT32 *size);
TPM_RC
TPML_DIGEST_Unmarshal(TPML_DIGEST *target, BYTE **buffer, INT32 *size);


// Table 96 -- TPML_DIGEST_VALUES Structure <I/O>
UINT16
TPML_DIGEST_VALUES_Marshal(TPML_DIGEST_VALUES *source, BYTE **buffer, INT32 *size);
TPM_RC
TPML_DIGEST_VALUES_Unmarshal(TPML_DIGEST_VALUES *target, BYTE **buffer, INT32 *size);


// Table 97 -- TPM2B_DIGEST_VALUES Structure <I/O>
UINT16
TPM2B_DIGEST_VALUES_Marshal(TPM2B_DIGEST_VALUES *source, BYTE **buffer, INT32 *size);
TPM_RC
TPM2B_DIGEST_VALUES_Unmarshal(TPM2B_DIGEST_VALUES *target, BYTE **buffer, INT32 *size);


// Table 98 -- TPML_PCR_SELECTION Structure <I/O>
UINT16
TPML_PCR_SELECTION_Marshal(TPML_PCR_SELECTION *source, BYTE **buffer, INT32 *size);
TPM_RC
TPML_PCR_SELECTION_Unmarshal(TPML_PCR_SELECTION *target, BYTE **buffer, INT32 *size);


// Table 99 -- TPML_ALG_PROPERTY Structure <O,S>
UINT16
TPML_ALG_PROPERTY_Marshal(TPML_ALG_PROPERTY *source, BYTE **buffer, INT32 *size);


// Table 100 -- TPML_TAGGED_TPM_PROPERTY Structure <O,S>
TPM_RC
TPML_TAGGED_TPM_PROPERTY_Unmarshal(TPML_TAGGED_TPM_PROPERTY *target, BYTE **buffer, INT32 *size);
UINT16
TPML_TAGGED_TPM_PROPERTY_Marshal(TPML_TAGGED_TPM_PROPERTY *source, BYTE **buffer, INT32 *size);


// Table 101 -- TPML_TAGGED_PCR_PROPERTY Structure <O,S>
UINT16
TPML_TAGGED_PCR_PROPERTY_Marshal(TPML_TAGGED_PCR_PROPERTY *source, BYTE **buffer, INT32 *size);


// Table 102 -- TPML_ECC_CURVE Structure <O,S>
UINT16
TPML_ECC_CURVE_Marshal(TPML_ECC_CURVE *source, BYTE **buffer, INT32 *size);


// Table 103 -- TPMU_CAPABILITIES Union <O,S>
UINT16
TPMU_CAPABILITIES_Marshal(TPMU_CAPABILITIES *source, BYTE **buffer, INT32 *size, UINT32 selector);


// Table 104 -- TPMS_CAPABILITY_DATA Structure <O,S>
TPM_RC
TPMS_CAPABILITY_DATA_Unmarshal(TPMS_CAPABILITY_DATA *target, BYTE **buffer, INT32 *size);
UINT16
TPMS_CAPABILITY_DATA_Marshal(TPMS_CAPABILITY_DATA *source, BYTE **buffer, INT32 *size);


// Table 105 -- TPMS_CLOCK_INFO Structure <I/O>
UINT16
TPMS_CLOCK_INFO_Marshal(TPMS_CLOCK_INFO *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMS_CLOCK_INFO_Unmarshal(TPMS_CLOCK_INFO *target, BYTE **buffer, INT32 *size);


// Table 106 -- TPMS_TIME_INFO Structure <I/O>
UINT16
TPMS_TIME_INFO_Marshal(TPMS_TIME_INFO *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMS_TIME_INFO_Unmarshal(TPMS_TIME_INFO *target, BYTE **buffer, INT32 *size);


// Table 107 -- TPMS_TIME_ATTEST_INFO Structure <O,S>
TPM_RC
TPMS_TIME_ATTEST_INFO_Unmarshal(TPMS_TIME_ATTEST_INFO *target, BYTE **buffer, INT32 *size);
UINT16
TPMS_TIME_ATTEST_INFO_Marshal(TPMS_TIME_ATTEST_INFO *source, BYTE **buffer, INT32 *size);


// Table 108 -- TPMS_CERTIFY_INFO Structure <O,S>
TPM_RC
TPMS_CERTIFY_INFO_Unmarshal(TPMS_CERTIFY_INFO *target, BYTE **buffer, INT32 *size);
UINT16
TPMS_CERTIFY_INFO_Marshal(TPMS_CERTIFY_INFO *source, BYTE **buffer, INT32 *size);


// Table 109 -- TPMS_QUOTE_INFO Structure <O,S>
TPM_RC
TPMS_QUOTE_INFO_Unmarshal(TPMS_QUOTE_INFO *target, BYTE **buffer, INT32 *size);
UINT16
TPMS_QUOTE_INFO_Marshal(TPMS_QUOTE_INFO *source, BYTE **buffer, INT32 *size);


// Table 110 -- TPMS_COMMAND_AUDIT_INFO Structure <O,S>
TPM_RC
TPMS_COMMAND_AUDIT_INFO_Unmarshal(TPMS_COMMAND_AUDIT_INFO *target, BYTE **buffer, INT32 *size);
UINT16
TPMS_COMMAND_AUDIT_INFO_Marshal(TPMS_COMMAND_AUDIT_INFO *source, BYTE **buffer, INT32 *size);


// Table 111 -- TPMS_SESSION_AUDIT_INFO Structure <O,S>
TPM_RC
TPMS_SESSION_AUDIT_INFO_Unmarshal(TPMS_SESSION_AUDIT_INFO *target, BYTE **buffer, INT32 *size);
UINT16
TPMS_SESSION_AUDIT_INFO_Marshal(TPMS_SESSION_AUDIT_INFO *source, BYTE **buffer, INT32 *size);


// Table 112 -- TPMS_CREATION_INFO Structure <O,S>
TPM_RC
TPMS_CREATION_INFO_Unmarshal(TPMS_CREATION_INFO *target, BYTE **buffer, INT32 *size);
UINT16
TPMS_CREATION_INFO_Marshal(TPMS_CREATION_INFO *source, BYTE **buffer, INT32 *size);


// Table 113 -- TPMS_NV_CERTIFY_INFO Structure <O,S>
TPM_RC
TPMS_NV_CERTIFY_INFO_Unmarshal(TPMS_NV_CERTIFY_INFO *target, BYTE **buffer, INT32 *size);
UINT16
TPMS_NV_CERTIFY_INFO_Marshal(TPMS_NV_CERTIFY_INFO *source, BYTE **buffer, INT32 *size);


// Table 114 -- TPMI_ST_ATTEST Type <O,S>
TPM_RC
TPMI_ST_ATTEST_Unmarshal(TPMI_ST_ATTEST *target, BYTE **buffer, INT32 *size);
UINT16
TPMI_ST_ATTEST_Marshal(TPMI_ST_ATTEST *source, BYTE **buffer, INT32 *size);


// Table 115 -- TPMU_ATTEST Union <O,S>
TPM_RC
TPMU_ATTEST_Unmarshal(TPMU_ATTEST *target, BYTE **buffer, INT32 *size, UINT32 selector);
UINT16
TPMU_ATTEST_Marshal(TPMU_ATTEST *source, BYTE **buffer, INT32 *size, UINT32 selector);


// Table 116 -- TPMS_ATTEST Structure <O,S>
TPM_RC
TPMS_ATTEST_Unmarshal(TPMS_ATTEST *target, BYTE **buffer, INT32 *size);
UINT16
TPMS_ATTEST_Marshal(TPMS_ATTEST *source, BYTE **buffer, INT32 *size);


// Table 117 -- TPM2B_ATTEST Structure <O,S>
TPM_RC
TPM2B_ATTEST_Unmarshal(TPM2B_ATTEST *target, BYTE **buffer, INT32 *size);
UINT16
TPM2B_ATTEST_Marshal(TPM2B_ATTEST *source, BYTE **buffer, INT32 *size);


// Table 118 -- TPMS_AUTH_COMMAND Structure <I>
TPM_RC
TPMS_AUTH_COMMAND_Unmarshal(TPMS_AUTH_COMMAND *target, BYTE **buffer, INT32 *size);


// Table 119 -- TPMS_AUTH_RESPONSE Structure <O,S>
UINT16
TPMS_AUTH_RESPONSE_Marshal(TPMS_AUTH_RESPONSE *source, BYTE **buffer, INT32 *size);


// Table 120 -- TPMI_AES_KEY_BITS Type <I/O>
UINT16
TPMI_AES_KEY_BITS_Marshal(TPMI_AES_KEY_BITS *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMI_AES_KEY_BITS_Unmarshal(TPMI_AES_KEY_BITS *target, BYTE **buffer, INT32 *size);


// Table 121 -- TPMI_SM4_KEY_BITS Type <I/O>
UINT16
TPMI_SM4_KEY_BITS_Marshal(TPMI_SM4_KEY_BITS *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMI_SM4_KEY_BITS_Unmarshal(TPMI_SM4_KEY_BITS *target, BYTE **buffer, INT32 *size);


// Table 122 -- TPMU_SYM_KEY_BITS Union <I/O>
UINT16
TPMU_SYM_KEY_BITS_Marshal(TPMU_SYM_KEY_BITS *source, BYTE **buffer, INT32 *size, UINT32 selector);
TPM_RC
TPMU_SYM_KEY_BITS_Unmarshal(TPMU_SYM_KEY_BITS *target, BYTE **buffer, INT32 *size, UINT32 selector);


// Table 123 -- TPMU_SYM_MODE Union <I/O>
UINT16
TPMU_SYM_MODE_Marshal(TPMU_SYM_MODE *source, BYTE **buffer, INT32 *size, UINT32 selector);
TPM_RC
TPMU_SYM_MODE_Unmarshal(TPMU_SYM_MODE *target, BYTE **buffer, INT32 *size, UINT32 selector);


// Table 125 -- TPMT_SYM_DEF Structure <I/O>
UINT16
TPMT_SYM_DEF_Marshal(TPMT_SYM_DEF *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMT_SYM_DEF_Unmarshal(TPMT_SYM_DEF *target, BYTE **buffer, INT32 *size, BOOL flag);


// Table 126 -- TPMT_SYM_DEF_OBJECT Structure <I/O>
UINT16
TPMT_SYM_DEF_OBJECT_Marshal(TPMT_SYM_DEF_OBJECT *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMT_SYM_DEF_OBJECT_Unmarshal(TPMT_SYM_DEF_OBJECT *target, BYTE **buffer, INT32 *size, BOOL flag);


// Table 127 -- TPM2B_SYM_KEY Structure <I/O>
UINT16
TPM2B_SYM_KEY_Marshal(TPM2B_SYM_KEY *source, BYTE **buffer, INT32 *size);
TPM_RC
TPM2B_SYM_KEY_Unmarshal(TPM2B_SYM_KEY *target, BYTE **buffer, INT32 *size);


// Table 128 -- TPMS_SYMCIPHER_PARMS Structure <I/O>
UINT16
TPMS_SYMCIPHER_PARMS_Marshal(TPMS_SYMCIPHER_PARMS *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMS_SYMCIPHER_PARMS_Unmarshal(TPMS_SYMCIPHER_PARMS *target, BYTE **buffer, INT32 *size);


// Table 129 -- TPM2B_SENSITIVE_DATA Structure <I/O>
UINT16
TPM2B_SENSITIVE_DATA_Marshal(TPM2B_SENSITIVE_DATA *source, BYTE **buffer, INT32 *size);
TPM_RC
TPM2B_SENSITIVE_DATA_Unmarshal(TPM2B_SENSITIVE_DATA *target, BYTE **buffer, INT32 *size);


// Table 130 -- TPMS_SENSITIVE_CREATE Structure <I>
TPM_RC
TPMS_SENSITIVE_CREATE_Unmarshal(TPMS_SENSITIVE_CREATE *target, BYTE **buffer, INT32 *size);
UINT16
TPMS_SENSITIVE_CREATE_Marshal(TPMS_SENSITIVE_CREATE *source, BYTE **buffer, INT32 *size);


// Table 131 -- TPM2B_SENSITIVE_CREATE Structure <I,S>
TPM_RC
TPM2B_SENSITIVE_CREATE_Unmarshal(TPM2B_SENSITIVE_CREATE *target, BYTE **buffer, INT32 *size);
UINT16
TPM2B_SENSITIVE_CREATE_Marshal(TPM2B_SENSITIVE_CREATE *source, BYTE **buffer, INT32 *size);

// Table 132 -- TPMS_SCHEME_SIGHASH Structure <I/O>
UINT16
TPMS_SCHEME_SIGHASH_Marshal(TPMS_SCHEME_SIGHASH *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMS_SCHEME_SIGHASH_Unmarshal(TPMS_SCHEME_SIGHASH *target, BYTE **buffer, INT32 *size);


// Table 133 -- TPMI_ALG_KEYEDHASH_SCHEME Type <I/O>
UINT16
TPMI_ALG_KEYEDHASH_SCHEME_Marshal(TPMI_ALG_KEYEDHASH_SCHEME *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMI_ALG_KEYEDHASH_SCHEME_Unmarshal(TPMI_ALG_KEYEDHASH_SCHEME *target, BYTE **buffer, INT32 *size, BOOL flag);


// Table 134 -- HMAC_SIG_SCHEME Types <I/O>
UINT16
TPMS_SCHEME_HMAC_Marshal(TPMS_SCHEME_HMAC *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMS_SCHEME_HMAC_Unmarshal(TPMS_SCHEME_HMAC *target, BYTE **buffer, INT32 *size);



// Table 135 -- TPMS_SCHEME_XOR Structure <I/O>
UINT16
TPMS_SCHEME_XOR_Marshal(TPMS_SCHEME_XOR *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMS_SCHEME_XOR_Unmarshal(TPMS_SCHEME_XOR *target, BYTE **buffer, INT32 *size, BOOL flag);


// Table 136 -- TPMU_SCHEME_KEYEDHASH Union <I/O,S>
UINT16
TPMU_SCHEME_KEYEDHASH_Marshal(TPMU_SCHEME_KEYEDHASH *source, BYTE **buffer, INT32 *size, UINT32 selector);
TPM_RC
TPMU_SCHEME_KEYEDHASH_Unmarshal(TPMU_SCHEME_KEYEDHASH *target, BYTE **buffer, INT32 *size, UINT32 selector);


// Table 137 -- TPMT_KEYEDHASH_SCHEME Structure <I/O>
UINT16
TPMT_KEYEDHASH_SCHEME_Marshal(TPMT_KEYEDHASH_SCHEME *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMT_KEYEDHASH_SCHEME_Unmarshal(TPMT_KEYEDHASH_SCHEME *target, BYTE **buffer, INT32 *size, BOOL flag);


// Table 138 -- RSA_SIG_SCHEMES Types <I/O>
UINT16
TPMS_SCHEME_RSASSA_Marshal(TPMS_SCHEME_RSASSA *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMS_SCHEME_RSASSA_Unmarshal(TPMS_SCHEME_RSASSA *target, BYTE **buffer, INT32 *size);
UINT16
TPMS_SCHEME_RSAPSS_Marshal(TPMS_SCHEME_RSAPSS *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMS_SCHEME_RSAPSS_Unmarshal(TPMS_SCHEME_RSAPSS *target, BYTE **buffer, INT32 *size);



// Table 139 -- ECC_SIG_SCHEMES Types <I/O>
UINT16
TPMS_SCHEME_ECDSA_Marshal(TPMS_SCHEME_ECDSA *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMS_SCHEME_ECDSA_Unmarshal(TPMS_SCHEME_ECDSA *target, BYTE **buffer, INT32 *size);
UINT16
TPMS_SCHEME_SM2_Marshal(TPMS_SCHEME_SM2 *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMS_SCHEME_SM2_Unmarshal(TPMS_SCHEME_SM2 *target, BYTE **buffer, INT32 *size);
UINT16
TPMS_SCHEME_ECSCHNORR_Marshal(TPMS_SCHEME_ECSCHNORR *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMS_SCHEME_ECSCHNORR_Unmarshal(TPMS_SCHEME_ECSCHNORR *target, BYTE **buffer, INT32 *size);



// Table 140 -- TPMS_SCHEME_ECDAA Structure <I/O>
UINT16
TPMS_SCHEME_ECDAA_Marshal(TPMS_SCHEME_ECDAA *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMS_SCHEME_ECDAA_Unmarshal(TPMS_SCHEME_ECDAA *target, BYTE **buffer, INT32 *size);


// Table 141 -- TPMU_SIG_SCHEME Union <I/O,S>
UINT16
TPMU_SIG_SCHEME_Marshal(TPMU_SIG_SCHEME *source, BYTE **buffer, INT32 *size, UINT32 selector);
TPM_RC
TPMU_SIG_SCHEME_Unmarshal(TPMU_SIG_SCHEME *target, BYTE **buffer, INT32 *size, UINT32 selector);


// Table 142 -- TPMT_SIG_SCHEME Structure <I/O>
UINT16
TPMT_SIG_SCHEME_Marshal(TPMT_SIG_SCHEME *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMT_SIG_SCHEME_Unmarshal(TPMT_SIG_SCHEME *target, BYTE **buffer, INT32 *size, BOOL flag);


// Table 143 -- TPMS_SCHEME_OAEP Structure <I/O>
UINT16
TPMS_SCHEME_OAEP_Marshal(TPMS_SCHEME_OAEP *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMS_SCHEME_OAEP_Unmarshal(TPMS_SCHEME_OAEP *target, BYTE **buffer, INT32 *size, BOOL flag);


// Table 144 -- TPMS_SCHEME_ECDH Structure <I/O>
UINT16
TPMS_SCHEME_ECDH_Marshal(TPMS_SCHEME_ECDH *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMS_SCHEME_ECDH_Unmarshal(TPMS_SCHEME_ECDH *target, BYTE **buffer, INT32 *size, BOOL flag);


// Table 145 -- TPMS_SCHEME_MGF1 Structure <I/O>
UINT16
TPMS_SCHEME_MGF1_Marshal(TPMS_SCHEME_MGF1 *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMS_SCHEME_MGF1_Unmarshal(TPMS_SCHEME_MGF1 *target, BYTE **buffer, INT32 *size);


// Table 146 -- TPMS_SCHEME_KDF1_SP800_56a Structure <I/O>
UINT16
TPMS_SCHEME_KDF1_SP800_56a_Marshal(TPMS_SCHEME_KDF1_SP800_56a *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMS_SCHEME_KDF1_SP800_56a_Unmarshal(TPMS_SCHEME_KDF1_SP800_56a *target, BYTE **buffer, INT32 *size);


// Table 147 -- TPMS_SCHEME_KDF2 Structure <I/O>
UINT16
TPMS_SCHEME_KDF2_Marshal(TPMS_SCHEME_KDF2 *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMS_SCHEME_KDF2_Unmarshal(TPMS_SCHEME_KDF2 *target, BYTE **buffer, INT32 *size);


// Table 148 -- TPMS_SCHEME_KDF1_SP800_108 Structure <I/O>
UINT16
TPMS_SCHEME_KDF1_SP800_108_Marshal(TPMS_SCHEME_KDF1_SP800_108 *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMS_SCHEME_KDF1_SP800_108_Unmarshal(TPMS_SCHEME_KDF1_SP800_108 *target, BYTE **buffer, INT32 *size);


// Table 149 -- TPMU_KDF_SCHEME Union <I/O,S>
UINT16
TPMU_KDF_SCHEME_Marshal(TPMU_KDF_SCHEME *source, BYTE **buffer, INT32 *size, UINT32 selector);
TPM_RC
TPMU_KDF_SCHEME_Unmarshal(TPMU_KDF_SCHEME *target, BYTE **buffer, INT32 *size, UINT32 selector);


// Table 150 -- TPMT_KDF_SCHEME Structure <I/O>
UINT16
TPMT_KDF_SCHEME_Marshal(TPMT_KDF_SCHEME *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMT_KDF_SCHEME_Unmarshal(TPMT_KDF_SCHEME *target, BYTE **buffer, INT32 *size, BOOL flag);



// Table 152 -- TPMU_ASYM_SCHEME Union <I/O>
UINT16
TPMU_ASYM_SCHEME_Marshal(TPMU_ASYM_SCHEME *source, BYTE **buffer, INT32 *size, UINT32 selector);
TPM_RC
TPMU_ASYM_SCHEME_Unmarshal(TPMU_ASYM_SCHEME *target, BYTE **buffer, INT32 *size, UINT32 selector);



// Table 154 -- TPMI_ALG_RSA_SCHEME Type <I/O>
UINT16
TPMI_ALG_RSA_SCHEME_Marshal(TPMI_ALG_RSA_SCHEME *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMI_ALG_RSA_SCHEME_Unmarshal(TPMI_ALG_RSA_SCHEME *target, BYTE **buffer, INT32 *size, BOOL flag);


// Table 155 -- TPMT_RSA_SCHEME Structure <I/O>
UINT16
TPMT_RSA_SCHEME_Marshal(TPMT_RSA_SCHEME *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMT_RSA_SCHEME_Unmarshal(TPMT_RSA_SCHEME *target, BYTE **buffer, INT32 *size, BOOL flag);


// Table 156 -- TPMI_ALG_RSA_DECRYPT Type <I/O>
UINT16
TPMI_ALG_RSA_DECRYPT_Marshal(TPMI_ALG_RSA_DECRYPT *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMI_ALG_RSA_DECRYPT_Unmarshal(TPMI_ALG_RSA_DECRYPT *target, BYTE **buffer, INT32 *size, BOOL flag);


// Table 157 -- TPMT_RSA_DECRYPT Structure <I/O>
UINT16
TPMT_RSA_DECRYPT_Marshal(TPMT_RSA_DECRYPT *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMT_RSA_DECRYPT_Unmarshal(TPMT_RSA_DECRYPT *target, BYTE **buffer, INT32 *size, BOOL flag);


// Table 158 -- TPM2B_PUBLIC_KEY_RSA Structure <I/O>
UINT16
TPM2B_PUBLIC_KEY_RSA_Marshal(TPM2B_PUBLIC_KEY_RSA *source, BYTE **buffer, INT32 *size);
TPM_RC
TPM2B_PUBLIC_KEY_RSA_Unmarshal(TPM2B_PUBLIC_KEY_RSA *target, BYTE **buffer, INT32 *size);


// Table 159 -- TPMI_RSA_KEY_BITS Type <I/O>
UINT16
TPMI_RSA_KEY_BITS_Marshal(TPMI_RSA_KEY_BITS *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMI_RSA_KEY_BITS_Unmarshal(TPMI_RSA_KEY_BITS *target, BYTE **buffer, INT32 *size);


// Table 160 -- TPM2B_PRIVATE_KEY_RSA Structure <I/O>
UINT16
TPM2B_PRIVATE_KEY_RSA_Marshal(TPM2B_PRIVATE_KEY_RSA *source, BYTE **buffer, INT32 *size);
TPM_RC
TPM2B_PRIVATE_KEY_RSA_Unmarshal(TPM2B_PRIVATE_KEY_RSA *target, BYTE **buffer, INT32 *size);


// Table 161 -- TPM2B_ECC_PARAMETER Structure <I/O>
UINT16
TPM2B_ECC_PARAMETER_Marshal(TPM2B_ECC_PARAMETER *source, BYTE **buffer, INT32 *size);
TPM_RC
TPM2B_ECC_PARAMETER_Unmarshal(TPM2B_ECC_PARAMETER *target, BYTE **buffer, INT32 *size);


// Table 162 -- TPMS_ECC_POINT Structure <I/O>
UINT16
TPMS_ECC_POINT_Marshal(TPMS_ECC_POINT *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMS_ECC_POINT_Unmarshal(TPMS_ECC_POINT *target, BYTE **buffer, INT32 *size);


// Table 163 -- TPM2B_ECC_POINT Structure <I/O>
UINT16
TPM2B_ECC_POINT_Marshal(TPM2B_ECC_POINT *source, BYTE **buffer, INT32 *size);
TPM_RC
TPM2B_ECC_POINT_Unmarshal(TPM2B_ECC_POINT *target, BYTE **buffer, INT32 *size);


// Table 164 -- TPMI_ALG_ECC_SCHEME Type <I/O>
UINT16
TPMI_ALG_ECC_SCHEME_Marshal(TPMI_ALG_ECC_SCHEME *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMI_ALG_ECC_SCHEME_Unmarshal(TPMI_ALG_ECC_SCHEME *target, BYTE **buffer, INT32 *size, BOOL flag);


// Table 165 -- TPMI_ECC_CURVE Type <I/O>
UINT16
TPMI_ECC_CURVE_Marshal(TPMI_ECC_CURVE *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMI_ECC_CURVE_Unmarshal(TPMI_ECC_CURVE *target, BYTE **buffer, INT32 *size);


// Table 166 -- TPMT_ECC_SCHEME Structure <I/O>
UINT16
TPMT_ECC_SCHEME_Marshal(TPMT_ECC_SCHEME *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMT_ECC_SCHEME_Unmarshal(TPMT_ECC_SCHEME *target, BYTE **buffer, INT32 *size, BOOL flag);


// Table 167 -- TPMS_ALGORITHM_DETAIL_ECC Structure <O,S>
UINT16
TPMS_ALGORITHM_DETAIL_ECC_Marshal(TPMS_ALGORITHM_DETAIL_ECC *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMS_ALGORITHM_DETAIL_ECC_Unmarshal(TPMS_ALGORITHM_DETAIL_ECC *target, BYTE **buffer, INT32 *size);


// Table 168 -- TPMS_SIGNATURE_RSASSA Structure <I/O>
UINT16
TPMS_SIGNATURE_RSASSA_Marshal(TPMS_SIGNATURE_RSASSA *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMS_SIGNATURE_RSASSA_Unmarshal(TPMS_SIGNATURE_RSASSA *target, BYTE **buffer, INT32 *size);


// Table 169 -- TPMS_SIGNATURE_RSAPSS Structure <I/O>
UINT16
TPMS_SIGNATURE_RSAPSS_Marshal(TPMS_SIGNATURE_RSAPSS *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMS_SIGNATURE_RSAPSS_Unmarshal(TPMS_SIGNATURE_RSAPSS *target, BYTE **buffer, INT32 *size);


// Table 170 -- TPMS_SIGNATURE_ECDSA Structure <I/O>
UINT16
TPMS_SIGNATURE_ECDSA_Marshal(TPMS_SIGNATURE_ECDSA *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMS_SIGNATURE_ECDSA_Unmarshal(TPMS_SIGNATURE_ECDSA *target, BYTE **buffer, INT32 *size);


// Table 171 -- TPMU_SIGNATURE Union <I/O,S>
UINT16
TPMU_SIGNATURE_Marshal(TPMU_SIGNATURE *source, BYTE **buffer, INT32 *size, UINT32 selector);
TPM_RC
TPMU_SIGNATURE_Unmarshal(TPMU_SIGNATURE *target, BYTE **buffer, INT32 *size, UINT32 selector);


// Table 172 -- TPMT_SIGNATURE Structure <I/O>
UINT16
TPMT_SIGNATURE_Marshal(TPMT_SIGNATURE *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMT_SIGNATURE_Unmarshal(TPMT_SIGNATURE *target, BYTE **buffer, INT32 *size, BOOL flag);



// Table 174 -- TPM2B_ENCRYPTED_SECRET Structure <I/O>
UINT16
TPM2B_ENCRYPTED_SECRET_Marshal(TPM2B_ENCRYPTED_SECRET *source, BYTE **buffer, INT32 *size);
TPM_RC
TPM2B_ENCRYPTED_SECRET_Unmarshal(TPM2B_ENCRYPTED_SECRET *target, BYTE **buffer, INT32 *size);


// Table 175 -- TPMI_ALG_PUBLIC Type <I/O>
UINT16
TPMI_ALG_PUBLIC_Marshal(TPMI_ALG_PUBLIC *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMI_ALG_PUBLIC_Unmarshal(TPMI_ALG_PUBLIC *target, BYTE **buffer, INT32 *size);


// Table 176 -- TPMU_PUBLIC_ID Union <I/O,S>
UINT16
TPMU_PUBLIC_ID_Marshal(TPMU_PUBLIC_ID *source, BYTE **buffer, INT32 *size, UINT32 selector);
TPM_RC
TPMU_PUBLIC_ID_Unmarshal(TPMU_PUBLIC_ID *target, BYTE **buffer, INT32 *size, UINT32 selector);


// Table 177 -- TPMS_KEYEDHASH_PARMS Structure <I/O>
UINT16
TPMS_KEYEDHASH_PARMS_Marshal(TPMS_KEYEDHASH_PARMS *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMS_KEYEDHASH_PARMS_Unmarshal(TPMS_KEYEDHASH_PARMS *target, BYTE **buffer, INT32 *size);



// Table 179 -- TPMS_RSA_PARMS Structure <I/O>
UINT16
TPMS_RSA_PARMS_Marshal(TPMS_RSA_PARMS *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMS_RSA_PARMS_Unmarshal(TPMS_RSA_PARMS *target, BYTE **buffer, INT32 *size);


// Table 180 -- TPMS_ECC_PARMS Structure <I/O>
UINT16
TPMS_ECC_PARMS_Marshal(TPMS_ECC_PARMS *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMS_ECC_PARMS_Unmarshal(TPMS_ECC_PARMS *target, BYTE **buffer, INT32 *size);


// Table 181 -- TPMU_PUBLIC_PARMS Union <I/O,S>
UINT16
TPMU_PUBLIC_PARMS_Marshal(TPMU_PUBLIC_PARMS *source, BYTE **buffer, INT32 *size, UINT32 selector);
TPM_RC
TPMU_PUBLIC_PARMS_Unmarshal(TPMU_PUBLIC_PARMS *target, BYTE **buffer, INT32 *size, UINT32 selector);


// Table 182 -- TPMT_PUBLIC_PARMS Structure <I/O>
UINT16
TPMT_PUBLIC_PARMS_Marshal(TPMT_PUBLIC_PARMS *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMT_PUBLIC_PARMS_Unmarshal(TPMT_PUBLIC_PARMS *target, BYTE **buffer, INT32 *size);


// Table 183 -- TPMT_PUBLIC Structure <I/O>
UINT16
TPMT_PUBLIC_Marshal(TPMT_PUBLIC *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMT_PUBLIC_Unmarshal(TPMT_PUBLIC *target, BYTE **buffer, INT32 *size, BOOL flag);


// Table 184 -- TPM2B_PUBLIC Structure <I/O>
UINT16
TPM2B_PUBLIC_Marshal(TPM2B_PUBLIC *source, BYTE **buffer, INT32 *size);
TPM_RC
TPM2B_PUBLIC_Unmarshal(TPM2B_PUBLIC *target, BYTE **buffer, INT32 *size, BOOL flag);



// Table 186 -- TPMU_SENSITIVE_COMPOSITE Union <I/O,S>
UINT16
TPMU_SENSITIVE_COMPOSITE_Marshal(TPMU_SENSITIVE_COMPOSITE *source, BYTE **buffer, INT32 *size, UINT32 selector);
TPM_RC
TPMU_SENSITIVE_COMPOSITE_Unmarshal(TPMU_SENSITIVE_COMPOSITE *target, BYTE **buffer, INT32 *size, UINT32 selector);


// Table 187 -- TPMT_SENSITIVE Structure <I/O>
UINT16
TPMT_SENSITIVE_Marshal(TPMT_SENSITIVE *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMT_SENSITIVE_Unmarshal(TPMT_SENSITIVE *target, BYTE **buffer, INT32 *size);


// Table 188 -- TPM2B_SENSITIVE Structure <I/O>
UINT16
TPM2B_SENSITIVE_Marshal(TPM2B_SENSITIVE *source, BYTE **buffer, INT32 *size);
TPM_RC
TPM2B_SENSITIVE_Unmarshal(TPM2B_SENSITIVE *target, BYTE **buffer, INT32 *size);



// Table 190 -- TPM2B_PRIVATE Structure <I/O,S>
UINT16
TPM2B_PRIVATE_Marshal(TPM2B_PRIVATE *source, BYTE **buffer, INT32 *size);
TPM_RC
TPM2B_PRIVATE_Unmarshal(TPM2B_PRIVATE *target, BYTE **buffer, INT32 *size);



// Table 192 -- TPM2B_ID_OBJECT Structure <I/O>
UINT16
TPM2B_ID_OBJECT_Marshal(TPM2B_ID_OBJECT *source, BYTE **buffer, INT32 *size);
TPM_RC
TPM2B_ID_OBJECT_Unmarshal(TPM2B_ID_OBJECT *target, BYTE **buffer, INT32 *size);



// Table 195 -- TPMA_NV Bits <I/O>
UINT16
TPMA_NV_Marshal(TPMA_NV *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMA_NV_Unmarshal(TPMA_NV *target, BYTE **buffer, INT32 *size);


// Table 196 -- TPMS_NV_PUBLIC Structure <I/O>
UINT16
TPMS_NV_PUBLIC_Marshal(TPMS_NV_PUBLIC *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMS_NV_PUBLIC_Unmarshal(TPMS_NV_PUBLIC *target, BYTE **buffer, INT32 *size);


// Table 197 -- TPM2B_NV_PUBLIC Structure <I/O>
UINT16
TPM2B_NV_PUBLIC_Marshal(TPM2B_NV_PUBLIC *source, BYTE **buffer, INT32 *size);
TPM_RC
TPM2B_NV_PUBLIC_Unmarshal(TPM2B_NV_PUBLIC *target, BYTE **buffer, INT32 *size);


// Table 198 -- TPM2B_CONTEXT_SENSITIVE Structure <I/O>
UINT16
TPM2B_CONTEXT_SENSITIVE_Marshal(TPM2B_CONTEXT_SENSITIVE *source, BYTE **buffer, INT32 *size);
TPM_RC
TPM2B_CONTEXT_SENSITIVE_Unmarshal(TPM2B_CONTEXT_SENSITIVE *target, BYTE **buffer, INT32 *size);


// Table 199 -- TPMS_CONTEXT_DATA Structure <I/O,S>
UINT16
TPMS_CONTEXT_DATA_Marshal(TPMS_CONTEXT_DATA *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMS_CONTEXT_DATA_Unmarshal(TPMS_CONTEXT_DATA *target, BYTE **buffer, INT32 *size);


// Table 200 -- TPM2B_CONTEXT_DATA Structure <I/O>
UINT16
TPM2B_CONTEXT_DATA_Marshal(TPM2B_CONTEXT_DATA *source, BYTE **buffer, INT32 *size);
TPM_RC
TPM2B_CONTEXT_DATA_Unmarshal(TPM2B_CONTEXT_DATA *target, BYTE **buffer, INT32 *size);


// Table 201 -- TPMS_CONTEXT Structure <I/O>
UINT16
TPMS_CONTEXT_Marshal(TPMS_CONTEXT *source, BYTE **buffer, INT32 *size);
TPM_RC
TPMS_CONTEXT_Unmarshal(TPMS_CONTEXT *target, BYTE **buffer, INT32 *size);


// Table 203 -- TPMS_CREATION_DATA Structure <O,S>
TPM_RC
TPMS_CREATION_DATA_Unmarshal(TPMS_CREATION_DATA *target, BYTE **buffer, INT32 *size);
UINT16
TPMS_CREATION_DATA_Marshal(TPMS_CREATION_DATA *source, BYTE **buffer, INT32 *size);


// Table 204 -- TPM2B_CREATION_DATA Structure <O,S>
TPM_RC
TPM2B_CREATION_DATA_Unmarshal(TPM2B_CREATION_DATA *target, BYTE **buffer, INT32 *size);
UINT16
TPM2B_CREATION_DATA_Marshal(TPM2B_CREATION_DATA *source, BYTE **buffer, INT32 *size);

// Array Marshal/Unmarshal for TPMS_TAGGED_PROPERTY
TPM_RC
TPMS_TAGGED_PROPERTY_Array_Unmarshal(TPMS_TAGGED_PROPERTY *target, BYTE **buffer, INT32 *size, INT32 count);
UINT16
TPMS_TAGGED_PROPERTY_Array_Marshal(TPMS_TAGGED_PROPERTY *source, BYTE **buffer, INT32 *size, INT32 count);

// Array Marshal/Unmarshal for TPMS_ALG_PROPERTY
TPM_RC
TPMS_ALG_PROPERTY_Array_Unmarshal(TPMS_ALG_PROPERTY *target, BYTE **buffer, INT32 *size, INT32 count);
UINT16
TPMS_ALG_PROPERTY_Array_Marshal(TPMS_ALG_PROPERTY *source, BYTE **buffer, INT32 *size, INT32 count);

// Array Marshal/Unmarshal for TPMS_PCR_SELECTION
TPM_RC
TPMS_PCR_SELECTION_Array_Unmarshal(TPMS_PCR_SELECTION *target, BYTE **buffer, INT32 *size, INT32 count);
UINT16
TPMS_PCR_SELECTION_Array_Marshal(TPMS_PCR_SELECTION *source, BYTE **buffer, INT32 *size, INT32 count);

// Array Marshal/Unmarshal for TPMT_HA
TPM_RC
TPMT_HA_Array_Unmarshal(TPMT_HA *target, BYTE **buffer, INT32 *size, BOOL flag, INT32 count);
UINT16
TPMT_HA_Array_Marshal(TPMT_HA *source, BYTE **buffer, INT32 *size, INT32 count);

// Array Marshal/Unmarshal for BYTE
TPM_RC
BYTE_Array_Unmarshal(BYTE *target, BYTE **buffer, INT32 *size, INT32 count);
UINT16
BYTE_Array_Marshal(BYTE *source, BYTE **buffer, INT32 *size, INT32 count);

// Array Marshal/Unmarshal for TPM_HANDLE
TPM_RC
TPM_HANDLE_Array_Unmarshal(TPM_HANDLE *target, BYTE **buffer, INT32 *size, INT32 count);
UINT16
TPM_HANDLE_Array_Marshal(TPM_HANDLE *source, BYTE **buffer, INT32 *size, INT32 count);

// Array Marshal/Unmarshal for TPMA_CC
TPM_RC
TPMA_CC_Array_Unmarshal(TPMA_CC *target, BYTE **buffer, INT32 *size, INT32 count);
UINT16
TPMA_CC_Array_Marshal(TPMA_CC *source, BYTE **buffer, INT32 *size, INT32 count);

// Array Marshal/Unmarshal for TPMS_TAGGED_PCR_SELECT
TPM_RC
TPMS_TAGGED_PCR_SELECT_Array_Unmarshal(TPMS_TAGGED_PCR_SELECT *target, BYTE **buffer, INT32 *size, INT32 count);
UINT16
TPMS_TAGGED_PCR_SELECT_Array_Marshal(TPMS_TAGGED_PCR_SELECT *source, BYTE **buffer, INT32 *size, INT32 count);

// Array Marshal/Unmarshal for TPM_ECC_CURVE
TPM_RC
TPM_ECC_CURVE_Array_Unmarshal(TPM_ECC_CURVE *target, BYTE **buffer, INT32 *size, INT32 count);
UINT16
TPM_ECC_CURVE_Array_Marshal(TPM_ECC_CURVE *source, BYTE **buffer, INT32 *size, INT32 count);

// Array Marshal/Unmarshal for TPM2B_DIGEST
TPM_RC
TPM2B_DIGEST_Array_Unmarshal(TPM2B_DIGEST *target, BYTE **buffer, INT32 *size, INT32 count);
UINT16
TPM2B_DIGEST_Array_Marshal(TPM2B_DIGEST *source, BYTE **buffer, INT32 *size, INT32 count);

// Array Marshal/Unmarshal for TPM_CC
TPM_RC
TPM_CC_Array_Unmarshal(TPM_CC *target, BYTE **buffer, INT32 *size, INT32 count);
UINT16
TPM_CC_Array_Marshal(TPM_CC *source, BYTE **buffer, INT32 *size, INT32 count);

// Array Marshal/Unmarshal for TPM_ALG_ID
TPM_RC
TPM_ALG_ID_Array_Unmarshal(TPM_ALG_ID *target, BYTE **buffer, INT32 *size, INT32 count);
UINT16
TPM_ALG_ID_Array_Marshal(TPM_ALG_ID *source, BYTE **buffer, INT32 *size, INT32 count);

#endif //_MARSHAL_H_

#ifndef    MEMORYLIB_FP_H
#define    MEMORYLIB_FP_H

//*** MemoryMove()
// This function moves data from one place in memory to another. No
// safety checks of any type are performed. If source and data buffer overlap,
// then the move is done as if an intermediate buffer were used.
// Note: This funciton is used by MemoryCopy, MemoryCopy2B, and MemoryConcat2b and
// requires that the caller know the maximum size of the destination buffer
// so that there is no possibility of buffer overrun.
void
MemoryMove(
    void            *destination,   // OUT: move destination
    const void      *source,        // IN: move source
    UINT32           size,          // IN: number of octets to moved
    UINT32           dSize          // IN: size of the receive buffer
);

#define MemoryCopy(a, b, c, d) MemoryMove((a), (b), (c), (d))

//*** MemoryEqual()
// This function indicates if two buffers have the same values in the indicated
// number of bytes.
// return type: BOOL
//      TRUE    all octets are the same
//      FALSE   all octets are not the same
BOOL
MemoryEqual(
    const void      *buffer1,           // IN: compare buffer1
    const void      *buffer2,           // IN: compare buffer2
    UINT32           size               // IN: size of bytes being compared
);

//*** MemoryCopy2B()
// This function copies a TPM2B. This can be used when the TPM2B types are
// the same or different. No size checking is done on the destination so
// the caller should make sure that the destination is large enough.
//
// This function returns the number of octets in the data buffer of the TPM2B.
INT16
MemoryCopy2B(
    TPM2B         *dest,      // OUT: receiving TPM2B
    const TPM2B   *source,    // IN: source TPM2B
    UINT16         dSize      // IN: size of the receiving buffer
);

//*** MemoryConcat2B()
// This function will concatenate the buffer contents of a TPM2B to an
// the buffer contents of another TPM2B and adjust the size accordingly
//      ('a' := ('a' | 'b')).
void
MemoryConcat2B(
    TPM2B   *aInOut,    // IN/OUT: destination 2B
    TPM2B   *bIn,       // IN: second 2B
    UINT16   aSize      // IN: The size of aInOut.buffer
                        //     (max values for aInOut.size)
);

//*** Memory2BEqual()
// This function will compare two TPM2B structures. To be equal, they
// need to be the same size and the buffer contexts need to be the same
// in all octets.
// return type: BOOL
//      TRUE    size and buffer contents are the same
//      FALSE   size or buffer contents are not the same
BOOL
Memory2BEqual(
    const TPM2B       *aIn,     // IN: compare value
    const TPM2B       *bIn      // IN: compare value
);

//*** MemorySet()
// This function will set all the octets in the specified memory range to
// the specified octet value.
// Note: the "dSize" parameter forces the caller to know how big the receiving
// buffer is to make sure that there is no possiblity that the caller will
// inadvertentl run over the end of the buffer.
// return type: void
void
MemorySet(
    void            *destination,       // OUT: memory destination
    char             value,             // IN: fill value
    UINT32           size              // IN: number of octets to fill
);

//*** MemoryGetActionInputBuffer()
// This function returns the address of the buffer into which the
// command parameters will be unmarshaled in preparation for calling
// the command actions.
BYTE *
MemoryGetActionInputBuffer(
    UINT32      size        // Size, in bytes, required for the input unmarshaling
);

//*** MemoryGetActionOutputBuffer()
// This function returns the address of the buffer into which the command
// action code places its output values.
void *
MemoryGetActionOutputBuffer(
    TPM_CC      command                 // Command that requires the buffer
);

//*** MemoryGetResponseBuffer()
// This function returns the address into which the command response is marshaled
// from values in the action output buffer.
BYTE *
MemoryGetResponseBuffer(
    TPM_CC      command                 // Command that requires the buffer
);

//*** MemoryRemoveTrailingZeros()
// This function is used to adjust the length of an authorization value.
// It adjusts the size of the TPM2B so that it does not include octets
// at the end of the buffer that contain zero.
// The function returns the number of non-zero octets in the buffer.
UINT16
MemoryRemoveTrailingZeros (
    TPM2B_AUTH      *auth        // IN/OUT: value to adjust
);

#endif //MEMORYLIB_FP_H

#ifndef    CRYPTUTIL_FP_H
#define    CRYPTUTIL_FP_H

//****************************************************************************
//**        Random Number Generation Functions
//****************************************************************************
//***  CryptStirRandom()
// Stir random entropy
#ifdef TPM_ALG_NULL //%
void
CryptStirRandom(
    UINT32               entropySize,       // IN: size of entropy buffer
    BYTE                *buffer             // IN: entropy buffer
);

//***  CryptGenerateRandom()
// This is the interface to _cpri__GenerateRandom.
UINT16
CryptGenerateRandom(
    UINT16               randomSize,        // IN: size of random number
    BYTE                *buffer             // OUT: buffer of random number
);

#endif //TPM_ALG_NULL //%

//****************************************************************************/
//**     Hash/HMAC Functions
//****************************************************************************/
//***  CryptGetContextAlg()
// This function returns the hash algorithm associated with a hash context.
#ifdef TPM_ALG_KEYEDHASH        //% 1
TPM_ALG_ID
CryptGetContextAlg(
    void                *state              // IN: the context to check
);

//***  CryptStartHash()
//   This function starts a hash and return the size, in bytes, of the digest.
//
//   return type: UINT16
//      > 0     the digest size of the algorithm
//      = 0     the hashAlg was TPM_ALG_NULL
UINT16
CryptStartHash(
    TPMI_ALG_HASH        hashAlg,           // IN: hash algorithm
    HASH_STATE          *hashState          // OUT: the state of hash stack. It
                                            //      will be used in hash update
                                            //      and completion
);

//*** CryptStartHashSequence()
// Start a hash stack for a sequence object and return the size, in bytes, of the
// digest. This call uses the form of the hash state that requires context save
// and restored.
//
//   return type: UINT16
//      > 0     the digest size of the algorithm
//      = 0     the hashAlg was TPM_ALG_NULL
UINT16
CryptStartHashSequence(
    TPMI_ALG_HASH        hashAlg,           // IN: hash algorithm
    HASH_STATE          *hashState          // OUT: the state of hash stack. It
                                            //      will be used in hash update
                                            //      and completion
);

//***  CryptStartHMAC()
// This function starts an HMAC sequence and returns the size of the digest
// that will be produced.
//
// The caller must provide a block of memory in which the hash sequence state
// is kept.  The caller should not alter the contents of this buffer until the
// hash sequence is completed or abandoned.
//
//   return type: UINT16
//      > 0     the digest size of the algorithm
//      = 0     the hashAlg was TPM_ALG_NULL
UINT16
CryptStartHMAC(
    TPMI_ALG_HASH        hashAlg,           // IN: hash algorithm
    UINT16               keySize,           // IN: the size of HMAC key in bytes
    BYTE                *key,               // IN: HMAC key
    HMAC_STATE          *hmacState          // OUT: the state of HMAC stack. It
                                            //      will be used in HMAC update
                                            //      and completion
);

//*** CryptStartHMACSequence()
// This function starts an HMAC sequence and returns the size of the digest
// that will be produced.
//
// The caller must provide a block of memory in which the hash sequence state
// is kept.  The caller should not alter the contents of this buffer until the
// hash sequence is completed or abandoned.
//
// This call is used to start a sequence HMAC that spans multiple TPM commands.
//
//   return type: UINT16
//      > 0     the digest size of the algorithm
//      = 0     the hashAlg was TPM_ALG_NULL
UINT16
CryptStartHMACSequence(
    TPMI_ALG_HASH        hashAlg,           // IN: hash algorithm
    UINT16               keySize,           // IN: the size of HMAC key in bytes
    BYTE                *key,               // IN: HMAC key
    HMAC_STATE          *hmacState          // OUT: the state of HMAC stack. It
                                            //      will be used in HMAC update
                                            //      and completion
);

//*** CryptStartHMAC2B()
// This function starts an HMAC and returns the size of the digest
// that will be produced.
//
// This function is provided to support the most common use of starting an HMAC
// with a TPM2B key.
//
// The caller must provide a block of memory in which the hash sequence state
// is kept.  The caller should not alter the contents of this buffer until the
// hash sequence is completed or abandoned.
//
//  return type: UINT16
//      > 0     the digest size of the algorithm
//      = 0     the hashAlg was TPM_ALG_NULL
UINT16
CryptStartHMAC2B(
    TPMI_ALG_HASH        hashAlg,           // IN: hash algorithm
    TPM2B               *key,               // IN: HMAC key
    HMAC_STATE          *hmacState          // OUT: the state of HMAC stack. It
                                            //      will be used in HMAC update
                                            //      and completion
);

//*** CryptStartHMACSequence2B()
// This function starts an HMAC sequence and returns the size of the digest
// that will be produced.
//
// This function is provided to support the most common use of starting an HMAC
// with a TPM2B key.
//
// The caller must provide a block of memory in which the hash sequence state
// is kept.  The caller should not alter the contents of this buffer until the
// hash sequence is completed or abandoned.
//
// return type: UINT16
//      > 0     the digest size of the algorithm
//      = 0     the hashAlg was TPM_ALG_NULL
UINT16
CryptStartHMACSequence2B(
    TPMI_ALG_HASH        hashAlg,           // IN: hash algorithm
    TPM2B               *key,               // IN: HMAC key
    HMAC_STATE          *hmacState          // OUT: the state of HMAC stack. It
                                            //      will be used in HMAC update
                                            //      and completion
);

//*** CryptUpdateDigest()
// This function updates a digest (hash or HMAC) with an array of octets.
//
// This function can be used for both HMAC and hash functions so the
// 'digestState' is void so that either state type can be passed.
void
CryptUpdateDigest(
    void                *digestState,       // IN: the state of hash stack
    UINT32               dataSize,          // IN: the size of data
    BYTE                *data               // IN: data to be hashed
);

//*** CryptUpdateDigest2B()
// This function updates a digest (hash or HMAC) with a TPM2B.
//
// This function can be used for both HMAC and hash functions so the
// 'digestState' is void so that either state type can be passed.
void
CryptUpdateDigest2B(
    void                *digestState,       // IN: the digest state
    TPM2B               *bIn                // IN: 2B containing the data
);

//*** CryptUpdateDigestInt()
// This function is used to include an integer value to a hash stack. The function
// marshals the integer into its canonical form before calling CryptUpdateHash().
void
CryptUpdateDigestInt(
    void                *state,             // IN: the state of hash stack
    UINT32               intSize,           // IN: the size of 'intValue' in bytes
    void                *intValue           // IN: integer value to be hashed
);

//*** CryptCompleteHash()
// This function completes a hash sequence and returns the digest.
//
// This function can be called to complete either an HMAC or hash sequence.
// The state type determines if the context type is a hash or HMAC. If an HMAC,
// then the call is forwarded to CryptCompleteHash().
//
// If "digestSize" is smaller than the digest size of hash/HMAC algorithm, the
// most significant bytes of required size will be returned
//
// return type: UINT16
//      >=0     the number of bytes placed in 'digest'
UINT16
CryptCompleteHash(
    void                *state,             // IN: the state of hash stack
    UINT16               digestSize,        // IN: size of digest buffer
    BYTE                *digest             // OUT: hash digest
);

//*** CryptCompleteHash2B()
// This function is the same as CypteCompleteHash() but the digest is
// placed in a TPM2B. This is the most common use and this is provided
// for specification clarity. 'digst.size' should be set to indicate the number of
// bytes to place in the buffer
//   return type: UINT16
//      >=0     the number of bytes placed in 'digest.buffer'
UINT16
CryptCompleteHash2B(
    void                *state,             // IN: the state of hash stack
    TPM2B               *digest             // IN: the size of the buffer
                                            // Out: requested number of bytes
);

//*** CryptHashBlock()
// Hash a block of data and return the results. If the digest is larger than
// 'retSize', it is truncated and with the least significant octets dropped.
//   return type: UINT16
//      >=0     the number of bytes placed in 'ret'
UINT16
CryptHashBlock(
    TPM_ALG_ID           algId,             // IN: the hash algorithm to use
    UINT16               blockSize,         // IN: size of the data block
    BYTE                *block,             // IN: address of the block to hash
    UINT16               retSize,           // IN: size of the return buffer
    BYTE                *ret                // OUT: address of the buffer
);

//*** CryptCompleteHMAC()
//   This function completes a HMAC sequence and returns the digest.
//   If 'digestSize' is smaller than the digest size of the HMAC algorithm, the
//   most significant bytes of required size will be returned.
//   return type: UINT16
//      >=0     the number of bytes placed in 'digest'
UINT16
CryptCompleteHMAC(
    HMAC_STATE          *hmacState,         // IN: the state of HMAC stack
    UINT32               digestSize,        // IN: size of digest buffer
    BYTE                *digest             // OUT: HMAC digest
);

//*** CryptCompleteHMAC2B()
//   This function is the same as CryptCompleteHMAC() but the HMAC result
//   is returned in a TPM2B which is the most common use.
//   return type: UINT16
//      >=0     the number of bytes placed in 'digest'
UINT16
CryptCompleteHMAC2B(
    HMAC_STATE          *hmacState,         // IN: the state of HMAC stack
    TPM2B               *digest             // OUT: HMAC
);

//*** CryptGetHashDigestSize()
// This function returns the digest size in bytes for a hash algorithm.
//  return type: UINT16
//    0         digest size for TPM_ALG_NULL
//   > 0        digest size
UINT16
CryptGetHashDigestSize(
    TPM_ALG_ID           hashAlg            // IN: hash algorithm
);

//*** CryptGetHashBlockSize()
// Get the digest size in byte of a hash algorithm.
//  return type: UINT16
//    0         block size for TPM_ALG_NULL
//   > 0        block size
UINT16
CryptGetHashBlockSize(
    TPM_ALG_ID           hash               // IN: hash algorithm to look up
);

//*** CryptGetHashAlgByIndex()
// This function is used to iterate through the hashes. TPM_ALG_NULL
// is returned for all indexes that are not valid hashes.
// If the TPM implements 3 hashes, then an 'index' value of 0 will
// return the first implemented hash and an 'index' value of 2 will return the
// last implemented hash. All other index values will return TPM_ALG_NULL.
//
// return type: TPM_ALG_ID
//  TPM_ALG_xxx         a hash algorithm
//  TPM_ALG_NULL        this can be used as a stop value
TPM_ALG_ID
CryptGetHashAlgByIndex(
    UINT32      index       // IN: the index
);

#define CryptKDFa(hashAlg, key, label, contextU, contextV,   \
                  sizeInBits, keyStream, counterInOut)       \
        _cpri__KDFa(                                         \
                     ((TPM_ALG_ID)hashAlg),                  \
                     ((TPM2B *)key),                         \
                     ((const char *)label),                  \
                     ((TPM2B *)contextU),                    \
                     ((TPM2B *)contextV),                    \
                     ((UINT32)sizeInBits),                   \
                     ((BYTE *)keyStream),                    \
                     ((UINT32 *)counterInOut),               \
                     ((BOOL) FALSE)                          \
                    )

#define CryptKDFaOnce(hashAlg, key, label, contextU, contextV,   \
                      sizeInBits, keyStream, counterInOut)       \
        _cpri__KDFa(                                             \
                     ((TPM_ALG_ID)hashAlg),                      \
                     ((TPM2B *)key),                             \
                     ((const char *)label),                      \
                     ((TPM2B *)contextU),                        \
                     ((TPM2B *)contextV),                        \
                     ((UINT32)sizeInBits),                       \
                     ((BYTE *)keyStream),                        \
                     ((UINT32 *)counterInOut),                   \
                     ((BOOL) TRUE)                               \
                    )

//*** KDFa()
// This function is used by functions outside of CryptUtil to access _cpri_KDFa.
void
KDFa(
    TPM_ALG_ID           hash,              // IN: hash algorithm used in HMAC
    TPM2B               *key,               // IN: HMAC key
    const char          *label,             // IN: a null-terminated label for KDF
    TPM2B               *contextU,          // IN: context U
    TPM2B               *contextV,          // IN: context V
    UINT32               sizeInBits,        // IN: size of generated key in bits
    BYTE                *keyStream,         // OUT: key buffer
    UINT32              *counterInOut       // IN/OUT: caller may provide the
                                            //         iteration counter for
                                            //         incremental operations to
                                            //         avoid large intermediate
                                            //         buffers.
);

#define CryptKDFe(hashAlg, Z, label, partyUInfo, partyVInfo,         \
                  sizeInBits, keyStream)                             \
 _cpri__KDFe(                                                        \
             ((TPM_ALG_ID)hashAlg),                                  \
             ((TPM2B *)Z),                                           \
             ((const char *)label),                                  \
             ((TPM2B *)partyUInfo),                                  \
             ((TPM2B *)partyVInfo),                                  \
             ((UINT32)sizeInBits),                                   \
             ((BYTE *)keyStream)                                     \
             )

#endif //TPM_ALG_KEYEDHASH    //% 1

#ifdef TPM_ALG_RSA          //% 2

//*** CryptTestKeyRSA()
// This function provides the interface to _cpri__TestKeyRSA().
// If both 'p' and 'q' are provided, 'n' will be set to 'p'*'q'.
//
// If only 'p' is provided, 'q' is computed by 'q' = 'n'/'p'. If 'n' mod 'p' != 0,
// TPM_RC_BINDING is returned.
//
// The key is validated by checking that a 'd' can be found such that
// 'e' 'd' mod (('p'-1)*('q'-1)) = 1. If 'd' is found that satisfies this
// requirement, it will be placed in 'd'.
//
// return type: TPM_RC
//  TPM_RC_BINDING          the public and private portions of the key are not
//                          matched
TPM_RC
CryptTestKeyRSA(
    TPM2B               *d,                 // OUT: receives the private exponent
    UINT32               e,                 // IN: public exponent
    TPM2B               *n,                 // IN/OUT: public modulus
    TPM2B               *p,                 // IN: a first prime
    TPM2B               *q                  // IN: an optional second prime
);

//*** CryptLoadPrivateRSA()
// This function is called to generate the private exponent of an RSA key. It
// uses CryptTestKeyRSA().
//
// return type: TPM_RC
//  TPM_RC_BINDING      public and private parts of 'rsaKey' are not matched
TPM_RC
CryptLoadPrivateRSA(
    OBJECT      *rsaKey     // IN: the RSA key object
);

//*** CryptSelectRSAScheme()
// This function is used by TPM2_RSA_Decrypt and TPM2_RSA_Encrypt.  It sets up
// the rules to select a scheme between input and object default.
// This function assume the RSA object is loaded.
// If a default scheme is defined in object, the default scheme should be chosen,
// otherwise, the input scheme should be chosen.
// In the case that both the object and 'scheme' are not TPM_ALG_NULL, then
// if the schemes are the same, the input scheme will be chosen.
// if the scheme are not compatible, a NULL pointer will be returned.
//
// The return pointer may point to a TPM_ALG_NULL scheme.
TPMT_RSA_DECRYPT*
CryptSelectRSAScheme(
    OBJECT              *rsaObject,         // IN: handle of sign key
    TPMT_RSA_DECRYPT    *scheme             // IN: a sign or decrypt scheme
);

//*** CryptDecryptRSA()
// This function is the interface to _cpri__DecryptRSA(). It handles
// the return codes from that function and converts them from CRYPT_RESULT
// to TPM_RC values. The "rsaKey" parameter must reference an RSA decryption key
//
// return type: TPM_RC
//   TPM_RC_BINDING              Public and private parts of the key are not
//                               cryptographically bound.
//   TPM_RC_SIZE                 Size of data to decrypt is not the same as the key
//                               size.
//   TPM_RC_VALUE                Numeric value of the encrypted data is greater than
//                               the public exponent, or output buffer is too small
//                               for the decrypted message.
TPM_RC
CryptDecryptRSA(
    UINT16              *dataOutSize,       // OUT: size of plain text in byte
    BYTE                *dataOut,           // OUT: plain text
    OBJECT              *rsaKey,            // IN: internal RSA key
    TPMT_RSA_DECRYPT    *scheme,            // IN: selects the padding scheme
    UINT16               cipherInSize,      // IN: size of cipher text  in byte
    BYTE                *cipherIn,          // IN: cipher text
    const char          *label              // IN: a label, when needed
);

//*** CryptEncryptRSA()
// This function provides the interface to _cpri__EncryptRSA().
// The object referenced by "rsaKey" is required to be an RSA decryption key.
// return type: TPM_RC
//   TPM_RC_SCHEME          'scheme' is not supported
//   TPM_RC_VALUE           numeric value of 'dataIn' is greater than the key
//                          modulus
TPM_RC
CryptEncryptRSA(
    UINT16              *cipherOutSize,     // OUT: size of cipher text in byte
    BYTE                *cipherOut,         // OUT: cipher text
    OBJECT              *rsaKey,            // IN: internal RSA key
    TPMT_RSA_DECRYPT    *scheme,            // IN: selects the padding scheme
    UINT16               dataInSize,        // IN: size of plain text in byte
    BYTE                *dataIn,            // IN: plain text
    const char          *label              // IN: an optional label
);

#endif //TPM_ALG_RSA      //% 2
#ifdef TPM_ALG_ECC //% 3

//*** CryptEccGetKeySizeInBits()
// This function returns the size in bits of the key associated with a curve.
UINT16
CryptEccGetKeySizeInBits(
    TPM_ECC_CURVE            curveID     // IN: id of the curve
);

// The next lines will be placed in CyrptUtil_fp.h with the //% removed
 #define CryptEccGetKeySizeInBytes(curve)            \
             ((CryptEccGetKeySizeInBits(curve)+7)/8)

//*** CryptEccGetParameter()
// This function returns a pointer to an ECC curve parameter. The parameter is
// selected by a single character designator from the set of {}.
const TPM2B *
CryptEccGetParameter(
    char                 p,                 // IN: the parameter selector
    TPM_ECC_CURVE        curveId            // IN: the curve id
);

//*** CryptGetCurveSignScheme()
// This function will return a pointer to the scheme of the curve.
const TPMT_ECC_SCHEME *
CryptGetCurveSignScheme(
    TPM_ECC_CURVE        curveId             // IN: The curve selector
    );

//*** CryptEccIsPointOnCurve()
// This function will validate that an ECC point is on the curve of given curveID.
//
// return type: BOOL
//      TRUE           if the point is on curve
//      FALSE          if the point is not on curve
BOOL
CryptEccIsPointOnCurve(
    TPM_ECC_CURVE        curveID,           // IN: ECC curve ID
    TPMS_ECC_POINT      *Q                  // IN: ECC point
);

//*** CryptNewEccKey()
// This function creates a random ECC key that is not derived from other
// parameters as is a Primary Key.
TPM_RC
CryptNewEccKey(
    TPM_ECC_CURVE        curveID,           // IN: ECC curve
    TPMS_ECC_POINT      *publicPoint,       // OUT: public point
    TPM2B_ECC_PARAMETER *sensitive          // OUT: private area
);

//*** CryptEccPointMultiply()
// This function is used to perform a point multiply 'R' = ['d']'Q'.
// If 'Q' is not provided, the multiplication is performed using the generator
// point of the curve.
//
// return type: TPM_RC
//   TPM_RC_ECC_POINT       invalid optional ECC point 'pIn'
//   TPM_RC_NO_RESULT       multiplication resulted in a point at infinity
TPM_RC
CryptEccPointMultiply(
    TPMS_ECC_POINT      *pOut,              // OUT: output point
    TPM_ECC_CURVE        curveId,           // IN: curve selector
    TPM2B_ECC_PARAMETER *dIn,               // IN: public scalar
    TPMS_ECC_POINT      *pIn                // IN: optional point
);

//*** CryptGenerateR()
// This function computes the commit random value for a split signing scheme.
//
// If 'c' is NULL, it indicates that 'r' is being generated
// for TPM2_Commit.
// If 'c' is not NULL, the TPM will validate that the gr.commitArray
// bit associated with the input value of 'c' is SET. If not, the TPM
// returns FALSE and no 'r' value is generated.
//  return type:    BOOL
//  TRUE            r value computed
//  FALSE           no r value computed
BOOL
CryptGenerateR(
    TPM2B_ECC_PARAMETER *r,                 // OUT: the generated random value
    UINT16              *c,                 // IN/OUT: count value.
    TPMI_ECC_CURVE       curveID,           // IN: the curve for the value
    TPM2B_NAME          *name               // IN: optional name of a key to
                                            //     associate with 'r'
);

//*** CryptCommit()
// This function is called when the count value is committed. The gr.commitArray
// value associated with the current count value is SET and g_commitCounter is
// incremented. The low-order 16 bits of old value of the counter is returned.
UINT16
CryptCommit(
    void
);

//*** CryptEndCommit()
// This function is called when the signing operation using the committed value
// is completed. It clears the gr.commitArray bit associated with the count
// value so that it can't be used again.
void
CryptEndCommit(
    UINT16               c              // IN: the counter value of the commitment
);

//*** CryptCommitCompute()
// This function performs the computations for the TPM2_Commit command.
// This could be a macro.
// return type: TPM_RC
//   TPM_RC_NO_RESULT       'K', 'L', or 'E' is the point at infinity
//   TPM_RC_CANCELLED       command was cancelled
TPM_RC
CryptCommitCompute(
    TPMS_ECC_POINT      *K,                 // OUT: [d]B
    TPMS_ECC_POINT      *L,                 // OUT: [r]B
    TPMS_ECC_POINT      *E,                 // OUT: [r]M
    TPM_ECC_CURVE        curveID,           // IN: The curve for the computations
    TPMS_ECC_POINT      *M,                 // IN: M (P1)
    TPMS_ECC_POINT      *B,                 // IN: B (x2, y2)
    TPM2B_ECC_PARAMETER *d,                 // IN: the private scalar
    TPM2B_ECC_PARAMETER *r                  // IN: the computed r value
);

//*** CryptEccGetParameters()
// This function returns the ECC parameter details of the given curve
// return type: BOOL
//      TRUE            Get parameters success
//      FALSE           Unsupported ECC curve ID
BOOL
CryptEccGetParameters(
    TPM_ECC_CURVE                curveId,     // IN: ECC curve ID
    TPMS_ALGORITHM_DETAIL_ECC   *parameters // OUT: ECC parameters
);

// CryptEcc2PhaseKeyExchange()
// This is the interface to the key exchange funciton.
TPM_RC
CryptEcc2PhaseKeyExchange(
    TPMS_ECC_POINT          *outZ1,         // OUT: the computed point
    TPMS_ECC_POINT          *outZ2,         // OUT: optional second point
    TPM_ALG_ID               scheme,        // IN: the key exchange scheme
    TPM_ECC_CURVE            curveId,       // IN: the curve for the computations
    TPM2B_ECC_PARAMETER     *dsA,           // IN: static private TPM key
    TPM2B_ECC_PARAMETER     *deA,           // IN: ephemeral private TPM key
    TPMS_ECC_POINT          *QsB,           // IN: static public party B key
    TPMS_ECC_POINT          *QeB            // IN: ephemeral public party B key
    );

#endif //TPM_ALG_ECC  //% 3

//*** CryptIsSchemeAnonymous()
// This function is used to test a scheme to see if it is an anonymous scheme
// The only anonymous scheme is ECDAA. ECDAA can be used to do things
// like U-Prove.
BOOL
CryptIsSchemeAnonymous(
    TPM_ALG_ID           scheme             // IN: the scheme algorithm to test
);

//*** ParmDecryptSym()
//  This function performs parameter decryption using symmetric block cipher.
void
ParmDecryptSym(
    TPM_ALG_ID           symAlg,            // IN: the symmetric algorithm
    TPM_ALG_ID           hash,              // IN: hash algorithm for KDFa
    UINT16               keySizeInBits,     // IN: key key size in bits
    TPM2B               *key,               // IN: KDF HMAC key
    TPM2B               *nonceCaller,       // IN: nonce caller
    TPM2B               *nonceTpm,          // IN: nonce TPM
    UINT32               dataSize,          // IN: size of parameter buffer
    BYTE                *data               // OUT: buffer to be decrypted
);

//*** ParmEncryptSym()
//  This function performs parameter encryption using symmetric block cipher.
void
ParmEncryptSym(
    TPM_ALG_ID           symAlg,            // IN: symmetric algorithm
    TPM_ALG_ID           hash,              // IN: hash algorithm for KDFa
    UINT16               keySizeInBits,     // IN: AES key size in bits
    TPM2B               *key,               // IN: KDF HMAC key
    TPM2B               *nonceCaller,       // IN: nonce caller
    TPM2B               *nonceTpm,          // IN: nonce TPM
    UINT32               dataSize,          // IN: size of parameter buffer
    BYTE                *data               // OUT: buffer to be encrypted
);

//*** CryptXORObfuscation()
// This function implements XOR obfuscation. It should not be called if the
// hash algorithm is not implemented. The only return value from this function
// is TPM_RC_SUCCESS.
#ifdef TPM_ALG_KEYEDHASH //% 5
void
CryptXORObfuscation(
    TPM_ALG_ID           hash,              // IN: hash algorithm for KDF
    TPM2B               *key,               // IN: KDF key
    TPM2B               *contextU,          // IN: contextU
    TPM2B               *contextV,          // IN: contextV
    UINT32               dataSize,          // IN: size of data buffer
    BYTE                *data               // IN/OUT: data to be XORed in place
);

#endif //TPM_ALG_KEYED_HASH //%5

//*** CryptInitUnits()
// This function is called when the TPM receives a _TPM_Init indication. After
// function returns, the hash algorithms should be available.
//
// NOTE: The hash algorithms do not have to be tested, they just need to be
// available. They have to be tested before the TPM can accept HMAC authorization
// or return any result that relies on a hash algorithm.
//
void
CryptInitUnits(void);

//*** CryptStopUnits()
// This function is only used in a simulated environment. There should be no
// reason to shut down the cryptography on an actual TPM other than loss of power.
// After receiving TPM2_Startup(), the TPM should be able to accept commands
// until it loses power and, unless the TPM is in Failure Mode, the cryptographic
// algorithms should be available.
void
CryptStopUnits(void);

//*** CryptUtilStartup()
// This function is called by TPM2_Startup() to initialize the functions in
// this crypto library and in the provided CryptoEngine. In this implementation,
// the only initialization required in this library is initialization of the
// Commit nonce on TPM Reset.
//
// This function returns false if some problem prevents the functions from
// starting correctly. The TPM should go into failure mode.
BOOL
CryptUtilStartup(
    STARTUP_TYPE         type               // IN: the startup type
);

//****************************************************************************
//** Algorithm-Independent Functions
//****************************************************************************
//*** Introduction
// These functions are used generically when a function of a general type
// (e.g., symmetric encryption) is required.  The functions will modify the
// parameters as required to interface to the indicated algorithms.
//
//*** CryptIsAsymAlgorithm()
// This function indicates if an algorithm is an asymmetric algorithm.
// return type: BOOL
//      TRUE           if it is an asymmetric algorithm
//      FALSE          if it is not an asymmetric algorithm
BOOL
CryptIsAsymAlgorithm(
    TPM_ALG_ID           algID              // IN: algorithm ID
);

//*** CryptGetSymmetricBlockSize()
// This function returns the size in octets of the symmetric encryption block
// used by an algorithm and key size combination.
INT16
CryptGetSymmetricBlockSize(
    TPMI_ALG_SYM         algorithm,         // IN: symmetric algorithm
    UINT16               keySize            // IN: key size in bit
);

//*** CryptSymmetricEncrypt()
// This function does in-place encryption of a buffer using the indicated
// symmetric algorithm, key, IV, and mode. If the symmetric algorithm
// and mode are not defined, the TPM will fail.
void
CryptSymmetricEncrypt(
    BYTE                *encrypted,         // OUT: the encrypted data
    TPM_ALG_ID           algorithm,         // IN: algorithm for encryption
    UINT16               keySizeInBits,     // IN: key size in bits
    TPMI_ALG_SYM_MODE    mode,              // IN: symmetric encryption mode
    BYTE                *key,               // IN: encryption key
    TPM2B_IV            *ivIn,              // IN/OUT: Input IV and output chaining
                                            //         value for the next block
    UINT32               dataSize,          // IN: data size in byte
    BYTE*                data               // IN/OUT: data buffer
);

//*** CryptSymmetricDecrypt()
// This function does in-place decryption of a buffer using the indicated
// symmetric algorithm, key, IV, and mode. If the symmetric algorithm
// and mode are not defined, the TPM will fail.
void
CryptSymmetricDecrypt(
    BYTE                *decrypted,
    TPM_ALG_ID           algorithm,         // IN: algorithm for encryption
    UINT16               keySizeInBits,     // IN: key size in bits
    TPMI_ALG_SYM_MODE    mode,              // IN: symmetric encryption mode
    BYTE                *key,               // IN: encryption key
    TPM2B_IV            *ivIn,              // IN/OUT: IV for next block
    UINT32               dataSize,          // IN: data size in byte
    BYTE*                data               // IN/OUT: data buffer
);

//*** CryptSecretEncrypt()
// This function creates a secret value and its associated secret structure using
// an asymmetric algorithm.
//
// This function is used by TPM2_MakeCredential().
// return type: TPM_RC
//   TPM_RC_ATTRIBUTES      'keyHandle' does not reference a valid decryption key
//   TPM_RC_KEY             invalid ECC key (public point is not on the curve)
//   TPM_RC_SCHEME          RSA key with an unsupported padding scheme
//   TPM_RC_VALUE           numeric value of the data to be decrypted is greater
//                          than the RSA key modulus
TPM_RC
CryptSecretEncrypt(
    OBJECT                  *encryptKey, // IN: encryption key
    const char              *label,      // IN: a null-terminated string as L
    TPM2B_DATA              *data,       // OUT: secret value
    TPM2B_ENCRYPTED_SECRET  *secret      // OUT: secret structure
);

//*** CryptSecretDecrypt()
// Decrypt a secret value by asymmetric (or symmetric) algorithm
// This function is used for ActivateCredential and Import for asymmetric
// decryption, and StartAuthSession for both asymmetric and symmetric
// decryption process
//
// return type: TPM_RC
//   TPM_RC_ATTRIBUTES           RSA key is not a decryption key
//   TPM_RC_BINDING              Invalid RSA key (public and private parts are not
//                               cryptographically bound.
//   TPM_RC_ECC_POINT            ECC point in the secret is not on the curve
//   TPM_RC_INSUFFICIENT         failed to retrieve ECC point from the secret
//   TPM_RC_NO_RESULT            multiplication resulted in ECC point at infinity
//   TPM_RC_SIZE                 data to decrypt is not of the same size as RSA key
//   TPM_RC_VALUE                For RSA key, numeric value of the encrypted data is
//                               greater than the modulus, or the recovered data is
//                               larger than the output buffer.
//                               For keyedHash or symmetric key, the secret is
//                               larger than the size of the digest produced by
//                               the name algorithm.
//   TPM_RC_FAILURE              internal error
TPM_RC
CryptSecretDecrypt(
    TPM_HANDLE              tpmKey,         // IN: decrypt key
    TPM2B_NONCE            *nonceCaller,    // IN: nonceCaller.  It is needed for
                                            //     symmetric decryption.  For
                                            //     asymmetric decryption, this
                                            //     parameter is NULL
    const char              *label,         // IN: a null-terminated string as L
    TPM2B_ENCRYPTED_SECRET  *secret,        // IN: input secret
    TPM2B_DATA              *data           // OUT: decrypted secret value
);

//*** CryptParameterEncryption()
// This function does in-place encryption of a response parameter.
void
CryptParameterEncryption(
    SESSION             *session,           // IN: encrypt session handle
    TPM2B               *nonceCaller,       // IN: nonce caller
    UINT16               leadingSizeInByte, // IN: the size of the leading size
                                            //     field in bytes
    TPM2B_AUTH          *extraKey,          // IN: additional key material other
                                            //     than session auth
    BYTE                *buffer             // IN/OUT: parameter buffer to be
                                            //         encrypted
);

//*** CryptParameterDecryption()
// This function does in-place decryption of a command parameter.
// return type: TPM_RC
//  TPM_RC_SIZE             The number of bytes in the input buffer is less than
//                          the number of bytes to be decrypted.
TPM_RC
CryptParameterDecryption(
    SESSION             *session,           // IN: encrypted session handle
    TPM2B               *nonceCaller,       // IN: nonce caller
    UINT32               bufferSize,        // IN: size of parameter buffer
    UINT16               leadingSizeInByte, // IN: the size of the leading size
                                            //     field in byte
    TPM2B_AUTH          *extraKey,          // IN: the authValue
    BYTE                *buffer             // IN/OUT: parameter buffer to be
                                            //         decrypted
);

//*** CryptComputeSymmetricUnique()
// This function computes the unique field in public area for symmetric objects.
void
CryptComputeSymmetricUnique(
    TPMI_ALG_HASH        nameAlg,           // IN: object name algorithm
    TPMT_SENSITIVE      *sensitive,         // IN: sensitive area
    TPM2B_DIGEST        *unique             // OUT: unique buffer
);

//*** CryptComputeSymValue()
// This function computes the seedValue field in sensitive.  It contains the
// obfuscation value for symmetric object and a seed value for storage key.
void
CryptComputeSymValue(
    TPM_HANDLE           parentHandle,      // IN: parent handle of the
                                            // object to be created
    TPMT_PUBLIC         *publicArea,        // IN/OUT: the public area template
    TPMT_SENSITIVE      *sensitive,         // IN: sensitive area
    TPM2B_SEED          *seed,              // IN: the seed
    TPMI_ALG_HASH        hashAlg,           // IN: hash algorithm for KDFa
    TPM2B_NAME          *name               // IN: object name
);

//*** CryptCreateObject()
// This function creates an object. It:
//      1. fills in the created key in public and sensitive area;
//      2. creates a random number in sensitive area for symmetric keys; and
//      3. compute the unique id in public area for symmetric keys.
//
// return type: TPM_RC
//   TPM_RC_KEY_SIZE        key size in the public area does not match the size
//                          in the sensitive creation area for a symmetric key
//   TPM_RC_RANGE           for an RSA key, the exponent is not supported
//   TPM_RC_SIZE            sensitive data size is larger than allowed for the
//                          scheme for a keyed hash object
//   TPM_RC_VALUE           exponent is not prime or could not find a prime using
//                          the provided parameters for an RSA key;
//                          unsupported name algorithm for an ECC key
TPM_RC
CryptCreateObject(
    ANY_OBJECT              *parent,            // IN/OUT: indication of the
                                                //         seed source
    TPMT_PUBLIC             *publicArea,        // IN/OUT: public area
    TPMS_SENSITIVE_CREATE   *sensitiveCreate,   // IN: sensitive creation
    TPMT_SENSITIVE          *sensitive          // OUT: sensitive area
);

//*** CryptObjectIsPublicConsistent()
// This function checks that the key sizes in the public area are consistent.
// For an asymmetric key, the size of the public key must match the
// size indicated by the public->parameters.
//
// Checks for the algorithm types matching the key type are handled by the
// unmarshaling operation.
//
// return type: BOOL
//      TRUE            sizes are consistent
//      FALSE           sizes are not consistent
BOOL
CryptObjectIsPublicConsistent(
    TPMT_PUBLIC         *publicArea          // IN: public area
);

//*** CryptObjectPublicPrivateMatch()
// This function checks the cryptographic binding between the public
// and sensitive areas.
// return type: TPM_RC
//      TPM_RC_TYPE         the type of the public and private areas are not the
//                          same
//      TPM_RC_FAILURE      crypto error
//      TPM_RC_BINDING      the public and private areas are not cryptographically
//                          matched.
TPM_RC
CryptObjectPublicPrivateMatch(
    OBJECT              *object     // IN: the object to check
);

//*** CryptGetSignHashAlg()
// Get the hash algorithm of signature from a TPMT_SIGNATURE structure.
// It assumes the signature is not NULL
//  This is a function for easy access
TPMI_ALG_HASH
CryptGetSignHashAlg(
    TPMT_SIGNATURE      *auth               // IN: signature
);

//*** CryptIsSplitSign()
// This function us used to determine if the signing operation is a split
// signing operation that required a TPM2_Commit().
//
BOOL
CryptIsSplitSign(
    TPM_ALG_ID           scheme             // IN: the algorithm selector
);

//*** CryptIsSignScheme()
// This function indicates if a scheme algorithm is a sign algorithm.
BOOL
CryptIsSignScheme(
    TPMI_ALG_ASYM_SCHEME    scheme
);

//*** CryptIsDecryptScheme()
// This function indicate if a scheme algorithm is a decrypt algorithm.
BOOL
CryptIsDecryptScheme(
    TPMI_ALG_ASYM_SCHEME    scheme
);

//*** CryptSelectSignScheme()
// This function is used by the attestation and signing commands.  It implements
// the rules for selecting the signature scheme to use in signing. This function
// requires that the signing key either be TPM_RH_NULL or be loaded.
//
// If a default scheme is defined in object, the default scheme should be chosen,
// otherwise, the input scheme should be chosen.
// In the case that  both object and input scheme has a non-NULL scheme
// algorithm, if the schemes are compatible, the input scheme will be chosen.
//
// return type: TPM_RC
//   TPM_RC_KEY             key referenced by 'signHandle' is not a signing key
//   TPM_RC_SCHEME          both 'scheme' and key's default scheme are empty; or
//                          'scheme' is empty while key's default scheme requires
//                          explicit input scheme (split signing); or
//                          non-empty default key scheme differs from 'scheme'
TPM_RC
CryptSelectSignScheme(
    TPMI_DH_OBJECT       signHandle,        // IN: handle of signing key
    TPMT_SIG_SCHEME     *scheme             // IN/OUT: signing scheme
);

//*** CryptSign()
// Sign a digest with asymmetric key or HMAC.
// This function is called by attestation commands and the generic TPM2_Sign
// command.
// This function checks the key scheme and digest size.  It does not
// check if the sign operation is allowed for restricted key.  It should be
// checked before the function is called.
// The function will assert if the key is not a signing key.
//
// return type: TPM_RC
//   TPM_RC_SCHEME          'signScheme' is not compatible with the signing key type
//   TPM_RC_VALUE           'digest' value is greater than the modulus of
//                          'signHandle' or size of 'hashData' does not match hash
//                          algorithm in'signScheme' (for an RSA key);

//                          invalid commit status or failed to generate "r" value
//                          (for an ECC key)
TPM_RC
CryptSign(
    TPMI_DH_OBJECT       signHandle,        // IN: The handle of sign key
    TPMT_SIG_SCHEME     *signScheme,        // IN: sign scheme.
    TPM2B_DIGEST        *digest,            // IN: The digest being signed
    TPMT_SIGNATURE      *signature          // OUT: signature
);

//*** CryptVerifySignature()
// This function is used to verify a signature.  It is called by
// TPM2_VerifySignature() and TPM2_PolicySigned.
//
// Since this operation only requires use of a public key, no consistency
// checks are necessary for the key to signature type because a caller can load
// any public key that they like with any scheme that they like. This routine
// simply makes sure that the signature is correct, whatever the type.
//
// This function requires that 'auth' is not a NULL pointer.
//
// return type: TPM_RC
//      TPM_RC_SIGNATURE            the signature is not genuine
//      TPM_RC_SCHEME               the scheme is not supported
TPM_RC
CryptVerifySignature(
    TPMI_DH_OBJECT       keyHandle,         // IN: The handle of sign key
    TPM2B_DIGEST        *digest,            // IN: The digest being validated
    TPMT_SIGNATURE      *signature          // IN: signature
);

TPM_RC
CryptDivide(
    TPM2B       *numerator,     // IN: numerator
    TPM2B       *denominator,   // IN: denominator
    TPM2B       *quotient,      // OUT: quotient = numerator / denominator.
    TPM2B       *remainder      // OUT: numerator mod denominator.
);

//*** CryptCompare()
// This function interfaces to the math library for large number, unsigned compare.
// return type: int
//      1         if a > b
//      0         if a = b
//      -1        if a < b
int
CryptCompare(
    const UINT32               aSize,             // IN: size of a
    const BYTE                *a,                 // IN: a buffer
    const UINT32               bSize,             // IN: size of b
    const BYTE                *b                  // IN: b buffer
);

//*** CryptCompareSigned()
// This function interfaces to the math library for large number, signed compare.
// return type: int
//      1         if a > b
//      0         if a = b
//      -1        if a < b
int
CryptCompareSigned(
    UINT32               aSize,             // IN: size of a
    BYTE                *a,                 // IN: a buffer
    UINT32               bSize,             // IN: size of b
    BYTE                *b                  // IN: b buffer
);

//*** CryptSelfTest
// This function is called to start a full self-test.
// Note: the behavior in this function is NOT the correct behavior for a real
// TPM implementation.  An artificial behavior is placed here due to the
// limitation of a software simulation environment.  For the correct behavior,
// consult the part 3 specification for TPM2_SelfTest().
// return type: TPM_RC
//      TPM_RC_TESTING          if fullTest is YES
TPM_RC
CryptSelfTest(
    TPMI_YES_NO          fullTest           // IN: if full test is required
);

//*** CryptIncrementalSelfTest
// This function is used to start an incremental self-test.
// return type: TPM_RC
//      TPM_RC_TESTING          if toTest list is not empty
TPM_RC
CryptIncrementalSelfTest(
    TPML_ALG            *toTest,            // IN: list of algorithms to be tested
    TPML_ALG            *toDoList           // OUT: list of algorithms needing test
);

//*** CryptGetTestResult
// This function returns the results of a self-test function.
// Note: the behavior in this function is NOT the correct behavior for a real
// TPM implementation.  An artificial behavior is placed here due to the
// limitation of a software simulation environment.  For the correct behavior,
// consult the part 3 specification for TPM2_GetTestResult().
TPM_RC
CryptGetTestResult(
    TPM2B_MAX_BUFFER    *outData            // OUT: test result data
);

//*** CryptCapGetECCCurve()
// This function returns the list of implemented ECC curves.
// return type: TPMI_YES_NO
//  YES        if no more ECC curve is available
//  NO         if there are more ECC curves not reported
#ifdef TPM_ALG_ECC //% 5
TPMI_YES_NO
CryptCapGetECCCurve(
    TPM_ECC_CURVE        curveID,           // IN: the starting ECC curve
    UINT32               maxCount,          // IN: count of returned curves
    TPML_ECC_CURVE      *curveList          // OUT: ECC curve list
);

//*** CryptCapGetEccCurveNumber()
// This function returns the number of ECC curves supported by the TPM.
UINT32
CryptCapGetEccCurveNumber(void);

#endif //TPM_ALG_ECC //% 5

//*** CryptAreKeySizesConsistent()
// This function validates that the public key size values are consistent for
// an asymmetric key.
// NOTE: This is not a comprehensive test of the public key.
//
//  return type: BOOL
//  TRUE        sizes are consistent
//  FALSE       sizes are not consistent
BOOL
CryptAreKeySizesConsistent(
    TPMT_PUBLIC         *publicArea         // IN: the public area to check
);

#endif //CRYPTUTIL_FP_H

#ifndef _CRYPT_PRI_H
#define _CRYPT_PRI_H

#ifndef NULL
#define NULL    0
#endif

typedef UINT16  NUMBYTES;       // When a size is a number of bytes
typedef UINT32  NUMDIGITS;      // When a size is a number of "digits"

extern  UINT32     g_entropySize;
extern  BYTE       g_entropy[];


//*** General Purpose Macros

#ifndef MAX
#   define MAX(a, b) ((a) > (b) ? (a) : b)
#endif

//*** Hash-related Structures

typedef struct {
    TPM_ALG_ID      alg;
    NUMBYTES        digestSize;
    NUMBYTES        blockSize;
    NUMBYTES        derSize;
    BYTE            der[20];
} HASH_INFO;

// This value will change with each implementation. The value of 16 is used to
// account for any slop in the context values. The overall size needs to be as large
// as any of the hash contexts plus the value of the hashAlg ID.
#define MAX_HASH_STATE_SIZE ((2 * TPM_MAX_HASH_BLOCK_SIZE) + 16)
//#define HASH_STATE_SIZE   ((MAX_HASH_STATE_SIZE + sizeof(UINT64) - 1)/sizeof(UINT64))

// This is an array that will hold any of the hash contexts. It is defined as an
// array of 8-octet values so that the compiler will align the structure.
typedef UINT64  HASH_STATE_ARRAY[(MAX_HASH_STATE_SIZE + 15)/8];

// Struct member alignment tweak necessary to ensure CPRI_HASH_STATE structure
// compatibility with underlying crypto libraries
#ifndef CPRI_ALIGN
#   define CPRI_ALIGN
#endif

//typedef union
//{
//    CPRI_ALIGN HASH_STATE_ARRAY    data;
//} ALIGNED_HASH_STATE_ARRAY, *PALIGNED_HASH_STATE_ARRAY;

// This is the structure that is used for passing a context into the hashing 
// funcitons. It should be the same size as the function context used within
// the hashing functions. This is checked when the hash function is initialized.
// This version uses a new layout for the contexts and a different definition. The
// state buffer is an array of 8-byte values so that a decent compiler will put the
// structure on an 8-byte boundary. If the structure is not properly aligned, the
// code that manipulates the structure will copy to a properly aligned structure
// before it is used and copy the result back. This just makes things slower.
//typedef struct _HASH_STATE
//{
//    ALIGNED_HASH_STATE_ARRAY    state;
//    TPM_ALG_ID           hashAlg;
//} CPRI_HASH_STATE, *PCPRI_HASH_STATE;

extern const HASH_INFO   g_hashData[HASH_COUNT + 1];

//***Asymmetric Structures and Values

#ifdef TPM_ALG_ECC


//*** ECC-related Structures

// This structure replicates the structure definition in TPM_Types.h. It is
// duplicated to avoid inclusion of all of TPM_Types.h

// This structure is similar to the RSA_KEY structure below. The purpose of these 
// structures is to reduce the overhead of a function call and to make the code
// less dependent on key types as much as possible.
typedef struct {
    UINT32                 curveID;       // The curve identifier
    TPMS_ECC_POINT        *publicPoint;   // Pointer to the public point
    TPM2B                 *privateKey;    // Pointer to the private key
} ECC_KEY;

#endif // TPM_ALG_ECC

#ifdef TPM_ALG_RSA
//*** RSA-related Structures

// This structure is a succinct representation of the cryptographic components
// of an RSA key. 
typedef struct {
    UINT32        exponent;      // The public exponent pointer
    TPM2B        *publicKey;     // Pointer to the public modulus
    TPM2B        *privateKey;    // The private exponent (not a prime)
} RSA_KEY;

#endif // TPM_ALG_RSA


#ifdef TPM_ALG_RSA
#   ifdef TPM_ALG_ECC
#       if   MAX_RSA_KEY_BYTES > MAX_ECC_KEY_BYTES
#           define  MAX_NUMBER_SIZE         MAX_RSA_KEY_BYTES
#       else
#           define  MAX_NUMBER_SIZE         MAX_ECC_KEY_BYTES    
#       endif
#   else // RSA but no ECC
#       define MAX_NUMBER_SIZE              MAX_RSA_KEY_BYTES
#   endif
#elif defined TPM_ALG_ECC
#   define MAX_NUMBER_SIZE                 MAX_ECC_KEY_BYTES
#else
#   error No assymmetric algorithm implemented.
#endif

typedef INT16     CRYPT_RESULT;

#define CRYPT_RESULT_MIN    INT16_MIN
#define CRYPT_RESULT_MAX    INT16_MAX

//      < 0         recoverable error
//       0          success
//       > 0       command specific return value (generally a digest size)
#define CRYPT_FAIL          ((CRYPT_RESULT)  1)
#define CRYPT_SUCCESS       ((CRYPT_RESULT)  0)
#define CRYPT_NO_RESULT     ((CRYPT_RESULT) -1)
#define CRYPT_SCHEME        ((CRYPT_RESULT) -2)
#define CRYPT_PARAMETER     ((CRYPT_RESULT) -3)
#define CRYPT_UNDERFLOW     ((CRYPT_RESULT) -4)
#define CRYPT_POINT         ((CRYPT_RESULT) -5)
#define CRYPT_CANCEL        ((CRYPT_RESULT) -6)

typedef UINT64              HASH_CONTEXT[MAX_HASH_STATE_SIZE/sizeof(UINT64)];

#ifndef    CPRIRNG_FP_H
#define    CPRIRNG_FP_H

//****************************************************************************
//** Random Number Generation
//****************************************************************************
BOOL
_cpri__RngStartup(void);

//***_cpri__StirRandom()
// Set random entropy
CRYPT_RESULT
_cpri__StirRandom(
INT32      entropySize,
BYTE       *entropy
);

//***_cpri__GenerateRandom()
// Generate a 'randomSize' number or random bytes.
UINT16
_cpri__GenerateRandom(
INT32       randomSize,
BYTE       *buffer
);

#endif //CPRIRNG_FP_H

#ifndef    CPRIHASH_FP_H
#define    CPRIHASH_FP_H

//*** _cpri__HashStartup()
// Function that is called to initialize the hash service. In this implementation,
// this function does nothing but it is called by the CryptUtilStartup() function
// and must be present.
BOOL
_cpri__HashStartup(
void
);

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
);

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
);

//*** _cpri__GetHashDER
// This function returns a pointer to the DER string for the algorithm and
// indicates its size.
UINT16
_cpri__GetHashDER(
TPM_ALG_ID             hashAlg,    // IN: the algorithm to look up
const BYTE           **p
);

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
);

//*** _cpri__GetContextAlg()
// This function returns the algorithm associated with a hash context
TPM_ALG_ID
_cpri__GetContextAlg(
CPRI_HASH_STATE         *hashState  // IN: the hash context
);

//*** _cpri__CopyHashState
// This function is used to "clone" a CPRI_HASH_STATE.
// The return value is the size of the state.
UINT16
_cpri__CopyHashState(
CPRI_HASH_STATE    *out,       // OUT: destination of the state
CPRI_HASH_STATE    *in         // IN: source of the state
);

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
TPM_ALG_ID       hashAlg,       // IN: hash algorithm
BOOL             sequence,      // IN: TRUE if the state should be saved
CPRI_HASH_STATE *hashState      // OUT: the state of hash stack.
);

//*** _cpri__UpdateHash()
// Add data to a hash or HMAC stack.
//
void
_cpri__UpdateHash(
CPRI_HASH_STATE     *hashState,     // IN: the hash context information
UINT32               dataSize,      // IN: the size of data to be added to
//     the digest
BYTE                *data           // IN: data to be hashed
);

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
CPRI_HASH_STATE     *hashState,     // IN: the state of hash stack
UINT32               dOutSize,      // IN: size of digest buffer
BYTE                *dOut           // OUT: hash digest
);

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
TPM_ALG_ID   hashAlg,        // IN: The hash algorithm
UINT32       dataSize,       // IN: size of buffer to hash
BYTE        *data,           // IN: the buffer to hash
UINT32       digestSize,     // IN: size of the digest buffer
BYTE        *digest          // OUT: hash digest
);

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
);

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
);

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
BYTE       *mask,      // OUT: buffer to receive the mask
TPM_ALG_ID  hashAlg,   // IN: hash to use
UINT32      sSize,     // IN: size of the seed
BYTE       *seed       // IN: seed size
);

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
);

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
);

#endif //CPRIHASH_FP_H

#ifndef    CPRISYM_FP_H
#define    CPRISYM_FP_H

//** Utility Functions
//
//*** _cpri_SymStartup()
BOOL
_cpri__SymStartup(
void
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
);

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
);

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
BYTE       *iv,             // IN/OUT: IV for decryption. The size of
// this buffer if 16 byte.
UINT32      dInSize,        // IN: data size
BYTE       *dIn             // IN: data buffer
);

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
BYTE        *dOut,          // OUT: the encrypted
UINT32       keySizeInBits, // IN: key size in bit
BYTE        *key,           // IN: key buffer. The size of this buffer
//     in bytes is (keySizeInBits + 7) / 8
BYTE        *iv,            // IN/OUT: IV for decryption.
UINT32       dInSize,       // IN: data size
BYTE        *dIn            // IN/OUT: data buffer
);

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
BYTE        *dOut,          // OUT: the decrypted data
UINT32       keySizeInBits, // IN: key size in bit
BYTE        *key,           // IN: key buffer. The size of this buffer
//     in bytes is (keySizeInBits + 7) / 8
BYTE        *iv,            // IN/OUT: IV for decryption.
UINT32       dInSize,       // IN: data size
BYTE        *dIn            // IN/OUT: data buffer
);

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
BYTE        *dOut,          // OUT: the encrypted data
UINT32       keySizeInBits, // IN: key size in bits
BYTE        *key,           // IN: key buffer. The size of this buffer
//     in bytes is (keySizeInBits + 7) / 8
BYTE        *iv,            // IN/OUT: IV for decryption.
UINT32       dInSize,       // IN: data size
BYTE        *dIn            // IN: data buffer
);

#define _cpri__AESDecryptCTR(dOut, keySize, key, iv, dInSize, dIn) \
    _cpri__AESEncryptCTR(\
    ((BYTE *)dOut), \
    ((UINT32)keySize), \
    ((BYTE *)key), \
    ((BYTE *)iv), \
    ((UINT32)dInSize), \
    ((BYTE *)dIn)              \
    )

// The //% is used by the prototype extraction program to cause it to include the
// line in the prototype file after removing the //%.  Need an extra line with

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
);

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
);

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
BYTE        *dOut,          // OUT: the encrypted/decrypted data
UINT32       keySizeInBits, // IN: key size in bit
BYTE        *key,           // IN: key buffer. The size of this buffer
//     in bytes is (keySizeInBits + 7) / 8
BYTE        *iv,            // IN/OUT: IV for decryption. The size of
//     this buffer if 16 byte.
UINT32       dInSize,       // IN: data size
BYTE        *dIn            // IN: data buffer
);

#define _cpri__AESDecryptOFB(dOut,keySizeInBits, key, iv, dInSize, dIn) \
    _cpri__AESEncryptOFB(\
    ((BYTE *)dOut), \
    ((UINT32)keySizeInBits), \
    ((BYTE *)key), \
    ((BYTE *)iv), \
    ((UINT32)dInSize), \
    ((BYTE *)dIn)                  \
    )


#endif //CPRISYM_FP_H

#ifdef  TPM_ALG_RSA
#ifndef    CPRIRSA_FP_H
#define    CPRIRSA_FP_H

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
TPM2B           *d,         // OUT: the address to receive the private exponent
UINT32           exponent,  // IN: the public modulus
TPM2B           *publicKey, // IN/OUT: an input if only one prime is provided.
//         an output if both primes are provided
TPM2B           *prime1,    // IN: a first prime
TPM2B           *prime2     // IN: an optional second prime
);

//*** _cpri__RsaStartup()
// Function that is called to initialize the hash service. In this implementation,
// this function does nothing but it is called by the CryptUtilStartup() function
// and must be present.
BOOL
_cpri__RsaStartup(
void
);

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
);

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
);

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
);

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
);

#endif //CPRIRSA_FP_H
#endif //TPM_ALG_RSA

#endif // _CRYPT_PRI_H

extern TPM2B_AUTH g_LockoutAuth;
extern TPM2B_AUTH g_EndorsementAuth;
extern TPM2B_AUTH g_StorageAuth;

#define    NOT_IMPLEMENTED      0
#define    PP_COMMMAND         (1 << 0)
#define    DECRYPT_4           (1 << 1)
#define    DECRYPT_2           (1 << 2)
#define    HANDLE_1_DUP        (1 << 3)
#define    NO_SESSIONS         (1 << 4)
#define    HANDLE_1_USER       (1 << 5)
#define    ENCRYPT_4           (1 << 6)
#define    IS_IMPLEMENTED      (1 << 7)
#define    ENCRYPT_2           (1 << 8)
#define    HANDLE_1_ADMIN      (1 << 9)
#define    RESPONSE_HANDLE     (1 << 10)
#define    NV_COMMAND          (1 << 11)
#define    HANDLE_2_USER       (1 << 12)

typedef UINT16 ATTRIBUTE_TYPE;
extern const ATTRIBUTE_TYPE s_commandAttributes[];

typedef struct
{
    ANY_OBJECT                      objectTableIn[MAX_HANDLE_NUM];
    UINT32                          objectCntIn;
    ANY_OBJECT                      objectTableOut[MAX_HANDLE_NUM];
    UINT32                          objectCntOut;
    void*                           parmIn;
    void*                           parmOut;
} Marshal_Parms;

typedef UINT16
(*Parameter_Marshal_fp)(
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

typedef TPM_RC
(*Parameter_Unmarshal_fp)(
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

#ifndef _ACTIVATECREDENTIAL_H
#define _ACTIVATECREDENTIAL_H

#define TPM2_ActivateCredential_HdlIn_ActivateHandle  (0)
#define TPM2_ActivateCredential_HdlIn_KeyHandle  (1)
#define TPM2_ActivateCredential_HdlCntIn  (2)
#define TPM2_ActivateCredential_HdlCntOut  (0)
#define TPM2_ActivateCredential_SessionCnt  (2)

typedef struct {
    TPM2B_ID_OBJECT                     credentialBlob;
    TPM2B_ENCRYPTED_SECRET              secret;
} ActivateCredential_In;

typedef struct {
    TPM2B_DIGEST                        certInfo;
} ActivateCredential_Out;

UINT16
TPM2_ActivateCredential_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_ActivateCredential_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_ActivateCredential_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_ActivateCredential_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_ACTIVATECREDENTIAL_H

#ifndef _CERTIFY_H
#define _CERTIFY_H

#define TPM2_Certify_HdlIn_ObjectHandle  (0)
#define TPM2_Certify_HdlIn_SignHandle (1)
#define TPM2_Certify_HdlCntIn  (2)
#define TPM2_Certify_HdlCntOut  (0)
#define TPM2_Certify_SessionCnt  (2)

typedef struct {
    TPM2B_DATA                          qualifyingData;
    TPMT_SIG_SCHEME                     inScheme;
} Certify_In;

typedef struct {
    TPM2B_ATTEST                        certifyInfo;
    TPMT_SIGNATURE                      signature;
} Certify_Out;

UINT16
TPM2_Certify_Marshal(
    SESSION *sessionTable,
    UINT32 sessionCnt,
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

TPM_RC
TPM2_Certify_Unmarshal(
    SESSION *sessionTable,
    UINT32 sessionCnt,
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

UINT16
TPM2_Certify_Parameter_Marshal(
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

TPM_RC
TPM2_Certify_Parameter_Unmarshal(
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

#endif //_CERTIFY_H

#ifndef _CERTIFYCREATION_H
#define _CERTIFYCREATION_H

#define TPM2_CertifyCreation_HdlIn_SignHandle (0)
#define TPM2_CertifyCreation_HdlIn_ObjectHandle  (1)
#define TPM2_CertifyCreation_HdlCntIn  (2)
#define TPM2_CertifyCreation_HdlCntOut  (0)
#define TPM2_CertifyCreation_SessionCnt  (1)

typedef struct {
    TPM2B_DATA                          qualifyingData;
    TPM2B_DIGEST                        creationHash;
    TPMT_SIG_SCHEME                     inScheme;
    TPMT_TK_CREATION                    creationTicket;
} CertifyCreation_In;

typedef struct {
    TPM2B_ATTEST                        certifyInfo;
    TPMT_SIGNATURE                      signature;
} CertifyCreation_Out;

UINT16
TPM2_CertifyCreation_Marshal(
    SESSION *sessionTable,
    UINT32 sessionCnt,
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

TPM_RC
TPM2_CertifyCreation_Unmarshal(
    SESSION *sessionTable,
    UINT32 sessionCnt,
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

UINT16
TPM2_CertifyCreation_Parameter_Marshal(
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

TPM_RC
TPM2_CertifyCreation_Parameter_Unmarshal(
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

#endif //_CERTIFYCREATION_H

#ifndef _CHANGEEPS_H
#define _CHANGEEPS_H

#define TPM2_ChangeEPS_HdlIn_AuthHandle  (0)
#define TPM2_ChangeEPS_HdlCntIn  (1)
#define TPM2_ChangeEPS_HdlCntOut  (0)
#define TPM2_ChangeEPS_SessionCnt  (1)

typedef struct {
    BYTE nothing;
} ChangeEPS_In;

typedef struct {
    BYTE nothing;
} ChangeEPS_Out;

UINT16
TPM2_ChangeEPS_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_ChangeEPS_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_ChangeEPS_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_ChangeEPS_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_CHANGEEPS_H

#ifndef _CHANGEPPS_H
#define _CHANGEPPS_H

#define TPM2_ChangePPS_HdlIn_AuthHandle  (0)
#define TPM2_ChangePPS_HdlCntIn  (1)
#define TPM2_ChangePPS_HdlCntOut  (0)
#define TPM2_ChangePPS_SessionCnt  (1)

typedef struct {
    BYTE nothing;
} ChangePPS_In;

typedef struct {
    BYTE nothing;
} ChangePPS_Out;

UINT16
TPM2_ChangePPS_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_ChangePPS_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_ChangePPS_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_ChangePPS_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_CHANGEPPS_H

#ifndef _CLEAR_H
#define _CLEAR_H

#define TPM2_Clear_HdlIn_AuthHandle  (0)
#define TPM2_Clear_HdlCntIn  (1)
#define TPM2_Clear_HdlCntOut  (0)
#define TPM2_Clear_SessionCnt  (1)

typedef struct {
    BYTE nothing;
} Clear_In;

typedef struct {
    BYTE nothing;
} Clear_Out;

UINT16
TPM2_Clear_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_Clear_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_Clear_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_Clear_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_CLEAR_H

#ifndef _CLEARCONTROL_H
#define _CLEARCONTROL_H

#define TPM2_ClearControl_HdlIn_Auth  (0)
#define TPM2_ClearControl_HdlCntIn  (1)
#define TPM2_ClearControl_HdlCntOut  (0)
#define TPM2_ClearControl_SessionCnt  (1)

typedef struct {
    TPMI_YES_NO                         disable;
} ClearControl_In;

typedef struct {
    BYTE nothing;
} ClearControl_Out;

UINT16
TPM2_ClearControl_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_ClearControl_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_ClearControl_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_ClearControl_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_CLEARCONTROL_H

#ifndef _CLOCKRATEADJUST_H
#define _CLOCKRATEADJUST_H

#define TPM2_ClockRateAdjust_HdlIn_Auth  (0)
#define TPM2_ClockRateAdjust_HdlCntIn  (1)
#define TPM2_ClockRateAdjust_HdlCntOut  (0)
#define TPM2_ClockRateAdjust_SessionCnt  (1)

typedef struct {
    TPM_CLOCK_ADJUST                    rateAdjust;
} ClockRateAdjust_In;

typedef struct {
    BYTE nothing;
} ClockRateAdjust_Out;

UINT16
TPM2_ClockRateAdjust_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_ClockRateAdjust_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_ClockRateAdjust_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_ClockRateAdjust_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_CLOCKRATEADJUST_H

#ifndef _CLOCKSET_H
#define _CLOCKSET_H

#define TPM2_ClockSet_HdlIn_Auth  (0)
#define TPM2_ClockSet_HdlCntIn  (1)
#define TPM2_ClockSet_HdlCntOut  (0)
#define TPM2_ClockSet_SessionCnt  (1)

typedef struct {
    UINT64                              newTime;
} ClockSet_In;

typedef struct {
    BYTE nothing;
} ClockSet_Out;

UINT16
TPM2_ClockSet_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_ClockSet_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_ClockSet_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_ClockSet_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_CLOCKSET_H

#ifndef _COMMIT_H
#define _COMMIT_H

#define TPM2_Commit_HdlIn_SignHandle  (0)
#define TPM2_Commit_HdlCntIn  (1)
#define TPM2_Commit_HdlCntOut  (0)
#define TPM2_Commit_SessionCnt  (1)

typedef struct {
    TPM2B_ECC_POINT                     P1;
    TPM2B_SENSITIVE_DATA                s2;
    TPM2B_ECC_PARAMETER                 y2;
} Commit_In;

typedef struct {
    TPM2B_ECC_POINT                     K;
    TPM2B_ECC_POINT                     L;
    TPM2B_ECC_POINT                     E;
    UINT16                              counter;
} Commit_Out;

UINT16
TPM2_Commit_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_Commit_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_Commit_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_Commit_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_COMMIT_H

#ifndef _CONTEXTLOAD_H
#define _CONTEXTLOAD_H

#define TPM2_ContextLoad_HdlCntIn  (0)
#define TPM2_ContextLoad_HdlOut_LoadedHandle  (0)
#define TPM2_ContextLoad_HdlCntOut  (1)
#define TPM2_ContextLoad_SessionCnt  (0)

typedef struct {
    TPMS_CONTEXT                        context;
} ContextLoad_In;

typedef struct {
    BYTE nothing;
} ContextLoad_Out;

UINT16
TPM2_ContextLoad_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_ContextLoad_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_ContextLoad_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_ContextLoad_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_CONTEXTLOAD_H

#ifndef _CONTEXTSAVE_H
#define _CONTEXTSAVE_H

#define TPM2_ContextSave_HdlIn_SaveHandle  (0)
#define TPM2_ContextSave_HdlCntIn  (1)
#define TPM2_ContextSave_HdlCntOut  (0)
#define TPM2_ContextSave_SessionCnt  (0)

typedef struct {
    BYTE nothing;
} ContextSave_In;

typedef struct {
    TPMS_CONTEXT                        context;
} ContextSave_Out;

UINT16
TPM2_ContextSave_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_ContextSave_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_ContextSave_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_ContextSave_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_CONTEXTSAVE_H

#ifndef _CREATE_H
#define _CREATE_H

#define TPM2_Create_HdlIn_ParentHandle  (0)
#define TPM2_Create_HdlCntIn  (1)
#define TPM2_Create_HdlCntOut  (0)
#define TPM2_Create_SessionCnt  (1)

typedef struct {
    TPM2B_SENSITIVE_CREATE              inSensitive;
    TPM2B_PUBLIC                        inPublic;
    TPM2B_DATA                          outsideInfo;
    TPML_PCR_SELECTION                  creationPCR;
} Create_In;

typedef struct {
    TPM2B_PRIVATE                       outPrivate;
    TPM2B_PUBLIC                        outPublic;
    TPM2B_CREATION_DATA                 creationData;
    TPM2B_DIGEST                        creationHash;
    TPMT_TK_CREATION                    creationTicket;
} Create_Out;

UINT16
TPM2_Create_Marshal(
    SESSION *sessionTable,
    UINT32 sessionCnt,
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

TPM_RC
TPM2_Create_Unmarshal(
    SESSION *sessionTable,
    UINT32 sessionCnt,
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

UINT16
TPM2_Create_Parameter_Marshal(
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

TPM_RC
TPM2_Create_Parameter_Unmarshal(
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

#endif //_CREATE_H

#ifndef _CREATEPRIMARY_H
#define _CREATEPRIMARY_H

#define TPM2_CreatePrimary_HdlIn_PrimaryHandle  (0)
#define TPM2_CreatePrimary_HdlCntIn  (1)
#define TPM2_CreatePrimary_HdlOut_ObjectHandle  (0)
#define TPM2_CreatePrimary_HdlCntOut  (1)
#define TPM2_CreatePrimary_SessionCnt  (1)

typedef struct {
    TPM2B_SENSITIVE_CREATE              inSensitive;
    TPM2B_PUBLIC                        inPublic;
    TPM2B_DATA                          outsideInfo;
    TPML_PCR_SELECTION                  creationPCR;
} CreatePrimary_In;

typedef struct {
    TPM2B_PUBLIC                        outPublic;
    TPM2B_CREATION_DATA                 creationData;
    TPM2B_DIGEST                        creationHash;
    TPMT_TK_CREATION                    creationTicket;
    TPM2B_NAME                          name;
} CreatePrimary_Out;

UINT16
TPM2_CreatePrimary_Marshal(
    SESSION *sessionTable,
    UINT32 sessionCnt,
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

TPM_RC
TPM2_CreatePrimary_Unmarshal(
    SESSION *sessionTable,
    UINT32 sessionCnt,
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

UINT16
TPM2_CreatePrimary_Parameter_Marshal(
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

TPM_RC
TPM2_CreatePrimary_Parameter_Unmarshal(
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

#endif //_CREATEPRIMARY_H

#ifndef _DICTIONARYATTACKLOCKRESET_H
#define _DICTIONARYATTACKLOCKRESET_H

#define TPM2_DictionaryAttackLockReset_HdlIn_LockHandle  (0)
#define TPM2_DictionaryAttackLockReset_HdlCntIn  (1)
#define TPM2_DictionaryAttackLockReset_HdlCntOut  (0)
#define TPM2_DictionaryAttackLockReset_SessionCnt  (1)

typedef struct {
    BYTE nothing;
} DictionaryAttackLockReset_In;

typedef struct {
    BYTE nothing;
} DictionaryAttackLockReset_Out;

UINT16
TPM2_DictionaryAttackLockReset_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_DictionaryAttackLockReset_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_DictionaryAttackLockReset_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_DictionaryAttackLockReset_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_DICTIONARYATTACKLOCKRESET_H

#ifndef _DICTIONARYATTACKPARAMETERS_H
#define _DICTIONARYATTACKPARAMETERS_H

#define TPM2_DictionaryAttackParameters_HdlIn_LockHandle  (0)
#define TPM2_DictionaryAttackParameters_HdlCntIn  (1)
#define TPM2_DictionaryAttackParameters_HdlCntOut  (0)
#define TPM2_DictionaryAttackParameters_SessionCnt  (1)

typedef struct {
    UINT32                              newMaxTries;
    UINT32                              newRecoveryTime;
    UINT32                              lockoutRecovery;
} DictionaryAttackParameters_In;

typedef struct {
    BYTE nothing;
} DictionaryAttackParameters_Out;

UINT16
TPM2_DictionaryAttackParameters_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_DictionaryAttackParameters_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_DictionaryAttackParameters_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_DictionaryAttackParameters_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_DICTIONARYATTACKPARAMETERS_H

#ifndef _DUPLICATE_H
#define _DUPLICATE_H

#define TPM2_Duplicate_HdlIn_ObjectHandle  (0)
#define TPM2_Duplicate_HdlIn_NewParentHandle  (1)
#define TPM2_Duplicate_HdlCntIn  (2)
#define TPM2_Duplicate_HdlCntOut  (0)
#define TPM2_Duplicate_SessionCnt  (1)

typedef struct {
    TPM2B_DATA                          encryptionKeyIn;
    TPMT_SYM_DEF_OBJECT                 symmetricAlg;
} Duplicate_In;

typedef struct {
    TPM2B_DATA                          encryptionKeyOut;
    TPM2B_PRIVATE                       duplicate;
    TPM2B_ENCRYPTED_SECRET              outSymSeed;
} Duplicate_Out;

UINT16
TPM2_Duplicate_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_Duplicate_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_Duplicate_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_Duplicate_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_DUPLICATE_H

#ifndef _EC_EPHEMERAL_H
#define _EC_EPHEMERAL_H

#define TPM2_EC_Ephemeral_HdlCntIn  (0)
#define TPM2_EC_Ephemeral_HdlCntOut  (0)
#define TPM2_EC_Ephemeral_SessionCnt  (0)

typedef struct {
    TPMI_ECC_CURVE                      curveID;
} EC_Ephemeral_In;

typedef struct {
    TPM2B_ECC_POINT                     Q;
    UINT16                              counter;
} EC_Ephemeral_Out;

UINT16
TPM2_EC_Ephemeral_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_EC_Ephemeral_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_EC_Ephemeral_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_EC_Ephemeral_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_EC_EPHEMERAL_H

#ifndef _ECC_PARAMETERS_H
#define _ECC_PARAMETERS_H

#define TPM2_ECC_Parameters_HdlCntIn  (0)
#define TPM2_ECC_Parameters_HdlCntOut  (0)
#define TPM2_ECC_Parameters_SessionCnt  (0)

typedef struct {
    TPMI_ECC_CURVE                      curveID;
} ECC_Parameters_In;

typedef struct {
    TPMS_ALGORITHM_DETAIL_ECC           parameters;
} ECC_Parameters_Out;

UINT16
TPM2_ECC_Parameters_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_ECC_Parameters_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_ECC_Parameters_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_ECC_Parameters_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_ECC_PARAMETERS_H

#ifndef _ECDH_KEYGEN_H
#define _ECDH_KEYGEN_H

#define TPM2_ECDH_KeyGen_HdlIn_KeyHandle  (0)
#define TPM2_ECDH_KeyGen_HdlCntIn  (1)
#define TPM2_ECDH_KeyGen_HdlCntOut  (0)
#define TPM2_ECDH_KeyGen_SessionCnt  (0)

typedef struct {
    BYTE nothing;
} ECDH_KeyGen_In;

typedef struct {
    TPM2B_ECC_POINT                     zPoint;
    TPM2B_ECC_POINT                     pubPoint;
} ECDH_KeyGen_Out;

UINT16
TPM2_ECDH_KeyGen_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_ECDH_KeyGen_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_ECDH_KeyGen_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_ECDH_KeyGen_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_ECDH_KEYGEN_H

#ifndef _ECDH_ZGEN_H
#define _ECDH_ZGEN_H

#define TPM2_ECDH_ZGen_HdlIn_KeyHandle  (0)
#define TPM2_ECDH_ZGen_HdlCntIn  (1)
#define TPM2_ECDH_ZGen_HdlCntOut  (0)
#define TPM2_ECDH_ZGen_SessionCnt  (1)

typedef struct {
    TPM2B_ECC_POINT                     inPoint;
} ECDH_ZGen_In;

typedef struct {
    TPM2B_ECC_POINT                     outPoint;
} ECDH_ZGen_Out;

UINT16
TPM2_ECDH_ZGen_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_ECDH_ZGen_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_ECDH_ZGen_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_ECDH_ZGen_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_ECDH_ZGEN_H

#ifndef _ENCRYPTDECRYPT_H
#define _ENCRYPTDECRYPT_H

#define TPM2_EncryptDecrypt_HdlIn_KeyHandle  (0)
#define TPM2_EncryptDecrypt_HdlCntIn  (1)
#define TPM2_EncryptDecrypt_HdlCntOut  (0)
#define TPM2_EncryptDecrypt_SessionCnt  (1)

typedef struct {
    TPMI_YES_NO                         decrypt;
    TPMI_ALG_SYM_MODE                   mode;
    TPM2B_IV                            ivIn;
    TPM2B_MAX_BUFFER                    inData;
} EncryptDecrypt_In;

typedef struct {
    TPM2B_MAX_BUFFER                    outData;
    TPM2B_IV                            ivOut;
} EncryptDecrypt_Out;

UINT16
TPM2_EncryptDecrypt_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_EncryptDecrypt_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_EncryptDecrypt_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_EncryptDecrypt_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_ENCRYPTDECRYPT_H

#ifndef _EVENTSEQUENCECOMPLETE_H
#define _EVENTSEQUENCECOMPLETE_H

#define TPM2_EventSequenceComplete_HdlIn_PcrHandle  (0)
#define TPM2_EventSequenceComplete_HdlIn_SequenceHandle (1)
#define TPM2_EventSequenceComplete_HdlCntIn  (2)
#define TPM2_EventSequenceComplete_HdlCntOut  (0)
#define TPM2_EventSequenceComplete_SessionCnt  (2)

typedef struct {
    TPM2B_MAX_BUFFER                    buffer;
} EventSequenceComplete_In;

typedef struct {
    TPML_DIGEST_VALUES                  results;
} EventSequenceComplete_Out;

UINT16
TPM2_EventSequenceComplete_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_EventSequenceComplete_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_EventSequenceComplete_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_EventSequenceComplete_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_EVENTSEQUENCECOMPLETE_H

#ifndef _EVICTCONTROL_H
#define _EVICTCONTROL_H

#define TPM2_EvictControl_HdlIn_Auth  (0)
#define TPM2_EvictControl_HdlIn_ObjectHandle  (1)
#define TPM2_EvictControl_HdlCntIn  (2)
#define TPM2_EvictControl_HdlCntOut  (0)
#define TPM2_EvictControl_SessionCnt  (1)

typedef struct {
    TPMI_DH_PERSISTENT                  persistentHandle;
} EvictControl_In;

typedef struct {
    BYTE nothing;
} EvictControl_Out;

UINT16
TPM2_EvictControl_Marshal(
    SESSION *sessionTable,
    UINT32 sessionCnt,
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

TPM_RC
TPM2_EvictControl_Unmarshal(
    SESSION *sessionTable,
    UINT32 sessionCnt,
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

UINT16
TPM2_EvictControl_Parameter_Marshal(
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

TPM_RC
TPM2_EvictControl_Parameter_Unmarshal(
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

#endif //_EVICTCONTROL_H

#ifndef _FIELDUPGRADEDATA_H
#define _FIELDUPGRADEDATA_H

#define TPM2_FieldUpgradeData_HdlCntIn  (0)
#define TPM2_FieldUpgradeData_HdlCntOut  (0)
#define TPM2_FieldUpgradeData_SessionCnt  (0)

typedef struct {
    TPM2B_MAX_BUFFER                    fuData;
} FieldUpgradeData_In;

typedef struct {
    TPMT_HA                             nextDigest;
    TPMT_HA                             firstDigest;
} FieldUpgradeData_Out;

UINT16
TPM2_FieldUpgradeData_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_FieldUpgradeData_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_FieldUpgradeData_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_FieldUpgradeData_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_FIELDUPGRADEDATA_H

#ifndef _FIELDUPGRADESTART_H
#define _FIELDUPGRADESTART_H

#define TPM2_FieldUpgradeStart_HdlIn_Authorization  (0)
#define TPM2_FieldUpgradeStart_HdlIn_KeyHandle  (1)
#define TPM2_FieldUpgradeStart_HdlCntIn  (2)
#define TPM2_FieldUpgradeStart_HdlCntOut  (0)
#define TPM2_FieldUpgradeStart_SessionCnt  (1)

typedef struct {
    TPM2B_DIGEST                        fuDigest;
    TPMT_SIGNATURE                      manifestSignature;
} FieldUpgradeStart_In;

typedef struct {
    BYTE nothing;
} FieldUpgradeStart_Out;

UINT16
TPM2_FieldUpgradeStart_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_FieldUpgradeStart_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_FieldUpgradeStart_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_FieldUpgradeStart_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_FIELDUPGRADESTART_H

#ifndef _FIRMWAREREAD_H
#define _FIRMWAREREAD_H

#define TPM2_FirmwareRead_HdlCntIn  (0)
#define TPM2_FirmwareRead_HdlCntOut  (0)
#define TPM2_FirmwareRead_SessionCnt  (0)

typedef struct {
    UINT32                              sequenceNumber;
} FirmwareRead_In;

typedef struct {
    TPM2B_MAX_BUFFER                    fuData;
} FirmwareRead_Out;

UINT16
TPM2_FirmwareRead_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_FirmwareRead_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_FirmwareRead_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_FirmwareRead_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_FIRMWAREREAD_H

#ifndef _FLUSHCONTEXT_H
#define _FLUSHCONTEXT_H

#define TPM2_FlushContext_HdlIn_FlushHandle  (0)
#define TPM2_FlushContext_HdlCntIn  (1)
#define TPM2_FlushContext_HdlCntOut  (0)
#define TPM2_FlushContext_SessionCnt  (0)

typedef struct {
    BYTE nothing;
} FlushContext_In;

typedef struct {
    BYTE nothing;
} FlushContext_Out;

UINT16
TPM2_FlushContext_Marshal(
    SESSION *sessionTable,
    UINT32 sessionCnt,
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

TPM_RC
TPM2_FlushContext_Unmarshal(
    SESSION *sessionTable,
    UINT32 sessionCnt,
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

UINT16
TPM2_FlushContext_Parameter_Marshal(
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

TPM_RC
TPM2_FlushContext_Parameter_Unmarshal(
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

#endif //_FLUSHCONTEXT_H

#ifndef _GETCAPABILITY_H
#define _GETCAPABILITY_H

#define TPM2_GetCapability_HdlCntIn  (0)
#define TPM2_GetCapability_HdlCntOut  (0)
#define TPM2_GetCapability_SessionCnt  (0)

typedef struct {
    TPM_CAP                             capability;
    UINT32                              property;
    UINT32                              propertyCount;
} GetCapability_In;

typedef struct {
    TPMI_YES_NO                         moreData;
    TPMS_CAPABILITY_DATA                capabilityData;
} GetCapability_Out;

UINT16
TPM2_GetCapability_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_GetCapability_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_GetCapability_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_GetCapability_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_GETCAPABILITY_H

#ifndef _GETCOMMANDAUDITDIGEST_H
#define _GETCOMMANDAUDITDIGEST_H

#define TPM2_GetCommandAuditDigest_HdlIn_PrivacyHandle  (0)
#define TPM2_GetCommandAuditDigest_HdlIn_SignHandle (1)
#define TPM2_GetCommandAuditDigest_HdlCntIn  (2)
#define TPM2_GetCommandAuditDigest_HdlCntOut  (0)
#define TPM2_GetCommandAuditDigest_SessionCnt  (2)

typedef struct {
    TPM2B_DATA                          qualifyingData;
    TPMT_SIG_SCHEME                     inScheme;
} GetCommandAuditDigest_In;

typedef struct {
    TPM2B_ATTEST                        auditInfo;
    TPMT_SIGNATURE                      signature;
} GetCommandAuditDigest_Out;

UINT16
TPM2_GetCommandAuditDigest_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_GetCommandAuditDigest_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_GetCommandAuditDigest_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_GetCommandAuditDigest_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_GETCOMMANDAUDITDIGEST_H

#ifndef _GETRANDOM_H
#define _GETRANDOM_H

#define TPM2_GetRandom_HdlIn_PublicKey  (0)
#define TPM2_GetRandom_HdlCntIn  (0)
#define TPM2_GetRandom_HdlCntOut  (0)
#define TPM2_GetRandom_SessionCnt  (0)

typedef struct {
    UINT16                              bytesRequested;
} GetRandom_In;

typedef struct {
    TPM2B_DIGEST                        randomBytes;
} GetRandom_Out;

UINT16
TPM2_GetRandom_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_GetRandom_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_GetRandom_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_GetRandom_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_GETRANDOM_H

#ifndef _GETSESSIONAUDITDIGEST_H
#define _GETSESSIONAUDITDIGEST_H

#define TPM2_GetSessionAuditDigest_HdlIn_PrivacyAdminHandle  (0)
#define TPM2_GetSessionAuditDigest_HdlIn_SignHandle (1)
#define TPM2_GetSessionAuditDigest_HdlIn_SessionHandle (2)
#define TPM2_GetSessionAuditDigest_HdlCntIn  (3)
#define TPM2_GetSessionAuditDigest_HdlCntOut  (0)
#define TPM2_GetSessionAuditDigest_SessionCnt  (2)

typedef struct {
    TPM2B_DATA                          qualifyingData;
    TPMT_SIG_SCHEME                     inScheme;
} GetSessionAuditDigest_In;

typedef struct {
    TPM2B_ATTEST                        auditInfo;
    TPMT_SIGNATURE                      signature;
} GetSessionAuditDigest_Out;

UINT16
TPM2_GetSessionAuditDigest_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_GetSessionAuditDigest_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_GetSessionAuditDigest_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_GetSessionAuditDigest_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_GETSESSIONAUDITDIGEST_H

#ifndef _GETTESTRESULT_H
#define _GETTESTRESULT_H

#define TPM2_GetTestResult_HdlCntIn  (0)
#define TPM2_GetTestResult_HdlCntOut  (0)
#define TPM2_GetTestResult_SessionCnt  (0)

typedef struct {
    BYTE nothing;
} GetTestResult_In;

typedef struct {
    TPM2B_MAX_BUFFER                    outData;
    TPM_RC                              testResult;
} GetTestResult_Out;

UINT16
TPM2_GetTestResult_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_GetTestResult_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_GetTestResult_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_GetTestResult_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_GETTESTRESULT_H

#ifndef _GETTIME_H
#define _GETTIME_H

#define TPM2_GetTime_HdlIn_PrivacyAdminHandle (0)
#define TPM2_GetTime_HdlIn_SignHandle (1)
#define TPM2_GetTime_HdlCntIn  (2)
#define TPM2_GetTime_HdlCntOut  (0)
#define TPM2_GetTime_SessionCnt  (2)

typedef struct {
    TPM2B_DATA                          qualifyingData;
    TPMT_SIG_SCHEME                     inScheme;
} GetTime_In;

typedef struct {
    TPM2B_ATTEST                        timeInfo;
    TPMT_SIGNATURE                      signature;
} GetTime_Out;

UINT16
TPM2_GetTime_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_GetTime_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_GetTime_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_GetTime_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_GETTIME_H

#ifndef _HASH_H
#define _HASH_H

#define TPM2_Hash_HdlCntIn  (0)
#define TPM2_Hash_HdlCntOut  (0)
#define TPM2_Hash_SessionCnt  (0)

typedef struct {
    TPM2B_MAX_BUFFER                    data;
    TPMI_ALG_HASH                       hashAlg;
    TPMI_RH_HIERARCHY                   hierarchy;
} Hash_In;

typedef struct {
    TPM2B_DIGEST                        outHash;
    TPMT_TK_HASHCHECK                   validation;
} Hash_Out;

UINT16
TPM2_Hash_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_Hash_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_Hash_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_Hash_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_HASH_H

#ifndef _HASHSEQUENCESTART_H
#define _HASHSEQUENCESTART_H

#define TPM2_HashSequenceStart_HdlCntIn  (0)
#define TPM2_HashSequenceStart_HdlOut_SequenceHandle  (0)
#define TPM2_HashSequenceStart_HdlCntOut  (1)
#define TPM2_HashSequenceStart_SessionCnt  (0)

typedef struct {
    TPM2B_AUTH                          auth;
    TPMI_ALG_HASH                       hashAlg;
} HashSequenceStart_In;

typedef struct {
    TPMI_DH_OBJECT                      sequenceHandle;
} HashSequenceStart_Out;

UINT16
TPM2_HashSequenceStart_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_HashSequenceStart_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_HashSequenceStart_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_HashSequenceStart_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_HASHSEQUENCESTART_H

#ifndef _HIERARCHYCHANGEAUTH_H
#define _HIERARCHYCHANGEAUTH_H

#define TPM2_HierarchyChangeAuth_HdlIn_AuthHandle  (0)
#define TPM2_HierarchyChangeAuth_HdlCntIn  (1)
#define TPM2_HierarchyChangeAuth_HdlCntOut  (0)
#define TPM2_HierarchyChangeAuth_SessionCnt  (1)

typedef struct {
    TPM2B_AUTH                          newAuth;
} HierarchyChangeAuth_In;

typedef struct {
    BYTE nothing;
} HierarchyChangeAuth_Out;

UINT16
TPM2_HierarchyChangeAuth_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_HierarchyChangeAuth_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_HierarchyChangeAuth_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_HierarchyChangeAuth_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_HIERARCHYCHANGEAUTH_H

#ifndef _HIERARCHYCONTROL_H
#define _HIERARCHYCONTROL_H

#define TPM2_HierarchyControl_HdlIn_AuthHandle  (0)
#define TPM2_HierarchyControl_HdlCntIn  (1)
#define TPM2_HierarchyControl_HdlCntOut  (0)
#define TPM2_HierarchyControl_SessionCnt  (1)

typedef struct {
    TPMI_RH_HIERARCHY                   hierarchy;
    TPMI_YES_NO                         state;
} HierarchyControl_In;

typedef struct {
    BYTE nothing;
} HierarchyControl_Out;

UINT16
TPM2_HierarchyControl_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_HierarchyControl_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_HierarchyControl_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_HierarchyControl_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_HIERARCHYCONTROL_H

#ifndef _HMAC_H
#define _HMAC_H

#define TPM2_HMAC_HdlIn_Handle  (0)
#define TPM2_HMAC_HdlCntIn  (1)
#define TPM2_HMAC_HdlCntOut  (0)
#define TPM2_HMAC_SessionCnt  (1)

typedef struct {
    TPM2B_MAX_BUFFER                    buffer;
    TPMI_ALG_HASH                       hashAlg;
} HMAC_In;

typedef struct {
    TPM2B_DIGEST                        outHMAC;
} HMAC_Out;

UINT16
TPM2_HMAC_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_HMAC_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_HMAC_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_HMAC_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_HMAC_H

#ifndef _HMAC_START_H
#define _HMAC_START_H

#define TPM2_HMAC_Start_HdlIn_Handle  (0)
#define TPM2_HMAC_Start_HdlCntIn  (1)
#define TPM2_HMAC_Start_HdlOut_SequenceHandle  (0)
#define TPM2_HMAC_Start_HdlCntOut  (1)
#define TPM2_HMAC_Start_SessionCnt  (1)

typedef struct {
    TPM2B_AUTH                          auth;
    TPMI_ALG_HASH                       hashAlg;
} HMAC_Start_In;

typedef struct {
    TPMI_DH_OBJECT                      sequenceHandle;
} HMAC_Start_Out;

UINT16
TPM2_HMAC_Start_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_HMAC_Start_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_HMAC_Start_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_HMAC_Start_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_HMAC_START_H

#ifndef _IMPORT_H
#define _IMPORT_H

#define TPM2_Import_HdlIn_ParentHandle  (0)
#define TPM2_Import_HdlCntIn  (1)
#define TPM2_Import_HdlCntOut  (0)
#define TPM2_Import_SessionCnt  (1)

typedef struct {
    TPM2B_DATA                          encryptionKey;
    TPM2B_PUBLIC                        objectPublic;
    TPM2B_PRIVATE                       duplicate;
    TPM2B_ENCRYPTED_SECRET              inSymSeed;
    TPMT_SYM_DEF_OBJECT                 symmetricAlg;
} Import_In;

typedef struct {
    TPM2B_PRIVATE                       outPrivate;
} Import_Out;

UINT16
TPM2_Import_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_Import_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_Import_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_Import_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_IMPORT_H

#ifndef _INCREMENTALSELFTEST_H
#define _INCREMENTALSELFTEST_H

#define TPM2_IncrementalSelfTest_HdlCntIn  (0)
#define TPM2_IncrementalSelfTest_HdlCntOut  (0)
#define TPM2_IncrementalSelfTest_SessionCnt  (0)

typedef struct {
    TPML_ALG                            toTest;
} IncrementalSelfTest_In;

typedef struct {
    TPML_ALG                            toDoList;
} IncrementalSelfTest_Out;

UINT16
TPM2_IncrementalSelfTest_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_IncrementalSelfTest_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_IncrementalSelfTest_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_IncrementalSelfTest_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_INCREMENTALSELFTEST_H

#ifndef _LOAD_H
#define _LOAD_H

#define TPM2_Load_HdlIn_ParentHandle  (0)
#define TPM2_Load_HdlCntIn  (1)
#define TPM2_Load_HdlOut_ObjectHandle  (0)
#define TPM2_Load_HdlCntOut  (1)
#define TPM2_Load_SessionCnt  (1)

typedef struct {
    TPM2B_PRIVATE                       inPrivate;
    TPM2B_PUBLIC                        inPublic;
} Load_In;

typedef struct {
    TPM2B_NAME                          name;
} Load_Out;

UINT16
TPM2_Load_Marshal(
    SESSION *sessionTable,
    UINT32 sessionCnt,
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

TPM_RC
TPM2_Load_Unmarshal(
    SESSION *sessionTable,
    UINT32 sessionCnt,
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

UINT16
TPM2_Load_Parameter_Marshal(
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

TPM_RC
TPM2_Load_Parameter_Unmarshal(
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

#endif //_LOAD_H

#ifndef _LOADEXTERNAL_H
#define _LOADEXTERNAL_H

#define TPM2_LoadExternal_HdlCntIn  (0)
#define TPM2_LoadExternal_HdlOut_ObjectHandle  (0)
#define TPM2_LoadExternal_HdlCntOut  (1)
#define TPM2_LoadExternal_SessionCnt  (0)

typedef struct {
    TPM2B_SENSITIVE                     inPrivate;
    TPM2B_PUBLIC                        inPublic;
    TPMI_RH_HIERARCHY                   hierarchy;
} LoadExternal_In;

typedef struct {
    TPM_HANDLE                          objectHandle;
    TPM2B_NAME                          name;
} LoadExternal_Out;

UINT16
TPM2_LoadExternal_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_LoadExternal_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_LoadExternal_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_LoadExternal_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_LOADEXTERNAL_H

#ifndef _MAKECREDENTIAL_H
#define _MAKECREDENTIAL_H

#define TPM2_MakeCredential_HdlIn_Handle  (0)
#define TPM2_MakeCredential_HdlCntIn  (1)
#define TPM2_MakeCredential_HdlCntOut  (0)
#define TPM2_MakeCredential_SessionCnt  (0)

typedef struct {
    TPM2B_DIGEST                        credential;
    TPM2B_NAME                          objectName;
} MakeCredential_In;

typedef struct {
    TPM2B_ID_OBJECT                     credentialBlob;
    TPM2B_ENCRYPTED_SECRET              secret;
} MakeCredential_Out;

UINT16
TPM2_MakeCredential_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_MakeCredential_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_MakeCredential_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_MakeCredential_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_MAKECREDENTIAL_H

#ifndef _NV_CERTIFY_H
#define _NV_CERTIFY_H

#define TPM2_NV_Certify_HdlIn_SignHandle (0)
#define TPM2_NV_Certify_HdlIn_AuthHandle  (1)
#define TPM2_NV_Certify_HdlIn_NvIndex  (2)
#define TPM2_NV_Certify_HdlCntIn  (3)
#define TPM2_NV_Certify_HdlCntOut  (0)
#define TPM2_NV_Certify_SessionCnt  (2)

typedef struct {
    TPM2B_DATA                          qualifyingData;
    TPMT_SIG_SCHEME                     inScheme;
    UINT16                              size;
    UINT16                              offset;
} NV_Certify_In;

typedef struct {
    TPM2B_ATTEST                        certifyInfo;
    TPMT_SIGNATURE                      signature;
} NV_Certify_Out;

UINT16
TPM2_NV_Certify_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_NV_Certify_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_NV_Certify_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_NV_Certify_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_NV_CERTIFY_H

#ifndef _NV_CHANGEAUTH_H
#define _NV_CHANGEAUTH_H

#define TPM2_NV_ChangeAuth_HdlIn_NvIndex (0)
#define TPM2_NV_ChangeAuth_HdlCntIn  (1)
#define TPM2_NV_ChangeAuth_HdlCntOut  (0)
#define TPM2_NV_ChangeAuth_SessionCnt  (1)

typedef struct {
    TPM2B_AUTH                          newAuth;
} NV_ChangeAuth_In;

typedef struct {
    BYTE nothing;
} NV_ChangeAuth_Out;

UINT16
TPM2_NV_ChangeAuth_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_NV_ChangeAuth_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_NV_ChangeAuth_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_NV_ChangeAuth_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_NV_CHANGEAUTH_H

#ifndef _NV_DEFINESPACE_H
#define _NV_DEFINESPACE_H

#define TPM2_NV_DefineSpace_HdlIn_AuthHandle  (0)
#define TPM2_NV_DefineSpace_HdlCntIn  (1)
#define TPM2_NV_DefineSpace_HdlCntOut  (0)
#define TPM2_NV_DefineSpace_SessionCnt  (1)

typedef struct {
    TPM2B_AUTH                          auth;
    TPM2B_NV_PUBLIC                     publicInfo;
} NV_DefineSpace_In;

typedef struct
{
    BYTE nothing;
} NV_DefineSpace_Out;

UINT16
TPM2_NV_DefineSpace_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_NV_DefineSpace_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_NV_DefineSpace_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_NV_DefineSpace_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_NV_DEFINESPACE_H

#ifndef _NV_EXTEND_H
#define _NV_EXTEND_H

#define TPM2_NV_Extend_HdlIn_AuthHandle (0)
#define TPM2_NV_Extend_HdlIn_NvIndex (1)
#define TPM2_NV_Extend_HdlCntIn  (2)
#define TPM2_NV_Extend_HdlCntOut  (0)
#define TPM2_NV_Extend_SessionCnt  (1)

typedef struct {
    TPM2B_MAX_NV_BUFFER                 data;
} NV_Extend_In;

typedef struct {
    BYTE nothing;
} NV_Extend_Out;

UINT16
TPM2_NV_Extend_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_NV_Extend_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_NV_Extend_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_NV_Extend_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_NV_EXTEND_H

#ifndef _NV_GLOBALWRITELOCK_H
#define _NV_GLOBALWRITELOCK_H

#define TPM2_NV_GlobalWriteLock_HdlIn_AuthHandle (0)
#define TPM2_NV_GlobalWriteLock_HdlCntIn  (1)
#define TPM2_NV_GlobalWriteLock_HdlCntOut  (0)
#define TPM2_NV_GlobalWriteLock_SessionCnt  (1)

typedef struct {
    BYTE nothing;
} NV_GlobalWriteLock_In;

typedef struct {
    BYTE nothing;
} NV_GlobalWriteLock_Out;

UINT16
TPM2_NV_GlobalWriteLock_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_NV_GlobalWriteLock_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_NV_GlobalWriteLock_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_NV_GlobalWriteLock_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_NV_GLOBALWRITELOCK_H

#ifndef _NV_INCREMENT_H
#define _NV_INCREMENT_H

#define TPM2_NV_Increment_HdlIn_AuthHandle (0)
#define TPM2_NV_Increment_HdlIn_NvIndex (1)
#define TPM2_NV_Increment_HdlCntIn  (2)
#define TPM2_NV_Increment_HdlCntOut  (0)
#define TPM2_NV_Increment_SessionCnt  (1)

typedef struct {
    BYTE nothing;
} NV_Increment_In;

typedef struct {
    BYTE nothing;
} NV_Increment_Out;

UINT16
TPM2_NV_Increment_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_NV_Increment_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_NV_Increment_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_NV_Increment_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_NV_INCREMENT_H

#ifndef _NV_READ_H
#define _NV_READ_H

#define TPM2_NV_Read_HdlIn_AuthHandle  (0)
#define TPM2_NV_Read_HdlIn_NvIndex  (1)
#define TPM2_NV_Read_HdlCntIn  (2)
#define TPM2_NV_Read_HdlCntOut  (0)
#define TPM2_NV_Read_SessionCnt  (1)

typedef struct {
    UINT16                              size;
    UINT16                              offset;
} NV_Read_In;

typedef struct {
    TPM2B_MAX_NV_BUFFER                 data;
} NV_Read_Out;

UINT16
TPM2_NV_Read_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_NV_Read_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_NV_Read_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_NV_Read_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_NV_READ_H

#ifndef _NV_READLOCK_H
#define _NV_READLOCK_H

#define TPM2_NV_ReadLock_HdlIn_AuthHandle (0)
#define TPM2_NV_ReadLock_HdlIn_NvIndex (1)
#define TPM2_NV_ReadLock_HdlCntIn  (2)
#define TPM2_NV_ReadLock_HdlCntOut  (0)
#define TPM2_NV_ReadLock_SessionCnt  (1)

typedef struct {
    TPMI_RH_NV_AUTH                     authHandle;
    TPMI_RH_NV_INDEX                    nvIndex;
} NV_ReadLock_In;

typedef struct {
    BYTE nothing;
} NV_ReadLock_Out;

UINT16
TPM2_NV_ReadLock_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_NV_ReadLock_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_NV_ReadLock_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_NV_ReadLock_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_NV_READLOCK_H

#ifndef _NV_READPUBLIC_H
#define _NV_READPUBLIC_H

#define TPM2_NV_ReadPublic_HdlIn_NvIndex  (0)
#define TPM2_NV_ReadPublic_HdlCntIn  (1)
#define TPM2_NV_ReadPublic_HdlCntOut  (0)
#define TPM2_NV_ReadPublic_SessionCnt  (0)

typedef struct {
    BYTE nothing;
} NV_ReadPublic_In;

typedef struct {
    TPM2B_NV_PUBLIC                     nvPublic;
    TPM2B_NAME                          nvName;
} NV_ReadPublic_Out;

UINT16
TPM2_NV_ReadPublic_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_NV_ReadPublic_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_NV_ReadPublic_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_NV_ReadPublic_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_NV_READPUBLIC_H

#ifndef _NV_SETBITS_H
#define _NV_SETBITS_H

#define TPM2_NV_SetBits_HdlIn_AuthHandle (0)
#define TPM2_NV_SetBits_HdlIn_NvIndex (1)
#define TPM2_NV_SetBits_HdlCntIn  (2)
#define TPM2_NV_SetBits_HdlCntOut  (0)
#define TPM2_NV_SetBits_SessionCnt  (1)

typedef struct {
    UINT64                              bits;
} NV_SetBits_In;

typedef struct {
    BYTE nothing;
} NV_SetBits_Out;

UINT16
TPM2_NV_SetBits_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_NV_SetBits_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_NV_SetBits_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_NV_SetBits_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_NV_SETBITS_H

#ifndef _NV_UNDEFINESPACE_H
#define _NV_UNDEFINESPACE_H

#define TPM2_NV_UndefineSpace_HdlIn_AuthHandle  (0)
#define TPM2_NV_UndefineSpace_HdlIn_NvIndex  (1)
#define TPM2_NV_UndefineSpace_HdlCntIn  (2)
#define TPM2_NV_UndefineSpace_HdlCntOut  (0)
#define TPM2_NV_UndefineSpace_SessionCnt  (1)

typedef struct {
    BYTE nothing;
} NV_UndefineSpace_In;

typedef struct
{
    BYTE nothing;
} NV_UndefineSpace_Out;

UINT16
TPM2_NV_UndefineSpace_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_NV_UndefineSpace_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_NV_UndefineSpace_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_NV_UndefineSpace_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_NV_UNDEFINESPACE_H

#ifndef _NV_UNDEFINESPACESPECIAL_H
#define _NV_UNDEFINESPACESPECIAL_H

#define TPM2_NV_UndefineSpaceSpecial_HdlIn_NvIndex  (0)
#define TPM2_NV_UndefineSpaceSpecial_HdlIn_Platform  (1)
#define TPM2_NV_UndefineSpaceSpecial_HdlCntIn  (2)
#define TPM2_NV_UndefineSpaceSpecial_HdlCntOut  (0)
#define TPM2_NV_UndefineSpaceSpecial_SessionCnt  (2)

typedef struct {
    BYTE nothing;
} NV_UndefineSpaceSpecialSpecial_In;

typedef struct
{
    BYTE nothing;
} NV_UndefineSpaceSpecial_Out;

UINT16
TPM2_NV_UndefineSpaceSpecial_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_NV_UndefineSpaceSpecial_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_NV_UndefineSpaceSpecial_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_NV_UndefineSpaceSpecial_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_NV_UNDEFINESPACESPECIAL_H

#ifndef _NV_WRITE_H
#define _NV_WRITE_H

#define TPM2_NV_Write_HdlIn_AuthHandle  (0)
#define TPM2_NV_Write_HdlIn_NvIndex  (1)
#define TPM2_NV_Write_HdlCntIn  (2)
#define TPM2_NV_Write_HdlCntOut  (0)
#define TPM2_NV_Write_SessionCnt  (1)

typedef struct {
    TPM2B_MAX_NV_BUFFER                 data;
    UINT16                              offset;
} NV_Write_In;

typedef struct
{
    BYTE nothing;
} NV_Write_Out;

UINT16
TPM2_NV_Write_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_NV_Write_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_NV_Write_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_NV_Write_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_NV_WRITE_H

#ifndef _NV_WRITELOCK_H
#define _NV_WRITELOCK_H

#define TPM2_NV_WriteLock_HdlIn_AuthHandle (0)
#define TPM2_NV_WriteLock_HdlIn_NvIndex (1)
#define TPM2_NV_WriteLock_HdlCntIn  (2)
#define TPM2_NV_WriteLock_HdlCntOut  (0)
#define TPM2_NV_WriteLock_SessionCnt  (1)

typedef struct {
    BYTE nothing;
} NV_WriteLock_In;

typedef struct {
    BYTE nothing;
} NV_WriteLock_Out;

UINT16
TPM2_NV_WriteLock_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_NV_WriteLock_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_NV_WriteLock_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_NV_WriteLock_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_NV_WRITELOCK_H

#ifndef _OBJECTCHANGEAUTH_H
#define _OBJECTCHANGEAUTH_H

#define TPM2_ObjectChangeAuth_HdlIn_ObjectHandle  (0)
#define TPM2_ObjectChangeAuth_HdlIn_ParentHandle  (1)
#define TPM2_ObjectChangeAuth_HdlCntIn  (2)
#define TPM2_ObjectChangeAuth_HdlCntOut  (0)
#define TPM2_ObjectChangeAuth_SessionCnt  (1)

typedef struct {
    TPM2B_AUTH                          newAuth;
} ObjectChangeAuth_In;

typedef struct {
    TPM2B_PRIVATE                       outPrivate;
} ObjectChangeAuth_Out;

UINT16
TPM2_ObjectChangeAuth_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_ObjectChangeAuth_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_ObjectChangeAuth_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_ObjectChangeAuth_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_OBJECTCHANGEAUTH_H

#ifndef _PCR_ALLOCATE_H
#define _PCR_ALLOCATE_H

#define TPM2_PCR_Allocate_HdlIn_AuthHandle  (0)
#define TPM2_PCR_Allocate_HdlCntIn  (1)
#define TPM2_PCR_Allocate_HdlCntOut  (0)
#define TPM2_PCR_Allocate_SessionCnt  (1)

typedef struct {
    TPML_PCR_SELECTION                  pcrAllocation;
} PCR_Allocate_In;

typedef struct {
    TPMI_YES_NO                         allocationSuccess;
    UINT32                              maxPCR;
    UINT32                              sizeNeeded;
    UINT32                              sizeAvailable;
} PCR_Allocate_Out;

UINT16
TPM2_PCR_Allocate_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_PCR_Allocate_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_PCR_Allocate_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_PCR_Allocate_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_PCR_ALLOCATE_H

#ifndef _PCR_EVENT_H
#define _PCR_EVENT_H

#define TPM2_PCR_Event_HdlIn_PcrHandle  (0)
#define TPM2_PCR_Event_HdlCntIn  (1)
#define TPM2_PCR_Event_HdlCntOut  (0)
#define TPM2_PCR_Event_SessionCnt  (1)

typedef struct {
    TPM2B_EVENT                         eventData;
} PCR_Event_In;

typedef struct {
    TPML_DIGEST_VALUES                  digests;
} PCR_Event_Out;

UINT16
TPM2_PCR_Event_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_PCR_Event_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_PCR_Event_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_PCR_Event_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_PCR_EVENT_H

#ifndef _PCR_EXTEND_H
#define _PCR_EXTEND_H

#define TPM2_PCR_Extend_HdlIn_PcrHandle  (0)
#define TPM2_PCR_Extend_HdlCntIn  (1)
#define TPM2_PCR_Extend_HdlCntOut  (0)
#define TPM2_PCR_Extend_SessionCnt  (1)

typedef struct {
    TPML_DIGEST_VALUES                  digests;
} PCR_Extend_In;

typedef struct {
    BYTE nothing;
} PCR_Extend_Out;

UINT16
TPM2_PCR_Extend_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_PCR_Extend_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_PCR_Extend_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_PCR_Extend_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_PCR_EXTEND_H

#ifndef _PCR_READ_H
#define _PCR_READ_H

#define TPM2_PCR_Read_HdlCntIn  (0)
#define TPM2_PCR_Read_HdlCntOut  (0)
#define TPM2_PCR_Read_SessionCnt  (0)

typedef struct {
    TPML_PCR_SELECTION                  pcrSelectionIn;
} PCR_Read_In;

typedef struct {
    UINT32                              pcrUpdateCounter;
    TPML_PCR_SELECTION                  pcrSelectionOut;
    TPML_DIGEST                         pcrValues;
} PCR_Read_Out;

UINT16
TPM2_PCR_Read_Marshal(
    SESSION *sessionTable,
    UINT32 sessionCnt,
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

TPM_RC
TPM2_PCR_Read_Unmarshal(
    SESSION *sessionTable,
    UINT32 sessionCnt,
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

UINT16
TPM2_PCR_Read_Parameter_Marshal(
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

TPM_RC
TPM2_PCR_Read_Parameter_Unmarshal(
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

#endif //_PCR_READ_H

#ifndef _PCR_RESET_H
#define _PCR_RESET_H

#define TPM2_PCR_Reset_HdlIn_PcrHandle  (0)
#define TPM2_PCR_Reset_HdlCntIn  (1)
#define TPM2_PCR_Reset_HdlCntOut  (0)
#define TPM2_PCR_Reset_SessionCnt  (1)

typedef struct {
    BYTE nothing;
} PCR_Reset_In;

typedef struct {
    BYTE nothing;
} PCR_Reset_Out;

UINT16
TPM2_PCR_Reset_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_PCR_Reset_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_PCR_Reset_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_PCR_Reset_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_PCR_RESET_H

#ifndef _PCR_SETAUTHPOLICY_H
#define _PCR_SETAUTHPOLICY_H

#define TPM2_PCR_SetAuthPolicy_HdlIn_AuthHandle (0)
#define TPM2_PCR_SetAuthPolicy_HdlCntIn  (1)
#define TPM2_PCR_SetAuthPolicy_HdlCntOut  (0)
#define TPM2_PCR_SetAuthPolicy_SessionCnt  (1)

typedef struct {
    TPM2B_DIGEST                        authPolicy;
    TPMI_ALG_HASH                       policyDigest;
    TPMI_DH_PCR                         pcrNum;
} PCR_SetAuthPolicy_In;

typedef struct {
    BYTE nothing;
} PCR_SetAuthPolicy_Out;

UINT16
TPM2_PCR_SetAuthPolicy_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_PCR_SetAuthPolicy_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_PCR_SetAuthPolicy_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_PCR_SetAuthPolicy_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_PCR_SETAUTHPOLICY_H

#ifndef _PCR_SETAUTHVALUE_H
#define _PCR_SETAUTHVALUE_H

#define TPM2_PCR_SetAuthValue_HdlIn_PcrHandle (0)
#define TPM2_PCR_SetAuthValue_HdlCntIn  (1)
#define TPM2_PCR_SetAuthValue_HdlCntOut  (0)
#define TPM2_PCR_SetAuthValue_SessionCnt  (1)

typedef struct {
    TPM2B_DIGEST                        auth;
} PCR_SetAuthValue_In;

UINT16
TPM2_PCR_SetAuthValue_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_PCR_SetAuthValue_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_PCR_SetAuthValue_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_PCR_SetAuthValue_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_PCR_SETAUTHVALUE_H

#ifndef _POLICYAUTHORIZE_H
#define _POLICYAUTHORIZE_H

#define TPM2_PolicyAuthorize_HdlIn_PolicySession  (0)
#define TPM2_PolicyAuthorize_HdlCntIn  (1)
#define TPM2_PolicyAuthorize_HdlCntOut  (0)
#define TPM2_PolicyAuthorize_SessionCnt  (0)

typedef struct
{
    TPM2B_DIGEST                        approvedPolicy;
    TPM2B_NONCE                         policyRef;
    TPM2B_NAME                          keySign;
    TPMT_TK_VERIFIED                    checkTicket;
} PolicyAuthorize_In;

typedef struct
{
    BYTE nothing;
} PolicyAuthorize_Out;

UINT16
TPM2_PolicyAuthorize_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_PolicyAuthorize_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_PolicyAuthorize_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_PolicyAuthorize_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

void
TPM2_PolicyAuthorize_CalculateUpdate(
TPM_ALG_ID hashAlg,
TPM2B_DIGEST *policyDigest,
PolicyAuthorize_In *policyAuthorizeIn
);

#endif //_POLICYAUTHORIZE_H

#ifndef _POLICYAUTHVALUE_H
#define _POLICYAUTHVALUE_H

#define TPM2_PolicyAuthValue_HdlIn_PolicySession  (0)
#define TPM2_PolicyAuthValue_HdlCntIn  (1)
#define TPM2_PolicyAuthValue_HdlCntOut  (0)
#define TPM2_PolicyAuthValue_SessionCnt  (0)

typedef struct {
    BYTE nothing;
} PolicyAuthValue_In;

typedef struct
{
    BYTE nothing;
} PolicyAuthValue_Out;

UINT16
TPM2_PolicyAuthValue_Marshal(
    SESSION *sessionTable,
    UINT32 sessionCnt,
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

TPM_RC
TPM2_PolicyAuthValue_Unmarshal(
    SESSION *sessionTable,
    UINT32 sessionCnt,
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

UINT16
TPM2_PolicyAuthValue_Parameter_Marshal(
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

TPM_RC
TPM2_PolicyAuthValue_Parameter_Unmarshal(
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

void
TPM2_PolicyAuthValue_CalculateUpdate(
    TPM_ALG_ID hashAlg,
    TPM2B_DIGEST *policyDigest,
    PolicyAuthValue_In *policyAuthValue_In
);

#endif //_POLICYAUTHVALUE_H

#ifndef _POLICYCOMMANDCODE_H
#define _POLICYCOMMANDCODE_H

#define TPM2_PolicyCommandCode_HdlIn_PolicySession  (0)
#define TPM2_PolicyCommandCode_HdlCntIn  (1)
#define TPM2_PolicyCommandCode_HdlCntOut  (0)
#define TPM2_PolicyCommandCode_SessionCnt  (0)

typedef struct {
    TPM_CC                              code;
} PolicyCommandCode_In;

typedef struct
{
    BYTE nothing;
} PolicyCommandCode_Out;

UINT16
TPM2_PolicyCommandCode_Marshal(
    SESSION *sessionTable,
    UINT32 sessionCnt,
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

TPM_RC
TPM2_PolicyCommandCode_Unmarshal(
    SESSION *sessionTable,
    UINT32 sessionCnt,
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

UINT16
TPM2_PolicyCommandCode_Parameter_Marshal(
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

TPM_RC
TPM2_PolicyCommandCode_Parameter_Unmarshal(
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

void
TPM2_PolicyCommandCode_CalculateUpdate(
    TPM_ALG_ID hashAlg,
    TPM2B_DIGEST *policyDigest,
    PolicyCommandCode_In *policyCommandCodeIn
);

#endif //_POLICYCOMMANDCODE_H

#ifndef _POLICYCOUNTERTIMER_H
#define _POLICYCOUNTERTIMER_H

#define TPM2_PolicyCounterTimer_HdlIn_PolicySession  (0)
#define TPM2_PolicyCounterTimer_HdlCntIn  (1)
#define TPM2_PolicyCounterTimer_HdlCntOut  (0)
#define TPM2_PolicyCounterTimer_SessionCnt  (0)

typedef struct {
    TPM2B_OPERAND                       operandB;
    UINT16                              offset;
    TPM_EO                              operation;
} PolicyCounterTimer_In;

typedef struct {
    BYTE nothing;
} PolicyCounterTimer_Out;

UINT16
TPM2_PolicyCounterTimer_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_PolicyCounterTimer_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_PolicyCounterTimer_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_PolicyCounterTimer_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

void
TPM2_PolicyCounterTimer_CalculateUpdate(
TPM_ALG_ID hashAlg,
TPM2B_DIGEST *policyDigest,
PolicyCounterTimer_In *policyCounterTimer_In
);

#endif //_POLICYCOUNTERTIMER_H

#ifndef _POLICYCPHASH_H
#define _POLICYCPHASH_H

#define TPM2_PolicyCpHash_HdlIn_PolicySession  (0)
#define TPM2_PolicyCpHash_HdlCntIn  (1)
#define TPM2_PolicyCpHash_HdlCntOut  (0)
#define TPM2_PolicyCpHash_SessionCnt  (0)

typedef struct {
    TPM2B_DIGEST                        cpHashA;
} PolicyCpHash_In;

typedef struct {
    BYTE nothing;
} PolicyCpHash_Out;

UINT16
TPM2_PolicyCpHash_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_PolicyCpHash_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_PolicyCpHash_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_PolicyCpHash_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

void
TPM2_PolicyCpHash_CalculateUpdate(
TPM_ALG_ID hashAlg,
TPM2B_DIGEST *policyDigest,
PolicyCpHash_In *policyCpHash_In
);

#endif //_POLICYCPHASH_H

#ifndef _POLICYDUPLICATIONSELECT_H
#define _POLICYDUPLICATIONSELECT_H

#define TPM2_PolicyDuplicationSelect_HdlIn_PolicySession  (0)
#define TPM2_PolicyDuplicationSelect_HdlCntIn  (1)
#define TPM2_PolicyDuplicationSelect_HdlCntOut  (0)
#define TPM2_PolicyDuplicationSelect_SessionCnt  (0)

typedef struct {
    TPM2B_NAME                          objectName;
    TPM2B_NAME                          newParentName;
    TPMI_YES_NO                         includeObject;
} PolicyDuplicationSelect_In;

typedef struct
{
    BYTE nothing;
} PolicyDuplicationSelect_Out;

UINT16
TPM2_PolicyDuplicationSelect_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_PolicyDuplicationSelect_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_PolicyDuplicationSelect_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_PolicyDuplicationSelect_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

void
TPM2_PolicyDuplicationSelect_CalculateUpdate(
TPM_ALG_ID hashAlg,
TPM2B_DIGEST *policyDigest,
PolicyDuplicationSelect_In *policyCommandCodeIn
);

#endif //_POLICYDUPLICATIONSELECT_H

#ifndef _POLICYGETDIGEST_H
#define _POLICYGETDIGEST_H

#define TPM2_PolicyGetDigest_HdlIn_PolicySession  (0)
#define TPM2_PolicyGetDigest_HdlCntIn  (1)
#define TPM2_PolicyGetDigest_HdlCntOut  (0)
#define TPM2_PolicyGetDigest_SessionCnt  (0)

typedef struct {
    BYTE nothing;
} PolicyGetDigest_In;

typedef struct {
    TPM2B_DIGEST                        policyDigest;
} PolicyGetDigest_Out;

UINT16
TPM2_PolicyGetDigest_Marshal(
    SESSION *sessionTable,
    UINT32 sessionCnt,
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

TPM_RC
TPM2_PolicyGetDigest_Unmarshal(
    SESSION *sessionTable,
    UINT32 sessionCnt,
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

UINT16
TPM2_PolicyGetDigest_Parameter_Marshal(
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

TPM_RC
TPM2_PolicyGetDigest_Parameter_Unmarshal(
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

#endif //_POLICYGETDIGEST_H

#ifndef _POLICYLOCALITY_H
#define _POLICYLOCALITY_H

#define TPM2_PolicyLocality_HdlIn_PolicySession  (0)
#define TPM2_PolicyLocality_HdlCntIn  (1)
#define TPM2_PolicyLocality_HdlCntOut  (0)
#define TPM2_PolicyLocality_SessionCnt  (0)

typedef struct {
    TPMA_LOCALITY                       locality;
} PolicyLocality_In;

typedef struct {
    BYTE nothing;
} PolicyLocality_Out;

UINT16
TPM2_PolicyLocality_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_PolicyLocality_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_PolicyLocality_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_PolicyLocality_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

void
TPM2_PolicyLocality_CalculateUpdate(
TPM_ALG_ID hashAlg,
TPM2B_DIGEST *policyDigest,
PolicyLocality_In *policyLocality_In
);

#endif //_POLICYLOCALITY_H

#ifndef _POLICYNAMEHASH_H
#define _POLICYNAMEHASH_H

#define TPM2_PolicyNameHash_HdlIn_PolicySession  (0)
#define TPM2_PolicyNameHash_HdlCntIn  (1)
#define TPM2_PolicyNameHash_HdlCntOut  (0)
#define TPM2_PolicyNameHash_SessionCnt  (0)

typedef struct {
    TPMI_SH_POLICY                      policySession;
    TPM2B_DIGEST                        nameHash;
} PolicyNameHash_In;

typedef struct {
    BYTE nothing;
} PolicyNameHash_Out;

UINT16
TPM2_PolicyNameHash_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_PolicyNameHash_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_PolicyNameHash_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_PolicyNameHash_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

void
TPM2_PolicyNameHash_CalculateUpdate(
TPM_ALG_ID hashAlg,
TPM2B_DIGEST *policyDigest,
PolicyNameHash_In *policyNameHash_In
);

#endif //_POLICYNAMEHASH_H

#ifndef _POLICYNV_H
#define _POLICYNV_H

#define TPM2_PolicyNV_HdlIn_AuthHandle  (0)
#define TPM2_PolicyNV_HdlIn_NvIndex  (1)
#define TPM2_PolicyNV_HdlIn_PolicySession  (2)
#define TPM2_PolicyNV_HdlCntIn  (3)
#define TPM2_PolicyNV_HdlCntOut  (0)
#define TPM2_PolicyNV_SessionCnt  (1)

typedef struct {
    TPM2B_OPERAND                       operandB;
    UINT16                              offset;
    TPM_EO                              operation;
} PolicyNV_In;

typedef struct {
    BYTE nothing;
} PolicyNV_Out;

UINT16
TPM2_PolicyNV_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_PolicyNV_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_PolicyNV_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_PolicyNV_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

void
TPM2_PolicyNV_CalculateUpdate(
TPM_ALG_ID hashAlg,
TPM2B_DIGEST *policyDigest,
PolicyNV_In *policyNV_In,
TPM2B_NAME *nvName
);

#endif //_POLICYNV_H

#ifndef _POLICYOR_H
#define _POLICYOR_H

#define TPM2_PolicyOR_HdlIn_PolicySession  (0)
#define TPM2_PolicyOR_HdlCntIn  (1)
#define TPM2_PolicyOR_HdlCntOut  (0)
#define TPM2_PolicyOR_SessionCnt  (0)

typedef struct {
    TPML_DIGEST                         pHashList;
} PolicyOR_In;

typedef struct
{
    BYTE nothing;
} PolicyOR_Out;

UINT16
TPM2_PolicyOR_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_PolicyOR_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_PolicyOR_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_PolicyOR_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

void
TPM2_PolicyOR_CalculateUpdate(
TPM_ALG_ID hashAlg,
TPM2B_DIGEST *policyDigest,
PolicyOR_In *policyORIn
);

#endif //_POLICYOR_H

#ifndef _POLICYPASSWORD_H
#define _POLICYPASSWORD_H

#define TPM2_PolicyPassword_HdlIn_PolicySession  (0)
#define TPM2_PolicyPassword_HdlCntIn  (1)
#define TPM2_PolicyPassword_HdlCntOut  (0)
#define TPM2_PolicyPassword_SessionCnt  (0)

typedef struct {
    BYTE nothing;
} PolicyPassword_In;

typedef struct {
    BYTE nothing;
} PolicyPassword_Out;

UINT16
TPM2_PolicyPassword_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_PolicyPassword_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_PolicyPassword_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_PolicyPassword_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

void
TPM2_PolicyPassword_CalculateUpdate(
TPM_ALG_ID hashAlg,
TPM2B_DIGEST *policyDigest,
PolicyPassword_In *policyPassword_In
);

#endif //_POLICYPASSWORD_H

#ifndef _POLICYPCR_H
#define _POLICYPCR_H

#define TPM2_PolicyPCR_HdlIn_PolicySession  (0)
#define TPM2_PolicyPCR_HdlCntIn  (1)
#define TPM2_PolicyPCR_HdlCntOut  (0)
#define TPM2_PolicyPCR_SessionCnt  (0)

typedef struct {
    TPM2B_DIGEST                        pcrDigest;
    TPML_PCR_SELECTION                  pcrs;
} PolicyPCR_In;

typedef struct {
    BYTE nothing;
} PolicyPCR_Out;

UINT16
TPM2_PolicyPCR_Marshal(
    SESSION *sessionTable,
    UINT32 sessionCnt,
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

TPM_RC
TPM2_PolicyPCR_Unmarshal(
    SESSION *sessionTable,
    UINT32 sessionCnt,
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

UINT16
TPM2_PolicyPCR_Parameter_Marshal(
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

TPM_RC
TPM2_PolicyPCR_Parameter_Unmarshal(
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

void
TPM2_PolicyPCR_CalculateUpdate(
    TPM_ALG_ID hashAlg,
    TPM2B_DIGEST *policyDigest,
    PolicyPCR_In *policyPCRIn
);

#endif //_POLICYPCR_H

#ifndef _POLICYPHYSICALPRESENCE_H
#define _POLICYPHYSICALPRESENCE_H

#define TPM2_PolicyPhysicalPresence_HdlIn_PolicySession  (0)
#define TPM2_PolicyPhysicalPresence_HdlCntIn  (1)
#define TPM2_PolicyPhysicalPresence_HdlCntOut  (0)
#define TPM2_PolicyPhysicalPresence_SessionCnt  (0)

typedef struct {
    TPMI_SH_POLICY                      policySession;
} PolicyPhysicalPresence_In;

typedef struct {
    BYTE nothing;
} PolicyPhysicalPresence_Out;

UINT16
TPM2_PolicyPhysicalPresence_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_PolicyPhysicalPresence_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_PolicyPhysicalPresence_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_PolicyPhysicalPresence_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

void
TPM2_PolicyPhysicalPresence_CalculateUpdate(
TPM_ALG_ID hashAlg,
TPM2B_DIGEST *policyDigest,
PolicyPhysicalPresence_In *policyPhysicalPresenceIn
);

#endif //_POLICYPHYSICALPRESENCE_H

#ifndef _POLICYRESTART_H
#define _POLICYRESTART_H

#define TPM2_PolicyRestart_HdlIn_SessionHandle  (0)
#define TPM2_PolicyRestart_HdlCntIn  (1)
#define TPM2_PolicyRestart_HdlCntOut  (0)
#define TPM2_PolicyRestart_SessionCnt  (0)

typedef struct {
    BYTE nothing;
} PolicyRestart_In;

typedef struct
{
    BYTE nothing;
} PolicyRestart_Out;

UINT16
TPM2_PolicyRestart_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_PolicyRestart_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_PolicyRestart_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_PolicyRestart_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_POLICYRESTART_H

#ifndef _POLICYRESTART_H
#define _POLICYRESTART_H

#define TPM2_PolicyRestart_HdlIn_SessionHandle  (0)
#define TPM2_PolicyRestart_HdlCntIn  (1)
#define TPM2_PolicyRestart_HdlCntOut  (0)
#define TPM2_PolicyRestart_SessionCnt  (0)

typedef struct {
    BYTE nothing;
} PolicyRestart_In;

typedef struct
{
    BYTE nothing;
} PolicyRestart_Out;

UINT16
TPM2_PolicyRestart_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_PolicyRestart_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_PolicyRestart_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_PolicyRestart_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_POLICYRESTART_H

#ifndef _POLICYSECRET_H
#define _POLICYSECRET_H

#define TPM2_PolicySecret_HdlIn_AuthHandle (0)
#define TPM2_PolicySecret_HdlIn_PolicySession  (1)
#define TPM2_PolicySecret_HdlCntIn  (2)
#define TPM2_PolicySecret_HdlCntOut  (0)
#define TPM2_PolicySecret_SessionCnt  (1)

typedef struct {
    TPM2B_NONCE                         nonceTPM;
    TPM2B_DIGEST                        cpHashA;
    TPM2B_NONCE                         policyRef;
    UINT32                              expiration;
} PolicySecret_In;

typedef struct {
    TPM2B_TIMEOUT                       timeout;
    TPMT_TK_AUTH                        policyTicket;
} PolicySecret_Out;

UINT16
TPM2_PolicySecret_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_PolicySecret_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_PolicySecret_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_PolicySecret_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

void
TPM2_PolicySecret_CalculateUpdate(
TPM_ALG_ID hashAlg,
TPM2B_DIGEST *policyDigest,
PolicySecret_In *policySecret_In,
TPM2B_NAME *name
);

#endif //_POLICYSECRET_H

#ifndef _POLICYSIGNED_H
#define _POLICYSIGNED_H

#define TPM2_PolicySigned_HdlIn_AuthObject  (0)
#define TPM2_PolicySigned_HdlIn_PolicySession  (1)
#define TPM2_PolicySigned_HdlCntIn  (2)
#define TPM2_PolicySigned_HdlCntOut  (0)
#define TPM2_PolicySigned_SessionCnt  (0)

typedef struct {
    TPM2B_NONCE                         nonceTPM;
    TPM2B_DIGEST                        cpHashA;
    TPM2B_NONCE                         policyRef;
    UINT32                              expiration;
    TPMT_SIGNATURE                      auth;
} PolicySigned_In;

typedef struct {
    TPM2B_TIMEOUT                       timeout;
    TPMT_TK_AUTH                        policyTicket;
} PolicySigned_Out;

UINT16
TPM2_PolicySigned_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_PolicySigned_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_PolicySigned_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_PolicySigned_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

void
TPM2_PolicySigned_CalculateUpdate(
TPM_ALG_ID hashAlg,
TPM2B_DIGEST *policyDigest,
PolicySigned_In *policySigned_In,
TPM2B_NAME *authObjectName
);

#endif //_POLICYSIGNED_H

#ifndef _POLICYTICKET_H
#define _POLICYTICKET_H

#define TPM2_PolicyTicket_HdlIn_PolicySession  (0)
#define TPM2_PolicyTicket_HdlCntIn  (1)
#define TPM2_PolicyTicket_HdlCntOut  (0)
#define TPM2_PolicyTicket_SessionCnt  (0)

typedef struct {
    TPM2B_TIMEOUT                       timeout;
    TPM2B_DIGEST                        cpHashA;
    TPM2B_NONCE                         policyRef;
    TPM2B_NAME                          authName;
    TPMT_TK_AUTH                        ticket;
} PolicyTicket_In;

typedef struct {
    BYTE nothing;
} PolicyTicket_Out;

UINT16
TPM2_PolicyTicket_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_PolicyTicket_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_PolicyTicket_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_PolicyTicket_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

void
TPM2_PolicyTicket_CalculateUpdate(
TPM_ALG_ID hashAlg,
TPM2B_DIGEST *policyDigest,
PolicyTicket_In *policyTicket_In
);

#endif //_POLICYTICKET_H

#ifndef _PP_COMMANDS_H
#define _PP_COMMANDS_H

#define TPM2_PP_Commands_HdlIn_Auth  (0)
#define TPM2_PP_Commands_HdlCntIn  (1)
#define TPM2_PP_Commands_HdlCntOut  (0)
#define TPM2_PP_Commands_SessionCnt  (1)

typedef struct {
    TPML_CC                             setList;
    TPML_CC                             clearList;
} PP_Commands_In;

typedef struct {
    BYTE nothing;
} PP_Commands_Out;

UINT16
TPM2_PP_Commands_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_PP_Commands_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_PP_Commands_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_PP_Commands_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_PP_COMMANDS_H

#ifndef _QUOTE_H
#define _QUOTE_H

#define TPM2_Quote_HdlIn_SignHandle (0)
#define TPM2_Quote_HdlCntIn  (1)
#define TPM2_Quote_HdlCntOut  (0)
#define TPM2_Quote_SessionCnt  (1)

typedef struct {
    TPM2B_DATA                          qualifyingData;
    TPMT_SIG_SCHEME                     inScheme;
    TPML_PCR_SELECTION                  PCRselect;
} Quote_In;

typedef struct {
    TPM2B_ATTEST                        quoted;
    TPMT_SIGNATURE                      signature;
} Quote_Out;

UINT16
TPM2_Quote_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_Quote_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_Quote_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_Quote_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_QUOTE_H

#ifndef _READCLOCK_H
#define _READCLOCK_H

#define TPM2_ReadClock_HdlCntIn  (0)
#define TPM2_ReadClock_HdlCntOut  (0)
#define TPM2_ReadClock_SessionCnt  (0)

typedef struct {
    BYTE nothing;
} ReadClock_In;

typedef struct {
    TPMS_TIME_INFO                      currentTime;
} ReadClock_Out;

UINT16
TPM2_ReadClock_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_ReadClock_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_ReadClock_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_ReadClock_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_READCLOCK_H

#ifndef _READPUBLIC_H
#define _READPUBLIC_H

#define TPM2_ReadPublic_HdlIn_PublicKey  (0)
#define TPM2_ReadPublic_HdlCntIn  (1)
#define TPM2_ReadPublic_HdlCntOut  (0)
#define TPM2_ReadPublic_SessionCnt  (0)

typedef struct {
    BYTE nothing;
} ReadPublic_In;

typedef struct {
    TPM2B_PUBLIC                        outPublic;
    TPM2B_NAME                          name;
    TPM2B_NAME                          qualifiedName;
} ReadPublic_Out;

UINT16
TPM2_ReadPublic_Marshal(
    SESSION *sessionTable,
    UINT32 sessionCnt,
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

TPM_RC
TPM2_ReadPublic_Unmarshal(
    SESSION *sessionTable,
    UINT32 sessionCnt,
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

UINT16
TPM2_ReadPublic_Parameter_Marshal(
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

TPM_RC
TPM2_ReadPublic_Parameter_Unmarshal(
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

#endif //_READPUBLIC_H

#ifndef _REWRAP_H
#define _REWRAP_H

#define TPM2_Rewrap_HdlIn_OldParent  (0)
#define TPM2_Rewrap_HdlIn_NewParent  (1)
#define TPM2_Rewrap_HdlCntIn  (2)
#define TPM2_Rewrap_HdlCntOut  (0)
#define TPM2_Rewrap_SessionCnt  (1)

typedef struct {
    TPM2B_PRIVATE                       inDuplicate;
    TPM2B_NAME                          name;
    TPM2B_ENCRYPTED_SECRET              inSymSeed;
} Rewrap_In;

typedef struct {
    TPM2B_PRIVATE                       outDuplicate;
    TPM2B_ENCRYPTED_SECRET              outSymSeed;
} Rewrap_Out;

UINT16
TPM2_Rewrap_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_Rewrap_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_Rewrap_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_Rewrap_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_REWRAP_H

#ifndef _RSA_DECRYPT_H
#define _RSA_DECRYPT_H

#define TPM2_RSA_Decrypt_HdlIn_KeyHandle  (0)
#define TPM2_RSA_Decrypt_HdlCntIn  (1)
#define TPM2_RSA_Decrypt_HdlCntOut  (0)
#define TPM2_RSA_Decrypt_SessionCnt  (1)

typedef struct {
    TPM2B_PUBLIC_KEY_RSA                cipherText;
    TPMT_RSA_DECRYPT                    inScheme;
    TPM2B_DATA                          label;
} RSA_Decrypt_In;

typedef struct {
    TPM2B_PUBLIC_KEY_RSA                message;
} RSA_Decrypt_Out;

UINT16
TPM2_RSA_Decrypt_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_RSA_Decrypt_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_RSA_Decrypt_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_RSA_Decrypt_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_RSA_DECRYPT_H

#ifndef _RSA_ENCRYPT_H
#define _RSA_ENCRYPT_H

#define TPM2_RSA_Encrypt_HdlIn_KeyHandle  (0)
#define TPM2_RSA_Encrypt_HdlCntIn  (1)
#define TPM2_RSA_Encrypt_HdlCntOut  (0)
#define TPM2_RSA_Encrypt_SessionCnt  (0)

typedef struct {
    TPM2B_PUBLIC_KEY_RSA                message;
    TPMT_RSA_DECRYPT                    inScheme;
    TPM2B_DATA                          label;
} RSA_Encrypt_In;

typedef struct {
    TPM2B_PUBLIC_KEY_RSA                outData;
} RSA_Encrypt_Out;

UINT16
TPM2_RSA_Encrypt_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_RSA_Encrypt_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_RSA_Encrypt_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_RSA_Encrypt_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_RSA_ENCRYPT_H

#ifndef _SELFTEST_H
#define _SELFTEST_H

#define TPM2_SelfTest_HdlCntIn  (0)
#define TPM2_SelfTest_HdlCntOut  (0)
#define TPM2_SelfTest_SessionCnt  (0)

typedef struct {
    TPMI_YES_NO                         fullTest;
} SelfTest_In;

typedef struct {
    BYTE nothing;
} SelfTest_Out;

UINT16
TPM2_SelfTest_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_SelfTest_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_SelfTest_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_SelfTest_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_SELFTEST_H

#ifndef _SEQUENCECOMPLETE_H
#define _SEQUENCECOMPLETE_H

#define TPM2_SequenceComplete_HdlIn_SequenceHandle  (0)
#define TPM2_SequenceComplete_HdlCntIn  (1)
#define TPM2_SequenceComplete_HdlCntOut  (0)
#define TPM2_SequenceComplete_SessionCnt  (1)

typedef struct {
    TPM2B_MAX_BUFFER                    buffer;
    TPMI_RH_HIERARCHY                   hierarchy;
} SequenceComplete_In;

typedef struct {
    TPM2B_DIGEST                        result;
    TPMT_TK_HASHCHECK                   validation;
} SequenceComplete_Out;

UINT16
TPM2_SequenceComplete_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_SequenceComplete_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_SequenceComplete_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_SequenceComplete_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_SEQUENCECOMPLETE_H


#ifndef _SEQUENCEUPDATE_H
#define _SEQUENCEUPDATE_H

#define TPM2_SequenceUpdate_HdlIn_SequenceHandle  (0)
#define TPM2_SequenceUpdate_HdlCntIn  (1)
#define TPM2_SequenceUpdate_HdlCntOut  (0)
#define TPM2_SequenceUpdate_SessionCnt  (1)

typedef struct {
    TPM2B_MAX_BUFFER                    buffer;
} SequenceUpdate_In;

typedef struct {
    BYTE nothing;
} SequenceUpdate_Out;

UINT16
TPM2_SequenceUpdate_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_SequenceUpdate_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_SequenceUpdate_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_SequenceUpdate_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_SEQUENCEUPDATE_H

#ifndef _SETALGORITHMSET_H
#define _SETALGORITHMSET_H

#define TPM2_SetAlgorithmSet_HdlIn_AuthHandle  (0)
#define TPM2_SetAlgorithmSet_HdlCntIn  (1)
#define TPM2_SetAlgorithmSet_HdlCntOut  (0)
#define TPM2_SetAlgorithmSet_SessionCnt  (1)

typedef struct {
    UINT32                              algorithmSet;
} SetAlgorithmSet_In;

typedef struct {
    BYTE nothing;
} SetAlgorithmSet_Out;

UINT16
TPM2_SetAlgorithmSet_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_SetAlgorithmSet_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_SetAlgorithmSet_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_SetAlgorithmSet_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_SETALGORITHMSET_H

#ifndef _SETCOMMANDCODEAUDITSTATUS_H
#define _SETCOMMANDCODEAUDITSTATUS_H

#define TPM2_SetCommandCodeAuditStatus_HdlIn_Auth  (0)
#define TPM2_SetCommandCodeAuditStatus_HdlCntIn  (1)
#define TPM2_SetCommandCodeAuditStatus_HdlCntOut  (0)
#define TPM2_SetCommandCodeAuditStatus_SessionCnt  (1)

typedef struct {
    TPMI_ALG_HASH                       auditAlg;
    TPML_CC                             setList;
    TPML_CC                             clearList;
} SetCommandCodeAuditStatus_In;

UINT16
TPM2_SetCommandCodeAuditStatus_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_SetCommandCodeAuditStatus_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_SetCommandCodeAuditStatus_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_SetCommandCodeAuditStatus_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_SETCOMMANDCODEAUDITSTATUS_H

#ifndef _SETPRIMARYPOLICY_H
#define _SETPRIMARYPOLICY_H

#define TPM2_SetPrimaryPolicy_HdlIn_Auth  (0)
#define TPM2_SetPrimaryPolicy_HdlCntIn  (1)
#define TPM2_SetPrimaryPolicy_HdlCntOut  (0)
#define TPM2_SetPrimaryPolicy_SessionCnt  (1)

typedef struct {
    TPMI_RH_HIERARCHY                   authHandle;
    TPM2B_DIGEST                        authPolicy;
    TPMI_ALG_HASH                       hashAlg;
} SetPrimaryPolicy_In;

typedef struct {
    BYTE nothing;
} SetPrimaryPolicy_Out;

UINT16
TPM2_SetPrimaryPolicy_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_SetPrimaryPolicy_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_SetPrimaryPolicy_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_SetPrimaryPolicy_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_SETPRIMARYPOLICY_H

#ifndef _SHUTDOWN_H
#define _SHUTDOWN_H

#define TPM2_Shutdown_HdlCntIn  (0)
#define TPM2_Shutdown_HdlCntOut  (0)
#define TPM2_Shutdown_SessionCnt  (0)

typedef struct {
    TPM_SU                              shutdownType;
} Shutdown_In;

typedef struct {
    BYTE nothing;
} Shutdown_Out;

UINT16
TPM2_Shutdown_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_Shutdown_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_Shutdown_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_Shutdown_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_SHUTDOWN_H

#ifndef _SIGN_H
#define _SIGN_H

#define TPM2_Sign_HdlIn_KeyHandle  (0)
#define TPM2_Sign_HdlCntIn  (1)
#define TPM2_Sign_HdlCntOut  (0)
#define TPM2_Sign_SessionCnt  (1)

typedef struct {
    TPM2B_DIGEST                        digest;
    TPMT_SIG_SCHEME                     inScheme;
    TPMT_TK_HASHCHECK                   validation;
} Sign_In;

typedef struct {
    TPMT_SIGNATURE                      signature;
} Sign_Out;

UINT16
TPM2_Sign_Marshal(
    SESSION *sessionTable,
    UINT32 sessionCnt,
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

TPM_RC
TPM2_Sign_Unmarshal(
    SESSION *sessionTable,
    UINT32 sessionCnt,
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

UINT16
TPM2_Sign_Parameter_Marshal(
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

TPM_RC
TPM2_Sign_Parameter_Unmarshal(
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

#endif //_SIGN_H

#ifndef _STARTAUTHSESSION_H
#define _STARTAUTHSESSION_H

#define TPM2_StartAuthSession_HdlIn_TpmKey  (0)
#define TPM2_StartAuthSession_HdlIn_Bind  (1)
#define TPM2_StartAuthSession_HdlCntIn  (2)
#define TPM2_StartAuthSession_HdlOut_SessionHandle  (0)
#define TPM2_StartAuthSession_HdlCntOut  (1)
#define TPM2_StartAuthSession_SessionCnt  (0)

typedef struct {
    TPM2B_NONCE                         nonceCaller;
    TPM2B_DATA                          salt; 
    TPM2B_ENCRYPTED_SECRET              encryptedSalt;
    TPM_SE                              sessionType;
    TPMT_SYM_DEF                        symmetric;
    TPMI_ALG_HASH                       authHash;
} StartAuthSession_In;

typedef struct {
    TPM2B_NONCE                         nonceTPM;
} StartAuthSession_Out;

UINT16
TPM2_StartAuthSession_Marshal(
    SESSION *sessionTable,
    UINT32 sessionCnt,
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

TPM_RC
TPM2_StartAuthSession_Unmarshal(
    SESSION *sessionTable,
    UINT32 sessionCnt,
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

UINT16
TPM2_StartAuthSession_Parameter_Marshal(
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

TPM_RC
TPM2_StartAuthSession_Parameter_Unmarshal(
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
);

#endif //_STARTAUTHSESSION_H

#ifndef _STARTUP_H
#define _STARTUP_H

#define TPM2_Startup_HdlCntIn  (0)
#define TPM2_Startup_HdlCntOut  (0)
#define TPM2_Startup_SessionCnt  (0)

typedef struct {
    TPM_SU                              startupType;
} Startup_In;

typedef struct {
    BYTE nothing;
} Startup_Out;

UINT16
TPM2_Startup_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_Startup_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_Startup_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_Startup_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_STARTUP_H

#ifndef _STIRRANDOM_H
#define _STIRRANDOM_H

#define TPM2_StirRandom_HdlIn_PublicKey  (0)
#define TPM2_StirRandom_HdlCntIn  (0)
#define TPM2_StirRandom_HdlCntOut  (0)
#define TPM2_StirRandom_SessionCnt  (0)

typedef struct {
    TPM2B_SENSITIVE_DATA                inData;
} StirRandom_In;

typedef struct {
    BYTE nothing;
} StirRandom_Out;

UINT16
TPM2_StirRandom_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_StirRandom_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_StirRandom_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_StirRandom_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_STIRRANDOM_H

#ifndef _TESTPARMS_H
#define _TESTPARMS_H

#define TPM2_TestParms_HdlCntIn  (0)
#define TPM2_TestParms_HdlCntOut  (0)
#define TPM2_TestParms_SessionCnt  (0)

typedef struct {
    TPMT_PUBLIC_PARMS                   parameters;
} TestParms_In;

typedef struct {
    BYTE nothing;
} TestParms_Out;

UINT16
TPM2_TestParms_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_TestParms_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_TestParms_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_TestParms_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_TESTPARMS_H

#ifndef _UNSEAL_H
#define _UNSEAL_H

#define TPM2_Unseal_HdlIn_ItemHandle  (0)
#define TPM2_Unseal_HdlCntIn  (1)
#define TPM2_Unseal_HdlCntOut  (0)
#define TPM2_Unseal_SessionCnt  (1)

typedef struct {
    BYTE nothing;
} Unseal_In;

typedef struct {
    TPM2B_SENSITIVE_DATA                outData;
} Unseal_Out;

UINT16
TPM2_Unseal_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_Unseal_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_Unseal_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_Unseal_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_UNSEAL_H

#ifndef _VERIFYSIGNATURE_H
#define _VERIFYSIGNATURE_H

#define TPM2_VerifySignature_HdlIn_KeyHandle  (0)
#define TPM2_VerifySignature_HdlCntIn  (1)
#define TPM2_VerifySignature_HdlCntOut  (0)
#define TPM2_VerifySignature_SessionCnt  (0)

typedef struct {
    TPM2B_DIGEST                        digest;
    TPMT_SIGNATURE                      signature;
} VerifySignature_In;

typedef struct {
    TPMT_TK_VERIFIED                    validation;
} VerifySignature_Out;

UINT16
TPM2_VerifySignature_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_VerifySignature_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_VerifySignature_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_VerifySignature_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_VERIFYSIGNATURE_H

#ifndef _ZGEN_2PHASE_H
#define _ZGEN_2PHASE_H

#define TPM2_ZGen_2Phase_HdlIn_KeyA  (0)
#define TPM2_ZGen_2Phase_HdlCntIn  (1)
#define TPM2_ZGen_2Phase_HdlCntOut  (0)
#define TPM2_ZGen_2Phase_SessionCnt  (1)

typedef struct {
    TPM2B_ECC_POINT                     inQsB;
    TPM2B_ECC_POINT                     inQeB;
    TPMI_ECC_KEY_EXCHANGE               inScheme;
    UINT16                              counter;
} ZGen_2Phase_In;

typedef struct {
    TPM2B_ECC_POINT                     outZ1;
    TPM2B_ECC_POINT                     outZ2;
} ZGen_2Phase_Out;

UINT16
TPM2_ZGen_2Phase_Marshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_ZGen_2Phase_Unmarshal(
SESSION *sessionTable,
UINT32 sessionCnt,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

UINT16
TPM2_ZGen_2Phase_Parameter_Marshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
TPM2_ZGen_2Phase_Parameter_Unmarshal(
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#endif //_ZGEN_2PHASE_H

UINT16
Command_Marshal(
TPM_CC command_code,
SESSION *sessionTable,
UINT32 sessionCnt,
Parameter_Marshal_fp Parameter_Marshal,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

TPM_RC
Command_Unmarshal(
TPM_CC command_code,
SESSION *sessionTable,
UINT32 sessionCnt,
Parameter_Unmarshal_fp Parameter_Unmarshal,
Marshal_Parms *parms,
BYTE **buffer,
INT32 *size
);

#define DEFINE_CALL_BUFFERS \
    BYTE pbCmd[2048] = { 0 }; \
    UINT32 cbCmd = 0; \
    BYTE pbRsp[2048] = { 0 }; \
    UINT32 cbRsp = 0; \
    BYTE *buffer = pbCmd; \
    INT32 size = sizeof(pbCmd); \
    Marshal_Parms parms = { 0 }; \
    SESSION sessionTable[MAX_HANDLE_NUM] = { 0 }; \
    for(uint8_t n = 0; n < MAX_HANDLE_NUM; n++) sessionTable[n].handle = TPM_RS_PW; \
    UINT32 sessionCnt = 0; \

#define INITIALIZE_CALL_BUFFERS(__CommandType, __InParm, __OutParm) \
    sessionCnt = __CommandType ## _SessionCnt; \
    buffer = pbCmd; \
    size = sizeof(pbCmd); \
    MemorySet(&parms, 0x00, sizeof(parms)); \
    MemorySet(__InParm, 0x00, sizeof(*__InParm)); \
    MemorySet(__OutParm, 0x00, sizeof(*__OutParm)); \
    parms.parmIn = (void*)__InParm; \
    parms.parmOut = (void*)__OutParm; \
    parms.objectCntIn = __CommandType  ## _HdlCntIn; \
    parms.objectCntOut = __CommandType ## _HdlCntOut; \

#define EXECUTE_TPM_CALL(__CloseContext, __CommandType) \
    cbCmd = __CommandType ## _Marshal(sessionTable, sessionCnt, &parms, &buffer, &size); \
    if ((result = PlatformSubmitTPM20Command(__CloseContext, pbCmd, cbCmd, pbRsp, sizeof(pbRsp), &cbRsp)) != TPM_RC_SUCCESS) \
    { \
        goto Cleanup; \
    } \
    buffer = pbRsp; \
    size = cbRsp; \
    if ((result = __CommandType ## _Unmarshal(sessionTable, sessionCnt, &parms, &buffer, &size)) != TPM_RC_SUCCESS) \
    { \
        goto Cleanup; \
    } \

#define TRY_TPM_CALL(__CloseContext, __CommandType) \
    cbCmd = __CommandType ## _Marshal(sessionTable, sessionCnt, &parms, &buffer, &size); \
    if ((result = PlatformSubmitTPM20Command(__CloseContext, pbCmd, cbCmd, pbRsp, sizeof(pbRsp), &cbRsp)) == TPM_RC_SUCCESS) \
    { \
        buffer = pbRsp; \
        size = cbRsp; \
        result = __CommandType ## _Unmarshal(sessionTable, sessionCnt, &parms, &buffer, &size); \
    } \

void
ComputeCpHash(
TPMI_ALG_HASH    hashAlg,           // IN: hash algorithm
TPM_CC           commandCode,       // IN: command code
Marshal_Parms   *parms,
UINT32           parmBufferSize,    // IN: size of input parameter area
const BYTE      *parmBuffer,        // IN: input parameter area
TPM2B_DIGEST    *cpHash,            // OUT: cpHash
TPM2B_DIGEST    *nameHash           // OUT: name hash of command
);

void
ObjectComputeName(
TPMT_PUBLIC *publicArea,        // IN: public area of an object
TPM2B_NAME *name                // OUT: name of the object
);

UINT16
EntityGetName(
ANY_OBJECT *object,
TPM2B_NAME *name        // OUT: name of entity
);

UINT16
EntityGetQualifiedName(
TPMI_ALG_HASH hashAlg,
ANY_OBJECT *parent,
ANY_OBJECT *object,
TPM2B_NAME *name        // OUT: qualified name of entity
);

void
SensitiveToDuplicate(
TPMT_SENSITIVE          *sensitive,     // IN: sensitive structure
TPM2B_NAME              *name,          // IN: the name of the object
ANY_OBJECT              *parent,        // IN: The new parent
TPM_ALG_ID              nameAlg,        // IN: hash algorithm in public area
TPM2B_SEED              *seed,          // IN: the external seed.
TPMT_SYM_DEF_OBJECT     *symDef,        // IN: Symmetric key definition.
TPM2B_DATA              *innerSymKey,   // IN: a symmetric key may be
TPM2B_PRIVATE           *outPrivate     // OUT: output private structure
);

TPM_RC
DuplicateToSensitive(
TPM2B_PRIVATE           *inPrivate,     // IN: input private structure
TPM2B_NAME              *name,          // IN: the name of the object
ANY_OBJECT              *parent,        // IN: The new parent
TPM_ALG_ID              nameAlg,        // IN: hash algorithm in public area.
TPM2B_SEED              *seed,          // IN: an external seed may be provided.
TPMT_SYM_DEF_OBJECT     *symDef,        // IN: Symmetric key definition.
TPM2B_DATA              *innerSymKey,   // IN: a symmetric key may be
TPMT_SENSITIVE          *sensitive      // OUT: sensitive structure
);

void
SecretToCredential(
TPM2B_DIGEST        *secret,        // IN: secret information
TPM2B_NAME          *name,          // IN: the name of the object
TPM2B_SEED          *seed,          // IN: an external seed.
ANY_OBJECT          *protector,     // IN: The protector
TPM2B_ID_OBJECT     *outIDObject    // OUT: output credential
);

void
PolicyUpdate(
TPM_ALG_ID           authHashAlg,       // IN: SessionAlg
TPM_CC               commandCode,       // IN: command code
TPM2B_NAME          *name,              // IN: name of entity
TPM2B_NONCE         *ref,               // IN: the reference data
TPM2B_DIGEST        *policyDigest       // IN/OUT: policy digest to be updated
);

// Windows defined constants
#define TPM_20_SRK_HANDLE 0x81000001
#define TPM_20_EK_HANDLE 0x81010001
#define TPM_20_TCG_NV_SPACE ((TPM_HT_NV_INDEX << 24) | (0x00 << 22)
#define TPM_20_OWNER_NV_SPACE ((TPM_HT_NV_INDEX << 24) | (0x01 << 22))
#define TPM_20_PLATFORM_MANUFACTURER_NV_SPACE ((TPM_HT_NV_INDEX << 24) | (0x02 << 22))
#define TPM_20_TPM_MANUFACTURER_NV_SPACE ((TPM_HT_NV_INDEX << 24) | (0x03 << 22))
#define TPM_20_NV_INDEX_EK_CERTIFICATE (TPM_20_PLATFORM_MANUFACTURER_NV_SPACE + 2)
#define TPM_20_NV_INDEX_EK_NONCE (TPM_20_PLATFORM_MANUFACTURER_NV_SPACE + 3)
#define TPM_20_NV_INDEX_EK_TEMPLATE (TPM_20_PLATFORM_MANUFACTURER_NV_SPACE + 4)

extern UINT32 g_CommandTimeout;
#define TPM_DEFAULT_COMMAND_TIMEOUT (2000) // 2 seconds should be OK for all non-create commands
#define TPM_CREATE_COMMAND_TIMEOUT (90000) // 90 seconds should cover all create commands

void SetEkTemplate(
TPM2B_PUBLIC *publicArea         // OUT: public area of EK object
);
void SetSrkTemplate(
TPM2B_PUBLIC *publicArea         // OUT: public area of SRK object
);

#endif // __URCHIN_H__
