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

#ifndef TPM_ALG_ID
typedef UINT16 TPM_ALG_ID;
#define    TPM_ALG_RSA               (TPM_ALG_ID)(0x0001)
#define    TPM_ALG_SHA               (TPM_ALG_ID)(0x0004)
#define    TPM_ALG_SHA1              (TPM_ALG_ID)(0x0004)
#define    TPM_ALG_HMAC              (TPM_ALG_ID)(0x0005)
#define    TPM_ALG_AES               (TPM_ALG_ID)(0x0006)
#define    TPM_ALG_MGF1              (TPM_ALG_ID)(0x0007)
#define    TPM_ALG_KEYEDHASH         (TPM_ALG_ID)(0x0008)
#define    TPM_ALG_XOR               (TPM_ALG_ID)(0x000A)
#define    TPM_ALG_SHA256            (TPM_ALG_ID)(0x000B)
#define    TPM_ALG_SHA384            (TPM_ALG_ID)(0x000C)
#define    TPM_ALG_SHA512            (TPM_ALG_ID)(0x000D)
#define    TPM_ALG_NULL              (TPM_ALG_ID)(0x0010)
#define    TPM_ALG_SM3_256           (TPM_ALG_ID)(0x0012)
#define    TPM_ALG_SM4               (TPM_ALG_ID)(0x0013)
#define    TPM_ALG_RSASSA            (TPM_ALG_ID)(0x0014)
#define    TPM_ALG_RSAES             (TPM_ALG_ID)(0x0015)
#define    TPM_ALG_RSAPSS            (TPM_ALG_ID)(0x0016)
#define    TPM_ALG_OAEP              (TPM_ALG_ID)(0x0017)
#define    TPM_ALG_ECDSA             (TPM_ALG_ID)(0x0018)
#define    TPM_ALG_ECDH              (TPM_ALG_ID)(0x0019)
#define    TPM_ALG_ECDAA             (TPM_ALG_ID)(0x001A)
#define    TPM_ALG_SM2               (TPM_ALG_ID)(0x001B)
#define    TPM_ALG_ECSCHNORR         (TPM_ALG_ID)(0x001C)
#define    TPM_ALG_ECMQV             (TPM_ALG_ID)(0x001D)
#define    TPM_ALG_KDF1_SP800_56a    (TPM_ALG_ID)(0x0020)
#define    TPM_ALG_KDF2              (TPM_ALG_ID)(0x0021)
#define    TPM_ALG_KDF1_SP800_108    (TPM_ALG_ID)(0x0022)
#define    TPM_ALG_ECC               (TPM_ALG_ID)(0x0023)
#define    TPM_ALG_SYMCIPHER         (TPM_ALG_ID)(0x0025)
#define    TPM_ALG_CTR               (TPM_ALG_ID)(0x0040)
#define    TPM_ALG_OFB               (TPM_ALG_ID)(0x0041)
#define    TPM_ALG_CBC               (TPM_ALG_ID)(0x0042)
#define    TPM_ALG_CFB               (TPM_ALG_ID)(0x0043)
#define    TPM_ALG_ECB               (TPM_ALG_ID)(0x0044)
#endif

#ifndef CRYPT_RESULT
typedef INT16 CRYPT_RESULT;
#endif

#ifndef TPM2B
typedef struct {
    UINT16        size;
    BYTE          buffer[1024];
} TPM2B;
#endif

#ifndef RSA_KEY
typedef struct {
    UINT32        exponent;
    TPM2B        *publicKey;
    TPM2B        *privateKey;
} RSA_KEY;
#endif

#ifndef CPRI_HASH_STATE
typedef struct _HASH_STATE
{
    void* state;
    TPM_ALG_ID hashAlg;
} CPRI_HASH_STATE, *PCPRI_HASH_STATE;
#endif

UINT16 _cpri__StartHash(TPM_ALG_ID hashAlg,
    BOOL sequence,
    PCPRI_HASH_STATE hashState);

void _cpri__UpdateHash(PCPRI_HASH_STATE hashState,
    UINT32 dataSize,
    BYTE *data);

UINT16 _cpri__CompleteHash(PCPRI_HASH_STATE hashState,
    UINT32 dOutSize,
    BYTE *dOut);

UINT16 _cpri__HashBlock(TPM_ALG_ID hashAlg,
    UINT32 dataSize,
    BYTE* data,
    UINT32 digestSize,
    BYTE* digest);

UINT16 _cpri__StartHMAC(TPM_ALG_ID hashAlg,
    BOOL sequence,
    CPRI_HASH_STATE *state,
    UINT16 keySize,
    BYTE *key,
    TPM2B *oPadKey);

UINT16 _cpri__CompleteHMAC(CPRI_HASH_STATE *hashState,
    TPM2B *oPadKey,
    UINT32 dOutSize,
    BYTE *dOut);

UINT16 _cpri__HMACBlock(TPM_ALG_ID hashAlg,
    UINT32 keySize,
    BYTE* key,
    UINT32 dataSize,
    BYTE* data,
    UINT32 digestSize,
    BYTE* hmac);

UINT16 _cpri__GenerateRandom(INT32 randomSize,
    BYTE *buffer);

CRYPT_RESULT _cpri__StirRandom(INT32 seedSize,
    BYTE *buffer);

UINT16 _cpri__KDFa(TPM_ALG_ID hashAlg,
    TPM2B *key,
    const char *label,
    TPM2B *contextU,
    TPM2B *contextV,
    UINT32 sizeInBits,
    BYTE *keyStream,
    UINT32 *counterInOut,
    BOOL once);

UINT16 _cpri__KDFe(TPM_ALG_ID hashAlg,
    TPM2B *Z,
    const char *label,
    TPM2B *partyUInfo,
    TPM2B *partyVInfo,
    UINT32 sizeInBits,
    BYTE *keyStream);

CRYPT_RESULT _cpri__TestKeyRSA(TPM2B* d,
    UINT32 exponent,
    TPM2B* publicKey,
    TPM2B* prime1,
    TPM2B* prime2);

CRYPT_RESULT _cpri__EncryptRSA(UINT32 *cOutSize,
    BYTE *cOut,
    RSA_KEY *key,
    TPM_ALG_ID padType,
    UINT32 dInSize,
    BYTE *dIn,
    TPM_ALG_ID hashAlg,
    const char *label);

CRYPT_RESULT _cpri__DecryptRSA(UINT32 *dOutSize,
    BYTE *dOut,
    RSA_KEY *key,
    TPM_ALG_ID padType,
    UINT32 cInSize,
    BYTE *cIn,
    TPM_ALG_ID hashAlg,
    const char *label);

CRYPT_RESULT _cpri__SignRSA(UINT32 *sigOutSize,
    BYTE *sigOut,
    RSA_KEY *key,
    TPM_ALG_ID scheme,
    TPM_ALG_ID hashAlg,
    UINT32 hInSize,
    BYTE *hIn);

CRYPT_RESULT _cpri__ValidateSignatureRSA(RSA_KEY *key,
    TPM_ALG_ID scheme,
    TPM_ALG_ID hashAlg,
    UINT32 hInSize,
    BYTE *hIn,
    UINT32 sigInSize,
    BYTE *sigIn,
    UINT16 saltSize);

CRYPT_RESULT
_cpri__AESEncryptECB(BYTE *dOut,
    UINT32 keySizeInBits,
    BYTE *key,
    UINT32 dInSize,
    BYTE *dIn);

CRYPT_RESULT
_cpri__AESDecryptECB(BYTE *dOut,
    UINT32 keySizeInBits,
    BYTE *key,
    UINT32 dInSize,
    BYTE *dIn);

CRYPT_RESULT
_cpri__AESEncryptCBC(BYTE *dOut,
    UINT32 keySizeInBits,
    BYTE *key,
    BYTE *iv,
    UINT32 dInSize,
    BYTE *dIn);

CRYPT_RESULT
_cpri__AESDecryptCBC(BYTE *dOut,
    UINT32 keySizeInBits,
    BYTE *key,
    BYTE *iv,
    UINT32 dInSize,
    BYTE *dIn);

CRYPT_RESULT
_cpri__AESEncryptCFB(BYTE *dOut,
    UINT32 keySizeInBits,
    BYTE *key,
    BYTE *iv,
    UINT32 dInSize,
    BYTE *dIn);

CRYPT_RESULT
_cpri__AESDecryptCFB(BYTE *dOut,
    UINT32 keySizeInBits,
    BYTE *key,
    BYTE *iv,
    UINT32 dInSize,
    BYTE *dIn);

CRYPT_RESULT
_cpri__AESEncryptCTR(BYTE *dOut,
    UINT32 keySizeInBits,
    BYTE *key,
    BYTE *iv,
    UINT32 dInSize,
    BYTE *dIn);

#ifndef _cpri__AESDecryptCTR
#define _cpri__AESDecryptCTR(dOut, keySize, key, iv, dInSize, dIn) \
_cpri__AESEncryptCTR(((BYTE *)dOut), \
    ((UINT32)keySize),               \
    ((BYTE *)key),                   \
    ((BYTE *)iv),                    \
    ((UINT32)dInSize),               \
    ((BYTE *)dIn))
#endif

CRYPT_RESULT
_cpri__AESEncryptOFB(BYTE *dOut,
    UINT32 keySizeInBits,
    BYTE *key,
    BYTE *iv,
    UINT32 dInSize,
    BYTE *dIn);

#ifndef _cpri__AESDecryptOFB
#define _cpri__AESDecryptOFB(dOut, keySize, key, iv, dInSize, dIn) \
_cpri__AESEncryptOFB(((BYTE *)dOut), \
    ((UINT32)keySize),               \
    ((BYTE *)key),                   \
    ((BYTE *)iv),                    \
    ((UINT32)dInSize),               \
    ((BYTE *)dIn))
#endif

