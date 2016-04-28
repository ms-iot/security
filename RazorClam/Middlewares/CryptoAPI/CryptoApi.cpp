#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
//#include <CryptoAPI.h>

// Documentation @ https://wolfssl.com/wolfSSL/Docs-wolfssl-manual-18-wolfcrypt-api-reference.html
extern "C" {
#include "wolfssl/wolfcrypt/random.h"
#include "wolfssl/wolfcrypt/sha.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/sha512.h"
#include "wolfssl/wolfcrypt/hmac.h"
#include "wolfssl/wolfcrypt/integer.h"
#include "wolfssl/wolfcrypt/aes.h"
}

// Use the FreeRTOS heap
#define malloc pvPortMalloc
#define free vPortFree

typedef uint8_t UINT8;
typedef uint8_t BYTE;
typedef int8_t INT8;
typedef int BOOL;
typedef uint16_t UINT16;
typedef int16_t INT16;
typedef uint32_t UINT32;
typedef int32_t INT32;
typedef uint64_t UINT64;
typedef int64_t INT64;
typedef void *PVOID;

#define TRUE (1)
#define FALSE (0)

#ifndef MIN
#define MIN(a,b) (((a)<(b))?(a):(b))
#endif
#ifndef MAX
#define MAX(a,b) (((a)>(b))?(a):(b))
#endif

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

typedef UINT16 TPM_ALG_ID;

#define    TPM_ALG_RSA               (TPM_ALG_ID)(0x0001)        // a: A O; D: 
#define    TPM_ALG_SHA               (TPM_ALG_ID)(0x0004)        // a: H; D: 
#define    TPM_ALG_SHA1              (TPM_ALG_ID)(0x0004)        // a: H; D: 
#define    TPM_ALG_HMAC              (TPM_ALG_ID)(0x0005)        // a: H X; D: 
#define    TPM_ALG_AES               (TPM_ALG_ID)(0x0006)        // a: S; D: 
#define    TPM_ALG_MGF1              (TPM_ALG_ID)(0x0007)        // a: H M; D: 
#define    TPM_ALG_KEYEDHASH         (TPM_ALG_ID)(0x0008)        // a: H E X O; D: 
#define    TPM_ALG_XOR               (TPM_ALG_ID)(0x000A)        // a: H S; D: 
#define    TPM_ALG_SHA256            (TPM_ALG_ID)(0x000B)        // a: H; D: 
#define    TPM_ALG_SHA384            (TPM_ALG_ID)(0x000C)        // a: H; D: 
#define    TPM_ALG_SHA512            (TPM_ALG_ID)(0x000D)        // a: H; D: 
#define    TPM_ALG_NULL              (TPM_ALG_ID)(0x0010)        // a: ; D: 
#define    TPM_ALG_SM3_256           (TPM_ALG_ID)(0x0012)        // a: H; D: 
#define    TPM_ALG_SM4               (TPM_ALG_ID)(0x0013)        // a: S; D: 
#define    TPM_ALG_RSASSA            (TPM_ALG_ID)(0x0014)        // a: A X; D: RSA 
#define    TPM_ALG_RSAES             (TPM_ALG_ID)(0x0015)        // a: A E; D: RSA 
#define    TPM_ALG_RSAPSS            (TPM_ALG_ID)(0x0016)        // a: A X; D: RSA 
#define    TPM_ALG_OAEP              (TPM_ALG_ID)(0x0017)        // a: A E; D: RSA 
#define    TPM_ALG_ECDSA             (TPM_ALG_ID)(0x0018)        // a: A X; D: ECC 
#define    TPM_ALG_ECDH              (TPM_ALG_ID)(0x0019)        // a: A M; D: ECC 
#define    TPM_ALG_ECDAA             (TPM_ALG_ID)(0x001A)        // a: A X; D: ECC 
#define    TPM_ALG_SM2               (TPM_ALG_ID)(0x001B)        // a: A X E; D: ECC 
#define    TPM_ALG_ECSCHNORR         (TPM_ALG_ID)(0x001C)        // a: A X; D: ECC 
#define    TPM_ALG_ECMQV             (TPM_ALG_ID)(0x001D)        // a: A E; D: ECC 
#define    TPM_ALG_KDF1_SP800_56a    (TPM_ALG_ID)(0x0020)        // a: H M; D: ECC 
#define    TPM_ALG_KDF2              (TPM_ALG_ID)(0x0021)        // a: H M; D: 
#define    TPM_ALG_KDF1_SP800_108    (TPM_ALG_ID)(0x0022)        // a: H M; D: 
#define    TPM_ALG_ECC               (TPM_ALG_ID)(0x0023)        // a: A O; D: 
#define    TPM_ALG_SYMCIPHER         (TPM_ALG_ID)(0x0025)        // a: O; D: 
#define    TPM_ALG_CTR               (TPM_ALG_ID)(0x0040)        // a: S E; D: 
#define    TPM_ALG_OFB               (TPM_ALG_ID)(0x0041)        // a: S E; D: 
#define    TPM_ALG_CBC               (TPM_ALG_ID)(0x0042)        // a: S E; D: 
#define    TPM_ALG_CFB               (TPM_ALG_ID)(0x0043)        // a: S E; D: 
#define    TPM_ALG_ECB               (TPM_ALG_ID)(0x0044)        // a: S E; D: 

#define    SHA1_DIGEST_SIZE    20
#define    SHA1_BLOCK_SIZE     64
#define    SHA1_DER_SIZE       15
#define    SHA1_DER            {\
    0x30,0x21,0x30,0x09,0x06,0x05,0x2B,0x0E,0x03,0x02,0x1A,0x05,0x00,0x04,0x14}
BYTE SHA1_DER_STRING[] = SHA1_DER;

#define    SHA256_DIGEST_SIZE    32
#define    SHA256_BLOCK_SIZE     64
#define    SHA256_DER_SIZE       19
#define    SHA256_DER            {\
    0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,\
    0x05,0x00,0x04,0x20}
BYTE SHA256_DER_STRING[] = SHA256_DER;

#define    SHA384_DIGEST_SIZE    48
#define    SHA384_BLOCK_SIZE     128
#define    SHA384_DER_SIZE       19
#define    SHA384_DER            {\
    0x30,0x41,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02,\
    0x05,0x00,0x04,0x30}
BYTE SHA384_DER_STRING[] = SHA384_DER;

#define    SHA512_DIGEST_SIZE    64
#define    SHA512_BLOCK_SIZE     128
#define    SHA512_DER_SIZE       19
#define    SHA512_DER            {\
    0x30,0x51,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03,\
    0x05,0x00,0x04,0x40}
BYTE SHA512_DER_STRING[] = SHA512_DER;

typedef INT16 CRYPT_RESULT;

typedef struct {
    UINT16        size;
    BYTE          buffer[1024];
} TPM2B;

typedef struct {
    UINT32        exponent;      // The public exponent pointer
    TPM2B        *publicKey;     // Pointer to the public modulus
    TPM2B        *privateKey;    // The private exponent (not a prime)
} RSA_KEY;

typedef struct _HASH_STATE
{
    void* state;
    TPM_ALG_ID hashAlg;
} CPRI_HASH_STATE, *PCPRI_HASH_STATE;

#define CRYPT_FAIL          ((CRYPT_RESULT)  1)
#define CRYPT_SUCCESS       ((CRYPT_RESULT)  0)
#define CRYPT_NO_RESULT     ((CRYPT_RESULT) -1)
#define CRYPT_SCHEME        ((CRYPT_RESULT) -2)
#define CRYPT_PARAMETER     ((CRYPT_RESULT) -3)
#define CRYPT_UNDERFLOW     ((CRYPT_RESULT) -4)
#define CRYPT_POINT         ((CRYPT_RESULT) -5)
#define CRYPT_CANCEL        ((CRYPT_RESULT) -6)

CRYPT_RESULT
_cpri__TestKeyRSA(
    TPM2B* dOut,
    UINT32 exponent,
    TPM2B* publicKey,
    TPM2B* prime1,
    TPM2B* prime2
    )
{
    CRYPT_RESULT retVal = CRYPT_SUCCESS;
    long exp = (!exponent) ? 0x00010001 : (long)exponent;
    mp_int e = { 0 };
    mp_int d = { 0 };
    mp_int n = { 0 };
    mp_int p = { 0 };
    mp_int q = { 0 };
    mp_int qr = { 0 };
    mp_int tmp1 = { 0 };
    mp_int tmp2 = { 0 };

    if (publicKey->size / 2 != prime1->size)
        return CRYPT_PARAMETER;

    if ((mp_init_multi(&e, &d, &n, &p, &q, &qr) != 0) ||
        (mp_init_multi(&tmp1, &tmp2, NULL, NULL, NULL, NULL) != 0))
    {
        retVal = CRYPT_FAIL;
        goto Cleanup;
    }
    if (mp_set_int(&e, exp) != 0)  /* key->e = exp */
    {
        retVal = CRYPT_PARAMETER;
        goto Cleanup;
    }

    // Read the first prime
    if (mp_read_unsigned_bin(&p, (const unsigned char*)prime1->buffer, prime1->size) != 0)
    {
        retVal = CRYPT_PARAMETER;
        goto Cleanup;
    }

    // If prime2 is provided, then compute n
    if ((prime2 != NULL) && (prime2->size != 0))
    {
        // Two primes provided so use them to compute n
        if (mp_read_unsigned_bin(&q, (const unsigned char*)prime2->buffer, prime2->size) != 0)
        {
            retVal = CRYPT_PARAMETER;
            goto Cleanup;
        }

        // Make sure that the sizes of the primes are compatible
        if (mp_unsigned_bin_size(&q) != mp_unsigned_bin_size(&p))
        {
            retVal = CRYPT_PARAMETER;
            goto Cleanup;
        }

        // Multiply the primes to get the public modulus
        if (mp_mul(&p, &q, &n) != 0)
        {
            retVal = CRYPT_FAIL;
            goto Cleanup;
        }

        // if the space provided for the public modulus is large enough,
        // save the created value
        if ((mp_unsigned_bin_size(&n) == publicKey->size) &&
            (mp_to_unsigned_bin(&n, publicKey->buffer) != 0))
        {
            retVal = CRYPT_PARAMETER;
            goto Cleanup;
        }
    }
    else
    {
        // One prime provided so find the second prime by division
        if (mp_read_unsigned_bin(&n, (const unsigned char*)publicKey->buffer, publicKey->size) != 0)
        {
            retVal = CRYPT_PARAMETER;
            goto Cleanup;
        }

        // Get q = n/p;
        if (mp_div(&n, &p, &q, &qr) != 0)
        {
            retVal = CRYPT_FAIL;
            goto Cleanup;
        }

        // If there is a remainder, then this is not a valid n
        if (mp_unsigned_bin_size(&qr) != 0 || mp_count_bits(&q) != mp_count_bits(&p))
        {
            retVal = CRYPT_PARAMETER;
            goto Cleanup;
        }

        // Return the second prime if requested
        if (prime2 != NULL)
        {
            prime2->size = mp_unsigned_bin_size(&q);
            mp_to_unsigned_bin(&q, prime2->buffer);
        }
    }

    // We have both primes now
    if ((mp_sub_d(&q, 1, &tmp1) != 0) ||    /* tmp1 = q-1 */
        (mp_sub_d(&p, 1, &tmp2) != 0) ||    /* tmp2 = p-1 */
        (mp_lcm(&tmp1, &tmp2, &tmp1) != 0)) /* tmp1 = lcm(p-1, q-1) */
    {
        retVal = CRYPT_FAIL;
        goto Cleanup;
    }

    // Calculate the private key
    if (mp_invmod(&e, &tmp1, &d) != 0)
    {
        retVal = CRYPT_FAIL;
        goto Cleanup;
    }

    // Return the private key
    dOut->size = mp_unsigned_bin_size(&d);
    mp_to_unsigned_bin(&d, dOut->buffer);

Cleanup:
    mp_clear(&e);
    mp_clear(&d);
    mp_clear(&n);
    mp_clear(&p);
    mp_clear(&q);
    mp_clear(&qr);
    mp_clear(&tmp1);
    mp_clear(&tmp2);
    return retVal;
}

static BOOL RSAEP(size_t dInOutSize, 
    const void* dInOut,
    size_t modulusSize,
    const void* modulus,
    unsigned int exponent)
{
    BOOL retVal = TRUE;
    long exp = (!exponent) ? 0x00010001 : (long)exponent;
    mp_int e = { 0 };
    mp_int n = { 0 };
    mp_int tmp = { 0 };
    UINT32 offset = (UINT32)dInOutSize;

    // Set up the public key
    if (mp_init_multi(&e, &n, &tmp, NULL, NULL, NULL) != 0)
    {
        retVal = FALSE;
        goto Cleanup;
    }
    if (mp_set_int(&e, exp) != 0)
    {
        retVal = FALSE;
        goto Cleanup;
    }
    if (mp_read_unsigned_bin(&n, (const unsigned char*)modulus, (int)modulusSize) != 0)
    {
        retVal = FALSE;
        goto Cleanup;
    }

    // Perform the encryption
    if ((mp_read_unsigned_bin(&tmp, (const unsigned char*)dInOut, (int)dInOutSize) != 0) ||
        (mp_exptmod(&tmp, &e, &n, &tmp) != 0))
    {
        retVal = FALSE;
        goto Cleanup;
    }

    // Prepare the output
    memset((BYTE*)dInOut, 0x00, dInOutSize);
    offset -= mp_unsigned_bin_size(&tmp);
    if (mp_to_unsigned_bin(&tmp, &((unsigned char*)dInOut)[offset]) != 0)
    {
        retVal = FALSE;
        goto Cleanup;
    }

Cleanup:
    mp_clear(&e);
    mp_clear(&n);
    mp_clear(&tmp);
    return retVal;
}

static BOOL RSADP(size_t dInOutSize,
    const void* dInOut,
    size_t privateExponentSize,
    const void* privateExponent,
    size_t modulusSize,
    const void* modulus)
{
    BOOL retVal = TRUE;
    mp_int d = { 0 };
    mp_int n = { 0 };
    mp_int tmp = { 0 };
    UINT32 offset = (UINT32)dInOutSize;

    // Set up the private key
    if (mp_init_multi(&d, &n, &tmp, NULL, NULL, NULL) != 0)
    {
        retVal = FALSE;
        goto Cleanup;
    }
    if (mp_read_unsigned_bin(&n, (const unsigned char*)modulus, (int)modulusSize) != 0)
    {
        retVal = FALSE;
        goto Cleanup;
    }
    if (mp_read_unsigned_bin(&d, (const unsigned char*)privateExponent, (int)privateExponentSize) != 0)
    {
        retVal = FALSE;
        goto Cleanup;
    }

    // Perform the decryption
    if ((mp_read_unsigned_bin(&tmp, (const unsigned char*)dInOut, (int)dInOutSize) != 0) ||
        (mp_exptmod(&tmp, &d, &n, &tmp) != 0))
    {
        retVal = FALSE;
        goto Cleanup;
    }

    // Prepare the output
    memset((BYTE*)dInOut, 0x00, dInOutSize);
    offset -= mp_unsigned_bin_size(&tmp);
    if (mp_to_unsigned_bin(&tmp, &((unsigned char*)dInOut)[offset]) != 0)
    {
        retVal = FALSE;
        goto Cleanup;
    }

Cleanup:
    mp_clear(&d);
    mp_clear(&n);
    mp_clear(&tmp);
    return retVal;
}

//// Low priority work in progress. We will likely have to write our own RNG implementation.

//CRYPT_RESULT
//_cpri__GenerateKeyRSA(
//    TPM2B           *n,             // OUT: The public modulus
//    TPM2B           *p,             // OUT: One of the prime factors of n
//    UINT16           keySizeInBits, // IN: Size of the public modulus in bits
//    UINT32           e,             // IN: The public exponent
//    TPM_ALG_ID       hashAlg,       // IN: hash algorithm to use in the key
//                                    //     generation process
//    TPM2B           *seed,          // IN: the seed to use
//    const char      *label,         // IN: A label for the generation process.
//    TPM2B           *extra,         // IN: Party 1 data for the KDF
//    UINT32          *counter        // IN/OUT: Counter value to allow KFD iteration
//                                    //         to be propagated across multiple 
//                                    //         routines
//    )
//{
//    CRYPT_RESULT     result = CRYPT_SUCCESS;
//    UINT32           lLen;          // length of the label
//                                    // (counting the terminating 0);
//    UINT16           digestSize = (UINT16)HashLength(hashAlg);
//
////    TPM2B_HASH_BLOCK    oPadKey;
//
//    UINT32          outer;
//    UINT32          inner;
//    BYTE            swapped[4];
//
//    CRYPT_RESULT    retVal;
//    int             i, fill;
//    const static char     defaultLabel[] = "RSA key";
//    BYTE            *pb;
//
//
//    CPRI_HASH_STATE  h1;            // contains the hash of the
//                                    //   HMAC key w/ iPad
//    CPRI_HASH_STATE  h2;            // contains the hash of the
//                                    //   HMAC key w/ oPad
//    CPRI_HASH_STATE  h;             // the working hash context
//
//    mp_int           bnP;
//    mp_int           bnQ;
//    mp_int           bnT;
//    mp_int           bnE;
//    mp_int           bnN;
//    UINT32           rem;
//
//    // if present, use externally provided counter
//    if (counter != NULL)
//        outer = *counter;
//    else
//        outer = 1;
//
//    // Validate exponent
//    UINT32_TO_BYTE_ARRAY(e, swapped);
//
//    // Need to check that the exponent is prime and not less than 3
////    if (e != 0 && (e < 3 || !_math__IsPrime(e)))
////        return CRYPT_FAIL;
//
//    // Get structures for the big number representations
//    if (mp_init_multi(&bnP, &bnQ, &bnT, &bnE, &bnN, NULL) != 0)
//    {
//        result = CRYPT_FAIL;
//        goto Cleanup;
//    }
//
//    // Set Q to zero. This is used as a flag. The prime is computed in P. When a
//    // new prime is found, Q is checked to see if it is zero.  If so, P is copied
//    // to Q and a new P is found.  When both P and Q are non-zero, the modulus and
//    // private exponent are computed and a trial encryption/decryption is
//    // performed.  If the encrypt/decrypt fails, assume that at least one of the
//    // primes is composite. Since we don't know which one, set Q to zero and start
//    // over and find a new pair of primes.
////    BN_zero(bnQ);
//
//    // Need to have some label
//    if (label == NULL)
//        label = (const char *)&defaultLabel;
//    // Get the label size
//    for (lLen = 0; label[lLen++] != 0;);
//
//    // Start the hash using the seed and get the intermediate hash value
//    _cpri__StartHMAC(hashAlg, FALSE, &h1, seed->size, seed->buffer, NULL);
//    _cpri__StartHash(hashAlg, FALSE, &h2);
//    _cpri__UpdateHash(&h2, oPadKey.b.size, oPadKey.b.buffer);
//
//    n->size = keySizeInBits / 8;
////    pAssert(n->size <= MAX_RSA_KEY_BYTES);
//    p->size = n->size / 2;
//    if (e == 0)
//        e = RSA_DEFAULT_PUBLIC_EXPONENT;
//
//    BN_set_word(bnE, e);
//
//    // The first test will increment the counter from zero.
//    for (outer += 1; outer != 0; outer++)
//    {
//        //if (_plat__IsCanceled())
//        //{
//        //    retVal = CRYPT_CANCEL;
//        //    goto Cleanup;
//        //}
//
//        // Need to fill in the candidate with the hash
//        fill = digestSize;
//        pb = p->buffer;
//
//        // Reset the inner counter
//        inner = 0;
//        for (i = p->size; i > 0; i -= digestSize)
//        {
//            inner++;
//            // Initialize the HMAC with saved state
//            _cpri__CopyHashState(&h, &h1);
//
//            // Hash the inner counter (the one that changes on each HMAC iteration)
//            UINT32_TO_BYTE_ARRAY(inner, swapped);
//            _cpri__UpdateHash(&h, 4, swapped);
//            _cpri__UpdateHash(&h, lLen, (BYTE *)label);
//
//            // Is there any party 1 data
//            if (extra != NULL)
//                _cpri__UpdateHash(&h, extra->size, extra->buffer);
//
//            // Include the outer counter (the one that changes on each prime
//            // prime candidate generation
//            UINT32_TO_BYTE_ARRAY(outer, swapped);
//            _cpri__UpdateHash(&h, 4, swapped);
//            _cpri__UpdateHash(&h, 2, (BYTE *)&keySizeInBits);
//            if (i < fill)
//                fill = i;
//            _cpri__CompleteHash(&h, fill, pb);
//
//            // Restart the oPad hash
//            _cpri__CopyHashState(&h, &h2);
//
//            // Add the last hashed data
//            _cpri__UpdateHash(&h, fill, pb);
//
//            // gives a completed HMAC
//            _cpri__CompleteHash(&h, fill, pb);
//            pb += fill;
//        }
//        // Set the Most significant 2 bits and the low bit of the candidate
//        p->buffer[0] |= 0xC0;
//        p->buffer[p->size - 1] |= 1;
//
//        // Convert the candidate to a BN
//        BN_bin2bn(p->buffer, p->size, bnP);
//
//        // If this is the second prime, make sure that it differs from the
//        // first prime by at least 2^100
//        if (!BN_is_zero(bnQ))
//        {
//            // bnQ is non-zero if we already found it
//            if (BN_ucmp(bnP, bnQ) < 0)
//                BN_sub(bnT, bnQ, bnP);
//            else
//                BN_sub(bnT, bnP, bnQ);
//            if (BN_num_bits(bnT) < 100)  // Difference has to be at least 100 bits
//                continue;
//        }
//        // Make sure that the prime candidate (p) is not divisible by the exponent
//        // and that (p-1) is not divisible by the exponent
//        // Get the remainder after dividing by the modulus
//        rem = BN_mod_word(bnP, e);
//        if (rem == 0) // evenly divisible so add two keeping the number odd and
//                      // making sure that 1 != p mod e
//            BN_add_word(bnP, 2);
//        else if (rem == 1) // leaves a remainder of 1 so subtract two keeping the
//                           // number odd and making (e-1) = p mod e
//            BN_sub_word(bnP, 2);
//
//        // Have a candidate, check for primality 
//        if ((retVal = (CRYPT_RESULT)BN_is_prime_ex(bnP,
//            BN_prime_checks, NULL, NULL)) < 0)
//            FAIL(FATAL_ERROR_INTERNAL);
//
//        if (retVal != 1)
//            continue;
//
//        // Found a prime, is this the first or second.
//        if (BN_is_zero(bnQ))
//        {
//            // copy p to q and compute another prime in p
//            BN_copy(bnQ, bnP);
//            continue;
//        }
//        //Form the public modulus
//        BN_mul(bnN, bnP, bnQ, context);
//        if (BN_num_bits(bnN) != keySizeInBits)
//            FAIL(FATAL_ERROR_INTERNAL);
//
//        // Save the public modulus
//        BnTo2B(n, bnN, 0);  // Fills the buffer with the correct size
//        pAssert((n->size == (keySizeInBits + 7) / 8) && ((n->buffer[0] & 0x80)
//            != 0));
//
//        // And one prime
//        BnTo2B(p, bnP, 0);
//        pAssert((p->size == n->size / 2) && ((p->buffer[0] & 0x80) != 0));
//
//        // Finish by making sure that we can form the modular inverse of PHI
//        // with respect to the public exponent
//        // Compute PHI = (p - 1)(q - 1) = n - p - q + 1
//        // Make sure that we can form the modular inverse
//        BN_sub(bnT, bnN, bnP);
//        BN_sub(bnT, bnT, bnQ);
//        BN_add_word(bnT, 1);
//
//        // find d such that (Phi * d) mod e ==1
//        // If there isn't then we are broken because we took the step
//        // of making sure that the prime != 1 mod e so the modular inverse
//        // must exist
//        if (BN_mod_inverse(bnT, bnE, bnT, context) == NULL || BN_is_zero(bnT))
//            FAIL(FATAL_ERROR_INTERNAL);
//
//        // And, finally, do a trial encryption decryption
//        {
//            TPM2B_TYPE(RSA_KEY, MAX_RSA_KEY_BYTES);
//            TPM2B_RSA_KEY        r;
//            r.t.size = sizeof(n->size);
//
//            // If we are using a seed, then results must be reproducible on each
//            // call. Otherwise, just get a random number
//            if (seed == NULL)
//                _cpri__GenerateRandom(n->size, r.t.buffer);
//            else
//            {
//                // this this version does not have a deterministic RNG, XOR the
//                // public key and private exponent to get a deterministic value
//                // for testing.
//                int         i;
//
//                // Generate a random-ish number starting with the public modulus
//                // XORed with the MSO of the seed
//                for (i = 0; i < n->size; i++)
//                    r.t.buffer[i] = n->buffer[i] ^ seed->buffer[0];
//            }
//            // Make sure that the number is smaller than the public modulus
//            r.t.buffer[0] &= 0x7F;
//            // Convert
//            if (BN_bin2bn(r.t.buffer, r.t.size, bnP) == NULL
//                // Encrypt with the public exponent
//                || BN_mod_exp(bnQ, bnP, bnE, bnN, context) != 1
//                // Decrypt with the private exponent
//                || BN_mod_exp(bnQ, bnQ, bnT, bnN, context) != 1)
//                FAIL(FATAL_ERROR_INTERNAL);
//            // If the starting and ending values are not the same, start over )-;
//            if (BN_ucmp(bnP, bnQ) != 0)
//            {
//                BN_zero(bnQ);
//                continue;
//            }
//        }
//        retVal = CRYPT_SUCCESS;
//        goto Cleanup;
//    }
//    retVal = CRYPT_FAIL;
//
//
//Cleanup:
//    // Close out the hash sessions
//    _cpri__CompleteHash(&h2, 0, NULL);
//    _cpri__CompleteHash(&h1, 0, NULL);
//
//    // Free up allocated BN values
//    BN_CTX_end(context);
//    BN_CTX_free(context);
//    if (counter != NULL)
//        *counter = outer;
//    return retVal;
//}

static size_t HashLength(TPM_ALG_ID hashAlg)
{
    size_t digestLen = 0;

    switch (hashAlg) {
    case TPM_ALG_SHA1:
        digestLen = 20;
        break;

    case TPM_ALG_SHA256:
        digestLen = 32;
        break;

    case TPM_ALG_SHA384:
        digestLen = 48;
        break;

    case TPM_ALG_SHA512:
        digestLen = 64;
        break;
    }

    return digestLen;
}

UINT16 _cpri__StartHash(TPM_ALG_ID hashAlg,
    BOOL sequence,
    PCPRI_HASH_STATE hashState)
{
    if (sequence) return 0;

    switch (hashAlg) {
    case TPM_ALG_SHA1:
        if ((hashState->state = malloc(sizeof(Sha))) != NULL)
        {
            wc_InitSha((Sha*)hashState->state);
        }
        break;

    case TPM_ALG_SHA256:
        if ((hashState->state = malloc(sizeof(Sha256))) != NULL)
        {
            wc_InitSha256((Sha256*)hashState->state);
        }
        break;

    case TPM_ALG_SHA384:
        if ((hashState->state = malloc(sizeof(Sha384))) != NULL)
        {
            wc_InitSha384((Sha384*)hashState->state);
        }
        break;

    case TPM_ALG_SHA512:
        if ((hashState->state = malloc(sizeof(Sha512))) != NULL)
        {
            wc_InitSha512((Sha512*)hashState->state);
        }
        break;

    default:
        return 0;
    }

    hashState->hashAlg = hashAlg;

    return (UINT16)HashLength(hashAlg);
}

void _cpri__UpdateHash(PCPRI_HASH_STATE hashState,
    UINT32 dataSize,
    BYTE *data)
{
    switch (hashState->hashAlg)
    {
    case TPM_ALG_SHA1:
        wc_ShaUpdate((Sha*)hashState->state, data, dataSize);
        break;

    case TPM_ALG_SHA256:
        wc_Sha256Update((Sha256*)hashState->state, data, dataSize);
        break;

    case TPM_ALG_SHA384:
        wc_Sha384Update((Sha384*)hashState->state, data, dataSize);
        break;

    case TPM_ALG_SHA512:
        wc_Sha512Update((Sha512*)hashState->state, data, dataSize);
        break;

    case TPM_ALG_HMAC:
        wc_HmacUpdate((Hmac*)hashState->state, data, dataSize);
        break;
    }
}

UINT16 _cpri__CompleteHash(PCPRI_HASH_STATE hashState,
    UINT32 dOutSize,
    BYTE *dOut)
{
    UINT32 digestLen = HashLength(hashState->hashAlg);
    BYTE digest[64] = { 0 };

    switch (hashState->hashAlg)
    {
    case TPM_ALG_SHA1:
        wc_ShaFinal((Sha*)hashState->state, digest);
        memset(hashState->state, 0x00, sizeof(Sha));
        break;

    case TPM_ALG_SHA256:
        wc_Sha256Final((Sha256*)hashState->state, digest);
        memset(hashState->state, 0x00, sizeof(Sha256));
        break;

    case TPM_ALG_SHA384:
        wc_Sha384Final((Sha384*)hashState->state, digest);
        memset(hashState->state, 0x00, sizeof(Sha384));
        break;

    case TPM_ALG_SHA512:
        wc_Sha512Final((Sha512*)hashState->state, digest);
        memset(hashState->state, 0x00, sizeof(Sha512));
        break;
    default:
        digestLen = 0;
        break;
    }
    free(hashState->state);
    memcpy(dOut, digest, MIN(digestLen, dOutSize));

    return (UINT16)MIN(digestLen, dOutSize);
}

UINT16 _cpri__HashBlock(TPM_ALG_ID hashAlg,
    UINT32 dataSize,
    BYTE* data,
    UINT32 digestSize,
    BYTE* digest)
{
    if (digestSize >= HashLength(hashAlg))
    {
        switch (hashAlg)
        {
            case TPM_ALG_SHA1:
            {
                Sha context = { 0 };
                wc_InitSha(&context);
                wc_ShaUpdate(&context, data, dataSize);
                wc_ShaFinal(&context, digest);
                break;
            }
            case TPM_ALG_SHA256:
            {
                Sha256 context = { 0 };
                wc_InitSha256(&context);
                wc_Sha256Update(&context, data, dataSize);
                wc_Sha256Final(&context, digest);
                break;
            }
            case TPM_ALG_SHA384:
            {
                Sha384 context = { 0 };
                wc_InitSha384(&context);
                wc_Sha384Update(&context, data, dataSize);
                wc_Sha384Final(&context, digest);
                break;
            }
            case TPM_ALG_SHA512:
            {
                Sha512 context = { 0 };
                wc_InitSha512(&context);
                wc_Sha512Update(&context, data, dataSize);
                wc_Sha512Final(&context, digest);
                break;
            }
        }

        return (UINT16)HashLength(hashAlg);
    }
    else
    {
        return 0;
    }
}

UINT16 _cpri__StartHMAC(TPM_ALG_ID hashAlg,
    BOOL sequence,
    CPRI_HASH_STATE *state,
    UINT16 keySize,
    BYTE *key,
    TPM2B *oPadKey)
{
    Hmac* context = NULL;
    int type = 0;

//    UNREFERENCED_PARAMETER(oPadKey);

    if (sequence) return 0;

    switch (hashAlg)
    {
    case TPM_ALG_SHA1:
        type = SHA;
        break;
    case TPM_ALG_SHA256:
        type = SHA256;
        break;
    case TPM_ALG_SHA384:
        type = SHA384;
        break;
    case TPM_ALG_SHA512:
        type = SHA512;
        break;
    default:
        return 0;
    }

    if (((context = (Hmac*)malloc(sizeof(Hmac))) == NULL) ||
        (wc_HmacSetKey(context, type, key, keySize) != 0))
    {
        return CRYPT_FAIL;
    }

    state->state = context;
    state->hashAlg = TPM_ALG_HMAC;

    return (UINT16)HashLength(hashAlg);
}

UINT16 _cpri__CompleteHMAC(CPRI_HASH_STATE *hashState,
    TPM2B *oPadKey,
    UINT32 dOutSize,
    BYTE *dOut
    )
{
    Hmac* context = (Hmac*)hashState->state;
    UINT16 hmacLen = 0;
    BYTE hmac[64] = {0};

//    UNREFERENCED_PARAMETER(oPadKey);
    switch (context->macType)
    {
    case SHA:
        hmacLen = (UINT16)HashLength(TPM_ALG_SHA1);
        break;
    case SHA256:
        hmacLen = (UINT16)HashLength(TPM_ALG_SHA256);
        break;
    case SHA384:
        hmacLen = (UINT16)HashLength(TPM_ALG_SHA384);
        break;
    case SHA512:
        hmacLen = (UINT16)HashLength(TPM_ALG_SHA512);
        break;
    default:
        hmacLen = 0;
        break;
    }

    if (wc_HmacFinal(context, hmac) != 0)
    {
        hmacLen = 0;
        goto Cleanup;
    }
    memcpy(dOut, hmac, MIN(hmacLen, dOutSize));

Cleanup:
    memset(context, 0x00, sizeof(Hmac));
    free(context);
    return MIN(hmacLen, dOutSize);
}

UINT16 _cpri__HMACBlock(TPM_ALG_ID hashAlg,
    UINT32 keySize,
    BYTE* key,
    UINT32 dataSize,
    BYTE* data,
    UINT32 digestSize,
    BYTE* hmac)
{
    Hmac context = { 0 };
    int type = 0;

    if (digestSize < HashLength(hashAlg)) return 0;

    switch (hashAlg)
    {
    case TPM_ALG_SHA1:
        type = SHA;
        break;
    case TPM_ALG_SHA256:
        type = SHA256;
        break;
    case TPM_ALG_SHA384:
        type = SHA384;
        break;
    case TPM_ALG_SHA512:
        type = SHA512;
        break;
    default:
        return 0;
    }

    if ((wc_HmacSetKey(&context, type, key, keySize) != 0) ||
        (wc_HmacUpdate(&context, data, dataSize) != 0) ||
        (wc_HmacFinal(&context, hmac) != 0))
    {
        return 0;
    }

    return (UINT16)HashLength(hashAlg);
}

WC_RNG* platformRng = NULL;
UINT16 _cpri__GenerateRandom(INT32 randomSize,
    BYTE *buffer)
{
    // Intialize if needed
    if ((platformRng == NULL) &&
        (((platformRng = (WC_RNG*)malloc(sizeof(WC_RNG))) == NULL) ||
            (wc_InitRng(platformRng) != 0)))
    {
        return 0;
    }

    if (wc_RNG_GenerateBlock(platformRng, buffer, randomSize) != 0)
    {
        return 0;
    }

    return randomSize;
}

CRYPT_RESULT _cpri__StirRandom(INT32 seedSize,
    BYTE *buffer)
{
    // RNG automatically reseeds from the platform
    return CRYPT_SUCCESS;
}

static CRYPT_RESULT _cpri__MGF1(UINT32 mSize,
    BYTE *mask,
    TPM_ALG_ID hashAlg,
    UINT32 sSize,
    BYTE *seed)
{
    CPRI_HASH_STATE      hashState = { 0 };
    CRYPT_RESULT         retVal = 0;
    BYTE                 b[64]; // temp buffer in case mask is not an
                                // even multiple of a full digest
    CRYPT_RESULT         dSize = (UINT16)HashLength(hashAlg);
    unsigned int         digestSize; //= (UINT32)dSize;
    UINT32               remaining;
    UINT32               counter;
    BYTE                 swappedCounter[4];

    // If there is no digest to compute return
    if (dSize <= 0)
        return 0;

    for (counter = 0, remaining = mSize; remaining > 0; counter++)
    {
        // Because the system may be either Endian...
        UINT32_TO_BYTE_ARRAY(counter, swappedCounter);

        // Start the hash and include the seed and counter
        _cpri__StartHash(hashAlg, FALSE, &hashState);
        _cpri__UpdateHash(&hashState, sSize, seed);
        _cpri__UpdateHash(&hashState, 4, swappedCounter);

        // Handling the completion depends on how much space remains in the mask
        // buffer. If it can hold the entire digest, put it there. If not
        // put the digest in a temp buffer and only copy the amount that
        // will fit into the mask buffer.
        if (remaining < (unsigned)dSize)
        {
            digestSize = _cpri__CompleteHash(&hashState, sizeof(b), b);
            memcpy(mask, b, remaining);
            break;
        }
        else
        {
            digestSize = _cpri__CompleteHash(&hashState, remaining, mask);
            remaining -= dSize;
            mask = &mask[dSize];
        }
        retVal = (CRYPT_RESULT)mSize;
    }

    return retVal;
}

UINT16 _cpri__KDFa(TPM_ALG_ID hashAlg,
    TPM2B *key,
    const char *label,
    TPM2B *contextU,
    TPM2B *contextV,
    UINT32 sizeInBits,
    BYTE *keyStream,
    UINT32 *counterInOut,
    BOOL once)
{
    UINT32                   counter = 0;    // counter value
    INT32                    lLen = 0;       // length of the label
    INT16                    hLen;           // length of the hash
    INT16                    bytes;          // number of bytes to produce
    BYTE                    *stream = keyStream;
    BYTE                     marshaledUint32[4];
    CPRI_HASH_STATE          hashState;
    TPM2B                    hmacKey;

    if (counterInOut != NULL)
        counter = *counterInOut;

    // Prepare label buffer.  Calculate its size and keep the last 0 byte
    if (label != NULL)
        for (lLen = 0; label[lLen++] != 0; );

    // Get the hash size.  If it is less than or 0, either the
    // algorithm is not supported or the hash is TPM_ALG_NULL
    // In either case the digest size is zero.  This is the only return
    // other than the one at the end. All other exits from this function
    // are fatal errors. After we check that the algorithm is supported
    // anything else that goes wrong is an implementation flaw.
    if ((hLen = (INT16)HashLength(hashAlg)) == 0)
        return 0;

    bytes = once ? hLen : (INT16)((sizeInBits + 7) / 8);

    // Generate required bytes
    for (; bytes > 0; stream = &stream[hLen], bytes = bytes - hLen)
    {
        if (bytes < hLen)
            hLen = bytes;

        counter++;
        // Start HMAC
        if (_cpri__StartHMAC(hashAlg,
            FALSE,
            &hashState,
            key->size,
            &key->buffer[0],
            &hmacKey) <= 0)
            return 0;

        // Adding counter
        UINT32_TO_BYTE_ARRAY(counter, marshaledUint32);
        _cpri__UpdateHash(&hashState, sizeof(UINT32), marshaledUint32);

        // Adding label
        if (label != NULL)
            _cpri__UpdateHash(&hashState, lLen, (BYTE *)label);

        // Adding contextU
        if (contextU != NULL)
            _cpri__UpdateHash(&hashState, contextU->size, contextU->buffer);

        // Adding contextV
        if (contextV != NULL)
            _cpri__UpdateHash(&hashState, contextV->size, contextV->buffer);

        // Adding size in bits
        UINT32_TO_BYTE_ARRAY(sizeInBits, marshaledUint32);
        _cpri__UpdateHash(&hashState, sizeof(UINT32), marshaledUint32);

        // Compute HMAC. At the start of each iteration, hLen is set
        // to the smaller of hLen and bytes. This causes bytes to decrement
        // exactly to zero to complete the loop
        _cpri__CompleteHMAC(&hashState, &hmacKey, hLen, stream);
    }

    // Mask off bits if the required bits is not a multiple of byte size
    if ((sizeInBits % 8) != 0)
        keyStream[0] &= ((1 << (sizeInBits % 8)) - 1);
    if (counterInOut != NULL)
        *counterInOut = counter;
    return (CRYPT_RESULT)((sizeInBits + 7) / 8);
}

UINT16 _cpri__KDFe(TPM_ALG_ID hashAlg,
    TPM2B *Z,
    const char *label,
    TPM2B *partyUInfo,
    TPM2B *partyVInfo,
    UINT32 sizeInBits,
    BYTE*keyStream)
{
    UINT32       counter = 0;       // counter value
    UINT32       lSize = 0;
    BYTE        *stream = keyStream;
    CPRI_HASH_STATE         hashState;
    INT16        hLen = (INT16)HashLength(hashAlg);
    INT16        bytes;             // number of bytes to generate
    BYTE         marshaledUint32[4];

    if (hLen == 0)
        return 0;

    bytes = (INT16)((sizeInBits + 7) / 8);

    // Prepare label buffer.  Calculate its size and keep the last 0 byte
    if (label != NULL)
        for (lSize = 0; label[lSize++] != 0;);

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
        if (bytes < hLen)
            hLen = bytes;

        counter++;
        // Start hash
        if (_cpri__StartHash(hashAlg, FALSE, &hashState) == 0)
            return 0;

        // Add counter
        UINT32_TO_BYTE_ARRAY(counter, marshaledUint32);
        _cpri__UpdateHash(&hashState, sizeof(UINT32), marshaledUint32);

        // Add Z
        if (Z != NULL)
            _cpri__UpdateHash(&hashState, Z->size, Z->buffer);

        // Add label
        if (label != NULL)
            _cpri__UpdateHash(&hashState, lSize, (BYTE *)label);
        else

            // The SP800-108 specification requires a zero between the label
            // and the context.
            _cpri__UpdateHash(&hashState, 1, (BYTE *)"");

        // Add PartyUInfo
        if (partyUInfo != NULL)
            _cpri__UpdateHash(&hashState, partyUInfo->size, partyUInfo->buffer);

        // Add PartyVInfo
        if (partyVInfo != NULL)
            _cpri__UpdateHash(&hashState, partyVInfo->size, partyVInfo->buffer);

        // Compute Hash. hLen was changed to be the smaller of bytes or hLen
        // at the start of each iteration.
        _cpri__CompleteHash(&hashState, hLen, stream);
    }

    // Mask off bits if the required bits is not a multiple of byte size
    if ((sizeInBits % 8) != 0)
        keyStream[0] &= ((1 << (sizeInBits % 8)) - 1);

    return (CRYPT_RESULT)((sizeInBits + 7) / 8);

}

static CRYPT_RESULT OaepEncode(UINT32 paddedSize,
    BYTE *padded,
    TPM_ALG_ID hashAlg,
    const char *label,
    UINT32 messageSize,
    BYTE *message)
{
    UINT32       padLen;
    UINT32       dbSize;
    UINT32       i;
    BYTE         mySeed[64];
    BYTE        *seed = mySeed;
    INT32        hLen = (UINT32)HashLength(hashAlg);
    BYTE         mask[1024];
    BYTE        *pp;
    BYTE        *pm;
    UINT32       lSize = 0;
    CRYPT_RESULT retVal = CRYPT_SUCCESS;

    // A value of zero is not allowed because the KDF can't produce a result
    // if the digest size is zero.
    if (hLen <= 0)
        return CRYPT_PARAMETER;

    // If a label is provided, get the length of the string, including the 
    // terminator
    if (label != NULL)
        lSize = (UINT32)strlen(label) + 1;

    // Basic size check
    // messageSize <= k  2hLen  2
    if (messageSize > paddedSize - 2 * hLen - 2)
        return CRYPT_FAIL;

    // Hash L even if it is null
    // Offset into padded leaving room for masked seed and byte of zero
    pp = &padded[hLen + 1];
    retVal = _cpri__HashBlock(hashAlg, lSize, (BYTE *)label, hLen, pp);

    // concatenate PS of k  mLen  2hLen  2
    padLen = paddedSize - messageSize - (2 * hLen) - 2;
    memset(&pp[hLen], 0, padLen);
    pp[hLen + padLen] = 0x01;
    padLen += 1;
    memcpy(&pp[hLen + padLen], message, messageSize);

    // The total size of db = hLen + pad + mSize;
    dbSize = hLen + padLen + messageSize;

    // If testing, then use the provided seed. Otherwise, use values
    // from the RNG
    _cpri__GenerateRandom(hLen, mySeed);

    // mask = MGF1 (seed, nSize  hLen  1)
    if ((retVal = _cpri__MGF1(dbSize, mask, hashAlg, hLen, seed)) < 0)
        return retVal; // Don't expect an error because hash size is not zero
                       // was detected in the call to _cpri__HashBlock() above.

                       // Create the masked db
    pm = mask;
    for (i = dbSize; i > 0; i--)
        *pp++ ^= *pm++;
    pp = &padded[hLen + 1];

    // Run the masked data through MGF1
    if ((retVal = _cpri__MGF1(hLen, &padded[1], hashAlg, dbSize, pp)) < 0)
        return retVal; // Don't expect zero here as the only case for zero
                       // was detected in the call to _cpri__HashBlock() above.

                       // Now XOR the seed to create masked seed
    pp = &padded[1];
    pm = seed;
    for (i = hLen; i > 0; i--)
        *pp++ ^= *pm++;

    // Set the first byte to zero
    *padded = 0x00;
    return CRYPT_SUCCESS;
}

static CRYPT_RESULT OaepDecode(UINT32 *dataOutSize,
    BYTE *dataOut,
    TPM_ALG_ID hashAlg,
    const char *label,
    UINT32 paddedSize,
    BYTE *padded)
{
    UINT32       dSizeSave;
    UINT32       i;
    BYTE         seedMask[64];
    INT32        hLen = (UINT32)HashLength(hashAlg);

    BYTE         mask[1024];
    BYTE        *pp;
    BYTE        *pm;
    UINT32       lSize = 0;
    CRYPT_RESULT retVal = CRYPT_SUCCESS;

    // If there is a label, get its size including the terminating 0x00
    if (label != NULL)
        lSize = (UINT32)strlen(label) + 1;

    // Set the return size to zero so that it doesn't have to be done on each
    // failure
    dSizeSave = *dataOutSize;
    *dataOutSize = 0;

    // Strange size (anything smaller can't be an OAEP padded block)
    // Also check for no leading 0
    if (paddedSize < (unsigned)((2 * hLen) + 2) || *padded != 0)
        return CRYPT_FAIL;

    // Use the hash size to determine what to put through MGF1 in order
    // to recover the seedMask
    if ((retVal = _cpri__MGF1(hLen, seedMask, hashAlg,
        paddedSize - hLen - 1, &padded[hLen + 1])) < 0)
        return retVal;

    // Recover the seed into seedMask
    pp = &padded[1];
    pm = seedMask;
    for (i = hLen; i > 0; i--)
        *pm++ ^= *pp++;

    // Use the seed to generate the data mask
    if ((retVal = _cpri__MGF1(paddedSize - hLen - 1, mask, hashAlg,
        hLen, seedMask)) < 0)
        return retVal;

    // Use the mask generated from seed to recover the padded data
    pp = &padded[hLen + 1];
    pm = mask;
    for (i = paddedSize - hLen - 1; i > 0; i--)
        *pm++ ^= *pp++;

    // Make sure that the recovered data has the hash of the label
    // Put trial value in the seed mask
    if ((retVal = _cpri__HashBlock(hashAlg, lSize, (BYTE *)label, hLen, seedMask)) < 0)
        return retVal;

    if (memcmp(seedMask, mask, hLen) != 0)
        return CRYPT_FAIL;


    // find the start of the data
    pm = &mask[hLen];
    for (i = paddedSize - (2 * hLen) - 1; i > 0; i--)
    {
        if (*pm++ != 0)
            break;
    }
    if (i == 0)
        return CRYPT_PARAMETER;

    // pm should be pointing at the first part of the data
    // and i is one greater than the number of bytes to move
    i--;
    if (i > dSizeSave)
    {
        // Restore dSize
        *dataOutSize = dSizeSave;
        return CRYPT_FAIL;
    }
    memcpy(dataOut, pm, i);
    *dataOutSize = i;
    return CRYPT_SUCCESS;
}

static CRYPT_RESULT RSAES_PKSC1v1_5Encode(UINT32 paddedSize,
    BYTE *padded,
    UINT32 messageSize,
    BYTE *message)
{
    UINT32      ps = paddedSize - messageSize - 3;
    if (messageSize > paddedSize - 11)
        return CRYPT_PARAMETER;

    // move the message to the end of the buffer
    memcpy(&padded[paddedSize - messageSize], message, messageSize);

    // Set the first byte to 0x00 and the second to 0x02
    *padded = 0;
    padded[1] = 2;

    // Fill with random bytes
    _cpri__GenerateRandom(ps, &padded[2]);

    // Set the delimiter for the random field to 0
    padded[2 + ps] = 0;

    // Now, the only messy part. Make sure that all the ps bytes are non-zero
    // In this implementation, use the value of the current index
    for (ps++; ps > 1; ps--)
    {
        if (padded[ps] == 0)
            padded[ps] = 0x55;    // In the < 0.5% of the cases that the random
                                  // value is 0, just pick a value to put into
                                  // the spot.
    }
    return CRYPT_SUCCESS;
}

static CRYPT_RESULT RSAES_Decode(UINT32 *messageSize,
    BYTE *message,
    UINT32 codedSize,
    BYTE *coded)
{
    BOOL        fail = FALSE;
    UINT32      ps;

    fail = (codedSize < 11);
    fail |= (coded[0] != 0x00) || (coded[1] != 0x02);
    for (ps = 2; ps < codedSize; ps++)
    {
        if (coded[ps] == 0)
            break;
    }
    ps++;

    // Make sure that ps has not gone over the end and that there are at least 8
    // bytes of pad data.
    fail |= ((ps >= codedSize) || ((ps - 2) < 8));
    if ((*messageSize < codedSize - ps) || fail)
        return CRYPT_FAIL;

    *messageSize = codedSize - ps;
    memcpy(message, &coded[ps], codedSize - ps);
    return CRYPT_SUCCESS;
}

static CRYPT_RESULT PssEncode(UINT32 eOutSize,
    BYTE *eOut,
    TPM_ALG_ID hashAlg,
    UINT32 hashInSize,
    BYTE *hashIn)
{
    INT32                hLen = (UINT32)HashLength(hashAlg);
    BYTE                 salt[1024 - 1];
    UINT16               saltSize;
    BYTE                *ps = salt;
    CRYPT_RESULT         retVal;
    UINT16               mLen;
    CPRI_HASH_STATE      hashState;

    // Get the size of the mask
    mLen = (UINT16)(eOutSize - hLen - 1);

    // Use the maximum salt size
    saltSize = mLen - 1;

    //using eOut for scratch space
    // Set the first 8 bytes to zero
    memset(eOut, 0, 8);

    // Get set the salt
    _cpri__GenerateRandom(saltSize, salt);

    // Create the hash of the pad || input hash || salt
    _cpri__StartHash(hashAlg, FALSE, &hashState);
    _cpri__UpdateHash(&hashState, 8, eOut);
    _cpri__UpdateHash(&hashState, hashInSize, hashIn);
    _cpri__UpdateHash(&hashState, saltSize, salt);
    _cpri__CompleteHash(&hashState, hLen, &eOut[eOutSize - hLen - 1]);

    // Create a mask
    if ((retVal = _cpri__MGF1(mLen, eOut, hashAlg, hLen, &eOut[mLen])) < 0)
    {
        // Currently _cpri__MGF1 is not expected to return a CRYPT_RESULT error.
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
    for (; saltSize > 0; saltSize--)
        *eOut++ ^= *ps++;

    // and we are done
    return CRYPT_SUCCESS;
}

static CRYPT_RESULT PssDecode(TPM_ALG_ID hashAlg,
    UINT32 dInSize,
    BYTE *dIn,
    UINT32 eInSize,
    BYTE *eIn,
    UINT32 saltSize)
{
    INT32            hLen = (UINT32)HashLength(hashAlg);
    BYTE             mask[1024];
    BYTE            *pm = mask;
    BYTE             pad[8] = { 0 };
    UINT32           i;
    UINT32           mLen;
    BOOL             fail = FALSE;
    CRYPT_RESULT     retVal;
    CPRI_HASH_STATE  hashState;

    // check the hash scheme
    if (hLen == 0)
        return CRYPT_SCHEME;

    // most significant bit must be zero
    fail = ((eIn[0] & 0x80) != 0);

    // last byte must be 0xbc
    fail |= (eIn[eInSize - 1] != 0xbc);

    // Use the hLen bytes at the end of the buffer to generate a mask
    // Doesn't start at the end which is a flag byte
    mLen = eInSize - hLen - 1;
    if ((retVal = _cpri__MGF1(mLen, mask, hashAlg, hLen, &eIn[mLen])) < 0)
        return retVal;
    if (retVal == 0)
        return CRYPT_FAIL;

    // Clear the MSO of the mask to make it consistent with the encoding.
    mask[0] &= 0x7F;

    // XOR the data into the mask to recover the salt. This sequence
    // advances eIn so that it will end up pointing to the seed data
    // which is the hash of the signature data
    for (i = mLen; i > 0; i--)
        *pm++ ^= *eIn++;

    // Find the first byte of 0x01 after a string of all 0x00
    for (pm = mask, i = mLen; i > 0; i--)
    {
        if (*pm == 0x01)
            break;
        else
            fail |= (*pm++ != 0);
    }
    fail |= (i == 0);

    // if we have failed, will continue using the entire mask as the salt value so
    // that the timing attacks will not disclose anything (I don't think that this
    // is a problem for TPM applications but, usually, we don't fail so this
    // doesn't cost anything).
    if (fail)
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
    retVal = _cpri__CompleteHash(&hashState, sizeof(mask), mask);

    // retVal will be the size of the digest or zero. If not equal to the indicated
    // digest size, then the signature doesn't match
    fail |= (retVal != hLen);
    fail |= (memcmp(mask, eIn, hLen) != 0);
    if (fail)
        return CRYPT_FAIL;
    else
        return CRYPT_SUCCESS;
}

static UINT16 _cpri__GetHashDER(TPM_ALG_ID hashAlg,
    const BYTE **p)
{
    switch (hashAlg)
    {
    case TPM_ALG_SHA1:
        *p = SHA1_DER_STRING;
        return SHA1_DER_SIZE;

    case TPM_ALG_SHA256:
        *p = SHA256_DER_STRING;
        return SHA256_DER_SIZE;

    case TPM_ALG_SHA384:
        *p = SHA384_DER_STRING;
        return SHA384_DER_SIZE;

    case TPM_ALG_SHA512:
        *p = SHA512_DER_STRING;
        return SHA512_DER_SIZE;

    default:
        *p = NULL;
        return 0;
    }
}

static CRYPT_RESULT RSASSA_Encode(UINT32 eOutSize,
    BYTE *eOut,
    TPM_ALG_ID hashAlg,
    UINT32 hInSize,
    BYTE *hIn)
{
    BYTE            *der;
    INT32            derSize = _cpri__GetHashDER(hashAlg, (const BYTE**)&der);
    INT32            fillSize;

    // Can't use this scheme if the algorithm doesn't have a DER string defined.
    if (derSize == 0)
        return CRYPT_SCHEME;

    // If the digest size of 'hashAl' doesn't match the input digest size, then 
    // the DER will misidentify the digest so return an error
    if ((unsigned)HashLength(hashAlg) != hInSize)
        return CRYPT_PARAMETER;

    fillSize = eOutSize - derSize - hInSize - 3;

    // Make sure that this combination will fit in the provided space
    if (fillSize < 8)
        return CRYPT_PARAMETER;
    // Start filling
    *eOut++ = 0; // initial byte of zero
    *eOut++ = 1; // byte of 0x01
    for (; fillSize > 0; fillSize--)
        *eOut++ = 0xff; // bunch of 0xff
    *eOut++ = 0; // another 0
    for (; derSize > 0; derSize--)
        *eOut++ = *der++;   // copy the DER
    for (; hInSize > 0; hInSize--)
        *eOut++ = *hIn++;   // copy the hash
    return CRYPT_SUCCESS;
}

static CRYPT_RESULT RSASSA_Decode(TPM_ALG_ID hashAlg,
    UINT32 hInSize,
    BYTE *hIn,
    UINT32 eInSize,
    BYTE *eIn)
{
    BOOL             fail = FALSE;
    BYTE            *der;
    INT32            derSize = _cpri__GetHashDER(hashAlg, (const BYTE**)&der);
    INT32            hashSize = (UINT32)HashLength(hashAlg);
    INT32            fillSize;

    // Can't use this scheme if the algorithm doesn't have a DER string
    // defined or if the provided hash isn't the right size
    if (derSize == 0 || (unsigned)hashSize != hInSize)
        return CRYPT_SCHEME;

    // Make sure that this combination will fit in the provided space
    // Since no data movement takes place, can just walk though this
    // and accept nearly random values. This can only be called from
    // _cpri__ValidateSignature() so eInSize is known to be in range.
    fillSize = eInSize - derSize - hashSize - 3;

    // Start checking
    fail |= (*eIn++ != 0); // initial byte of zero
    fail |= (*eIn++ != 1); // byte of 0x01
    for (; fillSize > 0; fillSize--)
        fail |= (*eIn++ != 0xff); // bunch of 0xff
    fail |= (*eIn++ != 0); // another 0
    for (; derSize > 0; derSize--)
        fail |= (*eIn++ != *der++); // match the DER
    for (; hInSize > 0; hInSize--)
        fail |= (*eIn++ != *hIn++); // match the hash
    if (fail)
        return CRYPT_FAIL;
    return CRYPT_SUCCESS;
}

CRYPT_RESULT _cpri__EncryptRSA(UINT32 *cOutSize,
    BYTE *cOut,
    RSA_KEY *key,
    TPM_ALG_ID padType,
    UINT32 dInSize,
    BYTE *dIn,
    TPM_ALG_ID hashAlg,
    const char *label)
{
    CRYPT_RESULT    retVal = CRYPT_SUCCESS;

    // All encryption schemes return the same size of data
    if (*cOutSize < key->publicKey->size)
        return CRYPT_PARAMETER;
    *cOutSize = key->publicKey->size;

    switch (padType)
    {
    case TPM_ALG_NULL:  // 'raw' encryption
    {
        // dIn can have more bytes than cOut as long as the extra bytes
        // are zero
        for (; dInSize > *cOutSize; dInSize--)
        {
            if (*dIn++ != 0)
                return CRYPT_PARAMETER;

        }
        // If dIn is smaller than cOut, fill cOut with zeros
        if (dInSize < *cOutSize)
            memset(cOut, 0, *cOutSize - dInSize);

        // Copy the rest of the value
        memcpy(&cOut[*cOutSize - dInSize], dIn, dInSize);
        // If the size of dIn is the same as cOut dIn could be larger than
        // the modulus. If it is, then RSAEP() will catch it.
    }
    break;
    case TPM_ALG_RSAES:
        retVal = RSAES_PKSC1v1_5Encode(*cOutSize, cOut, dInSize, dIn);
        break;
    case TPM_ALG_OAEP:
        retVal = OaepEncode(*cOutSize, cOut, hashAlg, label, dInSize, dIn);
        break;
    default:
        return CRYPT_SCHEME;
    }
    // All the schemes that do padding will come here for the encryption step
    // Check that the Encoding worked
    if (retVal != CRYPT_SUCCESS)
        return retVal;

    // Padding OK so do the encryption
    return (RSAEP(*cOutSize, cOut, key->publicKey->size, key->publicKey->buffer, key->exponent) == TRUE) ? CRYPT_SUCCESS : CRYPT_FAIL;
}

CRYPT_RESULT _cpri__DecryptRSA(UINT32 *dOutSize,
    BYTE *dOut,
    RSA_KEY *key,
    TPM_ALG_ID padType,
    UINT32 cInSize,
    BYTE *cIn,
    TPM_ALG_ID hashAlg,
    const char *label)
{
    // Size is checked to make sure that the decryption works properly
    if (cInSize != key->publicKey->size)
        return CRYPT_PARAMETER;

    // For others that do padding, do the decryption in place and then
    // go handle the decoding.
    if (RSADP(cInSize, cIn, key->privateKey->size, key->privateKey->buffer, key->publicKey->size, key->publicKey->buffer) != TRUE)
        return CRYPT_FAIL;  // Decryption failed

                            // Remove padding
    switch (padType)
    {
    case TPM_ALG_NULL:
        if (*dOutSize < key->publicKey->size)
            return CRYPT_FAIL;
        *dOutSize = key->publicKey->size;
        memcpy(dOut, cIn, *dOutSize);
        return CRYPT_SUCCESS;
    case TPM_ALG_RSAES:
        return RSAES_Decode(dOutSize, dOut, cInSize, cIn);
    case TPM_ALG_OAEP:
        return OaepDecode(dOutSize, dOut, hashAlg, label, cInSize, cIn);
    default:
        return CRYPT_SCHEME;
    }
}

CRYPT_RESULT _cpri__SignRSA(UINT32 *sigOutSize,
    BYTE *sigOut,
    RSA_KEY *key,
    TPM_ALG_ID scheme,
    TPM_ALG_ID hashAlg,
    UINT32 hInSize,
    BYTE *hIn)
{
    CRYPT_RESULT    retVal;

    // For all signatures the size is the size of the key modulus
    *sigOutSize = key->publicKey->size;
    switch (scheme)
    {
    case TPM_ALG_NULL:
        *sigOutSize = 0;
        return CRYPT_SUCCESS;
    case TPM_ALG_RSAPSS:
        // PssEncode can return CRYPT_PARAMETER
        retVal = PssEncode(*sigOutSize, sigOut, hashAlg, hInSize, hIn);
        break;
    case TPM_ALG_RSASSA:
        // RSASSA_Encode can return CRYPT_PARAMETER or CRYPT_SCHEME
        retVal = RSASSA_Encode(*sigOutSize, sigOut, hashAlg, hInSize, hIn);
        break;
    default:
        return CRYPT_SCHEME;
    }
    if (retVal != CRYPT_SUCCESS)
        return retVal;
    // Do the encryption using the private key
    // RSADP can return CRYPT_PARAMETR
    return (RSADP(*sigOutSize, sigOut, key->privateKey->size, key->privateKey->buffer, key->publicKey->size, key->publicKey->buffer) == TRUE) ? CRYPT_SUCCESS : CRYPT_FAIL;
}

CRYPT_RESULT _cpri__ValidateSignatureRSA(RSA_KEY *key,
    TPM_ALG_ID scheme,
    TPM_ALG_ID hashAlg,
    UINT32 hInSize,
    BYTE *hIn,
    UINT32 sigInSize,
    BYTE *sigIn,
    UINT16 saltSize)
{
    // Errors that might be caused by calling parameters
    if (sigInSize != key->publicKey->size)
        return CRYPT_FAIL;
    // Decrypt the block
    if (RSAEP(sigInSize, sigIn, key->publicKey->size, key->publicKey->buffer, key->exponent) != TRUE)
        return CRYPT_FAIL;
    switch (scheme)
    {
    case TPM_ALG_NULL:
        return CRYPT_SCHEME;
    case TPM_ALG_RSAPSS:
        return PssDecode(hashAlg, hInSize, hIn, sigInSize, sigIn, saltSize);
    case TPM_ALG_RSASSA:
        return RSASSA_Decode(hashAlg, hInSize, hIn, sigInSize, sigIn);
    default:
        break;
    }
    return CRYPT_SCHEME;
}

static CRYPT_RESULT
AES_create_key(const unsigned char *userKey,
    const int bits,
    PVOID *key)
{
    TPM2B* keyContext = NULL;

    // Remember the key
    if ((keyContext = (TPM2B*)malloc(sizeof(TPM2B))) != NULL)
    {
        keyContext->size = bits / 8;
        memcpy(keyContext->buffer, userKey, keyContext->size);
        *key = keyContext;
    }

    return (keyContext) ? CRYPT_SUCCESS : CRYPT_FAIL;
}

static CRYPT_RESULT
AES_destroy_key(PVOID key)
{
    TPM2B* keyContext = (TPM2B*)key;
    memset(keyContext, 0x00, sizeof(TPM2B));
    free(keyContext);
    return CRYPT_SUCCESS;
}

static CRYPT_RESULT
AES_encrypt(const unsigned char *in,
    unsigned char *out,
    PVOID key)
{
    TPM2B* keyContext = (TPM2B*)key;
    Aes aesKey = { 0 };
    BYTE iv[AES_BLOCK_SIZE] = { 0 };
    if (wc_AesSetKey(&aesKey, keyContext->buffer, keyContext->size, iv, AES_ENCRYPTION) != 0)
    {
        return CRYPT_FAIL;
    }
    wc_AesEncryptDirect(&aesKey, out, in);
    memset(&aesKey, 0x00, sizeof(aesKey));
    return CRYPT_SUCCESS;
}

static CRYPT_RESULT
AES_decrypt(const unsigned char *in,
    unsigned char *out,
    PVOID key)
{
    TPM2B* keyContext = (TPM2B*)key;
    Aes aesKey = { 0 };
    BYTE iv[AES_BLOCK_SIZE] = { 0 };
    if (wc_AesSetKey(&aesKey, keyContext->buffer, keyContext->size, iv, AES_DECRYPTION) != 0)
    {
        return CRYPT_FAIL;
    }
    wc_AesDecryptDirect(&aesKey, out, in);
    memset(&aesKey, 0x00, sizeof(aesKey));
    return CRYPT_SUCCESS;
}

CRYPT_RESULT
_cpri__AESEncryptCBC(BYTE *dOut,
    UINT32 keySizeInBits,
    BYTE *key,
    BYTE *iv,
    UINT32 dInSize,
    BYTE *dIn)
{
    PVOID  AesKey;
    BYTE  *pIv;
    INT32  dSize;         // Need a signed version
    int    i;

    if (dInSize == 0)
        return CRYPT_SUCCESS;

    dSize = (INT32)dInSize;

    // For CBC, the data size must be an even multiple of the
    // cipher block size
    if ((dSize % 16) != 0)
        return CRYPT_PARAMETER;

    // Create AES encrypt key schedule
    if (AES_create_key(key, keySizeInBits, &AesKey) != 0)
        return CRYPT_FAIL;

    // XOR the data block into the IV, encrypt the IV into the IV
    // and then copy the IV to the output
    for (; dSize > 0; dSize -= 16)
    {
        pIv = iv;
        for (i = 16; i > 0; i--)
            *pIv++ ^= *dIn++;
        AES_encrypt(iv, iv, AesKey);
        pIv = iv;
        for (i = 16; i > 0; i--)
            *dOut++ = *pIv++;
    }

    // destroy AES encrypt key schedule
    if (AES_destroy_key(AesKey) != 0)
        return CRYPT_FAIL;

    return CRYPT_SUCCESS;
}

CRYPT_RESULT
_cpri__AESDecryptCBC(BYTE *dOut,
    UINT32 keySizeInBits,
    BYTE *key,
    BYTE *iv,
    UINT32 dInSize,
    BYTE *dIn)
{
    PVOID  AesKey;
    BYTE  *pIv;
    int    i;
    BYTE   tmp[16];
    BYTE  *pT = NULL;
    INT32  dSize;

    if (dInSize == 0)
        return CRYPT_SUCCESS;

    dSize = (INT32)dInSize;

    // For CBC, the data size must be an even multiple of the
    // cipher block size
    if ((dSize % 16) != 0)
        return CRYPT_PARAMETER;

    // Create AES key schedule
    if (AES_create_key(key, keySizeInBits, &AesKey) != 0)
        return CRYPT_FAIL;

    // Copy the input data to a temp buffer, decrypt the buffer into the output;
    // XOR in the IV, and copy the temp buffer to the IV and repeat.
    for (; dSize > 0; dSize -= 16)
    {
        pT = tmp;
        for (i = 16; i> 0; i--)
            *pT++ = *dIn++;
        AES_decrypt(tmp, dOut, AesKey);
        pIv = iv;
        pT = tmp;
        for (i = 16; i> 0; i--)
        {
            *dOut++ ^= *pIv;
            *pIv++ = *pT++;
        }
    }

    // destroy AES encrypt key schedule
    if (AES_destroy_key(AesKey) != 0)
        return CRYPT_FAIL;

    return CRYPT_SUCCESS;
}

CRYPT_RESULT
_cpri__AESEncryptCFB(BYTE *dOut,
    UINT32 keySizeInBits,
    BYTE *key,
    BYTE *iv,
    UINT32 dInSize,
    BYTE *dIn)
{
    BYTE        *pIv = NULL;
    PVOID        AesKey;
    INT32        dSize;         // Need a signed version of dInSize
    int          i;

    if (dInSize == 0)
        return CRYPT_SUCCESS;

    dSize = (INT32)dInSize;

    // Create AES encryption key schedule
    if (AES_create_key(key, keySizeInBits, &AesKey) != 0)
        return CRYPT_FAIL;

    // Encrypt the IV into the IV, XOR in the data, and copy to output
    for (; dSize > 0; dSize -= 16)
    {
        // Encrypt the current value of the IV
        AES_encrypt(iv, iv, AesKey);
        pIv = iv;
        for (i = (int)(dSize < 16) ? dSize : 16; i > 0; i--)
            // XOR the data into the IV to create the cipher text
            // and put into the output
            *dOut++ = *pIv++ ^= *dIn++;
    }
    // If the inner loop (i loop) was smaller than 16, then dSize would have been
    // smaller than 16 and it is now negative. If it is negative, then it indicates
    // how many bytes are needed to pad out the IV for the next round.
    for (; dSize < 0; dSize++)
        *pIv++ = 0;

    // destroy AES encrypt key schedule
    if (AES_destroy_key(AesKey) != 0)
        return CRYPT_FAIL;

    return CRYPT_SUCCESS;
}

CRYPT_RESULT
_cpri__AESDecryptCFB(BYTE *dOut,
    UINT32 keySizeInBits,
    BYTE *key,
    BYTE *iv,
    UINT32 dInSize,
    BYTE *dIn)
{
    BYTE        *pIv = NULL;
    BYTE         tmp[16];
    int          i;
    BYTE        *pT;
    PVOID      AesKey;
    INT32        dSize;

    if (dInSize == 0)
        return CRYPT_SUCCESS;

    dSize = (INT32)dInSize;

    // Create AES encryption key schedule
    if (AES_create_key(key, keySizeInBits, &AesKey) != 0)
        return CRYPT_FAIL;

    for (; dSize > 0; dSize -= 16)
    {
        // Encrypt the IV into the temp buffer
        AES_encrypt(iv, tmp, AesKey);
        pT = tmp;
        pIv = iv;
        for (i = (dSize < 16) ? dSize : 16; i > 0; i--)
            // Copy the current cipher text to IV, XOR
            // with the temp buffer and put into the output
            *dOut++ = *pT++ ^ (*pIv++ = *dIn++);
    }
    // If the inner loop (i loop) was smaller than 16, then dSize
    // would have been smaller than 16 and it is now negative
    // If it is negative, then it indicates how may fill bytes
    // are needed to pad out the IV for the next round.
    for (; dSize < 0; dSize++)
        *pIv++ = 0;

    // destroy AES encrypt key schedule
    if (AES_destroy_key(AesKey) != 0)
        return CRYPT_FAIL;

    return CRYPT_SUCCESS;
}

CRYPT_RESULT
_cpri__AESEncryptCTR(BYTE *dOut,
    UINT32 keySizeInBits,
    BYTE *key,
    BYTE *iv,
    UINT32 dInSize,
    BYTE *dIn)
{
    BYTE         tmp[16];
    BYTE        *pT;
    PVOID        AesKey;
    int          i;
    INT32        dSize;

    if (dInSize == 0)
        return CRYPT_SUCCESS;

    dSize = (INT32)dInSize;

    // Create AES encryption schedule
    if (AES_create_key(key, keySizeInBits, &AesKey) != 0)
        return CRYPT_FAIL;

    for (; dSize > 0; dSize -= 16)
    {
        // Encrypt the current value of the IV(counter)
        AES_encrypt(iv, (BYTE *)tmp, AesKey);

        //increment the counter (counter is big-endian so start at end)
        for (i = 15; i >= 0; i--)
            if ((iv[i] += 1) != 0)
                break;

        // XOR the encrypted counter value with input and put into output
        pT = tmp;
        for (i = (dSize < 16) ? dSize : 16; i > 0; i--)
            *dOut++ = *dIn++ ^ *pT++;
    }

    // destroy AES encrypt key schedule
    if (AES_destroy_key(AesKey) != 0)
        return CRYPT_FAIL;

    return CRYPT_SUCCESS;
}

CRYPT_RESULT
_cpri__AESEncryptECB(BYTE *dOut,
    UINT32 keySizeInBits,
    BYTE *key,
    UINT32 dInSize,
    BYTE *dIn)
{
    PVOID      AesKey;
    INT32        dSize;

    if (dInSize == 0)
        return CRYPT_SUCCESS;

    dSize = (INT32)dInSize;

    // For ECB, the data size must be an even multiple of the
    // cipher block size
    if ((dSize % 16) != 0)
        return CRYPT_PARAMETER;
    // Create AES encrypting key schedule
    if (AES_create_key(key, keySizeInBits, &AesKey) != 0)
        return CRYPT_FAIL;

    for (; dSize > 0; dSize -= 16)
    {
        AES_encrypt(dIn, dOut, AesKey);
        dIn = &dIn[16];
        dOut = &dOut[16];
    }

    // destroy AES encrypt key schedule
    if (AES_destroy_key(AesKey) != 0)
        return CRYPT_FAIL;

    return CRYPT_SUCCESS;
}

CRYPT_RESULT
_cpri__AESDecryptECB(BYTE *dOut,
    UINT32 keySizeInBits,
    BYTE *key,
    UINT32 dInSize,
    BYTE *dIn)
{
    PVOID      AesKey;
    INT32        dSize;

    if (dInSize == 0)
        return CRYPT_SUCCESS;

    dSize = (INT32)dInSize;

    // For ECB, the data size must be an even multiple of the
    // cipher block size
    if ((dSize % 16) != 0)
        return CRYPT_PARAMETER;

    // Create AES decryption key schedule
    if (AES_create_key(key, keySizeInBits, &AesKey) != 0)
        return CRYPT_FAIL;

    for (; dSize > 0; dSize -= 16)
    {
        AES_decrypt(dIn, dOut, AesKey);
        dIn = &dIn[16];
        dOut = &dOut[16];
    }

    // destroy AES encrypt key schedule
    if (AES_destroy_key(AesKey) != 0)
        return CRYPT_FAIL;

    return CRYPT_SUCCESS;
}

CRYPT_RESULT
_cpri__AESEncryptOFB(BYTE *dOut,
    UINT32 keySizeInBits,
    BYTE *key,
    BYTE *iv,
    UINT32 dInSize,
    BYTE *dIn)
{
    BYTE        *pIv;
    PVOID      AesKey;
    INT32        dSize;
    int          i;

    if (dInSize == 0)
        return CRYPT_SUCCESS;

    dSize = (INT32)dInSize;

    // Create AES key schedule
    if (AES_create_key(key, keySizeInBits, &AesKey) != 0)
        return CRYPT_FAIL;

    // This is written so that dIn and dOut may be the same

    for (; dSize > 0; dSize -= 16)
    {
        // Encrypt the current value of the "IV"
        AES_encrypt(iv, iv, AesKey);

        // XOR the encrypted IV into dIn to create the cipher text (dOut)
        pIv = iv;
        for (i = (dSize < 16) ? dSize : 16; i > 0; i--)
            *dOut++ = (*pIv++ ^ *dIn++);
    }

    // destroy AES encrypt key schedule
    if (AES_destroy_key(AesKey) != 0)
        return CRYPT_FAIL;

    return CRYPT_SUCCESS;
}
