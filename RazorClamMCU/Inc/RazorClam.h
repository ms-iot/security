#ifndef __RAZORCLAM_H
#define __RAZORCLAM_H

#define TPM_SECUREBOOT_NV_RANGE (0x4241) // "AB" AuthenticatedBoot (an arbitrary spot in NV)
#define TPM_PLATFORM_LOCKDOWN_POLICY_NV_INDEX (0x01000000 | (TPM_SECUREBOOT_NV_RANGE << 8))
#define TPM_PLATFORM_COUNTERS_NV_INDEX (0x01000010 | (TPM_SECUREBOOT_NV_RANGE << 8))

#define RAZORCLAMPERSISTEDDATA (0x4144504d4c435a52) //'ADPMLCZR' RaZorCLaM Persisted Data Area
#define RAZORCLAMPERSISTEDVERSION (0x00000001)
#define TPM_APP_AUTHORITY_SECTION (0x48545541324D5054) //'TPM2AUTH'

#define TPM_SECUREBOOT_NV_RANGE (0x4241) // "AB" AuthenticatedBoot (an arbitrary spot in NV)
#define TPM_PLATFORM_LOCKDOWN_POLICY_NV_INDEX (0x01000000 | (TPM_SECUREBOOT_NV_RANGE << 8))
#define PLATFORM_POLICY_MAX_ENTRIES                   10

#define ADDR_FLASH_SECTOR_23 ((uint32_t)0x081E0000)

typedef struct {
    unsigned int dropPlatformAuth            : 1;
    unsigned int dropLockoutAuth             : 1;
    unsigned int dropEndorsementAuth         : 1;
    unsigned int dropOwnerAuth               : 1;
    unsigned int incrementCounter            : 2;
    unsigned int resetLockout                : 1;
    unsigned int platformClearTpm            : 1;
    unsigned int disablePlatformHierarchy    : 1;
    unsigned int disablePlatformNV           : 1;
    unsigned int disableEndorsementHierarchy : 1;
    unsigned int disableOwnerHierarchy       : 1;
} TPMA_POLICY_ACTION;

typedef struct {
    unsigned int isDefaultPolicy             : 1;
    unsigned int isAuthorityPolicy           : 1;
    unsigned int isBinaryPolicy              : 1;
    unsigned int launchApp                   : 1;
    unsigned int rebootMcu                   : 1;
    unsigned int haltMcu                     : 1;
    unsigned int launchFlashLoader           : 1;
} TPMA_POLICY_INFO;

typedef union {
    struct
    {
        TPMA_POLICY_INFO info;
        TPMA_POLICY_ACTION action;
    } t;
    UINT64 b;
} TPMU_POLICY_FLAGS;

typedef struct {
    TPMU_POLICY_FLAGS policy;
    TPM2B_NAME entity;
} TPMT_POLICY_ENTRY;

typedef struct {
    UINT32           count;
    TPMT_POLICY_ENTRY policies[PLATFORM_POLICY_MAX_ENTRIES];
} TPML_POLICY_ENTRIES;

typedef struct
{
    UINT64       magic;
    UINT32       version;
    UINT32       size;
    TPM2B_DIGEST compoundIdentity;
    TPM2B_NAME   ekName;
    TPM2B_NAME   platformAuthorityName;
    TPM2B_AUTH   lockoutAuth;
    TPM2B_AUTH   endorsementAuth;
    TPM2B_AUTH   storageAuth;
} RazorClamPersistentDataType, *pRazorClamPersistentDataType;

typedef struct
{
    UINT32 pcrIndex;
    TPML_DIGEST_VALUES measurement;
} RazorClamLogEntry, *pRazorClamLogEntry;

typedef struct
{
    TPM2B_AUTH        platformAuth;
    ANY_OBJECT        platformObject;
    ANY_OBJECT        lockoutObject;
    ANY_OBJECT        endorsementObject;
    ANY_OBJECT        storageOwnerObject;
    ANY_OBJECT        ekObject;
    ANY_OBJECT        srkObject;
    ANY_OBJECT        hmacAikObject;
    TPMS_CONTEXT      hmacAikBlob;
    ANY_OBJECT        aesDpkObject;
    TPMS_CONTEXT      aesDpkBlob;
    SESSION           ekSeededSession;
    UINT32            resetCount;
    UINT32            restartCount;
    INT64             tickOffest;
    INT32             tickDrift;
    UINT32            measurementIndex;
    RazorClamLogEntry measurementLog[10];
} RazorClamVolatileDataType, *pRazorClamVolatileDataType;

extern RazorClamVolatileDataType volatileData;
extern RazorClamPersistentDataType persistedData;
extern uint32_t fakeAppPayloadSize;
extern uint8_t* fakeAppPayload;

extern "C" uint32_t RazorClam(void);
void PrintBuffer(char* label, uint8_t* dataPtr, uint32_t dataSize);
void PrintTPM2B(const char* label, const TPM2B* data);
void PrintTPM2BInitializer(const char* label, const TPM2B* data);
UINT16 TPML_POLICY_ENTRIES_Marshal(TPML_POLICY_ENTRIES *source, BYTE **buffer, INT32 *size);
TPM_RC TPML_POLICY_ENTRIES_Unmarshal(TPML_POLICY_ENTRIES *target, BYTE **buffer, INT32 *size);
UINT32 FlushContext(ANY_OBJECT* tpmObject);
UINT32 ProtectPlatformData(uint8_t* dataPtr, uint16_t dataSize, TPMI_YES_NO decrypt);
UINT32 StartEkSeededSession(void);
UINT32 MeasureEventConfidential(UINT32 pcrIndex, UINT32 dataSize, BYTE* dataPtr);


#endif
