/*
 * TpmUtil.cpp
 *
 *  Created on: Apr 12, 2016
 *      Author: stefanth
 */

#include <string.h>
#include "stm32f4xx_hal.h"
#include "TisTpmDrv.h"
#include "UrchinLib.h"
#include "UrchinPlatform.h"
#include "RazorClam.h"
#include "TpmUtil.h"

#define ADDR_FLASH_SECTOR_23 ((uint32_t)0x081E0000)

//extern uint8_t fakeAppPayload[213];

void
TpmUtilStorePersistedData(void)
{
    printf("Persisting new configuration in MCU flash");
    HAL_FLASH_Unlock();
    FLASH_Erase_Sector(FLASH_SECTOR_23, FLASH_VOLTAGE_RANGE_3);
    for(uint32_t n = 0; n < sizeof(persistedData); n++)
    {
        if(HAL_FLASH_Program(FLASH_TYPEPROGRAM_BYTE, ADDR_FLASH_SECTOR_23 + n, ((uint8_t*)&persistedData)[n]) != HAL_OK)
        {
            printf("Flash Write Error @ 0x%08x\r\n", ADDR_FLASH_SECTOR_23 + n);
        }
    }
    HAL_FLASH_Lock();
}

void
TpmUtilLoadPersistedData(void)
{
    printf("Retrieving configuration from MCU flash");
    memcpy((uint8_t*)&persistedData, (void*)ADDR_FLASH_SECTOR_23, sizeof(persistedData));
    fakeAppPayloadSize = *((uint32_t*)(ADDR_FLASH_SECTOR_23 + persistedData.size));
    fakeAppPayload = ((uint8_t*)(ADDR_FLASH_SECTOR_23 + persistedData.size + sizeof(uint32_t)));
}

static UINT32
SetTpmAuthValues(void)
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    union
    {
        HierarchyChangeAuth_In hierarchyChangeAuth;
    } in;
    union
    {
        HierarchyChangeAuth_Out hierarchyChangeAuth;
    } out;

    INITIALIZE_CALL_BUFFERS(TPM2_HierarchyChangeAuth, &in.hierarchyChangeAuth, &out.hierarchyChangeAuth);
    parms.objectTableIn[TPM2_HierarchyChangeAuth_HdlIn_AuthHandle].entity.handle = TPM_RH_LOCKOUT;
    UINT32_TO_BYTE_ARRAY(parms.objectTableIn[TPM2_HierarchyChangeAuth_HdlIn_AuthHandle].entity.handle, parms.objectTableIn[TPM2_HierarchyChangeAuth_HdlIn_AuthHandle].entity.name.t.name);
    parms.objectTableIn[TPM2_HierarchyChangeAuth_HdlIn_AuthHandle].entity.name.t.size = sizeof(parms.objectTableIn[TPM2_HierarchyChangeAuth_HdlIn_AuthHandle].entity.handle);
    in.hierarchyChangeAuth.newAuth.t.size = CryptGenerateRandom(SHA256_DIGEST_SIZE, in.hierarchyChangeAuth.newAuth.t.buffer);
    EXECUTE_TPM_CALL(FALSE, TPM2_HierarchyChangeAuth);
    persistedData.lockoutAuth = in.hierarchyChangeAuth.newAuth;

    INITIALIZE_CALL_BUFFERS(TPM2_HierarchyChangeAuth, &in.hierarchyChangeAuth, &out.hierarchyChangeAuth);
    parms.objectTableIn[TPM2_HierarchyChangeAuth_HdlIn_AuthHandle].entity.handle = TPM_RH_ENDORSEMENT;
    UINT32_TO_BYTE_ARRAY(parms.objectTableIn[TPM2_HierarchyChangeAuth_HdlIn_AuthHandle].entity.handle, parms.objectTableIn[TPM2_HierarchyChangeAuth_HdlIn_AuthHandle].entity.name.t.name);
    parms.objectTableIn[TPM2_HierarchyChangeAuth_HdlIn_AuthHandle].entity.name.t.size = sizeof(parms.objectTableIn[TPM2_HierarchyChangeAuth_HdlIn_AuthHandle].entity.handle);
    in.hierarchyChangeAuth.newAuth.t.size = CryptGenerateRandom(SHA256_DIGEST_SIZE, in.hierarchyChangeAuth.newAuth.t.buffer);
    EXECUTE_TPM_CALL(FALSE, TPM2_HierarchyChangeAuth);
    persistedData.endorsementAuth = in.hierarchyChangeAuth.newAuth;

    INITIALIZE_CALL_BUFFERS(TPM2_HierarchyChangeAuth, &in.hierarchyChangeAuth, &out.hierarchyChangeAuth);
    parms.objectTableIn[TPM2_HierarchyChangeAuth_HdlIn_AuthHandle].entity.handle = TPM_RH_OWNER;
    UINT32_TO_BYTE_ARRAY(parms.objectTableIn[TPM2_HierarchyChangeAuth_HdlIn_AuthHandle].entity.handle, parms.objectTableIn[TPM2_HierarchyChangeAuth_HdlIn_AuthHandle].entity.name.t.name);
    parms.objectTableIn[TPM2_HierarchyChangeAuth_HdlIn_AuthHandle].entity.name.t.size = sizeof(parms.objectTableIn[TPM2_HierarchyChangeAuth_HdlIn_AuthHandle].entity.handle);
    in.hierarchyChangeAuth.newAuth.t.size = CryptGenerateRandom(SHA256_DIGEST_SIZE, in.hierarchyChangeAuth.newAuth.t.buffer);
    EXECUTE_TPM_CALL(FALSE, TPM2_HierarchyChangeAuth);
    persistedData.storageAuth = in.hierarchyChangeAuth.newAuth;

Cleanup:
    if(result != TPM_RC_SUCCESS)
    {
        // Copy the EKSeeded session back out in case of an error
        sessionTable[0].attributes = volatileData.ekSeededSession.attributes;
        volatileData.ekSeededSession = sessionTable[0];
    }
    return TPM_RC_SUCCESS;
}

static uint32_t
TpmUtilCreateAuthority(
    char* authorityName,
    ANY_OBJECT* sigkey
    )
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    union
    {
        CreatePrimary_In createPrimary;
    } in;
    union
    {
        CreatePrimary_Out createPrimary;
    } out;

    // This is set up to create an SM2 key that is using SM3 payload hashing
    INITIALIZE_CALL_BUFFERS(TPM2_CreatePrimary, &in.createPrimary, &out.createPrimary);
    parms.objectTableIn[TPM2_CreatePrimary_HdlIn_PrimaryHandle].entity.handle = TPM_RH_ENDORSEMENT;
    in.createPrimary.inPublic.t.publicArea.nameAlg = TPM_ALG_SHA256;
    in.createPrimary.inPublic.t.publicArea.objectAttributes.sensitiveDataOrigin = SET;
    in.createPrimary.inPublic.t.publicArea.objectAttributes.userWithAuth = SET;
    in.createPrimary.inPublic.t.publicArea.objectAttributes.noDA = SET;
    in.createPrimary.inPublic.t.publicArea.objectAttributes.sign = SET;
#ifdef NTZTPM
    in.createPrimary.inPublic.t.publicArea.type = TPM_ALG_ECC;
    in.createPrimary.inPublic.t.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_SM2;
    in.createPrimary.inPublic.t.publicArea.parameters.eccDetail.scheme.details.ecdsa.hashAlg = TPM_ALG_SM3_256;
    in.createPrimary.inPublic.t.publicArea.parameters.eccDetail.curveID = TPM_ECC_SM2_P256;
    in.createPrimary.inPublic.t.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
    in.createPrimary.inPublic.t.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
#else
    in.createPrimary.inPublic.t.publicArea.type = TPM_ALG_ECC;
    in.createPrimary.inPublic.t.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_ECDSA;
    in.createPrimary.inPublic.t.publicArea.parameters.eccDetail.scheme.details.ecdsa.hashAlg = TPM_ALG_SHA256;
    in.createPrimary.inPublic.t.publicArea.parameters.eccDetail.curveID = TPM_ECC_NIST_P256;
    in.createPrimary.inPublic.t.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
    in.createPrimary.inPublic.t.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
//    in.createPrimary.inPublic.t.publicArea.type = TPM_ALG_RSA;
//    in.createPrimary.inPublic.t.publicArea.parameters.rsaDetail.keyBits = MAX_RSA_KEY_BITS;
//    in.createPrimary.inPublic.t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_RSAPSS;
//    in.createPrimary.inPublic.t.publicArea.parameters.rsaDetail.scheme.details.rsapss.hashAlg = TPM_ALG_SHA256;
//    in.createPrimary.inPublic.t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
#endif
    in.createPrimary.inPublic.t.publicArea.unique.ecc.x.t.size = CryptHashBlock(TPM_ALG_SHA256, strlen(authorityName), (BYTE*)authorityName, sizeof(in.createPrimary.inPublic.t.publicArea.unique.ecc.x.t.buffer), in.createPrimary.inPublic.t.publicArea.unique.ecc.x.t.buffer);
    EXECUTE_TPM_CALL(FALSE, TPM2_CreatePrimary);
    *sigkey = parms.objectTableOut[TPM2_CreatePrimary_HdlOut_ObjectHandle];

Cleanup:
    return result;
}

static uint32_t
TpmUtilCreateCounters(
    void)
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    union
    {
        NV_ReadPublic_In nv_ReadPublic;
        NV_UndefineSpace_In nv_UndefineSpace;
        NV_DefineSpace_In nv_DefineSpace;
    } in;
    union
    {
        NV_ReadPublic_Out nv_ReadPublic;
        NV_UndefineSpace_Out nv_UndefineSpace;
        NV_DefineSpace_Out nv_DefineSpace;
    } out;
    ANY_OBJECT nvIndex = {0};

    for(UINT32 n = 0; n < 2; n++)
    {
        // Next we want to see if there is already a counter and remove it if yes
        INITIALIZE_CALL_BUFFERS(TPM2_NV_ReadPublic, &in.nv_ReadPublic, &out.nv_ReadPublic);
        parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex].nv.handle = TPM_PLATFORM_COUNTERS_NV_INDEX + n;
        TRY_TPM_CALL(FALSE, TPM2_NV_ReadPublic);
        if(result == TPM_RC_SUCCESS)
        {
            nvIndex = parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex];
            INITIALIZE_CALL_BUFFERS(TPM2_NV_UndefineSpace, &in.nv_UndefineSpace, &out.nv_UndefineSpace);
            parms.objectTableIn[TPM2_NV_UndefineSpace_HdlIn_AuthHandle].entity.handle = TPM_RH_PLATFORM;
            parms.objectTableIn[TPM2_NV_UndefineSpace_HdlIn_NvIndex] = nvIndex;
            EXECUTE_TPM_CALL(FALSE, TPM2_NV_UndefineSpace);
        }

        // Now we create a new counter
        INITIALIZE_CALL_BUFFERS(TPM2_NV_DefineSpace, &in.nv_DefineSpace, &out.nv_DefineSpace);
        parms.objectTableIn[TPM2_NV_DefineSpace_HdlIn_AuthHandle].entity.handle = TPM_RH_PLATFORM;
        in.nv_DefineSpace.publicInfo.t.nvPublic.dataSize = sizeof(UINT64);
        in.nv_DefineSpace.publicInfo.t.nvPublic.nameAlg = TPM_ALG_SHA256;
        in.nv_DefineSpace.publicInfo.t.nvPublic.nvIndex = TPM_PLATFORM_COUNTERS_NV_INDEX + n;
        in.nv_DefineSpace.publicInfo.t.nvPublic.attributes.TPMA_NV_AUTHREAD = SET;
        in.nv_DefineSpace.publicInfo.t.nvPublic.attributes.TPMA_NV_OWNERREAD = SET;
        in.nv_DefineSpace.publicInfo.t.nvPublic.attributes.TPMA_NV_PPREAD = SET;
        in.nv_DefineSpace.publicInfo.t.nvPublic.attributes.TPMA_NV_PPWRITE = SET;
        in.nv_DefineSpace.publicInfo.t.nvPublic.attributes.TPMA_NV_NO_DA = SET;
        in.nv_DefineSpace.publicInfo.t.nvPublic.attributes.TPMA_NV_PLATFORMCREATE = SET;
        in.nv_DefineSpace.publicInfo.t.nvPublic.attributes.TPMA_NV_COUNTER = SET;
        EXECUTE_TPM_CALL(FALSE, TPM2_NV_DefineSpace);
    }

Cleanup:
    return result;
}

static uint32_t
TpmUtilSignAppPayload(
    ANY_OBJECT* appPayloadAuthority
    )
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    union
    {
        Hash_In hash;
        Sign_In sign;
        VerifySignature_In verifySignature;
    } in;
    union
    {
        Hash_Out hash;
        Sign_Out sign;
        VerifySignature_Out verifySignature;
    } out;
    TPM2B_DIGEST digest = {0};
    TPMT_TK_HASHCHECK hashCheck = {0};
    TPMT_SIGNATURE signature = {0};
    const UINT64 marker = TPM_APP_AUTHORITY_SECTION;
    uint8_t appPayload[] = {
    0x54, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63, 0x6b, 0x20, 0x62, 0x72, 0x6f, 0x77, 0x6e, 0x20, // The quick brown
    0x66, 0x6f, 0x78, 0x20, 0x6a, 0x75, 0x6d, 0x70, 0x73, 0x20, 0x6f, 0x76, 0x65, 0x72, 0x20, 0x74, // fox jumps over t
    0x68, 0x65, 0x20, 0x6c, 0x61, 0x7a, 0x79, 0x20, 0x64, 0x6f, 0x67                                // he lazy dog
    };

    // Hash the payload in the TPM
    INITIALIZE_CALL_BUFFERS(TPM2_Hash, &in.hash, &out.hash);
    in.hash.data.t.size = sizeof(appPayload);
    MemoryCopy(in.hash.data.t.buffer, appPayload, in.hash.data.t.size, sizeof(in.hash.data.t.buffer));
#ifdef NTZTPM
    in.hash.hashAlg = TPM_ALG_SM3_256;
#else
    in.hash.hashAlg = TPM_ALG_SHA256;
#endif
    in.hash.hierarchy = TPM_RH_NULL;
    EXECUTE_TPM_CALL(FALSE, TPM2_Hash);
    digest = out.hash.outHash;
    hashCheck = out.hash.validation;

    // Sign the digest
    INITIALIZE_CALL_BUFFERS(TPM2_Sign, &in.sign, &out.sign);
    parms.objectTableIn[TPM2_Sign_HdlIn_KeyHandle] = *appPayloadAuthority;
    in.sign.digest = digest;
    in.sign.inScheme.scheme = TPM_ALG_NULL;
    in.sign.validation = hashCheck;
    EXECUTE_TPM_CALL(FALSE, TPM2_Sign);
    signature = out.sign.signature;

    // Verify the signature
    INITIALIZE_CALL_BUFFERS(TPM2_VerifySignature, &in.verifySignature, &out.verifySignature);
    parms.objectTableIn[TPM2_VerifySignature_HdlIn_KeyHandle] = *appPayloadAuthority;
    in.verifySignature.digest = digest;
    in.verifySignature.signature = signature;
    EXECUTE_TPM_CALL(FALSE, TPM2_VerifySignature);

    // Dump the appPayload data
    if(sizeof(pbCmd) < (sizeof(appPayload) + sizeof(UINT64)))
    {
        result = TPM_RC_FAILURE;
        goto Cleanup;
    }
    MemorySet(pbCmd, 0x00, sizeof(pbCmd));
    buffer = pbCmd;
    size = sizeof(pbCmd);
    MemoryCopy(pbCmd, appPayload, sizeof(appPayload), size);
    buffer += sizeof(appPayload);
    size -= sizeof(appPayload);
    MemoryCopy(buffer, &marker, sizeof(TPM_APP_AUTHORITY_SECTION), size);
    buffer += sizeof(UINT64);
    size -= sizeof(UINT64);
    if((TPM2B_PUBLIC_Marshal(&appPayloadAuthority->obj.publicArea, &buffer, &size) < 0) ||
       (TPMT_SIGNATURE_Marshal(&signature, &buffer, &size) < 0))
    {
        result = TPM_RC_FAILURE;
        goto Cleanup;
    }

    // Write the fakeAppPayload to flash
    HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD, ADDR_FLASH_SECTOR_23 + sizeof(persistedData), (uint32_t)(sizeof(pbCmd) - size));
    for(uint32_t n = 0; n < (sizeof(pbCmd) - size); n++)
    {
        if(HAL_FLASH_Program(FLASH_TYPEPROGRAM_BYTE, ADDR_FLASH_SECTOR_23 + sizeof(persistedData) + sizeof(uint32_t) + n, pbCmd[n]) != HAL_OK)
        {
            printf("Flash Write Error @ 0x%08x\r\n", ADDR_FLASH_SECTOR_23 + n);
        }
    }


Cleanup:
    return result;
}

static uint32_t
TpmUtilBuildSamplePolicy(
    ANY_OBJECT* appPayloadAuthority,
    TPM2B_MAX_NV_BUFFER* rawPolicy
    )
{
    UINT32 result = TPM_RC_SUCCESS;
    BYTE* buffer = rawPolicy->t.buffer;
    INT32 size = sizeof(rawPolicy->t.buffer);
    TPML_POLICY_ENTRIES policyDB = {0};

    // fakeAppPayload name for binary policy
#ifndef NTZTPM
    TPM2B_NAME appDigest = {0x0022, {0x00, 0x0b, 0xd7, 0xa8, 0xfb, 0xb3, 0x07, 0xd7, 0x80, 0x94, 0x69, 0xca, 0x9a, 0xbc, 0xb0, 0x08, 0x2e, 0x4f, 0x8d, 0x56, 0x51, 0xe4, 0x6d, 0x3c, 0xdb, 0x76, 0x2d, 0x02, 0xd0, 0xbf, 0x37, 0xc9, 0xe5, 0x92}};
#else
    TPM2B_NAME appDigest = {0x0022, {0x00, 0x12, 0x5f, 0xdf, 0xe8, 0x14, 0xb8, 0x57, 0x3c, 0xa0, 0x21, 0x98, 0x39, 0x70, 0xfc, 0x79, 0xb2, 0x21, 0x8c, 0x95, 0x70, 0x36, 0x9b, 0x48, 0x59, 0x68, 0x4e, 0x2e, 0x4c, 0x3f, 0xc7, 0x6c, 0xb8, 0xea}};
#endif

    policyDB.count = 3;

    // Authority Policy
    policyDB.policies[0].policy.t.info.isAuthorityPolicy = YES;
    policyDB.policies[0].policy.t.info.launchApp = YES;
    policyDB.policies[0].policy.t.action.randomizePlatformAuth = YES;
    policyDB.policies[0].policy.t.action.incrementCounter = 1;
    policyDB.policies[0].entity = appPayloadAuthority->obj.name;

    // Binary Policy
    policyDB.policies[1].policy.t.info.isBinaryPolicy = YES;
    policyDB.policies[1].policy.t.info.launchApp = YES;
    policyDB.policies[1].policy.t.action.resetLockout = YES;
    policyDB.policies[1].policy.t.action.incrementCounter = 1;
    policyDB.policies[1].entity = appDigest;

    // Default Policy
    policyDB.policies[2].policy.t.info.isDefaultPolicy = YES;
    policyDB.policies[2].policy.t.info.haltMcu= YES;
    policyDB.policies[2].policy.t.action.disablePlatformHierarchy = YES;
    policyDB.policies[2].policy.t.action.disablePlatformNV = YES;
    policyDB.policies[2].policy.t.action.disableEndorsementHierarchy = YES;
    policyDB.policies[2].policy.t.action.disableOwnerHierarchy = YES;
    policyDB.policies[2].policy.t.action.incrementCounter = 2;
    rawPolicy->t.size = TPML_POLICY_ENTRIES_Marshal(&policyDB, &buffer, &size);

Cleanup:
    return result;
}

static uint32_t
TpmUtilIssueBootPolicy(
    ANY_OBJECT* platformAuthority,
    TPM2B_MAX_NV_BUFFER* policy,
    TPM2B_NAME* deviceId,
    TPMT_SIGNATURE* authorizationSignature
    )
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    union
    {
        PolicyAuthorize_In policyAuthorize;
        PolicyGetDigest_In policyGetDigest;
        PolicyCpHash_In policyCpHash;
        Sign_In sign;
    } in;
    union
    {
        Sign_Out sign;
    } out;
    TPM2B_NV_PUBLIC nvPublicInfo = {0};
    TPM2B_NAME nvIndexName = {0};
    const TPM_CC commandCode = TPM_CC_NV_Write;
    const UINT16 offset = 0;
    TPM2B_DIGEST cpHash = {0};
    TPM2B_DIGEST approvedPolicy = {0};
    TPM2B_DIGEST authorization = {0};
    HASH_STATE hash = {0};

    // Next we predict the NV storage Name that this policy will be hosted in
    nvPublicInfo.t.nvPublic.dataSize = policy->t.size;
    nvPublicInfo.t.nvPublic.nameAlg = TPM_ALG_SHA256;
    nvPublicInfo.t.nvPublic.nvIndex = TPM_PLATFORM_LOCKDOWN_POLICY_NV_INDEX;
    nvPublicInfo.t.nvPublic.attributes.TPMA_NV_AUTHREAD = SET;
    nvPublicInfo.t.nvPublic.attributes.TPMA_NV_OWNERREAD = SET;
    nvPublicInfo.t.nvPublic.attributes.TPMA_NV_NO_DA = SET;
    nvPublicInfo.t.nvPublic.attributes.TPMA_NV_PLATFORMCREATE = SET;
    nvPublicInfo.t.nvPublic.attributes.TPMA_NV_POLICYWRITE = SET;

    // Calculate the authPolicy for the index
    MemorySet(&in.policyAuthorize, 0x00, sizeof(in.policyAuthorize));
    in.policyAuthorize.approvedPolicy.t.size = SHA256_DIGEST_SIZE;
    in.policyAuthorize.policyRef.t.size = SHA256_DIGEST_SIZE;
    MemoryCopy(in.policyAuthorize.policyRef.t.buffer, &deviceId->t.name[sizeof(UINT16)], in.policyAuthorize.policyRef.t.size, sizeof(in.policyAuthorize.policyRef.t.buffer));
    in.policyAuthorize.keySign = platformAuthority->obj.name;
    in.policyAuthorize.checkTicket.tag = TPM_ST_VERIFIED;
    in.policyAuthorize.checkTicket.hierarchy = TPM_RH_NULL;
    nvPublicInfo.t.nvPublic.authPolicy.t.size = SHA256_DIGEST_SIZE;
    TPM2_PolicyAuthorize_CalculateUpdate(TPM_ALG_SHA256, &nvPublicInfo.t.nvPublic.authPolicy, &in.policyAuthorize);

    // Serialize the public index to get it's name
    buffer = pbCmd;
    size = sizeof(pbCmd);
    if(TPMS_NV_PUBLIC_Marshal(&nvPublicInfo.t.nvPublic, &buffer, &size) < 0)
    {
        result = TPM_RC_FAILURE;
        goto Cleanup;
    }
    UINT16_TO_BYTE_ARRAY(TPM_ALG_SHA256, nvIndexName.t.name);
    nvIndexName.t.size = sizeof(UINT16) + CryptHashBlock(TPM_ALG_SHA256, sizeof(pbCmd) - size, pbCmd, sizeof(nvIndexName.t.name) - sizeof(UINT16), &nvIndexName.t.name[sizeof(UINT16)]);

    // Next we are calculating cpHash for the write command we want to execute later
    cpHash.t.size = CryptStartHash(TPM_ALG_SHA256, &hash);
    CryptUpdateDigestInt(&hash, sizeof(commandCode), (void*)&commandCode);
    CryptUpdateDigest2B(&hash, &nvIndexName.b);
    CryptUpdateDigest2B(&hash, &nvIndexName.b);
    CryptUpdateDigestInt(&hash, sizeof(UINT16), &policy->t.size);
    CryptUpdateDigest2B(&hash, (TPM2B*)policy);
    CryptUpdateDigestInt(&hash, sizeof(UINT16), (void*)&offset);
    CryptCompleteHash2B(&hash, &cpHash.b);

    // We calculate the policy digest of PolicyCpHash(cpHash)
    MemorySet(&in.policyCpHash, 0x00, sizeof(in.policyCpHash));
    approvedPolicy.t.size = SHA256_DIGEST_SIZE;
    in.policyCpHash.cpHashA = cpHash;
    TPM2_PolicyCpHash_CalculateUpdate(TPM_ALG_SHA256, &approvedPolicy, &in.policyCpHash);

    // Calculate the authorization
    authorization.t.size = CryptStartHash(TPM_ALG_SHA256, &hash);
    CryptUpdateDigest2B(&hash, (TPM2B*)&approvedPolicy);
    CryptUpdateDigest(&hash, SHA256_DIGEST_SIZE, &deviceId->t.name[sizeof(UINT16)]);
    CryptCompleteHash2B(&hash, &authorization.b);

    // Sign the authorization
    INITIALIZE_CALL_BUFFERS(TPM2_Sign, &in.sign, &out.sign);
    parms.objectTableIn[TPM2_Sign_HdlIn_KeyHandle] = *platformAuthority;
    in.sign.digest = authorization;
    in.sign.inScheme.scheme = TPM_ALG_NULL; // Use whatever the key demands
    in.sign.validation.tag = TPM_ST_HASHCHECK;
    in.sign.validation.hierarchy = TPM_RH_NULL;
    EXECUTE_TPM_CALL(FALSE, TPM2_Sign);

    *authorizationSignature = out.sign.signature;

Cleanup:
    return result;
}

static uint32_t
TpmUtilWriteBootPolicy(
    TPM2B_MAX_NV_BUFFER* policy,
    TPM2B_PUBLIC* platformAuthority,
    TPMT_SIGNATURE* authorizationSignature
    )
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    union
    {
        LoadExternal_In loadExternal;
        NV_ReadPublic_In nv_ReadPublic;
        NV_UndefineSpace_In nv_UndefineSpace;
        PolicyAuthorize_In policyAuthorize;
        PolicyCpHash_In policyCpHash;
        NV_DefineSpace_In nv_DefineSpace;
        StartAuthSession_In startAuthSession;
        VerifySignature_In verifySignature;
        NV_Write_In nv_Write;
        PolicyGetDigest_In policyGetDigest;
    } in;
    union
    {
        LoadExternal_Out loadExternal;
        NV_ReadPublic_Out nv_ReadPublic;
        NV_UndefineSpace_Out nv_UndefineSpace;
        PolicyAuthorize_Out policyAuthorize;
        PolicyCpHash_Out policyCpHash;
        NV_DefineSpace_Out nv_DefineSpace;
        StartAuthSession_Out startAuthSession;
        VerifySignature_Out verifySignature;
        NV_Write_Out nv_Write;
        PolicyGetDigest_Out policyGetDigest;
    } out;
    ANY_OBJECT platformAuthorityKey = {0};
    ANY_OBJECT nvIndex = {0};
    TPM2B_DIGEST authPolicy = {0};
    TPM2B_DIGEST cpHash = {0};
    TPM2B_DIGEST approvedPolicy = {0};
    TPM2B_DIGEST authorization = {0};
    HASH_STATE hash = {0};
    SESSION policySession = {0};
    TPMT_TK_VERIFIED ticket = {0};
    const TPM_CC commandCode = TPM_CC_NV_Write;
    const UINT16 offset = 0;

    // First we want to see if we have already a policyAuthority installed and
    // if yes if this is the same one
    INITIALIZE_CALL_BUFFERS(TPM2_LoadExternal, &in.loadExternal, &out.loadExternal);
    in.loadExternal.inPublic = *platformAuthority;
    in.loadExternal.hierarchy = TPM_RH_PLATFORM;
    EXECUTE_TPM_CALL(FALSE, TPM2_LoadExternal);
    platformAuthorityKey = parms.objectTableOut[TPM2_LoadExternal_HdlOut_ObjectHandle];
    if((persistedData.platformAuthorityName.t.size != 0) &&
       (!Memory2BEqual((TPM2B*)&persistedData.platformAuthorityName, (TPM2B*)&platformAuthorityKey.obj.name)))
    {
        result = TPM_RC_FAILURE;
        goto Cleanup;
    }

    // Next we want to see if there is already a policy in NV and remove it if yes
    INITIALIZE_CALL_BUFFERS(TPM2_NV_ReadPublic, &in.nv_ReadPublic, &out.nv_ReadPublic);
    parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex].nv.handle = TPM_PLATFORM_LOCKDOWN_POLICY_NV_INDEX;
    TRY_TPM_CALL(FALSE, TPM2_NV_ReadPublic);
    if(result == TPM_RC_SUCCESS)
    {
        // Get the old NV index object
        nvIndex = parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex];

        INITIALIZE_CALL_BUFFERS(TPM2_NV_UndefineSpace, &in.nv_UndefineSpace, &out.nv_UndefineSpace);
        parms.objectTableIn[TPM2_NV_UndefineSpace_HdlIn_AuthHandle].entity.handle = TPM_RH_PLATFORM;
        parms.objectTableIn[TPM2_NV_UndefineSpace_HdlIn_NvIndex] = nvIndex;
        EXECUTE_TPM_CALL(FALSE, TPM2_NV_UndefineSpace);
    }

    // Lets start by building the index policy digest from the policy authority key above
    // Calculate the authPolicy for the index
    MemorySet(&in.policyAuthorize, 0x00, sizeof(in.policyAuthorize));
    in.policyAuthorize.approvedPolicy.t.size = SHA256_DIGEST_SIZE;
    in.policyAuthorize.policyRef.t.size = SHA256_DIGEST_SIZE;
    MemoryCopy(in.policyAuthorize.policyRef.t.buffer, &persistedData.ekName.t.name[sizeof(UINT16)], in.policyAuthorize.policyRef.t.size, sizeof(in.policyAuthorize.policyRef.t.buffer));
    in.policyAuthorize.keySign = platformAuthorityKey.obj.name;
    in.policyAuthorize.checkTicket.tag = TPM_ST_VERIFIED;
    in.policyAuthorize.checkTicket.hierarchy = TPM_RH_NULL;
    authPolicy.t.size = SHA256_DIGEST_SIZE;
    TPM2_PolicyAuthorize_CalculateUpdate(TPM_ALG_SHA256, &authPolicy, &in.policyAuthorize);

    // Now we create the Index in the TPM
    INITIALIZE_CALL_BUFFERS(TPM2_NV_DefineSpace, &in.nv_DefineSpace, &out.nv_DefineSpace);
    parms.objectTableIn[TPM2_NV_DefineSpace_HdlIn_AuthHandle].entity.handle = TPM_RH_PLATFORM;
    in.nv_DefineSpace.publicInfo.t.nvPublic.dataSize = policy->t.size;
    in.nv_DefineSpace.publicInfo.t.nvPublic.nameAlg = TPM_ALG_SHA256;
    in.nv_DefineSpace.publicInfo.t.nvPublic.nvIndex = TPM_PLATFORM_LOCKDOWN_POLICY_NV_INDEX;
    in.nv_DefineSpace.publicInfo.t.nvPublic.attributes.TPMA_NV_AUTHREAD = SET;
    in.nv_DefineSpace.publicInfo.t.nvPublic.attributes.TPMA_NV_OWNERREAD = SET;
    in.nv_DefineSpace.publicInfo.t.nvPublic.attributes.TPMA_NV_NO_DA = SET;
    in.nv_DefineSpace.publicInfo.t.nvPublic.attributes.TPMA_NV_PLATFORMCREATE = SET;
    in.nv_DefineSpace.publicInfo.t.nvPublic.attributes.TPMA_NV_POLICYWRITE = SET;
    in.nv_DefineSpace.publicInfo.t.nvPublic.authPolicy = authPolicy;
    EXECUTE_TPM_CALL(FALSE, TPM2_NV_DefineSpace);

    // Read the name from the new index back
    INITIALIZE_CALL_BUFFERS(TPM2_NV_ReadPublic, &in.nv_ReadPublic, &out.nv_ReadPublic);
    parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex].nv.handle = TPM_PLATFORM_LOCKDOWN_POLICY_NV_INDEX;
    EXECUTE_TPM_CALL(FALSE, TPM2_NV_ReadPublic);
    nvIndex = parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex];  // Careful this name will change after writing

    // Start a policy session in preparation of the initial write
    INITIALIZE_CALL_BUFFERS(TPM2_StartAuthSession, &in.startAuthSession, &out.startAuthSession);
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_TpmKey].obj.handle = TPM_RH_NULL;
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_Bind].obj.handle = TPM_RH_NULL;
    in.startAuthSession.nonceCaller.t.size = CryptGenerateRandom(SHA256_DIGEST_SIZE, in.startAuthSession.nonceCaller.t.buffer);
    in.startAuthSession.sessionType = TPM_SE_POLICY;
    in.startAuthSession.symmetric.algorithm = TPM_ALG_NULL;
    in.startAuthSession.authHash = TPM_ALG_SHA256;
    EXECUTE_TPM_CALL(FALSE, TPM2_StartAuthSession);
    policySession = parms.objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session;

    // Next we are calculating cpHash for the write command that we want to execute later
    cpHash.t.size = CryptStartHash(TPM_ALG_SHA256, &hash);
    CryptUpdateDigestInt(&hash, sizeof(commandCode), (void*)&commandCode);
    CryptUpdateDigest2B(&hash, &nvIndex.nv.name.b);
    CryptUpdateDigest2B(&hash, &nvIndex.nv.name.b);
    CryptUpdateDigestInt(&hash, sizeof(UINT16), &policy->t.size);
    CryptUpdateDigest2B(&hash, (TPM2B*)policy);
    CryptUpdateDigestInt(&hash, sizeof(UINT16), (void*)&offset);
    CryptCompleteHash2B(&hash, &cpHash.b);

    // We execute PolicyCpHash(cpHash) on the policy session to prepare the session for the
    // NV_Write() command. No other command can be executed through this session after that
    INITIALIZE_CALL_BUFFERS(TPM2_PolicyCpHash, &in.policyCpHash, &out.policyCpHash);
    parms.objectTableIn[TPM2_PolicyCpHash_HdlIn_PolicySession].session = policySession;
    in.policyCpHash.cpHashA = cpHash;
    EXECUTE_TPM_CALL(FALSE, TPM2_PolicyCpHash);

    // Now we read back the current policy digest. We are assuming everything is correct.
    // If not things will start to blow up later.
    INITIALIZE_CALL_BUFFERS(TPM2_PolicyGetDigest, &in.policyGetDigest, &out.policyGetDigest);
    parms.objectTableIn[TPM2_PolicyGetDigest_HdlIn_PolicySession].session = policySession;
    EXECUTE_TPM_CALL(FALSE, TPM2_PolicyGetDigest);
    approvedPolicy = out.policyGetDigest.policyDigest;

    // Calculate the authorization with the policy digest. If this authorization does not match
    // what was signed by the platform authority the signature verification is going to fail
    authorization.t.size = CryptStartHash(TPM_ALG_SHA256, &hash);
    CryptUpdateDigest2B(&hash, (TPM2B*)&approvedPolicy);
    CryptUpdateDigest(&hash, SHA256_DIGEST_SIZE, &persistedData.ekName.t.name[sizeof(UINT16)]);
    CryptCompleteHash2B(&hash, &authorization.b);

    // Verify the signature with the authorization - Moment of truth!
    INITIALIZE_CALL_BUFFERS(TPM2_VerifySignature, &in.verifySignature, &out.verifySignature);
    parms.objectTableIn[TPM2_VerifySignature_HdlIn_KeyHandle] = platformAuthorityKey;
    in.verifySignature.digest = authorization;
    in.verifySignature.signature = *authorizationSignature;
    EXECUTE_TPM_CALL(FALSE, TPM2_VerifySignature);
    ticket = out.verifySignature.validation;

    // Now authorize the current write specific policy digest by executing policyAuthorize().
    // If this matches the policy session will have the generic policy digest in it afterwards
    INITIALIZE_CALL_BUFFERS(TPM2_PolicyAuthorize, &in.policyAuthorize, &out.policyAuthorize);
    parms.objectTableIn[TPM2_PolicyCpHash_HdlIn_PolicySession].session = policySession;
    in.policyAuthorize.checkTicket = ticket;
    in.policyAuthorize.keySign = platformAuthorityKey.obj.name;
    in.policyAuthorize.policyRef.t.size = SHA256_DIGEST_SIZE;
    MemoryCopy(in.policyAuthorize.policyRef.t.buffer, &persistedData.ekName.t.name[sizeof(UINT16)], in.policyAuthorize.policyRef.t.size, sizeof(in.policyAuthorize.policyRef.t.buffer));
    in.policyAuthorize.approvedPolicy = approvedPolicy;
    EXECUTE_TPM_CALL(FALSE, TPM2_PolicyAuthorize);

    // The policy session is now primed for the NV_Write() command and nothing else
    // Because the session in the TPM has the cpHash for the pending command, while the
    // policy digest in the session has the generic policy digest that the NV Index requires
    policySession.attributes.continueSession = NO; // Kill the policy session with this command
    sessionTable[0] = policySession;
    INITIALIZE_CALL_BUFFERS(TPM2_NV_Write, &in.nv_Write, &out.nv_Write);
    parms.objectTableIn[TPM2_NV_Write_HdlIn_AuthHandle] = nvIndex;
    parms.objectTableIn[TPM2_NV_Write_HdlIn_NvIndex] = nvIndex;
    in.nv_Write.data = *policy;
    in.nv_Write.offset = 0;
    EXECUTE_TPM_CALL(FALSE, TPM2_NV_Write);

    if(persistedData.platformAuthorityName.t.size == 0)
    {
        // Finally if we wrote a policy make sure that we remember the policy
        // authority in the MCU if it was not set already
        persistedData.platformAuthorityName = platformAuthorityKey.obj.name;
    }

Cleanup:
    if(platformAuthorityKey.obj.handle != 0)
    {
        FlushContext(&platformAuthorityKey);
    }
    return result;
}

static uint32_t
TpmUtilCreateSrk(
    void
    )
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    union
    {
        CreatePrimary_In createPrimaryIn;
        EvictControl_In evictControlIn;
    } in;
    union
    {
        CreatePrimary_Out createPrimaryOut;
        EvictControl_Out evictControlOut;
    } out;
    ANY_OBJECT srk = {0};

    // Create the SRK
    INITIALIZE_CALL_BUFFERS(TPM2_CreatePrimary, &in.createPrimaryIn, &out.createPrimaryOut);
    parms.objectTableIn[TPM2_CreatePrimary_HdlIn_PrimaryHandle].entity.handle = TPM_RH_OWNER;
    SetSrkTemplate(&in.createPrimaryIn.inPublic);
    EXECUTE_TPM_CALL(FALSE, TPM2_CreatePrimary);
    srk = parms.objectTableOut[TPM2_CreatePrimary_HdlOut_ObjectHandle];

    // ...and persist it.
    INITIALIZE_CALL_BUFFERS(TPM2_EvictControl, &in.evictControlIn, &out.evictControlOut);
    parms.objectTableIn[TPM2_EvictControl_HdlIn_Auth].entity.handle = TPM_RH_OWNER;
    parms.objectTableIn[TPM2_EvictControl_HdlIn_ObjectHandle] = srk;
    in.evictControlIn.persistentHandle = TPM_20_SRK_HANDLE;
    EXECUTE_TPM_CALL(FALSE, TPM2_EvictControl);

Cleanup:
    if(srk.obj.handle != 0)
    {
        FlushContext(&srk);
    }
    return result;
}

static uint32_t
TpmUtilCreateEk(
    void
    )
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    union
    {
        CreatePrimary_In createPrimaryIn;
        EvictControl_In evictControlIn;
    } in;
    union
    {
        CreatePrimary_Out createPrimaryOut;
        EvictControl_Out evictControlOut;
    } out;
    ANY_OBJECT ek = {0};

    // Create the EK
    INITIALIZE_CALL_BUFFERS(TPM2_CreatePrimary, &in.createPrimaryIn, &out.createPrimaryOut);
    parms.objectTableIn[TPM2_CreatePrimary_HdlIn_PrimaryHandle].entity.handle = TPM_RH_ENDORSEMENT;
    SetEkTemplate(&in.createPrimaryIn.inPublic);
    EXECUTE_TPM_CALL(FALSE, TPM2_CreatePrimary);
    ek = parms.objectTableOut[TPM2_CreatePrimary_HdlOut_ObjectHandle];

    // ...and persist it in NV.
    INITIALIZE_CALL_BUFFERS(TPM2_EvictControl, &in.evictControlIn, &out.evictControlOut);
    parms.objectTableIn[TPM2_EvictControl_HdlIn_Auth].entity.handle = TPM_RH_OWNER;
    parms.objectTableIn[TPM2_EvictControl_HdlIn_ObjectHandle] = ek;
    in.evictControlIn.persistentHandle = TPM_20_EK_HANDLE;
    EXECUTE_TPM_CALL(FALSE, TPM2_EvictControl);

    persistedData.ekName = ek.obj.name;

Cleanup:
    if(ek.obj.handle != 0)
    {
        FlushContext(&ek);
    }
    return result;
}

uint32_t
TpmUtilClearAndProvision(
    void
    )
{
    uint32_t retVal = 0;
    ANY_OBJECT appPayloadAuthority = {0};
    ANY_OBJECT platformAuthority = {0};
    TPM2B_MAX_NV_BUFFER rawPolicy = {0};
    TPMT_SIGNATURE authorizationSignature = {0};

    if((retVal = TpmClearControl(0x00)) != TPM_RC_SUCCESS)
    {
        printf("TpmClearControl() failed with 0x%03x.\r\n", retVal);
        goto Cleanup;
    }
    printf("TpmClearControl() complete.\r\n");

    if((retVal = TpmClear()) != TPM_RC_SUCCESS)
    {
        printf("TpmClear() failed with 0x%03x.\r\n", retVal);
        goto Cleanup;
    }
    printf("TpmClear() complete.\r\n");

    if((retVal = TpmUtilCreateSrk()) != TPM_RC_SUCCESS)
    {
        printf("TpmUtilCreateSrk() failed with 0x%03x.\r\n", retVal);
        goto Cleanup;
    }
    printf("TpmUtilCreateSrk() complete.\r\n");

    if((retVal = TpmUtilCreateEk()) != TPM_RC_SUCCESS)
    {
        printf("TpmUtilCreateEk() failed with 0x%03x.\r\n", retVal);
        goto Cleanup;
    }
    printf("TpmUtilCreateEk() complete.\r\n");

    if((retVal = TpmUtilCreateCounters()) != TPM_RC_SUCCESS)
    {
        printf("TpmUtilCreateCounters() failed with 0x%03x.\r\n", retVal);
        goto Cleanup;
    }
    printf("TpmUtilCreateCounters() complete.\r\n");

    if((retVal = TpmUtilCreateAuthority("PlatformAuthority", &platformAuthority)) != TPM_RC_SUCCESS)
    {
        printf("TpmUtilCreateAuthority(PlatformAuthority) failed with 0x%03x.\r\n", retVal);
        goto Cleanup;
    }
    printf("TpmUtilCreateAuthority(PlatformAuthority) complete.\r\n");
    persistedData.platformAuthorityName = platformAuthority.obj.name;

    if((retVal = TpmUtilCreateAuthority("AppPayloadAuthority", &appPayloadAuthority)) != TPM_RC_SUCCESS)
    {
        printf("TpmUtilCreateAuthority(AppPayloadAuthority) failed with 0x%03x.\r\n", retVal);
        goto Cleanup;
    }
    printf("TpmUtilCreateAuthority(AppPayloadAuthority) complete.\r\n");

    if((retVal = TpmUtilBuildSamplePolicy(&appPayloadAuthority, &rawPolicy)) != TPM_RC_SUCCESS)
    {
        printf("TpmUtilBuildSamplePolicy() failed with 0x%03x.\r\n", retVal);
        goto Cleanup;
    }
    printf("TpmUtilBuildSamplePolicy() complete.\r\n");

    if((retVal = TpmUtilIssueBootPolicy(&platformAuthority, &rawPolicy, &persistedData.ekName, &authorizationSignature)) != TPM_RC_SUCCESS)
    {
        printf("TpmUtilIssueBootPolicy() failed with 0x%03x.\r\n", retVal);
        goto Cleanup;
    }
    printf("TpmUtilIssueBootPolicy() complete.\r\n");

    if((retVal = TpmUtilWriteBootPolicy(&rawPolicy, &platformAuthority.obj.publicArea, &authorizationSignature)) != TPM_RC_SUCCESS)
    {
        printf("TpmUtilWriteBootPolicy() failed with 0x%03x.\r\n", retVal);
        goto Cleanup;
    }
    printf("TpmUtilWriteBootPolicy() complete.\r\n");

    HAL_FLASH_Unlock();
    FLASH_Erase_Sector(FLASH_SECTOR_23, FLASH_VOLTAGE_RANGE_3);
    persistedData.magic = RAZORCLAMPERSISTEDDATA;
    persistedData.version = RAZORCLAMPERSISTEDVERSION;
    persistedData.size = sizeof(RazorClamPersistentDataType);

    if((retVal = TpmUtilSignAppPayload(&appPayloadAuthority)) != TPM_RC_SUCCESS)
    {
        printf("TpmUtilSignAppPayload() failed with 0x%03x.\r\n", retVal);
        goto Cleanup;
    }
    printf("TpmUtilSignAppPayload() complete.\r\n");

    if((retVal = SetTpmAuthValues()) != TPM_RC_SUCCESS)
    {
        printf("SetTpmAuthValues() failed with 0x%03x.\r\n", retVal);
        goto Cleanup;
    }
    printf("SetTpmAuthValues() complete.\r\n");

    // Persist the data in flash
    for(uint32_t n = 0; n < sizeof(persistedData); n++)
    {
        if(HAL_FLASH_Program(FLASH_TYPEPROGRAM_BYTE, ADDR_FLASH_SECTOR_23 + n, ((uint8_t*)&persistedData)[n]) != HAL_OK)
        {
            printf("Flash Write Error @ 0x%08x\r\n", ADDR_FLASH_SECTOR_23 + n);
        }
    }
    HAL_FLASH_Lock();

#ifdef NTZTPM
    // Best effort: Make the TPM clean house and persist everything that needs
    // to be persisted. There is an issue with the RSA engine on the NatZ TPM that
    // could fail StartAuthSession with an EK encrypted seed when using the
    // persisted EK and this work around seems to mitigate that issue on that TPM.
    TpmShutdown(TPM_SU_CLEAR);
    HAL_Delay(200);
    TpmStartup(TPM_SU_CLEAR);
    TpmSelfTest();
#endif

Cleanup:
    if(platformAuthority.obj.handle != 0)
    {
        FlushContext(&platformAuthority);
    }
    if(appPayloadAuthority.obj.handle != 0)
    {
        FlushContext(&appPayloadAuthority);
    }
    return retVal;
}
