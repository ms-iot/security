/*
 * RazorClam.cpp
 *
 *  Created on: Mar 24, 2016
 *      Author: stefanth
 */
#include "stm32f4xx_hal.h"
#include "TisTpmDrv.h"
#include "UrchinLib.h"
#include "UrchinPlatform.h"
#include "RazorClam.h"

#ifdef WC_RNG
extern WC_RNG wcRng;
#endif

RazorClamVolatileDataType volatileData = { 0 };
RazorClamPersistentDataType persistedData = { 0 };
uint32_t fakeAppPayloadSize = 0;
uint8_t* fakeAppPayload = NULL;

char* pcrPurpose[] =
{
        "Crtm",                // PCR[0]
        "CrtmData",            // PCR[1]
        "AppPayloadCode",      // PCR[2]
        "AppPayloadAuthority", // PCR[3]
        "BootPolicy",          // PCR[4]
        "AppPayloadData",      // PCR[5]
};

static TPM_RC
TPMT_POLICY_ENTRY_Unmarshal(TPMT_POLICY_ENTRY *target, BYTE **buffer, INT32 *size, BOOL flag)
{
    TPM_RC    result;
    result = UINT64_Unmarshal((UINT64 *)&(target->policy.b), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPM2B_NAME_Unmarshal((TPM2B_NAME *)&(target->entity), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

static UINT16
TPMT_POLICY_ENTRY_Marshal(TPMT_POLICY_ENTRY *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + UINT64_Marshal((UINT64 *)&(source->policy.b), buffer, size));
    result = (UINT16)(result + TPM2B_NAME_Marshal((TPM2B_NAME *)&(source->entity), buffer, size));

    return result;
}

static TPM_RC
TPMT_POLICY_ENTRY_Array_Unmarshal(TPMT_POLICY_ENTRY *target, BYTE **buffer, INT32 *size, BOOL flag, INT32 count)
{
    TPM_RC    result;
    INT32 i;
    for(i = 0; i < count; i++) {
        result = TPMT_POLICY_ENTRY_Unmarshal(&target[i], buffer, size, flag);
        if(result != TPM_RC_SUCCESS)
            return result;
    }
    return TPM_RC_SUCCESS;
}

static UINT16
TPMT_POLICY_ENTRY_Array_Marshal(TPMT_POLICY_ENTRY *source, BYTE **buffer, INT32 *size, INT32 count)
{
    UINT16    result = 0;
    INT32 i;
    for(i = 0; i < count; i++) {
        result = (UINT16)(result + TPMT_POLICY_ENTRY_Marshal(&source[i], buffer, size));
    }
    return result;
}

TPM_RC
TPML_POLICY_ENTRIES_Unmarshal(TPML_POLICY_ENTRIES *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = UINT32_Unmarshal((UINT32 *)&(target->count), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPMT_POLICY_ENTRY_Array_Unmarshal((TPMT_POLICY_ENTRY *)(target->policies), buffer, size, FALSE, (INT32)(target->count));
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPML_POLICY_ENTRIES_Marshal(TPML_POLICY_ENTRIES *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + UINT32_Marshal((UINT32 *)&(source->count), buffer, size));
    result = (UINT16)(result + TPMT_POLICY_ENTRY_Array_Marshal((TPMT_POLICY_ENTRY *)(source->policies), buffer, size, (INT32)(source->count)));

    return result;
}

char* GetAlgName(TPM_ALG_ID name)
{
    switch(name)
    {
    case TPM_ALG_RSA:
        return "RSA";
    case TPM_ALG_SHA1:
        return "SHA1";
    case TPM_ALG_HMAC:
        return "HMAC";
    case TPM_ALG_AES:
        return "AES";
    case TPM_ALG_MGF1:
        return "MGF";
    case TPM_ALG_KEYEDHASH:
        return "KEYEDHASH";
    case TPM_ALG_XOR:
        return "XOR";
    case TPM_ALG_SHA256:
        return "SHA256";
    case TPM_ALG_SHA384:
        return "SHA384";
    case TPM_ALG_SHA512:
        return "SHA512";
    case TPM_ALG_NULL:
        return "NULL";
    case TPM_ALG_SM3_256:
        return "SM3";
    case TPM_ALG_SM4:
        return "SM4";
    case TPM_ALG_RSASSA:
        return "RSASSA";
    case TPM_ALG_RSAES:
        return "RSAES";
    case TPM_ALG_RSAPSS:
        return "RSAPSS";
    case TPM_ALG_OAEP:
        return "OAEP";
    case TPM_ALG_ECDSA:
        return "ECDSA";
    case TPM_ALG_ECDH:
        return "ECDH";
    case TPM_ALG_ECDAA:
        return "ECDAA";
    case TPM_ALG_SM2:
        return "SM2";
//    case TPM_ALG_ECSCHNORR:
//        return "ECSCHNORR";
//    case TPM_ALG_ECMQV:
//        return "ECMQV";
    case TPM_ALG_KDF1_SP800_56a:
        return "KDF1_SP800_56a";
//    case TPM_ALG_KDF2:
//        return "KDF2";
    case TPM_ALG_KDF1_SP800_108:
        return "KDF1_SP800_108";
    case TPM_ALG_ECC:
        return "ECC";
    case TPM_ALG_SYMCIPHER:
        return "SYMCIPHER";
    case TPM_ALG_CTR:
        return "CTR";
    case TPM_ALG_OFB:
        return "OFB";
    case TPM_ALG_CBC:
        return "CBC";
    case TPM_ALG_CFB:
        return "CFB";
    case TPM_ALG_ECB:
        return "ECB";
    default:
        return "UNKNOWN";
    }
}

void
PrintBuffer(char* label, uint8_t* dataPtr, uint32_t dataSize)
{
    printf("uint8_t %s[%u] = {\r\n", label, (unsigned int)dataSize);
    for(uint32_t n = 0; n < dataSize; n++)
    {
        if(n > 0)
        {
            if((n % 16) == 0)
            {
                printf(",\r\n");
            }
            else
            {
                printf(", ");
            }
        }
        printf("0x%02x", dataPtr[n]);
    }
    printf("\r\n};\r\n");
}

void
PrintTPM2B(const char* label, const TPM2B* data)
{
    if(label != NULL) printf("%s:\r\n[%u]0x", label, data->size);
    else printf("[%u]0x", data->size);
    for(UINT32 n = 0; n < data->size; n++)
        printf("%02x", data->buffer[n]);
    printf("\r\n");
}

void
PrintTPM2BInitializer(const char* label, const TPM2B* data)
{
    printf("{0x%04x, {", data->size);
    for(UINT32 n = 0; n < data->size; n++)
        printf("%s0x%02x",(n != 0)? ", " : "", data->buffer[n]);
    printf("}} // %s\r\n", label);
}

static void
PrintMeasurement(UINT32 index)
{
    printf("Event(%d) for PCR[%02u] (%s):\r\n", index, (unsigned int)volatileData.measurementLog[index].pcrIndex, pcrPurpose[(unsigned int)volatileData.measurementLog[index].pcrIndex]);
    for(UINT32 n = 0; n < volatileData.measurementLog[index].measurement.count; n++)
    {
        switch(volatileData.measurementLog[index].measurement.digests[n].hashAlg)
        {
        case TPM_ALG_SHA1:
            printf("SHA1: 0x");
            for(UINT32 m = 0; m < sizeof(volatileData.measurementLog[index].measurement.digests[n].digest.sha1); m++)
                printf("%02x", volatileData.measurementLog[index].measurement.digests[n].digest.sha1[m]);
            break;
        case TPM_ALG_SHA256:
            printf("SHA256: 0x");
            for(UINT32 m = 0; m < sizeof(volatileData.measurementLog[index].measurement.digests[n].digest.sha256); m++)
                printf("%02x", volatileData.measurementLog[index].measurement.digests[n].digest.sha256[m]);
            break;
        case TPM_ALG_SHA384:
            printf("SHA384: 0x");
            for(UINT32 m = 0; m < sizeof(volatileData.measurementLog[index].measurement.digests[n].digest.sha384); m++)
                printf("%02x", volatileData.measurementLog[index].measurement.digests[n].digest.sha384[m]);
            break;
        case TPM_ALG_SHA512:
            printf("SHA512: 0x");
            for(UINT32 m = 0; m < sizeof(volatileData.measurementLog[index].measurement.digests[n].digest.sha512); m++)
                printf("%02x", volatileData.measurementLog[index].measurement.digests[n].digest.sha512[m]);
            break;
        case TPM_ALG_SM3_256:
            printf("SM3: 0x");
            for(UINT32 m = 0; m < sizeof(volatileData.measurementLog[index].measurement.digests[n].digest.sm3_256); m++)
                printf("%02x", volatileData.measurementLog[index].measurement.digests[n].digest.sm3_256[m]);
            break;
        }
        printf("\r\n");
    }
}

static int32_t
FindSignatureBlock(uint8_t* appData, uint32_t appSize)
{
    if(appSize > sizeof(uint64_t))
    {
        union
        {
            uint8_t bytes[sizeof(uint64_t)];
            uint64_t uint;
        } marker;
        marker.uint = TPM_APP_AUTHORITY_SECTION;

        for(uint32_t n = 0; n < (appSize - sizeof(uint64_t)); n++)
        {
            if(appData[n] == marker.bytes[0])
            {
                uint64_t appMarker = 0;
                MemoryCopy((void*)&appMarker, &appData[n], sizeof(uint64_t), sizeof(appMarker));
                if(appMarker == marker.uint)
                {
                    return n;
                }
            }
        }
    }
    return -1;
}

UINT32
FlushContext(ANY_OBJECT* tpmObject)
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    union
    {
        FlushContext_In flushContext;
    } in;
    union
    {
        FlushContext_Out flushContext;
    } out;

    // Unload the object
    INITIALIZE_CALL_BUFFERS(TPM2_FlushContext, &in.flushContext, &out.flushContext);
    parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle] = *tpmObject;
    EXECUTE_TPM_CALL(FALSE, TPM2_FlushContext);

    // Copy the updated object back out
    *tpmObject = parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle];

Cleanup:
    return result;
}

static UINT32
VerifyCodeSignature(uint8_t* signatureBlock, uint32_t signatureBlockSize, TPML_DIGEST_VALUES* digests, TPM2B_NAME* payloadKeyName)
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    union
    {
        LoadExternal_In loadExternal;
        VerifySignature_In verifySignature;
    } in;
    union
    {
        LoadExternal_Out loadExternal;
        VerifySignature_Out verifySignature;
    } out;
    TPMI_ALG_HASH hashAlg = TPM_ALG_NULL;
    TPM2B_DIGEST appPayloadDigest = {0};
    TPMT_SIGNATURE appPayloadSignature = {0};
    TPM2B_PUBLIC appPayloadPubKey = {0};
    ANY_OBJECT payloadKey = {0};

    // Un-marshal the key and the signature from the appPayload
    buffer = signatureBlock;
    size = signatureBlockSize;
    if((result = TPM2B_PUBLIC_Unmarshal(&appPayloadPubKey, &buffer, &size, FALSE)) != TPM_RC_SUCCESS)
    {
        goto Cleanup;
    }
    if((result = TPMT_SIGNATURE_Unmarshal(&appPayloadSignature, &buffer, &size, FALSE)) != TPM_RC_SUCCESS)
    {
        goto Cleanup;
    }

    // Get the right digest from the measurement to compare with
    hashAlg = appPayloadSignature.signature.any.hashAlg;
    printf("AppPayload has a %s signature with a %s digest.\r\n", GetAlgName(appPayloadSignature.sigAlg), GetAlgName(hashAlg));

    // Get the matching digest from the measurement
    for(uint32_t n = 0; n < digests->count; n++)
    {
        if(digests->digests[n].hashAlg == hashAlg)
        {
            switch(hashAlg)
            {
            case TPM_ALG_SHA1:
                appPayloadDigest.t.size = SHA1_DIGEST_SIZE;
                MemoryCopy(appPayloadDigest.t.buffer, digests->digests[n].digest.sha1, appPayloadDigest.t.size, sizeof(appPayloadDigest.t.buffer));
                break;
            case TPM_ALG_SHA256:
                appPayloadDigest.t.size = SHA256_DIGEST_SIZE;
                MemoryCopy(appPayloadDigest.t.buffer, digests->digests[n].digest.sha256, appPayloadDigest.t.size, sizeof(appPayloadDigest.t.buffer));
                break;
            case TPM_ALG_SHA384:
                appPayloadDigest.t.size = SHA384_DIGEST_SIZE;
                MemoryCopy(appPayloadDigest.t.buffer, digests->digests[n].digest.sha384, appPayloadDigest.t.size, sizeof(appPayloadDigest.t.buffer));
                break;
            case TPM_ALG_SHA512:
                appPayloadDigest.t.size = SHA512_DIGEST_SIZE;
                MemoryCopy(appPayloadDigest.t.buffer, digests->digests[n].digest.sha512, appPayloadDigest.t.size, sizeof(appPayloadDigest.t.buffer));
                break;
            case TPM_ALG_SM3_256:
                appPayloadDigest.t.size = SM3_256_DIGEST_SIZE;
                MemoryCopy(appPayloadDigest.t.buffer, digests->digests[n].digest.sm3_256, appPayloadDigest.t.size, sizeof(appPayloadDigest.t.buffer));
                break;
            default:
                result = TPM_RC_FAILURE;
                goto Cleanup;
            }
        }
    }
    // Make sure we found a matching digest in the measurements
    if(appPayloadDigest.t.size == 0)
    {
        result = TPM_RC_FAILURE;
        goto Cleanup;
    }

    // Load the public payload key into the TPM
    sessionTable[0] = volatileData.ekSeededSession;
    sessionTable[0].attributes.audit = SET;
    INITIALIZE_CALL_BUFFERS(TPM2_LoadExternal, &in.loadExternal, &out.loadExternal);
    sessionCnt += 1; // Add the EK session for auditing to make sure we are loading the right key
    in.loadExternal.inPublic = appPayloadPubKey;
    in.loadExternal.hierarchy = TPM_RH_OWNER;
    EXECUTE_TPM_CALL(FALSE, TPM2_LoadExternal);
    sessionTable[0].attributes = volatileData.ekSeededSession.attributes;
    volatileData.ekSeededSession = sessionTable[0];
    payloadKey = parms.objectTableOut[TPM2_LoadExternal_HdlOut_ObjectHandle];

    // Verify the payload signature
    sessionTable[0] = volatileData.ekSeededSession;
    sessionTable[0].attributes.audit = SET;
    INITIALIZE_CALL_BUFFERS(TPM2_VerifySignature, &in.verifySignature, &out.verifySignature);
    sessionCnt += 1; // Add the EK session for auditing to make sure we are loading the right key
    parms.objectTableIn[TPM2_VerifySignature_HdlIn_KeyHandle] = payloadKey;
    in.verifySignature.digest = appPayloadDigest;
    in.verifySignature.signature = appPayloadSignature;
    EXECUTE_TPM_CALL(FALSE, TPM2_VerifySignature);
    sessionTable[0].attributes = volatileData.ekSeededSession.attributes;
    volatileData.ekSeededSession = sessionTable[0];

    // When everything checks out return the payload key name
    *payloadKeyName = payloadKey.obj.name;

Cleanup:
    if(payloadKey.obj.handle != 0)
    {
        FlushContext(&payloadKey);
    }
    return result;
}

static UINT32
FilterBootPolicy(
    TPM2B_MAX_NV_BUFFER* rawPolicy,
    TPM2B_NAME* payloadAuthorityName,
    TPMU_POLICY_FLAGS* policy
    )
{
    UINT32 result = TPM_RC_SUCCESS;
    BYTE* buffer = rawPolicy->t.buffer;
    INT32 size = rawPolicy->t.size;
    TPML_POLICY_ENTRIES policyTable = {0};
    TPMU_POLICY_FLAGS defaultPolicy = {0};
    TPMU_POLICY_FLAGS matchPolicy = {0};

    if((result = TPML_POLICY_ENTRIES_Unmarshal(&policyTable, &buffer, &size)) != TPM_RC_SUCCESS)
    {
        goto Cleanup;
    }

    for(UINT32 n = 0; n < policyTable.count; n++)
    {
        // Make note of the default policy when we see it
        if(policyTable.policies[n].policy.t.info.isDefaultPolicy)
        {
            if((defaultPolicy.b == 0L) && (policyTable.policies[n].entity.t.size == 0))
            {
                defaultPolicy = policyTable.policies[n].policy;
            }
            else
            {
                // More than one default policy or a default policy with an entity is fishy
                result = TPM_RC_FAILURE;
                goto Cleanup;
            }
        }
        if(Memory2BEqual((TPM2B*)&policyTable.policies[n].entity, (TPM2B*)payloadAuthorityName) != FALSE)
        {
            // We found a specific policy for the entity
            matchPolicy = policyTable.policies[n].policy;
            break;
        }
    }

    if((matchPolicy.t.info.isAuthorityPolicy == YES) || (matchPolicy.t.info.isBinaryPolicy == YES))
    {
        *policy = matchPolicy;
    }
    else if(defaultPolicy.t.info.isDefaultPolicy == YES)
    {
        *policy = defaultPolicy;
    }
    else
    {
        // No policy found
        result = TPM_RC_FAILURE;
        goto Cleanup;
    }

Cleanup:
    return result;
}

static UINT32
ObtainRawPolicy(
    TPM2B_MAX_NV_BUFFER* rawPolicy
    )
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    union
    {
        NV_ReadPublic_In nv_ReadPublic;
        PolicyAuthorize_In policyAuthorize;
        NV_Read_In nv_Read;
    } in;
    union
    {
        NV_ReadPublic_Out nv_ReadPublic;
        NV_Read_Out nv_Read;
    } out;
    ANY_OBJECT nvIndex = {0};

    // First read the NV name - this is untrusted
    INITIALIZE_CALL_BUFFERS(TPM2_NV_ReadPublic, &in.nv_ReadPublic, &out.nv_ReadPublic);
    parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex].nv.handle = TPM_PLATFORM_LOCKDOWN_POLICY_NV_INDEX;
    EXECUTE_TPM_CALL(FALSE, TPM2_NV_ReadPublic);
    nvIndex = parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex];

    // Read again with the name and auditing to make sure we are getting the real public
    // NV info so we can verify it if we can trust it
    sessionTable[0] = volatileData.ekSeededSession;
    sessionTable[0].attributes.audit = SET;
    INITIALIZE_CALL_BUFFERS(TPM2_NV_ReadPublic, &in.nv_ReadPublic, &out.nv_ReadPublic);
    sessionCnt += 1; // Add the EK session for auditing to make sure we are loading the right key
    parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex] = nvIndex;
    EXECUTE_TPM_CALL(FALSE, TPM2_NV_ReadPublic);
    sessionTable[0].attributes = volatileData.ekSeededSession.attributes;
    volatileData.ekSeededSession = sessionTable[0];
    nvIndex = parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex];

    // Make sure the security relevant attributes are set the way we expect them to
    // Basically only PolicyWrite is supposed to be allowed.
    if((nvIndex.nv.nvPublic.t.nvPublic.nameAlg != TPM_ALG_SHA256) ||
       (nvIndex.nv.nvPublic.t.nvPublic.nvIndex != TPM_PLATFORM_LOCKDOWN_POLICY_NV_INDEX) ||
       (nvIndex.nv.nvPublic.t.nvPublic.attributes.TPMA_NV_POLICYWRITE != 1) ||
       (nvIndex.nv.nvPublic.t.nvPublic.attributes.TPMA_NV_AUTHWRITE == 1) ||
       (nvIndex.nv.nvPublic.t.nvPublic.attributes.TPMA_NV_OWNERWRITE == 1) ||
       (nvIndex.nv.nvPublic.t.nvPublic.attributes.TPMA_NV_PPWRITE == 1) ||
       (nvIndex.nv.nvPublic.t.nvPublic.attributes.TPMA_NV_PLATFORMCREATE != 1))
    {
        result = TPM_RC_FAILURE;
        goto Cleanup;
    }

    // Next we verify that the authPolicy points to the platform authority we remember in the MCU
    // persisted configuration. Because anybody will be able to delete and re-create the index
    // with platformAuth, but since we require the index to be exclusively be written by the
    // platform authority nobody will be able to write a policy to the index but it.
    // So let's calculate the expected auth policy for the index if set and compare it
    if(persistedData.platformAuthorityName.t.size != 0)
    {
        TPM2B_DIGEST authPolicy = {0};
        MemorySet(&in.policyAuthorize, 0x00, sizeof(in.policyAuthorize));
        in.policyAuthorize.approvedPolicy.t.size = SHA256_DIGEST_SIZE;
        in.policyAuthorize.policyRef.t.size = SHA256_DIGEST_SIZE;
        MemoryCopy(in.policyAuthorize.policyRef.t.buffer, &persistedData.ekName.t.name[sizeof(UINT16)], in.policyAuthorize.policyRef.t.size, sizeof(in.policyAuthorize.policyRef.t.buffer));
        in.policyAuthorize.keySign = persistedData.platformAuthorityName;
        in.policyAuthorize.checkTicket.tag = TPM_ST_VERIFIED;
        in.policyAuthorize.checkTicket.hierarchy = TPM_RH_NULL;
        authPolicy.t.size = SHA256_DIGEST_SIZE;
        TPM2_PolicyAuthorize_CalculateUpdate(TPM_ALG_SHA256, &authPolicy, &in.policyAuthorize);
        if(!Memory2BEqual((TPM2B*)&authPolicy, (TPM2B*)&nvIndex.nv.nvPublic.t.nvPublic.authPolicy))
        {
            result = TPM_RC_FAILURE;
            goto Cleanup;
        }
    }

    // Now read the actual raw policy from the TPM
    sessionTable[0] = volatileData.ekSeededSession;
    INITIALIZE_CALL_BUFFERS(TPM2_NV_Read, &in.nv_Read, &out.nv_Read);
    parms.objectTableIn[TPM2_NV_Read_HdlIn_AuthHandle] = nvIndex;
    parms.objectTableIn[TPM2_NV_Read_HdlIn_NvIndex] = nvIndex;
    in.nv_Read.size = nvIndex.nv.nvPublic.t.nvPublic.dataSize;
    in.nv_Read.offset = 0;
    EXECUTE_TPM_CALL(FALSE, TPM2_NV_Read);
    volatileData.ekSeededSession = sessionTable[0];

    *rawPolicy = out.nv_Read.data;

Cleanup:
    return result;
}

static UINT32
ReadEkObjectUntrusted(
    void
    )
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    union
    {
        ReadPublic_In readPublic;
    } in;
    union
    {
        ReadPublic_Out readPublic;
    } out;
    TPM2B_PUBLIC publicArea = {0};
    TPM2B_DIGEST name = {0};

    // Read the EK public - This data is untrusted until we verify this against the EKName stored in the MCU
    INITIALIZE_CALL_BUFFERS(TPM2_ReadPublic, &in.readPublic, &out.readPublic);
    parms.objectTableIn[TPM2_ReadPublic_HdlIn_PublicKey].generic.handle = TPM_20_EK_HANDLE;
    EXECUTE_TPM_CALL(FALSE, TPM2_ReadPublic);
    volatileData.ekObject = parms.objectTableIn[0];

    // Make sure the key properties are correct
    SetEkTemplate(&publicArea);
    if((!Memory2BEqual((TPM2B*)&publicArea.t.publicArea.authPolicy, (TPM2B*)&volatileData.ekObject.obj.publicArea.t.publicArea.authPolicy)) ||
       (publicArea.t.publicArea.nameAlg != volatileData.ekObject.obj.publicArea.t.publicArea.nameAlg) ||
       (*((UINT32*)&publicArea.t.publicArea.objectAttributes) != *((UINT32*)&volatileData.ekObject.obj.publicArea.t.publicArea.objectAttributes)) ||
       (publicArea.t.publicArea.parameters.rsaDetail.exponent != volatileData.ekObject.obj.publicArea.t.publicArea.parameters.rsaDetail.exponent) ||
       (publicArea.t.publicArea.parameters.rsaDetail.keyBits != volatileData.ekObject.obj.publicArea.t.publicArea.parameters.rsaDetail.keyBits) ||
       (publicArea.t.publicArea.parameters.rsaDetail.scheme.scheme != volatileData.ekObject.obj.publicArea.t.publicArea.parameters.rsaDetail.scheme.scheme) ||
       (publicArea.t.publicArea.parameters.rsaDetail.symmetric.algorithm != volatileData.ekObject.obj.publicArea.t.publicArea.parameters.rsaDetail.symmetric.algorithm) ||
       (publicArea.t.publicArea.parameters.rsaDetail.symmetric.keyBits.aes != volatileData.ekObject.obj.publicArea.t.publicArea.parameters.rsaDetail.symmetric.keyBits.aes) ||
       (publicArea.t.publicArea.parameters.rsaDetail.symmetric.mode.aes != volatileData.ekObject.obj.publicArea.t.publicArea.parameters.rsaDetail.symmetric.mode.aes) ||
       (publicArea.t.publicArea.unique.rsa.t.size != volatileData.ekObject.obj.publicArea.t.publicArea.unique.rsa.t.size) ||
       (publicArea.t.publicArea.type != volatileData.ekObject.obj.publicArea.t.publicArea.type))
    {
        result = TPM_RC_FAILURE;
        goto Cleanup;
    }

    // Make sure the EKName the TPM sent matches the public portion of the key
    buffer = pbCmd;
    size = sizeof(pbCmd);
    UINT16_TO_BYTE_ARRAY(volatileData.ekObject.obj.publicArea.t.publicArea.nameAlg, name.t.buffer);
    name.t.size = sizeof(TPM_ALG_ID);
    if((cbCmd = TPMT_PUBLIC_Marshal(&volatileData.ekObject.obj.publicArea.t.publicArea, &buffer, &size)) <= 0)
    {
        result = TPM_RC_FAILURE;
        goto Cleanup;
    }
    name.t.size += CryptHashBlock(volatileData.ekObject.obj.publicArea.t.publicArea.nameAlg, cbCmd, pbCmd, sizeof(name.t.buffer) - name.t.size, &name.t.buffer[name.t.size]);
    if(Memory2BEqual((TPM2B*)&name, (TPM2B*)&volatileData.ekObject.obj.name) == FALSE)
    {
        result = TPM_RC_FAILURE;
        goto Cleanup;
    }

Cleanup:
    return result;
}

static UINT32
StartEkSeededSession(
        void
        )
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    union
    {
        StartAuthSession_In startAuthSession;
    } in;
    union
    {
        StartAuthSession_Out startAuthSession;
    } out;

    // Start EK salted session
    INITIALIZE_CALL_BUFFERS(TPM2_StartAuthSession, &in.startAuthSession, &out.startAuthSession);
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_TpmKey] = volatileData.ekObject;  // Encrypt salt to EK
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_Bind].obj.handle = TPM_RH_NULL;
    in.startAuthSession.nonceCaller.t.size = CryptGenerateRandom(SHA256_DIGEST_SIZE, in.startAuthSession.nonceCaller.t.buffer);
    in.startAuthSession.sessionType = TPM_SE_HMAC;
    in.startAuthSession.symmetric.algorithm = TPM_ALG_AES;
    in.startAuthSession.symmetric.keyBits.aes = 128;
    in.startAuthSession.symmetric.mode.aes = TPM_ALG_CFB;
    in.startAuthSession.authHash = TPM_ALG_SHA256;
#ifndef NTZTPM
    EXECUTE_TPM_CALL(FALSE, TPM2_StartAuthSession);
#else
    TRY_TPM_CALL(FALSE, TPM2_StartAuthSession);

    // The NatZ TPM has a quirk where the persisted EK fails to decrypt the seed
    // sometimes. A reliable workaround is to re-create the EK as transient object
    // and use that to protect the seed. Hopefully this will be fixed in future
    // versions of the NatZ TPm firmware
    if(result == (RC_FMT1 | TPM_RC_P | TPM_RC_2 | TPM_RC_VALUE)) // 0x00002c4
    {
        TPM2B_DATA salt = in.startAuthSession.salt; // We persist the encrypted salt to save time
        TPM2B_ENCRYPTED_SECRET encSalt = in.startAuthSession.encryptedSalt;
        CreatePrimary_In createPrimaryIn;
        CreatePrimary_Out createPrimaryOut;
        ANY_OBJECT ek = {0};
        SESSION hmacSession = {0};

        // Start an HMAC session so we can protect the endorsementAuth from exposure
        // since we don't have the salted session up yet.
        INITIALIZE_CALL_BUFFERS(TPM2_StartAuthSession, &in.startAuthSession, &out.startAuthSession);
        parms.objectTableIn[TPM2_StartAuthSession_HdlIn_TpmKey].obj.handle = TPM_RH_NULL;
        parms.objectTableIn[TPM2_StartAuthSession_HdlIn_Bind].obj.handle = TPM_RH_NULL;
        in.startAuthSession.nonceCaller.t.size = CryptGenerateRandom(SHA256_DIGEST_SIZE, in.startAuthSession.nonceCaller.t.buffer);
        in.startAuthSession.sessionType = TPM_SE_HMAC;
        in.startAuthSession.symmetric.algorithm = TPM_ALG_NULL;
        in.startAuthSession.authHash = TPM_ALG_SHA256;
        EXECUTE_TPM_CALL(FALSE, TPM2_StartAuthSession);
        hmacSession = parms.objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session;
        hmacSession.attributes.continueSession = NO; // Schedule the session to terminate with the next call

        // Re-create the EK as a new object with a transient handle. This key will
        // be absolutely identical to the persisted one
        sessionTable[0] = hmacSession;
        INITIALIZE_CALL_BUFFERS(TPM2_CreatePrimary, &createPrimaryIn, &createPrimaryOut);
        parms.objectTableIn[TPM2_CreatePrimary_HdlIn_PrimaryHandle].entity.handle = TPM_RH_ENDORSEMENT;
        parms.objectTableIn[TPM2_CreatePrimary_HdlIn_PrimaryHandle].entity.authValue = persistedData.endorsementAuth;
        UINT32_TO_BYTE_ARRAY(TPM_RH_ENDORSEMENT, parms.objectTableIn[TPM2_CreatePrimary_HdlIn_PrimaryHandle].entity.name.t.name);
        parms.objectTableIn[TPM2_CreatePrimary_HdlIn_PrimaryHandle].entity.name.t.size = sizeof(TPM_RH_ENDORSEMENT);
        SetEkTemplate(&createPrimaryIn.inPublic);
        EXECUTE_TPM_CALL(FALSE, TPM2_CreatePrimary);
        ek = parms.objectTableOut[TPM2_CreatePrimary_HdlOut_ObjectHandle];

        // Make sure that the key that we just created matches the persisted EK
        if(Memory2BEqual((TPM2B*)&ek.obj.name, (TPM2B*)&volatileData.ekObject.obj.name) == FALSE)
        {
            FlushContext(&ek);
            result = TPM_RC_FAILURE;
            goto Cleanup;
        }

        // Attempt to start the AuthSession with the transient EK now
        INITIALIZE_CALL_BUFFERS(TPM2_StartAuthSession, &in.startAuthSession, &out.startAuthSession);
        parms.objectTableIn[TPM2_StartAuthSession_HdlIn_TpmKey] = ek;  // Encrypt salt to the identical transient EK
        parms.objectTableIn[TPM2_StartAuthSession_HdlIn_Bind].obj.handle = TPM_RH_NULL;
        in.startAuthSession.nonceCaller.t.size = CryptGenerateRandom(SHA256_DIGEST_SIZE, in.startAuthSession.nonceCaller.t.buffer);
        in.startAuthSession.sessionType = TPM_SE_HMAC;
        in.startAuthSession.symmetric.algorithm = TPM_ALG_AES;
        in.startAuthSession.symmetric.keyBits.aes = 128;
        in.startAuthSession.symmetric.mode.aes = TPM_ALG_CFB;
        in.startAuthSession.authHash = TPM_ALG_SHA256;
        in.startAuthSession.salt = salt; // We use the already encrypted salt from the first attempt
        in.startAuthSession.encryptedSalt = encSalt;
        TRY_TPM_CALL(FALSE, TPM2_StartAuthSession);

        // Flush the transient EK again
        FlushContext(&ek);

        if(result != TPM_RC_SUCCESS)
        {
            goto Cleanup;
        }
    }
#endif

    // Copy the session out
    volatileData.ekSeededSession = parms.objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session;

Cleanup:
    return result;
}

static UINT32
CreateAuthorities()
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    union
    {
        GetCapability_In getCapability;
        HierarchyChangeAuth_In hierarchyChangeAuth;
    } in;
    union
    {
        GetCapability_Out getCapability;
        HierarchyChangeAuth_Out hierarchyChangeAuth;
    } out;
    TPMA_PERMANENT permanent;

    INITIALIZE_CALL_BUFFERS(TPM2_GetCapability, &in.getCapability, &out.getCapability);
    in.getCapability.capability = TPM_CAP_TPM_PROPERTIES;
    in.getCapability.property = TPM_PT_PERMANENT;
    in.getCapability.propertyCount = 1;
    EXECUTE_TPM_CALL(FALSE, TPM2_GetCapability);
    if((out.getCapability.capabilityData.capability != TPM_CAP_TPM_PROPERTIES) ||
       (out.getCapability.capabilityData.data.tpmProperties.count != 1) ||
       (out.getCapability.capabilityData.data.tpmProperties.tpmProperty[0].property != TPM_PT_PERMANENT))
    {
        result = TPM_RC_FAILURE;
        goto Cleanup;
    }
    permanent = *((TPMA_PERMANENT*)&out.getCapability.capabilityData.data.tpmProperties.tpmProperty[0].value);

// ToDo: Retrieve the authValues from EEPROM

    volatileData.lockoutObject.entity.handle = TPM_RH_LOCKOUT;
    UINT32_TO_BYTE_ARRAY(volatileData.lockoutObject.entity.handle, volatileData.lockoutObject.entity.name.t.name);
    volatileData.lockoutObject.entity.name.t.size = sizeof(volatileData.lockoutObject.entity.handle);
//    buffer = volatileData.lockoutObject.entity.name.t.name;
//    size = sizeof(volatileData.lockoutObject.entity.name.t.name);
//    volatileData.lockoutObject.entity.name.t.size = TPM_HANDLE_Marshal(&volatileData.lockoutObject.entity.handle, &buffer, &size);
    if(permanent.lockoutAuthSet == CLEAR)
    {
        // ToDo: Generate random Auth and persist in EEPROM
        //UINT8 authSeed[] = "Lockout";
        //persistedData.lockoutAuth.t.size = _cpri__HashBlock(TPM_ALG_SHA256, sizeof(authSeed), authSeed, sizeof(persistedData.lockoutAuth.t.buffer), persistedData.lockoutAuth.t.buffer);

        sessionTable[0] = volatileData.ekSeededSession;
        sessionTable[0].attributes.decrypt = SET;
        INITIALIZE_CALL_BUFFERS(TPM2_HierarchyChangeAuth, &in.hierarchyChangeAuth, &out.hierarchyChangeAuth);
        parms.objectTableIn[TPM2_HierarchyChangeAuth_HdlIn_AuthHandle] = volatileData.lockoutObject;
        in.hierarchyChangeAuth.newAuth = persistedData.lockoutAuth;
        EXECUTE_TPM_CALL(FALSE, TPM2_HierarchyChangeAuth);
        sessionTable[0].attributes = volatileData.ekSeededSession.attributes;
        volatileData.ekSeededSession = sessionTable[0];
        volatileData.lockoutObject = parms.objectTableIn[TPM2_HierarchyChangeAuth_HdlIn_AuthHandle];
    }
    else
    {
        volatileData.lockoutObject.entity.authValue = persistedData.lockoutAuth;
    }

    volatileData.endorsementObject.entity.handle = TPM_RH_ENDORSEMENT;
    UINT32_TO_BYTE_ARRAY(volatileData.endorsementObject.entity.handle, volatileData.endorsementObject.entity.name.t.name);
    volatileData.endorsementObject.entity.name.t.size = sizeof(volatileData.endorsementObject.entity.handle);
//    buffer = volatileData.endorsementObject.entity.name.t.name;
//    size = sizeof(volatileData.endorsementObject.entity.name.t.name);
//    volatileData.endorsementObject.entity.name.t.size = TPM_HANDLE_Marshal(&volatileData.endorsementObject.entity.handle, &buffer, &size);
    if(permanent.endorsementAuthSet == CLEAR)
    {
        // ToDo: Generate random Auth and persist in EEPROM
        //UINT8 authSeed[] = "Endorsement";
        //persistedData.endorsementAuth.t.size = _cpri__HashBlock(TPM_ALG_SHA256, sizeof(authSeed), authSeed, sizeof(persistedData.endorsementAuth.t.buffer), persistedData.endorsementAuth.t.buffer);

        sessionTable[0] = volatileData.ekSeededSession;
        sessionTable[0].attributes.decrypt = SET;
        INITIALIZE_CALL_BUFFERS(TPM2_HierarchyChangeAuth, &in.hierarchyChangeAuth, &out.hierarchyChangeAuth);
        parms.objectTableIn[TPM2_HierarchyChangeAuth_HdlIn_AuthHandle] = volatileData.endorsementObject;
        in.hierarchyChangeAuth.newAuth = persistedData.endorsementAuth;
        EXECUTE_TPM_CALL(FALSE, TPM2_HierarchyChangeAuth);
        sessionTable[0].attributes = volatileData.ekSeededSession.attributes;
        volatileData.ekSeededSession = sessionTable[0];
        volatileData.endorsementObject = parms.objectTableIn[TPM2_HierarchyChangeAuth_HdlIn_AuthHandle];
    }
    else
    {
        volatileData.endorsementObject.entity.authValue = persistedData.endorsementAuth;
    }

    volatileData.storageOwnerObject.entity.handle = TPM_RH_OWNER;
    UINT32_TO_BYTE_ARRAY(volatileData.storageOwnerObject.entity.handle, volatileData.storageOwnerObject.entity.name.t.name);
    volatileData.storageOwnerObject.entity.name.t.size = sizeof(volatileData.storageOwnerObject.entity.handle);
//    buffer = volatileData.storageOwnerObject.entity.name.t.name;
//    size = sizeof(volatileData.storageOwnerObject.entity.name.t.name);
//    volatileData.storageOwnerObject.entity.name.t.size = TPM_HANDLE_Marshal(&volatileData.storageOwnerObject.entity.handle, &buffer, &size);
    if(permanent.ownerAuthSet == CLEAR)
    {
        // ToDo: Generate random Auth and persist in EEPROM
        //UINT8 authSeed[] = "Storage";
        //persistedData.storageAuth.t.size = _cpri__HashBlock(TPM_ALG_SHA256, sizeof(authSeed), authSeed, sizeof(persistedData.storageAuth.t.buffer), persistedData.storageAuth.t.buffer);

        sessionTable[0] = volatileData.ekSeededSession;
        sessionTable[0].attributes.decrypt = SET;
        INITIALIZE_CALL_BUFFERS(TPM2_HierarchyChangeAuth, &in.hierarchyChangeAuth, &out.hierarchyChangeAuth);
        parms.objectTableIn[TPM2_HierarchyChangeAuth_HdlIn_AuthHandle] = volatileData.storageOwnerObject;
        in.hierarchyChangeAuth.newAuth = persistedData.storageAuth;
        EXECUTE_TPM_CALL(FALSE, TPM2_HierarchyChangeAuth);
        sessionTable[0].attributes = volatileData.ekSeededSession.attributes;
        volatileData.ekSeededSession = sessionTable[0];
        volatileData.storageOwnerObject = parms.objectTableIn[TPM2_HierarchyChangeAuth_HdlIn_AuthHandle];
    }
    else
    {
        volatileData.storageOwnerObject.entity.authValue = persistedData.storageAuth;
    }

    // Keeping this auth NULL for now
    volatileData.platformObject.entity.handle = TPM_RH_PLATFORM;
    UINT32_TO_BYTE_ARRAY(volatileData.platformObject.entity.handle, volatileData.platformObject.entity.name.t.name);
    volatileData.platformObject.entity.name.t.size = sizeof(volatileData.platformObject.entity.handle);
//    buffer = volatileData.platformObject.entity.name.t.name;
//    size = sizeof(volatileData.platformObject.entity.name.t.name);
//    volatileData.platformObject.entity.name.t.size = TPM_HANDLE_Marshal(&volatileData.platformObject.entity.handle, &buffer, &size);

Cleanup:
    if(result != TPM_RC_SUCCESS)
    {
        // Copy the EKSeeded session back out in case of an error
        sessionTable[0].attributes = volatileData.ekSeededSession.attributes;
        volatileData.ekSeededSession = sessionTable[0];
    }
    return TPM_RC_SUCCESS;
}

static UINT32
ReadSrkObject(
        void
        )
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    union
    {
        ReadPublic_In readPublic;
    } in;
    union
    {
        ReadPublic_Out readPublic;
    } out;
    TPM2B_PUBLIC publicArea = {0};
    TPM2B_NAME qualifiedName = {0};

    // First we read the SRK public without auditing, because we need to know
    // the SRK name for that. An attacker may feed us a bad SRK name now so we
    // will not really trust what we read now until we have confirmed it later
    // again with the EK seeded audit session.
    INITIALIZE_CALL_BUFFERS(TPM2_ReadPublic, &in.readPublic, &out.readPublic);
    parms.objectTableIn[TPM2_ReadPublic_HdlIn_PublicKey].generic.handle = TPM_20_SRK_HANDLE;
    EXECUTE_TPM_CALL(FALSE, TPM2_ReadPublic);

    // This is not confirmed yet
    volatileData.srkObject = parms.objectTableIn[0];

    // Make sure the key properties are correct
    SetSrkTemplate(&publicArea);
    if((!Memory2BEqual((TPM2B*)&publicArea.t.publicArea.authPolicy, (TPM2B*)&volatileData.srkObject.obj.publicArea.t.publicArea.authPolicy)) ||
       (publicArea.t.publicArea.nameAlg != volatileData.srkObject.obj.publicArea.t.publicArea.nameAlg) ||
       (*((UINT32*)&publicArea.t.publicArea.objectAttributes) != *((UINT32*)&volatileData.srkObject.obj.publicArea.t.publicArea.objectAttributes)) ||
       (publicArea.t.publicArea.parameters.rsaDetail.exponent != volatileData.srkObject.obj.publicArea.t.publicArea.parameters.rsaDetail.exponent) ||
       (publicArea.t.publicArea.parameters.rsaDetail.keyBits != volatileData.srkObject.obj.publicArea.t.publicArea.parameters.rsaDetail.keyBits) ||
       (publicArea.t.publicArea.parameters.rsaDetail.scheme.scheme != volatileData.srkObject.obj.publicArea.t.publicArea.parameters.rsaDetail.scheme.scheme) ||
       (publicArea.t.publicArea.parameters.rsaDetail.symmetric.algorithm != volatileData.srkObject.obj.publicArea.t.publicArea.parameters.rsaDetail.symmetric.algorithm) ||
       (publicArea.t.publicArea.parameters.rsaDetail.symmetric.keyBits.aes != volatileData.srkObject.obj.publicArea.t.publicArea.parameters.rsaDetail.symmetric.keyBits.aes) ||
       (publicArea.t.publicArea.parameters.rsaDetail.symmetric.mode.aes != volatileData.srkObject.obj.publicArea.t.publicArea.parameters.rsaDetail.symmetric.mode.aes) ||
       (publicArea.t.publicArea.unique.rsa.t.size != volatileData.srkObject.obj.publicArea.t.publicArea.unique.rsa.t.size) ||
       (publicArea.t.publicArea.type != volatileData.srkObject.obj.publicArea.t.publicArea.type))
    {
        result = TPM_RC_FAILURE;
        goto Cleanup;
    }

    // Check the qualified name to make sure this is a primary key in the storage hierarchy
    qualifiedName.t.size = EntityGetQualifiedName(volatileData.srkObject.obj.publicArea.t.publicArea.nameAlg, &volatileData.storageOwnerObject, &volatileData.srkObject, &qualifiedName);
    if(!Memory2BEqual((const TPM2B*)&qualifiedName, (const TPM2B*)&out.readPublic.qualifiedName))
    {
        result = TPM_RC_FAILURE;
        goto Cleanup;
    }

    // Read the SRK public again, but now with the EK seeded session for auditing
    // because we have the name the TPM claims to have SRK name. If this was a
    // lie it will blow up now.
    sessionTable[0] = volatileData.ekSeededSession;
    sessionTable[0].attributes.audit = SET;
    INITIALIZE_CALL_BUFFERS(TPM2_ReadPublic, &in.readPublic, &out.readPublic);
    sessionCnt += 1; // Add the EK session for auditing
    parms.objectTableIn[TPM2_ReadPublic_HdlIn_PublicKey] = volatileData.srkObject;
    EXECUTE_TPM_CALL(FALSE, TPM2_ReadPublic);
    sessionTable[0].attributes = volatileData.ekSeededSession.attributes;
    volatileData.ekSeededSession = sessionTable[0];

    // We have now successfully read the SRK and can trust it as much as we
    // trust the EK
    volatileData.srkObject = parms.objectTableIn[0];

Cleanup:
    if(result != TPM_RC_SUCCESS)
    {
        // Copy the EKSeeded session back out in case of an error
        sessionTable[0].attributes = volatileData.ekSeededSession.attributes;
        volatileData.ekSeededSession = sessionTable[0];
    }
    return result;
}

static UINT32
ReSeedRng(
    void
    )
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    union
    {
        GetRandom_In getRandom;
    } in;
    union
    {
        GetRandom_Out getRandom;
    } out;

    // Read some entropy from the TPM in a way that we are sure that it really
    // came from the TPM and nobody is feeding us stale random numbers
    sessionTable[0] = volatileData.ekSeededSession;
    sessionTable[0].attributes.audit = SET;
    INITIALIZE_CALL_BUFFERS(TPM2_GetRandom, &in.getRandom, &out.getRandom);
    sessionCnt += 1; // Add the EK session for auditing
    in.getRandom.bytesRequested = SHA256_DIGEST_SIZE;
    EXECUTE_TPM_CALL(FALSE, TPM2_GetRandom);
    sessionTable[0].attributes = volatileData.ekSeededSession.attributes;
    volatileData.ekSeededSession = sessionTable[0];

    // Re-seed the internal RNG with the entropy
    PrintTPM2B("rngReSeed", (TPM2B*)&out.getRandom.randomBytes);
    CryptStirRandom(out.getRandom.randomBytes.t.size, out.getRandom.randomBytes.t.buffer);

Cleanup:
    if(result != TPM_RC_SUCCESS)
    {
        // Copy the EKSeeded session back out in case of an error
        sessionTable[0].attributes = volatileData.ekSeededSession.attributes;
        volatileData.ekSeededSession = sessionTable[0];
    }
    return result;
}

static UINT32
LoadAik(
        void
        )
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    union
    {
        CreatePrimary_In createPrimary;
        ContextSave_In contextSave;
        ContextLoad_In contextLoad;
    } in;
    union
    {
        CreatePrimary_Out createPrimary;
        ContextSave_Out contextSave;
        ContextLoad_Out contextLoad;
    } out;

    if(volatileData.hmacAikObject.obj.name.t.size == 0)
    {
        // Key was not created yet. Create it securely
        sessionTable[0] = volatileData.ekSeededSession;
        INITIALIZE_CALL_BUFFERS(TPM2_CreatePrimary, &in.createPrimary, &out.createPrimary);
        parms.objectTableIn[TPM2_CreatePrimary_HdlIn_PrimaryHandle] = volatileData.endorsementObject;
        in.createPrimary.inPublic.t.publicArea.type = TPM_ALG_KEYEDHASH;
        in.createPrimary.inPublic.t.publicArea.nameAlg = TPM_ALG_SHA256;
        in.createPrimary.inPublic.t.publicArea.objectAttributes.fixedTPM = SET;
        in.createPrimary.inPublic.t.publicArea.objectAttributes.fixedParent = SET;
        in.createPrimary.inPublic.t.publicArea.objectAttributes.sensitiveDataOrigin = SET;
        in.createPrimary.inPublic.t.publicArea.objectAttributes.userWithAuth = SET;
        in.createPrimary.inPublic.t.publicArea.objectAttributes.noDA = SET;
        in.createPrimary.inPublic.t.publicArea.objectAttributes.restricted = SET;
        in.createPrimary.inPublic.t.publicArea.objectAttributes.sign = SET;
        in.createPrimary.inPublic.t.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_HMAC;
        in.createPrimary.inPublic.t.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = TPM_ALG_SHA256;
        EXECUTE_TPM_CALL(FALSE, TPM2_CreatePrimary);
        volatileData.ekSeededSession = sessionTable[0];
        volatileData.hmacAikObject = parms.objectTableOut[TPM2_CreatePrimary_HdlOut_ObjectHandle];

        // Create a backup copy of that object
        INITIALIZE_CALL_BUFFERS(TPM2_ContextSave, &in.contextSave, &out.contextSave);
        parms.objectTableIn[TPM2_ContextSave_HdlIn_SaveHandle] = volatileData.hmacAikObject;
        EXECUTE_TPM_CALL(FALSE, TPM2_ContextSave);
        volatileData.hmacAikBlob = out.contextSave.context;
    }
    else
    {
        INITIALIZE_CALL_BUFFERS(TPM2_ContextLoad, &in.contextLoad, &out.contextLoad);
        in.contextLoad.context = volatileData.hmacAikBlob;
        EXECUTE_TPM_CALL(FALSE, TPM2_ContextLoad);
        volatileData.hmacAikObject.obj.handle = parms.objectTableOut[TPM2_ContextLoad_HdlOut_LoadedHandle].obj.handle;
    }

Cleanup:
    if(result != TPM_RC_SUCCESS)
    {
        // Copy the EKSeeded session back out in case of an error
        volatileData.ekSeededSession = sessionTable[0];
    }
    return result;
}

static UINT32
CheckTickSyncronized(
        void
        )
{
    UINT32 result = TPM_RC_SUCCESS;
#ifndef IFXTPM
    DEFINE_CALL_BUFFERS;
    UINT32 mcuTick = 0;
    union
    {
        GetTime_In getTime;
    } in;
    union
    {
        GetTime_Out getTime;
    } out;

    // Load the AIK
    if((result = LoadAik()) != TPM_RC_SUCCESS)
    {
        goto Cleanup;
    }

    // Get the time
    sessionTable[0] = volatileData.ekSeededSession;
    INITIALIZE_CALL_BUFFERS(TPM2_GetTime, &in.getTime, &out.getTime);
    parms.objectTableIn[TPM2_GetTime_HdlIn_PrivacyAdminHandle] = volatileData.endorsementObject;
    parms.objectTableIn[TPM2_GetTime_HdlIn_SignHandle] = volatileData.hmacAikObject;
    in.getTime.inScheme.scheme = TPM_ALG_HMAC;
    in.getTime.inScheme.details.hmac.hashAlg = TPM_ALG_SHA256;
    EXECUTE_TPM_CALL(FALSE, TPM2_GetTime);
    mcuTick = HAL_GetTick();
    volatileData.ekSeededSession = sessionTable[0];

    // Jettison it again
    if((result = FlushContext(&volatileData.hmacAikObject)) != TPM_RC_SUCCESS)
    {
        goto Cleanup;
    }

    if(volatileData.tickOffest != 0)
    {
        // Check if we are still in the same boot session
        if((volatileData.resetCount != out.getTime.timeInfo.t.attestationData.clockInfo.resetCount) ||
           (volatileData.restartCount != out.getTime.timeInfo.t.attestationData.clockInfo.restartCount))
        {
            result = TPM_RC_FAILURE;
            goto Cleanup;
        }

        // Make sure the tick count remains within +-1s of each other
        if((((INT64)out.getTime.timeInfo.t.attestationData.clockInfo.clock - mcuTick) < (volatileData.tickOffest - 1000)) ||
           (((INT64)out.getTime.timeInfo.t.attestationData.clockInfo.clock - mcuTick) > (volatileData.tickOffest + 1000)))
        {
            result = TPM_RC_FAILURE;
            goto Cleanup;
        }
        volatileData.tickDrift = volatileData.tickOffest - (out.getTime.timeInfo.t.attestationData.clockInfo.clock - mcuTick);
    }

    // Record the offset to avoid slow drift.
    volatileData.tickOffest = out.getTime.timeInfo.t.attestationData.clockInfo.clock - mcuTick;
    volatileData.resetCount = out.getTime.timeInfo.t.attestationData.clockInfo.resetCount;
    volatileData.restartCount = out.getTime.timeInfo.t.attestationData.clockInfo.restartCount;

Cleanup:
    if(result != TPM_RC_SUCCESS)
    {
        // Copy the EKSeeded session back out in case of an error
        volatileData.ekSeededSession = sessionTable[0];
    }
#else
    printf("CheckTickSyncronized: TPM_CC_GetTime() is not implemented on TPM.\r\n");
#endif
    return result;
}

static UINT32
MeasureEvent(
    UINT32 pcrIndex,
    UINT32 dataSize,
    BYTE* dataPtr
    )
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    ANY_OBJECT pcr = {0};
    union
    {
        PCR_Event_In pcrEvent;
        HashSequenceStart_In hashSequenceStart;
        SequenceUpdate_In sequenceUpdate;
        EventSequenceComplete_In eventSequenceComplete;
    } in;
    union
    {
        PCR_Event_Out pcrEvent;
        HashSequenceStart_Out hashSequenceStart;
        SequenceUpdate_Out sequenceUpdate;
        EventSequenceComplete_Out eventSequenceComplete;
    } out;

    // Create the PCR object
    pcr.generic.handle = TPM_HT_PCR + pcrIndex;
    buffer = pcr.generic.name.t.name;
    size = sizeof(pcr.generic.name.t.name);
    pcr.generic.name.t.size = TPM_HANDLE_Marshal(&pcr.generic.handle, &buffer, &size);

    if(dataSize <= 1024)
    {
        // If the Event data is equal or less than 1024 we can do the operation in one shot
        sessionTable[0] = volatileData.ekSeededSession;
        INITIALIZE_CALL_BUFFERS(TPM2_PCR_Event, &in.pcrEvent, &out.pcrEvent);
        parms.objectTableIn[TPM2_PCR_Event_HdlIn_PcrHandle] = pcr;
        in.pcrEvent.eventData.t.size = (UINT16)dataSize;
        MemoryCopy(in.pcrEvent.eventData.t.buffer, dataPtr, dataSize, sizeof(in.pcrEvent.eventData.t.buffer));
        EXECUTE_TPM_CALL(FALSE, TPM2_PCR_Event);
        volatileData.ekSeededSession = sessionTable[0];
        volatileData.measurementLog[volatileData.measurementIndex].pcrIndex = pcr.generic.handle;
        volatileData.measurementLog[volatileData.measurementIndex++].measurement = out.pcrEvent.digests;
    }
    else
    {
        ANY_OBJECT hashObject = {0};
        UINT32 index = 0;

        // Make up a random hashAuth so nobody can hash data we don't want to hash
        hashObject.obj.authValue.t.size = CryptGenerateRandom(SHA256_DIGEST_SIZE, hashObject.obj.authValue.t.buffer);

        // Start the hash sequence and pass in an encrypted hashAuth
        sessionTable[0] = volatileData.ekSeededSession;
        sessionTable[0].attributes.decrypt = SET;
        INITIALIZE_CALL_BUFFERS(TPM2_HashSequenceStart, &in.hashSequenceStart, &out.hashSequenceStart);
        sessionCnt += 1;
        in.hashSequenceStart.auth = hashObject.obj.authValue;
        in.hashSequenceStart.hashAlg = TPM_ALG_NULL;
        EXECUTE_TPM_CALL(FALSE, TPM2_HashSequenceStart);
        sessionTable[0].attributes = volatileData.ekSeededSession.attributes;
        volatileData.ekSeededSession = sessionTable[0];
        hashObject.obj.handle = parms.objectTableOut[TPM2_HashSequenceStart_HdlOut_SequenceHandle].obj.handle;
        // Note: The name of a sequenceObject is according to the spec the empty buffer, so we don't have
        // to set a name up in that object.

        // Iterate through the buffer
        while(dataSize > (index + MAX_DIGEST_BUFFER))
        {
            sessionTable[0] = volatileData.ekSeededSession;
            INITIALIZE_CALL_BUFFERS(TPM2_SequenceUpdate, &in.sequenceUpdate, &out.sequenceUpdate);
            parms.objectTableIn[TPM2_SequenceUpdate_HdlIn_SequenceHandle] = hashObject;
            in.sequenceUpdate.buffer.t.size = MAX_DIGEST_BUFFER;
            MemoryCopy(in.sequenceUpdate.buffer.t.buffer, &dataPtr[index], in.sequenceUpdate.buffer.t.size, sizeof(in.sequenceUpdate.buffer.t.buffer));
            EXECUTE_TPM_CALL(FALSE, TPM2_SequenceUpdate);
            volatileData.ekSeededSession = sessionTable[0];
            index += in.sequenceUpdate.buffer.t.size;
        }

        // Finalize with the last bytes
        sessionTable[TPM2_EventSequenceComplete_HdlIn_PcrHandle].handle = TPM_RS_PW;
        sessionTable[TPM2_EventSequenceComplete_HdlIn_SequenceHandle] = volatileData.ekSeededSession;
        INITIALIZE_CALL_BUFFERS(TPM2_EventSequenceComplete, &in.eventSequenceComplete, &out.eventSequenceComplete);
        parms.objectTableIn[TPM2_EventSequenceComplete_HdlIn_PcrHandle] = pcr;
        parms.objectTableIn[TPM2_EventSequenceComplete_HdlIn_SequenceHandle] = hashObject;
        in.eventSequenceComplete.buffer.t.size = (UINT16)(dataSize - index);
        MemoryCopy(in.eventSequenceComplete.buffer.t.buffer, &dataPtr[index], in.eventSequenceComplete.buffer.t.size, sizeof(in.eventSequenceComplete.buffer.t.buffer));
        EXECUTE_TPM_CALL(FALSE, TPM2_EventSequenceComplete);
        volatileData.ekSeededSession = sessionTable[1];
        index += dataSize - index;
        volatileData.measurementLog[volatileData.measurementIndex].pcrIndex = pcr.generic.handle;
        volatileData.measurementLog[volatileData.measurementIndex++].measurement = out.eventSequenceComplete.results;
    }

Cleanup:
    return result;
}

static UINT32
DumpTPMInfo()
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    union
    {
        GetCapability_In getCapability;
    } in;
    union
    {
        GetCapability_Out getCapability;
    } out;
    char manufacturer[5] = "NONE";
    UINT32 revision = 0;
    UINT32 version = 0;

    INITIALIZE_CALL_BUFFERS(TPM2_GetCapability, &in.getCapability, &out.getCapability);
    in.getCapability.capability = TPM_CAP_TPM_PROPERTIES;
    in.getCapability.property = TPM_PT_MANUFACTURER;
    in.getCapability.propertyCount = 1;
    EXECUTE_TPM_CALL(FALSE, TPM2_GetCapability);
    if(out.getCapability.capabilityData.data.tpmProperties.tpmProperty[0].property == TPM_PT_MANUFACTURER)
    {
        UINT32_TO_BYTE_ARRAY(out.getCapability.capabilityData.data.tpmProperties.tpmProperty[0].value, manufacturer);
    }

    INITIALIZE_CALL_BUFFERS(TPM2_GetCapability, &in.getCapability, &out.getCapability);
    in.getCapability.capability = TPM_CAP_TPM_PROPERTIES;
    in.getCapability.property = TPM_PT_FIRMWARE_VERSION_1;
    in.getCapability.propertyCount = 1;
    EXECUTE_TPM_CALL(FALSE, TPM2_GetCapability);
    if(out.getCapability.capabilityData.data.tpmProperties.tpmProperty[0].property == TPM_PT_FIRMWARE_VERSION_1)
    {
        version = out.getCapability.capabilityData.data.tpmProperties.tpmProperty[0].value;
    }

    INITIALIZE_CALL_BUFFERS(TPM2_GetCapability, &in.getCapability, &out.getCapability);
    in.getCapability.capability = TPM_CAP_TPM_PROPERTIES;
    in.getCapability.property = TPM_PT_REVISION;
    in.getCapability.propertyCount = 1;
    EXECUTE_TPM_CALL(FALSE, TPM2_GetCapability);
    if(out.getCapability.capabilityData.data.tpmProperties.tpmProperty[0].property == TPM_PT_REVISION)
    {
        revision = out.getCapability.capabilityData.data.tpmProperties.tpmProperty[0].value;
    }

    printf("TPM Rev %u.%u %s (FW%u.%u)\r\n", (revision/100), (revision%100), manufacturer, ((version & 0xffff0000) >> 16), (version & 0x0000ffff));

Cleanup:
    return result;
}

static UINT32
EnforceBootPolicy(
    TPMU_POLICY_FLAGS* bootPolicy
    )
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    union
    {
        NV_ReadPublic_In nv_ReadPublic;
        NV_Increment_In nv_Increment;
        NV_Read_In nv_Read;
        HierarchyChangeAuth_In hierarchyChangeAuth;
        DictionaryAttackLockReset_In dictionaryAttackLockReset;
        HierarchyControl_In hierarchyControl;
        ClearControl_In clearControl;
        Clear_In clear;
    } in;
    union
    {
        NV_ReadPublic_Out nv_ReadPublic;
        NV_Increment_Out nv_Increment;
        NV_Read_Out nv_Read;
        HierarchyChangeAuth_Out hierarchyChangeAuth;
        DictionaryAttackLockReset_Out dictionaryAttackLockReset;
        HierarchyControl_Out hierarchyControl;
        ClearControl_Out clearControl;
        Clear_Out clear;
    } out;

    if(bootPolicy->t.action.incrementCounter > 0)
    {
        for(UINT32 n = 0; n < 2; n++)
        {
            if((bootPolicy->t.action.incrementCounter >> n) != 0)
            {
                ANY_OBJECT nvIndex = {0};
                UINT64 count = 0;

                // First read the NV name - this is untrusted
                INITIALIZE_CALL_BUFFERS(TPM2_NV_ReadPublic, &in.nv_ReadPublic, &out.nv_ReadPublic);
                parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex].nv.handle = TPM_PLATFORM_COUNTERS_NV_INDEX + n;
                EXECUTE_TPM_CALL(FALSE, TPM2_NV_ReadPublic);
                nvIndex = parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex];

                // Read again with the name and auditing to make sure we are getting the real public
                // NV info so we can verify it if we can trust it
                sessionTable[0] = volatileData.ekSeededSession;
                sessionTable[0].attributes.audit = SET;
                INITIALIZE_CALL_BUFFERS(TPM2_NV_ReadPublic, &in.nv_ReadPublic, &out.nv_ReadPublic);
                sessionCnt += 1; // Add the EK session for auditing to make sure we are loading the right key
                parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex] = nvIndex;
                EXECUTE_TPM_CALL(FALSE, TPM2_NV_ReadPublic);
                sessionTable[0].attributes = volatileData.ekSeededSession.attributes;
                volatileData.ekSeededSession = sessionTable[0];
                nvIndex = parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex];

                sessionTable[0] = volatileData.ekSeededSession;
                INITIALIZE_CALL_BUFFERS(TPM2_NV_Increment, &in.nv_Increment, &out.nv_Increment);
                parms.objectTableIn[TPM2_NV_Increment_HdlIn_AuthHandle] = volatileData.platformObject;
                parms.objectTableIn[TPM2_NV_Increment_HdlIn_NvIndex] = nvIndex;
                EXECUTE_TPM_CALL(FALSE, TPM2_NV_Increment);
                volatileData.ekSeededSession = sessionTable[0];

                sessionTable[0] = volatileData.ekSeededSession;
                INITIALIZE_CALL_BUFFERS(TPM2_NV_Read, &in.nv_Read, &out.nv_Read);
                parms.objectTableIn[TPM2_NV_Read_HdlIn_AuthHandle] = volatileData.platformObject;
                parms.objectTableIn[TPM2_NV_Read_HdlIn_NvIndex] = nvIndex;
                in.nv_Read.size = nvIndex.nv.nvPublic.t.nvPublic.dataSize;
                in.nv_Read.offset = 0;
                EXECUTE_TPM_CALL(FALSE, TPM2_NV_Read);
                volatileData.ekSeededSession = sessionTable[0];

                count = BYTE_ARRAY_TO_UINT64(out.nv_Read.data.t.buffer);
                printf("Policy applied: incrementCounter(%u) = %u\r\n", n, (unsigned int)count);
            }
        }
    }
    if(bootPolicy->t.action.resetLockout == YES)
    {
        sessionTable[0] = volatileData.ekSeededSession;
        INITIALIZE_CALL_BUFFERS(TPM2_DictionaryAttackLockReset, &in.dictionaryAttackLockReset, &out.dictionaryAttackLockReset);
        parms.objectTableIn[TPM2_DictionaryAttackLockReset_HdlIn_LockHandle] = volatileData.lockoutObject;
        EXECUTE_TPM_CALL(FALSE, TPM2_DictionaryAttackLockReset);
        volatileData.ekSeededSession = sessionTable[0];
        printf("Policy applied: resetLockout\r\n");
    }
    if(bootPolicy->t.action.disableOwnerHierarchy == YES)
    {
        sessionTable[0] = volatileData.ekSeededSession;
        INITIALIZE_CALL_BUFFERS(TPM2_HierarchyControl, &in.hierarchyControl, &out.hierarchyControl);
        parms.objectTableIn[TPM2_HierarchyControl_HdlIn_AuthHandle] = volatileData.platformObject;
        in.hierarchyControl.hierarchy = TPM_RH_OWNER;
        in.hierarchyControl.state = NO;
        EXECUTE_TPM_CALL(FALSE, TPM2_HierarchyControl);
        volatileData.ekSeededSession = sessionTable[0];
        printf("Policy applied: disableOwnerHierarchy\r\n");
    }
    if(bootPolicy->t.action.disableEndorsementHierarchy == YES)
    {
        sessionTable[0] = volatileData.ekSeededSession;
        INITIALIZE_CALL_BUFFERS(TPM2_HierarchyControl, &in.hierarchyControl, &out.hierarchyControl);
        parms.objectTableIn[TPM2_HierarchyControl_HdlIn_AuthHandle] = volatileData.platformObject;
        in.hierarchyControl.hierarchy = TPM_RH_ENDORSEMENT;
        in.hierarchyControl.state = NO;
        EXECUTE_TPM_CALL(FALSE, TPM2_HierarchyControl);
        volatileData.ekSeededSession = sessionTable[0];
        printf("Policy applied: disableEndorsementHierarchy\r\n");
    }
    if(bootPolicy->t.action.disablePlatformNV == YES)
    {
        sessionTable[0] = volatileData.ekSeededSession;
        INITIALIZE_CALL_BUFFERS(TPM2_HierarchyControl, &in.hierarchyControl, &out.hierarchyControl);
        parms.objectTableIn[TPM2_HierarchyControl_HdlIn_AuthHandle] = volatileData.platformObject;
        in.hierarchyControl.hierarchy = TPM_RH_PLATFORM_NV;
        in.hierarchyControl.state = NO;
        EXECUTE_TPM_CALL(FALSE, TPM2_HierarchyControl);
        volatileData.ekSeededSession = sessionTable[0];
        printf("Policy applied: disablePlatformNV\r\n");
    }
    if(bootPolicy->t.action.disablePlatformHierarchy == YES)
    {
        sessionTable[0] = volatileData.ekSeededSession;
        INITIALIZE_CALL_BUFFERS(TPM2_HierarchyControl, &in.hierarchyControl, &out.hierarchyControl);
        parms.objectTableIn[TPM2_HierarchyControl_HdlIn_AuthHandle] = volatileData.platformObject;
        in.hierarchyControl.hierarchy = TPM_RH_PLATFORM;
        in.hierarchyControl.state = NO;
        EXECUTE_TPM_CALL(FALSE, TPM2_HierarchyControl);
        volatileData.ekSeededSession = sessionTable[0];
        printf("Policy applied: disablePlatformHierarchy\r\n");
    }
    if(bootPolicy->t.action.wipeLockoutAuth == YES)
    {
        // Wipe the Auth from the persisted storage so it is lost forever until we take ownership again and everything is lost
        MemorySet(&persistedData.lockoutAuth, 0x00, sizeof(persistedData.lockoutAuth));
        MemorySet(&volatileData.lockoutObject, 0x00, sizeof(volatileData.lockoutObject));
        printf("Policy applied: wipeLockoutAuth\r\n");
    }
    if(bootPolicy->t.action.wipeEndorsementAuth == YES)
    {
        // Wipe the Auth from the persisted storage so it is lost forever until we take ownership again and everything is lost
        MemorySet(&persistedData.endorsementAuth, 0x00, sizeof(persistedData.endorsementAuth));
        MemorySet(&volatileData.endorsementObject, 0x00, sizeof(volatileData.endorsementObject));
        printf("Policy applied: wipeEndorsementAuth\r\n");
    }
    if(bootPolicy->t.action.wipeOwnerAuth == YES)
    {
        // Wipe the Auth from the persisted storage so it is lost forever until we take ownership again and everything is lost
        MemorySet(&persistedData.storageAuth, 0x00, sizeof(persistedData.storageAuth));
        MemorySet(&volatileData.storageOwnerObject, 0x00, sizeof(volatileData.storageOwnerObject));
        printf("Policy applied: wipeOwnerAuth\r\n");
    }
    if(bootPolicy->t.action.randomizePlatformAuth == YES)
    {
        sessionTable[0] = volatileData.ekSeededSession;
        sessionTable[0].attributes.decrypt = SET;
        INITIALIZE_CALL_BUFFERS(TPM2_HierarchyChangeAuth, &in.hierarchyChangeAuth, &out.hierarchyChangeAuth);
        parms.objectTableIn[TPM2_HierarchyChangeAuth_HdlIn_AuthHandle] = volatileData.platformObject;
        in.hierarchyChangeAuth.newAuth.t.size = CryptGenerateRandom(SHA256_DIGEST_SIZE, in.hierarchyChangeAuth.newAuth.t.buffer);
        EXECUTE_TPM_CALL(FALSE, TPM2_HierarchyChangeAuth);
        sessionTable[0].attributes = volatileData.ekSeededSession.attributes;
        volatileData.ekSeededSession = sessionTable[0];
        MemorySet(&volatileData.platformAuth, 0x00, sizeof(volatileData.platformAuth));
        MemorySet(&volatileData.platformObject, 0x00, sizeof(volatileData.platformObject));
        printf("Policy applied: randomizePlatformAuth\r\n");
    }
    if(bootPolicy->t.action.platformClearTpm == YES)
    {
        sessionTable[0] = volatileData.ekSeededSession;
        INITIALIZE_CALL_BUFFERS(TPM2_ClearControl, &in.clearControl, &out.clearControl);
        parms.objectTableIn[TPM2_ClearControl_HdlIn_Auth] = volatileData.platformObject;
        in.clearControl.disable = NO;
        EXECUTE_TPM_CALL(FALSE, TPM2_ClearControl);
        volatileData.ekSeededSession = sessionTable[0];

        sessionTable[0] = volatileData.ekSeededSession;
        INITIALIZE_CALL_BUFFERS(TPM2_Clear, &in.clear, &out.clear);
        parms.objectTableIn[TPM2_Clear_HdlIn_AuthHandle] = volatileData.platformObject;
        EXECUTE_TPM_CALL(FALSE, TPM2_Clear);
        volatileData.ekSeededSession = sessionTable[0];
        printf("Policy applied: platformClearTpm\r\n");
    }
    if(bootPolicy->t.info.haltMcu == YES)
    {
        printf("Policy applied: haltMcu\r\n");
        for(;;);
    }
    if(bootPolicy->t.info.rebootMcu == YES)
    {
        printf("Policy applied: rebootMcu\r\n");
        NVIC_SystemReset();
    }
Cleanup:
    return result;
}

uint32_t
RazorClam(
    void
)
{
    uint32_t retVal = 0;
    uint32_t startT = 0;
    uint32_t razorClamStartT = HAL_GetTick();
    const char* crtmString = "RazorClam-V0.02";
    int32_t appPayloadSigntureBlock = -1;
    TPMU_POLICY_FLAGS bootPolicy = {0};
    BYTE extendBuf[sizeof(UINT32)] = {0};
    TPM2B_MAX_NV_BUFFER rawPolicy = {0};

    printf("==== %s ==========================================================\r\n", crtmString);

    DumpTPMInfo();

    // Get the EK object from the TPM, if necessary create and persist it
    // What this call returns is untrusted at this point
    startT = HAL_GetTick();
    if((retVal = ReadEkObjectUntrusted()) != TPM_RC_SUCCESS)
    {
        TpmFail("ReadEkObjectUntrusted", __LINE__, retVal);
    }
    PrintTPM2B("EKName", (const TPM2B*)&volatileData.ekObject.obj.name);
    printf("EK public and name read from TPM - UNTRUSTED!(%ums)\r\n", (unsigned int)(HAL_GetTick() - startT));

    if(!Memory2BEqual((const TPM2B*)&persistedData.ekName, (const TPM2B*)&volatileData.ekObject.obj.name))
    {
        TpmFail("Memory2BEqual", __LINE__, retVal);
    }
    printf("EK name matches with the MCU stored EK name.\r\n");

    // Start the EK seeded session so we make sure nobody can pull the TPM from underneath us without us noticing
    startT = HAL_GetTick();
    if((retVal = StartEkSeededSession()) != TPM_RC_SUCCESS)
    {
        TpmFail("StartEkSeededSession", __LINE__, retVal);
    }
    printf("EK seeded session started. The EK is now TRUSTED!(%ums)\r\n", (unsigned int)(HAL_GetTick() - startT));

    startT = HAL_GetTick();
    if((retVal = ReSeedRng()) != TPM_RC_SUCCESS)
    {
        TpmFail("ReSeedRng", __LINE__, retVal);
    }
    printf("Requested entropy from the TPM to re-seed the MCU RNG.(%ums)\r\n", (unsigned int)(HAL_GetTick() - startT));

    // Get the TPM authorities ready
    startT = HAL_GetTick();
    if((retVal = CreateAuthorities()) != TPM_RC_SUCCESS)
    {
        TpmFail("CreateAuthorities", __LINE__, retVal);
    }
    printf("TPM authority objects created.(%ums)\r\n", (unsigned int)(HAL_GetTick() - startT));

    // Get the TPMs boot counter and record the tick offset from the MCU so we can detect
    // monkey business later if someone silently reset the TPM or is slowing things down
    startT = HAL_GetTick();
    if((retVal = CheckTickSyncronized()) != TPM_RC_SUCCESS)
    {
        TpmFail("CheckTickSyncronized", __LINE__, retVal);
    }
    printf("Initialize runtime info resetCnt:%u restartCnt:%u (%ums)\r\n", (unsigned int)volatileData.resetCount, (unsigned int)volatileData.restartCount, (unsigned int)(HAL_GetTick() - startT));

    // Get the SRK object from the TPM, if necessary create and persist it
    startT = HAL_GetTick();
    if((retVal = ReadSrkObject()) != TPM_RC_SUCCESS)
    {
        TpmFail("ReadSrkObject", __LINE__, retVal);
    }
    PrintTPM2B("SRKName", (const TPM2B*)&volatileData.srkObject.obj.name);
    printf("SRK securely read from TPM and now TRUSTED.(%ums)\r\n", (unsigned int)(HAL_GetTick() - startT));

    // Self measure the CRTM version to PCR[0]
    startT = HAL_GetTick();
    if((retVal = MeasureEvent(HR_PCR + 0, sizeof(crtmString), (BYTE*)crtmString)) != TPM_RC_SUCCESS)
    {
        TpmFail("MeasureEvent", __LINE__, retVal);
    }
    printf("Measurement: CRTM in PCR[0].(%ums)\r\n", (unsigned int)(HAL_GetTick() - startT));

    // Measure the CRTM persisted data to PCR[1]
    startT = HAL_GetTick();
    if((retVal = MeasureEvent(HR_PCR + 1, sizeof(persistedData), (BYTE*)&persistedData)) != TPM_RC_SUCCESS)
    {
        TpmFail("MeasureEvent", __LINE__, retVal);
    }
    printf("Measurement: Persisted CRTM Data in PCR[1].(%ums)\r\n", (unsigned int)(HAL_GetTick() - startT));

    // Read the raw policy from the TPM
    startT = HAL_GetTick();
    if((retVal = ObtainRawPolicy(&rawPolicy)) != TPM_RC_SUCCESS)
    {
        TpmFail("ObtainRawPolicy", __LINE__, retVal);
    }
    PrintTPM2B("RawBootPolicy", (const TPM2B*)&rawPolicy);
    printf("Read raw boot policy from the Trusted Device Configuration Store in the TPM.(%ums)\r\n", (unsigned int)(HAL_GetTick() - startT));

    // Verify that the reset count still matches and the ticks are still somewhat synchronized.
    startT = HAL_GetTick();
    if((retVal = CheckTickSyncronized()) != TPM_RC_SUCCESS)
    {
        TpmFail("CheckTickSyncronized", __LINE__, retVal);
    }
    printf("Runtime verification resetCnt:%u restartCnt:%u tickDrift:%dms (%ums)\r\n", (unsigned int)volatileData.resetCount, (unsigned int)volatileData.restartCount, volatileData.tickDrift, (unsigned int)(HAL_GetTick() - startT));

    // Look at the application payload and see if it is signed
    if((appPayloadSigntureBlock = FindSignatureBlock(fakeAppPayload, fakeAppPayloadSize)) > 0)
    {
        TPM2B_NAME payloadAuthorityName = {0};

//        PrintBuffer("APP", fakeAppPayload, appPayloadSigntureBlock);
        printf("Found trailing signature block in AppPayload.\r\n");

        // Extend the appPayload and exclude the signature block
        startT = HAL_GetTick();
        if((retVal = MeasureEvent(HR_PCR + 2, appPayloadSigntureBlock, fakeAppPayload)) != TPM_RC_SUCCESS)
        {
            TpmFail("MeasureEvent", __LINE__, retVal);
        }
        printf("Measurement: AppPayload code (without signature block) in PCR[2].(%ums)\r\n", (unsigned int)(HAL_GetTick() - startT));

        if((retVal = VerifyCodeSignature(&fakeAppPayload[appPayloadSigntureBlock + sizeof(uint64_t)], fakeAppPayloadSize - appPayloadSigntureBlock - sizeof(uint64_t), &volatileData.measurementLog[volatileData.measurementIndex - 1].measurement, &payloadAuthorityName)) != TPM_RC_SUCCESS)
        {
            TpmFail("VerifyCodeSignature", __LINE__, retVal);
        }
        printf("AppPayload signature successfully verified.\r\n");
        PrintTPM2B("PayloadAuthority", (const TPM2B*)&payloadAuthorityName);

        // Measure the payload keyName to PCR[2]
        startT = HAL_GetTick();
        if((retVal = MeasureEvent(HR_PCR + 3, payloadAuthorityName.t.size, payloadAuthorityName.t.name)) != TPM_RC_SUCCESS)
        {
            TpmFail("MeasureEvent", __LINE__, retVal);
        }
        printf("Measurement: PayloadAuthority in PCR[3].(%ums)\r\n", (unsigned int)(HAL_GetTick() - startT));

        // Look up the boot policy
        if((rawPolicy.t.size != 0) &&
           ((retVal = FilterBootPolicy(&rawPolicy, &payloadAuthorityName, &bootPolicy)) != TPM_RC_SUCCESS))
        {
            TpmFail("FilterBootPolicy", __LINE__, retVal);
        }
    }
    else
    {
        BYTE noAuthority[sizeof(TPM_RH)] = {0};
        UINT32_TO_BYTE_ARRAY(TPM_RH_NULL, noAuthority);
        UINT32 codeMeasurement = volatileData.measurementIndex;

        PrintBuffer("APP", fakeAppPayload, sizeof(fakeAppPayload));
        printf("No signature block found in AppPayload.\r\n");

        // Extend the entire appPayload
        startT = HAL_GetTick();
        if((retVal = MeasureEvent(HR_PCR + 2, sizeof(fakeAppPayload), fakeAppPayload)) != TPM_RC_SUCCESS)
        {
            TpmFail("MeasureEvent", __LINE__, retVal);
        }
        printf("Measurement: AppPayload in PCR[2].(%ums)\r\n", (unsigned int)(HAL_GetTick() - startT));

        // Measure the noAuthority
        startT = HAL_GetTick();
        if((retVal = MeasureEvent(HR_PCR + 3, sizeof(noAuthority), noAuthority)) != TPM_RC_SUCCESS)
        {
            TpmFail("MeasureEvent", __LINE__, retVal);
        }
        printf("Measurement: No PayloadAuthority, so TPM_RH_NULL in PCR[3].(%ums)\r\n", (unsigned int)(HAL_GetTick() - startT));

        if(rawPolicy.t.size != 0)
        {
            // Look up the boot policy. It could be for any of the TPM generated code digests
            for(UINT32 n = 0; n < volatileData.measurementLog[codeMeasurement].measurement.count; n++)
            {
                TPM2B_NAME binaryName = {0};
                switch(volatileData.measurementLog[codeMeasurement].measurement.digests[n].hashAlg)
                {
                case TPM_ALG_SHA1:
                    binaryName.t.size = sizeof(volatileData.measurementLog[codeMeasurement].measurement.digests[n].digest.sha1) + sizeof(TPM_ALG_SHA1);
                    UINT16_TO_BYTE_ARRAY(TPM_ALG_SHA1, binaryName.t.name);
                    MemoryCopy(&binaryName.t.name[sizeof(TPM_ALG_SHA1)], volatileData.measurementLog[codeMeasurement].measurement.digests[n].digest.sha1, sizeof(volatileData.measurementLog[codeMeasurement].measurement.digests[n].digest.sha1), sizeof(binaryName.t.name) - sizeof(TPM_ALG_SHA1));
                    break;
                case TPM_ALG_SHA256:
                    binaryName.t.size = sizeof(volatileData.measurementLog[codeMeasurement].measurement.digests[n].digest.sha256) + sizeof(TPM_ALG_SHA256);
                    UINT16_TO_BYTE_ARRAY(TPM_ALG_SHA256, binaryName.t.name);
                    MemoryCopy(&binaryName.t.name[sizeof(TPM_ALG_SHA256)], volatileData.measurementLog[codeMeasurement].measurement.digests[n].digest.sha256, sizeof(volatileData.measurementLog[codeMeasurement].measurement.digests[n].digest.sha256), sizeof(binaryName.t.name) - sizeof(TPM_ALG_SHA256));
                    break;
                case TPM_ALG_SHA384:
                    binaryName.t.size = sizeof(volatileData.measurementLog[codeMeasurement].measurement.digests[n].digest.sha384) + sizeof(TPM_ALG_SHA384);
                    UINT16_TO_BYTE_ARRAY(TPM_ALG_SHA384, binaryName.t.name);
                    MemoryCopy(&binaryName.t.name[sizeof(TPM_ALG_SHA384)], volatileData.measurementLog[codeMeasurement].measurement.digests[n].digest.sha384, sizeof(volatileData.measurementLog[codeMeasurement].measurement.digests[n].digest.sha384), sizeof(binaryName.t.name) - sizeof(TPM_ALG_SHA384));
                    break;
                case TPM_ALG_SHA512:
                    binaryName.t.size = sizeof(volatileData.measurementLog[codeMeasurement].measurement.digests[n].digest.sha512) + sizeof(TPM_ALG_SHA512);
                    UINT16_TO_BYTE_ARRAY(TPM_ALG_SHA512, binaryName.t.name);
                    MemoryCopy(&binaryName.t.name[sizeof(TPM_ALG_SHA512)], volatileData.measurementLog[codeMeasurement].measurement.digests[n].digest.sha512, sizeof(volatileData.measurementLog[codeMeasurement].measurement.digests[n].digest.sha512), sizeof(binaryName.t.name) - sizeof(TPM_ALG_SHA512));
                    break;
                case TPM_ALG_SM3_256:
                    binaryName.t.size = sizeof(volatileData.measurementLog[codeMeasurement].measurement.digests[n].digest.sm3_256) + sizeof(TPM_ALG_SM3_256);
                    UINT16_TO_BYTE_ARRAY(TPM_ALG_SM3_256, binaryName.t.name);
                    MemoryCopy(&binaryName.t.name[sizeof(TPM_ALG_SM3_256)], volatileData.measurementLog[codeMeasurement].measurement.digests[n].digest.sm3_256, sizeof(volatileData.measurementLog[codeMeasurement].measurement.digests[n].digest.sm3_256), sizeof(binaryName.t.name) - sizeof(TPM_ALG_SM3_256));
                    break;
                }
                if((retVal = FilterBootPolicy(&rawPolicy, &binaryName, &bootPolicy)) != TPM_RC_SUCCESS)
                {
                    TpmFail("FilterBootPolicy", __LINE__, retVal);
                }
                if(bootPolicy.t.info.isBinaryPolicy == YES)
                {
                    // We found a policy for this payload digest
                    break;
                }
            }
        }
    }
    if((bootPolicy.t.info.isAuthorityPolicy == YES) || (bootPolicy.t.info.isBinaryPolicy == YES) || (bootPolicy.t.info.isDefaultPolicy == YES))
    {
        uint8_t seperatorNeeded = 0;
        printf("Boot policy found: \r\nINFO:   {");
        if(bootPolicy.t.info.isDefaultPolicy == YES) printf("%sisDefaultPolicy", (seperatorNeeded++) ? ", " : "");
        if(bootPolicy.t.info.isAuthorityPolicy == YES) printf("%sisAuthorityPolicy", (seperatorNeeded++) ? ", " : "");
        if(bootPolicy.t.info.isBinaryPolicy == YES) printf("%sisBinaryPolicy", (seperatorNeeded++) ? ", " : "");
        if(bootPolicy.t.info.launchApp == YES) printf("%slaunchApp", (seperatorNeeded++) ? ", " : "");
        if(bootPolicy.t.info.rebootMcu == YES) printf("%srebootMcu", (seperatorNeeded++) ? ", " : "");
        if(bootPolicy.t.info.haltMcu == YES) printf("%shaltMcu", (seperatorNeeded++) ? ", " : "");
        if(bootPolicy.t.info.launchFlashLoader == YES) printf("%slaunchFlashLoader", (seperatorNeeded++) ? ", " : "");
        printf("}\r\nACTION: {");
        seperatorNeeded = 0;
        if(bootPolicy.t.action.wipeLockoutAuth == YES) printf("%swipeLockoutAuth", (seperatorNeeded++) ? ", " : "");
        if(bootPolicy.t.action.wipeEndorsementAuth == YES) printf("%swipeEndorsementAuth", (seperatorNeeded++) ? ", " : "");
        if(bootPolicy.t.action.wipeOwnerAuth == YES) printf("%swipeOwnerAuth", (seperatorNeeded++) ? ", " : "");
        if(bootPolicy.t.action.incrementCounter & 0x01) printf("%sincrementCounter(1)", (seperatorNeeded++) ? ", " : "");
        if(bootPolicy.t.action.incrementCounter & 0x02) printf("%sincrementCounter(2)", (seperatorNeeded++) ? ", " : "");
        if(bootPolicy.t.action.randomizePlatformAuth == YES) printf("%srandomizePlatformAuth", (seperatorNeeded++) ? ", " : "");
        if(bootPolicy.t.action.resetLockout == YES) printf("%sresetLockout", (seperatorNeeded++) ? ", " : "");
        if(bootPolicy.t.action.platformClearTpm == YES) printf("%splatformClearTpm", (seperatorNeeded++) ? ", " : "");
        if(bootPolicy.t.action.disablePlatformHierarchy == YES) printf("%sdisablePlatformHierarchy", (seperatorNeeded++) ? ", " : "");
        if(bootPolicy.t.action.disablePlatformNV == YES) printf("%sdisablePlatformNV", (seperatorNeeded++) ? ", " : "");
        if(bootPolicy.t.action.disableEndorsementHierarchy == YES) printf("%sdisableEndorsementHierarchy", (seperatorNeeded++) ? ", " : "");
        if(bootPolicy.t.action.disableOwnerHierarchy == YES) printf("%sdisableOwnerHierarchy", (seperatorNeeded++) ? ", " : "");
        printf("}\r\n");
    }
    else if(bootPolicy.b == 0L)
    {
        printf("Not policy provisioned in the platform.\r\n");
    }
    else
    {
        TpmFail("BootPolicy Integrity Error", __LINE__, retVal);
    }

    // Measure the read policy to PCR[4]
    UINT64_TO_BYTE_ARRAY(bootPolicy.b, extendBuf);
    startT = HAL_GetTick();
    if((retVal = MeasureEvent(HR_PCR + 4, sizeof(extendBuf), extendBuf)) != TPM_RC_SUCCESS)
    {
        TpmFail("MeasureEvent", __LINE__, retVal);
    }
    printf("Measurement: Boot policy in PCR[4].(%ums)\r\n", (unsigned int)(HAL_GetTick() - startT));

    // Measure the application data to PCR[5]
    startT = HAL_GetTick();
    if((retVal = MeasureEvent(HR_PCR + 5, sizeof(retVal), (BYTE*)&retVal)) != TPM_RC_SUCCESS) // fake a measurement
    {
        TpmFail("MeasureEvent", __LINE__, retVal);
    }
    printf("Measurement: AppPayload data in PCR[5].(%ums)\r\n", (unsigned int)(HAL_GetTick() - startT));

    printf("---- EventLog Start -----------------------------------------------------------\r\n");
    for(UINT32 n = 0; n < volatileData.measurementIndex; n++)
    {
        PrintMeasurement(n);
    }
    printf("---- EventLog End -------------------------------------------------------------\r\n");

    // Verify that the reset count still matches and the ticks are still somewhat synchronized.
    startT = HAL_GetTick();
    if((retVal = CheckTickSyncronized()) != TPM_RC_SUCCESS)
    {
        TpmFail("CheckTickSyncronized", __LINE__, retVal);
    }
    printf("RuntimeInfo resetCnt:%u restartCnt:%u tickDrift:%dms (%ums)\r\n", (unsigned int)volatileData.resetCount, (unsigned int)volatileData.restartCount, volatileData.tickDrift, (unsigned int)(HAL_GetTick() - startT));

    printf(">>>> EnforceBootPolicy <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\r\n");
    if((retVal = EnforceBootPolicy(&bootPolicy)) != TPM_RC_SUCCESS)
    {
        TpmFail("EnforceBootPolicy", __LINE__, retVal);
    }
    printf(">>>> EnforceBootPolicy <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\r\n");

    // Verify that the reset count still matches and the ticks are still somewhat synchronized.
    startT = HAL_GetTick();
    if((retVal = CheckTickSyncronized()) != TPM_RC_SUCCESS)
    {
        TpmFail("CheckTickSyncronized", __LINE__, retVal);
    }
    printf("RuntimeInfo resetCnt:%u restartCnt:%u tickDrift:%dms (%ums)\r\n", (unsigned int)volatileData.resetCount, (unsigned int)volatileData.restartCount, volatileData.tickDrift, (unsigned int)(HAL_GetTick() - startT));

//Cleanup:
    printf("RazorClam complete.(%ums)\r\n", (unsigned int)(HAL_GetTick() - razorClamStartT));
    printf("==== %s ==========================================================\r\n", crtmString);
    if(g_UsingLocality != (UINT32)TIS_LOCALITY_NONE)
    {
        ReleaseLocality();
        g_UsingLocality = (UINT32)TIS_LOCALITY_NONE;
    }
    return retVal;
}
