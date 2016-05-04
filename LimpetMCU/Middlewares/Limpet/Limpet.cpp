/*
 * Limpet.cpp
 *
 *  Created on: Apr 5, 2016
 *      Author: stefanth
 */

#include "stm32f4xx_hal.h"
#include "TisTpmDrv.h"
#include "UrchinLib.h"
#include "UrchinPlatform.h"
#include "Limpet.h"

#define AIOTH_PERSISTED_URI_INDEX (TPM_20_OWNER_NV_SPACE + 0x100)
#define AIOTH_PERSISTED_KEY_INDEX ((TPMI_DH_PERSISTENT)0x81000100)
#define MAX_LOGICAL_DEVICE (10)

uint32_t
LimpetCreateSrk(
    void
    )
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    union
    {
        ReadPublic_In readPublicIn;
        CreatePrimary_In createPrimaryIn;
        EvictControl_In evictControlIn;
    } in;
    union
    {
        ReadPublic_Out readPublicOut;
        CreatePrimary_Out createPrimaryOut;
        EvictControl_Out evictControlOut;
    } out;
    ANY_OBJECT srk = {0};


    // First we read the SRK public without auditing, because we need to know
    // the SRK name for that. An attacker may feed us a bad SRK name now so we
    // will not really trust what we read now until we have confirmed it later
    // again with the EK seeded audit session.
    INITIALIZE_CALL_BUFFERS(TPM2_ReadPublic, &in.readPublicIn, &out.readPublicOut);
    parms.objectTableIn[TPM2_ReadPublic_HdlIn_PublicKey].generic.handle = TPM_20_SRK_HANDLE;
    TRY_TPM_CALL(FALSE, TPM2_ReadPublic);

    if(result != TPM_RC_SUCCESS)
    {
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
    }

Cleanup:
    return result;
}

// Read the deviceID for a given logical device
uint32_t LimpetReadDeviceId(
    uint32_t LogicalDeviceNumber,
    uint8_t* DeviceId,
    uint32_t DeviceIdMax,
    uint32_t* DeviceIdLen
    )
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    ReadPublic_In readPublicIn;
    ReadPublic_Out readPublicOut;
    HASH_STATE hash = { 0 };
    TPM2B_DIGEST deviceId = { 0 };

    // Read the SRK name which is the basis for our logical deviceIDs. This name is different on every TPM.
    INITIALIZE_CALL_BUFFERS(TPM2_ReadPublic, &readPublicIn, &readPublicOut);
    parms.objectTableIn[TPM2_ReadPublic_HdlIn_PublicKey].generic.handle = TPM_20_SRK_HANDLE;
    EXECUTE_TPM_CALL(FALSE, TPM2_ReadPublic);

    // Calculate the logical deviceID = SHA256( LogicalDeviceNo || SRKName) and convert it into readable hex form
    deviceId.t.size = CryptStartHash(TPM_ALG_SHA256, &hash);
    CryptUpdateDigest(&hash, sizeof(LogicalDeviceNumber), (BYTE*)&LogicalDeviceNumber);
    CryptUpdateDigest2B(&hash, (TPM2B*)&readPublicOut.name);
    deviceId.t.size = CryptCompleteHash2B(&hash, (TPM2B*)&deviceId);

    *DeviceIdLen = MIN(deviceId.t.size, DeviceIdMax);
    MemoryCopy(DeviceId, deviceId.t.buffer, *DeviceIdLen, DeviceIdMax);

Cleanup:
    return result;
}

uint32_t LimpetStoreURI(
    uint32_t LogicalDeviceNumber,
    uint8_t* UriData,
    uint32_t UriLen
    )
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    union
    {
        NV_ReadPublic_In nv_ReadPublic;
        NV_DefineSpace_In nv_DefineSpace;
        NV_Write_In nv_Write;

    } in;
    union
    {
        NV_ReadPublic_Out nv_ReadPublic;
        NV_DefineSpace_Out nv_DefineSpace;
        NV_Write_Out nv_Write;
    } out;
    ANY_OBJECT nvIndex = { 0 };

    // Define the NV storage space in the TPM
    INITIALIZE_CALL_BUFFERS(TPM2_NV_DefineSpace, &in.nv_DefineSpace, &out.nv_DefineSpace);
    parms.objectTableIn[TPM2_NV_DefineSpace_HdlIn_AuthHandle].entity.handle = TPM_RH_OWNER;
    in.nv_DefineSpace.publicInfo.t.nvPublic.nvIndex = AIOTH_PERSISTED_URI_INDEX + LogicalDeviceNumber;
    in.nv_DefineSpace.publicInfo.t.nvPublic.nameAlg = TPM_ALG_SHA256;
    in.nv_DefineSpace.publicInfo.t.nvPublic.attributes.TPMA_NV_OWNERWRITE = SET;
    in.nv_DefineSpace.publicInfo.t.nvPublic.attributes.TPMA_NV_AUTHREAD = SET;
    in.nv_DefineSpace.publicInfo.t.nvPublic.attributes.TPMA_NV_NO_DA = SET;
    in.nv_DefineSpace.publicInfo.t.nvPublic.dataSize = UriLen;
    EXECUTE_TPM_CALL(FALSE, TPM2_NV_DefineSpace);

    // Read the definition back to get the NV storage name
    INITIALIZE_CALL_BUFFERS(TPM2_NV_ReadPublic, &in.nv_ReadPublic, &out.nv_ReadPublic);
    parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex].generic.handle = AIOTH_PERSISTED_URI_INDEX + LogicalDeviceNumber;
    EXECUTE_TPM_CALL(FALSE, TPM2_NV_ReadPublic);
    nvIndex = parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex];

    INITIALIZE_CALL_BUFFERS(TPM2_NV_Write, &in.nv_Write, &in.nv_Write);
    parms.objectTableIn[TPM2_NV_Write_HdlIn_AuthHandle].entity.handle = TPM_RH_OWNER;
    parms.objectTableIn[TPM2_NV_Write_HdlIn_NvIndex] = nvIndex;
    in.nv_Write.offset = 0;
    in.nv_Write.data.t.size = (UINT16)UriLen;
    MemoryCopy(in.nv_Write.data.t.buffer, UriData, in.nv_Write.data.t.size, sizeof(in.nv_Write.data.t.buffer));
    EXECUTE_TPM_CALL(FALSE, TPM2_NV_Write);

Cleanup:
    return result;
}

uint32_t LimpetReadURI(
    uint32_t LogicalDeviceNumber,
    uint8_t* UriData,
    uint32_t UriMax,
    uint32_t* UriLen
    )
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    union
    {
        NV_ReadPublic_In nv_ReadPublic;
        NV_Read_In nv_Read;
    } in;
    union
    {
        NV_ReadPublic_Out nv_ReadPublic;
        NV_Read_Out nv_Read;
    } out;
    ANY_OBJECT nvIndex = { 0 };
    UINT16 dataLen = 0;

    // Read the public definition to get the name
    INITIALIZE_CALL_BUFFERS(TPM2_NV_ReadPublic, &in.nv_ReadPublic, &out.nv_ReadPublic);
    parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex].generic.handle = AIOTH_PERSISTED_URI_INDEX + LogicalDeviceNumber;
    EXECUTE_TPM_CALL(FALSE, TPM2_NV_ReadPublic);
    nvIndex = parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex];
    dataLen = out.nv_ReadPublic.nvPublic.t.nvPublic.dataSize;

    // Read the content of the Index
    INITIALIZE_CALL_BUFFERS(TPM2_NV_Read, &in.nv_Read, &out.nv_Read);
    parms.objectTableIn[TPM2_NV_Read_HdlIn_AuthHandle] = nvIndex;
    parms.objectTableIn[TPM2_NV_Read_HdlIn_NvIndex] = nvIndex;
    in.nv_Read.offset = 0;
    in.nv_Read.size = dataLen;
    EXECUTE_TPM_CALL(FALSE, TPM2_NV_Read);

    *UriLen = MIN(out.nv_Read.data.t.size, UriMax);
    MemoryCopy(UriData, out.nv_Read.data.t.buffer, *UriLen, UriMax);

Cleanup:
    return result;
}

uint32_t LimpetDestroyURI(
    uint32_t LogicalDeviceNumber
    )
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    union
    {
        NV_ReadPublic_In nv_ReadPublic;
        NV_UndefineSpace_In nv_UndefineSpace;
    } in;
    union
    {
        NV_ReadPublic_Out nv_ReadPublic;
        NV_UndefineSpace_Out nv_UndefineSpace;
    } out;
    ANY_OBJECT nvIndex = { 0 };

    // Read the public information to get the name
    INITIALIZE_CALL_BUFFERS(TPM2_NV_ReadPublic, &in.nv_ReadPublic, &out.nv_ReadPublic);
    parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex].generic.handle = AIOTH_PERSISTED_URI_INDEX + LogicalDeviceNumber;
    EXECUTE_TPM_CALL(FALSE, TPM2_NV_ReadPublic);
    nvIndex = parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex];

    // Destroy the storage location
    INITIALIZE_CALL_BUFFERS(TPM2_NV_UndefineSpace, &in.nv_UndefineSpace, &out.nv_UndefineSpace);
    parms.objectTableIn[TPM2_NV_UndefineSpace_HdlIn_AuthHandle].entity.handle = TPM_RH_OWNER;
    parms.objectTableIn[TPM2_NV_UndefineSpace_HdlIn_NvIndex] = nvIndex;
    EXECUTE_TPM_CALL(FALSE, TPM2_NV_UndefineSpace);

Cleanup:
    return result;
}

uint32_t LimpetCreateHmacKey(
    uint32_t LogicalDeviceNumber,
    uint8_t* HmacKeyIn,
    uint32_t HmacKeyInLen
    )
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    union
    {
        Create_In create;
        Load_In load;
        EvictControl_In evictControl;
    } in;
    union
    {
        Create_Out create;
        Load_Out load;
        EvictControl_Out evictControl;
    } out;
    ANY_OBJECT hmacKey = { 0 };

    // Create the HMAC key, or better import it after Base64 decoding it
    INITIALIZE_CALL_BUFFERS(TPM2_Create, &in.create, &out.create);
    parms.objectTableIn[TPM2_Create_HdlIn_ParentHandle].generic.handle = TPM_20_SRK_HANDLE;
    in.create.inSensitive.t.sensitive.data.t.size = (UINT16)HmacKeyInLen;
    MemoryCopy(in.create.inSensitive.t.sensitive.data.t.buffer, HmacKeyIn, in.create.inSensitive.t.sensitive.data.t.size , sizeof(in.create.inSensitive.t.sensitive.data.t.buffer));
    in.create.inPublic.t.publicArea.type = TPM_ALG_KEYEDHASH;
    in.create.inPublic.t.publicArea.nameAlg = TPM_ALG_SHA256;
    in.create.inPublic.t.publicArea.objectAttributes.userWithAuth = 1;
    in.create.inPublic.t.publicArea.objectAttributes.noDA = 1;
    in.create.inPublic.t.publicArea.objectAttributes.sign = 1;
    in.create.inPublic.t.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_HMAC;
    in.create.inPublic.t.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = TPM_ALG_SHA256;
    EXECUTE_TPM_CALL(FALSE, TPM2_Create);

    // Copy the HMAC key object out
    hmacKey.obj.publicArea = out.create.outPublic;
    hmacKey.obj.privateArea = out.create.outPrivate;

    // Load the HMAC key object
    INITIALIZE_CALL_BUFFERS(TPM2_Load, &in.load, &out.load);
    parms.objectTableIn[TPM2_Load_HdlIn_ParentHandle].generic.handle = TPM_20_SRK_HANDLE;
    parms.objectTableOut[TPM2_Load_HdlOut_ObjectHandle] = hmacKey; // Copy the key in to be updated
    in.load.inPublic = hmacKey.obj.publicArea;
    in.load.inPrivate = hmacKey.obj.privateArea;
    EXECUTE_TPM_CALL(FALSE, TPM2_Load);

    // Copy the updated HMAC back out. This one has a valid handle now
    hmacKey = parms.objectTableOut[TPM2_Load_HdlOut_ObjectHandle];

    // Persist the key in TPM NV storage and it will never ever see the light of day
    INITIALIZE_CALL_BUFFERS(TPM2_EvictControl, &in.evictControl, &out.evictControl);
    parms.objectTableIn[TPM2_EvictControl_HdlIn_Auth].entity.handle = TPM_RH_OWNER;
    parms.objectTableIn[TPM2_EvictControl_HdlIn_ObjectHandle] = hmacKey;
    in.evictControl.persistentHandle = AIOTH_PERSISTED_KEY_INDEX + LogicalDeviceNumber;
    EXECUTE_TPM_CALL(FALSE, TPM2_EvictControl);

Cleanup:
    return result;
}

uint32_t LimpetSignWithHmacKey(
    uint32_t LogicalDeviceNumber,
    uint8_t* DataPtr,
    uint32_t DataSize,
    uint8_t* Hmac,
    uint32_t HmacMax,
    uint32_t* HmacLen
    )
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    union
    {
        ReadPublic_In readPublic;
        HMAC_In hmac;
        HMAC_Start_In hmac_Start;
        SequenceUpdate_In sequenceUpdate;
        SequenceComplete_In sequenceComplete;
    } in;
    union
    {
        ReadPublic_Out readPublic;
        HMAC_Out hmac;
        HMAC_Start_Out hmac_Start;
        SequenceUpdate_Out sequenceUpdate;
        SequenceComplete_Out sequenceComplete;
    } out;
    ANY_OBJECT hmacKey = { 0 };

    // Read the public portion of the HMAC key
    INITIALIZE_CALL_BUFFERS(TPM2_ReadPublic, &in.readPublic, &out.readPublic);
    parms.objectTableIn[TPM2_ReadPublic_HdlIn_PublicKey].generic.handle = AIOTH_PERSISTED_KEY_INDEX + LogicalDeviceNumber;
    TRY_TPM_CALL(FALSE, TPM2_ReadPublic);
    hmacKey.obj.publicArea = out.readPublic.outPublic;
    hmacKey.obj.name = out.readPublic.name;
    hmacKey.obj.handle = AIOTH_PERSISTED_KEY_INDEX + LogicalDeviceNumber;

    // The TPM provides a simple one command HMAC operation if the data is at or smaller than 1k
    if (DataSize <= 1024)
    {
        // Feed it through the grinder
        INITIALIZE_CALL_BUFFERS(TPM2_HMAC, &in.hmac, &out.hmac);
        parms.objectTableIn[TPM2_HMAC_HdlIn_Handle] = hmacKey;
        in.hmac.hashAlg = TPM_ALG_SHA256;
        in.hmac.buffer.t.size = (UINT16)DataSize;
        MemoryCopy(in.hmac.buffer.t.buffer, DataPtr, in.hmac.buffer.t.size, sizeof(in.hmac.buffer.t.buffer));
        EXECUTE_TPM_CALL(FALSE, TPM2_HMAC);
        *HmacLen = MIN(HmacMax,out.hmac.outHMAC.t.size);
        MemoryCopy(Hmac, out.hmac.outHMAC.t.buffer, *HmacLen, HmacMax);
    }
    else
    {
        ANY_OBJECT sequence = { 0 };
        UINT32 dataIndex = 0;

        // Start SHA-256 HMAC
        INITIALIZE_CALL_BUFFERS(TPM2_HMAC_Start, &in.hmac_Start, &in.hmac_Start);
        parms.objectTableIn[TPM2_HMAC_Start_HdlIn_Handle] = hmacKey;
        in.hmac_Start.hashAlg = TPM_ALG_SHA256;
        EXECUTE_TPM_CALL(FALSE, TPM2_HMAC_Start);
        sequence = parms.objectTableOut[TPM2_HashSequenceStart_HdlOut_SequenceHandle];

        // Iterate through the file until we have only 1024 or less left
        while ((DataSize - dataIndex) > MAX_DIGEST_BUFFER)
        {
            // Update the SHA-256 digest
            INITIALIZE_CALL_BUFFERS(TPM2_SequenceUpdate, &in.sequenceUpdate, &out.sequenceUpdate);
            parms.objectTableIn[TPM2_SequenceUpdate_HdlIn_SequenceHandle] = sequence;
            in.sequenceUpdate.buffer.t.size = MAX_DIGEST_BUFFER;
            MemoryCopy(in.sequenceUpdate.buffer.t.buffer, &DataPtr[dataIndex], in.sequenceUpdate.buffer.t.size, sizeof(in.sequenceUpdate.buffer.t.buffer));
            EXECUTE_TPM_CALL(FALSE, TPM2_SequenceUpdate);
            dataIndex += in.sequenceUpdate.buffer.t.size;
        }

        // Finalize with the last data and get the SHA256 HMAC
        INITIALIZE_CALL_BUFFERS(TPM2_SequenceComplete, &in.sequenceComplete, &out.sequenceComplete);
        parms.objectTableIn[TPM2_SequenceUpdate_HdlIn_SequenceHandle] = sequence;
        in.sequenceComplete.hierarchy = TPM_RH_NULL;
        in.sequenceComplete.buffer.t.size = (UINT16)(DataSize - dataIndex);
        MemoryCopy(in.sequenceComplete.buffer.t.buffer, &DataPtr[dataIndex], in.sequenceComplete.buffer.t.size, sizeof(in.sequenceComplete.buffer.t.buffer));
        EXECUTE_TPM_CALL(FALSE, TPM2_SequenceComplete);
        sequence = parms.objectTableIn[TPM2_SequenceComplete_HdlIn_SequenceHandle];
        *HmacLen = MIN(HmacMax, out.sequenceComplete.result.t.size);
        MemoryCopy(Hmac, out.sequenceComplete.result.t.buffer, *HmacLen, HmacMax);
    }

Cleanup:
    return result;
}

uint32_t LimpetEvictHmacKey(
    UINT32 LogicalDeviceNumber
    )
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    union
    {
        ReadPublic_In readPublic;
        EvictControl_In evictControl;
    } in;
    union
    {
        ReadPublic_Out readPublic;
        EvictControl_Out evictControl;
    } out;
    ANY_OBJECT hmacKey = { 0 };

    // Read the public portion to get the name
    INITIALIZE_CALL_BUFFERS(TPM2_ReadPublic, &in.readPublic, &out.readPublic);
    parms.objectTableIn[TPM2_ReadPublic_HdlIn_PublicKey].obj.handle = AIOTH_PERSISTED_KEY_INDEX + LogicalDeviceNumber;
    EXECUTE_TPM_CALL(FALSE, TPM2_ReadPublic);
    hmacKey = parms.objectTableIn[TPM2_ReadPublic_HdlIn_PublicKey];

    // Evict the key from TPM NV. This will irretrievably destroy it. Note the key is not returned!
    INITIALIZE_CALL_BUFFERS(TPM2_EvictControl, &in.evictControl, &out.evictControl);
    parms.objectTableIn[TPM2_EvictControl_HdlIn_Auth].entity.handle = TPM_RH_OWNER;
    parms.objectTableIn[TPM2_EvictControl_HdlIn_ObjectHandle] = hmacKey;
    in.evictControl.persistentHandle = AIOTH_PERSISTED_KEY_INDEX + LogicalDeviceNumber;
    EXECUTE_TPM_CALL(FALSE, TPM2_EvictControl);

Cleanup:
    return result;
}

