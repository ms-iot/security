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

#ifdef USE_TPM_SIMULATOR
// Linked Simulator Hookup
extern "C"
{
    UINT32 TPMSimSubmitCommand(
        BOOL CloseContext,
        BYTE* pbCommand,
        UINT32 cbCommand,
        BYTE* pbResponse,
        UINT32 cbResponse,
        UINT32* pcbResponse
        );
    void TPMSimTeardown(void);
}
#define PlatformSubmitTPM20Command TPMSimSubmitCommand
#endif

#define MAX_KEYSLOTS (3)
#define MAX_SESSIONSLOTS (10)
#define OBJECT_NOT_LOADED (0xffffffff)
#define MAX_TABLE_SIZE (50)

typedef struct _CONTEXT_TABLE_OBJECT
{
    UINT64 lastUsed;
    TPM_HT handleType;
    TPM_RH physicalHdl;
    TPMS_CONTEXT context;
} CONTEXT_TABLE_OBJECT, *PCONTEXT_TABLE_OBJECT;

UINT64 g_objectUsageCounter = 1L;
UINT64 g_sessionUsageCounter = 1L;
UINT32 g_numObjectsLoaded = 0;
UINT32 g_numSessionsLoaded = 0;
CONTEXT_TABLE_OBJECT g_objectTable[MAX_TABLE_SIZE] = {0};

BOOL
IsHandleInResponse(
TPM_CC commandCode
);

UINT32
GetNextFreeVHandle(PCONTEXT_TABLE_OBJECT pTable, UINT32 tableSize)
{
    for(UINT32 n = 0; n < tableSize; n++)
    {
        if(pTable[n].lastUsed == 0L)
        {
            return n;
        }
    }
    return 0xffffffff;
}

UINT32
FindOldestLoaded(PCONTEXT_TABLE_OBJECT pTable, UINT32 tableSize, TPM_HT handleType)
{
    UINT64 useCnt = 0xffffffffffffffffL;
    UINT32 index = 0xffffffff;
    for(UINT32 n = 0; n < tableSize; n++)
    {
        if((pTable[n].lastUsed != 0) &&
           (pTable[n].handleType == handleType) &&
           (pTable[n].physicalHdl != OBJECT_NOT_LOADED) &&
           (pTable[n].lastUsed < useCnt))
        {
            index = n;
            useCnt = pTable[n].lastUsed;
        }
    }
    return index;
}

UINT32
FindByVHandle(TPM_RH virtualHdl)
{
    return (virtualHdl & 0x00ffffff);
}

UINT32
FindByPHandle(PCONTEXT_TABLE_OBJECT pTable, UINT32 tableSize, TPM_RH physicalHdl)
{
    for(UINT32 n = 0; n < tableSize; n++)
    {
        if(pTable[n].physicalHdl == physicalHdl)
        {
            return n;
        }
    }
    return 0xffffffff;
}

TPM_RC
FlushObject(PCONTEXT_TABLE_OBJECT object)
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    FlushContext_In flushContextIn;
    FlushContext_Out flushContextOut;

    // Unload the object
    INITIALIZE_CALL_BUFFERS(TPM2_FlushContext, &flushContextIn, &flushContextOut);
    parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle].generic.handle = object->physicalHdl;
    EXECUTE_TPM_CALL(FALSE, TPM2_FlushContext);

    // Update the object
    object->physicalHdl = OBJECT_NOT_LOADED;

Cleanup:
    return result;
}

TPM_RC
SwapObjectOut(PCONTEXT_TABLE_OBJECT object)
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    ContextSave_In contextSaveIn;
    ContextSave_Out contextSaveOut;

    if(object->physicalHdl == OBJECT_NOT_LOADED)
    {
        goto Cleanup;
    }

    // Unload the object
    INITIALIZE_CALL_BUFFERS(TPM2_ContextSave, &contextSaveIn, &contextSaveOut);
    parms.objectTableIn[TPM2_ContextSave_HdlIn_SaveHandle].generic.handle = object->physicalHdl;
    EXECUTE_TPM_CALL(FALSE, TPM2_ContextSave);
    object->context = contextSaveOut.context;

Cleanup:
    return result;
}

TPM_RC
SwapObjectIn(PCONTEXT_TABLE_OBJECT object)
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    ContextLoad_In contextLoadIn;
    ContextLoad_Out contextLoadOut;

    if(object->physicalHdl != OBJECT_NOT_LOADED)
    {
        goto Cleanup;
    }

    // Load the context
    INITIALIZE_CALL_BUFFERS(TPM2_ContextLoad, &contextLoadIn, &contextLoadOut);
    contextLoadIn.context = object->context;
    EXECUTE_TPM_CALL(FALSE, TPM2_ContextLoad);
    object->physicalHdl = parms.objectTableOut[TPM2_ContextLoad_HdlOut_LoadedHandle].generic.handle;

Cleanup:
    return result;
}

void
DropFromTable(PCONTEXT_TABLE_OBJECT object)
{
    MemorySet(object, 0x00, sizeof(CONTEXT_TABLE_OBJECT));
}

TPM_RC
ParseHandleBuffer(
TPM_CC      command_code,
BYTE        **handle_buffer_start,
INT32       *buffer_remain_size,
TPM_HANDLE  handles[],
UINT32      *handle_num
)
{
    TPM_RC      result;

    switch(command_code)
    {
#if      CC_Startup == YES
    case TPM_CC_Startup:
        *handle_num = 0;
        break;
#endif     // CC_Startup
#if      CC_Shutdown == YES
    case TPM_CC_Shutdown:
        *handle_num = 0;
        break;
#endif     // CC_Shutdown
#if      CC_SelfTest == YES
    case TPM_CC_SelfTest:
        *handle_num = 0;
        break;
#endif     // CC_SelfTest
#if      CC_IncrementalSelfTest == YES
    case TPM_CC_IncrementalSelfTest:
        *handle_num = 0;
        break;
#endif     // CC_IncrementalSelfTest
#if      CC_GetTestResult == YES
    case TPM_CC_GetTestResult:
        *handle_num = 0;
        break;
#endif     // CC_GetTestResult
#if      CC_StartAuthSession == YES
    case TPM_CC_StartAuthSession:
        *handle_num = 2;
        result = TPMI_DH_OBJECT_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size, TRUE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        result = TPMI_DH_ENTITY_Unmarshal(&handles[1], handle_buffer_start, buffer_remain_size, TRUE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_2;
        break;
#endif     // CC_StartAuthSession
#if      CC_PolicyRestart == YES
    case TPM_CC_PolicyRestart:
        *handle_num = 1;
        result = TPMI_SH_POLICY_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_PolicyRestart
#if      CC_Create == YES
    case TPM_CC_Create:
        *handle_num = 1;
        result = TPMI_DH_OBJECT_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size, FALSE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_Create
#if      CC_Load == YES
    case TPM_CC_Load:
        *handle_num = 1;
        result = TPMI_DH_OBJECT_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size, FALSE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_Load
#if      CC_LoadExternal == YES
    case TPM_CC_LoadExternal:
        *handle_num = 0;
        break;
#endif     // CC_LoadExternal
#if      CC_ReadPublic == YES
    case TPM_CC_ReadPublic:
        *handle_num = 1;
        result = TPMI_DH_OBJECT_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size, FALSE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_ReadPublic
#if      CC_ActivateCredential == YES
    case TPM_CC_ActivateCredential:
        *handle_num = 2;
        result = TPMI_DH_OBJECT_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size, FALSE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        result = TPMI_DH_OBJECT_Unmarshal(&handles[1], handle_buffer_start, buffer_remain_size, FALSE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_2;
        break;
#endif     // CC_ActivateCredential
#if      CC_MakeCredential == YES
    case TPM_CC_MakeCredential:
        *handle_num = 1;
        result = TPMI_DH_OBJECT_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size, FALSE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_MakeCredential
#if      CC_Unseal == YES
    case TPM_CC_Unseal:
        *handle_num = 1;
        result = TPMI_DH_OBJECT_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size, FALSE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_Unseal
#if      CC_ObjectChangeAuth == YES
    case TPM_CC_ObjectChangeAuth:
        *handle_num = 2;
        result = TPMI_DH_OBJECT_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size, FALSE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        result = TPMI_DH_OBJECT_Unmarshal(&handles[1], handle_buffer_start, buffer_remain_size, FALSE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_2;
        break;
#endif     // CC_ObjectChangeAuth
#if      CC_Duplicate == YES
    case TPM_CC_Duplicate:
        *handle_num = 2;
        result = TPMI_DH_OBJECT_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size, FALSE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        result = TPMI_DH_OBJECT_Unmarshal(&handles[1], handle_buffer_start, buffer_remain_size, TRUE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_2;
        break;
#endif     // CC_Duplicate
#if      CC_Rewrap == YES
    case TPM_CC_Rewrap:
        *handle_num = 2;
        result = TPMI_DH_OBJECT_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size, TRUE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        result = TPMI_DH_OBJECT_Unmarshal(&handles[1], handle_buffer_start, buffer_remain_size, TRUE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_2;
        break;
#endif     // CC_Rewrap
#if      CC_Import == YES
    case TPM_CC_Import:
        *handle_num = 1;
        result = TPMI_DH_OBJECT_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size, FALSE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_Import
#if      CC_RSA_Encrypt == YES
    case TPM_CC_RSA_Encrypt:
        *handle_num = 1;
        result = TPMI_DH_OBJECT_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size, FALSE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_RSA_Encrypt
#if      CC_RSA_Decrypt == YES
    case TPM_CC_RSA_Decrypt:
        *handle_num = 1;
        result = TPMI_DH_OBJECT_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size, FALSE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_RSA_Decrypt
#if      CC_ECDH_KeyGen == YES
    case TPM_CC_ECDH_KeyGen:
        *handle_num = 1;
        result = TPMI_DH_OBJECT_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size, FALSE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_ECDH_KeyGen
#if      CC_ECDH_ZGen == YES
    case TPM_CC_ECDH_ZGen:
        *handle_num = 1;
        result = TPMI_DH_OBJECT_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size, FALSE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_ECDH_ZGen
#if      CC_ECC_Parameters == YES
    case TPM_CC_ECC_Parameters:
        *handle_num = 0;
        break;
#endif     // CC_ECC_Parameters
#if      CC_ZGen_2Phase == YES
    case TPM_CC_ZGen_2Phase:
        *handle_num = 1;
        result = TPMI_DH_OBJECT_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size, FALSE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_ZGen_2Phase
#if      CC_EncryptDecrypt == YES
    case TPM_CC_EncryptDecrypt:
        *handle_num = 1;
        result = TPMI_DH_OBJECT_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size, FALSE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_EncryptDecrypt
#if      CC_Hash == YES
    case TPM_CC_Hash:
        *handle_num = 0;
        break;
#endif     // CC_Hash
#if      CC_HMAC == YES
    case TPM_CC_HMAC:
        *handle_num = 1;
        result = TPMI_DH_OBJECT_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size, FALSE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_HMAC
#if      CC_GetRandom == YES
    case TPM_CC_GetRandom:
        *handle_num = 0;
        break;
#endif     // CC_GetRandom
#if      CC_StirRandom == YES
    case TPM_CC_StirRandom:
        *handle_num = 0;
        break;
#endif     // CC_StirRandom
#if      CC_HMAC_Start == YES
    case TPM_CC_HMAC_Start:
        *handle_num = 1;
        result = TPMI_DH_OBJECT_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size, FALSE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_HMAC_Start
#if      CC_HashSequenceStart == YES
    case TPM_CC_HashSequenceStart:
        *handle_num = 0;
        break;
#endif     // CC_HashSequenceStart
#if      CC_SequenceUpdate == YES
    case TPM_CC_SequenceUpdate:
        *handle_num = 1;
        result = TPMI_DH_OBJECT_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size, FALSE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_SequenceUpdate
#if      CC_SequenceComplete == YES
    case TPM_CC_SequenceComplete:
        *handle_num = 1;
        result = TPMI_DH_OBJECT_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size, FALSE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_SequenceComplete
#if      CC_EventSequenceComplete == YES
    case TPM_CC_EventSequenceComplete:
        *handle_num = 2;
        result = TPMI_DH_PCR_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size, TRUE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        result = TPMI_DH_OBJECT_Unmarshal(&handles[1], handle_buffer_start, buffer_remain_size, FALSE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_2;
        break;
#endif     // CC_EventSequenceComplete
#if      CC_Certify == YES
    case TPM_CC_Certify:
        *handle_num = 2;
        result = TPMI_DH_OBJECT_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size, FALSE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        result = TPMI_DH_OBJECT_Unmarshal(&handles[1], handle_buffer_start, buffer_remain_size, TRUE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_2;
        break;
#endif     // CC_Certify
#if      CC_CertifyCreation == YES
    case TPM_CC_CertifyCreation:
        *handle_num = 2;
        result = TPMI_DH_OBJECT_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size, TRUE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        result = TPMI_DH_OBJECT_Unmarshal(&handles[1], handle_buffer_start, buffer_remain_size, FALSE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_2;
        break;
#endif     // CC_CertifyCreation
#if      CC_Quote == YES
    case TPM_CC_Quote:
        *handle_num = 1;
        result = TPMI_DH_OBJECT_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size, FALSE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_Quote
#if      CC_GetSessionAuditDigest == YES
    case TPM_CC_GetSessionAuditDigest:
        *handle_num = 3;
        result = TPMI_RH_ENDORSEMENT_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size, FALSE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        result = TPMI_DH_OBJECT_Unmarshal(&handles[1], handle_buffer_start, buffer_remain_size, TRUE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_2;
        result = TPMI_SH_HMAC_Unmarshal(&handles[2], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_3;
        break;
#endif     // CC_GetSessionAuditDigest
#if      CC_GetCommandAuditDigest == YES
    case TPM_CC_GetCommandAuditDigest:
        *handle_num = 2;
        result = TPMI_RH_ENDORSEMENT_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size, FALSE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        result = TPMI_DH_OBJECT_Unmarshal(&handles[1], handle_buffer_start, buffer_remain_size, TRUE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_2;
        break;
#endif     // CC_GetCommandAuditDigest
#if      CC_GetTime == YES
    case TPM_CC_GetTime:
        *handle_num = 2;
        result = TPMI_RH_ENDORSEMENT_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size, FALSE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        result = TPMI_DH_OBJECT_Unmarshal(&handles[1], handle_buffer_start, buffer_remain_size, TRUE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_2;
        break;
#endif     // CC_GetTime
#if      CC_Commit == YES
    case TPM_CC_Commit:
        *handle_num = 1;
        result = TPMI_DH_OBJECT_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size, FALSE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_Commit
#if      CC_EC_Ephemeral == YES
    case TPM_CC_EC_Ephemeral:
        *handle_num = 0;
        break;
#endif     // CC_EC_Ephemeral
#if      CC_VerifySignature == YES
    case TPM_CC_VerifySignature:
        *handle_num = 1;
        result = TPMI_DH_OBJECT_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size, FALSE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_VerifySignature
#if      CC_Sign == YES
    case TPM_CC_Sign:
        *handle_num = 1;
        result = TPMI_DH_OBJECT_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size, FALSE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_Sign
#if      CC_SetCommandCodeAuditStatus == YES
    case TPM_CC_SetCommandCodeAuditStatus:
        *handle_num = 1;
        result = TPMI_RH_PROVISION_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_SetCommandCodeAuditStatus
#if      CC_PCR_Extend == YES
    case TPM_CC_PCR_Extend:
        *handle_num = 1;
        result = TPMI_DH_PCR_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size, TRUE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_PCR_Extend
#if      CC_PCR_Event == YES
    case TPM_CC_PCR_Event:
        *handle_num = 1;
        result = TPMI_DH_PCR_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size, TRUE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_PCR_Event
#if      CC_PCR_Read == YES
    case TPM_CC_PCR_Read:
        *handle_num = 0;
        break;
#endif     // CC_PCR_Read
#if      CC_PCR_Allocate == YES
    case TPM_CC_PCR_Allocate:
        *handle_num = 1;
        result = TPMI_RH_PLATFORM_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_PCR_Allocate
#if      CC_PCR_SetAuthPolicy == YES
    case TPM_CC_PCR_SetAuthPolicy:
        *handle_num = 1;
        result = TPMI_RH_PLATFORM_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_PCR_SetAuthPolicy
#if      CC_PCR_SetAuthValue == YES
    case TPM_CC_PCR_SetAuthValue:
        *handle_num = 1;
        result = TPMI_DH_PCR_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size, FALSE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_PCR_SetAuthValue
#if      CC_PCR_Reset == YES
    case TPM_CC_PCR_Reset:
        *handle_num = 1;
        result = TPMI_DH_PCR_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size, FALSE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_PCR_Reset
#if      CC_PolicySigned == YES
    case TPM_CC_PolicySigned:
        *handle_num = 2;
        result = TPMI_DH_OBJECT_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size, FALSE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        result = TPMI_SH_POLICY_Unmarshal(&handles[1], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_2;
        break;
#endif     // CC_PolicySigned
#if      CC_PolicySecret == YES
    case TPM_CC_PolicySecret:
        *handle_num = 2;
        result = TPMI_DH_ENTITY_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size, TRUE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        result = TPMI_SH_POLICY_Unmarshal(&handles[1], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_2;
        break;
#endif     // CC_PolicySecret
#if      CC_PolicyTicket == YES
    case TPM_CC_PolicyTicket:
        *handle_num = 1;
        result = TPMI_SH_POLICY_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_PolicyTicket
#if      CC_PolicyOR == YES
    case TPM_CC_PolicyOR:
        *handle_num = 1;
        result = TPMI_SH_POLICY_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_PolicyOR
#if      CC_PolicyPCR == YES
    case TPM_CC_PolicyPCR:
        *handle_num = 1;
        result = TPMI_SH_POLICY_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_PolicyPCR
#if      CC_PolicyLocality == YES
    case TPM_CC_PolicyLocality:
        *handle_num = 1;
        result = TPMI_SH_POLICY_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_PolicyLocality
#if      CC_PolicyNV == YES
    case TPM_CC_PolicyNV:
        *handle_num = 3;
        result = TPMI_RH_NV_AUTH_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        result = TPMI_RH_NV_INDEX_Unmarshal(&handles[1], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_2;
        result = TPMI_SH_POLICY_Unmarshal(&handles[2], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_3;
        break;
#endif     // CC_PolicyNV
#if      CC_PolicyCounterTimer == YES
    case TPM_CC_PolicyCounterTimer:
        *handle_num = 1;
        result = TPMI_SH_POLICY_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_PolicyCounterTimer
#if      CC_PolicyCommandCode == YES
    case TPM_CC_PolicyCommandCode:
        *handle_num = 1;
        result = TPMI_SH_POLICY_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_PolicyCommandCode
#if      CC_PolicyPhysicalPresence == YES
    case TPM_CC_PolicyPhysicalPresence:
        *handle_num = 1;
        result = TPMI_SH_POLICY_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_PolicyPhysicalPresence
#if      CC_PolicyCpHash == YES
    case TPM_CC_PolicyCpHash:
        *handle_num = 1;
        result = TPMI_SH_POLICY_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_PolicyCpHash
#if      CC_PolicyNameHash == YES
    case TPM_CC_PolicyNameHash:
        *handle_num = 1;
        result = TPMI_SH_POLICY_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_PolicyNameHash
#if      CC_PolicyDuplicationSelect == YES
    case TPM_CC_PolicyDuplicationSelect:
        *handle_num = 1;
        result = TPMI_SH_POLICY_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_PolicyDuplicationSelect
#if      CC_PolicyAuthorize == YES
    case TPM_CC_PolicyAuthorize:
        *handle_num = 1;
        result = TPMI_SH_POLICY_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_PolicyAuthorize
#if      CC_PolicyAuthValue == YES
    case TPM_CC_PolicyAuthValue:
        *handle_num = 1;
        result = TPMI_SH_POLICY_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_PolicyAuthValue
#if      CC_PolicyPassword == YES
    case TPM_CC_PolicyPassword:
        *handle_num = 1;
        result = TPMI_SH_POLICY_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_PolicyPassword
#if      CC_PolicyGetDigest == YES
    case TPM_CC_PolicyGetDigest:
        *handle_num = 1;
        result = TPMI_SH_POLICY_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_PolicyGetDigest
#if      CC_CreatePrimary == YES
    case TPM_CC_CreatePrimary:
        *handle_num = 1;
        result = TPMI_RH_HIERARCHY_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size, TRUE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_CreatePrimary
#if      CC_HierarchyControl == YES
    case TPM_CC_HierarchyControl:
        *handle_num = 1;
        result = TPMI_RH_HIERARCHY_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size, FALSE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_HierarchyControl
#if      CC_SetPrimaryPolicy == YES
    case TPM_CC_SetPrimaryPolicy:
        *handle_num = 1;
        result = TPMI_RH_HIERARCHY_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size, FALSE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_SetPrimaryPolicy
#if      CC_ChangePPS == YES
    case TPM_CC_ChangePPS:
        *handle_num = 1;
        result = TPMI_RH_PLATFORM_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_ChangePPS
#if      CC_ChangeEPS == YES
    case TPM_CC_ChangeEPS:
        *handle_num = 1;
        result = TPMI_RH_PLATFORM_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_ChangeEPS
#if      CC_Clear == YES
    case TPM_CC_Clear:
        *handle_num = 1;
        result = TPMI_RH_CLEAR_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_Clear
#if      CC_ClearControl == YES
    case TPM_CC_ClearControl:
        *handle_num = 1;
        result = TPMI_RH_CLEAR_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_ClearControl
#if      CC_HierarchyChangeAuth == YES
    case TPM_CC_HierarchyChangeAuth:
        *handle_num = 1;
        result = TPMI_RH_HIERARCHY_AUTH_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_HierarchyChangeAuth
#if      CC_DictionaryAttackLockReset == YES
    case TPM_CC_DictionaryAttackLockReset:
        *handle_num = 1;
        result = TPMI_RH_LOCKOUT_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_DictionaryAttackLockReset
#if      CC_DictionaryAttackParameters == YES
    case TPM_CC_DictionaryAttackParameters:
        *handle_num = 1;
        result = TPMI_RH_LOCKOUT_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_DictionaryAttackParameters
#if      CC_PP_Commands == YES
    case TPM_CC_PP_Commands:
        *handle_num = 1;
        result = TPMI_RH_PLATFORM_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_PP_Commands
#if      CC_SetAlgorithmSet == YES
    case TPM_CC_SetAlgorithmSet:
        *handle_num = 1;
        result = TPMI_RH_PLATFORM_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_SetAlgorithmSet
#if      CC_FieldUpgradeStart == YES
    case TPM_CC_FieldUpgradeStart:
        *handle_num = 2;
        result = TPMI_RH_PLATFORM_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        result = TPMI_DH_OBJECT_Unmarshal(&handles[1], handle_buffer_start, buffer_remain_size, FALSE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_2;
        break;
#endif     // CC_FieldUpgradeStart
#if      CC_FieldUpgradeData == YES
    case TPM_CC_FieldUpgradeData:
        *handle_num = 0;
        break;
#endif     // CC_FieldUpgradeData
#if      CC_FirmwareRead == YES
    case TPM_CC_FirmwareRead:
        *handle_num = 0;
        break;
#endif     // CC_FirmwareRead
#if      CC_ContextSave == YES
    case TPM_CC_ContextSave:
        *handle_num = 1;
        result = TPMI_DH_CONTEXT_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_ContextSave
#if      CC_ContextLoad == YES
    case TPM_CC_ContextLoad:
        *handle_num = 0;
        break;
#endif     // CC_ContextLoad
#if      CC_FlushContext == YES
    case TPM_CC_FlushContext:
        *handle_num = 1;
        result = TPMI_DH_OBJECT_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size, FALSE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_FlushContext
#if      CC_EvictControl == YES
    case TPM_CC_EvictControl:
        *handle_num = 2;
        result = TPMI_RH_PROVISION_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        result = TPMI_DH_OBJECT_Unmarshal(&handles[1], handle_buffer_start, buffer_remain_size, FALSE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_2;
        break;
#endif     // CC_EvictControl
#if      CC_ReadClock == YES
    case TPM_CC_ReadClock:
        *handle_num = 0;
        break;
#endif     // CC_ReadClock
#if      CC_ClockSet == YES
    case TPM_CC_ClockSet:
        *handle_num = 1;
        result = TPMI_RH_PROVISION_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_ClockSet
#if      CC_ClockRateAdjust == YES
    case TPM_CC_ClockRateAdjust:
        *handle_num = 1;
        result = TPMI_RH_PROVISION_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_ClockRateAdjust
#if      CC_GetCapability == YES
    case TPM_CC_GetCapability:
        *handle_num = 0;
        break;
#endif     // CC_GetCapability
#if      CC_TestParms == YES
    case TPM_CC_TestParms:
        *handle_num = 0;
        break;
#endif     // CC_TestParms
#if      CC_NV_DefineSpace == YES
    case TPM_CC_NV_DefineSpace:
        *handle_num = 1;
        result = TPMI_RH_PROVISION_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_NV_DefineSpace
#if      CC_NV_UndefineSpace == YES
    case TPM_CC_NV_UndefineSpace:
        *handle_num = 2;
        result = TPMI_RH_PROVISION_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        result = TPMI_RH_NV_INDEX_Unmarshal(&handles[1], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_2;
        break;
#endif     // CC_NV_UndefineSpace
#if      CC_NV_UndefineSpaceSpecial == YES
    case TPM_CC_NV_UndefineSpaceSpecial:
        *handle_num = 2;
        result = TPMI_RH_NV_INDEX_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        result = TPMI_RH_PLATFORM_Unmarshal(&handles[1], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_2;
        break;
#endif     // CC_NV_UndefineSpaceSpecial
#if      CC_NV_ReadPublic == YES
    case TPM_CC_NV_ReadPublic:
        *handle_num = 1;
        result = TPMI_RH_NV_INDEX_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_NV_ReadPublic
#if      CC_NV_Write == YES
    case TPM_CC_NV_Write:
        *handle_num = 2;
        result = TPMI_RH_NV_AUTH_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        result = TPMI_RH_NV_INDEX_Unmarshal(&handles[1], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_2;
        break;
#endif     // CC_NV_Write
#if      CC_NV_Increment == YES
    case TPM_CC_NV_Increment:
        *handle_num = 2;
        result = TPMI_RH_NV_AUTH_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        result = TPMI_RH_NV_INDEX_Unmarshal(&handles[1], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_2;
        break;
#endif     // CC_NV_Increment
#if      CC_NV_Extend == YES
    case TPM_CC_NV_Extend:
        *handle_num = 2;
        result = TPMI_RH_NV_AUTH_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        result = TPMI_RH_NV_INDEX_Unmarshal(&handles[1], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_2;
        break;
#endif     // CC_NV_Extend
#if      CC_NV_SetBits == YES
    case TPM_CC_NV_SetBits:
        *handle_num = 2;
        result = TPMI_RH_NV_AUTH_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        result = TPMI_RH_NV_INDEX_Unmarshal(&handles[1], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_2;
        break;
#endif     // CC_NV_SetBits
#if      CC_NV_WriteLock == YES
    case TPM_CC_NV_WriteLock:
        *handle_num = 2;
        result = TPMI_RH_NV_AUTH_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        result = TPMI_RH_NV_INDEX_Unmarshal(&handles[1], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_2;
        break;
#endif     // CC_NV_WriteLock
#if      CC_NV_GlobalWriteLock == YES
    case TPM_CC_NV_GlobalWriteLock:
        *handle_num = 1;
        result = TPMI_RH_PROVISION_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_NV_GlobalWriteLock
#if      CC_NV_Read == YES
    case TPM_CC_NV_Read:
        *handle_num = 2;
        result = TPMI_RH_NV_AUTH_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        result = TPMI_RH_NV_INDEX_Unmarshal(&handles[1], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_2;
        break;
#endif     // CC_NV_Read
#if      CC_NV_ReadLock == YES
    case TPM_CC_NV_ReadLock:
        *handle_num = 2;
        result = TPMI_RH_NV_AUTH_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        result = TPMI_RH_NV_INDEX_Unmarshal(&handles[1], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_2;
        break;
#endif     // CC_NV_ReadLock
#if      CC_NV_ChangeAuth == YES
    case TPM_CC_NV_ChangeAuth:
        *handle_num = 1;
        result = TPMI_RH_NV_INDEX_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        break;
#endif     // CC_NV_ChangeAuth
#if      CC_NV_Certify == YES
    case TPM_CC_NV_Certify:
        *handle_num = 3;
        result = TPMI_DH_OBJECT_Unmarshal(&handles[0], handle_buffer_start, buffer_remain_size, TRUE);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_1;
        result = TPMI_RH_NV_AUTH_Unmarshal(&handles[1], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_2;
        result = TPMI_RH_NV_INDEX_Unmarshal(&handles[2], handle_buffer_start, buffer_remain_size);
        if(result != TPM_RC_SUCCESS) return result + TPM_RC_H + TPM_RC_3;
        break;
#endif     // CC_NV_Certify
    default:
        pAssert(FALSE);
        break;
    }
    return TPM_RC_SUCCESS;
}

TPM_RC
DevirtualizeTPM20Command(
    BYTE* pbCommand,
    UINT32 cbCommand,
    BYTE* pbResponse,
    UINT32 cbResponse,
    UINT32* pcbResponse,
    TPMI_YES_NO* pOperationComplete 
    )
{
    INT32 size = (INT32)cbCommand;
    INT32 sessionSize = 0;
    BYTE *handleBuffer = NULL;
    BYTE *sessionBuffer = NULL;
    BYTE *buffer = pbCommand;
    TPM_RC result = TPM_RC_SUCCESS;
    TPM_ST tag = 0;
    UINT32 commandSize = 0;
    TPM_CC commandCode = 0;
    UINT32 handleNum = 0;
    TPM_HANDLE handles[MAX_HANDLE_NUM];
    const BYTE flushResponse[] = {0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00};

    // By default call the TPM after this call
    *pOperationComplete = NO;

    result = TPMI_ST_COMMAND_TAG_Unmarshal(&tag, &buffer, &size);
    if(result != TPM_RC_SUCCESS)
        goto Cleanup;
    result = UINT32_Unmarshal(&commandSize, &buffer, &size);
    if(result != TPM_RC_SUCCESS)
        goto Cleanup;
    if(cbCommand != (size + sizeof(tag) + sizeof(commandSize)))
    {
        result = TPM_RC_SIZE;
        goto Cleanup;
    }
    result = TPM_CC_Unmarshal(&commandCode, &buffer, &size);
    if(result != TPM_RC_SUCCESS)
        goto Cleanup;
    handleBuffer = buffer;
    result = ParseHandleBuffer(commandCode, &buffer, &size, handles, &handleNum);
    if(result != TPM_RC_SUCCESS)
        goto Cleanup;

    // If the command is authorized prepare for sessionauthorization
    if(tag == TPM_ST_SESSIONS)
    {
        result = UINT32_Unmarshal((UINT32*)&sessionSize, &buffer, &size);
        if(result != TPM_RC_SUCCESS)
            goto Cleanup;
        sessionBuffer = buffer;
    }

    // Translate the object handles in the command to virtual
    for(UINT32 n = 0; n < handleNum; n++)
    {
        PCONTEXT_TABLE_OBJECT object = NULL;

        // Only devirtualize transient handles
        if((handles[n] & 0xff000000) != HR_TRANSIENT)
        {
            handleBuffer += sizeof(TPMI_DH_OBJECT);
            continue;
        }

        // Look up the virtual handle in the table
        object = &g_objectTable[FindByVHandle(0x00ffffff - (handles[n] & 0x00ffffff))];

        // Check if the object is currently loaded
        if(object->physicalHdl == OBJECT_NOT_LOADED)
        {
            // If the object is not loaded we can silently drop it from the table and don't have to bother the TPM
            if(commandCode == TPM_CC_FlushContext)
            {
                DropFromTable(object);
                g_numObjectsLoaded--;
                MemoryCopy(pbResponse, flushResponse, sizeof(flushResponse), cbResponse);
                *pcbResponse = sizeof(flushResponse);
                *pOperationComplete = YES;
                goto Cleanup;
            }

            if(g_numObjectsLoaded >= MAX_KEYSLOTS)
            {
                // TPM is full - Drop the oldest object
                PCONTEXT_TABLE_OBJECT dropMe = &g_objectTable[FindOldestLoaded(g_objectTable, MAX_TABLE_SIZE, TPM_HT_TRANSIENT)];

                // Kick the object out
                if((result = FlushObject(dropMe)) != TPM_RC_SUCCESS)
                {
                    goto Cleanup;
                }
                g_numObjectsLoaded--;
            }

            // Swap the required object in
            if((result = SwapObjectIn(object)) != TPM_RC_SUCCESS)
            {
                goto Cleanup;
            }
            g_numObjectsLoaded++;
        }

        // Mark the object as used last
        object->lastUsed = g_objectUsageCounter++;

        // overwrite the virtual handle with the physical handle in the command
        TPMI_DH_OBJECT_Marshal(&object->physicalHdl, &handleBuffer, NULL);
    }

    // If we are loading and object, make sure we have a slot available
    if(((commandCode == TPM_CC_Load) ||
        (commandCode == TPM_CC_LoadExternal)) &&
        (g_numObjectsLoaded >= MAX_KEYSLOTS))
    {
        UINT32 index = FindOldestLoaded(g_objectTable, MAX_TABLE_SIZE, TPM_HT_TRANSIENT);
        PCONTEXT_TABLE_OBJECT dropMe = &g_objectTable[index];
        if((result = FlushObject(dropMe)) != TPM_RC_SUCCESS)
        {
            goto Cleanup;
        }
        g_numObjectsLoaded--;
    }

    // If we are starting a new session, make sure we have a slot available
    if((commandCode == TPM_CC_StartAuthSession) &&
        (g_numSessionsLoaded >= MAX_SESSIONSLOTS))
    {
        UINT32 index = FindOldestLoaded(g_objectTable, MAX_TABLE_SIZE, TPM_HT_HMAC_SESSION);
        PCONTEXT_TABLE_OBJECT dropMe = &g_objectTable[index];
        if((result = SwapObjectOut(dropMe)) != TPM_RC_SUCCESS)
        {
            goto Cleanup;
        }
        dropMe->physicalHdl = OBJECT_NOT_LOADED;
        g_numSessionsLoaded--;
    }

    if(commandCode == TPM_CC_GetCapability)
    {
        TPM_CAP capability = 0;
        UINT32 property = 0;
        UINT32 propertyCount = 0;
        TPMI_YES_NO moreData = NO;
        TPMS_CAPABILITY_DATA capData = {0};
        UINT32 numberOfHandles = 0;
        UINT32 addCount = 0;

        result = TPM_CAP_Unmarshal(&capability, &buffer, &size);
        if(result != TPM_RC_SUCCESS) return result;
        result = UINT32_Unmarshal(&property, &buffer, &size);
        if(result != TPM_RC_SUCCESS) return result;
        result = UINT32_Unmarshal(&propertyCount, &buffer, &size);
        if(result != TPM_RC_SUCCESS) return result;

        // We will only answer the transiend handle request
        if((capability != TPM_CAP_HANDLES) ||
           (((property & 0xff000000) != HR_TRANSIENT) &&
            ((property & 0xff000000) != HR_HMAC_SESSION) && 
            ((property & 0xff000000) != HR_POLICY_SESSION)))
        {
            goto Cleanup;
        }

        // Count the vHandles
        for(UINT32 n = 0; n < MAX_TABLE_SIZE; n++)
        {
            if(g_objectTable[n].lastUsed != 0L)
            {
                numberOfHandles++;
            }
        }

        // Build the vHandle table
        capData.capability = TPM_CAP_HANDLES;
        for(UINT32 n = MAX_TABLE_SIZE; n > 0; n--)
        {
            TPM_RH vHandle = (property & 0xff000000) | (0x00FFFFFF - (n - 1));
            if((property <= vHandle) &&
               (g_objectTable[n - 1].handleType == ((property & 0xff000000) >> 24)) &&
               (g_objectTable[n - 1].lastUsed != 0L))
            {
                if(addCount >= min(numberOfHandles, propertyCount))
                {
                    moreData = YES;
                    break;
                }
                capData.data.handles.handle[addCount++] = vHandle;
            }
        }
        capData.data.handles.count = addCount;

        // Format the response
        MemoryCopy(pbResponse, flushResponse, sizeof(flushResponse), cbResponse);
        *pcbResponse = sizeof(flushResponse);
        buffer = &pbResponse[sizeof(flushResponse)];
        size = cbResponse - sizeof(flushResponse);
        *pcbResponse += TPMI_YES_NO_Marshal(&moreData, &buffer, &size);
        *pcbResponse += TPMS_CAPABILITY_DATA_Marshal(&capData, &buffer, &size);
        buffer = &pbResponse[sizeof(TPM_ST)];
        size = cbResponse - sizeof(TPM_ST);
        UINT32_Marshal(pcbResponse, &buffer, &size);
        *pOperationComplete = YES;
        goto Cleanup;
    }

    // Session Virtualization
    if((tag == TPM_ST_SESSIONS) && (sessionSize != 0) && (sessionBuffer != NULL))
    {
        while(sessionSize > 0)
        {
            BYTE* handlePtr = sessionBuffer;
            TPM_HANDLE sessionHdl = 0;
            TPM2B_NONCE nonceCaller = {0};
            TPMA_SESSION attributes = {0};
            TPM2B_AUTH authValue = {0};
            PCONTEXT_TABLE_OBJECT object = NULL;

            // First parameter: Session handle.
            result = TPM_HANDLE_Unmarshal(&sessionHdl, &sessionBuffer, &sessionSize);
            if(result != TPM_RC_SUCCESS)return result;
            // Second parameter: Nonce.
            result = TPM2B_NONCE_Unmarshal(&nonceCaller, &sessionBuffer, &sessionSize);
            if(result != TPM_RC_SUCCESS) return result;
            // Third parameter: sessionAttributes.
            result = TPMA_SESSION_Unmarshal(&attributes, &sessionBuffer, &sessionSize);
            if(result != TPM_RC_SUCCESS) return result;
            // Fourth parameter: authValue (PW or HMAC).
            result = TPM2B_AUTH_Unmarshal(&authValue, &sessionBuffer, &sessionSize);
            if(result != TPM_RC_SUCCESS) return result;

            if(((sessionHdl & 0xFF000000) != HR_HMAC_SESSION) &&
                ((sessionHdl & 0xFF000000) != HR_POLICY_SESSION))
            {
                // We only virtualize HMAC and Policy Sessions and nor Password
                continue;
            }

            // Devirtualize the vHandle to a pHandle
            object = &g_objectTable[FindByVHandle(0x00FFFFFF - (sessionHdl & 0x00FFFFFF))];

            // Check if the object is currently loaded
            if(object->physicalHdl == OBJECT_NOT_LOADED)
            {
                if(g_numSessionsLoaded >= MAX_SESSIONSLOTS)
                {
                    // TPM is full - Drop the oldest session
                    PCONTEXT_TABLE_OBJECT dropMe = &g_objectTable[FindOldestLoaded(g_objectTable, MAX_TABLE_SIZE, TPM_HT_HMAC_SESSION)];

                    // Unload the session
                    if((result = SwapObjectOut(dropMe)) != TPM_RC_SUCCESS)
                    {
                        goto Cleanup;
                    }
                    dropMe->physicalHdl = OBJECT_NOT_LOADED;
                    g_numSessionsLoaded--;
                }

                // Swap the required session in
                if((result = SwapObjectIn(object)) != TPM_RC_SUCCESS)
                {
                    goto Cleanup;
                }
                g_numSessionsLoaded++;
            }

            // Mark the session as used last
            object->lastUsed = g_sessionUsageCounter++;

            // Overwrite the pHandle in the session
            TPM_HANDLE_Marshal(&object->physicalHdl, &handlePtr, NULL);
        }
    }

Cleanup:
    return result;
}

TPM_RC
VirtualizeTPM20Response(
    BYTE* pbCommand,
    UINT32 cbCommand,
    BYTE* pbResponse,
    UINT32 cbResponse,
    UINT32* pcbResponse
)
{
    INT32 size = 0;
    INT32 sessionSize = 0;
    BYTE *handleBuffer = NULL;
    BYTE *sessionBuffer = NULL;
    BYTE *buffer = NULL;
    TPM_RC result = TPM_RC_SUCCESS;
    TPM_CC commandCode = 0;
    UINT32 handleNum = 0;
    TPM_HANDLE handles[MAX_HANDLE_NUM];
    TPM_ST tag = 0;
    UINT32 responseSize = 0;
    TPM_RC responseCode = 0;

    // Read the command header again
    size = (INT32)cbCommand;
    buffer = pbCommand;
    result = TPMI_ST_COMMAND_TAG_Unmarshal(&tag, &buffer, &size);
    if(result != TPM_RC_SUCCESS) goto Cleanup;
    result = UINT32_Unmarshal(&responseSize, &buffer, &size);
    if(result != TPM_RC_SUCCESS) goto Cleanup;
    if(responseSize != cbCommand)
    {
        result = TPM_RC_SIZE;
        goto Cleanup;
    }
    result = TPM_CC_Unmarshal(&commandCode, &buffer, &size);
    if(result != TPM_RC_SUCCESS) goto Cleanup;
    handleBuffer = buffer;
    result = ParseHandleBuffer(commandCode, &buffer, &size, handles, &handleNum);
    if(result != TPM_RC_SUCCESS) goto Cleanup;
    if(tag == TPM_ST_SESSIONS)
    {
        result = UINT32_Unmarshal((UINT32*)&sessionSize, &buffer, &size);
        if(result != TPM_RC_SUCCESS)
            goto Cleanup;
        sessionBuffer = buffer;
    }

    // Read the response header
    size = (INT32)cbResponse;
    buffer = pbResponse;
    result = TPMI_ST_COMMAND_TAG_Unmarshal(&tag, &buffer, &size);
    if(result != TPM_RC_SUCCESS) goto Cleanup;
    result = UINT32_Unmarshal(&responseSize, &buffer, &size);
    if(result != TPM_RC_SUCCESS) goto Cleanup;
    if(responseSize != *pcbResponse)
    {
        result = TPM_RC_SIZE;
        goto Cleanup;
    }
    result = UINT32_Unmarshal(&responseCode, &buffer, &size);
    if(result != TPM_RC_SUCCESS) return result;
    if(responseCode != TPM_RC_SUCCESS) return TPM_RC_SUCCESS;

    // Remove the flushed object from the table
    if((commandCode == TPM_CC_FlushContext) && (handleNum == 1))
    {
        PCONTEXT_TABLE_OBJECT object = &g_objectTable[FindByPHandle(g_objectTable, MAX_TABLE_SIZE, handles[0])];
        if(object->handleType == TPM_HT_TRANSIENT) g_numObjectsLoaded--;
        else if (object->handleType == TPM_HT_HMAC_SESSION) g_numSessionsLoaded--;
        DropFromTable(object);
        goto Cleanup;
    }

    // We have to see if we asked for sessions to be closed
    if((tag == TPM_ST_SESSIONS) && (sessionSize != 0) && (sessionBuffer != NULL))
    {
        while(sessionSize > 0)
        {
            TPM_HANDLE sessionHdl = 0;
            TPM2B_NONCE nonceCaller = {0};
            TPMA_SESSION attributes = {0};
            TPM2B_AUTH authValue = {0};

            // First parameter: Session handle.
            result = TPM_HANDLE_Unmarshal(&sessionHdl, &sessionBuffer, &sessionSize);
            if(result != TPM_RC_SUCCESS)return result;
            // Second parameter: Nonce.
            result = TPM2B_NONCE_Unmarshal(&nonceCaller, &sessionBuffer, &sessionSize);
            if(result != TPM_RC_SUCCESS) return result;
            // Third parameter: sessionAttributes.
            result = TPMA_SESSION_Unmarshal(&attributes, &sessionBuffer, &sessionSize);
            if(result != TPM_RC_SUCCESS) return result;
            // Fourth parameter: authValue (PW or HMAC).
            result = TPM2B_AUTH_Unmarshal(&authValue, &sessionBuffer, &sessionSize);
            if(result != TPM_RC_SUCCESS) return result;

            // If the session was supposed to be closed, look it up and drop the row from the table
            if((((sessionHdl & 0xFF000000) == HR_HMAC_SESSION) ||
                ((sessionHdl & 0xFF000000) == HR_POLICY_SESSION)) &&
               (attributes.continueSession == NO))
            {
                PCONTEXT_TABLE_OBJECT object = &g_objectTable[FindByPHandle(g_objectTable, MAX_TABLE_SIZE, sessionHdl)];
                DropFromTable(object);
                g_numSessionsLoaded--;
            }
        }
    }

    // If this response has no return handle, we got nothing to do
    if((!IsHandleInResponse(commandCode)) &&
        (commandCode != TPM_CC_GetCapability))
    {
        goto Cleanup;
    }

    // These are the only commands we should be processing
    pAssert((commandCode == TPM_CC_Load) ||
            (commandCode == TPM_CC_LoadExternal) ||
            (commandCode == TPM_CC_GetCapability) ||
            (commandCode == TPM_CC_StartAuthSession));

    // Read the physical return handle from TPM_CC_Load*
    if((commandCode == TPM_CC_Load) ||
       (commandCode == TPM_CC_LoadExternal))
    {
        BYTE *handleBuffer = buffer;
        TPM_RH vHandle = GetNextFreeVHandle(g_objectTable, MAX_TABLE_SIZE);
        PCONTEXT_TABLE_OBJECT newObject = &g_objectTable[vHandle];
        newObject->lastUsed = g_objectUsageCounter++;
        newObject->handleType = TPM_HT_TRANSIENT;
        result = TPM_HANDLE_Unmarshal(&newObject->physicalHdl, &buffer, &size);
        if(result != TPM_RC_SUCCESS) return result;
        if((result = SwapObjectOut(newObject)) != TPM_RC_SUCCESS) return result;
        vHandle = (newObject->physicalHdl & 0xff000000) + (0x00ffffff - vHandle);
        TPM_HANDLE_Marshal(&vHandle, &handleBuffer, NULL);
        g_numObjectsLoaded++;
    }
    else if(commandCode == TPM_CC_GetCapability)
    {
        //ToDo Get handle table
    }
    else if(commandCode == TPM_CC_StartAuthSession)
    {
        BYTE *handleBuffer = buffer;
        TPM_RH vHandle = GetNextFreeVHandle(g_objectTable, MAX_TABLE_SIZE);
        PCONTEXT_TABLE_OBJECT newObject = &g_objectTable[vHandle];
        newObject->lastUsed = g_objectUsageCounter++;
        newObject->handleType = TPM_HT_HMAC_SESSION;
        result = TPM_HANDLE_Unmarshal(&newObject->physicalHdl, &buffer, &size);
        if(result != TPM_RC_SUCCESS) return result;
        vHandle = (newObject->physicalHdl & 0xff000000) + (0x00ffffff - vHandle);
        TPM_HANDLE_Marshal(&vHandle, &handleBuffer, NULL);
        g_numSessionsLoaded++;
    }

Cleanup:
    return result;
}
