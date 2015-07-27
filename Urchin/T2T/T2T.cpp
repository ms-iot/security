/*
TPM2Tool

Copyright (c) Microsoft Corporation

All rights reserved.

MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "stdafx.h"

#define ALLOCATEOBJECTMEMORY(__OBJTYPE, __VARNAME) \
if ((__VARNAME = (__OBJTYPE*)malloc(sizeof(__OBJTYPE))) == NULL) \
{ \
    result = TPM_RC_MEMORY; \
    goto Cleanup; \
} \
    memset(__VARNAME, 0x00, sizeof(__OBJTYPE)); \

#define FREEOBJECTMEMORY(__VARNAME) \
if (__VARNAME != NULL) \
{ \
    free(__VARNAME); \
    __VARNAME = NULL; \
} \

TPM_DEVICE_INFO deviceInfo = { 0 };
TBS_CONTEXT_PARAMS2 context = { TBS_CONTEXT_VERSION_TWO, { 0, 0, 1 } };

TRANSLATE_TABLE AlgorithmNameTable[] =
{
    { (TPM_ALG_ID)(0x0001), L"TPM_ALG_RSA" },
    { (TPM_ALG_ID)(0x0004), L"TPM_ALG_SHA" },
    { (TPM_ALG_ID)(0x0004), L"TPM_ALG_SHA1" },
    { (TPM_ALG_ID)(0x0005), L"TPM_ALG_HMAC" },
    { (TPM_ALG_ID)(0x0006), L"TPM_ALG_AES" },
    { (TPM_ALG_ID)(0x0007), L"TPM_ALG_MGF1" },
    { (TPM_ALG_ID)(0x0008), L"TPM_ALG_KEYEDHASH" },
    { (TPM_ALG_ID)(0x000A), L"TPM_ALG_XOR" },
    { (TPM_ALG_ID)(0x000B), L"TPM_ALG_SHA256" },
    { (TPM_ALG_ID)(0x000C), L"TPM_ALG_SHA384" },
    { (TPM_ALG_ID)(0x000D), L"TPM_ALG_SHA512" },
    { (TPM_ALG_ID)(0x0010), L"TPM_ALG_NULL" },
    { (TPM_ALG_ID)(0x0012), L"TPM_ALG_SM3_256" },
    { (TPM_ALG_ID)(0x0013), L"TPM_ALG_SM4" },
    { (TPM_ALG_ID)(0x0014), L"TPM_ALG_RSASSA" },
    { (TPM_ALG_ID)(0x0015), L"TPM_ALG_RSAES" },
    { (TPM_ALG_ID)(0x0016), L"TPM_ALG_RSAPSS" },
    { (TPM_ALG_ID)(0x0017), L"TPM_ALG_OAEP" },
    { (TPM_ALG_ID)(0x0018), L"TPM_ALG_ECDSA" },
    { (TPM_ALG_ID)(0x0019), L"TPM_ALG_ECDH" },
    { (TPM_ALG_ID)(0x001A), L"TPM_ALG_ECDAA" },
    { (TPM_ALG_ID)(0x001B), L"TPM_ALG_SM2" },
    { (TPM_ALG_ID)(0x001C), L"TPM_ALG_ECSCHNORR" },
    { (TPM_ALG_ID)(0x001D), L"TPM_ALG_ECMQV" },
    { (TPM_ALG_ID)(0x0020), L"TPM_ALG_KDF1_SP800_56a" },
    { (TPM_ALG_ID)(0x0021), L"TPM_ALG_KDF2" },
    { (TPM_ALG_ID)(0x0022), L"TPM_ALG_KDF1_SP800_108" },
    { (TPM_ALG_ID)(0x0023), L"TPM_ALG_ECC" },
    { (TPM_ALG_ID)(0x0025), L"TPM_ALG_SYMCIPHER" },
    { (TPM_ALG_ID)(0x0040), L"TPM_ALG_CTR" },
    { (TPM_ALG_ID)(0x0041), L"TPM_ALG_OFB" },
    { (TPM_ALG_ID)(0x0042), L"TPM_ALG_CBC" },
    { (TPM_ALG_ID)(0x0043), L"TPM_ALG_CFB" },
    { (TPM_ALG_ID)(0x0044), L"TPM_ALG_ECB" },
    { 0xffffffff, L"UNKNOWN" }
};

TRANSLATE_TABLE CurveNameTable[] =
{
    { TPM_ECC_NONE, L"TPM_ECC_NONE" },
    { TPM_ECC_NIST_P192, L"TPM_ECC_NIST_P192" },
    { TPM_ECC_NIST_P224, L"TPM_ECC_NIST_P224" },
    { TPM_ECC_NIST_P256, L"TPM_ECC_NIST_P256" },
    { TPM_ECC_NIST_P384, L"TPM_ECC_NIST_P384" },
    { TPM_ECC_NIST_P521, L"TPM_ECC_NIST_P521" },
    { TPM_ECC_BN_P256, L"TPM_ECC_BN_P256" },
    { TPM_ECC_BN_P638, L"TPM_ECC_BN_P638" },
    { TPM_ECC_SM2_P256, L"TPM_ECC_SM2_P256" },
    { 0xffffffff, L"UNKNOWN" }
};

TRANSLATE_TABLE CommandNameTable[] =
{
    { TPM_CC_NV_UndefineSpaceSpecial, L"TPM_CC_NV_UndefineSpaceSpecial" },
    { TPM_CC_EvictControl, L"TPM_CC_EvictControl" },
    { TPM_CC_HierarchyControl, L"TPM_CC_HierarchyControl" },
    { TPM_CC_NV_UndefineSpace, L"TPM_CC_NV_UndefineSpace" },
    { TPM_CC_ChangeEPS, L"TPM_CC_ChangeEPS" },
    { TPM_CC_ChangePPS, L"TPM_CC_ChangePPS" },
    { TPM_CC_Clear, L"TPM_CC_Clear" },
    { TPM_CC_ClearControl, L"TPM_CC_ClearControl" },
    { TPM_CC_ClockSet, L"TPM_CC_ClockSet" },
    { TPM_CC_HierarchyChangeAuth, L"TPM_CC_HierarchyChangeAuth" },
    { TPM_CC_NV_DefineSpace, L"TPM_CC_NV_DefineSpace" },
    { TPM_CC_PCR_Allocate, L"TPM_CC_PCR_Allocate" },
    { TPM_CC_PCR_SetAuthPolicy, L"TPM_CC_PCR_SetAuthPolicy" },
    { TPM_CC_PP_Commands, L"TPM_CC_PP_Commands" },
    { TPM_CC_SetPrimaryPolicy, L"TPM_CC_SetPrimaryPolicy" },
    { TPM_CC_FieldUpgradeStart, L"TPM_CC_FieldUpgradeStart" },
    { TPM_CC_ClockRateAdjust, L"TPM_CC_ClockRateAdjust" },
    { TPM_CC_CreatePrimary, L"TPM_CC_CreatePrimary" },
    { TPM_CC_NV_GlobalWriteLock, L"TPM_CC_NV_GlobalWriteLock" },
    { TPM_CC_PP_LAST, L"TPM_CC_PP_LAST" },
    { TPM_CC_GetCommandAuditDigest, L"TPM_CC_GetCommandAuditDigest" },
    { TPM_CC_NV_Increment, L"TPM_CC_NV_Increment" },
    { TPM_CC_NV_SetBits, L"TPM_CC_NV_SetBits" },
    { TPM_CC_NV_Extend, L"TPM_CC_NV_Extend" },
    { TPM_CC_NV_Write, L"TPM_CC_NV_Write" },
    { TPM_CC_NV_WriteLock, L"TPM_CC_NV_WriteLock" },
    { TPM_CC_DictionaryAttackLockReset, L"TPM_CC_DictionaryAttackLockReset" },
    { TPM_CC_DictionaryAttackParameters, L"TPM_CC_DictionaryAttackParameters" },
    { TPM_CC_NV_ChangeAuth, L"TPM_CC_NV_ChangeAuth" },
    { TPM_CC_PCR_Event, L"TPM_CC_PCR_Event" },
    { TPM_CC_PCR_Reset, L"TPM_CC_PCR_Reset" },
    { TPM_CC_SequenceComplete, L"TPM_CC_SequenceComplete" },
    { TPM_CC_SetAlgorithmSet, L"TPM_CC_SetAlgorithmSet" },
    { TPM_CC_SetCommandCodeAuditStatus, L"TPM_CC_SetCommandCodeAuditStatus" },
    { TPM_CC_FieldUpgradeData, L"TPM_CC_FieldUpgradeData" },
    { TPM_CC_IncrementalSelfTest, L"TPM_CC_IncrementalSelfTest" },
    { TPM_CC_SelfTest, L"TPM_CC_SelfTest" },
    { TPM_CC_Startup, L"TPM_CC_Startup" },
    { TPM_CC_Shutdown, L"TPM_CC_Shutdown" },
    { TPM_CC_StirRandom, L"TPM_CC_StirRandom" },
    { TPM_CC_ActivateCredential, L"TPM_CC_ActivateCredential" },
    { TPM_CC_Certify, L"TPM_CC_Certify" },
    { TPM_CC_PolicyNV, L"TPM_CC_PolicyNV" },
    { TPM_CC_CertifyCreation, L"TPM_CC_CertifyCreation" },
    { TPM_CC_Duplicate, L"TPM_CC_Duplicate" },
    { TPM_CC_GetTime, L"TPM_CC_GetTime" },
    { TPM_CC_GetSessionAuditDigest, L"TPM_CC_GetSessionAuditDigest" },
    { TPM_CC_NV_Read, L"TPM_CC_NV_Read" },
    { TPM_CC_NV_ReadLock, L"TPM_CC_NV_ReadLock" },
    { TPM_CC_ObjectChangeAuth, L"TPM_CC_ObjectChangeAuth" },
    { TPM_CC_PolicySecret, L"TPM_CC_PolicySecret" },
    { TPM_CC_Rewrap, L"TPM_CC_Rewrap" },
    { TPM_CC_Create, L"TPM_CC_Create" },
    { TPM_CC_ECDH_ZGen, L"TPM_CC_ECDH_ZGen" },
    { TPM_CC_HMAC, L"TPM_CC_HMAC" },
    { TPM_CC_Import, L"TPM_CC_Import" },
    { TPM_CC_Load, L"TPM_CC_Load" },
    { TPM_CC_Quote, L"TPM_CC_Quote" },
    { TPM_CC_RSA_Decrypt, L"TPM_CC_RSA_Decrypt" },
    { TPM_CC_HMAC_Start, L"TPM_CC_HMAC_Start" },
    { TPM_CC_SequenceUpdate, L"TPM_CC_SequenceUpdate" },
    { TPM_CC_Sign, L"TPM_CC_Sign" },
    { TPM_CC_Unseal, L"TPM_CC_Unseal" },
    { TPM_CC_PolicySigned, L"TPM_CC_PolicySigned" },
    { TPM_CC_ContextLoad, L"TPM_CC_ContextLoad" },
    { TPM_CC_ContextSave, L"TPM_CC_ContextSave" },
    { TPM_CC_ECDH_KeyGen, L"TPM_CC_ECDH_KeyGen" },
    { TPM_CC_EncryptDecrypt, L"TPM_CC_EncryptDecrypt" },
    { TPM_CC_FlushContext, L"TPM_CC_FlushContext" },
    { TPM_CC_LoadExternal, L"TPM_CC_LoadExternal" },
    { TPM_CC_MakeCredential, L"TPM_CC_MakeCredential" },
    { TPM_CC_NV_ReadPublic, L"TPM_CC_NV_ReadPublic" },
    { TPM_CC_PolicyAuthorize, L"TPM_CC_PolicyAuthorize" },
    { TPM_CC_PolicyAuthValue, L"TPM_CC_PolicyAuthValue" },
    { TPM_CC_PolicyCommandCode, L"TPM_CC_PolicyCommandCode" },
    { TPM_CC_PolicyCounterTimer, L"TPM_CC_PolicyCounterTimer" },
    { TPM_CC_PolicyCpHash, L"TPM_CC_PolicyCpHash" },
    { TPM_CC_PolicyLocality, L"TPM_CC_PolicyLocality" },
    { TPM_CC_PolicyNameHash, L"TPM_CC_PolicyNameHash" },
    { TPM_CC_PolicyOR, L"TPM_CC_PolicyOR" },
    { TPM_CC_PolicyTicket, L"TPM_CC_PolicyTicket" },
    { TPM_CC_ReadPublic, L"TPM_CC_ReadPublic" },
    { TPM_CC_RSA_Encrypt, L"TPM_CC_RSA_Encrypt" },
    { TPM_CC_StartAuthSession, L"TPM_CC_StartAuthSession" },
    { TPM_CC_VerifySignature, L"TPM_CC_VerifySignature" },
    { TPM_CC_ECC_Parameters, L"TPM_CC_ECC_Parameters" },
    { TPM_CC_FirmwareRead, L"TPM_CC_FirmwareRead" },
    { TPM_CC_GetCapability, L"TPM_CC_GetCapability" },
    { TPM_CC_GetRandom, L"TPM_CC_GetRandom" },
    { TPM_CC_GetTestResult, L"TPM_CC_GetTestResult" },
    { TPM_CC_Hash, L"TPM_CC_Hash" },
    { TPM_CC_PCR_Read, L"TPM_CC_PCR_Read" },
    { TPM_CC_PolicyPCR, L"TPM_CC_PolicyPCR" },
    { TPM_CC_PolicyRestart, L"TPM_CC_PolicyRestart" },
    { TPM_CC_ReadClock, L"TPM_CC_ReadClock" },
    { TPM_CC_PCR_Extend, L"TPM_CC_PCR_Extend" },
    { TPM_CC_PCR_SetAuthValue, L"TPM_CC_PCR_SetAuthValue" },
    { TPM_CC_NV_Certify, L"TPM_CC_NV_Certify" },
    { TPM_CC_EventSequenceComplete, L"TPM_CC_EventSequenceComplete" },
    { TPM_CC_HashSequenceStart, L"TPM_CC_HashSequenceStart" },
    { TPM_CC_PolicyPhysicalPresence, L"TPM_CC_PolicyPhysicalPresence" },
    { TPM_CC_PolicyDuplicationSelect, L"TPM_CC_PolicyDuplicationSelect" },
    { TPM_CC_PolicyGetDigest, L"TPM_CC_PolicyGetDigest" },
    { TPM_CC_TestParms, L"TPM_CC_TestParms" },
    { TPM_CC_Commit, L"TPM_CC_Commit" },
    { TPM_CC_PolicyPassword, L"TPM_CC_PolicyPassword" },
    { TPM_CC_ZGen_2Phase, L"TPM_CC_ZGen_2Phase" },
    { TPM_CC_EC_Ephemeral, L"TPM_CC_EC_Ephemeral" },
    { 0xffffffff, L"UNKNOWN" }
};

TRANSLATE_TABLE FixedCapabilityNameTable[] =
{
    { TPM_PT_FAMILY_INDICATOR, L"TPM_PT_FAMILY_INDICATOR" },
    { TPM_PT_LEVEL, L"TPM_PT_LEVEL" },
    { TPM_PT_REVISION, L"TPM_PT_REVISION" },
    { TPM_PT_DAY_OF_YEAR, L"TPM_PT_DAY_OF_YEAR" },
    { TPM_PT_YEAR, L"TPM_PT_YEAR" },
    { TPM_PT_MANUFACTURER, L"TPM_PT_MANUFACTURER" },
    { TPM_PT_VENDOR_STRING_1, L"TPM_PT_VENDOR_STRING_1" },
    { TPM_PT_VENDOR_STRING_2, L"TPM_PT_VENDOR_STRING_2" },
    { TPM_PT_VENDOR_STRING_3, L"TPM_PT_VENDOR_STRING_3" },
    { TPM_PT_VENDOR_STRING_4, L"TPM_PT_VENDOR_STRING_4" },
    { TPM_PT_VENDOR_TPM_TYPE, L"TPM_PT_VENDOR_TPM_TYPE" },
    { TPM_PT_FIRMWARE_VERSION_1, L"TPM_PT_FIRMWARE_VERSION_1" },
    { TPM_PT_FIRMWARE_VERSION_2, L"TPM_PT_FIRMWARE_VERSION_2" },
    { TPM_PT_INPUT_BUFFER, L"TPM_PT_INPUT_BUFFER" },
    { TPM_PT_HR_TRANSIENT_MIN, L"TPM_PT_HR_TRANSIENT_MIN" },
    { TPM_PT_HR_PERSISTENT_MIN, L"TPM_PT_HR_PERSISTENT_MIN" },
    { TPM_PT_HR_LOADED_MIN, L"TPM_PT_HR_LOADED_MIN" },
    { TPM_PT_ACTIVE_SESSIONS_MAX, L"TPM_PT_ACTIVE_SESSIONS_MAX" },
    { TPM_PT_PCR_COUNT, L"TPM_PT_PCR_COUNT" },
    { TPM_PT_PCR_SELECT_MIN, L"TPM_PT_PCR_SELECT_MIN" },
    { TPM_PT_CONTEXT_GAP_MAX, L"TPM_PT_CONTEXT_GAP_MAX" },
    { TPM_PT_NV_COUNTERS_MAX, L"TPM_PT_NV_COUNTERS_MAX" },
    { TPM_PT_NV_INDEX_MAX, L"TPM_PT_NV_INDEX_MAX" },
    { TPM_PT_MEMORY, L"TPM_PT_MEMORY" },
    { TPM_PT_CLOCK_UPDATE, L"TPM_PT_CLOCK_UPDATE" },
    { TPM_PT_CONTEXT_HASH, L"TPM_PT_CONTEXT_HASH" },
    { TPM_PT_CONTEXT_SYM, L"TPM_PT_CONTEXT_SYM" },
    { TPM_PT_CONTEXT_SYM_SIZE, L"TPM_PT_CONTEXT_SYM_SIZE" },
    { TPM_PT_ORDERLY_COUNT, L"TPM_PT_ORDERLY_COUNT" },
    { TPM_PT_MAX_COMMAND_SIZE, L"TPM_PT_MAX_COMMAND_SIZE" },
    { TPM_PT_MAX_RESPONSE_SIZE, L"TPM_PT_MAX_RESPONSE_SIZE" },
    { TPM_PT_MAX_DIGEST, L"TPM_PT_MAX_DIGEST" },
    { TPM_PT_MAX_OBJECT_CONTEXT, L"TPM_PT_MAX_OBJECT_CONTEXT" },
    { TPM_PT_MAX_SESSION_CONTEXT, L"TPM_PT_MAX_SESSION_CONTEXT" },
    { TPM_PT_PS_FAMILY_INDICATOR, L"TPM_PT_PS_FAMILY_INDICATOR" },
    { TPM_PT_PS_LEVEL, L"TPM_PT_PS_LEVEL" },
    { TPM_PT_PS_REVISION, L"TPM_PT_PS_REVISION" },
    { TPM_PT_PS_DAY_OF_YEAR, L"TPM_PT_PS_DAY_OF_YEAR" },
    { TPM_PT_PS_YEAR, L"TPM_PT_PS_YEAR" },
    { TPM_PT_SPLIT_MAX, L"TPM_PT_SPLIT_MAX" },
    { TPM_PT_TOTAL_COMMANDS, L"TPM_PT_TOTAL_COMMANDS" },
    { TPM_PT_LIBRARY_COMMANDS, L"TPM_PT_LIBRARY_COMMANDS" },
    { TPM_PT_VENDOR_COMMANDS, L"TPM_PT_VENDOR_COMMANDS" },
    { TPM_PT_NV_BUFFER_MAX, L"TPM_PT_NV_BUFFER_MAX" },
    { TPM_PT_PERMANENT, L"TPM_PT_PERMANENT" },
    { TPM_PT_STARTUP_CLEAR, L"TPM_PT_STARTUP_CLEAR" },
    { TPM_PT_HR_NV_INDEX, L"TPM_PT_HR_NV_INDEX" },
    { TPM_PT_HR_LOADED, L"TPM_PT_HR_LOADED" },
    { TPM_PT_HR_LOADED_AVAIL, L"TPM_PT_HR_LOADED_AVAIL" },
    { TPM_PT_HR_ACTIVE, L"TPM_PT_HR_ACTIVE" },
    { TPM_PT_HR_ACTIVE_AVAIL, L"TPM_PT_HR_ACTIVE_AVAIL" },
    { TPM_PT_HR_TRANSIENT_AVAIL, L"TPM_PT_HR_TRANSIENT_AVAIL" },
    { TPM_PT_HR_PERSISTENT, L"TPM_PT_HR_PERSISTENT" },
    { TPM_PT_HR_PERSISTENT_AVAIL, L"TPM_PT_HR_PERSISTENT_AVAIL" },
    { TPM_PT_NV_COUNTERS, L"TPM_PT_NV_COUNTERS" },
    { TPM_PT_NV_COUNTERS_AVAIL, L"TPM_PT_NV_COUNTERS_AVAIL" },
    { TPM_PT_ALGORITHM_SET, L"TPM_PT_ALGORITHM_SET" },
    { TPM_PT_LOADED_CURVES, L"TPM_PT_LOADED_CURVES" },
    { TPM_PT_LOCKOUT_COUNTER, L"TPM_PT_LOCKOUT_COUNTER" },
    { TPM_PT_MAX_AUTH_FAIL, L"TPM_PT_MAX_AUTH_FAIL" },
    { TPM_PT_LOCKOUT_INTERVAL, L"TPM_PT_LOCKOUT_INTERVAL" },
    { TPM_PT_LOCKOUT_RECOVERY, L"TPM_PT_LOCKOUT_RECOVERY" },
    { TPM_PT_NV_WRITE_RECOVERY, L"TPM_PT_NV_WRITE_RECOVERY" },
    { TPM_PT_AUDIT_COUNTER_0, L"TPM_PT_AUDIT_COUNTER_0" },
    { TPM_PT_AUDIT_COUNTER_1, L"TPM_PT_AUDIT_COUNTER_1" },
    { 0xffffffff, L"UNKNOWN" }
};

TRANSLATE_TABLE VarCapabilityNameTable[] =
{
    { TPM_PT_PERMANENT, L"TPM_PT_PERMANENT" },
    { TPM_PT_STARTUP_CLEAR, L"TPM_PT_STARTUP_CLEAR" },
    { TPM_PT_HR_NV_INDEX, L"TPM_PT_HR_NV_INDEX" },
    { TPM_PT_HR_LOADED, L"TPM_PT_HR_LOADED" },
    { TPM_PT_HR_LOADED_AVAIL, L"TPM_PT_HR_LOADED_AVAIL" },
    { TPM_PT_HR_ACTIVE, L"TPM_PT_HR_ACTIVE" },
    { TPM_PT_HR_ACTIVE_AVAIL, L"TPM_PT_HR_ACTIVE_AVAIL" },
    { TPM_PT_HR_TRANSIENT_AVAIL, L"TPM_PT_HR_TRANSIENT_AVAIL" },
    { TPM_PT_HR_PERSISTENT, L"TPM_PT_HR_PERSISTENT" },
    { TPM_PT_HR_PERSISTENT_AVAIL, L"TPM_PT_HR_PERSISTENT_AVAIL" },
    { TPM_PT_NV_COUNTERS, L"TPM_PT_NV_COUNTERS" },
    { TPM_PT_NV_COUNTERS_AVAIL, L"TPM_PT_NV_COUNTERS_AVAIL" },
    { TPM_PT_ALGORITHM_SET, L"TPM_PT_ALGORITHM_SET" },
    { TPM_PT_LOADED_CURVES, L"TPM_PT_LOADED_CURVES" },
    { TPM_PT_LOCKOUT_COUNTER, L"TPM_PT_LOCKOUT_COUNTER" },
    { TPM_PT_MAX_AUTH_FAIL, L"TPM_PT_MAX_AUTH_FAIL" },
    { TPM_PT_LOCKOUT_INTERVAL, L"TPM_PT_LOCKOUT_INTERVAL" },
    { TPM_PT_LOCKOUT_RECOVERY, L"TPM_PT_LOCKOUT_RECOVERY" },
    { TPM_PT_NV_WRITE_RECOVERY, L"TPM_PT_NV_WRITE_RECOVERY" },
    { TPM_PT_AUDIT_COUNTER_0, L"TPM_PT_AUDIT_COUNTER_0" },
    { TPM_PT_AUDIT_COUNTER_1, L"TPM_PT_AUDIT_COUNTER_1" },
    { 0xffffffff, L"UNKNOWN" }
};

TRANSLATE_TABLE FamilyNameTable[] =
{
    { TPM_PS_MAIN, L"TPM_PS_MAIN" },
    { TPM_PS_PC, L"TPM_PS_PC" },
    { TPM_PS_PDA, L"TPM_PS_PDA" },
    { TPM_PS_CELL_PHONE, L"TPM_PS_CELL_PHONE" },
    { TPM_PS_SERVER, L"TPM_PS_SERVER" },
    { TPM_PS_PERIPHERAL, L"TPM_PS_PERIPHERAL" },
    { TPM_PS_TSS, L"TPM_PS_TSS" },
    { TPM_PS_STORAGE, L"TPM_PS_STORAGE" },
    { TPM_PS_AUTHENTICATION, L"TPM_PS_AUTHENTICATION" },
    { TPM_PS_EMBEDDED, L"TPM_PS_EMBEDDED" },
    { TPM_PS_HARDCOPY, L"TPM_PS_HARDCOPY" },
    { TPM_PS_INFRASTRUCTURE, L"TPM_PS_INFRASTRUCTURE" },
    { TPM_PS_VIRTUALIZATION, L"TPM_PS_VIRTUALIZATION" },
    { TPM_PS_TNC, L"TPM_PS_TNC" },
    { TPM_PS_MULTI_TENANT, L"TPM_PS_MULTI_TENANT" },
    { TPM_PS_TC, L"TPM_PS_TC" },
    { 0xffffffff, L"UNKNOWN" }
};

TRANSLATE_TABLE* ResolveString(TRANSLATE_TABLE* pTable, DWORD value)
{
    DWORD n = 0;
    for (n = 0; ((pTable[n].Id != 0xffffffff) && (pTable[n].Id != value)); n++);
    return &pTable[n];
}

HRESULT
GetMissingOrdinals()
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    GetCapability_In* pGetCapabilityIn = NULL;
    GetCapability_Out* pGetCapabilityOut = NULL;
    BOOL moreCmdCapsToRead = TRUE;
    TPM_CC nextCmdToRead = TPM_CC_FIRST;
    TRANSLATE_TABLE* pCommand = NULL;
    UINT32 cmdTblIdx = 0;
    BYTE comTbl[((TPM_CC_LAST - TPM_CC_FIRST + 7) / 8)] = { 0 };

    ALLOCATEOBJECTMEMORY(GetCapability_In, pGetCapabilityIn);
    ALLOCATEOBJECTMEMORY(GetCapability_Out, pGetCapabilityOut);

    // Read all command caps
    wprintf(L"Missing Ordinals:\n");
    while (moreCmdCapsToRead)
    {
        INITIALIZE_CALL_BUFFERS(TPM2_GetCapability, pGetCapabilityIn, pGetCapabilityOut);
        pGetCapabilityIn->capability = TPM_CAP_COMMANDS;
        pGetCapabilityIn->property = nextCmdToRead;
        pGetCapabilityIn->propertyCount = MAX_CAP_CC;
        EXECUTE_TPM_CALL(FALSE, TPM2_GetCapability);
        moreCmdCapsToRead = (pGetCapabilityOut->moreData != 0) ? TRUE : FALSE;

        if (pGetCapabilityOut->capabilityData.data.command.count > MAX_CAP_CC)
        {
            result = TPM_RC_SIZE;
            goto Cleanup;
        }

        for (UINT32 n = 0; n < pGetCapabilityOut->capabilityData.data.command.count; n++)
        {
            cmdTblIdx = ((pGetCapabilityOut->capabilityData.data.command.commandAttributes[n].commandIndex - TPM_CC_FIRST) / 8);
            comTbl[cmdTblIdx] |= 0x01 << (pGetCapabilityOut->capabilityData.data.command.commandAttributes[n].commandIndex - TPM_CC_FIRST) % 8;
        }

        if (moreCmdCapsToRead)
        {
            nextCmdToRead = pGetCapabilityOut->capabilityData.data.command.commandAttributes[pGetCapabilityOut->capabilityData.data.command.count - 1].commandIndex + 1;
        }
    }

    for (UINT32 n = TPM_CC_FIRST; n < TPM_CC_LAST; n++)
    {
        cmdTblIdx = (n - TPM_CC_FIRST) / 8;
        if ((n == 0x00000123) || // Ignore the removed command ordinals
            (n == 0x0000015a) ||
            (n == 0x0000015f) ||
            (n == 0x00000166) ||
            (n == 0x00000175) ||
            (comTbl[cmdTblIdx] & (0x01 << ((n - TPM_CC_FIRST) % 8))))
        {
            continue;
        }

        pCommand = ResolveString(CommandNameTable, n);
        if (pCommand->Id != n)
        {
            wprintf(L"%s(0x%08x)\n", pCommand->Name, n);
        }
        else
        {
            wprintf(L"%s(0x%08x)\n", pCommand->Name, n);
        }
    }

Cleanup:
    FREEOBJECTMEMORY(pGetCapabilityIn);
    FREEOBJECTMEMORY(pGetCapabilityOut);
    return (HRESULT)result;
}

HRESULT
GetCapabilities()
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    GetCapability_In* pGetCapabilityIn = NULL;
    GetCapability_Out* pGetCapabilityOut = NULL;
    BOOL moreCmdCapsToRead = TRUE;
    TPM_CC nextCapToRead = PT_FIXED;
    BOOL tInVarArea = FALSE;
    char vendorString[4 * sizeof(UINT32)+1] = { 0 };
    UINT64 auditCounter = 0L;

    ALLOCATEOBJECTMEMORY(GetCapability_In, pGetCapabilityIn);
    ALLOCATEOBJECTMEMORY(GetCapability_Out, pGetCapabilityOut);

    // Read all command caps
    wprintf(L"Capabilities:\nPT_FIXED:\n");
    do
    {
        INITIALIZE_CALL_BUFFERS(TPM2_GetCapability, pGetCapabilityIn, pGetCapabilityOut);
        pGetCapabilityIn->capability = TPM_CAP_TPM_PROPERTIES;
        pGetCapabilityIn->property = nextCapToRead;
        pGetCapabilityIn->propertyCount = PT_GROUP * 2; // all properties in group PT_FIXED and PT_VAR
        EXECUTE_TPM_CALL(FALSE, TPM2_GetCapability);

        if (pGetCapabilityOut->moreData)
        {
            moreCmdCapsToRead = TRUE;
            nextCapToRead = pGetCapabilityOut->capabilityData.data.tpmProperties.tpmProperty[pGetCapabilityOut->capabilityData.data.tpmProperties.count - 1].property + 1;
        }
        else
        {
            moreCmdCapsToRead = FALSE;
        }
        for (UINT32 n = 0; n < pGetCapabilityOut->capabilityData.data.tpmProperties.count; n++)
        {
            TPM_PT cap = pGetCapabilityOut->capabilityData.data.tpmProperties.tpmProperty[n].property;
            UINT32 value = pGetCapabilityOut->capabilityData.data.tpmProperties.tpmProperty[n].value;
            PBYTE pCharValue = (PBYTE)&value;
            TRANSLATE_TABLE* pCap = ResolveString(FixedCapabilityNameTable, cap);

            if ((cap >= PT_VAR) && (!tInVarArea))
            {
                wprintf(L"\nPT_VAR:\n");
                tInVarArea = TRUE;
            }

            if ((cap != TPM_PT_VENDOR_STRING_1) &&
                (cap != TPM_PT_VENDOR_STRING_2) &&
                (cap != TPM_PT_VENDOR_STRING_3) &&
                (cap != TPM_PT_VENDOR_STRING_4) &&
                (cap != TPM_PT_AUDIT_COUNTER_0) &&
                (cap != TPM_PT_AUDIT_COUNTER_1))
            {
                if (pCap->Id != 0xffffffff)
                {
                    wprintf(L"%s = ", pCap->Name);
                }
                else
                {
                    wprintf(L"%s(0x%08x) = ", pCap->Name, cap);
                }
            }

            switch (cap)
            {
            case TPM_PT_FAMILY_INDICATOR:
            case TPM_PT_MANUFACTURER:
            {
                                        wprintf(L"'%c%c%c%c", pCharValue[3], pCharValue[2], pCharValue[1], pCharValue[0]);
                                        wprintf(L"'\n");
                                        break;
            }
            case TPM_PT_VENDOR_STRING_1:
            {
                                           vendorString[0] = pCharValue[3];
                                           vendorString[1] = pCharValue[2];
                                           vendorString[2] = pCharValue[1];
                                           vendorString[3] = pCharValue[0];
                                           break;
            }
            case TPM_PT_VENDOR_STRING_2:
            {
                                           vendorString[4] = pCharValue[3];
                                           vendorString[5] = pCharValue[2];
                                           vendorString[6] = pCharValue[1];
                                           vendorString[7] = pCharValue[0];
                                           break;
            }
            case TPM_PT_VENDOR_STRING_3:
            {
                                           vendorString[8] = pCharValue[3];
                                           vendorString[9] = pCharValue[2];
                                           vendorString[10] = pCharValue[1];
                                           vendorString[11] = pCharValue[0];
                                           break;
            }
            case TPM_PT_VENDOR_STRING_4:
            {
                                           vendorString[12] = pCharValue[3];
                                           vendorString[13] = pCharValue[2];
                                           vendorString[14] = pCharValue[1];
                                           vendorString[15] = pCharValue[0];

                                           printf("TPM_PT_VENDOR_STRING = '%s'\n", vendorString);
                                           break;
            }
            case TPM_PT_REVISION:
            {
                                    wprintf(L"%d.%d\n", (value / 100), (value % 100));
                                    break;
            }
            case TPM_PT_FIRMWARE_VERSION_1:
            case TPM_PT_FIRMWARE_VERSION_2:
            {
                                              UINT16 major = ((value & 0xffff0000) >> 16);
                                              UINT16 minor = (value & 0x0000ffff);
                                              wprintf(L"%d.%d (0x%x.0x%x)\n", major, minor, major, minor);
                                              break;
            }
            case TPM_PT_MEMORY:
            {
                                  if (value != 0)
                                  {
                                      if (value & 0x00000001) printf("sharedRAM ");
                                      if (value & 0x00000002) printf("sharedNV ");
                                      if (value & 0x00000004) printf("objectCopiedToRam ");
                                  }
                                  else
                                  {
                                      wprintf(L"none");
                                  }
                                  wprintf(L"\n");
                                  break;
            }
            case TPM_PT_CLOCK_UPDATE:
            case TPM_PT_NV_WRITE_RECOVERY:
            {
                                             wprintf(L"%dms\n", value);
                                             break;
            }
            case TPM_PT_CONTEXT_HASH:
            case TPM_PT_CONTEXT_SYM:
            {
                                       TRANSLATE_TABLE* pAlg = ResolveString(AlgorithmNameTable, value);
                                       wprintf(L"%s\n", pAlg->Name);
                                       break;
            }
            case TPM_PT_PS_FAMILY_INDICATOR:
            {
                                               TRANSLATE_TABLE* pFamily = ResolveString(FamilyNameTable, value);
                                               wprintf(L"%s\n", pFamily->Name);
                                               break;
            }
            case TPM_PT_PS_REVISION:
            {
                                       wprintf(L"%d\n", (value * 100));
                                       break;
            }
            case TPM_PT_PERMANENT:
            {
                                     if (value != 0)
                                     {
                                         if (value & 0x00000001) printf("ownerAuthSet ");
                                         if (value & 0x00000002) printf("endorsementAuthSet ");
                                         if (value & 0x00000004) printf("lockoutAuthSet ");
                                         if (value & 0x00000100) printf("disableClear ");
                                         if (value & 0x00000200) printf("inLockout ");
                                         if (value & 0x00000400) printf("tpmGeneratedEPS ");
                                         if (value & 0xFFFFF8F8) printf("UNKNOWN(0x%08x)", (value & 0xFFFFF8F8));
                                     }
                                     else
                                     {
                                         wprintf(L"none");
                                     }
                                     wprintf(L"\n");
                                     break;
            }
            case TPM_PT_STARTUP_CLEAR:
            {
                                         if (value != 0)
                                         {
                                             if (value & 0x00000001) printf("phEnable ");
                                             if (value & 0x00000002) printf("shEnable ");
                                             if (value & 0x00000004) printf("ehEnable ");
                                             if (value & 0x00000008) printf("ehEnableNV ");
                                             if (value & 0x80000000) printf("orderly ");
                                             if (value & 0x7FFFFFF0) printf("UNKNOWN(0x%08x)", (value & 0x7FFFFFF0));
                                         }
                                         else
                                         {
                                             wprintf(L"none");
                                         }
                                         wprintf(L"\n");
                                         break;
            }
            case TPM_PT_LOCKOUT_INTERVAL:
            case TPM_PT_LOCKOUT_RECOVERY:
            {
                                            UINT32 hrs = value / 3600;
                                            UINT32 min = (value - hrs * 3600) / 60;
                                            UINT32 sec = (value - hrs * 3600 - min * 60);
                                            wprintf(L"%dh %d\" %d'\n", hrs, min, sec);
                                            break;
            }
            case TPM_PT_AUDIT_COUNTER_0:
            {
                                           auditCounter = (((UINT64)value) << 32);
                                           break;
            }
            case TPM_PT_AUDIT_COUNTER_1:
            {
                                           auditCounter |= value;

                                           wprintf(L"TPM_PT_AUDIT_COUNTER = %I64d\n", auditCounter);
                                           break;
            }
            default:
            {
                       wprintf(L"%d (0x%08x)\n", value, value);
                       break;
            }
            }
        }
    } while (moreCmdCapsToRead);

Cleanup:
    FREEOBJECTMEMORY(pGetCapabilityIn);
    FREEOBJECTMEMORY(pGetCapabilityOut);
    return (HRESULT)result;
}

UINT32
GetAlgsAndCurves()
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    GetCapability_In* pGetCapabilityIn = NULL;
    GetCapability_Out* pGetCapabilityOut = NULL;
    UINT32 nextOne = 0;
    TRANSLATE_TABLE* pCommand = NULL;
    BYTE count = 0;

    ALLOCATEOBJECTMEMORY(GetCapability_In, pGetCapabilityIn);
    ALLOCATEOBJECTMEMORY(GetCapability_Out, pGetCapabilityOut);

    pGetCapabilityOut->moreData = YES;
    wprintf(L"Algorithms:\n");
    while (pGetCapabilityOut->moreData != NO)
    {
        INITIALIZE_CALL_BUFFERS(TPM2_GetCapability, pGetCapabilityIn, pGetCapabilityOut);
        pGetCapabilityIn->capability = TPM_CAP_ALGS;
        pGetCapabilityIn->property = nextOne;
        pGetCapabilityIn->propertyCount = MAX_CAP_ALGS;
        EXECUTE_TPM_CALL(FALSE, TPM2_GetCapability);

        if ((pGetCapabilityOut->capabilityData.data.algorithms.count == 0) ||
            (pGetCapabilityOut->capabilityData.data.algorithms.count > MAX_CAP_ALGS))
        {
            result = TPM_RC_SIZE;
            goto Cleanup;
        }
        if (pGetCapabilityOut->moreData != NO)
        {
            nextOne = pGetCapabilityOut->capabilityData.data.algorithms.algProperties[pGetCapabilityOut->capabilityData.data.algorithms.count - 1].alg + 1;
        }
        for (UINT32 n = 0; n < pGetCapabilityOut->capabilityData.data.algorithms.count; n++)
        {
            pCommand = ResolveString(AlgorithmNameTable, pGetCapabilityOut->capabilityData.data.algorithms.algProperties[n].alg);
            if (pCommand->Id != 0xffffffff)
            {
                wprintf(L"%s(0x%04x)\n", pCommand->Name, pGetCapabilityOut->capabilityData.data.algorithms.algProperties[n].alg);
            }
            else
            {
                wprintf(L"%s(0x%04x)\n", pCommand->Name, pGetCapabilityOut->capabilityData.data.algorithms.algProperties[n].alg);
            }
        }
    }

    pGetCapabilityOut->moreData = YES;
    nextOne = 0;
    count = 0;
    wprintf(L"\nCurves:\n");
    while (pGetCapabilityOut->moreData != NO)
    {
        INITIALIZE_CALL_BUFFERS(TPM2_GetCapability, pGetCapabilityIn, pGetCapabilityOut);
        pGetCapabilityIn->capability = TPM_CAP_ECC_CURVES;
        pGetCapabilityIn->property = nextOne;
        pGetCapabilityIn->propertyCount = MAX_ECC_CURVES;

        cbCmd = TPM2_GetCapability_Marshal(sessionTable, sessionCnt, &parms, &buffer, &size);
        if (((result = PlatformSubmitTPM20Command(FALSE, pbCmd, cbCmd, pbRsp, sizeof(pbRsp), &cbRsp)) != TPM_RC_SUCCESS) ||
            ((buffer = pbRsp) == NULL) ||
            ((size = cbRsp) == 0) ||
            ((result = TPM2_GetCapability_Unmarshal(sessionTable, sessionCnt, &parms, &buffer, &size)) != TPM_RC_SUCCESS))
        {
            wprintf(L"None");
            break;
        }

        if (pGetCapabilityOut->moreData != NO)
        {
            nextOne = pGetCapabilityOut->capabilityData.data.eccCurves.eccCurves[pGetCapabilityOut->capabilityData.data.eccCurves.count - 1] + 1;
        }
        for (UINT32 n = 0; n < pGetCapabilityOut->capabilityData.data.eccCurves.count; n++)
        {
            pCommand = ResolveString(CurveNameTable, pGetCapabilityOut->capabilityData.data.eccCurves.eccCurves[n]);
            if (pCommand->Id != 0xffffffff)
            {
                wprintf(L"%s(0x%04x)\n", pCommand->Name, pGetCapabilityOut->capabilityData.data.eccCurves.eccCurves[n]);
            }
            else
            {
                wprintf(L"%s(0x%04x)\n", pCommand->Name, pGetCapabilityOut->capabilityData.data.eccCurves.eccCurves[n]);
            }
        }
    }

Cleanup:
    FREEOBJECTMEMORY(pGetCapabilityIn);
    FREEOBJECTMEMORY(pGetCapabilityOut);
    return result;
}

UINT32
ReadPcrs()
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    PCR_Read_In* pPCR_Read_In = NULL;
    PCR_Read_Out* pPCR_Read_Out = NULL;
    TPMI_ALG_HASH hashTable[] = { TPM_ALG_SHA1, TPM_ALG_SHA256 };

    ALLOCATEOBJECTMEMORY(PCR_Read_In, pPCR_Read_In);
    ALLOCATEOBJECTMEMORY(PCR_Read_Out, pPCR_Read_Out);

    for (UINT32 pcrBank = 0; pcrBank < 2; pcrBank++)
    {
        TRANSLATE_TABLE* pHashAlg = ResolveString(AlgorithmNameTable, hashTable[pcrBank]);
        wprintf(L"Bank: %s\n", pHashAlg->Name);
        for (UINT32 pcrGroup = 0; pcrGroup < 3; pcrGroup++)
        {
            INITIALIZE_CALL_BUFFERS(TPM2_PCR_Read, pPCR_Read_In, pPCR_Read_Out);
            pPCR_Read_In->pcrSelectionIn.count = 1;
            pPCR_Read_In->pcrSelectionIn.pcrSelections[0].hash = hashTable[pcrBank];
            pPCR_Read_In->pcrSelectionIn.pcrSelections[0].sizeofSelect = 3;
            pPCR_Read_In->pcrSelectionIn.pcrSelections[0].pcrSelect[0] = (pcrGroup == 0) ? 0xFF : 0x00;
            pPCR_Read_In->pcrSelectionIn.pcrSelections[0].pcrSelect[1] = (pcrGroup == 1) ? 0xFF : 0x00;
            pPCR_Read_In->pcrSelectionIn.pcrSelections[0].pcrSelect[2] = (pcrGroup == 2) ? 0xFF : 0x00;
            EXECUTE_TPM_CALL(FALSE, TPM2_PCR_Read);
            for (UINT32 n = 0; n < pPCR_Read_Out->pcrValues.count; n++)
            {
                wprintf(L"PCR[%02d]=", pcrGroup * 8 + n);
                for (UINT32 m = 0; m < pPCR_Read_Out->pcrValues.digests[n].t.size; m++)
                {
                    wprintf(L"%02x", pPCR_Read_Out->pcrValues.digests[n].t.buffer[m]);
                }
                wprintf(L"\n");
            }
        }
        wprintf(L"\n");
    }

Cleanup:
    if (result != TPM_RC_SUCCESS)
    {
        wprintf(L"FAILED: 0x%08x\n", result);
        wprintf(L"Cmd:");
        for (UINT32 n = 0; n < cbCmd; n++)
            wprintf(L"%02x ", pbCmd[n]);
        wprintf(L"\nRsp:");
        for (UINT32 n = 0; n < cbRsp; n++)
            wprintf(L"%02x ", pbRsp[n]);
        wprintf(L"\n");
    }
    FREEOBJECTMEMORY(pPCR_Read_In);
    FREEOBJECTMEMORY(pPCR_Read_Out);
    return result;
}

UINT32
ResetDebugPcr()
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    PCR_Reset_In* pPCR_Reset_In = NULL;
    PCR_Reset_Out* pPCR_Reset_Out = NULL;

    ALLOCATEOBJECTMEMORY(PCR_Reset_In, pPCR_Reset_In);
    ALLOCATEOBJECTMEMORY(PCR_Reset_Out, pPCR_Reset_Out);

    // Create the session
    sessionTable[0].handle = TPM_RS_PW;

    // Reset the debug PCR
    INITIALIZE_CALL_BUFFERS(TPM2_PCR_Reset, pPCR_Reset_In, pPCR_Reset_Out);
    parms.objectTableIn[TPM2_PCR_Reset_HdlIn_PcrHandle].generic.handle = 0x00000010;
    EXECUTE_TPM_CALL(FALSE, TPM2_PCR_Reset);

    wprintf(L"OK.\n");

Cleanup:
    if (result != TPM_RC_SUCCESS)
    {
        wprintf(L"FAILED: 0x%08x\n", result);
        wprintf(L"Cmd:");
        for (UINT32 n = 0; n < cbCmd; n++)
            wprintf(L"%02x ", pbCmd[n]);
        wprintf(L"\nRsp:");
        for (UINT32 n = 0; n < cbRsp; n++)
            wprintf(L"%02x ", pbRsp[n]);
        wprintf(L"\n");
    }
    FREEOBJECTMEMORY(pPCR_Reset_In);
    FREEOBJECTMEMORY(pPCR_Reset_Out);
    return result;
}

UINT32
ExtendDebugPcr()
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    PCR_Extend_In* pPCR_Extend_In = NULL;
    PCR_Extend_Out* pPCR_Extend_Out = NULL;

    ALLOCATEOBJECTMEMORY(PCR_Extend_In, pPCR_Extend_In);
    ALLOCATEOBJECTMEMORY(PCR_Extend_Out, pPCR_Extend_Out);

    // Create the session
    sessionTable[0].handle = TPM_RS_PW;

    // Extend the debug PCR
    INITIALIZE_CALL_BUFFERS(TPM2_PCR_Extend, pPCR_Extend_In, pPCR_Extend_Out);
    parms.objectTableIn[TPM2_PCR_Extend_HdlIn_PcrHandle].generic.handle = 0x00000010;
    pPCR_Extend_In->digests.count = 1;
    pPCR_Extend_In->digests.digests[0].hashAlg = TPM_ALG_SHA1;
    MemorySet(pPCR_Extend_In->digests.digests[0].digest.sha1, 0x00, sizeof(pPCR_Extend_In->digests.digests[0].digest.sha1));
    EXECUTE_TPM_CALL(FALSE, TPM2_PCR_Extend);
    wprintf(L"SHA1 - OK.\n");

    INITIALIZE_CALL_BUFFERS(TPM2_PCR_Extend, pPCR_Extend_In, pPCR_Extend_Out);
    parms.objectTableIn[TPM2_PCR_Extend_HdlIn_PcrHandle].generic.handle = 0x00000010;
    pPCR_Extend_In->digests.count = 1;
    pPCR_Extend_In->digests.digests[0].hashAlg = TPM_ALG_SHA256;
    MemorySet(pPCR_Extend_In->digests.digests[0].digest.sha256, 0x00, sizeof(pPCR_Extend_In->digests.digests[0].digest.sha256));
    EXECUTE_TPM_CALL(FALSE, TPM2_PCR_Extend);
    wprintf(L"SHA256 - OK.\n");

Cleanup:
    if (result != TPM_RC_SUCCESS)
    {
        wprintf(L"FAILED: 0x%08x\n", result);
        wprintf(L"Cmd:");
        for (UINT32 n = 0; n < cbCmd; n++)
            wprintf(L"%02x ", pbCmd[n]);
        wprintf(L"\nRsp:");
        for (UINT32 n = 0; n < cbRsp; n++)
            wprintf(L"%02x ", pbRsp[n]);
        wprintf(L"\n");
    }
    FREEOBJECTMEMORY(pPCR_Extend_In);
    FREEOBJECTMEMORY(pPCR_Extend_Out);
    return result;
}

UINT32
ReadClock()
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    ReadClock_In* pReadClockIn = NULL;
    ReadClock_Out* pReadClockOut = NULL;

    ALLOCATEOBJECTMEMORY(ReadClock_In, pReadClockIn);
    ALLOCATEOBJECTMEMORY(ReadClock_Out, pReadClockOut);

    INITIALIZE_CALL_BUFFERS(TPM2_ReadClock, pReadClockIn, pReadClockOut);
    EXECUTE_TPM_CALL(FALSE, TPM2_ReadClock);

    wprintf(L"time: %I64d\n", pReadClockOut->currentTime.time);
    wprintf(L"TPMS_CLOCK_INFO.clock: %I64d\n", pReadClockOut->currentTime.clockInfo.clock);
    wprintf(L"TPMS_CLOCK_INFO.resetCount: %d\n", pReadClockOut->currentTime.clockInfo.resetCount);
    wprintf(L"TPMS_CLOCK_INFO.restartCount: %d\n", pReadClockOut->currentTime.clockInfo.restartCount);
    wprintf(L"TPMS_CLOCK_INFO.safe: %s\n", pReadClockOut->currentTime.clockInfo.safe ? L"Yes" : L"No");

Cleanup:
    if (result != TPM_RC_SUCCESS)
    {
        wprintf(L"FAILED: 0x%08x\n", result);
        wprintf(L"Cmd:");
        for (UINT32 n = 0; n < cbCmd; n++)
            wprintf(L"%02x ", pbCmd[n]);
        wprintf(L"\nRsp:");
        for (UINT32 n = 0; n < cbRsp; n++)
            wprintf(L"%02x ", pbRsp[n]);
        wprintf(L"\n");
    }
    FREEOBJECTMEMORY(pReadClockIn);
    FREEOBJECTMEMORY(pReadClockOut);
    return result;
}


UINT32
DumpPubKey(TPM_HANDLE hTpmKey)
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    ReadPublic_In* pReadPublicIn = NULL;
    ReadPublic_Out* pReadPublicOut = NULL;

    ALLOCATEOBJECTMEMORY(ReadPublic_In, pReadPublicIn);
    ALLOCATEOBJECTMEMORY(ReadPublic_Out, pReadPublicOut);

    INITIALIZE_CALL_BUFFERS(TPM2_ReadPublic, pReadPublicIn, pReadPublicOut);
    parms.objectTableIn[TPM2_ReadPublic_HdlIn_PublicKey].generic.handle = hTpmKey;
    EXECUTE_TPM_CALL(FALSE, TPM2_ReadPublic);

    wprintf(L"Name: ");
    for (UINT32 n = 0; n < pReadPublicOut->name.t.size; n++)
    {
        wprintf(L"%02x", pReadPublicOut->name.t.name[n]);
    }
    wprintf(L"\n");
    TRANSLATE_TABLE* pAlg = ResolveString(AlgorithmNameTable, pReadPublicOut->outPublic.t.publicArea.nameAlg);
    wprintf(L"NameAlg: %s\n", pAlg->Name);
    wprintf(L"Attributes:\n");
    if (pReadPublicOut->outPublic.t.publicArea.objectAttributes.fixedTPM) wprintf(L"- FixedTPM\n");
    if (pReadPublicOut->outPublic.t.publicArea.objectAttributes.stClear) wprintf(L"- STClear\n");
    if (pReadPublicOut->outPublic.t.publicArea.objectAttributes.fixedParent) wprintf(L"- FixedParent\n");
    if (pReadPublicOut->outPublic.t.publicArea.objectAttributes.sensitiveDataOrigin) wprintf(L"- SensitiveDataOrigin\n");
    if (pReadPublicOut->outPublic.t.publicArea.objectAttributes.userWithAuth) wprintf(L"- UserWithAuth\n");
    if (pReadPublicOut->outPublic.t.publicArea.objectAttributes.adminWithPolicy) wprintf(L"- AdminWithPolicy\n");
    if (pReadPublicOut->outPublic.t.publicArea.objectAttributes.noDA) wprintf(L"- NoDA\n");
    if (pReadPublicOut->outPublic.t.publicArea.objectAttributes.encryptedDuplication) wprintf(L"- EncryptedDuplication\n");
    if (pReadPublicOut->outPublic.t.publicArea.objectAttributes.restricted) wprintf(L"- Restricted\n");
    if (pReadPublicOut->outPublic.t.publicArea.objectAttributes.decrypt) wprintf(L"- Decrypt\n");
    if (pReadPublicOut->outPublic.t.publicArea.objectAttributes.sign) wprintf(L"- Sign\n");
    wprintf(L"AuthPolicy: ");
    if (pReadPublicOut->outPublic.t.publicArea.authPolicy.t.size == 0)
    {
        wprintf(L"none");
    }
    else
    {
        for (UINT32 n = 0; n < pReadPublicOut->outPublic.t.publicArea.authPolicy.t.size; n++)
        {
            wprintf(L"%02x", pReadPublicOut->outPublic.t.publicArea.authPolicy.t.buffer[n]);
        }
    }
    wprintf(L"\n");
    if (pReadPublicOut->outPublic.t.publicArea.type == TPM_ALG_RSA)
    {
        wprintf(L"Modulus (%d bit): ", pReadPublicOut->outPublic.t.publicArea.parameters.rsaDetail.keyBits);
        for (UINT32 n = 0; n < pReadPublicOut->outPublic.t.publicArea.unique.rsa.t.size; n++)
        {
            wprintf(L"%02x", pReadPublicOut->outPublic.t.publicArea.unique.rsa.t.buffer[n]);
        }
        wprintf(L"\n");
    }

Cleanup:
    if (result != TPM_RC_SUCCESS)
    {
        wprintf(L"FAILED: 0x%08x\n", result);
        wprintf(L"Cmd:");
        for (UINT32 n = 0; n < cbCmd; n++)
            wprintf(L"%02x ", pbCmd[n]);
        wprintf(L"\nRsp:");
        for (UINT32 n = 0; n < cbRsp; n++)
            wprintf(L"%02x ", pbRsp[n]);
        wprintf(L"\n");
    }
    FREEOBJECTMEMORY(pReadPublicIn);
    FREEOBJECTMEMORY(pReadPublicOut);
    return result;
}

UINT32
GetNvKeys()
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    GetCapability_In* pGetCapabilityIn = NULL;
    GetCapability_Out* pGetCapabilityOut = NULL;

    ALLOCATEOBJECTMEMORY(GetCapability_In, pGetCapabilityIn);
    ALLOCATEOBJECTMEMORY(GetCapability_Out, pGetCapabilityOut);

    INITIALIZE_CALL_BUFFERS(TPM2_GetCapability, pGetCapabilityIn, pGetCapabilityOut);
    pGetCapabilityIn->capability = TPM_CAP_HANDLES;
    pGetCapabilityIn->property = PERSISTENT_FIRST;
    pGetCapabilityIn->propertyCount = PERSISTENT_LAST - PERSISTENT_FIRST;
    EXECUTE_TPM_CALL(FALSE, TPM2_GetCapability);

    wprintf(L"Persistent Handles in NV:\n");
    for (UINT32 n = 0; n < pGetCapabilityOut->capabilityData.data.handles.count; n++)
    {
        switch (pGetCapabilityOut->capabilityData.data.handles.handle[n])
        {
        case 0x81000001:
            wprintf(L"\nFTPM_PERSISTENT_SRK_HANDLE(0x%08x):\n", pGetCapabilityOut->capabilityData.data.handles.handle[n]);
            break;
        case 0x81000002:
            wprintf(L"\nFTPM_PERSISTENT_AIK_HANDLE(0x%08x):\n", pGetCapabilityOut->capabilityData.data.handles.handle[n]);
            break;
        case 0x81010001:
            wprintf(L"\nFTPM_PERSISTENT_EK_HANDLE(0x%08x):\n", pGetCapabilityOut->capabilityData.data.handles.handle[n]);
            break;
        default:
            wprintf(L"\n0x%08x:\n", pGetCapabilityOut->capabilityData.data.handles.handle[n]);
            break;
        }

        if ((result = DumpPubKey(pGetCapabilityOut->capabilityData.data.handles.handle[n])) != TPM_RC_SUCCESS)
        {
            goto Cleanup;
        }
    }

Cleanup:
    if (result != TPM_RC_SUCCESS)
    {
        wprintf(L"FAILED: 0x%08x\n", result);
        wprintf(L"Cmd:");
        for (UINT32 n = 0; n < cbCmd; n++)
            wprintf(L"%02x ", pbCmd[n]);
        wprintf(L"\nRsp:");
        for (UINT32 n = 0; n < cbRsp; n++)
            wprintf(L"%02x ", pbRsp[n]);
        wprintf(L"\n");
    }
    FREEOBJECTMEMORY(pGetCapabilityIn);
    FREEOBJECTMEMORY(pGetCapabilityOut);
    return result;
}

UINT32
DumpPubNV(TPM_HANDLE hNVIndex)
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    NV_ReadPublic_In* pNv_ReadPublicIn = NULL;
    NV_ReadPublic_Out* pNv_ReadPublicOut = NULL;

    ALLOCATEOBJECTMEMORY(NV_ReadPublic_In, pNv_ReadPublicIn);
    ALLOCATEOBJECTMEMORY(NV_ReadPublic_Out, pNv_ReadPublicOut);

    INITIALIZE_CALL_BUFFERS(TPM2_NV_ReadPublic, pNv_ReadPublicIn, pNv_ReadPublicOut);
    parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex].generic.handle = hNVIndex;
    EXECUTE_TPM_CALL(FALSE, TPM2_NV_ReadPublic);

    wprintf(L"Name: ");
    for (UINT32 n = 0; n < pNv_ReadPublicOut->nvName.t.size; n++)
    {
        wprintf(L"%02x", pNv_ReadPublicOut->nvName.t.name[n]);
    }
    wprintf(L"\n");
    TRANSLATE_TABLE* pAlg = ResolveString(AlgorithmNameTable, pNv_ReadPublicOut->nvPublic.t.nvPublic.nameAlg);
    wprintf(L"NameAlg: %s\n", pAlg->Name);
    wprintf(L"Size: %d\n", pNv_ReadPublicOut->nvPublic.t.nvPublic.dataSize);
    wprintf(L"Attributes:\n");
    if (pNv_ReadPublicOut->nvPublic.t.nvPublic.attributes.TPMA_NV_PPWRITE) wprintf(L"- PPWrite\n");
    if (pNv_ReadPublicOut->nvPublic.t.nvPublic.attributes.TPMA_NV_OWNERWRITE) wprintf(L"- OwnerWrite\n");
    if (pNv_ReadPublicOut->nvPublic.t.nvPublic.attributes.TPMA_NV_AUTHWRITE) wprintf(L"- AuthWrite\n");
    if (pNv_ReadPublicOut->nvPublic.t.nvPublic.attributes.TPMA_NV_POLICYWRITE) wprintf(L"- PolicyWrite\n");
    if (pNv_ReadPublicOut->nvPublic.t.nvPublic.attributes.TPMA_NV_COUNTER) wprintf(L"- Counter\n");
    if (pNv_ReadPublicOut->nvPublic.t.nvPublic.attributes.TPMA_NV_BITS) wprintf(L"- Bits\n");
    if (pNv_ReadPublicOut->nvPublic.t.nvPublic.attributes.TPMA_NV_EXTEND) wprintf(L"- Extend\n");
    if (pNv_ReadPublicOut->nvPublic.t.nvPublic.attributes.TPMA_NV_POLICY_DELETE) wprintf(L"- PolicyDelete\n");
    if (pNv_ReadPublicOut->nvPublic.t.nvPublic.attributes.TPMA_NV_WRITELOCKED) wprintf(L"- WriteLocked\n");
    if (pNv_ReadPublicOut->nvPublic.t.nvPublic.attributes.TPMA_NV_WRITEALL) wprintf(L"- WriteAll\n");
    if (pNv_ReadPublicOut->nvPublic.t.nvPublic.attributes.TPMA_NV_WRITEDEFINE) wprintf(L"- WriteDefine\n");
    if (pNv_ReadPublicOut->nvPublic.t.nvPublic.attributes.TPMA_NV_WRITE_STCLEAR) wprintf(L"- WriteSTClear\n");
    if (pNv_ReadPublicOut->nvPublic.t.nvPublic.attributes.TPMA_NV_GLOBALLOCK) wprintf(L"- GlobalLock\n");
    if (pNv_ReadPublicOut->nvPublic.t.nvPublic.attributes.TPMA_NV_PPREAD) wprintf(L"- PPRead\n");
    if (pNv_ReadPublicOut->nvPublic.t.nvPublic.attributes.TPMA_NV_OWNERREAD) wprintf(L"- OwnerRead\n");
    if (pNv_ReadPublicOut->nvPublic.t.nvPublic.attributes.TPMA_NV_AUTHREAD) wprintf(L"- AuthRead\n");
    if (pNv_ReadPublicOut->nvPublic.t.nvPublic.attributes.TPMA_NV_POLICYREAD) wprintf(L"- PolicyRead\n");
    if (pNv_ReadPublicOut->nvPublic.t.nvPublic.attributes.TPMA_NV_NO_DA) wprintf(L"- NoDA\n");
    if (pNv_ReadPublicOut->nvPublic.t.nvPublic.attributes.TPMA_NV_ORDERLY) wprintf(L"- Orderly\n");
    if (pNv_ReadPublicOut->nvPublic.t.nvPublic.attributes.TPMA_NV_CLEAR_STCLEAR) wprintf(L"- ClearSTClear\n");
    if (pNv_ReadPublicOut->nvPublic.t.nvPublic.attributes.TPMA_NV_READLOCKED) wprintf(L"- ReadLocked\n");
    if (pNv_ReadPublicOut->nvPublic.t.nvPublic.attributes.TPMA_NV_WRITTEN) wprintf(L"- Written\n");
    if (pNv_ReadPublicOut->nvPublic.t.nvPublic.attributes.TPMA_NV_PLATFORMCREATE) wprintf(L"- PlatformCreate\n");
    if (pNv_ReadPublicOut->nvPublic.t.nvPublic.attributes.TPMA_NV_READ_STCLEAR) wprintf(L"- ReadSTClear\n");
    wprintf(L"AuthPolicy: ");
    if (pNv_ReadPublicOut->nvPublic.t.nvPublic.authPolicy.t.size == 0)
    {
        wprintf(L"none");
    }
    else
    {
        for (UINT32 n = 0; n < pNv_ReadPublicOut->nvPublic.t.nvPublic.authPolicy.t.size; n++)
        {
            wprintf(L"%02x", pNv_ReadPublicOut->nvPublic.t.nvPublic.authPolicy.t.buffer[n]);
        }
    }
    wprintf(L"\n");

Cleanup:
    if (result != TPM_RC_SUCCESS)
    {
        wprintf(L"FAILED: 0x%08x\n", result);
        wprintf(L"Cmd:");
        for (UINT32 n = 0; n < cbCmd; n++)
            wprintf(L"%02x ", pbCmd[n]);
        wprintf(L"\nRsp:");
        for (UINT32 n = 0; n < cbRsp; n++)
            wprintf(L"%02x ", pbRsp[n]);
        wprintf(L"\n");
    }
    FREEOBJECTMEMORY(pNv_ReadPublicIn);
    FREEOBJECTMEMORY(pNv_ReadPublicOut);
    return result;
}

UINT32
GetNvObjects()
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    GetCapability_In* pGetCapabilityIn = NULL;
    GetCapability_Out* pGetCapabilityOut = NULL;
    BOOL moreCmdCapsToRead = TRUE;
    TPM_CC nextCapToRead = NV_INDEX_FIRST;

    ALLOCATEOBJECTMEMORY(GetCapability_In, pGetCapabilityIn);
    ALLOCATEOBJECTMEMORY(GetCapability_Out, pGetCapabilityOut);

    wprintf(L"NV Objects:\n");
    do
    {
        INITIALIZE_CALL_BUFFERS(TPM2_GetCapability, pGetCapabilityIn, pGetCapabilityOut);
        pGetCapabilityIn->capability = TPM_CAP_HANDLES;
        pGetCapabilityIn->property = nextCapToRead;
        pGetCapabilityIn->propertyCount = NV_INDEX_LAST - nextCapToRead;
        EXECUTE_TPM_CALL(FALSE, TPM2_GetCapability);

        if ((moreCmdCapsToRead = pGetCapabilityOut->moreData) != FALSE)
        {
            nextCapToRead = pGetCapabilityOut->capabilityData.data.handles.handle[pGetCapabilityOut->capabilityData.data.handles.count - 1] + 1;
        }

        for (UINT32 n = 0; n < pGetCapabilityOut->capabilityData.data.handles.count; n++)
        {
            wprintf(L"\n0x%08x:\n", pGetCapabilityOut->capabilityData.data.handles.handle[n]);
            if ((result = DumpPubNV(pGetCapabilityOut->capabilityData.data.handles.handle[n])) != TPM_RC_SUCCESS)
            {
                goto Cleanup;
            }
        }
    } while (moreCmdCapsToRead);

Cleanup:
    if (result != TPM_RC_SUCCESS)
    {
        wprintf(L"FAILED: 0x%08x\n", result);
        wprintf(L"Cmd:");
        for (UINT32 n = 0; n < cbCmd; n++)
            wprintf(L"%02x ", pbCmd[n]);
        wprintf(L"\nRsp:");
        for (UINT32 n = 0; n < cbRsp; n++)
            wprintf(L"%02x ", pbRsp[n]);
        wprintf(L"\n");
    }
    FREEOBJECTMEMORY(pGetCapabilityIn);
    FREEOBJECTMEMORY(pGetCapabilityOut);
    return result;
}

UINT32
PHClear()
{
    UINT32 result = TPM_RC_SUCCESS;
    DEFINE_CALL_BUFFERS;
    ClearControl_In* pClearControlIn = NULL;
    ClearControl_Out* pClearControlOut = NULL;
    Clear_In* pClearIn = NULL;
    Clear_Out* pClearOut = NULL;

    ALLOCATEOBJECTMEMORY(ClearControl_In, pClearControlIn);
    ALLOCATEOBJECTMEMORY(ClearControl_Out, pClearControlOut);
    ALLOCATEOBJECTMEMORY(Clear_In, pClearIn);
    ALLOCATEOBJECTMEMORY(Clear_Out, pClearOut);

    // Create the session
    sessionTable[0].handle = TPM_RS_PW;

    INITIALIZE_CALL_BUFFERS(TPM2_ClearControl, pClearControlIn, pClearControlOut);
    parms.objectTableIn[TPM2_ClearControl_HdlIn_Auth].generic.handle = TPM_RH_PLATFORM;
    pClearControlIn->disable = NO;
    EXECUTE_TPM_CALL(FALSE, TPM2_ClearControl);

    INITIALIZE_CALL_BUFFERS(TPM2_Clear, pClearIn, pClearOut);
    parms.objectTableIn[TPM2_Clear_HdlIn_AuthHandle].generic.handle = TPM_RH_PLATFORM;
    EXECUTE_TPM_CALL(FALSE, TPM2_Clear);

Cleanup:
    if (result != TPM_RC_SUCCESS)
    {
        wprintf(L"FAILED: 0x%08x\n", result);
        wprintf(L"Cmd:");
        for (UINT32 n = 0; n < cbCmd; n++)
            wprintf(L"%02x ", pbCmd[n]);
        wprintf(L"\nRsp:");
        for (UINT32 n = 0; n < cbRsp; n++)
            wprintf(L"%02x ", pbRsp[n]);
        wprintf(L"\n");
    }
    FREEOBJECTMEMORY(pClearControlIn);
    FREEOBJECTMEMORY(pClearControlOut);
    FREEOBJECTMEMORY(pClearIn);
    FREEOBJECTMEMORY(pClearOut);
    return result;
}

UINT32
OwnerClear()
{
    UINT32 result = TPM_RC_SUCCESS;
    DEFINE_CALL_BUFFERS;
    ClearControl_In* pClearControlIn = NULL;
    ClearControl_Out* pClearControlOut = NULL;
    Clear_In* pClearIn = NULL;
    Clear_Out* pClearOut = NULL;

    ALLOCATEOBJECTMEMORY(ClearControl_In, pClearControlIn);
    ALLOCATEOBJECTMEMORY(ClearControl_Out, pClearControlOut);
    ALLOCATEOBJECTMEMORY(Clear_In, pClearIn);
    ALLOCATEOBJECTMEMORY(Clear_Out, pClearOut);

    wprintf(L"LockoutAuth(%d):", g_LockoutAuth.t.size);
    for (UINT n = 0; n < g_LockoutAuth.t.size; n++) wprintf(L"%02x", g_LockoutAuth.t.buffer[n]);
    wprintf(L"\n");

    // Create the session
    sessionTable[0].handle = TPM_RS_PW;

    INITIALIZE_CALL_BUFFERS(TPM2_ClearControl, pClearControlIn, pClearControlOut);
    parms.objectTableIn[TPM2_ClearControl_HdlIn_Auth].entity.handle = TPM_RH_LOCKOUT;
    parms.objectTableIn[TPM2_ClearControl_HdlIn_Auth].entity.authValue = g_LockoutAuth;
    pClearControlIn->disable = NO;
    EXECUTE_TPM_CALL(FALSE, TPM2_ClearControl);

    INITIALIZE_CALL_BUFFERS(TPM2_Clear, pClearIn, pClearOut);
    parms.objectTableIn[TPM2_Clear_HdlIn_AuthHandle].entity.handle = TPM_RH_LOCKOUT;
    parms.objectTableIn[TPM2_Clear_HdlIn_AuthHandle].entity.authValue = g_LockoutAuth;
    EXECUTE_TPM_CALL(FALSE, TPM2_Clear);

Cleanup:
    if (result != TPM_RC_SUCCESS)
    {
        wprintf(L"FAILED: 0x%08x\n", result);
        wprintf(L"Cmd:");
        for (UINT32 n = 0; n < cbCmd; n++)
            wprintf(L"%02x ", pbCmd[n]);
        wprintf(L"\nRsp:");
        for (UINT32 n = 0; n < cbRsp; n++)
            wprintf(L"%02x ", pbRsp[n]);
        wprintf(L"\n");
    }
    FREEOBJECTMEMORY(pClearControlIn);
    FREEOBJECTMEMORY(pClearControlOut);
    FREEOBJECTMEMORY(pClearIn);
    FREEOBJECTMEMORY(pClearOut);
    return result;
}


UINT32
PhysicalPresenceInterfaceClear()
{
    BYTE ppiBuffer[256] = { 0 };
    UINT32 ppiBufferSize = sizeof(ppiBuffer);
    TBS_RESULT result = TBS_SUCCESS;
    PUINT32 pInts = (PUINT32)ppiBuffer;
    BOOL cancelOp = false;

    // Look at PPI
    memset(ppiBuffer, sizeof(ppiBuffer), 0x00);
    pInts[0] = 0x00000001;
    if ((result = Tbsi_Physical_Presence_Command(g_hTbs, ppiBuffer, sizeof(DWORD), ppiBuffer, &ppiBufferSize)) != TBS_SUCCESS)
    {
        wprintf(L"Tbsi_Physical_Presence_Command failed with 0x%08x.\n", result);
        goto Cleanup;
    }
    printf("PPI Version %s available.\n", ppiBuffer);

    // Look at last operation execution results
    memset(ppiBuffer, sizeof(ppiBuffer), 0x00);
    ppiBufferSize = sizeof(ppiBuffer);
    pInts[0] = 0x00000005;

    if (((result = Tbsi_Physical_Presence_Command(g_hTbs, ppiBuffer, sizeof(DWORD), ppiBuffer, &ppiBufferSize)) != TBS_SUCCESS) ||
        (pInts[0] != 0))
    {
        wprintf(L"Tbsi_Physical_Presence_Command returned 0x%08x and FW returned 0x%08x.\n", result, pInts[0]);
        goto Cleanup;
    }

    if (pInts[1] != 0)
    {
        printf("Last Operation %d returned 0x%08x\n", pInts[1], pInts[2]);
        goto Cleanup;
    }

    // See if there is a pending operation
    memset(ppiBuffer, sizeof(ppiBuffer), 0x00);
    ppiBufferSize = sizeof(ppiBuffer);
    pInts[0] = 0x00000003;
    if (((result = Tbsi_Physical_Presence_Command(g_hTbs, ppiBuffer, sizeof(DWORD), ppiBuffer, &ppiBufferSize)) != TBS_SUCCESS) ||
        (pInts[0] != 0))
    {
        wprintf(L"Tbsi_Physical_Presence_Command returned 0x%08x and FW returned 0x%08x.\n", result, pInts[0]);
        goto Cleanup;
    }
    printf("Pending Operation %d\n", pInts[1]);
    cancelOp = (pInts[1] != 0);

    // ScheduleOp
    memset(ppiBuffer, sizeof(ppiBuffer), 0x00);
    ppiBufferSize = sizeof(ppiBuffer);
    pInts[0] = 0x00000002;
    if (cancelOp)
    {
        pInts[1] = 0;
        printf("Cancel pending operation.\n");
    }
    else
    {
        pInts[1] = 22;
        printf("Request operation 22 (Enable,Activate,Clear,Enable,Activate).\n");
    }
    if ((result = Tbsi_Physical_Presence_Command(g_hTbs, ppiBuffer, sizeof(DWORD)* 2, ppiBuffer, &ppiBufferSize)) != TBS_SUCCESS)
    {
        wprintf(L"Tbsi_Physical_Presence_Command returned 0x%08x and FW returned 0x%08x.\n", result, pInts[0]);
        goto Cleanup;
    }

Cleanup:
    return result;
}

UINT32
TestAES128Key()
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    Create_In* pCreateIn = NULL;
    Create_Out* pCreateOut = NULL;
    Load_In* pLoadIn = NULL;
    Load_Out* pLoadOut = NULL;
    EncryptDecrypt_In* pEncryptDecryptIn = NULL;
    EncryptDecrypt_Out* pEncryptDecryptOut = NULL;
    FlushContext_In* pFlushContextIn = NULL;
    FlushContext_Out* pFlushContextOut = NULL;
    ULONGLONG startTime = 0;
    ULONGLONG stopTime = 0;
    ULONGLONG timeSum = 0;
    const char usageAuth[] = "ThisIsASecretUsageAuth";
    ANY_OBJECT aesKey = { 0 };

    ALLOCATEOBJECTMEMORY(Create_In, pCreateIn);
    ALLOCATEOBJECTMEMORY(Create_Out, pCreateOut);
    ALLOCATEOBJECTMEMORY(Load_In, pLoadIn);
    ALLOCATEOBJECTMEMORY(Load_Out, pLoadOut);
    ALLOCATEOBJECTMEMORY(EncryptDecrypt_In, pEncryptDecryptIn);
    ALLOCATEOBJECTMEMORY(EncryptDecrypt_Out, pEncryptDecryptOut);
    ALLOCATEOBJECTMEMORY(FlushContext_In, pFlushContextIn);
    ALLOCATEOBJECTMEMORY(FlushContext_Out, pFlushContextOut);

    // Create the session
    sessionTable[0].handle = TPM_RS_PW;

    // Create random AES key
    INITIALIZE_CALL_BUFFERS(TPM2_Create, pCreateIn, pCreateOut);
    parms.objectTableIn[TPM2_Create_HdlIn_ParentHandle].generic.handle = TPM_20_SRK_HANDLE;
    pCreateIn->inSensitive.t.sensitive.userAuth.t.size = (UINT16)strlen(usageAuth);
    MemoryCopy(pCreateIn->inSensitive.t.sensitive.userAuth.t.buffer, usageAuth, pCreateIn->inSensitive.t.sensitive.userAuth.t.size, sizeof(pCreateIn->inSensitive.t.sensitive.userAuth.t.buffer));
    pCreateIn->inPublic.t.publicArea.type = TPM_ALG_SYMCIPHER;
    pCreateIn->inPublic.t.publicArea.nameAlg = TPM_ALG_SHA256;
    pCreateIn->inPublic.t.publicArea.objectAttributes.sensitiveDataOrigin = 1;
    pCreateIn->inPublic.t.publicArea.objectAttributes.userWithAuth = 1;
    pCreateIn->inPublic.t.publicArea.objectAttributes.noDA = 1;
    pCreateIn->inPublic.t.publicArea.objectAttributes.decrypt = 1;
    pCreateIn->inPublic.t.publicArea.parameters.symDetail.algorithm = TPM_ALG_AES;
    pCreateIn->inPublic.t.publicArea.parameters.symDetail.keyBits.aes = MAX_AES_KEY_BITS;
    pCreateIn->inPublic.t.publicArea.parameters.symDetail.mode.aes = TPM_ALG_CBC;
    startTime = GetTickCount64();
    EXECUTE_TPM_CALL(FALSE, TPM2_Create);
    stopTime = GetTickCount64();
    aesKey.obj.publicArea = pCreateOut->outPublic;
    aesKey.obj.privateArea = pCreateOut->outPrivate;
    aesKey.obj.authValue = pCreateIn->inSensitive.t.sensitive.userAuth;

    timeSum += stopTime - startTime;

    // Load the key
    INITIALIZE_CALL_BUFFERS(TPM2_Load, pLoadIn, pLoadOut);
    parms.objectTableIn[TPM2_Load_HdlIn_ParentHandle].generic.handle = TPM_20_SRK_HANDLE;
    parms.objectTableOut[TPM2_Load_HdlOut_ObjectHandle] = aesKey; // Copy the key in to be updated
    pLoadIn->inPublic = aesKey.obj.publicArea;
    pLoadIn->inPrivate = aesKey.obj.privateArea;
    startTime = GetTickCount64();
    EXECUTE_TPM_CALL(FALSE, TPM2_Load);
    stopTime = GetTickCount64();
    aesKey = parms.objectTableOut[TPM2_Load_HdlOut_ObjectHandle]; // Copy the object back out

    wprintf(L"AES128 Key Name:\n");
    for (UINT32 n = 0; n < pLoadOut->name.t.size; n++)
    {
        wprintf(L"%02x", pLoadOut->name.t.name[n]);
    }
    wprintf(L"\n");
    wprintf(L"Create: %I64dms\n", timeSum);

    wprintf(L"Load: %I64dms\n", stopTime - startTime);
    timeSum += stopTime - startTime;

    INITIALIZE_CALL_BUFFERS(TPM2_EncryptDecrypt, pEncryptDecryptIn, pEncryptDecryptOut);
    parms.objectTableIn[TPM2_EncryptDecrypt_HdlIn_KeyHandle] = aesKey;
    pEncryptDecryptIn->decrypt = NO;
    pEncryptDecryptIn->mode = TPM_ALG_CBC;
    pEncryptDecryptIn->ivIn.t.size = MAX_AES_BLOCK_SIZE_BYTES;
    MemorySet(pEncryptDecryptIn->ivIn.t.buffer, 0x00, pEncryptDecryptIn->ivIn.t.size);
    pEncryptDecryptIn->inData.t.size = MAX_AES_BLOCK_SIZE_BYTES;
    MemorySet(pEncryptDecryptIn->inData.t.buffer, 0x00, pEncryptDecryptIn->inData.t.size);
    startTime = GetTickCount64();
    EXECUTE_TPM_CALL(FALSE, TPM2_EncryptDecrypt);
    stopTime = GetTickCount64();

    wprintf(L"Encrypt: %I64dms\n", stopTime - startTime);
    timeSum += stopTime - startTime;

    INITIALIZE_CALL_BUFFERS(TPM2_EncryptDecrypt, pEncryptDecryptIn, pEncryptDecryptOut);
    parms.objectTableIn[TPM2_EncryptDecrypt_HdlIn_KeyHandle] = aesKey;
    pEncryptDecryptIn->decrypt = YES;
    pEncryptDecryptIn->mode = TPM_ALG_CBC;
    pEncryptDecryptIn->ivIn.t.size = MAX_AES_BLOCK_SIZE_BYTES;
    MemorySet(pEncryptDecryptIn->ivIn.t.buffer, 0x00, pEncryptDecryptIn->ivIn.t.size);
    pEncryptDecryptIn->inData.t.size = pEncryptDecryptOut->outData.t.size;
    MemoryCopy(pEncryptDecryptIn->inData.t.buffer, pEncryptDecryptOut->outData.t.buffer, pEncryptDecryptOut->outData.t.size, sizeof(pEncryptDecryptIn->inData.t.buffer));
    startTime = GetTickCount64();
    EXECUTE_TPM_CALL(FALSE, TPM2_EncryptDecrypt);
    stopTime = GetTickCount64();

    wprintf(L"Decrypt: %I64dms\n", stopTime - startTime);
    timeSum += stopTime - startTime;

    // Unload the AES key
    INITIALIZE_CALL_BUFFERS(TPM2_FlushContext, pFlushContextIn, pFlushContextOut);
    parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle] = aesKey;
    startTime = GetTickCount64();
    EXECUTE_TPM_CALL(FALSE, TPM2_FlushContext);
    stopTime = GetTickCount64();

    // Copy the updated AES back out
    aesKey = parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle];

    wprintf(L"Unload: %I64dms\n", stopTime - startTime);
    timeSum += stopTime - startTime;

    wprintf(L"Total: %I64dms\n", timeSum);

Cleanup:
    if (result != TPM_RC_SUCCESS)
    {
        wprintf(L"FAILED: 0x%08x\n", result);
        wprintf(L"Cmd:");
        for (UINT32 n = 0; n < cbCmd; n++)
            wprintf(L"%02x ", pbCmd[n]);
        wprintf(L"\nRsp:");
        for (UINT32 n = 0; n < cbRsp; n++)
            wprintf(L"%02x ", pbRsp[n]);
        wprintf(L"\n");
    }
    FREEOBJECTMEMORY(pCreateIn);
    FREEOBJECTMEMORY(pCreateOut);
    FREEOBJECTMEMORY(pLoadIn);
    FREEOBJECTMEMORY(pLoadOut);
    FREEOBJECTMEMORY(pEncryptDecryptIn);
    FREEOBJECTMEMORY(pEncryptDecryptOut);
    FREEOBJECTMEMORY(pFlushContextIn);
    FREEOBJECTMEMORY(pFlushContextOut);
    return result;
}

UINT32
TestECDSAP256Key()
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    Create_In* pCreateIn = NULL;
    Create_Out* pCreateOut = NULL;
    Load_In* pLoadIn = NULL;
    Load_Out* pLoadOut = NULL;
    Sign_In* pSignIn = NULL;
    Sign_Out* pSignOut = NULL;
    VerifySignature_In* pVerifySignatureIn = NULL;
    VerifySignature_Out* pVerifySignatureOut = NULL;
    FlushContext_In* pFlushContextIn = NULL;
    FlushContext_Out* pFlushContextOut = NULL;
    ULONGLONG startTime = 0;
    ULONGLONG stopTime = 0;
    ULONGLONG timeSum = 0;
    const char usageAuth[] = "ThisIsASecretUsageAuth";
    ANY_OBJECT ecdsaKey = { 0 };

    ALLOCATEOBJECTMEMORY(Create_In, pCreateIn);
    ALLOCATEOBJECTMEMORY(Create_Out, pCreateOut);
    ALLOCATEOBJECTMEMORY(Load_In, pLoadIn);
    ALLOCATEOBJECTMEMORY(Load_Out, pLoadOut);
    ALLOCATEOBJECTMEMORY(Sign_In, pSignIn);
    ALLOCATEOBJECTMEMORY(Sign_Out, pSignOut);
    ALLOCATEOBJECTMEMORY(VerifySignature_In, pVerifySignatureIn);
    ALLOCATEOBJECTMEMORY(VerifySignature_Out, pVerifySignatureOut);
    ALLOCATEOBJECTMEMORY(FlushContext_In, pFlushContextIn);
    ALLOCATEOBJECTMEMORY(FlushContext_Out, pFlushContextOut);

    // Create the session
    sessionTable[0].handle = TPM_RS_PW;

    // Create random RSA key
    INITIALIZE_CALL_BUFFERS(TPM2_Create, pCreateIn, pCreateOut);
    parms.objectTableIn[TPM2_Create_HdlIn_ParentHandle].generic.handle = TPM_20_SRK_HANDLE;
    pCreateIn->inSensitive.t.sensitive.userAuth.t.size = (UINT16)strlen(usageAuth);
    MemoryCopy(pCreateIn->inSensitive.t.sensitive.userAuth.t.buffer, usageAuth, pCreateIn->inSensitive.t.sensitive.userAuth.t.size, sizeof(pCreateIn->inSensitive.t.sensitive.userAuth.t.buffer));
    pCreateIn->inPublic.t.publicArea.type = TPM_ALG_ECC;
    pCreateIn->inPublic.t.publicArea.nameAlg = TPM_ALG_SHA256;
    pCreateIn->inPublic.t.publicArea.objectAttributes.fixedTPM = 1;
    pCreateIn->inPublic.t.publicArea.objectAttributes.fixedParent = 1;
    pCreateIn->inPublic.t.publicArea.objectAttributes.sensitiveDataOrigin = 1;
    pCreateIn->inPublic.t.publicArea.objectAttributes.userWithAuth = 1;
    pCreateIn->inPublic.t.publicArea.objectAttributes.noDA = 1;
    pCreateIn->inPublic.t.publicArea.objectAttributes.sign = 1;
    pCreateIn->inPublic.t.publicArea.parameters.symDetail.algorithm = TPM_ALG_NULL;
    pCreateIn->inPublic.t.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
    pCreateIn->inPublic.t.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_ECDSA;
    pCreateIn->inPublic.t.publicArea.parameters.eccDetail.scheme.details.ecdsa.hashAlg = TPM_ALG_SHA256;
    pCreateIn->inPublic.t.publicArea.parameters.eccDetail.curveID = TPM_ECC_NIST_P256;
    pCreateIn->inPublic.t.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
    startTime = GetTickCount64();
    EXECUTE_TPM_CALL(FALSE, TPM2_Create);
    stopTime = GetTickCount64();
    ecdsaKey.obj.publicArea = pCreateOut->outPublic;
    ecdsaKey.obj.privateArea = pCreateOut->outPrivate;
    ecdsaKey.obj.authValue = pCreateIn->inSensitive.t.sensitive.userAuth;

    timeSum += stopTime - startTime;

    // Load the key
    INITIALIZE_CALL_BUFFERS(TPM2_Load, pLoadIn, pLoadOut);
    parms.objectTableIn[TPM2_Load_HdlIn_ParentHandle].generic.handle = TPM_20_SRK_HANDLE;
    parms.objectTableOut[TPM2_Load_HdlOut_ObjectHandle] = ecdsaKey; // Copy the key in to be updated
    pLoadIn->inPublic = ecdsaKey.obj.publicArea;
    pLoadIn->inPrivate = ecdsaKey.obj.privateArea;
    startTime = GetTickCount64();
    EXECUTE_TPM_CALL(FALSE, TPM2_Load);
    stopTime = GetTickCount64();
    ecdsaKey = parms.objectTableOut[TPM2_Load_HdlOut_ObjectHandle]; // Copy the object back out

    wprintf(L"ECDSA-P256 Key Name:\n");
    for (UINT32 n = 0; n < pLoadOut->name.t.size; n++)
    {
        wprintf(L"%02x", pLoadOut->name.t.name[n]);
    }
    wprintf(L"\n");
    wprintf(L"Create: %I64dms\n", timeSum);

    wprintf(L"Load: %I64dms\n", stopTime - startTime);
    timeSum += stopTime - startTime;

    INITIALIZE_CALL_BUFFERS(TPM2_Sign, pSignIn, pSignOut);
    parms.objectTableIn[TPM2_Sign_HdlIn_KeyHandle] = ecdsaKey;
    pSignIn->digest.t.size = SHA256_DIGEST_SIZE;
    MemorySet((TPM2B*)&pSignIn->digest.t.buffer, 0x11, pSignIn->digest.t.size);
    pSignIn->inScheme.scheme = TPM_ALG_ECDSA;
    pSignIn->inScheme.details.ecdsa.hashAlg = TPM_ALG_SHA256;
    pSignIn->validation.tag = TPM_ST_HASHCHECK;
    pSignIn->validation.hierarchy = TPM_RH_NULL;
    startTime = GetTickCount64();
    EXECUTE_TPM_CALL(FALSE, TPM2_Sign);
    stopTime = GetTickCount64();

    wprintf(L"Sign: %I64dms\n", stopTime - startTime);
    timeSum += stopTime - startTime;

    INITIALIZE_CALL_BUFFERS(TPM2_VerifySignature, pVerifySignatureIn, pVerifySignatureOut);
    parms.objectTableIn[TPM2_VerifySignature_HdlIn_KeyHandle] = ecdsaKey;
    pVerifySignatureIn->digest = pSignIn->digest;
    pVerifySignatureIn->signature = pSignOut->signature;
    startTime = GetTickCount64();
    EXECUTE_TPM_CALL(FALSE, TPM2_VerifySignature);
    stopTime = GetTickCount64();

    wprintf(L"Verify: %I64dms\n", stopTime - startTime);
    timeSum += stopTime - startTime;

    // Unload the RSA key
    INITIALIZE_CALL_BUFFERS(TPM2_FlushContext, pFlushContextIn, pFlushContextOut);
    parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle] = ecdsaKey;
    startTime = GetTickCount64();
    EXECUTE_TPM_CALL(FALSE, TPM2_FlushContext);
    stopTime = GetTickCount64();

    // Copy the updated RSA back out
    ecdsaKey = parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle];

    wprintf(L"Unload: %I64dms\n", stopTime - startTime);
    timeSum += stopTime - startTime;

    wprintf(L"Total: %I64dms\n", timeSum);

Cleanup:
    if (result != TPM_RC_SUCCESS)
    {
        wprintf(L"FAILED: 0x%08x\n", result);
        wprintf(L"Cmd:");
        for (UINT32 n = 0; n < cbCmd; n++)
            wprintf(L"%02x ", pbCmd[n]);
        wprintf(L"\nRsp:");
        for (UINT32 n = 0; n < cbRsp; n++)
            wprintf(L"%02x ", pbRsp[n]);
        wprintf(L"\n");
    }
    FREEOBJECTMEMORY(pCreateIn);
    FREEOBJECTMEMORY(pCreateOut);
    FREEOBJECTMEMORY(pLoadIn);
    FREEOBJECTMEMORY(pLoadOut);
    FREEOBJECTMEMORY(pSignIn);
    FREEOBJECTMEMORY(pSignOut);
    FREEOBJECTMEMORY(pVerifySignatureIn);
    FREEOBJECTMEMORY(pVerifySignatureOut);
    FREEOBJECTMEMORY(pFlushContextIn);
    FREEOBJECTMEMORY(pFlushContextOut);
    return result;
}

UINT32
TestHMACKey()
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    Create_In* pCreateIn = NULL;
    Create_Out* pCreateOut = NULL;
    Load_In* pLoadIn = NULL;
    Load_Out* pLoadOut = NULL;
    HMAC_In* pHmacIn = NULL;
    HMAC_Out* pHmacOut = NULL;
    FlushContext_In* pFlushContextIn = NULL;
    FlushContext_Out* pFlushContextOut = NULL;
    ULONGLONG startTime = 0;
    ULONGLONG stopTime = 0;
    ULONGLONG timeSum = 0;
    const char usageAuth[] = "ThisIsASecretUsageAuth";
    ANY_OBJECT hmacKey = { 0 };

    ALLOCATEOBJECTMEMORY(Create_In, pCreateIn);
    ALLOCATEOBJECTMEMORY(Create_Out, pCreateOut);
    ALLOCATEOBJECTMEMORY(Load_In, pLoadIn);
    ALLOCATEOBJECTMEMORY(Load_Out, pLoadOut);
    ALLOCATEOBJECTMEMORY(HMAC_In, pHmacIn);
    ALLOCATEOBJECTMEMORY(HMAC_Out, pHmacOut);
    ALLOCATEOBJECTMEMORY(FlushContext_In, pFlushContextIn);
    ALLOCATEOBJECTMEMORY(FlushContext_Out, pFlushContextOut);

    // Create the session
    sessionTable[0].handle = TPM_RS_PW;

    // Create random AES key
    INITIALIZE_CALL_BUFFERS(TPM2_Create, pCreateIn, pCreateOut);
    parms.objectTableIn[TPM2_Create_HdlIn_ParentHandle].generic.handle = TPM_20_SRK_HANDLE;
    pCreateIn->inSensitive.t.sensitive.userAuth.t.size = (UINT16)strlen(usageAuth);
    MemoryCopy(pCreateIn->inSensitive.t.sensitive.userAuth.t.buffer, usageAuth, pCreateIn->inSensitive.t.sensitive.userAuth.t.size, sizeof(pCreateIn->inSensitive.t.sensitive.userAuth.t.buffer));
    pCreateIn->inPublic.t.publicArea.type = TPM_ALG_KEYEDHASH;
    pCreateIn->inPublic.t.publicArea.nameAlg = TPM_ALG_SHA256;
    pCreateIn->inPublic.t.publicArea.objectAttributes.sensitiveDataOrigin = 1;
    pCreateIn->inPublic.t.publicArea.objectAttributes.userWithAuth = 1;
    pCreateIn->inPublic.t.publicArea.objectAttributes.noDA = 1;
    pCreateIn->inPublic.t.publicArea.objectAttributes.sign = 1;
    pCreateIn->inPublic.t.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_HMAC;
    pCreateIn->inPublic.t.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = TPM_ALG_SHA256;
    startTime = GetTickCount64();
    EXECUTE_TPM_CALL(FALSE, TPM2_Create);
    stopTime = GetTickCount64();
    hmacKey.obj.publicArea = pCreateOut->outPublic;
    hmacKey.obj.privateArea = pCreateOut->outPrivate;
    hmacKey.obj.authValue = pCreateIn->inSensitive.t.sensitive.userAuth;

    timeSum += stopTime - startTime;

    // Load the key
    INITIALIZE_CALL_BUFFERS(TPM2_Load, pLoadIn, pLoadOut);
    parms.objectTableIn[TPM2_Load_HdlIn_ParentHandle].generic.handle = TPM_20_SRK_HANDLE;
    parms.objectTableOut[TPM2_Load_HdlOut_ObjectHandle] = hmacKey; // Copy the key in to be updated
    pLoadIn->inPublic = hmacKey.obj.publicArea;
    pLoadIn->inPrivate = hmacKey.obj.privateArea;
    startTime = GetTickCount64();
    EXECUTE_TPM_CALL(FALSE, TPM2_Load);
    stopTime = GetTickCount64();
    hmacKey = parms.objectTableOut[TPM2_Load_HdlOut_ObjectHandle]; // Copy the object back out

    wprintf(L"HMAC Key Name:\n");
    for (UINT32 n = 0; n < pLoadOut->name.t.size; n++)
    {
        wprintf(L"%02x", pLoadOut->name.t.name[n]);
    }
    wprintf(L"\n");
    wprintf(L"Create: %I64dms\n", timeSum);

    wprintf(L"Load: %I64dms\n", stopTime - startTime);
    timeSum += stopTime - startTime;

    INITIALIZE_CALL_BUFFERS(TPM2_HMAC, pHmacIn, pHmacOut);
    parms.objectTableIn[TPM2_HMAC_HdlIn_Handle] = hmacKey;
    pHmacIn->buffer.t.size = SHA256_DIGEST_SIZE;
    pHmacIn->hashAlg = TPM_ALG_SHA256;
    startTime = GetTickCount64();
    EXECUTE_TPM_CALL(FALSE, TPM2_HMAC);
    stopTime = GetTickCount64();

    wprintf(L"HMAC: %I64dms\n", stopTime - startTime);
    timeSum += stopTime - startTime;

    // Unload the HMAC key
    INITIALIZE_CALL_BUFFERS(TPM2_FlushContext, pFlushContextIn, pFlushContextOut);
    parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle] = hmacKey;
    startTime = GetTickCount64();
    EXECUTE_TPM_CALL(FALSE, TPM2_FlushContext);
    stopTime = GetTickCount64();

    // Copy the updated AES back out
    hmacKey = parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle];

    wprintf(L"Unload: %I64dms\n", stopTime - startTime);
    timeSum += stopTime - startTime;

    wprintf(L"Total: %I64dms\n", timeSum);

Cleanup:
    if (result != TPM_RC_SUCCESS)
    {
        wprintf(L"FAILED: 0x%08x\n", result);
        wprintf(L"Cmd:");
        for (UINT32 n = 0; n < cbCmd; n++)
            wprintf(L"%02x ", pbCmd[n]);
        wprintf(L"\nRsp:");
        for (UINT32 n = 0; n < cbRsp; n++)
            wprintf(L"%02x ", pbRsp[n]);
        wprintf(L"\n");
    }
    FREEOBJECTMEMORY(pCreateIn);
    FREEOBJECTMEMORY(pCreateOut);
    FREEOBJECTMEMORY(pLoadIn);
    FREEOBJECTMEMORY(pLoadOut);
    FREEOBJECTMEMORY(pHmacIn);
    FREEOBJECTMEMORY(pHmacOut);
    FREEOBJECTMEMORY(pFlushContextIn);
    FREEOBJECTMEMORY(pFlushContextOut);
    return result;
}

UINT32
TestRSA2048Key()
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    Create_In* pCreateIn = NULL;
    Create_Out* pCreateOut = NULL;
    Load_In* pLoadIn = NULL;
    Load_Out* pLoadOut = NULL;
    Sign_In* pSignIn = NULL;
    Sign_Out* pSignOut = NULL;
    VerifySignature_In* pVerifySignatureIn = NULL;
    VerifySignature_Out* pVerifySignatureOut = NULL;
    FlushContext_In* pFlushContextIn = NULL;
    FlushContext_Out* pFlushContextOut = NULL;
    ULONGLONG startTime = 0;
    ULONGLONG stopTime = 0;
    ULONGLONG timeSum = 0;
    const char usageAuth[] = "ThisIsASecretUsageAuth";
    ANY_OBJECT rsaKey = { 0 };

    ALLOCATEOBJECTMEMORY(Create_In, pCreateIn);
    ALLOCATEOBJECTMEMORY(Create_Out, pCreateOut);
    ALLOCATEOBJECTMEMORY(Load_In, pLoadIn);
    ALLOCATEOBJECTMEMORY(Load_Out, pLoadOut);
    ALLOCATEOBJECTMEMORY(Sign_In, pSignIn);
    ALLOCATEOBJECTMEMORY(Sign_Out, pSignOut);
    ALLOCATEOBJECTMEMORY(VerifySignature_In, pVerifySignatureIn);
    ALLOCATEOBJECTMEMORY(VerifySignature_Out, pVerifySignatureOut);
    ALLOCATEOBJECTMEMORY(FlushContext_In, pFlushContextIn);
    ALLOCATEOBJECTMEMORY(FlushContext_Out, pFlushContextOut);

    // Create the session
    sessionTable[0].handle = TPM_RS_PW;

    // Create random RSA key
    INITIALIZE_CALL_BUFFERS(TPM2_Create, pCreateIn, pCreateOut);
    parms.objectTableIn[TPM2_Create_HdlIn_ParentHandle].generic.handle = TPM_20_SRK_HANDLE;
    pCreateIn->inSensitive.t.sensitive.userAuth.t.size = (UINT16)strlen(usageAuth);
    MemoryCopy(pCreateIn->inSensitive.t.sensitive.userAuth.t.buffer, usageAuth, pCreateIn->inSensitive.t.sensitive.userAuth.t.size, sizeof(pCreateIn->inSensitive.t.sensitive.userAuth.t.buffer));
    pCreateIn->inPublic.t.publicArea.type = TPM_ALG_RSA;
    pCreateIn->inPublic.t.publicArea.nameAlg = TPM_ALG_SHA256;
    pCreateIn->inPublic.t.publicArea.objectAttributes.fixedTPM = 1;
    pCreateIn->inPublic.t.publicArea.objectAttributes.fixedParent = 1;
    pCreateIn->inPublic.t.publicArea.objectAttributes.sensitiveDataOrigin = 1;
    pCreateIn->inPublic.t.publicArea.objectAttributes.userWithAuth = 1;
    pCreateIn->inPublic.t.publicArea.objectAttributes.noDA = 1;
    pCreateIn->inPublic.t.publicArea.objectAttributes.decrypt = 1;
    pCreateIn->inPublic.t.publicArea.objectAttributes.sign = 1;
    pCreateIn->inPublic.t.publicArea.parameters.symDetail.algorithm = TPM_ALG_NULL;
    pCreateIn->inPublic.t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
    pCreateIn->inPublic.t.publicArea.parameters.rsaDetail.keyBits = 2048;
    pCreateIn->inPublic.t.publicArea.unique.rsa.b.size = 256;
    startTime = GetTickCount64();
    EXECUTE_TPM_CALL(FALSE, TPM2_Create);
    stopTime = GetTickCount64();
    rsaKey.obj.publicArea = pCreateOut->outPublic;
    rsaKey.obj.privateArea = pCreateOut->outPrivate;
    rsaKey.obj.authValue = pCreateIn->inSensitive.t.sensitive.userAuth;
    timeSum = stopTime - startTime;

    // Load the key
    INITIALIZE_CALL_BUFFERS(TPM2_Load, pLoadIn, pLoadOut);
    parms.objectTableIn[TPM2_Load_HdlIn_ParentHandle].generic.handle = TPM_20_SRK_HANDLE;
    parms.objectTableOut[TPM2_Load_HdlOut_ObjectHandle] = rsaKey; // Copy the key in to be updated
    pLoadIn->inPublic = rsaKey.obj.publicArea;
    pLoadIn->inPrivate = rsaKey.obj.privateArea;
    startTime = GetTickCount64();
    EXECUTE_TPM_CALL(FALSE, TPM2_Load);
    stopTime = GetTickCount64();
    rsaKey = parms.objectTableOut[TPM2_Load_HdlOut_ObjectHandle]; // Copy the object back out

    wprintf(L"RSA2048 Key Name:\n");
    for (UINT32 n = 0; n < pLoadOut->name.t.size; n++)
    {
        wprintf(L"%02x", pLoadOut->name.t.name[n]);
    }
    wprintf(L"\n");
    wprintf(L"Create: %I64dms\n", timeSum);

    wprintf(L"Load: %I64dms\n", stopTime - startTime);
    timeSum += stopTime - startTime;

    INITIALIZE_CALL_BUFFERS(TPM2_Sign, pSignIn, pSignOut);
    parms.objectTableIn[TPM2_Sign_HdlIn_KeyHandle] = rsaKey;
    pSignIn->digest.t.size = SHA256_DIGEST_SIZE;
    MemorySet((TPM2B*)&pSignIn->digest.t.buffer, 0x11, pSignIn->digest.t.size);
    pSignIn->inScheme.scheme = TPM_ALG_RSAPSS;
    pSignIn->inScheme.details.rsapss.hashAlg = TPM_ALG_SHA256;
    pSignIn->validation.tag = TPM_ST_HASHCHECK;
    pSignIn->validation.hierarchy = TPM_RH_NULL;
    startTime = GetTickCount64();
    EXECUTE_TPM_CALL(FALSE, TPM2_Sign);
    stopTime = GetTickCount64();

    wprintf(L"Sign: %I64dms\n", stopTime - startTime);
    timeSum += stopTime - startTime;

    INITIALIZE_CALL_BUFFERS(TPM2_VerifySignature, pVerifySignatureIn, pVerifySignatureOut);
    parms.objectTableIn[TPM2_VerifySignature_HdlIn_KeyHandle] = rsaKey;
    pVerifySignatureIn->digest = pSignIn->digest;
    pVerifySignatureIn->signature = pSignOut->signature;
    startTime = GetTickCount64();
    EXECUTE_TPM_CALL(FALSE, TPM2_VerifySignature);
    stopTime = GetTickCount64();

    wprintf(L"Verify: %I64dms\n", stopTime - startTime);
    timeSum += stopTime - startTime;

    // Unload the RSA key
    INITIALIZE_CALL_BUFFERS(TPM2_FlushContext, pFlushContextIn, pFlushContextOut);
    parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle] = rsaKey;
    startTime = GetTickCount64();
    EXECUTE_TPM_CALL(FALSE, TPM2_FlushContext);
    stopTime = GetTickCount64();

    // Copy the updated RSA back out
    rsaKey = parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle];

    wprintf(L"Unload: %I64dms\n", stopTime - startTime);
    timeSum += stopTime - startTime;

    wprintf(L"Total: %I64dms\n", timeSum);

Cleanup:
    if (result != TPM_RC_SUCCESS)
    {
        wprintf(L"FAILED: 0x%08x\n", result);
        wprintf(L"Cmd:");
        for (UINT32 n = 0; n < cbCmd; n++)
            wprintf(L"%02x ", pbCmd[n]);
        wprintf(L"\nRsp:");
        for (UINT32 n = 0; n < cbRsp; n++)
            wprintf(L"%02x ", pbRsp[n]);
        wprintf(L"\n");
    }
    return result;
}

UINT32
TestCNG()
{
    HRESULT hr = S_OK;
    NCRYPT_PROV_HANDLE hProv = NULL;
    NCRYPT_KEY_HANDLE hKey = NULL;
    PCTSTR keyName = TEXT("T2T-TestKey");
    BCRYPT_PKCS1_PADDING_INFO padding = { BCRYPT_SHA1_ALGORITHM };
    BYTE hash[20] = { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };
    BYTE signature[256] = { 0 };
    DWORD sigSize = 0;
    BYTE pubkey[1024] = { 0 };
    DWORD pubkeySize = 0;
    ULONGLONG startTime = 0;
    ULONGLONG stopTime = 0;
    ULONGLONG timeSum = 0;

    startTime = GetTickCount64();
    if (FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenStorageProvider(&hProv,
        MS_PLATFORM_CRYPTO_PROVIDER,
        0))))
    {
        goto Cleanup;
    }
    stopTime = GetTickCount64();
    wprintf(L"NCryptOpenStorageProvider: %I64dms\n", stopTime - startTime);
    timeSum += stopTime - startTime;

    startTime = GetTickCount64();
    if (FAILED(hr = HRESULT_FROM_WIN32(NCryptCreatePersistedKey(hProv,
        &hKey,
        BCRYPT_RSA_ALGORITHM,
        keyName,
        0,
        NCRYPT_OVERWRITE_KEY_FLAG))))
    {
        goto Cleanup;
    }
    stopTime = GetTickCount64();
    wprintf(L"NCryptCreatePersistedKey: %I64dms\n", stopTime - startTime);
    timeSum += stopTime - startTime;

    startTime = GetTickCount64();
    if (FAILED(hr = HRESULT_FROM_WIN32(NCryptFinalizeKey(hKey,
        0))))
    {
        goto Cleanup;
    }
    stopTime = GetTickCount64();
    wprintf(L"NCryptFinalizeKey: %I64dms\n", stopTime - startTime);
    timeSum += stopTime - startTime;

    startTime = GetTickCount64();
    if (FAILED(hr = HRESULT_FROM_WIN32(NCryptExportKey(hKey,
        NULL,
        BCRYPT_RSAPUBLIC_BLOB,
        NULL,
        pubkey,
        sizeof(pubkey),
        &pubkeySize,
        0))))
    {
        goto Cleanup;
    }
    stopTime = GetTickCount64();
    wprintf(L"NCryptExportKey: %I64dms\n", stopTime - startTime);
    timeSum += stopTime - startTime;

    startTime = GetTickCount64();
    if (FAILED(hr = HRESULT_FROM_WIN32(NCryptSignHash(hKey,
        &padding,
        hash,
        sizeof(hash),
        signature,
        sizeof(signature),
        &sigSize,
        BCRYPT_PAD_PKCS1))))
    {
        goto Cleanup;
    }
    stopTime = GetTickCount64();
    wprintf(L"NCryptSignHash: %I64dms\n", stopTime - startTime);
    timeSum += stopTime - startTime;

    wprintf(L"Total: %I64dms\n", timeSum);

    if (FAILED(hr = HRESULT_FROM_WIN32(NCryptFreeObject(hKey))))
    {
        goto Cleanup;
    }
    hKey = NULL;

    if (FAILED(hr = HRESULT_FROM_WIN32(NCryptFreeObject(hProv))))
    {
        goto Cleanup;
    }
    hProv = NULL;

    if (FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenStorageProvider(&hProv,
        NULL,
        0))))
    {
        goto Cleanup;
    }

    if (FAILED(hr = HRESULT_FROM_WIN32(NCryptImportKey(hProv,
        NULL,
        BCRYPT_RSAPUBLIC_BLOB,
        NULL,
        &hKey,
        pubkey,
        pubkeySize,
        0))))
    {
        goto Cleanup;
    }

    if (FAILED(hr = HRESULT_FROM_WIN32(NCryptVerifySignature(hKey,
        &padding,
        hash,
        sizeof(hash),
        signature,
        sigSize,
        BCRYPT_PAD_PKCS1))))
    {
        goto Cleanup;
    }
    wprintf(L"Signature: Valid!\n");


Cleanup:
    if (hKey != NULL)
    {
        NCryptFreeObject(hKey);
        hKey = NULL;
    }
    if (hProv != NULL)
    {
        NCryptFreeObject(hProv);
        hProv = NULL;
    }
    if (hr != S_OK)
    {
        wprintf(L"Error: hr = 0x%08x\n", hr);
    }
    return hr;
}

void
GetHelp(
)
{
    wprintf(L"Microsoft Tpm2ToolKit V1.0.\nStefan Thom, stefanth@microsoft.com, 2014\n");

    wprintf(L"Commands:\n");
    wprintf(L" -GAV  - Get TPM AuthValues\n");
    wprintf(L" -Ppi  - Physical Presence Interface Info\n");
    wprintf(L" -Log  - TCG Log Info\n");
    wprintf(L" -Cap  - Get TPM capabilities\n");
    wprintf(L" -NvK  - Enumerate all persistent keys in NV\n");
    wprintf(L" -NvO  - Enumerate all NV objects\n");
    wprintf(L" -Ord  - Dump missing ordinals\n");
    wprintf(L" -Alg  - Dump supported algorithms and curves\n");
    wprintf(L" -CPh  - Clear with Platform Hierachy\n");
    wprintf(L" -CLA  - Clear with LockoutAuth\n");
    wprintf(L" -CPP  - Clear with Physical Presence Interface\n");
    wprintf(L" -RPR  - Read Platform Configuration Registers\n");
    wprintf(L" -EDP  - Extend debug PCR\n");
    wprintf(L" -RDP  - Reset debug PCR\n");
    wprintf(L" -RCl  - Read Clock\n");
    wprintf(L" -TAK  - Test AES 128bit Key\n");
    wprintf(L" -TEK  - Test ECDSA P-256 Key\n");
    wprintf(L" -THK  - Test HMAC Key\n");
    wprintf(L" -TRK  - Test RSA 2048bit Key\n");
    wprintf(L" -CNG  - Test PCPKSP key creation and usage\n");
    wprintf(L"\nSwitch:\n");
    wprintf(L" -BoE  - Break into the debugger on entry\n");
}

UINT32
__cdecl
wmain(
__in INT32 argc,
__in_ecount(argc) LPCWSTR argv[]
)
{
    HRESULT hr = S_OK;
    TBS_RESULT result = TBS_SUCCESS;
    WCHAR* command = 0;
    HANDLE hFile = INVALID_HANDLE_VALUE;

    _cpri__RngStartup();
    _cpri__HashStartup();
    _cpri__RsaStartup();
    _cpri__SymStartup();
    PlattformRetrieveAuthValues();

    if (argc <= 1)
    {
        GetHelp();
        goto Cleanup;
    }
    command = (WCHAR*)argv[1];

    // Parse switches
    for (INT32 n = 0; n < argc; n++)
    {
        WCHAR param[MAX_PATH] = L"";

        if (FAILED(hr = StringCchCopy(param, MAX_PATH, argv[n])))
        {
            goto Cleanup;
        }
        param[4] = 0;

        if ((!wcscmp(param, L"/?")) ||
            (!wcscmp(param, L"-?")) ||
            (!_wcsicmp(param, L"/h")) ||
            (!_wcsicmp(param, L"-h")))
        {
            GetHelp();
            goto Cleanup;
        }
        else if (!_wcsicmp(param, L"-boe"))
        {
            __debugbreak();
        }
    }

    // Check the TPM
    if ((result = Tbsi_GetDeviceInfo(sizeof(deviceInfo), &deviceInfo)) != TBS_SUCCESS)
    {
        wprintf(L"ERROR(0x%08x): Tbsi_GetDeviceInfo() failed.\n", result);
    }
    else
    {
        if (deviceInfo.structVersion != 1)
        {
            wprintf(L"WARNING: deviceInfo.structVersion = %08x\n", deviceInfo.structVersion);
        }
        if (deviceInfo.tpmVersion == TPM_VERSION_12)
        {
            wprintf(L"TBS detected 1.2 ");
        }
        else if (deviceInfo.tpmVersion == TPM_VERSION_20)
        {
            wprintf(L"TBS detected 2.0 ");
        }
        else
        {
            wprintf(L"WARNING: deviceInfo.tpmVersion = %08x\n", deviceInfo.tpmVersion);
            goto Cleanup;
        }

        if (deviceInfo.tpmInterfaceType == TPM_IFTYPE_1)
        {
            wprintf(L"discrete TPM (dTPM) using TIS on MMIO/IO.\n");
        }
        else if (deviceInfo.tpmInterfaceType == TPM_IFTYPE_TRUSTZONE)
        {
            wprintf(L"firmware TPM (fTPM) using Trustzone.\n");
        }
        else if (deviceInfo.tpmInterfaceType == TPM_IFTYPE_HW)
        {
            wprintf(L"firmware TPM (fTPM) using Intel TEE.\n");
        }
        else if (deviceInfo.tpmInterfaceType == TPM_IFTYPE_EMULATOR)
        {
            wprintf(L"simulated TPM (sTPM).\n");
        }
        else if (deviceInfo.tpmInterfaceType == TPM_IFTYPE_SPB)
        {
            wprintf(L"discrete TPM (dTPM) using TIS on SPB.\n");
        }
        else
        {
            wprintf(L"TPM using unknown interface.\n");
        }

        // Open a context
        if ((result = Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&context, &g_hTbs)) != TBS_SUCCESS)
        {
            wprintf(L"ERROR(0x%08x): Tbsi_Context_Create() failed.\n", result);
            goto Cleanup;
        }
    }

    // Parse the command
    if (!_wcsicmp(command, L"-gav"))
    {
        wprintf(L"LockoutAuth(%d) = ", g_LockoutAuth.t.size);
        for (UINT32 m = 0; m < g_LockoutAuth.t.size; m++)
        {
            wprintf(L"%02x", g_LockoutAuth.t.buffer[m]);
        }
        wprintf(L"\nStorageAuth(%d) = ", g_StorageAuth.t.size);
        for (UINT32 m = 0; m < g_StorageAuth.t.size; m++)
        {
            wprintf(L"%02x", g_StorageAuth.t.buffer[m]);
        }
        wprintf(L"\nEndorsementAuth(%d) = ", g_EndorsementAuth.t.size);
        for (UINT32 m = 0; m < g_EndorsementAuth.t.size; m++)
        {
            wprintf(L"%02x", g_EndorsementAuth.t.buffer[m]);
        }
        wprintf(L"\n");
    }
    else if (!_wcsicmp(command, L"-ppi"))
    {
        BYTE ppiBuffer[256] = { 0x01, 0x00, 0x00, 0x00 };
        UINT32 ppiBufferSize = sizeof(ppiBuffer);
        if ((result = Tbsi_Physical_Presence_Command(g_hTbs, ppiBuffer, sizeof(DWORD), ppiBuffer, &ppiBufferSize)) != TBS_SUCCESS)
        {
            wprintf(L"ERROR(0x%08x): Tbsi_Physical_Presence_Command() failed.\n", result);
        }
        else
        {
            printf("PPI Version %s available.\n", ppiBuffer);
        }
    }
    else if (!_wcsicmp(command, L"-log"))
    {
        UINT32 cbTcgLog = 0;
        if ((result = Tbsi_Get_TCG_Log(g_hTbs, NULL, &cbTcgLog)) != TBS_SUCCESS)
        {
            wprintf(L"ERROR(0x%08x): Tbsi_Get_TCG_Log() failed.\n", result);
        }
        else
        {
            if (cbTcgLog == 0)
            {
                wprintf(L"No TCGLog available.\n");
            }
            else
            {
                wprintf(L"TCGLog size %d bytes.\n", cbTcgLog);
                PBYTE pbTcgLog = (PBYTE)malloc(cbTcgLog);
                if ((result = Tbsi_Get_TCG_Log(g_hTbs, pbTcgLog, &cbTcgLog)) == TBS_SUCCESS)
                {
                    HANDLE hFile = INVALID_HANDLE_VALUE;
                    DWORD written = 0;
                    if ((hFile = CreateFileW(L"TCGLog.bin", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)) != INVALID_HANDLE_VALUE)
                    {
                        if (WriteFile(hFile, pbTcgLog, cbTcgLog, &written, NULL))
                        {
                            wprintf(L"Written to TCGLog.bin.\n");
                        }
                        CloseHandle(hFile);
                    }
                }
                free(pbTcgLog);
                pbTcgLog = NULL;
            }
        }
    }
    else if (!_wcsicmp(command, L"-cap"))
    {
        hr = GetCapabilities();
    }
    else if (!_wcsicmp(command, L"-nvk"))
    {
        hr = GetNvKeys();
    }
    else if (!_wcsicmp(command, L"-nvo"))
    {
        hr = GetNvObjects();
    }
    else if (!_wcsicmp(command, L"-ord"))
    {
        hr = GetMissingOrdinals();
    }
    else if (!_wcsicmp(command, L"-alg"))
    {
        hr = GetAlgsAndCurves();
    }
    else if (!_wcsicmp(command, L"-cph"))
    {
        hr = PHClear();
    }
    else if (!_wcsicmp(command, L"-cla"))
    {
        hr = OwnerClear();
    }
    else if (!_wcsicmp(command, L"-cpp"))
    {
        hr = PhysicalPresenceInterfaceClear();
    }
    else if (!_wcsicmp(command, L"-rpr"))
    {
        hr = ReadPcrs();
    }
    else if (!_wcsicmp(command, L"-edp"))
    {
        hr = ExtendDebugPcr();
    }
    else if (!_wcsicmp(command, L"-rdp"))
    {
        hr = ResetDebugPcr();
    }
    else if (!_wcsicmp(command, L"-rcl"))
    {
        hr = ReadClock();
    }
    else if (!_wcsicmp(command, L"-tak"))
    {
        hr = TestAES128Key();
    }
    else if (!_wcsicmp(command, L"-tek"))
    {
        hr = TestECDSAP256Key();
    }
    else if (!_wcsicmp(command, L"-thk"))
    {
        hr = TestHMACKey();
    }
    else if (!_wcsicmp(command, L"-trk"))
    {
        hr = TestRSA2048Key();
    }
    else if (!_wcsicmp(command, L"-cng"))
    {
        hr = TestCNG();
    }
    else
    {
        GetHelp();
    }

Cleanup:
    if (hFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hFile);
        hFile = INVALID_HANDLE_VALUE;
    }
    if (g_hTbs != NULL)
    {
        Tbsip_Context_Close(g_hTbs);
        g_hTbs = NULL;
    }
    return (UINT32)hr;
}
