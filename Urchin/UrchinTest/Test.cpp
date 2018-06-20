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

// Extern algorithm handles from the platform library
extern BCRYPT_ALG_HANDLE g_hRngAlg;
extern BCRYPT_ALG_HANDLE g_hAlg[HASH_COUNT + 1];
extern BCRYPT_ALG_HANDLE g_hRsaAlg;
extern BCRYPT_ALG_HANDLE g_hAesAlg;

// Global Handles and Objects
BCRYPT_KEY_HANDLE g_hAik = NULL;
BCRYPT_KEY_HANDLE g_hKey = NULL;
ANY_OBJECT g_EkObject = {0};
ANY_OBJECT g_SrkObject = {0};
ANY_OBJECT g_AikObject = {0};
ANY_OBJECT g_KeyObject = {0};
ANY_OBJECT g_Lockout = {0};
ANY_OBJECT g_Endorsement = {0};
ANY_OBJECT g_StorageOwner = {0};
TPML_DIGEST g_AdminPolicyHashList = {0};
const char g_UsageAuth[] = "ThisIsASecretUsageAuth";
const char g_KeyCreationNonce[32] = "RandomServerPickedCreationNonce";
TPM2B_CREATION_DATA g_KeyCreationData = {0};
TPM2B_DIGEST g_KeyCreationHash = {0};
TPMT_TK_CREATION g_KeyCreationTicket = {0};

UINT32
ImportPubKey(
	BCRYPT_KEY_HANDLE* hKey,
	ANY_OBJECT* tKey
	)
{
    NTSTATUS status = 0;
    BYTE buffer[1024] = { 0 };
    BYTE defaultExponent[3] = {0x01, 0x00, 0x01};
    BCRYPT_RSAKEY_BLOB* pKey = (BCRYPT_RSAKEY_BLOB*)buffer;

    if((status = BCryptOpenAlgorithmProvider(&g_hRsaAlg, BCRYPT_RSA_ALGORITHM, NULL, 0)) != 0)
    {
        return status;
    }
    pKey->Magic = BCRYPT_RSAPUBLIC_MAGIC;
    pKey->BitLength = tKey->obj.publicArea.t.publicArea.parameters.rsaDetail.keyBits;
    pKey->cbPublicExp = (tKey->obj.publicArea.t.publicArea.parameters.rsaDetail.exponent) ? sizeof(UINT32) : sizeof(defaultExponent);
    pKey->cbModulus = tKey->obj.publicArea.t.publicArea.unique.rsa.t.size;
    if(tKey->obj.publicArea.t.publicArea.parameters.rsaDetail.exponent == 0)
    {
        memcpy_s(&buffer[sizeof(BCRYPT_RSAKEY_BLOB)], 1024-sizeof(BCRYPT_RSAKEY_BLOB), defaultExponent, pKey->cbPublicExp);
    }
    else
    {
        PBYTE expBuf = &buffer[sizeof(BCRYPT_RSAKEY_BLOB)];
        UINT32_Marshal(&tKey->obj.publicArea.t.publicArea.parameters.rsaDetail.exponent, &expBuf, NULL);
    }
    memcpy_s(&buffer[sizeof(BCRYPT_RSAKEY_BLOB) + pKey->cbPublicExp], 1024-(sizeof(BCRYPT_RSAKEY_BLOB) + pKey->cbPublicExp), tKey->obj.publicArea.t.publicArea.unique.rsa.t.buffer, pKey->cbModulus);
    if((status = BCryptImportKeyPair(g_hRsaAlg, NULL, BCRYPT_RSAPUBLIC_BLOB, hKey, buffer, sizeof(BCRYPT_RSAKEY_BLOB) + pKey->cbPublicExp + pKey->cbModulus, 0)) !=0)
    {
        return status;
    }
    return status;
}

UINT32
CreateAuthorities()
{
    BYTE *buffer = NULL;
    INT32 size = 0;

    PlattformRetrieveAuthValues();

    g_StorageOwner.entity.handle = TPM_RH_OWNER;
    buffer = g_StorageOwner.entity.name.t.name;
    size = sizeof(g_StorageOwner.entity.name.t.name);
    g_StorageOwner.entity.name.t.size = TPM_HANDLE_Marshal(&g_StorageOwner.entity.handle, &buffer, &size);
    g_StorageOwner.entity.authValue = g_StorageAuth;

    g_Endorsement.entity.handle = TPM_RH_ENDORSEMENT;
    buffer = g_Endorsement.entity.name.t.name;
    size = sizeof(g_Endorsement.entity.name.t.name);
    g_Endorsement.entity.name.t.size = TPM_HANDLE_Marshal(&g_Endorsement.entity.handle, &buffer, &size);
    g_Endorsement.entity.authValue = g_EndorsementAuth;

    g_Lockout.entity.handle = TPM_RH_LOCKOUT;
    buffer = g_Lockout.entity.name.t.name;
    size = sizeof(g_Lockout.entity.name.t.name);
    g_Lockout.entity.name.t.size = TPM_HANDLE_Marshal(&g_Lockout.entity.handle, &buffer, &size);
    g_Lockout.entity.authValue = g_LockoutAuth;

//Cleanup:
    return TPM_RC_SUCCESS;
}

UINT32
CreateSrkObject()
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    ReadPublic_Out readPublicIn;
    ReadPublic_Out readPublicOut = {0};

    // Read the SRK public
    INITIALIZE_CALL_BUFFERS(TPM2_ReadPublic, &readPublicIn, &readPublicOut);
    parms.objectTableIn[TPM2_ReadPublic_HdlIn_PublicKey].generic.handle = TPM_20_SRK_HANDLE;
    EXECUTE_TPM_CALL(FALSE, TPM2_ReadPublic);
    g_SrkObject = parms.objectTableIn[0];

Cleanup:
    return result;
}

UINT32
CreateEkObject()
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    CreatePrimary_In createPrimaryIn = {0};
    CreatePrimary_Out createPrimaryOut = {0};

    // Create the session
    sessionTable[0].handle = TPM_RS_PW;

    // Create the EK
    INITIALIZE_CALL_BUFFERS(TPM2_CreatePrimary, &createPrimaryIn, &createPrimaryOut);
    parms.objectTableIn[TPM2_CreatePrimary_HdlIn_PrimaryHandle] = g_Endorsement;
    SetEkTemplate(&createPrimaryIn.inPublic);
    EXECUTE_TPM_CALL(FALSE, TPM2_CreatePrimary);

    // Copy the EK out
    g_EkObject = parms.objectTableOut[TPM2_CreatePrimary_HdlOut_ObjectHandle];

Cleanup:
    return result;
}

UINT32
CreateAndLoadAikObject()
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    PolicyCommandCode_In policyCommandCodeIn = {0};
    PolicyAuthValue_In policyAuthValueIn;
    TestParms_In testParmsIn = {0};
    TestParms_Out testParmsOut;
    Create_In createIn = {0};
    Create_Out createOut = {0};
    Load_In loadIn = {0};
    Load_Out loadOut = {0};

    // Test the key paramters to see if they are supported without kicking off a key creation
    INITIALIZE_CALL_BUFFERS(TPM2_TestParms, &testParmsIn, &testParmsOut);
    testParmsIn.parameters.type = TPM_ALG_RSA;
    testParmsIn.parameters.parameters.symDetail.algorithm = TPM_ALG_NULL;
    testParmsIn.parameters.parameters.rsaDetail.scheme.scheme = TPM_ALG_RSAPSS;
    testParmsIn.parameters.parameters.rsaDetail.scheme.details.rsapss.hashAlg = TPM_ALG_SHA256;
    testParmsIn.parameters.parameters.rsaDetail.keyBits = 2048;
    EXECUTE_TPM_CALL(FALSE, TPM2_TestParms);


    // Create the session
    sessionTable[0].handle = TPM_RS_PW;

    // Create the key
    INITIALIZE_CALL_BUFFERS(TPM2_Create, &createIn, &createOut);
    parms.objectTableIn[TPM2_Create_HdlIn_ParentHandle] = g_SrkObject;
    createIn.inSensitive.t.sensitive.userAuth.t.size = sizeof(g_UsageAuth);
    MemoryCopy(createIn.inSensitive.t.sensitive.userAuth.t.buffer, g_UsageAuth, createIn.inSensitive.t.sensitive.userAuth.t.size, sizeof(createIn.inSensitive.t.sensitive.userAuth.t.buffer));
    MemoryRemoveTrailingZeros(&createIn.inSensitive.t.sensitive.userAuth);

    // Calculate the admin policy for an AIK
    createIn.inPublic.t.publicArea.authPolicy.t.size = SHA256_DIGEST_SIZE;
    policyCommandCodeIn.code = TPM_CC_ActivateCredential;
    TPM2_PolicyCommandCode_CalculateUpdate(TPM_ALG_SHA256, &createIn.inPublic.t.publicArea.authPolicy, &policyCommandCodeIn);
    TPM2_PolicyAuthValue_CalculateUpdate(TPM_ALG_SHA256, &createIn.inPublic.t.publicArea.authPolicy, &policyAuthValueIn);

    createIn.inPublic.t.publicArea.type = TPM_ALG_RSA;
    createIn.inPublic.t.publicArea.nameAlg = TPM_ALG_SHA256;
    createIn.inPublic.t.publicArea.objectAttributes.fixedTPM = 1;
    createIn.inPublic.t.publicArea.objectAttributes.fixedParent = 1;
    createIn.inPublic.t.publicArea.objectAttributes.sensitiveDataOrigin = 1;
    createIn.inPublic.t.publicArea.objectAttributes.userWithAuth = 1;
    createIn.inPublic.t.publicArea.objectAttributes.adminWithPolicy = 1;
    createIn.inPublic.t.publicArea.objectAttributes.noDA = 1;
    createIn.inPublic.t.publicArea.objectAttributes.restricted = 1;
    createIn.inPublic.t.publicArea.objectAttributes.sign = 1;
    createIn.inPublic.t.publicArea.parameters.symDetail.algorithm = TPM_ALG_NULL;
    createIn.inPublic.t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_RSAPSS;
    createIn.inPublic.t.publicArea.parameters.rsaDetail.scheme.details.rsapss.hashAlg = TPM_ALG_SHA256;
    createIn.inPublic.t.publicArea.parameters.rsaDetail.keyBits = 2048;
    createIn.inPublic.t.publicArea.unique.rsa.b.size = 256;
    EXECUTE_TPM_CALL(FALSE, TPM2_Create);

    // Build the key object
    g_AikObject.obj.publicArea = createOut.outPublic;
    g_AikObject.obj.privateArea = createOut.outPrivate;
    g_AikObject.obj.authValue = createIn.inSensitive.t.sensitive.userAuth;

    // Load the key
    INITIALIZE_CALL_BUFFERS(TPM2_Load, &loadIn, &loadOut);
    parms.objectTableIn[TPM2_Load_HdlIn_ParentHandle] = g_SrkObject;
    parms.objectTableOut[TPM2_Load_HdlOut_ObjectHandle] = g_AikObject; // Copy the key in to be updated
    loadIn.inPublic = g_AikObject.obj.publicArea;
    loadIn.inPrivate = g_AikObject.obj.privateArea;
    EXECUTE_TPM_CALL(FALSE, TPM2_Load);

    // Copy the updated key back out
    g_AikObject = parms.objectTableOut[TPM2_Load_HdlOut_ObjectHandle];

    // Get the BCrypt Handle for the pubKey
    if((result = ImportPubKey(&g_hAik, &g_AikObject)) != 0)
    {
        goto Cleanup;
    }

Cleanup:
    return result;
}

UINT32
CreateAndLoadKeyObject()
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    Create_In createIn = {0};
    Create_Out createOut = {0};
    Load_In loadIn = {0};
    Load_Out loadOut = {0};
    PolicyOR_In policyORIn = {0};
    PolicyCommandCode_In policyCommandCodeIn = {0};
    PolicyAuthValue_In policyAuthValueIn;

    // Create the session
    sessionTable[0].handle = TPM_RS_PW;

    // Create the key
    INITIALIZE_CALL_BUFFERS(TPM2_Create, &createIn, &createOut);
    parms.objectTableIn[TPM2_Create_HdlIn_ParentHandle] = g_SrkObject;
    createIn.inSensitive.t.sensitive.userAuth.t.size = sizeof(g_UsageAuth);
    MemoryCopy(createIn.inSensitive.t.sensitive.userAuth.t.buffer, g_UsageAuth, createIn.inSensitive.t.sensitive.userAuth.t.size, sizeof(createIn.inSensitive.t.sensitive.userAuth.t.buffer));
    MemoryRemoveTrailingZeros(&createIn.inSensitive.t.sensitive.userAuth);

    // Calculate the admin policy: ((ObjectChangeAuth with usageAuth) || (Duplication with usageAuth))
    policyORIn.pHashList.count = 3;

    policyORIn.pHashList.digests[0].b.size = SHA256_DIGEST_SIZE;
    policyCommandCodeIn.code = TPM_CC_ObjectChangeAuth;
    TPM2_PolicyCommandCode_CalculateUpdate(TPM_ALG_SHA256, &policyORIn.pHashList.digests[0], &policyCommandCodeIn);
    // c1 b5 0b c8 a2 d5 aa 27 b6 2d c9 c0 d7 76 86 4f 2e fd 67 61 3e 01 43 e5 75 3e 8d e5 bd 2d 70 85
    TPM2_PolicyAuthValue_CalculateUpdate(TPM_ALG_SHA256, &policyORIn.pHashList.digests[0], &policyAuthValueIn);
    // e5 29 f5 d6 11 28 72 95 4e 8e d6 60 51 17 b7 57 e2 37 c6 e1 95 13 a9 49 fe e1 f2 04 c4 58 02 3a

    policyORIn.pHashList.digests[1].b.size = SHA256_DIGEST_SIZE;
    policyCommandCodeIn.code = TPM_CC_Duplicate;
    TPM2_PolicyCommandCode_CalculateUpdate(TPM_ALG_SHA256, &policyORIn.pHashList.digests[1], &policyCommandCodeIn);
    // be f5 6b 8c 1c c8 4e 11 ed d7 17 52 8d 2c d9 93 56 bd 2b bf 8f 01 52 09 c3 f8 4a ee ab a8 e8 a2
    TPM2_PolicyAuthValue_CalculateUpdate(TPM_ALG_SHA256, &policyORIn.pHashList.digests[1], &policyAuthValueIn);
    // 7d 49 01 0b 81 2b 21 79 b3 7a a6 7a 45 7a 7a e4 f5 0f ec c6 cc 1a 56 98 67 71 76 12 b9 02 86 c8

    policyORIn.pHashList.digests[2].b.size = SHA256_DIGEST_SIZE;
    policyCommandCodeIn.code = TPM_CC_Certify;
    TPM2_PolicyCommandCode_CalculateUpdate(TPM_ALG_SHA256, &policyORIn.pHashList.digests[2], &policyCommandCodeIn);
    // 04 8e 9a 3a ce 08 58 3f 79 f3 44 ff 78 5b be a9 f0 7a c7 fa 33 25 b3 d4 9a 21 dd 51 94 c6 58 50
    TPM2_PolicyAuthValue_CalculateUpdate(TPM_ALG_SHA256, &policyORIn.pHashList.digests[2], &policyAuthValueIn);
    // af 2c a5 69 69 9c 43 6a 21 00 6f 1c b8 a2 75 6c 98 bc 1c 76 5a 35 59 c5 fe 1c 3f 5e 72 28 a7 e7

    g_AdminPolicyHashList = policyORIn.pHashList; // Remember that so we dont have to calculate the entire graph every time
    createIn.inPublic.t.publicArea.authPolicy.t.size = SHA256_DIGEST_SIZE;
    TPM2_PolicyOR_CalculateUpdate(TPM_ALG_SHA256, &createIn.inPublic.t.publicArea.authPolicy, &policyORIn);
    // 37 d7 29 9b a7 11 d4 2d 58 d5 d8 84 17 51 a7 9a 28 e7 30 bc ea 9f 4f 72 5d 4c 1e 48 28 88 01 3c

    createIn.inPublic.t.publicArea.type = TPM_ALG_RSA;
    createIn.inPublic.t.publicArea.nameAlg = TPM_ALG_SHA256;
//    createIn.inPublic.t.publicArea.objectAttributes.fixedTPM = 1;
//    createIn.inPublic.t.publicArea.objectAttributes.fixedParent = 1;
//    createIn.inPublic.t.publicArea.objectAttributes.encryptedDuplication = 1;
    createIn.inPublic.t.publicArea.objectAttributes.sensitiveDataOrigin = 1;
    createIn.inPublic.t.publicArea.objectAttributes.userWithAuth = 1;
    createIn.inPublic.t.publicArea.objectAttributes.adminWithPolicy = 1;
    createIn.inPublic.t.publicArea.objectAttributes.noDA = 1;
    createIn.inPublic.t.publicArea.objectAttributes.decrypt = 1;
    createIn.inPublic.t.publicArea.objectAttributes.sign = 1;
    createIn.inPublic.t.publicArea.parameters.symDetail.algorithm = TPM_ALG_NULL;
    createIn.inPublic.t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
    createIn.inPublic.t.publicArea.parameters.rsaDetail.keyBits = 2048;
    createIn.inPublic.t.publicArea.unique.rsa.b.size = 256;
    createIn.outsideInfo.t.size = sizeof(g_KeyCreationNonce);
    MemoryCopy(createIn.outsideInfo.t.buffer, g_KeyCreationNonce, sizeof(g_KeyCreationNonce), sizeof(createIn.outsideInfo.t.buffer));
    EXECUTE_TPM_CALL(FALSE, TPM2_Create);

    // Build the key object
    g_KeyObject.obj.publicArea = createOut.outPublic;
    g_KeyObject.obj.privateArea = createOut.outPrivate;
    g_KeyObject.obj.authValue = createIn.inSensitive.t.sensitive.userAuth;
    g_KeyCreationData = createOut.creationData;
    g_KeyCreationHash = createOut.creationHash;
    g_KeyCreationTicket = createOut.creationTicket;

    // Load the key
    INITIALIZE_CALL_BUFFERS(TPM2_Load, &loadIn, &loadOut);
    parms.objectTableIn[TPM2_Load_HdlIn_ParentHandle] = g_SrkObject;
    parms.objectTableOut[TPM2_Load_HdlOut_ObjectHandle] = g_KeyObject; // Copy the key in to be updated
    loadIn.inPublic = g_KeyObject.obj.publicArea;
    loadIn.inPrivate = g_KeyObject.obj.privateArea;
    EXECUTE_TPM_CALL(FALSE, TPM2_Load);

    // Copy the updated key back out
    g_KeyObject = parms.objectTableOut[TPM2_Load_HdlOut_ObjectHandle];

    // Get the BCrypt Handle for the pubKey
    if((result = ImportPubKey(&g_hKey, &g_KeyObject)) != 0)
    {
        goto Cleanup;
    }

Cleanup:
    return result;
}

UINT32
UnloadKeyObjects()
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    FlushContext_In flushContextIn;
    FlushContext_Out flushContextOut;

    // Unload the key
    INITIALIZE_CALL_BUFFERS(TPM2_FlushContext, &flushContextIn, &flushContextOut);
    parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle] = g_KeyObject; // Copy the key in to be updated
    EXECUTE_TPM_CALL(FALSE, TPM2_FlushContext);

    // Copy the updated key back out
    g_KeyObject = parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle];

    // Destroy the BCrypt key
    BCryptDestroyHash(g_hKey);

    // Unload the AIK
    INITIALIZE_CALL_BUFFERS(TPM2_FlushContext, &flushContextIn, &flushContextOut);
    parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle] = g_AikObject; // Copy the key in to be updated
    EXECUTE_TPM_CALL(FALSE, TPM2_FlushContext);

    // Copy the updated key back out
    g_AikObject = parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle];

    // Destroy the BCrypt key
    BCryptDestroyHash(g_hAik);

    // Unload the EK
    INITIALIZE_CALL_BUFFERS(TPM2_FlushContext, &flushContextIn, &flushContextOut);
    parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle] = g_EkObject; // Copy the key in to be updated
    EXECUTE_TPM_CALL(TRUE, TPM2_FlushContext);

    // Copy the updated key back out
    g_EkObject = parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle];


Cleanup:
    return result;
}

UINT32
TestGetCapability()
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    GetCapability_In getCapabilityIn;
    GetCapability_Out getCapabilityOut;
    BOOL moreCmdCapsToRead = TRUE;
    TPM_CC nextCmdToRead = TPM_CC_FIRST;

    // Read all command caps
    while(moreCmdCapsToRead)
    {
        INITIALIZE_CALL_BUFFERS(TPM2_GetCapability, &getCapabilityIn, &getCapabilityOut);
        getCapabilityIn.capability = TPM_CAP_COMMANDS;
        getCapabilityIn.property = nextCmdToRead;
        getCapabilityIn.propertyCount = 0x10;
        EXECUTE_TPM_CALL(FALSE, TPM2_GetCapability);
        moreCmdCapsToRead = (getCapabilityOut.moreData != 0) ? TRUE : FALSE;
        nextCmdToRead = getCapabilityOut.capabilityData.data.command.commandAttributes[getCapabilityOut.capabilityData.data.command.count - 1].commandIndex + 1;
    }

Cleanup:
    return result;
}

UINT32
TestGetEntropy()
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    GetRandom_In getRandomIn = { 0 };
    GetRandom_Out getRandomOut = { 0 };
    StirRandom_In stirRandomIn = { 0 };
    StirRandom_Out stirRandomOut;

    // Get some entropy from the PRNG
    INITIALIZE_CALL_BUFFERS(TPM2_GetRandom, &getRandomIn, &getRandomOut);
    getRandomIn.bytesRequested = SHA256_DIGEST_SIZE;
    EXECUTE_TPM_CALL(FALSE, TPM2_GetRandom);

    // Reseed the PRNG
    INITIALIZE_CALL_BUFFERS(TPM2_StirRandom, &stirRandomIn, &stirRandomOut);
    MemoryCopy2B((TPM2B*)&stirRandomIn.inData, (TPM2B*)&getRandomOut.randomBytes, sizeof(stirRandomIn.inData.t.buffer));
    EXECUTE_TPM_CALL(FALSE, TPM2_StirRandom);

Cleanup:
    return result;
}

UINT32
TestSignParameterDecryption()
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    StartAuthSession_In startAuthSessionIn = {0};
    StartAuthSession_Out startAuthSessionOut = {0};
    Load_In loadIn = {0};
    Load_Out loadOut = {0};
    FlushContext_In flushContextIn;
    FlushContext_Out flushContextOut;
    ANY_OBJECT key = {0};

    // Start session
    INITIALIZE_CALL_BUFFERS(TPM2_StartAuthSession, &startAuthSessionIn, &startAuthSessionOut);
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_TpmKey].obj.handle = TPM_RH_NULL;
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_Bind].obj.handle = TPM_RH_NULL;
    startAuthSessionIn.nonceCaller.t.size = CryptGenerateRandom(SHA256_DIGEST_SIZE, startAuthSessionIn.nonceCaller.t.buffer);
    startAuthSessionIn.sessionType = TPM_SE_HMAC;
    startAuthSessionIn.symmetric.algorithm = TPM_ALG_XOR;
    startAuthSessionIn.symmetric.keyBits.xOr = TPM_ALG_SHA256;
    startAuthSessionIn.authHash = TPM_ALG_SHA256;
    EXECUTE_TPM_CALL(FALSE, TPM2_StartAuthSession);

    // Copy the session out
    sessionTable[0] = parms.objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session;

    // Prepare the session to terminate
    sessionTable[0].attributes.continueSession = CLEAR;

    // Set parameter encryption for key session
    sessionTable[0].attributes.encrypt = SET;

    // Load the key
    INITIALIZE_CALL_BUFFERS(TPM2_Load, &loadIn, &loadOut);
    parms.objectTableIn[TPM2_Load_HdlIn_ParentHandle] = g_SrkObject;
    loadIn.inPublic = g_KeyObject.obj.publicArea;
    loadIn.inPrivate = g_KeyObject.obj.privateArea;
    EXECUTE_TPM_CALL(FALSE, TPM2_Load);
    key = parms.objectTableOut[0];

    if(!MemoryEqual(loadOut.name.t.name, g_KeyObject.obj.name.t.name, loadOut.name.t.size))
    {
        result = 1;
        goto Cleanup;
    }

    // Unload the key
    INITIALIZE_CALL_BUFFERS(TPM2_FlushContext, &flushContextIn, &flushContextOut);
    parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle] = key;
    EXECUTE_TPM_CALL(FALSE, TPM2_FlushContext);

    // Start session
    INITIALIZE_CALL_BUFFERS(TPM2_StartAuthSession, &startAuthSessionIn, &startAuthSessionOut);
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_TpmKey].obj.handle = TPM_RH_NULL;
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_Bind].obj.handle = TPM_RH_NULL;
    startAuthSessionIn.nonceCaller.t.size = CryptGenerateRandom(SHA256_DIGEST_SIZE, startAuthSessionIn.nonceCaller.t.buffer);
    startAuthSessionIn.sessionType = TPM_SE_HMAC;
    startAuthSessionIn.symmetric.algorithm = TPM_ALG_AES;
    startAuthSessionIn.symmetric.keyBits.aes = 128;
    startAuthSessionIn.symmetric.mode.aes = TPM_ALG_CFB;
    startAuthSessionIn.authHash = TPM_ALG_SHA256;
    EXECUTE_TPM_CALL(FALSE, TPM2_StartAuthSession);

    // Copy the session out
    sessionTable[0] = parms.objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session;

    // Prepare the session to terminate
    sessionTable[0].attributes.continueSession = CLEAR;

    // Set parameter encryption for key session
    sessionTable[0].attributes.encrypt = SET;

    // Load the key
    INITIALIZE_CALL_BUFFERS(TPM2_Load, &loadIn, &loadOut);
    parms.objectTableIn[TPM2_Load_HdlIn_ParentHandle] = g_SrkObject;
    loadIn.inPublic = g_KeyObject.obj.publicArea;
    loadIn.inPrivate = g_KeyObject.obj.privateArea;
    EXECUTE_TPM_CALL(FALSE, TPM2_Load);
    key = parms.objectTableOut[0];

    if(!MemoryEqual(loadOut.name.t.name, g_KeyObject.obj.name.t.name, loadOut.name.t.size))
    {
        result = 1;
        goto Cleanup;
    }

    // Unload the key
    INITIALIZE_CALL_BUFFERS(TPM2_FlushContext, &flushContextIn, &flushContextOut);
    parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle] = key;
    EXECUTE_TPM_CALL(FALSE, TPM2_FlushContext);

    //
    // Encrypted parameter with salted session (session key)
    //

    // Start session
    INITIALIZE_CALL_BUFFERS(TPM2_StartAuthSession, &startAuthSessionIn, &startAuthSessionOut);
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_TpmKey] = g_SrkObject;  // Encrypt salt to SRK
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_Bind].obj.handle = TPM_RH_NULL;
    startAuthSessionIn.nonceCaller.t.size = CryptGenerateRandom(SHA256_DIGEST_SIZE, startAuthSessionIn.nonceCaller.t.buffer);
    startAuthSessionIn.sessionType = TPM_SE_HMAC;
    startAuthSessionIn.symmetric.algorithm = TPM_ALG_XOR;
    startAuthSessionIn.symmetric.keyBits.xOr = TPM_ALG_SHA256;
    startAuthSessionIn.authHash = TPM_ALG_SHA256;
    EXECUTE_TPM_CALL(FALSE, TPM2_StartAuthSession);

    // Copy the session out
    sessionTable[0] = parms.objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session;

    // Prepare the session to terminate
    sessionTable[0].attributes.continueSession = CLEAR;

    // Set parameter encryption for key session
    sessionTable[0].attributes.encrypt = SET;

    // Load the key
    INITIALIZE_CALL_BUFFERS(TPM2_Load, &loadIn, &loadOut);
    parms.objectTableIn[TPM2_Load_HdlIn_ParentHandle] = g_SrkObject;
    loadIn.inPublic = g_KeyObject.obj.publicArea;
    loadIn.inPrivate = g_KeyObject.obj.privateArea;
    EXECUTE_TPM_CALL(FALSE, TPM2_Load);
    key = parms.objectTableOut[0];

    if(!MemoryEqual(loadOut.name.t.name, g_KeyObject.obj.name.t.name, loadOut.name.t.size))
    {
        result = 1;
        goto Cleanup;
    }

    // Unload the key
    INITIALIZE_CALL_BUFFERS(TPM2_FlushContext, &flushContextIn, &flushContextOut);
    parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle] = key;
    EXECUTE_TPM_CALL(FALSE, TPM2_FlushContext);

    // Start session
    INITIALIZE_CALL_BUFFERS(TPM2_StartAuthSession, &startAuthSessionIn, &startAuthSessionOut);
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_TpmKey] = g_SrkObject;  // Encrypt salt to SRK
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_Bind].obj.handle = TPM_RH_NULL;
    startAuthSessionIn.nonceCaller.t.size = CryptGenerateRandom(SHA256_DIGEST_SIZE, startAuthSessionIn.nonceCaller.t.buffer);
    startAuthSessionIn.sessionType = TPM_SE_HMAC;
    startAuthSessionIn.symmetric.algorithm = TPM_ALG_AES;
    startAuthSessionIn.symmetric.keyBits.aes = 128;
    startAuthSessionIn.symmetric.mode.aes = TPM_ALG_CFB;
    startAuthSessionIn.authHash = TPM_ALG_SHA256;
    EXECUTE_TPM_CALL(FALSE, TPM2_StartAuthSession);

    // Copy the session out
    sessionTable[0] = parms.objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session;

    // Prepare the session to terminate
    sessionTable[0].attributes.continueSession = CLEAR;

    // Set parameter encryption for key session
    sessionTable[0].attributes.encrypt = SET;

    // Load the key
    INITIALIZE_CALL_BUFFERS(TPM2_Load, &loadIn, &loadOut);
    parms.objectTableIn[TPM2_Load_HdlIn_ParentHandle] = g_SrkObject;
    loadIn.inPublic = g_KeyObject.obj.publicArea;
    loadIn.inPrivate = g_KeyObject.obj.privateArea;
    EXECUTE_TPM_CALL(FALSE, TPM2_Load);
    key = parms.objectTableOut[0];

    if(!MemoryEqual(loadOut.name.t.name, g_KeyObject.obj.name.t.name, loadOut.name.t.size))
    {
        result = 1;
        goto Cleanup;
    }

    // Unload the key
    INITIALIZE_CALL_BUFFERS(TPM2_FlushContext, &flushContextIn, &flushContextOut);
    parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle] = key;
    EXECUTE_TPM_CALL(FALSE, TPM2_FlushContext);

    //
    // Encrypted parameter with extra session
    //

    // Start key session
    INITIALIZE_CALL_BUFFERS(TPM2_StartAuthSession, &startAuthSessionIn, &startAuthSessionOut);
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_TpmKey].obj.handle = TPM_RH_NULL;
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_Bind].obj.handle = TPM_RH_NULL;
    startAuthSessionIn.nonceCaller.t.size = CryptGenerateRandom(SHA256_DIGEST_SIZE, startAuthSessionIn.nonceCaller.t.buffer);
    startAuthSessionIn.sessionType = TPM_SE_HMAC;
    startAuthSessionIn.symmetric.algorithm = TPM_ALG_NULL;
    startAuthSessionIn.authHash = TPM_ALG_SHA256;
    EXECUTE_TPM_CALL(FALSE, TPM2_StartAuthSession);

    // Copy the session out
    sessionTable[0] = parms.objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session;

    // Prepare the session to terminate
    sessionTable[0].attributes.continueSession = CLEAR;

    // Start parameter encryption session
    INITIALIZE_CALL_BUFFERS(TPM2_StartAuthSession, &startAuthSessionIn, &startAuthSessionOut);
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_TpmKey] = g_SrkObject;  // Encrypt salt to SRK
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_Bind].obj.handle = TPM_RH_NULL;
    startAuthSessionIn.nonceCaller.t.size = CryptGenerateRandom(SHA256_DIGEST_SIZE, startAuthSessionIn.nonceCaller.t.buffer);
    startAuthSessionIn.sessionType = TPM_SE_HMAC;
    startAuthSessionIn.symmetric.algorithm = TPM_ALG_XOR;
    startAuthSessionIn.symmetric.keyBits.xOr = TPM_ALG_SHA256;
    startAuthSessionIn.authHash = TPM_ALG_SHA256;
    EXECUTE_TPM_CALL(FALSE, TPM2_StartAuthSession);

    // Copy the session out
    sessionTable[1] = parms.objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session;

    // Prepare the session to terminate
    sessionTable[1].attributes.continueSession = CLEAR;

    // Set parameter encryption for key session
    sessionTable[1].attributes.encrypt = SET;

    // Load the key
    INITIALIZE_CALL_BUFFERS(TPM2_Load, &loadIn, &loadOut);
    sessionCnt += 1; // Extra Session
    parms.objectTableIn[TPM2_Load_HdlIn_ParentHandle] = g_SrkObject;
    loadIn.inPublic = g_KeyObject.obj.publicArea;
    loadIn.inPrivate = g_KeyObject.obj.privateArea;
    EXECUTE_TPM_CALL(FALSE, TPM2_Load);
    key = parms.objectTableOut[0];

    if(!MemoryEqual(loadOut.name.t.name, g_KeyObject.obj.name.t.name, loadOut.name.t.size))
    {
        result = 1;
        goto Cleanup;
    }

    // Unload the key
    INITIALIZE_CALL_BUFFERS(TPM2_FlushContext, &flushContextIn, &flushContextOut);
    parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle] = key;
    EXECUTE_TPM_CALL(FALSE, TPM2_FlushContext);

    // Start key session
    INITIALIZE_CALL_BUFFERS(TPM2_StartAuthSession, &startAuthSessionIn, &startAuthSessionOut);
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_TpmKey].obj.handle = TPM_RH_NULL;
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_Bind].obj.handle = TPM_RH_NULL;
    startAuthSessionIn.nonceCaller.t.size = CryptGenerateRandom(SHA256_DIGEST_SIZE, startAuthSessionIn.nonceCaller.t.buffer);
    startAuthSessionIn.sessionType = TPM_SE_HMAC;
    startAuthSessionIn.symmetric.algorithm = TPM_ALG_NULL;
    startAuthSessionIn.authHash = TPM_ALG_SHA256;
    EXECUTE_TPM_CALL(FALSE, TPM2_StartAuthSession);

    // Copy the session out
    sessionTable[0] = parms.objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session;

    // Prepare the session to terminate
    sessionTable[0].attributes.continueSession = CLEAR;

    // Start parameter encryption session
    INITIALIZE_CALL_BUFFERS(TPM2_StartAuthSession, &startAuthSessionIn, &startAuthSessionOut);
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_TpmKey] = g_SrkObject;  // Encrypt salt to SRK
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_Bind].obj.handle = TPM_RH_NULL;
    startAuthSessionIn.nonceCaller.t.size = CryptGenerateRandom(SHA256_DIGEST_SIZE, startAuthSessionIn.nonceCaller.t.buffer);
    startAuthSessionIn.sessionType = TPM_SE_HMAC;
    startAuthSessionIn.symmetric.algorithm = TPM_ALG_AES;
    startAuthSessionIn.symmetric.keyBits.aes = 128;
    startAuthSessionIn.symmetric.mode.aes = TPM_ALG_CFB;
    startAuthSessionIn.authHash = TPM_ALG_SHA256;
    EXECUTE_TPM_CALL(FALSE, TPM2_StartAuthSession);

    // Copy the session out
    sessionTable[1] = parms.objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session;

    // Prepare the session to terminate
    sessionTable[1].attributes.continueSession = CLEAR;

    // Set parameter encryption for key session
    sessionTable[1].attributes.encrypt = SET;

    // Load the key
    INITIALIZE_CALL_BUFFERS(TPM2_Load, &loadIn, &loadOut);
    sessionCnt += 1; // Extra Session
    parms.objectTableIn[TPM2_Load_HdlIn_ParentHandle] = g_SrkObject;
    loadIn.inPublic = g_KeyObject.obj.publicArea;
    loadIn.inPrivate = g_KeyObject.obj.privateArea;
    EXECUTE_TPM_CALL(FALSE, TPM2_Load);
    key = parms.objectTableOut[0];

    if(!MemoryEqual(loadOut.name.t.name, g_KeyObject.obj.name.t.name, loadOut.name.t.size))
    {
        result = 1;
        goto Cleanup;
    }

    // Unload the key
    sessionCnt = 0;
    INITIALIZE_CALL_BUFFERS(TPM2_FlushContext, &flushContextIn, &flushContextOut);
    parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle] = key;
    EXECUTE_TPM_CALL(FALSE, TPM2_FlushContext);

Cleanup:
    return result;
}

UINT32
TestSignParameterEncryption()
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    StartAuthSession_In startAuthSessionIn = {0};
    StartAuthSession_Out startAuthSessionOut = {0};
    Sign_In signIn = {0};
    Sign_Out signOut = {0};
    BCRYPT_PSS_PADDING_INFO padding = {BCRYPT_SHA256_ALGORITHM, (256 - 32 - 2)};

    // Start session
    INITIALIZE_CALL_BUFFERS(TPM2_StartAuthSession, &startAuthSessionIn, &startAuthSessionOut);
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_TpmKey].obj.handle = TPM_RH_NULL;
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_Bind].obj.handle = TPM_RH_NULL;
    startAuthSessionIn.nonceCaller.t.size = CryptGenerateRandom(SHA256_DIGEST_SIZE, startAuthSessionIn.nonceCaller.t.buffer);
    startAuthSessionIn.sessionType = TPM_SE_HMAC;
    startAuthSessionIn.symmetric.algorithm = TPM_ALG_XOR;
    startAuthSessionIn.symmetric.keyBits.xOr = TPM_ALG_SHA256;
    startAuthSessionIn.authHash = TPM_ALG_SHA256;
    EXECUTE_TPM_CALL(FALSE, TPM2_StartAuthSession);

    // Copy the session out
    sessionTable[0] = parms.objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session;

    // Prepare the session to terminate
    sessionTable[0].attributes.continueSession = CLEAR;

    // Set parameter encryption for key session
    sessionTable[0].attributes.decrypt = SET;

    // Sign digest
    INITIALIZE_CALL_BUFFERS(TPM2_Sign, &signIn, &signOut);
    parms.objectTableIn[0] = g_KeyObject;
    signIn.digest.t.size = SHA256_DIGEST_SIZE;
    MemorySet((TPM2B*)&signIn.digest.t.buffer, 0x11, signIn.digest.t.size);
    signIn.inScheme.scheme = TPM_ALG_RSAPSS;
    signIn.inScheme.details.rsapss.hashAlg = TPM_ALG_SHA256;
    signIn.validation.tag = TPM_ST_HASHCHECK;
    signIn.validation.hierarchy = TPM_RH_NULL;
    EXECUTE_TPM_CALL(FALSE, TPM2_Sign);

    // Verify signature
    if((result = BCryptVerifySignature(g_hKey,
                                       &padding,
                                       signIn.digest.t.buffer,
                                       signIn.digest.t.size,
                                       signOut.signature.signature.rsassa.sig.t.buffer,
                                       signOut.signature.signature.rsassa.sig.t.size,
                                       BCRYPT_PAD_PSS)) != 0)
    {
        goto Cleanup;
    }

    // Start session
    INITIALIZE_CALL_BUFFERS(TPM2_StartAuthSession, &startAuthSessionIn, &startAuthSessionOut);
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_TpmKey].obj.handle = TPM_RH_NULL;
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_Bind].obj.handle = TPM_RH_NULL;
    startAuthSessionIn.nonceCaller.t.size = CryptGenerateRandom(SHA256_DIGEST_SIZE, startAuthSessionIn.nonceCaller.t.buffer);
    startAuthSessionIn.sessionType = TPM_SE_HMAC;
    startAuthSessionIn.symmetric.algorithm = TPM_ALG_AES;
    startAuthSessionIn.symmetric.keyBits.aes = 128;
    startAuthSessionIn.symmetric.mode.aes = TPM_ALG_CFB;
    startAuthSessionIn.authHash = TPM_ALG_SHA256;
    EXECUTE_TPM_CALL(FALSE, TPM2_StartAuthSession);

    // Copy the session out
    sessionTable[0] = parms.objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session;

    // Prepare the session to terminate
    sessionTable[0].attributes.continueSession = CLEAR;

    // Set parameter encryption for key session
    sessionTable[0].attributes.decrypt = SET;

    // Sign digest
    INITIALIZE_CALL_BUFFERS(TPM2_Sign, &signIn, &signOut);
    parms.objectTableIn[0] = g_KeyObject;
    signIn.digest.t.size = SHA256_DIGEST_SIZE;
    MemorySet((TPM2B*)&signIn.digest.t.buffer, 0x11, signIn.digest.t.size);
    signIn.inScheme.scheme = TPM_ALG_RSAPSS;
    signIn.inScheme.details.rsapss.hashAlg = TPM_ALG_SHA256;
    signIn.validation.tag = TPM_ST_HASHCHECK;
    signIn.validation.hierarchy = TPM_RH_NULL;
    EXECUTE_TPM_CALL(FALSE, TPM2_Sign);

    // Verify signature
    if((result = BCryptVerifySignature(g_hKey,
                                       &padding,
                                       signIn.digest.t.buffer,
                                       signIn.digest.t.size,
                                       signOut.signature.signature.rsassa.sig.t.buffer,
                                       signOut.signature.signature.rsassa.sig.t.size,
                                       BCRYPT_PAD_PSS)) != 0)
    {
        goto Cleanup;
    }

    //
    // Encrypted parameter with salted session (session key)
    //

    // Start session
    INITIALIZE_CALL_BUFFERS(TPM2_StartAuthSession, &startAuthSessionIn, &startAuthSessionOut);
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_TpmKey] = g_SrkObject;  // Encrypt salt to SRK
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_Bind].obj.handle = TPM_RH_NULL;
    startAuthSessionIn.nonceCaller.t.size = CryptGenerateRandom(SHA256_DIGEST_SIZE, startAuthSessionIn.nonceCaller.t.buffer);
    startAuthSessionIn.sessionType = TPM_SE_HMAC;
    startAuthSessionIn.symmetric.algorithm = TPM_ALG_XOR;
    startAuthSessionIn.symmetric.keyBits.xOr = TPM_ALG_SHA256;
    startAuthSessionIn.authHash = TPM_ALG_SHA256;
    EXECUTE_TPM_CALL(FALSE, TPM2_StartAuthSession);

    // Copy the session out
    sessionTable[0] = parms.objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session;

    // Prepare the session to terminate
    sessionTable[0].attributes.continueSession = CLEAR;

    // Set parameter encryption for key session
    sessionTable[0].attributes.decrypt = SET;

    // Sign digest
    INITIALIZE_CALL_BUFFERS(TPM2_Sign, &signIn, &signOut);
    parms.objectTableIn[0] = g_KeyObject;
    signIn.digest.t.size = SHA256_DIGEST_SIZE;
    MemorySet((TPM2B*)&signIn.digest.t.buffer, 0x11, signIn.digest.t.size);
    signIn.inScheme.scheme = TPM_ALG_RSAPSS;
    signIn.inScheme.details.rsapss.hashAlg = TPM_ALG_SHA256;
    signIn.validation.tag = TPM_ST_HASHCHECK;
    signIn.validation.hierarchy = TPM_RH_NULL;
    EXECUTE_TPM_CALL(FALSE, TPM2_Sign);

    // Verify signature
    if((result = BCryptVerifySignature(g_hKey,
                                       &padding,
                                       signIn.digest.t.buffer,
                                       signIn.digest.t.size,
                                       signOut.signature.signature.rsassa.sig.t.buffer,
                                       signOut.signature.signature.rsassa.sig.t.size,
                                       BCRYPT_PAD_PSS)) != 0)
    {
        goto Cleanup;
    }

    // Start session
    INITIALIZE_CALL_BUFFERS(TPM2_StartAuthSession, &startAuthSessionIn, &startAuthSessionOut);
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_TpmKey] = g_SrkObject;  // Encrypt salt to SRK
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_Bind].obj.handle = TPM_RH_NULL;
    startAuthSessionIn.nonceCaller.t.size = CryptGenerateRandom(SHA256_DIGEST_SIZE, startAuthSessionIn.nonceCaller.t.buffer);
    startAuthSessionIn.sessionType = TPM_SE_HMAC;
    startAuthSessionIn.symmetric.algorithm = TPM_ALG_AES;
    startAuthSessionIn.symmetric.keyBits.aes = 128;
    startAuthSessionIn.symmetric.mode.aes = TPM_ALG_CFB;
    startAuthSessionIn.authHash = TPM_ALG_SHA256;
    EXECUTE_TPM_CALL(FALSE, TPM2_StartAuthSession);

    // Copy the session out
    sessionTable[0] = parms.objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session;

    // Prepare the session to terminate
    sessionTable[0].attributes.continueSession = CLEAR;

    // Set parameter encryption for key session
    sessionTable[0].attributes.decrypt = SET;

    // Sign digest
    INITIALIZE_CALL_BUFFERS(TPM2_Sign, &signIn, &signOut);
    parms.objectTableIn[0] = g_KeyObject;
    signIn.digest.t.size = SHA256_DIGEST_SIZE;
    MemorySet((TPM2B*)&signIn.digest.t.buffer, 0x11, signIn.digest.t.size);
    signIn.inScheme.scheme = TPM_ALG_RSAPSS;
    signIn.inScheme.details.rsapss.hashAlg = TPM_ALG_SHA256;
    signIn.validation.tag = TPM_ST_HASHCHECK;
    signIn.validation.hierarchy = TPM_RH_NULL;
    EXECUTE_TPM_CALL(FALSE, TPM2_Sign);

    // Verify signature
    if((result = BCryptVerifySignature(g_hKey,
                                       &padding,
                                       signIn.digest.t.buffer,
                                       signIn.digest.t.size,
                                       signOut.signature.signature.rsassa.sig.t.buffer,
                                       signOut.signature.signature.rsassa.sig.t.size,
                                       BCRYPT_PAD_PSS)) != 0)
    {
        goto Cleanup;
    }

    //
    // Encrypted parameter with extra session
    //

    // Start key session
    INITIALIZE_CALL_BUFFERS(TPM2_StartAuthSession, &startAuthSessionIn, &startAuthSessionOut);
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_TpmKey].obj.handle = TPM_RH_NULL;
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_Bind].obj.handle = TPM_RH_NULL;
    startAuthSessionIn.nonceCaller.t.size = CryptGenerateRandom(SHA256_DIGEST_SIZE, startAuthSessionIn.nonceCaller.t.buffer);
    startAuthSessionIn.sessionType = TPM_SE_HMAC;
    startAuthSessionIn.symmetric.algorithm = TPM_ALG_NULL;
    startAuthSessionIn.authHash = TPM_ALG_SHA256;
    EXECUTE_TPM_CALL(FALSE, TPM2_StartAuthSession);

    // Copy the session out
    sessionTable[0] = parms.objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session;

    // Prepare the session to terminate
    sessionTable[0].attributes.continueSession = CLEAR;

    // Start parameter encryption session
    INITIALIZE_CALL_BUFFERS(TPM2_StartAuthSession, &startAuthSessionIn, &startAuthSessionOut);
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_TpmKey] = g_SrkObject;  // Encrypt salt to SRK
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_Bind].obj.handle = TPM_RH_NULL;
    startAuthSessionIn.nonceCaller.t.size = CryptGenerateRandom(SHA256_DIGEST_SIZE, startAuthSessionIn.nonceCaller.t.buffer);
    startAuthSessionIn.sessionType = TPM_SE_HMAC;
    startAuthSessionIn.symmetric.algorithm = TPM_ALG_XOR;
    startAuthSessionIn.symmetric.keyBits.xOr = TPM_ALG_SHA256;
    startAuthSessionIn.authHash = TPM_ALG_SHA256;
    EXECUTE_TPM_CALL(FALSE, TPM2_StartAuthSession);

    // Copy the session out
    sessionTable[1] = parms.objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session;

    // Prepare the session to terminate
    sessionTable[1].attributes.continueSession = CLEAR;

    // Set parameter encryption for key session
    sessionTable[1].attributes.decrypt = SET;

    // Sign digest
    INITIALIZE_CALL_BUFFERS(TPM2_Sign, &signIn, &signOut);
    sessionCnt += 1; // Extra Session
    parms.objectTableIn[0] = g_KeyObject;
    signIn.digest.t.size = SHA256_DIGEST_SIZE;
    MemorySet((TPM2B*)&signIn.digest.t.buffer, 0x11, signIn.digest.t.size);
    signIn.inScheme.scheme = TPM_ALG_RSAPSS;
    signIn.inScheme.details.rsapss.hashAlg = TPM_ALG_SHA256;
    signIn.validation.tag = TPM_ST_HASHCHECK;
    signIn.validation.hierarchy = TPM_RH_NULL;
    EXECUTE_TPM_CALL(FALSE, TPM2_Sign);

    // Verify signature
    if((result = BCryptVerifySignature(g_hKey,
                                       &padding,
                                       signIn.digest.t.buffer,
                                       signIn.digest.t.size,
                                       signOut.signature.signature.rsassa.sig.t.buffer,
                                       signOut.signature.signature.rsassa.sig.t.size,
                                       BCRYPT_PAD_PSS)) != 0)
    {
        goto Cleanup;
    }

    // Start key session
    INITIALIZE_CALL_BUFFERS(TPM2_StartAuthSession, &startAuthSessionIn, &startAuthSessionOut);
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_TpmKey].obj.handle = TPM_RH_NULL;
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_Bind].obj.handle = TPM_RH_NULL;
    startAuthSessionIn.nonceCaller.t.size = CryptGenerateRandom(SHA256_DIGEST_SIZE, startAuthSessionIn.nonceCaller.t.buffer);
    startAuthSessionIn.sessionType = TPM_SE_HMAC;
    startAuthSessionIn.symmetric.algorithm = TPM_ALG_NULL;
    startAuthSessionIn.authHash = TPM_ALG_SHA256;
    EXECUTE_TPM_CALL(FALSE, TPM2_StartAuthSession);

    // Copy the session out
    sessionTable[0] = parms.objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session;

    // Prepare the session to terminate
    sessionTable[0].attributes.continueSession = CLEAR;

    // Start parameter encryption session
    INITIALIZE_CALL_BUFFERS(TPM2_StartAuthSession, &startAuthSessionIn, &startAuthSessionOut);
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_TpmKey] = g_SrkObject;  // Encrypt salt to SRK
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_Bind].obj.handle = TPM_RH_NULL;
    startAuthSessionIn.nonceCaller.t.size = CryptGenerateRandom(SHA256_DIGEST_SIZE, startAuthSessionIn.nonceCaller.t.buffer);
    startAuthSessionIn.sessionType = TPM_SE_HMAC;
    startAuthSessionIn.symmetric.algorithm = TPM_ALG_AES;
    startAuthSessionIn.symmetric.keyBits.aes = 128;
    startAuthSessionIn.symmetric.mode.aes = TPM_ALG_CFB;
    startAuthSessionIn.authHash = TPM_ALG_SHA256;
    EXECUTE_TPM_CALL(FALSE, TPM2_StartAuthSession);

    // Copy the session out
    sessionTable[1] = parms.objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session;

    // Prepare the session to terminate
    sessionTable[1].attributes.continueSession = CLEAR;

    // Set parameter encryption for key session
    sessionTable[1].attributes.decrypt = SET;

    // Sign digest
    INITIALIZE_CALL_BUFFERS(TPM2_Sign, &signIn, &signOut);
    sessionCnt += 1; // Extra Session
    parms.objectTableIn[0] = g_KeyObject;
    signIn.digest.t.size = SHA256_DIGEST_SIZE;
    MemorySet((TPM2B*)&signIn.digest.t.buffer, 0x11, signIn.digest.t.size);
    signIn.inScheme.scheme = TPM_ALG_RSAPSS;
    signIn.inScheme.details.rsapss.hashAlg = TPM_ALG_SHA256;
    signIn.validation.tag = TPM_ST_HASHCHECK;
    signIn.validation.hierarchy = TPM_RH_NULL;
    EXECUTE_TPM_CALL(FALSE, TPM2_Sign);

    // Verify signature
    if((result = BCryptVerifySignature(g_hKey,
                                       &padding,
                                       signIn.digest.t.buffer,
                                       signIn.digest.t.size,
                                       signOut.signature.signature.rsassa.sig.t.buffer,
                                       signOut.signature.signature.rsassa.sig.t.size,
                                       BCRYPT_PAD_PSS)) != 0)
    {
        goto Cleanup;
    }

Cleanup:
    return result;
}

UINT32
TestSignSaltedAndBound()
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    StartAuthSession_In startAuthSessionIn = {0};
    StartAuthSession_Out startAuthSessionOut = {0};
    Sign_In signIn = {0};
    Sign_Out signOut = {0};

    // Start SRK session
    INITIALIZE_CALL_BUFFERS(TPM2_StartAuthSession, &startAuthSessionIn, &startAuthSessionOut);
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_TpmKey] = g_SrkObject;  // Encrypt salt to SRK
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_Bind] = g_SrkObject;  // Bind session to SRK
    startAuthSessionIn.nonceCaller.t.size = CryptGenerateRandom(SHA256_DIGEST_SIZE, startAuthSessionIn.nonceCaller.t.buffer);
    startAuthSessionIn.sessionType = TPM_SE_HMAC;
    startAuthSessionIn.symmetric.algorithm = TPM_ALG_NULL;
    startAuthSessionIn.authHash = TPM_ALG_SHA256;
    EXECUTE_TPM_CALL(FALSE, TPM2_StartAuthSession);

    // Copy the session out
    sessionTable[0] = parms.objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session;

    // Prepare the session to terminate
    sessionTable[0].attributes.continueSession = CLEAR;

    // Sign digest
    INITIALIZE_CALL_BUFFERS(TPM2_Sign, &signIn, &signOut);
    parms.objectTableIn[0] = g_KeyObject;
    signIn.digest.t.size = SHA256_DIGEST_SIZE;
    MemorySet((TPM2B*)&signIn.digest.t.buffer, 0x11, signIn.digest.t.size);
    signIn.inScheme.scheme = TPM_ALG_RSAPSS;
    signIn.inScheme.details.rsapss.hashAlg = TPM_ALG_SHA256;
    signIn.validation.tag = TPM_ST_HASHCHECK;
    signIn.validation.hierarchy = TPM_RH_NULL;
    EXECUTE_TPM_CALL(FALSE, TPM2_Sign);

    // Start Key session
    INITIALIZE_CALL_BUFFERS(TPM2_StartAuthSession, &startAuthSessionIn, &startAuthSessionOut);
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_TpmKey] = g_SrkObject;  // Encrypt salt to SRK
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_Bind] = g_KeyObject;  // Bind session to the key
    startAuthSessionIn.nonceCaller.t.size = CryptGenerateRandom(SHA256_DIGEST_SIZE, startAuthSessionIn.nonceCaller.t.buffer);
    startAuthSessionIn.sessionType = TPM_SE_HMAC;
    startAuthSessionIn.symmetric.algorithm = TPM_ALG_NULL;
    startAuthSessionIn.authHash = TPM_ALG_SHA256;
    EXECUTE_TPM_CALL(FALSE, TPM2_StartAuthSession);

    // Copy the session out
    sessionTable[0] = parms.objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session;

    // Prepare the session to terminate
    sessionTable[0].attributes.continueSession = CLEAR;

    // Sign digest
    INITIALIZE_CALL_BUFFERS(TPM2_Sign, &signIn, &signOut);
    parms.objectTableIn[0] = g_KeyObject;
    signIn.digest.t.size = SHA256_DIGEST_SIZE;
    MemorySet((TPM2B*)&signIn.digest.t.buffer, 0x11, signIn.digest.t.size);
    signIn.inScheme.scheme = TPM_ALG_RSAPSS;
    signIn.inScheme.details.rsapss.hashAlg = TPM_ALG_SHA256;
    signIn.validation.tag = TPM_ST_HASHCHECK;
    signIn.validation.hierarchy = TPM_RH_NULL;
    EXECUTE_TPM_CALL(FALSE, TPM2_Sign);

Cleanup:
    return result;
}

UINT32
TestSignSalted()
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    StartAuthSession_In startAuthSessionIn = {0};
    StartAuthSession_Out startAuthSessionOut = {0};
    Sign_In signIn = {0};
    Sign_Out signOut = {0};

    // Start SRK session
    INITIALIZE_CALL_BUFFERS(TPM2_StartAuthSession, &startAuthSessionIn, &startAuthSessionOut);
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_TpmKey] = g_SrkObject;  // Encrypt salt to SRK
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_Bind].obj.handle = TPM_RH_NULL;
    startAuthSessionIn.nonceCaller.t.size = CryptGenerateRandom(SHA256_DIGEST_SIZE, startAuthSessionIn.nonceCaller.t.buffer);
    startAuthSessionIn.sessionType = TPM_SE_HMAC;
    startAuthSessionIn.symmetric.algorithm = TPM_ALG_NULL;
    startAuthSessionIn.authHash = TPM_ALG_SHA256;
    EXECUTE_TPM_CALL(FALSE, TPM2_StartAuthSession);

    // Copy the session out
    sessionTable[0] = parms.objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session;

    // Prepare the session to terminate
    sessionTable[0].attributes.continueSession = CLEAR;

    // Sign digest
    INITIALIZE_CALL_BUFFERS(TPM2_Sign, &signIn, &signOut);
    parms.objectTableIn[0] = g_KeyObject;
    signIn.digest.t.size = SHA256_DIGEST_SIZE;
    MemorySet((TPM2B*)&signIn.digest.t.buffer, 0x11, signIn.digest.t.size);
    signIn.inScheme.scheme = TPM_ALG_RSAPSS;
    signIn.inScheme.details.rsapss.hashAlg = TPM_ALG_SHA256;
    signIn.validation.tag = TPM_ST_HASHCHECK;
    signIn.validation.hierarchy = TPM_RH_NULL;
    EXECUTE_TPM_CALL(FALSE, TPM2_Sign);

Cleanup:
    return result;
}

UINT32
TestSignBound()
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    StartAuthSession_In startAuthSessionIn = {0};
    StartAuthSession_Out startAuthSessionOut = {0};
    Sign_In signIn = {0};
    Sign_Out signOut = {0};

    // Start SRK session
    INITIALIZE_CALL_BUFFERS(TPM2_StartAuthSession, &startAuthSessionIn, &startAuthSessionOut);
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_TpmKey].obj.handle = TPM_RH_NULL;
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_Bind] = g_SrkObject;  // Bind session to SRK
    startAuthSessionIn.nonceCaller.t.size = CryptGenerateRandom(SHA256_DIGEST_SIZE, startAuthSessionIn.nonceCaller.t.buffer);
    startAuthSessionIn.sessionType = TPM_SE_HMAC;
    startAuthSessionIn.symmetric.algorithm = TPM_ALG_NULL;
    startAuthSessionIn.authHash = TPM_ALG_SHA256;
    EXECUTE_TPM_CALL(FALSE, TPM2_StartAuthSession);

    // Copy the session out
    sessionTable[0] = parms.objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session;

    // Prepare the session to terminate
    sessionTable[0].attributes.continueSession = CLEAR;

    // Sign digest
    INITIALIZE_CALL_BUFFERS(TPM2_Sign, &signIn, &signOut);
    parms.objectTableIn[0] = g_KeyObject;
    signIn.digest.t.size = SHA256_DIGEST_SIZE;
    MemorySet((TPM2B*)&signIn.digest.t.buffer, 0x11, signIn.digest.t.size);
    signIn.inScheme.scheme = TPM_ALG_RSAPSS;
    signIn.inScheme.details.rsapss.hashAlg = TPM_ALG_SHA256;
    signIn.validation.tag = TPM_ST_HASHCHECK;
    signIn.validation.hierarchy = TPM_RH_NULL;
    EXECUTE_TPM_CALL(FALSE, TPM2_Sign);

    // Start Key session
    INITIALIZE_CALL_BUFFERS(TPM2_StartAuthSession, &startAuthSessionIn, &startAuthSessionOut);
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_TpmKey].obj.handle = TPM_RH_NULL;
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_Bind] = g_KeyObject;  // Bind session to the key
    startAuthSessionIn.nonceCaller.t.size = CryptGenerateRandom(SHA256_DIGEST_SIZE, startAuthSessionIn.nonceCaller.t.buffer);
    startAuthSessionIn.sessionType = TPM_SE_HMAC;
    startAuthSessionIn.symmetric.algorithm = TPM_ALG_NULL;
    startAuthSessionIn.authHash = TPM_ALG_SHA256;
    EXECUTE_TPM_CALL(FALSE, TPM2_StartAuthSession);

    // Copy the session out
    sessionTable[0] = parms.objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session;

    // Prepare the session to terminate
    sessionTable[0].attributes.continueSession = CLEAR;

    // Sign digest
    INITIALIZE_CALL_BUFFERS(TPM2_Sign, &signIn, &signOut);
    parms.objectTableIn[0] = g_KeyObject;
    signIn.digest.t.size = SHA256_DIGEST_SIZE;
    MemorySet((TPM2B*)&signIn.digest.t.buffer, 0x11, signIn.digest.t.size);
    signIn.inScheme.scheme = TPM_ALG_RSAPSS;
    signIn.inScheme.details.rsapss.hashAlg = TPM_ALG_SHA256;
    signIn.validation.tag = TPM_ST_HASHCHECK;
    signIn.validation.hierarchy = TPM_RH_NULL;
    EXECUTE_TPM_CALL(FALSE, TPM2_Sign);

Cleanup:
    return result;
}

UINT32
TestSignHMAC()
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    StartAuthSession_In startAuthSessionIn = { 0 };
    StartAuthSession_Out startAuthSessionOut = { 0 };
    Sign_In signIn = { 0 };
    Sign_Out signOut = { 0 };

    // Start session
    INITIALIZE_CALL_BUFFERS(TPM2_StartAuthSession, &startAuthSessionIn, &startAuthSessionOut);
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_TpmKey].obj.handle = TPM_RH_NULL;
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_Bind].obj.handle = TPM_RH_NULL;
    startAuthSessionIn.nonceCaller.t.size = CryptGenerateRandom(SHA256_DIGEST_SIZE, startAuthSessionIn.nonceCaller.t.buffer);
    startAuthSessionIn.sessionType = TPM_SE_HMAC;
    startAuthSessionIn.symmetric.algorithm = TPM_ALG_NULL;
    startAuthSessionIn.authHash = TPM_ALG_SHA256;
    EXECUTE_TPM_CALL(FALSE, TPM2_StartAuthSession);

    // Copy the session out
    sessionTable[0] = parms.objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session;

    // Prepare the session to terminate
    sessionTable[0].attributes.continueSession = CLEAR;

    // Sign digest
    INITIALIZE_CALL_BUFFERS(TPM2_Sign, &signIn, &signOut);
    parms.objectTableIn[0] = g_KeyObject;
    signIn.digest.t.size = SHA256_DIGEST_SIZE;
    MemorySet((TPM2B*)&signIn.digest.t.buffer, 0x11, signIn.digest.t.size);
    signIn.inScheme.scheme = TPM_ALG_RSAPSS;
    signIn.inScheme.details.rsapss.hashAlg = TPM_ALG_SHA256;
    signIn.validation.tag = TPM_ST_HASHCHECK;
    signIn.validation.hierarchy = TPM_RH_NULL;
    EXECUTE_TPM_CALL(FALSE, TPM2_Sign);

Cleanup:
    return result;
}

UINT32
TestSignWithPW()
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    Sign_In signIn = {0};
    Sign_Out signOut = {0};

    // Create the session
    sessionTable[0].handle = TPM_RS_PW;

    // Sign digest
    INITIALIZE_CALL_BUFFERS(TPM2_Sign, &signIn, &signOut);
    parms.objectTableIn[TPM2_Sign_HdlIn_KeyHandle] = g_KeyObject;
    signIn.digest.t.size = SHA256_DIGEST_SIZE;
    MemorySet((TPM2B*)&signIn.digest.t.buffer, 0x11, signIn.digest.t.size);
    signIn.inScheme.scheme = TPM_ALG_RSAPSS;
    signIn.inScheme.details.rsapss.hashAlg = TPM_ALG_SHA256;
    signIn.validation.tag = TPM_ST_HASHCHECK;
    signIn.validation.hierarchy = TPM_RH_NULL;
    EXECUTE_TPM_CALL(FALSE, TPM2_Sign);

Cleanup:
    return result;
}

UINT32
TestPolicySession()
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    SESSION policySession = { 0 };
    StartAuthSession_In startAuthSessionIn = { 0 };
    StartAuthSession_Out startAuthSessionOut = { 0 };
    PolicyGetDigest_In policyGetDigestIn;
    PolicyGetDigest_Out policyGetDigestOut = {0};
    HASH_STATE hashState = { 0 };
    TPM2B_DIGEST pcrs = { 0 };
    TPM2B_DIGEST policyDigest = { 0 };
    PCR_Read_In pcrReadIn = { 0 };
    PCR_Read_Out pcrReadOut = { 0 };
    PolicyPCR_In policyPCRIn = {0};
    PolicyPCR_Out policyPCROut;
    FlushContext_In flushContextIn;
    FlushContext_Out flushContextOut;

    // Initialize the policyDigest
    policyDigest.t.size = SHA256_DIGEST_SIZE;

    // Start session
    INITIALIZE_CALL_BUFFERS(TPM2_StartAuthSession, &startAuthSessionIn, &startAuthSessionOut);
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_TpmKey].obj.handle = TPM_RH_NULL;
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_Bind].obj.handle = TPM_RH_NULL;
    startAuthSessionIn.nonceCaller.t.size = CryptGenerateRandom(SHA256_DIGEST_SIZE, startAuthSessionIn.nonceCaller.t.buffer);
    startAuthSessionIn.sessionType = TPM_SE_POLICY;
    startAuthSessionIn.symmetric.algorithm = TPM_ALG_NULL;
    startAuthSessionIn.authHash = TPM_ALG_SHA256;
    EXECUTE_TPM_CALL(FALSE, TPM2_StartAuthSession);

    // Copy the session out
    policySession = parms.objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session;

    // Get the current policyDigest
    INITIALIZE_CALL_BUFFERS(TPM2_PolicyGetDigest, &policyGetDigestIn, &policyGetDigestOut);
    parms.objectTableIn[TPM2_PolicyGetDigest_HdlIn_PolicySession].session = policySession;
    EXECUTE_TPM_CALL(FALSE, TPM2_PolicyGetDigest);

    // Copy session back out
    policySession = parms.objectTableIn[TPM2_PolicyGetDigest_HdlIn_PolicySession].session;

    // Check that the policyDigest matches the calulated value
    if(!Memory2BEqual((TPM2B*)&policyGetDigestOut.policyDigest, (TPM2B*)&policyDigest))
    {
        result = TPM_RC_FAILURE;
        goto Cleanup;
    }

    // Check that the policyDigest matches with the session
    if(!Memory2BEqual((TPM2B*)&policyGetDigestOut.policyDigest, (TPM2B*)&policySession.u2.policyDigest))
    {
        result = TPM_RC_FAILURE;
        goto Cleanup;
    }

    // Read PCR[0]
    INITIALIZE_CALL_BUFFERS(TPM2_PCR_Read, &pcrReadIn, &pcrReadOut);
    pcrReadIn.pcrSelectionIn.count = 1;
    pcrReadIn.pcrSelectionIn.pcrSelections[0].hash = TPM_ALG_SHA1;
    pcrReadIn.pcrSelectionIn.pcrSelections[0].sizeofSelect = 3;
    pcrReadIn.pcrSelectionIn.pcrSelections[0].pcrSelect[0] = 0x00000001;
    pcrReadIn.pcrSelectionIn.pcrSelections[0].pcrSelect[1] = 0x00000000;
    pcrReadIn.pcrSelectionIn.pcrSelections[0].pcrSelect[2] = 0x00000000;
    EXECUTE_TPM_CALL(FALSE, TPM2_PCR_Read);

    // Calculate pcrs
    pcrs.t.size = CryptStartHash(startAuthSessionIn.authHash, &hashState);
    for(UINT32 n = 0; n < pcrReadOut.pcrValues.count; n++)
    {
        CryptUpdateDigest2B(&hashState, &pcrReadOut.pcrValues.digests[n].b);
    }
    pcrs.t.size = CryptCompleteHash2B(&hashState, &pcrs.b);

    // Add PCR policy
    INITIALIZE_CALL_BUFFERS(TPM2_PolicyPCR, &policyPCRIn, &policyPCROut);
    parms.objectTableIn[TPM2_PolicyPCR_HdlIn_PolicySession].session = policySession;
    policyPCRIn.pcrs.count = 1;
    policyPCRIn.pcrs.pcrSelections[0].hash = TPM_ALG_SHA1;
    policyPCRIn.pcrs.pcrSelections[0].sizeofSelect = 3;
    policyPCRIn.pcrs.pcrSelections[0].pcrSelect[0] = 0x00000001;
    policyPCRIn.pcrs.pcrSelections[0].pcrSelect[1] = 0x00000000;
    policyPCRIn.pcrs.pcrSelections[0].pcrSelect[2] = 0x00000000;
    policyPCRIn.pcrDigest = pcrs;
    EXECUTE_TPM_CALL(FALSE, TPM2_PolicyPCR);

    // Copy session back out
    policySession = parms.objectTableIn[TPM2_PolicyGetDigest_HdlIn_PolicySession].session;

    // Calulate the policyDigeat
    TPM2_PolicyPCR_CalculateUpdate(startAuthSessionIn.authHash, &policyDigest, &policyPCRIn);

    // Check that the policyDigest matches with the session
    if(!Memory2BEqual((TPM2B*)&policyDigest, (TPM2B*)&policySession.u2.policyDigest))
    {
        result = TPM_RC_FAILURE;
        goto Cleanup;
    }

    // Get the current policy digest from the TPM
    INITIALIZE_CALL_BUFFERS(TPM2_PolicyGetDigest, &policyGetDigestIn, &policyGetDigestOut);
    parms.objectTableIn[TPM2_PolicyGetDigest_HdlIn_PolicySession].session = policySession;
    EXECUTE_TPM_CALL(FALSE, TPM2_PolicyGetDigest);

    // Copy session back out
    policySession = parms.objectTableIn[TPM2_PolicyGetDigest_HdlIn_PolicySession].session;

    // Check that the policyDigest matches the value in the TPM
    if(!Memory2BEqual((TPM2B*)&policyDigest, (TPM2B*)&policyGetDigestOut.policyDigest))
    {
        result = TPM_RC_FAILURE;
        goto Cleanup;
    }

    // Check that the policyDigest matches with the session
    if(!Memory2BEqual((TPM2B*)&policyDigest, (TPM2B*)&policySession.u2.policyDigest))
    {
        result = TPM_RC_FAILURE;
        goto Cleanup;
    }

    // Unload the Session
    INITIALIZE_CALL_BUFFERS(TPM2_FlushContext, &flushContextIn, &flushContextOut);
    parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle].session = policySession;
    EXECUTE_TPM_CALL(FALSE, TPM2_FlushContext);

Cleanup:
    return result;
}

UINT32
TestReadPcrWithEkSeededSession()
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    StartAuthSession_In startAuthSessionIn = {0};
    StartAuthSession_Out startAuthSessionOut = {0};
    PCR_Read_In pcrReadIn = { 0 };
    PCR_Read_Out pcrReadOut = { 0 };

    // Start EK salted session
    INITIALIZE_CALL_BUFFERS(TPM2_StartAuthSession, &startAuthSessionIn, &startAuthSessionOut);
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_TpmKey] = g_EkObject;  // Encrypt salt to EK
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_Bind].obj.handle = TPM_RH_NULL;
    startAuthSessionIn.nonceCaller.t.size = CryptGenerateRandom(SHA256_DIGEST_SIZE, startAuthSessionIn.nonceCaller.t.buffer);
    startAuthSessionIn.sessionType = TPM_SE_HMAC;
    startAuthSessionIn.symmetric.algorithm = TPM_ALG_NULL;
    startAuthSessionIn.authHash = TPM_ALG_SHA256;
    EXECUTE_TPM_CALL(FALSE, TPM2_StartAuthSession);

    // Copy the session out
    sessionTable[0] = parms.objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session;

    // Mark the session as Audit
    sessionTable[0].attributes.audit = SET;

    // Prepare the session to terminate
    sessionTable[0].attributes.continueSession = CLEAR;

    // Read the PCRs with session
    INITIALIZE_CALL_BUFFERS(TPM2_PCR_Read, &pcrReadIn, &pcrReadOut);
    sessionCnt += 1; // Add the EK session
    pcrReadIn.pcrSelectionIn.count = 1;
    pcrReadIn.pcrSelectionIn.pcrSelections[0].hash = TPM_ALG_SHA1;
    pcrReadIn.pcrSelectionIn.pcrSelections[0].sizeofSelect = 3;
    pcrReadIn.pcrSelectionIn.pcrSelections[0].pcrSelect[0] = 0x00000001;
    pcrReadIn.pcrSelectionIn.pcrSelections[0].pcrSelect[1] = 0x00000000;
    pcrReadIn.pcrSelectionIn.pcrSelections[0].pcrSelect[2] = 0x00000000;
    EXECUTE_TPM_CALL(FALSE, TPM2_PCR_Read);

Cleanup:
    return result;
}

UINT32
TestCreateHashAndHMACSequence()
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    ANY_OBJECT sequence = { 0 };
    BYTE userData[] = "The quick brown fox jumps over the lazy dog";
    BYTE userKey[] = "ThisIsMyHmacKey";
    BYTE sha256Reference[] = { 0xd7, 0xa8, 0xfb, 0xb3, 0x07, 0xd7, 0x80, 0x94, 0x69, 0xca, 0x9a, 0xbc, 0xb0, 0x08, 0x2e, 0x4f, 0x8d, 0x56, 0x51, 0xe4, 0x6d, 0x3c, 0xdb, 0x76, 0x2d, 0x02, 0xd0, 0xbf, 0x37, 0xc9, 0xe5, 0x92 };
    BYTE sha256HmacReference[] = { 0x90, 0xd1, 0x29, 0x1d, 0x13, 0x37, 0x51, 0xa6, 0x57, 0x37, 0x37, 0xbc, 0xdb, 0xb8, 0x2c, 0x6a, 0x34, 0xd0, 0x9c, 0x77, 0x32, 0x9a, 0x26, 0x6a, 0xfa, 0xcb, 0x89, 0x97, 0xeb, 0x3d, 0x1f, 0xce };
    HashSequenceStart_In hashSequenceStartIn = { 0 };
    HashSequenceStart_Out hashSequenceStartOut = { 0 };
    HMAC_Start_In hmac_StartIn = { 0 };
    HMAC_Start_Out hmac_StartOut = { 0 };
    SequenceUpdate_In sequenceUpdateIn = { 0 };
    SequenceUpdate_Out sequenceUpdateOut;
    SequenceComplete_In sequenceCompleteIn = { 0 };
    SequenceComplete_Out sequenceCompleteOut = { 0 };
    Create_In createIn = { 0 };
    Create_Out createOut = { 0 };
    ANY_OBJECT hmacKey = { 0 };
    Load_In loadIn = { 0 };
    Load_Out loadOut = { 0 };
    FlushContext_In flushContextIn;
    FlushContext_Out flushContextOut;

    // Create the session
    sessionTable[0].handle = TPM_RS_PW;

    // Start SHA-256 digest
    INITIALIZE_CALL_BUFFERS(TPM2_HashSequenceStart, &hashSequenceStartIn, &hashSequenceStartOut);
    hashSequenceStartIn.auth.t.size = sizeof(g_UsageAuth);
    MemoryCopy(hashSequenceStartIn.auth.t.buffer, g_UsageAuth, sizeof(g_UsageAuth), sizeof(hashSequenceStartIn.auth.t.buffer));
    hashSequenceStartIn.hashAlg = TPM_ALG_SHA256;
    EXECUTE_TPM_CALL(FALSE, TPM2_HashSequenceStart);
    sequence = parms.objectTableOut[TPM2_HashSequenceStart_HdlOut_SequenceHandle];

    // Update the SHA-256 digest
    INITIALIZE_CALL_BUFFERS(TPM2_SequenceUpdate, &sequenceUpdateIn, &sequenceUpdateOut);
    parms.objectTableIn[TPM2_SequenceUpdate_HdlIn_SequenceHandle] = sequence;
    sequenceUpdateIn.buffer.t.size = sizeof(userData);
    MemoryCopy(sequenceUpdateIn.buffer.t.buffer, userData, sizeof(userData), sizeof(sequenceUpdateIn.buffer.t.buffer));
    EXECUTE_TPM_CALL(FALSE, TPM2_SequenceUpdate);

    // Finalize the SHA-256 digest
    INITIALIZE_CALL_BUFFERS(TPM2_SequenceComplete, &sequenceCompleteIn, &sequenceCompleteOut);
    parms.objectTableIn[TPM2_SequenceComplete_HdlIn_SequenceHandle] = sequence;
    sequenceCompleteIn.hierarchy = TPM_RH_NULL;
    EXECUTE_TPM_CALL(FALSE, TPM2_SequenceComplete);
    sequence = parms.objectTableIn[TPM2_SequenceComplete_HdlIn_SequenceHandle];

    if ((sequenceCompleteOut.result.t.size != sizeof(sha256Reference)) &&
        (!MemoryEqual(sequenceCompleteOut.result.t.buffer, sha256Reference, sizeof(sha256Reference))))
    {
        result = TPM_RC_FAILURE;
    }

    // Create the SHA-256 HMAC key
    INITIALIZE_CALL_BUFFERS(TPM2_Create, &createIn, &createOut);
    parms.objectTableIn[TPM2_Create_HdlIn_ParentHandle] = g_SrkObject;
    createIn.inSensitive.t.sensitive.userAuth.t.size = sizeof(g_UsageAuth);
    MemoryCopy(createIn.inSensitive.t.sensitive.userAuth.t.buffer, g_UsageAuth, createIn.inSensitive.t.sensitive.userAuth.t.size, sizeof(createIn.inSensitive.t.sensitive.userAuth.t.buffer));
    MemoryRemoveTrailingZeros(&createIn.inSensitive.t.sensitive.userAuth);
    createIn.inSensitive.t.sensitive.data.t.size = sizeof(userKey);
    MemoryCopy(createIn.inSensitive.t.sensitive.data.t.buffer, userKey, sizeof(userKey), sizeof(createIn.inSensitive.t.sensitive.data.t.buffer));
    createIn.inPublic.t.publicArea.type = TPM_ALG_KEYEDHASH;
    createIn.inPublic.t.publicArea.nameAlg = TPM_ALG_SHA256;
    createIn.inPublic.t.publicArea.objectAttributes.userWithAuth = 1;
    createIn.inPublic.t.publicArea.objectAttributes.noDA = 1;
    createIn.inPublic.t.publicArea.objectAttributes.sign = 1;
    createIn.inPublic.t.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_HMAC;
    createIn.inPublic.t.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = TPM_ALG_SHA256;
    EXECUTE_TPM_CALL(FALSE, TPM2_Create);

    // Copy the SHA-256 HMAC key out
    hmacKey.obj.publicArea = createOut.outPublic;
    hmacKey.obj.privateArea = createOut.outPrivate;
    hmacKey.obj.authValue = createIn.inSensitive.t.sensitive.userAuth;

    // Load the SHA-256 HMAC
    INITIALIZE_CALL_BUFFERS(TPM2_Load, &loadIn, &loadOut);
    parms.objectTableIn[TPM2_Load_HdlIn_ParentHandle] = g_SrkObject;
    parms.objectTableOut[TPM2_Load_HdlOut_ObjectHandle] = hmacKey; // Copy the key in to be updated
    loadIn.inPublic = hmacKey.obj.publicArea;
    loadIn.inPrivate = hmacKey.obj.privateArea;
    EXECUTE_TPM_CALL(FALSE, TPM2_Load);

    // Copy the updated SHA-256 HMAC back out
    hmacKey = parms.objectTableOut[TPM2_Load_HdlOut_ObjectHandle];

    // Start SHA-256 hmac
    INITIALIZE_CALL_BUFFERS(TPM2_HMAC_Start, &hmac_StartIn, &hmac_StartOut);
    parms.objectTableIn[TPM2_HMAC_Start_HdlIn_Handle] = hmacKey;
    hmac_StartIn.auth.t.size = sizeof(g_UsageAuth);
    MemoryCopy(hmac_StartIn.auth.t.buffer, g_UsageAuth, sizeof(g_UsageAuth), sizeof(hmac_StartIn.auth.t.buffer));
    hmac_StartIn.hashAlg = TPM_ALG_SHA256;
    EXECUTE_TPM_CALL(FALSE, TPM2_HMAC_Start);
    sequence = parms.objectTableOut[TPM2_HashSequenceStart_HdlOut_SequenceHandle];

    // Update the SHA-256 digest
    INITIALIZE_CALL_BUFFERS(TPM2_SequenceUpdate, &sequenceUpdateIn, &sequenceUpdateOut);
    parms.objectTableIn[TPM2_SequenceUpdate_HdlIn_SequenceHandle] = sequence;
    sequenceUpdateIn.buffer.t.size = sizeof(userData);
    MemoryCopy(sequenceUpdateIn.buffer.t.buffer, userData, sizeof(userData), sizeof(sequenceUpdateIn.buffer.t.buffer));
    EXECUTE_TPM_CALL(FALSE, TPM2_SequenceUpdate);

    // Finalize the SHA-256 digest
    INITIALIZE_CALL_BUFFERS(TPM2_SequenceComplete, &sequenceCompleteIn, &sequenceCompleteOut);
    parms.objectTableIn[TPM2_SequenceUpdate_HdlIn_SequenceHandle] = sequence;
    sequenceCompleteIn.hierarchy = TPM_RH_NULL;
    EXECUTE_TPM_CALL(FALSE, TPM2_SequenceComplete);
    sequence = parms.objectTableIn[TPM2_SequenceComplete_HdlIn_SequenceHandle];

    if ((sequenceCompleteOut.result.t.size != sizeof(sha256HmacReference)) &&
        (!MemoryEqual(sequenceCompleteOut.result.t.buffer, sha256HmacReference, sizeof(sha256HmacReference))))
    {
        result = TPM_RC_FAILURE;
    }

    // Unload the SHA256 HMAC key
    INITIALIZE_CALL_BUFFERS(TPM2_FlushContext, &flushContextIn, &flushContextOut);
    parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle] = hmacKey;
    EXECUTE_TPM_CALL(FALSE, TPM2_FlushContext);

    // Copy the updated SHA-256 HMAC back out
    hmacKey = parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle];

Cleanup:
    return result;
}

UINT32
TestCreateHashAndHMAC()
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    BYTE userData[] = "The quick brown fox jumps over the lazy dog";
    BYTE userKey[] = "ThisIsMyHmacKey";
    BYTE sha1Reference[] = {0x2f, 0xd4, 0xe1, 0xc6, 0x7a, 0x2d, 0x28, 0xfc, 0xed, 0x84, 0x9e, 0xe1, 0xbb, 0x76, 0xe7, 0x39, 0x1b, 0x93, 0xeb, 0x12};
    BYTE sha256Reference[] = {0xd7, 0xa8, 0xfb, 0xb3, 0x07, 0xd7, 0x80, 0x94, 0x69, 0xca, 0x9a, 0xbc, 0xb0, 0x08, 0x2e, 0x4f, 0x8d, 0x56, 0x51, 0xe4, 0x6d, 0x3c, 0xdb, 0x76, 0x2d, 0x02, 0xd0, 0xbf, 0x37, 0xc9, 0xe5, 0x92};
    BYTE sha1HmacReference[] = {0x33, 0x68, 0xf5, 0x98, 0x31, 0x0b, 0xc7, 0x8f, 0x32, 0x88, 0x5e, 0x9b, 0x93, 0x40, 0xd5, 0xc4, 0xce, 0x96, 0x55, 0x9a};
    BYTE sha256HmacReference[] = {0x90, 0xd1, 0x29, 0x1d, 0x13, 0x37, 0x51, 0xa6, 0x57, 0x37, 0x37, 0xbc, 0xdb, 0xb8, 0x2c, 0x6a, 0x34, 0xd0, 0x9c, 0x77, 0x32, 0x9a, 0x26, 0x6a, 0xfa, 0xcb, 0x89, 0x97, 0xeb, 0x3d, 0x1f, 0xce};
    Hash_In hashIn = {0};
    Hash_Out hashOut = {0};
    Create_In createIn = {0};
    Create_Out createOut = {0};
    ANY_OBJECT hmacKey = {0};
    Load_In loadIn = {0};
    Load_Out loadOut = {0};
    FlushContext_In flushContextIn;
    FlushContext_Out flushContextOut;
    HMAC_In hmacIn = {0};
    HMAC_Out hmacOut = {0};

    // Calculate a SHA-1 digest
    INITIALIZE_CALL_BUFFERS(TPM2_Hash, &hashIn, &hashOut);
    hashIn.data.t.size = sizeof(userData);
    MemoryCopy(hashIn.data.t.buffer, userData, hashIn.data.t.size, sizeof(hashIn.data.t.buffer));
    hashIn.hashAlg = TPM_ALG_SHA1;
    hashIn.hierarchy = TPM_RH_NULL;
    EXECUTE_TPM_CALL(FALSE, TPM2_Hash);

    if((hashOut.outHash.t.size != sizeof(sha1Reference)) &&
        (!MemoryEqual(hashOut.outHash.t.buffer, sha1Reference, sizeof(sha1Reference))))
    {
        result = TPM_RC_FAILURE;
    }

    // Calculate a SHA-256 digest
    INITIALIZE_CALL_BUFFERS(TPM2_Hash, &hashIn, &hashOut);
    hashIn.data.t.size = sizeof(userData);
    MemoryCopy(hashIn.data.t.buffer, userData, hashIn.data.t.size, sizeof(hashIn.data.t.buffer));
    hashIn.hashAlg = TPM_ALG_SHA256;
    hashIn.hierarchy = TPM_RH_NULL;
    EXECUTE_TPM_CALL(FALSE, TPM2_Hash);

    if((hashOut.outHash.t.size != sizeof(sha256Reference)) &&
        (!MemoryEqual(hashOut.outHash.t.buffer, sha256Reference, sizeof(sha256Reference))))
    {
        result = TPM_RC_FAILURE;
    }

    // Create the session
    sessionTable[0].handle = TPM_RS_PW;

    // Create the SHA-1 HMAC key
    INITIALIZE_CALL_BUFFERS(TPM2_Create, &createIn, &createOut);
    parms.objectTableIn[TPM2_Create_HdlIn_ParentHandle] = g_SrkObject;
    createIn.inSensitive.t.sensitive.userAuth.t.size = sizeof(g_UsageAuth);
    MemoryCopy(createIn.inSensitive.t.sensitive.userAuth.t.buffer, g_UsageAuth, createIn.inSensitive.t.sensitive.userAuth.t.size, sizeof(createIn.inSensitive.t.sensitive.userAuth.t.buffer));
    MemoryRemoveTrailingZeros(&createIn.inSensitive.t.sensitive.userAuth);
    createIn.inSensitive.t.sensitive.data.t.size = sizeof(userKey);
    MemoryCopy(createIn.inSensitive.t.sensitive.data.t.buffer, userKey, sizeof(userKey), sizeof(createIn.inSensitive.t.sensitive.data.t.buffer));
    createIn.inPublic.t.publicArea.type = TPM_ALG_KEYEDHASH;
    createIn.inPublic.t.publicArea.nameAlg = TPM_ALG_SHA256;
    createIn.inPublic.t.publicArea.objectAttributes.userWithAuth = 1;
    createIn.inPublic.t.publicArea.objectAttributes.noDA = 1;
    createIn.inPublic.t.publicArea.objectAttributes.sign = 1;
    createIn.inPublic.t.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_HMAC;
    createIn.inPublic.t.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = TPM_ALG_SHA1;
    EXECUTE_TPM_CALL(FALSE, TPM2_Create);

    // Copy the SHA-1 HMAC key out
    hmacKey.obj.publicArea = createOut.outPublic;
    hmacKey.obj.privateArea = createOut.outPrivate;
    hmacKey.obj.authValue = createIn.inSensitive.t.sensitive.userAuth;

    // Load the SHA-1 HMAC
    INITIALIZE_CALL_BUFFERS(TPM2_Load, &loadIn, &loadOut);
    parms.objectTableIn[TPM2_Load_HdlIn_ParentHandle] = g_SrkObject;
    parms.objectTableOut[TPM2_Load_HdlOut_ObjectHandle] = hmacKey; // Copy the key in to be updated
    loadIn.inPublic = hmacKey.obj.publicArea;
    loadIn.inPrivate = hmacKey.obj.privateArea;
    EXECUTE_TPM_CALL(FALSE, TPM2_Load);

    // Copy the updated SHA-1 HMAC back out
    hmacKey = parms.objectTableOut[TPM2_Load_HdlOut_ObjectHandle];

    // Calculate a SHA-1 HMAC
    INITIALIZE_CALL_BUFFERS(TPM2_HMAC, &hmacIn, &hmacOut);
    parms.objectTableIn[TPM2_HMAC_HdlIn_Handle] = hmacKey;
    hmacIn.buffer.t.size = sizeof(userData);
    MemoryCopy(hmacIn.buffer.t.buffer, userData, hmacIn.buffer.t.size, sizeof(hmacIn.buffer.t.buffer));
    hmacIn.hashAlg = TPM_ALG_SHA1;
    EXECUTE_TPM_CALL(FALSE, TPM2_HMAC);

    if((hmacOut.outHMAC.t.size != sizeof(sha1HmacReference)) &&
        (!MemoryEqual(hmacOut.outHMAC.t.buffer, sha1HmacReference, sizeof(sha1HmacReference))))
    {
        result = TPM_RC_FAILURE;
    }

    // Unload the SHA1 HMAC key
    INITIALIZE_CALL_BUFFERS(TPM2_FlushContext, &flushContextIn, &flushContextOut);
    parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle] = hmacKey;
    EXECUTE_TPM_CALL(FALSE, TPM2_FlushContext);

    // Copy the updated SHA-1 HMAC back out
    hmacKey = parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle];

    // Create the SHA-256 HMAC key
    INITIALIZE_CALL_BUFFERS(TPM2_Create, &createIn, &createOut);
    parms.objectTableIn[TPM2_Create_HdlIn_ParentHandle] = g_SrkObject;
    createIn.inSensitive.t.sensitive.userAuth.t.size = sizeof(g_UsageAuth);
    MemoryCopy(createIn.inSensitive.t.sensitive.userAuth.t.buffer, g_UsageAuth, createIn.inSensitive.t.sensitive.userAuth.t.size, sizeof(createIn.inSensitive.t.sensitive.userAuth.t.buffer));
    MemoryRemoveTrailingZeros(&createIn.inSensitive.t.sensitive.userAuth);
    createIn.inSensitive.t.sensitive.data.t.size = sizeof(userKey);
    MemoryCopy(createIn.inSensitive.t.sensitive.data.t.buffer, userKey, sizeof(userKey), sizeof(createIn.inSensitive.t.sensitive.data.t.buffer));
    createIn.inPublic.t.publicArea.type = TPM_ALG_KEYEDHASH;
    createIn.inPublic.t.publicArea.nameAlg = TPM_ALG_SHA256;
    createIn.inPublic.t.publicArea.objectAttributes.userWithAuth = 1;
    createIn.inPublic.t.publicArea.objectAttributes.noDA = 1;
    createIn.inPublic.t.publicArea.objectAttributes.sign = 1;
    createIn.inPublic.t.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_HMAC;
    createIn.inPublic.t.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = TPM_ALG_SHA256;
    EXECUTE_TPM_CALL(FALSE, TPM2_Create);

    // Copy the SHA-256 HMAC key out
    hmacKey.obj.publicArea = createOut.outPublic;
    hmacKey.obj.privateArea = createOut.outPrivate;
    hmacKey.obj.authValue = createIn.inSensitive.t.sensitive.userAuth;

    // Load the SHA-256 HMAC
    INITIALIZE_CALL_BUFFERS(TPM2_Load, &loadIn, &loadOut);
    parms.objectTableIn[TPM2_Load_HdlIn_ParentHandle] = g_SrkObject;
    parms.objectTableOut[TPM2_Load_HdlOut_ObjectHandle] = hmacKey; // Copy the key in to be updated
    loadIn.inPublic = hmacKey.obj.publicArea;
    loadIn.inPrivate = hmacKey.obj.privateArea;
    EXECUTE_TPM_CALL(FALSE, TPM2_Load);

    // Copy the updated SHA-256 HMAC back out
    hmacKey = parms.objectTableOut[TPM2_Load_HdlOut_ObjectHandle];

    // Calculate a SHA-256 HMAC
    INITIALIZE_CALL_BUFFERS(TPM2_HMAC, &hmacIn, &hmacOut);
    parms.objectTableIn[TPM2_HMAC_HdlIn_Handle] = hmacKey;
    hmacIn.buffer.t.size = sizeof(userData);
    MemoryCopy(hmacIn.buffer.t.buffer, userData, hmacIn.buffer.t.size, sizeof(hmacIn.buffer.t.buffer));
    hmacIn.hashAlg = TPM_ALG_SHA256;
    EXECUTE_TPM_CALL(FALSE, TPM2_HMAC);

    if((hmacOut.outHMAC.t.size != sizeof(sha256HmacReference)) &&
        (!MemoryEqual(hmacOut.outHMAC.t.buffer, sha256HmacReference, sizeof(sha256HmacReference))))
    {
        result = TPM_RC_FAILURE;
    }

    // Unload the SHA1 HMAC key
    INITIALIZE_CALL_BUFFERS(TPM2_FlushContext, &flushContextIn, &flushContextOut);
    parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle] = hmacKey;
    EXECUTE_TPM_CALL(FALSE, TPM2_FlushContext);

    // Copy the updated SHA-1 HMAC back out
    hmacKey = parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle];

Cleanup:
    return result;
}

UINT32
TestSymKeyImport()
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    BYTE userData[] = "The quick brown fox jumps over the lazy dog";
    BYTE userKey[] = "ThisIsMyHmacKey";
    BYTE sha256HmacReference[] = {0x90, 0xd1, 0x29, 0x1d, 0x13, 0x37, 0x51, 0xa6, 0x57, 0x37, 0x37, 0xbc, 0xdb, 0xb8, 0x2c, 0x6a, 0x34, 0xd0, 0x9c, 0x77, 0x32, 0x9a, 0x26, 0x6a, 0xfa, 0xcb, 0x89, 0x97, 0xeb, 0x3d, 0x1f, 0xce};
    ANY_OBJECT hmacKey = {0};
    Import_In importIn = {0};
    Import_Out importOut = {0};
    Load_In loadIn = {0};
    Load_Out loadOut = {0};
    FlushContext_In flushContextIn;
    FlushContext_Out flushContextOut;
    HMAC_In hmacIn = {0};
    HMAC_Out hmacOut = {0};

    TPMS_SENSITIVE_CREATE sensitiveCreate = {0};
    TPMT_SENSITIVE sensitive = {0};
    TPM2B_NAME name = {0};
    TPM2B_SEED seed = {0};
    TPM2B_DATA innerKey = {0};
    TPMT_SYM_DEF_OBJECT symDef = {TPM_ALG_NULL, 0, TPM_ALG_NULL};
    OBJECT newParent = {0};
    TPM2B_ENCRYPTED_SECRET inSymSeed = {0};

    // Build a hostage key. Start with the public portion.
    hmacKey.obj.publicArea.t.publicArea.type = TPM_ALG_KEYEDHASH;
    hmacKey.obj.publicArea.t.publicArea.nameAlg = TPM_ALG_SHA256;
    hmacKey.obj.publicArea.t.publicArea.objectAttributes.userWithAuth = 1;
    hmacKey.obj.publicArea.t.publicArea.objectAttributes.noDA = 1;
    hmacKey.obj.publicArea.t.publicArea.objectAttributes.sign = 1;
    hmacKey.obj.publicArea.t.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_HMAC;
    hmacKey.obj.publicArea.t.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = TPM_ALG_SHA256;

    // Fill out the private portion
    sensitiveCreate.userAuth.t.size = sizeof(g_UsageAuth);
    MemoryCopy(sensitiveCreate.userAuth.t.buffer, g_UsageAuth, sensitiveCreate.userAuth.t.size, sizeof(sensitiveCreate.userAuth.t.buffer));
    MemoryRemoveTrailingZeros(&sensitiveCreate.userAuth);
    sensitiveCreate.data.t.size = sizeof(userKey);
    MemoryCopy(sensitiveCreate.data.t.buffer, userKey, sizeof(userKey), sizeof(sensitiveCreate.data.t.buffer));
    MemoryRemoveTrailingZeros((TPM2B_AUTH*)&sensitiveCreate.data);

    // Create the symmetric object
    if((result = CryptCreateObject(&g_SrkObject,
                                   &hmacKey.obj.publicArea.t.publicArea,
                                   &sensitiveCreate,
                                   &sensitive)) != TPM_RC_SUCCESS)
    {
        goto Cleanup;
    }

    // Create the session
    sessionTable[0].handle = TPM_RS_PW;

    // Import the SHA-256 HMAC key unprotected
    INITIALIZE_CALL_BUFFERS(TPM2_Import, &importIn, &importOut);
    parms.objectTableIn[TPM2_Import_HdlIn_ParentHandle] = g_SrkObject;
    importIn.encryptionKey.t.size = 0;
    importIn.objectPublic = hmacKey.obj.publicArea;
    importIn.inSymSeed.t.size = 0;
    importIn.symmetricAlg.algorithm = TPM_ALG_NULL;
    ObjectComputeName(&hmacKey.obj.publicArea.t.publicArea, &name);
    SensitiveToDuplicate(&sensitive,
                         &name,
                         &g_SrkObject,
                         hmacKey.obj.publicArea.t.publicArea.nameAlg,
                         (TPM2B_SEED*)&importIn.inSymSeed,
                         &importIn.symmetricAlg,
                         &innerKey,
                         &importIn.duplicate);
    EXECUTE_TPM_CALL(FALSE, TPM2_Import);

    // Copy the SHA-256 HMAC key out
    hmacKey.obj.privateArea = importOut.outPrivate;
    hmacKey.obj.authValue = sensitive.authValue;

    // Load the key
    INITIALIZE_CALL_BUFFERS(TPM2_Load, &loadIn, &loadOut);
    parms.objectTableIn[TPM2_Load_HdlIn_ParentHandle] = g_SrkObject;
    parms.objectTableOut[TPM2_Load_HdlOut_ObjectHandle] = hmacKey; // Copy the key in to be updated
    loadIn.inPublic = hmacKey.obj.publicArea;
    loadIn.inPrivate = hmacKey.obj.privateArea;
    EXECUTE_TPM_CALL(FALSE, TPM2_Load);

    // Copy the updated SHA-256 HMAC key back out
    hmacKey = parms.objectTableOut[TPM2_Load_HdlOut_ObjectHandle];

    // Calculate a SHA-256 HMAC
    INITIALIZE_CALL_BUFFERS(TPM2_HMAC, &hmacIn, &hmacOut);
    parms.objectTableIn[TPM2_HMAC_HdlIn_Handle] = hmacKey;
    hmacIn.buffer.t.size = sizeof(userData);
    MemoryCopy(hmacIn.buffer.t.buffer, userData, hmacIn.buffer.t.size, sizeof(hmacIn.buffer.t.buffer));
    hmacIn.hashAlg = TPM_ALG_SHA256;
    EXECUTE_TPM_CALL(FALSE, TPM2_HMAC);

    if((hmacOut.outHMAC.t.size != sizeof(sha256HmacReference)) &&
        (!MemoryEqual(hmacOut.outHMAC.t.buffer, sha256HmacReference, sizeof(sha256HmacReference))))
    {
        result = TPM_RC_FAILURE;
    }

    // Unload the SHA-256 HMAC key
    INITIALIZE_CALL_BUFFERS(TPM2_FlushContext, &flushContextIn, &flushContextOut);
    parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle] = hmacKey;
    EXECUTE_TPM_CALL(FALSE, TPM2_FlushContext);

    // Copy the updated SHA-256 HMAC back out
    hmacKey = parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle];

    // Create a protected key import blob
    newParent.publicArea = g_SrkObject.obj.publicArea.t.publicArea;
    newParent.name = name;
    seed.t.size = SHA256_DIGEST_SIZE;
    inSymSeed.t.size = sizeof(inSymSeed.t.secret);
    if((result = CryptSecretEncrypt(&newParent, "DUPLICATE", (TPM2B_DATA*)&seed, &inSymSeed)) != TPM_RC_SUCCESS)
    {
        goto Cleanup;
    }
    ObjectComputeName(&hmacKey.obj.publicArea.t.publicArea, &name);
    SensitiveToDuplicate(&sensitive,
                         &name,
                         &g_SrkObject,
                         hmacKey.obj.publicArea.t.publicArea.nameAlg,
                         &seed,
                         &symDef,
                         &innerKey,
                         &hmacKey.obj.privateArea);

    // Import the protected SHA-256 HMAC key
    INITIALIZE_CALL_BUFFERS(TPM2_Import, &importIn, &importOut);
    parms.objectTableIn[TPM2_Import_HdlIn_ParentHandle] = g_SrkObject;
    importIn.objectPublic = hmacKey.obj.publicArea;
    importIn.inSymSeed = inSymSeed;
    importIn.duplicate = hmacKey.obj.privateArea;
    importIn.symmetricAlg.algorithm = TPM_ALG_NULL;
    EXECUTE_TPM_CALL(FALSE, TPM2_Import);

    // Copy the SHA-256 HMAC key out
    hmacKey.obj.privateArea = importOut.outPrivate;
    hmacKey.obj.authValue = sensitive.authValue;

    // Load the key
    INITIALIZE_CALL_BUFFERS(TPM2_Load, &loadIn, &loadOut);
    parms.objectTableIn[TPM2_Load_HdlIn_ParentHandle] = g_SrkObject;
    parms.objectTableOut[TPM2_Load_HdlOut_ObjectHandle] = hmacKey; // Copy the key in to be updated
    loadIn.inPublic = hmacKey.obj.publicArea;
    loadIn.inPrivate = hmacKey.obj.privateArea;
    EXECUTE_TPM_CALL(FALSE, TPM2_Load);

    // Copy the updated SHA-256 HMAC key back out
    hmacKey = parms.objectTableOut[TPM2_Load_HdlOut_ObjectHandle];

    // Calculate a SHA-256 HMAC
    INITIALIZE_CALL_BUFFERS(TPM2_HMAC, &hmacIn, &hmacOut);
    parms.objectTableIn[TPM2_HMAC_HdlIn_Handle] = hmacKey;
    hmacIn.buffer.t.size = sizeof(userData);
    MemoryCopy(hmacIn.buffer.t.buffer, userData, hmacIn.buffer.t.size, sizeof(hmacIn.buffer.t.buffer));
    hmacIn.hashAlg = TPM_ALG_SHA256;
    EXECUTE_TPM_CALL(FALSE, TPM2_HMAC);

    if((hmacOut.outHMAC.t.size != sizeof(sha256HmacReference)) &&
        (!MemoryEqual(hmacOut.outHMAC.t.buffer, sha256HmacReference, sizeof(sha256HmacReference))))
    {
        result = TPM_RC_FAILURE;
    }

    // Unload the SHA-256 HMAC key
    INITIALIZE_CALL_BUFFERS(TPM2_FlushContext, &flushContextIn, &flushContextOut);
    parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle] = hmacKey;
    EXECUTE_TPM_CALL(FALSE, TPM2_FlushContext);

    // Copy the updated SHA-256 HMAC back out
    hmacKey = parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle];

Cleanup:
    return result;
}

UINT32
TestRsaKeyImport()
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    ANY_OBJECT rsaKey = {0};
    Import_In importIn = {0};
    Import_Out importOut = {0};
    Load_In loadIn = {0};
    Load_Out loadOut = {0};
    Sign_In signIn = {0};
    Sign_Out signOut = {0};
    FlushContext_In flushContextIn;
    FlushContext_Out flushContextOut;

    BCRYPT_KEY_HANDLE hSwKey = NULL;
    BYTE swKey[1024] = {0};
    BCRYPT_RSAKEY_BLOB *pSwKey = (BCRYPT_RSAKEY_BLOB*)swKey;
    ULONG cbSwKey = 0;
    BCRYPT_PSS_PADDING_INFO padding = {BCRYPT_SHA256_ALGORITHM, (256 - 32 - 2)};
    TPMT_SENSITIVE sensitive = {0};
    TPM2B_NAME name = {0};
    TPM2B_SEED seed = {0};
    TPM2B_DATA innerKey = {0};
    TPMT_SYM_DEF_OBJECT symDef = {TPM_ALG_NULL, 0, TPM_ALG_NULL};
    OBJECT newParent = {0};
    TPM2B_ENCRYPTED_SECRET inSymSeed = {0};

    // Create SW key
    if(((result = BCryptGenerateKeyPair(g_hRsaAlg, &hSwKey, 2048, 0)) != ERROR_SUCCESS) ||
       ((result = BCryptFinalizeKeyPair(hSwKey, 0)) != ERROR_SUCCESS) ||
       ((result = BCryptExportKey(hSwKey, NULL, BCRYPT_RSAPRIVATE_BLOB, swKey, sizeof(swKey), &cbSwKey, 0)) != ERROR_SUCCESS))
    {
        goto Cleanup;
    }

    // Build a hostage key. Start with the public portion.
    rsaKey.obj.publicArea.t.publicArea.type = TPM_ALG_RSA;
    rsaKey.obj.publicArea.t.publicArea.nameAlg = TPM_ALG_SHA256;
    rsaKey.obj.publicArea.t.publicArea.objectAttributes.userWithAuth = 1;
    rsaKey.obj.publicArea.t.publicArea.objectAttributes.noDA = 1;
    rsaKey.obj.publicArea.t.publicArea.objectAttributes.sign = 1;
    rsaKey.obj.publicArea.t.publicArea.objectAttributes.decrypt = 1;
    rsaKey.obj.publicArea.t.publicArea.parameters.rsaDetail.keyBits = 2048;
    rsaKey.obj.publicArea.t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
    rsaKey.obj.publicArea.t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
    rsaKey.obj.publicArea.t.publicArea.unique.rsa.t.size = (UINT16)pSwKey->cbModulus;
    MemoryCopy(rsaKey.obj.publicArea.t.publicArea.unique.rsa.t.buffer, &swKey[sizeof(BCRYPT_RSAKEY_BLOB) + pSwKey->cbPublicExp], rsaKey.obj.publicArea.t.publicArea.unique.rsa.t.size, sizeof(rsaKey.obj.publicArea.t.publicArea.unique.rsa.t.buffer));

    // Fill out the private portion
    sensitive.sensitiveType = TPM_ALG_RSA;
    sensitive.authValue.t.size = sizeof(g_UsageAuth);
    MemoryCopy(sensitive.authValue.t.buffer, g_UsageAuth, sensitive.authValue.t.size, sizeof(sensitive.authValue.t.buffer));
    MemoryRemoveTrailingZeros((TPM2B_AUTH*)&sensitive.authValue);
    sensitive.sensitive.rsa.t.size = (UINT16)pSwKey->cbPrime1;
    MemoryCopy(sensitive.sensitive.rsa.t.buffer, &swKey[sizeof(BCRYPT_RSAKEY_BLOB) + pSwKey->cbPublicExp + pSwKey->cbModulus], sensitive.sensitive.rsa.t.size, sizeof(sensitive.sensitive.rsa.t.buffer));

    // Create the session
    sessionTable[0].handle = TPM_RS_PW;

    // Import the RSA key unprotected
    INITIALIZE_CALL_BUFFERS(TPM2_Import, &importIn, &importOut);
    parms.objectTableIn[TPM2_Import_HdlIn_ParentHandle] = g_SrkObject;
    importIn.encryptionKey.t.size = 0;
    importIn.objectPublic = rsaKey.obj.publicArea;
    importIn.inSymSeed.t.size = 0;
    importIn.symmetricAlg.algorithm = TPM_ALG_NULL;
    ObjectComputeName(&rsaKey.obj.publicArea.t.publicArea, &name);
    SensitiveToDuplicate(&sensitive,
                         &name,
                         &g_SrkObject,
                         rsaKey.obj.publicArea.t.publicArea.nameAlg,
                         (TPM2B_SEED*)&importIn.inSymSeed,
                         &importIn.symmetricAlg,
                         &innerKey,
                         &importIn.duplicate);
    EXECUTE_TPM_CALL(FALSE, TPM2_Import);

    // Copy the RSA key out
    rsaKey.obj.privateArea = importOut.outPrivate;
    rsaKey.obj.authValue = sensitive.authValue;

    // Load the key
    INITIALIZE_CALL_BUFFERS(TPM2_Load, &loadIn, &loadOut);
    parms.objectTableIn[TPM2_Load_HdlIn_ParentHandle] = g_SrkObject;
    parms.objectTableOut[TPM2_Load_HdlOut_ObjectHandle] = rsaKey; // Copy the key in to be updated
    loadIn.inPublic = rsaKey.obj.publicArea;
    loadIn.inPrivate = rsaKey.obj.privateArea;
    EXECUTE_TPM_CALL(FALSE, TPM2_Load);

    // Copy the updated RSA key back out
    rsaKey = parms.objectTableOut[TPM2_Load_HdlOut_ObjectHandle];

    // Sign digest
    INITIALIZE_CALL_BUFFERS(TPM2_Sign, &signIn, &signOut);
    parms.objectTableIn[TPM2_Sign_HdlIn_KeyHandle] = rsaKey;
    signIn.digest.t.size = SHA256_DIGEST_SIZE;
    MemorySet((TPM2B*)&signIn.digest.t.buffer, 0x11, signIn.digest.t.size);
    signIn.inScheme.scheme = TPM_ALG_RSAPSS;
    signIn.inScheme.details.rsapss.hashAlg = TPM_ALG_SHA256;
    signIn.validation.tag = TPM_ST_HASHCHECK;
    signIn.validation.hierarchy = TPM_RH_NULL;
    EXECUTE_TPM_CALL(FALSE, TPM2_Sign);

    // Verify signature in software
    if((result = BCryptVerifySignature(hSwKey,
                                       &padding,
                                       signIn.digest.t.buffer,
                                       signIn.digest.t.size,
                                       signOut.signature.signature.rsapss.sig.t.buffer,
                                       signOut.signature.signature.rsapss.sig.t.size,
                                       BCRYPT_PAD_PSS)) != ERROR_SUCCESS)
    {
        goto Cleanup;
    }

    // Unload the RSA key
    INITIALIZE_CALL_BUFFERS(TPM2_FlushContext, &flushContextIn, &flushContextOut);
    parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle] = rsaKey;
    EXECUTE_TPM_CALL(FALSE, TPM2_FlushContext);

    // Copy the updated RSA back out
    rsaKey = parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle];

    // Create a protected key import blob
    newParent.publicArea = g_SrkObject.obj.publicArea.t.publicArea;
    seed.t.size = SHA256_DIGEST_SIZE;
    inSymSeed.t.size = sizeof(inSymSeed.t.secret);
    if((result = CryptSecretEncrypt(&newParent, "DUPLICATE", (TPM2B_DATA*)&seed, &inSymSeed)) != TPM_RC_SUCCESS)
    {
        goto Cleanup;
    }
    ObjectComputeName(&rsaKey.obj.publicArea.t.publicArea, &name);
    SensitiveToDuplicate(&sensitive,
                         &name,
                         &g_SrkObject,
                         rsaKey.obj.publicArea.t.publicArea.nameAlg,
                         &seed,
                         &symDef,
                         &innerKey,
                         &rsaKey.obj.privateArea);

    // Import the protected RSA key
    INITIALIZE_CALL_BUFFERS(TPM2_Import, &importIn, &importOut);
    parms.objectTableIn[TPM2_Import_HdlIn_ParentHandle] = g_SrkObject;
    importIn.objectPublic = rsaKey.obj.publicArea;
    importIn.inSymSeed = inSymSeed;
    importIn.duplicate = rsaKey.obj.privateArea;
    importIn.symmetricAlg.algorithm = TPM_ALG_NULL;
    EXECUTE_TPM_CALL(FALSE, TPM2_Import);

    // Copy the RSA key out
    rsaKey.obj.privateArea = importOut.outPrivate;
    rsaKey.obj.authValue = sensitive.authValue;

    // Load the key
    INITIALIZE_CALL_BUFFERS(TPM2_Load, &loadIn, &loadOut);
    parms.objectTableIn[TPM2_Load_HdlIn_ParentHandle] = g_SrkObject;
    parms.objectTableOut[TPM2_Load_HdlOut_ObjectHandle] = rsaKey; // Copy the key in to be updated
    loadIn.inPublic = rsaKey.obj.publicArea;
    loadIn.inPrivate = rsaKey.obj.privateArea;
    EXECUTE_TPM_CALL(FALSE, TPM2_Load);

    // Copy the updated RSA key back out
    rsaKey = parms.objectTableOut[TPM2_Load_HdlOut_ObjectHandle];

    // Sign digest
    INITIALIZE_CALL_BUFFERS(TPM2_Sign, &signIn, &signOut);
    parms.objectTableIn[TPM2_Sign_HdlIn_KeyHandle] = rsaKey;
    signIn.digest.t.size = SHA256_DIGEST_SIZE;
    MemorySet((TPM2B*)&signIn.digest.t.buffer, 0x11, signIn.digest.t.size);
    signIn.inScheme.scheme = TPM_ALG_RSAPSS;
    signIn.inScheme.details.rsapss.hashAlg = TPM_ALG_SHA256;
    signIn.validation.tag = TPM_ST_HASHCHECK;
    signIn.validation.hierarchy = TPM_RH_NULL;
    EXECUTE_TPM_CALL(FALSE, TPM2_Sign);

    // Verify signature in software
    if((result = BCryptVerifySignature(hSwKey,
                                       &padding,
                                       signIn.digest.t.buffer,
                                       signIn.digest.t.size,
                                       signOut.signature.signature.rsapss.sig.t.buffer,
                                       signOut.signature.signature.rsapss.sig.t.size,
                                       BCRYPT_PAD_PSS)) != ERROR_SUCCESS)
    {
        goto Cleanup;
    }

    // Unload the RSA key
    INITIALIZE_CALL_BUFFERS(TPM2_FlushContext, &flushContextIn, &flushContextOut);
    parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle] = rsaKey;
    EXECUTE_TPM_CALL(FALSE, TPM2_FlushContext);

    // Copy the updated RSA back out
    rsaKey = parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle];

Cleanup:
    if(hSwKey != NULL)
    {
        BCryptDestroyKey(hSwKey);
        hSwKey = NULL;
    }
    return result;
}

UINT32
TestCredentialActivation()
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    ANY_OBJECT ekpub = {0};
    TPM2B_DIGEST credential = {0};
    TPM2B_ID_OBJECT credentialBlob = {0};
    TPM2B_ENCRYPTED_SECRET secret = {0};
    SESSION policySessionAik = {0};
    SESSION policySessionEk = {0};
    LoadExternal_In loadExternalIn = {0};
    LoadExternal_Out loadExternalOut = {0};
    MakeCredential_In makeCredentialIn = {0};
    MakeCredential_Out makeCredentialOut = {0};
    FlushContext_In flushContextIn;
    FlushContext_Out flushContextOut;
    StartAuthSession_In startAuthSessionIn = {0};
    StartAuthSession_Out startAuthSessionOut = {0};
    PolicyCommandCode_In policyCommandCodeIn = {0};
    PolicyCommandCode_Out policyCommandCodeOut;
    PolicyAuthValue_In policyAuthValueIn;
    PolicyAuthValue_Out policyAuthValueOut;
    PolicySecret_In policySecretIn;
    PolicySecret_Out policySecretOut;
    ActivateCredential_In activateCredentialIn = {0};
    ActivateCredential_Out activateCredentialOut = {0};
    PolicyRestart_In policyRestartIn;
    PolicyRestart_Out policyRestartOut;
    TPM2B_SEED seed = {0};
    OBJECT ekPub = {0};

    // Make a credential
    credential.t.size = SHA256_DIGEST_SIZE;
    MemorySet(credential.t.buffer, 0x11, credential.t.size);

    // Load the EKpub
    INITIALIZE_CALL_BUFFERS(TPM2_LoadExternal, &loadExternalIn, &loadExternalOut);
    loadExternalIn.inPublic = g_EkObject.obj.publicArea;
    loadExternalIn.hierarchy = TPM_RH_NULL;
    EXECUTE_TPM_CALL(FALSE, TPM2_LoadExternal);

    // Copy the EKpub out
    ekpub = parms.objectTableOut[TPM2_LoadExternal_HdlOut_ObjectHandle];

    // Make the credential in the TPM
    INITIALIZE_CALL_BUFFERS(TPM2_MakeCredential, &makeCredentialIn, &makeCredentialOut);
    parms.objectTableIn[TPM2_MakeCredential_HdlIn_Handle] = ekpub;
    makeCredentialIn.credential = credential;
    makeCredentialIn.objectName = g_AikObject.obj.name;
    EXECUTE_TPM_CALL(FALSE, TPM2_MakeCredential);

    // Copy the credential out
    credentialBlob = makeCredentialOut.credentialBlob;
    secret = makeCredentialOut.secret;

    // Unload the EKpub
    INITIALIZE_CALL_BUFFERS(TPM2_FlushContext, &flushContextIn, &flushContextOut);
    parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle] = ekpub; // Copy the key in to be updated
    EXECUTE_TPM_CALL(FALSE, TPM2_FlushContext);

    // Copy the updated key back out
    ekpub = parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle];

    // Create the AIK policy Session
    INITIALIZE_CALL_BUFFERS(TPM2_StartAuthSession, &startAuthSessionIn, &startAuthSessionOut);
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_TpmKey].obj.handle = TPM_RH_NULL;
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_Bind].obj.handle = TPM_RH_NULL;
    startAuthSessionIn.nonceCaller.t.size = CryptGenerateRandom(SHA256_DIGEST_SIZE, startAuthSessionIn.nonceCaller.t.buffer);
    startAuthSessionIn.sessionType = TPM_SE_POLICY;
    startAuthSessionIn.symmetric.algorithm = TPM_ALG_NULL;
    startAuthSessionIn.authHash = TPM_ALG_SHA256;
    EXECUTE_TPM_CALL(FALSE, TPM2_StartAuthSession);

    // Copy session back out
    policySessionAik = parms.objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session;

    // Set the session up for Admin role
    INITIALIZE_CALL_BUFFERS(TPM2_PolicyCommandCode, &policyCommandCodeIn, &policyCommandCodeOut);
    parms.objectTableIn[TPM2_PolicyCommandCode_HdlIn_PolicySession].session = policySessionAik;
    policyCommandCodeIn.code = TPM_CC_ActivateCredential;
    EXECUTE_TPM_CALL(FALSE, TPM2_PolicyCommandCode);
    policySessionAik = parms.objectTableIn[TPM2_PolicyCommandCode_HdlIn_PolicySession].session;
    INITIALIZE_CALL_BUFFERS(TPM2_PolicyAuthValue, &policyAuthValueIn, &policyAuthValueOut);
    parms.objectTableIn[TPM2_PolicyAuthValue_HdlIn_PolicySession].session = policySessionAik;
    EXECUTE_TPM_CALL(FALSE, TPM2_PolicyAuthValue);
    policySessionAik = parms.objectTableIn[TPM2_PolicyCommandCode_HdlIn_PolicySession].session;

    // Create the EK policy Session
    INITIALIZE_CALL_BUFFERS(TPM2_StartAuthSession, &startAuthSessionIn, &startAuthSessionOut);
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_TpmKey].obj.handle = TPM_RH_NULL;
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_Bind].obj.handle = TPM_RH_NULL;
    startAuthSessionIn.nonceCaller.t.size = CryptGenerateRandom(SHA256_DIGEST_SIZE, startAuthSessionIn.nonceCaller.t.buffer);
    startAuthSessionIn.sessionType = TPM_SE_POLICY;
    startAuthSessionIn.symmetric.algorithm = TPM_ALG_NULL;
    startAuthSessionIn.authHash = TPM_ALG_SHA256;
    EXECUTE_TPM_CALL(FALSE, TPM2_StartAuthSession);

    // Copy session back out
    policySessionEk = parms.objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session;

    // Create the session
    sessionTable[0].handle = TPM_RS_PW;

    // Set the session up for Admin role
    INITIALIZE_CALL_BUFFERS(TPM2_PolicySecret, &policySecretIn, &policySecretOut);
    parms.objectTableIn[TPM2_PolicySecret_HdlIn_AuthHandle] = g_Endorsement;
    parms.objectTableIn[TPM2_PolicySecret_HdlIn_PolicySession].session = policySessionEk;
    EXECUTE_TPM_CALL(FALSE, TPM2_PolicySecret);
    policySessionEk = parms.objectTableIn[TPM2_PolicySecret_HdlIn_PolicySession].session;

    // Put the sessions together
    sessionTable[0] = policySessionAik;
    sessionTable[1] = policySessionEk;
    sessionTable[0].attributes.continueSession = SET;
    sessionTable[1].attributes.continueSession = SET;

    // Activate the Credential
    INITIALIZE_CALL_BUFFERS(TPM2_ActivateCredential, &activateCredentialIn, &activateCredentialOut);
    parms.objectTableIn[TPM2_ActivateCredential_HdlIn_ActivateHandle] = g_AikObject;
    parms.objectTableIn[TPM2_ActivateCredential_HdlIn_KeyHandle] = g_EkObject;
    activateCredentialIn.credentialBlob = credentialBlob;
    activateCredentialIn.secret = secret;
    EXECUTE_TPM_CALL(FALSE, TPM2_ActivateCredential);

    // Copy the sessions back out
    policySessionAik = sessionTable[0];
    policySessionEk = sessionTable[1];

    // Check credential
    if((activateCredentialOut.certInfo.t.size != credential.t.size) ||
        !MemoryEqual(activateCredentialOut.certInfo.t.buffer, credential.t.buffer, activateCredentialOut.certInfo.t.size))
    {
        result = TPM_RC_FAILURE;
    }

    // Prepare secret in software
    ekPub.publicArea = g_EkObject.obj.publicArea.t.publicArea;
    ekPub.name = g_EkObject.obj.name;
    seed.t.size = SHA256_DIGEST_SIZE;
    secret.t.size = sizeof(secret.t.secret);
    result = CryptSecretEncrypt(&ekPub, "IDENTITY", (TPM2B_DATA*)&seed, &secret);
    if(result != TPM_RC_SUCCESS)
    {
        goto Cleanup;
    }

    // Prepare output credential data from secret
    SecretToCredential(&credential, &g_AikObject.obj.name, &seed, &g_EkObject, &credentialBlob);

    // Reset the AIK policy Session
    INITIALIZE_CALL_BUFFERS(TPM2_PolicyRestart, &policyRestartIn, &policyRestartOut);
    parms.objectTableIn[TPM2_PolicyRestart_HdlIn_SessionHandle].session = policySessionAik;
    EXECUTE_TPM_CALL(FALSE, TPM2_PolicyRestart);

    // Copy session back out
    policySessionAik = parms.objectTableIn[TPM2_PolicyRestart_HdlIn_SessionHandle].session;

    // Set the session up for Admin role
    INITIALIZE_CALL_BUFFERS(TPM2_PolicyCommandCode, &policyCommandCodeIn, &policyCommandCodeOut);
    parms.objectTableIn[TPM2_PolicyCommandCode_HdlIn_PolicySession].session = policySessionAik;
    policyCommandCodeIn.code = TPM_CC_ActivateCredential;
    EXECUTE_TPM_CALL(FALSE, TPM2_PolicyCommandCode);
    policySessionAik = parms.objectTableIn[TPM2_PolicyCommandCode_HdlIn_PolicySession].session;
    INITIALIZE_CALL_BUFFERS(TPM2_PolicyAuthValue, &policyAuthValueIn, &policyAuthValueOut);
    parms.objectTableIn[TPM2_PolicyAuthValue_HdlIn_PolicySession].session = policySessionAik;
    EXECUTE_TPM_CALL(FALSE, TPM2_PolicyAuthValue);
    policySessionAik = parms.objectTableIn[TPM2_PolicyCommandCode_HdlIn_PolicySession].session;

    // Create the EK policy Session
    INITIALIZE_CALL_BUFFERS(TPM2_PolicyRestart, &policyRestartIn, &policyRestartOut);
    parms.objectTableIn[TPM2_PolicyRestart_HdlIn_SessionHandle].session = policySessionEk;
    EXECUTE_TPM_CALL(FALSE, TPM2_PolicyRestart);

    // Copy session back out
    policySessionEk = parms.objectTableIn[TPM2_PolicyRestart_HdlIn_SessionHandle].session;

    // Create the session
    sessionTable[0].handle = TPM_RS_PW;

    // Set the session up for Admin role
    INITIALIZE_CALL_BUFFERS(TPM2_PolicySecret, &policySecretIn, &policySecretOut);
    parms.objectTableIn[TPM2_PolicySecret_HdlIn_AuthHandle] = g_Endorsement;
    parms.objectTableIn[TPM2_PolicySecret_HdlIn_PolicySession].session = policySessionEk;
    EXECUTE_TPM_CALL(FALSE, TPM2_PolicySecret);
    policySessionEk = parms.objectTableIn[TPM2_PolicySecret_HdlIn_PolicySession].session;

    // Put the sessions together
    sessionTable[0] = policySessionAik;
    sessionTable[1] = policySessionEk;
    sessionTable[0].attributes.continueSession = CLEAR;
    sessionTable[1].attributes.continueSession = CLEAR;

    // Activate the Credential
    INITIALIZE_CALL_BUFFERS(TPM2_ActivateCredential, &activateCredentialIn, &activateCredentialOut);
    parms.objectTableIn[TPM2_ActivateCredential_HdlIn_ActivateHandle] = g_AikObject;
    parms.objectTableIn[TPM2_ActivateCredential_HdlIn_KeyHandle] = g_EkObject;
    activateCredentialIn.credentialBlob = credentialBlob;
    activateCredentialIn.secret = secret;
    EXECUTE_TPM_CALL(FALSE, TPM2_ActivateCredential);

    // Check credential
    if((activateCredentialOut.certInfo.t.size != credential.t.size) ||
        !MemoryEqual(activateCredentialOut.certInfo.t.buffer, credential.t.buffer, activateCredentialOut.certInfo.t.size))
    {
        result = TPM_RC_FAILURE;
    }

Cleanup:
    return result;
}

UINT32
TestKeyExport()
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    ANY_OBJECT rsaKey = {0};
    SESSION policySession = {0};
    LoadExternal_In loadExternalIn = {0};
    LoadExternal_Out loadExternalOut = {0};
    StartAuthSession_In startAuthSessionIn = {0};
    StartAuthSession_Out startAuthSessionOut = {0};
    PolicyCommandCode_In policyCommandCodeIn = {0};
    PolicyCommandCode_Out policyCommandCodeOut;
    PolicyAuthValue_In policyAuthValueIn;
    PolicyAuthValue_Out policyAuthValueOut;
    PolicyOR_In policyORIn = {0};
    PolicyOR_Out policyOROut;
    Duplicate_In duplicateIn = {0};
    Duplicate_Out duplicateOut = {0};
    FlushContext_In flushContextIn;
    FlushContext_Out flushContextOut;

    BCRYPT_KEY_HANDLE hSwKey = NULL;
    BYTE swKey[1024] = {0};
    BCRYPT_RSAKEY_BLOB *pSwKey = (BCRYPT_RSAKEY_BLOB*)swKey;
    ULONG cbSwKey = 0;
    UCHAR label[] = "DUPLICATE";
    BCRYPT_OAEP_PADDING_INFO padding = {BCRYPT_SHA256_ALGORITHM, label, sizeof(label)};
    TPMT_SENSITIVE sensitive = {0};
    TPM2B_SEED seed = {0};
    TPMT_SYM_DEF_OBJECT symDef = {0};
    TPM2B_DATA innerSymKey = {0};

    // Create SW key
    if(((result = BCryptGenerateKeyPair(g_hRsaAlg, &hSwKey, 2048, 0)) != ERROR_SUCCESS) ||
        ((result = BCryptFinalizeKeyPair(hSwKey, 0)) != ERROR_SUCCESS) ||
        ((result = BCryptExportKey(hSwKey, NULL, BCRYPT_RSAPRIVATE_BLOB, swKey, sizeof(swKey), &cbSwKey, 0)) != ERROR_SUCCESS))
    {
        goto Cleanup;
    }

    // Build the storage key.
    rsaKey.obj.publicArea.t.publicArea.type = TPM_ALG_RSA;
    rsaKey.obj.publicArea.t.publicArea.nameAlg = TPM_ALG_SHA256;
    rsaKey.obj.publicArea.t.publicArea.objectAttributes.userWithAuth = 1;
    rsaKey.obj.publicArea.t.publicArea.objectAttributes.noDA = 1;
    rsaKey.obj.publicArea.t.publicArea.objectAttributes.restricted = 1;
    rsaKey.obj.publicArea.t.publicArea.objectAttributes.decrypt = 1;
    rsaKey.obj.publicArea.t.publicArea.parameters.rsaDetail.keyBits = 2048;
    rsaKey.obj.publicArea.t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
    rsaKey.obj.publicArea.t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
    rsaKey.obj.publicArea.t.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = MAX_AES_KEY_BITS;
    rsaKey.obj.publicArea.t.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
    rsaKey.obj.publicArea.t.publicArea.unique.rsa.t.size = (UINT16)pSwKey->cbModulus;
    MemoryCopy(rsaKey.obj.publicArea.t.publicArea.unique.rsa.t.buffer, &swKey[sizeof(BCRYPT_RSAKEY_BLOB)+pSwKey->cbPublicExp], rsaKey.obj.publicArea.t.publicArea.unique.rsa.t.size, sizeof(rsaKey.obj.publicArea.t.publicArea.unique.rsa.t.buffer));

    // Load the public key
    INITIALIZE_CALL_BUFFERS(TPM2_LoadExternal, &loadExternalIn, &loadExternalOut);
    loadExternalIn.inPublic = rsaKey.obj.publicArea;
    loadExternalIn.hierarchy = TPM_RH_NULL;
    EXECUTE_TPM_CALL(FALSE, TPM2_LoadExternal);

    // Copy the key out
    rsaKey = parms.objectTableOut[TPM2_LoadExternal_HdlOut_ObjectHandle];

    // Create the admin policy Session
    INITIALIZE_CALL_BUFFERS(TPM2_StartAuthSession, &startAuthSessionIn, &startAuthSessionOut);
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_TpmKey].obj.handle = TPM_RH_NULL;
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_Bind].obj.handle = TPM_RH_NULL;
    startAuthSessionIn.nonceCaller.t.size = CryptGenerateRandom(SHA256_DIGEST_SIZE, startAuthSessionIn.nonceCaller.t.buffer);
    startAuthSessionIn.sessionType = TPM_SE_POLICY;
    startAuthSessionIn.symmetric.algorithm = TPM_ALG_NULL;
    startAuthSessionIn.authHash = TPM_ALG_SHA256;
    EXECUTE_TPM_CALL(FALSE, TPM2_StartAuthSession);

    // Copy session back out
    policySession = parms.objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session;

    // Set the session up for admin duplication
    INITIALIZE_CALL_BUFFERS(TPM2_PolicyCommandCode, &policyCommandCodeIn, &policyCommandCodeOut);
    parms.objectTableIn[TPM2_PolicyCommandCode_HdlIn_PolicySession].session = policySession;
    policyCommandCodeIn.code = TPM_CC_Duplicate;
    EXECUTE_TPM_CALL(FALSE, TPM2_PolicyCommandCode);
    policySession = parms.objectTableIn[TPM2_PolicyCommandCode_HdlIn_PolicySession].session;
    INITIALIZE_CALL_BUFFERS(TPM2_PolicyAuthValue, &policyAuthValueIn, &policyAuthValueOut);
    parms.objectTableIn[TPM2_PolicyAuthValue_HdlIn_PolicySession].session = policySession;
    EXECUTE_TPM_CALL(FALSE, TPM2_PolicyAuthValue);
    policySession = parms.objectTableIn[TPM2_PolicyCommandCode_HdlIn_PolicySession].session;
    INITIALIZE_CALL_BUFFERS(TPM2_PolicyOR, &policyORIn, &policyOROut);
    parms.objectTableIn[TPM2_PolicyCommandCode_HdlIn_PolicySession].session = policySession;
    policyORIn.pHashList = g_AdminPolicyHashList; // We are taking the previously stored policy list so we don't have to recalculate the entire policy
    EXECUTE_TPM_CALL(FALSE, TPM2_PolicyOR);
    policySession = parms.objectTableIn[TPM2_PolicyOR_HdlIn_PolicySession].session;

    // Put the sessions together
    sessionTable[0] = policySession;
    sessionTable[0].attributes.continueSession = SET;

    // Export the key without encryption (Allowed, because publicArea.objectAttributes.encryptedDuplication = 0)
    INITIALIZE_CALL_BUFFERS(TPM2_Duplicate, &duplicateIn, &duplicateOut);
    parms.objectTableIn[TPM2_Duplicate_HdlIn_ObjectHandle] = g_KeyObject;
    parms.objectTableIn[TPM2_Duplicate_HdlIn_NewParentHandle].generic.handle = TPM_RH_NULL;
    duplicateIn.symmetricAlg.algorithm = TPM_ALG_NULL;
    EXECUTE_TPM_CALL(FALSE, TPM2_Duplicate);

    // Copy the session out
    policySession = sessionTable[0];

    // Marshal the private key structure out
    symDef.algorithm = TPM_ALG_NULL;
    result = DuplicateToSensitive(&duplicateOut.duplicate,
                                  &g_KeyObject.obj.name,
                                  NULL,
                                  g_KeyObject.obj.publicArea.t.publicArea.nameAlg,
                                  &seed,
                                  &symDef,
                                  &innerSymKey,
                                  &sensitive);
    if(result != TPM_RC_SUCCESS)
    {
        goto Cleanup;
    }

    // Set the session up for admin duplication
    INITIALIZE_CALL_BUFFERS(TPM2_PolicyCommandCode, &policyCommandCodeIn, &policyCommandCodeOut);
    parms.objectTableIn[TPM2_PolicyCommandCode_HdlIn_PolicySession].session = policySession;
    policyCommandCodeIn.code = TPM_CC_Duplicate;
    EXECUTE_TPM_CALL(FALSE, TPM2_PolicyCommandCode);
    policySession = parms.objectTableIn[TPM2_PolicyCommandCode_HdlIn_PolicySession].session;
    INITIALIZE_CALL_BUFFERS(TPM2_PolicyAuthValue, &policyAuthValueIn, &policyAuthValueOut);
    parms.objectTableIn[TPM2_PolicyAuthValue_HdlIn_PolicySession].session = policySession;
    EXECUTE_TPM_CALL(FALSE, TPM2_PolicyAuthValue);
    policySession = parms.objectTableIn[TPM2_PolicyCommandCode_HdlIn_PolicySession].session;
    INITIALIZE_CALL_BUFFERS(TPM2_PolicyOR, &policyORIn, &policyOROut);
    parms.objectTableIn[TPM2_PolicyCommandCode_HdlIn_PolicySession].session = policySession;
    policyORIn.pHashList = g_AdminPolicyHashList;
    EXECUTE_TPM_CALL(FALSE, TPM2_PolicyOR);
    policySession = parms.objectTableIn[TPM2_PolicyOR_HdlIn_PolicySession].session;

    // Put the sessions together
    sessionTable[0] = policySession;

    // Export the key with encryption
    INITIALIZE_CALL_BUFFERS(TPM2_Duplicate, &duplicateIn, &duplicateOut);
    parms.objectTableIn[TPM2_Duplicate_HdlIn_ObjectHandle] = g_KeyObject;
    parms.objectTableIn[TPM2_Duplicate_HdlIn_NewParentHandle] = rsaKey;
    duplicateIn.symmetricAlg.algorithm = TPM_ALG_NULL;
    EXECUTE_TPM_CALL(FALSE, TPM2_Duplicate);

    // Decrypt the TPM generated seed with the wrapping key
    ULONG cbData;
    if((result = BCryptDecrypt(hSwKey,
                               duplicateOut.outSymSeed.t.secret,
                               (ULONG)duplicateOut.outSymSeed.t.size,
                               &padding,
                               NULL,
                               0,
                               seed.t.buffer,
                               sizeof(seed.t.buffer),
                               &cbData,
                               BCRYPT_PAD_OAEP)) != ERROR_SUCCESS)
    {
        goto Cleanup;
    }
    seed.t.size = (UINT16)cbData;

    // Unprotect and unmarshal the sensitive structure
    symDef.algorithm = TPM_ALG_NULL;
    result = DuplicateToSensitive(&duplicateOut.duplicate,
                                  &g_KeyObject.obj.name,
                                  &rsaKey,
                                  g_KeyObject.obj.publicArea.t.publicArea.nameAlg,
                                  &seed,
                                  &symDef,
                                  &innerSymKey,
                                  &sensitive);
    if(result != TPM_RC_SUCCESS)
    {
        goto Cleanup;
    }

    // Unload the Pubkey
    INITIALIZE_CALL_BUFFERS(TPM2_FlushContext, &flushContextIn, &flushContextOut);
    parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle] = rsaKey;
    EXECUTE_TPM_CALL(FALSE, TPM2_FlushContext);

Cleanup:
    if(hSwKey != NULL)
    {
        BCryptDestroyKey(hSwKey);
        hSwKey = NULL;
    }
    return result;
}

UINT32
TestSymEncryption()
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    BYTE userKey[] = "ThisIsMyHmacKey";
    ANY_OBJECT aesKey = {0};
    Create_In createIn = {0};
    Create_Out createOut = {0};
    Load_In loadIn = {0};
    Load_Out loadOut = {0};
    FlushContext_In flushContextIn;
    FlushContext_Out flushContextOut;
    EncryptDecrypt_In encryptDecryptIn = {0};
    EncryptDecrypt_Out encryptDecryptOut = {0};
    TPM2B_MAX_BUFFER clearData = {0};
    TPM2B_MAX_BUFFER cipherData = {0};
    TPM2B_IV iv = {0};
    BCRYPT_KEY_HANDLE hAesKey = NULL;
    BCRYPT_KEY_HANDLE hAesKeyCopy = NULL;
    BYTE pbBuf[1024] = {0};
    ULONG cbBuf = 0;
    BYTE pbIv[16] = {0};
    ULONG cbIv = sizeof(pbIv);

    // Create the session
    sessionTable[0].handle = TPM_RS_PW;

    // Create the SHA-1 HMAC key
    INITIALIZE_CALL_BUFFERS(TPM2_Create, &createIn, &createOut);
    parms.objectTableIn[TPM2_Create_HdlIn_ParentHandle] = g_SrkObject;
    createIn.inSensitive.t.sensitive.userAuth.t.size = sizeof(g_UsageAuth);
    MemoryCopy(createIn.inSensitive.t.sensitive.userAuth.t.buffer, g_UsageAuth, createIn.inSensitive.t.sensitive.userAuth.t.size, sizeof(createIn.inSensitive.t.sensitive.userAuth.t.buffer));
    MemoryRemoveTrailingZeros(&createIn.inSensitive.t.sensitive.userAuth);
    createIn.inSensitive.t.sensitive.data.t.size = sizeof(userKey);
    MemoryCopy(createIn.inSensitive.t.sensitive.data.t.buffer, userKey, sizeof(userKey), sizeof(createIn.inSensitive.t.sensitive.data.t.buffer));
    createIn.inPublic.t.publicArea.type = TPM_ALG_SYMCIPHER;
    createIn.inPublic.t.publicArea.nameAlg = TPM_ALG_SHA256;
    createIn.inPublic.t.publicArea.objectAttributes.userWithAuth = 1;
    createIn.inPublic.t.publicArea.objectAttributes.noDA = 1;
    createIn.inPublic.t.publicArea.objectAttributes.decrypt = 1;
    createIn.inPublic.t.publicArea.parameters.symDetail.algorithm = TPM_ALG_AES;
    createIn.inPublic.t.publicArea.parameters.symDetail.keyBits.aes = MAX_AES_KEY_BITS;
    createIn.inPublic.t.publicArea.parameters.symDetail.mode.aes = TPM_ALG_CBC;
    EXECUTE_TPM_CALL(FALSE, TPM2_Create);

    // Copy the AES key out
    aesKey.obj.publicArea = createOut.outPublic;
    aesKey.obj.privateArea = createOut.outPrivate;
    aesKey.obj.authValue = createIn.inSensitive.t.sensitive.userAuth;

    // Load the AES key
    INITIALIZE_CALL_BUFFERS(TPM2_Load, &loadIn, &loadOut);
    parms.objectTableIn[TPM2_Load_HdlIn_ParentHandle] = g_SrkObject;
    parms.objectTableOut[TPM2_Load_HdlOut_ObjectHandle] = aesKey; // Copy the key in to be updated
    loadIn.inPublic = aesKey.obj.publicArea;
    loadIn.inPrivate = aesKey.obj.privateArea;
    EXECUTE_TPM_CALL(FALSE, TPM2_Load);

    // Copy the updated AES key back out
    aesKey = parms.objectTableOut[TPM2_Load_HdlOut_ObjectHandle];

    // Create the data
    clearData.t.size = MAX_AES_BLOCK_SIZE_BYTES * 16;
    iv.t.size = MAX_AES_BLOCK_SIZE_BYTES;

    // Encrypt data with the key
    INITIALIZE_CALL_BUFFERS(TPM2_EncryptDecrypt, &encryptDecryptIn, &encryptDecryptOut);
    parms.objectTableIn[TPM2_EncryptDecrypt_HdlIn_KeyHandle] = aesKey;
    encryptDecryptIn.decrypt = NO;
    encryptDecryptIn.mode = TPM_ALG_CBC;
    encryptDecryptIn.ivIn = iv;
    encryptDecryptIn.inData = clearData;
    EXECUTE_TPM_CALL(FALSE, TPM2_EncryptDecrypt);
    cipherData = encryptDecryptOut.outData;

    // Decrypt data with the key
    INITIALIZE_CALL_BUFFERS(TPM2_EncryptDecrypt, &encryptDecryptIn, &encryptDecryptOut);
    parms.objectTableIn[TPM2_EncryptDecrypt_HdlIn_KeyHandle] = aesKey;
    encryptDecryptIn.decrypt = YES;
    encryptDecryptIn.mode = TPM_ALG_CBC;
    encryptDecryptIn.ivIn.t.size = MAX_AES_BLOCK_SIZE_BYTES;
    encryptDecryptIn.inData = cipherData;
    EXECUTE_TPM_CALL(FALSE, TPM2_EncryptDecrypt);
    
    // Check that we got the input back
    for(UINT32 n = 0; n < encryptDecryptOut.outData.t.size; n++)
    {
        if(encryptDecryptOut.outData.t.buffer[n] != 0)
        {
            result = TPM_RC_FAILURE;
            goto Cleanup;
        }
    }

    // Unload the AES key
    INITIALIZE_CALL_BUFFERS(TPM2_FlushContext, &flushContextIn, &flushContextOut);
    parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle] = aesKey;
    EXECUTE_TPM_CALL(FALSE, TPM2_FlushContext);

    // Copy the updated AES key back out
    aesKey = parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle];

    // Create a software key
    if(((result = BCryptGenerateSymmetricKey(g_hAesAlg, &hAesKey, NULL, 0, userKey, sizeof(userKey), 0)) != ERROR_SUCCESS) ||
       ((result = BCryptSetProperty(hAesKey, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0)) != ERROR_SUCCESS))
    {
        goto Cleanup;
    }

    // Encrypt the data with software key
    MemorySet(pbIv, 0x00, cbIv);
    if(((result = BCryptDuplicateKey(hAesKey, &hAesKeyCopy, NULL, 0, 0)) != ERROR_SUCCESS) ||
       ((result = BCryptEncrypt(hAesKeyCopy, clearData.t.buffer, clearData.t.size, NULL, pbIv, cbIv, pbBuf, sizeof(pbBuf), (PULONG)&cbBuf, 0)) != ERROR_SUCCESS) ||
       ((result = BCryptDestroyKey(hAesKeyCopy)) != ERROR_SUCCESS))
    {
        goto Cleanup;
    }
    hAesKeyCopy = NULL;

    // Check that we got the same cipher
    if(cbBuf != cipherData.t.size)
    {
        result = TPM_RC_FAILURE;
        goto Cleanup;
    }
    for(UINT32 n = 0; n < cbBuf; n++)
    {
        if(pbBuf[n] != cipherData.t.buffer[n])
        {
            result = TPM_RC_FAILURE;
            goto Cleanup;
        }
    }

    // Decrypt the data with the software key
    MemorySet(pbIv, 0x00, cbIv);
    if(((result = BCryptDuplicateKey(hAesKey, &hAesKeyCopy, NULL, 0, 0)) != ERROR_SUCCESS) ||
       ((result = BCryptDecrypt(hAesKeyCopy, pbBuf, cbBuf, NULL, pbIv, cbIv, pbBuf, sizeof(pbBuf), (PULONG)&cbBuf, 0)) != ERROR_SUCCESS) ||
       ((result = BCryptDestroyKey(hAesKeyCopy)) != ERROR_SUCCESS))
    {
        goto Cleanup;
    }
    hAesKeyCopy = NULL;

    // Check that we got the input back
    if(cbBuf != clearData.t.size)
    {
        result = TPM_RC_FAILURE;
        goto Cleanup;
    }
    for(UINT32 n = 0; n < cbBuf; n++)
    {
        if(pbBuf[n] != 0)
        {
            result = TPM_RC_FAILURE;
            goto Cleanup;
        }
    }

Cleanup:
    if(hAesKeyCopy != NULL)
    {
        BCryptDestroyKey(hAesKeyCopy);
    }
    if(hAesKey != NULL)
    {
        BCryptDestroyKey(hAesKey);
    }
    return result;
}

UINT32
TestCertifiedMigration()
{

    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    ANY_OBJECT pubKey = {0};
    ANY_OBJECT migrationAuthority = {0};
    ANY_OBJECT newParent = {0};
    ANY_OBJECT key = {0};
    TPM2B_PRIVATE duplicate = {0};
    TPM2B_ENCRYPTED_SECRET symSeed = {0};
    SESSION policySession = {0};
    TPM2B_DATA innerWrapKey = {0};
    CreatePrimary_In createPrimaryIn = {0};
    CreatePrimary_Out createPrimaryOut = {0};
    PolicyDuplicationSelect_In  policyDuplicationSelectIn = {0};
    PolicyDuplicationSelect_Out  policyDuplicationSelectOut;
    PolicyAuthValue_In policyAuthValueIn;
    PolicyAuthValue_Out policyAuthValueOut;
    Create_In createIn = {0};
    Create_Out createOut = {0};
    Load_In loadIn = {0};
    Load_Out loadOut = {0};
    LoadExternal_In loadExternalIn = {0};
    LoadExternal_Out loadExternalOut = {0};
    StartAuthSession_In startAuthSessionIn = {0};
    StartAuthSession_Out startAuthSessionOut = {0};
    Duplicate_In duplicateIn = {0};
    Duplicate_Out duplicateOut = {0};
    Rewrap_In rewrapIn = {0};
    Rewrap_Out rewrapOut = {0};
    Import_In importIn = {0};
    Import_Out importOut = {0};
    FlushContext_In flushContextIn;
    FlushContext_Out flushContextOut;

    // Create the session
    sessionTable[0].handle = TPM_RS_PW;

    // Lets set up the infrastructure and create the following keys:
    // Primary Objects:      SRK         MigrationAuthority          NewParent
    //                        |
    // TPM2_Create:       SRKEnc(Key)

    // Create the MigrationAuthority
    INITIALIZE_CALL_BUFFERS(TPM2_CreatePrimary, &createPrimaryIn, &createPrimaryOut);
    parms.objectTableIn[TPM2_CreatePrimary_HdlIn_PrimaryHandle] = g_StorageOwner;
    createPrimaryIn.inPublic.t.publicArea.type = TPM_ALG_RSA;
    createPrimaryIn.inPublic.t.publicArea.nameAlg = TPM_ALG_SHA256;
    createPrimaryIn.inPublic.t.publicArea.objectAttributes.fixedTPM = SET;
    createPrimaryIn.inPublic.t.publicArea.objectAttributes.fixedParent = SET;
    createPrimaryIn.inPublic.t.publicArea.objectAttributes.sensitiveDataOrigin = SET;
    createPrimaryIn.inPublic.t.publicArea.objectAttributes.userWithAuth = SET;
    createPrimaryIn.inPublic.t.publicArea.objectAttributes.noDA = SET;
    createPrimaryIn.inPublic.t.publicArea.objectAttributes.restricted = SET;
    createPrimaryIn.inPublic.t.publicArea.objectAttributes.decrypt = SET;
    createPrimaryIn.inPublic.t.publicArea.parameters.rsaDetail.keyBits = MAX_RSA_KEY_BITS;
    createPrimaryIn.inPublic.t.publicArea.parameters.rsaDetail.exponent = 0;
    createPrimaryIn.inPublic.t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
    createPrimaryIn.inPublic.t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
    createPrimaryIn.inPublic.t.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
    createPrimaryIn.inPublic.t.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
    createPrimaryIn.inPublic.t.publicArea.unique.rsa.t.size = MAX_RSA_KEY_BYTES;
    CryptGenerateRandom(createPrimaryIn.inPublic.t.publicArea.unique.rsa.t.size, createPrimaryIn.inPublic.t.publicArea.unique.rsa.t.buffer); // Ensure that we are getting a unique key
    EXECUTE_TPM_CALL(FALSE, TPM2_CreatePrimary);

    // Copy the MigrationAuthority out
    migrationAuthority = parms.objectTableOut[TPM2_CreatePrimary_HdlOut_ObjectHandle];

    // Create the NewParent
    INITIALIZE_CALL_BUFFERS(TPM2_CreatePrimary, &createPrimaryIn, &createPrimaryOut);
    parms.objectTableIn[TPM2_CreatePrimary_HdlIn_PrimaryHandle] = g_StorageOwner;
    createPrimaryIn.inPublic.t.publicArea.type = TPM_ALG_RSA;
    createPrimaryIn.inPublic.t.publicArea.nameAlg = TPM_ALG_SHA256;
    createPrimaryIn.inPublic.t.publicArea.objectAttributes.fixedTPM = SET;
    createPrimaryIn.inPublic.t.publicArea.objectAttributes.fixedParent = SET;
    createPrimaryIn.inPublic.t.publicArea.objectAttributes.sensitiveDataOrigin = SET;
    createPrimaryIn.inPublic.t.publicArea.objectAttributes.userWithAuth = SET;
    createPrimaryIn.inPublic.t.publicArea.objectAttributes.noDA = SET;
    createPrimaryIn.inPublic.t.publicArea.objectAttributes.restricted = SET;
    createPrimaryIn.inPublic.t.publicArea.objectAttributes.decrypt = SET;
    createPrimaryIn.inPublic.t.publicArea.parameters.rsaDetail.keyBits = MAX_RSA_KEY_BITS;
    createPrimaryIn.inPublic.t.publicArea.parameters.rsaDetail.exponent = 0;
    createPrimaryIn.inPublic.t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
    createPrimaryIn.inPublic.t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
    createPrimaryIn.inPublic.t.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
    createPrimaryIn.inPublic.t.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
    createPrimaryIn.inPublic.t.publicArea.unique.rsa.t.size = MAX_RSA_KEY_BYTES;
    CryptGenerateRandom(createPrimaryIn.inPublic.t.publicArea.unique.rsa.t.size, createPrimaryIn.inPublic.t.publicArea.unique.rsa.t.buffer); // Ensure that we are getting a unique key
    EXECUTE_TPM_CALL(FALSE, TPM2_CreatePrimary);

    // Copy the MigrationAuthority out
    newParent = parms.objectTableOut[TPM2_CreatePrimary_HdlOut_ObjectHandle];

    // Create the key
    INITIALIZE_CALL_BUFFERS(TPM2_Create, &createIn, &createOut);
    parms.objectTableIn[TPM2_Create_HdlIn_ParentHandle] = g_SrkObject;
    createIn.inSensitive.t.sensitive.userAuth.t.size = sizeof(g_UsageAuth);
    memcpy(createIn.inSensitive.t.sensitive.userAuth.t.buffer, g_UsageAuth, createIn.inSensitive.t.sensitive.userAuth.t.size);
    MemoryRemoveTrailingZeros(&createIn.inSensitive.t.sensitive.userAuth);

    // The key has to have a policy that allows only encrypted duplication and only to the
    // MigrationAuthority. Lets calculate that policy for the the MigrationAuthority.
    // TPM2_PolicyDuplicationSelect(migrationAuthority, No) | TPM2_PolicyAuthValue()
    createIn.inPublic.t.publicArea.authPolicy.t.size = SHA256_DIGEST_SIZE;
    MemorySet(createIn.inPublic.t.publicArea.authPolicy.t.buffer, 0x00, sizeof(createIn.inPublic.t.publicArea.authPolicy.t.buffer));
    policyDuplicationSelectIn.includeObject = NO;
    policyDuplicationSelectIn.newParentName = migrationAuthority.obj.name;
    TPM2_PolicyDuplicationSelect_CalculateUpdate(TPM_ALG_SHA256, &createIn.inPublic.t.publicArea.authPolicy, &policyDuplicationSelectIn);
    TPM2_PolicyAuthValue_CalculateUpdate(TPM_ALG_SHA256, &createIn.inPublic.t.publicArea.authPolicy, &policyAuthValueIn);

    createIn.inPublic.t.publicArea.type = TPM_ALG_RSA;
    createIn.inPublic.t.publicArea.nameAlg = TPM_ALG_SHA256;
    createIn.inPublic.t.publicArea.objectAttributes.encryptedDuplication = 1;  // Not supported by Win8 Intel fTPM
    createIn.inPublic.t.publicArea.objectAttributes.sensitiveDataOrigin = 1;
    createIn.inPublic.t.publicArea.objectAttributes.userWithAuth = 1;
    createIn.inPublic.t.publicArea.objectAttributes.adminWithPolicy = 1;
    createIn.inPublic.t.publicArea.objectAttributes.noDA = 1;
    createIn.inPublic.t.publicArea.objectAttributes.decrypt = 1;
    createIn.inPublic.t.publicArea.objectAttributes.sign = 1;
    createIn.inPublic.t.publicArea.parameters.symDetail.algorithm = TPM_ALG_NULL;
    createIn.inPublic.t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
    createIn.inPublic.t.publicArea.parameters.rsaDetail.keyBits = 2048;
    createIn.inPublic.t.publicArea.unique.rsa.b.size = 256;
    EXECUTE_TPM_CALL(FALSE, TPM2_Create);

    // Build the key object
    key.obj.publicArea = createOut.outPublic;
    key.obj.privateArea = createOut.outPrivate;
    key.obj.authValue = createIn.inSensitive.t.sensitive.userAuth;

    // Load the key
    INITIALIZE_CALL_BUFFERS(TPM2_Load, &loadIn, &loadOut);
    parms.objectTableIn[TPM2_Load_HdlIn_ParentHandle] = g_SrkObject;
    parms.objectTableOut[TPM2_Load_HdlOut_ObjectHandle] = key; // Copy the key in to be updated
    loadIn.inPublic = key.obj.publicArea;
    loadIn.inPrivate = key.obj.privateArea;
    EXECUTE_TPM_CALL(FALSE, TPM2_Load);

    // Copy the updated key back out
    key = parms.objectTableOut[TPM2_Load_HdlOut_ObjectHandle];

    // We duplicate with an inner wrapper to make sure that the MigrationAuthority
    // cannot TPM2_Import the key, since he is the authority but not the owner.
    // Primary Objects:      SRK         MigrationAuthority          NewParent
    //                        |                  |
    // TPM2_Duplicate:    SRKEnc(Key) ->  MAEnc(Enc(Key))

    // Load the public migration authority key - we are assuming that this key lives on a different TPM far far away
    INITIALIZE_CALL_BUFFERS(TPM2_LoadExternal, &loadExternalIn, &loadExternalOut);
    loadExternalIn.inPublic = migrationAuthority.obj.publicArea;
    loadExternalIn.hierarchy = TPM_RH_NULL;
    EXECUTE_TPM_CALL(FALSE, TPM2_LoadExternal);

    // Copy the public migration authority key out
    pubKey = parms.objectTableOut[TPM2_LoadExternal_HdlOut_ObjectHandle];

    // Create the admin policy Session
    INITIALIZE_CALL_BUFFERS(TPM2_StartAuthSession, &startAuthSessionIn, &startAuthSessionOut);
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_TpmKey].obj.handle = TPM_RH_NULL;
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_Bind].obj.handle = TPM_RH_NULL;
    startAuthSessionIn.nonceCaller.t.size = CryptGenerateRandom(SHA256_DIGEST_SIZE, startAuthSessionIn.nonceCaller.t.buffer);
    startAuthSessionIn.sessionType = TPM_SE_POLICY;
    startAuthSessionIn.symmetric.algorithm = TPM_ALG_NULL;
    startAuthSessionIn.authHash = TPM_ALG_SHA256;
    EXECUTE_TPM_CALL(FALSE, TPM2_StartAuthSession);

    // Copy session back out
    policySession = parms.objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session;

    // Set the session up for admin duplication
    INITIALIZE_CALL_BUFFERS(TPM2_PolicyDuplicationSelect, &policyDuplicationSelectIn, &policyDuplicationSelectOut);
    parms.objectTableIn[TPM2_PolicyAuthValue_HdlIn_PolicySession].session = policySession;
    policyDuplicationSelectIn.includeObject = NO;
    policyDuplicationSelectIn.objectName = key.obj.name;
    policyDuplicationSelectIn.newParentName = migrationAuthority.obj.name;
    EXECUTE_TPM_CALL(FALSE, TPM2_PolicyDuplicationSelect);
    policySession = parms.objectTableIn[TPM2_PolicyCommandCode_HdlIn_PolicySession].session;
    INITIALIZE_CALL_BUFFERS(TPM2_PolicyAuthValue, &policyAuthValueIn, &policyAuthValueOut);
    parms.objectTableIn[TPM2_PolicyAuthValue_HdlIn_PolicySession].session = policySession;
    EXECUTE_TPM_CALL(FALSE, TPM2_PolicyAuthValue);
    policySession = parms.objectTableIn[TPM2_PolicyCommandCode_HdlIn_PolicySession].session;

    // Put the sessions together
    sessionTable[0] = policySession;

    // Export the key encrypted for the migration authority, including an inner wrapper that prevents the migration authority from importing it
    INITIALIZE_CALL_BUFFERS(TPM2_Duplicate, &duplicateIn, &duplicateOut);
    parms.objectTableIn[TPM2_Duplicate_HdlIn_ObjectHandle] = key;
    parms.objectTableIn[TPM2_Duplicate_HdlIn_NewParentHandle] = pubKey;
    duplicateIn.symmetricAlg.algorithm = TPM_ALG_AES;
    duplicateIn.symmetricAlg.keyBits.aes = MAX_AES_KEY_BITS;
    duplicateIn.symmetricAlg.mode.aes = TPM_ALG_CFB;
    EXECUTE_TPM_CALL(FALSE, TPM2_Duplicate);
    innerWrapKey = duplicateOut.encryptionKeyOut; // Remember that since we will have to give that to the new parent later
    duplicate = duplicateOut.duplicate;
    symSeed = duplicateOut.outSymSeed;

    // Unload the migration authority pub key
    INITIALIZE_CALL_BUFFERS(TPM2_FlushContext, &flushContextIn, &flushContextOut);
    parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle] = pubKey;
    EXECUTE_TPM_CALL(FALSE, TPM2_FlushContext);
    pubKey = parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle];

    // Unload the key
    INITIALIZE_CALL_BUFFERS(TPM2_FlushContext, &flushContextIn, &flushContextOut);
    parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle] = key;
    EXECUTE_TPM_CALL(FALSE, TPM2_FlushContext);
    key = parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle];

    // The MigrationAuthority can now TPM2_Rewrap the key to NewParent
    // Primary Objects:      SRK         MigrationAuthority          NewParent
    //                        |                  |                       |
    // TPM2_Rewrap:      SRKEnc(Key) ->  MAEnc(Enc(Key))     ->    NPEnc(Enc(Key))

    // Load the public new parent key - we are assuming that this key lives on a different TPM far far away
    INITIALIZE_CALL_BUFFERS(TPM2_LoadExternal, &loadExternalIn, &loadExternalOut);
    loadExternalIn.inPublic = newParent.obj.publicArea;
    loadExternalIn.hierarchy = TPM_RH_NULL;
    EXECUTE_TPM_CALL(FALSE, TPM2_LoadExternal);

    // Copy the public new parent key out
    pubKey = parms.objectTableOut[TPM2_LoadExternal_HdlOut_ObjectHandle];

    // Create the session
    sessionTable[0].handle = TPM_RS_PW;

    // Rewrap the key for the new parent
    INITIALIZE_CALL_BUFFERS(TPM2_Rewrap, &rewrapIn, &rewrapOut);
    parms.objectTableIn[TPM2_Rewrap_HdlIn_OldParent] = migrationAuthority;
    parms.objectTableIn[TPM2_Rewrap_HdlIn_NewParent] = pubKey;
    rewrapIn.inDuplicate = duplicate;
    rewrapIn.inSymSeed = symSeed;
    rewrapIn.name = key.obj.name;
    EXECUTE_TPM_CALL(FALSE, TPM2_Rewrap);
    duplicate = rewrapOut.outDuplicate;
    symSeed = rewrapOut.outSymSeed;

    // Unload the new parent pub key
    INITIALIZE_CALL_BUFFERS(TPM2_FlushContext, &flushContextIn, &flushContextOut);
    parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle] = pubKey;
    EXECUTE_TPM_CALL(FALSE, TPM2_FlushContext);
    pubKey = parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle];

    // The NewParent can now use TPM2_Import and remove the inner wrapper that
    // is provided to him by the original owner of the key and then use the key.
    // The policy on the key is still valid. He can create an encrypted duplicate
    // of the key, but only to the MA.
    // Primary Objects:      SRK         MigrationAuthority          NewParent
    //                        |                  |                       |
    // TPM2_Import:      SRKEnc(Key) ->  MAEnc(Enc(Key))     ->     NPEnc(Key)

    // No we import the blob under the new parent
    INITIALIZE_CALL_BUFFERS(TPM2_Import, &importIn, &importOut);
    parms.objectTableIn[TPM2_Import_HdlIn_ParentHandle] = newParent;
    importIn.encryptionKey = innerWrapKey; // Here comes the inner wrap key to authorize the import.
    importIn.objectPublic = key.obj.publicArea;
    importIn.duplicate = duplicate;
    importIn.inSymSeed = symSeed;
    importIn.symmetricAlg.algorithm = TPM_ALG_AES;
    importIn.symmetricAlg.keyBits.aes = MAX_AES_KEY_BITS;
    importIn.symmetricAlg.mode.aes = TPM_ALG_CFB;
    EXECUTE_TPM_CALL(FALSE, TPM2_Import);
    key.obj.privateArea = importOut.outPrivate;

    // Load the key under the new parent
    INITIALIZE_CALL_BUFFERS(TPM2_Load, &loadIn, &loadOut);
    parms.objectTableIn[TPM2_Load_HdlIn_ParentHandle] = newParent;
    parms.objectTableOut[TPM2_Load_HdlOut_ObjectHandle] = key; // Copy the key in to be updated
    loadIn.inPublic = key.obj.publicArea;
    loadIn.inPrivate = key.obj.privateArea;
    EXECUTE_TPM_CALL(FALSE, TPM2_Load);
    key = parms.objectTableOut[TPM2_Load_HdlOut_ObjectHandle];

    // Unload the key
    INITIALIZE_CALL_BUFFERS(TPM2_FlushContext, &flushContextIn, &flushContextOut);
    parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle] = key;
    EXECUTE_TPM_CALL(FALSE, TPM2_FlushContext);
    key = parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle];

    // Phew! We are done!
Cleanup:
    return result;
}

UINT32
TestNVIndexReadWrite()
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    ANY_OBJECT nvIndex = {0};
    NV_DefineSpace_In nv_DefineSpaceIn = {0};
    NV_DefineSpace_Out nv_DefineSpaceOut;
    NV_ReadPublic_In nv_ReadPublicIn;
    NV_ReadPublic_Out nv_ReadPublicOut = {0};
    NV_Write_In nv_WriteIn = {0};
    NV_Write_Out nv_WriteOut;
    NV_Read_In nv_ReadIn = {0};
    NV_Read_Out nv_ReadOut = {0};
    NV_UndefineSpace_In nv_UndefineSpaceIn;
    NV_UndefineSpace_Out nv_UndefineSpaceOut;

    // Create the session
    sessionTable[0].handle = TPM_RS_PW;

    // Create NV Storage Index
    INITIALIZE_CALL_BUFFERS(TPM2_NV_DefineSpace, &nv_DefineSpaceIn, &nv_DefineSpaceOut);
    parms.objectTableIn[TPM2_NV_DefineSpace_HdlIn_AuthHandle] = g_StorageOwner;
    nv_DefineSpaceIn.publicInfo.t.nvPublic.nvIndex = TPM_20_OWNER_NV_SPACE + 0x003FFFFF; // Last owner Index
    nv_DefineSpaceIn.publicInfo.t.nvPublic.nameAlg = TPM_ALG_SHA256;
    nv_DefineSpaceIn.publicInfo.t.nvPublic.attributes.TPMA_NV_AUTHWRITE = SET;
    nv_DefineSpaceIn.publicInfo.t.nvPublic.attributes.TPMA_NV_AUTHREAD = SET;
    nv_DefineSpaceIn.publicInfo.t.nvPublic.attributes.TPMA_NV_NO_DA = SET;
    nv_DefineSpaceIn.publicInfo.t.nvPublic.attributes.TPMA_NV_ORDERLY = SET;
    nv_DefineSpaceIn.publicInfo.t.nvPublic.dataSize = SHA256_DIGEST_SIZE;
    nv_DefineSpaceIn.auth.t.size = sizeof(g_UsageAuth);
    MemoryCopy(nv_DefineSpaceIn.auth.t.buffer, g_UsageAuth, sizeof(g_UsageAuth), sizeof(nv_DefineSpaceIn.auth.t.buffer));
    MemoryRemoveTrailingZeros(&nv_DefineSpaceIn.auth);
    EXECUTE_TPM_CALL(FALSE, TPM2_NV_DefineSpace);

    // Put the index object together
    nvIndex.nv.handle = nv_DefineSpaceIn.publicInfo.t.nvPublic.nvIndex;
    nvIndex.nv.authValue = nv_DefineSpaceIn.auth;

    // Read public NV storage info
    INITIALIZE_CALL_BUFFERS(TPM2_NV_ReadPublic, &nv_ReadPublicIn, &nv_ReadPublicOut);
    parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex] = nvIndex; // Copy the object in to be completed
    EXECUTE_TPM_CALL(FALSE, TPM2_NV_ReadPublic);

    // Copy the object back out
    nvIndex = parms.objectTableIn[TPM2_NV_ReadPublic_HdlIn_NvIndex];

    // Write to the NV index
    INITIALIZE_CALL_BUFFERS(TPM2_NV_Write, &nv_WriteIn, &nv_WriteOut);
    parms.objectTableIn[TPM2_NV_Write_HdlIn_AuthHandle] = nvIndex;
    parms.objectTableIn[TPM2_NV_Write_HdlIn_NvIndex] = nvIndex;
    nv_WriteIn.offset = 0;
    nv_WriteIn.data.t.size = nvIndex.nv.nvPublic.t.nvPublic.dataSize;
    MemorySet(nv_WriteIn.data.t.buffer, 0x11, nv_WriteIn.data.t.size);
    EXECUTE_TPM_CALL(FALSE, TPM2_NV_Write);

    // Read from the NV index
    INITIALIZE_CALL_BUFFERS(TPM2_NV_Read, &nv_ReadIn, &nv_ReadOut);
    parms.objectTableIn[TPM2_NV_Read_HdlIn_AuthHandle] = nvIndex;
    parms.objectTableIn[TPM2_NV_Read_HdlIn_NvIndex] = nvIndex;
    nv_ReadIn.size = nvIndex.nv.nvPublic.t.nvPublic.dataSize;
    nv_ReadIn.offset = 0;
    EXECUTE_TPM_CALL(FALSE, TPM2_NV_Read);

    if((nv_ReadOut.data.t.size != nvIndex.nv.nvPublic.t.nvPublic.dataSize) || (!MemoryEqual(nv_WriteIn.data.t.buffer, nv_ReadOut.data.t.buffer, nv_ReadOut.data.t.size)))
    {
        result = TPM_RC_FAILURE;
    }

    // Undefine NV Storage Index
    INITIALIZE_CALL_BUFFERS(TPM2_NV_UndefineSpace, &nv_UndefineSpaceIn, &nv_UndefineSpaceOut);
    parms.objectTableIn[TPM2_NV_UndefineSpace_HdlIn_AuthHandle] = g_StorageOwner;
    parms.objectTableIn[TPM2_NV_UndefineSpace_HdlIn_NvIndex] = nvIndex;
    EXECUTE_TPM_CALL(FALSE, TPM2_NV_UndefineSpace);

Cleanup:
    return result;
}

UINT32
TestVirtualization()
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    Load_In loadIn = {0};
    Load_Out loadOut = {0};
    Sign_In signIn = {0};
    Sign_Out signOut = {0};
    GetCapability_In getCapabilityIn;
    GetCapability_Out getCapabilityOut;
    StartAuthSession_In startAuthSessionIn = {0};
    StartAuthSession_Out startAuthSessionOut = {0};
    FlushContext_In flushContextIn;
    FlushContext_Out flushContextOut;
    ANY_OBJECT objectTable[5] = {0};
    SESSION sesTable[15] = {0};
    TPMI_YES_NO cmdComplete = NO;

    // Create the session
    sessionTable[0].handle = TPM_RS_PW;

    // Create the object table
    for(UINT32 n = 0; n < 5; n++)
    {
        objectTable[n].obj.publicArea = g_KeyObject.obj.publicArea;
        objectTable[n].obj.privateArea = g_KeyObject.obj.privateArea;
        objectTable[n].obj.authValue = g_KeyObject.obj.authValue;

        // Load the key
        INITIALIZE_CALL_BUFFERS(TPM2_Load, &loadIn, &loadOut);
        parms.objectTableIn[TPM2_Load_HdlIn_ParentHandle] = g_SrkObject;
        parms.objectTableOut[TPM2_Load_HdlOut_ObjectHandle] = objectTable[n];
        loadIn.inPublic = objectTable[n].obj.publicArea;
        loadIn.inPrivate = objectTable[n].obj.privateArea;
        EXECUTE_VIRTUALIZED_TPM_CALL(FALSE, TPM2_Load);

        // copy the keyt back out
        objectTable[n] = parms.objectTableOut[TPM2_Load_HdlOut_ObjectHandle];
    }

    for(UINT32 n = 0; n < 5; n++)
    {
        // Sign digest
        INITIALIZE_CALL_BUFFERS(TPM2_Sign, &signIn, &signOut);
        parms.objectTableIn[TPM2_Sign_HdlIn_KeyHandle] = objectTable[n];
        signIn.digest.t.size = SHA256_DIGEST_SIZE;
        MemorySet((TPM2B*)&signIn.digest.t.buffer, 0x11, signIn.digest.t.size);
        signIn.inScheme.scheme = TPM_ALG_RSAPSS;
        signIn.inScheme.details.rsapss.hashAlg = TPM_ALG_SHA256;
        signIn.validation.tag = TPM_ST_HASHCHECK;
        signIn.validation.hierarchy = TPM_RH_NULL;
        EXECUTE_VIRTUALIZED_TPM_CALL(FALSE, TPM2_Sign);
    }

    INITIALIZE_CALL_BUFFERS(TPM2_GetCapability, &getCapabilityIn, &getCapabilityOut);
    getCapabilityIn.capability = TPM_CAP_HANDLES;
    getCapabilityIn.property = HR_TRANSIENT;
    getCapabilityIn.propertyCount = 0x100;
    EXECUTE_VIRTUALIZED_TPM_CALL(FALSE, TPM2_GetCapability);

    for(UINT32 n = 0; n < 15; n++)
    {
        // Start session
        INITIALIZE_CALL_BUFFERS(TPM2_StartAuthSession, &startAuthSessionIn, &startAuthSessionOut);
        parms.objectTableIn[TPM2_StartAuthSession_HdlIn_TpmKey].obj.handle = TPM_RH_NULL;
        parms.objectTableIn[TPM2_StartAuthSession_HdlIn_Bind].obj.handle = TPM_RH_NULL;
        startAuthSessionIn.nonceCaller.t.size = CryptGenerateRandom(SHA256_DIGEST_SIZE, startAuthSessionIn.nonceCaller.t.buffer);
        startAuthSessionIn.sessionType = TPM_SE_HMAC;
        startAuthSessionIn.symmetric.algorithm = TPM_ALG_NULL;
        startAuthSessionIn.authHash = TPM_ALG_SHA256;
        EXECUTE_VIRTUALIZED_TPM_CALL(FALSE, TPM2_StartAuthSession);

        // Copy the session out
        sesTable[n] = parms.objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session;
    }

    INITIALIZE_CALL_BUFFERS(TPM2_GetCapability, &getCapabilityIn, &getCapabilityOut);
    getCapabilityIn.capability = TPM_CAP_HANDLES;
    getCapabilityIn.property = HR_HMAC_SESSION;
    getCapabilityIn.propertyCount = 0x100;
    EXECUTE_VIRTUALIZED_TPM_CALL(FALSE, TPM2_GetCapability);

    for(UINT32 n = 0; n < 15; n++)
    {
        sessionTable[0] = sesTable[n];
        sessionTable[0].attributes.continueSession = CLEAR;

        // Sign digest
        INITIALIZE_CALL_BUFFERS(TPM2_Sign, &signIn, &signOut);
        parms.objectTableIn[0] = objectTable[n % 5];
        signIn.digest.t.size = SHA256_DIGEST_SIZE;
        MemorySet((TPM2B*)&signIn.digest.t.buffer, 0x11, signIn.digest.t.size);
        signIn.inScheme.scheme = TPM_ALG_RSAPSS;
        signIn.inScheme.details.rsapss.hashAlg = TPM_ALG_SHA256;
        signIn.validation.tag = TPM_ST_HASHCHECK;
        signIn.validation.hierarchy = TPM_RH_NULL;
        EXECUTE_VIRTUALIZED_TPM_CALL(FALSE, TPM2_Sign);
    }

    for(UINT32 n = 0; n < 5; n++)
    {
        // Unload the key
        INITIALIZE_CALL_BUFFERS(TPM2_FlushContext, &flushContextIn, &flushContextOut);
        parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle] = objectTable[n];
        EXECUTE_VIRTUALIZED_TPM_CALL(FALSE, TPM2_FlushContext);
 
        objectTable[n] = parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle];
    }



Cleanup:
    return result;
}

UINT32
TestObjectChangeAuth()
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    SESSION policySession = {0};
    ANY_OBJECT newKey = {0};
    StartAuthSession_In startAuthSessionIn = {0};
    StartAuthSession_Out startAuthSessionOut = {0};
    PolicyCommandCode_In policyCommandCodeIn = {0};
    PolicyCommandCode_Out policyCommandCodeOut;
    PolicyAuthValue_In policyAuthValueIn;
    PolicyAuthValue_Out policyAuthValueOut;
    PolicyOR_In policyORIn = {0};
    PolicyOR_Out policyOROut;
    ObjectChangeAuth_In objectChangeAuthIn = {0};
    ObjectChangeAuth_Out objectChangeAuthOut = {0};
    Load_In loadIn = {0};
    Load_Out loadOut = {0};
    Sign_In signIn = {0};
    Sign_Out signOut = {0};

    // Create the admin policy Session
    INITIALIZE_CALL_BUFFERS(TPM2_StartAuthSession, &startAuthSessionIn, &startAuthSessionOut);
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_TpmKey].obj.handle = TPM_RH_NULL;
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_Bind].obj.handle = TPM_RH_NULL;
    startAuthSessionIn.nonceCaller.t.size = CryptGenerateRandom(SHA256_DIGEST_SIZE, startAuthSessionIn.nonceCaller.t.buffer);
    startAuthSessionIn.sessionType = TPM_SE_POLICY;
    startAuthSessionIn.symmetric.algorithm = TPM_ALG_NULL;
    startAuthSessionIn.authHash = TPM_ALG_SHA256;
    EXECUTE_TPM_CALL(FALSE, TPM2_StartAuthSession);

    // Copy session back out
    policySession = parms.objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session;

    // Set the session up for admin ObjectChangeAuth
    INITIALIZE_CALL_BUFFERS(TPM2_PolicyCommandCode, &policyCommandCodeIn, &policyCommandCodeOut);
    parms.objectTableIn[TPM2_PolicyCommandCode_HdlIn_PolicySession].session = policySession;
    policyCommandCodeIn.code = TPM_CC_ObjectChangeAuth;
    EXECUTE_TPM_CALL(FALSE, TPM2_PolicyCommandCode);
    policySession = parms.objectTableIn[TPM2_PolicyCommandCode_HdlIn_PolicySession].session;
    INITIALIZE_CALL_BUFFERS(TPM2_PolicyAuthValue, &policyAuthValueIn, &policyAuthValueOut);
    parms.objectTableIn[TPM2_PolicyAuthValue_HdlIn_PolicySession].session = policySession;
    EXECUTE_TPM_CALL(FALSE, TPM2_PolicyAuthValue);
    policySession = parms.objectTableIn[TPM2_PolicyAuthValue_HdlIn_PolicySession].session;
    INITIALIZE_CALL_BUFFERS(TPM2_PolicyOR, &policyORIn, &policyOROut);
    parms.objectTableIn[TPM2_PolicyOR_HdlIn_PolicySession].session = policySession;
    policyORIn.pHashList = g_AdminPolicyHashList; // Copy in the previously stored value, so we don't haveto calculate the entire policy again
    EXECUTE_TPM_CALL(FALSE, TPM2_PolicyOR);
    policySession = parms.objectTableIn[TPM2_PolicyOR_HdlIn_PolicySession].session;

    // Put the sessions together
    sessionTable[0] = policySession;
    policySession.attributes.continueSession = NO;

    // Change the Auth of the key
    INITIALIZE_CALL_BUFFERS(TPM2_ObjectChangeAuth, &objectChangeAuthIn, &objectChangeAuthOut);
    parms.objectTableIn[TPM2_ObjectChangeAuth_HdlIn_ObjectHandle] = g_KeyObject;
    parms.objectTableIn[TPM2_ObjectChangeAuth_HdlIn_ParentHandle] = g_SrkObject;
    objectChangeAuthIn.newAuth.t.size = CryptGenerateRandom(SHA256_DIGEST_SIZE, objectChangeAuthIn.newAuth.t.buffer);
    MemoryRemoveTrailingZeros(&objectChangeAuthIn.newAuth);
    EXECUTE_TPM_CALL(FALSE, TPM2_ObjectChangeAuth);

    // Copy the new key out
    newKey = parms.objectTableIn[TPM2_ObjectChangeAuth_HdlIn_ObjectHandle];

    // Create the session
    sessionTable[0].handle = TPM_RS_PW;

    // Load the new key
    INITIALIZE_CALL_BUFFERS(TPM2_Load, &loadIn, &loadOut);
    parms.objectTableIn[TPM2_Load_HdlIn_ParentHandle] = g_SrkObject;
    parms.objectTableOut[TPM2_Load_HdlOut_ObjectHandle] = newKey;
    loadIn.inPublic = newKey.obj.publicArea;
    loadIn.inPrivate = newKey.obj.privateArea;
    EXECUTE_TPM_CALL(FALSE, TPM2_Load);

    // Copy the updated key back out
    newKey = parms.objectTableOut[TPM2_Load_HdlOut_ObjectHandle];

    // Sign digest
    INITIALIZE_CALL_BUFFERS(TPM2_Sign, &signIn, &signOut);
    parms.objectTableIn[TPM2_Sign_HdlIn_KeyHandle] = newKey;
    signIn.digest.t.size = SHA256_DIGEST_SIZE;
    MemorySet((TPM2B*)&signIn.digest.t.buffer, 0x11, signIn.digest.t.size);
    signIn.inScheme.scheme = TPM_ALG_RSAPSS;
    signIn.inScheme.details.rsapss.hashAlg = TPM_ALG_SHA256;
    signIn.validation.tag = TPM_ST_HASHCHECK;
    signIn.validation.hierarchy = TPM_RH_NULL;
    EXECUTE_TPM_CALL(FALSE, TPM2_Sign);

Cleanup:
    return result;
}

UINT32
TestUnseal()
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    ANY_OBJECT sealedBlob = {0};
    Create_In createIn = {0};
    Create_Out createOut = {0};
    Load_In loadIn = {0};
    Load_Out loadOut = {0};
    Unseal_In unsealIn;
    Unseal_Out unsealOut = {0};
    FlushContext_In flushContextIn;
    FlushContext_Out flushContextOut;

    // Create the session
    sessionTable[0].handle = TPM_RS_PW;

    // Create the sealed blob
    INITIALIZE_CALL_BUFFERS(TPM2_Create, &createIn, &createOut);
    parms.objectTableIn[TPM2_Create_HdlIn_ParentHandle] = g_SrkObject;
    createIn.inSensitive.t.sensitive.userAuth.t.size = sizeof(g_UsageAuth);
    MemoryCopy(createIn.inSensitive.t.sensitive.userAuth.t.buffer, g_UsageAuth, createIn.inSensitive.t.sensitive.userAuth.t.size, sizeof(createIn.inSensitive.t.sensitive.userAuth.t.buffer));
    MemoryRemoveTrailingZeros(&createIn.inSensitive.t.sensitive.userAuth);
    createIn.inSensitive.t.sensitive.data.t.size = SHA256_DIGEST_SIZE;
    MemorySet(createIn.inSensitive.t.sensitive.data.t.buffer, 0x11, createIn.inSensitive.t.sensitive.data.t.size);
    createIn.inPublic.t.publicArea.type = TPM_ALG_KEYEDHASH;
    createIn.inPublic.t.publicArea.nameAlg = TPM_ALG_SHA256;
    createIn.inPublic.t.publicArea.objectAttributes.fixedTPM = 1;
    createIn.inPublic.t.publicArea.objectAttributes.fixedParent = 1;
    createIn.inPublic.t.publicArea.objectAttributes.userWithAuth = 1;
    createIn.inPublic.t.publicArea.objectAttributes.noDA = 1;
    createIn.inPublic.t.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_NULL;
    EXECUTE_TPM_CALL(FALSE, TPM2_Create);

    // Build the selead object
    sealedBlob.obj.publicArea = createOut.outPublic;
    sealedBlob.obj.privateArea = createOut.outPrivate;
    sealedBlob.obj.authValue = createIn.inSensitive.t.sensitive.userAuth;

    // Load the sealed blob
    INITIALIZE_CALL_BUFFERS(TPM2_Load, &loadIn, &loadOut);
    parms.objectTableIn[TPM2_Load_HdlIn_ParentHandle] = g_SrkObject;
    parms.objectTableOut[TPM2_Load_HdlOut_ObjectHandle] = sealedBlob;
    loadIn.inPublic = sealedBlob.obj.publicArea;
    loadIn.inPrivate = sealedBlob.obj.privateArea;
    EXECUTE_TPM_CALL(FALSE, TPM2_Load);

    // Copy the updated object back out
    sealedBlob = parms.objectTableOut[TPM2_Load_HdlOut_ObjectHandle];

    // Unseal the blob
    INITIALIZE_CALL_BUFFERS(TPM2_Unseal, &unsealIn, &unsealOut);
    parms.objectTableIn[TPM2_Unseal_HdlIn_ItemHandle] = sealedBlob;
    EXECUTE_TPM_CALL(FALSE, TPM2_Unseal);

    // Check the returned data
    if((unsealOut.outData.t.size != createIn.inSensitive.t.sensitive.data.t.size) ||
       !MemoryEqual(unsealOut.outData.t.buffer, createIn.inSensitive.t.sensitive.data.t.buffer, unsealOut.outData.t.size))
    {
        result = TPM_RC_FAILURE;
        goto Cleanup;
    }

    // Unload the blob
    INITIALIZE_CALL_BUFFERS(TPM2_FlushContext, &flushContextIn, &flushContextOut);
    parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle] = sealedBlob;
    EXECUTE_TPM_CALL(FALSE, TPM2_FlushContext);

    sealedBlob = parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle];

Cleanup:
    return result;
}

UINT32
TestDynamicPolicies()
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    ANY_OBJECT sealedBlob = {0};
    ANY_OBJECT authorityPubKey = {0};
    TPM2B_DIGEST dynamicPolicyDigest = {0};
    TPM2B_DIGEST dynamicPolicyRef = {0};
    HASH_STATE hashState = {0};
    SESSION policySession = {0};

    PolicyAuthorize_In policyAuthorizeIn = {0};
    PolicyAuthorize_Out policyAuthorizeOut;
    PolicyAuthValue_In policyAuthValueIn;
    PolicyAuthValue_Out policyAuthValueOut;
    Create_In createIn = {0};
    Create_Out createOut = {0};
    Load_In loadIn = {0};
    Load_Out loadOut = {0};
    Sign_In signIn = {0};
    Sign_Out signOut = {0};
    LoadExternal_In loadExternalIn = {0};
    LoadExternal_Out loadExternalOut = {0};
    VerifySignature_In verifySignatureIn = {0};
    VerifySignature_Out verifySignatureOut = {0};
    StartAuthSession_In startAuthSessionIn = {0};
    StartAuthSession_Out startAuthSessionOut = {0};
    Unseal_In unsealIn;
    Unseal_Out unsealOut = {0};
    FlushContext_In flushContextIn;
    FlushContext_Out flushContextOut;

    // Create the session
    sessionTable[0].handle = TPM_RS_PW;

    // Create a sealed blob that acceps a dynamic policy
    INITIALIZE_CALL_BUFFERS(TPM2_Create, &createIn, &createOut);
    parms.objectTableIn[TPM2_Create_HdlIn_ParentHandle] = g_SrkObject;
    createIn.inSensitive.t.sensitive.userAuth.t.size = sizeof(g_UsageAuth);
    MemoryCopy(createIn.inSensitive.t.sensitive.userAuth.t.buffer, g_UsageAuth, createIn.inSensitive.t.sensitive.userAuth.t.size, sizeof(createIn.inSensitive.t.sensitive.userAuth.t.buffer));
    MemoryRemoveTrailingZeros(&createIn.inSensitive.t.sensitive.userAuth);
    createIn.inSensitive.t.sensitive.data.t.size = SHA256_DIGEST_SIZE;
    MemorySet(createIn.inSensitive.t.sensitive.data.t.buffer, 0x11, createIn.inSensitive.t.sensitive.data.t.size);
    
    // Build the dynamic policy authority for this object
    dynamicPolicyRef.t.size = SHA256_DIGEST_SIZE;
    MemorySet(dynamicPolicyRef.t.buffer, 0x11, dynamicPolicyRef.t.size);
    policyAuthorizeIn.policyRef = dynamicPolicyRef;
    policyAuthorizeIn.keySign = g_KeyObject.obj.name;
    createIn.inPublic.t.publicArea.authPolicy.t.size = SHA256_DIGEST_SIZE;
    TPM2_PolicyAuthorize_CalculateUpdate(TPM_ALG_SHA256, &createIn.inPublic.t.publicArea.authPolicy, &policyAuthorizeIn);

    createIn.inPublic.t.publicArea.type = TPM_ALG_KEYEDHASH;
    createIn.inPublic.t.publicArea.nameAlg = TPM_ALG_SHA256;
    createIn.inPublic.t.publicArea.objectAttributes.fixedTPM = 1;
    createIn.inPublic.t.publicArea.objectAttributes.fixedParent = 1;
    createIn.inPublic.t.publicArea.objectAttributes.noDA = 1;
    createIn.inPublic.t.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_NULL;
    EXECUTE_TPM_CALL(FALSE, TPM2_Create);

    // Build the sealed blob
    sealedBlob.obj.publicArea = createOut.outPublic;
    sealedBlob.obj.privateArea = createOut.outPrivate;
    sealedBlob.obj.authValue = createIn.inSensitive.t.sensitive.userAuth;

    // Load the sealed blob
    INITIALIZE_CALL_BUFFERS(TPM2_Load, &loadIn, &loadOut);
    parms.objectTableIn[TPM2_Load_HdlIn_ParentHandle] = g_SrkObject;
    parms.objectTableOut[TPM2_Load_HdlOut_ObjectHandle] = sealedBlob;
    loadIn.inPublic = sealedBlob.obj.publicArea;
    loadIn.inPrivate = sealedBlob.obj.privateArea;
    EXECUTE_TPM_CALL(FALSE, TPM2_Load);

    // Copy the updated object back out
    sealedBlob = parms.objectTableOut[TPM2_Load_HdlOut_ObjectHandle];

    // The authority builds a dynamic policy (PolicyAuthValue)
    dynamicPolicyDigest.t.size = SHA256_DIGEST_SIZE;
    TPM2_PolicyAuthValue_CalculateUpdate(TPM_ALG_SHA256, &dynamicPolicyDigest, &policyAuthValueIn);

    // The authority signs the policy into action. Obviously this happens on
    // the server likely in software, however our authority key happens to be TPM bound.
    INITIALIZE_CALL_BUFFERS(TPM2_Sign, &signIn, &signOut);
    parms.objectTableIn[TPM2_Sign_HdlIn_KeyHandle] = g_KeyObject;
    signIn.digest.t.size = CryptStartHash(TPM_ALG_SHA256, &hashState);
    CryptUpdateDigest2B(&hashState, (TPM2B*)&dynamicPolicyDigest);
    CryptUpdateDigest2B(&hashState, (TPM2B*)&dynamicPolicyRef);
    CryptCompleteHash2B(&hashState, (TPM2B*)&signIn.digest);
    signIn.inScheme.scheme = TPM_ALG_RSAPSS;
    signIn.inScheme.details.rsapss.hashAlg = TPM_ALG_SHA256;
    signIn.validation.tag = TPM_ST_HASHCHECK;
    signIn.validation.hierarchy = TPM_RH_NULL;
    EXECUTE_TPM_CALL(FALSE, TPM2_Sign);

    // Back on the client we load the authority pubKey
    INITIALIZE_CALL_BUFFERS(TPM2_LoadExternal, &loadExternalIn, &loadExternalOut);
    loadExternalIn.inPublic = g_KeyObject.obj.publicArea;
    loadExternalIn.hierarchy = TPM_RH_OWNER; // We use the OWNER hierarchy so we get a real tickets
    EXECUTE_TPM_CALL(FALSE, TPM2_LoadExternal);
    authorityPubKey = parms.objectTableOut[TPM2_LoadExternal_HdlOut_ObjectHandle];

    // ...and verify the signature on the policy digest to produce a ticket from the OWNER hierarchy
    INITIALIZE_CALL_BUFFERS(TPM2_VerifySignature, &verifySignatureIn, &verifySignatureOut);
    parms.objectTableIn[TPM2_VerifySignature_HdlIn_KeyHandle] = authorityPubKey;
    verifySignatureIn.digest = signIn.digest;
    verifySignatureIn.signature = signOut.signature;
    EXECUTE_TPM_CALL(FALSE, TPM2_VerifySignature);

    // Unload the authority pubKey
    INITIALIZE_CALL_BUFFERS(TPM2_FlushContext, &flushContextIn, &flushContextOut);
    parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle] = authorityPubKey;
    EXECUTE_TPM_CALL(FALSE, TPM2_FlushContext);

    // Next we create the policy session to use the dynamic policy
    INITIALIZE_CALL_BUFFERS(TPM2_StartAuthSession, &startAuthSessionIn, &startAuthSessionOut);
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_TpmKey].obj.handle = TPM_RH_NULL;
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_Bind].obj.handle = TPM_RH_NULL;
    startAuthSessionIn.nonceCaller.t.size = CryptGenerateRandom(SHA256_DIGEST_SIZE, startAuthSessionIn.nonceCaller.t.buffer);
    startAuthSessionIn.sessionType = TPM_SE_POLICY;
    startAuthSessionIn.symmetric.algorithm = TPM_ALG_NULL;
    startAuthSessionIn.authHash = TPM_ALG_SHA256;
    EXECUTE_TPM_CALL(FALSE, TPM2_StartAuthSession);

    // Copy session back out
    policySession = parms.objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session;

    // First we execute the dynamic policy portion (PolicyAuthValue)
    INITIALIZE_CALL_BUFFERS(TPM2_PolicyAuthValue, &policyAuthValueIn, &policyAuthValueOut);
    parms.objectTableIn[TPM2_PolicyAuthValue_HdlIn_PolicySession].session = policySession;
    EXECUTE_TPM_CALL(FALSE, TPM2_PolicyAuthValue);
    policySession = parms.objectTableIn[TPM2_PolicyAuthorize_HdlIn_PolicySession].session;

    // Next we execute the fixed policy portion that is baked into the key (PolicyAuthorize)
    INITIALIZE_CALL_BUFFERS(TPM2_PolicyAuthorize, &policyAuthorizeIn, &policyAuthorizeOut);
    parms.objectTableIn[TPM2_PolicyAuthorize_HdlIn_PolicySession].session = policySession;
    policyAuthorizeIn.approvedPolicy = dynamicPolicyDigest;
    policyAuthorizeIn.policyRef = dynamicPolicyRef;
    policyAuthorizeIn.keySign = authorityPubKey.obj.name;
    policyAuthorizeIn.checkTicket = verifySignatureOut.validation;
    EXECUTE_TPM_CALL(FALSE, TPM2_PolicyAuthorize);
    policySession = parms.objectTableIn[TPM2_PolicyAuthorize_HdlIn_PolicySession].session;

    // Put the sessions together
    sessionTable[0] = policySession;
    sessionTable[0].attributes.continueSession = 0;

    // Unseal the blob using the policy session
    INITIALIZE_CALL_BUFFERS(TPM2_Unseal, &unsealIn, &unsealOut);
    parms.objectTableIn[TPM2_Unseal_HdlIn_ItemHandle] = sealedBlob;
    EXECUTE_TPM_CALL(FALSE, TPM2_Unseal);

    // Check the returned data
    if((unsealOut.outData.t.size != createIn.inSensitive.t.sensitive.data.t.size) ||
        !MemoryEqual(unsealOut.outData.t.buffer, createIn.inSensitive.t.sensitive.data.t.buffer, unsealOut.outData.t.size))
    {
        result = TPM_RC_FAILURE;
        goto Cleanup;
    }

    // Unload the sealed blob
    INITIALIZE_CALL_BUFFERS(TPM2_FlushContext, &flushContextIn, &flushContextOut);
    parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle] = sealedBlob;
    EXECUTE_TPM_CALL(FALSE, TPM2_FlushContext);

    sealedBlob = parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle];

Cleanup:
    return result;
}

UINT32
TestRSADecrypt()
{
    DEFINE_CALL_BUFFERS;
    const char label[] = "ThisIsMyLabel";
    UINT32 result = TPM_RC_SUCCESS;
    RSA_Encrypt_In rsaEncryptIn = {0};
    RSA_Encrypt_Out rsaEncryptOut = {0};
    RSA_Decrypt_In rsaDecryptIn = {0};
    RSA_Decrypt_Out rsaDecryptOut = {0};
    BCRYPT_OAEP_PADDING_INFO padding = {BCRYPT_SHA256_ALGORITHM, (PUCHAR)label, sizeof(label)};
    ULONG cbResult = 0;

    // Create the encrypted blob in the TPM
    INITIALIZE_CALL_BUFFERS(TPM2_RSA_Encrypt, &rsaEncryptIn, &rsaEncryptOut);
    parms.objectTableIn[TPM2_Create_HdlIn_ParentHandle] = g_KeyObject;
    rsaEncryptIn.message.t.size = SHA256_DIGEST_SIZE;
    MemorySet(rsaEncryptIn.message.t.buffer, 0x11, rsaEncryptIn.message.t.size);
    rsaEncryptIn.inScheme.scheme = TPM_ALG_OAEP;
    rsaEncryptIn.inScheme.details.oaep.hashAlg = TPM_ALG_SHA256;
    rsaEncryptIn.label.t.size = sizeof(label); // Null terminated label is mandatory
    MemoryCopy(rsaEncryptIn.label.t.buffer, label, rsaEncryptIn.label.t.size, sizeof(rsaEncryptIn.label.t.buffer));
    EXECUTE_TPM_CALL(FALSE, TPM2_RSA_Encrypt);

    // Create the session
    sessionTable[0].handle = TPM_RS_PW;

    // Decrypt the blob
    INITIALIZE_CALL_BUFFERS(TPM2_RSA_Decrypt, &rsaDecryptIn, &rsaDecryptOut);
    parms.objectTableIn[TPM2_Create_HdlIn_ParentHandle] = g_KeyObject;
    rsaDecryptIn.cipherText = rsaEncryptOut.outData;
    rsaDecryptIn.inScheme.scheme = TPM_ALG_OAEP;
    rsaDecryptIn.inScheme.details.oaep.hashAlg = TPM_ALG_SHA256;
    rsaDecryptIn.label.t.size = sizeof(label); // Null terminated label is mandatory
    MemoryCopy(rsaDecryptIn.label.t.buffer, label, rsaDecryptIn.label.t.size, sizeof(rsaDecryptIn.label.t.buffer));
    EXECUTE_TPM_CALL(FALSE, TPM2_RSA_Decrypt);

    // Check the returned data
    if((rsaDecryptOut.message.t.size != rsaEncryptIn.message.t.size) ||
        !MemoryEqual(rsaDecryptOut.message.t.buffer, rsaEncryptIn.message.t.buffer, rsaDecryptOut.message.t.size))
    {
        result = TPM_RC_FAILURE;
        goto Cleanup;
    }

    // Decrypt a blob that was encrypted with software
    INITIALIZE_CALL_BUFFERS(TPM2_RSA_Decrypt, &rsaDecryptIn, &rsaDecryptOut);
    parms.objectTableIn[TPM2_Create_HdlIn_ParentHandle] = g_KeyObject;

    // Use the BCrypt key to encrypt the message
    if((result = BCryptEncrypt(g_hKey,
                               rsaEncryptIn.message.t.buffer,
                               rsaEncryptIn.message.t.size,
                               &padding,
                               NULL,
                               0,
                               rsaDecryptIn.cipherText.t.buffer,
                               sizeof(rsaDecryptIn.cipherText.t.buffer),
                               &cbResult,
                               BCRYPT_PAD_OAEP)) != ERROR_SUCCESS)
    {
        goto Cleanup;
    }
    rsaDecryptIn.cipherText.t.size = (UINT16)cbResult;

    rsaDecryptIn.inScheme.scheme = TPM_ALG_OAEP;
    rsaDecryptIn.inScheme.details.oaep.hashAlg = TPM_ALG_SHA256;
    rsaDecryptIn.label.t.size = sizeof(label); // Null terminated label is mandatory
    MemoryCopy(rsaDecryptIn.label.t.buffer, label, rsaDecryptIn.label.t.size, sizeof(rsaDecryptIn.label.t.buffer));
    EXECUTE_TPM_CALL(FALSE, TPM2_RSA_Decrypt);

    // Check the returned data
    if((rsaDecryptOut.message.t.size != rsaEncryptIn.message.t.size) ||
        !MemoryEqual(rsaDecryptOut.message.t.buffer, rsaEncryptIn.message.t.buffer, rsaDecryptOut.message.t.size))
    {
        result = TPM_RC_FAILURE;
        goto Cleanup;
    }

Cleanup:
    return result;
}

UINT32
TestECDSASign()
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    ANY_OBJECT ecdsaKey = {0};
    BCRYPT_ALG_HANDLE hEcdsaP256Alg = NULL;
    BCRYPT_KEY_HANDLE hEcdsaKey = NULL;
    BYTE pubKey[sizeof(BCRYPT_ECCKEY_BLOB) + 0x20 + 0x20] = {0};
    BYTE signature[0x40] = {0};
    BCRYPT_ECCKEY_BLOB* pPubKey = (BCRYPT_ECCKEY_BLOB*)pubKey;
    Create_In createIn = {0};
    Create_Out createOut = {0};
    Load_In loadIn = {0};
    Load_Out loadOut = {0};
    Sign_In signIn = {0};
    Sign_Out signOut = {0};
    FlushContext_In flushContextIn;
    FlushContext_Out flushContextOut;

    // Create the session
    sessionTable[0].handle = TPM_RS_PW;

    // Create the ECDSA key
    INITIALIZE_CALL_BUFFERS(TPM2_Create, &createIn, &createOut);
    parms.objectTableIn[TPM2_Create_HdlIn_ParentHandle] = g_SrkObject;
    createIn.inSensitive.t.sensitive.userAuth.t.size = sizeof(g_UsageAuth);
    MemoryCopy(createIn.inSensitive.t.sensitive.userAuth.t.buffer, g_UsageAuth, createIn.inSensitive.t.sensitive.userAuth.t.size, sizeof(createIn.inSensitive.t.sensitive.userAuth.t.buffer));
    MemoryRemoveTrailingZeros(&createIn.inSensitive.t.sensitive.userAuth);
    createIn.inPublic.t.publicArea.type = TPM_ALG_ECC;
    createIn.inPublic.t.publicArea.nameAlg = TPM_ALG_SHA256;
    createIn.inPublic.t.publicArea.objectAttributes.fixedTPM = 1;
    createIn.inPublic.t.publicArea.objectAttributes.fixedParent = 1;
    createIn.inPublic.t.publicArea.objectAttributes.sensitiveDataOrigin = 1;
    createIn.inPublic.t.publicArea.objectAttributes.userWithAuth = 1;
    createIn.inPublic.t.publicArea.objectAttributes.noDA = 1;
    createIn.inPublic.t.publicArea.objectAttributes.sign = 1;
    createIn.inPublic.t.publicArea.parameters.symDetail.algorithm = TPM_ALG_NULL;
    createIn.inPublic.t.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
    createIn.inPublic.t.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_ECDSA;
    createIn.inPublic.t.publicArea.parameters.eccDetail.scheme.details.ecdsa.hashAlg = TPM_ALG_SHA256;
    createIn.inPublic.t.publicArea.parameters.eccDetail.curveID = TPM_ECC_NIST_P256;
    createIn.inPublic.t.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
    EXECUTE_TPM_CALL(FALSE, TPM2_Create);

    // Build the key object
    ecdsaKey.obj.publicArea = createOut.outPublic;
    ecdsaKey.obj.privateArea = createOut.outPrivate;
    ecdsaKey.obj.authValue = createIn.inSensitive.t.sensitive.userAuth;

    // Load the key
    INITIALIZE_CALL_BUFFERS(TPM2_Load, &loadIn, &loadOut);
    parms.objectTableIn[TPM2_Load_HdlIn_ParentHandle] = g_SrkObject;
    parms.objectTableOut[TPM2_Load_HdlOut_ObjectHandle] = ecdsaKey; // Copy the key in to be updated
    loadIn.inPublic = ecdsaKey.obj.publicArea;
    loadIn.inPrivate = ecdsaKey.obj.privateArea;
    EXECUTE_TPM_CALL(FALSE, TPM2_Load);

    // Copy the updated key back out
    ecdsaKey = parms.objectTableOut[TPM2_Load_HdlOut_ObjectHandle];

    // Sign digest
    INITIALIZE_CALL_BUFFERS(TPM2_Sign, &signIn, &signOut);
    parms.objectTableIn[TPM2_Sign_HdlIn_KeyHandle] = ecdsaKey;
    signIn.digest.t.size = SHA256_DIGEST_SIZE;
    MemorySet((TPM2B*)&signIn.digest.t.buffer, 0x11, signIn.digest.t.size);
    signIn.inScheme.scheme = TPM_ALG_ECDSA;
    signIn.inScheme.details.ecdsa.hashAlg = TPM_ALG_SHA256;
    signIn.validation.tag = TPM_ST_HASHCHECK;
    signIn.validation.hierarchy = TPM_RH_NULL;
    EXECUTE_TPM_CALL(FALSE, TPM2_Sign);

    // Verify the signature in software
    pPubKey->dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
    pPubKey->cbKey = ecdsaKey.obj.publicArea.t.publicArea.unique.ecc.x.t.size;
    MemoryCopy(&pubKey[sizeof(BCRYPT_ECCKEY_BLOB)], ecdsaKey.obj.publicArea.t.publicArea.unique.ecc.x.t.buffer, ecdsaKey.obj.publicArea.t.publicArea.unique.ecc.x.t.size, pPubKey->cbKey);
    MemoryCopy(&pubKey[sizeof(BCRYPT_ECCKEY_BLOB) + pPubKey->cbKey], ecdsaKey.obj.publicArea.t.publicArea.unique.ecc.y.t.buffer, ecdsaKey.obj.publicArea.t.publicArea.unique.ecc.y.t.size, pPubKey->cbKey);
    MemoryCopy(&signature[0], signOut.signature.signature.ecdsa.signatureR.t.buffer, signOut.signature.signature.ecdsa.signatureR.t.size, sizeof(signature) / 2);
    MemoryCopy(&signature[0x20], signOut.signature.signature.ecdsa.signatureS.t.buffer, signOut.signature.signature.ecdsa.signatureS.t.size, sizeof(signature) / 2);
    if(((result = BCryptOpenAlgorithmProvider(&hEcdsaP256Alg, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0)) != ERROR_SUCCESS) ||
        ((result = BCryptImportKeyPair(hEcdsaP256Alg, NULL, BCRYPT_ECCPUBLIC_BLOB, &hEcdsaKey, pubKey, sizeof(pubKey), 0)) != ERROR_SUCCESS) ||
        ((result = BCryptVerifySignature(hEcdsaKey, NULL, signIn.digest.t.buffer, signIn.digest.t.size, signature, sizeof(signature), 0)) != ERROR_SUCCESS))
    {
        goto Cleanup;
    }

    // Unload the ECDSA key
    INITIALIZE_CALL_BUFFERS(TPM2_FlushContext, &flushContextIn, &flushContextOut);
    parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle] = ecdsaKey; // Copy the key in to be updated
    EXECUTE_TPM_CALL(FALSE, TPM2_FlushContext);

    // Copy the updated key back out
    ecdsaKey = parms.objectTableIn[TPM2_FlushContext_HdlIn_FlushHandle];

Cleanup:
    if(hEcdsaKey != NULL)
    {
        BCryptDestroyKey(hEcdsaKey);
        hEcdsaKey = NULL;
    }
    if(hEcdsaP256Alg != NULL)
    {
        BCryptCloseAlgorithmProvider(&hEcdsaP256Alg, 0);
        hEcdsaP256Alg = NULL;
    }
    return result;
}

UINT32
TestKeyAttestation()
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    SESSION policySession = {0};
    CertifyCreation_In certifyCreationIn = {0};
    CertifyCreation_Out certifyCreationOut = {0};
    StartAuthSession_In startAuthSessionIn = {0};
    StartAuthSession_Out startAuthSessionOut = {0};
    Certify_In certifyIn = {0};
    Certify_Out certifyOut = {0};
    const char certifyNonce[32] = "RandomServerPickedCertifyNonce.";
    TPM2B_ATTEST attestation = {0};
    BCRYPT_HASH_HANDLE hHash = NULL;
    TPM2B_DIGEST signatureDigest = {0};
    BCRYPT_PSS_PADDING_INFO padding = {BCRYPT_SHA256_ALGORITHM, (256 - 32 - 2)};
    PolicyCommandCode_In policyCommandCodeIn = {0};
    PolicyCommandCode_Out policyCommandCodeOut;
    PolicyAuthValue_In policyAuthValueIn;
    PolicyAuthValue_Out policyAuthValueOut;
    PolicyOR_In policyORIn = {0};
    PolicyOR_Out policyOROut;

    // Create the session
    sessionTable[0].handle = TPM_RS_PW;

    // Create AIK signed certifyCreation structure
    INITIALIZE_CALL_BUFFERS(TPM2_CertifyCreation, &certifyCreationIn, &certifyCreationOut);
    parms.objectTableIn[TPM2_CertifyCreation_HdlIn_SignHandle] = g_AikObject;
    parms.objectTableIn[TPM2_CertifyCreation_HdlIn_ObjectHandle] = g_KeyObject;
    certifyCreationIn.qualifyingData.t.size = sizeof(certifyNonce);
    MemoryCopy(certifyCreationIn.qualifyingData.t.buffer, certifyNonce, sizeof(certifyNonce), sizeof(certifyCreationIn.qualifyingData.t.buffer));
    certifyCreationIn.creationHash = g_KeyCreationHash;
    certifyCreationIn.inScheme.scheme = TPM_ALG_RSAPSS;
    certifyCreationIn.inScheme.details.rsapss.hashAlg = TPM_ALG_SHA256;
    certifyCreationIn.creationTicket = g_KeyCreationTicket;
    EXECUTE_TPM_CALL(FALSE, TPM2_CertifyCreation);

    // Get the attestation digest
    buffer = attestation.b.buffer;
    size = sizeof(attestation.t.attestationData);
    attestation.b.size = TPMS_ATTEST_Marshal(&certifyCreationOut.certifyInfo.t.attestationData, &buffer, &size);
    signatureDigest.t.size = SHA256_DIGEST_SIZE;
    if(((result = BCryptCreateHash(g_hAlg[1], &hHash, NULL, 0, NULL, 0, 0)) != 0) ||
       ((result = BCryptHashData(hHash, attestation.b.buffer, attestation.b.size, 0)) != 0) ||
       ((result = BCryptFinishHash(hHash, signatureDigest.t.buffer, signatureDigest.t.size, 0)) != 0))
    {
        goto Cleanup;
    }

    // Verify attestation signature
    if((result = BCryptVerifySignature(g_hAik,
        &padding,
        signatureDigest.t.buffer,
        signatureDigest.t.size,
        certifyCreationOut.signature.signature.rsassa.sig.t.buffer,
        certifyCreationOut.signature.signature.rsassa.sig.t.size,
        BCRYPT_PAD_PSS)) != 0)
    {
        goto Cleanup;
    }

    // Create the admin policy Session
    INITIALIZE_CALL_BUFFERS(TPM2_StartAuthSession, &startAuthSessionIn, &startAuthSessionOut);
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_TpmKey].obj.handle = TPM_RH_NULL;
    parms.objectTableIn[TPM2_StartAuthSession_HdlIn_Bind].obj.handle = TPM_RH_NULL;
    startAuthSessionIn.nonceCaller.t.size = CryptGenerateRandom(SHA256_DIGEST_SIZE, startAuthSessionIn.nonceCaller.t.buffer);
    startAuthSessionIn.sessionType = TPM_SE_POLICY;
    startAuthSessionIn.symmetric.algorithm = TPM_ALG_NULL;
    startAuthSessionIn.authHash = TPM_ALG_SHA256;
    EXECUTE_TPM_CALL(FALSE, TPM2_StartAuthSession);

    // Copy session back out
    policySession = parms.objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session;

    // Set the session up for admin certification
    INITIALIZE_CALL_BUFFERS(TPM2_PolicyCommandCode, &policyCommandCodeIn, &policyCommandCodeOut);
    parms.objectTableIn[TPM2_PolicyCommandCode_HdlIn_PolicySession].session = policySession;
    policyCommandCodeIn.code = TPM_CC_Certify;
    EXECUTE_TPM_CALL(FALSE, TPM2_PolicyCommandCode);
    policySession = parms.objectTableIn[TPM2_PolicyCommandCode_HdlIn_PolicySession].session;
    INITIALIZE_CALL_BUFFERS(TPM2_PolicyAuthValue, &policyAuthValueIn, &policyAuthValueOut);
    parms.objectTableIn[TPM2_PolicyAuthValue_HdlIn_PolicySession].session = policySession;
    EXECUTE_TPM_CALL(FALSE, TPM2_PolicyAuthValue);
    policySession = parms.objectTableIn[TPM2_PolicyCommandCode_HdlIn_PolicySession].session;
    INITIALIZE_CALL_BUFFERS(TPM2_PolicyOR, &policyORIn, &policyOROut);
    parms.objectTableIn[TPM2_PolicyCommandCode_HdlIn_PolicySession].session = policySession;
    policyORIn.pHashList = g_AdminPolicyHashList; // We are taking the previously stored policy list so we don't have to recalculate the entire policy
    EXECUTE_TPM_CALL(FALSE, TPM2_PolicyOR);
    policySession = parms.objectTableIn[TPM2_PolicyOR_HdlIn_PolicySession].session;

    // Put the sessions together
    sessionTable[0] = policySession;
    sessionTable[1].handle = TPM_RS_PW;

    // Create AIK signed certify structure
    INITIALIZE_CALL_BUFFERS(TPM2_Certify, &certifyIn, &certifyOut);
    parms.objectTableIn[TPM2_Certify_HdlIn_ObjectHandle] = g_KeyObject;
    parms.objectTableIn[TPM2_Certify_HdlIn_SignHandle] = g_AikObject;
    certifyIn.qualifyingData.t.size = sizeof(certifyNonce);
    MemoryCopy(certifyIn.qualifyingData.t.buffer, certifyNonce, sizeof(certifyNonce), sizeof(certifyIn.qualifyingData.t.buffer));
    certifyIn.inScheme.scheme = TPM_ALG_RSAPSS;
    certifyIn.inScheme.details.rsapss.hashAlg = TPM_ALG_SHA256;
    EXECUTE_TPM_CALL(FALSE, TPM2_Certify);

    // Get the attestation digest
    buffer = attestation.b.buffer;
    size = sizeof(attestation.t.attestationData);
    attestation.b.size = TPMS_ATTEST_Marshal(&certifyOut.certifyInfo.t.attestationData, &buffer, &size);
    signatureDigest.t.size = SHA256_DIGEST_SIZE;
    if(((result = BCryptCreateHash(g_hAlg[1], &hHash, NULL, 0, NULL, 0, 0)) != 0) ||
        ((result = BCryptHashData(hHash, attestation.b.buffer, attestation.b.size, 0)) != 0) ||
        ((result = BCryptFinishHash(hHash, signatureDigest.t.buffer, signatureDigest.t.size, 0)) != 0))
    {
        goto Cleanup;
    }

    // Verify attestation signature
    if((result = BCryptVerifySignature(g_hAik,
        &padding,
        signatureDigest.t.buffer,
        signatureDigest.t.size,
        certifyOut.signature.signature.rsassa.sig.t.buffer,
        certifyOut.signature.signature.rsassa.sig.t.size,
        BCRYPT_PAD_PSS)) != 0)
    {
        goto Cleanup;
    }

Cleanup:
    return result;
}

UINT32
TestPlatformAttestation()
{
    DEFINE_CALL_BUFFERS;
    UINT32 result = TPM_RC_SUCCESS;
    const char attestNonce[32] = "RandomServerPickedCertifyNonce.";
    TPM2B_ATTEST attestation = { 0 };
    BCRYPT_HASH_HANDLE hHash = NULL;
    TPM2B_DIGEST signatureDigest = { 0 };
    BCRYPT_PSS_PADDING_INFO padding = { BCRYPT_SHA256_ALGORITHM, (256 - 32 - 2) };
    Quote_In quoteIn = { 0 };
    Quote_Out quoteOut = { 0 };
    GetTime_In getTimeIn = { 0 };
    GetTime_Out getTimeOut = { 0 };

    // Create the session
    sessionTable[0].handle = TPM_RS_PW;

    // Create AIK signed quote structure
    INITIALIZE_CALL_BUFFERS(TPM2_Quote, &quoteIn, &quoteOut);
    parms.objectTableIn[TPM2_Quote_HdlIn_SignHandle] = g_AikObject;
    quoteIn.PCRselect.count = 1;
    quoteIn.PCRselect.pcrSelections[0].hash = TPM_ALG_SHA256;
    quoteIn.PCRselect.pcrSelections[0].sizeofSelect = 3;
    quoteIn.PCRselect.pcrSelections[0].pcrSelect[0] = 0xff;
    quoteIn.PCRselect.pcrSelections[0].pcrSelect[1] = 0xff;
    quoteIn.PCRselect.pcrSelections[0].pcrSelect[2] = 0x00;
    quoteIn.inScheme.scheme = TPM_ALG_RSAPSS;
    quoteIn.inScheme.details.rsapss.hashAlg = TPM_ALG_SHA256;
    quoteIn.qualifyingData.t.size = sizeof(attestNonce);
    MemoryCopy(quoteIn.qualifyingData.t.buffer, attestNonce, sizeof(attestNonce), sizeof(quoteIn.qualifyingData.t.buffer));
    EXECUTE_TPM_CALL(FALSE, TPM2_Quote);

    // Get the attestation digest
    buffer = attestation.b.buffer;
    size = sizeof(attestation.t.attestationData);
    attestation.b.size = TPMS_ATTEST_Marshal(&quoteOut.quoted.t.attestationData, &buffer, &size);
    signatureDigest.t.size = SHA256_DIGEST_SIZE;
    if (((result = BCryptCreateHash(g_hAlg[1], &hHash, NULL, 0, NULL, 0, 0)) != 0) ||
        ((result = BCryptHashData(hHash, attestation.b.buffer, attestation.b.size, 0)) != 0) ||
        ((result = BCryptFinishHash(hHash, signatureDigest.t.buffer, signatureDigest.t.size, 0)) != 0))
    {
        goto Cleanup;
    }

    // Verify attestation signature
    if ((result = BCryptVerifySignature(g_hAik,
        &padding,
        signatureDigest.t.buffer,
        signatureDigest.t.size,
        quoteOut.signature.signature.rsassa.sig.t.buffer,
        quoteOut.signature.signature.rsassa.sig.t.size,
        BCRYPT_PAD_PSS)) != 0)
    {
        goto Cleanup;
    }

    // Create the session
    sessionTable[0].handle = TPM_RS_PW;
    sessionTable[1].handle = TPM_RS_PW;

    // Create AIK signed GetTime structure
    INITIALIZE_CALL_BUFFERS(TPM2_GetTime, &getTimeIn, &getTimeOut);
    parms.objectTableIn[TPM2_GetTime_HdlIn_PrivacyAdminHandle] = g_Endorsement;
    parms.objectTableIn[TPM2_GetTime_HdlIn_SignHandle] = g_AikObject;
    getTimeIn.inScheme.scheme = TPM_ALG_RSAPSS;
    getTimeIn.inScheme.details.rsapss.hashAlg = TPM_ALG_SHA256;
    getTimeIn.qualifyingData.t.size = sizeof(attestNonce);
    MemoryCopy(getTimeIn.qualifyingData.t.buffer, attestNonce, sizeof(attestNonce), sizeof(getTimeIn.qualifyingData.t.buffer));
    EXECUTE_TPM_CALL(FALSE, TPM2_GetTime);

    // Get the attestation digest
    buffer = attestation.b.buffer;
    size = sizeof(attestation.t.attestationData);
    attestation.b.size = TPMS_ATTEST_Marshal(&getTimeOut.timeInfo.t.attestationData, &buffer, &size);
    signatureDigest.t.size = SHA256_DIGEST_SIZE;
    if (((result = BCryptCreateHash(g_hAlg[1], &hHash, NULL, 0, NULL, 0, 0)) != 0) ||
        ((result = BCryptHashData(hHash, attestation.b.buffer, attestation.b.size, 0)) != 0) ||
        ((result = BCryptFinishHash(hHash, signatureDigest.t.buffer, signatureDigest.t.size, 0)) != 0))
    {
        goto Cleanup;
    }

    // Verify attestation signature
    if ((result = BCryptVerifySignature(g_hAik,
        &padding,
        signatureDigest.t.buffer,
        signatureDigest.t.size,
        getTimeOut.signature.signature.rsassa.sig.t.buffer,
        getTimeOut.signature.signature.rsassa.sig.t.size,
        BCRYPT_PAD_PSS)) != 0)
    {
        goto Cleanup;
    }

Cleanup:
    return result;
}

int __cdecl wmain(int argc, WCHAR* argv[])
{
    UINT32 result = 0;

    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    _cpri__RngStartup();
    _cpri__HashStartup();
    _cpri__RsaStartup();
    _cpri__SymStartup();

	wprintf(L"---NOTE-----------------------------------------\n");
	wprintf(L"* This test has to run elevated in order to access the TPM authValues in the registry.\n");
    wprintf(L"* Not all TPMs may have the full set of ordinals and algorithms implemented, some tests may fail on certain TPMs.\n");
	wprintf(L"* For full functional test run with TPM 2.0 reference implementation simulator.\n");
	wprintf(L"---SETUP----------------------------------------\n");
    wprintf(L"RUNNING........CreateAuthorities()\r");
    result = CreateAuthorities();
    if(result) wprintf(L"(0x%08x)\n", result); else wprintf(L"PASS........\n");
    wprintf(L"RUNNING........CreateEkObject()\r");
    result = CreateEkObject();
    if(result) wprintf(L"(0x%08x)\n", result); else wprintf(L"PASS........\n");
    wprintf(L"RUNNING........CreateSrkObject()\r");
    result = CreateSrkObject();
    if(result) wprintf(L"(0x%08x)\n", result); else wprintf(L"PASS........\n");
    wprintf(L"RUNNING........CreateAndLoadAikObject()\r");
    result = CreateAndLoadAikObject();
    if(result) wprintf(L"(0x%08x)\n", result); else wprintf(L"PASS........\n");
    wprintf(L"RUNNING........CreateAndLoadKeyObject()\r");
    result = CreateAndLoadKeyObject();
    if(result) wprintf(L"(0x%08x)\n", result); else wprintf(L"PASS........\n");

    wprintf(L"\n---TESTS----------------------------------------\n");
    wprintf(L"RUNNING........TestGetCapability()\r");
    result = TestGetCapability();
    if(result) wprintf(L"(0x%08x)\n", result); else wprintf(L"PASS........\n");
    wprintf(L"RUNNING........TestGetEntropy()\r");
    result = TestGetEntropy();
    if (result) wprintf(L"(0x%08x)\n", result); else wprintf(L"PASS........\n");
    wprintf(L"RUNNING........TestPolicySession()\r");
    result = TestPolicySession();
    if(result) wprintf(L"(0x%08x)\n", result); else wprintf(L"PASS........\n");
    wprintf(L"RUNNING........TestSignWithPW()\r");
    result = TestSignWithPW();
    if(result) wprintf(L"(0x%08x)\n", result); else wprintf(L"PASS........\n");
    wprintf(L"RUNNING........TestSignHMAC()\r");
    result = TestSignHMAC();
    if(result) wprintf(L"(0x%08x)\n", result); else wprintf(L"PASS........\n");
    wprintf(L"RUNNING........TestSignBound()\r");
    result = TestSignBound();
    if(result) wprintf(L"(0x%08x)\n", result); else wprintf(L"PASS........\n");
    wprintf(L"RUNNING........TestSignSalted()\r");
    result = TestSignSalted();
    if(result) wprintf(L"(0x%08x)\n", result); else wprintf(L"PASS........\n");
    wprintf(L"RUNNING........TestSignSaltedAndBound()\r");
    result = TestSignSaltedAndBound();
    if(result) wprintf(L"(0x%08x)\n", result); else wprintf(L"PASS........\n");
    wprintf(L"RUNNING........TestSignParameterEncryption()\r");
    result = TestSignParameterEncryption();
    if(result) wprintf(L"(0x%08x)\n", result); else wprintf(L"PASS........\n");
    wprintf(L"RUNNING........TestSignParameterDecryption()\r");
    result = TestSignParameterDecryption();
    if(result) wprintf(L"(0x%08x)\n", result); else wprintf(L"PASS........\n");
    wprintf(L"RUNNING........TestReadPcrWithEkSeededSession()\r");
    result = TestReadPcrWithEkSeededSession();
    if(result) wprintf(L"(0x%08x)\n", result); else wprintf(L"PASS........\n");
    wprintf(L"RUNNING........TestCreateHashAndHMAC()\r");
    result = TestCreateHashAndHMAC();
    if (result) wprintf(L"(0x%08x)\n", result); else wprintf(L"PASS........\n");
    wprintf(L"RUNNING........TestCreateHashAndHMACSequence()\r");
    result = TestCreateHashAndHMACSequence();
    if (result) wprintf(L"(0x%08x)\n", result); else wprintf(L"PASS........\n");
    wprintf(L"RUNNING........TestSymKeyImport()\r");
    result = TestSymKeyImport();
    if(result) wprintf(L"(0x%08x)\n", result); else wprintf(L"PASS........\n");
    wprintf(L"RUNNING........TestRsaKeyImport()\r");
    result = TestRsaKeyImport();
    if(result) wprintf(L"(0x%08x)\n", result); else wprintf(L"PASS........\n");
    wprintf(L"RUNNING........TestCredentialActivation()\r");
    result = TestCredentialActivation();
    if(result) wprintf(L"(0x%08x)\n", result); else wprintf(L"PASS........\n");
    wprintf(L"RUNNING........TestKeyExport()\r");
    result = TestKeyExport();
    if(result) wprintf(L"(0x%08x)\n", result); else wprintf(L"PASS........\n");
    wprintf(L"RUNNING........TestSymEncryption()\r");
    result = TestSymEncryption();
    if(result) wprintf(L"(0x%08x)\n", result); else wprintf(L"PASS........\n");
    wprintf(L"RUNNING........TestCertifiedMigration()\r");
    result = TestCertifiedMigration();
    if(result) wprintf(L"(0x%08x)\n", result); else wprintf(L"PASS........\n");
    wprintf(L"RUNNING........TestNVIndexReadWrite()\r");
    result = TestNVIndexReadWrite();
    if(result) wprintf(L"(0x%08x)\n", result); else wprintf(L"PASS........\n");
    wprintf(L"RUNNING........TestVirtualization()\r");
    result = TestVirtualization();
    if(result) wprintf(L"(0x%08x)\n", result); else wprintf(L"PASS........\n");
    wprintf(L"RUNNING........TestObjectChangeAuth()\r");
    result = TestObjectChangeAuth();
    if(result) wprintf(L"(0x%08x)\n", result); else wprintf(L"PASS........\n");
    wprintf(L"RUNNING........TestUnseal()\r");
    result = TestUnseal();
    if(result) wprintf(L"(0x%08x)\n", result); else wprintf(L"PASS........\n");
    wprintf(L"RUNNING........TestDynamicPolicies()\r");
    result = TestDynamicPolicies();
    if(result) wprintf(L"(0x%08x)\n", result); else wprintf(L"PASS........\n");
    wprintf(L"RUNNING........TestRSADecrypt()\r");
    result = TestRSADecrypt();
    if(result) wprintf(L"(0x%08x)\n", result); else wprintf(L"PASS........\n");
    wprintf(L"RUNNING........TestECDSASign()\r");
    result = TestECDSASign();
    if(result) wprintf(L"(0x%08x)\n", result); else wprintf(L"PASS........\n");
    wprintf(L"RUNNING........TestKeyAttestation()\r");
    result = TestKeyAttestation();
    if(result) wprintf(L"(0x%08x)\n", result); else wprintf(L"PASS........\n");
    wprintf(L"RUNNING........TestPlatformAttestation()\r");
    result = TestPlatformAttestation();
    if (result) wprintf(L"(0x%08x)\n", result); else wprintf(L"PASS........\n");

    wprintf(L"\n---CLEANUP--------------------------------------\n");
    wprintf(L"RUNNING........UnloadKeyObjects()\r");
    result = UnloadKeyObjects();
    if(result) wprintf(L"(0x%08x)\n", result); else wprintf(L"PASS........\n");

    return result;
}

