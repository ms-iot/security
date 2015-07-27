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

// This is the command code attribute structure.
    const ATTRIBUTE_TYPE s_commandAttributes [] = {
#if CC_NV_UndefineSpaceSpecial == YES        // 0x0000011F - TPM2_NV_UndefineSpaceSpecial
            IS_IMPLEMENTED + HANDLE_1_ADMIN + PP_COMMMAND + HANDLE_2_USER,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_EvictControl == YES                   // 0x00000120 - TPM2_EvictControl
            IS_IMPLEMENTED + PP_COMMMAND + HANDLE_1_USER,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_HierarchyControl == YES               // 0x00000121 - TPM2_HierarchyControl
            IS_IMPLEMENTED + PP_COMMMAND + HANDLE_1_USER,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_NV_UndefineSpace == YES               // 0x00000122 - TPM2_NV_UndefineSpace
            IS_IMPLEMENTED + PP_COMMMAND + HANDLE_1_USER,
#else
            NOT_IMPLEMENTED,               
#endif
            0,                              // 0x00000123
#if CC_ChangeEPS == YES                      // 0x00000124 - TPM2_ChangeEPS
            IS_IMPLEMENTED + PP_COMMMAND + HANDLE_1_USER,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_ChangePPS == YES                      // 0x00000125 - TPM2_ChangePPS
            IS_IMPLEMENTED + PP_COMMMAND + HANDLE_1_USER,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_Clear == YES                          // 0x00000126 - TPM2_Clear
            IS_IMPLEMENTED + PP_COMMMAND + HANDLE_1_USER,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_ClearControl == YES                   // 0x00000127 - TPM2_ClearControl
            IS_IMPLEMENTED + PP_COMMMAND + HANDLE_1_USER,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_ClockSet == YES                       // 0x00000128 - TPM2_ClockSet
            IS_IMPLEMENTED + PP_COMMMAND + HANDLE_1_USER,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_HierarchyChangeAuth == YES            // 0x00000129 - TPM2_HierarchyChangeAuth
            IS_IMPLEMENTED + PP_COMMMAND + HANDLE_1_USER + DECRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_NV_DefineSpace == YES                 // 0x0000012A - TPM2_NV_DefineSpace
            IS_IMPLEMENTED + PP_COMMMAND + HANDLE_1_USER + DECRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_PCR_Allocate == YES                   // 0x0000012B - TPM2_PCR_Allocate
            IS_IMPLEMENTED + PP_COMMMAND + HANDLE_1_USER,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_PCR_SetAuthPolicy == YES              // 0x0000012C - TPM2_PCR_SetAuthPolicy
            IS_IMPLEMENTED + PP_COMMMAND + HANDLE_1_USER + DECRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_PP_Commands == YES                    // 0x0000012D - TPM2_PP_Commands
            IS_IMPLEMENTED + PP_COMMMAND + HANDLE_1_USER,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_SetPrimaryPolicy == YES               // 0x0000012E - TPM2_SetPrimaryPolicy
            IS_IMPLEMENTED + PP_COMMMAND + HANDLE_1_USER + DECRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_FieldUpgradeStart == YES              // 0x0000012F - TPM2_FieldUpgradeStart
            IS_IMPLEMENTED + PP_COMMMAND + HANDLE_1_ADMIN + DECRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_ClockRateAdjust == YES                // 0x00000130 - TPM2_ClockRateAdjust
            IS_IMPLEMENTED + PP_COMMMAND + HANDLE_1_USER,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_CreatePrimary == YES                  // 0x00000131 - TPM2_CreatePrimary
            IS_IMPLEMENTED + PP_COMMMAND + HANDLE_1_USER + DECRYPT_2 + RESPONSE_HANDLE + ENCRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_NV_GlobalWriteLock == YES             // 0x00000132 - TPM2_NV_GlobalWriteLock
            IS_IMPLEMENTED + PP_COMMMAND + HANDLE_1_USER,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_GetCommandAuditDigest == YES          // 0x00000133 - TPM2_GetCommandAuditDigest
            IS_IMPLEMENTED + HANDLE_1_USER + HANDLE_2_USER + DECRYPT_2 + ENCRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_NV_Increment == YES                   // 0x00000134 - TPM2_NV_Increment
            IS_IMPLEMENTED + HANDLE_1_USER,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_NV_SetBits == YES                     // 0x00000135 - TPM2_NV_SetBits
            IS_IMPLEMENTED + HANDLE_1_USER,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_NV_Extend == YES                      // 0x00000136 - TPM2_NV_Extend
            IS_IMPLEMENTED + HANDLE_1_USER + DECRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_NV_Write == YES                       // 0x00000137 - TPM2_NV_Write
            IS_IMPLEMENTED + HANDLE_1_USER + DECRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_NV_WriteLock == YES                   // 0x00000138 - TPM2_NV_WriteLock
            IS_IMPLEMENTED + HANDLE_1_USER,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_DictionaryAttackLockReset == YES      // 0x00000139 - TPM2_DictionaryAttackLockReset
            IS_IMPLEMENTED + HANDLE_1_USER,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_DictionaryAttackParameters == YES     // 0x0000013A - TPM2_DictionaryAttackParameters
            IS_IMPLEMENTED + HANDLE_1_USER,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_NV_ChangeAuth == YES                  // 0x0000013B - TPM2_NV_ChangeAuth
            IS_IMPLEMENTED + HANDLE_1_ADMIN + DECRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_PCR_Event == YES                      // 0x0000013C - TPM2_PCR_Event
            IS_IMPLEMENTED + HANDLE_1_USER + DECRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_PCR_Reset == YES                      // 0x0000013D - TPM2_PCR_Reset
            IS_IMPLEMENTED + HANDLE_1_USER,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_SequenceComplete == YES               // 0x0000013E - TPM2_SequenceComplete
            IS_IMPLEMENTED + HANDLE_1_USER + DECRYPT_2 + ENCRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_SetAlgorithmSet == YES                // 0x0000013F - TPM2_SetAlgorithmSet
            IS_IMPLEMENTED + HANDLE_1_USER,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_SetCommandCodeAuditStatus == YES      // 0x00000140 - TPM2_SetCommandCodeAuditStatus
            IS_IMPLEMENTED + PP_COMMMAND + HANDLE_1_USER,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_FieldUpgradeData == YES               // 0x00000141 - TPM2_FieldUpgradeData
            IS_IMPLEMENTED + DECRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_IncrementalSelfTest == YES            // 0x00000142 - TPM2_IncrementalSelfTest
            IS_IMPLEMENTED,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_SelfTest == YES                       // 0x00000143 - TPM2_SelfTest
            IS_IMPLEMENTED,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_Startup == YES                        // 0x00000144 - TPM2_Startup
            IS_IMPLEMENTED + NO_SESSIONS,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_Shutdown == YES                       // 0x00000145 - TPM2_Shutdown
            IS_IMPLEMENTED,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_StirRandom == YES                     // 0x00000146 - TPM2_StirRandom
            IS_IMPLEMENTED + DECRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_ActivateCredential == YES             // 0x00000147 - TPM2_ActivateCredential
            IS_IMPLEMENTED + HANDLE_1_ADMIN + HANDLE_2_USER + DECRYPT_2 + ENCRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_Certify == YES                        // 0x00000148 - TPM2_Certify
            IS_IMPLEMENTED + HANDLE_1_ADMIN + HANDLE_2_USER + DECRYPT_2 + ENCRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_PolicyNV == YES                       // 0x00000149 - TPM2_PolicyNV
            IS_IMPLEMENTED + HANDLE_1_USER + DECRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_CertifyCreation == YES                // 0x0000014A - TPM2_CertifyCreation
            IS_IMPLEMENTED + HANDLE_1_USER + DECRYPT_2 + ENCRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_Duplicate == YES                      // 0x0000014B - TPM2_Duplicate
            IS_IMPLEMENTED + HANDLE_1_DUP + DECRYPT_2 + ENCRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_GetTime == YES                        // 0x0000014C - TPM2_GetTime
            IS_IMPLEMENTED + HANDLE_1_USER + HANDLE_2_USER + DECRYPT_2 + ENCRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_GetSessionAuditDigest == YES          // 0x0000014D - TPM2_GetSessionAuditDigest
            IS_IMPLEMENTED + HANDLE_1_USER + HANDLE_2_USER + DECRYPT_2 + ENCRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_NV_Read == YES                        // 0x0000014E - TPM2_NV_Read
            IS_IMPLEMENTED + HANDLE_1_USER + ENCRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_NV_ReadLock == YES                    // 0x0000014F - TPM2_NV_ReadLock
            IS_IMPLEMENTED + HANDLE_1_USER,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_ObjectChangeAuth == YES               // 0x00000150 - TPM2_ObjectChangeAuth
            IS_IMPLEMENTED + HANDLE_1_ADMIN + DECRYPT_2 + ENCRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_PolicySecret == YES                   // 0x00000151 - TPM2_PolicySecret
            IS_IMPLEMENTED + HANDLE_1_USER + DECRYPT_2 + ENCRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_Rewrap == YES                         // 0x00000152 - TPM2_Rewrap
            IS_IMPLEMENTED + HANDLE_1_USER + DECRYPT_2 + ENCRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_Create == YES                         // 0x00000153 - TPM2_Create
            IS_IMPLEMENTED + HANDLE_1_USER + DECRYPT_2 + ENCRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_ECDH_ZGen == YES                      // 0x00000154 - TPM2_ECDH_ZGen
            IS_IMPLEMENTED + HANDLE_1_USER + DECRYPT_2 + ENCRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_HMAC == YES                           // 0x00000155 - TPM2_HMAC
            IS_IMPLEMENTED + HANDLE_1_USER + DECRYPT_2 + ENCRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_Import == YES                         // 0x00000156 - TPM2_Import
            IS_IMPLEMENTED + HANDLE_1_USER + DECRYPT_2 + ENCRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_Load == YES                           // 0x00000157 - TPM2_Load
            IS_IMPLEMENTED + HANDLE_1_USER + DECRYPT_2 + RESPONSE_HANDLE + ENCRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_Quote == YES                          // 0x00000158 - TPM2_Quote
            IS_IMPLEMENTED + HANDLE_1_USER + DECRYPT_2 + ENCRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_RSA_Decrypt == YES                    // 0x00000159 - TPM2_RSA_Decrypt
            IS_IMPLEMENTED + HANDLE_1_USER + DECRYPT_2 + ENCRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
            0,                              // 0x0000015A
#if CC_HMAC_Start == YES                     // 0x0000015B - TPM2_HMAC_Start
            IS_IMPLEMENTED + HANDLE_1_USER + DECRYPT_2 + RESPONSE_HANDLE,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_SequenceUpdate == YES                 // 0x0000015C - TPM2_SequenceUpdate
            IS_IMPLEMENTED + HANDLE_1_USER + DECRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_Sign == YES                           // 0x0000015D - TPM2_Sign
            IS_IMPLEMENTED + HANDLE_1_USER + DECRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_Unseal == YES                         // 0x0000015E - TPM2_Unseal
            IS_IMPLEMENTED + HANDLE_1_USER + ENCRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
            0,                              // 0x0000015F
#if CC_PolicySigned == YES                   // 0x00000160 - TPM2_PolicySigned
            IS_IMPLEMENTED + DECRYPT_2 + ENCRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_ContextLoad == YES                    // 0x00000161 - TPM2_ContextLoad
            IS_IMPLEMENTED + NO_SESSIONS + RESPONSE_HANDLE,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_ContextSave == YES                    // 0x00000162 - TPM2_ContextSave
            IS_IMPLEMENTED + NO_SESSIONS,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_ECDH_KeyGen == YES                    // 0x00000163 - TPM2_ECDH_KeyGen
            IS_IMPLEMENTED + ENCRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_EncryptDecrypt == YES                 // 0x00000164 - TPM2_EncryptDecrypt
            IS_IMPLEMENTED + HANDLE_1_USER + ENCRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_FlushContext == YES                   // 0x00000165 - TPM2_FlushContext
            IS_IMPLEMENTED + NO_SESSIONS,
#else
            NOT_IMPLEMENTED,               
#endif
            0,                              // 0x00000166
#if CC_LoadExternal == YES                   // 0x00000167 - TPM2_LoadExternal
            IS_IMPLEMENTED + DECRYPT_2 + RESPONSE_HANDLE + ENCRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_MakeCredential == YES                 // 0x00000168 - TPM2_MakeCredential
            IS_IMPLEMENTED + DECRYPT_2 + ENCRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_NV_ReadPublic == YES                  // 0x00000169 - TPM2_NV_ReadPublic
            IS_IMPLEMENTED + ENCRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_PolicyAuthorize == YES                // 0x0000016A - TPM2_PolicyAuthorize
            IS_IMPLEMENTED + DECRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_PolicyAuthValue == YES                // 0x0000016B - TPM2_PolicyAuthValue
            IS_IMPLEMENTED,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_PolicyCommandCode == YES              // 0x0000016C - TPM2_PolicyCommandCode
            IS_IMPLEMENTED,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_PolicyCounterTimer == YES             // 0x0000016D - TPM2_PolicyCounterTimer
            IS_IMPLEMENTED + DECRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_PolicyCpHash == YES                   // 0x0000016E - TPM2_PolicyCpHash
            IS_IMPLEMENTED + DECRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_PolicyLocality == YES                 // 0x0000016F - TPM2_PolicyLocality
            IS_IMPLEMENTED,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_PolicyNameHash == YES                 // 0x00000170 - TPM2_PolicyNameHash
            IS_IMPLEMENTED + DECRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_PolicyOR == YES                       // 0x00000171 - TPM2_PolicyOR
            IS_IMPLEMENTED,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_PolicyTicket == YES                   // 0x00000172 - TPM2_PolicyTicket
            IS_IMPLEMENTED + DECRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_ReadPublic == YES                     // 0x00000173 - TPM2_ReadPublic
            IS_IMPLEMENTED + ENCRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_RSA_Encrypt == YES                    // 0x00000174 - TPM2_RSA_Encrypt
            IS_IMPLEMENTED + DECRYPT_2 + ENCRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
            0,                              // 0x00000175
#if CC_StartAuthSession == YES               // 0x00000176 - TPM2_StartAuthSession
            IS_IMPLEMENTED + DECRYPT_2 + RESPONSE_HANDLE + ENCRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_VerifySignature == YES                // 0x00000177 - TPM2_VerifySignature
            IS_IMPLEMENTED + DECRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_ECC_Parameters == YES                 // 0x00000178 - TPM2_ECC_Parameters
            IS_IMPLEMENTED,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_FirmwareRead == YES                   // 0x00000179 - TPM2_FirmwareRead
            IS_IMPLEMENTED + ENCRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_GetCapability == YES                  // 0x0000017A - TPM2_GetCapability
            IS_IMPLEMENTED,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_GetRandom == YES                      // 0x0000017B - TPM2_GetRandom
            IS_IMPLEMENTED + ENCRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_GetTestResult == YES                  // 0x0000017C - TPM2_GetTestResult
            IS_IMPLEMENTED + ENCRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_Hash == YES                           // 0x0000017D - TPM2_Hash
            IS_IMPLEMENTED + DECRYPT_2 + ENCRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_PCR_Read == YES                       // 0x0000017E - TPM2_PCR_Read
            IS_IMPLEMENTED,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_PolicyPCR == YES                      // 0x0000017F - TPM2_PolicyPCR
            IS_IMPLEMENTED + DECRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_PolicyRestart == YES                  // 0x00000180 - TPM2_PolicyRestart
            IS_IMPLEMENTED,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_ReadClock == YES                      // 0x00000181 - TPM2_ReadClock
            IS_IMPLEMENTED + NO_SESSIONS,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_PCR_Extend == YES                     // 0x00000182 - TPM2_PCR_Extend
            IS_IMPLEMENTED + HANDLE_1_USER,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_PCR_SetAuthValue == YES               // 0x00000183 - TPM2_PCR_SetAuthValue
            IS_IMPLEMENTED + HANDLE_1_USER + DECRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_NV_Certify == YES                     // 0x00000184 - TPM2_NV_Certify
            IS_IMPLEMENTED + HANDLE_1_USER + HANDLE_2_USER + DECRYPT_2 + ENCRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_EventSequenceComplete == YES          // 0x00000185 - TPM2_EventSequenceComplete
            IS_IMPLEMENTED + HANDLE_1_USER + HANDLE_2_USER + DECRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_HashSequenceStart == YES              // 0x00000186 - TPM2_HashSequenceStart
            IS_IMPLEMENTED + DECRYPT_2 + RESPONSE_HANDLE,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_PolicyPhysicalPresence == YES         // 0x00000187 - TPM2_PolicyPhysicalPresence
            IS_IMPLEMENTED,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_PolicyDuplicationSelect == YES        // 0x00000188 - TPM2_PolicyDuplicationSelect
            IS_IMPLEMENTED + DECRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_PolicyGetDigest == YES                // 0x00000189 - TPM2_PolicyGetDigest
            IS_IMPLEMENTED + ENCRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_TestParms == YES                      // 0x0000018A - TPM2_TestParms
            IS_IMPLEMENTED,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_Commit == YES                         // 0x0000018B - TPM2_Commit
            IS_IMPLEMENTED + HANDLE_1_USER + DECRYPT_2 + ENCRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_PolicyPassword == YES                 // 0x0000018C - TPM2_PolicyPassword
            IS_IMPLEMENTED,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_ZGen_2Phase == YES                    // 0x0000018D - TPM2_ZGen_2Phase
            IS_IMPLEMENTED + HANDLE_1_USER + DECRYPT_2 + ENCRYPT_2,
#else
            NOT_IMPLEMENTED,               
#endif
#if CC_EC_Ephemeral == YES                   // 0x0000018E - TPM2_EC_Ephemeral
            IS_IMPLEMENTED + ENCRYPT_2 
#else
            NOT_IMPLEMENTED                
#endif
};

// This is the command code attribute array for GetCapability.
// Both this array and s_commandAttributes provides command code attributes,
// but tuned for different purpose
    static const TPMA_CC    s_ccAttr [] = {
#if CC_Startup == YES
           {(UINT16) TPM_CC_Startup, 0, 1, 0, 0, 0, 0, 0, 0},                       // Nv 
#endif
#if CC_Shutdown == YES
           {(UINT16) TPM_CC_Shutdown, 0, 1, 0, 0, 0, 0, 0, 0},                      // Nv 
#endif
#if CC_SelfTest == YES
           {(UINT16) TPM_CC_SelfTest, 0, 1, 0, 0, 0, 0, 0, 0},                      // Nv 
#endif
#if CC_IncrementalSelfTest == YES
           {(UINT16) TPM_CC_IncrementalSelfTest, 0, 1, 0, 0, 0, 0, 0, 0},           // Nv 
#endif
#if CC_GetTestResult == YES
           {(UINT16) TPM_CC_GetTestResult, 0, 0, 0, 0, 0, 0, 0, 0}, 
#endif
#if CC_StartAuthSession == YES
           {(UINT16) TPM_CC_StartAuthSession, 0, 0, 0, 0, 2, 1, 0, 0}, 
#endif
#if CC_PolicyRestart == YES
           {(UINT16) TPM_CC_PolicyRestart, 0, 0, 0, 0, 1, 0, 0, 0}, 
#endif
#if CC_Create == YES
           {(UINT16) TPM_CC_Create, 0, 0, 0, 0, 1, 0, 0, 0}, 
#endif
#if CC_Load == YES
           {(UINT16) TPM_CC_Load, 0, 0, 0, 0, 1, 1, 0, 0}, 
#endif
#if CC_LoadExternal == YES
           {(UINT16) TPM_CC_LoadExternal, 0, 0, 0, 0, 0, 1, 0, 0}, 
#endif
#if CC_ReadPublic == YES
           {(UINT16) TPM_CC_ReadPublic, 0, 0, 0, 0, 1, 0, 0, 0}, 
#endif
#if CC_ActivateCredential == YES
           {(UINT16) TPM_CC_ActivateCredential, 0, 0, 0, 0, 2, 0, 0, 0}, 
#endif
#if CC_MakeCredential == YES
           {(UINT16) TPM_CC_MakeCredential, 0, 0, 0, 0, 1, 0, 0, 0}, 
#endif
#if CC_Unseal == YES
           {(UINT16) TPM_CC_Unseal, 0, 0, 0, 0, 1, 0, 0, 0}, 
#endif
#if CC_ObjectChangeAuth == YES
           {(UINT16) TPM_CC_ObjectChangeAuth, 0, 0, 0, 0, 2, 0, 0, 0}, 
#endif
#if CC_Duplicate == YES
           {(UINT16) TPM_CC_Duplicate, 0, 0, 0, 0, 2, 0, 0, 0}, 
#endif
#if CC_Rewrap == YES
           {(UINT16) TPM_CC_Rewrap, 0, 0, 0, 0, 2, 0, 0, 0}, 
#endif
#if CC_Import == YES
           {(UINT16) TPM_CC_Import, 0, 0, 0, 0, 1, 0, 0, 0}, 
#endif
#if CC_RSA_Encrypt == YES
           {(UINT16) TPM_CC_RSA_Encrypt, 0, 0, 0, 0, 1, 0, 0, 0}, 
#endif
#if CC_RSA_Decrypt == YES
           {(UINT16) TPM_CC_RSA_Decrypt, 0, 0, 0, 0, 1, 0, 0, 0}, 
#endif
#if CC_ECDH_KeyGen == YES
           {(UINT16) TPM_CC_ECDH_KeyGen, 0, 0, 0, 0, 1, 0, 0, 0}, 
#endif
#if CC_ECDH_ZGen == YES
           {(UINT16) TPM_CC_ECDH_ZGen, 0, 0, 0, 0, 1, 0, 0, 0}, 
#endif
#if CC_ECC_Parameters == YES
           {(UINT16) TPM_CC_ECC_Parameters, 0, 0, 0, 0, 0, 0, 0, 0}, 
#endif
#if CC_ZGen_2Phase == YES
           {(UINT16) TPM_CC_ZGen_2Phase, 0, 0, 0, 0, 1, 0, 0, 0}, 
#endif
#if CC_EncryptDecrypt == YES
           {(UINT16) TPM_CC_EncryptDecrypt, 0, 0, 0, 0, 1, 0, 0, 0}, 
#endif
#if CC_Hash == YES
           {(UINT16) TPM_CC_Hash, 0, 0, 0, 0, 0, 0, 0, 0}, 
#endif
#if CC_HMAC == YES
           {(UINT16) TPM_CC_HMAC, 0, 0, 0, 0, 1, 0, 0, 0}, 
#endif
#if CC_GetRandom == YES
           {(UINT16) TPM_CC_GetRandom, 0, 0, 0, 0, 0, 0, 0, 0}, 
#endif
#if CC_StirRandom == YES
           {(UINT16) TPM_CC_StirRandom, 0, 1, 0, 0, 0, 0, 0, 0},                    // Nv 
#endif
#if CC_HMAC_Start == YES
           {(UINT16) TPM_CC_HMAC_Start, 0, 0, 0, 0, 1, 1, 0, 0}, 
#endif
#if CC_HashSequenceStart == YES
           {(UINT16) TPM_CC_HashSequenceStart, 0, 0, 0, 0, 0, 1, 0, 0}, 
#endif
#if CC_SequenceUpdate == YES
           {(UINT16) TPM_CC_SequenceUpdate, 0, 0, 0, 0, 1, 0, 0, 0}, 
#endif
#if CC_SequenceComplete == YES
           {(UINT16) TPM_CC_SequenceComplete, 0, 0, 0, 1, 1, 0, 0, 0},              // Flushed 
#endif
#if CC_EventSequenceComplete == YES
           {(UINT16) TPM_CC_EventSequenceComplete, 0, 1, 0, 1, 2, 0, 0, 0},         // Nv Flushed 
#endif
#if CC_Certify == YES
           {(UINT16) TPM_CC_Certify, 0, 0, 0, 0, 2, 0, 0, 0}, 
#endif
#if CC_CertifyCreation == YES
           {(UINT16) TPM_CC_CertifyCreation, 0, 0, 0, 0, 2, 0, 0, 0}, 
#endif
#if CC_Quote == YES
           {(UINT16) TPM_CC_Quote, 0, 0, 0, 0, 1, 0, 0, 0}, 
#endif
#if CC_GetSessionAuditDigest == YES
           {(UINT16) TPM_CC_GetSessionAuditDigest, 0, 0, 0, 0, 3, 0, 0, 0}, 
#endif
#if CC_GetCommandAuditDigest == YES
           {(UINT16) TPM_CC_GetCommandAuditDigest, 0, 1, 0, 0, 2, 0, 0, 0},         // Nv 
#endif
#if CC_GetTime == YES
           {(UINT16) TPM_CC_GetTime, 0, 0, 0, 0, 2, 0, 0, 0}, 
#endif
#if CC_Commit == YES
           {(UINT16) TPM_CC_Commit, 0, 0, 0, 0, 1, 0, 0, 0}, 
#endif
#if CC_EC_Ephemeral == YES
           {(UINT16) TPM_CC_EC_Ephemeral, 0, 0, 0, 0, 0, 0, 0, 0}, 
#endif
#if CC_VerifySignature == YES
           {(UINT16) TPM_CC_VerifySignature, 0, 0, 0, 0, 1, 0, 0, 0}, 
#endif
#if CC_Sign == YES
           {(UINT16) TPM_CC_Sign, 0, 0, 0, 0, 1, 0, 0, 0}, 
#endif
#if CC_SetCommandCodeAuditStatus == YES
           {(UINT16) TPM_CC_SetCommandCodeAuditStatus, 0, 1, 0, 0, 1, 0, 0, 0},     // Nv 
#endif
#if CC_PCR_Extend == YES
           {(UINT16) TPM_CC_PCR_Extend, 0, 1, 0, 0, 1, 0, 0, 0},                    // Nv 
#endif
#if CC_PCR_Event == YES
           {(UINT16) TPM_CC_PCR_Event, 0, 1, 0, 0, 1, 0, 0, 0},                     // Nv 
#endif
#if CC_PCR_Read == YES
           {(UINT16) TPM_CC_PCR_Read, 0, 0, 0, 0, 0, 0, 0, 0}, 
#endif
#if CC_PCR_Allocate == YES
           {(UINT16) TPM_CC_PCR_Allocate, 0, 1, 0, 0, 1, 0, 0, 0},                  // Nv 
#endif
#if CC_PCR_SetAuthPolicy == YES
           {(UINT16) TPM_CC_PCR_SetAuthPolicy, 0, 1, 0, 0, 1, 0, 0, 0},             // Nv 
#endif
#if CC_PCR_SetAuthValue == YES
           {(UINT16) TPM_CC_PCR_SetAuthValue, 0, 0, 0, 0, 1, 0, 0, 0}, 
#endif
#if CC_PCR_Reset == YES
           {(UINT16) TPM_CC_PCR_Reset, 0, 1, 0, 0, 1, 0, 0, 0},                     // Nv 
#endif
#if CC_PolicySigned == YES
           {(UINT16) TPM_CC_PolicySigned, 0, 0, 0, 0, 2, 0, 0, 0}, 
#endif
#if CC_PolicySecret == YES
           {(UINT16) TPM_CC_PolicySecret, 0, 0, 0, 0, 2, 0, 0, 0}, 
#endif
#if CC_PolicyTicket == YES
           {(UINT16) TPM_CC_PolicyTicket, 0, 0, 0, 0, 1, 0, 0, 0}, 
#endif
#if CC_PolicyOR == YES
           {(UINT16) TPM_CC_PolicyOR, 0, 0, 0, 0, 1, 0, 0, 0}, 
#endif
#if CC_PolicyPCR == YES
           {(UINT16) TPM_CC_PolicyPCR, 0, 0, 0, 0, 1, 0, 0, 0}, 
#endif
#if CC_PolicyLocality == YES
           {(UINT16) TPM_CC_PolicyLocality, 0, 0, 0, 0, 1, 0, 0, 0}, 
#endif
#if CC_PolicyNV == YES
           {(UINT16) TPM_CC_PolicyNV, 0, 0, 0, 0, 3, 0, 0, 0}, 
#endif
#if CC_PolicyCounterTimer == YES
           {(UINT16) TPM_CC_PolicyCounterTimer, 0, 0, 0, 0, 1, 0, 0, 0}, 
#endif
#if CC_PolicyCommandCode == YES
           {(UINT16) TPM_CC_PolicyCommandCode, 0, 0, 0, 0, 1, 0, 0, 0}, 
#endif
#if CC_PolicyPhysicalPresence == YES
           {(UINT16) TPM_CC_PolicyPhysicalPresence, 0, 0, 0, 0, 1, 0, 0, 0}, 
#endif
#if CC_PolicyCpHash == YES
           {(UINT16) TPM_CC_PolicyCpHash, 0, 0, 0, 0, 1, 0, 0, 0}, 
#endif
#if CC_PolicyNameHash == YES
           {(UINT16) TPM_CC_PolicyNameHash, 0, 0, 0, 0, 1, 0, 0, 0}, 
#endif
#if CC_PolicyDuplicationSelect == YES
           {(UINT16) TPM_CC_PolicyDuplicationSelect, 0, 0, 0, 0, 1, 0, 0, 0}, 
#endif
#if CC_PolicyAuthorize == YES
           {(UINT16) TPM_CC_PolicyAuthorize, 0, 0, 0, 0, 1, 0, 0, 0}, 
#endif
#if CC_PolicyAuthValue == YES
           {(UINT16) TPM_CC_PolicyAuthValue, 0, 0, 0, 0, 1, 0, 0, 0}, 
#endif
#if CC_PolicyPassword == YES
           {(UINT16) TPM_CC_PolicyPassword, 0, 0, 0, 0, 1, 0, 0, 0}, 
#endif
#if CC_PolicyGetDigest == YES
           {(UINT16) TPM_CC_PolicyGetDigest, 0, 0, 0, 0, 1, 0, 0, 0}, 
#endif
#if CC_CreatePrimary == YES
           {(UINT16) TPM_CC_CreatePrimary, 0, 0, 0, 0, 1, 1, 0, 0}, 
#endif
#if CC_HierarchyControl == YES
           {(UINT16) TPM_CC_HierarchyControl, 0, 1, 1, 0, 1, 0, 0, 0},              // Nv Extensive 
#endif
#if CC_SetPrimaryPolicy == YES
           {(UINT16) TPM_CC_SetPrimaryPolicy, 0, 1, 0, 0, 1, 0, 0, 0},              // Nv 
#endif
#if CC_ChangePPS == YES
           {(UINT16) TPM_CC_ChangePPS, 0, 1, 1, 0, 1, 0, 0, 0},                     // Nv Extensive 
#endif
#if CC_ChangeEPS == YES
           {(UINT16) TPM_CC_ChangeEPS, 0, 1, 1, 0, 1, 0, 0, 0},                     // Nv Extensive 
#endif
#if CC_Clear == YES
           {(UINT16) TPM_CC_Clear, 0, 1, 1, 0, 1, 0, 0, 0},                         // Nv Extensive 
#endif
#if CC_ClearControl == YES
           {(UINT16) TPM_CC_ClearControl, 0, 1, 0, 0, 1, 0, 0, 0},                  // Nv 
#endif
#if CC_HierarchyChangeAuth == YES
           {(UINT16) TPM_CC_HierarchyChangeAuth, 0, 1, 0, 0, 1, 0, 0, 0},           // Nv 
#endif
#if CC_DictionaryAttackLockReset == YES
           {(UINT16) TPM_CC_DictionaryAttackLockReset, 0, 1, 0, 0, 1, 0, 0, 0},     // Nv 
#endif
#if CC_DictionaryAttackParameters == YES
           {(UINT16) TPM_CC_DictionaryAttackParameters, 0, 1, 0, 0, 1, 0, 0, 0},    // Nv 
#endif
#if CC_PP_Commands == YES
           {(UINT16) TPM_CC_PP_Commands, 0, 1, 0, 0, 1, 0, 0, 0},                   // Nv 
#endif
#if CC_SetAlgorithmSet == YES
           {(UINT16) TPM_CC_SetAlgorithmSet, 0, 1, 0, 0, 1, 0, 0, 0},               // Nv 
#endif
#if CC_FieldUpgradeStart == YES
           {(UINT16) TPM_CC_FieldUpgradeStart, 0, 0, 0, 0, 2, 0, 0, 0}, 
#endif
#if CC_FieldUpgradeData == YES
           {(UINT16) TPM_CC_FieldUpgradeData, 0, 1, 0, 0, 0, 0, 0, 0},              // Nv 
#endif
#if CC_FirmwareRead == YES
           {(UINT16) TPM_CC_FirmwareRead, 0, 0, 0, 0, 0, 0, 0, 0}, 
#endif
#if CC_ContextSave == YES
           {(UINT16) TPM_CC_ContextSave, 0, 0, 0, 0, 1, 0, 0, 0}, 
#endif
#if CC_ContextLoad == YES
           {(UINT16) TPM_CC_ContextLoad, 0, 0, 0, 0, 0, 1, 0, 0}, 
#endif
#if CC_FlushContext == YES
           {(UINT16) TPM_CC_FlushContext, 0, 0, 0, 0, 0, 0, 0, 0}, 
#endif
#if CC_EvictControl == YES
           {(UINT16) TPM_CC_EvictControl, 0, 1, 0, 0, 2, 0, 0, 0},                  // Nv 
#endif
#if CC_ReadClock == YES
           {(UINT16) TPM_CC_ReadClock, 0, 0, 0, 0, 0, 0, 0, 0}, 
#endif
#if CC_ClockSet == YES
           {(UINT16) TPM_CC_ClockSet, 0, 1, 0, 0, 1, 0, 0, 0},                      // Nv 
#endif
#if CC_ClockRateAdjust == YES
           {(UINT16) TPM_CC_ClockRateAdjust, 0, 0, 0, 0, 1, 0, 0, 0}, 
#endif
#if CC_GetCapability == YES
           {(UINT16) TPM_CC_GetCapability, 0, 0, 0, 0, 0, 0, 0, 0}, 
#endif
#if CC_TestParms == YES
           {(UINT16) TPM_CC_TestParms, 0, 0, 0, 0, 0, 0, 0, 0}, 
#endif
#if CC_NV_DefineSpace == YES
           {(UINT16) TPM_CC_NV_DefineSpace, 0, 1, 0, 0, 1, 0, 0, 0},                // Nv 
#endif
#if CC_NV_UndefineSpace == YES
           {(UINT16) TPM_CC_NV_UndefineSpace, 0, 1, 0, 0, 2, 0, 0, 0},              // Nv 
#endif
#if CC_NV_UndefineSpaceSpecial == YES
           {(UINT16) TPM_CC_NV_UndefineSpaceSpecial, 0, 1, 0, 0, 2, 0, 0, 0},       // Nv 
#endif
#if CC_NV_ReadPublic == YES
           {(UINT16) TPM_CC_NV_ReadPublic, 0, 0, 0, 0, 1, 0, 0, 0}, 
#endif
#if CC_NV_Write == YES
           {(UINT16) TPM_CC_NV_Write, 0, 1, 0, 0, 2, 0, 0, 0},                      // Nv 
#endif
#if CC_NV_Increment == YES
           {(UINT16) TPM_CC_NV_Increment, 0, 1, 0, 0, 2, 0, 0, 0},                  // Nv 
#endif
#if CC_NV_Extend == YES
           {(UINT16) TPM_CC_NV_Extend, 0, 1, 0, 0, 2, 0, 0, 0},                     // Nv 
#endif
#if CC_NV_SetBits == YES
           {(UINT16) TPM_CC_NV_SetBits, 0, 1, 0, 0, 2, 0, 0, 0},                    // Nv 
#endif
#if CC_NV_WriteLock == YES
           {(UINT16) TPM_CC_NV_WriteLock, 0, 1, 0, 0, 2, 0, 0, 0},                  // Nv 
#endif
#if CC_NV_GlobalWriteLock == YES
           {(UINT16) TPM_CC_NV_GlobalWriteLock, 0, 0, 0, 0, 1, 0, 0, 0}, 
#endif
#if CC_NV_Read == YES
           {(UINT16) TPM_CC_NV_Read, 0, 0, 0, 0, 2, 0, 0, 0}, 
#endif
#if CC_NV_ReadLock == YES
           {(UINT16) TPM_CC_NV_ReadLock, 0, 0, 0, 0, 2, 0, 0, 0}, 
#endif
#if CC_NV_ChangeAuth == YES
           {(UINT16) TPM_CC_NV_ChangeAuth, 0, 1, 0, 0, 1, 0, 0, 0},                 // Nv 
#endif
#if CC_NV_Certify == YES
           {(UINT16) TPM_CC_NV_Certify, 0, 0, 0, 0, 3, 0, 0, 0}, 
#endif
};
