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
TPM2B_TYPE(KEY, (sizeof(AUTH_VALUE)* 2));

UINT16
TPM2_StartAuthSession_Marshal(
    SESSION *sessionTable,
    UINT32 sessionCnt,
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
)
{
    StartAuthSession_In *in = (StartAuthSession_In *)parms->parmIn;
//    StartAuthSession_Out *out = (StartAuthSession_Out *)parms->parmOut;
    TPM_RC result = TPM_RC_SUCCESS;
    if((parms == NULL) ||
        (parms->objectCntIn < TPM2_StartAuthSession_HdlCntIn) ||
        (parms->objectCntOut < TPM2_StartAuthSession_HdlCntOut) ||
        (parms->parmIn == NULL) ||
        (parms->parmOut == NULL))
    {
        return TPM_RC_FAILURE;
    }
    // Encrypt the salt for salted sessions if not already provided
    if((parms->objectTableIn[0].generic.handle != TPM_RH_NULL) && (in->encryptedSalt.t.size == 0))
    {
        OBJECT key = {0};
        key.publicArea = parms->objectTableIn[TPM2_StartAuthSession_HdlIn_TpmKey].obj.publicArea.t.publicArea;
        in->encryptedSalt.t.size = sizeof(in->encryptedSalt.t.secret);
        result = CryptSecretEncrypt(&key, "SECRET", &in->salt, &in->encryptedSalt);
    }
    return Command_Marshal(
        TPM_CC_StartAuthSession,
        sessionTable,
        sessionCnt,
        TPM2_StartAuthSession_Parameter_Marshal,
        parms,
        buffer,
        size);
}

TPM_RC
TPM2_StartAuthSession_Unmarshal(
    SESSION *sessionTable,
    UINT32 sessionCnt,
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
)
{
    TPM_RC result = TPM_RC_SUCCESS;
    StartAuthSession_In *in = (StartAuthSession_In *)parms->parmIn;
    StartAuthSession_Out *out = (StartAuthSession_Out *)parms->parmOut;
    TPM2B_KEY key = {0};
    if((parms == NULL) ||
        (parms->objectCntIn < TPM2_StartAuthSession_HdlCntIn) ||
        (parms->objectCntOut < TPM2_StartAuthSession_HdlCntOut) ||
        (parms->parmIn == NULL) ||
        (parms->parmOut == NULL))
    {
        return TPM_RC_FAILURE;
    }
    if((result = Command_Unmarshal(
        TPM_CC_StartAuthSession,
        sessionTable,
        sessionCnt,
        TPM2_StartAuthSession_Parameter_Unmarshal,
        parms,
        buffer,
        size)) == TPM_RC_SUCCESS)
    {
        parms->objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session.nonceCaller = in->nonceCaller;
        parms->objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session.nonceTPM = out->nonceTPM;
        parms->objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session.authHashAlg = in->authHash;
        parms->objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session.symmetric = in->symmetric;
        parms->objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session.sessionAttributes.isAudit = CLEAR;
        parms->objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session.sessionAttributes.isAuthValueNeeded = CLEAR;
        parms->objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session.sessionAttributes.isBound = ((parms->objectTableIn[TPM2_StartAuthSession_HdlIn_Bind].generic.handle != TPM_RH_NULL) &&
                                                                                                               (in->sessionType == TPM_SE_HMAC));
        parms->objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session.sessionAttributes.iscpHashDefined = CLEAR;
        parms->objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session.sessionAttributes.isDaBound = ((parms->objectTableIn[TPM2_StartAuthSession_HdlIn_Bind].obj.handle != TPM_RH_NULL) &&
                                                                    (parms->objectTableIn[TPM2_StartAuthSession_HdlIn_Bind].obj.publicArea.t.publicArea.objectAttributes.noDA == SET));
        parms->objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session.sessionAttributes.isLockoutBound = (parms->objectTableIn[TPM2_StartAuthSession_HdlIn_Bind].obj.handle == TPM_RH_LOCKOUT);
        parms->objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session.sessionAttributes.isPasswordNeeded = (in->sessionType == TPM_SE_HMAC);
        parms->objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session.sessionAttributes.isPolicy = ((in->sessionType == TPM_SE_POLICY) ||
                                                                   (in->sessionType == TPM_SE_TRIAL));
        parms->objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session.sessionAttributes.isPPRequired = CLEAR;
        parms->objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session.sessionAttributes.isTrialPolicy = (in->sessionType == TPM_SE_TRIAL);
        parms->objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session.attributes.continueSession = SET;

        switch(in->authHash)
        {
#ifdef TPM_ALG_SHA1
        case TPM_ALG_SHA1:
            parms->objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session.u2.policyDigest.t.size = SHA1_DIGEST_SIZE;
            break;
#endif
#ifdef TPM_ALG_SHA256
        case TPM_ALG_SHA256:
            parms->objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session.u2.policyDigest.t.size = SHA256_DIGEST_SIZE;
            break;
#endif
#ifdef TPM_ALG_SHA384
        case TPM_ALG_SHA384:
            parms->objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session.u2.policyDigest.t.size = SHA384_DIGEST_SIZE;
            break;
#endif
#ifdef TPM_ALG_SHA512
        case TPM_ALG_SHA512:
            parms->objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session.u2.policyDigest.t.size = SHA512_DIGEST_SIZE;
            break;
#endif
        }

        // Extra stuff for bound and or salted sessions
        if(parms->objectTableIn[TPM2_StartAuthSession_HdlIn_Bind].obj.handle != TPM_RH_NULL) // Bound session
        {
            // Remember whom we are bound to
            parms->objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session.u1.boundEntity = parms->objectTableIn[TPM2_StartAuthSession_HdlIn_Bind].obj.name;

            // Add authValue of associated entity to key
            pAssert(key.t.size + parms->objectTableIn[TPM2_StartAuthSession_HdlIn_Bind].obj.authValue.t.size <= sizeof(key.t.buffer));
            MemoryConcat2B(&key.b, &parms->objectTableIn[TPM2_StartAuthSession_HdlIn_Bind].obj.authValue.b, sizeof(key.t.buffer));
            MemoryRemoveTrailingZeros((TPM2B_AUTH*)&key.b);
        }
        if(parms->objectTableIn[TPM2_StartAuthSession_HdlIn_TpmKey].obj.handle != TPM_RH_NULL) // Salted session
        {
            // Add salt to key
            pAssert(key.t.size + in->salt.t.size <= sizeof(key.t.buffer));
            MemoryConcat2B(&key.b, &in->salt.b, sizeof(key.t.buffer));
        }
        if((parms->objectTableIn[TPM2_StartAuthSession_HdlIn_Bind].obj.handle != TPM_RH_NULL) ||
            (parms->objectTableIn[TPM2_StartAuthSession_HdlIn_TpmKey].obj.handle != TPM_RH_NULL))
        {
            UINT16 hashSize;

            //  Calculate the shared secret for the bound session
            hashSize = CryptGetHashDigestSize(in->authHash);
            parms->objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session.sessionKey.t.size = hashSize;

            // Compute the session key
            KDFa(in->authHash,
                 &key.b,
                 "ATH",
                 &out->nonceTPM.b,
                 &in->nonceCaller.b,
                 hashSize * 8,
                 parms->objectTableOut[TPM2_StartAuthSession_HdlOut_SessionHandle].session.sessionKey.t.buffer,
                 (UINT32*)NULL);
        }
    }
    return result;
}

UINT16
TPM2_StartAuthSession_Parameter_Marshal(
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
)
{
    StartAuthSession_In *in = (StartAuthSession_In *)parms->parmIn;
//    StartAuthSession_Out *out = (StartAuthSession_Out *)parms->parmOut;
    UINT16 parameterSize = 0;

    // Marshal the parameters
    parameterSize += TPM2B_NONCE_Marshal(&in->nonceCaller, buffer, size);
    if (*size < 0) return TPM_RC_SIZE;
    parameterSize += TPM2B_ENCRYPTED_SECRET_Marshal(&in->encryptedSalt, buffer, size);
    if (*size < 0) return TPM_RC_SIZE;
    parameterSize += TPM_SE_Marshal(&in->sessionType, buffer, size);
    if (*size < 0) return TPM_RC_SIZE;
    parameterSize += TPMT_SYM_DEF_Marshal(&in->symmetric, buffer, size);
    if (*size < 0) return TPM_RC_SIZE;
    parameterSize += TPMI_ALG_HASH_Marshal(&in->authHash, buffer, size);
    if (*size < 0) return TPM_RC_SIZE;
    return parameterSize;
}

TPM_RC
TPM2_StartAuthSession_Parameter_Unmarshal(
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
)
{
//    StartAuthSession_In *in = (StartAuthSession_In *)parms->parmIn;
    StartAuthSession_Out *out = (StartAuthSession_Out *)parms->parmOut;
    TPM_RC result = TPM_RC_SUCCESS;

    // Unmarshal the parameters
    result = TPM2B_NONCE_Unmarshal(&out->nonceTPM, buffer, size);
    if (result != TPM_RC_SUCCESS) return result;

    return result;
}
