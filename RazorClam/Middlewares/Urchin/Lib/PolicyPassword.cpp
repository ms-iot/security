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

UINT16
TPM2_PolicyPassword_Marshal(
    SESSION *sessionTable,
    UINT32 sessionCnt,
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
)
{
    if((parms == NULL) ||
       (parms->objectCntIn < TPM2_PolicyPassword_HdlCntIn) ||
//       (parms->objectCntOut < TPM2_PolicyPassword_HdlCntOut) ||
       (parms->parmIn == NULL) ||
       (parms->parmOut == NULL))
    {
        return TPM_RC_FAILURE;
    }
    return Command_Marshal(
        TPM_CC_PolicyPassword,
        sessionTable,
        sessionCnt,
        TPM2_PolicyPassword_Parameter_Marshal,
        parms,
        buffer,
        size);
}

TPM_RC
TPM2_PolicyPassword_Unmarshal(
    SESSION *sessionTable,
    UINT32 sessionCnt,
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
)
{
    TPM_RC result = TPM_RC_SUCCESS;
    PolicyPassword_In *in = (PolicyPassword_In *)parms->parmIn;
//    PolicyPassword_Out *out = (PolicyPassword_Out *)parms->parmOut;

    if((parms == NULL) ||
       (parms->objectCntIn < TPM2_PolicyPassword_HdlCntIn) ||
//       (parms->objectCntOut < TPM2_PolicyPassword_HdlCntOut) ||
       (parms->parmIn == NULL) ||
       (parms->parmOut == NULL))
    {
        return TPM_RC_FAILURE;
    }
    if((result = Command_Unmarshal(
        TPM_CC_PolicyPassword,
        sessionTable,
        sessionCnt,
        TPM2_PolicyPassword_Parameter_Unmarshal,
        parms,
        buffer,
        size)) == TPM_RC_SUCCESS)
    {
        TPM2_PolicyPassword_CalculateUpdate(parms->objectTableIn[TPM2_PolicyPassword_HdlIn_PolicySession].session.authHashAlg,
                                                &parms->objectTableIn[TPM2_PolicyPassword_HdlIn_PolicySession].session.u2.policyDigest,
                                                in);
        parms->objectTableIn[TPM2_PolicyPassword_HdlIn_PolicySession].session.sessionAttributes.isPasswordNeeded = SET;
        parms->objectTableIn[TPM2_PolicyPassword_HdlIn_PolicySession].session.sessionAttributes.isAuthValueNeeded = CLEAR;
    }
    return result;
}

UINT16
TPM2_PolicyPassword_Parameter_Marshal(
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
)
{
//    PolicyPassword_In *in = (PolicyPassword_In *)parms->parmIn;
//    PolicyPassword_Out *out = (PolicyPassword_Out *)parms->parmOut;
    UINT16 parameterSize = 0;

    UNREFERENCED_PARAMETER(parms);
    UNREFERENCED_PARAMETER(buffer);
    UNREFERENCED_PARAMETER(size);

    return parameterSize;
}

TPM_RC
TPM2_PolicyPassword_Parameter_Unmarshal(
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
)
{
    TPM_RC result = TPM_RC_SUCCESS;
//    PolicyPassword_In *in = (PolicyPassword_In *)parms->parmIn;
//    PolicyPassword_Out *out = (PolicyPassword_Out *)parms->parmOut;

    UNREFERENCED_PARAMETER(parms);
    UNREFERENCED_PARAMETER(buffer);
    UNREFERENCED_PARAMETER(size);
    return result;
}

void
TPM2_PolicyPassword_CalculateUpdate(
    TPM_ALG_ID hashAlg,
    TPM2B_DIGEST *policyDigest,
    PolicyPassword_In *policyPasswordIn
)
{
    HASH_STATE hashState = { 0 };
    TPM_CC commandCode = TPM_CC_PolicyAuthValue;

    UNREFERENCED_PARAMETER(policyPasswordIn);

    // Internal Data Update
    // Update policy hash
    // policyDigestnew = hash(policyDigestold || TPM_CC_PolicyPassword )

    //  start hash
    CryptStartHash(hashAlg, &hashState);

    //  add old digest, which may be empty
    CryptUpdateDigest2B(&hashState, &policyDigest->b);

    //  add commandCode
    CryptUpdateDigestInt(&hashState, sizeof(TPM_CC), &commandCode);

    // complete the digest
    CryptCompleteHash2B(&hashState, &policyDigest->b);
}
