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
TPM2_PolicyDuplicationSelect_Marshal(
    SESSION *sessionTable,
    UINT32 sessionCnt,
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
)
{
    if((parms == NULL) ||
       (parms->objectCntIn < TPM2_PolicyDuplicationSelect_HdlCntIn) ||
//       (parms->objectCntOut < TPM2_PolicyDuplicationSelect_HdlCntOut) ||
       (parms->parmIn == NULL) ||
       (parms->parmOut == NULL))
    {
        return TPM_RC_FAILURE;
    }
    return Command_Marshal(
        TPM_CC_PolicyDuplicationSelect,
        sessionTable,
        sessionCnt,
        TPM2_PolicyDuplicationSelect_Parameter_Marshal,
        parms,
        buffer,
        size);
}

TPM_RC
TPM2_PolicyDuplicationSelect_Unmarshal(
    SESSION *sessionTable,
    UINT32 sessionCnt,
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
)
{
    TPM_RC result = TPM_RC_SUCCESS;
    PolicyDuplicationSelect_In *in = (PolicyDuplicationSelect_In *)parms->parmIn;
//    PolicyDuplicationSelect_Out *out = (PolicyDuplicationSelect_Out *)parms->parmOut;

    if((parms == NULL) ||
       (parms->objectCntIn < TPM2_PolicyDuplicationSelect_HdlCntIn) ||
//       (parms->objectCntOut < TPM2_PolicyDuplicationSelect_HdlCntOut) ||
       (parms->parmIn == NULL) ||
       (parms->parmOut == NULL))
    {
        return TPM_RC_FAILURE;
    }
    if((result = Command_Unmarshal(
        TPM_CC_PolicyDuplicationSelect,
        sessionTable,
        sessionCnt,
        TPM2_PolicyDuplicationSelect_Parameter_Unmarshal,
        parms,
        buffer,
        size)) == TPM_RC_SUCCESS)
    {
        TPM2_PolicyDuplicationSelect_CalculateUpdate(parms->objectTableIn[TPM2_PolicyDuplicationSelect_HdlIn_PolicySession].session.authHashAlg,
                                                     &parms->objectTableIn[TPM2_PolicyDuplicationSelect_HdlIn_PolicySession].session.u2.policyDigest,
                                                     in);
    }
    return result;
}

UINT16
TPM2_PolicyDuplicationSelect_Parameter_Marshal(
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
)
{
    PolicyDuplicationSelect_In *in = (PolicyDuplicationSelect_In *)parms->parmIn;
//    PolicyDuplicationSelect_Out *out = (PolicyDuplicationSelect_Out *)parms->parmOut;
    UINT16 parameterSize = 0;

    parameterSize += TPM2B_NAME_Marshal(&in->objectName, buffer, size);
    if(size < 0) return TPM_RC_SIZE;
    parameterSize += TPM2B_NAME_Marshal(&in->newParentName, buffer, size);
    if(size < 0) return TPM_RC_SIZE;
    parameterSize += TPMI_YES_NO_Marshal(&in->includeObject, buffer, size);
    if(size < 0) return TPM_RC_SIZE;

    return parameterSize;
}

TPM_RC
TPM2_PolicyDuplicationSelect_Parameter_Unmarshal(
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
)
{
    TPM_RC result = TPM_RC_SUCCESS;
//    PolicyDuplicationSelect_In *in = (PolicyDuplicationSelect_In *)parms->parmIn;
//    PolicyDuplicationSelect_Out *out = (PolicyDuplicationSelect_Out *)parms->parmOut;

    UNREFERENCED_PARAMETER(parms);
    UNREFERENCED_PARAMETER(buffer);
    UNREFERENCED_PARAMETER(size);
    return result;
}

void
TPM2_PolicyDuplicationSelect_CalculateUpdate(
    TPM_ALG_ID hashAlg,
    TPM2B_DIGEST *policyDigest,
    PolicyDuplicationSelect_In *policyDuplicationSelectIn
)
{
    HASH_STATE hashState = { 0 };
    TPM_CC commandCode = TPM_CC_PolicyDuplicationSelect;

    // Internal Data Update
    // Update policy hash
    // policyDigestnew = hash(policyDigestold || TPM_CC_PolicyDuplicationSelect || (includeObject == YES) ? objectName || newParentName || includeObject)
    CryptStartHash(hashAlg, &hashState);

    //  add old policy
    CryptUpdateDigest2B(&hashState, &policyDigest->b);

    //  add command code
    CryptUpdateDigestInt(&hashState, sizeof(TPM_CC), &commandCode);

    //  add objectName
    if(policyDuplicationSelectIn->includeObject == YES)
    {
        CryptUpdateDigest2B(&hashState, &policyDuplicationSelectIn->objectName.b);
    }

    //  add new parent name
    CryptUpdateDigest2B(&hashState, &policyDuplicationSelectIn->newParentName.b);

    //  add includeObject
    CryptUpdateDigestInt(&hashState, sizeof(TPMI_YES_NO), &policyDuplicationSelectIn->includeObject);

    //  complete digest
    CryptCompleteHash2B(&hashState, &policyDigest->b);
}
