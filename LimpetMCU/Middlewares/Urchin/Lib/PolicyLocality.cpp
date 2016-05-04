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
TPM2_PolicyLocality_Marshal(
    SESSION *sessionTable,
    UINT32 sessionCnt,
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
)
{
    if((parms == NULL) ||
       (parms->objectCntIn < TPM2_PolicyLocality_HdlCntIn) ||
//       (parms->objectCntOut < TPM2_PolicyLocality_HdlCntOut) ||
       (parms->parmIn == NULL) ||
       (parms->parmOut == NULL))
    {
        return TPM_RC_FAILURE;
    }
    return Command_Marshal(
        TPM_CC_PolicyLocality,
        sessionTable,
        sessionCnt,
        TPM2_PolicyLocality_Parameter_Marshal,
        parms,
        buffer,
        size);
}

TPM_RC
TPM2_PolicyLocality_Unmarshal(
    SESSION *sessionTable,
    UINT32 sessionCnt,
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
)
{
    TPM_RC result = TPM_RC_SUCCESS;
    PolicyLocality_In *in = (PolicyLocality_In *)parms->parmIn;
//    PolicyLocality_Out *out = (PolicyLocality_Out *)parms->parmOut;

    if((parms == NULL) ||
       (parms->objectCntIn < TPM2_PolicyLocality_HdlCntIn) ||
//       (parms->objectCntOut < TPM2_PolicyLocality_HdlCntOut) ||
       (parms->parmIn == NULL) ||
       (parms->parmOut == NULL))
    {
        return TPM_RC_FAILURE;
    }
    if((result = Command_Unmarshal(
        TPM_CC_PolicyLocality,
        sessionTable,
        sessionCnt,
        TPM2_PolicyLocality_Parameter_Unmarshal,
        parms,
        buffer,
        size)) == TPM_RC_SUCCESS)
    {
        TPM2_PolicyLocality_CalculateUpdate(parms->objectTableIn[TPM2_PolicyLocality_HdlIn_PolicySession].session.authHashAlg,
                                                &parms->objectTableIn[TPM2_PolicyLocality_HdlIn_PolicySession].session.u2.policyDigest,
                                                in);
    }
    return result;
}

UINT16
TPM2_PolicyLocality_Parameter_Marshal(
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
)
{
    PolicyLocality_In *in = (PolicyLocality_In *)parms->parmIn;
//    PolicyLocality_Out *out = (PolicyLocality_Out *)parms->parmOut;
    UINT16 parameterSize = 0;

    parameterSize += TPMA_LOCALITY_Marshal(&in->locality, buffer, size);
    if(size < 0) return TPM_RC_SIZE;

    return parameterSize;
}

TPM_RC
TPM2_PolicyLocality_Parameter_Unmarshal(
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
)
{
    TPM_RC result = TPM_RC_SUCCESS;
//    PolicyLocality_In *in = (PolicyLocality_In *)parms->parmIn;
//    PolicyLocality_Out *out = (PolicyLocality_Out *)parms->parmOut;

    UNREFERENCED_PARAMETER(parms);
    UNREFERENCED_PARAMETER(buffer);
    UNREFERENCED_PARAMETER(size);
    return result;
}

void
TPM2_PolicyLocality_CalculateUpdate(
    TPM_ALG_ID hashAlg,
    TPM2B_DIGEST *policyDigest,
    PolicyLocality_In *policyLocalityIn
)
{
    HASH_STATE hashState = { 0 };
    TPM_CC commandCode = TPM_CC_PolicyLocality;
    UINT32  marshalSize = 0;
    BYTE marshalBuffer[sizeof(TPMA_LOCALITY)] = { 0 };
    BYTE *buffer = NULL;

    // Get new locality setting in canonical form
    buffer = marshalBuffer;
    marshalSize = TPMA_LOCALITY_Marshal(&policyLocalityIn->locality, &buffer, NULL);

    // Internal Data Update
    // Update policy hash
    // policyDigestnew = hash(policyDigestold || TPM_CC_PolicyLocality || locality)

    //  start hash
    CryptStartHash(hashAlg, &hashState);

    //  add old digest, which may be empty
    CryptUpdateDigest2B(&hashState, &policyDigest->b);

    //  add commandCode
    CryptUpdateDigestInt(&hashState, sizeof(TPM_CC), &commandCode);

    //  add argument digest
    CryptUpdateDigest(&hashState, marshalSize, marshalBuffer);

    // complete the digest
    CryptCompleteHash2B(&hashState, &policyDigest->b);
}
