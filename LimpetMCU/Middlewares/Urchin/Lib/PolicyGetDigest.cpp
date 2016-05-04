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
TPM2_PolicyGetDigest_Marshal(
    SESSION *sessionTable,
    UINT32 sessionCnt,
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
)
{
    if((parms == NULL) ||
       (parms->objectCntIn < TPM2_PolicyGetDigest_HdlCntIn) ||
//       (parms->objectCntOut < TPM2_PolicyGetDigest_HdlCntOut) ||
       (parms->parmIn == NULL) ||
       (parms->parmOut == NULL))
    {
        return TPM_RC_FAILURE;
    }
    return Command_Marshal(
        TPM_CC_PolicyGetDigest,
        sessionTable,
        sessionCnt,
        TPM2_PolicyGetDigest_Parameter_Marshal,
        parms,
        buffer,
        size);
}

TPM_RC
TPM2_PolicyGetDigest_Unmarshal(
    SESSION *sessionTable,
    UINT32 sessionCnt,
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
)
{
    TPM_RC result = TPM_RC_SUCCESS;
//    PolicyGetDigest_In *in = (PolicyGetDigest_In *)parms->parmIn;
    PolicyGetDigest_Out *out = (PolicyGetDigest_Out *)parms->parmOut;

    if((parms == NULL) ||
       (parms->objectCntIn < TPM2_PolicyGetDigest_HdlCntIn) ||
//       (parms->objectCntOut < TPM2_PolicyGetDigest_HdlCntOut) ||
       (parms->parmIn == NULL) ||
       (parms->parmOut == NULL))
    {
        return TPM_RC_FAILURE;
    }
    if((result = Command_Unmarshal(
        TPM_CC_PolicyGetDigest,
        sessionTable,
        sessionCnt,
        TPM2_PolicyGetDigest_Parameter_Unmarshal,
        parms,
        buffer,
        size)) == TPM_RC_SUCCESS)
    {
        MemoryCopy2B((TPM2B*)&parms->objectTableIn[TPM2_PolicyPCR_HdlIn_PolicySession].session.u2.policyDigest,
                     (TPM2B*)&out->policyDigest,
                     sizeof(parms->objectTableIn[TPM2_PolicyPCR_HdlIn_PolicySession].session.u2.policyDigest.t.buffer));
    }
    return result;
}

UINT16
TPM2_PolicyGetDigest_Parameter_Marshal(
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
)
{
//    PolicyGetDigest_In *in = (PolicyGetDigest_In *)parms->parmIn;
//    PolicyGetDigest_Out *out = (PolicyGetDigest_Out *)parms->parmOut;
    UINT16 parameterSize = 0;

    UNREFERENCED_PARAMETER(parms);
    UNREFERENCED_PARAMETER(buffer);
    UNREFERENCED_PARAMETER(size);

    return parameterSize;
}

TPM_RC
TPM2_PolicyGetDigest_Parameter_Unmarshal(
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
)
{
    TPM_RC result = TPM_RC_SUCCESS;
//    PolicyGetDigest_In *in = (PolicyGetDigest_In *)parms->parmIn;
    PolicyGetDigest_Out *out = (PolicyGetDigest_Out *)parms->parmOut;

    result = TPM2B_DIGEST_Unmarshal(&out->policyDigest, buffer, size);

    return result;
}

