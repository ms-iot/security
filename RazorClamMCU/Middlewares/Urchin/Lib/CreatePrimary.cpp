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
TPM2_CreatePrimary_Marshal(
    SESSION *sessionTable,
    UINT32 sessionCnt,
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
)
{
    if((parms == NULL) ||
        (parms->objectCntIn < TPM2_CreatePrimary_HdlCntIn) ||
        (parms->objectCntOut < TPM2_CreatePrimary_HdlCntOut) ||
        (parms->parmIn == NULL) ||
        (parms->parmOut == NULL))
    {
        return TPM_RC_FAILURE;
    }
    g_CommandTimeout = TPM_CREATE_COMMAND_TIMEOUT;
    return Command_Marshal(
        TPM_CC_CreatePrimary,
        sessionTable,
        sessionCnt,
        TPM2_CreatePrimary_Parameter_Marshal,
        parms,
        buffer,
        size);
}

TPM_RC
TPM2_CreatePrimary_Unmarshal(
    SESSION *sessionTable,
    UINT32 sessionCnt,
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
)
{
    TPM_RC result = TPM_RC_SUCCESS;
//    CreatePrimary_In *in = (CreatePrimary_In *)parms->parmIn;
    CreatePrimary_Out *out = (CreatePrimary_Out *)parms->parmOut;

    if((parms == NULL) ||
        (parms->objectCntIn < TPM2_CreatePrimary_HdlCntIn) ||
        (parms->objectCntOut < TPM2_CreatePrimary_HdlCntOut) ||
        (parms->parmIn == NULL) ||
        (parms->parmOut == NULL))
    {
        return TPM_RC_FAILURE;
    }
    g_CommandTimeout = TPM_DEFAULT_COMMAND_TIMEOUT;
    if((result = Command_Unmarshal(
        TPM_CC_CreatePrimary,
        sessionTable,
        sessionCnt,
        TPM2_CreatePrimary_Parameter_Unmarshal,
        parms,
        buffer,
        size)) == TPM_RC_SUCCESS)
    {
        parms->objectTableOut[TPM2_CreatePrimary_HdlOut_ObjectHandle].obj.publicArea = out->outPublic;
        parms->objectTableOut[TPM2_CreatePrimary_HdlOut_ObjectHandle].obj.name = out->name;
    }
    return result;
}

UINT16
TPM2_CreatePrimary_Parameter_Marshal(
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
)
{
    CreatePrimary_In *in = (CreatePrimary_In *)parms->parmIn;
//    CreatePrimary_Out *out = (CreatePrimary_Out *)parms->parmOut;
    UINT16 parameterSize = 0;

    // Marshal the parameters
    parameterSize += TPM2B_SENSITIVE_CREATE_Marshal(&in->inSensitive, buffer, size);
    if (*size < 0) return TPM_RC_SIZE;
    parameterSize += TPM2B_PUBLIC_Marshal(&in->inPublic, buffer, size);
    if (*size < 0) return TPM_RC_SIZE;
    parameterSize += TPM2B_DATA_Marshal(&in->outsideInfo, buffer, size);
    if (*size < 0) return TPM_RC_SIZE;
    parameterSize += TPML_PCR_SELECTION_Marshal(&in->creationPCR, buffer, size);
    if (*size < 0) return TPM_RC_SIZE;

    return parameterSize;
}

TPM_RC
TPM2_CreatePrimary_Parameter_Unmarshal(
    Marshal_Parms *parms,
    BYTE **buffer,
    INT32 *size
)
{
    TPM_RC result = TPM_RC_SUCCESS;
//    CreatePrimary_In *in = (CreatePrimary_In *)parms->parmIn;
    CreatePrimary_Out *out = (CreatePrimary_Out *)parms->parmOut;

    // Unmarshal the parameters
    result = TPM2B_PUBLIC_Unmarshal(&out->outPublic, buffer, size, FALSE);
    if (result != TPM_RC_SUCCESS) return result;
    result = TPM2B_CREATION_DATA_Unmarshal(&out->creationData, buffer, size);
    if (result != TPM_RC_SUCCESS) return result;
    result = TPM2B_DIGEST_Unmarshal(&out->creationHash, buffer, size);
    if (result != TPM_RC_SUCCESS) return result;
    result = TPMT_TK_CREATION_Unmarshal(&out->creationTicket, buffer, size);
    if (result != TPM_RC_SUCCESS) return result;
    result = TPM2B_NAME_Unmarshal(&out->name, buffer, size);
    if (result != TPM_RC_SUCCESS) return result;

    return result;
}
