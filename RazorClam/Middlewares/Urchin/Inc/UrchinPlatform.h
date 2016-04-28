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

extern UINT32 g_UsingLocality;
extern UINT32 g_CommandTimeout;

extern TPM2B_AUTH g_LockoutAuth;
extern TPM2B_AUTH g_EndorsementAuth;
extern TPM2B_AUTH g_StorageAuth;

void
InitializeVirtualizationMgr(
    void
);

TPM_RC
DevirtualizeTPM20Command(
    BYTE* pbCommand,
    UINT32 cbCommand,
    BYTE* pbResponse,
    UINT32 cbResponse,
    UINT32* pcbResponse,
    TPMI_YES_NO* pOperationComplete
);

TPM_RC
VirtualizeTPM20Response(
    BYTE* pbCommand,
    UINT32 cbCommand,
    BYTE* pbResponse,
    UINT32 cbResponse,
    UINT32* pcbResponse
);

void
TearDownVirtualizationMgr(
    void
);

UINT32
PlatformSubmitTPM20Command(
    BOOL CloseContext,
    BYTE* pbCommand,
    UINT32 cbCommand,
    BYTE* pbResponse,
    UINT32 cbResponse,
    UINT32* pcbResponse
);

#define EXECUTE_VIRTUALIZED_TPM_CALL(__CloseContext, __CommandType) \
    cbCmd = ##__CommandType##_Marshal(sessionTable, sessionCnt, &parms, &buffer, &size); \
    if((result = DevirtualizeTPM20Command(pbCmd, cbCmd, pbRsp, sizeof(pbRsp), &cbRsp, &cmdComplete)) != TPM_RC_SUCCESS) \
        { \
        goto Cleanup; \
        } \
    if(!cmdComplete) \
        { \
    if ((result = PlatformSubmitTPM20Command(__CloseContext, pbCmd, cbCmd, pbRsp, sizeof(pbRsp), &cbRsp)) != TPM_RC_SUCCESS) \
        { \
            goto Cleanup; \
        } \
        if((result = VirtualizeTPM20Response(pbCmd, cbCmd, pbRsp, sizeof(pbRsp), &cbRsp)) != TPM_RC_SUCCESS) \
                { \
            goto Cleanup; \
                } \
        } \
    buffer = pbRsp; \
    size = cbRsp; \
    if((result = ##__CommandType##_Unmarshal(sessionTable, sessionCnt, &parms, &buffer, &size)) != TPM_RC_SUCCESS) \
        { \
        goto Cleanup; \
        }\

void
_cpri__PlatformRelease(void);

void
_cpri__PlatformReleaseCrypt(void);
