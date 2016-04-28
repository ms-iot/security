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

//** Random Number Generation

BOOL
_cpri__RngStartup(
    void
    )
{
    return TRUE;
}

//** Hash Functions
//*** _cpri__HashStartup()
// Function that is called to initialize the hash service. In this implementation,
// this function does nothing but it is called by the CryptUtilStartup() function
// and must be present.
BOOL
_cpri__HashStartup(
    void
    )
{
    return TRUE;
}

//*** _cpri__RsaStartup()
// Function that is called to initialize the hash service. In this implementation,
// this function does nothing but it is called by the CryptUtilStartup() function
// and must be present.
BOOL
_cpri__RsaStartup(
    void
    )
{
    return TRUE;
}

//*** _cpri_SymStartup()
BOOL
_cpri__SymStartup(
    void
    )
{
    return TRUE;
}

UINT32 g_UsingLocality = (UINT32)TIS_LOCALITY_NONE;
UINT32 g_CommandTimeout = 2000;
UINT32
PlatformSubmitTPM20Command(
    BOOL CloseContext,
    BYTE* pbCommand,
    UINT32 cbCommand,
    BYTE* pbResponse,
    UINT32 cbResponse,
    UINT32* pcbResponse
    )
{
    HAL_StatusTypeDef result = HAL_OK;

    if (g_UsingLocality == (UINT32)TIS_LOCALITY_NONE)
    {
        if((result = RequestLocality(TIS_LOCALITY_0)) != HAL_OK)
        {
            goto Cleanup;
        }
        g_UsingLocality = (UINT32)TIS_LOCALITY_0;
    }

    if ((result = TpmSubmit(pbCommand, cbCommand, pbResponse, cbResponse, pcbResponse, g_CommandTimeout)) != HAL_OK)
    {
        goto Cleanup;
    }

    if (CloseContext != FALSE)
    {
        ReleaseLocality();
        g_UsingLocality = (UINT32)TIS_LOCALITY_NONE;
    }
Cleanup:
    return (result == HAL_OK)? TPM_RC_SUCCESS : ((result == HAL_TIMEOUT) ? TPM_RC_RETRY : TPM_RC_FAILURE);
}

int
TpmFail(
    const char* function,
    int line,
    int code
    )
{
    printf("FATAL: Function:%s() @Line:%d Code:%d(0x%08x)\r\nMCU HALTED!\r\n", function, line, code, code);
    HAL_GPIO_WritePin(GPIOB, LD3_Pin, GPIO_PIN_SET);
    for(;;); // This is a fatal condition. We have to halt execution.
    return 0;
}
