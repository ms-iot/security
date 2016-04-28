// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <stdint.h>
#include <string.h>
#include "UrchinLib.h"

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
