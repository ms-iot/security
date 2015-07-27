// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <Strsafe.h>
#include <malloc.h>
#include <Windows.h>
#include <BCrypt.h>
#include <NCrypt.h>
#include <Wincrypt.h>
#include <CertEnroll.h>
#include <tbs.h>
#include "UrchinLib.h"
#include "UrchinPlatform.h"

// New Windows 10 definition for native SPI and I2C attached TPM 2.0
#ifndef TPM_IFTYPE_SPB
#define TPM_IFTYPE_SPB 5 // 2.0: SPB attached
#endif

typedef struct {
    UINT32 Id;
    WCHAR* Name;
} TRANSLATE_TABLE;
