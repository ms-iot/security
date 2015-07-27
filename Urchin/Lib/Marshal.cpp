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

// Table 3 -- BaseTypes BaseTypes <I/O>
TPM_RC 
UINT8_Unmarshal(UINT8 *target, BYTE **buffer, INT32 *size)
{
    if((*size -= 1) < 0)
        return TPM_RC_INSUFFICIENT;
    *target = BYTE_ARRAY_TO_UINT8(*buffer);
    *buffer += 1;
    return TPM_RC_SUCCESS;
}

UINT16 
UINT8_Marshal(UINT8 *source, BYTE **buffer, INT32 *size)
{
    if (buffer != NULL) 
    {
        if ((size == 0) || ((*size -= 1) >= 0)) 
        {
            UINT8_TO_BYTE_ARRAY(*source, *buffer);
            *buffer += 1;
        }
        pAssert(size == 0 || (*size >= 0));
    }
    return (1);
}

TPM_RC 
UINT16_Unmarshal(UINT16 *target, BYTE **buffer, INT32 *size)
{
    if((*size -= 2) < 0)
        return TPM_RC_INSUFFICIENT;
    *target = BYTE_ARRAY_TO_UINT16(*buffer);
    *buffer += 2;
    return TPM_RC_SUCCESS;
}

UINT16 
UINT16_Marshal(UINT16 *source, BYTE **buffer, INT32 *size)
{
    if (buffer != NULL) 
    {
        if ((size == 0) || ((*size -= 2) >= 0)) 
        {
            UINT16_TO_BYTE_ARRAY(*source, *buffer);
            *buffer += 2;
        }
        pAssert(size == 0 || (*size >= 0));
    }
    return (2);
}

TPM_RC 
UINT32_Unmarshal(UINT32 *target, BYTE **buffer, INT32 *size)
{
    if((*size -= 4) < 0)
        return TPM_RC_INSUFFICIENT;
    *target = BYTE_ARRAY_TO_UINT32(*buffer);
    *buffer += 4;
    return TPM_RC_SUCCESS;
}

UINT16 
UINT32_Marshal(UINT32 *source, BYTE **buffer, INT32 *size)
{
    if (buffer != NULL) 
    {
        if ((size == 0) || ((*size -= 4) >= 0)) 
        {
            UINT32_TO_BYTE_ARRAY(*source, *buffer);
            *buffer += 4;
        }
        pAssert(size == 0 || (*size >= 0));
    }
    return (4);
}

TPM_RC 
UINT64_Unmarshal(UINT64 *target, BYTE **buffer, INT32 *size)
{
    if((*size -= 8) < 0)
        return TPM_RC_INSUFFICIENT;
    *target = BYTE_ARRAY_TO_UINT64(*buffer);
    *buffer += 8;
    return TPM_RC_SUCCESS;
}

UINT16 
UINT64_Marshal(UINT64 *source, BYTE **buffer, INT32 *size)
{
    if (buffer != NULL) 
    {
        if ((size == 0) || ((*size -= 8) >= 0)) 
        {
            UINT64_TO_BYTE_ARRAY(*source, *buffer);
            *buffer += 8;
        }
        pAssert(size == 0 || (*size >= 0));
    }
    return (8);
}

TPM_RC 
BYTE_Unmarshal(BYTE *target, BYTE **buffer, INT32 *size)
{
    return UINT8_Unmarshal((UINT8 *)target, buffer, size);
}

UINT16 
BYTE_Marshal(BYTE *source, BYTE **buffer, INT32 *size)
{
    return UINT8_Marshal((UINT8 *)source, buffer, size);
}

TPM_RC 
INT8_Unmarshal(INT8 *target, BYTE **buffer, INT32 *size)
{
    return UINT8_Unmarshal((UINT8 *)target, buffer, size);
}

UINT16 
INT8_Marshal(INT8 *source, BYTE **buffer, INT32 *size)
{
    return UINT8_Marshal((UINT8 *)source, buffer, size);
}

TPM_RC 
BOOL_Unmarshal(BOOL *target, BYTE **buffer, INT32 *size)
{
    return UINT8_Unmarshal((UINT8 *)target, buffer, size);
}

UINT16 
BOOL_Marshal(BOOL *source, BYTE **buffer, INT32 *size)
{
    return UINT8_Marshal((UINT8 *)source, buffer, size);
}

TPM_RC 
INT16_Unmarshal(INT16 *target, BYTE **buffer, INT32 *size)
{
    return UINT16_Unmarshal((UINT16 *)target, buffer, size);
}

UINT16 
INT16_Marshal(INT16 *source, BYTE **buffer, INT32 *size)
{
    return UINT16_Marshal((UINT16 *)source, buffer, size);
}

TPM_RC 
INT32_Unmarshal(INT32 *target, BYTE **buffer, INT32 *size)
{
    return UINT32_Unmarshal((UINT32 *)target, buffer, size);
}

UINT16 
INT32_Marshal(INT32 *source, BYTE **buffer, INT32 *size)
{
    return UINT32_Marshal((UINT32 *)source, buffer, size);
}

TPM_RC 
INT64_Unmarshal(INT64 *target, BYTE **buffer, INT32 *size)
{
    return UINT64_Unmarshal((UINT64 *)target, buffer, size);
}

UINT16 
INT64_Marshal(INT64 *source, BYTE **buffer, INT32 *size)
{
    return UINT64_Marshal((UINT64 *)source, buffer, size);
}


// Table 4 -- DocumentationClarity Types <I/O>
TPM_RC
TPM_ALGORITHM_ID_Unmarshal(TPM_ALGORITHM_ID *target, BYTE **buffer, INT32 *size)
{
    return UINT32_Unmarshal((UINT32 *)target, buffer, size);
}

TPM_RC
TPM_MODIFIER_INDICATOR_Unmarshal(TPM_MODIFIER_INDICATOR *target, BYTE **buffer, INT32 *size)
{
    return UINT32_Unmarshal((UINT32 *)target, buffer, size);
}

TPM_RC
TPM_AUTHORIZATION_SIZE_Unmarshal(TPM_AUTHORIZATION_SIZE *target, BYTE **buffer, INT32 *size)
{
    return UINT32_Unmarshal((UINT32 *)target, buffer, size);
}

TPM_RC
TPM_PARAMETER_SIZE_Unmarshal(TPM_PARAMETER_SIZE *target, BYTE **buffer, INT32 *size)
{
    return UINT32_Unmarshal((UINT32 *)target, buffer, size);
}

TPM_RC
TPM_KEY_SIZE_Unmarshal(TPM_KEY_SIZE *target, BYTE **buffer, INT32 *size)
{
    return UINT16_Unmarshal((UINT16 *)target, buffer, size);
}

TPM_RC
TPM_KEY_BITS_Unmarshal(TPM_KEY_BITS *target, BYTE **buffer, INT32 *size)
{
    return UINT16_Unmarshal((UINT16 *)target, buffer, size);
}


UINT16
TPM_ALGORITHM_ID_Marshal(TPM_ALGORITHM_ID *source, BYTE **buffer, INT32 *size)
{
    return UINT32_Marshal((UINT32 *)source, buffer, size);
}

UINT16
TPM_MODIFIER_INDICATOR_Marshal(TPM_MODIFIER_INDICATOR *source, BYTE **buffer, INT32 *size)
{
    return UINT32_Marshal((UINT32 *)source, buffer, size);
}

UINT16
TPM_AUTHORIZATION_SIZE_Marshal(TPM_AUTHORIZATION_SIZE *source, BYTE **buffer, INT32 *size)
{
    return UINT32_Marshal((UINT32 *)source, buffer, size);
}

UINT16
TPM_PARAMETER_SIZE_Marshal(TPM_PARAMETER_SIZE *source, BYTE **buffer, INT32 *size)
{
    return UINT32_Marshal((UINT32 *)source, buffer, size);
}

UINT16
TPM_KEY_SIZE_Marshal(TPM_KEY_SIZE *source, BYTE **buffer, INT32 *size)
{
    return UINT16_Marshal((UINT16 *)source, buffer, size);
}

UINT16
TPM_KEY_BITS_Marshal(TPM_KEY_BITS *source, BYTE **buffer, INT32 *size)
{
    return UINT16_Marshal((UINT16 *)source, buffer, size);
}



// Table 6 -- TPM_GENERATED Constants <O,S>
TPM_RC
TPM_GENERATED_Unmarshal(TPM_GENERATED *target, BYTE **buffer, INT32 *size)
{
    return UINT32_Unmarshal((UINT32 *)target, buffer, size);
}

UINT16
TPM_GENERATED_Marshal(TPM_GENERATED *source, BYTE **buffer, INT32 *size)
{
    return UINT32_Marshal((UINT32 *)source, buffer, size);
}


// Table 7 -- TPM_ALG_ID Constants <I/O,S>
TPM_RC
TPM_ALG_ID_Unmarshal(TPM_ALG_ID *target, BYTE **buffer, INT32 *size)
{
    return UINT16_Unmarshal((UINT16 *)target, buffer, size);
}

UINT16
TPM_ALG_ID_Marshal(TPM_ALG_ID *source, BYTE **buffer, INT32 *size)
{
    return UINT16_Marshal((UINT16 *)source, buffer, size);
}


// Table 8 -- TPM_ECC_CURVE Constants <I/O,S>
#ifdef TPM_ALG_ECC
TPM_RC
TPM_ECC_CURVE_Unmarshal(TPM_ECC_CURVE *target, BYTE **buffer, INT32 *size)
{
    return UINT16_Unmarshal((UINT16 *)target, buffer, size);
}

#endif
#ifdef TPM_ALG_ECC
UINT16
TPM_ECC_CURVE_Marshal(TPM_ECC_CURVE *source, BYTE **buffer, INT32 *size)
{
    return UINT16_Marshal((UINT16 *)source, buffer, size);
}

#endif

// Table 11 -- TPM_CC Constants <I/O,S>
TPM_RC
TPM_CC_Unmarshal(TPM_CC *target, BYTE **buffer, INT32 *size)
{
    return UINT32_Unmarshal((UINT32 *)target, buffer, size);
}

UINT16
TPM_CC_Marshal(TPM_CC *source, BYTE **buffer, INT32 *size)
{
    return UINT32_Marshal((UINT32 *)source, buffer, size);
}


// Table 15 -- TPM_RC Constants <O,S>
TPM_RC
TPM_RC_Unmarshal(TPM_RC *target, BYTE **buffer, INT32 *size)
{
    return UINT32_Unmarshal((UINT32 *)target, buffer, size);
}
UINT16
TPM_RC_Marshal(TPM_RC *source, BYTE **buffer, INT32 *size)
{
    return UINT32_Marshal((UINT32 *)source, buffer, size);
}


// Table 16 -- TPM_CLOCK_ADJUST Constants <I>
TPM_RC
TPM_CLOCK_ADJUST_Unmarshal(TPM_CLOCK_ADJUST *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = INT8_Unmarshal((INT8 *)target, buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;

    switch(*target) {
        case TPM_CLOCK_COARSE_SLOWER :
        case TPM_CLOCK_MEDIUM_SLOWER :
        case TPM_CLOCK_FINE_SLOWER :
        case TPM_CLOCK_NO_CHANGE :
        case TPM_CLOCK_FINE_FASTER :
        case TPM_CLOCK_MEDIUM_FASTER :
        case TPM_CLOCK_COARSE_FASTER :
            break;
       default :
            return TPM_RC_VALUE;
            break;
    }

    return TPM_RC_SUCCESS;
}
UINT16
TPM_CLOCK_ADJUST_Marshal(TPM_CLOCK_ADJUST *source, BYTE **buffer, INT32 *size)
{
    return INT8_Marshal((INT8 *)source, buffer, size);
}


// Table 17 -- TPM_EO Constants <I/O>
TPM_RC
TPM_EO_Unmarshal(TPM_EO *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = UINT16_Unmarshal((UINT16 *)target, buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;

    switch(*target) {
        case TPM_EO_EQ :
        case TPM_EO_NEQ :
        case TPM_EO_SIGNED_GT :
        case TPM_EO_UNSIGNED_GT :
        case TPM_EO_SIGNED_LT :
        case TPM_EO_UNSIGNED_LT :
        case TPM_EO_SIGNED_GE :
        case TPM_EO_UNSIGNED_GE :
        case TPM_EO_SIGNED_LE :
        case TPM_EO_UNSIGNED_LE :
        case TPM_EO_BITSET :
        case TPM_EO_BITCLEAR :
            break;
       default :
            return TPM_RC_VALUE ;
            break;
    }

    return TPM_RC_SUCCESS;
}
UINT16
TPM_EO_Marshal(TPM_EO *source, BYTE **buffer, INT32 *size)
{
    return UINT16_Marshal((UINT16 *)source, buffer, size);
}


// Table 18 -- TPM_ST Constants <I/O,S>
TPM_RC
TPM_ST_Unmarshal(TPM_ST *target, BYTE **buffer, INT32 *size)
{
    return UINT16_Unmarshal((UINT16 *)target, buffer, size);
}

UINT16
TPM_ST_Marshal(TPM_ST *source, BYTE **buffer, INT32 *size)
{
    return UINT16_Marshal((UINT16 *)source, buffer, size);
}


// Table 19 -- TPM_SU Constants <I>
TPM_RC
TPM_SU_Unmarshal(TPM_SU *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = UINT16_Unmarshal((UINT16 *)target, buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;

    switch(*target) {
        case TPM_SU_CLEAR :
        case TPM_SU_STATE :
            break;
       default :
            return TPM_RC_VALUE;
            break;
    }

    return TPM_RC_SUCCESS;
}

UINT16
TPM_SU_Marshal(TPM_SU *source, BYTE **buffer, INT32 *size)
{
    return UINT16_Marshal((UINT16 *)source, buffer, size);
}


// Table 20 -- TPM_SE Constants <I>
TPM_RC
TPM_SE_Unmarshal(TPM_SE *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = UINT8_Unmarshal((UINT8 *)target, buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;

    switch(*target) {
        case TPM_SE_HMAC :
        case TPM_SE_POLICY :
        case TPM_SE_TRIAL :
            break;
       default :
            return TPM_RC_VALUE;
            break;
    }

    return TPM_RC_SUCCESS;
}

UINT16
TPM_SE_Marshal(TPM_SE *source, BYTE **buffer, INT32 *size)
{
    return UINT8_Marshal((UINT8 *)source, buffer, size);
}

// Table 21 -- TPM_CAP Constants <I/O>
TPM_RC
TPM_CAP_Unmarshal(TPM_CAP *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = UINT32_Unmarshal((UINT32 *)target, buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;

    switch(*target) {
        case TPM_CAP_ALGS :
        case TPM_CAP_HANDLES :
        case TPM_CAP_COMMANDS :
        case TPM_CAP_PP_COMMANDS :
        case TPM_CAP_AUDIT_COMMANDS :
        case TPM_CAP_PCRS :
        case TPM_CAP_TPM_PROPERTIES :
        case TPM_CAP_PCR_PROPERTIES :
        case TPM_CAP_ECC_CURVES :
        case TPM_CAP_VENDOR_PROPERTY :
            break;
       default :
            return TPM_RC_VALUE;
            break;
    }

    return TPM_RC_SUCCESS;
}
UINT16
TPM_CAP_Marshal(TPM_CAP *source, BYTE **buffer, INT32 *size)
{
    return UINT32_Marshal((UINT32 *)source, buffer, size);
}


// Table 22 -- TPM_PT Constants <I/O,S>
TPM_RC
TPM_PT_Unmarshal(TPM_PT *target, BYTE **buffer, INT32 *size)
{
    return UINT32_Unmarshal((UINT32 *)target, buffer, size);
}

UINT16
TPM_PT_Marshal(TPM_PT *source, BYTE **buffer, INT32 *size)
{
    return UINT32_Marshal((UINT32 *)source, buffer, size);
}


// Table 23 -- TPM_PT_PCR Constants <I/O,S>
TPM_RC
TPM_PT_PCR_Unmarshal(TPM_PT_PCR *target, BYTE **buffer, INT32 *size)
{
    return UINT32_Unmarshal((UINT32 *)target, buffer, size);
}

UINT16
TPM_PT_PCR_Marshal(TPM_PT_PCR *source, BYTE **buffer, INT32 *size)
{
    return UINT32_Marshal((UINT32 *)source, buffer, size);
}


// Table 24 -- TPM_PS Constants <O,S>
UINT16
TPM_PS_Marshal(TPM_PS *source, BYTE **buffer, INT32 *size)
{
    return UINT32_Marshal((UINT32 *)source, buffer, size);
}


// Table 25 -- Handles Types <I/O>
TPM_RC
TPM_HANDLE_Unmarshal(TPM_HANDLE *target, BYTE **buffer, INT32 *size)
{
    return UINT32_Unmarshal((UINT32 *)target, buffer, size);
}


UINT16
TPM_HANDLE_Marshal(TPM_HANDLE *source, BYTE **buffer, INT32 *size)
{
    return UINT32_Marshal((UINT32 *)source, buffer, size);
}



// Table 27 -- TPM_RH Constants <I,S>
TPM_RC
TPM_RH_Unmarshal(TPM_RH *target, BYTE **buffer, INT32 *size)
{
    return UINT32_Unmarshal((UINT32 *)target, buffer, size);
}


// Table 28 -- TPM_HC Constants <I,S>
TPM_RC
TPM_HC_Unmarshal(TPM_HC *target, BYTE **buffer, INT32 *size)
{
    return UINT32_Unmarshal((UINT32 *)target, buffer, size);
}


// Table 29 -- TPMA_ALGORITHM Bits <I/O>
TPM_RC
TPMA_ALGORITHM_Unmarshal(TPMA_ALGORITHM *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = UINT32_Unmarshal((UINT32 *)target, buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    if(*((UINT32 *)target) & 0xfffff8f0)
        return TPM_RC_RESERVED_BITS;
    return TPM_RC_SUCCESS;
}

UINT16
TPMA_ALGORITHM_Marshal(TPMA_ALGORITHM *source, BYTE **buffer, INT32 *size)
{
    return UINT32_Marshal((UINT32 *)source, buffer, size);
}


// Table 30 -- TPMA_OBJECT Bits <I/O>
TPM_RC
TPMA_OBJECT_Unmarshal(TPMA_OBJECT *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = UINT32_Unmarshal((UINT32 *)target, buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    if(*((UINT32 *)target) & 0xfff8f109)
        return TPM_RC_RESERVED_BITS;
    return TPM_RC_SUCCESS;
}

UINT16
TPMA_OBJECT_Marshal(TPMA_OBJECT *source, BYTE **buffer, INT32 *size)
{
    return UINT32_Marshal((UINT32 *)source, buffer, size);
}


// Table 31 -- TPMA_SESSION Bits <I/O>
TPM_RC
TPMA_SESSION_Unmarshal(TPMA_SESSION *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = UINT8_Unmarshal((UINT8 *)target, buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    if(*((UINT8 *)target) & 0x18)
        return TPM_RC_RESERVED_BITS;

    return TPM_RC_SUCCESS;
}

UINT16
TPMA_SESSION_Marshal(TPMA_SESSION *source, BYTE **buffer, INT32 *size)
{
    return UINT8_Marshal((UINT8 *)source, buffer, size);
}


// Table 32 -- TPMA_LOCALITY Bits <I/O>
TPM_RC
TPMA_LOCALITY_Unmarshal(TPMA_LOCALITY *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = UINT8_Unmarshal((UINT8 *)target, buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    return TPM_RC_SUCCESS;
}

UINT16
TPMA_LOCALITY_Marshal(TPMA_LOCALITY *source, BYTE **buffer, INT32 *size)
{
    return UINT8_Marshal((UINT8 *)source, buffer, size);
}


// Table 33 -- TPMA_PERMANENT Bits <O,S>
UINT16
TPMA_PERMANENT_Marshal(TPMA_PERMANENT *source, BYTE **buffer, INT32 *size)
{
    return UINT32_Marshal((UINT32 *)source, buffer, size);
}


// Table 34 -- TPMA_STARTUP_CLEAR Bits <O,S>
UINT16
TPMA_STARTUP_CLEAR_Marshal(TPMA_STARTUP_CLEAR *source, BYTE **buffer, INT32 *size)
{
    return UINT32_Marshal((UINT32 *)source, buffer, size);
}


// Table 35 -- TPMA_MEMORY Bits <O,S>
UINT16
TPMA_MEMORY_Marshal(TPMA_MEMORY *source, BYTE **buffer, INT32 *size)
{
    return UINT32_Marshal((UINT32 *)source, buffer, size);
}


// Table 36 -- TPMA_CC Bits <O,S>
UINT16
TPMA_CC_Marshal(TPMA_CC *source, BYTE **buffer, INT32 *size)
{
    return UINT32_Marshal((UINT32 *)source, buffer, size);
}

TPM_RC
TPMA_CC_Unmarshal(TPMA_CC *target, BYTE **buffer, INT32 *size)
{
    return UINT32_Unmarshal((UINT32 *)target, buffer, size);
}


// Table 37 -- TPMI_YES_NO Type <I/O>
TPM_RC
TPMI_YES_NO_Unmarshal(TPMI_YES_NO *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = BYTE_Unmarshal((BYTE *)target, buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    switch (*target) {
        case NO:
        case YES:
            break;
        default:
            return TPM_RC_VALUE;
    }
    return TPM_RC_SUCCESS;
}

UINT16
TPMI_YES_NO_Marshal(TPMI_YES_NO *source, BYTE **buffer, INT32 *size)
{
    return UINT8_Marshal((UINT8 *)source, buffer, size);
}


// Table 38 -- TPMI_DH_OBJECT Type <I/O>
TPM_RC
TPMI_DH_OBJECT_Unmarshal(TPMI_DH_OBJECT *target, BYTE **buffer, INT32 *size, BOOL flag)
{
    TPM_RC    result;
    result = TPM_HANDLE_Unmarshal((TPM_HANDLE *)target, buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
   if (*target == TPM_RH_NULL) {
        if(flag)
            return TPM_RC_SUCCESS;
        else
            return TPM_RC_VALUE;
    }
    if((*target < TRANSIENT_FIRST) || (*target > TRANSIENT_LAST))
        if((*target < PERSISTENT_FIRST) || (*target > PERSISTENT_LAST))
            return TPM_RC_VALUE;
    return TPM_RC_SUCCESS;
}

UINT16
TPMI_DH_OBJECT_Marshal(TPMI_DH_OBJECT *source, BYTE **buffer, INT32 *size)
{
    return UINT32_Marshal((UINT32 *)source, buffer, size);
}


// Table 39 -- TPMI_DH_PERSISTENT Type <I/O>
TPM_RC
TPMI_DH_PERSISTENT_Unmarshal(TPMI_DH_PERSISTENT *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPM_HANDLE_Unmarshal((TPM_HANDLE *)target, buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    if((*target < PERSISTENT_FIRST) || (*target > PERSISTENT_LAST))
        return TPM_RC_VALUE;
    return TPM_RC_SUCCESS;
}

UINT16
TPMI_DH_PERSISTENT_Marshal(TPMI_DH_PERSISTENT *source, BYTE **buffer, INT32 *size)
{
    return UINT32_Marshal((UINT32 *)source, buffer, size);
}


// Table 40 -- TPMI_DH_ENTITY Type <I>
TPM_RC
TPMI_DH_ENTITY_Unmarshal(TPMI_DH_ENTITY *target, BYTE **buffer, INT32 *size, BOOL flag)
{
    TPM_RC    result;
    result = TPM_HANDLE_Unmarshal((TPM_HANDLE *)target, buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    switch (*target) {
        case TPM_RH_OWNER:
        case TPM_RH_ENDORSEMENT:
        case TPM_RH_PLATFORM:
        case TPM_RH_LOCKOUT:
            break;
        case TPM_RH_NULL:
            if (flag)
                break;
            return TPM_RC_VALUE;
        default:
            if((*target < TRANSIENT_FIRST) || (*target >  TRANSIENT_LAST))
                if((*target < PERSISTENT_FIRST) || (*target >  PERSISTENT_LAST))
                    if((*target < NV_INDEX_FIRST) || (*target >  NV_INDEX_LAST))
                        if(*target >  PCR_LAST)
                            return TPM_RC_VALUE;
    }
    return TPM_RC_SUCCESS;
}


// Table 41 -- TPMI_DH_PCR Type <I>
TPM_RC
TPMI_DH_PCR_Unmarshal(TPMI_DH_PCR *target, BYTE **buffer, INT32 *size, BOOL flag)
{
    TPM_RC    result;
    result = TPM_HANDLE_Unmarshal((TPM_HANDLE *)target, buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
   if (*target == TPM_RH_NULL) {
        if(flag)
            return TPM_RC_SUCCESS;
        else
            return TPM_RC_VALUE;
    }
    if(*target > PCR_LAST)
        return TPM_RC_VALUE;
    return TPM_RC_SUCCESS;
}

UINT16
TPMI_DH_PCR_Marshal(TPMI_DH_PCR *source, BYTE **buffer, INT32 *size)
{
    return UINT32_Marshal((UINT32 *)source, buffer, size);
}


// Table 42 -- TPMI_SH_AUTH_SESSION Type <I/O>
TPM_RC
TPMI_SH_AUTH_SESSION_Unmarshal(TPMI_SH_AUTH_SESSION *target, BYTE **buffer, INT32 *size, BOOL flag)
{
    TPM_RC    result;
    result = TPM_HANDLE_Unmarshal((TPM_HANDLE *)target, buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
   if (*target == TPM_RS_PW) {
        if(flag)
            return TPM_RC_SUCCESS;
        else
            return TPM_RC_VALUE;
    }
    if((*target < HMAC_SESSION_FIRST) || (*target >  HMAC_SESSION_LAST))
        if((*target < POLICY_SESSION_FIRST) || (*target > POLICY_SESSION_LAST))
            return TPM_RC_VALUE;
    return TPM_RC_SUCCESS;
}

UINT16
TPMI_SH_AUTH_SESSION_Marshal(TPMI_SH_AUTH_SESSION *source, BYTE **buffer, INT32 *size)
{
    return UINT32_Marshal((UINT32 *)source, buffer, size);
}


// Table 43 -- TPMI_SH_HMAC Type <I/O>
TPM_RC
TPMI_SH_HMAC_Unmarshal(TPMI_SH_HMAC *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPM_HANDLE_Unmarshal((TPM_HANDLE *)target, buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    if((*target < HMAC_SESSION_FIRST) || (*target > HMAC_SESSION_LAST))
        return TPM_RC_VALUE;
    return TPM_RC_SUCCESS;
}

UINT16
TPMI_SH_HMAC_Marshal(TPMI_SH_HMAC *source, BYTE **buffer, INT32 *size)
{
    return UINT32_Marshal((UINT32 *)source, buffer, size);
}


// Table 44 -- TPMI_SH_POLICY Type <I/O>
TPM_RC
TPMI_SH_POLICY_Unmarshal(TPMI_SH_POLICY *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPM_HANDLE_Unmarshal((TPM_HANDLE *)target, buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    if((*target < POLICY_SESSION_FIRST) || (*target > POLICY_SESSION_LAST))
        return TPM_RC_VALUE;
    return TPM_RC_SUCCESS;
}

UINT16
TPMI_SH_POLICY_Marshal(TPMI_SH_POLICY *source, BYTE **buffer, INT32 *size)
{
    return UINT32_Marshal((UINT32 *)source, buffer, size);
}


// Table 45 -- TPMI_DH_CONTEXT Type <I/O>
TPM_RC
TPMI_DH_CONTEXT_Unmarshal(TPMI_DH_CONTEXT *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPM_HANDLE_Unmarshal((TPM_HANDLE *)target, buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    if((*target < HMAC_SESSION_FIRST) || (*target >  HMAC_SESSION_LAST))
        if((*target < POLICY_SESSION_FIRST) || (*target > POLICY_SESSION_LAST))
            if((*target < TRANSIENT_FIRST) || (*target > TRANSIENT_LAST))
                return TPM_RC_VALUE;
    return TPM_RC_SUCCESS;
}

UINT16
TPMI_DH_CONTEXT_Marshal(TPMI_DH_CONTEXT *source, BYTE **buffer, INT32 *size)
{
    return UINT32_Marshal((UINT32 *)source, buffer, size);
}


// Table 46 -- TPMI_RH_HIERARCHY Type <I/O>
TPM_RC
TPMI_RH_HIERARCHY_Unmarshal(TPMI_RH_HIERARCHY *target, BYTE **buffer, INT32 *size, BOOL flag)
{
    TPM_RC    result;
    result = TPM_HANDLE_Unmarshal((TPM_HANDLE *)target, buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    switch (*target) {
        case TPM_RH_OWNER:
        case TPM_RH_PLATFORM:
        case TPM_RH_ENDORSEMENT:
            break;
        case TPM_RH_NULL:
            if (flag)
                break;
            return TPM_RC_VALUE;
        default:
            return TPM_RC_VALUE;
    }
    return TPM_RC_SUCCESS;
}

UINT16
TPMI_RH_HIERARCHY_Marshal(TPMI_RH_HIERARCHY *source, BYTE **buffer, INT32 *size)
{
    return UINT32_Marshal((UINT32 *)source, buffer, size);
}


// Table 47 -- TPMI_RH_HIERARCHY_AUTH Type <I>
TPM_RC
TPMI_RH_HIERARCHY_AUTH_Unmarshal(TPMI_RH_HIERARCHY_AUTH *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPM_HANDLE_Unmarshal((TPM_HANDLE *)target, buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    switch (*target) {
        case TPM_RH_OWNER:
        case TPM_RH_PLATFORM:
        case TPM_RH_ENDORSEMENT:
        case TPM_RH_LOCKOUT:
            break;
        default:
            return TPM_RC_VALUE;
    }
    return TPM_RC_SUCCESS;
}


// Table 48 -- TPMI_RH_PLATFORM Type <I>
TPM_RC
TPMI_RH_PLATFORM_Unmarshal(TPMI_RH_PLATFORM *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPM_HANDLE_Unmarshal((TPM_HANDLE *)target, buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    switch (*target) {
        case TPM_RH_PLATFORM:
            break;
        default:
            return TPM_RC_VALUE;
    }
    return TPM_RC_SUCCESS;
}


// Table 49 -- TPMI_RH_OWNER Type <I>
TPM_RC
TPMI_RH_OWNER_Unmarshal(TPMI_RH_OWNER *target, BYTE **buffer, INT32 *size, BOOL flag)
{
    TPM_RC    result;
    result = TPM_HANDLE_Unmarshal((TPM_HANDLE *)target, buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    switch (*target) {
        case TPM_RH_OWNER:
            break;
        case TPM_RH_NULL:
            if (flag)
                break;
            return TPM_RC_VALUE;
        default:
            return TPM_RC_VALUE;
    }
    return TPM_RC_SUCCESS;
}


// Table 50 -- TPMI_RH_ENDORSEMENT Type <I>
TPM_RC
TPMI_RH_ENDORSEMENT_Unmarshal(TPMI_RH_ENDORSEMENT *target, BYTE **buffer, INT32 *size, BOOL flag)
{
    TPM_RC    result;
    result = TPM_HANDLE_Unmarshal((TPM_HANDLE *)target, buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    switch (*target) {
        case TPM_RH_ENDORSEMENT:
            break;
        case TPM_RH_NULL:
            if (flag)
                break;
            return TPM_RC_VALUE;
        default:
            return TPM_RC_VALUE;
    }
    return TPM_RC_SUCCESS;
}


// Table 51 -- TPMI_RH_PROVISION Type <I>
TPM_RC
TPMI_RH_PROVISION_Unmarshal(TPMI_RH_PROVISION *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPM_HANDLE_Unmarshal((TPM_HANDLE *)target, buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    switch (*target) {
        case TPM_RH_OWNER:
        case TPM_RH_PLATFORM:
            break;
        default:
            return TPM_RC_VALUE;
    }
    return TPM_RC_SUCCESS;
}


// Table 52 -- TPMI_RH_CLEAR Type <I>
TPM_RC
TPMI_RH_CLEAR_Unmarshal(TPMI_RH_CLEAR *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPM_HANDLE_Unmarshal((TPM_HANDLE *)target, buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    switch (*target) {
        case TPM_RH_LOCKOUT:
        case TPM_RH_PLATFORM:
            break;
        default:
            return TPM_RC_VALUE;
    }
    return TPM_RC_SUCCESS;
}


// Table 53 -- TPMI_RH_NV_AUTH Type <I>
TPM_RC
TPMI_RH_NV_AUTH_Unmarshal(TPMI_RH_NV_AUTH *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPM_HANDLE_Unmarshal((TPM_HANDLE *)target, buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    switch (*target) {
        case TPM_RH_PLATFORM:
        case TPM_RH_OWNER:
            break;
        default:
            if((*target < NV_INDEX_FIRST) || (*target > NV_INDEX_LAST))
                return TPM_RC_VALUE;
    }
    return TPM_RC_SUCCESS;
}


// Table 54 -- TPMI_RH_LOCKOUT Type <I>
TPM_RC
TPMI_RH_LOCKOUT_Unmarshal(TPMI_RH_LOCKOUT *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPM_HANDLE_Unmarshal((TPM_HANDLE *)target, buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    switch (*target) {
        case TPM_RH_LOCKOUT:
            break;
        default:
            return TPM_RC_VALUE;
    }
    return TPM_RC_SUCCESS;
}


// Table 55 -- TPMI_RH_NV_INDEX Type <I/O>
TPM_RC
TPMI_RH_NV_INDEX_Unmarshal(TPMI_RH_NV_INDEX *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPM_HANDLE_Unmarshal((TPM_HANDLE *)target, buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    if((*target < NV_INDEX_FIRST) || (*target > NV_INDEX_LAST))
        return TPM_RC_VALUE;
    return TPM_RC_SUCCESS;
}

UINT16
TPMI_RH_NV_INDEX_Marshal(TPMI_RH_NV_INDEX *source, BYTE **buffer, INT32 *size)
{
    return UINT32_Marshal((UINT32 *)source, buffer, size);
}


// Table 56 -- TPMI_ALG_HASH Type <I/O>
TPM_RC
TPMI_ALG_HASH_Unmarshal(TPMI_ALG_HASH *target, BYTE **buffer, INT32 *size, BOOL flag)
{
    TPM_RC    result;
    result = TPM_ALG_ID_Unmarshal((TPM_ALG_ID *)target, buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    switch (*target) {
#ifdef TPM_ALG_SHA1
        case TPM_ALG_SHA1:
#endif
#ifdef TPM_ALG_SHA256
        case TPM_ALG_SHA256:
#endif
#ifdef TPM_ALG_SM3_256
        case TPM_ALG_SM3_256:
#endif
#ifdef TPM_ALG_SHA384
        case TPM_ALG_SHA384:
#endif
#ifdef TPM_ALG_SHA512
        case TPM_ALG_SHA512:
#endif
            break;
        case TPM_ALG_NULL:
            if (flag)
                break;
            return TPM_RC_HASH;
        default:
            return TPM_RC_HASH;
    }
    return TPM_RC_SUCCESS;
}

UINT16
TPMI_ALG_HASH_Marshal(TPMI_ALG_HASH *source, BYTE **buffer, INT32 *size)
{
    return UINT16_Marshal((UINT16 *)source, buffer, size);
}


// Table 57 -- TPMI_ALG_ASYM Type <I/O>
TPM_RC
TPMI_ALG_ASYM_Unmarshal(TPMI_ALG_ASYM *target, BYTE **buffer, INT32 *size, BOOL flag)
{
    TPM_RC    result;
    result = TPM_ALG_ID_Unmarshal((TPM_ALG_ID *)target, buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    switch (*target) {
#ifdef TPM_ALG_RSA
        case TPM_ALG_RSA:
#endif
#ifdef TPM_ALG_ECC
        case TPM_ALG_ECC:
#endif
            break;
        case TPM_ALG_NULL:
            if (flag)
                break;
            return TPM_RC_ASYMMETRIC;
        default:
            return TPM_RC_ASYMMETRIC;
    }
    return TPM_RC_SUCCESS;
}

UINT16
TPMI_ALG_ASYM_Marshal(TPMI_ALG_ASYM *source, BYTE **buffer, INT32 *size)
{
    return UINT16_Marshal((UINT16 *)source, buffer, size);
}


// Table 58 -- TPMI_ALG_SYM Type <I/O>
TPM_RC
TPMI_ALG_SYM_Unmarshal(TPMI_ALG_SYM *target, BYTE **buffer, INT32 *size, BOOL flag)
{
    TPM_RC    result;
    result = TPM_ALG_ID_Unmarshal((TPM_ALG_ID *)target, buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    switch (*target) {
#ifdef TPM_ALG_AES
        case TPM_ALG_AES:
#endif
#ifdef TPM_ALG_SM4
        case TPM_ALG_SM4:
#endif
#ifdef TPM_ALG_XOR
        case TPM_ALG_XOR:
#endif
            break;
        case TPM_ALG_NULL:
            if (flag)
                break;
            return TPM_RC_SYMMETRIC;
        default:
            return TPM_RC_SYMMETRIC;
    }
    return TPM_RC_SUCCESS;
}

UINT16
TPMI_ALG_SYM_Marshal(TPMI_ALG_SYM *source, BYTE **buffer, INT32 *size)
{
    return UINT16_Marshal((UINT16 *)source, buffer, size);
}


// Table 59 -- TPMI_ALG_SYM_OBJECT Type <I/O>
TPM_RC
TPMI_ALG_SYM_OBJECT_Unmarshal(TPMI_ALG_SYM_OBJECT *target, BYTE **buffer, INT32 *size, BOOL flag)
{
    TPM_RC    result;
    result = TPM_ALG_ID_Unmarshal((TPM_ALG_ID *)target, buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    switch (*target) {
#ifdef TPM_ALG_AES
        case TPM_ALG_AES:
#endif
#ifdef TPM_ALG_SM4
        case TPM_ALG_SM4:
#endif
            break;
        case TPM_ALG_NULL:
            if (flag)
                break;
            return TPM_RC_SYMMETRIC;
        default:
            return TPM_RC_SYMMETRIC;
    }
    return TPM_RC_SUCCESS;
}

UINT16
TPMI_ALG_SYM_OBJECT_Marshal(TPMI_ALG_SYM_OBJECT *source, BYTE **buffer, INT32 *size)
{
    return UINT16_Marshal((UINT16 *)source, buffer, size);
}


// Table 60 -- TPMI_ALG_SYM_MODE Type <I/O>
TPM_RC
TPMI_ALG_SYM_MODE_Unmarshal(TPMI_ALG_SYM_MODE *target, BYTE **buffer, INT32 *size, BOOL flag)
{
    TPM_RC    result;
    result = TPM_ALG_ID_Unmarshal((TPM_ALG_ID *)target, buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    switch (*target) {
#ifdef TPM_ALG_CTR
        case TPM_ALG_CTR:
#endif
#ifdef TPM_ALG_OFB
        case TPM_ALG_OFB:
#endif
#ifdef TPM_ALG_CBC
        case TPM_ALG_CBC:
#endif
#ifdef TPM_ALG_CFB
        case TPM_ALG_CFB:
#endif
#ifdef TPM_ALG_ECB
        case TPM_ALG_ECB:
#endif
            break;
        case TPM_ALG_NULL:
            if (flag)
                break;
            return TPM_RC_MODE;
        default:
            return TPM_RC_MODE;
    }
    return TPM_RC_SUCCESS;
}

UINT16
TPMI_ALG_SYM_MODE_Marshal(TPMI_ALG_SYM_MODE *source, BYTE **buffer, INT32 *size)
{
    return UINT16_Marshal((UINT16 *)source, buffer, size);
}


// Table 61 -- TPMI_ALG_KDF Type <I/O>
TPM_RC
TPMI_ALG_KDF_Unmarshal(TPMI_ALG_KDF *target, BYTE **buffer, INT32 *size, BOOL flag)
{
    TPM_RC    result;
    result = TPM_ALG_ID_Unmarshal((TPM_ALG_ID *)target, buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    switch (*target) {
#ifdef TPM_ALG_MGF1
        case TPM_ALG_MGF1:
#endif
#ifdef TPM_ALG_KDF1_SP800_108
        case TPM_ALG_KDF1_SP800_108:
#endif
#ifdef TPM_ALG_KDF1_SP800_56a
        case TPM_ALG_KDF1_SP800_56a:
#endif
#ifdef TPM_ALG_KDF2
        case TPM_ALG_KDF2:
#endif
            break;
        case TPM_ALG_NULL:
            if (flag)
                break;
            return TPM_RC_KDF;
        default:
            return TPM_RC_KDF;
    }
    return TPM_RC_SUCCESS;
}

UINT16
TPMI_ALG_KDF_Marshal(TPMI_ALG_KDF *source, BYTE **buffer, INT32 *size)
{
    return UINT16_Marshal((UINT16 *)source, buffer, size);
}


// Table 62 -- TPMI_ALG_SIG_SCHEME Type <I/O>
TPM_RC
TPMI_ALG_SIG_SCHEME_Unmarshal(TPMI_ALG_SIG_SCHEME *target, BYTE **buffer, INT32 *size, BOOL flag)
{
    TPM_RC    result;
    result = TPM_ALG_ID_Unmarshal((TPM_ALG_ID *)target, buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    switch (*target) {
#ifdef TPM_ALG_RSASSA
        case TPM_ALG_RSASSA:
#endif
#ifdef TPM_ALG_RSAPSS
        case TPM_ALG_RSAPSS:
#endif
#ifdef TPM_ALG_ECDSA
        case TPM_ALG_ECDSA:
#endif
#ifdef TPM_ALG_ECDAA
        case TPM_ALG_ECDAA:
#endif
#ifdef TPM_ALG_ECSCHNORR
        case TPM_ALG_ECSCHNORR:
#endif
#ifdef TPM_ALG_SM2
        case TPM_ALG_SM2:
#endif
#ifdef TPM_ALG_HMAC
        case TPM_ALG_HMAC:
#endif
            break;
        case TPM_ALG_NULL:
            if (flag)
                break;
            return TPM_RC_SCHEME;
        default:
            return TPM_RC_SCHEME;
    }
    return TPM_RC_SUCCESS;
}

UINT16
TPMI_ALG_SIG_SCHEME_Marshal(TPMI_ALG_SIG_SCHEME *source, BYTE **buffer, INT32 *size)
{
    return UINT16_Marshal((UINT16 *)source, buffer, size);
}


// Table 63 -- TPMI_ECC_KEY_EXCHANGE Type <I/O>
TPM_RC
TPMI_ECC_KEY_EXCHANGE_Unmarshal(TPMI_ECC_KEY_EXCHANGE *target, BYTE **buffer, INT32 *size, BOOL flag)
{
    TPM_RC    result;
    result = TPM_ALG_ID_Unmarshal((TPM_ALG_ID *)target, buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    switch (*target) {
#ifdef TPM_ALG_ECDH
        case TPM_ALG_ECDH:
#endif
#ifdef TPM_ALG_ECMQV
        case TPM_ALG_ECMQV:
#endif
#ifdef TPM_ALG_SM2
        case TPM_ALG_SM2:
#endif
            break;
        case TPM_ALG_NULL:
            if (flag)
                break;
            return TPM_RC_SCHEME;
        default:
            return TPM_RC_SCHEME;
    }
    return TPM_RC_SUCCESS;
}

UINT16
TPMI_ECC_KEY_EXCHANGE_Marshal(TPMI_ECC_KEY_EXCHANGE *source, BYTE **buffer, INT32 *size)
{
    return UINT16_Marshal((UINT16 *)source, buffer, size);
}


// Table 64 -- TPMI_ST_COMMAND_TAG Type <I/O>
TPM_RC
TPMI_ST_COMMAND_TAG_Unmarshal(TPMI_ST_COMMAND_TAG *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPM_ST_Unmarshal((TPM_ST *)target, buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    switch (*target) {
        case TPM_ST_NO_SESSIONS:
        case TPM_ST_SESSIONS:
            break;
        default:
            return TPM_RC_BAD_TAG;
    }
    return TPM_RC_SUCCESS;
}

UINT16
TPMI_ST_COMMAND_TAG_Marshal(TPMI_ST_COMMAND_TAG *source, BYTE **buffer, INT32 *size)
{
    return UINT16_Marshal((UINT16 *)source, buffer, size);
}


// Table 65 -- TPMS_ALGORITHM_DESCRIPTION Structure <O,S>
UINT16
TPMS_ALGORITHM_DESCRIPTION_Marshal(TPMS_ALGORITHM_DESCRIPTION *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPM_ALG_ID_Marshal((TPM_ALG_ID *)&(source->alg), buffer, size));
    result = (UINT16)(result + TPMA_ALGORITHM_Marshal((TPMA_ALGORITHM *)&(source->attributes), buffer, size));

    return result;
}


// Table 66 -- TPMU_HA Union <I/O,S>
TPM_RC
TPMU_HA_Unmarshal(TPMU_HA *target, BYTE **buffer, INT32 *size, UINT32 selector)
{
    switch(selector) {
#ifdef TPM_ALG_SHA1
        case TPM_ALG_SHA1:
            return BYTE_Array_Unmarshal((BYTE *)(target->sha1), buffer, size, (INT32)SHA1_DIGEST_SIZE);
#endif
#ifdef TPM_ALG_SHA256
        case TPM_ALG_SHA256:
            return BYTE_Array_Unmarshal((BYTE *)(target->sha256), buffer, size, (INT32)SHA256_DIGEST_SIZE);
#endif
#ifdef TPM_ALG_SM3_256
        case TPM_ALG_SM3_256:
            return BYTE_Array_Unmarshal((BYTE *)(target->sm3_256), buffer, size, (INT32)SM3_256_DIGEST_SIZE);
#endif
#ifdef TPM_ALG_SHA384
        case TPM_ALG_SHA384:
            return BYTE_Array_Unmarshal((BYTE *)(target->sha384), buffer, size, (INT32)SHA384_DIGEST_SIZE);
#endif
#ifdef TPM_ALG_SHA512
        case TPM_ALG_SHA512:
            return BYTE_Array_Unmarshal((BYTE *)(target->sha512), buffer, size, (INT32)SHA512_DIGEST_SIZE);
#endif
        case TPM_ALG_NULL:
                    return TPM_RC_SUCCESS;
    }
    return TPM_RC_SELECTOR;
}

UINT16
TPMU_HA_Marshal(TPMU_HA *source, BYTE **buffer, INT32 *size, UINT32 selector)
{
    switch(selector) {
#ifdef TPM_ALG_SHA1
        case TPM_ALG_SHA1:
            return BYTE_Array_Marshal((BYTE *)(source->sha1), buffer, size, (INT32)SHA1_DIGEST_SIZE);
#endif
#ifdef TPM_ALG_SHA256
        case TPM_ALG_SHA256:
            return BYTE_Array_Marshal((BYTE *)(source->sha256), buffer, size, (INT32)SHA256_DIGEST_SIZE);
#endif
#ifdef TPM_ALG_SM3_256
        case TPM_ALG_SM3_256:
            return BYTE_Array_Marshal((BYTE *)(source->sm3_256), buffer, size, (INT32)SM3_256_DIGEST_SIZE);
#endif
#ifdef TPM_ALG_SHA384
        case TPM_ALG_SHA384:
            return BYTE_Array_Marshal((BYTE *)(source->sha384), buffer, size, (INT32)SHA384_DIGEST_SIZE);
#endif
#ifdef TPM_ALG_SHA512
        case TPM_ALG_SHA512:
            return BYTE_Array_Marshal((BYTE *)(source->sha512), buffer, size, (INT32)SHA512_DIGEST_SIZE);
#endif
        case TPM_ALG_NULL:
                    return 0;
    }
    pAssert(FALSE);
    return 0;
}


// Table 67 -- TPMT_HA Structure <I/O>
TPM_RC
TPMT_HA_Unmarshal(TPMT_HA *target, BYTE **buffer, INT32 *size, BOOL flag)
{
    TPM_RC    result;
    result = TPMI_ALG_HASH_Unmarshal((TPMI_ALG_HASH *)&(target->hashAlg), buffer, size, flag);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPMU_HA_Unmarshal((TPMU_HA *)&(target->digest), buffer, size, (UINT32)target->hashAlg);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPMT_HA_Marshal(TPMT_HA *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPMI_ALG_HASH_Marshal((TPMI_ALG_HASH *)&(source->hashAlg), buffer, size));
    result = (UINT16)(result + TPMU_HA_Marshal((TPMU_HA *)&(source->digest), buffer, size, (UINT32)source->hashAlg));

    return result;
}


// Table 68 -- TPM2B_DIGEST Structure <I/O>
TPM_RC
TPM2B_DIGEST_Unmarshal(TPM2B_DIGEST *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = UINT16_Unmarshal((UINT16 *)&(target->t.size), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    // if size equal to 0, the rest of the structure is a zero buffer.  Stop processing
    if(target->t.size == 0) return TPM_RC_SUCCESS;
    if((target->t.size) > sizeof(TPMU_HA))
        return TPM_RC_SIZE;
    result = BYTE_Array_Unmarshal((BYTE *)(target->t.buffer), buffer, size, (INT32)(target->t.size));
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPM2B_DIGEST_Marshal(TPM2B_DIGEST *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + UINT16_Marshal((UINT16 *)&(source->t.size), buffer, size));
    // if size equal to 0, the rest of the structure is a zero buffer.  Stop processing
    if(source->t.size == 0) return result;
    result = (UINT16)(result + BYTE_Array_Marshal((BYTE *)(source->t.buffer), buffer, size, (INT32)(source->t.size)));

    return result;
}


// Table 69 -- TPM2B_DATA Structure <I/O>
TPM_RC
TPM2B_DATA_Unmarshal(TPM2B_DATA *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = UINT16_Unmarshal((UINT16 *)&(target->t.size), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    // if size equal to 0, the rest of the structure is a zero buffer.  Stop processing
    if(target->t.size == 0) return TPM_RC_SUCCESS;
    if((target->t.size) > sizeof(TPMT_HA))
        return TPM_RC_SIZE;
    result = BYTE_Array_Unmarshal((BYTE *)(target->t.buffer), buffer, size, (INT32)(target->t.size));
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPM2B_DATA_Marshal(TPM2B_DATA *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + UINT16_Marshal((UINT16 *)&(source->t.size), buffer, size));
    // if size equal to 0, the rest of the structure is a zero buffer.  Stop processing
    if(source->t.size == 0) return result;
    result = (UINT16)(result + BYTE_Array_Marshal((BYTE *)(source->t.buffer), buffer, size, (INT32)(source->t.size)));

    return result;
}


// Table 70 -- TPM2B_NONCE Types <I/O>
TPM_RC
TPM2B_NONCE_Unmarshal(TPM2B_NONCE *target, BYTE **buffer, INT32 *size)
{
    return TPM2B_DIGEST_Unmarshal((TPM2B_DIGEST *)target, buffer, size);
}


UINT16
TPM2B_NONCE_Marshal(TPM2B_NONCE *source, BYTE **buffer, INT32 *size)
{
    return TPM2B_DIGEST_Marshal((TPM2B_DIGEST *)source, buffer, size);
}



// Table 71 -- TPM2B_AUTH Types <I/O>
TPM_RC
TPM2B_AUTH_Unmarshal(TPM2B_AUTH *target, BYTE **buffer, INT32 *size)
{
    return TPM2B_DIGEST_Unmarshal((TPM2B_DIGEST *)target, buffer, size);
}


UINT16
TPM2B_AUTH_Marshal(TPM2B_AUTH *source, BYTE **buffer, INT32 *size)
{
    return TPM2B_DIGEST_Marshal((TPM2B_DIGEST *)source, buffer, size);
}



// Table 72 -- TPM2B_OPERAND Types <I/O>
TPM_RC
TPM2B_OPERAND_Unmarshal(TPM2B_OPERAND *target, BYTE **buffer, INT32 *size)
{
    return TPM2B_DIGEST_Unmarshal((TPM2B_DIGEST *)target, buffer, size);
}


UINT16
TPM2B_OPERAND_Marshal(TPM2B_OPERAND *source, BYTE **buffer, INT32 *size)
{
    return TPM2B_DIGEST_Marshal((TPM2B_DIGEST *)source, buffer, size);
}



// Table 73 -- TPM2B_EVENT Structure <I/O>
TPM_RC
TPM2B_EVENT_Unmarshal(TPM2B_EVENT *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = UINT16_Unmarshal((UINT16 *)&(target->t.size), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    // if size equal to 0, the rest of the structure is a zero buffer.  Stop processing
    if(target->t.size == 0) return TPM_RC_SUCCESS;
    if((target->t.size) > 1024)
        return TPM_RC_SIZE;
    result = BYTE_Array_Unmarshal((BYTE *)(target->t.buffer), buffer, size, (INT32)(target->t.size));
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPM2B_EVENT_Marshal(TPM2B_EVENT *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + UINT16_Marshal((UINT16 *)&(source->t.size), buffer, size));
    // if size equal to 0, the rest of the structure is a zero buffer.  Stop processing
    if(source->t.size == 0) return result;
    result = (UINT16)(result + BYTE_Array_Marshal((BYTE *)(source->t.buffer), buffer, size, (INT32)(source->t.size)));

    return result;
}


// Table 74 -- TPM2B_MAX_BUFFER Structure <I/O>
TPM_RC
TPM2B_MAX_BUFFER_Unmarshal(TPM2B_MAX_BUFFER *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = UINT16_Unmarshal((UINT16 *)&(target->t.size), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    // if size equal to 0, the rest of the structure is a zero buffer.  Stop processing
    if(target->t.size == 0) return TPM_RC_SUCCESS;
    if((target->t.size) > MAX_DIGEST_BUFFER)
        return TPM_RC_SIZE;
    result = BYTE_Array_Unmarshal((BYTE *)(target->t.buffer), buffer, size, (INT32)(target->t.size));
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPM2B_MAX_BUFFER_Marshal(TPM2B_MAX_BUFFER *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + UINT16_Marshal((UINT16 *)&(source->t.size), buffer, size));
    // if size equal to 0, the rest of the structure is a zero buffer.  Stop processing
    if(source->t.size == 0) return result;
    result = (UINT16)(result + BYTE_Array_Marshal((BYTE *)(source->t.buffer), buffer, size, (INT32)(source->t.size)));

    return result;
}


// Table 75 -- TPM2B_MAX_NV_BUFFER Structure <I/O>
TPM_RC
TPM2B_MAX_NV_BUFFER_Unmarshal(TPM2B_MAX_NV_BUFFER *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = UINT16_Unmarshal((UINT16 *)&(target->t.size), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    // if size equal to 0, the rest of the structure is a zero buffer.  Stop processing
    if(target->t.size == 0) return TPM_RC_SUCCESS;
    if((target->t.size) > MAX_NV_INDEX_SIZE)
        return TPM_RC_SIZE;
    result = BYTE_Array_Unmarshal((BYTE *)(target->t.buffer), buffer, size, (INT32)(target->t.size));
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPM2B_MAX_NV_BUFFER_Marshal(TPM2B_MAX_NV_BUFFER *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + UINT16_Marshal((UINT16 *)&(source->t.size), buffer, size));
    // if size equal to 0, the rest of the structure is a zero buffer.  Stop processing
    if(source->t.size == 0) return result;
    result = (UINT16)(result + BYTE_Array_Marshal((BYTE *)(source->t.buffer), buffer, size, (INT32)(source->t.size)));

    return result;
}


// Table 76 -- TPM2B_TIMEOUT Structure <I/O>
TPM_RC
TPM2B_TIMEOUT_Unmarshal(TPM2B_TIMEOUT *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = UINT16_Unmarshal((UINT16 *)&(target->t.size), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    // if size equal to 0, the rest of the structure is a zero buffer.  Stop processing
    if(target->t.size == 0) return TPM_RC_SUCCESS;
    if((target->t.size) > sizeof(UINT64))
        return TPM_RC_SIZE;
    result = BYTE_Array_Unmarshal((BYTE *)(target->t.buffer), buffer, size, (INT32)(target->t.size));
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPM2B_TIMEOUT_Marshal(TPM2B_TIMEOUT *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + UINT16_Marshal((UINT16 *)&(source->t.size), buffer, size));
    // if size equal to 0, the rest of the structure is a zero buffer.  Stop processing
    if(source->t.size == 0) return result;
    result = (UINT16)(result + BYTE_Array_Marshal((BYTE *)(source->t.buffer), buffer, size, (INT32)(source->t.size)));

    return result;
}


// Table 77 -- TPM2B_IV Structure <I/O>
TPM_RC
TPM2B_IV_Unmarshal(TPM2B_IV *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = UINT16_Unmarshal((UINT16 *)&(target->t.size), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    // if size equal to 0, the rest of the structure is a zero buffer.  Stop processing
    if(target->t.size == 0) return TPM_RC_SUCCESS;
    if((target->t.size) > MAX_SYM_BLOCK_SIZE)
        return TPM_RC_SIZE;
    result = BYTE_Array_Unmarshal((BYTE *)(target->t.buffer), buffer, size, (INT32)(target->t.size));
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPM2B_IV_Marshal(TPM2B_IV *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + UINT16_Marshal((UINT16 *)&(source->t.size), buffer, size));
    // if size equal to 0, the rest of the structure is a zero buffer.  Stop processing
    if(source->t.size == 0) return result;
    result = (UINT16)(result + BYTE_Array_Marshal((BYTE *)(source->t.buffer), buffer, size, (INT32)(source->t.size)));

    return result;
}


// Table 79 -- TPM2B_NAME Structure <I/O>
TPM_RC
TPM2B_NAME_Unmarshal(TPM2B_NAME *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = UINT16_Unmarshal((UINT16 *)&(target->t.size), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    // if size equal to 0, the rest of the structure is a zero buffer.  Stop processing
    if(target->t.size == 0) return TPM_RC_SUCCESS;
    if((target->t.size) > sizeof(TPMU_NAME))
        return TPM_RC_SIZE;
    result = BYTE_Array_Unmarshal((BYTE *)(target->t.name), buffer, size, (INT32)(target->t.size));
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPM2B_NAME_Marshal(TPM2B_NAME *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + UINT16_Marshal((UINT16 *)&(source->t.size), buffer, size));
    // if size equal to 0, the rest of the structure is a zero buffer.  Stop processing
    if(source->t.size == 0) return result;
    result = (UINT16)(result + BYTE_Array_Marshal((BYTE *)(source->t.name), buffer, size, (INT32)(source->t.size)));

    return result;
}


// Table 80 -- TPMS_PCR_SELECT Structure <I/O>
TPM_RC
TPMS_PCR_SELECT_Unmarshal(TPMS_PCR_SELECT *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = UINT8_Unmarshal((UINT8 *)&(target->sizeofSelect), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    if( (target->sizeofSelect < PCR_SELECT_MIN))
        return TPM_RC_VALUE;
    if((target->sizeofSelect) > PCR_SELECT_MAX)
        return TPM_RC_VALUE;
    result = BYTE_Array_Unmarshal((BYTE *)(target->pcrSelect), buffer, size, (INT32)(target->sizeofSelect));
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPMS_PCR_SELECT_Marshal(TPMS_PCR_SELECT *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + UINT8_Marshal((UINT8 *)&(source->sizeofSelect), buffer, size));
    result = (UINT16)(result + BYTE_Array_Marshal((BYTE *)(source->pcrSelect), buffer, size, (INT32)(source->sizeofSelect)));

    return result;
}


// Table 81 -- TPMS_PCR_SELECTION Structure <I/O>
TPM_RC
TPMS_PCR_SELECTION_Unmarshal(TPMS_PCR_SELECTION *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPMI_ALG_HASH_Unmarshal((TPMI_ALG_HASH *)&(target->hash), buffer, size, FALSE);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = UINT8_Unmarshal((UINT8 *)&(target->sizeofSelect), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    if( (target->sizeofSelect < PCR_SELECT_MIN))
        return TPM_RC_VALUE;
    if((target->sizeofSelect) > PCR_SELECT_MAX)
        return TPM_RC_VALUE;
    result = BYTE_Array_Unmarshal((BYTE *)(target->pcrSelect), buffer, size, (INT32)(target->sizeofSelect));
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPMS_PCR_SELECTION_Marshal(TPMS_PCR_SELECTION *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPMI_ALG_HASH_Marshal((TPMI_ALG_HASH *)&(source->hash), buffer, size));
    result = (UINT16)(result + UINT8_Marshal((UINT8 *)&(source->sizeofSelect), buffer, size));
    result = (UINT16)(result + BYTE_Array_Marshal((BYTE *)(source->pcrSelect), buffer, size, (INT32)(source->sizeofSelect)));

    return result;
}


// Table 84 -- TPMT_TK_CREATION Structure <I/O>
TPM_RC
TPMT_TK_CREATION_Unmarshal(TPMT_TK_CREATION *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPM_ST_Unmarshal((TPM_ST *)&(target->tag), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    if( ((target->tag) != TPM_ST_CREATION))
        return TPM_RC_TAG;
    result = TPMI_RH_HIERARCHY_Unmarshal((TPMI_RH_HIERARCHY *)&(target->hierarchy), buffer, size, TRUE);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPM2B_DIGEST_Unmarshal((TPM2B_DIGEST *)&(target->digest), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPMT_TK_CREATION_Marshal(TPMT_TK_CREATION *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPM_ST_Marshal((TPM_ST *)&(source->tag), buffer, size));
    result = (UINT16)(result + TPMI_RH_HIERARCHY_Marshal((TPMI_RH_HIERARCHY *)&(source->hierarchy), buffer, size));
    result = (UINT16)(result + TPM2B_DIGEST_Marshal((TPM2B_DIGEST *)&(source->digest), buffer, size));

    return result;
}


// Table 85 -- TPMT_TK_VERIFIED Structure <I/O>
TPM_RC
TPMT_TK_VERIFIED_Unmarshal(TPMT_TK_VERIFIED *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPM_ST_Unmarshal((TPM_ST *)&(target->tag), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    if( ((target->tag) != TPM_ST_VERIFIED))
        return TPM_RC_TAG;
    result = TPMI_RH_HIERARCHY_Unmarshal((TPMI_RH_HIERARCHY *)&(target->hierarchy), buffer, size, TRUE);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPM2B_DIGEST_Unmarshal((TPM2B_DIGEST *)&(target->digest), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPMT_TK_VERIFIED_Marshal(TPMT_TK_VERIFIED *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPM_ST_Marshal((TPM_ST *)&(source->tag), buffer, size));
    result = (UINT16)(result + TPMI_RH_HIERARCHY_Marshal((TPMI_RH_HIERARCHY *)&(source->hierarchy), buffer, size));
    result = (UINT16)(result + TPM2B_DIGEST_Marshal((TPM2B_DIGEST *)&(source->digest), buffer, size));

    return result;
}


// Table 86 -- TPMT_TK_AUTH Structure <I/O>
TPM_RC
TPMT_TK_AUTH_Unmarshal(TPMT_TK_AUTH *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPM_ST_Unmarshal((TPM_ST *)&(target->tag), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    if( ((target->tag) != TPM_ST_AUTH_SIGNED)
     && ((target->tag) != TPM_ST_AUTH_SECRET))
        return TPM_RC_TAG;
    result = TPMI_RH_HIERARCHY_Unmarshal((TPMI_RH_HIERARCHY *)&(target->hierarchy), buffer, size, TRUE);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPM2B_DIGEST_Unmarshal((TPM2B_DIGEST *)&(target->digest), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPMT_TK_AUTH_Marshal(TPMT_TK_AUTH *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPM_ST_Marshal((TPM_ST *)&(source->tag), buffer, size));
    result = (UINT16)(result + TPMI_RH_HIERARCHY_Marshal((TPMI_RH_HIERARCHY *)&(source->hierarchy), buffer, size));
    result = (UINT16)(result + TPM2B_DIGEST_Marshal((TPM2B_DIGEST *)&(source->digest), buffer, size));

    return result;
}


// Table 87 -- TPMT_TK_HASHCHECK Structure <I/O>
TPM_RC
TPMT_TK_HASHCHECK_Unmarshal(TPMT_TK_HASHCHECK *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPM_ST_Unmarshal((TPM_ST *)&(target->tag), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    if( ((target->tag) != TPM_ST_HASHCHECK))
        return TPM_RC_TAG;
    result = TPMI_RH_HIERARCHY_Unmarshal((TPMI_RH_HIERARCHY *)&(target->hierarchy), buffer, size, TRUE);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPM2B_DIGEST_Unmarshal((TPM2B_DIGEST *)&(target->digest), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPMT_TK_HASHCHECK_Marshal(TPMT_TK_HASHCHECK *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPM_ST_Marshal((TPM_ST *)&(source->tag), buffer, size));
    result = (UINT16)(result + TPMI_RH_HIERARCHY_Marshal((TPMI_RH_HIERARCHY *)&(source->hierarchy), buffer, size));
    result = (UINT16)(result + TPM2B_DIGEST_Marshal((TPM2B_DIGEST *)&(source->digest), buffer, size));

    return result;
}


// Table 88 -- TPMS_ALG_PROPERTY Structure <O,S>
UINT16
TPMS_ALG_PROPERTY_Marshal(TPMS_ALG_PROPERTY *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPM_ALG_ID_Marshal((TPM_ALG_ID *)&(source->alg), buffer, size));
    result = (UINT16)(result + TPMA_ALGORITHM_Marshal((TPMA_ALGORITHM *)&(source->algProperties), buffer, size));

    return result;
}

TPM_RC
TPMS_ALG_PROPERTY_Unmarshal(TPMS_ALG_PROPERTY *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPM_ALG_ID_Unmarshal((TPM_ALG_ID *)&(target->alg), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPMA_ALGORITHM_Unmarshal((TPMA_ALGORITHM *)&(target->algProperties), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}


// Table 89 -- TPMS_TAGGED_PROPERTY Structure <O,S>
UINT16
TPMS_TAGGED_PROPERTY_Marshal(TPMS_TAGGED_PROPERTY *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPM_PT_Marshal((TPM_PT *)&(source->property), buffer, size));
    result = (UINT16)(result + UINT32_Marshal((UINT32 *)&(source->value), buffer, size));

    return result;
}

TPM_RC
TPMS_TAGGED_PROPERTY_Unmarshal(TPMS_TAGGED_PROPERTY *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPM_PT_Unmarshal((TPM_PT *)&(target->property), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = UINT32_Unmarshal((UINT32 *)&(target->value), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}


// Table 90 -- TPMS_TAGGED_PCR_SELECT Structure <O,S>
UINT16
TPMS_TAGGED_PCR_SELECT_Marshal(TPMS_TAGGED_PCR_SELECT *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPM_PT_Marshal((TPM_PT *)&(source->tag), buffer, size));
    result = (UINT16)(result + UINT8_Marshal((UINT8 *)&(source->sizeofSelect), buffer, size));
    result = (UINT16)(result + BYTE_Array_Marshal((BYTE *)(source->pcrSelect), buffer, size, (INT32)(source->sizeofSelect)));

    return result;
}

TPM_RC
TPMS_TAGGED_PCR_SELECT_Unmarshal(TPMS_TAGGED_PCR_SELECT *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPM_PT_Unmarshal((TPM_PT *)&(target->tag), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = UINT8_Unmarshal((UINT8 *)&(target->sizeofSelect), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = BYTE_Array_Unmarshal((BYTE *)(target->pcrSelect), buffer, size, (INT32)(target->sizeofSelect));
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}


// Table 91 -- TPML_CC Structure <I/O>
TPM_RC
TPML_CC_Unmarshal(TPML_CC *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = UINT32_Unmarshal((UINT32 *)&(target->count), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
//    if((target->count) > MAX_CAP_CC)
//        return TPM_RC_SIZE;
    result = TPM_CC_Array_Unmarshal((TPM_CC *)(target->commandCodes), buffer, size, (INT32)(target->count));
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPML_CC_Marshal(TPML_CC *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + UINT32_Marshal((UINT32 *)&(source->count), buffer, size));
    result = (UINT16)(result + TPM_CC_Array_Marshal((TPM_CC *)(source->commandCodes), buffer, size, (INT32)(source->count)));

    return result;
}


// Table 92 -- TPML_CCA Structure <O,S>
UINT16
TPML_CCA_Marshal(TPML_CCA *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + UINT32_Marshal((UINT32 *)&(source->count), buffer, size));
    result = (UINT16)(result + TPMA_CC_Array_Marshal((TPMA_CC *)(source->commandAttributes), buffer, size, (INT32)(source->count)));

    return result;
}

TPM_RC
TPML_CCA_Unmarshal(TPML_CCA *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = UINT32_Unmarshal((UINT32 *)&(target->count), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPMA_CC_Array_Unmarshal((TPMA_CC *)(target->commandAttributes), buffer, size, (INT32)(target->count));
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}


// Table 93 -- TPML_ALG Structure <I/O>
TPM_RC
TPML_ALG_Unmarshal(TPML_ALG *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = UINT32_Unmarshal((UINT32 *)&(target->count), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
//    if((target->count) > MAX_ALG_LIST_SIZE)
//        return TPM_RC_SIZE;
    result = TPM_ALG_ID_Array_Unmarshal((TPM_ALG_ID *)(target->algorithms), buffer, size, (INT32)(target->count));
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPML_ALG_Marshal(TPML_ALG *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + UINT32_Marshal((UINT32 *)&(source->count), buffer, size));
    result = (UINT16)(result + TPM_ALG_ID_Array_Marshal((TPM_ALG_ID *)(source->algorithms), buffer, size, (INT32)(source->count)));

    return result;
}


// Table 94 -- TPML_HANDLE Structure <O,S>
UINT16
TPML_HANDLE_Marshal(TPML_HANDLE *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + UINT32_Marshal((UINT32 *)&(source->count), buffer, size));
    result = (UINT16)(result + TPM_HANDLE_Array_Marshal((TPM_HANDLE *)(source->handle), buffer, size, (INT32)(source->count)));

    return result;
}

TPM_RC
TPML_HANDLE_Unmarshal(TPML_HANDLE *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = UINT32_Unmarshal((UINT32 *)&(target->count), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
//    if((target->count) > MAX_ALG_LIST_SIZE)
//        return TPM_RC_SIZE;
    result = TPM_HANDLE_Array_Unmarshal((TPM_HANDLE *)(target->handle), buffer, size, (INT32)(target->count));
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}


// Table 95 -- TPML_DIGEST Structure <I/O>
TPM_RC
TPML_DIGEST_Unmarshal(TPML_DIGEST *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = UINT32_Unmarshal((UINT32 *)&(target->count), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
//    if( (target->count < 2))
//        return TPM_RC_SIZE;
//    if((target->count) > 8)
//        return TPM_RC_SIZE;
    result = TPM2B_DIGEST_Array_Unmarshal((TPM2B_DIGEST *)(target->digests), buffer, size, (INT32)(target->count));
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPML_DIGEST_Marshal(TPML_DIGEST *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + UINT32_Marshal((UINT32 *)&(source->count), buffer, size));
    result = (UINT16)(result + TPM2B_DIGEST_Array_Marshal((TPM2B_DIGEST *)(source->digests), buffer, size, (INT32)(source->count)));

    return result;
}


// Table 96 -- TPML_DIGEST_VALUES Structure <I/O>
TPM_RC
TPML_DIGEST_VALUES_Unmarshal(TPML_DIGEST_VALUES *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = UINT32_Unmarshal((UINT32 *)&(target->count), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
//    if((target->count) > HASH_COUNT)
//        return TPM_RC_SIZE;
    result = TPMT_HA_Array_Unmarshal((TPMT_HA *)(target->digests), buffer, size, FALSE, (INT32)(target->count));
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPML_DIGEST_VALUES_Marshal(TPML_DIGEST_VALUES *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + UINT32_Marshal((UINT32 *)&(source->count), buffer, size));
    result = (UINT16)(result + TPMT_HA_Array_Marshal((TPMT_HA *)(source->digests), buffer, size, (INT32)(source->count)));

    return result;
}


// Table 97 -- TPM2B_DIGEST_VALUES Structure <I/O>
TPM_RC
TPM2B_DIGEST_VALUES_Unmarshal(TPM2B_DIGEST_VALUES *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = UINT16_Unmarshal((UINT16 *)&(target->t.size), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    // if size equal to 0, the rest of the structure is a zero buffer.  Stop processing
    if(target->t.size == 0) return TPM_RC_SUCCESS;
//    if((target->t.size) > sizeof(TPML_DIGEST_VALUES))
//        return TPM_RC_SIZE;
    result = BYTE_Array_Unmarshal((BYTE *)(target->t.buffer), buffer, size, (INT32)(target->t.size));
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPM2B_DIGEST_VALUES_Marshal(TPM2B_DIGEST_VALUES *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + UINT16_Marshal((UINT16 *)&(source->t.size), buffer, size));
    // if size equal to 0, the rest of the structure is a zero buffer.  Stop processing
    if(source->t.size == 0) return result;
    result = (UINT16)(result + BYTE_Array_Marshal((BYTE *)(source->t.buffer), buffer, size, (INT32)(source->t.size)));

    return result;
}


// Table 98 -- TPML_PCR_SELECTION Structure <I/O>
TPM_RC
TPML_PCR_SELECTION_Unmarshal(TPML_PCR_SELECTION *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = UINT32_Unmarshal((UINT32 *)&(target->count), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
//    if((target->count) > HASH_COUNT)
//        return TPM_RC_SIZE;
    result = TPMS_PCR_SELECTION_Array_Unmarshal((TPMS_PCR_SELECTION *)(target->pcrSelections), buffer, size, (INT32)(target->count));
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPML_PCR_SELECTION_Marshal(TPML_PCR_SELECTION *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + UINT32_Marshal((UINT32 *)&(source->count), buffer, size));
    result = (UINT16)(result + TPMS_PCR_SELECTION_Array_Marshal((TPMS_PCR_SELECTION *)(source->pcrSelections), buffer, size, (INT32)(source->count)));

    return result;
}


// Table 99 -- TPML_ALG_PROPERTY Structure <O,S>
UINT16
TPML_ALG_PROPERTY_Marshal(TPML_ALG_PROPERTY *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + UINT32_Marshal((UINT32 *)&(source->count), buffer, size));
    result = (UINT16)(result + TPMS_ALG_PROPERTY_Array_Marshal((TPMS_ALG_PROPERTY *)(source->algProperties), buffer, size, (INT32)(source->count)));

    return result;
}

TPM_RC
TPML_ALG_PROPERTY_Unmarshal(TPML_ALG_PROPERTY *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = UINT32_Unmarshal((UINT32 *)&(target->count), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
//    if((target->count) > HASH_COUNT)
//        return TPM_RC_SIZE;
    result = TPMS_ALG_PROPERTY_Array_Unmarshal((TPMS_ALG_PROPERTY *)(target->algProperties), buffer, size, (INT32)(target->count));
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}


// Table 100 -- TPML_TAGGED_TPM_PROPERTY Structure <O,S>
UINT16
TPML_TAGGED_TPM_PROPERTY_Marshal(TPML_TAGGED_TPM_PROPERTY *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + UINT32_Marshal((UINT32 *)&(source->count), buffer, size));
    result = (UINT16)(result + TPMS_TAGGED_PROPERTY_Array_Marshal((TPMS_TAGGED_PROPERTY *)(source->tpmProperty), buffer, size, (INT32)(source->count)));

    return result;
}

TPM_RC
TPML_TAGGED_TPM_PROPERTY_Unmarshal(TPML_TAGGED_TPM_PROPERTY *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = UINT32_Unmarshal((UINT32 *)&(target->count), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
//    if((target->count) > HASH_COUNT)
//        return TPM_RC_SIZE;
    result = TPMS_TAGGED_PROPERTY_Array_Unmarshal((TPMS_TAGGED_PROPERTY *)(target->tpmProperty), buffer, size, (INT32)(target->count));
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}


// Table 101 -- TPML_TAGGED_PCR_PROPERTY Structure <O,S>
UINT16
TPML_TAGGED_PCR_PROPERTY_Marshal(TPML_TAGGED_PCR_PROPERTY *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + UINT32_Marshal((UINT32 *)&(source->count), buffer, size));
    result = (UINT16)(result + TPMS_TAGGED_PCR_SELECT_Array_Marshal((TPMS_TAGGED_PCR_SELECT *)(source->pcrProperty), buffer, size, (INT32)(source->count)));

    return result;
}

TPM_RC
TPML_TAGGED_PCR_PROPERTY_Unmarshal(TPML_TAGGED_PCR_PROPERTY *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = UINT32_Unmarshal((UINT32 *)&(target->count), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
//    if((target->count) > HASH_COUNT)
//        return TPM_RC_SIZE;
    result = TPMS_TAGGED_PCR_SELECT_Array_Unmarshal((TPMS_TAGGED_PCR_SELECT *)(target->pcrProperty), buffer, size, (INT32)(target->count));
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}


// Table 102 -- TPML_ECC_CURVE Structure <O,S>
#ifdef TPM_ALG_ECC
#endif
#ifdef TPM_ALG_ECC
UINT16
TPML_ECC_CURVE_Marshal(TPML_ECC_CURVE *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + UINT32_Marshal((UINT32 *)&(source->count), buffer, size));
    result = (UINT16)(result + TPM_ECC_CURVE_Array_Marshal((TPM_ECC_CURVE *)(source->eccCurves), buffer, size, (INT32)(source->count)));

    return result;
}

TPM_RC
TPML_ECC_CURVE_Unmarshal(TPML_ECC_CURVE *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = UINT32_Unmarshal((UINT32 *)&(target->count), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
//    if((target->count) > HASH_COUNT)
//        return TPM_RC_SIZE;
    result = TPM_ECC_CURVE_Array_Unmarshal((TPM_ECC_CURVE *)(target->eccCurves), buffer, size, (INT32)(target->count));
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

#endif

// Table 103 -- TPMU_CAPABILITIES Union <O,S>
UINT16
TPMU_CAPABILITIES_Marshal(TPMU_CAPABILITIES *source, BYTE **buffer, INT32 *size, UINT32 selector)
{
    switch(selector) {
        case TPM_CAP_ALGS:
            return TPML_ALG_PROPERTY_Marshal((TPML_ALG_PROPERTY *)&(source->algorithms), buffer, size);
        case TPM_CAP_HANDLES:
            return TPML_HANDLE_Marshal((TPML_HANDLE *)&(source->handles), buffer, size);
        case TPM_CAP_COMMANDS:
            return TPML_CCA_Marshal((TPML_CCA *)&(source->command), buffer, size);
        case TPM_CAP_PP_COMMANDS:
            return TPML_CC_Marshal((TPML_CC *)&(source->ppCommands), buffer, size);
        case TPM_CAP_AUDIT_COMMANDS:
            return TPML_CC_Marshal((TPML_CC *)&(source->auditCommands), buffer, size);
        case TPM_CAP_PCRS:
            return TPML_PCR_SELECTION_Marshal((TPML_PCR_SELECTION *)&(source->assignedPCR), buffer, size);
        case TPM_CAP_TPM_PROPERTIES:
            return TPML_TAGGED_TPM_PROPERTY_Marshal((TPML_TAGGED_TPM_PROPERTY *)&(source->tpmProperties), buffer, size);
        case TPM_CAP_PCR_PROPERTIES:
            return TPML_TAGGED_PCR_PROPERTY_Marshal((TPML_TAGGED_PCR_PROPERTY *)&(source->pcrProperties), buffer, size);
#ifdef TPM_ALG_ECC
        case TPM_CAP_ECC_CURVES:
            return TPML_ECC_CURVE_Marshal((TPML_ECC_CURVE *)&(source->eccCurves), buffer, size);
#endif
    }
    pAssert(FALSE);
    return 0;
}

TPM_RC
TPMU_CAPABILITIES_Unmarshal(TPMU_CAPABILITIES *target, BYTE **buffer, INT32 *size, UINT32 selector)
{
    switch(selector)
    {
    case TPM_CAP_ALGS:
        return TPML_ALG_PROPERTY_Unmarshal((TPML_ALG_PROPERTY *)&(target->algorithms), buffer, size);
    case TPM_CAP_HANDLES:
        return TPML_HANDLE_Unmarshal((TPML_HANDLE *)&(target->handles), buffer, size);
    case TPM_CAP_COMMANDS:
        return TPML_CCA_Unmarshal((TPML_CCA *)&(target->command), buffer, size);
    case TPM_CAP_PP_COMMANDS:
        return TPML_CC_Unmarshal((TPML_CC *)&(target->ppCommands), buffer, size);
    case TPM_CAP_AUDIT_COMMANDS:
        return TPML_CC_Unmarshal((TPML_CC *)&(target->auditCommands), buffer, size);
    case TPM_CAP_PCRS:
        return TPML_PCR_SELECTION_Unmarshal((TPML_PCR_SELECTION *)&(target->assignedPCR), buffer, size);
    case TPM_CAP_TPM_PROPERTIES:
        return TPML_TAGGED_TPM_PROPERTY_Unmarshal((TPML_TAGGED_TPM_PROPERTY *)&(target->tpmProperties), buffer, size);
    case TPM_CAP_PCR_PROPERTIES:
        return TPML_TAGGED_PCR_PROPERTY_Unmarshal((TPML_TAGGED_PCR_PROPERTY *)&(target->pcrProperties), buffer, size);
#ifdef TPM_ALG_ECC
    case TPM_CAP_ECC_CURVES:
        return TPML_ECC_CURVE_Unmarshal((TPML_ECC_CURVE *)&(target->eccCurves), buffer, size);
#endif
    }
    pAssert(FALSE);

    return TPM_RC_SELECTOR;
}

// Table 104 -- TPMS_CAPABILITY_DATA Structure <O,S>
UINT16
TPMS_CAPABILITY_DATA_Marshal(TPMS_CAPABILITY_DATA *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPM_CAP_Marshal((TPM_CAP *)&(source->capability), buffer, size));
    result = (UINT16)(result + TPMU_CAPABILITIES_Marshal((TPMU_CAPABILITIES *)&(source->data), buffer, size, (UINT32)source->capability));

    return result;
}

TPM_RC
TPMS_CAPABILITY_DATA_Unmarshal(TPMS_CAPABILITY_DATA *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPM_CAP_Unmarshal((TPM_CAP *)&(target->capability), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPMU_CAPABILITIES_Unmarshal((TPMU_CAPABILITIES *)&(target->data), buffer, size, (UINT32)target->capability);
    if(result != TPM_RC_SUCCESS)
        return result;

    return result;
}


// Table 105 -- TPMS_CLOCK_INFO Structure <I/O>
TPM_RC
TPMS_CLOCK_INFO_Unmarshal(TPMS_CLOCK_INFO *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = UINT64_Unmarshal((UINT64 *)&(target->clock), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = UINT32_Unmarshal((UINT32 *)&(target->resetCount), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = UINT32_Unmarshal((UINT32 *)&(target->restartCount), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPMI_YES_NO_Unmarshal((TPMI_YES_NO *)&(target->safe), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPMS_CLOCK_INFO_Marshal(TPMS_CLOCK_INFO *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + UINT64_Marshal((UINT64 *)&(source->clock), buffer, size));
    result = (UINT16)(result + UINT32_Marshal((UINT32 *)&(source->resetCount), buffer, size));
    result = (UINT16)(result + UINT32_Marshal((UINT32 *)&(source->restartCount), buffer, size));
    result = (UINT16)(result + TPMI_YES_NO_Marshal((TPMI_YES_NO *)&(source->safe), buffer, size));

    return result;
}


// Table 106 -- TPMS_TIME_INFO Structure <I/O>
TPM_RC
TPMS_TIME_INFO_Unmarshal(TPMS_TIME_INFO *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = UINT64_Unmarshal((UINT64 *)&(target->time), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPMS_CLOCK_INFO_Unmarshal((TPMS_CLOCK_INFO *)&(target->clockInfo), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPMS_TIME_INFO_Marshal(TPMS_TIME_INFO *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + UINT64_Marshal((UINT64 *)&(source->time), buffer, size));
    result = (UINT16)(result + TPMS_CLOCK_INFO_Marshal((TPMS_CLOCK_INFO *)&(source->clockInfo), buffer, size));

    return result;
}


// Table 107 -- TPMS_TIME_ATTEST_INFO Structure <O,S>
TPM_RC
TPMS_TIME_ATTEST_INFO_Unmarshal(TPMS_TIME_ATTEST_INFO *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPMS_TIME_INFO_Unmarshal((TPMS_TIME_INFO *)&(target->time), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = UINT64_Unmarshal((UINT64 *)&(target->firmwareVersion), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPMS_TIME_ATTEST_INFO_Marshal(TPMS_TIME_ATTEST_INFO *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPMS_TIME_INFO_Marshal((TPMS_TIME_INFO *)&(source->time), buffer, size));
    result = (UINT16)(result + UINT64_Marshal((UINT64 *)&(source->firmwareVersion), buffer, size));

    return result;
}


// Table 108 -- TPMS_CERTIFY_INFO Structure <O,S>
TPM_RC
TPMS_CERTIFY_INFO_Unmarshal(TPMS_CERTIFY_INFO *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPM2B_NAME_Unmarshal((TPM2B_NAME *)&(target->name), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPM2B_NAME_Unmarshal((TPM2B_NAME *)&(target->qualifiedName), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPMS_CERTIFY_INFO_Marshal(TPMS_CERTIFY_INFO *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPM2B_NAME_Marshal((TPM2B_NAME *)&(source->name), buffer, size));
    result = (UINT16)(result + TPM2B_NAME_Marshal((TPM2B_NAME *)&(source->qualifiedName), buffer, size));

    return result;
}


// Table 109 -- TPMS_QUOTE_INFO Structure <O,S>
TPM_RC
TPMS_QUOTE_INFO_Unmarshal(TPMS_QUOTE_INFO *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPML_PCR_SELECTION_Unmarshal((TPML_PCR_SELECTION *)&(target->pcrSelect), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPM2B_DIGEST_Unmarshal((TPM2B_DIGEST *)&(target->pcrDigest), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPMS_QUOTE_INFO_Marshal(TPMS_QUOTE_INFO *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPML_PCR_SELECTION_Marshal((TPML_PCR_SELECTION *)&(source->pcrSelect), buffer, size));
    result = (UINT16)(result + TPM2B_DIGEST_Marshal((TPM2B_DIGEST *)&(source->pcrDigest), buffer, size));

    return result;
}


// Table 110 -- TPMS_COMMAND_AUDIT_INFO Structure <O,S>
TPM_RC
TPMS_COMMAND_AUDIT_INFO_Unmarshal(TPMS_COMMAND_AUDIT_INFO *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = UINT64_Unmarshal((UINT64 *)&(target->auditCounter), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPM_ALG_ID_Unmarshal((TPM_ALG_ID *)&(target->digestAlg), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPM2B_DIGEST_Unmarshal((TPM2B_DIGEST *)&(target->auditDigest), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPM2B_DIGEST_Unmarshal((TPM2B_DIGEST *)&(target->commandDigest), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPMS_COMMAND_AUDIT_INFO_Marshal(TPMS_COMMAND_AUDIT_INFO *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + UINT64_Marshal((UINT64 *)&(source->auditCounter), buffer, size));
    result = (UINT16)(result + TPM_ALG_ID_Marshal((TPM_ALG_ID *)&(source->digestAlg), buffer, size));
    result = (UINT16)(result + TPM2B_DIGEST_Marshal((TPM2B_DIGEST *)&(source->auditDigest), buffer, size));
    result = (UINT16)(result + TPM2B_DIGEST_Marshal((TPM2B_DIGEST *)&(source->commandDigest), buffer, size));

    return result;
}


// Table 111 -- TPMS_SESSION_AUDIT_INFO Structure <O,S>
TPM_RC
TPMS_SESSION_AUDIT_INFO_Unmarshal(TPMS_SESSION_AUDIT_INFO *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPMI_YES_NO_Unmarshal((TPMI_YES_NO *)&(target->exclusiveSession), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPM2B_DIGEST_Unmarshal((TPM2B_DIGEST *)&(target->sessionDigest), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPMS_SESSION_AUDIT_INFO_Marshal(TPMS_SESSION_AUDIT_INFO *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPMI_YES_NO_Marshal((TPMI_YES_NO *)&(source->exclusiveSession), buffer, size));
    result = (UINT16)(result + TPM2B_DIGEST_Marshal((TPM2B_DIGEST *)&(source->sessionDigest), buffer, size));

    return result;
}


// Table 112 -- TPMS_CREATION_INFO Structure <O,S>
TPM_RC
TPMS_CREATION_INFO_Unmarshal(TPMS_CREATION_INFO *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPM2B_NAME_Unmarshal((TPM2B_NAME *)&(target->objectName), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPM2B_DIGEST_Unmarshal((TPM2B_DIGEST *)&(target->creationHash), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPMS_CREATION_INFO_Marshal(TPMS_CREATION_INFO *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPM2B_NAME_Marshal((TPM2B_NAME *)&(source->objectName), buffer, size));
    result = (UINT16)(result + TPM2B_DIGEST_Marshal((TPM2B_DIGEST *)&(source->creationHash), buffer, size));

    return result;
}


// Table 113 -- TPMS_NV_CERTIFY_INFO Structure <O,S>
TPM_RC
TPMS_NV_CERTIFY_INFO_Unmarshal(TPMS_NV_CERTIFY_INFO *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPM2B_NAME_Unmarshal((TPM2B_NAME *)&(target->indexName), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = UINT16_Unmarshal((UINT16 *)&(target->offset), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPM2B_MAX_NV_BUFFER_Unmarshal((TPM2B_MAX_NV_BUFFER *)&(target->nvContents), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPMS_NV_CERTIFY_INFO_Marshal(TPMS_NV_CERTIFY_INFO *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPM2B_NAME_Marshal((TPM2B_NAME *)&(source->indexName), buffer, size));
    result = (UINT16)(result + UINT16_Marshal((UINT16 *)&(source->offset), buffer, size));
    result = (UINT16)(result + TPM2B_MAX_NV_BUFFER_Marshal((TPM2B_MAX_NV_BUFFER *)&(source->nvContents), buffer, size));

    return result;
}


// Table 114 -- TPMI_ST_ATTEST Type <O,S>
TPM_RC
TPMI_ST_ATTEST_Unmarshal(TPMI_ST_ATTEST *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = UINT16_Unmarshal((UINT16 *)target, buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPMI_ST_ATTEST_Marshal(TPMI_ST_ATTEST *source, BYTE **buffer, INT32 *size)
{
    return UINT16_Marshal((UINT16 *)source, buffer, size);
}


// Table 115 -- TPMU_ATTEST Union <O,S>
TPM_RC
TPMU_ATTEST_Unmarshal(TPMU_ATTEST *target, BYTE **buffer, INT32 *size, UINT32 selector)
{
    switch(selector) {
        case TPM_ST_ATTEST_CERTIFY:
            return TPMS_CERTIFY_INFO_Unmarshal((TPMS_CERTIFY_INFO *)&(target->certify), buffer, size);
        case TPM_ST_ATTEST_CREATION:
            return TPMS_CREATION_INFO_Unmarshal((TPMS_CREATION_INFO *)&(target->creation), buffer, size);
        case TPM_ST_ATTEST_QUOTE:
            return TPMS_QUOTE_INFO_Unmarshal((TPMS_QUOTE_INFO *)&(target->quote), buffer, size);
        case TPM_ST_ATTEST_COMMAND_AUDIT:
            return TPMS_COMMAND_AUDIT_INFO_Unmarshal((TPMS_COMMAND_AUDIT_INFO *)&(target->commandAudit), buffer, size);
        case TPM_ST_ATTEST_SESSION_AUDIT:
            return TPMS_SESSION_AUDIT_INFO_Unmarshal((TPMS_SESSION_AUDIT_INFO *)&(target->sessionAudit), buffer, size);
        case TPM_ST_ATTEST_TIME:
            return TPMS_TIME_ATTEST_INFO_Unmarshal((TPMS_TIME_ATTEST_INFO *)&(target->time), buffer, size);
        case TPM_ST_ATTEST_NV:
            return TPMS_NV_CERTIFY_INFO_Unmarshal((TPMS_NV_CERTIFY_INFO *)&(target->nv), buffer, size);
    }
    pAssert(FALSE);
    return 0;
}

UINT16
TPMU_ATTEST_Marshal(TPMU_ATTEST *source, BYTE **buffer, INT32 *size, UINT32 selector)
{
    switch(selector) {
        case TPM_ST_ATTEST_CERTIFY:
            return TPMS_CERTIFY_INFO_Marshal((TPMS_CERTIFY_INFO *)&(source->certify), buffer, size);
        case TPM_ST_ATTEST_CREATION:
            return TPMS_CREATION_INFO_Marshal((TPMS_CREATION_INFO *)&(source->creation), buffer, size);
        case TPM_ST_ATTEST_QUOTE:
            return TPMS_QUOTE_INFO_Marshal((TPMS_QUOTE_INFO *)&(source->quote), buffer, size);
        case TPM_ST_ATTEST_COMMAND_AUDIT:
            return TPMS_COMMAND_AUDIT_INFO_Marshal((TPMS_COMMAND_AUDIT_INFO *)&(source->commandAudit), buffer, size);
        case TPM_ST_ATTEST_SESSION_AUDIT:
            return TPMS_SESSION_AUDIT_INFO_Marshal((TPMS_SESSION_AUDIT_INFO *)&(source->sessionAudit), buffer, size);
        case TPM_ST_ATTEST_TIME:
            return TPMS_TIME_ATTEST_INFO_Marshal((TPMS_TIME_ATTEST_INFO *)&(source->time), buffer, size);
        case TPM_ST_ATTEST_NV:
            return TPMS_NV_CERTIFY_INFO_Marshal((TPMS_NV_CERTIFY_INFO *)&(source->nv), buffer, size);
    }
    pAssert(FALSE);
    return 0;
}

// Table 116 -- TPMS_ATTEST Structure <O,S>
TPM_RC
TPMS_ATTEST_Unmarshal(TPMS_ATTEST *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPM_GENERATED_Unmarshal((TPM_GENERATED *)&(target->magic), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPMI_ST_ATTEST_Unmarshal((TPMI_ST_ATTEST *)&(target->type), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPM2B_NAME_Unmarshal((TPM2B_NAME *)&(target->qualifiedSigner), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPM2B_DATA_Unmarshal((TPM2B_DATA *)&(target->extraData), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPMS_CLOCK_INFO_Unmarshal((TPMS_CLOCK_INFO *)&(target->clockInfo), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = UINT64_Unmarshal((UINT64 *)&(target->firmwareVersion), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPMU_ATTEST_Unmarshal((TPMU_ATTEST *)&(target->attested), buffer, size, (UINT32)target->type);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPMS_ATTEST_Marshal(TPMS_ATTEST *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPM_GENERATED_Marshal((TPM_GENERATED *)&(source->magic), buffer, size));
    result = (UINT16)(result + TPMI_ST_ATTEST_Marshal((TPMI_ST_ATTEST *)&(source->type), buffer, size));
    result = (UINT16)(result + TPM2B_NAME_Marshal((TPM2B_NAME *)&(source->qualifiedSigner), buffer, size));
    result = (UINT16)(result + TPM2B_DATA_Marshal((TPM2B_DATA *)&(source->extraData), buffer, size));
    result = (UINT16)(result + TPMS_CLOCK_INFO_Marshal((TPMS_CLOCK_INFO *)&(source->clockInfo), buffer, size));
    result = (UINT16)(result + UINT64_Marshal((UINT64 *)&(source->firmwareVersion), buffer, size));
    result = (UINT16)(result + TPMU_ATTEST_Marshal((TPMU_ATTEST *)&(source->attested), buffer, size, (UINT32)source->type));

    return result;
}


// Table 117 -- TPM2B_ATTEST Structure <O,S>
TPM_RC
TPM2B_ATTEST_Unmarshal(TPM2B_ATTEST *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    INT32    startSize;
    result = UINT16_Unmarshal((UINT16 *)&(target->t.size), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    startSize = *size;
    result = TPMS_ATTEST_Unmarshal((TPMS_ATTEST *)&(target->t.attestationData), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    if(target->t.size != (startSize - *size)) return TPM_RC_SIZE;

    return TPM_RC_SUCCESS;
}

UINT16
TPM2B_ATTEST_Marshal(TPM2B_ATTEST *source, BYTE **buffer, INT32 *size)
{
    UINT16 result = 0;
    BYTE *sizeField = NULL;
    // Advance buffer pointer by cononical size of a UINT16
    if(buffer != NULL)
    {
        sizeField = *buffer;
        *buffer += 2;
    }
    // Marshal the structure
    result = (UINT16)(result + TPMS_ATTEST_Marshal((TPMS_ATTEST *)&(source->t.attestationData), buffer, size));
    // Marshal the size
    result = (UINT16)(result + UINT16_Marshal(&result, sizeField ? &sizeField : NULL, size)); 

    return result;
}


// Table 118 -- TPMS_AUTH_COMMAND Structure <I>
TPM_RC
TPMS_AUTH_COMMAND_Unmarshal(TPMS_AUTH_COMMAND *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPMI_SH_AUTH_SESSION_Unmarshal((TPMI_SH_AUTH_SESSION *)&(target->sessionHandle), buffer, size, TRUE);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPM2B_NONCE_Unmarshal((TPM2B_NONCE *)&(target->nonce), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPMA_SESSION_Unmarshal((TPMA_SESSION *)&(target->sessionAttributes), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPM2B_AUTH_Unmarshal((TPM2B_AUTH *)&(target->hmac), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}


// Table 119 -- TPMS_AUTH_RESPONSE Structure <O,S>
UINT16
TPMS_AUTH_RESPONSE_Marshal(TPMS_AUTH_RESPONSE *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPM2B_NONCE_Marshal((TPM2B_NONCE *)&(source->nonce), buffer, size));
    result = (UINT16)(result + TPMA_SESSION_Marshal((TPMA_SESSION *)&(source->sessionAttributes), buffer, size));
    result = (UINT16)(result + TPM2B_AUTH_Marshal((TPM2B_AUTH *)&(source->hmac), buffer, size));

    return result;
}


// Table 120 -- TPMI_AES_KEY_BITS Type <I/O>
#ifdef TPM_ALG_AES
TPM_RC
TPMI_AES_KEY_BITS_Unmarshal(TPMI_AES_KEY_BITS *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPM_KEY_BITS_Unmarshal((TPM_KEY_BITS *)target, buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    switch (*target) {
        case 128:
            break;
        default:
            return TPM_RC_VALUE;
    }
    return TPM_RC_SUCCESS;
}

#endif
#ifdef TPM_ALG_AES
UINT16
TPMI_AES_KEY_BITS_Marshal(TPMI_AES_KEY_BITS *source, BYTE **buffer, INT32 *size)
{
    return UINT16_Marshal((UINT16 *)source, buffer, size);
}

#endif

// Table 121 -- TPMI_SM4_KEY_BITS Type <I/O>
#ifdef TPM_ALG_SM4
TPM_RC
TPMI_SM4_KEY_BITS_Unmarshal(TPMI_SM4_KEY_BITS *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPM_KEY_BITS_Unmarshal((TPM_KEY_BITS *)target, buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    switch (*target) {
        case 128:
            break;
        default:
            return TPM_RC_VALUE;
    }
    return TPM_RC_SUCCESS;
}

#endif
#ifdef TPM_ALG_SM4
UINT16
TPMI_SM4_KEY_BITS_Marshal(TPMI_SM4_KEY_BITS *source, BYTE **buffer, INT32 *size)
{
    return UINT16_Marshal((UINT16 *)source, buffer, size);
}

#endif

// Table 122 -- TPMU_SYM_KEY_BITS Union <I/O>
TPM_RC
TPMU_SYM_KEY_BITS_Unmarshal(TPMU_SYM_KEY_BITS *target, BYTE **buffer, INT32 *size, UINT32 selector)
{
    switch(selector) {
#ifdef TPM_ALG_AES
        case TPM_ALG_AES:
            return TPMI_AES_KEY_BITS_Unmarshal((TPMI_AES_KEY_BITS *)&(target->aes), buffer, size);
#endif
#ifdef TPM_ALG_SM4
        case TPM_ALG_SM4:
            return TPMI_SM4_KEY_BITS_Unmarshal((TPMI_SM4_KEY_BITS *)&(target->SM4), buffer, size);
#endif
#ifdef TPM_ALG_XOR
        case TPM_ALG_XOR:
            return TPMI_ALG_HASH_Unmarshal((TPMI_ALG_HASH *)&(target->xOr), buffer, size, FALSE);
#endif
        case TPM_ALG_NULL:
                    return TPM_RC_SUCCESS;
    }
    return TPM_RC_SELECTOR;
}

UINT16
TPMU_SYM_KEY_BITS_Marshal(TPMU_SYM_KEY_BITS *source, BYTE **buffer, INT32 *size, UINT32 selector)
{
    switch(selector) {
#ifdef TPM_ALG_AES
        case TPM_ALG_AES:
            return TPMI_AES_KEY_BITS_Marshal((TPMI_AES_KEY_BITS *)&(source->aes), buffer, size);
#endif
#ifdef TPM_ALG_SM4
        case TPM_ALG_SM4:
            return TPMI_SM4_KEY_BITS_Marshal((TPMI_SM4_KEY_BITS *)&(source->SM4), buffer, size);
#endif
#ifdef TPM_ALG_XOR
        case TPM_ALG_XOR:
            return TPMI_ALG_HASH_Marshal((TPMI_ALG_HASH *)&(source->xOr), buffer, size);
#endif
        case TPM_ALG_NULL:
                    return 0;
    }
    pAssert(FALSE);
    return 0;
}


// Table 123 -- TPMU_SYM_MODE Union <I/O>
TPM_RC
TPMU_SYM_MODE_Unmarshal(TPMU_SYM_MODE *target, BYTE **buffer, INT32 *size, UINT32 selector)
{
    switch(selector) {
#ifdef TPM_ALG_AES
        case TPM_ALG_AES:
            return TPMI_ALG_SYM_MODE_Unmarshal((TPMI_ALG_SYM_MODE *)&(target->aes), buffer, size, FALSE);
#endif
#ifdef TPM_ALG_SM4
        case TPM_ALG_SM4:
            return TPMI_ALG_SYM_MODE_Unmarshal((TPMI_ALG_SYM_MODE *)&(target->SM4), buffer, size, FALSE);
#endif
#ifdef TPM_ALG_XOR
        case TPM_ALG_XOR:
                    return TPM_RC_SUCCESS;
#endif
        case TPM_ALG_NULL:
                    return TPM_RC_SUCCESS;
    }
    return TPM_RC_SELECTOR;
}

UINT16
TPMU_SYM_MODE_Marshal(TPMU_SYM_MODE *source, BYTE **buffer, INT32 *size, UINT32 selector)
{
    switch(selector) {
#ifdef TPM_ALG_AES
        case TPM_ALG_AES:
            return TPMI_ALG_SYM_MODE_Marshal((TPMI_ALG_SYM_MODE *)&(source->aes), buffer, size);
#endif
#ifdef TPM_ALG_SM4
        case TPM_ALG_SM4:
            return TPMI_ALG_SYM_MODE_Marshal((TPMI_ALG_SYM_MODE *)&(source->SM4), buffer, size);
#endif
#ifdef TPM_ALG_XOR
        case TPM_ALG_XOR:
                    return 0;
#endif
        case TPM_ALG_NULL:
                    return 0;
    }
    pAssert(FALSE);
    return 0;
}


// Table 125 -- TPMT_SYM_DEF Structure <I/O>
TPM_RC
TPMT_SYM_DEF_Unmarshal(TPMT_SYM_DEF *target, BYTE **buffer, INT32 *size, BOOL flag)
{
    TPM_RC    result;
    result = TPMI_ALG_SYM_Unmarshal((TPMI_ALG_SYM *)&(target->algorithm), buffer, size, flag);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPMU_SYM_KEY_BITS_Unmarshal((TPMU_SYM_KEY_BITS *)&(target->keyBits), buffer, size, (UINT32)target->algorithm);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPMU_SYM_MODE_Unmarshal((TPMU_SYM_MODE *)&(target->mode), buffer, size, (UINT32)target->algorithm);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPMT_SYM_DEF_Marshal(TPMT_SYM_DEF *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPMI_ALG_SYM_Marshal((TPMI_ALG_SYM *)&(source->algorithm), buffer, size));
    result = (UINT16)(result + TPMU_SYM_KEY_BITS_Marshal((TPMU_SYM_KEY_BITS *)&(source->keyBits), buffer, size, (UINT32)source->algorithm));
    result = (UINT16)(result + TPMU_SYM_MODE_Marshal((TPMU_SYM_MODE *)&(source->mode), buffer, size, (UINT32)source->algorithm));

    return result;
}


// Table 126 -- TPMT_SYM_DEF_OBJECT Structure <I/O>
TPM_RC
TPMT_SYM_DEF_OBJECT_Unmarshal(TPMT_SYM_DEF_OBJECT *target, BYTE **buffer, INT32 *size, BOOL flag)
{
    TPM_RC    result;
    result = TPMI_ALG_SYM_OBJECT_Unmarshal((TPMI_ALG_SYM_OBJECT *)&(target->algorithm), buffer, size, flag);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPMU_SYM_KEY_BITS_Unmarshal((TPMU_SYM_KEY_BITS *)&(target->keyBits), buffer, size, (UINT32)target->algorithm);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPMU_SYM_MODE_Unmarshal((TPMU_SYM_MODE *)&(target->mode), buffer, size, (UINT32)target->algorithm);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPMT_SYM_DEF_OBJECT_Marshal(TPMT_SYM_DEF_OBJECT *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPMI_ALG_SYM_OBJECT_Marshal((TPMI_ALG_SYM_OBJECT *)&(source->algorithm), buffer, size));
    result = (UINT16)(result + TPMU_SYM_KEY_BITS_Marshal((TPMU_SYM_KEY_BITS *)&(source->keyBits), buffer, size, (UINT32)source->algorithm));
    result = (UINT16)(result + TPMU_SYM_MODE_Marshal((TPMU_SYM_MODE *)&(source->mode), buffer, size, (UINT32)source->algorithm));

    return result;
}


// Table 127 -- TPM2B_SYM_KEY Structure <I/O>
TPM_RC
TPM2B_SYM_KEY_Unmarshal(TPM2B_SYM_KEY *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = UINT16_Unmarshal((UINT16 *)&(target->t.size), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    // if size equal to 0, the rest of the structure is a zero buffer.  Stop processing
    if(target->t.size == 0) return TPM_RC_SUCCESS;
    if((target->t.size) > MAX_SYM_KEY_BYTES)
        return TPM_RC_SIZE;
    result = BYTE_Array_Unmarshal((BYTE *)(target->t.buffer), buffer, size, (INT32)(target->t.size));
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPM2B_SYM_KEY_Marshal(TPM2B_SYM_KEY *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + UINT16_Marshal((UINT16 *)&(source->t.size), buffer, size));
    // if size equal to 0, the rest of the structure is a zero buffer.  Stop processing
    if(source->t.size == 0) return result;
    result = (UINT16)(result + BYTE_Array_Marshal((BYTE *)(source->t.buffer), buffer, size, (INT32)(source->t.size)));

    return result;
}


// Table 128 -- TPMS_SYMCIPHER_PARMS Structure <I/O>
TPM_RC
TPMS_SYMCIPHER_PARMS_Unmarshal(TPMS_SYMCIPHER_PARMS *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPMT_SYM_DEF_OBJECT_Unmarshal((TPMT_SYM_DEF_OBJECT *)&(target->sym), buffer, size, FALSE);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPMS_SYMCIPHER_PARMS_Marshal(TPMS_SYMCIPHER_PARMS *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPMT_SYM_DEF_OBJECT_Marshal((TPMT_SYM_DEF_OBJECT *)&(source->sym), buffer, size));

    return result;
}


// Table 129 -- TPM2B_SENSITIVE_DATA Structure <I/O>
TPM_RC
TPM2B_SENSITIVE_DATA_Unmarshal(TPM2B_SENSITIVE_DATA *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = UINT16_Unmarshal((UINT16 *)&(target->t.size), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    // if size equal to 0, the rest of the structure is a zero buffer.  Stop processing
    if(target->t.size == 0) return TPM_RC_SUCCESS;
    if((target->t.size) > MAX_SYM_DATA)
        return TPM_RC_SIZE;
    result = BYTE_Array_Unmarshal((BYTE *)(target->t.buffer), buffer, size, (INT32)(target->t.size));
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPM2B_SENSITIVE_DATA_Marshal(TPM2B_SENSITIVE_DATA *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + UINT16_Marshal((UINT16 *)&(source->t.size), buffer, size));
    // if size equal to 0, the rest of the structure is a zero buffer.  Stop processing
    if(source->t.size == 0) return result;
    result = (UINT16)(result + BYTE_Array_Marshal((BYTE *)(source->t.buffer), buffer, size, (INT32)(source->t.size)));

    return result;
}


// Table 130 -- TPMS_SENSITIVE_CREATE Structure <I>
TPM_RC
TPMS_SENSITIVE_CREATE_Unmarshal(TPMS_SENSITIVE_CREATE *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPM2B_AUTH_Unmarshal((TPM2B_AUTH *)&(target->userAuth), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPM2B_SENSITIVE_DATA_Unmarshal((TPM2B_SENSITIVE_DATA *)&(target->data), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPMS_SENSITIVE_CREATE_Marshal(TPMS_SENSITIVE_CREATE *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPM2B_AUTH_Marshal((TPM2B_AUTH *)&(source->userAuth), buffer, size));
    result = (UINT16)(result + TPM2B_SENSITIVE_DATA_Marshal(&(source->data), buffer, size));

    return result;
}

// Table 131 -- TPM2B_SENSITIVE_CREATE Structure <I,S>
TPM_RC
TPM2B_SENSITIVE_CREATE_Unmarshal(TPM2B_SENSITIVE_CREATE *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    INT32    startSize;
    result = UINT16_Unmarshal((UINT16 *)&(target->t.size), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    startSize = *size;
    result = TPMS_SENSITIVE_CREATE_Unmarshal((TPMS_SENSITIVE_CREATE *)&(target->t.sensitive), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    if(target->t.size != (startSize - *size)) return TPM_RC_SIZE;

    return TPM_RC_SUCCESS;
}

UINT16
TPM2B_SENSITIVE_CREATE_Marshal(TPM2B_SENSITIVE_CREATE *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    BYTE      *sizeField = NULL;
    // Advance buffer pointer by cononical size of a UINT16
    if(buffer != NULL)
    {
        sizeField = *buffer;
        *buffer += 2;
    }
    // Marshal the structure
    result = (UINT16)(result + TPMS_SENSITIVE_CREATE_Marshal(&(source->t.sensitive), buffer, size));
    // Marshal the size
    result = (UINT16)(result + UINT16_Marshal(&result, sizeField ? &sizeField : NULL, size));
    return result;
}


// Table 132 -- TPMS_SCHEME_SIGHASH Structure <I/O>
TPM_RC
TPMS_SCHEME_SIGHASH_Unmarshal(TPMS_SCHEME_SIGHASH *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPMI_ALG_HASH_Unmarshal((TPMI_ALG_HASH *)&(target->hashAlg), buffer, size, FALSE);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPMS_SCHEME_SIGHASH_Marshal(TPMS_SCHEME_SIGHASH *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPMI_ALG_HASH_Marshal((TPMI_ALG_HASH *)&(source->hashAlg), buffer, size));

    return result;
}


// Table 133 -- TPMI_ALG_KEYEDHASH_SCHEME Type <I/O>
TPM_RC
TPMI_ALG_KEYEDHASH_SCHEME_Unmarshal(TPMI_ALG_KEYEDHASH_SCHEME *target, BYTE **buffer, INT32 *size, BOOL flag)
{
    TPM_RC    result;
    result = TPM_ALG_ID_Unmarshal((TPM_ALG_ID *)target, buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    switch (*target) {
#ifdef TPM_ALG_HMAC
        case TPM_ALG_HMAC:
#endif
#ifdef TPM_ALG_XOR
        case TPM_ALG_XOR:
#endif
            break;
        case TPM_ALG_NULL:
            if (flag)
                break;
            return TPM_RC_VALUE;
        default:
            return TPM_RC_VALUE;
    }
    return TPM_RC_SUCCESS;
}

UINT16
TPMI_ALG_KEYEDHASH_SCHEME_Marshal(TPMI_ALG_KEYEDHASH_SCHEME *source, BYTE **buffer, INT32 *size)
{
    return UINT16_Marshal((UINT16 *)source, buffer, size);
}


// Table 134 -- HMAC_SIG_SCHEME Types <I/O>
TPM_RC
TPMS_SCHEME_HMAC_Unmarshal(TPMS_SCHEME_HMAC *target, BYTE **buffer, INT32 *size)
{
    return TPMS_SCHEME_SIGHASH_Unmarshal((TPMS_SCHEME_SIGHASH *)target, buffer, size);
}


UINT16
TPMS_SCHEME_HMAC_Marshal(TPMS_SCHEME_HMAC *source, BYTE **buffer, INT32 *size)
{
    return TPMS_SCHEME_SIGHASH_Marshal((TPMS_SCHEME_SIGHASH *)source, buffer, size);
}



// Table 135 -- TPMS_SCHEME_XOR Structure <I/O>
TPM_RC
TPMS_SCHEME_XOR_Unmarshal(TPMS_SCHEME_XOR *target, BYTE **buffer, INT32 *size, BOOL flag)
{
    TPM_RC    result;
    result = TPMI_ALG_HASH_Unmarshal((TPMI_ALG_HASH *)&(target->hashAlg), buffer, size, flag);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPMI_ALG_KDF_Unmarshal((TPMI_ALG_KDF *)&(target->kdf), buffer, size, FALSE);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPMS_SCHEME_XOR_Marshal(TPMS_SCHEME_XOR *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPMI_ALG_HASH_Marshal((TPMI_ALG_HASH *)&(source->hashAlg), buffer, size));
    result = (UINT16)(result + TPMI_ALG_KDF_Marshal((TPMI_ALG_KDF *)&(source->kdf), buffer, size));

    return result;
}


// Table 136 -- TPMU_SCHEME_KEYEDHASH Union <I/O,S>
TPM_RC
TPMU_SCHEME_KEYEDHASH_Unmarshal(TPMU_SCHEME_KEYEDHASH *target, BYTE **buffer, INT32 *size, UINT32 selector)
{
    switch(selector) {
#ifdef TPM_ALG_HMAC
        case TPM_ALG_HMAC:
            return TPMS_SCHEME_HMAC_Unmarshal((TPMS_SCHEME_HMAC *)&(target->hmac), buffer, size);
#endif
#ifdef TPM_ALG_XOR
        case TPM_ALG_XOR:
            return TPMS_SCHEME_XOR_Unmarshal((TPMS_SCHEME_XOR *)&(target->xOr), buffer, size, FALSE);
#endif
        case TPM_ALG_NULL:
                    return TPM_RC_SUCCESS;
    }
    return TPM_RC_SELECTOR;
}

UINT16
TPMU_SCHEME_KEYEDHASH_Marshal(TPMU_SCHEME_KEYEDHASH *source, BYTE **buffer, INT32 *size, UINT32 selector)
{
    switch(selector) {
#ifdef TPM_ALG_HMAC
        case TPM_ALG_HMAC:
            return TPMS_SCHEME_HMAC_Marshal((TPMS_SCHEME_HMAC *)&(source->hmac), buffer, size);
#endif
#ifdef TPM_ALG_XOR
        case TPM_ALG_XOR:
            return TPMS_SCHEME_XOR_Marshal((TPMS_SCHEME_XOR *)&(source->xOr), buffer, size);
#endif
        case TPM_ALG_NULL:
                    return 0;
    }
    pAssert(FALSE);
    return 0;
}


// Table 137 -- TPMT_KEYEDHASH_SCHEME Structure <I/O>
TPM_RC
TPMT_KEYEDHASH_SCHEME_Unmarshal(TPMT_KEYEDHASH_SCHEME *target, BYTE **buffer, INT32 *size, BOOL flag)
{
    TPM_RC    result;
    result = TPMI_ALG_KEYEDHASH_SCHEME_Unmarshal((TPMI_ALG_KEYEDHASH_SCHEME *)&(target->scheme), buffer, size, flag);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPMU_SCHEME_KEYEDHASH_Unmarshal((TPMU_SCHEME_KEYEDHASH *)&(target->details), buffer, size, (UINT32)target->scheme);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPMT_KEYEDHASH_SCHEME_Marshal(TPMT_KEYEDHASH_SCHEME *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPMI_ALG_KEYEDHASH_SCHEME_Marshal((TPMI_ALG_KEYEDHASH_SCHEME *)&(source->scheme), buffer, size));
    result = (UINT16)(result + TPMU_SCHEME_KEYEDHASH_Marshal((TPMU_SCHEME_KEYEDHASH *)&(source->details), buffer, size, (UINT32)source->scheme));

    return result;
}


// Table 138 -- RSA_SIG_SCHEMES Types <I/O>
#ifdef TPM_ALG_RSA
TPM_RC
TPMS_SCHEME_RSASSA_Unmarshal(TPMS_SCHEME_RSASSA *target, BYTE **buffer, INT32 *size)
{
    return TPMS_SCHEME_SIGHASH_Unmarshal((TPMS_SCHEME_SIGHASH *)target, buffer, size);
}

TPM_RC
TPMS_SCHEME_RSAPSS_Unmarshal(TPMS_SCHEME_RSAPSS *target, BYTE **buffer, INT32 *size)
{
    return TPMS_SCHEME_SIGHASH_Unmarshal((TPMS_SCHEME_SIGHASH *)target, buffer, size);
}


#endif
#ifdef TPM_ALG_RSA
UINT16
TPMS_SCHEME_RSASSA_Marshal(TPMS_SCHEME_RSASSA *source, BYTE **buffer, INT32 *size)
{
    return TPMS_SCHEME_SIGHASH_Marshal((TPMS_SCHEME_SIGHASH *)source, buffer, size);
}

UINT16
TPMS_SCHEME_RSAPSS_Marshal(TPMS_SCHEME_RSAPSS *source, BYTE **buffer, INT32 *size)
{
    return TPMS_SCHEME_SIGHASH_Marshal((TPMS_SCHEME_SIGHASH *)source, buffer, size);
}


#endif

// Table 139 -- ECC_SIG_SCHEMES Types <I/O>
#ifdef TPM_ALG_ECC
TPM_RC
TPMS_SCHEME_ECDSA_Unmarshal(TPMS_SCHEME_ECDSA *target, BYTE **buffer, INT32 *size)
{
    return TPMS_SCHEME_SIGHASH_Unmarshal((TPMS_SCHEME_SIGHASH *)target, buffer, size);
}

TPM_RC
TPMS_SCHEME_SM2_Unmarshal(TPMS_SCHEME_SM2 *target, BYTE **buffer, INT32 *size)
{
    return TPMS_SCHEME_SIGHASH_Unmarshal((TPMS_SCHEME_SIGHASH *)target, buffer, size);
}

TPM_RC
TPMS_SCHEME_ECSCHNORR_Unmarshal(TPMS_SCHEME_ECSCHNORR *target, BYTE **buffer, INT32 *size)
{
    return TPMS_SCHEME_SIGHASH_Unmarshal((TPMS_SCHEME_SIGHASH *)target, buffer, size);
}


#endif
#ifdef TPM_ALG_ECC
UINT16
TPMS_SCHEME_ECDSA_Marshal(TPMS_SCHEME_ECDSA *source, BYTE **buffer, INT32 *size)
{
    return TPMS_SCHEME_SIGHASH_Marshal((TPMS_SCHEME_SIGHASH *)source, buffer, size);
}

UINT16
TPMS_SCHEME_SM2_Marshal(TPMS_SCHEME_SM2 *source, BYTE **buffer, INT32 *size)
{
    return TPMS_SCHEME_SIGHASH_Marshal((TPMS_SCHEME_SIGHASH *)source, buffer, size);
}

UINT16
TPMS_SCHEME_ECSCHNORR_Marshal(TPMS_SCHEME_ECSCHNORR *source, BYTE **buffer, INT32 *size)
{
    return TPMS_SCHEME_SIGHASH_Marshal((TPMS_SCHEME_SIGHASH *)source, buffer, size);
}


#endif

// Table 140 -- TPMS_SCHEME_ECDAA Structure <I/O>
#ifdef TPM_ALG_ECC
TPM_RC
TPMS_SCHEME_ECDAA_Unmarshal(TPMS_SCHEME_ECDAA *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPMI_ALG_HASH_Unmarshal((TPMI_ALG_HASH *)&(target->hashAlg), buffer, size, FALSE);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = UINT16_Unmarshal((UINT16 *)&(target->count), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

#endif
#ifdef TPM_ALG_ECC
UINT16
TPMS_SCHEME_ECDAA_Marshal(TPMS_SCHEME_ECDAA *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPMI_ALG_HASH_Marshal((TPMI_ALG_HASH *)&(source->hashAlg), buffer, size));
    result = (UINT16)(result + UINT16_Marshal((UINT16 *)&(source->count), buffer, size));

    return result;
}

#endif

// Table 141 -- TPMU_SIG_SCHEME Union <I/O,S>
TPM_RC
TPMU_SIG_SCHEME_Unmarshal(TPMU_SIG_SCHEME *target, BYTE **buffer, INT32 *size, UINT32 selector)
{
    switch(selector) {
#ifdef TPM_ALG_RSASSA
        case TPM_ALG_RSASSA:
            return TPMS_SCHEME_RSASSA_Unmarshal((TPMS_SCHEME_RSASSA *)&(target->rsassa), buffer, size);
#endif
#ifdef TPM_ALG_RSAPSS
        case TPM_ALG_RSAPSS:
            return TPMS_SCHEME_RSAPSS_Unmarshal((TPMS_SCHEME_RSAPSS *)&(target->rsapss), buffer, size);
#endif
#ifdef TPM_ALG_ECDSA
        case TPM_ALG_ECDSA:
            return TPMS_SCHEME_ECDSA_Unmarshal((TPMS_SCHEME_ECDSA *)&(target->ecdsa), buffer, size);
#endif
#ifdef TPM_ALG_SM2
        case TPM_ALG_SM2:
            return TPMS_SCHEME_SM2_Unmarshal((TPMS_SCHEME_SM2 *)&(target->sm2), buffer, size);
#endif
#ifdef TPM_ALG_ECDAA
        case TPM_ALG_ECDAA:
            return TPMS_SCHEME_ECDAA_Unmarshal((TPMS_SCHEME_ECDAA *)&(target->ecdaa), buffer, size);
#endif
#ifdef TPM_ALG_ECSCHNORR
        case TPM_ALG_ECSCHNORR:
            return TPMS_SCHEME_ECSCHNORR_Unmarshal((TPMS_SCHEME_ECSCHNORR *)&(target->ecSchnorr), buffer, size);
#endif
#ifdef TPM_ALG_HMAC
        case TPM_ALG_HMAC:
            return TPMS_SCHEME_HMAC_Unmarshal((TPMS_SCHEME_HMAC *)&(target->hmac), buffer, size);
#endif
        case TPM_ALG_NULL:
                    return TPM_RC_SUCCESS;
    }
    return TPM_RC_SELECTOR;
}

UINT16
TPMU_SIG_SCHEME_Marshal(TPMU_SIG_SCHEME *source, BYTE **buffer, INT32 *size, UINT32 selector)
{
    switch(selector) {
#ifdef TPM_ALG_RSASSA
        case TPM_ALG_RSASSA:
            return TPMS_SCHEME_RSASSA_Marshal((TPMS_SCHEME_RSASSA *)&(source->rsassa), buffer, size);
#endif
#ifdef TPM_ALG_RSAPSS
        case TPM_ALG_RSAPSS:
            return TPMS_SCHEME_RSAPSS_Marshal((TPMS_SCHEME_RSAPSS *)&(source->rsapss), buffer, size);
#endif
#ifdef TPM_ALG_ECDSA
        case TPM_ALG_ECDSA:
            return TPMS_SCHEME_ECDSA_Marshal((TPMS_SCHEME_ECDSA *)&(source->ecdsa), buffer, size);
#endif
#ifdef TPM_ALG_SM2
        case TPM_ALG_SM2:
            return TPMS_SCHEME_SM2_Marshal((TPMS_SCHEME_SM2 *)&(source->sm2), buffer, size);
#endif
#ifdef TPM_ALG_ECDAA
        case TPM_ALG_ECDAA:
            return TPMS_SCHEME_ECDAA_Marshal((TPMS_SCHEME_ECDAA *)&(source->ecdaa), buffer, size);
#endif
#ifdef TPM_ALG_ECSCHNORR
        case TPM_ALG_ECSCHNORR:
            return TPMS_SCHEME_ECSCHNORR_Marshal((TPMS_SCHEME_ECSCHNORR *)&(source->ecSchnorr), buffer, size);
#endif
#ifdef TPM_ALG_HMAC
        case TPM_ALG_HMAC:
            return TPMS_SCHEME_HMAC_Marshal((TPMS_SCHEME_HMAC *)&(source->hmac), buffer, size);
#endif
        case TPM_ALG_NULL:
                    return 0;
    }
    pAssert(FALSE);
    return 0;
}


// Table 142 -- TPMT_SIG_SCHEME Structure <I/O>
TPM_RC
TPMT_SIG_SCHEME_Unmarshal(TPMT_SIG_SCHEME *target, BYTE **buffer, INT32 *size, BOOL flag)
{
    TPM_RC    result;
    result = TPMI_ALG_SIG_SCHEME_Unmarshal((TPMI_ALG_SIG_SCHEME *)&(target->scheme), buffer, size, flag);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPMU_SIG_SCHEME_Unmarshal((TPMU_SIG_SCHEME *)&(target->details), buffer, size, (UINT32)target->scheme);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPMT_SIG_SCHEME_Marshal(TPMT_SIG_SCHEME *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPMI_ALG_SIG_SCHEME_Marshal((TPMI_ALG_SIG_SCHEME *)&(source->scheme), buffer, size));
    result = (UINT16)(result + TPMU_SIG_SCHEME_Marshal((TPMU_SIG_SCHEME *)&(source->details), buffer, size, (UINT32)source->scheme));

    return result;
}


// Table 143 -- TPMS_SCHEME_OAEP Structure <I/O>
#ifdef TPM_ALG_RSA
TPM_RC
TPMS_SCHEME_OAEP_Unmarshal(TPMS_SCHEME_OAEP *target, BYTE **buffer, INT32 *size, BOOL flag)
{
    TPM_RC    result;
    result = TPMI_ALG_HASH_Unmarshal((TPMI_ALG_HASH *)&(target->hashAlg), buffer, size, flag);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

#endif
#ifdef TPM_ALG_RSA
UINT16
TPMS_SCHEME_OAEP_Marshal(TPMS_SCHEME_OAEP *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPMI_ALG_HASH_Marshal((TPMI_ALG_HASH *)&(source->hashAlg), buffer, size));

    return result;
}

#endif

// Table 144 -- TPMS_SCHEME_ECDH Structure <I/O>
#ifdef TPM_ALG_ECC
TPM_RC
TPMS_SCHEME_ECDH_Unmarshal(TPMS_SCHEME_ECDH *target, BYTE **buffer, INT32 *size, BOOL flag)
{
    TPM_RC    result;
    result = TPMI_ALG_HASH_Unmarshal((TPMI_ALG_HASH *)&(target->hashAlg), buffer, size, flag);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

#endif
#ifdef TPM_ALG_ECC
UINT16
TPMS_SCHEME_ECDH_Marshal(TPMS_SCHEME_ECDH *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPMI_ALG_HASH_Marshal((TPMI_ALG_HASH *)&(source->hashAlg), buffer, size));

    return result;
}

#endif

// Table 145 -- TPMS_SCHEME_MGF1 Structure <I/O>
TPM_RC
TPMS_SCHEME_MGF1_Unmarshal(TPMS_SCHEME_MGF1 *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPMI_ALG_HASH_Unmarshal((TPMI_ALG_HASH *)&(target->hashAlg), buffer, size, FALSE);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPMS_SCHEME_MGF1_Marshal(TPMS_SCHEME_MGF1 *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPMI_ALG_HASH_Marshal((TPMI_ALG_HASH *)&(source->hashAlg), buffer, size));

    return result;
}


// Table 146 -- TPMS_SCHEME_KDF1_SP800_56a Structure <I/O>
#ifdef TPM_ALG_ECC
TPM_RC
TPMS_SCHEME_KDF1_SP800_56a_Unmarshal(TPMS_SCHEME_KDF1_SP800_56a *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPMI_ALG_HASH_Unmarshal((TPMI_ALG_HASH *)&(target->hashAlg), buffer, size, FALSE);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

#endif
#ifdef TPM_ALG_ECC
UINT16
TPMS_SCHEME_KDF1_SP800_56a_Marshal(TPMS_SCHEME_KDF1_SP800_56a *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPMI_ALG_HASH_Marshal((TPMI_ALG_HASH *)&(source->hashAlg), buffer, size));

    return result;
}

#endif

// Table 147 -- TPMS_SCHEME_KDF2 Structure <I/O>
TPM_RC
TPMS_SCHEME_KDF2_Unmarshal(TPMS_SCHEME_KDF2 *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPMI_ALG_HASH_Unmarshal((TPMI_ALG_HASH *)&(target->hashAlg), buffer, size, FALSE);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPMS_SCHEME_KDF2_Marshal(TPMS_SCHEME_KDF2 *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPMI_ALG_HASH_Marshal((TPMI_ALG_HASH *)&(source->hashAlg), buffer, size));

    return result;
}


// Table 148 -- TPMS_SCHEME_KDF1_SP800_108 Structure <I/O>
TPM_RC
TPMS_SCHEME_KDF1_SP800_108_Unmarshal(TPMS_SCHEME_KDF1_SP800_108 *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPMI_ALG_HASH_Unmarshal((TPMI_ALG_HASH *)&(target->hashAlg), buffer, size, FALSE);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPMS_SCHEME_KDF1_SP800_108_Marshal(TPMS_SCHEME_KDF1_SP800_108 *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPMI_ALG_HASH_Marshal((TPMI_ALG_HASH *)&(source->hashAlg), buffer, size));

    return result;
}


// Table 149 -- TPMU_KDF_SCHEME Union <I/O,S>
TPM_RC
TPMU_KDF_SCHEME_Unmarshal(TPMU_KDF_SCHEME *target, BYTE **buffer, INT32 *size, UINT32 selector)
{
    switch(selector) {
#ifdef TPM_ALG_MGF1
        case TPM_ALG_MGF1:
            return TPMS_SCHEME_MGF1_Unmarshal((TPMS_SCHEME_MGF1 *)&(target->mgf1), buffer, size);
#endif
#ifdef TPM_ALG_KDF1_SP800_56a
        case TPM_ALG_KDF1_SP800_56a:
            return TPMS_SCHEME_KDF1_SP800_56a_Unmarshal((TPMS_SCHEME_KDF1_SP800_56a *)&(target->kdf1_SP800_56a), buffer, size);
#endif
#ifdef TPM_ALG_KDF2
        case TPM_ALG_KDF2:
            return TPMS_SCHEME_KDF2_Unmarshal((TPMS_SCHEME_KDF2 *)&(target->kdf2), buffer, size);
#endif
#ifdef TPM_ALG_KDF1_SP800_108
        case TPM_ALG_KDF1_SP800_108:
            return TPMS_SCHEME_KDF1_SP800_108_Unmarshal((TPMS_SCHEME_KDF1_SP800_108 *)&(target->kdf1_sp800_108), buffer, size);
#endif
        case TPM_ALG_NULL:
                    return TPM_RC_SUCCESS;
    }
    return TPM_RC_SELECTOR;
}

UINT16
TPMU_KDF_SCHEME_Marshal(TPMU_KDF_SCHEME *source, BYTE **buffer, INT32 *size, UINT32 selector)
{
    switch(selector) {
#ifdef TPM_ALG_MGF1
        case TPM_ALG_MGF1:
            return TPMS_SCHEME_MGF1_Marshal((TPMS_SCHEME_MGF1 *)&(source->mgf1), buffer, size);
#endif
#ifdef TPM_ALG_KDF1_SP800_56a
        case TPM_ALG_KDF1_SP800_56a:
            return TPMS_SCHEME_KDF1_SP800_56a_Marshal((TPMS_SCHEME_KDF1_SP800_56a *)&(source->kdf1_SP800_56a), buffer, size);
#endif
#ifdef TPM_ALG_KDF2
        case TPM_ALG_KDF2:
            return TPMS_SCHEME_KDF2_Marshal((TPMS_SCHEME_KDF2 *)&(source->kdf2), buffer, size);
#endif
#ifdef TPM_ALG_KDF1_SP800_108
        case TPM_ALG_KDF1_SP800_108:
            return TPMS_SCHEME_KDF1_SP800_108_Marshal((TPMS_SCHEME_KDF1_SP800_108 *)&(source->kdf1_sp800_108), buffer, size);
#endif
        case TPM_ALG_NULL:
                    return 0;
    }
    pAssert(FALSE);
    return 0;
}


// Table 150 -- TPMT_KDF_SCHEME Structure <I/O>
TPM_RC
TPMT_KDF_SCHEME_Unmarshal(TPMT_KDF_SCHEME *target, BYTE **buffer, INT32 *size, BOOL flag)
{
    TPM_RC    result;
    result = TPMI_ALG_KDF_Unmarshal((TPMI_ALG_KDF *)&(target->scheme), buffer, size, flag);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPMU_KDF_SCHEME_Unmarshal((TPMU_KDF_SCHEME *)&(target->details), buffer, size, (UINT32)target->scheme);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPMT_KDF_SCHEME_Marshal(TPMT_KDF_SCHEME *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPMI_ALG_KDF_Marshal((TPMI_ALG_KDF *)&(source->scheme), buffer, size));
    result = (UINT16)(result + TPMU_KDF_SCHEME_Marshal((TPMU_KDF_SCHEME *)&(source->details), buffer, size, (UINT32)source->scheme));

    return result;
}


// Table 152 -- TPMU_ASYM_SCHEME Union <I/O>
TPM_RC
TPMU_ASYM_SCHEME_Unmarshal(TPMU_ASYM_SCHEME *target, BYTE **buffer, INT32 *size, UINT32 selector)
{
    switch(selector) {
#ifdef TPM_ALG_RSASSA
        case TPM_ALG_RSASSA:
            return TPMS_SCHEME_RSASSA_Unmarshal((TPMS_SCHEME_RSASSA *)&(target->rsassa), buffer, size);
#endif
#ifdef TPM_ALG_RSAPSS
        case TPM_ALG_RSAPSS:
            return TPMS_SCHEME_RSAPSS_Unmarshal((TPMS_SCHEME_RSAPSS *)&(target->rsapss), buffer, size);
#endif
#ifdef TPM_ALG_RSAES
        case TPM_ALG_RSAES:
                    return TPM_RC_SUCCESS;
#endif
#ifdef TPM_ALG_OAEP
        case TPM_ALG_OAEP:
            return TPMS_SCHEME_OAEP_Unmarshal((TPMS_SCHEME_OAEP *)&(target->oaep), buffer, size, FALSE);
#endif
#ifdef TPM_ALG_ECDSA
        case TPM_ALG_ECDSA:
            return TPMS_SCHEME_ECDSA_Unmarshal((TPMS_SCHEME_ECDSA *)&(target->ecdsa), buffer, size);
#endif
#ifdef TPM_ALG_SM2
        case TPM_ALG_SM2:
            return TPMS_SCHEME_SM2_Unmarshal((TPMS_SCHEME_SM2 *)&(target->sm2), buffer, size);
#endif
#ifdef TPM_ALG_ECDAA
        case TPM_ALG_ECDAA:
            return TPMS_SCHEME_ECDAA_Unmarshal((TPMS_SCHEME_ECDAA *)&(target->ecdaa), buffer, size);
#endif
#ifdef TPM_ALG_ECSCHNORR
        case TPM_ALG_ECSCHNORR:
            return TPMS_SCHEME_ECSCHNORR_Unmarshal((TPMS_SCHEME_ECSCHNORR *)&(target->ecSchnorr), buffer, size);
#endif
#ifdef TPM_ALG_ECDH
        case TPM_ALG_ECDH:
                    return TPM_RC_SUCCESS;
#endif
        case TPM_ALG_NULL:
                    return TPM_RC_SUCCESS;
    }
    return TPM_RC_SELECTOR;
}

UINT16
TPMU_ASYM_SCHEME_Marshal(TPMU_ASYM_SCHEME *source, BYTE **buffer, INT32 *size, UINT32 selector)
{
    switch(selector) {
#ifdef TPM_ALG_RSASSA
        case TPM_ALG_RSASSA:
            return TPMS_SCHEME_RSASSA_Marshal((TPMS_SCHEME_RSASSA *)&(source->rsassa), buffer, size);
#endif
#ifdef TPM_ALG_RSAPSS
        case TPM_ALG_RSAPSS:
            return TPMS_SCHEME_RSAPSS_Marshal((TPMS_SCHEME_RSAPSS *)&(source->rsapss), buffer, size);
#endif
#ifdef TPM_ALG_RSAES
        case TPM_ALG_RSAES:
                    return 0;
#endif
#ifdef TPM_ALG_OAEP
        case TPM_ALG_OAEP:
            return TPMS_SCHEME_OAEP_Marshal((TPMS_SCHEME_OAEP *)&(source->oaep), buffer, size);
#endif
#ifdef TPM_ALG_ECDSA
        case TPM_ALG_ECDSA:
            return TPMS_SCHEME_ECDSA_Marshal((TPMS_SCHEME_ECDSA *)&(source->ecdsa), buffer, size);
#endif
#ifdef TPM_ALG_SM2
        case TPM_ALG_SM2:
            return TPMS_SCHEME_SM2_Marshal((TPMS_SCHEME_SM2 *)&(source->sm2), buffer, size);
#endif
#ifdef TPM_ALG_ECDAA
        case TPM_ALG_ECDAA:
            return TPMS_SCHEME_ECDAA_Marshal((TPMS_SCHEME_ECDAA *)&(source->ecdaa), buffer, size);
#endif
#ifdef TPM_ALG_ECSCHNORR
        case TPM_ALG_ECSCHNORR:
            return TPMS_SCHEME_ECSCHNORR_Marshal((TPMS_SCHEME_ECSCHNORR *)&(source->ecSchnorr), buffer, size);
#endif
#ifdef TPM_ALG_ECDH
        case TPM_ALG_ECDH:
                    return 0;
#endif
        case TPM_ALG_NULL:
                    return 0;
    }
    pAssert(FALSE);
    return 0;
}


// Table 154 -- TPMI_ALG_RSA_SCHEME Type <I/O>
#ifdef TPM_ALG_RSA
TPM_RC
TPMI_ALG_RSA_SCHEME_Unmarshal(TPMI_ALG_RSA_SCHEME *target, BYTE **buffer, INT32 *size, BOOL flag)
{
    TPM_RC    result;
    result = TPM_ALG_ID_Unmarshal((TPM_ALG_ID *)target, buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    switch (*target) {
#ifdef TPM_ALG_RSASSA
        case TPM_ALG_RSASSA:
#endif
#ifdef TPM_ALG_RSAPSS
        case TPM_ALG_RSAPSS:
#endif
#ifdef TPM_ALG_RSAES
        case TPM_ALG_RSAES:
#endif
#ifdef TPM_ALG_OAEP
        case TPM_ALG_OAEP:
#endif
            break;
        case TPM_ALG_NULL:
            if (flag)
                break;
            return TPM_RC_VALUE;
        default:
            return TPM_RC_VALUE;
    }
    return TPM_RC_SUCCESS;
}

#endif
#ifdef TPM_ALG_RSA
UINT16
TPMI_ALG_RSA_SCHEME_Marshal(TPMI_ALG_RSA_SCHEME *source, BYTE **buffer, INT32 *size)
{
    return UINT16_Marshal((UINT16 *)source, buffer, size);
}

#endif

// Table 155 -- TPMT_RSA_SCHEME Structure <I/O>
#ifdef TPM_ALG_RSA
TPM_RC
TPMT_RSA_SCHEME_Unmarshal(TPMT_RSA_SCHEME *target, BYTE **buffer, INT32 *size, BOOL flag)
{
    TPM_RC    result;
    result = TPMI_ALG_RSA_SCHEME_Unmarshal((TPMI_ALG_RSA_SCHEME *)&(target->scheme), buffer, size, flag);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPMU_ASYM_SCHEME_Unmarshal((TPMU_ASYM_SCHEME *)&(target->details), buffer, size, (UINT32)target->scheme);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

#endif
#ifdef TPM_ALG_RSA
UINT16
TPMT_RSA_SCHEME_Marshal(TPMT_RSA_SCHEME *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPMI_ALG_RSA_SCHEME_Marshal((TPMI_ALG_RSA_SCHEME *)&(source->scheme), buffer, size));
    result = (UINT16)(result + TPMU_ASYM_SCHEME_Marshal((TPMU_ASYM_SCHEME *)&(source->details), buffer, size, (UINT32)source->scheme));

    return result;
}

#endif

// Table 156 -- TPMI_ALG_RSA_DECRYPT Type <I/O>
#ifdef TPM_ALG_RSA
TPM_RC
TPMI_ALG_RSA_DECRYPT_Unmarshal(TPMI_ALG_RSA_DECRYPT *target, BYTE **buffer, INT32 *size, BOOL flag)
{
    TPM_RC    result;
    result = TPM_ALG_ID_Unmarshal((TPM_ALG_ID *)target, buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    switch (*target) {
#ifdef TPM_ALG_RSAES
        case TPM_ALG_RSAES:
#endif
#ifdef TPM_ALG_OAEP
        case TPM_ALG_OAEP:
#endif
            break;
        case TPM_ALG_NULL:
            if (flag)
                break;
            return TPM_RC_VALUE;
        default:
            return TPM_RC_VALUE;
    }
    return TPM_RC_SUCCESS;
}

#endif
#ifdef TPM_ALG_RSA
UINT16
TPMI_ALG_RSA_DECRYPT_Marshal(TPMI_ALG_RSA_DECRYPT *source, BYTE **buffer, INT32 *size)
{
    return UINT16_Marshal((UINT16 *)source, buffer, size);
}

#endif

// Table 157 -- TPMT_RSA_DECRYPT Structure <I/O>
#ifdef TPM_ALG_RSA
TPM_RC
TPMT_RSA_DECRYPT_Unmarshal(TPMT_RSA_DECRYPT *target, BYTE **buffer, INT32 *size, BOOL flag)
{
    TPM_RC    result;
    result = TPMI_ALG_RSA_DECRYPT_Unmarshal((TPMI_ALG_RSA_DECRYPT *)&(target->scheme), buffer, size, flag);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPMU_ASYM_SCHEME_Unmarshal((TPMU_ASYM_SCHEME *)&(target->details), buffer, size, (UINT32)target->scheme);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

#endif
#ifdef TPM_ALG_RSA
UINT16
TPMT_RSA_DECRYPT_Marshal(TPMT_RSA_DECRYPT *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPMI_ALG_RSA_DECRYPT_Marshal((TPMI_ALG_RSA_DECRYPT *)&(source->scheme), buffer, size));
    result = (UINT16)(result + TPMU_ASYM_SCHEME_Marshal((TPMU_ASYM_SCHEME *)&(source->details), buffer, size, (UINT32)source->scheme));

    return result;
}

#endif

// Table 158 -- TPM2B_PUBLIC_KEY_RSA Structure <I/O>
#ifdef TPM_ALG_RSA
TPM_RC
TPM2B_PUBLIC_KEY_RSA_Unmarshal(TPM2B_PUBLIC_KEY_RSA *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = UINT16_Unmarshal((UINT16 *)&(target->t.size), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    // if size equal to 0, the rest of the structure is a zero buffer.  Stop processing
    if(target->t.size == 0) return TPM_RC_SUCCESS;
    if((target->t.size) > MAX_RSA_KEY_BYTES)
        return TPM_RC_SIZE;
    result = BYTE_Array_Unmarshal((BYTE *)(target->t.buffer), buffer, size, (INT32)(target->t.size));
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

#endif
#ifdef TPM_ALG_RSA
UINT16
TPM2B_PUBLIC_KEY_RSA_Marshal(TPM2B_PUBLIC_KEY_RSA *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + UINT16_Marshal((UINT16 *)&(source->t.size), buffer, size));
    // if size equal to 0, the rest of the structure is a zero buffer.  Stop processing
    if(source->t.size == 0) return result;
    result = (UINT16)(result + BYTE_Array_Marshal((BYTE *)(source->t.buffer), buffer, size, (INT32)(source->t.size)));

    return result;
}

#endif

// Table 159 -- TPMI_RSA_KEY_BITS Type <I/O>
#ifdef TPM_ALG_RSA
TPM_RC
TPMI_RSA_KEY_BITS_Unmarshal(TPMI_RSA_KEY_BITS *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPM_KEY_BITS_Unmarshal((TPM_KEY_BITS *)target, buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    switch (*target) {
        case 1024:
        case 2048:
            break;
        default:
            return TPM_RC_VALUE;
    }
    return TPM_RC_SUCCESS;
}

#endif
#ifdef TPM_ALG_RSA
UINT16
TPMI_RSA_KEY_BITS_Marshal(TPMI_RSA_KEY_BITS *source, BYTE **buffer, INT32 *size)
{
    return UINT16_Marshal((UINT16 *)source, buffer, size);
}

#endif

// Table 160 -- TPM2B_PRIVATE_KEY_RSA Structure <I/O>
#ifdef TPM_ALG_RSA
TPM_RC
TPM2B_PRIVATE_KEY_RSA_Unmarshal(TPM2B_PRIVATE_KEY_RSA *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = UINT16_Unmarshal((UINT16 *)&(target->t.size), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    // if size equal to 0, the rest of the structure is a zero buffer.  Stop processing
    if(target->t.size == 0) return TPM_RC_SUCCESS;
    if((target->t.size) > MAX_RSA_KEY_BYTES/2)
        return TPM_RC_SIZE;
    result = BYTE_Array_Unmarshal((BYTE *)(target->t.buffer), buffer, size, (INT32)(target->t.size));
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

#endif
#ifdef TPM_ALG_RSA
UINT16
TPM2B_PRIVATE_KEY_RSA_Marshal(TPM2B_PRIVATE_KEY_RSA *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + UINT16_Marshal((UINT16 *)&(source->t.size), buffer, size));
    // if size equal to 0, the rest of the structure is a zero buffer.  Stop processing
    if(source->t.size == 0) return result;
    result = (UINT16)(result + BYTE_Array_Marshal((BYTE *)(source->t.buffer), buffer, size, (INT32)(source->t.size)));

    return result;
}

#endif

// Table 161 -- TPM2B_ECC_PARAMETER Structure <I/O>
#ifdef TPM_ALG_ECC
TPM_RC
TPM2B_ECC_PARAMETER_Unmarshal(TPM2B_ECC_PARAMETER *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = UINT16_Unmarshal((UINT16 *)&(target->t.size), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    // if size equal to 0, the rest of the structure is a zero buffer.  Stop processing
    if(target->t.size == 0) return TPM_RC_SUCCESS;
    if((target->t.size) > MAX_ECC_KEY_BYTES)
        return TPM_RC_SIZE;
    result = BYTE_Array_Unmarshal((BYTE *)(target->t.buffer), buffer, size, (INT32)(target->t.size));
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

#endif
#ifdef TPM_ALG_ECC
UINT16
TPM2B_ECC_PARAMETER_Marshal(TPM2B_ECC_PARAMETER *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + UINT16_Marshal((UINT16 *)&(source->t.size), buffer, size));
    // if size equal to 0, the rest of the structure is a zero buffer.  Stop processing
    if(source->t.size == 0) return result;
    result = (UINT16)(result + BYTE_Array_Marshal((BYTE *)(source->t.buffer), buffer, size, (INT32)(source->t.size)));

    return result;
}

#endif

// Table 162 -- TPMS_ECC_POINT Structure <I/O>
#ifdef TPM_ALG_ECC
TPM_RC
TPMS_ECC_POINT_Unmarshal(TPMS_ECC_POINT *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPM2B_ECC_PARAMETER_Unmarshal((TPM2B_ECC_PARAMETER *)&(target->x), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPM2B_ECC_PARAMETER_Unmarshal((TPM2B_ECC_PARAMETER *)&(target->y), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

#endif
#ifdef TPM_ALG_ECC
UINT16
TPMS_ECC_POINT_Marshal(TPMS_ECC_POINT *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPM2B_ECC_PARAMETER_Marshal((TPM2B_ECC_PARAMETER *)&(source->x), buffer, size));
    result = (UINT16)(result + TPM2B_ECC_PARAMETER_Marshal((TPM2B_ECC_PARAMETER *)&(source->y), buffer, size));

    return result;
}

#endif

// Table 163 -- TPM2B_ECC_POINT Structure <I/O>
#ifdef TPM_ALG_ECC
TPM_RC
TPM2B_ECC_POINT_Unmarshal(TPM2B_ECC_POINT *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    INT32    startSize;
    result = UINT16_Unmarshal((UINT16 *)&(target->t.size), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    startSize = *size;
    result = TPMS_ECC_POINT_Unmarshal((TPMS_ECC_POINT *)&(target->t.point), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    if(target->t.size != (startSize - *size)) return TPM_RC_SIZE;

    return TPM_RC_SUCCESS;
}

#endif
#ifdef TPM_ALG_ECC
UINT16
TPM2B_ECC_POINT_Marshal(TPM2B_ECC_POINT *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    BYTE      *sizeField = NULL;
    // Advance buffer pointer by cononical size of a UINT16
    if(buffer != NULL)
    {
        sizeField = *buffer;
        *buffer += 2;
    }
    // Marshal the structure
    result = (UINT16)(result + TPMS_ECC_POINT_Marshal((TPMS_ECC_POINT *)&(source->t.point), buffer, size));
    // Marshal the size
    result = (UINT16)(result + UINT16_Marshal(&result, sizeField ? &sizeField : NULL, size)); 
    return result;
}
#endif

// Table 164 -- TPMI_ALG_ECC_SCHEME Type <I/O>
#ifdef TPM_ALG_ECC
TPM_RC
TPMI_ALG_ECC_SCHEME_Unmarshal(TPMI_ALG_ECC_SCHEME *target, BYTE **buffer, INT32 *size, BOOL flag)
{
    TPM_RC    result;
    result = TPM_ALG_ID_Unmarshal((TPM_ALG_ID *)target, buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    switch (*target) {
#ifdef TPM_ALG_ECDSA
        case TPM_ALG_ECDSA:
#endif
#ifdef TPM_ALG_SM2
        case TPM_ALG_SM2:
#endif
#ifdef TPM_ALG_ECDAA
        case TPM_ALG_ECDAA:
#endif
#ifdef TPM_ALG_ECSCHNORR
        case TPM_ALG_ECSCHNORR:
#endif
#ifdef TPM_ALG_ECDH
        case TPM_ALG_ECDH:
#endif
            break;
        case TPM_ALG_NULL:
            if (flag)
                break;
            return TPM_RC_SCHEME;
        default:
            return TPM_RC_SCHEME;
    }
    return TPM_RC_SUCCESS;
}

#endif
#ifdef TPM_ALG_ECC
UINT16
TPMI_ALG_ECC_SCHEME_Marshal(TPMI_ALG_ECC_SCHEME *source, BYTE **buffer, INT32 *size)
{
    return UINT16_Marshal((UINT16 *)source, buffer, size);
}

#endif

// Table 165 -- TPMI_ECC_CURVE Type <I/O>
#ifdef TPM_ALG_ECC
TPM_RC
TPMI_ECC_CURVE_Unmarshal(TPMI_ECC_CURVE *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPM_ECC_CURVE_Unmarshal((TPM_ECC_CURVE *)target, buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    switch (*target) {
        case TPM_ECC_NIST_P256:
        case TPM_ECC_BN_P256:
        case TPM_ECC_SM2_P256:
            break;
        default:
            return TPM_RC_CURVE;
    }
    return TPM_RC_SUCCESS;
}

#endif
#ifdef TPM_ALG_ECC
UINT16
TPMI_ECC_CURVE_Marshal(TPMI_ECC_CURVE *source, BYTE **buffer, INT32 *size)
{
    return UINT16_Marshal((UINT16 *)source, buffer, size);
}

#endif

// Table 166 -- TPMT_ECC_SCHEME Structure <I/O>
#ifdef TPM_ALG_ECC
TPM_RC
TPMT_ECC_SCHEME_Unmarshal(TPMT_ECC_SCHEME *target, BYTE **buffer, INT32 *size, BOOL flag)
{
    TPM_RC    result;
    result = TPMI_ALG_ECC_SCHEME_Unmarshal((TPMI_ALG_ECC_SCHEME *)&(target->scheme), buffer, size, flag);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPMU_SIG_SCHEME_Unmarshal((TPMU_SIG_SCHEME *)&(target->details), buffer, size, (UINT32)target->scheme);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

#endif
#ifdef TPM_ALG_ECC
UINT16
TPMT_ECC_SCHEME_Marshal(TPMT_ECC_SCHEME *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPMI_ALG_ECC_SCHEME_Marshal((TPMI_ALG_ECC_SCHEME *)&(source->scheme), buffer, size));
    result = (UINT16)(result + TPMU_SIG_SCHEME_Marshal((TPMU_SIG_SCHEME *)&(source->details), buffer, size, (UINT32)source->scheme));

    return result;
}

#endif

// Table 167 -- TPMS_ALGORITHM_DETAIL_ECC Structure <O,S>
#ifdef TPM_ALG_ECC
TPM_RC
TPMS_ALGORITHM_DETAIL_ECC_Unmarshal(TPMS_ALGORITHM_DETAIL_ECC *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPM_ECC_CURVE_Unmarshal((TPM_ECC_CURVE *)&(target->curveID), buffer, size);
    if (result != TPM_RC_SUCCESS) return result;
    result = UINT16_Unmarshal((UINT16 *)&(target->keySize), buffer, size);
    if (result != TPM_RC_SUCCESS) return result;
    result = TPMT_KDF_SCHEME_Unmarshal((TPMT_KDF_SCHEME *)&(target->kdf), buffer, size, FALSE);
    if (result != TPM_RC_SUCCESS) return result;
    result = TPMT_ECC_SCHEME_Unmarshal((TPMT_ECC_SCHEME *)&(target->sign), buffer, size, FALSE);
    if (result != TPM_RC_SUCCESS) return result;
    result = TPM2B_ECC_PARAMETER_Unmarshal((TPM2B_ECC_PARAMETER *)&(target->p), buffer, size);
    if (result != TPM_RC_SUCCESS) return result;
    result = TPM2B_ECC_PARAMETER_Unmarshal((TPM2B_ECC_PARAMETER *)&(target->a), buffer, size);
    if (result != TPM_RC_SUCCESS) return result;
    result = TPM2B_ECC_PARAMETER_Unmarshal((TPM2B_ECC_PARAMETER *)&(target->b), buffer, size);
    if (result != TPM_RC_SUCCESS) return result;
    result = TPM2B_ECC_PARAMETER_Unmarshal((TPM2B_ECC_PARAMETER *)&(target->gX), buffer, size);
    if (result != TPM_RC_SUCCESS) return result;
    result = TPM2B_ECC_PARAMETER_Unmarshal((TPM2B_ECC_PARAMETER *)&(target->gY), buffer, size);
    if (result != TPM_RC_SUCCESS) return result;
    result = TPM2B_ECC_PARAMETER_Unmarshal((TPM2B_ECC_PARAMETER *)&(target->n), buffer, size);
    if (result != TPM_RC_SUCCESS) return result;
    result = TPM2B_ECC_PARAMETER_Unmarshal((TPM2B_ECC_PARAMETER *)&(target->h), buffer, size);
    if (result != TPM_RC_SUCCESS) return result;

    return TPM_RC_SUCCESS;
}
#endif
#ifdef TPM_ALG_ECC
UINT16
TPMS_ALGORITHM_DETAIL_ECC_Marshal(TPMS_ALGORITHM_DETAIL_ECC *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPM_ECC_CURVE_Marshal((TPM_ECC_CURVE *)&(source->curveID), buffer, size));
    result = (UINT16)(result + UINT16_Marshal((UINT16 *)&(source->keySize), buffer, size));
    result = (UINT16)(result + TPMT_KDF_SCHEME_Marshal((TPMT_KDF_SCHEME *)&(source->kdf), buffer, size));
    result = (UINT16)(result + TPMT_ECC_SCHEME_Marshal((TPMT_ECC_SCHEME *)&(source->sign), buffer, size));
    result = (UINT16)(result + TPM2B_ECC_PARAMETER_Marshal((TPM2B_ECC_PARAMETER *)&(source->p), buffer, size));
    result = (UINT16)(result + TPM2B_ECC_PARAMETER_Marshal((TPM2B_ECC_PARAMETER *)&(source->a), buffer, size));
    result = (UINT16)(result + TPM2B_ECC_PARAMETER_Marshal((TPM2B_ECC_PARAMETER *)&(source->b), buffer, size));
    result = (UINT16)(result + TPM2B_ECC_PARAMETER_Marshal((TPM2B_ECC_PARAMETER *)&(source->gX), buffer, size));
    result = (UINT16)(result + TPM2B_ECC_PARAMETER_Marshal((TPM2B_ECC_PARAMETER *)&(source->gY), buffer, size));
    result = (UINT16)(result + TPM2B_ECC_PARAMETER_Marshal((TPM2B_ECC_PARAMETER *)&(source->n), buffer, size));
    result = (UINT16)(result + TPM2B_ECC_PARAMETER_Marshal((TPM2B_ECC_PARAMETER *)&(source->h), buffer, size));

    return result;
}

#endif

// Table 168 -- TPMS_SIGNATURE_RSASSA Structure <I/O>
#ifdef TPM_ALG_RSA
TPM_RC
TPMS_SIGNATURE_RSASSA_Unmarshal(TPMS_SIGNATURE_RSASSA *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPMI_ALG_HASH_Unmarshal((TPMI_ALG_HASH *)&(target->hash), buffer, size, FALSE);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPM2B_PUBLIC_KEY_RSA_Unmarshal((TPM2B_PUBLIC_KEY_RSA *)&(target->sig), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

#endif
#ifdef TPM_ALG_RSA
UINT16
TPMS_SIGNATURE_RSASSA_Marshal(TPMS_SIGNATURE_RSASSA *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPMI_ALG_HASH_Marshal((TPMI_ALG_HASH *)&(source->hash), buffer, size));
    result = (UINT16)(result + TPM2B_PUBLIC_KEY_RSA_Marshal((TPM2B_PUBLIC_KEY_RSA *)&(source->sig), buffer, size));

    return result;
}

#endif

// Table 169 -- TPMS_SIGNATURE_RSAPSS Structure <I/O>
#ifdef TPM_ALG_RSA
TPM_RC
TPMS_SIGNATURE_RSAPSS_Unmarshal(TPMS_SIGNATURE_RSAPSS *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPMI_ALG_HASH_Unmarshal((TPMI_ALG_HASH *)&(target->hash), buffer, size, FALSE);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPM2B_PUBLIC_KEY_RSA_Unmarshal((TPM2B_PUBLIC_KEY_RSA *)&(target->sig), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

#endif
#ifdef TPM_ALG_RSA
UINT16
TPMS_SIGNATURE_RSAPSS_Marshal(TPMS_SIGNATURE_RSAPSS *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPMI_ALG_HASH_Marshal((TPMI_ALG_HASH *)&(source->hash), buffer, size));
    result = (UINT16)(result + TPM2B_PUBLIC_KEY_RSA_Marshal((TPM2B_PUBLIC_KEY_RSA *)&(source->sig), buffer, size));

    return result;
}

#endif

// Table 170 -- TPMS_SIGNATURE_ECDSA Structure <I/O>
#ifdef TPM_ALG_ECC
TPM_RC
TPMS_SIGNATURE_ECDSA_Unmarshal(TPMS_SIGNATURE_ECDSA *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPMI_ALG_HASH_Unmarshal((TPMI_ALG_HASH *)&(target->hash), buffer, size, FALSE);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPM2B_ECC_PARAMETER_Unmarshal((TPM2B_ECC_PARAMETER *)&(target->signatureR), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPM2B_ECC_PARAMETER_Unmarshal((TPM2B_ECC_PARAMETER *)&(target->signatureS), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

#endif
#ifdef TPM_ALG_ECC
UINT16
TPMS_SIGNATURE_ECDSA_Marshal(TPMS_SIGNATURE_ECDSA *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPMI_ALG_HASH_Marshal((TPMI_ALG_HASH *)&(source->hash), buffer, size));
    result = (UINT16)(result + TPM2B_ECC_PARAMETER_Marshal((TPM2B_ECC_PARAMETER *)&(source->signatureR), buffer, size));
    result = (UINT16)(result + TPM2B_ECC_PARAMETER_Marshal((TPM2B_ECC_PARAMETER *)&(source->signatureS), buffer, size));

    return result;
}

#endif

// Table 171 -- TPMU_SIGNATURE Union <I/O,S>
TPM_RC
TPMU_SIGNATURE_Unmarshal(TPMU_SIGNATURE *target, BYTE **buffer, INT32 *size, UINT32 selector)
{
    switch(selector) {
#ifdef TPM_ALG_RSASSA
        case TPM_ALG_RSASSA:
            return TPMS_SIGNATURE_RSASSA_Unmarshal((TPMS_SIGNATURE_RSASSA *)&(target->rsassa), buffer, size);
#endif
#ifdef TPM_ALG_RSAPSS
        case TPM_ALG_RSAPSS:
            return TPMS_SIGNATURE_RSAPSS_Unmarshal((TPMS_SIGNATURE_RSAPSS *)&(target->rsapss), buffer, size);
#endif
#ifdef TPM_ALG_ECDSA
        case TPM_ALG_ECDSA:
            return TPMS_SIGNATURE_ECDSA_Unmarshal((TPMS_SIGNATURE_ECDSA *)&(target->ecdsa), buffer, size);
#endif
#ifdef TPM_ALG_SM2
        case TPM_ALG_SM2:
            return TPMS_SIGNATURE_ECDSA_Unmarshal((TPMS_SIGNATURE_ECDSA *)&(target->sm2), buffer, size);
#endif
#ifdef TPM_ALG_ECDAA
        case TPM_ALG_ECDAA:
            return TPMS_SIGNATURE_ECDSA_Unmarshal((TPMS_SIGNATURE_ECDSA *)&(target->ecdaa), buffer, size);
#endif
#ifdef TPM_ALG_ECSCHNORR
        case TPM_ALG_ECSCHNORR:
            return TPMS_SIGNATURE_ECDSA_Unmarshal((TPMS_SIGNATURE_ECDSA *)&(target->ecschnorr), buffer, size);
#endif
#ifdef TPM_ALG_HMAC
        case TPM_ALG_HMAC:
            return TPMT_HA_Unmarshal((TPMT_HA *)&(target->hmac), buffer, size, FALSE);
#endif
        case TPM_ALG_NULL:
                    return TPM_RC_SUCCESS;
    }
    return TPM_RC_SELECTOR;
}

UINT16
TPMU_SIGNATURE_Marshal(TPMU_SIGNATURE *source, BYTE **buffer, INT32 *size, UINT32 selector)
{
    switch(selector) {
#ifdef TPM_ALG_RSASSA
        case TPM_ALG_RSASSA:
            return TPMS_SIGNATURE_RSASSA_Marshal((TPMS_SIGNATURE_RSASSA *)&(source->rsassa), buffer, size);
#endif
#ifdef TPM_ALG_RSAPSS
        case TPM_ALG_RSAPSS:
            return TPMS_SIGNATURE_RSAPSS_Marshal((TPMS_SIGNATURE_RSAPSS *)&(source->rsapss), buffer, size);
#endif
#ifdef TPM_ALG_ECDSA
        case TPM_ALG_ECDSA:
            return TPMS_SIGNATURE_ECDSA_Marshal((TPMS_SIGNATURE_ECDSA *)&(source->ecdsa), buffer, size);
#endif
#ifdef TPM_ALG_SM2
        case TPM_ALG_SM2:
            return TPMS_SIGNATURE_ECDSA_Marshal((TPMS_SIGNATURE_ECDSA *)&(source->sm2), buffer, size);
#endif
#ifdef TPM_ALG_ECDAA
        case TPM_ALG_ECDAA:
            return TPMS_SIGNATURE_ECDSA_Marshal((TPMS_SIGNATURE_ECDSA *)&(source->ecdaa), buffer, size);
#endif
#ifdef TPM_ALG_ECSCHNORR
        case TPM_ALG_ECSCHNORR:
            return TPMS_SIGNATURE_ECDSA_Marshal((TPMS_SIGNATURE_ECDSA *)&(source->ecschnorr), buffer, size);
#endif
#ifdef TPM_ALG_HMAC
        case TPM_ALG_HMAC:
            return TPMT_HA_Marshal((TPMT_HA *)&(source->hmac), buffer, size);
#endif
        case TPM_ALG_NULL:
                    return 0;
    }
    pAssert(FALSE);
    return 0;
}


// Table 172 -- TPMT_SIGNATURE Structure <I/O>
TPM_RC
TPMT_SIGNATURE_Unmarshal(TPMT_SIGNATURE *target, BYTE **buffer, INT32 *size, BOOL flag)
{
    TPM_RC    result;
    result = TPMI_ALG_SIG_SCHEME_Unmarshal((TPMI_ALG_SIG_SCHEME *)&(target->sigAlg), buffer, size, flag);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPMU_SIGNATURE_Unmarshal((TPMU_SIGNATURE *)&(target->signature), buffer, size, (UINT32)target->sigAlg);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPMT_SIGNATURE_Marshal(TPMT_SIGNATURE *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPMI_ALG_SIG_SCHEME_Marshal((TPMI_ALG_SIG_SCHEME *)&(source->sigAlg), buffer, size));
    result = (UINT16)(result + TPMU_SIGNATURE_Marshal((TPMU_SIGNATURE *)&(source->signature), buffer, size, (UINT32)source->sigAlg));

    return result;
}


// Table 174 -- TPM2B_ENCRYPTED_SECRET Structure <I/O>
TPM_RC
TPM2B_ENCRYPTED_SECRET_Unmarshal(TPM2B_ENCRYPTED_SECRET *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = UINT16_Unmarshal((UINT16 *)&(target->t.size), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    // if size equal to 0, the rest of the structure is a zero buffer.  Stop processing
    if(target->t.size == 0) return TPM_RC_SUCCESS;
    if((target->t.size) > sizeof(TPMU_ENCRYPTED_SECRET))
        return TPM_RC_SIZE;
    result = BYTE_Array_Unmarshal((BYTE *)(target->t.secret), buffer, size, (INT32)(target->t.size));
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPM2B_ENCRYPTED_SECRET_Marshal(TPM2B_ENCRYPTED_SECRET *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + UINT16_Marshal((UINT16 *)&(source->t.size), buffer, size));
    // if size equal to 0, the rest of the structure is a zero buffer.  Stop processing
    if(source->t.size == 0) return result;
    result = (UINT16)(result + BYTE_Array_Marshal((BYTE *)(source->t.secret), buffer, size, (INT32)(source->t.size)));

    return result;
}


// Table 175 -- TPMI_ALG_PUBLIC Type <I/O>
TPM_RC
TPMI_ALG_PUBLIC_Unmarshal(TPMI_ALG_PUBLIC *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPM_ALG_ID_Unmarshal((TPM_ALG_ID *)target, buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    switch (*target) {
#ifdef TPM_ALG_KEYEDHASH
        case TPM_ALG_KEYEDHASH:
#endif
#ifdef TPM_ALG_SYMCIPHER
        case TPM_ALG_SYMCIPHER:
#endif
#ifdef TPM_ALG_RSA
        case TPM_ALG_RSA:
#endif
#ifdef TPM_ALG_ECC
        case TPM_ALG_ECC:
#endif
            break;
        default:
            return TPM_RC_TYPE;
    }
    return TPM_RC_SUCCESS;
}

UINT16
TPMI_ALG_PUBLIC_Marshal(TPMI_ALG_PUBLIC *source, BYTE **buffer, INT32 *size)
{
    return UINT16_Marshal((UINT16 *)source, buffer, size);
}


// Table 176 -- TPMU_PUBLIC_ID Union <I/O,S>
TPM_RC
TPMU_PUBLIC_ID_Unmarshal(TPMU_PUBLIC_ID *target, BYTE **buffer, INT32 *size, UINT32 selector)
{
    switch(selector) {
#ifdef TPM_ALG_KEYEDHASH
        case TPM_ALG_KEYEDHASH:
            return TPM2B_DIGEST_Unmarshal((TPM2B_DIGEST *)&(target->keyedHash), buffer, size);
#endif
#ifdef TPM_ALG_SYMCIPHER
        case TPM_ALG_SYMCIPHER:
            return TPM2B_DIGEST_Unmarshal((TPM2B_DIGEST *)&(target->sym), buffer, size);
#endif
#ifdef TPM_ALG_RSA
        case TPM_ALG_RSA:
            return TPM2B_PUBLIC_KEY_RSA_Unmarshal((TPM2B_PUBLIC_KEY_RSA *)&(target->rsa), buffer, size);
#endif
#ifdef TPM_ALG_ECC
        case TPM_ALG_ECC:
            return TPMS_ECC_POINT_Unmarshal((TPMS_ECC_POINT *)&(target->ecc), buffer, size);
#endif
    }
    return TPM_RC_SELECTOR;
}

UINT16
TPMU_PUBLIC_ID_Marshal(TPMU_PUBLIC_ID *source, BYTE **buffer, INT32 *size, UINT32 selector)
{
    switch(selector) {
#ifdef TPM_ALG_KEYEDHASH
        case TPM_ALG_KEYEDHASH:
            return TPM2B_DIGEST_Marshal((TPM2B_DIGEST *)&(source->keyedHash), buffer, size);
#endif
#ifdef TPM_ALG_SYMCIPHER
        case TPM_ALG_SYMCIPHER:
            return TPM2B_DIGEST_Marshal((TPM2B_DIGEST *)&(source->sym), buffer, size);
#endif
#ifdef TPM_ALG_RSA
        case TPM_ALG_RSA:
            return TPM2B_PUBLIC_KEY_RSA_Marshal((TPM2B_PUBLIC_KEY_RSA *)&(source->rsa), buffer, size);
#endif
#ifdef TPM_ALG_ECC
        case TPM_ALG_ECC:
            return TPMS_ECC_POINT_Marshal((TPMS_ECC_POINT *)&(source->ecc), buffer, size);
#endif
    }
    pAssert(FALSE);
    return 0;
}


// Table 177 -- TPMS_KEYEDHASH_PARMS Structure <I/O>
TPM_RC
TPMS_KEYEDHASH_PARMS_Unmarshal(TPMS_KEYEDHASH_PARMS *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPMT_KEYEDHASH_SCHEME_Unmarshal((TPMT_KEYEDHASH_SCHEME *)&(target->scheme), buffer, size, TRUE);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPMS_KEYEDHASH_PARMS_Marshal(TPMS_KEYEDHASH_PARMS *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPMT_KEYEDHASH_SCHEME_Marshal((TPMT_KEYEDHASH_SCHEME *)&(source->scheme), buffer, size));

    return result;
}


// Table 179 -- TPMS_RSA_PARMS Structure <I/O>
#ifdef TPM_ALG_RSA
TPM_RC
TPMS_RSA_PARMS_Unmarshal(TPMS_RSA_PARMS *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPMT_SYM_DEF_OBJECT_Unmarshal((TPMT_SYM_DEF_OBJECT *)&(target->symmetric), buffer, size, TRUE);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPMT_RSA_SCHEME_Unmarshal((TPMT_RSA_SCHEME *)&(target->scheme), buffer, size, TRUE);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPMI_RSA_KEY_BITS_Unmarshal((TPMI_RSA_KEY_BITS *)&(target->keyBits), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = UINT32_Unmarshal((UINT32 *)&(target->exponent), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

#endif
#ifdef TPM_ALG_RSA
UINT16
TPMS_RSA_PARMS_Marshal(TPMS_RSA_PARMS *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPMT_SYM_DEF_OBJECT_Marshal((TPMT_SYM_DEF_OBJECT *)&(source->symmetric), buffer, size));
    result = (UINT16)(result + TPMT_RSA_SCHEME_Marshal((TPMT_RSA_SCHEME *)&(source->scheme), buffer, size));
    result = (UINT16)(result + TPMI_RSA_KEY_BITS_Marshal((TPMI_RSA_KEY_BITS *)&(source->keyBits), buffer, size));
    result = (UINT16)(result + UINT32_Marshal((UINT32 *)&(source->exponent), buffer, size));

    return result;
}

#endif

// Table 180 -- TPMS_ECC_PARMS Structure <I/O>
#ifdef TPM_ALG_ECC
TPM_RC
TPMS_ECC_PARMS_Unmarshal(TPMS_ECC_PARMS *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPMT_SYM_DEF_OBJECT_Unmarshal((TPMT_SYM_DEF_OBJECT *)&(target->symmetric), buffer, size, TRUE);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPMT_ECC_SCHEME_Unmarshal((TPMT_ECC_SCHEME *)&(target->scheme), buffer, size, TRUE);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPMI_ECC_CURVE_Unmarshal((TPMI_ECC_CURVE *)&(target->curveID), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPMT_KDF_SCHEME_Unmarshal((TPMT_KDF_SCHEME *)&(target->kdf), buffer, size, TRUE);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

#endif
#ifdef TPM_ALG_ECC
UINT16
TPMS_ECC_PARMS_Marshal(TPMS_ECC_PARMS *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPMT_SYM_DEF_OBJECT_Marshal((TPMT_SYM_DEF_OBJECT *)&(source->symmetric), buffer, size));
    result = (UINT16)(result + TPMT_ECC_SCHEME_Marshal((TPMT_ECC_SCHEME *)&(source->scheme), buffer, size));
    result = (UINT16)(result + TPMI_ECC_CURVE_Marshal((TPMI_ECC_CURVE *)&(source->curveID), buffer, size));
    result = (UINT16)(result + TPMT_KDF_SCHEME_Marshal((TPMT_KDF_SCHEME *)&(source->kdf), buffer, size));

    return result;
}

#endif

// Table 181 -- TPMU_PUBLIC_PARMS Union <I/O,S>
TPM_RC
TPMU_PUBLIC_PARMS_Unmarshal(TPMU_PUBLIC_PARMS *target, BYTE **buffer, INT32 *size, UINT32 selector)
{
    switch(selector) {
#ifdef TPM_ALG_KEYEDHASH
        case TPM_ALG_KEYEDHASH:
            return TPMS_KEYEDHASH_PARMS_Unmarshal((TPMS_KEYEDHASH_PARMS *)&(target->keyedHashDetail), buffer, size);
#endif
#ifdef TPM_ALG_SYMCIPHER
        case TPM_ALG_SYMCIPHER:
            return TPMT_SYM_DEF_OBJECT_Unmarshal((TPMT_SYM_DEF_OBJECT *)&(target->symDetail), buffer, size, FALSE);
#endif
#ifdef TPM_ALG_RSA
        case TPM_ALG_RSA:
            return TPMS_RSA_PARMS_Unmarshal((TPMS_RSA_PARMS *)&(target->rsaDetail), buffer, size);
#endif
#ifdef TPM_ALG_ECC
        case TPM_ALG_ECC:
            return TPMS_ECC_PARMS_Unmarshal((TPMS_ECC_PARMS *)&(target->eccDetail), buffer, size);
#endif
    }
    return TPM_RC_SELECTOR;
}

UINT16
TPMU_PUBLIC_PARMS_Marshal(TPMU_PUBLIC_PARMS *source, BYTE **buffer, INT32 *size, UINT32 selector)
{
    switch(selector) {
#ifdef TPM_ALG_KEYEDHASH
        case TPM_ALG_KEYEDHASH:
            return TPMS_KEYEDHASH_PARMS_Marshal((TPMS_KEYEDHASH_PARMS *)&(source->keyedHashDetail), buffer, size);
#endif
#ifdef TPM_ALG_SYMCIPHER
        case TPM_ALG_SYMCIPHER:
            return TPMT_SYM_DEF_OBJECT_Marshal((TPMT_SYM_DEF_OBJECT *)&(source->symDetail), buffer, size);
#endif
#ifdef TPM_ALG_RSA
        case TPM_ALG_RSA:
            return TPMS_RSA_PARMS_Marshal((TPMS_RSA_PARMS *)&(source->rsaDetail), buffer, size);
#endif
#ifdef TPM_ALG_ECC
        case TPM_ALG_ECC:
            return TPMS_ECC_PARMS_Marshal((TPMS_ECC_PARMS *)&(source->eccDetail), buffer, size);
#endif
    }
    pAssert(FALSE);
    return 0;
}


// Table 182 -- TPMT_PUBLIC_PARMS Structure <I/O>
TPM_RC
TPMT_PUBLIC_PARMS_Unmarshal(TPMT_PUBLIC_PARMS *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPMI_ALG_PUBLIC_Unmarshal((TPMI_ALG_PUBLIC *)&(target->type), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPMU_PUBLIC_PARMS_Unmarshal((TPMU_PUBLIC_PARMS *)&(target->parameters), buffer, size, (UINT32)target->type);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPMT_PUBLIC_PARMS_Marshal(TPMT_PUBLIC_PARMS *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPMI_ALG_PUBLIC_Marshal((TPMI_ALG_PUBLIC *)&(source->type), buffer, size));
    result = (UINT16)(result + TPMU_PUBLIC_PARMS_Marshal((TPMU_PUBLIC_PARMS *)&(source->parameters), buffer, size, (UINT32)source->type));

    return result;
}


// Table 183 -- TPMT_PUBLIC Structure <I/O>
TPM_RC
TPMT_PUBLIC_Unmarshal(TPMT_PUBLIC *target, BYTE **buffer, INT32 *size, BOOL flag)
{
    TPM_RC    result;
    result = TPMI_ALG_PUBLIC_Unmarshal((TPMI_ALG_PUBLIC *)&(target->type), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPMI_ALG_HASH_Unmarshal((TPMI_ALG_HASH *)&(target->nameAlg), buffer, size, flag);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPMA_OBJECT_Unmarshal((TPMA_OBJECT *)&(target->objectAttributes), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPM2B_DIGEST_Unmarshal((TPM2B_DIGEST *)&(target->authPolicy), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPMU_PUBLIC_PARMS_Unmarshal((TPMU_PUBLIC_PARMS *)&(target->parameters), buffer, size, (UINT32)target->type);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPMU_PUBLIC_ID_Unmarshal((TPMU_PUBLIC_ID *)&(target->unique), buffer, size, (UINT32)target->type);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPMT_PUBLIC_Marshal(TPMT_PUBLIC *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPMI_ALG_PUBLIC_Marshal((TPMI_ALG_PUBLIC *)&(source->type), buffer, size));
    result = (UINT16)(result + TPMI_ALG_HASH_Marshal((TPMI_ALG_HASH *)&(source->nameAlg), buffer, size));
    result = (UINT16)(result + TPMA_OBJECT_Marshal((TPMA_OBJECT *)&(source->objectAttributes), buffer, size));
    result = (UINT16)(result + TPM2B_DIGEST_Marshal((TPM2B_DIGEST *)&(source->authPolicy), buffer, size));
    result = (UINT16)(result + TPMU_PUBLIC_PARMS_Marshal((TPMU_PUBLIC_PARMS *)&(source->parameters), buffer, size, (UINT32)source->type));
    result = (UINT16)(result + TPMU_PUBLIC_ID_Marshal((TPMU_PUBLIC_ID *)&(source->unique), buffer, size, (UINT32)source->type));

    return result;
}


// Table 184 -- TPM2B_PUBLIC Structure <I/O>
TPM_RC
TPM2B_PUBLIC_Unmarshal(TPM2B_PUBLIC *target, BYTE **buffer, INT32 *size, BOOL flag)
{
    TPM_RC    result;
    INT32    startSize;
    result = UINT16_Unmarshal((UINT16 *)&(target->t.size), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    startSize = *size;
    result = TPMT_PUBLIC_Unmarshal((TPMT_PUBLIC *)&(target->t.publicArea), buffer, size, flag);
    if(result != TPM_RC_SUCCESS)
        return result;
    if(target->t.size != (startSize - *size)) return TPM_RC_SIZE;

    return TPM_RC_SUCCESS;
}

UINT16
TPM2B_PUBLIC_Marshal(TPM2B_PUBLIC *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    BYTE      *sizeField = NULL;
    // Advance buffer pointer by cononical size of a UINT16
    if(buffer != NULL)
    {
        sizeField = *buffer;
        *buffer += 2;
    }
    // Marshal the structure
    result = (UINT16)(result + TPMT_PUBLIC_Marshal((TPMT_PUBLIC *)&(source->t.publicArea), buffer, size));
    // Marshal the size
    result = (UINT16)(result + UINT16_Marshal(&result, sizeField ? &sizeField : NULL, size));
    return result;
}
#ifdef TPM_ALG_RSA
#endif
#ifdef TPM_ALG_RSA
#endif

// Table 186 -- TPMU_SENSITIVE_COMPOSITE Union <I/O,S>
TPM_RC
TPMU_SENSITIVE_COMPOSITE_Unmarshal(TPMU_SENSITIVE_COMPOSITE *target, BYTE **buffer, INT32 *size, UINT32 selector)
{
    switch(selector) {
#ifdef TPM_ALG_RSA
        case TPM_ALG_RSA:
            return TPM2B_PRIVATE_KEY_RSA_Unmarshal((TPM2B_PRIVATE_KEY_RSA *)&(target->rsa), buffer, size);
#endif
#ifdef TPM_ALG_ECC
        case TPM_ALG_ECC:
            return TPM2B_ECC_PARAMETER_Unmarshal((TPM2B_ECC_PARAMETER *)&(target->ecc), buffer, size);
#endif
#ifdef TPM_ALG_KEYEDHASH
        case TPM_ALG_KEYEDHASH:
            return TPM2B_SENSITIVE_DATA_Unmarshal((TPM2B_SENSITIVE_DATA *)&(target->bits), buffer, size);
#endif
#ifdef TPM_ALG_SYMCIPHER
        case TPM_ALG_SYMCIPHER:
            return TPM2B_SYM_KEY_Unmarshal((TPM2B_SYM_KEY *)&(target->sym), buffer, size);
#endif
    }
    return TPM_RC_SELECTOR;
}

UINT16
TPMU_SENSITIVE_COMPOSITE_Marshal(TPMU_SENSITIVE_COMPOSITE *source, BYTE **buffer, INT32 *size, UINT32 selector)
{
    switch(selector) {
#ifdef TPM_ALG_RSA
        case TPM_ALG_RSA:
            return TPM2B_PRIVATE_KEY_RSA_Marshal((TPM2B_PRIVATE_KEY_RSA *)&(source->rsa), buffer, size);
#endif
#ifdef TPM_ALG_ECC
        case TPM_ALG_ECC:
            return TPM2B_ECC_PARAMETER_Marshal((TPM2B_ECC_PARAMETER *)&(source->ecc), buffer, size);
#endif
#ifdef TPM_ALG_KEYEDHASH
        case TPM_ALG_KEYEDHASH:
            return TPM2B_SENSITIVE_DATA_Marshal((TPM2B_SENSITIVE_DATA *)&(source->bits), buffer, size);
#endif
#ifdef TPM_ALG_SYMCIPHER
        case TPM_ALG_SYMCIPHER:
            return TPM2B_SYM_KEY_Marshal((TPM2B_SYM_KEY *)&(source->sym), buffer, size);
#endif
    }
    pAssert(FALSE);
    return 0;
}


// Table 187 -- TPMT_SENSITIVE Structure <I/O>
TPM_RC
TPMT_SENSITIVE_Unmarshal(TPMT_SENSITIVE *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPMI_ALG_PUBLIC_Unmarshal((TPMI_ALG_PUBLIC *)&(target->sensitiveType), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPM2B_AUTH_Unmarshal((TPM2B_AUTH *)&(target->authValue), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPM2B_DIGEST_Unmarshal((TPM2B_DIGEST *)&(target->seedValue), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPMU_SENSITIVE_COMPOSITE_Unmarshal((TPMU_SENSITIVE_COMPOSITE *)&(target->sensitive), buffer, size, (UINT32)target->sensitiveType);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPMT_SENSITIVE_Marshal(TPMT_SENSITIVE *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPMI_ALG_PUBLIC_Marshal((TPMI_ALG_PUBLIC *)&(source->sensitiveType), buffer, size));
    result = (UINT16)(result + TPM2B_AUTH_Marshal((TPM2B_AUTH *)&(source->authValue), buffer, size));
    result = (UINT16)(result + TPM2B_DIGEST_Marshal((TPM2B_DIGEST *)&(source->seedValue), buffer, size));
    result = (UINT16)(result + TPMU_SENSITIVE_COMPOSITE_Marshal((TPMU_SENSITIVE_COMPOSITE *)&(source->sensitive), buffer, size, (UINT32)source->sensitiveType));

    return result;
}


// Table 188 -- TPM2B_SENSITIVE Structure <I/O>
TPM_RC
TPM2B_SENSITIVE_Unmarshal(TPM2B_SENSITIVE *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    INT32    startSize;
    result = UINT16_Unmarshal((UINT16 *)&(target->t.size), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    // if size equal to 0, the rest of the structure is a zero buffer.  Stop processing
    if(target->t.size == 0) return TPM_RC_SUCCESS;
    startSize = *size;
    result = TPMT_SENSITIVE_Unmarshal((TPMT_SENSITIVE *)&(target->t.sensitiveArea), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    if(target->t.size != (startSize - *size)) return TPM_RC_SIZE;

    return TPM_RC_SUCCESS;
}

UINT16
TPM2B_SENSITIVE_Marshal(TPM2B_SENSITIVE *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    BYTE      *sizeField = NULL;
    BYTE      zeroDetector = 0;

    // Advance buffer pointer by cononical size of a UINT16
    if(buffer != NULL)
    {
        sizeField = *buffer;
        *buffer += 2;
    }
    // See if there is anything to marshal
    for(UINT32 n = 0; n < sizeof(TPM2B_SENSITIVE); n++)
    {
        zeroDetector |= ((BYTE*)source)[n];
    }
    if(zeroDetector != 0)
    {
        // Marshal the structure
        result = (UINT16)(result + TPMT_SENSITIVE_Marshal((TPMT_SENSITIVE *)&(source->t.sensitiveArea), buffer, size));
    }
    // Marshal the size
    result = (UINT16)(result + UINT16_Marshal(&result, sizeField ? &sizeField : NULL, size));
    return result;
}

// Table 190 -- TPM2B_PRIVATE Structure <I/O,S>
TPM_RC
TPM2B_PRIVATE_Unmarshal(TPM2B_PRIVATE *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = UINT16_Unmarshal((UINT16 *)&(target->t.size), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    // if size equal to 0, the rest of the structure is a zero buffer.  Stop processing
    if(target->t.size == 0) return TPM_RC_SUCCESS;
    if((target->t.size) > sizeof(_PRIVATE))
        return TPM_RC_SIZE;
    result = BYTE_Array_Unmarshal((BYTE *)(target->t.buffer), buffer, size, (INT32)(target->t.size));
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPM2B_PRIVATE_Marshal(TPM2B_PRIVATE *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + UINT16_Marshal((UINT16 *)&(source->t.size), buffer, size));
    // if size equal to 0, the rest of the structure is a zero buffer.  Stop processing
    if(source->t.size == 0) return result;
    result = (UINT16)(result + BYTE_Array_Marshal((BYTE *)(source->t.buffer), buffer, size, (INT32)(source->t.size)));

    return result;
}


// Table 192 -- TPM2B_ID_OBJECT Structure <I/O>
TPM_RC
TPM2B_ID_OBJECT_Unmarshal(TPM2B_ID_OBJECT *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = UINT16_Unmarshal((UINT16 *)&(target->t.size), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    // if size equal to 0, the rest of the structure is a zero buffer.  Stop processing
    if(target->t.size == 0) return TPM_RC_SUCCESS;
    if((target->t.size) > sizeof(_ID_OBJECT))
        return TPM_RC_SIZE;
    result = BYTE_Array_Unmarshal((BYTE *)(target->t.credential), buffer, size, (INT32)(target->t.size));
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPM2B_ID_OBJECT_Marshal(TPM2B_ID_OBJECT *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + UINT16_Marshal((UINT16 *)&(source->t.size), buffer, size));
    // if size equal to 0, the rest of the structure is a zero buffer.  Stop processing
    if(source->t.size == 0) return result;
    result = (UINT16)(result + BYTE_Array_Marshal((BYTE *)(source->t.credential), buffer, size, (INT32)(source->t.size)));

    return result;
}


// Table 195 -- TPMA_NV Bits <I/O>
TPM_RC
TPMA_NV_Unmarshal(TPMA_NV *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = UINT32_Unmarshal((UINT32 *)target, buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    if(*((UINT32 *)target) & 0x1f00380)
        return TPM_RC_RESERVED_BITS;
    return TPM_RC_SUCCESS;
}

UINT16
TPMA_NV_Marshal(TPMA_NV *source, BYTE **buffer, INT32 *size)
{
    return UINT32_Marshal((UINT32 *)source, buffer, size);
}


// Table 196 -- TPMS_NV_PUBLIC Structure <I/O>
TPM_RC
TPMS_NV_PUBLIC_Unmarshal(TPMS_NV_PUBLIC *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPMI_RH_NV_INDEX_Unmarshal((TPMI_RH_NV_INDEX *)&(target->nvIndex), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPMI_ALG_HASH_Unmarshal((TPMI_ALG_HASH *)&(target->nameAlg), buffer, size, FALSE);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPMA_NV_Unmarshal((TPMA_NV *)&(target->attributes), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPM2B_DIGEST_Unmarshal((TPM2B_DIGEST *)&(target->authPolicy), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = UINT16_Unmarshal((UINT16 *)&(target->dataSize), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
//    if( (target->dataSize> MAX_NV_INDEX_SIZE))
//        return TPM_RC_SIZE;

    return TPM_RC_SUCCESS;
}

UINT16
TPMS_NV_PUBLIC_Marshal(TPMS_NV_PUBLIC *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPMI_RH_NV_INDEX_Marshal((TPMI_RH_NV_INDEX *)&(source->nvIndex), buffer, size));
    result = (UINT16)(result + TPMI_ALG_HASH_Marshal((TPMI_ALG_HASH *)&(source->nameAlg), buffer, size));
    result = (UINT16)(result + TPMA_NV_Marshal((TPMA_NV *)&(source->attributes), buffer, size));
    result = (UINT16)(result + TPM2B_DIGEST_Marshal((TPM2B_DIGEST *)&(source->authPolicy), buffer, size));
    result = (UINT16)(result + UINT16_Marshal((UINT16 *)&(source->dataSize), buffer, size));

    return result;
}


// Table 197 -- TPM2B_NV_PUBLIC Structure <I/O>
TPM_RC
TPM2B_NV_PUBLIC_Unmarshal(TPM2B_NV_PUBLIC *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    INT32    startSize;
    result = UINT16_Unmarshal((UINT16 *)&(target->t.size), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    startSize = *size;
    result = TPMS_NV_PUBLIC_Unmarshal((TPMS_NV_PUBLIC *)&(target->t.nvPublic), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    if(target->t.size != (startSize - *size)) return TPM_RC_SIZE;

    return TPM_RC_SUCCESS;
}

UINT16
TPM2B_NV_PUBLIC_Marshal(TPM2B_NV_PUBLIC *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    BYTE      *sizeField = NULL;

    // Advance buffer pointer by cononical size of a UINT16
    if(buffer != NULL)
    {
        sizeField = *buffer;
        *buffer += 2;
    }
    // Marshal the structure
    result = (UINT16)(result + TPMS_NV_PUBLIC_Marshal((TPMS_NV_PUBLIC *)&(source->t.nvPublic), buffer, size));
    // Marshal the size
    result = (UINT16)(result + UINT16_Marshal(&result, sizeField ? &sizeField : NULL, size));
    return result;
}

// Table 198 -- TPM2B_CONTEXT_SENSITIVE Structure <I/O>
TPM_RC
TPM2B_CONTEXT_SENSITIVE_Unmarshal(TPM2B_CONTEXT_SENSITIVE *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = UINT16_Unmarshal((UINT16 *)&(target->t.size), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    // if size equal to 0, the rest of the structure is a zero buffer.  Stop processing
    if(target->t.size == 0) return TPM_RC_SUCCESS;
    if((target->t.size) > MAX_CONTEXT_SIZE)
        return TPM_RC_SIZE;
    result = BYTE_Array_Unmarshal((BYTE *)(target->t.buffer), buffer, size, (INT32)(target->t.size));
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPM2B_CONTEXT_SENSITIVE_Marshal(TPM2B_CONTEXT_SENSITIVE *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + UINT16_Marshal((UINT16 *)&(source->t.size), buffer, size));
    // if size equal to 0, the rest of the structure is a zero buffer.  Stop processing
    if(source->t.size == 0) return result;
    result = (UINT16)(result + BYTE_Array_Marshal((BYTE *)(source->t.buffer), buffer, size, (INT32)(source->t.size)));

    return result;
}


// Table 199 -- TPMS_CONTEXT_DATA Structure <I/O,S>
TPM_RC
TPMS_CONTEXT_DATA_Unmarshal(TPMS_CONTEXT_DATA *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPM2B_DIGEST_Unmarshal((TPM2B_DIGEST *)&(target->integrity), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPM2B_CONTEXT_SENSITIVE_Unmarshal((TPM2B_CONTEXT_SENSITIVE *)&(target->encrypted), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPMS_CONTEXT_DATA_Marshal(TPMS_CONTEXT_DATA *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPM2B_DIGEST_Marshal((TPM2B_DIGEST *)&(source->integrity), buffer, size));
    result = (UINT16)(result + TPM2B_CONTEXT_SENSITIVE_Marshal((TPM2B_CONTEXT_SENSITIVE *)&(source->encrypted), buffer, size));

    return result;
}


// Table 200 -- TPM2B_CONTEXT_DATA Structure <I/O>
TPM_RC
TPM2B_CONTEXT_DATA_Unmarshal(TPM2B_CONTEXT_DATA *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = UINT16_Unmarshal((UINT16 *)&(target->t.size), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    // if size equal to 0, the rest of the structure is a zero buffer.  Stop processing
    if(target->t.size == 0) return TPM_RC_SUCCESS;
    if((target->t.size) > sizeof(TPMS_CONTEXT_DATA))
        return TPM_RC_SIZE;
    result = BYTE_Array_Unmarshal((BYTE *)(target->t.buffer), buffer, size, (INT32)(target->t.size));
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPM2B_CONTEXT_DATA_Marshal(TPM2B_CONTEXT_DATA *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + UINT16_Marshal((UINT16 *)&(source->t.size), buffer, size));
    // if size equal to 0, the rest of the structure is a zero buffer.  Stop processing
    if(source->t.size == 0) return result;
    result = (UINT16)(result + BYTE_Array_Marshal((BYTE *)(source->t.buffer), buffer, size, (INT32)(source->t.size)));

    return result;
}


// Table 201 -- TPMS_CONTEXT Structure <I/O>
TPM_RC
TPMS_CONTEXT_Unmarshal(TPMS_CONTEXT *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = UINT64_Unmarshal((UINT64 *)&(target->sequence), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPMI_DH_CONTEXT_Unmarshal((TPMI_DH_CONTEXT *)&(target->savedHandle), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPMI_RH_HIERARCHY_Unmarshal((TPMI_RH_HIERARCHY *)&(target->hierarchy), buffer, size, TRUE);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPM2B_CONTEXT_DATA_Unmarshal((TPM2B_CONTEXT_DATA *)&(target->contextBlob), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPMS_CONTEXT_Marshal(TPMS_CONTEXT *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + UINT64_Marshal((UINT64 *)&(source->sequence), buffer, size));
    result = (UINT16)(result + TPMI_DH_CONTEXT_Marshal((TPMI_DH_CONTEXT *)&(source->savedHandle), buffer, size));
    result = (UINT16)(result + TPMI_RH_HIERARCHY_Marshal((TPMI_RH_HIERARCHY *)&(source->hierarchy), buffer, size));
    result = (UINT16)(result + TPM2B_CONTEXT_DATA_Marshal((TPM2B_CONTEXT_DATA *)&(source->contextBlob), buffer, size));

    return result;
}


// Table 203 -- TPMS_CREATION_DATA Structure <O,S>
TPM_RC
TPMS_CREATION_DATA_Unmarshal(TPMS_CREATION_DATA *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    result = TPML_PCR_SELECTION_Unmarshal(&(target->pcrSelect), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPM2B_DIGEST_Unmarshal(&(target->pcrDigest), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPMA_LOCALITY_Unmarshal(&(target->locality), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPM_ALG_ID_Unmarshal(&(target->parentNameAlg), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPM2B_NAME_Unmarshal(&(target->parentName), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPM2B_NAME_Unmarshal(&(target->parentQualifiedName), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    result = TPM2B_DATA_Unmarshal(&(target->outsideInfo), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;

    return TPM_RC_SUCCESS;
}

UINT16
TPMS_CREATION_DATA_Marshal(TPMS_CREATION_DATA *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    result = (UINT16)(result + TPML_PCR_SELECTION_Marshal((TPML_PCR_SELECTION *)&(source->pcrSelect), buffer, size));
    result = (UINT16)(result + TPM2B_DIGEST_Marshal((TPM2B_DIGEST *)&(source->pcrDigest), buffer, size));
    result = (UINT16)(result + TPMA_LOCALITY_Marshal((TPMA_LOCALITY *)&(source->locality), buffer, size));
    result = (UINT16)(result + TPM_ALG_ID_Marshal((TPM_ALG_ID *)&(source->parentNameAlg), buffer, size));
    result = (UINT16)(result + TPM2B_NAME_Marshal((TPM2B_NAME *)&(source->parentName), buffer, size));
    result = (UINT16)(result + TPM2B_NAME_Marshal((TPM2B_NAME *)&(source->parentQualifiedName), buffer, size));
    result = (UINT16)(result + TPM2B_DATA_Marshal((TPM2B_DATA *)&(source->outsideInfo), buffer, size));

    return result;
}


// Table 204 -- TPM2B_CREATION_DATA Structure <O,S>
TPM_RC
TPM2B_CREATION_DATA_Unmarshal(TPM2B_CREATION_DATA *target, BYTE **buffer, INT32 *size)
{
    TPM_RC    result;
    INT32    startSize;
    result = UINT16_Unmarshal((UINT16 *)&(target->t.size), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    // if size equal to 0, the rest of the structure is a zero buffer.  Stop processing
    if(target->t.size == 0) return TPM_RC_SUCCESS;
    startSize = *size;
    result = TPMS_CREATION_DATA_Unmarshal((TPMS_CREATION_DATA *)&(target->t.creationData), buffer, size);
    if(result != TPM_RC_SUCCESS)
        return result;
    if(target->t.size != (startSize - *size)) return TPM_RC_SIZE;

    return TPM_RC_SUCCESS;
}

UINT16
TPM2B_CREATION_DATA_Marshal(TPM2B_CREATION_DATA *source, BYTE **buffer, INT32 *size)
{
    UINT16    result = 0;
    BYTE      *sizeField = NULL;
    // Advance buffer pointer by cononical size of a UINT16
    if(buffer != NULL)
    {
        sizeField = *buffer;
        *buffer += 2;
    }
    // Marshal the structure
    result = (UINT16)(result + TPMS_CREATION_DATA_Marshal((TPMS_CREATION_DATA *)&(source->t.creationData), buffer, size));
    // Marshal the size
    result = (UINT16)(result + UINT16_Marshal(&result, sizeField ? &sizeField : NULL, size)); 
    return result;
}
// Array Marshal for TPMS_TAGGED_PROPERTY
UINT16
TPMS_TAGGED_PROPERTY_Array_Marshal(TPMS_TAGGED_PROPERTY *source, BYTE **buffer, INT32 *size, INT32 count)
{
    UINT16    result = 0;
    INT32 i;
    for(i = 0; i < count; i++) {
        result = (UINT16)(result + TPMS_TAGGED_PROPERTY_Marshal(&source[i], buffer, size));
    }
    return result;
}

TPM_RC
TPMS_TAGGED_PROPERTY_Array_Unmarshal(TPMS_TAGGED_PROPERTY *target, BYTE **buffer, INT32 *size, INT32 count)
{
    TPM_RC    result;
    INT32 i;
    for(i = 0; i < count; i++)
    {
        result = TPMS_TAGGED_PROPERTY_Unmarshal(&target[i], buffer, size);
        if(result != TPM_RC_SUCCESS)
            return result;
    }
    return TPM_RC_SUCCESS;
}
// Array Marshal for TPMS_ALG_PROPERTY
UINT16
TPMS_ALG_PROPERTY_Array_Marshal(TPMS_ALG_PROPERTY *source, BYTE **buffer, INT32 *size, INT32 count)
{
    UINT16    result = 0;
    INT32 i;
    for(i = 0; i < count; i++) {
        result = (UINT16)(result + TPMS_ALG_PROPERTY_Marshal(&source[i], buffer, size));
    }
    return result;
}

TPM_RC
TPMS_ALG_PROPERTY_Array_Unmarshal(TPMS_ALG_PROPERTY *target, BYTE **buffer, INT32 *size, INT32 count)
{
    TPM_RC    result;
    INT32 i;
    for(i = 0; i < count; i++)
    {
        result = TPMS_ALG_PROPERTY_Unmarshal(&target[i], buffer, size);
        if(result != TPM_RC_SUCCESS)
            return result;
    }
    return TPM_RC_SUCCESS;
}

// Array Unmarshal/Unmarshal for TPMS_PCR_SELECTION
TPM_RC
TPMS_PCR_SELECTION_Array_Unmarshal(TPMS_PCR_SELECTION *target, BYTE **buffer, INT32 *size, INT32 count)
{
    TPM_RC    result;
    INT32 i;
    for(i = 0; i < count; i++) {
        result = TPMS_PCR_SELECTION_Unmarshal(&target[i], buffer, size);
        if(result != TPM_RC_SUCCESS) 
            return result;
    }
    return TPM_RC_SUCCESS;
}

UINT16
TPMS_PCR_SELECTION_Array_Marshal(TPMS_PCR_SELECTION *source, BYTE **buffer, INT32 *size, INT32 count)
{
    UINT16    result = 0;
    INT32 i;
    for(i = 0; i < count; i++) {
        result = (UINT16)(result + TPMS_PCR_SELECTION_Marshal(&source[i], buffer, size));
    }
    return result;
}

// Array Unmarshal/Unmarshal for TPMT_HA
TPM_RC
TPMT_HA_Array_Unmarshal(TPMT_HA *target, BYTE **buffer, INT32 *size, BOOL flag, INT32 count)
{
    TPM_RC    result;
    INT32 i;
    for(i = 0; i < count; i++) {
        result = TPMT_HA_Unmarshal(&target[i], buffer, size, flag);
        if(result != TPM_RC_SUCCESS) 
            return result;
    }
    return TPM_RC_SUCCESS;
}

UINT16
TPMT_HA_Array_Marshal(TPMT_HA *source, BYTE **buffer, INT32 *size, INT32 count)
{
    UINT16    result = 0;
    INT32 i;
    for(i = 0; i < count; i++) {
        result = (UINT16)(result + TPMT_HA_Marshal(&source[i], buffer, size));
    }
    return result;
}

// Array Unmarshal for BYTE
TPM_RC
BYTE_Array_Unmarshal(BYTE *target, BYTE **buffer, INT32 *size, INT32 count)
{
    TPM_RC    result;
    INT32 i;
    for(i = 0; i < count; i++) {
        result = BYTE_Unmarshal(&target[i], buffer, size);
        if(result != TPM_RC_SUCCESS) 
            return result;
    }
    return TPM_RC_SUCCESS;
}

// Array Marshal for BYTE
UINT16
BYTE_Array_Marshal(BYTE *source, BYTE **buffer, INT32 *size, INT32 count)
{
    UINT16    result = 0;
    INT32 i;
    for(i = 0; i < count; i++) {
        result = (UINT16)(result + BYTE_Marshal(&source[i], buffer, size));
    }
    return result;
}

// Array Unmarshal/Unmarshal for TPM_HANDLE
TPM_RC
TPM_HANDLE_Array_Unmarshal(TPM_HANDLE *target, BYTE **buffer, INT32 *size, INT32 count)
{
    TPM_RC    result;
    INT32 i;
    for(i = 0; i < count; i++) {
        result = TPM_HANDLE_Unmarshal(&target[i], buffer, size);
        if(result != TPM_RC_SUCCESS) 
            return result;
    }
    return TPM_RC_SUCCESS;
}

UINT16
TPM_HANDLE_Array_Marshal(TPM_HANDLE *source, BYTE **buffer, INT32 *size, INT32 count)
{
    UINT16    result = 0;
    INT32 i;
    for(i = 0; i < count; i++) {
        result = (UINT16)(result + TPM_HANDLE_Marshal(&source[i], buffer, size));
    }
    return result;
}

// Array Marshal for TPMA_CC
UINT16
TPMA_CC_Array_Marshal(TPMA_CC *source, BYTE **buffer, INT32 *size, INT32 count)
{
    UINT16    result = 0;
    INT32 i;
    for(i = 0; i < count; i++) {
        result = (UINT16)(result + TPMA_CC_Marshal(&source[i], buffer, size));
    }
    return result;
}

TPM_RC
TPMA_CC_Array_Unmarshal(TPMA_CC *target, BYTE **buffer, INT32 *size, INT32 count)
{
    TPM_RC    result;
    INT32 i;
    for(i = 0; i < count; i++)
    {
        result = TPMA_CC_Unmarshal(&target[i], buffer, size);
        if(result != TPM_RC_SUCCESS)
            return result;
    }
    return TPM_RC_SUCCESS;
}

// Array Marshal for TPMS_TAGGED_PCR_SELECT
UINT16
TPMS_TAGGED_PCR_SELECT_Array_Marshal(TPMS_TAGGED_PCR_SELECT *source, BYTE **buffer, INT32 *size, INT32 count)
{
    UINT16    result = 0;
    INT32 i;
    for(i = 0; i < count; i++) {
        result = (UINT16)(result + TPMS_TAGGED_PCR_SELECT_Marshal(&source[i], buffer, size));
    }
    return result;
}

TPM_RC
TPMS_TAGGED_PCR_SELECT_Array_Unmarshal(TPMS_TAGGED_PCR_SELECT *target, BYTE **buffer, INT32 *size, INT32 count)
{
    TPM_RC    result = 0;
    INT32 i;
    for(i = 0; i < count; i++)
    {
        result = TPMS_TAGGED_PCR_SELECT_Unmarshal(&target[i], buffer, size);
        if(result != TPM_RC_SUCCESS)
            return result;
    }
    return TPM_RC_SUCCESS;
}


#ifdef TPM_ALG_ECC
// Array Unmarshal/Unmarshal for TPM_ECC_CURVE
TPM_RC
TPM_ECC_CURVE_Array_Unmarshal(TPM_ECC_CURVE *target, BYTE **buffer, INT32 *size, INT32 count)
{
    TPM_RC    result = 0;
    INT32 i;
    for(i = 0; i < count; i++) {
        result = TPM_ECC_CURVE_Unmarshal(&target[i], buffer, size);
        if(result != TPM_RC_SUCCESS) 
            return result;
    }
    return TPM_RC_SUCCESS;
}

UINT16
TPM_ECC_CURVE_Array_Marshal(TPM_ECC_CURVE *source, BYTE **buffer, INT32 *size, INT32 count)
{
    UINT16    result = 0;
    INT32 i;
    for(i = 0; i < count; i++) {
        result = (UINT16)(result + TPM_ECC_CURVE_Marshal(&source[i], buffer, size));
    }
    return result;
}

#endif
// Array Unmarshal/Unmarshal for TPM2B_DIGEST
TPM_RC
TPM2B_DIGEST_Array_Unmarshal(TPM2B_DIGEST *target, BYTE **buffer, INT32 *size, INT32 count)
{
    TPM_RC    result;
    INT32 i;
    for(i = 0; i < count; i++) {
        result = TPM2B_DIGEST_Unmarshal(&target[i], buffer, size);
        if(result != TPM_RC_SUCCESS) 
            return result;
    }
    return TPM_RC_SUCCESS;
}

UINT16
TPM2B_DIGEST_Array_Marshal(TPM2B_DIGEST *source, BYTE **buffer, INT32 *size, INT32 count)
{
    UINT16    result = 0;
    INT32 i;
    for(i = 0; i < count; i++) {
        result = (UINT16)(result + TPM2B_DIGEST_Marshal(&source[i], buffer, size));
    }
    return result;
}

// Array Unmarshal/Unmarshal for TPM_CC
TPM_RC
TPM_CC_Array_Unmarshal(TPM_CC *target, BYTE **buffer, INT32 *size, INT32 count)
{
    TPM_RC    result;
    INT32 i;
    for(i = 0; i < count; i++) {
        result = TPM_CC_Unmarshal(&target[i], buffer, size);
        if(result != TPM_RC_SUCCESS) 
            return result;
    }
    return TPM_RC_SUCCESS;
}

UINT16
TPM_CC_Array_Marshal(TPM_CC *source, BYTE **buffer, INT32 *size, INT32 count)
{
    UINT16    result = 0;
    INT32 i;
    for(i = 0; i < count; i++) {
        result = (UINT16)(result + TPM_CC_Marshal(&source[i], buffer, size));
    }
    return result;
}

// Array Unmarshal/Unmarshal for TPM_ALG_ID
TPM_RC
TPM_ALG_ID_Array_Unmarshal(TPM_ALG_ID *target, BYTE **buffer, INT32 *size, INT32 count)
{
    TPM_RC    result;
    INT32 i;
    for(i = 0; i < count; i++) {
        result = TPM_ALG_ID_Unmarshal(&target[i], buffer, size);
        if(result != TPM_RC_SUCCESS) 
            return result;
    }
    return TPM_RC_SUCCESS;
}

UINT16
TPM_ALG_ID_Array_Marshal(TPM_ALG_ID *source, BYTE **buffer, INT32 *size, INT32 count)
{
    UINT16    result = 0;
    INT32 i;
    for(i = 0; i < count; i++) {
        result = (UINT16)(result + TPM_ALG_ID_Marshal(&source[i], buffer, size));
    }
    return result;
}

