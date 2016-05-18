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

//** Description
// This file contains a set of miscellaneous memory manipulation routines. Many
// of the functions have the same semantics as functions defined in string.h.
// Those functions are not used in the TPM in order to avoid namespace
// contamination.

//** Includes and Data Definitions
#include    "stdafx.h"
#define MEMORY_LIB_C

// These buffers are set aside to hold command and response values. In this
// implementation, it is not guaranteed that the code will stop accessing
// the s_actionInputBuffer before starting to put values in the
// s_actionOutputBuffer so different buffers are required. However, the
// s_actionInputBuffer and s_responseBuffer are not needed at the same time
// and they could be the same buffer.
//


//** Functions

//*** MemoryMove()
// This function moves data from one place in memory to another. No
// safety checks of any type are performed. If source and data buffer overlap,
// then the move is done as if an intermediate buffer were used.
// Note: This funciton is used by MemoryCopy, MemoryCopy2B, and MemoryConcat2b and
// requires that the caller know the maximum size of the destination buffer
// so that there is no possibility of buffer overrun.
void
MemoryMove(
    void            *destination,   // OUT: move destination
    const void      *source,        // IN: move source
    UINT32           size,          // IN: number of octets to moved
    UINT32           dSize          // IN: size of the receive buffer
)
{
    const BYTE *p = (BYTE *)source;
    BYTE *q = (BYTE *)destination;

    pAssert(size <= dSize);
    // if the destination buffer has a lower address than the
    // source, then moving bytes in ascending order is safe.
    dSize -= size;

    if (p>q || (p+size <= q))
    {
        while(size--)
            *q++ = *p++;
    }
    // If the destination buffer has a higher address than the
    // source, then move bytes from the end to the beginning.
    else if (p < q)
    {
        p += size;
        q += size;
        while (size--)
            *--q = *--p;
    }
   
    // If the source and destination address are the same, nothing to move.
    return;
}



//*** MemoryCopy()
// This function moves data from one place in memory to another. No
// safety checks of any type are performed. If the destination and source
// overlap, then the results are unpredictable.
//void
//MemoryCopy(
//    void            *destination,           // OUT: copy destination
//    void            *source,                // IN: copy source
//    UINT32           size,                  // IN: number of octets being copied
//    UINT32           dSize                  // IN: size of the receive buffer
//)
//{
//    MemoryMove(destination, source, size, dSize);
//}

//%#define MemoryCopy(a, b, c, d) MemoryMove((a), (b), (c), (d))


//*** MemoryEqual()
// This function indicates if two buffers have the same values in the indicated
// number of bytes.
// return type: BOOL
//      TRUE    all octets are the same
//      FALSE   all octets are not the same
BOOL
MemoryEqual(
    const void      *buffer1,           // IN: compare buffer1
    const void      *buffer2,           // IN: compare buffer2
    UINT32           size               // IN: size of bytes being compared
)
{
    BOOL         equal = TRUE;
    const BYTE  *b1, *b2;

    b1 = (BYTE *)buffer1;
    b2 = (BYTE *)buffer2;

    // Compare all bytes so that there is no leakage of information
    // due to timing differences.
    for(; size > 0; size--)
        equal = (*b1++ == *b2++) && equal;

    return equal;
}

//*** MemoryCopy2B()
// This function copies a TPM2B. This can be used when the TPM2B types are
// the same or different. No size checking is done on the destination so
// the caller should make sure that the destination is large enough.
//
// This function returns the number of octets in the data buffer of the TPM2B.
INT16
MemoryCopy2B(
    TPM2B         *dest,      // OUT: receiving TPM2B
    const TPM2B   *source,    // IN: source TPM2B
    UINT16         dSize      // IN: size of the receiving buffer
)
{
    dest->size = source->size;
    MemoryMove(dest->buffer, source->buffer, dest->size, dSize);
    return dest->size;
}



//*** MemoryConcat2B()
// This function will concatenate the buffer contents of a TPM2B to an
// the buffer contents of another TPM2B and adjust the size accordingly
//      ('a' := ('a' | 'b')).
void
MemoryConcat2B(
    TPM2B   *aInOut,    // IN/OUT: destination 2B
    TPM2B   *bIn,       // IN: second 2B
    UINT16   aSize      // IN: The size of aInOut.buffer 
                        //     (max values for aInOut.size)
)
{
    MemoryMove(&aInOut->buffer[aInOut->size], 
               bIn->buffer, 
               bIn->size, 
               aSize - aInOut->size);
    aInOut->size = aInOut->size + bIn->size;
    return;
}

//*** Memory2BEqual()
// This function will compare two TPM2B structures. To be equal, they
// need to be the same size and the buffer contexts need to be the same
// in all octets.
// return type: BOOL
//      TRUE    size and buffer contents are the same
//      FALSE   size or buffer contents are not the same
BOOL
Memory2BEqual(
    const TPM2B       *aIn,     // IN: compare value
    const TPM2B       *bIn      // IN: compare value
)
{
    if(aIn->size != bIn->size)
        return FALSE;

    return MemoryEqual(aIn->buffer, bIn->buffer, aIn->size);
}

//*** MemorySet()
// This function will set all the octets in the specified memory range to
// the specified octet value.
// Note: the "dSize" parameter forces the caller to know how big the receiving
// buffer is to make sure that there is no possiblity that the caller will
// inadvertentl run over the end of the buffer.
// return type: void
void
MemorySet(
    void            *destination,       // OUT: memory destination
    char             value,             // IN: fill value
    UINT32           size              // IN: number of octets to fill
)
{
    char *p = (char *)destination;
    while (size--)
        *p++ = value;
    return;
}

//*** MemoryRemoveTrailingZeros()
// This function is used to adjust the length of an authorization value.
// It adjusts the size of the TPM2B so that it does not include octets
// at the end of the buffer that contain zero.
// The function returns the number of non-zero octets in the buffer.
UINT16
MemoryRemoveTrailingZeros (
    TPM2B_AUTH      *auth        // IN/OUT: value to adjust
)
{
    BYTE        *a = &auth->t.buffer[auth->t.size-1];
    for(; auth->t.size > 0; auth->t.size--)
    {
        if(*a--)
            break;
    }
    return auth->t.size;
}
