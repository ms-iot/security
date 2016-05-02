#ifndef __TPMUTIL_H
#define __TPMUTIL_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

uint32_t
TpmUtilClearAndProvision(
    void
    );

void
TpmUtilStorePersistedData(
    void
    );

void
TpmUtilLoadPersistedData(
    void
    );

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
