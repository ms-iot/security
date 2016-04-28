#ifndef __NTPCLIENT_H
#define __NTPCLIENT_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

HAL_StatusTypeDef NtpGetTime(
    const char* host,
    uint32_t timeout,
    time_t* ntpTime
    );

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif