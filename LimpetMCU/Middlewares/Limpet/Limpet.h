/*
 * Limpet.h
 *
 *  Created on: Apr 5, 2016
 *      Author: stefanth
 */

#ifndef LIMPET_H_
#define LIMPET_H_

#ifdef __cplusplus
extern "C" {
#endif

uint32_t LimpetCreateSrk(
    void
    );

uint32_t LimpetReadDeviceId(
    uint32_t LogicalDeviceNumber,
    uint8_t* DeviceId,
    uint32_t DeviceIdMax,
    uint32_t* DeviceIdLen
    );

uint32_t LimpetStoreURI(
    uint32_t LogicalDeviceNumber,
    uint8_t* UriData,
    uint32_t UriLen
    );

uint32_t LimpetReadURI(
    uint32_t LogicalDeviceNumber,
    uint8_t* UriData,
    uint32_t UriMax,
    uint32_t* UriLen
    );

uint32_t LimpetDestroyURI(
    uint32_t LogicalDeviceNumber
    );

uint32_t LimpetCreateHmacKey(
    uint32_t LogicalDeviceNumber,
    uint8_t* HmacKeyIn,
    uint32_t HmackeyInLen
    );

uint32_t LimpetSignWithHmacKey(
    uint32_t LogicalDeviceNumber,
    uint8_t* DataPtr,
    uint32_t DataSize,
    uint8_t* Hmac,
    uint32_t HmacMax,
    uint32_t* HmacLen
    );

uint32_t LimpetEvictHmacKey(
    uint32_t LogicalDeviceNumber
    );
#ifdef __cplusplus
}
#endif
#endif /* LIMPET_H_ */
