#include <stdlib.h>
#include <string.h>
#include "stm32f4xx_hal.h"
#include "TisTpmDrv.h"

#ifndef TISI2C
#ifndef TISSPI
#ifndef NTZI2C
#error No TPM Driver implementation selected!
#endif
#endif
#endif

static HAL_StatusTypeDef
TpmSubmitCmd(
    const uint8_t* cmd,
    uint32_t cmdLen,
    uint32_t timeout
);

static HAL_StatusTypeDef
TpmReceiveRsp(
    uint8_t* rsp,
    uint32_t rspMax,
    uint32_t* rspSize,
    uint32_t timeout
);

int32_t cycleDelay = -1;
static void
SpinWait(
    uint32_t microSeconds
)
{
    int32_t useCycleDelay = (cycleDelay >= 0) ? cycleDelay : 1000;
    uint32_t cycles = (microSeconds * 1000 / useCycleDelay);
    for(uint32_t n = 0; n < cycles; n++)
    {
        __asm__("nop;");
    }
}

int32_t
TpmAdjustSpinWait(
    int32_t preset
)
{
    if(preset < 0)
    {
        int32_t delta = HAL_GetTick();
        SpinWait(1000000);
        cycleDelay = HAL_GetTick() - delta;
    }
    else
    {
        cycleDelay = preset;
    }
    return cycleDelay;
}

static inline uint16_t
GetUInt16(
    uint8_t* dataIn,
    uint32_t offset
)
{
    return (((uint16_t)dataIn[offset]) << 8) | ((uint16_t)dataIn[offset + 1]);
}

static inline void
PutUInt16(
    uint16_t dataIn,
    uint8_t* dataOut,
    uint32_t offset
)
{
    dataOut[offset] = (uint8_t)((dataIn & 0xff00) >> 8);
    dataOut[offset + 1] = (uint8_t)(dataIn & 0x00ff);
}

static inline uint32_t
GetUInt32(
    uint8_t* dataIn,
    uint32_t offset
)
{
    return (((uint32_t)dataIn[offset]) << 24) | (((uint32_t)dataIn[offset + 1]) << 16) | (((uint32_t)dataIn[offset + 2]) << 8) | ((uint16_t)dataIn[offset + 3]);
}

static inline void
PutUInt32(
    uint32_t dataIn,
    uint8_t* dataOut,
    uint32_t offset
)
{
    dataOut[offset] = (uint8_t)((dataIn & 0xff000000) >> 24);
    dataOut[offset + 1] = (uint8_t)((dataIn & 0x00ff0000) >> 16);
    dataOut[offset + 2] = (uint8_t)((dataIn & 0x0000ff00) >> 8);
    dataOut[offset + 3] = (uint8_t)((dataIn & 0x000000ff));
}

HAL_StatusTypeDef
TpmSubmit(
    const uint8_t* cmd,
    uint32_t cmdLen,
    uint8_t* rsp,
    uint32_t rspMax,
    uint32_t* rspSize,
    uint32_t timeout
)
{
    HAL_StatusTypeDef result = HAL_OK;
    uint32_t deadline = HAL_GetTick() + timeout;
    uint32_t attempt = 0;
    *rspSize = 0;

    // 250ms max to submit the command
    HAL_GPIO_WritePin(GPIOB, LD2_Pin, GPIO_PIN_SET);
    if((result = TpmSubmitCmd(cmd, cmdLen, 500)) != HAL_OK)
    {
        goto Cleanup;
    }
    HAL_GPIO_WritePin(GPIOB, LD2_Pin, GPIO_PIN_RESET);

    do
    {
        // Cascaded wait so we don't bug the TPM too much while it is working
        if(attempt < 10)
        {
            // Wait 1m for the first 10ms
            HAL_Delay(1);
        }
        else if(attempt < 100)
        {
            // Wait 10ms for the next 90ms
            HAL_Delay(10);
        }
        else if(attempt < 1000)
        {
            // Wait 100ms for the next 900ms
            HAL_Delay(100);
        }
        else
        {
            // Wait 1s until we time out or the TPM is done
            HAL_Delay(1000);
        }
        attempt++;

        // 250ms max to receive the response
        HAL_GPIO_WritePin(GPIOB, LD2_Pin, GPIO_PIN_SET);
        if((result = TpmReceiveRsp(rsp, rspMax, rspSize, 500)) != HAL_OK)
        {
            goto Cleanup;
        }
        HAL_GPIO_WritePin(GPIOB, LD2_Pin, GPIO_PIN_RESET);
        if(*rspSize != 0)
        {
            break;
        }

        // Check that we have not timed out yet
        if(deadline < HAL_GetTick())
        {
            result = HAL_TIMEOUT;
            goto Cleanup;
        }
    }
    while(*rspSize == 0);
Cleanup:
    HAL_GPIO_WritePin(GPIOB, LD2_Pin, GPIO_PIN_RESET);
    return result;
}

uint32_t
TpmStartup(
    uint16_t startupType
)
{
    const uint8_t startup[] = {0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0xFF, 0xFF};
    uint8_t response[TPM_MINIMUM_RESPONSE] = {0};
    uint32_t responseLen = 0;
    uint32_t returnCode = 0;

    PutUInt16(startupType, startup, 10);

    if((TpmSubmit(startup,
                 sizeof(startup),
                 response,
                 sizeof(response),
                 &responseLen,
                 500) != HAL_OK) ||
       (responseLen < 10))
    {
        returnCode = TPM_RC_FAILURE;
        goto Cleanup;
    }
   returnCode =  GetUInt32(response, 6);

Cleanup:
   return returnCode;
}

uint32_t
TpmShutdown(
    uint16_t shutdownType
)
{
    const uint8_t shutdown[] = {0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x45, 0xFF, 0xFF};
    uint8_t response[TPM_MINIMUM_RESPONSE] = {0};
    uint32_t responseLen = 0;
    uint32_t returnCode = 0;

    PutUInt16(shutdownType, shutdown, 10);

    if((TpmSubmit(shutdown,
                 sizeof(shutdown),
                 response,
                 sizeof(response),
                 &responseLen,
                 500) != HAL_OK) ||
      (responseLen < 10))
     {
         returnCode = TPM_RC_FAILURE;
         goto Cleanup;
     }
    returnCode =  GetUInt32(response, 6);

Cleanup:
    return returnCode;
}

uint32_t
TpmSelfTest(
    void
)
{
    const uint8_t selfTest[] = {0x80, 0x01, 0x00, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x01, 0x43, 0x01};
    uint8_t response[TPM_MINIMUM_RESPONSE] = {0};
    uint32_t responseLen = 0;
    uint32_t returnCode = 0;

    if((TpmSubmit(selfTest,
                 sizeof(selfTest),
                 response,
                 sizeof(response),
                 &responseLen,
                 10000) != HAL_OK) ||
      (responseLen < 10))
    {
        printf("reponselen: %u", responseLen);
        returnCode = TPM_RC_FAILURE;
        goto Cleanup;
    }
    returnCode =  GetUInt32(response, 6);

Cleanup:
    return returnCode;
}

uint32_t
TpmGetRandom(
    uint8_t* random,
    uint32_t randomSize
)
{
    uint8_t getRandom[] = {0x80, 0x01, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x01, 0x7B,
                           0xFF, 0xFF}; // randomSize
    uint8_t* response = NULL;
    uint32_t responseSize = TPM_MINIMUM_RESPONSE + sizeof(uint16_t) + randomSize;
    uint32_t responseLen = 0;
    uint32_t returnCode = 0;

    // Complete command
    PutUInt16(randomSize, getRandom, 10);

    if(((response = (uint8_t*)malloc(responseSize)) == NULL) ||
       (TpmSubmit(getRandom,
                  sizeof(getRandom),
                  response,
                  responseSize,
                  &responseLen,
                  500) != HAL_OK) ||
       (responseLen < 10))
    {
        returnCode = TPM_RC_FAILURE;
        goto Cleanup;
    }

    if((returnCode = GetUInt32(response, 6)) == TPM_RC_SUCCESS)
    {
        if(responseSize != responseLen)
        {
            returnCode = TPM_RC_FAILURE;
            goto Cleanup;
        }
        memcpy(random, &response[12], MIN(randomSize, GetUInt16(response, 10)));
    }

Cleanup:
    if(response != NULL)
    {
        free(response);
        response = NULL;
    }
    return returnCode;
}

uint32_t
TpmClearControl(
    uint8_t disable
)
{
    // Please Note: This code is hard coded to use TPM_RH_PLATFORM
    uint8_t clearControl[] = {0x80, 0x02, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x01, 0x27,
                              0x40, 0x00, 0x00, 0x0C, // TPM_RH_PLATFORM
                              0x00, 0x00, 0x00, 0x09, // session size
                              0x40, 0x00, 0x00, 0x09, // PW session
                              0x00, 0x00,
                              0x01,
                              0x00, 0x00,
                              0xFF};
    uint8_t response[TPM_MINIMUM_AUTH_RESPONSE] = {0};
    uint32_t responseLen = 0;
    uint32_t returnCode = 0;

    clearControl[sizeof(clearControl) - sizeof(uint8_t)] = (disable == 0) ? 0x00 : 0x01;

    if((TpmSubmit(clearControl,
                 sizeof(clearControl),
                 response,
                 sizeof(response),
                 &responseLen,
                 500) != HAL_OK) ||
            (responseLen < 10))
    {
        returnCode = TPM_RC_FAILURE;
        goto Cleanup;
    }

    returnCode = GetUInt32(response, 6);

Cleanup:
    return returnCode;
}

uint32_t
TpmClear(
    void
)
{
    // Please Note: This code is hard coded to use TPM_RH_PLATFORM
    uint8_t clear[] = {0x80, 0x02, 0x00, 0x00, 0x00, 0x1b, 0x00, 0x00, 0x01, 0x26,
                       0x40, 0x00, 0x00, 0x0C, // TPM_RH_PLATFORM
                       0x00, 0x00, 0x00, 0x09, // session size
                       0x40, 0x00, 0x00, 0x09, // PW session
                       0x00, 0x00,
                       0x01,
                       0x00, 0x00};

    uint8_t response[TPM_MINIMUM_AUTH_RESPONSE] = {0};
    uint32_t responseLen = 0;
    uint32_t returnCode = 0;

    if((TpmSubmit(clear,
                 sizeof(clear),
                 response,
                 sizeof(response),
                 &responseLen,
                 2000) != HAL_OK) ||
            (responseLen < 10))
    {
        returnCode = TPM_RC_FAILURE;
        goto Cleanup;
    }

    returnCode = GetUInt32(response, 6);

Cleanup:
    return returnCode;
}

uint32_t
TpmHashSequenceStart(
    uint32_t* handle,
    uint16_t hashAlg
)
{
    uint8_t hashSequenceStart[] = {0x80, 0x01, 0x00, 0x00, 0x00, 0x0E, 0x00, 0x00, 0x01, 0x86, 0x00, 0x00, 0xFF, 0xFF};
    uint8_t response[TPM_MINIMUM_RESPONSE + sizeof(uint32_t)] = {0};
    uint32_t responseLen = 0;
    uint32_t returnCode = 0;

    PutUInt16(hashAlg, hashSequenceStart, 12);

    if((TpmSubmit(hashSequenceStart,
                 sizeof(hashSequenceStart),
                 response,
                 sizeof(response),
                 &responseLen,
                 500) != HAL_OK) ||
            (responseLen < 10))
     {
         returnCode = TPM_RC_FAILURE;
         goto Cleanup;
     }

    if((returnCode = GetUInt32(response, 6)) == TPM_RC_SUCCESS)
    {
        *handle = GetUInt32(response, 10);
    }

Cleanup:
    return returnCode;
}

uint32_t
TpmHashSequenceUpdate(
    uint32_t handle,
    uint8_t* dataPtr,
    uint32_t dataSize
)
{
    uint8_t hashSequenceUpdate[] = {0x80, 0x02, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x01, 0x5C,
                                    0xFF, 0xFF, 0xFF, 0xFF, // hash handle to be filled in
                                    0x00, 0x00, 0x00, 0x09,
                                    0x40, 0x00, 0x00, 0x09, // PW session: nullAuth
                                    0x00, 0x00,
                                    0x01,
                                    0x00, 0x00,
                                    0xFF, 0xFF}; // Trailed by up to 1024 bytes of data to hash
    uint8_t* command = NULL;
    uint32_t commandSize = sizeof(hashSequenceUpdate) + dataSize;
    uint8_t response[TPM_MINIMUM_AUTH_RESPONSE] = {0};
    uint32_t responseLen = 0;
    uint32_t returnCode = TPM_RC_SUCCESS;

    if((dataPtr != NULL) && (dataSize > 1024))
    {
        returnCode = TPM_RC_FAILURE;
        goto Cleanup;
    }

    if((command = (uint8_t*)malloc(commandSize)) == NULL)
    {
        returnCode = TPM_RC_FAILURE;
        goto Cleanup;
    }

    memcpy(command, hashSequenceUpdate, sizeof(hashSequenceUpdate));
    PutUInt32(sizeof(hashSequenceUpdate) + dataSize, command, 2);
    PutUInt32(handle, command, 10);
    PutUInt16(dataSize, command, (sizeof(hashSequenceUpdate) - sizeof(uint16_t)));
    memcpy(&command[sizeof(hashSequenceUpdate)], dataPtr, dataSize);

    if((TpmSubmit(command,
                  commandSize,
                  response,
                  sizeof(response),
                  &responseLen,
                  500) != HAL_OK) ||
       (responseLen < 10))
    {
        returnCode = TPM_RC_FAILURE;
        goto Cleanup;
    }

    returnCode = GetUInt32(response, 6);

Cleanup:
    if(command != NULL)
    {
        free(command);
        command = NULL;
    }
    return returnCode;
}

uint32_t
TpmHashSequenceComplete(
    uint32_t handle,
    uint8_t* dataPtr,
    uint32_t dataSize,
    uint8_t* digest,
    uint32_t digestMax,
    uint32_t* digestSize
)
{
    uint8_t hashSequenceComplete1[] = {0x80, 0x02, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x01, 0x3E,
                                       0xFF, 0xFF, 0xFF, 0xFF, // hash handle to be filled in
                                       0x00, 0x00, 0x00, 0x09,
                                       0x40, 0x00, 0x00, 0x09, // PW session: nullAuth
                                       0x00, 0x00,
                                       0x01,
                                       0x00, 0x00,
                                       0xFF, 0xFF}; // Trailed by up to 1024 bytes of data to hash
    uint8_t hashSequenceComplete2[] = {0x40, 0x00, 0x00, 0x07}; // TPM_RH_NULL
    uint8_t* command = NULL;
    uint32_t commandSize = sizeof(hashSequenceComplete1) + dataSize + sizeof(hashSequenceComplete2);
    uint8_t response[256] = {0};
    uint32_t responseLen = 0;
    uint32_t returnCode = 0;

    if(dataSize > 1024)
    {
        return TPM_RC_FAILURE;
    }

    if((command = (uint8_t*)malloc(commandSize)) == NULL)
    {
        return TPM_RC_FAILURE;
    }

    memcpy(command, hashSequenceComplete1, sizeof(hashSequenceComplete1));
    PutUInt32(commandSize, command, 2);
    PutUInt32(handle, command, 10);
    PutUInt16(dataSize, command, 27);
    memcpy(&command[sizeof(hashSequenceComplete1)], dataPtr, dataSize);
    memcpy(&command[sizeof(hashSequenceComplete1) + dataSize], hashSequenceComplete2, sizeof(hashSequenceComplete2));

    if((TpmSubmit(command,
                  commandSize,
                  response,
                  sizeof(response),
                  &responseLen,
                  500) != HAL_OK) ||
            (responseLen < 10))
    {
        returnCode = TPM_RC_FAILURE;
        goto Cleanup;
    }

    // Parse the TPM response
    if((returnCode = GetUInt32(response, 6)) == TPM_RC_SUCCESS)
    {
        if((*digestSize = MIN(GetUInt16(response, 14), digestMax)) > 0)
            memcpy(digest, &response[16], *digestSize);
    }
Cleanup:
    if(command != NULL)
    {
        free(command);
        command = NULL;
    }
    return returnCode;
}

uint32_t
TpmEventSequenceComplete(
    uint32_t handle,
    uint32_t pcrIndex,
    uint8_t* dataPtr,
    uint32_t dataSize,
    uint8_t* measurement,
    uint32_t measurementMax,
    uint32_t* measurementSize
)
{
    uint8_t eventSequenceComplete[] = {0x80, 0x02, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x01, 0x85,
                                       0xFF, 0xFF, 0xFF, 0xFF, // pcr handle to be filled in
                                       0xFF, 0xFF, 0xFF, 0xFF, // hash handle to be filled in
                                       0x00, 0x00, 0x00, 0x12,
                                       0x40, 0x00, 0x00, 0x09, // PCR PW session: nullAuth
                                       0x00, 0x00,
                                       0x01,
                                       0x00, 0x00,
                                       0x40, 0x00, 0x00, 0x09,  // Hash PW session: nullAuth
                                       0x00, 0x00,
                                       0x01,
                                       0x00, 0x00,
                                       0xFF, 0xFF}; // Trailed by up tp 1024 bytes of data to hash
    uint8_t* command = NULL;
    uint32_t commandSize = sizeof(eventSequenceComplete) + dataSize;
    uint8_t response[0x100] = {0};
    uint32_t responseLen = 0;
    uint32_t returnCode = 0;

    if(dataSize > 1024)
    {
        return TPM_RC_FAILURE;
    }

    if((command = (uint8_t*)malloc(commandSize)) == NULL)
    {
        return TPM_RC_FAILURE;
    }

    memcpy(command, eventSequenceComplete, sizeof(eventSequenceComplete));
    PutUInt32(commandSize, command, 2);
    PutUInt32(pcrIndex, command, 10);
    PutUInt32(handle, command, 14);
    PutUInt16(dataSize, command, 40);
    memcpy(&command[sizeof(eventSequenceComplete)], dataPtr, dataSize);

    if((TpmSubmit(command,
                  commandSize,
                  response,
                  sizeof(response),
                  &responseLen,
                  500) != HAL_OK) ||
            (responseLen < 10))
    {
        returnCode = TPM_RC_FAILURE;
        goto Cleanup;
    }

    // Parse the TPM response
    if((returnCode = GetUInt32(response, 6)) == TPM_RC_SUCCESS)
    {
        if((*measurementSize = MIN(GetUInt32(response, 10), measurementMax)) > 0)
            memcpy(measurement, &response[14], *measurementSize);
    }

 Cleanup:
    if(command != NULL)
    {
        free(command);
        command = NULL;
    }
    return returnCode;
}

#ifdef TISI2C
// TCG TIS I2C TPM 2.0 link layer driver implementation
uint8_t RW_GuardTime = 0xff;
uint8_t WR_GuardTime = 0xff;
uint8_t WW_GuardTime = 0xff;
uint8_t RR_GuardTime = 0xff;
char LastOperation = ' ';

static HAL_StatusTypeDef
ReadRegisterI2C(
    uint8_t reg,
    uint8_t* pbBuffer,
    uint16_t cbBuffer
)
{
    HAL_StatusTypeDef result = HAL_OK;

    // Wait out the guard time of the previous command
    if((LastOperation == 'w') && (WW_GuardTime != 0))
    {
    	SpinWait(WW_GuardTime);
    }
    if((LastOperation == 'r') && (WR_GuardTime != 0))
    {
    	SpinWait(WR_GuardTime);
    }

    LastOperation = 'w';
    for(uint8_t n = 0; n < 10; n++)
    {
        if((result = HAL_I2C_Master_Transmit(&TPMI2CBUSHANDLE,
                                             (TCGTIS_I2C_ADDRESS << 1),
                                             &reg,
                                             sizeof(reg),
                                             10)) == HAL_OK)
        {
            break;
        }
    }
    if(result != HAL_OK)
    {
        goto Cleanup;
    }

    SpinWait(RW_GuardTime);
    LastOperation = 'r';
    for(uint8_t n = 0; n < 10; n++)
    {
        if((result = HAL_I2C_Master_Receive(&TPMI2CBUSHANDLE,
                                            (TCGTIS_I2C_ADDRESS << 1),
                                             pbBuffer,
                                             cbBuffer,
                                             10)) == HAL_OK)
        {
            break;
        }
    }

Cleanup:
    return result;
}

static HAL_StatusTypeDef
WriteRegisterI2C(
    uint8_t reg,
    uint8_t* pbBuffer,
    uint16_t cbBuffer
)
{
    HAL_StatusTypeDef result = HAL_OK;
    uint8_t xmtBuf[0x100] = {0};

    if(cbBuffer >= sizeof(xmtBuf))
    {
        return HAL_ERROR;
    }

    xmtBuf[0] = reg;
    memcpy(&xmtBuf[1], pbBuffer, cbBuffer);

    // Wait out the guard time of the previous command
    if((LastOperation == 'w') && (WW_GuardTime != 0))
    {
    	SpinWait(WW_GuardTime);
    }
    if((LastOperation == 'r') && (WR_GuardTime != 0))
    {
    	SpinWait(WR_GuardTime);
    }

    LastOperation = 'w';
    for(uint8_t n = 0; n < 10; n++)
    {
        if((result = HAL_I2C_Master_Transmit(&TPMI2CBUSHANDLE,
                                     (TCGTIS_I2C_ADDRESS << 1),
                                     xmtBuf,
                                     sizeof(reg) + cbBuffer,
                                     10)) == HAL_OK)
        {
            break;
        }
    }

    return result;
}

HAL_StatusTypeDef
DetectTpm(
    void
)
{
    HAL_StatusTypeDef result = HAL_ERROR;

    if(RequestLocality(TIS_LOCALITY_0) == HAL_OK)
    {
        uint32_t regData = 0;
        if((ReadRegisterI2C(TCGTIS_I2C_TPM_I2C_INTERFACE_CAPABILITY, (uint8_t*)&regData, sizeof(regData)) == HAL_OK) &&
           ((regData & 0x000001F0) == TCGTIS_I2C_TPM_I2C_INTERFACE_CAPABILITY_TPM20))
        {
            uint32_t tpmResult = TPM_RC_SUCCESS;
            // Found something that responds like a TCG SPI TIS TPM 2.0
            uint8_t GuardTime = ((regData & 0x0001FE00) >> 9);
            RR_GuardTime = (regData & 0x00100000) ? GuardTime : 0;
            WR_GuardTime = (regData & 0x00080000) ? GuardTime : 0;
            RW_GuardTime = (regData & 0x00040000) ? GuardTime : 0;
            WW_GuardTime = (regData & 0x00020000) ? GuardTime : 0;
            do
            {
                tpmResult = TpmStartup(TPM_SU_CLEAR);
                if(tpmResult == TPM_RC_FAILURE)
                {
                    HAL_Delay(100);
                }
            }
            while (tpmResult == TPM_RC_FAILURE);
            if((tpmResult != TPM_RC_SUCCESS) && (tpmResult != TPM_RC_INITIALIZE))
            {
                goto Cleanup;
            }
            do
            {
                tpmResult = TpmSelfTest();
                if(tpmResult == TPM_RC_FAILURE)
                {
                    HAL_Delay(100);
                }
            }
            while (tpmResult == TPM_RC_FAILURE);
            if((tpmResult != TPM_RC_SUCCESS) && (tpmResult != TPM_RC_INITIALIZE))
            {
                goto Cleanup;
            }
        }
        ReleaseLocality();
    }

    result = HAL_OK;

Cleanup:
    return result;
}

HAL_StatusTypeDef
RequestLocality(
    TIS_LOCALITY locality
)
{
    HAL_StatusTypeDef result = HAL_OK;
    uint8_t dataByte = 0;
    uint32_t deadline = HAL_GetTick() + 10; // Timeout max 10ms

    // Switch to the requested locality
    if((result = WriteRegisterI2C(TCGTIS_I2C_TPM_LOC_SEL, (uint8_t*)&locality, sizeof(uint8_t))) != HAL_OK)
    {
       goto Cleanup;
    }

    do
    {
        // Read a valid access register. Turns out, it may take a couple of times if the TPM was sleeping
        do
        {
            dataByte = 0;
            if((result = ReadRegisterI2C(TCGTIS_I2C_TPM_ACCESS, &dataByte, sizeof(dataByte))) != HAL_OK)
            {
                goto Cleanup;
            }

            // Check for timeout
            if(deadline < HAL_GetTick())
            {
                result = HAL_TIMEOUT;
                goto Cleanup;
            }
            
            // First time we hit that, the TPM has to wake up give it some time
            if(!(dataByte & TIS_ACCESS_VALID))
            {
                HAL_Delay(100);
            }
        }
        while(!(dataByte & TIS_ACCESS_VALID));
 
        // If we have the locality we are done
        if(dataByte & TIS_ACCESS_ACTIVE_LOCALITY)
        {
            break;
        }
 
        // Request the locality
        dataByte = TIS_ACCESS_REQUEST_USE;
        if((result = WriteRegisterI2C(TCGTIS_I2C_TPM_ACCESS, &dataByte, sizeof(dataByte))) != HAL_OK)
        {
            goto Cleanup;
        }

        // Check for timeout
        if(deadline < HAL_GetTick())
        {
            result = HAL_TIMEOUT;
            goto Cleanup;
        }
    }
    while(!(dataByte & TIS_ACCESS_ACTIVE_LOCALITY));
 
Cleanup:
    return result;
}

HAL_StatusTypeDef
ReleaseLocality(
    void
)
{
    HAL_StatusTypeDef result = HAL_OK;
    uint8_t dataByte = 0;
    uint32_t deadline = HAL_GetTick() + 100; // Timeout max 100ms

    do
    {
        // Read a valid access register. Turns out, it may take a couple of times if the TPM was sleeping
        do
        {
            if((result = ReadRegisterI2C(TCGTIS_I2C_TPM_ACCESS, &dataByte, sizeof(dataByte))) != HAL_OK)
            {
                goto Cleanup;
            }

            // Check for timeout
            if(deadline < HAL_GetTick())
            {
                result = HAL_TIMEOUT;
                goto Cleanup;
            }
            
            // First time we hit that, the TPM has to wake up give it some time
            if(!(dataByte & TIS_ACCESS_VALID))
            {
                HAL_Delay(100);
            }
        }
        while(!(dataByte & TIS_ACCESS_VALID));
 
        // If we don't have the locality we are done
        if(!(dataByte & TIS_ACCESS_ACTIVE_LOCALITY))
        {
            break;
        }
 
        // Drop the locality
        dataByte = TIS_ACCESS_ACTIVE_LOCALITY;
        if((result = WriteRegisterI2C(TCGTIS_I2C_TPM_ACCESS, &dataByte, sizeof(dataByte))) != HAL_OK)
        {
            goto Cleanup;
        }

        // Check for timeout
        if(deadline < HAL_GetTick())
        {
            result = HAL_TIMEOUT;
            goto Cleanup;
        }
    }
    while(dataByte & TIS_ACCESS_ACTIVE_LOCALITY);

Cleanup:
    return result;
}

static HAL_StatusTypeDef
TpmSubmitCmd(
    const uint8_t* cmd,
    uint32_t cmdLen,
    uint32_t timeout
)
{
    HAL_StatusTypeDef result = HAL_OK;
    uint8_t tisStatus = 0;
    uint16_t burstCount = 0;
    uint32_t deadline = HAL_GetTick() + timeout;
    uint32_t index = 0;

    // Make sure the TPM is ready for a command
    do
    {
        tisStatus = TIS_STS_COMMAND_READY;

        // Check that we have not timed out yet
        if(deadline < HAL_GetTick())
        {
            result = HAL_TIMEOUT;
            goto Cleanup;
        }

        if(((result = WriteRegisterI2C(TCGTIS_I2C_TPM_STS, &tisStatus, sizeof(tisStatus))) != HAL_OK) ||
           ((result = ReadRegisterI2C(TCGTIS_I2C_TPM_STS, &tisStatus, sizeof(tisStatus))) != HAL_OK))
        {
            goto Cleanup;
        }
    }
    while((tisStatus & TIS_STS_COMMAND_READY) == 0);

    do
    {
        uint16_t iteration = 0;

        // Check that we have not timed out yet
        if(deadline < HAL_GetTick())
        {
            result = HAL_TIMEOUT;
            goto Cleanup;
        }

        // Read the burst count from the TPM
        if((result = ReadRegisterI2C(TCGTIS_I2C_TPM_STS_BURSTCOUNT, (uint8_t*)&burstCount, sizeof(burstCount))) != HAL_OK)
        {
            goto Cleanup;
        }

        if(burstCount > 0)
        {
            // send data burst to the TPM
            iteration = MIN((cmdLen - index), MIN(burstCount, TCGTIS_MAX_HW_FRAME_SIZE));
            if((result = WriteRegisterI2C(TCGTIS_I2C_TPM_DATA_FIFO, (uint8_t*)&cmd[index], iteration)) != HAL_OK)
            {
                goto Cleanup;
            }


            // Update the index
            index += iteration;
        }
    } while(index < cmdLen);

    // Was command completely received by the TPM?
    if((result = ReadRegisterI2C(TCGTIS_I2C_TPM_STS, &tisStatus, sizeof(tisStatus))) != HAL_OK)
    {
        goto Cleanup;
    }
    if(!(tisStatus & TIS_STS_VALID) || (tisStatus & TIS_STS_DATA_EXPECT))
    {
        result = HAL_ERROR;
        goto Cleanup;
    }

    // Kick the command off command execution
    tisStatus = TIS_STS_GO;
    if((result = WriteRegisterI2C(TCGTIS_I2C_TPM_STS, &tisStatus, sizeof(tisStatus))) != HAL_OK)
    {
        goto Cleanup;
    }

Cleanup:
    if(result != HAL_OK)
    {
        // Send an abort to the TPM no matter what state it is in now, to make sure that it is
        // operational for the next command by the time we come back to it.
        tisStatus = TIS_STS_COMMAND_READY;
        WriteRegisterI2C(TCGTIS_I2C_TPM_STS, &tisStatus, sizeof(tisStatus));
    }
    return result;
}

static HAL_StatusTypeDef
TpmReceiveRsp(
    uint8_t* rsp,
    uint32_t rspMax,
    uint32_t* rspSize,
    uint32_t timeout
)
{
    HAL_StatusTypeDef result = HAL_OK;
    uint8_t tisStatus = 0;
    uint16_t burstCount = 0;
    uint32_t rspLen = (sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint32_t));
    uint32_t deadline = HAL_GetTick() + timeout;
    uint32_t index = 0;

    *rspSize = 0;

    // Check if data is available
    if((result = ReadRegisterI2C(TCGTIS_I2C_TPM_STS, &tisStatus, sizeof(tisStatus))) != HAL_OK)
    {
        goto Cleanup;
    }
    if(!(tisStatus & TIS_STS_VALID))
    {
        result = HAL_ERROR;
        goto Cleanup;
    }
    if(!(tisStatus & TIS_STS_DATA_AVAIL))
    {
        goto Cleanup;
    }

    // Get the response header from the TPM
    index = 0;
    if((result = ReadRegisterI2C(TCGTIS_I2C_TPM_STS_BURSTCOUNT, (uint8_t*)&burstCount, sizeof(burstCount))) != HAL_OK)
    {
        goto Cleanup;
    }
    if((burstCount == 0) ||
       (burstCount < (sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint32_t))) ||
       (ReadRegisterI2C(TCGTIS_I2C_TPM_DATA_FIFO, &rsp[index], (sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint32_t))) != HAL_OK))
    {
        goto Cleanup;
    }
    index += (sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint32_t));
    rspLen = MIN(GetUInt32(rsp, sizeof(uint16_t)), rspMax);

    while(rspLen > index)
    {
        // Check that we have not timed out yet
        if(deadline < HAL_GetTick())
        {
            result = HAL_TIMEOUT;
            goto Cleanup;
        }

        // Read the burst count from the TPM
        if((result = ReadRegisterI2C(TCGTIS_I2C_TPM_STS_BURSTCOUNT, (uint8_t*)&burstCount, sizeof(burstCount))) != HAL_OK)
        {
            goto Cleanup;
        }

        // Calculate the response iteration size
        uint16_t iteration = MIN((rspLen - index), burstCount);

        // Read the data for this iteration
        if((result = ReadRegisterI2C(TCGTIS_I2C_TPM_DATA_FIFO, &rsp[index], iteration)) != HAL_OK)
        {
            goto Cleanup;
        }
        index += iteration;

        // After we got the complete header adjust the response size
        if(index == (sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint32_t)))
        {
            rspLen = MIN(GetUInt32(rsp, sizeof(uint16_t)), rspMax);
        }
    }
    *rspSize = rspLen;

Cleanup:
    if(result != HAL_OK)
    {
        // Send an abort to the TPM no matter what state it is in now, to make sure that it is
        // operational for the next command by the time we come back to it.
        tisStatus = TIS_STS_COMMAND_READY;
        WriteRegisterI2C(TCGTIS_I2C_TPM_STS, &tisStatus, sizeof(tisStatus));
    }
    return result;
}

#endif

#ifdef TISSPI
// TCG TIS SPI TPM 2.0 link layer driver implementation
static HAL_StatusTypeDef
TcgSpiFullDuplex(
    uint8_t readCycle,
    uint16_t reg,
    uint8_t* dataBuffer,
    uint16_t dataBufferSize
)
{
    HAL_StatusTypeDef result = HAL_OK;
    uint32_t tisHdr = TIS_HEADER(USELOCALITY, readCycle, reg, dataBufferSize);
    uint8_t hdrBuffer[4] = {0};
    uint32_t deadline = HAL_GetTick() + 250; // Timeout max 250ms

    // Lock the bus for this operation
    HAL_GPIO_WritePin(TPMSPIBUSCSPORT, TPMSPIBUSCSPIN, GPIO_PIN_RESET);
    
    // Send the TIS header
    PutUInt32(tisHdr, hdrBuffer, 0);
    if((result = HAL_SPI_TransmitReceive(&TPMSPIBUSHANDLE, hdrBuffer, hdrBuffer, sizeof(hdrBuffer), 10)) != HAL_OK)
    {
        goto Cleanup;
    }
 
    // The last bit we read full duplex is the first wait state indicator
    while(!(hdrBuffer[3] & 0x01))
    {
        // Give the TPM some time to get ready
        HAL_Delay(1);

        // Check for timeout
        if(deadline < HAL_GetTick())
        {
            result = HAL_TIMEOUT;
            goto Cleanup;
        }

        // Read the next byte to see is we still have to wait
        hdrBuffer[3] = 0;
        if((result = HAL_SPI_TransmitReceive(&TPMSPIBUSHANDLE, &hdrBuffer[3], &hdrBuffer[3], sizeof(uint8_t), 10)) != HAL_OK)
        {
            goto Cleanup;
        }
    }
 
    // Full duplex the payload
    if((result = HAL_SPI_TransmitReceive(&TPMSPIBUSHANDLE, dataBuffer, dataBuffer, dataBufferSize, 10)) != HAL_OK)
    {
        goto Cleanup;
    }

Cleanup:
    // Make sure to release the bus before we leave
    HAL_GPIO_WritePin(TPMSPIBUSCSPORT, TPMSPIBUSCSPIN, GPIO_PIN_SET);
    return result;
}

static HAL_StatusTypeDef
ReadRegisterSPI(
    uint16_t reg,
    uint8_t* pbBuffer,
    uint16_t cbBuffer
)
{
    return TcgSpiFullDuplex(0x01, reg, pbBuffer, cbBuffer);
}

static HAL_StatusTypeDef
WriteRegisterSPI(
    uint16_t reg,
    uint8_t* pbBuffer,
    uint16_t cbBuffer
)
{
    return TcgSpiFullDuplex(0x00, reg, pbBuffer, cbBuffer);
}

HAL_StatusTypeDef
DetectTpm(
    void
)
{
    HAL_StatusTypeDef result = HAL_ERROR;

    // Make sure CS is peoperly initialized
    HAL_GPIO_WritePin(TPMSPIBUSCSPORT, TPMSPIBUSCSPIN, GPIO_PIN_SET);

    if(RequestLocality(TIS_LOCALITY_0) == HAL_OK)
    {
        uint32_t regData = 0;
        if((ReadRegisterSPI(TCGTIS_SPI_STS_REGISTER, (uint8_t*)&regData, sizeof(regData)) == HAL_OK) &&
           ((regData & 0x0C000000) == TIS_STS_TPMFAMILY_20))
        {
            uint32_t tpmResult = TPM_RC_SUCCESS;
            // Found something that responds like a TCG SPI TIS TPM 2.0
            tpmResult = TpmStartup();
            if((tpmResult == TPM_RC_SUCCESS) || (tpmResult == TPM_RC_FAILURE))
            {
                result = HAL_OK;
            }
        }
        ReleaseLocality();
    }

    return result;
}

HAL_StatusTypeDef
RequestLocality(
    TIS_LOCALITY locality
)
{
    HAL_StatusTypeDef result = HAL_OK;
    uint8_t dataByteIn = 0;
    uint8_t dataByteOut = 0;
    uint32_t deadline = HAL_GetTick() + 10; // Timeout max 10ms

    do
    {
        // Read a valid access register. Turns out, it may take a couple of times if the TPM was sleeping
        do
        {
            dataByteIn = 0;
            if((result = ReadRegisterSPI(TCGTIS_SPI_ACCESS_REGISTER, &dataByteIn, sizeof(dataByteIn))) != HAL_OK)
            {
                goto Cleanup;
            }

            // Check for timeout
            if(deadline < HAL_GetTick())
            {
                result = HAL_TIMEOUT;
                goto Cleanup;
            }
            
            // First time we hit that, the TPM has to wake up give it some time
            if(!(dataByteIn & TIS_ACCESS_VALID))
            {
                HAL_Delay(100);
            }
        }
        while(!(dataByteIn & TIS_ACCESS_VALID));
 
        // If we have the locality we are done
        if(dataByteIn & TIS_ACCESS_ACTIVE_LOCALITY)
        {
            break;
        }
 
        // Request the locality
        dataByteOut = TIS_ACCESS_REQUEST_USE;
        if((result = WriteRegisterSPI(TCGTIS_SPI_ACCESS_REGISTER, &dataByteOut, sizeof(dataByteOut))) != HAL_OK)
        {
            goto Cleanup;
        }

        // Check for timeout
        if(deadline < HAL_GetTick())
        {
            result = HAL_TIMEOUT;
            goto Cleanup;
        }
    }
    while(!(dataByteIn & TIS_ACCESS_ACTIVE_LOCALITY));
 
Cleanup:
    return result;
}

HAL_StatusTypeDef
ReleaseLocality(
    void
)
{
    HAL_StatusTypeDef result = HAL_OK;
    uint8_t dataByteIn = 0;
    uint8_t dataByteOut = 0;
    uint32_t deadline = HAL_GetTick() + 100; // Timeout max 100ms

    do
    {
        // Read a valid access register. Turns out, it may take a couple of times if the TPM was sleeping
        do
        {
            if((result = ReadRegisterSPI(TCGTIS_SPI_ACCESS_REGISTER, &dataByteIn, sizeof(dataByteIn))) != HAL_OK)
            {
                goto Cleanup;
            }

            // Check for timeout
            if(deadline < HAL_GetTick())
            {
                result = HAL_TIMEOUT;
                goto Cleanup;
            }
            
            // First time we hit that, the TPM has to wake up give it some time
            if(!(dataByteIn & TIS_ACCESS_VALID))
            {
                HAL_Delay(100);
            }
        }
        while(!(dataByteIn & TIS_ACCESS_VALID));
 
        // If we don't have the locality we are done
        if(!(dataByteIn & TIS_ACCESS_ACTIVE_LOCALITY))
        {
            break;
        }
 
        // Drop the locality
        dataByteOut = TIS_ACCESS_ACTIVE_LOCALITY;
        if((result = WriteRegisterSPI(TCGTIS_SPI_ACCESS_REGISTER, &dataByteOut, sizeof(dataByteOut))) != HAL_OK)
        {
            goto Cleanup;
        }

        // Check for timeout
        if(deadline < HAL_GetTick())
        {
            result = HAL_TIMEOUT;
            goto Cleanup;
        }
    }
    while(dataByteIn & TIS_ACCESS_ACTIVE_LOCALITY);

Cleanup:
    return result;
}

static HAL_StatusTypeDef
TpmSubmitCmd(
    const uint8_t* cmd,
    uint32_t cmdLen,
    uint32_t timeout
)
{
    HAL_StatusTypeDef result = HAL_OK;
    uint8_t tisStatus = 0;
    uint16_t burstCount = 0;
    uint32_t deadline = HAL_GetTick() + timeout;
    uint32_t index = 0;
    
    // Make sure the TPM is ready for a command
    do
    {
        tisStatus = TIS_STS_COMMAND_READY;

        // Check that we have not timed out yet
        if(deadline < HAL_GetTick())
        {
            result = HAL_TIMEOUT;
            goto Cleanup;
        }

        if(((result = WriteRegisterSPI(TCGTIS_SPI_STS_REGISTER, &tisStatus, sizeof(tisStatus))) != HAL_OK) ||
           ((result = ReadRegisterSPI(TCGTIS_SPI_STS_REGISTER, &tisStatus, sizeof(tisStatus))) != HAL_OK))
        {
            goto Cleanup;
        }
    }
    while((tisStatus & TIS_STS_COMMAND_READY) == 0);

    do
    {
        uint16_t iteration = 0;

        // Check that we have not timed out yet
        if(deadline < HAL_GetTick())
        {
            result = HAL_TIMEOUT;
            goto Cleanup;
        }

        // Read the burst count from the TPM
        if((result = ReadRegisterSPI(TCGTIS_SPI_STS_BURSTCOUNT_REGISTER, (uint8_t*)&burstCount, sizeof(burstCount))) != HAL_OK)
        {
            goto Cleanup;
        }

        // send data burst to the TPM
        iteration = MIN((cmdLen - index), MIN(burstCount, TCGTIS_MAX_HW_FRAME_SIZE));
        if((result = WriteRegisterSPI(TCGTIS_SPI_DATA_FIFO, (uint8_t*)&cmd[index], iteration)) != HAL_OK)
        {
            goto Cleanup;
        }
 
        // Update the index
        index += iteration;
    } while(index < cmdLen);


    // Was command completely received by the TPM?
    if((result = ReadRegisterSPI(TCGTIS_SPI_STS_REGISTER, &tisStatus, sizeof(tisStatus))) != HAL_OK)
    {
        goto Cleanup;
    }
    if(!(tisStatus & TIS_STS_VALID) || (tisStatus & TIS_STS_DATA_EXPECT))
    {
        result = HAL_ERROR;
        goto Cleanup;
    }

    // Kick the command off command execution
    tisStatus = TIS_STS_GO;
    if((result = WriteRegisterSPI(TCGTIS_SPI_STS_REGISTER, &tisStatus, sizeof(tisStatus))) != HAL_OK)
    {
        goto Cleanup;
    }

Cleanup:
    if(result != HAL_OK)
    {
        // Send an abort to the TPM no matter what state it is in now, to make sure that it is
        // operational for the next command by the time we come back to it.
        tisStatus = TIS_STS_COMMAND_READY;
        WriteRegisterSPI(TCGTIS_SPI_STS_REGISTER, &tisStatus, sizeof(tisStatus));
    }
    return result;
}

static HAL_StatusTypeDef
TpmReceiveRsp(
    uint8_t* rsp,
    uint32_t rspMax,
    uint32_t* rspSize,
    uint32_t timeout
)
{
    HAL_StatusTypeDef result = HAL_OK;
    uint8_t tisStatus = 0;
    uint16_t burstCount = 0;
    uint32_t rspLen = sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint32_t);
    uint32_t deadline = HAL_GetTick() + timeout;
    uint32_t index = 0;

    *rspSize = 0;

    // Is response data available
    if((result = ReadRegisterSPI(TCGTIS_SPI_STS_REGISTER, &tisStatus, sizeof(tisStatus))) != HAL_OK)
    {
        result = result;
        goto Cleanup;
    }
    if(!(tisStatus & TIS_STS_VALID))
    {
        result = HAL_ERROR;
        goto Cleanup;
    }
    if(!(tisStatus & TIS_STS_DATA_AVAIL))
    {
        goto Cleanup;
    }

    // Get the response from the TPM
    while(rspLen > index)
    {
        uint16_t iteration = 0;

        // Check that we have not timed out yet
        if(deadline < HAL_GetTick())
        {
            result = HAL_TIMEOUT;
            goto Cleanup;
        }

        // Read the burst count from the TPM
        if((result = ReadRegisterSPI(TCGTIS_SPI_STS_BURSTCOUNT_REGISTER, (uint8_t*)&burstCount, sizeof(burstCount))) != HAL_OK)
        {
            goto Cleanup;
        }

        // Calculate the response iteration size
        iteration = MIN((rspLen - index), burstCount);

        // Read the data for this iteration
        if((result = ReadRegisterSPI(TCGTIS_SPI_DATA_FIFO, &rsp[index], iteration)) != HAL_OK)
        {
            goto Cleanup;
        }
        index += iteration;

        // After we got the complete header adjust the response size
        if(index == (sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint32_t)))
        {
            rspLen = MIN(GetUInt32(rsp, sizeof(uint16_t)), rspMax);
        }
    }
    *rspSize = rspLen;

Cleanup:
    if(result != HAL_OK)
    {
        // Send an abort to the TPM no matter what state it is in now, to make sure that it is
        // operational for the next command by the time we come back to it.
        tisStatus = TIS_STS_COMMAND_READY;
        WriteRegisterSPI(TCGTIS_SPI_STS_REGISTER, &tisStatus, sizeof(tisStatus));
    }
    return result;
}

#endif

#ifdef NTZI2C

HAL_StatusTypeDef
DetectTpm(
    void
)
{
    uint32_t tpmResult = TpmStartup(TPM_SU_CLEAR);
    return ((tpmResult == TPM_RC_SUCCESS) || (tpmResult == TPM_RC_INITIALIZE)) ? HAL_OK : HAL_ERROR;
}

HAL_StatusTypeDef
RequestLocality(
    TIS_LOCALITY locality
)
{
    return (locality == TIS_LOCALITY_0) ? HAL_OK : HAL_ERROR;
}

HAL_StatusTypeDef
ReleaseLocality(
    void
)
{
    return HAL_OK;
}

static HAL_StatusTypeDef
TpmSubmitCmd(
    const uint8_t* cmd,
    uint32_t cmdLen,
    uint32_t timeout
)
{
    HAL_StatusTypeDef result = HAL_OK;
    uint32_t deadline = HAL_GetTick() + timeout;

    while(HAL_I2C_Master_Transmit(&TPMI2CBUSHANDLE,
                                  (NTZI2C_I2C_ADDRESS << 1),
                                  (uint8_t*)cmd,
                                  cmdLen,
                                  10) != HAL_OK)
    {
        if(deadline < HAL_GetTick())
        {
            result = HAL_TIMEOUT;
            goto Cleanup;
        }
        // Wait for the TPM to come out of sleep and then retry
        HAL_Delay(10);
    }

Cleanup:
    return result;
}

static HAL_StatusTypeDef
TpmReceiveRsp(
    uint8_t* rsp,
    uint32_t rspMax,
    uint32_t* rspSize,
    uint32_t timeout
)
{
    HAL_StatusTypeDef result = HAL_OK;
    uint32_t deadline = HAL_GetTick() + timeout;
    uint32_t rspSizeInternal = TPM_MINIMUM_RESPONSE;

    // Check that there is enough storage for at least the minimum size TPM response
    if((rsp == NULL) || (rspMax < rspSizeInternal))
    {
        result = HAL_ERROR;
        goto Cleanup;
    }

    // Is data available?
    if(HAL_I2C_Master_Receive(&TPMI2CBUSHANDLE,
                              (NTZI2C_I2C_ADDRESS << 1),
                              rsp,
                              rspSizeInternal,
                              10) != HAL_OK)
    {
        // No, return so we can wait
        goto Cleanup;
    }
    
    // Read the actual response length and get the rest of the response if there is any
    rspSizeInternal = MIN(GetUInt32(rsp, 2), rspMax);
    if(rspSizeInternal > TPM_MINIMUM_RESPONSE)
    {
        // Retrive the rest of the pending response from the TPM
        if(HAL_I2C_Master_Receive(&TPMI2CBUSHANDLE,
                                  (NTZI2C_I2C_ADDRESS << 1),
                                  &rsp[TPM_MINIMUM_RESPONSE],
                                  MIN((rspSizeInternal - TPM_MINIMUM_RESPONSE),
                                  (rspMax - TPM_MINIMUM_RESPONSE)),
                                  10) != HAL_OK)
        {
            // If this read fails than we have an error
            result = HAL_ERROR;
            goto Cleanup;
        }
    }
    
    *rspSize = rspSizeInternal;

Cleanup:
    return result;
}

#endif
