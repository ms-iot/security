#ifndef __TISTPMDRV_H
#define __TISTPMDRV_H

#ifdef __cplusplus
 extern "C" {
#endif

#ifndef MIN
#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))
#endif

#define DETECT_CYCLE_DELAY (-1)

#ifdef TISSPI
//Interface definition
#ifndef TPMSPIBUSHANDLE
#error Define TPMSPIBUSHANDLE to SPI handle that the TPM is attached to
#endif
#ifndef TPMSPIBUSCSPORT
#error Define TPMSPIBUSCSPORT to GPIO_Port that the SPI_CS is connected to
#endif
#ifndef TPMSPIBUSCSPIN
#error Define TPMSPIBUSCSPIN to GPIO_Pin that the SPI_CS is connected to
#endif
extern SPI_HandleTypeDef TPMSPIBUSHANDLE;

// TCG TIS specific defines
#define TCGTIS_SPI_BASE_ADDRESS (0x00d40000)
#define TIS_HEADER(__LOCALITY, __READCYCLE, __REGISTER, __PAYLOAD)\
(TCGTIS_SPI_BASE_ADDRESS | \
 (__READCYCLE ? 0x80000000 : 0x00000000) | \
 ((__PAYLOAD - 1) << 24) | \
 (__LOCALITY << 12) | \
 (__REGISTER))

// SPI TIS registers addresses
#define TCGTIS_SPI_ACCESS_REGISTER (0x0000)
#define TCGTIS_SPI_STS_REGISTER (0x0018)
#define TCGTIS_SPI_STS_BURSTCOUNT_REGISTER (0x0019) // 16bit segment in TCGTIS_SPI_STS_REGISTER
#define TCGTIS_SPI_DATA_FIFO (0x0024)
#endif

#ifdef TISI2C
//Interface definition
#ifndef TPMI2CBUSHANDLE
#error Define TPMI2CBUSHANDLE to I2C handle that the TPM is attached to
#endif
extern I2C_HandleTypeDef TPMI2CBUSHANDLE;

// TCG TIS specific defines
#define TCGTIS_I2C_ADDRESS (0x2E) // TCG default address
//#define TCGTIS_I2C_ADDRESS (0x17) // 1st prototype of the STMicro part has the address calculation wrong

// I2C TIS register addresses
#define TCGTIS_I2C_TPM_LOC_SEL (0x00)
#define TCGTIS_I2C_TPM_ACCESS (0x04)
#define TCGTIS_I2C_TPM_STS (0x18)
#define TCGTIS_I2C_TPM_STS_COMMAND_READY (0x40)
#define TCGTIS_I2C_TPM_STS_GO (0x20)
#define TCGTIS_I2C_TPM_STS_DATA_AVAIL (0x10)
#define TCGTIS_I2C_TPM_STS_DATA_EXPECT (0x08)
#define TCGTIS_I2C_TPM_STS_BURSTCOUNT (0x19)
#define TCGTIS_I2C_TPM_DATA_FIFO (0x24)
#define TCGTIS_I2C_TPM_I2C_INTERFACE_CAPABILITY (0x30)
#define TCGTIS_I2C_TPM_I2C_INTERFACE_CAPABILITY_TPM20 (0x000000080)
#endif

#ifdef NTZI2C
#ifndef TPMI2CBUSHANDLE
#error Define TPMI2CBUSHANDLE to I2C handle that the TPM is attached to
#endif
extern I2C_HandleTypeDef TPMI2CBUSHANDLE;
#define NTZI2C_I2C_ADDRESS (0x58) // NTZ I2C address
#endif

// Generic TPM constants
#define TCGTIS_MAX_HW_FRAME_SIZE (64)
#define USELOCALITY (TIS_LOCALITY_0)
#ifndef TPM_RC_SUCCESS
#define TPM_RC_SUCCESS (0x00000000)
#endif
#ifndef TPM_RC_INITIALIZE
#define TPM_RC_INITIALIZE (0x00000100)
#endif
#ifndef TPM_RC_FAILURE
#define TPM_RC_FAILURE (0x00000101)
#endif
#ifndef TPM_SU_CLEAR
#define TPM_SU_CLEAR (0x0000)
#endif
#ifndef TPM_SU_STATE
#define TPM_SU_STATE (0x0001)
#endif
#define TPM_MINIMUM_RESPONSE (sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint32_t))
#define TPM_MINIMUM_AUTH_RESPONSE (sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint8_t) + sizeof(uint16_t))

// TCG TIS Specification Table 14
typedef enum 
{
    TIS_ACCESS_VALID = 0x80,
    TIS_ACCESS_ACTIVE_LOCALITY = 0x20,
    TIS_ACCESS_BEEING_SEIZED = 0x10,
    TIS_ACCESS_SEIZE = 0x08,
    TIS_ACCESS_PENDING_REQUEST = 0x04,
    TIS_ACCESS_REQUEST_USE = 0x02,
    TIS_ACCESS_TPM_ESTABLISHMENT = 0x01
} TIS_ACCESS;

// TIS Specification Table 15
typedef enum 
{
    TIS_STS_TPMFAMILY_20 = 0x04000000,
    TIS_STS_VALID = 0x80,
    TIS_STS_COMMAND_READY = 0x40,
    TIS_STS_GO = 0x20,
    TIS_STS_DATA_AVAIL = 0x10,
    TIS_STS_DATA_EXPECT = 0x08,
    TIS_STS_RESPONSERETRY = 0x02
} TIS_STS;

typedef enum 
{
    TIS_LOCALITY_0 = 0,
    TIS_LOCALITY_1 = 1,
    TIS_LOCALITY_2 = 2,
    TIS_LOCALITY_3 = 3,
    TIS_LOCALITY_4 = 4,
    TIS_LOCALITY_NONE = -1
} TIS_LOCALITY;

int32_t
TpmAdjustSpinWait(
	int32_t preset
);

HAL_StatusTypeDef
DetectTpm(
    void
);

HAL_StatusTypeDef
RequestLocality(
    TIS_LOCALITY locality
);

HAL_StatusTypeDef
ReleaseLocality(
    void
);

HAL_StatusTypeDef
TpmSubmit(
    const uint8_t* cmd,
    uint32_t cmdLen,
    uint8_t* rsp,
    uint32_t rspMax,
    uint32_t* rspSize,
    uint32_t timeout
);

uint32_t
TpmSelfTest(
    void
);

uint32_t
TpmGetRandom(
    uint8_t* random,
    uint32_t randomSize
);

uint32_t
TpmClearControl(
    uint8_t disable
);

uint32_t
TpmClear(
    void
);

uint32_t
TpmHashSequenceStart(
    uint32_t* handle,
    uint16_t hashAlg
);

uint32_t
TpmHashSequenceUpdate(
    uint32_t handle,
    uint8_t* dataPtr,
    uint32_t dataSize
);

uint32_t
TpmHashSequenceComplete(
    uint32_t handle,
    uint8_t* dataPtr,
    uint32_t dataSize,
    uint8_t* digest,
    uint32_t digestMax,
    uint32_t* digestSize
);

uint32_t
TpmEventSequenceComplete(
    uint32_t handle,
    uint32_t pcrIndex,
    uint8_t* dataPtr,
    uint32_t dataSize,
    uint8_t* measurement,
    uint32_t measurementMax,
    uint32_t* measurementSize
);

uint32_t
TpmStartup(
    uint16_t startupType
);

uint32_t
TpmShutdown(
    uint16_t shutdownType
);

#ifdef __cplusplus
}
#endif

#endif /* __TISTPMDRV_H */
