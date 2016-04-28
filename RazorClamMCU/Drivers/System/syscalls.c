/**
*****************************************************************************
**
**  File        : syscalls.c
**
**  Abstract    : Atollic TrueSTUDIO Minimal System calls file
**
** 		          For more information about which c-functions
**                need which of these lowlevel functions
**                please consult the Newlib libc-manual
**
**  Environment : Atollic TrueSTUDIO
**
**  Distribution: The file is distributed "as is", without any warranty
**                of any kind.
**
**  (c)Copyright Atollic AB.
**  You may use this file as-is or modify it according to the needs of your
**  project. This file may only be built (assembled or compiled and linked)
**  using the Atollic TrueSTUDIO(R) product. The use of this file together
**  with other tools than Atollic TrueSTUDIO(R) is not permitted.
**
*****************************************************************************
*/

/* Includes */
#include <stdint.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <sys/times.h>
#include "stm32f4xx_hal.h"
extern UART_HandleTypeDef huart3;
extern RTC_HandleTypeDef hrtc;

/* Variables */
#undef errno
extern int32_t errno;

register uint8_t * stack_ptr asm("sp");

uint8_t *__env[1] = { 0 };
uint8_t **environ = __env;


/* Functions */
void initialise_monitor_handles()
{
}

int _getpid(void)
{
	return 1;
}

int _kill(int32_t pid, int32_t sig)
{
	errno = EINVAL;
	return -1;
}

void _exit (int32_t status)
{
	_kill(status, -1);
	while (1) {}		/* Make sure we hang here */
}

int _write(int32_t file, uint8_t *ptr, int32_t len)
{
    HAL_UART_Transmit(&huart3, ptr, len, HAL_MAX_DELAY);
	return len;
}

caddr_t _sbrk(int32_t incr)
{
	extern uint8_t end asm("end");
	static uint8_t *heap_end;
	uint8_t *prev_heap_end;

	if (heap_end == 0)
		heap_end = &end;

	prev_heap_end = heap_end;
//	if (heap_end + incr > stack_ptr)
//	{
////		write(1, "Heap and stack collision\n", 25);
////		abort();
//		errno = ENOMEM;
//		return (caddr_t) -1;
//	}

	heap_end += incr;

	return (caddr_t) prev_heap_end;
}

int _close(int32_t file)
{
	return -1;
}


int _fstat(int32_t file, struct stat *st)
{
	st->st_mode = S_IFCHR;
	return 0;
}

int _isatty(int32_t file)
{
	return 1;
}

int _lseek(int32_t file, int32_t ptr, int32_t dir)
{
	return 0;
}

int _read(int32_t file, uint8_t *ptr, int32_t len)
{
    HAL_UART_Receive(&huart3, ptr, len, HAL_MAX_DELAY);
    return len;
}

int _open(const uint8_t *path, int32_t flags, int32_t mode)
{
	/* Pretend like we always fail */
	return -1;
}

int _wait(int32_t *status)
{
	errno = ECHILD;
	return -1;
}

int _unlink(const uint8_t *name)
{
	errno = ENOENT;
	return -1;
}

int _times(struct tms *buf)
{
	return -1;
}

int _stat(const uint8_t *file, struct stat *st)
{
	st->st_mode = S_IFCHR;
	return 0;
}

int _link(const uint8_t *old, const uint8_t *new)
{
	errno = EMLINK;
	return -1;
}

int _fork(void)
{
	errno = EAGAIN;
	return -1;
}

int _execve(const uint8_t *name, uint8_t * const *argv, uint8_t * const *env)
{
	errno = ENOMEM;
	return -1;
}

int _gettimeofday(struct timeval *tv, struct timezone *tz)
{
    HAL_StatusTypeDef retVal = HAL_OK;
    RTC_DateTypeDef date = { 0 };
    RTC_TimeTypeDef time = { 0 };
    time_t rawTime = 0;
    struct tm timeInfo = {0};

    if(((retVal = HAL_RTC_GetDate(&hrtc, &date, RTC_FORMAT_BIN)) != HAL_OK) ||
       ((retVal = HAL_RTC_GetTime(&hrtc, &time, RTC_FORMAT_BIN)) != HAL_OK))
    {
        return -1;
    }

    if(tv != NULL)
    {
        timeInfo.tm_sec = time.Seconds;
        timeInfo.tm_min = time.Minutes;
        timeInfo.tm_hour = time.Hours;
        timeInfo.tm_mday = date.Date - 1;
        timeInfo.tm_wday = date.WeekDay;
        timeInfo.tm_mon = date.Month - 1; // January = 0
        timeInfo.tm_year = date.Year + 100; // Base year is 1900
        rawTime = mktime(&timeInfo);
        tv->tv_sec = (long)rawTime;
        tv->tv_usec = ((time.SubSeconds * 1000) / time.SecondFraction) * 1000;
    }
    if(tz != NULL)
    {
        tz->tz_dsttime = 0;
        tz->tz_minuteswest = 0;
    }

    return 0;
}

int _settimeofday(struct timeval *tv, struct timezone *tz)
{
    HAL_StatusTypeDef retVal = HAL_OK;
    RTC_DateTypeDef date = { 0 };
    RTC_TimeTypeDef time = { 0 };
    struct tm* timeInfo = NULL;

    timeInfo = localtime((time_t*)&tv->tv_sec);
    time.Seconds = timeInfo->tm_sec;
    time.Minutes = timeInfo->tm_min;
    time.Hours = timeInfo->tm_hour;
    date.WeekDay = timeInfo->tm_wday;
    date.Date = timeInfo->tm_mday + 1; // mday 0 is the first
    date.Month = timeInfo->tm_mon + 1; // January = 0
    date.Year = timeInfo->tm_year - 100; // Base year is 1900

    if(((retVal = HAL_RTC_SetDate(&hrtc, &date, RTC_FORMAT_BIN)) != HAL_OK) ||
       ((retVal = HAL_RTC_SetTime(&hrtc, &time, RTC_FORMAT_BIN)) != HAL_OK))
    {
        return -1;
    }

    return 0;
}
