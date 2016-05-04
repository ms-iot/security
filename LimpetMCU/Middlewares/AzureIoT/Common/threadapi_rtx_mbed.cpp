// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <cstdlib>
#ifdef _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

#include "stdlib.h"
#include "threadapi.h"
#include "cmsis_os.h"
//#include "rtos.h"
#include "iot_logging.h"

DEFINE_ENUM_STRINGS(THREADAPI_RESULT, THREADAPI_RESULT_VALUES);

#define MAX_THREADS 4
#define STACK_SIZE  0x4000

typedef struct _thread
{
    osThreadId    id;
    osMessageQId  result;
} osThread;
static osThread threads[MAX_THREADS] = { 0 };
//typedef struct _thread
//{
//    Thread*       thrd;
//    osThreadId    id;
//    Queue<int, 1> result;
//} mbedThread;
//static mbedThread threads[MAX_THREADS] = { 0 };

typedef struct _create_param
{
    THREAD_START_FUNC func;
    const void* arg;
    osThread *p_thread;
} create_param;

static void thread_wrapper(const void* createParamArg)
{
    const create_param* p = (const create_param*)createParamArg;
    p->p_thread->id = osThreadGetId();
//    p->p_thread->id = Thread::gettid();
    (*(p->func))((void*)p->arg);
    free((void*)p);
}

THREADAPI_RESULT ThreadAPI_Create(THREAD_HANDLE* threadHandle, THREAD_START_FUNC func, void* arg)
{
    THREADAPI_RESULT result;
    if ((threadHandle == NULL) ||
        (func == NULL))
    {
        result = THREADAPI_INVALID_ARG;
        LogError("(result = %s)\r\n", ENUM_TO_STRING(THREADAPI_RESULT, result));
    }
    else
    {
        size_t slot;
        for (slot = 0; slot < MAX_THREADS; slot++)
        {
            if (threads[slot].id == NULL)
                break;
        }

        if (slot < MAX_THREADS)
        {
            create_param* param = (create_param*)malloc(sizeof(create_param));
            if (param != NULL)
            {
                const os_messageQ_def qDef = {1, sizeof(int)};
                threads[slot].result = osMessageCreate(&qDef, NULL);
                param->func = func;
                param->arg = arg;
                param->p_thread = threads + slot;
                osThreadDef(taskToStart, thread_wrapper, osPriorityNormal, 0, STACK_SIZE);
                threads[slot].id = osThreadCreate(osThread(taskToStart), param);
//                threads[slot].thrd = new Thread(thread_wrapper, param, osPriorityNormal, STACK_SIZE);
                *threadHandle = (THREAD_HANDLE)(threads + slot);
                result = THREADAPI_OK;
            }
            else
            {
                result = THREADAPI_NO_MEMORY;
                LogError("(result = %s)\r\n", ENUM_TO_STRING(THREADAPI_RESULT, result));
            }
        }
        else
        {
            result = THREADAPI_NO_MEMORY;
            LogError("(result = %s)\r\n", ENUM_TO_STRING(THREADAPI_RESULT, result));
        }
    }

    return result;
}

THREADAPI_RESULT ThreadAPI_Join(THREAD_HANDLE thr, int *res)
{
    THREADAPI_RESULT result = THREADAPI_OK;
    osThread* p = (osThread*)thr;
    if (p)
    {
        osEvent evt = osMessageGet(p->result, osWaitForever);
        if (evt.status == osEventMessage) {
            if (res)
            {
                *res = (int)evt.value.p;
            }
            osThreadTerminate(p->id);
        }
        else
        {
            result = THREADAPI_ERROR;
            LogError("(result = %s)\r\n", ENUM_TO_STRING(THREADAPI_RESULT, result));
        }
    }
    else
    {
        result = THREADAPI_INVALID_ARG;
        LogError("(result = %s)\r\n", ENUM_TO_STRING(THREADAPI_RESULT, result));
    }
    return result;
}

void ThreadAPI_Exit(int res)
{
    osThread* p;
    for (p = threads; p < &threads[MAX_THREADS]; p++)
    {
        if (p->id == osThreadGetId())
        {
            osMessagePut(p->result, res, 0);
//            p->result.put((int*)res);
            break;
        }
    }
}

void ThreadAPI_Sleep(unsigned int millisec)
{
    osDelay(millisec);
    // The timer on mbed seems to wrap around 65 seconds. Hmmm.
    // So we will do our waits in increments of 30 seconds.
    //
//    const int thirtySeconds = 30000;
//    int numberOfThirtySecondWaits = millisec / thirtySeconds;
//    int remainderOfThirtySeconds = millisec % thirtySeconds;
//    int i;
//    for (i = 1; i <= numberOfThirtySecondWaits; i++)
//    {
//        Thread::wait(thirtySeconds);
//    }
//    Thread::wait(remainderOfThirtySeconds);
}
