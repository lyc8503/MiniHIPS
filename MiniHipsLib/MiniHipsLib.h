#pragma once

#include <windows.h>
#include <stdio.h>


typedef struct _MiniHipsMessage {
    DWORD dwProcessId;
    SYSTEMTIME stTime;
    WCHAR szMsg[1024];
} MiniHipsMessage;


#define MINIHIPS_MQ_NAME "MiniHipsMessageQueue"
#define MINIHIPS_MQ_MSG_MAX_COUNT 100
#define MINIHIPS_MQ_MSG_SIZE sizeof(MiniHipsMessage)


#ifdef _DEBUG
void DebugPrint(const wchar_t* format, ...);
#else
#define DebugPrint(format, ...) ((void)0)
#endif

int InjectDll(HANDLE hProcess, LPCWSTR lpszDllPath);
LPVOID CreateIPCQueue(BOOL bServer);
DWORD IPCQueueRead(LPVOID lpQueue, MiniHipsMessage* lpMsg);
DWORD IPCQueueWrite(LPVOID lpQueue, MiniHipsMessage* lpMsg);
