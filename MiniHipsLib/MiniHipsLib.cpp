// MiniHipsLib.cpp : Defines the functions for the static library.
//

#include "pch.h"
#include "framework.h"

#include <windows.h>
#include <boost/interprocess/ipc/message_queue.hpp>

#include "MiniHipsLib.h"

// DebugPrint is a wrapper around OutputDebugStringW that takes a printf-style format string
void DebugPrint(const wchar_t* format, ...) {
    wchar_t buffer[1024];
    va_list args;

    va_start(args, format);
    _vsnwprintf_s(buffer, ARRAYSIZE(buffer) - 1, _TRUNCATE, format, args);
    buffer[ARRAYSIZE(buffer) - 1] = 0; // Ensure null-termination
    va_end(args);

    OutputDebugStringW(buffer);
}


// Given a process handle and a DLL path, inject the DLL into the process
// hProcess should have the following access rights:
// PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE
int InjectDll(HANDLE hProcess, LPCWSTR lpszDllPath)
{
    LPVOID lpBaseAddress = NULL;
    HMODULE hModule = NULL;
    LPVOID lpLoadLibrary = NULL;
    DWORD dwThreadId = 0;
    HANDLE hThread = NULL;
    DWORD dwRetCode = 0;

    // Allocate memory in the target process for the DLL path
    lpBaseAddress = VirtualAllocEx(hProcess, NULL, (wcslen(lpszDllPath) + 1) * sizeof(wchar_t), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (lpBaseAddress == NULL) {
        dwRetCode = -1;
        goto cleanup;
    }

    // Write the DLL path into the allocated memory
    if (!WriteProcessMemory(hProcess, lpBaseAddress, lpszDllPath, (wcslen(lpszDllPath) + 1) * sizeof(wchar_t), NULL)) {
        dwRetCode = -2;
        goto cleanup;
    }

    // Get the address of LoadLibraryW
    hModule = GetModuleHandle(L"kernel32.dll");
    if (hModule == NULL) {
        dwRetCode = -3;
        goto cleanup;
    }

    lpLoadLibrary = GetProcAddress(hModule, "LoadLibraryW");
    if (lpLoadLibrary == NULL) {
        dwRetCode = -4;
        goto cleanup;
    }

    // Create a remote thread to call LoadLibraryW with the DLL path
    hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpLoadLibrary, lpBaseAddress, 0, &dwThreadId);
    if (hThread == NULL) {
        dwRetCode = -5;
        goto cleanup;
    }

    if (WaitForSingleObject(hThread, 1000) != WAIT_OBJECT_0) {
        dwRetCode = -6;
        goto cleanup;
    }

    // If we get here, everything was successful
    dwRetCode = 0;

cleanup:
    if (lpBaseAddress != NULL) {
        VirtualFreeEx(hProcess, lpBaseAddress, 0, MEM_RELEASE);
    }

    if (hThread != NULL) {
        CloseHandle(hThread);
    }

    return dwRetCode;
}



// Create an boost interprocess message queue, return a pointer to the queue
// If bServer is TRUE, create a new queue, otherwise open an existing queue
LPVOID CreateIPCQueue(BOOL bServer) {

    if (bServer) {
        boost::interprocess::message_queue::remove(MINIHIPS_MQ_NAME);
    }

    boost::interprocess::message_queue* mq;

    try {
        if (bServer) {
            boost::interprocess::permissions unrestricted_permissions;
            unrestricted_permissions.set_unrestricted();

            mq = new boost::interprocess::message_queue(
                boost::interprocess::create_only,
                MINIHIPS_MQ_NAME,
                MINIHIPS_MQ_MSG_MAX_COUNT,
                MINIHIPS_MQ_MSG_SIZE,
                unrestricted_permissions);
        }
        else {
            mq = new boost::interprocess::message_queue(
                boost::interprocess::open_only,
                MINIHIPS_MQ_NAME);
        }
    }
    catch (boost::interprocess::interprocess_exception& ex) {
        DebugPrint(L"CreateIPCQueueFailed: %S\n", ex.what());
        return NULL;
    }

    return mq;
}


// Read a message from the queue, blocking until a message is available
// Return 0 on success or a negative value on failure
DWORD IPCQueueRead(LPVOID lpQueue, MiniHipsMessage* lpMsg) {
    boost::interprocess::message_queue* mq = (boost::interprocess::message_queue*)lpQueue;

    try {
        boost::interprocess::message_queue::size_type sRecvd;
        unsigned int dwPriority;

        mq->receive(lpMsg, MINIHIPS_MQ_MSG_SIZE, sRecvd, dwPriority);

        if (sRecvd != MINIHIPS_MQ_MSG_SIZE) {
            DebugPrint(L"IPCQueueReadFailed: sRecvd != MINIHIPS_MQ_MSG_SIZE\n");
            return -2;
        }
    }
    catch (boost::interprocess::interprocess_exception& ex) {
        DebugPrint(L"IPCQueueReadFailed: %S\n", ex.what());
        return -1;
    }

    return 0;
}


// Write a message to the queue, returning immediately
// Return 0 on success or a negative value on failure / full queue
DWORD IPCQueueWrite(LPVOID lpQueue, MiniHipsMessage* lpMsg) {
    boost::interprocess::message_queue* mq = (boost::interprocess::message_queue*)lpQueue;

    try {
        if (!mq->try_send(lpMsg, MINIHIPS_MQ_MSG_SIZE, 0)) {
            DebugPrint(L"IPCQueueWriteFailed: queue is full\n");
            return -2;
        }
    }
    catch (boost::interprocess::interprocess_exception& ex) {
        DebugPrint(L"IPCQueueWriteFailed: %S\n", ex.what());
        return -1;
    }

    return 0;
}
