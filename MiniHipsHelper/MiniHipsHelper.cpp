// MiniHipsHelper.cpp : Defines the exported functions for the DLL.
//

#include "pch.h"
#include "framework.h"
#include "MiniHipsHelper.h"

#include "MiniHipsLib.h"

#include <stdio.h>


MINIHIPSHELPER_API int InjectDllPid(DWORD dwProcessId, LPCWSTR lpszDllPath)
{
	HANDLE hProcess;
	DWORD dwInjectRet;
	DWORD dwRetCode;

	// Open the target process
	hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, dwProcessId);
	if (hProcess == NULL) {
		dwRetCode = 1;
		goto cleanup;
	}

	dwInjectRet = InjectDll(hProcess, lpszDllPath);

	if (dwInjectRet != 0) {
		dwRetCode = dwInjectRet;
		goto cleanup;
	}

	dwRetCode = 0;

cleanup:
	if (hProcess != NULL) {
		CloseHandle(hProcess);
	}

	return 0;
}

LPVOID lpQueue;

MINIHIPSHELPER_API WCHAR* IPCQueueWaitMsg() {

	if (lpQueue == NULL) {
		lpQueue = CreateIPCQueue(TRUE);
		if (lpQueue == NULL) {
			return NULL;
		}
	}

	MiniHipsMessage stMsg;
	int dwRet = IPCQueueRead(lpQueue, &stMsg);
	if (dwRet != 0) {
		return NULL;
	}

	// TODO
	return (WCHAR*) 1;
}

// This is an example of an exported variable
MINIHIPSHELPER_API int nMiniHipsHelper=0;

// This is an example of an exported function.
MINIHIPSHELPER_API int fnMiniHipsHelper(void)
{
    return 0;
}

// This is the constructor of a class that has been exported.
CMiniHipsHelper::CMiniHipsHelper()
{
    return;
}
