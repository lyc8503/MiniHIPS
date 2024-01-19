// MiniHipsHelper.cpp : Defines the exported functions for the DLL.
//

#include "pch.h"
#include "framework.h"
#include "MiniHipsHelper.h"


MINIHIPSHELPER_API int InjectDllPid(DWORD dwProcessId, const char* dllPath)
{
	HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, dwProcessId);
	if (hProcess == NULL)
	{
		return -1;
	}

	LPVOID pRemoteBuf = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
	if (pRemoteBuf == NULL)
	{
		return -2;
	}

	if (!WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)dllPath, strlen(dllPath) + 1, NULL))
	{
		return -3;
	}

	HMODULE hMod = GetModuleHandleA("kernel32.dll");
	if (hMod == NULL)
	{
		return -4;
	}

	LPVOID pLoadLibraryA = (LPVOID)GetProcAddress(hMod, "LoadLibraryA");
	if (pLoadLibraryA == NULL)
	{
		return -5;
	}

	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryA, pRemoteBuf, 0, NULL);
	if (hThread == NULL)
	{
		return -6;
	}

	WaitForSingleObject(hThread, INFINITE);

	VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
	CloseHandle(hThread);
	CloseHandle(hProcess);

	return 0;
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
