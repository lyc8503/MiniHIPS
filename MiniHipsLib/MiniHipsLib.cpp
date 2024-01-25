// MiniHipsLib.cpp : Defines the functions for the static library.
//

#include "pch.h"
#include "framework.h"

#include <windows.h>

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

    // TODO: some weird...
    //if (WaitForSingleObject(hThread, 1000) != WAIT_OBJECT_0) {
    //  dwRetCode = -6;
	//	goto cleanup;
    //}

    // If we get here, everything was successful
    dwRetCode = 0;

cleanup:
    //if (lpBaseAddress != NULL) {
    //    VirtualFreeEx(hProcess, lpBaseAddress, 0, MEM_RELEASE);
    //}

    if (hThread != NULL) {
		CloseHandle(hThread);
	}

    return dwRetCode;
}

