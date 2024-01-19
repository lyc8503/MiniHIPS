// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <windows.h>
#include "detours/detours.h"
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")
#include <pathcch.h>
#pragma comment(lib, "pathcch.lib")


#include <stdio.h>
#include <stdarg.h>

#ifdef _DEBUG
void DebugPrint(const wchar_t* format, ...);
void DebugPrint(const wchar_t* format, ...) {
    wchar_t buffer[1024];
    va_list args;

    va_start(args, format);
    _vsnwprintf_s(buffer, ARRAYSIZE(buffer) - 1, _TRUNCATE, format, args);
    buffer[ARRAYSIZE(buffer) - 1] = 0; // Ensure null-termination
    va_end(args);

    OutputDebugStringW(buffer);
}
#else
#define DebugPrint(format, ...) ((void)0)
#endif


static HANDLE(WINAPI* TrueCreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = CreateFileW;


HANDLE WINAPI HookedCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    //MessageBox(NULL, L"Hooked CreateFileW", L"Hi", MB_OK);
    DebugPrint(L"Hooked CreateFileW: %s", lpFileName);

    WCHAR canonicalPath[MAX_PATH + 100];
    HRESULT hr = PathCchCanonicalizeEx(canonicalPath, ARRAYSIZE(canonicalPath), lpFileName, PATHCCH_ALLOW_LONG_PATHS);

    if (!SUCCEEDED(hr)) {
        SetLastError(ERROR_INTERNAL_ERROR);
        return INVALID_HANDLE_VALUE;
    }

    if (PathMatchSpecW(canonicalPath, TEXT("C:\\*.txt"))) {
        SetLastError(ERROR_ACCESS_DENIED);
        return INVALID_HANDLE_VALUE;
    }

    return TrueCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{

    DebugPrint(L"Enter MiniHipsApiDetours.dll DllMain, PID: %lu", GetCurrentProcessId());

    // https://github.com/microsoft/Detours/wiki/OverviewHelpers
    // Immediately return TRUE if DetourIsHelperProcess return TRUE. 
    if (DetourIsHelperProcess()) {
        DebugPrint(L"DetourIsHelperProcess() = true, return");
        return TRUE;
    }

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // MessageBox(NULL, L"Hello from DLL", L"Hi", MB_OK);
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)TrueCreateFileW, HookedCreateFileW);
        DetourTransactionCommit();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

