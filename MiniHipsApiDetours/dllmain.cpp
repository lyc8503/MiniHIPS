// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <windows.h>
#include "detours/detours.h"
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")
#include <pathcch.h>
#pragma comment(lib, "pathcch.lib")


static HANDLE(WINAPI* TrueCreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = CreateFileW;


HANDLE WINAPI HookedCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    MessageBox(NULL, L"Hooked CreateFileW", L"Hi", MB_OK);

    WCHAR canonicalPath[MAX_PATH + 100];
    HRESULT hr = PathCchCanonicalizeEx(canonicalPath, ARRAYSIZE(canonicalPath), lpFileName, PATHCCH_ALLOW_LONG_PATHS);

    if (!SUCCEEDED(hr)) {
        SetLastError(ERROR_INTERNAL_ERROR);
        SetLastError(ERROR_OUT_OF_PAPER);
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

    // https://github.com/microsoft/Detours/wiki/OverviewHelpers
    // Immediately return TRUE if DetourIsHelperProcess return TRUE. 
    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        MessageBox(NULL, L"Hello from DLL", L"Hi", MB_OK);
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

