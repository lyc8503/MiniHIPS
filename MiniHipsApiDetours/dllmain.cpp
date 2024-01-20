// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <windows.h>
#include "detours/detours.h"

#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")
#include <pathcch.h>
#pragma comment(lib, "pathcch.lib")
#include <shellapi.h>

#include <winternl.h>
#include <ntstatus.h>

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

// https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile
typedef NTSTATUS(NTAPI* PFNNtCreateFile) (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
static PFNNtCreateFile TrueNtCreateFile = NULL;

typedef NTSTATUS(NTAPI* PFNNtOpenFile) (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);
static PFNNtOpenFile TrueNtOpenFile = NULL;

static BOOL(WINAPI* TrueCreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION) = CreateProcessW;
static BOOL(WINAPI* TrueCreateProcessAsUserW)(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION) = CreateProcessAsUserW;

static HINSTANCE(WINAPI* TrueShellExecuteW)(HWND, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, INT) = ShellExecuteW;


NTSTATUS NTAPI HookedNtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess,
    ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
{
	//MessageBox(NULL, L"Hooked NtCreateFile", L"Hi", MB_OK);
    DebugPrint(L"Hooked NtCreateFile: %s", ObjectAttributes->ObjectName->Buffer);

    WCHAR canonicalPath[MAX_PATH + 100];
    HRESULT hr = PathCchCanonicalizeEx(canonicalPath, ARRAYSIZE(canonicalPath), ObjectAttributes->ObjectName->Buffer, PATHCCH_ALLOW_LONG_PATHS);
    if (!SUCCEEDED(hr)) {
		return STATUS_INTERNAL_ERROR;
	}
    
	DebugPrint(L"canonicalPath: %s", canonicalPath);
    if (PathMatchSpecW(canonicalPath, TEXT("\\??\\C:\\*.txt"))) {
		DebugPrint(L"Rejected: %s", canonicalPath);
		return STATUS_ACCESS_DENIED;
	}

	return TrueNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess,
        		CreateDisposition, CreateOptions, EaBuffer, EaLength);
}


NTSTATUS NTAPI HookedNtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions)
{
	//MessageBox(NULL, L"Hooked NtOpenFile", L"Hi", MB_OK);
	DebugPrint(L"Hooked NtOpenFile: %s", ObjectAttributes->ObjectName->Buffer);

	WCHAR canonicalPath[MAX_PATH + 100];
	HRESULT hr = PathCchCanonicalizeEx(canonicalPath, ARRAYSIZE(canonicalPath), ObjectAttributes->ObjectName->Buffer, PATHCCH_ALLOW_LONG_PATHS);
    if (!SUCCEEDED(hr)) {
		return STATUS_INTERNAL_ERROR;
	}
	
	DebugPrint(L"canonicalPath: %s", canonicalPath);
    if (PathMatchSpecW(canonicalPath, TEXT("\\??\\C:\\*.txt"))) {
		DebugPrint(L"Rejected: %s", canonicalPath);
		return STATUS_ACCESS_DENIED;
	}

	return TrueNtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
}


BOOL WINAPI HookedCreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
{
	MessageBox(NULL, L"Hooked CreateProcessW", L"Hi", MB_OK);
	DebugPrint(L"Hooked CreateProcessW: %s", lpCommandLine);

	return TrueCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags,
        		lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}


BOOL WINAPI HookedCreateProcessAsUserW(HANDLE hToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
{
	MessageBox(NULL, L"Hooked CreateProcessAsUserW", L"Hi", MB_OK);
	DebugPrint(L"Hooked CreateProcessAsUserW: %s", lpCommandLine);

	return TrueCreateProcessAsUserW(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags,
        				lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}


HINSTANCE WINAPI HookedShellExecuteW(HWND hwnd, LPCWSTR lpOperation, LPCWSTR lpFile, LPCWSTR lpParameters, LPCWSTR lpDirectory, INT nShowCmd)
{
	MessageBox(NULL, L"Hooked ShellExecuteW", L"Hi", MB_OK);
	DebugPrint(L"Hooked ShellExecuteW: %s", lpFile);

	return TrueShellExecuteW(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);
}



BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    DebugPrint(L"Enter MiniHipsApiDetours.dll DllMain, PID: %lu, reason: %lu", GetCurrentProcessId(), ul_reason_for_call);

    if (ul_reason_for_call != DLL_PROCESS_ATTACH) {
        // Return on DLL_THREAD_ATTACH, DLL_THREAD_DETACH and DLL_PROCESS_DETACH
		return TRUE;
	}

    // Dynamically load Native APIs
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll == NULL) {
        DebugPrint(L"GetModuleHandleW(ntdll.dll) failed, return");
        return FALSE;
    }

    TrueNtCreateFile = (PFNNtCreateFile)GetProcAddress(hNtdll, "NtCreateFile");
    DebugPrint(L"GetProcAddress(NtCreateFile) = %p", TrueNtCreateFile);
    if (TrueNtCreateFile == NULL) {
        DebugPrint(L"GetProcAddress(NtCreateFile) failed, return");
        return FALSE;
    }

    TrueNtOpenFile = (PFNNtOpenFile)GetProcAddress(hNtdll, "NtOpenFile");
    DebugPrint(L"GetProcAddress(NtOpenFile) = %p", TrueNtOpenFile);
    if (TrueNtOpenFile == NULL) {
		DebugPrint(L"GetProcAddress(NtOpenFile) failed, return");
		return FALSE;
	}

    // https://github.com/microsoft/Detours/wiki/OverviewHelpers
    // Immediately return TRUE if DetourIsHelperProcess return TRUE. 
    if (DetourIsHelperProcess()) {
        DebugPrint(L"DetourIsHelperProcess() = true, return");
        return TRUE;
    }
    
    // MessageBox(NULL, L"Hello from DLL", L"Hi", MB_OK);
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourAttach(&(PVOID&)TrueNtCreateFile, HookedNtCreateFile);
    DetourAttach(&(PVOID&)TrueNtOpenFile, HookedNtOpenFile);

    DetourAttach(&(PVOID&)TrueCreateProcessW, HookedCreateProcessW);
    DetourAttach(&(PVOID&)TrueCreateProcessAsUserW, HookedCreateProcessAsUserW);
        
    DetourAttach(&(PVOID&)TrueShellExecuteW, HookedShellExecuteW);
    if (DetourTransactionCommit() != NO_ERROR) {
		DebugPrint(L"DetourTransactionCommit failed, return");
		return FALSE;
	}
    DebugPrint(L"AfterDetourAttach NtCreateFile = %p", TrueNtCreateFile);
    DebugPrint(L"AfterDetourAttach NtOpenFile = %p", TrueNtOpenFile);

    return TRUE;
}

