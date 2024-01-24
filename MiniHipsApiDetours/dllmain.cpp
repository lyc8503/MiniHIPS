// dllmain.cpp :
// This DLL is injected into all processes to intercept certain API calls. Specifically, 
// the system calls 'NtCreateFile' and 'NtOpenFile' are intercepted to regulate file access, 
// and 'NtCreateUserProcess' is intercepted to ensure the DLL is injected into any newly
// created subprocesses.

#include "pch.h"
#include <windows.h>
#include "detours/detours.h"

#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")
#include <pathcch.h>
#pragma comment(lib, "pathcch.lib")

#include <winternl.h>
#include <ntstatus.h>

#include "MiniHipsLib.h"


// Taken from https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h#L1330
#define PROCESS_CREATE_FLAGS_BREAKAWAY 0x00000001 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_NO_DEBUG_INHERIT 0x00000002 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_INHERIT_HANDLES 0x00000004 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_OVERRIDE_ADDRESS_SPACE 0x00000008 // NtCreateProcessEx only
#define PROCESS_CREATE_FLAGS_LARGE_PAGES 0x00000010 // NtCreateProcessEx only, requires SeLockMemory
#define PROCESS_CREATE_FLAGS_LARGE_PAGE_SYSTEM_DLL 0x00000020 // NtCreateProcessEx only, requires SeLockMemory
#define PROCESS_CREATE_FLAGS_PROTECTED_PROCESS 0x00000040 // NtCreateUserProcess only
#define PROCESS_CREATE_FLAGS_CREATE_SESSION 0x00000080 // NtCreateProcessEx & NtCreateUserProcess, requires SeLoadDriver
#define PROCESS_CREATE_FLAGS_INHERIT_FROM_PARENT 0x00000100 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_SUSPENDED 0x00000200 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_FORCE_BREAKAWAY 0x00000400 // NtCreateProcessEx & NtCreateUserProcess, requires SeTcb
#define PROCESS_CREATE_FLAGS_MINIMAL_PROCESS 0x00000800 // NtCreateProcessEx only
#define PROCESS_CREATE_FLAGS_RELEASE_SECTION 0x00001000 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_CLONE_MINIMAL 0x00002000 // NtCreateProcessEx only
#define PROCESS_CREATE_FLAGS_CLONE_MINIMAL_REDUCED_COMMIT 0x00004000 //
#define PROCESS_CREATE_FLAGS_AUXILIARY_PROCESS 0x00008000 // NtCreateProcessEx & NtCreateUserProcess, requires SeTcb
#define PROCESS_CREATE_FLAGS_CREATE_STORE 0x00020000 // NtCreateProcessEx only
#define PROCESS_CREATE_FLAGS_USE_PROTECTED_ENVIRONMENT 0x00040000 // NtCreateProcessEx & NtCreateUserProces

#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001 // NtCreateUserProcess & NtCreateThreadEx
#define THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH 0x00000002 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x00000004 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_LOADER_WORKER 0x00000010 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_SKIP_LOADER_INIT 0x00000020 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE 0x00000040 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_INITIAL_THREAD 0x00000080 // ?


// https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile
typedef NTSTATUS(NTAPI* PFNNtCreateFile) (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
static PFNNtCreateFile TrueNtCreateFile = NULL;

typedef NTSTATUS(NTAPI* PFNNtOpenFile) (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);
static PFNNtOpenFile TrueNtOpenFile = NULL;

typedef NTSTATUS(NTAPI* PFNNtCreateUserProcess) (PHANDLE, PHANDLE, ACCESS_MASK, ACCESS_MASK, POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES, ULONG, ULONG, PRTL_USER_PROCESS_PARAMETERS, PVOID, PVOID);
static PFNNtCreateUserProcess TrueNtCreateUserProcess = NULL;


WCHAR SelfPath[MAX_PATH];


// The function 'HookedNtCreateFile' is an implementation that intercepts the original 'NtCreateFile' system call.
// It applies custom security rules to file creation operations. If a rule is violated, the function returns a STATUS_ACCESS_DENIED error.
NTSTATUS NTAPI HookedNtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess,
    ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
{
    //MessageBox(NULL, L"Hooked NtCreateFile", L"Hi", MB_OK);

    WCHAR canonicalPath[MAX_PATH + 100];
    HRESULT hr;
    if (ObjectAttributes == NULL || ObjectAttributes->ObjectName == NULL || ObjectAttributes->ObjectName->Buffer == NULL) {
		DebugPrint(L"Hooked NtCreateFile: ObjectAttributes->ObjectName->Buffer is NULL");
		goto origin;
	}

    DebugPrint(L"Hooked NtCreateFile: %s", ObjectAttributes->ObjectName->Buffer);

    hr = PathCchCanonicalizeEx(canonicalPath, ARRAYSIZE(canonicalPath), ObjectAttributes->ObjectName->Buffer, PATHCCH_ALLOW_LONG_PATHS);
    if (!SUCCEEDED(hr)) {
		return STATUS_INTERNAL_ERROR;
	}
    
	DebugPrint(L"canonicalPath: %s", canonicalPath);
    if (PathMatchSpecW(canonicalPath, TEXT("\\??\\C:\\*.txt"))) {
		DebugPrint(L"Rejected: %s", canonicalPath);
		return STATUS_ACCESS_DENIED;
	}

origin:
	return TrueNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess,
        		CreateDisposition, CreateOptions, EaBuffer, EaLength);
}


// The function 'HookedNtOpenFile' is an implementation that intercepts the original 'NtCreateFile' system call.
// It applies custom security rules to file open operations. If a rule is violated, the function returns a STATUS_ACCESS_DENIED error.
NTSTATUS NTAPI HookedNtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions)
{
    //MessageBox(NULL, L"Hooked NtOpenFile", L"Hi", MB_OK);

	WCHAR canonicalPath[MAX_PATH + 100];
	HRESULT hr;
    if (ObjectAttributes == NULL || ObjectAttributes->ObjectName == NULL || ObjectAttributes->ObjectName->Buffer == NULL) {
        DebugPrint(L"Hooked NtOpenFile: ObjectAttributes->ObjectName->Buffer is NULL");
        goto origin;
    }

	DebugPrint(L"Hooked NtOpenFile: %s", ObjectAttributes->ObjectName->Buffer);

	hr = PathCchCanonicalizeEx(canonicalPath, ARRAYSIZE(canonicalPath), ObjectAttributes->ObjectName->Buffer, PATHCCH_ALLOW_LONG_PATHS);
    if (!SUCCEEDED(hr)) {
		return STATUS_INTERNAL_ERROR;
	}
	
	DebugPrint(L"canonicalPath: %s", canonicalPath);
    if (PathMatchSpecW(canonicalPath, TEXT("\\??\\C:\\*.txt"))) {
		DebugPrint(L"Rejected: %s", canonicalPath);
		return STATUS_ACCESS_DENIED;
	}

 origin:
	return TrueNtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
}


// The 'HookedNtCreateUserProcess' function is designed to replace the original 'NtCreateUserProcess' system call.
// Its purpose is to ensure that this DLL is automatically injected into every newly created subprocess, thereby extending
// the interception and custom handling to child processes as well.
NTSTATUS NTAPI HookedNtCreateUserProcess(PHANDLE ProcessHandle, PHANDLE ThreadHandle, ACCESS_MASK ProcessDesiredAccess,
    ACCESS_MASK ThreadDesiredAccess, POBJECT_ATTRIBUTES ProcessObjectAttributes, POBJECT_ATTRIBUTES ThreadObjectAttributes,
    ULONG CreateProcessFlags, ULONG CreateThreadFlags, PRTL_USER_PROCESS_PARAMETERS ProcessParameters, PVOID CreateInfo,
    PVOID AttributeList)
{
    NTSTATUS status;
    DWORD dwInjectStatus;

    if (ProcessParameters == NULL || ProcessParameters->CommandLine.Buffer == NULL) {
		DebugPrint(L"Hooked NtCreateUserProcess: ProcessParameters->CommandLine.Buffer is NULL");
        status = STATUS_INTERNAL_ERROR;
        goto exit;
	}

    DebugPrint(L"Hooked NtCreateUserProcess: %s", ProcessParameters->CommandLine.Buffer);

    // Definitions of dwCreationFlags don't apply here (https://captmeelo.com/redteam/maldev/2022/05/10/ntcreateuserprocess.html)
    // According to https://medium.com/@Achilles8284/the-birth-of-a-process-part-2-97c6fb9c42a2
    // CreateProcess generally sets the THREAD_CREATE_FLAGS_CREATE_SUSPENDED flag when calling NtCreateUserProcess
    if (!(CreateThreadFlags & THREAD_CREATE_FLAGS_CREATE_SUSPENDED)) {
        DebugPrint(L"CreateThreadFlags & THREAD_CREATE_FLAGS_CREATE_SUSPENDED is false, return");
        status = STATUS_INTERNAL_ERROR;
        goto exit;
    }
    // CreateProcessFlags |= PROCESS_CREATE_FLAGS_SUSPENDED;
    // CreateThreadFlags |= THREAD_CREATE_FLAGS_CREATE_SUSPENDED;

    status = TrueNtCreateUserProcess(ProcessHandle, ThreadHandle, ProcessDesiredAccess, ThreadDesiredAccess, ProcessObjectAttributes,
        						ThreadObjectAttributes, CreateProcessFlags, CreateThreadFlags, ProcessParameters, CreateInfo, AttributeList);
    if (!NT_SUCCESS(status)) {
        // Process creation failed, return original status
        goto exit;
    }

    // Inject self into the newly created process
    dwInjectStatus = InjectDll(*ProcessHandle, SelfPath);
    if (dwInjectStatus != 0) {
        DebugPrint(L"InjectDll failed: %d", dwInjectStatus);
        status = STATUS_INTERNAL_ERROR;
        goto cleanup;
    }

    // Everything is successful
    goto exit;

cleanup:
    if (ProcessHandle != NULL && *ProcessHandle != NULL) {
        TerminateProcess(*ProcessHandle, 233);
        CloseHandle(*ProcessHandle);
		*ProcessHandle = NULL;
	}

    if (ThreadHandle != NULL && *ThreadHandle != NULL) {
		CloseHandle(*ThreadHandle);
		*ThreadHandle = NULL;
	}

exit:
    return status;	
}


// 'DllMain' serves as the entry point when the DLL is loaded into a process. It is responsible 
// for initiating the API detouring within the host process to facilitate the above-mentioned functionalities.
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

    // https://github.com/microsoft/Detours/wiki/OverviewHelpers
    // Immediately return TRUE if DetourIsHelperProcess return TRUE. 
    if (DetourIsHelperProcess()) {
        DebugPrint(L"DetourIsHelperProcess() = true, return");
        return TRUE;
    }

    // Retrieve the current dll's path for subsequent injection into sub-processes
    if (GetModuleFileName(hModule, SelfPath, MAX_PATH) == 0) {
        DebugPrint(L"GetModuleFileName failed, return");
		return FALSE;
    }
    DebugPrint(L"SelfPath: %s", SelfPath);

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

    TrueNtCreateUserProcess = (PFNNtCreateUserProcess)GetProcAddress(hNtdll, "NtCreateUserProcess");
    DebugPrint(L"GetProcAddress(NtCreateUserProcess) = %p", TrueNtCreateUserProcess);
    if (TrueNtCreateUserProcess == NULL) {
        DebugPrint(L"GetProcAddress(NtCreateUserProcess) failed, return");
        return FALSE;
    }
    
    // MessageBox(NULL, L"Hello from DLL", L"Hi", MB_OK);
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourAttach(&(PVOID&)TrueNtCreateFile, HookedNtCreateFile);
    DetourAttach(&(PVOID&)TrueNtOpenFile, HookedNtOpenFile);
    DetourAttach(&(PVOID&)TrueNtCreateUserProcess, HookedNtCreateUserProcess);

    if (DetourTransactionCommit() != NO_ERROR) {
		DebugPrint(L"DetourTransactionCommit failed, return");
		return FALSE;
	}
    DebugPrint(L"AfterDetourAttach NtCreateFile = %p", TrueNtCreateFile);
    DebugPrint(L"AfterDetourAttach NtOpenFile = %p", TrueNtOpenFile);
    DebugPrint(L"AfterDetourAttach NtCreateUserProcess = %p", TrueNtCreateUserProcess);

    return TRUE;
}

