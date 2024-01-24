#pragma once

#include <windows.h>
#include <stdio.h>

#ifdef _DEBUG
void DebugPrint(const wchar_t* format, ...);
#else
#define DebugPrint(format, ...) ((void)0)
#endif

int InjectDll(HANDLE hProcess, LPCWSTR lpszDllPath);
