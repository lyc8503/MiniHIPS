// The following ifdef block is the standard way of creating macros which make exporting
// from a DLL simpler. All files within this DLL are compiled with the MINIHIPSHELPER_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see
// MINIHIPSHELPER_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef MINIHIPSHELPER_EXPORTS
#define MINIHIPSHELPER_API __declspec(dllexport)
#else
#define MINIHIPSHELPER_API __declspec(dllimport)
#endif

// This class is exported from the dll
class MINIHIPSHELPER_API CMiniHipsHelper {
public:
	CMiniHipsHelper(void);
	// TODO: add your methods here.
};

extern MINIHIPSHELPER_API int nMiniHipsHelper;

MINIHIPSHELPER_API int fnMiniHipsHelper(void);

extern "C" {

MINIHIPSHELPER_API int InjectDllPid(DWORD dwProcessId, LPCWSTR lpszDllPath);

}

