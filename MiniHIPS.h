// The following ifdef block is the standard way of creating macros which make exporting
// from a DLL simpler. All files within this DLL are compiled with the MINIHIPS_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see
// MINIHIPS_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef MINIHIPS_EXPORTS
#define MINIHIPS_API __declspec(dllexport)
#else
#define MINIHIPS_API __declspec(dllimport)
#endif

// This class is exported from the dll
class MINIHIPS_API CMiniHIPS {
public:
	CMiniHIPS(void);
	// TODO: add your methods here.
};

extern MINIHIPS_API int nMiniHIPS;

MINIHIPS_API int fnMiniHIPS(void);
