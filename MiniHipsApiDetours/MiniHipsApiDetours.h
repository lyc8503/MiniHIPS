// The following ifdef block is the standard way of creating macros which make exporting
// from a DLL simpler. All files within this DLL are compiled with the MINIHIPSAPIDETOURS_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see
// MINIHIPSAPIDETOURS_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef MINIHIPSAPIDETOURS_EXPORTS
#define MINIHIPSAPIDETOURS_API __declspec(dllexport)
#else
#define MINIHIPSAPIDETOURS_API __declspec(dllimport)
#endif

// This class is exported from the dll
class MINIHIPSAPIDETOURS_API CMiniHipsApiDetours {
public:
	CMiniHipsApiDetours(void);
	// TODO: add your methods here.
};

extern MINIHIPSAPIDETOURS_API int nMiniHipsApiDetours;

MINIHIPSAPIDETOURS_API int fnMiniHipsApiDetours(void);
