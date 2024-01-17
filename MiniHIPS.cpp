// MiniHIPS.cpp : Defines the exported functions for the DLL.
//

#include "pch.h"
#include "framework.h"
#include "MiniHIPS.h"


// This is an example of an exported variable
MINIHIPS_API int nMiniHIPS=0;

// This is an example of an exported function.
MINIHIPS_API int fnMiniHIPS(void)
{
    return 0;
}

// This is the constructor of a class that has been exported.
CMiniHIPS::CMiniHIPS()
{
    return;
}
