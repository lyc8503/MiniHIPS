// MiniHipsApiDetours.cpp : Defines the exported functions for the DLL.
//

#include "pch.h"
#include "framework.h"
#include "MiniHipsApiDetours.h"


// This is an example of an exported variable
MINIHIPSAPIDETOURS_API int nMiniHipsApiDetours=0;

// This is an example of an exported function.
MINIHIPSAPIDETOURS_API int fnMiniHipsApiDetours(void)
{
    return 0;
}

// This is the constructor of a class that has been exported.
CMiniHipsApiDetours::CMiniHipsApiDetours()
{
    return;
}
