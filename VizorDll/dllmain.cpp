// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

void InitializeVizor()
{
    // Initialization code for Vizor can be placed here.
    // For example, setting up logging, loading resources, etc.
	MessageBoxA(NULL, "Vizor Initialized", "Info", MB_OK | MB_ICONINFORMATION);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        MessageBoxA(NULL, "Vizor DLL Loaded", "Info", MB_OK | MB_ICONINFORMATION);
		break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

