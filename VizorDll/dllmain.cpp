#include "pch.h"
#include <Windows.h>

extern "C" __declspec(dllexport) PVOID g_CommBuffer;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        if (g_CommBuffer)
        {
            *((ULONG64*)g_CommBuffer) = 0x123456;
        }
    }
    return TRUE;
}

