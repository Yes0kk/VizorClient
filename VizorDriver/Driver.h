#pragma once
#include "Includes.h"

#define LocationOfDll L"\\??\\C:\\RobloxClient\\Vizor\\x64\\Debug\\VizorDll.dll" // Dll location
#define TargetProcessName "Notepad.exe" 
#define MAX_SEARCH_BUFFER_SIZE 0x1000000 // 16 MB cap


static NTSTATUS VerifyCommunicationBuffer(PVOID Remotebase);

NTSTATUS FindProcessByName(PEPROCESS* OutProcess);

NTSTATUS AllocateMemoryInProcess(PEPROCESS Process, PVOID* OutAddress, PSIZE_T OutSize);

NTSTATUS ManuallyMapDll(PEPROCESS Process, PVOID* Buffer, PUCHAR* DllBuffer, SIZE_T* TotalSize, SIZE_T* DllSize);

NTSTATUS RunDll(PEPROCESS Process, PVOID* DllBuffer, PVOID* CommunicationBuffer);
