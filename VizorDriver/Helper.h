#pragma once
#include "Includes.h"

NTSTATUS LoadDllFromDisk(PCWSTR FilePath, PUCHAR* OutBuffer, PSIZE_T OutSize);

NTSTATUS CopySectionsToRemote(PUCHAR DllBuffer, SIZE_T DllSize, PVOID RemoteBase, PEPROCESS Process);

NTSTATUS ApplyRelocations(PUCHAR DllBuffer, PVOID RemoteBase, SIZE_T DllSize, PEPROCESS Process);

NTSTATUS ResolveImports(PUCHAR DllBuffer, PVOID RemoteBase, PEPROCESS Process);

NTSTATUS WriteVizorTag(PVOID RemoteBase, PEPROCESS Process);

NTSTATUS NTAPI RemoteThreadStub(PVOID Context);

SIZE_T CalculateTotalAllocationSize(PCWSTR DllPath);

NTSTATUS DbgTestDll(PEPROCESS Process, PVOID* OutBuffer, PSIZE_T OutSize);

#ifdef DEBUG
VOID DbgTestRelocationPatch(PUCHAR dllBuffer, PVOID remoteBase);
NTSTATUS DbgTestDll(PEPROCESS Process, PVOID* OutBuffer, PSIZE_T OutSize);
#endif // DEBUG

