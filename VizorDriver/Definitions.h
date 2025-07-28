#pragma once
#include "Includes.h"

#define DLL_PROCESS_ATTACH 1


// Safe byte definition for kernel C
typedef unsigned char BYTE;

// Modern Windows SYSTEM_PROCESS_INFORMATION (Windows 10/11+)
typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER Reserved[3];
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    // Structure may be larger on newer Windows, but this is safe for enumeration
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

// Use enum or macro for clarity in API calls
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemProcessInformation = 5
} SYSTEM_INFORMATION_CLASS;

// Include necessary headers for NTSTATUS and other types
typedef NTSTATUS(*ZWCREATETHREADEX)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackReserve,
    SIZE_T StackCommit,
    PVOID AttributeList
    );

// Declare ZwQuerySystemInformation for manual use (not always present in ntifs.h)
NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_     PVOID                    SystemInformation,
    _In_      ULONG                    SystemInformationLength,
    _Out_opt_ PULONG                   ReturnLength
);

// Declare ZwCreateThreadEx for manual use (not always present in ntifs.h)
typedef struct _THREAD_CONTEXT {
    PEPROCESS TargetProcess;
    PVOID RemoteBase;
    PVOID EntryPoint;
    PVOID CommunicationBuffer;
} THREAD_CONTEXT, * PTHREAD_CONTEXT;
