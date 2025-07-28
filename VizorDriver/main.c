#include "Includes.h"
#include "Helper.h"
#include "Driver.h"
#include "Vizor.h"

// I took a long break, back to it! 7/1/25
// WOOOHOOO I UNLOCKED GLOBALS!! - 6/8/25

static PEPROCESS g_Process = NULL;
static PVOID g_Buffer = NULL;
static PUCHAR g_DllBuffer = NULL;
static SIZE_T g_TotalSize = 0;
static SIZE_T g_DllSize = 0;

static PVOID g_CommunicationBuffer = NULL; // Global communication buffer for Dll
static SIZE_T g_CommunicationSize = 0; // Size of the communication buffer


VOID Unload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    if (g_Process)
    {
        KAPC_STATE ApcState;
        KeStackAttachProcess(g_Process, &ApcState);

        HANDLE hTargetProcess;
        NTSTATUS status = ObOpenObjectByPointer(
            g_Process,
            OBJ_KERNEL_HANDLE,
            NULL,
            PROCESS_ALL_ACCESS,
            *PsProcessType,
            KernelMode,
            &hTargetProcess
        );

        if (NT_SUCCESS(status))
        {
            if (g_Buffer)
            {
                SIZE_T freeSize = g_TotalSize;
                PVOID base = g_Buffer;

                NTSTATUS freeStatus = ZwFreeVirtualMemory(
                    hTargetProcess,
                    &base,
                    &freeSize,
                    MEM_RELEASE
                );

                if (!NT_SUCCESS(freeStatus))
                    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor Unload] Failed to free g_Buffer: 0x%08X\n", freeStatus);
                else
                    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[Vizor Unload] g_Buffer freed.\n");

                g_Buffer = NULL;
                g_TotalSize = 0;

                DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
                    "[Vizor Unload] Freeing memory at: %p | size = %llu\n", base, freeSize);
            }

            if (g_CommunicationBuffer)
            {
                SIZE_T commSize = g_CommunicationSize;
                PVOID base = g_CommunicationBuffer;

                NTSTATUS commFree = ZwFreeVirtualMemory(
                    hTargetProcess,
                    &base,
                    &commSize,
                    MEM_RELEASE
                );

                if (!NT_SUCCESS(commFree))
                    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor Unload] Failed to free g_CommunicationBuffer: 0x%08X\n", commFree);
                else
                    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[Vizor Unload] g_CommunicationBuffer freed.\n");

                g_CommunicationBuffer = NULL;
                g_CommunicationSize = 0;
            }

            ZwClose(hTargetProcess);
        }

        KeUnstackDetachProcess(&ApcState);

        ObDereferenceObject(g_Process);
        g_Process = NULL;
    }

    if (g_DllBuffer)
    {
        ExFreePoolWithTag(g_DllBuffer, VIZOR_POOL_TAG);
        g_DllBuffer = NULL;
        g_DllSize = 0;
    }

    RtlZeroMemory(&VizorTag, sizeof(VIZOR_TAG));
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[Vizor Unload] Driver stopped and memory cleaned.\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) 
{
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = Unload;

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[Vizor Main] Driver Started\n");

	NTSTATUS status = STATUS_SUCCESS;

    __try {
        status = FindProcessByName(&g_Process);
        if (!NT_SUCCESS(status))
        {
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor Main] Failed to find process: %08X\n", status);
            return status;
        }
        /*
        status = AllocateMemoryInProcess(g_Process, &g_Buffer, &g_TotalSize);
        if (!NT_SUCCESS(status))
        {
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor Main] Memory allocation failed: %08X\n", status);
            return status;
        }
        */
        status = ManuallyMapDll(g_Process, &g_Buffer, &g_DllBuffer, &g_TotalSize, &g_DllSize);
        if (!NT_SUCCESS(status))
        {
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor Main] Manual mapping failed: %08X\n", status);
            return status;
        }
        /*
        status = DbgTestDll(g_Process, &g_CommunicationBuffer, &g_CommunicationSize);
        if (!NT_SUCCESS(status)) 
        {
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor Main] Debug test failed: %08X\n", status);
            return status;
        }
        */
		status = RunDll(g_Process, &g_DllBuffer, &g_CommunicationBuffer);
        if (!NT_SUCCESS(status)) 
        {
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor Main] Running DLL failed: %08X\n", status);
            return status;
		}
        
    }
    __except (EXCEPTION_EXECUTE_HANDLER) 
    {
        status = GetExceptionCode();
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor Main] Exception occurred: %08X\n", status);
        return status;
	}
	

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[Vizor Main] Driver Loaded\n");
    return STATUS_SUCCESS;
}
