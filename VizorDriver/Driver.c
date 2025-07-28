#include "Includes.h"
#include "Helper.h"
#include "Definitions.h"
#include "Vizor.h"

#define LocationOfDll L"\\??\\C:\\RobloxClient\\Vizor\\x64\\Debug\\VizorDll.dll" // Change this to your DLL location
#define TargetProcessName L"Notepad.exe" 
#define MAX_SEARCH_BUFFER_SIZE 0x1000000 // 16 MB cap

#define CommunicationBufferOffset 0x1C1D0 // Offset of the communication buffer in the remote DLL, change this to your actual offset
#define VizorMagicNumber 0x123456 // Magic number to verify the communication buffer

// 7/18/25 - ???     |     Verification of the communication buffer
static NTSTATUS VerifyCommunicationBuffer(PVOID Remotebase)
{
	ULONG_PTR communicationBufferOffset = CommunicationBufferOffset;

	PVOID* communicationBuffer = (PVOID*)((ULONG_PTR)Remotebase + communicationBufferOffset);
	PVOID targetAddress = NULL;
	ULONG magic = 0;

	__try
	{
		targetAddress = *communicationBuffer; // Read the communication buffer address
		if (!targetAddress)
		{
			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor VerifyCommunicationBuffer] Communication buffer is NULL.\n");
			return STATUS_INVALID_PARAMETER;
		}

		magic = (ULONG)*(ULONG64*)targetAddress; // Read the magic value from the communication buffer
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor VerifyCommunicationBuffer] Exception occurred while reading communication buffer.\n");
		return GetExceptionCode();
	}

	if (magic == VizorMagicNumber)
	{
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[Vizor VerifyCommunicationBuffer] Communication buffer verified successfully.\n");
		return STATUS_SUCCESS; // Magic number matches, verification successful
	}
	else
	{
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor VerifyCommunicationBuffer] Communication buffer verification failed. Expected: 0x%08X, Got: 0x%08X\n", VizorMagicNumber, magic);
		return STATUS_UNSUCCESSFUL; // Magic number does not match, verification failed
	}
}

// (Project initial start date) - 6/1/25    |    I am kinda confused so far, but I think the allocation of memory inside a process will be easier.
NTSTATUS FindProcessByName(PEPROCESS* OutProcess)
{
	if (!OutProcess)
	{
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor FindProcessByName] OutProcess pointer is NULL\n");
		return STATUS_INVALID_PARAMETER;
	}

	NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;
	ULONG bufferSize = 0x4000; // 16 KB initial
	PVOID buffer = NULL;
	ULONG_PTR maxPtr = 0;

	while (status == STATUS_INFO_LENGTH_MISMATCH)
	{
		buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, VIZOR_POOL_TAG);
		if (!buffer)
		{
			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor FindProcessByName] Failed to allocate memory size: 0x%lx\n", bufferSize);
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		status = ZwQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, 0);
		if (status == STATUS_INFO_LENGTH_MISMATCH)
		{
			ExFreePoolWithTag(buffer, VIZOR_POOL_TAG);
			buffer = NULL;
			bufferSize *= 2;
		}
		if (bufferSize > MAX_SEARCH_BUFFER_SIZE)
		{
			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor FindProcessByName] Buffer size exceeded maximum limit: 0x%lx\n", MAX_SEARCH_BUFFER_SIZE);
			return STATUS_INSUFFICIENT_RESOURCES;
		}
	}

	PSYSTEM_PROCESS_INFORMATION currProcess = (PSYSTEM_PROCESS_INFORMATION)buffer;
	maxPtr = (ULONG_PTR)buffer + bufferSize;
	__try
	{
		while ((ULONG_PTR)currProcess < maxPtr)
		{
			BOOLEAN validName = FALSE;

			__try
			{
				if (currProcess &&
					currProcess->ImageName.Buffer &&
					currProcess->ImageName.Length > 0 &&
					currProcess->ImageName.Length <= currProcess->ImageName.MaximumLength)
				{
					validName = TRUE;
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor FindProcessByName] Exception reading process name fields\n");
			}

			if (!validName)
			{
				currProcess = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)currProcess + currProcess->NextEntryOffset);
				continue;
			}

			if (_wcsicmp(currProcess->ImageName.Buffer, TargetProcessName) == 0)
			{
				status = PsLookupProcessByProcessId(currProcess->UniqueProcessId, OutProcess);
				if (!NT_SUCCESS(status))
				{
					DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor FindProcessByName] PsLookupProcessByProcessId failed: %08X\n", status);
				}
				else
				{
					DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[Vizor FindProcessByName] Found process: %wZ\n", &currProcess->ImageName);
				}
				ExFreePoolWithTag(buffer, VIZOR_POOL_TAG);
				return status;
			}


			if (currProcess->NextEntryOffset == 0)
			{
				break;
			}

			if ((ULONG_PTR)currProcess + currProcess->NextEntryOffset >= maxPtr)
			{
				DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor FindProcessByName] NextEntryOffset exceeds buffer bounds, breaking\n");
				break;
			}


			currProcess = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)currProcess + currProcess->NextEntryOffset);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor FindProcessByName] Exception occurred during process iteration\n");
		return GetExceptionCode();
	}

	ExFreePoolWithTag(buffer, VIZOR_POOL_TAG);
	return STATUS_NOT_FOUND;
}
// 6/1/25 - 6/4/25     |     Got it working during school, __try is so good for debugging, i love it.
NTSTATUS AllocateMemoryInProcess(PEPROCESS Process, PVOID* OutAddress, PSIZE_T OutSize)
{
	if (!Process || !OutAddress)
	{
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor AllocateMemoryInProcess] Invalid input parameters.\n");
		return STATUS_INVALID_PARAMETER;
	}


	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PVOID allocatedMemory = NULL;
	KAPC_STATE ApcState;
	SIZE_T Size = 0;

	__try
	{
		Size = CalculateTotalAllocationSize(LocationOfDll);
		if (Size == 0)
		{
			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor AllocateMemoryInProcess] CalculateTotalAllocationSize failed\n");
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		Size = (Size + 0xFFF) & ~0xFFF; // align to 0x1000 just in case

		KeStackAttachProcess(Process, &ApcState); // Attach to the target process context

		status = ZwAllocateVirtualMemory(
			ZwCurrentProcess(),
			&allocatedMemory,
			0,
			&Size,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE
		);

		if (NT_SUCCESS(status) && allocatedMemory)
			RtlZeroMemory(allocatedMemory, Size); // Zero the allocated memory
		else
			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor AllocateMemoryInProcess] ZwAllocateVirtualMemory failed: %08X\n", status);
		

		KeUnstackDetachProcess(&ApcState); // Detach from the target process context

		if (!NT_SUCCESS(status) || !allocatedMemory)
		{
			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor AllocateMemoryInProcess] ZwAllocateVirtualMemory failed: %08X\n", status);
			return status;
		}

		*OutAddress = allocatedMemory; // Return the allocated address
		if (OutSize)
			*OutSize = Size; // Return the size of the allocated memory
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[Vizor AllocateMemoryInProcess] Memory allocated at: %p in process %p\n", allocatedMemory, Process);

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor AllocateMemoryInProcess] Exception occurred during memory allocation\n");
		return GetExceptionCode();
	}
	return status;
}
// 6/4/25 - 6/11/25     |     Now is where I got stucka bunch of times, the manually mapping the dll. This is kinda painful but its whatever.
NTSTATUS ManuallyMapDll(PEPROCESS Process, PVOID* Buffer, PUCHAR* DllBuffer, PSIZE_T TotalSize, PSIZE_T DllSize)
{
	if (!Process || !Buffer || !DllBuffer || !TotalSize)
	{
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor ManuallyMapDll] Invalid input parameters.\n");
		return STATUS_INVALID_PARAMETER;
	}

	NTSTATUS status = AllocateMemoryInProcess(Process, Buffer, TotalSize);
	if (!NT_SUCCESS(status) || !*Buffer)
	{
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor ManuallyMapDll] AllocateMemoryInProcess failed: 0x%08X\n", status);
		return status;
	}

	status = LoadDllFromDisk(LocationOfDll, DllBuffer, DllSize);
	if (!NT_SUCCESS(status) || !*DllBuffer || *TotalSize == 0)
	{
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor ManuallyMapDll] LoadDllFromDisk failed: 0x%08X\n", status);
		return status;
	}

	status = CopySectionsToRemote(*DllBuffer, *DllSize, *Buffer, Process);
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor ManuallyMapDll] CopySectionsToRemote failed: 0x%08X\n", status);
		return status;
	}

	status = ApplyRelocations(*DllBuffer, *Buffer, *DllSize, Process);
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor ManuallyMapDll] ApplyRelocations failed: 0x%08X\n", status);
		return status;
	}
	/*
	status = ResolveImports(*DllBuffer, *Buffer, Process);
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor ManuallyMapDll] ResolveImports failed: 0x%08X\n", status);
		return status;
	}
	
	status = WriteVizorTag(*Buffer, Process);
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor ManuallyMapDll] WriteVizorTag failed: 0x%08X\n", status);
		return status;
	}
	*/
	
	return STATUS_SUCCESS;
}
// 6/11/25 - ???     |     Finally got it to map properly after 2 months of work. Now lets see if it'll start :sob:
NTSTATUS RunDll(PEPROCESS Process, PVOID* RemoteBase, PVOID* CommunicationBuffer)
{
	if (!Process || !RemoteBase || !*RemoteBase)
	{
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor RunDll] Invalid input parameters.\n");
		return STATUS_INVALID_PARAMETER;
	}	

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)*RemoteBase;
	if (!dosHeader || dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor RunDll] Invalid DOS header.\n");
		return STATUS_INVALID_IMAGE_FORMAT;
	}

	PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)*RemoteBase + dosHeader->e_lfanew);
	if (!ntHeaders || ntHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor RunDll] Invalid NT headers.\n");
		return STATUS_INVALID_IMAGE_FORMAT;
	}

	ULONG_PTR entryRVA = ntHeaders->OptionalHeader.AddressOfEntryPoint; // FIX

	if (entryRVA == 0)
	{
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor RunDll] Invalid entry point address.\n");
		return STATUS_INVALID_IMAGE_FORMAT;
	}

	PVOID entryPoint = (PUCHAR)*RemoteBase + entryRVA;

	PTHREAD_CONTEXT context = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(THREAD_CONTEXT), VIZOR_POOL_TAG);
	if (!context)
	{
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor RunDll] Failed to allocate memory for thread context.\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	context->TargetProcess = Process;
	context->RemoteBase = *RemoteBase;
	context->EntryPoint = entryPoint;
	context->CommunicationBuffer = CommunicationBuffer;

	// A test for if we managed to inject succesfully;
	// == Inject CommunicationBuffer value into remote DLL's global ==
	ULONG_PTR commBufferOffset = CommunicationBufferOffset; // Replace with actual offset of g_CommBuffer
	PVOID remoteCommVar = (PUCHAR)*RemoteBase + commBufferOffset;

	KAPC_STATE apc;
	KeStackAttachProcess(Process, &apc);
	__try {
		RtlCopyMemory(remoteCommVar, &CommunicationBuffer, sizeof(PVOID));
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[Vizor RunDll] Communication buffer written to remote DLL at %p\n", remoteCommVar);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor RunDll] Exception writing communication buffer.\n");
		KeUnstackDetachProcess(&apc);
		ExFreePoolWithTag(context, VIZOR_POOL_TAG);
		return STATUS_ACCESS_VIOLATION;
	}
	KeUnstackDetachProcess(&apc);
	///////////////////////////////////////////////////////////



	__try
	{
		HANDLE hThread = NULL;
		NTSTATUS status = PsCreateSystemThread(
			&hThread, \
			THREAD_ALL_ACCESS,
			NULL,
			NULL,
			NULL,
			RemoteThreadStub,
			context
		);

		if (!NT_SUCCESS(status) || !hThread)
		{
			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor RunDll] PsCreateSystemThread failed: 0x%08X\n", status);
			ExFreePoolWithTag(context, VIZOR_POOL_TAG);
			return status;
		}
		if (hThread)
		{
			ZwClose(hThread); // Close the thread handle, we don't need it anymore
			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[Vizor RunDll] System thread created successfully.\n");
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor RunDll] Exception occurred during thread creation\n");
		ExFreePoolWithTag(context, VIZOR_POOL_TAG);
		return GetExceptionCode();
	}

	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[Vizor RunDll] DLL mapped and thread created successfully.\n");

	/*
	NTSTATUS status = VerifyCommunicationBuffer(*RemoteBase);
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor RunDll] VerifyCommunicationBuffer failed: 0x%08X\n", status);
		return status;
	}
	*/
	return STATUS_SUCCESS;
}
