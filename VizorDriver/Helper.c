#include "Definitions.h"
#include "Helper.h"
#include "Vizor.h"
#include "Includes.h"

#define MAX_RELOCS 100000 // Maximum number of relocations to process

// ???-???     |     I forgot to date this function.
static SIZE_T GetImageSizeFromDisk(PCWSTR FilePath) {
	NTSTATUS status;
	HANDLE fileHandle = NULL;
	OBJECT_ATTRIBUTES objectAttributes;
	IO_STATUS_BLOCK ioStatusBlock;
	UNICODE_STRING fileName;
	PVOID buffer = NULL;
	SIZE_T bufferSize = 0x10000; // 64 KB buffer size

	__try
	{
		RtlInitUnicodeString(&fileName, FilePath);
		InitializeObjectAttributes(&objectAttributes, &fileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

		status = ZwCreateFile(
			&fileHandle,
			FILE_GENERIC_READ,
			&objectAttributes,
			&ioStatusBlock,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ,
			FILE_OPEN,
			FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,
			0
		);

		// Verification
		if (!NT_SUCCESS(status))
		{
			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor GetImageSizeFromDisk] Failed to open file: %wZ, Status: 0x%X\n", &fileName, status);
			return 0;
		}

		// Verification
		buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, VIZOR_POOL_TAG);
		if (!buffer)
		{
			ZwClose(fileHandle);
			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor GetImageSizeFromDisk] Failed to allocate memory for buffer\n");
			return 0;
		}

		status = ZwReadFile(
			fileHandle,
			NULL,
			NULL,
			NULL,
			&ioStatusBlock,
			buffer,
			(ULONG)bufferSize,
			NULL,
			NULL
		);
		ZwClose(fileHandle);

		// Verification
		if (!NT_SUCCESS(status))
		{
			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor GetImageSizeFromDisk] Failed to read file: %wZ, Status: 0x%X\n", &fileName, status);
			ExFreePoolWithTag(buffer, VIZOR_POOL_TAG);
			return 0;
		}

		PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)buffer;
		// Verification
		if (dos->e_magic != IMAGE_DOS_SIGNATURE)
		{
			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor GetImageSizeFromDisk] Invalid DOS signature in file: %wZ\n", &fileName);
			ExFreePoolWithTag(buffer, VIZOR_POOL_TAG);
			return 0;
		}

		PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((PUCHAR)buffer + dos->e_lfanew);
		// Verification
		if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
		{
			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor GetImageSizeFromDisk] Invalid NT signature in file: %wZ\n", &fileName);
			ExFreePoolWithTag(buffer, VIZOR_POOL_TAG);
			return 0;
		}

		SIZE_T imageSize = ntHeaders->OptionalHeader.SizeOfImage;

		ExFreePoolWithTag(buffer, VIZOR_POOL_TAG);
		return imageSize;

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		if (buffer)
		{
			ExFreePoolWithTag(buffer, VIZOR_POOL_TAG);
		}
		if (fileHandle)
			ZwClose(fileHandle);
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor GetImageSizeFromDisk] Exception occurred while processing file: %wZ\n", &fileName);
		return 0;
	}
}
// 6/3/25 - 6/4/25     |     I forgot to date this function. [6/11/25 - I'm gonna make this function private so others cant load their own dlls :<]
NTSTATUS LoadDllFromDisk(PCWSTR FilePath, PUCHAR* OutBuffer, PSIZE_T OutSize)
{
	if (!FilePath || !OutBuffer || !OutSize)
	{
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor LoadDllFromDisk] Invalid parameters.\n");
		return STATUS_INVALID_PARAMETER;
	}



	NTSTATUS status;
	HANDLE fileHandle = NULL;
	OBJECT_ATTRIBUTES objectAttributes;
	UNICODE_STRING fileName;
	IO_STATUS_BLOCK ioStatusBlock;
	PVOID buffer = NULL;
	SIZE_T fileSize = 0;

	*OutBuffer = NULL;
	*OutSize = 0;


	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
		"[Vizor LoadDllFromDisk] Starting load: %wZ\n", FilePath);

	__try
	{

		RtlInitUnicodeString(&fileName, FilePath);
		InitializeObjectAttributes(&objectAttributes, &fileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

		status = ZwCreateFile(
			&fileHandle,
			FILE_GENERIC_READ,
			&objectAttributes,
			&ioStatusBlock,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ,
			FILE_OPEN,
			FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,
			0
		);
		// Verification
		if (!NT_SUCCESS(status))
		{
			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor LoadDllFromDisk] Failed to open file: %wZ, Status: 0x%X\n", &fileName, status);
			return status;
		}

		FILE_STANDARD_INFORMATION fileInfo = { 0 };
		status = ZwQueryInformationFile(
			fileHandle,
			&ioStatusBlock,
			&fileInfo,
			sizeof(fileInfo),
			FileStandardInformation
		);
		// Verification
		if (!NT_SUCCESS(status))
		{
			ZwClose(fileHandle);
			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor LoadDllFromDisk] Failed to query file information: %wZ, Status: 0x%X\n", &fileName, status);
			return status;
		}

		fileSize = (SIZE_T)fileInfo.EndOfFile.QuadPart;
		if (fileSize == 0)
		{
			ZwClose(fileHandle);
			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor LoadDllFromDisk] File is empty: %wZ\n", &fileName);
			return STATUS_INVALID_IMAGE_FORMAT;
		}


		buffer = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, fileSize, VIZOR_POOL_TAG);
		// Verification
		if (!buffer)
		{
			ZwClose(fileHandle);
			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor LoadDllFromDisk] Failed to allocate memory for buffer\n");
			return status;
		}

		RtlZeroMemory(buffer, fileSize);

		status = ZwReadFile(
			fileHandle,
			NULL,
			NULL,
			NULL,
			&ioStatusBlock,
			buffer,
			(ULONG)fileSize,
			NULL,
			NULL
		);

		ZwClose(fileHandle);
		// Verification
		if (!NT_SUCCESS(status))
		{
			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor LoadDllFromDisk] Failed to read file: %wZ, Status: 0x%X\n", &fileName, status);
			ExFreePoolWithTag(buffer, VIZOR_POOL_TAG);
			return status;
		}

		*OutBuffer = buffer;
		*OutSize = fileSize;

		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[Vizor LoadDllFromDisk] Successfully loaded DLL from disk: %wZ, Size: %zu bytes\n", &fileName, fileSize);

		return STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		if (buffer)
		{
			ExFreePoolWithTag(buffer, VIZOR_POOL_TAG);
		}
		if (fileHandle)
		{
			ZwClose(fileHandle);
		}
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor LoadDllFromDisk] Exception occurred while processing file: %wZ\n", &fileName);
		return GetExceptionCode();
	}
}
// 6/11/25 - 6/11/25     |     Gonna see if I can get the total size for the allocation so I can unallocate it and allocate it wherever, whenever I want. I feel smarter
SIZE_T CalculateTotalAllocationSize(PCWSTR DllPath)
{
	__try {

		SIZE_T dllSize = GetImageSizeFromDisk(DllPath);
		if (dllSize == 0)
		{
			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor CalculateTotalAllocationSize] Failed to get DLL size from disk.\n");
			return 0; // Return an error if the size could not be determined
		}

		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[Vizor CalculateTotalAllocationSize] DLL Size: %zu bytes | Tag Size: %zu bytes\n", dllSize, sizeof(VizorTag));
		// I dont wanna include the tag for now
		// SIZE_T totalSize = (SIZE_T)(dllSize + sizeof(VizorTag));
		SIZE_T totalSize = dllSize; 

		return (totalSize + 0xFFF) & ~0xFFF; // Return the total size needed for allocation, including the tag size
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor CalculateTotalAllocationSize] Exception occurred while getting DLL size: 0x%X\n", GetExceptionCode());
		return GetExceptionCode(); // Return the exception code if an error occurs
	}
}
// 7/3/25 - 7/7/25     |     Copying sections of the dll. I hate myself :3
NTSTATUS CopySectionsToRemote(PUCHAR DllBuffer, SIZE_T DllSize, PVOID RemoteBase, PEPROCESS Process)
{
	if (!DllBuffer || !RemoteBase || !Process)
	{
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor CopySectionsToRemote] Invalid parameters.\n");
		return STATUS_INVALID_PARAMETER;
	}

	KAPC_STATE apcState;
	KeStackAttachProcess(Process, &apcState);

	NTSTATUS status = STATUS_SUCCESS;

	__try
	{
		PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)DllBuffer;
		if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			status = STATUS_INVALID_IMAGE_FORMAT;
			goto Exit;
		}

		PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)(DllBuffer + dosHeader->e_lfanew);
		if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
		{
			status = STATUS_INVALID_IMAGE_FORMAT;
			goto Exit;
		}

		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
			"[Vizor CopySectionsToRemote] Processing %u sections\n",
			ntHeaders->FileHeader.NumberOfSections);

		PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
		for (ULONG i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++)
		{
			ULONG rawSize = section->SizeOfRawData;
			ULONG rawOffset = section->PointerToRawData;

			// Validate raw offset
			if (rawOffset == 0 || rawOffset > DllSize)
			{
				DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
					"[Vizor CopySectionsToRemote] Section %.*s has invalid PointerToRawData: 0x%X\n",
					IMAGE_SIZEOF_SHORT_NAME, section->Name, rawOffset);
				continue;
			}

			// Validate size doesn't overflow buffer
			if ((SIZE_T)rawOffset + rawSize > DllSize)
			{
				DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
					"[Vizor CopySectionsToRemote] Section %.*s size exceeds buffer: raw=0x%X size=0x%X\n",
					IMAGE_SIZEOF_SHORT_NAME, section->Name, rawOffset, rawSize);
				continue;
			}

			PUCHAR localSource = DllBuffer + rawOffset;
			PUCHAR remoteDestination = (PUCHAR)RemoteBase + section->VirtualAddress;

			ULONGLONG remoteBase = (ULONGLONG)RemoteBase;
			ULONGLONG remoteEnd = remoteBase + ntHeaders->OptionalHeader.SizeOfImage;
			ULONGLONG remoteDest = (ULONGLONG)remoteDestination;

			if (remoteDest < remoteBase || remoteDest + rawSize > remoteEnd)
			{
				DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
					"[Vizor CopySectionsToRemote] Section %.*s would overflow remote image\n",
					IMAGE_SIZEOF_SHORT_NAME, section->Name);
				continue;
			}

			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
				"[Vizor CopySectionsToRemote] Copying section %.*s (0x%X bytes) to %p\n",
				IMAGE_SIZEOF_SHORT_NAME, section->Name, rawSize, remoteDestination);

			__try
			{
				RtlCopyMemory(remoteDestination, localSource, rawSize);

				DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
					"[Vizor CopySectionsToRemote] Successfully copied %.*s\n",
					IMAGE_SIZEOF_SHORT_NAME, section->Name);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
					"[Vizor CopySectionsToRemote] Exception copying %.*s: 0x%X\n",
					IMAGE_SIZEOF_SHORT_NAME, section->Name, GetExceptionCode());
				status = GetExceptionCode();
				goto Exit;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		status = GetExceptionCode();
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"[Vizor CopySectionsToRemote] Exception in main loop: 0x%X\n", status);
	}

Exit:
	KeUnstackDetachProcess(&apcState);
	return status;
}
// 7/3/25 - 7/7/25     |     The actual relocations!
NTSTATUS ApplyRelocations(PUCHAR DllBuffer, PVOID RemoteBase, SIZE_T DllSize, PEPROCESS Process)
{
	UNREFERENCED_PARAMETER(DllSize); // DllSize is not used in this function, but kept for consistency

	if (!DllBuffer || !RemoteBase || !Process)
	{
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor ApplyRelocations] Invalid parameters.\n");
		return STATUS_INVALID_PARAMETER;
	}

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)DllBuffer;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor ApplyRelocations] Invalid DOS header.\n");
		return STATUS_INVALID_IMAGE_FORMAT;
	}

	PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)(DllBuffer + dosHeader->e_lfanew);
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor ApplyRelocations] Invalid NT header.\n");
		return STATUS_INVALID_IMAGE_FORMAT;
	}

	ULONGLONG imageBase = ntHeaders->OptionalHeader.ImageBase;
	ULONGLONG delta = (ULONGLONG)RemoteBase - imageBase;
	if (delta == 0)
	{
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[Vizor ApplyRelocations] No relocation needed.\n");
		return STATUS_SUCCESS;
	}

	ULONG relocRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	ULONG relocSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	SIZE_T ImageSize = ntHeaders->OptionalHeader.SizeOfImage;

	if (!relocRVA || !relocSize || (relocRVA + relocSize > ImageSize))
	{
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor ApplyRelocations] Invalid relocation directory.\n");
		return STATUS_INVALID_IMAGE_FORMAT;
	}

	PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)((PUCHAR)RemoteBase + relocRVA);
	PUCHAR relocEnd = (PUCHAR)RemoteBase + relocRVA + relocSize;

	if (relocEnd > (PUCHAR)RemoteBase + ImageSize)
	{
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"[Vizor ApplyRelocations] Relocation range exceeds image bounds! relocEnd=%p, ImageEnd=%p\n",
			relocEnd, (PUCHAR)RemoteBase + ImageSize);
		return STATUS_INVALID_IMAGE_FORMAT;
	}

	ULONG totalRelocs = 0;
	ULONG patchedCount = 0;

	KAPC_STATE apcState;
	KeStackAttachProcess(Process, &apcState);

	__try
	{
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
			"[Vizor ApplyRelocations] Starting relocation | Base: %p | Delta: 0x%llX | Size: 0x%llX\n",
			RemoteBase, delta, ImageSize);

		while ((PUCHAR)reloc < relocEnd && reloc->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
		{
			// Validate reloc block size
			if ((PUCHAR)reloc + reloc->SizeOfBlock > (PUCHAR)relocEnd)
			{
				DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
					"[Vizor ApplyRelocations] Reloc block exceeds relocation section bounds: VA=0x%X Size=0x%X\n",
					reloc->VirtualAddress, reloc->SizeOfBlock);
				break;
			}

			ULONG count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
			USHORT* relocData = (USHORT*)((PUCHAR)reloc + sizeof(IMAGE_BASE_RELOCATION));
			PUCHAR relocBase = (PUCHAR)RemoteBase + reloc->VirtualAddress;

			for (ULONG i = 0; i < count; i++)
			{
				totalRelocs++;
				if (totalRelocs > MAX_RELOCS)
				{
					DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
						"[Vizor ApplyRelocations] Too many relocations. Stopping.\n");
					break;
				}

				USHORT entry = relocData[i];
				USHORT type = entry >> 12;
				USHORT offset = entry & 0xFFF;

				if (type != IMAGE_REL_BASED_DIR64)
					continue;

				ULONG rva = reloc->VirtualAddress + offset;
				if (rva + sizeof(ULONGLONG) > ImageSize)
				{
					DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
						"[Vizor ApplyRelocations] Out-of-bounds RVA: 0x%X (DllSize: 0x%llX)\n", rva, ImageSize);
					continue;
				}

				PUCHAR patchAddrByte = relocBase + offset;
				ULONGLONG* patchAddr = (ULONGLONG*)patchAddrByte;
				ULONGLONG patchAddrVal = (ULONGLONG)patchAddr;
				ULONGLONG base = (ULONGLONG)RemoteBase;

				if (patchAddrVal < base || patchAddrVal + sizeof(ULONGLONG) > base + ImageSize)
				{
					DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
						"[Vizor ApplyRelocations] PatchAddr out of range: %p | Base: 0x%llX | Size: 0x%llX\n",
						patchAddr, base, ImageSize);
					continue;
				}

				if (!MmIsAddressValid(patchAddr))
				{
					DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
						"[Vizor ApplyRelocations] Invalid address: %p\n", patchAddr);
					continue;
				}

				if ((patchAddrByte + sizeof(ULONGLONG)) > ((PUCHAR)RemoteBase + ImageSize))
				{
					DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
						"[Vizor ApplyRelocations] Patch address calculation out-of-bounds: %p\n", patchAddr);
					continue;
				}

				__try {
					*patchAddr += delta;
					patchedCount++;
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {
					DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
						"[Vizor ApplyRelocations] Exception writing to patch address: %p\n", patchAddr);
				}
			}

			if (totalRelocs > MAX_RELOCS)
			{
				DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
					"[Vizor ApplyRelocations] Too many relocations. Breaking outer loop.\n");
				break;
			}

			reloc = (PIMAGE_BASE_RELOCATION)((PUCHAR)reloc + reloc->SizeOfBlock);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"[Vizor ApplyRelocations] Exception occurred: 0x%X\n", GetExceptionCode());
		KeUnstackDetachProcess(&apcState);
		return GetExceptionCode();
	}

	KeUnstackDetachProcess(&apcState);

	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
		"[Vizor ApplyRelocations] Done. %lu relocations patched.\n", patchedCount);

	return STATUS_SUCCESS;
}
// 7/4/25 - 7/7/25     |     Resolving imports, this is the last step before we can call the entry point.
NTSTATUS ResolveImports(PUCHAR DllBuffer, PVOID RemoteBase, PEPROCESS Process)
{
	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
		"[Vizor ResolveImports] DllBuffer: %p, RemoteBase: %p, Process: %p\n",
		DllBuffer, RemoteBase, Process);
	if (!DllBuffer || !RemoteBase || !Process)
	{
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor ResolveImports] Invalid parameters.\n");
		return STATUS_INVALID_PARAMETER;
	}

	KAPC_STATE apc;
	KeStackAttachProcess(Process, &apc);

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)DllBuffer;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return STATUS_INVALID_IMAGE_FORMAT;

	PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)(DllBuffer + dosHeader->e_lfanew);
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
		return STATUS_INVALID_IMAGE_FORMAT;

	ULONG importRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	if (!importRVA)
	{
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[Vizor ResolveImports] No import table present.\n");
		return STATUS_SUCCESS;
	}

	PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(DllBuffer + importRVA);

	__try
	{
		while (importDesc->Name)
		{
			const CHAR* moduleName = (CHAR*)(DllBuffer + importDesc->Name);
			ANSI_STRING ansiModule;
			UNICODE_STRING unicodeModule;

			RtlInitAnsiString(&ansiModule, moduleName);
			if (!NT_SUCCESS(RtlAnsiStringToUnicodeString(&unicodeModule, &ansiModule, TRUE)))
			{
				++importDesc;
				continue;
			}

			PVOID moduleBase = MmGetSystemRoutineAddress(&unicodeModule);
			RtlFreeUnicodeString(&unicodeModule);

			if (!moduleBase)
			{
				DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
					"[Vizor ResolveImports] Skipping module: %s (not found in kernel exports)\n", moduleName);
				++importDesc;
				continue;
			}

			PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)(DllBuffer + importDesc->OriginalFirstThunk);
			PIMAGE_THUNK_DATA firstThunk = (PIMAGE_THUNK_DATA)((PUCHAR)RemoteBase + importDesc->FirstThunk);

			while (origThunk->u1.AddressOfData)
			{
				if (IMAGE_SNAP_BY_ORDINAL(origThunk->u1.Ordinal))
				{
					++origThunk;
					++firstThunk;
					continue;
				}

				PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(DllBuffer + origThunk->u1.AddressOfData);
				ANSI_STRING funcAnsi;
				UNICODE_STRING funcUnicode;

				RtlInitAnsiString(&funcAnsi, (PCSZ)importByName->Name);
				if (NT_SUCCESS(RtlAnsiStringToUnicodeString(&funcUnicode, &funcAnsi, TRUE)))
				{
					PVOID funcPtr = MmGetSystemRoutineAddress(&funcUnicode);
					RtlFreeUnicodeString(&funcUnicode);

					if (funcPtr)
					{
						firstThunk->u1.Function = (ULONGLONG)funcPtr;

						DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
							"[Vizor ResolveImports] Resolved %s!%s -> %p\n",
							moduleName, importByName->Name, funcPtr);
					}
				}

				++origThunk;
				++firstThunk;
			}

			++importDesc;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KeUnstackDetachProcess(&apc);
		return GetExceptionCode();
	}

	KeUnstackDetachProcess(&apc);
	return STATUS_SUCCESS;
}
// 7/5/25 - ???     |     The tag for our application! Will be usefull for checking for memory leaks and other stuff.
NTSTATUS WriteVizorTag(PVOID RemoteBase, PEPROCESS Process)
{
	UNREFERENCED_PARAMETER(RemoteBase);
	UNREFERENCED_PARAMETER(Process);

	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[Vizor WriteVizorTag] Skipped (stub).\n");
	return STATUS_SUCCESS;
}
// 7/7/25 - ???     |     Some stub for remote thread.
NTSTATUS NTAPI RemoteThreadStub(PVOID Context)
{
	PTHREAD_CONTEXT ctx = (PTHREAD_CONTEXT)Context;
	KAPC_STATE apcState;
	KeStackAttachProcess(ctx->TargetProcess, &apcState); // Attach to target process

	typedef NTSTATUS(NTAPI* DLLMAIN)(PVOID, ULONG, PVOID);
	DLLMAIN DllMain = (DLLMAIN)ctx->EntryPoint;

	__try
	{
		if (DllMain)
			DllMain(ctx->RemoteBase, DLL_PROCESS_ATTACH, NULL); // Call the DLL entry point
		else
		{
			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
				"[Vizor RemoteThreadStub] DllMain is NULL, cannot call entry point.\n");
			return STATUS_INVALID_PARAMETER; // Return error if DllMain is NULL
		}
	} 
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"[Vizor RemoteThreadStub] Exception in remote thread: 0x%X\n", GetExceptionCode());
		return GetExceptionCode(); // Capture the exception code
	}

	KeUnstackDetachProcess(&apcState); // Detach from target process
	ExFreePoolWithTag(ctx, VIZOR_POOL_TAG); // Free the thread context memory
	PsTerminateSystemThread(STATUS_SUCCESS); // Terminate the thread

	return STATUS_SUCCESS; // Return success
}

// 7/7/25 - ???     |     Some testing for the acutal Dll.
NTSTATUS DbgTestDll(PEPROCESS Process, PVOID* OutBuffer, PSIZE_T OutSize)
{
	if (!Process || !OutBuffer || !OutSize) {
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor DbgTestDll] Invalid parameters.\n");
		return STATUS_INVALID_PARAMETER; // Return error if parameters are invalid
	}
	*OutBuffer = NULL;
	*OutSize = 0; // Initialize output parameters

	NTSTATUS status = STATUS_SUCCESS;

	PVOID communicationBuffer = NULL;
	SIZE_T bufferSize = sizeof(ULONG64);

	KAPC_STATE apcState;
	KeStackAttachProcess(Process, &apcState); // Attach to target process

	__try {
		status = ZwAllocateVirtualMemory(
			ZwCurrentProcess(),
			&communicationBuffer,
			0,
			&bufferSize,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_READWRITE
		);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"[Vizor DbgTestDll] Exception in PEPROCESS %p while allocating communication buffer. Code: 0x%X\n",
			Process, GetExceptionCode());
		return GetExceptionCode(); // Capture the exception code
	}

	KeUnstackDetachProcess(&apcState); // Detach from target process

	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
		"[Vizor DbgTestDll] Allocated buffer at %p with size %llu bytes\n",
		communicationBuffer, bufferSize);

	if (!NT_SUCCESS(status) || !communicationBuffer)
	{
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor DbgTestDll] Failed to allocate communication buffer. Status: 0x%X\n", status);
		return status; // Return error if allocation fails
	}

	*OutBuffer = (PUCHAR)communicationBuffer;
	*OutSize = bufferSize;

	return STATUS_SUCCESS; // Stubbed for now, return success
}
// 6/5/25 - 6/8/25     |     TESTING ONLY DO NOT CALL
VOID DbgTestRelocationPatch(PUCHAR DllBuffer, PVOID RemoteBase)
{
	__try
	{

		PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)DllBuffer;
		PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)(DllBuffer + dosHeader->e_lfanew);

		ULONG relocRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
		ULONG relocSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

		if (!relocRVA || !relocSize)
		{
			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor DbgTestRelocationPatch] No relocation directory found.\n");
			return; // No relocations to fix
		}

		PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(DllBuffer + relocRVA);
		ULONG parsed = 0;

		while (parsed < relocSize && reloc->SizeOfBlock)
		{
			ULONG entryCount = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
			USHORT* entries = (USHORT*)(reloc + 1);

			for (ULONG i = 0; i < entryCount; i++)
			{
				USHORT raw = entries[i];
				USHORT type = raw >> 12;
				USHORT offset = raw & 0xFFF;

				if (type == IMAGE_REL_BASED_DIR64)
				{
					ULONG patchRVA = reloc->VirtualAddress + offset;
					PVOID patchVA = (PUCHAR)RemoteBase + patchRVA;
					ULONGLONG patchedValue = *(ULONGLONG*)patchVA;

					DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
						"[Vizor TestReloc] Patched @ RVA 0x%X = VA %p = 0x%llX\n",
						patchRVA, patchVA, patchedValue);

					return; // just test the first one
				}
			}

			parsed += reloc->SizeOfBlock;
			reloc = (PIMAGE_BASE_RELOCATION)((PUCHAR)reloc + reloc->SizeOfBlock);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[Vizor DbgTestRelocationPatch] Exception occurred: 0x%X\n", GetExceptionCode());
		return; // Handle any exceptions that occur
	}
}