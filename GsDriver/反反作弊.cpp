#include "驱动核心.h"

PHOOK_NOTIFY_BUFFER pLoadNotifyHookBuffer = NULL;

auto Hook_ExAllocatePool(POOL_TYPE PoolType, SIZE_T NumberOfBytes)->LPVOID {

	return (BOOL)(PoolType == PagedPool && NumberOfBytes == 24) ? NULL : ExAllocatePool(PoolType, NumberOfBytes);
}

auto Hook_ExAllocatePoolWithTag(POOL_TYPE PoolType, SIZE_T NumberOfBytes, ULONG Tag)->LPVOID {

	return (BOOL)(PoolType == PagedPool && NumberOfBytes == 24 && Tag == 'EB') ? NULL : ExAllocatePoolWithTag(PoolType, NumberOfBytes, Tag);
}

auto Hook_MmGetSystemRoutineAddress(PUNICODE_STRING RoutineName)->LPVOID {

	LPVOID Relust = MmGetSystemRoutineAddress(RoutineName);

	if (Relust != NULL) {

		if (GetTextHashW(RoutineName->Buffer) == 0x11B390F4) { Relust = (LPVOID)Hook_ExAllocatePool; }

		if (GetTextHashW(RoutineName->Buffer) == 0xE69F8578) { Relust = (LPVOID)Hook_ExAllocatePoolWithTag; }
	}

	return Relust;
}

auto IATHook(PBYTE lpBaseAddress, UINT32 lpcStrImportHask, LPVOID lpFuncAddress)->NTSTATUS {

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	PIMAGE_DOS_HEADER pDosHeaders = (PIMAGE_DOS_HEADER)(lpBaseAddress);

	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(lpBaseAddress + pDosHeaders->e_lfanew);

	IMAGE_DATA_DIRECTORY ImportsDirectory = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(ImportsDirectory.VirtualAddress + lpBaseAddress);

	while (ImportDescriptor->Name != 0) {

		PIMAGE_THUNK_DATA OrigFirstThunk = (PIMAGE_THUNK_DATA)(lpBaseAddress + ImportDescriptor->OriginalFirstThunk);

		PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)(lpBaseAddress + ImportDescriptor->FirstThunk);

		while (OrigFirstThunk->u1.AddressOfData != 0) {

			PIMAGE_IMPORT_BY_NAME FunctionName = (PIMAGE_IMPORT_BY_NAME)(lpBaseAddress + OrigFirstThunk->u1.AddressOfData);

			if (GetTextHashA(FunctionName->Name) == lpcStrImportHask) {

				RtlSuperCopyMemory(&FirstThunk->u1.Function, &lpFuncAddress, sizeof(ULONGLONG));

				Status = STATUS_SUCCESS;

				break;
			}

			++OrigFirstThunk;

			++FirstThunk;
		}

		if (NT_SUCCESS(Status)) {

			break;
		}

		ImportDescriptor++;
	}

	return Status;
}

auto BEDHook(PBYTE lpBaseAddress)->NTSTATUS {

	NTSTATUS Status = STATUS_SUCCESS;

	if (!NT_SUCCESS(IATHook(lpBaseAddress, 0x11B390F4, (LPVOID)Hook_ExAllocatePool))) { Status = STATUS_UNSUCCESSFUL; }

	if (!NT_SUCCESS(IATHook(lpBaseAddress, 0xE69F8578, (LPVOID)Hook_ExAllocatePoolWithTag))) { Status = STATUS_UNSUCCESSFUL; }

	if (!NT_SUCCESS(IATHook(lpBaseAddress, 0xCD8E2B0B, (LPVOID)Hook_MmGetSystemRoutineAddress))) { Status = STATUS_UNSUCCESSFUL; }

	return Status;
}