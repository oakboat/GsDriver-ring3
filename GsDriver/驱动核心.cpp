#include "驱动核心.h"

auto VariateInit()->NTSTATUS {

	/*内核发包*/ {

		RtlZeroMemoryEx(&WSKProviderNpi, sizeof(WSKProviderNpi));

		RtlZeroMemoryEx(&WSKSocketsState, sizeof(WSKSocketsState));

		RtlZeroMemoryEx(&WSKRegistration, sizeof(WSKRegistration));

		RtlZeroMemoryEx(&WSKClientDispatch, sizeof(WSKClientDispatch));
	}

	/*键鼠模拟*/ {

		RtlZeroMemoryEx(&MouseDeviceObject, sizeof(MouseDeviceObject));

		RtlZeroMemoryEx(&MouseClassServiceCallback, sizeof(MouseClassServiceCallback));

		RtlZeroMemoryEx(&KeyboardDeviceObject, sizeof(KeyboardDeviceObject));

		RtlZeroMemoryEx(&KeyboardClassServiceCallback, sizeof(KeyboardClassServiceCallback));
	}

	return STATUS_SUCCESS;
}

auto DriverStart()->NTSTATUS {

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	RTL_OSVERSIONINFOEXW WinVersion = { sizeof(RTL_OSVERSIONINFOEXW) };

	Status = RtlGetVersion((PRTL_OSVERSIONINFOW)&WinVersion);

	if (NT_SUCCESS(Status)) {

		DynamicData->WinVersion = WinVersion.dwMajorVersion << 8 | WinVersion.dwMinorVersion << 4 | WinVersion.wServicePackMajor;

		DynamicData->BuildNumber = WinVersion.dwBuildNumber;

		DynamicData->VadRoot = DynamicData->WinVersion <= WINVER_7 ? 0x448 : (DynamicData->WinVersion <= WINVER_8 ? 0x590 : (DynamicData->WinVersion <= WINVER_8X ? 0x5D8 : (DynamicData->BuildNumber <= 10240 ? 0x608 : (DynamicData->BuildNumber <= 10586 ? 0x610 : (DynamicData->BuildNumber <= 14393 ? 0x620 : (DynamicData->BuildNumber <= 17763 ? 0x628 : (DynamicData->BuildNumber <= 18850 ? 0x658 : (DynamicData->BuildNumber <= 18865 ? 0x698 : 0x7D8))))))));

		DynamicData->PrcessId = DynamicData->WinVersion <= WINVER_7 ? 0x180 : (DynamicData->WinVersion <= WINVER_8X ? 0x2E0 : ((DynamicData->WinVersion == WINVER_1X && DynamicData->BuildNumber <= 14393) ? 0x2E8 : ((DynamicData->WinVersion == WINVER_1X && DynamicData->BuildNumber <= 17763) ? 0x2E0 : ((DynamicData->WinVersion == WINVER_1X && DynamicData->BuildNumber <= 18363) ? 0x2E8 : 0x440))));

		DynamicData->Protection = DynamicData->WinVersion <= WINVER_7 ? 0x43C : (DynamicData->WinVersion == WINVER_8 ? 0x648 : (DynamicData->WinVersion == WINVER_8X ? 0x67A : ((DynamicData->WinVersion == WINVER_1X && DynamicData->BuildNumber <= 10586) ? 0x6B2 : ((DynamicData->WinVersion == WINVER_1X && DynamicData->BuildNumber <= 17763) ? 0x6CA : ((DynamicData->WinVersion == WINVER_1X && DynamicData->BuildNumber <= 18363) ? 0x6FA : 0x87A)))));

		DynamicData->PspCidTable = DynamicData->WinVersion <= WINVER_7 ? 0x200 : (DynamicData->WinVersion <= WINVER_8X ? 0x408 : ((DynamicData->WinVersion == WINVER_1X && DynamicData->BuildNumber <= 18363) ? 0x418 : 0x570));

		DynamicData->ProcessLinks = DynamicData->WinVersion <= WINVER_7 ? 0x188 : (DynamicData->WinVersion <= WINVER_8X ? 0x2E8 : ((DynamicData->WinVersion == WINVER_1X && DynamicData->BuildNumber <= 14393) ? 0x2F0 : ((DynamicData->WinVersion == WINVER_1X && DynamicData->BuildNumber <= 17763) ? 0x2E8 : ((DynamicData->WinVersion == WINVER_1X && DynamicData->BuildNumber <= 18363) ? 0x2F0 : 0x448))));

		DynamicData->PrcessIdOffset = DynamicData->WinVersion <= WINVER_7 ? 0x180 : (DynamicData->WinVersion <= WINVER_8X ? 0x2E0 : ((DynamicData->WinVersion == WINVER_1X && DynamicData->BuildNumber <= 14393) ? 0x2E8 : ((DynamicData->WinVersion == WINVER_1X && DynamicData->BuildNumber <= 17763) ? 0x2E0 : ((DynamicData->WinVersion == WINVER_1X && DynamicData->BuildNumber <= 18363) ? 0x2E8 : 0x440))));

		DynamicData->ParentPrcessIdOffset = DynamicData->WinVersion <= WINVER_7 ? 0x290 : (DynamicData->WinVersion <= WINVER_8X ? 0x3E0 : ((DynamicData->WinVersion == WINVER_1X && DynamicData->BuildNumber <= 14393) ? 0x3E0 : ((DynamicData->WinVersion == WINVER_1X && DynamicData->BuildNumber <= 17763) ? 0x3E0 : ((DynamicData->WinVersion == WINVER_1X && DynamicData->BuildNumber <= 18363) ? 0x3E8 : 0x540))));
	}

	if (NT_SUCCESS(Status) && DynamicData != NULL) {

		RtlZeroMemoryEx(&pHideMemoryList, sizeof(pHideMemoryList));

		//RtlZeroMemoryEx(DynamicData->DriverBase, PAGE_SIZE);

		RtlZeroMemoryEx(&InjectCache, sizeof(InjectCache));

		RtlZeroMemoryEx(&InjectData, sizeof(InjectData));

		pHideMemoryList = (PHIDE_MEMORY_BUFFER)(RtlAllocateMemory(sizeof(HIDE_MEMORY_BUFFER)));

		pInjectNotifyHookBuffer = (PHOOK_NOTIFY_BUFFER)(RtlAllocateMemory(sizeof(HIDE_MEMORY_BUFFER)));

		pProcessNotifyHookBuffer = (PHOOK_NOTIFY_BUFFER)(RtlAllocateMemory(sizeof(HOOK_NOTIFY_BUFFER)));

		pRegisterNotifyHookBuffer = (PHOOK_NOTIFY_BUFFER)(RtlAllocateMemory(sizeof(HOOK_NOTIFY_BUFFER)));
	}

	return Status;
}

auto GetPteTable(PBYTE pBuffer[]) -> NTSTATUS {

	NTSTATUS Result = STATUS_SUCCESS;

	if (DynamicData->WinVersion < WINVER_1X) {

		pBuffer[0] = (PBYTE)(0xFFFF'F680'0000'0000);

		pBuffer[1] = (PBYTE)(0xFFFF'F6FB'4000'0000);

		pBuffer[2] = (PBYTE)(0xFFFF'F6FB'7DA0'0000);

		pBuffer[3] = (PBYTE)(0xFFFF'F6FB'7DBE'D000);
	}

	if (DynamicData->WinVersion > WINVER_8X) {

		PHYSICAL_ADDRESS PML4;

		PML4.QuadPart = __readcr3();

		PVOID VirtualAddress = MmGetVirtualForPhysical(PML4);

		if (MmIsAddressValid(VirtualAddress)) {

			PMMPTE PageDirectory = (PMMPTE)(PAGE_ALIGN(VirtualAddress));

			for (SIZE_T Index = 0;; Index++) {

				if (PageDirectory[Index].u.Hard.PageFrameNumber == (UINT64)(PML4.QuadPart >> PAGE_SHIFT)) {

					pBuffer[0] = (PBYTE)((UINT64)(Index << 39) | (UINT64)(0xFFFF'0000'0000'0000));

					pBuffer[1] = (PBYTE)((UINT64)(Index << 30) | (UINT64)(pBuffer[0]));

					pBuffer[2] = (PBYTE)((UINT64)(Index << 21) | (UINT64)(pBuffer[1]));

					pBuffer[3] = (PBYTE)((UINT64)(Index << 12) | (UINT64)(pBuffer[2]));

					Result = STATUS_SUCCESS;

					break;
				}
			}
		}
	}

	return Result;
}

auto SystemStart(PSYSTEM_SERVICE_DESCRIPTOR_TABLE pServiceTableBase) -> NTSTATUS {

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	HANDLE FileHandle = NULL;

	UNICODE_STRING FileName = { NULL };

	IO_STATUS_BLOCK IoStatusBlock = { NULL };

	OBJECT_ATTRIBUTES ObjectAttributes = { NULL };

	if (pServiceTableBase != NULL) {

		RtlInitUnicodeString(&FileName, L"\\SystemRoot\\System32\\ntdll.dll");

		InitializeObjectAttributes(&ObjectAttributes, &FileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

		Status = ZwCreateFile(&FileHandle, GENERIC_READ, &ObjectAttributes, &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

		if (NT_SUCCESS(Status)) {

			FILE_STANDARD_INFORMATION StandardInformation = { NULL };

			Status = ZwQueryInformationFile(FileHandle, &IoStatusBlock, &StandardInformation, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);

			if (NT_SUCCESS(Status) && StandardInformation.EndOfFile.LowPart > PAGE_SIZE) {

				LPBYTE FileData = RtlAllocateMemory(StandardInformation.EndOfFile.LowPart);

				if (FileData != NULL) {

					LARGE_INTEGER ByteOffset = { NULL };

					Status = ZwReadFile(FileHandle, NULL, NULL, NULL, &IoStatusBlock, FileData, StandardInformation.EndOfFile.LowPart, &ByteOffset, NULL);

					if (NT_SUCCESS(Status)) {

						DynamicData->NtCreateThreadEx = GetTableFunByName(pServiceTableBase, FileData, StandardInformation.EndOfFile.LowPart, "NtCreateThreadEx");

						DynamicData->NtProtectVirtualMemory = GetTableFunByName(pServiceTableBase, FileData, StandardInformation.EndOfFile.LowPart, "NtProtectVirtualMemory");
					}

					RtlFreeMemoryEx(FileData);
				}
			}

			ZwClose(FileHandle);
		}
	}

	return Status;
}

auto KernelStart(PKLDR_DATA_TABLE_ENTRY pThisModule) -> NTSTATUS {

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	PVOID NtOpenFile = RtlGetSystemFun(L"NtOpenFile");

	if (NtOpenFile != NULL) {

		ULONG Size = NULL;

		Status = ZwQuerySystemInformation(SystemModuleInformation, NULL, Size, &Size);

		if (!NT_SUCCESS(Status) && Size != NULL) {

			PSYSTEM_MODULE_INFORMATION pMods = (PSYSTEM_MODULE_INFORMATION)(RtlAllocateMemory(Size));

			if (pMods != NULL) {

				Status = ZwQuerySystemInformation(SystemModuleInformation, pMods, Size, &Size);

				if (NT_SUCCESS(Status)) {

					PSYSTEM_MODULE_INFORMATION_ENTRY pMod = pMods->Modules;

					for (ULONG Index = NULL; Index < pMods->NumberOfModules; Index++) {

						if (NtOpenFile >= pMod[Index].ImageBase && NtOpenFile < (LPBYTE)(pMod[Index].ImageBase + pMod[Index].ImageSize)) {

							for (PLIST_ENTRY pListEntry = pThisModule->InLoadOrderLinks.Flink; pListEntry != &pThisModule->InLoadOrderLinks; pListEntry = pListEntry->Flink) {

								PKLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

								if (pMod[Index].ImageBase == pEntry->DllBase && (LPBYTE)pListEntry->Blink >= pEntry->DllBase && (LPBYTE)pListEntry->Blink < (LPBYTE)pEntry->DllBase + pEntry->SizeOfImage) {

									DynamicData->KernelBase = (LPBYTE)(pMod[Index].ImageBase);

									DynamicData->ModuleList = (LPBYTE)(pListEntry->Blink);

									break;
								}
							}
						}
					}
				}

				RtlFreeMemoryEx(pMods);
			}
		}
	}

	return Status;
}

VOID Unload(PDRIVER_OBJECT pDriverObject)
{
	RegisterNotifyInit(FALSE);
	InjectNotifyInit(FALSE);
	ProcessNotifyInit(FALSE);
}

auto DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath) -> NTSTATUS {
	pDriverObject->DriverUnload = Unload;
	DynamicData = (PDYNDATA)(RtlAllocateMemory(sizeof(DYNDATA)));
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	if (NT_SUCCESS(Status = VariateInit())) {

		if (NT_SUCCESS(Status = DriverStart())) {
			if (NT_SUCCESS(Status = KernelStart(((PKLDR_DATA_TABLE_ENTRY)pDriverObject->DriverSection)))) {

				if (NT_SUCCESS(Status = SystemStart((PSYSTEM_SERVICE_DESCRIPTOR_TABLE)(GetServiceTableBase(DynamicData->KernelBase))))) {

					if (NT_SUCCESS(Status = GetPteTable(DynamicData->PageTables))) {
						Status =RegisterNotifyInit(TRUE);
						RtlForceDeleteFile(&((PKLDR_DATA_TABLE_ENTRY)pDriverObject->DriverSection)->FullDllName);
					}
				}
			}
		}
	}
	return Status;
}