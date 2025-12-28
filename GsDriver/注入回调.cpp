#include "驱动核心.h"

INJECT_DATA InjectData;

INJECT_CACHE InjectCache;

PHOOK_NOTIFY_BUFFER pInjectNotifyHookBuffer = NULL;

auto SetPhysicalPage(UINT64 VirtualAddress, SIZE_T Size, BOOL Write, BOOL Execute)->BOOLEAN {

	UINT64 Begin = (UINT64)(VirtualAddress & (~0xFFF));

	UINT64 End = (UINT64)((VirtualAddress + Size) & (~0xFFF));

	for (UINT64 Local = Begin; Local < End; Local += PAGE_SIZE) {

		PMMPTE PTE = MiGetPteAddress(DynamicData->PageTables[0], Local); {

			if (PTE->u.Hard.Valid == 1) {

				PTE->u.Hard.Write = Write;

				PTE->u.Hard.NoExecute = !Execute;
			}
		}

		PMMPTE PDE = MiGetPdeAddress(DynamicData->PageTables[1], Local); {

			if (PDE->u.Hard.Valid == 1) {

				PDE->u.Hard.Write = Write;

				PDE->u.Hard.NoExecute = !Execute;
			}
		}

		PMMPTE PPE = MiGetPpeAddress(DynamicData->PageTables[2], Local); {

			if (PPE->u.Hard.Valid == 1) {

				PPE->u.Hard.Write = Write;

				PPE->u.Hard.NoExecute = !Execute;
			}
		}

		PMMPTE PXE = MiGetPxeAddress(DynamicData->PageTables[3], Local); {

			if (PXE->u.Hard.Valid == 1) {

				PXE->u.Hard.Write = Write;

				PXE->u.Hard.NoExecute = !Execute;
			}
		}

		__invlpg((PVOID)(Local));
	}

	return STATUS_SUCCESS;
}

auto ShareMemoryEx(LPBYTE MappedSystemVa, SIZE_T Size)->LPBYTE {

	UINT64 Begin = (UINT64)((UINT64)MappedSystemVa & (~0xFFF));

	UINT64 End = (UINT64)(((UINT64)MappedSystemVa + Size) & (~0xFFF));

	for (UINT64 Local = Begin; Local < End; Local += PAGE_SIZE) {

		PMMPTE PTE = MiGetPteAddress(DynamicData->PageTables[0], Local); {

			if (MmIsAddressValid(PTE)) {

				PTE->u.Hard.Valid = 1;

				PTE->u.Hard.Write = 1;

				PTE->u.Hard.Owner = 1;

				PTE->u.Hard.NoExecute = 0;
			}
		}

		PMMPTE PDE = MiGetPdeAddress(DynamicData->PageTables[1], Local); {

			if (MmIsAddressValid(PDE)) {

				PDE->u.Hard.Valid = 1;

				PDE->u.Hard.Write = 1;

				PDE->u.Hard.Owner = 1;

				PDE->u.Hard.NoExecute = 0;
			}
		}

		PMMPTE PPE = MiGetPpeAddress(DynamicData->PageTables[2], Local); {

			if (MmIsAddressValid(PPE)) {

				PPE->u.Hard.Valid = 1;

				PPE->u.Hard.Write = 1;

				PPE->u.Hard.Owner = 1;

				PPE->u.Hard.NoExecute = 0;
			}
		}

		PMMPTE PXE = MiGetPxeAddress(DynamicData->PageTables[3], Local); {

			if (MmIsAddressValid(PXE)) {

				PXE->u.Hard.Valid = 1;

				PXE->u.Hard.Write = 1;

				PXE->u.Hard.Owner = 1;

				PXE->u.Hard.NoExecute = 0;
			}
		}

		__invlpg((PVOID)(Local));
	}

	return MappedSystemVa;
}

auto ValidInjectEx(PUNICODE_STRING pFullImageName, UINT32 InjectNameHash, LPWSTR DelayModule)->BOOLEAN {

	BOOLEAN bResult = NULL;

	UNICODE_STRING SearchImageName;

	RtlInitUnicodeString(&SearchImageName, DelayModule);

	if (NT_SUCCESS(SearchStr(pFullImageName, &SearchImageName, TRUE))) {

		PUNICODE_STRING UnicodeBuffer = NULL;

		if (NT_SUCCESS(ZwGetProcessFullName(NtCurrentProcess(), &UnicodeBuffer)) && UnicodeBuffer != NULL) {

			UNICODE_STRING InjectNamesHash;

			if (NT_SUCCESS(StripPath(UnicodeBuffer, &InjectNamesHash))) {

				if (GetTextHashW(InjectNamesHash.Buffer) == InjectNameHash) {

					bResult = TRUE;
				}
			}

			RtlFreeMemoryEx(UnicodeBuffer);
		}
	}

	return bResult;
}

auto ValidHashName(UINT32 NameHash, PUNICODE_STRING pFullImageName)->BOOLEAN {

	BOOLEAN bResult = FALSE;

	if (pFullImageName != NULL && MmIsAddressValid(pFullImageName->Buffer)) {

		UNICODE_STRING ImageName;

		if (NT_SUCCESS(StripPath(pFullImageName, &ImageName))) {

			if (GetTextHashW(ImageName.Buffer) == NameHash) {

				bResult = TRUE;
			}
		}
	}

	return bResult;
}

auto GetProcFun_x86(PBYTE hModule, LPCTSTR lpProcName)->UINT32 {

	UINT_PTR uiLibraryAddress = (UINT_PTR)hModule;

	ULONG_PTR fpResult = NULL;

	UINT_PTR uiAddressArray = NULL;

	UINT_PTR uiNameArray = NULL;

	UINT_PTR uiNameOrdinals = NULL;

	PIMAGE_NT_HEADERS32 pNtHeaders32 = NULL;

	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;

	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;

	pNtHeaders32 = (PIMAGE_NT_HEADERS32)(uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew);

	pDataDirectory = (PIMAGE_DATA_DIRECTORY)&pNtHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(uiLibraryAddress + pDataDirectory->VirtualAddress);

	uiAddressArray = (uiLibraryAddress + pExportDirectory->AddressOfFunctions);

	uiNameArray = (uiLibraryAddress + pExportDirectory->AddressOfNames);

	uiNameOrdinals = (uiLibraryAddress + pExportDirectory->AddressOfNameOrdinals);

	if ((PtrToUlong(lpProcName) & 0xFFFF0000) == 0x00000000) {

		uiAddressArray += ((IMAGE_ORDINAL(PtrToUlong(lpProcName)) - pExportDirectory->Base) * sizeof(unsigned long));

		fpResult = (ULONG_PTR)(uiLibraryAddress + *(unsigned long*)(uiAddressArray));
	}
	else {

		unsigned long dwCounter = pExportDirectory->NumberOfNames;

		while (dwCounter--) {

			char * cpExportedFunctionName = (char *)(uiLibraryAddress + *(unsigned long*)(uiNameArray));

			if (strcmp(cpExportedFunctionName, lpProcName) == 0) {

				uiAddressArray += (*(unsigned short*)(uiNameOrdinals) * sizeof(unsigned long));

				fpResult = (ULONG_PTR)(uiLibraryAddress + *(unsigned long*)(uiAddressArray));

				break;
			}

			uiNameArray += sizeof(unsigned long);

			uiNameOrdinals += sizeof(unsigned short);
		}
	}

	return (UINT32)fpResult;
}

auto GetProcFun_x64(PBYTE hModule, LPCTSTR lpProcName)->UINT64 {

	UINT_PTR uiLibraryAddress = (UINT_PTR)hModule;

	ULONG_PTR fpResult = NULL;

	UINT_PTR uiAddressArray = NULL;

	UINT_PTR uiNameArray = NULL;

	UINT_PTR uiNameOrdinals = NULL;

	PIMAGE_NT_HEADERS64 pNtHeaders64 = NULL;

	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;

	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;

	pNtHeaders64 = (PIMAGE_NT_HEADERS64)(uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew);

	pDataDirectory = (PIMAGE_DATA_DIRECTORY)&pNtHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(uiLibraryAddress + pDataDirectory->VirtualAddress);

	uiAddressArray = (uiLibraryAddress + pExportDirectory->AddressOfFunctions);

	uiNameArray = (uiLibraryAddress + pExportDirectory->AddressOfNames);

	uiNameOrdinals = (uiLibraryAddress + pExportDirectory->AddressOfNameOrdinals);

	if ((PtrToUlong(lpProcName) & 0xFFFF0000) == 0x00000000) {

		uiAddressArray += ((IMAGE_ORDINAL(PtrToUlong(lpProcName)) - pExportDirectory->Base) * sizeof(unsigned long));

		fpResult = (ULONG_PTR)(uiLibraryAddress + *(unsigned long*)(uiAddressArray));
	}
	else {

		unsigned long dwCounter = pExportDirectory->NumberOfNames;

		while (dwCounter--) {

			char * cpExportedFunctionName = (char *)(uiLibraryAddress + *(unsigned long*)(uiNameArray));

			if (strcmp(cpExportedFunctionName, lpProcName) == 0) {

				uiAddressArray += (*(unsigned short*)(uiNameOrdinals) * sizeof(unsigned long));

				fpResult = (ULONG_PTR)(uiLibraryAddress + *(unsigned long*)(uiAddressArray));

				break;
			}

			uiNameArray += sizeof(unsigned long);

			uiNameOrdinals += sizeof(unsigned short);
		}
	}

	return (UINT64)fpResult;
}

auto GetMapSize_x86(PBYTE pInjectData)->ULONG {

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(pInjectData);

	PIMAGE_NT_HEADERS32 pNtHeaders = (PIMAGE_NT_HEADERS32)(pInjectData + pDosHeader->e_lfanew);

	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)pNtHeaders + sizeof(IMAGE_NT_HEADERS32));

	ULONG nAlign = pNtHeaders->OptionalHeader.SectionAlignment;

	ULONG ImageSize = (ULONG)((ULONG)(pNtHeaders->OptionalHeader.SizeOfHeaders + nAlign - 1) / nAlign * nAlign);

	for (ULONG i = NULL; i < pNtHeaders->FileHeader.NumberOfSections; ++i) {

		ULONG CodeSize = pSectionHeader[i].Misc.VirtualSize;

		ULONG LoadSize = pSectionHeader[i].SizeOfRawData;

		ULONG MaxSize = (ULONG)(LoadSize > CodeSize ? LoadSize : CodeSize);

		ULONG SectionSize = (pSectionHeader[i].VirtualAddress + MaxSize + nAlign - 1) / nAlign * nAlign;

		if (ImageSize < SectionSize) {

			ImageSize = SectionSize;
		}
	}

	return ImageSize;
}

auto GetMapSize_x64(PBYTE pInjectData)->ULONG {

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(pInjectData);

	PIMAGE_NT_HEADERS64 pNtHeaders = (PIMAGE_NT_HEADERS64)(pInjectData + pDosHeader->e_lfanew);

	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)pNtHeaders + sizeof(IMAGE_NT_HEADERS64));

	ULONG nAlign = pNtHeaders->OptionalHeader.SectionAlignment;

	ULONG ImageSize = (ULONG)((ULONG)(pNtHeaders->OptionalHeader.SizeOfHeaders + nAlign - 1) / nAlign * nAlign);

	for (ULONG i = NULL; i < pNtHeaders->FileHeader.NumberOfSections; ++i) {

		ULONG CodeSize = pSectionHeader[i].Misc.VirtualSize;

		ULONG LoadSize = pSectionHeader[i].SizeOfRawData;

		ULONG MaxSize = (ULONG)(LoadSize > CodeSize ? LoadSize : CodeSize);

		ULONG SectionSize = (pSectionHeader[i].VirtualAddress + MaxSize + nAlign - 1) / nAlign * nAlign;

		if (ImageSize < SectionSize) {

			ImageSize = SectionSize;
		}
	}

	return ImageSize;
}

auto AllocMemory_x86(PSIZE_T pDesiredSize, ULONG Protect)->PBYTE {

	PBYTE Result = NULL;

	if (Protect != PAGE_NOACCESS) {

		PBYTE AllocateAddress = DynamicData->WinVersion < WINVER_8X ? NULL : (PBYTE)(0x70000000);

		if (NT_SUCCESS(ZwAllocateVirtualMemory(ZwCurrentProcess(), reinterpret_cast<LPVOID*>(&AllocateAddress), 0, pDesiredSize, MEM_RESERVE | MEM_COMMIT, Protect))) {

			RtlZeroMemoryEx(AllocateAddress, *pDesiredSize);

			Result = AllocateAddress;
		}
	}
	else {

		LARGE_INTEGER LowAddress;

		LARGE_INTEGER HighAddress;

		LowAddress.QuadPart = 0;

		HighAddress.QuadPart = 0xFFFF'FFFF'FFFF'FFFFULL;

		PMDL pMdl = MmAllocatePagesForMdlEx(LowAddress, HighAddress, LowAddress, *pDesiredSize, MmCached, MM_DONT_ZERO_ALLOCATION);

		if (pMdl != NULL) {

			if (MmMapLockedPagesSpecifyCache(pMdl, KernelMode, MmCached, NULL, NULL, NormalPagePriority) == pMdl->MappedSystemVa) {

				if (NT_SUCCESS(MmProtectMdlSystemAddress(pMdl, PAGE_EXECUTE_READWRITE))) {

					PPFN_NUMBER MdlPfnArray = MmGetMdlPfnArray(pMdl);

					if (MdlPfnArray != NULL) {

						SIZE_T PageSize = ADDRESS_AND_SIZE_TO_SPAN_PAGES(MmGetMdlVirtualAddress(pMdl), MmGetMdlByteCount(pMdl));

						for (SIZE_T i = 0; i < PageSize; i++) {

							MdlPfnArray[i] = 0;
						}
					}

					Result = ShareMemoryEx((LPBYTE)(pMdl->MappedSystemVa), *pDesiredSize);

					RtlZeroMemoryEx(pMdl->MappedSystemVa, *pDesiredSize);
				}
			}
		}
	}

	return Result;
}

auto AllocMemory_x64(PSIZE_T pDesiredSize, ULONG Protect)->PBYTE {

	PBYTE Result = NULL;

	if (Protect != PAGE_NOACCESS) {

		PBYTE AllocateAddress = DynamicData->WinVersion < WINVER_8X ? (PBYTE)(0x70000000) : (PBYTE)(0x700000000000);

		if (NT_SUCCESS(ZwAllocateVirtualMemory(ZwCurrentProcess(), reinterpret_cast<LPVOID*>(&AllocateAddress), 0, pDesiredSize, MEM_RESERVE | MEM_COMMIT, Protect))) {

			RtlZeroMemoryEx(AllocateAddress, *pDesiredSize);

			Result = AllocateAddress;
		}
	}
	else {

		LARGE_INTEGER LowAddress;

		LARGE_INTEGER HighAddress;

		LowAddress.QuadPart = 0;

		HighAddress.QuadPart = 0xFFFF'FFFF'FFFF'FFFFULL;

		PMDL pMdl = MmAllocatePagesForMdlEx(LowAddress, HighAddress, LowAddress, *pDesiredSize, MmCached, MM_DONT_ZERO_ALLOCATION);

		if (pMdl != NULL) {

			if (MmMapLockedPagesSpecifyCache(pMdl, KernelMode, MmCached, NULL, NULL, NormalPagePriority) == pMdl->MappedSystemVa) {

				if (NT_SUCCESS(MmProtectMdlSystemAddress(pMdl, PAGE_EXECUTE_READWRITE))) {

					PPFN_NUMBER MdlPfnArray = MmGetMdlPfnArray(pMdl);

					if (MdlPfnArray != NULL) {

						SIZE_T PageSize = ADDRESS_AND_SIZE_TO_SPAN_PAGES(MmGetMdlVirtualAddress(pMdl), MmGetMdlByteCount(pMdl));

						for (SIZE_T i = 0; i < PageSize; i++) {

							MdlPfnArray[i] = 0;
						}
					}

					Result = ShareMemoryEx((LPBYTE)(pMdl->MappedSystemVa), *pDesiredSize);

					RtlZeroMemoryEx(pMdl->MappedSystemVa, *pDesiredSize);
				}
			}
		}
	}

	return Result;
}

auto StartInject_x86(PUNICODE_STRING pFullImageName, HANDLE hProcessId, PIMAGE_INFO pImageInfo)->NTSTATUS {

	NTSTATUS Status = STATUS_SUCCESS;

	if (InjectData.InjectMode <= 0) {

		if (InjectCache.hProcessId != hProcessId) {

			if (ValidInjectEx(pFullImageName, InjectData.InjectHash, L"\\SysWOW64\\ntdll.dll")) {

				SIZE_T ImageSize = (SIZE_T)(GetMapSize_x86(InjectData.InjectData));

				SIZE_T AllocSize = (SIZE_T)(ImageSize + InjectData.InjectSize + sizeof(ShellCodeX86_0) + sizeof(ShellCodeX86_3));

				UINT64 AllocAdds = (UINT64)(AllocMemory_x86(&AllocSize, InjectData.InjectHide <= 1 ? PAGE_EXECUTE_READWRITE : (InjectData.InjectHide == 2 ? PAGE_READWRITE : PAGE_NOACCESS)));

				if (AllocAdds != 0 && NT_SUCCESS(InjectData.InjectHide == 1 ? AddMemoryItem(IoGetCurrentProcess(), AllocAdds, AllocSize) : (InjectData.InjectHide == 2 ? SetPhysicalPage(AllocAdds, AllocSize, TRUE, TRUE) : STATUS_SUCCESS))) {

					InjectCache.AllocCache[0] = reinterpret_cast<LPBYTE>(AllocAdds);

					InjectCache.AllocCache[1] = reinterpret_cast<LPBYTE>(AllocAdds + ImageSize);

					InjectCache.AllocCache[2] = reinterpret_cast<LPBYTE>(AllocAdds + ImageSize + InjectData.InjectSize + sizeof(ShellCodeX86_0));

					XorByte(InjectCache.AllocCache[1], ShellCodeX86_0, sizeof(ShellCodeX86_0));

					XorByte(InjectCache.AllocCache[2], ShellCodeX86_3, sizeof(ShellCodeX86_3));

					*(UINT32*)((UINT64)(InjectCache.AllocCache[1]) + 0x0001) = (UINT32)((UINT64)(InjectCache.AllocCache[1]) + sizeof(ShellCodeX86_0));

					*(UINT32*)((UINT64)(InjectCache.AllocCache[1]) + 0x0006) = (UINT32)((UINT64)(InjectCache.AllocCache[2]) - (UINT64)(InjectCache.AllocCache[1]) - 0x0005 - 0x0005);

					*(UINT32*)((UINT64)(InjectCache.AllocCache[1]) + 0x000D) = (UINT32)(InjectData.InjectSize + sizeof(ShellCodeX86_3));

					*(UINT32*)((UINT64)(InjectCache.AllocCache[1]) + 0x0012) = (UINT32)((UINT64)(InjectCache.AllocCache[1]) + sizeof(ShellCodeX86_0));

					*(UINT32*)((UINT64)(InjectCache.AllocCache[2]) + 0x0338) = (UINT32)((UINT64)(InjectCache.AllocCache[0]));

					RtlCopyMemoryEx(reinterpret_cast<LPBYTE>((UINT64)(InjectCache.AllocCache[1]) + sizeof(ShellCodeX86_0)), InjectData.InjectData, InjectData.InjectSize);

					if (NT_SUCCESS(ZwCreateThreadEx(ZwCurrentProcess(), InjectCache.AllocCache[1]))) {

						RtlZeroMemoryEx(&InjectCache, sizeof(InjectCache));

						RtlCopyMemoryEx(&InjectCache.hProcessId, &hProcessId, sizeof(hProcessId));
					}
				}
			}
		}
	}

	if (InjectData.InjectMode == 1) {

		if (InjectCache.hProcessId != hProcessId) {

			if (ValidInjectEx(pFullImageName, InjectData.InjectHash, L"\\SysWOW64\\ntdll.dll")) {

				SIZE_T ImageSize = (SIZE_T)(GetMapSize_x86(InjectData.InjectData));

				SIZE_T AllocSize = (SIZE_T)(ImageSize + InjectData.InjectSize + sizeof(ShellCodeX86_1) + sizeof(ShellCodeX86_3));

				UINT64 AllocAdds = (UINT64)(AllocMemory_x86(&AllocSize, InjectData.InjectHide <= 1 ? PAGE_EXECUTE_READWRITE : (InjectData.InjectHide == 2 ? PAGE_READWRITE : PAGE_NOACCESS)));

				UINT32 HijackFun = (UINT32)(GetProcFun_x86(reinterpret_cast<LPBYTE>(pImageInfo->ImageBase), "ZwContinue"));

				if (AllocAdds != 0 && HijackFun != 0 && NT_SUCCESS(InjectData.InjectHide == 1 ? AddMemoryItem(IoGetCurrentProcess(), AllocAdds, AllocSize) : (InjectData.InjectHide == 2 ? SetPhysicalPage(AllocAdds, AllocSize, TRUE, TRUE) : STATUS_SUCCESS))) {

					InjectCache.AllocCache[0] = reinterpret_cast<LPBYTE>(AllocAdds);

					InjectCache.AllocCache[1] = reinterpret_cast<LPBYTE>(AllocAdds + ImageSize);

					InjectCache.AllocCache[2] = reinterpret_cast<LPBYTE>(AllocAdds + ImageSize + InjectData.InjectSize + sizeof(ShellCodeX86_1));

					XorByte(InjectCache.AllocCache[1], ShellCodeX86_1, sizeof(ShellCodeX86_1));

					XorByte(InjectCache.AllocCache[2], ShellCodeX86_3, sizeof(ShellCodeX86_3));

					*(UINT32*)((UINT64)(InjectCache.AllocCache[1]) + 0x0003) = (UINT32)(0x0005);

					*(UINT32*)((UINT64)(InjectCache.AllocCache[1]) + 0x0008) = (UINT32)((UINT64)(InjectCache.AllocCache[1]) + 50);

					*(UINT32*)((UINT64)(InjectCache.AllocCache[1]) + 0x000D) = (UINT32)(HijackFun);

					*(UINT32*)((UINT64)(InjectCache.AllocCache[1]) + 0x0014) = (UINT32)((UINT64)(InjectCache.AllocCache[1]) + sizeof(ShellCodeX86_1));

					*(UINT32*)((UINT64)(InjectCache.AllocCache[1]) + 0x0019) = (UINT32)((UINT64)(InjectCache.AllocCache[2]) - (UINT64)(InjectCache.AllocCache[1]) - 0x0018 - 0x0005);

					*(UINT32*)((UINT64)(InjectCache.AllocCache[1]) + 0x0020) = (UINT32)(InjectData.InjectSize + sizeof(ShellCodeX86_3));

					*(UINT32*)((UINT64)(InjectCache.AllocCache[1]) + 0x0025) = (UINT32)((UINT64)(InjectCache.AllocCache[1]) + sizeof(ShellCodeX86_1));

					*(UINT32*)((UINT64)(InjectCache.AllocCache[1]) + 0x002E) = (UINT32)(HijackFun - (UINT32)((UINT64)(InjectCache.AllocCache[1]) + sizeof(ShellCodeX86_1) - 5));

					*(UINT32*)((UINT64)(InjectCache.AllocCache[2]) + 0x0338) = (UINT32)((UINT64)(InjectCache.AllocCache[0]));

					RtlCopyMemoryEx(reinterpret_cast<LPBYTE>((UINT64)(InjectCache.AllocCache[1]) + sizeof(ShellCodeX86_1)), InjectData.InjectData, InjectData.InjectSize);

					struct {
						UINT64 BaseAddress;
						UINT64 RegionSize;
						UINT32 NewProtect;
					} Context;

					Context.BaseAddress = HijackFun;
					
					Context.RegionSize = 5;
					
					Context.NewProtect = PAGE_EXECUTE_READWRITE;

					if (NT_SUCCESS(ZwProtectVirtualMemory(ZwCurrentProcess(), &Context))) {

						BYTE ShellCodeX86_HookJmp[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };

						*(UINT32*)(ShellCodeX86_HookJmp + 0x0001) = (UINT32)((ULONGLONG)(InjectCache.AllocCache[1]) - HijackFun - 5);

						RtlCopyMemoryEx(reinterpret_cast<LPBYTE>((UINT64)(InjectCache.AllocCache[1]) + 50), reinterpret_cast<LPBYTE>(HijackFun), 5);

						RtlCopyMemoryEx(reinterpret_cast<LPBYTE>(HijackFun), ShellCodeX86_HookJmp, sizeof(ShellCodeX86_HookJmp));

						RtlZeroMemoryEx(&InjectCache, sizeof(InjectCache));

						RtlCopyMemoryEx(&InjectCache.hProcessId, &hProcessId, sizeof(hProcessId));
					}
				}
			}
		}
	}

	if (InjectData.InjectMode == 2) {

		if (InjectCache.hProcessId == hProcessId) {

			if (ValidInjectEx(pFullImageName, InjectData.InjectHash, L"\\GameOverlayRenderer.dll")) {

				InjectCache.SteamCache[0] = (PBYTE)(pImageInfo->ImageBase);

				InjectCache.SteamCache[1] = (PBYTE)(pImageInfo->ImageSize);

				InjectCache.SteamCache[2] = (PBYTE)(SearchSignForMemory(InjectCache.SteamCache[0], (DWORD)(pImageInfo->ImageSize), "\x55\x8B\xEC\x83\xEC\x10\x53\x56\x57\x8B\x7D\x08\x57\x8B\x07", "xxxxxxxxxxxxxxx", 15));
			}
			else {

				if (InjectCache.SteamCache[0] && InjectCache.SteamCache[1] && InjectCache.SteamCache[2]) {

					InjectCache.SteamCache[3] = SearchSignForMemory(InjectCache.SteamCache[2], PAGE_SIZE, "\xFF\x15\x00\x00\x00\x00\x8B", "xx????x", 7);
					
					InjectCache.SteamCache[4] = (PBYTE)(*(UINT32*)(InjectCache.SteamCache[3] + 2));

					InjectCache.SteamCache[5] = (PBYTE)(*(UINT32*)(InjectCache.SteamCache[4]));

					if (InjectCache.SteamCache[5] != NULL) {

						*(UINT32*)((UINT64)(InjectCache.AllocCache[1]) + 0x000B) = (UINT32)((UINT64)(InjectCache.SteamCache[4]));

						*(UINT32*)((UINT64)(InjectCache.AllocCache[1]) + 0x0034) = (UINT32)((UINT64)(InjectCache.SteamCache[5]) - (UINT64)(InjectCache.AllocCache[1]) - 0x0033 - 0x0005);

						*(UINT32*)((UINT64)(InjectCache.AllocCache[1]) + 0x0038) = (UINT32)((UINT64)(InjectCache.SteamCache[5]));

						RtlCopyMemoryEx(reinterpret_cast<LPBYTE>(InjectCache.SteamCache[4]), &InjectCache.AllocCache[1], sizeof(InjectCache.AllocCache[1]));

						RtlZeroMemoryEx(&InjectCache, sizeof(InjectCache));
					}
				}
			}
		}

		if (InjectCache.hProcessId != hProcessId) {

			if (ValidInjectEx(pFullImageName, InjectData.InjectHash, L"\\SysWOW64\\ntdll.dll")) {

				SIZE_T ImageSize = (SIZE_T)(GetMapSize_x86(InjectData.InjectData));

				SIZE_T AllocSize = (SIZE_T)(ImageSize + InjectData.InjectSize + sizeof(ShellCodeX86_2) + sizeof(ShellCodeX86_3));

				UINT64 AllocAdds = (UINT64)(AllocMemory_x86(&AllocSize, InjectData.InjectHide <= 1 ? PAGE_EXECUTE_READWRITE : (InjectData.InjectHide == 2 ? PAGE_READWRITE : PAGE_NOACCESS)));

				if (AllocAdds != 0 && NT_SUCCESS(InjectData.InjectHide == 1 ? AddMemoryItem(IoGetCurrentProcess(), AllocAdds, AllocSize) : (InjectData.InjectHide == 2 ? SetPhysicalPage(AllocAdds, AllocSize, TRUE, TRUE) : STATUS_SUCCESS))) {

					InjectCache.AllocCache[0] = reinterpret_cast<LPBYTE>(AllocAdds);

					InjectCache.AllocCache[1] = reinterpret_cast<LPBYTE>(AllocAdds + ImageSize);

					InjectCache.AllocCache[2] = reinterpret_cast<LPBYTE>(AllocAdds + ImageSize + InjectData.InjectSize + sizeof(ShellCodeX86_2));

					XorByte(InjectCache.AllocCache[1], ShellCodeX86_2, sizeof(ShellCodeX86_2));

					XorByte(InjectCache.AllocCache[2], ShellCodeX86_3, sizeof(ShellCodeX86_3));

					*(UINT32*)((UINT64)(InjectCache.AllocCache[1]) + 0x0010) = (UINT32)((UINT64)(InjectCache.AllocCache[1]) + sizeof(ShellCodeX86_2) - 0x0004);

					*(UINT32*)((UINT64)(InjectCache.AllocCache[1]) + 0x0017) = (UINT32)((UINT64)(InjectCache.AllocCache[1]) + sizeof(ShellCodeX86_2));

					*(UINT32*)((UINT64)(InjectCache.AllocCache[1]) + 0x001C) = (UINT32)((UINT64)(InjectCache.AllocCache[2]) - (UINT64)(InjectCache.AllocCache[1]) - 0x001B - 0x0005);

					*(UINT32*)((UINT64)(InjectCache.AllocCache[1]) + 0x0023) = (UINT32)((UINT64)(InjectCache.AllocCache[1]) + sizeof(ShellCodeX86_2) - 0x0004);

					*(UINT32*)((UINT64)(InjectCache.AllocCache[1]) + 0x0028) = (UINT32)(InjectData.InjectSize + sizeof(ShellCodeX86_2));

					*(UINT32*)((UINT64)(InjectCache.AllocCache[2]) + 0x0338) = (UINT32)((UINT64)(InjectCache.AllocCache[0]));

					RtlCopyMemoryEx(reinterpret_cast<LPBYTE>((UINT64)(InjectCache.AllocCache[1]) + sizeof(ShellCodeX86_2)), InjectData.InjectData, InjectData.InjectSize);

					RtlZeroMemoryEx(&InjectCache.SteamCache, sizeof(InjectCache.SteamCache));

					RtlCopyMemoryEx(&InjectCache.hProcessId, &hProcessId, sizeof(hProcessId));
				}
			}
		}
	}

	return Status;
}

auto StartInject_x64(PUNICODE_STRING pFullImageName, HANDLE hProcessId, PIMAGE_INFO pImageInfo)->NTSTATUS {

	NTSTATUS Status = STATUS_SUCCESS;

	if (InjectData.InjectMode <= 0) {

		if (InjectCache.hProcessId != hProcessId) {

			if (ValidInjectEx(pFullImageName, InjectData.InjectHash, L"\\System32\\ntdll.dll")) {

				SIZE_T ImageSize = (SIZE_T)(GetMapSize_x64(InjectData.InjectData));

				SIZE_T AllocSize = (SIZE_T)(ImageSize + InjectData.InjectSize + sizeof(ShellCodeX64_0) + sizeof(ShellCodeX64_3));
	
				UINT64 AllocAdds = (UINT64)(AllocMemory_x64(&AllocSize, InjectData.InjectHide <= 1 ? PAGE_EXECUTE_READWRITE : (InjectData.InjectHide == 2 ? PAGE_READWRITE : PAGE_NOACCESS)));

				if (AllocAdds != 0 && NT_SUCCESS(InjectData.InjectHide == 1 ? AddMemoryItem(IoGetCurrentProcess(), AllocAdds, AllocSize) : (InjectData.InjectHide == 2 ? SetPhysicalPage(AllocAdds, AllocSize, TRUE, TRUE) : STATUS_SUCCESS))) {

					InjectCache.AllocCache[0] = reinterpret_cast<LPBYTE>(AllocAdds);

					InjectCache.AllocCache[1] = reinterpret_cast<LPBYTE>(AllocAdds + ImageSize);

					InjectCache.AllocCache[2] = reinterpret_cast<LPBYTE>(AllocAdds + ImageSize + InjectData.InjectSize + sizeof(ShellCodeX64_0));

					XorByte(InjectCache.AllocCache[1], ShellCodeX64_0, sizeof(ShellCodeX64_0));

					XorByte(InjectCache.AllocCache[2], ShellCodeX64_3, sizeof(ShellCodeX64_3));

					*(UINT64*)((UINT64)(InjectCache.AllocCache[1]) + 0x0006) = (UINT64)((UINT64)(InjectCache.AllocCache[1]) + sizeof(ShellCodeX64_0));

					*(UINT32*)((UINT64)(InjectCache.AllocCache[1]) + 0x000F) = (UINT32)((UINT64)(InjectCache.AllocCache[2]) - (UINT64)(InjectCache.AllocCache[1]) - 0x000E - 0x0005);

					*(UINT64*)((UINT64)(InjectCache.AllocCache[1]) + 0x0015) = (UINT64)((UINT64)(InjectCache.AllocCache[1]) + sizeof(ShellCodeX64_0));

					*(UINT64*)((UINT64)(InjectCache.AllocCache[1]) + 0x0021) = (UINT64)(InjectData.InjectSize + sizeof(ShellCodeX64_0));

					*(UINT64*)((UINT64)(InjectCache.AllocCache[2]) + 0x04FD) = (UINT64)(InjectCache.AllocCache[0]);

					RtlCopyMemoryEx(reinterpret_cast<LPBYTE>((UINT64)(InjectCache.AllocCache[1]) + sizeof(ShellCodeX64_0)), InjectData.InjectData, InjectData.InjectSize);

					if (NT_SUCCESS(ZwCreateThreadEx(ZwCurrentProcess(), InjectCache.AllocCache[1]))) {

						RtlZeroMemoryEx(&InjectCache, sizeof(InjectCache));

						RtlCopyMemoryEx(&InjectCache.hProcessId, &hProcessId, sizeof(hProcessId));
					}
				}
			}
		}
	}

	if (InjectData.InjectMode == 1) {

		if (InjectCache.hProcessId != hProcessId) {

			if (ValidInjectEx(pFullImageName, InjectData.InjectHash, L"\\System32\\ntdll.dll")) {

				SIZE_T ImageSize = (SIZE_T)(GetMapSize_x64(InjectData.InjectData));

				SIZE_T AllocSize = (SIZE_T)(ImageSize + InjectData.InjectSize + sizeof(ShellCodeX64_1) + sizeof(ShellCodeX64_3));

				UINT64 AllocAdds = (UINT64)(AllocMemory_x64(&AllocSize, InjectData.InjectHide <= 1 ? PAGE_EXECUTE_READWRITE : (InjectData.InjectHide == 2 ? PAGE_READWRITE : PAGE_NOACCESS)));

				UINT64 HijackFun = (UINT64)(GetProcFun_x64(reinterpret_cast<LPBYTE>(pImageInfo->ImageBase), "ZwContinue"));

				if (AllocAdds != 0 && HijackFun != 0 && NT_SUCCESS(InjectData.InjectHide == 1 ? AddMemoryItem(IoGetCurrentProcess(), AllocAdds, AllocSize) : (InjectData.InjectHide == 2 ? SetPhysicalPage(AllocAdds, AllocSize, TRUE, TRUE) : STATUS_SUCCESS))) {

					InjectCache.AllocCache[0] = reinterpret_cast<LPBYTE>(AllocAdds);

					InjectCache.AllocCache[1] = reinterpret_cast<LPBYTE>(AllocAdds + ImageSize);

					InjectCache.AllocCache[2] = reinterpret_cast<LPBYTE>(AllocAdds + ImageSize + InjectData.InjectSize + sizeof(ShellCodeX64_1));

					XorByte(InjectCache.AllocCache[1], ShellCodeX64_1, sizeof(ShellCodeX64_1));

					XorByte(InjectCache.AllocCache[2], ShellCodeX64_3, sizeof(ShellCodeX64_3));

					*(UINT64*)((UINT64)(InjectCache.AllocCache[1]) + 0x001E) = (UINT64)(0x000E);

					*(UINT64*)((UINT64)(InjectCache.AllocCache[1]) + 0x0028) = (UINT64)(HijackFun);

					*(UINT64*)((UINT64)(InjectCache.AllocCache[1]) + 0x0032) = (UINT64)((UINT64)(InjectCache.AllocCache[1]) + sizeof(ShellCodeX64_1) - 0x000E);

					*(UINT64*)((UINT64)(InjectCache.AllocCache[1]) + 0x003E) = (UINT64)((UINT64)(InjectCache.AllocCache[1]) + sizeof(ShellCodeX64_1));

					*(UINT32*)((UINT64)(InjectCache.AllocCache[1]) + 0x0047) = (UINT32)((UINT64)(InjectCache.AllocCache[2]) - (UINT64)(InjectCache.AllocCache[1]) - 0x0046 - 0x0005);

					*(UINT64*)((UINT64)(InjectCache.AllocCache[1]) + 0x004D) = (UINT64)((UINT64)(InjectCache.AllocCache[1]) + sizeof(ShellCodeX64_1));

					*(UINT64*)((UINT64)(InjectCache.AllocCache[1]) + 0x0059) = (UINT64)(InjectData.InjectSize + sizeof(ShellCodeX64_1));

					*(UINT64*)((UINT64)(InjectCache.AllocCache[1]) + 0x0085) = (UINT64)(HijackFun);

					*(UINT64*)((UINT64)(InjectCache.AllocCache[2]) + 0x04FD) = (UINT64)(InjectCache.AllocCache[0]);

					RtlCopyMemoryEx(reinterpret_cast<LPBYTE>((UINT64)(InjectCache.AllocCache[1]) + sizeof(ShellCodeX64_1)), InjectData.InjectData, InjectData.InjectSize);

					struct {
						UINT64 BaseAddress;
						UINT64 RegionSize;
						UINT32 NewProtect;
					} Context;

					Context.BaseAddress = HijackFun; 

					Context.RegionSize = 14; 

					Context.NewProtect = PAGE_EXECUTE_READWRITE;

					if (NT_SUCCESS(ZwProtectVirtualMemory(ZwCurrentProcess(), &Context))) {

						BYTE ShellCodeX64_HookJmp[] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

						*(UINT64*)(ShellCodeX64_HookJmp + 0x0006) = (UINT64)(InjectCache.AllocCache[1]);

						RtlCopyMemoryEx(reinterpret_cast<LPBYTE>((UINT64)(InjectCache.AllocCache[1]) + 141), reinterpret_cast<LPBYTE>(HijackFun), 14);

						RtlCopyMemoryEx(reinterpret_cast<LPBYTE>(HijackFun), ShellCodeX64_HookJmp, sizeof(ShellCodeX64_HookJmp));

						RtlZeroMemoryEx(&InjectCache, sizeof(InjectCache));

						RtlCopyMemoryEx(&InjectCache.hProcessId, &hProcessId, sizeof(hProcessId));
					}
				}
			}
		}
	}

	if (InjectData.InjectMode == 2) {

		if (InjectCache.hProcessId == hProcessId) {

			if (ValidInjectEx(pFullImageName, InjectData.InjectHash, L"\\GameOverlayRenderer64.dll")) {

				InjectCache.SteamCache[0] = (PBYTE)(pImageInfo->ImageBase);

				InjectCache.SteamCache[1] = (PBYTE)(pImageInfo->ImageSize);
				
				InjectCache.SteamCache[2] = (PBYTE)(SearchSignForMemory(InjectCache.SteamCache[0], (DWORD)(pImageInfo->ImageSize), "\x48\x89\x6C\x24\x18\x48\x89\x74\x24\x20\x41\x56\x48\x83\xEC\x20\x41\x8B\xE8\x8B\xF2", "xxxxxxxxxxxxxxxxxxxxx", 21));
			}
			else {

				if (InjectCache.SteamCache[0] && InjectCache.SteamCache[1] && InjectCache.SteamCache[2]) {

					InjectCache.SteamCache[3] = SearchSignForMemory(InjectCache.SteamCache[2], PAGE_SIZE, "\xFF\x15\x00\x00\x00\x00\x8B\xF0", "xx????xx", 8);

					InjectCache.SteamCache[4] = (PBYTE)(InjectCache.SteamCache[3] + *(INT*)(InjectCache.SteamCache[3] + 2) + 6);

					InjectCache.SteamCache[5] = *(PBYTE*)(InjectCache.SteamCache[4]);

					if (InjectCache.SteamCache[5] != NULL) {

						*(UINT64*)((UINT64)(InjectCache.AllocCache[1]) + 0x0028) = (UINT64)(InjectCache.SteamCache[4]);

						*(UINT64*)((UINT64)(InjectCache.AllocCache[1]) + 0x0085) = (UINT64)(InjectCache.SteamCache[5]);

						RtlCopyMemoryEx(InjectCache.SteamCache[4], &InjectCache.AllocCache[1], sizeof(InjectCache.AllocCache[1]));

						RtlZeroMemoryEx(&InjectCache, sizeof(InjectCache));
					}
				}
			}
		}

		if (InjectCache.hProcessId != hProcessId) {

			if (ValidInjectEx(pFullImageName, InjectData.InjectHash, L"\\System32\\ntdll.dll")) {

				SIZE_T ImageSize = (SIZE_T)(GetMapSize_x64(InjectData.InjectData));

				SIZE_T AllocSize = (SIZE_T)(ImageSize + InjectData.InjectSize + sizeof(ShellCodeX64_2) + sizeof(ShellCodeX64_3));

				UINT64 AllocAdds = (UINT64)(AllocMemory_x64(&AllocSize, InjectData.InjectHide <= 1 ? PAGE_EXECUTE_READWRITE : (InjectData.InjectHide == 2 ? PAGE_READWRITE : PAGE_NOACCESS)));

				if (AllocAdds != 0 && NT_SUCCESS(InjectData.InjectHide == 1 ? AddMemoryItem(IoGetCurrentProcess(), AllocAdds, AllocSize) : (InjectData.InjectHide == 2 ? SetPhysicalPage(AllocAdds, AllocSize, TRUE, TRUE) : STATUS_SUCCESS))) {

					InjectCache.AllocCache[0] = reinterpret_cast<LPBYTE>(AllocAdds);

					InjectCache.AllocCache[1] = reinterpret_cast<LPBYTE>(AllocAdds + ImageSize);

					InjectCache.AllocCache[2] = reinterpret_cast<LPBYTE>(AllocAdds + ImageSize + InjectData.InjectSize + sizeof(ShellCodeX64_2));

					XorByte(InjectCache.AllocCache[1], ShellCodeX64_2, sizeof(ShellCodeX64_2));

					XorByte(InjectCache.AllocCache[2], ShellCodeX64_3, sizeof(ShellCodeX64_3));

					*(UINT64*)((UINT64)(InjectCache.AllocCache[1]) + 0x0032) = (UINT64)((UINT64)(InjectCache.AllocCache[1]) + sizeof(ShellCodeX64_2) - 0x0008);

					*(UINT64*)((UINT64)(InjectCache.AllocCache[1]) + 0x003E) = (UINT64)((UINT64)(InjectCache.AllocCache[1]) + sizeof(ShellCodeX64_2));

					*(UINT32*)((UINT64)(InjectCache.AllocCache[1]) + 0x0047) = (UINT32)((UINT64)(InjectCache.AllocCache[2]) - (UINT64)(InjectCache.AllocCache[1]) - 0x0046 - 0x0005);

					*(UINT64*)((UINT64)(InjectCache.AllocCache[1]) + 0x004D) = (UINT64)((UINT64)(InjectCache.AllocCache[1]) + sizeof(ShellCodeX64_2));

					*(UINT64*)((UINT64)(InjectCache.AllocCache[1]) + 0x0059) = (UINT64)(InjectData.InjectSize + sizeof(ShellCodeX64_2));

					*(UINT64*)((UINT64)(InjectCache.AllocCache[2]) + 0x04FD) = (UINT64)(InjectCache.AllocCache[0]);

					RtlCopyMemoryEx(reinterpret_cast<LPBYTE>((UINT64)(InjectCache.AllocCache[1]) + sizeof(ShellCodeX64_2)), InjectData.InjectData, InjectData.InjectSize);

					RtlZeroMemoryEx(&InjectCache.SteamCache, sizeof(InjectCache.SteamCache));

					RtlCopyMemoryEx(&InjectCache.hProcessId, &hProcessId, sizeof(hProcessId));
				}
			}
		}
	}

	return Status;
}

auto InjectNotify(PUNICODE_STRING pFullImageName, HANDLE hProcessId, PIMAGE_INFO pImageInfo)->VOID {

	if (pFullImageName != NULL && pImageInfo != NULL) {

		if (pImageInfo->SystemModeImage) {

			if (ValidHashName(0xAB126A52, pFullImageName)) { BEDHook(reinterpret_cast<LPBYTE>(pImageInfo->ImageBase)); }
		}
		else {

			if (InjectData.InjectBits == 32) { StartInject_x86(pFullImageName, hProcessId, pImageInfo); }

			if (InjectData.InjectBits == 64) { StartInject_x64(pFullImageName, hProcessId, pImageInfo); }
		}
	}
}

auto InjectNotifyInit(ULONG Enable)->NTSTATUS {

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	if (pInjectNotifyHookBuffer->Enable != Enable) {

		if (pInjectNotifyHookBuffer->HookPoint == NULL) {

			pInjectNotifyHookBuffer->HookPoint = GetSystemDrvJumpHook(InjectNotify, pInjectNotifyHookBuffer);
		}

		if (pInjectNotifyHookBuffer->HookPoint != NULL) {

			if (Enable == TRUE) {

				RtlSuperCopyMemory(pInjectNotifyHookBuffer->HookPoint, pInjectNotifyHookBuffer->NewBytes, sizeof(pInjectNotifyHookBuffer->NewBytes));

				Status = PsSetLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)(pInjectNotifyHookBuffer->HookPoint));

				if (NT_SUCCESS(Status)) {

					pInjectNotifyHookBuffer->Enable = TRUE;
				}
			}

			if (Enable != TRUE) {

				if (pInjectNotifyHookBuffer->HookPoint != NULL) {

					Status = PsRemoveLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)(pInjectNotifyHookBuffer->HookPoint));

					if (NT_SUCCESS(Status)) {

						RtlSuperCopyMemory(pInjectNotifyHookBuffer->HookPoint, pInjectNotifyHookBuffer->OldBytes, sizeof(pInjectNotifyHookBuffer->OldBytes));

						pInjectNotifyHookBuffer->Enable = FALSE;
					}
				}
			}
		}
	}

	if (pInjectNotifyHookBuffer->Enable == Enable) {

		Status = STATUS_SUCCESS;
	}

	return Status;
}