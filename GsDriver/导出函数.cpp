#include "驱动核心.h"

auto PsGetProcessImageFileName(PEPROCESS Process)->LPSTR {

	typedef LPSTR(NTAPI *fn_PsGetProcessImageFileName)(PEPROCESS);

	static fn_PsGetProcessImageFileName _PsGetProcessImageFileName = NULL;

	LPSTR Result = NULL;

	if (_PsGetProcessImageFileName == NULL) {

		_PsGetProcessImageFileName = (fn_PsGetProcessImageFileName)(RtlGetSystemFun(L"PsGetProcessImageFileName"));
	}

	if (_PsGetProcessImageFileName != NULL) {

		Result = _PsGetProcessImageFileName(Process);
	}

	return Result;
}

auto PsGetProcessSectionBaseAddress(PEPROCESS Process)->LPVOID {

	typedef LPVOID(NTAPI *fn_PsGetProcessSectionBaseAddress)(PEPROCESS);

	static fn_PsGetProcessSectionBaseAddress _PsGetProcessSectionBaseAddress = NULL;

	LPVOID Result = NULL;

	if (_PsGetProcessSectionBaseAddress == NULL) {

		_PsGetProcessSectionBaseAddress = (fn_PsGetProcessSectionBaseAddress)(RtlGetSystemFun(L"PsGetProcessSectionBaseAddress"));
	}

	if (_PsGetProcessSectionBaseAddress != NULL) {

		Result = _PsGetProcessSectionBaseAddress(Process);
	}

	return Result;
}

auto ZwQuerySystemInformation(ULONG SystemInformationClass, LPVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)->NTSTATUS {

	typedef NTSTATUS(NTAPI *fn_ZwQuerySystemInformation)(ULONG, LPVOID, ULONG, PULONG);

	static fn_ZwQuerySystemInformation _ZwQuerySystemInformation = NULL;

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	if (_ZwQuerySystemInformation == NULL) {

		_ZwQuerySystemInformation = (fn_ZwQuerySystemInformation)(RtlGetSystemFun(L"ZwQuerySystemInformation"));
	}

	if (_ZwQuerySystemInformation != NULL) {

		Status = _ZwQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	}

	return Status;
}

auto ZwQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, LPVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength)->NTSTATUS {

	typedef NTSTATUS(NTAPI *fn_ZwQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, LPVOID, ULONG, PULONG);

	static fn_ZwQueryInformationProcess _ZwQueryInformationProcess = NULL;

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	if (_ZwQueryInformationProcess == NULL) {

		_ZwQueryInformationProcess = (fn_ZwQueryInformationProcess)(RtlGetSystemFun(L"ZwQueryInformationProcess"));
	}

	if (_ZwQueryInformationProcess != NULL) {

		Status = _ZwQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
	}

	return Status;
}

auto ZwSetInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, LPVOID ProcessInformation, ULONG ProcessInformationLength)->NTSTATUS {

	typedef NTSTATUS(NTAPI *fn_ZwSetInformationProcess)(HANDLE, PROCESSINFOCLASS, LPVOID, ULONG);

	static fn_ZwSetInformationProcess _ZwSetInformationProcess = NULL;

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	if (_ZwSetInformationProcess == NULL) {

		_ZwSetInformationProcess = (fn_ZwSetInformationProcess)(RtlGetSystemFun(L"ZwSetInformationProcess"));
	}

	if (_ZwSetInformationProcess != NULL) {

		Status = _ZwSetInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength);
	}

	return Status;
}

auto ZwReferenceObjectByName(PUNICODE_STRING ObjectName, ULONG Attributes, PACCESS_STATE PassedAccessState, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, LPVOID ParseContext, PDRIVER_OBJECT *Object)->NTSTATUS {

	typedef NTSTATUS(NTAPI *fn_ObReferenceObjectByName)(PUNICODE_STRING, ULONG, PACCESS_STATE, ACCESS_MASK, POBJECT_TYPE, KPROCESSOR_MODE, LPVOID, PDRIVER_OBJECT*);

	static fn_ObReferenceObjectByName _ObReferenceObjectByName = NULL;

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	if (_ObReferenceObjectByName == NULL) {

		_ObReferenceObjectByName = (fn_ObReferenceObjectByName)(RtlGetSystemFun(L"ObReferenceObjectByName"));
	}

	if (_ObReferenceObjectByName != NULL) {

		Status = _ObReferenceObjectByName(ObjectName, Attributes, PassedAccessState, DesiredAccess, ObjectType, AccessMode, ParseContext, Object);
	}

	return Status;
}

auto ZwGetProcessIdForHash(UINT32 ProcessNameHash, PHANDLE hProcessId)->NTSTATUS {

	NTSTATUS Result = STATUS_UNSUCCESSFUL;

	ULONG Size = 0;

	if (!NT_SUCCESS(ZwQuerySystemInformation(SystemProcessInformation, NULL, Size, &Size))) {

		PSYSTEM_PROCESS_INFORMATION pBuffer = (PSYSTEM_PROCESS_INFORMATION)(RtlAllocateMemory(Size));

		if (pBuffer != NULL) {

			if (NT_SUCCESS(ZwQuerySystemInformation(SystemProcessInformation, pBuffer, Size, &Size))) {

				for (PSYSTEM_PROCESS_INFORMATION pInfo = (PSYSTEM_PROCESS_INFORMATION)(((PUCHAR)pBuffer) + pBuffer->NextEntryOffset); pInfo->NextEntryOffset; pInfo = (PSYSTEM_PROCESS_INFORMATION)(((PUCHAR)pInfo) + pInfo->NextEntryOffset)) {

					if (GetTextHashW(pInfo->ImageName.Buffer) == ProcessNameHash) {

						*hProcessId = pInfo->hProcessId;

						Result = STATUS_SUCCESS;

						break;
					}
				}
			}

			RtlFreeMemoryEx(pBuffer);
		}
	}

	return Result;
}

auto ZwGetProcessFullName(HANDLE ProcessHandle, PUNICODE_STRING* pNameBuffer)->NTSTATUS {

	NTSTATUS Status = STATUS_SUCCESS;

	ULONG NameBufferLen = 0;

	Status = ZwQueryInformationProcess(ProcessHandle, ProcessImageFileName, NULL, 0, &NameBufferLen);

	if (!NT_SUCCESS(Status) && NameBufferLen != NULL) {

		PUNICODE_STRING pBuffer = (PUNICODE_STRING)(RtlAllocateMemory(NameBufferLen));

		if (pBuffer != NULL) {

			Status = ZwQueryInformationProcess(ProcessHandle, ProcessImageFileName, pBuffer, NameBufferLen, &NameBufferLen);

			if (NT_SUCCESS(Status)) {

				*pNameBuffer = pBuffer;
			}
		}
	}

	return Status;
}

auto ZwCopyVirtualMemory(PEPROCESS FromProcess, LPVOID FromAddress, PEPROCESS ToProcess, LPVOID ToAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode)->NTSTATUS {

	typedef NTSTATUS(NTAPI *fn_MmCopyVirtualMemory)(PEPROCESS, LPVOID, PEPROCESS, LPVOID, SIZE_T, KPROCESSOR_MODE, PSIZE_T);

	static fn_MmCopyVirtualMemory _MmCopyVirtualMemory = NULL;

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	if (_MmCopyVirtualMemory == NULL) {

		_MmCopyVirtualMemory = (fn_MmCopyVirtualMemory)(RtlGetSystemFun(L"MmCopyVirtualMemory"));
	}

	if (_MmCopyVirtualMemory != NULL) {

		SIZE_T NumberOfBytesCopied;

		Status = _MmCopyVirtualMemory(FromProcess, FromAddress, ToProcess, ToAddress, BufferSize, PreviousMode, &NumberOfBytesCopied);
	}

	return Status;
}

auto ZwMmCopyMemory(LPVOID TargetAddress, LPVOID SourceAddress, SIZE_T NumberOfBytes)->NTSTATUS {

	typedef NTSTATUS(NTAPI *fn_MmCopyMemory)(LPVOID, LPVOID, SIZE_T, ULONG, PSIZE_T);

	static fn_MmCopyMemory _MmCopyMemory = NULL;

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	if (_MmCopyMemory == NULL) {

		_MmCopyMemory = (fn_MmCopyMemory)(RtlGetSystemFun(L"MmCopyMemory"));
	}

	if (_MmCopyMemory != NULL) {

		SIZE_T Transferred;

		Status = _MmCopyMemory(TargetAddress, SourceAddress, NumberOfBytes, 2, &Transferred);

		if (NT_SUCCESS(Status)) {

			if (NumberOfBytes != Transferred) {

				Status = STATUS_UNSUCCESSFUL;
			}
		}
	}

	return Status;
}

auto ZwProtectVirtualMemory(HANDLE ProcessHandle, LPVOID pContext)->NTSTATUS {

	typedef NTSTATUS(NTAPI *fn_ZwProtectVirtualMemory)(HANDLE, PULONG64, PULONG64, ULONG, PULONG);

	static fn_ZwProtectVirtualMemory _ZwProtectVirtualMemory = NULL;

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	if (_ZwProtectVirtualMemory == NULL) {

		_ZwProtectVirtualMemory = (fn_ZwProtectVirtualMemory)DynamicData->NtProtectVirtualMemory;
	}

	if (_ZwProtectVirtualMemory != NULL) {

		struct {
			ULONG64 BaseAddress;
			ULONG64 RegionSize;
			ULONG32 NewProtect;
		} Context;

		RtlCopyMemoryEx(&Context, pContext, sizeof(Context));

		ULONG OldProtect;

		KPROCESSOR_MODE OldPreviousMode = SetPreviousMode(KernelMode);

		Status = _ZwProtectVirtualMemory(ProcessHandle, &Context.BaseAddress, &Context.RegionSize, Context.NewProtect, &OldProtect);

		SetPreviousMode(OldPreviousMode);
	}

	return Status;
}

auto ZwProtectWindow(HWND hWnd, UINT Flags)->BOOL {

	typedef BOOL(__fastcall *fn_GreProtectSpriteContent)(LPVOID, HWND, INT, UINT);

	static fn_GreProtectSpriteContent _GreProtectSpriteContent = NULL;

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	if (_GreProtectSpriteContent == NULL) {

		_GreProtectSpriteContent = (fn_GreProtectSpriteContent)(ResolveRelativeAddress(SearchSignForImage(GetModuleBaseForHash(DynamicData->WinVersion <= WINVER_7 ? 0x546E0672 : 0x3F5BCB23), DynamicData->WinVersion <= WINVER_7 ? "\xE8\xCC\xCC\xCC\xCC\x8B\xF8\x85\xC0\x75\x26" : "\xE8\xCC\xCC\xCC\xCC\x8B\xF8\x85\xC0\x75\x0E", "x????xxxxxx", 11), 1));
	}

	if (_GreProtectSpriteContent != NULL) {

		Status = _GreProtectSpriteContent(NULL, hWnd, TRUE, Flags) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
	}

	return Status;
}

auto ZwCreateThreadEx(HANDLE ProcessHandle, LPVOID StratAddress, LPVOID lpParameter)->NTSTATUS {

	typedef NTSTATUS(NTAPI *fn_ZwCreateThreadEx)(PHANDLE, ACCESS_MASK, LPVOID, HANDLE, LPVOID, LPVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, LPVOID);

	static fn_ZwCreateThreadEx _ZwCreateThreadEx = NULL;

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	if (_ZwCreateThreadEx == NULL) {

		_ZwCreateThreadEx = (fn_ZwCreateThreadEx)DynamicData->NtCreateThreadEx;
	}

	if (_ZwCreateThreadEx != NULL) {

		HANDLE hThread = NULL;

		OBJECT_ATTRIBUTES Object = { 0 };

		InitializeObjectAttributes(&Object, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

		CHAR pOldMode = SetPreviousMode(KernelMode);

		Status = _ZwCreateThreadEx(&hThread, THREAD_ALL_ACCESS, &Object, ProcessHandle, StratAddress, lpParameter, DynamicData->WinVersion <= WINVER_7 ? 0 : 2, 0, 0, 0, NULL);

		if (NT_SUCCESS(Status)) {

			ObCloseHandle(hThread, KernelMode);
		}

		SetPreviousMode(pOldMode);
	}

	return Status;
}

auto ZwQueryKeyValue(LPCWSTR KeyPath, LPCWSTR ValueName, PKEY_VALUE_PARTIAL_INFORMATION* pKeyValueInfo)->NTSTATUS {

	NTSTATUS Result = STATUS_UNSUCCESSFUL;

	OBJECT_ATTRIBUTES ObjAttrs = { NULL };

	UNICODE_STRING usKeyName = { NULL };

	RtlInitUnicodeString(&usKeyName, KeyPath);

	InitializeObjectAttributes(&ObjAttrs, &usKeyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	HANDLE KeyHandle = NULL;

	Result = ZwOpenKey(&KeyHandle, KEY_ALL_ACCESS, &ObjAttrs);

	if (NT_SUCCESS(Result)) {

		RtlInitUnicodeString(&usKeyName, ValueName);

		InitializeObjectAttributes(&ObjAttrs, &usKeyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

		ULONG ulSize = NULL;

		Result = ZwQueryValueKey(KeyHandle, &usKeyName, KeyValuePartialInformation, NULL, 0, &ulSize);

		if (!NT_SUCCESS(Result) && ulSize) {

			PKEY_VALUE_PARTIAL_INFORMATION pBuffer = (PKEY_VALUE_PARTIAL_INFORMATION)(RtlAllocateMemory(ulSize));

			if (pBuffer != NULL) {

				Result = ZwQueryValueKey(KeyHandle, &usKeyName, KeyValuePartialInformation, pBuffer, ulSize, &ulSize);

				if (NT_SUCCESS(Result)) {

					*pKeyValueInfo = pBuffer;
				}
			}
		}

		ObCloseHandle(KeyHandle, KernelMode);
	}

	return Result;
}

auto ZwEnumDeviceObj(PDRIVER_OBJECT pDriverObject, PDEVICE_OBJECT** pRetBuffer, PULONG pRetLen)->NTSTATUS {

	NTSTATUS Result = STATUS_UNSUCCESSFUL;

	ULONG DeviceObjLength = NULL;

	Result = IoEnumerateDeviceObjectList(pDriverObject, NULL, DeviceObjLength, &DeviceObjLength);

	if (Result == STATUS_BUFFER_TOO_SMALL && DeviceObjLength != NULL) {

		ULONG DeviceObjListSize = DeviceObjLength * sizeof(PDEVICE_OBJECT);

		PDEVICE_OBJECT* pBuffer = (PDEVICE_OBJECT*)(RtlAllocateMemory(DeviceObjListSize));

		if (pBuffer != NULL) {

			Result = IoEnumerateDeviceObjectList(pDriverObject, pBuffer, DeviceObjListSize, &DeviceObjLength);

			if (NT_SUCCESS(Result)) {

				*pRetBuffer = pBuffer;

				*pRetLen = DeviceObjLength;
			}
		}
	}

	return Result;
}

auto ZwQueryNameStr(LPVOID Object, POBJECT_NAME_INFORMATION* pObjNameInfo, PULONG pRetLen)->NTSTATUS {

	NTSTATUS Result = STATUS_UNSUCCESSFUL;

	ULONG ObjNameInfoLen = NULL;

	Result = ObQueryNameString(Object, NULL, NULL, &ObjNameInfoLen);

	if (!NT_SUCCESS(Result)) {

		POBJECT_NAME_INFORMATION pBuffer = (POBJECT_NAME_INFORMATION)(RtlAllocateMemory(ObjNameInfoLen));

		if (pBuffer != NULL) {

			Result = ObQueryNameString(Object, pBuffer, ObjNameInfoLen, &ObjNameInfoLen);

			if (NT_SUCCESS(Result)) {

				*pObjNameInfo = pBuffer;

				*pRetLen = ObjNameInfoLen;
			}
		}
	}

	return Result;
}

auto ZwQueryFileEx(LPCWSTR FilePath)->NTSTATUS {

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	IO_STATUS_BLOCK IoStatus = { NULL };

	OBJECT_ATTRIBUTES FileAttrib = { NULL };

	FILE_NETWORK_OPEN_INFORMATION FileInfo = { NULL };

	UNICODE_STRING usFileName = { NULL };

	RtlInitUnicodeString(&usFileName, FilePath);

	InitializeObjectAttributes(&FileAttrib, &usFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);

	if (IoFastQueryNetworkAttributes(&FileAttrib, DELETE, 0, &IoStatus, &FileInfo)) {

		if (NT_SUCCESS(IoStatus.Status) && IoStatus.Information != FILE_DOES_NOT_EXIST) {

			Status = STATUS_SUCCESS;
		}
	}

	return Status;
}

auto ZwDeleteFileEx(LPCWSTR FilePath)->NTSTATUS {

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	HANDLE hFile = NULL;

	UNICODE_STRING FileName = { NULL };

	IO_STATUS_BLOCK IoStatus = { NULL };

	OBJECT_ATTRIBUTES FileAttrib = { NULL };

	RtlInitUnicodeString(&FileName, FilePath);

	InitializeObjectAttributes(&FileAttrib, &FileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);

	Status = IoCreateFileEx(&hFile, SYNCHRONIZE | DELETE, &FileAttrib, &IoStatus, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0, CreateFileTypeNone, NULL, IO_NO_PARAMETER_CHECKING, NULL);

	if (NT_SUCCESS(Status)) {

		PFILE_OBJECT FileObject;

		Status = ObReferenceObjectByHandleWithTag(hFile, SYNCHRONIZE | DELETE, *IoFileObjectType, KernelMode, 'tlfD', (LPVOID*)(&FileObject), NULL);

		if (NT_SUCCESS(Status)) {

			FileObject->SectionObjectPointer->ImageSectionObject = NULL;

			MmFlushImageSection(FileObject->SectionObjectPointer, MmFlushForDelete);

			Status = ZwDeleteFile(&FileAttrib);

			ObfDereferenceObject(FileObject);

			ObCloseHandle(hFile, KernelMode);
		}
	}

	return Status;
}

auto ZwReadFileEx(LPCWSTR FilePath, LPVOID pBuffer, ULONG BufferSize)->NTSTATUS {

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	HANDLE hFile = NULL;

	OBJECT_ATTRIBUTES ObjectAttributes = { NULL };

	IO_STATUS_BLOCK IoStatusBlock = { NULL };

	UNICODE_STRING usFileName = { NULL };

	RtlInitUnicodeString(&usFileName, FilePath);

	InitializeObjectAttributes(&ObjectAttributes, &usFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	Status = ZwCreateFile(&hFile, GENERIC_READ, &ObjectAttributes, &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

	if (NT_SUCCESS(Status)) {

		LARGE_INTEGER ByteOffset = { NULL };

		Status = ZwReadFile(hFile, NULL, NULL, NULL, &IoStatusBlock, pBuffer, BufferSize, &ByteOffset, NULL);

		if (NT_SUCCESS(Status)) {

			ZwClose(hFile);

			ZwDeleteFile(&ObjectAttributes);
		}
	}

	return Status;
}

auto ZwWriteFileEx(LPCWSTR FilePath, LPVOID pBuffer, ULONG BufferSize)->NTSTATUS {

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	HANDLE hFile = NULL;

	OBJECT_ATTRIBUTES ObjectAttributes = { NULL };

	IO_STATUS_BLOCK IoStatusBlock = { NULL };

	UNICODE_STRING usFileName = { NULL };

	RtlInitUnicodeString(&usFileName, FilePath);

	InitializeObjectAttributes(&ObjectAttributes, &usFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	Status = ZwCreateFile(&hFile, GENERIC_ALL, &ObjectAttributes, &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

	if (NT_SUCCESS(Status)) {

		LARGE_INTEGER liFileOff = { NULL };

		Status = ZwWriteFile(hFile, NULL, NULL, NULL, &IoStatusBlock, pBuffer, BufferSize, &liFileOff, NULL);

		ZwClose(hFile);
	}

	return Status;
}

auto ZwKillProcess(LPCWSTR ProcessName)->NTSTATUS {

	NTSTATUS Result = STATUS_UNSUCCESSFUL;

	ULONG Size = NULL;

	Result = ZwQuerySystemInformation(SystemProcessInformation, NULL, Size, &Size);

	if (!NT_SUCCESS(Result) && Size != NULL) {

		PSYSTEM_PROCESS_INFORMATION pBuffer = (PSYSTEM_PROCESS_INFORMATION)(RtlAllocateMemory(Size));

		if (pBuffer != NULL) {

			Result = ZwQuerySystemInformation(SystemProcessInformation, pBuffer, Size, &Size);

			if (NT_SUCCESS(Result)) {

				for (PSYSTEM_PROCESS_INFORMATION pInfo = (PSYSTEM_PROCESS_INFORMATION)(((PUCHAR)pBuffer) + pBuffer->NextEntryOffset); pInfo->NextEntryOffset; pInfo = (PSYSTEM_PROCESS_INFORMATION)(((PUCHAR)pInfo) + pInfo->NextEntryOffset)) {

					if (pInfo->ImageName.Buffer && !_wcsicmp(pInfo->ImageName.Buffer, ProcessName)) {

						HANDLE hProcess = NULL;

						CLIENT_ID ClientId = { NULL };

						OBJECT_ATTRIBUTES Object = { NULL };

						Object.Length = sizeof(Object);

						ClientId.UniqueProcess = pInfo->hProcessId;

						Result = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &Object, &ClientId);

						if (NT_SUCCESS(Result)) {

							Result = ZwTerminateProcess(hProcess, STATUS_SUCCESS);

							ZwClose(hProcess);
						}
					}
				}
			}

			RtlFreeMemoryEx(pBuffer);
		}
	}

	return Result;
}

auto ZwProtectProcess(PEPROCESS Process, BOOLEAN Enable)->NTSTATUS {

	NTSTATUS Result = STATUS_UNSUCCESSFUL;

	if (DynamicData->Protection != 0) {

		if (DynamicData->WinVersion <= WINVER_7) {

			if (Enable != TRUE) { *(PULONG)((ULONG64)Process + DynamicData->Protection) &= ~(1 << 0xB); }

			if (Enable == TRUE) { *(PULONG)((ULONG64)Process + DynamicData->Protection) |= 1 << 0xB; }

			Result = STATUS_SUCCESS;
		}

		if (DynamicData->WinVersion == WINVER_8) {

			if (Enable != TRUE) { _InterlockedExchange8((PCHAR)((ULONG64)Process + DynamicData->Protection), 1); }

			if (Enable == TRUE) { _InterlockedExchange8((PCHAR)((ULONG64)Process + DynamicData->Protection), 0); }

			Result = STATUS_SUCCESS;
		}

		if (DynamicData->WinVersion >= WINVER_8X) {

			LPVOID hSystem = NULL;

			LPVOID pSystem = NULL;

			if (NT_SUCCESS(ZwGetProcessIdForHash(Enable == TRUE ? 0x3977A6E2 : 0xD9F7D13D, &hSystem))) {

				Result = PsLookupProcessByProcessId(hSystem, (PEPROCESS*)&pSystem);

				if (NT_SUCCESS(Result)) {

					_InterlockedExchange((PLONG)((ULONG64)Process + DynamicData->Protection), *(LONG*)((ULONG64)pSystem + DynamicData->Protection));

					_InterlockedExchange((PLONG)((ULONG64)Process + DynamicData->ParentPrcessIdOffset), *(LONG*)((ULONG64)pSystem + DynamicData->ParentPrcessIdOffset));

					ObfDereferenceObject(pSystem);
				}
			}
		}
	}

	return Result;
}

auto RtlImageNtHeader(LPBYTE ImageBase)->LPVOID {

	typedef LPVOID(NTAPI *fn_RtlImageNtHeader)(LPBYTE);

	static fn_RtlImageNtHeader _RtlImageNtHeader = NULL;

	LPVOID Result = NULL;

	if (_RtlImageNtHeader == NULL) {

		_RtlImageNtHeader = (fn_RtlImageNtHeader)(RtlGetSystemFun(L"RtlImageNtHeader"));
	}

	if (_RtlImageNtHeader != NULL) {

		Result = _RtlImageNtHeader(ImageBase);
	}

	return Result;
}

auto RtlImageDirectoryEntryToData(LPBYTE ImageBase, BOOLEAN MappedAsImage, USHORT DirectoryEntry, PULONG Size)->LPVOID {

	typedef LPVOID(NTAPI *fn_RtlImageDirectoryEntryToData)(LPBYTE, BOOLEAN, USHORT, PULONG);

	static fn_RtlImageDirectoryEntryToData _RtlImageDirectoryEntryToData = NULL;

	LPVOID Result = NULL;

	if (_RtlImageDirectoryEntryToData == NULL) {

		_RtlImageDirectoryEntryToData = (fn_RtlImageDirectoryEntryToData)(RtlGetSystemFun(L"RtlImageDirectoryEntryToData"));
	}

	if (_RtlImageDirectoryEntryToData != NULL) {

		Result = _RtlImageDirectoryEntryToData(ImageBase, MappedAsImage, DirectoryEntry, Size);
	}

	return Result;
}

auto RtlForceDeleteFile(PUNICODE_STRING pFilePath)->NTSTATUS {

	NTSTATUS Status = STATUS_SUCCESS;

	HANDLE hFile = NULL;

	LPBYTE pFileObject = NULL;

	IO_STATUS_BLOCK IoStatusBlock;

	OBJECT_ATTRIBUTES ObjectAttributes;

	InitializeObjectAttributes(&ObjectAttributes, pFilePath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, 0, 0);

	Status = IoCreateFileEx(&hFile, SYNCHRONIZE | DELETE, &ObjectAttributes, &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0, CreateFileTypeNone, NULL, IO_NO_PARAMETER_CHECKING, NULL);

	if (NT_SUCCESS(Status)) {

		Status = ObReferenceObjectByHandleWithTag(hFile, SYNCHRONIZE | DELETE, *IoFileObjectType, KernelMode, 'ELIF', (LPVOID*)&pFileObject, NULL);

		if (NT_SUCCESS(Status)) {

			((PFILE_OBJECT)pFileObject)->SectionObjectPointer->ImageSectionObject = NULL;

			if (MmFlushImageSection(((PFILE_OBJECT)pFileObject)->SectionObjectPointer, MmFlushForDelete)) {

				Status = ZwDeleteFile(&ObjectAttributes);
			}

			ObfDereferenceObject(pFileObject);
		}

		ObCloseHandle(hFile, KernelMode);
	}

	return Status;
}

auto RtlSuperCopyMemory(LPVOID pDst, LPVOID pSrc, ULONG Length)->NTSTATUS {

	NTSTATUS Result = STATUS_UNSUCCESSFUL;

	PMDL pMdl = IoAllocateMdl(pDst, Length, FALSE, FALSE, NULL);

	if (pMdl != NULL) {

		MmBuildMdlForNonPagedPool(pMdl);

		pMdl->MdlFlags |= MDL_MAPPED_TO_SYSTEM_VA;

		LPVOID pMapped = MmMapLockedPagesSpecifyCache(pMdl, KernelMode, MmNonCached, NULL, NULL, LowPagePriority);

		if (pMapped != NULL) {

			KIRQL kirql = KeRaiseIrqlToDpcLevel();

			RtlCopyMemory(pMapped, pSrc, Length);

			KeLowerIrql(kirql);

			MmUnmapLockedPages(pMapped, pMdl);

			Result = STATUS_SUCCESS;
		}

		IoFreeMdl(pMdl);
	}

	return Result;
}

auto RtlAllocateMemory(SIZE_T Size)->LPBYTE {

	LPBYTE Result = (LPBYTE)(ExAllocatePoolWithTag(NonPagedPool, Size, 'SG'));

	if (Result != NULL) {

		RtlZeroMemoryEx(Result, Size);
	}

	return Result;
}

auto RtlFreeMemoryEx(LPVOID pDst)->VOID {

	if (pDst != NULL) {

		ExFreePoolWithTag(pDst, 'SG');

		pDst = NULL;
	}
}

auto RtlFillMemoryEx(LPBYTE pDst, BYTE Value, SIZE_T Size)->VOID {

	for (SIZE_T i = NULL; i < Size; i++) {

		((BYTE*)pDst)[i] = Value;
	}
}

auto RtlZeroMemoryEx(PVOID pDst, SIZE_T Size)->VOID {

	for (SIZE_T i = 0; i < Size; i++) {

		((BYTE*)pDst)[i] = (BYTE)0;
	}
}

auto RtlCopyMemoryEx(PVOID pDst, PVOID pSrc, SIZE_T Size)->VOID {

	for (SIZE_T i = 0; i < Size; i++) {

		((BYTE*)pDst)[i] = ((BYTE*)pSrc)[i];
	}
}

auto RtlRandMemoryEx(PVOID pDst, SIZE_T Size)->VOID {

	for (SIZE_T i = 0; i < Size; i++) {

		ULONG Speed = (ULONG)(123456 * i);

		((BYTE*)pDst)[i] = (BYTE)(RtlRandomEx(&Speed) % 255);
	}
}

auto RtlAllocatePool(SIZE_T Size)->LPBYTE {

	LPBYTE Result = NULL;

	LARGE_INTEGER LowAddress;

	LARGE_INTEGER HighAddress;

	LowAddress.QuadPart = NULL;

	HighAddress.QuadPart = 0xFFFF'FFFF'FFFF'FFFFULL;

	PMDL pMdl = MmAllocatePagesForMdlEx(LowAddress, HighAddress, LowAddress, Size, MmCached, MM_DONT_ZERO_ALLOCATION);

	if (pMdl != NULL) {

		Result = (LPBYTE)(MmMapLockedPagesSpecifyCache(pMdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority));

		if (Result != NULL) {

			if (NT_SUCCESS(MmProtectMdlSystemAddress(pMdl, PAGE_EXECUTE_READWRITE))) {

				PPFN_NUMBER MdlPfnArray = MmGetMdlPfnArray(pMdl);

				if (MdlPfnArray != NULL) {

					SIZE_T PageSize = ADDRESS_AND_SIZE_TO_SPAN_PAGES(MmGetMdlVirtualAddress(pMdl), MmGetMdlByteCount(pMdl));

					for (SIZE_T i = NULL; i < PageSize; i++) {

						MdlPfnArray[i] = NULL;
					}
				}
			}
		}
	}

	return Result;
}

auto RtlGetSystemFun(LPWSTR Name)->LPBYTE {

	UNICODE_STRING RoutineName;

	RtlInitUnicodeString(&RoutineName, Name);

	return (LPBYTE)(MmGetSystemRoutineAddress(&RoutineName));
}

auto SetPreviousMode(BYTE Mode)->BYTE {

	return _InterlockedExchange8((PCHAR)((UINT64)(PsGetCurrentThread()) + (UINT64)(DynamicData->WinVersion <= WINVER_7 ? 0x1F6 : 0x232)), Mode);
}

auto GetTextHashA(PCSTR Str)->UINT32 {

	UINT32 Hash = NULL;

	while (Str != NULL && *Str) {

		Hash = (UINT32)(65599 * (Hash + (*Str++) + (*Str > 64 && *Str < 91 ? 32 : 0)));
	}

	return Hash;
}

auto GetTextHashW(PCWSTR Str)->UINT {

	UINT32 Hash = NULL;

	while (Str != NULL && *Str) {

		Hash = (UINT32)(65599 * (Hash + (*Str++) + (*Str > 64 && *Str < 91 ? 32 : 0)));
	}

	return Hash;
}

auto StripPath(PUNICODE_STRING FilePath, PUNICODE_STRING FileName)->NTSTATUS {

	INT32 Result = STATUS_UNSUCCESSFUL;

	for (USHORT i = (FilePath->Length / sizeof(WCHAR)) - 1; i != 0; i--) {

		if (FilePath->Buffer[i] == L'\\' || FilePath->Buffer[i] == L'/') {

			FileName->Buffer = &FilePath->Buffer[i + 1];

			FileName->Length = FileName->MaximumLength = FilePath->Length - (i + 1) * sizeof(WCHAR);

			Result = STATUS_SUCCESS;

			break;
		}
	}

	return Result;
}

auto SearchStr(PUNICODE_STRING Dst, PUNICODE_STRING Src, BOOLEAN CaseInSensitive)->NTSTATUS {

	INT32 Result = STATUS_UNSUCCESSFUL;

	if (Dst->Length >= Src->Length) {

		USHORT Diff = Dst->Length - Src->Length;

		for (USHORT i = 0; i <= (Diff / sizeof(WCHAR)); i++) {

			if (RtlCompareUnicodeStrings(Dst->Buffer + i, Src->Length / sizeof(WCHAR), Src->Buffer, Src->Length / sizeof(WCHAR), CaseInSensitive) == 0) {

				Result = STATUS_SUCCESS;

				break;
			}
		}
	}

	return Result;
}

auto XorByte(LPBYTE Dst, LPBYTE Src, SIZE_T Size)->LPBYTE {

	for (ULONG i = NULL; i < Size; i++) {

		Dst[i] = (BOOLEAN)(Src[i] != 0x00 && Src[i] != 0xFF) ? Src[i] ^ 0xFF : Src[i];
	}

	return Dst;
}

auto Decrypt(LPBYTE Dst, LPBYTE Src, SIZE_T Size, LPBYTE Decryption)->LPBYTE {

	BCRYPT_KEY_HANDLE BcryptKeyHandle = NULL;

	BCRYPT_ALG_HANDLE BcryptAlgHandle = NULL;

	if (NT_SUCCESS(BCryptOpenAlgorithmProvider(&BcryptAlgHandle, BCRYPT_AES_ALGORITHM, MS_PRIMITIVE_PROVIDER, BCRYPT_PROV_DISPATCH))) {

		if (NT_SUCCESS(BCryptSetProperty(BcryptAlgHandle, BCRYPT_CHAINING_MODE, (LPBYTE)(BCRYPT_CHAIN_MODE_ECB), sizeof(BCRYPT_CHAIN_MODE_ECB), 0))) {

			if (NT_SUCCESS(BCryptGenerateSymmetricKey(BcryptAlgHandle, &BcryptKeyHandle, NULL, 0, Decryption, 16, 0))) {

				ULONG pResult = NULL;

				BCryptDecrypt(BcryptKeyHandle, (LPBYTE)(Src), (ULONG)(Size), NULL, NULL, 0, (LPBYTE)(Dst), (ULONG)(Size), &pResult, BCRYPT_PAD_PKCS1);

				BCryptDestroyKey(BcryptKeyHandle);

				XorByte(Dst, Dst, Size);
			}
		}

		BCryptCloseAlgorithmProvider(BcryptAlgHandle, 0);
	}

	return Dst;
}

auto Compare(LPBYTE pAddress, PCHAR Pattern, PCHAR Mask, DWORD MaskLen)->BOOL {

	for (SIZE_T i = 0; i < MaskLen; i++) {

		if (Mask[i] == 'x' && pAddress[i] != (BYTE)(Pattern[i])) {

			return FALSE;
		}
	}

	return TRUE;
}

auto SearchHookForImage(LPBYTE ImageBase, PCHAR Pattern, PCHAR Mask, DWORD MaskLen)->LPBYTE {

	LPBYTE Result = NULL;

	if (ImageBase != NULL) {

		PIMAGE_NT_HEADERS Headers = (PIMAGE_NT_HEADERS)(ImageBase + ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew);;

		PIMAGE_SECTION_HEADER Sections = IMAGE_FIRST_SECTION(Headers);

		for (DWORD Index = 0; Index < Headers->FileHeader.NumberOfSections; ++Index) {

			PIMAGE_SECTION_HEADER pSection = &Sections[Index];

			if ((pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE) && RtlEqualMemory(pSection->Name, ".text", 5)) {

				Result = SearchSignForMemory(ImageBase + pSection->VirtualAddress, pSection->Misc.VirtualSize, Pattern, Mask, MaskLen);

				if (Result != NULL) {

					break;
				}
			}
		}
	}

	return Result;
}

auto SearchSignForImage(LPBYTE ImageBase, PCHAR Pattern, PCHAR Mask, DWORD MaskLen)->LPBYTE {

	LPBYTE Result = NULL;

	if (ImageBase != NULL) {

		PIMAGE_NT_HEADERS Headers = (PIMAGE_NT_HEADERS)(ImageBase + ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew);;

		PIMAGE_SECTION_HEADER Sections = IMAGE_FIRST_SECTION(Headers);

		for (DWORD Index = NULL; Index < Headers->FileHeader.NumberOfSections; ++Index) {

			PIMAGE_SECTION_HEADER pSection = &Sections[Index];

			if (RtlEqualMemory(pSection->Name, ".text", 5)) {

				Result = SearchSignForMemory(ImageBase + pSection->VirtualAddress, pSection->Misc.VirtualSize, Pattern, Mask, MaskLen);
				
				if (Result != NULL) {

					break;
				}
			}
		}
	}

	return Result;
}

auto SearchSignForMemory(LPBYTE MemoryBase, DWORD Length, PCHAR Pattern, PCHAR Mask, DWORD MaskLen)->LPBYTE {

	for (DWORD Index = NULL; Index < (DWORD)(Length - MaskLen); Index++) {

		LPBYTE pTempAddress = &MemoryBase[Index];

		if (Compare(pTempAddress, Pattern, Mask, MaskLen)) {

			return pTempAddress;
		}
	}

	return NULL;
}

auto ResolveRelativeAddress(LPBYTE pAddress, ULONG Index)->LPBYTE {

	LPBYTE Result = NULL;

	if (pAddress != NULL) {

		Result = (LPBYTE)(pAddress + *(INT*)(pAddress + Index) + Index + 4);
	}

	return Result;
}

auto GetSystemDrvJumpHook(PVOID Notify, PHOOK_NOTIFY_BUFFER NotifyBuffer)->LPBYTE {

	LPBYTE pJumpDrvBase = NULL;

	for (PLIST_ENTRY pListEntry = ((PLIST_ENTRY)(DynamicData->ModuleList))->Flink; pListEntry != (PLIST_ENTRY)(DynamicData->ModuleList) && !pJumpDrvBase; pListEntry = pListEntry->Flink) {

		PKLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		static UINT32 SystemModuleHash[] = { 0x19C74195/*tcpipreg.sys*/, 0x480CCDFA/*null.sys*/, 0xAF41C973/*beep.sys*/, 0xBC69A139/*http.sys*/, 0x71254340/*hidusb.sys*/, 0x7AB2FACC/*hidclass.sys*/, 0x5255C6CB/*kbdhid.sys*/, 0x848A4E96/*kbdclass.sys*/, 0x25A4DD11/*mouhid.sys*/, 0x9826A1DC/*mouclass.sys*/ };

		for (ULONG i = 0; i < ARRAYSIZE(SystemModuleHash); i++) {

			if (pEntry->BaseDllName.Buffer && GetTextHashW(pEntry->BaseDllName.Buffer) == SystemModuleHash[i]) {

				pJumpDrvBase = SearchHookForImage(pEntry->DllBase, "\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC", "xxxxxxxxxxxxx", 13);

				if (pJumpDrvBase != NULL) {

					unsigned char JmpCode[] = {
						0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
						0x90,
						0xFF, 0xE0
					};

					RtlCopyMemoryEx(&JmpCode[2], &Notify, sizeof(Notify));

					RtlCopyMemoryEx(&NotifyBuffer->NewBytes, JmpCode, sizeof(NotifyBuffer->NewBytes));

					pEntry->Flags |= 0x20;

					break;
				}
			}
		}
	}

	return pJumpDrvBase;
}

auto GetModuleBaseForHash(UINT32 ModuleHash)->LPBYTE {

	LPBYTE Result = NULL;

	if (ModuleHash == 0xFF2A308D) {

		Result = DynamicData->KernelBase;
	}
	else {

		ULONG Size = NULL;

		if (ZwQuerySystemInformation(SystemModuleInformation, NULL, Size, &Size) == STATUS_INFO_LENGTH_MISMATCH) {

			PSYSTEM_MODULE_INFORMATION pMods = (PSYSTEM_MODULE_INFORMATION)(RtlAllocateMemory(Size));

			if (pMods != NULL) {

				if (NT_SUCCESS(ZwQuerySystemInformation(SystemModuleInformation, pMods, Size, &Size))) {

					for (ULONG Index = NULL; Index < pMods->NumberOfModules; Index++) {

						if (GetTextHashA(pMods->Modules[Index].ImageName) == ModuleHash) {

							Result = pMods->Modules[Index].ImageBase;

							break;
						}
					}
				}

				RtlFreeMemoryEx(pMods);
			}
		}
	}

	return Result;
}

auto GetSystemModuleSection(LPVOID ModuleBase)->LPVOID {

	LPVOID pEntry = NULL;

	if (ModuleBase != NULL) {

		for (PLIST_ENTRY pListEntry = ((PLIST_ENTRY)(DynamicData->ModuleList))->Flink; pListEntry != (PLIST_ENTRY)(DynamicData->ModuleList); pListEntry = pListEntry->Flink) {

			PKLDR_DATA_TABLE_ENTRY pTemp = CONTAINING_RECORD(pListEntry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

			if (pTemp->DllBase == ModuleBase) {

				pEntry = pTemp;
			}
		}
	}

	return pEntry;
}

auto RvaToOffset(PIMAGE_NT_HEADERS64 ImageHead, ULONG RVA, ULONG FileSize) -> ULONG {

	ULONG Result = NULL;

	PIMAGE_SECTION_HEADER ImageSection = IMAGE_FIRST_SECTION(ImageHead);

	USHORT NumberOfSections = ImageHead->FileHeader.NumberOfSections;

	for (USHORT i = NULL; i < NumberOfSections; i++) {

		if (ImageSection->VirtualAddress <= RVA && (ImageSection->VirtualAddress + ImageSection->Misc.VirtualSize) > RVA) {

			RVA -= ImageSection->VirtualAddress;

			RVA += ImageSection->PointerToRawData;

			Result = RVA < FileSize ? RVA : 0;

			break;
		}
		else
			ImageSection++;
	}

	return Result;
}

auto GetExportOffset(LPBYTE FileData, ULONG FileSize, LPCSTR ExportName) -> ULONG {

	ULONG Result = NULL;

	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)FileData;

	PIMAGE_NT_HEADERS64 NtHeaders = (PIMAGE_NT_HEADERS64)(FileData + DosHeader->e_lfanew);

	PIMAGE_DATA_DIRECTORY ImageDataDirectory = NtHeaders->OptionalHeader.DataDirectory;

	ULONG ExportDirectoryRva = ImageDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	ULONG ExportDirectorySize = ImageDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	ULONG ExportDirectoryOffset = RvaToOffset(NtHeaders, ExportDirectoryRva, FileSize);

	if (ExportDirectoryOffset != NULL) {

		PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(FileData + ExportDirectoryOffset);

		ULONG NumberOfNames = ExportDirectory->NumberOfNames;

		ULONG AddressOfFunctionsOffset = RvaToOffset(NtHeaders, ExportDirectory->AddressOfFunctions, FileSize);

		if (AddressOfFunctionsOffset != NULL) {

			ULONG AddressOfNameOrdinalsOffset = RvaToOffset(NtHeaders, ExportDirectory->AddressOfNameOrdinals, FileSize);

			if (AddressOfNameOrdinalsOffset != NULL) {

				ULONG AddressOfNamesOffset = RvaToOffset(NtHeaders, ExportDirectory->AddressOfNames, FileSize);

				if (AddressOfNamesOffset != NULL) {

					PULONG AddressOfNames = (PULONG)(FileData + AddressOfNamesOffset);

					PULONG AddressOfFunctions = (PULONG)(FileData + AddressOfFunctionsOffset);

					PUSHORT AddressOfNameOrdinals = (PUSHORT)(FileData + AddressOfNameOrdinalsOffset);

					for (ULONG i = NULL; i < NumberOfNames; i++) {

						ULONG CurrentNameOffset = RvaToOffset(NtHeaders, AddressOfNames[i], FileSize);

						if (CurrentNameOffset != NULL) {

							LPCSTR CurrentName = (LPCSTR)(FileData + CurrentNameOffset);

							ULONG CurrentFunctionRva = AddressOfFunctions[AddressOfNameOrdinals[i]];

							if (CurrentFunctionRva >= ExportDirectoryRva && CurrentFunctionRva < ExportDirectoryRva + ExportDirectorySize) {

								continue;
							}
							else {

								if (!strcmp(CurrentName, ExportName)) {

									Result = RvaToOffset(NtHeaders, CurrentFunctionRva, FileSize);

									break;
								}
							}
						}
					}
				}
			}
		}
	}

	return Result;
}

auto GetTableFunByName(PSYSTEM_SERVICE_DESCRIPTOR_TABLE pServiceTableBase, LPBYTE FileData, ULONG FileSize, LPCSTR ExportName) -> LPBYTE {

	LPBYTE Result = NULL;

	ULONG ExportOffset = GetExportOffset(FileData, FileSize, ExportName);

	if (ExportOffset != NULL) {

		INT32 SSDTIndex = -1;

		LPBYTE RoutineData = FileData + ExportOffset;

		for (ULONG i = NULL; i < 32 && ExportOffset + i < FileSize; i++) {

			if (RoutineData[i] == 0xB8) {

				SSDTIndex = *(INT32*)(RoutineData + i + 1);

				break;
			}
		}

		if (SSDTIndex > -1 && SSDTIndex < pServiceTableBase->NumberOfServices) {

			Result = (LPBYTE)((LPBYTE)pServiceTableBase->ServiceTableBase + (((PLONG)pServiceTableBase->ServiceTableBase)[SSDTIndex] >> 4));
		}
	}

	return Result;
}

auto GetServiceTableBase(LPBYTE pKernelBase) -> LPBYTE {

	LPBYTE Result = NULL;

	if (pKernelBase != NULL) {
		LPBYTE pFound = SearchSignForImage(pKernelBase, "\x4C\x8D\x15\x00\x00\x00\x00\x4C\x8D\x1D\x00\x00\x00\x00\xF7", "xxx????xxx????x", strlen("xxx????xxx????x"));

		if (pFound != NULL) {

			Result = ResolveRelativeAddress(pFound, 3);

		}
	}

	return Result;
}