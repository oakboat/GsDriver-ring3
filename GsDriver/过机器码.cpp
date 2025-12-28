#include "驱动核心.h"

BOOLEAN SpoofEnable = FALSE;

auto RtlRandomAnsi(PCHAR pBuffer, SIZE_T Size)->VOID {

	CHAR Ansi[] = "ABCDEF1234567890";

	RtlZeroMemoryEx(pBuffer, Size);

	for (SIZE_T i = 0; i < Size; i++) {

		ULONG Speed = (ULONG)(123456 * i);

		pBuffer[i] = Ansi[RtlRandomEx(&Speed) % (sizeof(Ansi) - sizeof(CHAR))];
	}
}

auto RtlRandomUnicode(PWCHAR pBuffer, SIZE_T Size)->VOID {

	WCHAR Unicode[] = L"ABCDEF1234567890";

	RtlZeroMemoryEx(pBuffer, Size);

	for (SIZE_T i = 0; i < Size; i++) {

		ULONG Speed = (ULONG)(123456 * i);

		pBuffer[i] = Unicode[RtlRandomEx(&Speed) % (sizeof(Unicode) - sizeof(WCHAR))];
	}
}

auto RtlRandomAnsiGuid(PCHAR pBuffer, SIZE_T Size, BOOL Flags)->VOID {

	ULONG Speed[] = { 0x18547856, 0x74569821, 0x56741359, 0x12347865, 0x75234785, 0x35132475, 0x23547856 };

	RtlZeroMemoryEx(pBuffer, Size);

	StringCchPrintfA(pBuffer, Size, Flags ? "{%08X-%04X-%04X-%04X-%04X%04X%04X}" : "%08X-%04X-%04X-%04X-%04X%04X%04X", RtlRandomEx(&Speed[0]) & 0xffffffff, RtlRandomEx(&Speed[1]) & 0xffff, RtlRandomEx(&Speed[2]) & 0xffff, RtlRandomEx(&Speed[3]) & 0xffff, RtlRandomEx(&Speed[4]) & 0xffff, RtlRandomEx(&Speed[5]) & 0xffff, RtlRandomEx(&Speed[6]) & 0xffff);
}

auto RtlRandomUnicodeGuid(PWCHAR pBuffer, SIZE_T Size, BOOL Flags)->VOID {

	ULONG Speed[] = { 0x18547856, 0x74569821, 0x56741359, 0x12347865, 0x75234785, 0x35132475, 0x23547856 };

	RtlZeroMemoryEx(pBuffer, Size);

	StringCchPrintfW(pBuffer, Size, Flags ? L"{%08X-%04X-%04X-%04X-%04X%04X%04X}" : L"%08X-%04X-%04X-%04X-%04X%04X%04X", RtlRandomEx(&Speed[0]) & 0xffffffff, RtlRandomEx(&Speed[1]) & 0xffff, RtlRandomEx(&Speed[2]) & 0xffff, RtlRandomEx(&Speed[3]) & 0xffff, RtlRandomEx(&Speed[4]) & 0xffff, RtlRandomEx(&Speed[5]) & 0xffff, RtlRandomEx(&Speed[6]) & 0xffff);
}

auto BuildCompRoutine(PIO_STACK_LOCATION pIoStack, PIRP IRP, PIO_COMPLETION_ROUTINE Routine)->NTSTATUS{

	NTSTATUS Result = STATUS_UNSUCCESSFUL;

	INT32 TextHash = GetTextHashA(PsGetProcessImageFileName(IoGetCurrentProcess()));

	if (TextHash != 0x6BCCDEC3 && TextHash != 0xD9F7D13D) {

		struct {
			LPVOID Buffer;
			ULONG BufferLength;
			LPVOID OldContext;
			PIO_COMPLETION_ROUTINE OldRoutine;
		} Request;

		LPVOID pRequest = RtlAllocateMemory(PAGE_SIZE);

		if (pRequest != NULL) {

			Request.Buffer = IRP->AssociatedIrp.SystemBuffer;

			Request.BufferLength = pIoStack->Parameters.DeviceIoControl.OutputBufferLength;

			Request.OldContext = pIoStack->Context;

			Request.OldRoutine = pIoStack->CompletionRoutine;

			RtlCopyMemoryEx(pRequest, &Request, sizeof(Request));

			pIoStack->Control = SL_INVOKE_ON_SUCCESS;

			pIoStack->Context = pRequest;

			pIoStack->CompletionRoutine = Routine;

			Result = STATUS_SUCCESS;
		}
	}

	return Result;
}

auto NicCompRoutine(PDEVICE_OBJECT pDevice, PIRP IRP, LPVOID Context)->NTSTATUS {

	NTSTATUS Result = STATUS_SUCCESS;

	if (Context != NULL) {

		struct {
			LPVOID Buffer;
			ULONG BufferLength;
			LPVOID OldContext;
			PIO_COMPLETION_ROUTINE OldRoutine;
		} Request;

		RtlCopyMemoryEx(&Request, Context, sizeof(Request));

		RtlFreeMemoryEx(Context);

		if (IRP->MdlAddress != NULL) {

			PBYTE RealAddress = (PBYTE)(MmGetSystemAddressForMdl(IRP->MdlAddress));

			if (RealAddress != NULL) {

				RtlRandMemoryEx(RealAddress, 6);
			}
		}

		if (Request.OldRoutine != NULL) {

			if (IRP->StackCount > 1) {

				Result = Request.OldRoutine(pDevice, IRP, Request.OldContext);
			}
		}
	}

	return Result;
}

auto PartInfoCompRoutine(PDEVICE_OBJECT pDevice, PIRP IRP, LPVOID Context)->NTSTATUS {

	NTSTATUS Result = STATUS_SUCCESS;

	if (Context != NULL) {

		struct {
			LPVOID Buffer;
			ULONG BufferLength;
			LPVOID OldContext;
			PIO_COMPLETION_ROUTINE OldRoutine;
		} Request;

		RtlCopyMemoryEx(&Request, Context, sizeof(Request));

		RtlFreeMemoryEx(Context);

		if (Request.BufferLength >= sizeof(PARTITION_INFORMATION_EX)) {

			PPARTITION_INFORMATION_EX pPartInfoEx = (PPARTITION_INFORMATION_EX)Request.Buffer;

			if (pPartInfoEx != NULL) {

				if (pPartInfoEx->PartitionStyle == PARTITION_STYLE_GPT) {

					RtlRandMemoryEx(&pPartInfoEx->Gpt.PartitionId, sizeof(pPartInfoEx->Gpt.PartitionId));
				}
			}
		}

		if (Request.OldRoutine != NULL) {

			if (IRP->StackCount > 1) {

				Result = Request.OldRoutine(pDevice, IRP, Request.OldContext);
			}
		}
	}

	return Result;
}

auto PartLayouCompRoutine(PDEVICE_OBJECT pDevice, PIRP IRP, LPVOID Context)->NTSTATUS {

	NTSTATUS Result = STATUS_SUCCESS;

	if (Context != NULL) {

		struct {
			LPVOID Buffer;
			ULONG BufferLength;
			LPVOID OldContext;
			PIO_COMPLETION_ROUTINE OldRoutine;
		} Request;

		RtlCopyMemoryEx(&Request, Context, sizeof(Request));

		RtlFreeMemoryEx(Context);

		if (Request.BufferLength >= sizeof(DRIVE_LAYOUT_INFORMATION_EX)) {

			PDRIVE_LAYOUT_INFORMATION_EX pPartLayou = (PDRIVE_LAYOUT_INFORMATION_EX)Request.Buffer;

			if (pPartLayou != NULL) {

				if (pPartLayou->PartitionStyle == PARTITION_STYLE_GPT) {

					RtlRandMemoryEx(&pPartLayou->Gpt.DiskId, sizeof(pPartLayou->Gpt.DiskId));
				}
			}
		}

		if (Request.OldRoutine != NULL) {

			if (IRP->StackCount > 1) {

				Result = Request.OldRoutine(pDevice, IRP, Request.OldContext);
			}
		}
	}

	return Result;
}

auto DiskAtaPassCompRoutine(PDEVICE_OBJECT pDevice, PIRP IRP, LPVOID Context)->NTSTATUS {

	NTSTATUS Result = STATUS_SUCCESS;

	if (MmIsAddressValid(Context)) {

		struct {
			LPVOID Buffer;
			ULONG BufferLength;
			LPVOID OldContext;
			PIO_COMPLETION_ROUTINE OldRoutine;
		} Request;

		RtlCopyMemoryEx(&Request, Context, sizeof(Request));

		RtlFreeMemoryEx(Context);

		if (Request.BufferLength >= sizeof(ATA_PASS_THROUGH_EX) + sizeof(PIDENTIFY_DEVICE_DATA)) {

			PATA_PASS_THROUGH_EX pAtaPassEx = (PATA_PASS_THROUGH_EX)Request.Buffer;

			if (pAtaPassEx != NULL) {

				if (pAtaPassEx->DataBufferOffset < Request.BufferLength) {
					
					PIDENTIFY_DEVICE_DATA pDeviceData = (PIDENTIFY_DEVICE_DATA)((PBYTE)Request.Buffer + pAtaPassEx->DataBufferOffset);

					RtlRandomAnsi((PCHAR)pDeviceData->ModelNumber, sizeof(pDeviceData->ModelNumber));

					RtlRandomAnsi((PCHAR)pDeviceData->SerialNumber, sizeof(pDeviceData->SerialNumber));

					RtlRandomAnsi((PCHAR)pDeviceData->CurrentMediaSerialNumber, sizeof(pDeviceData->CurrentMediaSerialNumber));
				}
			}
		}

		if (Request.OldRoutine != NULL) {

			if (IRP->StackCount > 1) {

				Result = Request.OldRoutine(pDevice, IRP, Request.OldContext);
			}
		}
	}

	return Result;
}

auto DiskRcvDataCompRoutine(PDEVICE_OBJECT pDevice, PIRP IRP, LPVOID Context)->NTSTATUS {

	NTSTATUS Result = STATUS_SUCCESS;

	if (MmIsAddressValid(Context)) {

		struct {
			LPVOID Buffer;
			ULONG BufferLength;
			LPVOID OldContext;
			PIO_COMPLETION_ROUTINE OldRoutine;
		} Request;

		RtlCopyMemoryEx(&Request, Context, sizeof(Request));

		RtlFreeMemoryEx(Context);

		if (Request.BufferLength >= sizeof(SENDCMDOUTPARAMS)) {

			PSENDCMDOUTPARAMS pSmartData = (PSENDCMDOUTPARAMS)Request.Buffer;

			if (pSmartData != NULL) {

				typedef struct _IDINFO
				{
					USHORT  wGenConfig;                 // WORD 0: 基本信息字
					USHORT  wNumCyls;                   // WORD 1: 柱面数
					USHORT  wReserved2;                 // WORD 2: 保留
					USHORT  wNumHeads;                  // WORD 3: 磁头数
					USHORT  wReserved4;                 // WORD 4: 保留
					USHORT  wReserved5;                 // WORD 5: 保留
					USHORT  wNumSectorsPerTrack;        // WORD 6: 每磁道扇区数
					USHORT  wVendorUnique[3];           // WORD 7-9: 厂家设定值
					CHAR    sSerialNumber[20];          // WORD 10-19:序列号
					USHORT  wBufferType;                // WORD 20: 缓冲类型
					USHORT  wBufferSize;                // WORD 21: 缓冲大小
					USHORT  wECCSize;                   // WORD 22: ECC校验大小
					CHAR    sFirmwareRev[8];            // WORD 23-26: 固件版本
					CHAR    sModelNumber[40];           // WORD 27-46: 内部型号
				} IDINFO, *PIDINFO;

				PIDINFO pInfo = (PIDINFO)(((PSENDCMDOUTPARAMS)Request.Buffer)->bBuffer);

				if (pInfo != NULL) {

					RtlRandomAnsi(pInfo->sFirmwareRev, sizeof(pInfo->sFirmwareRev));

					RtlRandomAnsi(pInfo->sModelNumber, sizeof(pInfo->sModelNumber));

					RtlRandomAnsi(pInfo->sSerialNumber, sizeof(pInfo->sSerialNumber));
				}
			}
		}

		if (Request.OldRoutine != NULL) {

			if (IRP->StackCount > 1) {

				Result = Request.OldRoutine(pDevice, IRP, Request.OldContext);
			}
		}
	}

	return Result;
}

auto DiskStorageQueryCompRoutine(PDEVICE_OBJECT pDevice, PIRP IRP, LPVOID Context)->NTSTATUS {

	NTSTATUS Result = STATUS_SUCCESS;

	if (MmIsAddressValid(Context)) {

		struct {
			LPVOID Buffer;
			ULONG BufferLength;
			LPVOID OldContext;
			PIO_COMPLETION_ROUTINE OldRoutine;
		} Request;

		RtlCopyMemoryEx(&Request, Context, sizeof(Request));

		RtlFreeMemoryEx(Context);

		if (Request.BufferLength >= sizeof(STORAGE_DEVICE_DESCRIPTOR)) {

			PSTORAGE_DEVICE_DESCRIPTOR pStorageQuery = (PSTORAGE_DEVICE_DESCRIPTOR)Request.Buffer;

			if (pStorageQuery != NULL) {

				if (pStorageQuery->SerialNumberOffset < Request.BufferLength) {

					PCHAR SerialNumber = (PCHAR)((PBYTE)Request.Buffer + pStorageQuery->SerialNumberOffset); {

						RtlRandomAnsi(SerialNumber, strlen(SerialNumber));
					}

					PCHAR VendorId = (PCHAR)((PBYTE)Request.Buffer + pStorageQuery->VendorIdOffset); {

						RtlRandomAnsi(VendorId, strlen(VendorId));
					}

					PCHAR ProductId = (PCHAR)((PBYTE)Request.Buffer + pStorageQuery->ProductIdOffset); {

						RtlRandomAnsi(ProductId, strlen(ProductId));
					}

					PCHAR ProductRevision = (PCHAR)((PBYTE)Request.Buffer + pStorageQuery->ProductRevisionOffset); {

						RtlRandomAnsi(ProductRevision, strlen(ProductRevision));
					}
				}
			}
		}

		if (Request.OldRoutine != NULL) {

			if (IRP->StackCount > 1) {

				Result = Request.OldRoutine(pDevice, IRP, Request.OldContext);
			}
		}
	}

	return Result;
}

auto MountPointsCompRoutine(PDEVICE_OBJECT pDevice, PIRP IRP, LPVOID Context)->NTSTATUS {

	NTSTATUS Result = STATUS_SUCCESS;

	if (Context != NULL) {

		struct {
			LPVOID Buffer;
			ULONG BufferLength;
			LPVOID OldContext;
			PIO_COMPLETION_ROUTINE OldRoutine;
		} Request;

		RtlCopyMemoryEx(&Request, Context, sizeof(Request));

		RtlFreeMemoryEx(Context);

		if (Request.BufferLength >= sizeof(MOUNTMGR_MOUNT_POINTS)) {

			PMOUNTMGR_MOUNT_POINTS pMountPoints = (PMOUNTMGR_MOUNT_POINTS)Request.Buffer;

			if (pMountPoints != NULL) {

				for (DWORD i = NULL; i < pMountPoints->NumberOfMountPoints; i++) {

					PMOUNTMGR_MOUNT_POINT pMountPoint = &pMountPoints->MountPoints[i];

					if (pMountPoint != NULL) {

						pMountPoint->UniqueIdOffset = NULL;

						pMountPoint->SymbolicLinkNameOffset = NULL;
					}
				}
			}
		}

		if (Request.OldRoutine != NULL) {

			if (IRP->StackCount > 1) {

				Result = Request.OldRoutine(pDevice, IRP, Request.OldContext);
			}
		}
	}

	return Result;
}

auto MountUniqueCompRoutine(PDEVICE_OBJECT pDevice, PIRP IRP, LPVOID Context)->NTSTATUS {

	NTSTATUS Result = STATUS_SUCCESS;

	if (Context != NULL) {

		struct {
			LPVOID Buffer;
			ULONG BufferLength;
			LPVOID OldContext;
			PIO_COMPLETION_ROUTINE OldRoutine;
		} Request;

		RtlCopyMemoryEx(&Request, Context, sizeof(Request));

		RtlFreeMemoryEx(Context);

		if (Request.BufferLength >= sizeof(MOUNTDEV_UNIQUE_ID)) {

			PMOUNTDEV_UNIQUE_ID pMountPoints = (PMOUNTDEV_UNIQUE_ID)Request.Buffer;

			if (pMountPoints != NULL) {

				pMountPoints->UniqueIdLength = NULL;
			}
		}

		if (Request.OldRoutine != NULL) {

			if (IRP->StackCount > 1) {

				Result = Request.OldRoutine(pDevice, IRP, Request.OldContext);
			}
		}
	}

	return Result;
}

auto SpoofNicControl(PDEVICE_OBJECT pDevice, PIRP IRP)->NTSTATUS {

	PIO_STACK_LOCATION pIoStack = IoGetCurrentIrpStackLocation(IRP);

	if (pIoStack != NULL) {

		if (pIoStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_NDIS_QUERY_GLOBAL_STATS) {

			ULONG IdCode = *(ULONG*)(IRP->AssociatedIrp.SystemBuffer);

			if (IdCode == OID_802_3_PERMANENT_ADDRESS || IdCode == OID_802_3_CURRENT_ADDRESS || IdCode == OID_802_5_PERMANENT_ADDRESS || IdCode == OID_802_5_CURRENT_ADDRESS) {

				BuildCompRoutine(pIoStack, IRP, NicCompRoutine);
			}
		}
	}

	return pDevice->DriverObject->MajorFunction[28](pDevice, IRP);
}

auto SpoofNsiControl(PDEVICE_OBJECT pDevice, PIRP IRP)->NTSTATUS {

	PIO_STACK_LOCATION pIoStack = IoGetCurrentIrpStackLocation(IRP);

	if (pIoStack != NULL) {

		if (pIoStack->Parameters.DeviceIoControl.IoControlCode == /*IOCTL_NSI_PROXY_ARP*/0x0012001B) {

			ULONG BufferLength = pIoStack->Parameters.DeviceIoControl.OutputBufferLength;

			NTSTATUS Result = pDevice->DriverObject->MajorFunction[28](pDevice, IRP);

			PBYTE pUserBuffer = (PBYTE)(IRP->UserBuffer);

			if (pUserBuffer != NULL && *(ULONG*)(pUserBuffer + 0x18) == 11) {

				RtlZeroMemoryEx(pUserBuffer, BufferLength);
			}

			return Result;
		}
	}

	return pDevice->DriverObject->MajorFunction[28](pDevice, IRP);
}

auto SpoofGpuControl(PDEVICE_OBJECT pDevice, PIRP IRP)->NTSTATUS {

	PIO_STACK_LOCATION pIoStack = IoGetCurrentIrpStackLocation(IRP);

	if (pIoStack != NULL) {

		if (pIoStack->Parameters.DeviceIoControl.IoControlCode == /*IOCTL_NVIDIA_SMIL*/0x8DE0008) {

			NTSTATUS Result = pDevice->DriverObject->MajorFunction[28](pDevice, IRP);

			PBYTE pUserBuffer = (PBYTE)(IRP->UserBuffer);

			if (pUserBuffer != NULL) {

				PBYTE pKernelBuffer = RtlAllocateMemory(/*IOCTL_NVIDIA_SMIL_MAX*/512);

				if (pKernelBuffer != NULL) {

					SIZE_T CopyByte = NULL;

					Result = ZwMmCopyMemory(pKernelBuffer, pUserBuffer, /*IOCTL_NVIDIA_SMIL_MAX*/512);

					if (NT_SUCCESS(Result) && CopyByte == /*IOCTL_NVIDIA_SMIL_MAX*/512) {

						for (INT Index = NULL; Index < 508; Index++) {

							if (!memcmp(pKernelBuffer + Index, "GPU-", 4)) {

								pUserBuffer[Index] = '\0';

								break;
							}
						}
					}

					RtlFreeMemoryEx(pKernelBuffer);
				}
			}

			return Result;
		}
	}

	return pDevice->DriverObject->MajorFunction[28](pDevice, IRP);
}

auto SpoofPartControl(PDEVICE_OBJECT pDevice, PIRP IRP)->NTSTATUS {

	PIO_STACK_LOCATION pIoStack = IoGetCurrentIrpStackLocation(IRP);

	if (pIoStack != NULL) {

		if (pIoStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_DISK_GET_DRIVE_LAYOUT_EX) {

			BuildCompRoutine(pIoStack, IRP, PartLayouCompRoutine);
		}

		if (pIoStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_DISK_GET_PARTITION_INFO_EX) {

			BuildCompRoutine(pIoStack, IRP, PartInfoCompRoutine);
		}
	}

	return pDevice->DriverObject->MajorFunction[28](pDevice, IRP);
}

auto SpoofDiskControl(PDEVICE_OBJECT pDevice, PIRP IRP)->NTSTATUS {

	PIO_STACK_LOCATION pIoStack = IoGetCurrentIrpStackLocation(IRP);

	if (pIoStack != NULL) {

		if (pIoStack->Parameters.DeviceIoControl.IoControlCode == SMART_RCV_DRIVE_DATA) {

			BuildCompRoutine(pIoStack, IRP, DiskRcvDataCompRoutine);
		}

		if (pIoStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_ATA_PASS_THROUGH) {

			BuildCompRoutine(pIoStack, IRP, DiskAtaPassCompRoutine);
		}

		if (pIoStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_STORAGE_QUERY_PROPERTY) {

			PSTORAGE_PROPERTY_QUERY pQuery = (PSTORAGE_PROPERTY_QUERY)(IRP->AssociatedIrp.SystemBuffer);

			if (pQuery != NULL) {

				if (pQuery->PropertyId == StorageDeviceProperty) {

					BuildCompRoutine(pIoStack, IRP, DiskStorageQueryCompRoutine);
				}
			}
		}
	}

	return pDevice->DriverObject->MajorFunction[28](pDevice, IRP);
}

auto SpoofMountControl(PDEVICE_OBJECT pDevice, PIRP IRP)->NTSTATUS {

	PIO_STACK_LOCATION pIoStack = IoGetCurrentIrpStackLocation(IRP);

	if (pIoStack != NULL) {

		if (pIoStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_MOUNTMGR_QUERY_POINTS) {

			BuildCompRoutine(pIoStack, IRP, MountPointsCompRoutine);
		}

		if (pIoStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_MOUNTDEV_QUERY_UNIQUE_ID) {

			BuildCompRoutine(pIoStack, IRP, MountUniqueCompRoutine);
		}
	}

	return pDevice->DriverObject->MajorFunction[28](pDevice, IRP);
}

auto RestartWmiPrvSE()->NTSTATUS {

	return ZwKillProcess(L"WmiPrvSE.exe");
}

auto SpoofReg()->NTSTATUS {

	static BOOLEAN Enable = FALSE;

	NTSTATUS Result = STATUS_SUCCESS;

	if (Enable == FALSE) {

		PWCHAR pSpoofBuffer = (PWCHAR)(RtlAllocateMemory(PAGE_SIZE));

		if (pSpoofBuffer != NULL) {

			/*Spoof*/ {

				RtlRandomUnicodeGuid(pSpoofBuffer, MAX_PATH, TRUE);

				Result = RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, L"\\Registry\\Machine\\Software\\Microsoft\\SQMClient", L"MachineId", REG_SZ, pSpoofBuffer, (ULONG)(wcslen(pSpoofBuffer) * sizeof(WCHAR)));
			
				Result = RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, L"\\Registry\\Machine\\Software\\Microsoft\\Cryptography", L"MachineGuid", REG_SZ, pSpoofBuffer, (ULONG)(wcslen(pSpoofBuffer) * sizeof(WCHAR)));
				
				Result = RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001", L"HwProfileGuid", REG_SZ, pSpoofBuffer, (ULONG)(wcslen(pSpoofBuffer) * sizeof(WCHAR)));
				
				Result = RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, L"\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\OneSettings\\WSD\\UpdateAgent\\QueryParameters", L"deviceId", REG_SZ, pSpoofBuffer, (ULONG)(wcslen(pSpoofBuffer) * sizeof(WCHAR)));
				
				Result = RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, L"\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\OneSettings\\appcompat\\runtimesdbincloud\\QueryParameters", L"deviceid", REG_SZ, pSpoofBuffer, (ULONG)(wcslen(pSpoofBuffer) * sizeof(WCHAR)));

				RtlRandomUnicodeGuid(pSpoofBuffer, MAX_PATH, FALSE);
	
				Result = RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\TPM\\WMI", L"WindowsAIKHash", REG_BINARY, pSpoofBuffer, (ULONG)(wcslen(pSpoofBuffer) * sizeof(WCHAR)));
				
				Result = RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, L"\\Registry\\Machine\\Software\\NVIDIA Corporation\\Global\\CoProcManager", L"ChipsetMatchID", REG_SZ, pSpoofBuffer, (ULONG)(wcslen(pSpoofBuffer) * sizeof(WCHAR)));
			}

			/*Delete*/ {

				PWCHAR VolumeIndex[] = { L"A", L"B", L"C", L"D", L"E", L"F", L"G", L"H", L"I", L"J", L"K", L"L", L"M", L"N", L"O", L"P", L"Q", L"R", L"S", L"T", L"U", L"V", L"W", L"X", L"Y", L"Z" };

				for (SIZE_T Index = NULL; Index < ARRAYSIZE(VolumeIndex); Index++) {

					WCHAR VolumeGuidPath[MAX_PATH] = { NULL };

					RtlZeroMemoryEx(VolumeGuidPath, sizeof(VolumeGuidPath));

					Result = RtlStringCbPrintfW(VolumeGuidPath, sizeof(VolumeGuidPath), L"\\DosDevices\\%ws:", VolumeIndex[Index]);

					if (NT_SUCCESS(Result)) {

						Result = RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, L"\\Registry\\Machine\\System\\MountedDevices", VolumeGuidPath);

						if (NT_SUCCESS(Result)) {

							Enable = TRUE;
						}
					}
				}
			}

			RtlFreeMemoryEx(pSpoofBuffer);
		}
	}

	if (Enable != FALSE) {

		Result = STATUS_SUCCESS;
	}

	return Result;
}

auto SpoofHdd()->NTSTATUS {

	static BOOLEAN Enable = FALSE;

	NTSTATUS Result = STATUS_SUCCESS;

	if (Enable == FALSE) {

		/* 48 8B CB E8 ?? ?? ?? ?? 48 8B CB E8 ?? ?? ?? ?? 85 C0 */

		LPVOID RaidUnitRegisterInterfaces = NULL;

		PBYTE RaidUnitExtensionSerialNumber = NULL;

		LPBYTE ModuleBase = GetModuleBaseForHash(0x18C1E17C);

		if (ModuleBase != NULL) {

			if (DynamicData->WinVersion >= WINVER_1X) {

				RaidUnitRegisterInterfaces = ResolveRelativeAddress(SearchSignForImage(ModuleBase, "\x48\x8B\xCB\xE8\x00\x00\x00\x00\x48\x8B\xCB\xE8\x00\x00\x00\x00\x85\xC0", "xxxx????xxxx????xx", 18), 4);

				if (RaidUnitRegisterInterfaces != NULL) {

					RaidUnitExtensionSerialNumber = SearchSignForMemory(SearchSignForImage(ModuleBase, "\x66\x39\x2C\x41\x75\xF7", "xxxxxx", 6), 32, "\x4C\x8D\x4F", "xxx", 3);

					if (RaidUnitExtensionSerialNumber != NULL) {

						RaidUnitExtensionSerialNumber += 3;
					}
				}
			}

			if (RaidUnitRegisterInterfaces != NULL && RaidUnitExtensionSerialNumber != NULL) {

				UNICODE_STRING usDriverName = RTL_CONSTANT_STRING(L"\\Driver\\storahci");

				PDRIVER_OBJECT pDriverObject = NULL;

				Result = ZwReferenceObjectByName(&usDriverName, OBJ_CASE_INSENSITIVE, 0, 0, *IoDriverObjectType, KernelMode, 0, &pDriverObject);

				if (NT_SUCCESS(Result)) {

					PDEVICE_OBJECT* pDeviceList = NULL;

					ULONG DeviceObjLen = NULL;

					Result = ZwEnumDeviceObj(pDriverObject, &pDeviceList, &DeviceObjLen);

					if (NT_SUCCESS(Result) && pDeviceList != NULL && DeviceObjLen != 0) {

						for (ULONG Index = NULL; Index < DeviceObjLen; Index++) {

							PDEVICE_OBJECT pDevice = pDeviceList[Index];

							if (pDevice != NULL) {

								POBJECT_NAME_INFORMATION pObjNameInfo = NULL;

								ULONG ObjNameInfoLen = NULL;

								Result = ZwQueryNameStr(pDevice, &pObjNameInfo, &ObjNameInfoLen);

								if (NT_SUCCESS(Result) && pObjNameInfo != NULL && ObjNameInfoLen != 0) {

									UNICODE_STRING SearchName = RTL_CONSTANT_STRING(L"\\RaidPort");

									Result = SearchStr(&pObjNameInfo->Name, &SearchName, TRUE);

									if (NT_SUCCESS(Result) && pDevice->DriverObject != NULL) {

										for (PDEVICE_OBJECT pLocalDevice = pDevice->DriverObject->DeviceObject; pLocalDevice; pLocalDevice = pLocalDevice->NextDevice) {

											if (pLocalDevice->DeviceType == FILE_DEVICE_DISK) {

												PSTRING Serial = (PSTRING)((PBYTE)pLocalDevice->DeviceExtension + *RaidUnitExtensionSerialNumber);

												if (MmIsAddressValid(Serial->Buffer) && Serial->Length < MAX_PATH) {

													RtlRandomAnsi(Serial->Buffer, Serial->Length);

													Enable = TRUE;
												}
											}
										}
									}

									RtlFreeMemoryEx(pObjNameInfo);
								}
							}
						}

						RtlFreeMemoryEx(pDeviceList);
					}

					ObfDereferenceObject(pDriverObject);
				}
			}
		}
	}

	if (Enable != FALSE) {

		Result = STATUS_SUCCESS;
	}

	return Result;
}

auto SpoofNic()->NTSTATUS {

	static BOOLEAN Enable = FALSE;

	NTSTATUS Result = STATUS_SUCCESS;

	if (Enable == FALSE) {

		for (SIZE_T Index = NULL; Index < 100; Index++) {

			PUNICODE_STRING pQueryBuffer = (PUNICODE_STRING)(RtlAllocateMemory(PAGE_SIZE));

			if (pQueryBuffer != NULL) {

				RTL_QUERY_REGISTRY_TABLE QueryTable[2]; {

					RtlZeroMemoryEx(QueryTable, sizeof(QueryTable));
				}

				QueryTable[0].Flags = RTL_QUERY_REGISTRY_DIRECT;

				QueryTable[0].Name = L"NetCfgInstanceId";

				QueryTable[0].DefaultType = REG_SZ;

				QueryTable[0].DefaultLength = PAGE_SIZE;

				QueryTable[0].EntryContext = QueryTable[0].DefaultData = pQueryBuffer;

				WCHAR KeyPath[MAX_PATH]; {

					RtlZeroMemoryEx(KeyPath, sizeof(KeyPath));

					RtlStringCbPrintfW(KeyPath, sizeof(KeyPath), L"\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}\\00%02d", Index);
				}

				Result = RtlQueryRegistryValues(RTL_REGISTRY_CONTROL, KeyPath, QueryTable, NULL, NULL);

				if (NT_SUCCESS(Result)) {

					WCHAR Adapter[MAX_PATH]; {

						RtlZeroMemoryEx(Adapter, sizeof(Adapter));

						RtlStringCbPrintfW(Adapter, sizeof(Adapter), L"\\Device\\%ws", pQueryBuffer->Buffer);
					}

					UNICODE_STRING usDeviceName = { NULL };

					RtlInitUnicodeString(&usDeviceName, Adapter);

					PFILE_OBJECT pFileObj = NULL;

					PDEVICE_OBJECT pDeviceObj = NULL;

					Result = IoGetDeviceObjectPointer(&usDeviceName, FILE_READ_DATA, &pFileObj, &pDeviceObj);

					if (NT_SUCCESS(Result)) {

						for (PDEVICE_OBJECT pLocalObj = pDeviceObj; pLocalObj; pLocalObj = pLocalObj->NextDevice) {

							PDRIVER_OBJECT pDriverObj = pLocalObj->DriverObject;

							if (pDriverObj != NULL) {

								*(LPVOID*)&pDriverObj->MajorFunction[28] = InterlockedExchangePointer((LPVOID*)&pDriverObj->MajorFunction[14], (LPVOID)SpoofNicControl);

								Enable = TRUE;
							}
						}

						ObfDereferenceObject(pFileObj);
					}
				}

				RtlFreeMemoryEx(pQueryBuffer);
			}
		}
	}

	if (Enable != FALSE) {

		Result = STATUS_SUCCESS;
	}

	return Result;
}

auto SpoofFile()->NTSTATUS {

	static BOOLEAN Enable = FALSE;

	NTSTATUS Result = STATUS_SUCCESS;

	if (Enable == FALSE) {

		PCHAR pSpoofBuffer = (PCHAR)(RtlAllocateMemory(PAGE_SIZE));

		if (pSpoofBuffer != NULL) {

			RtlRandomAnsiGuid(pSpoofBuffer, MAX_PATH, TRUE);

			Result = ZwWriteFileEx(L"\\SystemRoot\\System32\\Restore\\MachineGuid.txt", pSpoofBuffer, (ULONG)(strlen(pSpoofBuffer)));

			Enable = NT_SUCCESS(Result) ? TRUE : FALSE;

			RtlFreeMemoryEx(pSpoofBuffer);
		}
	}

	if (Enable != FALSE) {

		Result = STATUS_SUCCESS;
	}

	return Result;
}

auto SpoofNdis()->NTSTATUS {

	static BOOLEAN Enable = FALSE;

	NTSTATUS Result = STATUS_SUCCESS;

	if (Enable == FALSE) {

		/* 48 8B CB E8 ?? ?? ?? ?? 48 8B CB E8 ?? ?? ?? ?? 85 C0 */

		PBYTE NdisGlobalFilterList = NULL;

		PBYTE NdisFilterBlock = NULL;

		DWORD NdisFilterBlockOffset = NULL;

		LPBYTE ModuleBase = GetModuleBaseForHash(0x8C95DD81);

		if (ModuleBase != NULL) {

			if (DynamicData->WinVersion >= WINVER_1X) {

				NdisGlobalFilterList = SearchSignForImage(ModuleBase, "\x40\x8A\xF0\x48\x8B\x05", "xxxxxx", 6);

				if (NdisGlobalFilterList != NULL) {

					NdisFilterBlock = SearchSignForImage(ModuleBase, "\x48\x85\x00\x0F\x84\x00\x00\x00\x00\x00\x8B\x00\x00\x00\x00\x00\x33", "xx?xx?????x???xxx", 17);

					if (NdisFilterBlock != NULL) {

						NdisGlobalFilterList = (PBYTE)(NdisGlobalFilterList + 3);

						NdisGlobalFilterList = *(PBYTE*)((PBYTE)NdisGlobalFilterList + 7 + *(PINT)((PBYTE)NdisGlobalFilterList + 3));

						NdisFilterBlockOffset = *(PDWORD)((PBYTE)NdisFilterBlock + 12);
					}
				}
			}

			if (NdisGlobalFilterList != NULL && NdisFilterBlock != NULL && NdisFilterBlockOffset != 0) {

				for (PBYTE Filter = NdisGlobalFilterList; MmIsAddressValid(Filter); Filter = *(PBYTE*)(Filter + 0x8)) {

					typedef struct _NDIS_IF_BLOCK {
						char _padding_0[0x464];
						IF_PHYSICAL_ADDRESS_LH ifPhysAddress; // 0x464
						IF_PHYSICAL_ADDRESS_LH PermanentPhysAddress; // 0x486
					} NDIS_IF_BLOCK, *PNDIS_IF_BLOCK;

					PNDIS_IF_BLOCK Block = *(PNDIS_IF_BLOCK*)(Filter + NdisFilterBlockOffset);

					if (MmIsAddressValid(Block)) {

						RtlRandMemoryEx(((PIF_PHYSICAL_ADDRESS_LH)&Block->ifPhysAddress)->Address, ((PIF_PHYSICAL_ADDRESS_LH)&Block->ifPhysAddress)->Length);

						RtlRandMemoryEx(((PIF_PHYSICAL_ADDRESS_LH)&Block->PermanentPhysAddress)->Address, ((PIF_PHYSICAL_ADDRESS_LH)&Block->PermanentPhysAddress)->Length);

						Enable = TRUE;
					}
				}
			}
		}
	}

	if (Enable != FALSE) {

		Result = STATUS_SUCCESS;
	}

	return Result;
}

auto SpoofNsiEx()->NTSTATUS {

	static BOOLEAN Enable = FALSE;

	NTSTATUS Result = STATUS_SUCCESS;

	if (Enable == FALSE) {

		UNICODE_STRING ObjeName = RTL_CONSTANT_STRING(L"\\Driver\\nsiproxy");

		PDRIVER_OBJECT DriverObj = NULL;

		Result = ZwReferenceObjectByName(&ObjeName, OBJ_CASE_INSENSITIVE, 0, 0, *IoDriverObjectType, KernelMode, 0, &DriverObj);

		if (NT_SUCCESS(Result)) {

			*(LPVOID*)&DriverObj->MajorFunction[28] = InterlockedExchangePointer((LPVOID*)&DriverObj->MajorFunction[14], (LPVOID)SpoofNsiControl);

			ObfDereferenceObject(DriverObj);

			Enable = TRUE;
		}
	}

	if (Enable != FALSE) {

		Result = STATUS_SUCCESS;
	}

	return Result;
}

auto SpoofGpuEx()->NTSTATUS {

	static BOOLEAN Enable = FALSE;

	NTSTATUS Result = STATUS_SUCCESS;

	if (Enable == FALSE) {

		UNICODE_STRING ObjeName = RTL_CONSTANT_STRING(L"\\Driver\\nvlddmkm");

		PDRIVER_OBJECT DriverObj = NULL;

		Result = ZwReferenceObjectByName(&ObjeName, OBJ_CASE_INSENSITIVE, 0, 0, *IoDriverObjectType, KernelMode, 0, &DriverObj);

		if (NT_SUCCESS(Result)) {

			*(LPVOID*)&DriverObj->MajorFunction[28] = InterlockedExchangePointer((LPVOID*)&DriverObj->MajorFunction[14], (LPVOID)SpoofGpuControl);

			ObfDereferenceObject(DriverObj);

			Enable = TRUE;
		}
	}

	if (Enable != FALSE) {

		Result = STATUS_SUCCESS;
	}

	return Result;
}

auto SpoofPartEx()->NTSTATUS {

	static BOOLEAN Enable = FALSE;

	NTSTATUS Result = STATUS_SUCCESS;

	if (Enable == FALSE) {

		//VMProtectBeginMutation(__FUNCTION__);

		UNICODE_STRING ObjeName = RTL_CONSTANT_STRING(L"\\Driver\\partmgr");

		PDRIVER_OBJECT DriverObj = NULL;

		Result = ZwReferenceObjectByName(&ObjeName, OBJ_CASE_INSENSITIVE, 0, 0, *IoDriverObjectType, KernelMode, 0, &DriverObj);

		if (NT_SUCCESS(Result)) {

			*(LPVOID*)&DriverObj->MajorFunction[28] = InterlockedExchangePointer((LPVOID*)&DriverObj->MajorFunction[14], (LPVOID)SpoofPartControl);

			ObfDereferenceObject(DriverObj);

			Enable = TRUE;
		}

		//VMProtectEnd();
	}

	if (Enable != FALSE) {

		Result = STATUS_SUCCESS;
	}

	return Result;
}

auto SpoofDiskEx()->NTSTATUS {

	static BOOLEAN Enable = FALSE;

	NTSTATUS Result = STATUS_SUCCESS;

	if (Enable == FALSE) {

		//VMProtectBeginMutation(__FUNCTION__);

		UNICODE_STRING ObjeName = RTL_CONSTANT_STRING(L"\\Driver\\Disk");

		PDRIVER_OBJECT DriverObj = NULL;

		Result = ZwReferenceObjectByName(&ObjeName, OBJ_CASE_INSENSITIVE, 0, 0, *IoDriverObjectType, KernelMode, 0, &DriverObj);

		if (NT_SUCCESS(Result)) {

			*(LPVOID*)&DriverObj->MajorFunction[28] = InterlockedExchangePointer((LPVOID*)&DriverObj->MajorFunction[14], (LPVOID)SpoofDiskControl);

			ObfDereferenceObject(DriverObj);

			Enable = TRUE;
		}

		//VMProtectEnd();
	}

	if (Enable != FALSE) {

		Result = STATUS_SUCCESS;
	}

	return Result;
}

auto SpoofSmbios()->NTSTATUS {

	static BOOLEAN Enable = FALSE;

	NTSTATUS Result = STATUS_SUCCESS;

	if (Enable == FALSE) {

		LPVOID ExpBootEnvironmentInformation = NULL;

		PPHYSICAL_ADDRESS WmipSMBiosTablePhysicalAddress = NULL;

		//VMProtectBeginMutation(__FUNCTION__);

		if (DynamicData->WinVersion <= WINVER_7) {

			/* F3 0F 7F 05 ?? ?? ?? ?? C3 */

			/* 48 8B 0D ?? ?? ?? ?? 48 3B CB 74 30 */

			ExpBootEnvironmentInformation = ResolveRelativeAddress(SearchSignForImage(DynamicData->KernelBase, "\xF3\x0F\x7F\x05\x00\x00\x00\x00\xC3", "xxxx????x", 9), 4);

			if (ExpBootEnvironmentInformation != NULL) {

				WmipSMBiosTablePhysicalAddress = (PPHYSICAL_ADDRESS)(ResolveRelativeAddress(SearchSignForImage(DynamicData->KernelBase, "\x48\x8B\x0D\x00\x00\x00\x00\x48\x3B\xCB\x74\x30", "xxx????xxxxx", 12), 3));
			}
		}

		if (DynamicData->WinVersion >= WINVER_1X) {

			/* 0F 10 05 ?? ?? ?? ?? 0F 11 ?? 8B */

			/* 48 8B 0D ?? ?? ?? ?? 48 85 C9 0F 84 ?? ?? ?? ?? 48 8B D0 */

			ExpBootEnvironmentInformation = ResolveRelativeAddress(SearchSignForImage(DynamicData->KernelBase, "\x0F\x10\x05\x00\x00\x00\x00\x0F\x11\x00\x8B", "xxx????xx?x", 11), 3);

			if (ExpBootEnvironmentInformation != NULL) {

				LPBYTE SignAddress = SearchSignForImage(DynamicData->KernelBase, "\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x0F\x84\x00\x00\x00\x00\x48\x8B\xD0", "xxx????xxxxx????xxx", 19);

				WmipSMBiosTablePhysicalAddress = (PPHYSICAL_ADDRESS)(ResolveRelativeAddress(SignAddress, 3));
			}
		}

		if (ExpBootEnvironmentInformation != NULL && WmipSMBiosTablePhysicalAddress != NULL) {

			RtlRandMemoryEx(ExpBootEnvironmentInformation, 16);

			RtlZeroMemoryEx(WmipSMBiosTablePhysicalAddress, sizeof(PHYSICAL_ADDRESS));

			Enable = TRUE;
		}

		//VMProtectEnd();
	}

	if (Enable != FALSE) {

		Result = STATUS_SUCCESS;
	}

	return Result;
}

auto SpoofVolumes()->NTSTATUS {

	static BOOLEAN Enable = FALSE;

	NTSTATUS Result = STATUS_SUCCESS;

	if (Enable == FALSE) {

		//VMProtectBeginMutation(__FUNCTION__);

		PCHAR pSpoofBuffer = (PCHAR)(RtlAllocateMemory(PAGE_SIZE));

		if (pSpoofBuffer != NULL) {

			PWCHAR VolumeIndex[] = { L"A", L"B", L"C", L"D", L"E", L"F", L"G", L"H", L"I", L"J", L"K", L"L", L"M", L"N", L"O", L"P", L"Q", L"R", L"S", L"T", L"U", L"V", L"W", L"X", L"Y", L"Z" };

			for (SIZE_T Index = NULL; Index < ARRAYSIZE(VolumeIndex); Index++) {

				WCHAR VolumeGuidPath[MAX_PATH] = { NULL };

				RtlZeroMemoryEx(VolumeGuidPath, sizeof(VolumeGuidPath));

				Result = RtlStringCbPrintfW(VolumeGuidPath, sizeof(VolumeGuidPath), L"\\??\\%ws:\\System Volume Information\\IndexerVolumeGuid", VolumeIndex[Index]);

				if (NT_SUCCESS(Result)) {

					Result = ZwQueryFileEx(VolumeGuidPath);

					if (NT_SUCCESS(Result)) {

						RtlRandomAnsiGuid(pSpoofBuffer, MAX_PATH, TRUE);

						Result = ZwWriteFileEx(VolumeGuidPath, pSpoofBuffer, (ULONG)(strlen(pSpoofBuffer)));

						Enable = TRUE;
					}
				}
			}

			for (SIZE_T Index = NULL; Index < ARRAYSIZE(VolumeIndex); Index++) {

				WCHAR VolumeGuidPath[MAX_PATH] = { NULL };

				RtlZeroMemoryEx(VolumeGuidPath, sizeof(VolumeGuidPath));

				Result = RtlStringCbPrintfW(VolumeGuidPath, sizeof(VolumeGuidPath), L"\\??\\%ws:\\System Volume Information\\WPSSettings.data", VolumeIndex[Index]);

				if (NT_SUCCESS(Result)) {

					Result = ZwQueryFileEx(VolumeGuidPath);

					if (NT_SUCCESS(Result)) {

						RtlRandomAnsiGuid(pSpoofBuffer, MAX_PATH, FALSE);

						Result = ZwWriteFileEx(VolumeGuidPath, pSpoofBuffer, (ULONG)(strlen(pSpoofBuffer)));

						Enable = TRUE;
					}
				}
			}

			RtlFreeMemoryEx(pSpoofBuffer);
		}

		//VMProtectEnd();
	}

	if (Enable != FALSE) {

		Result = STATUS_SUCCESS;
	}

	return Result;
}

auto SpoofVolumesEx()->NTSTATUS {

	static BOOLEAN Enable = FALSE;

	NTSTATUS Result = STATUS_SUCCESS;

	if (Enable == FALSE) {

		//VMProtectBeginMutation(__FUNCTION__);

		UNICODE_STRING ObjeName = RTL_CONSTANT_STRING(L"\\Driver\\mountmgr");

		PDRIVER_OBJECT DriverObj = NULL;

		Result = ZwReferenceObjectByName(&ObjeName, OBJ_CASE_INSENSITIVE, 0, 0, *IoDriverObjectType, KernelMode, 0, &DriverObj);

		if (NT_SUCCESS(Result)) {

			*(LPVOID*)&DriverObj->MajorFunction[28] = InterlockedExchangePointer((LPVOID*)&DriverObj->MajorFunction[14], (LPVOID)SpoofMountControl);

			ObfDereferenceObject(DriverObj);

			Enable = TRUE;
		}

		//VMProtectEnd();
	}

	if (Enable != FALSE) {

		Result = STATUS_SUCCESS;
	}

	return Result;
}

auto SpoofInitialize(ULONG Type)->NTSTATUS {

	switch (Type) {
	case 0: {
		SpoofReg();
		SpoofHdd();
		SpoofNic();
		SpoofFile();
		SpoofNdis();
		SpoofNsiEx();
		SpoofGpuEx();
		SpoofPartEx();
		SpoofDiskEx();
		SpoofSmbios();
		SpoofVolumes();
		SpoofVolumesEx();
		break;
	}
	case 1: {
		SpoofReg();
		break;
	}
	case 2: {
		SpoofHdd();
		break;
	}
	case 3: {
		SpoofNic();
		break;
	}
	case 4: {
		SpoofFile();
		break;
	}
	case 5: {
		SpoofNdis();
		break;
	}
	case 6: {
		SpoofNsiEx();
		break;
	}
	case 7: {
		SpoofGpuEx();
		break;
	}
	case 8: {
		SpoofPartEx();
		break;
	}
	case 9: {
		SpoofDiskEx();
		break;
	}
	case 10: {
		SpoofSmbios();
		break;
	}
	case 11: {
		SpoofVolumes();
		break;
	}
	case 12: {
		SpoofVolumesEx();
		break;
	}
	default:
		break;
	}

	return RestartWmiPrvSE();
}