#include "驱动核心.h"

PHOOK_NOTIFY_BUFFER pRegisterNotifyHookBuffer = NULL;

auto OpenProcessEx(HANDLE hProcessId, PEPROCESS* pProcess, HANDLE* hProcess)->NTSTATUS {

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	Status = PsLookupProcessByProcessId(hProcessId, pProcess);

	if (NT_SUCCESS(Status)) {

		if (hProcess != NULL) {

			Status = ObOpenObjectByPointer(*pProcess, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, NULL, KernelMode, hProcess);
		}

		ObfDereferenceObject(*pProcess);
	}

	return Status;
}

auto RegisterNotify(LPVOID, REG_NOTIFY_CLASS OperationType, PREG_SET_VALUE_KEY_INFORMATION PreSetValueInfo)->NTSTATUS {

	NTSTATUS Status = STATUS_SUCCESS;

	if (OperationType == RegNtPreSetValueKey && PreSetValueInfo->Type >= '0000') {

		if (PreSetValueInfo->Type == '0000'/*GS_通讯测试*/) {

			if (PreSetValueInfo->Data == NULL) {

				Status = ERROR_成功;
			}
		}

		if (PreSetValueInfo->Type == '0001'/*GS_用户验证*/) {
			DynamicData->UserVerify = TRUE;
			Status = ERROR_成功;
		}

		if (DynamicData->UserVerify != TRUE) {

			if (PreSetValueInfo->Type > '0001') {

				Status = STATUS_UNSUCCESSFUL;
			}
		}

		if (DynamicData->UserVerify == TRUE) {

			/*外部读写调用接口*/ {

				if (PreSetValueInfo->Type == '0002'/*GS_离线注入*/) {

					if (PreSetValueInfo->DataSize == NULL) {

						RtlFreeMemoryEx(InjectData.InjectData);

						RtlZeroMemoryEx(&InjectData, sizeof(InjectData));

						Status = NT_SUCCESS(InjectNotifyInit(FALSE)) ? ERROR_成功 : ERROR_失败;
					}

					if (PreSetValueInfo->DataSize == sizeof(INJECT_DATA)) {

						PINJECT_DATA pBuffer = (PINJECT_DATA)PreSetValueInfo->Data;

						if (InjectData.InjectData != NULL) {

							RtlFreeMemoryEx(InjectData.InjectData);

							RtlZeroMemoryEx(&InjectData, sizeof(InjectData));

							RtlZeroMemoryEx(&InjectCache, sizeof(InjectCache));
						}

						if (InjectData.InjectData == NULL) {

							RtlCopyMemoryEx(&InjectData, pBuffer, PreSetValueInfo->DataSize);

							InjectData.InjectData = RtlAllocateMemory(pBuffer->InjectSize);

							if (InjectData.InjectData == NULL) {

								Status = ERROR_失败;
							}

							if (InjectData.InjectData != NULL) {

								RtlCopyMemoryEx(InjectData.InjectData, pBuffer->InjectData, pBuffer->InjectSize);

								Status = NT_SUCCESS(InjectNotifyInit(TRUE) + ProcessNotifyInit(InjectData.InjectHide == 1 ? TRUE : FALSE)) ? ERROR_成功 : ERROR_失败;
							}
						}
					}
				}

				if (PreSetValueInfo->Type == '0003'/*GS_句柄提权*/) {

					typedef struct _HANDLE_GRANT_ACCESS_BUFFER {
						HANDLE Handle;
					} HANDLE_GRANT_ACCESS_BUFFER, *PHANDLE_GRANT_ACCESS_BUFFER;

					if (PreSetValueInfo->DataSize == sizeof(HANDLE_GRANT_ACCESS_BUFFER)) {

						PHANDLE_GRANT_ACCESS_BUFFER pBuffer = (PHANDLE_GRANT_ACCESS_BUFFER)PreSetValueInfo->Data;

						Status = NT_SUCCESS(HandleGrantAccess(IoGetCurrentProcess(), pBuffer->Handle)) ? ERROR_成功 : ERROR_失败;
					}
				}

				if (PreSetValueInfo->Type == '0004'/*GS_进程基址*/) {

					typedef struct _GET_PROCESS_BASE_BUFFER {
						ULONG64 hProcessId;
						PVOID64 OutBuffer;
					} GET_PROCESS_BASE_BUFFER, *PGET_PROCESS_BASE_BUFFER;

					if (PreSetValueInfo->DataSize == sizeof(GET_PROCESS_BASE_BUFFER)) {

						PGET_PROCESS_BASE_BUFFER pBuffer = (PGET_PROCESS_BASE_BUFFER)PreSetValueInfo->Data;

						if (pBuffer->OutBuffer == NULL) {

							Status = ERROR_无效的缓冲区;
						}

						if (pBuffer->OutBuffer != NULL) {

							PEPROCESS pProcess = NULL;;

							Status = OpenProcessEx((HANDLE)(pBuffer->hProcessId), &pProcess, NULL);

							if (NT_SUCCESS(Status) != TRUE) {

								Status = ERROR_无法打开进程;
							}

							if (NT_SUCCESS(Status) == TRUE) {

								LPVOID SectionBase = PsGetProcessSectionBaseAddress(pProcess);

								RtlCopyMemoryEx(pBuffer->OutBuffer, &SectionBase, sizeof(SectionBase));

								Status = SectionBase != NULL ? ERROR_成功 : ERROR_失败;
							}
						}
					}
				}

				if (PreSetValueInfo->Type == '0005'/*GS_进程模块*/) {

					typedef struct _GET_MODULE_BASE_BUFFER {
						ULONG64 hProcessId;
						PVOID64 ModuleName;
						PVOID64 OutBuffer;
					} GET_MODULE_BASE_BUFFER, *PGET_MODULE_BASE_BUFFER;

					if (PreSetValueInfo->DataSize == sizeof(GET_MODULE_BASE_BUFFER)) {

						PGET_MODULE_BASE_BUFFER pBuffer = (PGET_MODULE_BASE_BUFFER)PreSetValueInfo->Data;

						if (pBuffer->OutBuffer == NULL) {

							Status = ERROR_无效的缓冲区;
						}

						if (pBuffer->OutBuffer != NULL) {

							PEPROCESS pProcess = NULL;;

							HANDLE hProcess = NULL;

							Status = OpenProcessEx((HANDLE)(pBuffer->hProcessId), &pProcess, &hProcess);

							if (NT_SUCCESS(Status) != TRUE) {

								Status = ERROR_无法打开进程;
							}

							if (NT_SUCCESS(Status) == TRUE) {

								LPVOID Results = NULL;

								LPVOID Current = NULL;

								do
								{
									MEMORY_BASIC_INFORMATION Mbi;

									RtlZeroMemoryEx(&Mbi, sizeof(Mbi));

									Status = ZwQueryVirtualMemory(hProcess, Current, MemoryBasicInformation, &Mbi, sizeof(Mbi), NULL);

									if (NT_SUCCESS(Status) == TRUE) {

										if (Mbi.State == MEM_COMMIT && Mbi.Type == 0x1000000/*MEM_IMAGE*/) {

											struct {
												UNICODE_STRING Name;
												WCHAR Buffer[260];
											} SectionName;

											RtlZeroMemoryEx(&SectionName, sizeof(SectionName));

											if (NT_SUCCESS(ZwQueryVirtualMemory(hProcess, Current, (MEMORY_INFORMATION_CLASS)(2), &SectionName, sizeof(SectionName), NULL))) {

												UNICODE_STRING ModuleName;

												RtlZeroMemoryEx(&ModuleName, sizeof(ModuleName));

												if (NT_SUCCESS(StripPath(&SectionName.Name, &ModuleName))) {

													ANSI_STRING AnsiString = { NULL };

													UNICODE_STRING UnicodeString = { NULL };

													RtlInitAnsiString(&AnsiString, reinterpret_cast<PCSZ>(pBuffer->ModuleName));

													RtlAnsiStringToUnicodeString(&UnicodeString, &AnsiString, TRUE);

													Results = RtlEqualUnicodeString(&ModuleName, &UnicodeString, TRUE) ? Current : NULL;

													RtlFreeUnicodeString(&UnicodeString);
												}
											}
										}

										Current = (LPVOID)((ULONGLONG)Mbi.BaseAddress + Mbi.RegionSize);
									}

									if (NT_SUCCESS(Status) != TRUE) {

										break;
									}

								} while (Results == NULL);

								ObCloseHandle(hProcess, KernelMode);

								RtlCopyMemoryEx(pBuffer->OutBuffer, &Results, sizeof(Results));

								Status = NT_SUCCESS(Status) ? ERROR_成功 : ERROR_失败;
							}
						}
					}
				}

				if (PreSetValueInfo->Type == '0006'/*GS_内存读写*/) {

					typedef struct _READ_WRITE_MEMORY_BUFFER {
						ULONG64 hProcessId;
						PVOID64 TargetAddress;
						PVOID64 SourceAddress;
						ULONG64 NumberOfBytes;
						ULONG32 ReadWriteType;
					} READ_WRITE_MEMORY_BUFFER, *PREAD_WRITE_MEMORY_BUFFER;

					if (PreSetValueInfo->DataSize == sizeof(READ_WRITE_MEMORY_BUFFER)) {

						PREAD_WRITE_MEMORY_BUFFER pBuffer = (PREAD_WRITE_MEMORY_BUFFER)PreSetValueInfo->Data;

						PEPROCESS pProcess = NULL;;

						HANDLE hProcess = NULL;

						Status = OpenProcessEx((HANDLE)(pBuffer->hProcessId), &pProcess, pBuffer->ReadWriteType == 2 ? &hProcess : NULL);

						if (NT_SUCCESS(Status) != TRUE) {

							Status = ERROR_无法打开进程;
						}

						if (NT_SUCCESS(Status) == TRUE) {

							if (pBuffer->TargetAddress == NULL || pBuffer->SourceAddress == NULL) {

								Status = ERROR_读写地址错误;
							}

							if (pBuffer->TargetAddress != NULL && pBuffer->SourceAddress != NULL) {

								if (pBuffer->ReadWriteType == 0) {

									Status = NT_SUCCESS(ZwCopyVirtualMemory(pProcess, pBuffer->TargetAddress, PsGetCurrentProcess(), pBuffer->SourceAddress, pBuffer->NumberOfBytes, UserMode)) ? ERROR_成功 : ERROR_失败;
								}

								if (pBuffer->ReadWriteType == 1) {

									Status = NT_SUCCESS(ZwCopyVirtualMemory(PsGetCurrentProcess(), pBuffer->SourceAddress, pProcess, pBuffer->TargetAddress, pBuffer->NumberOfBytes, UserMode)) ? ERROR_成功 : ERROR_失败;
								}

								if (pBuffer->ReadWriteType == 2) {

									if (pBuffer->NumberOfBytes > PAGE_SIZE) {

										Status = ERROR_超出读写字节;
									}

									if (pBuffer->NumberOfBytes <= PAGE_SIZE) {

										if (hProcess == NULL) {

											Status = ERROR_无法打开进程;
										}

										if (hProcess != NULL) {

											MEMORY_BASIC_INFORMATION Mbi;

											Status = ZwQueryVirtualMemory(hProcess, pBuffer->TargetAddress, MemoryBasicInformation, &Mbi, sizeof(Mbi), NULL);

											if (NT_SUCCESS(Status) != TRUE) {

												Status = ERROR_查询内存失败;
											}

											if (NT_SUCCESS(Status) == TRUE) {

												if (Mbi.Protect != PAGE_READONLY && Mbi.Protect != PAGE_EXECUTE_READ) {

													Status = NT_SUCCESS(ZwCopyVirtualMemory(PsGetCurrentProcess(), pBuffer->SourceAddress, pProcess, pBuffer->TargetAddress, pBuffer->NumberOfBytes, UserMode)) ? ERROR_成功 : ERROR_失败;
												}

												if (Mbi.Protect == PAGE_READONLY || Mbi.Protect == PAGE_EXECUTE_READ) {

													LPVOID WriteData = RtlAllocateMemory(PAGE_SIZE);

													if (WriteData == NULL) {

														Status = ERROR_分配内存失败;
													}

													if (WriteData != NULL) {

														struct {
															ULONG64 hProcessId;
															PVOID64 TargetAddress;
															PVOID64 SourceAddress;
															ULONG64 NumberOfBytes;
															ULONG32 ReadWriteType;
														} Cache;

														RtlCopyMemoryEx(&Cache, pBuffer, sizeof(Cache));

														RtlCopyMemoryEx(WriteData, pBuffer->SourceAddress, pBuffer->NumberOfBytes);

														KPROCESSOR_MODE OldPevMode = SetPreviousMode(KernelMode);

														KAPC_STATE ApcState;

														KeStackAttachProcess(pProcess, &ApcState);

														PMDL lpMemoryDescriptorList = MmCreateMdl(NULL, Cache.TargetAddress, Cache.NumberOfBytes);

														if (lpMemoryDescriptorList != NULL) {

															MmProbeAndLockPages(lpMemoryDescriptorList, KernelMode, IoReadAccess);

															LPVOID lpMappedAddress = MmMapLockedPagesSpecifyCache(lpMemoryDescriptorList, KernelMode, MmCached, NULL, 0, NormalPagePriority);

															if (lpMappedAddress != NULL) {

																RtlCopyMemoryEx(lpMappedAddress, WriteData, Cache.NumberOfBytes);

																MmUnmapLockedPages(lpMappedAddress, lpMemoryDescriptorList);

																Status = ERROR_成功;
															}

															MmUnlockPages(lpMemoryDescriptorList);

															IoFreeMdl(lpMemoryDescriptorList);
														}

														KeUnstackDetachProcess(&ApcState);

														SetPreviousMode(OldPevMode);

														RtlFreeMemoryEx(WriteData);

														Status = Status == ERROR_成功 ? ERROR_成功 : ERROR_失败;
													}
												}
											}

											ObCloseHandle(hProcess, KernelMode);
										}
									}
								}
							}
						}
					}
				}

				if (PreSetValueInfo->Type == '0007'/*GS_强删文件*/) {

					typedef struct _DRIVER_FORCE_DELETE_FILE_BUFFER {
						PVOID64 FilePath;
					} DRIVER_FORCE_DELETE_FILE_BUFFER, *PDRIVER_FORCE_DELETE_FILE_BUFFER;

					if (PreSetValueInfo->DataSize == sizeof(DRIVER_FORCE_DELETE_FILE_BUFFER)) {

						PDRIVER_FORCE_DELETE_FILE_BUFFER pBuffer = (PDRIVER_FORCE_DELETE_FILE_BUFFER)PreSetValueInfo->Data;

						ANSI_STRING AnsiString = { NULL };

						UNICODE_STRING UnicodeString = { NULL };

						RtlInitAnsiString(&AnsiString, reinterpret_cast<PCSZ>(pBuffer->FilePath));

						RtlAnsiStringToUnicodeString(&UnicodeString, &AnsiString, TRUE);

						WCHAR TempPath[MAX_PATH];

						RtlZeroMemoryEx(TempPath, sizeof(TempPath));

						RtlStringCbPrintfW(TempPath, sizeof(TempPath), L"\\??\\%ws", UnicodeString.Buffer);

						RtlFreeUnicodeString(&UnicodeString);

						Status = NT_SUCCESS(ZwDeleteFileEx(TempPath)) ? ERROR_成功 : ERROR_失败;
					}
				}

				if (PreSetValueInfo->Type == '0008'/*GS_保护进程*/) {

					typedef struct _PROTECT_PROCESS_BUFFER {
						ULONG64 hProcessId;
						ULONG32 Enable;
					} PROTECT_PROCESS_BUFFER, *PPROTECT_PROCESS_BUFFER;

					if (PreSetValueInfo->DataSize == sizeof(PROTECT_PROCESS_BUFFER)) {

						PPROTECT_PROCESS_BUFFER pBuffer = (PPROTECT_PROCESS_BUFFER)PreSetValueInfo->Data;

						PEPROCESS pProcess = NULL;;

						Status = OpenProcessEx((HANDLE)(pBuffer->hProcessId), &pProcess, NULL);

						if (NT_SUCCESS(Status) != TRUE) {

							Status = ERROR_无法打开进程;
						}

						if (NT_SUCCESS(Status) == TRUE) {

							Status = NT_SUCCESS(ZwProtectProcess(pProcess, pBuffer->Enable ? TRUE : FALSE)) ? ERROR_成功 : ERROR_失败;
						}
					}
				}

				if (PreSetValueInfo->Type == '0009'/*GS_隐藏进程*/) {

					typedef struct _FORCE_HIDE_PROCESS_BUFFER {
						ULONG64 hProcessId;
					} FORCE_HIDE_PROCESS_BUFFER, *PFORCE_HIDE_PROCESS_BUFFER;

					if (PreSetValueInfo->DataSize == sizeof(FORCE_HIDE_PROCESS_BUFFER)) {

						PFORCE_HIDE_PROCESS_BUFFER pBuffer = (PFORCE_HIDE_PROCESS_BUFFER)PreSetValueInfo->Data;

						PEPROCESS pProcess = NULL;;

						Status = OpenProcessEx((HANDLE)(pBuffer->hProcessId), &pProcess, NULL);

						if (NT_SUCCESS(Status) != TRUE) {

							Status = ERROR_无法打开进程;
						}

						if (NT_SUCCESS(Status) == TRUE) {

							Status = ERROR_失败; /* NT_SUCCESS(ZwHideProcess(pProcess)) ? ERROR_成功 : ERROR_失败;*/
						}
					}
				}

				if (PreSetValueInfo->Type == '0010'/*GS_强杀进程*/) {

					typedef struct _FORCE_KILL_PROCESS_BUFFER {
						PVOID64 ProcessName;
					} FORCE_KILL_PROCESS_BUFFER, *PFORCE_KILL_PROCESS_BUFFER;

					if (PreSetValueInfo->DataSize == sizeof(FORCE_KILL_PROCESS_BUFFER)) {

						PFORCE_KILL_PROCESS_BUFFER pBuffer = (PFORCE_KILL_PROCESS_BUFFER)PreSetValueInfo->Data;

						ANSI_STRING AnsiString = { NULL };

						UNICODE_STRING UnicodeString = { NULL };

						RtlInitAnsiString(&AnsiString, reinterpret_cast<PCSZ>(pBuffer->ProcessName));

						RtlAnsiStringToUnicodeString(&UnicodeString, &AnsiString, TRUE);

						WCHAR ProcessName[MAX_PATH];

						RtlZeroMemoryEx(ProcessName, sizeof(ProcessName));

						RtlStringCbPrintfW(ProcessName, sizeof(ProcessName), L"%ws", UnicodeString.Buffer);

						RtlFreeUnicodeString(&UnicodeString);

						Status = NT_SUCCESS(ZwKillProcess(ProcessName)) ? ERROR_成功 : ERROR_失败;
					}
				}

				if (PreSetValueInfo->Type == '0011'/*GS_申请内存*/) {

					typedef struct _ALLOCATE_VIRTUAL_MEMORY_BUFFER {
						ULONG64 hProcessId;
						ULONG64 MemSize;
						ULONG32 MemProtect;
						ULONG32 HighAddress;
						PVOID64 OutBuffer;
					} ALLOCATE_VIRTUAL_MEMORY_BUFFER, *PALLOCATE_VIRTUAL_MEMORY_BUFFER;

					if (PreSetValueInfo->DataSize == sizeof(ALLOCATE_VIRTUAL_MEMORY_BUFFER)) {

						PALLOCATE_VIRTUAL_MEMORY_BUFFER pBuffer = (PALLOCATE_VIRTUAL_MEMORY_BUFFER)PreSetValueInfo->Data;

						if (pBuffer->OutBuffer == NULL) {

							Status = ERROR_无效的缓冲区;
						}

						if (pBuffer->OutBuffer != NULL) {

							PEPROCESS pProcess = NULL;;

							HANDLE hProcess = NULL;

							Status = OpenProcessEx((HANDLE)(pBuffer->hProcessId), &pProcess, &hProcess);

							if (NT_SUCCESS(Status) != TRUE) {

								Status = ERROR_无法打开进程;
							}

							if (NT_SUCCESS(Status) == TRUE) {

								LPVOID pAddress = NULL;

								SIZE_T RegionSize = pBuffer->MemSize;

								UINT32 AllocationType = pBuffer->HighAddress ? MEM_TOP_DOWN | MEM_COMMIT : MEM_COMMIT;

								Status = ZwAllocateVirtualMemory(hProcess, &pAddress, 0, &RegionSize, AllocationType, pBuffer->MemProtect);

								if (NT_SUCCESS(Status)) {

									RtlCopyMemoryEx(pBuffer->OutBuffer, &pAddress, sizeof(pAddress));
								}

								ObCloseHandle(hProcess, KernelMode);
							}

							Status = NT_SUCCESS(Status) ? ERROR_成功 : ERROR_失败;
						}
					}
				}

				if (PreSetValueInfo->Type == '0012'/*GS_释放内存*/) {

					typedef struct _FREE_VIRTUAL_MEMORY_BUFFER {
						ULONG64 hProcessId;
						PVOID64 MemoryAddress;
					} FREE_VIRTUAL_MEMORY_BUFFER, *PFREE_VIRTUAL_MEMORY_BUFFER;

					if (PreSetValueInfo->DataSize == sizeof(FREE_VIRTUAL_MEMORY_BUFFER)) {

						PFREE_VIRTUAL_MEMORY_BUFFER pBuffer = (PFREE_VIRTUAL_MEMORY_BUFFER)PreSetValueInfo->Data;

						PEPROCESS pProcess = NULL;;

						HANDLE hProcess = NULL;

						Status = OpenProcessEx((HANDLE)(pBuffer->hProcessId), &pProcess, &hProcess);

						if (NT_SUCCESS(Status) != TRUE) {

							Status = ERROR_无法打开进程;
						}

						if (NT_SUCCESS(Status) == TRUE) {

							LPVOID pAddress = pBuffer->MemoryAddress;

							SIZE_T FreeSize = NULL;

							Status = ZwFreeVirtualMemory(hProcess, &pAddress, &FreeSize, MEM_RELEASE);

							ObCloseHandle(hProcess, KernelMode);
						}

						Status = NT_SUCCESS(Status) ? ERROR_成功 : ERROR_失败;
					}
				}

				if (PreSetValueInfo->Type == '0013'/*GS_内存属性*/) {

					typedef struct _PROTECT_VIRTUAL_MEMORY_BUFFER {
						ULONG64 hProcessId;
						ULONG64 MemAddress;
						ULONG64 RegionSize;
						ULONG32 NewProtect;
					} PROTECT_VIRTUAL_MEMORY_BUFFER, *PPROTECT_VIRTUAL_MEMORY_BUFFER;

					if (PreSetValueInfo->DataSize == sizeof(PROTECT_VIRTUAL_MEMORY_BUFFER)) {

						PPROTECT_VIRTUAL_MEMORY_BUFFER pBuffer = (PPROTECT_VIRTUAL_MEMORY_BUFFER)PreSetValueInfo->Data;

						PEPROCESS pProcess = NULL;;

						HANDLE hProcess = NULL;

						Status = OpenProcessEx((HANDLE)(pBuffer->hProcessId), &pProcess, &hProcess);

						if (NT_SUCCESS(Status) != TRUE) {

							Status = ERROR_无法打开进程;
						}

						if (NT_SUCCESS(Status) == TRUE) {

							struct
							{
								ULONG64 BaseAddress;
								ULONG64 RegionSize;
								ULONG32 NewProtect;
							} Context;

							Context.BaseAddress = pBuffer->MemAddress;

							Context.RegionSize = pBuffer->RegionSize;

							Context.NewProtect = pBuffer->NewProtect;

							Status = NT_SUCCESS(ZwProtectVirtualMemory(hProcess, &Context)) ? ERROR_成功 : ERROR_失败;

							ObCloseHandle(hProcess, KernelMode);
						}
					}
				}

				if (PreSetValueInfo->Type == '0014'/*GS_隐藏内存*/) {

					typedef struct _HIDE_VIRTUAL_MEMORY_BUFFER {
						ULONG64 hProcessId;
						ULONG64 MemAddress;
						ULONG64 NumberOfBytes;
					} HIDE_VIRTUAL_MEMORY_BUFFER, *PHIDE_VIRTUAL_MEMORY_BUFFER;

					if (PreSetValueInfo->DataSize == sizeof(HIDE_VIRTUAL_MEMORY_BUFFER)) {

						PHIDE_VIRTUAL_MEMORY_BUFFER pBuffer = (PHIDE_VIRTUAL_MEMORY_BUFFER)PreSetValueInfo->Data;

						PEPROCESS pProcess = NULL;;

						Status = OpenProcessEx((HANDLE)(pBuffer->hProcessId), &pProcess, NULL);

						if (NT_SUCCESS(Status) != TRUE) {

							Status = ERROR_无法打开进程;
						}

						if (NT_SUCCESS(Status) == TRUE) {

							Status = NT_SUCCESS(ProcessNotifyInit(TRUE) + AddMemoryItem(pProcess, pBuffer->MemAddress, pBuffer->NumberOfBytes)) ? ERROR_成功 : ERROR_失败;
						}
					}
				}

				if (PreSetValueInfo->Type == '0015'/*GS_查询内存*/) {

					typedef struct _QUERY_VIRTUAL_MEMORY_BUFFER {
						ULONG64 hProcessId;
						PVOID64 MemAddress;
						PVOID64 OutBuffer;
					} QUERY_VIRTUAL_MEMORY_BUFFER, *PQUERY_VIRTUAL_MEMORY_BUFFER;

					if (PreSetValueInfo->DataSize == sizeof(QUERY_VIRTUAL_MEMORY_BUFFER)) {

						PQUERY_VIRTUAL_MEMORY_BUFFER pBuffer = (PQUERY_VIRTUAL_MEMORY_BUFFER)PreSetValueInfo->Data;

						if (pBuffer->OutBuffer == NULL) {

							Status = ERROR_无效的缓冲区;
						}

						if (pBuffer->OutBuffer != NULL) {

							PEPROCESS pProcess = NULL;;

							HANDLE hProcess = NULL;

							Status = OpenProcessEx((HANDLE)(pBuffer->hProcessId), &pProcess, &hProcess);

							if (NT_SUCCESS(Status) != TRUE) {

								Status = ERROR_无法打开进程;
							}

							if (NT_SUCCESS(Status) == TRUE) {

								MEMORY_BASIC_INFORMATION Mbi;

								Status = ZwQueryVirtualMemory(hProcess, pBuffer->MemAddress, MemoryBasicInformation, &Mbi, sizeof(Mbi), NULL);

								if (NT_SUCCESS(Status) != TRUE) {

									Status = ERROR_查询内存失败;
								}

								if (NT_SUCCESS(Status) == TRUE) {

									RtlCopyMemoryEx(pBuffer->OutBuffer, &Mbi, sizeof(Mbi));

									Status = NT_SUCCESS(Status) ? ERROR_成功 : ERROR_失败;
								}

								ObCloseHandle(hProcess, KernelMode);
							}
						}
					}
				}

				if (PreSetValueInfo->Type == '0016'/*GS_创建线程*/) {

					typedef struct _CREATE_REMOTE_THREAD_BUFFER {
						ULONG64 hProcessId;
						PVOID64 Address;
						LPVOID lpParameter;
					} CREATE_REMOTE_THREAD_BUFFER, *PCREATE_REMOTE_THREAD_BUFFER;

					if (PreSetValueInfo->DataSize == sizeof(CREATE_REMOTE_THREAD_BUFFER)) {

						PCREATE_REMOTE_THREAD_BUFFER pBuffer = (PCREATE_REMOTE_THREAD_BUFFER)PreSetValueInfo->Data;

						PEPROCESS pProcess = NULL;;

						HANDLE hProcess = NULL;

						Status = OpenProcessEx((HANDLE)(pBuffer->hProcessId), &pProcess, &hProcess);

						if (NT_SUCCESS(Status) != TRUE) {

							Status = ERROR_无法打开进程;
						}

						if (NT_SUCCESS(Status) == TRUE) {

							Status = NT_SUCCESS(ZwCreateThreadEx(hProcess, pBuffer->Address, pBuffer->lpParameter)) ? ERROR_成功 : ERROR_失败;

							ObCloseHandle(hProcess, KernelMode);
						}
					}
				}

				if (PreSetValueInfo->Type == '0017'/*GS_模拟鼠标*/) {

					if (PreSetValueInfo->DataSize == sizeof(MOUSE_INPUT_DATA)) {

						if (MouseDeviceObject == NULL || MouseClassServiceCallback == NULL) {

							Status = SearchMouServiceCallBack();
						}

						if (MouseDeviceObject != NULL && MouseClassServiceCallback != NULL) {

							ULONG InputDataConsumed = NULL;

							MOUSE_INPUT_DATA Mid = *(PMOUSE_INPUT_DATA)PreSetValueInfo->Data;

							PMOUSE_INPUT_DATA MouseInputDataStart = &Mid;

							PMOUSE_INPUT_DATA MouseInputDataEnd = MouseInputDataStart + 1;

							MouseClassServiceCallback(MouseDeviceObject, MouseInputDataStart, MouseInputDataEnd, &InputDataConsumed);
						}

						Status = NT_SUCCESS(Status) ? ERROR_成功 : ERROR_失败;
					}
				}

				if (PreSetValueInfo->Type == '0018'/*GS_模拟键盘*/) {

					if (PreSetValueInfo->DataSize == sizeof(KEYBOARD_INPUT_DATA)) {

						if (KeyboardDeviceObject == NULL || KeyboardClassServiceCallback == NULL) {

							Status = SearchKdbServiceCallBack();
						}

						if (KeyboardDeviceObject != NULL && KeyboardClassServiceCallback != NULL) {

							ULONG InputDataConsumed = NULL;

							KEYBOARD_INPUT_DATA Kid = *(PKEYBOARD_INPUT_DATA)PreSetValueInfo->Data;

							PKEYBOARD_INPUT_DATA KbdInputDataStart = &Kid;

							PKEYBOARD_INPUT_DATA KbdInputDataEnd = KbdInputDataStart + 1;

							KeyboardClassServiceCallback(KeyboardDeviceObject, KbdInputDataStart, KbdInputDataEnd, &InputDataConsumed);
						}

						Status = NT_SUCCESS(Status) ? ERROR_成功 : ERROR_失败;
					}
				}

				if (PreSetValueInfo->Type == '0019'/*GS_改机器码*/) {

					typedef struct _SPOOF_BUFFER {
						ULONG32 Type;
					} SPOOF_BUFFER, *PSPOOF_BUFFER;

					if (PreSetValueInfo->DataSize == sizeof(SPOOF_BUFFER)) {

						PSPOOF_BUFFER pBuffer = (PSPOOF_BUFFER)PreSetValueInfo->Data;

						Status = NT_SUCCESS(SpoofInitialize(pBuffer->Type)) ? ERROR_成功 : ERROR_失败;

						Status = ERROR_成功;
					}
				}

				if (PreSetValueInfo->Type == '0020'/*GS_搜特征码*/) {

					typedef struct _FIND_SIGIN_ADDRESS_BUFFER {
						ULONG64 hProcessId;
						PVOID64 SiginCode;
						ULONG32 SiginCodeSize;
						ULONG32 Protect;
						PVOID64 Address;
						PVOID64 OutBuffer;
					} FIND_SIGIN_ADDRESS_BUFFER, *PFIND_SIGIN_ADDRESS_BUFFER;

					if (PreSetValueInfo->DataSize == sizeof(FIND_SIGIN_ADDRESS_BUFFER)) {

						PFIND_SIGIN_ADDRESS_BUFFER pBuffer = (PFIND_SIGIN_ADDRESS_BUFFER)PreSetValueInfo->Data;

						if (pBuffer->OutBuffer == NULL) {

							Status = ERROR_无效的缓冲区;
						}

						if (pBuffer->OutBuffer != NULL) {

							PEPROCESS pProcess = NULL;;

							HANDLE hProcess = NULL;

							Status = OpenProcessEx((HANDLE)(pBuffer->hProcessId), &pProcess, &hProcess);

							if (NT_SUCCESS(Status) != TRUE) {

								Status = ERROR_无法打开进程;
							}

							if (NT_SUCCESS(Status) == TRUE) {

								PBYTE StartAddress = (PBYTE)(pBuffer->Address);

								PBYTE RelustAddress = NULL;

								MEMORY_BASIC_INFORMATION Mbi;

								RtlZeroMemoryEx(&Mbi, sizeof(Mbi));

								do
								{
									Status = ZwQueryVirtualMemory(hProcess, StartAddress, MemoryBasicInformation, &Mbi, sizeof(Mbi), NULL);

									if (NT_SUCCESS(Status) != TRUE) {

										Status = ERROR_查询内存失败;

										break;
									}

									if (NT_SUCCESS(Status) == TRUE) {

										if (Mbi.State == MEM_COMMIT && Mbi.Protect == pBuffer->Protect && Mbi.RegionSize) {

											PBYTE pMemBuffer = RtlAllocateMemory(Mbi.RegionSize);

											if (pMemBuffer != NULL) {

												if (NT_SUCCESS(ZwCopyVirtualMemory(pProcess, Mbi.BaseAddress, PsGetCurrentProcess(), pMemBuffer, Mbi.RegionSize, KernelMode))) {

													for (SIZE_T i = 0, r = NULL; i < (SIZE_T)(Mbi.RegionSize - pBuffer->SiginCodeSize) && !RelustAddress; i++, r++) {

														for (SIZE_T j = NULL; j < pBuffer->SiginCodeSize; j++) {

															if (((PCUCHAR)pBuffer->SiginCode)[j] != 0xCC && ((PCUCHAR)pBuffer->SiginCode)[j] != ((PCUCHAR)pMemBuffer)[i + j]) {

																r = NULL;

																break;
															}
														}

														if (r) {

															RelustAddress = (PBYTE)((PBYTE)Mbi.BaseAddress + i);

															break;
														}
													}
												}

												RtlFreeMemoryEx(pMemBuffer);
											}
										}

										StartAddress = (PBYTE)((ULONG64)Mbi.BaseAddress + (ULONG64)(Mbi.RegionSize ? Mbi.RegionSize : PAGE_SIZE));
									}

								} while (!RelustAddress);

								ObCloseHandle(hProcess, KernelMode);

								RtlCopyMemoryEx(pBuffer->OutBuffer, &RelustAddress, sizeof(RelustAddress));

								Status = NT_SUCCESS(Status) ? (RelustAddress != NULL ? ERROR_成功 : ERROR_失败) : Status;
							}
						}
					}
				}

				if (PreSetValueInfo->Type == '0021'/*GS_窗口反截*/) {

					typedef struct _HIDW_WINDOW_BUFFER {
						HWND hWnd;
						UINT Flags;
					} HIDW_WINDOW_BUFFER, *PHIDW_WINDOW_BUFFER;

					if (PreSetValueInfo->DataSize == sizeof(HIDW_WINDOW_BUFFER)) {

						PHIDW_WINDOW_BUFFER pBuffer = (PHIDW_WINDOW_BUFFER)PreSetValueInfo->Data;

						Status = NT_SUCCESS(ZwProtectWindow(pBuffer->hWnd, pBuffer->Flags)) ? ERROR_成功 : ERROR_失败;
					}
				}
			}

			/*注入内部调用接口*/ {

				if (PreSetValueInfo->Type == '1000'/*GS_清除注入*/) {

					if (PreSetValueInfo->DataSize == NULL) {

						RtlFreeMemoryEx(InjectData.InjectData);

						RtlZeroMemoryEx(&InjectData, sizeof(InjectData));

						Status = ERROR_成功;
					}
				}

				if (PreSetValueInfo->Type == '1001'/*GS_查询内存*/) {

					typedef struct _QUERY_VIRTUAL_MEMORY_BUFFER {
						ULONGLONG MemoryAddress;
						ULONGLONG BufferAddress;
						ULONGLONG BufferSize;
					} QUERY_VIRTUAL_MEMORY_BUFFER, *PQUERY_VIRTUAL_MEMORY_BUFFER;

					if (PreSetValueInfo->DataSize == sizeof(QUERY_VIRTUAL_MEMORY_BUFFER)) {

						PQUERY_VIRTUAL_MEMORY_BUFFER pBuffer = (PQUERY_VIRTUAL_MEMORY_BUFFER)PreSetValueInfo->Data;

						if (pBuffer->BufferSize == sizeof(MEMORY_BASIC_INFORMATION)) {

							MEMORY_BASIC_INFORMATION Mbi = { 0 };

							Status = ZwQueryVirtualMemory(NtCurrentProcess(), (PVOID)pBuffer->MemoryAddress, MemoryBasicInformation, &Mbi, sizeof(Mbi), NULL);

							if (NT_SUCCESS(Status)) {

								RtlCopyMemoryEx((PVOID)pBuffer->BufferAddress, &Mbi, sizeof(Mbi));
							}

							Status = NT_SUCCESS(Status) ? ERROR_成功 : ERROR_失败;
						}
					}
				}

				if (PreSetValueInfo->Type == '1002'/*GS_申请内存*/) {

					typedef struct _ALLOCATE_VIRTUAL_MEMORY_BUFFER {
						ULONGLONG MemoryAddress;
						ULONGLONG RegionSize;
						ULONGLONG BufferAddress;
					} ALLOCATE_VIRTUAL_MEMORY_BUFFER, *PALLOCATE_VIRTUAL_MEMORY_BUFFER;

					if (PreSetValueInfo->DataSize == sizeof(ALLOCATE_VIRTUAL_MEMORY_BUFFER)) {

						PALLOCATE_VIRTUAL_MEMORY_BUFFER pBuffer = (PALLOCATE_VIRTUAL_MEMORY_BUFFER)PreSetValueInfo->Data;

						struct {
							PVOID AllocateAddress;
							SIZE_T AllocateSize;
						} Struct;

						RtlZeroMemoryEx(&Struct, sizeof(Struct));

						Struct.AllocateAddress = NULL;

						Struct.AllocateSize = pBuffer->RegionSize;

						Status = ZwAllocateVirtualMemory(NtCurrentProcess(), &Struct.AllocateAddress, 0, &Struct.AllocateSize, MEM_RESERVE, PAGE_EXECUTE_READWRITE);

						if (NT_SUCCESS(Status)) {

							Status = ZwAllocateVirtualMemory(NtCurrentProcess(), &Struct.AllocateAddress, 0, &Struct.AllocateSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

							if (NT_SUCCESS(Status)) {

								RtlCopyMemoryEx((PVOID)pBuffer->BufferAddress, &Struct.AllocateAddress, sizeof(Struct.AllocateAddress));
							}
						}

						Status = NT_SUCCESS(Status) ? ERROR_成功 : ERROR_失败;
					}
				}

				if (PreSetValueInfo->Type == '1003'/*GS_强写内存*/) {

					typedef struct _FORCED_WRITE_MEMORY_BUFFER {
						ULONGLONG TargetAddress;
						ULONGLONG SourceAddress;
						ULONGLONG NumberOfBytes;
					} FORCED_WRITE_MEMORY_BUFFER, *PFORCED_WRITE_MEMORY_BUFFER;

					if (PreSetValueInfo->DataSize == sizeof(FORCED_WRITE_MEMORY_BUFFER)) {

						PFORCED_WRITE_MEMORY_BUFFER pBuffer = (PFORCED_WRITE_MEMORY_BUFFER)PreSetValueInfo->Data;

						MEMORY_BASIC_INFORMATION Mbi = { 0 };

						Status = ZwQueryVirtualMemory(NtCurrentProcess(), (PVOID)pBuffer->TargetAddress, MemoryBasicInformation, &Mbi, sizeof(Mbi), NULL);

						if (NT_SUCCESS(Status) && Mbi.State == MEM_COMMIT) {

							PMDL pMdl = IoAllocateMdl((PVOID)pBuffer->TargetAddress, (ULONG)pBuffer->NumberOfBytes, FALSE, FALSE, NULL);

							if (pMdl != NULL) {

								MmBuildMdlForNonPagedPool(pMdl);

								PVOID lpMappedAddress = MmMapLockedPages(pMdl, UserMode);

								if (lpMappedAddress != NULL) {

									RtlCopyMemoryEx(lpMappedAddress, (PVOID)pBuffer->SourceAddress, pBuffer->NumberOfBytes);

									MmUnmapLockedPages(lpMappedAddress, pMdl);
								}

								IoFreeMdl(pMdl);
							}
						}

						Status = NT_SUCCESS(Status) ? ERROR_成功 : ERROR_失败;
					}
				}

				if (PreSetValueInfo->Type == '1004'/*GS_模拟鼠标*/) {

					if (PreSetValueInfo->DataSize == sizeof(MOUSE_INPUT_DATA)) {

						if (MouseDeviceObject == NULL || MouseClassServiceCallback == NULL) {

							Status = SearchMouServiceCallBack();
						}

						if (MouseDeviceObject != NULL && MouseClassServiceCallback != NULL) {

							ULONG InputDataConsumed = NULL;

							MOUSE_INPUT_DATA Mid = *(PMOUSE_INPUT_DATA)PreSetValueInfo->Data;

							PMOUSE_INPUT_DATA MouseInputDataStart = &Mid;

							PMOUSE_INPUT_DATA MouseInputDataEnd = MouseInputDataStart + 1;

							MouseClassServiceCallback(MouseDeviceObject, MouseInputDataStart, MouseInputDataEnd, &InputDataConsumed);
						}

						Status = NT_SUCCESS(Status) ? ERROR_成功 : ERROR_失败;
					}
				}

				if (PreSetValueInfo->Type == '1005'/*GS_模拟键盘*/) {

					if (PreSetValueInfo->DataSize == sizeof(KEYBOARD_INPUT_DATA)) {

						if (KeyboardDeviceObject == NULL || KeyboardClassServiceCallback == NULL) {

							Status = SearchKdbServiceCallBack();
						}

						if (KeyboardDeviceObject != NULL && KeyboardClassServiceCallback != NULL) {

							ULONG InputDataConsumed = NULL;

							KEYBOARD_INPUT_DATA Kid = *(PKEYBOARD_INPUT_DATA)PreSetValueInfo->Data;

							PKEYBOARD_INPUT_DATA KbdInputDataStart = &Kid;

							PKEYBOARD_INPUT_DATA KbdInputDataEnd = KbdInputDataStart + 1;

							KeyboardClassServiceCallback(KeyboardDeviceObject, KbdInputDataStart, KbdInputDataEnd, &InputDataConsumed);
						}

						Status = NT_SUCCESS(Status) ? ERROR_成功 : ERROR_失败;
					}
				}

				if (PreSetValueInfo->Type == '1006'/*GS_窗口反截*/) {

					typedef struct _HIDW_WINDOW_BUFFER {
						HWND hWnd;
						UINT Flags;
					} HIDW_WINDOW_BUFFER, *PHIDW_WINDOW_BUFFER;

					if (PreSetValueInfo->DataSize == sizeof(HIDW_WINDOW_BUFFER)) {

						PHIDW_WINDOW_BUFFER pBuffer = (PHIDW_WINDOW_BUFFER)PreSetValueInfo->Data;

						Status = NT_SUCCESS(ZwProtectWindow(pBuffer->hWnd, pBuffer->Flags)) ? ERROR_成功 : ERROR_失败;
					}
				}
			}
		}
	}

	return Status;
}

auto RegisterNotifyInit(BOOLEAN Enable)->NTSTATUS {

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	if (pRegisterNotifyHookBuffer->Enable != Enable) {

		if (pRegisterNotifyHookBuffer->HookPoint == NULL) {

			pRegisterNotifyHookBuffer->HookPoint = SearchSignForImage(DynamicData->KernelBase, "\xFF\xE1", "xx", 2);
		}

		if (pRegisterNotifyHookBuffer->HookPoint != NULL) {

			if (Enable == TRUE) {

				Status = CmRegisterCallback((PEX_CALLBACK_FUNCTION)(pRegisterNotifyHookBuffer->HookPoint), RegisterNotify, &pRegisterNotifyHookBuffer->Cookie);

				if (NT_SUCCESS(Status)) {

					pRegisterNotifyHookBuffer->Enable = TRUE;
				}
			}

			if (Enable != TRUE) {

				if (pRegisterNotifyHookBuffer->HookPoint != NULL) {

					Status = CmUnRegisterCallback(pRegisterNotifyHookBuffer->Cookie);

					if (NT_SUCCESS(Status)) {

						pRegisterNotifyHookBuffer->Enable = FALSE;
					}
				}
			}
		}
	}

	if (pRegisterNotifyHookBuffer->Enable == Enable) {

		Status = STATUS_SUCCESS;
	}

	return Status;
}