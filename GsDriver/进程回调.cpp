#include "驱动核心.h"

PHIDE_MEMORY_BUFFER pHideMemoryList;

PHOOK_NOTIFY_BUFFER pProcessNotifyHookBuffer;

auto WIN7_MiFindNodeOrParent(WIN7_PMM_AVL_TABLE Table, ULONG_PTR StartingVpn, WIN7_PMM_AVL_NODE *NodeOrParent)->ULONG {

	ULONG Relust = TableEmptyTree;

	WIN7_PMM_AVL_NODE Child;

	WIN7_PMM_AVL_NODE NodeToExamine;

	WIN7_PMMVAD_SHORT VpnCompare;

	ULONG_PTR startVpn;

	ULONG_PTR endVpn;

	if (Table->NumberGenericTableElements != 0) {

		NodeToExamine = (WIN7_PMM_AVL_NODE)(&Table->BalancedRoot);

		for (;;) {

			VpnCompare = (WIN7_PMMVAD_SHORT)NodeToExamine;

			startVpn = VpnCompare->StartingVpn;

			endVpn = VpnCompare->EndingVpn;

			if (StartingVpn < startVpn) {

				Child = NodeToExamine->LeftChild;

				if (Child != NULL) {

					NodeToExamine = Child;
				}
				else {

					*NodeOrParent = NodeToExamine;

					Relust = TableInsertAsLeft;

					break;
				}
			}
			else if (StartingVpn <= endVpn) {

				*NodeOrParent = NodeToExamine;

				Relust = TableFoundNode;

				break;
			}
			else {

				Child = NodeToExamine->RightChild;

				if (Child != NULL) {

					NodeToExamine = Child;
				}
				else {

					*NodeOrParent = NodeToExamine;

					Relust = TableInsertAsRight;

					break;
				}
			}
		};
	}

	return Relust;
}

auto WIN8_MiFindNodeOrParent(WIN8_PMM_AVL_TABLE Table, ULONG_PTR StartingVpn, WIN8_PMM_AVL_NODE *NodeOrParent)->ULONG {

	ULONG Relust = TableEmptyTree;

	WIN8_PMM_AVL_NODE Child;

	WIN8_PMM_AVL_NODE NodeToExamine;

	WIN8_PMMVAD_SHORT VpnCompare;

	ULONG_PTR startVpn;

	ULONG_PTR endVpn;

	if (Table->NumberGenericTableElements != 0) {

		NodeToExamine = (WIN8_PMM_AVL_NODE)(Table->BalancedRoot.RightChild);

		for (;;) {

			VpnCompare = (WIN8_PMMVAD_SHORT)NodeToExamine;

			startVpn = VpnCompare->StartingVpn;

			endVpn = VpnCompare->EndingVpn;

			if (StartingVpn < startVpn) {

				Child = NodeToExamine->LeftChild;

				if (Child != NULL) {

					NodeToExamine = Child;
				}
				else {

					*NodeOrParent = NodeToExamine;

					Relust = TableInsertAsLeft;

					break;
				}
			}
			else if (StartingVpn <= endVpn) {

				*NodeOrParent = NodeToExamine;

				Relust = TableFoundNode;

				break;
			}
			else {

				Child = NodeToExamine->RightChild;

				if (Child != NULL) {

					NodeToExamine = Child;
				}
				else {

					*NodeOrParent = NodeToExamine;

					Relust = TableInsertAsRight;

					break;
				}
			}
		};
	}

	return Relust;
}

auto WIN8X_MiFindNodeOrParent(WIN8X_PMM_AVL_TABLE Table, ULONG_PTR StartingVpn, WIN8X_PMM_AVL_NODE *NodeOrParent)->ULONG {

	ULONG Relust = TableEmptyTree;

	WIN8X_PMM_AVL_NODE Child;

	WIN8X_PMM_AVL_NODE NodeToExamine;

	WIN8X_PMMVAD_SHORT VpnCompare;

	ULONG_PTR startVpn;

	ULONG_PTR endVpn;

	if (Table->NumberGenericTableElements != 0) {

		NodeToExamine = (WIN8X_PMM_AVL_NODE)(Table->BalancedRoot);

		for (;;) {

			VpnCompare = (WIN8X_PMMVAD_SHORT)NodeToExamine;

			startVpn = VpnCompare->StartingVpn;

			endVpn = VpnCompare->EndingVpn;

			startVpn |= (ULONG_PTR)VpnCompare->StartingVpnHigh << 32;

			endVpn |= (ULONG_PTR)VpnCompare->EndingVpnHigh << 32;

			if (StartingVpn < startVpn) {

				Child = NodeToExamine->LeftChild;

				if (Child != NULL) {

					NodeToExamine = Child;
				}
				else {

					*NodeOrParent = NodeToExamine;

					Relust = TableInsertAsLeft;

					break;
				}
			}
			else if (StartingVpn <= endVpn) {

				*NodeOrParent = NodeToExamine;

				Relust = TableFoundNode;

				break;
			}
			else {

				Child = NodeToExamine->RightChild;

				if (Child != NULL) {

					NodeToExamine = Child;
				}
				else {

					*NodeOrParent = NodeToExamine;

					Relust = TableInsertAsRight;

					break;
				}
			}
		};
	}

	return Relust;
}

auto WIN1X_MiFindNodeOrParent(WIN1X_PMM_AVL_TABLE Table, ULONG_PTR StartingVpn, WIN1X_PMM_AVL_NODE *NodeOrParent)->ULONG {

	ULONG Relust = TableEmptyTree;

	WIN1X_PMM_AVL_NODE Child;

	WIN1X_PMM_AVL_NODE NodeToExamine;

	WIN1X_PMMVAD_SHORT VpnCompare;

	ULONG_PTR startVpn;

	ULONG_PTR endVpn;

	if (Table->NumberGenericTableElements != 0) {

		NodeToExamine = (WIN1X_PMM_AVL_NODE)(Table->BalancedRoot);

		for (;;) {

			VpnCompare = (WIN1X_PMMVAD_SHORT)NodeToExamine;

			startVpn = VpnCompare->StartingVpn;

			endVpn = VpnCompare->EndingVpn;

			startVpn |= (ULONGLONG)VpnCompare->StartingVpnHigh << 32;

			endVpn |= (ULONGLONG)VpnCompare->EndingVpnHigh << 32;

			if (StartingVpn < startVpn) {

				Child = NodeToExamine->LeftChild;

				if (Child != NULL) {

					NodeToExamine = Child;
				}
				else {

					*NodeOrParent = NodeToExamine;

					Relust = TableInsertAsLeft;

					break;
				}
			}
			else if (StartingVpn <= endVpn) {

				*NodeOrParent = NodeToExamine;

				Relust = TableFoundNode;

				break;
			}
			else {

				Child = NodeToExamine->RightChild;

				if (Child != NULL) {

					NodeToExamine = Child;
				}
				else {

					*NodeOrParent = NodeToExamine;

					Relust = TableInsertAsRight;

					break;
				}
			}
		};
	}

	return Relust;
}

auto MiRemoveNode(LPVOID Table, LPVOID Node)->NTSTATUS {

	typedef VOID(__fastcall *fn_MiRemoveNode)(LPVOID, LPVOID);

	static fn_MiRemoveNode _MiRemoveNode = NULL;

	if (_MiRemoveNode == NULL) {

		_MiRemoveNode = (fn_MiRemoveNode)(ResolveRelativeAddress(SearchSignForImage(DynamicData->KernelBase, "\x48\x8D\x96\x48\x04\x00\x00\x48\xCC\xCC\xE8", "xxxxxxxx??x", 11) + 10, 1));
	}

	if (_MiRemoveNode != NULL) {

		_MiRemoveNode(Node, Table);
	}

	return _MiRemoveNode != NULL ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

auto RtlAvlRemoveNode(LPVOID Table, LPVOID Node)->NTSTATUS {

	typedef VOID(__fastcall *fn_RtlAvlRemoveNode)(LPVOID, LPVOID);

	static fn_RtlAvlRemoveNode _RtlAvlRemoveNode = NULL;

	if (_RtlAvlRemoveNode == NULL) {

		BYTE ShellCode[] = {
			0xAD, 0x00, 0x8B, 0x00, 0x93, 0x00, 0xBE, 0x00, 0x89, 0x00, 0x93, 0x00, 0xAD, 0x00, 0x9A, 0x00, 0x92, 0x00, 0x90, 0x00, 0x89, 0x00, 0x9A, 0x00, 0xB1, 0x00, 0x90, 0x00, 0x9B, 0x00, 0x9A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
		};

		UNICODE_STRING RoutineName = { NULL };

		RtlInitUnicodeString(&RoutineName, (PCWSTR)(XorByte(ShellCode, ShellCode, sizeof(ShellCode))));

		_RtlAvlRemoveNode = (fn_RtlAvlRemoveNode)(MmGetSystemRoutineAddress(&RoutineName));
	}

	if (_RtlAvlRemoveNode != NULL) {

		_RtlAvlRemoveNode(Table, Node);
	}

	return _RtlAvlRemoveNode != NULL ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

auto VadHideMemory(PEPROCESS pProcess, UINT64 Address, SIZE_T Size, PHIDE_MEMORY_BUFFER pBuffer)->NTSTATUS {

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	if (DynamicData->VadRoot != 0) {

		if (DynamicData->WinVersion <= WINVER_7) {

			WIN7_PMM_AVL_TABLE pTable = (WIN7_PMM_AVL_TABLE)((PBYTE)pProcess + DynamicData->VadRoot);

			WIN7_PMM_AVL_NODE pNode = NULL;

			ULONGLONG VpnStart = Address >> PAGE_SHIFT;

			if (WIN7_MiFindNodeOrParent(pTable, VpnStart, &pNode) == TableFoundNode) {

				WIN7_PMMVAD_SHORT pVadShort = (WIN7_PMMVAD_SHORT)pNode;

				pBuffer->pProcess = pProcess;

				pBuffer->Address = Address;

				pBuffer->Size = Size;

				Status = MiRemoveNode(pTable, pVadShort);
			}
		}

		if (DynamicData->WinVersion == WINVER_8) {

			WIN8_PMM_AVL_TABLE pTable = (WIN8_PMM_AVL_TABLE)((PBYTE)pProcess + DynamicData->VadRoot);

			WIN8_PMM_AVL_NODE pNode = NULL;

			ULONGLONG VpnStart = Address >> PAGE_SHIFT;

			if (WIN8_MiFindNodeOrParent(pTable, VpnStart, &pNode) == TableFoundNode) {

				WIN8_PMMVAD_SHORT pVadShort = (WIN8_PMMVAD_SHORT)pNode;

				pBuffer->pProcess = pProcess;

				pBuffer->Address = Address;

				pBuffer->Size = Size;

				Status = RtlAvlRemoveNode(pTable, pVadShort);
			}
		}

		if (DynamicData->WinVersion == WINVER_8X) {

			WIN8X_PMM_AVL_TABLE pTable = (WIN8X_PMM_AVL_TABLE)((PBYTE)pProcess + DynamicData->VadRoot);

			WIN8X_PMM_AVL_NODE pNode = NULL;

			ULONGLONG VpnStart = Address >> PAGE_SHIFT;

			if (WIN8X_MiFindNodeOrParent(pTable, VpnStart, &pNode) == TableFoundNode) {

				WIN8X_PMMVAD_SHORT pVadShort = (WIN8X_PMMVAD_SHORT)pNode;

				pBuffer->pProcess = pProcess;

				pBuffer->Address = Address;

				pBuffer->Size = Size;

				Status = RtlAvlRemoveNode(pTable, pVadShort);
			}
		}

		if (DynamicData->WinVersion == WINVER_1X) {

			WIN1X_PMM_AVL_TABLE pTable = (WIN1X_PMM_AVL_TABLE)((PBYTE)pProcess + DynamicData->VadRoot);

			WIN1X_PMM_AVL_NODE pNode = NULL;

			ULONGLONG VpnStart = Address >> PAGE_SHIFT;

			if (WIN1X_MiFindNodeOrParent(pTable, VpnStart, &pNode) == TableFoundNode) {

				WIN1X_PMMVAD_SHORT pVadShort = (WIN1X_PMMVAD_SHORT)pNode;

				pBuffer->pProcess = pProcess;

				pBuffer->Address = Address;

				pBuffer->Size = Size;

				Status = RtlAvlRemoveNode(pTable, pVadShort);
			}
		}
	}

	return Status;
}

auto VadShowMemory(PHIDE_MEMORY_BUFFER Buffer)->NTSTATUS {

	return ZwAllocateVirtualMemory(ZwCurrentProcess(), (LPVOID*)&Buffer->Address, 0, &Buffer->Size, MEM_RESERVE, PAGE_NOACCESS);
}

auto DelMemoryItem(PEPROCESS pProcess)->NTSTATUS {

	NTSTATUS Status = STATUS_SUCCESS;

	if (pHideMemoryList != NULL) {

		for (SIZE_T i = NULL; i < (SIZE_T)(PAGE_SIZE / sizeof(HIDE_MEMORY_BUFFER)); i++) {

			if (pHideMemoryList[i].pProcess == pProcess) {

				VadShowMemory(&pHideMemoryList[i]);

				RtlZeroMemoryEx(&pHideMemoryList[i], sizeof(pHideMemoryList[i]));
			}
		}
	}

	return Status;
}

auto AddMemoryItem(PEPROCESS pProcess, UINT64 Address, SIZE_T Size)->NTSTATUS {

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	if (pHideMemoryList != NULL) {

		for (SIZE_T i = NULL; i < PAGE_SIZE / sizeof(HIDE_MEMORY_BUFFER); i++) {

			if (pHideMemoryList[i].pProcess == NULL) {

				Status = VadHideMemory(pProcess, Address, Size, &pHideMemoryList[i]);

				break;
			}
		}
	}

	return Status;
}

auto ProcessNotify(HANDLE ParentId, HANDLE hProcessId, BOOLEAN Create)->VOID {

	if (!KeGetCurrentIrql()) {

		if (!Create) {

			DelMemoryItem(IoGetCurrentProcess());
		}
	}
}

auto ProcessNotifyInit(ULONG Enable)->NTSTATUS {

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	if (pProcessNotifyHookBuffer->Enable != Enable) {

		if (pProcessNotifyHookBuffer->HookPoint == NULL) {

			pProcessNotifyHookBuffer->HookPoint = GetSystemDrvJumpHook(ProcessNotify, pProcessNotifyHookBuffer);
		}

		if (pProcessNotifyHookBuffer->HookPoint != NULL) {

			if (Enable == TRUE) {

				RtlSuperCopyMemory(pProcessNotifyHookBuffer->HookPoint, pProcessNotifyHookBuffer->NewBytes, sizeof(pProcessNotifyHookBuffer->NewBytes));

				Status = PsSetCreateProcessNotifyRoutine((PCREATE_PROCESS_NOTIFY_ROUTINE)(pProcessNotifyHookBuffer->HookPoint), FALSE);

				if (NT_SUCCESS(Status)) {

					pProcessNotifyHookBuffer->Enable = TRUE;
				}
			}

			if (Enable != TRUE) {

				if (pProcessNotifyHookBuffer->HookPoint != NULL) {

					Status = PsSetCreateProcessNotifyRoutine((PCREATE_PROCESS_NOTIFY_ROUTINE)(pProcessNotifyHookBuffer->HookPoint), TRUE);

					if (NT_SUCCESS(Status)) {

						RtlSuperCopyMemory(pProcessNotifyHookBuffer->HookPoint, pProcessNotifyHookBuffer->OldBytes, sizeof(pProcessNotifyHookBuffer->OldBytes));

						pProcessNotifyHookBuffer->Enable = FALSE;
					}
				}
			}
		}
	}

	if (pProcessNotifyHookBuffer->Enable == Enable) {

		Status = STATUS_SUCCESS;
	}

	return Status;
}