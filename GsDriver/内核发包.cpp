#include "驱动核心.h"

LONG WSKSocketsState = NULL;

WSK_PROVIDER_NPI WSKProviderNpi = { NULL };

WSK_REGISTRATION WSKRegistration = { NULL };

WSK_CLIENT_DISPATCH WSKClientDispatch = { NULL };

auto WSKStartup()->NTSTATUS {

	NTSTATUS Status = STATUS_ALREADY_REGISTERED;

	WSK_CLIENT_NPI WskClient;

	RtlZeroMemoryEx(&WskClient, sizeof(WskClient));

	WSKClientDispatch.Version = MAKE_WSK_VERSION(1, 0);

	WSKClientDispatch.Reserved = NULL;

	WSKClientDispatch.WskClientEvent = NULL;

	if (InterlockedCompareExchange(&WSKSocketsState, 2, 0) == 0) {

		WskClient.ClientContext = NULL;

		WskClient.Dispatch = &WSKClientDispatch;

		Status = WskRegister(&WskClient, &WSKRegistration);

		if (NT_SUCCESS(Status)) {

			Status = WskCaptureProviderNPI(&WSKRegistration, WSK_NO_WAIT, &WSKProviderNpi);

			if (NT_SUCCESS(Status)) {

				InterlockedExchange(&WSKSocketsState, 3);
			}
		}
	}

	return Status;
}

auto WSKCleanup()->NTSTATUS {

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	if (InterlockedCompareExchange(&WSKSocketsState, 3, 1) == 3) {

		WskReleaseProviderNPI(&WSKRegistration);

		WskDeregister(&WSKRegistration);

		InterlockedExchange(&WSKSocketsState, 0);

		Status = STATUS_SUCCESS;
	}

	return Status;
}

auto WSKCompletionRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp, PKEVENT CompletionEvent)->NTSTATUS {

	if (CompletionEvent != NULL) {

		KeSetEvent(CompletionEvent, IO_NO_INCREMENT, FALSE);
	}

	return STATUS_MORE_PROCESSING_REQUIRED;
}

auto WSKInitData(PIRP* pIrp, PKEVENT CompletionEvent)->NTSTATUS {

	NTSTATUS Status = STATUS_INSUFFICIENT_RESOURCES;

	*pIrp = IoAllocateIrp(1, FALSE);

	if (*pIrp != NULL) {

		KeInitializeEvent(CompletionEvent, SynchronizationEvent, FALSE);

		IoSetCompletionRoutine(*pIrp, (PIO_COMPLETION_ROUTINE)WSKCompletionRoutine, CompletionEvent, TRUE, TRUE, TRUE);

		Status = STATUS_SUCCESS;
	}

	return Status;
}

auto WSKInitBuffer(LPVOID Buffer, SIZE_T BufferSize, PWSK_BUF WskBuffer)->NTSTATUS {

	NTSTATUS Status = STATUS_INSUFFICIENT_RESOURCES;

	if (WskBuffer != NULL) {

		WskBuffer->Offset = NULL;

		WskBuffer->Length = BufferSize;

		WskBuffer->Mdl = IoAllocateMdl(Buffer, (ULONG)(BufferSize), FALSE, FALSE, NULL);

		if (WskBuffer->Mdl != NULL) {

			MmProbeAndLockPages(WskBuffer->Mdl, KernelMode, IoWriteAccess);

			Status = STATUS_SUCCESS;
		}
	}

	return Status;
}

auto WSKFreeBuffer(PWSK_BUF WskBuffer)->NTSTATUS {

	NTSTATUS Status = STATUS_INSUFFICIENT_RESOURCES;

	if (WskBuffer != NULL) {

		MmUnlockPages(WskBuffer->Mdl);

		IoFreeMdl(WskBuffer->Mdl);

		Status = STATUS_SUCCESS;
	}

	return Status;
}

auto WSKCreateSocket(PWSK_SOCKET* TcpSocket, ADDRESS_FAMILY AddressFamily, USHORT SocketType, ULONG Protocol, ULONG Flags)->NTSTATUS {

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	if (WSKSocketsState == 3) {

		PIRP Irp;

		KEVENT CompletionEvent;

		Status = WSKInitData(&Irp, &CompletionEvent);

		if (NT_SUCCESS(Status)) {

			Status = WSKProviderNpi.Dispatch->WskSocket(WSKProviderNpi.Client, AddressFamily, SocketType, Protocol, Flags, NULL, NULL, NULL, NULL, NULL, Irp);

			if (Status == STATUS_PENDING) {

				Status = KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);

				if (NT_SUCCESS(Status)) {

					if (NT_SUCCESS(Irp->IoStatus.Status)) {

						*TcpSocket = (PWSK_SOCKET)(Irp->IoStatus.Information);
					}
				}
			}

			IoFreeIrp(Irp);
		}
	}

	return Status;
}

auto WSKCloseSocket(PWSK_SOCKET WskSocket)->NTSTATUS {

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	KEVENT CompletionEvent;

	PIRP Irp;

	if (WSKSocketsState == 3) {

		if (WskSocket != NULL) {

			Status = WSKInitData(&Irp, &CompletionEvent);

			if (NT_SUCCESS(Status)) {

				Status = ((PWSK_PROVIDER_BASIC_DISPATCH)WskSocket->Dispatch)->WskCloseSocket(WskSocket, Irp);

				if (Status == STATUS_PENDING) {

					KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);

					Status = Irp->IoStatus.Status;
				}

				IoFreeIrp(Irp);
			}
		}
	}

	return Status;
}

auto WSKConnect(PWSK_SOCKET WskSocket, PSOCKADDR_IN RemoteAddress)->NTSTATUS {

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	KEVENT CompletionEvent;

	PIRP Irp;

	if (WSKSocketsState == 3) {

		if (WskSocket != NULL) {

			if (RemoteAddress != NULL) {

				Status = WSKInitData(&Irp, &CompletionEvent);

				if (NT_SUCCESS(Status)) {

					Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)WskSocket->Dispatch)->WskConnect(WskSocket, (PSOCKADDR)RemoteAddress, 0, Irp);

					if (Status == STATUS_PENDING) {

						KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);

						Status = Irp->IoStatus.Status;
					}

					IoFreeIrp(Irp);
				}
			}
		}
	}

	return Status;
}

auto WSKSend(PWSK_SOCKET WskSocket, LPVOID Buffer, SIZE_T BufferSize, ULONG Flags)->LONG {

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	KEVENT CompletionEvent;

	PIRP Irp;

	WSK_BUF WskBuffer = { NULL };

	LONG BytesSent = -1;

	if (WSKSocketsState == 3 && WskSocket && Buffer && BufferSize) {

		Status = WSKInitBuffer(Buffer, BufferSize, &WskBuffer);

		if (NT_SUCCESS(Status)) {

			Status = WSKInitData(&Irp, &CompletionEvent);

			if (NT_SUCCESS(Status)) {

				Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)WskSocket->Dispatch)->WskSend(WskSocket, &WskBuffer, Flags, Irp);

				if (Status == STATUS_PENDING) {

					KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);

					Status = Irp->IoStatus.Status;

					BytesSent = NT_SUCCESS(Status) ? (LONG)(Irp->IoStatus.Information) : -1;
				}

				IoFreeIrp(Irp);
			}

			WSKFreeBuffer(&WskBuffer);
		}
	}

	return BytesSent;
}

auto WSKRecv(PWSK_SOCKET WskSocket, LPVOID Buffer, SIZE_T BufferSize, ULONG Flags)-> LONG{

	KEVENT CompletionEvent = { NULL };

	PIRP Irp = NULL;

	WSK_BUF WskBuffer = { NULL };

	LONG BytesReceived = -1;

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	if (WSKSocketsState == 3 && WskSocket && Buffer && BufferSize) {

		Status = WSKInitBuffer(Buffer, BufferSize, &WskBuffer);

		if (NT_SUCCESS(Status)) {

			Status = WSKInitData(&Irp, &CompletionEvent);

			if (NT_SUCCESS(Status)) {

				Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)WskSocket->Dispatch)->WskReceive(WskSocket, &WskBuffer, Flags, Irp);

				if (Status == STATUS_PENDING) {

					KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);

					Status = Irp->IoStatus.Status;
					
					BytesReceived = NT_SUCCESS(Status) ? (LONG)(Irp->IoStatus.Information) : -1;
				}

				IoFreeIrp(Irp);
			}

			WSKFreeBuffer(&WskBuffer);
		}
	}

	return BytesReceived;
}

auto WSKBind(PWSK_SOCKET WskSocket, PSOCKADDR_IN LocalAddress)->NTSTATUS {

	KEVENT CompletionEvent = { NULL };

	PIRP Irp = NULL;

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	if (WSKSocketsState == 3 && WskSocket && LocalAddress) {

		Status = WSKInitData(&Irp, &CompletionEvent);

		if (NT_SUCCESS(Status)) {

			Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)WskSocket->Dispatch)->WskBind(WskSocket, (PSOCKADDR)LocalAddress, 0, Irp);

			if (Status == STATUS_PENDING) {

				KeWaitForSingleObject(&CompletionEvent, Executive, KernelMode, FALSE, NULL);

				Status = Irp->IoStatus.Status;
			}

			IoFreeIrp(Irp);
		}
	}

	return Status;
}

auto HttpPost(ULONG IP1, ULONG IP2, ULONG IP3, ULONG IP4, SHORT Port, LPVOID SendBuffer, SIZE_T SendSize, LPVOID RecvBuffer, SIZE_T RecvSize)->NTSTATUS {

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	PWSK_SOCKET TcpSocket = NULL;

	Status = WSKStartup();

	if (NT_SUCCESS(Status)) {

		Status = WSKCreateSocket(&TcpSocket, AF_INET, SOCK_STREAM, IPPROTO_TCP, WSK_FLAG_CONNECTION_SOCKET);

		if (NT_SUCCESS(Status)) {

			SOCKADDR_IN LocalAddr;

			RtlZeroMemoryEx(&LocalAddr, sizeof(LocalAddr));

			LocalAddr.sin_family = AF_INET;

			LocalAddr.sin_addr.s_addr = INADDR_ANY;

			Status = WSKBind(TcpSocket, &LocalAddr);

			if (NT_SUCCESS(Status)) {

				SOCKADDR_IN RemoteAddr;

				RtlZeroMemoryEx(&RemoteAddr, sizeof(RemoteAddr));

				RemoteAddr.sin_family = AF_INET;

				RemoteAddr.sin_addr.s_addr = (ULONG)(IP1 + (IP2 << 8) + (IP3 << 16) + (IP4 << 24));

				RemoteAddr.sin_port = (USHORT)((Port & 0xFF) << 8 | (Port & 0xFF00) >> 8);

				Status = WSKConnect(TcpSocket, &RemoteAddr);

				if (NT_SUCCESS(Status)) {

					WSKSend(TcpSocket, SendBuffer, SendSize, 0);

					WSKRecv(TcpSocket, RecvBuffer, RecvSize, 0);
				}
			}

			WSKCloseSocket(TcpSocket);
		}

		WSKCleanup();
	}

	return Status;
}