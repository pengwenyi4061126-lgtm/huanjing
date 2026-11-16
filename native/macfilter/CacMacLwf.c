#include <ntifs.h>
#include <ndis.h>
#include <ntddndis.h>
#include <ntstrsafe.h>
#include "CacMacLwfIoctl.h"

/*
 * CacMacLwf - NDIS 6 lightweight filter that rewrites MAC OID query results
 * to the active profile MAC.
 *
 * This is the supported replacement for attaching generic filter device
 * objects to NDIS miniports (which received short-stack IRPs and caused
 * 0x18 / 0xEF bugchecks). NDIS allocates and drives every request here, so
 * there is no manual IRP handling on the data path.
 *
 * Scope: query results only. The on-wire source MAC is untouched - what
 * Claude reads (GetAdaptersAddresses is userland-covered; ring-0 readers
 * use OID queries) is what gets rewritten.
 */

#define CAC_MAC_POOL_TAG 'fMCC'

/* Trimmed WDK NuGet ndis.h lacks these revision values and Wi-Fi OIDs. */
#ifndef NDIS_FILTER_DRIVER_CHARACTERISTICS_REVISION_2
#define NDIS_FILTER_DRIVER_CHARACTERISTICS_REVISION_2 2
#endif
#ifndef NDIS_FILTER_DRIVER_CHARACTERISTICS_REVISION_1
#define NDIS_FILTER_DRIVER_CHARACTERISTICS_REVISION_1 1
#endif
#ifndef OID_802_11_MAC_ADDRESS
#define OID_802_11_MAC_ADDRESS 0x0D010004u
#endif
#ifndef OID_802_11_PERMANENT_ADDRESS
#define OID_802_11_PERMANENT_ADDRESS 0x0D010005u
#endif

typedef struct _CAC_MAC_FILTER_CTX {
    NDIS_HANDLE NdisFilterHandle;
    BOOLEAN Running;
} CAC_MAC_FILTER_CTX;

static NDIS_HANDLE g_FilterDriverHandle = NULL;
static PDEVICE_OBJECT g_ControlDevice = NULL;
static BOOLEAN g_SymlinkCreated = FALSE;
static KSPIN_LOCK g_MacLock;
static BOOLEAN g_MacLockInit = FALSE;
static UCHAR g_Mac[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
static ULONG g_SetCount = 0;
static ULONG g_OidSeen = 0;
static ULONG g_OidRewrites = 0;
static ULONG g_Attached = 0;
static ULONG g_Detached = 0;
static ULONG g_RegisterStatus = 0xFFFFFFFFu;

static NDIS_STATUS
CacMacFilterAttach(
    _In_ NDIS_HANDLE NdisFilterHandle,
    _In_ NDIS_HANDLE FilterDriverContext,
    _In_ PNDIS_FILTER_ATTACH_PARAMETERS AttachParameters
    )
{
    NDIS_FILTER_ATTRIBUTES attributes;
    CAC_MAC_FILTER_CTX *context;
    NDIS_STATUS status;

    UNREFERENCED_PARAMETER(FilterDriverContext);
    UNREFERENCED_PARAMETER(AttachParameters);

    context = (CAC_MAC_FILTER_CTX *)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(*context), CAC_MAC_POOL_TAG);
    if (context == NULL) {
        return NDIS_STATUS_RESOURCES;
    }
    NdisZeroMemory(context, sizeof(*context));
    context->NdisFilterHandle = NdisFilterHandle;

    NdisZeroMemory(&attributes, sizeof(attributes));
    attributes.Header.Revision = NDIS_FILTER_ATTRIBUTES_REVISION_1;
    attributes.Header.Type = NDIS_OBJECT_TYPE_FILTER_ATTRIBUTES;
    attributes.Header.Size = NDIS_SIZEOF_FILTER_ATTRIBUTES_REVISION_1;
    attributes.Flags = 0;

    status = NdisFSetAttributes(NdisFilterHandle, context, &attributes);
    if (status != NDIS_STATUS_SUCCESS) {
        ExFreePoolWithTag(context, CAC_MAC_POOL_TAG);
        return status;
    }
    NdisInterlockedIncrement((PLONG)&g_Attached);
    return NDIS_STATUS_SUCCESS;
}

static VOID
CacMacFilterDetach(
    _In_ NDIS_HANDLE FilterModuleContext
    )
{
    CAC_MAC_FILTER_CTX *context = (CAC_MAC_FILTER_CTX *)FilterModuleContext;
    NdisInterlockedIncrement((PLONG)&g_Detached);
    if (context != NULL) {
        ExFreePoolWithTag(context, CAC_MAC_POOL_TAG);
    }
}

static NDIS_STATUS
CacMacFilterRestart(
    _In_ NDIS_HANDLE FilterModuleContext,
    _In_ PNDIS_FILTER_RESTART_PARAMETERS RestartParameters
    )
{
    CAC_MAC_FILTER_CTX *context = (CAC_MAC_FILTER_CTX *)FilterModuleContext;

    UNREFERENCED_PARAMETER(RestartParameters);
    context->Running = TRUE;
    return NDIS_STATUS_SUCCESS;
}

static NDIS_STATUS
CacMacFilterPause(
    _In_ NDIS_HANDLE FilterModuleContext,
    _In_ PNDIS_FILTER_PAUSE_PARAMETERS PauseParameters
    )
{
    CAC_MAC_FILTER_CTX *context = (CAC_MAC_FILTER_CTX *)FilterModuleContext;

    UNREFERENCED_PARAMETER(PauseParameters);
    context->Running = FALSE;

    /*
     * FILTER_PAUSE must never fail.  This filter does not queue, originate
     * or meaningfully modify NBLs, so there is no private work to drain.
     * NDIS owns the pass-through lifetime; returning SUCCESS is correct.
     */
    return NDIS_STATUS_SUCCESS;
}

static NDIS_STATUS
CacMacFilterOidRequest(
    _In_ NDIS_HANDLE FilterModuleContext,
    _In_ PNDIS_OID_REQUEST OidRequest
    )
{
    CAC_MAC_FILTER_CTX *context = (CAC_MAC_FILTER_CTX *)FilterModuleContext;
    NDIS_OID oid;

    if (OidRequest->RequestType == NdisRequestQueryInformation) {
        oid = OidRequest->DATA.QUERY_INFORMATION.Oid;
        if (oid == OID_802_3_CURRENT_ADDRESS ||
            oid == OID_802_11_MAC_ADDRESS ||
            oid == OID_802_11_PERMANENT_ADDRESS) {
            if (OidRequest->DATA.QUERY_INFORMATION.InformationBuffer != NULL &&
                OidRequest->DATA.QUERY_INFORMATION.InformationBufferLength >= 6) {
                KIRQL irql;

                NdisInterlockedIncrement((PLONG)&g_OidSeen);
                KeAcquireSpinLock(&g_MacLock, &irql);
                NdisMoveMemory(
                    OidRequest->DATA.QUERY_INFORMATION.InformationBuffer,
                    g_Mac,
                    6);
                KeReleaseSpinLock(&g_MacLock, irql);
                OidRequest->DATA.QUERY_INFORMATION.BytesWritten = 6;
                OidRequest->DATA.QUERY_INFORMATION.BytesNeeded = 6;
                NdisInterlockedIncrement((PLONG)&g_OidRewrites);
                return NDIS_STATUS_SUCCESS;
            }

            OidRequest->DATA.QUERY_INFORMATION.BytesWritten = 0;
            OidRequest->DATA.QUERY_INFORMATION.BytesNeeded = 6;
            return NDIS_STATUS_INVALID_LENGTH;
        }
    }

    NdisInterlockedIncrement((PLONG)&g_OidSeen);
    return NdisFOidRequest(context->NdisFilterHandle, OidRequest);
}

static VOID
CacMacFilterOidRequestComplete(
    _In_ NDIS_HANDLE FilterModuleContext,
    _In_ PNDIS_OID_REQUEST OidRequest,
    _In_ NDIS_STATUS Status
    )
{
    CAC_MAC_FILTER_CTX *context = (CAC_MAC_FILTER_CTX *)FilterModuleContext;

    NdisFOidRequestComplete(
        context->NdisFilterHandle, OidRequest, Status);
}

static VOID
CacMacFilterSendNetBufferLists(
    _In_ NDIS_HANDLE FilterModuleContext,
    _In_ PNET_BUFFER_LIST NetBufferLists,
    _In_ NDIS_PORT_NUMBER PortNumber,
    _In_ ULONG SendFlags
    )
{
    CAC_MAC_FILTER_CTX *context = (CAC_MAC_FILTER_CTX *)FilterModuleContext;

    if (!context->Running) {
        PNET_BUFFER_LIST current = NetBufferLists;
        ULONG completeFlags = NDIS_TEST_SEND_AT_DISPATCH_LEVEL(SendFlags)
            ? NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL
            : 0;

        while (current != NULL) {
            NET_BUFFER_LIST_STATUS(current) = NDIS_STATUS_PAUSED;
            current = NET_BUFFER_LIST_NEXT_NBL(current);
        }
        NdisFSendNetBufferListsComplete(
            context->NdisFilterHandle, NetBufferLists, completeFlags);
        return;
    }

    NdisFSendNetBufferLists(
        context->NdisFilterHandle, NetBufferLists, PortNumber, SendFlags);
}

static VOID
CacMacFilterSendNetBufferListsComplete(
    _In_ NDIS_HANDLE FilterModuleContext,
    _In_ PNET_BUFFER_LIST NetBufferLists,
    _In_ ULONG SendCompleteFlags
    )
{
    CAC_MAC_FILTER_CTX *context = (CAC_MAC_FILTER_CTX *)FilterModuleContext;

    NdisFSendNetBufferListsComplete(
        context->NdisFilterHandle, NetBufferLists, SendCompleteFlags);
}

static VOID
CacMacFilterReceiveNetBufferLists(
    _In_ NDIS_HANDLE FilterModuleContext,
    _In_ PNET_BUFFER_LIST NetBufferLists,
    _In_ NDIS_PORT_NUMBER PortNumber,
    _In_ ULONG NumberOfNetBufferLists,
    _In_ ULONG ReceiveFlags
    )
{
    CAC_MAC_FILTER_CTX *context = (CAC_MAC_FILTER_CTX *)FilterModuleContext;

    if (!context->Running) {
        if (NDIS_TEST_RECEIVE_CAN_PEND(ReceiveFlags)) {
            ULONG returnFlags = 0;

            if (NDIS_TEST_RECEIVE_AT_DISPATCH_LEVEL(ReceiveFlags)) {
                NDIS_SET_RETURN_FLAG(
                    returnFlags, NDIS_RETURN_FLAGS_DISPATCH_LEVEL);
            }
            NdisFReturnNetBufferLists(
                context->NdisFilterHandle, NetBufferLists, returnFlags);
        }
        return;
    }

    NdisFIndicateReceiveNetBufferLists(
        context->NdisFilterHandle, NetBufferLists, PortNumber,
        NumberOfNetBufferLists, ReceiveFlags);
}

static VOID
CacMacFilterReturnNetBufferLists(
    _In_ NDIS_HANDLE FilterModuleContext,
    _In_ PNET_BUFFER_LIST NetBufferLists,
    _In_ ULONG ReturnFlags
    )
{
    CAC_MAC_FILTER_CTX *context = (CAC_MAC_FILTER_CTX *)FilterModuleContext;

    NdisFReturnNetBufferLists(
        context->NdisFilterHandle, NetBufferLists, ReturnFlags);
}

static VOID
CacMacFilterCancelSendNetBufferLists(
    _In_ NDIS_HANDLE FilterModuleContext,
    _In_ PVOID CancelId
    )
{
    CAC_MAC_FILTER_CTX *context = (CAC_MAC_FILTER_CTX *)FilterModuleContext;

    NdisFCancelSendNetBufferLists(context->NdisFilterHandle, CancelId);
}

/* ---------------------------------------------------------------- */
/* Control device                                                    */
/* ---------------------------------------------------------------- */

static NTSTATUS
CacMacCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS
CacMacDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
    )
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG inputLength = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputLength = stack->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG information = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    switch (code) {
    case CAC_MAC_IOCTL_SET:
        if (inputLength < 6) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        {
            UCHAR mac[6];
            KIRQL irql;
            NdisMoveMemory(mac, buffer, sizeof(mac));
            KeAcquireSpinLock(&g_MacLock, &irql);
            NdisMoveMemory(g_Mac, mac, sizeof(mac));
            KeReleaseSpinLock(&g_MacLock, irql);
            NdisInterlockedIncrement((PLONG)&g_SetCount);
        }
        status = STATUS_SUCCESS;
        break;

    case CAC_MAC_IOCTL_STATE: {
        CAC_MAC_STATE *state = (CAC_MAC_STATE *)buffer;
        KIRQL irql;
        if (outputLength < sizeof(*state)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        NdisZeroMemory(state, sizeof(*state));
        state->SetCount = g_SetCount;
        state->OidQueriesSeen = g_OidSeen;
        state->OidRewrites = g_OidRewrites;
        state->AttachedModules = g_Attached;
        state->DetachedModules = g_Detached;
        state->RegisterStatus = g_RegisterStatus;
        KeAcquireSpinLock(&g_MacLock, &irql);
        NdisMoveMemory(state->Mac, g_Mac, sizeof(state->Mac));
        KeReleaseSpinLock(&g_MacLock, irql);
        information = sizeof(*state);
        status = STATUS_SUCCESS;
        break;
    }

    default:
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

static VOID
CacMacUnload(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    UNREFERENCED_PARAMETER(DriverObject);

    if (g_FilterDriverHandle != NULL) {
        NdisFDeregisterFilterDriver(g_FilterDriverHandle);
        g_FilterDriverHandle = NULL;
    }
    if (g_SymlinkCreated) {
        UNICODE_STRING symlinkName;
        RtlInitUnicodeString(&symlinkName, CAC_MAC_SYMLINK_NAME);
        IoDeleteSymbolicLink(&symlinkName);
        g_SymlinkCreated = FALSE;
    }
    if (g_ControlDevice != NULL) {
        IoDeleteDevice(g_ControlDevice);
        g_ControlDevice = NULL;
    }
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NDIS_FILTER_DRIVER_CHARACTERISTICS characteristics;
    NDIS_STRING friendlyName =
        RTL_CONSTANT_STRING(L"CAC Profile MAC Lightweight Filter");
    NDIS_STRING uniqueName =
        RTL_CONSTANT_STRING(L"{b4320c2d-c807-4829-b8b8-054feddd024c}");
    NDIS_STRING serviceName = RTL_CONSTANT_STRING(L"CacMacLwf");
    NDIS_STATUS ndisStatus;
    NTSTATUS status;
    UNICODE_STRING deviceName;
    UNICODE_STRING symlinkName;

    UNREFERENCED_PARAMETER(RegistryPath);

    NdisZeroMemory(&characteristics, sizeof(characteristics));
    characteristics.Header.Type = NDIS_OBJECT_TYPE_FILTER_DRIVER_CHARACTERISTICS;
    characteristics.Header.Revision =
        NDIS_FILTER_DRIVER_CHARACTERISTICS_REVISION_1;
    characteristics.Header.Size =
        NDIS_SIZEOF_FILTER_DRIVER_CHARACTERISTICS_REVISION_1;
    characteristics.MajorNdisVersion = 6;
    characteristics.MinorNdisVersion = 0;
    characteristics.Flags = 0;
    NdisInitUnicodeString(&characteristics.FriendlyName,
                          L"CAC Profile MAC Lightweight Filter");
    NdisInitUnicodeString(&characteristics.UniqueName,
                          L"CAC Profile MAC Lightweight Filter");
    NdisInitUnicodeString(&characteristics.ServiceName, L"CacMacLwf");
    characteristics.FriendlyName = friendlyName;
    characteristics.UniqueName = uniqueName;
    characteristics.ServiceName = serviceName;
    characteristics.AttachHandler = CacMacFilterAttach;
    characteristics.DetachHandler = CacMacFilterDetach;
    characteristics.RestartHandler = CacMacFilterRestart;
    characteristics.PauseHandler = CacMacFilterPause;
    /*
     * 2026-11-16: on 22631.7376 + wfplwfs, any OID participation
     * reproduces 0x1E in ndisFOidRequestCompleteInternal even after the
     * FILTER_PAUSE and completion fixes.  Keep the OID path disabled on
     * this stack; see LWF-FIX-TEST-20261116.md.  The MAC view is covered
     * above NDIS by NativeBridge.
     */
    characteristics.OidRequestHandler = NULL;
    characteristics.OidRequestCompleteHandler = NULL;
    characteristics.SendNetBufferListsHandler =
        CacMacFilterSendNetBufferLists;
    characteristics.SendNetBufferListsCompleteHandler =
        CacMacFilterSendNetBufferListsComplete;
    characteristics.ReceiveNetBufferListsHandler =
        CacMacFilterReceiveNetBufferLists;
    characteristics.ReturnNetBufferListsHandler =
        CacMacFilterReturnNetBufferLists;
    characteristics.CancelSendNetBufferListsHandler =
        CacMacFilterCancelSendNetBufferLists;

    ndisStatus = NdisFRegisterFilterDriver(
        DriverObject,
        (NDIS_HANDLE)DriverObject,
        &characteristics,
        &g_FilterDriverHandle);
    g_RegisterStatus = (ULONG)ndisStatus;

    KeInitializeSpinLock(&g_MacLock);
    g_MacLockInit = TRUE;

    RtlInitUnicodeString(&deviceName, CAC_MAC_DEVICE_NAME);
    RtlInitUnicodeString(&symlinkName, CAC_MAC_SYMLINK_NAME);

    status = IoCreateDevice(
        DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE,
        &g_ControlDevice);
    if (!NT_SUCCESS(status)) {
        if (g_FilterDriverHandle != NULL) {
            NdisFDeregisterFilterDriver(g_FilterDriverHandle);
            g_FilterDriverHandle = NULL;
        }
        return status;
    }
    g_ControlDevice->Flags |= DO_BUFFERED_IO;

    status = IoCreateSymbolicLink(&symlinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_ControlDevice);
        g_ControlDevice = NULL;
        if (g_FilterDriverHandle != NULL) {
            NdisFDeregisterFilterDriver(g_FilterDriverHandle);
            g_FilterDriverHandle = NULL;
        }
        return status;
    }
    g_SymlinkCreated = TRUE;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = CacMacCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = CacMacCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = CacMacDeviceControl;
    DriverObject->DriverUnload = CacMacUnload;

    return STATUS_SUCCESS;
}
