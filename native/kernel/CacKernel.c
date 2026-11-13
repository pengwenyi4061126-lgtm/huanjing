#include <ntifs.h>
#include "CacKernelIoctl.h"
#include <wdmsec.h>

#define CAC_POOL_TAG 'cCaC'

typedef struct _CAC_POLICY_ENTRY {
    LIST_ENTRY Link;
    ULONG ProcessId;
    ULONG Flags;
    LONGLONG CreateTime;
    UCHAR ProfileId[CAC_PROFILE_ID_LENGTH];
} CAC_POLICY_ENTRY;

typedef struct _CAC_DEVICE_EXTENSION {
    LIST_ENTRY PolicyList;
    ULONG PolicyCount;
    ERESOURCE PolicyLock;
    BOOLEAN PolicyLockReady;
    KSPIN_LOCK AuditLock;
    CAC_AUDIT_RECORD Audit[CAC_AUDIT_CAPACITY];
    ULONG AuditNext;
    ULONG AuditTotal;
    BOOLEAN NotifyRegistered;
    BOOLEAN LegacyNotifyRegistered;
} CAC_DEVICE_EXTENSION;

static PDEVICE_OBJECT g_CacDevice = NULL;
static BOOLEAN g_CacSymlinkCreated = FALSE;

static const GUID g_CacDeviceClassGuid =
    { 0x7f4f4d31, 0x2d2a, 0x4a79, { 0x9c, 0x3e, 0x51, 0x33, 0x8c, 0x0e, 0x2b, 0x71 } };

static VOID
CacAuditAppend(
    _In_ CAC_DEVICE_EXTENSION *Extension,
    _In_ ULONG EventType,
    _In_ ULONG ProcessId,
    _In_ NTSTATUS Status,
    _In_z_ PCSTR Detail
    )
{
    KIRQL irql;
    ULONG index;
    ULONG i;
    LARGE_INTEGER now;

    KeQuerySystemTimePrecise(&now);
    KeAcquireSpinLock(&Extension->AuditLock, &irql);

    index = Extension->AuditNext;
    Extension->Audit[index].Sequence = Extension->AuditTotal + 1;
    Extension->Audit[index].EventType = EventType;
    Extension->Audit[index].ProcessId = ProcessId;
    Extension->Audit[index].Status = (ULONG)Status;
    Extension->Audit[index].TimestampUtc = now.QuadPart;
    if (Detail == NULL) {
        Detail = "";
    }
    for (i = 0; i + 1 < CAC_AUDIT_DETAIL_LENGTH && Detail[i] != '\0'; ++i) {
        Extension->Audit[index].Detail[i] = Detail[i];
    }
    Extension->Audit[index].Detail[i] = '\0';
    for (++i; i < CAC_AUDIT_DETAIL_LENGTH; ++i) {
        Extension->Audit[index].Detail[i] = '\0';
    }

    Extension->AuditNext = (index + 1) % CAC_AUDIT_CAPACITY;
    Extension->AuditTotal += 1;
    KeReleaseSpinLock(&Extension->AuditLock, irql);
}

static VOID
CacAuditCounts(
    _In_ CAC_DEVICE_EXTENSION *Extension,
    _Out_ PULONG Total,
    _Out_ PULONG Dropped
    )
{
    KIRQL irql;
    ULONG value;

    KeAcquireSpinLock(&Extension->AuditLock, &irql);
    value = Extension->AuditTotal;
    KeReleaseSpinLock(&Extension->AuditLock, irql);
    *Total = value;
    *Dropped = value > CAC_AUDIT_CAPACITY ? value - CAC_AUDIT_CAPACITY : 0;
}

static BOOLEAN
CacIsProcessAlive(
    _In_ ULONG ProcessId,
    _In_ LONGLONG CreateTime
    )
{
    PEPROCESS process = NULL;
    BOOLEAN alive = FALSE;
    NTSTATUS status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)ProcessId, &process);

    if (NT_SUCCESS(status)) {
        alive = PsGetProcessCreateTimeQuadPart(process) == CreateTime &&
                PsGetProcessExitStatus(process) == STATUS_PENDING;
        ObDereferenceObject(process);
    }
    return alive;
}

static ULONG
CacPurgeStalePolicies(
    _In_ CAC_DEVICE_EXTENSION *Extension
    )
{
    PLIST_ENTRY cursor;
    ULONG purged = 0;

    ExAcquireResourceExclusiveLite(&Extension->PolicyLock, TRUE);
    cursor = Extension->PolicyList.Flink;
    while (cursor != &Extension->PolicyList) {
        PLIST_ENTRY next = cursor->Flink;
        CAC_POLICY_ENTRY *candidate = CONTAINING_RECORD(cursor, CAC_POLICY_ENTRY, Link);
        if (!CacIsProcessAlive(candidate->ProcessId, candidate->CreateTime)) {
            RemoveEntryList(cursor);
            Extension->PolicyCount -= 1;
            ExFreePoolWithTag(candidate, CAC_POOL_TAG);
            purged += 1;
        }
        cursor = next;
    }
    ExReleaseResourceLite(&Extension->PolicyLock);

    if (purged != 0) {
        CacAuditAppend(Extension, CacAuditProcessExit, 0, STATUS_SUCCESS,
                       "stale policies purged");
    }
    return purged;
}

static BOOLEAN
CacPurgePolicyForProcessId(
    _In_ CAC_DEVICE_EXTENSION *Extension,
    _In_ ULONG ProcessId
    )
{
    PLIST_ENTRY cursor;
    CAC_POLICY_ENTRY *found = NULL;

    ExAcquireResourceExclusiveLite(&Extension->PolicyLock, TRUE);
    for (cursor = Extension->PolicyList.Flink;
         cursor != &Extension->PolicyList;
         cursor = cursor->Flink) {
        CAC_POLICY_ENTRY *candidate = CONTAINING_RECORD(cursor, CAC_POLICY_ENTRY, Link);
        if (candidate->ProcessId == ProcessId) {
            RemoveEntryList(cursor);
            Extension->PolicyCount -= 1;
            found = candidate;
            break;
        }
    }
    ExReleaseResourceLite(&Extension->PolicyLock);

    if (found == NULL) {
        return FALSE;
    }
    ExFreePoolWithTag(found, CAC_POOL_TAG);
    CacAuditAppend(Extension, CacAuditProcessExit, ProcessId,
                   STATUS_SUCCESS, "policy purged on exit");
    return TRUE;
}

static NTSTATUS
CacRegisterPolicy(
    _In_ CAC_DEVICE_EXTENSION *Extension,
    _In_ const CAC_POLICY_REQUEST *Request
    )
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    LONGLONG createTime;
    CAC_POLICY_ENTRY *entry;
    CAC_POLICY_ENTRY *existing = NULL;
    PLIST_ENTRY cursor;

    if (Request == NULL || Request->Version != CAC_KERNEL_PROTOCOL_VERSION) {
        return STATUS_REVISION_MISMATCH;
    }
    if (Request->ProcessId == 0 || Request->ProcessId == 4) {
        return STATUS_INVALID_PARAMETER;
    }
    if ((Request->Flags & ~CAC_POLICY_FLAG_ALL) != 0) {
        return STATUS_INVALID_PARAMETER;
    }

    CacPurgeStalePolicies(Extension);

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Request->ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    createTime = PsGetProcessCreateTimeQuadPart(process);
    ObDereferenceObject(process);

    entry = (CAC_POLICY_ENTRY *)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(*entry), CAC_POOL_TAG);
    if (entry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(entry, sizeof(*entry));
    entry->ProcessId = Request->ProcessId;
    entry->Flags = Request->Flags;
    entry->CreateTime = createTime;
    RtlCopyMemory(entry->ProfileId, Request->ProfileId, CAC_PROFILE_ID_LENGTH);

    ExAcquireResourceExclusiveLite(&Extension->PolicyLock, TRUE);
    for (cursor = Extension->PolicyList.Flink;
         cursor != &Extension->PolicyList;
         cursor = cursor->Flink) {
        CAC_POLICY_ENTRY *candidate = CONTAINING_RECORD(cursor, CAC_POLICY_ENTRY, Link);
        if (candidate->ProcessId == Request->ProcessId) {
            existing = candidate;
            break;
        }
    }

    if (existing != NULL) {
        existing->Flags = entry->Flags;
        existing->CreateTime = entry->CreateTime;
        RtlCopyMemory(existing->ProfileId, entry->ProfileId, CAC_PROFILE_ID_LENGTH);
        status = STATUS_SUCCESS;
    } else if (Extension->PolicyCount >= CAC_MAX_POLICY_ENTRIES) {
        status = STATUS_QUOTA_EXCEEDED;
    } else {
        InsertTailList(&Extension->PolicyList, &entry->Link);
        Extension->PolicyCount += 1;
        entry = NULL;
        status = STATUS_SUCCESS;
    }
    ExReleaseResourceLite(&Extension->PolicyLock);

    if (entry != NULL) {
        ExFreePoolWithTag(entry, CAC_POOL_TAG);
    }
    return status;
}

static NTSTATUS
CacUnregisterPolicy(
    _In_ CAC_DEVICE_EXTENSION *Extension,
    _In_ ULONG ProcessId
    )
{
    PLIST_ENTRY cursor;
    CAC_POLICY_ENTRY *found = NULL;

    if (ProcessId == 0 || ProcessId == 4) {
        return STATUS_INVALID_PARAMETER;
    }

    ExAcquireResourceExclusiveLite(&Extension->PolicyLock, TRUE);
    for (cursor = Extension->PolicyList.Flink;
         cursor != &Extension->PolicyList;
         cursor = cursor->Flink) {
        CAC_POLICY_ENTRY *candidate = CONTAINING_RECORD(cursor, CAC_POLICY_ENTRY, Link);
        if (candidate->ProcessId == ProcessId) {
            RemoveEntryList(cursor);
            Extension->PolicyCount -= 1;
            found = candidate;
            break;
        }
    }
    ExReleaseResourceLite(&Extension->PolicyLock);

    if (found == NULL) {
        return STATUS_NOT_FOUND;
    }
    ExFreePoolWithTag(found, CAC_POOL_TAG);
    return STATUS_SUCCESS;
}

static NTSTATUS
CacQueryPolicy(
    _In_ CAC_DEVICE_EXTENSION *Extension,
    _In_ ULONG ProcessId,
    _Out_ CAC_POLICY_RESPONSE *Response
    )
{
    PLIST_ENTRY cursor;
    BOOLEAN found = FALSE;
    BOOLEAN purged = FALSE;
    CAC_POLICY_ENTRY *stale = NULL;

    RtlZeroMemory(Response, sizeof(*Response));
    Response->Version = CAC_KERNEL_PROTOCOL_VERSION;
    Response->ProcessId = ProcessId;

    ExAcquireResourceExclusiveLite(&Extension->PolicyLock, TRUE);
    for (cursor = Extension->PolicyList.Flink;
         cursor != &Extension->PolicyList;
         cursor = cursor->Flink) {
        CAC_POLICY_ENTRY *candidate = CONTAINING_RECORD(cursor, CAC_POLICY_ENTRY, Link);
        if (candidate->ProcessId == ProcessId) {
            Response->Flags = candidate->Flags;
            Response->ProcessCreateTime = candidate->CreateTime;
            RtlCopyMemory(Response->ProfileId, candidate->ProfileId, CAC_PROFILE_ID_LENGTH);
            found = TRUE;
            stale = candidate;
            break;
        }
    }

    if (stale != NULL && !CacIsProcessAlive(ProcessId, stale->CreateTime)) {
            RemoveEntryList(&stale->Link);
            Extension->PolicyCount -= 1;
            found = FALSE;
            purged = TRUE;
    }
    ExReleaseResourceLite(&Extension->PolicyLock);

    if (stale != NULL && !found) {
        ExFreePoolWithTag(stale, CAC_POOL_TAG);
        if (purged) {
            CacAuditAppend(Extension, CacAuditProcessExit, ProcessId,
                           STATUS_SUCCESS, "stale policy purged on query");
        }
        RtlZeroMemory(Response, sizeof(*Response));
        Response->Version = CAC_KERNEL_PROTOCOL_VERSION;
        Response->ProcessId = ProcessId;
    }

    Response->Registered = found ? 1u : 0u;
    return STATUS_SUCCESS;
}

static VOID
CacProcessNotify(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    )
{
    CAC_DEVICE_EXTENSION *extension;
    ULONG pid;

    UNREFERENCED_PARAMETER(Process);
    if (CreateInfo != NULL || g_CacDevice == NULL) {
        return;
    }

    pid = (ULONG)(ULONG_PTR)ProcessId;
    extension = (CAC_DEVICE_EXTENSION *)g_CacDevice->DeviceExtension;
    CacPurgePolicyForProcessId(extension, pid);
}

static VOID
CacProcessNotifyLegacy(
    _In_ HANDLE ParentId,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN Create
    )
{
    CAC_DEVICE_EXTENSION *extension;
    ULONG pid;

    UNREFERENCED_PARAMETER(ParentId);
    if (Create || g_CacDevice == NULL) {
        return;
    }

    pid = (ULONG)(ULONG_PTR)ProcessId;
    extension = (CAC_DEVICE_EXTENSION *)g_CacDevice->DeviceExtension;
    CacPurgePolicyForProcessId(extension, pid);
}

static NTSTATUS
CacPing(
    _In_ CAC_DEVICE_EXTENSION *Extension,
    _Out_ PVOID Buffer,
    _In_ ULONG OutputLength,
    _Out_ PULONG Information
    )
{
    CAC_PING_RESPONSE *response;

    if (OutputLength < sizeof(CAC_PING_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    response = (CAC_PING_RESPONSE *)Buffer;
    RtlZeroMemory(response, sizeof(*response));
    response->Version = CAC_KERNEL_PROTOCOL_VERSION;
    response->Capabilities =
        CAC_CAP_CONTROL_PLANE | CAC_CAP_PER_PROCESS_POLICY | CAC_CAP_AUDIT_RING;

    CacPurgeStalePolicies(Extension);
    if (Extension->NotifyRegistered) {
        response->Capabilities |= CAC_CAP_PROCESS_LIFECYCLE;
    }

    ExAcquireResourceSharedLite(&Extension->PolicyLock, TRUE);
    response->PolicyCount = Extension->PolicyCount;
    ExReleaseResourceLite(&Extension->PolicyLock);
    CacAuditCounts(Extension, &response->AuditCount, &response->AuditDropped);
    response->ServiceState = 1;
    response->NotifyRegistered = Extension->NotifyRegistered ? 1u : 0u;

    *Information = sizeof(*response);
    return STATUS_SUCCESS;
}

static NTSTATUS
CacQueryAudit(
    _In_ CAC_DEVICE_EXTENSION *Extension,
    _Inout_ PVOID Buffer,
    _In_ ULONG InputLength,
    _In_ ULONG OutputLength,
    _Out_ PULONG Information
    )
{
    CAC_AUDIT_QUERY *query;
    ULONG maxRecords;
    ULONG startSequence;
    ULONG capacity;
    ULONG total;
    ULONG available;
    ULONG firstAvailable;
    ULONG count;
    ULONG i;
    KIRQL irql;

    if (InputLength < sizeof(ULONG) * 2) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (OutputLength < (ULONG)FIELD_OFFSET(CAC_AUDIT_QUERY, Records)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    query = (CAC_AUDIT_QUERY *)Buffer;
    maxRecords = query->MaxRecords;
    startSequence = query->StartSequence;
    capacity = (OutputLength - (ULONG)FIELD_OFFSET(CAC_AUDIT_QUERY, Records)) /
               sizeof(CAC_AUDIT_RECORD);
    if (maxRecords > capacity) {
        maxRecords = capacity;
    }

    KeAcquireSpinLock(&Extension->AuditLock, &irql);
    total = Extension->AuditTotal;
    available = total < CAC_AUDIT_CAPACITY ? total : CAC_AUDIT_CAPACITY;
    firstAvailable = total - available + 1;

    if (startSequence == 0) {
        startSequence = total >= maxRecords ? total - maxRecords + 1 : 1;
    }
    if (startSequence < firstAvailable) {
        startSequence = firstAvailable;
    }
    if (startSequence > total) {
        startSequence = total + 1;
    }

    count = 0;
    for (i = 0; i < maxRecords && startSequence + i <= total; ++i) {
        ULONG sequence = startSequence + i;
        ULONG index = (sequence - 1) % CAC_AUDIT_CAPACITY;
        query->Records[i] = Extension->Audit[index];
        count += 1;
    }
    query->Returned = count;
    query->TotalRecorded = total;
    query->Dropped = total > CAC_AUDIT_CAPACITY ? total - CAC_AUDIT_CAPACITY : 0;
    KeReleaseSpinLock(&Extension->AuditLock, irql);

    *Information = (ULONG)FIELD_OFFSET(CAC_AUDIT_QUERY, Records) +
                   count * sizeof(CAC_AUDIT_RECORD);
    return STATUS_SUCCESS;
}

static NTSTATUS
CacCreateClose(
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
CacDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
    )
{
    PIO_STACK_LOCATION stack;
    CAC_DEVICE_EXTENSION *extension;
    PVOID buffer;
    ULONG inputLength;
    ULONG outputLength;
    ULONG code;
    ULONG information = 0;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;

    stack = IoGetCurrentIrpStackLocation(Irp);
    extension = (CAC_DEVICE_EXTENSION *)DeviceObject->DeviceExtension;
    buffer = Irp->AssociatedIrp.SystemBuffer;
    inputLength = stack->Parameters.DeviceIoControl.InputBufferLength;
    outputLength = stack->Parameters.DeviceIoControl.OutputBufferLength;
    code = stack->Parameters.DeviceIoControl.IoControlCode;

    switch (code) {
    case CAC_IOCTL_PING:
        status = CacPing(extension, buffer, outputLength, &information);
        break;

    case CAC_IOCTL_POLICY_REGISTER: {
        CAC_POLICY_REQUEST *request = (CAC_POLICY_REQUEST *)buffer;
        if (inputLength < sizeof(CAC_POLICY_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        status = CacRegisterPolicy(extension, request);
        if (NT_SUCCESS(status)) {
            CacAuditAppend(extension, CacAuditPolicyRegister,
                           request->ProcessId, status, "policy registered");
        } else {
            CacAuditAppend(extension, CacAuditPolicyReject,
                           request->ProcessId, status, "policy register rejected");
        }
        break;
    }

    case CAC_IOCTL_POLICY_UNREGISTER: {
        CAC_POLICY_REQUEST *request = (CAC_POLICY_REQUEST *)buffer;
        if (inputLength < sizeof(ULONG) * 2) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        if (request->Version != CAC_KERNEL_PROTOCOL_VERSION) {
            status = STATUS_REVISION_MISMATCH;
            break;
        }
        status = CacUnregisterPolicy(extension, request->ProcessId);
        if (NT_SUCCESS(status)) {
            CacAuditAppend(extension, CacAuditPolicyUnregister,
                           request->ProcessId, status, "policy unregistered");
        } else {
            CacAuditAppend(extension, CacAuditPolicyReject,
                           request->ProcessId, status, "policy unregister rejected");
        }
        break;
    }

    case CAC_IOCTL_POLICY_QUERY: {
        CAC_POLICY_REQUEST *request = (CAC_POLICY_REQUEST *)buffer;
        CAC_POLICY_RESPONSE *response = (CAC_POLICY_RESPONSE *)buffer;
        if (inputLength < sizeof(ULONG) * 2 ||
            outputLength < sizeof(CAC_POLICY_RESPONSE)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        if (request->Version != CAC_KERNEL_PROTOCOL_VERSION) {
            status = STATUS_REVISION_MISMATCH;
            break;
        }
        if (request->ProcessId == 0 || request->ProcessId == 4) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        status = CacQueryPolicy(extension, request->ProcessId, response);
        information = sizeof(*response);
        break;
    }

    case CAC_IOCTL_AUDIT_QUERY:
        status = CacQueryAudit(extension, buffer, inputLength,
                               outputLength, &information);
        break;

    default:
        CacAuditAppend(extension, CacAuditUnknownIoctl,
                       0, STATUS_INVALID_DEVICE_REQUEST, "unknown ioctl");
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

static VOID
CacDriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    CAC_DEVICE_EXTENSION *extension = NULL;
    UNICODE_STRING symlinkName;

    UNREFERENCED_PARAMETER(DriverObject);

    if (g_CacDevice != NULL) {
        extension = (CAC_DEVICE_EXTENSION *)g_CacDevice->DeviceExtension;
        CacAuditAppend(extension, CacAuditDriverUnload,
                       0, STATUS_SUCCESS, "driver unloading");
    }

    if (extension != NULL && extension->NotifyRegistered) {
        if (extension->LegacyNotifyRegistered) {
            PsSetCreateProcessNotifyRoutine(CacProcessNotifyLegacy, TRUE);
        } else {
            PsSetCreateProcessNotifyRoutineEx(CacProcessNotify, TRUE);
        }
        extension->NotifyRegistered = FALSE;
        extension->LegacyNotifyRegistered = FALSE;
    }

    if (g_CacSymlinkCreated) {
        RtlInitUnicodeString(&symlinkName, CAC_KERNEL_SYMLINK_NAME);
        IoDeleteSymbolicLink(&symlinkName);
        g_CacSymlinkCreated = FALSE;
    }

    if (extension != NULL) {
        while (!IsListEmpty(&extension->PolicyList)) {
            PLIST_ENTRY link = RemoveHeadList(&extension->PolicyList);
            CAC_POLICY_ENTRY *entry = CONTAINING_RECORD(link, CAC_POLICY_ENTRY, Link);
            ExFreePoolWithTag(entry, CAC_POOL_TAG);
        }
        if (extension->PolicyLockReady) {
            ExDeleteResourceLite(&extension->PolicyLock);
            extension->PolicyLockReady = FALSE;
        }
    }

    if (g_CacDevice != NULL) {
        IoDeleteDevice(g_CacDevice);
        g_CacDevice = NULL;
    }
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;
    PDEVICE_OBJECT device = NULL;
    CAC_DEVICE_EXTENSION *extension;
    UNICODE_STRING deviceName;
    UNICODE_STRING symlinkName;
    UNICODE_STRING sddl;

    UNREFERENCED_PARAMETER(RegistryPath);

    RtlInitUnicodeString(&deviceName, CAC_KERNEL_DEVICE_NAME);
    RtlInitUnicodeString(&symlinkName, CAC_KERNEL_SYMLINK_NAME);
    RtlInitUnicodeString(&sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");

    status = IoCreateDeviceSecure(
        DriverObject,
        sizeof(CAC_DEVICE_EXTENSION),
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &sddl,
        &g_CacDeviceClassGuid,
        &device);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    extension = (CAC_DEVICE_EXTENSION *)device->DeviceExtension;
    RtlZeroMemory(extension, sizeof(*extension));
    InitializeListHead(&extension->PolicyList);
    KeInitializeSpinLock(&extension->AuditLock);

    status = ExInitializeResourceLite(&extension->PolicyLock);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(device);
        return status;
    }
    extension->PolicyLockReady = TRUE;
    device->Flags |= DO_BUFFERED_IO;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = CacCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = CacCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = CacDeviceControl;
    DriverObject->DriverUnload = CacDriverUnload;

    status = IoCreateSymbolicLink(&symlinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        ExDeleteResourceLite(&extension->PolicyLock);
        IoDeleteDevice(device);
        return status;
    }
    g_CacSymlinkCreated = TRUE;
    g_CacDevice = device;

    status = PsSetCreateProcessNotifyRoutineEx(CacProcessNotify, FALSE);
    if (NT_SUCCESS(status)) {
        extension->NotifyRegistered = TRUE;
        extension->LegacyNotifyRegistered = FALSE;
        CacAuditAppend(extension, CacAuditNotifyState,
                       0, status, "process notify registered");
    } else {
        NTSTATUS legacyStatus = PsSetCreateProcessNotifyRoutine(
            CacProcessNotifyLegacy, FALSE);
        if (NT_SUCCESS(legacyStatus)) {
            extension->NotifyRegistered = TRUE;
            extension->LegacyNotifyRegistered = TRUE;
            CacAuditAppend(extension, CacAuditNotifyState,
                           0, legacyStatus, "legacy process notify registered");
        } else {
            CacAuditAppend(extension, CacAuditNotifyState,
                           0, status, "process notify registration failed");
        }
    }

    CacAuditAppend(extension, CacAuditDriverLoad,
                   0, STATUS_SUCCESS, "driver loaded");
    CacAuditAppend(extension, CacAuditDeviceCreate,
                   0, STATUS_SUCCESS, "control device ready");

    return STATUS_SUCCESS;
}
