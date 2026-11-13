#pragma once

/*
 * Shared user/kernel ABI for the CAC kernel control plane.
 *
 * This header intentionally contains no pointers and no variable-length
 * inline payloads other than the audit record tail. All structures are
 * fixed-width so the same definitions compile in WDM and user mode.
 */

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <windows.h>
#include <winioctl.h>
#endif

#define CAC_KERNEL_PROTOCOL_VERSION 1u
#define CAC_KERNEL_DEVICE_NAME L"\\Device\\CacKernel"
#define CAC_KERNEL_SYMLINK_NAME L"\\DosDevices\\CacKernel"
#define CAC_KERNEL_USER_PATH L"\\\\.\\CacKernel"

#define CAC_MAX_POLICY_ENTRIES 64u
#define CAC_AUDIT_CAPACITY 128u
#define CAC_PROFILE_ID_LENGTH 16u
#define CAC_AUDIT_DETAIL_LENGTH 64u

#define CAC_POLICY_FLAG_ACTIVE 0x00000001u
#define CAC_POLICY_FLAG_STRICT_EMPTY 0x00000002u
#define CAC_POLICY_FLAG_ALL (CAC_POLICY_FLAG_ACTIVE | CAC_POLICY_FLAG_STRICT_EMPTY)

#define CAC_CAP_CONTROL_PLANE 0x00000001u
#define CAC_CAP_PER_PROCESS_POLICY 0x00000002u
#define CAC_CAP_AUDIT_RING 0x00000004u
#define CAC_CAP_PROCESS_LIFECYCLE 0x00000008u

typedef enum _CAC_AUDIT_EVENT {
    CacAuditDriverLoad = 1,
    CacAuditDeviceCreate = 2,
    CacAuditPolicyRegister = 3,
    CacAuditPolicyUnregister = 4,
    CacAuditPolicyReject = 5,
    CacAuditProcessExit = 6,
    CacAuditUnknownIoctl = 7,
    CacAuditDriverUnload = 8,
    CacAuditNotifyState = 9
} CAC_AUDIT_EVENT;

typedef struct _CAC_POLICY_REQUEST {
    ULONG Version;
    ULONG ProcessId;
    ULONG Flags;
    UCHAR ProfileId[CAC_PROFILE_ID_LENGTH];
} CAC_POLICY_REQUEST;

typedef struct _CAC_POLICY_RESPONSE {
    ULONG Version;
    ULONG ProcessId;
    ULONG Flags;
    ULONG Registered;
    LONGLONG ProcessCreateTime;
    UCHAR ProfileId[CAC_PROFILE_ID_LENGTH];
} CAC_POLICY_RESPONSE;

typedef struct _CAC_AUDIT_RECORD {
    ULONG Sequence;
    ULONG EventType;
    ULONG ProcessId;
    ULONG Status;
    LONGLONG TimestampUtc;
    CHAR Detail[CAC_AUDIT_DETAIL_LENGTH];
} CAC_AUDIT_RECORD;

typedef struct _CAC_AUDIT_QUERY {
    ULONG MaxRecords;
    ULONG StartSequence;
    ULONG Returned;
    ULONG TotalRecorded;
    ULONG Dropped;
    CAC_AUDIT_RECORD Records[1];
} CAC_AUDIT_QUERY;

typedef struct _CAC_PING_RESPONSE {
    ULONG Version;
    ULONG Capabilities;
    ULONG PolicyCount;
    ULONG AuditCount;
    ULONG AuditDropped;
    ULONG ServiceState;
    ULONG NotifyRegistered;
} CAC_PING_RESPONSE;

#define CAC_IOCTL_PING \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_DATA)
#define CAC_IOCTL_POLICY_REGISTER \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)
#define CAC_IOCTL_POLICY_UNREGISTER \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_WRITE_DATA)
#define CAC_IOCTL_POLICY_QUERY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_READ_DATA)
#define CAC_IOCTL_AUDIT_QUERY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_READ_DATA)
