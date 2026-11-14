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

#define CAC_KERNEL_PROTOCOL_VERSION 2u
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
#define CAC_CAP_STORAGE_FILTER 0x00000010u
#define CAC_CAP_SMBIOS_REWRITE 0x00000020u
#define CAC_CAP_MAC_OID_FILTER 0x00000040u

/*
 * Identity modules. Each module is enabled with an explicit flag and applies
 * only after CAC_IOCTL_IDENTITY_SET succeeds. Storage and MAC filters attach
 * once per driver lifetime and become pass-through when disabled.
 */
#define CAC_MODULE_FLAG_STORAGE 0x00000001u
#define CAC_MODULE_FLAG_SMBIOS 0x00000002u
#define CAC_MODULE_FLAG_MAC 0x00000004u
#define CAC_MODULE_FLAG_ALL \
    (CAC_MODULE_FLAG_STORAGE | CAC_MODULE_FLAG_SMBIOS | CAC_MODULE_FLAG_MAC)

#define CAC_IDENTITY_FIELD_LENGTH 64u
#define CAC_UUID_LENGTH 16u

/*
 * Fixed-width identity handed from the wrapper to the kernel control plane.
 * All strings are ANSI and NUL-terminated. The wrapper derives every field
 * deterministically from profile machine_id (see scripts/lib.ps1).
 */
typedef struct _CAC_IDENTITY {
    ULONG Version;   /* CAC_KERNEL_PROTOCOL_VERSION */
    ULONG ModuleFlags;
    CHAR DiskVendor[CAC_IDENTITY_FIELD_LENGTH];
    CHAR DiskProduct[CAC_IDENTITY_FIELD_LENGTH];
    CHAR DiskRevision[CAC_IDENTITY_FIELD_LENGTH];
    CHAR DiskSerial[CAC_IDENTITY_FIELD_LENGTH];
    UCHAR MacAddress[6];
    UCHAR SystemUuid[CAC_UUID_LENGTH];
    CHAR BiosVendor[CAC_IDENTITY_FIELD_LENGTH];
    CHAR BiosVersion[CAC_IDENTITY_FIELD_LENGTH];
    CHAR SystemManufacturer[CAC_IDENTITY_FIELD_LENGTH];
    CHAR SystemProduct[CAC_IDENTITY_FIELD_LENGTH];
    CHAR SystemVersion[CAC_IDENTITY_FIELD_LENGTH];
    CHAR SystemSerial[CAC_IDENTITY_FIELD_LENGTH];
    CHAR BaseboardManufacturer[CAC_IDENTITY_FIELD_LENGTH];
    CHAR BaseboardProduct[CAC_IDENTITY_FIELD_LENGTH];
    CHAR BaseboardSerial[CAC_IDENTITY_FIELD_LENGTH];
} CAC_IDENTITY;

typedef struct _CAC_MODULE_STATE {
    ULONG Version;
    ULONG ModuleFlags;
    ULONG StorageFilters;
    ULONG SmbiosLocated;
    ULONG SmbiosApplied;
    ULONG64 SmbiosPhysicalAddress;
    ULONG SmbiosLength;
    ULONG StorageRewrites;
    ULONG StorageDispatchSeen;
    ULONG StorageCompletionSeen;
    ULONG LastPropertyId;
    ULONG LastDescriptorVersion;
    ULONG LastDescriptorSize;
    ULONG LastSerialOffset;
    ULONG LastCompletionStatus;
    ULONG64 LastBufferWord0;
    ULONG64 LastBufferWord1;
    ULONG LastPolicyHit;
} CAC_MODULE_STATE;

typedef enum _CAC_AUDIT_EVENT {
    CacAuditDriverLoad = 1,
    CacAuditDeviceCreate = 2,
    CacAuditPolicyRegister = 3,
    CacAuditPolicyUnregister = 4,
    CacAuditPolicyReject = 5,
    CacAuditProcessExit = 6,
    CacAuditUnknownIoctl = 7,
    CacAuditDriverUnload = 8,
    CacAuditNotifyState = 9,
    CacAuditIdentitySet = 10,
    CacAuditSmbiosLocated = 11,
    CacAuditSmbiosApplied = 12,
    CacAuditSmbiosRestored = 13,
    CacAuditStorageRewrite = 14,
    CacAuditMacRewrite = 15,
    CacAuditFilterAttach = 16,
    CacAuditFilterDetach = 17
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
#define CAC_IOCTL_IDENTITY_SET \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_WRITE_DATA)
#define CAC_IOCTL_MODULE_QUERY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_READ_DATA)
