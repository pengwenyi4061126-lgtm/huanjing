#pragma once

#include <ntifs.h>
#include "CacKernelIoctl.h"

/*
 * Non-VM hardware identity modules living inside the signed WDM control
 * plane:
 *
 *   storage filter  - attaches to \Device\HarddiskN\DRN / RaidPort / NVMe
 *                     devices and rewrites IOCTL_STORAGE_QUERY_PROPERTY
 *                     output for processes registered in the policy table.
 *   smbios rewrite   - locates the physical SMBIOS table copy that
 *                     ntoskrnl caches at boot (WmipSMBiosTable*) and
 *                     rewrites the identity strings in place. All later
 *                     ring-0 readers see the profile values; the original
 *                     copy is restored on unload.
 *
 * MAC is NOT filtered at NDIS level here: attaching a generic filter device
 * to NDIS miniports receives IRPs allocated with the miniport's own stack
 * size, which corrupts the IRP stack (observed as 0x18 / 0xEF bugchecks on
 * this host). Kernel-level MAC spoofing requires a real NDIS lightweight
 * filter driver; the userland GetAdaptersAddresses/OID surface remains
 * covered by NativeBridge.
 *
 * CPUID/XGETBV remain out of scope for a kernel driver: those instructions
 * do not trap into ring 0. They are covered by the userland manifest-based
 * inline hook (see native/README.md, "CPUID / XGETBV manifest").
 */

#define CAC_FILTER_MAGIC 0x4C696643u  /* 'FfiL' */

typedef enum _CAC_FILTER_KIND {
    CAC_FILTER_KIND_STORAGE = 1,
    CAC_FILTER_KIND_MAC = 2
} CAC_FILTER_KIND;

typedef struct _CAC_FILTER_EXT {
    ULONG Magic;
    CAC_FILTER_KIND Kind;
    PDEVICE_OBJECT LowerDevice;
    PDEVICE_OBJECT FilterDevice;
    WCHAR NameBuffer[64];
    BOOLEAN RemoveLockInitialized;
    IO_REMOVE_LOCK RemoveLock;
    LIST_ENTRY Link;
} CAC_FILTER_EXT;

NTSTATUS
CacIdentityFilterInit(
    _In_ PDRIVER_OBJECT DriverObject
    );

VOID
CacIdentityFilterCleanup(
    VOID
    );

NTSTATUS
CacIdentityFilterSetIdentity(
    _In_ const CAC_IDENTITY *Identity
    );

VOID
CacIdentityFilterQueryState(
    _Out_ CAC_MODULE_STATE *State
    );

/*
 * Shared IRP entry points routed from CacKernel.c. Both check the
 * extension magic and fall back to the control-device path when the
 * device object is not a filter.
 */
NTSTATUS
CacIdentityFilterDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
    );

NTSTATUS
CacIdentityFilterForward(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
    );

/*
 * Implemented in CacKernel.c. CacPolicyIndexQuery is callable at
 * DISPATCH_LEVEL and returns whether the PID has an active policy plus the
 * strict-empty flag. CacAuditExternal appends an audit record.
 */
BOOLEAN
CacPolicyIndexQuery(
    _In_ ULONG ProcessId,
    _Out_ PBOOLEAN StrictEmpty
    );

VOID
CacAuditExternal(
    _In_ ULONG EventType,
    _In_ ULONG ProcessId,
    _In_ NTSTATUS Status,
    _In_z_ PCSTR Detail
    );
