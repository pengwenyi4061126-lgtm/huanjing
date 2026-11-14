#include <ntifs.h>
#include <ntstrsafe.h>
#include <initguid.h>
#include <ntddstor.h>
#include <storduid.h>
#include "IdentityFilter.h"

#define CAC_POOL_TAG 'cCaC'

#define CAC_SMBIOS_MAX_CAPACITY_ENTRIES 256u

/*
 * The WDK NuGet km headers this project builds against do not expose the
 * SystemModuleInformation definitions. Declare the documented ABI locally;
 * the layout is frozen by the public RTL_PROCESS_MODULE_INFORMATION contract.
 */
typedef struct _CAC_RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} CAC_RTL_PROCESS_MODULE_INFORMATION;

typedef struct _CAC_RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    CAC_RTL_PROCESS_MODULE_INFORMATION Modules[1];
} CAC_RTL_PROCESS_MODULES;

#define CAC_SYSTEM_MODULE_INFORMATION 11u

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

typedef struct _CAC_SMBIOS_STRING_CAP {
    ULONG StructOffset;
    UCHAR StringIndex;
    ULONG Capacity;
} CAC_SMBIOS_STRING_CAP;

typedef struct _CAC_IDENTITY_MODULE {
    BOOLEAN Initialized;
    PDRIVER_OBJECT DriverObject;
    KSPIN_LOCK Lock;
    ULONG ModuleFlags;
    BOOLEAN IdentityPresent;
    CAC_IDENTITY Identity;

    LIST_ENTRY FilterList;
    ULONG StorageCount;

    BOOLEAN SmbiosLocated;
    BOOLEAN SmbiosApplied;
    PHYSICAL_ADDRESS SmbiosPhysical;
    ULONG SmbiosLength;
    PVOID SmbiosMapped;
    PVOID SmbiosOriginal;
    CAC_SMBIOS_STRING_CAP *SmbiosCaps;
    ULONG SmbiosCapCount;

    ULONG StorageRewrites;
    ULONG StorageDispatchSeen;
    ULONG StorageCompletionSeen;
    ULONG LastPropertyId;
    ULONG LastDescriptorVersion;
    ULONG LastDescriptorSize;
    ULONG LastCompletionStatus;
    ULONG64 LastBufferWord0;
    ULONG64 LastBufferWord1;
    ULONG LastPolicyHit;
} CAC_IDENTITY_MODULE;

typedef struct _CAC_FILTER_IRP_CTX {
    CAC_FILTER_EXT *Filter;
    BOOLEAN StorageRewrite;
    ULONG Pid;
    ULONG IoControlCode;
    ULONG PropertyId;
    ULONG OutputBufferLength;
    PVOID SystemBuffer;
} CAC_FILTER_IRP_CTX;

static CAC_IDENTITY_MODULE g_IdentityModule;

static NTSTATUS
CacFilterIrpCompletion(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_opt_ PVOID Context
    );

/* ---------------------------------------------------------------- */
/* Small helpers                                                     */
/* ---------------------------------------------------------------- */

/* ---------------------------------------------------------------- */
/* Filter attach / detach                                            */
/* ---------------------------------------------------------------- */

static NTSTATUS
CacAttachFilter(
    _In_ CAC_FILTER_KIND Kind,
    _In_ PDEVICE_OBJECT Target,
    _In_ PCUNICODE_STRING DisplayName
    )
{
    PDEVICE_OBJECT filter = NULL;
    PDEVICE_OBJECT lower = NULL;
    CAC_FILTER_EXT *extension;
    NTSTATUS status;

    status = IoCreateDevice(
        g_IdentityModule.DriverObject,
        sizeof(CAC_FILTER_EXT),
        NULL,
        Target->DeviceType,
        0,
        FALSE,
        &filter);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    filter->Flags &= ~DO_DEVICE_INITIALIZING;
    filter->Flags |= Target->Flags & (DO_BUFFERED_IO | DO_DIRECT_IO);
    filter->Characteristics = Target->Characteristics;

    lower = IoAttachDeviceToDeviceStack(filter, Target);
    if (lower == NULL) {
        IoDeleteDevice(filter);
        return STATUS_UNSUCCESSFUL;
    }
    filter->StackSize = lower->StackSize + 1;

    extension = (CAC_FILTER_EXT *)filter->DeviceExtension;
    RtlZeroMemory(extension, sizeof(*extension));
    extension->Magic = CAC_FILTER_MAGIC;
    extension->Kind = Kind;
    extension->LowerDevice = lower;
    extension->FilterDevice = filter;
    IoInitializeRemoveLock(&extension->RemoveLock, CAC_POOL_TAG, 0, 0);
    extension->RemoveLockInitialized = TRUE;
    if (DisplayName != NULL && DisplayName->Buffer != NULL) {
        if (DisplayName->Length / sizeof(WCHAR) >
            (ARRAYSIZE(extension->NameBuffer) - 1)) {
            RtlCopyMemory(extension->NameBuffer, DisplayName->Buffer,
                          (ARRAYSIZE(extension->NameBuffer) - 1) * sizeof(WCHAR));
            extension->NameBuffer[ARRAYSIZE(extension->NameBuffer) - 1] = L'\0';
        } else {
            RtlCopyMemory(extension->NameBuffer, DisplayName->Buffer,
                          DisplayName->Length);
            extension->NameBuffer[DisplayName->Length / sizeof(WCHAR)] = L'\0';
        }
    }

    InsertTailList(&g_IdentityModule.FilterList, &extension->Link);
    g_IdentityModule.StorageCount += 1;

    CacAuditExternal(CacAuditFilterAttach, 0, STATUS_SUCCESS,
                     "storage filter attached");
    return STATUS_SUCCESS;
}

static NTSTATUS
CacAttachKind(
    _In_ CAC_FILTER_KIND Kind
    )
{
    GUID interfaceGuid = GUID_DEVINTERFACE_DISK;
    PWSTR interfaceBuffer = NULL;
    PWSTR cursor;
    ULONG attached = 0;
    NTSTATUS status;

    if (!g_IdentityModule.Initialized) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (Kind != CAC_FILTER_KIND_STORAGE) {
        return STATUS_NOT_SUPPORTED;
    }

    status = IoGetDeviceInterfaces(&interfaceGuid, NULL, 0, &interfaceBuffer);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    cursor = interfaceBuffer;
    while (*cursor != L'\0') {
        UNICODE_STRING interfaceName;
        PDEVICE_OBJECT target = NULL;
        PFILE_OBJECT fileObject = NULL;
        NTSTATUS openStatus;

        RtlInitUnicodeString(&interfaceName, cursor);
        openStatus = IoGetDeviceObjectPointer(
            &interfaceName, FILE_READ_ATTRIBUTES, &fileObject, &target);
        if (NT_SUCCESS(openStatus) && target != NULL) {
            if (NT_SUCCESS(CacAttachFilter(Kind, target, &interfaceName))) {
                attached += 1;
            }
        }
        if (fileObject != NULL) {
            ObDereferenceObject(fileObject);
        }
        if (target != NULL) {
            ObDereferenceObject(target);
        }
        cursor += wcslen(cursor) + 1;
    }

    ExFreePool(interfaceBuffer);
    CacAuditExternal(CacAuditFilterAttach, 0,
                     attached != 0 ? STATUS_SUCCESS : STATUS_NOT_FOUND,
                     "storage interfaces scanned");
    if (attached == 0) {
        return STATUS_NOT_FOUND;
    }
    return STATUS_SUCCESS;
}

/* ---------------------------------------------------------------- */
/* Storage identity rewrite                                          */
/* ---------------------------------------------------------------- */

static VOID
CacRewriteAnsiField(
    _In_ PVOID Buffer,
    _In_ ULONG BufferLength,
    _In_ ULONG FieldOffset,
    _In_z_ PCSTR Value
    )
{
    PCHAR field;
    ULONG capacity;
    ULONG i;
    SIZE_T valueLength;

    if (Buffer == NULL || Value == NULL || FieldOffset >= BufferLength) {
        return;
    }
    field = (PCHAR)Buffer + FieldOffset;
    capacity = 0;
    while (capacity < BufferLength - FieldOffset && field[capacity] != '\0') {
        capacity += 1;
    }
    if (capacity == 0) {
        return;
    }

    valueLength = strlen(Value);
    if ((ULONG)valueLength > capacity) {
        valueLength = capacity;
    }
    for (i = 0; i < (ULONG)valueLength; ++i) {
        field[i] = Value[i];
    }
    if ((ULONG)valueLength < capacity) {
        field[valueLength] = '\0';
    }
    for (i = (ULONG)valueLength + 1; i < capacity; ++i) {
        field[i] = '\0';
    }
}

static VOID
CacRewriteStorageDeviceProperty(
    _In_ PVOID Buffer,
    _In_ ULONG BufferLength,
    _In_ BOOLEAN StrictEmpty
    )
{
    PSTORAGE_DEVICE_DESCRIPTOR descriptor;
    CHAR vendor[CAC_IDENTITY_FIELD_LENGTH];
    CHAR product[CAC_IDENTITY_FIELD_LENGTH];
    CHAR revision[CAC_IDENTITY_FIELD_LENGTH];
    CHAR serial[CAC_IDENTITY_FIELD_LENGTH];
    KIRQL irql;

    if (Buffer == NULL || BufferLength < sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
        return;
    }
    descriptor = (PSTORAGE_DEVICE_DESCRIPTOR)Buffer;
    if (descriptor->Version < sizeof(STORAGE_DEVICE_DESCRIPTOR) ||
        descriptor->Size < sizeof(STORAGE_DEVICE_DESCRIPTOR) ||
        descriptor->Size > BufferLength) {
        return;
    }

    if (StrictEmpty) {
        vendor[0] = '\0';
        product[0] = '\0';
        revision[0] = '\0';
        serial[0] = '\0';
    } else {
        KeAcquireSpinLock(&g_IdentityModule.Lock, &irql);
        RtlStringCbCopyA(vendor, sizeof(vendor), g_IdentityModule.Identity.DiskVendor);
        RtlStringCbCopyA(product, sizeof(product), g_IdentityModule.Identity.DiskProduct);
        RtlStringCbCopyA(revision, sizeof(revision), g_IdentityModule.Identity.DiskRevision);
        RtlStringCbCopyA(serial, sizeof(serial), g_IdentityModule.Identity.DiskSerial);
        KeReleaseSpinLock(&g_IdentityModule.Lock, irql);
    }

    CacRewriteAnsiField(Buffer, BufferLength, descriptor->VendorIdOffset, vendor);
    CacRewriteAnsiField(Buffer, BufferLength, descriptor->ProductIdOffset, product);
    CacRewriteAnsiField(Buffer, BufferLength, descriptor->ProductRevisionOffset, revision);
    CacRewriteAnsiField(Buffer, BufferLength, descriptor->SerialNumberOffset, serial);

    InterlockedIncrement((volatile LONG *)&g_IdentityModule.StorageRewrites);
    if ((g_IdentityModule.StorageRewrites & 0x3Fu) == 1u) {
        CacAuditExternal(CacAuditStorageRewrite, 0, STATUS_SUCCESS,
                         StrictEmpty ? "storage identity emptied"
                                     : "storage identity rewritten");
    }
}

static VOID
CacStoragePrepare(
    _In_ CAC_FILTER_EXT *Extension,
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION Stack,
    _Inout_ CAC_FILTER_IRP_CTX *Context
    )
{
    UNREFERENCED_PARAMETER(Extension);
    if ((g_IdentityModule.ModuleFlags & CAC_MODULE_FLAG_STORAGE) == 0 ||
        !g_IdentityModule.IdentityPresent) {
        return;
    }
    InterlockedIncrement((volatile LONG *)&g_IdentityModule.StorageDispatchSeen);
    Context->StorageRewrite = TRUE;
    Context->Pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    Context->IoControlCode = Stack->Parameters.DeviceIoControl.IoControlCode;
    Context->PropertyId = 0xFFFFFFFFu;
    if (Irp->AssociatedIrp.SystemBuffer != NULL &&
        Stack->Parameters.DeviceIoControl.InputBufferLength >=
            sizeof(STORAGE_PROPERTY_QUERY)) {
        Context->PropertyId =
            ((PSTORAGE_PROPERTY_QUERY)Irp->AssociatedIrp.SystemBuffer)->PropertyId;
    }
    Context->OutputBufferLength =
        Stack->Parameters.DeviceIoControl.OutputBufferLength;
    Context->SystemBuffer = Irp->AssociatedIrp.SystemBuffer;
}

/* ---------------------------------------------------------------- */
/* SMBIOS physical-table rewrite                                     */
/* ---------------------------------------------------------------- */

static PCHAR
CacSmbiosFindString(
    _In_ PUCHAR Table,
    _In_ ULONG TableLength,
    _In_ ULONG StructOffset,
    _In_ UCHAR StructLength,
    _In_ UCHAR Index,
    _Out_ PULONG Capacity
    )
{
    ULONG position = StructOffset + StructLength;
    UCHAR current = 1;

    *Capacity = 0;
    while (position < TableLength) {
        if (Table[position] == 0) {
            if (current == Index) {
                return NULL;
            }
            current += 1;
            position += 1;
            if (position >= TableLength) {
                return NULL;
            }
            if (Table[position] == 0) {
                position += 1;
                continue;
            }
            continue;
        }
        if (current == Index) {
            ULONG length = 0;
            while (position + length < TableLength && Table[position + length] != 0) {
                length += 1;
            }
            *Capacity = length;
            return (PCHAR)(Table + position);
        }
        position += 1;
    }
    return NULL;
}

static ULONG
CacSmbiosNextStructure(
    _In_ PUCHAR Table,
    _In_ ULONG TableLength,
    _In_ ULONG StringAreaStart
    )
{
    ULONG position = StringAreaStart;

    while (position + 1 < TableLength) {
        if (Table[position] == 0 && Table[position + 1] == 0) {
            return position + 2;
        }
        position += 1;
    }
    if (position >= TableLength) {
        return TableLength;
    }
    return (ULONG)-1;
}

static BOOLEAN
CacSmbiosValidate(
    _In_ PUCHAR Table,
    _In_ ULONG TableLength,
    _Out_ PULONG Score
    )
{
    ULONG offset = 0;
    ULONG count = 0;
    BOOLEAN sawType0 = FALSE;
    BOOLEAN sawType1 = FALSE;

    while (offset + 4 <= TableLength) {
        UCHAR type = Table[offset];
        UCHAR structureLength = Table[offset + 1];
        ULONG stringArea;
        ULONG next;

        if (type == 127) {
            break;
        }
        if (structureLength < 4 || type > 126) {
            return FALSE;
        }
        stringArea = offset + structureLength;
        if (stringArea > TableLength) {
            return FALSE;
        }
        next = CacSmbiosNextStructure(Table, TableLength, stringArea);
        if (next == (ULONG)-1) {
            return FALSE;
        }
        if (type == 0) {
            sawType0 = TRUE;
        } else if (type == 1) {
            sawType1 = TRUE;
        }
        count += 1;
        offset = next;
    }

    if (count == 0 || (!sawType0 && !sawType1)) {
        return FALSE;
    }
    *Score = count + (sawType0 ? 2u : 0u) + (sawType1 ? 4u : 0u);
    return TRUE;
}

static NTSTATUS
CacSmbiosLocate(
    VOID
    )
{
    ULONG needed = 0;
    PVOID moduleBuffer = NULL;
    CAC_RTL_PROCESS_MODULES *modules;
    PUCHAR imageBase = NULL;
    ULONG imageSize = 0;
    ULONG i;
    ULONG64 bestPhysical = 0;
    ULONG bestLength = 0;
    ULONG bestScore = 0;
    ULONG mappedCandidates = 0;
    NTSTATUS status;

    status = ZwQuerySystemInformation(CAC_SYSTEM_MODULE_INFORMATION, NULL, 0, &needed);
    if (status != STATUS_INFO_LENGTH_MISMATCH ||
        needed < sizeof(CAC_RTL_PROCESS_MODULES)) {
        return status == STATUS_INFO_LENGTH_MISMATCH ? STATUS_UNSUCCESSFUL : status;
    }
    needed += 0x2000;

    moduleBuffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, needed, CAC_POOL_TAG);
    if (moduleBuffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    status = ZwQuerySystemInformation(
        CAC_SYSTEM_MODULE_INFORMATION, moduleBuffer, needed, &needed);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(moduleBuffer, CAC_POOL_TAG);
        return status;
    }

    modules = (CAC_RTL_PROCESS_MODULES *)moduleBuffer;
    /*
     * Scan the kernel image only. The WmipSMBiosTable* globals live in
     * ntoskrnl; probing other modules (or mapping arbitrary physical
     * addresses beyond a tight budget) was observed to fault inside
     * system-service context on this host. Hard caps below keep the
     * probing surface tiny and deterministic.
     */
    for (ULONG pass = 1; pass <= 1 && bestPhysical == 0; ++pass) {
        ULONG foundModules = 0;
        for (i = 0; i < modules->NumberOfModules; ++i) {
            PCWSTR fullName = (PCWSTR)modules->Modules[i].FullPathName;
            PCWSTR component = fullName;
            SIZE_T nameChars = 0;
            SIZE_T j;
            BOOLEAN isKernelImage;
            WCHAR prefix[8];
            SIZE_T prefixLen;
            ULONG k;

            if (mappedCandidates >= 64) {
                break;
            }
            while (nameChars < 127 && fullName[nameChars] != L'\0') {
                nameChars += 1;
            }
            for (j = nameChars; j > 0; --j) {
                if (fullName[j - 1] == L'\\' || fullName[j - 1] == L'/') {
                    component = &fullName[j];
                    break;
                }
            }
            prefixLen = 0;
            while (component[prefixLen] != L'\0' && prefixLen < 7) {
                prefix[prefixLen] = component[prefixLen];
                if (prefix[prefixLen] >= L'a' && prefix[prefixLen] <= L'z') {
                    prefix[prefixLen] = (WCHAR)(prefix[prefixLen] - L'a' + L'A');
                }
                prefixLen += 1;
            }
            prefix[prefixLen] = L'\0';
            isKernelImage =
                i == 0 ||
                wcscmp(prefix, L"NTOSKRN") == 0 ||
                wcscmp(prefix, L"NTKRNL") == 0;
            if ((pass == 1) != isKernelImage) {
                continue;
            }
            foundModules += 1;

            imageBase = (PUCHAR)modules->Modules[i].ImageBase;
            imageSize = modules->Modules[i].ImageSize;
            if (imageBase == NULL || imageSize < 0x1000) {
                continue;
            }

            __try {
                ULONG64 offset;
                for (offset = 0; offset + 16 <= imageSize; offset += 8) {
                    ULONG64 physical;
                    ULONG64 length;
                    ULONG length32;
                    PVOID mapped;
                    BOOLEAN valid = FALSE;
                    ULONG score = 0;

                    if (mappedCandidates >= 64) {
                        break;
                    }
                    /*
                     * Try both field orders. Some builds store
                     * (physical, length), others (length, physical).
                     */
                    for (ULONG order = 0; order < 2 && !valid; ++order) {
                        if (order == 0) {
                            physical = *(volatile ULONG64 *)(imageBase + offset);
                            length = *(volatile ULONG64 *)(imageBase + offset + 8);
                        } else {
                            length = *(volatile ULONG64 *)(imageBase + offset);
                            physical = *(volatile ULONG64 *)(imageBase + offset + 8);
                        }
                        length32 = (ULONG)(length & 0xFFFFFFFFull);
                        if (physical < 0x10000 || physical > 0x40000000ull) {
                            continue;
                        }
                        if (length32 < 0x40 || length32 > 0x4000) {
                            continue;
                        }
                        if (physical + length32 > 0x40000000ull) {
                            continue;
                        }
                        mapped = MmMapIoSpace(
                            *(PPHYSICAL_ADDRESS)&physical, (SIZE_T)length32,
                            MmNonCached);
                        if (mapped == NULL) {
                            continue;
                        }
                        mappedCandidates += 1;
                        __try {
                            valid = CacSmbiosValidate(
                                (PUCHAR)mapped, length32, &score);
                            if (!valid && length32 > 0x20) {
                                valid = CacSmbiosValidate(
                                    (PUCHAR)mapped + 0x20, length32 - 0x20,
                                    &score);
                            }
                            if (!valid && length32 > 0x18) {
                                valid = CacSmbiosValidate(
                                    (PUCHAR)mapped + 0x18, length32 - 0x18,
                                    &score);
                            }
                        } __except (EXCEPTION_EXECUTE_HANDLER) {
                            valid = FALSE;
                        }
                        MmUnmapIoSpace(mapped, (SIZE_T)length32);
                        if (valid && score > bestScore) {
                            bestScore = score;
                            bestPhysical = physical;
                            bestLength = length32;
                        }
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                /* Skip modules whose image is not fully readable. */
            }
        }
        if (pass == 1 && foundModules == 0) {
            CacAuditExternal(CacAuditSmbiosLocated, 0, STATUS_NOT_FOUND,
                             "smbios locate: kernel module not found");
        }
    }

    ExFreePoolWithTag(moduleBuffer, CAC_POOL_TAG);
    if (bestPhysical == 0 || bestLength == 0) {
        char detail[CAC_AUDIT_DETAIL_LENGTH];
        const char *prefix = "smbios locate: no pair (mapped ";
        size_t prefixLength = strlen(prefix);
        char digits[12];
        ULONG value = mappedCandidates;
        ULONG digitCount = 0;
        char *cursor;

        if (prefixLength > sizeof(detail) - 1) {
            prefixLength = sizeof(detail) - 1;
        }
        RtlCopyMemory(detail, prefix, prefixLength);
        cursor = detail + prefixLength;
        do {
            digits[digitCount++] = (char)('0' + (value % 10));
            value /= 10;
        } while (value != 0);
        while (digitCount != 0 && cursor + 1 < detail + sizeof(detail)) {
            *cursor++ = digits[--digitCount];
        }
        if (cursor + 1 < detail + sizeof(detail)) {
            *cursor++ = ')';
            *cursor = '\0';
        } else {
            detail[sizeof(detail) - 1] = '\0';
        }
        CacAuditExternal(CacAuditSmbiosLocated, 0, STATUS_NOT_FOUND,
                         detail);
        return STATUS_NOT_FOUND;
    }

    g_IdentityModule.SmbiosMapped = MmMapIoSpace(
        *(PPHYSICAL_ADDRESS)&bestPhysical, bestLength, MmNonCached);
    if (g_IdentityModule.SmbiosMapped == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    g_IdentityModule.SmbiosOriginal = ExAllocatePool2(
        POOL_FLAG_NON_PAGED, bestLength, CAC_POOL_TAG);
    if (g_IdentityModule.SmbiosOriginal == NULL) {
        MmUnmapIoSpace(g_IdentityModule.SmbiosMapped, bestLength);
        g_IdentityModule.SmbiosMapped = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(g_IdentityModule.SmbiosOriginal, g_IdentityModule.SmbiosMapped, bestLength);

    g_IdentityModule.SmbiosCaps = (CAC_SMBIOS_STRING_CAP *)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(CAC_SMBIOS_STRING_CAP) * CAC_SMBIOS_MAX_CAPACITY_ENTRIES,
        CAC_POOL_TAG);
    if (g_IdentityModule.SmbiosCaps != NULL) {
        ULONG tableOffset = 0;
        ULONG capCount = 0;
        __try {
            while (tableOffset + 4 <= bestLength && capCount < CAC_SMBIOS_MAX_CAPACITY_ENTRIES) {
                UCHAR type = ((PUCHAR)g_IdentityModule.SmbiosMapped)[tableOffset];
                UCHAR structureLength = ((PUCHAR)g_IdentityModule.SmbiosMapped)[tableOffset + 1];
                ULONG stringArea;
                ULONG next;
                UCHAR stringIndex;

                if (type == 127) {
                    break;
                }
                stringArea = tableOffset + structureLength;
                if (stringArea > bestLength) {
                    break;
                }
                next = CacSmbiosNextStructure(
                    (PUCHAR)g_IdentityModule.SmbiosMapped, bestLength, stringArea);
                if (next == (ULONG)-1) {
                    break;
                }
                for (stringIndex = 1;
                     stringIndex <= 6 && capCount < CAC_SMBIOS_MAX_CAPACITY_ENTRIES;
                     ++stringIndex) {
                    ULONG capacity = 0;
                    PCHAR stringValue = CacSmbiosFindString(
                        (PUCHAR)g_IdentityModule.SmbiosMapped, bestLength,
                        tableOffset, structureLength, stringIndex, &capacity);
                    if (stringValue == NULL && capacity == 0) {
                        break;
                    }
                    if (stringValue != NULL && capacity != 0) {
                        g_IdentityModule.SmbiosCaps[capCount].StructOffset = tableOffset;
                        g_IdentityModule.SmbiosCaps[capCount].StringIndex = stringIndex;
                        g_IdentityModule.SmbiosCaps[capCount].Capacity = capacity;
                        capCount += 1;
                    }
                }
                tableOffset = next;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            capCount = 0;
        }
        g_IdentityModule.SmbiosCapCount = capCount;
    }

    g_IdentityModule.SmbiosPhysical = *(PPHYSICAL_ADDRESS)&bestPhysical;
    g_IdentityModule.SmbiosLength = bestLength;
    g_IdentityModule.SmbiosLocated = TRUE;
    CacAuditExternal(CacAuditSmbiosLocated, 0, STATUS_SUCCESS,
                     "physical smbios table located");
    return STATUS_SUCCESS;
}

static ULONG
CacSmbiosStringCapacity(
    _In_ ULONG StructOffset,
    _In_ UCHAR StringIndex
    )
{
    ULONG i;

    for (i = 0; i < g_IdentityModule.SmbiosCapCount; ++i) {
        if (g_IdentityModule.SmbiosCaps[i].StructOffset == StructOffset &&
            g_IdentityModule.SmbiosCaps[i].StringIndex == StringIndex) {
            return g_IdentityModule.SmbiosCaps[i].Capacity;
        }
    }
    return 0;
}

static VOID
CacSmbiosPatchString(
    _In_ ULONG StructOffset,
    _In_ UCHAR StructLength,
    _In_ UCHAR StringIndex,
    _In_z_ PCSTR Value
    )
{
    ULONG capacity = CacSmbiosStringCapacity(StructOffset, StringIndex);
    ULONG position;
    ULONG valueLength;
    ULONG i;
    PUCHAR table = (PUCHAR)g_IdentityModule.SmbiosMapped;
    ULONG tableLength = g_IdentityModule.SmbiosLength;
    PCHAR stringStart;
    ULONG current;

    if (capacity == 0 || Value == NULL || table == NULL) {
        return;
    }
    stringStart = CacSmbiosFindString(
        table, tableLength, StructOffset, StructLength, StringIndex, &current);
    if (stringStart == NULL || current != capacity) {
        return;
    }
    position = (ULONG)(stringStart - (PCHAR)table);
    valueLength = (ULONG)strlen(Value);
    if (valueLength > capacity) {
        valueLength = capacity;
    }
    for (i = 0; i < valueLength; ++i) {
        table[position + i] = (UCHAR)Value[i];
    }
    for (i = valueLength; i < capacity; ++i) {
        table[position + i] = 0;
    }
}

static ULONG
CacSmbiosApply(
    _In_ const CAC_IDENTITY *Identity
    )
{
    ULONG tableOffset = 0;
    ULONG patched = 0;
    PUCHAR table = (PUCHAR)g_IdentityModule.SmbiosMapped;
    ULONG tableLength = g_IdentityModule.SmbiosLength;

    if (table == NULL || tableLength == 0) {
        return 0;
    }

    __try {
        while (tableOffset + 4 <= tableLength) {
            UCHAR type = table[tableOffset];
            UCHAR structureLength = table[tableOffset + 1];
            ULONG stringArea;
            ULONG next;

            if (type == 127) {
                break;
            }
            stringArea = tableOffset + structureLength;
            if (stringArea > tableLength) {
                break;
            }
            next = CacSmbiosNextStructure(table, tableLength, stringArea);
            if (next == (ULONG)-1) {
                break;
            }

            switch (type) {
            case 0:
                CacSmbiosPatchString(tableOffset, structureLength, 1, Identity->BiosVendor);
                CacSmbiosPatchString(tableOffset, structureLength, 2, Identity->BiosVersion);
                patched += 2;
                break;
            case 1:
                CacSmbiosPatchString(tableOffset, structureLength, 1, Identity->SystemManufacturer);
                CacSmbiosPatchString(tableOffset, structureLength, 2, Identity->SystemProduct);
                CacSmbiosPatchString(tableOffset, structureLength, 3, Identity->SystemVersion);
                CacSmbiosPatchString(tableOffset, structureLength, 4, Identity->SystemSerial);
                if (stringArea <= tableLength - 16) {
                    RtlCopyMemory(table + tableOffset + 8, Identity->SystemUuid, 16);
                    patched += 1;
                }
                patched += 4;
                break;
            case 2:
                CacSmbiosPatchString(tableOffset, structureLength, 1, Identity->BaseboardManufacturer);
                CacSmbiosPatchString(tableOffset, structureLength, 2, Identity->BaseboardProduct);
                CacSmbiosPatchString(tableOffset, structureLength, 4, Identity->BaseboardSerial);
                patched += 3;
                break;
            case 3:
                CacSmbiosPatchString(tableOffset, structureLength, 1, Identity->SystemManufacturer);
                CacSmbiosPatchString(tableOffset, structureLength, 4, Identity->SystemSerial);
                patched += 2;
                break;
            default:
                break;
            }
            tableOffset = next;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        patched = 0;
    }
    return patched;
}

/* ---------------------------------------------------------------- */
/* Completion routines                                               */
/* ---------------------------------------------------------------- */

static NTSTATUS
CacFilterIrpCompletion(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_opt_ PVOID Context
    )
{
    CAC_FILTER_IRP_CTX *context = (CAC_FILTER_IRP_CTX *)Context;

    UNREFERENCED_PARAMETER(DeviceObject);
    if (Irp->PendingReturned) {
        IoMarkIrpPending(Irp);
    }
    if (context != NULL) {
        __try {
            if (context->StorageRewrite) {
                InterlockedIncrement(
                    (volatile LONG *)&g_IdentityModule.StorageCompletionSeen);
                g_IdentityModule.LastPropertyId = context->PropertyId;
                g_IdentityModule.LastCompletionStatus =
                    (ULONG)Irp->IoStatus.Status;
                g_IdentityModule.LastBufferWord0 = 0;
                g_IdentityModule.LastBufferWord1 = 0;
                if (context->SystemBuffer != NULL &&
                    context->OutputBufferLength >= 16) {
                    g_IdentityModule.LastBufferWord0 =
                        *(volatile ULONG64 *)context->SystemBuffer;
                    g_IdentityModule.LastBufferWord1 =
                        *(volatile ULONG64 *)((PUCHAR)context->SystemBuffer + 8);
                }
                if (NT_SUCCESS(Irp->IoStatus.Status)) {
                    g_IdentityModule.LastDescriptorVersion = 0;
                    g_IdentityModule.LastDescriptorSize = 0;
                    if (context->SystemBuffer != NULL &&
                        context->OutputBufferLength >=
                            sizeof(STORAGE_DESCRIPTOR_HEADER)) {
                        PSTORAGE_DESCRIPTOR_HEADER header =
                            (PSTORAGE_DESCRIPTOR_HEADER)context->SystemBuffer;
                        g_IdentityModule.LastDescriptorVersion = header->Version;
                        g_IdentityModule.LastDescriptorSize = header->Size;
                    }
                    BOOLEAN strictEmpty = FALSE;
                    BOOLEAN policyHit =
                        CacPolicyIndexQuery(context->Pid, &strictEmpty);
                    g_IdentityModule.LastPolicyHit = policyHit ? 1u : 0u;
                    if (policyHit &&
                        (context->IoControlCode & 0x3u) == METHOD_BUFFERED &&
                        context->SystemBuffer != NULL &&
                        context->OutputBufferLength >=
                            sizeof(STORAGE_PROPERTY_QUERY)) {
                        if (context->PropertyId == StorageDeviceProperty) {
                            CacRewriteStorageDeviceProperty(
                                context->SystemBuffer,
                                context->OutputBufferLength,
                                strictEmpty);
                        } else if (context->PropertyId ==
                                       StorageDeviceUniqueIdProperty &&
                                   strictEmpty &&
                                   context->OutputBufferLength >=
                                       sizeof(STORAGE_DEVICE_UNIQUE_IDENTIFIER)) {
                            PSTORAGE_DEVICE_UNIQUE_IDENTIFIER uniqueId =
                                (PSTORAGE_DEVICE_UNIQUE_IDENTIFIER)context->SystemBuffer;
                            uniqueId->StorageDeviceOffset = 0;
                            uniqueId->StorageDeviceIdOffset = 0;
                            uniqueId->DriveLayoutSignatureOffset = 0;
                        }
                    }
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            /* Never let a rewrite fault propagate from completion context. */
        }
    }
    if (context != NULL && context->Filter != NULL &&
        context->Filter->RemoveLockInitialized) {
        IoReleaseRemoveLock(&context->Filter->RemoveLock, Irp);
    }
    if (context != NULL) {
        ExFreePoolWithTag(context, CAC_POOL_TAG);
    }
    return STATUS_SUCCESS;
}

/* ---------------------------------------------------------------- */
/* Public entry points                                               */
/* ---------------------------------------------------------------- */

NTSTATUS
CacIdentityFilterInit(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    if (g_IdentityModule.Initialized) {
        return STATUS_SUCCESS;
    }
    RtlZeroMemory(&g_IdentityModule, sizeof(g_IdentityModule));
    KeInitializeSpinLock(&g_IdentityModule.Lock);
    InitializeListHead(&g_IdentityModule.FilterList);
    g_IdentityModule.DriverObject = DriverObject;
    g_IdentityModule.Initialized = TRUE;
    return STATUS_SUCCESS;
}

VOID
CacIdentityFilterCleanup(
    VOID
    )
{
    KIRQL irql;

    if (!g_IdentityModule.Initialized) {
        return;
    }

    /* Disarm every module before touching any device object. */
    KeAcquireSpinLock(&g_IdentityModule.Lock, &irql);
    g_IdentityModule.ModuleFlags = 0;
    g_IdentityModule.IdentityPresent = FALSE;
    KeReleaseSpinLock(&g_IdentityModule.Lock, irql);

    if (g_IdentityModule.SmbiosMapped != NULL &&
        g_IdentityModule.SmbiosOriginal != NULL &&
        g_IdentityModule.SmbiosLength != 0) {
        __try {
            RtlCopyMemory(
                g_IdentityModule.SmbiosMapped,
                g_IdentityModule.SmbiosOriginal,
                g_IdentityModule.SmbiosLength);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
        CacAuditExternal(CacAuditSmbiosRestored, 0, STATUS_SUCCESS,
                         "smbios table restored");
    }
    if (g_IdentityModule.SmbiosMapped != NULL) {
        MmUnmapIoSpace(g_IdentityModule.SmbiosMapped, g_IdentityModule.SmbiosLength);
        g_IdentityModule.SmbiosMapped = NULL;
    }
    if (g_IdentityModule.SmbiosOriginal != NULL) {
        ExFreePoolWithTag(g_IdentityModule.SmbiosOriginal, CAC_POOL_TAG);
        g_IdentityModule.SmbiosOriginal = NULL;
    }
    if (g_IdentityModule.SmbiosCaps != NULL) {
        ExFreePoolWithTag(g_IdentityModule.SmbiosCaps, CAC_POOL_TAG);
        g_IdentityModule.SmbiosCaps = NULL;
    }
    g_IdentityModule.SmbiosCapCount = 0;
    g_IdentityModule.SmbiosLocated = FALSE;
    g_IdentityModule.SmbiosApplied = FALSE;

    while (!IsListEmpty(&g_IdentityModule.FilterList)) {
        PLIST_ENTRY link = RemoveHeadList(&g_IdentityModule.FilterList);
        CAC_FILTER_EXT *extension = CONTAINING_RECORD(link, CAC_FILTER_EXT, Link);
        if (extension->RemoveLockInitialized) {
            IoReleaseRemoveLockAndWait(
                &extension->RemoveLock, extension->FilterDevice);
        }
        IoDetachDevice(extension->LowerDevice);
        IoDeleteDevice(extension->FilterDevice);
        CacAuditExternal(CacAuditFilterDetach, 0, STATUS_SUCCESS,
                         "filter detached");
    }
    g_IdentityModule.StorageCount = 0;
    g_IdentityModule.Initialized = FALSE;
}

NTSTATUS
CacIdentityFilterSetIdentity(
    _In_ const CAC_IDENTITY *Identity
    )
{
    KIRQL irql;
    NTSTATUS status;

    if (!g_IdentityModule.Initialized) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (Identity == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Identity->Version != CAC_KERNEL_PROTOCOL_VERSION) {
        return STATUS_REVISION_MISMATCH;
    }
    if ((Identity->ModuleFlags & ~CAC_MODULE_FLAG_ALL) != 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if ((Identity->ModuleFlags & CAC_MODULE_FLAG_STORAGE) != 0 &&
        g_IdentityModule.StorageCount == 0) {
        status = CacAttachKind(CAC_FILTER_KIND_STORAGE);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }
    if ((Identity->ModuleFlags & CAC_MODULE_FLAG_SMBIOS) != 0 &&
        !g_IdentityModule.SmbiosLocated) {
        status = CacSmbiosLocate();
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    KeAcquireSpinLock(&g_IdentityModule.Lock, &irql);
    RtlCopyMemory(&g_IdentityModule.Identity, Identity, sizeof(*Identity));
    g_IdentityModule.IdentityPresent = TRUE;
    g_IdentityModule.ModuleFlags = Identity->ModuleFlags;
    KeReleaseSpinLock(&g_IdentityModule.Lock, irql);

    if ((Identity->ModuleFlags & CAC_MODULE_FLAG_SMBIOS) != 0) {
        ULONG patched = CacSmbiosApply(Identity);
        g_IdentityModule.SmbiosApplied = (patched != 0);
        CacAuditExternal(CacAuditSmbiosApplied, 0,
                         patched != 0 ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL,
                         patched != 0 ? "smbios table patched"
                                      : "smbios patch produced no fields");
    } else if (g_IdentityModule.SmbiosMapped != NULL &&
               g_IdentityModule.SmbiosOriginal != NULL) {
        __try {
            RtlCopyMemory(
                g_IdentityModule.SmbiosMapped,
                g_IdentityModule.SmbiosOriginal,
                g_IdentityModule.SmbiosLength);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
        g_IdentityModule.SmbiosApplied = FALSE;
        CacAuditExternal(CacAuditSmbiosRestored, 0, STATUS_SUCCESS,
                         "smbios table restored on disable");
    }

    CacAuditExternal(CacAuditIdentitySet, 0, STATUS_SUCCESS,
                     "kernel identity applied");
    return STATUS_SUCCESS;
}

VOID
CacIdentityFilterQueryState(
    _Out_ CAC_MODULE_STATE *State
    )
{
    RtlZeroMemory(State, sizeof(*State));
    if (!g_IdentityModule.Initialized) {
        State->Version = CAC_KERNEL_PROTOCOL_VERSION;
        return;
    }
    State->Version = CAC_KERNEL_PROTOCOL_VERSION;
    State->ModuleFlags = g_IdentityModule.ModuleFlags;
    State->StorageFilters = g_IdentityModule.StorageCount;
    State->SmbiosLocated = g_IdentityModule.SmbiosLocated ? 1u : 0u;
    State->SmbiosApplied = g_IdentityModule.SmbiosApplied ? 1u : 0u;
    State->SmbiosPhysicalAddress = (ULONG64)g_IdentityModule.SmbiosPhysical.QuadPart;
    State->SmbiosLength = g_IdentityModule.SmbiosLength;
    State->StorageRewrites = g_IdentityModule.StorageRewrites;
    State->StorageDispatchSeen = g_IdentityModule.StorageDispatchSeen;
    State->StorageCompletionSeen = g_IdentityModule.StorageCompletionSeen;
    State->LastPropertyId = g_IdentityModule.LastPropertyId;
    State->LastDescriptorVersion = g_IdentityModule.LastDescriptorVersion;
    State->LastDescriptorSize = g_IdentityModule.LastDescriptorSize;
    State->LastSerialOffset = 0;
    State->LastCompletionStatus = g_IdentityModule.LastCompletionStatus;
    State->LastBufferWord0 = g_IdentityModule.LastBufferWord0;
    State->LastBufferWord1 = g_IdentityModule.LastBufferWord1;
    State->LastPolicyHit = g_IdentityModule.LastPolicyHit;
}

NTSTATUS
CacIdentityFilterDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
    )
{
    CAC_FILTER_EXT *extension = (CAC_FILTER_EXT *)DeviceObject->DeviceExtension;
    CAC_FILTER_IRP_CTX *context = NULL;
    PIO_STACK_LOCATION stack;

    if (extension->Magic != CAC_FILTER_MAGIC) {
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    if (!NT_SUCCESS(IoAcquireRemoveLock(&extension->RemoveLock, Irp))) {
        Irp->IoStatus.Status = STATUS_DELETE_PENDING;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_DELETE_PENDING;
    }

    context = (CAC_FILTER_IRP_CTX *)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(*context), CAC_POOL_TAG);
    if (context == NULL) {
        IoReleaseRemoveLock(&extension->RemoveLock, Irp);
        Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(context, sizeof(*context));
    context->Filter = extension;

    stack = IoGetCurrentIrpStackLocation(Irp);
    if (extension->Kind == CAC_FILTER_KIND_STORAGE) {
        if (stack->MajorFunction == IRP_MJ_DEVICE_CONTROL &&
            stack->Parameters.DeviceIoControl.IoControlCode ==
                IOCTL_STORAGE_QUERY_PROPERTY) {
            CacStoragePrepare(extension, Irp, stack, context);
        }
    }

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutineEx(
        DeviceObject, Irp, CacFilterIrpCompletion, context,
        TRUE, TRUE, TRUE);
    return IoCallDriver(extension->LowerDevice, Irp);
}

NTSTATUS
CacIdentityFilterForward(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
    )
{
    CAC_FILTER_EXT *extension = (CAC_FILTER_EXT *)DeviceObject->DeviceExtension;

    if (extension->Magic == CAC_FILTER_MAGIC) {
        CAC_FILTER_IRP_CTX *context;
        if (!NT_SUCCESS(IoAcquireRemoveLock(&extension->RemoveLock, Irp))) {
            Irp->IoStatus.Status = STATUS_DELETE_PENDING;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_DELETE_PENDING;
        }
        context = (CAC_FILTER_IRP_CTX *)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, sizeof(*context), CAC_POOL_TAG);
        if (context == NULL) {
            IoReleaseRemoveLock(&extension->RemoveLock, Irp);
            Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(context, sizeof(*context));
        context->Filter = extension;
        IoCopyCurrentIrpStackLocationToNext(Irp);
        IoSetCompletionRoutineEx(
            DeviceObject, Irp, CacFilterIrpCompletion, context,
            TRUE, TRUE, TRUE);
        return IoCallDriver(extension->LowerDevice, Irp);
    }
    Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_INVALID_DEVICE_REQUEST;
}
