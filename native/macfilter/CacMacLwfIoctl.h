#pragma once

/*
 * Shared ABI between CacMacLwf.sys and cac-macctl.exe.
 */

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <windows.h>
#include <winioctl.h>
#endif

#define CAC_MAC_DEVICE_NAME L"\\Device\\CacMacLwf"
#define CAC_MAC_SYMLINK_NAME L"\\DosDevices\\CacMacLwf"
#define CAC_MAC_USER_PATH L"\\\\.\\CacMacLwf"

typedef struct _CAC_MAC_STATE {
    ULONG SetCount;
    ULONG OidQueriesSeen;
    ULONG OidRewrites;
    ULONG AttachedModules;
    ULONG DetachedModules;
    ULONG RegisterStatus;
    UCHAR Mac[6];
    UCHAR Padding[2];
} CAC_MAC_STATE;

#define CAC_MAC_IOCTL_SET \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_WRITE_DATA)
#define CAC_MAC_IOCTL_STATE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_READ_DATA)
