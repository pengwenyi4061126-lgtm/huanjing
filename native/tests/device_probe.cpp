#define _WIN32_WINNT 0x0A00

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <winioctl.h>
#include <winternl.h>
#include <psapi.h>
#include <setupapi.h>
#include <initguid.h>
#include <devguid.h>

#include <cstdio>
#include <string>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "psapi.lib")

namespace {

typedef NTSTATUS (NTAPI* PFN_NtQueryVolumeInformationFile)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG);
typedef NTSTATUS (NTAPI* PFN_NtDeviceIoControlFile)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID,
                                                    PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);

struct FsVolumeInformation {
    LARGE_INTEGER CreationTime;
    ULONG SerialNumber;
    ULONG LabelLength;
    BOOLEAN SupportsObjects;
    WCHAR Label[1];
};

std::string WideToUtf8(const wchar_t* value) {
    if (!value) return std::string();
    const int length = WideCharToMultiByte(CP_UTF8, 0, value, -1, nullptr, 0, nullptr, nullptr);
    if (length <= 1) return std::string();
    std::string result(static_cast<size_t>(length - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value, -1, result.data(), length, nullptr, nullptr);
    return result;
}

std::string MacText(const BYTE* address, ULONG length) {
    if (!address || length < 6) return "none";
    bool any = false;
    for (ULONG i = 0; i < 6; ++i) if (address[i]) any = true;
    if (!any) return "none";
    char text[32] = {};
    std::snprintf(text, sizeof(text), "%02x:%02x:%02x:%02x:%02x:%02x",
                  address[0], address[1], address[2], address[3], address[4], address[5]);
    return text;
}

void ProbeVolume(HANDLE file) {
    DWORD serial = 0;
    if (GetVolumeInformationByHandleW(file, nullptr, 0, &serial, nullptr, nullptr, nullptr, 0)) {
        std::printf("handle_volume=%08X\n", static_cast<unsigned int>(serial));
    } else {
        std::printf("handle_volume=error\n");
    }

    BY_HANDLE_FILE_INFORMATION information = {};
    if (GetFileInformationByHandle(file, &information)) {
        std::printf("file_volume=%08X\n", static_cast<unsigned int>(information.dwVolumeSerialNumber));
    } else {
        std::printf("file_volume=error\n");
    }

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto query = reinterpret_cast<PFN_NtQueryVolumeInformationFile>(
        ntdll ? GetProcAddress(ntdll, "NtQueryVolumeInformationFile") : nullptr);
    if (!query) {
        std::printf("nt_volume=missing\n");
        return;
    }
    IO_STATUS_BLOCK status = {};
    BYTE buffer[1024] = {};
    FsVolumeInformation* volume = reinterpret_cast<FsVolumeInformation*>(buffer);
    const NTSTATUS result = query(file, &status, buffer, sizeof(buffer), 1);
    if (result >= 0 || result == static_cast<NTSTATUS>(0x80000005L)) {
        std::printf("nt_volume=%08X\n", static_cast<unsigned int>(volume->SerialNumber));
    } else {
        std::printf("nt_volume=error(0x%08X)\n", static_cast<unsigned int>(result));
    }
}

void ProbeInterfaces() {
    PMIB_IF_TABLE2 table = nullptr;
    std::string mac = "none";
    std::string entryMac = "none";
    if (GetIfTable2(&table) == NO_ERROR && table) {
        for (ULONG i = 0; i < table->NumEntries; ++i) {
            if (table->Table[i].PhysicalAddressLength >= 6) {
                mac = MacText(table->Table[i].PhysicalAddress, table->Table[i].PhysicalAddressLength);
                MIB_IF_ROW2 row = {};
                row.InterfaceLuid = table->Table[i].InterfaceLuid;
                row.InterfaceIndex = table->Table[i].InterfaceIndex;
                if (GetIfEntry2(&row) == NO_ERROR) {
                    entryMac = MacText(row.PhysicalAddress, row.PhysicalAddressLength);
                }
                break;
            }
        }
        FreeMibTable(table);
    }
    std::printf("if2_mac=%s\n", mac.c_str());
    std::printf("if2_entry_mac=%s\n", entryMac.c_str());
}

void ProbeDiskSerial() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto ioctl = reinterpret_cast<PFN_NtDeviceIoControlFile>(
        ntdll ? GetProcAddress(ntdll, "NtDeviceIoControlFile") : nullptr);
    HANDLE disk = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (disk == INVALID_HANDLE_VALUE) {
        std::printf("nt_disk_serial=open-denied\n");
        return;
    }
    if (!ioctl) {
        CloseHandle(disk);
        std::printf("nt_disk_serial=missing\n");
        return;
    }
    STORAGE_PROPERTY_QUERY query = {};
    query.PropertyId = StorageDeviceProperty;
    query.QueryType = PropertyStandardQuery;
    BYTE output[1024] = {};
    IO_STATUS_BLOCK status = {};
    const NTSTATUS result = ioctl(disk, nullptr, nullptr, nullptr, &status, IOCTL_STORAGE_QUERY_PROPERTY,
                                  &query, sizeof(query), output, sizeof(output));
    CloseHandle(disk);
    if (result < 0) {
        std::printf("nt_disk_serial=ioctl-error\n");
        return;
    }
    STORAGE_DEVICE_DESCRIPTOR* descriptor = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR*>(output);
    if (descriptor->SerialNumberOffset == 0 || descriptor->SerialNumberOffset >= status.Information) {
        std::printf("nt_disk_serial=empty\n");
        return;
    }
    std::printf("nt_disk_serial=%s\n",
                reinterpret_cast<char*>(output) + descriptor->SerialNumberOffset);
}

void ProbeDrivers() {
    LPVOID bases[2048] = {};
    DWORD needed = 0;
    const BOOL ok = EnumDeviceDrivers(bases, sizeof(bases), &needed);
    const DWORD count = ok ? needed / static_cast<DWORD>(sizeof(LPVOID)) : 0;
    std::printf("driver_count=%lu\n", static_cast<unsigned long>(count));
}

void ProbeSetupDi() {
    HDEVINFO set = SetupDiGetClassDevsW(&GUID_DEVCLASS_DISKDRIVE, nullptr, nullptr, DIGCF_PRESENT);
    if (set == INVALID_HANDLE_VALUE) {
        std::printf("disk_setupdi=empty\n");
        return;
    }
    std::printf("disk_setupdi=ok\n");
    SetupDiDestroyDeviceInfoList(set);
}

void ProbeRegistryEnum() {
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ, &key) !=
        ERROR_SUCCESS) {
        std::printf("enum_machine_guid=open-error\n");
        return;
    }
    std::string value = "not-found";
    for (DWORD index = 0;; ++index) {
        wchar_t name[256] = {};
        DWORD nameLength = static_cast<DWORD>(_countof(name));
        BYTE data[512] = {};
        DWORD dataLength = static_cast<DWORD>(sizeof(data));
        DWORD type = 0;
        const LSTATUS status = RegEnumValueW(key, index, name, &nameLength, nullptr, &type,
                                             data, &dataLength);
        if (status != ERROR_SUCCESS) break;
        if (_wcsicmp(name, L"MachineGuid") == 0) {
            if (type == REG_SZ && dataLength >= sizeof(wchar_t)) {
                value = WideToUtf8(reinterpret_cast<const wchar_t*>(data));
            } else {
                value = "empty";
            }
            break;
        }
    }
    RegCloseKey(key);
    std::printf("enum_machine_guid=%s\n", value.c_str());
}

}  // namespace

int wmain() {
    HANDLE root = CreateFileW(L"C:\\", FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (root != INVALID_HANDLE_VALUE) {
        ProbeVolume(root);
        CloseHandle(root);
    } else {
        std::printf("handle_volume=open-error\nfile_volume=open-error\nnt_volume=open-error\n");
    }
    ProbeInterfaces();
    ProbeDiskSerial();
    ProbeDrivers();
    ProbeSetupDi();
    ProbeRegistryEnum();
    return 0;
}
