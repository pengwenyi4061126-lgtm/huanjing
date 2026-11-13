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
#include <devpkey.h>

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
typedef HANDLE (WINAPI* PFN_CreateFile2)(LPCWSTR, DWORD, DWORD, DWORD, LPCREATEFILE2_EXTENDED_PARAMETERS);
typedef NTSTATUS (NTAPI* PFN_NtCreateFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
                                           PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef HDEVINFO (WINAPI* PFN_SetupDiGetClassDevsW)(const GUID*, PCWSTR, HWND, DWORD);
typedef BOOL (WINAPI* PFN_SetupDiGetDevicePropertyW)(HDEVINFO, PSP_DEVINFO_DATA, const DEVPROPKEY*, DEVPROPTYPE*,
                                                     PBYTE, DWORD, PDWORD, DWORD);
typedef BOOL (WINAPI* PFN_SetupDiGetDeviceRegistryPropertyW)(HDEVINFO, PSP_DEVINFO_DATA, DWORD, PDWORD,
                                                              PBYTE, DWORD, PDWORD);
typedef BOOL (WINAPI* PFN_SetupDiGetDeviceInstanceIdW)(HDEVINFO, PSP_DEVINFO_DATA, PWSTR, DWORD, PDWORD);

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

void ProbeSetupDiDynamic() {
    HMODULE setupapi = LoadLibraryW(L"setupapi.dll");
    if (!setupapi) {
        std::printf("setupdi_dynamic=missing\n");
        return;
    }
    auto getClassDevs = reinterpret_cast<PFN_SetupDiGetClassDevsW>(
        GetProcAddress(setupapi, "SetupDiGetClassDevsW"));
    auto getProperty = reinterpret_cast<PFN_SetupDiGetDevicePropertyW>(
        GetProcAddress(setupapi, "SetupDiGetDevicePropertyW"));
    auto getRegistryProperty = reinterpret_cast<PFN_SetupDiGetDeviceRegistryPropertyW>(
        GetProcAddress(setupapi, "SetupDiGetDeviceRegistryPropertyW"));
    auto getInstanceId = reinterpret_cast<PFN_SetupDiGetDeviceInstanceIdW>(
        GetProcAddress(setupapi, "SetupDiGetDeviceInstanceIdW"));
    if (!getClassDevs || !getProperty || !getRegistryProperty || !getInstanceId) {
        std::printf("setupdi_dynamic=missing\n");
        FreeLibrary(setupapi);
        return;
    }

    HDEVINFO set = getClassDevs(&GUID_DEVCLASS_DISKDRIVE, nullptr, nullptr, DIGCF_PRESENT);
    if (set == INVALID_HANDLE_VALUE) {
        std::printf("setupdi_dynamic=empty\n");
        FreeLibrary(setupapi);
        return;
    }
    SP_DEVINFO_DATA info = {};
    info.cbSize = sizeof(info);
    if (!SetupDiEnumDeviceInfo(set, 0, &info)) {
        std::printf("setupdi_dynamic=enum-empty\n");
        SetupDiDestroyDeviceInfoList(set);
        FreeLibrary(setupapi);
        return;
    }

    BYTE propertyBuffer[512] = {};
    DEVPROPTYPE propertyType = 0;
    DWORD required = 0;
    const BOOL propertyOk = getProperty(set, &info, &DEVPKEY_Device_InstanceId, &propertyType,
                                        propertyBuffer, sizeof(propertyBuffer), &required, 0);
    BYTE registryBuffer[512] = {};
    DWORD registryType = 0;
    DWORD registryRequired = 0;
    const BOOL registryOk = getRegistryProperty(set, &info, SPDRP_HARDWAREID, &registryType,
                                                registryBuffer, sizeof(registryBuffer), &registryRequired);
    wchar_t instanceId[512] = {};
    DWORD instanceRequired = 0;
    const BOOL instanceOk = getInstanceId(set, &info, instanceId, _countof(instanceId), &instanceRequired);
    std::printf("setupdi_dynamic_property=%s\n", propertyOk ? "ok" : "empty");
    std::printf("setupdi_dynamic_registry=%s\n", registryOk ? "ok" : "empty");
    std::printf("setupdi_dynamic_instance=%s\n", instanceOk ? "ok" : "empty");
    SetupDiDestroyDeviceInfoList(set);
    FreeLibrary(setupapi);
}

void ProbeRawCreateAlternates() {
    const char* rawAnsi = "\\\\.\\PhysicalDrive0";
    HANDLE ansi = CreateFileA(rawAnsi, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              nullptr, OPEN_EXISTING, 0, nullptr);
    const DWORD ansiError = ansi == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
    std::printf("raw_createfile_a=%s\n",
                ansi == INVALID_HANDLE_VALUE ? (ansiError == ERROR_ACCESS_DENIED ? "denied" : "error") : "opened");
    if (ansi != INVALID_HANDLE_VALUE) CloseHandle(ansi);

    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    auto createFile2 = reinterpret_cast<PFN_CreateFile2>(
        kernel32 ? GetProcAddress(kernel32, "CreateFile2") : nullptr);
    HANDLE file2 = createFile2
        ? createFile2(L"\\\\.\\PhysicalDrive0", GENERIC_READ,
                      FILE_SHARE_READ | FILE_SHARE_WRITE, OPEN_EXISTING, nullptr)
        : INVALID_HANDLE_VALUE;
    const DWORD file2Error = file2 == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
    std::printf("raw_createfile2=%s\n",
                !createFile2 ? "missing" :
                (file2 == INVALID_HANDLE_VALUE ? (file2Error == ERROR_ACCESS_DENIED ? "denied" : "error") : "opened"));
    if (file2 != INVALID_HANDLE_VALUE) CloseHandle(file2);

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto ntCreateFile = reinterpret_cast<PFN_NtCreateFile>(
        ntdll ? GetProcAddress(ntdll, "NtCreateFile") : nullptr);
    std::wstring rawNtPath = L"\\??\\PhysicalDrive0";
    UNICODE_STRING name = {};
    name.Length = static_cast<USHORT>(rawNtPath.size() * sizeof(wchar_t));
    name.MaximumLength = name.Length;
    name.Buffer = rawNtPath.data();
    OBJECT_ATTRIBUTES attributes = {};
    attributes.Length = sizeof(attributes);
    attributes.Attributes = OBJ_CASE_INSENSITIVE;
    attributes.ObjectName = &name;
    IO_STATUS_BLOCK ioStatus = {};
    HANDLE ntFile = nullptr;
    const NTSTATUS ntStatus = ntCreateFile
        ? ntCreateFile(&ntFile, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &attributes, &ioStatus, nullptr,
                       FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN,
                       FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0)
        : static_cast<NTSTATUS>(0xC0000002L);
    std::printf("raw_ntcreatefile=%s\n",
                !ntCreateFile ? "missing" :
                (ntStatus == static_cast<NTSTATUS>(0xC0000022L) ? "denied" :
                 (ntStatus >= 0 ? "opened" : "error")));
    if (ntFile) CloseHandle(ntFile);
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
    setvbuf(stdout, nullptr, _IONBF, 0);
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
    ProbeSetupDiDynamic();
    ProbeRawCreateAlternates();
    ProbeRegistryEnum();
    return 0;
}
