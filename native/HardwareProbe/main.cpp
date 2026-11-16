#define _WIN32_WINNT 0x0A00

#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <tlhelp32.h>

#include <cstdint>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")

namespace {

typedef NTSTATUS (NTAPI* PFN_NtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);

struct SystemModuleEntry {
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
};

struct SystemModuleInformation {
    ULONG Count;
    SystemModuleEntry Modules[1];
};

bool IsVirtualName(const char* name) {
    if (!name) return false;
    static const char* const markers[] = {
        "vmcompute", "vmbus", "hvservice", "hvix64", "hvax64", "winhvr",
        "vmbusr", "storvsp", "netvsc", "hidvsp", "vpci", "hyperkbd",
        "vsmb", "vhdmp", "wsl", "lxss", "vmms", "vmswitch", "vmsif",
    };
    std::string lower(name);
    for (char& c : lower) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    for (const char* marker : markers) {
        if (lower.find(marker) != std::string::npos) return true;
    }
    return false;
}

char* SmbiosString(BYTE* structure, BYTE structLength, int index) {
    if (index <= 0) return nullptr;
    BYTE* p = structure + structLength;
    int current = 1;
    while (p[0] || p[1]) {
        if (current == index) return reinterpret_cast<char*>(p);
        p += std::strlen(reinterpret_cast<char*>(p)) + 1;
        ++current;
    }
    return nullptr;
}

void ProbeSmbios() {
    const DWORD signature = 0x52534D42;
    const UINT needed = GetSystemFirmwareTable(signature, 0, nullptr, 0);
    std::vector<BYTE> buffer(needed ? needed : 1);
    const UINT result = needed ? GetSystemFirmwareTable(signature, 0, buffer.data(), needed) : 0;
    std::printf("smbios_size=%u\n", result);
    if (!result) return;
    BYTE* table = buffer.data();
    DWORD length = result;
    if (length >= 8 && buffer[0] == 0 && buffer[1] >= 2 && buffer[1] <= 3) {
        const DWORD declared = *reinterpret_cast<DWORD*>(buffer.data() + 4);
        if (declared > 0 && declared <= length - 8) {
            table = buffer.data() + 8;
            length = declared;
        }
    }
    BYTE* cursor = table;
    BYTE* end = table + length;
    while (cursor + 4 <= end) {
        const BYTE type = cursor[0];
        const BYTE structLength = cursor[1];
        if (structLength < 4 || cursor + structLength > end) break;
        BYTE* strings = cursor + structLength;
        BYTE* stringsEnd = strings;
        while (stringsEnd + 1 < end && !(stringsEnd[0] == 0 && stringsEnd[1] == 0)) ++stringsEnd;
        if (stringsEnd + 1 >= end) break;
        stringsEnd += 2;
        if (type == 1 && structLength > 0x07) {
            char* serial = SmbiosString(cursor, structLength, cursor[0x07]);
            std::printf("smbios_type1_serial=%s\n", serial ? serial : "");
        } else if (type == 4 && structLength > 0x10) {
            char* version = SmbiosString(cursor, structLength, cursor[0x10]);
            std::printf("smbios_type4_version=%s\n", version ? version : "");
        } else if (type == 17 && structLength > 0x1A) {
            char* serial = SmbiosString(cursor, structLength, cursor[0x18]);
            char* part = SmbiosString(cursor, structLength, cursor[0x1A]);
            const unsigned int size = structLength > 0x0D
                ? *reinterpret_cast<WORD*>(cursor + 0x0C) : 0;
            std::printf("smbios_type17_serial=%s part=%s size=%u\n", serial ? serial : "",
                        part ? part : "", size);
        } else if (type == 43 && structLength >= 0x13) {
            const DWORD vendor = *reinterpret_cast<DWORD*>(cursor + 0x04);
            std::printf("smbios_type43_vendor=0x%08x major=%u minor=%u\n", vendor,
                        cursor[0x08], cursor[0x09]);
        }
        cursor = stringsEnd;
    }
}

void ProbeFirmwareTables() {
    const UINT needed = EnumSystemFirmwareTables(0, nullptr, 0);
    std::vector<DWORD> signatures(needed ? needed / sizeof(DWORD) : 1);
    const UINT result = needed ? EnumSystemFirmwareTables(0, signatures.data(), needed) : 0;
    std::printf("firmware_table_signatures=%u", result / sizeof(DWORD));
    for (UINT i = 0; i < result / sizeof(DWORD); ++i) {
        std::printf(" 0x%08x", signatures[i]);
    }
    std::printf("\n");
    const UINT acpi = GetSystemFirmwareTable(0x41435049, 0, nullptr, 0);
    std::printf("acpi_size=%u\n", acpi);
}

void ProbeDrivers() {
    DWORD needed = 0;
    EnumDeviceDrivers(nullptr, 0, &needed);
    std::vector<LPVOID> drivers(needed ? needed / sizeof(LPVOID) : 1);
    DWORD result = 0;
    if (!EnumDeviceDrivers(drivers.data(), static_cast<DWORD>(drivers.size() * sizeof(LPVOID)),
                           &result)) {
        std::printf("enumdrivers=failed\n");
        return;
    }
    const DWORD count = result / sizeof(LPVOID);
    int virtualCount = 0;
    std::string names;
    for (DWORD i = 0; i < count; ++i) {
        wchar_t name[260] = {};
        GetDeviceDriverBaseNameW(drivers[i], name, _countof(name));
        char narrow[260] = {};
        WideCharToMultiByte(CP_UTF8, 0, name, -1, narrow, sizeof(narrow), nullptr, nullptr);
        if (IsVirtualName(narrow)) {
            ++virtualCount;
            names += narrow;
            names += ",";
        }
    }
    std::printf("drivers=%lu virtual=%d names=%s\n", static_cast<unsigned long>(count),
                virtualCount, names.c_str());
}

void ProbeModules() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto query = reinterpret_cast<PFN_NtQuerySystemInformation>(
        GetProcAddress(ntdll, "NtQuerySystemInformation"));
    if (!query) return;
    ULONG needed = 0;
    query(11, nullptr, 0, &needed);
    std::vector<BYTE> buffer(needed ? needed : 0x10000);
    ULONG result = 0;
    const NTSTATUS status = query(11, buffer.data(), static_cast<ULONG>(buffer.size()), &result);
    if (status < 0) {
        std::printf("modules_status=0x%08lx\n", static_cast<unsigned long>(status));
        return;
    }
    auto* modules = reinterpret_cast<SystemModuleInformation*>(buffer.data());
    int virtualCount = 0;
    std::string names;
    for (ULONG i = 0; i < modules->Count; ++i) {
        const SystemModuleEntry& entry = modules->Modules[i];
        if (entry.OffsetToFileName >= sizeof(entry.FullPathName)) continue;
        const char* name = reinterpret_cast<const char*>(entry.FullPathName +
                                                         entry.OffsetToFileName);
        if (IsVirtualName(name)) {
            ++virtualCount;
            names += name;
            names += ",";
        }
    }
    std::printf("modules=%lu virtual=%d names=%s\n",
                static_cast<unsigned long>(modules->Count), virtualCount, names.c_str());
}

void ProbeRegistryEdid() {
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software", 0, KEY_READ, &key) != ERROR_SUCCESS) return;
    BYTE edid[256] = {};
    DWORD size = sizeof(edid);
    DWORD type = 0;
    const LSTATUS status = RegQueryValueExW(key, L"EDID", nullptr, &type, edid, &size);
    RegCloseKey(key);
    std::printf("edid_status=%ld type=%lu size=%lu head=", status, type, size);
    for (DWORD i = 0; i < size && i < 8; ++i) std::printf("%02x", edid[i]);
    std::printf("\n");
}

}  // namespace

int wmain() {
    Sleep(500);
    MEMORYSTATUSEX memory = {};
    memory.dwLength = sizeof(memory);
    GlobalMemoryStatusEx(&memory);
    std::printf("memory_total_mb=%llu available_mb=%llu load=%lu\n",
                memory.ullTotalPhys / 1024ULL / 1024ULL,
                memory.ullAvailPhys / 1024ULL / 1024ULL,
                static_cast<unsigned long>(memory.dwMemoryLoad));

    ULONGLONG installedKb = 0;
    GetPhysicallyInstalledSystemMemory(&installedKb);
    std::printf("physically_installed_mb=%llu\n", installedKb / 1024ULL);

    ULARGE_INTEGER freeAvailable = {};
    ULARGE_INTEGER total = {};
    ULARGE_INTEGER totalFree = {};
    GetDiskFreeSpaceExW(L"C:\\", &freeAvailable, &total, &totalFree);
    std::printf("disk_total_gb=%llu free_gb=%llu\n",
                total.QuadPart / 1024ULL / 1024ULL / 1024ULL,
                totalFree.QuadPart / 1024ULL / 1024ULL / 1024ULL);

    wchar_t volumeName[64] = {};
    wchar_t fileSystem[32] = {};
    DWORD serial = 0;
    GetVolumeInformationW(L"C:\\", volumeName, _countof(volumeName), &serial, nullptr, nullptr,
                          fileSystem, _countof(fileSystem));
    std::printf("volume_label=%ls filesystem=%ls serial=%08lx\n", volumeName, fileSystem,
                static_cast<unsigned long>(serial));

    SYSTEM_INFO systemInfo = {};
    GetSystemInfo(&systemInfo);
    std::printf("processors=%lu\n", static_cast<unsigned long>(systemInfo.dwNumberOfProcessors));

    DISPLAY_DEVICEW display = {};
    display.cb = sizeof(display);
    if (EnumDisplayDevicesW(nullptr, 0, &display, 0)) {
        std::printf("display0_name=%ls string=%ls id=%ls\n", display.DeviceName,
                    display.DeviceString, display.DeviceID);
    }
    DEVMODEW mode = {};
    mode.dmSize = sizeof(mode);
    if (EnumDisplaySettingsW(nullptr, ENUM_CURRENT_SETTINGS, &mode)) {
        std::printf("display_mode=%lux%lu@%lu\n",
                    static_cast<unsigned long>(mode.dmPelsWidth),
                    static_cast<unsigned long>(mode.dmPelsHeight),
                    static_cast<unsigned long>(mode.dmDisplayFrequency));
    }
    POINT point = {0, 0};
    HMONITOR monitor = MonitorFromPoint(point, MONITOR_DEFAULTTOPRIMARY);
    MONITORINFOEXW monitorInfo = {};
    monitorInfo.cbSize = sizeof(monitorInfo);
    if (GetMonitorInfoW(monitor, &monitorInfo)) {
        std::printf("monitor_name=%ls primary=%lu\n", monitorInfo.szDevice,
                    static_cast<unsigned long>(monitorInfo.dwFlags));
    }

    ProbeSmbios();
    ProbeFirmwareTables();
    ProbeDrivers();
    ProbeModules();
    ProbeRegistryEdid();
    Sleep(1000);
    return 0;
}
