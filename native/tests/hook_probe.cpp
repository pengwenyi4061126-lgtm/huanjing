#define _WIN32_WINNT 0x0A00

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <winioctl.h>
#include <hidsdi.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "hid.lib")

namespace {

unsigned long long Fnv(const BYTE* data, size_t length) {
    unsigned long long hash = 1469598103934665603ULL;
    for (size_t i = 0; i < length; ++i) {
        hash ^= data[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

std::string FirstAdapterMac() {
    ULONG size = 0;
    GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                         nullptr, nullptr, &size);
    std::vector<BYTE> buffer(size);
    PIP_ADAPTER_ADDRESSES addresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                             nullptr, addresses, &size) != NO_ERROR) {
        return "error";
    }
    for (PIP_ADAPTER_ADDRESSES current = addresses; current; current = current->Next) {
        if (current->PhysicalAddressLength == 6) {
            char text[32] = {};
            std::snprintf(text, sizeof(text), "%02x:%02x:%02x:%02x:%02x:%02x",
                          current->PhysicalAddress[0], current->PhysicalAddress[1], current->PhysicalAddress[2],
                          current->PhysicalAddress[3], current->PhysicalAddress[4], current->PhysicalAddress[5]);
            return text;
        }
    }
    return "none";
}

std::string FirstInfoMac() {
    ULONG size = 0;
    GetAdaptersInfo(nullptr, &size);
    std::vector<BYTE> buffer(size);
    PIP_ADAPTER_INFO info = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());
    if (GetAdaptersInfo(info, &size) != ERROR_SUCCESS) return "error";
    for (PIP_ADAPTER_INFO current = info; current; current = current->Next) {
        if (current->AddressLength == 6) {
            char text[32] = {};
            std::snprintf(text, sizeof(text), "%02x:%02x:%02x:%02x:%02x:%02x",
                          current->Address[0], current->Address[1], current->Address[2],
                          current->Address[3], current->Address[4], current->Address[5]);
            return text;
        }
    }
    return "none";
}

std::string SmbiosReport(unsigned long long* hashOut) {
    const DWORD signature = 'RSMB';
    const UINT size = GetSystemFirmwareTable(signature, 0, nullptr, 0);
    if (size == 0) return "unavailable";
    std::vector<BYTE> buffer(size);
    const UINT got = GetSystemFirmwareTable(signature, 0, buffer.data(), size);
    if (got == 0) return "unavailable";
    *hashOut = Fnv(buffer.data(), got);

    BYTE* table = buffer.data();
    DWORD length = got;
    if (length > 8 && table[0] == 0 && table[1] >= 2 && table[1] <= 3 && table[8] == 0) {
        length = *reinterpret_cast<DWORD*>(table + 4);
        table += 8;
    }
    BYTE* end = table + length;
    BYTE* cursor = table;
    while (cursor + 4 <= end) {
        const BYTE type = cursor[0];
        const BYTE structLength = cursor[1];
        if (structLength < 4 || cursor + structLength > end) break;
        BYTE* strings = cursor + structLength;
        BYTE* setEnd = strings;
        while (setEnd + 1 < end && !(setEnd[0] == 0 && setEnd[1] == 0)) ++setEnd;
        setEnd += 2;
        if (type == 1 && structLength > 0x07) {
            const int index = cursor[0x07];
            int current = 1;
            for (BYTE* p = strings; p < setEnd - 2; ++current) {
                const size_t len = strnlen(reinterpret_cast<char*>(p), static_cast<size_t>(setEnd - p));
                if (current == index) return std::string(reinterpret_cast<char*>(p), len);
                p += len + 1;
            }
        }
        cursor = setEnd;
    }
    return "not-found";
}

std::string DiskSerial() {
    HANDLE device = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (device == INVALID_HANDLE_VALUE) return "open-failed";
    STORAGE_PROPERTY_QUERY query = {};
    query.PropertyId = StorageDeviceProperty;
    query.QueryType = PropertyStandardQuery;
    BYTE output[1024] = {};
    DWORD returned = 0;
    const BOOL ok = DeviceIoControl(device, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query),
                                    output, sizeof(output), &returned, nullptr);
    CloseHandle(device);
    if (!ok) return "ioctl-failed";
    STORAGE_DEVICE_DESCRIPTOR* descriptor = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR*>(output);
    if (descriptor->SerialNumberOffset == 0 || descriptor->SerialNumberOffset >= returned) return "no-serial";
    return std::string(reinterpret_cast<char*>(output) + descriptor->SerialNumberOffset);
}

std::string WideToUtf8(const wchar_t* value) {
    if (!value) return "";
    const int length = WideCharToMultiByte(CP_UTF8, 0, value, -1, nullptr, 0, nullptr, nullptr);
    if (length <= 1) return "";
    std::string result(static_cast<size_t>(length - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value, -1, result.data(), length, nullptr, nullptr);
    return result;
}

std::string ComputerName() {
    wchar_t buffer[256] = {};
    DWORD size = static_cast<DWORD>(_countof(buffer));
    if (!GetComputerNameW(buffer, &size)) return "error";
    return WideToUtf8(buffer);
}

std::string UserName() {
    wchar_t buffer[256] = {};
    DWORD size = static_cast<DWORD>(_countof(buffer));
    if (!GetUserNameW(buffer, &size)) return "error";
    return WideToUtf8(buffer);
}

std::string ComputerNameEx() {
    wchar_t buffer[256] = {};
    DWORD size = static_cast<DWORD>(_countof(buffer));
    if (!GetComputerNameExW(ComputerNameDnsHostname, buffer, &size)) return "error";
    return WideToUtf8(buffer);
}

std::string MachineGuidRegistry() {
    wchar_t buffer[256] = {};
    DWORD size = sizeof(buffer);
    if (RegGetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid",
                     RRF_RT_REG_SZ, nullptr, buffer, &size) != ERROR_SUCCESS) {
        return "error";
    }
    return WideToUtf8(buffer);
}

std::string MachineGuidQuery() {
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ, &key) != ERROR_SUCCESS) {
        return "open-error";
    }
    wchar_t buffer[256] = {};
    DWORD size = sizeof(buffer);
    DWORD type = 0;
    const LSTATUS status = RegQueryValueExW(key, L"MachineGuid", nullptr, &type,
                                            reinterpret_cast<LPBYTE>(buffer), &size);
    RegCloseKey(key);
    if (status != ERROR_SUCCESS) return "query-error";
    return WideToUtf8(buffer);
}

std::string HidSerial() {
    wchar_t buffer[256] = {};
    if (!HidD_GetSerialNumberString(reinterpret_cast<HANDLE>(static_cast<uintptr_t>(1)),
                                    buffer, static_cast<ULONG>(sizeof(buffer)))) {
        return "error";
    }
    return WideToUtf8(buffer);
}

}  // namespace

int wmain() {
    DWORD volumeSerial = 0;
    GetVolumeInformationW(L"C:\\", nullptr, 0, &volumeSerial, nullptr, nullptr, nullptr, 0);
    unsigned long long smbiosHash = 0;
    const std::string smbiosSerial = SmbiosReport(&smbiosHash);
    std::printf("mac=%s\n", FirstAdapterMac().c_str());
    std::printf("mac_info=%s\n", FirstInfoMac().c_str());
    std::printf("volume=%08X\n", static_cast<unsigned int>(volumeSerial));
    std::printf("smbios_hash=%016llX\n", smbiosHash);
    std::printf("smbios_serial=%s\n", smbiosSerial.c_str());
    std::printf("disk_serial=%s\n", DiskSerial().c_str());
    std::printf("native_computer_name=%s\n", ComputerName().c_str());
    std::printf("native_computer_name_ex=%s\n", ComputerNameEx().c_str());
    std::printf("native_user_name=%s\n", UserName().c_str());
    std::printf("native_machine_guid=%s\n", MachineGuidRegistry().c_str());
    std::printf("native_machine_guid_query=%s\n", MachineGuidQuery().c_str());
    std::printf("native_hid_serial=%s\n", HidSerial().c_str());
    wchar_t audit[32768] = {};
    GetEnvironmentVariableW(L"CAC_NATIVE_AUDIT", audit, static_cast<DWORD>(_countof(audit)));
    std::printf("audit=%ls\n", audit);
    return 0;
}
