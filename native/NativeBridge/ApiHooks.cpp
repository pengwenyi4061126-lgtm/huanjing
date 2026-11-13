#define _WIN32_WINNT 0x0A00

#include "ApiHooks.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <winioctl.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <bcrypt.h>
#include <intrin.h>
#include <setupapi.h>
#include <devpropdef.h>
#include <initguid.h>
#include <devguid.h>
#include <netioapi.h>
#include <psapi.h>

#include <cstdint>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <string>
#include <vector>

#include "Audit.h"
#include "Firmware.h"
#include "HookEngine.h"
#include "Identity.h"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "bcrypt.lib")

namespace {

std::wstring Utf8ToWide(const std::string& value);

enum class NativeReadPolicy {
    Profile,
    Empty,
};

NativeReadPolicy GetNativeReadPolicy() {
    static int cached = -1;
    if (cached < 0) {
        char value[32] = {};
        const DWORD size = GetEnvironmentVariableA("CAC_NATIVE_READ_POLICY", value,
                                                   static_cast<DWORD>(sizeof(value)));
        cached = (size > 0 && size < sizeof(value) && _stricmp(value, "empty") == 0) ? 1 : 0;
    }
    return cached == 1 ? NativeReadPolicy::Empty : NativeReadPolicy::Profile;
}

bool EmptyReadsEnabled() {
    return GetNativeReadPolicy() == NativeReadPolicy::Empty;
}

bool ContainsNoCase(const wchar_t* text, const wchar_t* needle) {
    if (!text || !needle || !*needle) return false;
    const size_t length = wcslen(needle);
    for (const wchar_t* cursor = text; *cursor; ++cursor) {
        if (_wcsnicmp(cursor, needle, length) == 0) return true;
    }
    return false;
}

std::wstring AnsiToWide(const char* value) {
    if (!value || !*value) return std::wstring();
    const int length = MultiByteToWideChar(CP_ACP, 0, value, -1, nullptr, 0);
    if (length <= 1) return std::wstring();
    std::wstring result(static_cast<size_t>(length), L'\0');
    MultiByteToWideChar(CP_ACP, 0, value, -1, result.data(), length);
    result.pop_back();
    return result;
}

bool IsVirtualAdapter(const IP_ADAPTER_ADDRESSES* adapter) {
    if (!adapter) return false;
    return NativeIsVirtualAdapterName(adapter->FriendlyName) ||
           NativeIsVirtualAdapterName(adapter->Description);
}

bool IsVirtualAdapter(const IP_ADAPTER_INFO* adapter) {
    if (!adapter) return false;
    return NativeIsVirtualAdapterName(AnsiToWide(adapter->Description).c_str()) ||
           NativeIsVirtualAdapterName(AnsiToWide(adapter->AdapterName).c_str());
}

void FilterAdapterAddresses(PIP_ADAPTER_ADDRESSES head) {
    if (!head) return;
    const bool emptyAll = EmptyReadsEnabled();
    PIP_ADAPTER_ADDRESSES firstKept = nullptr;
    for (PIP_ADAPTER_ADDRESSES cursor = head; cursor; cursor = cursor->Next) {
        if (!emptyAll && !IsVirtualAdapter(cursor)) {
            firstKept = cursor;
            break;
        }
    }
    if (!firstKept) {
        std::memset(head, 0, sizeof(IP_ADAPTER_ADDRESSES));
        head->Next = nullptr;
        head->OperStatus = IfOperStatusDown;
        AuditEventRateLimited("api.getadaptersaddresses", "clean-none");
        return;
    }
    if (firstKept != head) {
        const IP_ADAPTER_ADDRESSES saved = *firstKept;
        *head = saved;
    }
    PIP_ADAPTER_ADDRESSES* link = &head->Next;
    while (*link) {
        if (emptyAll || IsVirtualAdapter(*link)) {
            *link = (*link)->Next;
        } else {
            link = &(*link)->Next;
        }
    }
    AuditEventRateLimited("api.getadaptersaddresses", "cleaned");
}

void FilterAdapterInfo(PIP_ADAPTER_INFO head) {
    if (!head) return;
    const bool emptyAll = EmptyReadsEnabled();
    PIP_ADAPTER_INFO firstKept = nullptr;
    for (PIP_ADAPTER_INFO cursor = head; cursor; cursor = cursor->Next) {
        if (!emptyAll && !IsVirtualAdapter(cursor)) {
            firstKept = cursor;
            break;
        }
    }
    if (!firstKept) {
        std::memset(head, 0, sizeof(IP_ADAPTER_INFO));
        head->Next = nullptr;
        AuditEventRateLimited("api.getadaptersinfo", "clean-none");
        return;
    }
    if (firstKept != head) {
        const IP_ADAPTER_INFO saved = *firstKept;
        *head = saved;
    }
    PIP_ADAPTER_INFO* link = &head->Next;
    while (*link) {
        if (emptyAll || IsVirtualAdapter(*link)) {
            *link = (*link)->Next;
        } else {
            link = &(*link)->Next;
        }
    }
    AuditEventRateLimited("api.getadaptersinfo", "cleaned");
}

bool IsVirtualIfRow(const MIB_IF_ROW2& row) {
    return NativeIsVirtualAdapterName(row.Alias) ||
           NativeIsVirtualAdapterName(row.Description) ||
           row.Type == IF_TYPE_TUNNEL || row.Type == IF_TYPE_PPP;
}

void FilterIfTable2(PMIB_IF_TABLE2 table) {
    if (!table) return;
    if (EmptyReadsEnabled()) {
        table->NumEntries = 0;
        AuditEventRateLimited("api.getiftable2", "clean-none");
        return;
    }
    ULONG kept = 0;
    for (ULONG index = 0; index < table->NumEntries; ++index) {
        if (IsVirtualIfRow(table->Table[index])) continue;
        if (kept != index) table->Table[kept] = table->Table[index];
        ++kept;
    }
    table->NumEntries = kept;
    AuditEventRateLimited("api.getiftable2", "cleaned");
}

bool CopyEmptyWideToBuffer(LPWSTR buffer, DWORD capacity, LPDWORD outSize) {
    if (outSize) *outSize = 1;
    if (!buffer || capacity < 1) {
        SetLastError(ERROR_MORE_DATA);
        return false;
    }
    buffer[0] = L'\0';
    SetLastError(ERROR_SUCCESS);
    return true;
}

void ClearAdapterMac(BYTE* address, ULONG* length) {
    if (!address || !length || *length == 0) return;
    std::memset(address, 0, 6);
    *length = 0;
}

void ClearAdapterMac(PIP_ADAPTER_INFO adapter) {
    if (!adapter || adapter->AddressLength == 0) return;
    std::memset(adapter->Address, 0, sizeof(adapter->Address));
    adapter->AddressLength = 0;
}

typedef ULONG (WINAPI* PFN_GetAdaptersAddresses)(ULONG, ULONG, PVOID, PIP_ADAPTER_ADDRESSES, PULONG);
typedef DWORD (WINAPI* PFN_GetAdaptersInfo)(PIP_ADAPTER_INFO, PULONG);
typedef BOOL (WINAPI* PFN_GetVolumeInformationW)(LPCWSTR, LPWSTR, DWORD, LPDWORD, LPDWORD, LPDWORD, LPWSTR, DWORD);
typedef UINT (WINAPI* PFN_GetSystemFirmwareTable)(DWORD, DWORD, PVOID, DWORD);
typedef NTSTATUS (NTAPI* PFN_NtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
typedef BOOL (WINAPI* PFN_DeviceIoControl)(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL (WINAPI* PFN_GetComputerNameW)(LPWSTR, LPDWORD);
typedef BOOL (WINAPI* PFN_GetComputerNameExW)(COMPUTER_NAME_FORMAT, LPWSTR, LPDWORD);
typedef BOOL (WINAPI* PFN_GetUserNameW)(LPWSTR, LPDWORD);
typedef LSTATUS (WINAPI* PFN_RegGetValueW)(HKEY, LPCWSTR, LPCWSTR, DWORD, LPDWORD, PVOID, LPDWORD);
typedef LSTATUS (WINAPI* PFN_RegQueryValueExW)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
typedef BOOLEAN (WINAPI* PFN_HidD_GetSerialNumberString)(HANDLE, PVOID, ULONG);
typedef BOOL (WINAPI* PFN_SetupDiGetDevicePropertyW)(HDEVINFO, PSP_DEVINFO_DATA, const DEVPROPKEY*, DEVPROPTYPE*, PBYTE, DWORD, PDWORD, DWORD);
typedef BOOL (WINAPI* PFN_SetupDiGetDeviceRegistryPropertyW)(HDEVINFO, PSP_DEVINFO_DATA, DWORD, PDWORD, PBYTE, DWORD, PDWORD);
typedef BOOL (WINAPI* PFN_SetupDiGetDeviceInstanceIdW)(HDEVINFO, PSP_DEVINFO_DATA, PWSTR, DWORD, PDWORD);
typedef BOOL (WINAPI* PFN_GetVolumeInformationByHandleW)(HANDLE, LPWSTR, DWORD, LPDWORD, LPDWORD, LPDWORD, LPWSTR, DWORD);
typedef BOOL (WINAPI* PFN_GetFileInformationByHandle)(HANDLE, LPBY_HANDLE_FILE_INFORMATION);
typedef NTSTATUS (NTAPI* PFN_NtQueryVolumeInformationFile)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG);
typedef NTSTATUS (NTAPI* PFN_NtDeviceIoControlFile)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID,
                                                    PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
typedef HANDLE (WINAPI* PFN_CreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef HANDLE (WINAPI* PFN_CreateFile2)(LPCWSTR, DWORD, DWORD, DWORD, LPCREATEFILE2_EXTENDED_PARAMETERS);
typedef NTSTATUS (NTAPI* PFN_NtCreateFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
                                           PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef BOOL (WINAPI* PFN_GetOverlappedResult)(HANDLE, LPOVERLAPPED, LPDWORD, BOOL);
typedef BOOL (WINAPI* PFN_GetOverlappedResultEx)(HANDLE, LPOVERLAPPED, LPDWORD, DWORD, BOOL);
typedef BOOL (WINAPI* PFN_GetQueuedCompletionStatus)(HANDLE, LPDWORD, PULONG_PTR, LPOVERLAPPED*, DWORD);
typedef BOOL (WINAPI* PFN_GetQueuedCompletionStatusEx)(HANDLE, LPOVERLAPPED_ENTRY, ULONG, PULONG, DWORD, BOOL);
typedef NETIO_STATUS (WINAPI* PFN_GetIfTable2)(PMIB_IF_TABLE2*);
typedef NETIO_STATUS (WINAPI* PFN_GetIfEntry2)(PMIB_IF_ROW2);
typedef DWORD (WINAPI* PFN_GetIfTable)(PMIB_IFTABLE, PULONG, BOOL);
typedef LSTATUS (WINAPI* PFN_RegEnumValueW)(HKEY, DWORD, LPWSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
typedef BOOL (WINAPI* PFN_EnumDeviceDrivers)(LPVOID*, DWORD, LPDWORD);
typedef HDEVINFO (WINAPI* PFN_SetupDiGetClassDevsW)(const GUID*, PCWSTR, HWND, DWORD);
typedef HANDLE (WINAPI* PFN_CreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);

PFN_GetAdaptersAddresses g_origGetAdaptersAddresses = nullptr;
PFN_GetAdaptersInfo g_origGetAdaptersInfo = nullptr;
PFN_GetVolumeInformationW g_origGetVolumeInformation = nullptr;
PFN_GetSystemFirmwareTable g_origGetSystemFirmwareTable = nullptr;
PFN_NtQuerySystemInformation g_origNtQuerySystemInformation = nullptr;
PFN_DeviceIoControl g_origDeviceIoControl = nullptr;
PFN_GetComputerNameW g_origGetComputerName = nullptr;
PFN_GetComputerNameExW g_origGetComputerNameEx = nullptr;
PFN_GetUserNameW g_origGetUserName = nullptr;
PFN_RegGetValueW g_origRegGetValue = nullptr;
PFN_RegQueryValueExW g_origRegQueryValueEx = nullptr;
PFN_HidD_GetSerialNumberString g_origHidGetSerial = nullptr;
PFN_SetupDiGetDevicePropertyW g_origSetupDiGetDeviceProperty = nullptr;
PFN_SetupDiGetDeviceRegistryPropertyW g_origSetupDiGetRegistryProperty = nullptr;
PFN_SetupDiGetDeviceInstanceIdW g_origSetupDiGetInstanceId = nullptr;
PFN_GetVolumeInformationByHandleW g_origGetVolumeInformationByHandle = nullptr;
PFN_GetFileInformationByHandle g_origGetFileInformationByHandle = nullptr;
PFN_NtQueryVolumeInformationFile g_origNtQueryVolumeInformationFile = nullptr;
PFN_NtDeviceIoControlFile g_origNtDeviceIoControlFile = nullptr;
PFN_GetIfTable2 g_origGetIfTable2 = nullptr;
PFN_GetIfEntry2 g_origGetIfEntry2 = nullptr;
PFN_GetIfTable g_origGetIfTable = nullptr;
PFN_RegEnumValueW g_origRegEnumValue = nullptr;
PFN_EnumDeviceDrivers g_origEnumDeviceDrivers = nullptr;
PFN_SetupDiGetClassDevsW g_origSetupDiGetClassDevs = nullptr;
PFN_CreateFileW g_origCreateFile = nullptr;
PFN_CreateFileA g_origCreateFileA = nullptr;
PFN_CreateFile2 g_origCreateFile2 = nullptr;
PFN_NtCreateFile g_origNtCreateFile = nullptr;
PFN_GetOverlappedResult g_origGetOverlappedResult = nullptr;
PFN_GetOverlappedResultEx g_origGetOverlappedResultEx = nullptr;
PFN_GetQueuedCompletionStatus g_origGetQueuedCompletionStatus = nullptr;
PFN_GetQueuedCompletionStatusEx g_origGetQueuedCompletionStatusEx = nullptr;

std::atomic<unsigned int> g_hookInstallFailures{0};

struct PendingDeviceIo {
    LPOVERLAPPED overlapped = nullptr;
    DWORD code = 0;
    std::vector<BYTE> input;
    LPVOID output = nullptr;
    DWORD outputSize = 0;
};

SRWLOCK g_pendingDeviceIoLock = SRWLOCK_INIT;
std::vector<PendingDeviceIo> g_pendingDeviceIo;

struct FirmwareTableInfo {
    ULONG ProviderSignature;
    ULONG Action;
    ULONG TableID;
    ULONG TableBufferLength;
    UCHAR TableBuffer[1];
};

constexpr DWORD kRsmbSignature = 0x52534D42;  // 'RSMB'

#ifndef IOCTL_SMART_RECEIVE_DRIVE_DATA
#define IOCTL_SMART_RECEIVE_DRIVE_DATA 0x0007C088
#endif

bool ReplaceBufferString(char* value, size_t maxLength, const std::string& desired) {
    if (!value || maxLength == 0) return false;
    size_t oldLength = strnlen(value, maxLength);
    if (oldLength == 0 || oldLength >= maxLength) return false;
    const size_t copy = desired.size() < maxLength - 1 ? desired.size() : maxLength - 1;
    std::memcpy(value, desired.data(), copy);
    if (copy < oldLength) std::memset(value + copy, ' ', oldLength - copy);
    value[copy] = 0;
    return true;
}

void PatchSmbiosAndAudit(BYTE* buffer, DWORD length) {
    int patched = 0;
    if (PatchSmbiosBuffer(buffer, length, ProfileIdentity::Get(), &patched)) {
        AuditEventRateLimited("smbios.patch", "patched", nullptr, static_cast<unsigned long long>(patched), true);
    }
}

bool CopyWideToBuffer(const std::wstring& value, LPWSTR buffer, DWORD capacity, LPDWORD outSize) {
    const DWORD needed = static_cast<DWORD>(value.size()) + 1;
    if (outSize) *outSize = needed;
    if (!buffer || capacity < needed) {
        SetLastError(ERROR_MORE_DATA);
        return false;
    }
    std::wmemcpy(buffer, value.c_str(), needed);
    SetLastError(ERROR_SUCCESS);
    return true;
}

bool GetRegistrySpoofValue(const wchar_t* name, std::wstring& value) {
    if (!name) return false;
    const ProfileIdentity& identity = ProfileIdentity::Get();
    if (_wcsicmp(name, L"MachineGuid") == 0) { value = Utf8ToWide(identity.machineId); return true; }
    if (_wcsicmp(name, L"SystemSerialNumber") == 0) { value = Utf8ToWide(identity.systemSerial); return true; }
    if (_wcsicmp(name, L"BaseBoardSerialNumber") == 0) { value = Utf8ToWide(identity.boardSerial); return true; }
    if (_wcsicmp(name, L"BIOSVersion") == 0) { value = L"F.20"; return true; }
    if (_wcsicmp(name, L"BIOSReleaseDate") == 0) { value = L"01/01/2024"; return true; }
    if (_wcsicmp(name, L"BIOSVendor") == 0) { value = L"American Megatrends Inc."; return true; }
    if (_wcsicmp(name, L"SystemManufacturer") == 0 || _wcsicmp(name, L"BaseBoardManufacturer") == 0) {
        value = L"Default string"; return true;
    }
    if (_wcsicmp(name, L"SystemProductName") == 0) { value = L"System Product Name"; return true; }
    if (_wcsicmp(name, L"BaseBoardProduct") == 0) { value = L"Base Board"; return true; }
    if (_wcsicmp(name, L"SystemVersion") == 0 || _wcsicmp(name, L"BaseBoardVersion") == 0) {
        value = L"1.0"; return true;
    }
    if (_wcsicmp(name, L"SystemSKU") == 0 || _wcsicmp(name, L"SystemFamily") == 0) {
        value = L"Default string"; return true;
    }
    if (_wcsicmp(name, L"ProcessorNameString") == 0) { value = L"Generic x64 Processor"; return true; }
    if (_wcsicmp(name, L"VendorIdentifier") == 0) { value = L"GenuineIntel"; return true; }
    if (_wcsicmp(name, L"Identifier") == 0) { value = L"x86 Family 6 Model 0 Stepping 0"; return true; }
    return false;
}

LSTATUS ReturnRegistryString(const std::wstring& value, LPDWORD type, PVOID data, LPDWORD size) {
    if (type) *type = REG_SZ;
    if (!size) return ERROR_INVALID_PARAMETER;
    const DWORD needed = static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t));
    if (!data) {
        *size = needed;
        return ERROR_SUCCESS;
    }
    if (*size < needed) {
        *size = needed;
        return ERROR_MORE_DATA;
    }
    std::memcpy(data, value.c_str(), needed);
    *size = needed;
    return ERROR_SUCCESS;
}

LSTATUS ReturnRegistryDword(DWORD value, LPDWORD type, PVOID data, LPDWORD size) {
    if (type) *type = REG_DWORD;
    if (!size) return ERROR_INVALID_PARAMETER;
    if (!data) {
        *size = sizeof(DWORD);
        return ERROR_SUCCESS;
    }
    if (*size < sizeof(DWORD)) {
        *size = sizeof(DWORD);
        return ERROR_MORE_DATA;
    }
    *reinterpret_cast<DWORD*>(data) = value;
    *size = sizeof(DWORD);
    return ERROR_SUCCESS;
}

bool IsProxyRegistryValue(const wchar_t* name, bool& dwordValue) {
    if (!name) return false;
    if (_wcsicmp(name, L"ProxyEnable") == 0 || _wcsicmp(name, L"AutoDetect") == 0) {
        dwordValue = true;
        return true;
    }
    if (_wcsicmp(name, L"ProxyServer") == 0 || _wcsicmp(name, L"ProxyOverride") == 0 ||
        _wcsicmp(name, L"AutoConfigURL") == 0) {
        dwordValue = false;
        return true;
    }
    return false;
}

std::wstring ProfileComputerName(COMPUTER_NAME_FORMAT format) {
    const std::wstring hostname = Utf8ToWide(ProfileIdentity::Get().hostname);
    wchar_t domainBuffer[512] = {};
    const DWORD domainLength = GetEnvironmentVariableW(L"CAC_DNS_DOMAIN", domainBuffer,
                                                        static_cast<DWORD>(_countof(domainBuffer)));
    const std::wstring domain = domainLength > 0 && domainLength < _countof(domainBuffer)
        ? std::wstring(domainBuffer, domainLength) : std::wstring();
    switch (format) {
        case ComputerNameNetBIOS:
        case ComputerNamePhysicalNetBIOS:
            return hostname.substr(0, hostname.size() > 15 ? 15 : hostname.size());
        case ComputerNameDnsHostname:
        case ComputerNamePhysicalDnsHostname:
            return hostname;
        case ComputerNameDnsDomain:
        case ComputerNamePhysicalDnsDomain:
            return domain;
        case ComputerNameDnsFullyQualified:
        case ComputerNamePhysicalDnsFullyQualified:
            return domain.empty() ? hostname : hostname + L"." + domain;
        default:
            return std::wstring();
    }
}

BOOL WINAPI HookGetComputerNameW(LPWSTR buffer, LPDWORD size) {
    const DWORD capacity = (size && *size) ? *size : 0;
    if (EmptyReadsEnabled()) {
        const BOOL result = CopyEmptyWideToBuffer(buffer, capacity, size);
        AuditEventRateLimited("api.getcomputername", result ? "empty" : "buffer-too-small");
        return result;
    }
    const BOOL result = CopyWideToBuffer(Utf8ToWide(ProfileIdentity::Get().hostname), buffer, capacity, size);
    AuditEventRateLimited("api.getcomputername", result ? "patched" : "buffer-too-small");
    return result;
}

BOOL WINAPI HookGetComputerNameExW(COMPUTER_NAME_FORMAT format, LPWSTR buffer, LPDWORD size) {
    const DWORD capacity = (size && *size) ? *size : 0;
    if (EmptyReadsEnabled()) {
        const BOOL result = CopyEmptyWideToBuffer(buffer, capacity, size);
        AuditEventRateLimited("api.getcomputernameex", result ? "empty" : "buffer-too-small");
        return result;
    }
    const BOOL result = CopyWideToBuffer(ProfileComputerName(format), buffer, capacity, size);
    AuditEventRateLimited("api.getcomputernameex", result ? "patched" : "buffer-too-small");
    return result;
}

BOOL WINAPI HookGetUserNameW(LPWSTR buffer, LPDWORD size) {
    const DWORD capacity = (size && *size) ? *size : 0;
    if (EmptyReadsEnabled()) {
        const BOOL result = CopyEmptyWideToBuffer(buffer, capacity, size);
        AuditEventRateLimited("api.getusername", result ? "empty" : "buffer-too-small");
        return result;
    }
    const BOOL result = CopyWideToBuffer(Utf8ToWide(ProfileIdentity::Get().username), buffer, capacity, size);
    AuditEventRateLimited("api.getusername", result ? "patched" : "buffer-too-small");
    return result;
}

LSTATUS WINAPI HookRegGetValueW(HKEY key, LPCWSTR subKey, LPCWSTR valueName, DWORD flags,
                                LPDWORD type, PVOID data, LPDWORD size) {
    bool proxyDword = false;
    if (NativeCleanNetworkEnabled() && IsProxyRegistryValue(valueName, proxyDword)) {
        AuditEventRateLimited("api.reggetvalue.proxy", "empty");
        return proxyDword ? ReturnRegistryDword(0, type, data, size)
                          : ReturnRegistryString(L"", type, data, size);
    }
    std::wstring spoof;
    if (valueName && GetRegistrySpoofValue(valueName, spoof)) {
        if (EmptyReadsEnabled()) spoof.clear();
        AuditEventRateLimited("api.reggetvalue", EmptyReadsEnabled() ? "empty" : "patched");
        return ReturnRegistryString(spoof, type, data, size);
    }
    return g_origRegGetValue ? g_origRegGetValue(key, subKey, valueName, flags, type, data, size)
                             : ERROR_PROC_NOT_FOUND;
}

LSTATUS WINAPI HookRegQueryValueExW(HKEY key, LPCWSTR valueName, LPDWORD reserved,
                                    LPDWORD type, LPBYTE data, LPDWORD size) {
    bool proxyDword = false;
    if (NativeCleanNetworkEnabled() && IsProxyRegistryValue(valueName, proxyDword)) {
        AuditEventRateLimited("api.regqueryvalue.proxy", "empty");
        return proxyDword ? ReturnRegistryDword(0, type, data, size)
                          : ReturnRegistryString(L"", type, data, size);
    }
    std::wstring spoof;
    if (valueName && GetRegistrySpoofValue(valueName, spoof)) {
        if (EmptyReadsEnabled()) spoof.clear();
        AuditEventRateLimited("api.regqueryvalue", EmptyReadsEnabled() ? "empty" : "patched");
        return ReturnRegistryString(spoof, type, data, size);
    }
    return g_origRegQueryValueEx ? g_origRegQueryValueEx(key, valueName, reserved, type, data, size)
                                 : ERROR_PROC_NOT_FOUND;
}

BOOLEAN WINAPI HookHidD_GetSerialNumberString(HANDLE device, PVOID buffer, ULONG bufferLength) {
    (void)device;
    const std::wstring value = EmptyReadsEnabled() ? std::wstring() : Utf8ToWide(ProfileIdentity::Get().hidSerial);
    const size_t needed = (value.size() + 1) * sizeof(wchar_t);
    if (!buffer || bufferLength < needed) {
        AuditEventRateLimited("api.hid.serial", "buffer-too-small");
        return FALSE;
    }
    std::memcpy(buffer, value.c_str(), needed);
    AuditEventRateLimited("api.hid.serial", EmptyReadsEnabled() ? "empty" : "patched");
    return TRUE;
}

BOOL WINAPI HookSetupDiGetDevicePropertyW(HDEVINFO set, PSP_DEVINFO_DATA info, const DEVPROPKEY* key,
                                          DEVPROPTYPE* type, PBYTE buffer, DWORD bufferSize,
                                          PDWORD required, DWORD flags) {
    if (EmptyReadsEnabled()) {
        (void)set; (void)info; (void)key; (void)buffer; (void)bufferSize; (void)flags;
        if (type) *type = DEVPROP_TYPE_EMPTY;
        if (required) *required = 0;
        SetLastError(ERROR_NOT_FOUND);
        AuditEventRateLimited("api.setupdi.property", "empty");
        return FALSE;
    }
    const BOOL result = g_origSetupDiGetDeviceProperty
        ? g_origSetupDiGetDeviceProperty(set, info, key, type, buffer, bufferSize, required, flags)
        : FALSE;
    if (key) {
        AuditEventRateLimited("api.setupdi.property", result ? "observed" : "error", nullptr,
                              key->pid, true);
    }
    return result;
}

BOOL WINAPI HookSetupDiGetDeviceRegistryPropertyW(HDEVINFO set, PSP_DEVINFO_DATA info, DWORD property,
                                                  PDWORD type, PBYTE buffer, DWORD bufferSize,
                                                  PDWORD required) {
    if (EmptyReadsEnabled()) {
        (void)set; (void)info; (void)property; (void)buffer; (void)bufferSize;
        if (type) *type = 0;
        if (required) *required = 0;
        SetLastError(ERROR_NOT_FOUND);
        AuditEventRateLimited("api.setupdi.registry", "empty");
        return FALSE;
    }
    const BOOL result = g_origSetupDiGetRegistryProperty
        ? g_origSetupDiGetRegistryProperty(set, info, property, type, buffer, bufferSize, required)
        : FALSE;
    AuditEventRateLimited("api.setupdi.registry", result ? "observed" : "error", nullptr, property, true);
    return result;
}

BOOL WINAPI HookSetupDiGetDeviceInstanceIdW(HDEVINFO set, PSP_DEVINFO_DATA info, PWSTR instanceId,
                                            DWORD instanceIdSize, PDWORD required) {
    if (EmptyReadsEnabled()) {
        (void)set; (void)info;
        if (instanceId && instanceIdSize > 0) instanceId[0] = L'\0';
        if (required) *required = 1;
        SetLastError(ERROR_NOT_FOUND);
        AuditEventRateLimited("api.setupdi.instanceid", "empty");
        return FALSE;
    }
    const BOOL result = g_origSetupDiGetInstanceId
        ? g_origSetupDiGetInstanceId(set, info, instanceId, instanceIdSize, required)
        : FALSE;
    AuditEventRateLimited("api.setupdi.instanceid", result ? "observed" : "error");
    return result;
}

ULONG WINAPI HookGetAdaptersAddresses(ULONG family, ULONG flags, PVOID reserved,
                                      PIP_ADAPTER_ADDRESSES addresses, PULONG size) {
    const ULONG result = g_origGetAdaptersAddresses ? g_origGetAdaptersAddresses(family, flags, reserved, addresses, size)
                                                    : ERROR_PROC_NOT_FOUND;
    if (result == NO_ERROR && addresses) {
        const ProfileIdentity& identity = ProfileIdentity::Get();
        if (EmptyReadsEnabled()) {
            for (PIP_ADAPTER_ADDRESSES current = addresses; current; current = current->Next) {
                ClearAdapterMac(current->PhysicalAddress, &current->PhysicalAddressLength);
            }
            AuditEventRateLimited("api.getadaptersaddresses", "empty");
        } else if (identity.hasMac) {
            for (PIP_ADAPTER_ADDRESSES current = addresses; current; current = current->Next) {
                if (current->PhysicalAddressLength > 0) {
                    std::memcpy(current->PhysicalAddress, identity.macBytes, 6);
                    current->PhysicalAddressLength = 6;
                }
            }
            AuditEventRateLimited("api.getadaptersaddresses", "patched");
        }
        if (NativeCleanNetworkEnabled()) FilterAdapterAddresses(addresses);
    }
    return result;
}

DWORD WINAPI HookGetAdaptersInfo(PIP_ADAPTER_INFO info, PULONG size) {
    const DWORD result = g_origGetAdaptersInfo ? g_origGetAdaptersInfo(info, size) : ERROR_PROC_NOT_FOUND;
    if (result == ERROR_SUCCESS && info) {
        const ProfileIdentity& identity = ProfileIdentity::Get();
        if (EmptyReadsEnabled()) {
            for (PIP_ADAPTER_INFO current = info; current; current = current->Next) {
                ClearAdapterMac(current);
            }
            AuditEventRateLimited("api.getadaptersinfo", "empty");
        } else if (identity.hasMac) {
            for (PIP_ADAPTER_INFO current = info; current; current = current->Next) {
                if (current->AddressLength > 0) {
                    std::memcpy(current->Address, identity.macBytes, 6);
                    current->AddressLength = 6;
                }
            }
            AuditEventRateLimited("api.getadaptersinfo", "patched");
        }
        if (NativeCleanNetworkEnabled()) FilterAdapterInfo(info);
    }
    return result;
}

BOOL WINAPI HookGetVolumeInformationW(LPCWSTR root, LPWSTR volumeName, DWORD volumeNameSize,
                                      LPDWORD serial, LPDWORD maxComponentLength, LPDWORD flags,
                                      LPWSTR fileSystemName, DWORD fileSystemNameSize) {
    const BOOL result = g_origGetVolumeInformation
        ? g_origGetVolumeInformation(root, volumeName, volumeNameSize, serial, maxComponentLength, flags, fileSystemName, fileSystemNameSize)
        : FALSE;
    if (result && EmptyReadsEnabled()) {
        if (serial) *serial = 0;
        if (volumeName && volumeNameSize > 0) volumeName[0] = L'\0';
        if (fileSystemName && fileSystemNameSize > 0) fileSystemName[0] = L'\0';
        AuditEventRateLimited("api.getvolumeinformation", "empty");
    } else if (result && serial) {
        *serial = ProfileIdentity::Get().volumeSerial;
        AuditEventRateLimited("api.getvolumeinformation", "patched");
    }
    return result;
}

UINT WINAPI HookGetSystemFirmwareTable(DWORD signature, DWORD tableId, PVOID buffer, DWORD bufferSize) {
    if (EmptyReadsEnabled()) {
        (void)tableId; (void)buffer; (void)bufferSize;
        AuditEventRateLimited("api.firmware", "empty", nullptr, signature, true);
        return 0;
    }
    const UINT result = g_origGetSystemFirmwareTable
        ? g_origGetSystemFirmwareTable(signature, tableId, buffer, bufferSize)
        : 0;
    if (result > 0 && buffer && result <= bufferSize && signature == kRsmbSignature) {
        PatchSmbiosAndAudit(static_cast<BYTE*>(buffer), result);
    }
    return result;
}

NTSTATUS NTAPI HookNtQuerySystemInformation(ULONG infoClass, PVOID info, ULONG length, PULONG returnLength) {
    if (EmptyReadsEnabled() && infoClass == 11) {  // SystemModuleInformation: driver list
        (void)info; (void)length;
        if (returnLength) *returnLength = 0;
        AuditEventRateLimited("api.ntquerysysteminformation.modules", "empty");
        return static_cast<NTSTATUS>(0xC0000003L);
    }
    if (EmptyReadsEnabled() && infoClass == 76) {
        (void)info; (void)length;
        if (returnLength) *returnLength = 0;
        AuditEventRateLimited("api.ntquerysysteminformation", "empty");
        return static_cast<NTSTATUS>(0xC0000002L);
    }
    const NTSTATUS status = g_origNtQuerySystemInformation
        ? g_origNtQuerySystemInformation(infoClass, info, length, returnLength)
        : static_cast<NTSTATUS>(0xC0000002L);
    if (status >= 0 && infoClass == 76 && info && length >= sizeof(FirmwareTableInfo)) {
        FirmwareTableInfo* table = static_cast<FirmwareTableInfo*>(info);
        if (table->Action == 0 && table->ProviderSignature == kRsmbSignature &&
            table->TableBufferLength > 0 && table->TableBufferLength <= length - sizeof(FirmwareTableInfo)) {
            PatchSmbiosAndAudit(table->TableBuffer, table->TableBufferLength);
        }
    }
    return status;
}

void SanitizeStorageOutput(DWORD code, const void* input, DWORD inputSize, void* output,
                           DWORD outputSize, DWORD returned, const char* surface) {
    if (!output || returned == 0) return;
    const DWORD available = (outputSize && outputSize < returned) ? outputSize : returned;
    const bool identifierOnly = code == IOCTL_SMART_RECEIVE_DRIVE_DATA ||
                                code == IOCTL_STORAGE_FIRMWARE_GET_INFO;
    if (EmptyReadsEnabled()) {
        // Keep the descriptor layout intact when the caller asked for the
        // standard device property; only the serial string is emptied.
        if (code == IOCTL_STORAGE_QUERY_PROPERTY && input &&
            inputSize >= sizeof(STORAGE_PROPERTY_QUERY) && available >= sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
            const STORAGE_PROPERTY_QUERY* query = static_cast<const STORAGE_PROPERTY_QUERY*>(input);
            STORAGE_DEVICE_DESCRIPTOR* descriptor = static_cast<STORAGE_DEVICE_DESCRIPTOR*>(output);
            if (query->PropertyId == StorageDeviceProperty &&
                descriptor->SerialNumberOffset > 0 && descriptor->SerialNumberOffset < available) {
                char* serial = static_cast<char*>(output) + descriptor->SerialNumberOffset;
                serial[0] = '\0';
                AuditEventRateLimited(surface, "empty", nullptr, code, true);
                return;
            }
        }
        if (code == IOCTL_STORAGE_QUERY_PROPERTY || identifierOnly) {
            std::memset(output, 0, available);
            AuditEventRateLimited(surface, "empty", nullptr, code, true);
            return;
        }
    }
    if (identifierOnly) {
        // SMART and firmware payloads are pure hardware identifiers. They are
        // cleared in both modes instead of leaking a real disk/firmware serial.
        std::memset(output, 0, available);
        AuditEventRateLimited(surface, "cleared", nullptr, code, true);
        return;
    }
    if (code == IOCTL_STORAGE_QUERY_PROPERTY && input && inputSize >= sizeof(STORAGE_PROPERTY_QUERY) &&
        available >= sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
        const STORAGE_PROPERTY_QUERY* query = static_cast<const STORAGE_PROPERTY_QUERY*>(input);
        STORAGE_DEVICE_DESCRIPTOR* descriptor = static_cast<STORAGE_DEVICE_DESCRIPTOR*>(output);
        if (query->PropertyId == StorageDeviceUniqueIdProperty) {
            std::memset(output, 0, available);
            AuditEventRateLimited(surface, "cleared", nullptr, code, true);
            return;
        }
        if (query->PropertyId == StorageDeviceProperty && query->QueryType == PropertyStandardQuery &&
            descriptor->Size <= available && descriptor->SerialNumberOffset > 0 &&
            descriptor->SerialNumberOffset < available) {
            char* serial = static_cast<char*>(output) + descriptor->SerialNumberOffset;
            const size_t max = available - descriptor->SerialNumberOffset;
            if (ReplaceBufferString(serial, max, ProfileIdentity::Get().diskSerial)) {
                AuditEventRateLimited(surface, "patched", nullptr, code, true);
            }
        }
    }
}

void TrackPendingDeviceIo(LPOVERLAPPED overlapped, DWORD code, const void* input, DWORD inputSize,
                          LPVOID output, DWORD outputSize) {
    if (!overlapped) return;
    PendingDeviceIo pending = {};
    pending.overlapped = overlapped;
    pending.code = code;
    pending.output = output;
    pending.outputSize = outputSize;
    if (input && inputSize > 0 && inputSize <= 4096) {
        const BYTE* begin = static_cast<const BYTE*>(input);
        pending.input.assign(begin, begin + inputSize);
    }

    AcquireSRWLockExclusive(&g_pendingDeviceIoLock);
    for (auto it = g_pendingDeviceIo.begin(); it != g_pendingDeviceIo.end(); ++it) {
        if (it->overlapped == overlapped) {
            *it = pending;
            ReleaseSRWLockExclusive(&g_pendingDeviceIoLock);
            AuditEventRateLimited("api.deviceiocontrol.pending", "replaced", nullptr, code, true);
            return;
        }
    }
    g_pendingDeviceIo.push_back(pending);
    ReleaseSRWLockExclusive(&g_pendingDeviceIoLock);
    AuditEventRateLimited("api.deviceiocontrol.pending", "tracked", nullptr, code, true);
}

bool CompletePendingDeviceIo(LPOVERLAPPED overlapped, DWORD returned, const char* completionSurface) {
    if (!overlapped) return false;
    PendingDeviceIo pending = {};
    bool found = false;
    AcquireSRWLockExclusive(&g_pendingDeviceIoLock);
    for (auto it = g_pendingDeviceIo.begin(); it != g_pendingDeviceIo.end(); ++it) {
        if (it->overlapped == overlapped) {
            pending = *it;
            g_pendingDeviceIo.erase(it);
            found = true;
            break;
        }
    }
    ReleaseSRWLockExclusive(&g_pendingDeviceIoLock);
    if (!found) return false;

    const void* input = pending.input.empty() ? nullptr : pending.input.data();
    SanitizeStorageOutput(pending.code, input, static_cast<DWORD>(pending.input.size()),
                          pending.output, pending.outputSize, returned, completionSurface);
    AuditEventRateLimited("api.deviceiocontrol.pending", "sanitized", completionSurface,
                          pending.code, true);
    return true;
}

void DropPendingDeviceIo(LPOVERLAPPED overlapped, const char* action) {
    if (!overlapped) return;
    DWORD code = 0;
    bool found = false;
    AcquireSRWLockExclusive(&g_pendingDeviceIoLock);
    for (auto it = g_pendingDeviceIo.begin(); it != g_pendingDeviceIo.end(); ++it) {
        if (it->overlapped == overlapped) {
            code = it->code;
            g_pendingDeviceIo.erase(it);
            found = true;
            break;
        }
    }
    ReleaseSRWLockExclusive(&g_pendingDeviceIoLock);
    if (found) AuditEventRateLimited("api.deviceiocontrol.pending", action, nullptr, code, true);
}

BOOL WINAPI HookDeviceIoControl(HANDLE device, DWORD code, LPVOID input, DWORD inputSize,
                                LPVOID output, DWORD outputSize, LPDWORD returned, LPOVERLAPPED overlapped) {
    const BOOL result = g_origDeviceIoControl
        ? g_origDeviceIoControl(device, code, input, inputSize, output, outputSize, returned, overlapped)
        : FALSE;
    const DWORD lastError = result ? ERROR_SUCCESS : GetLastError();
    if (result && output && returned && *returned > 0) {
        SanitizeStorageOutput(code, input, inputSize, output, outputSize, *returned,
                              "api.deviceiocontrol.serial");
        AuditEventRateLimited("api.deviceiocontrol", "observed", nullptr, code, true);
    } else if (!result && overlapped && lastError == ERROR_IO_PENDING) {
        TrackPendingDeviceIo(overlapped, code, input, inputSize, output, outputSize);
    }
    if (!result) SetLastError(lastError);
    return result;
}

BOOL WINAPI HookGetOverlappedResult(HANDLE file, LPOVERLAPPED overlapped, LPDWORD transferred,
                                    BOOL wait) {
    const BOOL result = g_origGetOverlappedResult
        ? g_origGetOverlappedResult(file, overlapped, transferred, wait)
        : FALSE;
    const DWORD lastError = result ? ERROR_SUCCESS : GetLastError();
    if (result) {
        CompletePendingDeviceIo(overlapped, transferred ? *transferred : 0,
                                "GetOverlappedResult");
    } else if (lastError != ERROR_IO_INCOMPLETE) {
        DropPendingDeviceIo(overlapped, "failed");
    }
    if (!result) SetLastError(lastError);
    return result;
}

BOOL WINAPI HookGetOverlappedResultEx(HANDLE file, LPOVERLAPPED overlapped, LPDWORD transferred,
                                      DWORD milliseconds, BOOL alertable) {
    const BOOL result = g_origGetOverlappedResultEx
        ? g_origGetOverlappedResultEx(file, overlapped, transferred, milliseconds, alertable)
        : FALSE;
    const DWORD lastError = result ? ERROR_SUCCESS : GetLastError();
    if (result) {
        CompletePendingDeviceIo(overlapped, transferred ? *transferred : 0,
                                "GetOverlappedResultEx");
    } else if (lastError != ERROR_IO_INCOMPLETE) {
        DropPendingDeviceIo(overlapped, "failed");
    }
    if (!result) SetLastError(lastError);
    return result;
}

BOOL WINAPI HookGetQueuedCompletionStatus(HANDLE port, LPDWORD transferred, PULONG_PTR key,
                                          LPOVERLAPPED* overlapped, DWORD milliseconds) {
    const BOOL result = g_origGetQueuedCompletionStatus
        ? g_origGetQueuedCompletionStatus(port, transferred, key, overlapped, milliseconds)
        : FALSE;
    const DWORD lastError = result ? ERROR_SUCCESS : GetLastError();
    if (result && overlapped && *overlapped) {
        CompletePendingDeviceIo(*overlapped, transferred ? *transferred : 0,
                                "GetQueuedCompletionStatus");
    } else if (!result && overlapped && *overlapped && lastError != ERROR_IO_INCOMPLETE) {
        DropPendingDeviceIo(*overlapped, "failed");
    }
    if (!result) SetLastError(lastError);
    return result;
}

BOOL WINAPI HookGetQueuedCompletionStatusEx(HANDLE port, LPOVERLAPPED_ENTRY entries, ULONG count,
                                            PULONG removed, DWORD milliseconds, BOOL alertable) {
    const BOOL result = g_origGetQueuedCompletionStatusEx
        ? g_origGetQueuedCompletionStatusEx(port, entries, count, removed, milliseconds, alertable)
        : FALSE;
    const DWORD lastError = result ? ERROR_SUCCESS : GetLastError();
    if (result && entries && removed) {
        for (ULONG index = 0; index < *removed; ++index) {
            CompletePendingDeviceIo(entries[index].lpOverlapped,
                                    entries[index].dwNumberOfBytesTransferred,
                                    "GetQueuedCompletionStatusEx");
        }
    }
    if (!result) SetLastError(lastError);
    return result;
}

BOOL WINAPI HookGetVolumeInformationByHandleW(HANDLE handle, LPWSTR volumeName, DWORD volumeNameSize,
                                              LPDWORD serial, LPDWORD maxComponentLength, LPDWORD flags,
                                              LPWSTR fileSystemName, DWORD fileSystemNameSize) {
    const BOOL result = g_origGetVolumeInformationByHandle
        ? g_origGetVolumeInformationByHandle(handle, volumeName, volumeNameSize, serial,
                                             maxComponentLength, flags, fileSystemName, fileSystemNameSize)
        : FALSE;
    if (result && EmptyReadsEnabled()) {
        if (serial) *serial = 0;
        if (volumeName && volumeNameSize > 0) volumeName[0] = L'\0';
        if (fileSystemName && fileSystemNameSize > 0) fileSystemName[0] = L'\0';
        AuditEventRateLimited("api.getvolumeinformationbyhandle", "empty");
    } else if (result && serial) {
        *serial = ProfileIdentity::Get().volumeSerial;
        AuditEventRateLimited("api.getvolumeinformationbyhandle", "patched");
    }
    return result;
}

BOOL WINAPI HookGetFileInformationByHandle(HANDLE handle, LPBY_HANDLE_FILE_INFORMATION information) {
    const BOOL result = g_origGetFileInformationByHandle
        ? g_origGetFileInformationByHandle(handle, information)
        : FALSE;
    if (result && information) {
        information->dwVolumeSerialNumber = EmptyReadsEnabled()
            ? 0
            : ProfileIdentity::Get().volumeSerial;
        AuditEventRateLimited("api.getfileinformationbyhandle",
                              EmptyReadsEnabled() ? "empty" : "patched");
    }
    return result;
}

struct FsVolumeInformation {
    LARGE_INTEGER CreationTime;
    ULONG SerialNumber;
    ULONG LabelLength;
    BOOLEAN SupportsObjects;
    WCHAR Label[1];
};

NTSTATUS NTAPI HookNtQueryVolumeInformationFile(HANDLE handle, PIO_STATUS_BLOCK ioStatus,
                                                PVOID information, ULONG length, ULONG informationClass) {
    const NTSTATUS status = g_origNtQueryVolumeInformationFile
        ? g_origNtQueryVolumeInformationFile(handle, ioStatus, information, length, informationClass)
        : static_cast<NTSTATUS>(0xC0000002L);
    // FileFsVolumeInformation == 1
    if ((status >= 0 || status == static_cast<NTSTATUS>(0x80000005L)) &&
        informationClass == 1 && information && length >= sizeof(FsVolumeInformation)) {
        FsVolumeInformation* volume = static_cast<FsVolumeInformation*>(information);
        if (EmptyReadsEnabled()) {
            volume->SerialNumber = 0;
            volume->LabelLength = 0;
            if (volume->Label[0]) volume->Label[0] = L'\0';
            AuditEventRateLimited("api.ntqueryvolumeinformation", "empty");
        } else {
            volume->SerialNumber = ProfileIdentity::Get().volumeSerial;
            AuditEventRateLimited("api.ntqueryvolumeinformation", "patched");
        }
    }
    return status;
}

NTSTATUS NTAPI HookNtDeviceIoControlFile(HANDLE file, HANDLE event, PIO_APC_ROUTINE apc, PVOID apcContext,
                                         PIO_STATUS_BLOCK ioStatus, ULONG code, PVOID input, ULONG inputLength,
                                         PVOID output, ULONG outputLength) {
    const NTSTATUS status = g_origNtDeviceIoControlFile
        ? g_origNtDeviceIoControlFile(file, event, apc, apcContext, ioStatus, code, input, inputLength,
                                      output, outputLength)
        : static_cast<NTSTATUS>(0xC0000002L);
    if (status >= 0 && ioStatus && output && ioStatus->Information > 0) {
        SanitizeStorageOutput(code, input, inputLength, output, outputLength,
                              static_cast<DWORD>(ioStatus->Information), "api.ntdeviceiocontrol.serial");
        AuditEventRateLimited("api.ntdeviceiocontrol", "observed", nullptr, code, true);
    } else if (status == static_cast<NTSTATUS>(0x00000103L)) { // STATUS_PENDING
        // NtDeviceIoControlFile can complete through an APC, event, or IOCP after
        // this function returns. Without a completion-context hook, clearing the
        // buffer here would be overwritten by the kernel. Keep explicit evidence
        // instead of reporting this path as covered. This path is intentionally
        // audit-only; smoke coverage asserts the pending audit event, not output
        // sanitization after an asynchronous completion.
        AuditEventRateLimited("api.ntdeviceiocontrol.pending", "unhandled", nullptr, code, true);
    }
    return status;
}

void ApplyPhysicalAddress(BYTE* address, ULONG* length, ULONG capacity) {
    if (!address || !length) return;
    const ProfileIdentity& identity = ProfileIdentity::Get();
    if (EmptyReadsEnabled()) {
        if (capacity) std::memset(address, 0, capacity);
        *length = 0;
        return;
    }
    if (identity.hasMac && capacity >= 6) {
        std::memcpy(address, identity.macBytes, 6);
        *length = 6;
    }
}

NETIO_STATUS WINAPI HookGetIfTable2(PMIB_IF_TABLE2* table) {
    const NETIO_STATUS status = g_origGetIfTable2 ? g_origGetIfTable2(table) : ERROR_NOT_SUPPORTED;
    if (status == NO_ERROR && table && *table) {
        if (NativeCleanNetworkEnabled()) FilterIfTable2(*table);
        for (ULONG i = 0; i < (*table)->NumEntries; ++i) {
            MIB_IF_ROW2& row = (*table)->Table[i];
            ApplyPhysicalAddress(row.PhysicalAddress, &row.PhysicalAddressLength, IF_MAX_PHYS_ADDRESS_LENGTH);
            // MIB_IF_ROW2 exposes one length for both current and permanent
            // address buffers; keep that shared length synchronized.
            ApplyPhysicalAddress(row.PermanentPhysicalAddress, &row.PhysicalAddressLength,
                                 IF_MAX_PHYS_ADDRESS_LENGTH);
        }
        AuditEventRateLimited("api.getiftable2", EmptyReadsEnabled() ? "empty" : "patched");
    }
    return status;
}

NETIO_STATUS WINAPI HookGetIfEntry2(PMIB_IF_ROW2 row) {
    const NETIO_STATUS status = g_origGetIfEntry2 ? g_origGetIfEntry2(row) : ERROR_NOT_SUPPORTED;
    if (status == NO_ERROR && row) {
        if (NativeCleanNetworkEnabled() && (EmptyReadsEnabled() || IsVirtualIfRow(*row))) {
            AuditEventRateLimited("api.getifentry2", "clean-none");
            return ERROR_NOT_FOUND;
        }
        ApplyPhysicalAddress(row->PhysicalAddress, &row->PhysicalAddressLength, IF_MAX_PHYS_ADDRESS_LENGTH);
        ApplyPhysicalAddress(row->PermanentPhysicalAddress, &row->PhysicalAddressLength,
                             IF_MAX_PHYS_ADDRESS_LENGTH);
        AuditEventRateLimited("api.getifentry2", EmptyReadsEnabled() ? "empty" : "patched");
    }
    return status;
}

DWORD WINAPI HookGetIfTable(PMIB_IFTABLE table, PULONG size, BOOL order) {
    const DWORD status = g_origGetIfTable ? g_origGetIfTable(table, size, order) : ERROR_NOT_SUPPORTED;
    if (status == NO_ERROR && table) {
        if (NativeCleanNetworkEnabled()) {
            if (EmptyReadsEnabled()) {
                table->dwNumEntries = 0;
                AuditEventRateLimited("api.getiftable", "clean-none");
            } else {
                DWORD kept = 0;
                for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                    const MIB_IFROW& candidate = table->table[i];
                    if (NativeIsVirtualAdapterName(candidate.wszName) ||
                        NativeIsVirtualAdapterName(AnsiToWide(reinterpret_cast<const char*>(candidate.bDescr)).c_str()) ||
                        candidate.dwType == IF_TYPE_TUNNEL || candidate.dwType == IF_TYPE_PPP) {
                        continue;
                    }
                    if (kept != i) table->table[kept] = candidate;
                    ++kept;
                }
                table->dwNumEntries = kept;
                AuditEventRateLimited("api.getiftable", "cleaned");
            }
        }
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            MIB_IFROW& row = table->table[i];
            ApplyPhysicalAddress(row.bPhysAddr, &row.dwPhysAddrLen, sizeof(row.bPhysAddr));
        }
        AuditEventRateLimited("api.getiftable", EmptyReadsEnabled() ? "empty" : "patched");
    }
    return status;
}

LSTATUS WINAPI HookRegEnumValueW(HKEY key, DWORD index, LPWSTR valueName, LPDWORD valueNameLength,
                                 LPDWORD reserved, LPDWORD type, LPBYTE data, LPDWORD dataSize) {
    const LSTATUS status = g_origRegEnumValue
        ? g_origRegEnumValue(key, index, valueName, valueNameLength, reserved, type, data, dataSize)
        : ERROR_PROC_NOT_FOUND;
    if (status == ERROR_SUCCESS && valueName && type && data && dataSize) {
        bool proxyDword = false;
        if (NativeCleanNetworkEnabled() && IsProxyRegistryValue(valueName, proxyDword)) {
            if (proxyDword) {
                if (*dataSize >= sizeof(DWORD)) {
                    *reinterpret_cast<DWORD*>(data) = 0;
                    *dataSize = sizeof(DWORD);
                    *type = REG_DWORD;
                    AuditEventRateLimited("api.regenumvalue.proxy", "empty");
                }
            } else if (*dataSize >= sizeof(wchar_t)) {
                *reinterpret_cast<wchar_t*>(data) = L'\0';
                *dataSize = sizeof(wchar_t);
                *type = REG_SZ;
                AuditEventRateLimited("api.regenumvalue.proxy", "empty");
            }
            return status;
        }
        std::wstring spoof;
        if (GetRegistrySpoofValue(valueName, spoof)) {
            if (EmptyReadsEnabled()) spoof.clear();
            const DWORD needed = static_cast<DWORD>((spoof.size() + 1) * sizeof(wchar_t));
            if (*dataSize >= needed) {
                std::memcpy(data, spoof.c_str(), needed);
                *dataSize = needed;
                *type = REG_SZ;
                AuditEventRateLimited("api.regenumvalue", EmptyReadsEnabled() ? "empty" : "patched");
            }
        }
    }
    return status;
}

BOOL WINAPI HookEnumDeviceDrivers(LPVOID* imageBase, DWORD size, LPDWORD needed) {
    if (EmptyReadsEnabled()) {
        if (imageBase && size) std::memset(imageBase, 0, size);
        if (needed) *needed = 0;
        AuditEventRateLimited("api.enumdevicedrivers", "empty");
        return TRUE;
    }
    return g_origEnumDeviceDrivers ? g_origEnumDeviceDrivers(imageBase, size, needed) : FALSE;
}

bool IsBlockedDeviceClass(const GUID* classGuid) {
    if (!classGuid) return false;
    return IsEqualGUID(*classGuid, GUID_DEVCLASS_DISKDRIVE) ||
           IsEqualGUID(*classGuid, GUID_DEVCLASS_DISPLAY) ||
           IsEqualGUID(*classGuid, GUID_DEVCLASS_NET) ||
           IsEqualGUID(*classGuid, GUID_DEVCLASS_SYSTEM) ||
           IsEqualGUID(*classGuid, GUID_DEVCLASS_VOLUME) ||
           IsEqualGUID(*classGuid, GUID_DEVCLASS_VOLUMESNAPSHOT);
}

HDEVINFO WINAPI HookSetupDiGetClassDevsW(const GUID* classGuid, PCWSTR enumerator, HWND parent, DWORD flags) {
    if (EmptyReadsEnabled() && IsBlockedDeviceClass(classGuid)) {
        SetLastError(ERROR_NO_MORE_ITEMS);
        AuditEventRateLimited("api.setupdi.classdevs", "empty");
        return INVALID_HANDLE_VALUE;
    }
    return g_origSetupDiGetClassDevs ? g_origSetupDiGetClassDevs(classGuid, enumerator, parent, flags)
                                     : INVALID_HANDLE_VALUE;
}

bool IsRawHardwarePath(const wchar_t* path) {
    if (!path) return false;
    static const wchar_t* prefixes[] = {
        L"\\\\.\\PhysicalDrive",
        L"\\\\.\\CdRom",
        L"\\\\.\\Volume",
        L"\\\\.\\SCSI",
        L"\\\\.\\GLOBALROOT\\Device\\Harddisk",
        L"\\\\?\\GLOBALROOT\\Device\\Harddisk",
        L"\\\\.\\MountPointManager",
        L"\\Device\\Harddisk",
        L"\\Device\\CdRom",
        L"\\Device\\Scsi",
        L"\\Device\\MountPointManager",
        L"\\??\\PhysicalDrive",
        L"\\??\\CdRom",
        L"\\??\\Volume",
        L"\\??\\GLOBALROOT\\Device\\Harddisk",
    };
    for (const wchar_t* prefix : prefixes) {
        const size_t length = wcslen(prefix);
        if (_wcsnicmp(path, prefix, length) == 0) return true;
    }
    return false;
}

HANDLE WINAPI HookCreateFileW(LPCWSTR fileName, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES security,
                              DWORD creation, DWORD flags, HANDLE templateFile) {
    if (EmptyReadsEnabled() && IsRawHardwarePath(fileName)) {
        AuditEventRateLimited("api.createfile.rawdevice", "denied");
        SetLastError(ERROR_ACCESS_DENIED);
        return INVALID_HANDLE_VALUE;
    }
    return g_origCreateFile
        ? g_origCreateFile(fileName, access, share, security, creation, flags, templateFile)
        : INVALID_HANDLE_VALUE;
}

HANDLE WINAPI HookCreateFileA(LPCSTR fileName, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES security,
                              DWORD creation, DWORD flags, HANDLE templateFile) {
    const std::wstring wideName = AnsiToWide(fileName);
    if (IsRawHardwarePath(wideName.c_str())) {
        if (EmptyReadsEnabled()) {
            AuditEventRateLimited("api.createfilea.rawdevice", "denied");
            SetLastError(ERROR_ACCESS_DENIED);
            return INVALID_HANDLE_VALUE;
        }
        AuditEventRateLimited("api.createfilea.rawdevice", "observed");
    }
    return g_origCreateFileA
        ? g_origCreateFileA(fileName, access, share, security, creation, flags, templateFile)
        : INVALID_HANDLE_VALUE;
}

HANDLE WINAPI HookCreateFile2(LPCWSTR fileName, DWORD access, DWORD share, DWORD creation,
                              LPCREATEFILE2_EXTENDED_PARAMETERS extended) {
    if (IsRawHardwarePath(fileName)) {
        if (EmptyReadsEnabled()) {
            AuditEventRateLimited("api.createfile2.rawdevice", "denied");
            SetLastError(ERROR_ACCESS_DENIED);
            return INVALID_HANDLE_VALUE;
        }
        AuditEventRateLimited("api.createfile2.rawdevice", "observed");
    }
    return g_origCreateFile2
        ? g_origCreateFile2(fileName, access, share, creation, extended)
        : INVALID_HANDLE_VALUE;
}

std::wstring ObjectAttributesPath(POBJECT_ATTRIBUTES attributes) {
    if (!attributes || !attributes->ObjectName || !attributes->ObjectName->Buffer ||
        attributes->ObjectName->Length == 0) {
        return std::wstring();
    }
    return std::wstring(attributes->ObjectName->Buffer,
                        attributes->ObjectName->Length / sizeof(wchar_t));
}

NTSTATUS NTAPI HookNtCreateFile(PHANDLE fileHandle, ACCESS_MASK access, POBJECT_ATTRIBUTES attributes,
                                PIO_STATUS_BLOCK ioStatus, PLARGE_INTEGER allocationSize,
                                ULONG fileAttributes, ULONG shareAccess, ULONG disposition,
                                ULONG createOptions, PVOID eaBuffer, ULONG eaLength) {
    const std::wstring path = ObjectAttributesPath(attributes);
    if (IsRawHardwarePath(path.c_str())) {
        if (EmptyReadsEnabled()) {
            SetLastError(ERROR_ACCESS_DENIED);
            AuditEventRateLimited("api.ntcreatefile.rawdevice", "denied");
            return static_cast<NTSTATUS>(0xC0000022L); // STATUS_ACCESS_DENIED
        }
        AuditEventRateLimited("api.ntcreatefile.rawdevice", "observed");
    }
    return g_origNtCreateFile
        ? g_origNtCreateFile(fileHandle, access, attributes, ioStatus, allocationSize,
                             fileAttributes, shareAccess, disposition, createOptions,
                             eaBuffer, eaLength)
        : static_cast<NTSTATUS>(0xC0000022L);
}

bool PatchIatInModule(HMODULE module, const char* dllName, const char* functionName,
                      void* replacement, void** original, int* patchedCount) {
    if (!module || !replacement) return false;
    BYTE* base = reinterpret_cast<BYTE*>(module);
    PIMAGE_DOS_HEADER dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    PIMAGE_NT_HEADERS nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    const IMAGE_DATA_DIRECTORY& directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (directory.VirtualAddress == 0 || directory.Size == 0) return false;

    bool touched = false;
    PIMAGE_IMPORT_DESCRIPTOR descriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(base + directory.VirtualAddress);
    for (; descriptor->Name; ++descriptor) {
        const char* importedDll = reinterpret_cast<const char*>(base + descriptor->Name);
        if (_stricmp(importedDll, dllName) != 0) continue;
        PIMAGE_THUNK_DATA thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(base + descriptor->FirstThunk);
        PIMAGE_THUNK_DATA names = descriptor->OriginalFirstThunk
            ? reinterpret_cast<PIMAGE_THUNK_DATA>(base + descriptor->OriginalFirstThunk) : nullptr;
        for (; thunk->u1.Function; ++thunk) {
            bool match = false;
            if (names) {
                if (!(names->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                    PIMAGE_IMPORT_BY_NAME byName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(base + names->u1.AddressOfData);
                    if (std::strcmp(reinterpret_cast<const char*>(byName->Name), functionName) == 0) match = true;
                }
                ++names;
            }
            if (!match) continue;
            void* current = reinterpret_cast<void*>(static_cast<uintptr_t>(thunk->u1.Function));
            if (current == replacement) continue;
            DWORD oldProtect = 0;
            if (!VirtualProtect(&thunk->u1.Function, sizeof(void*), PAGE_READWRITE, &oldProtect)) continue;
            if (original && *original == nullptr) *original = current;
            thunk->u1.Function = reinterpret_cast<ULONG_PTR>(replacement);
            DWORD ignored = 0;
            VirtualProtect(&thunk->u1.Function, sizeof(void*), oldProtect, &ignored);
            ++(*patchedCount);
            touched = true;
        }
    }
    return touched;
}

int PatchAllModules(const char* dllName, const char* functionName, void* replacement, void** original) {
    int count = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
    if (snapshot == INVALID_HANDLE_VALUE) return 0;
    MODULEENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    if (Module32FirstW(snapshot, &entry)) {
        do {
            PatchIatInModule(entry.hModule, dllName, functionName, replacement, original, &count);
        } while (Module32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return count;
}

struct DelayLoadDescriptor {
    DWORD attributes;
    DWORD dllName;
    DWORD moduleHandle;
    DWORD iat;
    DWORD intTable;
    DWORD boundIat;
    DWORD unloadIat;
    DWORD timestamp;
};

bool PatchDelayIatInModule(HMODULE module, const char* dllName, const char* functionName,
                           void* replacement, void** original, int* patchedCount) {
    if (!module || !replacement) return false;
    BYTE* base = reinterpret_cast<BYTE*>(module);
    PIMAGE_DOS_HEADER dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    PIMAGE_NT_HEADERS nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    const IMAGE_DATA_DIRECTORY& directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    if (directory.VirtualAddress == 0 || directory.Size == 0) return false;

    const uintptr_t imageBase = nt->OptionalHeader.ImageBase;
    auto fix = [imageBase](DWORD value, DWORD attributes) -> DWORD {
        if (value == 0) return 0;
        if (attributes & 1) return value;
        return static_cast<DWORD>(static_cast<uintptr_t>(value) - imageBase);
    };

    bool touched = false;
    DelayLoadDescriptor* descriptor =
        reinterpret_cast<DelayLoadDescriptor*>(base + directory.VirtualAddress);
    for (; descriptor->dllName; ++descriptor) {
        const DWORD nameRva = fix(descriptor->dllName, descriptor->attributes);
        const char* importedDll = reinterpret_cast<const char*>(base + nameRva);
        if (_stricmp(importedDll, dllName) != 0) continue;

        const DWORD intRva = fix(descriptor->intTable, descriptor->attributes);
        const DWORD iatRva = fix(descriptor->iat, descriptor->attributes);
        if (!intRva || !iatRva) continue;
        PIMAGE_THUNK_DATA names = reinterpret_cast<PIMAGE_THUNK_DATA>(base + intRva);
        PIMAGE_THUNK_DATA thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(base + iatRva);
        HMODULE targetModule = LoadLibraryA(dllName);
        if (!targetModule) continue;
        for (; names->u1.AddressOfData && thunk->u1.Function; ++names, ++thunk) {
            if (names->u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;
            PIMAGE_IMPORT_BY_NAME byName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
                base + static_cast<DWORD>(names->u1.AddressOfData));
            if (std::strcmp(reinterpret_cast<const char*>(byName->Name), functionName) != 0) continue;
            void* real = reinterpret_cast<void*>(GetProcAddress(targetModule, functionName));
            if (!real) break;
            void* current = reinterpret_cast<void*>(static_cast<uintptr_t>(thunk->u1.Function));
            if (current == replacement) continue;
            DWORD oldProtect = 0;
            if (!VirtualProtect(&thunk->u1.Function, sizeof(void*), PAGE_READWRITE, &oldProtect)) continue;
            if (original && *original == nullptr) *original = real;
            thunk->u1.Function = reinterpret_cast<ULONG_PTR>(replacement);
            DWORD ignored = 0;
            VirtualProtect(&thunk->u1.Function, sizeof(void*), oldProtect, &ignored);
            ++(*patchedCount);
            touched = true;
        }
    }
    return touched;
}

int PatchDelayAllModules(const char* dllName, const char* functionName, void* replacement, void** original) {
    int count = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
    if (snapshot == INVALID_HANDLE_VALUE) return 0;
    MODULEENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    if (Module32FirstW(snapshot, &entry)) {
        do {
            PatchDelayIatInModule(entry.hModule, dllName, functionName, replacement, original, &count);
        } while (Module32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return count;
}

void* ResolveExport(const char* dllName, const char* functionName) {
    HMODULE module = GetModuleHandleA(dllName);
    if (!module) module = LoadLibraryA(dllName);
    if (!module) return nullptr;
    BYTE* target = reinterpret_cast<BYTE*>(GetProcAddress(module, functionName));
    // Kernel32/advapi32/psapi frequently expose forwarder stubs. Follow the
    // x64 RIP-relative indirection before installing an inline detour; copying
    // the six-byte forwarder into a trampoline would make its RIP displacement
    // point at the wrong address and crash on the first original call.
    for (int depth = 0; target && depth < 4; ++depth) {
        if (target[0] == 0xFF && target[1] == 0x25) {
            const int32_t displacement = *reinterpret_cast<const int32_t*>(target + 2);
            void** slot = reinterpret_cast<void**>(target + 6 + displacement);
            target = slot ? reinterpret_cast<BYTE*>(*slot) : nullptr;
            continue;
        }
        if (target[0] == 0x48 && target[1] == 0xFF && target[2] == 0x25) {
            const int32_t displacement = *reinterpret_cast<const int32_t*>(target + 3);
            void** slot = reinterpret_cast<void**>(target + 7 + displacement);
            target = slot ? reinterpret_cast<BYTE*>(*slot) : nullptr;
            continue;
        }
        break;
    }
    return target;
}

void InstallOne(const char* dllName, const char* functionName, void* detour, void** original,
                bool allowInline = true) {
    const int iatCount = PatchAllModules(dllName, functionName, detour, original);
    const int delayCount = PatchDelayAllModules(dllName, functionName, detour, original);
    if (iatCount + delayCount > 0) {
        char detail[256] = {};
        std::snprintf(detail, sizeof(detail), "%s!%s iat=%d delay=%d", dllName, functionName, iatCount, delayCount);
        AuditEvent("api.install", "iat+delay", detail,
                   static_cast<unsigned long long>(iatCount + delayCount), true);
        return;
    }

    if (!allowInline) {
        char detail[256] = {};
        std::snprintf(detail, sizeof(detail), "%s!%s", dllName, functionName);
        AuditEvent("api.install", "not-imported", detail);
        ++g_hookInstallFailures;
        return;
    }

    void* target = ResolveExport(dllName, functionName);
    if (!target) {
        char detail[256] = {};
        std::snprintf(detail, sizeof(detail), "%s!%s", dllName, functionName);
        AuditEvent("api.install", "missing", detail);
        ++g_hookInstallFailures;
        return;
    }
    if (void* existing = HookEngine::FindTrampoline(target)) {
        if (original) *original = existing;
        char detail[256] = {};
        std::snprintf(detail, sizeof(detail), "%s!%s -> existing target", dllName, functionName);
        AuditEvent("api.install", "alias", detail);
        return;
    }
    void* trampoline = nullptr;
    std::string error;
    if (HookEngine::Install(target, detour, &trampoline, &error)) {
        // Multiple exported aliases can share the same kernelbase target. If
        // an earlier IAT patch populated the original pointer with that target,
        // replace it with the trampoline before the inline patch takes effect;
        // otherwise the detour would call its own patched entry recursively.
        if (original) *original = trampoline;
        AuditEvent("api.install", "inline", functionName);
    } else {
        char detail[256] = {};
        std::snprintf(detail, sizeof(detail), "%s!%s: %s", dllName, functionName, error.c_str());
        AuditEvent("api.install", "refused", detail);
        ++g_hookInstallFailures;
    }
}

// Some callers resolve ntdll exports with GetProcAddress, so an IAT-only patch
// is not sufficient. Install the inline detour first (capturing the trampoline
// as the original) and then patch every import table to point at the detour.
void InstallInlineThenIat(const char* dllName, const char* functionName, void* detour,
                          void** original) {
    void* target = ResolveExport(dllName, functionName);
    bool inlineInstalled = false;
    if (target) {
        if (void* existing = HookEngine::FindTrampoline(target)) {
            if (original) *original = existing;
            char detail[256] = {};
            std::snprintf(detail, sizeof(detail), "%s!%s -> existing target", dllName, functionName);
            AuditEvent("api.install", "alias", detail);
            inlineInstalled = true;
        } else {
            void* trampoline = nullptr;
            std::string error;
            if (HookEngine::Install(target, detour, &trampoline, &error)) {
                if (original) *original = trampoline;
                char detail[256] = {};
                std::snprintf(detail, sizeof(detail), "%s!%s", dllName, functionName);
                AuditEvent("api.install", "inline-primary", detail);
                inlineInstalled = true;
            } else {
                char detail[256] = {};
                std::snprintf(detail, sizeof(detail), "%s!%s: %s", dllName, functionName, error.c_str());
                AuditEvent("api.install", "inline-refused", detail);
                ++g_hookInstallFailures;
            }
        }
    } else {
        char detail[256] = {};
        std::snprintf(detail, sizeof(detail), "%s!%s", dllName, functionName);
        AuditEvent("api.install", "inline-missing", detail);
        ++g_hookInstallFailures;
    }

    const int iatCount = PatchAllModules(dllName, functionName, detour, original);
    const int delayCount = PatchDelayAllModules(dllName, functionName, detour, original);
    if (iatCount + delayCount > 0) {
        char detail[256] = {};
        std::snprintf(detail, sizeof(detail), "%s!%s iat=%d delay=%d",
                      dllName, functionName, iatCount, delayCount);
        AuditEvent("api.install", "iat+delay", detail,
                   static_cast<unsigned long long>(iatCount + delayCount), true);
    }
}

bool ReadManifestLines(const std::wstring& path, std::vector<std::string>& lines) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER size = {};
    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 || size.QuadPart > 4 * 1024 * 1024) {
        CloseHandle(file);
        return false;
    }
    std::string data;
    data.resize(static_cast<size_t>(size.QuadPart));
    DWORD read = 0;
    const bool ok = ReadFile(file, data.data(), static_cast<DWORD>(data.size()), &read, nullptr) != FALSE;
    CloseHandle(file);
    if (!ok) return false;
    if (data.size() >= 3 && static_cast<unsigned char>(data[0]) == 0xEF &&
        static_cast<unsigned char>(data[1]) == 0xBB && static_cast<unsigned char>(data[2]) == 0xBF) {
        data.erase(0, 3);
    }
    size_t start = 0;
    while (start <= data.size()) {
        size_t end = data.find('\n', start);
        if (end == std::string::npos) end = data.size();
        std::string line = data.substr(start, end - start);
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ' || line.back() == '\t')) line.pop_back();
        while (!line.empty() && (line.front() == ' ' || line.front() == '\t')) line.erase(line.begin());
        if (!line.empty() && line[0] != '#') lines.push_back(line);
        if (end == data.size()) break;
        start = end + 1;
    }
    return true;
}

std::wstring Utf8ToWide(const std::string& value) {
    if (value.empty()) return std::wstring();
    const int length = MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0);
    if (length <= 0) return std::wstring();
    std::wstring result(length, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), result.data(), length);
    return result;
}

bool ComputeFileSha256(const std::wstring& path, std::string& hex) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;

    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    bool ok = false;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0 &&
        BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) >= 0) {
        std::vector<BYTE> buffer(64 * 1024);
        DWORD read = 0;
        while (ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr) && read > 0) {
            if (BCryptHashData(hash, buffer.data(), read, 0) < 0) break;
        }
        BYTE digest[32] = {};
        if (BCryptFinishHash(hash, digest, sizeof(digest), 0) >= 0) {
            char text[65] = {};
            for (int i = 0; i < 32; ++i) std::snprintf(text + i * 2, 3, "%02X", digest[i]);
            hex.assign(text, 64);
            ok = true;
        }
    }
    if (hash) BCryptDestroyHash(hash);
    if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    CloseHandle(file);
    return ok;
}

HMODULE FindModuleByPath(const std::wstring& path) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
    if (snapshot == INVALID_HANDLE_VALUE) return nullptr;
    MODULEENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    HMODULE result = nullptr;
    if (Module32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExePath, path.c_str()) == 0) {
                result = entry.hModule;
                break;
            }
        } while (Module32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return result;
}

std::vector<BYTE> ParseHexBytes(const std::string& hex) {
    std::vector<BYTE> bytes;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        char pair[3] = { hex[i], hex[i + 1], 0 };
        char* end = nullptr;
        const unsigned long value = strtoul(pair, &end, 16);
        if (end == pair) return {};
        bytes.push_back(static_cast<BYTE>(value));
    }
    return bytes;
}

enum class CpuidReadMode {
    Neutral,
    Empty,
    Passthrough,
};

CpuidReadMode GetCpuidReadMode() {
    static int cached = -1;
    if (cached < 0) {
        char value[32] = {};
        const DWORD size = GetEnvironmentVariableA("CAC_NATIVE_CPUID_MODE", value,
                                                   static_cast<DWORD>(sizeof(value)));
        if (size > 0 && size < sizeof(value) && _stricmp(value, "empty") == 0) {
            cached = 1;
        } else if (size > 0 && size < sizeof(value) && _stricmp(value, "passthrough") == 0) {
            cached = 2;
        } else if (EmptyReadsEnabled()) {
            cached = 1;
        } else {
            cached = 0;
        }
    }
    return cached == 1 ? CpuidReadMode::Empty
         : cached == 2 ? CpuidReadMode::Passthrough
                       : CpuidReadMode::Neutral;
}

void CpuIdFilter(int regs[4], int leaf) {
    static int testMode = -1;
    if (testMode < 0) {
        char value[8] = {};
        testMode = GetEnvironmentVariableA("CAC_NATIVE_CPUID_TEST", value, sizeof(value)) > 0 && value[0] == '1' ? 1 : 0;
    }
    if (testMode == 1 && leaf == 0x13371337) {
        regs[0] = 0xCAFE;
        regs[1] = 0xBEEF;
        regs[2] = 0x1234;
        regs[3] = 0x5678;
        return;
    }
    const CpuidReadMode mode = GetCpuidReadMode();
    if (mode == CpuidReadMode::Empty) {
        regs[0] = regs[1] = regs[2] = regs[3] = 0;
        return;
    }
    if (mode == CpuidReadMode::Passthrough) return;
    if (leaf == 1) regs[2] &= ~(1 << 31);          // hypervisor-present bit
    if (leaf >= 0x40000000) regs[0] = regs[1] = regs[2] = regs[3] = 0;
}

void __cdecl CpuIdDetour(int out[4], int leaf) {
    int regs[4] = {};
    if (GetCpuidReadMode() != CpuidReadMode::Empty) {
        __cpuidex(regs, leaf, 0);
    }
    CpuIdFilter(regs, leaf);
    std::memcpy(out, regs, sizeof(regs));
    char detail[64] = {};
    std::snprintf(detail, sizeof(detail), "leaf=0x%x", static_cast<unsigned int>(leaf));
    AuditEventRateLimited("cpu.cpuid", "filtered", detail);
}

void __cdecl CpuIdExDetour(int out[4], int leaf, int subleaf) {
    int regs[4] = {};
    if (GetCpuidReadMode() != CpuidReadMode::Empty) {
        __cpuidex(regs, leaf, subleaf);
    }
    CpuIdFilter(regs, leaf);
    std::memcpy(out, regs, sizeof(regs));
    char detail[96] = {};
    std::snprintf(detail, sizeof(detail), "leaf=0x%x subleaf=0x%x",
                  static_cast<unsigned int>(leaf), static_cast<unsigned int>(subleaf));
    AuditEventRateLimited("cpu.cpuid", "filtered", detail);
}

unsigned __int64 __cdecl XgetbvDetour(unsigned int index) {
    if (GetCpuidReadMode() == CpuidReadMode::Empty) {
        AuditEventRateLimited("cpu.xgetbv", "empty", nullptr, index, true);
        return 0;
    }
    const unsigned __int64 value = _xgetbv(index);
    AuditEventRateLimited("cpu.xgetbv", "observed", nullptr, index, true);
    return value;
}

bool InstallManifestEntry(const std::string& line) {
    // module|sha256|rva|kind|prologue_hex
    std::vector<std::string> fields;
    size_t start = 0;
    while (start <= line.size()) {
        size_t end = line.find('|', start);
        if (end == std::string::npos) end = line.size();
        fields.push_back(line.substr(start, end - start));
        if (end == line.size()) break;
        start = end + 1;
    }
    if (fields.size() < 5) {
        AuditEvent("cpu.manifest", "invalid-line", line.c_str());
        ++g_hookInstallFailures;
        return false;
    }

    const std::wstring modulePath = Utf8ToWide(fields[0]);
    const std::string expectedHash = fields[1];
    const uint64_t rva = _strtoui64(fields[2].c_str(), nullptr, 0);
    const std::string kind = fields[3];
    const std::vector<BYTE> prologue = ParseHexBytes(fields[4]);

    std::string actualHash;
    if (!ComputeFileSha256(modulePath, actualHash)) {
        AuditEvent("cpu.manifest", "hash-unreadable", fields[0].c_str());
        ++g_hookInstallFailures;
        return false;
    }
    if (_stricmp(actualHash.c_str(), expectedHash.c_str()) != 0) {
        AuditEvent("cpu.manifest", "hash-mismatch", fields[0].c_str());
        ++g_hookInstallFailures;
        return false;
    }

    HMODULE module = FindModuleByPath(modulePath);
    if (!module) {
        AuditEvent("cpu.manifest", "module-not-loaded", fields[0].c_str());
        ++g_hookInstallFailures;
        return false;
    }

    BYTE* target = reinterpret_cast<BYTE*>(module) + rva;
    if (!HookEngine::IsExecutableAddress(target)) {
        AuditEvent("cpu.manifest", "target-not-executable", fields[0].c_str(), rva, true);
        ++g_hookInstallFailures;
        return false;
    }
    if (prologue.empty() || std::memcmp(target, prologue.data(), prologue.size()) != 0) {
        AuditEvent("cpu.manifest", "prologue-mismatch", fields[0].c_str(), rva, true);
        ++g_hookInstallFailures;
        return false;
    }

    void* detour = nullptr;
    if (kind == "cpuid") detour = reinterpret_cast<void*>(&CpuIdDetour);
    else if (kind == "cpuidex") detour = reinterpret_cast<void*>(&CpuIdExDetour);
    else if (kind == "xgetbv") detour = reinterpret_cast<void*>(&XgetbvDetour);
    else {
        AuditEvent("cpu.manifest", "unknown-kind", kind.c_str());
        ++g_hookInstallFailures;
        return false;
    }

    void* trampoline = nullptr;
    std::string error;
    if (HookEngine::Install(target, detour, &trampoline, &error)) {
        AuditEvent("cpu.install", "installed", kind.c_str(), rva, true);
        return true;
    } else {
        AuditEvent("cpu.install", "refused", error.c_str(), rva, true);
        ++g_hookInstallFailures;
        return false;
    }
}

}  // namespace

void InstallHookShared(const char* dllName, const char* functionName, void* detour,
                       void** original, bool allowInline) {
    InstallOne(dllName, functionName, detour, original, allowInline);
}

void InstallHookInlinePrimary(const char* dllName, const char* functionName, void* detour,
                              void** original) {
    InstallInlineThenIat(dllName, functionName, detour, original);
}

bool NativeEmptyReadsEnabled() {
    return EmptyReadsEnabled();
}

bool NativeIsVirtualAdapterName(const wchar_t* name) {
    if (!name || !*name) return false;
    static const wchar_t* const markers[] = {
        L"vmware", L"virtualbox", L"hyper-v", L"vethernet", L"virtual",
        L"tap-windows", L"tap0901", L"wintun", L"wireguard", L"tailscale",
        L"zerotier", L"openvpn", L"clash", L"mihomo", L"meta tunnel", L"meta",
        L"tunnel", L"vpn", L"ppp", L"sstp", L"l2tp", L"ipsec", L"teredo",
        L"6to4", L"ip-https", L"isatap", L"npcap", L"docker", L"wsl",
        L"veth", L"hamachi", L"radmin", L"softether",
    };
    for (const wchar_t* marker : markers) {
        if (ContainsNoCase(name, marker)) return true;
    }
    return false;
}

bool NativeCleanNetworkEnabled() {
    if (EmptyReadsEnabled()) return true;
    static int cached = -1;
    if (cached < 0) {
        char value[16] = {};
        const DWORD size = GetEnvironmentVariableA("CAC_NETWORK_MODE", value,
                                                   static_cast<DWORD>(sizeof(value)));
        cached = (size > 0 && size < sizeof(value) &&
                  (_stricmp(value, "clean") == 0 || _stricmp(value, "enforce") == 0)) ? 1 : 0;
    }
    return cached == 1;
}

bool NativeProxyRedirectEnabled() {
    char value[2048] = {};
    const DWORD size = GetEnvironmentVariableA("CAC_HTTP_PROXY_LOCAL", value,
                                               static_cast<DWORD>(sizeof(value)));
    return size > 0 && size < sizeof(value);
}

bool InstallApiHooks() {
    g_hookInstallFailures.store(0);
    InstallInlineThenIat("iphlpapi.dll", "GetAdaptersAddresses", reinterpret_cast<void*>(&HookGetAdaptersAddresses),
                         reinterpret_cast<void**>(&g_origGetAdaptersAddresses));
    InstallInlineThenIat("iphlpapi.dll", "GetAdaptersInfo", reinterpret_cast<void*>(&HookGetAdaptersInfo),
                         reinterpret_cast<void**>(&g_origGetAdaptersInfo));
    InstallInlineThenIat("kernel32.dll", "GetVolumeInformationW", reinterpret_cast<void*>(&HookGetVolumeInformationW),
                         reinterpret_cast<void**>(&g_origGetVolumeInformation));
    InstallInlineThenIat("kernel32.dll", "GetSystemFirmwareTable", reinterpret_cast<void*>(&HookGetSystemFirmwareTable),
                         reinterpret_cast<void**>(&g_origGetSystemFirmwareTable));
    InstallInlineThenIat("ntdll.dll", "NtQuerySystemInformation",
                         reinterpret_cast<void*>(&HookNtQuerySystemInformation),
                         reinterpret_cast<void**>(&g_origNtQuerySystemInformation));
    InstallInlineThenIat("kernel32.dll", "DeviceIoControl", reinterpret_cast<void*>(&HookDeviceIoControl),
                         reinterpret_cast<void**>(&g_origDeviceIoControl));
    InstallInlineThenIat("kernel32.dll", "GetComputerNameW", reinterpret_cast<void*>(&HookGetComputerNameW),
                         reinterpret_cast<void**>(&g_origGetComputerName));
    InstallInlineThenIat("kernel32.dll", "GetComputerNameExW", reinterpret_cast<void*>(&HookGetComputerNameExW),
                         reinterpret_cast<void**>(&g_origGetComputerNameEx));
    InstallInlineThenIat("advapi32.dll", "GetUserNameW", reinterpret_cast<void*>(&HookGetUserNameW),
                         reinterpret_cast<void**>(&g_origGetUserName));
    InstallInlineThenIat("advapi32.dll", "RegGetValueW", reinterpret_cast<void*>(&HookRegGetValueW),
                         reinterpret_cast<void**>(&g_origRegGetValue));
    InstallInlineThenIat("advapi32.dll", "RegQueryValueExW", reinterpret_cast<void*>(&HookRegQueryValueExW),
                         reinterpret_cast<void**>(&g_origRegQueryValueEx));
    InstallInlineThenIat("hid.dll", "HidD_GetSerialNumberString", reinterpret_cast<void*>(&HookHidD_GetSerialNumberString),
                         reinterpret_cast<void**>(&g_origHidGetSerial));
    InstallInlineThenIat("setupapi.dll", "SetupDiGetDevicePropertyW",
                         reinterpret_cast<void*>(&HookSetupDiGetDevicePropertyW),
                         reinterpret_cast<void**>(&g_origSetupDiGetDeviceProperty));
    InstallInlineThenIat("setupapi.dll", "SetupDiGetDeviceRegistryPropertyW",
                         reinterpret_cast<void*>(&HookSetupDiGetDeviceRegistryPropertyW),
                         reinterpret_cast<void**>(&g_origSetupDiGetRegistryProperty));
    InstallInlineThenIat("setupapi.dll", "SetupDiGetDeviceInstanceIdW",
                         reinterpret_cast<void*>(&HookSetupDiGetDeviceInstanceIdW),
                         reinterpret_cast<void**>(&g_origSetupDiGetInstanceId));
    InstallInlineThenIat("kernel32.dll", "GetVolumeInformationByHandleW",
                         reinterpret_cast<void*>(&HookGetVolumeInformationByHandleW),
                         reinterpret_cast<void**>(&g_origGetVolumeInformationByHandle));
    InstallInlineThenIat("kernel32.dll", "GetFileInformationByHandle",
                         reinterpret_cast<void*>(&HookGetFileInformationByHandle),
                         reinterpret_cast<void**>(&g_origGetFileInformationByHandle));
    InstallInlineThenIat("ntdll.dll", "NtQueryVolumeInformationFile",
                         reinterpret_cast<void*>(&HookNtQueryVolumeInformationFile),
                         reinterpret_cast<void**>(&g_origNtQueryVolumeInformationFile));
    InstallInlineThenIat("ntdll.dll", "NtDeviceIoControlFile",
                         reinterpret_cast<void*>(&HookNtDeviceIoControlFile),
                         reinterpret_cast<void**>(&g_origNtDeviceIoControlFile));
    InstallInlineThenIat("iphlpapi.dll", "GetIfTable2", reinterpret_cast<void*>(&HookGetIfTable2),
                         reinterpret_cast<void**>(&g_origGetIfTable2));
    InstallInlineThenIat("iphlpapi.dll", "GetIfEntry2", reinterpret_cast<void*>(&HookGetIfEntry2),
                         reinterpret_cast<void**>(&g_origGetIfEntry2));
    InstallInlineThenIat("iphlpapi.dll", "GetIfTable", reinterpret_cast<void*>(&HookGetIfTable),
                         reinterpret_cast<void**>(&g_origGetIfTable));
    InstallInlineThenIat("advapi32.dll", "RegEnumValueW", reinterpret_cast<void*>(&HookRegEnumValueW),
                         reinterpret_cast<void**>(&g_origRegEnumValue));
    InstallInlineThenIat("kernel32.dll", "K32EnumDeviceDrivers", reinterpret_cast<void*>(&HookEnumDeviceDrivers),
                         reinterpret_cast<void**>(&g_origEnumDeviceDrivers));
    InstallInlineThenIat("psapi.dll", "EnumDeviceDrivers", reinterpret_cast<void*>(&HookEnumDeviceDrivers),
                         reinterpret_cast<void**>(&g_origEnumDeviceDrivers));
    InstallInlineThenIat("setupapi.dll", "SetupDiGetClassDevsW", reinterpret_cast<void*>(&HookSetupDiGetClassDevsW),
                         reinterpret_cast<void**>(&g_origSetupDiGetClassDevs));
    InstallInlineThenIat("kernel32.dll", "CreateFileW", reinterpret_cast<void*>(&HookCreateFileW),
                         reinterpret_cast<void**>(&g_origCreateFile));
    InstallInlineThenIat("kernel32.dll", "CreateFileA", reinterpret_cast<void*>(&HookCreateFileA),
                         reinterpret_cast<void**>(&g_origCreateFileA));
    InstallInlineThenIat("kernel32.dll", "CreateFile2", reinterpret_cast<void*>(&HookCreateFile2),
                         reinterpret_cast<void**>(&g_origCreateFile2));
    InstallInlineThenIat("ntdll.dll", "NtCreateFile", reinterpret_cast<void*>(&HookNtCreateFile),
                         reinterpret_cast<void**>(&g_origNtCreateFile));
    InstallInlineThenIat("kernel32.dll", "GetOverlappedResult", reinterpret_cast<void*>(&HookGetOverlappedResult),
                         reinterpret_cast<void**>(&g_origGetOverlappedResult));
    InstallInlineThenIat("kernel32.dll", "GetOverlappedResultEx", reinterpret_cast<void*>(&HookGetOverlappedResultEx),
                         reinterpret_cast<void**>(&g_origGetOverlappedResultEx));
    InstallInlineThenIat("kernel32.dll", "GetQueuedCompletionStatus", reinterpret_cast<void*>(&HookGetQueuedCompletionStatus),
                         reinterpret_cast<void**>(&g_origGetQueuedCompletionStatus));
    InstallInlineThenIat("kernel32.dll", "GetQueuedCompletionStatusEx", reinterpret_cast<void*>(&HookGetQueuedCompletionStatusEx),
                         reinterpret_cast<void**>(&g_origGetQueuedCompletionStatusEx));
    const unsigned int failures = g_hookInstallFailures.load();
    char detail[64] = {};
    std::snprintf(detail, sizeof(detail), "failures=%u", failures);
    AuditEvent("api.install", "complete", detail, failures, true);
    return failures == 0;
}

unsigned int NativeHookInstallFailures() {
    return g_hookInstallFailures.load();
}

void InstallCpuHooksFromManifest() {
    wchar_t manifestPath[32768] = {};
    DWORD size = GetEnvironmentVariableW(L"CAC_NATIVE_MANIFEST", manifestPath, static_cast<DWORD>(_countof(manifestPath)));
    if (size == 0 || size >= _countof(manifestPath)) {
        AuditEvent("cpu.manifest", "not-configured");
        return;
    }
    std::vector<std::string> lines;
    if (!ReadManifestLines(manifestPath, lines)) {
        AuditEvent("cpu.manifest", "unreadable");
        ++g_hookInstallFailures;
        return;
    }
    if (lines.empty()) {
        AuditEvent("cpu.manifest", "empty");
        ++g_hookInstallFailures;
        return;
    }
    unsigned int installed = 0;
    for (const std::string& line : lines) {
        if (InstallManifestEntry(line)) ++installed;
    }
    char detail[64] = {};
    std::snprintf(detail, sizeof(detail), "entries=%u installed=%u",
                  static_cast<unsigned int>(lines.size()), installed);
    AuditEvent("cpu.manifest", installed == lines.size() ? "complete" : "failed", detail,
               installed, installed != lines.size());
}

void ScanCpuCandidates() {
    // Discovery is evidence only. Patching always requires an exact manifest.
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
    if (snapshot == INVALID_HANDLE_VALUE) return;
    MODULEENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    int candidates = 0;
    if (Module32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szModule, L"NativeBridge.dll") == 0) continue;
            BYTE* base = entry.modBaseAddr;
            const DWORD size = entry.modBaseSize;
            for (DWORD i = 0; i + 4 < size; ++i) {
                if (base[i] == 0x0F && base[i + 1] == 0xA2) {
                    ++candidates;
                    AuditEventRateLimited("cpu.candidate", "cpuid", nullptr,
                                          reinterpret_cast<ULONG_PTR>(base + i) - reinterpret_cast<ULONG_PTR>(entry.hModule), true);
                }
                if (base[i] == 0x0F && base[i + 1] == 0x01 && base[i + 2] == 0xD0) {
                    ++candidates;
                    AuditEventRateLimited("cpu.candidate", "xgetbv", nullptr,
                                          reinterpret_cast<ULONG_PTR>(base + i) - reinterpret_cast<ULONG_PTR>(entry.hModule), true);
                }
            }
        } while (Module32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    AuditEvent("cpu.candidate", "scan-complete", nullptr, static_cast<unsigned long long>(candidates), true);
}
