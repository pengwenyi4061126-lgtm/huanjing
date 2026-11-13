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

#include <cstdint>
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

struct FirmwareTableInfo {
    ULONG ProviderSignature;
    ULONG Action;
    ULONG TableID;
    ULONG TableBufferLength;
    UCHAR TableBuffer[1];
};

constexpr DWORD kRsmbSignature = 0x52534D42;  // 'RSMB'

bool ReplaceBufferString(char* value, size_t maxLength, const std::string& desired) {
    if (!value || maxLength == 0) return false;
    size_t oldLength = strnlen(value, maxLength);
    if (oldLength == 0 || oldLength >= maxLength) return false;
    const size_t copy = desired.size() < oldLength ? desired.size() : oldLength;
    std::memcpy(value, desired.data(), copy);
    if (copy < oldLength) std::memset(value + copy, ' ', oldLength - copy);
    value[oldLength] = 0;
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
    (void)format;
    const DWORD capacity = (size && *size) ? *size : 0;
    if (EmptyReadsEnabled()) {
        const BOOL result = CopyEmptyWideToBuffer(buffer, capacity, size);
        AuditEventRateLimited("api.getcomputernameex", result ? "empty" : "buffer-too-small");
        return result;
    }
    const BOOL result = CopyWideToBuffer(Utf8ToWide(ProfileIdentity::Get().hostname), buffer, capacity, size);
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

BOOL WINAPI HookDeviceIoControl(HANDLE device, DWORD code, LPVOID input, DWORD inputSize,
                                LPVOID output, DWORD outputSize, LPDWORD returned, LPOVERLAPPED overlapped) {
    const BOOL result = g_origDeviceIoControl
        ? g_origDeviceIoControl(device, code, input, inputSize, output, outputSize, returned, overlapped)
        : FALSE;
    if (result && output && returned && *returned > 0) {
        if (code == IOCTL_STORAGE_QUERY_PROPERTY && input && inputSize >= sizeof(STORAGE_PROPERTY_QUERY)) {
            const STORAGE_PROPERTY_QUERY* query = static_cast<const STORAGE_PROPERTY_QUERY*>(input);
            if (query->PropertyId == StorageDeviceProperty && query->QueryType == PropertyStandardQuery) {
                STORAGE_DEVICE_DESCRIPTOR* descriptor = static_cast<STORAGE_DEVICE_DESCRIPTOR*>(output);
                if (descriptor->Size <= *returned && descriptor->SerialNumberOffset > 0 &&
                    descriptor->SerialNumberOffset < *returned) {
                    char* serial = static_cast<char*>(output) + descriptor->SerialNumberOffset;
                    const size_t max = *returned - descriptor->SerialNumberOffset;
                    if (EmptyReadsEnabled()) {
                        serial[0] = '\0';
                        AuditEventRateLimited("api.deviceiocontrol.serial", "empty");
                    } else if (ReplaceBufferString(serial, max, ProfileIdentity::Get().diskSerial)) {
                        AuditEventRateLimited("api.deviceiocontrol.serial", "patched");
                    }
                }
            }
        }
        AuditEventRateLimited("api.deviceiocontrol", "observed", nullptr, code, true);
    }
    return result;
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
    return reinterpret_cast<void*>(GetProcAddress(module, functionName));
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
        AuditEvent("api.install", "not-imported", functionName);
        return;
    }

    void* target = ResolveExport(dllName, functionName);
    if (!target) {
        AuditEvent("api.install", "missing", dllName);
        return;
    }
    void* trampoline = nullptr;
    std::string error;
    if (HookEngine::Install(target, detour, &trampoline, &error)) {
        if (original && *original == nullptr) *original = trampoline;
        AuditEvent("api.install", "inline", functionName);
    } else {
        AuditEvent("api.install", "refused", error.c_str());
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

void InstallManifestEntry(const std::string& line) {
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
        return;
    }

    const std::wstring modulePath = Utf8ToWide(fields[0]);
    const std::string expectedHash = fields[1];
    const uint64_t rva = _strtoui64(fields[2].c_str(), nullptr, 0);
    const std::string kind = fields[3];
    const std::vector<BYTE> prologue = ParseHexBytes(fields[4]);

    std::string actualHash;
    if (!ComputeFileSha256(modulePath, actualHash)) {
        AuditEvent("cpu.manifest", "hash-unreadable", fields[0].c_str());
        return;
    }
    if (_stricmp(actualHash.c_str(), expectedHash.c_str()) != 0) {
        AuditEvent("cpu.manifest", "hash-mismatch", fields[0].c_str());
        return;
    }

    HMODULE module = FindModuleByPath(modulePath);
    if (!module) {
        AuditEvent("cpu.manifest", "module-not-loaded", fields[0].c_str());
        return;
    }

    BYTE* target = reinterpret_cast<BYTE*>(module) + rva;
    if (!HookEngine::IsExecutableAddress(target)) {
        AuditEvent("cpu.manifest", "target-not-executable", fields[0].c_str(), rva, true);
        return;
    }
    if (prologue.empty() || std::memcmp(target, prologue.data(), prologue.size()) != 0) {
        AuditEvent("cpu.manifest", "prologue-mismatch", fields[0].c_str(), rva, true);
        return;
    }

    void* detour = nullptr;
    if (kind == "cpuid") detour = reinterpret_cast<void*>(&CpuIdDetour);
    else if (kind == "cpuidex") detour = reinterpret_cast<void*>(&CpuIdExDetour);
    else if (kind == "xgetbv") detour = reinterpret_cast<void*>(&XgetbvDetour);
    else {
        AuditEvent("cpu.manifest", "unknown-kind", kind.c_str());
        return;
    }

    void* trampoline = nullptr;
    std::string error;
    if (HookEngine::Install(target, detour, &trampoline, &error)) {
        AuditEvent("cpu.install", "installed", kind.c_str(), rva, true);
    } else {
        AuditEvent("cpu.install", "refused", error.c_str(), rva, true);
    }
}

}  // namespace

bool InstallApiHooks() {
    InstallOne("iphlpapi.dll", "GetAdaptersAddresses", reinterpret_cast<void*>(&HookGetAdaptersAddresses),
               reinterpret_cast<void**>(&g_origGetAdaptersAddresses));
    InstallOne("iphlpapi.dll", "GetAdaptersInfo", reinterpret_cast<void*>(&HookGetAdaptersInfo),
               reinterpret_cast<void**>(&g_origGetAdaptersInfo));
    InstallOne("kernel32.dll", "GetVolumeInformationW", reinterpret_cast<void*>(&HookGetVolumeInformationW),
               reinterpret_cast<void**>(&g_origGetVolumeInformation));
    InstallOne("kernel32.dll", "GetSystemFirmwareTable", reinterpret_cast<void*>(&HookGetSystemFirmwareTable),
               reinterpret_cast<void**>(&g_origGetSystemFirmwareTable));
    InstallOne("ntdll.dll", "NtQuerySystemInformation", reinterpret_cast<void*>(&HookNtQuerySystemInformation),
               reinterpret_cast<void**>(&g_origNtQuerySystemInformation));
    InstallOne("kernel32.dll", "DeviceIoControl", reinterpret_cast<void*>(&HookDeviceIoControl),
               reinterpret_cast<void**>(&g_origDeviceIoControl));
    InstallOne("kernel32.dll", "GetComputerNameW", reinterpret_cast<void*>(&HookGetComputerNameW),
               reinterpret_cast<void**>(&g_origGetComputerName));
    InstallOne("kernel32.dll", "GetComputerNameExW", reinterpret_cast<void*>(&HookGetComputerNameExW),
               reinterpret_cast<void**>(&g_origGetComputerNameEx));
    InstallOne("advapi32.dll", "GetUserNameW", reinterpret_cast<void*>(&HookGetUserNameW),
               reinterpret_cast<void**>(&g_origGetUserName));
    InstallOne("advapi32.dll", "RegGetValueW", reinterpret_cast<void*>(&HookRegGetValueW),
               reinterpret_cast<void**>(&g_origRegGetValue));
    InstallOne("advapi32.dll", "RegQueryValueExW", reinterpret_cast<void*>(&HookRegQueryValueExW),
               reinterpret_cast<void**>(&g_origRegQueryValueEx));
    InstallOne("hid.dll", "HidD_GetSerialNumberString", reinterpret_cast<void*>(&HookHidD_GetSerialNumberString),
               reinterpret_cast<void**>(&g_origHidGetSerial));
    InstallOne("setupapi.dll", "SetupDiGetDevicePropertyW", reinterpret_cast<void*>(&HookSetupDiGetDevicePropertyW),
               reinterpret_cast<void**>(&g_origSetupDiGetDeviceProperty), false);
    InstallOne("setupapi.dll", "SetupDiGetDeviceRegistryPropertyW", reinterpret_cast<void*>(&HookSetupDiGetDeviceRegistryPropertyW),
               reinterpret_cast<void**>(&g_origSetupDiGetRegistryProperty), false);
    InstallOne("setupapi.dll", "SetupDiGetDeviceInstanceIdW", reinterpret_cast<void*>(&HookSetupDiGetDeviceInstanceIdW),
               reinterpret_cast<void**>(&g_origSetupDiGetInstanceId), false);
    AuditEvent("api.install", "complete");
    return true;
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
        return;
    }
    for (const std::string& line : lines) InstallManifestEntry(line);
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
