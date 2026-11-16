#include <windows.h>
#include <setupapi.h>
#include <devguid.h>

#include <cstdio>
#include <string>
#include <vector>

#pragma comment(lib, "setupapi.lib")

static std::wstring InstanceId(HDEVINFO set, SP_DEVINFO_DATA* info) {
    wchar_t buffer[512] = {};
    DWORD required = 0;
    if (!SetupDiGetDeviceInstanceIdW(set, info, buffer, _countof(buffer), &required)) {
        return std::wstring();
    }
    return buffer;
}

static std::wstring RegistryString(HDEVINFO set, SP_DEVINFO_DATA* info, DWORD property) {
    wchar_t buffer[1024] = {};
    DWORD type = 0;
    DWORD required = 0;
    if (!SetupDiGetDeviceRegistryPropertyW(set, info, property, &type,
                                          reinterpret_cast<PBYTE>(buffer), sizeof(buffer),
                                          &required)) {
        return std::wstring();
    }
    if (type == REG_SZ) return buffer;
    if (type == REG_MULTI_SZ) {
        std::wstring joined;
        for (const wchar_t* cursor = buffer; *cursor; cursor += wcslen(cursor) + 1) {
            if (!joined.empty()) joined += L';';
            joined += cursor;
        }
        return joined;
    }
    return std::wstring();
}

static const DEVPROPKEY kDevPkeyParent = {
    {0xA45C254E, 0xDF1C, 0x4EFD, {0x80, 0x20, 0x67, 0xD1, 0x46, 0xA8, 0x50, 0xE0}}, 8};
static const DEVPROPKEY kDevPkeyClass = {
    {0xA45C254E, 0xDF1C, 0x4EFD, {0x80, 0x20, 0x67, 0xD1, 0x46, 0xA8, 0x50, 0xE0}}, 9};
static const DEVPROPKEY kDevPkeyClassGuid = {
    {0xA45C254E, 0xDF1C, 0x4EFD, {0x80, 0x20, 0x67, 0xD1, 0x46, 0xA8, 0x50, 0xE0}}, 10};
static const DEVPROPKEY kDevPkeyDriver = {
    {0xA45C254E, 0xDF1C, 0x4EFD, {0x80, 0x20, 0x67, 0xD1, 0x46, 0xA8, 0x50, 0xE0}}, 11};

static std::wstring DevicePropertyString(HDEVINFO set, SP_DEVINFO_DATA* info,
                                         const DEVPROPKEY& key) {
    wchar_t buffer[512] = {};
    DEVPROPTYPE type = 0;
    DWORD required = 0;
    if (!SetupDiGetDevicePropertyW(set, info, &key, &type, reinterpret_cast<PBYTE>(buffer),
                                   sizeof(buffer), &required, 0) ||
        type != DEVPROP_TYPE_STRING) {
        return std::wstring();
    }
    return buffer;
}

static std::wstring DevicePropertyGuid(HDEVINFO set, SP_DEVINFO_DATA* info,
                                       const DEVPROPKEY& key) {
    GUID guid = {};
    DEVPROPTYPE type = 0;
    DWORD required = 0;
    if (!SetupDiGetDevicePropertyW(set, info, &key, &type, reinterpret_cast<PBYTE>(&guid),
                                   sizeof(guid), &required, 0) ||
        type != DEVPROP_TYPE_GUID) {
        return std::wstring();
    }
    wchar_t text[64] = {};
    swprintf_s(text, L"{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
               guid.Data1, guid.Data2, guid.Data3, guid.Data4[0], guid.Data4[1],
               guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5],
               guid.Data4[6], guid.Data4[7]);
    return text;
}

static void Enumerate(const wchar_t* enumerator, const char* label) {
    HDEVINFO set = SetupDiGetClassDevsW(nullptr, enumerator, nullptr,
                                        DIGCF_ALLCLASSES | DIGCF_PRESENT);
    if (set == INVALID_HANDLE_VALUE) {
        std::printf("%s_state=open-failed error=%lu\n", label, GetLastError());
        return;
    }
    int count = 0;
    for (DWORD index = 0; index < 64; ++index) {
        SP_DEVINFO_DATA info = {};
        info.cbSize = sizeof(info);
        if (!SetupDiEnumDeviceInfo(set, index, &info)) break;
        const std::wstring instance = InstanceId(set, &info);
        const std::wstring hardware = RegistryString(set, &info, SPDRP_HARDWAREID);
        const std::wstring manufacturer = RegistryString(set, &info, SPDRP_MFG);
        const std::wstring description = RegistryString(set, &info, SPDRP_DEVICEDESC);
        const std::wstring friendly = RegistryString(set, &info, SPDRP_FRIENDLYNAME);
        wprintf(L"%s%d_instance=%ls\n", enumerator, count, instance.c_str());
        wprintf(L"%s%d_hardware=%ls\n", enumerator, count, hardware.c_str());
        wprintf(L"%s%d_manufacturer=%ls\n", enumerator, count, manufacturer.c_str());
        wprintf(L"%s%d_description=%ls\n", enumerator, count, description.c_str());
        wprintf(L"%s%d_friendly=%ls\n", enumerator, count, friendly.c_str());
        wprintf(L"%s%d_class=%ls\n", enumerator, count,
                DevicePropertyString(set, &info, kDevPkeyClass).c_str());
        wprintf(L"%s%d_classguid=%ls\n", enumerator, count,
                DevicePropertyGuid(set, &info, kDevPkeyClassGuid).c_str());
        wprintf(L"%s%d_parent=%ls\n", enumerator, count,
                DevicePropertyString(set, &info, kDevPkeyParent).c_str());
        wprintf(L"%s%d_driver=%ls\n", enumerator, count,
                DevicePropertyString(set, &info, kDevPkeyDriver).c_str());
        ++count;
    }
    SetupDiDestroyDeviceInfoList(set);
    std::printf("%ls_count=%d\n", enumerator, count);
}

int wmain() {
    Enumerate(L"USB", "usb");
    Enumerate(L"USBSTOR", "usbstor");
    return 0;
}
