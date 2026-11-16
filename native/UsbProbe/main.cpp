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
