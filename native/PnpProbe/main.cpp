#include <windows.h>
#include <setupapi.h>
#include <devguid.h>
#include <devpkey.h>

#include <cstdio>

static const DEVPROPKEY kDevPkeyDeviceDesc = {
    {0xA45C254E, 0xDF1C, 0x4EFD, {0x80, 0x20, 0x67, 0xD1, 0x46, 0xA8, 0x50, 0xE0}}, 2};
static const DEVPROPKEY kDevPkeyDeviceManufacturer = {
    {0xA45C254E, 0xDF1C, 0x4EFD, {0x80, 0x20, 0x67, 0xD1, 0x46, 0xA8, 0x50, 0xE0}}, 13};
static const DEVPROPKEY kDevPkeyDeviceFriendlyName = {
    {0xA45C254E, 0xDF1C, 0x4EFD, {0x80, 0x20, 0x67, 0xD1, 0x46, 0xA8, 0x50, 0xE0}}, 14};

static void PrintDevices(const GUID& guid, const char* label) {
    static DWORD slot = 0;
    HDEVINFO set = SetupDiGetClassDevsW(&guid, nullptr, nullptr, DIGCF_PRESENT);
    if (set == INVALID_HANDLE_VALUE) return;
    SP_DEVINFO_DATA info = {};
    info.cbSize = sizeof(info);
    for (DWORD index = 0; index < 8; ++index) {
        if (!SetupDiEnumDeviceInfo(set, index, &info)) break;
        wchar_t instance[512] = {};
        wchar_t friendly[512] = {};
        wchar_t description[512] = {};
        wchar_t hardware[1024] = {};
        wchar_t devFriendly[512] = {};
        wchar_t devDesc[512] = {};
        wchar_t devManufacturer[512] = {};
        DWORD type = 0;
        DWORD needed = 0;
        if (!SetupDiGetDeviceInstanceIdW(set, &info, instance,
                                         sizeof(instance) / sizeof(instance[0]), &needed)) continue;
        SetupDiGetDeviceRegistryPropertyW(set, &info, SPDRP_FRIENDLYNAME, &type,
                                          reinterpret_cast<PBYTE>(friendly),
                                          sizeof(friendly), &needed);
        SetupDiGetDeviceRegistryPropertyW(set, &info, SPDRP_DEVICEDESC, &type,
                                          reinterpret_cast<PBYTE>(description),
                                          sizeof(description), &needed);
        SetupDiGetDeviceRegistryPropertyW(set, &info, SPDRP_HARDWAREID, &type,
                                          reinterpret_cast<PBYTE>(hardware),
                                          sizeof(hardware), &needed);
        DEVPROPTYPE propType = 0;
        SetupDiGetDevicePropertyW(set, &info, &kDevPkeyDeviceFriendlyName, &propType,
                                  reinterpret_cast<PBYTE>(devFriendly),
                                  sizeof(devFriendly), &needed, 0);
        SetupDiGetDevicePropertyW(set, &info, &kDevPkeyDeviceDesc, &propType,
                                  reinterpret_cast<PBYTE>(devDesc),
                                  sizeof(devDesc), &needed, 0);
        SetupDiGetDevicePropertyW(set, &info, &kDevPkeyDeviceManufacturer, &propType,
                                  reinterpret_cast<PBYTE>(devManufacturer),
                                  sizeof(devManufacturer), &needed, 0);
        const DWORD current = slot++;
        std::printf("pnp%lu_class=%s\n", static_cast<unsigned long>(current), label);
        wprintf(L"pnp%lu_instance=%ls\n", static_cast<unsigned long>(current), instance);
        wprintf(L"pnp%lu_friendly=%ls\n", static_cast<unsigned long>(current), friendly);
        wprintf(L"pnp%lu_desc=%ls\n", static_cast<unsigned long>(current), description);
        wprintf(L"pnp%lu_hwid=%ls\n", static_cast<unsigned long>(current), hardware);
        wprintf(L"pnp%lu_devfriendly=%ls\n", static_cast<unsigned long>(current), devFriendly);
        wprintf(L"pnp%lu_devdesc=%ls\n", static_cast<unsigned long>(current), devDesc);
        wprintf(L"pnp%lu_devmanufacturer=%ls\n", static_cast<unsigned long>(current), devManufacturer);
    }
    SetupDiDestroyDeviceInfoList(set);
}

int wmain() {
    std::printf("pnp_state=ok\n");
    PrintDevices(GUID_DEVCLASS_DISPLAY, "display");
    PrintDevices(GUID_DEVCLASS_MONITOR, "monitor");
    return 0;
}
