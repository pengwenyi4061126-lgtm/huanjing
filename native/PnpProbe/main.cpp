#include <windows.h>
#include <setupapi.h>
#include <devguid.h>

#include <cstdio>

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
        const DWORD current = slot++;
        std::printf("pnp%lu_class=%s\n", static_cast<unsigned long>(current), label);
        wprintf(L"pnp%lu_instance=%ls\n", static_cast<unsigned long>(current), instance);
        wprintf(L"pnp%lu_friendly=%ls\n", static_cast<unsigned long>(current), friendly);
        wprintf(L"pnp%lu_desc=%ls\n", static_cast<unsigned long>(current), description);
        wprintf(L"pnp%lu_hwid=%ls\n", static_cast<unsigned long>(current), hardware);
    }
    SetupDiDestroyDeviceInfoList(set);
}

int wmain() {
    std::printf("pnp_state=ok\n");
    PrintDevices(GUID_DEVCLASS_DISPLAY, "display");
    PrintDevices(GUID_DEVCLASS_MONITOR, "monitor");
    return 0;
}
