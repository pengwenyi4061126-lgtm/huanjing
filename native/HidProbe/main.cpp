#include <windows.h>
#include <hidsdi.h>
#include <setupapi.h>

#include <cstdio>
#include <vector>

int wmain() {
    GUID hidGuid = {};
    HidD_GetHidGuid(&hidGuid);
    HDEVINFO set = SetupDiGetClassDevsW(&hidGuid, nullptr, nullptr,
                                        DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (set == INVALID_HANDLE_VALUE) {
        std::printf("hid_state=enum-failed error=%lu\n", GetLastError());
        return 2;
    }

    int shown = 0;
    for (DWORD index = 0; index < 16 && shown < 3; ++index) {
        SP_DEVICE_INTERFACE_DATA interfaceData = {};
        interfaceData.cbSize = sizeof(interfaceData);
        if (!SetupDiEnumDeviceInterfaces(set, nullptr, &hidGuid, index, &interfaceData)) {
            break;
        }
        DWORD needed = 0;
        SetupDiGetDeviceInterfaceDetailW(set, &interfaceData, nullptr, 0, &needed, nullptr);
        if (needed == 0) continue;
        std::vector<BYTE> buffer(needed);
        auto* detail = reinterpret_cast<PSP_DEVICE_INTERFACE_DETAIL_DATA_W>(buffer.data());
        detail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);
        if (!SetupDiGetDeviceInterfaceDetailW(set, &interfaceData, detail, needed,
                                              &needed, nullptr)) {
            continue;
        }

        HANDLE device = CreateFileW(detail->DevicePath, GENERIC_READ,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                    OPEN_EXISTING, 0, nullptr);
        if (device == INVALID_HANDLE_VALUE) {
            std::printf("hid%d_state=open-failed error=%lu\n", shown, GetLastError());
            continue;
        }

        HIDD_ATTRIBUTES attributes = {};
        attributes.Size = sizeof(attributes);
        if (HidD_GetAttributes(device, &attributes)) {
            wchar_t manufacturer[256] = {};
            wchar_t product[256] = {};
            wchar_t serial[256] = {};
            HidD_GetManufacturerString(device, manufacturer, sizeof(manufacturer));
            HidD_GetProductString(device, product, sizeof(product));
            HidD_GetSerialNumberString(device, serial, sizeof(serial));
            std::printf("hid%d_vendor=0x%04x\n", shown, attributes.VendorID);
            std::printf("hid%d_product=0x%04x\n", shown, attributes.ProductID);
            std::printf("hid%d_version=0x%04x\n", shown, attributes.VersionNumber);
            wprintf(L"hid%d_manufacturer=%ls\n", shown, manufacturer);
            wprintf(L"hid%d_product_string=%ls\n", shown, product);
            wprintf(L"hid%d_serial=%ls\n", shown, serial);
            ++shown;
        }
        CloseHandle(device);
    }
    SetupDiDestroyDeviceInfoList(set);
    std::printf("hid_state=%s\n", shown > 0 ? "ok" : "none");
    return 0;
}
