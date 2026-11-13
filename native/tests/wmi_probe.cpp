#define _WIN32_WINNT 0x0A00

#include <windows.h>
#include <wbemidl.h>
#include <oleauto.h>

#include <cstdio>
#include <string>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

namespace {

std::string WideToUtf8(const std::wstring& value) {
    if (value.empty()) return std::string();
    const int length = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()),
                                           nullptr, 0, nullptr, nullptr);
    if (length <= 0) return std::string();
    std::string result(static_cast<size_t>(length), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()),
                        result.data(), length, nullptr, nullptr);
    return result;
}

std::wstring QueryFirst(IWbemServices* service, const wchar_t* query, const wchar_t* property) {
    IEnumWbemClassObject* enumerator = nullptr;
    const HRESULT queryResult = service->ExecQuery(
        const_cast<BSTR>(L"WQL"), const_cast<BSTR>(query),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &enumerator);
    if (FAILED(queryResult) || !enumerator) return L"<query-error>";

    IWbemClassObject* object = nullptr;
    ULONG returned = 0;
    std::wstring result = L"<none>";
    if (SUCCEEDED(enumerator->Next(5000, 1, &object, &returned)) && returned == 1 && object) {
        VARIANT value;
        VariantInit(&value);
        if (SUCCEEDED(object->Get(property, 0, &value, nullptr, nullptr))) {
            if (value.vt == VT_BSTR && value.bstrVal) {
                result.assign(value.bstrVal, SysStringLen(value.bstrVal));
            } else if (value.vt == VT_NULL) {
                result = L"<null>";
            }
        }
        VariantClear(&value);
        object->Release();
    }
    enumerator->Release();
    return result;
}

}  // namespace

int wmain() {
    const HRESULT initialized = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(initialized)) {
        std::printf("wmi_state=coinit-error\n");
        return 1;
    }
    CoInitializeSecurity(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT,
                         RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);

    IWbemLocator* locator = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                                  IID_IWbemLocator, reinterpret_cast<void**>(&locator));
    if (FAILED(hr) || !locator) {
        std::printf("wmi_state=create-error\n");
        CoUninitialize();
        return 1;
    }

    IWbemServices* service = nullptr;
    hr = locator->ConnectServer(const_cast<BSTR>(L"ROOT\\CIMV2"), nullptr, nullptr, nullptr, 0,
                                nullptr, nullptr, &service);
    if (FAILED(hr) || !service) {
        std::printf("wmi_state=connect-error\n");
        locator->Release();
        CoUninitialize();
        return 1;
    }

    std::printf("wmi_state=ok\n");
    std::printf("wmi_bios_serial=%s\n",
                WideToUtf8(QueryFirst(service, L"SELECT SerialNumber FROM Win32_BIOS", L"SerialNumber")).c_str());
    std::printf("wmi_uuid=%s\n",
                WideToUtf8(QueryFirst(service, L"SELECT UUID FROM Win32_ComputerSystemProduct", L"UUID")).c_str());
    std::printf("wmi_disk_serial=%s\n",
                WideToUtf8(QueryFirst(service, L"SELECT SerialNumber FROM Win32_DiskDrive", L"SerialNumber")).c_str());
    std::printf("wmi_mac=%s\n",
                WideToUtf8(QueryFirst(service,
                                      L"SELECT MACAddress FROM Win32_NetworkAdapter WHERE PhysicalAdapter = TRUE",
                                      L"MACAddress")).c_str());
    std::printf("wmi_adapter_name=%s\n",
                WideToUtf8(QueryFirst(service, L"SELECT Name FROM Win32_NetworkAdapter", L"Name")).c_str());
    std::printf("wmi_processor_id=%s\n",
                WideToUtf8(QueryFirst(service, L"SELECT ProcessorId FROM Win32_Processor", L"ProcessorId")).c_str());
    std::printf("wmi_volume_serial=%s\n",
                WideToUtf8(QueryFirst(service,
                                      L"SELECT VolumeSerialNumber FROM Win32_LogicalDisk WHERE DeviceID = 'C:'",
                                      L"VolumeSerialNumber")).c_str());

    service->Release();
    locator->Release();
    CoUninitialize();
    return 0;
}
