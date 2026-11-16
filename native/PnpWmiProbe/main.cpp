#include <windows.h>
#include <wbemidl.h>

#include <cstdio>
#include <cwctype>
#include <string>

static bool GetString(IWbemClassObject* object, const wchar_t* name, std::wstring* value) {
    VARIANT variant;
    VariantInit(&variant);
    const HRESULT hr = object->Get(name, 0, &variant, nullptr, nullptr);
    if (SUCCEEDED(hr) && variant.vt == VT_BSTR && variant.bstrVal) {
        value->assign(variant.bstrVal, SysStringLen(variant.bstrVal));
        VariantClear(&variant);
        return true;
    }
    VariantClear(&variant);
    return false;
}

static std::wstring NormalizeGuid(const std::wstring& value) {
    std::wstring text;
    for (wchar_t ch : value) {
        if (iswxdigit(ch)) text.push_back(static_cast<wchar_t>(towlower(ch)));
    }
    return text;
}

static bool Connect(IWbemLocator* locator, IWbemServices** services) {
    BSTR ns = SysAllocString(L"ROOT\\CIMV2");
    const HRESULT hr = locator->ConnectServer(ns, nullptr, nullptr, nullptr, 0, nullptr, nullptr,
                                              services);
    SysFreeString(ns);
    if (FAILED(hr) || !*services) return false;
    CoSetProxyBlanket(*services, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                      RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
    return true;
}

static IEnumWbemClassObject* Query(IWbemServices* services, const wchar_t* wql) {
    BSTR language = SysAllocString(L"WQL");
    BSTR query = SysAllocString(wql);
    IEnumWbemClassObject* enumerator = nullptr;
    const HRESULT hr = services->ExecQuery(
        language, query, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr,
        &enumerator);
    SysFreeString(language);
    SysFreeString(query);
    return SUCCEEDED(hr) ? enumerator : nullptr;
}

static void PrintScalar(IWbemServices* services, const char* label, const wchar_t* wql,
                        const wchar_t* property) {
    IEnumWbemClassObject* enumerator = Query(services, wql);
    if (!enumerator) {
        std::printf("%s=<query-failed>\n", label);
        return;
    }
    IWbemClassObject* object = nullptr;
    ULONG returned = 0;
    std::wstring value;
    if (enumerator->Next(5000, 1, &object, &returned) == S_OK && returned == 1 && object) {
        GetString(object, property, &value);
        object->Release();
    }
    enumerator->Release();
    wprintf(L"%hs=%ls\n", label, value.c_str());
}

int wmain() {
    CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    IWbemLocator* locator = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                                  IID_IWbemLocator, reinterpret_cast<void**>(&locator));
    if (FAILED(hr) || !locator) {
        std::printf("pnp_wmi_state=locator-failed\n");
        return 2;
    }
    IWbemServices* services = nullptr;
    if (!Connect(locator, &services)) {
        locator->Release();
        std::printf("pnp_wmi_state=connect-failed\n");
        return 3;
    }
    locator->Release();

    const wchar_t* queries[] = {
        L"SELECT * FROM Win32_PnPEntity",
        L"SELECT Name, ClassGuid, PNPDeviceID FROM Win32_PnPEntity",
        L"SELECT Name, PNPDeviceID FROM Win32_PnPEntity",
    };
    IEnumWbemClassObject* enumerator = nullptr;
    int queryIndex = 0;
    for (; queryIndex < 3; ++queryIndex) {
        enumerator = Query(services, queries[queryIndex]);
        if (enumerator) break;
    }
    if (!enumerator) {
        services->Release();
        std::printf("pnp_wmi_state=query-failed\n");
        return 4;
    }

    std::printf("pnp_wmi_state=ok\n");
    std::printf("pnp_wmi_query=%d\n", queryIndex + 1);
    int total = 0;
    int gameViewer = 0;
    int displayRows = 0;
    int monitorRows = 0;
    int audioRows = 0;
    int diskRows = 0;
    int netRows = 0;
    for (int index = 0; index < 4000; ++index) {
        IWbemClassObject* object = nullptr;
        ULONG returned = 0;
        if (enumerator->Next(WBEM_INFINITE, 1, &object, &returned) != S_OK || returned == 0) break;
        std::wstring name;
        std::wstring classGuid;
        std::wstring id;
        GetString(object, L"Name", &name);
        GetString(object, L"ClassGuid", &classGuid);
        GetString(object, L"PNPDeviceID", &id);
        const std::wstring guid = NormalizeGuid(classGuid);
        ++total;
        if (name.find(L"GameViewer") != std::wstring::npos ||
            id.find(L"GameViewer") != std::wstring::npos) {
            ++gameViewer;
        }
        if (guid == L"4d36e968e32511cebfc108002be10318") ++displayRows;
        if (guid == L"4d36e96ee32511cebfc108002be10318") ++monitorRows;
        if (guid == L"4d36e96ce32511cebfc108002be10318") ++audioRows;
        if (guid == L"4d36e967e32511cebfc108002be10318") ++diskRows;
        if (guid == L"4d36e972e32511cebfc108002be10318") ++netRows;
        if (index < 400) {
            wprintf(L"pnp_wmi%d_name=%ls\n", index, name.c_str());
            wprintf(L"pnp_wmi%d_class=%ls\n", index, guid.c_str());
            wprintf(L"pnp_wmi%d_id=%ls\n", index, id.c_str());
        }
        object->Release();
    }
    enumerator->Release();

    std::printf("pnp_wmi_total=%d\n", total);
    std::printf("pnp_wmi_gameviewer=%d\n", gameViewer);
    std::printf("pnp_wmi_display_rows=%d\n", displayRows);
    std::printf("pnp_wmi_monitor_rows=%d\n", monitorRows);
    std::printf("pnp_wmi_audio_rows=%d\n", audioRows);
    std::printf("pnp_wmi_disk_rows=%d\n", diskRows);
    std::printf("pnp_wmi_net_rows=%d\n", netRows);

    PrintScalar(services, "wmi_bios_serial", L"SELECT SerialNumber FROM Win32_BIOS",
                L"SerialNumber");
    PrintScalar(services, "wmi_cs_name", L"SELECT Name FROM Win32_ComputerSystem", L"Name");
    PrintScalar(services, "wmi_cs_manufacturer",
                L"SELECT Manufacturer FROM Win32_ComputerSystem", L"Manufacturer");
    PrintScalar(services, "wmi_cs_model", L"SELECT Model FROM Win32_ComputerSystem", L"Model");
    PrintScalar(services, "wmi_processor_name", L"SELECT Name FROM Win32_Processor", L"Name");
    PrintScalar(services, "wmi_processor_id", L"SELECT ProcessorId FROM Win32_Processor",
                L"ProcessorId");
    PrintScalar(services, "wmi_disk_serial", L"SELECT SerialNumber FROM Win32_DiskDrive",
                L"SerialNumber");
    PrintScalar(services, "wmi_nic_mac", L"SELECT MACAddress FROM Win32_NetworkAdapter",
                L"MACAddress");

    services->Release();
    CoUninitialize();
    return 0;
}
