#include <windows.h>
#include <wbemidl.h>

#include <cstdio>
#include <string>

static bool ReadArray(IWbemClassObject* object, const wchar_t* name, std::wstring* text) {
    VARIANT value;
    VariantInit(&value);
    if (FAILED(object->Get(name, 0, &value, nullptr, nullptr))) return false;
    bool ok = false;
    if ((value.vt & VT_ARRAY) && value.parray) {
        const LONG lower = value.parray->rgsabound[0].lLbound;
        const LONG count = static_cast<LONG>(value.parray->rgsabound[0].cElements);
        text->clear();
        const VARTYPE elementType = value.vt & VT_TYPEMASK;
        if (elementType == VT_VARIANT) {
            VARIANT* data = nullptr;
            if (SUCCEEDED(SafeArrayAccessData(value.parray, reinterpret_cast<void**>(&data)))) {
                for (LONG index = 0; index < count; ++index) {
                    const VARIANT& item = data[lower + index];
                    if (item.vt == VT_UI2) text->push_back(static_cast<wchar_t>(item.uiVal));
                    else if (item.vt == VT_I2) text->push_back(static_cast<wchar_t>(item.iVal));
                }
                SafeArrayUnaccessData(value.parray);
                ok = true;
            }
        } else if (elementType == VT_UI2 || elementType == VT_I2) {
            USHORT* data = nullptr;
            if (SUCCEEDED(SafeArrayAccessData(value.parray, reinterpret_cast<void**>(&data)))) {
                for (LONG index = 0; index < count; ++index) {
                    text->push_back(static_cast<wchar_t>(static_cast<SHORT>(data[lower + index])));
                }
                SafeArrayUnaccessData(value.parray);
                ok = true;
            }
        }
    }
    VariantClear(&value);
    return ok;
}

static bool ReadScalar(IWbemClassObject* object, const wchar_t* name, std::wstring* text) {
    VARIANT value;
    VariantInit(&value);
    const HRESULT hr = object->Get(name, 0, &value, nullptr, nullptr);
    bool ok = false;
    if (SUCCEEDED(hr) && value.vt == VT_BSTR && value.bstrVal) {
        text->assign(value.bstrVal, SysStringLen(value.bstrVal));
        ok = true;
    }
    VariantClear(&value);
    return ok;
}

int wmain() {
    CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    IWbemLocator* locator = nullptr;
    if (FAILED(CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                                IID_IWbemLocator, reinterpret_cast<void**>(&locator))) ||
        !locator) {
        std::printf("monitor_wmi_state=locator-failed\n");
        return 2;
    }
    BSTR ns = SysAllocString(L"ROOT\\WMI");
    IWbemServices* services = nullptr;
    const HRESULT connected =
        locator->ConnectServer(ns, nullptr, nullptr, nullptr, 0, nullptr, nullptr, &services);
    SysFreeString(ns);
    locator->Release();
    if (FAILED(connected) || !services) {
        std::printf("monitor_wmi_state=connect-failed\n");
        return 3;
    }
    CoSetProxyBlanket(services, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                      RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
    BSTR language = SysAllocString(L"WQL");
    BSTR query = SysAllocString(L"SELECT * FROM WmiMonitorID");
    IEnumWbemClassObject* enumerator = nullptr;
    const HRESULT queried = services->ExecQuery(
        language, query, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr,
        &enumerator);
    SysFreeString(language);
    SysFreeString(query);
    services->Release();
    if (FAILED(queried) || !enumerator) {
        std::printf("monitor_wmi_state=query-failed\n");
        return 4;
    }
    std::printf("monitor_wmi_state=ok\n");
    int count = 0;
    IWbemClassObject* object = nullptr;
    ULONG returned = 0;
    while (enumerator->Next(5000, 1, &object, &returned) == S_OK && returned == 1) {
        std::wstring instance;
        std::wstring manufacturer;
        std::wstring product;
        std::wstring serial;
        std::wstring friendly;
        ReadScalar(object, L"InstanceName", &instance);
        ReadArray(object, L"ManufacturerName", &manufacturer);
        ReadArray(object, L"ProductCodeID", &product);
        ReadArray(object, L"SerialNumberID", &serial);
        ReadArray(object, L"UserFriendlyName", &friendly);
        wprintf(L"monitor_wmi%d_instance=%ls\n", count, instance.c_str());
        wprintf(L"monitor_wmi%d_manufacturer=%ls\n", count, manufacturer.c_str());
        wprintf(L"monitor_wmi%d_product=%ls\n", count, product.c_str());
        wprintf(L"monitor_wmi%d_serial=%ls\n", count, serial.c_str());
        wprintf(L"monitor_wmi%d_friendly=%ls\n", count, friendly.c_str());
        object->Release();
        object = nullptr;
        ++count;
    }
    enumerator->Release();
    std::printf("monitor_wmi_count=%d\n", count);
    CoUninitialize();
    return 0;
}
