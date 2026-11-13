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

class AsyncSink : public IWbemObjectSink {
public:
    AsyncSink() : refs_(1), event_(CreateEventW(nullptr, TRUE, FALSE, nullptr)) {}
    ~AsyncSink() { if (event_) CloseHandle(event_); }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** object) override {
        if (!object) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IWbemObjectSink) {
            *object = static_cast<IWbemObjectSink*>(this);
            AddRef();
            return S_OK;
        }
        *object = nullptr;
        return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return static_cast<ULONG>(InterlockedIncrement(&refs_)); }
    ULONG STDMETHODCALLTYPE Release() override {
        const LONG refs = InterlockedDecrement(&refs_);
        if (refs == 0) delete this;
        return static_cast<ULONG>(refs);
    }

    HRESULT STDMETHODCALLTYPE Indicate(LONG count, IWbemClassObject** objects) override {
        if (count > 0 && objects && objects[0]) {
            VARIANT value;
            VariantInit(&value);
            if (SUCCEEDED(objects[0]->Get(L"SerialNumber", 0, &value, nullptr, nullptr)) &&
                value.vt == VT_BSTR && value.bstrVal) {
                value_ = value.bstrVal;
            }
            VariantClear(&value);
        }
        indicated_ += count;
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE SetStatus(LONG flags, HRESULT result, BSTR message,
                                        IWbemClassObject* param) override {
        status_ = result;
        (void)flags;
        (void)message;
        (void)param;
        if (event_) SetEvent(event_);
        return S_OK;
    }

    bool Wait(DWORD timeout) const { return event_ && WaitForSingleObject(event_, timeout) == WAIT_OBJECT_0; }
    HRESULT status() const { return status_; }
    LONG indicated() const { return indicated_; }
    const std::wstring& value() const { return value_; }

private:
    LONG refs_;
    HANDLE event_;
    HRESULT status_ = E_PENDING;
    LONG indicated_ = 0;
    std::wstring value_;
};

void ProbeAsync(IWbemServices* service) {
    AsyncSink* sink = new AsyncSink();
    HRESULT hr = service->ExecQueryAsync(
        const_cast<BSTR>(L"WQL"),
        const_cast<BSTR>(L"SELECT SerialNumber FROM Win32_BIOS"),
        WBEM_FLAG_SEND_STATUS, nullptr, sink);
    if (FAILED(hr)) {
        std::printf("wmi_async_state=call-error\n");
        sink->Release();
        return;
    }
    const bool completed = sink->Wait(10000);
    if (!completed) {
        service->CancelAsyncCall(sink);
        std::printf("wmi_async_state=timeout\n");
        sink->Release();
        return;
    }
    std::printf("wmi_async_state=%s\n", SUCCEEDED(sink->status()) ? "ok" : "status-error");
    std::printf("wmi_async_indicated=%ld\n", static_cast<long>(sink->indicated()));
    std::printf("wmi_async_bios_serial=%s\n", WideToUtf8(sink->value()).c_str());
    sink->Release();
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
    ProbeAsync(service);

    service->Release();
    locator->Release();
    CoUninitialize();
    return 0;
}
