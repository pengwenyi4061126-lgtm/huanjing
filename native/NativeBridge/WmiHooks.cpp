#define _WIN32_WINNT 0x0A00

#include "WmiHooks.h"

#include <windows.h>
#include <wbemidl.h>
#include <oleauto.h>

#include <cwchar>
#include <new>
#include <string>
#include <vector>

#include "ApiHooks.h"
#include "Audit.h"
#include "Identity.h"

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

namespace {

bool SameText(const std::wstring& value, const wchar_t* expected) {
    return expected && _wcsicmp(value.c_str(), expected) == 0;
}

std::wstring ToWide(const std::string& value) {
    if (value.empty()) return std::wstring();
    const int length = MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                                           nullptr, 0);
    if (length <= 0) return std::wstring();
    std::wstring result(static_cast<size_t>(length), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                        result.data(), length);
    return result;
}

std::wstring FormatUuid(const std::string& hex) {
    if (hex.size() != 32) return std::wstring();
    std::wstring upper = ToWide(hex);
    for (wchar_t& c : upper) c = static_cast<wchar_t>(towupper(c));
    return upper.substr(0, 8) + L"-" + upper.substr(8, 4) + L"-" + upper.substr(12, 4) + L"-" +
           upper.substr(16, 4) + L"-" + upper.substr(20, 12);
}

struct Rule {
    const wchar_t* cls;
    const wchar_t* prop;
    int kind;
};

// kind: 0 blank, 1 system serial, 2 system UUID, 3 processor id, 4 MAC,
//       5 volume serial, 6 hostname, 7 BIOS serial, 8 board serial, 9 disk serial.
const Rule kRules[] = {
    { L"Win32_BIOS", L"SerialNumber", 1 },
    { L"Win32_BIOS", L"SMBIOSBIOSVersion", 7 },
    { L"Win32_BIOS", L"Manufacturer", 0 },
    { L"Win32_BIOS", L"ReleaseDate", 0 },
    { L"Win32_BaseBoard", L"SerialNumber", 8 },
    { L"Win32_BaseBoard", L"Product", 0 },
    { L"Win32_BaseBoard", L"Manufacturer", 0 },
    { L"Win32_BaseBoard", L"Version", 0 },
    { L"Win32_ComputerSystemProduct", L"UUID", 2 },
    { L"Win32_ComputerSystemProduct", L"IdentifyingNumber", 1 },
    { L"Win32_ComputerSystemProduct", L"Vendor", 0 },
    { L"Win32_ComputerSystemProduct", L"Name", 0 },
    { L"Win32_ComputerSystemProduct", L"Version", 0 },
    { L"Win32_DiskDrive", L"SerialNumber", 9 },
    { L"Win32_DiskDrive", L"Model", 0 },
    { L"Win32_DiskDrive", L"FirmwareRevision", 0 },
    { L"Win32_PhysicalMedia", L"SerialNumber", 9 },
    { L"Win32_Processor", L"ProcessorId", 3 },
    { L"Win32_Processor", L"Name", 0 },
    { L"Win32_Processor", L"Manufacturer", 0 },
    { L"Win32_Processor", L"Version", 0 },
    { L"Win32_NetworkAdapter", L"MACAddress", 4 },
    { L"Win32_NetworkAdapterConfiguration", L"MACAddress", 4 },
    { L"Win32_NetworkAdapterConfiguration", L"SettingID", 0 },
    { L"Win32_NetworkAdapterConfiguration", L"Description", 0 },
    { L"MSFT_NetAdapter", L"MacAddress", 4 },
    { L"MSFT_NetAdapter", L"PermanentAddress", 4 },
    { L"MSFT_NetAdapter", L"InterfaceDescription", 0 },
    { L"MSFT_NetAdapter", L"DriverDescription", 0 },
    { L"MSFT_NetAdapter", L"PNPDeviceID", 0 },
    { L"MSFT_NetAdapter", L"DeviceID", 0 },
    { L"Win32_ComputerSystem", L"Name", 6 },
    { L"Win32_ComputerSystem", L"Manufacturer", 0 },
    { L"Win32_ComputerSystem", L"Model", 0 },
    { L"Win32_OperatingSystem", L"CSName", 6 },
    { L"Win32_OperatingSystem", L"SerialNumber", 1 },
    { L"Win32_VideoController", L"PNPDeviceID", 0 },
    { L"Win32_VideoController", L"DeviceID", 0 },
    { L"Win32_VideoController", L"Name", 0 },
    { L"Win32_VideoController", L"AdapterCompatibility", 0 },
    { L"Win32_SystemEnclosure", L"SerialNumber", 1 },
    { L"Win32_SystemEnclosure", L"SMBIOSAssetTag", 0 },
    { L"Win32_PhysicalMemory", L"SerialNumber", 0 },
    { L"Win32_PhysicalMemory", L"PartNumber", 0 },
    { L"Win32_PhysicalMemory", L"Manufacturer", 0 },
    { nullptr, L"SerialNumber", 1 },
    { nullptr, L"UUID", 2 },
    { nullptr, L"IdentifyingNumber", 1 },
    { nullptr, L"ProcessorId", 3 },
    { nullptr, L"MACAddress", 4 },
    { nullptr, L"VolumeSerialNumber", 5 },
    { nullptr, L"PNPDeviceID", 0 },
    { nullptr, L"SMBIOSAssetTag", 0 },
    { nullptr, L"AssetTag", 0 },
    { nullptr, L"PartNumber", 0 },
};

std::wstring ValueForKind(int kind) {
    const ProfileIdentity& identity = ProfileIdentity::Get();
    switch (kind) {
        case 1: return ToWide(identity.systemSerial);
        case 2: return FormatUuid(identity.systemUuid);
        case 3: return ToWide(identity.processorId);
        case 4: return ToWide(identity.mac);
        case 5: return ToWide(identity.volumeSerialHex_);
        case 6: return ToWide(identity.hostname);
        case 7: return ToWide(identity.biosSerial);
        case 8: return ToWide(identity.boardSerial);
        case 9: return ToWide(identity.diskSerial);
        default: return std::wstring();
    }
}

bool SpoofWmiValue(const std::wstring& cls, const std::wstring& prop, std::wstring& out) {
    for (const Rule& rule : kRules) {
        if (_wcsicmp(prop.c_str(), rule.prop) != 0) continue;
        if (rule.cls && _wcsicmp(cls.c_str(), rule.cls) != 0) continue;
        out.clear();
        if (!NativeEmptyReadsEnabled()) out = ValueForKind(rule.kind);
        AuditEventRateLimited("wmi.get", NativeEmptyReadsEnabled() ? "empty" : "spoofed");
        return true;
    }
    return false;
}

std::wstring GetObjectString(IWbemClassObject* object, LPCWSTR property) {
    if (!object) return std::wstring();
    VARIANT value;
    VariantInit(&value);
    std::wstring result;
    if (SUCCEEDED(object->Get(property, 0, &value, nullptr, nullptr)) && value.vt == VT_BSTR &&
        value.bstrVal) {
        result.assign(value.bstrVal, SysStringLen(value.bstrVal));
    }
    VariantClear(&value);
    return result;
}

bool IsVirtualNetworkObject(IWbemClassObject* object) {
    if (!object || !NativeCleanNetworkEnabled()) return false;
    const std::wstring cls = GetObjectString(object, L"__CLASS");
    if (_wcsicmp(cls.c_str(), L"Win32_NetworkAdapter") != 0 &&
        _wcsicmp(cls.c_str(), L"Win32_NetworkAdapterConfiguration") != 0 &&
        _wcsicmp(cls.c_str(), L"MSFT_NetAdapter") != 0) {
        return false;
    }
    static const wchar_t* const properties[] = {
        L"Name", L"Description", L"InterfaceDescription", L"DriverDescription",
        L"PNPDeviceID", L"SettingID", L"DeviceID",
    };
    for (const wchar_t* property : properties) {
        const std::wstring value = GetObjectString(object, property);
        if (NativeIsVirtualAdapterName(value.c_str())) {
            AuditEventRateLimited("wmi.network", "clean-none");
            return true;
        }
    }
    return false;
}

class RefCounted {
public:
    RefCounted() : refs_(1) {}
    virtual ~RefCounted() {}
    ULONG AddRef() { return static_cast<ULONG>(InterlockedIncrement(&refs_)); }
    ULONG Release() {
        const LONG value = InterlockedDecrement(&refs_);
        if (value == 0) delete this;
        return static_cast<ULONG>(value);
    }

private:
    LONG refs_;
};

class WmiObject : public IWbemClassObject, public RefCounted {
public:
    explicit WmiObject(IWbemClassObject* inner) : inner_(inner) {}
    ~WmiObject() override { if (inner_) inner_->Release(); }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IWbemClassObject) {
            *ppv = static_cast<IWbemClassObject*>(this);
            AddRef();
            return S_OK;
        }
        return inner_->QueryInterface(riid, ppv);
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return RefCounted::AddRef(); }
    ULONG STDMETHODCALLTYPE Release() override { return RefCounted::Release(); }

    HRESULT STDMETHODCALLTYPE GetQualifierSet(IWbemQualifierSet** ppQualSet) override {
        return inner_->GetQualifierSet(ppQualSet);
    }
    HRESULT STDMETHODCALLTYPE Get(LPCWSTR name, long flags, VARIANT* value, CIMTYPE* type,
                                  long* flavor) override {
        if (name && value) {
            std::wstring spoof;
            if (SpoofWmiValue(ClassName(), name, spoof)) {
                VariantInit(value);
                value->vt = VT_BSTR;
                value->bstrVal = SysAllocString(spoof.c_str());
                if (!value->bstrVal) return E_OUTOFMEMORY;
                if (type) *type = CIM_STRING;
                if (flavor) *flavor = 0;
                return S_OK;
            }
        }
        return inner_->Get(name, flags, value, type, flavor);
    }
    HRESULT STDMETHODCALLTYPE Put(LPCWSTR name, long flags, VARIANT* value, CIMTYPE type) override {
        return inner_->Put(name, flags, value, type);
    }
    HRESULT STDMETHODCALLTYPE Delete(LPCWSTR name) override { return inner_->Delete(name); }
    HRESULT STDMETHODCALLTYPE GetNames(LPCWSTR qualifier, long flags, VARIANT* qualifierValue,
                                       SAFEARRAY** names) override {
        return inner_->GetNames(qualifier, flags, qualifierValue, names);
    }
    HRESULT STDMETHODCALLTYPE BeginEnumeration(long flags) override {
        return inner_->BeginEnumeration(flags);
    }
    HRESULT STDMETHODCALLTYPE Next(long flags, BSTR* name, VARIANT* value, CIMTYPE* type,
                                   long* flavor) override {
        const HRESULT hr = inner_->Next(flags, name, value, type, flavor);
        if (FAILED(hr) || !name || !*name || !value) return hr;
        std::wstring spoof;
        if (!SpoofWmiValue(ClassName(), *name, spoof)) return hr;
        BSTR replacement = SysAllocString(spoof.c_str());
        if (!replacement) return E_OUTOFMEMORY;
        VariantClear(value);
        VariantInit(value);
        value->vt = VT_BSTR;
        value->bstrVal = replacement;
        if (type) *type = CIM_STRING;
        if (flavor) *flavor = 0;
        return hr;
    }
    HRESULT STDMETHODCALLTYPE EndEnumeration() override { return inner_->EndEnumeration(); }
    HRESULT STDMETHODCALLTYPE GetPropertyQualifierSet(LPCWSTR property,
                                                      IWbemQualifierSet** qualifierSet) override {
        return inner_->GetPropertyQualifierSet(property, qualifierSet);
    }
    HRESULT STDMETHODCALLTYPE Clone(IWbemClassObject** copy) override {
        if (!copy) return E_POINTER;
        HRESULT hr = inner_->Clone(copy);
        if (SUCCEEDED(hr) && *copy) {
            WmiObject* wrapper = new (std::nothrow) WmiObject(*copy);
            if (!wrapper) { (*copy)->Release(); *copy = nullptr; return E_OUTOFMEMORY; }
            *copy = wrapper;
        }
        return hr;
    }
    HRESULT STDMETHODCALLTYPE GetObjectText(long flags, BSTR* text) override {
        return inner_->GetObjectText(flags, text);
    }
    HRESULT STDMETHODCALLTYPE SpawnDerivedClass(long flags, IWbemClassObject** newClass) override {
        return inner_->SpawnDerivedClass(flags, newClass);
    }
    HRESULT STDMETHODCALLTYPE SpawnInstance(long flags, IWbemClassObject** newInstance) override {
        return inner_->SpawnInstance(flags, newInstance);
    }
    HRESULT STDMETHODCALLTYPE CompareTo(long flags, IWbemClassObject* compareTo) override {
        return inner_->CompareTo(flags, compareTo);
    }
    HRESULT STDMETHODCALLTYPE GetPropertyOrigin(LPCWSTR name, BSTR* className) override {
        return inner_->GetPropertyOrigin(name, className);
    }
    HRESULT STDMETHODCALLTYPE InheritsFrom(LPCWSTR ancestor) override {
        return inner_->InheritsFrom(ancestor);
    }
    HRESULT STDMETHODCALLTYPE GetMethod(LPCWSTR name, long flags, IWbemClassObject** inSignature,
                                        IWbemClassObject** outSignature) override {
        return inner_->GetMethod(name, flags, inSignature, outSignature);
    }
    HRESULT STDMETHODCALLTYPE PutMethod(LPCWSTR name, long flags, IWbemClassObject* inSignature,
                                        IWbemClassObject* outSignature) override {
        return inner_->PutMethod(name, flags, inSignature, outSignature);
    }
    HRESULT STDMETHODCALLTYPE DeleteMethod(LPCWSTR name) override { return inner_->DeleteMethod(name); }
    HRESULT STDMETHODCALLTYPE BeginMethodEnumeration(long flags) override {
        return inner_->BeginMethodEnumeration(flags);
    }
    HRESULT STDMETHODCALLTYPE NextMethod(long flags, BSTR* name, IWbemClassObject** inSignature,
                                         IWbemClassObject** outSignature) override {
        return inner_->NextMethod(flags, name, inSignature, outSignature);
    }
    HRESULT STDMETHODCALLTYPE EndMethodEnumeration() override { return inner_->EndMethodEnumeration(); }
    HRESULT STDMETHODCALLTYPE GetMethodQualifierSet(LPCWSTR method,
                                                    IWbemQualifierSet** qualifierSet) override {
        return inner_->GetMethodQualifierSet(method, qualifierSet);
    }
    HRESULT STDMETHODCALLTYPE GetMethodOrigin(LPCWSTR method, BSTR* className) override {
        return inner_->GetMethodOrigin(method, className);
    }

private:
    std::wstring ClassName() {
        if (classLoaded_) return className_;
        classLoaded_ = true;
        VARIANT value;
        VariantInit(&value);
        if (SUCCEEDED(inner_->Get(L"__CLASS", 0, &value, nullptr, nullptr)) && value.vt == VT_BSTR &&
            value.bstrVal) {
            className_.assign(value.bstrVal, SysStringLen(value.bstrVal));
        }
        VariantClear(&value);
        return className_;
    }

    IWbemClassObject* inner_;
    std::wstring className_;
    bool classLoaded_ = false;
};

class WmiSink : public IWbemObjectSink, public RefCounted {
public:
    explicit WmiSink(IWbemObjectSink* inner) : inner_(inner) {
        if (inner_) inner_->AddRef();
        AuditEventRateLimited("wmi.sink", "wrapped");
    }
    ~WmiSink() override { if (inner_) inner_->Release(); }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IWbemObjectSink) {
            *ppv = static_cast<IWbemObjectSink*>(this);
            AddRef();
            return S_OK;
        }
        return inner_->QueryInterface(riid, ppv);
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return RefCounted::AddRef(); }
    ULONG STDMETHODCALLTYPE Release() override { return RefCounted::Release(); }

    HRESULT STDMETHODCALLTYPE Indicate(LONG count, IWbemClassObject** objects) override {
        if (!inner_ || count <= 0 || !objects) return inner_ ? inner_->Indicate(count, objects) : E_POINTER;
        AuditEventRateLimited("wmi.sink", "indicate", nullptr,
                              static_cast<unsigned long long>(count), true);
        std::vector<IWbemClassObject*> forwarded;
        std::vector<WmiObject*> wrappers;
        forwarded.reserve(static_cast<size_t>(count));
        wrappers.reserve(static_cast<size_t>(count));
        for (LONG index = 0; index < count; ++index) {
            IWbemClassObject* raw = objects[index];
            if (!raw || IsVirtualNetworkObject(raw)) continue;
            raw->AddRef();
            WmiObject* wrapper = new (std::nothrow) WmiObject(raw);
            if (!wrapper) {
                raw->Release();
                for (WmiObject* previous : wrappers) previous->Release();
                return E_OUTOFMEMORY;
            }
            wrappers.push_back(wrapper);
            forwarded.push_back(wrapper);
        }
        HRESULT hr = S_OK;
        if (!forwarded.empty()) {
            hr = inner_->Indicate(static_cast<LONG>(forwarded.size()), forwarded.data());
        }
        for (WmiObject* wrapper : wrappers) wrapper->Release();
        AuditEventRateLimited("wmi.sink", "async-filtered", nullptr,
                              static_cast<unsigned long long>(forwarded.size()), true);
        return hr;
    }

    HRESULT STDMETHODCALLTYPE SetStatus(LONG flags, HRESULT result, BSTR message,
                                        IWbemClassObject* param) override {
        return inner_ ? inner_->SetStatus(flags, result, message, param) : E_POINTER;
    }

private:
    IWbemObjectSink* inner_;
};

WmiSink* WrapSink(IWbemObjectSink* sink) {
    if (!sink) return nullptr;
    return new (std::nothrow) WmiSink(sink);
}

class WmiEnum : public IEnumWbemClassObject, public RefCounted {
public:
    explicit WmiEnum(IEnumWbemClassObject* inner) : inner_(inner) {}
    ~WmiEnum() override { if (inner_) inner_->Release(); }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IEnumWbemClassObject) {
            *ppv = static_cast<IEnumWbemClassObject*>(this);
            AddRef();
            return S_OK;
        }
        return inner_->QueryInterface(riid, ppv);
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return RefCounted::AddRef(); }
    ULONG STDMETHODCALLTYPE Release() override { return RefCounted::Release(); }

    HRESULT STDMETHODCALLTYPE Reset() override { return inner_->Reset(); }
    HRESULT STDMETHODCALLTYPE Next(long timeout, ULONG count, IWbemClassObject** objects,
                                   ULONG* returned) override {
        if (!objects || !returned) return inner_->Next(timeout, count, objects, returned);
        for (int attempt = 0; attempt < 8; ++attempt) {
            ULONG fetched = 0;
            const HRESULT hr = inner_->Next(timeout, count, objects, &fetched);
            if (FAILED(hr) || fetched == 0) {
                *returned = 0;
                return hr;
            }
            ULONG kept = 0;
            for (ULONG i = 0; i < fetched; ++i) {
                IWbemClassObject* raw = objects[i];
                if (!raw) continue;
                if (IsVirtualNetworkObject(raw)) {
                    raw->Release();
                    continue;
                }
                WmiObject* wrapper = new (std::nothrow) WmiObject(raw);
                if (!wrapper) {
                    raw->Release();
                    for (ULONG j = i + 1; j < fetched; ++j) {
                        if (objects[j]) objects[j]->Release();
                    }
                    *returned = 0;
                    return E_OUTOFMEMORY;
                }
                objects[kept++] = wrapper;
            }
            *returned = kept;
            if (kept > 0) return hr;
            if (hr == WBEM_S_FALSE) return S_FALSE;
            if (hr == WBEM_S_TIMEDOUT) return hr;
        }
        *returned = 0;
        return S_FALSE;
    }
    HRESULT STDMETHODCALLTYPE NextAsync(ULONG count, IWbemObjectSink* sink) override {
        WmiSink* wrapped = WrapSink(sink);
        if (sink && !wrapped) return E_OUTOFMEMORY;
        HRESULT hr = inner_->NextAsync(count, wrapped ? static_cast<IWbemObjectSink*>(wrapped) : sink);
        if (wrapped) wrapped->Release();
        AuditEventRateLimited("wmi.async", "NextAsync", nullptr,
                              static_cast<unsigned long long>(static_cast<unsigned long>(hr)), true);
        return hr;
    }
    HRESULT STDMETHODCALLTYPE Clone(IEnumWbemClassObject** enumerator) override {
        if (!enumerator) return E_POINTER;
        HRESULT hr = inner_->Clone(enumerator);
        if (SUCCEEDED(hr) && *enumerator) {
            WmiEnum* wrapper = new (std::nothrow) WmiEnum(*enumerator);
            if (!wrapper) { (*enumerator)->Release(); *enumerator = nullptr; return E_OUTOFMEMORY; }
            *enumerator = wrapper;
        }
        return hr;
    }
    HRESULT STDMETHODCALLTYPE Skip(long timeout, ULONG count) override {
        return inner_->Skip(timeout, count);
    }

private:
    IEnumWbemClassObject* inner_;
};

class WmiServices : public IWbemServices, public RefCounted {
public:
    explicit WmiServices(IWbemServices* inner) : inner_(inner) {}
    ~WmiServices() override { if (inner_) inner_->Release(); }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IWbemServices) {
            *ppv = static_cast<IWbemServices*>(this);
            AddRef();
            return S_OK;
        }
        return inner_->QueryInterface(riid, ppv);
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return RefCounted::AddRef(); }
    ULONG STDMETHODCALLTYPE Release() override { return RefCounted::Release(); }

    HRESULT STDMETHODCALLTYPE OpenNamespace(const BSTR name, long flags, IWbemContext* context,
                                            IWbemServices** workingNamespace,
                                            IWbemCallResult** result) override {
        HRESULT hr = inner_->OpenNamespace(name, flags, context, workingNamespace, result);
        if (SUCCEEDED(hr) && workingNamespace && *workingNamespace) {
            *workingNamespace = new (std::nothrow) WmiServices(*workingNamespace);
        }
        return hr;
    }
    HRESULT STDMETHODCALLTYPE CancelAsyncCall(IWbemObjectSink* sink) override {
        return inner_->CancelAsyncCall(sink);
    }
    HRESULT STDMETHODCALLTYPE QueryObjectSink(long flags, IWbemObjectSink** handler) override {
        return inner_->QueryObjectSink(flags, handler);
    }
    HRESULT STDMETHODCALLTYPE GetObject(const BSTR path, long flags, IWbemContext* context,
                                        IWbemClassObject** object, IWbemCallResult** result) override {
        HRESULT hr = inner_->GetObject(path, flags, context, object, result);
        if (SUCCEEDED(hr) && object && *object) {
            *object = new (std::nothrow) WmiObject(*object);
        }
        return hr;
    }
    HRESULT STDMETHODCALLTYPE GetObjectAsync(const BSTR path, long flags, IWbemContext* context,
                                             IWbemObjectSink* handler) override {
        WmiSink* wrapped = WrapSink(handler);
        if (handler && !wrapped) return E_OUTOFMEMORY;
        HRESULT hr = inner_->GetObjectAsync(path, flags, context,
                                            wrapped ? static_cast<IWbemObjectSink*>(wrapped) : handler);
        if (wrapped) wrapped->Release();
        AuditEventRateLimited("wmi.async", "GetObjectAsync", nullptr,
                              static_cast<unsigned long long>(static_cast<unsigned long>(hr)), true);
        return hr;
    }
    HRESULT STDMETHODCALLTYPE PutClass(IWbemClassObject* object, long flags, IWbemContext* context,
                                       IWbemCallResult** result) override {
        return inner_->PutClass(object, flags, context, result);
    }
    HRESULT STDMETHODCALLTYPE PutClassAsync(IWbemClassObject* object, long flags, IWbemContext* context,
                                            IWbemObjectSink* handler) override {
        WmiSink* wrapped = WrapSink(handler);
        if (handler && !wrapped) return E_OUTOFMEMORY;
        HRESULT hr = inner_->PutClassAsync(object, flags, context,
                                           wrapped ? static_cast<IWbemObjectSink*>(wrapped) : handler);
        if (wrapped) wrapped->Release();
        AuditEventRateLimited("wmi.async", "PutClassAsync", nullptr,
                              static_cast<unsigned long long>(static_cast<unsigned long>(hr)), true);
        return hr;
    }
    HRESULT STDMETHODCALLTYPE DeleteClass(const BSTR name, long flags, IWbemContext* context,
                                          IWbemCallResult** result) override {
        return inner_->DeleteClass(name, flags, context, result);
    }
    HRESULT STDMETHODCALLTYPE DeleteClassAsync(const BSTR name, long flags, IWbemContext* context,
                                               IWbemObjectSink* handler) override {
        WmiSink* wrapped = WrapSink(handler);
        if (handler && !wrapped) return E_OUTOFMEMORY;
        HRESULT hr = inner_->DeleteClassAsync(name, flags, context,
                                              wrapped ? static_cast<IWbemObjectSink*>(wrapped) : handler);
        if (wrapped) wrapped->Release();
        AuditEventRateLimited("wmi.async", "DeleteClassAsync", nullptr,
                              static_cast<unsigned long long>(static_cast<unsigned long>(hr)), true);
        return hr;
    }
    HRESULT STDMETHODCALLTYPE CreateClassEnum(const BSTR superclass, long flags, IWbemContext* context,
                                              IEnumWbemClassObject** enumerator) override {
        HRESULT hr = inner_->CreateClassEnum(superclass, flags, context, enumerator);
        if (SUCCEEDED(hr) && enumerator && *enumerator) {
            *enumerator = new (std::nothrow) WmiEnum(*enumerator);
        }
        return hr;
    }
    HRESULT STDMETHODCALLTYPE CreateClassEnumAsync(const BSTR superclass, long flags,
                                                   IWbemContext* context, IWbemObjectSink* handler) override {
        WmiSink* wrapped = WrapSink(handler);
        if (handler && !wrapped) return E_OUTOFMEMORY;
        HRESULT hr = inner_->CreateClassEnumAsync(superclass, flags, context,
                                                  wrapped ? static_cast<IWbemObjectSink*>(wrapped) : handler);
        if (wrapped) wrapped->Release();
        AuditEventRateLimited("wmi.async", "CreateClassEnumAsync", nullptr,
                              static_cast<unsigned long long>(static_cast<unsigned long>(hr)), true);
        return hr;
    }
    HRESULT STDMETHODCALLTYPE PutInstance(IWbemClassObject* instance, long flags, IWbemContext* context,
                                          IWbemCallResult** result) override {
        return inner_->PutInstance(instance, flags, context, result);
    }
    HRESULT STDMETHODCALLTYPE PutInstanceAsync(IWbemClassObject* instance, long flags,
                                               IWbemContext* context, IWbemObjectSink* handler) override {
        WmiSink* wrapped = WrapSink(handler);
        if (handler && !wrapped) return E_OUTOFMEMORY;
        HRESULT hr = inner_->PutInstanceAsync(instance, flags, context,
                                              wrapped ? static_cast<IWbemObjectSink*>(wrapped) : handler);
        if (wrapped) wrapped->Release();
        AuditEventRateLimited("wmi.async", "PutInstanceAsync", nullptr,
                              static_cast<unsigned long long>(static_cast<unsigned long>(hr)), true);
        return hr;
    }
    HRESULT STDMETHODCALLTYPE DeleteInstance(const BSTR path, long flags, IWbemContext* context,
                                             IWbemCallResult** result) override {
        return inner_->DeleteInstance(path, flags, context, result);
    }
    HRESULT STDMETHODCALLTYPE DeleteInstanceAsync(const BSTR path, long flags, IWbemContext* context,
                                                  IWbemObjectSink* handler) override {
        WmiSink* wrapped = WrapSink(handler);
        if (handler && !wrapped) return E_OUTOFMEMORY;
        HRESULT hr = inner_->DeleteInstanceAsync(path, flags, context,
                                                 wrapped ? static_cast<IWbemObjectSink*>(wrapped) : handler);
        if (wrapped) wrapped->Release();
        AuditEventRateLimited("wmi.async", "DeleteInstanceAsync", nullptr,
                              static_cast<unsigned long long>(static_cast<unsigned long>(hr)), true);
        return hr;
    }
    HRESULT STDMETHODCALLTYPE CreateInstanceEnum(const BSTR filter, long flags, IWbemContext* context,
                                                 IEnumWbemClassObject** enumerator) override {
        HRESULT hr = inner_->CreateInstanceEnum(filter, flags, context, enumerator);
        if (SUCCEEDED(hr) && enumerator && *enumerator) {
            *enumerator = new (std::nothrow) WmiEnum(*enumerator);
        }
        return hr;
    }
    HRESULT STDMETHODCALLTYPE CreateInstanceEnumAsync(const BSTR filter, long flags,
                                                      IWbemContext* context, IWbemObjectSink* handler) override {
        WmiSink* wrapped = WrapSink(handler);
        if (handler && !wrapped) return E_OUTOFMEMORY;
        HRESULT hr = inner_->CreateInstanceEnumAsync(filter, flags, context,
                                                     wrapped ? static_cast<IWbemObjectSink*>(wrapped) : handler);
        if (wrapped) wrapped->Release();
        AuditEventRateLimited("wmi.async", "CreateInstanceEnumAsync", nullptr,
                              static_cast<unsigned long long>(static_cast<unsigned long>(hr)), true);
        return hr;
    }
    HRESULT STDMETHODCALLTYPE ExecQuery(const BSTR language, const BSTR query, long flags,
                                        IWbemContext* context, IEnumWbemClassObject** enumerator) override {
        HRESULT hr = inner_->ExecQuery(language, query, flags, context, enumerator);
        if (SUCCEEDED(hr) && enumerator && *enumerator) {
            *enumerator = new (std::nothrow) WmiEnum(*enumerator);
        }
        return hr;
    }
    HRESULT STDMETHODCALLTYPE ExecQueryAsync(const BSTR language, const BSTR query, long flags,
                                             IWbemContext* context, IWbemObjectSink* handler) override {
        WmiSink* wrapped = WrapSink(handler);
        if (handler && !wrapped) return E_OUTOFMEMORY;
        HRESULT hr = inner_->ExecQueryAsync(language, query, flags, context,
                                            wrapped ? static_cast<IWbemObjectSink*>(wrapped) : handler);
        if (wrapped) wrapped->Release();
        AuditEventRateLimited("wmi.async", "ExecQueryAsync", nullptr,
                              static_cast<unsigned long long>(static_cast<unsigned long>(hr)), true);
        return hr;
    }
    HRESULT STDMETHODCALLTYPE ExecNotificationQuery(const BSTR language, const BSTR query, long flags,
                                                    IWbemContext* context,
                                                    IEnumWbemClassObject** enumerator) override {
        HRESULT hr = inner_->ExecNotificationQuery(language, query, flags, context, enumerator);
        if (SUCCEEDED(hr) && enumerator && *enumerator) {
            *enumerator = new (std::nothrow) WmiEnum(*enumerator);
        }
        return hr;
    }
    HRESULT STDMETHODCALLTYPE ExecNotificationQueryAsync(const BSTR language, const BSTR query,
                                                         long flags, IWbemContext* context,
                                                         IWbemObjectSink* handler) override {
        WmiSink* wrapped = WrapSink(handler);
        if (handler && !wrapped) return E_OUTOFMEMORY;
        HRESULT hr = inner_->ExecNotificationQueryAsync(language, query, flags, context,
                                                        wrapped ? static_cast<IWbemObjectSink*>(wrapped) : handler);
        if (wrapped) wrapped->Release();
        AuditEventRateLimited("wmi.async", "ExecNotificationQueryAsync", nullptr,
                              static_cast<unsigned long long>(static_cast<unsigned long>(hr)), true);
        return hr;
    }
    HRESULT STDMETHODCALLTYPE ExecMethod(const BSTR path, const BSTR method, long flags,
                                         IWbemContext* context, IWbemClassObject* inParams,
                                         IWbemClassObject** outParams, IWbemCallResult** result) override {
        HRESULT hr = inner_->ExecMethod(path, method, flags, context, inParams, outParams, result);
        if (SUCCEEDED(hr) && outParams && *outParams) {
            *outParams = new (std::nothrow) WmiObject(*outParams);
        }
        return hr;
    }
    HRESULT STDMETHODCALLTYPE ExecMethodAsync(const BSTR path, const BSTR method, long flags,
                                              IWbemContext* context, IWbemClassObject* inParams,
                                              IWbemObjectSink* handler) override {
        WmiSink* wrapped = WrapSink(handler);
        if (handler && !wrapped) return E_OUTOFMEMORY;
        HRESULT hr = inner_->ExecMethodAsync(path, method, flags, context, inParams,
                                             wrapped ? static_cast<IWbemObjectSink*>(wrapped) : handler);
        if (wrapped) wrapped->Release();
        AuditEventRateLimited("wmi.async", "ExecMethodAsync", nullptr,
                              static_cast<unsigned long long>(static_cast<unsigned long>(hr)), true);
        return hr;
    }

private:
    IWbemServices* inner_;
};

class WmiLocator : public IWbemLocator, public RefCounted {
public:
    explicit WmiLocator(IWbemLocator* inner) : inner_(inner) {}
    ~WmiLocator() override { if (inner_) inner_->Release(); }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IWbemLocator) {
            *ppv = static_cast<IWbemLocator*>(this);
            AddRef();
            return S_OK;
        }
        return inner_->QueryInterface(riid, ppv);
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return RefCounted::AddRef(); }
    ULONG STDMETHODCALLTYPE Release() override { return RefCounted::Release(); }

    HRESULT STDMETHODCALLTYPE ConnectServer(const BSTR resource, const BSTR user, const BSTR password,
                                            const BSTR locale, long securityFlags, const BSTR authority,
                                            IWbemContext* context, IWbemServices** services) override {
        HRESULT hr = inner_->ConnectServer(resource, user, password, locale, securityFlags, authority,
                                           context, services);
        if (SUCCEEDED(hr) && services && *services) {
            WmiServices* wrapper = new (std::nothrow) WmiServices(*services);
            if (!wrapper) { (*services)->Release(); *services = nullptr; return E_OUTOFMEMORY; }
            *services = wrapper;
        }
        return hr;
    }

private:
    IWbemLocator* inner_;
};

class WmiFactory : public IClassFactory, public RefCounted {
public:
    explicit WmiFactory(IClassFactory* inner) : inner_(inner) {}
    ~WmiFactory() override { if (inner_) inner_->Release(); }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IClassFactory) {
            *ppv = static_cast<IClassFactory*>(this);
            AddRef();
            return S_OK;
        }
        return inner_->QueryInterface(riid, ppv);
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return RefCounted::AddRef(); }
    ULONG STDMETHODCALLTYPE Release() override { return RefCounted::Release(); }

    HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown* outer, REFIID riid, void** ppv) override {
        HRESULT hr = inner_->CreateInstance(outer, riid, ppv);
        if (SUCCEEDED(hr) && ppv && *ppv) WrapLocator(riid, ppv);
        return hr;
    }
    HRESULT STDMETHODCALLTYPE LockServer(BOOL lock) override { return inner_->LockServer(lock); }

private:
    static void WrapLocator(REFIID riid, void** ppv) {
        if (riid == IID_IWbemLocator) {
            WmiLocator* wrapper = new (std::nothrow) WmiLocator(static_cast<IWbemLocator*>(*ppv));
            if (wrapper) *ppv = static_cast<IWbemLocator*>(wrapper);
            return;
        }
        if (riid == IID_IUnknown) {
            IUnknown* raw = static_cast<IUnknown*>(*ppv);
            IWbemLocator* locator = nullptr;
            if (SUCCEEDED(raw->QueryInterface(IID_IWbemLocator, reinterpret_cast<void**>(&locator))) && locator) {
                WmiLocator* wrapper = new (std::nothrow) WmiLocator(locator);
                if (wrapper) {
                    raw->Release();
                    *ppv = static_cast<IUnknown*>(static_cast<IWbemLocator*>(wrapper));
                } else {
                    locator->Release();
                }
            }
        }
    }

    IClassFactory* inner_;
};

typedef HRESULT (WINAPI* PFN_CoCreateInstance)(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);
typedef HRESULT (WINAPI* PFN_CoCreateInstanceEx)(REFCLSID, LPUNKNOWN, DWORD, COSERVERINFO*, DWORD, MULTI_QI*);
typedef HRESULT (WINAPI* PFN_CoGetClassObject)(REFCLSID, DWORD, LPVOID, REFIID, LPVOID*);

PFN_CoCreateInstance g_origCoCreateInstance = nullptr;
PFN_CoCreateInstanceEx g_origCoCreateInstanceEx = nullptr;
PFN_CoGetClassObject g_origCoGetClassObject = nullptr;

void WrapLocatorResult(REFIID riid, void** ppv) {
    if (!ppv || !*ppv) return;
    if (riid == IID_IWbemLocator) {
        WmiLocator* wrapper = new (std::nothrow) WmiLocator(static_cast<IWbemLocator*>(*ppv));
        if (wrapper) *ppv = static_cast<IWbemLocator*>(wrapper);
        return;
    }
    if (riid == IID_IUnknown) {
        IUnknown* raw = static_cast<IUnknown*>(*ppv);
        IWbemLocator* locator = nullptr;
        if (SUCCEEDED(raw->QueryInterface(IID_IWbemLocator, reinterpret_cast<void**>(&locator))) && locator) {
            WmiLocator* wrapper = new (std::nothrow) WmiLocator(locator);
            if (wrapper) {
                raw->Release();
                *ppv = static_cast<IUnknown*>(static_cast<IWbemLocator*>(wrapper));
            } else {
                locator->Release();
            }
        }
    }
}

HRESULT WINAPI HookCoCreateInstance(REFCLSID clsid, LPUNKNOWN outer, DWORD context, REFIID riid,
                                    LPVOID* ppv) {
    HRESULT hr = g_origCoCreateInstance ? g_origCoCreateInstance(clsid, outer, context, riid, ppv)
                                        : E_NOTIMPL;
    if (SUCCEEDED(hr) && ppv && IsEqualCLSID(clsid, CLSID_WbemLocator)) {
        WrapLocatorResult(riid, ppv);
        AuditEventRateLimited("wmi.install", "wrapped");
    }
    return hr;
}

HRESULT WINAPI HookCoCreateInstanceEx(REFCLSID clsid, LPUNKNOWN outer, DWORD context,
                                      COSERVERINFO* server, DWORD count, MULTI_QI* results) {
    HRESULT hr = g_origCoCreateInstanceEx
        ? g_origCoCreateInstanceEx(clsid, outer, context, server, count, results)
        : E_NOTIMPL;
    if (SUCCEEDED(hr) && results && IsEqualCLSID(clsid, CLSID_WbemLocator)) {
        for (DWORD i = 0; i < count; ++i) {
            if (results[i].hr == S_OK && results[i].pItf && results[i].pIID) {
                void* pointer = results[i].pItf;
                WrapLocatorResult(*results[i].pIID, &pointer);
                results[i].pItf = static_cast<IUnknown*>(pointer);
            }
        }
        AuditEventRateLimited("wmi.install", "wrapped-ex");
    }
    return hr;
}

HRESULT WINAPI HookCoGetClassObject(REFCLSID clsid, DWORD context, LPVOID reserved, REFIID riid,
                                    LPVOID* ppv) {
    HRESULT hr = g_origCoGetClassObject ? g_origCoGetClassObject(clsid, context, reserved, riid, ppv)
                                        : E_NOTIMPL;
    if (SUCCEEDED(hr) && ppv && *ppv && IsEqualCLSID(clsid, CLSID_WbemLocator)) {
        if (riid == IID_IClassFactory) {
            WmiFactory* wrapper = new (std::nothrow) WmiFactory(static_cast<IClassFactory*>(*ppv));
            if (wrapper) *ppv = static_cast<IClassFactory*>(wrapper);
        } else if (riid == IID_IUnknown) {
            IUnknown* raw = static_cast<IUnknown*>(*ppv);
            IClassFactory* factory = nullptr;
            if (SUCCEEDED(raw->QueryInterface(IID_IClassFactory, reinterpret_cast<void**>(&factory))) && factory) {
                WmiFactory* wrapper = new (std::nothrow) WmiFactory(factory);
                if (wrapper) {
                    raw->Release();
                    *ppv = static_cast<IUnknown*>(static_cast<IClassFactory*>(wrapper));
                } else {
                    factory->Release();
                }
            }
        }
        AuditEventRateLimited("wmi.install", "wrapped-factory");
    }
    return hr;
}

}  // namespace

void InstallWmiHooks() {
    InstallHookInlinePrimary("ole32.dll", "CoCreateInstance", reinterpret_cast<void*>(&HookCoCreateInstance),
                             reinterpret_cast<void**>(&g_origCoCreateInstance));
    InstallHookInlinePrimary("ole32.dll", "CoCreateInstanceEx", reinterpret_cast<void*>(&HookCoCreateInstanceEx),
                             reinterpret_cast<void**>(&g_origCoCreateInstanceEx));
    InstallHookInlinePrimary("ole32.dll", "CoGetClassObject", reinterpret_cast<void*>(&HookCoGetClassObject),
                             reinterpret_cast<void**>(&g_origCoGetClassObject));
}
