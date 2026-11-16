#include "GpuHooks.h"

#include <windows.h>
#include <dxgi.h>

#include <cstdio>
#include <string>

#include "ApiHooks.h"
#include "Audit.h"
#include "Identity.h"

namespace {

// Local IID_IDXGIFactory1 to avoid a link-time dependency on dxgi.lib.
const GUID kIidIdxgiFactory1 = {
    0x770aae78, 0xf26f, 0x4dba, {0xa8, 0x29, 0x25, 0x3c, 0x83, 0xd1, 0xb3, 0x87}};

typedef HRESULT(WINAPI* PFN_CreateDXGIFactory1)(REFIID riid, void** factory);
typedef HRESULT(STDMETHODCALLTYPE* PFN_GetDesc)(IDXGIAdapter* adapter, DXGI_ADAPTER_DESC* desc);
typedef HRESULT(STDMETHODCALLTYPE* PFN_GetDesc1)(IDXGIAdapter1* adapter, DXGI_ADAPTER_DESC1* desc);

PFN_GetDesc g_origGetDesc = nullptr;
PFN_GetDesc1 g_origGetDesc1 = nullptr;

std::wstring Utf8ToWideLocal(const std::string& value) {
    if (value.empty()) return std::wstring();
    const int length = MultiByteToWideChar(CP_UTF8, 0, value.c_str(),
                                           static_cast<int>(value.size()), nullptr, 0);
    if (length <= 0) return std::wstring();
    std::wstring result(static_cast<size_t>(length), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()),
                        &result[0], length);
    return result;
}

void ApplyIdentity(DXGI_ADAPTER_DESC* desc) {
    if (!desc) return;
    const ProfileIdentity& identity = ProfileIdentity::Get();
    const std::wstring name = Utf8ToWideLocal(identity.gpuName);
    wcsncpy_s(desc->Description, _countof(desc->Description), name.c_str(), _TRUNCATE);
    desc->DedicatedVideoMemory = identity.gpuMemoryMb * 1024ULL * 1024ULL;
    desc->SharedSystemMemory = identity.memoryTotalMb * 1024ULL * 1024ULL / 2;
    unsigned int vendor = 0;
    unsigned int device = 0;
    unsigned int subsys = 0;
    unsigned int revision = 0;
    const std::wstring pci = Utf8ToWideLocal(identity.gpuPciId);
    if (swscanf_s(pci.c_str(), L"PCI\\VEN_%x&DEV_%x&SUBSYS_%x&REV_%x",
                  &vendor, &device, &subsys, &revision) == 4) {
        desc->VendorId = vendor;
        desc->DeviceId = device;
        desc->SubSysId = subsys;
        desc->Revision = revision;
    }
    AuditEventRateLimited("gpu.getdesc", "patched");
}

void ApplyIdentity1(DXGI_ADAPTER_DESC1* desc) {
    if (!desc) return;
    // Reuse the same profile fields for the IDXGIAdapter1 surface.
    const ProfileIdentity& identity = ProfileIdentity::Get();
    const std::wstring name = Utf8ToWideLocal(identity.gpuName);
    wcsncpy_s(desc->Description, _countof(desc->Description), name.c_str(), _TRUNCATE);
    desc->DedicatedVideoMemory = identity.gpuMemoryMb * 1024ULL * 1024ULL;
    desc->SharedSystemMemory = identity.memoryTotalMb * 1024ULL * 1024ULL / 2;
    unsigned int vendor = 0;
    unsigned int device = 0;
    unsigned int subsys = 0;
    unsigned int revision = 0;
    const std::wstring pci = Utf8ToWideLocal(identity.gpuPciId);
    if (swscanf_s(pci.c_str(), L"PCI\\VEN_%x&DEV_%x&SUBSYS_%x&REV_%x",
                  &vendor, &device, &subsys, &revision) == 4) {
        desc->VendorId = vendor;
        desc->DeviceId = device;
        desc->SubSysId = subsys;
        desc->Revision = revision;
    }
    desc->Flags = 0;
    AuditEventRateLimited("gpu.getdesc1", "patched");
}

HRESULT STDMETHODCALLTYPE HookGetDesc(IDXGIAdapter* adapter, DXGI_ADAPTER_DESC* desc) {
    const HRESULT hr = g_origGetDesc ? g_origGetDesc(adapter, desc) : E_FAIL;
    if (SUCCEEDED(hr) && desc) ApplyIdentity(desc);
    return hr;
}

HRESULT STDMETHODCALLTYPE HookGetDesc1(IDXGIAdapter1* adapter, DXGI_ADAPTER_DESC1* desc) {
    const HRESULT hr = g_origGetDesc1 ? g_origGetDesc1(adapter, desc) : E_FAIL;
    if (SUCCEEDED(hr) && desc) ApplyIdentity1(desc);
    return hr;
}

bool PatchSlot(void** vtable, size_t index, void* hook, void** original) {
    if (!vtable || !original) return false;
    void** slot = &vtable[index];
    DWORD oldProtect = 0;
    if (!VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &oldProtect)) return false;
    *original = *slot;
    *slot = hook;
    DWORD ignored = 0;
    VirtualProtect(slot, sizeof(void*), oldProtect, &ignored);
    FlushInstructionCache(GetCurrentProcess(), slot, sizeof(void*));
    return true;
}

}  // namespace

void InstallGpuHooks() {
    if (!NativeHardwareHooksEnabled()) {
        AuditEvent("gpu.hook", "skipped", "hardware-disabled");
        return;
    }

    HMODULE dxgi = GetModuleHandleW(L"dxgi.dll");
    if (!dxgi) dxgi = LoadLibraryW(L"dxgi.dll");
    if (!dxgi) {
        AuditEvent("gpu.hook", "skipped", "dxgi-missing");
        return;
    }
    auto create = reinterpret_cast<PFN_CreateDXGIFactory1>(
        GetProcAddress(dxgi, "CreateDXGIFactory1"));
    if (!create) {
        AuditEvent("gpu.hook", "skipped", "create-missing");
        return;
    }

    IDXGIFactory1* factory = nullptr;
    HRESULT hr = create(kIidIdxgiFactory1, reinterpret_cast<void**>(&factory));
    if (FAILED(hr) || !factory) {
        AuditEvent("gpu.hook", "skipped", "factory-failed");
        return;
    }

    IDXGIAdapter1* adapter = nullptr;
    hr = factory->EnumAdapters1(0, &adapter);
    if (FAILED(hr) || !adapter) {
        factory->Release();
        AuditEvent("gpu.hook", "skipped", "adapter-failed");
        return;
    }

    void** vtable = *reinterpret_cast<void***>(adapter);
    const bool getDesc = PatchSlot(vtable, 8,
                                   reinterpret_cast<void*>(&HookGetDesc),
                                   reinterpret_cast<void**>(&g_origGetDesc));
    const bool getDesc1 = PatchSlot(vtable, 10,
                                    reinterpret_cast<void*>(&HookGetDesc1),
                                    reinterpret_cast<void**>(&g_origGetDesc1));
    adapter->Release();
    factory->Release();

    AuditEvent("gpu.hook", (getDesc || getDesc1) ? "installed" : "failed",
               getDesc1 ? "dxgi-getdesc1" : "dxgi-getdesc");
}
