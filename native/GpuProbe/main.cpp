#include <windows.h>
#include <dxgi.h>
#include <cstdio>

// Local copy of IID_IDXGIFactory1 so the probe can load dxgi.dll dynamically
// without linking dxgi.lib.
static const GUID kIidIdxgiFactory1 = {
    0x770aae78, 0xf26f, 0x4dba, {0xa8, 0x29, 0x25, 0x3c, 0x83, 0xd1, 0xb3, 0x87}};

typedef HRESULT(WINAPI* PFN_CreateDXGIFactory1)(REFIID riid, void** factory);

int wmain() {
    const HRESULT com = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    const bool comOwned = SUCCEEDED(com);
    HMODULE dxgi = LoadLibraryW(L"dxgi.dll");
    if (!dxgi) {
        wprintf(L"gpu_state=dxgi-missing\n");
        return 2;
    }
    auto create = reinterpret_cast<PFN_CreateDXGIFactory1>(
        GetProcAddress(dxgi, "CreateDXGIFactory1"));
    if (!create) {
        wprintf(L"gpu_state=create-missing\n");
        FreeLibrary(dxgi);
        return 3;
    }

    IDXGIFactory1* factory = nullptr;
    HRESULT hr = create(kIidIdxgiFactory1, reinterpret_cast<void**>(&factory));
    if (FAILED(hr) || !factory) {
        wprintf(L"gpu_state=create-failed hr=0x%08lx\n",
                     static_cast<unsigned long>(hr));
        FreeLibrary(dxgi);
        return 4;
    }

    wprintf(L"gpu_state=ok\n");
    for (UINT index = 0; index < 32; ++index) {
        IDXGIAdapter1* adapter = nullptr;
        hr = factory->EnumAdapters1(index, &adapter);
        if (hr == DXGI_ERROR_NOT_FOUND) break;
        if (FAILED(hr) || !adapter) break;
        DXGI_ADAPTER_DESC1 desc = {};
        if (SUCCEEDED(adapter->GetDesc1(&desc))) {
            wprintf(L"gpu%d_name=%ls\n", index, desc.Description);
            wprintf(L"gpu%d_vendor=0x%04x\n", index, desc.VendorId);
            wprintf(L"gpu%d_device=0x%04x\n", index, desc.DeviceId);
            wprintf(L"gpu%d_subsys=0x%08x\n", index, desc.SubSysId);
            wprintf(L"gpu%d_revision=0x%04x\n", index, desc.Revision);
            wprintf(L"gpu%d_vram_mb=%llu\n", index,
                         static_cast<unsigned long long>(
                             desc.DedicatedVideoMemory / (1024ULL * 1024ULL)));
        }
        adapter->Release();
    }

    factory->Release();
    FreeLibrary(dxgi);
    if (comOwned) CoUninitialize();
    return 0;
}

