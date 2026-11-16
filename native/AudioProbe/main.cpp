#include <windows.h>
#include <mmdeviceapi.h>
#include "../AudioGuids.h"

#include <cstdio>

int wmain() {
    const HRESULT comResult = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    IMMDeviceEnumerator* enumerator = nullptr;
    HRESULT hr = CoCreateInstance(kClsidMMDeviceEnumerator, nullptr, CLSCTX_ALL,
                                  kIidMMDeviceEnumerator,
                                  reinterpret_cast<void**>(&enumerator));
    if (FAILED(hr) || !enumerator) {
        std::printf("audio_state=create-failed hr=0x%08lx\n",
                    static_cast<unsigned long>(hr));
        return 2;
    }
    IMMDeviceCollection* collection = nullptr;
    hr = enumerator->EnumAudioEndpoints(eRender, DEVICE_STATE_ACTIVE, &collection);
    if (FAILED(hr) || !collection) {
        enumerator->Release();
        std::printf("audio_state=enum-failed hr=0x%08lx\n",
                    static_cast<unsigned long>(hr));
        return 3;
    }
    UINT count = 0;
    collection->GetCount(&count);
    std::printf("audio_state=ok\n");
    std::printf("audio_count=%lu\n", static_cast<unsigned long>(count));
    const UINT limit = count < 4 ? count : 4;
    for (UINT index = 0; index < limit; ++index) {
        IMMDevice* device = nullptr;
        if (FAILED(collection->Item(index, &device)) || !device) continue;
        LPWSTR id = nullptr;
        DWORD state = 0;
        if (SUCCEEDED(device->GetId(&id)) && id) {
            wprintf(L"audio%lu_id=%ls\n", static_cast<unsigned long>(index), id);
            CoTaskMemFree(id);
        }
        if (SUCCEEDED(device->GetState(&state))) {
            std::printf("audio%lu_state=0x%08lx\n",
                        static_cast<unsigned long>(index),
                        static_cast<unsigned long>(state));
        }
        device->Release();
    }
    collection->Release();
    enumerator->Release();
    if (SUCCEEDED(comResult)) CoUninitialize();
    return 0;
}
