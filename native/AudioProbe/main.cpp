#include <windows.h>
#include <mmdeviceapi.h>
#include <propsys.h>
#include <propvarutil.h>
#include <functiondiscoverykeys_devpkey.h>
#include "../AudioGuids.h"

#include <cstdio>

static const PROPERTYKEY kPkeyAudioEndpointFormFactor = {
    {0x1DA5D803, 0xD492, 0x4EDD, {0x8C, 0x23, 0xE0, 0xC0, 0xFF, 0xEE, 0x7F, 0x0E}}, 0};
static const PROPERTYKEY kPkeyAudioEndpointGuid = {
    {0x1DA5D803, 0xD492, 0x4EDD, {0x8C, 0x23, 0xE0, 0xC0, 0xFF, 0xEE, 0x7F, 0x0E}}, 4};

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
        IPropertyStore* store = nullptr;
        if (SUCCEEDED(device->OpenPropertyStore(STGM_READ, &store)) && store) {
            PROPVARIANT value;
            PropVariantInit(&value);
            if (SUCCEEDED(store->GetValue(PKEY_Device_FriendlyName, &value)) &&
                value.vt == VT_LPWSTR) {
                wprintf(L"audio%lu_friendly=%ls\n",
                        static_cast<unsigned long>(index), value.pwszVal);
            }
            PropVariantClear(&value);
            PropVariantInit(&value);
            if (SUCCEEDED(store->GetValue(PKEY_DeviceInterface_FriendlyName, &value)) &&
                value.vt == VT_LPWSTR) {
                wprintf(L"audio%lu_interface=%ls\n",
                        static_cast<unsigned long>(index), value.pwszVal);
            }
            PropVariantClear(&value);
            PropVariantInit(&value);
            if (SUCCEEDED(store->GetValue(kPkeyAudioEndpointGuid, &value)) &&
                value.vt == VT_LPWSTR) {
                wprintf(L"audio%lu_guid=%ls\n",
                        static_cast<unsigned long>(index), value.pwszVal);
            }
            PropVariantClear(&value);
            PropVariantInit(&value);
            if (SUCCEEDED(store->GetValue(kPkeyAudioEndpointFormFactor, &value)) &&
                value.vt == VT_UI4) {
                std::printf("audio%lu_formfactor=%lu\n",
                            static_cast<unsigned long>(index),
                            static_cast<unsigned long>(value.ulVal));
            }
            PropVariantClear(&value);
            store->Release();
        }
        device->Release();
    }
    collection->Release();
    enumerator->Release();
    if (SUCCEEDED(comResult)) CoUninitialize();
    return 0;
}
