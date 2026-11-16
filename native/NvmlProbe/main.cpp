#include <windows.h>

#include <cstdio>

typedef void* nvmlDevice_t;
struct CacNvmlMemory { unsigned long long total, free, used; };
typedef int (*PFN_nvmlInit)(void);
typedef int (*PFN_nvmlDeviceGetCount)(unsigned int*);
typedef int (*PFN_nvmlDeviceGetHandleByIndex)(unsigned int, nvmlDevice_t*);
typedef int (*PFN_nvmlDeviceGetName)(nvmlDevice_t, char*, unsigned int);
typedef int (*PFN_nvmlDeviceGetSerial)(nvmlDevice_t, char*, unsigned int);
typedef int (*PFN_nvmlDeviceGetUUID)(nvmlDevice_t, char*, unsigned int);
typedef int (*PFN_nvmlDeviceGetMemoryInfo)(nvmlDevice_t, CacNvmlMemory*);

template <typename T>
static T Resolve(HMODULE module, const char* name) {
    return reinterpret_cast<T>(GetProcAddress(module, name));
}

int wmain() {
    HMODULE nvml = LoadLibraryW(L"nvml.dll");
    if (!nvml) {
        std::printf("nvml_state=missing\n");
        return 2;
    }
    auto init = Resolve<PFN_nvmlInit>(nvml, "nvmlInit_v2");
    auto countFn = Resolve<PFN_nvmlDeviceGetCount>(nvml, "nvmlDeviceGetCount_v2");
    auto handleFn = Resolve<PFN_nvmlDeviceGetHandleByIndex>(
        nvml, "nvmlDeviceGetHandleByIndex_v2");
    auto nameFn = Resolve<PFN_nvmlDeviceGetName>(nvml, "nvmlDeviceGetName");
    auto serialFn = Resolve<PFN_nvmlDeviceGetSerial>(nvml, "nvmlDeviceGetSerial");
    auto uuidFn = Resolve<PFN_nvmlDeviceGetUUID>(nvml, "nvmlDeviceGetUUID");
    auto memoryFn = Resolve<PFN_nvmlDeviceGetMemoryInfo>(nvml, "nvmlDeviceGetMemoryInfo");
    if (!init || !countFn || !handleFn || !nameFn || !serialFn || !uuidFn || !memoryFn) {
        std::printf("nvml_state=exports-missing\n");
        FreeLibrary(nvml);
        return 3;
    }
    if (init() != 0) {
        std::printf("nvml_state=init-failed\n");
        FreeLibrary(nvml);
        return 4;
    }

    unsigned int count = 0;
    countFn(&count);
    std::printf("nvml_state=ok\n");
    std::printf("nvml_count=%u\n", count);
    nvmlDevice_t device = nullptr;
    if (count == 0 || handleFn(0, &device) != 0 || !device) {
        std::printf("nvml0_state=no-device\n");
        FreeLibrary(nvml);
        return 0;
    }

    char name[96] = {};
    char serial[96] = {};
    char uuid[96] = {};
    CacNvmlMemory memory = {};
    nameFn(device, name, sizeof(name));
    serialFn(device, serial, sizeof(serial));
    uuidFn(device, uuid, sizeof(uuid));
    memoryFn(device, &memory);
    std::printf("nvml0_name=%s\n", name);
    std::printf("nvml0_serial=%s\n", serial);
    std::printf("nvml0_uuid=%s\n", uuid);
    std::printf("nvml0_mem_total_mb=%llu\n", memory.total / (1024ULL * 1024ULL));
    std::printf("nvml0_mem_free_mb=%llu\n", memory.free / (1024ULL * 1024ULL));

    FreeLibrary(nvml);
    return 0;
}
