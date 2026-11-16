#include <windows.h>

#include <cstdio>

typedef void* nvmlDevice_t;
struct CacNvmlMemory { unsigned long long total, free, used; };

extern "C" {
__declspec(dllimport) int __cdecl nvmlInit_v2(void);
__declspec(dllimport) int __cdecl nvmlDeviceGetCount_v2(unsigned int* count);
__declspec(dllimport) int __cdecl nvmlDeviceGetHandleByIndex_v2(unsigned int index,
                                                               nvmlDevice_t* device);
__declspec(dllimport) int __cdecl nvmlDeviceGetName(nvmlDevice_t device, char* name,
                                                    unsigned int length);
__declspec(dllimport) int __cdecl nvmlDeviceGetSerial(nvmlDevice_t device, char* serial,
                                                      unsigned int length);
__declspec(dllimport) int __cdecl nvmlDeviceGetUUID(nvmlDevice_t device, char* uuid,
                                                    unsigned int length);
__declspec(dllimport) int __cdecl nvmlDeviceGetMemoryInfo(nvmlDevice_t device,
                                                          CacNvmlMemory* memory);
}

int wmain() {
    if (nvmlInit_v2() != 0) {
        std::printf("nvml_state=init-failed\n");
        return 4;
    }
    unsigned int count = 0;
    nvmlDeviceGetCount_v2(&count);
    std::printf("nvml_state=ok\n");
    std::printf("nvml_count=%u\n", count);
    nvmlDevice_t device = nullptr;
    if (count == 0 || nvmlDeviceGetHandleByIndex_v2(0, &device) != 0 || !device) {
        std::printf("nvml0_state=no-device\n");
        return 0;
    }

    char name[96] = {};
    char serial[96] = {};
    char uuid[96] = {};
    CacNvmlMemory memory = {};
    nvmlDeviceGetName(device, name, sizeof(name));
    nvmlDeviceGetSerial(device, serial, sizeof(serial));
    nvmlDeviceGetUUID(device, uuid, sizeof(uuid));
    nvmlDeviceGetMemoryInfo(device, &memory);
    std::printf("nvml0_name=%s\n", name);
    std::printf("nvml0_serial=%s\n", serial);
    std::printf("nvml0_uuid=%s\n", uuid);
    std::printf("nvml0_mem_total_mb=%llu\n", memory.total / (1024ULL * 1024ULL));
    std::printf("nvml0_mem_free_mb=%llu\n", memory.free / (1024ULL * 1024ULL));
    return 0;
}
