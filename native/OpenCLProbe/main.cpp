#include <windows.h>

#include <cstdio>

typedef void* cl_platform_id;
typedef void* cl_device_id;
typedef unsigned int cl_uint;
typedef unsigned long long cl_ulong;
typedef int cl_int;

extern "C" {
__declspec(dllimport) cl_int __stdcall clGetPlatformIDs(cl_uint, cl_platform_id*, cl_uint*);
__declspec(dllimport) cl_int __stdcall clGetDeviceIDs(cl_platform_id, cl_uint, cl_uint,
                                                      cl_device_id*, cl_uint*);
__declspec(dllimport) cl_int __stdcall clGetDeviceInfo(cl_device_id, cl_uint, size_t, void*,
                                                       size_t*);
}

int wmain() {
    cl_platform_id platform = nullptr;
    cl_uint platformCount = 0;
    if (clGetPlatformIDs(1, &platform, &platformCount) != 0 || !platform) {
        std::printf("opencl_state=no-platform\n");
        return 2;
    }
    cl_device_id device = nullptr;
    cl_uint deviceCount = 0;
    if (clGetDeviceIDs(platform, 4, 1, &device, &deviceCount) != 0 || !device) {
        std::printf("opencl_state=no-gpu\n");
        return 3;
    }
    char name[256] = {};
    char vendor[256] = {};
    char version[256] = {};
    cl_ulong memory = 0;
    cl_uint units = 0;
    clGetDeviceInfo(device, 0x102B, sizeof(name), name, nullptr);
    clGetDeviceInfo(device, 0x102C, sizeof(vendor), vendor, nullptr);
    clGetDeviceInfo(device, 0x102F, sizeof(version), version, nullptr);
    clGetDeviceInfo(device, 0x101F, sizeof(memory), &memory, nullptr);
    clGetDeviceInfo(device, 0x1002, sizeof(units), &units, nullptr);
    std::printf("opencl_state=ok\n");
    std::printf("opencl_platforms=%u\n", platformCount);
    std::printf("opencl_devices=%u\n", deviceCount);
    std::printf("opencl_name=%s\n", name);
    std::printf("opencl_vendor=%s\n", vendor);
    std::printf("opencl_version=%s\n", version);
    std::printf("opencl_mem_mb=%llu\n", memory / (1024ULL * 1024ULL));
    std::printf("opencl_cus=%u\n", units);
    return 0;
}
