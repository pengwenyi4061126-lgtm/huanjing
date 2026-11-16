#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cstring>

namespace {

typedef void* VkInstance;
typedef void* VkPhysicalDevice;
typedef int32_t VkResult;

struct VkApplicationInfo {
    uint32_t sType = 0;
    const void* pNext = nullptr;
    const char* pApplicationName = "cac-vulkan-probe";
    uint32_t applicationVersion = 1;
    const char* pEngineName = "none";
    uint32_t engineVersion = 0;
    uint32_t apiVersion = (1u << 22) | (1u << 12);
};

struct VkInstanceCreateInfo {
    uint32_t sType = 1;
    const void* pNext = nullptr;
    uint32_t flags = 0;
    const VkApplicationInfo* pApplicationInfo = nullptr;
    uint32_t enabledLayerCount = 0;
    const char* const* ppEnabledLayerNames = nullptr;
    uint32_t enabledExtensionCount = 0;
    const char* const* ppEnabledExtensionNames = nullptr;
};

typedef VkResult (*PFN_vkCreateInstance)(const VkInstanceCreateInfo*, const void*, VkInstance*);
typedef void (*PFN_vkDestroyInstance)(VkInstance, const void*);
typedef VkResult (*PFN_vkEnumeratePhysicalDevices)(VkInstance, uint32_t*, VkPhysicalDevice*);
typedef void (*PFN_vkGetPhysicalDeviceProperties)(VkPhysicalDevice, void*);
typedef void (*PFN_vkGetPhysicalDeviceMemoryProperties)(VkPhysicalDevice, void*);

constexpr size_t kPropertyBytes = 2048;
constexpr size_t kMemoryBytes = 2048;
constexpr size_t kDeviceNameOffset = 20;
constexpr size_t kDeviceNameLength = 256;
constexpr size_t kMemoryHeapCountOffset = 260;
constexpr size_t kMemoryHeapsOffset = 264;

const char* DeviceTypeName(uint32_t type) {
    switch (type) {
        case 1: return "integrated";
        case 2: return "discrete";
        case 3: return "virtual";
        case 4: return "cpu";
        default: return "other";
    }
}

}  // namespace

int wmain() {
    HMODULE loader = LoadLibraryW(L"vulkan-1.dll");
    if (!loader) {
        std::printf("vulkan_state=unavailable\n");
        return 0;
    }
    auto createInstance =
        reinterpret_cast<PFN_vkCreateInstance>(GetProcAddress(loader, "vkCreateInstance"));
    auto destroyInstance =
        reinterpret_cast<PFN_vkDestroyInstance>(GetProcAddress(loader, "vkDestroyInstance"));
    auto enumerateDevices = reinterpret_cast<PFN_vkEnumeratePhysicalDevices>(
        GetProcAddress(loader, "vkEnumeratePhysicalDevices"));
    auto getProperties = reinterpret_cast<PFN_vkGetPhysicalDeviceProperties>(
        GetProcAddress(loader, "vkGetPhysicalDeviceProperties"));
    auto getMemory = reinterpret_cast<PFN_vkGetPhysicalDeviceMemoryProperties>(
        GetProcAddress(loader, "vkGetPhysicalDeviceMemoryProperties"));
    if (!createInstance || !enumerateDevices || !getProperties || !getMemory) {
        std::printf("vulkan_state=exports-missing\n");
        return 2;
    }

    VkApplicationInfo app;
    VkInstanceCreateInfo createInfo;
    createInfo.pApplicationInfo = &app;
    VkInstance instance = nullptr;
    if (createInstance(&createInfo, nullptr, &instance) < 0 || !instance) {
        std::printf("vulkan_state=instance-failed\n");
        return 3;
    }

    uint32_t count = 0;
    if (enumerateDevices(instance, &count, nullptr) < 0 || count == 0) {
        std::printf("vulkan_state=no-device\n");
        if (destroyInstance) destroyInstance(instance, nullptr);
        return 0;
    }
    if (count > 8) count = 8;
    VkPhysicalDevice devices[8] = {};
    if (enumerateDevices(instance, &count, devices) < 0) {
        std::printf("vulkan_state=enumerate-failed\n");
        if (destroyInstance) destroyInstance(instance, nullptr);
        return 4;
    }

    std::printf("vulkan_state=ok\n");
    std::printf("vulkan_count=%u\n", count);
    for (uint32_t index = 0; index < count; ++index) {
        unsigned char properties[kPropertyBytes] = {};
        getProperties(devices[index], properties);
        const uint32_t apiVersion = *reinterpret_cast<const uint32_t*>(properties);
        const uint32_t driverVersion = *reinterpret_cast<const uint32_t*>(properties + 4);
        const uint32_t vendorId = *reinterpret_cast<const uint32_t*>(properties + 8);
        const uint32_t deviceId = *reinterpret_cast<const uint32_t*>(properties + 12);
        const uint32_t deviceType = *reinterpret_cast<const uint32_t*>(properties + 16);
        const char* name = reinterpret_cast<const char*>(properties + kDeviceNameOffset);
        char safeName[kDeviceNameLength] = {};
        std::memcpy(safeName, name, kDeviceNameLength - 1);
        std::printf("vulkan%u_name=%s\n", index, safeName);
        std::printf("vulkan%u_vendor=0x%04x\n", index, vendorId);
        std::printf("vulkan%u_device=0x%04x\n", index, deviceId);
        std::printf("vulkan%u_type=%s\n", index, DeviceTypeName(deviceType));
        std::printf("vulkan%u_api=%u.%u.%u\n", index, (apiVersion >> 22) & 0x7F,
                    (apiVersion >> 12) & 0x3FF, apiVersion & 0xFFF);
        std::printf("vulkan%u_driver=0x%08x\n", index, driverVersion);

        unsigned char memory[kMemoryBytes] = {};
        getMemory(devices[index], memory);
        const uint32_t heapCount =
            *reinterpret_cast<const uint32_t*>(memory + kMemoryHeapCountOffset);
        std::printf("vulkan%u_heaps=%u\n", index, heapCount);
        if (heapCount > 0 && heapCount <= 16) {
            const uint64_t heap0 =
                *reinterpret_cast<const uint64_t*>(memory + kMemoryHeapsOffset);
            std::printf("vulkan%u_heap0_mb=%llu\n", index,
                        static_cast<unsigned long long>(heap0 / (1024ULL * 1024ULL)));
        }
    }
    if (destroyInstance) destroyInstance(instance, nullptr);
    return 0;
}
