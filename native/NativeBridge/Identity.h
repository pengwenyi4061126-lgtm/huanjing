#pragma once

#include <windows.h>
#include <cstdint>
#include <string>

// Profile-scoped identity shared by the Node preload and the native layer.
// Values are loaded from %CAC_PROFILE_IDENTITY% (identity.json) and from the
// CAC_* environment variables set by the cac wrapper.
struct ProfileIdentity {
    std::wstring profileDir;
    std::string  hostname;
    std::string  username;
    std::string  machineId;
    std::string  stableId;
    std::string  mac;              // aa:bb:cc:dd:ee:ff
    BYTE         macBytes[6] = {};
    bool         hasMac = false;
    std::string  diskSerial;
    std::string  biosSerial;
    std::string  boardSerial;
    std::string  systemSerial;
    std::string  systemUuid;       // 32 hex chars
    std::string  processorId;      // 16 hex chars
    std::string  hidSerial;
    std::string  volumeSerialHex_;
    DWORD        volumeSerial = 0;

    // Hardware profile values used by the memory/disk/GPU/SMBIOS/WMI layers.
    // Defaults are deliberately generic; identity.json can override them.
    uint64_t memoryTotalMb = 16384;
    uint64_t memoryAvailableMb = 12288;
    uint64_t memoryModuleMb = 8192;
    uint32_t memorySpeedMhz = 3200;
    uint64_t diskTotalGb = 512;
    uint64_t diskFreeGb = 256;
    uint32_t cpuCores = 4;
    uint32_t cpuLogical = 8;
    uint32_t cpuMaxMhz = 3000;
    uint32_t l2CacheKb = 512;
    uint32_t l3CacheKb = 8192;
    uint32_t displayWidth = 1920;
    uint32_t displayHeight = 1080;
    uint32_t displayRefresh = 60;
    uint32_t gpuMemoryMb = 128;
    bool hypervisorPresent = false;
    bool tpmPresent = false;

    std::string volumeLabel = "System";
    std::string fileSystem = "NTFS";
    std::string gpuName = "Generic Display Adapter";
    std::string gpuVendor = "Generic";
    std::string gpuDriverVersion = "1.0.0.0";
    std::string monitorName = "Generic Monitor";
    std::string monitorSerial;
    std::string monitorEdidHex;
    std::string tpmVendor = "IFX";
    std::string tpmVersion = "2.0";
    std::string systemManufacturer = "Default string";
    std::string systemProduct = "System Product Name";
    std::string systemVersion = "1.0";
    std::string boardManufacturer = "Default string";
    std::string boardProduct = "Base Board";
    std::string boardVersion = "1.0";
    std::string biosVendor = "American Megatrends Inc.";
    std::string biosVersion = "F.20";
    std::string biosReleaseDate = "01/01/2024";
    std::string processorName = "Generic x64 Processor";
    std::string chassisAssetTag;
    std::string boardAssetTag;

    bool Load();

    static ProfileIdentity& Get();
};
