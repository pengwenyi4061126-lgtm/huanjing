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
    uint32_t     hidVendorId = 0x046D;
    uint32_t     hidProductId = 0xC52B;
    uint32_t     hidVersion = 0x0111;
    std::string  hidManufacturer = "Logitech";
    std::string  hidProduct = "USB Receiver";
    std::string  audioEndpointId =
        "{0.0.0.00000000}.{8f3c2a1e-5b7d-4c9a-9e2f-1a3b5c7d9e0f}";
    std::string  audioFriendlyName = "Speakers (Realtek(R) Audio)";
    std::string  audioInterfaceName = "Realtek High Definition Audio";
    std::string  audioEndpointGuid = "{8f3c2a1e-5b7d-4c9a-9e2f-1a3b5c7d9e0f}";
    uint32_t     audioFormFactor = 1;
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
    uint32_t gpuMemoryMb = 4096;
    bool hypervisorPresent = false;
    bool tpmPresent = false;

    std::string volumeLabel = "System";
    std::string fileSystem = "NTFS";
    std::string gpuName = "NVIDIA GeForce GTX 1650";
    std::string gpuVendor = "NVIDIA";
    std::string gpuDriverVersion = "31.0.15.3699";
    std::string gpuPciId = "PCI\\VEN_10DE&DEV_1F82&SUBSYS_1F8210DE&REV_A1";
    std::string gpuSerial = "1321919076543";
    std::string gpuUuid = "GPU-8f3c2a1e-5b7d-4c9a-9e2f-1a3b5c7d9e0f";
    std::string monitorName = "Dell U2419H";
    std::string monitorManufacturer = "Dell";
    std::string monitorPnpId = "DEL41A9";
    uint32_t monitorEdidManufacturer = 0x10AC;
    uint32_t monitorEdidProduct = 0x41A9;
    std::string monitorSerial;
    std::string monitorEdidHex;
    std::string tpmVendor = "IFX";
    std::string tpmVersion = "2.0";
    std::string systemManufacturer = "ASUSTeK COMPUTER INC.";
    std::string systemProduct = "PRIME B550M-K";
    std::string systemVersion = "1.0";
    std::string boardManufacturer = "ASUSTeK COMPUTER INC.";
    std::string boardProduct = "PRIME B550M-K";
    std::string boardVersion = "1.0";
    std::string biosVendor = "American Megatrends Inc.";
    std::string biosVersion = "5.17";
    std::string biosReleaseDate = "01/01/2024";
    std::string processorName = "AMD Ryzen 3 3100 4-Core Processor";
    std::string cpuVendor = "AuthenticAMD";
    std::string cpuIdentifier = "AMD64 Family 23 Model 113 Stepping 0";
    std::string memoryVendor = "Samsung";
    std::string memoryPart = "M378A1K43CB2-CRC";
    std::string nicName = "Realtek PCIe GbE Family Controller";
    std::string diskModel = "WDC WDS500G2B0A-00SM50";
    std::string chassisAssetTag;
    std::string boardAssetTag;

    bool Load();

    static ProfileIdentity& Get();
};
