#define _WIN32_WINNT 0x0A00

#include "WmiHooks.h"

#include <windows.h>
#include <wbemidl.h>
#include <oleauto.h>
#include <mmdeviceapi.h>
#include <propsys.h>
#include <propvarutil.h>
#include <functiondiscoverykeys_devpkey.h>
#include "../AudioGuids.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <new>
#include <string>
#include <vector>

#include "ApiHooks.h"
#include "Audit.h"
#include "Identity.h"

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

namespace {

bool SameText(const std::wstring& value, const wchar_t* expected) {
    return expected && _wcsicmp(value.c_str(), expected) == 0;
}

std::wstring ToWide(const std::string& value) {
    if (value.empty()) return std::wstring();
    const int length = MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                                           nullptr, 0);
    if (length <= 0) return std::wstring();
    std::wstring result(static_cast<size_t>(length), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                        result.data(), length);
    return result;
}

std::wstring FormatUuid(const std::string& hex) {
    if (hex.size() != 32) return std::wstring();
    std::wstring upper = ToWide(hex);
    for (wchar_t& c : upper) c = static_cast<wchar_t>(towupper(c));
    return upper.substr(0, 8) + L"-" + upper.substr(8, 4) + L"-" + upper.substr(12, 4) + L"-" +
           upper.substr(16, 4) + L"-" + upper.substr(20, 12);
}

std::wstring FormatCimDate(const std::string& text) {
    int month = 1;
    int day = 1;
    int year = 2024;
    if (sscanf_s(text.c_str(), "%d/%d/%d", &month, &day, &year) != 3) {
        month = 1;
        day = 1;
        year = 2024;
    }
    wchar_t buffer[48] = {};
    swprintf_s(buffer, L"%04d%02d%02d000000.000000+480", year, month, day);
    return buffer;
}

enum class WmiValueType {
    String,
    UInt32,
    UInt64,
    Bool,
};

struct WmiSpoof {
    WmiValueType type = WmiValueType::String;
    std::wstring text;
    uint64_t number = 0;
    bool boolean = false;
};

struct Rule {
    const wchar_t* cls;
    const wchar_t* prop;
    int kind;
    WmiValueType type = WmiValueType::String;
};

// kind: 0 blank, 1 system serial, 2 system UUID, 3 processor id, 4 MAC,
//       5 volume serial, 6 hostname, 7 BIOS serial, 8 board serial, 9 disk serial.
const Rule kRules[] = {
    { L"Win32_BIOS", L"Manufacturer", 44 },
    { L"Win32_BIOS", L"SMBIOSBIOSVersion", 45 },
    { L"Win32_BIOS", L"ReleaseDate", 46 },
    { L"Win32_BaseBoard", L"Manufacturer", 47 },
    { L"Win32_BaseBoard", L"Product", 48 },
    { L"Win32_BaseBoard", L"Version", 49 },
    { L"Win32_ComputerSystem", L"Manufacturer", 47 },
    { L"Win32_ComputerSystem", L"Model", 48 },
    { L"Win32_ComputerSystemProduct", L"Vendor", 47 },
    { L"Win32_ComputerSystemProduct", L"Name", 48 },
    { L"Win32_ComputerSystemProduct", L"Version", 49 },
    { L"Win32_ComputerSystem", L"TotalPhysicalMemory", 10, WmiValueType::UInt64 },
    { L"Win32_ComputerSystem", L"HypervisorPresent", 20, WmiValueType::Bool },
    { L"Win32_OperatingSystem", L"TotalVisibleMemorySize", 28, WmiValueType::UInt64 },
    { L"Win32_OperatingSystem", L"FreePhysicalMemory", 29, WmiValueType::UInt64 },
    { L"Win32_LogicalDisk", L"Size", 12, WmiValueType::UInt64 },
    { L"Win32_LogicalDisk", L"FreeSpace", 13, WmiValueType::UInt64 },
    { L"Win32_LogicalDisk", L"VolumeName", 30 },
    { L"Win32_LogicalDisk", L"FileSystem", 31 },
    { L"Win32_DiskDrive", L"Size", 12, WmiValueType::UInt64 },
    { L"Win32_DiskDrive", L"Partitions", 32, WmiValueType::UInt32 },
    { L"Win32_DiskDrive", L"InterfaceType", 33 },
    { L"Win32_DiskDrive", L"MediaType", 34 },
    { L"Win32_DiskDrive", L"Model", 35 },
    { L"Win32_DiskDrive", L"FirmwareRevision", 36 },
    { L"Win32_PhysicalMemory", L"Capacity", 22, WmiValueType::UInt64 },
    { L"Win32_PhysicalMemory", L"Speed", 23, WmiValueType::UInt32 },
    { L"Win32_PhysicalMemory", L"ConfiguredClockSpeed", 23, WmiValueType::UInt32 },
    { L"Win32_PhysicalMemory", L"DeviceLocator", 37 },
    { L"Win32_PhysicalMemory", L"BankLabel", 38 },
    { L"Win32_Processor", L"NumberOfCores", 15, WmiValueType::UInt32 },
    { L"Win32_Processor", L"NumberOfLogicalProcessors", 16, WmiValueType::UInt32 },
    { L"Win32_Processor", L"MaxClockSpeed", 17, WmiValueType::UInt32 },
    { L"Win32_Processor", L"L2CacheSize", 18, WmiValueType::UInt32 },
    { L"Win32_Processor", L"L3CacheSize", 19, WmiValueType::UInt32 },
    { L"Win32_Processor", L"VirtualizationFirmwareEnabled", 20, WmiValueType::Bool },
    { L"Win32_Processor", L"VMMonitorModeExtensions", 20, WmiValueType::Bool },
    { L"Win32_Processor", L"SecondLevelAddressTranslationExtensions", 20, WmiValueType::Bool },
    { L"Win32_Processor", L"Name", 51 },
    { L"Win32_Processor", L"Manufacturer", 52 },
    { L"Win32_Processor", L"Version", 53 },
    { L"Win32_VideoController", L"Name", 39 },
    { L"Win32_VideoController", L"VideoProcessor", 39 },
    { L"Win32_VideoController", L"DriverVersion", 40 },
    { L"Win32_VideoController", L"AdapterRAM", 14, WmiValueType::UInt32 },
    { L"Win32_VideoController", L"PNPDeviceID", 41 },
    { L"Win32_VideoController", L"DeviceID", 41 },
    { L"Win32_VideoController", L"AdapterCompatibility", 42 },
    { L"Win32_DesktopMonitor", L"Name", 43 },
    { L"Win32_DesktopMonitor", L"MonitorID", 59 },
    { L"Win32_DesktopMonitor", L"PNPDeviceID", 59 },
    { L"Win32_SystemEnclosure", L"SMBIOSAssetTag", 50 },
    { L"Win32_NetworkAdapter", L"Name", 56 },
    { L"Win32_NetworkAdapter", L"Description", 56 },
    { L"Win32_NetworkAdapter", L"AdapterType", 57 },
    { L"Win32_NetworkAdapter", L"PNPDeviceID", 60 },
    { L"Win32_NetworkAdapterConfiguration", L"Description", 56 },
    { L"MSFT_NetAdapter", L"InterfaceDescription", 56 },
    { L"MSFT_NetAdapter", L"DriverDescription", 56 },
    { L"MSFT_NetAdapter", L"PNPDeviceID", 60 },
    { L"MSFT_NetAdapter", L"DeviceID", 60 },
    { L"Win32_Battery", L"Name", 58 },
    { L"Win32_Battery", L"DeviceID", 41 },
    { L"Win32_Battery", L"SerialNumber", 1 },
    { L"Win32_SoundDevice", L"Name", 58 },
    { L"Win32_SoundDevice", L"DeviceID", 41 },
    { L"Win32_Printer", L"Name", 58 },
    { L"Win32_Printer", L"PortName", 0 },
    { L"Win32_SerialPort", L"Name", 58 },
    { L"Win32_SerialPort", L"DeviceID", 41 },
    { L"Win32_Camera", L"Name", 58 },
    { L"Win32_Camera", L"DeviceID", 41 },
    { L"Win32_Keyboard", L"Name", 58 },
    { L"Win32_Keyboard", L"DeviceID", 41 },
    { L"Win32_PointingDevice", L"Name", 58 },
    { L"Win32_PointingDevice", L"DeviceID", 41 },
    { L"Win32_Tpm", L"ManufacturerId", 54 },
    { L"Win32_Tpm", L"ManufacturerVersion", 55 },
    { L"Win32_Tpm", L"SpecVersion", 55 },
    { L"Win32_Tpm", L"PhysicalPresenceVersionInfo", 55 },
    { L"Win32_Tpm", L"IsEnabled_InitialValue", 20, WmiValueType::Bool },
    { L"Win32_Tpm", L"IsActivated_InitialValue", 20, WmiValueType::Bool },
    { L"Win32_Tpm", L"IsOwned_InitialValue", 20, WmiValueType::Bool },
    { L"Win32_BIOS", L"SerialNumber", 1 },
    { L"Win32_BIOS", L"SMBIOSBIOSVersion", 7 },
    { L"Win32_BIOS", L"Manufacturer", 0 },
    { L"Win32_BIOS", L"ReleaseDate", 0 },
    { L"Win32_BaseBoard", L"SerialNumber", 8 },
    { L"Win32_BaseBoard", L"Product", 0 },
    { L"Win32_BaseBoard", L"Manufacturer", 0 },
    { L"Win32_BaseBoard", L"Version", 0 },
    { L"Win32_ComputerSystemProduct", L"UUID", 2 },
    { L"Win32_ComputerSystemProduct", L"IdentifyingNumber", 1 },
    { L"Win32_ComputerSystemProduct", L"Vendor", 0 },
    { L"Win32_ComputerSystemProduct", L"Name", 0 },
    { L"Win32_ComputerSystemProduct", L"Version", 0 },
    { L"Win32_DiskDrive", L"SerialNumber", 9 },
    { L"Win32_DiskDrive", L"Model", 0 },
    { L"Win32_DiskDrive", L"FirmwareRevision", 0 },
    { L"Win32_PhysicalMedia", L"SerialNumber", 9 },
    { L"Win32_Processor", L"ProcessorId", 3 },
    { L"Win32_Processor", L"Name", 0 },
    { L"Win32_Processor", L"Manufacturer", 0 },
    { L"Win32_Processor", L"Version", 0 },
    { L"Win32_NetworkAdapter", L"MACAddress", 4 },
    { L"Win32_NetworkAdapterConfiguration", L"MACAddress", 4 },
    { L"Win32_NetworkAdapterConfiguration", L"SettingID", 0 },
    { L"Win32_NetworkAdapterConfiguration", L"Description", 0 },
    { L"MSFT_NetAdapter", L"MacAddress", 4 },
    { L"MSFT_NetAdapter", L"PermanentAddress", 4 },
    { L"MSFT_NetAdapter", L"InterfaceDescription", 0 },
    { L"MSFT_NetAdapter", L"DriverDescription", 0 },
    { L"MSFT_NetAdapter", L"PNPDeviceID", 0 },
    { L"MSFT_NetAdapter", L"DeviceID", 0 },
    { L"Win32_ComputerSystem", L"Name", 6 },
    { L"Win32_ComputerSystem", L"Manufacturer", 0 },
    { L"Win32_ComputerSystem", L"Model", 0 },
    { L"Win32_OperatingSystem", L"CSName", 6 },
    { L"Win32_OperatingSystem", L"SerialNumber", 1 },
    { L"Win32_VideoController", L"PNPDeviceID", 0 },
    { L"Win32_VideoController", L"DeviceID", 0 },
    { L"Win32_VideoController", L"Name", 0 },
    { L"Win32_VideoController", L"AdapterCompatibility", 0 },
    { L"Win32_SystemEnclosure", L"SerialNumber", 1 },
    { L"Win32_SystemEnclosure", L"SMBIOSAssetTag", 0 },
    { L"Win32_PhysicalMemory", L"SerialNumber", 0 },
    { L"Win32_PhysicalMemory", L"PartNumber", 0 },
    { L"Win32_PhysicalMemory", L"Manufacturer", 0 },
    { nullptr, L"SerialNumber", 1 },
    { nullptr, L"UUID", 2 },
    { nullptr, L"IdentifyingNumber", 1 },
    { nullptr, L"ProcessorId", 3 },
    { nullptr, L"MACAddress", 4 },
    { nullptr, L"VolumeSerialNumber", 5 },
    { nullptr, L"PNPDeviceID", 0 },
    { nullptr, L"SMBIOSAssetTag", 0 },
    { nullptr, L"AssetTag", 0 },
    { nullptr, L"PartNumber", 0 },
};

WmiSpoof ValueForKind(int kind) {
    const ProfileIdentity& identity = ProfileIdentity::Get();
    WmiSpoof spoof;
    switch (kind) {
        case 1: spoof.text = ToWide(identity.systemSerial); break;
        case 2: spoof.text = FormatUuid(identity.systemUuid); break;
        case 3: spoof.text = ToWide(identity.processorId); break;
        case 4: spoof.text = ToWide(identity.mac); break;
        case 5: spoof.text = ToWide(identity.volumeSerialHex_); break;
        case 6: spoof.text = ToWide(identity.hostname); break;
        case 7: spoof.text = ToWide(identity.biosSerial); break;
        case 8: spoof.text = ToWide(identity.boardSerial); break;
        case 9: spoof.text = ToWide(identity.diskSerial); break;
        case 10:
            spoof.type = WmiValueType::UInt64;
            spoof.number = identity.memoryTotalMb * 1024ULL * 1024ULL;
            break;
        case 12:
            spoof.type = WmiValueType::UInt64;
            spoof.number = identity.diskTotalGb * 1024ULL * 1024ULL * 1024ULL;
            break;
        case 13:
            spoof.type = WmiValueType::UInt64;
            spoof.number = identity.diskFreeGb * 1024ULL * 1024ULL * 1024ULL;
            break;
        case 14:
            spoof.type = WmiValueType::UInt32;
            spoof.number = identity.gpuMemoryMb * 1024ULL * 1024ULL;
            if (spoof.number > 0xFFFFFFFFULL) spoof.number = 0xFFFFFFFFULL;
            break;
        case 15: spoof.type = WmiValueType::UInt32; spoof.number = identity.cpuCores; break;
        case 16: spoof.type = WmiValueType::UInt32; spoof.number = identity.cpuLogical; break;
        case 17: spoof.type = WmiValueType::UInt32; spoof.number = identity.cpuMaxMhz; break;
        case 18: spoof.type = WmiValueType::UInt32; spoof.number = identity.l2CacheKb; break;
        case 19: spoof.type = WmiValueType::UInt32; spoof.number = identity.l3CacheKb; break;
        case 20: spoof.type = WmiValueType::Bool; spoof.boolean = identity.hypervisorPresent; break;
        case 22:
            spoof.type = WmiValueType::UInt64;
            spoof.number = identity.memoryModuleMb * 1024ULL * 1024ULL;
            break;
        case 23: spoof.type = WmiValueType::UInt32; spoof.number = identity.memorySpeedMhz; break;
        case 28:
            spoof.type = WmiValueType::UInt64;
            spoof.number = identity.memoryTotalMb * 1024ULL;
            break;
        case 29:
            spoof.type = WmiValueType::UInt64;
            spoof.number = identity.memoryAvailableMb * 1024ULL;
            break;
        case 30: spoof.text = ToWide(identity.volumeLabel); break;
        case 31: spoof.text = ToWide(identity.fileSystem); break;
        case 32: spoof.type = WmiValueType::UInt32; spoof.number = 1; break;
        case 33: spoof.text = L"SCSI"; break;
        case 34: spoof.text = L"Fixed hard disk media"; break;
        case 35: spoof.text = ToWide(identity.diskModel); break;
        case 36: spoof.text = L"1.0"; break;
        case 37: spoof.text = L"DIMM 0"; break;
        case 38: spoof.text = L"BANK 0"; break;
        case 39: spoof.text = ToWide(identity.gpuName); break;
        case 40: spoof.text = ToWide(identity.gpuDriverVersion); break;
        case 41: spoof.text = ToWide(identity.gpuPciId); break;
        case 42: spoof.text = ToWide(identity.gpuVendor); break;
        case 43: spoof.text = ToWide(identity.monitorName); break;
        case 44: spoof.text = ToWide(identity.biosVendor); break;
        case 45: spoof.text = ToWide(identity.biosVersion); break;
        case 46: spoof.text = FormatCimDate(identity.biosReleaseDate); break;
        case 47: spoof.text = ToWide(identity.systemManufacturer); break;
        case 48: spoof.text = ToWide(identity.systemProduct); break;
        case 49: spoof.text = ToWide(identity.systemVersion); break;
        case 50: spoof.text = ToWide(identity.chassisAssetTag); break;
        case 51: spoof.text = ToWide(identity.processorName); break;
        case 52: spoof.text = ToWide(identity.cpuVendor); break;
        case 53: spoof.text = ToWide(identity.cpuIdentifier); break;
        case 54: spoof.text = ToWide(identity.tpmVendor); break;
        case 55: spoof.text = ToWide(identity.tpmVersion); break;
        case 56: spoof.text = ToWide(identity.nicName); break;
        case 57: spoof.text = L"Ethernet 802.3"; break;
        case 58: spoof.text = ToWide(identity.systemProduct); break;
        case 59:
            spoof.text = std::wstring(L"MONITOR\\") + ToWide(identity.monitorPnpId);
            break;
        case 60: spoof.text = ToWide(identity.nicPciId); break;
        default: break;
    }
    return spoof;
}

bool SpoofWmiValue(const std::wstring& cls, const std::wstring& prop, WmiSpoof& out) {
    static int disabled = -1;
    if (disabled < 0) {
        char value[8] = {};
        disabled = GetEnvironmentVariableA("CAC_NATIVE_WMI_DISABLE", value,
                                           static_cast<DWORD>(sizeof(value))) > 0 &&
                   value[0] == '1' ? 1 : 0;
    }
    if (disabled) return false;
    for (const Rule& rule : kRules) {
        if (_wcsicmp(prop.c_str(), rule.prop) != 0) continue;
        if (rule.cls && _wcsicmp(cls.c_str(), rule.cls) != 0) continue;
        if (NativeCleanNetworkEnabled() && (rule.kind == 56 || rule.kind == 57)) continue;
        out = ValueForKind(rule.kind);
        out.type = rule.type;
        if (rule.type == WmiValueType::String && out.text.empty()) out.text.clear();
        if (NativeEmptyReadsEnabled()) {
            if (rule.type == WmiValueType::String) out.text.clear();
            else out.number = 0;
            out.boolean = false;
        }
        AuditEventRateLimited("wmi.get", NativeEmptyReadsEnabled() ? "empty" : "spoofed");
        return true;
    }
    return false;
}

std::wstring GetObjectString(IWbemClassObject* object, LPCWSTR property) {
    if (!object) return std::wstring();
    VARIANT value;
    VariantInit(&value);
    std::wstring result;
    if (SUCCEEDED(object->Get(property, 0, &value, nullptr, nullptr)) && value.vt == VT_BSTR &&
        value.bstrVal) {
        result.assign(value.bstrVal, SysStringLen(value.bstrVal));
    }
    VariantClear(&value);
    return result;
}

bool IsVirtualNetworkObject(IWbemClassObject* object) {
    if (!object || !NativeCleanNetworkEnabled()) return false;
    const std::wstring cls = GetObjectString(object, L"__CLASS");
    if (_wcsicmp(cls.c_str(), L"Win32_NetworkAdapter") != 0 &&
        _wcsicmp(cls.c_str(), L"Win32_NetworkAdapterConfiguration") != 0 &&
        _wcsicmp(cls.c_str(), L"MSFT_NetAdapter") != 0) {
        return false;
    }
    static const wchar_t* const properties[] = {
        L"Name", L"Description", L"InterfaceDescription", L"DriverDescription",
        L"PNPDeviceID", L"SettingID", L"DeviceID",
    };
    for (const wchar_t* property : properties) {
        const std::wstring value = GetObjectString(object, property);
        if (NativeIsVirtualAdapterName(value.c_str())) {
            AuditEventRateLimited("wmi.network", "clean-none");
            return true;
        }
    }
    return false;
}

class RefCounted {
public:
    RefCounted() : refs_(1) {}
    virtual ~RefCounted() {}
    ULONG AddRef() { return static_cast<ULONG>(InterlockedIncrement(&refs_)); }
    ULONG Release() {
        const LONG value = InterlockedDecrement(&refs_);
        if (value == 0) delete this;
        return static_cast<ULONG>(value);
    }

private:
    LONG refs_;
};

CIMTYPE CimTypeFor(WmiValueType type) {
    switch (type) {
        case WmiValueType::UInt32: return CIM_UINT32;
        case WmiValueType::UInt64: return CIM_UINT64;
        case WmiValueType::Bool: return CIM_BOOLEAN;
        default: return CIM_STRING;
    }
}

bool SetSpoofVariant(VARIANT* value, const WmiSpoof& spoof) {
    if (!value) return false;
    VariantInit(value);
    switch (spoof.type) {
        case WmiValueType::UInt32:
            value->vt = VT_UI4;
            value->ulVal = static_cast<ULONG>(spoof.number);
            return true;
        case WmiValueType::UInt64:
            value->vt = VT_UI8;
            value->ullVal = spoof.number;
            return true;
        case WmiValueType::Bool:
            value->vt = VT_BOOL;
            value->boolVal = spoof.boolean ? VARIANT_TRUE : VARIANT_FALSE;
            return true;
        default:
            value->vt = VT_BSTR;
            value->bstrVal = SysAllocString(spoof.text.c_str());
            return value->bstrVal != nullptr;
    }
}

bool IsVirtualPnpObject(IWbemClassObject* object) {
    if (!object || !NativeHardwareHooksEnabled()) return false;
    const std::wstring cls = GetObjectString(object, L"__CLASS");
    if (_wcsicmp(cls.c_str(), L"Win32_PnPEntity") != 0) return false;
    static const wchar_t* const properties[] = {L"Name", L"DeviceID", L"PNPDeviceID"};
    for (const wchar_t* property : properties) {
        const std::wstring value = GetObjectString(object, property);
        if (wcsstr(value.c_str(), L"GameViewer")) {
            AuditEventRateLimited("wmi.pnp", "virtual-hidden");
            return true;
        }
    }
    return false;
}

std::wstring NormalizeGuidText(const std::wstring& value) {
    std::wstring text;
    for (wchar_t ch : value) {
        if ((ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'f') ||
            (ch >= L'A' && ch <= L'F')) {
            text.push_back(static_cast<wchar_t>(towlower(ch)));
        }
    }
    return text;
}

// Project Win32_PnPEntity rows onto the profile device graph. The host row
// keeps its position, but the class-relevant name and instance id come from
// the Profile so a WMI consumer cannot cross-check the real device behind it.
bool PnpPropertyOverride(IWbemClassObject* object, LPCWSTR property, std::wstring* text) {
    if (!object || !property || !text || !NativeHardwareHooksEnabled()) return false;
    const std::wstring cls = GetObjectString(object, L"__CLASS");
    if (_wcsicmp(cls.c_str(), L"Win32_PnPEntity") != 0) return false;
    const bool wantName = _wcsicmp(property, L"Name") == 0;
    const bool wantId = _wcsicmp(property, L"DeviceID") == 0 ||
                        _wcsicmp(property, L"PNPDeviceID") == 0;
    if (!wantName && !wantId) return false;

    std::wstring deviceClass = GetObjectString(object, L"PNPClass");
    const std::wstring instanceId = GetObjectString(object, L"PNPDeviceID");
    if (deviceClass.empty()) {
        const std::wstring guid = NormalizeGuidText(GetObjectString(object, L"ClassGuid"));
        if (guid == L"4d36e968e32511cebfc108002be10318") deviceClass = L"Display";
        else if (guid == L"4d36e96ee32511cebfc108002be10318") deviceClass = L"Monitor";
        else if (guid == L"4d36e96ce32511cebfc108002be10318") deviceClass = L"MEDIA";
        else if (guid == L"4d36e967e32511cebfc108002be10318") deviceClass = L"DiskDrive";
        else if (guid == L"4d36e972e32511cebfc108002be10318") deviceClass = L"Net";
    }
    if (deviceClass.empty() && instanceId.rfind(L"MONITOR\\", 0) == 0) {
        deviceClass = L"Monitor";
    }
    const ProfileIdentity& identity = ProfileIdentity::Get();
    if (_wcsicmp(deviceClass.c_str(), L"Display") == 0) {
        *text = wantName ? ToWide(identity.gpuName) : ToWide(identity.gpuPciId);
    } else if (_wcsicmp(deviceClass.c_str(), L"Monitor") == 0) {
        *text = wantName ? ToWide(identity.monitorName)
                         : (std::wstring(L"MONITOR\\") + ToWide(identity.monitorPnpId));
    } else if (_wcsicmp(deviceClass.c_str(), L"AudioEndpoint") == 0 ||
               _wcsicmp(deviceClass.c_str(), L"MEDIA") == 0) {
        if (!wantName) return false;
        *text = ToWide(identity.audioFriendlyName);
    } else if (_wcsicmp(deviceClass.c_str(), L"DiskDrive") == 0) {
        if (!wantName) return false;
        *text = ToWide(identity.diskModel);
    } else if (_wcsicmp(deviceClass.c_str(), L"Net") == 0) {
        *text = wantName ? ToWide(identity.nicName) : ToWide(identity.nicPciId);
    } else {
        return false;
    }
    AuditEventRateLimited("wmi.pnp", "projected");
    return true;
}

class WmiObject : public IWbemClassObject, public RefCounted {
public:
    explicit WmiObject(IWbemClassObject* inner) : inner_(inner) {}
    ~WmiObject() override { if (inner_) inner_->Release(); }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IWbemClassObject) {
            *ppv = static_cast<IWbemClassObject*>(this);
            AddRef();
            return S_OK;
        }
        return inner_->QueryInterface(riid, ppv);
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return RefCounted::AddRef(); }
    ULONG STDMETHODCALLTYPE Release() override { return RefCounted::Release(); }

    HRESULT STDMETHODCALLTYPE GetQualifierSet(IWbemQualifierSet** ppQualSet) override {
        return inner_->GetQualifierSet(ppQualSet);
    }
    HRESULT STDMETHODCALLTYPE Get(LPCWSTR name, long flags, VARIANT* value, CIMTYPE* type,
                                  long* flavor) override {
        const HRESULT original = inner_->Get(name, flags, value, type, flavor);
        if (FAILED(original)) return original;
        if (name && value) {
            const CIMTYPE originalType = type ? *type : CIM_ILLEGAL;
            std::wstring pnpText;
            if (PnpPropertyOverride(inner_, name, &pnpText)) {
                VariantClear(value);
                value->vt = VT_BSTR;
                value->bstrVal = SysAllocStringLen(pnpText.data(),
                                                   static_cast<UINT>(pnpText.size()));
                if (!value->bstrVal) return E_OUTOFMEMORY;
                if (type) *type = originalType != CIM_ILLEGAL ? originalType : CIM_STRING;
                if (flavor) *flavor = 0;
                return S_OK;
            }
            WmiSpoof spoof;
            if (SpoofWmiValue(ClassName(), name, spoof)) {
                VariantClear(value);
                if (!SetSpoofVariant(value, spoof)) return E_OUTOFMEMORY;
                if (type) {
                    // Keep the provider-declared CIM type for strings so
                    // datetime and reference properties stay convertible by
                    // the MI/CIM client instead of failing with TYPE_MISMATCH.
                    const bool keepOriginal = spoof.type == WmiValueType::String &&
                                              originalType != CIM_ILLEGAL &&
                                              originalType != CIM_STRING;
                    *type = keepOriginal ? originalType : CimTypeFor(spoof.type);
                }
                if (flavor) *flavor = 0;
                return S_OK;
            }
        }
        return original;
    }
    HRESULT STDMETHODCALLTYPE Put(LPCWSTR name, long flags, VARIANT* value, CIMTYPE type) override {
        return inner_->Put(name, flags, value, type);
    }
    HRESULT STDMETHODCALLTYPE Delete(LPCWSTR name) override { return inner_->Delete(name); }
    HRESULT STDMETHODCALLTYPE GetNames(LPCWSTR qualifier, long flags, VARIANT* qualifierValue,
                                       SAFEARRAY** names) override {
        return inner_->GetNames(qualifier, flags, qualifierValue, names);
    }
    HRESULT STDMETHODCALLTYPE BeginEnumeration(long flags) override {
        return inner_->BeginEnumeration(flags);
    }
    HRESULT STDMETHODCALLTYPE Next(long flags, BSTR* name, VARIANT* value, CIMTYPE* type,
                                   long* flavor) override {
        const HRESULT hr = inner_->Next(flags, name, value, type, flavor);
        if (FAILED(hr) || !name || !*name || !value) return hr;
        const CIMTYPE originalType = type ? *type : CIM_ILLEGAL;
        std::wstring pnpText;
        if (PnpPropertyOverride(inner_, *name, &pnpText)) {
            VariantClear(value);
            value->vt = VT_BSTR;
            value->bstrVal = SysAllocStringLen(pnpText.data(),
                                               static_cast<UINT>(pnpText.size()));
            if (!value->bstrVal) return E_OUTOFMEMORY;
            if (type) *type = originalType != CIM_ILLEGAL ? originalType : CIM_STRING;
            if (flavor) *flavor = 0;
            return hr;
        }
        WmiSpoof spoof;
        if (!SpoofWmiValue(ClassName(), *name, spoof)) return hr;
        VariantClear(value);
        if (!SetSpoofVariant(value, spoof)) return E_OUTOFMEMORY;
        if (type) {
            const bool keepOriginal = spoof.type == WmiValueType::String &&
                                      originalType != CIM_ILLEGAL &&
                                      originalType != CIM_STRING;
            *type = keepOriginal ? originalType : CimTypeFor(spoof.type);
        }
        if (flavor) *flavor = 0;
        return hr;
    }
    HRESULT STDMETHODCALLTYPE EndEnumeration() override { return inner_->EndEnumeration(); }
    HRESULT STDMETHODCALLTYPE GetPropertyQualifierSet(LPCWSTR property,
                                                      IWbemQualifierSet** qualifierSet) override {
        return inner_->GetPropertyQualifierSet(property, qualifierSet);
    }
    HRESULT STDMETHODCALLTYPE Clone(IWbemClassObject** copy) override {
        if (!copy) return E_POINTER;
        HRESULT hr = inner_->Clone(copy);
        if (SUCCEEDED(hr) && *copy) {
            WmiObject* wrapper = new (std::nothrow) WmiObject(*copy);
            if (!wrapper) { (*copy)->Release(); *copy = nullptr; return E_OUTOFMEMORY; }
            *copy = wrapper;
        }
        return hr;
    }
    HRESULT STDMETHODCALLTYPE GetObjectText(long flags, BSTR* text) override {
        return inner_->GetObjectText(flags, text);
    }
    HRESULT STDMETHODCALLTYPE SpawnDerivedClass(long flags, IWbemClassObject** newClass) override {
        return inner_->SpawnDerivedClass(flags, newClass);
    }
    HRESULT STDMETHODCALLTYPE SpawnInstance(long flags, IWbemClassObject** newInstance) override {
        return inner_->SpawnInstance(flags, newInstance);
    }
    HRESULT STDMETHODCALLTYPE CompareTo(long flags, IWbemClassObject* compareTo) override {
        return inner_->CompareTo(flags, compareTo);
    }
    HRESULT STDMETHODCALLTYPE GetPropertyOrigin(LPCWSTR name, BSTR* className) override {
        return inner_->GetPropertyOrigin(name, className);
    }
    HRESULT STDMETHODCALLTYPE InheritsFrom(LPCWSTR ancestor) override {
        return inner_->InheritsFrom(ancestor);
    }
    HRESULT STDMETHODCALLTYPE GetMethod(LPCWSTR name, long flags, IWbemClassObject** inSignature,
                                        IWbemClassObject** outSignature) override {
        return inner_->GetMethod(name, flags, inSignature, outSignature);
    }
    HRESULT STDMETHODCALLTYPE PutMethod(LPCWSTR name, long flags, IWbemClassObject* inSignature,
                                        IWbemClassObject* outSignature) override {
        return inner_->PutMethod(name, flags, inSignature, outSignature);
    }
    HRESULT STDMETHODCALLTYPE DeleteMethod(LPCWSTR name) override { return inner_->DeleteMethod(name); }
    HRESULT STDMETHODCALLTYPE BeginMethodEnumeration(long flags) override {
        return inner_->BeginMethodEnumeration(flags);
    }
    HRESULT STDMETHODCALLTYPE NextMethod(long flags, BSTR* name, IWbemClassObject** inSignature,
                                         IWbemClassObject** outSignature) override {
        return inner_->NextMethod(flags, name, inSignature, outSignature);
    }
    HRESULT STDMETHODCALLTYPE EndMethodEnumeration() override { return inner_->EndMethodEnumeration(); }
    HRESULT STDMETHODCALLTYPE GetMethodQualifierSet(LPCWSTR method,
                                                    IWbemQualifierSet** qualifierSet) override {
        return inner_->GetMethodQualifierSet(method, qualifierSet);
    }
    HRESULT STDMETHODCALLTYPE GetMethodOrigin(LPCWSTR method, BSTR* className) override {
        return inner_->GetMethodOrigin(method, className);
    }

private:
    std::wstring ClassName() {
        if (classLoaded_) return className_;
        classLoaded_ = true;
        VARIANT value;
        VariantInit(&value);
        if (SUCCEEDED(inner_->Get(L"__CLASS", 0, &value, nullptr, nullptr)) && value.vt == VT_BSTR &&
            value.bstrVal) {
            className_.assign(value.bstrVal, SysStringLen(value.bstrVal));
        }
        VariantClear(&value);
        return className_;
    }

    IWbemClassObject* inner_;
    std::wstring className_;
    bool classLoaded_ = false;
};

class WmiSink : public IWbemObjectSink, public RefCounted {
public:
    explicit WmiSink(IWbemObjectSink* inner) : inner_(inner) {
        if (inner_) inner_->AddRef();
        AuditEventRateLimited("wmi.sink", "wrapped");
    }
    ~WmiSink() override { if (inner_) inner_->Release(); }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IWbemObjectSink) {
            *ppv = static_cast<IWbemObjectSink*>(this);
            AddRef();
            return S_OK;
        }
        return inner_->QueryInterface(riid, ppv);
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return RefCounted::AddRef(); }
    ULONG STDMETHODCALLTYPE Release() override { return RefCounted::Release(); }

    HRESULT STDMETHODCALLTYPE Indicate(LONG count, IWbemClassObject** objects) override {
        if (!inner_ || count <= 0 || !objects) return inner_ ? inner_->Indicate(count, objects) : E_POINTER;
        AuditEventRateLimited("wmi.sink", "indicate", nullptr,
                              static_cast<unsigned long long>(count), true);
        std::vector<IWbemClassObject*> forwarded;
        std::vector<WmiObject*> wrappers;
        forwarded.reserve(static_cast<size_t>(count));
        wrappers.reserve(static_cast<size_t>(count));
        for (LONG index = 0; index < count; ++index) {
            IWbemClassObject* raw = objects[index];
            if (!raw || IsVirtualNetworkObject(raw) || IsVirtualPnpObject(raw)) continue;
            raw->AddRef();
            WmiObject* wrapper = new (std::nothrow) WmiObject(raw);
            if (!wrapper) {
                raw->Release();
                for (WmiObject* previous : wrappers) previous->Release();
                return E_OUTOFMEMORY;
            }
            wrappers.push_back(wrapper);
            forwarded.push_back(wrapper);
        }
        HRESULT hr = S_OK;
        if (!forwarded.empty()) {
            hr = inner_->Indicate(static_cast<LONG>(forwarded.size()), forwarded.data());
        }
        for (WmiObject* wrapper : wrappers) wrapper->Release();
        AuditEventRateLimited("wmi.sink", "async-filtered", nullptr,
                              static_cast<unsigned long long>(forwarded.size()), true);
        return hr;
    }

    HRESULT STDMETHODCALLTYPE SetStatus(LONG flags, HRESULT result, BSTR message,
                                        IWbemClassObject* param) override {
        return inner_ ? inner_->SetStatus(flags, result, message, param) : E_POINTER;
    }

private:
    IWbemObjectSink* inner_;
};

WmiSink* WrapSink(IWbemObjectSink* sink) {
    if (!sink) return nullptr;
    return new (std::nothrow) WmiSink(sink);
}

class WmiEnum : public IEnumWbemClassObject, public RefCounted {
public:
    explicit WmiEnum(IEnumWbemClassObject* inner) : inner_(inner) {}
    ~WmiEnum() override { if (inner_) inner_->Release(); }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IEnumWbemClassObject) {
            *ppv = static_cast<IEnumWbemClassObject*>(this);
            AddRef();
            return S_OK;
        }
        return inner_->QueryInterface(riid, ppv);
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return RefCounted::AddRef(); }
    ULONG STDMETHODCALLTYPE Release() override { return RefCounted::Release(); }

    HRESULT STDMETHODCALLTYPE Reset() override {
        displayKept_ = monitorKept_ = netKept_ = audioKept_ = diskKept_ = 0;
        return inner_->Reset();
    }
    HRESULT STDMETHODCALLTYPE Next(long timeout, ULONG count, IWbemClassObject** objects,
                                   ULONG* returned) override {
        if (!objects || !returned) return inner_->Next(timeout, count, objects, returned);
        for (int attempt = 0; attempt < 64; ++attempt) {
            ULONG fetched = 0;
            const HRESULT hr = inner_->Next(timeout, count, objects, &fetched);
            if (FAILED(hr) || fetched == 0) {
                *returned = 0;
                return hr;
            }
            ULONG kept = 0;
            for (ULONG i = 0; i < fetched; ++i) {
                IWbemClassObject* raw = objects[i];
                if (!raw) continue;
                if (IsVirtualNetworkObject(raw) || IsVirtualPnpObject(raw) ||
                    CollapsePnpRow(raw)) {
                    raw->Release();
                    continue;
                }
                WmiObject* wrapper = new (std::nothrow) WmiObject(raw);
                if (!wrapper) {
                    raw->Release();
                    for (ULONG j = 0; j < kept; ++j) {
                        if (objects[j]) objects[j]->Release();
                    }
                    for (ULONG j = i + 1; j < fetched; ++j) {
                        if (objects[j]) objects[j]->Release();
                    }
                    *returned = 0;
                    return E_OUTOFMEMORY;
                }
                objects[kept++] = wrapper;
            }
            *returned = kept;
            if (kept > 0) return hr;
            if (hr == WBEM_S_FALSE) return S_FALSE;
            if (hr == WBEM_S_TIMEDOUT) return hr;
        }
        *returned = 0;
        return S_FALSE;
    }
    HRESULT STDMETHODCALLTYPE NextAsync(ULONG count, IWbemObjectSink* sink) override {
        WmiSink* wrapped = WrapSink(sink);
        if (sink && !wrapped) return E_OUTOFMEMORY;
        HRESULT hr = inner_->NextAsync(count, wrapped ? static_cast<IWbemObjectSink*>(wrapped) : sink);
        if (wrapped) wrapped->Release();
        AuditEventRateLimited("wmi.async", "NextAsync", nullptr,
                              static_cast<unsigned long long>(static_cast<unsigned long>(hr)), true);
        return hr;
    }
    HRESULT STDMETHODCALLTYPE Clone(IEnumWbemClassObject** enumerator) override {
        if (!enumerator) return E_POINTER;
        HRESULT hr = inner_->Clone(enumerator);
        if (SUCCEEDED(hr) && *enumerator) {
            WmiEnum* wrapper = new (std::nothrow) WmiEnum(*enumerator);
            if (!wrapper) { (*enumerator)->Release(); *enumerator = nullptr; return E_OUTOFMEMORY; }
            *enumerator = wrapper;
        }
        return hr;
    }
    HRESULT STDMETHODCALLTYPE Skip(long timeout, ULONG count) override {
        return inner_->Skip(timeout, count);
    }

private:
    bool CollapsePnpRow(IWbemClassObject* object) {
        const std::wstring cls = GetObjectString(object, L"__CLASS");
        if (_wcsicmp(cls.c_str(), L"Win32_PnPEntity") != 0) return false;
        const std::wstring guid = NormalizeGuidText(GetObjectString(object, L"ClassGuid"));
        int* counter = nullptr;
        if (guid == L"4d36e968e32511cebfc108002be10318") counter = &displayKept_;
        else if (guid == L"4d36e96ee32511cebfc108002be10318") counter = &monitorKept_;
        else if (guid == L"4d36e972e32511cebfc108002be10318") counter = &netKept_;
        else if (guid == L"4d36e96ce32511cebfc108002be10318") counter = &audioKept_;
        else if (guid == L"4d36e967e32511cebfc108002be10318") counter = &diskKept_;
        if (!counter) return false;
        ++(*counter);
        if (*counter > 1) {
            AuditEventRateLimited("wmi.pnp", "collapsed");
            return true;
        }
        return false;
    }

    IEnumWbemClassObject* inner_;
    int displayKept_ = 0;
    int monitorKept_ = 0;
    int netKept_ = 0;
    int audioKept_ = 0;
    int diskKept_ = 0;
};

class WmiServices : public IWbemServices, public IClientSecurity, public RefCounted {
public:
    explicit WmiServices(IWbemServices* inner) : inner_(inner) {}
    ~WmiServices() override { if (inner_) inner_->Release(); }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IWbemServices) {
            *ppv = static_cast<IWbemServices*>(this);
            AddRef();
            return S_OK;
        }
        if (riid == IID_IClientSecurity) {
            *ppv = static_cast<IClientSecurity*>(this);
            AddRef();
            return S_OK;
        }
        return inner_->QueryInterface(riid, ppv);
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return RefCounted::AddRef(); }
    ULONG STDMETHODCALLTYPE Release() override { return RefCounted::Release(); }

    HRESULT STDMETHODCALLTYPE QueryBlanket(IUnknown* pProxy, DWORD* pAuthnSvc, DWORD* pAuthzSvc,
                                           OLECHAR** pServerPrincName, DWORD* pAuthnLevel,
                                           DWORD* pImpLevel, void** pAuthInfo,
                                           DWORD* pCapabilities) override {
        return CoQueryProxyBlanket(inner_, pAuthnSvc, pAuthzSvc, pServerPrincName,
                                   pAuthnLevel, pImpLevel, pAuthInfo, pCapabilities);
    }
    HRESULT STDMETHODCALLTYPE SetBlanket(IUnknown* pProxy, DWORD AuthnSvc, DWORD AuthzSvc,
                                         OLECHAR* pServerPrincName, DWORD AuthnLevel,
                                         DWORD ImpLevel, void* pAuthInfo,
                                         DWORD Capabilities) override {
        return CoSetProxyBlanket(inner_, AuthnSvc, AuthzSvc, pServerPrincName,
                                 AuthnLevel, ImpLevel, pAuthInfo, Capabilities);
    }
    HRESULT STDMETHODCALLTYPE CopyProxy(IUnknown* pProxy, IUnknown** ppCopy) override {
        return CoCopyProxy(inner_, ppCopy);
    }

    HRESULT STDMETHODCALLTYPE OpenNamespace(const BSTR name, long flags, IWbemContext* context,
                                            IWbemServices** workingNamespace,
                                            IWbemCallResult** result) override {
        HRESULT hr = inner_->OpenNamespace(name, flags, context, workingNamespace, result);
        if (SUCCEEDED(hr) && workingNamespace && *workingNamespace) {
            IWbemServices* raw = *workingNamespace;
            WmiServices* wrapper = new (std::nothrow) WmiServices(raw);
            if (!wrapper) {
                raw->Release();
                *workingNamespace = nullptr;
                return E_OUTOFMEMORY;
            }
            *workingNamespace = wrapper;
        }
        return hr;
    }
    HRESULT STDMETHODCALLTYPE CancelAsyncCall(IWbemObjectSink* sink) override {
        return inner_->CancelAsyncCall(sink);
    }
    HRESULT STDMETHODCALLTYPE QueryObjectSink(long flags, IWbemObjectSink** handler) override {
        return inner_->QueryObjectSink(flags, handler);
    }
    HRESULT STDMETHODCALLTYPE GetObject(const BSTR path, long flags, IWbemContext* context,
                                        IWbemClassObject** object, IWbemCallResult** result) override {
        HRESULT hr = inner_->GetObject(path, flags, context, object, result);
        if (SUCCEEDED(hr) && object && *object) {
            IWbemClassObject* raw = *object;
            WmiObject* wrapper = new (std::nothrow) WmiObject(raw);
            if (!wrapper) {
                raw->Release();
                *object = nullptr;
                return E_OUTOFMEMORY;
            }
            *object = wrapper;
        }
        return hr;
    }
    HRESULT STDMETHODCALLTYPE GetObjectAsync(const BSTR path, long flags, IWbemContext* context,
                                             IWbemObjectSink* handler) override {
        WmiSink* wrapped = WrapSink(handler);
        if (handler && !wrapped) return E_OUTOFMEMORY;
        HRESULT hr = inner_->GetObjectAsync(path, flags, context,
                                            wrapped ? static_cast<IWbemObjectSink*>(wrapped) : handler);
        if (wrapped) wrapped->Release();
        AuditEventRateLimited("wmi.async", "GetObjectAsync", nullptr,
                              static_cast<unsigned long long>(static_cast<unsigned long>(hr)), true);
        return hr;
    }
    HRESULT STDMETHODCALLTYPE PutClass(IWbemClassObject* object, long flags, IWbemContext* context,
                                       IWbemCallResult** result) override {
        return inner_->PutClass(object, flags, context, result);
    }
    HRESULT STDMETHODCALLTYPE PutClassAsync(IWbemClassObject* object, long flags, IWbemContext* context,
                                            IWbemObjectSink* handler) override {
        WmiSink* wrapped = WrapSink(handler);
        if (handler && !wrapped) return E_OUTOFMEMORY;
        HRESULT hr = inner_->PutClassAsync(object, flags, context,
                                           wrapped ? static_cast<IWbemObjectSink*>(wrapped) : handler);
        if (wrapped) wrapped->Release();
        AuditEventRateLimited("wmi.async", "PutClassAsync", nullptr,
                              static_cast<unsigned long long>(static_cast<unsigned long>(hr)), true);
        return hr;
    }
    HRESULT STDMETHODCALLTYPE DeleteClass(const BSTR name, long flags, IWbemContext* context,
                                          IWbemCallResult** result) override {
        return inner_->DeleteClass(name, flags, context, result);
    }
    HRESULT STDMETHODCALLTYPE DeleteClassAsync(const BSTR name, long flags, IWbemContext* context,
                                               IWbemObjectSink* handler) override {
        WmiSink* wrapped = WrapSink(handler);
        if (handler && !wrapped) return E_OUTOFMEMORY;
        HRESULT hr = inner_->DeleteClassAsync(name, flags, context,
                                              wrapped ? static_cast<IWbemObjectSink*>(wrapped) : handler);
        if (wrapped) wrapped->Release();
        AuditEventRateLimited("wmi.async", "DeleteClassAsync", nullptr,
                              static_cast<unsigned long long>(static_cast<unsigned long>(hr)), true);
        return hr;
    }
    HRESULT STDMETHODCALLTYPE CreateClassEnum(const BSTR superclass, long flags, IWbemContext* context,
                                              IEnumWbemClassObject** enumerator) override {
        HRESULT hr = inner_->CreateClassEnum(superclass, flags, context, enumerator);
        if (SUCCEEDED(hr) && enumerator && *enumerator) {
            IEnumWbemClassObject* raw = *enumerator;
            WmiEnum* wrapper = new (std::nothrow) WmiEnum(raw);
            if (!wrapper) {
                raw->Release();
                *enumerator = nullptr;
                return E_OUTOFMEMORY;
            }
            *enumerator = wrapper;
        }
        return hr;
    }
    HRESULT STDMETHODCALLTYPE CreateClassEnumAsync(const BSTR superclass, long flags,
                                                   IWbemContext* context, IWbemObjectSink* handler) override {
        WmiSink* wrapped = WrapSink(handler);
        if (handler && !wrapped) return E_OUTOFMEMORY;
        HRESULT hr = inner_->CreateClassEnumAsync(superclass, flags, context,
                                                  wrapped ? static_cast<IWbemObjectSink*>(wrapped) : handler);
        if (wrapped) wrapped->Release();
        AuditEventRateLimited("wmi.async", "CreateClassEnumAsync", nullptr,
                              static_cast<unsigned long long>(static_cast<unsigned long>(hr)), true);
        return hr;
    }
    HRESULT STDMETHODCALLTYPE PutInstance(IWbemClassObject* instance, long flags, IWbemContext* context,
                                          IWbemCallResult** result) override {
        return inner_->PutInstance(instance, flags, context, result);
    }
    HRESULT STDMETHODCALLTYPE PutInstanceAsync(IWbemClassObject* instance, long flags,
                                               IWbemContext* context, IWbemObjectSink* handler) override {
        WmiSink* wrapped = WrapSink(handler);
        if (handler && !wrapped) return E_OUTOFMEMORY;
        HRESULT hr = inner_->PutInstanceAsync(instance, flags, context,
                                              wrapped ? static_cast<IWbemObjectSink*>(wrapped) : handler);
        if (wrapped) wrapped->Release();
        AuditEventRateLimited("wmi.async", "PutInstanceAsync", nullptr,
                              static_cast<unsigned long long>(static_cast<unsigned long>(hr)), true);
        return hr;
    }
    HRESULT STDMETHODCALLTYPE DeleteInstance(const BSTR path, long flags, IWbemContext* context,
                                             IWbemCallResult** result) override {
        return inner_->DeleteInstance(path, flags, context, result);
    }
    HRESULT STDMETHODCALLTYPE DeleteInstanceAsync(const BSTR path, long flags, IWbemContext* context,
                                                  IWbemObjectSink* handler) override {
        WmiSink* wrapped = WrapSink(handler);
        if (handler && !wrapped) return E_OUTOFMEMORY;
        HRESULT hr = inner_->DeleteInstanceAsync(path, flags, context,
                                                 wrapped ? static_cast<IWbemObjectSink*>(wrapped) : handler);
        if (wrapped) wrapped->Release();
        AuditEventRateLimited("wmi.async", "DeleteInstanceAsync", nullptr,
                              static_cast<unsigned long long>(static_cast<unsigned long>(hr)), true);
        return hr;
    }
    HRESULT STDMETHODCALLTYPE CreateInstanceEnum(const BSTR filter, long flags, IWbemContext* context,
                                                 IEnumWbemClassObject** enumerator) override {
        HRESULT hr = inner_->CreateInstanceEnum(filter, flags, context, enumerator);
        if (SUCCEEDED(hr) && enumerator && *enumerator) {
            IEnumWbemClassObject* raw = *enumerator;
            WmiEnum* wrapper = new (std::nothrow) WmiEnum(raw);
            if (!wrapper) {
                raw->Release();
                *enumerator = nullptr;
                return E_OUTOFMEMORY;
            }
            *enumerator = wrapper;
        }
        return hr;
    }
    HRESULT STDMETHODCALLTYPE CreateInstanceEnumAsync(const BSTR filter, long flags,
                                                      IWbemContext* context, IWbemObjectSink* handler) override {
        WmiSink* wrapped = WrapSink(handler);
        if (handler && !wrapped) return E_OUTOFMEMORY;
        HRESULT hr = inner_->CreateInstanceEnumAsync(filter, flags, context,
                                                     wrapped ? static_cast<IWbemObjectSink*>(wrapped) : handler);
        if (wrapped) wrapped->Release();
        AuditEventRateLimited("wmi.async", "CreateInstanceEnumAsync", nullptr,
                              static_cast<unsigned long long>(static_cast<unsigned long>(hr)), true);
        return hr;
    }
    HRESULT STDMETHODCALLTYPE ExecQuery(const BSTR language, const BSTR query, long flags,
                                        IWbemContext* context, IEnumWbemClassObject** enumerator) override {
        HRESULT hr = inner_->ExecQuery(language, query, flags, context, enumerator);
        if (SUCCEEDED(hr) && enumerator && *enumerator) {
            IEnumWbemClassObject* raw = *enumerator;
            WmiEnum* wrapper = new (std::nothrow) WmiEnum(raw);
            if (!wrapper) {
                raw->Release();
                *enumerator = nullptr;
                return E_OUTOFMEMORY;
            }
            *enumerator = wrapper;
        }
        return hr;
    }
    HRESULT STDMETHODCALLTYPE ExecQueryAsync(const BSTR language, const BSTR query, long flags,
                                             IWbemContext* context, IWbemObjectSink* handler) override {
        WmiSink* wrapped = WrapSink(handler);
        if (handler && !wrapped) return E_OUTOFMEMORY;
        HRESULT hr = inner_->ExecQueryAsync(language, query, flags, context,
                                            wrapped ? static_cast<IWbemObjectSink*>(wrapped) : handler);
        if (wrapped) wrapped->Release();
        AuditEventRateLimited("wmi.async", "ExecQueryAsync", nullptr,
                              static_cast<unsigned long long>(static_cast<unsigned long>(hr)), true);
        return hr;
    }
    HRESULT STDMETHODCALLTYPE ExecNotificationQuery(const BSTR language, const BSTR query, long flags,
                                                    IWbemContext* context,
                                                    IEnumWbemClassObject** enumerator) override {
        HRESULT hr = inner_->ExecNotificationQuery(language, query, flags, context, enumerator);
        if (SUCCEEDED(hr) && enumerator && *enumerator) {
            IEnumWbemClassObject* raw = *enumerator;
            WmiEnum* wrapper = new (std::nothrow) WmiEnum(raw);
            if (!wrapper) {
                raw->Release();
                *enumerator = nullptr;
                return E_OUTOFMEMORY;
            }
            *enumerator = wrapper;
        }
        return hr;
    }
    HRESULT STDMETHODCALLTYPE ExecNotificationQueryAsync(const BSTR language, const BSTR query,
                                                         long flags, IWbemContext* context,
                                                         IWbemObjectSink* handler) override {
        WmiSink* wrapped = WrapSink(handler);
        if (handler && !wrapped) return E_OUTOFMEMORY;
        HRESULT hr = inner_->ExecNotificationQueryAsync(language, query, flags, context,
                                                        wrapped ? static_cast<IWbemObjectSink*>(wrapped) : handler);
        if (wrapped) wrapped->Release();
        AuditEventRateLimited("wmi.async", "ExecNotificationQueryAsync", nullptr,
                              static_cast<unsigned long long>(static_cast<unsigned long>(hr)), true);
        return hr;
    }
    HRESULT STDMETHODCALLTYPE ExecMethod(const BSTR path, const BSTR method, long flags,
                                         IWbemContext* context, IWbemClassObject* inParams,
                                         IWbemClassObject** outParams, IWbemCallResult** result) override {
        HRESULT hr = inner_->ExecMethod(path, method, flags, context, inParams, outParams, result);
        if (SUCCEEDED(hr) && outParams && *outParams) {
            IWbemClassObject* raw = *outParams;
            WmiObject* wrapper = new (std::nothrow) WmiObject(raw);
            if (!wrapper) {
                raw->Release();
                *outParams = nullptr;
                return E_OUTOFMEMORY;
            }
            *outParams = wrapper;
        }
        return hr;
    }
    HRESULT STDMETHODCALLTYPE ExecMethodAsync(const BSTR path, const BSTR method, long flags,
                                              IWbemContext* context, IWbemClassObject* inParams,
                                              IWbemObjectSink* handler) override {
        WmiSink* wrapped = WrapSink(handler);
        if (handler && !wrapped) return E_OUTOFMEMORY;
        HRESULT hr = inner_->ExecMethodAsync(path, method, flags, context, inParams,
                                             wrapped ? static_cast<IWbemObjectSink*>(wrapped) : handler);
        if (wrapped) wrapped->Release();
        AuditEventRateLimited("wmi.async", "ExecMethodAsync", nullptr,
                              static_cast<unsigned long long>(static_cast<unsigned long>(hr)), true);
        return hr;
    }

private:
    IWbemServices* inner_;
};

class WmiLocator : public IWbemLocator, public RefCounted {
public:
    explicit WmiLocator(IWbemLocator* inner) : inner_(inner) {}
    ~WmiLocator() override { if (inner_) inner_->Release(); }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IWbemLocator) {
            *ppv = static_cast<IWbemLocator*>(this);
            AddRef();
            return S_OK;
        }
        return inner_->QueryInterface(riid, ppv);
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return RefCounted::AddRef(); }
    ULONG STDMETHODCALLTYPE Release() override { return RefCounted::Release(); }

    HRESULT STDMETHODCALLTYPE ConnectServer(const BSTR resource, const BSTR user, const BSTR password,
                                            const BSTR locale, long securityFlags, const BSTR authority,
                                            IWbemContext* context, IWbemServices** services) override {
        HRESULT hr = inner_->ConnectServer(resource, user, password, locale, securityFlags, authority,
                                           context, services);
        if (SUCCEEDED(hr) && services && *services) {
            WmiServices* wrapper = new (std::nothrow) WmiServices(*services);
            if (!wrapper) { (*services)->Release(); *services = nullptr; return E_OUTOFMEMORY; }
            *services = wrapper;
        }
        return hr;
    }

private:
    IWbemLocator* inner_;
};

class WmiFactory : public IClassFactory, public RefCounted {
public:
    explicit WmiFactory(IClassFactory* inner) : inner_(inner) {}
    ~WmiFactory() override { if (inner_) inner_->Release(); }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IClassFactory) {
            *ppv = static_cast<IClassFactory*>(this);
            AddRef();
            return S_OK;
        }
        return inner_->QueryInterface(riid, ppv);
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return RefCounted::AddRef(); }
    ULONG STDMETHODCALLTYPE Release() override { return RefCounted::Release(); }

    HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown* outer, REFIID riid, void** ppv) override {
        HRESULT hr = inner_->CreateInstance(outer, riid, ppv);
        if (SUCCEEDED(hr) && ppv && *ppv) {
            const HRESULT wrapHr = WrapLocator(riid, ppv);
            if (FAILED(wrapHr)) return wrapHr;
        }
        return hr;
    }
    HRESULT STDMETHODCALLTYPE LockServer(BOOL lock) override { return inner_->LockServer(lock); }

private:
    static HRESULT WrapLocator(REFIID riid, void** ppv) {
        if (!ppv || !*ppv) return E_POINTER;
        if (riid == IID_IWbemLocator) {
            IWbemLocator* raw = static_cast<IWbemLocator*>(*ppv);
            WmiLocator* wrapper = new (std::nothrow) WmiLocator(raw);
            if (wrapper) *ppv = static_cast<IWbemLocator*>(wrapper);
            else {
                raw->Release();
                *ppv = nullptr;
                return E_OUTOFMEMORY;
            }
            return S_OK;
        }
        if (riid == IID_IUnknown) {
            IUnknown* raw = static_cast<IUnknown*>(*ppv);
            IWbemLocator* locator = nullptr;
            if (SUCCEEDED(raw->QueryInterface(IID_IWbemLocator, reinterpret_cast<void**>(&locator))) && locator) {
                WmiLocator* wrapper = new (std::nothrow) WmiLocator(locator);
                if (wrapper) {
                    raw->Release();
                    *ppv = static_cast<IUnknown*>(static_cast<IWbemLocator*>(wrapper));
                } else {
                    locator->Release();
                    raw->Release();
                    *ppv = nullptr;
                    return E_OUTOFMEMORY;
                }
            }
        }
        return S_OK;
    }

    IClassFactory* inner_;
};

typedef HRESULT (WINAPI* PFN_CoCreateInstance)(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);
typedef HRESULT (WINAPI* PFN_CoCreateInstanceEx)(REFCLSID, LPUNKNOWN, DWORD, COSERVERINFO*, DWORD, MULTI_QI*);
typedef HRESULT (WINAPI* PFN_CoGetClassObject)(REFCLSID, DWORD, LPVOID, REFIID, LPVOID*);

PFN_CoCreateInstance g_origCoCreateInstance = nullptr;
PFN_CoCreateInstanceEx g_origCoCreateInstanceEx = nullptr;
PFN_CoGetClassObject g_origCoGetClassObject = nullptr;

HRESULT WrapLocatorResult(REFIID riid, void** ppv) {
    if (!ppv || !*ppv) return E_POINTER;
    if (riid == IID_IWbemLocator) {
        IWbemLocator* raw = static_cast<IWbemLocator*>(*ppv);
        WmiLocator* wrapper = new (std::nothrow) WmiLocator(raw);
        if (wrapper) *ppv = static_cast<IWbemLocator*>(wrapper);
        else {
            raw->Release();
            *ppv = nullptr;
            return E_OUTOFMEMORY;
        }
        return S_OK;
    }
    if (riid == IID_IUnknown) {
        IUnknown* raw = static_cast<IUnknown*>(*ppv);
        IWbemLocator* locator = nullptr;
        if (SUCCEEDED(raw->QueryInterface(IID_IWbemLocator, reinterpret_cast<void**>(&locator))) && locator) {
            WmiLocator* wrapper = new (std::nothrow) WmiLocator(locator);
            if (wrapper) {
                raw->Release();
                *ppv = static_cast<IUnknown*>(static_cast<IWbemLocator*>(wrapper));
            } else {
                locator->Release();
                raw->Release();
                *ppv = nullptr;
                return E_OUTOFMEMORY;
            }
        }
    }
    return S_OK;
}

bool SamePropertyKey(REFPROPERTYKEY left, REFPROPERTYKEY right) {
    return IsEqualGUID(left.fmtid, right.fmtid) && left.pid == right.pid;
}

const PROPERTYKEY kPkeyAudioEndpointFormFactor = {
    {0x1DA5D803, 0xD492, 0x4EDD, {0x8C, 0x23, 0xE0, 0xC0, 0xFF, 0xEE, 0x7F, 0x0E}}, 0};
const PROPERTYKEY kPkeyAudioEndpointGuid = {
    {0x1DA5D803, 0xD492, 0x4EDD, {0x8C, 0x23, 0xE0, 0xC0, 0xFF, 0xEE, 0x7F, 0x0E}}, 4};

HRESULT ReturnPropString(const std::string& value, PROPVARIANT* result) {
    if (!result) return E_POINTER;
    PropVariantInit(result);
    const std::wstring text = ToWide(value);
    const size_t bytes = (text.size() + 1) * sizeof(wchar_t);
    auto* copy = static_cast<LPWSTR>(CoTaskMemAlloc(bytes));
    if (!copy) return E_OUTOFMEMORY;
    std::memcpy(copy, text.c_str(), bytes);
    result->vt = VT_LPWSTR;
    result->pwszVal = copy;
    return S_OK;
}

HRESULT ReturnPropUInt32(uint32_t value, PROPVARIANT* result) {
    if (!result) return E_POINTER;
    PropVariantInit(result);
    result->vt = VT_UI4;
    result->ulVal = value;
    return S_OK;
}

class AudioPropertyStore : public IPropertyStore, public RefCounted {
public:
    explicit AudioPropertyStore(IPropertyStore* inner) : inner_(inner) {
        if (inner_) inner_->AddRef();
    }
    ~AudioPropertyStore() override { if (inner_) inner_->Release(); }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IPropertyStore) {
            *ppv = static_cast<IPropertyStore*>(this);
            AddRef();
            return S_OK;
        }
        return inner_->QueryInterface(riid, ppv);
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return RefCounted::AddRef(); }
    ULONG STDMETHODCALLTYPE Release() override { return RefCounted::Release(); }
    HRESULT STDMETHODCALLTYPE GetCount(DWORD* count) override {
        return inner_->GetCount(count);
    }
    HRESULT STDMETHODCALLTYPE GetAt(DWORD index, PROPERTYKEY* key) override {
        return inner_->GetAt(index, key);
    }
    HRESULT STDMETHODCALLTYPE GetValue(REFPROPERTYKEY key, PROPVARIANT* value) override {
        if (!NativeHardwareHooksEnabled()) return inner_->GetValue(key, value);
        const ProfileIdentity& identity = ProfileIdentity::Get();
        if (SamePropertyKey(key, PKEY_Device_FriendlyName)) {
            AuditEventRateLimited("api.audio.friendlyname", "patched");
            return ReturnPropString(identity.audioFriendlyName, value);
        }
        if (SamePropertyKey(key, PKEY_DeviceInterface_FriendlyName)) {
            AuditEventRateLimited("api.audio.interfacename", "patched");
            return ReturnPropString(identity.audioInterfaceName, value);
        }
        if (SamePropertyKey(key, kPkeyAudioEndpointGuid)) {
            AuditEventRateLimited("api.audio.endpointguid", "patched");
            return ReturnPropString(identity.audioEndpointGuid, value);
        }
        if (SamePropertyKey(key, kPkeyAudioEndpointFormFactor)) {
            AuditEventRateLimited("api.audio.formfactor", "patched");
            return ReturnPropUInt32(identity.audioFormFactor, value);
        }
        return inner_->GetValue(key, value);
    }
    HRESULT STDMETHODCALLTYPE SetValue(REFPROPERTYKEY key, REFPROPVARIANT value) override {
        return inner_->SetValue(key, value);
    }
    HRESULT STDMETHODCALLTYPE Commit() override { return inner_->Commit(); }

private:
    IPropertyStore* inner_;
};

HRESULT WrapAudioPropertyStore(IPropertyStore** store) {
    if (!store || !*store) return E_POINTER;
    auto* raw = *store;
    auto* wrapper = new (std::nothrow) AudioPropertyStore(raw);
    if (!wrapper) {
        raw->Release();
        *store = nullptr;
        return E_OUTOFMEMORY;
    }
    raw->Release();
    *store = wrapper;
    return S_OK;
}

class AudioDevice : public IMMDevice, public RefCounted {
public:
    explicit AudioDevice(IMMDevice* inner) : inner_(inner) {
        if (inner_) inner_->AddRef();
    }
    ~AudioDevice() override { if (inner_) inner_->Release(); }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == kIidMMDevice) {
            *ppv = static_cast<IMMDevice*>(this);
            AddRef();
            return S_OK;
        }
        return inner_->QueryInterface(riid, ppv);
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return RefCounted::AddRef(); }
    ULONG STDMETHODCALLTYPE Release() override { return RefCounted::Release(); }

    HRESULT STDMETHODCALLTYPE Activate(REFIID iid, DWORD clsCtx, PROPVARIANT* activation,
                                       void** outInterface) override {
        return inner_->Activate(iid, clsCtx, activation, outInterface);
    }
    HRESULT STDMETHODCALLTYPE OpenPropertyStore(DWORD access, IPropertyStore** store) override {
        HRESULT hr = inner_->OpenPropertyStore(access, store);
        if (SUCCEEDED(hr) && store && *store) {
            hr = WrapAudioPropertyStore(store);
        }
        return hr;
    }
    HRESULT STDMETHODCALLTYPE GetId(LPWSTR* id) override {
        if (!NativeHardwareHooksEnabled()) return inner_->GetId(id);
        if (!id) return E_POINTER;
        const std::wstring value = ToWide(ProfileIdentity::Get().audioEndpointId);
        const size_t bytes = (value.size() + 1) * sizeof(wchar_t);
        auto* copy = static_cast<LPWSTR>(CoTaskMemAlloc(bytes));
        if (!copy) return E_OUTOFMEMORY;
        std::memcpy(copy, value.c_str(), bytes);
        *id = copy;
        AuditEventRateLimited("api.audio.getid", "patched");
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetState(DWORD* state) override {
        return inner_->GetState(state);
    }

private:
    IMMDevice* inner_;
};

HRESULT WrapAudioDevice(REFIID riid, void** ppv) {
    if (!ppv || !*ppv) return E_POINTER;
    if (riid != kIidMMDevice && riid != IID_IUnknown) return S_OK;
    auto* raw = static_cast<IMMDevice*>(*ppv);
    auto* wrapper = new (std::nothrow) AudioDevice(raw);
    if (!wrapper) {
        raw->Release();
        *ppv = nullptr;
        return E_OUTOFMEMORY;
    }
    raw->Release();
    *ppv = static_cast<IMMDevice*>(wrapper);
    return S_OK;
}

class AudioCollection : public IMMDeviceCollection, public RefCounted {
public:
    explicit AudioCollection(IMMDeviceCollection* inner) : inner_(inner) {
        if (inner_) inner_->AddRef();
    }
    ~AudioCollection() override { if (inner_) inner_->Release(); }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == kIidMMDeviceCollection) {
            *ppv = static_cast<IMMDeviceCollection*>(this);
            AddRef();
            return S_OK;
        }
        return inner_->QueryInterface(riid, ppv);
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return RefCounted::AddRef(); }
    ULONG STDMETHODCALLTYPE Release() override { return RefCounted::Release(); }
    HRESULT STDMETHODCALLTYPE GetCount(UINT* count) override {
        return inner_->GetCount(count);
    }
    HRESULT STDMETHODCALLTYPE Item(UINT index, IMMDevice** device) override {
        HRESULT hr = inner_->Item(index, device);
        if (SUCCEEDED(hr) && device && *device) {
            hr = WrapAudioDevice(kIidMMDevice, reinterpret_cast<void**>(device));
        }
        return hr;
    }

private:
    IMMDeviceCollection* inner_;
};

HRESULT WrapAudioCollection(REFIID riid, void** ppv) {
    if (!ppv || !*ppv) return E_POINTER;
    if (riid != kIidMMDeviceCollection && riid != IID_IUnknown) return S_OK;
    auto* raw = static_cast<IMMDeviceCollection*>(*ppv);
    auto* wrapper = new (std::nothrow) AudioCollection(raw);
    if (!wrapper) {
        raw->Release();
        *ppv = nullptr;
        return E_OUTOFMEMORY;
    }
    raw->Release();
    *ppv = static_cast<IMMDeviceCollection*>(wrapper);
    return S_OK;
}

class AudioEnumerator : public IMMDeviceEnumerator, public RefCounted {
public:
    explicit AudioEnumerator(IMMDeviceEnumerator* inner) : inner_(inner) {
        if (inner_) inner_->AddRef();
    }
    ~AudioEnumerator() override { if (inner_) inner_->Release(); }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == kIidMMDeviceEnumerator) {
            *ppv = static_cast<IMMDeviceEnumerator*>(this);
            AddRef();
            return S_OK;
        }
        return inner_->QueryInterface(riid, ppv);
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return RefCounted::AddRef(); }
    ULONG STDMETHODCALLTYPE Release() override { return RefCounted::Release(); }
    HRESULT STDMETHODCALLTYPE EnumAudioEndpoints(EDataFlow flow, DWORD state,
                                                 IMMDeviceCollection** collection) override {
        HRESULT hr = inner_->EnumAudioEndpoints(flow, state, collection);
        if (SUCCEEDED(hr) && collection && *collection) {
            hr = WrapAudioCollection(kIidMMDeviceCollection,
                                     reinterpret_cast<void**>(collection));
        }
        return hr;
    }
    HRESULT STDMETHODCALLTYPE GetDefaultAudioEndpoint(EDataFlow flow, ERole role,
                                                      IMMDevice** device) override {
        HRESULT hr = inner_->GetDefaultAudioEndpoint(flow, role, device);
        if (SUCCEEDED(hr) && device && *device) {
            hr = WrapAudioDevice(kIidMMDevice, reinterpret_cast<void**>(device));
        }
        return hr;
    }
    HRESULT STDMETHODCALLTYPE GetDevice(LPCWSTR id, IMMDevice** device) override {
        HRESULT hr = inner_->GetDevice(id, device);
        if (SUCCEEDED(hr) && device && *device) {
            hr = WrapAudioDevice(kIidMMDevice, reinterpret_cast<void**>(device));
        }
        return hr;
    }
    HRESULT STDMETHODCALLTYPE RegisterEndpointNotificationCallback(
        IMMNotificationClient* client) override {
        return inner_->RegisterEndpointNotificationCallback(client);
    }
    HRESULT STDMETHODCALLTYPE UnregisterEndpointNotificationCallback(
        IMMNotificationClient* client) override {
        return inner_->UnregisterEndpointNotificationCallback(client);
    }

private:
    IMMDeviceEnumerator* inner_;
};

HRESULT WrapAudioEnumerator(REFIID riid, void** ppv) {
    if (!ppv || !*ppv) return E_POINTER;
    if (riid != kIidMMDeviceEnumerator && riid != IID_IUnknown) return S_OK;
    auto* raw = static_cast<IMMDeviceEnumerator*>(*ppv);
    auto* wrapper = new (std::nothrow) AudioEnumerator(raw);
    if (!wrapper) {
        raw->Release();
        *ppv = nullptr;
        return E_OUTOFMEMORY;
    }
    raw->Release();
    *ppv = static_cast<IMMDeviceEnumerator*>(wrapper);
    return S_OK;
}

HRESULT WINAPI HookCoCreateInstance(REFCLSID clsid, LPUNKNOWN outer, DWORD context, REFIID riid,
                                    LPVOID* ppv) {
    HRESULT hr = g_origCoCreateInstance ? g_origCoCreateInstance(clsid, outer, context, riid, ppv)
                                        : E_NOTIMPL;
    if (SUCCEEDED(hr) && ppv && IsEqualCLSID(clsid, CLSID_WbemLocator)) {
        const HRESULT wrapHr = WrapLocatorResult(riid, ppv);
        if (FAILED(wrapHr)) return wrapHr;
        AuditEventRateLimited("wmi.install", "wrapped");
    }
    if (SUCCEEDED(hr) && ppv && IsEqualCLSID(clsid, kClsidMMDeviceEnumerator)) {
        const HRESULT wrapHr = WrapAudioEnumerator(riid, ppv);
        if (FAILED(wrapHr)) return wrapHr;
        AuditEventRateLimited("audio.enumerator", "wrapped");
    }
    return hr;
}

HRESULT WINAPI HookCoCreateInstanceEx(REFCLSID clsid, LPUNKNOWN outer, DWORD context,
                                      COSERVERINFO* server, DWORD count, MULTI_QI* results) {
    HRESULT hr = g_origCoCreateInstanceEx
        ? g_origCoCreateInstanceEx(clsid, outer, context, server, count, results)
        : E_NOTIMPL;
    if (SUCCEEDED(hr) && results && IsEqualCLSID(clsid, CLSID_WbemLocator)) {
        for (DWORD i = 0; i < count; ++i) {
            if (results[i].hr == S_OK && results[i].pItf && results[i].pIID) {
                void* pointer = results[i].pItf;
                const HRESULT wrapHr = WrapLocatorResult(*results[i].pIID, &pointer);
                results[i].pItf = static_cast<IUnknown*>(pointer);
                if (FAILED(wrapHr)) {
                    results[i].hr = wrapHr;
                    hr = wrapHr;
                }
            }
        }
        AuditEventRateLimited("wmi.install", "wrapped-ex");
    }
    return hr;
}

HRESULT WINAPI HookCoGetClassObject(REFCLSID clsid, DWORD context, LPVOID reserved, REFIID riid,
                                    LPVOID* ppv) {
    HRESULT hr = g_origCoGetClassObject ? g_origCoGetClassObject(clsid, context, reserved, riid, ppv)
                                        : E_NOTIMPL;
    if (SUCCEEDED(hr) && ppv && *ppv && IsEqualCLSID(clsid, CLSID_WbemLocator)) {
        if (riid == IID_IClassFactory) {
            IClassFactory* raw = static_cast<IClassFactory*>(*ppv);
            WmiFactory* wrapper = new (std::nothrow) WmiFactory(raw);
            if (wrapper) *ppv = static_cast<IClassFactory*>(wrapper);
            else {
                raw->Release();
                *ppv = nullptr;
                return E_OUTOFMEMORY;
            }
        } else if (riid == IID_IUnknown) {
            IUnknown* raw = static_cast<IUnknown*>(*ppv);
            IClassFactory* factory = nullptr;
            if (SUCCEEDED(raw->QueryInterface(IID_IClassFactory, reinterpret_cast<void**>(&factory))) && factory) {
                WmiFactory* wrapper = new (std::nothrow) WmiFactory(factory);
                if (wrapper) {
                    raw->Release();
                    *ppv = static_cast<IUnknown*>(static_cast<IClassFactory*>(wrapper));
                } else {
                    factory->Release();
                    raw->Release();
                    *ppv = nullptr;
                    return E_OUTOFMEMORY;
                }
            }
        }
        AuditEventRateLimited("wmi.install", "wrapped-factory");
    }
    return hr;
}

}  // namespace

void InstallWmiHooks() {
    InstallHookInlinePrimary("ole32.dll", "CoCreateInstance", reinterpret_cast<void*>(&HookCoCreateInstance),
                             reinterpret_cast<void**>(&g_origCoCreateInstance));
    InstallHookInlinePrimary("ole32.dll", "CoCreateInstanceEx", reinterpret_cast<void*>(&HookCoCreateInstanceEx),
                             reinterpret_cast<void**>(&g_origCoCreateInstanceEx));
    InstallHookInlinePrimary("ole32.dll", "CoGetClassObject", reinterpret_cast<void*>(&HookCoGetClassObject),
                             reinterpret_cast<void**>(&g_origCoGetClassObject));
}

