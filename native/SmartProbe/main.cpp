#define _WIN32_WINNT 0x0A00
#define NTDDI_VERSION 0x0A000000

#include <windows.h>
#include <winioctl.h>
#include <ntddstor.h>
#include <ntddscsi.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#ifndef IOCTL_SMART_RECEIVE_DRIVE_DATA
#define IOCTL_SMART_RECEIVE_DRIVE_DATA 0x0007C088
#endif

namespace {

std::string BufferString(const BYTE* base, DWORD offset, DWORD available) {
    if (!base || offset == 0 || offset >= available) return std::string();
    const char* text = reinterpret_cast<const char*>(base + offset);
    size_t length = 0;
    while (offset + length < available && text[length] && length < 256) ++length;
    return std::string(text, length);
}

void PrintDeviceDescriptor(HANDLE drive) {
    STORAGE_PROPERTY_QUERY query = {};
    query.PropertyId = StorageDeviceProperty;
    query.QueryType = PropertyStandardQuery;
    std::vector<BYTE> buffer(2048);
    DWORD returned = 0;
    if (!DeviceIoControl(drive, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query), buffer.data(),
                         static_cast<DWORD>(buffer.size()), &returned, nullptr)) {
        std::printf("descriptor_state=ioctl-failed error=%lu\n", GetLastError());
        return;
    }
    const auto* descriptor = reinterpret_cast<const STORAGE_DEVICE_DESCRIPTOR*>(buffer.data());
    const DWORD available = returned < buffer.size() ? returned : static_cast<DWORD>(buffer.size());
    std::printf("descriptor_state=ok\n");
    std::printf("disk_vendor=%s\n", BufferString(buffer.data(), descriptor->VendorIdOffset, available).c_str());
    std::printf("disk_model=%s\n", BufferString(buffer.data(), descriptor->ProductIdOffset, available).c_str());
    std::printf("disk_firmware=%s\n", BufferString(buffer.data(), descriptor->ProductRevisionOffset, available).c_str());
    std::printf("disk_serial=%s\n", BufferString(buffer.data(), descriptor->SerialNumberOffset, available).c_str());
}

void PrintSmart(HANDLE drive) {
    SENDCMDINPARAMS input = {};
    input.cBufferSize = 512;
    input.irDriveRegs.bFeaturesReg = 0xD0;  // SMART READ DATA
    input.irDriveRegs.bSectorCountReg = 1;
    input.irDriveRegs.bSectorNumberReg = 1;
    input.irDriveRegs.bCylLowReg = 0x4F;
    input.irDriveRegs.bCylHighReg = 0xC2;
    input.irDriveRegs.bDriveHeadReg = 0xA0;
    input.irDriveRegs.bCommandReg = 0xB0;
    input.bDriveNumber = 0;
    std::vector<BYTE> output(sizeof(SENDCMDOUTPARAMS) + 512);
    DWORD returned = 0;
    if (!DeviceIoControl(drive, IOCTL_SMART_RECEIVE_DRIVE_DATA, &input, sizeof(input),
                         output.data(), static_cast<DWORD>(output.size()), &returned, nullptr)) {
        std::printf("smart_state=ioctl-failed error=%lu\n", GetLastError());
        return;
    }
    const auto* result = reinterpret_cast<const SENDCMDOUTPARAMS*>(output.data());
    const BYTE* data = result->bBuffer;
    std::printf("smart_state=ok\n");
    std::printf("smart_version=0x%02x%02x\n", data[1], data[0]);
    for (int index = 0; index < 12; ++index) {
        const BYTE* attribute = data + 2 + index * 12;
        if (attribute[0] == 0) continue;
        const unsigned raw = attribute[5] | (attribute[6] << 8) | (attribute[7] << 16) |
                             (attribute[8] << 24);
        std::printf("smart_attr%u=%u/%u/%u\n", attribute[0], attribute[3], attribute[4], raw);
    }
}

void PrintFirmware(HANDLE drive) {
    STORAGE_HW_FIRMWARE_INFO_QUERY query = {};
    query.Version = sizeof(query);
    query.Size = sizeof(query);
    std::vector<BYTE> output(4096);
    DWORD returned = 0;
    if (!DeviceIoControl(drive, IOCTL_STORAGE_FIRMWARE_GET_INFO, &query, sizeof(query),
                         output.data(), static_cast<DWORD>(output.size()), &returned, nullptr)) {
        std::printf("firmware_state=ioctl-failed error=%lu\n", GetLastError());
        return;
    }
    const auto* info = reinterpret_cast<const STORAGE_HW_FIRMWARE_INFO*>(output.data());
    std::printf("firmware_state=ok\n");
    std::printf("firmware_head=%02x%02x%02x%02x%02x%02x%02x%02x\n", output[0], output[1],
                output[2], output[3], output[4], output[5], output[6], output[7]);
    std::printf("firmware_version=%u\n", info->Version);
    std::printf("firmware_slots=%u\n", info->SlotCount);
    if (info->SlotCount > 0) {
        char revision[17] = {};
        std::memcpy(revision, info->Slot[0].Revision, 16);
        std::printf("firmware_slot0=%s\n", revision);
    }
}

void PrintNvme(HANDLE drive) {
    struct Input {
        STORAGE_PROPERTY_QUERY query;
        STORAGE_PROTOCOL_SPECIFIC_DATA specific;
    } input = {};
    input.query.PropertyId = StorageAdapterProtocolSpecificProperty;
    input.query.QueryType = PropertyStandardQuery;
    input.specific.ProtocolType = ProtocolTypeNvme;
    input.specific.DataType = 1;  // NVMeDataTypeIdentify
    input.specific.ProtocolDataRequestValue = 1;  // NVME_IDENTIFY_CNS_CONTROLLER
    input.specific.ProtocolDataOffset = sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA);
    input.specific.ProtocolDataLength = 4096;
    std::vector<BYTE> output(8192);
    DWORD returned = 0;
    if (!DeviceIoControl(drive, IOCTL_STORAGE_QUERY_PROPERTY, &input, sizeof(input), output.data(),
                         static_cast<DWORD>(output.size()), &returned, nullptr)) {
        std::printf("nvme_state=unsupported error=%lu\n", GetLastError());
        return;
    }
    const auto* descriptor = reinterpret_cast<const STORAGE_PROTOCOL_DATA_DESCRIPTOR*>(output.data());
    const STORAGE_PROTOCOL_SPECIFIC_DATA& specific = descriptor->ProtocolSpecificData;
    if (specific.ProtocolType != ProtocolTypeNvme || specific.ProtocolDataLength < 72) {
        std::printf("nvme_state=no-payload\n");
        return;
    }
    const BYTE* payload = reinterpret_cast<const BYTE*>(&specific) + specific.ProtocolDataOffset;
    char serial[21] = {};
    char model[41] = {};
    char firmware[9] = {};
    std::memcpy(serial, payload + 4, 20);
    std::memcpy(model, payload + 24, 40);
    std::memcpy(firmware, payload + 64, 8);
    std::printf("nvme_state=ok\n");
    std::printf("nvme_serial=%s\n", serial);
    std::printf("nvme_model=%s\n", model);
    std::printf("nvme_firmware=%s\n", firmware);
}

}  // namespace

int wmain() {
    HANDLE drive = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_READ | GENERIC_WRITE,
                               FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0,
                               nullptr);
    if (drive == INVALID_HANDLE_VALUE) {
        drive = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0,
                            nullptr);
    }
    if (drive == INVALID_HANDLE_VALUE) {
        std::printf("smart_probe_state=open-failed error=%lu\n", GetLastError());
        return 2;
    }
    PrintDeviceDescriptor(drive);
    PrintSmart(drive);
    PrintFirmware(drive);
    PrintNvme(drive);
    CloseHandle(drive);
    return 0;
}
