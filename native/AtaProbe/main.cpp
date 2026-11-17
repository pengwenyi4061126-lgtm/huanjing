#include <windows.h>
#include <winioctl.h>
#include <ntddscsi.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static std::string AtaString(const unsigned char* identify, int firstWord, int words) {
    std::string text;
    for (int i = 0; i < words; ++i) {
        const int offset = (firstWord + i) * 2;
        text.push_back(static_cast<char>(identify[offset + 1]));
        text.push_back(static_cast<char>(identify[offset]));
    }
    while (!text.empty() && (text.back() == ' ' || text.back() == '\0')) text.pop_back();
    return text;
}

int wmain() {
    HANDLE drive = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_READ | GENERIC_WRITE,
                               FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0,
                               nullptr);
    if (drive == INVALID_HANDLE_VALUE) {
        std::printf("ata_state=open-failed error=%lu\n", GetLastError());
        return 2;
    }
    const DWORD dataSize = 512;
    std::vector<unsigned char> buffer(sizeof(ATA_PASS_THROUGH_EX) + dataSize, 0);
    auto* request = reinterpret_cast<ATA_PASS_THROUGH_EX*>(buffer.data());
    request->Length = sizeof(ATA_PASS_THROUGH_EX);
    request->AtaFlags = ATA_FLAGS_DATA_IN;
    request->DataTransferLength = dataSize;
    request->TimeOutValue = 10;
    request->DataBufferOffset = sizeof(ATA_PASS_THROUGH_EX);
    request->CurrentTaskFile[6] = 0xEC;  // IDENTIFY DEVICE
    DWORD returned = 0;
    if (!DeviceIoControl(drive, IOCTL_ATA_PASS_THROUGH, buffer.data(),
                         static_cast<DWORD>(buffer.size()), buffer.data(),
                         static_cast<DWORD>(buffer.size()), &returned, nullptr)) {
        std::printf("ata_state=ioctl-failed error=%lu\n", GetLastError());
        CloseHandle(drive);
        return 3;
    }
    const unsigned char* identify = buffer.data() + sizeof(ATA_PASS_THROUGH_EX);
    const std::string serial = AtaString(identify, 10, 10);
    const std::string firmware = AtaString(identify, 23, 4);
    const std::string model = AtaString(identify, 27, 20);
    std::printf("ata_state=ok\n");
    std::printf("ata_model=%s\n", model.c_str());
    std::printf("ata_serial=%s\n", serial.c_str());
    std::printf("ata_firmware=%s\n", firmware.c_str());
    CloseHandle(drive);
    return 0;
}
