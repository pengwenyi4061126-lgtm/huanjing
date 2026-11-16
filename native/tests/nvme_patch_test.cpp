#include <windows.h>
#include <winioctl.h>
#include <ntddstor.h>

#include <cstdio>
#include <cstring>
#include <vector>

#include "../NativeBridge/StorageIdentity.h"

int wmain() {
    std::vector<BYTE> buffer(sizeof(STORAGE_PROTOCOL_DATA_DESCRIPTOR) + 4096, 0xAA);
    auto* descriptor = reinterpret_cast<STORAGE_PROTOCOL_DATA_DESCRIPTOR*>(buffer.data());
    descriptor->ProtocolSpecificData.ProtocolType = ProtocolTypeNvme;
    descriptor->ProtocolSpecificData.DataType = 1;
    descriptor->ProtocolSpecificData.ProtocolDataOffset =
        sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA);
    descriptor->ProtocolSpecificData.ProtocolDataLength = 72;

    if (!cac::PatchNvmeIdentifyBuffer(buffer.data(), static_cast<DWORD>(buffer.size()),
                                      "TESTSERIAL123", "TESTMODEL", "1.2.3")) {
        std::printf("nvme_patch_test=fail reason=not-applied\n");
        return 2;
    }
    const BYTE* payload =
        reinterpret_cast<const BYTE*>(&descriptor->ProtocolSpecificData) +
        descriptor->ProtocolSpecificData.ProtocolDataOffset;
    char serial[21] = {};
    char model[41] = {};
    char firmware[9] = {};
    std::memcpy(serial, payload + 4, 20);
    std::memcpy(model, payload + 24, 40);
    std::memcpy(firmware, payload + 64, 8);
    if (std::strncmp(serial, "TESTSERIAL123", 13) != 0 ||
        std::strncmp(model, "TESTMODEL", 9) != 0 ||
        std::strncmp(firmware, "1.2.3", 5) != 0) {
        std::printf("nvme_patch_test=fail serial=%s model=%s firmware=%s\n", serial, model,
                    firmware);
        return 3;
    }
    std::printf("nvme_patch_test=pass\n");
    std::printf("nvme_patch_serial=%s\n", serial);
    std::printf("nvme_patch_model=%s\n", model);
    std::printf("nvme_patch_firmware=%s\n", firmware);
    return 0;
}
