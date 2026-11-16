#pragma once

#include <cstring>
#include <string>

namespace cac {

inline bool PatchNvmeIdentifyBuffer(void* output, DWORD available, const std::string& serial,
                                    const std::string& model, const char* firmware) {
    if (!output || !firmware || available < sizeof(STORAGE_PROTOCOL_DATA_DESCRIPTOR)) {
        return false;
    }
    auto* descriptor = static_cast<STORAGE_PROTOCOL_DATA_DESCRIPTOR*>(output);
    STORAGE_PROTOCOL_SPECIFIC_DATA& specific = descriptor->ProtocolSpecificData;
    if (specific.ProtocolType != ProtocolTypeNvme || specific.DataType != 1) return false;
    const DWORD relative = specific.ProtocolDataOffset;
    const DWORD length = specific.ProtocolDataLength;
    if (relative < sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA) || length < 72) return false;
    BYTE* payload = reinterpret_cast<BYTE*>(&specific) + relative;
    const BYTE* end = static_cast<const BYTE*>(output) + available;
    if (payload + 72 > end) return false;
    std::memset(payload + 4, ' ', 20);
    std::memcpy(payload + 4, serial.data(), serial.size() < 20 ? serial.size() : 20);
    std::memset(payload + 24, ' ', 40);
    std::memcpy(payload + 24, model.data(), model.size() < 40 ? model.size() : 40);
    std::memset(payload + 64, ' ', 8);
    std::memcpy(payload + 64, firmware, 8);
    return true;
}

}  // namespace cac
