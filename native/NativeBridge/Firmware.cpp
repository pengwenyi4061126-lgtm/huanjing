#include "Firmware.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>

namespace {

struct SmbiosStringSet {
    BYTE* begin;
    DWORD length;
    int count;
};

BYTE* FindStringSetEnd(BYTE* begin, BYTE* end) {
    BYTE* p = begin;
    while (p + 1 < end) {
        if (p[0] == 0 && p[1] == 0) return p + 2;
        ++p;
    }
    return nullptr;
}

char* GetString(BYTE* begin, BYTE* setEnd, int index) {
    if (index <= 0) return nullptr;
    int current = 1;
    BYTE* p = begin;
    while (p < setEnd - 2) {
        char* value = reinterpret_cast<char*>(p);
        size_t max = static_cast<size_t>(setEnd - p);
        size_t len = strnlen(value, max);
        if (len >= max) return nullptr;
        if (current == index) return value;
        p += len + 1;
        ++current;
    }
    return nullptr;
}

void ReplaceFixed(char* destination, size_t originalLength, const std::string& desired, int* counter) {
    if (!destination || originalLength == 0) return;
    const size_t copy = desired.size() < originalLength ? desired.size() : originalLength;
    std::memcpy(destination, desired.data(), copy);
    if (copy < originalLength) {
        std::memset(destination + copy, ' ', originalLength - copy);
    }
    destination[originalLength] = 0;
    if (counter) ++(*counter);
}

void PatchStringByIndex(BYTE* structure, BYTE* stringsBegin, BYTE* stringsEnd,
                        int offset, int index, const std::string& desired, int* counter) {
    if (structure[1] <= offset) return;
    char* value = GetString(stringsBegin, stringsEnd, index);
    if (!value) return;
    const size_t max = static_cast<size_t>(stringsEnd - reinterpret_cast<BYTE*>(value));
    const size_t len = strnlen(value, max);
    if (len == 0 || len >= max) return;
    ReplaceFixed(value, len, desired, counter);
}

void PatchAllStrings(BYTE* stringsBegin, BYTE* stringsEnd, const char* desired, int* counter) {
    BYTE* p = stringsBegin;
    while (p + 1 < stringsEnd && p[0] != 0) {
        char* value = reinterpret_cast<char*>(p);
        const size_t max = static_cast<size_t>(stringsEnd - p);
        const size_t len = strnlen(value, max);
        if (len == 0 || len >= max) break;
        ReplaceFixed(value, len, desired, counter);
        p += len + 1;
    }
}

void PatchWord(BYTE* structure, BYTE structLength, int offset, uint16_t value, int* counter) {
    if (structLength < offset + 2) return;
    std::memcpy(structure + offset, &value, sizeof(value));
    if (counter) ++(*counter);
}

void PatchByte(BYTE* structure, BYTE structLength, int offset, uint8_t value, int* counter) {
    if (structLength <= offset) return;
    structure[offset] = value;
    if (counter) ++(*counter);
}

void PatchDword(BYTE* structure, BYTE structLength, int offset, uint32_t value, int* counter) {
    if (structLength < offset + 4) return;
    std::memcpy(structure + offset, &value, sizeof(value));
    if (counter) ++(*counter);
}

void PatchQword(BYTE* structure, BYTE structLength, int offset, uint64_t value, int* counter) {
    if (structLength < offset + 8) return;
    std::memcpy(structure + offset, &value, sizeof(value));
    if (counter) ++(*counter);
}

bool ParseHex(const std::string& hex, BYTE* out, size_t count) {
    if (hex.size() < count * 2) return false;
    for (size_t i = 0; i < count; ++i) {
        char pair[3] = { hex[i * 2], hex[i * 2 + 1], 0 };
        char* end = nullptr;
        const unsigned long value = strtoul(pair, &end, 16);
        if (end == pair) return false;
        out[i] = static_cast<BYTE>(value);
    }
    return true;
}

}  // namespace

bool PatchSmbiosBuffer(BYTE* buffer, DWORD length, const ProfileIdentity& identity, int* patchedFields) {
    if (!buffer || length < 0x20) return false;
    if (patchedFields) *patchedFields = 0;

    BYTE* table = buffer;
    DWORD tableLength = length;

    // RawSMBIOSData header: Used20CallingMethod, Major, Minor, DmiRevision, Length(4)
    if (length >= 8 + 0x12) {
        const DWORD declared = *reinterpret_cast<DWORD*>(buffer + 4);
        const BYTE firstType = buffer[8];
        const BYTE firstLength = buffer[9];
        if (buffer[0] == 0 && buffer[1] >= 2 && buffer[1] <= 3 && declared > 0 &&
            declared <= length - 8 && firstType == 0 && firstLength >= 0x12) {
            table = buffer + 8;
            tableLength = declared;
        }
    }

    BYTE* cursor = table;
    BYTE* end = table + tableLength;
    int patched = 0;

    while (cursor + 4 <= end) {
        const BYTE type = cursor[0];
        const BYTE structLength = cursor[1];
        if (structLength < 4 || cursor + structLength > end) break;
        BYTE* stringsBegin = cursor + structLength;
        BYTE* stringsEnd = FindStringSetEnd(stringsBegin, end);
        if (!stringsEnd) break;

        if (type == 0) {  // BIOS information
            if (structLength > 0x05) PatchStringByIndex(cursor, stringsBegin, stringsEnd, 0x05, cursor[0x05], identity.biosVersion, &patched);
            if (structLength > 0x08) PatchStringByIndex(cursor, stringsBegin, stringsEnd, 0x08, cursor[0x08], identity.biosReleaseDate, &patched);
        } else if (type == 1) {  // System information
            if (structLength > 0x04) PatchStringByIndex(cursor, stringsBegin, stringsEnd, 0x04, cursor[0x04], identity.systemManufacturer, &patched);
            if (structLength > 0x05) PatchStringByIndex(cursor, stringsBegin, stringsEnd, 0x05, cursor[0x05], identity.systemProduct, &patched);
            if (structLength > 0x06) PatchStringByIndex(cursor, stringsBegin, stringsEnd, 0x06, cursor[0x06], identity.systemVersion, &patched);
            if (structLength > 0x07) PatchStringByIndex(cursor, stringsBegin, stringsEnd, 0x07, cursor[0x07], identity.systemSerial, &patched);
            if (structLength >= 0x08 + 16) {
                BYTE uuid[16] = {};
                if (ParseHex(identity.systemUuid, uuid, sizeof(uuid))) {
                    std::memcpy(cursor + 0x08, uuid, sizeof(uuid));
                    ++patched;
                }
            }
            if (structLength > 0x19) PatchStringByIndex(cursor, stringsBegin, stringsEnd, 0x19, cursor[0x19], "Default string", &patched);
            if (structLength > 0x1A) PatchStringByIndex(cursor, stringsBegin, stringsEnd, 0x1A, cursor[0x1A], "Default string", &patched);
        } else if (type == 2) {  // Baseboard
            if (structLength > 0x04) PatchStringByIndex(cursor, stringsBegin, stringsEnd, 0x04, cursor[0x04], identity.boardManufacturer, &patched);
            if (structLength > 0x05) PatchStringByIndex(cursor, stringsBegin, stringsEnd, 0x05, cursor[0x05], identity.boardProduct, &patched);
            if (structLength > 0x06) PatchStringByIndex(cursor, stringsBegin, stringsEnd, 0x06, cursor[0x06], identity.boardVersion, &patched);
            if (structLength > 0x07) PatchStringByIndex(cursor, stringsBegin, stringsEnd, 0x07, cursor[0x07], identity.boardSerial, &patched);
            if (structLength > 0x08) PatchStringByIndex(cursor, stringsBegin, stringsEnd, 0x08, cursor[0x08], identity.boardAssetTag, &patched);
        } else if (type == 3) {  // Chassis
            if (structLength > 0x04) PatchStringByIndex(cursor, stringsBegin, stringsEnd, 0x04, cursor[0x04], identity.systemManufacturer, &patched);
            if (structLength > 0x05) PatchStringByIndex(cursor, stringsBegin, stringsEnd, 0x05, cursor[0x05], identity.systemVersion, &patched);
            if (structLength > 0x06) PatchStringByIndex(cursor, stringsBegin, stringsEnd, 0x06, cursor[0x06], identity.systemSerial, &patched);
            if (structLength > 0x07) PatchStringByIndex(cursor, stringsBegin, stringsEnd, 0x07, cursor[0x07], identity.chassisAssetTag, &patched);
        } else if (type == 4) {  // Processor
            if (structLength > 0x07) PatchStringByIndex(cursor, stringsBegin, stringsEnd, 0x07, cursor[0x07], "GenuineIntel", &patched);
            if (structLength >= 0x10) {
                BYTE processor[8] = {};
                if (ParseHex(identity.processorId, processor, sizeof(processor))) {
                    std::memcpy(cursor + 0x08, processor, sizeof(processor));
                    ++patched;
                }
            }
            if (structLength > 0x10) PatchStringByIndex(cursor, stringsBegin, stringsEnd, 0x10, cursor[0x10], identity.processorName, &patched);
            if (structLength > 0x20) PatchStringByIndex(cursor, stringsBegin, stringsEnd, 0x20, cursor[0x20], identity.processorId, &patched);
            if (structLength > 0x21) PatchStringByIndex(cursor, stringsBegin, stringsEnd, 0x21, cursor[0x21], identity.chassisAssetTag, &patched);
            if (structLength > 0x22) PatchStringByIndex(cursor, stringsBegin, stringsEnd, 0x22, cursor[0x22], identity.processorName, &patched);
            if (structLength > 0x23) PatchByte(cursor, structLength, 0x23, static_cast<uint8_t>(identity.cpuCores), &patched);
            if (structLength > 0x24) PatchByte(cursor, structLength, 0x24, static_cast<uint8_t>(identity.cpuCores), &patched);
            if (structLength > 0x25) PatchByte(cursor, structLength, 0x25, static_cast<uint8_t>(identity.cpuLogical), &patched);
        } else if (type == 9) {  // System slots
            if (structLength > 0x04) PatchStringByIndex(cursor, stringsBegin, stringsEnd, 0x04, cursor[0x04], "PCI Slot", &patched);
        } else if (type == 10) {  // On-board devices
            if (structLength > 0x04) PatchStringByIndex(cursor, stringsBegin, stringsEnd, 0x04, cursor[0x04], "Onboard Device", &patched);
        } else if (type == 11) {  // OEM strings
            PatchAllStrings(stringsBegin, stringsEnd, "OEM String", &patched);
        } else if (type == 12) {  // System configuration
            PatchAllStrings(stringsBegin, stringsEnd, "Default", &patched);
        } else if (type == 13) {  // BIOS language
            PatchAllStrings(stringsBegin, stringsEnd, "en-US", &patched);
        } else if (type == 16) {  // Physical memory array
            PatchDword(cursor, structLength, 0x07,
                       static_cast<uint32_t>(identity.memoryTotalMb * 1024ULL), &patched);
            PatchQword(cursor, structLength, 0x0F,
                       identity.memoryTotalMb * 1024ULL * 1024ULL, &patched);
        } else if (type == 17) {  // Memory device
            uint16_t originalSize = 0;
            if (structLength >= 0x0E) {
                std::memcpy(&originalSize, cursor + 0x0C, sizeof(originalSize));
            }
            const bool populated = originalSize != 0 && originalSize != 0xFFFF;
            if (populated) {
                const uint32_t moduleMb = static_cast<uint32_t>(identity.memoryModuleMb);
                if (moduleMb > 0x7FFF) {
                    PatchWord(cursor, structLength, 0x0C, 0x7FFF, &patched);
                    PatchDword(cursor, structLength, 0x1C, moduleMb, &patched);
                } else {
                    PatchWord(cursor, structLength, 0x0C, static_cast<uint16_t>(moduleMb), &patched);
                }
                PatchWord(cursor, structLength, 0x15, static_cast<uint16_t>(identity.memorySpeedMhz), &patched);
                if (structLength > 0x17) PatchStringByIndex(cursor, stringsBegin, stringsEnd, 0x17, cursor[0x17], identity.memoryVendor, &patched);
                if (structLength > 0x18) PatchStringByIndex(cursor, stringsBegin, stringsEnd, 0x18, cursor[0x18], identity.systemSerial, &patched);
                if (structLength > 0x19) PatchStringByIndex(cursor, stringsBegin, stringsEnd, 0x19, cursor[0x19], identity.boardAssetTag, &patched);
                if (structLength > 0x1A) PatchStringByIndex(cursor, stringsBegin, stringsEnd, 0x1A, cursor[0x1A], identity.memoryPart, &patched);
                PatchWord(cursor, structLength, 0x20, static_cast<uint16_t>(identity.memorySpeedMhz), &patched);
            }
        } else if (type == 39) {  // Power supply
            if (structLength > 0x05) PatchStringByIndex(cursor, stringsBegin, stringsEnd, 0x05, cursor[0x05], "Internal", &patched);
            if (structLength > 0x06) PatchStringByIndex(cursor, stringsBegin, stringsEnd, 0x06, cursor[0x06], "Power Supply", &patched);
            if (structLength > 0x07) PatchStringByIndex(cursor, stringsBegin, stringsEnd, 0x07, cursor[0x07], "Generic", &patched);
            if (structLength > 0x08) PatchStringByIndex(cursor, stringsBegin, stringsEnd, 0x08, cursor[0x08], identity.systemSerial, &patched);
            if (structLength > 0x09) PatchStringByIndex(cursor, stringsBegin, stringsEnd, 0x09, cursor[0x09], identity.chassisAssetTag, &patched);
            if (structLength > 0x0A) PatchStringByIndex(cursor, stringsBegin, stringsEnd, 0x0A, cursor[0x0A], "Generic PSU", &patched);
            if (structLength > 0x0B) PatchStringByIndex(cursor, stringsBegin, stringsEnd, 0x0B, cursor[0x0B], "1.0", &patched);
        } else if (type == 41 || type == 42) {  // Onboard extended / onboard
            if (structLength > 0x04) PatchStringByIndex(cursor, stringsBegin, stringsEnd, 0x04, cursor[0x04], "Onboard", &patched);
        } else if (type == 43) {  // TPM device
            if (identity.tpmPresent) {
                const uint32_t vendor = 0x00465849;  // "IFX\0"
                PatchDword(cursor, structLength, 0x04, vendor, &patched);
                if (structLength > 0x08) cursor[0x08] = 2;
                if (structLength > 0x09) cursor[0x09] = 0;
                PatchDword(cursor, structLength, 0x0A, 0, &patched);
                PatchDword(cursor, structLength, 0x0E, 0, &patched);
                if (structLength > 0x12) PatchStringByIndex(cursor, stringsBegin, stringsEnd, 0x12, cursor[0x12], "Generic TPM", &patched);
            } else {
                PatchDword(cursor, structLength, 0x04, 0, &patched);
                if (structLength > 0x08) cursor[0x08] = 0;
                if (structLength > 0x09) cursor[0x09] = 0;
                PatchDword(cursor, structLength, 0x0A, 0, &patched);
                PatchDword(cursor, structLength, 0x0E, 0, &patched);
                if (structLength > 0x12) PatchStringByIndex(cursor, stringsBegin, stringsEnd, 0x12, cursor[0x12], "Not Present", &patched);
            }
        }

        cursor = stringsEnd;
    }

    if (patchedFields) *patchedFields = patched;
    return patched > 0;
}
