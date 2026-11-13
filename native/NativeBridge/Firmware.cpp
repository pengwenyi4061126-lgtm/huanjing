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
            if (structLength > 0x05) PatchStringByIndex(cursor, stringsBegin, stringsEnd, 0x05, cursor[0x05], "F.20", &patched);
            if (structLength > 0x08) PatchStringByIndex(cursor, stringsBegin, stringsEnd, 0x08, cursor[0x08], "01/01/2024", &patched);
        } else if (type == 1) {  // System information
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
            if (structLength > 0x07) PatchStringByIndex(cursor, stringsBegin, stringsEnd, 0x07, cursor[0x07], identity.boardSerial, &patched);
        } else if (type == 3) {  // Chassis
            if (structLength > 0x07) PatchStringByIndex(cursor, stringsBegin, stringsEnd, 0x07, cursor[0x07], identity.systemSerial, &patched);
        } else if (type == 4) {  // Processor
            if (structLength >= 0x10) {
                BYTE processor[8] = {};
                if (ParseHex(identity.processorId, processor, sizeof(processor))) {
                    std::memcpy(cursor + 0x08, processor, sizeof(processor));
                    ++patched;
                }
            }
        }

        cursor = stringsEnd;
    }

    if (patchedFields) *patchedFields = patched;
    return patched > 0;
}
