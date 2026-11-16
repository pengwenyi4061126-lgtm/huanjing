#include <windows.h>

#include <cstdio>
#include <vector>

int wmain() {
    DWORD length = 0;
    GetLogicalProcessorInformationEx(RelationCache, nullptr, &length);
    if (length == 0) {
        std::printf("cache_state=size-failed error=%lu\n", GetLastError());
        return 2;
    }
    std::vector<BYTE> buffer(length);
    if (!GetLogicalProcessorInformationEx(
            RelationCache, reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(buffer.data()),
            &length)) {
        std::printf("cache_state=query-failed error=%lu\n", GetLastError());
        return 3;
    }
    int l1 = 0;
    int l2 = 0;
    int l3 = 0;
    unsigned long long l2Bytes = 0;
    unsigned long long l3Bytes = 0;
    unsigned long long l2First = 0;
    DWORD offset = 0;
    while (offset + sizeof(DWORD) * 2 <= length) {
        auto* entry = reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(
            buffer.data() + offset);
        if (entry->Size < sizeof(DWORD) * 2 || offset + entry->Size > length) break;
        if (entry->Relationship == RelationCache) {
            if (entry->Cache.Level == 1) ++l1;
            else if (entry->Cache.Level == 2) {
                ++l2;
                l2Bytes += entry->Cache.CacheSize;
                if (l2First == 0) l2First = entry->Cache.CacheSize;
            } else if (entry->Cache.Level == 3) {
                ++l3;
                l3Bytes += entry->Cache.CacheSize;
            }
        }
        offset += entry->Size;
    }
    std::printf("cache_state=ok\n");
    std::printf("cache_l1_entries=%d\n", l1);
    std::printf("cache_l2_entries=%d\n", l2);
    std::printf("cache_l3_entries=%d\n", l3);
    std::printf("cache_l2_total_kb=%llu\n", l2Bytes / 1024ULL);
    std::printf("cache_l3_total_kb=%llu\n", l3Bytes / 1024ULL);
    std::printf("cache_l2_first_kb=%llu\n", l2First / 1024ULL);
    return 0;
}
