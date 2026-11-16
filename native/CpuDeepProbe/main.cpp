#include <windows.h>
#include <psapi.h>

#include <cstdio>
#include <vector>

static void PrintTopology() {
    DWORD coreLength = 0;
    GetLogicalProcessorInformationEx(RelationProcessorCore, nullptr, &coreLength);
    std::printf("ex_core_query_len=%lu\n", static_cast<unsigned long>(coreLength));
    std::vector<ULONGLONG> coreStorage(coreLength / sizeof(ULONGLONG) + 16);
    DWORD coreReturned = static_cast<DWORD>(coreStorage.size() * sizeof(ULONGLONG));
    if (GetLogicalProcessorInformationEx(
            RelationProcessorCore,
            reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(coreStorage.data()),
            &coreReturned)) {
        std::printf("ex_core_returned=%lu\n", static_cast<unsigned long>(coreReturned));
        const BYTE* raw = reinterpret_cast<const BYTE*>(coreStorage.data());
        std::printf("ex_core_head=%02x %02x %02x %02x %02x %02x %02x %02x\n",
                    raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7]);
        DWORD offset = 0;
        DWORD count = 0;
        unsigned long long mask0 = 0;
        unsigned long long mask1 = 0;
        while (offset + 2 * sizeof(DWORD) <= coreReturned) {
            auto* entry = reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(
                reinterpret_cast<BYTE*>(coreStorage.data()) + offset);
            if (entry->Size < 2 * sizeof(DWORD) ||
                offset + entry->Size > coreReturned) break;
            if (entry->Relationship == RelationProcessorCore &&
                entry->Processor.GroupCount > 0) {
                if (count == 0) mask0 = entry->Processor.GroupMask[0].Mask;
                if (count == 1) mask1 = entry->Processor.GroupMask[0].Mask;
                ++count;
            }
            offset += entry->Size;
        }
        std::printf("core_entries=%lu\n", static_cast<unsigned long>(count));
        std::printf("core0_mask=0x%llx\n", mask0);
        std::printf("core1_mask=0x%llx\n", mask1);
    } else {
        std::printf("core_entries=failed error=%lu\n",
                    static_cast<unsigned long>(GetLastError()));
    }

    DWORD packageLength = 0;
    GetLogicalProcessorInformationEx(RelationProcessorPackage, nullptr, &packageLength);
    std::vector<ULONGLONG> packageStorage(packageLength / sizeof(ULONGLONG) + 16);
    DWORD packageReturned = static_cast<DWORD>(packageStorage.size() * sizeof(ULONGLONG));
    if (GetLogicalProcessorInformationEx(
            RelationProcessorPackage,
            reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(packageStorage.data()),
            &packageReturned)) {
        DWORD offset = 0;
        while (offset + 2 * sizeof(DWORD) <= packageReturned) {
            auto* entry = reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(
                reinterpret_cast<BYTE*>(packageStorage.data()) + offset);
            if (entry->Size < 2 * sizeof(DWORD) ||
                offset + entry->Size > packageReturned) break;
            if (entry->Relationship == RelationProcessorPackage &&
                entry->Processor.GroupCount > 0) {
                std::printf("package_mask=0x%llx\n",
                            static_cast<unsigned long long>(
                                entry->Processor.GroupMask[0].Mask));
                break;
            }
            offset += entry->Size;
        }
    } else {
        std::printf("package_mask=failed error=%lu\n",
                    static_cast<unsigned long>(GetLastError()));
    }

    DWORD legacyLength = 0;
    GetLogicalProcessorInformation(nullptr, &legacyLength);
    std::vector<SYSTEM_LOGICAL_PROCESSOR_INFORMATION> legacy(
        legacyLength / sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION));
    DWORD legacyReturned = legacyLength;
    if (GetLogicalProcessorInformation(legacy.data(), &legacyReturned)) {
        DWORD count = 0;
        const DWORD entries = legacyReturned / sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION);
        for (DWORD index = 0; index < entries; ++index) {
            if (legacy[index].Relationship == RelationProcessorCore) ++count;
        }
        std::printf("legacy_core_entries=%lu\n", static_cast<unsigned long>(count));
    }
}

int wmain() {
    SYSTEM_INFO systemInfo = {};
    GetSystemInfo(&systemInfo);
    std::printf("system_processors=%lu\n",
                static_cast<unsigned long>(systemInfo.dwNumberOfProcessors));
    std::printf("active_processors=%lu\n",
                static_cast<unsigned long>(GetActiveProcessorCount(ALL_PROCESSOR_GROUPS)));
    std::printf("maximum_processors=%lu\n",
                static_cast<unsigned long>(GetMaximumProcessorCount(ALL_PROCESSOR_GROUPS)));

    PERFORMANCE_INFORMATION info = {};
    info.cb = sizeof(info);
    if (GetPerformanceInfo(&info, sizeof(info))) {
        const unsigned long long page = static_cast<unsigned long long>(info.PageSize);
        std::printf("perf_physical_mb=%llu\n",
                    static_cast<unsigned long long>(info.PhysicalTotal) * page / (1024ULL * 1024ULL));
        std::printf("perf_available_mb=%llu\n",
                    static_cast<unsigned long long>(info.PhysicalAvailable) * page / (1024ULL * 1024ULL));
        std::printf("perf_page_size=%llu\n", page);
    } else {
        std::printf("perf_state=failed\n");
    }
    PrintTopology();
    return 0;
}
