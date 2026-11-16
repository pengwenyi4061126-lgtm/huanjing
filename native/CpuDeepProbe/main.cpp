#include <windows.h>
#include <psapi.h>
#include <cstdio>

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
    return 0;
}
