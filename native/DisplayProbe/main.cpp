#include <windows.h>
#include <wingdi.h>

#include <cstdio>
#include <vector>

int wmain() {
    UINT32 pathCount = 0;
    UINT32 modeCount = 0;
    LONG status = GetDisplayConfigBufferSizes(QDC_ONLY_ACTIVE_PATHS, &pathCount, &modeCount);
    if (status != ERROR_SUCCESS) {
        std::printf("display_state=buffer-failed status=%ld\n", status);
        return 2;
    }
    std::vector<DISPLAYCONFIG_PATH_INFO> paths(pathCount);
    std::vector<DISPLAYCONFIG_MODE_INFO> modes(modeCount);
    status = QueryDisplayConfig(QDC_ONLY_ACTIVE_PATHS, &pathCount, paths.data(),
                                &modeCount, modes.data(), nullptr);
    if (status != ERROR_SUCCESS) {
        std::printf("display_state=query-failed status=%ld\n", status);
        return 3;
    }

    std::printf("display_state=ok\n");
    std::printf("display_count=%lu\n", static_cast<unsigned long>(pathCount));
    for (UINT32 index = 0; index < pathCount; ++index) {
        DISPLAYCONFIG_TARGET_DEVICE_NAME target = {};
        target.header.type = DISPLAYCONFIG_DEVICE_INFO_GET_TARGET_NAME;
        target.header.size = sizeof(target);
        target.header.adapterId = paths[index].targetInfo.adapterId;
        target.header.id = paths[index].targetInfo.id;
        const LONG targetStatus = DisplayConfigGetDeviceInfo(&target.header);
        if (targetStatus == ERROR_SUCCESS) {
            std::printf("display%lu_edid_manufacturer=0x%04x\n",
                        static_cast<unsigned long>(index), target.edidManufactureId);
            std::printf("display%lu_edid_product=0x%04x\n",
                        static_cast<unsigned long>(index), target.edidProductCodeId);
            wprintf(L"display%lu_friendly=%ls\n",
                    static_cast<unsigned long>(index), target.monitorFriendlyDeviceName);
            wprintf(L"display%lu_path=%ls\n",
                    static_cast<unsigned long>(index), target.monitorDevicePath);
        } else {
            std::printf("display%lu_state=target-failed status=%ld\n",
                        static_cast<unsigned long>(index), targetStatus);
        }

        DISPLAYCONFIG_ADAPTER_NAME adapter = {};
        adapter.header.type = DISPLAYCONFIG_DEVICE_INFO_GET_ADAPTER_NAME;
        adapter.header.size = sizeof(adapter);
        adapter.header.adapterId = paths[index].targetInfo.adapterId;
        if (DisplayConfigGetDeviceInfo(&adapter.header) == ERROR_SUCCESS) {
            wprintf(L"adapter%lu_path=%ls\n",
                    static_cast<unsigned long>(index), adapter.adapterDevicePath);
        }
    }
    return 0;
}
