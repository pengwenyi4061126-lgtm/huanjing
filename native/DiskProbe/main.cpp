#include <windows.h>
#include <winioctl.h>

#include <cstdio>
#include <vector>

static void FormatGuid(const GUID& guid, wchar_t* buffer, size_t count) {
    swprintf_s(buffer, count, L"{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
               static_cast<unsigned long>(guid.Data1), guid.Data2, guid.Data3,
               guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
               guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
}

int wmain() {
    HANDLE drive = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                               OPEN_EXISTING, 0, nullptr);
    if (drive == INVALID_HANDLE_VALUE) {
        std::printf("disk_state=open-failed error=%lu\n", GetLastError());
        return 2;
    }

    std::vector<BYTE> buffer(64 * 1024);
    DWORD returned = 0;
    BOOL ok = DeviceIoControl(drive, IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
                              nullptr, 0, buffer.data(),
                              static_cast<DWORD>(buffer.size()), &returned, nullptr);
    if (!ok && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        buffer.resize(returned);
        ok = DeviceIoControl(drive, IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
                             nullptr, 0, buffer.data(),
                             static_cast<DWORD>(buffer.size()), &returned, nullptr);
    }
    if (!ok || returned < sizeof(DRIVE_LAYOUT_INFORMATION_EX)) {
        std::printf("disk_state=ioctl-failed error=%lu returned=%lu\n",
                    GetLastError(), static_cast<unsigned long>(returned));
        CloseHandle(drive);
        return 3;
    }

    auto* layout = reinterpret_cast<DRIVE_LAYOUT_INFORMATION_EX*>(buffer.data());
    std::printf("disk_state=ok\n");
    std::printf("partition_count=%lu\n",
                static_cast<unsigned long>(layout->PartitionCount));
    if (layout->PartitionStyle == PARTITION_STYLE_GPT) {
        wchar_t guid[64] = {};
        FormatGuid(layout->Gpt.DiskId, guid, _countof(guid));
        std::printf("disk_style=GPT\n");
        wprintf(L"disk_id=%ls\n", guid);
        for (DWORD index = 0; index < layout->PartitionCount; ++index) {
            const PARTITION_INFORMATION_EX& partition = layout->PartitionEntry[index];
            if (partition.PartitionStyle != PARTITION_STYLE_GPT) continue;
            FormatGuid(partition.Gpt.PartitionId, guid, _countof(guid));
            std::printf("partition%lu_size=%llu\n", static_cast<unsigned long>(index),
                        static_cast<unsigned long long>(partition.PartitionLength.QuadPart));
            wprintf(L"partition%lu_id=%ls\n", static_cast<unsigned long>(index), guid);
            wprintf(L"partition%lu_name=%ls\n", static_cast<unsigned long>(index),
                         partition.Gpt.Name);
        }
    } else if (layout->PartitionStyle == PARTITION_STYLE_MBR) {
        wchar_t guid[64] = {};
        std::printf("disk_style=MBR\n");
        std::printf("disk_signature=0x%08lx\n",
                    static_cast<unsigned long>(layout->Mbr.Signature));
        for (DWORD index = 0; index < layout->PartitionCount; ++index) {
            const PARTITION_INFORMATION_EX& partition = layout->PartitionEntry[index];
            if (partition.PartitionStyle != PARTITION_STYLE_MBR) continue;
            std::printf("partition%lu_type=0x%02x\n", static_cast<unsigned long>(index),
                        static_cast<unsigned int>(partition.Mbr.PartitionType));
            FormatGuid(partition.Mbr.PartitionId, guid, _countof(guid));
            wprintf(L"partition%lu_id=%ls\n", static_cast<unsigned long>(index), guid);
        }
    } else {
        std::printf("disk_style=RAW\n");
    }

    CloseHandle(drive);
    return 0;
}

