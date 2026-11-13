#define _WIN32_WINNT 0x0A00

#include <windows.h>
#include <winioctl.h>

#include <cstdio>

namespace {

void PrintSerial(const BYTE* buffer, DWORD size) {
    if (!buffer || size < sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
        std::printf("overlap_serial=empty\n");
        return;
    }
    const STORAGE_DEVICE_DESCRIPTOR* descriptor =
        reinterpret_cast<const STORAGE_DEVICE_DESCRIPTOR*>(buffer);
    if (descriptor->SerialNumberOffset == 0 || descriptor->SerialNumberOffset >= size) {
        std::printf("overlap_serial=empty\n");
        return;
    }
    const char* serial = reinterpret_cast<const char*>(buffer) + descriptor->SerialNumberOffset;
    std::printf("overlap_serial=%s\n", *serial ? serial : "empty");
}

}  // namespace

int wmain() {
    HANDLE disk = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                              FILE_FLAG_OVERLAPPED, nullptr);
    if (disk == INVALID_HANDLE_VALUE) {
        std::printf("overlap_state=%s\n",
                    GetLastError() == ERROR_ACCESS_DENIED ? "open-denied" : "open-error");
        return 0;
    }

    HANDLE event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!event) {
        CloseHandle(disk);
        std::printf("overlap_state=event-error\n");
        return 0;
    }
    OVERLAPPED overlapped = {};
    overlapped.hEvent = event;
    STORAGE_PROPERTY_QUERY query = {};
    query.PropertyId = StorageDeviceProperty;
    query.QueryType = PropertyStandardQuery;
    BYTE output[4096] = {};
    DWORD transferred = 0;
    const BOOL started = DeviceIoControl(disk, IOCTL_STORAGE_QUERY_PROPERTY,
                                         &query, sizeof(query), output, sizeof(output),
                                         &transferred, &overlapped);
    if (started) {
        std::printf("overlap_state=immediate\n");
        PrintSerial(output, transferred);
    } else if (GetLastError() == ERROR_IO_PENDING) {
        std::printf("overlap_state=pending\n");
        const BOOL completed = GetOverlappedResult(disk, &overlapped, &transferred, TRUE);
        std::printf("overlap_completion=%s\n", completed ? "ok" : "error");
        if (completed) PrintSerial(output, transferred);
    } else {
        const DWORD error = GetLastError();
        std::printf("overlap_state=%s\n", error == ERROR_ACCESS_DENIED ? "open-denied" : "io-error");
    }

    CloseHandle(event);
    CloseHandle(disk);
    return 0;
}
