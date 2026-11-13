#include "../CacKernelIoctl.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static HANDLE OpenControlDevice() {
    return CreateFileW(
        CAC_KERNEL_USER_PATH,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);
}

static int Fail(const char *message, DWORD error) {
    printf("{\"ok\":false,\"error\":\"%s\",\"win32\":%lu}\n", message, (unsigned long)error);
    return 1;
}

static bool ParseUlong(const wchar_t *text, unsigned long *value) {
    wchar_t *end = NULL;
    unsigned long parsed = wcstoul(text, &end, 10);
    if (end == text || (end != NULL && *end != L'\0')) {
        return false;
    }
    *value = parsed;
    return true;
}

static int Usage() {
    printf(
        "cac-kernelctl ping\n"
        "cac-kernelctl register --pid N --profile NAME [--flags N]\n"
        "cac-kernelctl unregister --pid N\n"
        "cac-kernelctl query --pid N\n"
        "cac-kernelctl audit [--max N]\n");
    return 2;
}

int wmain(int argc, wchar_t **argv) {
    if (argc < 2) {
        return Usage();
    }

    HANDLE device = OpenControlDevice();
    if (device == INVALID_HANDLE_VALUE) {
        return Fail("open device", GetLastError());
    }

    const wchar_t *command = argv[1];
    DWORD returned = 0;
    int result = 0;

    if (wcscmp(command, L"ping") == 0) {
        CAC_PING_RESPONSE ping = {};
        if (!DeviceIoControl(device, CAC_IOCTL_PING, NULL, 0,
                             &ping, sizeof(ping), &returned, NULL)) {
            result = Fail("ping", GetLastError());
        } else {
            printf("{\"ok\":true,\"version\":%lu,\"capabilities\":%lu,"
                   "\"policyCount\":%lu,\"auditCount\":%lu,\"auditDropped\":%lu,"
                   "\"notifyRegistered\":%lu}\n",
                   (unsigned long)ping.Version,
                   (unsigned long)ping.Capabilities,
                   (unsigned long)ping.PolicyCount,
                   (unsigned long)ping.AuditCount,
                   (unsigned long)ping.AuditDropped,
                   (unsigned long)ping.NotifyRegistered);
        }
    } else if (wcscmp(command, L"register") == 0) {
        unsigned long pid = 0;
        unsigned long flags = CAC_POLICY_FLAG_ACTIVE;
        const wchar_t *profile = NULL;
        for (int i = 2; i < argc; ++i) {
            if (wcscmp(argv[i], L"--pid") == 0 && i + 1 < argc) {
                if (!ParseUlong(argv[++i], &pid)) { return Fail("invalid pid", 0); }
            } else if (wcscmp(argv[i], L"--profile") == 0 && i + 1 < argc) {
                profile = argv[++i];
            } else if (wcscmp(argv[i], L"--flags") == 0 && i + 1 < argc) {
                if (!ParseUlong(argv[++i], &flags)) { return Fail("invalid flags", 0); }
            }
        }
        if (pid == 0 || profile == NULL) { return Usage(); }

        CAC_POLICY_REQUEST request = {};
        request.Version = CAC_KERNEL_PROTOCOL_VERSION;
        request.ProcessId = (ULONG)pid;
        request.Flags = (ULONG)flags;
        size_t length = wcslen(profile);
        if (length > CAC_PROFILE_ID_LENGTH) {
            length = CAC_PROFILE_ID_LENGTH;
        }
        for (size_t i = 0; i < length; ++i) {
            request.ProfileId[i] = (UCHAR)profile[i];
        }

        if (!DeviceIoControl(device, CAC_IOCTL_POLICY_REGISTER,
                             &request, sizeof(request), NULL, 0, &returned, NULL)) {
            result = Fail("register", GetLastError());
        } else {
            printf("{\"ok\":true,\"pid\":%lu,\"flags\":%lu}\n",
                   (unsigned long)pid, (unsigned long)flags);
        }
    } else if (wcscmp(command, L"unregister") == 0) {
        unsigned long pid = 0;
        for (int i = 2; i < argc; ++i) {
            if (wcscmp(argv[i], L"--pid") == 0 && i + 1 < argc) {
                if (!ParseUlong(argv[++i], &pid)) { return Fail("invalid pid", 0); }
            }
        }
        if (pid == 0) { return Usage(); }

        CAC_POLICY_REQUEST request = {};
        request.Version = CAC_KERNEL_PROTOCOL_VERSION;
        request.ProcessId = (ULONG)pid;
        if (!DeviceIoControl(device, CAC_IOCTL_POLICY_UNREGISTER,
                             &request, sizeof(request), NULL, 0, &returned, NULL)) {
            result = Fail("unregister", GetLastError());
        } else {
            printf("{\"ok\":true,\"pid\":%lu}\n", (unsigned long)pid);
        }
    } else if (wcscmp(command, L"query") == 0) {
        unsigned long pid = 0;
        for (int i = 2; i < argc; ++i) {
            if (wcscmp(argv[i], L"--pid") == 0 && i + 1 < argc) {
                if (!ParseUlong(argv[++i], &pid)) { return Fail("invalid pid", 0); }
            }
        }
        if (pid == 0) { return Usage(); }

        CAC_POLICY_REQUEST request = {};
        request.Version = CAC_KERNEL_PROTOCOL_VERSION;
        request.ProcessId = (ULONG)pid;
        CAC_POLICY_RESPONSE response = {};
        if (!DeviceIoControl(device, CAC_IOCTL_POLICY_QUERY,
                             &request, sizeof(request),
                             &response, sizeof(response), &returned, NULL)) {
            result = Fail("query", GetLastError());
        } else {
            printf("{\"ok\":true,\"pid\":%lu,\"registered\":%lu,\"flags\":%lu,"
                   "\"createTime\":%lld}\n",
                   (unsigned long)response.ProcessId,
                   (unsigned long)response.Registered,
                   (unsigned long)response.Flags,
                   (long long)response.ProcessCreateTime);
        }
    } else if (wcscmp(command, L"audit") == 0) {
        unsigned long maxRecords = 32;
        for (int i = 2; i < argc; ++i) {
            if (wcscmp(argv[i], L"--max") == 0 && i + 1 < argc) {
                if (!ParseUlong(argv[++i], &maxRecords)) { return Fail("invalid max", 0); }
            }
        }
        if (maxRecords == 0 || maxRecords > 128) { maxRecords = 32; }

        unsigned char buffer[sizeof(CAC_AUDIT_QUERY) + 127 * sizeof(CAC_AUDIT_RECORD)] = {};
        CAC_AUDIT_QUERY *query = (CAC_AUDIT_QUERY *)buffer;
        query->MaxRecords = (ULONG)maxRecords;
        if (!DeviceIoControl(device, CAC_IOCTL_AUDIT_QUERY,
                             query, sizeof(ULONG) * 2,
                             buffer, sizeof(buffer), &returned, NULL)) {
            result = Fail("audit", GetLastError());
        } else {
            printf("{\"ok\":true,\"total\":%lu,\"dropped\":%lu,\"records\":[",
                   (unsigned long)query->TotalRecorded,
                   (unsigned long)query->Dropped);
            for (ULONG i = 0; i < query->Returned; ++i) {
                const CAC_AUDIT_RECORD *record = &query->Records[i];
                printf("%s{\"seq\":%lu,\"event\":%lu,\"pid\":%lu,\"status\":%lu,"
                       "\"time\":%lld,\"detail\":\"%s\"}",
                       i == 0 ? "" : ",",
                       (unsigned long)record->Sequence,
                       (unsigned long)record->EventType,
                       (unsigned long)record->ProcessId,
                       (unsigned long)record->Status,
                       (long long)record->TimestampUtc,
                       record->Detail);
            }
            printf("]}\n");
        }
    } else {
        result = Usage();
    }

    CloseHandle(device);
    return result;
}
