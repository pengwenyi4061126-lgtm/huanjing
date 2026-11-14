#include "../CacKernelIoctl.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>

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

static bool JsonReadString(
    const char *document,
    const char *key,
    char *output,
    size_t outputSize
    )
{
    std::string search = std::string("\"") + key + "\"";
    const char *position = strstr(document, search.c_str());
    if (position == NULL) {
        return false;
    }
    position += search.size();
    while (*position == ' ' || *position == '\t' ||
           *position == '\r' || *position == '\n') {
        position++;
    }
    if (*position != ':') {
        return false;
    }
    position++;
    while (*position == ' ' || *position == '\t' ||
           *position == '\r' || *position == '\n') {
        position++;
    }
    if (*position != '"') {
        return false;
    }
    position++;
    size_t length = 0;
    while (*position != '\0' && *position != '"') {
        if (length + 1 < outputSize) {
            output[length++] = *position;
        }
        position++;
    }
    output[length] = '\0';
    return true;
}

static bool JsonReadUlong(const char *document, const char *key, unsigned long *value) {
    char text[32];
    if (!JsonReadString(document, key, text, sizeof(text))) {
        return false;
    }
    char *end = NULL;
    unsigned long parsed = strtoul(text, &end, 10);
    if (end == text) {
        return false;
    }
    *value = parsed;
    return true;
}

static int HexNibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool HexToBytes(const char *hex, unsigned char *output, size_t outputSize) {
    size_t length = strlen(hex);
    if (length != outputSize * 2) {
        return false;
    }
    for (size_t i = 0; i < outputSize; ++i) {
        int high = HexNibble(hex[i * 2]);
        int low = HexNibble(hex[i * 2 + 1]);
        if (high < 0 || low < 0) {
            return false;
        }
        output[i] = (unsigned char)((high << 4) | low);
    }
    return true;
}

static bool MacToBytes(const char *mac, unsigned char *output) {
    char cleaned[18] = {};
    size_t cleanedLength = 0;
    for (size_t i = 0; mac[i] != '\0' && cleanedLength < sizeof(cleaned) - 1; ++i) {
        if (mac[i] != ':' && mac[i] != '-') {
            cleaned[cleanedLength++] = mac[i];
        }
    }
    if (cleanedLength != 12) {
        return false;
    }
    return HexToBytes(cleaned, output, 6);
}

static int PrintModuleState(const CAC_MODULE_STATE &state) {
    printf("{\"ok\":true,\"flags\":%lu,\"storageFilters\":%lu,"
           "\"smbiosLocated\":%lu,\"smbiosApplied\":%lu,\"smbiosPhys\":%llu,"
           "\"smbiosLength\":%lu,\"storageRewrites\":%lu,"
           "\"storageSeen\":%lu,\"storageCompletionSeen\":%lu,"
           "\"lastPropertyId\":%lu,\"lastDescriptorVersion\":%lu,"
           "\"lastDescriptorSize\":%lu,"
           "\"lastCompletionStatus\":%lu,\"lastBufferWord0\":%llu,"
           "\"lastBufferWord1\":%llu,\"lastPolicyHit\":%lu}\n",
           (unsigned long)state.ModuleFlags,
           (unsigned long)state.StorageFilters,
           (unsigned long)state.SmbiosLocated,
           (unsigned long)state.SmbiosApplied,
           (unsigned long long)state.SmbiosPhysicalAddress,
           (unsigned long)state.SmbiosLength,
           (unsigned long)state.StorageRewrites,
           (unsigned long)state.StorageDispatchSeen,
           (unsigned long)state.StorageCompletionSeen,
           (unsigned long)state.LastPropertyId,
           (unsigned long)state.LastDescriptorVersion,
           (unsigned long)state.LastDescriptorSize,
           (unsigned long)state.LastCompletionStatus,
           (unsigned long long)state.LastBufferWord0,
           (unsigned long long)state.LastBufferWord1,
           (unsigned long)state.LastPolicyHit);
    return 0;
}

static int CommandIdentitySet(HANDLE device, int argc, wchar_t **argv) {
    const wchar_t *filePath = NULL;
    for (int i = 2; i < argc; ++i) {
        if (wcscmp(argv[i], L"--file") == 0 && i + 1 < argc) {
            filePath = argv[++i];
        }
    }
    if (filePath == NULL) {
        fprintf(stderr, "identity-set requires --file IDENTITY.json\n");
        return 2;
    }

    FILE *file = NULL;
    if (_wfopen_s(&file, filePath, L"rb") != 0 || file == NULL) {
        return Fail("identity file open", GetLastError());
    }
    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);
    if (fileSize <= 0 || fileSize > 1024 * 1024) {
        fclose(file);
        return Fail("identity file size", 0);
    }
    std::string document((size_t)fileSize, '\0');
    fread(&document[0], 1, (size_t)fileSize, file);
    fclose(file);

    CAC_IDENTITY identity = {};
    identity.Version = CAC_KERNEL_PROTOCOL_VERSION;
    unsigned long moduleFlags = CAC_MODULE_FLAG_ALL;
    JsonReadUlong(document.c_str(), "module_flags", &moduleFlags);
    identity.ModuleFlags = (ULONG)moduleFlags;

    char field[CAC_IDENTITY_FIELD_LENGTH];
    if (JsonReadString(document.c_str(), "disk_vendor", field, sizeof(field))) {
        memcpy(identity.DiskVendor, field, sizeof(field));
    }
    if (JsonReadString(document.c_str(), "disk_product", field, sizeof(field))) {
        memcpy(identity.DiskProduct, field, sizeof(field));
    }
    if (JsonReadString(document.c_str(), "disk_revision", field, sizeof(field))) {
        memcpy(identity.DiskRevision, field, sizeof(field));
    }
    if (JsonReadString(document.c_str(), "disk_serial", field, sizeof(field))) {
        memcpy(identity.DiskSerial, field, sizeof(field));
    }
    if (JsonReadString(document.c_str(), "mac_address", field, sizeof(field))) {
        MacToBytes(field, identity.MacAddress);
    }
    if (JsonReadString(document.c_str(), "system_uuid", field, sizeof(field))) {
        HexToBytes(field, identity.SystemUuid, CAC_UUID_LENGTH);
    }
    if (JsonReadString(document.c_str(), "bios_vendor", field, sizeof(field))) {
        memcpy(identity.BiosVendor, field, sizeof(field));
    }
    if (JsonReadString(document.c_str(), "bios_version", field, sizeof(field))) {
        memcpy(identity.BiosVersion, field, sizeof(field));
    }
    if (JsonReadString(document.c_str(), "system_manufacturer", field, sizeof(field))) {
        memcpy(identity.SystemManufacturer, field, sizeof(field));
    }
    if (JsonReadString(document.c_str(), "system_product", field, sizeof(field))) {
        memcpy(identity.SystemProduct, field, sizeof(field));
    }
    if (JsonReadString(document.c_str(), "system_version", field, sizeof(field))) {
        memcpy(identity.SystemVersion, field, sizeof(field));
    }
    if (JsonReadString(document.c_str(), "system_serial", field, sizeof(field))) {
        memcpy(identity.SystemSerial, field, sizeof(field));
    }
    if (JsonReadString(document.c_str(), "baseboard_manufacturer", field, sizeof(field))) {
        memcpy(identity.BaseboardManufacturer, field, sizeof(field));
    }
    if (JsonReadString(document.c_str(), "baseboard_product", field, sizeof(field))) {
        memcpy(identity.BaseboardProduct, field, sizeof(field));
    }
    if (JsonReadString(document.c_str(), "baseboard_serial", field, sizeof(field))) {
        memcpy(identity.BaseboardSerial, field, sizeof(field));
    }

    DWORD returned = 0;
    if (!DeviceIoControl(device, CAC_IOCTL_IDENTITY_SET,
                         &identity, sizeof(identity), NULL, 0, &returned, NULL)) {
        return Fail("identity-set", GetLastError());
    }
    CAC_MODULE_STATE state = {};
    if (!DeviceIoControl(device, CAC_IOCTL_MODULE_QUERY,
                         NULL, 0, &state, sizeof(state), &returned, NULL)) {
        return Fail("module-state", GetLastError());
    }
    return PrintModuleState(state);
}

static int CommandModuleState(HANDLE device) {
    CAC_MODULE_STATE state = {};
    DWORD returned = 0;
    if (!DeviceIoControl(device, CAC_IOCTL_MODULE_QUERY,
                         NULL, 0, &state, sizeof(state), &returned, NULL)) {
        return Fail("module-state", GetLastError());
    }
    return PrintModuleState(state);
}

static int Usage() {
    printf(
        "cac-kernelctl ping\n"
        "cac-kernelctl register --pid N --profile NAME [--flags N]\n"
        "cac-kernelctl unregister --pid N\n"
        "cac-kernelctl query --pid N\n"
        "cac-kernelctl identity-set --file IDENTITY.json\n"
        "cac-kernelctl module-state\n"
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
    } else if (wcscmp(command, L"identity-set") == 0) {
        result = CommandIdentitySet(device, argc, argv);
    } else if (wcscmp(command, L"module-state") == 0) {
        result = CommandModuleState(device);
    } else {
        result = Usage();
    }

    CloseHandle(device);
    return result;
}
