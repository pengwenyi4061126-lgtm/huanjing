#include "../CacKernelIoctl.h"

#include <windows.h>
#include <winioctl.h>
#include <ntddstor.h>
#include <initguid.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_failures = 0;

static void Check(bool ok, const char *name) {
    printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) {
        g_failures += 1;
    }
}

static bool Ioctl(
    HANDLE device,
    DWORD code,
    void *input,
    DWORD inputLength,
    void *output,
    DWORD outputLength,
    DWORD *returned
    )
{
    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(
        device, code, input, inputLength, output, outputLength, &bytes, NULL);
    if (returned != NULL) {
        *returned = bytes;
    }
    return ok != FALSE;
}

static void WriteJson(const wchar_t *path, const CAC_PING_RESPONSE &ping, DWORD pid) {
    if (path == NULL) {
        return;
    }
    FILE *file = NULL;
    if (_wfopen_s(&file, path, L"w") != 0 || file == NULL) {
        printf("[WARN] cannot write %ls\n", path);
        return;
    }
    fprintf(file,
        "{\n"
        "  \"protocolVersion\": %lu,\n"
        "  \"capabilities\": %lu,\n"
        "  \"policyCount\": %lu,\n"
        "  \"auditCount\": %lu,\n"
        "  \"notifyRegistered\": %lu,\n"
        "  \"pid\": %lu,\n"
        "  \"failures\": %d\n"
        "}\n",
        (unsigned long)ping.Version,
        (unsigned long)ping.Capabilities,
        (unsigned long)ping.PolicyCount,
        (unsigned long)ping.AuditCount,
        (unsigned long)ping.NotifyRegistered,
        (unsigned long)pid,
        g_failures);
    fclose(file);
}

int wmain(int argc, wchar_t **argv) {
    bool pingOnly = false;
    bool identityProbe = false;
    bool smbiosProbe = false;
    const wchar_t *jsonPath = NULL;
    for (int i = 1; i < argc; ++i) {
        if (wcscmp(argv[i], L"--ping") == 0) {
            pingOnly = true;
        } else if (wcscmp(argv[i], L"--identity") == 0) {
            identityProbe = true;
        } else if (wcscmp(argv[i], L"--smbios") == 0) {
            identityProbe = true;
            smbiosProbe = true;
        } else if (wcscmp(argv[i], L"--json") == 0 && i + 1 < argc) {
            jsonPath = argv[++i];
        }
    }

    printf("CAC kernel control-plane smoke\n");
    HANDLE device = CreateFileW(
        CAC_KERNEL_USER_PATH,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);
    if (device == INVALID_HANDLE_VALUE) {
        printf("  [FAIL] open %ls (error %lu)\n", CAC_KERNEL_USER_PATH, GetLastError());
        return 1;
    }

    CAC_PING_RESPONSE ping = {};
    DWORD returned = 0;
    Check(Ioctl(device, CAC_IOCTL_PING, NULL, 0, &ping, sizeof(ping), &returned),
          "ping ioctl");
    Check(ping.Version == CAC_KERNEL_PROTOCOL_VERSION, "protocol version");
    Check((ping.Capabilities & CAC_CAP_CONTROL_PLANE) != 0, "control-plane capability");
    Check((ping.Capabilities & CAC_CAP_PER_PROCESS_POLICY) != 0, "per-process policy capability");
    Check((ping.Capabilities & CAC_CAP_AUDIT_RING) != 0, "audit ring capability");
    Check((ping.Capabilities & CAC_CAP_PROCESS_LIFECYCLE) != 0, "process lifecycle capability");
    Check(ping.ServiceState == 1, "service state reports ready");
    Check(ping.NotifyRegistered == 1, "process notify registered");
    printf("  [INFO] process notify registered: %lu\n", (unsigned long)ping.NotifyRegistered);

    DWORD pid = GetCurrentProcessId();
    if (!pingOnly) {
        CAC_POLICY_REQUEST request = {};
        request.Version = CAC_KERNEL_PROTOCOL_VERSION;
        request.ProcessId = pid;
        request.Flags = CAC_POLICY_FLAG_ACTIVE;
        memcpy(request.ProfileId, "profile-smoke", 13);

        Check(Ioctl(device, CAC_IOCTL_POLICY_REGISTER, &request, sizeof(request),
                    NULL, 0, &returned),
              "register current process");

        if (identityProbe) {
            CAC_IDENTITY identity = {};
            identity.Version = CAC_KERNEL_PROTOCOL_VERSION;
            identity.ModuleFlags = CAC_MODULE_FLAG_STORAGE;
            if (smbiosProbe) {
                identity.ModuleFlags |= CAC_MODULE_FLAG_SMBIOS;
            }
            memcpy(identity.DiskSerial, "CAC-DISK-01", 12);
            identity.MacAddress[0] = 0x02;
            identity.MacAddress[5] = 0x01;
            memcpy(identity.BiosVendor, "CAC-TEST-VENDOR", 16);
            memcpy(identity.SystemManufacturer, "CAC-TEST-SYSMFR", 16);

            Check(Ioctl(device, CAC_IOCTL_IDENTITY_SET,
                        &identity, sizeof(identity), NULL, 0, &returned),
                  "identity-set accepted");

            CAC_MODULE_STATE state = {};
            Check(Ioctl(device, CAC_IOCTL_MODULE_QUERY,
                        NULL, 0, &state, sizeof(state), &returned),
                  "module-state query");
            Check(state.StorageFilters > 0, "storage filters attached");
            if (smbiosProbe) {
                Check(state.SmbiosLocated == 1, "physical smbios table located");
                Check(state.SmbiosApplied == 1, "smbios table patched");
            }
            printf("  [INFO] filters storage=%lu smbiosPhys=0x%llx len=%lu\n",
                   (unsigned long)state.StorageFilters,
                   (unsigned long long)state.SmbiosPhysicalAddress,
                   (unsigned long)state.SmbiosLength);

            /* Storage probe: the registered PID must observe the profile serial. */
            HANDLE drive = CreateFileW(
                L"\\\\.\\PhysicalDrive0",
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                NULL,
                OPEN_EXISTING,
                0,
                NULL);
            if (drive == INVALID_HANDLE_VALUE) {
                Check(false, "open PhysicalDrive0");
            } else {
                STORAGE_PROPERTY_QUERY query = {};
                query.PropertyId = StorageDeviceProperty;
                query.QueryType = PropertyStandardQuery;
                unsigned char buffer[512] = {};
                DWORD bytes = 0;
                bool queried = DeviceIoControl(
                    drive,
                    IOCTL_STORAGE_QUERY_PROPERTY,
                    &query,
                    sizeof(query),
                    buffer,
                    sizeof(buffer),
                    &bytes,
                    NULL) != FALSE;
                Check(queried, "storage query succeeded");
                if (queried && bytes >= sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
                    PSTORAGE_DEVICE_DESCRIPTOR descriptor =
                        (PSTORAGE_DEVICE_DESCRIPTOR)buffer;
                    const char *serial = (const char *)buffer +
                                         descriptor->SerialNumberOffset;
                    bool rewritten =
                        strstr(serial, "CAC-DISK-01") != NULL;
                    Check(rewritten, "storage serial rewritten for registered pid");
                    printf("  [INFO] disk serial after rewrite: %s\n", serial);
                }
                CloseHandle(drive);
            }

            /* SMBIOS probe: GetSystemFirmwareTable must return the patched table. */
            if (smbiosProbe) {
                DWORD size = GetSystemFirmwareTable('RSMB', 0, NULL, 0);
                bool patched = false;
                if (size == 0 || size > 0x100000) {
                    Check(false, "smbios table size plausible");
                } else {
                    unsigned char *table = (unsigned char *)calloc(1, size);
                    if (table == NULL) {
                        Check(false, "smbios buffer alloc");
                    } else {
                        DWORD got = GetSystemFirmwareTable('RSMB', 0, table, size);
                        Check(got == size, "smbios table read");
                        for (DWORD i = 0; i + 15 < got; ++i) {
                            if (memcmp(table + i, "CAC-TEST-VENDOR", 15) == 0) {
                                patched = true;
                                break;
                            }
                        }
                        free(table);
                    }
                }
                Check(patched, "kernel-level smbios rewrite visible to userland");
            }

            /* Disable modules: the driver must restore the original SMBIOS. */
            CAC_IDENTITY disable = {};
            disable.Version = CAC_KERNEL_PROTOCOL_VERSION;
            disable.ModuleFlags = 0;
            Check(Ioctl(device, CAC_IOCTL_IDENTITY_SET,
                        &disable, sizeof(disable), NULL, 0, &returned),
                  "identity disable accepted");
            CAC_MODULE_STATE after = {};
            Check(Ioctl(device, CAC_IOCTL_MODULE_QUERY,
                        NULL, 0, &after, sizeof(after), &returned),
                  "module-state after disable");
            if (smbiosProbe) {
                Check(after.SmbiosApplied == 0, "smbios restored on disable");
            }
        }

        CAC_POLICY_RESPONSE response = {};
        Check(Ioctl(device, CAC_IOCTL_POLICY_QUERY, &request, sizeof(request),
                    &response, sizeof(response), &returned),
              "query policy");
        Check(response.Registered == 1, "policy is visible");
        Check(response.ProcessId == pid, "policy pid matches");
        Check(response.ProcessCreateTime != 0, "process create time captured");
        Check(memcmp(response.ProfileId, "profile-smoke", 13) == 0, "profile id round-trips");

        unsigned char auditBuffer[sizeof(CAC_AUDIT_QUERY) + 31 * sizeof(CAC_AUDIT_RECORD)] = {};
        CAC_AUDIT_QUERY *audit = (CAC_AUDIT_QUERY *)auditBuffer;
        audit->MaxRecords = 32;
        Check(Ioctl(device, CAC_IOCTL_AUDIT_QUERY, audit, sizeof(ULONG) * 2,
                    auditBuffer, sizeof(auditBuffer), &returned),
              "read audit ring");
        Check(audit->Returned > 0, "audit records returned");

        bool sawRegister = false;
        for (ULONG i = 0; i < audit->Returned; ++i) {
            if (audit->Records[i].EventType == CacAuditPolicyRegister &&
                audit->Records[i].ProcessId == pid) {
                sawRegister = true;
            }
        }
        Check(sawRegister, "register event is audited");

        CAC_POLICY_REQUEST invalid = {};
        invalid.Version = CAC_KERNEL_PROTOCOL_VERSION;
        invalid.ProcessId = 0;
        Check(!Ioctl(device, CAC_IOCTL_POLICY_REGISTER, &invalid, sizeof(invalid),
                     NULL, 0, &returned),
              "pid 0 is rejected");

        Check(Ioctl(device, CAC_IOCTL_POLICY_UNREGISTER, &request, sizeof(request),
                    NULL, 0, &returned),
              "unregister current process");

        CAC_POLICY_RESPONSE cleared = {};
        Check(Ioctl(device, CAC_IOCTL_POLICY_QUERY, &request, sizeof(request),
                    &cleared, sizeof(cleared), &returned),
              "query after unregister");
        Check(cleared.Registered == 0, "policy is removed");
    }

    CAC_PING_RESPONSE finalPing = {};
    Check(Ioctl(device, CAC_IOCTL_PING, NULL, 0, &finalPing, sizeof(finalPing), &returned),
          "final ping");
    WriteJson(jsonPath, finalPing, pid);

    CloseHandle(device);
    printf("%s: %d failure(s)\n", g_failures == 0 ? "PASS" : "FAIL", g_failures);
    return g_failures == 0 ? 0 : 1;
}
