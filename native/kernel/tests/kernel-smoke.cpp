#include "../CacKernelIoctl.h"

#include <stdio.h>
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
    const wchar_t *jsonPath = NULL;
    for (int i = 1; i < argc; ++i) {
        if (wcscmp(argv[i], L"--ping") == 0) {
            pingOnly = true;
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
