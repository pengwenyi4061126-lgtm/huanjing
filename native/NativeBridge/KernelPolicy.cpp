#include "KernelPolicy.h"

#include <windows.h>

#include <cstring>
#include <string>

#include "../kernel/CacKernelIoctl.h"
#include "ApiHooks.h"
#include "Audit.h"
#include "Identity.h"

namespace {

bool IsTruthy(const char* name) {
    char value[16] = {};
    const DWORD length = GetEnvironmentVariableA(name, value, static_cast<DWORD>(sizeof(value)));
    if (length == 0 || length >= sizeof(value)) return false;
    for (DWORD i = 0; i < length; ++i) {
        if (value[i] >= 'A' && value[i] <= 'Z') value[i] = static_cast<char>(value[i] - 'A' + 'a');
    }
    return std::strcmp(value, "1") == 0 || std::strcmp(value, "true") == 0 ||
           std::strcmp(value, "yes") == 0;
}

HANDLE OpenControlDevice() {
    return CreateFileW(CAC_KERNEL_USER_PATH,
                       GENERIC_READ | GENERIC_WRITE,
                       0, nullptr, OPEN_EXISTING, 0, nullptr);
}

void FillProfileId(UCHAR (&out)[CAC_PROFILE_ID_LENGTH]) {
    const ProfileIdentity& identity = ProfileIdentity::Get();
    const std::string& source = identity.stableId.empty() ? identity.machineId : identity.stableId;
    const size_t length = source.size() < CAC_PROFILE_ID_LENGTH
        ? source.size() : CAC_PROFILE_ID_LENGTH;
    if (length != 0) std::memcpy(out, source.data(), length);
}

bool SameProfileId(const UCHAR (&left)[CAC_PROFILE_ID_LENGTH],
                   const UCHAR (&right)[CAC_PROFILE_ID_LENGTH]) {
    return std::memcmp(left, right, CAC_PROFILE_ID_LENGTH) == 0;
}

}  // namespace

bool KernelPolicyRequired() {
    return IsTruthy("CAC_KERNEL_POLICY_REQUIRED");
}

bool RegisterCurrentProcessKernelPolicy() {
    HANDLE device = OpenControlDevice();
    if (device == INVALID_HANDLE_VALUE) {
        AuditEvent("kernel.policy", "unavailable", "open", GetLastError(), true);
        return false;
    }

    CAC_POLICY_REQUEST request = {};
    request.Version = CAC_KERNEL_PROTOCOL_VERSION;
    request.ProcessId = GetCurrentProcessId();
    request.Flags = CAC_POLICY_FLAG_ACTIVE;
    if (NativeEmptyReadsEnabled()) request.Flags |= CAC_POLICY_FLAG_STRICT_EMPTY;
    FillProfileId(request.ProfileId);

    DWORD returned = 0;
    if (!DeviceIoControl(device, CAC_IOCTL_POLICY_REGISTER,
                         &request, sizeof(request), nullptr, 0, &returned, nullptr)) {
        const DWORD error = GetLastError();
        AuditEvent("kernel.policy", "register-failed", "ioctl", error, true);
        CloseHandle(device);
        return false;
    }

    CAC_POLICY_RESPONSE response = {};
    if (!DeviceIoControl(device, CAC_IOCTL_POLICY_QUERY,
                         &request, sizeof(request), &response, sizeof(response),
                         &returned, nullptr)) {
        const DWORD error = GetLastError();
        AuditEvent("kernel.policy", "query-failed", "ioctl", error, true);
        CloseHandle(device);
        return false;
    }

    const bool verified = response.Version == CAC_KERNEL_PROTOCOL_VERSION &&
                          response.Registered == 1 &&
                          response.ProcessId == request.ProcessId &&
                          response.ProcessCreateTime != 0 &&
                          response.Flags == request.Flags &&
                          SameProfileId(response.ProfileId, request.ProfileId);
    if (!verified) {
        AuditEvent("kernel.policy", "verify-failed", "response", response.Registered, true);
        CloseHandle(device);
        return false;
    }

    AuditEvent("kernel.policy", "verified", "per-process policy",
               request.ProcessId, true);
    CloseHandle(device);
    return true;
}
