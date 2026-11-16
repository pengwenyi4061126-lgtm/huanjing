#include <windows.h>
#include <cstdio>
#include <cwchar>
#include <cstring>
#include <string>
#include <vector>

#include "ApiHooks.h"
#include "Audit.h"
#include "ChildInject.h"
#include "Identity.h"
#include "KernelPolicy.h"
#include "NetworkHooks.h"
#include "WfpPolicy.h"
#include "WmiHooks.h"

namespace {

std::wstring TrimWide(const std::wstring& value) {
    size_t begin = 0;
    while (begin < value.size() && (value[begin] == L' ' || value[begin] == L'\t' ||
                                    value[begin] == L'\r' || value[begin] == L'\n')) {
        ++begin;
    }
    size_t end = value.size();
    while (end > begin && (value[end - 1] == L' ' || value[end - 1] == L'\t' ||
                           value[end - 1] == L'\r' || value[end - 1] == L'\n')) {
        --end;
    }
    return value.substr(begin, end - begin);
}

void SetProfileEnvironment(const std::wstring& key, const std::wstring& value) {
    if (!key.empty() && !value.empty()) {
        SetEnvironmentVariableW(key.c_str(), value.c_str());
    }
}

// A service does not inherit the per-user CAC_* environment.  The injector
// writes the active Profile handoff here before loading NativeBridge.dll.
void LoadProgramDataProfile() {
    wchar_t existing[4] = {};
    if (GetEnvironmentVariableW(L"CAC_PROFILE_DIR", existing, _countof(existing)) > 0) {
        return;
    }

    HANDLE file = CreateFileW(
        L"C:\\ProgramData\\CAC\\active-profile.ini",
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return;
    }

    LARGE_INTEGER size = {};
    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 || size.QuadPart > 64 * 1024) {
        CloseHandle(file);
        return;
    }

    std::vector<BYTE> bytes(static_cast<size_t>(size.QuadPart));
    DWORD read = 0;
    const BOOL ok = ReadFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr);
    CloseHandle(file);
    if (!ok || read < 2) {
        return;
    }

    const wchar_t* text = reinterpret_cast<const wchar_t*>(bytes.data());
    size_t chars = read / sizeof(wchar_t);
    if (chars > 0 && text[0] == 0xFEFF) {
        ++text;
        --chars;
    }

    std::wstring content(text, chars);
    size_t pos = 0;
    while (pos < content.size()) {
        size_t end = content.find(L'\n', pos);
        if (end == std::wstring::npos) end = content.size();
        std::wstring line = TrimWide(content.substr(pos, end - pos));
        pos = end + 1;
        if (line.empty() || line[0] == L'#' || line[0] == L';') continue;

        const size_t equals = line.find(L'=');
        if (equals == std::wstring::npos) continue;
        const std::wstring key = TrimWide(line.substr(0, equals));
        const std::wstring value = TrimWide(line.substr(equals + 1));
        if (key == L"profile_dir") SetProfileEnvironment(L"CAC_PROFILE_DIR", value);
        else if (key == L"profile_identity") SetProfileEnvironment(L"CAC_PROFILE_IDENTITY", value);
        else if (key == L"mac") SetProfileEnvironment(L"CAC_MAC", value);
        else if (key == L"machine_id") SetProfileEnvironment(L"CAC_MACHINE_ID", value);
        else if (key == L"hostname") SetProfileEnvironment(L"CAC_HOSTNAME", value);
        else if (key == L"username") SetProfileEnvironment(L"CAC_USERNAME", value);
        else if (key == L"read_policy") SetProfileEnvironment(L"CAC_NATIVE_READ_POLICY", value);
        else if (key == L"cpuid_mode") SetProfileEnvironment(L"CAC_NATIVE_CPUID_MODE", value);
        else if (key == L"manifest") SetProfileEnvironment(L"CAC_NATIVE_MANIFEST", value);
        else if (key == L"network_mode") SetProfileEnvironment(L"CAC_NETWORK_MODE", value);
        else if (key == L"audit") SetProfileEnvironment(L"CAC_NATIVE_AUDIT", value);
    }
}

bool NetworkHooksDisabledForCommandLineProxy() {
    char value[16] = {};
    const DWORD length = GetEnvironmentVariableA(
        "CAC_NATIVE_DISABLE_NETWORK_HOOKS", value, static_cast<DWORD>(sizeof(value)));
    if (length == 0 || length >= sizeof(value)) return false;
    for (DWORD i = 0; i < length; ++i) {
        if (value[i] >= 'A' && value[i] <= 'Z') value[i] = static_cast<char>(value[i] - 'A' + 'a');
    }
    return std::strcmp(value, "1") == 0 || std::strcmp(value, "true") == 0 ||
           std::strcmp(value, "yes") == 0;
}

const char* ProcessTypeDetail() {
    const wchar_t* commandLine = GetCommandLineW();
    if (commandLine) {
        if (wcsstr(commandLine, L"--type=renderer")) return "process=renderer";
        if (wcsstr(commandLine, L"--type=utility")) return "process=utility";
        if (wcsstr(commandLine, L"--type=gpu-process")) return "process=gpu-process";
        if (wcsstr(commandLine, L"--type=crashpad-handler")) return "process=crashpad-handler";
    }
    return "process=main";
}

bool SignalBridgeEvent(const wchar_t* kind) {
    wchar_t name[96] = {};
    std::swprintf(name, _countof(name), L"Local\\CACNativeBridge%s_%lu", kind,
                  static_cast<unsigned long>(GetCurrentProcessId()));
    HANDLE event = OpenEventW(EVENT_MODIFY_STATE, FALSE, name);
    if (!event) {
        return false;
    }
    const BOOL signaled = SetEvent(event);
    const DWORD error = signaled ? ERROR_SUCCESS : GetLastError();
    CloseHandle(event);
    if (!signaled) {
        return false;
    }
    return true;
}

bool SignalReady() {
    if (!SignalBridgeEvent(L"Ready")) {
        AuditEvent("native.bridge", "ready-signal-failed", "SetEvent", GetLastError(), true);
        return false;
    }
    return true;
}

void SignalFailure() {
    (void)SignalBridgeEvent(L"Failed");
}

DWORD WINAPI InitializeThread(LPVOID) {
    LoadProgramDataProfile();
    ProfileIdentity& identity = ProfileIdentity::Get();
    AuditInit(identity.profileDir);
    AuditEvent("native.bridge", "attach", ProcessTypeDetail());
    {
        char identityDetail[512] = {};
        std::snprintf(identityDetail, sizeof(identityDetail),
                      "mac=%s host=%s machine=%s disk=%s",
                      identity.mac.c_str(), identity.hostname.c_str(),
                      identity.machineId.c_str(), identity.diskSerial.c_str());
        AuditEvent("native.identity", "loaded", identityDetail);
    }

    const bool apiReady = InstallApiHooks();
    InstallChildInjection();
    InstallWmiHooks();
    if (NetworkHooksDisabledForCommandLineProxy()) {
        AuditEvent("network.hooks", "skipped", "command-line-proxy-authoritative");
    } else {
        InstallNetworkHooks();
    }
    InstallCpuHooksFromManifest();

    const bool kernelPolicyReady = RegisterCurrentProcessKernelPolicy();
    if (!kernelPolicyReady && KernelPolicyRequired()) {
        AuditEvent("native.bridge", "failed", "kernel-policy-required", 0, false);
        SignalFailure();
        return 0;
    }

    const bool wfpReady = InstallWfpBoundary();
    if (!wfpReady && WfpPolicyRequired()) {
        AuditEvent("native.bridge", "failed", "wfp-policy-required", 0, false);
        SignalFailure();
        return 0;
    }

    char scan[8] = {};
    if (GetEnvironmentVariableA("CAC_NATIVE_SCAN", scan, sizeof(scan)) > 0 && scan[0] == '1') {
        ScanCpuCandidates();
    }

    const unsigned int failures = NativeHookInstallFailures();
    if (!apiReady || failures != 0) {
        char detail[96] = {};
        std::snprintf(detail, sizeof(detail), "required-hook-failures=%u", failures);
        AuditEvent("native.bridge", "failed", detail, failures, true);
        SignalFailure();
        return 0;
    }

    if (!SignalReady()) {
        SignalFailure();
        return 0;
    }
    AuditEvent("native.bridge", "ready");
    return 0;
}

}  // namespace

BOOL WINAPI DllMain(HMODULE module, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(module);
        HANDLE thread = CreateThread(nullptr, 0, InitializeThread, nullptr, 0, nullptr);
        if (thread) {
            CloseHandle(thread);
        } else {
            SignalFailure();
        }
    }
    return TRUE;
}

extern "C" __declspec(dllexport) BOOL WINAPI NativeBridgeInitialize() {
    return TRUE;
}
