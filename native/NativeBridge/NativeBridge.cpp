#include <windows.h>
#include <cstdio>
#include <cwchar>

#include "ApiHooks.h"
#include "Audit.h"
#include "ChildInject.h"
#include "Identity.h"
#include "KernelPolicy.h"
#include "NetworkHooks.h"
#include "WfpPolicy.h"
#include "WmiHooks.h"

namespace {

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

bool SignalReady() {
    wchar_t name[96] = {};
    std::swprintf(name, _countof(name), L"Local\\CACNativeBridgeReady_%lu",
                  static_cast<unsigned long>(GetCurrentProcessId()));
    HANDLE event = OpenEventW(EVENT_MODIFY_STATE, FALSE, name);
    if (!event) {
        AuditEvent("native.bridge", "ready-signal-failed", "OpenEventW", GetLastError(), true);
        return false;
    }
    const BOOL signaled = SetEvent(event);
    const DWORD error = signaled ? ERROR_SUCCESS : GetLastError();
    CloseHandle(event);
    if (!signaled) {
        AuditEvent("native.bridge", "ready-signal-failed", "SetEvent", error, true);
        return false;
    }
    return true;
}

DWORD WINAPI InitializeThread(LPVOID) {
    ProfileIdentity& identity = ProfileIdentity::Get();
    AuditInit(identity.profileDir);
    AuditEvent("native.bridge", "attach", ProcessTypeDetail());

    const bool apiReady = InstallApiHooks();
    InstallChildInjection();
    InstallWmiHooks();
    InstallNetworkHooks();
    InstallCpuHooksFromManifest();

    const bool kernelPolicyReady = RegisterCurrentProcessKernelPolicy();
    if (!kernelPolicyReady && KernelPolicyRequired()) {
        AuditEvent("native.bridge", "failed", "kernel-policy-required", 0, false);
        return 0;
    }

    const bool wfpReady = InstallWfpBoundary();
    if (!wfpReady && WfpPolicyRequired()) {
        AuditEvent("native.bridge", "failed", "wfp-policy-required", 0, false);
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
        return 0;
    }

    if (!SignalReady()) return 0;
    AuditEvent("native.bridge", "ready");
    return 0;
}

}  // namespace

BOOL WINAPI DllMain(HMODULE module, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(module);
        HANDLE thread = CreateThread(nullptr, 0, InitializeThread, nullptr, 0, nullptr);
        if (thread) CloseHandle(thread);
    }
    return TRUE;
}

extern "C" __declspec(dllexport) BOOL WINAPI NativeBridgeInitialize() {
    return TRUE;
}
