#include <windows.h>
#include <cstdio>
#include <cwchar>

#include "ApiHooks.h"
#include "Audit.h"
#include "ChildInject.h"
#include "Identity.h"
#include "NetworkHooks.h"
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

void SignalReady() {
    wchar_t name[96] = {};
    std::swprintf(name, _countof(name), L"Local\\CACNativeBridgeReady_%lu",
                  static_cast<unsigned long>(GetCurrentProcessId()));
    HANDLE event = OpenEventW(EVENT_MODIFY_STATE, FALSE, name);
    if (event) {
        SetEvent(event);
        CloseHandle(event);
    }
}

DWORD WINAPI InitializeThread(LPVOID) {
    ProfileIdentity& identity = ProfileIdentity::Get();
    AuditInit(identity.profileDir);
    AuditEvent("native.bridge", "attach", ProcessTypeDetail());

    InstallApiHooks();
    InstallChildInjection();
    InstallWmiHooks();
    InstallNetworkHooks();
    InstallCpuHooksFromManifest();

    char scan[8] = {};
    if (GetEnvironmentVariableA("CAC_NATIVE_SCAN", scan, sizeof(scan)) > 0 && scan[0] == '1') {
        ScanCpuCandidates();
    }

    AuditEvent("native.bridge", "ready");
    SignalReady();
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
