#define _WIN32_WINNT 0x0A00

#include <windows.h>
#include <tlhelp32.h>
#include <sddl.h>

#include <cstdio>
#include <cstring>
#include <cwchar>
#include <string>
#include <vector>

#pragma comment(lib, "advapi32.lib")

namespace {

const wchar_t* kDefaultTarget = L"cowork-svc.exe";
const wchar_t* kDefaultDll = L"C:\\ProgramData\\CAC\\native\\NativeBridge.dll";
const wchar_t* kDefaultAudit = L"C:\\ProgramData\\CAC\\logs\\service-injector.jsonl";
const wchar_t* kServiceName = L"CacServiceInjector";

SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
SERVICE_STATUS g_status = {};
HANDLE g_stopEvent = nullptr;

bool EnableDebugPrivilege() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        return false;
    }
    LUID luid = {};
    const bool found = LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid) != FALSE;
    TOKEN_PRIVILEGES privileges = {};
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Luid = luid;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    const bool adjusted = found &&
        AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), nullptr, nullptr) != FALSE;
    const DWORD error = GetLastError();
    CloseHandle(token);
    return adjusted && error == ERROR_SUCCESS;
}

void EnsureDirectory(const wchar_t* path) {
    CreateDirectoryW(path, nullptr);
}

void AppendAudit(const std::wstring& auditPath, const char* action, DWORD processId,
                 const char* detail) {
    EnsureDirectory(L"C:\\ProgramData\\CAC");
    EnsureDirectory(L"C:\\ProgramData\\CAC\\logs");
    HANDLE file = CreateFileW(auditPath.c_str(), FILE_APPEND_DATA,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return;

    SYSTEMTIME now = {};
    GetSystemTime(&now);
    char line[1024] = {};
    std::snprintf(
        line, sizeof(line),
        "{\"utc\":\"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ\",\"surface\":\"service.injector\","
        "\"action\":\"%s\",\"pid\":%lu,\"detail\":\"%s\"}\r\n",
        now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond,
        now.wMilliseconds, action ? action : "", static_cast<unsigned long>(processId),
        detail ? detail : "");
    DWORD written = 0;
    WriteFile(file, line, static_cast<DWORD>(std::strlen(line)), &written, nullptr);
    CloseHandle(file);
}

DWORD FindProcessId(const wchar_t* targetName) {
    std::wstring target = targetName ? targetName : L"";
    if (!target.empty() && target.find(L'.') == std::wstring::npos) {
        target += L".exe";
    }
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    DWORD result = 0;
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, target.c_str()) == 0) {
                result = entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return result;
}

bool IsModuleLoaded(DWORD processId, const wchar_t* moduleName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
    if (snapshot == INVALID_HANDLE_VALUE) return false;
    MODULEENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    bool loaded = false;
    if (Module32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szModule, moduleName) == 0) {
                loaded = true;
                break;
            }
        } while (Module32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return loaded;
}

HANDLE CreateBridgeEvent(DWORD processId, const wchar_t* kind, bool* alreadyExists) {
    wchar_t name[96] = {};
    std::swprintf(name, _countof(name), L"Local\\CACNativeBridge%s_%lu", kind,
                  static_cast<unsigned long>(processId));
    if (alreadyExists) *alreadyExists = false;

    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:(A;;0x00100003;;;WD)", SDDL_REVISION_1, &descriptor, nullptr)) {
        return nullptr;
    }
    SECURITY_ATTRIBUTES attributes = {};
    attributes.nLength = sizeof(attributes);
    attributes.lpSecurityDescriptor = descriptor;
    SetLastError(ERROR_SUCCESS);
    HANDLE event = CreateEventW(&attributes, TRUE, FALSE, name);
    const DWORD createError = GetLastError();
    LocalFree(descriptor);
    if (event) {
        if (alreadyExists) *alreadyExists = (createError == ERROR_ALREADY_EXISTS);
        return event;
    }
    if (createError == ERROR_ACCESS_DENIED) {
        event = OpenEventW(EVENT_MODIFY_STATE | SYNCHRONIZE, FALSE, name);
        if (event && alreadyExists) *alreadyExists = true;
    }
    return event;
}

bool InjectLibrary(HANDLE process, const std::wstring& dllPath, std::string* error) {
    const size_t bytes = (dllPath.size() + 1) * sizeof(wchar_t);
    void* remote = VirtualAllocEx(process, nullptr, bytes, MEM_COMMIT | MEM_RESERVE,
                                  PAGE_READWRITE);
    if (!remote) {
        *error = "VirtualAllocEx failed";
        return false;
    }
    SIZE_T written = 0;
    if (!WriteProcessMemory(process, remote, dllPath.c_str(), bytes, &written) ||
        written != bytes) {
        *error = "WriteProcessMemory failed";
        VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        return false;
    }

    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC loadLibrary = kernel32 ? GetProcAddress(kernel32, "LoadLibraryW") : nullptr;
    if (!loadLibrary) {
        *error = "LoadLibraryW not found";
        VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        return false;
    }

    HANDLE thread = CreateRemoteThread(
        process, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibrary), remote, 0, nullptr);
    if (!thread) {
        *error = "CreateRemoteThread failed";
        VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        return false;
    }
    const DWORD wait = WaitForSingleObject(thread, 20000);
    CloseHandle(thread);
    VirtualFreeEx(process, remote, 0, MEM_RELEASE);
    if (wait != WAIT_OBJECT_0) {
        *error = "injection timed out";
        return false;
    }
    return true;
}

bool InjectAndWait(DWORD processId, const std::wstring& dllPath, std::string* error) {
    if (IsModuleLoaded(processId, L"NativeBridge.dll")) {
        return true;
    }

    HANDLE process = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE | PROCESS_VM_READ | SYNCHRONIZE,
        FALSE, processId);
    if (!process) {
        char detail[64] = {};
        std::snprintf(detail, sizeof(detail), "OpenProcess=%lu", GetLastError());
        *error = detail;
        return false;
    }

    bool readyExists = false;
    HANDLE ready = CreateBridgeEvent(processId, L"Ready", &readyExists);
    HANDLE failed = CreateBridgeEvent(processId, L"Failed", nullptr);
    if (!ready || !failed) {
        *error = "bridge event creation failed";
        if (ready) CloseHandle(ready);
        if (failed) CloseHandle(failed);
        CloseHandle(process);
        return false;
    }
    // A stale event may exist if the PID was reused.  Reset before injection.
    ResetEvent(ready);
    ResetEvent(failed);

    const bool injected = InjectLibrary(process, dllPath, error);
    CloseHandle(process);
    if (!injected) {
        CloseHandle(ready);
        CloseHandle(failed);
        return false;
    }

    HANDLE events[2] = { ready, failed };
    const DWORD wait = WaitForMultipleObjects(_countof(events), events, FALSE, 20000);
    CloseHandle(ready);
    CloseHandle(failed);
    if (wait != WAIT_OBJECT_0) {
        *error = wait == WAIT_OBJECT_0 + 1 ? "NativeBridge reported failure"
                                           : "NativeBridge ready timeout";
        return false;
    }
    if (!IsModuleLoaded(processId, L"NativeBridge.dll")) {
        *error = "NativeBridge module not found after injection";
        return false;
    }
    return true;
}

int InjectOnce(const std::wstring& target, const std::wstring& dllPath,
               const std::wstring& auditPath) {
    const DWORD processId = FindProcessId(target.c_str());
    if (!processId) {
        AppendAudit(auditPath, "target-not-found", 0, "");
        std::fwprintf(stderr, L"[cac-injector] target not found: %s\n", target.c_str());
        return 2;
    }
    if (IsModuleLoaded(processId, L"NativeBridge.dll")) {
        AppendAudit(auditPath, "already-injected", processId, "");
        std::wprintf(L"[cac-injector] already injected: pid=%lu\n",
                     static_cast<unsigned long>(processId));
        return 0;
    }

    std::string error;
    if (!InjectAndWait(processId, dllPath, &error)) {
        AppendAudit(auditPath, "failed", processId, error.c_str());
        std::fwprintf(stderr, L"[cac-injector] inject failed: pid=%lu %hs\n",
                      static_cast<unsigned long>(processId), error.c_str());
        return 3;
    }
    AppendAudit(auditPath, "injected", processId, "");
    std::wprintf(L"[cac-injector] injected: pid=%lu\n",
                 static_cast<unsigned long>(processId));
    return 0;
}

int Watch(const std::wstring& target, const std::wstring& dllPath,
          const std::wstring& auditPath) {
    DWORD lastPid = 0;
    DWORD lastFailure = 0;
    AppendAudit(auditPath, "watch-start", 0, "");
    while (!g_stopEvent || WaitForSingleObject(g_stopEvent, 0) == WAIT_TIMEOUT) {
        const DWORD processId = FindProcessId(target.c_str());
        if (processId && processId != lastPid) {
            AppendAudit(auditPath, "target-found", processId, "");
            lastPid = processId;
        }
        if (processId && !IsModuleLoaded(processId, L"NativeBridge.dll")) {
            std::string error;
            if (!InjectAndWait(processId, dllPath, &error)) {
                const DWORD now = GetTickCount();
                if (lastFailure == 0 || now - lastFailure > 30000) {
                    AppendAudit(auditPath, "failed", processId, error.c_str());
                    lastFailure = now;
                }
            } else {
                AppendAudit(auditPath, "injected", processId, "");
                lastFailure = 0;
            }
        } else if (!processId && lastPid != 0) {
            AppendAudit(auditPath, "target-exited", lastPid, "");
            lastPid = 0;
        }
        Sleep(2000);
    }
    AppendAudit(auditPath, "watch-stop", 0, "");
    return 0;
}

void SetServiceStatusValue(DWORD state, DWORD win32ExitCode, DWORD waitHint) {
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState = state;
    g_status.dwWin32ExitCode = win32ExitCode;
    g_status.dwWaitHint = waitHint;
    g_status.dwControlsAccepted =
        state == SERVICE_RUNNING ? (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN) : 0;
    SetServiceStatus(g_statusHandle, &g_status);
}

DWORD WINAPI ServiceControlHandler(DWORD control, DWORD, LPVOID, LPVOID) {
    if (control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN) {
        SetServiceStatusValue(SERVICE_STOP_PENDING, NO_ERROR, 5000);
        if (g_stopEvent) SetEvent(g_stopEvent);
    }
    return NO_ERROR;
}

void WINAPI ServiceMain(DWORD, wchar_t**) {
    g_statusHandle = RegisterServiceCtrlHandlerExW(
        kServiceName, ServiceControlHandler, nullptr);
    if (!g_statusHandle) return;
    SetServiceStatusValue(SERVICE_START_PENDING, NO_ERROR, 5000);
    g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_stopEvent) {
        SetServiceStatusValue(SERVICE_STOPPED, GetLastError(), 0);
        return;
    }
    SetServiceStatusValue(SERVICE_RUNNING, NO_ERROR, 0);
    Watch(kDefaultTarget, kDefaultDll, kDefaultAudit);
    SetServiceStatusValue(SERVICE_STOPPED, NO_ERROR, 0);
}

void PrintUsage() {
    std::fwprintf(stderr,
                  L"usage: cac-service-injector [--target name] [--dll path] "
                  L"[--audit path] (--once | --watch | --service)\n");
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    std::wstring target = kDefaultTarget;
    std::wstring dllPath = kDefaultDll;
    std::wstring auditPath = kDefaultAudit;
    bool once = false;
    bool watch = false;
    bool service = false;

    for (int i = 1; i < argc; ++i) {
        if (_wcsicmp(argv[i], L"--target") == 0 && i + 1 < argc) {
            target = argv[++i];
        } else if (_wcsicmp(argv[i], L"--dll") == 0 && i + 1 < argc) {
            dllPath = argv[++i];
        } else if (_wcsicmp(argv[i], L"--audit") == 0 && i + 1 < argc) {
            auditPath = argv[++i];
        } else if (_wcsicmp(argv[i], L"--once") == 0) {
            once = true;
        } else if (_wcsicmp(argv[i], L"--watch") == 0) {
            watch = true;
        } else if (_wcsicmp(argv[i], L"--service") == 0) {
            service = true;
        } else {
            PrintUsage();
            return 2;
        }
    }

    EnableDebugPrivilege();
    if (service) {
        SERVICE_TABLE_ENTRYW table[] = {
            { const_cast<wchar_t*>(kServiceName), ServiceMain },
            { nullptr, nullptr },
        };
        if (!StartServiceCtrlDispatcherW(table)) {
            return 5;
        }
        return 0;
    }
    if (once) {
        return InjectOnce(target, dllPath, auditPath);
    }
    if (watch) {
        g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        return Watch(target, dllPath, auditPath);
    }
    PrintUsage();
    return 2;
}
