#define _WIN32_WINNT 0x0A00

#include "ChildInject.h"

#include <windows.h>
#include <winternl.h>
#include <sddl.h>

#include <cwchar>
#include <string>
#include <vector>

#include "ApiHooks.h"
#include "Audit.h"

#pragma comment(lib, "advapi32.lib")

namespace {

typedef BOOL (WINAPI* PFN_CreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
                                          LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR,
                                          LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI* PFN_CreateProcessInternalW)(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
                                                  LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR,
                                                  LPSTARTUPINFOW, LPPROCESS_INFORMATION, PHANDLE);
typedef BOOL (WINAPI* PFN_CreateProcessAsUserW)(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
                                                LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR,
                                                LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI* PFN_CreateProcessWithTokenW)(HANDLE, DWORD, LPCWSTR, LPWSTR, DWORD, LPVOID,
                                                   LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

PFN_CreateProcessW g_origCreateProcessW = nullptr;
PFN_CreateProcessInternalW g_origCreateProcessInternalW = nullptr;
PFN_CreateProcessAsUserW g_origCreateProcessAsUserW = nullptr;
PFN_CreateProcessWithTokenW g_origCreateProcessWithTokenW = nullptr;
thread_local bool g_inProcessCreation = false;

typedef NTSTATUS (NTAPI* PFN_NtCreateUserProcess)(PHANDLE, PHANDLE, ACCESS_MASK, ACCESS_MASK,
                                                  POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES, ULONG, ULONG,
                                                  PRTL_USER_PROCESS_PARAMETERS, PVOID, PVOID);
PFN_NtCreateUserProcess g_origNtCreateUserProcess = nullptr;

std::wstring HostImagePath() {
    wchar_t path[32768] = {};
    const DWORD length = GetModuleFileNameW(nullptr, path, static_cast<DWORD>(_countof(path)));
    if (length == 0 || length >= _countof(path)) return std::wstring();
    return std::wstring(path, length);
}

std::wstring BridgeModulePath() {
    HMODULE self = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCWSTR>(&BridgeModulePath), &self)) {
        return std::wstring();
    }
    wchar_t path[32768] = {};
    const DWORD length = GetModuleFileNameW(self, path, static_cast<DWORD>(_countof(path)));
    if (length == 0 || length >= _countof(path)) return std::wstring();
    return std::wstring(path, length);
}

std::wstring BaseName(const std::wstring& path) {
    const size_t slash = path.find_last_of(L"\\/");
    return slash == std::wstring::npos ? path : path.substr(slash + 1);
}

std::wstring NormalizeImagePath(const std::wstring& path) {
    if (path.empty()) return std::wstring();
    wchar_t buffer[32768] = {};
    const DWORD length = GetFullPathNameW(path.c_str(), static_cast<DWORD>(_countof(buffer)), buffer, nullptr);
    if (length == 0 || length >= _countof(buffer)) return std::wstring();
    return std::wstring(buffer, length);
}

std::wstring DirectoryName(const std::wstring& path) {
    const size_t slash = path.find_last_of(L"\\/");
    return slash == std::wstring::npos ? std::wstring() : path.substr(0, slash);
}

std::wstring EnvironmentValue(const wchar_t* name) {
    wchar_t buffer[32768] = {};
    const DWORD length = GetEnvironmentVariableW(name, buffer, static_cast<DWORD>(_countof(buffer)));
    if (length == 0 || length >= _countof(buffer)) return std::wstring();
    return std::wstring(buffer, length);
}

// Electron passes the image as the first token of lpCommandLine when
// lpApplicationName is NULL.
bool ExtractImageName(const wchar_t* application, const wchar_t* commandLine, std::wstring& image) {
    image.clear();
    if (application && *application) {
        image = application;
        return true;
    }
    if (!commandLine) return false;
    const wchar_t* cursor = commandLine;
    while (*cursor == L' ' || *cursor == L'\t') ++cursor;
    if (*cursor == L'\0') return false;
    if (*cursor == L'"') {
        ++cursor;
        const wchar_t* end = wcschr(cursor, L'"');
        if (!end) return false;
        image.assign(cursor, end);
        return !image.empty();
    }
    const wchar_t* end = cursor;
    while (*end && *end != L' ' && *end != L'\t') ++end;
    image.assign(cursor, end);
    return !image.empty();
}

bool InjectLibrary(HANDLE process, const std::wstring& dllPath, std::string* error) {
    const size_t bytes = (dllPath.size() + 1) * sizeof(wchar_t);
    void* remote = VirtualAllocEx(process, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) {
        *error = "VirtualAllocEx failed";
        return false;
    }
    SIZE_T written = 0;
    if (!WriteProcessMemory(process, remote, dllPath.c_str(), bytes, &written) || written != bytes) {
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

    HANDLE thread = CreateRemoteThread(process, nullptr, 0,
                                       reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibrary),
                                       remote, 0, nullptr);
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
    // The thread exit code is a 32-bit value even on x64 and is not a safe
    // way to validate an HMODULE. NativeBridge's ready event is the authority.
    return true;
}

HANDLE CreateReadyEvent(DWORD processId, bool* alreadyExists) {
    wchar_t name[96] = {};
    std::swprintf(name, _countof(name), L"Local\\CACNativeBridgeReady_%lu",
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

bool WaitForReady(HANDLE event) {
    return event && WaitForSingleObject(event, 20000) == WAIT_OBJECT_0;
}

bool CloseFailedChild(LPPROCESS_INFORMATION processInformation) {
    if (!processInformation) return false;
    const DWORD processId = processInformation->dwProcessId;
    bool stopped = true;
    if (processInformation->hProcess) {
        if (!TerminateProcess(processInformation->hProcess, 4) &&
            GetLastError() != ERROR_ACCESS_DENIED) {
            stopped = false;
        }
        if (WaitForSingleObject(processInformation->hProcess, 5000) != WAIT_OBJECT_0) {
            stopped = false;
        }
    }
    if (!stopped) AuditEvent("native.child", "terminate-failed", nullptr, processId, true);
    if (processInformation->hThread) CloseHandle(processInformation->hThread);
    if (processInformation->hProcess) CloseHandle(processInformation->hProcess);
    processInformation->hThread = nullptr;
    processInformation->hProcess = nullptr;
    processInformation->dwThreadId = 0;
    processInformation->dwProcessId = 0;
    return stopped;
}

bool IsNetworkToolImage(const std::wstring& baseName) {
    static const wchar_t* const tools[] = {
        L"powershell.exe", L"pwsh.exe", L"cmd.exe", L"ipconfig.exe", L"netsh.exe",
        L"wmic.exe", L"getmac.exe", L"route.exe", L"arp.exe", L"systeminfo.exe",
        L"nbtstat.exe",
    };
    for (const wchar_t* tool : tools) {
        if (_wcsicmp(baseName.c_str(), tool) == 0) return true;
    }
    return false;
}

bool PrepareInjection(const wchar_t* application, const wchar_t* commandLine, std::wstring& dllPath) {
    std::wstring image;
    const bool haveImage = ExtractImageName(application, commandLine, image);
    const std::wstring baseName = haveImage ? BaseName(image) : std::wstring();
    const std::wstring normalizedImage = haveImage ? NormalizeImagePath(image) : std::wstring();
    const std::wstring normalizedHost = NormalizeImagePath(HostImagePath());
    const bool sameImage = !normalizedImage.empty() && !normalizedHost.empty() &&
                           _wcsicmp(normalizedImage.c_str(), normalizedHost.c_str()) == 0;
    const bool toolImage = haveImage && NativeCleanNetworkEnabled() && IsNetworkToolImage(baseName);
    const bool candidate = sameImage || toolImage;
    dllPath.clear();
    if (candidate) {
        dllPath = EnvironmentValue(L"CAC_NATIVE_DLL");
        if (dllPath.empty()) dllPath = DirectoryName(BridgeModulePath()) + L"\\NativeBridge.dll";
    }
    return candidate && !dllPath.empty() &&
           GetFileAttributesW(dllPath.c_str()) != INVALID_FILE_ATTRIBUTES;
}

bool FinishInjection(const std::wstring& dllPath, bool inject, bool forcedSuspend,
                     LPPROCESS_INFORMATION processInformation) {
    if (!processInformation) return false;
    if (!inject) {
        if (forcedSuspend) ResumeThread(processInformation->hThread);
        return true;
    }

    const DWORD processId = processInformation->dwProcessId;
    bool alreadyExists = false;
    HANDLE ready = CreateReadyEvent(processId, &alreadyExists);
    std::string error;
    const bool injected = ready && (alreadyExists || InjectLibrary(processInformation->hProcess, dllPath, &error));
    const bool readySignaled = injected && WaitForReady(ready);
    if (ready) CloseHandle(ready);

    if (!injected || !readySignaled) {
        if (!ready) error = "ready event creation failed";
        else if (injected) error = "NativeBridge ready signal was not received";
        AuditEvent("native.child", "failed", error.c_str(), processId, true);
        const bool stopped = CloseFailedChild(processInformation);
        SetLastError(stopped ? ERROR_DLL_INIT_FAILED : ERROR_PROCESS_ABORTED);
        return false;
    }

    AuditEvent("native.child", "injected", nullptr, processId, true);
    if (forcedSuspend) ResumeThread(processInformation->hThread);
    return true;
}

BOOL WINAPI HookCreateProcessW(LPCWSTR application, LPWSTR commandLine,
                               LPSECURITY_ATTRIBUTES processAttributes,
                               LPSECURITY_ATTRIBUTES threadAttributes, BOOL inheritHandles,
                               DWORD creationFlags, LPVOID environment, LPCWSTR currentDirectory,
                               LPSTARTUPINFOW startupInfo, LPPROCESS_INFORMATION processInformation) {
    if (!g_origCreateProcessW) return FALSE;
    std::wstring dllPath;
    const bool inject = PrepareInjection(application, commandLine, dllPath);
    bool forcedSuspend = false;
    DWORD effectiveFlags = creationFlags;
    if (inject && !(effectiveFlags & CREATE_SUSPENDED)) {
        effectiveFlags |= CREATE_SUSPENDED;
        forcedSuspend = true;
    }
    const bool previous = g_inProcessCreation;
    g_inProcessCreation = true;
    const BOOL created = g_origCreateProcessW(application, commandLine, processAttributes,
                                              threadAttributes, inheritHandles, effectiveFlags,
                                              environment, currentDirectory, startupInfo,
                                              processInformation);
    g_inProcessCreation = previous;
    if (!created) return FALSE;
    return FinishInjection(dllPath, inject, forcedSuspend, processInformation) ? TRUE : FALSE;
}

BOOL WINAPI HookCreateProcessInternalW(HANDLE token, LPCWSTR application, LPWSTR commandLine,
                                       LPSECURITY_ATTRIBUTES processAttributes,
                                       LPSECURITY_ATTRIBUTES threadAttributes, BOOL inheritHandles,
                                       DWORD creationFlags, LPVOID environment, LPCWSTR currentDirectory,
                                       LPSTARTUPINFOW startupInfo, LPPROCESS_INFORMATION processInformation,
                                       PHANDLE newToken) {
    if (!g_origCreateProcessInternalW) return FALSE;
    if (g_inProcessCreation) {
        return g_origCreateProcessInternalW(token, application, commandLine, processAttributes,
                                            threadAttributes, inheritHandles, creationFlags,
                                            environment, currentDirectory, startupInfo,
                                            processInformation, newToken);
    }
    std::wstring dllPath;
    const bool inject = PrepareInjection(application, commandLine, dllPath);
    bool forcedSuspend = false;
    DWORD effectiveFlags = creationFlags;
    if (inject && !(effectiveFlags & CREATE_SUSPENDED)) {
        effectiveFlags |= CREATE_SUSPENDED;
        forcedSuspend = true;
    }
    const BOOL created = g_origCreateProcessInternalW(token, application, commandLine, processAttributes,
                                                      threadAttributes, inheritHandles, effectiveFlags,
                                                      environment, currentDirectory, startupInfo,
                                                      processInformation, newToken);
    if (!created) return FALSE;
    return FinishInjection(dllPath, inject, forcedSuspend, processInformation) ? TRUE : FALSE;
}

BOOL WINAPI HookCreateProcessAsUserW(HANDLE token, LPCWSTR application, LPWSTR commandLine,
                                     LPSECURITY_ATTRIBUTES processAttributes,
                                     LPSECURITY_ATTRIBUTES threadAttributes, BOOL inheritHandles,
                                     DWORD creationFlags, LPVOID environment, LPCWSTR currentDirectory,
                                     LPSTARTUPINFOW startupInfo, LPPROCESS_INFORMATION processInformation) {
    if (!g_origCreateProcessAsUserW) return FALSE;
    if (g_inProcessCreation) {
        return g_origCreateProcessAsUserW(token, application, commandLine, processAttributes,
                                          threadAttributes, inheritHandles, creationFlags, environment,
                                          currentDirectory, startupInfo, processInformation);
    }
    std::wstring dllPath;
    const bool inject = PrepareInjection(application, commandLine, dllPath);
    bool forcedSuspend = false;
    DWORD effectiveFlags = creationFlags;
    if (inject && !(effectiveFlags & CREATE_SUSPENDED)) {
        effectiveFlags |= CREATE_SUSPENDED;
        forcedSuspend = true;
    }
    const bool previous = g_inProcessCreation;
    g_inProcessCreation = true;
    const BOOL created = g_origCreateProcessAsUserW(token, application, commandLine, processAttributes,
                                                    threadAttributes, inheritHandles, effectiveFlags,
                                                    environment, currentDirectory, startupInfo,
                                                    processInformation);
    g_inProcessCreation = previous;
    if (!created) return FALSE;
    const bool injectionReady = FinishInjection(dllPath, inject, forcedSuspend, processInformation);
    if (!injectionReady) return FALSE;
    if (inject) AuditEventRateLimited("native.child", "entry", "CreateProcessAsUserW");
    return TRUE;
}

BOOL WINAPI HookCreateProcessWithTokenW(HANDLE token, DWORD logonFlags, LPCWSTR application,
                                        LPWSTR commandLine, DWORD creationFlags, LPVOID environment,
                                        LPCWSTR currentDirectory, LPSTARTUPINFOW startupInfo,
                                        LPPROCESS_INFORMATION processInformation) {
    if (!g_origCreateProcessWithTokenW) return FALSE;
    if (g_inProcessCreation) {
        return g_origCreateProcessWithTokenW(token, logonFlags, application, commandLine,
                                             creationFlags, environment, currentDirectory,
                                             startupInfo, processInformation);
    }
    std::wstring dllPath;
    const bool inject = PrepareInjection(application, commandLine, dllPath);
    bool forcedSuspend = false;
    DWORD effectiveFlags = creationFlags;
    if (inject && !(effectiveFlags & CREATE_SUSPENDED)) {
        effectiveFlags |= CREATE_SUSPENDED;
        forcedSuspend = true;
    }
    const bool previous = g_inProcessCreation;
    g_inProcessCreation = true;
    const BOOL created = g_origCreateProcessWithTokenW(token, logonFlags, application, commandLine,
                                                       effectiveFlags, environment, currentDirectory,
                                                       startupInfo, processInformation);
    g_inProcessCreation = previous;
    if (!created) return FALSE;
    const bool injectionReady = FinishInjection(dllPath, inject, forcedSuspend, processInformation);
    if (!injectionReady) return FALSE;
    if (inject) AuditEventRateLimited("native.child", "entry", "CreateProcessWithTokenW");
    return TRUE;
}

std::wstring UnicodeValue(const UNICODE_STRING& value) {
    if (!value.Buffer || value.Length == 0) return std::wstring();
    return std::wstring(value.Buffer, value.Length / sizeof(wchar_t));
}

NTSTATUS NTAPI HookNtCreateUserProcess(PHANDLE processHandle, PHANDLE threadHandle,
                                       ACCESS_MASK processAccess, ACCESS_MASK threadAccess,
                                       POBJECT_ATTRIBUTES processAttributes,
                                       POBJECT_ATTRIBUTES threadAttributes, ULONG processFlags,
                                       ULONG threadFlags,
                                       PRTL_USER_PROCESS_PARAMETERS processParameters,
                                       PVOID createInfo, PVOID attributeList) {
    if (!g_origNtCreateUserProcess) return static_cast<NTSTATUS>(0xC0000002L);
    if (g_inProcessCreation) {
        return g_origNtCreateUserProcess(processHandle, threadHandle, processAccess, threadAccess,
                                         processAttributes, threadAttributes, processFlags, threadFlags,
                                         processParameters, createInfo, attributeList);
    }

    const std::wstring image = processParameters ? UnicodeValue(processParameters->ImagePathName)
                                                 : std::wstring();
    const std::wstring commandLine = processParameters ? UnicodeValue(processParameters->CommandLine)
                                                       : std::wstring();
    std::wstring dllPath;
    const bool inject = PrepareInjection(image.c_str(), commandLine.c_str(), dllPath);
    constexpr ULONG kThreadCreateSuspended = 0x00000001UL;
    const bool forcedSuspend = inject && ((threadFlags & kThreadCreateSuspended) == 0);
    const ULONG effectiveThreadFlags = forcedSuspend ?
        (threadFlags | kThreadCreateSuspended) : threadFlags;

    const NTSTATUS status = g_origNtCreateUserProcess(
        processHandle, threadHandle, processAccess, threadAccess, processAttributes, threadAttributes,
        processFlags, effectiveThreadFlags, processParameters, createInfo, attributeList);
    if (status < 0 || !processHandle || !*processHandle) return status;

    if (inject) {
        const DWORD processId = GetProcessId(*processHandle);
        HANDLE target = OpenProcess(PROCESS_TERMINATE | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                                        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | SYNCHRONIZE,
                                    FALSE, processId);
        const bool borrowed = (target == nullptr);
        if (!target) target = *processHandle;

        bool alreadyExists = false;
        HANDLE ready = CreateReadyEvent(processId, &alreadyExists);
        std::string error;
        const bool injected = ready && (alreadyExists || InjectLibrary(target, dllPath, &error));
        const bool readySignaled = injected && WaitForReady(ready);
        if (ready) CloseHandle(ready);
        if (injected && readySignaled) {
            AuditEvent("native.child", "injected", "ntcreateuserprocess", processId, true);
        } else {
            if (!ready) error = "ready event creation failed";
            else if (injected) error = "NativeBridge ready signal was not received";
            AuditEvent("native.child", "failed", error.c_str(), processId, true);
            bool stopped = TerminateProcess(target, 4) != FALSE;
            if (!stopped && GetLastError() == ERROR_ACCESS_DENIED) stopped = true;
            if (WaitForSingleObject(target, 5000) != WAIT_OBJECT_0) stopped = false;
            if (!stopped) AuditEvent("native.child", "terminate-failed", nullptr, processId, true);
        }
        if (!borrowed) CloseHandle(target);
        if (!(injected && readySignaled)) {
            if (threadHandle && *threadHandle) {
                CloseHandle(*threadHandle);
                *threadHandle = nullptr;
            }
            if (processHandle && *processHandle) {
                CloseHandle(*processHandle);
                *processHandle = nullptr;
            }
            SetLastError(ERROR_DLL_INIT_FAILED);
            return static_cast<NTSTATUS>(0xC0000225L);
        }
    }
    if (forcedSuspend && threadHandle && *threadHandle) ResumeThread(*threadHandle);
    return status;
}

}  // namespace

void InstallChildInjection() {
    InstallHookInlinePrimary("kernel32.dll", "CreateProcessW",
                             reinterpret_cast<void*>(&HookCreateProcessW),
                             reinterpret_cast<void**>(&g_origCreateProcessW));
    InstallHookInlinePrimary("kernel32.dll", "CreateProcessInternalW",
                             reinterpret_cast<void*>(&HookCreateProcessInternalW),
                             reinterpret_cast<void**>(&g_origCreateProcessInternalW));
    InstallHookInlinePrimary("advapi32.dll", "CreateProcessAsUserW",
                             reinterpret_cast<void*>(&HookCreateProcessAsUserW),
                             reinterpret_cast<void**>(&g_origCreateProcessAsUserW));
    InstallHookInlinePrimary("advapi32.dll", "CreateProcessWithTokenW",
                             reinterpret_cast<void*>(&HookCreateProcessWithTokenW),
                             reinterpret_cast<void**>(&g_origCreateProcessWithTokenW));
    InstallHookInlinePrimary("ntdll.dll", "NtCreateUserProcess",
                             reinterpret_cast<void*>(&HookNtCreateUserProcess),
                             reinterpret_cast<void**>(&g_origNtCreateUserProcess));
}
