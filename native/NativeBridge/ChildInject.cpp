#define _WIN32_WINNT 0x0A00

#include "ChildInject.h"

#include <windows.h>
#include <winternl.h>

#include <string>
#include <vector>

#include "ApiHooks.h"
#include "Audit.h"

namespace {

typedef BOOL (WINAPI* PFN_CreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
                                          LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR,
                                          LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI* PFN_CreateProcessInternalW)(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
                                                  LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR,
                                                  LPSTARTUPINFOW, LPPROCESS_INFORMATION, PHANDLE);

PFN_CreateProcessW g_origCreateProcessW = nullptr;
PFN_CreateProcessInternalW g_origCreateProcessInternalW = nullptr;
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
    DWORD moduleBase = 0;
    GetExitCodeThread(thread, &moduleBase);
    CloseHandle(thread);
    VirtualFreeEx(process, remote, 0, MEM_RELEASE);
    if (wait != WAIT_OBJECT_0 || moduleBase == 0) {
        *error = wait == WAIT_OBJECT_0 ? "LoadLibraryW returned NULL in child" : "injection timed out";
        return false;
    }
    return true;
}

bool PrepareInjection(const wchar_t* application, const wchar_t* commandLine, std::wstring& dllPath) {
    std::wstring image;
    const bool sameImage = ExtractImageName(application, commandLine, image) &&
                           _wcsicmp(BaseName(image).c_str(), BaseName(HostImagePath()).c_str()) == 0;
    dllPath.clear();
    if (sameImage) {
        dllPath = EnvironmentValue(L"CAC_NATIVE_DLL");
        if (dllPath.empty()) dllPath = DirectoryName(BridgeModulePath()) + L"\\NativeBridge.dll";
    }
    return sameImage && !dllPath.empty() &&
           GetFileAttributesW(dllPath.c_str()) != INVALID_FILE_ATTRIBUTES;
}

void FinishInjection(const std::wstring& dllPath, bool inject, bool forcedSuspend,
                     LPPROCESS_INFORMATION processInformation) {
    if (!processInformation) return;
    if (inject) {
        std::string error;
        if (InjectLibrary(processInformation->hProcess, dllPath, &error)) {
            AuditEvent("native.child", "injected", nullptr, processInformation->dwProcessId, true);
        } else {
            AuditEvent("native.child", "failed", error.c_str(), processInformation->dwProcessId, true);
        }
    }
    if (forcedSuspend) ResumeThread(processInformation->hThread);
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
    FinishInjection(dllPath, inject, forcedSuspend, processInformation);
    return TRUE;
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
    FinishInjection(dllPath, inject, forcedSuspend, processInformation);
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

    const NTSTATUS status = g_origNtCreateUserProcess(
        processHandle, threadHandle, processAccess, threadAccess, processAttributes, threadAttributes,
        processFlags, threadFlags, processParameters, createInfo, attributeList);
    if (status < 0 || !processHandle || !*processHandle) return status;

    const std::wstring image = processParameters ? UnicodeValue(processParameters->ImagePathName)
                                                 : std::wstring();
    const std::wstring commandLine = processParameters ? UnicodeValue(processParameters->CommandLine)
                                                       : std::wstring();
    std::wstring dllPath;
    if (!PrepareInjection(image.c_str(), commandLine.c_str(), dllPath)) return status;

    const DWORD processId = GetProcessId(*processHandle);
    HANDLE target = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                                    PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | SYNCHRONIZE,
                                FALSE, processId);
    const bool borrowed = (target == nullptr);
    if (!target) target = *processHandle;

    std::string error;
    if (InjectLibrary(target, dllPath, &error)) {
        AuditEvent("native.child", "injected", "ntcreateuserprocess", processId, true);
    } else {
        AuditEvent("native.child", "failed", error.c_str(), processId, true);
    }
    if (!borrowed) CloseHandle(target);
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
    InstallHookInlinePrimary("ntdll.dll", "NtCreateUserProcess",
                             reinterpret_cast<void*>(&HookNtCreateUserProcess),
                             reinterpret_cast<void**>(&g_origNtCreateUserProcess));
}
