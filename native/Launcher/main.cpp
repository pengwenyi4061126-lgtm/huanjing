#include <windows.h>
#include <tlhelp32.h>
#include <bcrypt.h>

#include <cstdio>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

#if __has_include("expected_dll_hash.h")
#include "expected_dll_hash.h"
#endif

#ifndef CAC_EXPECTED_DLL_SHA256
#define CAC_EXPECTED_DLL_SHA256 ""
#endif

namespace {

std::wstring Quote(const std::wstring& value) {
    if (value.find_first_of(L" \t\"") == std::wstring::npos) return value;
    std::wstring result = L"\"";
    size_t backslashes = 0;
    for (wchar_t c : value) {
        if (c == L'\\') {
            ++backslashes;
        } else if (c == L'"') {
            result.append(backslashes * 2 + 1, L'\\');
            result.push_back(L'"');
            backslashes = 0;
        } else {
            result.append(backslashes, L'\\');
            backslashes = 0;
            result.push_back(c);
        }
    }
    result.append(backslashes * 2, L'\\');
    result.push_back(L'"');
    return result;
}

std::wstring ExecutablePath() {
    wchar_t path[32768] = {};
    const DWORD size = GetModuleFileNameW(nullptr, path, static_cast<DWORD>(_countof(path)));
    if (size == 0 || size >= _countof(path)) return L"";
    return std::wstring(path, size);
}

std::wstring ExecutableDirectory() {
    std::wstring result = ExecutablePath();
    const size_t slash = result.find_last_of(L"\\/");
    if (slash == std::wstring::npos) return L".";
    return result.substr(0, slash);
}

bool InjectDll(HANDLE process, const std::wstring& dllPath, std::string* error) {
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
    WaitForSingleObject(thread, 20000);
    DWORD moduleBase = 0;
    GetExitCodeThread(thread, &moduleBase);
    CloseHandle(thread);
    VirtualFreeEx(process, remote, 0, MEM_RELEASE);
    if (moduleBase == 0) {
        *error = "LoadLibraryW returned NULL in target";
        return false;
    }
    return true;
}

bool ComputeFileSha256(const std::wstring& path, std::string& hex) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;

    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    bool ok = false;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0 &&
        BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) >= 0) {
        std::vector<BYTE> buffer(64 * 1024);
        bool readOk = true;
        DWORD read = 0;
        while (true) {
            if (!ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr)) {
                readOk = false;
                break;
            }
            if (read == 0) break;
            if (BCryptHashData(hash, buffer.data(), read, 0) < 0) {
                readOk = false;
                break;
            }
        }
        BYTE digest[32] = {};
        if (readOk && BCryptFinishHash(hash, digest, sizeof(digest), 0) >= 0) {
            char text[65] = {};
            for (int i = 0; i < 32; ++i) std::snprintf(text + i * 2, 3, "%02X", digest[i]);
            hex.assign(text, 64);
            ok = true;
        }
    }
    if (hash) BCryptDestroyHash(hash);
    if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    CloseHandle(file);
    return ok;
}

bool IsHex(char value) {
    return (value >= '0' && value <= '9') ||
           (value >= 'a' && value <= 'f') ||
           (value >= 'A' && value <= 'F');
}

bool ReadDeclaredSha256(const std::wstring& path, std::string& hash) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;

    std::string content;
    char buffer[512] = {};
    bool ok = true;
    while (true) {
        DWORD read = 0;
        if (!ReadFile(file, buffer, static_cast<DWORD>(sizeof(buffer)), &read, nullptr)) {
            ok = false;
            break;
        }
        if (read == 0) break;
        content.append(buffer, read);
        if (content.size() > 4096) {
            ok = false;
            break;
        }
    }
    CloseHandle(file);
    if (!ok) return false;

    bool found = false;
    for (size_t i = 0; i + 64 <= content.size(); ++i) {
        if ((i > 0 && IsHex(content[i - 1])) ||
            (i + 64 < content.size() && IsHex(content[i + 64]))) {
            continue;
        }
        bool hex = true;
        for (size_t j = 0; j < 64; ++j) {
            if (!IsHex(content[i + j])) {
                hex = false;
                break;
            }
        }
        if (!hex) continue;
        if (found) return false;
        hash.assign(content.data() + i, 64);
        found = true;
        i += 63;
    }
    return found;
}

bool VerifyDeclaredSha256(const std::wstring& filePath,
                          const std::wstring& manifestPath,
                          const char* label,
                          std::string& error) {
    const DWORD attributes = GetFileAttributesW(filePath.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY)) {
        error = std::string(label) + " file is missing";
        return false;
    }

    std::string expected;
    if (!ReadDeclaredSha256(manifestPath, expected)) {
        error = std::string(label) + " SHA-256 manifest is missing or invalid";
        return false;
    }
    std::string actual;
    if (!ComputeFileSha256(filePath, actual)) {
        error = std::string(label) + " SHA-256 could not be computed";
        return false;
    }
    if (_stricmp(actual.c_str(), expected.c_str()) != 0) {
        error = std::string(label) + " SHA-256 mismatch";
        return false;
    }
    return true;
}

bool QueryImagePath(DWORD processId, std::wstring& path) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (!process) return false;
    wchar_t buffer[32768] = {};
    DWORD size = static_cast<DWORD>(_countof(buffer));
    const BOOL ok = QueryFullProcessImageNameW(process, 0, buffer, &size);
    CloseHandle(process);
    if (!ok) return false;
    path.assign(buffer, size);
    return true;
}

bool IsModuleLoaded(DWORD processId, const wchar_t* moduleName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
    if (snapshot == INVALID_HANDLE_VALUE) return false;
    MODULEENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    bool found = false;
    if (Module32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szModule, moduleName) == 0) {
                found = true;
                break;
            }
        } while (Module32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return found;
}

std::set<DWORD> DescendantsOf(DWORD root) {
    std::vector<std::pair<DWORD, DWORD>> rows;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W entry = {};
        entry.dwSize = sizeof(entry);
        if (Process32FirstW(snapshot, &entry)) {
            do {
                rows.emplace_back(entry.th32ProcessID, entry.th32ParentProcessID);
            } while (Process32NextW(snapshot, &entry));
        }
        CloseHandle(snapshot);
    }

    std::set<DWORD> result;
    result.insert(root);
    bool changed = true;
    while (changed) {
        changed = false;
        for (const auto& row : rows) {
            if (result.count(row.second) && !result.count(row.first)) {
                result.insert(row.first);
                changed = true;
            }
        }
    }
    return result;
}

void AppendAudit(const std::wstring& path, const char* action, DWORD processId, const char* detail) {
    if (path.empty()) return;
    SYSTEMTIME st = {};
    GetSystemTime(&st);
    char line[512] = {};
    int length = std::snprintf(line, sizeof(line),
        "{\"utc\":\"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ\",\"pid\":%lu,\"surface\":\"native.child\","
        "\"action\":\"%s\",\"value\":\"%lu\"",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
        static_cast<unsigned long>(GetCurrentProcessId()), action,
        static_cast<unsigned long>(processId));
    if (detail && *detail && length > 0 && length < static_cast<int>(sizeof(line) - 32)) {
        length += std::snprintf(line + length, sizeof(line) - length, ",\"detail\":\"%s\"", detail);
    }
    if (length > 0 && length < static_cast<int>(sizeof(line) - 2)) {
        line[length++] = '}';
        line[length++] = '\n';
        line[length] = 0;
    } else {
        return;
    }
    HANDLE file = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteFile(file, line, static_cast<DWORD>(length), &written, nullptr);
        CloseHandle(file);
    }
}

struct MonitorContext {
    HANDLE process;
    DWORD rootPid;
    std::wstring exePath;
    std::wstring dllPath;
    std::wstring auditPath;
};

DWORD WINAPI MonitorThread(LPVOID parameter) {
    MonitorContext* context = static_cast<MonitorContext*>(parameter);
    std::set<DWORD> handled;
    std::map<DWORD, int> attempts;
    std::map<DWORD, ULONGLONG> retryAfter;
    ULONGLONG graceDeadline = 0;
    while (true) {
        const ULONGLONG now = GetTickCount64();
        const bool rootAlive = WaitForSingleObject(context->process, 0) == WAIT_TIMEOUT;
        if (!rootAlive) {
            if (graceDeadline == 0) graceDeadline = now + 5000;
            if (now >= graceDeadline) break;
        }
        for (DWORD processId : DescendantsOf(context->rootPid)) {
            if (processId == context->rootPid || handled.count(processId)) continue;
            const auto next = retryAfter.find(processId);
            if (next != retryAfter.end() && now < next->second) continue;
            std::wstring image;
            if (!QueryImagePath(processId, image)) continue;
            if (_wcsicmp(image.c_str(), context->exePath.c_str()) != 0) continue;
            if (IsModuleLoaded(processId, L"NativeBridge.dll")) {
                handled.insert(processId);
                continue;
            }
            HANDLE process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                                             PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ |
                                             SYNCHRONIZE,
                                         FALSE, processId);
            if (!process) {
                const int attempt = ++attempts[processId];
                const ULONGLONG delay = static_cast<ULONGLONG>(100 + attempt * 100);
                retryAfter[processId] = now + (delay > 2000 ? 2000 : delay);
                continue;
            }
            std::string error;
            if (InjectDll(process, context->dllPath, &error)) {
                handled.insert(processId);
                AppendAudit(context->auditPath, "launcher-injected", processId, nullptr);
            } else {
                const int attempt = ++attempts[processId];
                const ULONGLONG delay = static_cast<ULONGLONG>(100 + attempt * 100);
                retryAfter[processId] = now + (delay > 2000 ? 2000 : delay);
                if (attempt == 1 || (attempt % 10) == 0) {
                    AppendAudit(context->auditPath, "launcher-failed", processId, error.c_str());
                }
            }
            CloseHandle(process);
        }
        Sleep(300);
    }
    CloseHandle(context->process);
    delete context;
    return 0;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) {
        std::fwprintf(stderr, L"usage: cac-native-launch <target.exe> [args...]\n");
        return 2;
    }

    const std::wstring target = argv[1];
    const std::wstring launcherPath = ExecutablePath();
    if (launcherPath.empty()) {
        std::fwprintf(stderr, L"[cac-native] unable to resolve launcher path\n");
        return 5;
    }
    std::string integrityError;
    const std::wstring launcherManifest = ExecutableDirectory() + L"\\cac-native-launch.sha256";
    if (!VerifyDeclaredSha256(launcherPath, launcherManifest, "native launcher", integrityError)) {
        std::fwprintf(stderr, L"[cac-native] %hs; refusing to start\n", integrityError.c_str());
        return 5;
    }

    std::wstring dllPath;
    wchar_t configured[32768] = {};
    const DWORD configuredSize = GetEnvironmentVariableW(L"CAC_NATIVE_DLL", configured,
                                                         static_cast<DWORD>(_countof(configured)));
    if (configuredSize > 0 && configuredSize < _countof(configured)) dllPath.assign(configured, configuredSize);
    else dllPath = ExecutableDirectory() + L"\\NativeBridge.dll";

    const DWORD dllAttributes = GetFileAttributesW(dllPath.c_str());
    if (dllAttributes == INVALID_FILE_ATTRIBUTES || (dllAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
        std::fwprintf(stderr, L"[cac-native] NativeBridge.dll missing: %s\n", dllPath.c_str());
        return 4;
    }
    const size_t dllSlash = dllPath.find_last_of(L"\\/");
    const std::wstring dllDirectory = dllSlash == std::wstring::npos ? L"." : dllPath.substr(0, dllSlash);
    const std::wstring dllManifest = dllDirectory + L"\\NativeBridge.sha256";
    if (!VerifyDeclaredSha256(dllPath, dllManifest, "NativeBridge.dll", integrityError)) {
        std::fwprintf(stderr, L"[cac-native] %hs; refusing to start\n", integrityError.c_str());
        return 4;
    }
    const std::string expectedDllHash = CAC_EXPECTED_DLL_SHA256;
    if (!expectedDllHash.empty()) {
        std::string actualDllHash;
        if (!ComputeFileSha256(dllPath, actualDllHash) ||
            _stricmp(actualDllHash.c_str(), expectedDllHash.c_str()) != 0) {
            std::fwprintf(stderr, L"[cac-native] NativeBridge.dll compiled SHA-256 mismatch; refusing to start\n");
            return 4;
        }
    }

    std::wstring commandLine = Quote(target);
    for (int i = 2; i < argc; ++i) {
        commandLine += L" ";
        commandLine += Quote(argv[i]);
    }
    std::vector<wchar_t> mutableCommand(commandLine.begin(), commandLine.end());
    mutableCommand.push_back(0);

    STARTUPINFOW startup = {};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process = {};
    if (!CreateProcessW(target.c_str(), mutableCommand.data(), nullptr, nullptr, TRUE,
                        CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT, nullptr, nullptr,
                        &startup, &process)) {
        std::fwprintf(stderr, L"[cac-native] CreateProcessW failed: %lu\n", GetLastError());
        return 1;
    }

    wchar_t eventName[96] = {};
    std::swprintf(eventName, _countof(eventName), L"Local\\CACNativeBridgeReady_%lu",
                  static_cast<unsigned long>(process.dwProcessId));
    HANDLE ready = CreateEventW(nullptr, TRUE, FALSE, eventName);

    SetEnvironmentVariableW(L"CAC_NATIVE_DLL", dllPath.c_str());
    std::string error;
    if (InjectDll(process.hProcess, dllPath, &error)) {
        if (ready) WaitForSingleObject(ready, 20000);
    } else {
        std::fwprintf(stderr, L"[cac-native] injection failed: %hs\n", error.c_str());
    }

    if (ready) CloseHandle(ready);
    ResumeThread(process.hThread);

    std::wstring auditPath;
    wchar_t auditBuffer[32768] = {};
    const DWORD auditLength = GetEnvironmentVariableW(L"CAC_NATIVE_AUDIT", auditBuffer,
                                                      static_cast<DWORD>(_countof(auditBuffer)));
    if (auditLength > 0 && auditLength < _countof(auditBuffer)) auditPath.assign(auditBuffer, auditLength);
    HANDLE monitorProcess = nullptr;
    if (DuplicateHandle(GetCurrentProcess(), process.hProcess, GetCurrentProcess(), &monitorProcess,
                        SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 0)) {
        MonitorContext* monitorContext = new MonitorContext{monitorProcess, process.dwProcessId, target,
                                                            dllPath, auditPath};
        HANDLE monitor = CreateThread(nullptr, 0, MonitorThread, monitorContext, 0, nullptr);
        if (monitor) CloseHandle(monitor);
        else {
            CloseHandle(monitorProcess);
            delete monitorContext;
        }
    }

    WaitForSingleObject(process.hProcess, INFINITE);
    DWORD exitCode = 1;
    GetExitCodeProcess(process.hProcess, &exitCode);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return static_cast<int>(exitCode);
}
