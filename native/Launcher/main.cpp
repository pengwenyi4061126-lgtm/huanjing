#include <windows.h>

#include <cstdio>
#include <string>
#include <vector>

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

std::wstring ExecutableDirectory() {
    wchar_t path[32768] = {};
    const DWORD size = GetModuleFileNameW(nullptr, path, static_cast<DWORD>(_countof(path)));
    std::wstring result(path, size);
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

}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) {
        std::fwprintf(stderr, L"usage: cac-native-launch <target.exe> [args...]\n");
        return 2;
    }

    const std::wstring target = argv[1];
    std::wstring dllPath;
    wchar_t configured[32768] = {};
    const DWORD configuredSize = GetEnvironmentVariableW(L"CAC_NATIVE_DLL", configured,
                                                         static_cast<DWORD>(_countof(configured)));
    if (configuredSize > 0 && configuredSize < _countof(configured)) dllPath.assign(configured, configuredSize);
    else dllPath = ExecutableDirectory() + L"\\NativeBridge.dll";

    if (GetFileAttributesW(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::fwprintf(stderr, L"[cac-native] NativeBridge.dll missing: %s\n", dllPath.c_str());
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

    if (GetFileAttributesW(dllPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
        SetEnvironmentVariableW(L"CAC_NATIVE_DLL", dllPath.c_str());
        std::string error;
        if (InjectDll(process.hProcess, dllPath, &error)) {
            if (ready) WaitForSingleObject(ready, 20000);
        } else {
            std::fwprintf(stderr, L"[cac-native] injection failed: %hs\n", error.c_str());
        }
    }

    if (ready) CloseHandle(ready);
    ResumeThread(process.hThread);
    WaitForSingleObject(process.hProcess, INFINITE);
    DWORD exitCode = 1;
    GetExitCodeProcess(process.hProcess, &exitCode);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return static_cast<int>(exitCode);
}
