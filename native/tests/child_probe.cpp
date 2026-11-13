#define _WIN32_WINNT 0x0A00

#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")

namespace {

std::string FirstMac() {
    ULONG size = 0;
    GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                         nullptr, nullptr, &size);
    std::vector<BYTE> buffer(size);
    PIP_ADAPTER_ADDRESSES addresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                             nullptr, addresses, &size) != NO_ERROR) {
        return "error";
    }
    for (PIP_ADAPTER_ADDRESSES current = addresses; current; current = current->Next) {
        if (current->PhysicalAddressLength == 6) {
            char text[32] = {};
            std::snprintf(text, sizeof(text), "%02x:%02x:%02x:%02x:%02x:%02x",
                          current->PhysicalAddress[0], current->PhysicalAddress[1],
                          current->PhysicalAddress[2], current->PhysicalAddress[3],
                          current->PhysicalAddress[4], current->PhysicalAddress[5]);
            return text;
        }
    }
    return "none";
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc >= 3 && _wcsicmp(argv[1], L"--child") == 0) {
        const std::string mac = FirstMac();
        FILE* file = _wfopen(argv[2], L"wb");
        if (!file) return 2;
        std::fprintf(file, "child_mac=%s\n", mac.c_str());
        std::fclose(file);
        return 0;
    }

    wchar_t exe[32768] = {};
    const DWORD exeLength = GetModuleFileNameW(nullptr, exe, static_cast<DWORD>(_countof(exe)));
    if (exeLength == 0 || exeLength >= _countof(exe)) return 2;
    wchar_t temp[32768] = {};
    const DWORD tempLength = GetTempPathW(static_cast<DWORD>(_countof(temp)), temp);
    if (tempLength == 0 || tempLength >= _countof(temp)) return 2;
    const std::wstring resultPath = std::wstring(temp) + L"cac-child-" +
                                    std::to_wstring(GetCurrentProcessId()) + L".txt";
    const std::wstring command = L"\"" + std::wstring(exe) + L"\" --child \"" + resultPath + L"\"";
    std::vector<wchar_t> mutableCommand(command.begin(), command.end());
    mutableCommand.push_back(0);

    STARTUPINFOW startup = {};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process = {};
    const BOOL created = CreateProcessW(exe, mutableCommand.data(), nullptr, nullptr, FALSE,
                                        CREATE_UNICODE_ENVIRONMENT, nullptr, nullptr, &startup, &process);
    if (!created) {
        std::printf("child_ok=0\nchild_mac=create-failed\n");
        return 1;
    }
    WaitForSingleObject(process.hProcess, 30000);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);

    std::string result = "missing";
    FILE* file = _wfopen(resultPath.c_str(), L"rb");
    if (file) {
        char line[256] = {};
        while (std::fgets(line, sizeof(line), file)) {
            const char* prefix = "child_mac=";
            if (std::strncmp(line, prefix, std::strlen(prefix)) == 0) {
                result.assign(line + std::strlen(prefix));
                while (!result.empty() && (result.back() == '\r' || result.back() == '\n')) result.pop_back();
                break;
            }
        }
        std::fclose(file);
    }
    DeleteFileW(resultPath.c_str());
    std::printf("child_ok=1\nchild_mac=%s\n", result.c_str());
    return 0;
}
