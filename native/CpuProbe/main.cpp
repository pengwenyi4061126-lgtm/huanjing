#define _WIN32_WINNT 0x0A00

#include <windows.h>
#include <tlhelp32.h>
#include <intrin.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#pragma comment(lib, "advapi32.lib")

namespace {

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
    const bool adjusted =
        found && AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), nullptr, nullptr) != FALSE;
    const DWORD error = GetLastError();
    CloseHandle(token);
    return adjusted && error == ERROR_SUCCESS;
}

uint64_t FindModuleBase(DWORD processId, const wchar_t* moduleName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;
    MODULEENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    uint64_t base = 0;
    if (Module32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szModule, moduleName) == 0) {
                base = reinterpret_cast<uint64_t>(entry.modBaseAddr);
                break;
            }
        } while (Module32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return base;
}

void EmitByte(std::vector<BYTE>& code, BYTE value) {
    code.push_back(value);
}

void EmitDword(std::vector<BYTE>& code, uint32_t value) {
    code.push_back(static_cast<BYTE>(value));
    code.push_back(static_cast<BYTE>(value >> 8));
    code.push_back(static_cast<BYTE>(value >> 16));
    code.push_back(static_cast<BYTE>(value >> 24));
}

void EmitQword(std::vector<BYTE>& code, uint64_t value) {
    EmitDword(code, static_cast<uint32_t>(value));
    EmitDword(code, static_cast<uint32_t>(value >> 32));
}

std::vector<BYTE> BuildStub(uint64_t target, uint64_t output, uint32_t leaf, uint32_t subleaf,
                            bool xgetbv) {
    std::vector<BYTE> code;
    // push rbp; mov rbp, rsp; and rsp, -16; sub rsp, 0x40
    EmitByte(code, 0x55);
    EmitByte(code, 0x48);
    EmitByte(code, 0x89);
    EmitByte(code, 0xE5);
    EmitByte(code, 0x48);
    EmitByte(code, 0x83);
    EmitByte(code, 0xE4);
    EmitByte(code, 0xF0);
    EmitByte(code, 0x48);
    EmitByte(code, 0x83);
    EmitByte(code, 0xEC);
    EmitByte(code, 0x40);

    if (!xgetbv) {
        // mov dword ptr [rsp], leaf; mov dword ptr [rsp+4], subleaf
        EmitByte(code, 0xC7);
        EmitByte(code, 0x04);
        EmitByte(code, 0x24);
        EmitDword(code, leaf);
        EmitByte(code, 0xC7);
        EmitByte(code, 0x44);
        EmitByte(code, 0x24);
        EmitByte(code, 0x04);
        EmitDword(code, subleaf);
    }

    // mov rax, target; call rax; mov rcx, output
    EmitByte(code, 0x48);
    EmitByte(code, 0xB8);
    EmitQword(code, target);
    EmitByte(code, 0xFF);
    EmitByte(code, 0xD0);
    EmitByte(code, 0x48);
    EmitByte(code, 0xB9);
    EmitQword(code, output);

    const int count = xgetbv ? 2 : 4;
    for (int i = 0; i < count; ++i) {
        // mov eax, [rsp + stackOffset]; mov [rcx + resultOffset], eax
        const int stackOffset = xgetbv ? i * 4 : 8 + i * 4;
        const int resultOffset = i * 4;
        if (stackOffset == 0) {
            EmitByte(code, 0x8B);
            EmitByte(code, 0x04);
            EmitByte(code, 0x24);
        } else {
            EmitByte(code, 0x8B);
            EmitByte(code, 0x44);
            EmitByte(code, 0x24);
            EmitByte(code, static_cast<BYTE>(stackOffset));
        }
        if (resultOffset == 0) {
            EmitByte(code, 0x89);
            EmitByte(code, 0x01);
        } else {
            EmitByte(code, 0x89);
            EmitByte(code, 0x41);
            EmitByte(code, static_cast<BYTE>(resultOffset));
        }
    }

    // mov rsp, rbp; pop rbp; xor eax, eax; ret
    EmitByte(code, 0x48);
    EmitByte(code, 0x89);
    EmitByte(code, 0xEC);
    EmitByte(code, 0x5D);
    EmitByte(code, 0x31);
    EmitByte(code, 0xC0);
    EmitByte(code, 0xC3);
    return code;
}

void PrintHexBytes(const BYTE* bytes, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        std::printf("%02x", bytes[i]);
    }
}

bool ParseU64(const char* text, uint64_t& value) {
    char* end = nullptr;
    value = _strtoui64(text, &end, 0);
    return end && *end == 0;
}

std::string Narrow(const wchar_t* text) {
    char buffer[512] = {};
    WideCharToMultiByte(CP_UTF8, 0, text, -1, buffer, sizeof(buffer), nullptr, nullptr);
    return buffer;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    DWORD processId = 0;
    uint64_t rva = 0;
    uint64_t leaf = 0x40000000ULL;
    uint64_t subleaf = 0;
    uint64_t readRva = 0;
    uint64_t readLength = 0;
    bool readMode = false;
    std::wstring module = L"cowork-svc.exe";
    bool xgetbv = false;

    for (int i = 1; i < argc; ++i) {
        const std::wstring arg = argv[i];
        if (arg == L"--pid" && i + 1 < argc) {
            processId = static_cast<DWORD>(strtoul(Narrow(argv[++i]).c_str(), nullptr, 0));
        } else if (arg == L"--rva" && i + 1 < argc) {
            if (!ParseU64(Narrow(argv[++i]).c_str(), rva)) return 2;
        } else if (arg == L"--leaf" && i + 1 < argc) {
            if (!ParseU64(Narrow(argv[++i]).c_str(), leaf)) return 2;
        } else if (arg == L"--subleaf" && i + 1 < argc) {
            if (!ParseU64(Narrow(argv[++i]).c_str(), subleaf)) return 2;
        } else if (arg == L"--read" && i + 1 < argc) {
            if (!ParseU64(Narrow(argv[++i]).c_str(), readRva)) return 2;
            readMode = true;
        } else if (arg == L"--length" && i + 1 < argc) {
            if (!ParseU64(Narrow(argv[++i]).c_str(), readLength)) return 2;
        } else if (arg == L"--module" && i + 1 < argc) {
            module = argv[++i];
        } else if (arg == L"--kind" && i + 1 < argc) {
            const std::wstring kind = argv[++i];
            xgetbv = _wcsicmp(kind.c_str(), L"xgetbv") == 0;
            if (!xgetbv && _wcsicmp(kind.c_str(), L"cpuid") != 0) {
                std::fprintf(stderr, "unknown kind: %ls\n", kind.c_str());
                return 2;
            }
        } else {
            std::fprintf(stderr, "unknown argument: %ls\n", arg.c_str());
            return 2;
        }
    }

    if (processId == 0 || (!readMode && rva == 0)) {
        std::fprintf(stderr,
                     "usage: cac-cpu-probe --pid PID --rva RVA [--kind cpuid|xgetbv] "
                     "[--leaf N] [--subleaf N] [--module NAME]\n"
                     "       cac-cpu-probe --pid PID --read RVA --length N [--module NAME]\n");
        return 2;
    }

    EnableDebugPrivilege();
    const uint64_t base = FindModuleBase(processId, module.c_str());
    if (base == 0) {
        std::fprintf(stderr, "module not found: %ls (pid=%lu)\n", module.c_str(),
                     static_cast<unsigned long>(processId));
        return 3;
    }

    if (readMode) {
        if (readLength == 0 || readLength > 0x1000) {
            std::fprintf(stderr, "invalid read length: %llu\n",
                         static_cast<unsigned long long>(readLength));
            return 2;
        }
        HANDLE reader = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
        if (!reader) {
            std::fprintf(stderr, "OpenProcess(read) failed: %lu\n",
                         static_cast<unsigned long>(GetLastError()));
            return 3;
        }
        std::vector<BYTE> buffer(static_cast<size_t>(readLength));
        SIZE_T read = 0;
        const uint64_t address = base + readRva;
        const BOOL ok = ReadProcessMemory(reader, reinterpret_cast<const void*>(address),
                                          buffer.data(), buffer.size(), &read);
        const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
        CloseHandle(reader);
        if (!ok || read != buffer.size()) {
            std::fprintf(stderr, "ReadProcessMemory(0x%llx) failed: %lu\n",
                         static_cast<unsigned long long>(address),
                         static_cast<unsigned long>(error));
            return 3;
        }
        std::printf("{\"mode\":\"read\",\"pid\":%lu,\"module\":\"%ls\",\"base\":\"0x%llx\","
                    "\"rva\":\"0x%llx\",\"length\":%llu,\"hex\":\"",
                    static_cast<unsigned long>(processId), module.c_str(),
                    static_cast<unsigned long long>(base),
                    static_cast<unsigned long long>(readRva),
                    static_cast<unsigned long long>(readLength));
        PrintHexBytes(buffer.data(), buffer.size());
        std::printf("\"}\n");
        return 0;
    }

    const uint64_t target = base + rva;

    HANDLE process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                                     PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                                 FALSE, processId);
    if (!process) {
        std::fprintf(stderr, "OpenProcess failed: %lu\n", static_cast<unsigned long>(GetLastError()));
        return 3;
    }

    BYTE entry[8] = {};
    SIZE_T read = 0;
    if (!ReadProcessMemory(process, reinterpret_cast<const void*>(target), entry, sizeof(entry), &read) ||
        read != sizeof(entry)) {
        std::fprintf(stderr, "ReadProcessMemory(entry) failed: %lu\n",
                     static_cast<unsigned long>(GetLastError()));
        CloseHandle(process);
        return 3;
    }

    void* remote = VirtualAllocEx(process, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE,
                                  PAGE_EXECUTE_READWRITE);
    if (!remote) {
        std::fprintf(stderr, "VirtualAllocEx failed: %lu\n", static_cast<unsigned long>(GetLastError()));
        CloseHandle(process);
        return 3;
    }
    const uint64_t remoteBase = reinterpret_cast<uint64_t>(remote);
    const uint64_t output = remoteBase + 0x200;
    const std::vector<BYTE> stub =
        BuildStub(target, output, static_cast<uint32_t>(leaf), static_cast<uint32_t>(subleaf), xgetbv);
    if (!WriteProcessMemory(process, remote, stub.data(), stub.size(), nullptr)) {
        std::fprintf(stderr, "WriteProcessMemory(stub) failed: %lu\n",
                     static_cast<unsigned long>(GetLastError()));
        VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        CloseHandle(process);
        return 3;
    }

    HANDLE thread = CreateRemoteThread(
        process, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(static_cast<uintptr_t>(remoteBase)), nullptr, 0,
        nullptr);
    if (!thread) {
        std::fprintf(stderr, "CreateRemoteThread failed: %lu\n",
                     static_cast<unsigned long>(GetLastError()));
        VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        CloseHandle(process);
        return 3;
    }
    const DWORD wait = WaitForSingleObject(thread, 15000);
    DWORD threadExit = 0;
    GetExitCodeThread(thread, &threadExit);
    CloseHandle(thread);

    unsigned int results[4] = {};
    if (wait == WAIT_OBJECT_0) {
        ReadProcessMemory(process, reinterpret_cast<const void*>(output), results, sizeof(results), &read);
    }
    VirtualFreeEx(process, remote, 0, MEM_RELEASE);
    CloseHandle(process);

    if (wait != WAIT_OBJECT_0) {
        std::fprintf(stderr, "remote thread did not finish: wait=%lu\n",
                     static_cast<unsigned long>(wait));
        return 4;
    }

    std::printf("{\"pid\":%lu,\"module\":\"%ls\",\"base\":\"0x%llx\",\"rva\":\"0x%llx\","
                "\"kind\":\"%s\",\"leaf\":\"0x%llx\",\"subleaf\":\"0x%llx\",\"entry\":\"",
                static_cast<unsigned long>(processId), module.c_str(),
                static_cast<unsigned long long>(base), static_cast<unsigned long long>(rva),
                xgetbv ? "xgetbv" : "cpuid", static_cast<unsigned long long>(leaf),
                static_cast<unsigned long long>(subleaf));
    PrintHexBytes(entry, sizeof(entry));
    std::printf("\",\"threadExit\":%lu,\"results\":[\"%08x\",\"%08x\",\"%08x\",\"%08x\"]",
                static_cast<unsigned long>(threadExit), results[0], results[1], results[2],
                results[3]);

    if (!xgetbv) {
        int host[4] = {};
        __cpuidex(host, static_cast<int>(leaf), static_cast<int>(subleaf));
        std::printf(",\"host\":[\"%08x\",\"%08x\",\"%08x\",\"%08x\"]",
                    static_cast<unsigned int>(host[0]), static_cast<unsigned int>(host[1]),
                    static_cast<unsigned int>(host[2]), static_cast<unsigned int>(host[3]));
    } else {
        const unsigned long long value = _xgetbv(0);
        std::printf(",\"host\":[\"%08x\",\"%08x\"]",
                    static_cast<unsigned int>(value),
                    static_cast<unsigned int>(value >> 32));
    }
    std::printf("}\n");
    return 0;
}
