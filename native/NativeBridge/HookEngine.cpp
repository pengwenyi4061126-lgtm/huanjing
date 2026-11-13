#include "HookEngine.h"

#include <cstdint>
#include <cstring>
#include <vector>

#pragma comment(lib, "kernel32.lib")

namespace {

struct HookRecord {
    BYTE* target;
    BYTE  original[32];
    int   length;
    BYTE* trampoline;
    BYTE* relay;
};

std::vector<HookRecord> g_hooks;

BYTE* AllocateRelayNear(BYTE* target) {
    const uintptr_t base = reinterpret_cast<uintptr_t>(target);
    const uintptr_t minAddress = base > 0x70000000ULL ? base - 0x70000000ULL : 0x10000ULL;
    const uintptr_t maxAddress = base + 0x70000000ULL;
    for (uintptr_t delta = 0x10000; delta < 0x70000000ULL; delta += 0x10000) {
        for (int direction = -1; direction <= 1; direction += 2) {
            uintptr_t candidate = direction < 0 ? base - delta : base + delta;
            candidate &= ~static_cast<uintptr_t>(0xFFFF);
            if (candidate < minAddress || candidate > maxAddress) continue;
            MEMORY_BASIC_INFORMATION info = {};
            if (VirtualQuery(reinterpret_cast<void*>(candidate), &info, sizeof(info)) == 0) continue;
            if (info.State != MEM_FREE) continue;
            void* memory = VirtualAlloc(reinterpret_cast<void*>(candidate), 4096,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (memory) return static_cast<BYTE*>(memory);
        }
    }
    return nullptr;
}

}  // namespace

namespace HookEngine {

int DecodePrologueInstruction(const BYTE* p, int available) {
    if (!p || available <= 0) return 0;

    // endbr64
    if (available >= 4 && p[0] == 0xF3 && p[1] == 0x0F && p[2] == 0x1E && p[3] == 0xFA) return 4;

    // RIP-relative import/export forwarders must be resolved by the caller.
    // Copying them into a trampoline without relocating the displacement is
    // unsafe, so reject them instead of producing a crashing original call.
    if (available >= 6 && p[0] == 0xFF && p[1] == 0x25) return 0;
    if (available >= 7 && p[0] == 0x48 && p[1] == 0xFF && p[2] == 0x25) return 0;

    // REX.W mov [rsp+disp8], r64  (48/4C 89 /r, mod=01, rm=100)
    if (available >= 5 && (p[0] == 0x48 || p[0] == 0x4C) && p[1] == 0x89 &&
        (p[2] & 0xC7) == 0x44 && p[3] == 0x24) {
        return 5;
    }
    if (available >= 5 && p[0] == 0x4C && p[1] == 0x89 && p[2] == 0x4C && p[3] == 0x24) return 5;

    // mov [rsp+disp8], r32 / mov r32, [rsp+disp8]
    if (available >= 4 && p[0] == 0x89 && (p[1] & 0xC7) == 0x44 && p[2] == 0x24) return 4;
    if (available >= 4 && p[0] == 0x8B && (p[1] & 0xC7) == 0x44 && p[2] == 0x24) return 4;
    if (available >= 5 && p[0] == 0x48 && p[1] == 0x8B && (p[2] & 0xC7) == 0x44 && p[3] == 0x24) return 5;

    // mov r32, imm32
    if (available >= 5 && (p[0] == 0xB8 || p[0] == 0xB9 || p[0] == 0xBA)) return 5;

    // xor ecx, ecx / xor eax, eax / xor edx, edx / xor r8d, r8d
    if (available >= 2 && p[0] == 0x33 && (p[1] == 0xC9 || p[1] == 0xC0 || p[1] == 0xD2)) return 2;
    if (available >= 3 && p[0] == 0x45 && p[1] == 0x33 && p[2] == 0xC0) return 3;

    // sub rsp, imm8 without REX.W
    if (available >= 3 && p[0] == 0x83 && p[1] == 0xEC) return 3;

    // REX.W sub rsp, imm8 / imm32
    if (available >= 4 && p[0] == 0x48 && p[1] == 0x83 && p[2] == 0xEC) return 4;
    if (available >= 7 && p[0] == 0x48 && p[1] == 0x81 && p[2] == 0xEC) return 7;

    // push r64 with a REX prefix
    if (available >= 2 && (p[0] & 0xF8) == 0x40 && p[1] >= 0x50 && p[1] <= 0x57) return 2;
    if (p[0] >= 0x50 && p[0] <= 0x57) return 1;

    // REX.W mov r64, r/m64 with a register or simple disp8 memory operand.
    if (available >= 4 && p[0] == 0x48 && p[1] == 0x89 &&
        (p[2] & 0xC0) == 0x40 && (p[2] & 0x07) != 0x04) return 4;

    // REX.W mov r/m64, r64 used by Windows unwind prologues, including
    // 49 89 5B 08 / 49 89 73 18. Only register and base+disp forms are
    // accepted; RIP-relative forms are deliberately excluded.
    if (available >= 3 && (p[0] & 0xF8) == 0x48 && p[1] == 0x89) {
        const BYTE modrm = p[2];
        const int mod = modrm >> 6;
        const int rm = modrm & 7;
        if (mod == 3) return 3;
        if (mod == 1) return rm == 4 ? 5 : 4;
        if (mod == 2) return rm == 4 ? 8 : 7;
    }

    // mov rax/rbx, rsp
    if (available >= 3 && p[0] == 0x48 && p[1] == 0x8B && (p[2] == 0xC4 || p[2] == 0xDC)) return 3;

    // lea r64, [rsp+disp8]. HidD_GetSerialNumberString and other Win32
    // entry points use this stack-relative form in their prologue.
    if (available >= 5 && p[0] == 0x48 && p[1] == 0x8D &&
        (p[2] & 0xC7) == 0x44 && p[3] == 0x24) return 5;

    // and qword ptr [rsp+disp8], imm8
    if (available >= 6 && p[0] == 0x48 && p[1] == 0x83 && p[2] == 0x64 && p[3] == 0x24) return 6;

    // mov r64, r/m64 register prologues (including mov r8, rax)
    if (available >= 3 && p[0] == 0x4C && p[1] == 0x8B && (p[2] & 0xC0) == 0xC0) {
        return 3;
    }

    // push rbp; mov rbp, rsp
    if (available >= 4 && p[0] == 0x55 && p[1] == 0x48 && p[2] == 0x89 && p[3] == 0xE5) return 1;
    if (available >= 3 && p[0] == 0x48 && p[1] == 0x89 && p[2] == 0xE5) return 3;

    // Multi-byte NOP
    if (available >= 3 && p[0] == 0x0F && p[1] == 0x1F) {
        const BYTE modrm = p[2];
        const int mod = modrm >> 6;
        const int rm = modrm & 7;
        if (mod == 0 && rm == 5) return 7;
        if (mod == 0 && rm == 4) {
            if (available >= 4 && p[3] == 0x00) return 5;
            return 0;
        }
        if (mod == 0 && rm < 4) return 3;
        if (mod == 1 && rm == 4) return 5;
        if (mod == 1) return 4;
        if (mod == 2 && rm == 4) return 8;
        if (mod == 2) return 7;
        return 0;
    }

    return 0;
}

bool IsExecutableAddress(const void* address) {
    MEMORY_BASIC_INFORMATION info = {};
    if (VirtualQuery(address, &info, sizeof(info)) == 0) return false;
    if (info.State != MEM_COMMIT) return false;
    const DWORD protect = info.Protect & 0xFF;
    return protect == PAGE_EXECUTE || protect == PAGE_EXECUTE_READ ||
           protect == PAGE_EXECUTE_READWRITE || protect == PAGE_EXECUTE_WRITECOPY;
}

void* FindTrampoline(void* target) {
    if (!target) return nullptr;
    for (const HookRecord& record : g_hooks) {
        if (record.target == target) return record.trampoline;
    }
    return nullptr;
}

bool Install(void* target, void* detour, void** trampoline, std::string* error) {
    if (!target || !detour || !trampoline) {
        if (error) *error = "invalid argument";
        return false;
    }
    if (!IsExecutableAddress(target)) {
        if (error) *error = "target is not executable";
        return false;
    }

    BYTE* entry = static_cast<BYTE*>(target);
    int consumed = 0;
    int length = 0;
    while (length < 5) {
        const int step = DecodePrologueInstruction(entry + consumed, 16);
        if (step <= 0) {
            if (error) *error = "unsupported prologue instruction";
            return false;
        }
        consumed += step;
        length = consumed;
        if (consumed > 24) {
            if (error) *error = "prologue too long";
            return false;
        }
    }

    BYTE* memory = static_cast<BYTE*>(VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!memory) {
        if (error) *error = "trampoline allocation failed";
        return false;
    }
    std::memcpy(memory, entry, length);
    BYTE* jumpBack = memory + length;
    jumpBack[0] = 0xFF;
    jumpBack[1] = 0x25;
    *reinterpret_cast<DWORD*>(jumpBack + 2) = 0;
    *reinterpret_cast<void**>(jumpBack + 6) = entry + length;

    HookRecord record = {};
    record.target = entry;
    record.length = length;
    record.trampoline = memory;
    std::memcpy(record.original, entry, length);

    DWORD oldProtect = 0;
    if (!VirtualProtect(entry, length, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        VirtualFree(memory, 0, MEM_RELEASE);
        if (error) *error = "VirtualProtect failed";
        return false;
    }
    BYTE* jumpTarget = static_cast<BYTE*>(detour);
    BYTE* relay = nullptr;
    intptr_t relative = jumpTarget - (entry + 5);
    if (relative < INT32_MIN || relative > INT32_MAX) {
        relay = AllocateRelayNear(entry);
        if (!relay) {
            VirtualProtect(entry, length, oldProtect, &oldProtect);
            VirtualFree(memory, 0, MEM_RELEASE);
            if (error) *error = "relay allocation failed";
            return false;
        }
        relay[0] = 0xFF;
        relay[1] = 0x25;
        *reinterpret_cast<DWORD*>(relay + 2) = 0;
        *reinterpret_cast<void**>(relay + 6) = detour;
        jumpTarget = relay;
        relative = jumpTarget - (entry + 5);
    }
    entry[0] = 0xE9;
    *reinterpret_cast<int32_t*>(entry + 1) = static_cast<int32_t>(relative);
    for (int i = 5; i < length; ++i) entry[i] = 0x90;
    DWORD ignored = 0;
    VirtualProtect(entry, length, oldProtect, &ignored);
    FlushInstructionCache(GetCurrentProcess(), entry, length);

    g_hooks.push_back(record);
    g_hooks.back().relay = relay;
    *trampoline = memory;
    return true;
}

bool Uninstall(void* target) {
    for (size_t i = 0; i < g_hooks.size(); ++i) {
        HookRecord& record = g_hooks[i];
        if (record.target != target) continue;
        DWORD oldProtect = 0;
        if (!VirtualProtect(record.target, record.length, PAGE_EXECUTE_READWRITE, &oldProtect)) return false;
        std::memcpy(record.target, record.original, record.length);
        DWORD ignored = 0;
        VirtualProtect(record.target, record.length, oldProtect, &ignored);
        FlushInstructionCache(GetCurrentProcess(), record.target, record.length);
        VirtualFree(record.trampoline, 0, MEM_RELEASE);
        if (record.relay) VirtualFree(record.relay, 0, MEM_RELEASE);
        g_hooks.erase(g_hooks.begin() + i);
        return true;
    }
    return false;
}

}  // namespace HookEngine
