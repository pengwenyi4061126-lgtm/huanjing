#pragma once

#include <windows.h>
#include <string>

namespace HookEngine {

// Installs a 5-byte relative jump at target. Only a bounded set of common
// x64 prologue instructions is accepted; anything else is refused instead of
// being patched blindly.
bool Install(void* target, void* detour, void** trampoline, std::string* error);

bool Uninstall(void* target);

// Number of bytes consumed by a recognized prologue instruction, or 0.
int DecodePrologueInstruction(const BYTE* code, int available);

bool IsExecutableAddress(const void* address);

}  // namespace HookEngine
