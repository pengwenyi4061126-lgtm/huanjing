#include "Audit.h"

#include <cstdio>
#include <cstring>

namespace {

CRITICAL_SECTION g_lock;
INIT_ONCE g_once = INIT_ONCE_STATIC_INIT;
std::wstring g_path;

struct RateSlot {
    char surface[64];
    unsigned int count;
};

RateSlot g_rates[64] = {};
int g_rateCount = 0;

BOOL CALLBACK InitOnce(PINIT_ONCE, PVOID, PVOID*) {
    InitializeCriticalSection(&g_lock);
    wchar_t envPath[32768] = {};
    DWORD size = GetEnvironmentVariableW(L"CAC_NATIVE_AUDIT", envPath, static_cast<DWORD>(_countof(envPath)));
    if (size > 0 && size < _countof(envPath)) {
        g_path.assign(envPath, size);
    } else {
        wchar_t profile[32768] = {};
        size = GetEnvironmentVariableW(L"CAC_PROFILE_DIR", profile, static_cast<DWORD>(_countof(profile)));
        if (size > 0 && size < _countof(profile)) {
            g_path.assign(profile, size);
            g_path += L"\\audit\\native-hook.jsonl";
        }
    }
    return TRUE;
}

void EnsureInit() {
    InitOnceExecuteOnce(&g_once, InitOnce, nullptr, nullptr);
}

std::string Escape(const char* input) {
    std::string out;
    if (!input) return out;
    for (const char* p = input; *p; ++p) {
        switch (*p) {
            case '\\': out += "\\\\"; break;
            case '"': out += "\\\""; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default: out.push_back(*p); break;
        }
    }
    return out;
}

void WriteLine(const char* surface, const char* action, const char* detail,
               unsigned long long value, bool hasValue) {
    EnsureInit();
    if (g_path.empty()) return;

    SYSTEMTIME st = {};
    GetSystemTime(&st);
    char line[1024] = {};
    int written = std::snprintf(line, sizeof(line),
        "{\"utc\":\"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ\",\"pid\":%lu,\"surface\":\"%s\",\"action\":\"%s\"",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
        static_cast<unsigned long>(GetCurrentProcessId()), Escape(surface).c_str(), Escape(action).c_str());
    if (written <= 0 || written >= static_cast<int>(sizeof(line))) return;
    int used = written;
    if (detail && *detail) {
        written = std::snprintf(line + used, sizeof(line) - used, ",\"detail\":\"%s\"", Escape(detail).c_str());
        if (written <= 0 || written >= static_cast<int>(sizeof(line) - used)) return;
        used += written;
    }
    if (hasValue) {
        written = std::snprintf(line + used, sizeof(line) - used, ",\"value\":\"%llu\"",
                                static_cast<unsigned long long>(value));
        if (written <= 0 || written >= static_cast<int>(sizeof(line) - used)) return;
        used += written;
    }
    if (used + 2 < static_cast<int>(sizeof(line))) {
        line[used++] = '}';
        line[used++] = '\n';
        line[used] = 0;
    } else {
        return;
    }

    EnterCriticalSection(&g_lock);
    HANDLE file = CreateFileW(g_path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file != INVALID_HANDLE_VALUE) {
        DWORD bytes = 0;
        WriteFile(file, line, static_cast<DWORD>(used), &bytes, nullptr);
        CloseHandle(file);
    }
    LeaveCriticalSection(&g_lock);
}

}  // namespace

void AuditInit(const std::wstring& profileDir) {
    EnsureInit();
    if (g_path.empty() && !profileDir.empty()) {
        g_path = profileDir + L"\\audit\\native-hook.jsonl";
    }
}

void AuditEvent(const char* surface, const char* action, const char* detail,
                unsigned long long value, bool hasValue) {
    WriteLine(surface, action, detail, value, hasValue);
}

void AuditEventRateLimited(const char* surface, const char* action, const char* detail,
                           unsigned long long value, bool hasValue) {
    EnsureInit();
    EnterCriticalSection(&g_lock);
    bool log = false;
    for (int i = 0; i < g_rateCount; ++i) {
        if (std::strcmp(g_rates[i].surface, surface) == 0) {
            if (g_rates[i].count < 16) {
                ++g_rates[i].count;
                log = true;
            }
            break;
        }
    }
    if (!log && g_rateCount < static_cast<int>(_countof(g_rates))) {
        std::snprintf(g_rates[g_rateCount].surface, sizeof(g_rates[g_rateCount].surface), "%s", surface);
        g_rates[g_rateCount].count = 1;
        ++g_rateCount;
        log = true;
    }
    LeaveCriticalSection(&g_lock);
    if (log) WriteLine(surface, action, detail, value, hasValue);
}
