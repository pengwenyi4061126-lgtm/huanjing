#define _WIN32_WINNT 0x0A00

#include <windows.h>
#include <tlhelp32.h>
#include <sddl.h>
#include <bcrypt.h>

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <map>
#include <set>
#include <string>
#include <vector>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "bcrypt.lib")

namespace {

const wchar_t* kDefaultTarget = L"cowork-svc.exe";
const wchar_t* kDefaultDll = L"C:\\ProgramData\\CAC\\native\\NativeBridge.dll";
const wchar_t* kDefaultAudit = L"C:\\ProgramData\\CAC\\logs\\service-injector.jsonl";
const wchar_t* kServiceName = L"CacServiceInjector";
const wchar_t* kTargetHashCache = L"C:\\ProgramData\\CAC\\native\\cowork-svc.hash";
const char* kCoworkSvcHash =
    "88447B35800CD7A8C3DDE1F7E2ABB001DD14B93749637BF653D92DEBA4133646";
const uint64_t kInternalFlagsRva = 0x123B9C0;
const size_t kInternalFlagCount = 21;
const size_t kInternalOsxsaveIndex = 12;
const uint64_t kVendorFlagsRva = 0x123BB00;
const size_t kVendorFlagCount = 45;
const size_t kVendorSse2Index = 37;

SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
SERVICE_STATUS g_status = {};
HANDLE g_stopEvent = nullptr;
HANDLE g_cpuVerifiedEvent = nullptr;
DWORD g_cpuVerifiedPid = 0;

std::wstring g_cachedTargetPath;
std::string g_cachedTargetHash;
uint64_t g_cachedTargetSize = 0;
uint64_t g_cachedTargetTicks = 0;
bool g_targetCacheLoaded = false;

HANDLE CreateBridgeEvent(DWORD processId, const wchar_t* kind, bool* alreadyExists);

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

uint64_t FindMainModuleBase(DWORD processId, const wchar_t* moduleName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
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

bool ComputeFileSha256(const std::wstring& path, std::string& hex) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;

    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objectSize = 0;
    DWORD hashSize = 0;
    DWORD result = 0;
    bool ok = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0;
    if (ok) {
        ok = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                               reinterpret_cast<PUCHAR>(&objectSize),
                               sizeof(objectSize), &result, 0) == 0;
    }
    if (ok) {
        ok = BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH,
                               reinterpret_cast<PUCHAR>(&hashSize),
                               sizeof(hashSize), &result, 0) == 0;
    }
    std::vector<BYTE> object;
    std::vector<BYTE> digest;
    if (ok) {
        object.resize(objectSize);
        digest.resize(hashSize);
        ok = BCryptCreateHash(algorithm, &hash, object.data(), objectSize, nullptr, 0, 0) == 0;
    }
    std::vector<BYTE> buffer(64 * 1024);
    while (ok) {
        DWORD read = 0;
        if (!ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr)) {
            ok = false;
            break;
        }
        if (read == 0) break;
        ok = BCryptHashData(hash, buffer.data(), read, 0) == 0;
    }
    if (ok) ok = BCryptFinishHash(hash, digest.data(), hashSize, 0) == 0;
    if (hash) BCryptDestroyHash(hash);
    if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    CloseHandle(file);

    if (!ok) return false;
    char text[65] = {};
    for (DWORD i = 0; i < hashSize; ++i) {
        std::snprintf(text + i * 2, sizeof(text) - i * 2, "%02X", digest[i]);
    }
    hex.assign(text, hashSize * 2);
    return true;
}

std::wstring Utf8ToWide(const std::string& value) {
    if (value.empty()) return std::wstring();
    const int length = MultiByteToWideChar(CP_UTF8, 0, value.data(),
                                           static_cast<int>(value.size()), nullptr, 0);
    if (length <= 0) return std::wstring();
    std::wstring result(static_cast<size_t>(length), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                        result.data(), length);
    return result;
}

void LoadTargetHashCache() {
    if (g_targetCacheLoaded) return;
    g_targetCacheLoaded = true;
    HANDLE file = CreateFileW(kTargetHashCache, GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return;
    char buffer[2048] = {};
    DWORD read = 0;
    const BOOL ok = ReadFile(file, buffer, static_cast<DWORD>(sizeof(buffer) - 1), &read, nullptr);
    CloseHandle(file);
    if (!ok || read == 0) return;

    std::string text(buffer, read);
    while (!text.empty() && (text.back() == '\r' || text.back() == '\n' || text.back() == ' ')) {
        text.pop_back();
    }
    size_t p1 = text.find('|');
    size_t p2 = p1 == std::string::npos ? std::string::npos : text.find('|', p1 + 1);
    size_t p3 = p2 == std::string::npos ? std::string::npos : text.find('|', p2 + 1);
    if (p1 == std::string::npos || p2 == std::string::npos || p3 == std::string::npos) return;
    g_cachedTargetPath = Utf8ToWide(text.substr(0, p1));
    g_cachedTargetSize = _strtoui64(text.substr(p1 + 1, p2 - p1 - 1).c_str(), nullptr, 10);
    g_cachedTargetTicks = _strtoui64(text.substr(p2 + 1, p3 - p2 - 1).c_str(), nullptr, 10);
    g_cachedTargetHash = text.substr(p3 + 1);
}

bool GetTargetHash(const std::wstring& path, std::string& hash, bool& fromCache) {
    fromCache = false;
    LoadTargetHashCache();
    if (!g_cachedTargetPath.empty() && _wcsicmp(g_cachedTargetPath.c_str(), path.c_str()) == 0 &&
        !g_cachedTargetHash.empty()) {
        WIN32_FILE_ATTRIBUTE_DATA data = {};
        if (GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data)) {
            const uint64_t size =
                (static_cast<uint64_t>(data.nFileSizeHigh) << 32) | data.nFileSizeLow;
            const uint64_t ticks =
                (static_cast<uint64_t>(data.ftLastWriteTime.dwHighDateTime) << 32) |
                data.ftLastWriteTime.dwLowDateTime;
            if (size == g_cachedTargetSize && ticks == g_cachedTargetTicks) {
                hash = g_cachedTargetHash;
                fromCache = true;
                return true;
            }
        }
    }
    return ComputeFileSha256(path, hash);
}

bool ReadProfileCpuidMode(std::wstring& mode) {
    HANDLE file = CreateFileW(L"C:\\ProgramData\\CAC\\active-profile.ini", GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER size = {};
    if (!GetFileSizeEx(file, &size) || size.QuadPart < 2 || size.QuadPart > 64 * 1024) {
        CloseHandle(file);
        return false;
    }
    std::vector<BYTE> bytes(static_cast<size_t>(size.QuadPart));
    DWORD read = 0;
    const BOOL ok = ReadFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr);
    CloseHandle(file);
    if (!ok || read < 2) return false;

    size_t offset = 0;
    if (bytes.size() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE) offset = 2;
    else return false;
    const wchar_t* text = reinterpret_cast<const wchar_t*>(bytes.data() + offset);
    const size_t chars = (bytes.size() - offset) / sizeof(wchar_t);
    std::wstring content(text, chars);
    size_t pos = 0;
    while (pos < content.size()) {
        size_t end = content.find(L'\n', pos);
        if (end == std::wstring::npos) end = content.size();
        std::wstring line = content.substr(pos, end - pos);
        pos = end + 1;
        while (!line.empty() && (line.back() == L'\r' || line.back() == L' ' || line.back() == L'\t')) {
            line.pop_back();
        }
        size_t begin = 0;
        while (begin < line.size() && (line[begin] == L' ' || line[begin] == L'\t')) ++begin;
        line.erase(0, begin);
        const std::wstring prefix = L"cpuid_mode=";
        if (line.compare(0, prefix.size(), prefix) == 0) {
            mode = line.substr(prefix.size());
            return true;
        }
    }
    return false;
}

enum class FlagPatchResult {
    Retry,
    Patched,
    Skipped,
};

FlagPatchResult PatchCoworkCpuFlags(DWORD processId, const std::wstring& auditPath) {
    std::wstring mode;
    if (ReadProfileCpuidMode(mode) && _wcsicmp(mode.c_str(), L"neutral") != 0) {
        AppendAudit(auditPath, "cpu-flags", processId, "skipped:profile-mode");
        return FlagPatchResult::Skipped;
    }

    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ |
                                     PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
                                 FALSE, processId);
    if (!process) return FlagPatchResult::Retry;

    wchar_t imagePath[32768] = {};
    DWORD imageLength = static_cast<DWORD>(_countof(imagePath));
    if (!QueryFullProcessImageNameW(process, 0, imagePath, &imageLength)) {
        CloseHandle(process);
        return FlagPatchResult::Retry;
    }
    const uint64_t base = FindMainModuleBase(processId, L"cowork-svc.exe");
    if (!base) {
        CloseHandle(process);
        return FlagPatchResult::Retry;
    }

    std::string hash;
    bool hashFromCache = false;
    if (!GetTargetHash(imagePath, hash, hashFromCache)) {
        CloseHandle(process);
        return FlagPatchResult::Retry;
    }
    if (_stricmp(hash.c_str(), kCoworkSvcHash) != 0) {
        AppendAudit(auditPath, "cpu-flags", processId, "skipped:hash-mismatch");
        CloseHandle(process);
        return FlagPatchResult::Skipped;
    }
    if (g_cpuVerifiedPid != processId) {
        if (g_cpuVerifiedEvent) CloseHandle(g_cpuVerifiedEvent);
        g_cpuVerifiedEvent = CreateBridgeEvent(processId, L"CpuVerified", nullptr);
        g_cpuVerifiedPid = processId;
        if (g_cpuVerifiedEvent) SetEvent(g_cpuVerifiedEvent);
    }

    BYTE internalFlags[kInternalFlagCount] = {};
    BYTE vendorFlags[kVendorFlagCount] = {};
    SIZE_T read = 0;
    if (!ReadProcessMemory(process, reinterpret_cast<const void*>(base + kInternalFlagsRva),
                           internalFlags, sizeof(internalFlags), &read) ||
        read != sizeof(internalFlags) ||
        !ReadProcessMemory(process, reinterpret_cast<const void*>(base + kVendorFlagsRva),
                           vendorFlags, sizeof(vendorFlags), &read) ||
        read != sizeof(vendorFlags)) {
        CloseHandle(process);
        return FlagPatchResult::Retry;
    }

    unsigned int internalChanged = 0;
    unsigned int vendorChanged = 0;
    for (size_t i = 0; i < kInternalFlagCount; ++i) {
        const BYTE value = i == kInternalOsxsaveIndex ? internalFlags[i] : 0;
        if (internalFlags[i] != value) ++internalChanged;
        internalFlags[i] = value;
    }
    for (size_t i = 0; i < kVendorFlagCount; ++i) {
        const BYTE value = i == kVendorSse2Index ? vendorFlags[i] : 0;
        if (vendorFlags[i] != value) ++vendorChanged;
        vendorFlags[i] = value;
    }

    if (!WriteProcessMemory(process, reinterpret_cast<void*>(base + kInternalFlagsRva),
                            internalFlags, sizeof(internalFlags), nullptr) ||
        !WriteProcessMemory(process, reinterpret_cast<void*>(base + kVendorFlagsRva),
                            vendorFlags, sizeof(vendorFlags), nullptr)) {
        AppendAudit(auditPath, "cpu-flags", processId, "failed:write");
        CloseHandle(process);
        return FlagPatchResult::Skipped;
    }
    CloseHandle(process);

    char detail[128] = {};
    std::snprintf(detail, sizeof(detail), "internal=%u/%u vendor=%u/%u hash=%s",
                  internalChanged, static_cast<unsigned int>(kInternalFlagCount),
                  vendorChanged, static_cast<unsigned int>(kVendorFlagCount),
                  hashFromCache ? "cache" : "computed");
    AppendAudit(auditPath, "cpu-flags", processId, detail);
    return FlagPatchResult::Patched;
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

    for (int attempt = 0; attempt < 20; ++attempt) {
        if (PatchCoworkCpuFlags(processId, auditPath) != FlagPatchResult::Retry) break;
        Sleep(25);
    }

    std::string error;
    const bool injected = InjectAndWait(processId, dllPath, &error);
    if (g_cpuVerifiedEvent) {
        CloseHandle(g_cpuVerifiedEvent);
        g_cpuVerifiedEvent = nullptr;
        g_cpuVerifiedPid = 0;
    }
    if (!injected) {
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

std::wstring BaseName(const std::wstring& path) {
    const size_t slash = path.find_last_of(L"\\/");
    return slash == std::wstring::npos ? path : path.substr(slash + 1);
}

std::string Narrow(const std::wstring& value) {
    if (value.empty()) return std::string();
    const int length = WideCharToMultiByte(CP_UTF8, 0, value.c_str(),
                                           static_cast<int>(value.size()), nullptr, 0,
                                           nullptr, nullptr);
    if (length <= 0) return std::string();
    std::string result(static_cast<size_t>(length), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()),
                        result.data(), length, nullptr, nullptr);
    return result;
}

bool QueryProcessImage(DWORD processId, std::wstring& image) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (!process) return false;
    wchar_t buffer[32768] = {};
    DWORD length = static_cast<DWORD>(_countof(buffer));
    const BOOL ok = QueryFullProcessImageNameW(process, 0, buffer, &length);
    CloseHandle(process);
    if (!ok || length == 0) return false;
    image.assign(buffer, length);
    return true;
}

bool IsAllowedDescendantImage(const std::wstring& image) {
    const std::wstring baseName = BaseName(image);
    static const wchar_t* const allowed[] = {
        L"powershell.exe", L"pwsh.exe", L"cmd.exe", L"ipconfig.exe", L"netsh.exe",
        L"wmic.exe", L"getmac.exe", L"route.exe", L"arp.exe", L"systeminfo.exe",
        L"nbtstat.exe", L"reg.exe", L"sc.exe", L"tasklist.exe", L"driverquery.exe",
        L"msinfo32.exe", L"dxdiag.exe", L"pnputil.exe", L"devcon.exe", L"certutil.exe",
        L"cscript.exe", L"wscript.exe", L"rundll32.exe", L"regsvr32.exe",
        L"whoami.exe", L"hostname.exe", L"wsl.exe", L"wslhost.exe", L"wt.exe",
        L"openconsole.exe", L"windowsterminal.exe", L"powershell_ise.exe",
        L"claude-ssh-broker.exe", L"claude-ssh-proxy.exe", L"claude-ssh-askpass.exe",
        L"github-mcp-server.exe", L"chrome-native-host.exe",
        L"node.exe", L"bun.exe", L"deno.exe", L"python.exe", L"pythonw.exe",
        L"uvx.exe", L"npx.exe", L"pnpm.exe", L"yarn.exe",
        L"ssh.exe", L"git.exe", L"gh.exe",
    };
    for (const wchar_t* name : allowed) {
        if (_wcsicmp(baseName.c_str(), name) == 0) return true;
    }
    return false;
}

std::set<DWORD> DescendantsOf(DWORD root) {
    std::map<DWORD, std::vector<DWORD>> children;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return {};
    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            children[entry.th32ParentProcessID].push_back(entry.th32ProcessID);
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);

    std::set<DWORD> result;
    std::vector<DWORD> queue{root};
    while (!queue.empty()) {
        const DWORD parent = queue.back();
        queue.pop_back();
        const auto it = children.find(parent);
        if (it == children.end()) continue;
        for (DWORD child : it->second) {
            if (child == root || result.count(child)) continue;
            result.insert(child);
            queue.push_back(child);
        }
    }
    return result;
}

int Watch(const std::wstring& target, const std::wstring& dllPath,
          const std::wstring& auditPath) {
    DWORD lastPid = 0;
    DWORD lastFailure = 0;
    DWORD flagsPatchedPid = 0;
    DWORD flagsSkippedPid = 0;
    std::set<DWORD> descendantAttempts;
    AppendAudit(auditPath, "watch-start", 0, "");
    while (!g_stopEvent || WaitForSingleObject(g_stopEvent, 0) == WAIT_TIMEOUT) {
        const DWORD processId = FindProcessId(target.c_str());
        if (processId && processId != lastPid) {
            AppendAudit(auditPath, "target-found", processId, "");
            lastPid = processId;
            flagsPatchedPid = 0;
            flagsSkippedPid = 0;
        }
        if (processId && !IsModuleLoaded(processId, L"NativeBridge.dll") &&
            processId != flagsPatchedPid && processId != flagsSkippedPid) {
            const FlagPatchResult flags = PatchCoworkCpuFlags(processId, auditPath);
            if (flags == FlagPatchResult::Patched) flagsPatchedPid = processId;
            if (flags == FlagPatchResult::Skipped) flagsSkippedPid = processId;
        }
        if (processId && !IsModuleLoaded(processId, L"NativeBridge.dll") &&
            processId != flagsPatchedPid && processId != flagsSkippedPid &&
            !g_cpuVerifiedEvent) {
            for (int attempt = 0; attempt < 3; ++attempt) {
                const FlagPatchResult retryFlags = PatchCoworkCpuFlags(processId, auditPath);
                if (retryFlags == FlagPatchResult::Skipped) {
                    flagsSkippedPid = processId;
                    break;
                }
                if (retryFlags == FlagPatchResult::Patched) break;
                Sleep(8);
            }
        }
        if (processId && !IsModuleLoaded(processId, L"NativeBridge.dll")) {
            std::string error;
            const bool injected = InjectAndWait(processId, dllPath, &error);
            if (g_cpuVerifiedEvent) {
                CloseHandle(g_cpuVerifiedEvent);
                g_cpuVerifiedEvent = nullptr;
                g_cpuVerifiedPid = 0;
            }
            if (!injected) {
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
        if (processId && IsModuleLoaded(processId, L"NativeBridge.dll")) {
            for (DWORD child : DescendantsOf(processId)) {
                if (descendantAttempts.count(child)) continue;
                std::wstring image;
                if (!QueryProcessImage(child, image)) continue;
                if (!IsAllowedDescendantImage(image)) continue;
                descendantAttempts.insert(child);
                if (IsModuleLoaded(child, L"NativeBridge.dll")) continue;
                std::string error;
                const std::string name = Narrow(BaseName(image));
                if (InjectAndWait(child, dllPath, &error)) {
                    AppendAudit(auditPath, "descendant-injected", child, name.c_str());
                } else {
                    AppendAudit(auditPath, "descendant-failed", child, error.c_str());
                }
            }
        }
        Sleep(50);
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
