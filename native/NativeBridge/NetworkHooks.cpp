#define _WIN32_WINNT 0x0A00

#include "NetworkHooks.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <wininet.h>
#include <winhttp.h>

#include <cstring>
#include <cstdio>
#include <string>

#include "ApiHooks.h"
#include "Audit.h"

namespace {

typedef DWORD (WINAPI* PFN_GetInterfaceInfo)(PIP_INTERFACE_INFO, PULONG);
typedef BOOL (WINAPI* PFN_ConvertInterfaceLuidToNameW)(const NET_LUID*, PWSTR, ULONG);
typedef BOOL (WINAPI* PFN_ConvertInterfaceLuidToAlias)(const NET_LUID*, PWSTR, ULONG);
typedef BOOL (WINAPI* PFN_ConvertInterfaceNameToLuidW)(const WCHAR*, NET_LUID*);
typedef BOOL (WINAPI* PFN_WinHttpGetIEProxyConfigForCurrentUser)(PWINHTTP_CURRENT_USER_IE_PROXY_CONFIG);
typedef BOOL (WINAPI* PFN_WinHttpGetProxyForUrl)(HINTERNET, LPCWSTR, WINHTTP_AUTOPROXY_OPTIONS*,
                                                 WINHTTP_PROXY_INFO*);
typedef BOOL (WINAPI* PFN_WinHttpGetDefaultProxyConfiguration)(WINHTTP_PROXY_INFO*);
typedef HINTERNET (WINAPI* PFN_WinHttpOpen)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
typedef BOOL (WINAPI* PFN_InternetQueryOptionW)(HINTERNET, DWORD, LPVOID, LPDWORD);
typedef DWORD (WINAPI* PFN_GetBestRoute2)(const NET_LUID*, NET_IFINDEX, const SOCKADDR_INET*,
                                          const SOCKADDR_INET*, ULONG, PMIB_IPFORWARD_ROW2,
                                          PSOCKADDR_INET);

PFN_GetInterfaceInfo g_origGetInterfaceInfo = nullptr;
PFN_ConvertInterfaceLuidToNameW g_origConvertLuidToName = nullptr;
PFN_ConvertInterfaceLuidToAlias g_origConvertLuidToAlias = nullptr;
PFN_ConvertInterfaceNameToLuidW g_origConvertNameToLuid = nullptr;
PFN_WinHttpGetIEProxyConfigForCurrentUser g_origGetIeProxyConfig = nullptr;
PFN_WinHttpGetProxyForUrl g_origGetProxyForUrl = nullptr;
PFN_WinHttpGetDefaultProxyConfiguration g_origGetDefaultProxy = nullptr;
PFN_WinHttpOpen g_origWinHttpOpen = nullptr;
PFN_InternetQueryOptionW g_origInternetQueryOption = nullptr;
PFN_GetBestRoute2 g_origGetBestRoute2 = nullptr;

DWORD WINAPI HookGetInterfaceInfo(PIP_INTERFACE_INFO info, PULONG size) {
    const DWORD status = g_origGetInterfaceInfo ? g_origGetInterfaceInfo(info, size) : ERROR_NOT_SUPPORTED;
    if (status == NO_ERROR && info && NativeCleanNetworkEnabled()) {
        if (NativeEmptyReadsEnabled()) {
            info->NumAdapters = 0;
            AuditEventRateLimited("api.getinterfaceinfo", "clean-none");
            return status;
        }
        DWORD kept = 0;
        for (DWORD index = 0; index < static_cast<DWORD>(info->NumAdapters); ++index) {
            if (NativeIsVirtualAdapterName(info->Adapter[index].Name)) continue;
            if (kept != index) info->Adapter[kept] = info->Adapter[index];
            ++kept;
        }
        info->NumAdapters = kept;
        AuditEventRateLimited("api.getinterfaceinfo", "cleaned");
    }
    return status;
}

BOOL WINAPI HookConvertInterfaceLuidToNameW(const NET_LUID* luid, PWSTR name, ULONG size) {
    const BOOL result = g_origConvertLuidToName ? g_origConvertLuidToName(luid, name, size) : FALSE;
    if (result && NativeCleanNetworkEnabled() && NativeIsVirtualAdapterName(name)) {
        if (name && size) name[0] = L'\0';
        SetLastError(ERROR_NOT_FOUND);
        AuditEventRateLimited("api.convertinterfaceluidtoname", "clean-none");
        return FALSE;
    }
    return result;
}

BOOL WINAPI HookConvertInterfaceLuidToAlias(const NET_LUID* luid, PWSTR alias, ULONG size) {
    const BOOL result = g_origConvertLuidToAlias ? g_origConvertLuidToAlias(luid, alias, size) : FALSE;
    if (result && NativeCleanNetworkEnabled() && NativeIsVirtualAdapterName(alias)) {
        if (alias && size) alias[0] = L'\0';
        SetLastError(ERROR_NOT_FOUND);
        AuditEventRateLimited("api.convertinterfaceluidtoalias", "clean-none");
        return FALSE;
    }
    return result;
}

BOOL WINAPI HookConvertInterfaceNameToLuidW(const WCHAR* name, NET_LUID* luid) {
    if (NativeCleanNetworkEnabled() && NativeIsVirtualAdapterName(name)) {
        SetLastError(ERROR_NOT_FOUND);
        AuditEventRateLimited("api.convertinterfacenametoluid", "clean-none");
        return FALSE;
    }
    return g_origConvertNameToLuid ? g_origConvertNameToLuid(name, luid) : FALSE;
}

BOOL WINAPI HookWinHttpGetIEProxyConfigForCurrentUser(PWINHTTP_CURRENT_USER_IE_PROXY_CONFIG config) {
    if (config && NativeCleanNetworkEnabled()) {
        std::memset(config, 0, sizeof(*config));
        config->fAutoDetect = FALSE;
        AuditEventRateLimited("api.winhttp.ieproxyconfig", "clean-none");
        return TRUE;
    }
    return g_origGetIeProxyConfig ? g_origGetIeProxyConfig(config) : FALSE;
}

BOOL WINAPI HookWinHttpGetProxyForUrl(HINTERNET session, LPCWSTR url,
                                      WINHTTP_AUTOPROXY_OPTIONS* options, WINHTTP_PROXY_INFO* info) {
    if (info && NativeCleanNetworkEnabled()) {
        std::memset(info, 0, sizeof(*info));
        info->dwAccessType = WINHTTP_ACCESS_TYPE_NO_PROXY;
        AuditEventRateLimited("api.winhttp.proxyforurl", "clean-none");
        return TRUE;
    }
    return g_origGetProxyForUrl ? g_origGetProxyForUrl(session, url, options, info) : FALSE;
}

BOOL WINAPI HookWinHttpGetDefaultProxyConfiguration(WINHTTP_PROXY_INFO* info) {
    if (info && NativeCleanNetworkEnabled()) {
        std::memset(info, 0, sizeof(*info));
        info->dwAccessType = WINHTTP_ACCESS_TYPE_NO_PROXY;
        AuditEventRateLimited("api.winhttp.defaultproxy", "clean-none");
        return TRUE;
    }
    return g_origGetDefaultProxy ? g_origGetDefaultProxy(info) : FALSE;
}

HINTERNET WINAPI HookWinHttpOpen(LPCWSTR agent, DWORD accessType, LPCWSTR proxy, LPCWSTR bypass,
                                 DWORD flags) {
    if (NativeCleanNetworkEnabled()) {
        accessType = WINHTTP_ACCESS_TYPE_NO_PROXY;
        proxy = nullptr;
        bypass = nullptr;
    }
    return g_origWinHttpOpen ? g_origWinHttpOpen(agent, accessType, proxy, bypass, flags) : nullptr;
}

BOOL WINAPI HookInternetQueryOptionW(HINTERNET handle, DWORD option, LPVOID buffer, LPDWORD size) {
    if (NativeCleanNetworkEnabled() && option == INTERNET_OPTION_PROXY && buffer && size) {
        INTERNET_PROXY_INFO info = {};
        info.dwAccessType = INTERNET_OPEN_TYPE_DIRECT;
        const DWORD needed = static_cast<DWORD>(sizeof(info));
        if (*size < needed) {
            *size = needed;
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            return FALSE;
        }
        std::memcpy(buffer, &info, sizeof(info));
        *size = needed;
        AuditEventRateLimited("api.wininet.queryproxy", "clean-none");
        return TRUE;
    }
    return g_origInternetQueryOption ? g_origInternetQueryOption(handle, option, buffer, size) : FALSE;
}

DWORD WINAPI HookGetBestRoute2(const NET_LUID* interfaceLuid, NET_IFINDEX interfaceIndex,
                               const SOCKADDR_INET* sourceAddress,
                               const SOCKADDR_INET* destinationAddress, ULONG addressSortOptions,
                               PMIB_IPFORWARD_ROW2 bestRoute, PSOCKADDR_INET bestSourceAddress) {
    const DWORD status = g_origGetBestRoute2
        ? g_origGetBestRoute2(interfaceLuid, interfaceIndex, sourceAddress, destinationAddress,
                              addressSortOptions, bestRoute, bestSourceAddress)
        : ERROR_NOT_SUPPORTED;
    char detail[160] = {};
    if (status == NO_ERROR && bestRoute) {
        std::snprintf(detail, sizeof(detail), "status=0;interface=%lu;metric=%lu;policy=observe-only",
                      static_cast<unsigned long>(bestRoute->InterfaceIndex),
                      static_cast<unsigned long>(bestRoute->Metric));
        AuditEventRateLimited("api.getbestroute2",
                              NativeCleanNetworkEnabled() ? "observed-clean-passthrough" : "observed",
                              detail);
    } else {
        std::snprintf(detail, sizeof(detail), "status=%lu;policy=observe-only",
                      static_cast<unsigned long>(status));
        AuditEventRateLimited("api.getbestroute2", "observed-error", detail);
    }
    return status;
}

}  // namespace

void InstallNetworkHooks() {
    InstallHookInlinePrimary("iphlpapi.dll", "GetInterfaceInfo", reinterpret_cast<void*>(&HookGetInterfaceInfo),
                             reinterpret_cast<void**>(&g_origGetInterfaceInfo));
    InstallHookInlinePrimary("iphlpapi.dll", "ConvertInterfaceLuidToNameW",
                             reinterpret_cast<void*>(&HookConvertInterfaceLuidToNameW),
                             reinterpret_cast<void**>(&g_origConvertLuidToName));
    InstallHookInlinePrimary("iphlpapi.dll", "ConvertInterfaceLuidToAlias",
                             reinterpret_cast<void*>(&HookConvertInterfaceLuidToAlias),
                             reinterpret_cast<void**>(&g_origConvertLuidToAlias));
    InstallHookInlinePrimary("iphlpapi.dll", "ConvertInterfaceNameToLuidW",
                             reinterpret_cast<void*>(&HookConvertInterfaceNameToLuidW),
                             reinterpret_cast<void**>(&g_origConvertNameToLuid));
    InstallHookInlinePrimary("winhttp.dll", "WinHttpGetIEProxyConfigForCurrentUser",
                             reinterpret_cast<void*>(&HookWinHttpGetIEProxyConfigForCurrentUser),
                             reinterpret_cast<void**>(&g_origGetIeProxyConfig));
    InstallHookInlinePrimary("winhttp.dll", "WinHttpGetProxyForUrl",
                             reinterpret_cast<void*>(&HookWinHttpGetProxyForUrl),
                             reinterpret_cast<void**>(&g_origGetProxyForUrl));
    InstallHookInlinePrimary("winhttp.dll", "WinHttpGetDefaultProxyConfiguration",
                             reinterpret_cast<void*>(&HookWinHttpGetDefaultProxyConfiguration),
                             reinterpret_cast<void**>(&g_origGetDefaultProxy));
    InstallHookInlinePrimary("winhttp.dll", "WinHttpOpen",
                             reinterpret_cast<void*>(&HookWinHttpOpen),
                             reinterpret_cast<void**>(&g_origWinHttpOpen));
    InstallHookInlinePrimary("wininet.dll", "InternetQueryOptionW",
                             reinterpret_cast<void*>(&HookInternetQueryOptionW),
                             reinterpret_cast<void**>(&g_origInternetQueryOption));
    InstallHookInlinePrimary("iphlpapi.dll", "GetBestRoute2", reinterpret_cast<void*>(&HookGetBestRoute2),
                             reinterpret_cast<void**>(&g_origGetBestRoute2));
}
