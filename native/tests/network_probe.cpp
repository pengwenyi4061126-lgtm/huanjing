#define _WIN32_WINNT 0x0A00

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <winhttp.h>
#include <wininet.h>

#include <cstdio>
#include <string>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "wininet.lib")

namespace {

std::string WideToUtf8(const wchar_t* value) {
    if (!value) return std::string();
    const int length = WideCharToMultiByte(CP_UTF8, 0, value, -1, nullptr, 0, nullptr, nullptr);
    if (length <= 1) return std::string();
    std::string result(static_cast<size_t>(length - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value, -1, result.data(), length, nullptr, nullptr);
    return result;
}

std::string MacText(const BYTE* address, ULONG length) {
    if (!address || length < 6) return "-";
    bool any = false;
    for (ULONG i = 0; i < 6; ++i) if (address[i]) any = true;
    if (!any) return "-";
    char text[32] = {};
    std::snprintf(text, sizeof(text), "%02x:%02x:%02x:%02x:%02x:%02x",
                  address[0], address[1], address[2], address[3], address[4], address[5]);
    return text;
}

std::string AdapterList() {
    ULONG size = 0;
    GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                         nullptr, nullptr, &size);
    std::vector<BYTE> buffer(size ? size : 1);
    PIP_ADAPTER_ADDRESSES addresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                             nullptr, addresses, &size) != NO_ERROR) {
        return "error";
    }
    std::string result;
    int count = 0;
    for (PIP_ADAPTER_ADDRESSES current = addresses; current; current = current->Next) {
        if (!result.empty()) result += ";";
        result += WideToUtf8(current->FriendlyName);
        result += "|";
        result += WideToUtf8(current->Description);
        result += "|";
        result += MacText(current->PhysicalAddress, current->PhysicalAddressLength);
        ++count;
    }
    std::printf("adapter_count=%d\n", count);
    return result.empty() ? "none" : result;
}

std::string IfTable2Names() {
    PMIB_IF_TABLE2 table = nullptr;
    if (GetIfTable2(&table) != NO_ERROR || !table) return "error";
    std::string result;
    for (ULONG i = 0; i < table->NumEntries; ++i) {
        if (!result.empty()) result += ";";
        result += WideToUtf8(table->Table[i].Alias);
    }
    const ULONG count = table->NumEntries;
    FreeMibTable(table);
    std::printf("if2_count=%lu\n", static_cast<unsigned long>(count));
    return result.empty() ? "none" : result;
}

std::string InterfaceInfoNames() {
    ULONG size = 0;
    GetInterfaceInfo(nullptr, &size);
    std::vector<BYTE> buffer(size ? size : 1);
    PIP_INTERFACE_INFO info = reinterpret_cast<PIP_INTERFACE_INFO>(buffer.data());
    if (GetInterfaceInfo(info, &size) != NO_ERROR) return "error";
    std::string result;
    for (DWORD i = 0; i < static_cast<DWORD>(info->NumAdapters); ++i) {
        if (!result.empty()) result += ";";
        result += WideToUtf8(info->Adapter[i].Name);
    }
    std::printf("ifinfo_count=%lu\n", static_cast<unsigned long>(info->NumAdapters));
    return result.empty() ? "none" : result;
}

void ProbeIeProxy() {
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG config = {};
    if (WinHttpGetIEProxyConfigForCurrentUser(&config)) {
        std::printf("ie_proxy_autodetect=%d\n", config.fAutoDetect ? 1 : 0);
        std::printf("ie_proxy_server=%s\n", WideToUtf8(config.lpszProxy).c_str());
        std::printf("ie_proxy_autoconfig=%s\n", WideToUtf8(config.lpszAutoConfigUrl).c_str());
        if (config.lpszProxy) GlobalFree(config.lpszProxy);
        if (config.lpszAutoConfigUrl) GlobalFree(config.lpszAutoConfigUrl);
        if (config.lpszProxyBypass) GlobalFree(config.lpszProxyBypass);
    } else {
        std::printf("ie_proxy_server=error\n");
    }
}

void ProbeRegistryProxy() {
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
                      0, KEY_READ, &key) != ERROR_SUCCESS) {
        std::printf("reg_proxy_enable=open-error\n");
        return;
    }
    DWORD enable = 0;
    DWORD size = sizeof(enable);
    DWORD type = 0;
    if (RegQueryValueExW(key, L"ProxyEnable", nullptr, &type, reinterpret_cast<LPBYTE>(&enable), &size) ==
        ERROR_SUCCESS && type == REG_DWORD) {
        std::printf("reg_proxy_enable=%lu\n", static_cast<unsigned long>(enable));
    } else {
        std::printf("reg_proxy_enable=missing\n");
    }
    wchar_t server[512] = {};
    size = sizeof(server);
    if (RegQueryValueExW(key, L"ProxyServer", nullptr, &type, reinterpret_cast<LPBYTE>(server), &size) ==
        ERROR_SUCCESS && type == REG_SZ) {
        std::printf("reg_proxy_server=%s\n", WideToUtf8(server).c_str());
    } else {
        std::printf("reg_proxy_server=missing\n");
    }
    RegCloseKey(key);
}

void ProbeWinHttp() {
    HINTERNET session = WinHttpOpen(L"cac-network-probe", WINHTTP_ACCESS_TYPE_NAMED_PROXY,
                                    L"127.0.0.1:7890", nullptr, 0);
    if (!session) {
        std::printf("winhttp_access=open-error\n");
        return;
    }
    WINHTTP_PROXY_INFO info = {};
    DWORD size = sizeof(info);
    if (WinHttpQueryOption(session, WINHTTP_OPTION_PROXY, &info, &size)) {
        std::printf("winhttp_access=%lu\n", static_cast<unsigned long>(info.dwAccessType));
        std::printf("winhttp_proxy=%s\n", WideToUtf8(info.lpszProxy).c_str());
        if (info.lpszProxy) GlobalFree(info.lpszProxy);
        if (info.lpszProxyBypass) GlobalFree(info.lpszProxyBypass);
    } else {
        std::printf("winhttp_access=query-error\n");
    }
    WinHttpCloseHandle(session);
}

void ProbeRoute() {
    SOCKADDR_INET destination = {};
    destination.si_family = AF_INET;
    destination.Ipv4.sin_addr.S_un.S_addr = inet_addr("1.1.1.1");
    MIB_IPFORWARD_ROW2 route = {};
    SOCKADDR_INET source = {};
    const DWORD status = GetBestRoute2(nullptr, 0, nullptr, &destination, 0, &route, &source);
    std::printf("route_status=%lu\n", static_cast<unsigned long>(status));
    if (status == NO_ERROR) {
        std::printf("route_index=%lu\n", static_cast<unsigned long>(route.InterfaceIndex));
        std::printf("route_metric=%lu\n", static_cast<unsigned long>(route.Metric));
        std::printf("route_observation=best-route-interface-index\n");
    } else {
        std::printf("route_index=error\n");
    }
}

}  // namespace

int wmain() {
    std::printf("adapters=%s\n", AdapterList().c_str());
    std::printf("if2_names=%s\n", IfTable2Names().c_str());
    std::printf("ifinfo_names=%s\n", InterfaceInfoNames().c_str());
    ProbeIeProxy();
    ProbeRegistryProxy();
    ProbeWinHttp();
    ProbeRoute();
    return 0;
}
