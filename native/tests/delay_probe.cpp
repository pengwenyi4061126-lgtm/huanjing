#define _WIN32_WINNT 0x0A00

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

#include <cstdio>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "delayimp.lib")

int wmain() {
    ULONG size = 0;
    GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                         nullptr, nullptr, &size);
    std::vector<BYTE> buffer(size);
    PIP_ADAPTER_ADDRESSES addresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                             nullptr, addresses, &size) != NO_ERROR) {
        std::printf("delay_mac=error\n");
        return 1;
    }
    for (PIP_ADAPTER_ADDRESSES current = addresses; current; current = current->Next) {
        if (current->PhysicalAddressLength == 6) {
            std::printf("delay_mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
                        current->PhysicalAddress[0], current->PhysicalAddress[1], current->PhysicalAddress[2],
                        current->PhysicalAddress[3], current->PhysicalAddress[4], current->PhysicalAddress[5]);
            return 0;
        }
    }
    std::printf("delay_mac=none\n");
    return 0;
}
