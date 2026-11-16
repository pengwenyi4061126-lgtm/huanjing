#include "CacMacLwfIoctl.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static HANDLE OpenDevice() {
    return CreateFileW(
        CAC_MAC_USER_PATH,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);
}

static int Fail(const char *message, DWORD error) {
    printf("{\"ok\":false,\"error\":\"%s\",\"win32\":%lu}\n", message, (unsigned long)error);
    return 1;
}

static int HexNibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool ParseMac(const wchar_t *text, unsigned char *out) {
    char compact[13] = {};
    size_t length = 0;
    for (size_t i = 0; text[i] != L'\0' && length < 12; ++i) {
        if (text[i] != L':' && text[i] != L'-') {
            compact[length++] = (char)text[i];
        }
    }
    if (length != 12) {
        return false;
    }
    for (size_t i = 0; i < 6; ++i) {
        int high = HexNibble(compact[i * 2]);
        int low = HexNibble(compact[i * 2 + 1]);
        if (high < 0 || low < 0) {
            return false;
        }
        out[i] = (unsigned char)((high << 4) | low);
    }
    return true;
}

static int PrintState(const CAC_MAC_STATE &state) {
    printf("{\"ok\":true,\"setCount\":%lu,\"oidQueriesSeen\":%lu,"
           "\"oidRewrites\":%lu,\"attached\":%lu,\"detached\":%lu,"
           "\"registerStatus\":%lu,\"running\":%lu,\"lastOid\":%lu,"
           "\"lastRewriteOid\":%lu,\"sendPaused\":%lu,\"sendForwarded\":%lu,"
           "\"receivePaused\":%lu,\"receiveForwarded\":%lu,"
           "\"mac\":\"%02x:%02x:%02x:%02x:%02x:%02x\"}\n",
           (unsigned long)state.SetCount,
           (unsigned long)state.OidQueriesSeen,
           (unsigned long)state.OidRewrites,
           (unsigned long)state.AttachedModules,
           (unsigned long)state.DetachedModules,
           (unsigned long)state.RegisterStatus,
           (unsigned long)state.Running,
           (unsigned long)state.LastOid,
           (unsigned long)state.LastRewriteOid,
           (unsigned long)state.SendPaused,
           (unsigned long)state.SendForwarded,
           (unsigned long)state.ReceivePaused,
           (unsigned long)state.ReceiveForwarded,
           state.Mac[0], state.Mac[1], state.Mac[2],
           state.Mac[3], state.Mac[4], state.Mac[5]);
    return 0;
}

int wmain(int argc, wchar_t **argv) {
    if (argc < 2) {
        printf("cac-macctl set --mac AA:BB:CC:DD:EE:FF\n"
               "cac-macctl state\n");
        return 2;
    }

    HANDLE device = OpenDevice();
    if (device == INVALID_HANDLE_VALUE) {
        return Fail("open device", GetLastError());
    }

    DWORD returned = 0;
    int result = 0;
    if (wcscmp(argv[1], L"set") == 0) {
        const wchar_t *macText = NULL;
        for (int i = 2; i < argc; ++i) {
            if (wcscmp(argv[i], L"--mac") == 0 && i + 1 < argc) {
                macText = argv[++i];
            }
        }
        if (macText == NULL) {
            result = 2;
        } else {
            unsigned char mac[6];
            if (!ParseMac(macText, mac)) {
                result = Fail("invalid mac", 0);
            } else if (!DeviceIoControl(device, CAC_MAC_IOCTL_SET,
                                        mac, sizeof(mac), NULL, 0, &returned, NULL)) {
                result = Fail("set mac", GetLastError());
            } else {
                CAC_MAC_STATE state = {};
                if (!DeviceIoControl(device, CAC_MAC_IOCTL_STATE,
                                     NULL, 0, &state, sizeof(state), &returned, NULL)) {
                    result = Fail("state", GetLastError());
                } else {
                    result = PrintState(state);
                }
            }
        }
    } else if (wcscmp(argv[1], L"state") == 0) {
        CAC_MAC_STATE state = {};
        if (!DeviceIoControl(device, CAC_MAC_IOCTL_STATE,
                             NULL, 0, &state, sizeof(state), &returned, NULL)) {
            result = Fail("state", GetLastError());
        } else {
            result = PrintState(state);
        }
    } else {
        result = 2;
    }

    CloseHandle(device);
    return result;
}
