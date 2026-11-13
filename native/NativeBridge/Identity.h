#pragma once

#include <windows.h>
#include <string>

// Profile-scoped identity shared by the Node preload and the native layer.
// Values are loaded from %CAC_PROFILE_IDENTITY% (identity.json) and from the
// CAC_* environment variables set by the cac wrapper.
struct ProfileIdentity {
    std::wstring profileDir;
    std::string  hostname;
    std::string  username;
    std::string  machineId;
    std::string  mac;              // aa:bb:cc:dd:ee:ff
    BYTE         macBytes[6] = {};
    bool         hasMac = false;
    std::string  diskSerial;
    std::string  biosSerial;
    std::string  boardSerial;
    std::string  systemSerial;
    std::string  systemUuid;       // 32 hex chars
    std::string  processorId;      // 16 hex chars
    std::string  hidSerial;
    std::string  volumeSerialHex_;
    DWORD        volumeSerial = 0;

    bool Load();

    static ProfileIdentity& Get();
};
