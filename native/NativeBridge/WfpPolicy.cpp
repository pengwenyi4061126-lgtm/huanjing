#include "WfpPolicy.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <fwpmu.h>

#include <cstring>

#include "Audit.h"

namespace {

HANDLE g_engine = nullptr;

bool IsTruthy(const char* name) {
    char value[16] = {};
    const DWORD length = GetEnvironmentVariableA(name, value, static_cast<DWORD>(sizeof(value)));
    if (length == 0 || length >= sizeof(value)) return false;
    for (DWORD i = 0; i < length; ++i) {
        if (value[i] >= 'A' && value[i] <= 'Z') value[i] = static_cast<char>(value[i] - 'A' + 'a');
    }
    return std::strcmp(value, "1") == 0 || std::strcmp(value, "true") == 0 ||
           std::strcmp(value, "yes") == 0;
}

DWORD AddAppFilter(const GUID& layer,
                   FWP_BYTE_BLOB* appId,
                   bool allowLoopback,
                   bool ipv6,
                   UINT8 weight) {
    FWPM_FILTER_CONDITION0 conditions[2] = {};
    UINT32 loopback4 = htonl(INADDR_LOOPBACK);
    FWP_BYTE_ARRAY16 loopback6 = {};

    conditions[0].fieldKey = FWPM_CONDITION_ALE_APP_ID;
    conditions[0].matchType = FWP_MATCH_EQUAL;
    conditions[0].conditionValue.type = FWP_BYTE_BLOB_TYPE;
    conditions[0].conditionValue.byteBlob = appId;

    UINT32 conditionCount = 1;
    if (allowLoopback) {
        conditions[1].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        conditions[1].matchType = FWP_MATCH_EQUAL;
        if (ipv6) {
            loopback6.byteArray16[15] = 1;
            conditions[1].conditionValue.type = FWP_BYTE_ARRAY16_TYPE;
            conditions[1].conditionValue.byteArray16 = &loopback6;
        } else {
            conditions[1].conditionValue.type = FWP_UINT32;
            conditions[1].conditionValue.uint32 = loopback4;
        }
        conditionCount = 2;
    }

    FWPM_FILTER0 filter = {};
    filter.displayData.name = const_cast<wchar_t*>(
        allowLoopback ? L"CAC loopback proxy allow" : L"CAC non-loopback egress block");
    filter.layerKey = layer;
    filter.subLayerKey = FWPM_SUBLAYER_UNIVERSAL;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = weight;
    filter.numFilterConditions = conditionCount;
    filter.filterCondition = conditions;
    filter.action.type = allowLoopback ? FWP_ACTION_PERMIT : FWP_ACTION_BLOCK;
    return FwpmFilterAdd0(g_engine, &filter, nullptr, nullptr);
}

}  // namespace

bool WfpPolicyRequired() {
    return IsTruthy("CAC_WFP_REQUIRED");
}

bool InstallWfpBoundary() {
    if (!IsTruthy("CAC_NETWORK_ENFORCE")) {
        return true;
    }
    if (g_engine != nullptr) {
        return true;
    }

    FWPM_SESSION0 session = {};
    session.displayData.name = const_cast<wchar_t*>(L"CAC dynamic profile boundary");
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    DWORD status = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, &g_engine);
    if (status != ERROR_SUCCESS) {
        AuditEvent("wfp.policy", "failed", "engine-open", status, true);
        g_engine = nullptr;
        return false;
    }

    wchar_t executable[MAX_PATH * 4] = {};
    const DWORD pathLength = GetModuleFileNameW(nullptr, executable, _countof(executable));
    if (pathLength == 0 || pathLength >= _countof(executable)) {
        const DWORD error = GetLastError();
        AuditEvent("wfp.policy", "failed", "module-path", error, true);
        FwpmEngineClose0(g_engine);
        g_engine = nullptr;
        return false;
    }

    FWP_BYTE_BLOB* appId = nullptr;
    status = FwpmGetAppIdFromFileName0(executable, &appId);
    if (status != ERROR_SUCCESS || appId == nullptr) {
        AuditEvent("wfp.policy", "failed", "app-id", status, true);
        FwpmEngineClose0(g_engine);
        g_engine = nullptr;
        return false;
    }

    status = AddAppFilter(FWPM_LAYER_ALE_AUTH_CONNECT_V4, appId, true, false, 15);
    if (status == ERROR_SUCCESS) {
        status = AddAppFilter(FWPM_LAYER_ALE_AUTH_CONNECT_V4, appId, false, false, 14);
    }
    if (status == ERROR_SUCCESS) {
        status = AddAppFilter(FWPM_LAYER_ALE_AUTH_CONNECT_V6, appId, true, true, 15);
    }
    if (status == ERROR_SUCCESS) {
        status = AddAppFilter(FWPM_LAYER_ALE_AUTH_CONNECT_V6, appId, false, true, 14);
    }
    FwpmFreeMemory0(reinterpret_cast<void**>(&appId));
    if (status != ERROR_SUCCESS) {
        AuditEvent("wfp.policy", "failed", "filter-add", status, true);
        FwpmEngineClose0(g_engine);
        g_engine = nullptr;
        return false;
    }

    AuditEvent("wfp.policy", "installed", "image-loopback-allow-nonloopback-block",
               GetCurrentProcessId(), true);
    return true;
}
