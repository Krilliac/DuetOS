#pragma once

#include "util/types.h"

namespace duetos::net
{

inline constexpr u32 kWifiMaxIfaces = 4;
inline constexpr u32 kWifiMaxScanResults = 16;
inline constexpr u32 kWifiSsidMaxBytes = 32;
inline constexpr u32 kWifiPskMaxBytes = 63;

enum class WifiSecurity : u8
{
    Open = 0,
    Wpa2Psk = 1,
};

struct WifiScanResult
{
    char ssid[kWifiSsidMaxBytes + 1];
    i32 rssi_dbm;
    WifiSecurity security;
};

struct WifiStatus
{
    bool backend_present;
    bool connected;
    u32 iface_index;
    WifiSecurity security;
    char ssid[kWifiSsidMaxBytes + 1];
};

using WifiScanFn = bool (*)(void* ctx, WifiScanResult* out, u32 max_results, u32* out_count);
using WifiConnectFn = bool (*)(void* ctx, const char* ssid, WifiSecurity security, const char* psk_or_null);
using WifiDisconnectFn = bool (*)(void* ctx);

struct WifiBackendOps
{
    WifiScanFn scan;
    WifiConnectFn connect;
    WifiDisconnectFn disconnect;
    void* ctx;
};

void WifiInit();

bool WifiRegisterBackend(u32 iface_index, const WifiBackendOps& ops);

bool WifiScan(u32 iface_index, WifiScanResult* out, u32 max_results, u32* out_count);

bool WifiConnect(u32 iface_index, const char* ssid, WifiSecurity security, const char* psk_or_null);

bool WifiDisconnect(u32 iface_index);

WifiStatus WifiStatusRead(u32 iface_index);

} // namespace duetos::net
