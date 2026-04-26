#include "net/wifi.h"

#include "diag/cleanroom_trace.h"
#include "sync/spinlock.h"

namespace duetos::net
{

namespace
{

struct WifiIfaceState
{
    bool registered;
    WifiBackendOps ops;
    WifiStatus status;
};

constinit sync::SpinLock g_lock = {};
constinit WifiIfaceState g_ifaces[kWifiMaxIfaces] = {};

void CopyAsciiBounded(char* dst, u32 dst_cap, const char* src)
{
    if (dst == nullptr || dst_cap == 0)
        return;
    u32 i = 0;
    if (src != nullptr)
    {
        for (; i + 1 < dst_cap && src[i] != '\0'; ++i)
            dst[i] = src[i];
    }
    dst[i] = '\0';
}

} // namespace

void WifiInit()
{
    sync::SpinLockGuard guard(g_lock);
    (void)guard;
    for (u32 i = 0; i < kWifiMaxIfaces; ++i)
    {
        g_ifaces[i] = {};
        g_ifaces[i].status.iface_index = i;
        g_ifaces[i].status.security = WifiSecurity::Open;
    }
}

bool WifiRegisterBackend(u32 iface_index, const WifiBackendOps& ops)
{
    if (iface_index >= kWifiMaxIfaces || ops.scan == nullptr || ops.connect == nullptr || ops.disconnect == nullptr)
    {
        core::CleanroomTraceRecord("wifi", "register-reject", iface_index, 0, 0);
        return false;
    }
    sync::SpinLockGuard guard(g_lock);
    (void)guard;
    WifiIfaceState& s = g_ifaces[iface_index];
    s.registered = true;
    s.ops = ops;
    s.status.backend_present = true;
    s.status.iface_index = iface_index;
    core::CleanroomTraceRecord("wifi", "register-ok", iface_index, 0, 0);
    return true;
}

bool WifiScan(u32 iface_index, WifiScanResult* out, u32 max_results, u32* out_count)
{
    if (out_count != nullptr)
        *out_count = 0;
    if (iface_index >= kWifiMaxIfaces || out == nullptr || max_results == 0)
    {
        core::CleanroomTraceRecord("wifi", "scan-invalid", iface_index, max_results, 0);
        return false;
    }

    WifiBackendOps ops{};
    {
        sync::SpinLockGuard guard(g_lock);
        (void)guard;
        const WifiIfaceState& s = g_ifaces[iface_index];
        if (!s.registered)
        {
            core::CleanroomTraceRecord("wifi", "scan-no-backend", iface_index, 0, 0);
            return false;
        }
        ops = s.ops;
    }
    const bool ok = ops.scan(ops.ctx, out, max_results, out_count);
    core::CleanroomTraceRecord("wifi", ok ? "scan-ok" : "scan-fail", iface_index, out_count ? *out_count : 0, 0);
    return ok;
}

bool WifiConnect(u32 iface_index, const char* ssid, WifiSecurity security, const char* psk_or_null)
{
    if (iface_index >= kWifiMaxIfaces || ssid == nullptr || ssid[0] == '\0')
    {
        core::CleanroomTraceRecord("wifi", "connect-invalid", iface_index, 0, 0);
        return false;
    }
    if (security == WifiSecurity::Wpa2Psk)
    {
        if (psk_or_null == nullptr || psk_or_null[0] == '\0')
            return false;
        u32 psk_len = 0;
        while (psk_or_null[psk_len] != '\0')
            ++psk_len;
        if (psk_len < 8 || psk_len > kWifiPskMaxBytes)
        {
            core::CleanroomTraceRecord("wifi", "connect-bad-psk", iface_index, psk_len, 0);
            return false;
        }
    }

    WifiBackendOps ops{};
    {
        sync::SpinLockGuard guard(g_lock);
        (void)guard;
        const WifiIfaceState& s = g_ifaces[iface_index];
        if (!s.registered)
        {
            core::CleanroomTraceRecord("wifi", "connect-no-backend", iface_index, 0, 0);
            return false;
        }
        ops = s.ops;
    }

    if (!ops.connect(ops.ctx, ssid, security, psk_or_null))
    {
        core::CleanroomTraceRecord("wifi", "connect-driver-fail", iface_index, static_cast<u64>(security), 0);
        return false;
    }

    sync::SpinLockGuard guard(g_lock);
    (void)guard;
    WifiIfaceState& s = g_ifaces[iface_index];
    s.status.backend_present = true;
    s.status.connected = true;
    s.status.iface_index = iface_index;
    s.status.security = security;
    CopyAsciiBounded(s.status.ssid, sizeof(s.status.ssid), ssid);
    core::CleanroomTraceRecord("wifi", "connect-ok", iface_index, static_cast<u64>(security), 0);
    return true;
}

bool WifiDisconnect(u32 iface_index)
{
    if (iface_index >= kWifiMaxIfaces)
    {
        core::CleanroomTraceRecord("wifi", "disconnect-invalid", iface_index, 0, 0);
        return false;
    }
    WifiBackendOps ops{};
    {
        sync::SpinLockGuard guard(g_lock);
        (void)guard;
        const WifiIfaceState& s = g_ifaces[iface_index];
        if (!s.registered)
        {
            core::CleanroomTraceRecord("wifi", "disconnect-no-backend", iface_index, 0, 0);
            return false;
        }
        ops = s.ops;
    }
    if (!ops.disconnect(ops.ctx))
    {
        core::CleanroomTraceRecord("wifi", "disconnect-driver-fail", iface_index, 0, 0);
        return false;
    }

    sync::SpinLockGuard guard(g_lock);
    (void)guard;
    WifiIfaceState& s = g_ifaces[iface_index];
    s.status.connected = false;
    s.status.security = WifiSecurity::Open;
    s.status.ssid[0] = '\0';
    core::CleanroomTraceRecord("wifi", "disconnect-ok", iface_index, 0, 0);
    return true;
}

WifiStatus WifiStatusRead(u32 iface_index)
{
    WifiStatus status = {};
    if (iface_index >= kWifiMaxIfaces)
        return status;
    sync::SpinLockGuard guard(g_lock);
    (void)guard;
    status = g_ifaces[iface_index].status;
    status.iface_index = iface_index;
    return status;
}

} // namespace duetos::net
