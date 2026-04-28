#include "net/wifi.h"

#include "diag/cleanroom_trace.h"
#include "log/klog.h"
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

// Tagged with `kLockClassWifi` for lockdep.
constinit sync::SpinLock g_lock = {.locked = 0, .owner_cpu = 0xFFFFFFFFu, .class_id = sync::kLockClassWifi};
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
    KLOG_TRACE_SCOPE("net/wifi", "WifiInit");
    KLOG_INFO_V("net/wifi", "WifiInit: clearing iface table", kWifiMaxIfaces);
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
        KLOG_WARN_V("net/wifi", "WifiRegisterBackend: invalid args (index/ops)", iface_index);
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
    KLOG_INFO_V("net/wifi", "WifiRegisterBackend: backend online for iface", iface_index);
    core::CleanroomTraceRecord("wifi", "register-ok", iface_index, 0, 0);
    return true;
}

bool WifiScan(u32 iface_index, WifiScanResult* out, u32 max_results, u32* out_count)
{
    KLOG_TRACE_V("net/wifi", "WifiScan: iface", iface_index);
    if (out_count != nullptr)
        *out_count = 0;
    if (iface_index >= kWifiMaxIfaces || out == nullptr || max_results == 0)
    {
        KLOG_WARN_2V("net/wifi", "WifiScan: invalid args", "iface", iface_index, "max", max_results);
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
            KLOG_WARN_V("net/wifi", "WifiScan: no backend registered for iface", iface_index);
            core::CleanroomTraceRecord("wifi", "scan-no-backend", iface_index, 0, 0);
            return false;
        }
        ops = s.ops;
    }
    const bool ok = ops.scan(ops.ctx, out, max_results, out_count);
    if (ok)
    {
        KLOG_DEBUG("net/wifi", "WifiScan: backend scan succeeded");
    }
    else
    {
        KLOG_WARN_V("net/wifi", "WifiScan: backend scan failed for iface", iface_index);
    }
    core::CleanroomTraceRecord("wifi", ok ? "scan-ok" : "scan-fail", iface_index, out_count ? *out_count : 0, 0);
    return ok;
}

bool WifiConnect(u32 iface_index, const char* ssid, WifiSecurity security, const char* psk_or_null)
{
    KLOG_INFO_S("net/wifi", "WifiConnect: requested ssid", "ssid", (ssid != nullptr ? ssid : "<null>"));
    if (iface_index >= kWifiMaxIfaces || ssid == nullptr || ssid[0] == '\0')
    {
        KLOG_WARN_V("net/wifi", "WifiConnect: invalid args (iface or ssid)", iface_index);
        core::CleanroomTraceRecord("wifi", "connect-invalid", iface_index, 0, 0);
        return false;
    }
    if (security == WifiSecurity::Wpa2Psk)
    {
        if (psk_or_null == nullptr || psk_or_null[0] == '\0')
        {
            KLOG_WARN("net/wifi", "WifiConnect: WPA2-PSK requested with empty PSK");
            return false;
        }
        u32 psk_len = 0;
        while (psk_or_null[psk_len] != '\0')
            ++psk_len;
        if (psk_len < 8 || psk_len > kWifiPskMaxBytes)
        {
            KLOG_WARN_V("net/wifi", "WifiConnect: PSK length out of range", psk_len);
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
            KLOG_WARN_V("net/wifi", "WifiConnect: no backend for iface", iface_index);
            core::CleanroomTraceRecord("wifi", "connect-no-backend", iface_index, 0, 0);
            return false;
        }
        ops = s.ops;
    }

    if (!ops.connect(ops.ctx, ssid, security, psk_or_null))
    {
        KLOG_ERROR_S("net/wifi", "WifiConnect: backend connect failed", "ssid", ssid);
        core::CleanroomTraceRecord("wifi", "connect-driver-fail", iface_index, static_cast<u64>(security), 0);
        return false;
    }
    KLOG_INFO_S("net/wifi", "WifiConnect: connected", "ssid", ssid);

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
    KLOG_INFO_V("net/wifi", "WifiDisconnect: iface", iface_index);
    if (iface_index >= kWifiMaxIfaces)
    {
        KLOG_WARN_V("net/wifi", "WifiDisconnect: iface index out of range", iface_index);
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
            KLOG_WARN_V("net/wifi", "WifiDisconnect: no backend for iface", iface_index);
            core::CleanroomTraceRecord("wifi", "disconnect-no-backend", iface_index, 0, 0);
            return false;
        }
        ops = s.ops;
    }
    if (!ops.disconnect(ops.ctx))
    {
        KLOG_ERROR_V("net/wifi", "WifiDisconnect: backend disconnect failed", iface_index);
        core::CleanroomTraceRecord("wifi", "disconnect-driver-fail", iface_index, 0, 0);
        return false;
    }
    KLOG_INFO_V("net/wifi", "WifiDisconnect: ok", iface_index);

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
