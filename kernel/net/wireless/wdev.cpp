#include "net/wireless/wdev.h"

#include "core/panic.h"
#include "log/klog.h"
#include "net/wireless/wifi_diag.h"
#include "time/tick.h"

namespace duetos::net::wireless
{

namespace
{

constinit WirelessDevice g_devices[kWdevMaxDevices] = {};
constinit u32 g_count = 0;
constinit u32 g_next_id = 1;

void CopyBytes(u8* dst, const u8* src, u32 n)
{
    for (u32 i = 0; i < n; ++i)
        dst[i] = src[i];
}

bool MacEqual(const u8 a[6], const u8 b[6])
{
    for (u32 i = 0; i < 6; ++i)
        if (a[i] != b[i])
            return false;
    return true;
}

} // namespace

const char* WirelessOpStateName(WirelessOpState s)
{
    switch (s)
    {
    case WirelessOpState::Down:
        return "down";
    case WirelessOpState::Idle:
        return "idle";
    case WirelessOpState::Scanning:
        return "scanning";
    case WirelessOpState::Authenticating:
        return "auth";
    case WirelessOpState::Associating:
        return "assoc";
    case WirelessOpState::Handshaking:
        return "handshake";
    case WirelessOpState::Connected:
        return "connected";
    case WirelessOpState::Disconnecting:
        return "disconnecting";
    case WirelessOpState::Failed:
        return "failed";
    default:
        return "?";
    }
}

::duetos::core::Result<u32> WirelessDeviceRegister(const WirelessDevice& proto)
{
    if (g_count >= kWdevMaxDevices)
    {
        KLOG_ERROR_AV(::duetos::core::LogArea::Wireless, "net/wireless/wdev", "register: device table full, capacity",
                      static_cast<u64>(kWdevMaxDevices));
        diag::RecordErr(diag::Layer::Wdev, "register-full", static_cast<u32>(::duetos::core::ErrorCode::OutOfMemory),
                        kWdevMaxDevices, 0, 0);
        return ::duetos::core::Err{::duetos::core::ErrorCode::OutOfMemory};
    }
    g_devices[g_count] = proto;
    g_devices[g_count].wdev_id = g_next_id++;
    g_devices[g_count].op_state = WirelessOpState::Down;
    KLOG_INFO_AS(::duetos::core::LogArea::Wireless, "net/wireless/wdev", "device registered", "name", proto.name);
    diag::RecordOk(diag::Layer::Wdev, "register", g_devices[g_count].wdev_id, 0, 0, proto.name);
    return g_devices[g_count++].wdev_id;
}

WirelessDevice* WirelessDeviceById(u32 id)
{
    for (u32 i = 0; i < g_count; ++i)
        if (g_devices[i].wdev_id == id)
            return &g_devices[i];
    return nullptr;
}

u32 WirelessDeviceCount()
{
    return g_count;
}

WirelessDevice* WirelessDeviceAt(u32 index)
{
    if (index >= g_count)
        return nullptr;
    return &g_devices[index];
}

void WirelessSetState(WirelessDevice* wdev, WirelessOpState s)
{
    if (wdev == nullptr)
    {
        KLOG_WARN_A(::duetos::core::LogArea::Wireless, "net/wireless/wdev", "SetState: null wdev");
        return;
    }
    const auto prev = wdev->op_state;
    wdev->op_state = s;
    if (prev != s)
    {
        KLOG_INFO_A2V(::duetos::core::LogArea::Wireless, "net/wireless/wdev", "wdev op_state change", "from",
                      static_cast<u64>(prev), "to", static_cast<u64>(s));
    }
    diag::RecordOk(diag::Layer::Wdev, "state-change", static_cast<u64>(prev), static_cast<u64>(s), wdev->wdev_id);
}

::duetos::core::Result<void> WirelessDeliverBeacon(WirelessDevice* wdev, const WirelessFrameRx& f)
{
    if (wdev == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    BeaconParsed parsed{};
    auto pr = BeaconParse(f.frame, f.frame_len, &parsed);
    if (!pr.has_value())
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Wireless, "net/wireless/wdev", "beacon parse failed; frame_len",
                     static_cast<u64>(f.frame_len));
        diag::RecordErr(diag::Layer::Rx, "beacon-parse", static_cast<u32>(pr.error()), f.frame_len, 0, 0);
        return pr;
    }

    // Dedupe by BSSID — overwrite an existing entry if present.
    for (u32 i = 0; i < wdev->scan_result_count; ++i)
    {
        if (MacEqual(wdev->scan_results[i].bssid, parsed.bssid))
        {
            wdev->scan_results[i] = parsed;
            diag::RecordOk(diag::Layer::Rx, "beacon-dup", parsed.channel, i, wdev->wdev_id, parsed.ssid);
            return ::duetos::core::Result<void>{};
        }
    }
    if (wdev->scan_result_count < kWdevMaxScanResults)
    {
        wdev->scan_results[wdev->scan_result_count++] = parsed;
        KLOG_TRACE_AV(::duetos::core::LogArea::Wireless, "net/wireless/wdev", "scan-result added; channel",
                      static_cast<u64>(parsed.channel));
        diag::RecordOk(diag::Layer::Rx, "beacon-new", parsed.channel, wdev->scan_result_count - 1, wdev->wdev_id,
                       parsed.ssid);
    }
    else
    {
        KLOG_ONCE_WARN("net/wireless/wdev", "scan-result table full — dropping beacons");
        diag::RecordErr(diag::Layer::Rx, "beacon-full", static_cast<u32>(::duetos::core::ErrorCode::OutOfMemory),
                        kWdevMaxScanResults, 0, 0);
    }
    wdev->scan_completed_tick = duetos::time::TickCount();
    return ::duetos::core::Result<void>{};
}

::duetos::core::Result<void> WirelessDeliverMgmt(WirelessDevice* wdev, const WirelessFrameRx& f)
{
    if (wdev == nullptr || f.frame == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    diag::RecordOk(diag::Layer::Mlme, "mgmt-rx", f.frame_len, f.channel, wdev->wdev_id);
    // The MLME state machine reads from a deferred queue. v0
    // wires the dispatcher into mlme.cpp; this delivery point
    // just logs.
    return ::duetos::core::Result<void>{};
}

::duetos::core::Result<void> WirelessDeliverEapol(WirelessDevice* wdev, const WirelessFrameRx& f)
{
    if (wdev == nullptr || f.frame == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    diag::RecordOk(diag::Layer::Eapol, "eapol-rx", f.frame_len, f.channel, wdev->wdev_id);
    const FourWayState state_before = wdev->fw.state;
    auto pr = FourWayProcessIncoming(wdev->fw, f.frame, f.frame_len);
    if (!pr.has_value())
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Wireless, "net/wireless/wdev", "EAPOL incoming process failed",
                     static_cast<u64>(pr.error()));
        diag::RecordErr(diag::Layer::Eapol, "eapol-rx-err", static_cast<u32>(pr.error()), 0, 0, 0);
        return pr;
    }

    // After processing M1 (state advanced to AwaitingM3) the
    // supplicant must build + transmit M2 to keep the handshake
    // moving. Without this, the AP retransmits M1 forever and
    // the handshake stalls.
    if (state_before == FourWayState::AwaitingM1 && wdev->fw.state == FourWayState::AwaitingM3 &&
        wdev->ops.SendEapolFrame != nullptr)
    {
        u8 m2[512];
        u32 m2_len = 0;
        // Caller (MLME) is expected to have stashed an RSN IE for
        // us to include. v0 builds the default WPA2-PSK RSN IE.
        const u8 rsn[22] = {0x30, 0x14, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00, 0x00,
                            0x0F, 0xAC, 0x04, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x02, 0x00, 0x00};
        auto br = FourWayBuildOutgoing(wdev->fw, rsn, sizeof(rsn), m2, sizeof(m2), &m2_len);
        if (!br.has_value())
        {
            KLOG_ERROR_AV(::duetos::core::LogArea::Wireless, "net/wireless/wdev", "M2 build failed",
                          static_cast<u64>(br.error()));
            diag::RecordErr(diag::Layer::Eapol, "m2-build-err", static_cast<u32>(br.error()), 0, 0, 0);
            return br;
        }
        KLOG_INFO_AV(::duetos::core::LogArea::Wireless, "net/wireless/wdev", "TX M2; len", static_cast<u64>(m2_len));
        diag::RecordOk(diag::Layer::Eapol, "m2-tx", m2_len, 0, wdev->wdev_id);
        auto sr = wdev->ops.SendEapolFrame(wdev, m2, m2_len);
        if (!sr.has_value())
        {
            // A wrong PSK fails the AP-side M2 MIC check — a normal
            // authentication outcome, not a system error. The
            // returned Err is the real notification channel; keep
            // this at WARN so a mistyped Wi-Fi password doesn't
            // flood the log at ERROR.
            KLOG_WARN_AV(::duetos::core::LogArea::Wireless, "net/wireless/wdev", "M2 TX failed (bad PSK?)",
                         static_cast<u64>(sr.error()));
            diag::RecordErr(diag::Layer::Eapol, "m2-tx-err", static_cast<u32>(sr.error()), 0, 0, 0);
            return sr;
        }
    }

    // After M3 the supplicant has the PTK. Install the keys via
    // the driver before we ack M4 — installing AFTER M4 can lose
    // the very first encrypted frame on some chipsets.
    if (wdev->fw.state == FourWayState::AwaitingM4Ack)
    {
        if (wdev->ops.InstallKey != nullptr && wdev->fw.ptk_valid)
        {
            WirelessKeyInstallRequest k{};
            CopyBytes(k.mac, wdev->connected_bssid, 6);
            CopyBytes(k.key, FourWayTk(wdev->fw), kTkBytes);
            k.key_len = kTkBytes;
            k.key_index = 0;
            k.cipher = 0x000FAC04u; // CCMP-128 packed
            k.tx_capable = true;
            auto kr = wdev->ops.InstallKey(wdev, k);
            if (!kr.has_value())
            {
                KLOG_ERROR_AV(::duetos::core::LogArea::Wireless, "net/wireless/wdev", "TK install failed",
                              static_cast<u64>(kr.error()));
                diag::RecordErr(diag::Layer::KeyMgmt, "tk-install-err", static_cast<u32>(kr.error()), 0, 0, 0);
                WirelessSetState(wdev, WirelessOpState::Failed);
                return kr;
            }
            KLOG_INFO_A(::duetos::core::LogArea::Wireless, "net/wireless/wdev", "pairwise TK installed");
            diag::RecordOk(diag::Layer::KeyMgmt, "tk-installed", k.key_len, 0, wdev->wdev_id);
        }
        if (wdev->fw.gtk_valid && wdev->ops.InstallKey != nullptr)
        {
            WirelessKeyInstallRequest gk{};
            for (u32 i = 0; i < 6; ++i)
                gk.mac[i] = 0xFF;
            CopyBytes(gk.key, wdev->fw.gtk, wdev->fw.gtk_len);
            gk.key_len = wdev->fw.gtk_len;
            gk.key_index = wdev->fw.gtk_index;
            gk.cipher = 0x000FAC04u;
            gk.tx_capable = false;
            auto kr = wdev->ops.InstallKey(wdev, gk);
            if (!kr.has_value())
            {
                KLOG_WARN_AV(::duetos::core::LogArea::Wireless, "net/wireless/wdev", "GTK install failed",
                             static_cast<u64>(kr.error()));
                diag::RecordErr(diag::Layer::KeyMgmt, "gtk-install-err", static_cast<u32>(kr.error()), 0, 0, 0);
            }
            else
            {
                KLOG_INFO_A(::duetos::core::LogArea::Wireless, "net/wireless/wdev", "group GTK installed");
                diag::RecordOk(diag::Layer::KeyMgmt, "gtk-installed", gk.key_len, gk.key_index, wdev->wdev_id);
            }
        }
    }
    // After processing M3 + installing keys, build and TX M4 to
    // ack the handshake to the AP. Then transition to Established
    // and Connected.
    if (state_before == FourWayState::AwaitingM3 && wdev->fw.state == FourWayState::AwaitingM4Ack &&
        wdev->ops.SendEapolFrame != nullptr)
    {
        u8 m4[256];
        u32 m4_len = 0;
        auto br = FourWayBuildOutgoing(wdev->fw, nullptr, 0, m4, sizeof(m4), &m4_len);
        if (!br.has_value())
        {
            KLOG_ERROR_AV(::duetos::core::LogArea::Wireless, "net/wireless/wdev", "M4 build failed",
                          static_cast<u64>(br.error()));
            diag::RecordErr(diag::Layer::Eapol, "m4-build-err", static_cast<u32>(br.error()), 0, 0, 0);
            return br;
        }
        KLOG_INFO_AV(::duetos::core::LogArea::Wireless, "net/wireless/wdev", "TX M4; len", static_cast<u64>(m4_len));
        diag::RecordOk(diag::Layer::Eapol, "m4-tx", m4_len, 0, wdev->wdev_id);
        auto sr = wdev->ops.SendEapolFrame(wdev, m4, m4_len);
        if (!sr.has_value())
        {
            KLOG_ERROR_AV(::duetos::core::LogArea::Wireless, "net/wireless/wdev", "M4 TX failed",
                          static_cast<u64>(sr.error()));
            diag::RecordErr(diag::Layer::Eapol, "m4-tx-err", static_cast<u32>(sr.error()), 0, 0, 0);
            return sr;
        }
        // Transition the supplicant's view to Established. The
        // 4-way state machine itself only flips to Established
        // when the AP-side ack arrives over the air; in v0 the
        // STA decides locally that M4 having been TX'd is enough
        // because there's no explicit ack signal back from the AP.
        wdev->fw.state = FourWayState::Established;
        WirelessSetState(wdev, WirelessOpState::Connected);
        KLOG_INFO_A(::duetos::core::LogArea::Wireless, "net/wireless/wdev",
                    "4-way handshake established — link CONNECTED");
    }
    if (wdev->fw.state == FourWayState::Established)
        WirelessSetState(wdev, WirelessOpState::Connected);
    return ::duetos::core::Result<void>{};
}

void WdevSelfTest()
{
    KLOG_TRACE_SCOPE("net/wireless/wdev", "WdevSelfTest");
    KLOG_INFO_A(::duetos::core::LogArea::Wireless, "net/wireless/wdev",
                "self-test: register + deliver-beacon + dedupe");
    // Register a fake device, deliver a synthetic beacon, verify
    // it lands in the scan-results table.
    WirelessDevice proto{};
    const char* nm = "wlan-test";
    for (u32 i = 0; nm[i] != '\0' && i < sizeof(proto.name) - 1; ++i)
        proto.name[i] = nm[i];
    proto.if_type = WirelessIfType::Station;
    proto.mac[5] = 0x42;
    auto rr = WirelessDeviceRegister(proto);
    KASSERT(rr.has_value(), "net/wireless/wdev", "register failed");
    const u32 id = rr.value();
    WirelessDevice* wdev = WirelessDeviceById(id);
    KASSERT(wdev != nullptr, "net/wireless/wdev", "lookup by id returned null");

    // Build a minimal beacon and deliver.
    static u8 frame[64] = {};
    // FC: Mgmt + Beacon
    const u16 fc = (static_cast<u16>(FrameType::Management) << kFcTypeShift) |
                   (static_cast<u16>(MgmtSubtype::Beacon) << kFcSubtypeShift);
    frame[0] = static_cast<u8>(fc & 0xFFu);
    frame[1] = static_cast<u8>((fc >> 8) & 0xFFu);
    // BSSID at offset 16
    for (u32 i = 0; i < 6; ++i)
        frame[16 + i] = static_cast<u8>(0xAA + i);
    // TS, BcnInt=100, Cap=0x01
    frame[24 + 8] = 100;
    frame[24 + 8 + 1] = 0;
    frame[24 + 8 + 2] = 0x01;
    frame[24 + 8 + 3] = 0x00;
    // SSID IE (id=0, len=2, "hi")
    frame[24 + 12] = 0;
    frame[24 + 13] = 2;
    frame[24 + 14] = 'h';
    frame[24 + 15] = 'i';
    const u32 frame_len = 24 + 12 + 4;

    WirelessFrameRx rxf{};
    rxf.frame = frame;
    rxf.frame_len = frame_len;
    rxf.rssi_dbm = -60;
    rxf.channel = 6;

    auto db = WirelessDeliverBeacon(wdev, rxf);
    KASSERT(db.has_value(), "net/wireless/wdev", "deliver-beacon failed");
    KASSERT(wdev->scan_result_count == 1, "net/wireless/wdev", "scan_result_count wrong");
    KASSERT(wdev->scan_results[0].bssid[0] == 0xAA, "net/wireless/wdev", "BSSID not captured");

    // Re-deliver same BSSID — should dedupe (count stays 1).
    auto db2 = WirelessDeliverBeacon(wdev, rxf);
    KASSERT(db2.has_value(), "net/wireless/wdev", "second deliver-beacon failed");
    KASSERT(wdev->scan_result_count == 1, "net/wireless/wdev", "dedupe failed");
    KLOG_INFO_A(::duetos::core::LogArea::Wireless, "net/wireless/wdev",
                "self-test OK (register + beacon delivery + dedupe verified)");
}

} // namespace duetos::net::wireless
