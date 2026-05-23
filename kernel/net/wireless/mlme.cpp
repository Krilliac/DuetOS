#include "net/wireless/mlme.h"

#include "core/panic.h"
#include "log/klog.h"
#include "crypto/pbkdf2.h"
#include "net/wireless/wifi_diag.h"
#include "sched/sched.h"
#include "time/tick.h"

namespace duetos::net::wireless
{

namespace
{

void WriteLe16(u8* buf, u32 off, u16 v)
{
    buf[off] = static_cast<u8>(v & 0xFFu);
    buf[off + 1] = static_cast<u8>((v >> 8) & 0xFFu);
}

void CopyBytes(u8* dst, const u8* src, u32 n)
{
    for (u32 i = 0; i < n; ++i)
        dst[i] = src[i];
}

bool MacIsZero(const u8 m[6])
{
    for (u32 i = 0; i < 6; ++i)
        if (m[i] != 0)
            return false;
    return true;
}

bool MacEqual(const u8 a[6], const u8 b[6])
{
    for (u32 i = 0; i < 6; ++i)
        if (a[i] != b[i])
            return false;
    return true;
}

u32 BuildMgmtMacHeader(u8 subtype, const u8 da[6], const u8 sa[6], const u8 bssid[6], u8* out)
{
    const u16 fc =
        (static_cast<u16>(FrameType::Management) << kFcTypeShift) | (static_cast<u16>(subtype) << kFcSubtypeShift);
    WriteLe16(out, 0, fc);
    WriteLe16(out, 2, 0); // duration
    CopyBytes(out + 4, da, 6);
    CopyBytes(out + 10, sa, 6);
    CopyBytes(out + 16, bssid, 6);
    WriteLe16(out, 22, 0); // sequence
    return 24;
}

bool BeaconMatchesSsid(const BeaconParsed& b, const char* ssid, u8 ssid_len)
{
    if (b.ssid_length != ssid_len)
        return false;
    for (u8 i = 0; i < ssid_len; ++i)
        if (b.ssid[i] != ssid[i])
            return false;
    return true;
}

} // namespace

u32 MlmeBuildDefaultRsnIe(u8* out, u32 cap)
{
    if (out == nullptr || cap < 22)
        return 0;
    u32 o = 0;
    out[o++] = kIeRsn;
    out[o++] = 20; // body length
    // Version 1.
    out[o++] = 0x01;
    out[o++] = 0x00;
    // Group cipher: CCMP-128.
    out[o++] = 0x00;
    out[o++] = 0x0F;
    out[o++] = 0xAC;
    out[o++] = kCipherCcmp128;
    // Pairwise count = 1.
    out[o++] = 0x01;
    out[o++] = 0x00;
    out[o++] = 0x00;
    out[o++] = 0x0F;
    out[o++] = 0xAC;
    out[o++] = kCipherCcmp128;
    // AKM count = 1, PSK.
    out[o++] = 0x01;
    out[o++] = 0x00;
    out[o++] = 0x00;
    out[o++] = 0x0F;
    out[o++] = 0xAC;
    out[o++] = kAkmPsk;
    // RSN capabilities = 0.
    out[o++] = 0x00;
    out[o++] = 0x00;
    return o;
}

::duetos::core::Result<u32> MlmeBuildAuthOpenFrame(const u8 sta_mac[6], const u8 ap_mac[6], u8* out, u32 cap)
{
    if (out == nullptr)
    {
        KLOG_WARN_A(::duetos::core::LogArea::Wireless, "net/wireless/mlme", "BuildAuthOpenFrame: null out buffer");
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    }
    if (cap < kMlmeAuthFrameMaxBytes)
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Wireless, "net/wireless/mlme",
                     "BuildAuthOpenFrame: buffer too small, cap=", static_cast<u64>(cap));
        return ::duetos::core::Err{::duetos::core::ErrorCode::BufferTooSmall};
    }
    u32 o = BuildMgmtMacHeader(static_cast<u8>(MgmtSubtype::Authentication), ap_mac, sta_mac, ap_mac, out);
    // Auth body: u16 algo (0=open), u16 seq (1), u16 status (0).
    WriteLe16(out, o, 0);
    o += 2;
    WriteLe16(out, o, 1);
    o += 2;
    WriteLe16(out, o, kStatusSuccess);
    o += 2;
    diag::RecordOk(diag::Layer::Mlme, "auth-build", o, 0, 0);
    return o;
}

::duetos::core::Result<u32> MlmeBuildAssocReqFrame(const u8 sta_mac[6], const u8 ap_mac[6], const char* ssid,
                                                   u8 ssid_len, const u8 supp_rates[8], u8 supp_rates_count,
                                                   const u8* rsn_ie, u32 rsn_ie_len, u8* out, u32 cap)
{
    if (out == nullptr || ssid == nullptr || ssid_len > kSsidMaxBytes || rsn_ie_len > 256)
    {
        KLOG_WARN_2V("net/wireless/mlme", "BuildAssocReqFrame: invalid args", "ssid_len", static_cast<u64>(ssid_len),
                     "rsn_ie_len", static_cast<u64>(rsn_ie_len));
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    }
    if (cap < 24 + 4 + 2 + ssid_len + 2 + supp_rates_count + rsn_ie_len)
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Wireless, "net/wireless/mlme",
                     "BuildAssocReqFrame: buffer too small, cap=", static_cast<u64>(cap));
        return ::duetos::core::Err{::duetos::core::ErrorCode::BufferTooSmall};
    }

    u32 o = BuildMgmtMacHeader(static_cast<u8>(MgmtSubtype::AssocRequest), ap_mac, sta_mac, ap_mac, out);
    // Capability info: ESS + Privacy + ShortPreamble + ShortSlotTime.
    WriteLe16(out, o, kCapEss | kCapPrivacy | kCapShortPreamble | kCapShortSlotTime);
    o += 2;
    // Listen interval (10 beacons typical).
    WriteLe16(out, o, 10);
    o += 2;
    // SSID IE.
    out[o++] = kIeSsid;
    out[o++] = ssid_len;
    for (u8 i = 0; i < ssid_len; ++i)
        out[o++] = static_cast<u8>(ssid[i]);
    // Supported rates IE.
    out[o++] = kIeSupportedRates;
    out[o++] = supp_rates_count;
    for (u8 i = 0; i < supp_rates_count; ++i)
        out[o++] = supp_rates[i];
    // RSN IE if provided.
    if (rsn_ie != nullptr && rsn_ie_len > 0)
    {
        for (u32 i = 0; i < rsn_ie_len; ++i)
            out[o++] = rsn_ie[i];
    }
    diag::RecordOk(diag::Layer::Mlme, "assoc-build", o, ssid_len, rsn_ie_len);
    return o;
}

::duetos::core::Result<u32> MlmeBuildDeauthFrame(const u8 sta_mac[6], const u8 ap_mac[6], u16 reason_code, u8* out,
                                                 u32 cap)
{
    if (out == nullptr || cap < 24 + 2)
    {
        KLOG_WARN_A(::duetos::core::LogArea::Wireless, "net/wireless/mlme",
                    "BuildDeauthFrame: bad args or buffer too small");
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    }
    u32 o = BuildMgmtMacHeader(static_cast<u8>(MgmtSubtype::Deauthentication), ap_mac, sta_mac, ap_mac, out);
    WriteLe16(out, o, reason_code);
    o += 2;
    diag::RecordOk(diag::Layer::Mlme, "deauth-build", o, reason_code, 0);
    return o;
}

::duetos::core::Result<void> MlmeScanAndWait(WirelessDevice* wdev, const WirelessScanRequest& req, u32 timeout_ticks)
{
    KLOG_TRACE_SCOPE("net/wireless/mlme", "MlmeScanAndWait");
    if (wdev == nullptr || wdev->ops.Scan == nullptr)
    {
        KLOG_WARN_A(::duetos::core::LogArea::Wireless, "net/wireless/mlme", "ScanAndWait: wdev or ops.Scan is null");
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    }
    KLOG_INFO_A2V(::duetos::core::LogArea::Wireless, "net/wireless/mlme", "scan starting", "channels",
                  static_cast<u64>(req.channel_count), "dwell_ms", static_cast<u64>(req.dwell_ms_per_channel));
    diag::RecordOk(diag::Layer::Mlme, "scan-start", req.channel_count, req.dwell_ms_per_channel, wdev->wdev_id);
    WirelessSetState(wdev, WirelessOpState::Scanning);
    wdev->scan_result_count = 0;
    wdev->scan_started_tick = duetos::time::TickCount();
    auto sr = wdev->ops.Scan(wdev, req);
    if (!sr.has_value())
    {
        KLOG_ERROR_AV(::duetos::core::LogArea::Wireless, "net/wireless/mlme", "scan: driver Scan op returned error",
                      static_cast<u64>(sr.error()));
        diag::RecordErr(diag::Layer::Mlme, "scan-issue-err", static_cast<u32>(sr.error()), 0, 0, 0);
        WirelessSetState(wdev, WirelessOpState::Failed);
        return sr;
    }

    // Wait for results. v0 polls TickCount; production should wait
    // on a wakeup event from the driver. Yield each iteration so
    // the calling task doesn't hog the CPU during the wait window
    // — without this, the spin keeps the same TID on the runqueue
    // and the soft-lockup detector eventually trips when other
    // boot-time work doesn't preempt naturally. The completion
    // check uses `>=` so a synchronous driver that finishes inside
    // the same tick as scan_started_tick still breaks the loop.
    const u64 deadline = duetos::time::TickCount() + timeout_ticks;
    while (duetos::time::TickCount() < deadline)
    {
        if (wdev->scan_completed_tick >= wdev->scan_started_tick && wdev->scan_result_count > 0)
            break;
        duetos::sched::SchedYield();
    }
    KLOG_INFO_AV(::duetos::core::LogArea::Wireless, "net/wireless/mlme", "scan complete; results",
                 static_cast<u64>(wdev->scan_result_count));
    diag::RecordOk(diag::Layer::Mlme, "scan-done", wdev->scan_result_count, 0, wdev->wdev_id);
    WirelessSetState(wdev, WirelessOpState::Idle);
    return ::duetos::core::Result<void>{};
}

::duetos::core::Result<void> MlmeConnect(WirelessDevice* wdev, const MlmeConnectRequest& req)
{
    KLOG_TRACE_SCOPE("net/wireless/mlme", "MlmeConnect");
    if (wdev == nullptr)
    {
        KLOG_WARN_A(::duetos::core::LogArea::Wireless, "net/wireless/mlme", "Connect: null wdev");
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    }
    KLOG_INFO_AS(::duetos::core::LogArea::Wireless, "net/wireless/mlme", "connect starting", "ssid", req.ssid);
    diag::RecordOk(diag::Layer::Mlme, "connect-start", req.ssid_len, req.desired_channel, wdev->wdev_id, req.ssid);

    // Pick a target BSS.
    BeaconParsed* target = nullptr;
    for (u32 i = 0; i < wdev->scan_result_count; ++i)
    {
        if (!BeaconMatchesSsid(wdev->scan_results[i], req.ssid, req.ssid_len))
            continue;
        if (!MacIsZero(req.desired_bssid) && !MacEqual(wdev->scan_results[i].bssid, req.desired_bssid))
            continue;
        target = &wdev->scan_results[i];
        break;
    }
    if (target == nullptr)
    {
        KLOG_WARN_AS(::duetos::core::LogArea::Wireless, "net/wireless/mlme", "connect: target SSID not in scan results",
                     "ssid", req.ssid);
        diag::RecordErr(diag::Layer::Mlme, "connect-no-bss", static_cast<u32>(::duetos::core::ErrorCode::NotFound),
                        req.ssid_len, 0, 0, req.ssid);
        return ::duetos::core::Err{::duetos::core::ErrorCode::NotFound};
    }

    // Derive PMK from passphrase + SSID.
    u8 pmk[32];
    bool psk_mode = false;
    if (req.passphrase[0] != '\0' &&
        (target->security == WirelessSecurity::Wpa2 || target->security == WirelessSecurity::Wpa))
    {
        duetos::crypto::WpaPmkDerive(req.passphrase, req.ssid, req.ssid_len, pmk);
        psk_mode = true;
        diag::RecordOk(diag::Layer::Mlme, "pmk-derived", req.ssid_len, 0, wdev->wdev_id);
    }
    else if (target->security != WirelessSecurity::Open)
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Wireless, "net/wireless/mlme",
                     "connect: secured network with empty passphrase, security=", static_cast<u64>(target->security));
        diag::RecordErr(diag::Layer::Mlme, "connect-no-psk",
                        static_cast<u32>(::duetos::core::ErrorCode::InvalidArgument),
                        static_cast<u64>(target->security), 0, 0);
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    }

    // Authenticate.
    WirelessSetState(wdev, WirelessOpState::Authenticating);
    if (wdev->ops.Authenticate != nullptr)
    {
        WirelessAuthRequest ar{};
        CopyBytes(ar.bssid, target->bssid, 6);
        ar.channel = target->channel;
        ar.auth_type = 0; // open
        ar.timeout_ms = 1000;
        auto r = wdev->ops.Authenticate(wdev, ar);
        if (!r.has_value())
        {
            KLOG_ERROR_AV(::duetos::core::LogArea::Wireless, "net/wireless/mlme", "Authenticate failed",
                          static_cast<u64>(r.error()));
            diag::RecordErr(diag::Layer::Mlme, "auth-issue-err", static_cast<u32>(r.error()), 0, 0, 0);
            WirelessSetState(wdev, WirelessOpState::Failed);
            return r;
        }
    }

    // Associate.
    WirelessSetState(wdev, WirelessOpState::Associating);
    if (wdev->ops.Associate != nullptr)
    {
        WirelessAssocRequest as{};
        CopyBytes(as.bssid, target->bssid, 6);
        as.ssid_len = req.ssid_len;
        for (u8 i = 0; i < req.ssid_len; ++i)
            as.ssid[i] = req.ssid[i];
        as.ssid[req.ssid_len] = '\0';
        as.channel = target->channel;
        if (psk_mode)
            as.rsn_ie_len = MlmeBuildDefaultRsnIe(as.rsn_ie, sizeof(as.rsn_ie));
        as.timeout_ms = 1000;
        auto r = wdev->ops.Associate(wdev, as);
        if (!r.has_value())
        {
            KLOG_ERROR_AV(::duetos::core::LogArea::Wireless, "net/wireless/mlme", "Associate failed",
                          static_cast<u64>(r.error()));
            diag::RecordErr(diag::Layer::Mlme, "assoc-issue-err", static_cast<u32>(r.error()), 0, 0, 0);
            WirelessSetState(wdev, WirelessOpState::Failed);
            return r;
        }
    }

    // Initialize 4-way handshake context. Real flow waits for M1
    // from AP; here we just prepare the supplicant side.
    if (psk_mode)
    {
        FourWayInit(wdev->fw, pmk, wdev->mac, target->bssid, /*sha256=*/false, /*aes_cmac=*/false);
        WirelessSetState(wdev, WirelessOpState::Handshaking);
        KLOG_INFO_A(::duetos::core::LogArea::Wireless, "net/wireless/mlme",
                    "PSK mode — 4-way handshake context initialized");
    }
    else
    {
        WirelessSetState(wdev, WirelessOpState::Connected);
        CopyBytes(wdev->connected_bssid, target->bssid, 6);
        wdev->connected_ssid_len = req.ssid_len;
        for (u8 i = 0; i < req.ssid_len; ++i)
            wdev->connected_ssid[i] = req.ssid[i];
        wdev->connected_ssid[req.ssid_len] = '\0';
        wdev->connected_security = WirelessSecurity::Open;
        KLOG_INFO_AS(::duetos::core::LogArea::Wireless, "net/wireless/mlme", "open network — connected", "ssid",
                     req.ssid);
    }
    diag::RecordOk(diag::Layer::Mlme, "connect-handoff", 0, 0, wdev->wdev_id);
    return ::duetos::core::Result<void>{};
}

::duetos::core::Result<void> MlmeDisconnect(WirelessDevice* wdev, u16 reason)
{
    if (wdev == nullptr)
    {
        KLOG_WARN_A(::duetos::core::LogArea::Wireless, "net/wireless/mlme", "Disconnect: null wdev");
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    }
    KLOG_INFO_AV(::duetos::core::LogArea::Wireless, "net/wireless/mlme", "disconnecting; reason",
                 static_cast<u64>(reason));
    diag::RecordOk(diag::Layer::Mlme, "disconnect", reason, 0, wdev->wdev_id);
    WirelessSetState(wdev, WirelessOpState::Disconnecting);
    if (wdev->ops.Disconnect != nullptr)
        wdev->ops.Disconnect(wdev, reason);
    WirelessSetState(wdev, WirelessOpState::Idle);
    return ::duetos::core::Result<void>{};
}

void MlmeSelfTest()
{
    KLOG_TRACE_SCOPE("net/wireless/mlme", "MlmeSelfTest");
    KLOG_INFO_A(::duetos::core::LogArea::Wireless, "net/wireless/mlme",
                "self-test: auth/assoc/deauth frame builders + RSN IE");
    // Build the three frame types into a static buffer; assert
    // header offsets + IE layout.
    const u8 sta[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    const u8 ap[6] = {0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE};

    {
        u8 buf[64] = {};
        auto r = MlmeBuildAuthOpenFrame(sta, ap, buf, sizeof(buf));
        KASSERT(r.has_value() && r.value() == 30, "net/wireless/mlme", "auth frame bad length");
        // FC type = Mgmt (0), subtype = Authentication (11).
        const u16 fc = static_cast<u16>(buf[0]) | (static_cast<u16>(buf[1]) << 8);
        KASSERT(FcType(fc) == FrameType::Management, "net/wireless/mlme", "auth FC type wrong");
        KASSERT(FcSubtype(fc) == static_cast<u8>(MgmtSubtype::Authentication), "net/wireless/mlme",
                "auth FC subtype wrong");
        // Algo + seq + status.
        KASSERT(buf[24] == 0 && buf[25] == 0, "net/wireless/mlme", "auth algo not Open");
        KASSERT(buf[26] == 1 && buf[27] == 0, "net/wireless/mlme", "auth seq != 1");
        KASSERT(buf[28] == 0 && buf[29] == 0, "net/wireless/mlme", "auth status != Success");
    }

    {
        u8 rsn[32];
        const u32 rsn_len = MlmeBuildDefaultRsnIe(rsn, sizeof(rsn));
        KASSERT(rsn_len == 22, "net/wireless/mlme", "default RSN IE wrong length");
        KASSERT(rsn[0] == kIeRsn, "net/wireless/mlme", "RSN IE id wrong");
        KASSERT(rsn[1] == 20, "net/wireless/mlme", "RSN IE inner length wrong");
        KASSERT(rsn[7] == kCipherCcmp128, "net/wireless/mlme", "RSN group cipher != CCMP-128");

        const u8 rates[4] = {0x82, 0x84, 0x8B, 0x96};
        u8 buf[256] = {};
        const char* ssid = "TestNet";
        auto r = MlmeBuildAssocReqFrame(sta, ap, ssid, 7, rates, 4, rsn, rsn_len, buf, sizeof(buf));
        KASSERT(r.has_value(), "net/wireless/mlme", "assoc-req build failed");
        // 24 (hdr) + 2 (cap) + 2 (listen) + 2+7 (ssid) + 2+4 (rates) + 22 (rsn) = 65.
        KASSERT(r.value() == 65, "net/wireless/mlme", "assoc-req unexpected length");
        KASSERT(buf[28] == kIeSsid && buf[29] == 7, "net/wireless/mlme", "assoc SSID IE wrong");
    }

    {
        u8 buf[32] = {};
        auto r = MlmeBuildDeauthFrame(sta, ap, kReasonDeauthLeaving, buf, sizeof(buf));
        KASSERT(r.has_value() && r.value() == 26, "net/wireless/mlme", "deauth frame bad length");
        KASSERT(buf[24] == kReasonDeauthLeaving && buf[25] == 0, "net/wireless/mlme", "deauth reason wrong");
    }
    KLOG_INFO_A(::duetos::core::LogArea::Wireless, "net/wireless/mlme",
                "self-test OK (auth/assoc/deauth + RSN IE verified)");
}

} // namespace duetos::net::wireless
