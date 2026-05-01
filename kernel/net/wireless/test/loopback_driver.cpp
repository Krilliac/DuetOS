#include "net/wireless/test/loopback_driver.h"

#include "core/panic.h"
#include "net/wireless/mlme.h"
#include "net/wireless/wifi_diag.h"

namespace duetos::net::wireless::test
{

namespace
{

void CopyBytes(u8* dst, const u8* src, u32 n)
{
    for (u32 i = 0; i < n; ++i)
        dst[i] = src[i];
}

LoopbackDriver* DriverFromCtx(WirelessDevice* wdev)
{
    return static_cast<LoopbackDriver*>(wdev->ops.drv_ctx);
}

::duetos::core::Result<void> OpUp(WirelessDevice* wdev)
{
    diag::RecordOk(diag::Layer::Driver, "loop-up", wdev->wdev_id, 0, 0);
    return ::duetos::core::Result<void>{};
}

::duetos::core::Result<void> OpDown(WirelessDevice* wdev)
{
    diag::RecordOk(diag::Layer::Driver, "loop-down", wdev->wdev_id, 0, 0);
    return ::duetos::core::Result<void>{};
}

::duetos::core::Result<void> OpScan(WirelessDevice* wdev, const WirelessScanRequest& req)
{
    LoopbackDriver* drv = DriverFromCtx(wdev);
    if (drv == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::BadState};
    ++drv->scan_calls;
    diag::RecordOk(diag::Layer::Driver, "loop-scan", req.dwell_ms_per_channel, req.channel_count, wdev->wdev_id);

    static u8 beacon[256];
    const u32 beacon_len = FakeApBuildBeacon(&drv->ap, beacon, sizeof(beacon));
    if (beacon_len == 0)
        return ::duetos::core::Err{::duetos::core::ErrorCode::IoError};
    WirelessFrameRx rx{};
    rx.frame = beacon;
    rx.frame_len = beacon_len;
    rx.rssi_dbm = -45;
    rx.channel = drv->ap.channel;
    return WirelessDeliverBeacon(wdev, rx);
}

::duetos::core::Result<void> OpAuthenticate(WirelessDevice* wdev, const WirelessAuthRequest& req)
{
    LoopbackDriver* drv = DriverFromCtx(wdev);
    if (drv == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::BadState};
    ++drv->auth_calls;
    diag::RecordOk(diag::Layer::Driver, "loop-auth", req.auth_type, req.timeout_ms, wdev->wdev_id);

    static u8 resp[64];
    const u32 resp_len = FakeApBuildAuthResponse(&drv->ap, wdev->mac, resp, sizeof(resp));
    if (resp_len == 0)
        return ::duetos::core::Err{::duetos::core::ErrorCode::IoError};
    WirelessFrameRx rx{};
    rx.frame = resp;
    rx.frame_len = resp_len;
    rx.rssi_dbm = -45;
    rx.channel = drv->ap.channel;
    return WirelessDeliverMgmt(wdev, rx);
}

::duetos::core::Result<void> OpAssociate(WirelessDevice* wdev, const WirelessAssocRequest& req)
{
    LoopbackDriver* drv = DriverFromCtx(wdev);
    if (drv == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::BadState};
    ++drv->assoc_calls;
    diag::RecordOk(diag::Layer::Driver, "loop-assoc", req.ssid_len, req.rsn_ie_len, wdev->wdev_id);

    static u8 resp[64];
    const u32 resp_len = FakeApBuildAssocResponse(&drv->ap, wdev->mac, resp, sizeof(resp));
    if (resp_len == 0)
        return ::duetos::core::Err{::duetos::core::ErrorCode::IoError};
    WirelessFrameRx rx{};
    rx.frame = resp;
    rx.frame_len = resp_len;
    rx.rssi_dbm = -45;
    rx.channel = drv->ap.channel;
    return WirelessDeliverMgmt(wdev, rx);
}

::duetos::core::Result<void> OpDisconnect(WirelessDevice* wdev, u16 reason)
{
    LoopbackDriver* drv = DriverFromCtx(wdev);
    if (drv == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::BadState};
    ++drv->disconnect_calls;
    diag::RecordOk(diag::Layer::Driver, "loop-disconnect", reason, 0, wdev->wdev_id);
    drv->ap.state = FakeApState::Idle;
    return ::duetos::core::Result<void>{};
}

::duetos::core::Result<void> OpInstallKey(WirelessDevice* wdev, const WirelessKeyInstallRequest& req)
{
    LoopbackDriver* drv = DriverFromCtx(wdev);
    if (drv == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::BadState};
    ++drv->keys_installed;
    diag::RecordOk(diag::Layer::Driver, "loop-install-key", req.key_index, req.key_len, wdev->wdev_id);
    if (req.key_index == 0)
    {
        // Pairwise (TK).
        if (req.key_len > sizeof(drv->sta_pairwise_key))
            return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
        CopyBytes(drv->sta_pairwise_key, req.key, req.key_len);
        drv->sta_pairwise_key_len = req.key_len;
        CopyBytes(drv->sta_pairwise_mac, req.mac, 6);
    }
    else
    {
        // Group key (GTK).
        if (req.key_len > sizeof(drv->sta_group_key))
            return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
        CopyBytes(drv->sta_group_key, req.key, req.key_len);
        drv->sta_group_key_len = req.key_len;
        drv->sta_group_index = req.key_index;
    }
    return ::duetos::core::Result<void>{};
}

::duetos::core::Result<void> OpSendMgmtFrame(WirelessDevice* wdev, const u8* frame, u32 frame_len, u8 channel)
{
    (void)channel;
    LoopbackDriver* drv = DriverFromCtx(wdev);
    if (drv == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::BadState};
    ++drv->mgmt_frames_tx;
    diag::RecordOk(diag::Layer::Driver, "loop-tx-mgmt", frame_len, 0, wdev->wdev_id);
    // The supplicant's MLME doesn't send mgmt frames in the
    // loopback path (auth/assoc are synthesized via ops above).
    // If we get here it's something we don't handle yet — log it
    // and discard.
    (void)frame;
    return ::duetos::core::Result<void>{};
}

::duetos::core::Result<void> OpSendEapolFrame(WirelessDevice* wdev, const u8* frame, u32 frame_len)
{
    LoopbackDriver* drv = DriverFromCtx(wdev);
    if (drv == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::BadState};
    ++drv->eapol_frames_tx;
    diag::RecordOk(diag::Layer::Driver, "loop-tx-eapol", frame_len, 0, wdev->wdev_id);

    if (drv->ap.state == FakeApState::SentM1)
    {
        // Incoming frame is M2 from STA. Process it + build M3.
        static u8 m3[512];
        auto pr = FakeApProcessM2BuildM3(&drv->ap, frame, frame_len, m3, sizeof(m3));
        if (!pr.has_value())
        {
            diag::RecordErr(diag::Layer::Driver, "loop-m2-rx-fail", static_cast<u32>(pr.error()), 0, 0, 0);
            return ::duetos::core::Err{pr.error()};
        }
        // Re-enter the supplicant with M3.
        WirelessFrameRx rx{};
        rx.frame = m3;
        rx.frame_len = pr.value();
        rx.rssi_dbm = -45;
        rx.channel = drv->ap.channel;
        return WirelessDeliverEapol(wdev, rx);
    }
    if (drv->ap.state == FakeApState::GotM2_SentM3)
    {
        // Incoming frame is M4 from STA.
        return FakeApProcessM4(&drv->ap, frame, frame_len);
    }
    diag::RecordErr(diag::Layer::Driver, "loop-tx-eapol-unexpected",
                    static_cast<u32>(::duetos::core::ErrorCode::BadState), static_cast<u64>(drv->ap.state), 0, 0);
    return ::duetos::core::Err{::duetos::core::ErrorCode::BadState};
}

} // namespace

::duetos::core::Result<u32> LoopbackDriverRegister(LoopbackDriver* drv, const char* ssid, const char* passphrase,
                                                   const u8 ap_mac[6], const u8 sta_mac[6], u8 channel)
{
    if (drv == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    *drv = {};
    auto ir = FakeApInit(&drv->ap, ssid, passphrase, ap_mac, channel);
    if (!ir.has_value())
        return ::duetos::core::Err{ir.error()};

    WirelessDevice proto{};
    const char* nm = "wlan-loop";
    for (u32 i = 0; nm[i] != '\0' && i < sizeof(proto.name) - 1; ++i)
        proto.name[i] = nm[i];
    CopyBytes(proto.mac, sta_mac, 6);
    proto.if_type = WirelessIfType::Station;
    proto.ops.drv_ctx = drv;
    proto.ops.Up = OpUp;
    proto.ops.Down = OpDown;
    proto.ops.Scan = OpScan;
    proto.ops.Authenticate = OpAuthenticate;
    proto.ops.Associate = OpAssociate;
    proto.ops.Disconnect = OpDisconnect;
    proto.ops.InstallKey = OpInstallKey;
    proto.ops.SendMgmtFrame = OpSendMgmtFrame;
    proto.ops.SendEapolFrame = OpSendEapolFrame;

    auto rr = WirelessDeviceRegister(proto);
    if (!rr.has_value())
        return ::duetos::core::Err{rr.error()};
    drv->wdev_id = rr.value();
    drv->wdev = WirelessDeviceById(drv->wdev_id);
    diag::RecordOk(diag::Layer::Diag, "loop-register", drv->wdev_id, 0, 0);
    return drv->wdev_id;
}

::duetos::core::Result<void> LoopbackDriverDrive(LoopbackDriver* drv, const char* passphrase)
{
    if (drv == nullptr || drv->wdev == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};

    // Step 1: scan.
    WirelessScanRequest sr{};
    sr.active = true;
    sr.dwell_ms_per_channel = 10; // tiny dwell — loopback returns instantly
    auto scan_r = MlmeScanAndWait(drv->wdev, sr, /*timeout_ticks=*/2);
    if (!scan_r.has_value())
        return scan_r;
    if (drv->wdev->scan_result_count == 0)
    {
        diag::RecordErr(diag::Layer::Diag, "loop-no-scan-results",
                        static_cast<u32>(::duetos::core::ErrorCode::NotFound), 0, 0, 0);
        return ::duetos::core::Err{::duetos::core::ErrorCode::NotFound};
    }

    // Step 2: connect with provided passphrase.
    MlmeConnectRequest cr{};
    for (u8 i = 0; i < drv->ap.ssid_len; ++i)
        cr.ssid[i] = drv->ap.ssid[i];
    cr.ssid[drv->ap.ssid_len] = '\0';
    cr.ssid_len = drv->ap.ssid_len;
    if (passphrase != nullptr)
    {
        for (u32 i = 0; passphrase[i] != '\0' && i < sizeof(cr.passphrase) - 1; ++i)
            cr.passphrase[i] = passphrase[i];
    }
    auto conn_r = MlmeConnect(drv->wdev, cr);
    if (!conn_r.has_value())
        return conn_r;

    // Step 3: AP starts the 4-way handshake by sending M1.
    static u8 m1[512];
    auto m1r = FakeApBuildM1(&drv->ap, drv->wdev->mac, m1, sizeof(m1));
    if (!m1r.has_value())
        return ::duetos::core::Err{m1r.error()};
    WirelessFrameRx rx{};
    rx.frame = m1;
    rx.frame_len = m1r.value();
    rx.rssi_dbm = -45;
    rx.channel = drv->ap.channel;
    auto deliver_r = WirelessDeliverEapol(drv->wdev, rx);
    if (!deliver_r.has_value())
        return deliver_r;
    return ::duetos::core::Result<void>{};
}

void LoopbackDriverReset(LoopbackDriver* drv)
{
    if (drv == nullptr)
        return;
    drv->scan_calls = 0;
    drv->auth_calls = 0;
    drv->assoc_calls = 0;
    drv->disconnect_calls = 0;
    drv->keys_installed = 0;
    drv->mgmt_frames_tx = 0;
    drv->eapol_frames_tx = 0;
    drv->sta_pairwise_key_len = 0;
    drv->sta_group_key_len = 0;
    drv->ap.state = FakeApState::Idle;
    drv->ap.beacons_sent = 0;
    drv->ap.m1_sent = 0;
    drv->ap.m2_received_ok = 0;
    drv->ap.m2_mic_failures = 0;
    drv->ap.m3_sent = 0;
    drv->ap.m4_received_ok = 0;
    drv->ap.m4_mic_failures = 0;
    drv->ap.ptk_valid = false;
    for (u32 i = 0; i < 8; ++i)
        drv->ap.replay_counter[i] = 0;
    if (drv->wdev != nullptr)
    {
        drv->wdev->scan_result_count = 0;
        drv->wdev->scan_completed_tick = 0;
        drv->wdev->scan_started_tick = 0;
        drv->wdev->op_state = WirelessOpState::Idle;
        drv->wdev->fw = {};
    }
}

} // namespace duetos::net::wireless::test
