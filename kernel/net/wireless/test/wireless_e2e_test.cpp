#include "net/wireless/test/wireless_e2e_test.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "net/wireless/eapol.h"
#include "net/wireless/test/fake_ap.h"
#include "net/wireless/test/loopback_driver.h"
#include "net/wireless/wdev.h"
#include "net/wireless/wifi_diag.h"

namespace duetos::net::wireless::test
{

namespace
{

bool BytesEqual(const u8* a, const u8* b, u32 n)
{
    for (u32 i = 0; i < n; ++i)
        if (a[i] != b[i])
            return false;
    return true;
}

void RunSuccessCase()
{
    static LoopbackDriver drv = {};
    const u8 ap_mac[6] = {0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    const u8 sta_mac[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    auto rr = LoopbackDriverRegister(&drv, "DuetOS-Loopback", "ThisIsAPassword", ap_mac, sta_mac, /*channel=*/6);
    KASSERT(rr.has_value(), "net/wireless/test", "loopback register failed");

    auto dr = LoopbackDriverDrive(&drv, "ThisIsAPassword");
    KASSERT(dr.has_value(), "net/wireless/test", "loopback drive failed (good PSK)");
    KASSERT(drv.wdev->op_state == WirelessOpState::Connected, "net/wireless/test",
            "wdev did not reach Connected after handshake");
    KASSERT(drv.wdev->fw.state == FourWayState::Established, "net/wireless/test",
            "fourway state did not reach Established");
    KASSERT(drv.ap.state == FakeApState::GotM4_Done, "net/wireless/test", "AP did not reach GotM4_Done");

    // Counter checks.
    KASSERT(drv.ap.beacons_sent == 1, "net/wireless/test", "wrong beacon count");
    KASSERT(drv.ap.m1_sent == 1, "net/wireless/test", "wrong M1 count");
    KASSERT(drv.ap.m2_received_ok == 1, "net/wireless/test", "AP did not receive valid M2");
    KASSERT(drv.ap.m3_sent == 1, "net/wireless/test", "AP did not send M3");
    KASSERT(drv.ap.m4_received_ok == 1, "net/wireless/test", "AP did not receive valid M4");
    KASSERT(drv.ap.m2_mic_failures == 0 && drv.ap.m4_mic_failures == 0, "net/wireless/test",
            "AP saw MIC failures on the success path");

    // Key checks: STA's TK must match AP's TK; STA's GTK must match AP's GTK.
    KASSERT(drv.sta_pairwise_key_len == 16, "net/wireless/test", "STA pairwise key not installed (TK)");
    KASSERT(BytesEqual(drv.sta_pairwise_key, FakeApInstalledTk(&drv.ap), 16), "net/wireless/test",
            "STA TK does not match AP TK — PTK derivation diverged between endpoints");
    KASSERT(drv.sta_group_key_len == 16, "net/wireless/test", "STA group key not installed (GTK)");
    KASSERT(BytesEqual(drv.sta_group_key, FakeApInstalledGtk(&drv.ap), 16), "net/wireless/test",
            "STA GTK does not match AP GTK — M3 KDE extraction broke");
    KASSERT(drv.sta_group_index == 1, "net/wireless/test", "STA GTK index != 1");

    arch::SerialWrite("[wifi-e2e] success-case pass — keys match across endpoints\n");
}

void RunWrongPskCase()
{
    static LoopbackDriver drv = {};
    const u8 ap_mac[6] = {0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEF};
    const u8 sta_mac[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x56};
    auto rr = LoopbackDriverRegister(&drv, "DuetOS-Loopback-Wrong", "CorrectPassword", ap_mac, sta_mac, 11);
    KASSERT(rr.has_value(), "net/wireless/test", "loopback register failed (wrong-psk case)");

    // STA tries to connect with the WRONG passphrase. The AP
    // derives one PMK, the STA derives a different PMK; their
    // PTKs disagree; the AP's MIC verify on M2 fails.
    auto dr = LoopbackDriverDrive(&drv, "WrongPassword!");
    // The STA-side completes through M1 successfully, builds M2
    // with its (mismatched) PTK, and TXes it via SendEapolFrame.
    // The loopback driver routes M2 to FakeApProcessM2BuildM3,
    // which fails MIC and returns Corrupt.
    KASSERT(!dr.has_value() || drv.ap.m2_mic_failures > 0, "net/wireless/test",
            "wrong-PSK handshake did not surface a MIC failure");
    KASSERT(drv.ap.state == FakeApState::Failed, "net/wireless/test",
            "AP didn't transition to Failed on wrong-PSK case");

    // STA shouldn't have installed any keys.
    KASSERT(drv.sta_pairwise_key_len == 0, "net/wireless/test", "STA installed pairwise key on a failed handshake");
    KASSERT(drv.sta_group_key_len == 0, "net/wireless/test", "STA installed group key on a failed handshake");

    arch::SerialWrite("[wifi-e2e] wrong-psk pass — handshake correctly rejected\n");
}

void RunReplayCase()
{
    static LoopbackDriver drv = {};
    const u8 ap_mac[6] = {0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xF0};
    const u8 sta_mac[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x57};
    auto rr = LoopbackDriverRegister(&drv, "DuetOS-Loopback-Replay", "ReplayProtect", ap_mac, sta_mac, 1);
    KASSERT(rr.has_value(), "net/wireless/test", "loopback register failed (replay case)");

    // Drive a successful first handshake so the supplicant has
    // a non-zero last_replay value.
    auto dr1 = LoopbackDriverDrive(&drv, "ReplayProtect");
    KASSERT(dr1.has_value(), "net/wireless/test", "replay setup handshake failed");
    KASSERT(drv.wdev->fw.state == FourWayState::Established, "net/wireless/test", "replay setup did not establish");

    // Now build an M1 with a STALE replay counter (zeroes) and
    // feed it back to the supplicant via WirelessDeliverEapol.
    // The state machine should reject as Corrupt.
    static u8 m1[256];
    EapolKeyFrame stale{};
    stale.version = 2;
    stale.packet_type = kEapolPacketTypeKey;
    stale.descriptor_type = kEapolKeyDescriptorRsn;
    stale.key_info = kKiKeyType | kKiAck | kKdvHmacSha1;
    stale.key_length = 16;
    // Replay counter all-zero — strictly less than what
    // last_replay holds after the successful first handshake.
    for (u32 i = 0; i < 8; ++i)
        stale.replay_counter[i] = 0;
    for (u32 i = 0; i < 32; ++i)
        stale.key_nonce[i] = static_cast<u8>(0xFFu - i);
    u32 m1_len = 0;
    auto br = EapolKeyBuild(stale, m1, sizeof(m1), &m1_len);
    KASSERT(br.has_value(), "net/wireless/test", "stale-M1 build failed");

    const u32 prior_retries = drv.wdev->fw.retries_seen;
    WirelessFrameRx rx{};
    rx.frame = m1;
    rx.frame_len = m1_len;
    rx.rssi_dbm = -45;
    rx.channel = 1;
    auto deliver_r = WirelessDeliverEapol(drv.wdev, rx);
    KASSERT(!deliver_r.has_value(), "net/wireless/test", "stale replay was accepted");
    KASSERT(drv.wdev->fw.retries_seen > prior_retries, "net/wireless/test",
            "retries_seen did not advance on rejected replay");

    arch::SerialWrite("[wifi-e2e] replay-protection pass — stale counter rejected\n");
}

void RunMicTamperCase()
{
    static LoopbackDriver drv = {};
    const u8 ap_mac[6] = {0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xF1};
    const u8 sta_mac[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x58};
    auto rr = LoopbackDriverRegister(&drv, "DuetOS-Loopback-Tamper", "TamperShield", ap_mac, sta_mac, 36);
    KASSERT(rr.has_value(), "net/wireless/test", "loopback register failed (tamper case)");

    // Successful first handshake to establish PTK.
    auto dr1 = LoopbackDriverDrive(&drv, "TamperShield");
    KASSERT(dr1.has_value(), "net/wireless/test", "tamper setup handshake failed");

    // Now fabricate an M3 with a tampered byte. Use the same
    // shape as a real M3 but corrupt one byte mid-payload after
    // MIC computation — the supplicant should reject.
    static u8 m3[256];
    EapolKeyFrame fm{};
    fm.version = 2;
    fm.packet_type = kEapolPacketTypeKey;
    fm.descriptor_type = kEapolKeyDescriptorRsn;
    fm.key_info = kKiKeyType | kKiAck | kKiMic | kKiInstall | kKiSecure | kKdvHmacSha1;
    fm.key_length = 16;
    // Replay > last_replay so the replay check passes.
    for (u32 i = 0; i < 8; ++i)
        fm.replay_counter[i] = 0xFFu;
    for (u32 i = 0; i < 32; ++i)
        fm.key_nonce[i] = static_cast<u8>(0xA0u + (i & 0x0Fu));
    u32 m3_len = 0;
    auto br = EapolKeyBuild(fm, m3, sizeof(m3), &m3_len);
    KASSERT(br.has_value(), "net/wireless/test", "tamper M3 build failed");
    auto pp = EapolMicPatch(m3, m3_len, drv.wdev->fw.ptk, kKckBytes, kKdvHmacSha1);
    KASSERT(pp.has_value(), "net/wireless/test", "tamper M3 mic patch failed");
    // Tamper with one byte AFTER the MIC was computed.
    m3[12] ^= 0x42;

    // Reset wdev state to AwaitingM3 so the state machine accepts
    // the message-class but the MIC verify rejects it.
    drv.wdev->fw.state = FourWayState::AwaitingM3;
    const u32 prior_mics = drv.wdev->fw.mic_failures;
    WirelessFrameRx rx{};
    rx.frame = m3;
    rx.frame_len = m3_len;
    rx.rssi_dbm = -45;
    rx.channel = 36;
    auto deliver_r = WirelessDeliverEapol(drv.wdev, rx);
    KASSERT(!deliver_r.has_value(), "net/wireless/test", "tampered M3 was accepted");
    KASSERT(drv.wdev->fw.mic_failures > prior_mics, "net/wireless/test", "mic_failures did not advance on tampered M3");

    arch::SerialWrite("[wifi-e2e] tamper pass — corrupted M3 rejected\n");
}

} // namespace

void WirelessE2ESelfTest()
{
    arch::SerialWrite("[wifi-e2e] starting end-to-end loopback self-tests\n");
    RunSuccessCase();
    RunWrongPskCase();
    RunReplayCase();
    RunMicTamperCase();
    arch::SerialWrite("[wifi-e2e] all 4 cases pass\n");
}

} // namespace duetos::net::wireless::test
