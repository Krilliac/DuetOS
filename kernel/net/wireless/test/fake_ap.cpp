#include "net/wireless/test/fake_ap.h"

#include "core/panic.h"
#include "crypto/pbkdf2.h"
#include "crypto/prf.h"
#include "net/wireless/wifi_diag.h"

namespace duetos::net::wireless::test
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

void ZeroBytes(u8* dst, u32 n)
{
    for (u32 i = 0; i < n; ++i)
        dst[i] = 0;
}

bool MacLess(const u8 a[6], const u8 b[6])
{
    for (u32 i = 0; i < 6; ++i)
    {
        if (a[i] < b[i])
            return true;
        if (a[i] > b[i])
            return false;
    }
    return false;
}

bool NonceLess(const u8 a[32], const u8 b[32])
{
    for (u32 i = 0; i < 32; ++i)
    {
        if (a[i] < b[i])
            return true;
        if (a[i] > b[i])
            return false;
    }
    return false;
}

void BuildPrfSeed(const u8 sta[6], const u8 ap[6], const u8 snonce[32], const u8 anonce[32], u8 seed[76])
{
    if (MacLess(sta, ap))
    {
        CopyBytes(seed, sta, 6);
        CopyBytes(seed + 6, ap, 6);
    }
    else
    {
        CopyBytes(seed, ap, 6);
        CopyBytes(seed + 6, sta, 6);
    }
    if (NonceLess(snonce, anonce))
    {
        CopyBytes(seed + 12, snonce, 32);
        CopyBytes(seed + 12 + 32, anonce, 32);
    }
    else
    {
        CopyBytes(seed + 12, anonce, 32);
        CopyBytes(seed + 12 + 32, snonce, 32);
    }
}

u32 BuildMgmtMacHeader(u8 subtype, const u8 da[6], const u8 sa[6], const u8 bssid[6], u8* out)
{
    const u16 fc =
        (static_cast<u16>(FrameType::Management) << kFcTypeShift) | (static_cast<u16>(subtype) << kFcSubtypeShift);
    WriteLe16(out, 0, fc);
    WriteLe16(out, 2, 0);
    CopyBytes(out + 4, da, 6);
    CopyBytes(out + 10, sa, 6);
    CopyBytes(out + 16, bssid, 6);
    WriteLe16(out, 22, 0);
    return 24;
}

void IncrementReplay(u8 rc[8])
{
    for (i32 i = 7; i >= 0; --i)
    {
        if (++rc[i] != 0)
            return;
    }
}

u32 StringLen(const char* s)
{
    u32 n = 0;
    if (s != nullptr)
        while (s[n] != '\0')
            ++n;
    return n;
}

} // namespace

const char* FakeApStateName(FakeApState s)
{
    switch (s)
    {
    case FakeApState::Idle:
        return "idle";
    case FakeApState::Authenticated:
        return "authed";
    case FakeApState::Associated:
        return "assoc";
    case FakeApState::SentM1:
        return "m1-tx";
    case FakeApState::GotM2_SentM3:
        return "m3-tx";
    case FakeApState::GotM4_Done:
        return "done";
    case FakeApState::Failed:
        return "failed";
    default:
        return "?";
    }
}

::duetos::core::Result<void> FakeApInit(FakeAp* ap, const char* ssid, const char* passphrase, const u8 mac[6],
                                        u8 channel)
{
    if (ap == nullptr || ssid == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    *ap = {};
    const u32 sl = StringLen(ssid);
    if (sl == 0 || sl > kSsidMaxBytes)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    for (u32 i = 0; i < sl; ++i)
        ap->ssid[i] = ssid[i];
    ap->ssid[sl] = '\0';
    ap->ssid_len = static_cast<u8>(sl);
    if (passphrase != nullptr)
    {
        u32 pl = StringLen(passphrase);
        if (pl > sizeof(ap->passphrase) - 1)
            pl = sizeof(ap->passphrase) - 1;
        for (u32 i = 0; i < pl; ++i)
            ap->passphrase[i] = passphrase[i];
        ap->passphrase[pl] = '\0';
        ap->wpa2 = (pl > 0);
    }
    CopyBytes(ap->mac, mac, 6);
    ap->channel = channel;
    if (ap->wpa2)
        duetos::crypto::WpaPmkDerive(ap->passphrase, ap->ssid, ap->ssid_len, ap->pmk);
    // Pre-compute a deterministic GTK so the test can compare
    // STA-installed against AP-locked-in.
    for (u32 i = 0; i < 16; ++i)
        ap->gtk[i] = static_cast<u8>(0x70u + i);
    ap->gtk_index = 1;
    ap->state = FakeApState::Idle;
    diag::RecordOk(diag::Layer::Diag, "fakeap-init", sl, ap->wpa2 ? 1 : 0, channel);
    return ::duetos::core::Result<void>{};
}

u32 FakeApBuildBeacon(FakeAp* ap, u8* out, u32 cap)
{
    if (ap == nullptr || out == nullptr)
        return 0;
    const u32 need = 24 + 12 + 2 + ap->ssid_len + 2 + 4 + 2 + 1 + (ap->wpa2 ? 22u : 0u);
    if (cap < need)
        return 0;
    const u8 broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    u32 o = BuildMgmtMacHeader(static_cast<u8>(MgmtSubtype::Beacon), broadcast, ap->mac, ap->mac, out);
    // Timestamp.
    for (u32 i = 0; i < 8; ++i)
        out[o++] = 0;
    // Beacon interval (100 TU).
    WriteLe16(out, o, 100);
    o += 2;
    // Capability info.
    const u16 cap_info = kCapEss | (ap->wpa2 ? kCapPrivacy : 0u) | kCapShortPreamble | kCapShortSlotTime;
    WriteLe16(out, o, cap_info);
    o += 2;
    // SSID IE.
    out[o++] = kIeSsid;
    out[o++] = ap->ssid_len;
    for (u8 i = 0; i < ap->ssid_len; ++i)
        out[o++] = static_cast<u8>(ap->ssid[i]);
    // Supported rates: 1/2/5.5/11 Mbps basic.
    out[o++] = kIeSupportedRates;
    out[o++] = 4;
    out[o++] = 0x82;
    out[o++] = 0x84;
    out[o++] = 0x8B;
    out[o++] = 0x96;
    // DS Parameter Set (channel).
    out[o++] = kIeDsParamSet;
    out[o++] = 1;
    out[o++] = ap->channel;
    if (ap->wpa2)
    {
        // RSN IE: WPA2-PSK / CCMP.
        out[o++] = kIeRsn;
        out[o++] = 20;
        out[o++] = 0x01;
        out[o++] = 0x00;
        out[o++] = 0x00;
        out[o++] = 0x0F;
        out[o++] = 0xAC;
        out[o++] = kCipherCcmp128;
        out[o++] = 0x01;
        out[o++] = 0x00;
        out[o++] = 0x00;
        out[o++] = 0x0F;
        out[o++] = 0xAC;
        out[o++] = kCipherCcmp128;
        out[o++] = 0x01;
        out[o++] = 0x00;
        out[o++] = 0x00;
        out[o++] = 0x0F;
        out[o++] = 0xAC;
        out[o++] = kAkmPsk;
        out[o++] = 0x00;
        out[o++] = 0x00;
    }
    ++ap->beacons_sent;
    return o;
}

u32 FakeApBuildAuthResponse(FakeAp* ap, const u8 sta_mac[6], u8* out, u32 cap)
{
    if (cap < 24 + 6)
        return 0;
    u32 o = BuildMgmtMacHeader(static_cast<u8>(MgmtSubtype::Authentication), sta_mac, ap->mac, ap->mac, out);
    WriteLe16(out, o, 0); // algo open
    o += 2;
    WriteLe16(out, o, 2); // seq 2 (response)
    o += 2;
    WriteLe16(out, o, 0); // status success
    o += 2;
    ap->state = FakeApState::Authenticated;
    return o;
}

u32 FakeApBuildAssocResponse(FakeAp* ap, const u8 sta_mac[6], u8* out, u32 cap)
{
    if (cap < 24 + 6)
        return 0;
    u32 o = BuildMgmtMacHeader(static_cast<u8>(MgmtSubtype::AssocResponse), sta_mac, ap->mac, ap->mac, out);
    WriteLe16(out, o, kCapEss | (ap->wpa2 ? kCapPrivacy : 0u));
    o += 2;
    WriteLe16(out, o, 0); // status success
    o += 2;
    WriteLe16(out, o, 1); // AID 1
    o += 2;
    ap->state = FakeApState::Associated;
    return o;
}

::duetos::core::Result<u32> FakeApBuildM1(FakeAp* ap, const u8 sta_mac[6], u8* out, u32 cap)
{
    if (ap == nullptr || out == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    CopyBytes(ap->sta_mac, sta_mac, 6);
    // ANonce: deterministic for repeatable tests, but unique
    // per session via a counter. v0 mixes a fixed pattern with
    // the AP MAC so two FakeAps with different MACs produce
    // different ANonces.
    for (u32 i = 0; i < 32; ++i)
        ap->anonce[i] = static_cast<u8>(0xA0u ^ ap->mac[i % 6] ^ static_cast<u8>(i));

    EapolKeyFrame f{};
    f.version = 2;
    f.packet_type = kEapolPacketTypeKey;
    f.descriptor_type = kEapolKeyDescriptorRsn;
    f.key_info = kKiKeyType | kKiAck | kKdvHmacSha1;
    f.key_length = 16;
    IncrementReplay(ap->replay_counter);
    CopyBytes(f.replay_counter, ap->replay_counter, 8);
    CopyBytes(f.key_nonce, ap->anonce, 32);
    f.key_data = nullptr;
    f.key_data_len = 0;

    u32 m1_len = 0;
    auto br = EapolKeyBuild(f, out, cap, &m1_len);
    if (!br.has_value())
        return ::duetos::core::Err{br.error()};
    ap->state = FakeApState::SentM1;
    ++ap->m1_sent;
    diag::RecordOk(diag::Layer::Diag, "fakeap-m1-tx", m1_len, 0, 0);
    return m1_len;
}

::duetos::core::Result<u32> FakeApProcessM2BuildM3(FakeAp* ap, const u8* m2, u32 m2_len, u8* m3_out, u32 m3_cap)
{
    if (ap == nullptr || m2 == nullptr || m3_out == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    EapolKeyFrame fm{};
    auto pr = EapolKeyParse(m2, m2_len, &fm);
    if (!pr.has_value())
    {
        ap->state = FakeApState::Failed;
        ap->failure_step = 1;
        return ::duetos::core::Err{pr.error()};
    }
    // Capture SNonce, derive PTK independently.
    u8 snonce[32];
    CopyBytes(snonce, fm.key_nonce, 32);
    u8 seed[76];
    BuildPrfSeed(ap->sta_mac, ap->mac, snonce, ap->anonce, seed);
    duetos::crypto::Prf(ap->pmk, 32, "Pairwise key expansion", seed, 76, kPtkBytes * 8u, ap->ptk);
    ap->ptk_valid = true;

    // Verify M2 MIC against our derived KCK (first 16 bytes of PTK).
    auto vr = EapolMicVerify(m2, m2_len, ap->ptk, kKckBytes, kKdvHmacSha1);
    if (!vr.has_value())
    {
        ++ap->m2_mic_failures;
        ap->state = FakeApState::Failed;
        ap->failure_step = 2;
        diag::RecordErr(diag::Layer::Diag, "fakeap-m2-mic-fail", static_cast<u32>(vr.error()), 0, 0, 0);
        return ::duetos::core::Err{::duetos::core::ErrorCode::Corrupt};
    }
    ++ap->m2_received_ok;

    // Build M3 with GTK KDE.
    u8 m3_keydata[32];
    u32 kd = 0;
    m3_keydata[kd++] = 0xDD;
    m3_keydata[kd++] = 22;
    m3_keydata[kd++] = 0x00;
    m3_keydata[kd++] = 0x0F;
    m3_keydata[kd++] = 0xAC;
    m3_keydata[kd++] = 0x01; // GTK
    m3_keydata[kd++] = static_cast<u8>(ap->gtk_index & 0x03u);
    m3_keydata[kd++] = 0x00;
    for (u32 i = 0; i < 16; ++i)
        m3_keydata[kd++] = ap->gtk[i];

    EapolKeyFrame f{};
    f.version = 2;
    f.packet_type = kEapolPacketTypeKey;
    f.descriptor_type = kEapolKeyDescriptorRsn;
    f.key_info = kKiKeyType | kKiAck | kKiMic | kKiInstall | kKiSecure | kKdvHmacSha1;
    f.key_length = 16;
    IncrementReplay(ap->replay_counter);
    CopyBytes(f.replay_counter, ap->replay_counter, 8);
    CopyBytes(f.key_nonce, ap->anonce, 32);
    f.key_data = m3_keydata;
    f.key_data_len = static_cast<u16>(kd);

    u32 m3_len = 0;
    auto br = EapolKeyBuild(f, m3_out, m3_cap, &m3_len);
    if (!br.has_value())
        return ::duetos::core::Err{br.error()};
    auto pp = EapolMicPatch(m3_out, m3_len, ap->ptk, kKckBytes, kKdvHmacSha1);
    if (!pp.has_value())
        return ::duetos::core::Err{pp.error()};
    ap->state = FakeApState::GotM2_SentM3;
    ++ap->m3_sent;
    diag::RecordOk(diag::Layer::Diag, "fakeap-m3-tx", m3_len, 0, 0);
    return m3_len;
}

::duetos::core::Result<void> FakeApProcessM4(FakeAp* ap, const u8* m4, u32 m4_len)
{
    if (ap == nullptr || m4 == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    auto vr = EapolMicVerify(m4, m4_len, ap->ptk, kKckBytes, kKdvHmacSha1);
    if (!vr.has_value())
    {
        ++ap->m4_mic_failures;
        ap->state = FakeApState::Failed;
        ap->failure_step = 4;
        diag::RecordErr(diag::Layer::Diag, "fakeap-m4-mic-fail", static_cast<u32>(vr.error()), 0, 0, 0);
        return vr;
    }
    ++ap->m4_received_ok;
    ap->state = FakeApState::GotM4_Done;
    diag::RecordOk(diag::Layer::Diag, "fakeap-handshake-done", 0, 0, 0);
    (void)ZeroBytes; // silence unused
    return ::duetos::core::Result<void>{};
}

const u8* FakeApInstalledTk(const FakeAp* ap)
{
    return ap->ptk + kKckBytes + kKekBytes;
}

const u8* FakeApInstalledGtk(const FakeAp* ap)
{
    return ap->gtk;
}

} // namespace duetos::net::wireless::test
