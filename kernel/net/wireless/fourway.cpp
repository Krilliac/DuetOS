#include "net/wireless/fourway.h"

#include "core/panic.h"
#include "log/klog.h"
#include "crypto/aes.h"
#include "crypto/aes_keywrap.h"
#include "crypto/prf.h"
#include "net/wireless/wifi_diag.h"

namespace duetos::net::wireless
{

namespace
{

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

void CopyBytes(u8* dst, const u8* src, u32 len)
{
    for (u32 i = 0; i < len; ++i)
        dst[i] = src[i];
}

void ZeroBytes(u8* dst, u32 len)
{
    for (u32 i = 0; i < len; ++i)
        dst[i] = 0;
}

// Returns true iff 8-byte replay counter `incoming` is strictly
// greater than `last`. Treated as a 64-bit big-endian unsigned
// integer per 802.11i §8.4.2.
bool ReplayGt(const u8 incoming[8], const u8 last[8])
{
    for (u32 i = 0; i < 8; ++i)
    {
        if (incoming[i] > last[i])
            return true;
        if (incoming[i] < last[i])
            return false;
    }
    return false;
}

// Build the PRF seed: min(SPA, AA) || max(SPA, AA) ||
//                     min(SNonce, ANonce) || max(SNonce, ANonce).
// Length: 6 + 6 + 32 + 32 = 76 bytes.
void BuildPrfSeed(const u8 spa[6], const u8 aa[6], const u8 snonce[32], const u8 anonce[32], u8 seed_out[76])
{
    if (MacLess(spa, aa))
    {
        CopyBytes(seed_out, spa, 6);
        CopyBytes(seed_out + 6, aa, 6);
    }
    else
    {
        CopyBytes(seed_out, aa, 6);
        CopyBytes(seed_out + 6, spa, 6);
    }
    if (NonceLess(snonce, anonce))
    {
        CopyBytes(seed_out + 12, snonce, 32);
        CopyBytes(seed_out + 12 + 32, anonce, 32);
    }
    else
    {
        CopyBytes(seed_out + 12, anonce, 32);
        CopyBytes(seed_out + 12 + 32, snonce, 32);
    }
}

bool IsAllZero(const u8* buf, u32 len)
{
    for (u32 i = 0; i < len; ++i)
        if (buf[i] != 0)
            return false;
    return true;
}

// Walk an EAPOL key-data field looking for a GTK KDE.
// KDE format: u8 type=0xDD, u8 len, u8 oui[3]={00:0F:AC},
// u8 data_type=1 (GTK), u8 KeyId+TX, u8 reserved, u8 gtk[N].
//
// Three outcomes:
//   Found       — GTK KDE present and copied into `gtk`.
//   None        — KeyData walked cleanly to the end with no GTK
//                 KDE. Legitimate for early-WPA setups that ship
//                 the GTK in a separate Group Key Handshake.
//   Corrupt     — A KDE length advanced past `key_data_len`, or
//                 the GTK payload exceeded `gtk_capacity`. Caller
//                 must fail the handshake — silently treating
//                 this as None used to leave the link "connected"
//                 with no broadcast key, dropping all multicast.
enum class GtkKdeResult : u8
{
    None = 0,
    Found = 1,
    Corrupt = 2,
};

GtkKdeResult ExtractGtkKde(const u8* key_data, u32 key_data_len, u8* gtk, u32 gtk_capacity, u32* gtk_len_out,
                           u8* gtk_index_out)
{
    u32 off = 0;
    while (off + 2 <= key_data_len)
    {
        const u8 type = key_data[off];
        const u8 len = key_data[off + 1];
        if (off + 2u + len > key_data_len)
            return GtkKdeResult::Corrupt;
        if (type == 0xDD && len >= 6 && key_data[off + 2] == 0x00 && key_data[off + 3] == 0x0F &&
            key_data[off + 4] == 0xAC && key_data[off + 5] == 0x01)
        {
            // GTK KDE.
            const u8 key_id_tx = key_data[off + 6];
            // off+7 reserved
            const u32 gtk_bytes = static_cast<u32>(len) - 6u;
            if (gtk_bytes > gtk_capacity)
                return GtkKdeResult::Corrupt;
            for (u32 i = 0; i < gtk_bytes; ++i)
                gtk[i] = key_data[off + 8 + i];
            *gtk_len_out = gtk_bytes;
            *gtk_index_out = key_id_tx & 0x03u;
            return GtkKdeResult::Found;
        }
        off += 2u + len;
    }
    return GtkKdeResult::None;
}

} // namespace

const char* FourWayStateName(FourWayState s)
{
    switch (s)
    {
    case FourWayState::Idle:
        return "idle";
    case FourWayState::AwaitingM1:
        return "await-m1";
    case FourWayState::AwaitingM3:
        return "await-m3";
    case FourWayState::AwaitingM4Ack:
        return "await-m4-ack";
    case FourWayState::Established:
        return "established";
    case FourWayState::Failed:
        return "failed";
    default:
        return "?";
    }
}

void FourWayInit(FourWayContext& ctx, const u8 pmk[32], const u8 sta_mac[6], const u8 ap_mac[6], bool sha256,
                 bool aes_cmac)
{
    ctx = {};
    CopyBytes(ctx.pmk, pmk, 32);
    CopyBytes(ctx.sta_mac, sta_mac, 6);
    CopyBytes(ctx.ap_mac, ap_mac, 6);
    ctx.sha256 = sha256;
    ctx.aes_cmac = aes_cmac;
    ctx.state = FourWayState::AwaitingM1;
    KLOG_INFO_A2V(::duetos::core::LogArea::Wireless, "net/wireless/fourway", "4way init", "sha256",
                  static_cast<u64>(sha256 ? 1 : 0), "aes_cmac", static_cast<u64>(aes_cmac ? 1 : 0));
    diag::RecordOk(diag::Layer::Eapol, "4way-init", sha256 ? 1 : 0, aes_cmac ? 1 : 0);
}

::duetos::core::Result<void> FourWayProcessIncoming(FourWayContext& ctx, const u8* frame, u32 len)
{
    EapolKeyFrame f{};
    auto pr = EapolKeyParse(frame, len, &f);
    if (!pr.has_value())
        return pr;

    // Replay-counter check: incoming counter must be > last seen
    // (after the first non-zero one). On first message we just
    // record it.
    if (!IsAllZero(ctx.last_replay, kEapolReplayBytes) && !ReplayGt(f.replay_counter, ctx.last_replay))
    {
        ++ctx.retries_seen;
        KLOG_WARN_A(::duetos::core::LogArea::Wireless, "net/wireless/fourway",
                    "incoming replay counter <= last seen — frame rejected");
        diag::RecordErr(diag::Layer::Eapol, "4way-replay", static_cast<u32>(::duetos::core::ErrorCode::Corrupt), 0, 0,
                        0);
        return ::duetos::core::Err{::duetos::core::ErrorCode::Corrupt};
    }

    const bool has_mic = (f.key_info & kKiMic) != 0;
    const bool ack = (f.key_info & kKiAck) != 0;
    const bool install = (f.key_info & kKiInstall) != 0;
    const bool secure = (f.key_info & kKiSecure) != 0;
    const bool encrypted = (f.key_info & kKiEncrypted) != 0;
    (void)secure;

    // Classify message:
    //   M1: ACK=1, MIC=0           (pairwise install bit may be 0)
    //   M2: ACK=0, MIC=1           (no Install)
    //   M3: ACK=1, MIC=1, Install=1
    //   M4: ACK=0, MIC=1
    if (ack && !has_mic)
    {
        // M1.
        if (ctx.state != FourWayState::AwaitingM1)
        {
            ++ctx.unexpected_messages;
            KLOG_WARN_AS(::duetos::core::LogArea::Wireless, "net/wireless/fourway", "M1 received in unexpected state",
                         "state", FourWayStateName(ctx.state));
            diag::RecordErr(diag::Layer::Eapol, "4way-m1-unexp", static_cast<u32>(::duetos::core::ErrorCode::BadState),
                            static_cast<u64>(ctx.state), 0, 0);
            return ::duetos::core::Err{::duetos::core::ErrorCode::BadState};
        }
        CopyBytes(ctx.anonce, f.key_nonce, 32);
        CopyBytes(ctx.last_replay, f.replay_counter, kEapolReplayBytes);
        ++ctx.messages_processed;
        // Generate SNonce. v0: deterministic from MAC + replay
        // counter so the self-test can KAT against a known PTK.
        // Real driver will replace with random.
        for (u32 i = 0; i < 32; ++i)
            ctx.snonce[i] = static_cast<u8>(0xC0u ^ ctx.sta_mac[i % 6] ^ ctx.last_replay[i % 8] ^ i);

        // Derive PTK.
        u8 seed[76];
        BuildPrfSeed(ctx.sta_mac, ctx.ap_mac, ctx.snonce, ctx.anonce, seed);
        if (ctx.sha256)
            duetos::crypto::KdfSha256(ctx.pmk, 32, "Pairwise key expansion", seed, 76, kPtkBytes * 8u, ctx.ptk);
        else
            duetos::crypto::Prf(ctx.pmk, 32, "Pairwise key expansion", seed, 76, kPtkBytes * 8u, ctx.ptk);
        ctx.ptk_valid = true;
        ctx.state = FourWayState::AwaitingM3;
        KLOG_INFO_A(::duetos::core::LogArea::Wireless, "net/wireless/fourway",
                    "M1 processed — PTK derived; awaiting M3");
        diag::RecordOk(diag::Layer::Eapol, "4way-m1-ok", f.key_info, 0, 0);
        return ::duetos::core::Result<void>{};
    }
    if (ack && has_mic && install)
    {
        // M3.
        if (ctx.state != FourWayState::AwaitingM3)
        {
            ++ctx.unexpected_messages;
            KLOG_WARN_AS(::duetos::core::LogArea::Wireless, "net/wireless/fourway", "M3 received in unexpected state",
                         "state", FourWayStateName(ctx.state));
            diag::RecordErr(diag::Layer::Eapol, "4way-m3-unexp", static_cast<u32>(::duetos::core::ErrorCode::BadState),
                            static_cast<u64>(ctx.state), 0, 0);
            return ::duetos::core::Err{::duetos::core::ErrorCode::BadState};
        }
        // Verify MIC against KCK.
        const u16 kdv = ctx.aes_cmac ? kKdvAesCmac : kKdvHmacSha1;
        auto vr = EapolMicVerify(frame, len, FourWayKck(ctx), kKckBytes, kdv);
        if (!vr.has_value())
        {
            ++ctx.mic_failures;
            ctx.state = FourWayState::Failed;
            // WARN, not ERROR: a failed M3 MIC is a normal
            // remote-input protocol rejection (wrong PSK is the
            // common case). The Err return + ctx.state=Failed +
            // RecordErr are the real notification channels; an [E]
            // sentinel here floods the error log on every wrong
            // password and trips the boot-log [E] CI grep.
            KLOG_WARN_A(::duetos::core::LogArea::Wireless, "net/wireless/fourway",
                        "M3 MIC verify FAILED — handshake aborted");
            diag::RecordErr(diag::Layer::Eapol, "4way-m3-mic", static_cast<u32>(vr.error()), 0, 0, 0);
            return vr;
        }
        // Decide which buffer + length we're walking for KDEs. If
        // KeyInfo.Encrypted is set, the KeyData is AES-KW-wrapped
        // under the KEK (upper half of the PTK); we unwrap into a
        // stack-local buffer and walk that instead. Plain KeyData
        // (no Encrypted flag) walks `f.key_data` directly.
        const u8* keydata = f.key_data;
        u32 keydata_len = f.key_data_len;
        // 256 bytes covers a GTK KDE + IGTK KDE + 802.11i pad. The
        // hard ceiling lives at `kAesKwMaxSemiBlocks * 8 = 512` in
        // the AES-KW module; keeping this smaller avoids a
        // kernel-stack hog on the M3 path.
        constexpr u32 kUnwrapScratchMax = 256;
        u8 unwrapped[kUnwrapScratchMax];
        if (encrypted)
        {
            if (f.key_data_len < 24u || (f.key_data_len % 8u) != 0u)
            {
                ++ctx.mic_failures;
                ctx.state = FourWayState::Failed;
                KLOG_WARN_AV(::duetos::core::LogArea::Wireless, "net/wireless/fourway",
                             "M3 encrypted key-data length invalid", static_cast<u64>(f.key_data_len));
                diag::RecordErr(diag::Layer::Eapol, "4way-m3-keydata-len",
                                static_cast<u32>(::duetos::core::ErrorCode::Corrupt), f.key_data_len, 0, 0);
                return ::duetos::core::Err{::duetos::core::ErrorCode::Corrupt};
            }
            const u32 plain_len = f.key_data_len - 8u;
            if (plain_len > kUnwrapScratchMax)
            {
                ctx.state = FourWayState::Failed;
                KLOG_WARN_AV(::duetos::core::LogArea::Wireless, "net/wireless/fourway",
                             "M3 encrypted key-data exceeds unwrap scratch — refusing", static_cast<u64>(plain_len));
                diag::RecordErr(diag::Layer::Eapol, "4way-m3-keydata-too-big",
                                static_cast<u32>(::duetos::core::ErrorCode::Corrupt), plain_len, 0, 0);
                return ::duetos::core::Err{::duetos::core::ErrorCode::Corrupt};
            }
            duetos::crypto::AesCtx kek_ctx;
            duetos::crypto::AesKeyExpand128(kek_ctx, FourWayKek(ctx));
            if (!duetos::crypto::AesKeyUnwrap(kek_ctx, f.key_data, f.key_data_len, unwrapped))
            {
                ++ctx.mic_failures;
                ctx.state = FourWayState::Failed;
                KLOG_WARN_A(::duetos::core::LogArea::Wireless, "net/wireless/fourway",
                            "M3 AES-KW unwrap integrity check FAILED — handshake aborted");
                diag::RecordErr(diag::Layer::Eapol, "4way-m3-kw-fail",
                                static_cast<u32>(::duetos::core::ErrorCode::Corrupt), f.key_data_len, 0, 0);
                return ::duetos::core::Err{::duetos::core::ErrorCode::Corrupt};
            }
            keydata = unwrapped;
            keydata_len = plain_len;
            diag::RecordOk(diag::Layer::Eapol, "4way-m3-kw-ok", plain_len, 0, 0);
        }
        if (keydata_len > 0)
        {
            u8 gtk[kGtkMaxBytes];
            u32 gtk_len = 0;
            u8 gtk_idx = 0;
            const GtkKdeResult gr = ExtractGtkKde(keydata, keydata_len, gtk, sizeof(gtk), &gtk_len, &gtk_idx);
            if (gr == GtkKdeResult::Corrupt)
            {
                ++ctx.mic_failures;
                ctx.state = FourWayState::Failed;
                KLOG_WARN_A(::duetos::core::LogArea::Wireless, "net/wireless/fourway",
                            "M3 KeyData GTK KDE corrupt — handshake aborted");
                diag::RecordErr(diag::Layer::Eapol, "4way-m3-gtk-corrupt",
                                static_cast<u32>(::duetos::core::ErrorCode::Corrupt), keydata_len, 0, 0);
                return ::duetos::core::Err{::duetos::core::ErrorCode::Corrupt};
            }
            if (gr == GtkKdeResult::Found)
            {
                CopyBytes(ctx.gtk, gtk, gtk_len);
                ctx.gtk_len = gtk_len;
                ctx.gtk_index = gtk_idx;
                ctx.gtk_valid = true;
                KLOG_INFO_A2V(::duetos::core::LogArea::Wireless, "net/wireless/fourway", "GTK installed from M3",
                              "gtk_len", static_cast<u64>(gtk_len), "gtk_index", static_cast<u64>(gtk_idx));
                diag::RecordOk(diag::Layer::KeyMgmt, "gtk-installed", gtk_len, gtk_idx, 0);
            }
        }
        CopyBytes(ctx.last_replay, f.replay_counter, kEapolReplayBytes);
        ++ctx.messages_processed;
        ctx.state = FourWayState::AwaitingM4Ack;
        KLOG_INFO_A(::duetos::core::LogArea::Wireless, "net/wireless/fourway", "M3 processed — awaiting M4 ack");
        diag::RecordOk(diag::Layer::Eapol, "4way-m3-ok", f.key_info, f.key_data_len, 0);
        return ::duetos::core::Result<void>{};
    }
    // M2 / M4 are SUPPLICANT-side outgoing — receiving them as a
    // supplicant is a protocol error.
    ++ctx.unexpected_messages;
    KLOG_WARN_AV(::duetos::core::LogArea::Wireless, "net/wireless/fourway",
                 "rx of supplicant-side msg (M2/M4) — key_info", static_cast<u64>(f.key_info));
    diag::RecordErr(diag::Layer::Eapol, "4way-rx-unexpected", static_cast<u32>(::duetos::core::ErrorCode::BadState),
                    f.key_info, 0, 0);
    return ::duetos::core::Err{::duetos::core::ErrorCode::BadState};
}

::duetos::core::Result<void> FourWayBuildOutgoing(const FourWayContext& ctx, const u8* rsn_ie, u32 rsn_ie_len,
                                                  u8* out_buf, u32 cap, u32* out_len)
{
    EapolKeyFrame f{};
    f.version = 2;
    f.packet_type = kEapolPacketTypeKey;
    f.descriptor_type = kEapolKeyDescriptorRsn;
    f.key_length = 16;
    CopyBytes(f.replay_counter, ctx.last_replay, kEapolReplayBytes);

    if (ctx.state == FourWayState::AwaitingM3)
    {
        // M2: SNonce + RSN IE in key data, MIC.
        f.key_info = kKiKeyType | kKiMic | kKdvHmacSha1;
        if (ctx.aes_cmac)
            f.key_info = static_cast<u16>((f.key_info & ~kKiKeyDescriptorVersionMask) | kKdvAesCmac);
        CopyBytes(f.key_nonce, ctx.snonce, 32);
        f.key_data = rsn_ie;
        f.key_data_len = static_cast<u16>(rsn_ie_len);
    }
    else if (ctx.state == FourWayState::AwaitingM4Ack)
    {
        // M4: ack, MIC, no key data.
        f.key_info = kKiKeyType | kKiMic | kKiSecure | kKdvHmacSha1;
        if (ctx.aes_cmac)
            f.key_info = static_cast<u16>((f.key_info & ~kKiKeyDescriptorVersionMask) | kKdvAesCmac);
        ZeroBytes(f.key_nonce, 32);
        f.key_data = nullptr;
        f.key_data_len = 0;
    }
    else
    {
        KLOG_WARN_AS(::duetos::core::LogArea::Wireless, "net/wireless/fourway",
                     "BuildOutgoing called from unexpected state", "state", FourWayStateName(ctx.state));
        diag::RecordErr(diag::Layer::Eapol, "4way-build-unexp", static_cast<u32>(::duetos::core::ErrorCode::BadState),
                        static_cast<u64>(ctx.state), 0, 0);
        return ::duetos::core::Err{::duetos::core::ErrorCode::BadState};
    }

    auto br = EapolKeyBuild(f, out_buf, cap, out_len);
    if (!br.has_value())
    {
        KLOG_WARN_A(::duetos::core::LogArea::Wireless, "net/wireless/fourway", "BuildOutgoing: EapolKeyBuild failed");
        return br;
    }
    if (!ctx.ptk_valid)
    {
        KLOG_ERROR_A(::duetos::core::LogArea::Wireless, "net/wireless/fourway",
                     "BuildOutgoing: PTK not derived — cannot MIC");
        return ::duetos::core::Err{::duetos::core::ErrorCode::BadState};
    }
    const u16 kdv = ctx.aes_cmac ? kKdvAesCmac : kKdvHmacSha1;
    return EapolMicPatch(out_buf, *out_len, FourWayKck(ctx), kKckBytes, kdv);
}

void FourWaySelfTest()
{
    KLOG_TRACE_SCOPE("net/wireless/fourway", "FourWaySelfTest");
    KLOG_INFO_A(::duetos::core::LogArea::Wireless, "net/wireless/fourway",
                "self-test: synthetic 4-way handshake (M1→M2→M3→M4)");
    // Synthetic two-party 4-way handshake. PMK is 32 bytes of
    // 0xAA, SPA = 02:11:22:33:44:55, AA = 02:AA:BB:CC:DD:EE.
    // We construct M1 manually (as the AP would), feed it to the
    // supplicant context, then use the supplicant to build M2 and
    // verify MIC validity.
    u8 pmk[32];
    for (u32 i = 0; i < 32; ++i)
        pmk[i] = 0xAA;
    const u8 spa[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    const u8 aa[6] = {0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    FourWayContext ctx{};
    FourWayInit(ctx, pmk, spa, aa, /*sha256=*/false, /*aes_cmac=*/false);
    KASSERT(ctx.state == FourWayState::AwaitingM1, "net/wireless/fourway", "init not awaiting M1");

    // Build M1 as the AP would.
    EapolKeyFrame m1{};
    m1.version = 2;
    m1.packet_type = kEapolPacketTypeKey;
    m1.descriptor_type = kEapolKeyDescriptorRsn;
    m1.key_info = kKiKeyType | kKiAck | kKdvHmacSha1;
    m1.key_length = 16;
    for (u32 i = 0; i < 32; ++i)
        m1.key_nonce[i] = static_cast<u8>(0xA0 + (i & 0x0Fu));
    for (u32 i = 0; i < 8; ++i)
        m1.replay_counter[i] = static_cast<u8>(i + 1);
    m1.key_data_len = 0;
    m1.key_data = nullptr;

    u8 m1_buf[256] = {};
    u32 m1_len = 0;
    auto br = EapolKeyBuild(m1, m1_buf, sizeof(m1_buf), &m1_len);
    KASSERT(br.has_value(), "net/wireless/fourway", "M1 build failed");
    // M1 has no MIC (AP doesn't have KCK yet from supplicant POV).

    auto pr = FourWayProcessIncoming(ctx, m1_buf, m1_len);
    KASSERT(pr.has_value(), "net/wireless/fourway", "M1 process failed");
    KASSERT(ctx.state == FourWayState::AwaitingM3, "net/wireless/fourway", "M1 didn't advance to AwaitingM3");
    KASSERT(ctx.ptk_valid, "net/wireless/fourway", "PTK not derived after M1");

    // Build M2 (supplicant → AP) and verify MIC self-consistency.
    const u8 fake_rsn_ie[24] = {0x30, 0x14, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00, 0x00, 0x0F,
                                0xAC, 0x04, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x02, 0x00, 0x00, 0x00, 0x00};
    u8 m2_buf[256] = {};
    u32 m2_len = 0;
    auto br2 = FourWayBuildOutgoing(ctx, fake_rsn_ie, sizeof(fake_rsn_ie), m2_buf, sizeof(m2_buf), &m2_len);
    KASSERT(br2.has_value(), "net/wireless/fourway", "M2 build failed");

    auto vr = EapolMicVerify(m2_buf, m2_len, FourWayKck(ctx), kKckBytes, kKdvHmacSha1);
    KASSERT(vr.has_value(), "net/wireless/fourway", "M2 self-MIC verify failed");

    // Build M3 with a GTK KDE; feed to supplicant; verify state +
    // GTK extraction. M3 must include MIC over body keyed on KCK.
    u8 m3_keydata[32];
    u32 kd = 0;
    m3_keydata[kd++] = 0xDD; // KDE type
    m3_keydata[kd++] = 22;   // length: 6 (OUI+type+id+resv) + 16 (GTK)
    m3_keydata[kd++] = 0x00;
    m3_keydata[kd++] = 0x0F;
    m3_keydata[kd++] = 0xAC;
    m3_keydata[kd++] = 0x01; // GTK KDE
    m3_keydata[kd++] = 0x01; // KeyId=1, TX=0
    m3_keydata[kd++] = 0x00;
    for (u32 i = 0; i < 16; ++i)
        m3_keydata[kd++] = static_cast<u8>(0xE0 + i);

    EapolKeyFrame m3{};
    m3.version = 2;
    m3.packet_type = kEapolPacketTypeKey;
    m3.descriptor_type = kEapolKeyDescriptorRsn;
    m3.key_info = kKiKeyType | kKiAck | kKiMic | kKiInstall | kKiSecure | kKdvHmacSha1;
    m3.key_length = 16;
    for (u32 i = 0; i < 32; ++i)
        m3.key_nonce[i] = m1.key_nonce[i];
    for (u32 i = 0; i < 8; ++i)
        m3.replay_counter[i] = static_cast<u8>(i + 2);
    m3.key_data_len = static_cast<u16>(kd);
    m3.key_data = m3_keydata;

    u8 m3_buf[256] = {};
    u32 m3_len = 0;
    auto br3 = EapolKeyBuild(m3, m3_buf, sizeof(m3_buf), &m3_len);
    KASSERT(br3.has_value(), "net/wireless/fourway", "M3 build failed");
    // Patch with KCK as if the AP had derived the same PTK we did.
    auto pp = EapolMicPatch(m3_buf, m3_len, FourWayKck(ctx), kKckBytes, kKdvHmacSha1);
    KASSERT(pp.has_value(), "net/wireless/fourway", "M3 MIC patch failed");

    auto pr3 = FourWayProcessIncoming(ctx, m3_buf, m3_len);
    KASSERT(pr3.has_value(), "net/wireless/fourway", "M3 process failed");
    KASSERT(ctx.state == FourWayState::AwaitingM4Ack, "net/wireless/fourway", "M3 didn't advance to AwaitingM4Ack");
    KASSERT(ctx.gtk_valid && ctx.gtk_len == 16, "net/wireless/fourway", "GTK not extracted from M3");
    KASSERT(ctx.gtk[0] == 0xE0 && ctx.gtk[15] == 0xEF, "net/wireless/fourway", "GTK bytes wrong");

    // Build M4 — should succeed with valid MIC.
    u8 m4_buf[256] = {};
    u32 m4_len = 0;
    auto br4 = FourWayBuildOutgoing(ctx, nullptr, 0, m4_buf, sizeof(m4_buf), &m4_len);
    KASSERT(br4.has_value(), "net/wireless/fourway", "M4 build failed");
    auto vr4 = EapolMicVerify(m4_buf, m4_len, FourWayKck(ctx), kKckBytes, kKdvHmacSha1);
    KASSERT(vr4.has_value(), "net/wireless/fourway", "M4 MIC verify failed");

    // ---------------------------------------------------------------
    // Encrypted-M3 path: a real AP wraps M3 KeyData with AES-KW under
    // the KEK before transmitting. Before AES-KW landed we rejected
    // such M3s with Unsupported. Now we run a second handshake whose
    // M3 ships the same GTK KDE wrapped under the freshly-derived
    // KEK, asserting that:
    //   1. AesKeyUnwrap succeeds on properly-wrapped data.
    //   2. The GTK comes out byte-identical to the pre-wrap KDE.
    //   3. A tampered ciphertext fails integrity, marks the context
    //      Failed, and increments mic_failures.
    {
        FourWayContext c2{};
        FourWayInit(c2, pmk, spa, aa, /*sha256=*/false, /*aes_cmac=*/false);
        auto pr_a = FourWayProcessIncoming(c2, m1_buf, m1_len);
        KASSERT(pr_a.has_value(), "net/wireless/fourway", "encrypted M1 process failed");
        KASSERT(c2.ptk_valid, "net/wireless/fourway", "encrypted PTK not derived after M1");

        // Wrap the same plaintext key data we used in the plaintext
        // M3 above. Wrap input must be a multiple of 8; m3_keydata
        // is 30 bytes (KDE 24 + GTK 16 already aligned -> wait,
        // 2 (header) + 6 (OUI/type/id/resv) + 16 (GTK) = 24 -> kd
        // ends at 24). Pad with the 802.11i 0xDD/0x00 pad to make
        // the input 32 bytes.
        u8 plain_kd[32];
        for (u32 i = 0; i < 24; ++i)
            plain_kd[i] = m3_keydata[i];
        // 802.11i KeyData pad: 0xDD then zeros.
        plain_kd[24] = 0xDD;
        for (u32 i = 25; i < 32; ++i)
            plain_kd[i] = 0x00;

        u8 wrapped_kd[40]; // 32 plaintext + 8 IV semi-block
        duetos::crypto::AesCtx wrap_ctx;
        duetos::crypto::AesKeyExpand128(wrap_ctx, FourWayKek(c2));
        const bool wrap_ok = duetos::crypto::AesKeyWrap(wrap_ctx, plain_kd, 32, wrapped_kd);
        KASSERT(wrap_ok, "net/wireless/fourway", "AES-KW wrap of synthetic key data failed");

        EapolKeyFrame m3e{};
        m3e.version = 2;
        m3e.packet_type = kEapolPacketTypeKey;
        m3e.descriptor_type = kEapolKeyDescriptorRsn;
        m3e.key_info = kKiKeyType | kKiAck | kKiMic | kKiInstall | kKiSecure | kKiEncrypted | kKdvHmacSha1;
        m3e.key_length = 16;
        for (u32 i = 0; i < 32; ++i)
            m3e.key_nonce[i] = m1.key_nonce[i];
        for (u32 i = 0; i < 8; ++i)
            m3e.replay_counter[i] = static_cast<u8>(i + 2);
        m3e.key_data_len = 40;
        m3e.key_data = wrapped_kd;

        u8 m3e_buf[256] = {};
        u32 m3e_len = 0;
        auto br3e = EapolKeyBuild(m3e, m3e_buf, sizeof(m3e_buf), &m3e_len);
        KASSERT(br3e.has_value(), "net/wireless/fourway", "encrypted M3 build failed");
        auto pp_e = EapolMicPatch(m3e_buf, m3e_len, FourWayKck(c2), kKckBytes, kKdvHmacSha1);
        KASSERT(pp_e.has_value(), "net/wireless/fourway", "encrypted M3 MIC patch failed");

        auto pr_e = FourWayProcessIncoming(c2, m3e_buf, m3e_len);
        KASSERT(pr_e.has_value(), "net/wireless/fourway", "encrypted M3 process failed");
        KASSERT(c2.state == FourWayState::AwaitingM4Ack, "net/wireless/fourway",
                "encrypted M3 didn't advance to AwaitingM4Ack");
        KASSERT(c2.gtk_valid && c2.gtk_len == 16, "net/wireless/fourway", "encrypted M3 didn't extract GTK");
        for (u32 i = 0; i < 16; ++i)
            KASSERT(c2.gtk[i] == static_cast<u8>(0xE0 + i), "net/wireless/fourway",
                    "encrypted M3 GTK bytes mismatch (unwrap output corrupt)");

        // Tampered-M3 negative case — flip a byte in the wrapped IV
        // and assert the unwrap integrity check rejects it. Use a
        // FRESH context (the previous one already advanced past M3).
        FourWayContext c3{};
        FourWayInit(c3, pmk, spa, aa, /*sha256=*/false, /*aes_cmac=*/false);
        auto pr_b = FourWayProcessIncoming(c3, m1_buf, m1_len);
        KASSERT(pr_b.has_value(), "net/wireless/fourway", "tampered-M3 prereq M1 failed");

        u8 wrapped_tamper[40];
        for (u32 i = 0; i < 40; ++i)
            wrapped_tamper[i] = wrapped_kd[i];
        wrapped_tamper[0] ^= 0x01; // flip a bit in the wrapped IV

        EapolKeyFrame m3t = m3e;
        m3t.key_data = wrapped_tamper;
        u8 m3t_buf[256] = {};
        u32 m3t_len = 0;
        auto br3t = EapolKeyBuild(m3t, m3t_buf, sizeof(m3t_buf), &m3t_len);
        KASSERT(br3t.has_value(), "net/wireless/fourway", "tampered M3 build failed");
        auto pp_t = EapolMicPatch(m3t_buf, m3t_len, FourWayKck(c3), kKckBytes, kKdvHmacSha1);
        KASSERT(pp_t.has_value(), "net/wireless/fourway", "tampered M3 MIC patch failed");
        const u32 mic_before = c3.mic_failures;
        auto pr_t = FourWayProcessIncoming(c3, m3t_buf, m3t_len);
        KASSERT(!pr_t.has_value(), "net/wireless/fourway", "tampered M3 was accepted (AES-KW integrity check broken)");
        KASSERT(c3.state == FourWayState::Failed, "net/wireless/fourway", "tampered M3 didn't move state to Failed");
        KASSERT(c3.mic_failures == mic_before + 1u, "net/wireless/fourway", "tampered M3 didn't bump mic_failures");
    }
    KLOG_INFO_A(::duetos::core::LogArea::Wireless, "net/wireless/fourway",
                "self-test OK (M1+M2+M3+M4 + GTK + MIC + encrypted M3 + tamper-detect verified)");
}

} // namespace duetos::net::wireless
