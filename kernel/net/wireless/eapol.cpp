#include "net/wireless/eapol.h"

#include "core/panic.h"
#include "log/klog.h"
#include "net/wireless/crypto/hmac.h"
#include "net/wireless/wifi_diag.h"

namespace duetos::net::wireless
{

namespace
{

u16 ReadBe16(const u8* buf, u32 off)
{
    return static_cast<u16>(static_cast<u16>(buf[off]) << 8) | static_cast<u16>(buf[off + 1]);
}

void WriteBe16(u8* buf, u32 off, u16 v)
{
    buf[off] = static_cast<u8>((v >> 8) & 0xFFu);
    buf[off + 1] = static_cast<u8>(v & 0xFFu);
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

// Offset of the MIC field within an EAPOL key body (i.e. after
// the 4-byte EAPOL header). Computed: 1 (descriptor_type) + 2
// (key_info) + 2 (key_length) + 8 (replay) + 32 (nonce) + 16
// (iv) + 8 (rsc) + 8 (reserved) = 77.
constexpr u32 kMicOffsetInBody = 1u + 2u + 2u + 8u + 32u + 16u + 8u + 8u;

} // namespace

::duetos::core::Result<void> EapolKeyParse(const u8* frame, u32 len, EapolKeyFrame* out)
{
    if (frame == nullptr || out == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    *out = {};
    if (len < kEapolHdrBytes + kEapolKeyFixedBytes)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};

    // EAPOL header (4 bytes).
    out->version = frame[0];
    out->packet_type = frame[1];
    out->body_length = ReadBe16(frame, 2);
    if (out->packet_type != kEapolPacketTypeKey)
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Wireless, "net/wireless/eapol", "parse: non-key EAPOL packet_type",
                     static_cast<u64>(out->packet_type));
        diag::RecordErr(diag::Layer::Eapol, "key-parse-bad-pkt", static_cast<u32>(::duetos::core::ErrorCode::Corrupt),
                        out->packet_type, 0, 0);
        return ::duetos::core::Err{::duetos::core::ErrorCode::Corrupt};
    }
    if (kEapolHdrBytes + static_cast<u32>(out->body_length) > len)
    {
        KLOG_WARN_2V("net/wireless/eapol", "parse: truncated body", "body_length", static_cast<u64>(out->body_length),
                     "frame_len", static_cast<u64>(len));
        diag::RecordErr(diag::Layer::Eapol, "key-parse-trunc", static_cast<u32>(::duetos::core::ErrorCode::Corrupt),
                        out->body_length, len, 0);
        return ::duetos::core::Err{::duetos::core::ErrorCode::Corrupt};
    }

    // EAPOL-Key body fields. Body starts at offset 4.
    const u8* body = frame + kEapolHdrBytes;
    u32 off = 0;
    out->descriptor_type = body[off++];
    out->key_info = ReadBe16(body, off);
    off += 2;
    out->key_length = ReadBe16(body, off);
    off += 2;
    CopyBytes(out->replay_counter, body + off, kEapolReplayBytes);
    off += kEapolReplayBytes;
    CopyBytes(out->key_nonce, body + off, kEapolNonceBytes);
    off += kEapolNonceBytes;
    CopyBytes(out->eapol_key_iv, body + off, kEapolIvBytes);
    off += kEapolIvBytes;
    CopyBytes(out->key_rsc, body + off, kEapolRscBytes);
    off += kEapolRscBytes;
    CopyBytes(out->reserved, body + off, 8);
    off += 8;
    CopyBytes(out->key_mic, body + off, kEapolMicBytes);
    off += kEapolMicBytes;
    out->key_data_len = ReadBe16(body, off);
    off += 2;

    if (off + out->key_data_len > out->body_length)
    {
        KLOG_WARN_2V("net/wireless/eapol", "parse: key_data overruns body", "key_data_len",
                     static_cast<u64>(out->key_data_len), "body_length", static_cast<u64>(out->body_length));
        diag::RecordErr(diag::Layer::Eapol, "key-parse-data-trunc",
                        static_cast<u32>(::duetos::core::ErrorCode::Corrupt), out->key_data_len, out->body_length, 0);
        return ::duetos::core::Err{::duetos::core::ErrorCode::Corrupt};
    }
    out->key_data = body + off;

    out->eapol_body = body;
    out->eapol_body_len = out->body_length;
    out->mic_offset_in_body = kMicOffsetInBody;

    diag::RecordOk(diag::Layer::Eapol, "key-parse-ok", out->key_info, out->key_data_len, out->descriptor_type);
    return ::duetos::core::Result<void>{};
}

::duetos::core::Result<void> EapolKeyBuild(const EapolKeyFrame& f, u8* out_buf, u32 cap, u32* out_len)
{
    if (out_buf == nullptr || out_len == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    const u32 body_len = kEapolKeyFixedBytes + f.key_data_len;
    const u32 frame_len = kEapolHdrBytes + body_len;
    if (frame_len > cap || f.key_data_len > kEapolKeyDataMaxBytes)
    {
        KLOG_WARN_2V("net/wireless/eapol", "build: capacity exceeded", "want", static_cast<u64>(frame_len), "cap",
                     static_cast<u64>(cap));
        diag::RecordErr(diag::Layer::Eapol, "key-build-cap",
                        static_cast<u32>(::duetos::core::ErrorCode::InvalidArgument), frame_len, cap, 0);
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    }

    out_buf[0] = f.version;
    out_buf[1] = kEapolPacketTypeKey;
    WriteBe16(out_buf, 2, static_cast<u16>(body_len));

    u8* body = out_buf + kEapolHdrBytes;
    u32 off = 0;
    body[off++] = f.descriptor_type;
    WriteBe16(body, off, f.key_info);
    off += 2;
    WriteBe16(body, off, f.key_length);
    off += 2;
    CopyBytes(body + off, f.replay_counter, kEapolReplayBytes);
    off += kEapolReplayBytes;
    CopyBytes(body + off, f.key_nonce, kEapolNonceBytes);
    off += kEapolNonceBytes;
    CopyBytes(body + off, f.eapol_key_iv, kEapolIvBytes);
    off += kEapolIvBytes;
    CopyBytes(body + off, f.key_rsc, kEapolRscBytes);
    off += kEapolRscBytes;
    CopyBytes(body + off, f.reserved, 8);
    off += 8;
    // MIC is intentionally zero — caller patches via EapolMicPatch.
    ZeroBytes(body + off, kEapolMicBytes);
    off += kEapolMicBytes;
    WriteBe16(body, off, f.key_data_len);
    off += 2;
    if (f.key_data != nullptr && f.key_data_len > 0)
        CopyBytes(body + off, f.key_data, f.key_data_len);

    *out_len = frame_len;
    diag::RecordOk(diag::Layer::Eapol, "key-build-ok", f.key_info, f.key_data_len, frame_len);
    return ::duetos::core::Result<void>{};
}

::duetos::core::Result<void> EapolMicPatch(u8* frame, u32 len, const u8* kck, u32 kck_len, u16 kdv)
{
    if (frame == nullptr || kck == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    if (len < kEapolHdrBytes + kEapolKeyFixedBytes)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};

    u8* body = frame + kEapolHdrBytes;
    const u32 body_len = ReadBe16(frame, 2);
    if (body_len > len - kEapolHdrBytes)
        return ::duetos::core::Err{::duetos::core::ErrorCode::Corrupt};

    // Zero the MIC field in-place before computing.
    ZeroBytes(body + kMicOffsetInBody, kEapolMicBytes);

    if (kdv == kKdvHmacSha1)
    {
        u8 mac[20];
        crypto::HmacSha1(kck, kck_len, body, body_len, mac);
        // EAPOL-Key MIC for HMAC-SHA1 is the first 16 bytes.
        for (u32 i = 0; i < kEapolMicBytes; ++i)
            body[kMicOffsetInBody + i] = mac[i];
        diag::RecordOk(diag::Layer::Eapol, "mic-patch-sha1", body_len, 0, 0);
        return ::duetos::core::Result<void>{};
    }
    // AES-CMAC MIC (KDV=3) needs an AES core; not implemented in
    // v0. Record + reject.
    KLOG_WARN_AV(::duetos::core::LogArea::Wireless, "net/wireless/eapol", "mic-patch: unsupported KDV (need AES-CMAC)",
                 static_cast<u64>(kdv));
    diag::RecordErr(diag::Layer::Eapol, "mic-patch-kdv-unsup", static_cast<u32>(::duetos::core::ErrorCode::Unsupported),
                    kdv, 0, 0);
    return ::duetos::core::Err{::duetos::core::ErrorCode::Unsupported};
}

::duetos::core::Result<void> EapolMicVerify(const u8* frame, u32 len, const u8* kck, u32 kck_len, u16 kdv)
{
    if (frame == nullptr || kck == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    if (len < kEapolHdrBytes + kEapolKeyFixedBytes)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};

    if (kdv != kKdvHmacSha1)
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Wireless, "net/wireless/eapol", "mic-verify: unsupported KDV",
                     static_cast<u64>(kdv));
        diag::RecordErr(diag::Layer::Eapol, "mic-verify-kdv-unsup",
                        static_cast<u32>(::duetos::core::ErrorCode::Unsupported), kdv, 0, 0);
        return ::duetos::core::Err{::duetos::core::ErrorCode::Unsupported};
    }

    // Build a working copy of the body with the MIC field zeroed.
    u8 work[kEapolKeyFixedBytes + kEapolKeyDataMaxBytes];
    const u32 body_len = ReadBe16(frame, 2);
    if (body_len > sizeof(work) || body_len > len - kEapolHdrBytes)
        return ::duetos::core::Err{::duetos::core::ErrorCode::Corrupt};

    const u8* body = frame + kEapolHdrBytes;
    for (u32 i = 0; i < body_len; ++i)
        work[i] = body[i];
    ZeroBytes(work + kMicOffsetInBody, kEapolMicBytes);

    u8 expected[20];
    crypto::HmacSha1(kck, kck_len, work, body_len, expected);
    for (u32 i = 0; i < kEapolMicBytes; ++i)
    {
        if (body[kMicOffsetInBody + i] != expected[i])
        {
            KLOG_WARN_AV(::duetos::core::LogArea::Wireless, "net/wireless/eapol", "mic-verify: byte mismatch at offset",
                         static_cast<u64>(i));
            diag::RecordErr(diag::Layer::Eapol, "mic-verify-fail", static_cast<u32>(::duetos::core::ErrorCode::Corrupt),
                            i, body_len, 0);
            return ::duetos::core::Err{::duetos::core::ErrorCode::Corrupt};
        }
    }
    diag::RecordOk(diag::Layer::Eapol, "mic-verify-ok", body_len, 0, 0);
    return ::duetos::core::Result<void>{};
}

void EapolSelfTest()
{
    KLOG_TRACE_SCOPE("net/wireless/eapol", "EapolSelfTest");
    KLOG_INFO_A(::duetos::core::LogArea::Wireless, "net/wireless/eapol", "self-test: build/patch/verify round-trip");
    // Build → patch (HMAC-SHA1) → verify round-trip.
    EapolKeyFrame in{};
    in.version = 2;
    in.packet_type = kEapolPacketTypeKey;
    in.descriptor_type = kEapolKeyDescriptorRsn;
    in.key_info = kKiKeyType | kKiAck | kKdvHmacSha1; // M1-shaped
    in.key_length = 16;
    in.key_data_len = 0;
    in.key_data = nullptr;
    for (u32 i = 0; i < kEapolReplayBytes; ++i)
        in.replay_counter[i] = static_cast<u8>(i);
    for (u32 i = 0; i < kEapolNonceBytes; ++i)
        in.key_nonce[i] = static_cast<u8>(0x10 + i);

    u8 frame[256] = {};
    u32 frame_len = 0;
    auto br = EapolKeyBuild(in, frame, sizeof(frame), &frame_len);
    KASSERT(br.has_value(), "net/wireless/eapol", "EAPOL build failed");
    KASSERT(frame_len == kEapolHdrBytes + kEapolKeyFixedBytes, "net/wireless/eapol", "EAPOL build bad length");

    u8 kck[16] = {};
    for (u32 i = 0; i < 16; ++i)
        kck[i] = static_cast<u8>(0xA0 + i);
    auto pr = EapolMicPatch(frame, frame_len, kck, 16, kKdvHmacSha1);
    KASSERT(pr.has_value(), "net/wireless/eapol", "EAPOL MIC patch failed");

    auto vr = EapolMicVerify(frame, frame_len, kck, 16, kKdvHmacSha1);
    KASSERT(vr.has_value(), "net/wireless/eapol", "EAPOL MIC verify failed");

    // Tamper one byte → MIC must fail.
    frame[kEapolHdrBytes + 5] ^= 0x01;
    auto vr2 = EapolMicVerify(frame, frame_len, kck, 16, kKdvHmacSha1);
    KASSERT(!vr2.has_value(), "net/wireless/eapol", "EAPOL MIC verify accepted tampered frame");
    frame[kEapolHdrBytes + 5] ^= 0x01;

    // Parse round-trip — recover the field values.
    EapolKeyFrame out{};
    auto rp = EapolKeyParse(frame, frame_len, &out);
    KASSERT(rp.has_value(), "net/wireless/eapol", "EAPOL parse failed");
    KASSERT(out.descriptor_type == kEapolKeyDescriptorRsn, "net/wireless/eapol", "EAPOL parse desc-type");
    KASSERT(out.key_length == 16, "net/wireless/eapol", "EAPOL parse key-length");
    KASSERT(out.key_info == in.key_info, "net/wireless/eapol", "EAPOL parse key-info");
    bool nonce_ok = true;
    for (u32 i = 0; i < kEapolNonceBytes; ++i)
        if (out.key_nonce[i] != in.key_nonce[i])
            nonce_ok = false;
    KASSERT(nonce_ok, "net/wireless/eapol", "EAPOL parse nonce mismatch");
    KLOG_INFO_A(::duetos::core::LogArea::Wireless, "net/wireless/eapol",
                "self-test OK (build + patch + verify + parse)");
}

} // namespace duetos::net::wireless
