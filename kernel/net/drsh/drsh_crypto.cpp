#include "net/drsh/drsh_internal.h"

#include "crypto/aes.h"
#include "crypto/hmac.h"

/*
 * DRSH — encryption + integrity primitives for the on-wire framer.
 *
 * AES-128-CTR for confidentiality, HMAC-SHA256-128 (truncated) for
 * integrity. Encrypt-then-MAC, MAC verified before plaintext is
 * touched, MAC covers the cleartext header so an attacker can't
 * lie about (type, channel, length) and slip past the framer.
 *
 * Counter discipline:
 *   - Each direction has its own counter (ctr_s2c, ctr_c2s) of
 *     16 bytes — the AES block size.
 *   - The counter is a big-endian integer that increments by
 *     ceil(payload_len / 16) AES blocks per frame. We never reuse
 *     a (key, counter) pair: the increment is done strictly AFTER
 *     the keystream bytes are generated, so a 1-byte frame burns
 *     one counter step and a 4096-byte frame burns 256.
 *   - Reuse would be catastrophic (CTR mode is malleable, and
 *     two ciphertexts under the same keystream XOR to plaintext
 *     XOR plaintext). Counters are zeroed only when a session
 *     starts; DrshServerStop wipes them.
 *
 * Frame send/recv lives here too — it's the only place that
 * touches both the AES + HMAC primitives, so keeping it in one
 * TU avoids a header dance.
 */

namespace duetos::net::drsh::internal
{

namespace
{

inline void IncrementCounterBlocks(u8 ctr[kDrshCtrBytes], u32 blocks)
{
    // CTR counter is big-endian. We increment by `blocks` with carry.
    u32 carry = blocks;
    for (i32 i = static_cast<i32>(kDrshCtrBytes) - 1; i >= 0 && carry != 0; --i)
    {
        const u32 sum = static_cast<u32>(ctr[i]) + (carry & 0xFFu);
        ctr[i] = static_cast<u8>(sum & 0xFFu);
        carry = (carry >> 8) + (sum >> 8);
    }
    // Overflow past the counter top is silently absorbed — that's
    // fine because a single session reaching 2^128 blocks is not
    // physically reachable; the guarantee we need is "monotone
    // within session," not "never wraps."
}

} // namespace

void BuildFrameHeader(u8 type, u8 channel, u16 payload_len, u8 out_hdr[kDrshFrameHdrBytes])
{
    out_hdr[0] = type;
    out_hdr[1] = channel;
    // big-endian length so a host-side debugger sees the bytes in
    // the order the protocol talks about them.
    out_hdr[2] = static_cast<u8>((payload_len >> 8) & 0xFFu);
    out_hdr[3] = static_cast<u8>(payload_len & 0xFFu);
}

void ApplyAesCtr(crypto::AesCtx& ctx, u8 ctr[kDrshCtrBytes], u8* buf, u32 len)
{
    // CTR streaming over `len` bytes. We generate the keystream
    // block-by-block from the current counter, XOR it into `buf`,
    // then advance the counter past the consumed blocks.
    u8 block_in[crypto::kAesBlockBytes];
    u8 block_out[crypto::kAesBlockBytes];
    u32 done = 0;
    u32 blocks_consumed = 0;
    while (done < len)
    {
        // Build the keystream block input: current counter exactly.
        for (u32 i = 0; i < kDrshCtrBytes; ++i)
            block_in[i] = ctr[i];
        crypto::AesEncryptBlock(ctx, block_in, block_out);

        // Advance counter by exactly one for the NEXT block's
        // input. Doing this inside the per-block loop is simpler
        // than the bulk-increment route and matches the textbook
        // CTR construction. We track total blocks_consumed only
        // for telemetry / asserts.
        IncrementCounterBlocks(ctr, 1);
        ++blocks_consumed;

        const u32 chunk = (len - done) > crypto::kAesBlockBytes ? crypto::kAesBlockBytes : (len - done);
        for (u32 i = 0; i < chunk; ++i)
            buf[done + i] ^= block_out[i];
        done += chunk;
    }
    (void)blocks_consumed; // future probe / metrics hook
}

void ComputeFrameMac(const u8 mac_key[kDrshMacKeyBytes], const u8 hdr[kDrshFrameHdrBytes], const u8* payload,
                     u32 payload_len, u8* out_tag, u32 tag_bytes)
{
    // HMAC-SHA256 over (hdr || ciphertext). Standard HMAC produces
    // 32 bytes; we truncate to `tag_bytes` (typically 16) for the
    // wire. Truncation to 128 bits is the same security level as
    // AES-128 so we're not the weak link. The full 32 bytes are
    // computed in a scratch buffer because the HMAC API only emits
    // the full digest.
    u8 scratch[crypto::kSha256DigestBytes];
    // HmacSha256 takes one contiguous data buffer; for our two-part
    // input (header || payload) we materialise a small staging
    // buffer. One static is safe because the DRSH service is single-
    // task in v0 — DrshServerStart spawns exactly one server task
    // and one session is active at a time.
    static u8 staging[kDrshFrameHdrBytes + kDrshMaxPayload];
    for (u32 i = 0; i < kDrshFrameHdrBytes; ++i)
        staging[i] = hdr[i];
    for (u32 i = 0; i < payload_len; ++i)
        staging[kDrshFrameHdrBytes + i] = payload[i];
    crypto::HmacSha256(mac_key, kDrshMacKeyBytes, staging, kDrshFrameHdrBytes + payload_len, scratch);
    for (u32 i = 0; i < tag_bytes && i < crypto::kSha256DigestBytes; ++i)
        out_tag[i] = scratch[i];
}

bool ConstantTimeEquals(const u8* a, const u8* b, u32 len)
{
    // Branch-free compare. Diff stays 0 iff every byte matches.
    // Important against MAC-tag oracle attacks: an early-exit
    // memcmp leaks the prefix length, which an adversary can
    // amplify into a forgery over many trials.
    u32 diff = 0;
    for (u32 i = 0; i < len; ++i)
        diff |= static_cast<u32>(a[i] ^ b[i]);
    return diff == 0;
}

bool SendFrame(DrshTransport& t, DrshSession& s, u8 type, u8 channel, const u8* payload, u32 payload_len)
{
    if (payload_len > kDrshMaxPayload)
        return false;

    u8 hdr[kDrshFrameHdrBytes];
    BuildFrameHeader(type, channel, static_cast<u16>(payload_len), hdr);

    // Copy plaintext into a buffer we encrypt in place. We can't
    // mutate the caller's `payload` because some callers reuse the
    // same buffer for retries / logging.
    static u8 ct_buf[kDrshMaxPayload];
    for (u32 i = 0; i < payload_len; ++i)
        ct_buf[i] = payload[i];

    if (s.authenticated && payload_len > 0)
        ApplyAesCtr(s.aes_enc, s.ctr_s2c, ct_buf, payload_len);

    u8 mac[kDrshHmacTagBytes];
    if (s.authenticated)
        ComputeFrameMac(s.mac_key, hdr, ct_buf, payload_len, mac, kDrshHmacTagBytes);
    else
        // Pre-auth frames (HELLO / CHALLENGE / AUTH) are unauthenticated:
        // before keys exist we cannot HMAC anything. Send a zero tag
        // so the wire frame size is constant for the framer. The
        // handshake script doesn't rely on the tag bytes for those
        // frame types; their content is bound into the post-auth
        // session keys via the KDF instead.
        for (u32 i = 0; i < kDrshHmacTagBytes; ++i)
            mac[i] = 0;

    if (!t.WriteAll(t.ctx, hdr, kDrshFrameHdrBytes))
        return false;
    if (payload_len > 0 && !t.WriteAll(t.ctx, ct_buf, payload_len))
        return false;
    if (!t.WriteAll(t.ctx, mac, kDrshHmacTagBytes))
        return false;

    s.frames_tx += 1;
    s.bytes_tx += kDrshFrameHdrBytes + payload_len + kDrshHmacTagBytes;
    return true;
}

bool RecvFrame(DrshTransport& t, DrshSession& s, u8* out_type, u8* out_channel, u8* out_payload, u32* out_payload_len)
{
    u8 hdr[kDrshFrameHdrBytes];
    if (!t.ReadExact(t.ctx, hdr, kDrshFrameHdrBytes))
        return false;

    const u8 type = hdr[0];
    const u8 channel = hdr[1];
    const u16 plen = static_cast<u16>((static_cast<u16>(hdr[2]) << 8) | static_cast<u16>(hdr[3]));
    if (plen > kDrshMaxPayload)
        return false;

    static u8 ct_buf[kDrshMaxPayload];
    if (plen > 0 && !t.ReadExact(t.ctx, ct_buf, plen))
        return false;

    u8 mac_recv[kDrshHmacTagBytes];
    if (!t.ReadExact(t.ctx, mac_recv, kDrshHmacTagBytes))
        return false;

    if (s.authenticated)
    {
        u8 mac_expect[kDrshHmacTagBytes];
        ComputeFrameMac(s.mac_key, hdr, ct_buf, plen, mac_expect, kDrshHmacTagBytes);
        if (!ConstantTimeEquals(mac_recv, mac_expect, kDrshHmacTagBytes))
            return false;
        if (plen > 0)
            ApplyAesCtr(s.aes_enc, s.ctr_c2s, ct_buf, plen);
    }
    // Pre-auth: mac is zero by convention; do not enforce.

    *out_type = type;
    *out_channel = channel;
    *out_payload_len = plen;
    for (u32 i = 0; i < plen; ++i)
        out_payload[i] = ct_buf[i];

    s.frames_rx += 1;
    s.bytes_rx += kDrshFrameHdrBytes + plen + kDrshHmacTagBytes;
    return true;
}

} // namespace duetos::net::drsh::internal
