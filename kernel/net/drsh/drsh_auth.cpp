#include "net/drsh/drsh_internal.h"

#include "crypto/aes.h"
#include "crypto/hmac.h"
#include "crypto/pbkdf2.h"
#include "log/klog.h"
#include "util/random.h"

/*
 * DRSH — handshake (server side) + session-key derivation.
 *
 * The handshake is small enough to keep entirely in this TU. See the
 * top-of-drsh.h comment for the wire-level script; this file is the
 * authoritative implementation.
 *
 * Auth security properties:
 *   - Password never crosses the wire — only an HMAC under a PBKDF2-
 *     derived PMK, salted by the server-supplied nonce. PBKDF2-HMAC-
 *     SHA256 with 4096 iters at the time of writing isn't bcrypt /
 *     argon2 territory, but it's the strongest KDF we have in-tree
 *     and is wildly more expensive than the plain "compare digest"
 *     telnet-shaped designs we want to NOT inherit.
 *   - Two nonces (one from each side) feed the auth response and the
 *     KDF, so a passive replayer can't bind a recorded transcript to
 *     a fresh session.
 *   - Constant-time tag compare on the AUTH check (ConstantTimeEquals
 *     in drsh_crypto.cpp) — same shape as the per-frame MAC check.
 *
 * Failure mode discipline: any deviation from the script (length,
 * magic, type) returns false. We do NOT distinguish between "wrong
 * password" and "malformed frame" on the wire — a generic
 * kDrshFrameAuthFail covers both, denying an active attacker a free
 * oracle on which step they tripped on.
 */

namespace duetos::net::drsh::internal
{

namespace
{

// HMAC-SHA256 single-shot wrapper that lets us prefix a literal
// tag, a nonce, and (optionally) a body without juggling a context.
// Inputs are concatenated.
void HmacConcat3(const u8* key, u32 key_len, const u8* a, u32 a_len, const u8* b, u32 b_len, const u8* c, u32 c_len,
                 u8 out[crypto::kSha256DigestBytes])
{
    static u8 staging[256 + kDrshNonceBytes * 2 + kDrshChallengeBytes];
    u32 off = 0;
    for (u32 i = 0; i < a_len && off < sizeof(staging); ++i, ++off)
        staging[off] = a[i];
    for (u32 i = 0; i < b_len && off < sizeof(staging); ++i, ++off)
        staging[off] = b[i];
    for (u32 i = 0; i < c_len && off < sizeof(staging); ++i, ++off)
        staging[off] = c[i];
    crypto::HmacSha256(key, key_len, staging, off, out);
}

void DerivePmk(const u8* password, u32 password_len, const u8 nonce_s[kDrshNonceBytes], u8 out_pmk[kDrshPmkBytes])
{
    // Salt: "DRSH-PMK" || nonce_s. Server nonce is sufficient salt;
    // including the client nonce here would force re-running the
    // PBKDF2 4096-iter inner HMAC loop on every connection from the
    // server's perspective, and the security gain is nil because the
    // session keys already fold in BOTH nonces below.
    static u8 salt[8 + kDrshNonceBytes];
    const char tag[8] = {'D', 'R', 'S', 'H', '-', 'P', 'M', 'K'};
    for (u32 i = 0; i < 8; ++i)
        salt[i] = static_cast<u8>(tag[i]);
    for (u32 i = 0; i < kDrshNonceBytes; ++i)
        salt[8 + i] = nonce_s[i];
    crypto::Pbkdf2HmacSha256(password, password_len, salt, sizeof(salt), kDrshPbkdfIters, out_pmk, kDrshPmkBytes);
}

void ExpectedAuthResponse(const u8 pmk[kDrshPmkBytes], const u8 nonce_s[kDrshNonceBytes],
                          const u8 nonce_c[kDrshNonceBytes], const u8 challenge[kDrshChallengeBytes],
                          u8 out_resp[crypto::kSha256DigestBytes])
{
    // "DRSH-AUTH" prefix binds the response to this protocol's
    // context, so the same PMK can't be replayed against some other
    // HMAC-shaped construction in the kernel (e.g. WPA's PMK→PTK).
    const u8 prefix[9] = {'D', 'R', 'S', 'H', '-', 'A', 'U', 'T', 'H'};
    static u8 staging[9 + kDrshNonceBytes * 2 + kDrshChallengeBytes];
    u32 off = 0;
    for (u32 i = 0; i < 9; ++i, ++off)
        staging[off] = prefix[i];
    for (u32 i = 0; i < kDrshNonceBytes; ++i, ++off)
        staging[off] = nonce_s[i];
    for (u32 i = 0; i < kDrshNonceBytes; ++i, ++off)
        staging[off] = nonce_c[i];
    for (u32 i = 0; i < kDrshChallengeBytes; ++i, ++off)
        staging[off] = challenge[i];
    crypto::HmacSha256(pmk, kDrshPmkBytes, staging, off, out_resp);
}

// Send an unauthenticated pre-handshake frame (HELLO, CHALLENGE,
// AUTH, AUTH_OK, AUTH_FAIL). We piggyback on SendFrame's "session
// not authenticated → zero MAC" path so the framing code stays
// single-source.
bool SendPlainFrame(DrshTransport& t, DrshSession& s, u8 type, const u8* payload, u32 payload_len)
{
    return SendFrame(t, s, type, kDrshChannelControl, payload, payload_len);
}

bool RecvPlainFrame(DrshTransport& t, DrshSession& s, u8 expected_type, u8* out_payload, u32* out_payload_len)
{
    u8 type = 0;
    u8 ch = 0;
    if (!RecvFrame(t, s, &type, &ch, out_payload, out_payload_len))
        return false;
    if (type != expected_type)
        return false;
    if (ch != kDrshChannelControl)
        return false;
    return true;
}

} // namespace

void DeriveSessionKeys(const u8 pmk[kDrshPmkBytes], const u8 nonce_s[kDrshNonceBytes],
                       const u8 nonce_c[kDrshNonceBytes], DrshSession& out_session)
{
    // Each of the four key materials is HMAC(pmk, tag || ns || nc),
    // truncated to the byte-length the field needs.
    auto derive = [&](const char* tag9, u8* out, u32 out_len)
    {
        u8 digest[crypto::kSha256DigestBytes];
        // tag9 is exactly 9 bytes: "DRSH-XYZw" — the four user-
        // visible callers ("DRSH-ENC", "DRSH-MAC", "DRSH-IVS",
        // "DRSH-IVC") are all 8 chars; we pass 8 and pin the
        // count below.
        u8 tag_buf[8];
        for (u32 i = 0; i < 8; ++i)
            tag_buf[i] = static_cast<u8>(tag9[i]);
        HmacConcat3(pmk, kDrshPmkBytes, tag_buf, 8, nonce_s, kDrshNonceBytes, nonce_c, kDrshNonceBytes, digest);
        for (u32 i = 0; i < out_len && i < crypto::kSha256DigestBytes; ++i)
            out[i] = digest[i];
    };

    u8 enc_key[kDrshEncKeyBytes];
    derive("DRSH-ENC", enc_key, kDrshEncKeyBytes);
    crypto::AesKeyExpand128(out_session.aes_enc, enc_key);

    derive("DRSH-MAC", out_session.mac_key, kDrshMacKeyBytes);
    derive("DRSH-IVS", out_session.ctr_s2c, kDrshCtrBytes);
    derive("DRSH-IVC", out_session.ctr_c2s, kDrshCtrBytes);
    out_session.frames_tx = 0;
    out_session.frames_rx = 0;
    out_session.bytes_tx = 0;
    out_session.bytes_rx = 0;
}

bool ServerHandshake(DrshTransport& t, const u8* password, u32 password_len, DrshSession& out_session)
{
    // Session struct comes in zeroed.
    out_session.authenticated = false;

    // ----------------------------- Hello exchange.
    u8 buf[kDrshMaxPayload];
    u32 plen = 0;
    // Client hello: { magic(4 BE) | version(2 BE) | nonce_c(16) } = 22 bytes.
    if (!RecvPlainFrame(t, out_session, kDrshFrameHelloC, buf, &plen))
        return false;
    if (plen != 4 + 2 + kDrshNonceBytes)
        return false;
    const u32 magic = (static_cast<u32>(buf[0]) << 24) | (static_cast<u32>(buf[1]) << 16) |
                      (static_cast<u32>(buf[2]) << 8) | static_cast<u32>(buf[3]);
    const u16 version = static_cast<u16>((static_cast<u16>(buf[4]) << 8) | static_cast<u16>(buf[5]));
    if (magic != kDrshMagic || version != kDrshVersion)
        return false;
    u8 nonce_c[kDrshNonceBytes];
    for (u32 i = 0; i < kDrshNonceBytes; ++i)
        nonce_c[i] = buf[6 + i];

    // Server hello: { magic | version | nonce_s }.
    u8 nonce_s[kDrshNonceBytes];
    duetos::core::RandomFillBytes(nonce_s, kDrshNonceBytes);
    u8 hello_s[4 + 2 + kDrshNonceBytes];
    hello_s[0] = static_cast<u8>((kDrshMagic >> 24) & 0xFFu);
    hello_s[1] = static_cast<u8>((kDrshMagic >> 16) & 0xFFu);
    hello_s[2] = static_cast<u8>((kDrshMagic >> 8) & 0xFFu);
    hello_s[3] = static_cast<u8>(kDrshMagic & 0xFFu);
    hello_s[4] = static_cast<u8>((kDrshVersion >> 8) & 0xFFu);
    hello_s[5] = static_cast<u8>(kDrshVersion & 0xFFu);
    for (u32 i = 0; i < kDrshNonceBytes; ++i)
        hello_s[6 + i] = nonce_s[i];
    if (!SendPlainFrame(t, out_session, kDrshFrameHelloS, hello_s, sizeof(hello_s)))
        return false;

    // ----------------------------- Challenge.
    u8 challenge[kDrshChallengeBytes];
    duetos::core::RandomFillBytes(challenge, kDrshChallengeBytes);
    if (!SendPlainFrame(t, out_session, kDrshFrameChallenge, challenge, kDrshChallengeBytes))
        return false;

    // ----------------------------- Auth response.
    if (!RecvPlainFrame(t, out_session, kDrshFrameAuth, buf, &plen))
        return false;
    if (plen != crypto::kSha256DigestBytes)
        return false;

    u8 pmk[kDrshPmkBytes];
    DerivePmk(password, password_len, nonce_s, pmk);
    u8 expected[crypto::kSha256DigestBytes];
    ExpectedAuthResponse(pmk, nonce_s, nonce_c, challenge, expected);
    if (!ConstantTimeEquals(buf, expected, crypto::kSha256DigestBytes))
    {
        // Burn one heartbeat so timing isn't dominated by the PBKDF2
        // cost itself — a passive timer can still observe "AUTH_FAIL
        // came back fast" vs "AUTH_OK came back slow," but the gap
        // is bounded by HMAC-vs-AES-keysched, not by 4096 PBKDF2
        // iterations.
        (void)SendPlainFrame(t, out_session, kDrshFrameAuthFail, nullptr, 0);
        KLOG_WARN("net/drsh", "auth failed (bad response)");
        return false;
    }

    // ----------------------------- Promote to authenticated.
    DeriveSessionKeys(pmk, nonce_s, nonce_c, out_session);
    out_session.authenticated = true;
    if (!SendPlainFrame(t, out_session, kDrshFrameAuthOk, nullptr, 0))
        return false;

    KLOG_INFO("net/drsh", "session authenticated");
    return true;
}

} // namespace duetos::net::drsh::internal
