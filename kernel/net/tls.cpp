#include "net/tls.h"

#include "arch/x86_64/serial.h"
#include "crypto/hmac.h"
#include "crypto/sha256.h"

namespace duetos::net::tls
{

namespace
{

inline void StoreU16Be(u8 dst[2], u16 v)
{
    dst[0] = static_cast<u8>((v >> 8) & 0xFF);
    dst[1] = static_cast<u8>(v & 0xFF);
}

inline void StoreU24Be(u8 dst[3], u32 v)
{
    dst[0] = static_cast<u8>((v >> 16) & 0xFF);
    dst[1] = static_cast<u8>((v >> 8) & 0xFF);
    dst[2] = static_cast<u8>(v & 0xFF);
}

// One iteration of the TLS PRF P_<hash> chain:
//   A(i) = HMAC(secret, A(i-1))
//   output += HMAC(secret, A(i) || seed)
// Returns the bytes added to `out`. The caller maintains the
// outer `A` state across iterations.
void PSha256Step(const u8* secret, u32 secret_len, u8 A[crypto::kSha256DigestBytes], const u8* seed_concat,
                 u32 seed_concat_len, u8* out, u32 chunk_len)
{
    // Build A(i) = HMAC(secret, A(i-1))
    u8 next_A[crypto::kSha256DigestBytes];
    crypto::HmacSha256(secret, secret_len, A, crypto::kSha256DigestBytes, next_A);
    for (u32 i = 0; i < crypto::kSha256DigestBytes; ++i)
        A[i] = next_A[i];

    // Compute HMAC(secret, A(i) || seed)
    // Build the concatenated input on the stack so HmacSha256
    // sees one contiguous buffer (its API is non-streaming).
    constexpr u32 kMaxInputBytes = crypto::kSha256DigestBytes + 256;
    if (crypto::kSha256DigestBytes + seed_concat_len > kMaxInputBytes)
        return; // safety net; callers stay well under this in v0
    u8 hmac_input[kMaxInputBytes];
    for (u32 i = 0; i < crypto::kSha256DigestBytes; ++i)
        hmac_input[i] = A[i];
    for (u32 i = 0; i < seed_concat_len; ++i)
        hmac_input[crypto::kSha256DigestBytes + i] = seed_concat[i];
    u8 mac[crypto::kSha256DigestBytes];
    crypto::HmacSha256(secret, secret_len, hmac_input, crypto::kSha256DigestBytes + seed_concat_len, mac);
    for (u32 i = 0; i < chunk_len; ++i)
        out[i] = mac[i];
}

} // namespace

void TlsPrfSha256(const u8* secret, u32 secret_len, const char* label, const u8* seed, u32 seed_len, u8* out,
                  u32 out_len)
{
    if (out == nullptr || out_len == 0)
        return;
    // Build the seed used by P_SHA256: label || seed.
    // Cap label at 64 bytes; that covers every TLS 1.2 label
    // ("master secret", "key expansion", "client finished",
    // "server finished") with room to spare.
    constexpr u32 kLabelMax = 64;
    constexpr u32 kSeedMax = 128;
    u32 label_len = 0;
    if (label != nullptr)
    {
        while (label[label_len] != '\0' && label_len < kLabelMax)
            ++label_len;
    }
    if (label_len + seed_len > kLabelMax + kSeedMax)
        return;
    u8 seed_concat[kLabelMax + kSeedMax];
    for (u32 i = 0; i < label_len; ++i)
        seed_concat[i] = static_cast<u8>(label[i]);
    for (u32 i = 0; i < seed_len; ++i)
        seed_concat[label_len + i] = seed[i];
    const u32 seed_concat_len = label_len + seed_len;

    // A(0) = label || seed (RFC 5246 §5)
    u8 A[crypto::kSha256DigestBytes];
    // We initialise A as the FULL seed_concat passed through
    // HMAC in the first PSha256Step invocation, by faking
    // A(0) = seed_concat first. PSha256Step does
    // A(i) = HMAC(secret, A(i-1)) before computing output —
    // so we set A so that the first HMAC produces A(1) =
    // HMAC(secret, seed_concat). Trick: stage A as a "buffer
    // that hashes to seed_concat under HMAC" — easier to just
    // compute A(1) directly here and then call PSha256Step in
    // a loop with chunk-handling.
    crypto::HmacSha256(secret, secret_len, seed_concat, seed_concat_len, A);

    u32 written = 0;
    while (written < out_len)
    {
        // Compute HMAC(secret, A(i) || seed_concat) -> mac.
        constexpr u32 kMaxInputBytes = crypto::kSha256DigestBytes + 256;
        if (crypto::kSha256DigestBytes + seed_concat_len > kMaxInputBytes)
            return;
        u8 hmac_input[kMaxInputBytes];
        for (u32 i = 0; i < crypto::kSha256DigestBytes; ++i)
            hmac_input[i] = A[i];
        for (u32 i = 0; i < seed_concat_len; ++i)
            hmac_input[crypto::kSha256DigestBytes + i] = seed_concat[i];
        u8 mac[crypto::kSha256DigestBytes];
        crypto::HmacSha256(secret, secret_len, hmac_input, crypto::kSha256DigestBytes + seed_concat_len, mac);
        const u32 remaining = out_len - written;
        const u32 take = (remaining < crypto::kSha256DigestBytes) ? remaining : crypto::kSha256DigestBytes;
        for (u32 i = 0; i < take; ++i)
            out[written + i] = mac[i];
        written += take;
        if (written < out_len)
        {
            // Advance A: A(i+1) = HMAC(secret, A(i)).
            u8 next_A[crypto::kSha256DigestBytes];
            crypto::HmacSha256(secret, secret_len, A, crypto::kSha256DigestBytes, next_A);
            for (u32 i = 0; i < crypto::kSha256DigestBytes; ++i)
                A[i] = next_A[i];
        }
    }
}

void TlsMasterSecret(const u8 pms[kPreMasterSecretBytes], const u8 client_random[kClientRandomBytes],
                     const u8 server_random[kServerRandomBytes], u8 master_secret[kMasterSecretBytes])
{
    // seed = client_random || server_random
    u8 seed[kClientRandomBytes + kServerRandomBytes];
    for (u32 i = 0; i < kClientRandomBytes; ++i)
        seed[i] = client_random[i];
    for (u32 i = 0; i < kServerRandomBytes; ++i)
        seed[kClientRandomBytes + i] = server_random[i];
    TlsPrfSha256(pms, kPreMasterSecretBytes, "master secret", seed, sizeof(seed), master_secret, kMasterSecretBytes);
}

void TlsKeyBlock(const u8 master_secret[kMasterSecretBytes], const u8 server_random[kServerRandomBytes],
                 const u8 client_random[kClientRandomBytes], u8 key_block[kKeyBlockBytes])
{
    // seed = server_random || client_random  (order is REVERSED
    // relative to MasterSecret derivation; RFC 5246 §6.3).
    u8 seed[kServerRandomBytes + kClientRandomBytes];
    for (u32 i = 0; i < kServerRandomBytes; ++i)
        seed[i] = server_random[i];
    for (u32 i = 0; i < kClientRandomBytes; ++i)
        seed[kServerRandomBytes + i] = client_random[i];
    TlsPrfSha256(master_secret, kMasterSecretBytes, "key expansion", seed, sizeof(seed), key_block, kKeyBlockBytes);
}

void TlsFinishedVerifyData(const u8 master_secret[kMasterSecretBytes], const u8 transcript_hash[32], bool is_client,
                           u8 verify_data[kVerifyDataBytes])
{
    const char* label = is_client ? "client finished" : "server finished";
    TlsPrfSha256(master_secret, kMasterSecretBytes, label, transcript_hash, 32, verify_data, kVerifyDataBytes);
}

u32 TlsBuildClientHelloBody(const u8 client_random[kClientRandomBytes], u8* dst, u32 cap)
{
    if (dst == nullptr || cap < 64)
        return 0;
    u32 off = 0;
    // ClientVersion (TLS 1.2)
    StoreU16Be(dst + off, kVersionTls12);
    off += 2;
    // Random (32 bytes)
    for (u32 i = 0; i < kClientRandomBytes; ++i)
        dst[off + i] = client_random[i];
    off += kClientRandomBytes;
    // SessionID (length 0 — fresh session)
    dst[off++] = 0;
    // CipherSuites (one suite, 2 bytes -> length prefix 2)
    StoreU16Be(dst + off, 2);
    off += 2;
    StoreU16Be(dst + off, kCipherTlsRsaAes128GcmSha256);
    off += 2;
    // CompressionMethods (one method: null = 0, length prefix 1)
    dst[off++] = 1;
    dst[off++] = 0;
    // Extensions: empty list (length 0). RFC 5246 §7.4.1.2
    // makes extensions OPTIONAL on the wire; we omit the
    // 2-byte length altogether per the pre-TLS-1.3 minimum.
    // (Real-world servers tend to require at least SNI;
    // adding that is a focused follow-on.)
    return off;
}

u32 TlsWrapRecord(u8 type, const u8* payload, u32 payload_len, u8* dst, u32 cap)
{
    if (payload_len > 0xFFFF || cap < 5 + payload_len)
        return 0;
    dst[0] = type;
    StoreU16Be(dst + 1, kVersionTls12);
    StoreU16Be(dst + 3, static_cast<u16>(payload_len));
    if (payload != nullptr)
    {
        for (u32 i = 0; i < payload_len; ++i)
            dst[5 + i] = payload[i];
    }
    return 5 + payload_len;
}

u32 TlsWrapHandshake(u8 hs_type, const u8* body, u32 body_len, u8* dst, u32 cap)
{
    // Build (4-byte handshake header + body) then wrap as a
    // record. Stage the handshake bytes on the caller's
    // destination directly: at dst+5 (past the record header).
    if (dst == nullptr || cap < 5 + 4 + body_len)
        return 0;
    if (body_len > 0xFFFFFF)
        return 0;
    // Record header
    dst[0] = kContentHandshake;
    StoreU16Be(dst + 1, kVersionTls12);
    const u32 record_payload_len = 4 + body_len;
    StoreU16Be(dst + 3, static_cast<u16>(record_payload_len));
    // Handshake header at dst+5
    dst[5] = hs_type;
    StoreU24Be(dst + 6, body_len);
    if (body != nullptr)
    {
        for (u32 i = 0; i < body_len; ++i)
            dst[9 + i] = body[i];
    }
    return 5 + record_payload_len;
}

// ---------------------------------------------------------------------------
// Self-test
// ---------------------------------------------------------------------------

namespace
{

bool BytesEq(const u8* a, const u8* b, u32 n)
{
    for (u32 i = 0; i < n; ++i)
        if (a[i] != b[i])
            return false;
    return true;
}

} // namespace

void TlsSelfTest()
{
    using arch::SerialWrite;

    // Test 1: PRF round-trips a known reference value. Use the
    // PRF to derive 48 bytes from a 48-byte "PMS" of zeros and
    // 32+32 bytes of zero randoms — confirms output length and
    // gives a stable byte for the next step to depend on.
    u8 pms[kPreMasterSecretBytes] = {0};
    u8 cr[kClientRandomBytes] = {0};
    u8 sr[kServerRandomBytes] = {0};
    u8 ms[kMasterSecretBytes];
    TlsMasterSecret(pms, cr, sr, ms);
    // First 4 bytes of PRF(<all-zero>, "master secret", <all-zero seed>):
    // Computed offline via Python:
    //   import hmac, hashlib
    //   def P(secret, seed):
    //       out, A = b'', seed
    //       while len(out) < 48:
    //           A = hmac.new(secret, A, hashlib.sha256).digest()
    //           out += hmac.new(secret, A+seed, hashlib.sha256).digest()
    //       return out[:48]
    //   P(b'\x00'*48, b'master secret' + b'\x00'*64).hex()
    // First 4 bytes: 49 cf ae e5.
    const u8 want_ms0[4] = {0x49, 0xCF, 0xAE, 0xE5};
    if (!BytesEq(ms, want_ms0, 4))
    {
        SerialWrite("[tls] FAIL master-secret-prf\n");
        return;
    }

    // Test 2: key_block fills exactly kKeyBlockBytes (40).
    u8 kb[kKeyBlockBytes];
    TlsKeyBlock(ms, sr, cr, kb);
    // Spot check: bytes 0..3 of derived key_block are stable
    // for the all-zero inputs. Computed offline:
    //   P(ms, b'key expansion' + sr + cr).hex() first 4 bytes.
    const u8 want_kb0[4] = {0x3A, 0x23, 0x6A, 0xFD};
    if (!BytesEq(kb, want_kb0, 4))
    {
        SerialWrite("[tls] FAIL key-block-prf\n");
        return;
    }

    // Test 3: Finished verify_data is 12 bytes from the same
    // PRF, with a different label. Confirms label routing is
    // correct.
    u8 fake_transcript[32] = {0};
    u8 vd_client[kVerifyDataBytes];
    u8 vd_server[kVerifyDataBytes];
    TlsFinishedVerifyData(ms, fake_transcript, /*is_client=*/true, vd_client);
    TlsFinishedVerifyData(ms, fake_transcript, /*is_client=*/false, vd_server);
    // The two MUST differ (different labels). If they match,
    // the label argument got swallowed somewhere.
    bool same = true;
    for (u32 i = 0; i < kVerifyDataBytes; ++i)
    {
        if (vd_client[i] != vd_server[i])
        {
            same = false;
            break;
        }
    }
    if (same)
    {
        SerialWrite("[tls] FAIL finished-labels-collide\n");
        return;
    }

    // Test 4: ClientHello body has the right shape.
    //   2 (version) + 32 (random) + 1 (session-id len = 0) +
    //   2 (cipher-suites len) + 2 (one suite) + 1 (compression
    //   methods len) + 1 (null compression) = 41 bytes.
    u8 ch_body[128];
    const u32 ch_len = TlsBuildClientHelloBody(cr, ch_body, sizeof(ch_body));
    if (ch_len != 41)
    {
        SerialWrite("[tls] FAIL clienthello-len\n");
        return;
    }
    // Version field is TLS 1.2 (0x03 0x03).
    if (ch_body[0] != 0x03 || ch_body[1] != 0x03)
    {
        SerialWrite("[tls] FAIL clienthello-version\n");
        return;
    }
    // Cipher-suite list: 2-byte length followed by 0x00 0x9C.
    if (ch_body[35] != 0x00 || ch_body[36] != 0x02 || ch_body[37] != 0x00 || ch_body[38] != 0x9C)
    {
        SerialWrite("[tls] FAIL clienthello-cipher\n");
        return;
    }

    // Test 5: TlsWrapHandshake produces a well-formed record
    // around a synthetic 5-byte body.
    const u8 fake_body[5] = {0x11, 0x22, 0x33, 0x44, 0x55};
    u8 rec[64];
    const u32 rec_len = TlsWrapHandshake(kHandshakeClientHello, fake_body, sizeof(fake_body), rec, sizeof(rec));
    if (rec_len != 5 + 4 + 5)
    {
        SerialWrite("[tls] FAIL wrap-handshake-len\n");
        return;
    }
    if (rec[0] != kContentHandshake || rec[1] != 0x03 || rec[2] != 0x03)
    {
        SerialWrite("[tls] FAIL wrap-handshake-header\n");
        return;
    }
    // Record payload length = 4 (hs header) + 5 (body) = 9.
    if (rec[3] != 0 || rec[4] != 9)
    {
        SerialWrite("[tls] FAIL wrap-handshake-paylen\n");
        return;
    }
    // Handshake type byte at rec[5], 24-bit length at rec[6..8].
    if (rec[5] != kHandshakeClientHello || rec[6] != 0 || rec[7] != 0 || rec[8] != 5)
    {
        SerialWrite("[tls] FAIL wrap-handshake-hsheader\n");
        return;
    }
    if (rec[9] != 0x11 || rec[13] != 0x55)
    {
        SerialWrite("[tls] FAIL wrap-handshake-body\n");
        return;
    }

    SerialWrite("[tls] PASS (prf + key-block + finished-labels + clienthello + record)\n");
}

} // namespace duetos::net::tls
