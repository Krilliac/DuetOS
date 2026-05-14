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
// Record / handshake header peek
// ---------------------------------------------------------------------------

namespace
{

inline u16 LoadU16Be(const u8* p)
{
    return (u16(p[0]) << 8) | u16(p[1]);
}

inline u32 LoadU24Be(const u8* p)
{
    return (u32(p[0]) << 16) | (u32(p[1]) << 8) | u32(p[2]);
}

} // namespace

bool TlsPeekRecord(const u8* buf, u32 len, RecordView* out)
{
    if (buf == nullptr || out == nullptr || len < 5)
        return false;
    out->type = buf[0];
    out->version = LoadU16Be(buf + 1);
    out->length = LoadU16Be(buf + 3);
    out->payload = buf + 5;
    return true;
}

bool TlsPeekHandshake(const u8* buf, u32 len, HandshakeView* out)
{
    if (buf == nullptr || out == nullptr || len < 4)
        return false;
    out->type = buf[0];
    out->length = LoadU24Be(buf + 1);
    out->body = buf + 4;
    if (out->length > len - 4)
        return false;
    return true;
}

bool TlsParseServerHello(const u8* body, u32 len, u8 server_random[kServerRandomBytes], u16* out_cipher)
{
    // ServerHello layout (RFC 5246 §7.4.1.3):
    //   ProtocolVersion server_version;            // 2 bytes
    //   Random          random;                    // 32 bytes
    //   SessionID       session_id<0..32>;         // 1-byte length + body
    //   CipherSuite     cipher_suite;              // 2 bytes
    //   CompressionMethod compression_method;      // 1 byte
    //   Extension       extensions<0..2^16-1>;     // optional, 2-byte length + body
    if (body == nullptr || server_random == nullptr || out_cipher == nullptr)
        return false;
    if (len < 2 + 32 + 1 + 2 + 1)
        return false;
    const u16 version = LoadU16Be(body);
    if (version != kVersionTls12)
        return false;
    for (u32 i = 0; i < kServerRandomBytes; ++i)
        server_random[i] = body[2 + i];
    u32 off = 2 + 32;
    const u8 sid_len = body[off++];
    if (sid_len > 32 || off + sid_len + 2 + 1 > len)
        return false;
    off += sid_len;
    const u16 cipher = LoadU16Be(body + off);
    off += 2;
    if (cipher != kCipherTlsRsaAes128GcmSha256)
        return false;
    const u8 compression = body[off++];
    if (compression != 0)
        return false;
    // Extensions are optional. If `off` reaches `len`, server
    // chose to omit them entirely. Otherwise, there must be a
    // 2-byte length followed by exactly that many bytes — we
    // skip the contents in v0 (no extensions we negotiate).
    if (off < len)
    {
        if (off + 2 > len)
            return false;
        const u16 ext_len = LoadU16Be(body + off);
        off += 2;
        if (off + ext_len > len)
            return false;
        // off += ext_len; // (don't need to read; just validate length)
    }
    *out_cipher = cipher;
    return true;
}

bool TlsParseCertificateLeaf(const u8* body, u32 len, const u8** out_leaf_der, u32* out_leaf_len)
{
    // Certificate message body layout (RFC 5246 §7.4.2):
    //   opaque ASN.1Cert<1..2^24-1>;
    //   struct {
    //       ASN.1Cert certificate_list<0..2^24-1>;
    //   } Certificate;
    //
    // i.e. 3-byte total list length, then a stream of
    // [3-byte cert length | cert bytes] entries. The leaf
    // is the FIRST entry.
    if (body == nullptr || out_leaf_der == nullptr || out_leaf_len == nullptr || len < 6)
        return false;
    const u32 list_len = LoadU24Be(body);
    if (list_len + 3 > len)
        return false;
    if (list_len < 3)
        return false; // need at least one cert-length prefix
    const u32 leaf_len = LoadU24Be(body + 3);
    if (leaf_len == 0 || leaf_len + 3 > list_len)
        return false;
    *out_leaf_der = body + 6;
    *out_leaf_len = leaf_len;
    return true;
}

bool TlsParseServerHelloDone(const u8* /*body*/, u32 len)
{
    return len == 0;
}

// ---------------------------------------------------------------------------
// Client outbound: ClientKeyExchange
// ---------------------------------------------------------------------------

bool Pkcs1V15Type2Pad(const crypto::RsaPublicKey& k, const u8* msg, u32 msg_len, RandomByteFn random_nonzero_byte,
                      u8* dst)
{
    // EME-PKCS1-v1_5 encrypt (RFC 8017 §7.2.1):
    //   EM = 0x00 || 0x02 || PS || 0x00 || M
    //   PS is `k.n_bytes - msg_len - 3` bytes of non-zero
    //   random bytes (>= 8 per RFC 8017).
    if (dst == nullptr || msg == nullptr || random_nonzero_byte == nullptr)
        return false;
    if (k.n_bytes < msg_len + 11)
        return false;
    dst[0] = 0x00;
    dst[1] = 0x02;
    const u32 ps_len = k.n_bytes - msg_len - 3;
    for (u32 i = 0; i < ps_len; ++i)
    {
        u8 b = 0;
        // Pull non-zero bytes. random_nonzero_byte is expected
        // to do its own retry-until-nonzero, but defend
        // against a callback that doesn't.
        for (u32 tries = 0; tries < 16 && b == 0; ++tries)
            b = random_nonzero_byte();
        if (b == 0)
            return false;
        dst[2 + i] = b;
    }
    dst[2 + ps_len] = 0x00;
    for (u32 i = 0; i < msg_len; ++i)
        dst[3 + ps_len + i] = msg[i];
    return true;
}

u32 TlsBuildClientKeyExchangeBody(const crypto::RsaPublicKey& server_rsa, const u8 pms[kPreMasterSecretBytes],
                                  RandomByteFn random_nonzero_byte, u8* dst, u32 cap)
{
    // ClientKeyExchange body for TLS_RSA:
    //   2-byte length | encrypted_PMS (server modulus width)
    if (dst == nullptr || pms == nullptr || random_nonzero_byte == nullptr)
        return 0;
    if (server_rsa.n_bytes == 0 || cap < 2u + server_rsa.n_bytes)
        return 0;
    // Build the padded EM at the modulus width.
    constexpr u32 kMaxModBytes = crypto::kBigIntBits / 8;
    if (server_rsa.n_bytes > kMaxModBytes)
        return 0;
    u8 em[kMaxModBytes];
    if (!Pkcs1V15Type2Pad(server_rsa, pms, kPreMasterSecretBytes, random_nonzero_byte, em))
        return 0;
    // c = EM^e mod n (same primitive RSAVP1 verify uses).
    crypto::BigInt m{};
    if (!crypto::BigIntFromBytesBE(&m, em, server_rsa.n_bytes))
        return 0;
    crypto::BigInt c{};
    crypto::BigIntModExp(&c, m, server_rsa.e, server_rsa.n);
    // Write 2-byte length prefix + ciphertext at modulus width.
    StoreU16Be(dst, static_cast<u16>(server_rsa.n_bytes));
    crypto::BigIntToBytesBE(c, dst + 2, server_rsa.n_bytes);
    return 2u + server_rsa.n_bytes;
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

    // Test 6: Round-trip a synthetic ServerHello body and
    // confirm the parser extracts server_random + cipher.
    u8 sh_body[64];
    u32 si = 0;
    // version 0x0303
    sh_body[si++] = 0x03;
    sh_body[si++] = 0x03;
    // server_random: 0xAB filled
    for (u32 i = 0; i < 32; ++i)
        sh_body[si++] = 0xAB;
    // session_id (empty)
    sh_body[si++] = 0;
    // cipher_suite = TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x009C
    sh_body[si++] = 0x00;
    sh_body[si++] = 0x9C;
    // compression_method = null (0)
    sh_body[si++] = 0;
    u8 parsed_sr[32];
    u16 parsed_cipher = 0;
    if (!TlsParseServerHello(sh_body, si, parsed_sr, &parsed_cipher))
    {
        SerialWrite("[tls] FAIL parse-serverhello\n");
        return;
    }
    if (parsed_cipher != kCipherTlsRsaAes128GcmSha256)
    {
        SerialWrite("[tls] FAIL parse-serverhello-cipher\n");
        return;
    }
    for (u32 i = 0; i < 32; ++i)
    {
        if (parsed_sr[i] != 0xAB)
        {
            SerialWrite("[tls] FAIL parse-serverhello-random\n");
            return;
        }
    }
    // Tampered: replace cipher with one we don't support.
    sh_body[35] = 0x00;
    sh_body[36] = 0xFF; // not 0x009C
    if (TlsParseServerHello(sh_body, si, parsed_sr, &parsed_cipher))
    {
        SerialWrite("[tls] FAIL parse-serverhello-bad-cipher-accepted\n");
        return;
    }

    // Test 7: Certificate message with one 5-byte fake "cert".
    //   3 bytes list len = 0x000008
    //     3 bytes cert len = 0x000005
    //     5 bytes cert body 0xCA 0xFE 0xBA 0xBE 0x42
    u8 cert_body[16];
    cert_body[0] = 0x00;
    cert_body[1] = 0x00;
    cert_body[2] = 0x08;
    cert_body[3] = 0x00;
    cert_body[4] = 0x00;
    cert_body[5] = 0x05;
    cert_body[6] = 0xCA;
    cert_body[7] = 0xFE;
    cert_body[8] = 0xBA;
    cert_body[9] = 0xBE;
    cert_body[10] = 0x42;
    const u8* leaf = nullptr;
    u32 leaf_len = 0;
    if (!TlsParseCertificateLeaf(cert_body, 11, &leaf, &leaf_len))
    {
        SerialWrite("[tls] FAIL parse-cert\n");
        return;
    }
    if (leaf_len != 5 || leaf[0] != 0xCA || leaf[4] != 0x42)
    {
        SerialWrite("[tls] FAIL parse-cert-leaf-bytes\n");
        return;
    }

    // Test 8: ServerHelloDone is zero-length.
    if (!TlsParseServerHelloDone(nullptr, 0))
    {
        SerialWrite("[tls] FAIL parse-shd-empty\n");
        return;
    }
    if (TlsParseServerHelloDone(cert_body, 1))
    {
        SerialWrite("[tls] FAIL parse-shd-nonempty-accepted\n");
        return;
    }

    // Test 9: Record/handshake peek round-trip.
    // Re-use the record we built in test 5 (rec / rec_len).
    RecordView rv{};
    if (!TlsPeekRecord(rec, rec_len, &rv))
    {
        SerialWrite("[tls] FAIL peek-record\n");
        return;
    }
    if (rv.type != kContentHandshake || rv.version != kVersionTls12 || rv.length != 9)
    {
        SerialWrite("[tls] FAIL peek-record-fields\n");
        return;
    }
    HandshakeView hv{};
    if (!TlsPeekHandshake(rv.payload, rv.length, &hv))
    {
        SerialWrite("[tls] FAIL peek-handshake\n");
        return;
    }
    if (hv.type != kHandshakeClientHello || hv.length != 5 || hv.body[0] != 0x11 || hv.body[4] != 0x55)
    {
        SerialWrite("[tls] FAIL peek-handshake-fields\n");
        return;
    }

    // Test 10: PKCS#1 v1.5 type-2 padding (ClientKeyExchange).
    // Confirm the EM shape (0x00 0x02 PS 0x00 M) and that PS
    // contains no zero bytes. ModExp itself is exercised by
    // RsaSelfTest's toy key — here we only need to test the
    // padding + ClientKeyExchange wire shape.
    struct Det
    {
        static u8 NonZero()
        {
            static u8 counter = 0;
            ++counter;
            if (counter == 0)
                counter = 1;
            return counter;
        }
    };
    crypto::RsaPublicKey toy{};
    crypto::BigIntZero(&toy.n);
    crypto::BigIntZero(&toy.e);
    toy.n_bytes = 64;
    u8 em64[64];
    const u8 msg = 0x42;
    if (!Pkcs1V15Type2Pad(toy, &msg, 1, &Det::NonZero, em64))
    {
        SerialWrite("[tls] FAIL pkcs1-type2-pad\n");
        return;
    }
    if (em64[0] != 0x00 || em64[1] != 0x02 || em64[62] != 0x00 || em64[63] != 0x42)
    {
        SerialWrite("[tls] FAIL pkcs1-type2-shape\n");
        return;
    }
    for (u32 i = 2; i < 62; ++i)
    {
        if (em64[i] == 0)
        {
            SerialWrite("[tls] FAIL pkcs1-type2-ps-zero\n");
            return;
        }
    }
    // Modulus too small to fit PMS + padding -> reject.
    crypto::RsaPublicKey tiny{};
    crypto::BigIntZero(&tiny.n);
    tiny.n.limbs[0] = 3233;
    tiny.n.used = 1;
    crypto::BigIntZero(&tiny.e);
    tiny.e.limbs[0] = 17;
    tiny.e.used = 1;
    tiny.n_bytes = 2;
    u8 pms_zero[kPreMasterSecretBytes] = {0};
    u8 cke_buf[256];
    if (TlsBuildClientKeyExchangeBody(tiny, pms_zero, &Det::NonZero, cke_buf, sizeof(cke_buf)) != 0)
    {
        SerialWrite("[tls] FAIL cke-tiny-mod-accepted\n");
        return;
    }
    // 65-byte modulus is large enough — confirm body shape.
    crypto::RsaPublicKey big{};
    crypto::BigIntZero(&big.n);
    big.n.limbs[16] = 1; // 513-bit value, n_bytes = 65
    big.n.used = 17;
    crypto::BigIntZero(&big.e);
    big.e.limbs[0] = 3;
    big.e.used = 1;
    big.n_bytes = 65;
    const u32 cke_len = TlsBuildClientKeyExchangeBody(big, pms_zero, &Det::NonZero, cke_buf, sizeof(cke_buf));
    if (cke_len != 2 + 65 || cke_buf[0] != 0x00 || cke_buf[1] != 0x41)
    {
        SerialWrite("[tls] FAIL cke-len-prefix\n");
        return;
    }

    SerialWrite("[tls] PASS (prf + key-block + finished-labels + clienthello + record + parse + peek + cke)\n");
}
} // namespace duetos::net::tls
