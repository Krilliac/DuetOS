#include "net/tls.h"

#include "arch/x86_64/serial.h"
#include "crypto/hmac.h"
#include "crypto/sha256.h"
#include "duetos_tls.h"

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

    // RFC 5246 §5: A(0) = label || seed; A(i) = HMAC(secret, A(i-1)).
    // Compute A(1) up front so the loop below can produce the
    // first output chunk on entry.
    u8 A[crypto::kSha256DigestBytes];
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
    return TlsBuildClientHelloBodyWithSni(client_random, nullptr, dst, cap);
}

u32 TlsBuildClientHelloBodyWithSni(const u8 client_random[kClientRandomBytes], const char* hostname, u8* dst, u32 cap)
{
    if (dst == nullptr || cap < 64)
        return 0;
    u32 host_len = 0;
    if (hostname != nullptr)
    {
        while (hostname[host_len] != '\0' && host_len < 255)
            ++host_len;
    }
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
    if (host_len == 0)
    {
        // RFC 5246 §7.4.1.2 allows omitting the extensions
        // block entirely — preserve the pre-SNI shape so the
        // existing self-tests don't need updating.
        return off;
    }
    // Extensions block. Single extension: SNI (RFC 6066 §3).
    //
    //   extension_type   = 0 (server_name)
    //   extension_data:
    //     u16 server_name_list_length
    //     u8  NameType = 0 (host_name)
    //     u16 host_name_length
    //     opaque host_name[host_name_length]
    //
    // Total extension_data size = 2 (list length)
    //                           + 1 (name type)
    //                           + 2 (host name length)
    //                           + host_len
    const u32 sni_ext_data_len = 2 + 1 + 2 + host_len;
    const u32 ext_block_len = 2 + 2 + sni_ext_data_len; // type + len + data
    if (off + 2 + ext_block_len > cap)
        return 0;
    StoreU16Be(dst + off, static_cast<u16>(ext_block_len));
    off += 2;
    // Extension type = 0 (server_name)
    StoreU16Be(dst + off, 0);
    off += 2;
    // Extension data length
    StoreU16Be(dst + off, static_cast<u16>(sni_ext_data_len));
    off += 2;
    // server_name_list_length
    StoreU16Be(dst + off, static_cast<u16>(1 + 2 + host_len));
    off += 2;
    // NameType = host_name
    dst[off++] = 0;
    // host_name length + bytes
    StoreU16Be(dst + off, static_cast<u16>(host_len));
    off += 2;
    for (u32 i = 0; i < host_len; ++i)
        dst[off + i] = static_cast<u8>(hostname[i]);
    off += host_len;
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

} // namespace

// All five TLS parser entry points below delegate byte parsing
// to the `duetos_tls` Rust crate (kernel/net/tls_rust/). Remote
// peers control packet lengths, header offsets, session-id
// lengths, certificate-list / per-cert length prefixes, and
// extension-list lengths — Rust-Subsystems P0 surface. The
// Rust crate keeps `unsafe` confined to the FFI wall and runs
// the rest of each parser on bounds-checked slices with
// checked-arithmetic length comparisons. The C++ wrappers
// remain the public API; they translate between the Rust FFI
// structs (DuetosTlsRecordView, DuetosTlsHandshakeView) and
// the existing `tls.h` shapes so the rest of the kernel
// doesn't pick up Rust-side field names.
bool TlsPeekRecord(const u8* buf, u32 len, RecordView* out)
{
    if (out == nullptr)
        return false;
    DuetosTlsRecordView rv{};
    if (!duetos_tls_peek_record(buf, len, &rv))
        return false;
    out->type = rv.content_type;
    out->version = rv.version;
    out->length = rv.length;
    out->payload = rv.payload;
    return true;
}

bool TlsPeekHandshake(const u8* buf, u32 len, HandshakeView* out)
{
    if (out == nullptr)
        return false;
    DuetosTlsHandshakeView hv{};
    if (!duetos_tls_peek_handshake(buf, len, &hv))
        return false;
    out->type = hv.kind;
    out->length = hv.length;
    out->body = hv.body;
    return true;
}

bool TlsParseServerHello(const u8* body, u32 len, u8 server_random[kServerRandomBytes], u16* out_cipher)
{
    return duetos_tls_parse_server_hello(body, len, server_random, out_cipher);
}

bool TlsParseCertificateLeaf(const u8* body, u32 len, const u8** out_leaf_der, u32* out_leaf_len)
{
    return duetos_tls_parse_certificate_leaf(body, len, out_leaf_der, out_leaf_len);
}

bool TlsParseServerHelloDone(const u8* body, u32 len)
{
    return duetos_tls_parse_server_hello_done(body, len);
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

// ---------------------------------------------------------------------------
// Connection state machine
// ---------------------------------------------------------------------------

namespace
{

inline void ZeroBytes(u8* p, u32 n)
{
    for (u32 i = 0; i < n; ++i)
        p[i] = 0;
}

inline void CopyBytes(u8* dst, const u8* src, u32 n)
{
    for (u32 i = 0; i < n; ++i)
        dst[i] = src[i];
}

void ConnectionFail(Connection* c, const char* msg)
{
    c->state = State::Failed;
    c->err = msg;
}

// Slice the key_block into the four per-direction outputs.
void SplitKeyBlock(Connection* c, const u8 kb[kKeyBlockBytes])
{
    u32 off = 0;
    CopyBytes(c->client_write_key, kb + off, kAesGcmKeyBytes);
    off += kAesGcmKeyBytes;
    CopyBytes(c->server_write_key, kb + off, kAesGcmKeyBytes);
    off += kAesGcmKeyBytes;
    CopyBytes(c->client_iv_salt, kb + off, kAesGcmFixedIvBytes);
    off += kAesGcmFixedIvBytes;
    CopyBytes(c->server_iv_salt, kb + off, kAesGcmFixedIvBytes);
}

} // namespace

u32 ConnectionStart(Connection* c, const u8 client_random[kClientRandomBytes], const u8 pms[kPreMasterSecretBytes],
                    const char* hostname, u8* out, u32 cap)
{
    if (c == nullptr || client_random == nullptr || pms == nullptr || out == nullptr)
        return 0;
    // Zero everything except the things we're about to set.
    c->state = State::Init;
    CopyBytes(c->client_random, client_random, kClientRandomBytes);
    ZeroBytes(c->server_random, kServerRandomBytes);
    CopyBytes(c->pre_master_secret, pms, kPreMasterSecretBytes);
    ZeroBytes(c->master_secret, kMasterSecretBytes);
    ZeroBytes(c->client_write_key, kAesGcmKeyBytes);
    ZeroBytes(c->server_write_key, kAesGcmKeyBytes);
    ZeroBytes(c->client_iv_salt, kAesGcmFixedIvBytes);
    ZeroBytes(c->server_iv_salt, kAesGcmFixedIvBytes);
    c->client_seq = 0;
    c->server_seq = 0;
    TranscriptInit(&c->transcript);
    crypto::BigIntZero(&c->server_rsa.n);
    crypto::BigIntZero(&c->server_rsa.e);
    c->server_rsa.n_bytes = 0;
    c->server_cert_seen = false;
    c->server_flight_done = false;
    c->hs_reasm_len = 0;
    c->server_flight_consumed = 0;
    c->err = nullptr;
    // Capture the hostname for later cert-CN verification. Empty
    // hostname disables the check (some callers — internal tests,
    // CN-less self-signed deployments — legitimately want this).
    for (u32 i = 0; i < sizeof(c->expected_hostname); ++i)
        c->expected_hostname[i] = 0;
    if (hostname != nullptr)
    {
        u32 i = 0;
        while (hostname[i] != '\0' && i + 1 < sizeof(c->expected_hostname))
        {
            c->expected_hostname[i] = hostname[i];
            ++i;
        }
        c->expected_hostname[i] = '\0';
    }

    // Build the ClientHello body, then the handshake-framed body
    // for transcript hashing, then the record-wrapped version
    // for the wire. With SNI: 41-byte base + 9-byte SNI overhead
    // + hostname length. 320 bytes covers any realistic FQDN.
    u8 ch_body[320];
    const u32 ch_body_len = TlsBuildClientHelloBodyWithSni(c->client_random, hostname, ch_body, sizeof(ch_body));
    if (ch_body_len == 0)
    {
        ConnectionFail(c, "ClientHello body build failed");
        return 0;
    }
    // Mix the 4-byte-handshake-header + body into the transcript.
    u8 hs_msg[4 + sizeof(ch_body)];
    hs_msg[0] = kHandshakeClientHello;
    hs_msg[1] = static_cast<u8>((ch_body_len >> 16) & 0xFF);
    hs_msg[2] = static_cast<u8>((ch_body_len >> 8) & 0xFF);
    hs_msg[3] = static_cast<u8>(ch_body_len & 0xFF);
    CopyBytes(hs_msg + 4, ch_body, ch_body_len);
    TranscriptUpdate(&c->transcript, hs_msg, 4 + ch_body_len);

    const u32 record_len = TlsWrapHandshake(kHandshakeClientHello, ch_body, ch_body_len, out, cap);
    if (record_len == 0)
    {
        ConnectionFail(c, "ClientHello record wrap failed");
        return 0;
    }
    c->state = State::SentClientHello;
    return record_len;
}

namespace
{

// Walk a buffer of consecutive TLS records and call `visit` for
// each one. Stops at the first malformed record or when `visit`
// returns false. Returns the number of bytes consumed.
//
// `visit` receives the record TYPE and a slice over the record
// PAYLOAD (not including the 5-byte header).
struct RecordIter
{
    const u8* buf;
    u32 len;
    u32 cursor;
};

bool RecordIterNext(RecordIter* it, RecordView* out)
{
    if (it->cursor + 5 > it->len)
        return false;
    if (!TlsPeekRecord(it->buf + it->cursor, it->len - it->cursor, out))
        return false;
    if (5u + out->length > it->len - it->cursor)
        return false;
    it->cursor += 5u + out->length;
    return true;
}

// Dispatch a single, fully-reassembled server handshake message
// (ServerHello / Certificate / ServerHelloDone). The bytes have
// already been mixed into the transcript by the caller; this only
// performs the per-type semantic parse + state update. Returns
// false on a hard, unrecoverable error (and sets c->err).
bool DispatchServerHandshake(Connection* c, const HandshakeView& hv)
{
    switch (hv.type)
    {
    case kHandshakeServerHello:
    {
        u16 cipher = 0;
        if (!TlsParseServerHello(hv.body, hv.length, c->server_random, &cipher))
        {
            ConnectionFail(c, "ServerHello parse failed");
            return false;
        }
        return true;
    }
    case kHandshakeCertificate:
    {
        const u8* leaf_der = nullptr;
        u32 leaf_len = 0;
        if (!TlsParseCertificateLeaf(hv.body, hv.length, &leaf_der, &leaf_len))
        {
            ConnectionFail(c, "Certificate parse failed");
            return false;
        }
        // Pull the server's RSA public key out of the leaf cert.
        // v0 does NOT validate the cert chain or hostname — see
        // wiki/networking/TLS-Roadmap.md Tier 3 for the
        // trust-store roadmap.
        crypto::x509::Certificate parsed{};
        if (crypto::x509::Parse(leaf_der, leaf_len, &parsed) != crypto::x509::Status::Ok)
        {
            ConnectionFail(c, "X.509 parse failed");
            return false;
        }
        if (!parsed.subject_rsa_present)
        {
            // GAP: RSA-key-exchange only — an ECDSA-leaf server (no RSA
            // SPKI) needs ECDHE, which this v0 TLS doesn't negotiate yet.
            ConnectionFail(c, "leaf cert has no RSA SPKI");
            return false;
        }
        // Hostname verification is NOT done here. It used to be a CN-only
        // exact match, which rejected essentially every modern cert —
        // real leaves carry the hostname in the Subject Alternative Name
        // (SAN), not the CN, so the CN check failed before trust was even
        // evaluated ("leaf cert CN does not match expected hostname").
        // The authoritative check is the cert-verifier hook
        // (net::x509::Verify, run from tls_socket once the server cert is
        // seen): it is SAN-aware (dNSName + leftmost-'*.' wildcard, CN
        // fallback), verifies the chain to a trusted root, AND fails
        // closed when no verifier is installed (see tls_socket.cpp
        // RunCertVerifier). Doing a second, weaker hostname match here
        // only blocked the correct one — so this layer just extracts the
        // server key and lets the verifier own authentication.
        c->server_rsa = parsed.subject_rsa;
        c->server_cert_seen = true;
        return true;
    }
    case kHandshakeServerHelloDone:
    {
        if (!TlsParseServerHelloDone(hv.body, hv.length))
        {
            ConnectionFail(c, "malformed ServerHelloDone");
            return false;
        }
        // ServerHelloDone ends the server's first flight. We now
        // have everything needed to build the ClientKeyExchange,
        // AND — critically — the SHD message itself has just been
        // mixed into the transcript, so the client's Finished
        // verify_data will be computed over the complete flight.
        c->server_flight_done = true;
        return true;
    }
    default:
        // CertificateRequest / ServerKeyExchange (for non-RSA
        // suites) etc. show up here. v0 only negotiates TLS_RSA so
        // we shouldn't see ServerKeyExchange; if we do, fail
        // loudly.
        ConnectionFail(c, "unexpected server handshake type");
        return false;
    }
}

// Drain every COMPLETE handshake message currently buffered in
// c->hs_reasm into the transcript + dispatcher. Handshake-message
// boundaries are independent of the TLS records that delivered the
// bytes (RFC 5246 §6.2.1), so we parse the contiguous handshake
// byte-stream here regardless of how it was framed: multiple
// messages coalesced in one record, one message split across
// records, or a flight dribbled across several ConnectionFeed()
// calls.
//
// A trailing PARTIAL message (incomplete 4-byte header, or a
// complete header whose body hasn't fully arrived) is left in the
// buffer for the next call; the consumed bytes are compacted out.
// Stops early — leaving any trailing bytes intact — once
// ServerHelloDone is seen, so a (spec-violating) server that packs
// extra data after SHD doesn't get it silently absorbed.
//
// Returns false only on a hard parse/semantic error.
bool DrainServerHandshakes(Connection* c)
{
    u32 off = 0;
    while (off < c->hs_reasm_len)
    {
        const u32 avail = c->hs_reasm_len - off;
        // Need the full 4-byte handshake header before we can know
        // the message length.
        if (avail < 4)
            break;
        HandshakeView hv{};
        if (!TlsPeekHandshake(c->hs_reasm + off, avail, &hv))
        {
            // TlsPeekHandshake fails when the body hasn't fully
            // arrived yet (length > available). That's a partial
            // message, not corruption — wait for more bytes.
            break;
        }
        const u32 msg_len = 4 + hv.length;
        // Mix the full handshake message (header + body) into the
        // transcript BEFORE dispatching so the later verify_data
        // computation sees the canonical bytes.
        TranscriptUpdate(&c->transcript, c->hs_reasm + off, msg_len);
        if (!DispatchServerHandshake(c, hv))
            return false;
        off += msg_len;
        if (c->server_flight_done)
            break;
    }

    // Compact: drop the consumed prefix, keep any trailing partial.
    if (off > 0)
    {
        const u32 remaining = c->hs_reasm_len - off;
        for (u32 i = 0; i < remaining; ++i)
            c->hs_reasm[i] = c->hs_reasm[off + i];
        c->hs_reasm_len = remaining;
    }
    return true;
}

// Compose the second client flight:
//   ClientKeyExchange (handshake record)
//   ChangeCipherSpec (1-byte record, type 20)
//   Finished (handshake record, ENCRYPTED under new keys)
//
// Returns total bytes written. On failure, sets c->err and
// transitions to Failed.
u32 EmitClientKeyAndFinish(Connection* c, RandomByteFn random_nonzero_byte, u8* out, u32 cap)
{
    if (!c->server_cert_seen || c->server_rsa.n_bytes == 0)
    {
        ConnectionFail(c, "no server cert before client key exchange");
        return 0;
    }
    // CKE body
    u8 cke_body[crypto::kBigIntBits / 8 + 2];
    const u32 cke_body_len = TlsBuildClientKeyExchangeBody(c->server_rsa, c->pre_master_secret, random_nonzero_byte,
                                                           cke_body, sizeof(cke_body));
    if (cke_body_len == 0)
    {
        ConnectionFail(c, "ClientKeyExchange build failed");
        return 0;
    }
    // Mix the CKE handshake message into the transcript.
    u8 cke_hs_hdr[4];
    cke_hs_hdr[0] = kHandshakeClientKeyExchange;
    cke_hs_hdr[1] = static_cast<u8>((cke_body_len >> 16) & 0xFF);
    cke_hs_hdr[2] = static_cast<u8>((cke_body_len >> 8) & 0xFF);
    cke_hs_hdr[3] = static_cast<u8>(cke_body_len & 0xFF);
    TranscriptUpdate(&c->transcript, cke_hs_hdr, 4);
    TranscriptUpdate(&c->transcript, cke_body, cke_body_len);

    // Derive master_secret + key_block now that we have both
    // randoms + the pms.
    TlsMasterSecret(c->pre_master_secret, c->client_random, c->server_random, c->master_secret);
    u8 key_block[kKeyBlockBytes];
    TlsKeyBlock(c->master_secret, c->server_random, c->client_random, key_block);
    SplitKeyBlock(c, key_block);
    // Sequence numbers reset to 0 each time CCS flips the
    // cipher (only happens once per direction in TLS 1.2).
    c->client_seq = 0;
    c->server_seq = 0;

    u32 off = 0;

    // Wrap CKE as a Handshake record.
    const u32 cke_rec_len = TlsWrapHandshake(kHandshakeClientKeyExchange, cke_body, cke_body_len, out + off, cap - off);
    if (cke_rec_len == 0)
    {
        ConnectionFail(c, "CKE record wrap failed");
        return 0;
    }
    off += cke_rec_len;

    // ChangeCipherSpec: single 0x01 byte, content type 20.
    static constexpr u8 ccs_payload[1] = {0x01};
    const u32 ccs_rec_len = TlsWrapRecord(kContentChangeCipherSpec, ccs_payload, 1, out + off, cap - off);
    if (ccs_rec_len == 0)
    {
        ConnectionFail(c, "CCS record wrap failed");
        return 0;
    }
    off += ccs_rec_len;

    // Finished: encrypted under the freshly-derived client
    // keys at seq 0.
    const u32 fin_rec_len =
        TlsBuildEncryptedFinished(c->master_secret, c->transcript, c->client_write_key, c->client_iv_salt,
                                  c->client_seq, /*is_client=*/true, out + off, cap - off);
    if (fin_rec_len == 0)
    {
        ConnectionFail(c, "Finished build failed");
        return 0;
    }
    // After sending an encrypted record, advance the client
    // sequence. The client Finished message bytes (4 + 12 = 16)
    // also need to be mixed into the transcript so the server
    // Finished verify_data is computed over the right snapshot.
    u8 client_fin_msg[4 + kVerifyDataBytes];
    client_fin_msg[0] = kHandshakeFinished;
    client_fin_msg[1] = 0;
    client_fin_msg[2] = 0;
    client_fin_msg[3] = kVerifyDataBytes;
    // Re-derive verify_data so we can mix it in. (Slightly
    // wasteful — TlsBuildEncryptedFinished computed it
    // internally — but keeps the API simple.)
    {
        u8 hash[32];
        TranscriptSnapshot(&c->transcript, hash);
        u8 vd[kVerifyDataBytes];
        TlsFinishedVerifyData(c->master_secret, hash, /*is_client=*/true, vd);
        CopyBytes(client_fin_msg + 4, vd, kVerifyDataBytes);
    }
    TranscriptUpdate(&c->transcript, client_fin_msg, sizeof(client_fin_msg));
    c->client_seq++;
    off += fin_rec_len;
    return off;
}

} // namespace

u32 ConnectionFeed(Connection* c, const u8* server_bytes, u32 len, u8* out, u32 cap, RandomByteFn random_nonzero_byte)
{
    if (c == nullptr || server_bytes == nullptr || out == nullptr)
        return 0;
    if (c->state == State::Failed)
        return 0;

    RecordIter it{server_bytes, len, 0};
    if (c->state == State::SentClientHello)
    {
        // First server flight: ServerHello, Certificate,
        // ServerHelloDone. These arrive in one or more handshake
        // records, and the messages may be coalesced into / split
        // across record boundaries (RFC 5246 §6.2.1).
        //
        // The caller (TlsSocketHandshake) re-feeds the FULL
        // accumulated buffer each call, growing it until a flight
        // completes. server_flight_consumed marks how many bytes of
        // that buffer we've already peeled into hs_reasm, so a
        // re-feed skips records it already absorbed rather than
        // double-mixing them into the transcript.
        it.cursor = (c->server_flight_consumed <= len) ? c->server_flight_consumed : len;
        while (!c->server_flight_done)
        {
            RecordView rv{};
            if (!RecordIterNext(&it, &rv))
            {
                if (it.cursor >= len)
                    break; // incomplete trailing record — wait for more bytes
                ConnectionFail(c, "malformed server record");
                return 0;
            }
            if (rv.type != kContentHandshake)
            {
                ConnectionFail(c, "expected handshake record from server");
                return 0;
            }
            // Append this record's handshake payload to the
            // reassembly buffer (bounded — a hostile peer must not
            // be able to make us buffer unboundedly).
            if (rv.length > Connection::kHsReasmMax - c->hs_reasm_len)
            {
                ConnectionFail(c, "server handshake flight exceeds reassembly buffer");
                return 0;
            }
            for (u32 i = 0; i < rv.length; ++i)
                c->hs_reasm[c->hs_reasm_len + i] = rv.payload[i];
            c->hs_reasm_len += rv.length;
            c->server_flight_consumed = it.cursor;

            // Drain whatever complete handshake messages we now
            // have. Sets server_flight_done when SHD is reached.
            if (!DrainServerHandshakes(c))
                return 0;
        }
        if (c->server_flight_done)
            c->state = State::RecvServerHelloBundle;
    }

    if (c->state == State::RecvServerHelloBundle)
    {
        // Build the second client flight: CKE + CCS + Finished.
        const u32 wrote = EmitClientKeyAndFinish(c, random_nonzero_byte, out, cap);
        if (wrote == 0)
            return 0;
        c->state = State::SentClientKeyAndFinish;
        return wrote;
    }

    if (c->state == State::SentClientKeyAndFinish)
    {
        // Expect server CCS + encrypted Finished.
        // CCS is one record; Finished is the next (encrypted).
        RecordView ccs_rv{};
        if (!RecordIterNext(&it, &ccs_rv))
        {
            if (it.cursor >= len)
                return 0; // wait for more
            ConnectionFail(c, "malformed record awaiting CCS");
            return 0;
        }
        if (ccs_rv.type != kContentChangeCipherSpec || ccs_rv.length != 1 || ccs_rv.payload[0] != 0x01)
        {
            ConnectionFail(c, "bad server ChangeCipherSpec");
            return 0;
        }
        // Encrypted Finished
        RecordView fin_rv{};
        if (!RecordIterNext(&it, &fin_rv))
        {
            if (it.cursor >= len)
                return 0;
            ConnectionFail(c, "malformed record awaiting Finished");
            return 0;
        }
        // TlsVerifyEncryptedServerFinished wants the FULL
        // record bytes (including 5-byte header), so use the
        // pre-iter cursor.
        const u8* fin_record = server_bytes + (it.cursor - (5 + fin_rv.length));
        const u32 fin_record_len = 5 + fin_rv.length;
        if (!TlsVerifyEncryptedServerFinished(c->master_secret, c->transcript, c->server_write_key, c->server_iv_salt,
                                              c->server_seq, fin_record, fin_record_len))
        {
            ConnectionFail(c, "server Finished verify failed");
            return 0;
        }
        c->server_seq++;
        c->state = State::Established;
        return 0; // no client bytes owed; handshake complete
    }

    return 0;
}

u32 ConnectionEncryptApp(Connection* c, const u8* pt, u32 pt_len, u8* dst, u32 cap)
{
    if (c == nullptr || c->state != State::Established)
        return 0;
    const u32 wire = TlsEncryptRecord(c->client_write_key, c->client_iv_salt, c->client_seq, kContentApplicationData,
                                      pt, pt_len, dst, cap);
    if (wire == 0)
        return 0;
    c->client_seq++;
    return wire;
}

bool ConnectionDecryptApp(Connection* c, const u8* record_bytes, u32 record_len, u8* pt_out, u32 cap, u32* pt_len_out)
{
    if (c == nullptr || c->state != State::Established)
        return false;
    u8 content_type = 0;
    if (!TlsDecryptRecord(c->server_write_key, c->server_iv_salt, c->server_seq, record_bytes, record_len, pt_out, cap,
                          pt_len_out, &content_type))
        return false;
    c->server_seq++;
    return content_type == kContentApplicationData;
}

// ---------------------------------------------------------------------------
// Transcript hash + Finished message
// ---------------------------------------------------------------------------

void TranscriptInit(Transcript* t)
{
    if (t == nullptr)
        return;
    crypto::Sha256Init(t->ctx);
}

void TranscriptUpdate(Transcript* t, const u8* msg, u32 len)
{
    if (t == nullptr || msg == nullptr || len == 0)
        return;
    crypto::Sha256Update(t->ctx, msg, len);
}

void TranscriptSnapshot(const Transcript* t, u8 out[32])
{
    if (t == nullptr || out == nullptr)
        return;
    // SHA-256 final is destructive — clone the running ctx
    // first so the snapshot doesn't disturb future updates.
    crypto::Sha256Ctx clone = t->ctx;
    crypto::Sha256Final(clone, out);
}

u32 TlsBuildEncryptedFinished(const u8 master_secret[kMasterSecretBytes], const Transcript& transcript,
                              const u8 write_key[kAesGcmKeyBytes], const u8 write_iv_salt[kAesGcmFixedIvBytes],
                              u64 seq_num, bool is_client, u8* dst, u32 cap)
{
    if (master_secret == nullptr || write_key == nullptr || write_iv_salt == nullptr || dst == nullptr)
        return 0;
    u8 hash[32];
    TranscriptSnapshot(&transcript, hash);
    u8 vd[kVerifyDataBytes];
    TlsFinishedVerifyData(master_secret, hash, is_client, vd);
    // Compose the inner handshake message: 4-byte handshake
    // header (type=0x14 Finished, 24-bit length=0x0c) followed
    // by the 12-byte verify_data. Total 16 bytes.
    u8 inner[4 + kVerifyDataBytes];
    inner[0] = kHandshakeFinished;
    inner[1] = 0;
    inner[2] = 0;
    inner[3] = static_cast<u8>(kVerifyDataBytes);
    for (u32 i = 0; i < kVerifyDataBytes; ++i)
        inner[4 + i] = vd[i];
    return TlsEncryptRecord(write_key, write_iv_salt, seq_num, kContentHandshake, inner, sizeof(inner), dst, cap);
}

bool TlsVerifyEncryptedServerFinished(const u8 master_secret[kMasterSecretBytes], const Transcript& transcript,
                                      const u8 read_key[kAesGcmKeyBytes], const u8 read_iv_salt[kAesGcmFixedIvBytes],
                                      u64 seq_num, const u8* record_bytes, u32 record_len)
{
    if (record_bytes == nullptr || master_secret == nullptr)
        return false;
    u8 inner[64];
    u32 inner_len = 0;
    u8 content_type = 0;
    if (!TlsDecryptRecord(read_key, read_iv_salt, seq_num, record_bytes, record_len, inner, sizeof(inner), &inner_len,
                          &content_type))
        return false;
    if (content_type != kContentHandshake)
        return false;
    if (inner_len != 4 + kVerifyDataBytes)
        return false;
    if (inner[0] != kHandshakeFinished || inner[1] != 0 || inner[2] != 0 || inner[3] != kVerifyDataBytes)
        return false;
    u8 hash[32];
    TranscriptSnapshot(&transcript, hash);
    u8 expected_vd[kVerifyDataBytes];
    TlsFinishedVerifyData(master_secret, hash, /*is_client=*/false, expected_vd);
    u8 diff = 0;
    for (u32 i = 0; i < kVerifyDataBytes; ++i)
        diff |= inner[4 + i] ^ expected_vd[i];
    return diff == 0;
}

// ---------------------------------------------------------------------------
// Record-layer AES-GCM encrypt / decrypt
// ---------------------------------------------------------------------------

namespace
{

// Compose the 13-byte TLS 1.2 GCM AAD:
//   seq_num(8 BE) || type(1) || version(2 BE) || length(2 BE)
void BuildGcmAad(u64 seq_num, u8 content_type, u16 plaintext_len, u8 aad[13])
{
    for (u32 i = 0; i < 8; ++i)
        aad[i] = static_cast<u8>((seq_num >> ((7 - i) * 8)) & 0xFF);
    aad[8] = content_type;
    StoreU16Be(aad + 9, kVersionTls12);
    StoreU16Be(aad + 11, plaintext_len);
}

// Build the 12-byte GCM nonce from the per-direction salt + the
// 8-byte explicit-IV (RFC 5288 §3). v0 uses the record seq_num
// as the explicit-IV — same convention OpenSSL / BoringSSL use
// by default. Unique per record because the seq_num is unique.
void BuildGcmNonce(const u8 salt[kAesGcmFixedIvBytes], u64 seq_num, u8 nonce[crypto::kGcmIvBytes])
{
    for (u32 i = 0; i < kAesGcmFixedIvBytes; ++i)
        nonce[i] = salt[i];
    for (u32 i = 0; i < kAesGcmExplicitIvBytes; ++i)
        nonce[kAesGcmFixedIvBytes + i] = static_cast<u8>((seq_num >> ((7 - i) * 8)) & 0xFF);
}

} // namespace

u32 TlsEncryptRecord(const u8 write_key[kAesGcmKeyBytes], const u8 write_iv_salt[kAesGcmFixedIvBytes], u64 seq_num,
                     u8 content_type, const u8* plaintext, u32 plaintext_len, u8* dst, u32 cap)
{
    if (dst == nullptr || write_key == nullptr || write_iv_salt == nullptr)
        return 0;
    if (plaintext_len > 0 && plaintext == nullptr)
        return 0;
    if (plaintext_len > 0xFFFFu - kAesGcmExplicitIvBytes - crypto::kGcmTagBytes)
        return 0;
    const u32 wire_len = 5u + kAesGcmExplicitIvBytes + plaintext_len + crypto::kGcmTagBytes;
    if (cap < wire_len)
        return 0;

    // Record header: type | version | length (length = 8 + pt + 16).
    dst[0] = content_type;
    StoreU16Be(dst + 1, kVersionTls12);
    StoreU16Be(dst + 3, static_cast<u16>(kAesGcmExplicitIvBytes + plaintext_len + crypto::kGcmTagBytes));

    // Explicit IV bytes go on the wire right after the header.
    // We mirror the GCM nonce's explicit-IV half — the seq_num
    // in big-endian byte order.
    u8* explicit_iv = dst + 5;
    for (u32 i = 0; i < kAesGcmExplicitIvBytes; ++i)
        explicit_iv[i] = static_cast<u8>((seq_num >> ((7 - i) * 8)) & 0xFF);

    u8 aad[13];
    BuildGcmAad(seq_num, content_type, static_cast<u16>(plaintext_len), aad);
    u8 nonce[crypto::kGcmIvBytes];
    BuildGcmNonce(write_iv_salt, seq_num, nonce);

    u8* ct = dst + 5 + kAesGcmExplicitIvBytes;
    u8* tag = ct + plaintext_len;
    if (!crypto::AesGcm128Encrypt(write_key, nonce, aad, sizeof(aad), plaintext, plaintext_len, ct, tag))
        return 0;
    return wire_len;
}

bool TlsDecryptRecord(const u8 read_key[kAesGcmKeyBytes], const u8 read_iv_salt[kAesGcmFixedIvBytes], u64 seq_num,
                      const u8* record_bytes, u32 record_len, u8* plaintext_out, u32 cap, u32* out_plaintext_len,
                      u8* out_content_type)
{
    if (record_bytes == nullptr || read_key == nullptr || read_iv_salt == nullptr || out_plaintext_len == nullptr ||
        out_content_type == nullptr)
        return false;
    if (record_len < 5u + kAesGcmExplicitIvBytes + crypto::kGcmTagBytes)
        return false;
    const u8 type = record_bytes[0];
    const u16 version = LoadU16Be(record_bytes + 1);
    const u16 frag_len = LoadU16Be(record_bytes + 3);
    if (version != kVersionTls12)
        return false;
    if (record_len != 5u + frag_len)
        return false;
    if (frag_len < kAesGcmExplicitIvBytes + crypto::kGcmTagBytes)
        return false;
    const u32 plaintext_len = frag_len - kAesGcmExplicitIvBytes - crypto::kGcmTagBytes;
    if (cap < plaintext_len)
        return false;

    const u8* explicit_iv_in = record_bytes + 5;
    const u8* ct = record_bytes + 5 + kAesGcmExplicitIvBytes;
    const u8* tag = ct + plaintext_len;

    // Build the GCM nonce from the salt + the on-wire explicit
    // IV. We trust the server's explicit IV (RFC 5288 only
    // requires uniqueness, and the AEAD tag verify catches any
    // replay-shaped misuse).
    u8 nonce[crypto::kGcmIvBytes];
    for (u32 i = 0; i < kAesGcmFixedIvBytes; ++i)
        nonce[i] = read_iv_salt[i];
    for (u32 i = 0; i < kAesGcmExplicitIvBytes; ++i)
        nonce[kAesGcmFixedIvBytes + i] = explicit_iv_in[i];

    u8 aad[13];
    BuildGcmAad(seq_num, type, static_cast<u16>(plaintext_len), aad);
    if (!crypto::AesGcm128Decrypt(read_key, nonce, aad, sizeof(aad), ct, plaintext_len, tag, plaintext_out))
        return false;
    *out_plaintext_len = plaintext_len;
    *out_content_type = type;
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

// ---------------------------------------------------------------------------
// Fragmented-flight handshake self-test (record/handshake reassembly)
// ---------------------------------------------------------------------------
//
// Proves the client mixes EVERY server handshake message —
// including ServerHelloDone — into its transcript regardless of how
// the server packs those messages into / splits them across TLS
// records. Without the reassembly fix, a flight whose
// ServerHelloDone lands in a later record produces a client
// Finished computed over a transcript missing SHD, and the server
// Finished verify mismatches.
//
// We synthesise a minimal TLS_RSA server: it sends ServerHello +
// Certificate (a real self-signed RSA-512 leaf so x509::Parse +
// SPKI-extraction succeed) + ServerHelloDone, then — acting as the
// server — reproduces the master_secret-derived keys the client
// just computed (legitimate: both peers derive identical keys from
// the same handshake) and replies with CCS + an encrypted server
// Finished. We can reuse the keys the client derived (exposed on
// the Connection) because the RSA PMS round-trip is orthogonal to
// the transcript bug under test, and there is no RSA-decrypt
// primitive in-kernel to recover the PMS the honest way.

// Self-signed RSA-512 leaf, CN=duetos-tls-frag-test. Generated on
// the host with:
//   openssl req -x509 -newkey rsa:512 -nodes -days 3650 \
//     -subj /CN=duetos-tls-frag-test -outform DER
// (DER, 409 bytes). n_bytes = 64 >= 48+11, so it can carry the PMS.
constexpr u8 kFragTestLeafDer[] = {
    0x30, 0x82, 0x01, 0x95, 0x30, 0x82, 0x01, 0x3f, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x47, 0xb8, 0xa8, 0x02,
    0xd0, 0x62, 0x55, 0x6c, 0x75, 0x0f, 0x30, 0x3b, 0x41, 0xe6, 0x0a, 0x23, 0x06, 0x17, 0xbd, 0x2b, 0x30, 0x0d, 0x06,
    0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x1f, 0x31, 0x1d, 0x30, 0x1b, 0x06,
    0x03, 0x55, 0x04, 0x03, 0x0c, 0x14, 0x64, 0x75, 0x65, 0x74, 0x6f, 0x73, 0x2d, 0x74, 0x6c, 0x73, 0x2d, 0x66, 0x72,
    0x61, 0x67, 0x2d, 0x74, 0x65, 0x73, 0x74, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x36, 0x30, 0x31, 0x31, 0x34,
    0x33, 0x39, 0x32, 0x35, 0x5a, 0x17, 0x0d, 0x33, 0x36, 0x30, 0x35, 0x32, 0x39, 0x31, 0x34, 0x33, 0x39, 0x32, 0x35,
    0x5a, 0x30, 0x1f, 0x31, 0x1d, 0x30, 0x1b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x14, 0x64, 0x75, 0x65, 0x74, 0x6f,
    0x73, 0x2d, 0x74, 0x6c, 0x73, 0x2d, 0x66, 0x72, 0x61, 0x67, 0x2d, 0x74, 0x65, 0x73, 0x74, 0x30, 0x5c, 0x30, 0x0d,
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x4b, 0x00, 0x30, 0x48, 0x02,
    0x41, 0x00, 0xb4, 0xd2, 0xb1, 0x8f, 0x1a, 0x5c, 0xc7, 0xa2, 0x6a, 0x0c, 0x52, 0x9f, 0xbf, 0x00, 0x4e, 0x40, 0xa6,
    0x2e, 0x12, 0x95, 0x3f, 0x59, 0xd0, 0x5c, 0x43, 0xe4, 0x1f, 0x80, 0x57, 0x06, 0xbb, 0x72, 0xd4, 0x62, 0x22, 0x06,
    0x38, 0xfc, 0xfd, 0x3d, 0x97, 0x0a, 0xb9, 0xa4, 0x2c, 0x66, 0x20, 0xc9, 0x3e, 0x02, 0x6d, 0x53, 0x3a, 0x08, 0xe3,
    0x52, 0xac, 0x80, 0xf0, 0x51, 0xdc, 0x6e, 0x18, 0xbb, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x53, 0x30, 0x51, 0x30,
    0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x8a, 0x42, 0x07, 0xff, 0xcf, 0xa4, 0x3d, 0x29, 0xe6,
    0x79, 0xe6, 0x52, 0x41, 0x31, 0x1e, 0xdc, 0xf4, 0x8f, 0x77, 0x39, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04,
    0x18, 0x30, 0x16, 0x80, 0x14, 0x8a, 0x42, 0x07, 0xff, 0xcf, 0xa4, 0x3d, 0x29, 0xe6, 0x79, 0xe6, 0x52, 0x41, 0x31,
    0x1e, 0xdc, 0xf4, 0x8f, 0x77, 0x39, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30,
    0x03, 0x01, 0x01, 0xff, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00,
    0x03, 0x41, 0x00, 0x68, 0x0c, 0x8e, 0x9c, 0x85, 0x48, 0x92, 0xa4, 0x92, 0xd6, 0x90, 0x00, 0x03, 0xf9, 0xeb, 0x52,
    0x4b, 0x9e, 0xb3, 0x4a, 0x81, 0xfe, 0x54, 0x69, 0xb7, 0xf4, 0x20, 0x3d, 0x41, 0x5b, 0x1d, 0xa2, 0x64, 0xde, 0x87,
    0x0f, 0xb5, 0xe7, 0xac, 0x5b, 0xca, 0x1e, 0x99, 0x54, 0x30, 0x77, 0xb8, 0x10, 0xb0, 0x06, 0x7d, 0x3d, 0x90, 0x70,
    0x58, 0x9c, 0x48, 0x74, 0x9c, 0x10, 0x83, 0x1a, 0x9a, 0xc7};

// Deterministic non-zero byte source for the self-test's RSA
// padding / PMS — keeps the run reproducible.
u8 FragTestNonzeroByte()
{
    static u8 counter = 0;
    ++counter;
    if (counter == 0)
        counter = 1;
    return counter;
}

// Append a handshake message (4-byte header + body) to `dst`.
// Returns the new length.
u32 AppendHsMsg(u8* dst, u32 off, u8 hs_type, const u8* body, u32 body_len)
{
    dst[off + 0] = hs_type;
    dst[off + 1] = static_cast<u8>((body_len >> 16) & 0xFF);
    dst[off + 2] = static_cast<u8>((body_len >> 8) & 0xFF);
    dst[off + 3] = static_cast<u8>(body_len & 0xFF);
    for (u32 i = 0; i < body_len; ++i)
        dst[off + 4 + i] = body[i];
    return off + 4 + body_len;
}

// Build the server's first-flight handshake byte-stream (the
// concatenated SH || Cert || SHD handshake messages, no record
// framing). Returns total length. Also reports the byte offsets of
// each message so the caller can choose record boundaries.
struct FlightLayout
{
    u8 stream[1024];
    u32 stream_len;
    u32 cert_off; // start of the Certificate message
    u32 shd_off;  // start of the ServerHelloDone message
};

void BuildServerFlight(FlightLayout* fl)
{
    // ServerHello body: version || server_random(32, 0x5A) ||
    // session_id(0) || cipher(0x009C) || compression(0).
    u8 sh_body[38];
    u32 si = 0;
    sh_body[si++] = 0x03;
    sh_body[si++] = 0x03;
    for (u32 i = 0; i < 32; ++i)
        sh_body[si++] = 0x5A;
    sh_body[si++] = 0x00; // session_id len
    sh_body[si++] = 0x00; // cipher hi
    sh_body[si++] = 0x9C; // cipher lo
    sh_body[si++] = 0x00; // compression

    // Certificate body: cert_list_len(3) || cert_len(3) || der.
    const u32 der_len = sizeof(kFragTestLeafDer);
    u8 cert_body[3 + 3 + sizeof(kFragTestLeafDer)];
    StoreU24Be(cert_body + 0, der_len + 3);
    StoreU24Be(cert_body + 3, der_len);
    for (u32 i = 0; i < der_len; ++i)
        cert_body[6 + i] = kFragTestLeafDer[i];

    u32 off = 0;
    off = AppendHsMsg(fl->stream, off, kHandshakeServerHello, sh_body, si);
    fl->cert_off = off;
    off = AppendHsMsg(fl->stream, off, kHandshakeCertificate, cert_body, sizeof(cert_body));
    fl->shd_off = off;
    off = AppendHsMsg(fl->stream, off, kHandshakeServerHelloDone, nullptr, 0);
    fl->stream_len = off;
}

// Given a client that has just emitted CKE || CCS || (encrypted)
// client-Finished, act as the server: verify the client Finished,
// then build CCS || server-Finished using the keys the client
// derived, feed it back, and confirm the client reaches
// Established. Returns true on full success.
bool ServerCompleteHandshake(Connection* c, const u8* client_hello_rec, u32 client_hello_rec_len,
                             const u8* flight_stream, u32 flight_len, const u8* client_out, u32 client_out_len)
{
    // Parse the three records the client emitted: CKE (handshake),
    // CCS, encrypted Finished.
    RecordIter cit{client_out, client_out_len, 0};
    RecordView cke_rv{};
    RecordView ccs_rv{};
    RecordView fin_rv{};
    if (!RecordIterNext(&cit, &cke_rv) || cke_rv.type != kContentHandshake)
        return false;
    if (!RecordIterNext(&cit, &ccs_rv) || ccs_rv.type != kContentChangeCipherSpec)
        return false;
    if (!RecordIterNext(&cit, &fin_rv) || fin_rv.type != kContentHandshake)
        return false;

    // Rebuild the server's transcript exactly as the client's:
    //   ClientHello || ServerHello || Certificate || ServerHelloDone
    //   || ClientKeyExchange
    // The ClientHello handshake message is the ClientHello record's
    // payload (offset 5, length from the record header).
    RecordView ch_rv{};
    if (!TlsPeekRecord(client_hello_rec, client_hello_rec_len, &ch_rv) || ch_rv.type != kContentHandshake)
        return false;
    Transcript ts{};
    TranscriptInit(&ts);
    TranscriptUpdate(&ts, ch_rv.payload, ch_rv.length);
    TranscriptUpdate(&ts, flight_stream, flight_len);
    // The CKE handshake message is the CKE record's payload (4-byte
    // header + body), already in handshake-message shape.
    TranscriptUpdate(&ts, cke_rv.payload, cke_rv.length);

    // Decrypt the client Finished under the client's write keys
    // (server's read keys) and verify its verify_data matches the
    // "client finished" PRF over the server transcript. This is the
    // decisive check: if SHD were missing from the client's
    // transcript, this verify would fail.
    const u8* fin_record = client_out + (cit.cursor - (5 + fin_rv.length));
    const u32 fin_record_len = 5 + fin_rv.length;
    u8 cfin_inner[64];
    u32 cfin_inner_len = 0;
    u8 cfin_ct = 0;
    if (!TlsDecryptRecord(c->client_write_key, c->client_iv_salt, /*seq=*/0, fin_record, fin_record_len, cfin_inner,
                          sizeof(cfin_inner), &cfin_inner_len, &cfin_ct))
        return false;
    if (cfin_ct != kContentHandshake || cfin_inner_len != 4 + kVerifyDataBytes || cfin_inner[0] != kHandshakeFinished)
        return false;
    u8 ts_hash[32];
    TranscriptSnapshot(&ts, ts_hash);
    u8 want_cvd[kVerifyDataBytes];
    TlsFinishedVerifyData(c->master_secret, ts_hash, /*is_client=*/true, want_cvd);
    if (!BytesEq(cfin_inner + 4, want_cvd, kVerifyDataBytes))
        return false;

    // Mix the client Finished message into the server transcript,
    // then build the server's CCS + encrypted Finished.
    TranscriptUpdate(&ts, cfin_inner, cfin_inner_len);

    u8 server_reply[256];
    u32 ro = 0;
    static constexpr u8 ccs_payload[1] = {0x01};
    const u32 ccs_len =
        TlsWrapRecord(kContentChangeCipherSpec, ccs_payload, 1, server_reply + ro, sizeof(server_reply));
    if (ccs_len == 0)
        return false;
    ro += ccs_len;
    const u32 sfin_len =
        TlsBuildEncryptedFinished(c->master_secret, ts, c->server_write_key, c->server_iv_salt, /*seq=*/0,
                                  /*is_client=*/false, server_reply + ro, sizeof(server_reply) - ro);
    if (sfin_len == 0)
        return false;
    ro += sfin_len;

    // Feed the server's reply to the client. It must verify the
    // server Finished and reach Established.
    u8 unused_out[64];
    ConnectionFeed(c, server_reply, ro, unused_out, sizeof(unused_out), FragTestNonzeroByte);
    return c->state == State::Established;
}

// Drive one complete handshake where the server flight is delivered
// in a specific record framing. `feed_split_at` (>0) inserts a
// ConnectionFeed() boundary: the records up to that record-index
// are fed first, then the rest in a second Feed call (proving the
// flight can be dribbled across multiple Feed() calls). The records
// themselves are described by an array of [start,end) offsets into
// the handshake byte-stream — one record per entry — so the caller
// controls exactly where record boundaries fall (including mid
// handshake message).
struct RecBound
{
    u32 begin;
    u32 end;
};

bool RunFramedHandshake(const RecBound* recs, u32 rec_count, u32 feed_after_rec)
{
    FlightLayout fl{};
    BuildServerFlight(&fl);

    // Connection carries a 16 KiB reassembly buffer — keep it off
    // the (shared) boot self-test stack. This self-test is
    // single-threaded and non-reentrant, so a function-local static
    // is safe and zeroed fresh by ConnectionStart each call.
    static Connection c{};
    const u8 client_random[kClientRandomBytes] = {0};
    u8 pms[kPreMasterSecretBytes] = {0};
    pms[0] = 0x03;
    pms[1] = 0x03;
    u8 ch_out[512];
    // Empty hostname -> skip the CN check (the leaf CN is fixed).
    const u32 ch_len = ConnectionStart(&c, client_random, pms, "", ch_out, sizeof(ch_out));
    if (ch_len == 0)
        return false;

    // Materialise each described record into a contiguous wire
    // buffer.
    static u8 wire[2048];
    u32 wire_len = 0;
    u32 split_byte = 0xFFFFFFFFu; // byte offset of the Feed boundary
    for (u32 r = 0; r < rec_count; ++r)
    {
        const u32 slice_len = recs[r].end - recs[r].begin;
        const u32 w = TlsWrapRecord(kContentHandshake, fl.stream + recs[r].begin, slice_len, wire + wire_len,
                                    sizeof(wire) - wire_len);
        if (w == 0)
            return false;
        wire_len += w;
        if (feed_after_rec != 0 && r + 1 == feed_after_rec)
            split_byte = wire_len;
    }

    u8 cli_out[1024];
    u32 cli_out_len = 0;
    if (split_byte != 0xFFFFFFFFu && split_byte < wire_len)
    {
        // First Feed: only the leading records. The flight is
        // incomplete (no SHD yet, or SHD partial) -> no client
        // output; state stays SentClientHello.
        const u32 w1 = ConnectionFeed(&c, wire, split_byte, cli_out, sizeof(cli_out), FragTestNonzeroByte);
        if (c.state == State::Failed || w1 != 0 || c.state != State::SentClientHello)
            return false;
        // Second Feed: the full accumulated buffer (the caller
        // re-feeds from offset 0, matching TlsSocketHandshake).
        cli_out_len = ConnectionFeed(&c, wire, wire_len, cli_out, sizeof(cli_out), FragTestNonzeroByte);
    }
    else
    {
        cli_out_len = ConnectionFeed(&c, wire, wire_len, cli_out, sizeof(cli_out), FragTestNonzeroByte);
    }
    if (c.state != State::SentClientKeyAndFinish || cli_out_len == 0)
        return false;

    return ServerCompleteHandshake(&c, ch_out, ch_len, fl.stream, fl.stream_len, cli_out, cli_out_len);
}

// Returns true iff every framing variant drives a complete,
// Finished-verifying handshake.
bool TlsFragmentationCases()
{
    FlightLayout fl{};
    BuildServerFlight(&fl);
    const u32 end = fl.stream_len;

    // Case A (baseline): all three messages coalesced in ONE record.
    {
        const RecBound recs[] = {{0, end}};
        if (!RunFramedHandshake(recs, 1, 0))
            return false;
    }
    // Case B: SH, Cert, SHD as THREE separate records, one Feed call.
    {
        const RecBound recs[] = {{0, fl.cert_off}, {fl.cert_off, fl.shd_off}, {fl.shd_off, end}};
        if (!RunFramedHandshake(recs, 3, 0))
            return false;
    }
    // Case C: same three records, but split across TWO Feed calls
    // with the boundary AFTER record 2 (SH+Cert fed first, SHD
    // arrives in the second Feed).
    {
        const RecBound recs[] = {{0, fl.cert_off}, {fl.cert_off, fl.shd_off}, {fl.shd_off, end}};
        if (!RunFramedHandshake(recs, 3, 2))
            return false;
    }
    // Case D: a single handshake message SPLIT across two records —
    // the Certificate message is cut in the middle, so the client
    // must buffer the partial until the rest arrives. Also split the
    // Feed call mid-Certificate to exercise cross-Feed reassembly of
    // one message.
    {
        const u32 cert_mid = fl.cert_off + ((fl.shd_off - fl.cert_off) / 2);
        const RecBound recs[] = {{0, fl.cert_off}, {fl.cert_off, cert_mid}, {cert_mid, fl.shd_off}, {fl.shd_off, end}};
        // Feed boundary after record 2 (mid-Certificate).
        if (!RunFramedHandshake(recs, 4, 2))
            return false;
    }
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

    // Test 11: AES-GCM record encrypt/decrypt round-trip.
    // Build a 9-byte plaintext, encrypt under a known key+salt
    // at seq=42, decrypt with the same params, recover bytes.
    const u8 record_key[16] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                               0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00};
    const u8 record_salt[4] = {0xCA, 0xFE, 0xBA, 0xBE};
    const u8 record_pt[9] = {'H', 'e', 'l', 'l', 'o', ' ', 'T', 'L', 'S'};
    u8 record_wire[64];
    const u32 record_wire_len = TlsEncryptRecord(record_key, record_salt, /*seq_num=*/42, kContentApplicationData,
                                                 record_pt, sizeof(record_pt), record_wire, sizeof(record_wire));
    if (record_wire_len != 5u + 8u + sizeof(record_pt) + 16u)
    {
        SerialWrite("[tls] FAIL record-enc-len\n");
        return;
    }
    if (record_wire[0] != kContentApplicationData || record_wire[1] != 0x03 || record_wire[2] != 0x03)
    {
        SerialWrite("[tls] FAIL record-enc-header\n");
        return;
    }
    u8 record_back[32];
    u32 record_back_len = 0;
    u8 record_back_type = 0;
    if (!TlsDecryptRecord(record_key, record_salt, /*seq_num=*/42, record_wire, record_wire_len, record_back,
                          sizeof(record_back), &record_back_len, &record_back_type))
    {
        SerialWrite("[tls] FAIL record-dec\n");
        return;
    }
    if (record_back_len != sizeof(record_pt) || record_back_type != kContentApplicationData)
    {
        SerialWrite("[tls] FAIL record-dec-shape\n");
        return;
    }
    for (u32 i = 0; i < sizeof(record_pt); ++i)
    {
        if (record_back[i] != record_pt[i])
        {
            SerialWrite("[tls] FAIL record-dec-bytes\n");
            return;
        }
    }
    // Flip a ciphertext byte and confirm decrypt fails (the
    // AEAD tag catches it).
    record_wire[14] ^= 0x80;
    if (TlsDecryptRecord(record_key, record_salt, 42, record_wire, record_wire_len, record_back, sizeof(record_back),
                         &record_back_len, &record_back_type))
    {
        SerialWrite("[tls] FAIL record-dec-tamper-accepted\n");
        return;
    }
    record_wire[14] ^= 0x80; // restore
    // Wrong seq_num at decrypt -> AAD mismatch -> tag fail.
    if (TlsDecryptRecord(record_key, record_salt, /*seq_num=*/43, record_wire, record_wire_len, record_back,
                         sizeof(record_back), &record_back_len, &record_back_type))
    {
        SerialWrite("[tls] FAIL record-dec-wrong-seq-accepted\n");
        return;
    }

    // Test 12: Finished round-trip + transcript verify.
    // Build two parallel transcripts (client + server), feed
    // both the same handshake bytes, then verify the client's
    // encrypted Finished re-snaps the same verify_data and
    // that a server Finished computed with the matching
    // master_secret + transcript verifies via
    // TlsVerifyEncryptedServerFinished.
    Transcript tr_client{};
    Transcript tr_server{};
    TranscriptInit(&tr_client);
    TranscriptInit(&tr_server);
    // Feed three synthetic handshake messages into both
    // transcripts. Any 4-byte-headered byte sequence will do
    // for the test — we just need both sides to agree.
    const u8 msg_a[] = {0x01, 0x00, 0x00, 0x03, 0xAA, 0xBB, 0xCC};
    const u8 msg_b[] = {0x02, 0x00, 0x00, 0x02, 0xDE, 0xAD};
    const u8 msg_c[] = {0x0E, 0x00, 0x00, 0x00}; // ServerHelloDone
    TranscriptUpdate(&tr_client, msg_a, sizeof(msg_a));
    TranscriptUpdate(&tr_server, msg_a, sizeof(msg_a));
    TranscriptUpdate(&tr_client, msg_b, sizeof(msg_b));
    TranscriptUpdate(&tr_server, msg_b, sizeof(msg_b));
    TranscriptUpdate(&tr_client, msg_c, sizeof(msg_c));
    TranscriptUpdate(&tr_server, msg_c, sizeof(msg_c));

    // Use a synthetic master_secret + a single key for both
    // directions (simplifies the test; real handshake derives
    // distinct client/server keys from key_block).
    u8 test_ms[kMasterSecretBytes];
    for (u32 i = 0; i < kMasterSecretBytes; ++i)
        test_ms[i] = static_cast<u8>(0xA0 + (i & 0x1F));
    const u8 test_key[kAesGcmKeyBytes] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                          0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
    const u8 test_salt[kAesGcmFixedIvBytes] = {0x20, 0x21, 0x22, 0x23};

    // Client builds its Finished. Then the SERVER side
    // (different transcript at this exact point — client's
    // Finished hasn't been mixed in yet) would expect to see
    // exactly this verify_data when it decrypts.
    u8 client_fin_wire[64];
    const u32 client_fin_len = TlsBuildEncryptedFinished(test_ms, tr_client, test_key, test_salt, /*seq_num=*/0,
                                                         /*is_client=*/true, client_fin_wire, sizeof(client_fin_wire));
    if (client_fin_len == 0)
    {
        SerialWrite("[tls] FAIL fin-build\n");
        return;
    }

    // Decrypt the client Finished to confirm verify_data
    // matches what's expected with the "client finished" label.
    u8 fin_pt[32];
    u32 fin_pt_len = 0;
    u8 fin_pt_type = 0;
    if (!TlsDecryptRecord(test_key, test_salt, /*seq_num=*/0, client_fin_wire, client_fin_len, fin_pt, sizeof(fin_pt),
                          &fin_pt_len, &fin_pt_type))
    {
        SerialWrite("[tls] FAIL fin-decrypt\n");
        return;
    }
    if (fin_pt_type != kContentHandshake || fin_pt_len != 4 + kVerifyDataBytes || fin_pt[0] != kHandshakeFinished)
    {
        SerialWrite("[tls] FAIL fin-shape\n");
        return;
    }
    u8 fin_hash[32];
    TranscriptSnapshot(&tr_server, fin_hash);
    u8 want_client_vd[kVerifyDataBytes];
    TlsFinishedVerifyData(test_ms, fin_hash, /*is_client=*/true, want_client_vd);
    for (u32 i = 0; i < kVerifyDataBytes; ++i)
    {
        if (fin_pt[4 + i] != want_client_vd[i])
        {
            SerialWrite("[tls] FAIL fin-vd\n");
            return;
        }
    }

    // Now mix the client Finished message bytes into the
    // server's transcript (the server's view of what the
    // client just sent), then have a "server" build its
    // Finished and verify it from the client side.
    u8 client_fin_msg[4 + kVerifyDataBytes];
    client_fin_msg[0] = kHandshakeFinished;
    client_fin_msg[1] = 0;
    client_fin_msg[2] = 0;
    client_fin_msg[3] = kVerifyDataBytes;
    for (u32 i = 0; i < kVerifyDataBytes; ++i)
        client_fin_msg[4 + i] = want_client_vd[i];
    TranscriptUpdate(&tr_server, client_fin_msg, sizeof(client_fin_msg));
    TranscriptUpdate(&tr_client, client_fin_msg, sizeof(client_fin_msg));

    u8 server_fin_wire[64];
    const u32 server_fin_len = TlsBuildEncryptedFinished(test_ms, tr_server, test_key, test_salt, /*seq_num=*/0,
                                                         /*is_client=*/false, server_fin_wire, sizeof(server_fin_wire));
    if (server_fin_len == 0)
    {
        SerialWrite("[tls] FAIL srvfin-build\n");
        return;
    }
    if (!TlsVerifyEncryptedServerFinished(test_ms, tr_client, test_key, test_salt, /*seq_num=*/0, server_fin_wire,
                                          server_fin_len))
    {
        SerialWrite("[tls] FAIL srvfin-verify\n");
        return;
    }
    // Negative: tamper with the encrypted Finished -> verify
    // fails (GCM tag catches it before we even reach the
    // verify_data compare).
    server_fin_wire[5 + kAesGcmExplicitIvBytes] ^= 0x80;
    if (TlsVerifyEncryptedServerFinished(test_ms, tr_client, test_key, test_salt, 0, server_fin_wire, server_fin_len))
    {
        SerialWrite("[tls] FAIL srvfin-tamper-accepted\n");
        return;
    }

    // Test 13: Fragmented server flight. Drive the full client
    // handshake with SH/Cert/SHD framed coalesced, as three
    // separate records, split across two Feed calls, and with one
    // handshake message split across record boundaries — asserting
    // the client reaches Established and its Finished verifies in
    // EVERY framing. This is the regression guard for the
    // record/handshake-reassembly fix.
    if (!TlsFragmentationCases())
    {
        SerialWrite("[tls-fragmentation-selftest] FAIL\n");
        return;
    }
    SerialWrite("[tls-fragmentation-selftest] PASS\n");

    SerialWrite("[tls] PASS (prf + cke + record-aead + transcript + finished + srv-fin verify)\n");
}
} // namespace duetos::net::tls
