#pragma once

#include "crypto/aes_gcm.h"
#include "crypto/sha256.h"
#include "crypto/x509.h"
#include "util/types.h"

/*
 * DuetOS — TLS 1.2 client (Tier 1 scaffold).
 *
 * Single-cipher-suite TLS 1.2 client per RFC 5246, narrowed to:
 *   - TLS_RSA_WITH_AES_128_GCM_SHA256 (RFC 5288)
 *   - 96-bit explicit IV (TLS 1.2 GCM record-layer convention)
 *   - 128-bit AEAD tag
 *   - No client certificate
 *   - No SNI extension (yet — easy follow-on once a server we
 *     care about demands it)
 *
 * Trust model: v0 accepts ANY server certificate without
 * validation. The roadmap (wiki/networking/TLS-Roadmap.md)
 * Tier 3 is what wires real chain validation against a bundled
 * root store. The scaffold here makes the calling code see a
 * TLS connection; turning it into a cryptographically trusted
 * channel is a follow-on.
 *
 * Threading: the Connection struct is caller-owned. No global
 * state. Safe from any context that can do AES + RSA + SHA-256.
 *
 * I/O surface: pure-functional state transitions. The caller
 * is responsible for moving bytes between this module and a
 * socket — Tls{Step}Bytes returns the next plaintext bytes to
 * send; the caller feeds incoming bytes back via TlsFeed. This
 * keeps the TLS layer unit-testable without a real socket.
 */

namespace duetos::net::tls
{

inline constexpr u16 kVersionTls12 = 0x0303;
inline constexpr u16 kCipherTlsRsaAes128GcmSha256 = 0x009C; // RFC 5288

inline constexpr u8 kContentChangeCipherSpec = 20;
inline constexpr u8 kContentAlert = 21;
inline constexpr u8 kContentHandshake = 22;
inline constexpr u8 kContentApplicationData = 23;

inline constexpr u8 kHandshakeClientHello = 1;
inline constexpr u8 kHandshakeServerHello = 2;
inline constexpr u8 kHandshakeCertificate = 11;
inline constexpr u8 kHandshakeServerHelloDone = 14;
inline constexpr u8 kHandshakeClientKeyExchange = 16;
inline constexpr u8 kHandshakeFinished = 20;

inline constexpr u32 kClientRandomBytes = 32;
inline constexpr u32 kServerRandomBytes = 32;
inline constexpr u32 kPreMasterSecretBytes = 48;
inline constexpr u32 kMasterSecretBytes = 48;
inline constexpr u32 kVerifyDataBytes = 12;

inline constexpr u32 kAesGcmKeyBytes = 16;    // matches crypto::kAes128KeyBytes
inline constexpr u32 kAesGcmFixedIvBytes = 4; // RFC 5288 §3 — fixed_iv_length
inline constexpr u32 kAesGcmExplicitIvBytes = 8;

// Total derived material per RFC 5246 §6.3:
//   key_block = PRF(master_secret, "key expansion",
//                   ServerRandom || ClientRandom)
// For GCM: mac_key_length = 0, key_length = 16, iv_length = 4
//   -> key_block = 2*0 + 2*16 + 2*4 = 40 bytes
inline constexpr u32 kKeyBlockBytes = 2 * kAesGcmKeyBytes + 2 * kAesGcmFixedIvBytes;

/// Run TLS 1.2 PRF P_SHA256 (RFC 5246 §5):
///   PRF(secret, label, seed) = P_SHA256(secret, label || seed)
/// `out_len` is the number of output bytes the caller wants.
void TlsPrfSha256(const u8* secret, u32 secret_len, const char* label, const u8* seed, u32 seed_len, u8* out,
                  u32 out_len);

/// Compute key_block from master_secret + (server_random,
/// client_random). RFC 5246 §6.3. Caller passes a buffer of
/// `kKeyBlockBytes` bytes.
void TlsKeyBlock(const u8 master_secret[kMasterSecretBytes], const u8 server_random[kServerRandomBytes],
                 const u8 client_random[kClientRandomBytes], u8 key_block[kKeyBlockBytes]);

/// Compute the master secret from a pre-master secret and the
/// two nonces. RFC 5246 §8.1.
void TlsMasterSecret(const u8 pms[kPreMasterSecretBytes], const u8 client_random[kClientRandomBytes],
                     const u8 server_random[kServerRandomBytes], u8 master_secret[kMasterSecretBytes]);

/// Compute the Finished message's verify_data per RFC 5246 §7.4.9.
///   verify_data = PRF(master_secret, finished_label,
///                     SHA-256(handshake_messages))[0..12]
/// `is_client` selects "client finished" vs "server finished".
void TlsFinishedVerifyData(const u8 master_secret[kMasterSecretBytes], const u8 transcript_hash[32], bool is_client,
                           u8 verify_data[kVerifyDataBytes]);

/// Build a ClientHello body (just the body bytes — the
/// containing handshake header and record header are added by
/// the record-framing helpers). Writes ASCII-shaped TLS 1.2
/// ClientHello with our single cipher suite and an empty
/// extensions list.
///
/// `client_random` is the 32-byte random the caller has seeded
/// (caller pulls entropy from the kernel CSPRNG).
///
/// Returns the number of bytes written, or 0 if `cap` is too
/// small.
u32 TlsBuildClientHelloBody(const u8 client_random[kClientRandomBytes], u8* dst, u32 cap);

/// Wrap a payload as a TLS record (RFC 5246 §6.2.1):
///   type | version | length | payload
/// `type` is one of the kContent* constants. Returns the total
/// record length in bytes, or 0 if `cap` is insufficient.
u32 TlsWrapRecord(u8 type, const u8* payload, u32 payload_len, u8* dst, u32 cap);

/// Wrap a handshake message inside a record. Pre-pends the
/// handshake-header (1-byte type + 3-byte length) and then
/// `TlsWrapRecord` with type kContentHandshake.
u32 TlsWrapHandshake(u8 hs_type, const u8* body, u32 body_len, u8* dst, u32 cap);

// ---- record / handshake message peek ---------------------------

/// Parsed TLS record header. Slice into the caller's input
/// buffer — `payload` points to the first byte AFTER the
/// 5-byte record header.
struct RecordView
{
    u8 type;
    u16 version;
    u16 length; // record payload length
    const u8* payload;
};

/// Parse one record header out of `buf[0..len)`. Returns true
/// on success and populates `out`. Does NOT validate the
/// payload length against `len`; callers do `len >= 5 +
/// out.length` before consuming.
bool TlsPeekRecord(const u8* buf, u32 len, RecordView* out);

/// Parsed handshake header. Slice into the caller's input
/// buffer — `body` points to the first byte AFTER the 4-byte
/// handshake header.
struct HandshakeView
{
    u8 type;
    u32 length; // 24-bit handshake-body length
    const u8* body;
};

/// Parse the 4-byte handshake header from `buf[0..len)`. The
/// caller must have already extracted the record-layer
/// payload (e.g. via TlsPeekRecord).
bool TlsPeekHandshake(const u8* buf, u32 len, HandshakeView* out);

// ---- server-side handshake-message parsers ---------------------

/// Parse a ServerHello body (RFC 5246 §7.4.1.3) — the bytes
/// AFTER the handshake header (HandshakeView::body). Extracts
/// the server_random and the selected cipher suite. Returns
/// true on a well-formed message + a cipher suite we
/// recognise (we only support kCipherTlsRsaAes128GcmSha256).
bool TlsParseServerHello(const u8* body, u32 len, u8 server_random[kServerRandomBytes], u16* out_cipher);

/// Parse a Certificate message body (RFC 5246 §7.4.2). Returns
/// a slice over the LEAF certificate's DER bytes (the first
/// cert in the chain). The DER blob can be handed to
/// crypto::x509::Parse to extract the server's RSA public key.
bool TlsParseCertificateLeaf(const u8* body, u32 len, const u8** out_leaf_der, u32* out_leaf_len);

/// Confirm a ServerHelloDone message body is well-formed.
/// Body must be exactly 0 bytes; the only check is `len == 0`.
bool TlsParseServerHelloDone(const u8* body, u32 len);

// ---- client outbound: ClientKeyExchange ------------------------

/// Build the ClientKeyExchange body for a TLS_RSA cipher suite
/// (RFC 5246 §7.4.7.1):
///   struct {
///       opaque encrypted_pre_master_secret<0..2^16-1>;
///   } ClientKeyExchange;
///
/// The encrypted PMS is `pms` PKCS#1 v1.5 type-2 padded to the
/// server's RSA modulus width, then ModExp(server_e, server_n).
/// `random_fill` generates the non-zero padding bytes (one byte
/// per call, must be non-zero). v0 callers pass
/// duetos::core::RandomU64-backed wrappers.
///
/// Returns the body length on success (2-byte len + modulus
/// bytes), 0 on any failure (bad cap, RSA reject, etc.).
using RandomByteFn = u8 (*)();
u32 TlsBuildClientKeyExchangeBody(const crypto::RsaPublicKey& server_rsa, const u8 pms[kPreMasterSecretBytes],
                                  RandomByteFn random_nonzero_byte, u8* dst, u32 cap);

/// PKCS#1 v1.5 type-2 encrypt of a message into a buffer at the
/// modulus width. Exposed separately so the padding logic is
/// unit-testable without going through ModExp. Pads the EM to
/// `k.n_bytes` and writes to `dst[0..k.n_bytes)`. Caller still
/// has to do the ModExp to produce the ciphertext.
bool Pkcs1V15Type2Pad(const crypto::RsaPublicKey& k, const u8* msg, u32 msg_len, RandomByteFn random_nonzero_byte,
                      u8* dst);

// ---- handshake transcript hash ---------------------------------

/// Running SHA-256 over the handshake transcript. RFC 5246 §7.4.9
/// requires the Finished verify_data to be computed against a
/// hash of "all handshake messages sent or received in
/// chronological order" with their 4-byte handshake headers but
/// no record-layer framing. This wrapper exists so the call
/// site can keep state inside a Connection struct without
/// reaching into Sha256Ctx directly.
struct Transcript
{
    crypto::Sha256Ctx ctx;
};

void TranscriptInit(Transcript* t);

/// Mix one handshake message into the transcript. `msg` must
/// include the 4-byte handshake header (type + 24-bit length)
/// followed by the body — i.e. exactly what
/// `TlsWrapHandshake` produces from offset 5 onwards.
void TranscriptUpdate(Transcript* t, const u8* msg, u32 len);

/// Snapshot the current transcript hash without disturbing
/// the running state. Lets callers compute Finished
/// verify_data and then continue feeding subsequent messages
/// (the server's Finished, for instance).
void TranscriptSnapshot(const Transcript* t, u8 out[32]);

// ---- Finished message -----------------------------------------

/// Build a complete wire-format Finished record. Composes:
///   1. Snapshot the transcript hash.
///   2. Derive verify_data (12 bytes) via TlsFinishedVerifyData.
///   3. Frame it as a Finished handshake message
///        [type=0x14, 24-bit length=0x0c, verify_data...]
///      (16 bytes total, header + body).
///   4. Encrypt that as a TLS 1.2 record under (write_key,
///      write_iv_salt, seq_num) using TlsEncryptRecord.
///
/// Caller is responsible for incrementing the sequence number
/// after this call AND for mixing the 16-byte unencrypted
/// Finished message into the transcript afterwards (so the
/// matching server Finished verifies against the same
/// transcript snapshot).
///
/// Returns the on-wire record length, or 0 on capacity / arg
/// failure.
u32 TlsBuildEncryptedFinished(const u8 master_secret[kMasterSecretBytes], const Transcript& transcript,
                              const u8 write_key[kAesGcmKeyBytes], const u8 write_iv_salt[kAesGcmFixedIvBytes],
                              u64 seq_num, bool is_client, u8* dst, u32 cap);

/// Verify a server Finished record under the server's keys.
/// `record_bytes` is the encrypted wire-format record. The
/// helper decrypts it, confirms the inner handshake is a
/// 16-byte Finished message, computes the expected
/// verify_data from `transcript` + master_secret with the
/// "server finished" label, and constant-time-compares.
/// Returns true on a valid match.
bool TlsVerifyEncryptedServerFinished(const u8 master_secret[kMasterSecretBytes], const Transcript& transcript,
                                      const u8 read_key[kAesGcmKeyBytes], const u8 read_iv_salt[kAesGcmFixedIvBytes],
                                      u64 seq_num, const u8* record_bytes, u32 record_len);

// ---- Connection state machine ----------------------------------

enum class State : u8
{
    Init = 0,
    SentClientHello,
    RecvServerHelloBundle, // got ServerHello + Cert + SrvHelloDone
    SentClientKeyAndFinish,
    Established,
    Failed,
};

/// Caller-owned TLS 1.2 client connection. Holds every piece of
/// state across the handshake plus the established-mode read /
/// write keys. The state machine is driven by three calls:
///
///   1. ConnectionStart(c, random, pms, ...) — emits ClientHello
///   2. ConnectionFeed(c, server_bytes, ...) — parses server
///      records and emits the next client bytes (one round-trip
///      at a time)
///   3. After Established: ConnectionEncryptApp /
///      ConnectionDecryptApp for application-data records.
struct Connection
{
    State state;
    u8 client_random[kClientRandomBytes];
    u8 server_random[kServerRandomBytes];
    u8 pre_master_secret[kPreMasterSecretBytes];
    u8 master_secret[kMasterSecretBytes];

    // Derived from key_block (RFC 5246 §6.3). For TLS_RSA_WITH_
    // AES_128_GCM_SHA256: client_key | server_key | client_iv |
    // server_iv (16, 16, 4, 4 bytes).
    u8 client_write_key[kAesGcmKeyBytes];
    u8 server_write_key[kAesGcmKeyBytes];
    u8 client_iv_salt[kAesGcmFixedIvBytes];
    u8 server_iv_salt[kAesGcmFixedIvBytes];

    // Record-layer sequence numbers, per direction. Both reset
    // to 0 immediately after their respective ChangeCipherSpec.
    u64 client_seq;
    u64 server_seq;

    // Running SHA-256 of every handshake message (with the
    // 4-byte handshake header but no record framing).
    Transcript transcript;

    // Pulled from the server's leaf certificate. The state
    // machine RSA-encrypts the pms under this key for the
    // ClientKeyExchange.
    crypto::RsaPublicKey server_rsa;
    bool server_cert_seen;

    // Last error message, valid when state == Failed. Pointer
    // into a static literal — never freed.
    const char* err;
};

/// Initialise + emit ClientHello. Caller passes:
///   client_random: 32 bytes of CSPRNG output
///   pms          : 48 bytes — first two bytes MUST be 0x03 0x03
///                  (the client's offered TLS version, per
///                  RFC 5246 §7.4.7.1). Remaining 46 are
///                  caller-supplied entropy.
///
/// Writes the ClientHello record bytes to `out` and returns the
/// length. Advances state to SentClientHello.
u32 ConnectionStart(Connection* c, const u8 client_random[kClientRandomBytes], const u8 pms[kPreMasterSecretBytes],
                    u8* out, u32 cap);

/// Feed bytes received from the server. The state machine peels
/// off complete TLS records, advances state, and emits whatever
/// client-side bytes are owed in response. Returns the number of
/// bytes written to `out`. On state == Failed, writes nothing
/// and sets `c->err`.
///
/// `server_bytes` MUST cover at least one complete record /
/// flight worth of data (the caller buffers socket reads until a
/// boundary). v0 simplification — real-world TLS libraries
/// stream-decode incrementally; layering that on is a follow-on.
u32 ConnectionFeed(Connection* c, const u8* server_bytes, u32 len, u8* out, u32 cap, RandomByteFn random_nonzero_byte);

/// Encrypt an application-data payload into a wire-format TLS
/// record. Only valid in state == Established. Wraps the payload
/// with TlsEncryptRecord using client_write_key +
/// client_iv_salt + client_seq, then advances client_seq.
/// Returns the on-wire length, or 0 on capacity / state error.
u32 ConnectionEncryptApp(Connection* c, const u8* pt, u32 pt_len, u8* dst, u32 cap);

/// Decrypt one inbound application-data record. Validates the
/// content type, decrypts under server_write_key + server_iv_salt
/// + server_seq, then advances server_seq. Returns true on
/// success; writes the plaintext to `pt_out` + `*pt_len_out`.
bool ConnectionDecryptApp(Connection* c, const u8* record_bytes, u32 record_len, u8* pt_out, u32 cap, u32* pt_len_out);

/// True iff the handshake has completed.
inline bool ConnectionIsEstablished(const Connection* c)
{
    return c != nullptr && c->state == State::Established;
}

// ---- record-layer AES-GCM encrypt / decrypt ---------------------

/// Encrypt one TLS 1.2 record. Composes a wire-format record:
///
///   header  : type(1) | version(2) | length(2)
///             where length = 8 + plaintext_len + 16
///   payload : explicit_iv(8) || GCM-ciphertext(plaintext_len)
///                            || GCM-tag(16)
///
/// AAD (per RFC 5288 §3 / RFC 5246 §6.2.3.3) is:
///   seq_num(8 BE) || type(1) || version(2) || plaintext_len(2 BE)
///
/// GCM nonce is implicit_iv(4, the "salt" from key_block) ||
/// explicit_iv(8 — we use the record seq_num, BE). Returns the
/// total wire-format byte count, or 0 on capacity / argument
/// failure.
u32 TlsEncryptRecord(const u8 write_key[kAesGcmKeyBytes], const u8 write_iv_salt[kAesGcmFixedIvBytes], u64 seq_num,
                     u8 content_type, const u8* plaintext, u32 plaintext_len, u8* dst, u32 cap);

/// Decrypt one TLS 1.2 record. `record_bytes` is the full wire-
/// format record starting at the type byte; `record_len` is the
/// total record length (header + 8 explicit_iv + ct + 16 tag).
/// On success, writes the plaintext to `plaintext_out`,
/// populates `*out_plaintext_len` and `*out_content_type`, and
/// returns true. On any failure (bad header, bad length, GCM
/// tag mismatch), returns false without writing partial
/// plaintext.
bool TlsDecryptRecord(const u8 read_key[kAesGcmKeyBytes], const u8 read_iv_salt[kAesGcmFixedIvBytes], u64 seq_num,
                      const u8* record_bytes, u32 record_len, u8* plaintext_out, u32 cap, u32* out_plaintext_len,
                      u8* out_content_type);

void TlsSelfTest();

} // namespace duetos::net::tls
