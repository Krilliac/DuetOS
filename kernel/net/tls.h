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

void TlsSelfTest();

} // namespace duetos::net::tls
