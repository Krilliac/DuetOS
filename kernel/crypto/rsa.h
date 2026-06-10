#pragma once

#include "crypto/bigint.h"
#include "util/types.h"

/*
 * DuetOS — RSA public-key operations (verify-only in v0).
 *
 * Implements the v0 subset of PKCS#1 v2.2 (RFC 8017) we need
 * to verify X.509 certificate signatures and the TLS 1.2
 * server CertificateVerify messages backed by RSA:
 *
 *   - Key construction from big-endian (modulus, public-exponent)
 *     byte pairs as they appear in the SubjectPublicKeyInfo of
 *     an X.509 certificate.
 *   - RsaPkcs1V15Verify: the canonical EMSA-PKCS1-v1_5 verify
 *     path — RSAVP1 (modular exponentiation) followed by
 *     constant-time-ish PKCS1 v1.5 padding + DigestInfo decode.
 *
 * Out of scope:
 *   - RSA sign (we don't sign anything in v0; TLS client paths
 *     authenticate the server, not the client).
 *   - RSA-PSS (RSASSA-PSS) — RFC 8017 §8.1. Modern signers
 *     prefer PSS; verify support lands when we hit a TLS server
 *     that signs with PSS only.
 *   - OAEP encryption / decryption.
 *
 * Built on top of crypto/bigint.{h,cpp} for the big-integer
 * math and crypto/asn1.{h,cpp} for the DigestInfo SEQUENCE
 * parse on the unpadded message.
 */

namespace duetos::crypto
{

/// PKCS#1 v1.5 "DigestInfo" prefix for SHA-256. Concatenated
/// with the 32-byte raw digest gives the EM (encoded message)
/// payload that PKCS1 v1.5 wraps inside the signature.
/// Reference: RFC 8017 §9.2 Notes, line for sha256WithRSAEncryption.
inline constexpr u8 kPkcs1Sha256DigestPrefix[] = {0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                                  0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
inline constexpr u32 kPkcs1Sha256DigestPrefixLen = sizeof(kPkcs1Sha256DigestPrefix);

/// SHA-1 DigestInfo prefix (RFC 8017 §9.2).
inline constexpr u8 kPkcs1Sha1DigestPrefix[] = {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E,
                                                0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14};
inline constexpr u32 kPkcs1Sha1DigestPrefixLen = sizeof(kPkcs1Sha1DigestPrefix);

/// RSA public key. Caller-owned; populated by RsaPublicKeyFromBE.
struct RsaPublicKey
{
    BigInt n;    // modulus
    BigInt e;    // public exponent (typically 65537)
    u32 n_bytes; // ceil(bits(n) / 8) — signature width
};

/// Populate `k` from the big-endian byte forms typically pulled
/// out of an X.509 SubjectPublicKeyInfo:
///   modulus n     : RSAPublicKey.modulus INTEGER value (after
///                   ASN.1 padding strip)
///   exponent e    : RSAPublicKey.publicExponent INTEGER value
///                   (usually exactly 3 bytes for 65537)
/// Returns false if either value exceeds BigInt's fixed width
/// or both are non-zero is violated.
bool RsaPublicKeyFromBE(RsaPublicKey* k, const u8* mod_be, u32 mod_len, const u8* exp_be, u32 exp_len);

/// Verify a PKCS#1 v1.5 signature.
///
///   sig       Signature bytes, exactly `k.n_bytes` long. Output
///             of the matching RSAVP1 sign on the other side.
///   sig_len   Must equal `k.n_bytes`.
///   prefix    DigestInfo prefix bytes for the hash algorithm
///             (one of kPkcs1Sha256DigestPrefix etc.).
///   prefix_len  Length of `prefix`.
///   hash      Raw hash digest (e.g. 32 bytes of SHA-256 output).
///   hash_len  Length of `hash` (32 for SHA-256, 20 for SHA-1).
///
/// Returns true iff: RSAVP1(sig) decodes to a well-formed
/// PKCS#1 v1.5 padded message AND the trailing DigestInfo
/// segment matches `prefix || hash` exactly. Any deviation
/// (bad leading bytes, wrong PS length, T mismatch) returns
/// false — the caller should treat that as an authentication
/// failure.
bool RsaPkcs1V15Verify(const RsaPublicKey& k, const u8* sig, u32 sig_len, const u8* prefix, u32 prefix_len,
                       const u8* hash, u32 hash_len);

/// Decode an EM buffer (encoded message — the modulus-width
/// output of RSAVP1) as PKCS#1 v1.5 and validate the trailing
/// `prefix || hash` matches. Exposed separately so the padding
/// logic is unit-testable without going through ModExp.
///
/// Returns true on a valid v1.5 encoding with matching T.
bool Pkcs1V15UnwrapAndMatch(const u8* em, u32 em_len, const u8* prefix, u32 prefix_len, const u8* hash, u32 hash_len);

/// Verify an RSASSA-PSS signature with SHA-256 and salt length 32 — the
/// `rsa_pss_rsae_sha256` SignatureScheme used for an RSA CertificateVerify
/// in TLS 1.3 (which forbids PKCS#1 v1.5 for handshake signatures).
/// `mhash` is the 32-byte SHA-256 of the signed message; `mhash_len` must
/// be 32. Returns true iff the PSS encoding verifies under `k`.
bool RsaPssSha256Verify(const RsaPublicKey& k, const u8* sig, u32 sig_len, const u8* mhash, u32 mhash_len);

void RsaSelfTest();

} // namespace duetos::crypto
