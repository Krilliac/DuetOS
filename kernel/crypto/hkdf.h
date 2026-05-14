#pragma once

#include "crypto/sha256.h"
#include "util/types.h"

/*
 * DuetOS — HKDF-SHA-256 (RFC 5869).
 *
 * The Krawczyk extract-then-expand KDF used by TLS 1.3
 * (RFC 8446 §7.1) and a wide variety of modern protocols
 * (Signal, Noise, WireGuard, Tor onionskin v3). Composes
 * cleanly on top of the existing HMAC-SHA-256 in
 * `crypto/hmac.h`.
 *
 *   HKDF-Extract(salt, IKM)            -> PRK     (HMAC)
 *   HKDF-Expand(PRK, info, length)     -> OKM
 *
 * Lands now as TLS Tier 2 prep: TLS 1.3's whole key schedule
 * is HKDF, and even TLS 1.2 ECDHE suites use it for the PRF
 * variant when both peers negotiate it. Doesn't change the
 * existing TLS 1.2 RSA path, which uses TLS PRF directly.
 *
 * No allocation, no global state. Caller-owned input/output.
 * Output cap 255*HashLen per RFC 5869 §2.3 — for SHA-256 that
 * is 8160 bytes; we cap a touch lower (255 * 32 = 8160).
 */

namespace duetos::crypto
{

inline constexpr u32 kHkdfSha256MaxOkm = 255 * kSha256DigestBytes;

/// HKDF-Extract(salt, IKM) -> PRK
/// PRK is exactly 32 bytes (one SHA-256 digest worth).
/// `salt` may be nullptr / 0; per RFC 5869 §2.2 a missing
/// salt is treated as 32 zero bytes.
void HkdfSha256Extract(const u8* salt, u32 salt_len, const u8* ikm, u32 ikm_len, u8 prk[kSha256DigestBytes]);

/// HKDF-Expand(PRK, info, len) -> OKM
/// Writes `len` bytes to `out`. `len` MUST be <= kHkdfSha256MaxOkm
/// (255 * 32). `info` may be nullptr / 0.
/// Returns true on success, false if `len` exceeds the cap.
bool HkdfSha256Expand(const u8 prk[kSha256DigestBytes], const u8* info, u32 info_len, u8* out, u32 len);

/// Convenience: extract + expand in one shot.
bool HkdfSha256(const u8* salt, u32 salt_len, const u8* ikm, u32 ikm_len, const u8* info, u32 info_len, u8* out,
                u32 len);

void HkdfSelfTest();

} // namespace duetos::crypto
