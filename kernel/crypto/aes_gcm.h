#pragma once

#include "crypto/aes.h"
#include "util/types.h"

/*
 * DuetOS — AES-128-GCM authenticated encryption (NIST SP 800-38D).
 *
 * TLS 1.2's `TLS_RSA_WITH_AES_128_GCM_SHA256` cipher suite uses
 * AES-128-GCM as its AEAD construction. This module provides
 * encrypt + decrypt with 96-bit IVs and 128-bit tags — the
 * shapes TLS 1.2 actually emits.
 *
 * Encrypt:
 *   AesGcm128Encrypt(K, IV[12], AAD, PT) -> CT, Tag[16]
 *
 * Decrypt + verify (constant-time tag compare):
 *   AesGcm128Decrypt(K, IV[12], AAD, CT, Tag[16]) -> PT or false
 *
 * Out of scope (deliberate):
 *   - IV sizes other than 96 bits. TLS 1.2 always uses 12-byte
 *     IVs (4 bytes salt + 8 bytes record-layer counter).
 *   - Tag sizes other than 128 bits. TLS 1.2's GCM record MAC is
 *     fixed at 16 bytes.
 *   - AES-256-GCM (`TLS_RSA_WITH_AES_256_GCM_SHA384` etc.). The
 *     primitive supports it via AesKeyExpand256 but the wrapper
 *     here is 128-only until a 256-only server forces our hand.
 *
 * GHASH implementation: bitwise GF(2^128) multiplication. Slow
 * relative to a table-based or CLMUL-based version but easy to
 * audit. The TLS data path is bounded by the record-layer MTU
 * (16 KiB max plaintext) so per-record cost is acceptable for
 * v0.
 */

namespace duetos::crypto
{

inline constexpr u32 kGcmIvBytes = 12;
inline constexpr u32 kGcmTagBytes = 16;

/// Encrypt `pt[0..pt_len)` with `key[0..16)`, producing
/// `ct[0..pt_len)` and writing the authentication tag to
/// `tag[0..16)`. AAD is the additional-authenticated-data
/// region — covered by the MAC but not encrypted (TLS uses it
/// for the record-header fields).
///
/// Returns true on success. The only failure modes are
/// invalid argument pointers and pt_len overflow past the
/// internal counter (2^39 - 256 bytes per GCM spec; we cap at
/// 2^31 since a real TLS record never exceeds 16 KiB).
bool AesGcm128Encrypt(const u8 key[kAes128KeyBytes], const u8 iv[kGcmIvBytes], const u8* aad, u32 aad_len, const u8* pt,
                      u32 pt_len, u8* ct, u8 tag[kGcmTagBytes]);

/// Decrypt + verify. Computes the tag over (AAD || CT) and
/// compares it to `tag` in constant time. On match, writes the
/// plaintext into `pt[0..ct_len)` and returns true. On
/// mismatch (or any malformed input), returns false WITHOUT
/// writing partial plaintext — the caller treats false as an
/// authentication failure.
bool AesGcm128Decrypt(const u8 key[kAes128KeyBytes], const u8 iv[kGcmIvBytes], const u8* aad, u32 aad_len, const u8* ct,
                      u32 ct_len, const u8 tag[kGcmTagBytes], u8* pt);

void AesGcmSelfTest();

} // namespace duetos::crypto
