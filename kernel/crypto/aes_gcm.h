#pragma once

#include "crypto/aes.h"
#include "util/types.h"

/*
 * DuetOS — AES-GCM authenticated encryption per NIST SP 800-38D
 * (clean room).
 *
 * Composes the existing `AesCtx` block cipher with:
 *   - GHASH: multiplication over GF(2^128) using the irreducible
 *     polynomial x^128 + x^7 + x^2 + x + 1, big-endian bit order.
 *     The implementation uses bit-by-bit shift-and-XOR — slower
 *     than tabled approaches but small (~30 lines), no precomputed
 *     state, no side-channel concerns from data-dependent table
 *     lookups.
 *   - GCTR (counter-mode encrypt) with the AES block cipher and
 *     32-bit counter increment per the spec.
 *   - GCM construction: ICB derived from IV (special-cased for
 *     the common 96-bit IV), then GCTR-encrypt plaintext, then
 *     GHASH(AAD || pad || ciphertext || pad || lengths).
 *
 * Eventual consumers:
 *   - 802.11 GCMP (WPA3-only at the moment; CCMP covers WPA2).
 *   - TLS 1.2 / 1.3 with `TLS_AES_128_GCM_SHA256` etc.
 *   - Future: kernel sealed-storage envelope encryption.
 *
 * Scope (v0):
 *   - 96-bit IV only. Other IV lengths require an extra GHASH
 *     pass and are not used by any current target consumer.
 *   - Tag length 16 bytes (the only NIST-recommended length for
 *     general use; SP 800-38D Table 1 calls 12/13/14/15 "high-
 *     risk for forgery on streams that observe failures").
 *   - AES-128 + AES-256 keys.
 */

namespace duetos::crypto
{

inline constexpr u32 kAesGcmIvBytes = 12;
inline constexpr u32 kAesGcmTagBytes = 16;

/// AES-128-GCM encrypt. `ciphertext` may alias `plaintext`.
void AesGcm128Encrypt(const u8 key[kAes128KeyBytes], const u8 iv[kAesGcmIvBytes], const u8* aad, u32 aad_len,
                      const u8* plaintext, u32 plaintext_len, u8* ciphertext, u8 tag[kAesGcmTagBytes]);

/// AES-128-GCM decrypt. Returns true iff `tag` verifies. On
/// failure `plaintext` content is unspecified and MUST be discarded.
bool AesGcm128Decrypt(const u8 key[kAes128KeyBytes], const u8 iv[kAesGcmIvBytes], const u8* aad, u32 aad_len,
                      const u8* ciphertext, u32 ciphertext_len, const u8 tag[kAesGcmTagBytes], u8* plaintext);

/// AES-256-GCM encrypt.
void AesGcm256Encrypt(const u8 key[kAes256KeyBytes], const u8 iv[kAesGcmIvBytes], const u8* aad, u32 aad_len,
                      const u8* plaintext, u32 plaintext_len, u8* ciphertext, u8 tag[kAesGcmTagBytes]);

/// AES-256-GCM decrypt.
bool AesGcm256Decrypt(const u8 key[kAes256KeyBytes], const u8 iv[kAesGcmIvBytes], const u8* aad, u32 aad_len,
                      const u8* ciphertext, u32 ciphertext_len, const u8 tag[kAesGcmTagBytes], u8* plaintext);

void AesGcmSelfTest();

} // namespace duetos::crypto
