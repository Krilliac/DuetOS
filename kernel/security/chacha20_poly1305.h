#pragma once

#include "util/types.h"

/*
 * DuetOS — ChaCha20-Poly1305 AEAD (RFC 8439).
 *
 * Authenticated-encryption-with-associated-data primitive used by
 * the persistence layer to seal the on-disk account / role / member
 * tables. Pairs with Argon2id (security/argon2id.h) for KEK
 * derivation: KEK = Argon2id(password, salt); ciphertext =
 * ChaCha20-Poly1305(KEK, nonce, plaintext, ad).
 *
 * Construction
 * ------------
 * ChaCha20 stream cipher (RFC 8439 §2) with a Poly1305 MAC (§2.5),
 * keyed by a one-time Poly1305 key derived from the first 32 bytes
 * of the ChaCha20 keystream with block counter 0 (§2.6). Encrypted
 * data starts at block counter 1. AEAD tag = Poly1305 over
 * `pad16(ad) || pad16(ciphertext) || LE64(ad_len) || LE64(ct_len)`.
 *
 * Inputs
 * ------
 *   key:   32 bytes
 *   nonce: 12 bytes (caller-supplied, MUST be unique per (key, msg);
 *                    the persistence layer draws it from the kernel
 *                    entropy pool every encrypt)
 *   ad:    arbitrary associated data (authenticated, not encrypted)
 *   plaintext: arbitrary-length message
 *   tag:   16 bytes output
 *
 * Encrypt and decrypt are constant-time wrt the plaintext content
 * (the comparison on decrypt is constant-time across the 16-byte
 * tag). Decrypt returns false WITHOUT writing the plaintext on tag
 * mismatch, so a caller's plaintext buffer is never half-populated
 * with attacker-controlled bytes after a failed decrypt.
 *
 * Context: kernel. Pure — no allocations beyond the caller's
 * buffers. Safe to call from any task context; NOT IRQ-safe (uses
 * larger stack buffers than IRQ frames allow).
 */

namespace duetos::security
{

constexpr u32 kChaCha20KeyBytes = 32;
constexpr u32 kChaCha20NonceBytes = 12;
constexpr u32 kPoly1305TagBytes = 16;

/// AEAD encrypt. Writes `pt_len` ciphertext bytes to `ct` and 16
/// tag bytes to `tag`. `ad` is authenticated but not encrypted;
/// pass nullptr / 0 if unused. `ct` and `pt` may overlap (in-place
/// encrypt) only if they are exactly equal.
void ChaCha20Poly1305Encrypt(const u8 key[kChaCha20KeyBytes], const u8 nonce[kChaCha20NonceBytes], const u8* ad,
                             u32 ad_len, const u8* pt, u32 pt_len, u8* ct, u8 tag[kPoly1305TagBytes]);

/// AEAD decrypt with verification. Verifies `tag` against the
/// recomputed Poly1305 over `pad16(ad) || pad16(ct) || LE64 ||
/// LE64`. Returns false on mismatch — the caller's `pt` buffer is
/// NOT written in that case. Returns true on a verified plaintext.
bool ChaCha20Poly1305Decrypt(const u8 key[kChaCha20KeyBytes], const u8 nonce[kChaCha20NonceBytes], const u8* ad,
                             u32 ad_len, const u8* ct, u32 ct_len, const u8 tag[kPoly1305TagBytes], u8* pt);

/// Boot KAT — RFC 8439 §2.8.2 test vector + tampered-tag /
/// tampered-ct rejection paths. Panics on regression.
void ChaCha20Poly1305SelfTest();

} // namespace duetos::security
