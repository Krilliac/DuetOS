#pragma once

#include "util/types.h"

/*
 * DuetOS — ChaCha20 stream cipher + Poly1305 MAC + ChaCha20-
 * Poly1305 AEAD per RFC 8439 (clean room).
 *
 * Specs:
 *   - RFC 8439 §2.3 — ChaCha20 block function (10 double rounds
 *     over a 16×u32 state matrix).
 *   - RFC 8439 §2.5 — Poly1305 one-time MAC over a 32-byte key.
 *   - RFC 8439 §2.8 — ChaCha20-Poly1305 AEAD construction
 *     (combine via the 32-byte ChaCha20 counter-0 keystream as
 *     the Poly1305 key, then MAC the AAD and ciphertext).
 *
 * Eventual consumers:
 *   - TLS 1.2 / 1.3 client (`TLS_CHACHA20_POLY1305_SHA256` cipher
 *     suite). Both TLS slices are large multi-commit follow-ons;
 *     this primitive lets the TLS layer compose without re-
 *     deriving the AEAD math.
 *   - WireGuard-equivalent VPN (if/when that lands).
 *   - Future kernel sealed-storage if the crypto layer ever
 *     wants a non-AES alternative for envelope encryption.
 *
 * No allocation, no global state. The Poly1305 implementation
 * uses a 130-bit accumulator emulated through 64-bit arithmetic
 * — 5 26-bit limbs, multiply gives 64-bit products, no wider
 * integer type needed and no SIMD assumed.
 */

namespace duetos::crypto
{

inline constexpr u32 kChaCha20KeyBytes = 32;
inline constexpr u32 kChaCha20NonceBytes = 12;
inline constexpr u32 kChaCha20BlockBytes = 64;

inline constexpr u32 kPoly1305KeyBytes = 32;
inline constexpr u32 kPoly1305TagBytes = 16;

inline constexpr u32 kChaCha20Poly1305TagBytes = 16;

/// ChaCha20 keystream-XOR over `len` bytes. `key` is 32 bytes,
/// `nonce` is 12 bytes, `counter` is the initial 32-bit block
/// counter (0 for AEAD encrypt-of-plaintext, 1 for the actual
/// payload encryption — see RFC 8439 §2.6). `out` and `in` may
/// alias or be the same buffer.
void ChaCha20Xor(const u8 key[kChaCha20KeyBytes], const u8 nonce[kChaCha20NonceBytes], u32 counter, const u8* in,
                 u8* out, u32 len);

/// One-shot Poly1305 MAC. `key` is 32 bytes (16 bytes "r" then
/// 16 bytes "s" per RFC 8439 §2.5). Writes 16 bytes to `tag`.
void Poly1305Mac(const u8 key[kPoly1305KeyBytes], const u8* msg, u32 msg_len, u8 tag[kPoly1305TagBytes]);

/// ChaCha20-Poly1305 AEAD encrypt. Encrypts `plaintext_len` bytes
/// of `plaintext` to `ciphertext` (may alias `plaintext`) and
/// writes a 16-byte authentication tag to `tag`. AAD is
/// authenticated but not encrypted.
void ChaCha20Poly1305Encrypt(const u8 key[kChaCha20KeyBytes], const u8 nonce[kChaCha20NonceBytes], const u8* aad,
                             u32 aad_len, const u8* plaintext, u32 plaintext_len, u8* ciphertext,
                             u8 tag[kChaCha20Poly1305TagBytes]);

/// ChaCha20-Poly1305 AEAD decrypt. Returns true iff `tag` matches
/// the recomputed MAC, in which case `plaintext` holds the
/// decrypted bytes (may alias `ciphertext`). On a tag mismatch
/// returns false and `plaintext` is left in an unspecified state
/// — callers MUST discard it; the spec requires authenticate-
/// then-decrypt semantics for the consumer's correctness.
bool ChaCha20Poly1305Decrypt(const u8 key[kChaCha20KeyBytes], const u8 nonce[kChaCha20NonceBytes], const u8* aad,
                             u32 aad_len, const u8* ciphertext, u32 ciphertext_len,
                             const u8 tag[kChaCha20Poly1305TagBytes], u8* plaintext);

void ChaCha20Poly1305SelfTest();

} // namespace duetos::crypto
