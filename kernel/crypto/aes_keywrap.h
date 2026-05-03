#pragma once

#include "crypto/aes.h"
#include "util/types.h"

/*
 * DuetOS — AES Key Wrap (RFC 3394 / NIST SP 800-38F KW).
 *
 * The 802.11i protocol delivers the GTK (and optional IGTK / KCK)
 * inside the encrypted KeyData of EAPOL-Key M3. When the AKM
 * negotiates a CCMP-128 / CCMP-256 / GCMP-128 / GCMP-256 cipher
 * suite, that KeyData is wrapped with AES Key Wrap using the
 * 128-bit KEK that lives in the upper half of the PTK.
 *
 * RFC 3394's algorithm operates on 8-byte semi-blocks. Plaintext
 * of length 8n yields ciphertext of length 8(n+1); the extra
 * semi-block is the IV (`kAesKwDefaultIV`) that doubles as an
 * integrity check on unwrap.
 *
 * The `AesCtx` parameter is pre-expanded by the caller (so the
 * key schedule is paid once across many wrap/unwrap calls).
 *
 * AES-192 KEKs are not supported (no 802.11 AKM ever picks one).
 * The implementation works for both AES-128 and AES-256 KEKs
 * because the underlying block primitive selects rounds from
 * `ctx.num_rounds`.
 */

namespace duetos::crypto
{

inline constexpr u32 kAesKwSemiBlockBytes = 8;

/// RFC 3394 §2.2.3.1 default IV (A6 A6 A6 A6 A6 A6 A6 A6).
inline constexpr u64 kAesKwDefaultIV = 0xA6A6A6A6A6A6A6A6ull;

/// Maximum semi-block count we accept. 64 semi-blocks = 512 bytes
/// of plaintext, which comfortably covers every 802.11 KeyData
/// payload (GTK + IGTK + padding never exceeds a few hundred
/// bytes). Bump if a future caller needs more.
inline constexpr u32 kAesKwMaxSemiBlocks = 64;

/// Wrap `plaintext_bytes` of plaintext into `out`. Caller must
/// ensure `out` has `plaintext_bytes + kAesKwSemiBlockBytes` of
/// capacity. `plaintext_bytes` must be a non-zero multiple of 8.
/// Returns false on bad inputs (overflow, non-multiple-of-8,
/// out-of-range size).
bool AesKeyWrap(const AesCtx& kek, const u8* plaintext, u32 plaintext_bytes, u8* out);

/// Unwrap `ciphertext_bytes` of ciphertext into `out`. Caller
/// must ensure `out` has `ciphertext_bytes - kAesKwSemiBlockBytes`
/// of capacity. `ciphertext_bytes` must be ≥ 24 and a multiple of
/// 8. Returns false if the integrity check (recovered A vs IV)
/// fails — a true 802.11 stack treats this as an attacker-modified
/// KeyData and aborts the handshake.
bool AesKeyUnwrap(const AesCtx& kek, const u8* ciphertext, u32 ciphertext_bytes, u8* out);

void AesKeyWrapSelfTest();

} // namespace duetos::crypto
