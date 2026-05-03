#pragma once

#include "util/types.h"

/*
 * DuetOS — AES-128 / AES-256 block cipher per FIPS 197.
 *
 * Used as the primitive under:
 *   - AES Key Wrap (RFC 3394): unwraps the encrypted GTK / IGTK
 *     blob carried in EAPOL-Key M3 KeyData when AKM is one of the
 *     CCMP-128 / CCMP-256 / GCMP-128 / GCMP-256 suites. WPA2-Personal
 *     M3 GTK delivery hits this path on every association.
 *   - AES-CCM (NIST SP 800-38C) for 802.11 CCMP frame encryption.
 *   - AES-GCM (NIST SP 800-38D) for 802.11 GCMP frame encryption.
 *   - Future: TLS 1.2 AES-CBC + TLS 1.3 AES-GCM.
 *
 * Same shape as the rest of `kernel/crypto/`: zero allocation,
 * caller-owned context, KAT-driven self-test wired from
 * `core/main.cpp`.
 *
 * AES-192 is intentionally not supported in v0. No 802.11 AKM uses
 * it (the spec covers 128 and 256 only) and no consumer in the
 * tree is asking for it — adding it later is a few lines in
 * `AesKeyExpand` plus a constant change. Don't pre-pay that cost.
 */

namespace duetos::crypto
{

inline constexpr u32 kAesBlockBytes = 16;
inline constexpr u32 kAes128KeyBytes = 16;
inline constexpr u32 kAes256KeyBytes = 32;
inline constexpr u32 kAes128Rounds = 10;
inline constexpr u32 kAes256Rounds = 14;
inline constexpr u32 kAesMaxRoundKeysBytes = (kAes256Rounds + 1) * kAesBlockBytes; // 240

struct AesCtx
{
    u8 round_keys[kAesMaxRoundKeysBytes];
    u32 num_rounds; // 10 for AES-128, 14 for AES-256
};

/// Expand a 128-bit key into 11 round keys (176 bytes). `ctx` is
/// fully owned by the caller — no global state.
void AesKeyExpand128(AesCtx& ctx, const u8 key[kAes128KeyBytes]);

/// Expand a 256-bit key into 15 round keys (240 bytes).
void AesKeyExpand256(AesCtx& ctx, const u8 key[kAes256KeyBytes]);

/// Encrypt a single 16-byte block in-place-safe (out may alias in).
void AesEncryptBlock(const AesCtx& ctx, const u8 in[kAesBlockBytes], u8 out[kAesBlockBytes]);

/// Decrypt a single 16-byte block in-place-safe.
void AesDecryptBlock(const AesCtx& ctx, const u8 in[kAesBlockBytes], u8 out[kAesBlockBytes]);

void AesSelfTest();

} // namespace duetos::crypto
