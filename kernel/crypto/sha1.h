#pragma once

#include "util/types.h"

/*
 * DuetOS — SHA-1 hash for the wireless cryptographic stack.
 *
 * Used by:
 *   - HMAC-SHA1 (RFC 2104) — primitive for PBKDF2 + 802.11 PRF.
 *   - PBKDF2-HMAC-SHA1 (RFC 2898) — WPA2-PSK passphrase → PMK.
 *   - 802.11 PRF-X — PTK derivation in the 4-way handshake.
 *
 * SHA-1 is cryptographically broken for collision resistance, but
 * IEEE 802.11i / WPA2 derived its PSK pipeline from it, so a
 * conforming implementation ships SHA-1 alongside SHA-256.
 *
 * No allocation, no global state. Each `Sha1Ctx` is independent.
 * Threading: pure data shuffling, safe from any context.
 *
 * IMPORTANT: this is a hash function, not a MAC. Never use raw
 * SHA-1 for authentication; use HMAC-SHA1 from `hmac.h`.
 */

namespace duetos::crypto
{

inline constexpr u32 kSha1DigestBytes = 20;
inline constexpr u32 kSha1BlockBytes = 64;

struct Sha1Ctx
{
    u32 state[5];       // running hash a..e
    u64 length_bits;    // total message length in bits
    u32 buffered_bytes; // 0..63 within `block`
    u8 block[kSha1BlockBytes];
};

void Sha1Init(Sha1Ctx& ctx);
void Sha1Update(Sha1Ctx& ctx, const u8* data, u32 length);
void Sha1Final(Sha1Ctx& ctx, u8 out[kSha1DigestBytes]);

/// Convenience one-shot. Equivalent to Init + Update + Final.
void Sha1Hash(const u8* data, u32 length, u8 out[kSha1DigestBytes]);

/// Boot-time KAT — runs against the FIPS 180-1 / RFC 3174 test
/// vectors ("abc", million-a, etc.). Panics on mismatch.
void Sha1SelfTest();

} // namespace duetos::crypto
