#pragma once

#include "util/types.h"

/*
 * DuetOS — PBKDF2 (RFC 2898 §5.2) over HMAC-SHA1 + HMAC-SHA256.
 *
 * SHA-1 form: WPA2-Personal locks `c=4096` and SHA-1 by spec —
 *   PMK = PBKDF2_HMAC_SHA1(passphrase, ssid, ssid_len, 4096, 32)
 * — so the SHA-1 form stays as the WPA2 PMK derivation primitive.
 *
 * SHA-256 form: the preferred KDF for new code paths (account
 * password hashing, future key derivation, future TLS PRF). New
 * features SHOULD use the SHA-256 form; SHA-1 is kept only for
 * the WPA2 contract.
 */

namespace duetos::crypto
{

inline constexpr u32 kPmkBytes = 32;
inline constexpr u32 kPbkdf2WpaIterations = 4096;

/// Derive `out_len` bytes via PBKDF2-HMAC-SHA1. Caller must supply
/// `out` with at least `out_len` bytes of capacity.
void Pbkdf2HmacSha1(const u8* password, u32 password_len, const u8* salt, u32 salt_len, u32 iterations, u8* out,
                    u32 out_len);

/// Derive `out_len` bytes via PBKDF2-HMAC-SHA256. Same shape as
/// the SHA-1 form. Preferred over SHA-1 for any new code path.
void Pbkdf2HmacSha256(const u8* password, u32 password_len, const u8* salt, u32 salt_len, u32 iterations, u8* out,
                      u32 out_len);

/// Convenience wrapper for the WPA2 PMK derivation. `out` is
/// always the 32-byte PMK.
void WpaPmkDerive(const char* passphrase, const char* ssid, u32 ssid_len, u8 out[kPmkBytes]);

void Pbkdf2SelfTest();

} // namespace duetos::crypto
