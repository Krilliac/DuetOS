#pragma once

#include "util/types.h"

/*
 * DuetOS — PBKDF2-HMAC-SHA1 per RFC 2898 §5.2.
 *
 * In WPA2-Personal, the user enters a passphrase. The 802.11i
 * standard derives the 32-byte PMK from passphrase + SSID via
 * exactly this PBKDF2 invocation:
 *
 *   PMK = PBKDF2_HMAC_SHA1(passphrase, ssid, ssid_len, 4096, 32)
 *
 * This is the ONLY caller in v0; we expose the generic form for
 * future re-use. 4096 iterations is an 802.11 hard requirement
 * (the AP and client MUST agree).
 */

namespace duetos::net::wireless::crypto
{

inline constexpr u32 kPmkBytes = 32;
inline constexpr u32 kPbkdf2WpaIterations = 4096;

/// Derive `out_len` bytes via PBKDF2-HMAC-SHA1. Caller must supply
/// `out` with at least `out_len` bytes of capacity.
void Pbkdf2HmacSha1(const u8* password, u32 password_len, const u8* salt, u32 salt_len, u32 iterations, u8* out,
                    u32 out_len);

/// Convenience wrapper for the WPA2 PMK derivation. `out` is
/// always the 32-byte PMK.
void WpaPmkDerive(const char* passphrase, const char* ssid, u32 ssid_len, u8 out[kPmkBytes]);

void Pbkdf2SelfTest();

} // namespace duetos::net::wireless::crypto
