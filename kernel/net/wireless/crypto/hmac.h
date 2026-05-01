#pragma once

#include "net/wireless/crypto/sha1.h"
#include "net/wireless/crypto/sha256.h"
#include "util/types.h"

/*
 * DuetOS — HMAC-SHA1 + HMAC-SHA256 per RFC 2104.
 *
 * The 802.11 stack uses HMAC-SHA1 for:
 *   - PBKDF2-HMAC-SHA1: passphrase + SSID → 32-byte PMK.
 *   - PRF-X (X ∈ {128, 384, 512}): PMK + nonces + MACs → PTK.
 *   - EAPOL Key MIC verification (legacy WPA2-CCMP MIC =
 *     truncated HMAC-SHA1 of the EAPOL key frame).
 *
 * HMAC-SHA256 is required when AKM uses a SHA-256 suite
 * (`PSK-SHA256`, `802.1X-SHA256`, FT-...) or for WPA3-SAE.
 *
 * Both APIs follow the same shape: `HmacShaXHash(key, key_len,
 * data, data_len, out)`. The longer-form context-update flow
 * isn't exposed in v0; callers that need it can copy from the
 * Linux mac80211 keymgmt sources.
 */

namespace duetos::net::wireless::crypto
{

/// HMAC-SHA1 (RFC 2104). `out` must be at least 20 bytes.
void HmacSha1(const u8* key, u32 key_len, const u8* data, u32 data_len, u8 out[kSha1DigestBytes]);

/// HMAC-SHA256 (RFC 6234). `out` must be at least 32 bytes.
void HmacSha256(const u8* key, u32 key_len, const u8* data, u32 data_len, u8 out[kSha256DigestBytes]);

void HmacSelfTest();

} // namespace duetos::net::wireless::crypto
