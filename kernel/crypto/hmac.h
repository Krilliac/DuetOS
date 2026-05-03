#pragma once

#include "crypto/md5.h"
#include "crypto/sha1.h"
#include "crypto/sha256.h"
#include "crypto/sha512.h"
#include "util/types.h"

/*
 * DuetOS — HMAC-SHA1 + HMAC-SHA256 + HMAC-MD5 per RFC 2104.
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
 * HMAC-MD5 is the legacy-only entry: NTLMv1 / HTTP Digest
 * (RFC 2069). MD5 is broken for collision resistance, so this
 * primitive MUST NOT be used in any new security-sensitive path
 * — it exists so that future NTLMv1 and Digest-auth thunks can
 * interop with old peers without each one re-deriving MD5+HMAC.
 *
 * All three APIs follow the same shape: `HmacXHash(key, key_len,
 * data, data_len, out)`. The longer-form context-update flow
 * isn't exposed in v0; callers that need it can copy from the
 * Linux mac80211 keymgmt sources.
 */

namespace duetos::crypto
{

/// HMAC-SHA1 (RFC 2104). `out` must be at least 20 bytes.
void HmacSha1(const u8* key, u32 key_len, const u8* data, u32 data_len, u8 out[kSha1DigestBytes]);

/// HMAC-SHA256 (RFC 6234). `out` must be at least 32 bytes.
void HmacSha256(const u8* key, u32 key_len, const u8* data, u32 data_len, u8 out[kSha256DigestBytes]);

/// HMAC-MD5 (RFC 2104 + RFC 1321). Legacy interop only — see
/// header banner. `out` must be at least 16 bytes.
void HmacMd5(const u8* key, u32 key_len, const u8* data, u32 data_len, u8 out[kMd5DigestBytes]);

/// HMAC-SHA384 (RFC 4231). 128-byte block size; uses the SHA-512
/// underlying hash with a truncated 48-byte digest. `out` must be
/// at least 48 bytes.
void HmacSha384(const u8* key, u32 key_len, const u8* data, u32 data_len, u8 out[kSha384DigestBytes]);

/// HMAC-SHA512 (RFC 4231). 128-byte block size. `out` must be
/// at least 64 bytes.
void HmacSha512(const u8* key, u32 key_len, const u8* data, u32 data_len, u8 out[kSha512DigestBytes]);

void HmacSelfTest();

} // namespace duetos::crypto
