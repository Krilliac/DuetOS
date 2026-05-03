#pragma once

#include "crypto/aes.h"
#include "util/types.h"

/*
 * DuetOS — AES-CCM authenticated encryption per NIST SP 800-38C
 * (clean room).
 *
 * CCM (Counter with CBC-MAC) is the AEAD mode underneath 802.11
 * CCMP (the standard WPA2-Personal data-frame encryption). The
 * spec composes a CTR-mode encrypt with a CBC-MAC over a formatted
 * input string {AAD-len-block || AAD-with-padding || plaintext-
 * with-padding}. The CCMP usage pins:
 *   - 13-byte nonce (B.1 of 802.11i),
 *   - 8-byte tag (CCMP "MIC"),
 *   - 0..30 bytes of AAD (the 802.11 frame-header fields).
 *
 * Eventual consumers:
 *   - 802.11 CCMP frame encryption (WPA2-Personal data path —
 *     today the 4-way handshake derives the PTK but actual data
 *     frames go unencrypted because CCMP wasn't in tree). With
 *     this primitive in place, the TX/RX dispatch slice can wire
 *     it.
 *   - Future BLE / NFC paths that use CCM.
 *
 * Scope (v0):
 *   - AES-128 / AES-256.
 *   - 13-byte nonce only (the CCMP usage; SP 800-38C lets nonce
 *     length range 7..13, but no current target consumer needs
 *     anything else).
 *   - 4 / 6 / 8 / 10 / 12 / 14 / 16-byte tag (the spec's M
 *     values).
 *
 * Out of scope (deliberate):
 *   - Variable nonce length above 13 bytes (would change the
 *     L parameter and the CBC-MAC formatting).
 */

namespace duetos::crypto
{

inline constexpr u32 kAesCcmNonceBytes = 13;

/// AES-128-CCM encrypt. `ciphertext` may alias `plaintext`. `tag_len`
/// must be one of {4, 6, 8, 10, 12, 14, 16}.
bool AesCcm128Encrypt(const u8 key[kAes128KeyBytes], const u8 nonce[kAesCcmNonceBytes], const u8* aad, u32 aad_len,
                      const u8* plaintext, u32 plaintext_len, u8* ciphertext, u8* tag, u32 tag_len);

/// AES-128-CCM decrypt. Returns true iff `tag` verifies.
bool AesCcm128Decrypt(const u8 key[kAes128KeyBytes], const u8 nonce[kAesCcmNonceBytes], const u8* aad, u32 aad_len,
                      const u8* ciphertext, u32 ciphertext_len, const u8* tag, u32 tag_len, u8* plaintext);

bool AesCcm256Encrypt(const u8 key[kAes256KeyBytes], const u8 nonce[kAesCcmNonceBytes], const u8* aad, u32 aad_len,
                      const u8* plaintext, u32 plaintext_len, u8* ciphertext, u8* tag, u32 tag_len);

bool AesCcm256Decrypt(const u8 key[kAes256KeyBytes], const u8 nonce[kAesCcmNonceBytes], const u8* aad, u32 aad_len,
                      const u8* ciphertext, u32 ciphertext_len, const u8* tag, u32 tag_len, u8* plaintext);

void AesCcmSelfTest();

} // namespace duetos::crypto
