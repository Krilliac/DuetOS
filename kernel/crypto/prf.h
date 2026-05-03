#pragma once

#include "util/types.h"

/*
 * DuetOS — IEEE 802.11i PRF / 802.11-2020 KDF-Hash.
 *
 * The 4-way handshake derives the PTK (Pairwise Transient Key)
 * from the PMK + nonces + addresses via:
 *
 *   PTK = PRF-X(PMK, "Pairwise key expansion",
 *               min(SPA, AA) || max(SPA, AA) ||
 *               min(SNonce, ANonce) || max(SNonce, ANonce))
 *
 * For CCMP-128, X = 384 bits = 48 bytes (split into 16-byte KCK,
 * 16-byte KEK, 16-byte TK).
 *
 * The HMAC-SHA1-based PRF iterates `R(i) = HMAC-SHA1(K, A || 0x00 || B || i)`
 * and concatenates until X bits are produced. The HMAC-SHA256
 * variant is the same shape but with SHA-256 and a counter at
 * the END of the input.
 *
 * Reference: IEEE 802.11i §8.5.1.1 (legacy PRF) and 802.11-2020
 * §12.7.1.7 (KDF-Hash).
 */

namespace duetos::crypto
{

/// PRF-X with HMAC-SHA1. Used for CCMP-PSK PTK (X=384) and the
/// EAPOL Key MIC key (X=128).
///   `key` is the PMK or KCK.
///   `label` is the ASCII string e.g. "Pairwise key expansion".
///   `seed` is the 76-byte concatenation of MAC pair + nonce pair
///          (or whatever the calling layer constructs).
/// `out_bits` must be a multiple of 8. Caller supplies `out` with
/// `out_bits/8` bytes of capacity.
void Prf(const u8* key, u32 key_len, const char* label, const u8* seed, u32 seed_len, u32 out_bits, u8* out);

/// KDF-Hash-SHA256 per 802.11-2020 §12.7.1.7.5. Used for
/// SHA256-suite AKMs and WPA3.
void KdfSha256(const u8* key, u32 key_len, const char* label, const u8* context, u32 context_len, u32 out_bits,
               u8* out);

void PrfSelfTest();

} // namespace duetos::crypto
