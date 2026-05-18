#pragma once

#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — IEEE 802.11 GCMP-128 frame protection.
 *
 * GCMP (IEEE 802.11-2020 §12.5.5) is the AES-GCM AEAD used by
 * WPA3 and high-throughput WPA2. We pick GCMP-128 (cipher suite
 * 00-0F-AC:8) for the loopback data plane because the kernel
 * already ships a tested AES-GCM primitive (`crypto/aes_gcm`),
 * so the encrypted path is real AEAD — confidentiality AND
 * integrity — rather than a hand-rolled CCM stub.
 *
 * Wire layout of a protected MPDU body:
 *
 *   GCMP header (8): PN0 PN1 Rsvd KeyId  PN2 PN3 PN4 PN5
 *                    (KeyId byte: bit5 ExtIV=1, bits6..7 = key id)
 *   Ciphertext   (plaintext_len bytes)
 *   MIC / GCM tag (16)
 *
 * Nonce (12 bytes, fed to AES-GCM as the 96-bit IV):
 *   A2 (transmitter MAC, 6) || PN (48-bit, MSByte first, 6)
 *
 * AAD is the masked 802.11 MAC header supplied by the caller —
 * the loopback uses a fixed 24-byte 3-address data header, so
 * the AAD bytes are identical on both endpoints and the tag
 * verifies. The PN is monotonic per transmitter; the receiver
 * rejects a PN <= the last accepted one (replay protection).
 *
 * Threading: pure transform over caller buffers. No state — the
 * PN counter is owned by the caller (per-direction).
 *
 * GAP: only the 24-byte 3-address (no QoS, no A4) AAD shape is
 * implemented — sufficient for the software loopback; a real
 * driver carrying QoS-Data would extend the AAD construction.
 */

namespace duetos::net::wireless
{

inline constexpr u32 kGcmpHeaderBytes = 8;
inline constexpr u32 kGcmpMicBytes = 16;
inline constexpr u32 kGcmpTkBytes = 16;
inline constexpr u32 kGcmpOverheadBytes = kGcmpHeaderBytes + kGcmpMicBytes;

/// Encrypt + authenticate `pt[0..pt_len)` into `out`. Writes the
/// 8-byte GCMP header, the ciphertext, then the 16-byte tag.
/// `pn` is this transmitter's next packet number (must be > 0
/// and strictly increasing across calls for a given TK).
::duetos::core::Result<void> GcmpProtect(const u8 tk[kGcmpTkBytes], const u8 ta[6], u64 pn, const u8* aad, u32 aad_len,
                                         const u8* pt, u32 pt_len, u8* out, u32 out_cap, u32* out_len);

/// Verify + decrypt a protected MPDU body. Recovers the PN into
/// `*out_pn` and the plaintext into `pt_out`. Returns Corrupt on
/// tag-verify failure or a malformed/short frame.
::duetos::core::Result<void> GcmpUnprotect(const u8 tk[kGcmpTkBytes], const u8 ta[6], const u8* aad, u32 aad_len,
                                           const u8* in, u32 in_len, u64* out_pn, u8* pt_out, u32 pt_cap, u32* pt_len);

void GcmpSelfTest();

} // namespace duetos::net::wireless
