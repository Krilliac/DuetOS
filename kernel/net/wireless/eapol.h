#pragma once

#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — IEEE 802.1X / 802.11i EAPOL key-frame parser + builder.
 *
 * EAPOL ("Extensible Authentication Protocol over LAN") is the
 * transport for the 4-way handshake's four key-descriptor frames.
 * Each EAPOL frame on top of the 802.11 data path:
 *
 *   Ethernet header (14 bytes, ethertype 0x888E)
 *   EAPOL header (4 bytes):
 *     u8  version       (1 = 802.1X-2001, 2 = 802.1X-2004,
 *                        3 = 802.1X-2010)
 *     u8  packet_type   (3 = EAPOL-Key)
 *     u16 body_length   (big-endian)
 *   EAPOL-Key body (95+ bytes for key descriptor type 2):
 *     u8  descriptor_type   (2 = RSN/802.11 NIST AES key wrap)
 *     u16 key_info          (big-endian; flag bits)
 *     u16 key_length        (big-endian; usually 16 for CCMP-128)
 *     u8  replay_counter[8]
 *     u8  key_nonce[32]     (ANonce in M1, SNonce in M2)
 *     u8  eapol_key_iv[16]
 *     u8  key_rsc[8]
 *     u8  reserved[8]
 *     u8  key_mic[16]       (HMAC-SHA1 truncated, or HMAC-SHA256
 *                            for SHA-256 AKMs, or AES-CMAC for
 *                            FT/SAE)
 *     u16 key_data_len      (big-endian)
 *     u8  key_data[key_data_len]   (RSN IE / KDE / encrypted GTK)
 *
 * Reference: IEEE 802.11-2020 §12.7.2. The Linux mac80211
 * implementation lives in `net/mac80211/wpa.c`.
 */

namespace duetos::net::wireless
{

inline constexpr u16 kEapolEtherType = 0x888E;
inline constexpr u8 kEapolPacketTypeKey = 3;
inline constexpr u8 kEapolKeyDescriptorRsn = 2;
inline constexpr u8 kEapolKeyDescriptorWpa1 = 254;

inline constexpr u32 kEapolHdrBytes = 4;
inline constexpr u32 kEapolKeyFixedBytes = 1u + 2u + 2u + 8u + 32u + 16u + 8u + 8u + 16u + 2u; // = 95
inline constexpr u32 kEapolMicBytes = 16;
inline constexpr u32 kEapolNonceBytes = 32;
inline constexpr u32 kEapolReplayBytes = 8;
inline constexpr u32 kEapolRscBytes = 8;
inline constexpr u32 kEapolIvBytes = 16;
inline constexpr u32 kEapolKeyDataMaxBytes = 1024;

// Key Information bit positions (big-endian dword in the wire
// frame; we expose host order after parse).
inline constexpr u16 kKiKeyDescriptorVersionMask = 0x0007;
inline constexpr u16 kKiKeyType = 1u << 3; // 1 = pairwise
inline constexpr u16 kKiKeyIndexMask = 0x0030;
inline constexpr u16 kKiKeyIndexShift = 4;
inline constexpr u16 kKiInstall = 1u << 6;
inline constexpr u16 kKiAck = 1u << 7;
inline constexpr u16 kKiMic = 1u << 8;
inline constexpr u16 kKiSecure = 1u << 9;
inline constexpr u16 kKiError = 1u << 10;
inline constexpr u16 kKiRequest = 1u << 11;
inline constexpr u16 kKiEncrypted = 1u << 12;
inline constexpr u16 kKiSmkMessage = 1u << 13;

// Key Descriptor Version values (KI bits 0..2):
//   1 = HMAC-MD5 + RC4 (legacy WPA-1; rejected by v0)
//   2 = HMAC-SHA1 + AES key wrap (CCMP-PSK)
//   3 = AES-128-CMAC + AES key wrap (FT/SAE)
inline constexpr u16 kKdvHmacSha1 = 2;
inline constexpr u16 kKdvAesCmac = 3;

struct EapolKeyFrame
{
    u8 version;
    u8 packet_type;
    u16 body_length; // host order

    u8 descriptor_type;
    u16 key_info;   // host order
    u16 key_length; // host order
    u8 replay_counter[kEapolReplayBytes];
    u8 key_nonce[kEapolNonceBytes];
    u8 eapol_key_iv[kEapolIvBytes];
    u8 key_rsc[kEapolRscBytes];
    u8 reserved[8];
    u8 key_mic[kEapolMicBytes];
    u16 key_data_len; // host order

    // Pointer into the original buffer. Caller must keep it
    // alive for the lifetime of this struct.
    const u8* key_data;

    // Pointer to the BEGINNING of the EAPOL body (where the MIC
    // computation starts). Required by `EapolMicCompute`.
    const u8* eapol_body;
    u32 eapol_body_len;

    // Offset of the MIC field WITHIN `eapol_body` — the field
    // is zeroed before HMAC computation, then re-filled.
    u32 mic_offset_in_body;
};

::duetos::core::Result<void> EapolKeyParse(const u8* eapol_frame, u32 eapol_frame_len, EapolKeyFrame* out);

/// Build an EAPOL-Key frame in `out_buf` from `frame`. Returns the
/// number of bytes written via `out_len`. The MIC field is left
/// zero — the caller computes HMAC-SHA1(KCK, eapol_body) and
/// patches it back in via `EapolMicPatch`.
::duetos::core::Result<void> EapolKeyBuild(const EapolKeyFrame& f, u8* out_buf, u32 cap, u32* out_len);

/// Compute and patch the MIC into a pre-built EAPOL-Key frame.
/// `kdv` selects the algorithm: kKdvHmacSha1 (HMAC-SHA1, truncated
/// to 16 bytes) or kKdvAesCmac (AES-CMAC over the body).
::duetos::core::Result<void> EapolMicPatch(u8* eapol_frame, u32 eapol_frame_len, const u8* kck, u32 kck_len, u16 kdv);

/// Verify the MIC on a received EAPOL-Key frame. Returns Ok if the
/// MIC matches, Corrupt if it doesn't.
::duetos::core::Result<void> EapolMicVerify(const u8* eapol_frame, u32 eapol_frame_len, const u8* kck, u32 kck_len,
                                            u16 kdv);

void EapolSelfTest();

} // namespace duetos::net::wireless
