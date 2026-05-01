#pragma once

#include "net/wireless/eapol.h"
#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — IEEE 802.11i 4-way handshake state machine.
 *
 * After Authentication + Association complete (both 802.11
 * management-frame exchanges), the AP and client run the 4-way
 * handshake to derive and install the per-session keys:
 *
 *   M1: AP → STA   ANonce, replay=N
 *   M2: STA → AP   SNonce, RSN IE, MIC(KCK)
 *   M3: AP → STA   ANonce, GTK KDE, MIC(KCK)        (Install bit set)
 *   M4: STA → AP   ack, MIC(KCK)
 *
 * After M2, both sides derive PTK = PRF-384(PMK, "Pairwise key
 * expansion", min(SPA,AA) || max(SPA,AA) || min(SNonce,ANonce) ||
 * max(SNonce,ANonce)). The PTK splits into:
 *
 *   KCK[0..16]   EAPOL Key Confirmation Key (HMAC-SHA1 MIC)
 *   KEK[16..32]  EAPOL Key Encryption Key (AES key wrap of GTK)
 *   TK[32..48]   Temporal Key (CCMP encrypts unicast traffic)
 *
 * After M3, the GTK is decrypted from the M3 KDE and installed
 * for multicast/broadcast RX. After M4 acknowledged, the STA
 * unblocks the data plane.
 *
 * Reference: IEEE 802.11-2020 §12.7.6, hostapd
 * `src/rsn_supp/wpa.c`, Linux mac80211 `net/mac80211/wpa.c`.
 */

namespace duetos::net::wireless
{

inline constexpr u32 kPtkBytes = 48; // CCMP-128: KCK 16 + KEK 16 + TK 16
inline constexpr u32 kKckBytes = 16;
inline constexpr u32 kKekBytes = 16;
inline constexpr u32 kTkBytes = 16;
inline constexpr u32 kGtkMaxBytes = 32; // CCMP-128 GTK is 16 bytes; 32 covers GCMP-256 too

enum class FourWayState : u8
{
    Idle = 0,
    AwaitingM1 = 1,
    AwaitingM3 = 2,
    AwaitingM4Ack = 3,
    Established = 4,
    Failed = 5,
};

const char* FourWayStateName(FourWayState s);

struct FourWayContext
{
    // Inputs.
    u8 pmk[32];
    u8 sta_mac[6]; // SPA — supplicant address (us)
    u8 ap_mac[6];  // AA  — authenticator address
    bool sha256;   // true for SHA-256-suite AKMs
    bool aes_cmac; // true for FT/SAE (KDV=3)

    // Outputs derived during the handshake.
    FourWayState state;
    u8 anonce[32];
    u8 snonce[32];
    u8 ptk[kPtkBytes];
    bool ptk_valid;

    u8 gtk[kGtkMaxBytes];
    u32 gtk_len;
    u8 gtk_index;
    bool gtk_valid;

    u8 last_replay[kEapolReplayBytes];

    // Bookkeeping.
    u32 mic_failures;
    u32 unexpected_messages;
    u32 retries_seen;
    u32 messages_processed;
};

void FourWayInit(FourWayContext& ctx, const u8 pmk[32], const u8 sta_mac[6], const u8 ap_mac[6], bool sha256,
                 bool aes_cmac);

/// Process an incoming EAPOL-Key frame. Drives the state machine.
/// Returns Ok on accepted message; Corrupt on MIC fail / replay
/// violation; FailedPrecondition if message arrives in wrong
/// state (logged + counted in `unexpected_messages`).
::duetos::core::Result<void> FourWayProcessIncoming(FourWayContext& ctx, const u8* eapol_frame, u32 eapol_frame_len);

/// Build the supplicant's outgoing EAPOL-Key frame for the
/// current state (M2 or M4). Returns Ok on success;
/// FailedPrecondition if state doesn't expect an outgoing frame.
::duetos::core::Result<void> FourWayBuildOutgoing(const FourWayContext& ctx, const u8* rsn_ie, u32 rsn_ie_len,
                                                  u8* out_buf, u32 out_buf_capacity, u32* out_len);

/// PTK split helpers — view the PTK without copying.
inline const u8* FourWayKck(const FourWayContext& ctx)
{
    return ctx.ptk;
}
inline const u8* FourWayKek(const FourWayContext& ctx)
{
    return ctx.ptk + kKckBytes;
}
inline const u8* FourWayTk(const FourWayContext& ctx)
{
    return ctx.ptk + kKckBytes + kKekBytes;
}

void FourWaySelfTest();

} // namespace duetos::net::wireless
