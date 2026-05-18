#pragma once

#include "net/wireless/wdev.h"
#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — wireless data-plane netif glue.
 *
 * Bridges the kernel IP stack's 802.3 (Ethernet II) frame seam
 * (`NetStackBindInterface` / `NetStackInjectRx`) to a
 * GCMP-128-encrypted 802.11 data link.
 *
 *   TX: stack hands an 802.3 frame → strip the 14-byte Ethernet
 *       header → build a 24-byte 3-address 802.11 data header →
 *       MSDU = LLC/SNAP + EtherType + L3 → GCMP-encrypt the MSDU
 *       under TK → [802.11 hdr][GCMP body].
 *   RX: reverse — verify+decrypt, strip LLC/SNAP, rebuild the
 *       802.3 frame, push to the stack.
 *
 * The encap/decap helpers are direction-parameterised so the
 * supplicant (STA, ToDS) and the software AP (FromDS) share one
 * implementation. AAD = the 24-byte MAC header verbatim (we
 * never set the mutable FC bits, so it is already "masked"),
 * which is identical on both endpoints so the GCM tag verifies.
 *
 * Threading: the TX trampoline runs on the stack's send path;
 * `WNetifInjectDecrypted` runs on the driver RX path. The PN
 * counters in `WNetifCtx` are single-writer per direction.
 *
 * GAP: 3-address data frames only (no QoS, no A4 / WDS) — the
 * shape the software loopback uses; a real chip carrying QoS
 * data would extend the header + AAD.
 */

namespace duetos::net::wireless
{

inline constexpr u32 kWNetifMaxFrame = 1600;
inline constexpr u32 kWNetifEthHdr = 14;
inline constexpr u32 kWNetif80211Hdr = 24;
inline constexpr u32 kWNetifSnapBytes = 8; // AA AA 03 00 00 00 + EtherType(2)

struct WNetifCtx
{
    bool in_use;
    u32 iface_index;
    WirelessDevice* wdev;
    u8 tk[16];
    u8 sta_mac[6];
    u8 ap_mac[6];
    u64 tx_pn;      // STA → AP, monotonic
    u64 rx_pn_seen; // last accepted AP → STA PN (replay floor)
    u64 tx_frames;
    u64 rx_frames;
    u64 rx_replays;
    u64 rx_auth_fail;
};

/// Encapsulate an 802.3 frame into an encrypted 802.11 frame.
/// `from_ds` selects the address mapping (false = STA→AP / ToDS;
/// true = AP→STA / FromDS). `pn` is the transmitter's next
/// packet number.
::duetos::core::Result<void> WNetifEncap(const u8 tk[16], const u8 sta_mac[6], const u8 ap_mac[6], bool from_ds, u64 pn,
                                         const u8* eth, u32 eth_len, u8* out, u32 out_cap, u32* out_len);

/// Decapsulate an encrypted 802.11 frame back to 802.3. Verifies
/// the GCM tag and recovers the PN into `*out_pn`.
::duetos::core::Result<void> WNetifDecap(const u8 tk[16], const u8 sta_mac[6], const u8 ap_mac[6], bool from_ds,
                                         const u8* in, u32 in_len, u64* out_pn, u8* eth_out, u32 eth_cap, u32* eth_len);

/// Bind a wireless device into the IP stack at `iface_index`.
/// Registers a TX trampoline that routes the stack's 802.3
/// frames through `wdev->ops.SendDataFrame`. Returns the context
/// (owned by an internal fixed table) or null on exhaustion.
WNetifCtx* WNetifBind(WirelessDevice* wdev, u32 iface_index, const u8 sta_mac[6], const u8 ap_mac[6], const u8 tk[16]);

/// Look up the context bound at `iface_index`, or null.
WNetifCtx* WNetifByIface(u32 iface_index);

/// Driver RX entry: decrypt an inbound 802.11 frame and inject
/// the recovered 802.3 frame into the stack. Drops + counts on
/// tag-verify failure or PN replay.
::duetos::core::Result<void> WNetifInjectDecrypted(WNetifCtx* ctx, const u8* frame, u32 len);

} // namespace duetos::net::wireless
