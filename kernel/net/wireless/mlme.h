#pragma once

#include "net/wireless/wdev.h"
#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — IEEE 802.11 MLME (MAC Sublayer Management Entity).
 *
 * Drives a STA's state machine for connecting to a BSS. The
 * canonical sequence is:
 *
 *   Idle → Scanning → Authenticating → Associating → Handshaking → Connected
 *
 * Each transition is initiated by user request (`MlmeConnect`)
 * or driven by an arriving frame (`WirelessDeliverMgmt`). Every
 * state transition + frame TX/RX is logged to the wifi-diag ring.
 *
 * Frame builders construct authentication / association /
 * deauthentication frames. Receive paths parse responses (status
 * codes, association IDs, RSN IEs) and dispatch to the next
 * state.
 *
 * Reference: IEEE 802.11-2020 §11.3 (MLME), hostapd/wpa_supplicant
 * `src/rsn_supp/wpa_ft.c` for the FT additions, Linux mac80211
 * `net/mac80211/mlme.c` for the canonical state-machine shape.
 */

namespace duetos::net::wireless
{

inline constexpr u32 kMlmeAuthFrameMaxBytes = 32 + 6;
inline constexpr u32 kMlmeAssocReqFrameMaxBytes = 64 + 256; // header + var IEs

// 802.11 Reason Codes (subset). Used in deauth / disassoc.
inline constexpr u16 kReasonUnspecified = 1;
inline constexpr u16 kReasonAuthExpired = 2;
inline constexpr u16 kReasonDeauthLeaving = 3;
inline constexpr u16 kReasonDisassocInactive = 4;
inline constexpr u16 kReason4WayHandshakeTimeout = 15;
inline constexpr u16 kReasonGroupKeyHandshakeTimeout = 16;
inline constexpr u16 kReasonIeMismatch = 17;
inline constexpr u16 kReasonInvalidGroupCipher = 18;
inline constexpr u16 kReasonInvalidPairwiseCipher = 19;
inline constexpr u16 kReasonInvalidAkmp = 20;
inline constexpr u16 kReasonUnsupportedRsnVersion = 21;
inline constexpr u16 kReasonMicFailure = 14;

// 802.11 Status Codes (subset). Returned in auth / assoc response.
inline constexpr u16 kStatusSuccess = 0;
inline constexpr u16 kStatusFailure = 1;
inline constexpr u16 kStatusCapabilitiesUnsupported = 10;
inline constexpr u16 kStatusReassociationDenied = 11;
inline constexpr u16 kStatusAssociationDenied = 12;
inline constexpr u16 kStatusAuthAlgorithmUnsupported = 13;
inline constexpr u16 kStatusInvalidIe = 40;
inline constexpr u16 kStatusInvalidAkmp = 43;
inline constexpr u16 kStatusInvalidPairwiseCipher = 42;
inline constexpr u16 kStatusInvalidGroupCipher = 41;

struct MlmeConnectRequest
{
    char ssid[kSsidMaxBytes + 1];
    u8 ssid_len;
    char passphrase[64]; // PSK only; empty = open
    u8 desired_bssid[6]; // all-zero = pick best from scan results
    u8 desired_channel;  // 0 = use scan result's channel
};

/// User-level "connect to this SSID" request. Handles the entire
/// flow: pick best BSS from scan results, derive PMK from
/// passphrase, run auth/assoc, then drive 4-way handshake.
::duetos::core::Result<void> MlmeConnect(WirelessDevice* wdev, const MlmeConnectRequest& req);

/// User-level disconnect. Sends Deauthentication and tears down.
::duetos::core::Result<void> MlmeDisconnect(WirelessDevice* wdev, u16 reason);

/// Issue a scan and wait until results arrive (or timeout). The
/// driver's Scan op delivers beacons asynchronously via
/// `WirelessDeliverBeacon`; this wrapper wraps that with a
/// deadline in ticks.
::duetos::core::Result<void> MlmeScanAndWait(WirelessDevice* wdev, const WirelessScanRequest& req, u32 timeout_ticks);

/// Build a Class-1 Authentication frame body (Auth Algorithm =
/// Open, Sequence = 1, Status = 0). Returns bytes written.
::duetos::core::Result<u32> MlmeBuildAuthOpenFrame(const u8 sta_mac[6], const u8 ap_mac[6], u8* out_buf,
                                                   u32 out_buf_capacity);

/// Build an Association Request frame body. Includes RSN IE if
/// `rsn_ie_len > 0`. Returns bytes written.
::duetos::core::Result<u32> MlmeBuildAssocReqFrame(const u8 sta_mac[6], const u8 ap_mac[6], const char* ssid,
                                                   u8 ssid_len, const u8 supp_rates[8], u8 supp_rates_count,
                                                   const u8* rsn_ie, u32 rsn_ie_len, u8* out_buf, u32 out_buf_capacity);

/// Build a Deauthentication frame body.
::duetos::core::Result<u32> MlmeBuildDeauthFrame(const u8 sta_mac[6], const u8 ap_mac[6], u16 reason_code, u8* out_buf,
                                                 u32 out_buf_capacity);

/// Default RSN IE for WPA2-PSK with CCMP-128. Writes 22 bytes.
u32 MlmeBuildDefaultRsnIe(u8* out, u32 cap);

void MlmeSelfTest();

} // namespace duetos::net::wireless
