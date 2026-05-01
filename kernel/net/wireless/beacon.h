#pragma once

#include "net/wireless/ieee80211.h"
#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — IEEE 802.11 beacon / probe-response frame parser.
 *
 * Walks an on-air management frame (after the FCS has been
 * stripped), validates the MAC header, and parses the body's
 * Information Element stream. Captures everything an SSID picker
 * UI needs:
 *
 *   - SSID (id=0): up to 32 bytes; sanitized to printable.
 *   - DS Parameter Set (id=3): channel number on 2.4 GHz.
 *   - HT Operation (id=61): primary channel for 5 GHz.
 *   - Supported Rates + Extended Supported Rates: max basic rate.
 *   - RSN (id=48): WPA2/WPA3 cipher + AKM lists.
 *   - Vendor Specific (id=221, OUI 00:50:F2 type 1): WPA-1 IE.
 *   - Capability Info: ESS / Privacy / Short Preamble / Short Slot.
 *
 * Threading: pure function. No allocation, no global state.
 * `BeaconParsed` views point back into the original frame bytes;
 * the caller must keep the frame alive for the lifetime of the
 * parsed struct.
 */

namespace duetos::net::wireless
{

enum class WirelessSecurity : u8
{
    Open = 0,
    Wep = 1,
    Wpa = 2,     // WPA-1 (TKIP-PSK)
    Wpa2 = 3,    // WPA2 (CCMP-PSK)
    Wpa3 = 4,    // WPA3-SAE
    Wpa2Ent = 5, // WPA2-Enterprise (802.1X)
    Wpa3Ent = 6, // WPA3-Enterprise
};

inline constexpr u32 kBeaconMaxCipherSuites = 4;
inline constexpr u32 kBeaconMaxAkmSuites = 4;
inline constexpr u32 kBeaconMaxRates = 16;

struct BeaconParsed
{
    bool valid;

    // Derived from the MAC header.
    u8 bssid[6];
    u8 source[6];
    u16 frame_control;
    MgmtSubtype subtype;

    // Fixed body prefix.
    u64 timestamp;
    u16 beacon_interval; // in TUs (1024 µs)
    u16 capability_info; // raw cap bits

    // SSID.
    char ssid[kSsidMaxBytes + 1];
    u8 ssid_length;
    bool hidden_ssid; // SSID IE was present but length was 0.

    // Channel: from DS Parameter Set on 2.4 GHz, or HT Operation
    // on 5 GHz. 0 if neither IE was present.
    u8 channel;

    // Rates.
    u8 supported_rates[kBeaconMaxRates];
    u8 supported_rates_count;
    u8 max_basic_rate_500kbps; // top "Basic Rate" bit, in 500 kbps units.

    // RSN (WPA2/WPA3) information.
    bool rsn_present;
    u16 rsn_version;
    u32 rsn_group_cipher; // packed (oui[0]<<24)|(oui[1]<<16)|(oui[2]<<8)|type
    u32 rsn_pairwise_ciphers[kBeaconMaxCipherSuites];
    u8 rsn_pairwise_count;
    u32 rsn_akm_suites[kBeaconMaxAkmSuites];
    u8 rsn_akm_count;
    u16 rsn_capabilities;

    // WPA-1 (vendor IE 00:50:F2 type 1).
    bool wpa1_present;

    // Derived security taxonomy.
    WirelessSecurity security;

    // Bookkeeping.
    u32 ie_count;
    u32 unknown_ies;
    u32 walked_bytes;
};

::duetos::core::Result<void> BeaconParse(const u8* frame, u32 frame_size, BeaconParsed* parsed);

void BeaconLog(const BeaconParsed& parsed);

void BeaconSelfTest();

const char* WirelessSecurityName(WirelessSecurity s);

} // namespace duetos::net::wireless
