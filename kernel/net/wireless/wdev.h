#pragma once

#include "net/wireless/beacon.h"
#include "net/wireless/fourway.h"
#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — cfg80211-equivalent surface (WirelessDevice + ops vtable).
 *
 * Layered between the 802.11 MLME and the per-vendor driver. The
 * driver registers a `WirelessDeviceOps` vtable; MLME calls those
 * ops to issue scan / auth / assoc / TX-mgmt / key-install
 * primitives. The driver is responsible for translating each
 * call into the per-vendor command queue + ring writes.
 *
 * This is the seam at which "what does the user want?" (handled
 * by MLME + UI) meets "what does the silicon need?" (handled by
 * each driver). Linux's `cfg80211` plays this role; this file is
 * the freestanding equivalent for DuetOS.
 *
 * Threading: ops are invoked from an MLME worker thread; drivers
 * MUST be safe to call from process context. Receive callbacks
 * (`OnBeaconRx`, `OnEapolRx`) may be invoked from interrupt
 * bottom halves.
 */

namespace duetos::net::wireless
{

inline constexpr u32 kWdevMaxScanResults = 32;
inline constexpr u32 kWdevMaxChannels = 38; // 11 (2.4 GHz) + 25 (5 GHz subset)
inline constexpr u32 kWdevMaxCipherSuites = 8;
inline constexpr u32 kWdevMaxAkmSuites = 8;

enum class WirelessIfType : u8
{
    Station = 0,
    Adhoc = 1,   // not implemented in v0
    Monitor = 2, // not implemented in v0
    Ap = 3,      // not implemented in v0
};

enum class WirelessOpState : u8
{
    Down = 0, // device exists but isn't usable (no firmware)
    Idle = 1, // up, not associated
    Scanning = 2,
    Authenticating = 3,
    Associating = 4,
    Handshaking = 5, // 4-way handshake in progress
    Connected = 6,
    Disconnecting = 7,
    Failed = 8,
};

const char* WirelessOpStateName(WirelessOpState s);

struct WirelessChannel
{
    u8 number;    // 1..14 on 2.4 GHz; 36..165 on 5 GHz
    u16 freq_mhz; // center frequency
    u8 max_power_dbm;
    bool radar;
    bool no_ir; // no initiate-radiation (passive scan only)
};

struct WirelessRegInfo
{
    char alpha2[3]; // ISO-3166-1 country code (e.g. "US"), nul-terminated
    u32 channel_count;
    WirelessChannel channels[kWdevMaxChannels];
};

struct WirelessScanRequest
{
    u32 channel_count; // 0 = scan all in-region channels
    u8 channels[kWdevMaxChannels];
    bool active;                         // true = probe-request scan; false = passive
    u32 dwell_ms_per_channel;            // typical 100 ms active, 250 ms passive
    char ssid_filter[kSsidMaxBytes + 1]; // empty = wildcard
};

struct WirelessAuthRequest
{
    u8 bssid[6];
    u8 channel;
    u32 auth_type; // 0 = open, 1 = shared (legacy WEP), 3 = SAE
    u32 timeout_ms;
};

struct WirelessAssocRequest
{
    u8 bssid[6];
    char ssid[kSsidMaxBytes + 1];
    u8 ssid_len;
    u8 channel;
    u8 rsn_ie[256]; // local supplicant's RSN IE
    u32 rsn_ie_len;
    u32 timeout_ms;
};

struct WirelessKeyInstallRequest
{
    u8 mac[6]; // peer MAC for pairwise; broadcast for group
    u8 key[32];
    u32 key_len;     // 16 (CCMP-128) or 32 (CCMP-256/GCMP-256)
    u8 key_index;    // 0 = pairwise; 1..3 = group keys
    u32 cipher;      // packed (oui|type) — see ieee80211.h kCipher*
    bool tx_capable; // true for pairwise, group-tx-key, or
                     // TX-active group key
    u8 rsc[8];       // initial sequence counter (RX side)
};

struct WirelessFrameRx
{
    const u8* frame;
    u32 frame_len;
    i32 rssi_dbm;
    u8 channel;
};

struct WirelessDevice; // forward decl

struct WirelessDeviceOps
{
    /// Driver-specific context; passed back to every op.
    void* drv_ctx;

    /// Bring radio up (transition Down → Idle). Driver must
    /// have firmware loaded + rings live before returning Ok.
    ::duetos::core::Result<void> (*Up)(WirelessDevice* wdev);

    /// Bring radio down. Tear down rings, halt firmware. Idempotent.
    ::duetos::core::Result<void> (*Down)(WirelessDevice* wdev);

    /// Issue a scan. Results are delivered asynchronously via
    /// `WirelessDeliverBeacon` calls back into the wdev surface.
    ::duetos::core::Result<void> (*Scan)(WirelessDevice* wdev, const WirelessScanRequest& req);

    /// Send an Authenticate frame. The driver returns Ok if the
    /// frame was queued; success/failure of the auth itself
    /// arrives via OnAuthRx.
    ::duetos::core::Result<void> (*Authenticate)(WirelessDevice* wdev, const WirelessAuthRequest& req);

    /// Send an Associate Request frame. Same async pattern.
    ::duetos::core::Result<void> (*Associate)(WirelessDevice* wdev, const WirelessAssocRequest& req);

    /// Disassociate / deauth. Tear down current association.
    ::duetos::core::Result<void> (*Disconnect)(WirelessDevice* wdev, u16 reason_code);

    /// Install a unicast (pairwise) or broadcast (group) key for
    /// CCMP / GCMP / TKIP. After this returns Ok the chip will
    /// encrypt outgoing data with TK and decrypt RX with the GTK.
    ::duetos::core::Result<void> (*InstallKey)(WirelessDevice* wdev, const WirelessKeyInstallRequest& req);

    /// Transmit a raw 802.11 management frame (auth / assoc req /
    /// EAPOL inside a data frame). Driver returns Ok when queued.
    ::duetos::core::Result<void> (*SendMgmtFrame)(WirelessDevice* wdev, const u8* frame, u32 frame_len, u8 channel);
};

struct WirelessDevice
{
    char name[16];
    u8 mac[6];
    WirelessIfType if_type;
    WirelessOpState op_state;
    WirelessRegInfo reg;

    // Cipher / AKM capability advertised by the chip+firmware.
    u32 supported_ciphers[kWdevMaxCipherSuites];
    u32 supported_cipher_count;
    u32 supported_akms[kWdevMaxAkmSuites];
    u32 supported_akm_count;

    // Current connection state (only valid in Connected state).
    u8 connected_bssid[6];
    char connected_ssid[kSsidMaxBytes + 1];
    u8 connected_ssid_len;
    WirelessSecurity connected_security;

    // Most recent scan results (overwritten on each Scan).
    BeaconParsed scan_results[kWdevMaxScanResults];
    u32 scan_result_count;
    u64 scan_started_tick;
    u64 scan_completed_tick;

    // 4-way handshake context (only meaningful during
    // Handshaking / Connected).
    FourWayContext fw;

    // Per-driver vtable.
    WirelessDeviceOps ops;

    // Identifier used by MLME / UI for human-readable logs.
    u32 wdev_id;
};

inline constexpr u32 kWdevMaxDevices = 4;

::duetos::core::Result<u32> WirelessDeviceRegister(const WirelessDevice& proto);
WirelessDevice* WirelessDeviceById(u32 id);
u32 WirelessDeviceCount();
WirelessDevice* WirelessDeviceAt(u32 index);

/// Driver delivers a received beacon / probe response. wdev
/// stores it in the scan-results table (deduping by BSSID) and
/// updates `scan_completed_tick`. Caller must hold the frame
/// alive only for the duration of this call — beacon parsed
/// fields are copied into the table.
::duetos::core::Result<void> WirelessDeliverBeacon(WirelessDevice* wdev, const WirelessFrameRx& f);

/// Driver delivers a received management frame (auth / assoc
/// resp / deauth) to the MLME. Returns immediately; MLME
/// handles dispatch on its worker thread.
::duetos::core::Result<void> WirelessDeliverMgmt(WirelessDevice* wdev, const WirelessFrameRx& f);

/// Driver delivers a received EAPOL frame for the 4-way
/// handshake. Drives `wdev->fw` through `FourWayProcessIncoming`
/// and, on M3, calls `ops.InstallKey` for both PTK and GTK.
::duetos::core::Result<void> WirelessDeliverEapol(WirelessDevice* wdev, const WirelessFrameRx& f);

/// MLME-level state transitions.
::duetos::core::Result<void> WirelessSetState(WirelessDevice* wdev, WirelessOpState s);

void WdevSelfTest();

} // namespace duetos::net::wireless
