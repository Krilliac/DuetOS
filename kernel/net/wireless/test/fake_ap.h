#pragma once

#include "net/wireless/eapol.h"
#include "net/wireless/fourway.h"
#include "net/wireless/ieee80211.h"
#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — Software AP responder for the wireless loopback test.
 *
 * Implements the AP / authenticator side of the 802.11
 * association + WPA2-PSK 4-way handshake entirely in software.
 * Mirrors the role that `mac80211_hwsim` + `hostapd` plays for
 * Linux's wireless CI: a fake peer that runs the same algorithms
 * the real silicon + AP-side daemon would, so an end-to-end
 * supplicant flow can be exercised without hardware.
 *
 * Feeds frames back to the supplicant through the loopback
 * driver. Does not own MAC addressing, channel selection, or
 * radio behavior — those are configured at construction.
 *
 * Threading: callable only from one thread (the test). No
 * locking; the FakeAp is owned by the test harness.
 */

namespace duetos::net::wireless::test
{

enum class FakeApState : u8
{
    Idle = 0,
    Authenticated = 1,
    Associated = 2,
    SentM1 = 3,
    GotM2_SentM3 = 4,
    GotM4_Done = 5,
    Failed = 6,
};

const char* FakeApStateName(FakeApState s);

struct FakeAp
{
    char ssid[kSsidMaxBytes + 1];
    u8 ssid_len;
    char passphrase[64];
    u8 mac[6];
    u8 channel;
    bool wpa2; // true → WPA2-PSK; false → open

    // Derived once at init.
    u8 pmk[32];

    // Per-handshake state.
    u8 anonce[32];
    u8 sta_mac[6];
    u8 ptk[kPtkBytes];
    bool ptk_valid;
    u8 gtk[16];
    u8 gtk_index;
    u8 replay_counter[8];

    FakeApState state;
    u32 failure_step; // for diagnostic readback when state==Failed

    // Counters for the test harness to assert on.
    u32 beacons_sent;
    u32 m1_sent;
    u32 m2_received_ok;
    u32 m2_mic_failures;
    u32 m3_sent;
    u32 m4_received_ok;
    u32 m4_mic_failures;
};

::duetos::core::Result<void> FakeApInit(FakeAp* ap, const char* ssid, const char* passphrase, const u8 mac[6],
                                        u8 channel);

/// Build a beacon frame for this AP into `out`. Returns bytes
/// written or 0 on capacity failure.
u32 FakeApBuildBeacon(FakeAp* ap, u8* out, u32 cap);

/// Build an Authentication response (algo=Open, seq=2,
/// status=Success).
u32 FakeApBuildAuthResponse(FakeAp* ap, const u8 sta_mac[6], u8* out, u32 cap);

/// Build an Association response (status=Success, AID=1).
u32 FakeApBuildAssocResponse(FakeAp* ap, const u8 sta_mac[6], u8* out, u32 cap);

/// Generate ANonce + build M1 of the 4-way handshake. Sets
/// `ap->state = SentM1`.
::duetos::core::Result<u32> FakeApBuildM1(FakeAp* ap, const u8 sta_mac[6], u8* out, u32 cap);

/// Receive M2 from the STA: extract SNonce, derive PTK
/// independently, verify the MIC. On success, build M3 with
/// embedded GTK KDE.
::duetos::core::Result<u32> FakeApProcessM2BuildM3(FakeAp* ap, const u8* m2, u32 m2_len, u8* m3_out, u32 m3_cap);

/// Receive M4: verify the MIC. Marks handshake Done on success.
::duetos::core::Result<void> FakeApProcessM4(FakeAp* ap, const u8* m4, u32 m4_len);

/// Pairwise key (TK, 16 bytes) the AP locked in. After a
/// successful handshake, the STA's installed pairwise key MUST
/// match this byte-for-byte.
const u8* FakeApInstalledTk(const FakeAp* ap);

/// Group key (GTK, 16 bytes).
const u8* FakeApInstalledGtk(const FakeAp* ap);

} // namespace duetos::net::wireless::test
