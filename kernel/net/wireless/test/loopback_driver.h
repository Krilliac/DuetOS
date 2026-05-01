#pragma once

#include "net/wireless/test/fake_ap.h"
#include "net/wireless/wdev.h"
#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — Loopback wireless driver for end-to-end self-test.
 *
 * Implements a fake `WirelessDeviceOps` vtable. Each op
 * synthesizes the response a real driver+AP pair would produce
 * by calling into the FakeAp peer, then re-enters the kernel
 * stack via `WirelessDeliverBeacon / WirelessDeliverMgmt /
 * WirelessDeliverEapol`. The result is a pure-software exercise
 * of the entire control tier: scan, auth, assoc, 4-way
 * handshake, key install.
 *
 * Lifecycle: register one LoopbackDriver per FakeAp; tear down
 * with `LoopbackDriverShutdown` (which is a no-op since wdev
 * registration is one-shot for v0).
 *
 * Threading: all ops run on the calling thread (synchronous
 * loopback). Recursion depth is bounded at 4 levels (Connect →
 * SendEapolFrame → DeliverEapol → SendEapolFrame).
 */

namespace duetos::net::wireless::test
{

struct LoopbackDriver
{
    WirelessDevice* wdev; // points into the wdev table
    FakeAp ap;
    u32 wdev_id;

    // Captured STA-side keys when the supplicant calls
    // ops.InstallKey. After a successful handshake, these MUST
    // match the FakeAp's installed counterparts.
    u8 sta_pairwise_key[32];
    u32 sta_pairwise_key_len;
    u8 sta_pairwise_mac[6];
    u8 sta_group_key[32];
    u32 sta_group_key_len;
    u8 sta_group_index;

    // Counters for the test harness.
    u32 scan_calls;
    u32 auth_calls;
    u32 assoc_calls;
    u32 disconnect_calls;
    u32 keys_installed;
    u32 mgmt_frames_tx;
    u32 eapol_frames_tx;
};

/// Initialize + register the loopback driver. Builds a fake AP
/// with the given SSID + passphrase, then registers a wdev with
/// our ops vtable. Returns the wdev_id assigned by the wdev
/// surface.
::duetos::core::Result<u32> LoopbackDriverRegister(LoopbackDriver* drv, const char* ssid, const char* passphrase,
                                                   const u8 ap_mac[6], const u8 sta_mac[6], u8 channel);

/// Drive a complete connect cycle from the test harness. Calls
/// scan-and-wait, then drive-handshake, then asserts the keys
/// match. Returns Ok if all steps complete and keys match.
::duetos::core::Result<void> LoopbackDriverDrive(LoopbackDriver* drv, const char* passphrase);

/// Reset internal counters / handshake state without re-registering
/// the wdev. Useful for the "wrong PSK" failure-mode subtest.
void LoopbackDriverReset(LoopbackDriver* drv);

} // namespace duetos::net::wireless::test
