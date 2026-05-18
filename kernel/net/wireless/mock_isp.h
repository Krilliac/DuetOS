#pragma once

/*
 * DuetOS — live "mock ISP" Wi-Fi backend.
 *
 * Promotes the fake-AP + GCMP data-plane loopback (used by the
 * boot self-test) into a real `WifiBackendOps` registered on the
 * live path, so an interactive `wifi scan` / `wifi connect <ssid>
 * <psk>` actually works on a normal boot — the SSID shows up, the
 * router's WPA2 password is required to join (a wrong password is
 * rejected), and a successful join runs DHCP over the encrypted
 * link so the station is genuinely online.
 *
 * This is the userland-visible end of the same machinery the
 * self-test exercises: one software AP behind one software
 * gateway, reached through the kernel-owned `WirelessDevice` /
 * IP-stack seams (no subsystem shortcut).
 *
 * Call `MockIspInit()` once at boot, AFTER NetStackInit (it needs
 * WifiInit + the IP stack). It registers the loopback wdev and
 * the Wi-Fi backend; it does not associate until the user asks.
 *
 * GAP: a single WPA2-PSK network is exposed. Open / multi-SSID
 * live association is a follow-up — the data plane is GCMP-keyed,
 * so an unencrypted (open) data path is separate work.
 */

namespace duetos::net::wireless
{

void MockIspInit();

/// Self-test the live backend through the public Wi-Fi API:
/// scan lists the SSID, the correct PSK joins + leases an IP, a
/// wrong PSK is rejected, disconnect tears down. Runs as a boot
/// self-test after MockIspInit (no-op if the backend is offline).
void MockIspSelfTest();

} // namespace duetos::net::wireless
