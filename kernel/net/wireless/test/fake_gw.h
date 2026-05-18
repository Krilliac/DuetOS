#pragma once

#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — software gateway / "ISP" behind the fake AP.
 *
 * Pure L3 responder operating on 802.3 (Ethernet II) frames. It
 * is the thing on the far side of the simulated radio: the home
 * router + the ISP it uplinks to, collapsed into one deterministic
 * peer for the data-plane self-test. No crypto, no 802.11 here —
 * the loopback driver decrypts before calling in and encrypts the
 * reply, exactly as a real AP's MAC layer would.
 *
 * Implements just enough of a network edge for a client to "get
 * online like normal":
 *   - ARP: answers who-has for the gateway IP.
 *   - DHCP: DISCOVER → OFFER, REQUEST → ACK (a full RFC-2131
 *     subset lease: IP, mask, router, DNS, lease time).
 *   - ICMP: echo request to the gateway IP → echo reply.
 *
 * Anything else is silently not answered (returns out_len = 0,
 * Ok). GAP: no upstream NAT / DNS resolution / TCP termination —
 * the gateway IS the whole reachable network for the self-test,
 * the same containment SLIRP `restrict=on` gives the wired path.
 *
 * Threading: stateless apart from the caller-supplied config;
 * safe to call from the loopback driver's TX context.
 */

namespace duetos::net::wireless::test
{

struct FakeGwConfig
{
    u8 gw_mac[6];     // the AP/gateway's MAC (Ethernet src of replies)
    u8 client_mac[6]; // the STA's MAC (Ethernet dst of unicast replies)
    u8 gw_ip[4];      // gateway / DHCP server / DNS address
    u8 lease_ip[4];   // address handed to the client
    u8 netmask[4];    // subnet mask offered
    u32 lease_secs;   // lease time offered
};

/// Process one decrypted 802.3 frame from the client. If the
/// gateway has a reply, builds it into `out` and sets `*out_len`;
/// otherwise sets `*out_len = 0`. Returns Err only on a malformed
/// caller buffer — an unhandled protocol is a no-reply success.
::duetos::core::Result<void> FakeGwHandle(const FakeGwConfig& cfg, const u8* eth_in, u32 in_len, u8* out, u32 out_cap,
                                          u32* out_len);

} // namespace duetos::net::wireless::test
