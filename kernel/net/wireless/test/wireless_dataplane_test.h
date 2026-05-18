#pragma once

/*
 * DuetOS — wireless data-plane end-to-end self-test.
 *
 * Runs AFTER NetStackInit (the IP stack must be live). Drives a
 * full "join an SSID and get online" flow against the software
 * FakeAp + FakeGw peer over a GCMP-128-encrypted link:
 *
 *   associate (WPA2 4-way) → bind netif → DHCP DISCOVER/OFFER/
 *   REQUEST/ACK → lease bound → ARP + ICMP ping the gateway.
 *
 * Every data frame crosses the link GCMP-encrypted; the test
 * asserts the on-wire bytes are ciphertext (not the cleartext
 * 802.3 frame) and that the round-trip decrypts intact. This is
 * the wireless equivalent of the wired e1000+SLIRP DHCP proof.
 */

namespace duetos::net::wireless::test
{

void WirelessDataPlaneSelfTest();

} // namespace duetos::net::wireless::test
