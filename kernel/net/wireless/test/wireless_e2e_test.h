#pragma once

namespace duetos::net::wireless::test
{

/// Boot-time end-to-end self-test for the wireless control tier.
/// Builds a software loopback (FakeAp + LoopbackDriver), drives
/// the full Connect path through scan + auth + assoc + 4-way
/// handshake, then asserts:
///   - The supplicant reaches WirelessOpState::Connected.
///   - The TK installed on the STA side equals the TK derived
///     by the AP side (proves PRF + nonces + PMK + MAC ordering
///     all agree across both endpoints).
///   - The GTK installed on the STA side equals the GTK chosen
///     by the AP side (proves M3 KDE extraction works).
///   - Failure modes: wrong PSK rejects, MIC tampering rejects,
///     replay-counter regression rejects.
/// Panics on mismatch. Gated by DUETOS_BOOT_SELFTESTS.
void WirelessE2ESelfTest();

} // namespace duetos::net::wireless::test
