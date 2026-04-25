#pragma once

/*
 * DuetOS — boot-time live network smoke test.
 *
 * Spawns one kernel thread that, after DHCP completes, exercises the
 * full network stack against real peers:
 *
 *   1. ICMP echo to the DHCP-supplied gateway (10.0.2.2 under QEMU
 *      SLIRP — known-responsive).
 *   2. DNS A-record query for `www.google.com` to the DHCP-supplied
 *      resolver (or 10.0.2.3 by default under QEMU SLIRP).
 *   3. ICMP echo to 8.8.8.8 (Google DNS — only reachable when SLIRP
 *      `icmp_redirect` is on, or on real hardware).
 *   4. TCP connect + GET / on the DNS-resolved IP, port 80.
 *
 * Each step times out independently. Results print to the serial log
 * with a clear PASS/FAIL/skipped line per step so the boot transcript
 * can be grepped for connectivity status.
 *
 * Threading: spawned by `NetStackInit` after the e1000 path has
 * established an interface. Runs as a single kernel thread, then
 * exits. No retry, no periodic re-test — this is a one-shot
 * smoke check.
 */

namespace duetos::net
{

/// Spawn the live network smoke-test task. Idempotent — the second
/// call is a no-op. Safe to call before DHCP completes; the task
/// internally waits up to 5 seconds for a lease.
void NetSmokeTestStart();

} // namespace duetos::net
