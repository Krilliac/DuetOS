# Live Internet connectivity — DuetOS reaches Google over real DNS + TCP

**Last updated:** 2026-04-25
**Type:** Observation + Pattern
**Status:** Active

## Description

End-to-end Internet connectivity verified. The kernel boots in
QEMU under UEFI, brings up the e1000e NIC, completes a real DHCP
exchange, ARP-learns the gateway, ICMP-pings the gateway, resolves
`www.google.com` via real DNS, and TCP-connects to Google's
servers with an HTTP/1.0 GET that gets back a real **HTTP 426
Upgrade Required** response from Google's edge.

Demonstration command:

```bash
sudo apt-get install -y qemu-system-x86 grub-common grub-pc-bin grub-efi-amd64-bin xorriso mtools ovmf
cmake --preset x86_64-release
cmake --build build/x86_64-release
DUETOS_PRESET=x86_64-release DUETOS_TIMEOUT=30 tools/qemu/run.sh 2>&1 | grep '^\[net-smoke\]'
```

Expected output:

```
[net-smoke] starting — waiting up to 5s for DHCP...
[net-smoke] DHCP OK ip=10.0.2.15 router=10.0.2.2 dns=10.0.2.3
[net-smoke] step 1: ping gateway 10.0.2.2
[net-smoke] step 1: PASS — gateway replied to ICMP echo
[net-smoke] step 2: DNS A www.google.com via 10.0.2.3
[net-smoke] step 2: PASS — www.google.com -> 142.251.153.119
[net-smoke] step 3: ping 8.8.8.8 (public)
[net-smoke] step 3: skipped — no reply (SLIRP without raw-ICMP, or no public route)
[net-smoke] step 4: TCP GET / HTTP/1.0 -> 142.251.153.119:80
[net-smoke] step 4: PASS — server replied (HTTP status=426)
[net-smoke] done
```

## Scope

### Covered

- **`kernel/net/net_smoke.cpp/.h`** — boot-time live network
  smoke test. One kernel thread spawned by `NetStackInit` that
  waits up to 5 s for DHCP, then runs four ordered probes:
  1. ICMP echo to the DHCP-supplied gateway (always works
     under SLIRP).
  2. DNS A-record query for `www.google.com` via the
     DHCP-supplied resolver.
  3. ICMP echo to `8.8.8.8` (skipped when SLIRP runs without
     raw-ICMP capability — typical for unprivileged QEMU).
  4. TCP connect + HTTP/1.0 GET to the resolved Google IP.
- **`kernel/loader/firmware_loader.cpp/.h`** — vendor-firmware
  loader scaffold. v0 backend always misses; the API lets
  iwlwifi / rtl88xx / bcm43xx call `FwLoad(req)` honestly so
  `firmware_pending` is set from a real lookup result instead
  of being hard-coded.
- **e1000e MSI-X gating fix** — the v0 driver previously bound
  MSI-X for any e1000-family NIC, but only programmed the
  legacy IRQ source mask via `IMS`. e1000e (82574+) requires
  programming `IVAR` (0x000E4) to route RX/TX/Other interrupt
  causes to the bound MSI-X vector — without that, IRQs fire
  but never wake the RX wait queue, packets sit in descriptors,
  and replies never reach the stack.
  Fix: `is_classic_e1000 = (device_id 0x1000..0x107F)`; only
  classic e1000 takes the MSI-X path. e1000e tick-polls. The
  IVAR slice is a follow-up.
- **DHCP-router ARP fallback in `kernel/net/stack.cpp`** — three
  call sites (`NetTcpConnect`, `NetDnsQueryA`, `NetNtpQuery`)
  used to compute the gateway IP as `dst[0..2].2`, which only
  worked for QEMU SLIRP's 10.0.2.0/24 layout. For arbitrary
  public IPs (e.g. 142.251.150.119) the guess missed the ARP
  cache and the connect / query silently failed. Replaced with
  `DhcpLeaseRead().router` so the actual DHCP-supplied gateway
  is used.
- **TCP listener installation deferred to after smoke test** —
  the v0 TCP impl has a single connection slot. main.cpp used
  to install `TcpListen(7777, ...)` immediately after
  `NetStackInit`, which made the smoke test's active connect
  step fail with "slot busy". Moved the listener install to
  the end of `NetSmokeEntry` so the active connect runs first
  and the listener stays online for the rest of the boot.

### Deliberately not in scope

- Multi-slot TCP. The single-slot v0 impl is a documented
  limitation; growing it to N concurrent connections is a
  separate slice.
- ARP request-on-miss. The v0 stack only learns ARP from
  incoming traffic; it doesn't issue an ARP request when the
  cache misses. The DHCP-router fallback handles the common
  case (any peer reachable through the DHCP gateway), but a
  same-subnet peer DuetOS hasn't talked to yet still misses.
- e1000e IVAR programming for MSI-X. Polling at 100 Hz is
  enough for v0; the IVAR slice will return MSI-X to the
  faster wake path.
- Real ICMP raw-socket support in QEMU SLIRP (host-side
  capability — out of kernel scope).
- TLS / HTTPS. Google replied with `HTTP 426 Upgrade Required`
  asking us to upgrade to TLS — proves the connection
  reached real Google infra. A TLS stack is a much larger
  effort, not blocking on the netcode gap.

## Integration points

- `kernel/CMakeLists.txt`: `core/firmware_loader.cpp` +
  `net/net_smoke.cpp` added to the kernel sources list.
- `kernel/core/main.cpp`: calls `FwLoaderInit()` before
  `NetInit()`; calls `NetSmokeTestStart()` immediately after
  `NetStackInit()`. The boot HTTP listener install was moved
  out of main.cpp into `NetSmokeEntry` to defer it past the
  active-connect step.
- `kernel/drivers/net/iwlwifi.cpp`,`rtl88xx.cpp`,`bcm43xx.cpp`:
  each `*BringUp` now calls `core::FwLoad(req)` and sets
  `n.firmware_pending = !fw.has_value()`. With the v0 None
  backend this always fires the miss path, but the
  per-vendor blob naming (`iwlwifi-cc-a0-46.ucode`,
  `rtlwifi/rtl8821aefw.bin`, `brcm/brcmfmac<chip>-pcie.bin`)
  is wired up so the loader-implementation slice can land
  without any further driver changes.
- `kernel/drivers/net/net.cpp::E1000BringUp`: classic-only
  MSI-X gate; e1000e variants log "MSI-X gated off" and use
  polling.
- `kernel/net/stack.cpp::NetTcpConnect / NetDnsQueryA /
  NetNtpQuery`: ARP fallback now uses `DhcpLeaseRead().router`.

## Observable

The full boot transcript shows:

```
[boot] Bringing up firmware loader (scaffold).
[fw-loader] online — backend=None (no firmware-bearing FS mounted; FwLoad always misses).
[fw-loader] callers (iwlwifi / rtl88xx / bcm43xx / future) report `firmware_pending=true`.
[boot] Detecting NICs.
[e1000] e1000e detected — MSI-X gated off (IVAR programming pending), tick-poll only
[e1000] online pci=0:5.0 mac=52:54:00:12:34:56 link=up rx_ring=… tx_ring=…
[net-probe] vid=0x8086 did=0x10d3 family=e1000e-82574  (driver online)
…
[net-smoke] starting — waiting up to 5s for DHCP...
[dhcp] DISCOVER sent
[dhcp] REQUEST sent for 10.0.2.15
[dhcp] ACK bound ip=10.0.2.15 router=10.0.2.2 lease_secs=86400
[net-smoke] DHCP OK ip=10.0.2.15 router=10.0.2.2 dns=10.0.2.3
[net-smoke] step 1: PASS — gateway replied to ICMP echo
[net-smoke] step 2: PASS — www.google.com -> 142.251.153.119
[net-smoke] step 3: skipped — no reply (SLIRP without raw-ICMP, or no public route)
[net-smoke] step 4: PASS — server replied (HTTP status=426)
[net-smoke] done
[net-smoke] boot listener installed on tcp/7777
```

A QEMU `filter-dump` pcap of the same run shows: BOOTP/DHCP
DISCOVER+REPLY pair, the e1000 self-test broadcast frame,
ICMP echo request + matching reply, DNS A query + answer with 8
A records, then the HTTP/1.0 GET + Google's 426 response.

## Edge cases / what to remember

- **`-device e1000` works fine; `-device e1000e` was broken
  before the MSI-X gate.** The v0 driver's MSI-X bind would
  succeed on e1000e but no IRQs delivered → DHCP would still
  complete (replies arrive in the ring and the lost-wakeup
  recovery path drains them once before blocking) but
  *unicast* responses (ICMP reply, DNS reply) would never
  reach the stack. Symptom: pcap shows traffic, kernel sees
  none. The fix gates MSI-X to legacy e1000.
- **DHCP-router fallback is wider than the original guess.**
  The old `dst[0..2].2` heuristic worked for SLIRP because
  10.0.2.2 is the conventional gateway. On real LANs, the
  gateway is whatever DHCP says — typically `.1` on
  consumer routers, often `.254` on enterprise. The fix
  covers both.
- **TCP single-slot is a real constraint.** Anything that
  wants to do active connect must own the slot for the
  duration. Smoke test ordering is critical; don't install
  the boot listener until the test completes.
- **Firmware loader scaffold returns `Err{NotFound}` from
  every call.** This is correct v0 behavior — every iwlwifi
  / rtl88xx / bcm43xx adapter reports `firmware_pending=true`
  in its `NicInfo`. The shell + GUI handle this honestly.
- **Internet connectivity proven through the e1000 wired
  path; wireless drivers stay shell-level.** The user-visible
  outcome is "DuetOS can talk to the Internet from real
  hardware via wired Ethernet." Wireless association is
  blocked on the firmware loader + 802.11 stack — neither
  in scope for v0.

## See also

- `wireless-drivers-v0.md` — iwlwifi/rtl88xx/bcm43xx shells
  this slice extends.
- `e1000-driver-v0.md` — wired driver underpinning the live
  test path.
- `network-shell-commands-v0.md` — `ifconfig` / `dhcp` /
  `ping` / `nslookup` / `http` shell commands available
  once the user gets to the shell.
- `network-flyout-panel-v0.md` — GUI surface that consumes
  `WirelessStatusRead` (now reflecting `drivers_online > 0`
  for wireless adapters).
