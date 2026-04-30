# Live Internet connectivity — DuetOS reaches Google over QEMU SLIRP

**Last updated:** 2026-04-30
**Type:** Observation + Issue + Pattern
**Status:** Active

## Description

End-to-end Internet connectivity now also works under QEMU SLIRP,
not only on bare metal. The default user-facing instruction
("download Chrome and reach google.com") cannot run a real
browser — the Win32 surface is too thin — but the kernel's TCP
stack can speak HTTP/1.0 to www.google.com and pull back a real
**HTTP 426 Upgrade Required** response from Google's edge.

Demonstration:

```bash
cmake --preset x86_64-debug
cmake --build build/x86_64-debug
# Boot the new GRUB entry (selectable from the menu, id=duetos-live-internet):
#   DuetOS — Live Internet (reach google.com)
# Or boot any entry and pass `netsmoke=force` on the kernel cmdline.
DUETOS_PRESET=x86_64-debug DUETOS_TIMEOUT=45 tools/qemu/run.sh \
    2>&1 | grep '^\[net-smoke\]'
```

Expected output (one example transcript, IPs vary day to day):

```
[net-smoke] emulator detected but netsmoke=force set — running live probe
[net-smoke] starting — waiting up to 5s for DHCP...
[net-smoke] DHCP OK ip=10.0.2.15 router=10.0.2.2 dns=10.0.2.3
[net-smoke] step 1: ping gateway 10.0.2.2
[net-smoke] step 1: PASS — gateway replied to ICMP echo
[net-smoke] step 2: DNS A www.google.com via 10.0.2.3
[net-smoke] step 2: PASS — www.google.com -> 142.251.151.119
[net-smoke] step 3: ping 8.8.8.8 (public)
[net-smoke] step 3: skipped — no reply (SLIRP without raw-ICMP, or no public route)
[net-smoke] step 4: TCP GET / HTTP/1.0 -> 142.251.151.119:80
[net-smoke] step 4: PASS — server replied (HTTP status=426)
[net-smoke] done
[net-smoke] boot listener installed on tcp/7777
```

## What changed vs. the bare-metal-only knowledge file

`live-internet-connectivity-v0.md` documented the bare-metal path.
Under QEMU the smoke test was *intentionally* gated off because
the kernel devs found it unreliable — but the cause turned out
to be a single bug in the e1000e RX-poll task, not anything
about SLIRP itself. SLIRP responds to gateway ICMP, proxies
DNS at 10.0.2.3, and forwards TCP to the host's network — same
as documented. Once the kernel could actually drain RX packets
on QEMU, every step passed.

## Root cause and fix — e1000e RX wakeup hang

Symptom: under QEMU SLIRP, the very first packet exchange after
DHCP completed (`net-smoke` step 1: ICMP echo to 10.0.2.2)
timed out after 2 s, then DNS to 10.0.2.3 timed out after 3 s.
DHCP itself succeeded, proving RX worked at least once.

Diagnosis: `kernel/drivers/net/net.cpp` — `E1000RxPollEntry`
binds an MSI-X vector for any e1000-family NIC and, when the
binding succeeds, blocks on `WaitQueueBlock(&g_e1000.rx_wait)`
between drain passes. The lost-wakeup guard only checks the
*next* descriptor (`rx_tail + 1`) for the DD bit before
blocking — packets that arrive after that read but before the
block-and-unblock window land in later descriptors and never
wake the task.

QEMU's e1000e emulator under SLIRP does not deliver an MSI-X
interrupt for every RX packet — RXT0 in particular is held
back. So after the first arrival (DHCP REPLY) the wait queue
goes quiet and stays quiet. The kernel's TCP/UDP/ICMP retries
fire, but RX descriptors fill up without ever being drained.

Fix (`kernel/drivers/net/net.cpp` `E1000RxPollEntry`):
replace the unbounded `WaitQueueBlock` with
`WaitQueueBlockTimeout(&g_e1000.rx_wait, /*ticks=*/1)` so the
task wakes every ~10 ms regardless of IRQ activity. IRQ wakeups
still short-circuit the wait when they fire; the timeout is
purely a safety net. Real bare-metal IRQs aren't slowed down.

## Scope

### Covered

- **`kernel/net/net_smoke.cpp/.h`** — `NetSmokeTestStart` now
  takes a `bool force_on_emulator` argument that overrides the
  `arch::IsEmulator()` skip gate. Default `false` preserves
  pre-existing behaviour everywhere except the explicit opt-in.
- **`kernel/core/main.cpp`** — reads the kernel cmdline for
  `netsmoke=force` and passes the result into
  `NetSmokeTestStart`. No effect on bare-metal boots (which
  always run the smoke test) or on emulator boots without the
  flag (still skipped to keep boot-smoke fast).
- **`boot/grub/grub.cfg`** — new menuentry
  `DuetOS — Live Internet (reach google.com)` with id
  `duetos-live-internet`, boots `boot=tty netsmoke=force`. TTY
  rather than desktop so the smoke task doesn't compete with
  the windowing system for serial output. Existing entries
  keep their indices (the screenshot harness pins them).
- **`kernel/drivers/net/net.cpp` `E1000RxPollEntry`** — bounded
  WaitQueueBlockTimeout instead of unbounded WaitQueueBlock.

### Not covered (deferred)

- Proper IVAR programming + IRQ-only wakeup for QEMU's e1000e.
  The 10 ms tick poll wastes a small fraction of one core
  under load — fine for a v0 driver, but the IVAR slice is
  still a follow-up. Once it lands, the timeout can be
  loosened (e.g. 100 ms) or removed.
- Running an actual PE browser binary against google.com.
  That requires the Win32 GDI/D3D/threading surface to be far
  more complete than the current STUB matrix — multi-session
  work, not in scope here.

## Audit checklist (re-run on regressions)

```bash
DUETOS_PRESET=x86_64-debug DUETOS_TIMEOUT=45 tools/qemu/run.sh \
    2>&1 | grep -E '^\[net-smoke\]|cmdline:'
```

Boot the GRUB entry `DuetOS — Live Internet (reach google.com)`
(or pass `netsmoke=force` manually). Expect every step to
PASS except step 3, which is `skipped` under SLIRP without
raw-ICMP — that's normal.

## Why this matters

The user-facing pillar "DuetOS runs on commodity PC hardware
and reaches the public Internet" was already true on bare metal,
but every CI / dev-loop run is QEMU. Without the smoke test
running on the iron we actually develop on, regressions in the
DHCP/ARP/UDP/TCP path were invisible until the next bare-metal
boot. Now any PR can grep for `[net-smoke] step N: PASS` in the
serial transcript and the TCP-to-Google path is guarded by a
ground-truth probe.
