# Network shell commands v0 — ifconfig / dhcp / route / netscan / net

**Last updated:** 2026-04-25
**Type:** Observation
**Status:** Active

## Description

The kernel network stack (`kernel/net/stack.{h,cpp}`) had been
landing capabilities — ARP, IPv4, ICMP, UDP, TCP active+passive,
DHCP, DNS, NTP — slice by slice, with the e1000 driver kicking
DHCP automatically at NIC bring-up. None of that state was
visible from the operator shell beyond raw counters (`arp`,
`ipv4`) and one-shot tools (`ping`, `nslookup`, `http`, `ntp`).

This slice adds the user-facing surface that turns the stack from
"the kernel is talking on the wire" into "the operator can see and
manage their network". Five new commands plus three stack
accessors.

## What landed

### Stack accessors (`kernel/net/stack.{h,cpp}`)

- `bool InterfaceIsBound(u32 iface_index)` — true iff the L2 binding
  has a valid TX trampoline.
- `Ipv4Address InterfaceIp(u32 iface_index)` — the bound IP
  (rebound to the DHCP yiaddr on ACK).
- `MacAddress InterfaceMac(u32 iface_index)` — the bound MAC.
- `u32 ArpEntryCount()` — count of currently-cached, non-expired
  entries.

### Shell commands (`kernel/shell/shell.cpp`)

| Command       | Aliases       | Function                                             |
|---------------|---------------|------------------------------------------------------|
| `ifconfig`    | `netinfo`     | Per-iface: link / MAC / IP / gateway / DNS / lease   |
| `dhcp`        |               | Show lease; `dhcp renew` kicks fresh DISCOVER + waits |
| `route`       |               | Default-route view from DHCP lease; `-v` prints ARP  |
| `netscan`     | `wifi`        | "Networks I can connect to" — wireless adapter check + wired list |
| `net`         |               | Umbrella: `up` / `status` / `test`                   |

`net test` runs the full end-to-end smoke:
1. ensure DHCP lease (kicks DISCOVER if missing)
2. ARP-resolve the gateway (sends one ICMP if cache cold)
3. DNS A-record lookup of `example.com` via the lease's resolver
4. ICMP echo to the gateway
5. report PASS only if all four steps succeed

## Why these specifically

Before this slice, "is the box online?" required four separate
commands and operator inference. None of `ifconfig`, `dhcp`,
`route`, `netscan` had any equivalent — so a shell user could not
see their leased IP or manually renew without reading the serial
log.

## Wi-Fi honesty

`netscan` deliberately does NOT pretend to scan SSIDs when no
wireless driver is online. PCI subclass 0x80 plus family-string
heuristics (`iwlwifi*`, `rtl8821*`, `bcm4*`) detect wireless
hardware presence; if found, we say "wireless adapter detected,
but DuetOS has no wireless driver online" — which is the truth.
A future iwlwifi slice replaces the message with a real SSID
scan via the driver's per-radio interface.

## Edge cases

- **`net up` is idempotent.** If a lease is already valid, it
  reports the existing IP and returns; doesn't kick a redundant
  DISCOVER.
- **`dhcp renew` polls for ~2s** so the user sees the new IP
  inline rather than having to re-run the command.
- **`net test` has graceful failure messages** at every step so
  the operator knows where in the chain connectivity broke
  (DHCP / ARP / DNS / ICMP).

## Wiring

- `kCommandSet[]` extended with: `ifconfig netinfo dhcp route
  netscan wifi net`.
- Dispatcher (the big if-else in `MaybeRunCommand` / equivalent)
  has new branches placed adjacent to the existing networking
  block (`nic`, `arp`, `ipv4`).
- `CmdHelp` updated under "SYSTEM INTROSPECTION:" to surface the
  new commands.

## Files touched

- `kernel/net/stack.h` — 4 new accessor declarations
- `kernel/net/stack.cpp` — 4 new accessor definitions
- `kernel/shell/shell.cpp` — 5 new commands, dispatcher + help
- `.claude/knowledge/network-shell-commands-v0.md` — this file
- `.claude/index.md` — index entry

## Observable

```
> dhcp
DHCP: bound  ip=10.0.2.15
      gateway=10.0.2.2
      dns    =10.0.2.3
      server =10.0.2.2
      lease  =86400 sec

> ifconfig
net0  Intel e1000-82540em
       link    UP
       ether   52:54:00:12:34:56
       inet    10.0.2.15
       gateway 10.0.2.2
       dns     10.0.2.3
       dhcp    server=10.0.2.2  lease=86400s
ARP cache: 1 live entries

> net test
NET TEST: dhcp ... OK ip=10.0.2.15
NET TEST: gateway ARP ... OK mac=52:55:0a:00:02:02
NET TEST: dns ... OK example.com -> 93.184.216.34
NET TEST: ping gateway ... OK rtt~=10ms
NET TEST: PASS — DuetOS is online
```

## Future work

- Per-iface DHCP transactions (today the DHCP state machine is
  single-iface in v0; multi-NIC boxes would round-robin).
- `route add` / `route del` for a real routing table (today the
  default route is implicit-from-lease).
- Wireless driver — iwlwifi or rtl88xx — with `netscan` doing real
  SSID scans + a `connect <ssid> <psk>` command landing on top.
- IPv6 — every helper in the stack hard-codes `Ipv4Address`; the
  shell commands inherit that limitation.
