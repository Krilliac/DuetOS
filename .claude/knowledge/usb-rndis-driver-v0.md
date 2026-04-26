# USB RNDIS driver + bulk-poll serialization (v0)

**Last updated:** 2026-04-25
**Type:** Observation + Decision
**Status:** Active (manual probe via `usbnet probe`; auto-probe gated on event-router work)

## Description

Microsoft Remote NDIS class driver — the protocol QEMU's `-device
usb-net` emulates by default and the one most Android phones use
for USB tethering. Built on top of the same xHCI bulk + control
primitives that landed with CDC-ECM, plus a new bulk-poll
serialization layer that addresses the v0 event-ring data race.

## Scope

### Covered

- **`kernel/drivers/usb/rndis.cpp/h`** — full RNDIS class driver:
  - `SEND_ENCAPSULATED_COMMAND` / `GET_ENCAPSULATED_RESPONSE` over
    EP0 for the control RPC channel.
  - `RNDIS_INITIALIZE_MSG` → learn `MaxTransferSize` and
    `PacketAlignmentFactor`.
  - `RNDIS_SET_MSG` for `OID_GEN_CURRENT_PACKET_FILTER` (DIRECTED
    | BROADCAST | ALL_MULTICAST).
  - `RNDIS_QUERY_MSG` for `OID_802_3_PERMANENT_ADDRESS` to learn
    the device's MAC.
  - Configuration-descriptor walker that handles both legal RNDIS
    advertisements: class 0x02 / sub 0x02 / proto 0xFF (msft-style)
    and class 0xEF / sub 0x04 / proto 0x01 (USB-IF Wireless Mobile
    Communications Device).
  - Bulk IN / OUT endpoint configuration via the existing
    `XhciConfigureBulkEndpoint`.
  - 44-byte `RNDIS_PACKET_MSG` framing on TX; matching unwrap on RX.
  - Network-stack bind as `iface 1` (e1000 owns iface 0); spawns
    `rndis-rx` polling task; kicks off DHCP.
- **`XhciPauseEventConsumer` + `g_event_consumer_paused`** — gates
  the HID poll task while a class driver runs control transfers,
  preventing it from stealing Transfer Events from the class
  driver's `WaitEvent`.
- **TRB-keyed event side cache** (`g_trb_event_cache[4]`) — when
  `WaitEvent` drains a Transfer Event whose TRB pointer doesn't
  match the current waiter, the event is stashed by TRB phys for a
  future `XhciBulkPoll` to claim. Gracefully handles a single
  cross-thread event hand-off; doesn't fix the deeper concurrency
  bug below.
- **`g_bulk_poll_lock`** — atomic mutex serializing every
  `XhciBulkPoll` call. The v0 event-ring consumer indices
  (`Runtime::evt_idx`, `evt_cycle`) are non-atomic; two threads in
  `WaitEvent` simultaneously would corrupt them. The lock makes
  exactly one waiter touch the ring at a time. Acquire path
  yields via `SchedSleepTicks(1)` after 4096 spin attempts so the
  loser doesn't busy-burn CPU.
- **`usbnet` shell command** — manual invocation of the USB-net
  probe from a stable post-boot context. `usbnet probe` tries
  CDC-ECM first then RNDIS; `usbnet status` reports which (if
  any) is online.

### Verified live in QEMU

```
$ qemu-system-x86_64 ... -device qemu-xhci -device usb-net,bus=xhci.0,...

[rndis] online slot=0x1 mac=52:54:00:12:34:57 max_xfer=0x62c
                  bulk_in=0x82 bulk_out=0x02
[sched] created task id=0x2d name="rndis-rx" ...
```

INIT + SET_PACKET_FILTER + QUERY_MAC all complete; the device's
real MAC is read off the wire. Bulk endpoints are configured. The
network-stack bind succeeds. **The control-plane half of the
driver is functional end-to-end.**

### NOT working in v0

- **Concurrent bulk-IN polling vs DHCP TX.** Once the
  `rndis-rx` polling task is alive AND `DhcpStart` issues a
  bulk-OUT, both threads call `XhciBulkPoll` concurrently. Even
  with the new spinlock, the test rig hangs in `XhciBulkPoll`
  (TX submitted but Transfer Event never observed by either
  thread; `runaway-cpu` health warning fires). Suspected root
  cause is interaction between the long inner spin in
  `WaitEvent` and timer preemption that leaves event-ring
  state inconsistent. Needs proper investigation.
- **Auto-probe at boot.** Calling `RndisProbe()` from kernel
  init (or from the smoke-test tail) leaves the kernel
  unresponsive on the wire — same root cause as above.
- **Multi-packet RX aggregation.** Each USB transfer can
  carry multiple `RNDIS_PACKET_MSG` records back to back; v0
  parses only the first.
- **Status indications.** RNDIS_INDICATE_STATUS_MSG is
  silently dropped on RX; we don't track media-connect events.

## Integration points

- `kernel/drivers/usb/rndis.cpp/h` — driver itself.
- `kernel/drivers/usb/xhci.h` — exposes `XhciPauseEventConsumer`.
- `kernel/drivers/usb/xhci.cpp` — adds the side cache, the bulk
  poll lock + ack/release helpers, the forward declarations.
- `kernel/CMakeLists.txt` — `drivers/usb/rndis.cpp` added.
- `kernel/shell/shell.cpp` — `CmdUsbNet` + `usbnet` keyword.
- `kernel/core/main.cpp` — auto-probe deliberately NOT called.
- `kernel/net/net_smoke.cpp` — auto-probe deliberately NOT
  called from the smoke-test tail (regression note in code).

## Edge cases / what to remember

- **`SerialWrite("...")` truncated `runaway-cpu` warning is the
  signature of the bulk-poll hang.** When seen, the lock holder
  is `XhciBulkPoll` and the deeper event-ring race has triggered.
- **`RNDIS_INITIALIZE_CMPLT` Status field is at offset 12, not
  16.** I had this wrong on first cut; the device replied
  successfully and we discarded the answer. (Spec §3.2.2:
  MessageType / MessageLength / RequestID / Status / MajorVersion
  / MinorVersion / DeviceFlags / Medium / MaxPacketsPerTransfer /
  MaxTransferSize / PacketAlignmentFactor — fixed-width u32s,
  little-endian.)
- **QEMU's usb-net is RNDIS, not CDC-ECM.** No `rndis=off`
  property in current QEMU. `qemu-system-x86_64 -device usb-net,help`
  confirms.
- **Bulk-poll lock release-on-scope-exit pattern.** Used a tiny
  RAII `Unlocker` struct so early returns don't leak the lock.
  Standard C++23 idiom; the kernel doesn't have `std::lock_guard`.
- **`XhciBulkPoll`'s iter budget is `timeout_us * 1000`.** Roughly
  1000 iters per microsecond of wall clock on TCG. 50ms ≈ 50M
  iters. Keep these short to release the lock often.

## See also

- `usb-cdc-ecm-driver-v0.md` — sibling class driver targeting
  iPhones / Linux gadgets / premium USB-Ethernet.
- `live-internet-connectivity-v0.md` — the e1000 wired path that
  proves the network stack works end-to-end.
- `xhci-hid-keyboard-v0.md` — the HID bring-up that the bulk-poll
  primitives generalise.
