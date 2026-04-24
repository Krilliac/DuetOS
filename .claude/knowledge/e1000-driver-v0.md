# Intel e1000 NIC driver v0 — real packet I/O on commodity wired gigabit

**Last updated:** 2026-04-23
**Type:** Observation
**Status:** Active

## Description

First real network driver on top of the `drivers/net/` shell. Bring
up a classic Intel e1000 (82540EM / 82545EM etc.) from PCI discovery
through a live link with RX and TX rings armed, MAC read from the
EEPROM, and a periodic RX polling task that drains descriptors into
the kernel log. The matching network stack hand-off is a later
slice — this commit's job is to prove packet I/O works.

## Scope

Covered:
- PCI class 0x02 walk → match on Intel vid 0x8086, device id in
  the classic e1000 range `0x1000..0x107F` (QEMU's `-device e1000`
  is `0x100E`).
- Software reset (`CTRL.RST`), EEPROM MAC reload, `CTRL.SLU` +
  `CTRL.ASDE` for link-up + auto-speed.
- Multicast Table Array zeroed (128 × u32).
- RX ring: 256 legacy descriptors, 1 page. 256 × 2 KiB RX buffers
  (`AllocateContiguousFrames(128)` = 512 KiB). `RCTL.EN | BAM |
  SECRC`, buffer-size=2 KiB. Initial `RDT = 255`.
- TX ring: 256 legacy descriptors, 1 page. Per-descriptor 2 KiB
  staging buffers (`AllocateContiguousFrames(128)` = 512 KiB).
  `TCTL.EN | PSP | CT=0x10 | COLD=0x40`, `TIPG=0x0060200A`.
- `E1000Send(data, len)` — memcpy into staging, fill descriptor
  with `EOP | IFCS | RS`, bump TDT.
- Per-controller RX polling task (`e1000-rx-poll`) — sleeps one
  tick between drains, processes every DD-marked descriptor,
  logs the first 14 bytes (dst+src+ethertype), clears DD, advances
  RDT.
- TX self-test: one 60-byte broadcast frame with ethertype
  `0x88B5` ("LocalExperimental1") and the marker
  `DUETOS-E1000-SELFTEST` so a host-side `tcpdump` can pick
  the frame out of the netdev.

Deliberately not in scope:
- MSI-X (polling-only). The `MsixBindSimple` scaffolding is there;
  wiring e1000 to an MSI-X vector is a follow-up slice.
- Flow control / pause frames.
- Jumbo frames (BSIZE/BSEX configuration kept at the 2 KiB default).
- Checksum offload (CSO bits always 0).
- Hot plug / replug.
- Multi-controller — only the first classic e1000 instance comes
  up. Additional NICs stay in probe mode.
- e1000e (PCIe variants, 82571+) stays probe-only until somebody
  handles the different PHY access + flow-control register layout.

## Integration points

- `NetInit` in `kernel/drivers/net/net.cpp` → `RunVendorProbe` →
  `E1000BringUp` for matching device IDs.
- `sched::SchedCreate(E1000RxPollEntry, ...)` spawns the polling
  task; no compositor / UI coupling.
- `AllocateContiguousFrames(128)` for each ring's 512 KiB buffer
  pool — uses the same multi-page allocator the NVMe driver's
  staging buffer relies on.

## Observable

With `tools/qemu/run.sh` (which now provisions
`-netdev user -device e1000,mac=52:54:00:12:34:56`):

```
[e1000] online pci=0:5.0 mac=52:54:00:12:34:56 link=up rx_ring=0x4a0000 tx_ring=0x521000
[sched] created task id=0x3 name="e1000-rx-poll"
[e1000] self-test TX: 60-byte broadcast marker emitted
[net-probe] vid=0x8086 did=0x100e family=e1000-82540em  (driver online)
```

On a host where tcpdump runs against QEMU's SLIRP interface, the
broadcast frame appears at boot.

## Edge cases / what to remember

- **Ring sizing vs `RDLEN`.** The RDLEN register takes BYTES, not
  descriptors. 256 × 16 = 4096, which matches one frame.
- **Multicast Table Array must be zeroed.** Reset leaves it in an
  undefined state; leaving garbage there can accept random
  multicast frames and flood the RX ring.
- **SECRC (Strip Ethernet CRC) on RX** means the 4-byte FCS isn't
  delivered to software. Length reported in RX descriptor is the
  frame excluding FCS, which is what upper layers want.
- **TX PSP** pads short packets up to 60 bytes on the wire (plus
  4-byte FCS = 64 total). Our 60-byte self-test sits exactly at
  that boundary.
- **Contiguous-frame allocator dependency.** The 512 KiB RX/TX
  buffer pools require `AllocateContiguousFrames(128)` each. Both
  allocations succeed on a fresh 2 GiB QEMU boot; on real
  hardware with fragmented physmem this could fail.
- **Classic vs PCIe e1000e.** We gate by device ID range. An i210
  or 82574 has the same STATUS / RAL / RAH layout but different
  PHY / EEPROM paths — probing them the same way is harmless
  (`ProbeE1000State` just reads the MAC) but they won't come up
  as a driver until the PHY access gets added.

## See also

- `xhci-hid-keyboard-v0.md` / `nvme-driver-v0.md` — sibling drivers
  that share the "allocate contiguous DMA buffers, spawn a polling
  task" pattern.
- `kernel/arch/x86_64/traps.h` — `IrqAllocVector` is ready when
  this driver's MSI-X slice lands.
