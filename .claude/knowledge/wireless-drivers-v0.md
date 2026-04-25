# Wireless driver shells v0 — iwlwifi / rtl88xx / bcm43xx

**Last updated:** 2026-04-25
**Type:** Observation + Decision
**Status:** Active

## Description

First wireless driver work on DuetOS. Closes the long-standing
"netcode gap" where `WirelessStatusRead` always reported
`drivers_online == 0` and the shell `netscan` / GUI net flyout
flatly told the user "no wireless driver online" regardless of
which adapter the chassis carried. After this slice the kernel
identifies real Intel iwlwifi, Realtek rtl88xx, and Broadcom
bcm43xx silicon by reading vendor-specific MMIO chip-ID
registers, marks each NIC `driver_online=true,
firmware_pending=true`, and reports the new state honestly to
both surfaces.

This is **not** a full 802.11 implementation. The kernel has no
firmware-loader subsystem (vendor microcode upload + signing
handshake), no MLME, no scan, no association, no key install.
Every wireless silicon vendor requires firmware before the MAC
will associate, so a v0 driver shell that stops at chip ID is
the most honest unit of work the project can ship before a
firmware-loader slice lands.

## Scope

### Covered

- **`drivers/net/iwlwifi.cpp/.h`** — Intel Wireless. PCI ID
  match table covering the 1000 / 4965 / 5000 / 6000 / 7260 /
  3160 / 7265 / 3165 / 3168 / 8260 / 9000 / AX2xx / Be2xx
  device IDs (Linux iwlwifi `pci_table` mirror). Reads
  `CSR_HW_REV` (BAR0+0x028), `CSR_GP_CNTRL` (0x024), and
  `CSR_INT_COALESCING` (0x004). Logs silicon family from the
  `Type` nibble (bits 7..4 of HW_REV).
- **`drivers/net/rtl88xx.cpp/.h`** — Realtek wireless. PCI ID
  match table covering rtl8723be / rtl8812ae / rtl8813ae /
  rtl8814ae / rtl8821ae / rtl8822be / rtl8852ae. Reads
  `SYS_CFG1` (BAR0+0x00F0), `SYS_CFG2` (0x00FC), and
  `MAC_ID_SETTING` (0x0610). Decodes IC type (bits 7..4) and
  cut version (bits 23..20).
- **`drivers/net/bcm43xx.cpp/.h`** — Broadcom wireless. Match
  range 0x4300..0x43FF + 0x4727 (bcm4313). Reads ChipCommon
  CORE_INFO (BAR0+0x000), `CAPABILITIES` (0x004),
  `CORE_CTL` (0x008), and `STRAP_OPT` (0x010). Decodes ChipID
  (bits 15..0) and ChipRev (bits 19..16) from the CORE_INFO
  dword.
- **`NicInfo` extension** — three new fields: `driver_online`,
  `firmware_pending`, `chip_id`. `e1000` bring-up sets
  `driver_online=true, firmware_pending=false`; the wireless
  shells set both to true.
- **`WirelessStatusRead` rewrite** — `drivers_online` now
  reflects bound wireless shells instead of being hard-coded
  to 0.
- **Vendor classifier expansion** — `IntelNicTag` /
  `RealtekNicTag` / `BroadcomNicTag` widened to cover the new
  device IDs. `iwlwifi` family tag now subdivides into
  `iwlwifi-1000` / `-4965` / `-5000` / `-6000` / `-7260` /
  `-7265` / `-8260` / `-9000` / `-AX2xx` / `-Be2xx`.
- **Per-driver watch task** — each driver spawns a 1 Hz polling
  thread (`iwlwifi-watch` / `rtl88xx-watch` / `bcm43xx-watch`)
  that re-reads the chip-ID register; if the read returns
  `0xFFFFFFFF` the NIC is flipped to `driver_online=false` so
  the GUI's link indicator picks up hot-removal.
- **Shell + GUI honesty** — `CmdNetscan` and the network
  flyout's `DrawWirelessSection` now report
  "shell online (firmware loader pending)" when at least one
  wireless driver shell bound. Distinct from the
  "no driver matched" case (device ID outside our match
  tables).

### Deliberately not in scope

- Firmware loading. Each vendor has its own format
  (iwlwifi: signed `.ucode` with TLV sections;
  rtl88xx: `rtl8xxx*.bin` with section/protection codes;
  bcm43xx: BCM-internal `.fw` blobs + b43 cfg). A separate
  `kernel/core/firmware_loader.cpp` slice is the next
  unblocker.
- 802.11 MLME / scan / association / key install. The kernel
  has no `cfg80211`-equivalent surface; that's an even later
  slice once firmware loading is real.
- TX/RX queue setup. Each silicon family uses a different
  ring layout (iwlwifi: TFD/RBD; rtl88xx: BCN/MGNT/HIGH/NORMAL/
  LOW + RX_DESC; bcm43xx: DMA64 vs PIO depending on chip rev).
  All require firmware-supplied register layouts.
- Power management (D3hot / D0i3 / runtime PM).

## Integration points

- `drivers/net/net.cpp::RunVendorProbe` dispatches to one of
  `IwlwifiBringUp` / `Rtl88xxBringUp` / `Bcm43xxBringUp` after
  the e1000 path, gated by per-driver `*Matches` predicates.
  At most one wireless driver fires per NIC (vendor IDs are
  disjoint).
- `drivers/net/net.cpp::WirelessStatusRead` counts
  `g_nics[i].driver_online` over the wireless subset; replaces
  the hard-coded `drivers_online = 0`.
- `kernel/CMakeLists.txt` lists the three new `.cpp` files in
  `DUETOS_KERNEL_SHARED_SOURCES`.
- `core/shell.cpp::CmdNetscan` reads `WirelessStatusRead` and
  branches its message between "shell online (fw pending)" and
  "no driver matched".
- `drivers/video/netpanel.cpp::DrawWirelessSection` adds a
  three-line layout (count + shell-status + firmware-pending
  hint) when `drivers_online > 0`. Height computation in
  `ComputeFullHeight` bumped from 2 wireless rows to 3.

## Observable

On a dev VM with no real wireless adapter:

```
[net-probe] vid=0x8086 did=0x100e family=e1000-82540em  (driver online)
... no wireless driver fires ...
```

`netscan` → `WIRELESS NETWORKS:  (no wireless adapter detected)`.
GUI flyout → `no wireless adapter`.

On real hardware with an Intel AX200 (vid=0x8086 did=0x2723):

```
[iwlwifi] online pci=00:14.3 did=0x2723 hw_rev=0x340000 \
          gp_cntrl=0x40080000 int_coal=0x10 silicon=AX200/AX201 status=fw-pending
[net-probe] vid=0x8086 did=0x2723 family=iwlwifi-AX2xx  (driver shell online — firmware pending)
[sched] created task id=N name="iwlwifi-watch"
```

`netscan` → `wireless driver shell online for 1 of 1 adapter(s) /
(chip identified + MMIO live; firmware loader pending — cannot scan)`.

## Edge cases / what to remember

- **MMIO BAR sizes vary wildly.** iwlwifi reserves a 0x2000
  BAR; rtl88xx 0x4000 (newer) or 0x2000 (older); bcm43xx
  0x2000 for BAR0 + 0x80000 for BAR2 (SHARED_MEM, not yet
  mapped). The 2 MiB cap in `NetInit` is plenty for v0 BAR0
  use.
- **`0xFFFFFFFF` reads = chip not responsive.** Every shell
  treats an all-ones read of its primary chip-ID register as
  "BAR mapping wrong, or chip in deep sleep without an
  unimplemented wake handshake". The driver bails to
  probe-only state instead of fabricating a chip identity.
  The watch task uses the same signal for hot-removal
  detection.
- **`link_up` stays false on wireless until association.**
  Wired drivers (e1000) read CTRL.SLU + STATUS.LinkUp out of
  the EEPROM; wireless can't until firmware is up + we've
  associated. Forcing it true on wireless would lie to the
  GUI — every wireless `BringUp` explicitly clears it.
- **Vendor classifier ordering.** Intel's iwlwifi range
  overlaps the e1000 family numerically (0x008x is iwlwifi
  6000; 0x0083..0x008B is iwlwifi 1000), so `IntelNicTag`
  routes those to the wireless string and the wireless
  dispatch in `RunVendorProbe` (`IwlwifiMatches`) picks them
  up before the e1000 compatibility prefix gate would.
- **NetShutdown does NOT stop the watch tasks.** This is
  intentional — `NetShutdown` documents that MMIO mappings
  are retained across the cycle, and the watch tasks
  continue polling against the cached `NicInfo*`. When a
  task-reaper API lands (`SchedJoin`?), revisit.

## See also

- `e1000-driver-v0.md` — sibling driver, full I/O. Sets the
  pattern for vendor probes hooked into `RunVendorProbe`.
- `driver-shells-v0.md` — net/usb/audio/gpu probes that share
  the "identify chip + log + leave room for full driver"
  philosophy.
- `network-shell-commands-v0.md` — `netscan` / `wifi`
  command surface that consumes `WirelessStatusRead`.
- `network-flyout-panel-v0.md` — GUI surface that consumes
  `WirelessStatusRead`.
