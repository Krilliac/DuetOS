# Networking Drivers

> **Audience:** Driver authors, net stack hackers
>
> **Execution context:** Kernel — bounded polling workers for current PCI v0 paths; IRQ/worker delivery for USB
>
> **Maturity:** v0 Intel e1000/e1000e + AMD PCnet + modern virtio-net + USB CDC-ECM + USB RNDIS; PCI wireless is inventory-only

## Overview

Several NIC paths feed the same kernel net stack today:

| Driver | Path | Maturity |
|--------|------|----------|
| Intel e1000 / e1000e (wired) | `kernel/drivers/net/net.cpp` | v0 — packet-I/O profiles enabled only for QEMU identities `8086:100E` and `8086:10D3`; restart QEMU proof pending |
| AMD PCnet (wired) | `kernel/drivers/net/pcnet.cpp` | v0 — exact `1022:2000` profile with restart-safe polled packet I/O; QEMU runtime proof pending |
| virtio-net (wired) | `kernel/drivers/virtio/virtio_net.cpp` | v0 — modern `1AF4:1041` capability transport with restart-safe polled packet I/O; transitional `1AF4:1000` is inventory-only; QEMU runtime proof pending |
| USB CDC-ECM | `kernel/drivers/usb/cdc_ecm.cpp` | v0 — control + data plane |
| USB RNDIS | `kernel/drivers/usb/rndis.cpp` | v0 — control + data plane |
| Intel / Realtek / Broadcom / MediaTek PCI wireless | `kernel/drivers/net/{iwlwifi,rtl88xx,bcm43xx,mt76}.cpp` | inventory candidates only — all functional/MMIO gates closed |
| ath9k_htc (USB wireless) | `kernel/drivers/net/ath9k_htc.cpp` | shell — open-firmware upload |

The e1000 classifier recognizes exact classic/e1000e inventory families, but
full register bring-up is deliberately narrower: `8086:100E` (QEMU
`-device e1000`) and `8086:10D3` (QEMU `-device e1000e`) are the only enabled
functional profiles. Other family members remain inventory-only until their
reset, media, PHY, interrupt, and DMA contracts are verified. AMD PCnet's exact
`1022:2000` profile now uses the same generation-owned stack binding,
operation gate, worker join, DMA-synchronization, and bus-master shutdown proof
as e1000. Modern virtio-net `1AF4:1041` is activated on the registry-assigned
interface only after its staged PCI transport has been revalidated by exact BDF
and capability/BAR fingerprint. Other AMD NIC identities and transitional
virtio-net `1AF4:1000` remain inventory-only.

## PCI-ID classification (`nic_ids.h`)

All device-ID → family classification lives in
`kernel/drivers/net/nic_ids.h` — a freestanding, constexpr,
host-tested header. Candidate classification feeds inventory and UI labels;
separate backend-match and safe-probe gates control hardware access. Key
properties, pinned by `tests/host/test_nic_ids.cpp` and
`tools/test/test-nic-id-classification-contract.py`:

- **The e1000 family classifiers are explicit ID allow-lists**, not
  ranges, while the functional gate contains only `100E` and `10D3`.
  Intel's igb (82575/I210/I350), igc (I225/I226), ixgbe
  (82598/82599/X540/X550) and i40e (X710) device IDs interleave with
  the e1000e ID space; those families use queue-based ring register
  files at different offsets and must never receive e1000 register
  writes. They classify to their own inventory-only family tags. Unknown
  Intel IDs also stay inventory-only — the safe failure mode is "no
  driver", never "wrong-register writes".
- **Wireless candidate tags identify upstream backends**, not operational
  drivers. Realtek's 33 current PCI candidates split into `rtlwifi`, `rtw88`,
  and `rtw89`; rtl8192se uses BAR1 while the other current Realtek PCI modules
  use BAR2. BAR choice remains metadata while the safe-probe gates are closed.
- **Broadcom cannot be flattened by device ID.** The exact 65-ID inventory
  spans b43/SSB, BCMA, and brcmfmac. Raw `4355` requires subsystem
  `14E4:4355`; raw `4365` selects brcmfmac for `14E4:4365` or BCMA for its
  exact Dell/Foxconn/HP tuples. BAR0 is a windowed backplane aperture, not a
  fixed ChipCommon register block; the current generic BAR0 shell has no safe
  probe-eligible device.
- Every accepted ID needs a corresponding upstream `pci_device_id` row or a
  vendor datasheet. Do not inflate support with numeric ranges.

## AMD PCnet (Wired, Restart-Safe v0)

`kernel/drivers/net/pcnet.cpp`. Am79C970A / Am79C973 (PCI 1022:2000).

- Bring-up admits only the exact `1022:2000` identity and a valid I/O BAR,
  keeps PCI bus mastering disabled until coherent rings, the exact stack
  binding, and the worker lease are ready, then enables SWSTYLE 2 DMA.
- RAP/RDP access and TX publication are independently serialized. RX validates
  fragment/error/FCS bounds before injecting through its exact-generation
  `NetInterfaceBinding`; CSR0 runtime causes use explicit write-one-to-clear
  values and never echo control/status reads.
- Shutdown closes new operations, retires and joins the exact poll-worker
  generation, drains the stack receipt, proves STOP with RXON/TXON clear,
  disables bus mastering, restores the safe PCI command value, and only then
  frees DMA. A failed proof retains the context and reports Busy so a later
  `NetShutdown` can retry the quarantine.
- Strict MSVC and Clang sanitizer hosted tests cover descriptor rules, gate and
  lease races, TX reclaim, CSR0 semantics, and teardown ordering. A focused
  QEMU `-device pcnet` restart smoke is still required before claiming runtime
  readiness on the emulator or physical Am79C97x hardware.

## USB Network (CDC-ECM + RNDIS)

USB-attached Ethernet adapters present through xHCI. Both path types
register a netif identical in interface to the PCnet one — the net
stack does not know whether packets came from PCIe or USB.

See [USB](USB.md) for the class-driver details.

## Wireless Driver Shells

Firmware source classification, open-firmware candidates, and closed-blob handling are tracked in [Wireless and GPU Firmware Research](Wireless-Firmware.md).


The wireless sources live as flat files under `kernel/drivers/net/`
(`iwlwifi.cpp`, `rtl88xx.cpp`, `bcm43xx.cpp`, `mt76.cpp`,
`ath9k_htc.cpp`). PCI candidate identification is wired into inventory, but
the four PCI hardware shells fail closed before BAR mapping or MMIO:

- **iwlwifi** (Intel Wi-Fi, PCIe)
- **rtl88xx** (Realtek, PCIe)
- **bcm43xx** (Broadcom, PCIe)
- **mt76** (MediaTek MT7615/7663/7915/7916/7921/7922/7925/7927 PCIe
  candidates, including exact companion-function and alternate-vendor rows)
- **ath9k_htc** (Qualcomm Atheros AR9271 / AR7010, USB — the
  canonical open-firmware Wi-Fi target; firmware is uploaded over
  USB control transfers via the `core::FwLoad` path)

Offline parsers, 802.11 frame helpers, crypto/MLME scaffolds, ring structures,
and self-tests exist, but they are not evidence of a functional PCI driver.
No PCI wireless candidate is marked online, mapped for the dormant shell, or
authorized to upload firmware. A backend becomes functional only after its
full PCI identity, BAR/core enumeration, firmware, DMA, interrupt, and shutdown
contracts are implemented and verified — see
[Roadmap](../reference/Roadmap.md#wireless--real-hardware-verification).

## Network Stack

The kernel net stack (`kernel/net/`) sits above the netif interface
and is shared by every driver above. See
[Network Stack](../networking/Network-Stack.md).

Shell commands `ifconfig`, `dhcp`, `route`, `netscan`, `net` exercise
the stack from the kernel shell — see [Shell Commands](../reference/Shell-Commands.md).
The taskbar's bottom-right network flyout exposes the same status
through a hover-preview popup.

## Known Limits / GAPs

- **Wireless data plane on live silicon** is not implemented — PCI candidates
  are inventory-only and the dormant per-vendor shells do not access hardware.
  A full software data plane (GCMP-128
  802.11 ↔ 802.3 bridged into the IP stack, DHCP + ping over the
  encrypted link) is functional against the fake-AP loopback harness;
  see [Wireless 802.11](Wireless-80211.md).
- **No NIC bonding / failover**.
- **RNDIS bulk concurrency**: control plane is fine; bulk RX/TX
  serialization gap — control is single-threaded but RX can race
  with class-side teardown if a host hot-plugs mid-poll.

## Related Pages

- [Driver Overview](Driver-Overview.md)
- [USB](USB.md) — host controller for CDC-ECM and RNDIS
- [Network Stack](../networking/Network-Stack.md)
- [Live Internet Verification](../networking/Live-Internet.md)
