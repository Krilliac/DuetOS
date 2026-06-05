# Networking Drivers

> **Audience:** Driver authors, net stack hackers
>
> **Execution context:** Kernel — IRQ for RX/TX completions, softirq for stack
>
> **Maturity:** v0 AMD PCnet (wired) + USB CDC-ECM + USB RNDIS; wireless shells in place

## Overview

Several NIC paths feed the same kernel net stack today:

| Driver | Path | Maturity |
|--------|------|----------|
| AMD PCnet (wired) | `kernel/drivers/net/pcnet.cpp` | v0 — real packet I/O |
| USB CDC-ECM | `kernel/drivers/usb/cdc_ecm.cpp` | v0 — control + data plane |
| USB RNDIS | `kernel/drivers/usb/rndis.cpp` | v0 — control + data plane |
| iwlwifi / rtl88xx / bcm43xx / mt76 (PCIe wireless) | `kernel/drivers/net/{iwlwifi,rtl88xx,bcm43xx,mt76}.cpp` | shell only — chip-id bringup |
| ath9k_htc (USB wireless) | `kernel/drivers/net/ath9k_htc.cpp` | shell — open-firmware upload |

Intel e1000 / e1000e is a planned Tier-1 target but is **not yet
implemented** — there is no e1000 driver in the tree. The default
wired NIC today is AMD PCnet, which is VirtualBox's default adapter
and QEMU's `-device pcnet`, so a default-config VM gets real wired
networking with no reconfiguration.

## AMD PCnet (Wired)

`kernel/drivers/net/pcnet.cpp`. Am79C970A / Am79C973 (PCI 1022:2000).

- TX and RX descriptor rings in guest memory, driven through the
  RAP/RDP I/O-port register pair (BAR0 is an I/O BAR) in 32-bit
  DWIO mode, SWSTYLE 2.
- Polled RX/TX completion via a per-driver poll task — the emulated
  card flips descriptor OWN bits regardless of interrupt enables, so
  polling is reliable and sidesteps the IRQ-routing surface.
- Real packet I/O: DHCP, ARP, ICMP, TCP all live on this path.
- `PcnetBringUp` runs from `RunVendorProbe` during `NetInit`, binding
  iface 0 to the net stack and kicking off DHCP — the default for
  QEMU / VirtualBox smoke tests.

## USB Network (CDC-ECM + RNDIS)

USB-attached Ethernet adapters present through xHCI. Both path types
register a netif identical in interface to the PCnet one — the net
stack does not know whether packets came from PCIe or USB.

See [USB](USB.md) for the class-driver details.

## Wireless Driver Shells

Firmware source classification, open-firmware candidates, and closed-blob handling are tracked in [Wireless and GPU Firmware Research](Wireless-Firmware.md).


The wireless drivers live as flat files under `kernel/drivers/net/`
(`iwlwifi.cpp`, `rtl88xx.cpp`, `bcm43xx.cpp`, `mt76.cpp`,
`ath9k_htc.cpp`). Five families have chip-identification scaffolding
wired in:

- **iwlwifi** (Intel Wi-Fi, PCIe)
- **rtl88xx** (Realtek, PCIe)
- **bcm43xx** (Broadcom, PCIe)
- **mt76** (MediaTek MT76xx, PCIe — MT7921/7922/7925 ship in the
  majority of recent Ryzen 6000/7000/8000 laptops and current
  Chromebooks)
- **ath9k_htc** (Qualcomm Atheros AR9271 / AR7010, USB — the
  canonical open-firmware Wi-Fi target; firmware is uploaded over
  USB control transfers via the `core::FwLoad` path)

The data-decode tier (per-vendor envelope parsers + 802.11 frame
headers + beacon walker), the control tier (crypto + EAPOL + 4-way
handshake + wdev/MLME + per-vendor upload state machines + ring
scaffolds), DMA-coherent ring allocation, and AES key-wrap for
encrypted M3 KeyData all landed; 13 boot self-tests pass and ~95M
libFuzzer executions completed with zero crashes. Real-hardware
verification (per-vendor MSI/MSI-X IRQ wiring, iwlwifi TFD descriptor
build / doorbell / per-RBD data buffers, MLME runtime correctness) is
roadmap work — see [Roadmap](../reference/Roadmap.md#wireless--real-hardware-verification).

## Network Stack

The kernel net stack (`kernel/net/`) sits above the netif interface
and is shared by every driver above. See
[Network Stack](../networking/Network-Stack.md).

Shell commands `ifconfig`, `dhcp`, `route`, `netscan`, `net` exercise
the stack from the kernel shell — see [Shell Commands](../reference/Shell-Commands.md).
The taskbar's bottom-right network flyout exposes the same status
through a hover-preview popup.

## Known Limits / GAPs

- **Wireless data plane on live silicon** is not implemented — per-vendor
  drivers do chip discovery only. A full software data plane (GCMP-128
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
