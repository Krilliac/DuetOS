# Networking Drivers

> **Audience:** Driver authors, net stack hackers
>
> **Execution context:** Kernel — IRQ for RX/TX completions, softirq for stack
>
> **Maturity:** v0 e1000 + USB CDC-ECM + USB RNDIS; wireless shells in place

## Overview

Three NIC paths feed the same kernel net stack today:

| Driver | Path | Maturity |
|--------|------|----------|
| Intel e1000 (wired gigabit) | `kernel/drivers/net/e1000/` | v0 — real packet I/O |
| USB CDC-ECM | `kernel/drivers/usb/class/cdc-ecm/` | v0 — control + data plane |
| USB RNDIS | `kernel/drivers/usb/class/rndis/` | v0 — control + data plane |
| iwlwifi / rtl88xx / bcm43xx (wireless) | `kernel/drivers/net/wireless/` | shell only — chip-id bringup |

## Intel e1000 (Wired)

`kernel/drivers/net/e1000/`.

- TX and RX descriptor rings programmed against MMIO registers.
- IRQ-driven completion path (RXT0 / TXDW).
- Real packet I/O: DHCP, ARP, ICMP, TCP all live on this path.
- Used as the default for QEMU smoke tests (`-netdev user,model=e1000`).

## USB Network (CDC-ECM + RNDIS)

USB-attached Ethernet adapters present through xHCI. Both path types
register a netif identical in interface to the e1000 one — the net
stack does not know whether packets came from PCIe or USB.

See [USB](USB.md) for the class-driver details.

## Wireless Driver Shells

`kernel/drivers/net/wireless/`. Three families have chip-identification
scaffolding wired in:

- **iwlwifi** (Intel Wi-Fi)
- **rtl88xx** (Realtek)
- **bcm43xx** (Broadcom)

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

- **Wireless data plane** is not implemented — only chip discovery.
- **No NIC bonding / failover**.
- **RNDIS bulk concurrency**: control plane is fine; bulk RX/TX
  serialization gap — control is single-threaded but RX can race
  with class-side teardown if a host hot-plugs mid-poll.

## Related Pages

- [Driver Overview](Driver-Overview.md)
- [USB](USB.md) — host controller for CDC-ECM and RNDIS
- [Network Stack](../networking/Network-Stack.md)
- [Live Internet Verification](../networking/Live-Internet.md)
