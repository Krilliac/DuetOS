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

See `.claude/knowledge/e1000-driver-v0.md`.

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

GAP: each is a chip-detection probe today. Real association /
authentication / data plane is deferred — the design plan is
captured in `.claude/knowledge/wireless-drivers-v0.md`.

## Network Stack

The kernel net stack (`kernel/net/`) sits above the netif interface
and is shared by every driver above. See
[Network Stack](../networking/Network-Stack.md).

Shell commands `ifconfig`, `dhcp`, `route`, `netscan`, `net` exercise
the stack from the kernel shell. See
`.claude/knowledge/network-shell-commands-v0.md` and
`.claude/knowledge/network-flyout-panel-v0.md`.

## Known Limits / GAPs

- **Wireless data plane** is not implemented — only chip discovery.
- **No NIC bonding / failover**.
- **RNDIS bulk concurrency**: control plane is fine; bulk RX/TX
  serialization gap documented in
  `.claude/knowledge/usb-rndis-driver-v0.md`.

## Related Pages

- [Driver Overview](Driver-Overview.md)
- [USB](USB.md) — host controller for CDC-ECM and RNDIS
- [Network Stack](../networking/Network-Stack.md)
- [Live Internet Verification](../networking/Live-Internet.md)
