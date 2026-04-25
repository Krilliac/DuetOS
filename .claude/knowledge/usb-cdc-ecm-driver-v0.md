# USB CDC-ECM driver + xHCI bulk-transfer API (v0)

**Last updated:** 2026-04-25
**Type:** Observation + Decision
**Status:** Active (not auto-probed at boot yet — see below)

## Description

First USB-networking class driver on DuetOS. Targets standards-compliant
**CDC-ECM** (USB Communications Device Class — Ethernet Networking
Control Model): the USB-IF standard for Ethernet-over-USB. Works with
iPhone USB tethering (Apple Mobile Device Ethernet is CDC-ECM-shaped),
Linux-gadget `g_ether` devices, and premium USB-Ethernet dongles from
Anker / StarTech / Plugable that implement the ECM model.

Does **NOT** match QEMU's `-device usb-net` — QEMU ships only an RNDIS
(Microsoft Remote NDIS) emulation, with no `rndis=off` property in the
current build. Android phones default to RNDIS too. RNDIS is a
separate class driver slice.

## Scope

### Covered

- **xHCI public bulk-transfer API** (`kernel/drivers/usb/xhci.h`):
  - `XhciFindDeviceByClass(class, subclass)` — find addressed slot by
    device-descriptor class/subclass (wildcards via 0xFF).
  - `XhciEnumerateDevices(out, max)` — all addressed slot_ids; the
    fallback for devices that declare class at the interface level.
  - `XhciControlIn(slot, rt, req, val, idx, buf, len)` + `ControlOut`
    — generic vendor / class / standard control transfers on EP0.
  - `XhciConfigureBulkEndpoint(slot, ep_addr, max_packet)` —
    allocate a bulk transfer ring + run Configure Endpoint.
  - `XhciBulkSubmit(slot, ep_addr, buf_phys, len)` — enqueue a
    Normal TRB and ring the endpoint doorbell; returns the TRB
    phys pointer.
  - `XhciBulkPoll(slot, ep_addr, trb_phys, out_bytes, timeout_us)` —
    wait for the Transfer Event; write bytes-actually-transferred.
  - `XhciPauseEventConsumer(bool)` — gate the HID poll task's
    event-ring drainer while a class driver runs synchronous
    transfers. See "Known issues" below.
- **DeviceState extension**: per-device bulk_in / bulk_out
  endpoint rings (phys, virt, slots, idx, cycle, MPS, DCI). One
  pair per device — enough for every USB-net class in scope.
- **Unconditional publish of `g_poll_rt[idx]`** after xHCI
  enumeration. Previously set only inside the HID-present branch;
  a USB-net-only board left it zeroed, so every user-issued
  `WaitEvent` polled a nullptr ring and timed out.
- **CDC-ECM class driver** (`kernel/drivers/usb/cdc_ecm.cpp/h`):
  - Config-descriptor parser that walks the full descriptor tree
    for a CDC Data interface (class 0x0A) with `bAlternateSetting=1`,
    its bulk IN + bulk OUT endpoints, and the CDC Ethernet
    Functional Descriptor (subtype 0x0F) for the MAC string index.
  - String-descriptor decoder for the 12-char ASCII-hex MAC in
    `iMACAddress` (UTF-16LE encoded, ASCII-hex content).
  - Bring-up sequence: SET_CONFIGURATION → SET_INTERFACE 1 →
    Configure bulk-IN + bulk-OUT → SET_ETHERNET_PACKET_FILTER
    (DIRECTED | BROADCAST | ALL_MULTICAST).
  - DMA buffers (one page RX, one page TX) for bulk transfers.
  - Network-stack bind as `iface 1`; spawns `cdc-ecm-rx` poll
    task; kicks off DHCP.

### Known issues / NOT in scope

- **Auto-probe regresses e1000 DHCP.** Calling `CdcEcmProbe()` from
  `kernel_main` after `XhciInit` breaks the wired e1000 NIC's DHCP
  exchange even when no CDC-ECM device is attached (the probe
  enumerates slots, runs a few control transfers on EP0, fails to
  match, and returns — but the e1000 RX polling task stops
  delivering frames afterwards). Reproduced with both `-device
  e1000` and `-device e1000e`. Root cause not isolated yet;
  strongly suspect a timing / event-ring interaction with the
  not-yet-spawned HID poll task's dormant state. Workaround: the
  probe is **not auto-called at boot** in v0. Invoke manually from
  a shell command or a kernel thread once a real CDC-ECM device is
  attached.
- **RNDIS class driver.** QEMU `-device usb-net` is RNDIS. Android
  phones default to RNDIS. Implementing RNDIS (control-EP
  message-passing protocol: INITIALIZE / QUERY / SET / packet
  framing over bulk) is the biggest remaining gap for "USB tether
  actually works." ~400 lines on top of the existing xHCI bulk
  surface.
- **CDC-NCM class driver.** iPhones beyond the ECM model (newer iOS
  tethering), some Wi-Fi 6 routers. Similar shape to ECM but
  packet-aggregated into NTBs (NCM Transfer Blocks).
- **Multi-device USB-net coexistence.** The current event-ring
  consumer (`HidPollEntry`) is not TRB-dispatched — it drains every
  event in a single loop. A proper router that dispatches
  Transfer Events to waiters by TRB pointer is needed before
  multiple class drivers (HID keyboard + USB-Ethernet dongle +
  USB-Wi-Fi) can coexist. Today the CDC-ECM probe works around it
  with `XhciPauseEventConsumer(true)` kept asserted after a
  successful bring-up.
- **AX88179 / AX88772 / LAN78xx / RTL8152** — vendor-specific
  USB-net chips. Each is a separate class driver roughly the size
  of CDC-ECM.

## Integration points

- `kernel/drivers/usb/xhci.h` — new public API surface.
- `kernel/drivers/usb/xhci.cpp` — `DeviceState` bulk fields,
  `ControlOutWithData` internal helper, public API
  implementations, `g_event_consumer_paused` flag, unconditional
  `g_poll_rt` publish.
- `kernel/drivers/usb/cdc_ecm.cpp/h` — class driver.
- `kernel/drivers/usb/usb.h` — no change required (class-driver
  registration table remains a v0 stub).
- `kernel/CMakeLists.txt` — `cdc_ecm.cpp` added to the kernel
  source list.
- `kernel/core/main.cpp` — `#include "../drivers/usb/cdc_ecm.h"`
  added; the `CdcEcmProbe()` call is **commented out** pending
  the auto-probe regression fix (see Known issues).

## Observable

Boot log (with a real CDC-ECM device attached — not QEMU usb-net):

```
[xhci] enumeration: addressed=1 descriptors=1 configs=1 ...
[cdc-ecm] online slot=0x2 mac=aa:bb:cc:dd:ee:ff
                   bulk_in=0x82/0x40 bulk_out=0x02/0x40
[net-stack] iface 1 bound ip=0.0.0.0...
[sched] created task id=X name="cdc-ecm-rx"
[dhcp] DISCOVER sent  (iface 1)
[dhcp] ACK bound ip=192.168.1.42 router=192.168.1.1 ...
```

The e1000 wired path at iface 0 continues to work end-to-end with
the full net-smoke test (ICMP gateway, DNS www.google.com, HTTP GET
to Google's edge returning HTTP 426 Upgrade Required). See
`live-internet-connectivity-v0.md` for that transcript.

## Edge cases / what to remember

- **QEMU's usb-net is RNDIS.** `qemu-system-x86_64 -device
  usb-net,help` shows no `rndis` property, meaning this build
  only offers RNDIS. Writing RNDIS is the only way to live-test
  USB-net in QEMU without passthrough.
- **The CDC Ethernet Functional Descriptor is mandatory.** CDC-ECM
  devices MUST advertise subtype 0x0F carrying the `iMACAddress`
  string-descriptor index. Without it we cannot learn the MAC and
  the driver refuses to bind. Some near-ECM devices (simplified
  gadgets) skip this; they fail CDC-ECM compliance and need a
  vendor driver.
- **Alt setting 1 is mandatory.** Real CDC-ECM splits the data
  interface into alt 0 (no endpoints) + alt 1 (bulk IN + OUT).
  Devices that put bulk endpoints on alt 0 are not compliant.
- **The `XhciPauseEventConsumer` lock.** v0 leaves it asserted
  for the lifetime of the CDC-ECM RX task — safe only on boards
  with no HID keyboard/mouse. A TRB-dispatched router removes
  this limitation.
- **bLength sanity on string descriptors.** iMACAddress as UTF-16LE
  of 12 ASCII hex chars = 24 bytes + 2 header = 26-byte descriptor.
  Some buggy firmware reports more. Decode only the first 12
  characters.

## See also

- `live-internet-connectivity-v0.md` — e1000 wired path that
  proves the network stack works.
- `wireless-drivers-v0.md` — iwlwifi / rtl88xx / bcm43xx shells
  (separate track from USB-net).
- `xhci-hid-keyboard-v0.md` — the HID bring-up that this slice
  generalises.
