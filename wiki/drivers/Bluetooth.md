# Bluetooth (HCI)

> **Audience:** Driver authors, networking / radio stack contributors
>
> **Execution context:** Kernel — codec is pure (no IO); transport not yet
> wired
>
> **Maturity:** v0 — HCI command/event codec functional; no transport, no
> ACL/SCO data paths

## Overview

Bluetooth on DuetOS lives at [`kernel/net/bluetooth/`](../../kernel/net/bluetooth/).
The v0 surface is intentionally narrow: a **pure** HCI packet codec
(serialise commands, parse events) and a small diagnostic ring. The
transport (UART, USB, integrated radio over PCI) is not yet wired —
you can build and link the codec into the kernel today, but no real
adapter speaks to it.

That sequencing is deliberate. The HCI codec is the smallest surface
that's worth verifying end-to-end (against test vectors from the
spec); once it's stable, adding a transport is a matter of routing
bytes, not designing a packet format.

```
   userland radio control       (not yet wired)
              |
       HCI command codec  ----  kernel/net/bluetooth/hci.{h,cpp}
              |
       (transport TBD)          USB HCI / UART / integrated PCI controller
              |
              v
          Bluetooth radio
```

## File Layout

| File | Purpose |
|------|---------|
| [`hci.h`](../../kernel/net/bluetooth/hci.h) / `.cpp` | HCI packet codec |
| [`diag.h`](../../kernel/net/bluetooth/diag.h) / `.cpp` | Diagnostic ring — every packet in/out gets a one-liner |
| [`hid.h`](../../kernel/net/bluetooth/hid.h) / `.cpp` | HID keyboard upper stack — ACL reassembly + L2CAP + ATT-HOGP / HIDP → input queue |
| [`../../drivers/usb/btusb.h`](../../kernel/drivers/usb/btusb.h) / `.cpp` | USB Bluetooth transport driver — EP0 HCI commands + bulk-IN ACL RX pump |
| [`../hci_rust/`](../../kernel/net/hci_rust/) | Rust crate for the H4 framing layer (the byte-on-the-wire wrapper) |

## HCI Packet Codec

[`hci.h`](../../kernel/net/bluetooth/hci.h) implements the Bluetooth
HCI command/event packet structure (Core Spec Vol 4 Part E).

### Packet types

- **Command** (`HCI_COMMAND_PKT = 0x01`) — host → controller. 3-byte
  header (`OpCode` low / high / parameter length), then parameter bytes.
  The `OpCode` is composed of OGF (6 bits) + OCF (10 bits).
- **Event** (`HCI_EVENT_PKT = 0x04`) — controller → host. 2-byte
  header (`event code`, `parameter length`), then parameter bytes.
- **ACL** (`HCI_ACLDATA_PKT = 0x02`) — bidirectional data. 4-byte
  header (handle + flags + length). Not parsed in v0.
- **SCO** (`HCI_SCODATA_PKT = 0x03`) — bidirectional voice. 3-byte
  header. Not parsed in v0.

### v0 command set

Today's codec serialises and parses the minimum set that's worth
exercising before transport lands:

| Opcode | OGF | OCF | Purpose |
|--------|-----|-----|---------|
| `HCI_Reset` | 0x03 (HCI Control) | 0x0003 | Wake the controller |
| `HCI_Read_Local_Version_Information` | 0x04 (Informational) | 0x0001 | HCI + LMP version dump |
| `HCI_Read_BD_ADDR` | 0x04 | 0x0009 | Read the public BD_ADDR |
| `HCI_LE_Set_Scan_Parameters` | 0x08 (LE Controller) | 0x000B | Configure LE scan |
| `HCI_LE_Set_Scan_Enable` | 0x08 | 0x000C | Start / stop LE scan |

`HCI_LE_Advertising_Report` events are decoded into a fixed-shape
struct so a downstream LE scanner can fold raw bytes into device
inventory without each subsystem re-parsing the TLV report payload.

### Codec contract

The codec is **parser-pure**: no allocations, no transport, no global
state. It serialises into a caller-provided byte buffer and parses out
of a caller-provided byte slice. That makes it directly unit-testable
in the hosted test harness — see [Testing](../advanced/Testing.md).

```cpp
struct HciCommandHeader { u16 opcode; u8 plen; } __attribute__((packed));

// Build
size_t  HciBuildCommand(span<u8> out, u16 opcode, span<const u8> params);

// Parse
Result<HciEventView> HciParseEvent(span<const u8> bytes);
```

`HciEventView` is a span-style view back into the input bytes — no
copies. The caller decides whether to copy out fields it wants to
retain past the input buffer's lifetime.

## Diagnostic Ring

[`diag.h`](../../kernel/net/bluetooth/diag.h) is a fixed-size ring
that captures every HCI packet (in or out) with a 32-byte snapshot,
a direction, and a wall-clock timestamp. The shell command `bt` (when
wired) reads from this ring. The ring is sized for a few seconds of
LE scan traffic; expect older entries to be overwritten on a long
scan.

## HID Keyboard

[`hid.h`](../../kernel/net/bluetooth/hid.h) is the upper stack that
turns a Bluetooth keyboard's ACL traffic into kernel key events —
the layer the HCI codec deferred, scoped to the keyboard workload.

A keystroke's path:

```
HCI ACL packet  →  BtHidDeliverAcl   (transport driver IRQ ingress)
  └─ per-connection fragment reassembly (ACL PB flag)
     └─ L2CAP B-frame  {len, CID, payload}
        ├─ CID 0x0004  → ATT  : Handle Value Notification → HID report  (BLE HOGP)
        │                       Handle Value Indication   → HID report
        │                         + ATT Handle Value Confirmation (0x1E)
        │                           pushed back via BtHidSetAclSink egress
        └─ dynamic CID → HIDP : DATA/Input transaction      → HID report  (classic)
     └─ 8-byte boot keyboard report (optional Report-ID prefix stripped)
        └─ drivers::input::HidKeyboardDiffAndInject
           (the SAME decoder + inject queue USB HID uses)
```

The ACL egress is symmetric to the ingress: `BtHidSetAclSink`
registers the transport's bulk-OUT submit (btusb wires
`AclTxSink` at bring-up). The HID layer uses it only to answer
every received ATT Handle Value Indication with the 1-byte
Confirmation the GATT server stalls on until it arrives — the
confirmation is built and submitted outside the connection-table
spinlock.

The connection table is bounded (`kBtHidMaxConnections`) and keyed
on the 12-bit ACL handle. `BtHidRegisterLeKeyboard` /
`BtHidRegisterClassicKeyboard` are called when a keyboard
connection comes up; `BtHidUnregister` on Disconnection_Complete.
The `bt` shell command lists live HID keyboard connections and
their report counts.

The whole chain is end-to-end self-tested at boot
(`[bt-hid] selftest pass`): synthetic ACL packets exercise BLE
notification, classic HIDP, fragmented L2CAP reassembly, and the
Report-ID strip; KeyEvents are captured rather than injected so the
boot input stream stays clean. See
[Input](Input.md#bluetooth-hid-keyboard) for the consumer side.

**Transport driver.** The btusb USB transport driver
([`../../kernel/drivers/usb/btusb.{h,cpp}`](../../kernel/drivers/usb/btusb.cpp))
finds the USB Bluetooth controller, parses its endpoints,
configures the bulk + interrupt-IN endpoints, registers a diag
adapter, sends the HCI identity bring-up commands over EP0, and
runs two RX pumps: bulk-IN → `BtHidDeliverAcl` (the keyboard data
path) and interrupt-IN → HCI event processing (diag ring +
adapter stamping from the Command_Complete answers,
Disconnection_Complete → `BtHidUnregister`). The interrupt-IN
xHCI primitive is additive — independent `DeviceState` fields +
functions — so no bulk/HID/EP0 caller is perturbed. Like
`CdcEcmProbe` it is not auto-claimed at boot (event-ring race;
see the CdcEcmProbe note in `kernel/core/main.cpp`); invoked on
demand via the `bt probe` shell command. **The remaining gap is
the connection manager** — LE scan/connect, SMP pairing, GATT
(HOGP) discovery — a deliberate SMP-gated frontier (see
[Known Limits](#known-limits--gaps)). Once a link is up and a
keyboard registered, the ACL→keystroke path is fully real and
self-tested.

## H4 Framing — `hci_rust` Crate

[`kernel/net/hci_rust/`](../../kernel/net/hci_rust/) is a small Rust
crate that implements the H4 transport framing — the one-byte type
indicator (`0x01..0x04`) plus length-prefixed payload. The choice
to do that in Rust was the same as for [ACPI decoders](../kernel/ACPI.md):
bytes-from-untrusted-source where memory safety matters more than
C++ ergonomics. See [Rust Subsystems](../tooling/Rust-Subsystems.md).

The C++ codec hands the Rust framer raw transport bytes; the Rust
framer returns "here is one complete H4-framed HCI packet" or "more
bytes please" without ever exposing partial state to the kernel C++.

## Threading and Locking

- The codec is stateless and reentrant. Any thread can build and parse
  packets concurrently as long as each has its own buffer.
- The diagnostic ring uses a single-writer-per-direction pattern: the
  transport thread is the writer; readers (shell, GDB) are lockless
  via the ring's tail counter.
- When transport lands it will own a worker thread for command
  flow-control (the controller's command-credits model). Expect that
  worker thread to be the only thread touching the controller MMIO /
  USB endpoint.

## Capability Gates

The HCI codec has no gate (pure arithmetic). Once transport lands,
admin operations (powering the radio on, scanning, pairing) will be
gated through a new `kCapBluetooth` (proposed) or fold into
`kCapNetAdmin` if the policy team prefers a coarser bundle. The
choice is tracked in
[Roadmap](../reference/Roadmap.md#bluetooth-cap-gate).

## Known Limits / GAPs

- **No connection manager (SMP-gated).** The btusb driver
  ([`../../drivers/usb/btusb.cpp`](../../kernel/drivers/usb/btusb.cpp))
  brings the controller up, runs a real bulk-IN ACL RX pump, and
  drains the HCI **event** interrupt-IN endpoint (diag stamping
  from the Command_Complete bring-up answers,
  Disconnection_Complete → `BtHidUnregister`). What is *not* done:
  LE scan/connect, **SMP pairing/bonding**, and GATT (HOGP)
  service discovery — so a real BT keyboard cannot associate on
  its own yet. This is a deliberate frontier gated on the
  project's standing decision to defer SMP (see
  [Design-Decisions](../reference/Design-Decisions.md)); it is a
  multi-slice, security-critical effort unprovable on a host with
  no radio. No UART/SDIO transport. On a host with no BT hardware
  the driver no-ops; every layer is boot self-tested.
- **ACL data path: keyboard only.** [`hid.h`](../../kernel/net/bluetooth/hid.h)
  reassembles ACL fragments and decodes L2CAP B-frames for the HID
  keyboard path. No SCO (voice) path; no other ACL consumer.
- **L2CAP / GATT: HID slice only.** L2CAP B-frame decode + ATT
  Handle Value Notification / Indication (BLE HOGP; an Indication
  is answered with an ATT Handle Value Confirmation through the
  transport ACL egress sink) + classic HIDP DATA/Input are
  implemented for keyboards. No L2CAP signalling channel, no
  GATT service discovery (the report handle is supplied at
  connection setup), no RFCOMM, no SDP.
- **No pairing / SMP.** The Security Manager Protocol is not yet
  modelled — a production keyboard bonds first; the HID path
  decodes the post-connection report stream and trusts the link.
- **Vendor-specific opcodes** (Broadcom, Intel) deferred — the codec
  doesn't pretend to know vendor-specific TLVs.
- **LE Extended Advertising** (5.x): plan-of-record, but the v0 codec
  decodes only the legacy advertising report.

## Related Pages

- [Networking Drivers](Networking-Drivers.md) — overall NIC + radio
  driver story
- [Wireless Firmware](Wireless-Firmware.md) — for the radio-side
  firmware loading model (Bluetooth radios often share a firmware
  source with Wi-Fi)
- [WiFi Onboarding](WiFi-Onboarding.md) — the analogous user flow
  once Bluetooth pairing lands
- [Rust Subsystems](../tooling/Rust-Subsystems.md) — `hci_rust` crate
- [Roadmap](../reference/Roadmap.md) — Bluetooth transport + cap gate
