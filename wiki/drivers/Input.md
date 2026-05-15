# Input

> **Audience:** Driver authors, compositor / shell authors
>
> **Execution context:** Kernel — IRQ for key/button events
>
> **Maturity:** PS/2 v0 + USB HID boot keyboard v0 + Bluetooth HID
> keyboard v0 (decode path; transport driver pending)

## Overview

DuetOS routes input events from the device drivers through a small
input subsystem into the kernel shell and the focused compositor
window.

```
[ HW: PS/2 controller / USB keyboard / Bluetooth keyboard ]
        |  IRQ
[ Driver: ps2 / xhci+hid / bluetooth (L2CAP→ATT-HOGP|HIDP) ]
        |
[ Boot-report decoder ]            kernel/drivers/input/hid_keyboard.{h,cpp}
        |   (shared by USB + Bluetooth — one usage→KeyEvent table)
[ Input event queue ]              kernel/drivers/input/ (KeyboardInjectEvent)
        |
[ Kernel shell + Compositor focused window ]
```

PS/2 feeds the queue through its scancode decoder; USB HID and
Bluetooth HID both feed it through the shared boot-protocol decoder
in `kernel/drivers/input/hid_keyboard.{h,cpp}`, so a runtime layout
switch and the press/release/modifier semantics are identical
regardless of which bus carried the key.

## PS/2 Keyboard v0

`kernel/drivers/input/ps2/`.

- Legacy 8042 controller IRQ-driven path.
- Scancode -> keycode translation with the standard set-2 mapping.
- The first end-to-end IRQ-driven driver in the kernel (predates xHCI).

Used as the default input device when `-machine` doesn't expose USB
HID (e.g. some legacy QEMU configurations).

The PS/2 driver also runs an in-driver scan-code-set-1 → ASCII
translator over the existing raw byte ring. `Ps2KeyboardReadChar`
drains scan codes in task context, handles make/break edges, tracks
LShift/RShift + Caps Lock, consumes 0xE0-prefixed extended scans
silently, and returns only on a real press resolving to a printable
US-QWERTY character. The IRQ path and `Ps2KeyboardRead` (raw bytes)
remain untouched for any future consumer that needs set-2 decoding,
debugger-side view, or alternate keymap.

## USB HID Boot Keyboard

xHCI interrupt-IN poll (`kernel/drivers/usb/xhci_init.cpp`
`HidPollEntry`).

- 8-byte boot-protocol HID report handed to the shared decoder
  `duetos::drivers::input::HidKeyboardDiffAndInject`
  (`kernel/drivers/input/hid_keyboard.{h,cpp}`).
- Routes events into the same queue PS/2 uses.

## Bluetooth HID Keyboard

`kernel/net/bluetooth/hid.{h,cpp}`.

- Single ACL ingress `BtHidDeliverAcl` for a (future) btusb/btuart
  transport driver's IRQ path. Performs per-connection L2CAP
  fragment reassembly, B-frame decode, then routes by CID:
  - **BLE HOGP** (CID 0x0004 → ATT): a Handle Value Notification /
    Indication carrying the HID Input report.
  - **Classic HID** (dynamic CID → HIDP): a DATA/Input transaction
    carrying the report.
- The normalised 8-byte boot report (optionally one Report-ID
  prefix byte) goes through the *same* shared decoder USB HID uses
  — one source of truth for usage→KeyEvent, one inject queue.
- Bounded connection table keyed on the 12-bit ACL handle;
  register on connection-up, unregister on Disconnection_Complete.
- End-to-end self-tested at boot (`[bt-hid] selftest pass`):
  synthetic ACL packets for BLE notification, classic HIDP,
  fragmented reassembly, and Report-ID strip, with KeyEvents
  captured (not injected) so the boot input stream stays clean.

The btusb transport driver
(`kernel/drivers/usb/btusb.{h,cpp}`, invoked via the `bt probe`
shell command) is the real producer: it finds the USB Bluetooth
controller, configures the bulk + interrupt-IN endpoints, sends
HCI bring-up commands over EP0, and runs two RX pumps — bulk-IN
ACL into `BtHidDeliverAcl`, and interrupt-IN HCI events into the
diag layer / connection teardown.

GAPs (documented limits, not stubs): no connection manager (LE
scan/connect + SMP pairing + GATT-HOGP discovery — an SMP-gated
frontier), and only the boot keyboard report map is decoded. Once
a link is up the ACL→keystroke path is live and self-tested.

## Mouse

PS/2 mouse handling is wired alongside the keyboard. USB HID mouse is
planned but not yet implemented.

## Compositor Routing

The compositor's focused window receives keyboard + mouse events
via `SYS_WIN_*` message-pump syscalls. The kernel kbd-reader and
mouse-reader in `kernel/core/main.cpp` post `WM_KEYDOWN` /
`WM_SYSKEYDOWN` / `WM_KEYUP` / `WM_SYSKEYUP` / `WM_CHAR` /
`WM_SYSCHAR` (Alt held flips KEYDOWN/KEYUP/CHAR to their SYS
variants and sets lParam bit 29) plus `WM_MOUSEMOVE` (0x0200) /
`WM_LBUTTONDOWN` (0x0201) / `WM_LBUTTONUP` (0x0202) /
`WM_LBUTTONDBLCLK` (0x0203) / `WM_MOUSEWHEEL` (0x020A) to the
focused PE, with client-coordinate lParam packing. The mouse
route consults `WindowGetCapture()` first so a `SetCapture`d
window keeps receiving events after the cursor leaves.
`SetForegroundWindow` plumbs through `SetActiveWindow` →
`SYS_WIN_SET_ACTIVE` → `WindowRaise` and rewrites the active
window. See [Compositor](../subsystems/Compositor.md) §"Window
Chrome Interactions" for the full chrome-press dispatch.

## Known Limits / GAPs

- **No USB HID mouse driver yet.**
- **No raw input** API (`Win32 GetRawInputData`) — the few PEs that
  use it fall back to the message-pump path.
- **Bluetooth connection manager not yet implemented** — the
  btusb transport driver (`bt probe`) brings up the controller,
  pumps ACL into the keyboard stack, and processes HCI events
  (identity stamping, disconnect teardown). What is missing is LE
  scan/connect + SMP pairing + GATT-HOGP discovery, so a real BT
  keyboard can't yet associate on its own — a deliberate SMP-gated
  frontier. Once a link is up the full ACL→keystroke decode is
  live and self-tested. See [Bluetooth](Bluetooth.md#hid-keyboard).
- **No IME / non-Latin layouts** — PS/2 + xHCI HID drivers
  hardcode US layout. See
  [Roadmap](../reference/Roadmap.md#ime--non-latin-input).

## Related Pages

- [Driver Overview](Driver-Overview.md)
- [USB](USB.md)
- [Bluetooth](Bluetooth.md) — HID keyboard upper stack
- [Compositor and Window Manager](../subsystems/Compositor.md)
