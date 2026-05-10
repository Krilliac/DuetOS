# Input

> **Audience:** Driver authors, compositor / shell authors
>
> **Execution context:** Kernel — IRQ for key/button events
>
> **Maturity:** PS/2 v0 + USB HID boot keyboard v0

## Overview

DuetOS routes input events from the device drivers through a small
input subsystem into the kernel shell and the focused compositor
window.

```
[ HW: PS/2 controller / USB keyboard ]
        |  IRQ
[ Driver: ps2 / xhci+hid ]         kernel/drivers/input/ps2/, drivers/usb/class/hid/keyboard/
        |
[ Input event queue ]              kernel/drivers/input/
        |
[ Kernel shell + Compositor focused window ]
```

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

`kernel/drivers/usb/class/hid/keyboard/`.

- 8-byte boot-protocol HID report decoded into key events.
- Routes events into the same queue PS/2 uses.

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
- **No IME / non-Latin layouts** — PS/2 + xHCI HID drivers
  hardcode US layout. See
  [Roadmap](../reference/Roadmap.md#ime--non-latin-input).

## Related Pages

- [Driver Overview](Driver-Overview.md)
- [USB](USB.md)
- [Compositor and Window Manager](../subsystems/Compositor.md)
