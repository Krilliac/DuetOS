# xHCI HID boot keyboard — end-to-end USB keyboard input

**Last updated:** 2026-04-23
**Type:** Observation
**Status:** Active

## Description

Turns the xHCI enumeration stack into real keyboard input. Built on
top of `xhci-enumeration-v0.md` (Address Device + GET_DESCRIPTOR)
and the config-descriptor walk that found a HID/Boot/Keyboard
interface + its interrupt-IN endpoint.

### Pipeline

Per HID keyboard discovered during enumeration, the driver now:

1. `SET_CONFIGURATION(bConfigurationValue)` via a no-data control
   transfer on EP0.
2. Build a Configure Endpoint Input Context that re-describes EP0
   (A1) and adds the HID interrupt-IN endpoint at its DCI (A_dci);
   slot-context Context Entries is raised to the new DCI.
3. Submit Configure Endpoint on the command ring; wait for
   Command Completion.
4. Allocate an interrupt-IN transfer ring (4 KiB, with a trailing
   Link TRB so the producer can wrap without bounds).
5. Enqueue the first Normal TRB pointing at an 8-byte report
   buffer, IOC=1. Ring DB[slot_id] target=DCI.
6. Spawn (once per controller) a `xhci-hid-poll` kernel task that:
   - Drains every currently-valid event from the shared event
     ring.
   - Matches Transfer Events by TRB pointer to a device's
     `hid_outstanding_phys`.
   - Parses the 8-byte HID Boot Keyboard report, diffs it against
     the previous report, and injects KeyEvents for every edge.
   - Re-queues a Normal TRB + rings the endpoint's doorbell.
   - Sleeps one scheduler tick and loops.

### Keyboard event integration

A USB keystroke flows through the **same** KeyEvent pipeline the
PS/2 keyboard uses:

```
HID report → diff → KeyEvent → KeyboardInjectEvent
                                       ↓
                      ring buffer drained by Ps2KeyboardReadEvent
                                       ↓
                      main.cpp kbd-reader → shell / login / apps
```

`KeyboardInjectEvent` was added to `drivers/input/ps2kbd.h`:
thread-safe, Cli-bracketed enqueue into a small ring, wakes the
same `g_readers` wait queue the PS/2 IRQ uses. `Ps2KeyboardReadEvent`
drains the injection ring first before calling into the scancode
path. `Ps2KeyboardRead` treats a scancode of 0 as a sentinel for
"woke up for injection" so readers don't spin.

### HID usage → KeyCode translation

Built in `TranslateHidUsage(usage, shift)`:

- **0x04..0x1D** → 'a'..'z' (pre-shifted to 'A'..'Z' if the HID
  modifier byte has Shift bit set).
- **0x1E..0x27** → '1'..'0' with shift-map to the standard US
  punctuation row (`!@#$%^&*()`).
- **0x28..0x38** → Enter / Esc / Backspace / Tab / Space / hyphen
  / equals / brackets / backslash / semicolon / quote / backtick
  / comma / period / slash — all with US shift maps.
- **0x3A..0x45** → `kKeyF1`..`kKeyF12`.
- **0x4F..0x52** → Right / Left / Down / Up arrows.

Modifier bits (byte 0) map:
- 0x01 | 0x10 (LCtrl | RCtrl) → `kKeyModCtrl`
- 0x02 | 0x20 (LShift | RShift) → `kKeyModShift`
- 0x04 | 0x40 (LAlt | RAlt) → `kKeyModAlt`
- 0x08 | 0x80 (LMeta | RMeta) → `kKeyModMeta`

### Report diff

USB HID Boot Keyboard reports are 8 bytes:
`{ mod, reserved, usage[6] }`. On each report we compare against
the previous:

- Modifier byte differs → emit one modifier-only event
  (`code = kKeyNone`, updated `modifiers`).
- Usage in prev but not in curr → release event.
- Usage in curr but not in prev → press event.
- Usage 0x01 (ErrorRollOver) is filtered out — the keyboard sends
  this when more than 6 keys are held simultaneously; injecting
  it as a keypress would spam the shell.

### Edge cases worth remembering

- **xHCI interval from USB bInterval** differs per speed. HS/SS
  already encode log2(microframes); we do `bInterval - 1`.
  LS/FS is linear ms; we convert to log2 microframes via a walking
  shift. Clip to [0, 15].
- **Configure Endpoint Input Context must re-describe EP0.** The
  Input Control Context A1 flag tells the controller to use the
  EP0 context from this submission as the new EP0 state; the old
  state from Address Device is replaced, not merged. Omitting
  A1 here leaves EP0 "disabled" in the slot context even though
  the device is addressed.
- **freestanding-kernel memset trap.** Zero-initializing a large
  struct via `= {}` lowers to a libc `memset` call the linker
  can't resolve. `ZeroBytes` does a volatile byte loop as a
  local fallback — keeps the TU building without pulling in a
  kernel-wide memset decision.
- **Event ring ownership.** Only the HID polling task consumes
  events on this ring after boot. That's the v0 simplification:
  no more commands are issued on the command ring, so the task
  can own the event ring exclusively.

### Observable on boot

With `-usb -device usb-kbd` on QEMU, or a real USB keyboard on an
xHCI port, you should see:

```
[xhci]   HID-BOOT-KEYBOARD port=1 iface=0 ep=0x81 mps=8 interval=0xA config=1
[xhci]   HID-BOOT-KEYBOARD bound; polling task will pick up slot=1
[xhci] enumeration: addressed=1 descriptors=1 configs=1 hid-keyboards=1 hid-bound=1
```

and keystrokes type directly into the shell (and the login form).

### What this slice still doesn't do

- No SET_PROTOCOL(Boot) — most keyboards default to boot protocol
  on power-up. Add if testing finds a device that doesn't.
- No SET_IDLE(0) — unused in v0; report-on-change is the default.
- No LED output (caps-lock indicator etc.) — one-way input only.
- No hot-unplug detection — the polling task spins forever on a
  dead endpoint.
- No MSI-X — polling. A future MSI-X subsystem lets the HID task
  block on a wait queue instead of `SchedSleepTicks(1)` every
  10 ms.

## See also

- `xhci-enumeration-v0.md` — the prior slice that lands Address
  Device + GET_DESCRIPTOR(Device), whose `DoControlIn` helper +
  `Runtime` struct this slice extends.
- `kernel/drivers/input/ps2kbd.{h,cpp}` — host of the
  `KeyboardInjectEvent` seam that unifies PS/2 and USB input.
