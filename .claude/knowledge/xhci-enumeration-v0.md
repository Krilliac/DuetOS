# xHCI device enumeration v0 — Address Device + GET_DESCRIPTOR(Device)

**Last updated:** 2026-04-23
**Type:** Observation
**Status:** Active

## Description

Second slice of the xHCI driver at `kernel/drivers/usb/xhci.cpp`. The
previous slice got as far as HCRST → DCBAA / command / event rings →
NoOp round-trip → PORTSC scan → Enable Slot. This slice extends each
successfully-enabled slot through USB device enumeration:

1. **Address Device** — Input Context (Input Control + Slot + EP0
   contexts) built against `HCCPARAMS1.CSZ` (32 or 64 B per context).
   DCBAA[slot_id] gets the Device Context physical address. The
   Address Device TRB is submitted on the command ring with BSR=0 so
   the controller does the USB `SET_ADDRESS` itself.
2. **GET_DESCRIPTOR(Device)** via a three-TRB control transfer on
   EP0: Setup Stage (IDT=1, 8-byte setup packet inline), Data Stage
   (IN direction, points at a per-device scratch page), Status Stage
   (OUT direction, IOC=1). Doorbell[slot_id] target=1 (EP0). Wait
   for the Transfer Event whose TRB pointer matches the Status Stage
   TRB.
3. **Parse + log** the 18-byte device descriptor — VID, PID, class /
   subclass / protocol, `bMaxPacketSize0` — and stash them on the
   matching `PortRecord`.

## Why this slice

The v1 stops *just* short of typing a character on a USB keyboard.
Everything past this needs:

- GET_DESCRIPTOR(Config) → parse interface + endpoint descriptors
- SET_CONFIGURATION
- HID class: SET_PROTOCOL(Boot), SET_IDLE(0)
- Configure Endpoint command (add the HID interrupt-IN endpoint to
  the Slot Context's context-entries count)
- Interrupt-IN transfer ring + a polling task that walks event-ring
  Transfer Events and pushes HID report bytes into the PS/2-style
  KeyEvent queue.

All of that is tractable once Address Device + GET_DESCRIPTOR(Device)
works — the hard parts (command-ring + transfer-ring + event-ring
state machines, context-size handling, doorbell routing) are the
same regardless of the descriptor you're asking for.

## Code shape

Refactor-first — everything the old `InitOne` did in closed-over
lambdas is now file-scope on a `Runtime` struct:

```cpp
struct Runtime {
    volatile u8* mmio / op / intr0;
    volatile u32* db_base;
    Trb* cmd_ring;   u64 cmd_phys;  u32 cmd_slots / idx / cycle;
    Trb* evt_ring;   u64 evt_phys;  u32 evt_slots / idx / cycle;
    u64* dcbaa;      u32 ctx_bytes; u8 max_slots;
    ControllerInfo* info;
};
```

and the shared helpers:

- `SubmitCmd(rt, type, p_lo, p_hi, status, extra_ctl) -> phys` — put
  a TRB on the command ring, ring DB[0].
- `WaitCmdCompletion(rt, expect_phys, out_status, out_slot_id)` —
  drain events until a Command Completion with matching TRB pointer.
- `WaitEvent(rt, expect_phys, expect_type, out, iters)` — generic
  drain, used by both command completions and transfer events.
- `EnqueueRingTrb(ring, phys, slots, idx, cycle, ...)` — shared by
  command ring + EP0 transfer ring.

Per-device allocation lives in `DeviceState[kMaxDevicesTotal=32]`.
Each entry owns four pages: Device Context, Input Context, EP0
transfer ring (with trailing Link TRB for spec compliance), and a
scratch page for descriptor reads.

## Edge cases worth remembering

- **Context size.** QEMU q35 reports CSZ=0 (32-byte contexts); real
  hardware often reports CSZ=1 (64 B). We read it from HCCPARAMS1
  at init and stash it on `Runtime.ctx_bytes`. Input Context layout
  is always `[Control][Slot][EP0][...]` in units of `ctx_bytes`.
- **EP0 Max Packet Size before the descriptor arrives.** We seed it
  from PORTSC speed alone:  Low/Full=8, High=64, Super+=512. The
  xHCI spec lets us skip the two-step "address with BSR=1, read
  8 bytes, Evaluate Context" dance as long as the first transfer
  is small enough that MPS-mismatch doesn't matter. 18 bytes fits.
- **Status Stage direction is opposite of Data Stage** for IN
  control transfers. Our GET_DESCRIPTOR(Device) is IN so Status
  Stage is OUT (`dir` bit clear).
- **Doorbell target encoding.** DB[0] rings the command ring.
  DB[slot_id] with target=1 rings EP0 bidirectional. Targets 2+
  address individual endpoints (2=EP1 OUT, 3=EP1 IN, ...); we'll
  need those for the next slice.
- **Setup packet is IMMEDIATE.** Setup Stage TRB has IDT=1 so the
  8-byte USB SETUP packet goes directly in `param_lo`/`param_hi`
  rather than being dereferenced from a buffer. Layout:
  ```
  byte 0 = bmRequestType
  byte 1 = bRequest
  bytes 2..3 = wValue (little-endian)
  bytes 4..5 = wIndex
  bytes 6..7 = wLength
  ```

## Shutdown + restart

`XhciShutdown` now zeroes `g_devices[]` and resets `g_device_count`
so a subsequent `XhciInit` re-allocates slots cleanly. Physical
frames behind the rings / contexts / scratch pages are intentionally
leaked until we can prove HCH has latched and no DMA is outstanding.

## See also

- `.claude/knowledge/nvme-driver-v0.md` — sibling driver that went
  through the same "v0 shell → real-hardware hardening" arc.
- `kernel/drivers/usb/hid_descriptor.{h,cpp}` — existing HID class
  skeleton; will be the consumer of the interrupt-IN path in the
  next slice.
