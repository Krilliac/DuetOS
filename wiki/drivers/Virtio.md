# VirtIO Devices

> **Audience:** Driver authors, kernel hackers running under QEMU / KVM
>
> **Execution context:** Kernel — probe in early driver init; ring drain
> in IRQ tail when wired, polling in v0
>
> **Maturity:** v0 — fabric + 7 device classes wired; all polling-based

## Overview

[`kernel/drivers/virtio/`](../../kernel/drivers/virtio/) implements the
VirtIO 1.0 paravirtual device family. The fabric (the PCI transport plus
the shared queue layout) is generic; each device class plugs in through
a small probe function called from the fabric's dispatch table.

The roles are intentionally split:

```
PCI enumeration (kernel/drivers/pci/) discovers vendor 0x1AF4 device
                |
                v
VirtioInit() — walks the discovered list, dispatches by class
                |
        +-------+---------+---------+----------+----------+--------+
        v       v         v         v          v          v        v
  net    blk   console   balloon   rng   input    gpu    scsi/socket
                                                (drivers/gpu/virtio_gpu)  (logged, no probe yet)
```

The fabric does not own driver state — each `virtio_<class>.cpp` keeps
its own per-device structs and registers with the relevant kernel
subsystem (network stack, block layer, console, entropy pool).

## Why VirtIO at all

VirtIO is the lingua franca for paravirtual hardware under QEMU, KVM,
Firecracker, and a growing list of bare-metal VMMs. It gives DuetOS:

- A consistent storage path that doesn't need an NVMe emulation
- A consistent NIC path that doesn't need e1000 emulation
- A console with a guaranteed shape across hypervisors
- An entropy source on hosts that don't expose `RDRAND` to the guest
- An RNG-backed display surface (virtio-gpu) that doesn't need a real GPU

That makes virtio the **default** driver path in QEMU smoke tests; see
[QEMU Smoke](../tooling/QEMU-Smoke.md). Real hardware drivers
(NVMe, e1000, iwlwifi, …) are wired for the bare-metal path, but the
QEMU CI path runs through virtio.

## Transport: PCI + Queue Layout

[`virtio.h`](../../kernel/drivers/virtio/virtio.h) +
[`virtio_pci.h`](../../kernel/drivers/virtio/virtio_pci.h) +
[`virtio_queue.cpp`](../../kernel/drivers/virtio/virtio_queue.cpp) form
the shared transport layer.

`VirtioPciLayout` resolves the four standard PCI capabilities (common
config, notify, ISR, device-specific) and exposes:

- `common_cfg` — feature bits, device status, queue count, queue select
- `notify` — doorbell region (one MMIO offset per queue)
- `isr` — interrupt-status read register (acknowledge IRQs)
- `device_cfg` — per-class register block (MAC address for net, capacity
  for blk, target page count for balloon, …)

The split ring layout (`virtio_queue.cpp`) lays out descriptor / avail /
used rings, computes notify offsets, and exposes `QueueSubmit()` /
`QueueDrain()` helpers each device class reuses.

Feature negotiation follows the standard handshake:
`ACKNOWLEDGE → DRIVER → FEATURES_OK → DRIVER_OK`. A device that doesn't
support the features the driver demands ends in `FAILED` state and the
device is skipped (with a `KLOG_WARN` for the operator).

## Device Class Catalogue

### virtio-blk — Block Device

[`virtio_blk.cpp`](../../kernel/drivers/virtio/virtio_blk.cpp). PCI class
2 (Block).

- **Queues**: single `requestq`.
- **Descriptor chains**: 3 descriptors per request — header (24 B,
  device-read), data (caller-supplied, device-read or -write), status
  (1 B, device-write).
- **Features negotiated**: `SEG_MAX`, `GEOMETRY`, `RO`.
- **Read/write/flush**: read + write wired; flush is currently a
  no-op (FLUSH-aware host treats it as a barrier; we don't yet flush
  cache state on the driver side).

GAP: single in-flight request — the next slice adds the multi-tag path
so the block layer can issue multiple reads concurrently.

### virtio-net — Network Interface

[`virtio_net.cpp`](../../kernel/drivers/virtio/virtio_net.cpp). PCI class
1 (Network).

- **Queues**: `receiveq` + `transmitq` (multi-queue support negotiated
  but only the queue 0/1 pair driven in v0).
- **Descriptor chains**:
  - TX: 2 descriptors per packet — 12-byte virtio-net header + frame body.
  - RX: 1 descriptor per slot, 2 KiB buffer (12-byte virtio-net header +
    up to 2036 bytes of Ethernet frame). 32 slots pre-posted at probe.
- **Features negotiated**: `MAC` (use device-cfg MAC), `STATUS` (read
  link state), `MQ` (advertised; v0 still uses one queue pair).
- **TX**: live via `VirtioNetTransmit` + the kernel net stack's iface 2
  TX trampoline. **RX**: live — a dedicated `virtio-net-rx-poll` task
  drains the receiveq every 10 ms (no IRQ wire-up yet), parses the
  per-frame virtio-net header, and injects the Ethernet payload into
  the stack via `NetStackInjectRx`. The descriptor is re-published
  immediately so the buffer is available for the next packet.
- **NIC registration**: `NetStackBindInterface(iface_index=2, …)` runs
  at probe, then `DhcpStart(2)` kicks off a lease — the device behaves
  as a real Ethernet NIC from the rest of the stack's perspective.

GAP: IRQ-driven RX delivery (today's 10 ms polling cadence is the
CPU-time floor); checksum / TSO / GSO offload negotiation;
multi-queue queue-pair selection.

### virtio-console — Serial Console

[`virtio_console.cpp`](../../kernel/drivers/virtio/virtio_console.cpp).
PCI class 3 (Console).

- **Queues**: `receiveq` + `transmitq` for port 0.
- **Public API**: `VirtioConsoleWrite(span<const u8>)`,
  `VirtioConsolePollByte()` — used by the kernel log mirror and by
  the boot diagnostic stream.

GAP: only port 0 wired; multi-port (which the spec supports) is
deferred.

### virtio-balloon — Memory Pressure

[`virtio_balloon.cpp`](../../kernel/drivers/virtio/virtio_balloon.cpp).
PCI class 5 (Balloon).

- **Queues**: configured but driver does not yet inflate/deflate in
  response to host pressure.
- **device_cfg+0**: target page count (read-only from the driver's
  side; host writes it).

GAP: PFN dispatch (the inflate/deflate path) deferred. The probe reads
the target so an operator can `kdbg balloon` to see what the host wants.

### virtio-rng — Entropy

[`virtio_rng.cpp`](../../kernel/drivers/virtio/virtio_rng.cpp). PCI class
4 (Entropy).

- **Queues**: single `requestq` — driver posts read buffers; device
  fills them with entropy.
- **Sink**: `core::RandomMix` — every batch is XOR-folded into the
  kernel PRNG pool ([`kernel/util/random.h`](../../kernel/util/random.h)).
- **Polling cadence**: opportunistic — pulled when the pool's "stir
  request" counter ticks past the threshold.

This is the only virtio device that's "live" in the sense that it
matters even when no other device of its class is in use — the
entropy contribution is non-trivial on hosts that don't expose
RDRAND to the guest.

### virtio-input — Keyboard + Pointer

[`virtio_input.cpp`](../../kernel/drivers/virtio/virtio_input.cpp).
PCI class 18 (Input).

- **Queues**: `eventq` (0, device → driver). The `statusq` (1,
  LED / force-feedback) is not installed — no consumer in tree.
- **Wire format**: a stream of `virtio_input_event {type, code,
  value}` records, one per used-ring buffer — the exact Linux
  evdev shape.
- **Keyboard decode**: `EV_KEY` keyboard codes translate to the
  shared kernel `KeyEvent`. Linux keycodes for the AT 101/104
  block are numerically identical to PS/2 set-1 scancodes, so the
  printable path reuses the **active PS/2 keymap** — the same
  layout source the PS/2 and USB-HID decoders use (one source of
  truth). Decoded events go through `KeyboardInjectEvent`, the
  same input queue PS/2 / xHCI HID / Bluetooth HID feed.
- **Pointer decode**: `EV_REL` deltas (`REL_X` / `REL_Y` /
  `REL_WHEEL`) and the `BTN_*` mouse-button `EV_KEY` codes
  (`BTN_LEFT` / `RIGHT` / `MIDDLE` / `SIDE` / `EXTRA`) accumulate
  across a frame and flush as one `MousePacket` on the `EV_SYN`
  terminator, through `MouseInjectPacket` — the same kernel
  pointer queue PS/2 / xHCI-HID mice feed. evdev sign conventions
  already match `MousePacket` (REL_Y down-positive, wheel
  up-positive). Button state is level-tracked across frames.
- **Polling cadence**: a dedicated `virtio-input-evt-poll` task
  drains the eventq every 10 ms (same rhythm as `virtio-net-rx`).
- **Boot sentinel**: the device's `ID_NAME` config string is read
  and logged (`attached (keyboard/pointer, eventq) name="…"`).

GAP: `EV_ABS` (virtio-tablet absolute coordinates) is not wired —
the unified `MousePacket` API is relative-only, matching the PS/2
stance that the absolute path lands with USB HID. GAP: single
device — a second virtio-input function is rejected (matches
virtio-console's v0 stance). GAP: IRQ-driven eventq delivery is
the next layer beyond the poll task.

### virtio-gpu — Display

Lives at [`kernel/drivers/gpu/virtio_gpu.cpp`](../../kernel/drivers/gpu/virtio_gpu.cpp),
not in the virtio tree — the GPU class has enough device-specific
state (scanouts, 2D resources, command rings) that it earns its own
home. It does negotiate features through the same `VirtioPciLayout`,
though. See [Graphics Drivers](Graphics-Drivers.md).

### virtio-scsi / -socket — Detected, no probe

The fabric recognises the device IDs and logs them at boot; no probe
exists yet. The reason is pragmatic: NVMe + AHCI cover the storage
shapes we already need; vsock is on the Roadmap for the live
remote-debug story.

## Probe Lifecycle

Every device class follows the same dance, factored into the fabric:

1. `VirtioInit()` finds the PCI BDF + reads the device class.
2. The class dispatch table calls `virtio_<class>::Probe(bdf, layout)`.
3. The probe negotiates features, resets the device, allocates and
   posts queues, sets `DRIVER_OK`.
4. The probe registers with the relevant kernel subsystem (block layer,
   network stack, console mirror, entropy pool).
5. The probe records itself in the virtio fabric's `GetStats()` table
   so the boot inventory line and the shell `virtio` command can list it.

A probe failure rolls back its own allocations and logs a one-line
explanation; it does not panic. The fabric keeps probing the next
device.

## Threading and Locking

- **Probe path**: single-threaded boot context; no locking needed.
- **TX path (net, console, blk write)**: each queue has a spinlock
  protecting the descriptor ring submit pointer. IRQ-safe (the lock is
  held with IRQs masked).
- **IRQ tail**: when wired, the `isr` register is read in the IRQ
  handler; in v0 we **poll** the used-ring tail from a worker thread
  or from the caller's context.

## Capability Gates

VirtIO probes run at boot under the kernel's own privilege; user-mode
callers reach virtio devices indirectly through the relevant subsystem
gate (`kCapFsRead` on `read()` against a virtio-blk-backed file,
`kCapNet` on a socket served by virtio-net, etc.).

## Known Limits / GAPs

- **All paths poll.** IRQ wiring deferred across all device classes.
- **virtio-blk single in-flight.** Multi-tag queue is a near-term
  follow-up.
- **virtio-net RX is polled.** Receiveq is posted and a dedicated
  `virtio-net-rx-poll` task drains it every 10 ms; IRQ-driven delivery
  is the next slice.
- **virtio-balloon does not inflate.** Target page count read, action
  not taken.
- **virtio-console single-port.** Multi-port support pending.
- **virtio-input keyboard only.** eventq keyboard path is live and
  polled every 10 ms; pointer (EV_REL/EV_ABS) and the statusq
  (LED/FF) are deferred; IRQ-driven eventq is the next layer.
- **scsi / socket** detected but not probed.

## Related Pages

- [PCIe Enumeration](PCIe-Enumeration.md) — discovers virtio devices
- [Storage](Storage.md) — virtio-blk slots into the block layer
- [Networking Drivers](Networking-Drivers.md) — virtio-net slots into
  the network stack
- [Graphics Drivers](Graphics-Drivers.md) — virtio-gpu (lives in the GPU
  tree, not the virtio tree)
- [QEMU Smoke](../tooling/QEMU-Smoke.md) — virtio is the default driver
  path under QEMU
- [Memory Management](../kernel/Memory-Management.md) — DMA-coherent
  allocator that backs virtio descriptors
