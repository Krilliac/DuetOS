# A/B Kernel Boot Slots

> **Audience:** Installer / updater authors, anyone touching the
> ESP layout
>
> **Execution context:** Kernel — parsing / serialisation are pure
> functions; in-RAM state setter runs at boot
>
> **Maturity:** v0 — state-file format + parser + transition helpers
> + self-test; grub.cfg generator, watchdog hook, and installer
> wiring are GAP

## Overview

[`kernel/fs/boot_slot.{h,cpp}`](../../kernel/fs/boot_slot.h)
implements the kernel-side primitives behind a two-slot redundant
kernel layout on the ESP. The installer writes a new kernel image
into the **inactive** slot, validates the on-disk artifact, then
atomically flips the active-slot marker. If the next boot fails to
mark itself healthy within a watchdog window, the bootloader rolls
back to the other slot — so a botched kernel update never bricks
the box.

This is the analogue of ChromeOS's autoupdate slots or Android's
A/B partition design. It is the only sane way to ship rolling
kernel updates on a system whose boot path you cannot mutate
atomically.

## When to Read This Page

- Wiring the installer's write side ("land the new kernel on the
  inactive slot, update the state file").
- Wiring the watchdog hook ("mark the running slot healthy once
  boot completes").
- Reviewing a slice that touches the grub.cfg generator or the
  state-file path conventions.
- Investigating a boot-rollback event after a bad update.

## ESP Layout

```
/boot/duetos-kernel-a.elf       kernel image, slot A
/boot/duetos-kernel-b.elf       kernel image, slot B
/boot/duetos-slot.cfg           slot-state file (≤ 256 bytes, UTF-8, LF)
/boot/grub/grub.cfg             two menuentries, default per state file
```

The state file is plain text so any tool — including the firmware
shell or a recovery USB — can inspect and edit it. The
machine-readable format keeps the parser hand-checkable.

## State File Format

```
# duetos boot-slot state v1
active=a
pending=b
tries_remaining=3
last_healthy=a
```

| Field             | Meaning                                                                                                              |
|-------------------|----------------------------------------------------------------------------------------------------------------------|
| `active`          | Slot the next boot tries first.                                                                                      |
| `pending`         | Slot just installed; if it boots healthy, becomes the new `active`. `invalid` when no install is in flight.          |
| `tries_remaining` | Bootloader decrements on each attempt. At 0 without a healthy mark → rollback to `last_healthy`.                     |
| `last_healthy`    | Most recent slot that completed a boot and called `BootSlotMarkHealthy`.                                             |

## State Transitions

```
                       BeginInstall(target)
   ┌──────────────────────────────────────────────────────────┐
   │                                                          │
   ▼                                                          │
Default(A)          ──BeginInstall(B)──►         (A active,     │
(A active, no                                    B pending,     │
 pending)                                        tries=3)       │
                                                                │
                                                                │ MarkHealthy(B)
                                                                │ (B boots OK)
                                                                ▼
                                                (B active, last_healthy=B)
                                                                │
                                                                │ Rollback
                                                                │ (tries=0 without
                                                                │  MarkHealthy)
                                                                ▼
                                                (A active again)
```

The transition helpers are pure functions over `State`:

| Helper                          | Effect                                                                  |
|---------------------------------|-------------------------------------------------------------------------|
| `Default()`                     | `active=A`, `pending=invalid`, `last_healthy=A`, `tries=3`.             |
| `BeginInstall(state, target)`   | Set `pending=target`, refill `tries=3`; preserve `last_healthy`.        |
| `MarkHealthy(state, running)`   | Promote `pending` if it matches `running`; refill `tries`.              |
| `Rollback(state)`               | Reset `active` to `last_healthy`; clear `pending`.                      |

The caller is responsible for serialising the new state and
writing it back to the ESP. The helpers don't touch I/O.

## In-RAM Current State

`boot_slot` also maintains a single in-RAM `State` value that
answers the question "which slot is this kernel running from?".
The bootloader hand-off (cmdline param `slot=` or a multiboot2
module carrying the on-disk state file) calls `SetCurrentState`
before any consumer reads it.

| Reader                                | Purpose                                                          |
|---------------------------------------|------------------------------------------------------------------|
| `slotinfo` shell command              | One-screen status read.                                          |
| Watchdog hook (`MarkHealthyNow`)      | Promote `pending` once boot completes.                           |
| Installer "safe to flip?" check       | Refuses to start an install while a slot is still `pending`.     |

`MarkHealthyNow` is the convenience that does
`MarkHealthy(CurrentState(), CurrentState().active)` and writes
the result back into the in-RAM state.

## Callback-Based Persistence

The state file lives on the ESP (FAT32) today and on the future
DuetFS install tomorrow, and should be loadable from a kernel-side
ramfs blob for tests. To avoid coupling `boot_slot` to any one of
those, persistence is callback-driven:

```
using LoadFn = i64  (*)(void* ctx, u8* buf, u64 cap);
using SaveFn = bool (*)(void* ctx, const u8* buf, u64 len);

bool LoadVia(LoadFn fn, void* ctx, State* out);
bool SaveVia(SaveFn fn, void* ctx, const State& state);
```

The caller owns FAT32 read/write, ramfs lookups, or VFS path
resolution. `boot_slot` only knows the byte-level format.

## Boot Self-Test

`SelfTest` runs at kernel init:

1. `Default()` produces the canonical zero state.
2. `BeginInstall(B)` puts B in `pending`.
3. `MarkHealthy(B)` promotes B and refills `tries`.
4. `BeginInstall(A)` re-arms A.
5. `Rollback` rolls back to `last_healthy`.
6. Serialise / Parse round-trips every state.

Any invariant violation panics. Adding a new transition? Add its
case to the self-test.

## Known Limits / GAPs

- **grub.cfg generator unwritten.** The state file alone doesn't
  boot anything — the bootloader needs to consult the state and
  pick a menuentry. The generator lands when the installer wires
  this in.
- **Watchdog hook unwired.** A real "boot completed" trigger needs
  a high-confidence point in the boot path (post-login? post-first-
  shell? post-init-script?) — picking this is a design call that
  hasn't been made.
- **Installer integration GAP.** The state-file format and the
  per-slot kernel paths are stable; the installer's "write to
  inactive slot + atomically flip" sequence is the residual work.
- **Single state file.** No redundancy. A corrupted state file
  forces a manual recovery boot. The bootloader could verify a
  checksum line, but that's a v1 detail.

## Related Pages

- [Install Flow](../tooling/Install-Flow.md) — third-party app
  install context (different problem, similar
  active/pending/rollback discipline).
- [Live Updates](../tooling/Live-Updates.md) — kernel-update
  workflow that this subsystem backs.
- [VFS](VFS.md) — the path-resolution surface the state-file path
  consts (`kSlotStateFilePath`) reach through.
- [UEFI Loader](../kernel/UEFI-Loader.md) — boot-time hand-off
  that calls `SetCurrentState`.
