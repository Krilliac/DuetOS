# A/B Kernel Boot Slots

> **Audience:** Installer / updater authors, anyone touching the
> ESP layout
>
> **Execution context:** Kernel — parsing / serialisation are pure
> functions; in-RAM state setter runs at boot
>
> **Maturity:** v1 — state-file format + parser + transition
> helpers + grub.cfg generator + installer wiring (stage inactive
> slot, validate, `BeginInstall`, persist) + heartbeat
> mark-healthy persistence are all live

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

The single FAT32 bridge every persist site shares is
`installer::PersistSlotState(vol, state)`
([`kernel/fs/installer.cpp`](../../kernel/fs/installer.h)): it
writes the state file through `SaveVia` (same-size in-place
overwrite, else delete + create — the bounded-write tier), then
**regenerates `/boot/grub/grub.cfg` from the same state** when the
volume carries a `/boot/grub` directory, and flushes the volume.
Its callers: the installer at install time, the heartbeat after
`MarkHealthyNow`, and the `bootslot` shell subcommands.
`installer::FindBootSlotVolume()` picks the volume that already
holds the state file (the ESP), falling back to volume 0 on dev
boots.

## grub.cfg Generation

`GrubCfgGenerate(state, buf, cap)` emits the full installed-disk
grub.cfg as a **pure function of the state** — GRUB never parses
the state file (GRUB script can't tokenise key=value text); instead
the cfg is regenerated on every persist:

```
set timeout=3
set default=1            # entry of pending (install in flight) else active
set fallback="0 2"       # the other slot, then the legacy entry
menuentry "DuetOS (slot a)" {        # entry 0
    ... multiboot2 /boot/duetos-kernel-a.elf slot=a
}
menuentry "DuetOS (slot b)" {        # entry 1
    ... multiboot2 /boot/duetos-kernel-b.elf slot=b
}
menuentry "DuetOS (legacy single-kernel, system partition)" {  # entry 2
    ... multiboot2 /boot/duetos-kernel.elf
}
```

`set default` points at `pending` while an install with
`tries_remaining > 0` is in flight, otherwise `active`. The
`slot=a` / `slot=b` cmdline arg is parsed at boot
(`kernel/core/boot_bringup.cpp`) into the in-RAM `CurrentState`,
so `MarkHealthyNow` promotes the slot the kernel actually booted
from.

## Installer Integration

`installer::Install` (the shell's `install <handle> INSTALL`)
stages the embedded kernel ELF (when
`DUETOS_INSTALLER_KERNEL_EMBED=ON`) into
`SlotKernelPath(Other(active))` on the fresh ESP, validates it by
byte-for-byte read-back, then `BeginInstall` + `PersistSlotState`
— so the first boot of the installed disk tries the staged slot
with the legacy system-partition kernel as the GRUB fallback
chain's last resort. A failed stage/validate is non-fatal: the
state stays `Default()` so GRUB never defaults to an empty slot.

## Boot Self-Test

`SelfTest` runs at kernel init:

1. `Default()` produces the canonical zero state.
2. `BeginInstall(B)` puts B in `pending`.
3. `MarkHealthy(B)` promotes B and refills `tries`.
4. `BeginInstall(A)` re-arms A.
5. `Rollback` rolls back to `last_healthy`.
6. Serialise / Parse round-trips every state.
7. `GrubCfgGenerate` invariants: `set default` follows
   pending-else-active (including the exhausted-tries shape), both
   slot entries carry their `slot=` cmdline, invalid states and
   undersized buffers are refused.

Any invariant violation panics. Adding a new transition? Add its
case to the self-test.

## Known Limits / GAPs

- **GRUB does not decrement `tries_remaining`.** The cfg is a
  static artifact regenerated at persist time; rollback decisions
  are made by the kernel (`Rollback`, `bootslot force-fail`) and
  by GRUB's `set fallback` chain for missing/corrupt slot images.
  A kernel that loads but hangs before the heartbeat's
  mark-healthy needs a manual menu pick of the other slot.
- **`(hd0,gptN)` disk assumption.** The generated cfg assumes the
  install disk enumerates as GRUB's first disk; multi-disk
  installs need a search-by-UUID line.
- **State-file replace is non-atomic when the size changes.**
  Same-size persists go through `Fat32WriteInPlace`; a size change
  is delete + create, so a power cut in that window leaves the
  path absent until the next persist (GRUB then falls back to the
  generated defaults already in the cfg).
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
