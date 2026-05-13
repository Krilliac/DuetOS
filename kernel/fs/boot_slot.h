#pragma once

#include "util/types.h"

/*
 * DuetOS — A/B kernel boot slots.
 *
 * Two-slot redundant kernel layout on the ESP. The installer
 * writes a new kernel image into the INACTIVE slot, validates
 * the on-disk artifact (size + magic + checksum), then atomically
 * flips the active-slot marker. If the next boot fails to mark
 * itself "healthy" within a watchdog window, the boot loader
 * (grub.cfg) falls back to the other slot — so a botched kernel
 * update never bricks the box.
 *
 * ESP layout (post-install):
 *
 *   /boot/duetos-kernel-a.elf      kernel image, slot A
 *   /boot/duetos-kernel-b.elf      kernel image, slot B
 *   /boot/duetos-slot.cfg          slot-state file (see below)
 *   /boot/grub/grub.cfg            two menuentries, default per state file
 *
 * Slot-state file format (UTF-8, LF line endings, ≤256 B total):
 *
 *   # duetos boot-slot state v1
 *   active=a
 *   pending=b
 *   tries_remaining=3
 *   last_healthy=a
 *
 *   - active           — slot the next boot will try first.
 *   - pending          — slot just installed; if it boots
 *                        healthy, becomes active.
 *   - tries_remaining  — boot loader decrements on each
 *                        attempt; when it reaches 0 without
 *                        a healthy mark, falls back to
 *                        `last_healthy`.
 *   - last_healthy     — most recent slot that completed a
 *                        boot and called `BootSlotMarkHealthy`.
 *
 * Today (v0): the parser, writer, and state-transition helpers
 * land. The grub.cfg generator, the actual installer integration
 * (writing to the inactive slot), and the watchdog hook are
 * GAPped — they pick up the state file the helpers below
 * produce.
 */

namespace duetos::fs::boot_slot
{

enum class Slot : u8
{
    kInvalid = 0,
    kA = 1,
    kB = 2,
};

struct State
{
    Slot active;
    Slot pending; // kInvalid if no install is mid-flight.
    Slot last_healthy;
    u8 tries_remaining; // 0..255; 3 is the default at install time.
    bool valid;         // false after a failed parse.
    u8 _pad[3];
};

/// Return the canonical default state — used when no state file
/// is present on the ESP yet (fresh install). `active = A`,
/// `pending = invalid`, `last_healthy = A`, `tries_remaining = 3`.
State Default();

/// Parse a state file from an in-memory buffer. Returns true on
/// success; on failure writes `Default()` and sets `valid=false`
/// so the caller can choose to refuse boot or to fall back.
bool Parse(const u8* buf, u64 buf_len, State* out);

/// Serialise `state` into the buffer in the format above. Returns
/// the number of bytes written, or 0 on overflow / invalid input.
/// `buf_cap` ≥ 256 is sufficient for any state value.
u64 Serialise(const State& state, u8* buf, u64 buf_cap);

/// Identify the slot OPPOSITE `s`. Returns `kInvalid` if `s` is
/// itself invalid. Used by the installer to pick the write
/// target.
Slot Other(Slot s);

/// Human-readable single-character slot name ("a" / "b" / "?").
const char* Name(Slot s);

/// State transition: a fresh install has just landed on
/// `target`. Update the state so the next boot tries `target`,
/// with the previous active preserved as `last_healthy`. Returns
/// the updated state — caller serialises + writes.
State BeginInstall(const State& cur, Slot target);

/// State transition: the running kernel completed boot
/// successfully and is calling in to confirm itself healthy.
/// Promotes `pending` if it matches, refills `tries_remaining`.
State MarkHealthy(const State& cur, Slot running);

/// State transition: the boot loader observed `tries_remaining=0`
/// for `pending`. Roll back to `last_healthy` and clear pending.
State Rollback(const State& cur);

/// Boot-time self-test. Drives a Default → BeginInstall(B) →
/// MarkHealthy(B) → BeginInstall(A) → Rollback → loops through
/// Serialise/Parse round-trip. Panics on any invariant violation.
/// Called from kernel_main alongside other diag self-tests.
void SelfTest();

// ---------------------------------------------------------------
// In-RAM "current state" — single source of truth for "which slot
// is this kernel running from?". Initialised to Default() at
// kernel start; the bootloader hand-off (cmdline param `slot=`
// or a multiboot2 module carrying the on-disk state file) will
// `SetCurrentState` before any consumer reads it.
//
// Consumers: `slotinfo` shell command, the future watchdog that
// calls `MarkHealthyNow()` once the boot path completes, the
// installer's "is it safe to flip the active slot?" check.
// ---------------------------------------------------------------

/// Snapshot of the current boot-slot state. Cheap (struct copy).
/// Safe from any kernel context.
State CurrentState();

/// Replace the in-RAM current state. Called by the boot-loader
/// hand-off path once it has parsed cmdline / loaded the on-disk
/// state file. Idempotent on the same value.
void SetCurrentState(const State& state);

/// Convenience: apply `MarkHealthy` against the in-RAM state with
/// `CurrentState().active` as the running slot. Returns the new
/// state. The watchdog hook calls this once the boot path
/// completes — pending → active promotion + tries_remaining
/// refill all happen here.
State MarkHealthyNow();

/// Canonical on-disk paths the installer + bootloader integrate
/// against. The kernel does NOT consume them directly — they
/// exist here so the integration slices have a single source of
/// truth for the filename convention.
inline constexpr const char* kSlotStateFilePath = "/boot/duetos-slot.cfg";

/// Return the ESP-relative path for a given slot's kernel image.
/// nullptr for invalid slots.
const char* SlotKernelPath(Slot s);

} // namespace duetos::fs::boot_slot
