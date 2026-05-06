#pragma once

#include "util/types.h"

/*
 * DuetOS — named software tripwires.
 *
 * Companion to `kernel/debug/watch.h` (named hardware watchpoints).
 * Where `Watch()` programs DR0..DR3 and traps on the first CPU write
 * to a small range, `Tripwire()` snapshots a CRC-32 of an arbitrary-
 * length region and lets the operator ask "has anything in this
 * region changed since I armed it?" at any later point.
 *
 * What this catches that `watch` doesn't
 * --------------------------------------
 *   * DMA writes (a NIC / NVMe / xHCI controller scribbling a
 *     descriptor ring — the CPU never executed a write, so DR* never
 *     fired). The CRC notices.
 *   * Regions larger than 8 bytes — a whole struct, a page, a table.
 *   * More than 4 concurrent guarded regions — there are 4 hardware
 *     DR slots; the tripwire table holds 16 (`kMaxTripwires`).
 *   * Code regions you don't want to perturb with an int3 patch.
 *
 * What this DOESN'T do
 * --------------------
 *   * Pin the writer's RIP. The tripwire is lazy: it fires at
 *     `TripwireVerify()` time, not at write time. The detection tells
 *     you "something tampered with this region" but not who. Pair
 *     with `Watch()` (when the region fits in 8 bytes and the writer
 *     is CPU-side) for an immediate trap with RIP.
 *   * Detect a write that was reverted before the next verify — if a
 *     bug writes 0xDEAD then writes back the original value, the CRC
 *     matches at scan time and the tripwire stays green.
 *
 * Use cases
 * ---------
 *   * Page-table integrity: arm a tripwire on a known-frozen PT page
 *     and re-verify periodically.
 *       Tripwire("pt-frozen", pt_va, 4096, TripwireAction::Panic);
 *       … work …
 *       TripwireVerify();   // green or panic
 *
 *   * Driver descriptor ring: snapshot the inactive half of a ring,
 *     verify after a known-quiet interval, catch DMA stomp.
 *       Tripwire("nvme-cq-idle", &cq[64], sizeof(cq) / 2,
 *                TripwireAction::Log);
 *
 *   * Read-mostly globals that occasionally change legitimately:
 *       Tripwire("g_caps", &g_caps, sizeof(g_caps), TripwireAction::Log);
 *       … legitimate update …
 *       TripwireRefresh("g_caps");  // adopt the new value as baseline
 *
 * Action semantics
 * ----------------
 *   Log         — log once when the CRC first mismatches. Subsequent
 *                 verifies that still mismatch increment the counter
 *                 silently. Adopting the new state requires `Refresh`.
 *   LogEach     — log every verify call where the CRC mismatches.
 *                 Useful for "is this region still being mutated?"
 *                 sampling. Verbose under continuous corruption.
 *   Panic       — log + PanicWithValue(addr) on the first mismatch.
 *                 Use when ANY drift in this region means the kernel
 *                 has lost an invariant.
 *
 * Output format on detected mismatch
 *   [tripwire] HIT name="<name>" va=<addr> len=<bytes>
 *              expected_crc=<hex> actual_crc=<hex> hits=<N>
 *
 * Context / threading
 *   Install / remove / refresh / verify all serialise via the
 *   tripwire-table spinlock. Verify reads the watched region with
 *   plain loads — caller is responsible for ensuring those reads
 *   are safe (region is mapped, no torn-read concerns for the
 *   coarse "did anything change" question being asked). Verify is
 *   safe from task context; do NOT call from IRQ context — the CRC
 *   walk over a large region can take meaningful time.
 *
 * Hardware budget — none. The tripwire table is .bss-resident
 * (`kMaxTripwires` rows × ~48 bytes). No DR slots consumed.
 *
 * Pairing with Watch
 * ------------------
 * Typical workflow when chasing a memory-corruption bug:
 *   1. Tripwire the suspect region. Run the workload. If it stays
 *      green, the region wasn't touched — look elsewhere. If it
 *      flips, you've confirmed the region is the victim.
 *   2. Narrow to the smallest 8-byte sub-range that flips.
 *   3. Switch that sub-range to a `Watch(... Panic)` and rerun.
 *   4. The next boot's panic banner names the writer's RIP.
 */

namespace duetos::debug
{

/// What to do when `TripwireVerify` finds the region's CRC has
/// drifted from the snapshot taken at install (or last `Refresh`).
enum class TripwireAction : u8
{
    Log,     // log first detection; subsequent mismatches increment the counter silently
    LogEach, // log on every verify that still mismatches
    Panic,   // log + PanicWithValue(addr) on the first mismatch
};

/// Snapshot of one installed tripwire, returned by `TripwireList`.
struct TripwireInfo
{
    const char* name;
    u64 addr;
    u64 len_bytes;
    u32 expected_crc;    // baseline at last install / Refresh
    u32 last_actual_crc; // most recent observation (0 before first verify)
    TripwireAction action;
    u64 verify_count;   // # times Verify scanned past this row
    u64 mismatch_count; // # of those that found a mismatch
    bool armed;         // false after a Panic-action row has fired (kept for forensics)
};

/// Install a tripwire on `[addr, addr + len_bytes)`. Computes the
/// baseline CRC at install time. Returns true on success; false +
/// `[tripwire]` log line on failure (name collision, table full,
/// bad args). `name` should be a stable string literal — the table
/// holds the pointer, not a copy. `len_bytes` must be > 0.
bool Tripwire(const char* name, const void* addr, u64 len_bytes, TripwireAction action);

/// Convenience overload — Log on mismatch (the safest default).
inline bool Tripwire(const char* name, const void* addr, u64 len_bytes)
{
    return Tripwire(name, addr, len_bytes, TripwireAction::Log);
}

/// Remove a tripwire by name. Returns true if found + removed,
/// false if no row matched.
bool TripwireRemove(const char* name);

/// Recompute the baseline CRC for a tripwire — call after a
/// legitimate change to the region so the next Verify uses the
/// new value as ground truth. Returns true on success, false if
/// no row matched.
bool TripwireRefresh(const char* name);

/// Walk the table and verify every armed tripwire. For each row
/// whose CRC mismatches, applies the configured action. Returns
/// the number of rows that mismatched on this scan. Safe to call
/// repeatedly; each row's `verify_count` increments once per scan
/// regardless of outcome.
usize TripwireVerify();

/// Snapshot up to `cap` rows. Returns the count actually written.
/// No allocation. Safe from any non-IRQ context.
usize TripwireList(TripwireInfo* out, usize cap);

/// Boot self-test. Installs a tripwire on a stack-local buffer,
/// verifies it green, scribbles into the buffer, verifies it red,
/// refreshes, verifies green again, removes. Returns true on
/// success. Logs `[tripwire] selftest …` lines on COM1.
bool TripwireSelfTest();

} // namespace duetos::debug
