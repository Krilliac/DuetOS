#pragma once

#include "util/types.h"

/*
 * DuetOS — named hardware watchpoints.
 *
 * Thin friendly wrapper over `BpInstallHardware` (kernel/debug/breakpoints.h).
 * Lets any kernel TU drop a `Watch("name", &thing, sizeof(thing), …)` line
 * to catch the next CPU write to `&thing` with a serial-logged + symbolised
 * RIP, and (optionally) a panic.
 *
 * What this is for
 * ----------------
 * Hardware data breakpoints (DR0..DR3 + DR7) trap on the FIRST CPU access
 * to a watched 1/2/4/8-byte range. They cost zero memory, work on .rodata
 * / MMIO / device buffers / user pages, and produce a structured panic
 * banner naming the writer's RIP — far more actionable than a downstream
 * #PF on the corrupted page. The original use case was pinning a kernel
 * stack-overflow-into-`.bss.boot` regression (commit 6d4b410): a single
 * watchpoint on `boot_pd[0]` named the writer's RIP in one boot, which
 * `addr2line` resolved to `Fat32LookupPath +0x21`, which made the stack-
 * overflow diagnosis obvious.
 *
 * Use cases (sprinkle as needed; remove when done)
 * -----------------
 *   * "Who is corrupting my global?"
 *       Watch("g_foo", &g_foo, sizeof(g_foo), WatchAction::Panic);
 *
 *   * "This region must be RO after init."
 *       Watch("table-frozen", &g_table, 8, WatchAction::Panic);
 *       (Catches the next mutator with a panic + RIP banner.)
 *
 *   * "Who is racing this counter?"
 *       Watch("g_counter", &g_counter, 8, WatchAction::LogEachHit);
 *       (Logs every write; symbolises every RIP. Use sparingly —
 *        verbose under contention.)
 *
 *   * "Did anyone trip this trip-wire?"
 *       Watch("trip-wire", &g_canary, 8, WatchAction::LogOnce);
 *       (One log line per process boot — quiet by default.)
 *
 * Hardware budget — only 4 concurrent watchpoints
 * -----------------------------------------------
 * x86_64 has DR0..DR3, four total. Used for both watch points and the
 * `bp hw` shell command's HwExecute breakpoints. `Watch()` returns false
 * (and logs the failure) if no slot is free. Remove when you're done.
 *
 * Action semantics
 * ----------------
 *   LogOnce     — log the FIRST hit, count subsequent hits silently. Good
 *                 for "is this thing ever touched?".
 *   LogEachHit  — log every hit. Good for understanding access patterns;
 *                 turn it into a profiler post-hoc by counting log lines.
 *   Panic       — log + panic on the FIRST hit. Use when ANY write to the
 *                 watched address is a bug; the panic banner names the
 *                 culprit's RIP.
 *
 * Output format on hit
 *   [watch] HIT name="<name>" va=<addr> rip=<addr> [symbol+0xOFF (file:line)]
 *               rsp=<addr> hits=<N>
 *
 * Context / threading
 *   The hit callback runs in #DB trap context (interrupts disabled,
 *   kernel mode). It logs to COM1 directly and either returns (Log*)
 *   or hands off to PanicWithValue (Panic). No allocations along the
 *   way; safe from any context the underlying CPU access happens in.
 *
 *   Install / remove serialise via the underlying BP-subsystem spinlock;
 *   the local name-table updates use a small spinlock of their own.
 *   Both are uncontended in practice (install/remove are rare).
 *
 * Not for
 *   Catching DMA / device writes — DR* only fire on CPU-side accesses.
 *   For DMA suspicion, watch the device's PRP / descriptor list instead
 *   (CPU writes to those before the device reads them).
 */

namespace duetos::debug
{

/// What to do when the watched address is written.
enum class WatchAction : u8
{
    LogOnce,    // log first hit; subsequent hits increment the counter silently
    LogEachHit, // log every hit (use sparingly — verbose under contention)
    Panic,      // log + PanicWithValue(rip) on first hit
};

/// Snapshot of one installed watchpoint, returned by `WatchList`.
/// Pointer-into-the-table semantics — `name` stays valid for the life
/// of the install.
struct WatchInfo
{
    const char* name;
    u64 addr;
    u8 len_bytes;
    WatchAction action;
    u64 hit_count;
};

/// Install a write-watchpoint on `addr`. Returns true on success; false
/// + a `[watch]` log line on failure (name collision, no free DR slot,
/// bad length). `len_bytes` must be 1, 2, 4, or 8. `name` should be a
/// stable string literal (the wrapper holds the pointer, doesn't copy).
bool Watch(const char* name, const void* addr, u8 len_bytes, WatchAction action);

/// Convenience overload — 8-byte watch (a u64 / pointer slot), panic on
/// hit. The most common shape: "find the writer that should not exist."
inline bool Watch(const char* name, const void* addr)
{
    return Watch(name, addr, 8, WatchAction::Panic);
}

/// Remove a watchpoint by name. Returns true if removed, false if no
/// watchpoint with that name was installed.
bool WatchRemove(const char* name);

/// Snapshot up to `cap` watchpoint entries. Returns the count actually
/// written. No allocation — caller supplies the buffer. Safe in any
/// context.
usize WatchList(WatchInfo* out, usize cap);

/// Boot-time self-test. Installs a watch on a stack-local u64, writes
/// to it, verifies the hit count incremented, removes the watch.
/// Returns true on success. Logs `[watch] selftest …` lines on COM1.
/// Safe to call multiple times.
bool WatchSelfTest();

} // namespace duetos::debug
