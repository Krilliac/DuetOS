#pragma once

#include "util/types.h"

/*
 * DuetOS — kstat, the unified kernel-statistics surface.
 *
 * WHAT
 *   A flat registry of named typed counters/gauges (`module:name`)
 *   exposed by every kernel subsystem through one read interface.
 *   Pattern: illumos `kstat(9F)`. Every subsystem with a u64 statistic
 *   already has it sitting in a global / struct accessor — kstat
 *   gives diagnostic consumers (kshell, /proc/kstat, future FMA) ONE
 *   way to walk those values rather than learning a per-subsystem
 *   accessor every time.
 *
 * WHY NOT JUST READ klog?
 *   klog is a text stream for humans. kstat is a typed surface for
 *   programs. The heartbeat already emits "ctx_switches: N" lines
 *   every 5 s; that's fine for a human reading serial, but a tool
 *   that wants the *current* value cannot wait for the next beat
 *   and then parse a line. The two surfaces are complementary —
 *   klog stays the unstructured human log, kstat is the structured
 *   machine view.
 *
 * SCOPE FOR v0
 *   - Up to `kMaxKstatEntries` (128) live entries, fixed `.bss`,
 *     no growth. Boot-only registration via a spinlock; reads and
 *     walks are lock-free.
 *   - Two kinds: Counter (monotonic) and Gauge (instantaneous u64).
 *     No floats, no signed values — consumers compute rates at read
 *     time.
 *   - Each entry stores a function pointer + opaque ctx. Read pulls
 *     the live value from the source of truth (no caching, no
 *     staleness). Cost: one indirect call per read.
 *   - Linear scan for lookup. 128 entries × ~16 string compares =
 *     trivial.
 *
 * NOT IN SCOPE
 *   - Per-CPU counters, histograms, multi-field entries (named
 *     groups), persistence across reboots, removal of registered
 *     entries (we don't have a use case yet).
 *
 * USAGE PATTERN
 *
 *     // In a subsystem init (or first-call latch):
 *     KstatRegister("sched", "context_switches", KstatKind::Counter,
 *                   [](void*) -> u64 { return sched::SchedStatsRead().context_switches; },
 *                   nullptr);
 *
 *     // From a consumer (kshell, /proc/kstat refresh, FMA reader):
 *     u64 v = 0;
 *     if (KstatRead("sched", "context_switches", &v)) { ... }
 *
 *     // Or to format everything:
 *     char buf[8192];
 *     u64 wrote = KstatFormatProcText(buf, sizeof(buf));
 */

namespace duetos::diag
{

/// Entry kind. Two are enough for v0:
///   - Counter: monotonic increasing, never resets (alloc count, packets sent).
///   - Gauge:   instantaneous value that can rise or fall (free pages, queue depth).
/// Both are u64 — no signed values, no doubles. Subsystems that need
/// rates compute them at read time (current - previous-snapshot / time).
enum class KstatKind : u8
{
    Counter = 0,
    Gauge,
};

/// Reader function: subsystem provides a callback that returns the
/// current value. Called from the consumer thread (kshell command,
/// /proc/kstat refresh, FMA reader) — must not allocate, must not
/// take sleeping locks. Returns u64.
using KstatReader = u64 (*)(void* ctx);

/// Walker callback. Invoked once per registered entry with module,
/// name, kind, current value, and the caller's cookie.
using KstatWalkCb = void (*)(const char* module, const char* name, KstatKind kind, u64 value, void* cookie);

/// Maximum number of live entries. Sized for "the entire kernel has
/// fewer than this many top-level statistics in v0"; bump the
/// constant if the registry ever fills.
inline constexpr u32 kMaxKstatEntries = 128;

/// Registration. `module:name` becomes the canonical key —
/// "sched:context_switches", "mm:free_pages", "drv.nvme.0:read_lat_ns".
/// Module is a short stable identifier (no whitespace). Name same.
/// `kind` is informational (consumers may render Counter as a
/// delta-per-second, Gauge as a raw value).
/// `reader` is called every time a consumer reads this entry. `ctx`
/// is opaque, passed back to the reader.
///
/// Returns true on success, false if the registry is full
/// (`kMaxKstatEntries`) or the key already exists.
///
/// Lifetime: pointers passed in (module, name, ctx) MUST outlive the
/// registration. Typical pattern: `module`, `name` are string literals;
/// `ctx` is a pointer to a static/global struct.
bool KstatRegister(const char* module, const char* name, KstatKind kind, KstatReader reader, void* ctx);

/// Look up an entry by `module:name` and read its current value via
/// the registered reader. Returns the value via `out_value`, true if
/// found. Cheap: O(entries_live) string-compare scan.
bool KstatRead(const char* module, const char* name, u64* out_value);

/// Walk every registered entry, invoking `cb` with module, name, kind,
/// current value, and the caller's cookie. Safe to call from the
/// heartbeat or a kshell command — readers run without the
/// registration spinlock held.
void KstatWalk(KstatWalkCb cb, void* cookie);

/// Format the full registry into a multi-line text buffer (one entry
/// per line: "<module>:<name> <kind> <value>\n"). Caller-provided
/// buffer, returns bytes written. Truncates without an error if the
/// buffer is too small. Used by /proc/kstat snapshot.
u64 KstatFormatProcText(char* buf, u64 cap);

/// Diagnostic stats about the registry itself. Useful for spotting a
/// run that's leaking registrations (entries_live climbs every boot
/// phase) or hitting the cap silently (register_failures > 0).
struct KstatRegistryStats
{
    u32 entries_live;
    u32 registrations_total;
    u32 register_failures; // full-registry or duplicate-key refusals
    u64 reads_total;
};
KstatRegistryStats KstatRegistryStatsRead();

/// Boot self-test. Registers two synthetic counters and a gauge,
/// reads them back, exercises the walker, prints
/// `[kstat] self-test OK (...)`. Panics on mismatch — a broken
/// kstat surface silently mis-reports every other subsystem's
/// stats, so we fail loudly at boot.
void KstatSelfTest();

} // namespace duetos::diag
