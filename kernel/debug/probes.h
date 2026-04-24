#pragma once

#include "../core/types.h"

/*
 * DuetOS — static kernel probes.
 *
 * A `KBP_PROBE(tag)` macro sprinkled at interesting sites in
 * the kernel. Each probe is a named enum entry with a per-entry
 * arm state that the operator can flip from the `probe` shell
 * command. When a probe fires AND is armed, it emits a
 * `[probe] <tag> rip=<caller>` log line (plus optional u64
 * context) — think Linux kprobes / DTrace dtrace(1M), scaled
 * down to what's useful at v0.
 *
 * The macro captures the caller's return address via
 * `__builtin_return_address(0)` so each probe site is self-
 * identifying in the log even without source symbols. In debug
 * builds this rip resolves via the kernel's embedded symbol
 * table in the serial log's trap/panic dumps.
 *
 * Scope note: this is separate from the live-breakpoint
 * subsystem (`kernel/debug/breakpoints.h`). A probe is a static
 * call site baked into the kernel image at compile time. A
 * breakpoint is an address patched (or a DR slot programmed) at
 * runtime. Probes are cheaper — just a branch through an arm-
 * state byte — and appear at code sites the operator may want
 * to hear about but isn't willing to give up a DR slot for.
 *
 * Context: kernel. Safe from IRQ / trap / scheduler-internal
 * contexts — the fire path is "load a u8, check != 0, maybe
 * log". No locks, no blocking.
 */

namespace duetos::debug
{

// Each probe is an enum entry in a fixed table. Adding a new
// probe: extend `ProbeId`, add a row to `kProbeTable` in
// probes.cpp, sprinkle `KBP_PROBE(kProbe…)` at the site. That's
// it — no dynamic registration, no memory allocation.
enum class ProbeId : u8
{
    // Rare, high-signal events — armed-log by default. A clean
    // boot log will show most of these at least once.
    kPanicEnter,       // core::Panic called — about to halt
    kSandboxDenialCap, // a capability-gated syscall was denied
    kWin32StubMiss,    // an unresolved Win32 import got hit
    kKernelPageFault,  // #PF from ring 0 — always a bug, always logged

    // Medium-frequency events — disarmed by default, the
    // operator arms these when hunting a specific issue.
    kRing3Spawn,     // SpawnRing3Task finished queuing a task
    kProcessCreate,  // ProcessCreate built a Process struct
    kProcessDestroy, // ProcessDestroy freed one

    // High-frequency events — disarmed by default. Arming one
    // of these during normal boot floods the serial log; only
    // useful with a targeted filter in mind.
    kSchedContextSwitch, // every Schedule() that actually swaps

    kCount, // sentinel
};

enum class ProbeArm : u8
{
    Disarmed = 0,    // macro-site expands to near-nothing; no log
    ArmedLog = 1,    // log a `[probe] tag rip=...` line on fire
    ArmedSuspend = 2 // log + suspend current task (user-mode only,
                     // same safety rail as breakpoints)
};

struct ProbeInfo
{
    ProbeId id;
    const char* name; // "panic.enter", "win32.stub_miss", etc.
    ProbeArm arm;
    u64 fire_count;
};

/// Fire a probe. Called only by the `KBP_PROBE` macro — no
/// direct callers expected. `caller_rip` is the address that
/// invoked the macro, captured by the macro so the log row
/// shows where in the kernel the probe lives. `value` is an
/// optional u64 context tag (syscall number, pid, whatever —
/// each site decides) or 0 if none.
void ProbeFire(ProbeId id, u64 caller_rip, u64 value);

/// Set a probe's arm state. Returns false if `id` is out of
/// range. Safe from any context. Named `ProbeSetArm` (rather
/// than the shorter `ProbeArm`) to avoid a name clash with the
/// `ProbeArm` enum class in the same namespace.
bool ProbeSetArm(ProbeId id, ProbeArm arm);

/// Look up a probe by its name (e.g. "panic.enter"). Returns
/// kCount if no match. Used by the shell's `probe arm <name>`.
ProbeId ProbeByName(const char* name);

/// Snapshot the probe table. `out` must hold at least
/// `static_cast<u64>(ProbeId::kCount)` entries.
u64 ProbeList(ProbeInfo* out, u64 cap);

/// One-time init — zero every row's fire_count, set the default
/// arm states per the `kProbeTable` declaration.
void ProbeInit();

} // namespace duetos::debug

// Fire a probe. The `do {} while (0)` is so the macro works in
// `if (x) KBP_PROBE(foo); else y;` without dangling-else footguns.
// `__builtin_return_address(0)` is the caller's rip — one level
// up (us → ProbeFire → MSVC-style stack walk would be off by
// one; we already ARE at the caller, so we cast the frame we're
// inside to the "caller" tag by taking __builtin_return_address(0)
// which on a non-inlined call is literally the CALL-return of the
// caller of ProbeFire. In practice the log line shows "the byte
// right after the KBP_PROBE call site" which resolves back to
// the macro's source line via the embedded symbol table.
#define KBP_PROBE(probe_id)                                                                                            \
    do                                                                                                                 \
    {                                                                                                                  \
        ::duetos::debug::ProbeFire((probe_id), reinterpret_cast<::duetos::u64>(__builtin_return_address(0)), 0);   \
    } while (0)

#define KBP_PROBE_V(probe_id, value)                                                                                   \
    do                                                                                                                 \
    {                                                                                                                  \
        ::duetos::debug::ProbeFire((probe_id), reinterpret_cast<::duetos::u64>(__builtin_return_address(0)),       \
                                     static_cast<::duetos::u64>(value));                                             \
    } while (0)
