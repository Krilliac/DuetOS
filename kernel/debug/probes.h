#pragma once

#include "util/types.h"

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
    kPanicEnter,          // core::Panic called — about to halt
    kSandboxDenialCap,    // a capability-gated syscall was denied
    kWin32StubMiss,       // an unresolved Win32 import got hit
    kKernelPageFault,     // #PF from ring 0 — always a bug, always logged
    kKernelGpf,           // #GP from ring 0 — always a bug, always logged
    kKernelUd,            // #UD from ring 0 — invalid opcode, always a bug
    kMachineCheck,        // #MC (vector 18) — uncorrected hardware error.
                          // Caller passes (worst_bank | verdict<<32) so an
                          // attached GDB can `b duetos::debug::ProbeFire`
                          // and halt at the exact #MC frame with the
                          // failing bank in hand. ArmedLog: a clean boot
                          // never takes a #MC, so any fire is a real
                          // hardware fault worth a sentinel line.
    kChipsetNmi,          // a non-watchdog NMI whose port-0x61 status
                          // shows PCI SERR# and/or IOCHK# — a chipset /
                          // bus / add-in-card hardware error. Caller
                          // passes the raw 0x61 byte as `value`. ArmedLog:
                          // a clean boot never takes a chipset NMI, so any
                          // fire is a real hardware fault.
    kHeapAllocFail,       // KMalloc returned nullptr (kheap pool exhausted)
    kPhysAllocFail,       // AllocateFrame returned kNullFrame (physical OOM)
    kSmpApOnline,         // a secondary CPU finished bring-up; boot diagnostic
    kBootSelftestFail,    // a boot-time self-test reported FAIL; armed-log so
                          // GDB can `b duetos::debug::ProbeFire` and break
                          // immediately when a smoke regression first appears
    kAcpiMcfgTruncated,   // ACPI MCFG header.length too small for any entry —
                          // firmware bug or hostile table; fire and skip
    kPeLoaderOom,         // PeLoad ran out of frames partway through the
                          // alloc ladder; the unwind guard freed everything
    kElfLoaderOom,        // ElfLoad ran out of frames mid-segment; same
    kProbeFail,           // a driver vendor probe returned false; device
                          // skipped and any pre-probe MMIO mapping unwound
    kTopologyParseFailed, // CPUID 0xB/0x1F decode or SRAT walk fell back
                          // to cluster=0 for at least one CPU; locality-
                          // aware steal degrades to round-robin for the
                          // affected CPU
    kBootInitWedge,       // boot init went silent for >N seconds while the
                          // timer was still firing — a driver bring-up
                          // wedge or non-progressing wait. Caller passes
                          // the elapsed-silence tick count as `value`;
                          // attached GDB can `b duetos::debug::ProbeFire`
                          // to halt at the exact tick the wedge tripped.
    kFaultInjectFired,    // diag::fault_inject::Trigger entered. Caller
                          // passes the FaultClass enum value as `value`
                          // so an attached GDB can break at the exact
                          // frame the harness fired — the deliberate
                          // panic / kernel PF / slab-OOM trigger lives
                          // one stack frame up. ArmedLog by default so a
                          // clean boot stays quiet (the harness is never
                          // entered by accident) and any trigger leaves
                          // a sentinel line + a fire count for triage.
    kGpuRingBringupFail,  // a GPU vendor's command-ring bring-up did not
                          // reach the live state its register protocol
                          // requires (Intel RCS head/tail never converged,
                          // AMD CP never came out of reset, NVIDIA PFIFO
                          // never reported runlist online). Caller passes
                          // the last-observed engine head/status word as
                          // `value` so an attached GDB can break at the
                          // exact frame the bring-up gave up. ArmedLog by
                          // default: on hardware that ships a working
                          // engine a clean boot stays quiet; a regression
                          // (or an absence we hadn't catalogued — QEMU's
                          // `-vga std` legitimately can't satisfy this) is
                          // a single sentinel line + the recorded value.

    // Medium-frequency events — disarmed by default, the
    // operator arms these when hunting a specific issue.
    kRing3Spawn,     // SpawnRing3Task finished queuing a task
    kProcessCreate,  // ProcessCreate built a Process struct
    kProcessDestroy, // ProcessDestroy freed one
    kPeLoadOk,       // PeLoad finished a successful PE/COFF image load
    kElfLoadOk,      // ElfLoad finished a successful native ELF image load
    kThreadExit,     // SchedExit transitioned a task to TaskState::Dead

    // High-frequency events — disarmed by default. Arming one
    // of these during normal boot floods the serial log; only
    // useful with a targeted filter in mind.
    kSchedContextSwitch, // every Schedule() that actually swaps

    // Module lifecycle — fires on every operator-visible state
    // flip (Running ↔ Crashed ↔ Stopped) routed through
    // `security::Module*` or the watchdog drain. ArmedLog by
    // default so a clean boot stays quiet (no transitions
    // happen at steady state) but a triage session can break
    // on every flip with `b duetos::debug::ProbeFire`. The
    // packed value carries the FaultDomainId in the high 32
    // bits, the previous state in bits 8..15, and the new
    // state in bits 0..7.
    kModuleStateChange,

    // Leak detector — fires from `LeakDetectorReportProcessExit`
    // when a process's teardown leaves residue attributable to it
    // (kobject handles, win32 handle slots, ticks-over-budget, or
    // future GPU residue). ArmedLog by default so a clean boot
    // stays quiet and a leak shows up immediately; an attached
    // GDB can `b duetos::debug::ProbeFire` and break on the first
    // attribution. The packed value carries the total
    // attributable count (handles + slots + over-budget ticks).
    kLeakAttributable,

    // Fix journal — fires from `diag::FixJournalRecord` when a
    // brand-new (detector, source_pin) pair is interned (NOT on
    // dedup hits, so a long-running boot that re-hits the same
    // gap stays quiet). ArmedLog by default so a clean boot tells
    // the operator how many unique gaps were observed and an
    // attached GDB can `b duetos::debug::ProbeFire` to break on
    // each new gap. The packed value carries the FixDetector in
    // the low byte and the assigned sequence number in the
    // high 32 bits (seq << 32 | detector).
    kFixJournaled,

    // Environment monitor — fires from the `env-monitor` task when
    // the derived power policy transitions (e.g. AC→battery,
    // thermal-throttle onset). ArmedLog by default: a clean steady
    // boot never changes policy so the log stays quiet, but a real
    // transition leaves a sentinel line + an attached GDB can
    // `b duetos::debug::ProbeFire` and break at the exact recompose
    // that flipped it. The packed value carries the previous
    // EnvPowerPolicy in bits 8..15 and the new one in bits 0..7.
    kEnvPolicyChange,

    // The env autonomic engine took a defensive/optimising action
    // (memory reclaim, security escalation, scheduler power bias,
    // forced health scan). A clean idle boot never fires this; a
    // fire means a rule's condition went true. Packed value: rule
    // id in bits 8..15, action id in bits 0..7 (see env/autonomic.h).
    kAutonomicAction,

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
        ::duetos::debug::ProbeFire((probe_id), reinterpret_cast<::duetos::u64>(__builtin_return_address(0)), 0);       \
    } while (0)

#define KBP_PROBE_V(probe_id, value)                                                                                   \
    do                                                                                                                 \
    {                                                                                                                  \
        ::duetos::debug::ProbeFire((probe_id), reinterpret_cast<::duetos::u64>(__builtin_return_address(0)),           \
                                   static_cast<::duetos::u64>(value));                                                 \
    } while (0)
