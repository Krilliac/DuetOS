/*
 * DuetOS — lockdep-lite implementation, v0 (plan D1 infra).
 *
 * See `lockdep.h` for the public contract. This TU owns the graph
 * (256×256 bitset = 8 KiB BSS), the held-class stack, edge-recording,
 * cycle detection, and the boot self-test.
 *
 * Why interrupts-off + a private serialising design instead of a
 * `sync::SpinLock`: the eventual integration target IS SpinLock,
 * so any internal use of it would recurse infinitely through the
 * lockdep hooks. Lockdep maintains its own minimal critical
 * section — `arch::Cli` + a u32 `g_busy` flag — which is safe
 * because lockdep operations are short and never block.
 */

#include "sync/lockdep.h"

#include "acpi/acpi.h"
#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "cpu/percpu.h"
#include "log/klog.h"
#include "util/symbols.h" // TEMP: inversion-site diagnostic
#include "util/saturating.h"
#include "util/types.h"

namespace duetos::sync
{

namespace
{

// 256 classes × 256 outbound bits = 256 × 32 bytes = 8 KiB. Bit
// (from, to) is set when "from was held while to was acquired".
constinit u8 g_edges[kLockClassMax][kLockClassMax / 8] = {};

// Optional human-readable names per class. Stable string-literal
// pointers; nullptr means "not registered".
constinit const char* g_class_names[kLockClassMax] = {};

// Held-class stack — per-CPU storage indexed by current-CPU id.
// 2026-05-22 follow-on to the SMP=8 audit: the prior shape kept
// `kLockdepCpuMax = 1` and aliased `g_held_stack` / `g_held_depth`
// to `g_per_cpu[0]`, which was correct for one CPU but RACED on
// SMP — two CPUs concurrently calling LockdepBeforeAcquire each
// took their own `Cli/Sti` critical section and then mutated the
// shared stack and `g_in_lockdep` flag, producing
// false-inversion lines and held-stack overflows that the
// 2026-05-19 GSBASE/lidt fix masked but didn't repair (per-task
// snapshot/restore moves the SLEEPING-mutex half across CPUs;
// the SPINLOCK half is still per-CPU). Now sized to acpi::kMaxCpus
// so every online CPU indexes its own slot — `Cli` keeps IRQ
// preemption out of one CPU's mutation, and a single per-CPU
// reentrancy flag (formerly `g_in_lockdep`) keeps nested hooks
// out. Cross-CPU writers no longer touch each other's storage.
//
// The shared edge graph + counters DO still need cross-CPU
// safety; `SetEdge` and the saturating counters below now use
// atomic RMW.
struct PerCpuHeld
{
    LockClass stack[kLockdepHeldMax];
    u32 depth;
    u32 in_lockdep; // re-entry guard, per CPU not global
    u8 _pad[8];     // keep distinct cache lines for false-sharing-free updates
};

constexpr u32 kLockdepCpuMax = ::duetos::acpi::kMaxCpus;
constinit PerCpuHeld g_per_cpu[kLockdepCpuMax] = {};

// Current-CPU slot accessor. Falls back to slot 0 (BSP) until the
// per-CPU machinery is installed — pre-BSP-install callers are
// single-threaded by construction (frame allocator, early init),
// so the fallback is correct, not a workaround.
inline u32 CurrentLockdepSlot()
{
    const u32 id = ::duetos::cpu::CurrentCpuIdOrBsp();
    return (id < kLockdepCpuMax) ? id : 0u;
}
// Earlier slices had a CurrentHeld() inline helper. Every caller
// now goes through CriticalSection::slot() + g_per_cpu[slot]
// directly (so the busy-flag race is held across the whole
// critical section), making the helper dead code — removed.

// Counters — saturating per class BB. A noisy workload that keeps
// finding fresh inversion candidates cannot wrap g_inversions to
// zero and fool the post-boot audit into reporting a clean graph.
//
// SMP-safety: `util::SatU64`'s `operator++` is NOT atomic (load,
// inc, store). Updated below via `SatAtomicAdd` (CAS loop) so two
// CPUs setting a fresh edge concurrently both contribute, and the
// inversion counter doesn't lose increments under a contention
// storm. Plain u64 storage is fine — the wrapper only adds the
// clamp-at-max semantics.
constinit u64 g_inversions = 0;
constinit u64 g_edges_recorded = 0;

// Inversion-warnings-promote-to-panic knob (plan D1-followup).
// Default false: a kernel boot under instrumentation can complete
// with a noisy graph so an operator can collect evidence. After
// the graph stabilises the operator (or a future CI gate) flips
// this to true via the shell so any new inversion is fail-stop.
constinit bool g_promote_to_panic = false;

// Re-entry guard moved into `PerCpuHeld::in_lockdep` (see the
// comment on the structure above). Kept as a comment marker so
// `git blame` keeps a hand on the lifecycle.

inline bool ValidClass(LockClass id)
{
    return id != kLockClassUnclassified && id < kLockClassMax;
}

inline bool HasEdge(LockClass from, LockClass to)
{
    // Atomic load on the byte that holds the bit so a concurrent
    // SetEdge from another CPU is fully observed (not torn).
    const u8 byte = __atomic_load_n(&g_edges[from][to / 8], __ATOMIC_ACQUIRE);
    return (byte & (1u << (to & 7))) != 0;
}

inline void SetEdge(LockClass from, LockClass to)
{
    // Atomic OR — two CPUs each calling SetEdge with bits in the
    // SAME byte must both win. A plain `|=` does load, OR, store,
    // and one of the writes could clobber the other under SMP.
    // Use the `__atomic_fetch_or` builtin so the byte's other bits
    // survive. Then check the post-OR value to decide whether to
    // bump the recorded-edge counter (counter is "edges set this
    // boot", not "edges set per call").
    const u8 mask = u8(1u << (to & 7));
    const u8 prev = __atomic_fetch_or(&g_edges[from][to / 8], mask, __ATOMIC_ACQ_REL);
    if ((prev & mask) == 0)
    {
        (void)util::SatAtomicAdd<u64>(&g_edges_recorded, 1);
    }
}

// Symbolized one-shot backtrace for a detected inversion, bounded
// to one dump per ordered (held,id) class pair. The class names in
// the WARN above say WHICH locks crossed; the stack says WHERE.
// Kept (not stripped after the compositor/fat32 investigation):
// the next lock-order regression in any subsystem gets a free
// first-occurrence stack with zero operator setup. Raw SerialWrite
// is deliberate — an inversion is serious and the bound makes it
// flood-proof, so it must not be lost to log-level demotion.
constexpr u32 kInversionSeenMax = 32;
constinit u16 g_inv_seen_held[kInversionSeenMax] = {};
constinit u16 g_inv_seen_id[kInversionSeenMax] = {};
constinit u32 g_inv_seen_count = 0;

void MaybeDumpInversionStack(LockClass held, LockClass id)
{
    for (u32 i = 0; i < g_inv_seen_count; ++i)
    {
        if (g_inv_seen_held[i] == held && g_inv_seen_id[i] == id)
            return; // already dumped this ordered pair
    }
    if (g_inv_seen_count < kInversionSeenMax)
    {
        g_inv_seen_held[g_inv_seen_count] = held;
        g_inv_seen_id[g_inv_seen_count] = id;
        ++g_inv_seen_count;
    }
    arch::SerialWrite("[lockdep] inversion backtrace (held=");
    arch::SerialWrite(LockdepClassName(held));
    arch::SerialWrite(" id=");
    arch::SerialWrite(LockdepClassName(id));
    arch::SerialWrite("):\n");
    u64 rbp = reinterpret_cast<u64>(__builtin_frame_address(0));
    for (u32 f = 0; f < 16; ++f)
    {
        if (rbp < 0xffff800000000000ULL || (rbp & 0x7) != 0)
            break;
        const u64 ret = *reinterpret_cast<const u64*>(rbp + 8);
        const u64 next = *reinterpret_cast<const u64*>(rbp);
        if (ret < 0xffff800000000000ULL)
            break;
        arch::SerialWrite("  ");
        duetos::core::WriteAddressWithSymbol(ret);
        arch::SerialWrite("\n");
        if (next <= rbp)
            break;
        rbp = next;
    }
}

// IF bit in RFLAGS; if set on entry, restore-on-exit re-enables.
inline constexpr u64 kRflagsIf = 0x200ULL;

// Tiny RAII for cli/sti + per-CPU re-entry flag. NOT a SpinLock —
// see header rationale (the eventual integration target IS SpinLock,
// so reentering through it would recurse). Each CPU has its OWN
// `in_lockdep` flag in its `PerCpuHeld` slot; cli keeps an IRQ on
// the same CPU from preempting mid-mutation, and slot-per-CPU keeps
// peer CPUs out of each other's stack.
//
// IMPORTANT: read `CurrentLockdepSlot()` AFTER `Cli` so the cpu-id
// can't change mid-construction (a thread migration between the
// flag check and the flag set would corrupt a peer's slot). The
// matching destructor uses the saved slot so an interrupt that
// snuck in just before the cli (and migrated us — impossible with
// IF=1 but defensive) still releases the correct slot.
class LockdepCriticalSection
{
  public:
    LockdepCriticalSection()
    {
        u64 f;
        asm volatile("pushfq; pop %0" : "=r"(f)::"memory");
        m_rflags = f;
        arch::Cli();
        m_slot = CurrentLockdepSlot();
        PerCpuHeld& slot = g_per_cpu[m_slot];
        m_was_busy = (slot.in_lockdep != 0);
        slot.in_lockdep = 1;
    }

    ~LockdepCriticalSection()
    {
        g_per_cpu[m_slot].in_lockdep = m_was_busy ? 1u : 0u;
        if ((m_rflags & kRflagsIf) != 0)
        {
            arch::Sti();
        }
    }

    bool already_inside() const { return m_was_busy; }
    u32 slot() const { return m_slot; }

    LockdepCriticalSection(const LockdepCriticalSection&) = delete;
    LockdepCriticalSection& operator=(const LockdepCriticalSection&) = delete;

  private:
    u64 m_rflags = 0;
    u32 m_slot = 0;
    bool m_was_busy = false;
};

} // namespace

void LockdepRegisterClass(LockClass id, const char* name)
{
    if (!ValidClass(id))
    {
        return;
    }
    LockdepCriticalSection cs;
    g_class_names[id] = name;
}

const char* LockdepClassName(LockClass id)
{
    if (!ValidClass(id) || g_class_names[id] == nullptr)
    {
        return "?";
    }
    return g_class_names[id];
}

void LockdepBeforeAcquire(LockClass id)
{
    if (!ValidClass(id))
    {
        return;
    }
    LockdepCriticalSection cs;
    if (cs.already_inside())
    {
        return; // Recursive entry — ignore.
    }
    PerCpuHeld& slot = g_per_cpu[cs.slot()];

    for (u32 i = 0; i < slot.depth; ++i)
    {
        const LockClass held = slot.stack[i];
        if (held == id)
        {
            // Same class re-acquired. Either recursive (which the
            // primitives forbid by contract) or a same-class
            // false-positive across two distinct instances. Skip;
            // don't record a self-edge.
            continue;
        }

        // Record forward edge "held -> id".
        SetEdge(held, id);

        // Cycle check: if `id -> held` was previously recorded,
        // that's an inversion.
        if (HasEdge(id, held))
        {
            (void)util::SatAtomicAdd<u64>(&g_inversions, 1);
            // Raw serial (not KLOG_*) for the same reason as
            // LockdepBeforeRelease's warning: LockdepBeforeAcquire is
            // called from inside SpinLockAcquire / MutexLock with the
            // held-set already populated, and a KLOG warn here would
            // route through Tee -> klog_persist -> Fat32 ->
            // sched::MutexLock and self-deadlock on whichever held
            // lock the inversion is being reported against. The diag
            // stays visible without re-entering any lock-taking
            // subsystem.
            const char* id_name = LockdepClassName(id);
            const char* held_name = LockdepClassName(held);
            arch::SerialWrite("[W] lockdep : inversion detected newly-acquired=");
            arch::SerialWrite(id_name != nullptr ? id_name : "<unnamed>");
            arch::SerialWrite(" vs already-held=");
            arch::SerialWrite(held_name != nullptr ? held_name : "<unnamed>");
            arch::SerialWrite("\n");
            // One-shot-per-class-pair symbolized backtrace. An
            // inversion's class names alone rarely identify the
            // offending path (many call sites take the same lock);
            // the stack at first occurrence does. Bounded to one
            // dump per ordered (held,id) pair via a small seen-set
            // so a hot inversion can't flood the console — the
            // first dump carries all the diagnostic value.
            MaybeDumpInversionStack(held, id);
            if (g_promote_to_panic)
            {
                // Re-entry guard above keeps this Panic from
                // recursing through the lockdep hooks; the panic
                // path itself disables further classification.
                core::Panic("lockdep", "inversion (promote-to-panic enabled)");
            }
        }
    }
}

void LockdepAfterAcquire(LockClass id)
{
    if (!ValidClass(id))
    {
        return;
    }
    LockdepCriticalSection cs;
    if (cs.already_inside())
    {
        return;
    }
    PerCpuHeld& slot = g_per_cpu[cs.slot()];

    if (slot.depth >= kLockdepHeldMax)
    {
        // Raw serial + one-shot via a static flag — same rationale as
        // the other lockdep warnings: KLOG_ONCE_WARN would cycle
        // through klog persistence + FAT32 + sched::MutexLock while
        // the just-attempted spinlock acquire is still claiming the
        // ticket on this CPU, deadlocking on g_sched_lock.
        static constinit bool s_warned = false;
        if (!s_warned)
        {
            s_warned = true;
            arch::SerialWrite("[W] lockdep : held-stack overflow; dropping deepest lock\n");
        }
        return;
    }
    slot.stack[slot.depth++] = id;
}

void LockdepBeforeRelease(LockClass id)
{
    if (!ValidClass(id))
    {
        return;
    }
    LockdepCriticalSection cs;
    if (cs.already_inside())
    {
        return;
    }
    PerCpuHeld& slot = g_per_cpu[cs.slot()];

    // Find topmost match and remove. Allows out-of-order release
    // (lock A held longer than lock B but A released first).
    for (i32 i = static_cast<i32>(slot.depth) - 1; i >= 0; --i)
    {
        if (slot.stack[i] == id)
        {
            for (u32 j = static_cast<u32>(i); j + 1 < slot.depth; ++j)
            {
                slot.stack[j] = slot.stack[j + 1];
            }
            --slot.depth;
            return;
        }
    }
    // Release without prior acquire — likely a missed BeforeAcquire
    // hook on the matching path, OR the held-stack lost the entry to
    // the documented per-task vs global-storage hazard (see Roadmap
    // "Lockdep held-set must be per-task"). MUST use raw serial here:
    // we are called from inside SpinLockRelease BEFORE the ticket
    // advances, with g_sched_lock still held by THIS CPU on the
    // hot path (release of the lock-pass g_sched_lock by
    // SchedFinishTaskSwitch is the loudest example). A KLOG_WARN_S
    // would route through Tee -> klog_persist -> Fat32CreateAtPath
    // -> Fat32Guard -> sched::MutexLock -> SpinLockAcquire(g_sched_lock)
    // and self-deadlock on the still-held sched lock — repro'd by
    // gui-fuzz.sh ~10% of debug-preset runs as
    //     [spinlock] SELF-DEADLOCK lock=... class="sched"
    //     recursive_acquire_rip=MutexLock+...
    //     original_acquire_rip=SchedSleepTicks+...
    // The raw-serial form keeps the diagnostic visible without
    // re-entering any lock-taking subsystem.
    arch::SerialWrite("[W] lockdep : release with no matching held entry class=");
    const char* name = LockdepClassName(id);
    arch::SerialWrite(name != nullptr ? name : "<unnamed>");
    arch::SerialWrite("\n");
}

u32 LockdepHeldSnapshot(LockClass* out, u32 cap)
{
    if (out == nullptr)
        return 0;
    LockdepCriticalSection cs;
    if (cs.already_inside())
        return 0;
    PerCpuHeld& slot = g_per_cpu[cs.slot()];
    u32 d = slot.depth;
    if (d > cap)
        d = cap;
    for (u32 i = 0; i < d; ++i)
        out[i] = slot.stack[i];
    return d;
}

void LockdepHeldRestore(const LockClass* in, u32 depth)
{
    LockdepCriticalSection cs;
    if (cs.already_inside())
        return;
    PerCpuHeld& slot = g_per_cpu[cs.slot()];
    if (depth > kLockdepHeldMax)
        depth = kLockdepHeldMax;
    for (u32 i = 0; i < depth; ++i)
        slot.stack[i] = (in != nullptr) ? in[i] : kLockClassUnclassified;
    slot.depth = depth;
}

u64 LockdepInversionsDetected()
{
    return g_inversions;
}

void LockdepSetPromoteToPanic(bool enabled)
{
    g_promote_to_panic = enabled;
}

bool LockdepPromoteToPanic()
{
    return g_promote_to_panic;
}

u64 LockdepEdgesRecorded()
{
    return g_edges_recorded;
}

void LockdepRegisterCanonicalClasses()
{
    LockdepRegisterClass(kLockClassSched, "sched");
    LockdepRegisterClass(kLockClassKObject, "kobject");
    LockdepRegisterClass(kLockClassKStack, "kstack");
    LockdepRegisterClass(kLockClassPciConfig, "pci-config");
    LockdepRegisterClass(kLockClassBreakpoints, "breakpoints");
    LockdepRegisterClass(kLockClassCleanroomTrace, "cleanroom-trace");
    LockdepRegisterClass(kLockClassWifi, "wifi");
    LockdepRegisterClass(kLockClassFat32, "fat32");
    LockdepRegisterClass(kLockClassCompositor, "compositor");
}

void LockdepReset()
{
    // Wipe the per-CPU held-class stacks first so an in-flight
    // acquire doesn't try to release into a half-cleared state.
    // Also clear the re-entry flag in case a previous panic left
    // it stuck (the destructor would have restored it, but a
    // hard-halt path can skip the destructor).
    for (u32 cpu = 0; cpu < kLockdepCpuMax; ++cpu)
    {
        for (u32 i = 0; i < kLockdepHeldMax; ++i)
        {
            g_per_cpu[cpu].stack[i] = kLockClassUnclassified;
        }
        g_per_cpu[cpu].depth = 0;
        g_per_cpu[cpu].in_lockdep = 0;
    }
    // Clear the edge matrix and counters.
    for (u32 i = 0; i < kLockClassMax; ++i)
    {
        for (u32 j = 0; j < kLockClassMax / 8; ++j)
        {
            g_edges[i][j] = 0;
        }
    }
    g_inversions = 0;
    g_edges_recorded = 0;
    g_promote_to_panic = false;
}

namespace
{

[[noreturn]] void PanicLd(const char* what)
{
    core::Panic("sync/lockdep self-test", what);
}

constexpr LockClass kStA = 0xFE;
constexpr LockClass kStB = 0xFD;

} // namespace

void LockdepSelfTest()
{
    arch::SerialWrite("[sync] lockdep self-test: register / acquire / inversion detection\n");

    LockdepRegisterClass(kStA, "selftest-A");
    LockdepRegisterClass(kStB, "selftest-B");

    if (LockdepClassName(kStA) == nullptr)
    {
        PanicLd("Class name not registered");
    }

    const u64 baseline_inversions = LockdepInversionsDetected();

    // (1) Good order: acquire A, then B, while held.
    LockdepBeforeAcquire(kStA);
    LockdepAfterAcquire(kStA);
    LockdepBeforeAcquire(kStB);
    LockdepAfterAcquire(kStB);
    if (LockdepInversionsDetected() != baseline_inversions)
    {
        PanicLd("Inversion fired on first acquire pair");
    }
    LockdepBeforeRelease(kStB);
    LockdepBeforeRelease(kStA);
    if (g_per_cpu[CurrentLockdepSlot()].depth != 0)
    {
        PanicLd("Held depth not zero after balanced release");
    }

    // (2) Inverted order: acquire B, then A. Inversion MUST fire
    // because edge A->B was recorded in step 1 and now B->A would
    // create the cycle.
    LockdepBeforeAcquire(kStB);
    LockdepAfterAcquire(kStB);
    LockdepBeforeAcquire(kStA); // <-- inversion expected here
    LockdepAfterAcquire(kStA);
    if (LockdepInversionsDetected() != baseline_inversions + 1)
    {
        PanicLd("Inversion not detected on B-then-A");
    }
    LockdepBeforeRelease(kStA);
    LockdepBeforeRelease(kStB);

    // (3) Unclassified path is a no-op (must not push, must not
    // walk graph).
    const u64 inv_before_unclassified = LockdepInversionsDetected();
    const u64 edges_before_unclassified = LockdepEdgesRecorded();
    LockdepBeforeAcquire(kLockClassUnclassified);
    LockdepAfterAcquire(kLockClassUnclassified);
    LockdepBeforeRelease(kLockClassUnclassified);
    if (LockdepInversionsDetected() != inv_before_unclassified)
    {
        PanicLd("Unclassified acquire mutated inversion counter");
    }
    if (LockdepEdgesRecorded() != edges_before_unclassified)
    {
        PanicLd("Unclassified acquire recorded edges");
    }
    if (g_per_cpu[CurrentLockdepSlot()].depth != 0)
    {
        PanicLd("Unclassified acquire pushed onto held stack");
    }

    // (4) Held-stack overflow guard: push kLockdepHeldMax distinct
    // classes, then push one more — should warn-once and skip,
    // not corrupt memory.
    static_assert(kLockdepHeldMax + 2 < kLockClassMax, "test scratch range exhausted");
    for (u32 i = 0; i < kLockdepHeldMax; ++i)
    {
        const auto cid = static_cast<LockClass>(0x40 + i);
        LockdepBeforeAcquire(cid);
        LockdepAfterAcquire(cid);
    }
    if (g_per_cpu[CurrentLockdepSlot()].depth != kLockdepHeldMax)
    {
        PanicLd("Held stack did not fill to kLockdepHeldMax");
    }
    const auto overflow_cid = static_cast<LockClass>(0x40 + kLockdepHeldMax);
    LockdepBeforeAcquire(overflow_cid);
    LockdepAfterAcquire(overflow_cid); // Should warn + skip.
    if (g_per_cpu[CurrentLockdepSlot()].depth != kLockdepHeldMax)
    {
        PanicLd("Overflow push silently exceeded held-stack cap");
    }
    // Drain.
    for (i32 i = static_cast<i32>(kLockdepHeldMax) - 1; i >= 0; --i)
    {
        const auto cid = static_cast<LockClass>(0x40 + i);
        LockdepBeforeRelease(cid);
    }
    if (g_per_cpu[CurrentLockdepSlot()].depth != 0)
    {
        PanicLd("Held stack not empty after drain");
    }

    arch::SerialWrite("[sync] lockdep self-test OK (inversion detected, overflow safe).\n");
}

} // namespace duetos::sync
