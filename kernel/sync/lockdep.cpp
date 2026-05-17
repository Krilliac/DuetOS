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

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "core/panic.h"
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

// Held-class stack — restructured to per-CPU shape (D1-followup,
// 2026-04-28). v0 the array has one slot since only the BSP runs
// at boot. Each AP gets its own `PerCpuHeld` slot once SMP per-
// CPU storage exposes the current-CPU ID; structural change here
// keeps the existing single-CPU code paths readable through the
// `g_held_stack` / `g_held_depth` macro aliases.
struct PerCpuHeld
{
    LockClass stack[kLockdepHeldMax];
    u32 depth;
};

constexpr u32 kLockdepCpuMax = 1;
constinit PerCpuHeld g_per_cpu[kLockdepCpuMax] = {};
#define g_held_stack g_per_cpu[0].stack
#define g_held_depth g_per_cpu[0].depth

// Counters — saturating per class BB. A noisy workload that keeps
// finding fresh inversion candidates cannot wrap g_inversions to
// zero and fool the post-boot audit into reporting a clean graph.
constinit util::SatU64 g_inversions = 0;
constinit util::SatU64 g_edges_recorded = 0;

// Inversion-warnings-promote-to-panic knob (plan D1-followup).
// Default false: a kernel boot under instrumentation can complete
// with a noisy graph so an operator can collect evidence. After
// the graph stabilises the operator (or a future CI gate) flips
// this to true via the shell so any new inversion is fail-stop.
constinit bool g_promote_to_panic = false;

// Re-entry guard: when lockdep itself runs, ignore any nested
// hook calls that might come from logging / panic paths.
constinit bool g_in_lockdep = false;

inline bool ValidClass(LockClass id)
{
    return id != kLockClassUnclassified && id < kLockClassMax;
}

inline bool HasEdge(LockClass from, LockClass to)
{
    return (g_edges[from][to / 8] & (1u << (to & 7))) != 0;
}

inline void SetEdge(LockClass from, LockClass to)
{
    if (!HasEdge(from, to))
    {
        g_edges[from][to / 8] |= u8(1u << (to & 7));
        ++g_edges_recorded;
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

// Tiny RAII for cli/sti + re-entry flag. NOT a SpinLock — see
// header rationale (the eventual integration target IS SpinLock).
class LockdepCriticalSection
{
  public:
    LockdepCriticalSection() : m_was_busy(g_in_lockdep)
    {
        u64 f;
        asm volatile("pushfq; pop %0" : "=r"(f)::"memory");
        m_rflags = f;
        arch::Cli();
        g_in_lockdep = true;
    }

    ~LockdepCriticalSection()
    {
        g_in_lockdep = m_was_busy;
        if ((m_rflags & kRflagsIf) != 0)
        {
            arch::Sti();
        }
    }

    bool already_inside() const { return m_was_busy; }

    LockdepCriticalSection(const LockdepCriticalSection&) = delete;
    LockdepCriticalSection& operator=(const LockdepCriticalSection&) = delete;

  private:
    u64 m_rflags = 0;
    bool m_was_busy;
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

    for (u32 i = 0; i < g_held_depth; ++i)
    {
        const LockClass held = g_held_stack[i];
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
            ++g_inversions;
            KLOG_WARN_S("lockdep", "inversion detected", "newly-acquired", LockdepClassName(id));
            KLOG_WARN_S("lockdep", "  vs already-held", "class", LockdepClassName(held));
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

    if (g_held_depth >= kLockdepHeldMax)
    {
        KLOG_ONCE_WARN("lockdep", "held-stack overflow; dropping deepest lock");
        return;
    }
    g_held_stack[g_held_depth++] = id;
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

    // Find topmost match and remove. Allows out-of-order release
    // (lock A held longer than lock B but A released first).
    for (i32 i = static_cast<i32>(g_held_depth) - 1; i >= 0; --i)
    {
        if (g_held_stack[i] == id)
        {
            for (u32 j = static_cast<u32>(i); j + 1 < g_held_depth; ++j)
            {
                g_held_stack[j] = g_held_stack[j + 1];
            }
            --g_held_depth;
            return;
        }
    }
    // Release without prior acquire — likely a missed
    // BeforeAcquire hook on the matching path. Warn but don't
    // panic; lockdep regressions shouldn't take down the kernel.
    KLOG_WARN_S("lockdep", "release with no matching held entry", "class", LockdepClassName(id));
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
    for (u32 cpu = 0; cpu < kLockdepCpuMax; ++cpu)
    {
        for (u32 i = 0; i < kLockdepHeldMax; ++i)
        {
            g_per_cpu[cpu].stack[i] = kLockClassUnclassified;
        }
        g_per_cpu[cpu].depth = 0;
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
    if (g_held_depth != 0)
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
    if (g_held_depth != 0)
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
    if (g_held_depth != kLockdepHeldMax)
    {
        PanicLd("Held stack did not fill to kLockdepHeldMax");
    }
    const auto overflow_cid = static_cast<LockClass>(0x40 + kLockdepHeldMax);
    LockdepBeforeAcquire(overflow_cid);
    LockdepAfterAcquire(overflow_cid); // Should warn + skip.
    if (g_held_depth != kLockdepHeldMax)
    {
        PanicLd("Overflow push silently exceeded held-stack cap");
    }
    // Drain.
    for (i32 i = static_cast<i32>(kLockdepHeldMax) - 1; i >= 0; --i)
    {
        const auto cid = static_cast<LockClass>(0x40 + i);
        LockdepBeforeRelease(cid);
    }
    if (g_held_depth != 0)
    {
        PanicLd("Held stack not empty after drain");
    }

    arch::SerialWrite("[sync] lockdep self-test OK (inversion detected, overflow safe).\n");
}

} // namespace duetos::sync
