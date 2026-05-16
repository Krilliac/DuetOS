/*
 * DuetOS — deliberate kernel fault injection.
 *
 * See fault_inject.h for the contract; this TU is the entire
 * implementation. v0 ships exactly four classes (NullDeref, Panic,
 * OomSlab, MachineCheck), each with a single named caller (the
 * `fault-inject` kernel shell command in shell_logging.cpp, plus the
 * boot self-test for the recoverable OomSlab case).
 *
 * Design notes:
 *   - No fault registry, no plugin surface. The control flow is a
 *     switch over the enum values; the brief explicitly forbids
 *     abstraction.
 *   - Every reach fires `kFaultInjectFired` BEFORE the trigger so
 *     an attached GDB can break at the harness frame and the
 *     non-returning classes still leave a sentinel in the log ring.
 *   - The Panic message starts with the literal substring
 *     "[fault-inject]" so post-mortem grep distinguishes intentional
 *     from real panics.
 *   - NullDeref reads from a kernel VA the paging layout reserves
 *     for future use (0xFFFFFFFFE0000000 .. 0xFFFFFFFFFFFFFFFF, see
 *     kernel/mm/paging.h). The volatile load defeats DCE so the
 *     compiler doesn't elide the access.
 *   - OomSlab drains a private 64 B-slab cache via an intrusive
 *     freelist (each freshly-allocated object is reused as a list
 *     node). No KMalloc for tracking — the test exhausts the kheap
 *     by design and any side-channel allocation would compete with
 *     the workload under test.
 */

#include "diag/fault_inject.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "debug/probes.h"
#include "log/klog.h"
#include "mm/slab.h"
#include "util/types.h"

namespace duetos::diag::fault_inject
{

namespace
{

using ::duetos::core::Err;
using ::duetos::core::ErrorCode;
using ::duetos::core::Result;

// Kernel VA the linker layout guarantees unmapped: anything at or
// above 0xFFFFFFFFE0000000 falls in the "reserved for future use"
// zone documented in kernel/mm/paging.h alongside the higher-half
// direct map and the MMIO arena. Page-aligned so the #PF the load
// raises tags the whole guard-page as the offending frame rather
// than a sub-page edge.
//
// GAP: assumes the reserved zone above the MMIO arena stays
// unmapped — revisit if a future slice (e.g. an upper-half NUMA
// arena) carves the region up.
constexpr ::duetos::u64 kUnmappedKernelVa = 0xFFFFFFFFEDEAD000ULL;

// Per-trigger guardrail for the slab drain. 1 << 20 objects of 64 B
// is ~64 MiB of kheap-backed slab storage; on a CI machine with a
// smaller kheap the cap is unreachable and we hit nullptr long
// before it, which is the intended exit. The cap exists to bound a
// misconfigured-slab regression that would loop indefinitely.
constexpr ::duetos::u64 kOomDrainCap = 1u << 20;

// Width of one slab object. 64 B is the smallest size that still
// holds a void* freelist link with room for the slab's per-object
// poison check; anything smaller would force a parallel tracking
// array (which the brief forbids).
constexpr ::duetos::u32 kOomSlabObjSize = 64;
constexpr ::duetos::u32 kOomSlabAlign = 8;

// Free every object on the intrusive freelist rooted at `head`. Used
// by both the success and the cap-reached exit so the slab cache is
// safe to destroy afterwards. Walks the list before issuing each
// SlabFree so the cache's freelist isn't temporarily corrupt.
void DrainList(::duetos::mm::SlabCache* cache, void* head)
{
    while (head != nullptr)
    {
        void* next = *static_cast<void**>(head);
        ::duetos::mm::SlabFree(cache, head);
        head = next;
    }
}

// Execute the recoverable OOM path. Returns Ok on a clean drain
// (SlabAlloc returned nullptr within the cap and the harness freed
// every object it held). See fault_inject.h for the failure modes.
Result<void, ErrorCode> TriggerOomSlab()
{
    ::duetos::mm::SlabCache* cache = ::duetos::mm::SlabCacheCreate("fault-inject-oom", kOomSlabObjSize, kOomSlabAlign);
    if (cache == nullptr)
    {
        KLOG_WARN("diag/fault_inject", "OomSlab: SlabCacheCreate failed before drain");
        return Err{ErrorCode::Unsupported};
    }

    KLOG_DEBUG_V("diag/fault_inject", "OomSlab drain cap", kOomDrainCap);

    void* head = nullptr;
    ::duetos::u64 count = 0;
    while (count < kOomDrainCap)
    {
        void* obj = ::duetos::mm::SlabAlloc(cache);
        if (obj == nullptr)
            break;
        // Intrusive next-pointer at the head of the object; the
        // poison bytes the slab returned cover the rest of the
        // object and we don't touch them.
        *static_cast<void**>(obj) = head;
        head = obj;
        ++count;
    }

    if (count == kOomDrainCap)
    {
        // Cap reached without an allocation failure: either the
        // kheap is larger than the test was sized for, or the
        // slab allocator stopped reporting exhaustion. Surface it.
        KLOG_WARN_V("diag/fault_inject", "OomSlab: drain cap reached without OOM, count", count);
        DrainList(cache, head);
        ::duetos::mm::SlabCacheDestroy(cache);
        return Err{ErrorCode::BadState};
    }

    KLOG_DEBUG_V("diag/fault_inject", "OomSlab drained objects before failure", count);
    DrainList(cache, head);
    ::duetos::mm::SlabCacheDestroy(cache);
    return {};
}

[[noreturn]] void TriggerNullDeref()
{
    // Volatile load defeats DCE and prevents the compiler from
    // proving the load unreachable. The #PF handler in
    // arch/x86_64/traps.cpp will dump state and halt; the harness
    // never returns from here.
    volatile ::duetos::u32* p = reinterpret_cast<volatile ::duetos::u32*>(kUnmappedKernelVa);
    volatile ::duetos::u32 sink = *p;
    (void)sink;
    // The load is non-returning, but the compiler can't know that
    // without inspecting the page tables; mark the function noreturn
    // explicitly and trap if the cosmos disagrees.
    for (;;)
    {
        asm volatile("hlt");
    }
}

[[noreturn]] void TriggerMachineCheck()
{
    // Software-raise vector 18. The IDT gate for #MC is present and
    // routes through the IST2 machine-check stack; the trap
    // dispatcher hands the frame to arch::MachineCheckReport, which
    // decodes the (clean, software-raised) MCA banks and the
    // dispatcher panics. Non-returning by the same contract as
    // NullDeref / Panic.
    asm volatile("int $18");
    for (;;)
    {
        asm volatile("hlt");
    }
}

[[noreturn]] void TriggerPanic()
{
    // Subsystem tag + message together produce a panic banner whose
    // body starts with the literal "[fault-inject]" substring — the
    // contract documented in fault_inject.h and the wiki page so
    // post-mortem greps can distinguish intentional from real panics.
    ::duetos::core::Panic("diag/fault_inject", "[fault-inject] forced panic");
}

} // namespace

Result<void, ErrorCode> Trigger(FaultClass fc)
{
    // Probe BEFORE the trigger so the log ring records the fire even
    // for the non-returning classes (Panic / NullDeref). An attached
    // GDB session can `b duetos::debug::ProbeFire` and break at the
    // harness frame; the trigger lives one stack frame up.
    KBP_PROBE_V(::duetos::debug::ProbeId::kFaultInjectFired, static_cast<::duetos::u64>(fc));
    KLOG_WARN_V("diag/fault_inject", "entering fault class", static_cast<::duetos::u64>(fc));

    switch (fc)
    {
    case FaultClass::NullDeref:
        KLOG_DEBUG_V("diag/fault_inject", "NullDeref unmapped VA", kUnmappedKernelVa);
        TriggerNullDeref();

    case FaultClass::Panic:
        KLOG_DEBUG_S("diag/fault_inject", "Panic message prefix", "msg", "[fault-inject]");
        TriggerPanic();

    case FaultClass::OomSlab:
        return TriggerOomSlab();

    case FaultClass::MachineCheck:
        KLOG_DEBUG_S("diag/fault_inject", "MachineCheck raising", "vec", "int $18");
        TriggerMachineCheck();
    }

    // Out-of-range enum value reaches here. Surface it; the caller's
    // shape (uniform Result<...>) lets them log + abort cleanly.
    KLOG_WARN_V("diag/fault_inject", "Trigger: out-of-range FaultClass", static_cast<::duetos::u64>(fc));
    return Err{ErrorCode::InvalidArgument};
}

void FaultInjectSelfTest()
{
    // Only OomSlab is exercised — NullDeref and Panic are non-
    // returning by construction and would halt the boot. The test
    // contract: silence on PASS (just one PASS line via raw serial
    // so CI can grep for it), and a probe fire + WARN line on FAIL.
    const Result<void, ErrorCode> r = Trigger(FaultClass::OomSlab);
    if (!r)
    {
        // sub_check encoding: 1 = OomSlab failed
        KBP_PROBE_V(::duetos::debug::ProbeId::kBootSelftestFail, static_cast<::duetos::u64>(1));
        KLOG_WARN_V("diag/fault_inject_selftest", "[fault-inject-selftest] FAIL: OomSlab returned error",
                    static_cast<::duetos::u64>(r.error()));
        return;
    }
    // CLAUDE.md "self-tests pass silently by default" — the PASS line
    // is the one piece of structured output CI greps for, and it
    // bypasses klog so a `loglevel e` demotion doesn't drop it.
    ::duetos::arch::SerialWrite("[fault-inject-selftest] PASS (oom-slab drained)\n");
}

} // namespace duetos::diag::fault_inject
