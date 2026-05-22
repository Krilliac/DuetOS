#include "arch/x86_64/smp.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/gdt.h"
#include "arch/x86_64/idt.h"
#include "arch/x86_64/lapic.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/timer.h"
#include "arch/x86_64/traps.h"

#include "acpi/acpi.h"
#include "debug/probes.h"
#include "log/klog.h"
#include "core/panic.h"
#include "cpu/percpu.h"
#include "cpu/topology.h"
#include "mm/address_space.h"
#include "mm/kheap.h"
#include "mm/page.h"
#include "sched/sched.h"
#include "sync/spinlock.h"
#include "util/string.h"

// Linker-emitted symbols for the trampoline image (see ap_trampoline.S).
// Declared at file scope (outside any namespace) so the linker matches
// the unmangled .S labels; qualified types because `u8` lives inside
// duetos::.
extern "C" const duetos::u8 ap_trampoline_start[];
extern "C" const duetos::u8 ap_trampoline_end[];

namespace duetos::arch
{

namespace
{

// Parameter-block offsets — MUST match the `.set OFF_*` values in
// ap_trampoline.S. Changing one without the other wedges the AP into
// reading zero / random parameters.
constexpr u64 kOffOnlineFlag = 0xFD4;
constexpr u64 kOffCpuId = 0xFD8;
constexpr u64 kOffEntry = 0xFE0;
constexpr u64 kOffStack = 0xFE8;
constexpr u64 kOffPml4 = 0xFF0;

constexpr duetos::mm::PhysAddr kTrampolinePhys = 0x8000;
constexpr u32 kMaxAps = acpi::kMaxCpus - 1;

// Per-AP persistent state, indexed by cpu_id (1..N). BSP is slot 0
// and uses the static g_bsp_percpu in cpu/percpu.cpp; APs each get a
// heap-allocated PerCpu whose pointer is cached here so the AP's C++
// entry can find its own struct by cpu_id.
constinit cpu::PerCpu* g_ap_percpus[acpi::kMaxCpus] = {};

// Per-AP GDT bundle (GDT clone + Tss + 3 IST stacks). Allocated by
// AllocateApGdt during SmpStartAps; consumed by ApEntryFromTrampoline
// via LoadGdtForCurrent. Indexed by cpu_id like g_ap_percpus.
constinit ApGdtBundle* g_ap_gdt_bundles[acpi::kMaxCpus] = {};
constinit u64 g_cpus_online = 1;  // BSP always counted
constinit u32 g_cpu_id_limit = 1; // 1 + max cpu_id ever bound (so iteration covers BSP + every AP slot used)

// LAPIC ICR low-half fields. The ICR register layout itself
// (offsets / the x2APIC MSR / delivery-status polling) is owned by
// lapic.cpp's LapicSendIcr; smp.cpp only composes the command bits.
constexpr u32 kIcrDeliveryInit = 5U << 8;
constexpr u32 kIcrDeliveryStartup = 6U << 8;
constexpr u32 kIcrLevelAssert = 1U << 14;

inline void WriteMsrGsBase(u64 value)
{
    const u32 lo = static_cast<u32>(value & 0xFFFFFFFF);
    const u32 hi = static_cast<u32>(value >> 32);
    asm volatile("wrmsr" : : "c"(0xC0000101u), "a"(lo), "d"(hi));
}

// IA32_KERNEL_GS_BASE (MSR 0xC0000102) is the swapgs target: when ring-3
// runs SYSCALL into the kernel, `swapgs` atomically swaps GS_BASE with
// IA32_KERNEL_GS_BASE so the kernel sees its per-CPU pointer in GS while
// userland sees its own (typically TLS) value. The BSP programs this in
// linux::SyscallInit; the APs need the equivalent set HERE before any
// syscall path can fire. Without it, the first `swapgs` on an AP loads
// zero into GS_BASE and the next gs-relative load triple-faults.
inline void WriteMsrKernelGsBase(u64 value)
{
    const u32 lo = static_cast<u32>(value & 0xFFFFFFFF);
    const u32 hi = static_cast<u32>(value >> 32);
    asm volatile("wrmsr" : : "c"(0xC0000102u), "a"(lo), "d"(hi));
}

inline void* TrampVirt()
{
    return mm::PhysToVirt(kTrampolinePhys);
}

inline u64& TrampU64At(u64 offset)
{
    auto* base = static_cast<u8*>(TrampVirt());
    return *reinterpret_cast<u64*>(base + offset);
}

inline u32& TrampU32At(u64 offset)
{
    auto* base = static_cast<u8*>(TrampVirt());
    return *reinterpret_cast<u32*>(base + offset);
}

// Busy-spin up to ~200 ms for the AP to flip its online flag.
bool WaitForApOnline()
{
    constexpr u64 kTimeoutTicks = 20; // * 10 ms = 200 ms
    const u64 start = TimerTicks();
    while (TimerTicks() - start < kTimeoutTicks)
    {
        if (TrampU32At(kOffOnlineFlag) != 0)
        {
            return true;
        }
        asm volatile("pause" ::: "memory");
    }
    return false;
}

} // namespace

void SmpSendIpi(u32 target_apic_id, u32 icr_low)
{
    // Mode-aware (xAPIC ICR-hi/lo + poll, or one x2APIC MSR write).
    // target_apic_id is the full 32-bit ID — no <<24 / u8 truncation.
    LapicSendIcr(target_apic_id, icr_low);
}

void PanicBroadcastNmi()
{
    // No LAPIC means we panicked before LapicInit (early frame
    // allocator / paging failure). Nothing to broadcast to.
    if (!LapicIsReady())
    {
        return;
    }

    // ICR low:
    //   bits 0..7:   vector (ignored for NMI delivery mode)
    //   bits 8..10:  delivery mode = 0b100 (NMI)
    //   bit 14:      level = 1 (assert)
    //   bits 18..19: destination shorthand = 0b11 (all-excluding-self)
    //
    // Final value: (0b100 << 8) | (1 << 14) | (0b11 << 18) = 0xC4400.
    constexpr u32 kIcrDeliveryNmi = 4U << 8;
    constexpr u32 kIcrDstShorthandAllExSelf = 3U << 18;
    constexpr u32 icr_low = kIcrDeliveryNmi | kIcrLevelAssert | kIcrDstShorthandAllExSelf;

    // Shorthand => destination ignored. LapicSendIcr is bounded and
    // klog-free, so it is safe from the panic path (no Panic-in-
    // Panic recursion, no klog re-entrancy).
    LapicSendIcr(0, icr_low);
}

// Bounded busy-wait for peer NMI ack after PanicBroadcastNmi.
// LAPIC delivery is asynchronous and the receiving CPU takes a few
// hundred-to-thousand cycles to enter the NMI handler, capture its
// snapshot, and `cli; hlt`. Without this wait, the panicking CPU
// starts writing the panic dump to serial IMMEDIATELY after the
// ICR write — and peers still in flight to the NMI handler can
// have legitimate SerialWrite traffic mid-call (under the lock,
// not in panic-mode bypass). The bytes interleave at the UART. The
// captured `g_serial_panic_mode` bypass on the panicking CPU then
// writes raw bytes that race the peer's lock-protected bytes,
// corrupting the dump (observed 2026-05-22 as the SMP=8 debug
// recursive-fault: vec=/rip= rendered as a mix of hex digits and
// spaces — toaruos's `arch_fatal_prepare` pattern, ported).
//
// Returns the count of peers that acked (`panic_snapshot_valid == 1`
// or recognisably-halted via the lock-held-set heuristic) within
// the budget. Best-effort — exits early on the budget so a wedged
// peer can never trap the panicking CPU forever. `spin_budget` is
// in pause iterations; ~10k = a few ms of wall time on TCG, plenty
// for LAPIC NMI delivery + handler entry but bounded enough that a
// non-LAPIC / dropped-IPI case still completes the dump.
u32 PanicWaitPeersHalt(u64 spin_budget)
{
    if (!LapicIsReady() || g_cpus_online <= 1)
    {
        return 0;
    }
    const u32 limit = g_cpu_id_limit;
    cpu::PerCpu* self = cpu::CurrentCpu();
    const u32 self_id = (self != nullptr) ? self->cpu_id : 0xFFFFFFFFu;

    u32 acked = 0;
    for (u32 id = 0; id < limit; ++id)
    {
        if (id == self_id)
            continue;
        cpu::PerCpu* peer = SmpGetPercpu(id);
        if (peer == nullptr)
            continue;
        // Spin until peer's NMI handler flipped the snapshot flag
        // (or the budget runs out). The NMI handler stores to
        // `panic_snapshot_valid` with a compiler memory barrier
        // before the `cli; hlt` loop, so this single-byte read is
        // a sufficient happens-before for ack.
        for (u64 spin = 0; spin < spin_budget; ++spin)
        {
            if (__atomic_load_n(&peer->panic_snapshot_valid, __ATOMIC_ACQUIRE) != 0)
            {
                ++acked;
                break;
            }
            asm volatile("pause" ::: "memory");
        }
    }
    return acked;
}

// GDB stop-rendezvous flag. Set by SmpStopBroadcastNmi, cleared
// by SmpStopReleaseNmi. Read by the vector-2 NMI handler in
// traps.cpp via SmpGdbStopActive(). Plain volatile + asm fence —
// the NMI handler runs with IF=0 so atomic-RMW machinery isn't
// needed; we just need the compiler to actually issue the load
// each time and the store to be visible across cores.
constinit volatile u32 g_gdb_stop_active = 0;

void SmpStopBroadcastNmi()
{
    if (!LapicIsReady())
    {
        // Pre-LAPIC stop request — only the calling CPU exists
        // anyway (no APs without LAPIC). Set the flag for symmetry
        // and return.
        g_gdb_stop_active = 1;
        asm volatile("" ::: "memory");
        return;
    }

    // Order matters: peers must see the flag = 1 BEFORE the NMI
    // fires, otherwise a peer NMI handler that wins the race would
    // see flag = 0 and take the panic-halt path. Fence then write
    // then fence — the LAPIC ICR write itself is a serialising
    // operation per Intel SDM, but be explicit.
    asm volatile("" ::: "memory");
    g_gdb_stop_active = 1;
    asm volatile("mfence" ::: "memory");

    constexpr u32 kIcrDeliveryNmi = 4U << 8;
    constexpr u32 kIcrDstShorthandAllExSelf = 3U << 18;
    constexpr u32 icr_low = kIcrDeliveryNmi | kIcrLevelAssert | kIcrDstShorthandAllExSelf;

    LapicSendIcr(0, icr_low);
}

void SmpStopReleaseNmi()
{
    asm volatile("mfence" ::: "memory");
    g_gdb_stop_active = 0;
    asm volatile("" ::: "memory");
}

bool SmpGdbStopActive()
{
    return g_gdb_stop_active != 0;
}

u64 SmpCpusOnline()
{
    return g_cpus_online;
}

cpu::PerCpu* SmpGetPercpu(u32 cpu_id)
{
    if (cpu_id == 0)
    {
        return cpu::BspPercpu();
    }
    if (cpu_id >= acpi::kMaxCpus)
    {
        return nullptr;
    }
    return g_ap_percpus[cpu_id];
}

u32 SmpCpuIdLimit()
{
    return g_cpu_id_limit;
}

namespace
{
// Reschedule-IPI handler. Runs in the IRQ dispatcher context with
// IF=0; sets the per-CPU need_resched flag and returns. The
// dispatcher post-handler check (TakeNeedResched + Schedule) then
// runs the scheduler before iretq, exactly mirroring the timer-IRQ
// preemption path.
void ReschedIpiHandler()
{
    sched::SetNeedResched();
}

// TLB-shootdown IPI request. Filled by SmpTlbShootdown{Addr,Range} on
// the requesting CPU, read by every target CPU's IPI handler. A simple
// "current request" model is fine for v0 (shootdown is rare), but it
// is a SINGLE global slot, so concurrent requestors must be serialised
// explicitly — g_tlb_shootdown_lock below does that. (The earlier
// assumption that the caller's page-table lock serialises them was
// wrong: that lock is per-AS, so cross-AS shootdowns race.) If
// contention shows up, swap to a per-CPU mailbox.
struct TlbShootdownRequest
{
    mm::AddressSpace* as;
    u64 virt_start;
    u64 virt_end;      // half-open; equal to virt_start + 0x1000 for single-page
    volatile u64 acks; // bumped by each target CPU when done
};
volatile TlbShootdownRequest* g_tlb_request = nullptr;

// Serialises the whole publish/IPI/wait/clear window in
// SmpTlbShootdownBroadcast. The original "current request" model
// assumed concurrent shootdowns are serialised by the caller's
// page-table lock — but that lock is PER-ADDRESS-SPACE
// (as->regions_lock), so two CPUs unmapping pages in DIFFERENT
// address spaces concurrently both overwrite the single global
// g_tlb_request. Targets servicing the first requestor's IPI then
// ack the second request, the first requestor's ack count never
// completes, it times out and proceeds with a STALE WRITABLE TLB
// entry on a peer — pointing at a frame that may already be
// recycled into another process. A dedicated global lock (not the
// per-AS one) is the correct serialisation scope.
constinit duetos::sync::SpinLock g_tlb_shootdown_lock{};

// The shootdown target mask (and AddressSpace::active_cpu_mask it
// is built from) is a u32 indexed by `1u << (cpu_id & 31u)`. At
// the current cap there is no aliasing, but the day kMaxCpus is
// bumped past 32, CPU N and CPU N+32 would alias the same bit —
// silently reintroducing the stale-TLB hole with no other signal.
// Fail the build instead.
static_assert(acpi::kMaxCpus <= 32, "TLB-shootdown CPU mask is u32; widen the mask if kMaxCpus > 32");

// TLB-shootdown IPI handler. Runs with IF=0 on the target CPU. Flushes
// the requested range if the target's current AS matches, then acks.
void TlbShootdownIpiHandler()
{
    // Take a local snapshot so we can ack before re-checking; the
    // request struct is owned by the requesting CPU's stack and is
    // safe to read until the requestor sees ack count reach the
    // target count.
    volatile TlbShootdownRequest* req = g_tlb_request;
    if (req == nullptr)
    {
        return;
    }
    // Only flush if our CR3 holds the target AS — peer CPUs in a
    // different AS have no cached entry for these VAs.
    mm::AddressSpace* current = mm::AddressSpaceCurrent();
    if (current == req->as)
    {
        const u64 page = 0x1000;
        for (u64 v = req->virt_start; v < req->virt_end; v += page)
        {
            asm volatile("invlpg (%0)" : : "r"(v) : "memory");
        }
    }
    // Ack — atomic increment via x86 LOCK XADD; the requestor spins
    // on this counter reaching the target count.
    asm volatile("lock incq %0" : "+m"(req->acks) : : "memory");
}
} // namespace

void SmpInstallReschedIpiHandler()
{
    IrqInstall(kReschedIpiVector, ReschedIpiHandler);
}

void SmpInstallTlbShootdownIpiHandler()
{
    IrqInstall(kTlbShootdownIpiVector, TlbShootdownIpiHandler);
}

namespace
{
// Fixed-delivery IPI to every CPU except the sender in a SINGLE ICR
// write, via the all-excluding-self destination shorthand. Same
// mechanism PanicBroadcastNmi/SmpStopBroadcastNmi use, but with a
// normal fixed vector instead of NMI delivery. Only correct when
// the intended target set is provably "every online peer" — the
// shorthand cannot be narrowed to a subset, so per-AS / per-cluster
// scoped sends must still enumerate targets and use SmpSendIpi.
void SmpSendBroadcastIpiAllExSelf(u8 vector)
{
    constexpr u32 kIcrDeliveryFixed = 0U << 8;
    constexpr u32 kIcrDstShorthandAllExSelf = 3U << 18;
    // Shorthand => destination ignored; pass 0. One ICR write
    // (xAPIC) or one MSR write (x2APIC) reaches every peer.
    LapicSendIcr(0, kIcrDeliveryFixed | kIcrLevelAssert | kIcrDstShorthandAllExSelf | static_cast<u32>(vector));
}

// Helper: broadcast a TLB-shootdown IPI to every online CPU other than
// the requestor whose current AS matches `as`. Sets up the request
// struct, sends the IPI, and busy-waits for every target to ack.
// No-op when peer count is 0 (uniprocessor or all peers in other AS).
void SmpTlbShootdownBroadcast(mm::AddressSpace* as, u64 virt_start, u64 virt_end)
{
    const u32 limit = SmpCpuIdLimit();
    if (limit <= 1)
    {
        return; // single CPU: no peers
    }

    // Serialise the entire publish→IPI→wait→clear window against
    // any other CPU running a shootdown for a different AS. RAII so
    // every early return below (mask == 0, etc.) releases it; IRQs
    // are saved/disabled for the duration, which is required anyway
    // (the requestor must not be preempted between publishing the
    // request and clearing it). The wait is bounded by kSpinLimit.
    duetos::sync::SpinLockGuard tlb_guard(g_tlb_shootdown_lock);

    // Build the request struct on this stack. Targets read it via the
    // global pointer; the requesting CPU owns the lifetime.
    TlbShootdownRequest req{};
    req.as = as;
    req.virt_start = virt_start;
    req.virt_end = virt_end;
    req.acks = 0;

    cpu::PerCpu* self = cpu::CurrentCpu();
    const u32 self_id = (self != nullptr) ? self->cpu_id : 0u;

    // Targeted broadcast: only IPI peers whose CR3 currently holds
    // this AS. The AS's `active_cpu_mask` is maintained by
    // AddressSpaceActivate. A peer that left the AS between our
    // snapshot and the IPI is safe — switching CR3 invalidates the
    // outgoing AS's TLB on x86 (non-global pages), so re-entry
    // re-walks the up-to-date page tables. A peer that entered the
    // AS after our snapshot is also safe for the same reason: its
    // TLB started empty under the new CR3.
    //
    // `as == nullptr` (kernel-AS shootdown) falls back to a full
    // broadcast since the boot PML4 has no per-AS tracking.
    u32 mask = 0;
    // Kernel-AS shootdowns (as == nullptr) provably target every
    // online peer, so they can fan out in one ICR write via the
    // all-but-self shorthand instead of one SmpSendIpi per peer.
    // Per-AS shootdowns stay targeted: the shorthand can't be
    // narrowed to the subset that holds this AS.
    const bool full_broadcast = (as == nullptr);
    if (as != nullptr)
    {
        mask = __atomic_load_n(&as->active_cpu_mask, __ATOMIC_ACQUIRE);
    }
    else
    {
        for (u32 id = 0; id < limit; ++id)
        {
            cpu::PerCpu* peer = SmpGetPercpu(id);
            if (peer != nullptr)
                mask |= (1u << (id & 31u));
        }
    }
    // Don't IPI ourselves.
    mask &= ~(1u << (self_id & 31u));
    if (mask == 0)
    {
        return;
    }
    const u64 target_count = static_cast<u64>(__builtin_popcount(mask));

    g_tlb_request = &req;

    // Kernel-AS: one ICR write to all peers. Per-AS: one fixed
    // IPI per peer in the mask (no shorthand — exact LAPIC IDs so
    // the ack count matches exactly the CPUs we asked).
    if (full_broadcast)
    {
        SmpSendBroadcastIpiAllExSelf(kTlbShootdownIpiVector);
    }
    else
    {
        constexpr u32 kIcrDeliveryFixed = 0U << 8;
        constexpr u32 icr_low_base = kIcrDeliveryFixed | kIcrLevelAssert;
        for (u32 id = 0; id < limit && mask != 0; ++id)
        {
            const u32 bit = 1u << (id & 31u);
            if ((mask & bit) == 0)
                continue;
            mask &= ~bit;
            cpu::PerCpu* peer = SmpGetPercpu(id);
            if (peer == nullptr)
                continue;
            SmpSendIpi(peer->lapic_id, icr_low_base | kTlbShootdownIpiVector);
        }
    }

    // Spin until every target has acked. The handler runs with IF=0
    // and just hits a `lock inc` + iretq, so the worst-case wait is
    // the round-trip IPI latency — microseconds on healthy hardware.
    // A bounded spin keeps us from hanging forever if a peer's LAPIC
    // mis-fires; on timeout we log + proceed (better to risk a
    // stale TLB on one CPU than to hang the requesting CPU).
    constexpr u64 kSpinLimit = 1'000'000;
    u64 spins = 0;
    while (req.acks < target_count && spins < kSpinLimit)
    {
        asm volatile("pause" ::: "memory");
        ++spins;
    }
    if (req.acks < target_count)
    {
        KLOG_WARN("arch/smp", "tlb shootdown timeout — some peer did not ack");
    }
    g_tlb_request = nullptr;
}
} // namespace

void SmpTlbShootdownAddr(mm::AddressSpace* as, u64 virt)
{
    SmpTlbShootdownBroadcast(as, virt, virt + 0x1000);
}

void SmpTlbShootdownRange(mm::AddressSpace* as, u64 virt, u64 len)
{
    const u64 page = 0x1000;
    const u64 start = virt & ~(page - 1);
    const u64 end = (virt + len + page - 1) & ~(page - 1);
    SmpTlbShootdownBroadcast(as, start, end);
}

void SmpSendReschedIpi(u32 cpu_id)
{
    cpu::PerCpu* self = cpu::CurrentCpu();
    if (self != nullptr && self->cpu_id == cpu_id)
    {
        return; // self-IPI is pointless — caller already SetNeedResched
    }
    cpu::PerCpu* target = SmpGetPercpu(cpu_id);
    if (target == nullptr)
    {
        return;
    }
    // Fixed delivery, edge-triggered (level=assert), vector encoded
    // in the low 8 bits. No destination-shorthand — we want exactly
    // this CPU's LAPIC ID.
    constexpr u32 kIcrDeliveryFixed = 0U << 8;
    constexpr u32 icr_low_base = kIcrDeliveryFixed | kIcrLevelAssert;
    SmpSendIpi(target->lapic_id, icr_low_base | kReschedIpiVector);
}

// ---------------------------------------------------------------------------
// AP kernel entry — called from ap_trampoline.S once long mode is live.
// Signature: void ApEntryFromTrampoline(u32 cpu_id)
//
// The AP enters here on its own 16 KiB stack (top loaded by the
// trampoline from the parameter block). Interrupts are disabled, no
// scheduler on this CPU yet, no LAPIC timer.
//
// v0 scope:
//   1) install per-CPU struct via GSBASE
//   2) bring up the AP's LAPIC (enable MSR + SVR)
//   3) flip the trampoline's online_flag so BSP stops waiting
//   4) hlt forever (scheduler entry is a separate follow-up commit,
//      gated on the runqueue/sleepqueue spinlock work landing fully)
// ---------------------------------------------------------------------------
extern "C" [[noreturn]] void ApEntryFromTrampoline(u32 cpu_id)
{
    cpu::PerCpu* pcpu = g_ap_percpus[cpu_id];

    // Install this AP's own GDT + TSS so NMI / #DF / #MC trap entries
    // resolve to the AP's IST stacks (not the BSP's, which would race
    // any concurrent BSP fault and corrupt either CPU's frame). Must
    // happen BEFORE LAPIC enable — once LAPIC is on, an NMI could
    // arrive at any moment, and without an installed TSS the CPU
    // would triple-fault picking up RSP0 / IST stack from a stale or
    // missing slot. The bundle was prepared by SmpStartAps.
    ApGdtBundle* bundle = g_ap_gdt_bundles[cpu_id];
    // SmpStartAps only fires SIPI for an AP whose bundle was
    // allocated, so by construction we should never enter here
    // with a null bundle. If a future refactor violates the
    // invariant, continuing without a loaded GDT would crash
    // the AP at the first NMI/#DF on a stale or missing IST
    // stack — far worse than halting cleanly.
    KASSERT(bundle != nullptr, "arch/smp", "AP entered ApEntryFromTrampoline without an allocated GDT bundle");
    LoadGdtForCurrent(bundle);

    // Establish this CPU's GSBASE *after* LoadGdtForCurrent — not
    // before. LoadGdtForCurrent reloads the segment registers, and
    // its `mov %ax, %gs` reloads GS's hidden base from the kernel-
    // data descriptor (whose base is 0): the instruction ZEROES
    // IA32_GS_BASE as a side effect. Programming the per-CPU pointer
    // before the GDT load (as an earlier revision did) is therefore
    // dead — it is clobbered before any gs-relative read — and every
    // cpu::CurrentCpu() on this AP then saw GSBASE=0. The pre-fix
    // CurrentCpu() silently returned the BSP slot for a non-kernel
    // GSBASE, so the AP read/wrote the BSP's current_task /
    // ctxsw_lock_to_release / per-CPU runqueue selection: the
    // per-CPU-state corruption behind the intermittent SMP double-run
    // (MUTEX-NONOWNER / sync-spinlock release-out-of-order under
    // tools/qemu/gui-fuzz.sh). The BSP is correct for the mirror-
    // image reason: PerCpuInitBsp programs GSBASE *after* GdtInit.
    // Orders match now.
    WriteMsrGsBase(reinterpret_cast<u64>(pcpu));
    // IA32_KERNEL_GS_BASE is the swapgs shadow — `mov %gs` does NOT
    // touch it — but program it here too (co-located with the GSBASE
    // write) so the first ring-3 -> ring-0 swapgs on this AP loads
    // the per-CPU pointer, not 0, into GS_BASE. Mirrors the BSP path
    // in linux::SyscallInit which programs this same MSR.
    WriteMsrKernelGsBase(reinterpret_cast<u64>(pcpu));

    // Point THIS CPU's IDTR at the shared IDT. IDTR is per-CPU; the
    // SMP trampoline only loads a transition GDT (no lidt), and the
    // BSP's IdtInit lidt'd only the BSP. Without this an AP has no
    // valid IDT, so the first interrupt it takes — the LAPIC timer
    // tick after SchedEnterOnAp's idle loop runs `sti` — #GPs reading
    // a bogus gate, escalates #GP -> #DF -> triple fault, and the AP
    // resets silently (no serial PANIC; the run just looks "hung").
    // qemu.log showed exactly this: v=0d e=0102 (IDT, vector 0x20)
    // -> v=08 -> Triple fault at the MWAIT idle loop. Must follow
    // LoadGdtForCurrent (gate CS = kKernelCodeSelector must resolve
    // in the now-active GDT) and precede the LAPIC enable below.
    IdtLoadForCurrent();

    // Enable the AP's LAPIC. IA32_APIC_BASE MSR bit 11 (EN) is the
    // global enable; bit 10 (EXTD) selects x2APIC mode. The BSP
    // already programmed EN|EXTD when it ran LapicInit and set
    // g_x2apic = true — every AP must match, or LapicWrite() (which
    // routes through the x2APIC MSR range 0x800.. when g_x2apic is
    // true) will #GP on the first TPR/SVR write below.
    //
    // The historic intermittency: QEMU's SIPI hand-off left the AP's
    // IA32_APIC_BASE in different states across runs — sometimes bit
    // 10 stayed set from the BSP-side configuration, sometimes it
    // didn't. The old "only set bit 11" path worked when EXTD happened
    // to be preserved and #GPd on the wrmsr 0x808 (TPR) when it
    // didn't. Now we unconditionally OR in the bits g_x2apic says
    // this kernel needs — idempotent if firmware already set them,
    // corrective if not. The LAPIC MMIO window is mapped in the
    // shared PML4 for the legacy xAPIC fallback.
    u32 lo, hi;
    asm volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(0x1Bu));
    const u64 apic_base = (static_cast<u64>(hi) << 32) | lo;
    const u64 want_bits = LapicIsX2apic() ? ((1ULL << 11) | (1ULL << 10)) : (1ULL << 11);
    if ((apic_base & want_bits) != want_bits)
    {
        const u64 enabled = apic_base | want_bits;
        const u32 elo = static_cast<u32>(enabled & 0xFFFFFFFF);
        const u32 ehi = static_cast<u32>(enabled >> 32);
        asm volatile("wrmsr" : : "c"(0x1Bu), "a"(elo), "d"(ehi));
    }
    LapicWrite(kLapicRegTpr, 0);
    LapicWrite(kLapicRegSvr, (1U << 8) | 0xFF);

    // Decode this AP's CPUID/SRAT topology BEFORE flipping the
    // online_flag, so the BSP's WaitForApOnline poll inside
    // SmpStartAps doubles as the rendezvous on AP topology init.
    // After SmpStartAps returns, the BSP runs TopologyAssignClusters
    // and every AP's row is already populated — no separate done flag.
    cpu::TopologyInitAp(cpu_id);

    // Signal BSP BEFORE logging — log path races with BSP's serial
    // writes and can delay arbitrarily on contention.
    TrampU32At(kOffOnlineFlag) = 1;

    core::LogWithValue(core::LogLevel::Info, "arch/smp", "AP online cpu_id", static_cast<u64>(cpu_id));
    KBP_PROBE_V(::duetos::debug::ProbeId::kSmpApOnline, cpu_id);

    // AP-bringup tracer. Raw SerialWrite so it's safe at the point
    // where the AP has its scheduler context but might still be
    // racing the BSP's klog rotation. Each step is a structural
    // boot-log sentinel — a missing line localises which step
    // wedged. Pairs with "[sched/idle] armed cpu_id=..." emitted
    // by SchedStartIdle on success. SerialLineGuard makes the
    // three Write*s atomic at the line level: without it, a peer
    // CPU's `LOADTEST:` / `[stress] pre  heap_used_KiB=` line could
    // grab `g_serial_lock` between our `[arch/smp] AP pre-enter
    // cpu_id=` and its hex/newline, splitting the line — observed
    // 2026-05-22 on `smp-stress-sweep.sh 8 8 5` SMP=8 repeat 1
    // as `LOADTEST:[arch/smp] AP pre-enter cpu_id= 0x...w[sched]`.
    {
        arch::SerialLineGuard guard;
        arch::SerialWrite("[arch/smp] AP pre-enter cpu_id=");
        arch::SerialWriteHex(static_cast<u64>(cpu_id));
        arch::SerialWrite("\n");
    }

    // Hand off to the scheduler. SchedEnterOnAp spawns this CPU's
    // idle task, mints a boot sentinel as current_task, arms this
    // CPU's LAPIC timer, and never returns. The first timer IRQ on
    // this CPU dispatches Schedule(); from then on the AP runs
    // tasks routed to it via t->last_cpu (commit-2 affinity) plus
    // any work stolen by the idle path (commit-6 work-stealing).
    sched::SchedEnterOnAp(cpu_id);
}

u64 SmpStartAps()
{
    KASSERT(acpi::CpuCount() > 0, "arch/smp", "MADT reported zero CPUs");

    // Copy the trampoline image into physical 0x8000. Frame allocator
    // has the low 1 MiB permanently reserved, so nobody else owns this
    // memory.
    const u64 tramp_len = static_cast<u64>(ap_trampoline_end - ap_trampoline_start);
    if (tramp_len > 0x1000)
    {
        // Build-time invariant violated. Debug: panic so the
        // bloat is caught at boot. Release: log it and return 0 —
        // the BSP keeps running uniprocessor instead of halting
        // the whole machine over an SMP-only feature.
        core::DebugPanicOrWarnWithValue("arch/smp", "trampoline image larger than 4 KiB", tramp_len);
        return 0;
    }
    auto* dst = static_cast<u8*>(TrampVirt());
    for (u64 i = 0; i < tramp_len; ++i)
    {
        dst[i] = ap_trampoline_start[i];
    }

    // Shared parameters: the PML4 phys + the C++ entry point VA.
    // BSP's CR3 points at the kernel's single PML4; APs share it so
    // every kernel VA maps the same bytes everywhere.
    TrampU64At(kOffPml4) = ReadCr3() & ~0xFFFULL;
    TrampU64At(kOffEntry) = reinterpret_cast<u64>(&ApEntryFromTrampoline);

    // GAP: legacy MADT LAPIC records carry only an 8-bit APIC ID,
    // so AP matching below is on the low 8 bits. Fine for every
    // current target (QEMU + <=255-thread boxes); x2APIC MADT
    // (type 9) parsing for >255 IDs is a separate follow-on.
    const u32 bsp_apic_id = LapicCurrentId();
    u64 aps_started = 0;

    for (u64 i = 0; i < acpi::CpuCount(); ++i)
    {
        const acpi::LapicRecord& rec = acpi::Lapic(i);
        if (rec.apic_id == bsp_apic_id)
        {
            continue;
        }
        if (!rec.enabled)
        {
            core::LogWithValue(core::LogLevel::Warn, "arch/smp", "skipping disabled AP apic_id",
                               static_cast<u64>(rec.apic_id));
            continue;
        }
        if (aps_started >= kMaxAps)
        {
            core::Log(core::LogLevel::Warn, "arch/smp", "AP slot limit reached; skipping remainder");
            break;
        }

        const u32 cpu_id = static_cast<u32>(aps_started + 1);

        // Allocate per-AP PerCpu struct.
        auto* ap_pcpu = static_cast<cpu::PerCpu*>(mm::KMalloc(sizeof(cpu::PerCpu)));
        if (ap_pcpu == nullptr)
        {
            // Per-AP allocation failed. Debug: panic. Release:
            // log and skip this AP — the BSP and any APs that
            // already came up keep running.
            core::DebugPanicOrWarn("arch/smp", "KMalloc failed for AP PerCpu");
            continue;
        }
        // KMalloc does not zero. Zero the whole struct up front so
        // every PerCpu field has a defined (0/nullptr/false) initial
        // value — the explicit field assignments below then set the
        // ones that need a non-zero value. This makes the init a
        // property ("all of PerCpu starts zeroed") rather than a
        // hand-maintained whitelist: a newly-added PerCpu field can
        // no longer be silently left as KMalloc garbage (this is
        // exactly how sched_tasks_reaped was being read uninitialised
        // by SchedSumReaped).
        memset(ap_pcpu, 0, sizeof(cpu::PerCpu));
        ap_pcpu->cpu_id = cpu_id;
        ap_pcpu->lapic_id = rec.apic_id;
        ap_pcpu->current_task = nullptr;
        ap_pcpu->current_as = nullptr; // boot PML4 — APs come up on the kernel AS
        ap_pcpu->need_resched = false;
        ap_pcpu->kernel_rsp = 0;
        ap_pcpu->user_rsp_scratch = 0;
        // Snapshot + held-lock bookkeeping. Already zeroed by the
        // memset above; kept explicit because a stale
        // `panic_snapshot_valid` making a peer CPU look snapshotted
        // when it hasn't been NMI'd is the highest-consequence field
        // here and is worth documenting at the init site.
        ap_pcpu->panic_snapshot_valid = 0;
        ap_pcpu->panic_snapshot_rip = 0;
        ap_pcpu->panic_snapshot_rsp = 0;
        ap_pcpu->panic_snapshot_task = nullptr;
        ap_pcpu->held_locks_count = 0;
        for (u32 hl = 0; hl < cpu::kPerCpuMaxHeldLocks; ++hl)
        {
            ap_pcpu->held_locks[hl] = nullptr;
            ap_pcpu->held_lock_rips[hl] = 0;
        }
        // GDB stop-rendezvous fields. Zero — peer hasn't been
        // NMI-frozen yet on this AP.
        ap_pcpu->gdb_frozen = 0;
        ap_pcpu->gdb_snapshot_rip = 0;
        ap_pcpu->gdb_snapshot_rsp = 0;
        ap_pcpu->gdb_snapshot_rflags = 0;
        ap_pcpu->gdb_frozen_frame = nullptr;
        // Lock-pass slot — empty until this AP enters Schedule().
        ap_pcpu->ctxsw_lock_to_release = nullptr;
        ap_pcpu->ctxsw_lock_flags = 0;
        // Deferred-zombie slot — empty until a task on this AP exits.
        ap_pcpu->ctxsw_dying_task_to_zombie = nullptr;
        // Per-CPU runqueue heads — empty until SchedEnterOnAp spawns
        // this AP's idle task and tasks migrate here via wake routing.
        ap_pcpu->runq_head_normal = nullptr;
        ap_pcpu->runq_tail_normal = nullptr;
        ap_pcpu->runq_head_idle = nullptr;
        ap_pcpu->runq_tail_idle = nullptr;
        ap_pcpu->runq_normal_len = 0;
        // TSS slot wired by AllocateApGdt below, before the AP runs.
        ap_pcpu->tss = nullptr;

        // Allocate this AP's GDT clone + TSS body + 3 IST stacks.
        // ApEntryFromTrampoline picks them up via g_ap_gdt_bundles
        // and loads them via LoadGdtForCurrent before enabling LAPIC.
        ApGdtBundle* bundle = AllocateApGdt(ap_pcpu);
        if (bundle == nullptr)
        {
            core::DebugPanicOrWarn("arch/smp", "AllocateApGdt failed");
            mm::KFree(ap_pcpu);
            g_ap_percpus[cpu_id] = nullptr;
            continue;
        }
        g_ap_gdt_bundles[cpu_id] = bundle;
        g_ap_percpus[cpu_id] = ap_pcpu;
        if (cpu_id + 1 > g_cpu_id_limit)
        {
            g_cpu_id_limit = cpu_id + 1;
        }

        // Per-AP 16 KiB stack. The trampoline loads RSP with stack_top
        // (= stack_base + size) so we pass that.
        constexpr u64 kApStackBytes = 16 * 1024;
        auto* stack = static_cast<u8*>(mm::KMalloc(kApStackBytes));
        if (stack == nullptr)
        {
            // Per-AP stack allocation failed. Debug: panic.
            // Release: undo the PerCpu we just allocated and skip
            // this AP. Slightly-higher g_cpu_id_limit is harmless
            // — bounded loops just iterate over an empty slot.
            core::DebugPanicOrWarn("arch/smp", "KMalloc failed for AP stack");
            g_ap_percpus[cpu_id] = nullptr;
            mm::KFree(ap_pcpu);
            continue;
        }
        TrampU64At(kOffStack) = reinterpret_cast<u64>(stack + kApStackBytes);
        TrampU32At(kOffCpuId) = cpu_id;
        TrampU32At(kOffOnlineFlag) = 0;

        core::LogWithValue(core::LogLevel::Info, "arch/smp", "starting AP apic_id", static_cast<u64>(rec.apic_id));

        // INIT IPI (assert). Per Intel SDM Vol. 3A §8.4.4.
        SmpSendIpi(rec.apic_id, kIcrDeliveryInit | kIcrLevelAssert);

        // 10 ms wait — SchedSleepTicks(1) at 100 Hz. Interrupts must
        // be enabled for this (the wait path uses the timer-driven
        // sleep queue); SmpStartAps runs after TimerInit so that's fine.
        sched::SchedSleepTicks(1);

        // SIPI with vector = trampoline_phys >> 12 = 0x08.
        const u32 sipi = kIcrDeliveryStartup | (kTrampolinePhys >> 12);
        SmpSendIpi(rec.apic_id, sipi);

        if (!WaitForApOnline())
        {
            // Intel recommends a second SIPI if the first doesn't take.
            SmpSendIpi(rec.apic_id, sipi);
            if (!WaitForApOnline())
            {
                core::LogWithValue(core::LogLevel::Error, "arch/smp", "AP never signalled online, giving up",
                                   static_cast<u64>(rec.apic_id));
                continue;
            }
        }

        ++aps_started;
        ++g_cpus_online;
    }

    // Structural sentinel — ONE atomic SerialWrite so it stays a
    // clean, greppable line. The klog tally below renders as
    // several SerialWrite fragments (timestamp/level/tag/msg/val)
    // and the just-onlined APs print their own online/probe lines
    // concurrently in this window, so the klog form reliably
    // interleaves and is NOT reliably parseable. A single
    // SerialWrite of a pre-built buffer takes g_serial_lock once
    // for the whole line and cannot be split. CI + the boot-log /
    // determinism rigs grep this for the authoritative SMP count.
    {
        const u64 online = g_cpus_online;
        const u64 total = acpi::CpuCount();
        char buf[40];
        u32 n = 0;
        // Lead with '\n' so a partial klog fragment another CPU
        // left dangling (no newline yet) is terminated and this
        // sentinel always starts at column 0 — whole-line greps,
        // not just substring, then find it.
        buf[n++] = '\n';
        const char* p = "[smp] online=";
        while (*p)
            buf[n++] = *p++;
        auto put = [&](u64 v)
        {
            char t[20];
            u32 k = 0;
            do
            {
                t[k++] = static_cast<char>('0' + (v % 10));
                v /= 10;
            } while (v != 0);
            while (k > 0)
                buf[n++] = t[--k];
        };
        put(online);
        buf[n++] = '/';
        put(total);
        buf[n++] = '\n';
        buf[n] = '\0';
        SerialWrite(buf);
    }

    core::LogWithValue(core::LogLevel::Info, "arch/smp", "SMP bring-up complete, cpus_online", g_cpus_online);
    return aps_started;
}

} // namespace duetos::arch
