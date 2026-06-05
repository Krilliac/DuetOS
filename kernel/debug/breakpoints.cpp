/*
 * DuetOS — kernel breakpoint subsystem: implementation.
 *
 * Companion to breakpoints.h — see there for the phased v0
 * roadmap (per-task DR state, suspend/inspect/resume/step,
 * static KBP_PROBE macros, kCapDebug gating).
 *
 * WHAT
 *   Hardware-DR-backed breakpoints exposed both as a kernel-
 *   internal probe API (`KBP_PROBE` macros — code-armed traps
 *   that take a struct dump on hit) and as a syscall surface
 *   (SYS_BP_*). Per-task DR state stays with each Task and is
 *   reloaded on context switch.
 *
 * HOW
 *   `BpArm` writes DR0..DR3 + DR7 enable bits for the calling
 *   task. On #DB, the trap dispatcher (traps.cpp) calls into
 *   here to look up which probe fired and run its callback
 *   (suspend / log / step) without leaving ring 0.
 *
 *   Static probes use the KBP_PROBE_* macros: at compile time
 *   they emit a row in a `.kbp_probes` section the linker
 *   gathers; at boot, `BpScanStaticProbes` walks the section
 *   and arms each enabled probe. Disabled probes cost only
 *   that section row (a few bytes).
 */

#include "debug/breakpoints.h"

#include "arch/x86_64/smp.h"
#include "log/klog.h"
#include "proc/process.h"
#include "mm/address_space.h"
#include "mm/frame_allocator.h"
#include "mm/page.h"
#include "mm/paging.h"
#include "sched/sched.h"
#include "sync/spinlock.h"
#include "debug/dr.h"
#include "util/symbols.h"

// Embedded kernel symbol table — see util/symbols.cpp for the
// public ResolveAddress path. We reach the externs directly only
// for the bulk walk that seeds g_unsafe at boot. Declared here
// at file scope (above the `namespace duetos::debug` opening) so
// the qualified `duetos::core::g_duetos_symtab_*` names resolve
// against the global root, not against the enclosing debug
// namespace.
namespace duetos::core
{
extern "C" const SymbolEntry g_duetos_symtab_entries[];
extern "C" const u64 g_duetos_symtab_count;
} // namespace duetos::core

namespace duetos::debug
{

namespace
{

constexpr usize kMaxSwSlots = 16;
constexpr usize kMaxHwSlots = 4; // DR0..DR3

// Linker-provided kernel .text bounds — used to reject a software
// BP request that would land outside the executable image.
extern "C" u8 _text_start[];
extern "C" u8 _text_end[];

struct BpEntry
{
    u32 id; // 0 = slot free
    BpKind kind;
    BpLen len;
    u8 hw_slot; // 0..3 for hardware, 0xFF for software
    bool suspend_on_hit;
    u64 address;
    u64 hit_count;
    u64 owner_pid; // 0 = kernel-owned (shell / panic / self-test)
    u8 orig_byte;  // software BPs: the byte we overwrote with 0xCC

    // Phase 3: suspend-on-hit state. When a task hits this BP
    // (and suspend_on_hit is true + the hit is from ring 3), we
    // block it on `wq`, stash its task id + trap-frame pointer
    // + AddressSpace here, and the scheduler carries on with
    // other ready tasks. The shell's `bp regs / mem / resume /
    // step` commands read through these fields.
    // `stopped_task_id == 0` means no task is currently parked
    // on this BP. The AS pointer captures the target's user
    // pages for `bp mem` to read through without needing a
    // public task-by-id lookup in the scheduler.
    sched::WaitQueue wq;
    u64 stopped_task_id;
    arch::TrapFrame* stopped_frame;
    mm::AddressSpace* stopped_as;

    // Optional trap-context callback fired on hit (after the
    // reinsert / accounting). Used by the GDB stub to enter the
    // stop loop on a hit; nullptr for normal kernel-installed
    // BPs. Stored as a plain function pointer (no captures) to
    // keep the hot path branch-free when unused.
    BpHitCallback on_hit;
};

// Tagged with `kLockClassBreakpoints` for lockdep.
sync::SpinLock g_lock{
    .next_ticket = 0, .now_serving = 0, .owner_cpu = 0xFFFFFFFFu, .class_id = sync::kLockClassBreakpoints};
BpEntry g_sw_table[kMaxSwSlots]{};
BpEntry g_hw_table[kMaxHwSlots]{};
u32 g_next_id = 1;
bool g_inited = false;

// Single-step reinsertion state. Populated by HandleBreakpoint when
// a SW BP fires; consumed by HandleDebug on the following #DB that
// the set-TF raises. Phase 1 is single-CPU, so one pending reinsert
// slot suffices; a second SW BP hit while reinsert is pending is a
// reentrancy bug and gets logged + dropped.
struct ReinsertSlot
{
    bool pending;
    u64 addr;
    u8 orig_byte;
};
ReinsertSlot g_reinsert{};

// Phase 3 stepping state. Set by BpStep when the operator wants
// to advance one instruction and re-suspend; consumed by the #DB
// handler on the following single-step trap. Single slot matches
// the single-CPU assumption; the scheduler can still run unrelated
// tasks while this one is stopped (they just won't be stepping).
struct SteppingSlot
{
    u64 task_id; // 0 = no stepping session active
    u32 bp_id;
};
SteppingSlot g_stepping{};

// Re-entrancy depth for the trap-handler entry points. A non-zero
// value means a BP fired while we were already inside one of the
// handlers on this CPU — the cause is almost always a BP attached
// to a function the handler itself reaches (klog, the symbol
// resolver, the allocator). The unsafe-zone install gate
// catches this at install time for the common cases; the
// counter is the backstop for paths the gate doesn't know
// about (HW write watches, AllowUnsafe overrides). Phase 1 is
// single-CPU, so a plain int suffices; v0 SMP grows this to a
// per-CPU array.
u32 g_handler_depth = 0;

bool IsInKernelText(u64 va)
{
    const u64 lo = reinterpret_cast<u64>(_text_start);
    const u64 hi = reinterpret_cast<u64>(_text_end);
    return va >= lo && va < hi;
}

// Patch a single byte in kernel .text. Flips the containing 4 KiB
// page writable, writes the byte, flips it back to R+X. Caller
// MUST hold g_lock. Phase 1 single-CPU — other CPUs executing
// from this page during the W window are not a concern because
// there are no other CPUs.
void PokeByte(u64 va, u8 byte)
{
    const u64 page = va & ~0xFFFULL;
    mm::SetPteFlags4K(page, mm::kPagePresent | mm::kPageWritable);
    *reinterpret_cast<volatile u8*>(va) = byte;
    // Serialise so a subsequent instruction fetch on this CPU
    // picks up the new byte. iretq at the end of the trap
    // handler is itself a serialising instruction, but add mfence
    // defensively — the window between PokeByte and iretq could
    // otherwise include speculative fetches of the old line.
    asm volatile("mfence" ::: "memory");
    mm::SetPteFlags4K(page, mm::kPagePresent);
}

u8 PeekByte(u64 va)
{
    return *reinterpret_cast<volatile u8*>(va);
}

BpEntry* FindSwByAddr(u64 va)
{
    for (auto& e : g_sw_table)
    {
        if (e.id != 0 && e.address == va)
            return &e;
    }
    return nullptr;
}

BpEntry* FindSwById(u32 id)
{
    for (auto& e : g_sw_table)
    {
        if (e.id == id)
            return &e;
    }
    return nullptr;
}

BpEntry* FindHwBySlot(u8 slot)
{
    for (auto& e : g_hw_table)
    {
        if (e.id != 0 && e.hw_slot == slot)
            return &e;
    }
    return nullptr;
}

BpEntry* FindHwById(u32 id)
{
    for (auto& e : g_hw_table)
    {
        if (e.id == id)
            return &e;
    }
    return nullptr;
}

BpEntry* AllocSwSlot()
{
    for (auto& e : g_sw_table)
    {
        if (e.id == 0)
            return &e;
    }
    return nullptr;
}

// Returns an empty slot id 0..3, or -1 if all four DRs are taken.
int AllocHwSlot()
{
    for (u8 s = 0; s < kMaxHwSlots; ++s)
    {
        if (FindHwBySlot(s) == nullptr)
            return int(s);
    }
    return -1;
}

void WriteDrNumber(u8 slot, u64 addr)
{
    switch (slot)
    {
    case 0:
        dr::WriteDr0(addr);
        break;
    case 1:
        dr::WriteDr1(addr);
        break;
    case 2:
        dr::WriteDr2(addr);
        break;
    case 3:
        dr::WriteDr3(addr);
        break;
    default:
        // Hardware has DR0..DR3 only — slot >= 4 is a caller bug.
        KLOG_ONCE_WARN("debug/bp", "WriteDrNumber called with slot >= 4 (no DR register exists)");
        break;
    }
}

void ApplyDrSlot(u8 slot, u64 addr, u64 rw, u64 len)
{
    WriteDrNumber(slot, addr);
    u64 dr7 = dr::ReadDr7();
    // Clear the slot's R/W + LEN nibble, then OR the new bits.
    dr7 &= ~dr::Dr7SlotMask(slot);
    dr7 |= dr::MakeDr7SlotBits(slot, rw, len);
    // Enable the slot (Local-enable) and set the reserved MBS bit.
    dr7 |= dr::Dr7SlotEnableBit(slot) | dr::kDr7Mbs;
    dr::WriteDr7(dr7);
}

void ClearDrSlot(u8 slot)
{
    WriteDrNumber(slot, 0);
    u64 dr7 = dr::ReadDr7();
    dr7 &= ~dr::Dr7SlotMask(slot);
    dr7 &= ~dr::Dr7SlotEnableBit(slot);
    dr::WriteDr7(dr7);
}

u64 KindToRw(BpKind k)
{
    switch (k)
    {
    case BpKind::HwWrite:
        return dr::kDr7RwWrite;
    case BpKind::HwReadWrite:
        return dr::kDr7RwReadWrite;
    case BpKind::HwExecute:
    case BpKind::Software:
    default:
        return dr::kDr7RwExecute;
    }
}

u64 LenToDr7(BpLen l)
{
    switch (l)
    {
    case BpLen::One:
        return dr::kDr7Len1;
    case BpLen::Two:
        return dr::kDr7Len2;
    case BpLen::Four:
        return dr::kDr7Len4;
    case BpLen::Eight:
        return dr::kDr7Len8;
    default:
        return dr::kDr7Len1;
    }
}

// ------------------ Safety: unsafe-zone blocklist ------------
//
// A BP fired inside the trap dispatcher / klog / heap / scheduler
// / panic / spinlock primitives recurses into its own handler
// (logging, suspension, stack-frame inspection — all of those
// reach the very paths the BP is attached to). The result is
// triple-fault on UP, SMP-wide deadlock on multi-CPU, or a klog
// flood drowning the serial console. To cut that off at install
// time we resolve a curated list of demangled symbol-name
// substrings against the embedded `.symtab` at BpInit and cache
// each match's [addr, addr+size) range. Operators who knowingly
// want to BP a critical path pass `BpInstallFlags::AllowUnsafe`.
//
// The list is a compromise:
//   * Aggressive enough to catch the common footguns (the
//     dispatcher, the panic path, the symbol resolver, the
//     allocator, the scheduler core, the serial writer).
//   * Conservative on substring matches — exact `BpHandle...`
//     and unique tokens like `Schedule(` / `Panic(` only.
//     Vague tokens (`Init`, `Read`) would over-block.
//
// Phase-2 work: graduate to a build-script-emitted list (cheap to
// extend, no name fragility), add operator-extensible runtime
// `dbg bp unsafe-add <addr> <name>` for site-specific lockouts.

constexpr usize kMaxUnsafeRanges = 128;

struct UnsafeRangeSlot
{
    u64 lo;
    u64 hi;
    const char* name;
};

UnsafeRangeSlot g_unsafe[kMaxUnsafeRanges]{};
usize g_unsafe_count = 0;

bool SubstringMatch(const char* hay, const char* needle)
{
    if (hay == nullptr || needle == nullptr)
        return false;
    for (u32 i = 0; hay[i] != 0; ++i)
    {
        u32 j = 0;
        while (needle[j] != 0 && hay[i + j] == needle[j])
            ++j;
        if (needle[j] == 0)
            return true;
    }
    return false;
}

// Curated list of demangled-name substrings that mark a function
// the BP handler itself reaches. Order matters only for the log
// readability — we record every match. Substrings must be
// distinctive enough not to over-match common helpers.
const char* const kUnsafeSubstrings[] = {
    // The breakpoint subsystem itself — fires on every BP.
    "BpHandleBreakpoint",
    "BpHandleDebug",
    "BpReadRegs",
    "BpReadMem",
    "BpResume",
    "BpStep",

    // Symbol resolution — used by the BP-hit log line and the
    // panic dump.
    "ResolveAddress",
    "WriteResolvedAddress",
    "WriteAddressWithSymbol",

    // Logging primitives — every diagnostic the BP handler emits
    // routes through these.
    "SerialWrite",
    "SerialWriteByte",
    "KlogEmit",
    "KlogWrite",

    // Panic + trap dispatch — recursion here means we can't
    // even report the recursion.
    "TrapDispatch",
    "Panic",
    "isr_common",
    "PageFaultHandler",

    // Scheduler / context switch / lock primitives — suspend-on-
    // hit while holding sched/lock state deadlocks the box.
    "Schedule(",
    "ContextSwitch",
    "SpinLockAcquire",
    "SpinLockRelease",

    // Memory allocators — BP handler may log + allocate.
    "KMalloc",
    "KFree",
    "AllocateFrame",
};

// Walk the embedded symbol table, populate `g_unsafe` with every
// row whose demangled name contains any of the curated tokens.
// Called from BpInit (after the lock is held). Idempotent —
// safe to call multiple times; subsequent calls reset the table.
void PopulateUnsafeRanges()
{
    g_unsafe_count = 0;
    const u64 total = core::SymbolTableSize();
    if (total == 0)
        return; // stage-1 build with no embedded symbols
    constexpr u32 kSubstringCount = sizeof(kUnsafeSubstrings) / sizeof(kUnsafeSubstrings[0]);

    const auto* entries = core::g_duetos_symtab_entries;
    const u64 count = core::g_duetos_symtab_count;
    for (u64 i = 0; i < count && g_unsafe_count < kMaxUnsafeRanges; ++i)
    {
        const auto& e = entries[i];
        if (e.size == 0)
            continue;
        for (u32 k = 0; k < kSubstringCount; ++k)
        {
            if (SubstringMatch(e.name, kUnsafeSubstrings[k]))
            {
                g_unsafe[g_unsafe_count].lo = e.addr;
                g_unsafe[g_unsafe_count].hi = e.addr + e.size;
                g_unsafe[g_unsafe_count].name = e.name;
                ++g_unsafe_count;
                break;
            }
        }
    }
    KLOG_INFO_V("debug/bp", "unsafe-zone ranges populated: count=", g_unsafe_count);
    if (g_unsafe_count == kMaxUnsafeRanges)
    {
        // Hitting the cap means the curated substring list matched
        // more symbols than the table can hold; some critical paths
        // are unprotected at install time. The re-entrancy guard
        // still backstops them, but operators should bump the cap
        // in a follow-up slice.
        KLOG_WARN("debug/bp", "unsafe-zone table FULL — some critical paths unprotected at install time");
    }
}

bool InUnsafeRange(u64 va) /* MUST hold g_lock */
{
    for (usize i = 0; i < g_unsafe_count; ++i)
    {
        if (va >= g_unsafe[i].lo && va < g_unsafe[i].hi)
            return true;
    }
    return false;
}

} // namespace

void BpInit()
{
    sync::SpinLockGuard g(g_lock);
    if (g_inited)
        return;
    for (auto& e : g_sw_table)
    {
        e.id = 0;
        e.wq = sched::WaitQueue{};
        e.stopped_task_id = 0;
        e.stopped_frame = nullptr;
        e.stopped_as = nullptr;
    }
    for (auto& e : g_hw_table)
    {
        e.id = 0;
        e.wq = sched::WaitQueue{};
        e.stopped_task_id = 0;
        e.stopped_frame = nullptr;
        e.stopped_as = nullptr;
    }
    g_next_id = 1;
    g_reinsert.pending = false;
    g_stepping.task_id = 0;
    g_stepping.bp_id = 0;
    // Clear the DR state to a known baseline. All slots disabled,
    // MBS bit set (required by the architecture), DR6 reset to
    // its power-on value so stale status bits don't surface as
    // phantom hits.
    dr::WriteDr7(dr::kDr7Mbs);
    dr::WriteDr0(0);
    dr::WriteDr1(0);
    dr::WriteDr2(0);
    dr::WriteDr3(0);
    dr::WriteDr6(dr::kDr6InitValue);
    PopulateUnsafeRanges();
    g_inited = true;
    KLOG_INFO("debug/bp", "breakpoint subsystem online");
}

bool BpAddressInUnsafeZone(u64 va)
{
    sync::SpinLockGuard g(g_lock);
    return InUnsafeRange(va);
}

usize BpUnsafeRangesList(BpUnsafeRange* out, usize cap)
{
    if (out == nullptr || cap == 0)
        return 0;
    sync::SpinLockGuard g(g_lock);
    const usize n = (g_unsafe_count < cap) ? g_unsafe_count : cap;
    for (usize i = 0; i < n; ++i)
    {
        out[i].lo = g_unsafe[i].lo;
        out[i].hi = g_unsafe[i].hi;
        out[i].name = g_unsafe[i].name;
    }
    return n;
}

void BpTeardown()
{
    sync::SpinLockGuard g(g_lock);
    if (!g_inited)
        return;
    // Disarm all hardware breakpoint slots — DR7 to MBS-only with
    // every L0..L3 / G0..G3 enable bit cleared, then zero each
    // address register so a stale virtual address can't survive an
    // accidental DR7 re-enable. Mirrors the BpInit baseline.
    dr::WriteDr7(dr::kDr7Mbs);
    dr::WriteDr0(0);
    dr::WriteDr1(0);
    dr::WriteDr2(0);
    dr::WriteDr3(0);
    // Drop every software / hardware table entry. Software
    // breakpoints leave behind int3 patches in the .text bytes
    // they targeted; the table loses the original-byte record
    // here, so a later BpInit + new install at the same VA would
    // observe an int3 in place of the original instruction. v0
    // accepts that — restartable breakpoints are a debugger-only
    // surface and the operator is expected to manually
    // unregister the old IDs first via BpRemove. Real Linux's
    // perf_event subsystem has the same caveat.
    for (auto& e : g_sw_table)
    {
        e.id = 0;
        e.wq = sched::WaitQueue{};
        e.stopped_task_id = 0;
        e.stopped_frame = nullptr;
        e.stopped_as = nullptr;
    }
    for (auto& e : g_hw_table)
    {
        e.id = 0;
        e.wq = sched::WaitQueue{};
        e.stopped_task_id = 0;
        e.stopped_frame = nullptr;
        e.stopped_as = nullptr;
    }
    g_next_id = 1;
    g_reinsert.pending = false;
    g_stepping.task_id = 0;
    g_stepping.bp_id = 0;
    g_inited = false;
    KLOG_INFO("debug/bp", "breakpoint subsystem offline");
}

BreakpointId BpInstallSoftware(u64 kernel_va, bool suspend_on_hit, BpError* err, BpHitCallback on_hit,
                               BpInstallFlags flags)
{
    auto set_err = [&](BpError e)
    {
        if (err)
            *err = e;
    };
    if (!IsInKernelText(kernel_va))
    {
        set_err(BpError::InvalidAddress);
        return kBpIdNone;
    }
    if (arch::SmpCpusOnline() != 1)
    {
        set_err(BpError::SmpUnsupported);
        return kBpIdNone;
    }
    sync::SpinLockGuard g(g_lock);
    const bool allow_unsafe = (static_cast<u8>(flags) & static_cast<u8>(BpInstallFlags::AllowUnsafe)) != 0;
    if (!allow_unsafe && InUnsafeRange(kernel_va))
    {
        KLOG_WARN_V("debug/bp", "SW BP refused (unsafe zone) addr=", kernel_va);
        set_err(BpError::UnsafeZone);
        return kBpIdNone;
    }
    if (FindSwByAddr(kernel_va) != nullptr)
    {
        set_err(BpError::InvalidAddress); // already installed
        return kBpIdNone;
    }
    BpEntry* slot = AllocSwSlot();
    if (slot == nullptr)
    {
        set_err(BpError::TableFull);
        return kBpIdNone;
    }
    slot->id = g_next_id++;
    slot->kind = BpKind::Software;
    slot->len = BpLen::One;
    slot->hw_slot = 0xFF;
    slot->suspend_on_hit = suspend_on_hit;
    slot->address = kernel_va;
    slot->owner_pid = 0; // SW BPs are kernel-scope only in phase 2a
    slot->orig_byte = PeekByte(kernel_va);
    slot->hit_count = 0;
    slot->wq = sched::WaitQueue{};
    slot->stopped_task_id = 0;
    slot->stopped_frame = nullptr;
    slot->stopped_as = nullptr;
    slot->on_hit = on_hit;
    PokeByte(kernel_va, 0xCC);
    KLOG_INFO_2V("debug/bp", "SW BP installed", "addr", kernel_va, "id", slot->id);
    set_err(BpError::None);
    return {slot->id};
}

BreakpointId BpInstallHardware(u64 va, BpKind kind, BpLen len, u64 owner_pid, bool suspend_on_hit, BpError* err,
                               BpHitCallback on_hit, BpInstallFlags flags)
{
    auto set_err = [&](BpError e)
    {
        if (err)
            *err = e;
    };
    if (kind == BpKind::Software)
    {
        set_err(BpError::BadKind);
        return kBpIdNone;
    }
    if (kind == BpKind::HwExecute && len != BpLen::One)
    {
        set_err(BpError::BadKind);
        return kBpIdNone;
    }
    // Phase 2: HW breakpoints ride per-task DR state through
    // context switches, so SMP is safe without an IPI shootdown —
    // each CPU re-loads the running task's DRs on every switch-in.
    sync::SpinLockGuard g(g_lock);
    // The unsafe-zone gate applies to HwExecute targets only:
    // a Hw-write or Hw-read-write watch on a kernel data region
    // doesn't fire instruction-fetch recursion. (Suspend-on-hit
    // for a hot data slot is still a footgun, but a different
    // class — operator can disarm or remove the BP.)
    const bool allow_unsafe = (static_cast<u8>(flags) & static_cast<u8>(BpInstallFlags::AllowUnsafe)) != 0;
    if (!allow_unsafe && kind == BpKind::HwExecute && InUnsafeRange(va))
    {
        KLOG_WARN_V("debug/bp", "HW exec BP refused (unsafe zone) addr=", va);
        set_err(BpError::UnsafeZone);
        return kBpIdNone;
    }
    int s = AllocHwSlot();
    if (s < 0)
    {
        set_err(BpError::NoHwSlot);
        return kBpIdNone;
    }
    BpEntry* e = nullptr;
    for (auto& entry : g_hw_table)
    {
        if (entry.id == 0)
        {
            e = &entry;
            break;
        }
    }
    if (e == nullptr)
    {
        // Table full even though a slot was free — shouldn't
        // happen given kMaxHwSlots == 4 and the slot allocator
        // only answers yes when an entry is free, but the two
        // invariants aren't locked together so be defensive.
        set_err(BpError::TableFull);
        return kBpIdNone;
    }
    e->id = g_next_id++;
    e->kind = kind;
    e->len = len;
    e->hw_slot = u8(s);
    e->suspend_on_hit = suspend_on_hit;
    e->address = va;
    e->owner_pid = owner_pid;
    e->hit_count = 0;
    e->wq = sched::WaitQueue{};
    e->stopped_task_id = 0;
    e->stopped_frame = nullptr;
    e->stopped_as = nullptr;
    e->on_hit = on_hit;
    ApplyDrSlot(u8(s), va, KindToRw(kind), LenToDr7(len));
    KLOG_INFO_2V("debug/bp", "HW BP installed", "addr", va, "id", e->id);
    set_err(BpError::None);
    return {e->id};
}

BpError BpRemove(BreakpointId id, u64 requester_pid)
{
    if (id.value == 0)
        return BpError::NotInstalled;
    sync::SpinLockGuard g(g_lock);
    BpEntry* sw = FindSwById(id.value);
    if (sw != nullptr)
    {
        // Cross-owner guard: a ring-3 caller (requester_pid != 0)
        // cannot remove a BP it doesn't own. Kernel-scope removal
        // (requester_pid == 0) is always allowed — that's the
        // shell, the self-test, and process-exit cleanup.
        if (requester_pid != 0 && sw->owner_pid != requester_pid)
            return BpError::NotInstalled;
        // Auto-wake any task parked on this BP so it doesn't
        // strand on a dead queue.
        if (sw->stopped_task_id != 0)
        {
            sched::WaitQueueWakeAll(&sw->wq);
            sw->stopped_task_id = 0;
            sw->stopped_frame = nullptr;
            sw->stopped_as = nullptr;
        }
        PokeByte(sw->address, sw->orig_byte);
        KLOG_INFO_V("debug/bp", "SW BP removed id", sw->id);
        sw->id = 0;
        return BpError::None;
    }
    BpEntry* hw = FindHwById(id.value);
    if (hw != nullptr)
    {
        if (requester_pid != 0 && hw->owner_pid != requester_pid)
            return BpError::NotInstalled;
        if (hw->stopped_task_id != 0)
        {
            sched::WaitQueueWakeAll(&hw->wq);
            hw->stopped_task_id = 0;
            hw->stopped_frame = nullptr;
            hw->stopped_as = nullptr;
        }
        ClearDrSlot(hw->hw_slot);
        KLOG_INFO_V("debug/bp", "HW BP removed id", hw->id);
        hw->id = 0;
        return BpError::None;
    }
    return BpError::NotInstalled;
}

// ------------------ Phase 3: resume + step + inspect --------

// Forward decls — definitions lower in the file, after the public
// API. FindById and ResolveStoppedUserByte are namespace-scope
// helpers (not anon) because they get called from BpReadRegs /
// BpResume / BpStep / BpReadMem which also live at namespace
// scope. MaybeSuspend ditto.
BpEntry* FindById(u32 id);
const u8* ResolveStoppedUserByte(BpEntry* e, u64 user_va);
void MaybeSuspend(u32 bp_id, arch::TrapFrame* frame);

bool BpReadRegs(BreakpointId id, arch::TrapFrame* out)
{
    if (id.value == 0 || out == nullptr)
        return false;
    sync::SpinLockGuard g(g_lock);
    BpEntry* e = FindById(id.value);
    if (e == nullptr || e->stopped_frame == nullptr)
        return false;
    // Byte-copy the frame. No memcpy to avoid pulling in a
    // freestanding dependency.
    const u8* src = reinterpret_cast<const u8*>(e->stopped_frame);
    u8* dst = reinterpret_cast<u8*>(out);
    for (usize i = 0; i < sizeof(arch::TrapFrame); ++i)
        dst[i] = src[i];
    return true;
}

BpError BpWriteRegs(BreakpointId id, const arch::TrapFrame* in)
{
    if (id.value == 0 || in == nullptr)
        return BpError::NotInstalled;
    sync::SpinLockGuard g(g_lock);
    BpEntry* e = FindById(id.value);
    if (e == nullptr || e->stopped_frame == nullptr || e->stopped_task_id == 0)
        return BpError::NotInstalled;
    arch::TrapFrame* tf = e->stopped_frame;

    // GPRs transfer verbatim.
    tf->rax = in->rax;
    tf->rbx = in->rbx;
    tf->rcx = in->rcx;
    tf->rdx = in->rdx;
    tf->rsi = in->rsi;
    tf->rdi = in->rdi;
    tf->rbp = in->rbp;
    tf->r8 = in->r8;
    tf->r9 = in->r9;
    tf->r10 = in->r10;
    tf->r11 = in->r11;
    tf->r12 = in->r12;
    tf->r13 = in->r13;
    tf->r14 = in->r14;
    tf->r15 = in->r15;
    tf->rip = in->rip;
    tf->rsp = in->rsp;

    // RFLAGS sanitisation — same shape as SYS_THREAD_SET_CONTEXT
    // (kernel/syscall/syscall.cpp around the SetContext handler).
    // Force IF=1 (otherwise the target wakes with interrupts off
    // and the next timer tick deadlocks), force IOPL=0 (no port-
    // IO privilege gift), clear NT (no nested-task chains) and TF
    // (no surprise single-step). Operator-chosen arithmetic /
    // comparison flags pass through.
    constexpr u64 kRflagsIf = 1ULL << 9;
    constexpr u64 kRflagsTf = 1ULL << 8;
    constexpr u64 kRflagsNt = 1ULL << 14;
    constexpr u64 kRflagsIoplMask = 0x3ULL << 12;
    u64 new_flags = in->rflags;
    new_flags |= kRflagsIf;
    new_flags &= ~(kRflagsTf | kRflagsNt | kRflagsIoplMask);
    tf->rflags = new_flags;

    // Force ring-3 selectors. A malicious operator (or a buggy
    // GUI binding edit-fields to wide ints) passing kernel
    // selectors would otherwise iretq into ring 0 on resume.
    tf->cs = 0x2B; // kUserCodeSelector — matches syscall.cpp
    tf->ss = 0x33; // kUserDataSelector

    return BpError::None;
}

// Walk the stopped task's captured AddressSpace to find the
// physical frame backing a given user VA, returning a kernel
// direct-map pointer into that frame. Returns nullptr if the
// page isn't mapped or no AS was captured (kernel-only BPs).
const u8* ResolveStoppedUserByte(BpEntry* e, u64 user_va) /* MUST hold g_lock */
{
    if (e == nullptr || e->stopped_as == nullptr)
        return nullptr;
    const u64 page_va = user_va & ~0xFFFULL;
    mm::PhysAddr frame = mm::AddressSpaceLookupUserFrame(e->stopped_as, page_va);
    if (frame == mm::kNullFrame)
        return nullptr;
    const u8* page = static_cast<const u8*>(mm::PhysToVirt(frame));
    return page + (user_va & 0xFFF);
}

u64 BpReadMem(BreakpointId id, u64 user_va, u8* out, u64 len)
{
    if (id.value == 0 || out == nullptr || len == 0)
        return 0;
    sync::SpinLockGuard g(g_lock);
    BpEntry* e = FindById(id.value);
    if (e == nullptr || e->stopped_task_id == 0)
        return 0;
    u64 copied = 0;
    while (copied < len)
    {
        const u8* src = ResolveStoppedUserByte(e, user_va + copied);
        if (src == nullptr)
            break;
        // Copy up to the end of the current 4 KiB page in one chunk.
        const u64 page_off = (user_va + copied) & 0xFFFULL;
        const u64 page_room = 0x1000 - page_off;
        u64 chunk = len - copied;
        if (chunk > page_room)
            chunk = page_room;
        for (u64 i = 0; i < chunk; ++i)
            out[copied + i] = src[i];
        copied += chunk;
    }
    return copied;
}

BpError BpResume(BreakpointId id)
{
    if (id.value == 0)
        return BpError::NotInstalled;
    sync::SpinLockGuard g(g_lock);
    BpEntry* e = FindById(id.value);
    if (e == nullptr || e->stopped_task_id == 0)
        return BpError::NotInstalled;
    // WaitQueueWakeOne returns the Task* that was woken; we don't
    // need it here. The stopped_task_id field is cleared by the
    // resuming task itself when it returns from MaybeSuspend.
    sched::WaitQueueWakeOne(&e->wq);
    return BpError::None;
}

BpError BpStep(BreakpointId id)
{
    if (id.value == 0)
        return BpError::NotInstalled;
    sync::SpinLockGuard g(g_lock);
    BpEntry* e = FindById(id.value);
    if (e == nullptr || e->stopped_task_id == 0 || e->stopped_frame == nullptr)
        return BpError::NotInstalled;
    // Arm single-step on the resumed task's frame. Also record
    // the stepping session so the next #DB re-suspends on this
    // same BP instead of falling through to IsolateTask.
    e->stopped_frame->rflags |= 0x100ULL;
    g_stepping.task_id = e->stopped_task_id;
    g_stepping.bp_id = id.value;
    sched::WaitQueueWakeOne(&e->wq);
    return BpError::None;
}

usize BpList(BpInfo* out, usize cap)
{
    if (out == nullptr || cap == 0)
        return 0;
    sync::SpinLockGuard g(g_lock);
    usize written = 0;
    auto emit = [&](const BpEntry& e)
    {
        if (e.id == 0 || written >= cap)
            return;
        BpInfo& info = out[written++];
        info.id = {e.id};
        info.kind = e.kind;
        info.len = e.len;
        info.address = e.address;
        info.hit_count = e.hit_count;
        info.owner_pid = e.owner_pid;
        info.stopped_task_id = e.stopped_task_id;
        info.hw_slot = e.hw_slot;
        info.suspend_on_hit = e.suspend_on_hit;
        info.is_stopped = (e.stopped_task_id != 0);
        // _pad[7] intentionally left uninitialised — callers don't
        // read it. Explicit zero-fill would compile to a memset
        // call in freestanding mode; we have no kernel-side memset.
    };
    for (auto& e : g_sw_table)
        emit(e);
    for (auto& e : g_hw_table)
        emit(e);
    return written;
}

// Look up a BP entry by id in either the SW or HW table. Caller
// MUST hold g_lock. Returns nullptr if the id doesn't match any
// live slot.
BpEntry* FindById(u32 id) /* MUST hold g_lock */
{
    BpEntry* e = FindSwById(id);
    if (e != nullptr)
        return e;
    return FindHwById(id);
}

// Park the currently-running task on this BP's wait-queue. Must
// NOT be called with g_lock held — we acquire it briefly to set
// stopped_task_id / stopped_frame, release across the block, then
// re-acquire to clear. Returns when some other task calls
// WaitQueueWakeOne (via BpResume / BpStep / BpRemove).
//
// Phase 3 safety: only ring-3 hits suspend. A kernel-mode hit with
// suspend_on_hit set logs a "rejected" warning and resumes — we
// can't safely park a kernel-mode task without knowing it isn't
// holding a spinlock / mid-IRQ. The IrqNestDepthRaw telemetry that
// gates this is now live (traps.cpp), so Phase 4 — relaxing the
// kernel-mode suspend when depth == 0 and no locks are held — is
// unblocked; this site still takes the conservative resume until
// that relaxation is wired.
void MaybeSuspend(u32 bp_id, arch::TrapFrame* frame)
{
    if ((frame->cs & 3) != 3)
    {
        // Still might be a user BP hit vs. a suspend-on-hit request
        // for a kernel-installed BP; the flag check is below,
        // inside the lock.
    }
    sched::WaitQueue* wq = nullptr;
    u64 tid = 0;
    {
        sync::SpinLockGuard g(g_lock);
        BpEntry* e = FindById(bp_id);
        if (e == nullptr || !e->suspend_on_hit)
            return;
        if ((frame->cs & 3) != 3)
        {
            KLOG_WARN_V("debug/bp", "suspend-on-hit rejected: kernel-mode hit, id", bp_id);
            return;
        }
        tid = sched::CurrentTaskId();
        e->stopped_task_id = tid;
        e->stopped_frame = frame;
        e->stopped_as = core::CurrentProcess() != nullptr ? core::CurrentProcess()->as : nullptr;
        wq = &e->wq;
    }
    KLOG_INFO_2V("debug/bp", "task suspended on BP", "bp_id", bp_id, "task_id", tid);
    // Interrupts are disabled at trap entry, so the check-then-
    // block pair required by WaitQueueBlock is already atomic.
    sched::WaitQueueBlock(wq);
    // Resumed — we were woken by BpResume / BpStep / BpRemove.
    {
        sync::SpinLockGuard g(g_lock);
        BpEntry* e = FindById(bp_id);
        if (e != nullptr)
        {
            e->stopped_task_id = 0;
            e->stopped_frame = nullptr;
            e->stopped_as = nullptr;
        }
    }
    KLOG_INFO_V("debug/bp", "task resumed from BP id", bp_id);
}

bool BpHandleBreakpoint(arch::TrapFrame* frame)
{
    // int3 (0xCC) pushes rip pointing to the byte AFTER the 0xCC,
    // so the patched address is rip - 1.
    const u64 bp_addr = frame->rip - 1;

    // Cross-handler re-entrancy: a BP firing while we are already
    // executing a BP handler means the BP is attached to a path
    // the handler itself reaches. Don't recurse — claim the trap,
    // log once, and let the iretq run. If the BP is software
    // (int3 still patched), the very next execution of this VA
    // will re-fire — that's deliberate, the operator gets a
    // klog flood until they remove the BP.
    if (g_handler_depth > 0)
    {
        KLOG_WARN_V("debug/bp", "RECURSION: nested handler entry at addr=", bp_addr);
        return true;
    }
    ++g_handler_depth;

    u32 hit_id = 0;
    BpHitCallback hit_callback = nullptr;
    {
        sync::SpinLockGuard g(g_lock);
        BpEntry* e = FindSwByAddr(bp_addr);
        if (e == nullptr)
        {
            --g_handler_depth;
            return false; // spurious int3 — not one of ours
        }
        // Reentrancy guard: a second SW BP while reinsert is
        // pending means we'd lose the first one's re-patch.
        if (g_reinsert.pending)
        {
            KLOG_WARN_V("debug/bp", "nested SW BP hit while reinsert pending at", g_reinsert.addr);
            --g_handler_depth;
            return true;
        }
        ++e->hit_count;
        frame->rip = bp_addr;
        PokeByte(bp_addr, e->orig_byte);
        frame->rflags |= 0x100ULL; // RFLAGS.TF → single-step next insn
        g_reinsert.pending = true;
        g_reinsert.addr = bp_addr;
        g_reinsert.orig_byte = e->orig_byte;
        KLOG_INFO_2V("debug/bp", "SW BP hit", "addr", bp_addr, "hits", e->hit_count);
        hit_id = e->id;
        hit_callback = e->on_hit;
    }
    // Drop g_lock before invoking the on-hit callback OR the
    // potential block — both can re-enter through APIs that
    // need the lock (the inspector for MaybeSuspend; the GDB
    // stop loop for the callback). Drop the recursion-depth
    // guard here too: the synchronous danger window (klog +
    // PokeByte under g_lock) is over; a peer task that fires
    // a BP while we're parked in MaybeSuspend should be
    // handled normally, not skipped.
    --g_handler_depth;
    if (hit_callback != nullptr)
    {
        hit_callback({hit_id}, frame);
    }
    MaybeSuspend(hit_id, frame);
    return true;
}

bool BpHandleDebug(arch::TrapFrame* frame)
{
    // Cross-handler re-entrancy: see BpHandleBreakpoint above.
    // For #DB the recursive case is a HW write/read-write watch
    // installed on a kernel data slot the handler itself touches
    // (g_reinsert, g_stepping, the slot tables). Skip + log so
    // the trap iretqs without stacking into the same handler.
    if (g_handler_depth > 0)
    {
        KLOG_WARN("debug/bp", "RECURSION: nested #DB handler entry");
        return true;
    }
    ++g_handler_depth;

    const u64 dr6 = dr::ReadDr6();
    bool claimed = false;
    u32 suspend_id = 0; // BP to park the caller on after DR6 clear

    // Single-step reinsert path. The CPU pushed rflags WITH TF
    // still set (auto-clear only applies to the live RFLAGS
    // while the handler runs — NOT to the saved image on the
    // stack). We must clear TF in the trap frame ourselves so
    // iretq resumes without stepping further.
    if ((dr6 & dr::kDr6Bs) != 0 && g_reinsert.pending)
    {
        PokeByte(g_reinsert.addr, 0xCC);
        g_reinsert.pending = false;
        frame->rflags &= ~0x100ULL; // clear RFLAGS.TF
        claimed = true;
    }

    // Stepping-session path. BpStep set g_stepping.{task_id,bp_id}
    // and woke a task whose BP had suspend_on_hit. The task ran one
    // instruction (the CPU single-stepped via TF) and now we're in
    // #DB with BS=1 — re-suspend it on the same BP. Must run AFTER
    // the reinsert block so a SW-BP step first re-patches 0xCC,
    // then re-parks. Order the `task_id != 0` check FIRST so we
    // don't call CurrentTaskId() during the boot-time self-test
    // (scheduler / per-CPU GSBASE isn't live yet at that point).
    if ((dr6 & dr::kDr6Bs) != 0 && g_stepping.task_id != 0 && g_stepping.task_id == sched::CurrentTaskId())
    {
        suspend_id = g_stepping.bp_id;
        g_stepping.task_id = 0;
        g_stepping.bp_id = 0;
        frame->rflags &= ~0x100ULL; // cancel TF before re-parking
        claimed = true;
    }

    // Hardware-breakpoint hits. B0..B3 map to DR0..DR3; sticky
    // until software clears them by writing DR6.
    BpHitCallback hit_callback = nullptr;
    u32 hit_callback_id = 0;
    if ((dr6 & dr::kDr6Bn) != 0)
    {
        sync::SpinLockGuard g(g_lock);
        bool any_exec = false;
        for (u8 slot = 0; slot < kMaxHwSlots; ++slot)
        {
            if ((dr6 & (1ULL << slot)) == 0)
                continue;
            BpEntry* e = FindHwBySlot(slot);
            if (e == nullptr)
                continue; // slot fired but no manager entry — stale / racy
            ++e->hit_count;
            if (e->kind == BpKind::HwExecute)
                any_exec = true;
            KLOG_INFO_2V("debug/bp", "HW BP hit", "addr", e->address, "hits", e->hit_count);
            claimed = true;
            if (e->suspend_on_hit && suspend_id == 0)
                suspend_id = e->id;
            if (e->on_hit != nullptr && hit_callback == nullptr)
            {
                hit_callback = e->on_hit;
                hit_callback_id = e->id;
            }
        }
        // For instruction (execute) breakpoints the Intel SDM says
        // the CPU sets RFLAGS.RF (Resume Flag) in the pushed image
        // so that iretq resumes without re-triggering the match on
        // the same fetch. TCG doesn't reliably propagate that bit,
        // so set it explicitly here — write breakpoints (trap-after
        // semantics) don't need it.
        if (any_exec)
            frame->rflags |= 0x10000ULL;
    }

    // Always clear DR6 on exit. Sticky B0..B3 / BS bits that the
    // CPU set survive iretq and would surface as a phantom hit
    // on the next unrelated #DB.
    dr::WriteDr6(dr::kDr6InitValue);

    // Drop the recursion-depth guard: synchronous danger window
    // (DR access + log emission) is over. Callback / suspend run
    // outside the guard so a peer task firing a BP isn't skipped
    // while we're parked in MaybeSuspend.
    --g_handler_depth;

    // GDB-style on-hit callback runs AFTER DR6 clear (so a
    // GDB session can read DR6 and see the cleared state if it
    // wants to) and BEFORE MaybeSuspend (the wait-queue path
    // would compete for the trap-context).
    if (hit_callback != nullptr)
    {
        hit_callback({hit_callback_id}, frame);
    }

    // Suspend-on-hit runs AFTER DR6 clear so the task resumes with
    // a clean status register next time it runs an instruction.
    if (suspend_id != 0)
        MaybeSuspend(suspend_id, frame);

    return claimed;
}

// Sentinel used by BpSelfTest. `noinline + used` keeps it at a
// stable address and prevents LTO from inlining it into the test.
// The function intentionally does real work (a `nop`) so the SW-BP
// patch lands on an instruction byte with no special semantics.
__attribute__((noinline, used)) static void BpSelfTestTarget()
{
    asm volatile("nop");
}

bool BpSelfTest()
{
    const u64 target = reinterpret_cast<u64>(&BpSelfTestTarget);

    // --- SW BP round-trip -------------------------------------
    BpError err = BpError::None;
    BreakpointId sw_id = BpInstallSoftware(target, /*suspend_on_hit=*/false, &err);
    if (err != BpError::None)
    {
        KLOG_WARN_V("debug/bp", "self-test: SW install failed, err", static_cast<u64>(err));
        return false;
    }
    BpSelfTestTarget();
    BpInfo infos[kMaxSwSlots + kMaxHwSlots];
    usize n = BpList(infos, kMaxSwSlots + kMaxHwSlots);
    u64 sw_hits = 0;
    for (usize i = 0; i < n; ++i)
    {
        if (infos[i].id.value == sw_id.value)
            sw_hits = infos[i].hit_count;
    }
    BpRemove(sw_id, /*requester_pid=*/0);
    if (sw_hits == 0)
    {
        KLOG_WARN("debug/bp", "self-test: SW BP never fired");
        return false;
    }

    // --- HW execute BP round-trip -----------------------------
    // owner_pid = 0 → kernel-owned (self-test). Normal ring-3
    // callers pass their own pid via the SYS_BP_INSTALL path.
    BreakpointId hw_id =
        BpInstallHardware(target, BpKind::HwExecute, BpLen::One, /*owner_pid=*/0, /*suspend_on_hit=*/false, &err);
    if (err != BpError::None)
    {
        KLOG_WARN_V("debug/bp", "self-test: HW install failed, err", static_cast<u64>(err));
        return false;
    }
    BpSelfTestTarget();
    n = BpList(infos, kMaxSwSlots + kMaxHwSlots);
    u64 hw_hits = 0;
    for (usize i = 0; i < n; ++i)
    {
        if (infos[i].id.value == hw_id.value)
            hw_hits = infos[i].hit_count;
    }
    BpRemove(hw_id, /*requester_pid=*/0);
    if (hw_hits == 0)
    {
        KLOG_WARN("debug/bp", "self-test: HW BP never fired");
        return false;
    }

    KLOG_INFO_2V("debug/bp", "self-test OK", "sw_hits", sw_hits, "hw_hits", hw_hits);
    return true;
}

} // namespace duetos::debug
