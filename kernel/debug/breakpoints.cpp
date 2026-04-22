#include "breakpoints.h"

#include "../arch/x86_64/smp.h"
#include "../core/klog.h"
#include "../mm/paging.h"
#include "../sync/spinlock.h"
#include "dr.h"

namespace customos::debug
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
    u8 _pad[1];
    u64 address;
    u64 hit_count;
    u8 orig_byte; // software BPs: the byte we overwrote with 0xCC
    u8 _pad2[7];
};

sync::SpinLock g_lock{};
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
    }
    return dr::kDr7Len1;
}

} // namespace

void BpInit()
{
    sync::SpinLockGuard g(g_lock);
    if (g_inited)
        return;
    for (auto& e : g_sw_table)
        e.id = 0;
    for (auto& e : g_hw_table)
        e.id = 0;
    g_next_id = 1;
    g_reinsert.pending = false;
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
    g_inited = true;
    KLOG_INFO("debug/bp", "breakpoint subsystem online");
}

BreakpointId BpInstallSoftware(u64 kernel_va, BpError* err)
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
    slot->address = kernel_va;
    slot->orig_byte = PeekByte(kernel_va);
    slot->hit_count = 0;
    PokeByte(kernel_va, 0xCC);
    KLOG_INFO_2V("debug/bp", "SW BP installed", "addr", kernel_va, "id", slot->id);
    set_err(BpError::None);
    return {slot->id};
}

BreakpointId BpInstallHardware(u64 va, BpKind kind, BpLen len, BpError* err)
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
    if (arch::SmpCpusOnline() != 1)
    {
        set_err(BpError::SmpUnsupported);
        return kBpIdNone;
    }
    sync::SpinLockGuard g(g_lock);
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
    e->address = va;
    e->hit_count = 0;
    ApplyDrSlot(u8(s), va, KindToRw(kind), LenToDr7(len));
    KLOG_INFO_2V("debug/bp", "HW BP installed", "addr", va, "id", e->id);
    set_err(BpError::None);
    return {e->id};
}

BpError BpRemove(BreakpointId id)
{
    if (id.value == 0)
        return BpError::NotInstalled;
    sync::SpinLockGuard g(g_lock);
    BpEntry* sw = FindSwById(id.value);
    if (sw != nullptr)
    {
        PokeByte(sw->address, sw->orig_byte);
        KLOG_INFO_V("debug/bp", "SW BP removed id", sw->id);
        sw->id = 0;
        return BpError::None;
    }
    BpEntry* hw = FindHwById(id.value);
    if (hw != nullptr)
    {
        ClearDrSlot(hw->hw_slot);
        KLOG_INFO_V("debug/bp", "HW BP removed id", hw->id);
        hw->id = 0;
        return BpError::None;
    }
    return BpError::NotInstalled;
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
        info.hw_slot = e.hw_slot;
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

bool BpHandleBreakpoint(arch::TrapFrame* frame)
{
    // int3 (0xCC) pushes rip pointing to the byte AFTER the 0xCC,
    // so the patched address is rip - 1.
    const u64 bp_addr = frame->rip - 1;
    sync::SpinLockGuard g(g_lock);
    BpEntry* e = FindSwByAddr(bp_addr);
    if (e == nullptr)
        return false; // spurious int3 — not one of ours
    // Reentrancy guard: a second SW BP while reinsert is pending
    // means we'd lose the first one's re-patch. Shouldn't happen
    // in phase 1 (single-CPU, no nested debugging) but be safe.
    if (g_reinsert.pending)
    {
        KLOG_WARN_V("debug/bp", "nested SW BP hit while reinsert pending at", g_reinsert.addr);
        // Leave the 0xCC in place and step past the byte. Caller
        // will then execute whatever follows — imperfect but
        // keeps the kernel alive.
        return true;
    }
    ++e->hit_count;
    // 1. Rewind rip back onto the patched byte.
    frame->rip = bp_addr;
    // 2. Restore the original byte so the re-execution runs the
    //    real instruction.
    PokeByte(bp_addr, e->orig_byte);
    // 3. Arm single-step by setting RFLAGS.TF. iretq loads rflags
    //    from the trap frame, so TF is active for the next insn.
    frame->rflags |= 0x100ULL;
    // 4. Record pending reinsert — HandleDebug will re-patch 0xCC
    //    once the original instruction has completed.
    g_reinsert.pending = true;
    g_reinsert.addr = bp_addr;
    g_reinsert.orig_byte = e->orig_byte;
    KLOG_INFO_2V("debug/bp", "SW BP hit", "addr", bp_addr, "hits", e->hit_count);
    return true;
}

bool BpHandleDebug(arch::TrapFrame* frame)
{
    const u64 dr6 = dr::ReadDr6();
    bool claimed = false;

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

    // Hardware-breakpoint hits. B0..B3 map to DR0..DR3; sticky
    // until software clears them by writing DR6.
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

    (void)frame;
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
    BreakpointId sw_id = BpInstallSoftware(target, &err);
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
    BpRemove(sw_id);
    if (sw_hits == 0)
    {
        KLOG_WARN("debug/bp", "self-test: SW BP never fired");
        return false;
    }

    // --- HW execute BP round-trip -----------------------------
    BreakpointId hw_id = BpInstallHardware(target, BpKind::HwExecute, BpLen::One, &err);
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
    BpRemove(hw_id);
    if (hw_hits == 0)
    {
        KLOG_WARN("debug/bp", "self-test: HW BP never fired");
        return false;
    }

    KLOG_INFO_2V("debug/bp", "self-test OK", "sw_hits", sw_hits, "hw_hits", hw_hits);
    return true;
}

} // namespace customos::debug
