#include "arch/x86_64/gdt.h"

#include "cpu/percpu.h"
#include "log/klog.h"
#include "mm/kheap.h"

namespace duetos::arch
{

namespace
{

// Long-mode GDT descriptors. Each is 64 bits; the layout is fossil from the
// 16-bit era but we only care about a handful of fields:
//   0x9A = P | DPL=0 | S | exec/read code
//   0x92 = P | DPL=0 | S | read/write data
//   0xFA = P | DPL=3 | S | exec/read code  (user code)
//   0xF2 = P | DPL=3 | S | read/write data (user data)
//   0xA  (high nibble of flags) = G=1 | L=1 | DB=0   (code)
//   0xA  (high nibble of flags) = G=1 | L=0 | DB=0   (data — L ignored)
//
// Base=0 and limit=0xFFFFF are the standard flat-long-mode values. The CPU
// ignores base/limit checks in long mode except for FS/GS, but zeroing them
// keeps things tidy.
constexpr u64 kGdtNull = 0x0000000000000000ULL;
constexpr u64 kGdtKernelCode = 0x00AF9A000000FFFFULL;
constexpr u64 kGdtKernelData = 0x00AF92000000FFFFULL;
// 64-bit user code/data: access=0xFA/0xF2 (P, DPL=3, S, R/RW, code/data),
// flags=0xA (G=1, L=1 for code, L ignored for data, D=0).
constexpr u64 kGdtUserCode = 0x00AFFA000000FFFFULL;
constexpr u64 kGdtUserData = 0x00AFF2000000FFFFULL;
// 32-bit user code/data for compatibility-mode execution of PE32 (i386)
// binaries. Same DPL=3 + S + R/RW bits, but the flags nibble is 0xC
// (G=1, L=0, D=1) — D=1 = 32-bit default operand size + 32-bit stack
// pointer width. Used by the loader path that maps a PE32 image and
// enters it via EnterUserMode32 (kernel/arch/x86_64/usermode.S).
constexpr u64 kGdtUserCode32 = 0x00CFFA000000FFFFULL;
constexpr u64 kGdtUserData32 = 0x00CFF2000000FFFFULL;

// Slots 3-4 hold the 16-byte TSS system descriptor, filled in at
// runtime by TssInit. The initial 0s make them a null-present-bit
// descriptor that the CPU rejects, so LTR on an uninitialised TSS
// would fault rather than use garbage.
//
// Slots 5-6 are the ring-3 descriptors consumed by iretq-based user-
// mode entry: the CPU reads CS/SS from the iretq frame, looks them
// up in the GDT, and checks DPL/RPL/permission bits. An iretq with
// CS == kUserCodeSelector with the matching DPL=3 descriptor absent
// raises #GP(selector).
// GDT layout (9 entries):
//   0: NULL
//   1: kernel code (long mode)
//   2: kernel data
//   3-4: TSS descriptor (filled by TssInit)
//   5: user code (long mode, DPL=3) — kUserCodeSelector = 0x28|3 = 0x2B
//   6: user data (DPL=3)            — kUserDataSelector = 0x30|3 = 0x33
//   7: user code 32-bit (DPL=3)     — kUserCode32Selector = 0x38|3 = 0x3B
//   8: user data 32-bit (DPL=3)     — kUserData32Selector = 0x40|3 = 0x43
alignas(16) constinit u64 g_gdt[9] = {
    kGdtNull, kGdtKernelCode, kGdtKernelData, 0, 0, kGdtUserCode, kGdtUserData, kGdtUserCode32, kGdtUserData32,
};

struct [[gnu::packed]] GdtPointer
{
    u16 limit;
    u64 base;
};

// Not constinit — the base field requires a reinterpret_cast on a non-
// constexpr address, which the standard forbids from constant initializers.
// Filled in at runtime inside GdtInit().
GdtPointer g_gdt_pointer;

// BSP TSS (Tss layout lives in gdt.h so per-AP code can reference
// it). Only RSP0 (kernel stack on user→kernel transition) and IST1
// ..IST3 (dedicated stacks for the three critical exception vectors)
// carry meaningful values. The I/O-permission-bitmap offset is set
// past the TSS body in TssInit, disabling the bitmap entirely so
// every port access from user mode will #GP.
alignas(16) constinit Tss g_bsp_tss = {};

// Dedicated exception stacks. 4 KiB each is comfortable — the trap
// dispatcher's deepest path (symbolised backtrace + register dump +
// klog ring drain) runs to about 2 KiB, and these stacks never
// re-enter themselves.
//
// Each gets a stack canary at its LOW edge (stacks grow down, so
// byte 0 is the overflow edge). `TssInit` plants the canary; the
// trap dispatcher's crash-dump path can check it after the trap
// runs to detect a blown IST (which would otherwise corrupt
// neighbouring BSS silently). Matches the per-task stack canary
// pattern in kernel/sched/sched.cpp.
//
// Sized at 16 KiB (was 4 KiB). With `-fstack-protector-strong`
// enabled kernel-wide every function with a local array gets an
// 8-byte canary slot in its prologue + a load+cmp in the epilogue,
// inflating the per-call stack footprint enough that a deeply
// nested trap (panic-dump → backtrace → symbolize) blew past the
// 4 KiB IST limit, corrupted the saved trap frame, and produced
// the recursive-fault observed on 2026-05-11. 16 KiB matches the
// kernel-task stack size and leaves headroom for the symbolize
// machinery that runs inside the dump path.
constexpr u64 kIstStackBytes = 16384;
constexpr u64 kIstStackCanary = 0xC0DEB0B0CAFED00DULL;
alignas(16) constinit u8 g_ist_stack_df[kIstStackBytes] = {};
alignas(16) constinit u8 g_ist_stack_mc[kIstStackBytes] = {};
alignas(16) constinit u8 g_ist_stack_nmi[kIstStackBytes] = {};

} // namespace

void GdtInit()
{
    KLOG_TRACE_SCOPE("arch/gdt", "GdtInit");
    g_gdt_pointer.limit = sizeof(g_gdt) - 1;
    g_gdt_pointer.base = reinterpret_cast<u64>(&g_gdt[0]);

    // Load the new GDT. The CPU's cached segment descriptors still reference
    // the boot.S table until we reload each segment register, so we follow
    // lgdt with a far-return to reload CS and explicit writes for the data
    // selectors.
    asm volatile("lgdt %[gdtp]                 \n\t"
                 // Far-return trick to reload CS: push new CS, push the "return"
                 // address (label 1 below), then lretq. On return execution
                 // continues at label 1 with CS = kKernelCodeSelector.
                 "pushq %[kcode]               \n\t"
                 "leaq  1f(%%rip), %%rax       \n\t"
                 "pushq %%rax                  \n\t"
                 "lretq                        \n\t"
                 "1:                           \n\t"
                 // Reload data segments to pick up the new GDT's cached descriptors.
                 "movw %[kdata], %%ax          \n\t"
                 "movw %%ax,     %%ds          \n\t"
                 "movw %%ax,     %%es          \n\t"
                 "movw %%ax,     %%fs          \n\t"
                 "movw %%ax,     %%gs          \n\t"
                 "movw %%ax,     %%ss          \n\t"
                 :
                 : [gdtp] "m"(g_gdt_pointer), [kcode] "i"(kKernelCodeSelector), [kdata] "i"(kKernelDataSelector)
                 : "rax", "memory");
}

void TssInit()
{
    KLOG_TRACE_SCOPE("arch/gdt", "TssInit");
    // Plant a canary at the low edge of each IST stack. A blown
    // exception stack (say, #DF deeper than 4 KiB) would scribble
    // this value and IstStackCanaryIntact() picks it up.
    *reinterpret_cast<u64*>(g_ist_stack_df) = kIstStackCanary;
    *reinterpret_cast<u64*>(g_ist_stack_mc) = kIstStackCanary;
    *reinterpret_cast<u64*>(g_ist_stack_nmi) = kIstStackCanary;

    // Fill the TSS body. Stacks grow down; each IST pointer is the
    // stack's TOP (base + size). RSP0 stays 0 until ring 3 lands —
    // it's only consulted on user→kernel privilege transitions.
    g_bsp_tss.ist1 = reinterpret_cast<u64>(g_ist_stack_df) + sizeof(g_ist_stack_df);
    g_bsp_tss.ist2 = reinterpret_cast<u64>(g_ist_stack_mc) + sizeof(g_ist_stack_mc);
    g_bsp_tss.ist3 = reinterpret_cast<u64>(g_ist_stack_nmi) + sizeof(g_ist_stack_nmi);
    g_bsp_tss.iopb_offset = sizeof(Tss); // no I/O bitmap — port I/O from ring 3 will #GP

    // Build the 16-byte TSS system descriptor in GDT slots 3-4.
    // Intel SDM Vol. 3A §7.2.3 (64-bit TSS descriptor).
    const u64 base = reinterpret_cast<u64>(&g_bsp_tss);
    const u64 limit = sizeof(Tss) - 1;

    // Low 8 bytes: limit[15:0] | base[23:0]<<16 | access=0x89<<40 |
    //              limit[19:16]<<48 | base[31:24]<<56.
    // Access byte 0x89 = P=1 | DPL=0 | S=0 | Type=0x9 (available 64-bit TSS).
    const u64 low = (limit & 0xFFFFULL) | ((base & 0xFFFFFFULL) << 16) | (0x89ULL << 40) |
                    (((limit >> 16) & 0xFULL) << 48) | (((base >> 24) & 0xFFULL) << 56);
    const u64 high = (base >> 32) & 0xFFFFFFFFULL;

    g_gdt[3] = low;
    g_gdt[4] = high;

    // LTR reads the descriptor we just wrote and caches it; the GDT
    // pointer already covers slots 0..4 (loaded by GdtInit above),
    // so there's no re-lgdt dance.
    asm volatile("ltr %w0" : : "r"(kTssSelector));
}

bool IstStackCanariesIntact()
{
    const u64 df = *reinterpret_cast<const u64*>(g_ist_stack_df);
    const u64 mc = *reinterpret_cast<const u64*>(g_ist_stack_mc);
    const u64 nmi = *reinterpret_cast<const u64*>(g_ist_stack_nmi);
    const bool ok = df == kIstStackCanary && mc == kIstStackCanary && nmi == kIstStackCanary;
    if (!ok)
    {
        // A clobbered canary means an IST stack overflowed during a
        // double fault / NMI / #MC handler. The handler returned (or
        // we wouldn't be here to check) but kernel state may be
        // corrupt. Loud Error so it doesn't get lost in the noise.
        KLOG_ERROR("arch/gdt", "IST stack canary clobbered — IST overflow occurred");
    }
    return ok;
}

void TssSetRsp0(u64 rsp0)
{
    // Per-CPU TSS routing: write to whichever TSS this CPU has
    // ltr'd. BSP's PerCpu.tss is wired to &g_bsp_tss by
    // PerCpuInitBsp; each AP's PerCpu.tss is wired to its
    // heap-allocated AP TSS by SmpStartAps. Falls back to
    // g_bsp_tss if PerCpu hasn't been installed yet (only
    // possible on the very early boot path before PerCpuInitBsp
    // — and the only caller that can race that window is the
    // boot path's own ring-3 smoke, which runs much later).
    if (cpu::BspInstalled())
    {
        cpu::PerCpu* p = cpu::CurrentCpu();
        Tss* t = static_cast<Tss*>(p->tss);
        if (t != nullptr)
        {
            t->rsp0 = rsp0;
            return;
        }
    }
    g_bsp_tss.rsp0 = rsp0;
}

Tss* BspTssPtr()
{
    return &g_bsp_tss;
}

ApGdtBundle* AllocateApGdt(cpu::PerCpu* pcpu)
{
    auto* bundle = static_cast<ApGdtBundle*>(mm::KMalloc(sizeof(ApGdtBundle)));
    if (bundle == nullptr)
    {
        return nullptr;
    }
    *bundle = {};

    // 9-entry GDT clone — same layout as BSP's g_gdt. Slots 3-4
    // are the TSS descriptor; we fill them after allocating the
    // AP's TSS so the descriptor's base field can point at it.
    constexpr u64 kGdtSlots = 9;
    auto* ap_gdt = static_cast<u64*>(mm::KMalloc(kGdtSlots * sizeof(u64)));
    if (ap_gdt == nullptr)
    {
        mm::KFree(bundle);
        return nullptr;
    }
    ap_gdt[0] = kGdtNull;
    ap_gdt[1] = kGdtKernelCode;
    ap_gdt[2] = kGdtKernelData;
    ap_gdt[3] = 0; // filled below
    ap_gdt[4] = 0; // filled below
    ap_gdt[5] = kGdtUserCode;
    ap_gdt[6] = kGdtUserData;
    ap_gdt[7] = kGdtUserCode32;
    ap_gdt[8] = kGdtUserData32;

    auto* ap_tss = static_cast<Tss*>(mm::KMalloc(sizeof(Tss)));
    if (ap_tss == nullptr)
    {
        mm::KFree(ap_gdt);
        mm::KFree(bundle);
        return nullptr;
    }
    *ap_tss = {};
    ap_tss->iopb_offset = sizeof(Tss); // disable I/O bitmap

    auto* ist_df = static_cast<u8*>(mm::KMalloc(kIstStackBytes));
    auto* ist_mc = static_cast<u8*>(mm::KMalloc(kIstStackBytes));
    auto* ist_nmi = static_cast<u8*>(mm::KMalloc(kIstStackBytes));
    if (ist_df == nullptr || ist_mc == nullptr || ist_nmi == nullptr)
    {
        if (ist_df != nullptr)
            mm::KFree(ist_df);
        if (ist_mc != nullptr)
            mm::KFree(ist_mc);
        if (ist_nmi != nullptr)
            mm::KFree(ist_nmi);
        mm::KFree(ap_tss);
        mm::KFree(ap_gdt);
        mm::KFree(bundle);
        return nullptr;
    }
    // Plant canaries at the low edge of each IST stack — same
    // pattern as BSP's static IST stacks.
    *reinterpret_cast<u64*>(ist_df) = kIstStackCanary;
    *reinterpret_cast<u64*>(ist_mc) = kIstStackCanary;
    *reinterpret_cast<u64*>(ist_nmi) = kIstStackCanary;
    ap_tss->ist1 = reinterpret_cast<u64>(ist_df) + kIstStackBytes;
    ap_tss->ist2 = reinterpret_cast<u64>(ist_mc) + kIstStackBytes;
    ap_tss->ist3 = reinterpret_cast<u64>(ist_nmi) + kIstStackBytes;

    // Build the 16-byte TSS system descriptor in slots 3-4 of the
    // AP's own GDT. Same construction as TssInit's BSP path.
    const u64 base = reinterpret_cast<u64>(ap_tss);
    const u64 limit = sizeof(Tss) - 1;
    const u64 low = (limit & 0xFFFFULL) | ((base & 0xFFFFFFULL) << 16) | (0x89ULL << 40) |
                    (((limit >> 16) & 0xFULL) << 48) | (((base >> 24) & 0xFFULL) << 56);
    const u64 high = (base >> 32) & 0xFFFFFFFFULL;
    ap_gdt[3] = low;
    ap_gdt[4] = high;

    bundle->gdt = ap_gdt;
    bundle->gdt_limit = static_cast<u16>(kGdtSlots * sizeof(u64) - 1);
    bundle->tss = ap_tss;
    bundle->ist_stack_df = ist_df;
    bundle->ist_stack_mc = ist_mc;
    bundle->ist_stack_nmi = ist_nmi;

    pcpu->tss = ap_tss;
    return bundle;
}

void LoadGdtForCurrent(ApGdtBundle* bundle)
{
    // Build the lgdt operand on the stack — the CPU reads a
    // [u16 limit, u64 base] tuple. No need for a per-CPU static
    // GdtPointer slot; once lgdt has executed, the CPU has the
    // descriptor cached.
    GdtPointer ptr;
    ptr.limit = bundle->gdt_limit;
    ptr.base = reinterpret_cast<u64>(bundle->gdt);

    asm volatile("lgdt %[gdtp]                 \n\t"
                 // Far-return trick to reload CS — same idiom as GdtInit.
                 "pushq %[kcode]               \n\t"
                 "leaq  1f(%%rip), %%rax       \n\t"
                 "pushq %%rax                  \n\t"
                 "lretq                        \n\t"
                 "1:                           \n\t"
                 "movw %[kdata], %%ax          \n\t"
                 "movw %%ax,     %%ds          \n\t"
                 "movw %%ax,     %%es          \n\t"
                 "movw %%ax,     %%fs          \n\t"
                 "movw %%ax,     %%gs          \n\t"
                 "movw %%ax,     %%ss          \n\t"
                 :
                 : [gdtp] "m"(ptr), [kcode] "i"(kKernelCodeSelector), [kdata] "i"(kKernelDataSelector)
                 : "rax", "memory");

    // ltr loads the TSS selector from the new GDT (slot 3-4).
    asm volatile("ltr %w0" : : "r"(kTssSelector));
}

u64* GdtRawBase()
{
    return g_gdt;
}

u64 GdtHash()
{
    // FNV-1a over the code/data descriptors, with two
    // legitimate CPU-mutated bits masked:
    //
    //   * Slots 3-4 are the TSS descriptor. LTR sets the BUSY
    //     bit (access-byte bit 1); skip those slots entirely.
    //   * Slots 1/2/5/6 are code/data descriptors. Any time the
    //     CPU loads one into a segment register, it sets the
    //     ACCESSED bit (access-byte bit 0 = descriptor bit 40).
    //     Mask that bit before hashing so the hash reflects the
    //     immutable-by-software state.
    //
    // A rootkit-style descriptor swap would have to mutate a
    // code/data slot in a way beyond the A bit — replacing
    // kernel CS with a ring-3 entry to escalate privilege, or
    // planting a call gate in a user slot. That's the signal
    // we want to catch.
    constexpr u64 kFnvOffset = 0xcbf29ce484222325ULL;
    constexpr u64 kFnvPrime = 0x100000001b3ULL;
    constexpr u64 kSkipSlotStart = 3;
    constexpr u64 kSkipSlotEnd = 5;              // [3, 5) excluded
    constexpr u64 kAccessedBitMask = 1ULL << 40; // bit 40 = A
    u64 h = kFnvOffset;
    for (u64 slot = 0; slot < sizeof(g_gdt) / sizeof(g_gdt[0]); ++slot)
    {
        if (slot >= kSkipSlotStart && slot < kSkipSlotEnd)
            continue;
        const u64 v = g_gdt[slot] & ~kAccessedBitMask;
        const auto* p = reinterpret_cast<const u8*>(&v);
        for (u64 i = 0; i < sizeof(v); ++i)
        {
            h ^= p[i];
            h *= kFnvPrime;
        }
    }
    return h;
}

} // namespace duetos::arch
