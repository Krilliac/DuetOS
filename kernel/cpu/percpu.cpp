#include "cpu/percpu.h"

#include "arch/x86_64/gdt.h"
#include "arch/x86_64/lapic.h"
#include "arch/x86_64/serial.h"
#include "log/klog.h"

namespace duetos::cpu
{

namespace
{

constexpr u32 kIa32GsBaseMsr = 0xC0000101u;

// Static BSP struct. Every AP will have its own heap-allocated one.
constinit PerCpu g_bsp_percpu = {
    .cpu_id = 0,
    .lapic_id = 0,
    .current_task = nullptr,
    .current_as = nullptr, // kernel AS = boot PML4, until a process is activated
    .need_resched = false,
    ._pad = {},
    .kernel_rsp = 0,           // filled on first ring3 task switch-in (sched + ring3 smoke)
    .user_rsp_scratch = 0,     // touched only by the syscall entry stub
    .panic_snapshot_valid = 0, // capture is filled lazily by the NMI peer-snapshot path
    ._pad2 = {},
    .panic_snapshot_rip = 0,
    .panic_snapshot_rsp = 0,
    .panic_snapshot_task = nullptr,
    .held_locks_count = 0,
    ._pad3 = 0,
    .held_locks = {},
    .held_lock_rips = {},
    .gdb_frozen = 0,
    ._pad4 = {},
    .gdb_snapshot_rip = 0,
    .gdb_snapshot_rsp = 0,
    .gdb_snapshot_rflags = 0,
    .gdb_frozen_frame = nullptr,
    .ctxsw_lock_to_release = nullptr,
    .ctxsw_lock_flags = 0,
    .runq_head_normal = nullptr,
    .runq_tail_normal = nullptr,
    .runq_head_idle = nullptr,
    .runq_tail_idle = nullptr,
    .tss = nullptr,
    .cluster_id = 0,
    ._pad_topo = {},
    .runq_normal_len = 0,
    ._pad_runq_len = {},
};

// One-shot flag so CurrentCpuIdOrBsp can return a sane value before
// PerCpuInitBsp has run. Without it, reading GSBASE would return 0
// and CurrentCpu() would dereference a null pointer.
constinit bool g_bsp_installed = false;

inline void WriteMsr(u32 msr, u64 value)
{
    const u32 lo = static_cast<u32>(value & 0xFFFFFFFF);
    const u32 hi = static_cast<u32>(value >> 32);
    asm volatile("wrmsr" : : "c"(msr), "a"(lo), "d"(hi));
}

} // namespace

void PerCpuInitBsp()
{
    KLOG_TRACE_SCOPE("cpu/percpu", "PerCpuInitBsp");
    // Stamp the LAPIC ID from the LAPIC register — the MADT also
    // reports LAPIC IDs, but the register is the authoritative source
    // for the CPU we're actually executing on.
    g_bsp_percpu.lapic_id = static_cast<u32>(arch::LapicRead(arch::kLapicRegId) >> 24);

    WriteMsr(kIa32GsBaseMsr, reinterpret_cast<u64>(&g_bsp_percpu));
    // BSP TSS pointer wired here (TssInit ran before PerCpuInitBsp,
    // so the TSS body is fully populated). All TssSetRsp0 calls from
    // here on go through cpu::CurrentCpu()->tss; the static BSP TSS
    // remains the same object — just routed via PerCpu now.
    g_bsp_percpu.tss = arch::BspTssPtr();
    g_bsp_installed = true;

    arch::SerialWrite("[cpu] BSP PerCpu installed: cpu_id=0 lapic_id=");
    arch::SerialWriteHex(g_bsp_percpu.lapic_id);
    arch::SerialWrite(" addr=");
    arch::SerialWriteHex(reinterpret_cast<u64>(&g_bsp_percpu));
    arch::SerialWrite("\n");
}

PerCpu* CurrentCpu()
{
    // Before BSP install, callers (early-boot self-tests reaching
    // sched::Current() / mm::AddressSpaceCurrent() through inline
    // accessors) would read GSBASE = 0 and the next `->field`
    // deref would be a null-deref UB — UBSAN flagged this with
    // a type-mismatch report at sched.cpp:390 / address_space.cpp:644.
    // Falling back to the static BSP slot here gives every accessor
    // a non-null pointer with valid `current_task` /
    // `current_as` slots before BSP install completes, removing
    // the early-boot UB while the post-install path is unchanged.
    if (!g_bsp_installed)
    {
        return &g_bsp_percpu;
    }
    PerCpu* p;
    // "mov %%gs:0, %0" reads the first qword of the per-CPU region
    // treating it as an offset from GSBASE — but we want the BASE
    // itself. `rdgsbase` is the direct instruction; since we don't
    // gate on CPUID.EBX.FSGSBASE yet, use RDMSR instead.
    u32 lo, hi;
    asm volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(0xC0000101u));
    p = reinterpret_cast<PerCpu*>((static_cast<u64>(hi) << 32) | lo);
    return p;
}

u32 CurrentCpuIdOrBsp()
{
    if (!g_bsp_installed)
    {
        return 0;
    }
    return CurrentCpu()->cpu_id;
}

bool BspInstalled()
{
    return g_bsp_installed;
}

PerCpu* BspPercpu()
{
    return &g_bsp_percpu;
}

} // namespace duetos::cpu
