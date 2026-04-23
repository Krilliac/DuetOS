#include "process.h"

#include "../arch/x86_64/serial.h"
#include "../debug/probes.h"
#include "../mm/kheap.h"
#include "../sched/sched.h"
#include "klog.h"
#include "panic.h"

namespace customos::core
{

namespace
{

// Monotonic PID generator. Never reuses — matches the Task id
// discipline in the scheduler. PID 0 is reserved for "no process"
// (the kernel's implicit, never-allocated init-context), so the
// counter starts at 1.
constinit u64 g_next_pid = 1;
constinit u64 g_live_processes = 0;

} // namespace

Process* ProcessCreate(const char* name, mm::AddressSpace* as, CapSet caps, const fs::RamfsNode* root, u64 user_code_va,
                       u64 user_stack_va, u64 tick_budget)
{
    KLOG_TRACE_SCOPE("core/process", "ProcessCreate");
    KASSERT(name != nullptr, "core/process", "ProcessCreate null name");
    KASSERT(as != nullptr, "core/process", "ProcessCreate null as");
    KASSERT(root != nullptr, "core/process", "ProcessCreate null root");
    KASSERT(tick_budget > 0, "core/process", "ProcessCreate zero tick_budget");

    auto* p = static_cast<Process*>(mm::KMalloc(sizeof(Process)));
    if (p == nullptr)
    {
        return nullptr;
    }

    p->pid = g_next_pid++;
    p->name = name;
    p->as = as;
    p->caps = caps;
    p->root = root;
    p->user_code_va = user_code_va;
    p->user_stack_va = user_stack_va;
    p->user_rsp_init = 0; // loader overrides if it wants a custom rsp
    p->user_gs_base = 0;  // PE loader sets this to the TEB VA
    p->win32_iat_miss_count = 0;
    p->tick_budget = tick_budget;
    p->ticks_used = 0;
    p->sandbox_denials = 0;
    p->win32_last_error = 0; // ERROR_SUCCESS
    p->heap_base = 0;        // PeLoad fills these when the PE has
    p->heap_pages = 0;       // imports — see subsystems/win32/heap.cpp
    p->heap_free_head = 0;
    // Linux fd table: reserve stdin/stdout/stderr, mark rest unused.
    for (u32 i = 0; i < 16; ++i)
    {
        p->linux_fds[i].state = (i < 3) ? 1 /* reserved-tty */ : 0;
        p->linux_fds[i].first_cluster = 0;
        p->linux_fds[i].size = 0;
        p->linux_fds[i].offset = 0;
        for (u32 j = 0; j < sizeof(p->linux_fds[i]._pad); ++j)
            p->linux_fds[i]._pad[j] = 0;
        p->linux_fds[i]._pad2 = 0;
        for (u32 j = 0; j < sizeof(p->linux_fds[i].path); ++j)
            p->linux_fds[i].path[j] = 0;
    }
    p->linux_brk_base = 0; // loader fills when abi_flavor = kAbiLinux
    p->linux_brk_current = 0;
    p->linux_mmap_cursor = 0;
    p->abi_flavor = kAbiNative; // loaders flip to kAbiLinux if appropriate
    for (u32 i = 0; i < sizeof(p->_abi_pad); ++i)
        p->_abi_pad[i] = 0;
    // Win32 file-handle table — every slot starts unused. The
    // `kind == None` sentinel distinguishes free slots; the
    // ramfs / fat32 fields are valid only when kind matches.
    for (u32 i = 0; i < Process::kWin32HandleCap; ++i)
    {
        p->win32_handles[i].kind = Process::FsBackingKind::None;
        p->win32_handles[i].ramfs_node = nullptr;
        p->win32_handles[i].fat32_volume_idx = 0;
        p->win32_handles[i].cursor = 0;
    }
    // Win32 VirtualAlloc arena — bump-only for v0. Starts at
    // Process::kWin32VmapBase with 0 pages consumed.
    p->vmap_base = Process::kWin32VmapBase;
    p->vmap_pages_used = 0;
    // Win32 mutex table — every slot starts free + unowned.
    for (u32 i = 0; i < Process::kWin32MutexCap; ++i)
    {
        p->win32_mutexes[i].in_use = false;
        for (u32 j = 0; j < sizeof(p->win32_mutexes[i]._pad); ++j)
            p->win32_mutexes[i]._pad[j] = 0;
        p->win32_mutexes[i].recursion = 0;
        p->win32_mutexes[i].owner = nullptr;
        p->win32_mutexes[i].waiters.head = nullptr;
        p->win32_mutexes[i].waiters.tail = nullptr;
    }
    // Win32 event table — every slot starts free + unsignaled.
    for (u32 i = 0; i < Process::kWin32EventCap; ++i)
    {
        p->win32_events[i].in_use = false;
        p->win32_events[i].manual_reset = false;
        p->win32_events[i].signaled = false;
        for (u32 j = 0; j < sizeof(p->win32_events[i]._pad); ++j)
            p->win32_events[i]._pad[j] = 0;
        p->win32_events[i].waiters.head = nullptr;
        p->win32_events[i].waiters.tail = nullptr;
    }
    // Win32 thread table — every slot starts free.
    for (u32 i = 0; i < Process::kWin32ThreadCap; ++i)
    {
        p->win32_threads[i].in_use = false;
        for (u32 j = 0; j < sizeof(p->win32_threads[i]._pad); ++j)
            p->win32_threads[i]._pad[j] = 0;
        p->win32_threads[i].task = nullptr;
        p->win32_threads[i].user_stack_va = 0;
    }
    p->thread_stack_cursor = Process::kV0ThreadStackArenaBase;
    // Win32 TLS — no slots allocated, all values zero.
    p->tls_slot_in_use = 0;
    for (u32 i = 0; i < Process::kWin32TlsCap; ++i)
        p->tls_slot_value[i] = 0;
    // Linux signal-handler table — every signal starts at SIG_DFL
    // (handler_va == 0), no flags, no mask.
    for (u32 i = 0; i < Process::kLinuxSignalCount; ++i)
    {
        p->linux_sigactions[i].handler_va = 0;
        p->linux_sigactions[i].flags = 0;
        p->linux_sigactions[i].restorer_va = 0;
        p->linux_sigactions[i].mask = 0;
    }
    p->linux_signal_mask = 0;
    p->refcount = 1;

    ++g_live_processes;

    arch::SerialWrite("[proc] create pid=");
    arch::SerialWriteHex(p->pid);
    arch::SerialWrite(" name=\"");
    arch::SerialWrite(name);
    arch::SerialWrite("\" caps=");
    arch::SerialWriteHex(caps.bits);
    arch::SerialWrite(" code_va=");
    arch::SerialWriteHex(user_code_va);
    arch::SerialWrite(" stack_va=");
    arch::SerialWriteHex(user_stack_va);
    arch::SerialWrite("\n");

    KBP_PROBE_V(::customos::debug::ProbeId::kProcessCreate, p->pid);
    return p;
}

void ProcessRetain(Process* p)
{
    if (p == nullptr)
    {
        return;
    }
    ++p->refcount;
}

void ProcessRelease(Process* p)
{
    if (p == nullptr)
    {
        return;
    }
    if (p->refcount == 0)
    {
        PanicWithValue("core/process", "ProcessRelease on refcount==0", reinterpret_cast<u64>(p));
    }
    --p->refcount;
    if (p->refcount != 0)
    {
        return;
    }

    KBP_PROBE_V(::customos::debug::ProbeId::kProcessDestroy, p->pid);

    arch::SerialWrite("[proc] destroy pid=");
    arch::SerialWriteHex(p->pid);
    arch::SerialWrite(" name=\"");
    arch::SerialWrite(p->name);
    arch::SerialWrite("\"\n");

    // Drop the AS reference we took at create. If this was the last
    // process/task holding that AS (v0: always true — one task per
    // process, one process per AS), the AS destroy path runs inline:
    // user-half tables freed, backing frames returned, PML4 frame
    // returned.
    mm::AddressSpaceRelease(p->as);
    p->as = nullptr;

    mm::KFree(p);
    --g_live_processes;
}

Process* CurrentProcess()
{
    sched::Task* t = sched::CurrentTask();
    if (t == nullptr)
    {
        return nullptr;
    }
    return sched::TaskProcess(t);
}

void RecordSandboxDenial(Cap cap)
{
    sched::Task* t = sched::CurrentTask();
    if (t == nullptr)
    {
        return;
    }
    Process* p = sched::TaskProcess(t);
    if (p == nullptr)
    {
        return; // kernel-only task hit a cap-denial — shouldn't happen
    }
    ++p->sandbox_denials;

    // Fire the sandbox-denial probe at the same rate-limit the
    // existing denial logger uses (first hit + every 32nd). Same
    // motivation: a ring-3 hostile task can otherwise flood the
    // probe log with thousands of identical lines per boot.
    if (ShouldLogDenial(p->sandbox_denials))
    {
        KBP_PROBE_V(::customos::debug::ProbeId::kSandboxDenialCap, static_cast<u64>(cap));
    }

    // Threshold-crossing: fire once at exactly kSandbox-
    // DenialKillThreshold and flag the task. Uses `==` so the
    // message doesn't repeat for denials that race past the
    // flag before Schedule picks them up.
    if (p->sandbox_denials == kSandboxDenialKillThreshold)
    {
        arch::SerialWrite("[sandbox] pid=");
        arch::SerialWriteHex(p->pid);
        arch::SerialWrite(" hit ");
        arch::SerialWriteHex(kSandboxDenialKillThreshold);
        arch::SerialWrite(" denials (last cap=");
        arch::SerialWrite(CapName(cap));
        arch::SerialWrite(") — terminating as malicious\n");
        sched::FlagCurrentForKill(sched::KillReason::SandboxDenialThreshold);
    }
}

bool ShouldLogDenial(u64 denial_index)
{
    // Rate-limit per-process denial log output. Always log the
    // first denial (so a bug in legitimate code surfaces
    // immediately), then log once every 32 thereafter. A burst
    // of 100 denials produces 1 + 3 = 4 log lines instead of
    // 100. The counter itself advances on every denial — only
    // the log is rate-limited — so the threshold-kill still
    // fires at the exact 100th attempt.
    //
    // 32 chosen because log2 is convenient and it produces ~4
    // lines at the threshold; tune if future workloads spam
    // the log at a different rate.
    return denial_index == 1 || (denial_index & 31) == 0;
}

const char* CapName(Cap c)
{
    switch (c)
    {
    case kCapNone:
        return "<none>";
    case kCapSerialConsole:
        return "SerialConsole";
    case kCapFsRead:
        return "FsRead";
    case kCapDebug:
        return "Debug";
    case kCapFsWrite:
        return "FsWrite";
    case kCapSpawnThread:
        return "SpawnThread";
    case kCapCount:
        return "<sentinel>";
    }
    return "<unknown>";
}

} // namespace customos::core
