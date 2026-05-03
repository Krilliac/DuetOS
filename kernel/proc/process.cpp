#include "proc/process.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "diag/hexdump.h"
#include "diag/log_names.h"
#include "diag/runtime_checker.h"
#include "debug/probes.h"
#include "drivers/video/theme.h"
#include "drivers/video/widget.h"
#include "mm/kheap.h"
#include "util/string.h"
#include "subsystems/win32/custom.h"
#include "sched/sched.h"
#include "log/klog.h"
#include "core/panic.h"
#include "loader/pe_loader.h"
#include "time/tick.h"

namespace duetos::core
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
        KLOG_CRITICAL_AS(LogArea::Process, "core/process", "ProcessCreate: KMalloc(Process) returned null", "name",
                         name);
        return nullptr;
    }
    // Zero the entire Process struct. KMalloc returns memory still
    // carrying whatever was last in it — including the freed-payload
    // poison (0xDE) from the C2 frame-allocator patch. Several
    // embedded sub-structures (HandleTable kobj_handles, the
    // win32_dirs[] table, linux_child_exits[]) hold a SpinLock or
    // depend on zero-initialised state. Without this memset the
    // `HandleTableDrain` call in ProcessRelease would lock-acquire
    // a garbage SpinLock and spin forever — confirmed locally as
    // the cause of the qemu-smoke pe-* / ring3 / linux profiles
    // hanging at exactly the post-CleanupProcess marker, while the
    // smoke task slept waiting for a sentinel that never came.
    memset(p, 0, sizeof(Process));

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
    // DLL image table — every slot starts empty. `has_exports`
    // = false marks a free slot (matches DllLoad's post-state
    // on failure), and `ProcessRegisterDllImage` always writes
    // an image with has_exports = true. Walk condition in
    // `ProcessResolveDllExport` stops at `dll_image_count`,
    // so the intervening bytes only need to be zero-ish.
    for (u32 i = 0; i < Process::kDllImageCap; ++i)
    {
        p->dll_images[i].file = nullptr;
        p->dll_images[i].file_len = 0;
        p->dll_images[i].base_va = 0;
        p->dll_images[i].size = 0;
        p->dll_images[i].entry_rva = 0;
        p->dll_images[i].has_exports = false;
    }
    p->dll_image_count = 0;
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
    // Win32 thread table — every slot starts free with exit_code
    // = STILL_ACTIVE (matches Win32 GetExitCodeThread semantics on
    // a running thread).
    for (u32 i = 0; i < Process::kWin32ThreadCap; ++i)
    {
        p->win32_threads[i].in_use = false;
        for (u32 j = 0; j < sizeof(p->win32_threads[i]._pad); ++j)
            p->win32_threads[i]._pad[j] = 0;
        p->win32_threads[i].exit_code = 0x103; // STILL_ACTIVE
        p->win32_threads[i].task = nullptr;
        p->win32_threads[i].user_stack_va = 0;
    }
    // Win32 foreign-thread table — every slot starts free.
    // Populated by NtOpenThread (SYS_THREAD_OPEN), drained by
    // NtClose's by-range dispatch.
    for (u32 i = 0; i < Process::kWin32ForeignThreadCap; ++i)
    {
        p->win32_foreign_threads[i].in_use = false;
        for (u32 j = 0; j < sizeof(p->win32_foreign_threads[i]._pad); ++j)
            p->win32_foreign_threads[i]._pad[j] = 0;
        p->win32_foreign_threads[i].task = nullptr;
        p->win32_foreign_threads[i].owner = nullptr;
    }
    // Win32 section handle table — every slot starts free.
    // Populated by NtCreateSection (SYS_SECTION_CREATE), drained
    // by NtClose's by-range dispatch.
    for (u32 i = 0; i < Process::kWin32SectionCap; ++i)
    {
        p->win32_section_handles[i].in_use = false;
        for (u32 j = 0; j < sizeof(p->win32_section_handles[i]._pad); ++j)
            p->win32_section_handles[i]._pad[j] = 0;
        p->win32_section_handles[i].pool_index = 0;
    }
    // Win32 semaphore table — every slot starts free.
    for (u32 i = 0; i < Process::kWin32SemaphoreCap; ++i)
    {
        p->win32_semaphores[i].in_use = false;
        for (u32 j = 0; j < sizeof(p->win32_semaphores[i]._pad); ++j)
            p->win32_semaphores[i]._pad[j] = 0;
        p->win32_semaphores[i].count = 0;
        p->win32_semaphores[i].max_count = 0;
        for (u32 j = 0; j < sizeof(p->win32_semaphores[i]._pad2); ++j)
            p->win32_semaphores[i]._pad2[j] = 0;
        p->win32_semaphores[i].waiters.head = nullptr;
        p->win32_semaphores[i].waiters.tail = nullptr;
    }
    // Win32 directory handles — every slot empty; entries pointer
    // null until SYS_DIR_OPEN allocates a snapshot.
    for (u64 i = 0; i < Process::kWin32DirCap; ++i)
    {
        p->win32_dirs[i].in_use = false;
        for (u32 j = 0; j < sizeof(p->win32_dirs[i]._pad); ++j)
            p->win32_dirs[i]._pad[j] = 0;
        p->win32_dirs[i].entry_count = 0;
        p->win32_dirs[i].next_index = 0;
        p->win32_dirs[i]._pad2 = 0;
        p->win32_dirs[i].entries = nullptr;
        for (u32 j = 0; j < sizeof(p->win32_dirs[i].path); ++j)
            p->win32_dirs[i].path[j] = 0;
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
    p->linux_pending_signals = 0;
    p->linux_signal_wq.head = nullptr;
    p->linux_signal_wq.tail = nullptr;
    // Rlimit soft caps default to "no cap below kernel hard
    // ceiling"; setrlimit/prlimit64 lower these and fd-alloc /
    // clone honour them.
    p->linux_rlimit_nofile_cur = 0xFFFFFFFFFFFFFFFFull;
    p->linux_rlimit_nproc_cur = 0xFFFFFFFFFFFFFFFFull;
    // Linux parent / wait state. fork() / clone() patches the
    // parent_pid into the child after ProcessCreate returns; bare
    // ProcessCreate has no parent (init-spawned).
    p->linux_parent_pid = 0;
    p->linux_exit_code = 0;
    p->linux_was_signaled = false;
    p->linux_exit_signal = 0;
    for (u32 i = 0; i < sizeof(p->_linux_exit_pad); ++i)
        p->_linux_exit_pad[i] = 0;
    p->linux_child_exit_count = 0;
    for (u64 i = 0; i < Process::kLinuxChildExitCap; ++i)
    {
        p->linux_child_exits[i].pid = 0;
        p->linux_child_exits[i].exit_code = 0;
        p->linux_child_exits[i].exit_signal = 0;
        p->linux_child_exits[i].was_signaled = false;
    }
    p->linux_wait_wq.head = nullptr;
    p->linux_wait_wq.tail = nullptr;
    // Win32 custom-diagnostics state lazy-allocates on first opt-in.
    p->win32_custom_state = nullptr;
    // Default cwd is "/" — matches the value DoGetcwd hard-coded
    // before this field existed.
    for (u32 i = 0; i < Process::kLinuxCwdCap; ++i)
        p->linux_cwd[i] = 0;
    p->linux_cwd[0] = '/';
    for (u32 i = 0; i < Process::kLinuxTaskNameCap; ++i)
        p->linux_task_name[i] = 0;
    for (u64 i = 0; i < Process::kLinuxShmAttachCap; ++i)
    {
        p->linux_shm_attaches[i].in_use = false;
        for (u32 j = 0; j < sizeof(p->linux_shm_attaches[i]._pad); ++j)
            p->linux_shm_attaches[i]._pad[j] = 0;
        p->linux_shm_attaches[i].shmid = 0;
        p->linux_shm_attaches[i].base_va = 0;
        p->linux_shm_attaches[i].page_count = 0;
        p->linux_shm_attaches[i]._pad2 = 0;
    }
    p->linux_shm_cursor = Process::kLinuxShmArenaBase;
    p->refcount = 1;

    ++g_live_processes;

    arch::SerialWrite("[proc] create pid=");
    arch::SerialWriteHex(p->pid);
    arch::SerialWrite(" name=\"");
    arch::SerialWrite(name);
    arch::SerialWrite("\" caps=");
    arch::SerialWriteHex(caps.bits);
    arch::SerialWrite("(");
    SerialWriteCapBits(caps.bits);
    arch::SerialWrite(") code_va=");
    arch::SerialWriteHex(user_code_va);
    arch::SerialWrite(" stack_va=");
    arch::SerialWriteHex(user_stack_va);
    arch::SerialWrite("\n");

    KBP_PROBE_V(::duetos::debug::ProbeId::kProcessCreate, p->pid);
    return p;
}

void ProcessRetain(Process* p)
{
    if (p == nullptr)
    {
        return;
    }
    // A retain on a refcount==0 Process means somebody held a stale
    // pointer to a structure the reaper already returned to the slab.
    // Without this check the count would wrap from 0 to 1 and the
    // process would silently rejoin the live set with corrupted state.
    if (p->refcount == 0)
    {
        PanicWithValue("core/process", "ProcessRetain on refcount==0 (use-after-free?)", reinterpret_cast<u64>(p));
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

    KBP_PROBE_V(::duetos::debug::ProbeId::kProcessDestroy, p->pid);

    // Reap any windows this process registered but never
    // DestroyWindow'd. Walks the compositor registry under the
    // compositor lock so it serialises cleanly with the input
    // threads + ui ticker that also draw. Triggered on the LAST
    // reference-drop, so multi-threaded processes reap exactly
    // once (when the final thread exits). `WindowReapByOwner`
    // refuses pid==0 (kernel-owned boot windows) as a safety
    // belt.
    {
        duetos::drivers::video::CompositorLock();
        const u32 reaped = duetos::drivers::video::WindowReapByOwner(p->pid);
        if (reaped > 0)
        {
            const duetos::drivers::video::Theme& theme = duetos::drivers::video::ThemeCurrent();
            duetos::drivers::video::DesktopCompose(theme.desktop_bg, "WELCOME TO DUETOS   BOOT OK");
            arch::SerialWrite("[proc] reap-windows pid=");
            arch::SerialWriteHex(p->pid);
            arch::SerialWrite(" count=");
            arch::SerialWriteHex(reaped);
            arch::SerialWrite("\n");
        }
        duetos::drivers::video::CompositorUnlock();
    }

    arch::SerialWrite("[proc] destroy pid=");
    arch::SerialWriteHex(p->pid);
    arch::SerialWrite(" name=\"");
    arch::SerialWrite(p->name);
    arch::SerialWrite("\"\n");

    // Notify the Linux parent (if any) that this process has exited.
    // Parent is found by PID — pids are monotonically incrementing
    // and never reused, so a missed lookup means the parent died
    // first (orphaned child case; nothing to do — sub-GAP: no
    // init-style reaper yet, so orphaned exits drop their status).
    //
    // Done BEFORE the KFree below so the parent's queue mutation
    // happens while the dying process's data is still valid.
    if (p->linux_parent_pid != 0)
    {
        Process* parent = sched::SchedFindProcessByPid(p->linux_parent_pid);
        if (parent != nullptr)
        {
            arch::Cli();
            if (parent->linux_child_exit_count < Process::kLinuxChildExitCap)
            {
                auto& slot = parent->linux_child_exits[parent->linux_child_exit_count];
                slot.pid = p->pid;
                slot.exit_code = p->linux_exit_code;
                slot.was_signaled = p->linux_was_signaled;
                slot.exit_signal = p->linux_exit_signal;
                ++parent->linux_child_exit_count;
                sched::WaitQueueWakeOne(&parent->linux_wait_wq);
            }
            arch::Sti();
        }
    }

    // Drop the AS reference we took at create. If this was the last
    // process/task holding that AS (v0: always true — one task per
    // process, one process per AS), the AS destroy path runs inline:
    // user-half tables freed, backing frames returned, PML4 frame
    // returned.
    mm::AddressSpaceRelease(p->as);
    p->as = nullptr;
    arch::SerialWrite("[proc] release: post-AS\n");

    // Emit the recorded diagnostic data to serial before the
    // state is freed. No-op when the process has no custom state
    // (non-Win32 native + Linux processes). For Win32 PEs the
    // observability tier is auto-on, so this fires for every Win32
    // PE exit and gives a post-mortem record without anyone having
    // to know the dump syscall exists.
    subsystems::win32::custom::DumpOnAbnormalExit(p);
    arch::SerialWrite("[proc] release: post-DumpOnAbnormalExit\n");

    // Free the Win32 custom-diagnostics state if any was allocated.
    // No-op when the process never opted into any custom-Win32
    // feature (the common path).
    subsystems::win32::custom::CleanupProcess(p);
    arch::SerialWrite("[proc] release: post-CleanupProcess\n");

    // Free any directory-iteration snapshots the process leaked
    // by exiting without CloseHandle on its FindFirstFile pairs.
    for (u64 i = 0; i < Process::kWin32DirCap; ++i)
    {
        if (p->win32_dirs[i].entries != nullptr)
        {
            mm::KFree(p->win32_dirs[i].entries);
            p->win32_dirs[i].entries = nullptr;
        }
    }

    arch::SerialWrite("[proc] release: post-win32_dirs\n");

    // Drain the unified KObject handle table (plan A3). Calls
    // KObjectRelease on every live slot so any object whose final
    // reference was held by this process gets destroyed cleanly,
    // even on abnormal exit. No-op when the process never inserted
    // anything (the common case while the existing per-type Win32
    // tables remain authoritative).
    ::duetos::ipc::HandleTableDrain(p->kobj_handles);
    arch::SerialWrite("[proc] release: post-HandleTableDrain\n");

    // Drop the stdin focus if this process held it. Without this,
    // kbd-reader would keep pushing into the freed ring's head
    // cursor and walking off the heap. No-op for processes that
    // never called SYS_STDIN_READ.
    StdinFocusClearIf(p);

    mm::KFree(p);
    --g_live_processes;
    arch::SerialWrite("[proc] release: done\n");
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
    // Defence-in-depth against early-boot pre-PerCpuInit calls and
    // any future regression where CurrentTask() returns garbage:
    // a non-null but non-canonical / non-kernel-VA pointer would
    // pass the null-check above and #GP on the next dereference.
    // The original failure mode was SyscallGateSelfTest running
    // before PerCpuInitBsp under SeaBIOS — see main.cpp at the
    // SyscallGateSelfTest call site for the full rationale. The
    // ordering bug is fixed there; this guard ensures any future
    // pre-init caller fails closed instead of triple-faulting.
    if (!PlausibleKernelAddress(reinterpret_cast<u64>(t)))
    {
        return;
    }
    Process* p = sched::TaskProcess(t);
    if (p == nullptr)
    {
        // Invariant: kernel-only tasks never traverse the user-syscall
        // cap-gate path. Reaching this with a null Process means a
        // kernel TU mis-routed into the sandbox-denial recorder, or a
        // user task lost its Process pointer mid-flight — both indicate
        // memory corruption or a gating-table bug. Log once so the
        // first occurrence is visible without paniccing the live system.
        KLOG_ONCE_WARN("proc", "RecordSandboxDenial: kernel-only task hit cap denial (gating bug?)");
        return;
    }
    ++p->sandbox_denials;

    // Fire the sandbox-denial probe at the same rate-limit the
    // existing denial logger uses (first hit + every 32nd). Same
    // motivation: a ring-3 hostile task can otherwise flood the
    // probe log with thousands of identical lines per boot.
    if (ShouldLogDenial(p->sandbox_denials))
    {
        KBP_PROBE_V(::duetos::debug::ProbeId::kSandboxDenialCap, static_cast<u64>(cap));
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

i32 RecordFsWriteCheckLevel(Process* p, u64 bytes)
{
    if (p == nullptr || bytes == 0)
        return -1;
    p->fs_write_bytes_total += bytes;

    // Walk every window level. TickCount is monotonic, so a
    // "now older than start by >= window" check covers both
    // the fresh-window (start_tick == 0) case and the legitimate
    // roll case in one expression. We deliberately reset to
    // `bytes` (not 0) on roll so a single oversized write is
    // still counted toward the new window — an attacker cannot
    // evade the cap by pacing one >cap write per window.
    //
    // Returns the index of the FIRST level that tripped, or -1
    // if all three are still within budget. Returning the index
    // (instead of bool) lets the caller log which timescale's
    // wall just fired — an attacker who tripped the long-tail
    // wall is materially different from one who tripped the
    // burst wall, and operators care about the difference.
    const u64 now = ::duetos::time::TickCount();
    i32 first_tripped = -1;
    for (u32 lvl = 0; lvl < Process::kFsWriteWindowCount; ++lvl)
    {
        const u64 ticks = kFsWriteWindowTicksByLevel[lvl];
        const u64 cap = kFsWriteWindowByteCapByLevel[lvl];
        const u64 start = p->fs_write_window_start_tick[lvl];
        if (start == 0 || now - start >= ticks)
        {
            p->fs_write_window_start_tick[lvl] = now;
            p->fs_write_window_bytes[lvl] = bytes;
        }
        else
        {
            p->fs_write_window_bytes[lvl] += bytes;
        }
        if (first_tripped < 0 && p->fs_write_window_bytes[lvl] > cap)
            first_tripped = static_cast<i32>(lvl);
    }
    return first_tripped;
}

bool RecordFsWriteCheck(Process* p, u64 bytes)
{
    return RecordFsWriteCheckLevel(p, bytes) >= 0;
}

void RecordFsWrite(Process* p, u64 bytes)
{
    const i32 lvl = RecordFsWriteCheckLevel(p, bytes);
    if (lvl < 0)
        return;
    // Threshold crossed. Log every over-cap call so the operator
    // sees how badly the rogue process pushed past the limit;
    // FlagCurrentForKill is itself idempotent so repeated calls
    // before the scheduler reaps cost nothing beyond the log.
    arch::SerialWrite("[fsguard] pid=");
    arch::SerialWriteHex(p->pid);
    arch::SerialWrite(" name=\"");
    arch::SerialWrite(p->name != nullptr ? p->name : "<null>");
    arch::SerialWrite("\" tripped ");
    arch::SerialWrite(kFsWriteWindowLabels[lvl]);
    arch::SerialWrite(" cap (window_bytes=");
    arch::SerialWriteHex(p->fs_write_window_bytes[lvl]);
    arch::SerialWrite(") — terminating (suspected ransomware)\n");
    RuntimeCheckerNoteFsWriteRateExceeded(static_cast<u32>(lvl));
    sched::FlagCurrentForKill(sched::KillReason::FsWriteRateExceeded);
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
    case kCapNet:
        return "Net";
    case kCapInput:
        return "Input";
    case kCapCount:
        return "<sentinel>";
    default:
        return "<unknown>";
    }
}

namespace
{

// ASCII to-lower. Kernel has no stdlib; this keeps DLL name
// matching case-insensitive without pulling in <cctype>.
inline char AsciiToLower(char c)
{
    if (c >= 'A' && c <= 'Z')
        return static_cast<char>(c + ('a' - 'A'));
    return c;
}

// Case-insensitive strcmp for DLL names. Matches Win32
// convention — lld-link emits "CUSTOMDLL.dll" or
// "customdll.dll" inconsistently across toolchains.
bool DllNameEq(const char* a, const char* b)
{
    if (a == nullptr || b == nullptr)
        return a == b;
    while (*a && *b)
    {
        if (AsciiToLower(*a) != AsciiToLower(*b))
            return false;
        ++a;
        ++b;
    }
    return *a == *b;
}

} // namespace

u64 ProcessFindDllBaseByName(const Process* proc, const char* dll_name)
{
    if (proc == nullptr)
    {
        KLOG_DEBUG_A(LogArea::Loader, "core/process", "ProcessFindDllBaseByName: null proc");
        return 0;
    }
    /* NULL or empty name → return the EXE image base (Win32
     * GetModuleHandleW(NULL) semantics). pe_image_base is zero
     * for non-PE processes; the caller surfaces that as a NULL
     * HMODULE which matches the documented "no main module
     * available" behaviour. */
    if (dll_name == nullptr || dll_name[0] == '\0')
    {
        KLOG_DEBUG_AV(LogArea::Loader, "core/process", "ProcessFindDllBaseByName: empty name -> EXE pe_image_base",
                      proc->pe_image_base);
        return proc->pe_image_base;
    }
    // Strip any ".dll" / ".DLL" suffix from the lookup so callers
    // that pass either form match. Win32 convention is "name with
    // extension"; ld-link sometimes records the bare name in the
    // export table.
    char trimmed[64];
    u32 i = 0;
    while (dll_name[i] != '\0' && i < sizeof(trimmed) - 1)
    {
        trimmed[i] = dll_name[i];
        ++i;
    }
    trimmed[i] = '\0';
    if (i >= 4)
    {
        const char* tail = trimmed + i - 4;
        if ((tail[0] == '.') && AsciiToLower(tail[1]) == 'd' && AsciiToLower(tail[2]) == 'l' &&
            AsciiToLower(tail[3]) == 'l')
        {
            *(char*)tail = '\0';
        }
    }
    for (u64 j = 0; j < proc->dll_image_count; ++j)
    {
        const DllImage& img = proc->dll_images[j];
        if (!img.has_exports)
            continue;
        const char* name = PeExportsDllName(img.exports);
        if (name == nullptr)
            continue;
        // Compare with the same suffix-tolerant rule on both sides.
        char other[64];
        u32 oi = 0;
        while (name[oi] != '\0' && oi < sizeof(other) - 1)
        {
            other[oi] = name[oi];
            ++oi;
        }
        other[oi] = '\0';
        if (oi >= 4)
        {
            const char* tail = other + oi - 4;
            if ((tail[0] == '.') && AsciiToLower(tail[1]) == 'd' && AsciiToLower(tail[2]) == 'l' &&
                AsciiToLower(tail[3]) == 'l')
            {
                *(char*)tail = '\0';
            }
        }
        if (DllNameEq(trimmed, other))
            return img.base_va;
    }
    return 0;
}

bool ProcessRegisterDllImage(Process* proc, const DllImage& image)
{
    if (proc == nullptr)
        return false;
    if (proc->dll_image_count >= Process::kDllImageCap)
    {
        arch::SerialWrite("[proc] dll-table FULL pid=");
        arch::SerialWriteHex(proc->pid);
        arch::SerialWrite(" cap=");
        arch::SerialWriteHex(Process::kDllImageCap);
        arch::SerialWrite("\n");
        return false;
    }
    proc->dll_images[proc->dll_image_count] = image;
    ++proc->dll_image_count;
    return true;
}

u64 ProcessResolveDllExport(const Process* proc, const char* dll_name, const char* func_name)
{
    if (proc == nullptr || func_name == nullptr)
        return 0;
    for (u64 i = 0; i < proc->dll_image_count; ++i)
    {
        const DllImage& img = proc->dll_images[i];
        if (!img.has_exports)
            continue;
        if (dll_name != nullptr)
        {
            const char* name = PeExportsDllName(img.exports);
            if (!DllNameEq(name, dll_name))
                continue;
        }
        PeExport e{};
        if (!PeExportLookupName(img.exports, func_name, e))
            continue;
        if (e.is_forwarder)
        {
            // Chase the forwarder through the rest of the process's
            // DLL table. The shared resolver handles both name- and
            // ordinal-form forwarders and bounds against cycles.
            const char* fwd_dll = PeExportsDllName(img.exports);
            u64 va = 0;
            if (PeResolveViaDlls(fwd_dll, func_name, proc->dll_images, proc->dll_image_count, &va))
                return va;
            return 0;
        }
        return img.base_va + static_cast<u64>(e.rva);
    }
    return 0;
}

u64 ProcessResolveDllExportByBase(const Process* proc, u64 base_va, const char* func_name)
{
    if (proc == nullptr || func_name == nullptr)
        return 0;
    for (u64 i = 0; i < proc->dll_image_count; ++i)
    {
        const DllImage& img = proc->dll_images[i];
        if (!img.has_exports)
            continue;
        if (base_va != 0 && img.base_va != base_va)
            continue;
        PeExport e{};
        if (!PeExportLookupName(img.exports, func_name, e))
            continue;
        if (e.is_forwarder)
        {
            const char* fwd_dll = PeExportsDllName(img.exports);
            u64 va = 0;
            if (PeResolveViaDlls(fwd_dll, func_name, proc->dll_images, proc->dll_image_count, &va))
                return va;
            return 0;
        }
        return img.base_va + static_cast<u64>(e.rva);
    }
    return 0;
}

namespace
{

void Expect(bool cond, const char* what)
{
    if (cond)
    {
        return;
    }
    arch::SerialWrite("[process-selftest] FAIL ");
    arch::SerialWrite(what);
    arch::SerialWrite("\n");
    Panic("core/process", "ProcessSelfTest assertion failed");
}

bool StrEq(const char* a, const char* b)
{
    if (a == nullptr || b == nullptr)
    {
        return a == b;
    }
    while (*a && *b)
    {
        if (*a != *b)
        {
            return false;
        }
        ++a;
        ++b;
    }
    return *a == *b;
}

} // namespace

void ProcessSelfTest()
{
    KLOG_TRACE_SCOPE("core/process", "ProcessSelfTest");

    // ----- CapSet bitmap basics -----
    {
        constexpr CapSet empty = CapSetEmpty();
        Expect(empty.bits == 0, "CapSetEmpty.bits == 0");
        Expect(!CapSetHas(empty, kCapSerialConsole), "empty has no SerialConsole");
        Expect(!CapSetHas(empty, kCapFsRead), "empty has no FsRead");
        Expect(!CapSetHas(empty, kCapFsWrite), "empty has no FsWrite");
        Expect(!CapSetHas(empty, kCapDebug), "empty has no Debug");
        Expect(!CapSetHas(empty, kCapSpawnThread), "empty has no SpawnThread");
        Expect(!CapSetHas(empty, kCapNet), "empty has no Net");
        Expect(!CapSetHas(empty, kCapInput), "empty has no Input");
    }
    {
        constexpr CapSet trusted = CapSetTrusted();
        Expect(trusted.bits != 0, "CapSetTrusted not empty");
        Expect(CapSetHas(trusted, kCapSerialConsole), "trusted has SerialConsole");
        Expect(CapSetHas(trusted, kCapFsRead), "trusted has FsRead");
        Expect(CapSetHas(trusted, kCapFsWrite), "trusted has FsWrite");
        Expect(CapSetHas(trusted, kCapDebug), "trusted has Debug");
        Expect(CapSetHas(trusted, kCapSpawnThread), "trusted has SpawnThread");
        Expect(CapSetHas(trusted, kCapNet), "trusted has Net");
        Expect(CapSetHas(trusted, kCapInput), "trusted has Input");
    }

    // ----- Boundary cases on the cap enum -----
    {
        CapSet s = CapSetEmpty();
        // kCapNone never enters the bitmap — it's the "no cap" sentinel.
        CapSetAdd(s, kCapNone);
        Expect(s.bits == 0, "CapSetAdd(kCapNone) is a no-op");
        Expect(!CapSetHas(s, kCapNone), "CapSetHas(kCapNone) is false");

        // kCapCount is the boundary marker, never live.
        CapSetAdd(s, kCapCount);
        Expect(s.bits == 0, "CapSetAdd(kCapCount) is a no-op");
        Expect(!CapSetHas(s, kCapCount), "CapSetHas(kCapCount) is false");
    }

    // ----- CapSetAdd accumulates without disturbing other bits -----
    {
        CapSet s = CapSetEmpty();
        CapSetAdd(s, kCapSerialConsole);
        Expect(CapSetHas(s, kCapSerialConsole), "after Add SerialConsole, set");
        Expect(!CapSetHas(s, kCapFsRead), "after Add SerialConsole, FsRead unset");
        CapSetAdd(s, kCapFsRead);
        Expect(CapSetHas(s, kCapSerialConsole), "after second Add, SerialConsole still set");
        Expect(CapSetHas(s, kCapFsRead), "after Add FsRead, set");
        // Adding the same cap twice is a no-op.
        const u64 before = s.bits;
        CapSetAdd(s, kCapSerialConsole);
        Expect(s.bits == before, "double-Add is idempotent");
    }

    // ----- CapName: every defined cap returns a real string -----
    Expect(StrEq(CapName(kCapNone), "<none>"), "CapName(kCapNone) == <none>");
    Expect(StrEq(CapName(kCapSerialConsole), "SerialConsole"), "CapName(SerialConsole)");
    Expect(StrEq(CapName(kCapFsRead), "FsRead"), "CapName(FsRead)");
    Expect(StrEq(CapName(kCapDebug), "Debug"), "CapName(Debug)");
    Expect(StrEq(CapName(kCapFsWrite), "FsWrite"), "CapName(FsWrite)");
    Expect(StrEq(CapName(kCapSpawnThread), "SpawnThread"), "CapName(SpawnThread)");
    Expect(StrEq(CapName(kCapNet), "Net"), "CapName(Net)");
    Expect(StrEq(CapName(kCapInput), "Input"), "CapName(Input)");
    Expect(StrEq(CapName(kCapCount), "<sentinel>"), "CapName(kCapCount) == <sentinel>");

    // Catches "added an enum value, forgot the switch arm" — every
    // entry from 1 to kCapCount must produce a non-fallback name.
    for (u32 c = 1; c < static_cast<u32>(kCapCount); ++c)
    {
        const char* name = CapName(static_cast<Cap>(c));
        Expect(name != nullptr, "CapName non-null");
        Expect(!StrEq(name, "<unknown>"), "CapName covers every enumerator");
    }

    // ----- ShouldLogDenial rate-limit (1st, then every 32nd) -----
    Expect(ShouldLogDenial(1), "denial #1 logs");
    Expect(!ShouldLogDenial(2), "denial #2 silent");
    Expect(!ShouldLogDenial(31), "denial #31 silent");
    Expect(ShouldLogDenial(32), "denial #32 logs");
    Expect(!ShouldLogDenial(33), "denial #33 silent");
    Expect(ShouldLogDenial(64), "denial #64 logs");
    Expect(ShouldLogDenial(96), "denial #96 logs");
    Expect(ShouldLogDenial(kSandboxDenialKillThreshold - 4), "denial near threshold logs (96)");

    arch::SerialWrite("[process-selftest] PASS (CapSet + CapName + ShouldLogDenial)\n");
}

// ---------------------------------------------------------------
// Stdin ring buffer — per-process keyboard input pipe.
//
// Producer:  kbd-reader thread in core/main.cpp (single-writer).
// Consumer:  ring-3 task in SYS_STDIN_READ (single-reader).
//
// Lock-free single-writer / single-reader semantics: head moves
// only inside ProcessFeedStdinChar, tail moves only inside
// ProcessReadStdinBlocking. Interrupts are masked across the
// "check empty + block" pair in the reader so a wake from the
// producer can't slip between the read of `head` and the call
// into WaitQueueBlock.
//
// Overflow policy: drop oldest. The kbd-reader can't usefully
// back-pressure the IRQ source, and a wedged ring-3 reader
// shouldn't be able to freeze the pipeline. Treats stdin like a
// tty input queue.
// ---------------------------------------------------------------

namespace
{

// Single-process stdin focus. Set on the first SYS_STDIN_READ
// from a process; cleared on ProcessRelease for that process.
// nullptr = no ring-3 consumer is waiting on stdin, so the kbd-
// reader simply doesn't push anything (printable keys still feed
// the kernel shell + window-active-app handlers, unchanged).
constinit Process* g_stdin_focus = nullptr;

} // namespace

void ProcessFeedStdinChar(Process* proc, char c)
{
    if (proc == nullptr)
        return;
    Process::StdinRing& r = proc->stdin_ring;
    arch::Cli();
    // Drop oldest on overflow — keep the producer non-blocking.
    if (r.head - r.tail >= Process::StdinRing::kCap)
        ++r.tail;
    r.buf[r.head & (Process::StdinRing::kCap - 1)] = static_cast<u8>(c);
    ++r.head;
    sched::WaitQueueWakeOne(&r.waiters);
    arch::Sti();
}

i64 ProcessReadStdinBlocking(Process* proc, void* dst_user, u64 cap)
{
    if (proc == nullptr || dst_user == nullptr || cap == 0)
        return -1;
    // Claim the stdin focus on the first read. Lets the kbd-reader
    // start delivering bytes without an explicit registration call.
    if (g_stdin_focus == nullptr)
        g_stdin_focus = proc;

    Process::StdinRing& r = proc->stdin_ring;
    arch::Cli();
    while (r.head == r.tail)
    {
        sched::WaitQueueBlock(&r.waiters);
        // Returns with interrupts still off. Loop re-checks the
        // ring in case of a spurious wake.
    }
    // Drain whatever's available (cap-bounded). Bytes go into a
    // small kernel scratch first so CopyToUser is one shot per
    // call — the user buffer can't be touched with IRQs masked
    // (page fault on demand-paged user pages would never resolve).
    const u32 available = static_cast<u32>(r.head - r.tail);
    const u32 to_copy_u32 = (cap < available) ? static_cast<u32>(cap) : available;
    u8 scratch[Process::StdinRing::kCap];
    for (u32 i = 0; i < to_copy_u32; ++i)
        scratch[i] = r.buf[(r.tail + i) & (Process::StdinRing::kCap - 1)];
    r.tail += to_copy_u32;
    arch::Sti();

    if (!mm::CopyToUser(dst_user, scratch, to_copy_u32))
        return -1;
    return static_cast<i64>(to_copy_u32);
}

Process* StdinFocusGet()
{
    return g_stdin_focus;
}

void StdinFocusSet(Process* proc)
{
    g_stdin_focus = proc;
}

void StdinFocusClearIf(Process* proc)
{
    arch::Cli();
    if (g_stdin_focus == proc)
        g_stdin_focus = nullptr;
    arch::Sti();
}

void ProcessFeedStdinFocusChar(char c)
{
    // Read the focus pointer and push to the ring under one IRQ-
    // off section so a reaper running on this CPU can't free the
    // process between the two operations. The kbd-reader is the
    // sole caller; the cost (one Cli/Sti pair per byte) is
    // negligible compared to the IRQ-off hop the kbd-reader
    // already does to drain the scancode ring.
    arch::Cli();
    Process* const proc = g_stdin_focus;
    if (proc != nullptr)
    {
        Process::StdinRing& r = proc->stdin_ring;
        if (r.head - r.tail >= Process::StdinRing::kCap)
            ++r.tail;
        r.buf[r.head & (Process::StdinRing::kCap - 1)] = static_cast<u8>(c);
        ++r.head;
        sched::WaitQueueWakeOne(&r.waiters);
    }
    arch::Sti();
}

} // namespace duetos::core
