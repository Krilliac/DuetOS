#include "proc/process.h"

#include "ipc/kfile.h"
#include "ipc/kobject.h"
#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "diag/fix_journal.h"
#include "diag/hexdump.h"
#include "diag/leak_detector.h"
#include "diag/log_names.h"
#include "diag/runtime_checker.h"
#include "debug/probes.h"
#include "drivers/video/theme.h"
#include "drivers/video/widget.h"
#include "mm/address_space.h"
#include "mm/kheap.h"
#include "net/socket.h"
#include "util/string.h"
#include "subsystems/win32/custom.h"
#include "subsystems/win32/window_syscall.h"
#include "sched/sched.h"
#include "sync/spinlock.h"
#include "log/klog.h"
#include "core/panic.h"
#include "loader/pe_loader.h"
#include "security/event_ring.h"
#include "security/ir_runbook.h"
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
    p->heap_base = 0;  // PeLoad fills these when the PE has
    p->heap_pages = 0; // imports — see subsystems/win32/heap.cpp
    p->heap_free_head = 0;
    // Linux fd table: reserve stdin/stdout/stderr, mark rest unused.
    for (u32 i = 0; i < 16; ++i)
    {
        p->linux_fds[i].state = (i < 3) ? 1 /* reserved-tty */ : 0;
        p->linux_fds[i].flags = 0;
        p->linux_fds[i].first_cluster = 0;
        p->linux_fds[i].size = 0;
        p->linux_fds[i].kf_handle = ::duetos::ipc::kHandleInvalid;
        p->linux_fds[i].offset = 0;
        p->linux_fds[i].ofd = 0; // no shared open-file description yet
        for (u32 j = 0; j < sizeof(p->linux_fds[i].path); ++j)
            p->linux_fds[i].path[j] = 0;
    }
    p->linux_brk_base = 0; // loader fills when abi_flavor = kAbiLinux
    p->linux_brk_current = 0;
    p->linux_mmap_cursor = 0;
    p->linux_vdso_base = 0;
    p->linux_vdso_rt_sigreturn_va = 0;
    p->linux_vdso_clock_gettime_va = 0;
    p->linux_vdso_gettimeofday_va = 0;
    p->linux_vdso_time_va = 0;
    p->linux_vdso_getcpu_va = 0;
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
    // Win32 mutex / event / semaphore storage now lives in
    // `p->kobj_handles` — SYS_MUTEX_* / SYS_EVENT_* / SYS_SEM_*
    // allocate KMutex / KEvent / KSemaphore objects through that
    // path. Nothing to init here for those surfaces.
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

    {
        arch::SerialLineGuard guard;
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
    }

    KBP_PROBE_V(::duetos::debug::ProbeId::kProcessCreate, p->pid);
    return p;
}

void ProcessRetain(Process* p)
{
    if (p == nullptr)
    {
        return;
    }
    // CAS-loop retain: load → check non-zero → CAS(+1). Plain
    // `++p->refcount` was a cross-CPU race that surfaced as the
    // SMP=8 saturation UAF (RIP=0xdedede freed-poison): two CPUs
    // each holding a stale handle could both read refcount=1,
    // both `--` to 0, both enter the destruction path → double-
    // free → garbage poisoned bytes ending up as a return-address
    // slot on a recycled kstack. Atomic compare-exchange with
    // ACQUIRE on the witness load + RELEASE on the increment
    // means a peer's concurrent retain/release is observed
    // before this CPU's increment, and only one CPU at a time
    // gets to commit a witnessed transition.
    //
    // The refcount==0 panic stays as-is: a witnessed 0 means the
    // structure was already reaped; incrementing from 0 (instead
    // of panicking) would silently rejoin a corpse to the live
    // set. Pre-CAS-loop check is racy by itself, but the
    // CAS-from-0 fails and forces a retry that catches the same
    // condition deterministically.
    while (true)
    {
        u64 cur = __atomic_load_n(&p->refcount, __ATOMIC_ACQUIRE);
        if (cur == 0)
        {
            PanicWithValue("core/process", "ProcessRetain on refcount==0 (use-after-free?)", reinterpret_cast<u64>(p));
        }
        const u64 next = cur + 1;
        if (__atomic_compare_exchange_n(&p->refcount, &cur, next, /*weak=*/false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        {
            return;
        }
        // CAS lost the race; cur has the fresh value. Loop and retry.
    }
}

void ProcessRelease(Process* p)
{
    if (p == nullptr)
    {
        return;
    }
    // Atomic decrement-and-test. Plain `--p->refcount` was the
    // cross-CPU race source — two CPUs both observing refcount=1
    // and both decrementing to 0 would both enter the destruction
    // path, double-freeing the Process struct + its AS. Use
    // `__atomic_sub_fetch` with ACQ_REL so the witness of "I'm
    // the one who dropped it to 0" is well-defined across CPUs:
    // exactly one CPU sees `new == 0` and runs the destructor;
    // the others see `new > 0` and return early.
    //
    // ACQ_REL ordering: the destruction path below reads every
    // owned field (windows, popup menus, AS, etc.); those reads
    // must observe writes from prior retain/release pairs on
    // peer CPUs (acquire side). The decrement itself is
    // observable to peers as the release side.
    const u64 prev = __atomic_load_n(&p->refcount, __ATOMIC_ACQUIRE);
    if (prev == 0)
    {
        PanicWithValue("core/process", "ProcessRelease on refcount==0", reinterpret_cast<u64>(p));
    }
    const u64 new_count = __atomic_sub_fetch(&p->refcount, 1, __ATOMIC_ACQ_REL);
    if (new_count != 0)
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
            duetos::drivers::video::DesktopCompose(theme.desktop_bg, nullptr);
            arch::SerialLineGuard guard;
            arch::SerialWrite("[proc] reap-windows pid=");
            arch::SerialWriteHex(p->pid);
            arch::SerialWrite(" count=");
            arch::SerialWriteHex(reaped);
            arch::SerialWrite("\n");
        }
        duetos::drivers::video::CompositorUnlock();
    }
    // Cancel any in-flight TrackPopupMenu owned by this pid so the
    // syscall waiter doesn't block forever on a vanished caller.
    // Done OUTSIDE the compositor lock — TrackPopupCancelByOwner
    // takes both locks itself (in lock order tp_lock → compositor).
    duetos::subsystems::win32::TrackPopupCancelByOwner(p->pid);

    {
        arch::SerialLineGuard guard;
        arch::SerialWrite("[proc] destroy pid=");
        arch::SerialWriteHex(p->pid);
        arch::SerialWrite(" name=\"");
        arch::SerialWrite(p->name);
        arch::SerialWrite("\"\n");
    }

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
    subsystems::win32::custom::DumpExitDiagnostics(p);
    arch::SerialWrite("[proc] release: post-exit-diagnostics\n");

    // Free the Win32 custom-diagnostics state if any was allocated.
    // No-op when the process never opted into any custom-Win32
    // feature (the common path).
    subsystems::win32::custom::CleanupProcess(p);
    arch::SerialWrite("[proc] release: post-CleanupProcess\n");

    // Drain the unified KObject handle table (plan A3). Calls
    // KObjectRelease on every live slot so any object whose final
    // reference was held by this process gets destroyed cleanly,
    // even on abnormal exit. No-op when the process never inserted
    // anything (the common case while the existing per-type Win32
    // tables remain authoritative).
    //
    // Runs BEFORE the `win32_dirs[]` sweep below so dirfd KFiles
    // (state 11, owner-aware release) can call `SysDirClose(p, ...)`
    // through the live `p->win32_dirs[]` table — the sweep below
    // handles only Win32-only dir slots that had no KFile sidecar
    // (raw FindFirstFile callers without an attached Linux fd).
    ::duetos::ipc::HandleTableDrain(p->kobj_handles);
    arch::SerialWrite("[proc] release: post-HandleTableDrain\n");

    // Reclaim any kernel sockets this process left bound/open. Without
    // this, a networked process that exits (or crashes) leaks its pool
    // slot and leaves its listener port bound — which would make a
    // restart=Always service (e.g. netd) fail to re-bind on respawn
    // with EADDRINUSE. Kernel-owned sockets (owner_pid 0, e.g. DRSH)
    // are not touched.
    ::duetos::net::SocketReleaseByOwner(p->pid);

    // Surface anything still attributable to this PID after the
    // earlier drain steps (kobject handles, Win32 handle slots,
    // ticks-over-budget, future GPU residue). Silent on a clean
    // exit; logs WARN + fires kLeakAttributable on residue.
    ::duetos::diag::LeakDetectorReportProcessExit(*p);

    // Free any directory-iteration snapshots the process leaked
    // by exiting without CloseHandle on its FindFirstFile pairs.
    // Idempotent — slots already freed by a dirfd KFile destroy
    // (above) are skipped via the entries-null guard.
    for (u64 i = 0; i < Process::kWin32DirCap; ++i)
    {
        if (p->win32_dirs[i].entries != nullptr)
        {
            mm::KFree(p->win32_dirs[i].entries);
            p->win32_dirs[i].entries = nullptr;
        }
    }

    arch::SerialWrite("[proc] release: post-win32_dirs\n");

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
        // Journal the denial. Pin = `cap/<CapName>` so dedup groups
        // every denial of a particular capability under a single
        // record (one record per cap, regardless of how many pids
        // hit it). ctx_a = the offending pid; ctx_b = the
        // post-increment denial count for that pid. The off-line
        // tooling renders this as a SoftFaultRecov record under the
        // unrecognised-producer branch today; a follow-up could
        // teach the template to recognise the `cap/` pin prefix
        // and emit a denial-specific brief (which capability is
        // the most-denied? which pid is hitting it?).
        char pin[40];
        const char* prefix = "cap/";
        u64 pp = 0;
        while (pp < 39 && prefix[pp] != '\0')
        {
            pin[pp] = prefix[pp];
            ++pp;
        }
        const char* cn = CapName(cap);
        u64 ci = 0;
        while (pp < 39 && cn[ci] != '\0')
        {
            pin[pp++] = cn[ci++];
        }
        pin[pp] = '\0';
        (void)::duetos::diag::FixJournalRecordSev(
            ::duetos::diag::FixDetector::SoftFaultRecov, pin,
            "sandbox: cap-gated syscall denied; review whether the cap should be granted or the call rejected", p->pid,
            p->sandbox_denials, /*severity=*/1);
    }

    // Threshold-crossing: fire once at the first denial that lands
    // at-or-past kSandboxDenialKillThreshold. Use `>=` paired with
    // the threshold-already-fired flag below so a concurrent burst
    // of denials that jumps the counter from N to N+2 (on SMP, no
    // atomic on this counter today) still trips the kill — and so
    // the message itself only prints once because the next-greater
    // value won't equal the threshold under `==`.
    if (p->sandbox_denials >= kSandboxDenialKillThreshold && !p->sandbox_kill_flagged)
    {
        p->sandbox_kill_flagged = true;
        arch::SerialWrite("[sandbox] pid=");
        arch::SerialWriteHex(p->pid);
        arch::SerialWrite(" hit ");
        arch::SerialWriteHex(kSandboxDenialKillThreshold);
        arch::SerialWrite(" denials (last cap=");
        arch::SerialWrite(CapName(cap));
        arch::SerialWrite(") — terminating as malicious\n");
        const u32 pid = static_cast<u32>(p->pid);
        ::duetos::security::EventRingPublishKind(::duetos::security::EventKind::SandboxDenialKill, pid,
                                                 static_cast<u64>(cap), p->sandbox_denials, CapName(cap));
        ::duetos::security::IrRunbookEmit(::duetos::security::EventKind::SandboxDenialKill, pid);
        sched::FlagCurrentForKill(sched::KillReason::SandboxDenialThreshold);
    }
}

u64 ProcessLiveCount()
{
    return g_live_processes;
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
    {
        const u32 pid = static_cast<u32>(p->pid);
        ::duetos::security::EventKind kind;
        switch (lvl)
        {
        case 0:
            kind = ::duetos::security::EventKind::FsWriteRateBurst;
            break;
        case 1:
            kind = ::duetos::security::EventKind::FsWriteRateSustained;
            break;
        default:
            kind = ::duetos::security::EventKind::FsWriteRateLong;
            break;
        }
        ::duetos::security::EventRingPublishKind(kind, pid, p->fs_write_window_bytes[lvl], static_cast<u64>(lvl),
                                                 p->name != nullptr ? p->name : "?");
        ::duetos::security::IrRunbookEmit(kind, pid);
    }
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
    case kCapNetAdmin:
        return "NetAdmin";
    case kCapDiag:
        return "Diag";
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
        char* tail = trimmed + i - 4;
        if ((tail[0] == '.') && AsciiToLower(tail[1]) == 'd' && AsciiToLower(tail[2]) == 'l' &&
            AsciiToLower(tail[3]) == 'l')
        {
            tail[0] = '\0';
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
            char* tail = other + oi - 4;
            if ((tail[0] == '.') && AsciiToLower(tail[1]) == 'd' && AsciiToLower(tail[2]) == 'l' &&
                AsciiToLower(tail[3]) == 'l')
            {
                tail[0] = '\0';
            }
        }
        if (DllNameEq(trimmed, other))
            return img.base_va;
    }
    return 0;
}

u64 ProcessFindModuleBaseByVa(const Process* proc, u64 va)
{
    if (proc == nullptr || va == 0)
    {
        return 0;
    }
    // Preloaded DLLs first — they carry an exact mapped extent.
    for (u64 j = 0; j < proc->dll_image_count; ++j)
    {
        const DllImage& img = proc->dll_images[j];
        if (img.base_va == 0 || img.size == 0)
        {
            continue;
        }
        if (va >= img.base_va && va < img.base_va + img.size)
        {
            return img.base_va;
        }
    }
    // EXE fallback: no SizeOfImage is recorded for the main image,
    // so any VA at/above its base that matched no DLL is attributed
    // to the EXE. The ntdll caller re-checks the MZ/PE header at the
    // returned base before reading .pdata, so an over-broad guess
    // degrades to "no RUNTIME_FUNCTION" rather than a wild read.
    if (proc->pe_image_base != 0 && va >= proc->pe_image_base)
    {
        return proc->pe_image_base;
    }
    return 0;
}

bool ProcessRegisterDllImage(Process* proc, const DllImage& image)
{
    if (proc == nullptr)
        return false;
    if (proc->dll_image_count >= Process::kDllImageCap)
    {
        {
            arch::SerialLineGuard guard;
            arch::SerialWrite("[proc] dll-table FULL pid=");
            arch::SerialWriteHex(proc->pid);
            arch::SerialWrite(" cap=");
            arch::SerialWriteHex(Process::kDllImageCap);
            arch::SerialWrite("\n");
        }
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
        Expect(!CapSetHas(empty, kCapNetAdmin), "empty has no NetAdmin");
        Expect(!CapSetHas(empty, kCapDiag), "empty has no Diag");
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
        Expect(CapSetHas(trusted, kCapNetAdmin), "trusted has NetAdmin");
        Expect(CapSetHas(trusted, kCapDiag), "trusted has Diag");
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
    Expect(StrEqual(CapName(kCapNone), "<none>"), "CapName(kCapNone) == <none>");
    Expect(StrEqual(CapName(kCapSerialConsole), "SerialConsole"), "CapName(SerialConsole)");
    Expect(StrEqual(CapName(kCapFsRead), "FsRead"), "CapName(FsRead)");
    Expect(StrEqual(CapName(kCapDebug), "Debug"), "CapName(Debug)");
    Expect(StrEqual(CapName(kCapFsWrite), "FsWrite"), "CapName(FsWrite)");
    Expect(StrEqual(CapName(kCapSpawnThread), "SpawnThread"), "CapName(SpawnThread)");
    Expect(StrEqual(CapName(kCapNet), "Net"), "CapName(Net)");
    Expect(StrEqual(CapName(kCapInput), "Input"), "CapName(Input)");
    Expect(StrEqual(CapName(kCapNetAdmin), "NetAdmin"), "CapName(NetAdmin)");
    Expect(StrEqual(CapName(kCapDiag), "Diag"), "CapName(Diag)");
    Expect(StrEqual(CapName(kCapCount), "<sentinel>"), "CapName(kCapCount) == <sentinel>");

    // Catches "added an enum value, forgot the switch arm" — every
    // entry from 1 to kCapCount must produce a non-fallback name.
    for (u32 c = 1; c < static_cast<u32>(kCapCount); ++c)
    {
        const char* name = CapName(static_cast<Cap>(c));
        Expect(name != nullptr, "CapName non-null");
        Expect(!StrEqual(name, "<unknown>"), "CapName covers every enumerator");
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

// =========================================================================
// Linux fd-table helpers — see process.h for contract details.
// =========================================================================

namespace
{

// Mirrors duetos::subsystems::linux::internal::LinuxFdEffectiveMax,
// inlined here so the helper layer doesn't have to pull in the
// Linux subsystem's private header. Both definitions read the
// same `linux_rlimit_nofile_cur` field; keeping them in sync is
// a one-line change if the cap ever moves.
constexpr u32 kLinuxFdHardCap = 16;

u32 LinuxFdEffectiveMaxLocal(const Process* p)
{
    if (p == nullptr)
        return kLinuxFdHardCap;
    const u64 cap = p->linux_rlimit_nofile_cur;
    if (cap == 0xFFFFFFFFFFFFFFFFull || cap > kLinuxFdHardCap)
        return kLinuxFdHardCap;
    return static_cast<u32>(cap);
}

// KFileKind ↔ legacy LinuxFd::state mapping. Tags are wire-
// compatible (numeric values match) — see kfile.h's enum class
// KFileKind. Cast keeps process.cpp from having to reach into
// the ipc:: namespace at every helper site.
inline ::duetos::ipc::KFileKind KindOf(u8 state)
{
    return static_cast<::duetos::ipc::KFileKind>(state);
}

// ----------------------------------------------------------------
// Open-file-description (OFD) pool.
//
// POSIX models an open() as creating a kernel "open file
// description" that carries the file offset and the O_* status
// flags. A file descriptor is a per-process handle that points
// AT a description. dup()/dup2()/dup3() and fork() create new
// descriptors that point at the SAME description — so a seek or
// an F_SETFL through one fd is observed through its dup. close()
// drops the descriptor's reference; the description is freed when
// the last referencing fd closes.
//
// `Process::LinuxFd::ofd` is a 1-based index into this pool
// (0 = "no description"). The pool is kernel-wide because
// fork-inherited descriptions are shared ACROSS processes — the
// description is not owned by any single fd table. A ticket
// spinlock serialises alloc / retain / release; the per-field
// offset/flags reads and writes also take it so a concurrent
// seek from a sibling fd (another thread sharing the table, or a
// forked peer) can't tear a 64-bit offset.
//
// Sizing: 64 live descriptions kernel-wide is comfortable for the
// smoke / static-musl workloads (≤16 fds per process, a handful
// of processes). The pool is fixed so the path stays allocation-
// free and lock-bounded; exhaustion surfaces as a false return
// from `LinuxFdOpenDescription` which the caller maps to -ENFILE.
constexpr u32 kOfdPoolCap = 64;

struct OpenFileDescription
{
    u32 refcount;     // number of fds (across all processes) pointing here
    u32 status_flags; // O_* status flags shared by all referencing fds
    u64 offset;       // shared file offset (read/write cursor)
};

constinit OpenFileDescription g_ofd_pool[kOfdPoolCap] = {};
sync::SpinLock g_ofd_lock{};

// Allocate a fresh description with refcount 1. Returns the
// 1-based pool index, or 0 if the pool is exhausted. Caller holds
// g_ofd_lock.
u16 OfdAllocLocked(u64 offset, u32 status_flags)
{
    for (u32 i = 0; i < kOfdPoolCap; ++i)
    {
        if (g_ofd_pool[i].refcount == 0)
        {
            g_ofd_pool[i].refcount = 1;
            g_ofd_pool[i].offset = offset;
            g_ofd_pool[i].status_flags = status_flags;
            return static_cast<u16>(i + 1);
        }
    }
    return 0;
}

// Bump the refcount of an existing description (dup / fork).
// `ofd` is 1-based; 0 is a no-op. Caller holds g_ofd_lock.
void OfdRetainLocked(u16 ofd)
{
    if (ofd == 0 || ofd > kOfdPoolCap)
        return;
    ++g_ofd_pool[ofd - 1].refcount;
}

// Drop one reference; frees (refcount→0) the description on the
// last close. `ofd` is 1-based; 0 is a no-op. Caller holds
// g_ofd_lock.
void OfdReleaseLocked(u16 ofd)
{
    if (ofd == 0 || ofd > kOfdPoolCap)
        return;
    OpenFileDescription& d = g_ofd_pool[ofd - 1];
    if (d.refcount == 0)
    {
        // Double-release / stale index — refcount asymmetry bug.
        // Surface once; do not underflow the counter.
        KLOG_ONCE_WARN_V("proc/linux-fd", "OFD release on zero-refcount slot (1-based idx)", ofd);
        return;
    }
    if (--d.refcount == 0)
    {
        d.offset = 0;
        d.status_flags = 0;
    }
}

} // namespace

i32 LinuxFdAllocLowest(Process* p, u32 lo)
{
    if (p == nullptr)
        return -1;
    const u32 fd_max = LinuxFdEffectiveMaxLocal(p);
    if (lo >= fd_max)
        return -1;
    for (u32 i = lo; i < fd_max; ++i)
    {
        if (p->linux_fds[i].state == 0)
            return static_cast<i32>(i);
    }
    return -1;
}

bool LinuxFdAttachKFile(Process* p, u32 fd, u8 kind, u32 pool_index, void (*release)(u32))
{
    if (p == nullptr || fd >= 16)
        return false;
    auto kf_r = ::duetos::ipc::KFileCreate(KindOf(kind), pool_index, release, /*vnode=*/nullptr,
                                           /*flags=*/0);
    if (!kf_r.has_value())
    {
        // KFile pool exhausted — the caller already grabbed a
        // pool_index slot but the kfile bookkeeping struct couldn't
        // be allocated. Surface so a real pool-saturation event
        // appears in dmesg + the panic dump; the syscall layer
        // returns -ENFILE upward unchanged.
        KLOG_ONCE_WARN_V("proc/linux-fd", "KFileCreate failed (pool exhausted) on attach (kind)", kind);
        return false;
    }
    auto h_r = ::duetos::ipc::HandleTableInsert(p->kobj_handles, &kf_r.value()->base);
    if (!h_r.has_value())
    {
        // Insert failed (table full). Drop the fresh KFile ref so
        // its destroy callback runs and releases the pool slot —
        // the caller had already allocated `pool_index` and is
        // counting on cleanup if attach fails.
        KLOG_ONCE_WARN("proc/linux-fd", "HandleTableInsert failed (table full) on attach");
        ::duetos::ipc::KObjectRelease(&kf_r.value()->base);
        return false;
    }
    p->linux_fds[fd].kf_handle = h_r.value();
    return true;
}

bool LinuxFdAttachKFileOwned(Process* p, u32 fd, u8 kind, u32 pool_index, void (*release)(Process*, u32))
{
    if (p == nullptr || fd >= 16)
        return false;
    auto kf_r = ::duetos::ipc::KFileCreateWithOwner(KindOf(kind), pool_index, release, p,
                                                    /*vnode=*/nullptr, /*flags=*/0);
    if (!kf_r.has_value())
    {
        KLOG_ONCE_WARN_V("proc/linux-fd", "KFileCreateWithOwner failed on attach (kind)", kind);
        return false;
    }
    auto h_r = ::duetos::ipc::HandleTableInsert(p->kobj_handles, &kf_r.value()->base);
    if (!h_r.has_value())
    {
        // Same rollback shape as `LinuxFdAttachKFile` — KObjectRelease
        // fires the owner-aware destroy callback, which frees the
        // pool slot the caller had already allocated.
        KLOG_ONCE_WARN("proc/linux-fd", "HandleTableInsert failed (table full) on attach-owned");
        ::duetos::ipc::KObjectRelease(&kf_r.value()->base);
        return false;
    }
    p->linux_fds[fd].kf_handle = h_r.value();
    return true;
}

void LinuxFdClose(Process* p, u32 fd)
{
    if (p == nullptr || fd >= 16)
        return;
    Process::LinuxFd& lf = p->linux_fds[fd];
    if (lf.state == 0)
        return;
    if (lf.kf_handle != ::duetos::ipc::kHandleInvalid)
    {
        // Drops the table's KObject ref. KFileDestroy fires on
        // refcount=0, dispatching to the per-pool release callback
        // (PipeReleaseRead/Write, EventfdRelease, etc.) — no
        // explicit `*Release` call needed at the syscall layer
        // for KFile-backed fds.
        (void)::duetos::ipc::HandleTableRemove(p->kobj_handles, lf.kf_handle);
        lf.kf_handle = ::duetos::ipc::kHandleInvalid;
    }
    // Drop this fd's reference on the shared open-file description.
    // Last close frees it; a dup sibling still holding a ref keeps
    // the offset/flags alive. No-op when the slot never got an OFD
    // (lf.ofd == 0).
    if (lf.ofd != 0)
    {
        sync::SpinLockGuard g(g_ofd_lock);
        OfdReleaseLocked(lf.ofd);
        lf.ofd = 0;
    }
    lf.state = 0;
    lf.flags = 0;
    lf.first_cluster = 0;
    lf.size = 0;
    lf.offset = 0;
    for (u32 j = 0; j < sizeof(lf.path); ++j)
        lf.path[j] = 0;
}

bool LinuxFdDup(Process* p, u32 oldfd, u32 newfd)
{
    if (p == nullptr || oldfd >= 16 || newfd >= 16)
        return false;
    if (oldfd == newfd)
        return true;
    Process::LinuxFd& src = p->linux_fds[oldfd];
    if (src.state == 0)
        return false;
    // Close any existing slot at newfd FIRST. Drops the dst's
    // KFile ref via the unified path.
    LinuxFdClose(p, newfd);

    // Open-file-description sharing (POSIX dup semantics). The new
    // fd must reference the SAME description as the source so a
    // seek / F_SETFL through one is visible through the other. If
    // the source slot doesn't yet own a description (older open
    // paths that haven't migrated to LinuxFdOpenDescription), lazily
    // materialise one from its current inline offset/flags so both
    // fds end up sharing it. Do this BEFORE touching dst so a pool-
    // exhaustion failure leaves the whole table untouched.
    u16 shared_ofd = 0;
    {
        sync::SpinLockGuard g(g_ofd_lock);
        if (src.ofd == 0)
        {
            // Inline offset is the live cursor; status flags aren't
            // tracked inline yet, so seed the description's flags to 0.
            // GAP: status flags for pre-OFD opens are seeded empty —
            // revisit when sys_open/pipe2/socket call
            // LinuxFdOpenDescription with the real O_* flags so a
            // dup'd fd inherits the source's status flags too.
            src.ofd = OfdAllocLocked(src.offset, /*status_flags=*/0);
            if (src.ofd == 0)
            {
                KLOG_ONCE_WARN("proc/linux-fd", "OFD pool exhausted on dup (src materialise)");
                return false;
            }
        }
        OfdRetainLocked(src.ofd);
        shared_ofd = src.ofd;
    }

    Process::LinuxFd& dst = p->linux_fds[newfd];
    dst.state = src.state;
    dst.flags = src.flags;
    // Drop FD_CLOEXEC on the new fd by default. Linux semantics:
    // dup() always produces a non-cloexec fd; dup3() with
    // O_CLOEXEC re-sets it via LinuxFdSetCloexec at the call site.
    // FD_CLOEXEC is a per-fd (per-descriptor) flag, NOT part of the
    // shared open-file description — correct to differ per dup.
    dst.flags = static_cast<u8>(dst.flags & ~Process::kLinuxFdFlagCloexec);
    dst.first_cluster = src.first_cluster;
    dst.size = src.size;
    dst.ofd = shared_ofd;
    // Seed dst's inline mirror from the shared description so the
    // existing inline readers see the right cursor immediately.
    dst.offset = LinuxFdGetOffset(p, newfd);
    for (u32 j = 0; j < sizeof(dst.path); ++j)
        dst.path[j] = src.path[j];

    // Duplicate the KFile sidecar so both fds share the underlying
    // pool ref. Each fd holds one ref — closing one drops one ref;
    // closing both fires the per-pool release callback.
    if (src.kf_handle != ::duetos::ipc::kHandleInvalid)
    {
        auto h_r = ::duetos::ipc::HandleTableDuplicate(p->kobj_handles, p->kobj_handles, src.kf_handle);
        if (!h_r.has_value())
        {
            // Roll back EVERYTHING — we promised "either both fds
            // reference the same KFile + OFD, or neither does".
            // Drop the OFD ref we just took (refcount asymmetry
            // guard: the retain above must be matched on this leg).
            {
                sync::SpinLockGuard g(g_ofd_lock);
                OfdReleaseLocked(shared_ofd);
            }
            dst.state = 0;
            dst.flags = 0;
            dst.first_cluster = 0;
            dst.size = 0;
            dst.offset = 0;
            dst.ofd = 0;
            for (u32 j = 0; j < sizeof(dst.path); ++j)
                dst.path[j] = 0;
            return false;
        }
        dst.kf_handle = h_r.value();
    }
    else
    {
        dst.kf_handle = ::duetos::ipc::kHandleInvalid;
    }
    return true;
}

void LinuxFdSetCloexec(Process* p, u32 fd, bool on)
{
    if (p == nullptr || fd >= 16)
        return;
    Process::LinuxFd& lf = p->linux_fds[fd];
    if (lf.state == 0)
        return;
    if (on)
        lf.flags = static_cast<u8>(lf.flags | Process::kLinuxFdFlagCloexec);
    else
        lf.flags = static_cast<u8>(lf.flags & ~Process::kLinuxFdFlagCloexec);
}

bool LinuxFdGetCloexec(const Process* p, u32 fd)
{
    if (p == nullptr || fd >= 16)
        return false;
    const Process::LinuxFd& lf = p->linux_fds[fd];
    if (lf.state == 0)
        return false;
    return (lf.flags & Process::kLinuxFdFlagCloexec) != 0;
}

bool LinuxFdOpenDescription(Process* p, u32 fd, u64 initial_offset, u32 status_flags)
{
    if (p == nullptr || fd >= 16)
        return false;
    Process::LinuxFd& lf = p->linux_fds[fd];
    if (lf.state == 0)
        return false;
    if (lf.ofd != 0)
    {
        // Already has a description — refresh the inline offset
        // mirror and leave the shared object alone. (Re-opening a
        // description over a live one would silently orphan dup
        // siblings.)
        lf.offset = LinuxFdGetOffset(p, fd);
        return true;
    }
    sync::SpinLockGuard g(g_ofd_lock);
    const u16 ofd = OfdAllocLocked(initial_offset, status_flags);
    if (ofd == 0)
    {
        KLOG_ONCE_WARN("proc/linux-fd", "OFD pool exhausted on open");
        return false;
    }
    lf.ofd = ofd;
    lf.offset = initial_offset; // keep the inline mirror in step
    return true;
}

u64 LinuxFdGetOffset(const Process* p, u32 fd)
{
    if (p == nullptr || fd >= 16)
        return 0;
    const Process::LinuxFd& lf = p->linux_fds[fd];
    if (lf.ofd == 0)
        return lf.offset; // no shared description — inline is authoritative
    sync::SpinLockGuard g(g_ofd_lock);
    return g_ofd_pool[lf.ofd - 1].offset;
}

void LinuxFdSetOffset(Process* p, u32 fd, u64 offset)
{
    if (p == nullptr || fd >= 16)
        return;
    Process::LinuxFd& lf = p->linux_fds[fd];
    if (lf.ofd == 0)
    {
        lf.offset = offset; // no shared description — inline only
        return;
    }
    {
        sync::SpinLockGuard g(g_ofd_lock);
        g_ofd_pool[lf.ofd - 1].offset = offset;
    }
    // Keep the inline mirror in step for the TUs that still read
    // `linux_fds[fd].offset` directly.
    // GAP: syscall TUs that WRITE `linux_fds[fd].offset` inline (read,
    // write, lseek, sendfile, splice) won't propagate to dup siblings
    // until they migrate to LinuxFdSetOffset — revisit by porting
    // those write sites to this accessor; the OFD is the source of
    // truth, the inline field a per-fd cache.
    lf.offset = offset;
}

u32 LinuxFdGetStatusFlags(const Process* p, u32 fd)
{
    if (p == nullptr || fd >= 16)
        return 0;
    const Process::LinuxFd& lf = p->linux_fds[fd];
    if (lf.ofd == 0)
        return 0;
    sync::SpinLockGuard g(g_ofd_lock);
    return g_ofd_pool[lf.ofd - 1].status_flags;
}

void LinuxFdSetStatusFlags(Process* p, u32 fd, u32 status_flags)
{
    if (p == nullptr || fd >= 16)
        return;
    Process::LinuxFd& lf = p->linux_fds[fd];
    if (lf.ofd == 0)
        return;
    sync::SpinLockGuard g(g_ofd_lock);
    g_ofd_pool[lf.ofd - 1].status_flags = status_flags;
}

void LinuxFdInheritFromParent(Process* parent, Process* child)
{
    if (parent == nullptr || child == nullptr)
        return;
    for (u32 fd = 0; fd < 16; ++fd)
    {
        const Process::LinuxFd& src = parent->linux_fds[fd];
        if (src.state == 0)
            continue;
        Process::LinuxFd& dst = child->linux_fds[fd];
        // Reserved-tty slots (fd 0/1/2 in a freshly-created child)
        // start at state=1; just leave them alone if the parent
        // also has state=1 there. For a truly inherited fd, mirror
        // the parent's state including FD_CLOEXEC.
        dst.state = src.state;
        dst.flags = src.flags; // keeps cloexec; execve drops it later
        dst.first_cluster = src.first_cluster;
        dst.size = src.size;
        dst.offset = src.offset;
        for (u32 j = 0; j < sizeof(dst.path); ++j)
            dst.path[j] = src.path[j];

        // Open-file-description inheritance. POSIX fork(): the child
        // SHARES the parent's open file descriptions, so a seek in
        // the child moves the parent's cursor too (both fds point at
        // one description). Reserved-tty slots (state 1) carry no
        // offset semantics — leave them OFD-less to avoid burning a
        // pool slot per fork on the three standard streams. Already-
        // described slots share their existing OFD; a slot that has a
        // real backing (state >= 2) but no OFD yet gets one lazily so
        // both sides share it. The child's `ofd` references the same
        // pool slot; its refcount counts both the parent fd and the
        // child fd, so either side's close drops exactly one ref.
        if (src.state != 1)
        {
            sync::SpinLockGuard g(g_ofd_lock);
            // NB: `src` is const above; re-fetch the parent slot
            // mutably here to allow the lazy materialise to stick.
            Process::LinuxFd& psrc = parent->linux_fds[fd];
            if (psrc.ofd == 0)
            {
                psrc.ofd = OfdAllocLocked(psrc.offset, /*status_flags=*/0);
                // On pool exhaustion the parent stays OFD-less and
                // the child inherits no OFD either (dst.ofd left 0);
                // both keep their independent inline offset mirror —
                // degraded but safe.
                // GAP: fork under OFD-pool pressure loses offset
                // sharing for that fd — revisit by growing kOfdPoolCap
                // or making the pool KMalloc-backed if real workloads
                // exhaust 64 live descriptions.
            }
            OfdRetainLocked(psrc.ofd);
            dst.ofd = psrc.ofd;
        }

        // KFile sidecar inheritance — duplicate the parent's
        // handle into the child's table. Each side now holds one
        // KFile ref; the per-pool release callback fires only when
        // both have closed the fd.
        if (src.kf_handle != ::duetos::ipc::kHandleInvalid)
        {
            auto h_r = ::duetos::ipc::HandleTableDuplicate(parent->kobj_handles, child->kobj_handles, src.kf_handle);
            if (h_r.has_value())
            {
                dst.kf_handle = h_r.value();
            }
            else
            {
                // Child's table is full or duplication otherwise
                // failed. Best-effort: leave the slot's data
                // populated but with no KFile ref — close-side
                // will skip the HandleTableRemove. Pool will leak
                // (sub-GAP — fork failure under handle-table
                // pressure is exotic, and v0 forks are rare).
                dst.kf_handle = ::duetos::ipc::kHandleInvalid;
            }
        }
        else
        {
            dst.kf_handle = ::duetos::ipc::kHandleInvalid;
        }
    }
}

void LinuxFdCloseOnExec(Process* p)
{
    if (p == nullptr)
        return;
    for (u32 fd = 0; fd < 16; ++fd)
    {
        if (p->linux_fds[fd].state == 0)
            continue;
        if ((p->linux_fds[fd].flags & Process::kLinuxFdFlagCloexec) == 0)
            continue;
        LinuxFdClose(p, fd);
    }
}

// Side-channel for the self-test's synthetic per-pool release
// callback. File-scope so the lambda's `+` decay can use it
// without capturing.
namespace
{
u32 g_lfd_selftest_release_calls = 0;
u32 g_lfd_selftest_release_idx = 0;

void LinuxFdSelfTestRelease(u32 idx)
{
    ++g_lfd_selftest_release_calls;
    g_lfd_selftest_release_idx = idx;
}
} // namespace

void LinuxFdSelfTest()
{
    arch::SerialWrite("[proc] linux-fd-table self-test\n");

    // The helpers only touch `linux_fds[]`, `kobj_handles`, and
    // `linux_rlimit_nofile_cur`. Allocate a stand-in Process on
    // the heap, zero-init the whole thing, and exercise just
    // those fields — avoids the full ProcessCreate dependency
    // chain (AS / scheduler / serial banner) which isn't needed
    // for a unit test of the helper plumbing.
    auto* p = static_cast<Process*>(mm::KMalloc(sizeof(Process)));
    if (p == nullptr)
    {
        arch::SerialWrite("[proc] linux-fd-table self-test: skipped (no kheap)\n");
        return;
    }
    memset(p, 0, sizeof(Process));
    p->linux_rlimit_nofile_cur = 0xFFFFFFFFFFFFFFFFull; // unlimited
    for (u32 i = 0; i < 16; ++i)
    {
        p->linux_fds[i].state = (i < 3) ? 1 : 0;
        p->linux_fds[i].kf_handle = ::duetos::ipc::kHandleInvalid;
    }

    // 1) AllocLowest: should hand out fd 3 first (0/1/2 reserved).
    const i32 fd3 = LinuxFdAllocLowest(p, 3);
    if (fd3 != 3)
        core::Panic("proc/linux-fd", "self-test: AllocLowest(3) != 3");
    // Helper does NOT mark slot in_use — caller stamps state.
    p->linux_fds[3].state = 5; // synthetic eventfd-like
    p->linux_fds[3].first_cluster = 0xAAAA;

    // 2) AttachKFile: synthetic release callback that records.
    g_lfd_selftest_release_calls = 0;
    g_lfd_selftest_release_idx = 0;
    if (!LinuxFdAttachKFile(p, 3, /*kind=*/5, /*pool_index=*/0xAAAA, &LinuxFdSelfTestRelease))
        core::Panic("proc/linux-fd", "self-test: AttachKFile failed");
    if (p->linux_fds[3].kf_handle == ::duetos::ipc::kHandleInvalid)
        core::Panic("proc/linux-fd", "self-test: kf_handle invalid post-attach");

    // 3) Dup: fd 4 should share the KFile ref with fd 3.
    if (!LinuxFdDup(p, 3, 4))
        core::Panic("proc/linux-fd", "self-test: Dup(3, 4) failed");
    if (p->linux_fds[4].state != 5)
        core::Panic("proc/linux-fd", "self-test: Dup did not copy state");
    if (p->linux_fds[4].kf_handle == ::duetos::ipc::kHandleInvalid)
        core::Panic("proc/linux-fd", "self-test: Dup did not set kf_handle on dst");
    if (p->linux_fds[4].kf_handle == p->linux_fds[3].kf_handle)
        core::Panic("proc/linux-fd", "self-test: Dup gave dst the SAME handle");

    // 3b) Shared open-file description: dup MUST make fd 3 and fd 4
    // point at ONE description (same OFD index), so a seek through
    // one fd is observed through the other. This is the POSIX
    // semantic the OFD pool exists to provide.
    if (p->linux_fds[3].ofd == 0)
        core::Panic("proc/linux-fd", "self-test: Dup did not materialise an OFD on src");
    if (p->linux_fds[4].ofd != p->linux_fds[3].ofd)
        core::Panic("proc/linux-fd", "self-test: dup did not SHARE the open-file description");
    LinuxFdSetOffset(p, 3, 0x1234);
    if (LinuxFdGetOffset(p, 4) != 0x1234)
        core::Panic("proc/linux-fd", "self-test: seek on fd 3 not visible through dup fd 4");
    LinuxFdSetOffset(p, 4, 0x5678);
    if (LinuxFdGetOffset(p, 3) != 0x5678)
        core::Panic("proc/linux-fd", "self-test: seek on fd 4 not visible through fd 3");
    // Status flags share too.
    LinuxFdSetStatusFlags(p, 3, 0x0800 /*synthetic O_NONBLOCK-ish*/);
    if (LinuxFdGetStatusFlags(p, 4) != 0x0800)
        core::Panic("proc/linux-fd", "self-test: status flags not shared across dup");

    // 4) CLOEXEC: stamp on fd 3, leave fd 4 clear.
    LinuxFdSetCloexec(p, 3, true);
    if (!LinuxFdGetCloexec(p, 3))
        core::Panic("proc/linux-fd", "self-test: SetCloexec(3,true) didn't take");
    if (LinuxFdGetCloexec(p, 4))
        core::Panic("proc/linux-fd", "self-test: cloexec leaked across dup");

    // Remember the shared OFD index so we can prove it's freed only
    // on the LAST close (refcount-balance check).
    const u16 shared_ofd = p->linux_fds[3].ofd;

    // 5) CloseOnExec: fd 3 (cloexec) should close, fd 4 should survive.
    LinuxFdCloseOnExec(p);
    if (p->linux_fds[3].state != 0)
        core::Panic("proc/linux-fd", "self-test: CloseOnExec didn't close cloexec slot");
    if (p->linux_fds[4].state != 5)
        core::Panic("proc/linux-fd", "self-test: CloseOnExec dropped non-cloexec slot");
    if (g_lfd_selftest_release_calls != 0)
        core::Panic("proc/linux-fd", "self-test: pool release fired prematurely");
    // The shared description must SURVIVE fd 3's close — fd 4 still
    // references it (refcount 2 → 1, not 0).
    if (shared_ofd == 0 || g_ofd_pool[shared_ofd - 1].refcount != 1)
        core::Panic("proc/linux-fd", "self-test: OFD freed too early (closed one dup, both should keep it)");
    // fd 4 still reads the last offset written through the now-closed fd 3.
    if (LinuxFdGetOffset(p, 4) != 0x5678)
        core::Panic("proc/linux-fd", "self-test: surviving dup lost the shared offset");

    // 6) Final close on fd 4 — fires the per-pool release callback
    // AND drops the last OFD reference, freeing the description.
    LinuxFdClose(p, 4);
    if (g_lfd_selftest_release_calls != 1)
        core::Panic("proc/linux-fd", "self-test: pool release didn't fire on last close");
    if (g_lfd_selftest_release_idx != 0xAAAA)
        core::Panic("proc/linux-fd", "self-test: pool release got wrong index");
    if (g_ofd_pool[shared_ofd - 1].refcount != 0)
        core::Panic("proc/linux-fd", "self-test: OFD not freed on last close (refcount asymmetry)");

    mm::KFree(p);
    arch::SerialWrite("[proc] linux-fd-table self-test OK\n");
}

} // namespace duetos::core
