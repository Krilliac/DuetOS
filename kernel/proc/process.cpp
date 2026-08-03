#include "proc/process.h"

#include "core/service_exit_observer.h"
#include "core/service_runtime.h"
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
#include "fs/file_route.h"
#include "fs/ramfs.h"
#include "mm/address_space.h"
#include "mm/kheap.h"
#include "mm/paging.h"
#include "net/socket.h"
#include "proc/job.h"
#include "util/string.h"
#include "subsystems/linux/syscall_internal.h"
#include "subsystems/win32/custom.h"
#include "subsystems/win32/section.h"
#include "subsystems/win32/gdi_objects.h"
#include "subsystems/win32/window_syscall.h"
#include "sched/sched.h"
#include "sync/spinlock.h"
#include "syscall/service_endpoint_ingress.h"
#include "log/klog.h"
#include "core/panic.h"
#include "loader/pe_loader.h"
#include "security/event_ring.h"
#include "security/ir_runbook.h"
#include "time/tick.h"
#include "time/timekeeper.h"
#include "util/nospec.h"

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

u64 MintProcessKey()
{
    u64 observed = __atomic_load_n(&g_next_pid, __ATOMIC_RELAXED);
    for (;;)
    {
        // PID/identity zero is invalid and UINT64_MAX is the terminal
        // exhaustion sentinel. Refuse a new Process rather than wrapping the
        // namespace onto an earlier live or externally-retained identity.
        if (observed == ~u64{0})
            return 0;
        const u64 next = observed + 1;
        if (__atomic_compare_exchange_n(&g_next_pid, &observed, next, /*weak=*/false, __ATOMIC_RELAXED,
                                        __ATOMIC_RELAXED))
        {
            return observed;
        }
    }
}

void StdinFocusClearIf(Process* process);

void ReleaseProcessSecurityOwners(Process* process, const char* reason)
{
    if (AuthorizationContextKeyIsValid(process->authorization) && !AuthorizationRelease(&process->authorization))
    {
        PanicWithValue("core/process", reason, process->authorization.generation);
    }
    if (CredentialKeyIsValid(process->credentials) && !CredentialRelease(&process->credentials))
    {
        PanicWithValue("core/process", reason, process->credentials.generation);
    }
}

void ReleaseProcessResourceDomainOwner(Process* process, const char* reason)
{
    const ResourceDomainKey doomed = process->resource_domain;
    process->resource_domain = kInvalidResourceDomainKey;
    if (ResourceDomainKeyIsValid(doomed) && !ResourceDomainRelease(doomed))
    {
        PanicWithValue("core/process", reason, doomed.generation);
    }
}

// Event sequences bridge an external predicate lock to g_sched_lock. Never
// wrap one back onto an earlier observation: at UINT64_MAX the wait side uses
// a bounded cancellable fallback and rescans instead.
bool AdvanceStableEventSequenceLocked(u64* sequence)
{
    KASSERT(sequence != nullptr, "core/process", "null stable event sequence");
    const u64 previous = __atomic_load_n(sequence, __ATOMIC_RELAXED);
    if (previous == ~u64{0})
        return false;
    __atomic_store_n(sequence, previous + 1, __ATOMIC_RELEASE);
    return true;
}

void AdvanceStableEventSequenceAtomic(u64* sequence)
{
    KASSERT(sequence != nullptr, "core/process", "null atomic stable event sequence");
    u64 observed = __atomic_load_n(sequence, __ATOMIC_RELAXED);
    while (observed != ~u64{0})
    {
        const u64 desired = observed + 1;
        if (__atomic_compare_exchange_n(sequence, &observed, desired, /*weak=*/false, __ATOMIC_RELEASE,
                                        __ATOMIC_RELAXED))
        {
            return;
        }
    }
}

} // namespace

CapSet ProcessCapsSnapshot(const Process* process)
{
    if (process == nullptr)
        return CapSetEmpty();
    AuthorizationContextSnapshot snapshot{};
    return AuthorizationSnapshot(process->authorization, duetos::time::MonotonicNs(), &snapshot) &&
                   snapshot.state == AuthorizationContextState::Live
               ? CapSet{snapshot.effective_bits}
               : CapSetEmpty();
}

CredentialKey ProcessCredentialKeySnapshot(const Process* process)
{
    return process != nullptr ? process->credentials : kInvalidCredentialKey;
}

AuthorizationContextKey ProcessAuthorizationKeySnapshot(const Process* process)
{
    return process != nullptr ? process->authorization : kInvalidAuthorizationContextKey;
}

bool ProcessInspectCredentials(const Process* process, CredentialSnapshot* snapshot_out)
{
    if (snapshot_out == nullptr)
        return false;
    *snapshot_out = {};
    return process != nullptr && CredentialInspectExact(process->credentials, snapshot_out) &&
           snapshot_out->state == CredentialState::Live;
}

bool ProcessInspectAuthorization(const Process* process, AuthorizationContextSnapshot* snapshot_out)
{
    if (snapshot_out == nullptr)
        return false;
    *snapshot_out = {};
    return process != nullptr &&
           AuthorizationSnapshot(process->authorization, duetos::time::MonotonicNs(), snapshot_out) &&
           snapshot_out->state == AuthorizationContextState::Live;
}

AuthorizationActionResult ProcessChargeExecutionTicks(Process* process, u64 ticks)
{
    if (process == nullptr)
    {
        return AuthorizationActionResult{false, false, false, AuthorizationAction::None, kAuthorizationNoFsWriteWindow,
                                         0};
    }
    return AuthorizationChargeTick(process->authorization, ticks);
}

u64 ProcessTickBudgetSnapshot(const Process* process)
{
    AuthorizationContextSnapshot snapshot{};
    return ProcessInspectAuthorization(process, &snapshot) ? snapshot.tick_budget : 0;
}

u64 ProcessTicksUsedSnapshot(const Process* process)
{
    AuthorizationContextSnapshot snapshot{};
    return ProcessInspectAuthorization(process, &snapshot) ? snapshot.ticks_used : 0;
}

u64 ProcessSandboxDenialCountSnapshot(const Process* process)
{
    AuthorizationContextSnapshot snapshot{};
    return ProcessInspectAuthorization(process, &snapshot) ? snapshot.denial_count : 0;
}

bool ProcessCapsTrySnapshotNoExpire(const Process* process, CapSet* snapshot_out)
{
    if (snapshot_out == nullptr)
        return false;
    *snapshot_out = CapSetEmpty();
    if (process == nullptr)
        return false;

    // Stop-loop diagnostics must not run lease expiry: it reads the live
    // clock and mutates authority while another stopped CPU may own the lock.
    AuthorizationContextSnapshot snapshot{};
    if (!AuthorizationTrySnapshotNoExpire(process->authorization, &snapshot))
        return false;
    *snapshot_out = CapSet{snapshot.effective_bits};
    return true;
}

u32 ProcessWin32ThreadHandleCount(const Process* process)
{
    if (process == nullptr)
        return 0;
    Process* mutable_process = const_cast<Process*>(process);
    const sync::IrqFlags flags = sync::SpinLockAcquire(mutable_process->win32_thread_lock);
    u32 count = 0;
    for (u32 i = 0; i < Process::kWin32ThreadCap; ++i)
    {
        if (mutable_process->win32_threads[i].in_use && mutable_process->win32_threads[i].handle_open)
            ++count;
    }
    for (u32 i = 0; i < Process::kWin32ForeignThreadCap; ++i)
    {
        if (mutable_process->win32_foreign_threads[i].in_use)
            ++count;
    }
    sync::SpinLockRelease(mutable_process->win32_thread_lock, flags);
    return count;
}

void ProcessPublishWin32ThreadExit(Process* process, u64 tid, u32 exit_code)
{
    if (process == nullptr || tid == 0)
        return;
    sched::WaitQueue* waiters_to_wake = nullptr;
    const sync::IrqFlags flags = sync::SpinLockAcquire(process->win32_thread_lock);
    for (u32 i = 0; i < Process::kWin32ThreadCap; ++i)
    {
        auto& row = process->win32_threads[i];
        if (row.in_use && row.tid == tid)
        {
            if (!row.exited)
            {
                row.exit_code = exit_code;
                row.exited = true;
                (void)AdvanceStableEventSequenceLocked(&row.event_sequence);
                waiters_to_wake = &row.waiters;
            }
            // CloseHandle on a running thread hides the public
            // handle but cannot recycle its TEB/TLS resource slot.
            // Actual task death is the point where that closed row
            // becomes reusable.
            if (!row.handle_open && !row.creating)
            {
                row.in_use = false;
                row.exited = false;
                row.exit_code = 0x103;
                row.tid = 0;
                row.user_stack_va = 0;
            }
            break;
        }
    }
    sync::SpinLockRelease(process->win32_thread_lock, flags);
    if (waiters_to_wake != nullptr)
        sched::WaitQueueWakeAll(waiters_to_wake);
}

bool ProcessHasCap(const Process* process, Cap cap)
{
    return CapSetHas(ProcessCapsSnapshot(process), cap);
}

bool ProcessCapsGrant(Process* process, Cap cap)
{
    return process != nullptr && AuthorizationGrantDurable(process->authorization, cap);
}

bool ProcessCapsGrantLease(Process* process, Cap cap, u64 deadline_ns, u64 generation)
{
    const u64 now = duetos::time::MonotonicNs();
    return process != nullptr && AuthorizationGrantLease(process->authorization, cap, now, deadline_ns, generation);
}

bool ProcessCapsRevokeLease(Process* process, Cap cap, u64 expected_generation)
{
    return process != nullptr && AuthorizationRevokeLease(process->authorization, cap, expected_generation);
}

CapSet ProcessCapCeilingSnapshot(const Process* process)
{
    if (process == nullptr)
        return CapSetEmpty();
    AuthorizationContextSnapshot snapshot{};
    return ProcessInspectAuthorization(process, &snapshot) ? CapSet{snapshot.ceiling_bits} : CapSetEmpty();
}

CapSet ProcessCapsDisableMask(Process* process, u64 disable_mask)
{
    u64 before = 0;
    return process != nullptr &&
                   AuthorizationDisableMask(process->authorization, duetos::time::MonotonicNs(), disable_mask, &before)
               ? CapSet{before}
               : CapSetEmpty();
}

CapSet ProcessCapsDropMask(Process* process, u64 drop_mask)
{
    u64 before = 0;
    return process != nullptr && AuthorizationDropIrreversiblyWithPrevious(
                                     process->authorization, duetos::time::MonotonicNs(), drop_mask, &before)
               ? CapSet{before}
               : CapSetEmpty();
}

bool ProcessCaptureSpawnAuthority(const Process* process, u64 required_mask, CapSet* child_caps_out,
                                  CapSet* ceiling_out, CapSet* authority_out)
{
    if (process == nullptr || child_caps_out == nullptr || ceiling_out == nullptr || authority_out == nullptr)
        return false;

    AuthorizationContextSnapshot snapshot{};
    if (!ProcessInspectAuthorization(process, &snapshot))
        return false;
    const CapSet ceiling{snapshot.ceiling_bits};
    const CapSet authority{snapshot.effective_bits & snapshot.ceiling_bits};
    const CapSet child_caps{snapshot.durable_bits & snapshot.ceiling_bits};
    *child_caps_out = child_caps;
    *ceiling_out = ceiling;
    *authority_out = authority;

    const u64 defined_mask = CapSetTrusted().bits;
    return required_mask != 0 && (required_mask & ~defined_mask) == 0 &&
           (authority.bits & required_mask) == required_mask;
}

Process* ProcessCreate(const char* name, mm::AddressSpace* as, CapSet caps, const fs::RamfsNode* root, u64 user_code_va,
                       u64 user_stack_va, u64 tick_budget, CapSet cap_ceiling)
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
    // win32_dirs[] table, linux_child_relations[]) hold a SpinLock or
    // depend on zero-initialised state. Without this memset the
    // `HandleTableDrain` call in Process runtime teardown would lock-acquire
    // a garbage SpinLock and spin forever — confirmed locally as
    // the cause of the qemu-smoke pe-* / ring3 / linux profiles
    // hanging at exactly the post-CleanupProcess marker, while the
    // smoke task slept waiting for a sentinel that never came.
    memset(p, 0, sizeof(Process));

    // Establish resource-domain ownership before assigning a PID or exposing
    // any partially initialized Process state. User-originated spawns inherit
    // their parent's exact immutable domain; kernel roots receive an ordinary
    // trusted or sandbox domain based on the filesystem-root trust boundary.
    // Authenticated services replace this default only from their manifest-
    // authenticated prepublication callback.
    ResourceDomainKey resource_domain = kInvalidResourceDomainKey;
    Process* spawn_parent = CurrentProcess();
    bool have_resource_domain = false;
    if (spawn_parent != nullptr)
    {
        have_resource_domain = ResourceDomainKeyIsValid(spawn_parent->resource_domain) &&
                               ResourceDomainRetain(spawn_parent->resource_domain);
        if (have_resource_domain)
            resource_domain = spawn_parent->resource_domain;
    }
    else if (root == fs::RamfsSandboxRoot())
    {
        have_resource_domain = ResourceDomainCreateSandbox(as->frame_budget, &resource_domain);
    }
    else
    {
        have_resource_domain = ResourceDomainCreateTrusted(&resource_domain);
    }
    if (!have_resource_domain)
    {
        KLOG_ERROR("core/process", "ProcessCreate: resource-domain acquisition failed");
        mm::KFree(p);
        return nullptr;
    }
    p->resource_domain = resource_domain;

    // Credentials are immutable ABI identity, never a translation of DuetOS
    // caps. A normal child retains its parent's exact identity. Crossing from
    // a trusted root into the sandbox root mints the fixed nobody identity;
    // sandbox-to-trusted elevation is rejected independently by authorization
    // provenance below. No user buffer, path spelling, PID, or manifest claim
    // participates in either authority-bearing constructor.
    p->credentials = kInvalidCredentialKey;
    const bool sandbox_launch = root == fs::RamfsSandboxRoot();
    bool have_credentials = false;
    if (spawn_parent != nullptr && root == spawn_parent->root)
    {
        have_credentials =
            CredentialKeyIsValid(spawn_parent->credentials) && CredentialRetain(spawn_parent->credentials);
        if (have_credentials)
            p->credentials = spawn_parent->credentials;
    }
    else if (sandbox_launch)
    {
        have_credentials = CredentialAuthorityCreateNobodySandbox(&p->credentials);
    }
    else
    {
        have_credentials = CredentialAuthorityCreateTrustedRoot(&p->credentials);
    }
    if (!have_credentials)
    {
        ReleaseProcessResourceDomainOwner(p, "credential failure resource-domain release failed");
        KLOG_ERROR("core/process", "ProcessCreate: credential acquisition failed");
        mm::KFree(p);
        return nullptr;
    }

    // Authorization is an independent per-Process row. Children derive only
    // durable bits and a subset ceiling from the parent's exact context;
    // leases can authorize the outer spawn syscall but are never inherited.
    // Kernel roots use one explicit trusted/sandbox constructor. This makes
    // every Process creation failure-atomic without a mutable authority mirror.
    p->authorization = kInvalidAuthorizationContextKey;
    const CapSet bounded_caps{caps.bits & cap_ceiling.bits};
    const AuthorizationLaunchProfile launch_profile =
        sandbox_launch ? AuthorizationLaunchProfile::Sandbox : AuthorizationLaunchProfile::Trusted;
    bool have_authorization = false;
    if (spawn_parent != nullptr)
    {
        const u64 now_ns = duetos::time::MonotonicNs();
        have_authorization = AuthorizationContextKeyIsValid(spawn_parent->authorization) &&
                             AuthorizationDeriveForSpawn(spawn_parent->authorization, now_ns, 0, bounded_caps,
                                                         cap_ceiling, tick_budget, launch_profile, &p->authorization);
    }
    else if (sandbox_launch)
    {
        have_authorization = AuthorizationCreateSandbox(bounded_caps, cap_ceiling, tick_budget, &p->authorization);
    }
    else
    {
        have_authorization = AuthorizationCreateTrusted(bounded_caps, cap_ceiling, tick_budget, &p->authorization);
    }
    if (!have_authorization)
    {
        ReleaseProcessSecurityOwners(p, "authorization failure credential release failed");
        ReleaseProcessResourceDomainOwner(p, "authorization failure resource-domain release failed");
        KLOG_ERROR("core/process", "ProcessCreate: authorization acquisition failed");
        mm::KFree(p);
        return nullptr;
    }

    // ProcessCreate can run concurrently on multiple CPUs. Mint one exact
    // non-wrapping incarnation and use its current PID component for legacy
    // scheduler lookup. Long-lived authorities carry the full ProcessKey.
    const u64 process_identity = MintProcessKey();
    if (process_identity == 0)
    {
        ReleaseProcessSecurityOwners(p, "PID exhaustion security-owner release failed");
        ReleaseProcessResourceDomainOwner(p, "PID exhaustion resource-domain release failed");
        KLOG_ERROR("core/process", "ProcessCreate: ProcessKey namespace exhausted");
        mm::KFree(p);
        return nullptr;
    }
    p->pid = process_identity;
    p->process_identity = process_identity;
    p->lifecycle_state = ProcessLifecycleState::Private;
    p->termination_state = ProcessTerminationState::Open;
    p->win32_exit_status = 0;
    p->job_inheritance_parent = spawn_parent != nullptr ? ProcessKeySnapshot(spawn_parent) : kInvalidProcessKey;
    u64 name_len = 0;
    while (name[name_len] != '\0' && name_len + 1 < Process::kNameCap)
    {
        p->name_storage[name_len] = name[name_len];
        ++name_len;
    }
    p->name_storage[name_len] = '\0';
    p->name = p->name_storage;
    p->as = as;
    p->root = root;
    p->user_code_va = user_code_va;
    p->user_stack_va = user_stack_va;
    p->user_rsp_init = 0; // loader overrides if it wants a custom rsp
    p->user_gs_base = 0;  // PE loader sets this to the TEB VA
    // No growable stack until a loader publishes a reservation
    // (SpawnPeFile does; ELF / native smoke payloads do not).
    p->stack = UserStackRange{};
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
    p->win32_heap_lock.owner = nullptr;
    p->win32_heap_lock.waiters.head = nullptr;
    p->win32_heap_lock.waiters.tail = nullptr;
    p->win32_heap_lock.class_id = sync::kLockClassUnclassified;
    p->win32_heap_lock.ownership_class = sched::Mutex::OwnershipClass::Internal;
    p->heap_base = 0;  // PeLoad fills these when the PE has
    p->heap_pages = 0; // imports — see subsystems/win32/heap.cpp
    p->heap_free_head = 0;
    for (u32 slot = 0; slot < Process::kWin32ExtraHeapCap; ++slot)
    {
        p->extra_heaps[slot].in_use = false;
        for (u32 pad = 0; pad < sizeof(p->extra_heaps[slot]._pad); ++pad)
            p->extra_heaps[slot]._pad[pad] = 0;
        p->extra_heaps[slot].generation = 0;
        p->extra_heaps[slot].base_va = 0;
        p->extra_heaps[slot].pages = 0;
        p->extra_heaps[slot].free_head = 0;
    }
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
        p->linux_fds[i].generation = 1;
        for (u32 j = 0; j < sizeof(p->linux_fds[i].path); ++j)
            p->linux_fds[i].path[j] = 0;
    }
    p->linux_brk_base = 0; // loader fills when abi_flavor = kAbiLinux
    p->linux_brk_current = 0;
    p->linux_mmap_cursor = Process::kCompatAutoVmBase;
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
        p->win32_handles[i].generation = 0;
        p->win32_handles[i].kind = Process::FsBackingKind::None;
        p->win32_handles[i].ramfs_node = nullptr;
        p->win32_handles[i].fat32_volume_idx = 0;
        p->win32_handles[i].cursor = 0;
        p->win32_handles[i].named_pipe_registry_slot = -1;
        p->win32_handles[i].named_pipe_registry_gen = 0;
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
    // a running thread). `memset` above zero-initialized the
    // accompanying win32_thread_lock.
    for (u32 i = 0; i < Process::kWin32ThreadCap; ++i)
    {
        p->win32_threads[i].in_use = false;
        p->win32_threads[i].creating = false;
        p->win32_threads[i].handle_open = false;
        p->win32_threads[i].exited = false;
        p->win32_threads[i].exit_code = 0x103; // STILL_ACTIVE
        p->win32_threads[i].generation = 0;
        __atomic_store_n(&p->win32_threads[i].event_sequence, 0, __ATOMIC_RELAXED);
        p->win32_threads[i].waiters.head = nullptr;
        p->win32_threads[i].waiters.tail = nullptr;
        p->win32_threads[i].tid = 0;
        p->win32_threads[i].user_stack_va = 0;
    }
    // Process-handle publication advances zero-initialized rows to generation
    // one. Terminal generations retire permanently instead of wrapping.
    for (u32 i = 0; i < Process::kWin32ProcessCap; ++i)
    {
        p->win32_proc_handles[i].generation = 0;
        p->win32_proc_handles[i].state = Process::Win32ProcessHandleState::Free;
        for (u32 j = 0; j < sizeof(p->win32_proc_handles[i]._pad); ++j)
            p->win32_proc_handles[i]._pad[j] = 0;
        p->win32_proc_handles[i].target = nullptr;
    }
    // Win32 foreign-thread table — every slot starts free.
    // Populated by NtOpenThread (SYS_THREAD_OPEN), drained by
    // NtClose's by-range dispatch.
    for (u32 i = 0; i < Process::kWin32ForeignThreadCap; ++i)
    {
        p->win32_foreign_threads[i].in_use = false;
        for (u32 j = 0; j < sizeof(p->win32_foreign_threads[i]._pad); ++j)
            p->win32_foreign_threads[i]._pad[j] = 0;
        p->win32_foreign_threads[i].tid = 0;
    }
    // Win32 section handle table — every slot starts free.
    // Populated by NtCreateSection (SYS_SECTION_CREATE), drained
    // by NtClose's by-range dispatch.
    for (u32 i = 0; i < Process::kWin32SectionCap; ++i)
    {
        p->win32_section_handles[i].generation = 0;
        p->win32_section_handles[i].state = Process::Win32SectionHandleState::Free;
        for (u32 j = 0; j < sizeof(p->win32_section_handles[i]._pad); ++j)
            p->win32_section_handles[i]._pad[j] = 0;
        p->win32_section_handles[i].key = subsystems::win32::section::kInvalidSectionKey;
    }
    // Win32 section VIEW records — every slot free. Populated by
    // NtMapViewOfSection, cleared by NtUnmapViewOfSection, drained
    // by Process runtime teardown before the address space is torn down.
    for (u32 i = 0; i < Process::kWin32SectionCap; ++i)
    {
        p->win32_section_views[i].generation = 0;
        p->win32_section_views[i].state = Process::Win32SectionViewState::Free;
        for (u32 j = 0; j < sizeof(p->win32_section_views[i]._pad); ++j)
            p->win32_section_views[i]._pad[j] = 0;
        p->win32_section_views[i].key = subsystems::win32::section::kInvalidSectionKey;
        p->win32_section_views[i]._pad2 = 0;
        p->win32_section_views[i].base_va = 0;
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
    // Win32 TLS — no slots allocated, all generations zero.
    p->tls_slot_in_use = 0;
    for (u32 i = 0; i < Process::kWin32TlsCap; ++i)
        p->tls_slot_generation[i] = 0;
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
    __atomic_store_n(&p->linux_pending_signals, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&p->linux_signal_event_sequence, 0, __ATOMIC_RELAXED);
    p->linux_signal_wq.head = nullptr;
    p->linux_signal_wq.tail = nullptr;
    // Rlimit soft caps default to "no cap below kernel hard
    // ceiling"; setrlimit/prlimit64 lower these and fd-alloc /
    // clone honour them.
    p->linux_rlimit_nofile_cur = 0xFFFFFFFFFFFFFFFFull;
    __atomic_store_n(&p->linux_rlimit_nproc_cur, 0xFFFFFFFFFFFFFFFFull, __ATOMIC_RELEASE);
    // Linux parent / wait state. fork() / clone() registers the child in a
    // parent-owned relation row before scheduler publication; bare
    // ProcessCreate has no parent (init-spawned).
    p->linux_parent = nullptr;
    p->linux_parent_pid = 0;
    p->linux_exit_code = 0;
    p->linux_was_signaled = false;
    p->linux_exit_signal = 0;
    for (u32 i = 0; i < sizeof(p->_linux_exit_pad); ++i)
        p->_linux_exit_pad[i] = 0;
    p->linux_child_relation_count = 0;
    for (u64 i = 0; i < Process::kLinuxChildRelationCap; ++i)
    {
        p->linux_child_relations[i] = Process::LinuxChildRelation{};
    }
    __atomic_store_n(&p->linux_child_event_sequence, 0, __ATOMIC_RELAXED);
    p->linux_wait_wq.head = nullptr;
    p->linux_wait_wq.tail = nullptr;
    // Win32 custom-diagnostics state lazy-allocates on first opt-in.
    p->win32_custom_state = nullptr;
    // The CWD lock is process-owned and is initialized before this private
    // Process can be published. It needs no teardown; zero-ticket state is
    // unlocked, and the explicit diagnostic owner makes that state clear.
    p->linux_cwd_lock.next_ticket = 0;
    p->linux_cwd_lock.now_serving = 0;
    p->linux_cwd_lock.owner_cpu = 0xFFFFFFFFu;
    p->linux_cwd_lock.class_id = sync::kLockClassUnclassified;
    // Default cwd is "/" — matches the value DoGetcwd hard-coded before this
    // field existed. Publication happens only after initialization completes.
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

    __atomic_add_fetch(&g_live_processes, 1, __ATOMIC_RELAXED);

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

bool ProcessReplaceResourceDomainBeforePublish(Process* process, ResourceDomainKey replacement)
{
    if (process == nullptr || !ResourceDomainKeyIsValid(replacement) ||
        __atomic_load_n(&process->refcount, __ATOMIC_ACQUIRE) != 1 ||
        ProcessLifecycleLoad(process) != ProcessLifecycleState::Private)
    {
        return false;
    }
    if (!ResourceDomainRetain(replacement))
        return false;

    const ResourceDomainKey previous = process->resource_domain;
    if (!ResourceDomainRelease(previous))
    {
        const bool rolled_back = ResourceDomainRelease(replacement);
        if (!rolled_back)
            PanicWithValue("core/process", "resource-domain replacement rollback failed", replacement.generation);
        return false;
    }
    process->resource_domain = replacement;
    return true;
}

bool ProcessInstallPublicationGateBeforePublish(Process* process, ProcessPublicationGate gate, void* context)
{
    if (process == nullptr || gate == nullptr || __atomic_load_n(&process->refcount, __ATOMIC_ACQUIRE) != 1 ||
        ProcessLifecycleLoad(process) != ProcessLifecycleState::Private || process->publication_gate != nullptr ||
        process->publication_gate_context != nullptr)
    {
        return false;
    }

    process->publication_gate = gate;
    process->publication_gate_context = context;
    return true;
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
        if (cur == ~0ULL)
        {
            PanicWithValue("core/process", "ProcessRetain would wrap saturated refcount", reinterpret_cast<u64>(p));
        }
        const u64 next = cur + 1;
        if (__atomic_compare_exchange_n(&p->refcount, &cur, next, /*weak=*/false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        {
            return;
        }
        // CAS lost the race; cur has the fresh value. Loop and retry.
    }
}

ProcessLifecycleState ProcessLifecycleLoad(const Process* process)
{
    KASSERT(process != nullptr, "core/process", "ProcessLifecycleLoad null process");
    static_assert(sizeof(ProcessLifecycleState) == sizeof(u32));
    ProcessLifecycleState observed = ProcessLifecycleState::Private;
    // Use the generic builtin on the enum object itself. Reinterpreting the
    // storage as u32 gives the compiler an aliasing story the C++ type system
    // does not permit, even though the representation sizes match.
    __atomic_load(&process->lifecycle_state, &observed, __ATOMIC_ACQUIRE);
    return observed;
}

bool ProcessLifecycleTransition(Process* process, ProcessLifecycleState expected, ProcessLifecycleState desired)
{
    KASSERT(process != nullptr, "core/process", "ProcessLifecycleTransition null process");
    const bool valid = (expected == ProcessLifecycleState::Private && desired == ProcessLifecycleState::Published) ||
                       (expected == ProcessLifecycleState::Published && desired == ProcessLifecycleState::Exiting) ||
                       (expected == ProcessLifecycleState::Exiting && desired == ProcessLifecycleState::Exited);
    KASSERT(valid, "core/process", "invalid Process lifecycle transition");
    ProcessLifecycleState observed = expected;
    ProcessLifecycleState replacement = desired;
    return __atomic_compare_exchange(&process->lifecycle_state, &observed, &replacement, /*weak=*/false,
                                     __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
}

ProcessTerminationState ProcessTerminationLoad(const Process* process)
{
    KASSERT(process != nullptr, "core/process", "ProcessTerminationLoad null process");
    static_assert(sizeof(ProcessTerminationState) == sizeof(u32));
    ProcessTerminationState observed = ProcessTerminationState::Open;
    __atomic_load(&process->termination_state, &observed, __ATOMIC_ACQUIRE);
    return observed;
}

namespace
{
constexpr u64 kWin32ExitStatusPublished = 1ULL << 32;
constexpr u32 kWin32StillActive = 0x103;

u64 EncodeWin32ProcessExitStatus(u32 exit_code)
{
    return kWin32ExitStatusPublished | static_cast<u64>(exit_code);
}
} // namespace

bool ProcessTerminationClose(Process* process, u32 exit_code)
{
    KASSERT(process != nullptr, "core/process", "ProcessTerminationClose null process");
    ProcessTerminationState observed = ProcessTerminationState::Open;
    ProcessTerminationState replacement = ProcessTerminationState::Closed;
    if (__atomic_compare_exchange(&process->termination_state, &observed, &replacement, /*weak=*/false,
                                  __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
    {
        u64 empty = 0;
        const u64 published = EncodeWin32ProcessExitStatus(exit_code);
        KASSERT(__atomic_compare_exchange_n(&process->win32_exit_status, &empty, published, false, __ATOMIC_RELEASE,
                                            __ATOMIC_RELAXED),
                "core/process", "first Process close lost exit-status publication");
        return true;
    }
    KASSERT(observed == ProcessTerminationState::Closed, "core/process", "invalid Process termination state");
    return false;
}

void ProcessPublishLastTaskExitCodeIfUnset(Process* process, u32 exit_code)
{
    KASSERT(process != nullptr, "core/process", "last-Task exit-status publication on null process");
    u64 empty = 0;
    const u64 published = EncodeWin32ProcessExitStatus(exit_code);
    (void)__atomic_compare_exchange_n(&process->win32_exit_status, &empty, published, false, __ATOMIC_RELEASE,
                                      __ATOMIC_RELAXED);
}

u32 ProcessWin32ExitCodeSnapshot(const Process* process)
{
    KASSERT(process != nullptr, "core/process", "ProcessWin32ExitCodeSnapshot null process");
    if (ProcessLifecycleLoad(process) != ProcessLifecycleState::Exited)
        return kWin32StillActive;

    const u64 published = __atomic_load_n(&process->win32_exit_status, __ATOMIC_ACQUIRE);
    KASSERT((published & kWin32ExitStatusPublished) != 0, "core/process",
            "Exited Process has no durable Win32 exit status");
    return static_cast<u32>(published);
}

ProcessKey ProcessKeySnapshot(const Process* process)
{
    KASSERT(process != nullptr, "core/process", "ProcessKeySnapshot null process");
    const ProcessKey key{process->process_identity, process->pid};
    KASSERT(ProcessKeyIsValid(key), "core/process", "Process owns invalid immutable identity");
    return key;
}

bool ProcessRunPublicationGateAtSchedulerPublication(Process* process)
{
    KASSERT(process != nullptr, "core/process", "Process publication gate on null process");
    KASSERT(ProcessLifecycleLoad(process) == ProcessLifecycleState::Private, "core/process",
            "Process publication gate requires Private lifecycle");

    const ProcessKey key = ProcessKeySnapshot(process);
    ProcessPublicationGate gate = process->publication_gate;
    void* context = process->publication_gate_context;
    process->publication_gate = nullptr;
    process->publication_gate_context = nullptr;
    if (gate == nullptr)
    {
        KASSERT(context == nullptr, "core/process", "Process publication gate has orphan context");
        return true;
    }
    return gate(key, context);
}

u64 EncodeWin32FileHandle(const Process::Win32FileHandleIdentity& identity)
{
    static_assert((Process::kWin32HandleBase & ~Process::kWin32FileHandleTagMask) == 0,
                  "Win32 file-handle base must fit in the low tag");
    static_assert(Process::kWin32HandleBase + Process::kWin32HandleCap - 1 <= Process::kWin32FileHandleTagMask,
                  "Win32 file-handle tag band must fit in the low tag");
    static_assert(Process::kWin32FileHandleMaxGeneration == 0x7FFFF,
                  "Win32 file-handle generation must fit PE32 bits 12..30");

    if (identity.slot >= Process::kWin32HandleCap || identity.generation == 0 ||
        identity.generation > Process::kWin32FileHandleMaxGeneration)
    {
        return 0;
    }

    const u64 tag = Process::kWin32HandleBase + identity.slot;
    return (identity.generation << Process::kWin32FileHandleGenerationShift) | tag;
}

bool DecodeWin32FileHandle(u64 handle, Process::Win32FileHandleIdentity* identity_out)
{
    if (identity_out == nullptr || handle > Process::kWin32FileHandleMaxValue)
        return false;

    const u64 generation = handle >> Process::kWin32FileHandleGenerationShift;
    const u64 tag = handle & Process::kWin32FileHandleTagMask;
    if (generation == 0 || generation > Process::kWin32FileHandleMaxGeneration || tag < Process::kWin32HandleBase ||
        tag >= Process::kWin32HandleBase + Process::kWin32HandleCap)
    {
        return false;
    }

    Process::Win32FileHandleIdentity identity{};
    identity.slot = static_cast<u32>(util::MaskedIndex(tag - Process::kWin32HandleBase, Process::kWin32HandleCap));
    identity.generation = generation;
    *identity_out = identity;
    return true;
}

bool IsWin32FileHandle(u64 handle)
{
    Process::Win32FileHandleIdentity identity{};
    return DecodeWin32FileHandle(handle, &identity);
}

bool ProcessReserveWin32FileHandle(Process* owner, Process::Win32FileReservation* reservation_out)
{
    if (owner == nullptr || reservation_out == nullptr)
        return false;

    bool reserved = false;
    Process::Win32FileReservation reservation{};
    const sync::IrqFlags flags = sync::SpinLockAcquire(owner->win32_file_lock);
    for (u32 i = 0; i < Process::kWin32HandleCap; ++i)
    {
        Process::Win32FileHandle& row = owner->win32_handles[i];
        if (row.kind != Process::FsBackingKind::None || row.generation >= Process::kWin32FileHandleMaxGeneration)
            continue;

        const u64 generation = row.generation + 1;
        Process::Win32FileHandle claimed{};
        claimed.generation = generation;
        claimed.kind = Process::FsBackingKind::Reserved;
        claimed.named_pipe_registry_slot = -1;
        row = claimed;
        reservation.slot = i;
        reservation.generation = generation;
        reserved = true;
        break;
    }
    sync::SpinLockRelease(owner->win32_file_lock, flags);

    if (reserved)
        *reservation_out = reservation;
    return reserved;
}

bool ProcessPublishWin32FileHandle(Process* owner, const Process::Win32FileReservation& reservation,
                                   const Process::Win32FileHandle& candidate, u64* handle_out)
{
    if (owner == nullptr || handle_out == nullptr || reservation.slot >= Process::kWin32HandleCap ||
        reservation.generation == 0 || candidate.kind == Process::FsBackingKind::None ||
        candidate.kind == Process::FsBackingKind::Reserved)
    {
        return false;
    }

    const Process::Win32FileHandleIdentity identity{reservation.slot, 0, reservation.generation};
    const u64 encoded_handle = EncodeWin32FileHandle(identity);
    if (encoded_handle == 0)
        return false;

    bool published = false;
    const u32 slot = static_cast<u32>(util::MaskedIndex(reservation.slot, Process::kWin32HandleCap));
    const sync::IrqFlags flags = sync::SpinLockAcquire(owner->win32_file_lock);
    Process::Win32FileHandle& row = owner->win32_handles[slot];
    if (row.kind == Process::FsBackingKind::Reserved && row.generation == reservation.generation)
    {
        row = candidate;
        row.generation = reservation.generation;
        published = true;
    }
    sync::SpinLockRelease(owner->win32_file_lock, flags);

    if (published)
        *handle_out = encoded_handle;
    return published;
}

void ProcessAbortWin32FileHandle(Process* owner, const Process::Win32FileReservation& reservation)
{
    if (owner == nullptr || reservation.slot >= Process::kWin32HandleCap || reservation.generation == 0 ||
        reservation.generation > Process::kWin32FileHandleMaxGeneration)
        return;

    const u32 slot = static_cast<u32>(util::MaskedIndex(reservation.slot, Process::kWin32HandleCap));
    const sync::IrqFlags flags = sync::SpinLockAcquire(owner->win32_file_lock);
    Process::Win32FileHandle& row = owner->win32_handles[slot];
    if (row.kind == Process::FsBackingKind::Reserved && row.generation == reservation.generation)
    {
        Process::Win32FileHandle empty{};
        empty.generation = reservation.generation;
        empty.kind = Process::FsBackingKind::None;
        empty.named_pipe_registry_slot = -1;
        row = empty;
    }
    sync::SpinLockRelease(owner->win32_file_lock, flags);
}

bool ProcessDetachWin32FileHandle(Process* owner, u64 handle, Process::Win32FileHandle* detached_out)
{
    Process::Win32FileHandleIdentity identity{};
    if (owner == nullptr || detached_out == nullptr || !DecodeWin32FileHandle(handle, &identity))
        return false;

    bool detached = false;
    const sync::IrqFlags flags = sync::SpinLockAcquire(owner->win32_file_lock);
    Process::Win32FileHandle& row = owner->win32_handles[identity.slot];
    if (row.generation == identity.generation && row.kind != Process::FsBackingKind::None &&
        row.kind != Process::FsBackingKind::Reserved)
    {
        *detached_out = row;
        Process::Win32FileHandle empty{};
        empty.generation = row.generation;
        empty.kind = Process::FsBackingKind::None;
        empty.named_pipe_registry_slot = -1;
        row = empty;
        detached = true;
    }
    sync::SpinLockRelease(owner->win32_file_lock, flags);
    return detached;
}

u32 ProcessWin32FileHandleCount(const Process* owner)
{
    if (owner == nullptr)
        return 0;

    u32 count = 0;
    const sync::IrqFlags flags = sync::SpinLockAcquire(owner->win32_file_lock);
    for (u32 slot = 0; slot < Process::kWin32HandleCap; ++slot)
    {
        const Process::Win32FileHandle& row = owner->win32_handles[slot];
        if (row.kind != Process::FsBackingKind::None && row.kind != Process::FsBackingKind::Reserved &&
            row.generation != 0 && row.generation <= Process::kWin32FileHandleMaxGeneration)
        {
            ++count;
        }
    }
    sync::SpinLockRelease(owner->win32_file_lock, flags);
    return count;
}

u64 EncodeWin32SectionHandle(const Process::Win32SectionHandleIdentity& identity)
{
    static_assert((Process::kWin32SectionBase & ~Process::kWin32SectionHandleTagMask) == 0,
                  "Win32 Section base must fit in the low tag");
    static_assert(Process::kWin32SectionBase + Process::kWin32SectionCap - 1 <= Process::kWin32SectionHandleTagMask,
                  "Win32 Section tag band must fit in the low tag");
    static_assert(Process::kWin32SectionHandleMaxGeneration == 0x7FFFF,
                  "Win32 Section generation must fit PE32 bits 12..30");
    static_assert(Process::kWin32SectionHandleMaxGeneration == subsystems::win32::section::kSectionMaxGeneration,
                  "public Section rows and pool keys must share the PE32 generation ceiling");

    if (identity.slot >= Process::kWin32SectionCap || identity.generation == 0 ||
        identity.generation > Process::kWin32SectionHandleMaxGeneration)
    {
        return 0;
    }

    const u64 tag = Process::kWin32SectionBase + identity.slot;
    return (static_cast<u64>(identity.generation) << Process::kWin32SectionHandleGenerationShift) | tag;
}

bool DecodeWin32SectionHandle(u64 handle, Process::Win32SectionHandleIdentity* identity_out)
{
    if (identity_out == nullptr || handle > Process::kWin32SectionHandleMaxValue)
        return false;

    const u64 generation = handle >> Process::kWin32SectionHandleGenerationShift;
    const u64 tag = handle & Process::kWin32SectionHandleTagMask;
    if (generation == 0 || generation > Process::kWin32SectionHandleMaxGeneration || tag < Process::kWin32SectionBase ||
        tag >= Process::kWin32SectionBase + Process::kWin32SectionCap)
    {
        return false;
    }

    Process::Win32SectionHandleIdentity identity{};
    identity.slot = static_cast<u32>(util::MaskedIndex(tag - Process::kWin32SectionBase, Process::kWin32SectionCap));
    identity.generation = static_cast<u32>(generation);
    *identity_out = identity;
    return true;
}

bool IsWin32SectionHandle(u64 handle)
{
    Process::Win32SectionHandleIdentity identity{};
    return DecodeWin32SectionHandle(handle, &identity);
}

bool ProcessReserveWin32SectionHandle(Process* owner, Process::Win32SectionHandleReservation* reservation_out)
{
    if (owner == nullptr || reservation_out == nullptr)
        return false;

    bool reserved = false;
    Process::Win32SectionHandleReservation reservation{};
    const sync::IrqFlags flags = sync::SpinLockAcquire(owner->win32_section_lock);
    for (u32 slot = 0; slot < Process::kWin32SectionCap; ++slot)
    {
        Process::Win32SectionHandle& row = owner->win32_section_handles[slot];
        if (row.state != Process::Win32SectionHandleState::Free ||
            row.generation >= Process::kWin32SectionHandleMaxGeneration)
        {
            continue;
        }

        ++row.generation;
        row.state = Process::Win32SectionHandleState::Reserved;
        row.key = subsystems::win32::section::kInvalidSectionKey;
        reservation.slot = slot;
        reservation.generation = row.generation;
        reserved = true;
        break;
    }
    sync::SpinLockRelease(owner->win32_section_lock, flags);

    if (reserved)
        *reservation_out = reservation;
    return reserved;
}

bool ProcessPublishWin32SectionHandle(Process* owner, const Process::Win32SectionHandleReservation& reservation,
                                      subsystems::win32::section::SectionKey key, u64* handle_out)
{
    if (owner == nullptr || handle_out == nullptr || reservation.slot >= Process::kWin32SectionCap ||
        reservation.generation == 0 || reservation.generation > Process::kWin32SectionHandleMaxGeneration ||
        !subsystems::win32::section::SectionKeyIsValid(key))
    {
        return false;
    }

    const Process::Win32SectionHandleIdentity identity{reservation.slot, reservation.generation};
    const u64 handle = EncodeWin32SectionHandle(identity);
    if (handle == 0)
        return false;

    bool published = false;
    const u32 slot = static_cast<u32>(util::MaskedIndex(reservation.slot, Process::kWin32SectionCap));
    const sync::IrqFlags flags = sync::SpinLockAcquire(owner->win32_section_lock);
    Process::Win32SectionHandle& row = owner->win32_section_handles[slot];
    if (row.state == Process::Win32SectionHandleState::Reserved && row.generation == reservation.generation)
    {
        row.key = key;
        row.state = Process::Win32SectionHandleState::Live;
        published = true;
    }
    sync::SpinLockRelease(owner->win32_section_lock, flags);

    if (published)
        *handle_out = handle;
    return published;
}

void ProcessAbortWin32SectionHandle(Process* owner, const Process::Win32SectionHandleReservation& reservation)
{
    if (owner == nullptr || reservation.slot >= Process::kWin32SectionCap || reservation.generation == 0 ||
        reservation.generation > Process::kWin32SectionHandleMaxGeneration)
    {
        return;
    }

    const u32 slot = static_cast<u32>(util::MaskedIndex(reservation.slot, Process::kWin32SectionCap));
    const sync::IrqFlags flags = sync::SpinLockAcquire(owner->win32_section_lock);
    Process::Win32SectionHandle& row = owner->win32_section_handles[slot];
    if (row.state == Process::Win32SectionHandleState::Reserved && row.generation == reservation.generation)
    {
        row.state = Process::Win32SectionHandleState::Free;
        row.key = subsystems::win32::section::kInvalidSectionKey;
    }
    sync::SpinLockRelease(owner->win32_section_lock, flags);
}

bool ProcessAcquireWin32SectionHandle(Process* owner, u64 handle, subsystems::win32::section::SectionKey* key_out)
{
    Process::Win32SectionHandleIdentity identity{};
    if (owner == nullptr || key_out == nullptr || !DecodeWin32SectionHandle(handle, &identity))
        return false;

    subsystems::win32::section::SectionKey key = subsystems::win32::section::kInvalidSectionKey;
    {
        const sync::IrqFlags flags = sync::SpinLockAcquire(owner->win32_section_lock);
        const Process::Win32SectionHandle& row = owner->win32_section_handles[identity.slot];
        if (row.state == Process::Win32SectionHandleState::Live && row.generation == identity.generation &&
            subsystems::win32::section::SectionKeyIsValid(row.key))
        {
            key = row.key;
        }
        sync::SpinLockRelease(owner->win32_section_lock, flags);
    }

    // The Section pool is a separate lifetime domain. Pin it without holding
    // the per-Process table lock, then revalidate the exact public row before
    // publishing the operation reference. This avoids a Process->Section
    // nested-lock edge while making a concurrent close/recycle a clean miss.
    if (!subsystems::win32::section::SectionKeyIsValid(key) || !subsystems::win32::section::SectionRetain(key))
    {
        return false;
    }

    bool acquired = false;
    {
        const sync::IrqFlags flags = sync::SpinLockAcquire(owner->win32_section_lock);
        const Process::Win32SectionHandle& row = owner->win32_section_handles[identity.slot];
        acquired = row.state == Process::Win32SectionHandleState::Live && row.generation == identity.generation &&
                   row.key == key;
        sync::SpinLockRelease(owner->win32_section_lock, flags);
    }

    if (!acquired)
    {
        subsystems::win32::section::SectionRelease(key);
        return false;
    }

    if (key_out != nullptr)
        *key_out = key;
    return true;
}

bool ProcessDetachWin32SectionHandle(Process* owner, u64 handle, subsystems::win32::section::SectionKey* key_out)
{
    Process::Win32SectionHandleIdentity identity{};
    if (owner == nullptr || key_out == nullptr || !DecodeWin32SectionHandle(handle, &identity))
        return false;

    bool detached = false;
    subsystems::win32::section::SectionKey key = subsystems::win32::section::kInvalidSectionKey;
    const sync::IrqFlags flags = sync::SpinLockAcquire(owner->win32_section_lock);
    Process::Win32SectionHandle& row = owner->win32_section_handles[identity.slot];
    if (row.state == Process::Win32SectionHandleState::Live && row.generation == identity.generation &&
        subsystems::win32::section::SectionKeyIsValid(row.key))
    {
        key = row.key;
        row.state = Process::Win32SectionHandleState::Free;
        row.key = subsystems::win32::section::kInvalidSectionKey;
        detached = true;
    }
    sync::SpinLockRelease(owner->win32_section_lock, flags);

    if (detached)
        *key_out = key;
    return detached;
}

u32 ProcessWin32SectionHandleCount(const Process* owner)
{
    if (owner == nullptr)
        return 0;

    u32 count = 0;
    const sync::IrqFlags flags = sync::SpinLockAcquire(owner->win32_section_lock);
    for (u32 slot = 0; slot < Process::kWin32SectionCap; ++slot)
    {
        const Process::Win32SectionHandle& row = owner->win32_section_handles[slot];
        if (row.state == Process::Win32SectionHandleState::Live && row.generation != 0 &&
            row.generation <= Process::kWin32SectionHandleMaxGeneration &&
            subsystems::win32::section::SectionKeyIsValid(row.key))
        {
            ++count;
        }
    }
    sync::SpinLockRelease(owner->win32_section_lock, flags);
    return count;
}

bool ProcessReserveWin32SectionView(Process* owner, Process::Win32SectionViewReservation* reservation_out)
{
    if (owner == nullptr || reservation_out == nullptr)
        return false;

    bool reserved = false;
    Process::Win32SectionViewReservation reservation{};
    const sync::IrqFlags flags = sync::SpinLockAcquire(owner->win32_section_lock);
    for (u32 slot = 0; slot < Process::kWin32SectionCap; ++slot)
    {
        Process::Win32SectionView& row = owner->win32_section_views[slot];
        if (row.state != Process::Win32SectionViewState::Free || row.generation == ~0ULL)
            continue;

        ++row.generation;
        row.state = Process::Win32SectionViewState::Reserved;
        row.key = subsystems::win32::section::kInvalidSectionKey;
        row.base_va = 0;
        reservation.slot = slot;
        reservation.generation = row.generation;
        reserved = true;
        break;
    }
    sync::SpinLockRelease(owner->win32_section_lock, flags);

    if (reserved)
        *reservation_out = reservation;
    return reserved;
}

bool ProcessPublishWin32SectionView(Process* owner, const Process::Win32SectionViewReservation& reservation,
                                    subsystems::win32::section::SectionKey key, u64 base_va)
{
    if (owner == nullptr || reservation.slot >= Process::kWin32SectionCap || reservation.generation == 0 ||
        !subsystems::win32::section::SectionKeyIsValid(key) || base_va == 0)
    {
        return false;
    }

    bool published = false;
    const u32 slot = static_cast<u32>(util::MaskedIndex(reservation.slot, Process::kWin32SectionCap));
    const sync::IrqFlags flags = sync::SpinLockAcquire(owner->win32_section_lock);
    Process::Win32SectionView& row = owner->win32_section_views[slot];
    if (row.state == Process::Win32SectionViewState::Reserved && row.generation == reservation.generation)
    {
        row.key = key;
        row.base_va = base_va;
        row.state = Process::Win32SectionViewState::Live;
        published = true;
    }
    sync::SpinLockRelease(owner->win32_section_lock, flags);
    return published;
}

void ProcessAbortWin32SectionView(Process* owner, const Process::Win32SectionViewReservation& reservation)
{
    if (owner == nullptr || reservation.slot >= Process::kWin32SectionCap || reservation.generation == 0)
        return;

    const u32 slot = static_cast<u32>(util::MaskedIndex(reservation.slot, Process::kWin32SectionCap));
    const sync::IrqFlags flags = sync::SpinLockAcquire(owner->win32_section_lock);
    Process::Win32SectionView& row = owner->win32_section_views[slot];
    if (row.state == Process::Win32SectionViewState::Reserved && row.generation == reservation.generation)
    {
        row.state = Process::Win32SectionViewState::Free;
        row.key = subsystems::win32::section::kInvalidSectionKey;
        row.base_va = 0;
    }
    sync::SpinLockRelease(owner->win32_section_lock, flags);
}

bool ProcessClaimWin32SectionView(Process* owner, u64 base_va, Process::Win32SectionViewClaim* claim_out)
{
    if (owner == nullptr || claim_out == nullptr || base_va == 0)
        return false;

    bool claimed = false;
    Process::Win32SectionViewClaim claim{};
    const sync::IrqFlags flags = sync::SpinLockAcquire(owner->win32_section_lock);
    for (u32 slot = 0; slot < Process::kWin32SectionCap; ++slot)
    {
        Process::Win32SectionView& row = owner->win32_section_views[slot];
        if (row.state != Process::Win32SectionViewState::Live || row.base_va != base_va ||
            !subsystems::win32::section::SectionKeyIsValid(row.key))
        {
            continue;
        }

        row.state = Process::Win32SectionViewState::Claimed;
        claim.slot = slot;
        claim.generation = row.generation;
        claim.key = row.key;
        claim.base_va = row.base_va;
        claimed = true;
        break;
    }
    sync::SpinLockRelease(owner->win32_section_lock, flags);

    if (claimed)
        *claim_out = claim;
    return claimed;
}

bool ProcessClaimWin32SectionViewExact(Process* owner, const Process::Win32SectionViewReservation& reservation,
                                       subsystems::win32::section::SectionKey key, u64 base_va,
                                       Process::Win32SectionViewClaim* claim_out)
{
    if (owner == nullptr || claim_out == nullptr || reservation.slot >= Process::kWin32SectionCap ||
        reservation.generation == 0 || !subsystems::win32::section::SectionKeyIsValid(key) || base_va == 0)
    {
        return false;
    }

    bool claimed = false;
    Process::Win32SectionViewClaim claim{};
    const u32 slot = static_cast<u32>(util::MaskedIndex(reservation.slot, Process::kWin32SectionCap));
    const sync::IrqFlags flags = sync::SpinLockAcquire(owner->win32_section_lock);
    Process::Win32SectionView& row = owner->win32_section_views[slot];
    if (row.state == Process::Win32SectionViewState::Live && row.generation == reservation.generation &&
        row.key == key && row.base_va == base_va)
    {
        row.state = Process::Win32SectionViewState::Claimed;
        claim.slot = slot;
        claim.generation = row.generation;
        claim.key = row.key;
        claim.base_va = row.base_va;
        claimed = true;
    }
    sync::SpinLockRelease(owner->win32_section_lock, flags);

    if (claimed)
        *claim_out = claim;
    return claimed;
}

bool ProcessRestoreWin32SectionView(Process* owner, const Process::Win32SectionViewClaim& claim)
{
    if (owner == nullptr || claim.slot >= Process::kWin32SectionCap || claim.generation == 0 ||
        !subsystems::win32::section::SectionKeyIsValid(claim.key) || claim.base_va == 0)
    {
        return false;
    }

    bool restored = false;
    const u32 slot = static_cast<u32>(util::MaskedIndex(claim.slot, Process::kWin32SectionCap));
    const sync::IrqFlags flags = sync::SpinLockAcquire(owner->win32_section_lock);
    Process::Win32SectionView& row = owner->win32_section_views[slot];
    if (row.state == Process::Win32SectionViewState::Claimed && row.generation == claim.generation &&
        row.key == claim.key && row.base_va == claim.base_va)
    {
        row.state = Process::Win32SectionViewState::Live;
        restored = true;
    }
    sync::SpinLockRelease(owner->win32_section_lock, flags);
    return restored;
}

bool ProcessFinishWin32SectionView(Process* owner, const Process::Win32SectionViewClaim& claim)
{
    if (owner == nullptr || claim.slot >= Process::kWin32SectionCap || claim.generation == 0 ||
        !subsystems::win32::section::SectionKeyIsValid(claim.key) || claim.base_va == 0)
    {
        return false;
    }

    bool finished = false;
    const u32 slot = static_cast<u32>(util::MaskedIndex(claim.slot, Process::kWin32SectionCap));
    const sync::IrqFlags flags = sync::SpinLockAcquire(owner->win32_section_lock);
    Process::Win32SectionView& row = owner->win32_section_views[slot];
    if (row.state == Process::Win32SectionViewState::Claimed && row.generation == claim.generation &&
        row.key == claim.key && row.base_va == claim.base_va)
    {
        row.state = Process::Win32SectionViewState::Free;
        row.key = subsystems::win32::section::kInvalidSectionKey;
        row.base_va = 0;
        finished = true;
    }
    sync::SpinLockRelease(owner->win32_section_lock, flags);
    return finished;
}

u32 ProcessWin32SectionViewCount(const Process* owner)
{
    if (owner == nullptr)
        return 0;

    u32 count = 0;
    const sync::IrqFlags flags = sync::SpinLockAcquire(owner->win32_section_lock);
    for (u32 slot = 0; slot < Process::kWin32SectionCap; ++slot)
    {
        const Process::Win32SectionView& row = owner->win32_section_views[slot];
        if ((row.state == Process::Win32SectionViewState::Live ||
             row.state == Process::Win32SectionViewState::Claimed) &&
            subsystems::win32::section::SectionKeyIsValid(row.key) && row.base_va != 0)
        {
            ++count;
        }
    }
    sync::SpinLockRelease(owner->win32_section_lock, flags);
    return count;
}

bool ProcessHasBorrowedUserMappings(const Process* owner)
{
    if (owner == nullptr)
        return false;

    // Reserved and Claimed rows are included deliberately. Production map
    // and unmap paths hold vm_transaction_lock across those transient states,
    // so exec cannot normally observe one; treating one as busy is the safe
    // response to a future caller that violates that outer contract.
    const sync::IrqFlags section_flags = sync::SpinLockAcquire(owner->win32_section_lock);
    for (u32 slot = 0; slot < Process::kWin32SectionCap; ++slot)
    {
        if (owner->win32_section_views[slot].state != Process::Win32SectionViewState::Free)
        {
            sync::SpinLockRelease(owner->win32_section_lock, section_flags);
            return true;
        }
    }
    sync::SpinLockRelease(owner->win32_section_lock, section_flags);

    for (u32 slot = 0; slot < Process::kLinuxShmAttachCap; ++slot)
    {
        if (owner->linux_shm_attaches[slot].in_use)
            return true;
    }
    return false;
}

namespace
{

struct Win32SectionDrainSnapshot
{
    subsystems::win32::section::SectionKey handle_keys[Process::kWin32SectionCap];
    Process::Win32SectionViewClaim views[Process::kWin32SectionCap];
    u32 handle_count;
    u32 view_count;
};

void DetachAllWin32SectionRows(Process* owner, Win32SectionDrainSnapshot* snapshot)
{
    if (owner == nullptr || snapshot == nullptr)
        return;

    const sync::IrqFlags flags = sync::SpinLockAcquire(owner->win32_section_lock);
    for (u32 slot = 0; slot < Process::kWin32SectionCap; ++slot)
    {
        Process::Win32SectionHandle& handle = owner->win32_section_handles[slot];
        if (handle.state == Process::Win32SectionHandleState::Live &&
            subsystems::win32::section::SectionKeyIsValid(handle.key))
        {
            snapshot->handle_keys[snapshot->handle_count++] = handle.key;
        }
        handle.state = Process::Win32SectionHandleState::Free;
        handle.key = subsystems::win32::section::kInvalidSectionKey;

        Process::Win32SectionView& view = owner->win32_section_views[slot];
        if ((view.state == Process::Win32SectionViewState::Live ||
             view.state == Process::Win32SectionViewState::Claimed) &&
            subsystems::win32::section::SectionKeyIsValid(view.key) && view.base_va != 0)
        {
            Process::Win32SectionViewClaim& detached = snapshot->views[snapshot->view_count++];
            detached.slot = slot;
            detached.generation = view.generation;
            detached.key = view.key;
            detached.base_va = view.base_va;
        }
        view.state = Process::Win32SectionViewState::Free;
        view.key = subsystems::win32::section::kInvalidSectionKey;
        view.base_va = 0;
    }
    sync::SpinLockRelease(owner->win32_section_lock, flags);
}

} // namespace

u64 EncodeWin32ProcessHandle(const Process::Win32ProcessHandleIdentity& identity)
{
    static_assert((Process::kWin32ProcessBase & ~Process::kWin32ProcessHandleTagMask) == 0,
                  "Win32 Process base must fit in the low tag");
    static_assert(Process::kWin32ProcessBase + Process::kWin32ProcessCap - 1 <= Process::kWin32ProcessHandleTagMask,
                  "Win32 Process tag band must fit in the low tag");
    static_assert(Process::kWin32ProcessHandleMaxGeneration == 0x7FFFF,
                  "Win32 Process generation must fit PE32 bits 12..30");

    if (identity.slot >= Process::kWin32ProcessCap || identity.generation == 0 ||
        identity.generation > Process::kWin32ProcessHandleMaxGeneration)
    {
        return 0;
    }

    const u64 tag = Process::kWin32ProcessBase + identity.slot;
    return (static_cast<u64>(identity.generation) << Process::kWin32ProcessHandleGenerationShift) | tag;
}

bool DecodeWin32ProcessHandle(u64 handle, Process::Win32ProcessHandleIdentity* identity_out)
{
    if (identity_out == nullptr || handle > Process::kWin32ProcessHandleMaxValue)
        return false;

    const u64 generation = handle >> Process::kWin32ProcessHandleGenerationShift;
    const u64 tag = handle & Process::kWin32ProcessHandleTagMask;
    if (generation == 0 || generation > Process::kWin32ProcessHandleMaxGeneration || tag < Process::kWin32ProcessBase ||
        tag >= Process::kWin32ProcessBase + Process::kWin32ProcessCap)
    {
        return false;
    }

    Process::Win32ProcessHandleIdentity identity{};
    identity.slot = static_cast<u32>(util::MaskedIndex(tag - Process::kWin32ProcessBase, Process::kWin32ProcessCap));
    identity.generation = static_cast<u32>(generation);
    *identity_out = identity;
    return true;
}

bool IsWin32ProcessHandle(u64 handle)
{
    Process::Win32ProcessHandleIdentity identity{};
    return DecodeWin32ProcessHandle(handle, &identity);
}

u64 ProcessInstallWin32ProcessHandle(Process* owner, Process* target)
{
    if (owner == nullptr || target == nullptr)
    {
        return 0;
    }

    u64 encoded_handle = 0;
    const sync::IrqFlags flags = sync::SpinLockAcquire(owner->win32_handle_lock);
    for (u32 i = 0; i < Process::kWin32ProcessCap; ++i)
    {
        Process::Win32ProcessHandle& row = owner->win32_proc_handles[i];
        if (row.state != Process::Win32ProcessHandleState::Free)
            continue;
        if (row.generation >= Process::kWin32ProcessHandleMaxGeneration)
        {
            row.state = Process::Win32ProcessHandleState::Retired;
            continue;
        }

        ++row.generation;
        row.target = target;
        row.state = Process::Win32ProcessHandleState::Live;
        encoded_handle = EncodeWin32ProcessHandle(Process::Win32ProcessHandleIdentity{i, row.generation});
        KASSERT(encoded_handle != 0, "core/process", "live Win32 Process row did not encode");
        break;
    }
    sync::SpinLockRelease(owner->win32_handle_lock, flags);
    return encoded_handle;
}

Process* ProcessLookupWin32ProcessHandleRetained(Process* owner, u64 handle)
{
    Process::Win32ProcessHandleIdentity identity{};
    if (owner == nullptr || !DecodeWin32ProcessHandle(handle, &identity))
        return nullptr;

    Process* target = nullptr;
    const sync::IrqFlags flags = sync::SpinLockAcquire(owner->win32_handle_lock);
    const Process::Win32ProcessHandle& row = owner->win32_proc_handles[identity.slot];
    if (row.state == Process::Win32ProcessHandleState::Live && row.generation == identity.generation &&
        row.target != nullptr)
    {
        target = row.target;
        ProcessRetain(target);
    }
    sync::SpinLockRelease(owner->win32_handle_lock, flags);
    return target;
}

bool ProcessCloseWin32ProcessHandle(Process* owner, u64 handle)
{
    Process::Win32ProcessHandleIdentity identity{};
    if (owner == nullptr || !DecodeWin32ProcessHandle(handle, &identity))
        return false;

    Process* target = nullptr;
    bool removed = false;
    const sync::IrqFlags flags = sync::SpinLockAcquire(owner->win32_handle_lock);
    Process::Win32ProcessHandle& row = owner->win32_proc_handles[identity.slot];
    if (row.state == Process::Win32ProcessHandleState::Live && row.generation == identity.generation &&
        row.target != nullptr)
    {
        removed = true;
        target = row.target;
        row.target = nullptr;
        row.state = (row.generation == Process::kWin32ProcessHandleMaxGeneration)
                        ? Process::Win32ProcessHandleState::Retired
                        : Process::Win32ProcessHandleState::Free;
    }
    sync::SpinLockRelease(owner->win32_handle_lock, flags);

    if (target != nullptr)
    {
        ProcessRelease(target);
    }
    return removed;
}

u32 ProcessWin32ProcessHandleCount(const Process* owner)
{
    if (owner == nullptr)
    {
        return 0;
    }
    u32 count = 0;
    const sync::IrqFlags flags = sync::SpinLockAcquire(owner->win32_handle_lock);
    for (u64 i = 0; i < Process::kWin32ProcessCap; ++i)
    {
        if (owner->win32_proc_handles[i].state == Process::Win32ProcessHandleState::Live)
        {
            ++count;
        }
    }
    sync::SpinLockRelease(owner->win32_handle_lock, flags);
    return count;
}

void ProcessDropOwnedProcessHandles(Process* p)
{
    if (p == nullptr)
    {
        return;
    }
    Process* targets[Process::kWin32ProcessCap]{};
    u32 target_count = 0;
    {
        const sync::IrqFlags flags = sync::SpinLockAcquire(p->win32_handle_lock);
        for (u64 i = 0; i < Process::kWin32ProcessCap; ++i)
        {
            Process::Win32ProcessHandle& h = p->win32_proc_handles[i];
            if (h.state != Process::Win32ProcessHandleState::Live)
            {
                continue;
            }
            targets[target_count++] = h.target;
            h.target = nullptr;
            h.state = (h.generation == Process::kWin32ProcessHandleMaxGeneration)
                          ? Process::Win32ProcessHandleState::Retired
                          : Process::Win32ProcessHandleState::Free;
        }
        sync::SpinLockRelease(p->win32_handle_lock, flags);
    }

    // Drop refs after the entire table is detached and the slot lock is
    // released. A target may be `p` itself, or two targets may form an
    // A<->B cycle; no destructor can re-enter a half-cleared table.
    for (u32 i = 0; i < target_count; ++i)
    {
        if (targets[i] == p && __atomic_load_n(&p->refcount, __ATOMIC_ACQUIRE) == 0)
        {
            PanicWithValue("core/process", "zero-reference Process contained an impossible self-handle", p->pid);
        }
        ProcessRelease(targets[i]);
    }
}

namespace
{
void AdvanceLinuxChildEventLocked(Process* parent)
{
    (void)AdvanceStableEventSequenceLocked(&parent->linux_child_event_sequence);
}

void ClearLinuxChildRelationLocked(Process* parent, Process::LinuxChildRelation& relation)
{
    KASSERT(parent->linux_child_relation_count != 0, "core/process", "Linux child relation count underflow");
    relation = Process::LinuxChildRelation{};
    --parent->linux_child_relation_count;
    AdvanceLinuxChildEventLocked(parent);
}

void RollbackLinuxParentRelation(Process* child)
{
    Process* parent = child->linux_parent;
    if (parent == nullptr)
    {
        return;
    }

    ScopedProcessRuntimeAccess parent_runtime(parent);
    if (!parent_runtime)
    {
        // The parent has no live task that can observe this failed fork. Keep
        // its Exiting/Exited header inert and simply drop the child's strong
        // identity edge.
        child->linux_parent = nullptr;
        child->linux_parent_pid = 0;
        ProcessRelease(parent);
        return;
    }

    bool removed = false;
    {
        sync::SpinLockGuard child_guard(parent->linux_child_exit_lock);
        for (u64 i = 0; i < Process::kLinuxChildRelationCap; ++i)
        {
            Process::LinuxChildRelation& relation = parent->linux_child_relations[i];
            if (relation.state != Process::LinuxChildRelationState::Live || relation.exit.pid != child->pid)
            {
                continue;
            }
            ClearLinuxChildRelationLocked(parent, relation);
            removed = true;
            break;
        }
    }

    KASSERT(removed, "core/process", "Private child lost its registered parent relation");
    child->linux_parent = nullptr;
    child->linux_parent_pid = 0;
    parent_runtime.Unlock();

    // A sibling parent task may already be waiting on this Live row. Wake it
    // after the rollback is visible so it can rescan and return ECHILD.
    sched::WaitQueueWakeAll(&parent->linux_wait_wq);
    ProcessRelease(parent);
}

Process* QueueLinuxParentExit(Process* child)
{
    Process* parent = child->linux_parent;
    if (parent == nullptr)
    {
        return nullptr;
    }

    // A parent that has already entered Exiting has no task that can consume
    // status. Runtime admission shares the parent's VM transaction with the
    // reaper's Published -> Exiting transition, so success also proves the
    // relation row cannot become inert halfway through this update.
    ScopedProcessRuntimeAccess parent_runtime(parent);
    if (!parent_runtime)
    {
        child->linux_parent = nullptr;
        child->linux_parent_pid = 0;
        // No parent task can consume this row. It is header-local metadata and
        // contains no child pointer/reference, so leaving it untouched keeps
        // the Exiting/Exited parent inert; dropping the child's strong edge
        // below allows that header to be reclaimed normally.
        ProcessRelease(parent);
        return nullptr;
    }

    bool published = false;
    {
        sync::SpinLockGuard child_guard(parent->linux_child_exit_lock);
        for (u64 i = 0; i < Process::kLinuxChildRelationCap; ++i)
        {
            Process::LinuxChildRelation& relation = parent->linux_child_relations[i];
            if (relation.state != Process::LinuxChildRelationState::Live || relation.exit.pid != child->pid)
            {
                continue;
            }
            relation.exit.exit_code = child->linux_exit_code;
            relation.exit.was_signaled = child->linux_was_signaled;
            relation.exit.exit_signal = child->linux_exit_signal;
            relation.state = Process::LinuxChildRelationState::Exited;
            AdvanceLinuxChildEventLocked(parent);
            published = true;
            break;
        }
    }

    KASSERT(published, "core/process", "Exited child lost its registered parent relation");
    child->linux_parent = nullptr;
    return parent;
}

void TransferAcceptedServiceEndpointOwners(ProcessKey process)
{
    KASSERT(ProcessKeyIsValid(process), "core/process", "invalid ProcessKey during service endpoint teardown");

    // Transfer every exact accepted row in place before the generic handle
    // table can release a server endpoint KObject. The row's outer owner keeps
    // the boot-global endpoint slot and ChannelCore alive even if a peer is
    // NT-suspended while retaining an operation pin. This operation allocates
    // no second queue and has no Busy path: maintenance later retries the
    // exact generation-bearing rows from the scheduler reaper.
    const ServiceRuntimeDeferAcceptedProcessResultV1 deferred = ServiceRuntimeDeferAcceptedProcessKernelV1(process);
    if (deferred.runtime_status == ServiceRuntimeStatusV1::NotInitialized)
        return;
    if (deferred.runtime_status != ServiceRuntimeStatusV1::Ok)
    {
        PanicWithValue("core/process", "service runtime rejected Process endpoint ownership transfer",
                       static_cast<u64>(deferred.runtime_status));
    }
    if (deferred.directory_status != ServiceDirectoryStatus::Ok)
    {
        PanicWithValue("core/process", "service endpoint ownership transfer failed closed",
                       static_cast<u64>(deferred.directory_status));
    }
}

void TeardownProcessRuntimeResources(Process* p, bool observable_exit)
{
    KASSERT(p != nullptr, "core/process", "null Process runtime teardown");
    const ProcessLifecycleState lifecycle = ProcessLifecycleLoad(p);
    KASSERT((observable_exit && lifecycle == ProcessLifecycleState::Exiting) ||
                (!observable_exit && lifecycle == ProcessLifecycleState::Private),
            "core/process", "runtime teardown mode does not match lifecycle");
    KASSERT(p->as != nullptr, "core/process", "Process runtime teardown repeated after AS release");
    if (observable_exit)
        KBP_PROBE_V(::duetos::debug::ProbeId::kProcessDestroy, p->pid);

    // SchedCreateUser consumes the creator's Process reference even when task
    // allocation/publication fails. A pre-publication fork therefore reaches
    // this Private teardown path with a registered Live relation. Remove it,
    // advance the parent's event sequence, wake waiters, and release the
    // child's strong parent edge before reclaiming any other runtime state.
    if (!observable_exit)
        RollbackLinuxParentRelation(p);

    // Job member removal is scheduler-linearized with the exact last-Task
    // unlink before this unlocked teardown begins. Preserve the remaining
    // ordering: strong process-handle cycle breaking, then owner-Job
    // retirement, before GUI callbacks and address-space destruction.
    const ProcessKey process_key = ProcessKeySnapshot(p);

    // Completion receipts and accepted endpoint rows are both exact ProcessKey
    // authority. Retire ingress first, then transfer every accepted owner into
    // durable in-directory deferred state before any generic KObject handle can
    // release its raw ServiceEndpoint reference. The scheduler reaper drives
    // those strong owner rows outside this one-shot Process teardown, so a peer
    // suspended while holding an operation pin cannot wedge all Process exits.
    ServiceEndpointIngressCancelProcessKernel(process_key);
    TransferAcceptedServiceEndpointOwners(process_key);

    ProcessDropOwnedProcessHandles(p);
    if (observable_exit)
        JobDrainOwned(process_key);

    // A Private creator abort has never executed user code, so it cannot own
    // GUI, socket, or stdin-focus state. Avoid touching those potentially
    // uninitialized subsystems on early loader failure.
    if (observable_exit)
    {
        // Reap any windows this process registered but never DestroyWindow'd.
        // Walks the compositor registry under the compositor lock so it
        // serialises cleanly with input and UI workers.
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

        // These helpers run outside the compositor lock. TrackPopup takes its
        // own locks in tp_lock -> compositor order; GDI owns a separate pool.
        duetos::subsystems::win32::TrackPopupCancelByOwner(p->pid);
        duetos::subsystems::win32::GdiReapByOwner(p->pid);

        arch::SerialLineGuard guard;
        arch::SerialWrite("[proc] destroy pid=");
        arch::SerialWriteHex(p->pid);
        arch::SerialWrite(" name=\"");
        arch::SerialWrite(p->name);
        arch::SerialWrite("\"\n");
    }

    // Release any SysV SHM attachments still held. DoShmat takes a refcount
    // that only shmdt(2) dropped, so a process exiting while attached used to
    // strand the segment and its pool slot for the rest of the boot. Runs
    // before the AS goes away for ordering clarity, though the drain itself
    // does not touch p->as (SHM pages are borrowed, not AS-owned).
    ::duetos::subsystems::linux::internal::LinuxShmDrainProcess(p);

    // Atomically detach every Section handle and view row before touching the
    // global pool or this address space. The Published -> Exiting transition
    // was serialized by vm_transaction_lock, so admitted foreign Section
    // operations are finished and new operations fail before row access.
    Win32SectionDrainSnapshot section_drain{};
    DetachAllWin32SectionRows(p, &section_drain);

    // Exact view unmap must precede any release that could free its frames.
    // A mismatch leaves the view reference intact. Keep those exact keys in a
    // deferred list until the sole AS reference is released and its page
    // tables are destroyed, so a surviving PTE can never name freed frames.
    subsystems::win32::section::SectionKey deferred_view_releases[Process::kWin32SectionCap]{};
    u32 deferred_view_release_count = 0;
    for (u32 i = 0; i < section_drain.view_count; ++i)
    {
        const Process::Win32SectionViewClaim& view = section_drain.views[i];
        if (!subsystems::win32::section::SectionUnmapAndReleaseView(view.key, p->as, view.base_va))
        {
            deferred_view_releases[deferred_view_release_count++] = view.key;
        }
    }
    for (u32 i = 0; i < section_drain.handle_count; ++i)
    {
        subsystems::win32::section::SectionRelease(section_drain.handle_keys[i]);
    }

    // Drop the AS reference we took at create. Tasks retain Process rather
    // than its AddressSpace, so Process remains the sole AS owner even when
    // it has multiple tasks. The AS destroy path therefore runs inline:
    // user-half tables freed, backing frames returned, PML4 frame returned.
    const u64 section_teardown_as_refs = __atomic_load_n(&p->as->refcount.value, __ATOMIC_ACQUIRE);
    const bool as_will_destroy = section_teardown_as_refs == 1;
    if (!as_will_destroy && deferred_view_release_count != 0)
    {
        KLOG_CRITICAL_V("core/process", "shared AddressSpace during failed Section unmap; pinning deferred view refs",
                        section_teardown_as_refs);
    }
    KASSERT_WITH_VALUE(as_will_destroy, "core/process", "deferred Section release requires sole AddressSpace ownership",
                       section_teardown_as_refs);
    mm::AddressSpaceRelease(p->as);
    p->as = nullptr;

    // AddressSpaceRetain currently has no callers: Process owns the sole AS
    // reference, so the release above destroys every remaining PTE inline.
    // In an assertion-disabled future shared-AS build, fail safe by pinning
    // the deferred refs instead of freeing frames below surviving PTEs.
    if (as_will_destroy)
    {
        for (u32 i = 0; i < deferred_view_release_count; ++i)
        {
            subsystems::win32::section::SectionRelease(deferred_view_releases[i]);
        }
    }
    if (observable_exit)
        arch::SerialWrite("[proc] release: post-AS\n");

    // Emit the recorded diagnostic data to serial before the
    // state is freed. No-op when the process has no custom state
    // (non-Win32 native + Linux processes). For Win32 PEs the
    // observability tier is auto-on, so this fires for every Win32
    // PE exit and gives a post-mortem record without anyone having
    // to know the dump syscall exists.
    if (observable_exit)
    {
        subsystems::win32::custom::DumpExitDiagnostics(p);
        arch::SerialWrite("[proc] release: post-exit-diagnostics\n");
    }

    // Free the Win32 custom-diagnostics state if any was allocated.
    // No-op when the process never opted into any custom-Win32
    // feature (the common path).
    subsystems::win32::custom::CleanupProcess(p);
    if (observable_exit)
        arch::SerialWrite("[proc] release: post-CleanupProcess\n");

    // Close every Linux fd slot BEFORE the KObject drain below.
    //
    // The drain alone is not enough: it reclaims each fd's KFile
    // sidecar (pipe / eventfd / dirfd pool refs), but an fd slot
    // ALSO holds a reference on its shared open-file description
    // (`LinuxFd::ofd`), and nothing but `LinuxFdClose` drops that.
    // The OFD pool is kernel-wide and 64 slots deep, so an
    // unreleased reference is a machine-wide leak, not a per-
    // process one: every fork() retains one OFD ref per inherited
    // fd and every dup() retains one more, so a Linux guest that
    // forks with a few files open and exits permanently burns
    // those slots. Once all 64 are gone `OfdAllocLocked` returns 0
    // for the rest of the boot — dup() fails outright and fork()
    // silently degrades to unshared offsets.
    //
    // Running this BEFORE `HandleTableDrain` keeps KFile teardown
    // on its normal path (LinuxFdClose → HandleTableRemove →
    // KFileDestroy → per-pool release); the drain below then finds
    // those slots already empty and stays the belt-and-braces
    // sweep for handles that were never attached to an fd.
    for (u32 fd = 0; fd < 16; ++fd)
    {
        LinuxFdClose(p, fd);
    }

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
    if (observable_exit)
        arch::SerialWrite("[proc] release: post-HandleTableDrain\n");

    // Reclaim any kernel sockets this process left bound/open. Without
    // this, a networked process that exits (or crashes) leaks its pool
    // slot and leaves its listener port bound — which would make a
    // restart=Always service (e.g. netd) fail to re-bind on respawn
    // with EADDRINUSE. Kernel-owned sockets (owner_pid 0, e.g. DRSH)
    // are not touched.
    if (observable_exit)
        ::duetos::net::SocketReleaseByOwner(p->pid);

    // Close every Win32 file handle the process left open. Ramfs /
    // Fat32 / DuetFs / RamVol slots own nothing (a borrowed node or
    // an open-time snapshot), so this is only load-bearing for
    // FsBackingKind::Pipe slots — those hold a pipe-pool reference,
    // and `CloseForProcess` is the only code path that releases it
    // (plus NamedPipeOnServerClose for a server end). Without the
    // sweep, a Win32 PE that calls CreatePipe / CreateNamedPipe and
    // exits without CloseHandle permanently burns one of the 16
    // g_pipe_pool slots plus its 4 KiB buffer, and, for a server
    // end, a named-pipe registry slot.
    //
    // CloseForProcess is idempotent, clears the slot itself, takes
    // no reference on `p`, and wakes pipe waiters — all fine here:
    // Runtime teardown runs in reaper or creator-abort task context with
    // interrupts on, not in an IRQ handler.
    for (u32 slot = 0; slot < Process::kWin32HandleCap; ++slot)
    {
        u64 handle = 0;
        const sync::IrqFlags flags = sync::SpinLockAcquire(p->win32_file_lock);
        const Process::Win32FileHandle& row = p->win32_handles[slot];
        if (row.kind != Process::FsBackingKind::None && row.kind != Process::FsBackingKind::Reserved)
        {
            const Process::Win32FileHandleIdentity identity{slot, 0, row.generation};
            handle = EncodeWin32FileHandle(identity);
        }
        sync::SpinLockRelease(p->win32_file_lock, flags);

        // Close re-decodes and generation-checks the snapshot. If an impossible
        // late recycler raced this terminal drain, the old identity cannot
        // detach the new row.
        if (handle != 0)
            (void)fs::routing::CloseForProcess(p, handle);
    }

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

    if (observable_exit)
        arch::SerialWrite("[proc] release: post-win32_dirs\n");

    // Drop the stdin focus if this process held it. Without this,
    // kbd-reader would keep pushing into the freed ring's head
    // cursor and walking off the heap. No-op for processes that
    // never called SYS_STDIN_READ.
    if (observable_exit)
        StdinFocusClearIf(p);

    // Surface anything still attributable to this PID only after every normal
    // runtime drain above has completed. This callback may release diagnostic
    // GPU residue; it runs without any Process table or scheduler lock held.
    if (observable_exit)
        ::duetos::diag::LeakDetectorReportProcessExit(*p);

    // Every operation that could consult credentials or enforcement state has
    // now drained, including diagnostics and KObject/backend destruction.
    // Retire the exact security owners before the final resource-domain edge;
    // no Process header survives with live mutable authority after Exited.
    ReleaseProcessSecurityOwners(p, "security-owner final release failed");
    ReleaseProcessResourceDomainOwner(p, "resource-domain final release failed");

    if (observable_exit)
        arch::SerialWrite("[proc] release: done\n");
}
} // namespace

bool ProcessRegisterLinuxChildRelation(Process* parent, Process* child, u64 child_limit)
{
    if (parent == nullptr || child == nullptr || parent == child || child_limit == 0 ||
        ProcessLifecycleLoad(child) != ProcessLifecycleState::Private || child->linux_parent != nullptr)
    {
        return false;
    }

    // Retain before publishing the pointer into the Private child. Failure
    // drops this speculative edge only after the parent relation lock is free.
    ProcessRetain(parent);
    ScopedProcessRuntimeAccess parent_runtime(parent);
    if (!parent_runtime)
    {
        ProcessRelease(parent);
        return false;
    }
    bool registered = false;
    {
        sync::SpinLockGuard child_guard(parent->linux_child_exit_lock);
        // Revalidate the soft limit inside the same relation transaction that
        // serializes sibling fork admissions. A concurrent release-store from
        // setrlimit either linearizes before this acquire-load (and is honored)
        // or after this fork admission; lowering a limit never retroactively
        // invalidates an already-admitted child.
        const u64 latest_soft_limit = __atomic_load_n(&parent->linux_rlimit_nproc_cur, __ATOMIC_ACQUIRE);
        const u64 configured_limit = latest_soft_limit == ~u64(0) ? Process::kLinuxChildRelationCap : latest_soft_limit;
        const u64 snapshot_limit =
            child_limit < Process::kLinuxChildRelationCap ? child_limit : Process::kLinuxChildRelationCap;
        const u64 admission_limit = configured_limit < snapshot_limit ? configured_limit : snapshot_limit;
        if (parent->linux_child_relation_count < admission_limit)
        {
            for (u64 i = 0; i < Process::kLinuxChildRelationCap; ++i)
            {
                Process::LinuxChildRelation& relation = parent->linux_child_relations[i];
                if (relation.state != Process::LinuxChildRelationState::Free)
                {
                    KASSERT(relation.exit.pid != child->pid, "core/process", "duplicate Linux child relation PID");
                    continue;
                }

                relation.exit.pid = child->pid;
                relation.exit.exit_code = 0;
                relation.exit.exit_signal = 0;
                relation.exit.was_signaled = false;
                relation.state = Process::LinuxChildRelationState::Live;
                ++parent->linux_child_relation_count;
                child->linux_parent = parent;
                child->linux_parent_pid = parent->pid;
                AdvanceLinuxChildEventLocked(parent);
                registered = true;
                break;
            }
        }
    }
    parent_runtime.Unlock();

    if (!registered)
    {
        ProcessRelease(parent);
        return false;
    }

    // Registration changes exact-pid ECHILD answers for sibling waiters. The
    // wait queue is selector-shared, so wake all rather than risking that a
    // waiter for another PID consumes the sole wake.
    sched::WaitQueueWakeAll(&parent->linux_wait_wq);
    return true;
}

LinuxChildWaitResult ProcessPollLinuxChild(Process* parent, i64 target_pid, Process::LinuxChildExit* exit_out,
                                           u64* observed_sequence_out)
{
    KASSERT(parent != nullptr, "core/process", "ProcessPollLinuxChild null parent");
    KASSERT(exit_out != nullptr, "core/process", "ProcessPollLinuxChild null exit output");
    KASSERT(observed_sequence_out != nullptr, "core/process", "ProcessPollLinuxChild null sequence output");

    *exit_out = Process::LinuxChildExit{};
    *observed_sequence_out = 0;
    bool consumed = false;
    bool matching_relation = false;
    {
        sync::SpinLockGuard child_guard(parent->linux_child_exit_lock);
        for (u64 i = 0; i < Process::kLinuxChildRelationCap; ++i)
        {
            Process::LinuxChildRelation& relation = parent->linux_child_relations[i];
            if (relation.state == Process::LinuxChildRelationState::Free ||
                (target_pid > 0 && static_cast<i64>(relation.exit.pid) != target_pid))
            {
                continue;
            }

            matching_relation = true;
            if (relation.state != Process::LinuxChildRelationState::Exited)
            {
                continue;
            }

            *exit_out = relation.exit;
            ClearLinuxChildRelationLocked(parent, relation);
            consumed = true;
            break;
        }

        *observed_sequence_out = __atomic_load_n(&parent->linux_child_event_sequence, __ATOMIC_ACQUIRE);
    }

    if (consumed)
    {
        // Consumption can turn another waiter's answer into ECHILD. Publish
        // that relation-set change to every selector sharing this queue.
        sched::WaitQueueWakeAll(&parent->linux_wait_wq);
        return LinuxChildWaitResult::Exited;
    }
    return matching_relation ? LinuxChildWaitResult::Pending : LinuxChildWaitResult::NoMatchingChild;
}

sched::WaitQueueBlockResult ProcessWaitForLinuxChildEvent(Process* parent, u64 observed_sequence)
{
    KASSERT(parent != nullptr, "core/process", "ProcessWaitForLinuxChildEvent null parent");
    if (observed_sequence == ~u64{0})
        return sched::WaitQueueBlockTimeoutCancellable(&parent->linux_wait_wq, 1);
    return sched::WaitQueueBlockIfSequenceUnchangedCancellable(&parent->linux_wait_wq,
                                                               &parent->linux_child_event_sequence, observed_sequence);
}

void ProcessCompleteExitFromReaper(Process* process)
{
    KASSERT(process != nullptr, "core/process", "null Process exit completion");
    KASSERT(ProcessLifecycleLoad(process) == ProcessLifecycleState::Exiting, "core/process",
            "Process exit completion requires Exiting lifecycle");

    // These callbacks may release Process references, so the reaper's strong
    // pin is a precondition. No scheduler, runtime-admission, or table lock is
    // held across any callback or resource destructor.
    TeardownProcessRuntimeResources(process, true);

    // Publish the terminal lifecycle before making child status visible. A
    // parent already polling its queue must never observe a ready wait row
    // while the child's mutable runtime is still only Exiting.
    KASSERT(ProcessLifecycleTransition(process, ProcessLifecycleState::Exiting, ProcessLifecycleState::Exited),
            "core/process", "Process runtime teardown failed to publish Exited");
    __atomic_sub_fetch(&g_live_processes, 1, __ATOMIC_RELAXED);

    // The observer keeps only the immutable ProcessKey and durable scalar exit
    // result. Runtime teardown is complete, Exited is release-published, and
    // no scheduler or VM lock is held while its lower-ranked fixed-table lock
    // is acquired. Ordinary non-service Processes have no row and are benign.
    const ProcessKey exited_process = ProcessKeySnapshot(process);
    const u32 exit_code = ProcessWin32ExitCodeSnapshot(process);
    const ServiceExitObserverStatus exit_observer_status =
        ServiceExitObserverPublishKernelProcessExit(exited_process, exit_code);
    KASSERT(exit_observer_status == ServiceExitObserverStatus::Ok ||
                exit_observer_status == ServiceExitObserverStatus::NotFound ||
                exit_observer_status == ServiceExitObserverStatus::NotInitialized ||
                exit_observer_status == ServiceExitObserverStatus::Closed,
            "core/process", "Process exit observer rejected exact terminal publication");

    // The child retained this exact parent identity when its fixed relation
    // row was registered before scheduler publication. Transition that row in
    // place; there is no exit-time allocation or capacity failure.
    Process* parent_to_wake = QueueLinuxParentExit(process);

    if (parent_to_wake != nullptr)
    {
        // Waiters share one queue but can select different PIDs. WakeAll is
        // required: WakeOne could wake the wrong selector and strand the
        // waiter whose child actually exited.
        sched::WaitQueueWakeAll(&parent_to_wake->linux_wait_wq);
        ProcessRelease(parent_to_wake);
    }
    ::duetos::subsystems::linux::internal::LinuxPidfdExitWake();
}

void ProcessRelease(Process* p)
{
    if (p == nullptr)
        return;

    // Checked CAS decrement. A load-then-atomic-sub sequence still permits two
    // buggy releasers to both witness 1: one reaches zero while the other
    // underflows to UINT64_MAX on freed storage. Refuse zero inside the
    // transition loop so only an exact witnessed value can be decremented.
    // ACQ_REL publishes the decrement and makes the sole zero-transition owner
    // observe every field write released by prior holders before reclamation.
    u64 current = __atomic_load_n(&p->refcount, __ATOMIC_ACQUIRE);
    u64 new_count = 0;
    for (;;)
    {
        if (current == 0)
            PanicWithValue("core/process", "ProcessRelease on refcount==0", reinterpret_cast<u64>(p));
        new_count = current - 1;
        if (__atomic_compare_exchange_n(&p->refcount, &current, new_count, /*weak=*/false, __ATOMIC_ACQ_REL,
                                        __ATOMIC_ACQUIRE))
        {
            break;
        }
    }
    if (new_count != 0)
        return;

    const ProcessLifecycleState lifecycle = ProcessLifecycleLoad(p);
    if (lifecycle == ProcessLifecycleState::Private)
    {
        // A creator abort was never scheduler-visible: reclaim resources but
        // emit no Job, parent, pidfd, exit-diagnostic, or lifecycle event.
        TeardownProcessRuntimeResources(p, false);
        __atomic_sub_fetch(&g_live_processes, 1, __ATOMIC_RELAXED);
    }
    else if (lifecycle == ProcessLifecycleState::Exited)
    {
        // Runtime ownership ended at last-Task exit. Strong external handles
        // keep only stable identity metadata alive until this final release.
        KASSERT(p->as == nullptr, "core/process", "Exited Process retained a live address space");
        KASSERT(!ResourceDomainKeyIsValid(p->resource_domain), "core/process",
                "Exited Process retained a resource domain");
        KASSERT(!CredentialKeyIsValid(p->credentials), "core/process", "Exited Process retained credentials");
        KASSERT(!AuthorizationContextKeyIsValid(p->authorization), "core/process",
                "Exited Process retained authorization");
        KASSERT(p->linux_parent == nullptr, "core/process", "Exited Process retained a Linux parent reference");
    }
    else
    {
        PanicWithValue("core/process", "ProcessRelease reached zero outside a terminal lifecycle state",
                       static_cast<u64>(lifecycle));
    }

    mm::KFree(p);
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

u64 ProcessLinuxSignalPendingSnapshot(const Process* process)
{
    if (process == nullptr)
        return 0;
    return __atomic_load_n(&process->linux_pending_signals, __ATOMIC_ACQUIRE);
}

namespace
{

void WakeLinuxSignalReaders(Process* process)
{
    // WaitQueueWakeAll requires interrupts disabled, but callers include both
    // ordinary syscall context and trap-return paths. Preserve the incoming
    // IF state instead of unconditionally enabling interrupts on return.
    constexpr u64 kRflagsInterruptEnable = 1ULL << 9;
    const bool interrupts_were_enabled = (arch::ReadRflags() & kRflagsInterruptEnable) != 0;
    arch::Cli();
    sched::WaitQueueWakeAll(&process->linux_signal_wq);
    if (interrupts_were_enabled)
        arch::Sti();
}

} // namespace

bool ProcessLinuxSignalRaisePending(Process* process, u32 signum)
{
    const u64 bit = ProcessLinuxSignalBit(signum);
    if (process == nullptr || bit == 0)
        return false;
    __atomic_fetch_or(&process->linux_pending_signals, bit, __ATOMIC_RELEASE);
    AdvanceStableEventSequenceAtomic(&process->linux_signal_event_sequence);
    WakeLinuxSignalReaders(process);
    return true;
}

bool ProcessLinuxSignalClaimPending(Process* process, u32 signum)
{
    const u64 bit = ProcessLinuxSignalBit(signum);
    if (process == nullptr || bit == 0)
        return false;

    u64 observed = __atomic_load_n(&process->linux_pending_signals, __ATOMIC_ACQUIRE);
    while ((observed & bit) != 0)
    {
        const u64 desired = observed & ~bit;
        if (__atomic_compare_exchange_n(&process->linux_pending_signals, &observed, desired, false, __ATOMIC_ACQ_REL,
                                        __ATOMIC_ACQUIRE))
        {
            return true;
        }
    }
    return false;
}

void ProcessLinuxSignalRestorePending(Process* process, u64 signal_mask)
{
    if (process == nullptr || signal_mask == 0)
        return;
    __atomic_fetch_or(&process->linux_pending_signals, signal_mask, __ATOMIC_RELEASE);
    AdvanceStableEventSequenceAtomic(&process->linux_signal_event_sequence);
    WakeLinuxSignalReaders(process);
}

u64 ProcessLinuxSignalEventSequenceSnapshot(const Process* process)
{
    if (process == nullptr)
        return 0;
    return __atomic_load_n(&process->linux_signal_event_sequence, __ATOMIC_ACQUIRE);
}

void ProcessLinuxSignalNotifyWaiters(Process* process)
{
    if (process == nullptr)
        return;
    AdvanceStableEventSequenceAtomic(&process->linux_signal_event_sequence);
    WakeLinuxSignalReaders(process);
}

sched::WaitQueueBlockResult ProcessWaitForLinuxSignalEvent(Process* process, u64 observed_sequence)
{
    KASSERT(process != nullptr, "core/process", "ProcessWaitForLinuxSignalEvent null process");
    if (observed_sequence == ~u64{0})
        return sched::WaitQueueBlockTimeoutCancellable(&process->linux_signal_wq, 1);
    return sched::WaitQueueBlockIfSequenceUnchangedCancellable(
        &process->linux_signal_wq, &process->linux_signal_event_sequence, observed_sequence);
}

bool ProcessReserveMmapRange(Process* process, u64 size_bytes, u64* base_out)
{
    constexpr u64 kUserMaxExclusive = 0x0000800000000000ULL;
    if (process == nullptr || base_out == nullptr || size_bytes == 0 || (size_bytes & (mm::kPageSize - 1)) != 0)
    {
        return false;
    }
    *base_out = 0;
    const u64 limit = process->abi_flavor == kAbiLinux ? kUserMaxExclusive : Process::kCompatAutoVmLimit;
    u64 cursor = __atomic_load_n(&process->linux_mmap_cursor, __ATOMIC_ACQUIRE);
    for (;;)
    {
        if (cursor == 0 || (cursor & (mm::kPageSize - 1)) != 0 || cursor >= limit || size_bytes > (limit - cursor))
        {
            return false;
        }
        const u64 next = cursor + size_bytes;
        if (__atomic_compare_exchange_n(&process->linux_mmap_cursor, &cursor, next, /*weak=*/false, __ATOMIC_ACQ_REL,
                                        __ATOMIC_ACQUIRE))
        {
            *base_out = cursor;
            return true;
        }
    }
}

UserAbiWordStatus ProcessCopyUserAbiWordFrom(const Process* process, const void* user_src, u64* value_out)
{
    if (process == nullptr || user_src == nullptr || value_out == nullptr)
    {
        return UserAbiWordStatus::InvalidArgument;
    }
    *value_out = 0;
    if (process->user_is_pe32)
    {
        u32 value32 = 0;
        if (!mm::CopyFromUser(&value32, user_src, sizeof(value32)))
        {
            return UserAbiWordStatus::Fault;
        }
        *value_out = value32;
        return UserAbiWordStatus::Ok;
    }
    return mm::CopyFromUser(value_out, user_src, sizeof(*value_out)) ? UserAbiWordStatus::Ok : UserAbiWordStatus::Fault;
}

UserAbiWordStatus ProcessCopyUserAbiWordTo(const Process* process, void* user_dst, u64 value)
{
    if (process == nullptr || user_dst == nullptr)
    {
        return UserAbiWordStatus::InvalidArgument;
    }
    if (process->user_is_pe32)
    {
        if (value > static_cast<u64>(~0U))
        {
            return UserAbiWordStatus::ValueTooWide;
        }
        const u32 value32 = static_cast<u32>(value);
        return mm::CopyToUser(user_dst, &value32, sizeof(value32)) ? UserAbiWordStatus::Ok : UserAbiWordStatus::Fault;
    }
    return mm::CopyToUser(user_dst, &value, sizeof(value)) ? UserAbiWordStatus::Ok : UserAbiWordStatus::Fault;
}

u64 ProcessMmapCursorSnapshot(const Process* process)
{
    return process == nullptr ? 0 : __atomic_load_n(&process->linux_mmap_cursor, __ATOMIC_ACQUIRE);
}

ScopedProcessVmTransaction::ScopedProcessVmTransaction(Process* process) : m_process(process)
{
    KASSERT(m_process != nullptr, "core/process", "null Process VM transaction");
    sched::MutexLock(&m_process->vm_transaction_lock);
}

ScopedProcessVmTransaction::~ScopedProcessVmTransaction()
{
    Unlock();
}

void ScopedProcessVmTransaction::Unlock()
{
    if (m_process == nullptr)
        return;
    sched::MutexUnlock(&m_process->vm_transaction_lock);
    m_process = nullptr;
}

ScopedProcessRuntimeAccess::ScopedProcessRuntimeAccess(Process* process) : m_process(process)
{
    KASSERT(m_process != nullptr, "core/process", "null Process runtime admission");
    sched::MutexLock(&m_process->vm_transaction_lock);
    if (ProcessLifecycleLoad(m_process) != ProcessLifecycleState::Published || m_process->as == nullptr)
    {
        sched::MutexUnlock(&m_process->vm_transaction_lock);
        m_process = nullptr;
    }
}

ScopedProcessRuntimeAccess::~ScopedProcessRuntimeAccess()
{
    Unlock();
}

void ScopedProcessRuntimeAccess::Unlock()
{
    if (m_process == nullptr)
        return;
    sched::MutexUnlock(&m_process->vm_transaction_lock);
    m_process = nullptr;
}

u64 RecordSandboxDenial(Cap cap)
{
    sched::Task* t = sched::CurrentTask();
    if (t == nullptr)
    {
        return 0;
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
        return 0;
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
        return 0;
    }
    // AuthorizationContext serializes the cross-CPU increment and returns the
    // exact post-increment value plus the one-shot threshold action. Use that
    // single result for logging, journaling, and termination.
    const AuthorizationActionResult denial = AuthorizationRecordDenial(p->authorization);
    if (!denial.resolved)
    {
        KLOG_ONCE_WARN("proc", "RecordSandboxDenial: stale authorization owner; terminating fail-closed");
        sched::FlagCurrentForKill(sched::KillReason::SandboxDenialThreshold);
        return ~u64{0};
    }
    const u64 denials = denial.value;

    // Fire the sandbox-denial probe at the same rate-limit the
    // existing denial logger uses (first hit + every 32nd). Same
    // motivation: a ring-3 hostile task can otherwise flood the
    // probe log with thousands of identical lines per boot.
    if (ShouldLogDenial(denials))
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
        constexpr char prefix[] = "cap/";
        constexpr u64 kPrefixLen = sizeof(prefix) - 1;
        u64 pp = 0;
        while (pp < kPrefixLen && prefix[pp] != '\0')
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
            denials, /*severity=*/1);
    }

    // AuthorizationContext latches this action under its registry lock, so
    // exactly one CPU performs the threshold side effects.
    if (denial.action == AuthorizationAction::DenialThresholdExceeded)
    {
        arch::SerialWrite("[sandbox] pid=");
        arch::SerialWriteHex(p->pid);
        arch::SerialWrite(" hit ");
        arch::SerialWriteHex(kSandboxDenialKillThreshold);
        arch::SerialWrite(" denials (last cap=");
        arch::SerialWrite(CapName(cap));
        arch::SerialWrite(") — terminating as malicious\n");
        const u32 pid = static_cast<u32>(p->pid);
        ::duetos::security::EventRingPublishKind(::duetos::security::EventKind::SandboxDenialKill, pid,
                                                 static_cast<u64>(cap), denials, CapName(cap));
        ::duetos::security::IrRunbookEmit(::duetos::security::EventKind::SandboxDenialKill, pid);
        sched::FlagCurrentForKill(sched::KillReason::SandboxDenialThreshold);
    }
    return denials;
}

u64 ProcessLiveCount()
{
    return __atomic_load_n(&g_live_processes, __ATOMIC_RELAXED);
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
    const AuthorizationActionResult result =
        AuthorizationRecordFsWrite(p->authorization, ::duetos::time::TickCount(), bytes);
    if (!result.resolved)
    {
        KLOG_ONCE_WARN("proc", "RecordFsWrite: stale authorization owner; terminating fail-closed");
        return 0;
    }
    if (result.fs_write_window != kAuthorizationNoFsWriteWindow)
        return static_cast<i32>(result.fs_write_window);
    // Overflow and a regressing accounting clock are fail-closed even when no
    // ordinary rate window is the direct cause.
    return result.action == AuthorizationAction::FsWriteRateExceeded ? 0 : -1;
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
    AuthorizationContextSnapshot authorization{};
    const bool have_snapshot = ProcessInspectAuthorization(p, &authorization);
    const u64 window_bytes = have_snapshot && static_cast<u32>(lvl) < kAuthorizationFsWriteWindowCount
                                 ? authorization.fs_write_window_bytes[static_cast<u32>(lvl)]
                                 : ~u64{0};
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
    arch::SerialWriteHex(window_bytes);
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
        ::duetos::security::EventRingPublishKind(kind, pid, window_bytes, static_cast<u64>(lvl),
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
    case kCapSchedPriority:
        return "SchedPriority";
    case kCapPowerTune:
        return "PowerTune";
    case kCapServiceControl:
        return "ServiceControl";
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
    while (i < sizeof(trimmed) - 1 && dll_name[i] != '\0')
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
        while (oi < sizeof(other) - 1 && name[oi] != '\0')
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
    Expect(StrEqual(CapName(kCapSchedPriority), "SchedPriority"), "CapName(SchedPriority)");
    Expect(StrEqual(CapName(kCapPowerTune), "PowerTune"), "CapName(PowerTune)");
    Expect(StrEqual(CapName(kCapServiceControl), "ServiceControl"), "CapName(ServiceControl)");
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

void ProcessHandleLifetimeSelfTest()
{
    // This fixture needs KMalloc and therefore runs in the Heap initcall
    // phase, unlike the pure-helper ProcessSelfTest above. The target begins
    // with one base reference plus exactly one caller-owned reference for
    // every handle transferred into the table. Closing a slot and releasing
    // a retained lookup must return precisely to the base reference.
    auto* owner = static_cast<Process*>(mm::KMalloc(sizeof(Process)));
    auto* target = static_cast<Process*>(mm::KMalloc(sizeof(Process)));
    Expect(owner != nullptr && target != nullptr, "process-handle fixtures allocated");
    memset(owner, 0, sizeof(Process));
    memset(target, 0, sizeof(Process));
    target->refcount = Process::kWin32ProcessCap + 2;

    constexpr u64 kMmapFixtureBase = 0x0000700000000000ULL;
    owner->abi_flavor = kAbiLinux;
    owner->linux_mmap_cursor = kMmapFixtureBase; // fixture is not published
    u64 first_mmap_base = 0;
    u64 second_mmap_base = 0;
    Expect(ProcessMmapCursorSnapshot(owner) == kMmapFixtureBase, "mmap cursor snapshot is exact");
    Expect(ProcessReserveMmapRange(owner, mm::kPageSize, &first_mmap_base) && first_mmap_base == kMmapFixtureBase,
           "first mmap range reservation starts at cursor");
    Expect(ProcessReserveMmapRange(owner, 2 * mm::kPageSize, &second_mmap_base) &&
               second_mmap_base == kMmapFixtureBase + mm::kPageSize,
           "second mmap range reservation is disjoint");
    Expect(!ProcessReserveMmapRange(owner, 0, &second_mmap_base), "zero-length mmap reservation rejected");
    Expect(!ProcessReserveMmapRange(owner, mm::kPageSize + 1, &second_mmap_base),
           "unaligned mmap reservation rejected");
    __atomic_store_n(&owner->linux_mmap_cursor, 0x00007FFFFFFFF000ULL, __ATOMIC_RELEASE);
    Expect(ProcessReserveMmapRange(owner, mm::kPageSize, &second_mmap_base),
           "terminal user page can be reserved exactly once");
    Expect(!ProcessReserveMmapRange(owner, mm::kPageSize, &second_mmap_base),
           "mmap cursor cannot cross into kernel half");

    owner->abi_flavor = kAbiNative;
    __atomic_store_n(&owner->linux_mmap_cursor, 0, __ATOMIC_RELEASE);
    Expect(!ProcessReserveMmapRange(owner, mm::kPageSize, &second_mmap_base),
           "automatic VM reservation never returns page zero");
    __atomic_store_n(&owner->linux_mmap_cursor, Process::kCompatAutoVmBase, __ATOMIC_RELEASE);
    Expect(ProcessReserveMmapRange(owner, mm::kPageSize, &second_mmap_base) &&
               second_mmap_base == Process::kCompatAutoVmBase,
           "native automatic VM reservation starts in the PE32-safe arena");
    __atomic_store_n(&owner->linux_mmap_cursor, Process::kCompatAutoVmLimit - mm::kPageSize, __ATOMIC_RELEASE);
    Expect(ProcessReserveMmapRange(owner, mm::kPageSize, &second_mmap_base) &&
               second_mmap_base == Process::kCompatAutoVmLimit - mm::kPageSize,
           "terminal PE32-safe automatic VM page can be reserved once");
    Expect(!ProcessReserveMmapRange(owner, mm::kPageSize, &second_mmap_base),
           "native automatic VM cursor cannot cross the PE32-safe arena");

    // Process handles retain the 0x700..0x707 low-tag dispatch band while
    // carrying a non-zero generation in bits 12..30. Legacy slot-only and
    // PE32-negative values are malformed before any table access.
    Process::Win32ProcessHandleIdentity decoded_process{};
    Expect(!IsWin32ProcessHandle(Process::kWin32ProcessBase), "legacy slot-only Process handle rejected");
    Expect(!DecodeWin32ProcessHandle(Process::kWin32ProcessBase, &decoded_process),
           "legacy Process handle cannot be decoded");
    Expect(!IsWin32ProcessHandle((1ULL << 63) | (1ULL << Process::kWin32ProcessHandleGenerationShift) |
                                 Process::kWin32ProcessBase),
           "negative Process handle rejected");
    Expect(!IsWin32ProcessHandle((1ULL << 31) | (1ULL << Process::kWin32ProcessHandleGenerationShift) |
                                 Process::kWin32ProcessBase),
           "PE32-negative Process handle rejected");
    Expect(EncodeWin32ProcessHandle(Process::Win32ProcessHandleIdentity{0, 0}) == 0,
           "zero Process generation cannot encode");
    Expect(EncodeWin32ProcessHandle(
               Process::Win32ProcessHandleIdentity{static_cast<u32>(Process::kWin32ProcessCap), 1}) == 0,
           "out-of-range Process slot cannot encode");
    Expect(EncodeWin32ProcessHandle(Process::Win32ProcessHandleIdentity{
               0, static_cast<u32>(Process::kWin32ProcessHandleMaxGeneration + 1)}) == 0,
           "overflow Process generation cannot encode");
    const u64 terminal_process_encoding = EncodeWin32ProcessHandle(
        Process::Win32ProcessHandleIdentity{0, static_cast<u32>(Process::kWin32ProcessHandleMaxGeneration)});
    Expect(terminal_process_encoding != 0 && terminal_process_encoding <= Process::kWin32ProcessHandleMaxValue,
           "terminal Process generation remains PE32-positive");
    Expect(DecodeWin32ProcessHandle(terminal_process_encoding, &decoded_process) && decoded_process.slot == 0 &&
               decoded_process.generation == Process::kWin32ProcessHandleMaxGeneration,
           "terminal Process identity round-trips exactly");

    u64 handles[Process::kWin32ProcessCap]{};
    for (u32 i = 0; i < Process::kWin32ProcessCap; ++i)
    {
        handles[i] = ProcessInstallWin32ProcessHandle(owner, target);
        Expect(DecodeWin32ProcessHandle(handles[i], &decoded_process) && decoded_process.slot == i &&
                   decoded_process.generation == 1,
               "process-handle slot publication carries generation one");
    }
    Expect(ProcessWin32ProcessHandleCount(owner) == Process::kWin32ProcessCap, "process-handle count at capacity");
    Expect(ProcessInstallWin32ProcessHandle(owner, target) == 0, "process-handle saturation refused");
    Expect(__atomic_load_n(&target->refcount, __ATOMIC_ACQUIRE) == Process::kWin32ProcessCap + 2,
           "failed process-handle install preserves caller ownership");
    ProcessRelease(target); // drop the unadopted saturation-attempt ref

    const u64 first_process_handle = handles[0];
    Process* pinned = ProcessLookupWin32ProcessHandleRetained(owner, first_process_handle);
    Expect(pinned == target, "process-handle retained lookup");
    Expect(__atomic_load_n(&target->refcount, __ATOMIC_ACQUIRE) == Process::kWin32ProcessCap + 2,
           "process-handle lookup increments refcount");
    Expect(ProcessCloseWin32ProcessHandle(owner, first_process_handle), "process-handle close succeeds once");

    ProcessRetain(target); // next successful install transfers this exact ref
    const u64 second_process_handle = ProcessInstallWin32ProcessHandle(owner, target);
    Expect(second_process_handle != first_process_handle, "same-slot reuse advances the public Process identity");
    Expect(DecodeWin32ProcessHandle(second_process_handle, &decoded_process) && decoded_process.slot == 0 &&
               decoded_process.generation == 2,
           "same-slot Process reuse advances the row generation");
    Expect(ProcessLookupWin32ProcessHandleRetained(owner, first_process_handle) == nullptr,
           "stale Process handle cannot resolve a recycled row");
    Expect(!ProcessCloseWin32ProcessHandle(owner, first_process_handle),
           "stale Process close cannot detach a recycled row");
    ProcessRelease(pinned);

    ProcessDropOwnedProcessHandles(owner);
    ProcessDropOwnedProcessHandles(owner);
    Expect(ProcessWin32ProcessHandleCount(owner) == 0, "process-handle drain is idempotent");
    Expect(ProcessLookupWin32ProcessHandleRetained(owner, second_process_handle) == nullptr,
           "drained Process handle cannot be looked up");
    Expect(__atomic_load_n(&target->refcount, __ATOMIC_ACQUIRE) == 1, "process-handle references balance after drain");

    // Force one row to its final publishable generation and every other row
    // retired so allocation cannot choose a different slot.
    const sync::IrqFlags process_flags = sync::SpinLockAcquire(owner->win32_handle_lock);
    for (u32 slot = 0; slot < Process::kWin32ProcessCap; ++slot)
    {
        owner->win32_proc_handles[slot].generation = Process::kWin32ProcessHandleMaxGeneration;
        owner->win32_proc_handles[slot].state = Process::Win32ProcessHandleState::Retired;
        owner->win32_proc_handles[slot].target = nullptr;
    }
    owner->win32_proc_handles[0].generation = Process::kWin32ProcessHandleMaxGeneration - 1;
    owner->win32_proc_handles[0].state = Process::Win32ProcessHandleState::Free;
    sync::SpinLockRelease(owner->win32_handle_lock, process_flags);

    ProcessRetain(target);
    const u64 final_process_handle = ProcessInstallWin32ProcessHandle(owner, target);
    Expect(DecodeWin32ProcessHandle(final_process_handle, &decoded_process) && decoded_process.slot == 0 &&
               decoded_process.generation == Process::kWin32ProcessHandleMaxGeneration,
           "terminal Process row publishes exactly once");
    Expect(ProcessCloseWin32ProcessHandle(owner, final_process_handle), "terminal Process row closes once");
    const sync::IrqFlags retired_flags = sync::SpinLockAcquire(owner->win32_handle_lock);
    const Process::Win32ProcessHandleState retired_state = owner->win32_proc_handles[0].state;
    sync::SpinLockRelease(owner->win32_handle_lock, retired_flags);
    Expect(retired_state == Process::Win32ProcessHandleState::Retired,
           "terminal Process generation retires instead of wrapping");
    Expect(ProcessInstallWin32ProcessHandle(owner, target) == 0, "retired Process rows cannot be reused");

    // File handles retain their low 0x100..0x10F tag for dispatch, but the
    // public value must carry a non-zero generation in bits 12..30. The old
    // slot-only ABI and every negative pseudo-handle are therefore malformed.
    Process::Win32FileHandleIdentity decoded{};
    Expect(!IsWin32FileHandle(Process::kWin32HandleBase), "legacy slot-only file handle rejected");
    Expect(!DecodeWin32FileHandle(Process::kWin32HandleBase, &decoded), "legacy file handle cannot be decoded");
    Expect(!IsWin32FileHandle((1ULL << 63) | (1ULL << Process::kWin32FileHandleGenerationShift) |
                              Process::kWin32HandleBase),
           "negative file handle rejected");
    Expect(!IsWin32FileHandle((1ULL << 31) | (1ULL << Process::kWin32FileHandleGenerationShift) |
                              Process::kWin32HandleBase),
           "PE32-negative file handle rejected");
    Expect(EncodeWin32FileHandle(Process::Win32FileHandleIdentity{0, 0, 0}) == 0, "zero file generation cannot encode");
    Expect(EncodeWin32FileHandle(Process::Win32FileHandleIdentity{static_cast<u32>(Process::kWin32HandleCap), 0, 1}) ==
               0,
           "out-of-range file slot cannot encode");
    Expect(EncodeWin32FileHandle(Process::Win32FileHandleIdentity{0, 0, Process::kWin32FileHandleMaxGeneration + 1}) ==
               0,
           "overflow file generation cannot encode");
    const u64 terminal_file_handle =
        EncodeWin32FileHandle(Process::Win32FileHandleIdentity{0, 0, Process::kWin32FileHandleMaxGeneration});
    Expect(terminal_file_handle != 0 && terminal_file_handle <= Process::kWin32FileHandleMaxValue,
           "terminal file generation remains PE32-positive");
    Expect(DecodeWin32FileHandle(terminal_file_handle, &decoded) &&
               decoded.generation == Process::kWin32FileHandleMaxGeneration,
           "terminal file generation round-trips exactly");

    Process::Win32FileReservation first_reservation{};
    Expect(ProcessReserveWin32FileHandle(owner, &first_reservation), "first file row reserved");
    Process::Win32FileHandle candidate{};
    candidate.kind = Process::FsBackingKind::Ramfs;
    candidate.named_pipe_registry_slot = -1;
    u64 first_file_handle = 0;
    Expect(ProcessPublishWin32FileHandle(owner, first_reservation, candidate, &first_file_handle),
           "first file row published");
    Expect(IsWin32FileHandle(first_file_handle), "published file handle has valid opaque encoding");
    Expect((first_file_handle & (1ULL << 63)) == 0, "published file handle remains positive");
    Expect(DecodeWin32FileHandle(first_file_handle, &decoded), "published file handle decodes");
    Expect(decoded.slot == first_reservation.slot && decoded.generation == first_reservation.generation,
           "decoded file identity matches reservation");
    Expect((first_file_handle & Process::kWin32FileHandleTagMask) == Process::kWin32HandleBase + first_reservation.slot,
           "published file handle preserves low tag band");
    Expect(ProcessWin32FileHandleCount(owner) == 1, "published file handle counted once");

    Process::Win32FileHandle detached{};
    Expect(!ProcessDetachWin32FileHandle(owner, Process::kWin32HandleBase, &detached),
           "legacy file handle cannot detach a live row");
    Expect(ProcessDetachWin32FileHandle(owner, first_file_handle, &detached), "exact first file identity detaches");
    Expect(detached.generation == first_reservation.generation, "detached first file identity preserved");
    Expect(ProcessWin32FileHandleCount(owner) == 0, "detached file row no longer counted");

    Process::Win32FileReservation second_reservation{};
    Expect(ProcessReserveWin32FileHandle(owner, &second_reservation), "recycled file row reserved");
    Expect(second_reservation.slot == first_reservation.slot &&
               second_reservation.generation == first_reservation.generation + 1,
           "recycled file row advances generation");
    u64 second_file_handle = 0;
    Expect(ProcessPublishWin32FileHandle(owner, second_reservation, candidate, &second_file_handle),
           "recycled file row published");
    Expect(second_file_handle != first_file_handle, "recycled file handle has distinct identity");
    Expect((second_file_handle & Process::kWin32FileHandleTagMask) ==
               (first_file_handle & Process::kWin32FileHandleTagMask),
           "recycled file handle retains its slot tag");
    Expect(!ProcessDetachWin32FileHandle(owner, first_file_handle, &detached),
           "stale file handle cannot detach recycled row");
    Expect(ProcessWin32FileHandleCount(owner) == 1, "stale close leaves recycled row live");
    Expect(ProcessDetachWin32FileHandle(owner, second_file_handle, &detached), "exact recycled file identity detaches");

    const sync::IrqFlags file_flags = sync::SpinLockAcquire(owner->win32_file_lock);
    for (u32 slot = 0; slot < Process::kWin32HandleCap; ++slot)
    {
        Process::Win32FileHandle saturated{};
        saturated.generation = Process::kWin32FileHandleMaxGeneration;
        saturated.kind = Process::FsBackingKind::None;
        saturated.named_pipe_registry_slot = -1;
        owner->win32_handles[slot] = saturated;
    }
    sync::SpinLockRelease(owner->win32_file_lock, file_flags);
    Process::Win32FileReservation saturated_reservation{};
    Expect(!ProcessReserveWin32FileHandle(owner, &saturated_reservation),
           "saturated file generations are never reused");

    // Section handles use the same positive PE32-safe shape, with the
    // 0x900..0x907 low tag and an independent process-row generation.
    Process::Win32SectionHandleIdentity decoded_section{};
    Expect(!IsWin32SectionHandle(Process::kWin32SectionBase), "legacy slot-only Section handle rejected");
    Expect(!DecodeWin32SectionHandle(Process::kWin32SectionBase, &decoded_section),
           "legacy Section handle cannot be decoded");
    Expect(!IsWin32SectionHandle((1ULL << 63) | (1ULL << Process::kWin32SectionHandleGenerationShift) |
                                 Process::kWin32SectionBase),
           "negative Section handle rejected");
    Expect(!IsWin32SectionHandle((1ULL << 31) | (1ULL << Process::kWin32SectionHandleGenerationShift) |
                                 Process::kWin32SectionBase),
           "PE32-negative Section handle rejected");
    Expect(EncodeWin32SectionHandle(Process::Win32SectionHandleIdentity{0, 0}) == 0,
           "zero Section generation cannot encode");
    Expect(EncodeWin32SectionHandle(
               Process::Win32SectionHandleIdentity{static_cast<u32>(Process::kWin32SectionCap), 1}) == 0,
           "out-of-range Section slot cannot encode");
    Expect(EncodeWin32SectionHandle(
               Process::Win32SectionHandleIdentity{0, Process::kWin32SectionHandleMaxGeneration + 1}) == 0,
           "overflow Section generation cannot encode");
    const u64 terminal_section_handle =
        EncodeWin32SectionHandle(Process::Win32SectionHandleIdentity{0, Process::kWin32SectionHandleMaxGeneration});
    Expect(terminal_section_handle != 0 && terminal_section_handle <= Process::kWin32SectionHandleMaxValue,
           "terminal Section generation remains PE32-positive");
    Expect(DecodeWin32SectionHandle(terminal_section_handle, &decoded_section) &&
               decoded_section.generation == Process::kWin32SectionHandleMaxGeneration,
           "terminal Section generation round-trips exactly");

    ResourceDomainKey section_test_domain = kInvalidResourceDomainKey;
    Expect(ResourceDomainCreateTrusted(&section_test_domain), "Section selftest resource domain created");

    Process::Win32SectionHandleReservation first_section_reservation{};
    Expect(ProcessReserveWin32SectionHandle(owner, &first_section_reservation), "first Section row reserved");
    subsystems::win32::section::SectionKey first_section_key{};
    Expect(subsystems::win32::section::SectionCreate(section_test_domain, mm::kPageSize, 0x04, &first_section_key),
           "first Section pool identity created");
    u64 first_section_handle = 0;
    Expect(ProcessPublishWin32SectionHandle(owner, first_section_reservation, first_section_key, &first_section_handle),
           "first Section row published");
    Expect(IsWin32SectionHandle(first_section_handle), "published Section handle has opaque encoding");
    Expect(DecodeWin32SectionHandle(first_section_handle, &decoded_section) &&
               decoded_section.slot == first_section_reservation.slot &&
               decoded_section.generation == first_section_reservation.generation,
           "published Section handle decodes to exact row identity");
    Expect(ProcessWin32SectionHandleCount(owner) == 1, "published Section handle counted once");

    subsystems::win32::section::SectionKey first_operation_key{};
    Expect(ProcessAcquireWin32SectionHandle(owner, first_section_handle, &first_operation_key) &&
               first_operation_key == first_section_key,
           "Section handle acquire pins exact pool generation");
    subsystems::win32::section::SectionKey detached_section_key{};
    Expect(!ProcessDetachWin32SectionHandle(owner, Process::kWin32SectionBase, &detached_section_key),
           "legacy Section handle cannot detach live row");
    Expect(ProcessDetachWin32SectionHandle(owner, first_section_handle, &detached_section_key) &&
               detached_section_key == first_section_key,
           "exact first Section identity detaches");
    subsystems::win32::section::SectionRelease(detached_section_key);
    Expect(subsystems::win32::section::SectionViewSize(first_operation_key) == mm::kPageSize,
           "operation pin keeps detached Section generation alive");
    subsystems::win32::section::SectionRelease(first_operation_key);
    Expect(subsystems::win32::section::SectionViewSize(first_section_key) == 0,
           "Section handle and operation references balance after close");

    Process::Win32SectionHandleReservation second_section_reservation{};
    Expect(ProcessReserveWin32SectionHandle(owner, &second_section_reservation), "recycled Section row reserved");
    Expect(second_section_reservation.slot == first_section_reservation.slot &&
               second_section_reservation.generation == first_section_reservation.generation + 1,
           "recycled Section row advances generation");
    subsystems::win32::section::SectionKey second_section_key{};
    Expect(subsystems::win32::section::SectionCreate(section_test_domain, mm::kPageSize, 0x04, &second_section_key),
           "recycled Section pool identity created");
    u64 second_section_handle = 0;
    Expect(
        ProcessPublishWin32SectionHandle(owner, second_section_reservation, second_section_key, &second_section_handle),
        "recycled Section row published");
    Expect(second_section_handle != first_section_handle, "same-slot Section reuse publishes a distinct generation");
    Expect(!ProcessAcquireWin32SectionHandle(owner, first_section_handle, &first_operation_key),
           "stale Section handle cannot pin recycled row");
    Expect(!ProcessDetachWin32SectionHandle(owner, first_section_handle, &detached_section_key),
           "stale Section close cannot detach recycled row");

    const u32 foreign_generation = second_section_reservation.generation + 1;
    const u64 foreign_section_handle = EncodeWin32SectionHandle(
        Process::Win32SectionHandleIdentity{second_section_reservation.slot, foreign_generation});
    Expect(foreign_section_handle != 0 && IsWin32SectionHandle(foreign_section_handle),
           "foreign-generation Section handle is structurally valid");
    Expect(!ProcessAcquireWin32SectionHandle(owner, foreign_section_handle, &first_operation_key),
           "foreign-generation Section handle cannot pin live row");
    Expect(!ProcessDetachWin32SectionHandle(owner, foreign_section_handle, &detached_section_key),
           "foreign-generation Section close cannot detach live row");
    subsystems::win32::section::SectionRelease(first_section_key);
    Expect(subsystems::win32::section::SectionViewSize(second_section_key) == mm::kPageSize,
           "stale pool-key release cannot damage recycled Section");

    // Exercise the view-row token machine with one explicit simulated view
    // reference. Claim is exclusive, Restore returns ownership to the row,
    // and Finish follows consumption of exactly that one reference.
    Expect(!ProcessHasBorrowedUserMappings(owner), "fresh process has no borrowed user mappings");
    Expect(subsystems::win32::section::SectionRetain(second_section_key), "simulated Section view reference retained");
    Process::Win32SectionViewReservation view_reservation{};
    Expect(ProcessReserveWin32SectionView(owner, &view_reservation), "Section view row reserved");
    Expect(ProcessHasBorrowedUserMappings(owner), "reserved Section view fails exec admission closed");
    constexpr u64 kTestSectionViewBase = 0x0000000054000000ULL;
    Expect(ProcessPublishWin32SectionView(owner, view_reservation, second_section_key, kTestSectionViewBase),
           "Section view row published");
    Expect(ProcessWin32SectionViewCount(owner) == 1, "published Section view counted once");
    Process::Win32SectionViewClaim view_claim{};
    Expect(ProcessClaimWin32SectionViewExact(owner, view_reservation, second_section_key, kTestSectionViewBase,
                                             &view_claim),
           "Section view claimed by exact publication identity");
    Process::Win32SectionViewClaim duplicate_view_claim{};
    Expect(!ProcessClaimWin32SectionViewExact(owner, view_reservation, second_section_key, kTestSectionViewBase,
                                              &duplicate_view_claim),
           "claimed Section view cannot be double-claimed");
    Expect(ProcessRestoreWin32SectionView(owner, view_claim), "failed-unmap token restores Section view");
    Expect(ProcessClaimWin32SectionView(owner, kTestSectionViewBase, &view_claim),
           "restored Section view can be claimed by normal unmap");
    subsystems::win32::section::SectionRelease(second_section_key); // simulated successful exact unmap
    Expect(ProcessFinishWin32SectionView(owner, view_claim), "successful-unmap token finishes Section view");
    Expect(!ProcessRestoreWin32SectionView(owner, view_claim), "finished Section view token cannot restore");
    Expect(ProcessWin32SectionViewCount(owner) == 0, "finished Section view no longer counted");
    Expect(!ProcessHasBorrowedUserMappings(owner), "finished Section view reopens exec admission");

    // Reuse the same row and VA, then prove a delayed rollback carrying the
    // first publication token cannot claim or unmap the newer view.
    Expect(subsystems::win32::section::SectionRetain(second_section_key),
           "recycled simulated Section view reference retained");
    Process::Win32SectionViewReservation recycled_view_reservation{};
    Expect(ProcessReserveWin32SectionView(owner, &recycled_view_reservation), "recycled Section view row reserved");
    Expect(recycled_view_reservation.slot == view_reservation.slot &&
               recycled_view_reservation.generation == view_reservation.generation + 1,
           "recycled Section view row advances generation");
    Expect(ProcessPublishWin32SectionView(owner, recycled_view_reservation, second_section_key, kTestSectionViewBase),
           "same-base recycled Section view published");
    Expect(!ProcessClaimWin32SectionViewExact(owner, view_reservation, second_section_key, kTestSectionViewBase,
                                              &duplicate_view_claim),
           "stale exact rollback token cannot claim same-base recycled view");
    Expect(ProcessWin32SectionViewCount(owner) == 1, "stale exact rollback leaves recycled view live");
    Expect(ProcessClaimWin32SectionViewExact(owner, recycled_view_reservation, second_section_key, kTestSectionViewBase,
                                             &view_claim),
           "recycled Section view accepts exact current token");
    subsystems::win32::section::SectionRelease(second_section_key); // simulated successful exact unmap
    Expect(ProcessFinishWin32SectionView(owner, view_claim), "recycled Section view finishes once");
    Expect(ProcessWin32SectionViewCount(owner) == 0, "recycled Section view no longer counted");
    Expect(!ProcessHasBorrowedUserMappings(owner), "recycled Section teardown clears borrowed-map gate");

    owner->linux_shm_attaches[0].in_use = true;
    owner->linux_shm_attaches[0].shmid = 1;
    owner->linux_shm_attaches[0].base_va = Process::kLinuxShmArenaBase;
    owner->linux_shm_attaches[0].page_count = 1;
    Expect(ProcessHasBorrowedUserMappings(owner), "live SysV SHM attachment blocks exec admission");
    owner->linux_shm_attaches[0] = Process::LinuxShmAttach{};
    Expect(!ProcessHasBorrowedUserMappings(owner), "SysV SHM detach reopens exec admission");

    Expect(ProcessDetachWin32SectionHandle(owner, second_section_handle, &detached_section_key) &&
               detached_section_key == second_section_key,
           "exact recycled Section identity detaches");
    subsystems::win32::section::SectionRelease(detached_section_key);
    Expect(subsystems::win32::section::SectionViewSize(second_section_key) == 0,
           "recycled Section references balance after close");

    const sync::IrqFlags section_flags = sync::SpinLockAcquire(owner->win32_section_lock);
    for (u32 slot = 0; slot < Process::kWin32SectionCap; ++slot)
    {
        owner->win32_section_handles[slot].generation = Process::kWin32SectionHandleMaxGeneration;
        owner->win32_section_handles[slot].state = Process::Win32SectionHandleState::Free;
        owner->win32_section_handles[slot].key = subsystems::win32::section::kInvalidSectionKey;
    }
    sync::SpinLockRelease(owner->win32_section_lock, section_flags);
    Process::Win32SectionHandleReservation saturated_section_reservation{};
    Expect(!ProcessReserveWin32SectionHandle(owner, &saturated_section_reservation),
           "saturated Section row generations are never reused");

    Expect(ResourceDomainRelease(section_test_domain), "Section selftest resource domain released");

    mm::KFree(target);
    mm::KFree(owner);
    arch::SerialWrite("[process-handle-selftest] PASS (process + opaque file + Section lifetime)\n");
}

// ---------------------------------------------------------------
// Stdin ring buffer — per-process keyboard input pipe.
//
// Producer: kbd-reader thread in core/main.cpp. Consumers are ring-3 tasks in
// SYS_STDIN_READ. A per-ring spinlock protects the bytes and both cursors; an
// atomic event sequence closes the otherwise racy empty-check/waiter-enqueue
// window without nesting the scheduler lock under the ring lock.
//
// Overflow policy: when full, drop exactly the oldest byte before inserting
// the new byte. This preserves the newest kCap bytes and avoids back-pressure
// from a wedged reader into the keyboard input path.
// ---------------------------------------------------------------

namespace
{

// Single-process stdin focus. The pointer is protected by this lock and owns
// exactly one Process reference while non-null. Published runtime teardown
// breaks the otherwise self-pinning edge before the last Task pin is dropped.
constinit sync::SpinLock g_stdin_focus_lock{};
constinit Process* g_stdin_focus = nullptr;

void StdinAdvanceEventLocked(Process::StdinRing& ring)
{
    const u64 previous = __atomic_load_n(&ring.event_sequence, __ATOMIC_RELAXED);
    KASSERT(previous != ~u64{0}, "core/process", "stdin event sequence saturated");
    __atomic_store_n(&ring.event_sequence, previous + 1, __ATOMIC_RELEASE);
}

void StdinFocusClaimIfEmpty(Process* process)
{
    if (process == nullptr)
        return;

    ProcessRetain(process);
    ScopedProcessRef candidate(process);
    ScopedProcessRuntimeAccess runtime_access(process);
    if (!runtime_access)
        return;

    sync::SpinLockGuard focus_guard(g_stdin_focus_lock);
    if (g_stdin_focus == nullptr)
        g_stdin_focus = candidate.Detach();
}

void StdinFocusClearIf(Process* process)
{
    Process* detached = nullptr;
    {
        sync::SpinLockGuard focus_guard(g_stdin_focus_lock);
        if (g_stdin_focus == process)
        {
            detached = g_stdin_focus;
            g_stdin_focus = nullptr;
        }
    }
    // ProcessRelease may run teardown or panic, so never call it under the
    // focus spinlock. The reaper still owns the dying Task's pin here.
    ProcessRelease(detached);
}

} // namespace

i64 ProcessReadStdinBlocking(Process* proc, void* dst_user, u64 cap)
{
    if (proc == nullptr || dst_user == nullptr || cap == 0)
        return -1;
    // Claim the focus without holding runtime admission across the blocking
    // wait below. The focus itself owns the durable Process reference.
    StdinFocusClaimIfEmpty(proc);

    Process::StdinRing& r = proc->stdin_ring;
    u8 scratch[Process::StdinRing::kCap];
    u32 to_copy_u32 = 0;

    for (;;)
    {
        u64 observed_sequence = 0;
        {
            sync::SpinLockGuard ring_guard(r.lock);
            const u32 available = static_cast<u32>(r.head - r.tail);
            if (available != 0)
            {
                to_copy_u32 = (cap < available) ? static_cast<u32>(cap) : available;
                for (u32 i = 0; i < to_copy_u32; ++i)
                    scratch[i] = r.buf[(r.tail + i) & (Process::StdinRing::kCap - 1)];
                r.tail += to_copy_u32;
            }
            observed_sequence = __atomic_load_n(&r.event_sequence, __ATOMIC_ACQUIRE);
        }

        if (to_copy_u32 != 0)
            break;

        // If a producer published after the empty snapshot, the scheduler
        // declines to block. Otherwise it enqueues us and hands off under one
        // continuous scheduler-lock critical section, closing the lost wake.
        (void)sched::WaitQueueBlockIfSequenceUnchanged(&r.waiters, &r.event_sequence, observed_sequence);
    }

    // User access may fault or block and therefore occurs after dropping the
    // ring spinlock. As before, a failed copy consumes the drained bytes.
    if (!mm::CopyToUser(dst_user, scratch, to_copy_u32))
        return -1;
    return static_cast<i64>(to_copy_u32);
}

void ProcessFeedStdinFocusChar(char c)
{
    Process* process = nullptr;
    {
        sync::SpinLockGuard focus_guard(g_stdin_focus_lock);
        if (g_stdin_focus != nullptr)
        {
            ProcessRetain(g_stdin_focus);
            process = g_stdin_focus;
        }
    }
    ScopedProcessRef focus_pin(process);
    if (!focus_pin)
        return;

    ScopedProcessRuntimeAccess runtime_access(process);
    if (!runtime_access)
        return;

    Process::StdinRing& r = process->stdin_ring;
    {
        sync::SpinLockGuard ring_guard(r.lock);
        if (r.head - r.tail >= Process::StdinRing::kCap)
            ++r.tail;
        r.buf[r.head & (Process::StdinRing::kCap - 1)] = static_cast<u8>(c);
        ++r.head;
        StdinAdvanceEventLocked(r);
    }

    // Wake after publishing and after dropping the ring lock: waiter enqueue
    // and this wake serialize on the scheduler lock without a lock inversion.
    sched::WaitQueueWakeOne(&r.waiters);
}

bool ProcessSnapshotLinuxCwd(const Process* process, LinuxCwdSnapshot* snapshot_out)
{
    if (snapshot_out == nullptr)
        return false;
    *snapshot_out = LinuxCwdSnapshot{};
    if (process == nullptr)
        return false;

    LinuxCwdSnapshot candidate{};
    {
        // Leaf critical section: fixed storage copy only. Validation and
        // result publication happen after IRQ state and the lock are restored.
        sync::SpinLockGuard cwd_guard(process->linux_cwd_lock);
        for (u64 i = 0; i < Process::kLinuxCwdCap; ++i)
            candidate.path[i] = process->linux_cwd[i];
    }

    while (candidate.length < Process::kLinuxCwdCap && candidate.path[candidate.length] != 0)
        ++candidate.length;
    if (candidate.length == Process::kLinuxCwdCap)
        return false;

    *snapshot_out = candidate;
    return true;
}

bool ProcessReplaceLinuxCwd(Process* process, const char* path, u64 length)
{
    if (process == nullptr || path == nullptr || length == 0 || length >= Process::kLinuxCwdCap)
        return false;

    // Copy and validate before taking the spinlock. Besides keeping the
    // critical section bounded, this prevents an invalid source read from
    // occurring with IRQs disabled. Callers must supply a trusted kernel
    // buffer; user pointers are copied before entering this API.
    char candidate[Process::kLinuxCwdCap]{};
    for (u64 i = 0; i < length; ++i)
    {
        if (path[i] == 0)
            return false;
        candidate[i] = path[i];
    }

    {
        // Leaf critical section: never nest with fd/OFD/handle/VM locks and
        // never allocate, copy user memory, invoke VFS, log, or schedule here.
        sync::SpinLockGuard cwd_guard(process->linux_cwd_lock);
        for (u64 i = 0; i < Process::kLinuxCwdCap; ++i)
            process->linux_cwd[i] = candidate[i];
    }
    return true;
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
    // Authoritative mutable backing metadata for regular files. Descriptor
    // slots retain compatibility mirrors, but dup/fork siblings observe and
    // commit these fields through the one shared OFD.
    u8 regular_flags; // shared subset: kLinuxFdFlagPendingCreate only
    u8 _regular_pad[3];
    u32 first_cluster;
    u32 size;
    // Sleepable I/O/position serialization. Never acquire while holding
    // g_ofd_lock or a Process fd spinlock. A retained receipt pins this OFD
    // while a caller sleeps on or holds the mutex.
    sched::Mutex position_lock;
};

constinit OpenFileDescription g_ofd_pool[kOfdPoolCap] = {};
sync::SpinLock g_ofd_lock{};

// Allocate a fresh description with refcount 1. Returns the
// 1-based pool index, or 0 if the pool is exhausted. Caller holds
// g_ofd_lock.
u16 OfdAllocLocked(u64 offset, u32 status_flags, u8 regular_flags, u32 first_cluster, u32 size)
{
    for (u32 i = 0; i < kOfdPoolCap; ++i)
    {
        if (g_ofd_pool[i].refcount == 0)
        {
            g_ofd_pool[i].refcount = 1;
            g_ofd_pool[i].offset = offset;
            g_ofd_pool[i].status_flags = status_flags;
            g_ofd_pool[i].regular_flags = static_cast<u8>(regular_flags & Process::kLinuxFdFlagPendingCreate);
            g_ofd_pool[i].first_cluster = first_cluster;
            g_ofd_pool[i].size = size;
            return static_cast<u16>(i + 1);
        }
    }
    return 0;
}

// Checked retain for an existing description. Caller holds g_ofd_lock.
bool OfdRetainLocked(u16 ofd)
{
    if (ofd == 0 || ofd > kOfdPoolCap)
        return false;
    OpenFileDescription& d = g_ofd_pool[ofd - 1];
    if (d.refcount == 0 || d.refcount == static_cast<u32>(-1))
        return false;
    ++d.refcount;
    return true;
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
        d.regular_flags = 0;
        d.first_cluster = 0;
        d.size = 0;
    }
}

constexpr u64 kLinuxFdKFileRights =
    ::duetos::ipc::kHandleRightDuplicate | ::duetos::ipc::kHandleRightTransfer | ::duetos::ipc::kHandleRightDestroy;

bool LinuxFdNextGeneration(u32 generation, u32* next_out)
{
    if (next_out == nullptr)
        return false;
    *next_out = 0;
    if (generation == Process::kLinuxFdGenerationExhausted)
        return false;
    const u32 next = generation + 1;
    KASSERT(next != 0, "proc/linux-fd", "fd generation wrapped despite saturation guard");
    *next_out = next;
    return true;
}

void LinuxFdClearSnapshot(Process::LinuxFd* snapshot)
{
    if (snapshot == nullptr)
        return;
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->kf_handle = ::duetos::ipc::kHandleInvalid;
}

void LinuxFdClearSlotLocked(Process::LinuxFd& slot)
{
    // LinuxFdNextGeneration zeroes *next_out before it decides whether the
    // epoch can advance, so a saturated slot comes back as 0 with a false
    // return. Seeding `generation` with the exhausted marker and discarding
    // that return therefore published 0 — which both violates "zero is never
    // published" and un-retires a slot the header promises is permanently
    // retired, letting a stale receipt become current again. Honour the
    // return value instead.
    u32 next = 0;
    const bool advanced = LinuxFdNextGeneration(slot.generation, &next);
    LinuxFdClearSnapshot(&slot);
    slot.generation = advanced ? next : Process::kLinuxFdGenerationExhausted;
}

i32 LinuxFdFindLowestLocked(Process* p, u32 lo, i32 excluded = -1)
{
    sync::SpinLockAssertHeld(p->linux_fd_lock);
    const u32 fd_max = LinuxFdEffectiveMaxLocal(p);
    if (lo >= fd_max)
        return -1;
    for (u32 fd = lo; fd < fd_max; ++fd)
    {
        if (static_cast<i32>(fd) != excluded && p->linux_fds[fd].state == 0 &&
            p->linux_fds[fd].generation != Process::kLinuxFdGenerationExhausted)
            return static_cast<i32>(fd);
    }
    return -1;
}

void LinuxFdReleaseOfd(u16 ofd)
{
    if (ofd == 0)
        return;
    sync::SpinLockGuard guard(g_ofd_lock);
    OfdReleaseLocked(ofd);
}

void LinuxFdOverlayOfdSnapshotLocked(const OpenFileDescription& description, Process::LinuxFd* snapshot)
{
    snapshot->offset = description.offset;
    if (snapshot->state != 2)
        return;
    snapshot->flags =
        static_cast<u8>((snapshot->flags & ~Process::kLinuxFdFlagPendingCreate) | description.regular_flags);
    snapshot->first_cluster = description.first_cluster;
    snapshot->size = description.size;
}

OpenFileDescription* LinuxFdGuardDescriptionLocked(const LinuxFdIoGuard* guard)
{
    if (guard == nullptr || !guard->held || guard->ofd == 0 || guard->ofd > kOfdPoolCap)
        return nullptr;
    OpenFileDescription& description = g_ofd_pool[guard->ofd - 1];
    if (description.refcount == 0 || guard->position_lock != &description.position_lock)
        return nullptr;
    return &description;
}

bool LinuxFdReceiptValid(const Process::LinuxFd& snapshot, ::duetos::ipc::KObject* kfile_ref, bool owns_ofd_ref)
{
    if (snapshot.state == 0 || snapshot.kf_handle != ::duetos::ipc::kHandleInvalid)
        return false;
    if ((snapshot.ofd != 0) != owns_ofd_ref)
        return false;
    return kfile_ref == nullptr || kfile_ref->type == ::duetos::ipc::KObjectType::File;
}

bool LinuxFdAcquiredShapeValid(const LinuxFdAcquired* acquired)
{
    return acquired != nullptr && acquired->snapshot.state != 0 && acquired->snapshot.generation != 0 &&
           acquired->snapshot.kf_handle == ::duetos::ipc::kHandleInvalid &&
           (acquired->snapshot.ofd != 0) == acquired->owns_ofd_ref &&
           (acquired->kfile_ref == nullptr || acquired->kfile_ref->type == ::duetos::ipc::KObjectType::File);
}

bool LinuxFdGuardMatchesAcquired(const LinuxFdAcquired* acquired, const LinuxFdIoGuard* guard)
{
    return LinuxFdAcquiredShapeValid(acquired) && guard != nullptr && guard->held && guard->position_lock != nullptr &&
           guard->ofd == acquired->snapshot.ofd;
}

bool LinuxFdMatchesAcquiredLocked(Process* p, u32 fd, const LinuxFdAcquired* acquired)
{
    sync::SpinLockAssertHeld(p->linux_fd_lock);
    if (!LinuxFdAcquiredShapeValid(acquired) || fd >= kLinuxFdHardCap)
        return false;
    const Process::LinuxFd& slot = p->linux_fds[fd];
    return slot.state == acquired->snapshot.state && slot.generation == acquired->snapshot.generation &&
           slot.ofd == acquired->snapshot.ofd &&
           (slot.kf_handle != ::duetos::ipc::kHandleInvalid) == (acquired->kfile_ref != nullptr);
}

bool LinuxFdRetainPreparedIdentity(const LinuxFdPrepared* prepared, LinuxFdAcquired* acquired)
{
    *acquired = {};
    LinuxFdClearSnapshot(&acquired->snapshot);
    if (prepared == nullptr || !LinuxFdReceiptValid(prepared->snapshot, prepared->kfile_ref, prepared->owns_ofd_ref))
        return false;

    LinuxFdAcquired candidate{};
    candidate.snapshot = prepared->snapshot;
    candidate.snapshot.kf_handle = ::duetos::ipc::kHandleInvalid;
    candidate.owns_ofd_ref = prepared->owns_ofd_ref;
    if (candidate.owns_ofd_ref)
    {
        sync::SpinLockGuard guard(g_ofd_lock);
        if (!OfdRetainLocked(candidate.snapshot.ofd))
            return false;
    }
    if (prepared->kfile_ref != nullptr && !::duetos::ipc::KObjectAcquire(prepared->kfile_ref))
    {
        LinuxFdReleaseOfd(candidate.owns_ofd_ref ? candidate.snapshot.ofd : 0);
        return false;
    }
    candidate.kfile_ref = prepared->kfile_ref;
    *acquired = candidate;
    return true;
}

bool LinuxFdRetainSlotLocked(Process* p, u32 fd, u8 expected_state, LinuxFdAcquired* acquired)
{
    sync::SpinLockAssertHeld(p->linux_fd_lock);
    Process::LinuxFd& slot = p->linux_fds[fd];
    if (slot.state == 0 || (expected_state != 0 && slot.state != expected_state))
        return false;
    if (slot.generation == 0)
        slot.generation = 1;

    LinuxFdAcquired candidate{};
    candidate.snapshot = slot;
    candidate.snapshot.kf_handle = ::duetos::ipc::kHandleInvalid;

    if (slot.kf_handle != ::duetos::ipc::kHandleInvalid)
    {
        candidate.kfile_ref =
            ::duetos::ipc::HandleTableLookupRef(p->kobj_handles, slot.kf_handle, ::duetos::ipc::KObjectType::File);
        if (candidate.kfile_ref == nullptr)
        {
            *acquired = candidate;
            return false;
        }
    }

    if (slot.state != 1)
    {
        sync::SpinLockGuard ofd_guard(g_ofd_lock);
        if (slot.ofd == 0)
        {
            u32 next_generation = 0;
            if (!LinuxFdNextGeneration(slot.generation, &next_generation))
            {
                *acquired = candidate;
                return false;
            }
            const u16 ofd = OfdAllocLocked(slot.offset, /*status_flags=*/0, slot.flags, slot.first_cluster, slot.size);
            if (ofd != 0)
            {
                slot.ofd = ofd;
                slot.generation = next_generation;
            }
        }
        if (slot.ofd == 0 || !OfdRetainLocked(slot.ofd))
        {
            *acquired = candidate;
            return false;
        }
        candidate.snapshot.ofd = slot.ofd;
        candidate.snapshot.generation = slot.generation;
        LinuxFdOverlayOfdSnapshotLocked(g_ofd_pool[slot.ofd - 1], &candidate.snapshot);
        candidate.owns_ofd_ref = true;
    }
    else
    {
        candidate.snapshot.ofd = 0;
    }

    *acquired = candidate;
    return true;
}

bool LinuxFdDetachSlotLocked(Process* p, u32 fd, LinuxFdDetached* detached)
{
    sync::SpinLockAssertHeld(p->linux_fd_lock);
    Process::LinuxFd& slot = p->linux_fds[fd];
    if (slot.state == 0)
        return false;

    LinuxFdDetached candidate{};
    candidate.source_fd = fd;
    candidate.snapshot = slot;
    candidate.snapshot.kf_handle = ::duetos::ipc::kHandleInvalid;
    candidate.owns_ofd_ref = slot.ofd != 0;

    if (slot.kf_handle != ::duetos::ipc::kHandleInvalid)
    {
        auto object =
            ::duetos::ipc::HandleTableDetach(p->kobj_handles, slot.kf_handle, ::duetos::ipc::KObjectType::File);
        if (!object.has_value())
            return false;
        candidate.kfile_ref = object.value();
    }

    LinuxFdClearSlotLocked(slot);
    *detached = candidate;
    return true;
}

void LinuxFdConsumePrepared(LinuxFdPrepared* prepared)
{
    LinuxFdClearSnapshot(&prepared->snapshot);
    prepared->kfile_ref = nullptr;
    prepared->owns_ofd_ref = false;
}

void LinuxFdConsumeTransfer(LinuxFdTransfer* transfer)
{
    transfer->source_fd = 0;
    LinuxFdClearSnapshot(&transfer->snapshot);
    transfer->kfile_ref = nullptr;
    transfer->owns_ofd_ref = false;
}

bool LinuxFdPublishLocked(Process::LinuxFd& destination, const Process::LinuxFd& source,
                          ::duetos::ipc::Handle kfile_handle, bool cloexec)
{
    u32 generation = 0;
    if (!LinuxFdNextGeneration(destination.generation, &generation))
        return false;
    destination = source;
    destination.generation = generation;
    destination.kf_handle = kfile_handle;
    if (cloexec)
        destination.flags = static_cast<u8>(destination.flags | Process::kLinuxFdFlagCloexec);
    else
        destination.flags = static_cast<u8>(destination.flags & ~Process::kLinuxFdFlagCloexec);
    return true;
}

} // namespace

bool LinuxFdPrepare(LinuxFdPrepared* prepared, const Process::LinuxFd& payload, ::duetos::ipc::KObject* owned_kfile,
                    u32 status_flags)
{
    if (prepared == nullptr)
        return false;
    *prepared = {};
    LinuxFdClearSnapshot(&prepared->snapshot);
    if (payload.state == 0 || payload.ofd != 0 || payload.kf_handle != ::duetos::ipc::kHandleInvalid ||
        (owned_kfile != nullptr &&
         (owned_kfile->type != ::duetos::ipc::KObjectType::File || ::duetos::ipc::KObjectRefcount(owned_kfile) == 0)))
        return false;

    u16 ofd = 0;
    if (payload.state != 1)
    {
        sync::SpinLockGuard guard(g_ofd_lock);
        ofd = OfdAllocLocked(payload.offset, status_flags, payload.flags, payload.first_cluster, payload.size);
        if (ofd == 0)
            return false;
    }

    prepared->snapshot = payload;
    prepared->snapshot.ofd = ofd;
    prepared->snapshot.kf_handle = ::duetos::ipc::kHandleInvalid;
    prepared->snapshot.generation = 0;
    prepared->kfile_ref = owned_kfile;
    prepared->owns_ofd_ref = ofd != 0;
    return true;
}

void LinuxFdPreparedRelease(LinuxFdPrepared* prepared)
{
    if (prepared == nullptr)
        return;
    ::duetos::ipc::KObject* object = prepared->kfile_ref;
    const u16 ofd = prepared->owns_ofd_ref ? prepared->snapshot.ofd : 0;
    LinuxFdConsumePrepared(prepared);
    ::duetos::ipc::KObjectRelease(object);
    LinuxFdReleaseOfd(ofd);
}

i32 LinuxFdBindLowest(Process* p, u32 lo, LinuxFdPrepared* prepared, bool cloexec, LinuxFdAcquired* acquired_out)
{
    if (acquired_out != nullptr)
    {
        *acquired_out = {};
        LinuxFdClearSnapshot(&acquired_out->snapshot);
    }
    if (p == nullptr || prepared == nullptr ||
        !LinuxFdReceiptValid(prepared->snapshot, prepared->kfile_ref, prepared->owns_ofd_ref))
        return -1;

    LinuxFdAcquired retained{};
    LinuxFdClearSnapshot(&retained.snapshot);
    if (acquired_out != nullptr && !LinuxFdRetainPreparedIdentity(prepared, &retained))
        return -1;

    i32 result = -1;
    {
        sync::SpinLockGuard guard(p->linux_fd_lock);
        const i32 fd = LinuxFdFindLowestLocked(p, lo);
        if (fd >= 0)
        {
            ::duetos::ipc::Handle handle = ::duetos::ipc::kHandleInvalid;
            bool can_publish = true;
            if (prepared->kfile_ref != nullptr)
            {
                auto inserted =
                    ::duetos::ipc::HandleTableInsert(p->kobj_handles, prepared->kfile_ref, kLinuxFdKFileRights);
                if (!inserted.has_value())
                    can_publish = false;
                else
                    handle = inserted.value();
            }
            if (can_publish)
            {
                Process::LinuxFd& slot = p->linux_fds[static_cast<u32>(fd)];
                if (!LinuxFdPublishLocked(slot, prepared->snapshot, handle, cloexec))
                {
                    if (handle != ::duetos::ipc::kHandleInvalid)
                    {
                        auto detached =
                            ::duetos::ipc::HandleTableDetach(p->kobj_handles, handle, ::duetos::ipc::KObjectType::File);
                        KASSERT(detached.has_value() && detached.value() == prepared->kfile_ref, "proc/linux-fd",
                                "bind generation rollback lost KFile ownership");
                    }
                }
                else
                {
                    if (acquired_out != nullptr)
                    {
                        retained.snapshot = slot;
                        retained.snapshot.kf_handle = ::duetos::ipc::kHandleInvalid;
                    }
                    LinuxFdConsumePrepared(prepared);
                    result = fd;
                }
            }
        }
    }

    if (result < 0)
        LinuxFdAcquiredRelease(&retained);
    else if (acquired_out != nullptr)
        *acquired_out = retained;
    return result;
}

bool LinuxFdBindPairLowest(Process* p, u32 lo, LinuxFdPrepared* first, LinuxFdPrepared* second, u32* first_fd,
                           u32* second_fd, LinuxFdAcquired* first_acquired_out, LinuxFdAcquired* second_acquired_out)
{
    if (first_fd != nullptr)
        *first_fd = static_cast<u32>(-1);
    if (second_fd != nullptr)
        *second_fd = static_cast<u32>(-1);
    if (first_acquired_out != nullptr)
    {
        *first_acquired_out = {};
        LinuxFdClearSnapshot(&first_acquired_out->snapshot);
    }
    if (second_acquired_out != nullptr)
    {
        *second_acquired_out = {};
        LinuxFdClearSnapshot(&second_acquired_out->snapshot);
    }
    if (p == nullptr || first == nullptr || second == nullptr || first == second || first_fd == nullptr ||
        second_fd == nullptr || (first_acquired_out != nullptr && first_acquired_out == second_acquired_out) ||
        !LinuxFdReceiptValid(first->snapshot, first->kfile_ref, first->owns_ofd_ref) ||
        !LinuxFdReceiptValid(second->snapshot, second->kfile_ref, second->owns_ofd_ref))
        return false;

    LinuxFdAcquired retained[2]{};
    LinuxFdClearSnapshot(&retained[0].snapshot);
    LinuxFdClearSnapshot(&retained[1].snapshot);
    if (first_acquired_out != nullptr && !LinuxFdRetainPreparedIdentity(first, &retained[0]))
        return false;
    if (second_acquired_out != nullptr && !LinuxFdRetainPreparedIdentity(second, &retained[1]))
    {
        LinuxFdAcquiredRelease(&retained[0]);
        return false;
    }

    bool success = false;
    {
        sync::SpinLockGuard guard(p->linux_fd_lock);
        const i32 fd0 = LinuxFdFindLowestLocked(p, lo);
        const i32 fd1 = fd0 < 0 ? -1 : LinuxFdFindLowestLocked(p, lo, fd0);
        if (fd0 >= 0 && fd1 >= 0)
        {
            ::duetos::ipc::Handle handles[2]{::duetos::ipc::kHandleInvalid, ::duetos::ipc::kHandleInvalid};
            LinuxFdPrepared* receipts[2]{first, second};
            bool handles_ready = true;
            u32 inserted_count = 0;
            for (u32 i = 0; i < 2; ++i)
            {
                if (receipts[i]->kfile_ref == nullptr)
                    continue;
                auto inserted =
                    ::duetos::ipc::HandleTableInsert(p->kobj_handles, receipts[i]->kfile_ref, kLinuxFdKFileRights);
                if (!inserted.has_value())
                {
                    handles_ready = false;
                    break;
                }
                handles[i] = inserted.value();
                inserted_count = i + 1;
            }
            if (!handles_ready)
            {
                for (u32 rollback = 0; rollback < inserted_count; ++rollback)
                {
                    if (handles[rollback] == ::duetos::ipc::kHandleInvalid)
                        continue;
                    auto detached = ::duetos::ipc::HandleTableDetach(p->kobj_handles, handles[rollback],
                                                                     ::duetos::ipc::KObjectType::File);
                    KASSERT(detached.has_value() && detached.value() == receipts[rollback]->kfile_ref, "proc/linux-fd",
                            "pair-bind handle rollback lost ownership");
                }
            }
            else
            {
                const bool first_cloexec = (first->snapshot.flags & Process::kLinuxFdFlagCloexec) != 0;
                const bool second_cloexec = (second->snapshot.flags & Process::kLinuxFdFlagCloexec) != 0;
                Process::LinuxFd& first_slot = p->linux_fds[static_cast<u32>(fd0)];
                Process::LinuxFd& second_slot = p->linux_fds[static_cast<u32>(fd1)];
                KASSERT(LinuxFdPublishLocked(first_slot, first->snapshot, handles[0], first_cloexec), "proc/linux-fd",
                        "lowest-pair finder returned an exhausted first slot");
                KASSERT(LinuxFdPublishLocked(second_slot, second->snapshot, handles[1], second_cloexec),
                        "proc/linux-fd", "lowest-pair finder returned an exhausted second slot");
                if (first_acquired_out != nullptr)
                {
                    retained[0].snapshot = first_slot;
                    retained[0].snapshot.kf_handle = ::duetos::ipc::kHandleInvalid;
                }
                if (second_acquired_out != nullptr)
                {
                    retained[1].snapshot = second_slot;
                    retained[1].snapshot.kf_handle = ::duetos::ipc::kHandleInvalid;
                }
                LinuxFdConsumePrepared(first);
                LinuxFdConsumePrepared(second);
                *first_fd = static_cast<u32>(fd0);
                *second_fd = static_cast<u32>(fd1);
                success = true;
            }
        }
    }

    if (!success)
    {
        LinuxFdAcquiredRelease(&retained[0]);
        LinuxFdAcquiredRelease(&retained[1]);
        return false;
    }
    if (first_acquired_out != nullptr)
        *first_acquired_out = retained[0];
    if (second_acquired_out != nullptr)
        *second_acquired_out = retained[1];
    return true;
}

bool LinuxFdAcquire(Process* p, u32 fd, u8 expected_state, LinuxFdAcquired* acquired)
{
    if (acquired == nullptr)
        return false;
    *acquired = {};
    LinuxFdClearSnapshot(&acquired->snapshot);
    if (p == nullptr || fd >= kLinuxFdHardCap)
        return false;

    LinuxFdAcquired candidate{};
    LinuxFdClearSnapshot(&candidate.snapshot);
    bool retained = false;
    {
        sync::SpinLockGuard guard(p->linux_fd_lock);
        retained = LinuxFdRetainSlotLocked(p, fd, expected_state, &candidate);
    }
    if (!retained)
    {
        LinuxFdAcquiredRelease(&candidate);
        return false;
    }
    *acquired = candidate;
    return true;
}

bool LinuxFdAcquiredClone(const LinuxFdAcquired* source, LinuxFdAcquired* clone_out)
{
    if (clone_out == nullptr)
        return false;
    *clone_out = {};
    LinuxFdClearSnapshot(&clone_out->snapshot);
    if (source == nullptr || source->snapshot.state == 0 || source->snapshot.generation == 0 ||
        (source->snapshot.ofd != 0) != source->owns_ofd_ref ||
        (source->kfile_ref != nullptr && source->kfile_ref->type != ::duetos::ipc::KObjectType::File))
        return false;

    LinuxFdAcquired candidate = *source;
    candidate.snapshot.kf_handle = ::duetos::ipc::kHandleInvalid;
    if (source->owns_ofd_ref)
    {
        sync::SpinLockGuard guard(g_ofd_lock);
        if (!OfdRetainLocked(source->snapshot.ofd))
            return false;
    }
    if (source->kfile_ref != nullptr && !::duetos::ipc::KObjectAcquire(source->kfile_ref))
    {
        LinuxFdReleaseOfd(source->owns_ofd_ref ? source->snapshot.ofd : 0);
        return false;
    }
    *clone_out = candidate;
    return true;
}

void LinuxFdAcquiredRelease(LinuxFdAcquired* acquired)
{
    if (acquired == nullptr)
        return;
    ::duetos::ipc::KObject* object = acquired->kfile_ref;
    const u16 ofd = acquired->owns_ofd_ref ? acquired->snapshot.ofd : 0;
    *acquired = {};
    LinuxFdClearSnapshot(&acquired->snapshot);
    ::duetos::ipc::KObjectRelease(object);
    LinuxFdReleaseOfd(ofd);
}

bool LinuxFdIoGuardEnter(const LinuxFdAcquired* acquired, LinuxFdIoGuard* guard)
{
    if (guard == nullptr || guard->position_lock != nullptr || guard->ofd != 0 || guard->held ||
        !LinuxFdAcquiredShapeValid(acquired) || !acquired->owns_ofd_ref)
        return false;

    sched::Mutex* position_lock = nullptr;
    {
        sync::SpinLockGuard ofd_guard(g_ofd_lock);
        const u16 ofd = acquired->snapshot.ofd;
        if (ofd == 0 || ofd > kOfdPoolCap || g_ofd_pool[ofd - 1].refcount == 0)
            return false;
        position_lock = &g_ofd_pool[ofd - 1].position_lock;
    }

    // The retained receipt pins this OFD, so the pool slot and mutex cannot
    // be recycled while this potentially sleeping acquisition is in flight.
    sched::MutexLock(position_lock);
    guard->position_lock = position_lock;
    guard->ofd = acquired->snapshot.ofd;
    guard->held = true;
    return true;
}

void LinuxFdIoGuardExit(LinuxFdIoGuard* guard)
{
    if (guard == nullptr || !guard->held || guard->position_lock == nullptr)
        return;
    sched::Mutex* position_lock = guard->position_lock;
    guard->position_lock = nullptr;
    guard->ofd = 0;
    guard->held = false;
    sched::MutexUnlock(position_lock);
}

bool LinuxFdIoGuardGetOffset(const LinuxFdIoGuard* guard, u64* offset_out)
{
    if (offset_out == nullptr)
        return false;
    *offset_out = 0;
    sync::SpinLockGuard ofd_guard(g_ofd_lock);
    OpenFileDescription* description = LinuxFdGuardDescriptionLocked(guard);
    if (description == nullptr)
        return false;
    *offset_out = description->offset;
    return true;
}

bool LinuxFdIoGuardSetOffset(LinuxFdIoGuard* guard, u64 offset)
{
    sync::SpinLockGuard ofd_guard(g_ofd_lock);
    OpenFileDescription* description = LinuxFdGuardDescriptionLocked(guard);
    if (description == nullptr)
        return false;
    description->offset = offset;
    return true;
}

bool LinuxFdIoGuardAdvanceOffset(LinuxFdIoGuard* guard, u64 delta, u64* previous_out, u64* current_out)
{
    if (previous_out != nullptr)
        *previous_out = 0;
    if (current_out != nullptr)
        *current_out = 0;
    sync::SpinLockGuard ofd_guard(g_ofd_lock);
    OpenFileDescription* description = LinuxFdGuardDescriptionLocked(guard);
    if (description == nullptr || delta > static_cast<u64>(-1) - description->offset)
        return false;
    const u64 previous = description->offset;
    description->offset += delta;
    if (previous_out != nullptr)
        *previous_out = previous;
    if (current_out != nullptr)
        *current_out = description->offset;
    return true;
}

bool LinuxFdIoGuardGetStatusFlags(const LinuxFdIoGuard* guard, u32* flags_out)
{
    if (flags_out == nullptr)
        return false;
    *flags_out = 0;
    sync::SpinLockGuard ofd_guard(g_ofd_lock);
    OpenFileDescription* description = LinuxFdGuardDescriptionLocked(guard);
    if (description == nullptr)
        return false;
    *flags_out = description->status_flags;
    return true;
}

bool LinuxFdIoGuardSetStatusFlags(LinuxFdIoGuard* guard, u32 flags)
{
    sync::SpinLockGuard ofd_guard(g_ofd_lock);
    OpenFileDescription* description = LinuxFdGuardDescriptionLocked(guard);
    if (description == nullptr)
        return false;
    description->status_flags = flags;
    return true;
}

bool LinuxFdRefreshAcquired(Process* p, u32 fd, const LinuxFdAcquired* acquired, const LinuxFdIoGuard* guard,
                            Process::LinuxFd* snapshot_out)
{
    if (snapshot_out == nullptr)
        return false;
    LinuxFdClearSnapshot(snapshot_out);
    if (p == nullptr || fd >= kLinuxFdHardCap || !LinuxFdGuardMatchesAcquired(acquired, guard))
        return false;

    sync::SpinLockGuard fd_guard(p->linux_fd_lock);
    if (!LinuxFdMatchesAcquiredLocked(p, fd, acquired))
        return false;
    Process::LinuxFd candidate = p->linux_fds[fd];
    candidate.kf_handle = ::duetos::ipc::kHandleInvalid;
    {
        sync::SpinLockGuard ofd_guard(g_ofd_lock);
        OpenFileDescription* description = LinuxFdGuardDescriptionLocked(guard);
        if (description == nullptr || candidate.ofd != guard->ofd)
            return false;
        LinuxFdOverlayOfdSnapshotLocked(*description, &candidate);
    }
    *snapshot_out = candidate;
    return true;
}

bool LinuxFdRefreshRetainedRegular(const LinuxFdAcquired* acquired, const LinuxFdIoGuard* guard,
                                   Process::LinuxFd* snapshot_out)
{
    if (snapshot_out == nullptr)
        return false;
    LinuxFdClearSnapshot(snapshot_out);
    if (!LinuxFdAcquiredShapeValid(acquired) || acquired->snapshot.state != 2)
        return false;

    const bool guard_matches = LinuxFdGuardMatchesAcquired(acquired, guard);
    KASSERT(guard_matches, "proc/linux-fd", "retained regular refresh requires matching OFD guard");
    if (!guard_matches)
        return false;
    const bool guard_owned = guard->position_lock->owner == sched::CurrentTask();
    KASSERT(guard_owned, "proc/linux-fd", "retained regular refresh requires held OFD guard");
    if (!guard_owned)
        return false;

    Process::LinuxFd candidate = acquired->snapshot;
    {
        sync::SpinLockGuard ofd_guard(g_ofd_lock);
        OpenFileDescription* description = LinuxFdGuardDescriptionLocked(guard);
        if (description == nullptr || candidate.ofd != guard->ofd)
            return false;
        candidate.flags =
            static_cast<u8>((candidate.flags & ~Process::kLinuxFdFlagPendingCreate) | description->regular_flags);
        candidate.first_cluster = description->first_cluster;
        candidate.size = description->size;
    }
    *snapshot_out = candidate;
    return true;
}

bool LinuxFdUnbind(Process* p, u32 fd, LinuxFdDetached* detached)
{
    if (detached == nullptr)
        return false;
    *detached = {};
    LinuxFdClearSnapshot(&detached->snapshot);
    if (p == nullptr || fd >= kLinuxFdHardCap)
        return false;
    sync::SpinLockGuard guard(p->linux_fd_lock);
    return LinuxFdDetachSlotLocked(p, fd, detached);
}

bool LinuxFdUnbindAcquired(Process* p, u32 fd, const LinuxFdAcquired* acquired, LinuxFdDetached* detached)
{
    if (detached == nullptr)
        return false;
    *detached = {};
    LinuxFdClearSnapshot(&detached->snapshot);
    if (p == nullptr || fd >= kLinuxFdHardCap)
        return false;
    sync::SpinLockGuard guard(p->linux_fd_lock);
    if (!LinuxFdMatchesAcquiredLocked(p, fd, acquired))
        return false;
    return LinuxFdDetachSlotLocked(p, fd, detached);
}

bool LinuxFdSetCloexecAcquired(Process* p, u32 fd, const LinuxFdAcquired* acquired, bool on)
{
    if (p == nullptr || fd >= kLinuxFdHardCap)
        return false;
    sync::SpinLockGuard guard(p->linux_fd_lock);
    if (!LinuxFdMatchesAcquiredLocked(p, fd, acquired))
        return false;
    Process::LinuxFd& slot = p->linux_fds[fd];
    if (on)
        slot.flags = static_cast<u8>(slot.flags | Process::kLinuxFdFlagCloexec);
    else
        slot.flags = static_cast<u8>(slot.flags & ~Process::kLinuxFdFlagCloexec);
    return true;
}

bool LinuxFdCommitRegularMetadataAcquired(Process* p, u32 fd, const LinuxFdAcquired* acquired,
                                          const LinuxFdIoGuard* guard, const LinuxFdRegularMetadataCommit* commit)
{
    if (commit == nullptr || !LinuxFdGuardMatchesAcquired(acquired, guard) || acquired->snapshot.state != 2 ||
        (commit->flags_mask & ~Process::kLinuxFdFlagPendingCreate) != 0 ||
        (commit->flags_value & ~commit->flags_mask) != 0)
        return false;

    u8 regular_flags = 0;
    u32 first_cluster = 0;
    u32 size = 0;
    {
        sync::SpinLockGuard ofd_guard(g_ofd_lock);
        OpenFileDescription* description = LinuxFdGuardDescriptionLocked(guard);
        if (description == nullptr)
            return false;
        description->regular_flags = static_cast<u8>((description->regular_flags & ~commit->flags_mask) |
                                                     (commit->flags_value & commit->flags_mask));
        if (commit->update_first_cluster)
            description->first_cluster = commit->first_cluster;
        if (commit->update_size)
            description->size = commit->size;
        regular_flags = description->regular_flags;
        first_cluster = description->first_cluster;
        size = description->size;
    }

    // close(2) removes the descriptor, not an operation already holding the
    // open-file description. The shared update above therefore always wins.
    // Mirror only into the original slot identity; close+reuse must never let
    // the old operation overwrite the replacement descriptor.
    if (p != nullptr && fd < kLinuxFdHardCap)
    {
        sync::SpinLockGuard fd_guard(p->linux_fd_lock);
        if (LinuxFdMatchesAcquiredLocked(p, fd, acquired))
        {
            Process::LinuxFd& slot = p->linux_fds[fd];
            slot.flags = static_cast<u8>((slot.flags & ~Process::kLinuxFdFlagPendingCreate) | regular_flags);
            slot.first_cluster = first_cluster;
            slot.size = size;
        }
    }
    return true;
}

namespace
{
u32 LinuxFdDetachMatching(Process* p, LinuxFdDetached* detached, u32 capacity, bool cloexec_only)
{
    if (p == nullptr || detached == nullptr || capacity == 0)
        return 0;
    if (capacity > kLinuxFdHardCap)
        capacity = kLinuxFdHardCap;

    u32 count = 0;
    sync::SpinLockGuard guard(p->linux_fd_lock);
    for (u32 fd = 0; fd < kLinuxFdHardCap && count < capacity; ++fd)
    {
        const Process::LinuxFd& slot = p->linux_fds[fd];
        if (slot.state == 0 || (cloexec_only && (slot.flags & Process::kLinuxFdFlagCloexec) == 0))
            continue;
        detached[count] = {};
        LinuxFdClearSnapshot(&detached[count].snapshot);
        if (LinuxFdDetachSlotLocked(p, fd, &detached[count]))
            ++count;
        else
            KLOG_ONCE_WARN_V("proc/linux-fd", "batch detach failed for live fd", fd);
    }
    return count;
}
} // namespace

u32 LinuxFdDetachAll(Process* p, LinuxFdDetached* detached, u32 capacity)
{
    return LinuxFdDetachMatching(p, detached, capacity, false);
}

u32 LinuxFdDetachCloexec(Process* p, LinuxFdDetached* detached, u32 capacity)
{
    return LinuxFdDetachMatching(p, detached, capacity, true);
}

void LinuxFdDetachedRelease(LinuxFdDetached* detached)
{
    if (detached == nullptr)
        return;
    ::duetos::ipc::KObject* object = detached->kfile_ref;
    const u16 ofd = detached->owns_ofd_ref ? detached->snapshot.ofd : 0;
    *detached = {};
    LinuxFdClearSnapshot(&detached->snapshot);
    ::duetos::ipc::KObjectRelease(object);
    LinuxFdReleaseOfd(ofd);
}

bool LinuxFdExport(Process* source, u32 source_fd, LinuxFdTransfer* transfer)
{
    if (transfer == nullptr)
        return false;
    *transfer = {};
    LinuxFdClearSnapshot(&transfer->snapshot);
    LinuxFdAcquired acquired{};
    if (!LinuxFdAcquire(source, source_fd, 0, &acquired))
        return false;
    transfer->source_fd = source_fd;
    transfer->snapshot = acquired.snapshot;
    transfer->kfile_ref = acquired.kfile_ref;
    transfer->owns_ofd_ref = acquired.owns_ofd_ref;
    acquired.kfile_ref = nullptr;
    acquired.owns_ofd_ref = false;
    return true;
}

void LinuxFdTransferRelease(LinuxFdTransfer* transfer)
{
    if (transfer == nullptr)
        return;
    ::duetos::ipc::KObject* object = transfer->kfile_ref;
    const u16 ofd = transfer->owns_ofd_ref ? transfer->snapshot.ofd : 0;
    LinuxFdConsumeTransfer(transfer);
    ::duetos::ipc::KObjectRelease(object);
    LinuxFdReleaseOfd(ofd);
}

i32 LinuxFdImportLowest(Process* destination, u32 lo, LinuxFdTransfer* transfer, bool cloexec)
{
    if (destination == nullptr || transfer == nullptr ||
        !LinuxFdReceiptValid(transfer->snapshot, transfer->kfile_ref, transfer->owns_ofd_ref))
        return -1;

    sync::SpinLockGuard guard(destination->linux_fd_lock);
    const i32 fd = LinuxFdFindLowestLocked(destination, lo);
    if (fd < 0)
        return -1;

    ::duetos::ipc::Handle handle = ::duetos::ipc::kHandleInvalid;
    if (transfer->kfile_ref != nullptr)
    {
        auto inserted =
            ::duetos::ipc::HandleTableInsert(destination->kobj_handles, transfer->kfile_ref, kLinuxFdKFileRights);
        if (!inserted.has_value())
            return -1;
        handle = inserted.value();
    }
    if (!LinuxFdPublishLocked(destination->linux_fds[static_cast<u32>(fd)], transfer->snapshot, handle, cloexec))
    {
        if (handle != ::duetos::ipc::kHandleInvalid)
        {
            auto detached =
                ::duetos::ipc::HandleTableDetach(destination->kobj_handles, handle, ::duetos::ipc::KObjectType::File);
            KASSERT(detached.has_value() && detached.value() == transfer->kfile_ref, "proc/linux-fd",
                    "import generation rollback lost KFile ownership");
        }
        return -1;
    }
    LinuxFdConsumeTransfer(transfer);
    return fd;
}

bool LinuxFdImportExact(Process* destination, u32 destination_fd, LinuxFdTransfer* transfer, bool cloexec)
{
    if (destination == nullptr || transfer == nullptr || destination_fd >= kLinuxFdHardCap ||
        destination_fd >= LinuxFdEffectiveMaxLocal(destination) ||
        !LinuxFdReceiptValid(transfer->snapshot, transfer->kfile_ref, transfer->owns_ofd_ref))
        return false;

    ::duetos::ipc::KObject* displaced_object = nullptr;
    u16 displaced_ofd = 0;
    bool success = false;
    {
        sync::SpinLockGuard guard(destination->linux_fd_lock);
        Process::LinuxFd& slot = destination->linux_fds[destination_fd];
        u32 next_generation = 0;
        if (!LinuxFdNextGeneration(slot.generation, &next_generation))
            return false;
        ::duetos::ipc::Handle replacement_handle = ::duetos::ipc::kHandleInvalid;

        if (slot.kf_handle != ::duetos::ipc::kHandleInvalid && transfer->kfile_ref != nullptr)
        {
            auto replaced =
                ::duetos::ipc::HandleTableAdoptReplace(destination->kobj_handles, slot.kf_handle, transfer->kfile_ref,
                                                       kLinuxFdKFileRights, ::duetos::ipc::KObjectType::File);
            if (!replaced.has_value())
                return false;
            replacement_handle = replaced.value().handle;
            displaced_object = replaced.value().displaced;
        }
        else if (slot.kf_handle != ::duetos::ipc::kHandleInvalid)
        {
            auto detached = ::duetos::ipc::HandleTableDetach(destination->kobj_handles, slot.kf_handle,
                                                             ::duetos::ipc::KObjectType::File);
            if (!detached.has_value())
                return false;
            displaced_object = detached.value();
        }
        else if (transfer->kfile_ref != nullptr)
        {
            auto inserted =
                ::duetos::ipc::HandleTableInsert(destination->kobj_handles, transfer->kfile_ref, kLinuxFdKFileRights);
            if (!inserted.has_value())
                return false;
            replacement_handle = inserted.value();
        }

        displaced_ofd = slot.ofd;
        KASSERT(LinuxFdPublishLocked(slot, transfer->snapshot, replacement_handle, cloexec), "proc/linux-fd",
                "validated exact-import slot became exhausted under lock");
        LinuxFdConsumeTransfer(transfer);
        success = true;
    }

    // These may run pool callbacks/destructors, so they are deliberately after
    // both linux_fd_lock and HandleTable's internal lock have been released.
    ::duetos::ipc::KObjectRelease(displaced_object);
    LinuxFdReleaseOfd(displaced_ofd);
    return success;
}

bool LinuxFdExportTable(Process* source, LinuxFdTransfer* transfers, u32 capacity, u32* count_out)
{
    if (count_out == nullptr)
        return false;
    *count_out = 0;
    if (source == nullptr || transfers == nullptr || capacity == 0)
        return false;
    if (capacity > kLinuxFdHardCap)
        capacity = kLinuxFdHardCap;

    u32 count = 0;
    bool failed = false;
    {
        sync::SpinLockGuard guard(source->linux_fd_lock);
        u32 live = 0;
        for (u32 fd = 0; fd < kLinuxFdHardCap; ++fd)
            if (source->linux_fds[fd].state != 0)
                ++live;
        if (live > capacity)
            failed = true;

        for (u32 fd = 0; !failed && fd < kLinuxFdHardCap; ++fd)
        {
            if (source->linux_fds[fd].state == 0)
                continue;
            LinuxFdAcquired acquired{};
            LinuxFdClearSnapshot(&acquired.snapshot);
            if (!LinuxFdRetainSlotLocked(source, fd, 0, &acquired))
            {
                // Preserve any partial ownership so cleanup happens after the
                // source fd lock rather than inside this failure leg.
                transfers[count] = {};
                transfers[count].source_fd = fd;
                transfers[count].snapshot = acquired.snapshot;
                transfers[count].kfile_ref = acquired.kfile_ref;
                transfers[count].owns_ofd_ref = acquired.owns_ofd_ref;
                ++count;
                failed = true;
                break;
            }
            transfers[count] = {};
            transfers[count].source_fd = fd;
            transfers[count].snapshot = acquired.snapshot;
            transfers[count].kfile_ref = acquired.kfile_ref;
            transfers[count].owns_ofd_ref = acquired.owns_ofd_ref;
            ++count;
        }
    }

    if (!failed)
    {
        *count_out = count;
        return true;
    }
    for (u32 i = 0; i < count; ++i)
        LinuxFdTransferRelease(&transfers[i]);
    return false;
}

bool LinuxFdImportTable(Process* destination, LinuxFdTransfer* transfers, u32 count)
{
    if (destination == nullptr || (count != 0 && transfers == nullptr) || count > kLinuxFdHardCap)
        return false;

    ::duetos::ipc::Handle handles[kLinuxFdHardCap]{};
    bool present[kLinuxFdHardCap]{};
    for (u32 i = 0; i < kLinuxFdHardCap; ++i)
        handles[i] = ::duetos::ipc::kHandleInvalid;

    sync::SpinLockGuard guard(destination->linux_fd_lock);
    // Fork imports into a private ProcessCreate table. Validate every row, not
    // only rows present in the source snapshot, so a closed parent descriptor
    // clears the child's default TTY row instead of silently resurrecting it.
    for (u32 fd = 0; fd < kLinuxFdHardCap; ++fd)
    {
        const Process::LinuxFd& slot = destination->linux_fds[fd];
        if (slot.kf_handle != ::duetos::ipc::kHandleInvalid || slot.ofd != 0 || (slot.state != 0 && slot.state != 1))
            return false;
    }
    for (u32 i = 0; i < count; ++i)
    {
        const u32 fd = transfers[i].source_fd;
        if (fd >= kLinuxFdHardCap || fd >= LinuxFdEffectiveMaxLocal(destination) ||
            !LinuxFdReceiptValid(transfers[i].snapshot, transfers[i].kfile_ref, transfers[i].owns_ofd_ref))
            return false;
        u32 next_generation = 0;
        if (!LinuxFdNextGeneration(destination->linux_fds[fd].generation, &next_generation))
            return false;
        for (u32 prior = 0; prior < i; ++prior)
            if (transfers[prior].source_fd == fd)
                return false;
        present[fd] = true;
    }

    u32 inserted_count = 0;
    for (; inserted_count < count; ++inserted_count)
    {
        if (transfers[inserted_count].kfile_ref == nullptr)
            continue;
        auto inserted = ::duetos::ipc::HandleTableInsert(destination->kobj_handles, transfers[inserted_count].kfile_ref,
                                                         kLinuxFdKFileRights);
        if (!inserted.has_value())
            break;
        handles[inserted_count] = inserted.value();
    }

    if (inserted_count != count)
    {
        for (u32 i = 0; i < inserted_count; ++i)
        {
            if (handles[i] == ::duetos::ipc::kHandleInvalid)
                continue;
            auto detached = ::duetos::ipc::HandleTableDetach(destination->kobj_handles, handles[i],
                                                             ::duetos::ipc::KObjectType::File);
            KASSERT(detached.has_value() && detached.value() == transfers[i].kfile_ref, "proc/linux-fd",
                    "table-import rollback lost KFile ownership");
        }
        return false;
    }

    // Handle publication can no longer fail. First remove default child rows
    // absent from the source snapshot, then publish every imported identity.
    for (u32 fd = 0; fd < kLinuxFdHardCap; ++fd)
        if (!present[fd] && destination->linux_fds[fd].state != 0)
            LinuxFdClearSlotLocked(destination->linux_fds[fd]);
    for (u32 i = 0; i < count; ++i)
    {
        const u32 fd = transfers[i].source_fd;
        const bool cloexec = (transfers[i].snapshot.flags & Process::kLinuxFdFlagCloexec) != 0;
        KASSERT(LinuxFdPublishLocked(destination->linux_fds[fd], transfers[i].snapshot, handles[i], cloexec),
                "proc/linux-fd", "validated table-import slot became exhausted under lock");
        LinuxFdConsumeTransfer(&transfers[i]);
    }
    return true;
}

i32 LinuxFdDuplicateLowest(Process* p, u32 oldfd, u32 lo, bool cloexec)
{
    LinuxFdTransfer transfer{};
    if (!LinuxFdExport(p, oldfd, &transfer))
        return -1;
    const i32 fd = LinuxFdImportLowest(p, lo, &transfer, cloexec);
    LinuxFdTransferRelease(&transfer);
    return fd;
}

bool LinuxFdDuplicateExact(Process* p, u32 oldfd, u32 newfd, bool cloexec)
{
    if (p == nullptr || oldfd >= kLinuxFdHardCap || newfd >= kLinuxFdHardCap)
        return false;
    if (oldfd == newfd)
    {
        sync::SpinLockGuard guard(p->linux_fd_lock);
        return p->linux_fds[oldfd].state != 0;
    }

    LinuxFdTransfer transfer{};
    if (!LinuxFdExport(p, oldfd, &transfer))
        return false;
    const bool imported = LinuxFdImportExact(p, newfd, &transfer, cloexec);
    LinuxFdTransferRelease(&transfer);
    return imported;
}

i32 LinuxFdAllocLowest(Process* p, u32 lo)
{
    if (p == nullptr)
        return -1;
    sync::SpinLockGuard guard(p->linux_fd_lock);
    return LinuxFdFindLowestLocked(p, lo);
}

bool LinuxFdAttachKFile(Process* p, u32 fd, u8 kind, u32 pool_index, void (*release)(u32), bool* out_pool_released)
{
    if (out_pool_released != nullptr)
        *out_pool_released = false;
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
    bool installed = false;
    {
        sync::SpinLockGuard guard(p->linux_fd_lock);
        Process::LinuxFd& slot = p->linux_fds[fd];
        if (slot.state != 0 && slot.kf_handle == ::duetos::ipc::kHandleInvalid)
        {
            u32 next_generation = 0;
            if (LinuxFdNextGeneration(slot.generation, &next_generation))
            {
                auto inserted =
                    ::duetos::ipc::HandleTableInsert(p->kobj_handles, &kf_r.value()->base, kLinuxFdKFileRights);
                if (inserted.has_value())
                {
                    slot.generation = next_generation;
                    slot.kf_handle = inserted.value();
                    installed = true;
                }
            }
        }
    }
    if (!installed)
    {
        // Insert failed (table full). Drop the fresh KFile ref so
        // its destroy callback runs and releases the pool slot —
        // the caller had already allocated `pool_index` and is
        // counting on cleanup if attach fails.
        KLOG_ONCE_WARN("proc/linux-fd", "HandleTableInsert failed (table full) on attach");
        ::duetos::ipc::KObjectRelease(&kf_r.value()->base);
        if (out_pool_released != nullptr)
            *out_pool_released = true;
        return false;
    }
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
    bool installed = false;
    {
        sync::SpinLockGuard guard(p->linux_fd_lock);
        Process::LinuxFd& slot = p->linux_fds[fd];
        if (slot.state != 0 && slot.kf_handle == ::duetos::ipc::kHandleInvalid)
        {
            u32 next_generation = 0;
            if (LinuxFdNextGeneration(slot.generation, &next_generation))
            {
                auto inserted =
                    ::duetos::ipc::HandleTableInsert(p->kobj_handles, &kf_r.value()->base, kLinuxFdKFileRights);
                if (inserted.has_value())
                {
                    slot.generation = next_generation;
                    slot.kf_handle = inserted.value();
                    installed = true;
                }
            }
        }
    }
    if (!installed)
    {
        // Same rollback shape as `LinuxFdAttachKFile` — KObjectRelease
        // fires the owner-aware destroy callback, which frees the
        // pool slot the caller had already allocated.
        KLOG_ONCE_WARN("proc/linux-fd", "HandleTableInsert failed (table full) on attach-owned");
        ::duetos::ipc::KObjectRelease(&kf_r.value()->base);
        return false;
    }
    return true;
}

void LinuxFdClose(Process* p, u32 fd)
{
    LinuxFdDetached detached{};
    if (LinuxFdUnbind(p, fd, &detached))
        LinuxFdDetachedRelease(&detached);
}

bool LinuxFdDup(Process* p, u32 oldfd, u32 newfd)
{
    return LinuxFdDuplicateExact(p, oldfd, newfd, false);
}

void LinuxFdSetCloexec(Process* p, u32 fd, bool on)
{
    if (p == nullptr || fd >= 16)
        return;
    sync::SpinLockGuard guard(p->linux_fd_lock);
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
    sync::SpinLockGuard guard(const_cast<Process*>(p)->linux_fd_lock);
    const Process::LinuxFd& lf = p->linux_fds[fd];
    if (lf.state == 0)
        return false;
    return (lf.flags & Process::kLinuxFdFlagCloexec) != 0;
}

bool LinuxFdOpenDescription(Process* p, u32 fd, u64 initial_offset, u32 status_flags)
{
    if (p == nullptr || fd >= 16)
        return false;
    sync::SpinLockGuard fd_guard(p->linux_fd_lock);
    Process::LinuxFd& lf = p->linux_fds[fd];
    if (lf.state == 0)
        return false;
    if (lf.ofd != 0)
    {
        // Already has a description — refresh the inline offset
        // mirror and leave the shared object alone. (Re-opening a
        // description over a live one would silently orphan dup
        // siblings.)
        sync::SpinLockGuard ofd_guard(g_ofd_lock);
        if (lf.ofd > kOfdPoolCap || g_ofd_pool[lf.ofd - 1].refcount == 0)
            return false;
        LinuxFdOverlayOfdSnapshotLocked(g_ofd_pool[lf.ofd - 1], &lf);
        return true;
    }
    sync::SpinLockGuard g(g_ofd_lock);
    u32 next_generation = 0;
    if (!LinuxFdNextGeneration(lf.generation, &next_generation))
        return false;
    const u16 ofd = OfdAllocLocked(initial_offset, status_flags, lf.flags, lf.first_cluster, lf.size);
    if (ofd == 0)
    {
        KLOG_ONCE_WARN("proc/linux-fd", "OFD pool exhausted on open");
        return false;
    }
    lf.ofd = ofd;
    lf.generation = next_generation;
    lf.offset = initial_offset; // keep the inline mirror in step
    return true;
}

u64 LinuxFdGetOffset(const Process* p, u32 fd)
{
    if (p == nullptr || fd >= 16)
        return 0;
    sync::SpinLockGuard fd_guard(const_cast<Process*>(p)->linux_fd_lock);
    const Process::LinuxFd& lf = p->linux_fds[fd];
    if (lf.ofd == 0)
        return lf.offset; // no shared description — inline is authoritative
    sync::SpinLockGuard g(g_ofd_lock);
    if (lf.ofd > kOfdPoolCap || g_ofd_pool[lf.ofd - 1].refcount == 0)
        return lf.offset;
    return g_ofd_pool[lf.ofd - 1].offset;
}

void LinuxFdSetOffset(Process* p, u32 fd, u64 offset)
{
    if (p == nullptr || fd >= 16)
        return;
    sync::SpinLockGuard fd_guard(p->linux_fd_lock);
    Process::LinuxFd& lf = p->linux_fds[fd];
    if (lf.ofd == 0)
    {
        lf.offset = offset; // no shared description — inline only
        return;
    }
    {
        sync::SpinLockGuard g(g_ofd_lock);
        if (lf.ofd > kOfdPoolCap || g_ofd_pool[lf.ofd - 1].refcount == 0)
            return;
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
    sync::SpinLockGuard fd_guard(const_cast<Process*>(p)->linux_fd_lock);
    const Process::LinuxFd& lf = p->linux_fds[fd];
    if (lf.ofd == 0)
        return 0;
    sync::SpinLockGuard g(g_ofd_lock);
    if (lf.ofd > kOfdPoolCap || g_ofd_pool[lf.ofd - 1].refcount == 0)
        return 0;
    return g_ofd_pool[lf.ofd - 1].status_flags;
}

void LinuxFdSetStatusFlags(Process* p, u32 fd, u32 status_flags)
{
    if (p == nullptr || fd >= 16)
        return;
    sync::SpinLockGuard fd_guard(p->linux_fd_lock);
    Process::LinuxFd& lf = p->linux_fds[fd];
    if (lf.ofd == 0)
        return;
    sync::SpinLockGuard g(g_ofd_lock);
    if (lf.ofd > kOfdPoolCap || g_ofd_pool[lf.ofd - 1].refcount == 0)
        return;
    g_ofd_pool[lf.ofd - 1].status_flags = status_flags;
}

bool LinuxFdCopyAcrossProcesses(Process* dst, u32 dst_fd, Process* src, u32 src_fd)
{
    LinuxFdTransfer transfer{};
    if (!LinuxFdExport(src, src_fd, &transfer))
        return false;
    const bool cloexec = (transfer.snapshot.flags & Process::kLinuxFdFlagCloexec) != 0;
    const bool imported = LinuxFdImportExact(dst, dst_fd, &transfer, cloexec);
    LinuxFdTransferRelease(&transfer);
    return imported;
}

bool LinuxFdInheritFromParent(Process* parent, Process* child)
{
    if (parent == nullptr || child == nullptr || parent == child)
        return false;

    LinuxFdTransfer transfers[kLinuxFdHardCap]{};
    u32 count = 0;
    if (!LinuxFdExportTable(parent, transfers, kLinuxFdHardCap, &count))
        return false;

    // Directory-snapshot KFiles close a Process::win32_dirs slot through an
    // owner-aware callback and therefore cannot cross into another Process.
    // Drop their retained export references before the child table is ever
    // published, compacting the remaining ownership receipts in place.
    constexpr u8 kDirSnapshotState = static_cast<u8>(::duetos::ipc::KFileKind::DirSnapshot);
    u32 inheritable_count = 0;
    for (u32 i = 0; i < count; ++i)
    {
        if (transfers[i].snapshot.state == kDirSnapshotState)
        {
            LinuxFdTransferRelease(&transfers[i]);
            continue;
        }
        if (inheritable_count != i)
        {
            transfers[inheritable_count] = transfers[i];
            LinuxFdConsumeTransfer(&transfers[i]);
        }
        ++inheritable_count;
    }

    const bool imported = LinuxFdImportTable(child, transfers, inheritable_count);
    for (u32 i = 0; i < count; ++i)
        LinuxFdTransferRelease(&transfers[i]);
    return imported;
}

void LinuxFdCloseOnExec(Process* p)
{
    LinuxFdDetached detached[kLinuxFdHardCap]{};
    const u32 count = LinuxFdDetachCloexec(p, detached, kLinuxFdHardCap);
    for (u32 i = 0; i < count; ++i)
        LinuxFdDetachedRelease(&detached[i]);
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
        p->linux_fds[i].generation = 1;
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

    // 7) Exit drain. Process runtime teardown closes the whole fd table on
    // the way out precisely so an fd the guest never close()d does
    // not strand its open-file description in the kernel-wide OFD
    // pool. Exercise that same whole-table loop here: two fds
    // sharing one description, neither closed, must leave the pool
    // slot free once the loop has run — and the loop must be a
    // no-op on the empty slots it walks past.
    p->linux_fds[5].state = 5;
    p->linux_fds[5].first_cluster = 0xBBBB;
    p->linux_fds[5].offset = 0x99;
    if (!LinuxFdDup(p, 5, 6))
        core::Panic("proc/linux-fd", "self-test: Dup(5, 6) failed");
    const u16 leaked_ofd = p->linux_fds[5].ofd;
    if (leaked_ofd == 0 || g_ofd_pool[leaked_ofd - 1].refcount != 2)
        core::Panic("proc/linux-fd", "self-test: dup(5,6) did not take two OFD refs");
    for (u32 fd = 0; fd < 16; ++fd)
    {
        LinuxFdClose(p, fd);
    }
    if (g_ofd_pool[leaked_ofd - 1].refcount != 0)
        core::Panic("proc/linux-fd", "self-test: exit drain leaked an open-file description");


    // 8) Cross-process copy (the shape fork inheritance and
    // pidfd_getfd share). `kf_handle` is a dense index into the
    // SOURCE's own handle table with no owner tag, so a verbatim
    // struct copy would name whatever object sits at that index in
    // the DESTINATION's table — typically one of the destination's
    // own live fds, which its next close would then destroy.
    auto* q = static_cast<Process*>(mm::KMalloc(sizeof(Process)));
    if (q == nullptr)
    {
        mm::KFree(p);
        arch::SerialWrite("[proc] linux-fd-table self-test: cross-process leg skipped (no kheap)\n");
        return;
    }
    memset(q, 0, sizeof(Process));
    q->linux_rlimit_nofile_cur = 0xFFFFFFFFFFFFFFFFull;
    for (u32 i = 0; i < 16; ++i)
    {
        q->linux_fds[i].state = (i < 3) ? 1 : 0;
        q->linux_fds[i].kf_handle = ::duetos::ipc::kHandleInvalid;
        q->linux_fds[i].generation = 1;
    }

    // Source fd in `p`, and a DIFFERENT object already parked at
    // the destination's low handle — the value a verbatim copy
    // would have aliased.
    p->linux_fds[5].state = 5;
    p->linux_fds[5].first_cluster = 0xBEEF;
    if (!LinuxFdAttachKFile(p, 5, /*kind=*/5, /*pool_index=*/0xBEEF, &LinuxFdSelfTestRelease))
        core::Panic("proc/linux-fd", "self-test: AttachKFile(src) failed");
    q->linux_fds[3].state = 5;
    q->linux_fds[3].first_cluster = 0xC0DE;
    if (!LinuxFdAttachKFile(q, 3, /*kind=*/5, /*pool_index=*/0xC0DE, &LinuxFdSelfTestRelease))
        core::Panic("proc/linux-fd", "self-test: AttachKFile(dst-occupant) failed");
    const ::duetos::ipc::Handle collide = q->linux_fds[3].kf_handle;

    g_lfd_selftest_release_calls = 0;
    g_lfd_selftest_release_idx = 0;
    if (!LinuxFdCopyAcrossProcesses(q, 4, p, 5))
        core::Panic("proc/linux-fd", "self-test: cross-process copy failed");
    if (q->linux_fds[4].kf_handle == collide)
        core::Panic("proc/linux-fd", "self-test: cross-process copy aliased the destination's own handle");
    if (q->linux_fds[4].ofd == 0 || q->linux_fds[4].ofd != p->linux_fds[5].ofd)
        core::Panic("proc/linux-fd", "self-test: cross-process copy did not SHARE the open-file description");
    const u16 x_ofd = q->linux_fds[4].ofd;
    if (g_ofd_pool[x_ofd - 1].refcount != 2)
        core::Panic("proc/linux-fd", "self-test: cross-process copy did not retain the shared OFD");

    // Closing the copy must not release the source's pool ref, must
    // not disturb the destination's pre-existing fd, and must give
    // back exactly the OFD ref it took.
    LinuxFdClose(q, 4);
    if (g_lfd_selftest_release_calls != 0)
        core::Panic("proc/linux-fd", "self-test: closing a cross-process copy fired the pool release early");
    if (q->linux_fds[3].state != 5)
        core::Panic("proc/linux-fd", "self-test: closing a cross-process copy clobbered an unrelated fd");
    if (g_ofd_pool[x_ofd - 1].refcount != 1)
        core::Panic("proc/linux-fd", "self-test: cross-process copy did not balance its OFD ref");

    // Each owner's close releases its OWN pool index, once.
    LinuxFdClose(p, 5);
    if (g_lfd_selftest_release_calls != 1 || g_lfd_selftest_release_idx != 0xBEEF)
        core::Panic("proc/linux-fd", "self-test: source close did not release the source pool index");
    LinuxFdClose(q, 3);
    if (g_lfd_selftest_release_calls != 2 || g_lfd_selftest_release_idx != 0xC0DE)
        core::Panic("proc/linux-fd", "self-test: destination close did not release its own pool index");

    // 9) Strong acquired identity survives numeric-slot detach/reuse. The
    // detached table ref and two acquired refs must release independently;
    // only the last explicit receipt cleanup may fire the pool callback.
    g_lfd_selftest_release_calls = 0;
    g_lfd_selftest_release_idx = 0;
    auto acquired_kfile =
        ::duetos::ipc::KFileCreate(::duetos::ipc::KFileKind::Eventfd, 0xD00D, &LinuxFdSelfTestRelease, nullptr, 0);
    if (!acquired_kfile.has_value())
        core::Panic("proc/linux-fd", "self-test: acquired-identity KFileCreate failed");
    Process::LinuxFd acquired_payload{};
    acquired_payload.state = 5;
    acquired_payload.first_cluster = 0xD00D;
    acquired_payload.offset = 0x4242;
    acquired_payload.kf_handle = ::duetos::ipc::kHandleInvalid;
    LinuxFdPrepared acquired_prepared{};
    if (!LinuxFdPrepare(&acquired_prepared, acquired_payload, &acquired_kfile.value()->base, 0x800))
        core::Panic("proc/linux-fd", "self-test: LinuxFdPrepare failed");
    const i32 acquired_fd = LinuxFdBindLowest(p, 3, &acquired_prepared, false);
    if (acquired_fd < 0)
        core::Panic("proc/linux-fd", "self-test: LinuxFdBindLowest failed");
    const u32 acquired_generation = p->linux_fds[static_cast<u32>(acquired_fd)].generation;
    const u16 acquired_ofd = p->linux_fds[static_cast<u32>(acquired_fd)].ofd;

    LinuxFdAcquired acquired{};
    LinuxFdAcquired acquired_clone{};
    if (!LinuxFdAcquire(p, static_cast<u32>(acquired_fd), 5, &acquired) ||
        !LinuxFdAcquiredClone(&acquired, &acquired_clone))
        core::Panic("proc/linux-fd", "self-test: acquired identity retain/clone failed");
    LinuxFdDetached acquired_detached{};
    if (!LinuxFdUnbind(p, static_cast<u32>(acquired_fd), &acquired_detached))
        core::Panic("proc/linux-fd", "self-test: acquired identity unbind failed");
    if (acquired_detached.snapshot.generation != acquired_generation ||
        p->linux_fds[static_cast<u32>(acquired_fd)].generation == acquired_generation)
        core::Panic("proc/linux-fd", "self-test: fd generation did not advance across unbind");
    LinuxFdDetachedRelease(&acquired_detached);
    LinuxFdAcquiredRelease(&acquired);
    if (g_lfd_selftest_release_calls != 0)
        core::Panic("proc/linux-fd", "self-test: acquired identity released backing too early");
    LinuxFdAcquiredRelease(&acquired_clone);
    if (g_lfd_selftest_release_calls != 1 || g_lfd_selftest_release_idx != 0xD00D)
        core::Panic("proc/linux-fd", "self-test: acquired identity final release imbalance");
    if (acquired_ofd == 0 || g_ofd_pool[acquired_ofd - 1].refcount != 0)
        core::Panic("proc/linux-fd", "self-test: acquired identity leaked its OFD");

    // 10) Pair publication is atomic and exact duplicate replacement adopts
    // the new KFile before returning the displaced object for deferred cleanup.
    auto pair_a_kfile =
        ::duetos::ipc::KFileCreate(::duetos::ipc::KFileKind::Eventfd, 0xE001, &LinuxFdSelfTestRelease, nullptr, 0);
    auto pair_b_kfile =
        ::duetos::ipc::KFileCreate(::duetos::ipc::KFileKind::Eventfd, 0xE002, &LinuxFdSelfTestRelease, nullptr, 0);
    if (!pair_a_kfile.has_value() || !pair_b_kfile.has_value())
        core::Panic("proc/linux-fd", "self-test: pair KFileCreate failed");
    Process::LinuxFd pair_a_payload{};
    pair_a_payload.state = 5;
    pair_a_payload.first_cluster = 0xE001;
    pair_a_payload.kf_handle = ::duetos::ipc::kHandleInvalid;
    Process::LinuxFd pair_b_payload{};
    pair_b_payload.state = 5;
    pair_b_payload.first_cluster = 0xE002;
    pair_b_payload.kf_handle = ::duetos::ipc::kHandleInvalid;
    LinuxFdPrepared pair_a{};
    LinuxFdPrepared pair_b{};
    if (!LinuxFdPrepare(&pair_a, pair_a_payload, &pair_a_kfile.value()->base, 0) ||
        !LinuxFdPrepare(&pair_b, pair_b_payload, &pair_b_kfile.value()->base, 0))
        core::Panic("proc/linux-fd", "self-test: pair prepare failed");
    u32 pair_a_fd = 0;
    u32 pair_b_fd = 0;
    if (!LinuxFdBindPairLowest(p, 3, &pair_a, &pair_b, &pair_a_fd, &pair_b_fd) || pair_a_fd == pair_b_fd)
        core::Panic("proc/linux-fd", "self-test: atomic pair bind failed");
    g_lfd_selftest_release_calls = 0;
    g_lfd_selftest_release_idx = 0;
    if (!LinuxFdDuplicateExact(p, pair_a_fd, pair_b_fd, false))
        core::Panic("proc/linux-fd", "self-test: exact duplicate replacement failed");
    if (g_lfd_selftest_release_calls != 1 || g_lfd_selftest_release_idx != 0xE002)
        core::Panic("proc/linux-fd", "self-test: displaced exact-dup backing was not released once");
    LinuxFdClose(p, pair_a_fd);
    if (g_lfd_selftest_release_calls != 1)
        core::Panic("proc/linux-fd", "self-test: exact-dup shared backing released too early");
    LinuxFdClose(p, pair_b_fd);
    if (g_lfd_selftest_release_calls != 2 || g_lfd_selftest_release_idx != 0xE001)
        core::Panic("proc/linux-fd", "self-test: exact-dup final backing release imbalance");

    // 11) Generation exhaustion is terminal for a numeric slot. Closing a
    // live max-generation identity must preserve the saturated epoch and the
    // lowest-free search must skip that otherwise-empty row forever.
    Process::LinuxFd& exhausted_slot = p->linux_fds[15];
    exhausted_slot.state = 5;
    exhausted_slot.generation = Process::kLinuxFdGenerationExhausted;
    exhausted_slot.kf_handle = ::duetos::ipc::kHandleInvalid;
    exhausted_slot.ofd = 0;
    LinuxFdDetached exhausted_detached{};
    if (!LinuxFdUnbind(p, 15, &exhausted_detached))
        core::Panic("proc/linux-fd", "self-test: saturated fd detach failed");
    LinuxFdDetachedRelease(&exhausted_detached);
    u32 forbidden_next = 7;
    if (exhausted_slot.state != 0 || exhausted_slot.generation != Process::kLinuxFdGenerationExhausted ||
        LinuxFdAllocLowest(p, 15) >= 0 ||
        LinuxFdNextGeneration(Process::kLinuxFdGenerationExhausted, &forbidden_next) || forbidden_next != 0)
    {
        core::Panic("proc/linux-fd", "self-test: saturated fd slot became reusable");
    }

    mm::KFree(q);
    mm::KFree(p);
    arch::SerialWrite("[proc] linux-fd-table self-test OK\n");
}

} // namespace duetos::core
