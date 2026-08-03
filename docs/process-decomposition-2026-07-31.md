# Process decomposition implementation map

Date: 2026-07-31

Status: architecture and migration plan only. This document does not authorize a bulk rewrite.

Source boundary: this map was produced while the repository-wide resource preflight was at HARD STOP. No compiler, emulator, or new worker was launched for this audit. All implementation and runtime gates below remain required.

## Decision

The current Process struct is simultaneously:

- a lifetime and identity object;
- the sole AddressSpace owner;
- a security principal;
- a scheduler policy record;
- a Linux process, file, signal, timer, and parent-state container;
- a Win32 loader, heap, TLS, handle, section, APC, and compatibility container;
- a registry for kernel objects and backend resources; and
- the teardown script for all of those systems.

That shape cannot be made safe by adding another lock to Process. The target is a small ProcessCore that owns exact, generation-safe keys to independently synchronized services and ABI sidecars. The migration must be a compiling strangler: introduce one service behind an adapter, switch its consumers, prove its lifetime and concurrency properties, and only then remove the old fields.

The first implementation slice after the current source barrier should be AuthorizationContext. Credentials, ThreadGroup, ResourceDomain, HandleTable, LoadPlan, LoadImage, and ExecAdmission already provide the shape needed for the remaining migration, but most are not yet wired into Process.

## Non-negotiable invariants

1. PID, TID, a slot index, and a raw pointer are never sufficient authority. Any identity that can be recycled must include a non-zero, non-wrapping generation.
2. ProcessCore is unpublished until every mandatory owner, sidecar, image mapping, primary Task identity, ThreadGroup attachment, and Job assignment has a rollback path.
3. Publication is one-way. A published Task may run and be reaped on another CPU immediately; the creator must not inspect Task or Process state after the scheduler publication call unless it owns a separate retained reference.
4. ProcessCore owns exactly one AddressSpace reference. Section views are detached and unmapped before that reference is released.
5. No sidecar lock may be held across allocation, user copy, filesystem or network I/O, a wait, scheduler entry, ProcessRelease, KObjectRelease, SectionRelease, or an arbitrary backend callback.
6. The only allowed VM lock order is Process VM transaction gate, then AddressSpace mutation lock. The reverse order is forbidden.
7. Last-task exit and last-Process-reference release are different events. Strong-reference cycles through process handles and jobs are broken at last-task exit, before ProcessRelease can reach zero.
8. Destruction is detach-under-lock and release-outside-lock. Every released object is represented by an exact detached key or owned pointer.
9. PID-wide backend sweeps are compatibility fallbacks, not the target ownership model. New backends return exact owner tokens that are registered before publication and consumed once at teardown.
10. Linux task state belongs to Task even when the current implementation stores it on Process. In particular, signal masks, signal-frame stacks, task names, and task-directed pending signals are not process-global.
11. Win32 APCs target a Task incarnation. They do not live in an untagged process-wide queue keyed only by TID.
12. Every object family must survive at least 10,000 create, publish, rollback, detach, release, stale-key, reuse, and terminal-state cycles under host sanitizers before it can replace production state.

## Current lifetime boundary

The current code has several valuable contracts that the decomposition must preserve.

### Construction

ProcessCreate currently:

1. allocates and zeroes Process;
2. acquires a ResourceDomain before PID allocation or scheduler publication;
3. inherits the caller's exact ResourceDomain or creates a trusted/sandbox domain;
4. allocates the monotonic PID;
5. initializes all embedded tables and policy fields; and
6. publishes the object to its caller with refcount one.

ProcessReplaceResourceDomainBeforePublish is explicitly pre-publication-only. That contract should become the general rule for all key replacement.

Spawn then populates loader and ABI state before SchedCreateUserPrepared. The scheduler adopts the caller's Process reference on both success and failure. Once the Task is put on a runqueue, the creator cannot safely read either Task or Process without another pin.

### Last-task exit

The scheduler reaper currently performs work that cannot be deferred to ProcessRelease:

1. reap per-Task window state;
2. if this is the last Task, notify Job of process exit;
3. drop all Process-owned Win32 process handles;
4. drain jobs owned by the Process; and
5. release the Task's Process reference.

This ordering is essential for process-handle cycles: a self-process handle or an A-to-B and B-to-A pair holds Process references, so those rows must be detached before ProcessRelease can reach zero. Jobs no longer retain ProcessCore; their last-task notification and owner drain remain here to publish exact completion/accounting state before handle teardown and to retire creator authority deterministically.

### Last-reference destruction

The current ProcessRelease order is:

1. reap windows/compositor state by PID, cancel popup state, and release GDI state;
2. notify the Linux parent and wake its waiters after releasing the parent queue lock;
3. drop any remaining process-handle rows;
4. drain SysV shared-memory attachments;
5. detach Section view rows, unmap views, and release Section references;
6. release the sole AddressSpace reference;
7. dump Win32 diagnostics and clean the custom Win32 state;
8. close every Linux fd before draining the unified HandleTable;
9. drain the HandleTable;
10. release sockets by owner PID;
11. emit leak diagnostics;
12. sweep Win32 file rows, pipes, and named-pipe registrations;
13. free directory snapshots;
14. clear stdin focus;
15. release ResourceDomain; and
16. free Process.

The target does not preserve this as one large function. It preserves its dependency edges while moving each action to the service that owns the state.

## Target ownership graph

~~~mermaid
flowchart TD
    P["ProcessCore<br/>identity, refcount, lifecycle"] --> AS["AddressSpaceOwner<br/>AddressSpace plus VM gate"]
    P --> A["AuthorizationContextKey<br/>DuetOS caps and enforcement"]
    P --> C["CredentialKey<br/>POSIX identity and Win32 integrity"]
    P --> T["ThreadGroupKey<br/>exact Task incarnations"]
    P --> J["JobKey<br/>membership identity"]
    P --> R["ResourceDomainKey<br/>spawn-tree quotas"]
    P --> F["FilesystemNamespaceKey<br/>root and cwd context"]
    P --> H["HandleRegistryKey<br/>KObject-backed handles"]
    P --> B["BackendRegistryKey<br/>exact teardown tokens"]
    P --> N["NativeAbiSidecar"]
    P --> L["LinuxAbiSidecar"]
    P --> W["Win32AbiSidecar"]
    L --> LF["LinuxFdTable"]
    L --> LS["LinuxSignalGroupState"]
    L --> LT["LinuxTimerState"]
    L --> LV["LinuxVmState"]
    W --> WI["Win32ImageState"]
    W --> WM["Win32MemoryState"]
    W --> WT["Win32TlsNamespace"]
    W --> WV["SectionViewRegistry"]
    H --> KO["KObject implementations"]
    B --> BE["socket, pipe, window, GDI, console, custom backends"]
    T --> TK["Task-local start context, signal mask/frame, APC, TLS values"]
~~~

The arrows are ownership edges from ProcessCore to retained service keys. They are not permission to follow a raw pointer after releasing a pin.

## Minimal ProcessCore

ProcessCore should contain only fields needed to identify, retain, publish, and route the process to its owners:

| Member | Ownership and mutation rule |
|---|---|
| ProcessKey key | Immutable exact process identity. Contains the external PID plus an internal incarnation if PID reuse is ever introduced. |
| atomic refcount | Strong lifetime count. Saturating retain and exact final release remain mandatory. |
| ProcessLifecycle lifecycle | Constructing, Published, Exiting, Retired. Monotonic and independently synchronized. |
| immutable name | Owned bounded diagnostic label. Never an incoming borrowed pointer. |
| AddressSpaceOwner address_space | Sole AddressSpace reference plus the sleepable VM transaction mutex. |
| AuthorizationContextKey authorization | Owned key to DuetOS capability and enforcement state. |
| CredentialKey credentials | Owned key to immutable POSIX credentials and Win32 integrity metadata. |
| ThreadGroupKey thread_group | Owned key to exact member Task incarnations and group lifecycle. |
| optional JobMembershipKey job | Generation-safe non-owning membership route, only if direct ProcessCore lookup is proven necessary. Current Job completion records are discovered by exact ProcessKey and create no ProcessCore ownership edge. |
| ResourceDomainKey resource_domain | Owned spawn-tree resource-domain reference, immutable after publication. |
| FilesystemNamespaceKey fs_namespace | Owned immutable root plus synchronized working-directory state. |
| HandleRegistryKey handles | Owned registry containing KObject references. |
| BackendRegistryKey backends | Owned collection of exact teardown tokens. |
| AbiKind abi_kind | Native, Linux, or Win32. Immutable after successful exec commit. |
| AbiSidecarKey abi | Exactly one sidecar matching AbiKind. Replaceable only inside an unpublished spawn or an atomic exec transaction. |

Fields such as entry RIP, initial RSP, GS base, main stack, task name, signal mask, and APC queue do not belong in ProcessCore. They are Task start or Task runtime state.

The ProcessCore header should forward-declare all services and expose narrow key/value APIs. It must not include filesystem, loader, GUI, network, Section, or Win32 syscall headers.

## Identity and key rules

### ProcessKey

The current PID is monotonic and therefore currently non-reused. Preserve that externally, but introduce ProcessKey now so callers stop assuming a u64 PID is a lifetime pin. Lookup returns a retained ProcessRef or runs a callback while the registry lifetime lock is held; it never returns an unpinned raw pointer.

### CredentialKey

CredentialKey names an immutable credential object. It includes:

- POSIX real/effective/saved UID and GID;
- supplementary groups;
- POSIX permitted, effective, inheritable, and bounding capability masks; and
- Win32 integrity level.

These POSIX capability masks are not DuetOS CapSet. Conflating the two would let an ABI compatibility surface mutate kernel authorization.

Credential derivation creates a new object and returns a new key. Published credentials are never modified in place. Replacement on exec or set-id is an atomic key swap followed by release of the old key outside the Process lifecycle lock.

### ThreadGroupKey

ThreadGroup stores exact Task incarnation keys, not TIDs or Task pointers. Attach is legal only while Open. BeginExit moves Open to Exiting. Detach is idempotent for a live exact member. Final release is legal only in Exiting with no members and creates a terminal Retired generation.

ProcessCore owns the group key; Task stores the same group key or an exact membership token. The Task detach path runs before dropping its Process reference.

### JobKey

Job rows now contain bounded `{ProcessKey, exited}` completion records and never retain or borrow `Process*`. Owner authorization, assignment, exit replay, termination intents, and scheduler resolution all use the full non-recycled `ProcessKey`. This closes the original Job-to-Process lifetime cycle, but `JobKey` still names a Job row/handle authority rather than a per-Process membership object.

Migration rule:

1. preserve last-task `JobOnProcessExit(ProcessKey)` and exact owner-drain ordering;
2. keep termination intents as copied ProcessKeys protected by a Job operation pin;
3. retain completed keys only as bounded completion records until termination completion or row retirement, so a stale dead-Process handle cannot publish the same incarnation into another Job;
4. prove self-handle, mutual-handle, assignment/exit replay, termination/close, and owner-drain races under host and 2/4-vCPU QEMU stress; and
5. introduce a separate generation-safe membership key only if ProcessCore needs direct membership routing. Never restore a Job-to-Process strong edge.

### ResourceDomainKey

ResourceDomain remains a spawn-tree service, not an ABI sidecar. A child retains the parent's exact key. Quota charge tokens retain exact domain identity until the charged object is released. ResourceDomain must be acquired before any object that could publish a charge.

### HandleRegistryKey

The handle registry owns KObject references and generations. Public ABI handle encodings are adapters over registry Handle values; low tag bands remain wire compatible. HandleTableDrain detaches entries under its lock and performs KObjectRelease after unlocking.

### BackendRegistryKey

BackendRegistry stores heterogeneous exact tokens with typed release functions. A token contains backend type, exact generation, and enough identity to reject reuse. It is registered transactionally when the backend resource is created. Teardown drains tokens once.

The registry must not hold its lock while invoking release functions. Drain first moves tokens to a bounded local batch, marks them consumed, unlocks, and then invokes typed releases.

## AuthorizationContext versus Credentials

AuthorizationContext is DuetOS kernel policy. Credentials is ABI identity metadata. They remain separate even when a syscall consults both.

### AuthorizationContext owns

- durable CapSet;
- monotonic cap ceiling;
- broker lease mask;
- per-cap lease deadline and generation;
- execution tick budget and used ticks, or a retained key to the execution accounting domain;
- sandbox denial count and one-shot kill latch;
- filesystem-write rate windows and lifetime byte telemetry; and
- trusted/sandbox launch profile provenance.

The tick and rate-limit fields may later move to a ResourceAccounting service. Keeping them behind AuthorizationContext initially is a smaller safe extraction because their current consumers are security denial and scheduler enforcement paths.

### AuthorizationContext API

The initial adapter surface should be:

- AuthorizationCreateTrusted and AuthorizationCreateSandbox;
- AuthorizationDeriveForSpawn;
- AuthorizationRetain and AuthorizationRelease;
- AuthorizationSnapshot;
- AuthorizationHas;
- AuthorizationGrantDurable;
- AuthorizationDropIrreversibly;
- AuthorizationGrantLease;
- AuthorizationRevokeLease;
- AuthorizationChargeTick;
- AuthorizationRecordDenial; and
- AuthorizationRecordFsWrite.

All APIs accept or return values and exact keys. None returns pointers to internal masks or arrays.

Lease expiry obtains monotonic time before taking the context spinlock. The lock protects only local state and never calls the grace cache, scheduler, clock service, logging, or kill path. APIs return an action result such as ThresholdCrossed; the caller performs logging and scheduler work after unlocking.

### Credentials owns

- UID/GID identity;
- supplementary groups;
- POSIX capability sets; and
- Win32 integrity.

Credential checks answer ABI questions. Authorization checks answer whether DuetOS permits a kernel operation. A Linux operation may require both, for example a POSIX ownership predicate and DuetOS kCapFsWrite.

## ABI sidecars

### NativeAbiSidecar

The native sidecar is intentionally small:

- immutable image metadata needed for diagnostics and module ownership;
- native ABI version;
- native launch-contract metadata; and
- optional console endpoint key.

Native user stacks and initial registers are Task state. Filesystem root, handles, credentials, authorization, jobs, and resource domains are common process services.

### LinuxAbiSidecar

LinuxAbiSidecar owns keys to:

- LinuxFdTable;
- LinuxVmState;
- LinuxImageState, including vDSO addresses;
- LinuxSignalGroupState;
- LinuxTimerState;
- LinuxChildState;
- LinuxResourceLimits;
- LinuxIpcAttachments; and
- LinuxFsContext.

Correct Task-local Linux state:

- blocked signal mask;
- nested signal-frame stack;
- task-directed pending signals;
- Linux task name;
- thread-specific clear/set-tid and robust-list state when added; and
- entry RSP and TLS/GS state.

The current process-wide linux_signal_mask and linux_signal_frame_va stack are correctness bugs for a multi-threaded Linux process. Moving them to Task is part of the ThreadGroup integration slice, not a mechanical sidecar copy.

Process-directed pending signals and signal dispositions remain ThreadGroup-shared in LinuxSignalGroupState. Delivery chooses a Task under scheduler and ThreadGroup lifetime protection.

### Win32AbiSidecar

Win32AbiSidecar owns keys to:

- Win32ImageState;
- Win32MemoryState;
- Win32TlsNamespace;
- SectionViewRegistry;
- Win32ProcessPolicy;
- Win32ConsoleState; and
- optional Win32CustomState.

Correct Task-local Win32 state:

- TEB and GS-base;
- per-Task TLS values and generations;
- current fiber and FLS values;
- user stack ownership;
- thread exit state or a retained KThread completion object;
- APC queue; and
- per-thread priority when supported.

APC delivery must target an exact Task incarnation. A process-wide array keyed by TID is replaced by a per-Task queue or KThread-owned queue. QueueUserAPC first resolves and pins KThread, then enqueues while that Task incarnation is live.

## Handle and object registry

The target has one KObject registry per process. ABI tables become encoding and policy adapters, not independent object owners.

| Current family | Target KObject | Notes |
|---|---|---|
| Mutex, event, semaphore, IOCP | Existing KMutex, KEvent, KSemaphore, IocpPort | Already using kobj_handles; keep generation-tagged encodings. |
| Linux pool-backed fd | KFile | LinuxFd stores descriptor flags and a Handle; OFD is a refcounted object shared by dup and fork. |
| Win32 file and pipe | KFile | Preserve exact row reservation during migration; cursor should live in a shared file description, not a raw table row. |
| Win32 registry key | KRegistryKey | Converts borrowed static RegKey pointer into typed object semantics. |
| Win32 process handle | KProcessRef or KProcessCompletion | Must not indefinitely retain live ProcessCore after last Task. See cycle redesign. |
| Local and foreign thread handle | KThread | One generation-safe encoding; completion state outlives scheduler Task storage. |
| Win32 Section handle | KSection | Handle reference is independent from mapped-view reference. |
| Win32 directory enumeration | KDirectorySnapshot | Owns the snapshot allocation; normal KObject release frees it. |
| Named kernel objects | Existing KObject wrappers | Name registry retains KObject, never ABI table rows. |

The Linux descriptor table remains a separate fd namespace because FD_CLOEXEC is per descriptor and POSIX dup/fork semantics share an open file description. Its object field is a registry Handle, not a pool index or raw pointer.

The Win32 low-tag ranges remain stable while the backing is migrated. Decoding validates tag, table generation, KObject type, and required access mask.

## Exhaustive current-field destination map

The groups below cover every stored field in Process. Constants and nested row types move with the group that owns their storage.

| Current Process fields | Destination | Owning synchronization | Adapter and migration rule | Main consumers or blockers |
|---|---|---|---|---|
| pid | ProcessCore ProcessKey | Process registry lock for lookup; immutable after allocation | ProcessPid and retained ProcessLookup | scheduler, procfs, pidfd, debugging, shell, Win32 process APIs; active lookup/lifetime claims |
| name_storage, name | ProcessCore immutable name | none after construction | ProcessNameView; retain owned bounded storage | diagnostics, scheduler labels, loader |
| refcount | ProcessCore | atomic CAS | ProcessRetain/ProcessRelease or typed ProcessRef | every Task and process handle |
| as | AddressSpaceOwner in ProcessCore | Process VM transaction mutex, then AddressSpace mutation lock | ProcessWithAddressSpace or retained AddressSpaceRef; no public writable pointer | spawn, exec, VM syscalls, sections, signals, debug; active VM claims |
| vm_transaction_lock | AddressSpaceOwner | this mutex is the outer lock | ProcessVmTransaction | active VM transaction work |
| resource_domain | ProcessCore ResourceDomainKey | ResourceDomain service lock | ProcessResourceDomainSnapshot and prepublish replacement | spawn, Sections, frame accounting; active resource-domain claim |
| cap_lock, caps, cap_ceiling, cap_leases, cap_lease_deadline_ns, cap_lease_generation | AuthorizationContext | context spinlock | existing ProcessCaps functions become forwarding adapters, then callers take AuthorizationContextKey | cap_gate, token syscalls, broker, grace cache, shell |
| root | FilesystemNamespace | immutable root key; service lock only for future namespace mutation | ProcessFsRootSnapshot | path routing, spawn inheritance |
| user_code_va | ABI ImageState, not core | immutable after image commit | ProcessImageEntrySnapshot | spawn, diagnostics |
| user_stack_va, stack, user_rsp_init | primary Task UserStack and TaskStartContext | Task lifetime plus user-stack allocator | prepared Task start package consumed at scheduler publication | active user-stack claim; spawn and fault handler |
| user_gs_base | TaskStartContext and Task architecture state | Task/scheduler lifetime lock | TaskInitialGsBase | Win32 TEB setup, context switch |
| user_is_pe32 | immutable Win32ImageState machine type plus Task entry mode | none after commit | ProcessMachineType and TaskEntryMode | syscall entry, scheduler user entry |
| tick_budget, ticks_used | AuthorizationContext execution accounting, later ResourceAccounting | atomic charge or context-local lock | AuthorizationChargeTick returning action | timer IRQ and scheduler; must not block |
| sandbox_denials, sandbox_kill_flagged | AuthorizationContext enforcement counters | atomics or context lock | AuthorizationRecordDenial returning first-cross action | syscall denial paths |
| fs_write_bytes_total, fs_write_window_bytes, fs_write_window_start_tick | AuthorizationContext enforcement counters, later ResourceAccounting | context-local lock; clock sampled before lock | AuthorizationRecordFsWrite returning crossed window | Win32/Linux file write paths and attack simulation |
| heap_base, heap_pages, heap_free_head | Win32MemoryState default heap | Win32Memory mutex plus Process VM transaction for map/unmap | Win32HeapAlloc/Free facade | Win32 heap syscalls |
| linux_fds and LinuxFd fields state, flags, ofd, first_cluster, size, kf_handle, offset, path | LinuxFdTable | new sleepable fd-table mutex; KObject and OFD refs detached before release | LinuxFd* functions forward to table; no direct field access | syscall_io, async I/O, pipe, pidfd, file, msgq; largest migration blocker |
| linux_brk_base, linux_brk_current | LinuxVmState | Process VM transaction plus LinuxVm local state lock | LinuxBrkTransaction | Linux syscall_mm, spawn/exec |
| linux_mmap_cursor | common AddressSpace allocation policy or LinuxVmState | Process VM transaction | existing ProcessReserveMmapRange adapter | Linux mmap, zero-hint Win32 VM and Section callers; active VM claims |
| linux_vdso_base, linux_vdso_rt_sigreturn_va, linux_vdso_clock_gettime_va, linux_vdso_gettimeofday_va, linux_vdso_time_va, linux_vdso_getcpu_va | immutable LinuxImageState | none after image commit | LinuxVdsoSnapshot | signal delivery, auxv, time syscalls |
| abi_flavor | ProcessCore AbiKind | immutable after spawn; atomic exec commit | ProcessAbiKind | syscall entry |
| _abi_pad | no semantic destination | none | delete when AbiKind layout is introduced; use explicit serialization rather than struct padding | none |
| win32_iat_misses, win32_iat_miss_count | Win32ImageState diagnostics | loader-state mutex because runtime loads may add entries | Win32ImageRecordMiss and snapshot iterator | PE loader, pemiss diagnostics |
| dll_images, dll_image_count | Win32ImageState module registry | sleepable loader-state mutex; no borrowed buffer expiry | Win32ModuleRegister/Resolve; eventually own parsed metadata | loader, GetProcAddress, unwind, diagnostics |
| sxs_volume, sxs_dir | immutable Win32ImageState origin/search policy | none after image commit | Win32SxsOriginSnapshot | PE spawn, LoadLibrary |
| win32_file_operation_locks, win32_file_lock, win32_handles | temporary Win32FileTable, then HandleRegistry KFile | per-operation sleepable lock then row identity spinlock; never reverse; no I/O/release under spinlock | preserve reserve/publish/abort/acquire/detach APIs, then back them with KFile | file_route, Win32 file syscall, Linux/Win32 pipe and named-pipe; active file-lifetime claim |
| Win32 mutex/event/semaphore/IOCP bases/caps | Win32 handle codec next to adapters | no state | typed encode/decode functions | existing KObject handle work |
| win32_thread_lock, win32_threads | KThread objects plus ThreadGroup/Task state | scheduler lifetime lock and KThread lock; no Process row lock in target | local thread handles become HandleRegistry handles | thread syscalls, scheduler exit, file close; active Task and stack claims |
| win32_reg_handles | HandleRegistry KRegistryKey | HandleTable lock | registry adapter creates typed KObject | registry syscalls |
| win32_handle_lock, win32_proc_handles | HandleRegistry KProcessRef/KProcessCompletion | HandleTable lock; cycle break at last-task exit | existing process-handle APIs forward to object registry | process syscalls, scheduler reaper, jobs; active lifetime claims |
| win32_foreign_threads | same KThread handle namespace as local threads | scheduler lookup plus KThread pin | remove local/foreign dual table after typed handles land | thread syscalls and debug cap gates |
| win32_section_lock, win32_section_handles | HandleRegistry KSection | HandleTable lock; Section service own lock | keep exact reserve/publish/acquire/detach semantics | Section syscalls; active Section transaction claim |
| win32_section_views | SectionViewRegistry | registry identity lock only for detach/revalidate; VM transaction for map/unmap | reserve/publish/claim/restore/finish APIs move unchanged | ProcessRelease, Section map/unmap, fork; active Section/fork claims |
| win32_dirs | HandleRegistry KDirectorySnapshot | HandleTable lock; snapshot cursor lock inside object | directory adapter | directory and notify syscalls; Linux dirfd owner coupling is a blocker |
| thread_stack_cursor | UserStackAllocator associated with AddressSpace/ThreadGroup | sleepable allocator mutex plus VM transaction | UserStackReserve/Commit/Release | Win32 thread create; active user-stack claim |
| tls_lock, tls_slot_in_use, tls_slot_generation | Win32TlsNamespace | namespace spinlock | TlsReserve/Free/SnapshotGeneration | TLS syscalls; per-Task values remain Task |
| fls_lock, fls_slot_in_use, fls_slot_generation, fls_cleanup_callback | Win32TlsNamespace FLS subservice | namespace lock only for slot metadata; callbacks invoked unlocked | FlsReserve/Free; callback work queued to Task | FLS and fiber syscalls |
| _fls_pad0 | no semantic destination | none | delete with the embedded FLS layout | none |
| tls_present, tls_tmpl_src_va, tls_tmpl_raw, tls_tmpl_zerofill, tls_index_va, tls_cb_count, tls_callbacks | immutable Win32ImageState static-TLS descriptor | loader-state mutex until image seal, immutable afterward | Win32StaticTlsSnapshot | PE loader and thread create |
| tls_thread_region_cursor | UserStack/TEB region allocator, not TLS metadata | allocator mutex plus VM transaction | Win32ThreadEnvironmentReserve | thread creation |
| vmap_base, vmap_pages_used, vmap_regions | Win32MemoryState | memory-state mutex outside Process VM transaction; exact documented order is VM transaction then memory-state lock | Win32VirtualMemory facade | VM syscalls and page-fault guard handling |
| linux_sigactions | LinuxSignalGroupState | signal-group spinlock | LinuxSigactionSnapshot/Replace | signal syscalls and delivery |
| linux_signal_mask | Task LinuxSignalState | Task/scheduler lifetime lock or task-local atomic snapshot | LinuxTaskSignalMask* | rt_sigprocmask, delivery; current process scope is incorrect |
| linux_pending_signals | split into group-pending and Task-pending signal state | signal-group or Task signal lock | LinuxQueueProcessSignal and LinuxQueueTaskSignal | kill, tgkill, pidfd, signalfd |
| linux_signal_frame_va, linux_signal_frame_depth | Task LinuxSignalState | target Task lifetime lock; only target consumes return frame | LinuxTaskPush/PopSignalFrame | signal delivery and rt_sigreturn; current process scope is incorrect |
| linux_signal_wq | LinuxSignalGroupState or signalfd KFile | WaitQueue protocol plus signal lock | LinuxSignalWait | signalfd |
| linux_rlimit_nofile_cur, linux_rlimit_nproc_cur | LinuxResourceLimits | small service lock or atomics | LinuxRlimitSnapshot/Set | fd allocation, clone, prlimit |
| linux_alarm_deadline_ns, linux_alarm_interval_ns, linux_posix_timers | LinuxTimerState | timer-state spinlock; clock read before lock; delivery after unlock | LinuxTimerArm/Snapshot/CollectExpired | timer syscalls and dispatch return hook |
| linux_parent_pid, linux_exit_code, linux_was_signaled, linux_exit_signal, linux_child_exit_count, linux_child_exits, linux_child_exit_lock, linux_wait_wq | LinuxChildState using ProcessKey and bounded exit records | child-state lock; wake after unlock | LinuxChildPublishExit/Wait | clone/fork, exit, wait4/waitid; PID-only parent is a stale-identity risk |
| _linux_exit_pad | no semantic destination | none | delete with the embedded child-exit layout | none |
| win32_custom_state | typed Win32CustomStateKey or BackendRegistry token | custom service lock | Win32CustomAcquire/Cleanup | custom.cpp; cleanup callback must run unlocked |
| linux_cwd | FilesystemNamespace/LinuxFsContext | fs-context mutex | FsContextGetCwd/SetCwd | path syscalls |
| linux_task_name | Task | Task lifetime lock | TaskCommGet/Set | prctl; current process scope is incorrect |
| linux_shm_attaches, linux_shm_cursor | LinuxIpcAttachments plus LinuxVmState | attachment lock for rows, VM transaction for mapping | LinuxShmAttach/Detach/Drain | SysV IPC and Process teardown |
| kobj_handles | HandleRegistry service | HandleTable internal lock | ProcessHandles adapter | IPC and Win32 object syscalls |
| pe_image_base | immutable Win32ImageState | none after image commit | Win32MainModuleBase | GetModuleHandle and unwind |
| stdin_ring and waiters | ConsoleEndpoint KObject or Native/Win32 console key | endpoint queue lock; SPSC only if enforced by endpoint ownership | ConsoleRead/Feed | keyboard reader and native stdin; current Process SPSC assumption breaks with multiple readers |
| apc_slots | per-KThread APC queue | KThread/APC queue lock | KThreadQueueApc/KThreadDrainApc | APC syscalls; active Task identity work |
| win32_priority_class | Win32ProcessPolicy or Job scheduling policy | atomic or policy lock | ProcessPriorityClassGet/Set | MLFQ enqueue and priority syscalls |
| _priority_pad | no semantic destination | none | delete with the embedded priority layout | none |
| std_handles | Win32 launch handle set backed by HandleRegistry | immutable after spawn or policy lock for SetStdHandle | Win32StdHandleGet/Set | CreateProcess and kernel32 I/O |
| extra_heaps | Win32MemoryState | memory-state mutex plus VM transaction | Win32HeapCreate/Destroy | heap syscalls |
| compat_policy | immutable Win32ImageState | none after image commit | Win32CompatPolicySnapshot | compatibility call sites |
| manifest | immutable Win32ImageState | none after image commit | Win32ManifestSnapshot | loader, activation and UI policy |

## Lock model

### Global order

When more than one lock is necessary, the target order is:

1. registry lifetime pin or retained key, with no registry lock left held;
2. Process VM transaction mutex, when the operation changes mappings;
3. one sidecar sleepable transaction mutex;
4. one sidecar identity spinlock for a bounded snapshot or commit;
5. backend-internal lock, acquired only after Process and sidecar locks are released.

This is not permission to routinely nest all five. Normal code retains exact identities under one lock, unlocks, performs work, and revalidates to commit.

### Existing ordering to preserve

- VM transaction mutex before AddressSpace mutation lock.
- Win32 file operation mutex before win32_file_lock.
- win32_file_lock and pipe-pool lock are never nested.
- Section row lock is released before Section retain/release, mapping, unmapping, allocation, or user copy.
- Linux child-exit lock is released before waking waiters.
- HandleTable lock is released before KObjectRelease.
- Process/job handle cycles are drained from last-task exit, not destructor.

### Missing synchronization exposed by the audit

The current struct has no explicit owner lock adjacent to several mutable families: Linux fd rows, several Linux signal and timer fields, Win32 directory rows, vmap rows, APC slots, std handles, and extra heaps. Some are protected only by single-task assumptions or unrelated caller serialization. Decomposition must not preserve those assumptions as implicit contracts.

Each extraction begins by defining one synchronization owner and routing all access through adapters before moving storage. Adding a sidecar pointer while leaving direct field access in parallel is not a migration.

## Construction, publication, and rollback

The target spawn transaction is:

1. Validate executable bytes and policy into an immutable LoadPlan. No Process exists.
2. Admit the plan through ExecAdmission. The returned token is exact and single-consume.
3. Create an unpublished LoadImage staging package with owned mappings and rollback metadata.
4. Snapshot the parent's retained keys. Derive AuthorizationContext, Credentials, ResourceDomain, FilesystemNamespace, and Job policy without holding parent locks across allocation.
5. Create the HandleRegistry and BackendRegistry.
6. Create the selected ABI sidecar and all mandatory subservices.
7. Allocate AddressSpace and install LoadImage while holding the unpublished VM transaction. Nothing is globally discoverable.
8. Allocate ProcessCore with refcount one and lifecycle Constructing. Adopt all service keys and the sole AddressSpace reference.
9. Reserve an exact Task incarnation and build TaskStartContext, including owned user stack, entry RIP/RSP, architecture mode, GS/TEB, and ABI dispatch.
10. Create ThreadGroup with the exact leader Task key and attach the reserved Task.
11. Establish Job membership with an explicit rollback token. The Job publishes only the exact ProcessKey completion record; preserve the post-publication zero-live-task replay and last-task completion ordering.
12. Seal mutable loader state and validate that AbiKind matches the sidecar and Task entry mode.
13. Atomically transition ProcessCore to Published and publish the Task to scheduler/lookup registries. Scheduler adopts the creator Process reference on both success and failure.
14. Consume ExecAdmission and LoadImage tokens. The creator performs no unpinned read after scheduler publication.

Rollback runs in exact reverse order. Each step consumes only its own unpublished token:

1. abort Task reservation and release its user stack;
2. detach Task from ThreadGroup, begin group exit, and release group;
3. cancel Job assignment;
4. destroy ProcessCore without running published-process backend sweeps;
5. release ABI sidecar, registries, filesystem namespace, credentials, authorization, and resource domain;
6. unmap staged image and release AddressSpace;
7. cancel LoadImage and ExecAdmission.

Every failure edge needs a deterministic host fault-injection point. Rollback must be idempotent and leave every pool at its baseline live count.

## Exec transaction

Exec is not in-place mutation of dozens of fields. It prepares a replacement package while the current image remains runnable:

1. validate and admit a new LoadPlan;
2. prepare new Credentials, Authorization derivation, ABI sidecar, TaskStartContext, and LoadImage;
3. acquire the Process VM transaction mutex;
4. revalidate single-thread/group state and exact Process incarnation;
5. close FD_CLOEXEC descriptors at the documented commit point;
6. atomically swap AddressSpace image state, AbiKind, ABI sidecar, credentials, authorization policy, and primary Task start state;
7. release the old ABI sidecar and image resources after unlocking; and
8. roll back the new package on every pre-commit failure without changing the old process.

Exec must never expose a Linux AbiKind with a Win32 sidecar, an old credential with a new image, or a new AddressSpace with old Section view records.

## Teardown protocol

### Per-Task exit

1. Mark the exact Task incarnation exiting.
2. Stop new Task-directed APC and signal delivery.
3. publish KThread completion and exit code exactly once;
4. detach Task-owned user stack, TEB/TLS/FLS values, APCs, and signal frames;
5. reap per-Task GUI/window state by exact Task/Window identity;
6. detach the exact ThreadGroup membership;
7. if this was the final group member, run the last-task process boundary below; and
8. drop the Task's Process reference.

### Last-task process boundary

This runs once before the last Task drops its Process reference:

1. transition ProcessCore Published to Exiting;
2. stop new externally initiated Task creation and backend publication;
3. publish process completion state;
4. notify Job using the exact ProcessKey completion record;
5. detach and release all Process-owned process handles, including self and peer references;
6. drain jobs owned by the Process;
7. cancel remaining process-directed GUI/message delivery; and
8. begin ThreadGroup exit.

No operation here waits while holding the scheduler global lock. The scheduler reserves exact work under its lock, releases the lock, runs service transitions, and then commits bounded scheduler state if required.

### Last-reference ProcessCore destruction

1. Assert lifecycle Exiting and that ThreadGroup has no live members.
2. Freeze HandleRegistry, BackendRegistry, Linux child publication, and ABI sidecar creation.
3. Detach Linux child-exit notification data and enqueue it to the retained parent ProcessKey. Wake waiters after unlocking.
4. Close Linux fds. Until every fd object is fully unified, this precedes HandleRegistry drain so KFile/OFD callbacks still see their required pools and directory snapshots.
5. Drain HandleRegistry to a detached batch and release KObjects outside its lock.
6. Claim every Section view, unmap each exact VA under the VM transaction, and release each Section reference. No live or claimed view may remain.
7. Drain Linux shared-memory attachments and other address-space borrowing registries.
8. Drain exact BackendRegistry tokens for sockets, pipes, windows, GDI, popup state, console focus, and custom state. PID sweeps are allowed only as assertions/fallback during migration.
9. Release the sole AddressSpace reference.
10. Emit diagnostics from detached snapshots; diagnostics cannot reacquire a retiring Process through PID lookup.
11. Release ABI sidecar subservices.
12. Release FilesystemNamespace, Job membership state, ThreadGroup, Credentials, AuthorizationContext, and ResourceDomain.
13. mark the ProcessKey generation Retired and free ProcessCore.

The final service-release order may be mechanically topologically sorted from declared dependencies, but it must preserve: views before AddressSpace; Linux fds before dependent KFile pools; backend tokens before their owner service shutdown; and ResourceDomain after its last charge token.

## Reference cycles and dependency hazards

| Cycle or hazard | Why destructor-only cleanup fails | Required break |
|---|---|---|
| Process self-handle | The handle owns a Process ref, so refcount never reaches destructor | drain owned process handles at last-task exit |
| Process A to B and B to A | Both remain above zero with no Tasks | drain each owner's handles at its last-task exit |
| Job membership and Process lifetime | A Job-owned Process ref formed a cycle and PID-only completion could hit a later incarnation | resolved in core: exact ProcessKey completion records, no Process ref, last-task replay, copied-key termination intent; runtime stress remains |
| Task to Process and Process/ThreadGroup membership | Task owns Process ref while group records Task | detach exact membership before dropping Task Process ref |
| Section view to Section frames and AddressSpace mappings | AddressSpace teardown cannot infer borrowed Section frames | claim/unmap view registry before AddressSpace release |
| Linux fd to KFile to pool object and OFD | raw close ordering can double-release or release a pool before KFile callback | exact fd detach; close fds before transitional HandleTable drain |
| Linux dirfd to Process-owned directory snapshot | KFile callback currently needs owner Process | migrate snapshot to KDirectorySnapshot object; remove Process callback capture |
| backend object keyed only by PID | PID reuse or delayed callback can destroy a new owner's resource | exact BackendOwnerToken with generation |
| GUI HWND/GDI/menu side tables | slot or pointer reuse can route stale state | generation-safe HWND and exact Task/Window ownership |
| stdin focus raw Process pointer | producer can race teardown or multi-CPU release | retained ConsoleEndpoint key and explicit focus registry |

## Lock-inversion hazards to eliminate

1. Never call ProcessRelease while holding a Process sidecar or scheduler registry lock.
2. Never call Job, ThreadGroup, GUI, Section, socket, filesystem, or clock code while holding AuthorizationContext lock.
3. Never retain or release a Section while holding SectionViewRegistry identity lock.
4. Never perform file/pipe I/O, wait, user copy, allocation, or backing release under a file-row spinlock.
5. Never wake linux_wait_wq or linux_signal_wq while holding the producer state lock.
6. Never run FLS cleanup callbacks while holding the FLS namespace lock.
7. Never acquire Process VM transaction while holding an AddressSpace mutation lock.
8. Never call a backend release function under BackendRegistry lock.
9. Never perform ThreadGroup/Job/Process destruction under the global scheduler lock.
10. Never consult a PID/TID lookup result after its pin or callback boundary expires.

## Compiling strangler sequence

Every numbered item is intended to be a small reviewable commit or tightly related pair of commits. No item starts until its predecessors pass their host gates.

### 0. Freeze the contract

- Land this map and a short process-lifetime invariant checklist.
- Add a static check forbidding new direct Process fields without an ownership note.
- Record current ProcessCreate, scheduler publication, last-task, and ProcessRelease order in tests or assertions.

### 1. Add opaque core-facing types and forwarding accessors

- Introduce ProcessKey, AbiKind, and typed key members without moving storage.
- Add retained lookup APIs and deprecate raw PID lookup.
- Make new code use accessors; existing direct consumers remain temporarily.

### 2. Extract AuthorizationContext

- Implement the fixed-capacity, generation-safe service and 10,000-cycle host tests.
- Initialize it before Process publication and release it after all enforcement users stop.
- Point existing ProcessCaps, denial, tick, and write-rate functions at it.
- Switch cap_gate, broker, grace, token, scheduler, and write paths.
- Delete inline cap and enforcement fields only after direct-access scans are empty.

### 3. Wire Credentials

- Create trusted/sandbox credentials beside AuthorizationContext.
- Add immutable derive and atomic replacement APIs.
- Wire spawn inheritance first; then Linux UID/GID/group/cap and Win32 integrity consumers.
- Keep DuetOS CapSet checks separate.

### 4. Make ABI kind and sidecar presence explicit

- Add Native, Linux, and Win32 sidecar shells containing only keys/accessors.
- Construct exactly one before publication.
- Add invariants that reject mismatched AbiKind, machine mode, and sidecar.
- Do not move large tables yet.

### 5. Move immutable image metadata

- Move PE base, compatibility policy, manifest, SxS origin, machine type, static TLS descriptor, and Linux vDSO state.
- Then move DLL/module and IAT-miss registries behind a loader-state mutex.
- Stop storing borrowed loader buffers unless their lifetime is explicitly owned.

### 6. Integrate ThreadGroup and Task start state

- Reserve Task identity before publication.
- Attach exact leader/member identity to ThreadGroup.
- Move primary stack, entry RSP, GS/TEB, Linux task name, task signal mask/frame stack, and Task APC queue.
- Preserve the no-read-after-publication rule.

### 7. Redesign Job membership

- Implemented: Job rows contain exact ProcessKey completion records and no Process pointers or Process retains.
- Implemented: owner authority is exact, assignment uses a post-publication zero-live-task replay, and termination resolves copied keys through a retained scheduler lookup.
- Implemented: last-task teardown publishes Job completion before breaking owned process-handle cycles and draining owned Jobs.
- Pending: run the full self/mutual handle, assignment/exit, termination/close, and owner-exit campaigns under sanitizers and 2/4-vCPU QEMU and prove Process live counts return to baseline.
- Pending: decide whether the minimal ProcessCore needs a direct membership key. If it does, add a generation-safe non-owning membership token; do not reintroduce a strong Job-to-Process edge.

### 8. Extract the Linux fd table

- First add one owning mutex and eliminate direct row access through adapters.
- Preserve OFD sharing, FD_CLOEXEC, KFile handles, fork copying, and failure rollback.
- Remove owner-Process dependency from dirfd by introducing KDirectorySnapshot.
- Stress dup/fork/close and pidfd_getfd races before changing handle representation.

### 9. Migrate handle families one at a time

Suggested order:

1. registry handles;
2. directory snapshots;
3. local and foreign thread handles to KThread;
4. process handles to completion-safe KProcessRef;
5. Section handles to KSection;
6. Win32 files and pipes to KFile.

Keep public low-tag encodings stable. Each family removes its legacy table only after stale-generation and teardown tests pass.

### 10. Extract SectionViewRegistry and VM state

- Move Section view reserve/publish/claim/restore/finish unchanged.
- Move Linux brk/mmap/shm and Win32 vmap/heap arenas behind explicit VM transactions.
- Add failure injection at every reservation/map/commit edge.
- Prove exit during map/unmap cannot leak a frame or release a recycled Section.

### 11. Extract Linux signals, timers, child state, and limits

- Split group signal state from Task signal state.
- Replace parent PID with retained/exact ProcessKey or a completion endpoint.
- Move wake operations outside locks.
- Move timers to a service that samples time before locking and queues delivery after unlocking.

### 12. Extract Win32 TLS/FLS and memory services

- Move process-wide TLS/FLS namespaces while values remain per Task/fiber.
- Move heaps and vmap regions behind Win32MemoryState.
- Invoke cleanup callbacks and unmap work outside metadata locks.

### 13. Replace PID sweeps with BackendRegistry

- Add exact tokens for sockets, anonymous/named pipes, window/compositor/GDI/menu state, popup state, stdin focus, and custom state.
- Register tokens before backend publication.
- Drain exact tokens at exit and retain old PID sweeps temporarily as leak assertions.
- Remove PID sweeps after repeated QEMU exit storms show no residuals.

### 14. Shrink Process to ProcessCore

- Move filesystem namespace, console endpoint, priority policy, std handles, and remaining passive state.
- Delete compatibility aliases only after repository-wide direct-field scans are empty.
- Enforce a size and include-dependency budget for ProcessCore.

## Verification contract

### Per-service host gates

Every service or object family must pass:

- MSVC x64 strict build with /W4 /WX;
- Clang and GCC warning-clean builds where the host matrix supports them;
- CTest registration and direct test execution;
- ASan, UBSan, and LSan;
- TSan for every service with concurrent mutation;
- deterministic fixed-seed concurrency tests; and
- at least 10,000 lifecycle cycles with live-count baseline restored.

No sanitizer suppression is accepted for a newly introduced lifetime race.

### Required 10,000-cycle properties

| Family | Minimum property workload |
|---|---|
| ProcessCore transaction | fail each construction edge; rollback twice; publish/exit; stale ProcessKey; ref saturation/zero guards; final live count zero |
| AuthorizationContext | trusted/sandbox derive; ceiling drop; lease grant/revoke/expiry generation; concurrent snapshot; one-shot threshold actions |
| Credentials | immutable derive; restricted derivation cannot add UID/GID/groups/caps/integrity authority; stale key rejection; concurrent retain/release |
| ThreadGroup | create/attach/detach/begin-exit/retire; duplicate and stale Task key rejection; last-member races |
| Job completion record | assign/exit replay/close/owner drain; self and A/B handle cycles; termination/close races; exact key survives Process lifetime without retaining it |
| HandleRegistry | insert/duplicate/acquire/remove/drain; type confusion; generation exhaustion; concurrent close/wait |
| Linux fd/OFD/KFile | open/dup/fork/close/CLOEXEC; partial rollback; pool callbacks exactly once; dirfd snapshot lifetime; pidfd_getfd race |
| KThread/APC | create/open/close/exit/wait; stale handle; APC enqueue versus exit; exact target generation |
| Section handles/views | create/duplicate/map/unmap/close/exit; fault at every reserve/map/publish edge; frame/domain charges return to zero |
| VM state | brk/mmap/vmap/heap/shm plus concurrent foreign VM operation and exec; only permitted lock order |
| Signals/timers | per-Task masks and frames; nested depth; group versus task pending; delivery versus Task exit; timer delete/expiry race |
| Backend tokens | register/cancel/drain/reuse for each backend; stale generation cannot release a new object; callback exactly once |
| GUI/window/GDI | Task exit and Process exit storms; stale HWND/menu/HDC identities rejected; no PID-only residual |
| Console | focus transfer versus Process exit; multiple readers either serialized or rejected; no raw Process pointer race |

### Integration host gates

- Full tests/host configure and strict MSVC build.
- Full CTest with zero failures, including include_tracked after all intended files are staged.
- Static direct-access inventory proves each migrated field has no consumers outside its owning implementation and compatibility adapter.
- Static lock audit proves no prohibited lock nesting or external release under a sidecar lock.
- Fault-injection matrix records baseline live counts for Process, Task, AddressSpace, Section, ResourceDomain, Credential, ThreadGroup, Job rows/completion records, KObject, KFile, OFD, socket, pipe, window, and GDI families.

### QEMU gates

After the current machine preflight permits a kernel build and QEMU:

1. run profile-boot-smoke for every canonical profile:
   - bringup;
   - ring3;
   - pe-hello;
   - pe-winapi;
   - pe-threads;
   - pe-winkill; and
   - linux.
2. require the boot report pass, completion sentinel, and every per-profile signature checked by tools/test/profile-boot-smoke.sh;
3. repeat pe-threads and linux at SMP 1, 2, 4, and 8;
4. run tools/test/smp-stress-sweep.sh at its canonical SMP=8 topology for at least three clean repeats;
5. run a 10,000 spawn/exit campaign split across native, Linux, PE32, and PE32+ images, with process/thread handles, jobs, Sections, fds, pipes, sockets, and windows intentionally left open at exit;
6. inject spawn failures at every construction phase and require the kernel live-count report to return to baseline;
7. run self-handle and mutual-handle cycles plus job kill/close cases and require all Process objects to retire;
8. run Section map/unmap/exit races and require zero Section frames and ResourceDomain charges after the final reference;
9. run GUI task/process exit storms and reject every stale HWND/HDC/menu/APC target; and
10. analyze every serial log with tools/test/boot-log-analyze.sh and retain the logs as evidence.

The differential QEMU/Bochs matrix is required for changes that touch AddressSpace invalidation, scheduler publication, SMP lifetime, or Section mappings.

## Active source barrier

This document intentionally does not prescribe edits to files already held by active parallel claims. At the audit snapshot, the following relevant areas were unavailable:

- process.h, process.cpp, AddressSpace, scheduler process lifetime, and lookup callers;
- Win32 file-handle lifetime and pipe/named-pipe integration;
- scheduler Task affinity/publication and user-stack lifetime;
- Win32 Section transaction and Linux fork/Section cursor;
- Job service and job syscalls;
- KObject HandleTable v2 and its handle-family consumers;
- ResourceDomain;
- Credentials;
- ThreadGroup;
- GUI task message queues, window identity, GDI identity, and side tables;
- socket allocation transaction;
- loader LoadPlan, LoadImage, ExecAdmission, and execd protocol; and
- shared tests/host/CMakeLists.txt.

Implementation begins only after the exact intended files are unclaimed or the owners explicitly hand them off. A migration slice must rebase on the then-current branch and repeat the consumer/lock scan because this repository was changing during the audit.

## Architecture questions and recommended answers

### Should AuthorizationContext be embedded in ProcessCore?

No. Use a key to a separately refcounted service. Runtime broker leases and security snapshots are read from scheduler and syscall paths, and exec/spawn need transactional derivation. A key keeps ProcessCore small and supports immutable replacement.

### Should ResourceDomain absorb AuthorizationContext and Credentials?

No. ResourceDomain is shared across a spawn tree for aggregate quota accounting. Credentials and authorization may change at exec or privilege transition. Sharing them with the quota domain would make privilege changes affect siblings or force unnecessary domain splits.

### Should Linux and Win32 use separate Process types?

No. Keep one ProcessCore because scheduler, AddressSpace, credentials, jobs, resource accounting, and kernel-object ownership are common. Use exactly one ABI sidecar selected by immutable AbiKind. This avoids duplicated lifetime logic without forcing incompatible ABI state into one struct.

### Should all Linux fd state move directly into HandleTable?

No. The descriptor namespace still owns FD_CLOEXEC and maps an integer fd to a shared open-file description. Move the referred kernel object into HandleTable, but retain LinuxFdTable as the descriptor layer.

### Should Section views be normal handles?

No. A view is an AddressSpace mapping ownership record, not merely a user-visible handle. Closing every Section handle does not unmap views. Keep SectionViewRegistry separate and drain it before AddressSpace.

### Should ProcessCore own a strong Job reference immediately?

No. The Job-to-Process strong reference has been removed: Job rows now keep only exact ProcessKey completion records. ProcessCore should remain free of a Job ownership edge until runtime stress proves the new lifecycle, and any later direct membership field must be a generation-safe non-owning token rather than a Process-retaining reference.

### Should PID-based cleanup remain as defense in depth?

Temporarily. During migration, run exact token cleanup first and keep PID sweeps as diagnostic assertions or a bounded fallback. Remove them once exit-storm evidence proves exact registries are complete; otherwise they conceal missing ownership registrations and remain vulnerable to identity reuse.

### Should sidecars be heap allocated?

Use fixed-capacity service pools with generation keys where practical, matching Credentials, ThreadGroup, ResourceDomain, and kernel object services. Heap-backed variable payloads may be owned by a service, but ProcessCore should not store untyped heap pointers. Allocation failure must be an ordinary pre-publication rollback.

## Definition of complete

Process decomposition is complete only when:

- ProcessCore contains only identity, lifecycle, AddressSpace ownership, exact service keys, AbiKind, and one ABI sidecar key;
- no mutable ABI table remains directly accessible from ProcessCore;
- Task-local Linux and Win32 state has moved to exact Task/KThread ownership;
- process and job reference cycles terminate without relying on destructor reachability;
- all handle families use generation-safe KObjects or an explicitly justified descriptor layer;
- every backend resource has an exact teardown token;
- no PID-only or TID-only lookup grants lifetime or authority;
- all per-service and integration host gates pass;
- all canonical QEMU profiles and the required SMP/exit campaigns pass; and
- live counts and ResourceDomain charges return to baseline after every success, failure, and forced-exit campaign.
