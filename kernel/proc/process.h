#pragma once

#include "fs/fat32.h"
#include "ipc/handle_table.h"
#include "loader/compat_shim.h"
#include "loader/manifest.h"
#include "loader/dll_loader.h"
#include "proc/authorization_context.h"
#include "proc/credentials.h"
#include "proc/resource_domain.h"
#include "proc/user_stack.h"
#include "sched/sched.h"
#include "subsystems/win32/section.h"
#include "sync/spinlock.h"
#include "util/types.h"

// AddressSpace and RamfsNode are used in this header only via
// pointer fields and pointer-typed function signatures. Forward-
// declaring them lets the 80+ TUs that include proc/process.h
// skip the transitive parse of the full mm/ and fs/ headers; TUs
// that touch the actual struct members include the relevant
// header directly.
namespace duetos::mm
{
struct AddressSpace;
}
namespace duetos::fs
{
struct RamfsNode;
}

/*
 * DuetOS process + capability model — v0.
 *
 * A `Process` is the unit that owns user-visible state:
 *   - an `mm::AddressSpace` (its private PML4 and user-half tables)
 *   - a capability set (which privileged kernel operations it can
 *     request)
 *   - a name + pid for diagnostics
 *
 * A Task (see kernel/sched/sched.h) is a single thread of execution.
 * Every ring-3-bound Task belongs to exactly one Process; kernel-only
 * Tasks (idle, reaper, workers, drivers) have `process == nullptr`.
 * Multi-threaded processes (several Tasks sharing one Process)
 * become possible the day we grow ProcessRetain() callers beyond
 * "one retain per create"; the refcount is there already.
 *
 * ## Capability model
 *
 * Every syscall that lets user-mode observably affect the world
 * outside its own address space MUST be gated on a capability.
 * "Observably affect the world" = write to a device, spawn a task,
 * touch a file, send an IPC message, read a clock that reveals host
 * timing, etc. Syscalls that only read or mutate the caller's own
 * address space (SYS_GETPID, SYS_YIELD, SYS_EXIT) are unprivileged.
 *
 * Caps are a u64 bitmask. Up to 64 distinct caps today — more than
 * enough for v0. Promote to a variable-size array if we ever exceed
 * that.
 *
 * Profiles:
 *   - `kProfileSandbox` — empty set. The canonical "untrusted EXE"
 *     profile: zero ambient authority. Every syscall except
 *     GETPID / YIELD / EXIT returns -1. The process's address
 *     space is its entire observable universe — which is the
 *     "malicious code thinks its sandbox is the OS" goal.
 *   - `kProfileTrusted` — every defined cap. For internal kernel-
 *     shipped userland (the smoke tasks, init process, etc.).
 *
 * New caps are added at the END of the enum. Never renumber — a
 * capability number is ABI: a process image stored on disk with a
 * "requested caps" manifest would break if we reshuffled.
 */

namespace duetos::core
{

// u32 is a deliberate, ABI-adjacent width for this security-critical cap
// enum (see the "capability number is ABI" note above) — not a footprint
// choice worth narrowing.
// NOLINTNEXTLINE(performance-enum-size)
enum Cap : u32
{
    // Reserved. A process with kCapNone set explicitly still has
    // an empty cap set — the enum starts at 1 for the first real
    // cap so that `1ULL << Cap` is never 1ULL << 0 (which would
    // shadow the "no caps" default). Keeps the bitmap operations
    // from having to exclude bit 0.
    kCapNone = 0,

    // Write to the kernel serial console via SYS_WRITE(fd=1).
    // Without this cap, SYS_WRITE(fd=1) returns -1. The sandbox
    // profile lacks this so a malicious EXE can't spam the host's
    // log (information-leak vector: timing, byte ordering,
    // anything it can learn by observing the kernel's COM1
    // behaviour).
    kCapSerialConsole = 1,

    // Read filesystem metadata (SYS_STAT). Lookup is always
    // bounded by the process's `root` pointer — even a process
    // WITH this cap cannot name a node outside its root. The cap
    // gates the syscall itself, while Process::root gates the
    // reachable namespace; both layers compose.
    kCapFsRead = 2,

    // Install / remove debug breakpoints on THIS process via
    // SYS_BP_INSTALL / SYS_BP_REMOVE. Scoped to the caller — a
    // process with this cap cannot set a BP in another process;
    // the BP rides the caller's own task via per-task DR0..DR3
    // save/restore on context switch. Withholding this cap is
    // the default for untrusted code: a sandboxed process can
    // still crash, but it cannot use the 4 hardware DRs as a
    // side channel or stall the scheduler by pinning them.
    kCapDebug = 3,

    // Mutate the on-disk filesystem (SYS_FILE_WRITE,
    // SYS_FILE_CREATE). Read still requires kCapFsRead — a
    // typical writer holds both. Sandboxed profiles withhold
    // this cap by default; trusted profiles inherit it via the
    // [1..kCapCount) loop in `kProfileTrusted`. The cap covers
    // every backing the routing layer reaches today (ramfs is
    // read-only; fat32 honours the cap for Fat32WriteInPlace +
    // Fat32CreateAtPath); future backings (ext4 r/w, native FS)
    // share the same gate.
    kCapFsWrite = 4,

    // Spawn an additional ring-3 Task inside the caller's
    // Process (SYS_THREAD_CREATE). The new Task shares the
    // Process's AddressSpace, cap set, and handle tables, and
    // gets its own kernel stack + user stack. Withholding this
    // cap from a sandboxed profile keeps an untrusted PE
    // single-threaded regardless of its own intent. Trusted
    // profiles inherit it via the kProfileTrusted loop.
    kCapSpawnThread = 5,

    // Talk to the network. Gates every BSD-socket-family Linux
    // syscall the linux ABI dispatcher recognises (socket /
    // socketpair / accept / connect / bind / listen / send* /
    // recv* / sendmsg / recvmsg). Without this cap, the gate
    // returns -EACCES instead of the "no socket layer yet"
    // -ENETDOWN/-EBADF that callers WITH the cap see — a
    // sandboxed RAT prober gets a clean denial signal that
    // stays distinguishable from "the network stack is offline".
    // Held by the trusted profile (so internal kernel-shipped
    // userland keeps the same surface it had before this cap
    // existed); withheld from kProfileSandbox so untrusted PEs
    // cannot reach the socket family at all.
    //
    // Granularity is intentionally coarse — one cap covers
    // both inbound (bind/listen/accept) and outbound
    // (connect/send) for v0. Splitting into kCapNetSend +
    // kCapNetRecv is reserved for when a real workload proves
    // the asymmetric profile is needed.
    kCapNet = 6,

    // Read keyboard / mouse / cursor state. Gates the
    // SYS_WIN_GET_KEYSTATE + SYS_WIN_GET_CURSOR async-input
    // family — the syscalls a Win32 keylogger or click-
    // recorder polls. Without this cap, GetKeyState reports
    // "key up" for every code and GetCursorPos reports (0,0)
    // — the same shape a process gets when no input has ever
    // been delivered, so callers don't trip on a novel error
    // path. Trusted profile holds the cap; kProfileSandbox
    // does not.
    //
    // Note: synchronous input via WM_KEYDOWN / WM_MOUSEMOVE
    // through the message pump is NOT gated — those messages
    // are addressed to a specific HWND the kernel already
    // routed deliberately. The cap targets the unsolicited
    // GLOBAL polling surface that turns any process into a
    // keylogger.
    kCapInput = 7,

    // Mutate the firewall rule table. Read access (snapshot the
    // rule list, observe per-rule hit counters) is unprivileged —
    // configuration, not secrets — but FwAdd / FwRemove / FwToggle
    // / FwSetDefaultPolicy are gated on this cap so a sandboxed PE
    // cannot disable a deny rule that's blocking it. Distinct from
    // kCapNet so a process can be allowed to USE the network
    // without being allowed to RECONFIGURE it.
    kCapNetAdmin = 8,

    // Trigger kernel diagnostic-fault injection (SYS_DIAG_FAULT_INJECT).
    // Gates the deliberate panic / kernel page-fault / slab-OOM
    // harness in `diag/fault_inject` — surfaces a malicious PE could
    // use to crash the box or deny service if they reached it. Held
    // by the trusted profile (kernel-shell pseudo-process and the
    // root role gain it via the [1..kCapCount) loop); withheld from
    // every sandboxed profile and from every seed role except root.
    kCapDiag = 9,

    // Raise the calling process's MLFQ scheduling band ABOVE the
    // Normal band (SYS_PRIORITY_CLASS set to ABOVE_NORMAL / HIGH /
    // REALTIME). The kernel's own threads run in the Normal band, so
    // a process that can elevate above it can preempt kernel work and
    // starve the box — a denial-of-service lever. Without this cap a
    // SetPriorityClass(HIGH/REALTIME) request is refused (the class is
    // left unchanged); lowering to Below-Normal / Idle and staying at
    // Normal are always allowed. Held by the trusted profile (so
    // kernel-shipped userland keeps its scheduling reach); withheld
    // from kProfileSandbox so an untrusted PE cannot self-promote.
    kCapSchedPriority = 10,

    // Drive CPU frequency: write the P-state selection MSRs
    // (IA32_PERF_CTL / IA32_HWP_REQUEST on Intel, MSR_PSTATE_CTL on
    // AMD) through arch::CpuFreqSetTarget. Two distinct hazards, both
    // physical rather than merely logical: pinning every core to its
    // turbo ceiling is a thermal load the operator did not ask for,
    // and frequency is a well-documented side channel — a workload
    // that can raise and lower the clock at will can signal across
    // isolation boundaries and can amplify frequency-dependent timing
    // attacks (Hertzbleed).
    //
    // Deliberately NOT reachable from any syscall: no Win32 or Linux
    // thunk can request it, so a guest PE/ELF has no path to the
    // hardware at all regardless of the caps it holds. The only holder
    // that can act on it is the kernel shell's pseudo-process, and
    // even then only when the operator booted with `cpufreq=tune`.
    // Withheld from every sandboxed profile.
    kCapPowerTune = 11,

    // Supervise the authenticated service runtime through
    // SYS_SERVICE_CONTROL operations 3..8 (enumerate, activate, stop,
    // restage, exit dequeue, and exit acknowledgement). The syscall's two
    // self-service operations derive identity from CurrentProcess and do not
    // consult this bit. No request field can synthesize or widen this cap.
    //
    // ServiceManifest v1 deliberately admits this bit only through the
    // independent build authority. The generated package grants it solely to
    // serviced; accepting bit 12 does not widen any other service profile.
    kCapServiceControl = 12,

    // Sentinel: keep this as the last entry so kProfileTrusted can
    // be built by a loop that iterates [1 .. kCapCount). Do NOT
    // use kCapCount as a live cap — it's a boundary marker.
    kCapCount
};

struct CapSet
{
    u64 bits;
};

inline constexpr CapSet CapSetEmpty()
{
    return CapSet{0};
}

// Construct a CapSet with every defined cap set. Named
// "kProfileTrusted" rather than just "CapSetFull" to make the
// intent at call sites obvious — "this process is trusted" is
// what we mean, not "this process happens to have every bit set."
inline constexpr CapSet CapSetTrusted()
{
    u64 bits = 0;
    for (u32 c = 1; c < static_cast<u32>(kCapCount); ++c)
    {
        bits |= (1ULL << c);
    }
    return CapSet{bits};
}

/// SEC-008 least-privilege cap set for launching a binary the operator
/// CHOSE off a disk — a Files double-click, a Start-menu /APPS shortcut,
/// anything whose bytes came from the FAT32 interop volume.
///
/// Such a binary is UNTRUSTED. It must never inherit CapSetTrusted(),
/// which sets every bit including kCapDebug (cross-process VM read/write
/// + SetContext) and kCapDiag (SYS_DIAG_FAULT_INJECT, a guest-reachable
/// kernel panic). Grants only what a console/GUI binary needs, and
/// deliberately withholds kCapDebug / kCapDiag / kCapNet / kCapNetAdmin
/// / kCapInput / kCapFsWrite.
///
/// Lives HERE, next to CapSetTrusted, rather than being duplicated per
/// call site — the policy previously existed only as a file-local helper
/// in apps/files.cpp, and the /APPS launcher in core/menu_dispatch.cpp
/// was written without it and passed CapSetTrusted() instead. A
/// security policy copied per call site is a policy that drifts, and
/// that drift was the bug.
inline constexpr CapSet CapSetUserLaunch()
{
    return CapSet{(1ULL << static_cast<u32>(kCapSerialConsole)) | (1ULL << static_cast<u32>(kCapFsRead)) |
                  (1ULL << static_cast<u32>(kCapSpawnThread))};
}

inline constexpr bool CapSetHas(CapSet s, Cap c)
{
    if (c == kCapNone || c >= kCapCount)
    {
        return false;
    }
    return (s.bits & (1ULL << static_cast<u32>(c))) != 0;
}

inline constexpr void CapSetAdd(CapSet& s, Cap c)
{
    if (c == kCapNone || c >= kCapCount)
    {
        return;
    }
    s.bits |= (1ULL << static_cast<u32>(c));
}

// Drop a single cap from the set. Used by NtAdjustPrivilegesToken's
// disable / remove paths so a Win32 PE can voluntarily shed
// privilege at runtime. Adding a cap from user space is deliberately
// NOT exposed directly. Runtime elevation routes through the broker;
// spawn-time inheritance supplies durable baseline authority.
inline constexpr void CapSetRemove(CapSet& s, Cap c)
{
    if (c == kCapNone || c >= kCapCount)
    {
        return;
    }
    s.bits &= ~(1ULL << static_cast<u32>(c));
}

// A Process begins private to its loader, becomes scheduler-visible with its
// first Task, enters Exiting exactly when the reaper unlinks its last Task, and
// becomes Exited only after the one-shot runtime teardown has completed. Strong
// external references may retain the inert identity header after Exited; they
// do not retain the address space, handle tables, or other runtime resources.
// The explicit state closes the otherwise-ambiguous zero-Task window between
// creation, publication, teardown, and final header reclamation.
enum class ProcessLifecycleState : u32
{
    Private,
    Published,
    Exiting,
    Exited,
};

// Monotonic scheduler-publication tombstone. This is deliberately separate
// from ProcessLifecycleState: an explicit process-wide kill closes future Task
// publication immediately, while the Process remains Published until the
// reaper unlinks its last Task and performs the Published -> Exiting handoff.
enum class ProcessTerminationState : u32
{
    Open,
    Closed,
};

// Stable, non-recycled identity for one Process incarnation. `pid` remains
// the scheduler lookup and diagnostic component; `identity` is carried by
// long-lived policy/lifecycle receipts so they never rely on a recyclable
// namespace value. The v0 allocator mints both components together and
// refuses exhaustion instead of wrapping.
struct ProcessKey
{
    u64 identity;
    u64 pid;
};

constexpr ProcessKey kInvalidProcessKey{0, 0};

constexpr bool ProcessKeyIsValid(ProcessKey key)
{
    return key.identity != 0 && key.pid != 0;
}

constexpr bool operator==(ProcessKey lhs, ProcessKey rhs)
{
    return lhs.identity == rhs.identity && lhs.pid == rhs.pid;
}

using ProcessPublicationGate = bool (*)(ProcessKey, void*);

struct Process
{
    static constexpr u64 kNameCap = 64;

    u64 pid;
    u64 process_identity;
    ProcessLifecycleState lifecycle_state;
    ProcessTerminationState termination_state;
    // Durable Win32 process result. Zero means no result has been selected;
    // otherwise bit 32 is the publication marker and bits 0..31 are the
    // exact DWORD supplied by the first process-wide close. If no such close
    // exists, the scheduler publishes the last Task's exit code at the exact
    // last-Task boundary. Readers expose STILL_ACTIVE until lifecycle Exited.
    u64 win32_exit_status;
    // Immutable exact parent captured by ProcessCreate. First-Task
    // publication uses it under the scheduler lifetime lock to compose Job
    // inheritance with the one-shot external publication gate.
    ProcessKey job_inheritance_parent;
    // Optional one-shot policy callback consumed under the scheduler's first-
    // Task publication lock. Installation is limited to the exclusively-owned
    // Private Process. The callback and borrowed context are cleared before
    // invocation so rejection/re-entry cannot replay stale authority.
    ProcessPublicationGate publication_gate;
    void* publication_gate_context;
    // ProcessCreate copies every caller-supplied label here. Syscall spawn
    // paths build their leaf name on the syscall stack, so retaining the
    // incoming pointer would leave both process diagnostics and task labels
    // dangling as soon as the syscall returned.
    char name_storage[kNameCap];
    const char* name;
    mm::AddressSpace* as;
    // Immutable after scheduler publication. Every child Process retains and
    // inherits this exact generation-safe domain, so Section accounting is
    // aggregated across the whole spawn tree rather than reset per PID.
    ResourceDomainKey resource_domain;
    // Exact, independently synchronized security owners. Credentials are ABI
    // identity metadata; authorization is DuetOS kernel policy. They are
    // intentionally separate and remain valid through terminal runtime drain.
    CredentialKey credentials;
    AuthorizationContextKey authorization;
    // Outer transaction and lifecycle-admission boundary for this Process's
    // mutable runtime. Lock order is Process VM -> scheduler registry ->
    // AddressSpace/table mutation; never wait for this mutex while holding an
    // inner lock. VM callers keep it across result publication. Exec holds it
    // across clear/load publication; the reaper publishes Exiting while holding
    // it, then drains the runtime after all earlier admitted operations finish.
    sched::Mutex vm_transaction_lock;
    // Per-process view of the filesystem root. Path resolution
    // starts here — a process cannot name any node that isn't
    // reachable from `root`. Trusted processes get the rich
    // fs::RamfsTrustedRoot(); sandboxed processes get
    // fs::RamfsSandboxRoot() (which has one file). Never null
    // for a valid Process.
    const fs::RamfsNode* root;
    // ASLR — randomised per process at spawn time. The payload
    // bytes installed in the user code page are patched to embed
    // these VAs, so two processes running "the same" user code
    // actually execute at different addresses and reference their
    // stacks at different addresses. Makes pre-computed ROP chains
    // useless against any individual sandboxed process — the
    // attacker can't know where gadgets live without first leaking
    // the base.
    u64 user_code_va;
    u64 user_stack_va; // stack base; top = user_stack_va + kPageSize

    // Demand-grown ring-3 main-thread stack (PE spawns only; all
    // zero elsewhere, which makes every ring-3 fault classify as
    // NotStack). Unlocked by design — only the main thread can
    // satisfy the growth condition against it; see the concurrency
    // note in kernel/proc/user_stack.h.
    UserStackRange stack;
    // When non-zero, Ring3UserEntry enters ring 3 with rsp = this
    // value instead of the default `user_stack_va + kPageSize`.
    // Used by SpawnElfLinux to land the user task on a pre-
    // populated argc/argv/envp/auxv region at the top of the
    // stack page. 0 means "use the default" — keeps native + PE
    // spawn paths unchanged.
    u64 user_rsp_init;

    // When non-zero, Ring3UserEntry enters ring 3 with GSBASE
    // set to this VA instead of the zero default. Populated by
    // SpawnPeFile with the TEB VA so Win32 PEs can resolve
    // `gs:[0x30]` (TEB self-pointer), TLS slot reads, PEB
    // pointer, etc. Non-PE tasks leave this at 0 — they never
    // look at gs-relative addresses.
    u64 user_gs_base;

    // True iff this process is a PE32 (i386) image. Drives the
    // ring-3 entry-mode pick: PE32 tasks enter compat mode via
    // arch::EnterUserMode32 (CS=0x3B, D=1, L=0); PE32+ tasks enter
    // long mode via arch::EnterUserModeWithGs (CS=0x2B, L=1).
    // The kernel's int 0x80 dispatcher detects the same bit from
    // the trap-frame CS at every syscall and remaps the i386
    // register convention to the SysV AMD64 slots the C++
    // SyscallDispatch expects.
    bool user_is_pe32;

    // Capability, lease, tick, denial, and filesystem-write enforcement
    // state lives only in the exact `authorization` owner above. Keep this
    // compatibility count for callers that format the three policy windows;
    // it is checked against the AuthorizationContext contract below.
    static constexpr u32 kFsWriteWindowCount = kAuthorizationFsWriteWindowCount;

    // Win32 process heap — a per-process free-list allocator.
    // `heap_base` is the fixed user VA where heap pages start
    // (kWin32HeapVa, 0x50000000). `heap_pages` is the count of
    // pages currently mapped (zero if the PE had no imports and
    // the loader didn't stand up a heap). `heap_free_head` is
    // the user VA of the first free block's header; nullptr =
    // empty free list (everything allocated or heap uninit).
    //
    // Managed by kernel/subsystems/win32/heap.cpp and mutated from
    // SYS_HEAP_* on any thread in this process. `win32_heap_lock` is a
    // sleeping mutex because heap operations enter AddressSpace mutation
    // transactions and can map/unmap frames. It covers these default fields,
    // every `extra_heaps[]` row below, and all in-band free-list access. Lock
    // order is win32_heap_lock -> AddressSpace::mutation_lock -> regions_lock;
    // callers must not enter it while holding a spinlock.
    mutable sched::Mutex win32_heap_lock;
    u64 heap_base;
    u64 heap_pages;
    u64 heap_free_head;

    // Linux-ABI file descriptor table. Meaningful only when
    // abi_flavor == kAbiLinux. Slots 0 / 1 / 2 are reserved for
    // stdin / stdout / stderr; slots 3+ are file handles opened
    // via sys_open, each carrying the backing FAT32 entry's
    // first-cluster + size + the current read offset.
    //
    // A fixed-size 16-entry table is plenty for smoke tests and
    // the typical static-musl binary. Real programs (shells,
    // dynamic linkers) need more; grow to a KMalloc'd array when
    // a workload actually exceeds 16 open handles.
    //
    // KFile sidecar (kf_handle): for pool-backed kinds (states
    // 3..15), each open allocates a `KFile` carrying the kind tag
    // + pool index + per-pool release callback, parks it in
    // `kobj_handles`, and stores the resulting handle here. Close
    // / dup / fork all route through HandleTable* — the KFile's
    // refcount drives per-pool retain/release instead of every
    // syscall site open-coding the explicit *Retain / *Release
    // pair. Mirrors the Win32 mutex migration's shape. State 0/1
    // (unused / TTY) and state 2 (FAT32 file — no pool ref to
    // count) leave kf_handle = 0.
    struct LinuxFd
    {
        // state 0 = unused
        // state 1 = reserved-tty (fd 0/1/2)
        // state 2 = regular file (FAT32-backed)
        // state 3 = pipe-read end  → first_cluster = pipe pool idx
        // state 4 = pipe-write end → first_cluster = pipe pool idx
        // state 5 = eventfd        → first_cluster = eventfd pool idx
        // state 6 = socket         → first_cluster = socket pool idx
        // first_cluster is reused as a generic "pool index" slot
        // for the non-file states; all non-file callers must
        // ignore size/offset/path.
        u8 state;
        // Per-fd flag bits. CLOEXEC and Canary are descriptor-local.
        // PendingCreate is copied here as a compatibility mirror, but for a
        // regular file the shared OFD is authoritative so dup/fork siblings
        // observe the first successful create together.
        u8 flags;
        // Open-file-description (OFD) handle: 1-based index into the
        // kernel-wide refcounted OFD pool (see process.cpp), or 0 for
        // "no OFD attached". POSIX requires dup()/dup2()/dup3() (and
        // fork) to make the new fd share ONE open-file description —
        // a single file offset + a single set of O_* status flags —
        // with the source fd. The OFD object is that shared,
        // refcounted description: dup bumps its refcount, close drops
        // it, the last close releases it. `offset` below stays as a
        // live write-through mirror of the OFD's offset so the
        // existing syscall TUs that read `linux_fds[fd].offset`
        // inline keep working unchanged.
        u16 ofd;
        // For regular files these are compatibility mirrors of the shared
        // OFD backing metadata. For non-file states first_cluster remains the
        // per-kind pool index described above.
        u32 first_cluster;
        u32 size;
        // Sidecar handle into `kobj_handles`. 0 (kHandleInvalid) =
        // no KFile attached. Populated by `LinuxFdAttachKFile` at
        // creation time for pool-backed kinds; cleared by
        // `LinuxFdClose` after `HandleTableRemove` fires the per-
        // pool release callback. Stored as u32 so the LinuxFd
        // struct stays 8-byte aligned and process.h doesn't have
        // to pull in ipc/handle_table.h transitively.
        u32 kf_handle;
        u64 offset; // read cursor; only meaningful for state=file
        // Volume-relative path as passed to sys_open, NUL-
        // terminated. Needed so sys_write's extend path can call
        // Fat32AppendAtPath — the FAT32 writer walks the parent
        // directory by name to update the entry's size field.
        // Cap matches the sys_open copy buffer (63 chars + NUL).
        char path[64];

        // Per-slot identity epoch. Every publish and detach advances this
        // counter while `linux_fd_lock` is held; zero is never published and
        // wrap is forbidden. A closed slot at kLinuxFdGenerationExhausted is
        // permanently retired so no stale receipt can become current again.
        u32 generation;
    };
    static constexpr u32 kLinuxFdGenerationExhausted = static_cast<u32>(-1);
    static constexpr u8 kLinuxFdFlagPendingCreate = 0x01;
    // Canary flag: set at open / O_CREAT time when the path
    // matched `security::CanaryMatchesPath`. Read on every
    // sys_write (and copy_file_range / sendfile sinks) so an
    // in-place overwrite of an existing canary file trips the
    // wall even though the syscall doesn't re-evaluate the
    // path. Mirrors `Win32FileHandle::is_canary`.
    static constexpr u8 kLinuxFdFlagCanary = 0x02;
    // FD_CLOEXEC bit. Closes-on-exec (when `LinuxFdCloseOnExec`
    // runs at exec). Set at open via O_CLOEXEC, at pipe2 via
    // O_CLOEXEC, at dup3 via O_CLOEXEC, at *_create flag-args
    // (TFD_CLOEXEC, SFD_CLOEXEC, IN_CLOEXEC, MFD_CLOEXEC,
    // FAN_CLOEXEC, EFD_CLOEXEC, SOCK_CLOEXEC, EPOLL_CLOEXEC),
    // and via fcntl(F_SETFD, FD_CLOEXEC). Cleared by fcntl
    // F_SETFD with arg=0 and by dup() (which always produces a
    // non-cloexec fd). FD_CLOEXEC is correctly a per-fd (per-
    // descriptor) flag — distinct from O_CLOEXEC, which lives in the
    // shared open-file description (`LinuxFd::ofd`). dup() shares the
    // description but resets FD_CLOEXEC on the new fd, which is why
    // this flag lives inline here, not in the OFD.
    static constexpr u8 kLinuxFdFlagCloexec = 0x04;
    // Serializes fd-slot transitions and snapshots. KObject/OFD cleanup must
    // run only after this lock and every handle-table lock are gone.
    sync::SpinLock linux_fd_lock;
    LinuxFd linux_fds[16];

    // Linux-ABI brk heap. Meaningful only when abi_flavor ==
    // kAbiLinux; untouched otherwise. `linux_brk_base` is the
    // start of the program's data segment end (v0 smoke hard-
    // codes this; future ELF loader will set it from the highest
    // PT_LOAD's p_vaddr + p_memsz). `linux_brk_current` tracks
    // the top of the currently-mapped heap; brk() grows it by
    // mapping fresh RW pages on demand.
    u64 linux_brk_base;
    u64 linux_brk_current;

    // Linux-ABI mmap bump allocator. Anonymous private mmap()
    // calls return page-aligned regions starting here and march
    // forward. No reuse on munmap yet — v0 leaks mappings on
    // munmap, which is fine for short-lived smoke tasks.
    // Once Process is published, direct reads or writes are forbidden: use
    // ProcessReserveMmapRange / ProcessMmapCursorSnapshot so Linux mmap and
    // zero-hint Win32 VM/Section callers cannot claim the same range or form
    // a C++ data race. Pre-publication loader initialization may assign
    // directly. Failed post-reservation maps intentionally leave a safe gap.
    //
    // Native/Win32 processes start inside the low, PE32-representable arena
    // below kWin32VmapBase. Linux loaders replace this cursor with their high
    // canonical-user arena before publishing the Process. Page zero is never
    // a valid automatic-map result.
    static constexpr u64 kCompatAutoVmBase = 0x20000000ULL;
    static constexpr u64 kCompatAutoVmLimit = 0x40000000ULL;
    u64 linux_mmap_cursor;

    // Linux vDSO mapping. linux_vdso_base is the user VA where
    // the kernel painted the embedded vDSO blob at spawn time
    // (one R-X page); the per-export VAs are
    // linux_vdso_base + the kOffLinuxVdso* constant emitted by
    // the build script. Signal delivery uses
    // linux_vdso_rt_sigreturn_va when the caller's sigaction
    // omitted SA_RESTORER, instead of dropping the signal. The
    // __vdso_* clock/cpu entries are exposed to user code via
    // direct VA today (AT_SYSINFO_EHDR auxv hookup is the
    // dynamic-glibc support slice). All fields are 0 until the
    // loader maps the blob (PE / native processes leave them 0).
    u64 linux_vdso_base;
    u64 linux_vdso_rt_sigreturn_va;
    u64 linux_vdso_clock_gettime_va;
    u64 linux_vdso_gettimeofday_va;
    u64 linux_vdso_time_va;
    u64 linux_vdso_getcpu_va;

    // ABI flavor — which kernel syscall entry path this process's
    // tasks will route through at ring-3 boundary.
    //   kAbiNative (0): int 0x80 -> core::SyscallDispatch. The
    //     DuetOS native ABI + Win32 PE subsystem both live
    //     here (Win32 is a user-mode shim that trampolines
    //     through the native ints).
    //   kAbiLinux (1): syscall instruction -> linux::Dispatch.
    //     Linux-ABI binaries (RAX=nr, RDI/RSI/RDX/R10/R8/R9 args,
    //     sysret expected) reach a separate in-kernel table.
    //
    // Set by the loader at spawn time; read by the syscall entry
    // path. A u8 is enough — we aren't planning more than a
    // handful of peer subsystems.
    u8 abi_flavor;
    u8 _abi_pad[7];

    // Win32 "catch-all" miss table. Populated during PeLoad for
    // every import that didn't match a real stub and got routed
    // through the shared miss-logger trampoline. When the PE calls
    // the trampoline, the SYS_WIN32_MISS_LOG syscall looks up the
    // caller's IAT slot VA here and logs the function name it
    // maps to — telling us, in real time, which unstubbed import
    // the CRT just tried to call. Cap at 128 entries: winkill has
    // ~24 catch-alls, any PE with a full CRT will stay under 100.
    /// Longest import name retained. Win32 export names are short --
    /// even verbose ones like "GetQueuedCompletionStatusEx" are 27
    /// chars -- so this truncates essentially nothing while keeping the
    /// per-Process table bounded.
    static constexpr u64 kWin32IatMissNameMax = 48;

    struct Win32IatMiss
    {
        u64 slot_va; // VA of the IAT slot (user-space).
        // OWNED, NUL-terminated copy of the import name.
        //
        // This used to be a `const char*` documented as pointing into
        // the PE's on-disk byte buffer and "valid for the life of the
        // Process". That was true only for NAMED imports. An import by
        // ORDINAL has no name in the file, so the loader synthesised
        // "#123" into a FUNCTION-LOCAL `char ordinal_name_buf[32]` and
        // stored a pointer to it here -- a dangling stack pointer that
        // both readers (the `pemiss` shell command and the
        // SYS_WIN32_MISS_REPORT diagnostic) then dereferenced. A PE
        // chooses whether to import by ordinal, so that was reachable
        // straight from ring 3.
        //
        // Copying sidesteps the lifetime question for both cases and
        // costs 48 bytes per entry.
        char name[kWin32IatMissNameMax];
    };
    static constexpr u64 kWin32IatMissCap = 128;
    Win32IatMiss win32_iat_misses[kWin32IatMissCap];
    u64 win32_iat_miss_count;

    // Stage-2 DLL image table. Holds the loader metadata (base
    // VA, parsed EAT, borrowed file bytes) for every DLL the
    // loader has mapped into this process's address space.
    //
    // Populated by `ProcessRegisterDllImage` right after a
    // successful `DllLoad`; walked by `ProcessResolveDllExport`
    // to turn a {dll-opt, name} pair into an absolute VA.
    //
    // 16 slots is the v0 ceiling — enough for a typical Win32
    // PE's transitive DLL closure (ntdll + kernel32 + user32 +
    // a handful of apisets). Grow to a KMalloc'd list when a
    // real workload pushes past this.
    //
    // Lookup today is name-match only (case-insensitive on the
    // DLL name to mirror Win32 convention). The `DllImage`
    // copies its own `file`/`file_len` borrows, so the kernel
    // image bytes must stay alive for the Process's lifetime —
    // which they do, because ramfs blobs are static constexpr
    // arrays in the kernel ELF. LoadLibrary appends at runtime, so
    // foreign readers must first acquire ScopedProcessRuntimeAccess;
    // an Exited identity header is not an admitted DLL-table query.
    static constexpr u64 kDllImageCap = 48;
    DllImage dll_images[kDllImageCap];
    u64 dll_image_count;

    // Side-by-side DLL search directory: where this process's own
    // image was read from on disk, so a DLL that ships beside the
    // .exe can be found. Set once by `SpawnPeFile` from the
    // caller-supplied origin and never mutated afterwards.
    //
    // BOTH the load-time import binder and the runtime
    // `SYS_DLL_LOAD_FROM_PATH` (LoadLibraryW) read THIS field, so
    // there is exactly one search path per process rather than a
    // bind-time and a run-time answer that can disagree.
    //
    // `sxs_dir[0] == '\0'` means the image had no on-disk origin
    // (embedded blob, ramfs) and no side-by-side search happens.
    // See `loader/sxs_dll.h` for the search + gating rules.
    u32 sxs_volume;
    char sxs_dir[40];

    // Win32 file-handle table — backs CreateFileW / ReadFile /
    // CloseHandle / SetFilePointerEx. Each slot is
    // tagged by `kind`: a Ramfs-backed slot stores a pointer to
    // the resolved `.rodata` RamfsNode; a Fat32-backed slot
    // stores a (volume_index, dir_entry) snapshot so reads can
    // walk the cluster chain through `Fat32ReadAt`. Both share
    // the byte cursor.
    //
    // Routing is path-prefix driven in `DoFileOpen`:
    //
    //   "/disk/<idx>/<rest>"  →  Fat32, volume <idx>, lookup <rest>
    //   anything else         →  Ramfs, lookup against `proc->root`
    //
    // The "/disk/" prefix is the smallest credible mount-table
    // stand-in: it lets a Win32 PE name a real on-disk file
    // without yet building a real mount table or drive-letter
    // resolver. A follow-up replaces this with named mounts
    // (`/mnt/<name>/...`) once those exist.
    //
    // Public handles are opaque positive values. Bits 0..11 hold the
    // low-tag band `kWin32HandleBase + idx` (= 0x100 + 0..15), while
    // bits 12..30 hold a non-zero, non-wrapping row generation. Bits 31..63
    // stay zero so the same value is positive and lossless through both the
    // PE32 and PE32+ syscall ABIs. A handle is permanently stale once its
    // slot is recycled.
    //
    // 16 slots is plenty for v0 — typical console programs hold
    // ~4 (stdin/stdout/stderr + one input file). Grow to a
    // KMalloc'd table when a real workload needs more.
    enum class FsBackingKind : u8
    {
        None = 0, // slot is free
        // Kernel-private pre-publication claim. Public operations reject a
        // Reserved row; only the matching non-wrapping generation token can
        // publish or abort it.
        Reserved,
        Ramfs,
        Fat32,
        DuetFs,
        RamVol, // frame-backed writable RAM volume (/run); path-addressed
        Pipe,   // cross-process pipe end (Linux pipe pool slot)
    };
    struct Win32FileHandle
    {
        // Internal row identity and the generation encoded in every public
        // handle. Reserve/publish/abort/detach paths must match it so a delayed
        // or stale caller cannot act on a recycled row.
        u64 generation;
        FsBackingKind kind;              // None = free; otherwise selects which fields below are valid
        const fs::RamfsNode* ramfs_node; // valid iff kind == Ramfs
        u32 fat32_volume_idx;            // valid iff kind == Fat32
        fs::fat32::DirEntry fat32_entry; // valid iff kind == Fat32 (snapshot at open time)
        // DuetFs-backed handle. `block_handle` indexes the kernel
        // block-device table (or kBootHandleSentinel for the boot
        // RAM volume); `node_id` is the resolved DuetFS inode id;
        // `size_bytes` is captured at open time and refreshed on
        // each WriteForProcess so SeekForProcess / FstatForProcess
        // see the live size after appends.
        u32 duetfs_block_handle; // valid iff kind == DuetFs
        u32 duetfs_node_id;      // valid iff kind == DuetFs
        u64 duetfs_size_bytes;   // valid iff kind == DuetFs
        u64 cursor;              // current read position in bytes
        // Canary flag stamped at open / create time when the
        // resolved path matched `security::CanaryMatchesPath` or
        // `CanaryMatchesSuspiciousExtension`. Read on every
        // SYS_FILE_WRITE so an in-place overwrite of an existing
        // canary file (which doesn't carry a path string into
        // the write call) still trips the wall. Stamped once at
        // open; never cleared (handles are short-lived).
        bool is_canary;
        // FAT32 path inside the volume (e.g. "/SUB/FOO.TXT"),
        // captured at open / create time when kind == Fat32. Past-
        // EOF writes route through `Fat32WriteAtPath` which needs
        // the path so it can resolve the parent directory and
        // patch the dir-entry size after a chain extension. The
        // DirEntry snapshot doesn't carry parent-cluster info,
        // so the path is the cheapest way to reconstruct it.
        // 64 bytes covers every shell + Win32-CWD path that hits
        // the syscall surface today; longer paths fall back to the
        // bounded in-place write.
        static constexpr u64 kFat32PathCap = 64;
        char fat32_path[kFat32PathCap];
        // Absolute in-volume path (e.g. "/run/svc/state"), captured
        // at open time when kind == RamVol. RamVol is path-addressed
        // (its nodes are module-private), so every read/write
        // re-resolves via fs::RamVolRead/RamVolWrite using this. 128
        // covers /run/<service>/<file> depth; longer paths are
        // refused at open.
        static constexpr u64 kRamVolPathCap = 128;
        char ramvol_path[kRamVolPathCap];
        // Pipe-backed handle. `pipe_pool_idx` indexes the kernel
        // pipe pool (kernel/subsystems/linux/syscall_pipe.cpp);
        // `pipe_is_write_end` distinguishes the write side from
        // the read side. Both ends of a single CreatePipe call
        // share the same pool index.
        u32 pipe_pool_idx;      // valid iff kind == Pipe
        bool pipe_is_write_end; // valid iff kind == Pipe
        // Named-pipe registry slot for the SERVER end of a
        // CreateNamedPipe-allocated pipe. >= 0 = this handle is
        // the server end; CloseForProcess routes through
        // NamedPipeOnServerClose to drop the registry entry and
        // any orphan opposite-end ref. -1 = anonymous pipe or
        // client end of a named pipe (no registry housekeeping).
        // Stored as i8 because the registry has 16 slots; a wider
        // table needs only a typedef bump.
        i8 named_pipe_registry_slot;
        // Identity stamp for the registration named by
        // `named_pipe_registry_slot`. NamedPipeRegisterServer bumps
        // a slot's generation on every claim, so a copy of the pair
        // that outlived its registration fails the identity check in
        // NamedPipeOnServerClose instead of tearing down whatever
        // registration recycled the slot index. Meaningless (0) when
        // named_pipe_registry_slot < 0.
        u32 named_pipe_registry_gen;
    };
    struct Win32FileReservation
    {
        u32 slot;
        u32 _pad;
        u64 generation;
    };
    struct Win32FileHandleIdentity
    {
        u32 slot;
        u32 _pad;
        u64 generation;
    };
    static constexpr u64 kWin32HandleCap = 16;
    static constexpr u64 kWin32HandleBase = 0x100;
    static constexpr u64 kWin32FileHandleTagMask = 0xFFF;
    static constexpr u32 kWin32FileHandleGenerationShift = 12;
    // PE32 HANDLEs and syscall arguments are 32-bit. Keep bit 31 clear so an
    // encoded handle is positive in both public ABIs; do not silently grant
    // PE32+ more generations than PE32 can round-trip.
    static constexpr u64 kWin32FileHandleMaxValue = (1ULL << 31) - 1;
    static constexpr u64 kWin32FileHandleMaxGeneration = kWin32FileHandleMaxValue >> kWin32FileHandleGenerationShift;
    // Serializes one public operation (read/write/seek/fstat/duplicate) with
    // close for each slot. The mutex is deliberately separate from
    // win32_file_lock: filesystem I/O, pipe waits, allocation, and user copy
    // may block and therefore run with only this sleepable lock held.
    //
    // The slot mutex may independently acquire win32_file_lock to snapshot or
    // commit identity and the pipe-pool lock to retain/release a backing. The
    // two spinlocks are never nested; no wait, copy, allocation, or backing
    // release occurs under win32_file_lock.
    sched::Mutex win32_file_operation_locks[kWin32HandleCap];
    // Protects file-row identity and publication only. Backing releases,
    // filesystem I/O, allocation, user copy, and wait-queue work happen after
    // it is released. Pipe operation snapshots rely on the per-slot operation
    // mutex to exclude close, then acquire the pipe-pool lock only after this
    // identity lock is released.
    mutable sync::SpinLock win32_file_lock;
    Win32FileHandle win32_handles[kWin32HandleCap];

    // Win32 mutex handle range — backs CreateMutexW /
    // WaitForSingleObject / ReleaseMutex / CloseHandle. The
    // legacy fixed-size `Win32MutexHandle win32_mutexes[]` array
    // was removed when `SYS_MUTEX_*` migrated to `KMutex` +
    // `kobj_handles` (kernel/ipc/). The public Win32 value is now a
    // positive generation-tagged encoding whose low tag is
    // `kWin32MutexBase + slot`; stale generations cannot alias reuse.
    // The cap below stays disjoint from kWin32EventBase (0x300)
    // and the file handle low-tag band (0x100..0x10F). All migrated
    // KObject wrappers are opaque and dispatch through checked low-tag plus
    // non-zero-generation decoding.
    static constexpr u64 kWin32MutexBase = 0x200;
    static constexpr u64 kWin32MutexCap = ::duetos::ipc::kHandleTableCapacity;

    // Win32 event handle range — backs CreateEventW / SetEvent /
    // ResetEvent / WaitForSingleObject. Migrated to KEvent +
    // `kobj_handles` (kernel/ipc/) alongside mutexes; the legacy
    // `Win32EventHandle win32_events[]` array was removed at the
    // same time. Its public value carries the unified slot in the low tag
    // and that slot's generation in the high bits. The cap stays disjoint
    // from kWin32MutexBase (0x200)
    // and kWin32ThreadBase (0x400) so CloseHandle / WFMO can
    // continue to dispatch by range.
    static constexpr u64 kWin32EventBase = 0x300;
    static constexpr u64 kWin32EventCap = ::duetos::ipc::kHandleTableCapacity;

    // Win32 thread table — backs CreateThread. Each slot carries
    // the immutable scheduler TID of the spawned thread plus a
    // small bit of durable lifecycle state. Task pointers are
    // deliberately never stored here: the scheduler reaper owns
    // Task lifetime independently of Process lifetime.
    // Handles run kWin32ThreadBase + idx (= 0x400..0x407),
    // disjoint from every other Win32 handle range so a single
    // CloseHandle dispatch can pick the right table by value.
    //
    // `win32_thread_lock` serializes slot claim, task publication,
    // exit-code publication, waits, and CloseHandle reclamation.
    // A plain IRQ-off region is insufficient here: a worker may
    // exit on another CPU while its creator is polling the handle.
    //
    // v0 SCOPE (honest about what's not done):
    //   - WaitForSingleObject(thread) blocks on a per-slot wait queue.
    //     Exit publication advances a stable event sequence before waking,
    //     so the predicate recheck and scheduler enqueue are linearized.
    //   - Handles are slot-only values, without a generation in
    //     the public value. A stale closed handle can therefore
    //     alias a later thread that reuses the same slot.
    //   - Thread exit is via SYS_EXIT (same as process exit);
    //     the scheduler's single-task-dies-cleanly path handles
    //     it. Exiting the LAST task in the process implicitly
    //     tears the process down; the ordering is the
    //     scheduler's existing reaper contract.
    struct Win32ThreadHandle
    {
        bool in_use;
        // Set only between slot reservation and scheduler
        // publication. Guessed/predicted CloseHandle calls cannot
        // recycle a row while its creator still owns the claim.
        bool creating;
        // User-visible handle lifetime is distinct from the row's
        // task/TEB/TLS resource lifetime. Closing a live thread
        // clears this bit but retains `in_use` until task exit.
        bool handle_open;
        // Separate completion state is required because 0x103 is
        // both STILL_ACTIVE and a legal application exit code.
        bool exited;
        // Win32 exit-code tracking. Starts at
        // STILL_ACTIVE (0x103); overwritten by the SYS_EXIT
        // path when the owning task dies. GetExitCodeThread
        // reads this field via SYS_THREAD_EXIT_CODE and returns it
        // as the DWORD exit code. Waits consult `exited`, not the
        // sentinel value.
        u32 exit_code;
        // Internal ABA guard. Public handles remain slot-only for
        // ABI compatibility, but creator cleanup/publication must
        // match the exact row generation it reserved.
        u64 generation;
        // Never reset when this slot is recycled. Exit publication advances
        // the sequence under win32_thread_lock before waking `waiters`; a
        // waiter snapshots both this value and `generation`, drops the lock,
        // then performs an atomic sequence-recheck/enqueue transaction.
        u64 event_sequence;
        sched::WaitQueue waiters;
        u64 tid;           // monotonic scheduler identity; never reused
        u64 user_stack_va; // base VA of the thread's user stack
    };
    static constexpr u64 kWin32ThreadCap = 8;
    static constexpr u64 kWin32ThreadBase = 0x400;
    sync::SpinLock win32_thread_lock;
    Win32ThreadHandle win32_threads[kWin32ThreadCap];

    // Win32 counting-semaphore handle range — backs
    // CreateSemaphoreW / ReleaseSemaphore / WaitForSingleObject.
    // Migrated to KSemaphore + `kobj_handles` (kernel/ipc/)
    // alongside mutexes and events; the legacy
    // `Win32SemaphoreHandle win32_semaphores[]` array was removed
    // at the same time. Migration also fixed an incidental leak:
    // pre-migration CloseHandle had no semaphore arm at all, so
    // closed semaphore slots were never reclaimed.
    static constexpr u64 kWin32SemaphoreBase = 0x500;
    static constexpr u64 kWin32SemaphoreCap = ::duetos::ipc::kHandleTableCapacity;

    // Win32 IOCP handle range — backs NtCreateIoCompletion /
    // NtSetIoCompletion / NtRemoveIoCompletion(Ex) and the
    // Win32-shaped SYS_IOCP_POST. Migrated to the KObject-shaped
    // ipc::IocpPort + `kobj_handles` (kernel/ipc/iocp.{h,cpp})
    // alongside mutexes / events / semaphores; the legacy 8-port
    // global pool in iocp_job.cpp was retired at the same time.
    // The public handle is the generation-tagged encoding of the unified
    // slot with the legacy 0xB00 low-tag base. The base stays
    // wire-compatible; the cap grows
    // 8 → kHandleTableCapacity and remains disjoint from the
    // 0xC00 JobObject range so CloseHandle / NtClose can keep
    // dispatching by value alone.
    static constexpr u64 kWin32IocpBase = 0xB00;
    static constexpr u64 kWin32IocpCap = ::duetos::ipc::kHandleTableCapacity;

    // Win32 registry handle table — backs the in-kernel read-only
    // registry exposed via SYS_REGISTRY (NtOpenKey /
    // NtQueryValueKey / NtClose paths in ntdll.dll). Each slot
    // carries the resolved kernel-side `RegKey*` (a borrowed
    // pointer into the static well-known-keys table — no
    // ownership; never freed).
    //
    // Handles run kWin32RegistryBase + idx (= 0x600..0x607),
    // disjoint from every other Win32 handle range so the shared
    // CloseHandle / NtClose dispatch picks the right table by
    // value alone. Real Windows registry handles live in the same
    // HKEY-handle space as predefined sentinels (HKLM = 0x80000002
    // etc.); the kernel-side ABI always normalises predefined
    // HKEYs back to "open against HKEY-root" inside the SYS_REGISTRY
    // Open op, so callers see consistent kernel handles regardless
    // of whether they passed a predefined sentinel or a previously-
    // opened subkey.
    //
    // 8 slots is plenty for v0 — a typical MSVC PE startup probes
    // at most 2-3 keys (CurrentVersion + CurrentUser\Internet
    // Settings + Volatile Environment). Grow when a real workload
    // needs more.
    struct Win32RegistryHandle
    {
        bool in_use;
        u8 _pad[7];
        const void* reg_key; // borrowed RegKey* — opaque to process.h
    };
    static constexpr u64 kWin32RegistryCap = 8;
    static constexpr u64 kWin32RegistryBase = 0x600;
    Win32RegistryHandle win32_reg_handles[kWin32RegistryCap];

    // Win32 process handle table — backs NtOpenProcess /
    // OpenProcess. Each slot owns a refcount on the target
    // Process (`ProcessRetain` at open, `ProcessRelease` at
    // close). Holding a handle keeps the target alive even if
    // every Task it owned exits, which matches Windows
    // semantics: NtTerminateProcess on a still-open handle
    // succeeds, observers can still read the exit-code, etc.
    //
    // The public handle keeps 0x700..0x707 as its low tag and carries a
    // non-zero row generation in bits 12..30. Decoding rejects bit 31 and
    // all upper bits so the value stays positive in PE32 and PE32+.
    //
    // 8 slots is plenty for v0 — typical malware-style "open
    // every PID, look for one with a matching name" probes
    // close handles as soon as they're checked, so the table
    // turns over fast. Grow when a real workload pins more.
    enum class Win32ProcessHandleState : u8
    {
        Free = 0,
        Live,
        Retired,
    };

    struct Win32ProcessHandle
    {
        u32 generation;
        Win32ProcessHandleState state;
        u8 _pad[3];
        Process* target; // borrowed pointer; one refcount is owned while Live
    };

    struct Win32ProcessHandleIdentity
    {
        u32 slot;
        u32 generation;
    };
    static constexpr u64 kWin32ProcessCap = 8;
    static constexpr u64 kWin32ProcessBase = 0x700;
    static constexpr u64 kWin32ProcessHandleTagMask = 0xFFF;
    static constexpr u64 kWin32ProcessHandleGenerationShift = 12;
    static constexpr u64 kWin32ProcessHandleMaxValue = (1ULL << 31) - 1;
    static constexpr u64 kWin32ProcessHandleMaxGeneration =
        kWin32ProcessHandleMaxValue >> kWin32ProcessHandleGenerationShift;

    // [any thread, bounded/IRQ-safe] Serializes Win32 process-handle slots.
    // It protects only slot identity/state; reference drops and all external
    // lifetime work happen after release.
    mutable sync::SpinLock win32_handle_lock;
    Win32ProcessHandle win32_proc_handles[kWin32ProcessCap];

    // Cross-process Win32 thread handles produced by
    // NtOpenThread(tid). Each entry stores only the target's
    // immutable, non-reused scheduler TID. Every operation
    // resolves that identity inside the scheduler lock; neither a
    // raw Task pointer nor an owning Process reference escapes the
    // scheduler lifetime boundary. Disjoint from the local
    // win32_threads[] handle range (kWin32ThreadBase + idx =
    // 0x400..0x407) so the by-range dispatch in
    // SYS_THREAD_SUSPEND / RESUME / GET_CONTEXT / SET_CONTEXT
    // and DoFileClose can pick the right table by handle
    // value alone.
    //
    // 8 slots — same sizing rationale as win32_proc_handles:
    // typical "scan every thread, keep one" patterns close
    // handles immediately; the table turns over fast.
    //
    // v0 SCOPE: this table holds FOREIGN thread handles
    // (target Task is in a different Process). LOCAL thread
    // handles (the calling Process's own threads) still live
    // in win32_threads[]. NtOpenThread refuses self-PID
    // requests and routes the caller to the existing local-
    // handle path. The dual-table design lets the cap-gate
    // fire only on cross-process opens — local thread
    // operations need only kCapSpawnThread (the implicit
    // gate for having a thread handle in the first place).
    struct Win32ForeignThreadHandle
    {
        bool in_use;
        u8 _pad[7];
        u64 tid; // monotonic scheduler identity; never reused
    };
    static constexpr u64 kWin32ForeignThreadCap = 8;
    static constexpr u64 kWin32ForeignThreadBase = 0x800;
    Win32ForeignThreadHandle win32_foreign_threads[kWin32ForeignThreadCap];

    // Win32 section handles produced by NtCreateSection. A section is a
    // kernel-resident pool of frames that can be mapped into one or more
    // process address spaces. v0 honours pagefile-backed anonymous sections.
    //
    // Public handles are opaque positive values. Bits 0..11 hold the low tag
    // `kWin32SectionBase + slot` (= 0x900..0x907), while bits 12..30 hold a
    // non-zero, non-wrapping process-row generation. Bits 31..63 stay zero so
    // PE32 and PE32+ round-trip the same identity. Each live row owns one
    // exact generation-keyed Section pool reference.
    enum class Win32SectionHandleState : u8
    {
        Free,
        Reserved,
        Live,
    };
    struct Win32SectionHandle
    {
        u32 generation;
        Win32SectionHandleState state;
        u8 _pad[3];
        subsystems::win32::section::SectionKey key;
    };
    struct Win32SectionHandleReservation
    {
        u32 slot;
        u32 generation;
    };
    struct Win32SectionHandleIdentity
    {
        u32 slot;
        u32 generation;
    };
    static constexpr u64 kWin32SectionCap = 8;
    static constexpr u64 kWin32SectionBase = 0x900;
    static constexpr u64 kWin32SectionHandleTagMask = 0xFFF;
    static constexpr u32 kWin32SectionHandleGenerationShift = 12;
    static constexpr u64 kWin32SectionHandleMaxValue = (1ULL << 31) - 1;
    static constexpr u32 kWin32SectionHandleMaxGeneration =
        static_cast<u32>(kWin32SectionHandleMaxValue >> kWin32SectionHandleGenerationShift);
    // Serializes both Section handle and view row identities. Acquire snapshots
    // a key, pins the Section pool with this lock released, then revalidates the
    // exact row. Mapping, unmapping, releasing frames, and user copies likewise
    // happen after this lock is released.
    mutable sync::SpinLock win32_section_lock;
    Win32SectionHandle win32_section_handles[kWin32SectionCap];

    // Live section VIEWS installed into THIS process's address
    // space. Distinct from the handle table above: a view carries
    // its own section-pool reference (NtMapViewOfSection retains,
    // NtUnmapViewOfSection releases), so closing every handle is
    // not enough to reclaim a section's frames.
    //
    // The record exists because nothing else can reconstruct the
    // set at exit. Views are installed with
    // `mm::AddressSpaceMapBorrowedRange`, which deliberately does
    // NOT register the frame in the AS region table (the section
    // pool owns those frames, not the AS) — so AS teardown frees
    // page tables and cannot know a view was ever there. Without
    // this table a process that maps a view and exits strands the
    // section's frames even if it closed its handle correctly.
    //
    // Populated by SYS_SECTION_MAP into the TARGET process, cleared by
    // SYS_SECTION_UNMAP, and drained by runtime teardown before the AS goes
    // away. Reserve/publish and claim/restore/finish tokens serialize map,
    // unmap, rollback, and exit so exactly one path consumes each view ref.
    enum class Win32SectionViewState : u8
    {
        Free,
        Reserved,
        Live,
        Claimed,
    };
    struct Win32SectionView
    {
        u64 generation;
        Win32SectionViewState state;
        u8 _pad[3];
        subsystems::win32::section::SectionKey key;
        u32 _pad2;
        u64 base_va;
    };
    struct Win32SectionViewReservation
    {
        u32 slot;
        u32 _pad;
        u64 generation;
    };
    struct Win32SectionViewClaim
    {
        u32 slot;
        u32 _pad;
        u64 generation;
        subsystems::win32::section::SectionKey key;
        u64 base_va;
    };
    Win32SectionView win32_section_views[kWin32SectionCap];

    // Win32 directory iteration handles — backs FindFirstFile /
    // FindNextFile / NtQueryDirectoryFile via SYS_DIR_OPEN +
    // SYS_DIR_NEXT. Each open snapshots the directory's entries
    // into a KMalloc'd array (capped at kWin32DirEntryMax = 256
    // entries / handle); SYS_DIR_NEXT pumps the cursor through the
    // snapshot and copies one entry per call to user. The snapshot
    // is freed on CloseHandle.
    //
    // Disjoint from every other Win32 handle range — handles run
    // kWin32DirBase + idx (= 0xA00..0xA07). Snapshot semantics
    // match getdents (a deletion mid-walk doesn't perturb the
    // iterator).
    static constexpr u64 kWin32DirCap = 8;
    static constexpr u64 kWin32DirBase = 0xA00;
    static constexpr u64 kWin32DirEntryMax = 256;
    struct Win32DirHandle
    {
        bool in_use;
        u8 _pad[3];
        u32 entry_count;
        u32 next_index;
        u32 _pad2;
        // KMalloc'd array of fs::fat32::DirEntry copies. Owned by
        // this handle; freed on close. Opaque pointer here so
        // process.h doesn't pull in fs/fat32.h beyond what it
        // already #includes.
        void* entries;
        // Path the snapshot was taken from. Used by
        // NtNotifyChangeDirectoryFile to subscribe to FS-mutation
        // events on this directory. Volume-relative (no
        // "/disk/<idx>" prefix) — matches the path format
        // InotifyPublish receives. 64 byte cap matches the
        // kernel's other path-handling limits.
        char path[64];
    };
    Win32DirHandle win32_dirs[kWin32DirCap];

    // Per-process cursor for thread-stack allocation. Each new
    // thread carves kV0ThreadStackPages pages off this bump
    // cursor. The base sits above the main task's stack and
    // below the Win32 stubs region so collisions with mapped
    // images remain off-limits. Threads don't free their stacks
    // on exit in v0 — same leak profile as the vmap arena.
    static constexpr u64 kV0ThreadStackArenaBase = 0x68000000ULL;
    static constexpr u64 kV0ThreadStackPages = 4; // 16 KiB per thread
    u64 thread_stack_cursor;

    // Win32 TLS (Thread-Local Storage) slots — backs TlsAlloc /
    // TlsGetValue / TlsSetValue / TlsFree. Allocation and lifetime
    // generations are process-wide; values live on each Task so
    // one thread cannot observe another thread's slot contents.
    //
    // 64 slots is plenty for any CRT — typical MSVC CRT
    // uses 3-5 TLS slots.
    static constexpr u64 kWin32TlsCap = 64;
    sync::SpinLock tls_lock;
    u64 tls_slot_in_use; // bitmap: bit N = slot N allocated
    // Every free/allocate transition advances the slot generation.
    // Per-task values stamped with an older generation read as zero.
    u64 tls_slot_generation[kWin32TlsCap];

    // Fiber-Local Storage (FLS). Separate from TLS: FLS slots are
    // per-process allocation, but values are per-FIBER (not per-thread).
    // When a thread is not converted to a fiber, FLS falls back to
    // per-thread storage (same as TLS). 32 slots is enough for typical
    // CRT usage (MSVC uses 1-3 FLS slots for fiber-safe CRT state).
    static constexpr u64 kWin32FlsCap = 32;
    sync::SpinLock fls_lock;
    u32 fls_slot_in_use; // bitmap: bit N = slot N allocated
    u32 _fls_pad0;
    u64 fls_slot_generation[kWin32FlsCap];
    // Per-slot cleanup callback VA (user-mode function pointer).
    // Called when a fiber is deleted or when FlsFree is called.
    // 0 = no callback.
    u64 fls_cleanup_callback[kWin32FlsCap];

    // Static-TLS template descriptor (T6-01 per-thread half).
    // Populated by the PE loader's SetupStaticTls when the image
    // has an IMAGE_DIRECTORY_ENTRY_TLS. SYS_THREAD_CREATE uses it
    // to give each new thread its own TEB + TLS data block (a
    // fresh copy of the template) and to invoke DLL_THREAD_ATTACH
    // callbacks on that thread before its start routine — the
    // model multi-threaded __declspec(thread) code (Chrome) needs.
    // The template SOURCE bytes live in the image at
    // tls_tmpl_src_va (mapped, post-reloc); tls_tmpl_raw is the
    // copied byte count, tls_tmpl_zerofill the zero tail. The
    // callback VAs are absolute (already relocated).
    static constexpr u64 kTlsMaxCallbacks = 16;
    bool tls_present;
    u64 tls_tmpl_src_va;
    u64 tls_tmpl_raw;
    u64 tls_tmpl_zerofill;
    u64 tls_index_va; // *_tls_index lives here (already 0 for v0)
    u32 tls_cb_count;
    u64 tls_callbacks[kTlsMaxCallbacks];
    // Per-thread TEB/TLS region cursor. Thread N's TEB +
    // TLS-array + TLS-block are carved from a per-process window
    // so they never collide with the main thread's fixed VAs.
    u64 tls_thread_region_cursor;

    // Win32 VirtualAlloc bump arena — backs VirtualAlloc /
    // VirtualFree / VirtualProtect. Each SYS_VMAP
    // request rounds the size up to page multiples, allocates
    // fresh frames via AllocateFrame, maps them RW + NX + User
    // at the current cursor VA, then bumps the cursor.
    //
    // v0 is bump-only — VirtualFree is documented as a leak.
    // A follow-up adds a free list once a real workload
    // proves the leak matters. The cap is generous enough for
    // most CRT startups (heap fallback, TLS slot tables,
    // __chkstk probe area) to fit without needing reclaim.
    //
    // vmap_base is 0x40000000 — below the Win32 heap (0x50000000)
    // and distinct from the stubs page (0x60000000), proc-env
    // (0x65000000), TEB (0x70000000), and ring-3 stack bottom
    // (0x7FFFE000) — leaves 256 MiB of contiguous VA space so
    // large requests have somewhere to go.
    static constexpr u64 kWin32VmapBase = 0x40000000ULL;
    static_assert(kCompatAutoVmLimit == kWin32VmapBase,
                  "automatic Win32 mappings must stop where the VirtualAlloc arena begins");
    static constexpr u64 kWin32VmapCapPages = 128; // 512 KiB max per process
    u64 vmap_base;                                 // = kWin32VmapBase after PE load
    u64 vmap_pages_used;                           // bump cursor in pages

    // VirtualAlloc reserve/commit tracking (T5-01 partial). Each
    // region records a contiguous VA range carved out of the
    // vmap arena, the per-page commit state, and the Win32
    // protection bits the caller asked for. RESERVE-only regions
    // have `committed_bitmap == 0`; COMMIT-on-existing-RESERVE
    // sets the matching bits and maps frames. RELEASE clears the
    // slot and unmaps any committed pages; DECOMMIT clears the
    // bits and unmaps but keeps the region.
    //
    // 16 slots × up to 32 pages per region (= 128 KiB max region)
    // is plenty for v0 — typical CRT VirtualAlloc usage is two
    // regions (heap fallback + TLS slot table) of a few pages
    // each. Max region size matches the bitmap width (u32). Grow
    // both when a workload demands.
    struct Win32VmapRegion
    {
        bool in_use;
        u8 _pad[3];
        u32 protection;     // raw Win32 flProtect (PAGE_*) — last value set
        u64 base_va;        // 0 = slot free
        u32 pages;          // total pages in the reservation
        u32 committed_bits; // bit i set = page i is committed (mapped to a frame)
        // PAGE_GUARD per-page bitmap. Bit i set = page i is guard-armed
        // (mapped no-Writable so the next write traps). The page-fault
        // handler in `kernel/arch/x86_64/traps.cpp` consults this
        // bitmap on every ring-3 #PF; on hit it clears the bit,
        // restores the underlying protection encoded in
        // `protection` (with PAGE_GUARD stripped), and returns so the
        // faulting instruction retries — one-shot guard semantics
        // matching the Win32 contract. Full STATUS_GUARD_PAGE_VIOLATION
        // delivery is gated on T6-02 (x64 SEH); v0 silently re-arms
        // the access, which still serves the common stack-grow probe
        // use-case (the next push succeeds after the first fault).
        u32 guard_bits;
    };
    static constexpr u64 kWin32VmapRegionCap = 16;
    static constexpr u32 kWin32VmapRegionPagesMax = 32;
    Win32VmapRegion vmap_regions[kWin32VmapRegionCap];

    // Linux signal-handler table — backs rt_sigaction. Each slot
    // records the user-space handler VA + flags + mask. v0 does
    // NOT deliver signals (no trampoline, no pending queue), but
    // storing the sigaction means musl's init-time "install SIGPIPE
    // = SIG_IGN" pattern at least persists — a subsequent
    // rt_sigaction with nullptr new_act returns the previous one,
    // matching glibc's observed behaviour during CRT bring-up.
    //
    // POSIX defines 64 signals (SIGRTMAX = 64). We size to 65 so
    // signum 1..64 indexes directly.
    static constexpr u64 kLinuxSignalCount = 65;
    struct LinuxSigAction
    {
        u64 handler_va; // 0 = SIG_DFL, 1 = SIG_IGN, other = user VA
        u64 flags;      // SA_RESTART, SA_SIGINFO, ... (opaque to us)
        u64 restorer_va;
        u64 mask; // blocked-signals bitmask during handler
    };
    LinuxSigAction linux_sigactions[kLinuxSignalCount];
    u64 linux_signal_mask; // per-process blocked-signal bitmask (rt_sigprocmask)

    // Per-process rlimit soft caps. Only the ones the kernel can
    // actually enforce live here; everything else stays at the
    // RlimitDefaultsFor constant table. setrlimit / prlimit64
    // write `linux_rlimit_nofile_cur` and `linux_rlimit_nproc_cur`
    // and the next fd-alloc / clone consults them. 0xFFFFFFFFFFFFFFFF
    // sentinel = "no cap below kernel hard ceiling" (the constructor
    // initialises both to that). Hard caps stay 16 / 64. NPROC is shared
    // between sibling fork and setrlimit calls, so every access to that field
    // uses atomic acquire/release builtins; the relation lock serializes the
    // actual fork admission rows.
    u64 linux_rlimit_nofile_cur;
    u64 linux_rlimit_nproc_cur;
    // Bitmap of pending Linux signals. Linux's sigset ABI maps signum N to
    // bit N-1, so bit 0 is SIGHUP (1) and bit 63 is SIGRTMAX (64). Populated
    // by LinuxSignalDeliver()
    // (kill / tgkill / synthetic deliveries) and drained by
    // signalfd_read; rt_sigpending also reports it.
    //
    // v0 only honours the bitmap shape (one pending bit per
    // signum); real Linux distinguishes queued sigqueue() entries.
    // 64-bit width therefore covers the complete signum 1..64 range.
    // Every access after Process publication goes through the atomic helpers
    // below.  Interrupt masking is not an SMP synchronization primitive.
    u64 linux_pending_signals;
    // Monotonic publication identity for signalfd waits. Unlike the pending
    // bitmap predicate, this never moves backwards when a signal is claimed,
    // so raise+claim ABA cannot strand a waiter between its predicate scan and
    // scheduler enqueue. Saturates at UINT64_MAX rather than wrapping.
    u64 linux_signal_event_sequence;
    // Top-of-frame VA recorded by LinuxSignalDeliver and consumed by
    // LinuxSignalRestoreFrame (rt_sigreturn). 0 = no delivery in
    // flight. Per-process (not a global pid-hashed slot table) so a
    // pid-modular collision can't let one process's signal frame VA
    // overwrite another's — which on the victim's rt_sigreturn would
    // restore attacker-controlled registers into its trap frame.
    // A BOUNDED STACK, not a single slot.
    //
    // This was one u64 with the comment "1-deep: no nested signal
    // delivery in v0". That premise is false: nothing guards delivery
    // against a handler already running, and LinuxSignalDeliver is
    // reachable from kill(2), tgkill(2) and pidfd_send_signal(2). A
    // second signal arriving while the first handler runs OVERWROTE the
    // saved frame VA, so the outer handler's rt_sigreturn then found an
    // empty slot — which the restore path treats as "caller invented an
    // rt_sigreturn" and kills the process.
    //
    // That made it a ring-3 denial-of-service: any process permitted to
    // signal a target could kill it outright simply by signalling twice
    // while it was mid-handler, and a process can do it to itself by
    // raising from inside its own handler.
    //
    // Depth 8 comfortably covers real nesting (Linux programs rarely go
    // past 2-3) while staying a fixed, bounded cost per Process. When
    // the stack is FULL, delivery is REFUSED rather than clobbering an
    // older frame — losing a signal is recoverable, corrupting a live
    // handler's return path is not.
    static constexpr u32 kLinuxSignalFrameDepth = 8;
    u64 linux_signal_frame_va[kLinuxSignalFrameDepth];
    u32 linux_signal_frame_depth;
    // Wait queue for signalfd readers. LinuxSignalDeliver wakes
    // every reader after pushing a pending bit so a blocked
    // signalfd read (post-engine) immediately returns.
    sched::WaitQueue linux_signal_wq;

    // ITIMER_REAL state — backs alarm(2), setitimer(2),
    // getitimer(2). `linux_alarm_deadline_ns` is the absolute
    // monotonic-clock deadline at which SIGALRM should be
    // raised (0 = no alarm armed). `linux_alarm_interval_ns`
    // is the auto-rearm interval (0 = one-shot). The
    // dispatcher checks the deadline post-handler and lazily
    // injects SIGALRM into linux_pending_signals — there's no
    // per-tick callback in v0, so the signal is observed at
    // the next syscall return rather than asynchronously.
    u64 linux_alarm_deadline_ns;
    u64 linux_alarm_interval_ns;

    // POSIX per-process timers — backs timer_create / timer_settime
    // / timer_gettime / timer_getoverrun / timer_delete. Each
    // timer carries a monotonic deadline + auto-rearm interval +
    // signal-to-deliver. The dispatcher's post-handler hook
    // (LinuxAlarmCheckAndRaise) walks the table along with the
    // ITIMER_REAL slot above and ORs the signal into pending.
    // Cap matches typical glibc usage; eight timers per process is
    // more than any sane workload needs.
    struct LinuxPosixTimer
    {
        u64 deadline_ns; // 0 = disarmed
        u64 interval_ns; // 0 = one-shot
        u32 signo;       // signal to raise on expiry (SIGALRM default)
        u32 overrun;     // missed-fires count, drained by timer_getoverrun
        u8 in_use;
        u8 _pad[7];
    };
    static constexpr u32 kLinuxTimerCap = 8;
    LinuxPosixTimer linux_posix_timers[kLinuxTimerCap];

    // Linux parent / wait infrastructure — backs wait4 / waitid /
    // SIGCHLD reaping. A fork reserves one fixed parent-owned relation
    // row before the child can become scheduler-visible. The row stays
    // Live until the child's runtime teardown has release-published the
    // Process lifecycle as Exited, then becomes Exited in place. wait4 /
    // waitid consume the terminal row. Capacity is therefore admission,
    // never a best-effort exit queue that can overflow and lose status.
    //
    // The child holds `linux_parent` as a strong identity reference from
    // relation registration through exit publication (or Private rollback).
    // `linux_parent_pid` remains stable ABI metadata for getppid(). The
    // parent row does not retain the child, so this edge cannot form a cycle.
    //
    // `linux_child_event_sequence` is atomically advanced for every relation
    // event that can change a waiter's answer. Producers update the row and
    // sequence under `linux_child_exit_lock`, drop that lock, then wake all
    // `linux_wait_wq` waiters. Waiters use the scheduler's sequence-aware
    // conditional block primitive to close the SMP predicate/enqueue gap.
    static constexpr u64 kLinuxChildRelationCap = 64;
    enum class LinuxChildRelationState : u8
    {
        Free = 0,
        Live,
        Exited,
    };
    struct LinuxChildExit
    {
        u64 pid;
        u32 exit_code;     // raw 8-bit exit status passed to DoExit
        u8 exit_signal;    // signal that killed the process; 0 = clean exit
        bool was_signaled; // distinguishes "exited" from "killed by signal"
        u8 _pad[2];
    };
    struct LinuxChildRelation
    {
        LinuxChildRelationState state;
        u8 _pad[7];
        LinuxChildExit exit;
    };
    Process* linux_parent;
    u64 linux_parent_pid;
    u32 linux_exit_code;
    bool linux_was_signaled;
    u8 linux_exit_signal;
    u8 _linux_exit_pad[2];
    u64 linux_child_relation_count;
    LinuxChildRelation linux_child_relations[kLinuxChildRelationCap];
    u64 linux_child_event_sequence;
    // Serializes relation registration/rollback, child exit publication,
    // and wait4/waitid consumption. CLI is per-CPU and cannot protect this
    // shared state on SMP.
    mutable sync::SpinLock linux_child_exit_lock;
    sched::WaitQueue linux_wait_wq;

    // Win32 custom-diagnostics state — opaque pointer to a
    // duetos::subsystems::win32::custom::ProcessCustomState. nullptr
    // until the process opts into any custom-Win32 feature via
    // SYS_WIN32_CUSTOM op=SetPolicy. Owned by the custom module;
    // Runtime teardown forwards to custom::CleanupProcess. Kept as
    // an opaque void* so process.h doesn't pull in the win32
    // subsystem headers.
    void* win32_custom_state;

    // Linux current-working-directory. `chdir(path)` copies the
    // (resolved-or-not) path into this buffer; `getcwd` reads it
    // back. v0 stores the path verbatim — no canonicalisation, no
    // ".." collapsing — because every FAT32 path strip already
    // happens at open-time. The default is "/" so a fresh process
    // matches the value DoGetcwd previously hard-coded.
    //
    // Cap matches Linux's PATH_MAX-light: 256 bytes is enough for
    // every path the v0 FAT32 driver and ramfs accept (their copy
    // bounce buffers are 64 bytes), with headroom for future growth.
    // Access only through ProcessSnapshotLinuxCwd and
    // ProcessReplaceLinuxCwd once Process is published. The embedded lock is
    // initialized before publication and dies with its owning Process. It is
    // a leaf lock: never nest it with fd/OFD/handle/VM locks, and perform no
    // allocation, user copy, VFS operation, logging, or scheduler call while
    // holding it.
    static constexpr u64 kLinuxCwdCap = 256;
    mutable sync::SpinLock linux_cwd_lock;
    char linux_cwd[kLinuxCwdCap];

    // Linux per-task name (PR_SET_NAME / PR_GET_NAME). 16-byte
    // cap matches the Linux kernel's TASK_COMM_LEN. Empty string
    // means "use Process::name as the fallback" — the canonical
    // immutable name set at create time. PR_SET_NAME copies up to
    // 15 chars + NUL into this buffer; PR_GET_NAME reads it back.
    static constexpr u64 kLinuxTaskNameCap = 16;
    char linux_task_name[kLinuxTaskNameCap];

    // SysV shared-memory attach table. Each entry records a
    // (shmid, base_va, page_count) triple so shmdt can find the
    // right segment by user-space address and unmap the right
    // page range. 8 simultaneous attaches per process is plenty
    // for v0; typical SysV-using shells hold 1-3 segments.
    //
    // The actual SHM segment data (frames, refcount,
    // marked-for-destroy) lives in a global pool — see
    // kernel/subsystems/linux/sysv_ipc.cpp.
    static constexpr u64 kLinuxShmAttachCap = 8;
    struct LinuxShmAttach
    {
        bool in_use;
        u8 _pad[3];
        u32 shmid;
        u64 base_va;
        u32 page_count;
        u32 _pad2;
    };
    LinuxShmAttach linux_shm_attaches[kLinuxShmAttachCap];

    // SysV SHM bump arena — fresh shmat() requests pick a VA
    // here when shmaddr == NULL. Distinct from mmap_cursor so
    // unmaps of one don't perturb the other. 64 MiB high, well
    // away from text / heap / stack / mmap.
    static constexpr u64 kLinuxShmArenaBase = 0x70000000ULL;
    u64 linux_shm_cursor;

    // Unified per-process kernel-object handle table (plan A3).
    // Replaces the per-type `win32_*` arrays incrementally — for
    // now the table is empty by default and the existing arrays
    // stay authoritative. Future slices route SYS_MUTEX_*,
    // SYS_EVENT_*, SYS_SEM_*, and Linux fds through this table.
    // Process runtime teardown calls `HandleTableDrain` on it as part of
    // teardown so any KObject references parked here get released
    // even on abnormal exit. Zero-initialised — safe to embed
    // directly with no explicit init call.
    ::duetos::ipc::HandleTable kobj_handles;

    // PE image base — the resolved (post-ASLR) base VA of the
    // calling process's main EXE image, recorded by SpawnPeFile
    // after PeLoad. Backs GetModuleHandleW(NULL) which Windows
    // documents as "the calling EXE's HMODULE." Zero for non-PE
    // processes (native ELF, Linux ELF) — the kernel handler
    // returns 0 in that case, matching real Win32's "no module
    // for the EXE" semantics for non-Win32 callers.
    u64 pe_image_base;

    // Per-process stdin ring buffer. Producer is the kbd-reader
    // task in core/main.cpp's keyboard dispatch (after login is
    // closed and no app has key focus); consumer is SYS_STDIN_READ
    // from ring 3. Single-producer / single-consumer in v0 — one
    // ring-3 task per process drains stdin, the kbd-reader thread
    // is the only producer.
    //
    // 256 bytes is plenty for line-oriented use: a typical stdin
    // line is ≤ 80 chars, the userland shell drains one line per
    // Enter, and overflow drops the oldest byte (treats stdin like
    // a tty's input queue, not a guaranteed-delivery pipe).
    //
    // Zero-initialised by ProcessCreate's memset. The ring lock serializes
    // every cursor/data mutation across CPUs; `head - tail` remains bounded
    // by kCap, so unsigned cursor wrap preserves the occupancy calculation.
    // Producers publish a non-wrapping event sequence while still holding
    // the ring lock, then wake after dropping it. Readers use that sequence
    // for the scheduler's atomic predicate-recheck/enqueue handoff.
    struct StdinRing
    {
        static constexpr u32 kCap = 256;
        static_assert((kCap & (kCap - 1)) == 0);
        u8 buf[kCap];
        u32 head;
        u32 tail;
        sync::SpinLock lock;
        u64 event_sequence;
        sched::WaitQueue waiters;
    };
    StdinRing stdin_ring;

    // Kernel-resident APC queue. Backs Win32 QueueUserAPC and
    // ntdll!NtQueueApcThread. Each slot pins a (target_tid, pfn,
    // data) triple; the entry is queued by SYS_QUEUE_USER_APC and
    // popped by SYS_DRAIN_USER_APC when the targeted task wakes
    // from an alertable wait. Cross-thread same-process delivery
    // works regardless of whether the target was blocked in user
    // mode or kernel mode — the kernel queue is the source of
    // truth, and the alertable-wait slicing on the userland side
    // polls SYS_DRAIN_USER_APC every chunk to fire ready APCs.
    //
    // 16 slots matches the legacy user-space queue sizing in
    // userland/libs/kernel32. Real Windows queues unbounded APCs;
    // a workload that hits the cap can grow to a KMalloc'd ring.
    struct ApcSlot
    {
        u64 target_tid; // sched::Task::id of the destination
        u64 pfn;        // user-mode callback VA (PAPCFUNC / PIO_APC_ROUTINE)
        u64 data;       // NormalContext / ulData (1st arg passed to pfn)
        u64 arg1;       // SystemArgument1 — Nt-style 3-arg APC payload
        u64 arg2;       // SystemArgument2 — Nt-style 3-arg APC payload
        u8 in_use;      // 1 = pending, 0 = empty
        u8 _pad[7];
    };
    static constexpr u32 kApcSlotCap = 16;
    ApcSlot apc_slots[kApcSlotCap];

    // Win32 priority class — backs SetPriorityClass / GetPriorityClass.
    // Values mirror Microsoft's contract:
    //   IDLE_PRIORITY_CLASS         = 0x40
    //   BELOW_NORMAL_PRIORITY_CLASS = 0x4000
    //   NORMAL_PRIORITY_CLASS       = 0x20
    //   ABOVE_NORMAL_PRIORITY_CLASS = 0x8000
    //   HIGH_PRIORITY_CLASS         = 0x80
    //   REALTIME_PRIORITY_CLASS     = 0x100
    // The scheduler's MLFQ runqueue reads this on every enqueue:
    // sched::SchedBandForProcess maps the class to one of the four
    // Normal priority bands (REALTIME/HIGH -> band 0, ABOVE_NORMAL ->
    // band 1, NORMAL/default -> band 2, BELOW_NORMAL/IDLE -> band 3),
    // so a higher-class thread preempts a lower-class one within a
    // tick. A runtime SetPriorityClass takes effect at the thread's
    // next wake/preemption (the band is recomputed in RunqueuePushOn).
    u32 win32_priority_class;
    u8 _priority_pad[4];

    // Inherited stdio handles — populated at spawn by
    // CreateProcess(STARTF_USESTDHANDLES). Each is a Win32-shaped
    // handle copied verbatim from the parent's handle table; the
    // kernel materialises the matching child-side slot during
    // spawn (see SysProcessSpawnEx). Zero = no inheritance for
    // that slot, in which case GetStdHandle returns the legacy
    // pseudo-handle (-10/-11/-12) and WriteFile routes through
    // SYS_WRITE(fd=1) for stdout / fd=2 for stderr.
    //
    // Index: 0 = stdin, 1 = stdout, 2 = stderr.
    u64 std_handles[3];

    // Extra Win32 heaps — backs HeapCreate / HeapDestroy.
    // The default per-process heap stays at `heap_base /
    // heap_pages / heap_free_head` (kWin32HeapVa, 256 KiB);
    // HeapCreate carves a fresh region out of the extra-heap
    // arena (kWin32ExtraHeapArenaBase = 0x55000000), maps the
    // requested page count RW+NX, and seeds an independent
    // free list. Each slot's `base_va` is stable for the life
    // of the heap; HeapDestroy unmaps the pages and clears
    // the slot. All fields are protected by `win32_heap_lock`; pointers into
    // these rows never escape the locked heap implementation.
    //
    // 4 slots × up to 16 pages (64 KiB) per heap. Cap matches
    // typical workloads (CRT keeps one private heap; most apps
    // never call HeapCreate). Grow when a workload demands.
    struct Win32ExtraHeap
    {
        bool in_use;
        u8 _pad[7];
        u64 generation; // never zero while live; retained across destroy
        u64 base_va;    // 0 = slot free
        u64 pages;      // page count actually mapped
        u64 free_head;  // user VA of first free block (0 = full)
    };
    static constexpr u64 kWin32ExtraHeapCap = 4;
    static constexpr u64 kWin32ExtraHeapPagesMax = 16;
    static constexpr u64 kWin32ExtraHeapArenaBase = 0x55000000ULL;
    static constexpr u64 kWin32ExtraHeapStride = 0x100000ULL; // 1 MiB per slot
    Win32ExtraHeap extra_heaps[kWin32ExtraHeapCap];

    // Per-PE app-compat policy applied from a `<exe>.duetcompat`
    // sidecar at load time. Defaults are all-zero (= kernel behaves
    // exactly as it did before app-compat existed). The canonical
    // type lives in `kernel/loader/compat_shim.h` so subsystem
    // call-sites can `#include` just the small header instead of
    // the full process.h. Field is inlined into Process; small +
    // POD-shaped, no allocation needed.
    compat::CompatPolicy compat_policy;

    // Per-PE SxS assembly manifest, parsed from the RT_MANIFEST
    // resource (type 24) at load time. Defaults to all-zero (=
    // no manifest present, AsInvoker, DPI-unaware). The canonical
    // type lives in `kernel/loader/manifest.h`.
    ManifestInfo manifest;

    u64 refcount;
};

/// Snapshot effective authority after lazily expiring overdue leases.
CapSet ProcessCapsSnapshot(const Process* process);

/// Exact owned security keys. The caller must hold a Process reference and
/// must not retain these values past terminal runtime teardown without first
/// taking the service-specific owner reference.
CredentialKey ProcessCredentialKeySnapshot(const Process* process);
AuthorizationContextKey ProcessAuthorizationKeySnapshot(const Process* process);

/// Value-only diagnostic/security snapshots. Credential state is immutable;
/// authorization sampling expires leases using a pre-lock monotonic time.
bool ProcessInspectCredentials(const Process* process, CredentialSnapshot* snapshot_out);
bool ProcessInspectAuthorization(const Process* process, AuthorizationContextSnapshot* snapshot_out);

/// Scheduler and bounded diagnostic adapters for AuthorizationContext-owned
/// enforcement state. A malformed/stale key returns an unresolved action or
/// zero snapshot; policy callers fail closed on unresolved actions.
AuthorizationActionResult ProcessChargeExecutionTicks(Process* process, u64 ticks);
u64 ProcessTickBudgetSnapshot(const Process* process);
u64 ProcessTicksUsedSnapshot(const Process* process);
u64 ProcessSandboxDenialCountSnapshot(const Process* process);

/// Try to snapshot effective authority without waiting or expiring leases.
/// Intended for stop-the-world diagnostics where a stopped CPU may own
/// the AuthorizationContext lock; false leaves `snapshot_out` empty. Callers must not use this
/// side-effect-free view for an authorization decision.
bool ProcessCapsTrySnapshotNoExpire(const Process* process, CapSet* snapshot_out);

/// Test one capability against the effective snapshot.
bool ProcessHasCap(const Process* process, Cap cap);

/// Grant one durable capability only while the monotonic ceiling permits it.
bool ProcessCapsGrant(Process* process, Cap cap);

/// Grant a generation-tagged broker lease until an absolute monotonic deadline.
bool ProcessCapsGrantLease(Process* process, Cap cap, u64 deadline_ns, u64 generation);

/// Revoke only the matching broker lease; durable authority is untouched.
bool ProcessCapsRevokeLease(Process* process, Cap cap, u64 expected_generation);

/// Snapshot the monotonic grant ceiling.
CapSet ProcessCapCeilingSnapshot(const Process* process);

/// Reversibly disable durable and leased bits without lowering the ceiling.
CapSet ProcessCapsDisableMask(Process* process, u64 disable_mask);

/// Permanently lower the ceiling, then remove durable and leased bits.
CapSet ProcessCapsDropMask(Process* process, u64 drop_mask);

/// Atomically capture effective spawn authority, durable child caps, and
/// the inherited ceiling. Leases may authorize spawn but never become
/// durable child authority.
bool ProcessCaptureSpawnAuthority(const Process* process, u64 required_mask, CapSet* child_caps_out,
                                  CapSet* ceiling_out, CapSet* authority_out);

// Canonical ABI flavors. Enum-class would be cleaner but the
// existing Process fields use plain u8/u32 for ABI stability.
inline constexpr u8 kAbiNative = 0;
inline constexpr u8 kAbiLinux = 1;

// Canonical tick budgets. Timer runs at 100 Hz, so 1000 ticks ≈ 10 s.
inline constexpr u64 kTickBudgetSandbox = 1000;       // 10 seconds at 100 Hz
inline constexpr u64 kTickBudgetTrusted = 1ULL << 40; // ~12 decades at 100 Hz = effectively unlimited

// Threshold at which sandbox denials are treated as confirmed
// malicious behaviour. 100 is generous — a well-written sandbox
// probe (our ring3-sandbox task in the smoke test) stays well
// under this — but anything higher is a hostile retry loop.
inline constexpr u64 kSandboxDenialKillThreshold = kAuthorizationDenialThreshold;

// FS write-rate windows (multi-tier). One row per window level; indexes match
// the corresponding arrays in AuthorizationContextSnapshot. All three checks
// run on every successful write; first cap-cross kills the caller.
//
// Tick rate is 100 Hz (kernel/time/tick.h kTickHz). Tuning
// principle: each row's byte_cap / window_ticks is the
// MAXIMUM legitimate sustained throughput tolerated. The burst
// row is generous (16 MiB/s — a typical installer's peak
// extraction rate); sustained narrows that to ~850 KiB/s; long
// to ~580 KiB/s. Legitimate userland workloads (text editing,
// cache writes, compile output) sit at ~10s of KiB/s averaged
// across a session.
inline constexpr const auto& kFsWriteWindowTicksByLevel = kAuthorizationFsWriteWindowTicks;
inline constexpr const auto& kFsWriteWindowByteCapByLevel = kAuthorizationFsWriteWindowByteCaps;
inline constexpr const char* kFsWriteWindowLabels[kAuthorizationFsWriteWindowCount] = {
    "1s/16MiB",
    "5min/256MiB",
    "1h/2GiB",
};

// Back-compat aliases for the burst level (preserve existing
// callers that pre-date the multi-window split).
inline constexpr u64 kFsWriteWindowTicks = kFsWriteWindowTicksByLevel[0];
inline constexpr u64 kFsWriteWindowByteCap = kFsWriteWindowByteCapByLevel[0];

/// Allocate a Process and take ownership of `as`. Does NOT bump
/// `as`'s refcount — ProcessCreate assumes the caller hands over
/// the one reference AddressSpaceCreate returned. On runtime teardown,
/// the AS reference is dropped (which tears down the AS if nothing
/// else holds it). `root` MUST be non-null — pick from
/// fs::RamfsTrustedRoot() / fs::RamfsSandboxRoot() based on the
/// process's trust level. Returns nullptr on kheap failure.
Process* ProcessCreate(const char* name, mm::AddressSpace* as, CapSet caps, const fs::RamfsNode* root, u64 user_code_va,
                       u64 user_stack_va, u64 tick_budget, CapSet cap_ceiling);

/// Replace the default root/inherited resource domain during a spawn prepare
/// callback, before the Process is scheduler-visible. This is the sole path
/// used by the authenticated ServiceManager profile; it retains replacement
/// on success and releases the Process's previous owner reference.
bool ProcessReplaceResourceDomainBeforePublish(Process* process, ResourceDomainKey replacement);

/// Install one scheduler-publication callback on an exclusively-owned Private
/// Process. The callback context is borrowed only across the synchronous spawn
/// path and is either consumed before first-Task publication or discarded by
/// ordinary Private Process teardown.
bool ProcessInstallPublicationGateBeforePublish(Process* process, ProcessPublicationGate gate, void* context);

inline Process* ProcessCreate(const char* name, mm::AddressSpace* as, CapSet caps, const fs::RamfsNode* root,
                              u64 user_code_va, u64 user_stack_va, u64 tick_budget)
{
    return ProcessCreate(name, as, caps, root, user_code_va, user_stack_va, tick_budget, caps);
}

/// Bump refcount. Use when a second holder appears (a future thread
/// spawn that shares the process, a borrow into a non-owning table).
/// Every Retain must be matched by exactly one Release.
void ProcessRetain(Process* p);

/// Acquire a stable lifecycle snapshot.  Publication and exit transitions use
/// checked CAS operations so a stale creator/reaper cannot revive or complete
/// the same Process twice.
ProcessLifecycleState ProcessLifecycleLoad(const Process* process);
bool ProcessLifecycleTransition(Process* process, ProcessLifecycleState expected, ProcessLifecycleState desired);

/// Acquire the monotonic Task-publication tombstone. Process-wide kill paths
/// close it under the scheduler registry lock before scanning existing Tasks;
/// first and additional Task publication check it under that same lock.
ProcessTerminationState ProcessTerminationLoad(const Process* process);

/// Atomically close Task publication for this Process. Returns true only for
/// the caller that changed Open -> Closed; that winner also publishes the
/// supplied process-wide DWORD exactly once. Repeated closes preserve the
/// winner's code. Callers serialize this with Task publication/reap under the
/// scheduler registry lock; there is intentionally no reopen operation.
bool ProcessTerminationClose(Process* process, u32 exit_code);

/// Publish a fallback result for a Process whose last Task has been unlinked.
/// This never overwrites a process-wide close result.
void ProcessPublishLastTaskExitCodeIfUnset(Process* process, u32 exit_code);

/// Win32 process-query result: STILL_ACTIVE until terminal lifecycle
/// publication, then the exact durable DWORD selected above.
u32 ProcessWin32ExitCodeSnapshot(const Process* process);

/// Snapshot immutable identity metadata. Safe for a retained Process in every
/// lifecycle state, including Exited.
ProcessKey ProcessKeySnapshot(const Process* process);

/// Consume and invoke the optional one-shot gate before the first Task becomes
/// scheduler-visible. The caller holds the Process VM transaction and
/// scheduler publication lock and the Process must still be Private.
bool ProcessRunPublicationGateAtSchedulerPublication(Process* process);

/// Complete the one-shot Published -> Exiting exit transaction after the
/// scheduler has unlinked the last Task. Drains all runtime-owned resources,
/// publishes Exited with release semantics, and only then wakes observers.
/// The reaper keeps a strong reference for the entire call and holds no
/// scheduler or Process runtime-admission lock while invoking it.
void ProcessCompleteExitFromReaper(Process* process);

/// Drop a strong identity reference. Exited references retain only the inert
/// Process header; their last release frees that header without re-running
/// runtime teardown. A Private zero-reference abort performs non-observable
/// resource cleanup before freeing the header. The caller MUST NOT touch `p`
/// after its final release. nullptr is a no-op.
void ProcessRelease(Process* p);

/// Result of one atomic parent relation scan. `Pending` means at least one
/// matching registered child remains Live and returns the event sequence a
/// blocking waiter must recheck. `Exited` consumes exactly one matching row.
enum class LinuxChildWaitResult : u8
{
    NoMatchingChild,
    Pending,
    Exited,
};

/// Reserve one parent-owned child relation while `child` is still Private.
/// `child_limit` is the caller's RLIMIT_NPROC-derived admission ceiling and is
/// clamped to the fixed kernel capacity. On success the child owns one strong
/// parent reference until Private rollback or post-Exited status publication.
bool ProcessRegisterLinuxChildRelation(Process* parent, Process* child, u64 child_limit);

/// Atomically scan the parent's registered relations and consume one matching
/// Exited row. `target_pid > 0` selects that exact PID; non-positive selectors
/// match any child until Linux process-group identity is implemented.
LinuxChildWaitResult ProcessPollLinuxChild(Process* parent, i64 target_pid, Process::LinuxChildExit* exit_out,
                                           u64* observed_sequence_out);

/// Block only if the parent's atomic child-event sequence still equals the
/// value returned with `Pending`. The result distinguishes cancellation from
/// an ordinary wake/sequence race so Linux wait4/waitid can unwind with
/// -EINTR. At the saturating terminal sequence value this degrades to a
/// one-tick cancellable wait, guaranteeing a rescan without wrapping or an
/// indefinite lost wake.
sched::WaitQueueBlockResult ProcessWaitForLinuxChildEvent(Process* parent, u64 observed_sequence);

// Pointer-sized Win32 ingress/egress word. PE32 callers own four-byte cells;
// native/PE32+ callers own eight-byte cells. Keeping this decision at the
// Process boundary prevents individual syscall handlers from accidentally
// overwriting the canary immediately after a PE32 HANDLE*, PVOID*, or SIZE_T*.
enum class UserAbiWordStatus : u8
{
    Ok,
    InvalidArgument,
    Fault,
    ValueTooWide,
};

UserAbiWordStatus ProcessCopyUserAbiWordFrom(const Process* process, const void* user_src, u64* value_out);
UserAbiWordStatus ProcessCopyUserAbiWordTo(const Process* process, void* user_dst, u64 value);

/// Atomically claim one page-aligned half-open range from the process's shared
/// mmap cursor. The cursor advances before mapping work begins, so concurrent
/// callers receive disjoint bases; a later mapping failure leaves a safe gap.
/// Refuses zero, unaligned, wrapping, kernel-half, or ABI-arena-crossing
/// ranges. Native/Win32 ranges remain below 4 GiB; Linux loaders opt into the
/// canonical 47-bit user range before publication.
bool ProcessReserveMmapRange(Process* process, u64 size_bytes, u64* base_out);

/// Acquire snapshot for pre-publication fork inheritance and diagnostics.
u64 ProcessMmapCursorSnapshot(const Process* process);

/// Move-only scope for the outer Process address-space transaction mutex.
/// Lock order is Process::vm_transaction_lock -> scheduler registry ->
/// AddressSpace mutation lock. The inner locks need not overlap, but callers
/// must never acquire this while already inside either inner scope.
class ScopedProcessVmTransaction final
{
  public:
    explicit ScopedProcessVmTransaction(Process* process);
    ~ScopedProcessVmTransaction();

    ScopedProcessVmTransaction(const ScopedProcessVmTransaction&) = delete;
    ScopedProcessVmTransaction& operator=(const ScopedProcessVmTransaction&) = delete;
    ScopedProcessVmTransaction(ScopedProcessVmTransaction&&) = delete;
    ScopedProcessVmTransaction& operator=(ScopedProcessVmTransaction&&) = delete;

    /// Release early for a noreturn path such as fatal post-commit exec.
    void Unlock();

  private:
    Process* m_process;
};

/// Move-only admission scope for access to a published Process's mutable
/// runtime. The caller must already own a strong Process reference. Admission
/// locks vm_transaction_lock and succeeds only while lifecycle is Published;
/// the reaper transitions to Exiting under the same mutex before draining the
/// runtime, so no admitted operation can overlap teardown and an Exited header
/// can never expose a stale AS, fd table, Section view, or mutable handle table.
class ScopedProcessRuntimeAccess final
{
  public:
    explicit ScopedProcessRuntimeAccess(Process* process);
    ~ScopedProcessRuntimeAccess();

    ScopedProcessRuntimeAccess(const ScopedProcessRuntimeAccess&) = delete;
    ScopedProcessRuntimeAccess& operator=(const ScopedProcessRuntimeAccess&) = delete;
    ScopedProcessRuntimeAccess(ScopedProcessRuntimeAccess&&) = delete;
    ScopedProcessRuntimeAccess& operator=(ScopedProcessRuntimeAccess&&) = delete;

    explicit operator bool() const { return m_process != nullptr; }
    void Unlock();

  private:
    Process* m_process;
};

/// Move-only owner of one already-retained Process reference. The
/// constructor and Reset adopt a reference; they do not increment it.
/// Use with scheduler/handle APIs whose names end in `Retained` so every
/// early return releases deterministically. Detach transfers ownership to
/// a durable table or another explicit owner.
class ScopedProcessRef final
{
  public:
    explicit ScopedProcessRef(Process* process = nullptr) : m_process(process) {}
    ~ScopedProcessRef() { ProcessRelease(m_process); }

    ScopedProcessRef(const ScopedProcessRef&) = delete;
    ScopedProcessRef& operator=(const ScopedProcessRef&) = delete;

    ScopedProcessRef(ScopedProcessRef&& other) : m_process(other.m_process) { other.m_process = nullptr; }
    ScopedProcessRef& operator=(ScopedProcessRef&& other)
    {
        if (this != &other)
        {
            Reset();
            m_process = other.m_process;
            other.m_process = nullptr;
        }
        return *this;
    }

    [[nodiscard]] Process* Get() const { return m_process; }
    [[nodiscard]] Process* operator->() const { return m_process; }
    [[nodiscard]] explicit operator bool() const { return m_process != nullptr; }

    void Reset(Process* process = nullptr)
    {
        ProcessRelease(m_process);
        m_process = process;
    }

    [[nodiscard]] Process* Detach()
    {
        Process* process = m_process;
        m_process = nullptr;
        return process;
    }

  private:
    Process* m_process;
};

/// Encode/decode the opaque positive Win32 file-handle ABI. Decode performs
/// complete width, sign, generation, and slot validation and returns a nospec-
/// masked slot. Encode returns 0 for an invalid identity.
u64 EncodeWin32FileHandle(const Process::Win32FileHandleIdentity& identity);
bool DecodeWin32FileHandle(u64 handle, Process::Win32FileHandleIdentity* identity_out);
bool IsWin32FileHandle(u64 handle);

/// Claim one file-handle row without publishing it. The returned generation
/// token must be consumed by exactly one Publish or Abort call. Saturated
/// generations are never reused.
bool ProcessReserveWin32FileHandle(Process* owner, Process::Win32FileReservation* reservation_out);

/// Publish a fully-initialized candidate into the exact reserved row and
/// return its opaque generation-tagged handle. Candidate backing ownership transfers
/// to the table only on success.
bool ProcessPublishWin32FileHandle(Process* owner, const Process::Win32FileReservation& reservation,
                                   const Process::Win32FileHandle& candidate, u64* handle_out);

/// Cancel an unpublished file-row reservation. A stale token is a no-op.
void ProcessAbortWin32FileHandle(Process* owner, const Process::Win32FileReservation& reservation);

/// Atomically detach a live file row and copy its owned backing metadata to
/// `detached_out`. The caller releases that backing after the process lock is
/// gone. Normal close callers must first hold the matching
/// `win32_file_operation_locks` row so cursor-bearing operations are excluded.
/// Reserved/empty/invalid handles return false.
bool ProcessDetachWin32FileHandle(Process* owner, u64 handle, Process::Win32FileHandle* detached_out);

/// Count published, generation-valid Win32 file rows under the table lock.
/// Reserved pre-publication rows are intentionally excluded.
u32 ProcessWin32FileHandleCount(const Process* owner);

/// Encode/decode the opaque positive Win32 Section-handle ABI. Bits 0..11
/// retain the 0x900..0x907 low tag while bits 12..30 carry the process-row
/// generation. Decode masks the validated slot before returning it.
u64 EncodeWin32SectionHandle(const Process::Win32SectionHandleIdentity& identity);
bool DecodeWin32SectionHandle(u64 handle, Process::Win32SectionHandleIdentity* identity_out);
bool IsWin32SectionHandle(u64 handle);

/// Reserve one unpublished Section handle row. The returned exact generation
/// token must be consumed by Publish or Abort; exhausted generations never
/// wrap. Publish adopts the caller-owned SectionCreate reference only on
/// success.
bool ProcessReserveWin32SectionHandle(Process* owner, Process::Win32SectionHandleReservation* reservation_out);
bool ProcessPublishWin32SectionHandle(Process* owner, const Process::Win32SectionHandleReservation& reservation,
                                      subsystems::win32::section::SectionKey key, u64* handle_out);
void ProcessAbortWin32SectionHandle(Process* owner, const Process::Win32SectionHandleReservation& reservation);

/// Snapshot the exact pool key named by `handle`, pin it outside the process
/// lock, then revalidate the row. The caller owns the returned temporary pin
/// and must SectionRelease it.
bool ProcessAcquireWin32SectionHandle(Process* owner, u64 handle, subsystems::win32::section::SectionKey* key_out);

/// Atomically detach the exact live handle row. The caller adopts its pool
/// reference and releases it after the process lock is gone.
bool ProcessDetachWin32SectionHandle(Process* owner, u64 handle, subsystems::win32::section::SectionKey* key_out);
u32 ProcessWin32SectionHandleCount(const Process* owner);

/// Section-view row transaction. Reserve excludes exit/unmap before mapping;
/// Publish adopts a successfully mapped view reference. Claim transfers one
/// live row into exclusive unmap ownership. A failed exact unmap restores it;
/// a successful exact unmap consumes the reference and finishes the row.
bool ProcessReserveWin32SectionView(Process* owner, Process::Win32SectionViewReservation* reservation_out);
bool ProcessPublishWin32SectionView(Process* owner, const Process::Win32SectionViewReservation& reservation,
                                    subsystems::win32::section::SectionKey key, u64 base_va);
void ProcessAbortWin32SectionView(Process* owner, const Process::Win32SectionViewReservation& reservation);
bool ProcessClaimWin32SectionView(Process* owner, u64 base_va, Process::Win32SectionViewClaim* claim_out);
bool ProcessClaimWin32SectionViewExact(Process* owner, const Process::Win32SectionViewReservation& reservation,
                                       subsystems::win32::section::SectionKey key, u64 base_va,
                                       Process::Win32SectionViewClaim* claim_out);
bool ProcessRestoreWin32SectionView(Process* owner, const Process::Win32SectionViewClaim& claim);
bool ProcessFinishWin32SectionView(Process* owner, const Process::Win32SectionViewClaim& claim);
u32 ProcessWin32SectionViewCount(const Process* owner);

/// Fail-closed exec admission query for borrowed user mappings. The caller
/// holds `owner->vm_transaction_lock`; the preceding sole-Task scheduler gate
/// also excludes a concurrent current-process SysV syscall. Any non-Free
/// Section view transaction blocks exec, as does every live SysV SHM
/// attachment; whole-AS owned-page
/// replacement must never leave either owner's PTEs or lifetime records behind.
bool ProcessHasBorrowedUserMappings(const Process* owner);

/// Encode/decode the positive, generation-tagged Win32 Process handle ABI.
/// Decode validates the exact low-tag band before applying a nospec mask.
u64 EncodeWin32ProcessHandle(const Process::Win32ProcessHandleIdentity& identity);
bool DecodeWin32ProcessHandle(u64 handle, Process::Win32ProcessHandleIdentity* identity_out);
bool IsWin32ProcessHandle(u64 handle);

/// Install one already-retained `target` reference in `owner`'s Win32
/// process-handle table. On success the table adopts that reference and
/// returns an opaque handle; on failure returns 0 and ownership remains
/// with the caller. Slot publication is serialized by win32_handle_lock.
u64 ProcessInstallWin32ProcessHandle(Process* owner, Process* target);

/// Resolve an opaque Win32 process handle and take a reference while the
/// owning slot is still locked. The returned pointer remains alive across
/// blocking operations and must be paired with ProcessRelease. Returns
/// nullptr for an invalid, closed, or empty handle.
Process* ProcessLookupWin32ProcessHandleRetained(Process* owner, u64 handle);

/// Atomically remove a Win32 process-handle slot, then drop its target
/// reference after releasing win32_handle_lock. Returns false for an
/// invalid or already-closed handle.
bool ProcessCloseWin32ProcessHandle(Process* owner, u64 handle);

/// Count live Win32 process handles under win32_handle_lock.
u32 ProcessWin32ProcessHandleCount(const Process* owner);

/// Drop every reference this process's Win32 process-handle table
/// (`win32_proc_handles`, backing NtOpenProcess) holds on another
/// Process — or on itself.
///
/// This CANNOT wait for final ProcessRelease. `Process::refcount` counts
/// live tasks plus handle holders, so a retained process handle is
/// exactly what keeps the refcount above 0 and makes
/// final header reclamation unreachable: a process that opens
/// a handle on itself pins itself forever, and two processes that
/// open handles on each other form a cycle neither can break. The
/// drop therefore has to happen on the LAST TASK EXIT — a strictly
/// earlier event than the last reference drop — which is why the
/// one-shot reaper completion path is the caller.
void ProcessDropOwnedProcessHandles(Process* p);

/// Current Task's Process, or nullptr if the current Task is
/// kernel-only. Used by syscall handlers to check caps.
Process* CurrentProcess();

// =========================================================================
// Linux process-pending signal helpers.
// =========================================================================

/// Linux's stable sigset bit encoding. Signal numbers are 1..64 and map to
/// bits 0..63. Invalid signal numbers return zero instead of performing an
/// undefined-width shift.
constexpr u64 ProcessLinuxSignalBit(u32 signum)
{
    return signum >= 1 && signum <= 64 ? (1ULL << (signum - 1U)) : 0;
}
static_assert(ProcessLinuxSignalBit(0) == 0 && ProcessLinuxSignalBit(1) == 1ULL &&
              ProcessLinuxSignalBit(64) == (1ULL << 63) && ProcessLinuxSignalBit(65) == 0);

/// Acquire-snapshot the coalesced process-pending signal set. The Process
/// lifetime must remain pinned by the caller.
u64 ProcessLinuxSignalPendingSnapshot(const Process* process);

/// Release-publish one pending signal and wake signalfd readers after the
/// atomic publication. Returns false for a null Process or invalid signum.
bool ProcessLinuxSignalRaisePending(Process* process, u32 signum);

/// Atomically consume exactly one pending signal. A concurrent producer can
/// never be lost: failed compare/exchange retries observe its merged bitmap.
bool ProcessLinuxSignalClaimPending(Process* process, u32 signum);

/// Re-publish a set previously claimed by one consumer (for example when its
/// final user copy fails), then wake readers. A zero mask is a no-op.
void ProcessLinuxSignalRestorePending(Process* process, u64 signal_mask);

/// Acquire-snapshot the stable signal publication sequence used to linearize
/// signalfd predicate scans with scheduler enqueue.
u64 ProcessLinuxSignalEventSequenceSnapshot(const Process* process);

/// Publish a non-bitmap signalfd predicate change (for example a mask update)
/// and wake readers. The sequence saturates instead of wrapping.
void ProcessLinuxSignalNotifyWaiters(Process* process);

/// Block only while the stable signal publication sequence is unchanged.
/// Cancellation remains distinguishable so signalfd read can return -EINTR.
sched::WaitQueueBlockResult ProcessWaitForLinuxSignalEvent(Process* process, u64 observed_sequence);

/// Human-friendly cap name for diagnostics — returns a static
/// string or "unknown". Must be safe from any context (no locks,
/// no allocation).
const char* CapName(Cap c);

/// Called from every cap-denial site (inside a syscall that rejected its
/// caller). Charges the current Process's exact AuthorizationContext and, if
/// the threshold is crossed, flags the task for termination at next resched
/// (the scheduler converts the flag into a Dead transition).
///
/// Idempotent past the threshold — repeated calls keep
/// counting but the task is flagged exactly once. `cap`
/// argument is just for the log line; no functional effect.
u64 RecordSandboxDenial(Cap cap);

/// FS write rate-limit hook. Call from every successful
/// file-write syscall site (Win32 SYS_FILE_WRITE, Linux
/// sys_write to a regular file) AFTER the bytes have actually
/// landed on backing storage. Bumps per-process counters,
/// rolls the rate-limit window, and on threshold crossing:
///   1) bumps the global `MassFsWriteRate` health counter,
///   2) flags the calling task for kill via FlagCurrentForKill
///      with `KillReason::FsWriteRateExceeded`.
///
/// Idempotent past the threshold — repeated calls keep
/// counting and re-flagging, but the kill flag is itself
/// idempotent so the cost is just one extra log line per
/// over-cap call (which is desirable: the operator wants to
/// see how badly the rogue process pushed past the cap).
///
/// `bytes == 0` is a no-op (matches `write(2)` semantics where
/// a zero-length write is a query, not a transfer). `p ==
/// nullptr` is a no-op for kernel-only paths that don't have a
/// Process attached.
void RecordFsWrite(Process* p, u64 bytes);

/// Pure-bookkeeping variant of RecordFsWrite. Updates every
/// per-process window's running counter + rolls each one's
/// timestamp, and returns true if any window crossed its cap.
/// Does NOT bump global counters and does NOT flag the current
/// task for kill — useful for the attacker-simulation suite
/// where we want to verify the threshold logic without killing
/// the kernel main task that's running the test.
bool RecordFsWriteCheck(Process* p, u64 bytes);

/// Same as RecordFsWriteCheck but returns the INDEX of the
/// first window level that tripped (0..kFsWriteWindowCount-1)
/// or -1 if every window is still under cap. Lets test paths
/// distinguish which timescale fired without re-deriving from
/// raw bytes.
i32 RecordFsWriteCheckLevel(Process* p, u64 bytes);

/// Rate-limit predicate for denial log output. Call sites check
/// this after incrementing the counter (see
/// e.g. kernel/syscall/syscall.cpp SYS_WRITE/STAT/READ denial
/// paths) so a burst of 100 denials produces ~4 log lines
/// instead of 100 — the counter still advances every time, the
/// threshold-kill still fires at exactly 100. Returns true for
/// the 1st denial, then the 32nd, 64th, 96th, and so on.
bool ShouldLogDenial(u64 denial_index);

/// Register a loaded DLL image on `proc`. Copies `image` into
/// the next free slot of `proc->dll_images[]` and bumps
/// `dll_image_count`. Returns false if the table is full — the
/// caller should treat that as a load failure (a DLL that
/// can't be found via `ProcessResolveDllExport` is worse than
/// not loaded, because the mapping is already in the AS).
///
/// `proc` must be non-null. `image` must come from a successful
/// `DllLoad(... proc->as ...)` — the image's `base_va`/`exports`
/// reference bytes mapped in that AS and parsed from the
/// backing buffer; the buffer must stay alive for the Process's
/// lifetime.
bool ProcessRegisterDllImage(Process* proc, const DllImage& image);

/// Resolve an export name against every DLL registered on
/// `proc`. Returns the absolute VA on the first hit, or 0 on
/// miss. When `dll_name` is non-null, only the matching DLL's
/// EAT is consulted (case-insensitive match on the DLL's own
/// name embedded in its Export Directory); when `dll_name` is
/// null, every registered DLL is searched in registration
/// order. Forwarder exports currently return 0 — the caller
/// must handle forwarder chasing (not yet implemented).
u64 ProcessResolveDllExport(const Process* proc, const char* dll_name, const char* func_name);

/// Resolve an export by HMODULE (= DLL load-base VA), matching
/// the Win32 `GetProcAddress(HMODULE, LPCSTR)` shape. Returns
/// the absolute VA on hit, 0 on miss.
///
/// `base_va == 0` searches every registered DLL (useful for a
/// future "GetModuleHandle(NULL) handed us the EXE" behaviour
/// that wants to fall through to DLLs). A non-zero `base_va`
/// restricts the search to the single DLL whose load base
/// matches — Win32 callers always narrow this way, so the
/// common path stays O(1) in the DLL count.
///
/// Backs `SYS_DLL_PROC_ADDRESS`.
u64 ProcessResolveDllExportByBase(const Process* proc, u64 base_va, const char* func_name);

/// Look up a DLL in `proc`'s loaded-image table by name and
/// return its base VA. Backs SYS_DLL_BASE_BY_NAME →
/// GetModuleHandleW / LoadLibraryW for any DLL the loader has
/// already mapped (kernel32.dll, user32.dll, ucrtbase.dll, …).
/// Case-insensitive; tolerant of `.dll` suffix on either side
/// (export-table dll_name and caller-supplied lookup don't have
/// to match in form). Returns 0 on miss.
u64 ProcessFindDllBaseByName(const Process* proc, const char* dll_name);

/// Reverse map: given an absolute user VA, return the load base of
/// the module (main EXE image or any preloaded DLL) whose mapped
/// range contains it, or 0 if the VA lies in no known module.
/// Backs the cross-module `RtlLookupFunctionEntry` (SEH frame walk
/// crossing the EXE↔kernel32↔ntdll boundary) — ntdll asks the
/// kernel "which image owns this RIP?" so it can read that
/// module's in-memory `.pdata`. DLL ranges are matched by the
/// recorded `[base_va, base_va+size)`; the EXE has no recorded
/// size, so a VA at/above `pe_image_base` that matched no DLL
/// falls back to the EXE base (the ntdll side re-validates the
/// MZ/PE header before trusting it, so an over-broad EXE guess
/// fails safe to "no function entry").
u64 ProcessFindModuleBaseByVa(const Process* proc, u64 va);

/// Current count of live Process objects. Diagnostic-only; the
/// scheduler's task counters remain the source of truth for thread
/// counts, while this exposes the execution-lifetime counter incremented by
/// ProcessCreate and decremented by published exit or Private abort.
u64 ProcessLiveCount();

/// Count currently-open local and foreign Win32 thread handles
/// under the process's lifecycle lock. Diagnostic and process-
/// information readers use this instead of racing open/close.
u32 ProcessWin32ThreadHandleCount(const Process* process);

/// Publish a Win32 thread's terminal state exactly once. The normal
/// SYS_EXIT path supplies the application code; scheduler kill paths
/// call it with a fallback and cannot overwrite an earlier result.
void ProcessPublishWin32ThreadExit(Process* process, u64 tid, u32 exit_code);

/// Self-test of the process model's pure helpers: CapSet bitmap
/// operations, CapName lookup, the denial rate-limit predicate, and
/// the boundary checks around kCapNone / kCapCount. Does NOT create
/// a Process — that path needs an AddressSpace + scheduler that
/// aren't online at the call site. Panics on any failure.
void ProcessSelfTest();

/// Heap-phase test of Win32 process-handle publication, target pinning,
/// close/drain idempotence, and exact reference ownership. Uses synthetic
/// Process allocations and therefore must run only after KernelHeapInit.
void ProcessHandleLifetimeSelfTest();

/// Drain up to `cap` bytes from `proc`'s stdin ring into `dst_user`
/// (a ring-3 VA). Blocks via the ring's waitqueue until at least
/// one byte is available. Returns the number of bytes copied, or
/// the kernel-side -1 on a bad user pointer. Caller-side ABI
/// matches POSIX read(): a partial copy is fine — never blocks for
/// "fill the buffer," always returns as soon as any data is ready.
i64 ProcessReadStdinBlocking(Process* proc, void* dst_user, u64 cap);

/// Non-blocking probe of `proc`'s stdin ring. Returns the number of
/// bytes currently buffered (0 when empty) without consuming any of
/// them, or the kernel-side -1 on a bad user pointer. When `dst_user`
/// is non-null and `cap` > 0, additionally copies up to
/// min(cap, available) bytes into `dst_user` WITHOUT advancing the
/// ring tail — a subsequent ProcessReadStdinBlocking returns the same
/// bytes. `dst_user == nullptr` / `cap == 0` is the count-only form.
/// Claims stdin focus exactly like the blocking read so that a
/// poll-before-read consumer (kbhit loops) starts receiving bytes
/// without ever having to block first. Never blocks.
i64 ProcessPeekStdin(Process* proc, void* dst_user, u64 cap);

/// Push one cooked byte into whatever process currently owns the
/// stdin focus. The global focus owns a Process reference; this call
/// takes a temporary pin under the focus lock and admits the mutable
/// runtime before touching its ring. No-op when no live focus is
/// registered. This is the sole kbd-reader producer entry point.
void ProcessFeedStdinFocusChar(char c);

// =========================================================================
// Linux current-working-directory helpers.
// =========================================================================

/// Coherent fixed-capacity snapshot of a Process's Linux CWD. `length`
/// excludes the trailing NUL; `path[length]` is always NUL on success.
struct LinuxCwdSnapshot
{
    char path[Process::kLinuxCwdCap];
    u64 length;
};

/// Snapshot the CWD while holding only the owning Process's leaf cwd lock.
/// The caller must hold the Process lifetime (the current task's Process is
/// sufficient). The helper publishes to `snapshot_out` only after dropping
/// the lock, and performs no allocation, user copy, VFS work, or logging.
bool ProcessSnapshotLinuxCwd(const Process* process, LinuxCwdSnapshot* snapshot_out);

/// Replace the CWD from a trusted kernel buffer. `length` excludes the NUL
/// and must be in [1, kLinuxCwdCap). Validation and candidate construction
/// happen before taking the leaf cwd lock; the locked section is one bounded
/// fixed-buffer copy. The source must not alias Process::linux_cwd.
bool ProcessReplaceLinuxCwd(Process* process, const char* path, u64 length);

// =========================================================================
// Linux fd-table helpers (Linux fd → KFile migration).
//
// Centralises the "find lowest free fd >= N", per-fd CLOEXEC
// flag, fork-time inheritance, and exec-time teardown that
// were previously open-coded across ~13 syscall handlers
// (open, pipe, eventfd, socket, timerfd, signalfd, epoll,
// inotify, fanotify, pidfd, mq_open, memfd, dup/dup2/dup3,
// fcntl(F_DUPFD/F_DUPFD_CLOEXEC), close, clone(CLONE_FILES)).
//
// For pool-backed kinds (states 3..15) the helpers also wire
// a `KFile` sidecar into `Process::kobj_handles` so per-pool
// retain/release rides KObject refcounting instead of the
// scatter of explicit `*Retain` / `*Release` calls in the
// syscall layer. State 0/1/2 use the helpers but skip the
// KFile sidecar (no pool ref to count).
// =========================================================================

/// Lowest free fd ≥ `lo`, capped at `LinuxFdEffectiveMax(p)`
/// (which honours RLIMIT_NOFILE). Returns -1 = no slot. Does
/// NOT mark the slot in_use — caller stamps the slot's `state`
/// + per-kind data immediately after.
/// Plain ownership receipts for the fd transaction core. A zeroed receipt owns
/// nothing. Live receipts are consumed by a successful operation or released
/// explicitly after fd/handle/epoll/async locks are gone; no stack destructor
/// performs hidden KObject or OFD cleanup.
struct LinuxFdPrepared
{
    Process::LinuxFd snapshot;
    ipc::KObject* kfile_ref;
    bool owns_ofd_ref;
};

struct LinuxFdAcquired
{
    Process::LinuxFd snapshot;
    ipc::KObject* kfile_ref;
    bool owns_ofd_ref;
};

struct LinuxFdTransfer
{
    u32 source_fd;
    Process::LinuxFd snapshot;
    ipc::KObject* kfile_ref;
    bool owns_ofd_ref;
};

struct LinuxFdDetached
{
    u32 source_fd;
    Process::LinuxFd snapshot;
    ipc::KObject* kfile_ref;
    bool owns_ofd_ref;
};

/// Sleepable serialization guard for one retained open-file description.
/// Enter only from a live LinuxFdAcquired receipt and keep that receipt alive
/// until Exit. Enter samples the OFD under its spinlock, drops that spinlock,
/// then acquires this mutex; callers may hold the guard across VFS work, user
/// copies, and the final offset commit. pread/pwrite use the same guard for I/O
/// serialization but deliberately skip the shared-position accessors.
struct LinuxFdIoGuard
{
    sched::Mutex* position_lock;
    u16 ofd;
    bool held;
};

/// Retained regular-file OFD commit. Only PendingCreate is a valid flag mask;
/// CLOEXEC and Canary remain per-slot and are never overwritten. The caller
/// must hold the matching LinuxFdIoGuard so a dup/fork sibling cannot
/// interleave backing-state changes with the VFS operation. A concurrent
/// close does not cancel an already-started operation: the authoritative OFD
/// is still updated, while the compatibility slot mirror is updated only if
/// the original generation remains installed.
struct LinuxFdRegularMetadataCommit
{
    u8 flags_mask;
    u8 flags_value;
    bool update_first_cluster;
    bool update_size;
    u32 first_cluster;
    u32 size;
};

/// Build a receipt for a new descriptor. Success adopts `owned_kfile` and,
/// for non-TTY descriptors, owns one fresh OFD reference. Failure leaves the
/// KObject with the caller and clears `prepared`.
bool LinuxFdPrepare(LinuxFdPrepared* prepared, const Process::LinuxFd& payload, ipc::KObject* owned_kfile,
                    u32 status_flags);
void LinuxFdPreparedRelease(LinuxFdPrepared* prepared);

/// Publish one or two prepared descriptors at the lowest available slots.
/// Pair publication is all-or-nothing. Success consumes the receipt(s).
i32 LinuxFdBindLowest(Process* p, u32 lo, LinuxFdPrepared* prepared, bool cloexec,
                      LinuxFdAcquired* acquired_out = nullptr);
bool LinuxFdBindPairLowest(Process* p, u32 lo, LinuxFdPrepared* first, LinuxFdPrepared* second, u32* first_fd,
                           u32* second_fd, LinuxFdAcquired* first_acquired_out = nullptr,
                           LinuxFdAcquired* second_acquired_out = nullptr);

/// Retain one exact descriptor identity. `expected_state == 0` accepts any
/// live state. Clone duplicates an already-acquired identity without another
/// numeric fd-table lookup, as required by epoll wait snapshots.
bool LinuxFdAcquire(Process* p, u32 fd, u8 expected_state, LinuxFdAcquired* acquired);
bool LinuxFdAcquiredClone(const LinuxFdAcquired* source, LinuxFdAcquired* clone_out);
void LinuxFdAcquiredRelease(LinuxFdAcquired* acquired);
/// Re-snapshot descriptor-local bits plus authoritative shared OFD metadata
/// after waiting for an I/O guard. The retained identity must still match the
/// same fd generation/state/OFD/KFile; close+reuse fails without exposing
/// replacement metadata.
bool LinuxFdRefreshAcquired(Process* p, u32 fd, const LinuxFdAcquired* acquired, const LinuxFdIoGuard* guard,
                            Process::LinuxFd* snapshot_out);

/// Refresh a retained regular-file receipt after acquiring its matching OFD
/// guard. The source Process/numeric fd is deliberately not consulted: close
/// or reuse cannot cancel an operation that already retained the OFD. Starts
/// from the receipt snapshot and overlays only OFD-authoritative
/// PendingCreate, first_cluster, and size; it neither writes a slot mirror nor
/// refreshes offset/status flags.
bool LinuxFdRefreshRetainedRegular(const LinuxFdAcquired* acquired, const LinuxFdIoGuard* guard,
                                   Process::LinuxFd* snapshot_out);

/// Acquire/release the per-OFD sleepable serialization mutex. None of these
/// operations retain or release the receipt; the LinuxFdAcquired owner pins
/// the OFD for the guard's entire lifetime.
bool LinuxFdIoGuardEnter(const LinuxFdAcquired* acquired, LinuxFdIoGuard* guard);
void LinuxFdIoGuardExit(LinuxFdIoGuard* guard);
bool LinuxFdIoGuardGetOffset(const LinuxFdIoGuard* guard, u64* offset_out);
bool LinuxFdIoGuardSetOffset(LinuxFdIoGuard* guard, u64 offset);
bool LinuxFdIoGuardAdvanceOffset(LinuxFdIoGuard* guard, u64 delta, u64* previous_out, u64* current_out);
bool LinuxFdIoGuardGetStatusFlags(const LinuxFdIoGuard* guard, u32* flags_out);
bool LinuxFdIoGuardSetStatusFlags(LinuxFdIoGuard* guard, u32 flags);

/// Detach one or a batch of slots, moving all owned references into explicit
/// cleanup receipts. Returns the number of populated batch receipts.
bool LinuxFdUnbind(Process* p, u32 fd, LinuxFdDetached* detached);
bool LinuxFdUnbindAcquired(Process* p, u32 fd, const LinuxFdAcquired* acquired, LinuxFdDetached* detached);
u32 LinuxFdDetachAll(Process* p, LinuxFdDetached* detached, u32 capacity);
u32 LinuxFdDetachCloexec(Process* p, LinuxFdDetached* detached, u32 capacity);
void LinuxFdDetachedRelease(LinuxFdDetached* detached);

/// CLOEXEC requires the exact descriptor generation. Regular metadata commits
/// use the retained guarded OFD as authority after VFS mutation and touch the
/// numeric slot mirror only while the exact generation is still installed.
bool LinuxFdSetCloexecAcquired(Process* p, u32 fd, const LinuxFdAcquired* acquired, bool on);
bool LinuxFdCommitRegularMetadataAcquired(Process* p, u32 fd, const LinuxFdAcquired* acquired,
                                          const LinuxFdIoGuard* guard, const LinuxFdRegularMetadataCommit* commit);

/// Failure-atomic POSIX duplication. Exact replacement keeps the destination
/// unchanged on failure and cleans displaced identities after the fd lock.
i32 LinuxFdDuplicateLowest(Process* p, u32 oldfd, u32 lo, bool cloexec);
bool LinuxFdDuplicateExact(Process* p, u32 oldfd, u32 newfd, bool cloexec);

/// Cross-process transport. Export and import never hold two processes' fd
/// locks together; imports consume transfers only after successful publish.
bool LinuxFdExport(Process* source, u32 source_fd, LinuxFdTransfer* transfer);
void LinuxFdTransferRelease(LinuxFdTransfer* transfer);
i32 LinuxFdImportLowest(Process* destination, u32 lo, LinuxFdTransfer* transfer, bool cloexec);
bool LinuxFdImportExact(Process* destination, u32 destination_fd, LinuxFdTransfer* transfer, bool cloexec);
/// Export a failure-atomic table receipt. Empty tables are successful with
/// `*count_out == 0`; false uniquely reports validation/capacity/retain failure.
bool LinuxFdExportTable(Process* source, LinuxFdTransfer* transfers, u32 capacity, u32* count_out);
bool LinuxFdImportTable(Process* destination, LinuxFdTransfer* transfers, u32 count);

i32 LinuxFdAllocLowest(Process* p, u32 lo);

/// Stamp the KFile sidecar onto an already-allocated slot.
/// `kind` is the per-state pool tag; `pool_index` is whatever
/// the per-state pool returned (e.g. PipeAlloc's slot index);
/// `release` is the per-pool release function fired when the
/// KFile's refcount drops to zero. Returns false on heap or
/// HandleTable exhaustion (caller should roll back: free pool
/// slot + zero fd state). On success, stores the resulting
/// `ipc::Handle` in `p->linux_fds[fd].kf_handle` so close /
/// dup / fork can route through the unified table.
/// `out_pool_released`, when non-null, is set true when a failed
/// HandleTableInsert already dropped the newly-created KFile and fired
/// its pool-release callback. Callers that own the pool slot can use the
/// false case to release it themselves (KFileCreate failure).
bool LinuxFdAttachKFile(Process* p, u32 fd, u8 kind, u32 pool_index, void (*release)(u32),
                        bool* out_pool_released = nullptr);

/// Owner-aware variant of `LinuxFdAttachKFile`. Used by dirfd
/// (kind=11), whose backing storage is a `Process::win32_dirs[]`
/// slot — the release callback needs the owning Process to free
/// the slot. The owner is captured at attach time and pinned via
/// the no-cross-process rule (pidfd_splice refuses state 11; fork
/// closes the child's dirfd slots immediately). Rolls back the
/// pool slot via the release callback if HandleTable insertion
/// fails (mirroring `LinuxFdAttachKFile`'s rollback shape).
bool LinuxFdAttachKFileOwned(Process* p, u32 fd, u8 kind, u32 pool_index, void (*release)(Process*, u32));

/// Tear down a Linux fd slot. If a KFile sidecar is attached,
/// drops its handle-table reference (which fires the per-pool
/// release callback when refcount hits zero). Zeroes
/// state/first_cluster/size/offset/path so the slot is reusable.
/// No-op for slots already in state 0. Does NOT honour the
/// reserved-tty rule (state 1) — the legacy `DoClose` keeps that
/// guard at the syscall boundary.
void LinuxFdClose(Process* p, u32 fd);

/// Duplicate slot `oldfd` into slot `newfd`. Copies state +
/// first_cluster + size + path and SHARES the open-file
/// description (OFD) — both fds point at one refcounted OFD, so
/// a seek/offset change through one fd is visible through the
/// other (POSIX dup semantics). If a KFile sidecar exists, calls
/// `HandleTableDuplicate` so both fds share the underlying KFile
/// + its pool ref (each fd holds one ref — closing one drops one
/// ref, closing both fires the per-pool release callback).
/// Closes any existing slot at `newfd` first. Caller is
/// responsible for setting cloexec on the new slot if dup3
/// honoured O_CLOEXEC. Returns false on HandleTable / OFD-pool
/// exhaustion.
bool LinuxFdDup(Process* p, u32 oldfd, u32 newfd);

/// Set / clear FD_CLOEXEC on a slot. No-op for unused slots.
void LinuxFdSetCloexec(Process* p, u32 fd, bool on);
bool LinuxFdGetCloexec(const Process* p, u32 fd);

/// Open-file-description (OFD) accessors. The OFD is the
/// refcounted object that dup()/dup2()/dup3()/fork make the new
/// fd SHARE with the source fd — one file offset + one set of
/// O_* status flags per open, exactly as POSIX requires. These
/// are the authoritative read/write path for a slot's offset and
/// status flags; they keep `linux_fds[fd].offset` mirrored so the
/// existing inline readers still see the live value.
///
/// `LinuxFdOpenDescription` allocates a fresh OFD for a slot
/// (called at open/pipe/socket/etc. creation time when a brand-new
/// description is wanted). No-op-returns-true if the slot already
/// owns an OFD. Returns false only on OFD-pool exhaustion.
bool LinuxFdOpenDescription(Process* p, u32 fd, u64 initial_offset, u32 status_flags);
u64 LinuxFdGetOffset(const Process* p, u32 fd);
void LinuxFdSetOffset(Process* p, u32 fd, u64 offset);
u32 LinuxFdGetStatusFlags(const Process* p, u32 fd);
void LinuxFdSetStatusFlags(Process* p, u32 fd, u32 status_flags);

/// THE single implementation of copying one Linux fd from one
/// process's table into another's. Both fork inheritance and
/// `pidfd_getfd` route through it — never hand-roll a raw
/// `dst->linux_fds[i] = src->linux_fds[j]` struct copy, because
/// two of the fields are NOT process-portable:
///   - `kf_handle` is a dense index into the SOURCE's own handle
///     table (no owner tag, no generation counter), so the raw
///     value names an unrelated object in the destination. This
///     helper duplicates it with `HandleTableDuplicate`, which is
///     also what takes the per-pool reference — callers must NOT
///     add an explicit `*Retain`.
///   - `ofd` is a refcounted kernel-wide open-file-description
///     index; this helper retains it so both fds share one
///     description (POSIX fork/dup semantics) and neither side's
///     close frees it out from under the other.
/// `flags` (incl. FD_CLOEXEC) copies verbatim; callers needing
/// Linux's per-API cloexec rule call `LinuxFdSetCloexec` after.
/// Overwrites `dst_fd` without closing it — the caller owns
/// releasing an occupied destination slot first. Returns false
/// (leaving `dst_fd` unused and the OFD retain rolled back) when
/// the destination handle table is full.
bool LinuxFdCopyAcrossProcesses(Process* dst, u32 dst_fd, Process* src, u32 src_fd);

/// Copy the parent's inheritable fd-table snapshot into `child` at fork time
/// through one export/filter/import transaction. State-11 directory snapshots
/// are parent-owned and are released from the transfer set before any child
/// publication. Every other imported slot shares the parent's OFD and owns its
/// own KFile reference.
/// FD_CLOEXEC is preserved on the inherited slot — Linux
/// semantics: fork copies cloexec fds; only execve drops them.
/// Caller (DoFork / DoClone) must have already initialised
/// `child`'s fd table via `ProcessCreate`. Returns false without publishing a
/// partial table; the caller must abort private child construction.
bool LinuxFdInheritFromParent(Process* parent, Process* child);

/// Walk the fd table and close every slot with FD_CLOEXEC set.
///
/// Called by the native SYS_EXECVE handler at its point of no return,
/// immediately before `AddressSpaceClearUserMappings` replaces the
/// image — so it covers every ABI that routes through execve, not just
/// the Linux one. Invoked there and by the boot-time self-test that
/// exercises the CLOEXEC bit's plumbing.
///
/// Firing at the commit point is deliberate: POSIX closes these fds
/// only when exec actually SUCCEEDS, and every execve failure path
/// returns with the caller's fd table untouched.
void LinuxFdCloseOnExec(Process* p);

/// Self-test for the Linux fd-table helpers. Boot-time only;
/// exercises a synthetic Process's fd table through alloc /
/// dup / cloexec-set / inherit / close-on-exec. Panics on any
/// invariant violation.
void LinuxFdSelfTest();

} // namespace duetos::core
