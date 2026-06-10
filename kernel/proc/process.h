#pragma once

#include "fs/fat32.h"
#include "ipc/handle_table.h"
#include "loader/compat_shim.h"
#include "loader/dll_loader.h"
#include "sched/sched.h"
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
// NOT exposed — the kernel's spawn-time inheritance is the only
// path that grants caps. CapSetRemove is the safe counterpart.
inline constexpr void CapSetRemove(CapSet& s, Cap c)
{
    if (c == kCapNone || c >= kCapCount)
    {
        return;
    }
    s.bits &= ~(1ULL << static_cast<u32>(c));
}

struct Process
{
    u64 pid;
    const char* name;
    mm::AddressSpace* as;
    CapSet caps;
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

    // CPU-tick budget. tick_budget is a hard cap; ticks_used is
    // incremented by the timer IRQ for every tick this process's
    // task(s) were currently-running. When ticks_used >= tick_budget,
    // the scheduler marks the task Dead on its next re-enqueue
    // (see sched.cpp) and the reaper drops the Process reference.
    //
    // Sandbox profile gets a tight budget (long enough for normal
    // work but short enough that a spin-loop is caught in seconds).
    // Trusted profile gets effectively unlimited — the value is
    // stored and checked, but set so high the check never fires in
    // practice.
    u64 tick_budget;
    u64 ticks_used;

    // Sandbox-denial counter. Every cap-gated syscall that rejects
    // the caller bumps this by one. Legitimate sandboxed code
    // shouldn't attempt blocked syscalls; a process that crosses
    // the threshold is almost certainly hostile (e.g. brute-
    // forcing syscalls looking for something that isn't denied)
    // and is terminated. Complements the tick budget: a spinning
    // task would be caught by ticks, a retrying task by denials.
    u64 sandbox_denials;
    // Latch so the threshold-kill log + FlagCurrentForKill run at
    // most once even if multiple racing denials all observe a
    // counter past the kill threshold.
    bool sandbox_kill_flagged;

    // FS write rate-limit windows (multi-tier).
    //
    // Three rolling windows at decreasing granularities defend
    // against the full range of mass-file-rewrite strategies:
    //
    //   [0] burst    — 1 s   /  16 MiB : catches "go full speed".
    //   [1] sustained — 5 min /  256 MiB : catches "stay just under
    //                                       the burst cap forever".
    //   [2] long     — 1 h   /   2 GiB : catches "stay under
    //                                     sustained too" (≤ ~700 KiB/s
    //                                     averaged across an hour).
    //
    // An attacker who reads our open-source threshold constants
    // can stay under any single window with patience; staying
    // under all three at once requires moving so little data the
    // attack stops being worthwhile. The three caps do NOT
    // cumulate — a process is killed the moment ANY one of them
    // is breached.
    //
    // Each successful file-write syscall (Win32 SYS_FILE_WRITE,
    // SYS_FILE_CREATE init bytes, Linux sys_write to a regular
    // file, copy_file_range) calls `RecordFsWrite`, which adds
    // bytes to every window's running counter, rolls any window
    // past its tick budget, and on threshold-cross flags the
    // calling task for kill via `KillReason::FsWriteRateExceeded`.
    // `fs_write_bytes_total` is the cumulative lifetime counter
    // for telemetry only — never gates anything by itself.
    //
    // Threat model: trusted process IS the attacker (compromised
    // PE / ELF, smuggled installer). No cap-based exemption.
    static constexpr u32 kFsWriteWindowCount = 3;
    u64 fs_write_bytes_total;
    u64 fs_write_window_bytes[kFsWriteWindowCount];
    u64 fs_write_window_start_tick[kFsWriteWindowCount];

    // Win32 process heap — a per-process free-list allocator.
    // `heap_base` is the fixed user VA where heap pages start
    // (kWin32HeapVa, 0x50000000). `heap_pages` is the count of
    // pages currently mapped (zero if the PE had no imports and
    // the loader didn't stand up a heap). `heap_free_head` is
    // the user VA of the first free block's header; nullptr =
    // empty free list (everything allocated or heap uninit).
    //
    // Managed by kernel/subsystems/win32/heap.cpp and mutated
    // from SYS_HEAP_ALLOC / SYS_HEAP_FREE. A real Windows NT
    // process has many heaps (default + LocalAlloc + HeapCreate
    // returns); v0 collapses this to one process-wide heap.
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
        // Per-fd flag bits. kLinuxFdFlagPendingCreate (0x01) marks a
        // freshly-opened-with-O_CREAT regular-file fd whose backing
        // disk entry doesn't exist yet — the first sys_write routes
        // through Fat32CreateAtPath instead of Fat32AppendAtPath.
        // (FAT32's append path can't grow a 0-byte file in v0; see
        // fat32_write.cpp first_cluster<2 guards.)
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
    };
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
    struct Win32IatMiss
    {
        u64 slot_va;      // VA of the IAT slot (user-space).
        const char* name; // kernel-direct-map pointer into the PE's
                          // on-disk byte buffer (RAM-fs'd), valid
                          // for the life of the Process.
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
    // arrays in the kernel ELF.
    static constexpr u64 kDllImageCap = 48;
    DllImage dll_images[kDllImageCap];
    u64 dll_image_count;

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
    // Returned handles to user mode are `kWin32HandleBase + idx`
    // (= 0x100 + 0..15) so they don't collide with Win32 pseudo-
    // handles (-1 = INVALID_HANDLE_VALUE, -2 = current thread,
    // ...) or NULL. The kernel unwraps via `idx = handle -
    // kWin32HandleBase` and bounds-checks.
    //
    // 16 slots is plenty for v0 — typical console programs hold
    // ~4 (stdin/stdout/stderr + one input file). Grow to a
    // KMalloc'd table when a real workload needs more.
    enum class FsBackingKind : u8
    {
        None = 0, // slot is free
        Ramfs,
        Fat32,
        DuetFs,
        RamVol, // frame-backed writable RAM volume (/run); path-addressed
        Pipe,   // cross-process pipe end (Linux pipe pool slot)
    };
    struct Win32FileHandle
    {
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
    };
    static constexpr u64 kWin32HandleCap = 16;
    static constexpr u64 kWin32HandleBase = 0x100;
    Win32FileHandle win32_handles[kWin32HandleCap];

    // Win32 mutex handle range — backs CreateMutexW /
    // WaitForSingleObject / ReleaseMutex / CloseHandle. The
    // legacy fixed-size `Win32MutexHandle win32_mutexes[]` array
    // was removed when `SYS_MUTEX_*` migrated to `KMutex` +
    // `kobj_handles` (kernel/ipc/). The Win32 handle is now
    // `kWin32MutexBase + ipc_handle`, where `ipc_handle` is a
    // slot in the unified handle table (1..kHandleTableCapacity-1).
    // The cap below stays disjoint from kWin32EventBase (0x300)
    // and kWin32HandleBase (0x100..0x10F) so CloseHandle can
    // continue to dispatch by range without a tag bit.
    static constexpr u64 kWin32MutexBase = 0x200;
    static constexpr u64 kWin32MutexCap = ::duetos::ipc::kHandleTableCapacity;

    // Win32 event handle range — backs CreateEventW / SetEvent /
    // ResetEvent / WaitForSingleObject. Migrated to KEvent +
    // `kobj_handles` (kernel/ipc/) alongside mutexes; the legacy
    // `Win32EventHandle win32_events[]` array was removed at the
    // same time. The Win32 handle is now `kWin32EventBase +
    // ipc_handle`, with `ipc_handle` a slot in the unified handle
    // table. The cap stays disjoint from kWin32MutexBase (0x200)
    // and kWin32ThreadBase (0x400) so CloseHandle / WFMO can
    // continue to dispatch by range.
    static constexpr u64 kWin32EventBase = 0x300;
    static constexpr u64 kWin32EventCap = ::duetos::ipc::kHandleTableCapacity;

    // Win32 thread table — backs CreateThread. Each
    // slot carries a pointer to the scheduler Task that was
    // spawned for the thread + a small bit of lifecycle state.
    // Handles run kWin32ThreadBase + idx (= 0x400..0x407),
    // disjoint from every other Win32 handle range so a single
    // CloseHandle dispatch can pick the right table by value.
    //
    // v0 SCOPE (honest about what's not done):
    //   - All threads share the Process's single TEB page
    //     (kV0TebVa). Real Windows gives each thread its own
    //     TEB with per-thread TLS slots; that's a follow-up.
    //     Multi-threaded Win32 apps that key per-thread state
    //     off gs:[...] will see cross-thread bleeding. Apps
    //     that just want concurrent worker tasks over shared
    //     memory (the common case) work today.
    //   - No join / wait-for-thread primitive yet. CloseHandle
    //     frees the slot but doesn't block for exit. A future
    //     SYS_THREAD_JOIN / WaitForSingleObject(thread_handle)
    //     path lands the blocking side.
    //   - Thread exit is via SYS_EXIT (same as process exit);
    //     the scheduler's single-task-dies-cleanly path handles
    //     it. Exiting the LAST task in the process implicitly
    //     tears the process down; the ordering is the
    //     scheduler's existing reaper contract.
    struct Win32ThreadHandle
    {
        bool in_use;
        u8 _pad[3];
        // Win32 exit-code tracking. Starts at
        // STILL_ACTIVE (0x103); overwritten by the SYS_EXIT
        // path when the owning task dies. GetExitCodeThread
        // reads this field via SYS_THREAD_EXIT_CODE and
        // returns it as the DWORD exit code.
        u32 exit_code;
        sched::Task* task; // scheduler Task spawned for this thread
        u64 user_stack_va; // base VA of the thread's user stack
    };
    static constexpr u64 kWin32ThreadCap = 8;
    static constexpr u64 kWin32ThreadBase = 0x400;
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
    // Handles run kWin32ProcessBase + idx (= 0x700..0x707),
    // disjoint from every other Win32 handle range so the
    // shared CloseHandle / NtClose dispatch picks the right
    // table by value alone.
    //
    // 8 slots is plenty for v0 — typical malware-style "open
    // every PID, look for one with a matching name" probes
    // close handles as soon as they're checked, so the table
    // turns over fast. Grow when a real workload pins more.
    struct Win32ProcessHandle
    {
        bool in_use;
        u8 _pad[7];
        Process* target; // borrowed reference, refcount held while in_use
    };
    static constexpr u64 kWin32ProcessCap = 8;
    static constexpr u64 kWin32ProcessBase = 0x700;
    Win32ProcessHandle win32_proc_handles[kWin32ProcessCap];

    // Cross-process Win32 thread handles produced by
    // NtOpenThread(tid). Each entry pins a Task* (the target
    // thread) AND a Process* (the owner) — the owner ref is
    // ProcessRetained at open time so the foreign Task can't
    // be reaped under the inspector's hand. Disjoint from the
    // local win32_threads[] handle range (kWin32ThreadBase +
    // idx = 0x400..0x407) so the by-range dispatch in
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
        sched::Task* task; // borrowed
        Process* owner;    // refcount held while in_use
    };
    static constexpr u64 kWin32ForeignThreadCap = 8;
    static constexpr u64 kWin32ForeignThreadBase = 0x800;
    Win32ForeignThreadHandle win32_foreign_threads[kWin32ForeignThreadCap];

    // Win32 section handles produced by NtCreateSection. A
    // section is a kernel-resident pool of physical frames
    // that can be mapped into one or more process address
    // spaces via NtMapViewOfSection — backs Windows shared
    // memory + memory-mapped files. v0 honours pagefile-
    // backed (anonymous) sections only; file-backed sections
    // (FileHandle != 0) return NotImpl in the kernel handler.
    //
    // Disjoint from every other Win32 handle range so the
    // shared close dispatch can pick the right table by
    // handle value alone. 8 slots — same sizing rationale
    // as foreign-thread/process tables.
    //
    // Each entry holds an index into the global
    // g_win32_sections pool (defined in win32_section.cpp).
    // The pool entry's refcount is incremented on open and
    // decremented on NtClose; the section is freed only
    // when refcount hits 0 (which means every handle AND
    // every active mapping has gone away).
    struct Win32SectionHandle
    {
        bool in_use;
        u8 _pad[3];
        u32 pool_index; // index into g_win32_sections
    };
    static constexpr u64 kWin32SectionCap = 8;
    static constexpr u64 kWin32SectionBase = 0x900;
    Win32SectionHandle win32_section_handles[kWin32SectionCap];

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
    // TlsGetValue / TlsSetValue / TlsFree. v0 is
    // single-threaded per process, so "thread-local" is just
    // "process-local" — but the slot allocator + per-slot
    // storage give MSVC CRT's TLS-using startup paths (errno,
    // locale, uncaught_exception tracking) something real to
    // point at instead of TLS_OUT_OF_INDEXES.
    //
    // 64 slots is plenty for any CRT — typical MSVC CRT
    // uses 3-5 TLS slots. FLS (Fiber-Local Storage) aliases
    // to the same API in v0 since we have no fibers.
    static constexpr u64 kWin32TlsCap = 64;
    u64 tls_slot_in_use; // bitmap: bit N = slot N allocated
    u64 tls_slot_value[kWin32TlsCap];

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
    // initialises both to that). Hard caps stay 16 / 64.
    u64 linux_rlimit_nofile_cur;
    u64 linux_rlimit_nproc_cur;
    // Bitmap of pending Linux signals. Bit N set = signum N is
    // pending delivery. Populated by LinuxSignalDeliver()
    // (kill / tgkill / synthetic deliveries) and drained by
    // signalfd_read; rt_sigpending also reports it.
    //
    // v0 only honours the bitmap shape (one pending bit per
    // signum); real Linux distinguishes queued sigqueue() entries.
    // 64-bit width covers signum 1..63, which is the entire
    // POSIX rt-signal range.
    u64 linux_pending_signals;
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
    // SIGCHLD reaping. `linux_parent_pid` is set by DoFork (clone
    // without CLONE_THREAD); 0 means "no Linux parent" (kernel-
    // spawned process or pre-fork init). `linux_exit_code` is
    // populated by DoExit / DoExitGroup before the task dies; the
    // ProcessRelease teardown reads it to push an exit notification
    // onto the parent's queue.
    //
    // `linux_child_exits[8]` is the per-process zombie queue: each
    // dead child's (pid, exit_code, exit_signal) is appended here
    // when the child's last ref is released, and drained by wait4.
    // Cap is 8 — typical shell pipelines have 1-3 outstanding
    // children. Overflow drops the notification (sub-GAP for >8
    // simultaneous children).
    //
    // `linux_wait_wq` is the wake target for wait4 callers blocked
    // waiting for any child to exit. Every queue push wakes one
    // waiter.
    static constexpr u64 kLinuxChildExitCap = 8;
    struct LinuxChildExit
    {
        u64 pid;
        u32 exit_code;     // raw 8-bit exit status passed to DoExit
        u8 exit_signal;    // signal that killed the process; 0 = clean exit
        bool was_signaled; // distinguishes "exited" from "killed by signal"
        u8 _pad[2];
    };
    u64 linux_parent_pid;
    u32 linux_exit_code;
    bool linux_was_signaled;
    u8 linux_exit_signal;
    u8 _linux_exit_pad[2];
    u64 linux_child_exit_count;
    LinuxChildExit linux_child_exits[kLinuxChildExitCap];
    sched::WaitQueue linux_wait_wq;

    // Win32 custom-diagnostics state — opaque pointer to a
    // duetos::subsystems::win32::custom::ProcessCustomState. nullptr
    // until the process opts into any custom-Win32 feature via
    // SYS_WIN32_CUSTOM op=SetPolicy. Owned by the custom module;
    // ProcessRelease forwards to custom::CleanupProcess. Kept as
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
    static constexpr u64 kLinuxCwdCap = 256;
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
    // `ProcessRelease` calls `HandleTableDrain` on it as part of
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
    // Zero-initialised by ProcessCreate's memset — no explicit
    // init needed. `head == tail` on a fresh process means the
    // ring is empty; readers block on `waiters` until the kbd-
    // reader pushes a byte.
    struct StdinRing
    {
        static constexpr u32 kCap = 256;
        u8 buf[kCap];
        u32 head; // producer cursor (kbd-reader); writes new bytes
        u32 tail; // consumer cursor (SYS_STDIN_READ); drains
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
    // the slot.
    //
    // 4 slots × up to 16 pages (64 KiB) per heap. Cap matches
    // typical workloads (CRT keeps one private heap; most apps
    // never call HeapCreate). Grow when a workload demands.
    struct Win32ExtraHeap
    {
        bool in_use;
        u8 _pad[7];
        u64 base_va;   // 0 = slot free
        u64 pages;     // page count actually mapped
        u64 free_head; // user VA of first free block (0 = full)
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

    u64 refcount;
};

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
inline constexpr u64 kSandboxDenialKillThreshold = 100;

// FS write-rate windows (multi-tier). One row per window level
// — index matches `Process::fs_write_window_bytes[i]` and
// `fs_write_window_start_tick[i]`. All three checks run on
// every successful write; first cap-cross kills the caller.
//
// Tick rate is 100 Hz (kernel/time/tick.h kTickHz). Tuning
// principle: each row's byte_cap / window_ticks is the
// MAXIMUM legitimate sustained throughput tolerated. The burst
// row is generous (16 MiB/s — a typical installer's peak
// extraction rate); sustained narrows that to ~850 KiB/s; long
// to ~580 KiB/s. Legitimate userland workloads (text editing,
// cache writes, compile output) sit at ~10s of KiB/s averaged
// across a session.
inline constexpr u64 kFsWriteWindowTicksByLevel[3] = {
    100ULL,           // 1 s    @ 100 Hz   (burst)
    100ULL * 60 * 5,  // 5 min  @ 100 Hz   (sustained)
    100ULL * 60 * 60, // 1 h    @ 100 Hz   (long-tail)
};
inline constexpr u64 kFsWriteWindowByteCapByLevel[3] = {
    16ULL * 1024 * 1024,       // burst    : 16 MiB / 1 s
    256ULL * 1024 * 1024,      // sustained: 256 MiB / 5 min
    2ULL * 1024 * 1024 * 1024, // long     :  2 GiB / 1 h
};
inline constexpr const char* kFsWriteWindowLabels[3] = {
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
/// the one reference AddressSpaceCreate returned. On ProcessRelease,
/// the AS reference is dropped (which tears down the AS if nothing
/// else holds it). `root` MUST be non-null — pick from
/// fs::RamfsTrustedRoot() / fs::RamfsSandboxRoot() based on the
/// process's trust level. Returns nullptr on kheap failure.
Process* ProcessCreate(const char* name, mm::AddressSpace* as, CapSet caps, const fs::RamfsNode* root, u64 user_code_va,
                       u64 user_stack_va, u64 tick_budget);

/// Bump refcount. Use when a second holder appears (a future thread
/// spawn that shares the process, a borrow into a non-owning table).
/// Every Retain must be matched by exactly one Release.
void ProcessRetain(Process* p);

/// Drop a reference. When the last reference goes away, the AS
/// reference is dropped, the Process struct is freed, and the
/// caller MUST NOT touch `p` again. nullptr is a no-op — kernel-
/// only Tasks carry `process == nullptr` and release goes through
/// this path unchanged.
void ProcessRelease(Process* p);

/// Current Task's Process, or nullptr if the current Task is
/// kernel-only. Used by syscall handlers to check caps.
Process* CurrentProcess();

/// Human-friendly cap name for diagnostics — returns a static
/// string or "unknown". Must be safe from any context (no locks,
/// no allocation).
const char* CapName(Cap c);

/// Called from every cap-denial site (inside a syscall that
/// rejected its caller). Bumps the current Process's
/// sandbox_denials counter and, if the threshold is crossed,
/// flags the task for termination at next resched (same
/// mechanism the tick-budget path uses — the scheduler
/// converts the flag into a Dead transition).
///
/// Idempotent past the threshold — repeated calls keep
/// counting but the task is flagged exactly once. `cap`
/// argument is just for the log line; no functional effect.
void RecordSandboxDenial(Cap cap);

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
/// counts, while this exposes the process-lifetime counter maintained
/// by ProcessCreate / ProcessRelease.
u64 ProcessLiveCount();

/// Self-test of the process model's pure helpers: CapSet bitmap
/// operations, CapName lookup, the denial rate-limit predicate, and
/// the boundary checks around kCapNone / kCapCount. Does NOT create
/// a Process — that path needs an AddressSpace + scheduler that
/// aren't online at the call site. Panics on any failure.
void ProcessSelfTest();

/// Push one cooked ASCII byte into `proc`'s stdin ring and wake any
/// task blocked in SYS_STDIN_READ on that process. Safe to call
/// from task context with interrupts on; the producer-side cursor
/// update is single-writer (the kbd-reader thread is the only
/// caller in v0). Drops the oldest byte on overflow so a wedged
/// reader doesn't back-pressure the IRQ-fed input pipeline.
void ProcessFeedStdinChar(Process* proc, char c);

/// Drain up to `cap` bytes from `proc`'s stdin ring into `dst_user`
/// (a ring-3 VA). Blocks via the ring's waitqueue until at least
/// one byte is available. Returns the number of bytes copied, or
/// the kernel-side -1 on a bad user pointer. Caller-side ABI
/// matches POSIX read(): a partial copy is fine — never blocks for
/// "fill the buffer," always returns as soon as any data is ready.
i64 ProcessReadStdinBlocking(Process* proc, void* dst_user, u64 cap);

/// Last-stage stdin sink — set by the kbd-reader once login is
/// closed and ring-3 input is the right destination. nullptr on
/// boot until the userland shell first calls SYS_STDIN_READ;
/// cleared on process release. Callers should prefer
/// `ProcessFeedStdinFocusChar` to avoid the read-pointer / process-
/// release race.
Process* StdinFocusGet();
void StdinFocusSet(Process* proc);
void StdinFocusClearIf(Process* proc);

/// Push one cooked byte into whatever process currently owns the
/// stdin focus, atomically w.r.t. process teardown — the read of
/// the focus pointer and the push happen with interrupts disabled,
/// so the reaper can't free the process between the two on a
/// single-CPU system. No-op when no focus is registered. The
/// canonical kbd-reader entry point.
void ProcessFeedStdinFocusChar(char c);

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
bool LinuxFdAttachKFile(Process* p, u32 fd, u8 kind, u32 pool_index, void (*release)(u32));

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

/// Copy parent's fd table into `child` at fork time. Each
/// occupied slot in `parent` is mirrored into `child`; KFile
/// sidecars are duplicated via `HandleTableDuplicate` so the
/// child shares the parent's per-pool ref counts (each side
/// drops one ref on close). FD_CLOEXEC is preserved on the
/// inherited slot — Linux semantics: fork copies cloexec
/// fds; only execve drops them. Caller (DoFork / DoClone)
/// must have already initialised `child`'s fd table to all-
/// unused via `ProcessCreate`.
void LinuxFdInheritFromParent(Process* parent, Process* child);

/// Walk the fd table and close every slot with FD_CLOEXEC set.
/// Called from the future execve handler before the new image
/// is mapped in. v0 has no execve, so this is currently
/// invoked only by the boot-time self-test that exercises the
/// CLOEXEC bit's plumbing.
void LinuxFdCloseOnExec(Process* p);

/// Self-test for the Linux fd-table helpers. Boot-time only;
/// exercises a synthetic Process's fd table through alloc /
/// dup / cloexec-set / inherit / close-on-exec. Panics on any
/// invariant violation.
void LinuxFdSelfTest();

} // namespace duetos::core
