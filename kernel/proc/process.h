#pragma once

#include "fs/fat32.h"
#include "fs/ramfs.h"
#include "mm/address_space.h"
#include "sched/sched.h"
#include "loader/dll_loader.h"
#include "util/types.h"

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

    // Win32 last-error slot. Read + written by the kernel32
    // GetLastError / SetLastError stubs via SYS_GETLASTERROR /
    // SYS_SETLASTERROR. In real Windows this lives in the TEB
    // at offset 0x68 (thread-local). Multi-threading has since
    // landed (SYS_THREAD_CREATE + kCapSpawnThread), but the
    // slot still lives on the Process rather than each Task —
    // so all threads of a process currently share a single
    // last-error. Known gap for programs that rely on per-
    // thread semantics; revisit when a real TEB lands. Zero-
    // initialised by ProcessCreate — matches the Win32
    // convention that fresh processes see ERROR_SUCCESS (0).
    u32 win32_last_error;

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
    struct LinuxFd
    {
        // state 0 = unused
        // state 1 = reserved-tty (fd 0/1/2)
        // state 2 = regular file (FAT32-backed)
        // state 3 = pipe-read end  → first_cluster = pipe pool idx
        // state 4 = pipe-write end → first_cluster = pipe pool idx
        // state 5 = eventfd        → first_cluster = eventfd pool idx
        // first_cluster is reused as a generic "pool index" slot
        // for the non-file states; all non-file callers must
        // ignore size/offset/path.
        u8 state;
        u8 _pad[3];
        u32 first_cluster;
        u32 size;
        u32 _pad2;
        u64 offset; // read cursor; only meaningful for state=file
        // Volume-relative path as passed to sys_open, NUL-
        // terminated. Needed so sys_write's extend path can call
        // Fat32AppendAtPath — the FAT32 writer walks the parent
        // directory by name to update the entry's size field.
        // Cap matches the sys_open copy buffer (63 chars + NUL).
        char path[64];
    };
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
    };
    struct Win32FileHandle
    {
        FsBackingKind kind;              // None = free; otherwise selects which fields below are valid
        const fs::RamfsNode* ramfs_node; // valid iff kind == Ramfs
        u32 fat32_volume_idx;            // valid iff kind == Fat32
        fs::fat32::DirEntry fat32_entry; // valid iff kind == Fat32 (snapshot at open time)
        u64 cursor;                      // current read position in bytes
    };
    static constexpr u64 kWin32HandleCap = 16;
    static constexpr u64 kWin32HandleBase = 0x100;
    Win32FileHandle win32_handles[kWin32HandleCap];

    // Win32 mutex table — backs CreateMutexW / WaitForSingleObject /
    // ReleaseMutex. Per-mutex owner pointer + recursion
    // counter + waitqueue. Real blocking semantics; uses the
    // existing sched::WaitQueue + WaitQueueBlockTimeout path.
    //
    // Handles run kWin32MutexBase + idx (= 0x200..0x207); the range
    // is disjoint from kWin32HandleBase + idx (0x100..0x10F) so
    // CloseHandle can dispatch by range without a tag bit.
    //
    // Win32 mutexes are RECURSIVE — the same owner can acquire
    // multiple times, and must release the same number. The
    // recursion counter tracks this; only on final release does
    // the mutex become unowned + a waiter (if any) gets the
    // hand-off.
    struct Win32MutexHandle
    {
        bool in_use; // false = slot free
        u8 _pad[3];
        u32 recursion;            // # nested acquires by current owner
        sched::Task* owner;       // nullptr = unowned
        sched::WaitQueue waiters; // tasks blocked in WaitForSingleObject
    };
    static constexpr u64 kWin32MutexCap = 8;
    static constexpr u64 kWin32MutexBase = 0x200;
    Win32MutexHandle win32_mutexes[kWin32MutexCap];

    // Win32 event table — backs CreateEventW / SetEvent /
    // ResetEvent / WaitForSingleObject. Simpler than
    // mutexes: no owner, no recursion, just a signaled flag
    // with a waitqueue. Manual-reset events stay signaled until
    // ResetEvent; auto-reset events wake one waiter then clear
    // themselves automatically.
    //
    // Handles run kWin32EventBase + idx (= 0x300..0x307),
    // disjoint from the mutex and file handle ranges so
    // CloseHandle / WaitForSingleObject dispatch by range.
    struct Win32EventHandle
    {
        bool in_use;
        bool manual_reset; // true = stays signaled until reset; false = auto-clears on wake
        bool signaled;
        u8 _pad[5];
        sched::WaitQueue waiters; // tasks blocked in SYS_EVENT_WAIT
    };
    static constexpr u64 kWin32EventCap = 8;
    static constexpr u64 kWin32EventBase = 0x300;
    Win32EventHandle win32_events[kWin32EventCap];

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

    // Win32 counting-semaphore table — backs CreateSemaphoreW /
    // ReleaseSemaphore / WaitForSingleObject on a semaphore handle.
    // Handles run kWin32SemaphoreBase + idx
    // (= 0x500..0x507), disjoint from every other Win32 range.
    //
    // Semantics:
    //   - `count` is the current semaphore value. A wait that sees
    //     count > 0 decrements it and returns WAIT_OBJECT_0
    //     immediately. A wait that sees count == 0 blocks on
    //     `waiters` until a release bumps count back above zero.
    //   - `max_count` caps the count. Release-past-max is an
    //     error (returns FALSE, Win32 semantics — count stays at
    //     max_count, no-one wakes).
    //   - ReleaseSemaphore(handle, N) bumps count by N and wakes
    //     up to N waiters (one per unit of count increase).
    struct Win32SemaphoreHandle
    {
        bool in_use;
        u8 _pad[3];
        i32 count;     // current count; 0 = no resources
        i32 max_count; // upper limit
        u8 _pad2[4];
        sched::WaitQueue waiters;
    };
    static constexpr u64 kWin32SemaphoreCap = 8;
    static constexpr u64 kWin32SemaphoreBase = 0x500;
    Win32SemaphoreHandle win32_semaphores[kWin32SemaphoreCap];

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

/// Self-test of the process model's pure helpers: CapSet bitmap
/// operations, CapName lookup, the denial rate-limit predicate, and
/// the boundary checks around kCapNone / kCapCount. Does NOT create
/// a Process — that path needs an AddressSpace + scheduler that
/// aren't online at the call site. Panics on any failure.
void ProcessSelfTest();

} // namespace duetos::core
