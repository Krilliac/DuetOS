#pragma once

#include "../fs/ramfs.h"
#include "../mm/address_space.h"
#include "../sched/sched.h"
#include "types.h"

/*
 * CustomOS process + capability model — v0.
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

namespace customos::core
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
    // at offset 0x68 (thread-local). v0 is single-task per
    // process, so we park it on the Process struct and defer
    // the per-thread TEB until multi-threading lands. Zero-
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
        u8 state; // 0=unused, 1=reserved-tty, 2=file
        u8 _pad[3];
        u32 first_cluster; // only meaningful for state=file
        u32 size;          // only meaningful for state=file
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
    //     CustomOS native ABI + Win32 PE subsystem both live
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

    // Win32 file-handle table — backs CreateFileW / ReadFile /
    // CloseHandle / SetFilePointerEx (batch 24). Each slot holds
    // a pointer to the resolved RamfsNode plus the current read
    // cursor; all access is read-only because ramfs is .rodata.
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
    struct Win32FileHandle
    {
        const fs::RamfsNode* node; // nullptr = unused slot
        u64 cursor;                // current read position in bytes
    };
    static constexpr u64 kWin32HandleCap = 16;
    static constexpr u64 kWin32HandleBase = 0x100;
    Win32FileHandle win32_handles[kWin32HandleCap];

    // Win32 mutex table — backs CreateMutexW / WaitForSingleObject /
    // ReleaseMutex (batch 26). Per-mutex owner pointer + recursion
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

    // Win32 VirtualAlloc bump arena — backs VirtualAlloc /
    // VirtualFree / VirtualProtect (batch 28). Each SYS_VMAP
    // request rounds the size up to page multiples, allocates
    // fresh frames via AllocateFrame, maps them RW + NX + User
    // at the current cursor VA, then bumps the cursor.
    //
    // v0 is bump-only — VirtualFree is documented as a leak.
    // A second slice adds a free list once a real workload
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
/// e.g. kernel/core/syscall.cpp SYS_WRITE/STAT/READ denial
/// paths) so a burst of 100 denials produces ~4 log lines
/// instead of 100 — the counter still advances every time, the
/// threshold-kill still fires at exactly 100. Returns true for
/// the 1st denial, then the 32nd, 64th, 96th, and so on.
bool ShouldLogDenial(u64 denial_index);

} // namespace customos::core
