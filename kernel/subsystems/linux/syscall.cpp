/*
 * DuetOS — Linux ABI syscall surface: implementation.
 *
 * Companion to syscall.h (the Linux-subsystem header next to
 * this file) — see there for the SYS_* enum mirroring Linux
 * x86_64 syscall numbers and the dispatch contract.
 *
 * WHAT
 *   Implements (or stubs) every Linux syscall a Linux-flavour
 *   userland might call via the `syscall` instruction. Numbers
 *   match upstream Linux x86_64 — they're ABI in the same way
 *   DuetOS native SYS_* numbers are ABI: never reused, never
 *   renumbered.
 *
 * HOW
 *   `syscall_entry.S` (in this directory) is the asm stub
 *   MSR_LSTAR points at. It builds a TrapFrame and calls
 *   `LinuxSyscallDispatch` here, which is one big switch on
 *   the syscall number. Each handler either:
 *     - reuses an existing DuetOS native syscall (most cases:
 *       Linux read/write/openat translate to SYS_READ etc.),
 *     - implements Linux semantics directly (mmap flag fan-out,
 *       futex, signal-set bookkeeping),
 *     - returns -ENOSYS for genuinely-unsupported entries.
 *
 *   The auto-generated header `linux_syscall_table_generated.h`
 *   provides the full {number, name, supported?} table for the
 *   coverage scoreboard the boot log emits — same model as
 *   the Win32 NT-coverage logger.
 *
 * WHY THIS FILE IS LARGE
 *   Linux has ~350 syscalls. Many are short stubs but each
 *   carries argument-shape conversion (Linux ABI uses rdi/rsi/
 *   rdx/r10/r8/r9; DuetOS native uses rdi/rsi/rdx). At ~80
 *   handlers + the dispatch + the coverage logger, ~4.5K lines
 *   is in line with the file's job.
 */

#include "syscall.h"

#include "linux_syscall_table_generated.h"
#include "syscall_internal.h"

#include "../../arch/x86_64/hpet.h"
#include "../../arch/x86_64/serial.h"
#include "../../arch/x86_64/timer.h"
#include "../../arch/x86_64/traps.h"
#include "../../core/kdbg.h"
#include "../../core/klog.h"
#include "../../core/cleanroom_trace.h"
#include "../../core/log_names.h"
#include "../../core/process.h"
#include "../../core/random.h"
#include "../../cpu/percpu.h"
#include "../../fs/fat32.h"
#include "../../mm/address_space.h"
#include "../../mm/frame_allocator.h"
#include "../../mm/page.h"
#include "../../mm/paging.h"
#include "../../sched/sched.h"
#include "../translation/translate.h"

extern "C" void linux_syscall_entry();

namespace duetos::subsystems::linux
{

// Hoist cross-TU primitives (errno constants, sibling-TU handler
// declarations) into the subsystem's outer namespace so the
// dispatcher and the anonymous-namespace helpers below can call
// them unqualified, matching the in-TU layout this file used to
// have. Internal-only consumers outside this TU pick the names
// up by including syscall_internal.h.
using namespace internal;

namespace
{
// Hot-path tracing gate for LinuxSyscallDispatch. Debug keeps
// full trace scopes; release compiles them fully out so each
// syscall pays no trace RAII construction/destruction overhead.
#if defined(NDEBUG)
inline constexpr bool kTraceLinuxSyscallDispatch = false;
#else
inline constexpr bool kTraceLinuxSyscallDispatch = true;
#endif

// Linux x86_64 MSR numbers.
constexpr u32 kMsrStar = 0xC0000081;  // CS selectors for syscall/sysret
constexpr u32 kMsrLstar = 0xC0000082; // entry RIP for 64-bit syscall
// MSR_CSTAR (0xC0000083) is the compat-mode entry; we don't
// plan to run 32-bit code, so leave it unprogrammed.
constexpr u32 kMsrFsBase = 0xC0000100;       // user FS.base — musl TLS anchor
constexpr u32 kMsrSfmask = 0xC0000084;       // RFLAGS mask applied at entry
constexpr u32 kMsrKernelGsBase = 0xC0000102; // swapgs source for kernel GS

// Linux errno constants live in syscall_internal.h so sibling
// translation units (syscall_cred.cpp, etc.) can return them
// without redeclaring. The `using namespace internal;` directive
// above makes them visible here without qualification.

// Linux mmap flag bits (kMapPrivate / kMapAnonymous) moved with
// DoMmap into syscall_mm.cpp.

// Per-process Linux fd cap on a single write/read. A real kernel
// wouldn't impose this but musl's newline-buffered stdout rarely
// issues writes over a few KiB. Cap matches the native int-0x80
// write path so behaviour stays predictable across ABIs.
constexpr u64 kLinuxIoMax = 4096;

void WriteMsr(u32 msr, u64 value)
{
    const u32 lo = static_cast<u32>(value & 0xFFFFFFFFu);
    const u32 hi = static_cast<u32>(value >> 32);
    asm volatile("wrmsr" : : "c"(msr), "a"(lo), "d"(hi));
}

// Linux x86_64 syscall numbers we recognise. Spec-stable — the
// RAX number IS the ABI, so these cannot be reassigned. We
// intentionally enumerate only the ones implemented today;
// others fall through to the default -ENOSYS arm.
enum : u64
{
    kSysRead = 0,
    kSysWrite = 1,
    kSysOpen = 2,
    kSysClose = 3,
    kSysStat = 4,
    kSysFstat = 5,
    kSysLstat = 6,
    kSysLseek = 8,
    kSysMmap = 9,
    kSysMunmap = 11,
    kSysBrk = 12,
    kSysRtSigaction = 13,
    kSysRtSigprocmask = 14,
    kSysReadv = 19,
    kSysIoctl = 16,
    kSysWritev = 20,
    kSysMadvise = 28,
    kSysGetPid = 39,
    kSysExit = 60,
    kSysUname = 63,
    kSysGetUid = 102,
    kSysGetGid = 104,
    kSysGetEuid = 107,
    kSysGetEgid = 108,
    kSysArchPrctl = 158,
    kSysExitGroup = 231,
    kSysSetTidAddress = 218,
    kSysAccess = 21,
    kSysGetcwd = 79,
    kSysReadlink = 89,
    kSysFutex = 202,
    kSysGetRandom = 318,
    kSysClockGetTime = 228,
    kSysTime = 201,
    kSysNanosleep = 35,
    kSysMprotect = 10,
    kSysRtSigreturn = 15,
    kSysSigaltstack = 131,
    kSysSchedYield = 24,
    kSysGetTid = 186,
    kSysTgkill = 234,
    kSysKill = 62,
    kSysPread = 17,
    kSysPwrite = 18,
    kSysDup = 32,
    kSysDup2 = 33,
    kSysFsync = 74,
    kSysFdatasync = 75,
    kSysFcntl = 72,
    kSysGettimeofday = 96,
    kSysGetrlimit = 97,
    kSysSysinfo = 99,
    kSysChdir = 80,
    kSysFchdir = 81,
    kSysSetPgid = 109,
    kSysGetPpid = 110,
    kSysGetpgrp = 111,
    kSysGetPgid = 121,
    kSysGetSid = 124,
    kSysSetrlimit = 160,
    kSysPrlimit64 = 302,
    // Batch 54 — modern *at-family + directory + poll/select + rusage.
    // Everything here routes through an existing primary handler
    // (openat → DoOpen with AT_FDCWD treatment, newfstatat → DoStat
    // / DoFstat, dup3 → DoDup2) or is a structural stub (poll /
    // select / getdents64 / getrusage returning valid-shaped
    // results so callers can progress instead of -ENOSYS-crashing).
    kSysPoll = 7,
    kSysSelect = 23,
    kSysGetrusage = 98,
    kSysGetdents64 = 217,
    kSysOpenat = 257,
    kSysNewFstatat = 262,
    kSysDup3 = 292,
    // set_robust_list / get_robust_list — musl calls set_robust_list
    // at thread init. Accepting + no-op is the usual glibc-compat
    // move (we have no robust-futex machinery).
    kSysSetRobustList = 273,
    kSysGetRobustList = 274,

    // Batch 55 — fill out the most commonly-probed unimplemented
    // syscalls. Two flavours:
    //
    //   * No-op compat stubs — calls whose v0 semantics are
    //     "we don't model that subsystem (permissions, uids,
    //     priorities, mlock, etc.); return success / sane
    //     default so static-musl + simple POSIX programs make
    //     forward progress instead of bailing on -ENOSYS."
    //
    //   * Real-ish FS ops — `truncate` / `ftruncate` / `unlink` /
    //     `mkdir` / `rmdir` route through the existing FAT32
    //     primitives (Fat32TruncateAtPath / Fat32DeleteAtPath /
    //     Fat32MkdirAtPath / Fat32RmdirAtPath). lstat aliases stat
    //     since we have no symlinks — see DoLstat below.
    kSysMremap = 25,
    kSysMsync = 26,
    kSysMincore = 27,
    kSysPause = 34,
    kSysFlock = 73,
    kSysTruncate = 76,
    kSysFtruncate = 77,
    kSysMkdir = 83,
    kSysRmdir = 84,
    kSysUnlink = 87,
    kSysChmod = 90,
    kSysFchmod = 91,
    kSysChown = 92,
    kSysFchown = 93,
    kSysLchown = 94,
    kSysTimes = 100,
    kSysSetuid = 105,
    kSysSetgid = 106,
    kSysSetreuid = 113,
    kSysSetregid = 114,
    kSysGetgroups = 115,
    kSysSetgroups = 116,
    kSysSetresuid = 117,
    kSysGetresuid = 118,
    kSysSetresgid = 119,
    kSysGetresgid = 120,
    kSysSetfsuid = 122,
    kSysSetfsgid = 123,
    kSysCapget = 125,
    kSysCapset = 126,
    kSysUtime = 132,
    kSysMknod = 133,
    kSysPersonality = 135,
    kSysGetpriority = 140,
    kSysSetpriority = 141,
    kSysMlock = 149,
    kSysMunlock = 150,
    kSysMlockall = 151,
    kSysMunlockall = 152,

    // Batch 56 — additional compat stubs + *at-family delegations.
    // Brings overall primary coverage further + gives common
    // POSIX/glibc idioms a landing spot so they don't `-ENOSYS`.
    //
    // *at-family notes: we have no per-process CWD, so AT_FDCWD
    // (the common case) resolves against the sandbox root exactly
    // like the non-*at variants. Other dirfd values — -EBADF.
    //
    // FS-mutation stubs that would need filesystem primitives we
    // don't have (rename, link, symlink) return -EPERM or -ENOSYS
    // as appropriate rather than silently pretending to succeed.
    kSysPtrace = 101,
    kSysSyslog = 103,
    kSysSetsid = 112,
    kSysVhangup = 153,
    kSysAcct = 163,
    kSysMount = 165,
    kSysUmount2 = 166,
    kSysSync = 162,
    kSysSyncfs = 306,
    kSysRename = 82,
    kSysLink = 86,
    kSysSymlink = 88,
    kSysSetThreadArea = 205,
    kSysGetThreadArea = 211,
    kSysIoprioGet = 252,
    kSysIoprioSet = 251,
    kSysSchedSetaffinity = 203,
    kSysSchedGetaffinity = 204,
    kSysSchedSetparam = 142,
    kSysSchedGetparam = 143,
    kSysSchedSetscheduler = 144,
    kSysSchedGetscheduler = 145,
    kSysSchedGetPriorityMax = 146,
    kSysSchedGetPriorityMin = 147,
    kSysSchedRrGetInterval = 148,
    kSysClockGetres = 229,
    kSysClockNanosleep = 230,
    kSysGetcpu = 309,
    kSysMkdirat = 258,
    kSysUnlinkat = 263,
    kSysLinkat = 265,
    kSysSymlinkat = 266,
    kSysRenameat = 264,
    kSysRenameat2 = 316,
    kSysFchownat = 260,
    kSysFutimesat = 261,
    kSysFchmodat = 268,
    kSysFaccessat = 269,
    kSysFaccessat2 = 439,
    kSysUtimensat = 280,

    // Batch 67 — common syscalls that previously fell through to
    // the "unhandled" path. Each gets a Linux-shaped no-op so
    // a caller probing for "is this kernel a Linux v4+?" doesn't
    // immediately bail. Real semantics wait for the underlying
    // subsystem to land:
    //   pipe / pipe2          : -ENFILE (no pipe machinery)
    //   wait4 / waitid        : -ECHILD (no fork, no children)
    //   rt_sigpending         : 0 mask (no signal delivery)
    //   rt_sigsuspend / sigtimedwait / pselect6 / ppoll : -EINTR
    //   eventfd / eventfd2    : -ENOSYS
    //   timerfd_*             : -ENOSYS
    //   signalfd / signalfd4  : -ENOSYS
    //   fadvise64             : 0 (no readahead — accept)
    //   readahead             : 0
    //   epoll_create*         : -ENOSYS
    //   inotify_init*         : -ENOSYS
    //   prctl                 : minimal — PR_GET/SET_NAME accepted
    kSysPipe = 22,
    kSysPipe2 = 293,
    kSysWait4 = 61,
    kSysWaitid = 247,
    kSysRtSigpending = 127,
    kSysRtSigsuspend = 130,
    kSysRtSigtimedwait = 128,
    kSysPpoll = 271,
    kSysPselect6 = 270,
    kSysEventfd = 284,
    kSysEventfd2 = 290,
    kSysTimerfdCreate = 283,
    kSysTimerfdSettime = 286,
    kSysTimerfdGettime = 287,
    kSysSignalfd = 282,
    kSysSignalfd4 = 289,
    kSysFadvise64 = 221,
    kSysReadahead = 187,
    kSysEpollCreate = 213,
    kSysEpollCreate1 = 291,
    kSysEpollCtl = 233,
    kSysEpollWait = 232,
    kSysEpollPwait = 281,
    kSysInotifyInit = 253,
    kSysInotifyInit1 = 294,
    kSysPrctl = 157,

    // Batch 68 — Linux BSD-socket syscalls. v0 has no userland
    // socket layer; each handler returns -ENETDOWN or -ENOSYS so
    // a libc fallback to "no network" runs cleanly instead of
    // panicking on the unhandled-syscall path.
    kSysSocket = 41,
    kSysConnect = 42,
    kSysAccept = 43,
    kSysSendto = 44,
    kSysRecvfrom = 45,
    kSysSendmsg = 46,
    kSysRecvmsg = 47,
    kSysShutdown = 48,
    kSysBind = 49,
    kSysListen = 50,
    kSysGetsockname = 51,
    kSysGetpeername = 52,
    kSysSocketpair = 53,
    kSysSetsockopt = 54,
    kSysGetsockopt = 55,
    kSysAccept4 = 288,
    kSysSendmmsg = 307,
    kSysRecvmmsg = 299,

    // Batch 69 — process-control + IPC. Each returns a Linux-
    // shaped error so probing libc paths bail cleanly.
    kSysClone = 56,
    kSysFork = 57,
    kSysVfork = 58,
    kSysExecve = 59,
    kSysExecveat = 322,
    kSysChroot = 161,
    kSysPivotRoot = 155,
    kSysUmask = 95,
    // SysV IPC.
    kSysShmget = 29,
    kSysShmat = 30,
    kSysShmctl = 31,
    kSysShmdt = 67,
    kSysSemget = 64,
    kSysSemop = 65,
    kSysSemctl = 66,
    kSysSemtimedop = 220,
    kSysMsgget = 68,
    kSysMsgsnd = 69,
    kSysMsgrcv = 70,
    kSysMsgctl = 71,
    // POSIX message queues.
    kSysMqOpen = 240,
    kSysMqUnlink = 241,
    kSysMqTimedsend = 242,
    kSysMqTimedreceive = 243,
    kSysMqNotify = 244,
    kSysMqGetsetattr = 245,
    // inotify mutators.
    kSysInotifyAddWatch = 254,
    kSysInotifyRmWatch = 255,
    // misc.
    kSysIoSetup = 206,
    kSysIoDestroy = 207,
    kSysIoGetevents = 208,
    kSysIoSubmit = 209,
    kSysIoCancel = 210,
    kSysSwapon = 167,
    kSysSwapoff = 168,
    kSysReboot = 169,
    kSysSethostname = 170,
    kSysSetdomainname = 171,
    kSysIopl = 172,
    kSysIoperm = 173,
    kSysQuotactl = 179,
};

// POSIX AT_FDCWD — used by the *at family to mean "resolve
// relative to the caller's CWD". v0 has no per-process CWD
// yet, so AT_FDCWD always resolves to the sandbox root; any
// other dirfd is -EBADF until per-fd CWDs land.
constexpr i64 kAtFdCwd = -100;

// kESRCH / kESPIPE / kENOTTY moved to syscall_internal.h alongside
// the rest of the errno constants.

// ARCH_* codes for arch_prctl (linux/arch/x86/include/uapi/asm/prctl.h).
constexpr u64 kArchSetGs = 0x1001;
constexpr u64 kArchSetFs = 0x1002;
constexpr u64 kArchGetFs = 0x1003;
constexpr u64 kArchGetGs = 0x1004;

// DoExitGroup / DoExit / DoGetPid moved to syscall_proc.cpp
// alongside the rest of the process-control handlers.

// Linux: write(fd, buf, count). v0 implements fd=1 (stdout) and
// fd=2 (stderr) only — both go to COM1. Everything else returns
// -EBADF so musl's perror / write-to-pipe error paths surface
// predictably. No cap-gating here yet: a Linux process that
// reached the dispatcher is trusted to the same degree a native
// ring-3 task reaching SYS_WRITE is. Gating by Process::caps
// gets bolted on when we need per-sandbox Linux policy.
i64 DoWrite(u64 fd, u64 user_buf, u64 len)
{
    // fd 1/2 -> COM1 (unchanged from v0).
    if (fd == 1 || fd == 2)
    {
        const u64 to_copy = (len > kLinuxIoMax) ? kLinuxIoMax : len;
        if (to_copy == 0)
            return 0;
        u8 kbuf[kLinuxIoMax];
        if (!mm::CopyFromUser(kbuf, reinterpret_cast<const void*>(user_buf), to_copy))
            return kEFAULT;
        arch::SerialWriteN(reinterpret_cast<const char*>(kbuf), to_copy);
        return static_cast<i64>(to_copy);
    }
    // fd 0 (stdin) rejects write; unused fds too.
    if (fd == 0 || fd >= 16)
        return kEBADF;
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || p->linux_fds[fd].state != 2)
        return kEBADF;

    // File write. Three regions to consider:
    //   [off, min(off+len, size))     — in-bounds: WriteInPlace
    //   [max(off, size), off+len)     — extending: AppendAtPath
    // When off > size (seek past EOF), v0 refuses — FAT32 has no
    // sparse-file support and zeroing a gap would need an extra
    // write path. musl's write-loop never seeks past EOF so this
    // corner rarely matters.
    const u64 size = p->linux_fds[fd].size;
    const u64 off = p->linux_fds[fd].offset;
    if (off > size)
        return kEINVAL;
    u64 to_copy = len;
    if (to_copy > kLinuxIoMax)
        to_copy = kLinuxIoMax;
    static u8 kbuf[kLinuxIoMax];
    if (!mm::CopyFromUser(kbuf, reinterpret_cast<const void*>(user_buf), to_copy))
        return kEFAULT;
    const auto* v = fs::fat32::Fat32Volume(0);
    if (v == nullptr)
        return kEIO;

    u64 written = 0;
    // In-bounds portion.
    if (off < size)
    {
        const u64 in_bounds_len = (size - off < to_copy) ? (size - off) : to_copy;
        fs::fat32::DirEntry entry;
        for (u64 i = 0; i < sizeof(entry.name); ++i)
            entry.name[i] = 0;
        entry.attributes = 0;
        entry.first_cluster = p->linux_fds[fd].first_cluster;
        entry.size_bytes = size;
        const i64 n = fs::fat32::Fat32WriteInPlace(v, &entry, off, kbuf, in_bounds_len);
        if (n < 0)
            return kEIO;
        written = static_cast<u64>(n);
        if (written < in_bounds_len)
        {
            p->linux_fds[fd].offset = off + written;
            return static_cast<i64>(written);
        }
    }
    // Extend portion.
    if (written < to_copy)
    {
        const u64 extend_len = to_copy - written;
        // Fat32AppendAtPath appends to end-of-file; caller's
        // offset + written MUST equal the current on-disk size.
        // (True by construction: in-bounds code wrote up to size.)
        const i64 n = fs::fat32::Fat32AppendAtPath(v, p->linux_fds[fd].path, kbuf + written, extend_len);
        if (n < 0)
        {
            p->linux_fds[fd].offset = off + written;
            return written > 0 ? static_cast<i64>(written) : kEIO;
        }
        written += static_cast<u64>(n);
        // Update the cached size — AppendAtPath just extended the
        // on-disk size field; our cached copy needs to follow.
        p->linux_fds[fd].size = static_cast<u32>(size + (to_copy - (size - off)));
    }
    p->linux_fds[fd].offset = off + written;
    return static_cast<i64>(written);
}

// Skip the `/fat/` mount prefix (or a bare leading slash) so what
// we hand to Fat32LookupPath is volume-relative. musl and shell
// callers both use absolute-looking paths; the FAT32 driver
// doesn't understand mount-point naming.
const char* StripFatPrefix(const char* p)
{
    while (*p == '/')
        ++p;
    if (p[0] == 'f' && p[1] == 'a' && p[2] == 't' && p[3] == '/')
        return p + 4;
    return p;
}

// Forward declaration so chmod/chown/utime up top can call the
// volume-relative copy helper that's defined further down.
bool CopyAndStripFatPath(u64 user_path, char (&kbuf)[64], const char*& out_leaf);

// Linux: open(path, flags, mode). v0 scope:
//   - Read-only. Any write/create/truncate flag bits in `flags`
//     are silently ignored; the FAT32 entry has to exist already.
//   - Only FAT32 volume 0. Path may be absolute ("/HELLO.TXT"),
//     mount-prefixed ("/fat/HELLO.TXT"), or bare ("HELLO.TXT").
// Returns the new fd on success, -errno otherwise.
i64 DoOpen(u64 user_path, u64 flags, u64 mode)
{
    (void)flags;
    (void)mode;
    // Copy the path into a fixed-size kernel buffer. 63-char cap
    // covers v0's FAT32 path depth (basenames up to 128 chars are
    // possible via LFN; restrict the `open` path here since the
    // kernel scratch + syscall argument convention favour tight
    // bounds anyway).
    char path[64];
    for (u32 i = 0; i < sizeof(path); ++i)
        path[i] = 0;
    if (!mm::CopyFromUser(path, reinterpret_cast<const void*>(user_path), sizeof(path) - 1))
    {
        return kEFAULT;
    }
    path[sizeof(path) - 1] = 0;
    // Ensure there's a NUL somewhere in the copied region; a
    // missing NUL means the caller passed an over-long string
    // that'd spill past our buffer during matching.
    bool has_nul = false;
    for (u32 i = 0; i < sizeof(path); ++i)
    {
        if (path[i] == 0)
        {
            has_nul = true;
            break;
        }
    }
    if (!has_nul)
    {
        return kENAMETOOLONG;
    }

    const auto* v = fs::fat32::Fat32Volume(0);
    if (v == nullptr)
    {
        return kENOENT;
    }
    fs::fat32::DirEntry entry;
    const char* leaf = StripFatPrefix(path);
    if (!fs::fat32::Fat32LookupPath(v, leaf, &entry))
    {
        return kENOENT;
    }
    if (entry.attributes & 0x10)
    {
        return kEISDIR;
    }

    core::Process* p = core::CurrentProcess();
    if (p == nullptr)
    {
        return kEIO;
    }
    for (u32 i = 3; i < 16; ++i)
    {
        if (p->linux_fds[i].state == 0)
        {
            p->linux_fds[i].state = 2;
            p->linux_fds[i].first_cluster = entry.first_cluster;
            p->linux_fds[i].size = entry.size_bytes;
            p->linux_fds[i].offset = 0;
            // Remember the (stripped) volume-relative path so
            // sys_write can call Fat32AppendAtPath on extend.
            u32 pi = 0;
            while (leaf[pi] != 0 && pi + 1 < sizeof(p->linux_fds[i].path))
            {
                p->linux_fds[i].path[pi] = leaf[pi];
                ++pi;
            }
            p->linux_fds[i].path[pi] = 0;
            return static_cast<i64>(i);
        }
    }
    return kEMFILE;
}

// Linux: close(fd). Marks the slot unused. No destructor work —
// FAT32 entries are snapshotted into the fd at open() time; a
// close doesn't touch disk.
i64 DoClose(u64 fd)
{
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd >= 16)
    {
        return kEBADF;
    }
    // fd 0/1/2 are reserved-tty, never file handles; refuse close.
    if (fd < 3 || p->linux_fds[fd].state == 0)
    {
        return kEBADF;
    }
    p->linux_fds[fd].state = 0;
    p->linux_fds[fd].first_cluster = 0;
    p->linux_fds[fd].size = 0;
    p->linux_fds[fd].offset = 0;
    return 0;
}

// Linux: read(fd, buf, count).
//   fd == 0 (stdin): always 0 (EOF). See earlier comment.
//   fd == 1 / 2: -EBADF — you can't read stdout/stderr.
//   fd >= 3 file handle: read from the current offset into the
//     user buffer, advance the cursor, return the byte count.
//     Implementation reads the ENTIRE file into scratch and
//     slices — simple, bounded by 4 KiB (v0 file cap).
i64 DoRead(u64 fd, u64 user_buf, u64 len)
{
    if (fd == 0)
    {
        return 0;
    }
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd >= 16)
    {
        return kEBADF;
    }
    if (p->linux_fds[fd].state != 2)
    {
        return kEBADF;
    }
    if (len == 0)
    {
        return 0;
    }
    const auto* v = fs::fat32::Fat32Volume(0);
    if (v == nullptr)
    {
        return kEIO;
    }

    // Scratch read. 4 KiB accommodates HELLO.TXT / INNER.TXT /
    // LongFile.txt; larger files will truncate here. A streaming
    // read-with-offset helper in the FAT32 driver is the next
    // iteration.
    static u8 scratch[4096];
    fs::fat32::DirEntry entry;
    for (u64 i = 0; i < sizeof(entry.name); ++i)
        entry.name[i] = 0;
    entry.attributes = 0;
    entry.first_cluster = p->linux_fds[fd].first_cluster;
    entry.size_bytes = p->linux_fds[fd].size;
    const i64 total = fs::fat32::Fat32ReadFile(v, &entry, scratch, sizeof(scratch));
    if (total < 0)
    {
        return kEIO;
    }
    const u64 size = static_cast<u64>(total);
    const u64 off = p->linux_fds[fd].offset;
    if (off >= size)
    {
        return 0; // past-EOF
    }
    u64 to_copy = size - off;
    if (to_copy > len)
        to_copy = len;
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_buf), scratch + off, to_copy))
    {
        return kEFAULT;
    }
    p->linux_fds[fd].offset = off + to_copy;
    return static_cast<i64>(to_copy);
}

// Fill a Linux struct stat from the given FAT32 directory entry.
// Layout matches uapi/asm-generic/stat.h for x86_64 (144 bytes).
// Times are zeroed — no RTC integration yet.
void FillStatFromEntry(const fs::fat32::DirEntry& e, u8* out_144)
{
    for (u64 i = 0; i < 144; ++i)
        out_144[i] = 0;
    auto put_u64 = [&](u64 off, u64 v)
    {
        for (u64 i = 0; i < 8; ++i)
            out_144[off + i] = static_cast<u8>(v >> (i * 8));
    };
    auto put_u32 = [&](u64 off, u32 v)
    {
        for (u64 i = 0; i < 4; ++i)
            out_144[off + i] = static_cast<u8>(v >> (i * 8));
    };
    // st_dev = 0 (no device namespace yet).
    put_u64(0, 0);
    // st_ino = first_cluster — stable identity per on-disk entry.
    put_u64(8, e.first_cluster);
    // st_nlink = 1 for files, 1 for dirs (no hard links).
    put_u64(16, 1);
    // st_mode: dir or regular file, default permissions rw-r--r-- / rwxr-xr-x.
    const u32 mode = (e.attributes & 0x10) ? 0x41EDu  /* S_IFDIR | 0755 */
                                           : 0x81A4u; /* S_IFREG | 0644 */
    put_u32(24, mode);
    // st_uid/gid/rdev = 0.
    // st_size at offset 48.
    put_u64(48, e.size_bytes);
    // st_blksize at offset 56.
    put_u64(56, 4096);
    // st_blocks (in 512-byte units) at offset 64.
    put_u64(64, (u64(e.size_bytes) + 511) / 512);
    // times: all zero — RTC integration follows.
}

// Linux: stat(path, buf) / lstat(path, buf).
// Looks up the path in FAT32 volume 0, fills a struct stat, copies
// it to user. Treats symlinks as regular files (we have none).
i64 DoStat(u64 user_path, u64 user_buf)
{
    char path[64];
    for (u32 i = 0; i < sizeof(path); ++i)
        path[i] = 0;
    if (!mm::CopyFromUser(path, reinterpret_cast<const void*>(user_path), sizeof(path) - 1))
        return kEFAULT;
    path[sizeof(path) - 1] = 0;

    const auto* v = fs::fat32::Fat32Volume(0);
    if (v == nullptr)
        return kENOENT;
    fs::fat32::DirEntry entry;
    if (!fs::fat32::Fat32LookupPath(v, StripFatPrefix(path), &entry))
        return kENOENT;

    u8 sbuf[144];
    FillStatFromEntry(entry, sbuf);
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_buf), sbuf, sizeof(sbuf)))
        return kEFAULT;
    return 0;
}

// Linux: fstat(fd, buf). Synthesises a DirEntry from the fd's
// cached state; doesn't re-read the directory.
i64 DoFstat(u64 fd, u64 user_buf)
{
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd >= 16)
        return kEBADF;
    const auto state = p->linux_fds[fd].state;
    fs::fat32::DirEntry entry;
    for (u64 i = 0; i < sizeof(entry.name); ++i)
        entry.name[i] = 0;
    if (state == 1)
    {
        // tty — character-device-ish. Mode S_IFCHR | 0600 = 020600 = 0x2180.
        u8 sbuf[144];
        for (u64 i = 0; i < sizeof(sbuf); ++i)
            sbuf[i] = 0;
        // st_mode at 24:
        sbuf[24] = 0x80;
        sbuf[25] = 0x21;
        // st_nlink=1 at 16:
        sbuf[16] = 1;
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_buf), sbuf, sizeof(sbuf)))
            return kEFAULT;
        return 0;
    }
    if (state != 2)
        return kEBADF;
    entry.attributes = 0;
    entry.first_cluster = p->linux_fds[fd].first_cluster;
    entry.size_bytes = p->linux_fds[fd].size;
    u8 sbuf[144];
    FillStatFromEntry(entry, sbuf);
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_buf), sbuf, sizeof(sbuf)))
        return kEFAULT;
    return 0;
}

// Linux: writev(fd, iov, iovcnt). Each iovec is two u64s: base
// pointer + length. We call DoWrite on each in order, totaling
// the byte count. Short writes (DoWrite returning less than
// requested) stop the scatter early — same semantics as the
// kernel's real writev.
i64 DoWritev(u64 fd, u64 user_iov, u64 iovcnt)
{
    if (iovcnt == 0)
        return 0;
    if (iovcnt > 1024)
        return kEINVAL; // sanity cap
    i64 total = 0;
    for (u64 i = 0; i < iovcnt; ++i)
    {
        struct
        {
            u64 base;
            u64 len;
        } iov;
        if (!mm::CopyFromUser(&iov, reinterpret_cast<const void*>(user_iov + i * 16), sizeof(iov)))
        {
            return total > 0 ? total : kEFAULT;
        }
        if (iov.len == 0)
            continue;
        const i64 n = DoWrite(fd, iov.base, iov.len);
        if (n < 0)
        {
            return total > 0 ? total : n;
        }
        total += n;
        if (static_cast<u64>(n) < iov.len)
            break; // partial write — stop per spec
    }
    return total;
}

// Linux: readv(fd, iov, iovcnt). Symmetric with writev; streams each
// iovec through DoRead and stops on short read / error.
i64 DoReadv(u64 fd, u64 user_iov, u64 iovcnt)
{
    if (iovcnt == 0)
        return 0;
    if (iovcnt > 1024)
        return kEINVAL;
    i64 total = 0;
    for (u64 i = 0; i < iovcnt; ++i)
    {
        struct
        {
            u64 base;
            u64 len;
        } iov;
        if (!mm::CopyFromUser(&iov, reinterpret_cast<const void*>(user_iov + i * 16), sizeof(iov)))
        {
            return total > 0 ? total : kEFAULT;
        }
        if (iov.len == 0)
            continue;
        const i64 n = DoRead(fd, iov.base, iov.len);
        if (n < 0)
            return total > 0 ? total : n;
        total += n;
        if (static_cast<u64>(n) < iov.len)
            break;
    }
    return total;
}

// Linux: lseek(fd, offset, whence).
//   whence 0 = SEEK_SET — absolute
//   whence 1 = SEEK_CUR — relative to current
//   whence 2 = SEEK_END — relative to file size
// Only file fds support seek; tty fds return -ESPIPE so musl's
// isatty() heuristic works without extra plumbing.
i64 DoLseek(u64 fd, i64 offset, u64 whence)
{
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd >= 16)
        return kEBADF;
    if (p->linux_fds[fd].state == 1)
        return kESPIPE; // tty: can't seek
    if (p->linux_fds[fd].state != 2)
        return kEBADF;

    i64 new_off = 0;
    switch (whence)
    {
    case 0:
        new_off = offset;
        break;
    case 1:
        new_off = static_cast<i64>(p->linux_fds[fd].offset) + offset;
        break;
    case 2:
        new_off = static_cast<i64>(p->linux_fds[fd].size) + offset;
        break;
    default:
        return kEINVAL;
    }
    if (new_off < 0)
        return kEINVAL;
    p->linux_fds[fd].offset = static_cast<u64>(new_off);
    return new_off;
}

// Linux: ioctl(fd, cmd, arg). Handle the three ioctls musl's
// stdio actually reaches under a CRT bring-up:
//   TCGETS      (0x5401) — "is this a tty?" probe. Returns a
//                         populated termios struct so isatty(fd)
//                         returns true; line-edit features are
//                         effectively disabled via the c_lflag
//                         bits we clear.
//   TCSETS      (0x5402) — swallow — we don't honour the
//                         settings, but returning success avoids
//                         aborting callers that set RAW mode.
//   TIOCGWINSZ  (0x5413) — report a fake 80×24 terminal so
//                         curses-style programs stop asking.
// Anything else on a tty fd: -EINVAL. On a non-tty fd: -ENOTTY.
// On a closed slot: -EBADF.
i64 DoIoctl(u64 fd, u64 cmd, u64 arg)
{
    constexpr u64 kTCGETS = 0x5401;
    constexpr u64 kTCSETS = 0x5402;
    constexpr u64 kTCSETSW = 0x5403;
    constexpr u64 kTCSETSF = 0x5404;
    constexpr u64 kTIOCGWINSZ = 0x5413;
    constexpr u64 kTIOCGPGRP = 0x540F;
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd >= 16)
        return kEBADF;
    if (p->linux_fds[fd].state == 0)
        return kEBADF;
    const bool is_tty = (p->linux_fds[fd].state == 1);
    if (!is_tty)
        return kENOTTY;
    switch (cmd)
    {
    case kTCGETS:
    {
        // Linux kernel-ABI termios: 4×u32 flags + 1×u8 c_line +
        // 19×u8 c_cc + pad to 36 bytes. Emit a sensible baseline:
        // ICRNL on input, OPOST on output, CS8 + CREAD + B38400 on
        // control, and ISIG|ICANON|ECHO on lflag so isatty probes
        // that look for "tty with sane defaults" pass.
        struct Termios
        {
            u32 c_iflag;
            u32 c_oflag;
            u32 c_cflag;
            u32 c_lflag;
            u8 c_line;
            u8 c_cc[19];
        } t{};
        static_assert(sizeof(Termios) == 36, "Linux termios ABI is 36 bytes");
        t.c_iflag = 0x100;              // ICRNL
        t.c_oflag = 0x01;               // OPOST
        t.c_cflag = 0x30 | 0x80 | 0x0F; // CS8 | CREAD | B38400 baud
        t.c_lflag = 0x01 | 0x02 | 0x08; // ISIG | ICANON | ECHO
        t.c_line = 0;
        // c_cc: common control chars. VINTR=^C, VQUIT=^\, VERASE=^?,
        // VKILL=^U, VEOF=^D.
        t.c_cc[0] = 0x03; // VINTR
        t.c_cc[1] = 0x1C; // VQUIT
        t.c_cc[2] = 0x7F; // VERASE
        t.c_cc[3] = 0x15; // VKILL
        t.c_cc[4] = 0x04; // VEOF
        if (!mm::CopyToUser(reinterpret_cast<void*>(arg), &t, sizeof(t)))
            return kEFAULT;
        return 0;
    }
    case kTCSETS:
    case kTCSETSW:
    case kTCSETSF:
        // Accept + ignore. The cooked-mode / raw-mode distinction
        // has no observable effect on a serial-only tty today.
        (void)arg;
        return 0;
    case kTIOCGWINSZ:
    {
        struct WinSize
        {
            u16 ws_row;
            u16 ws_col;
            u16 ws_xpixel;
            u16 ws_ypixel;
        } w{};
        w.ws_row = 24;
        w.ws_col = 80;
        if (!mm::CopyToUser(reinterpret_cast<void*>(arg), &w, sizeof(w)))
            return kEFAULT;
        return 0;
    }
    case kTIOCGPGRP:
    {
        // There's no process-group concept in v0; report pid back
        // as the foreground pgid so shells' "am I in the fg?" test
        // resolves to yes.
        const i32 pgid = i32(p->pid);
        if (!mm::CopyToUser(reinterpret_cast<void*>(arg), &pgid, sizeof(pgid)))
            return kEFAULT;
        return 0;
    }
    default:
        return kEINVAL;
    }
}

// Linux: rt_sigaction. Store the requested handler + mask + flags
// in the per-process signal table so a subsequent rt_sigaction
// with a nullptr new_act returns the value we just persisted.
// Signal DELIVERY is still not wired (no user-mode trampoline, no
// pending queue) but musl's CRT init relies on readback to decide
// whether SIGPIPE is SIG_IGN'd — returning the previous value
// matters even though we never actually raise a signal.
//
// Linux sigaction layout (offsets into the user struct):
//   0x00  sa_handler (u64) or sa_sigaction
//   0x08  sa_flags (u64)
//   0x10  sa_restorer (u64)
//   0x18  sa_mask (u64, first u64 of the sigset)
// DoRtSigaction / DoRtSigprocmask moved to syscall_sig.cpp
// alongside the rest of the signal handlers.

i64 DoSetTidAddress(u64 user_tid_ptr)
{
    (void)user_tid_ptr;
    return static_cast<i64>(sched::CurrentTaskId());
}

// Linux: access(path, mode). v0 implements as a presence probe —
// if FAT32LookupPath finds the entry, return 0 (success); else
// -ENOENT. The `mode` bits (R_OK, W_OK, X_OK, F_OK) are ignored:
// everything in FAT32 is effectively rwx from the Linux task's
// perspective.
i64 DoAccess(u64 user_path, u64 mode)
{
    (void)mode;
    char path[64];
    for (u32 i = 0; i < sizeof(path); ++i)
        path[i] = 0;
    if (!mm::CopyFromUser(path, reinterpret_cast<const void*>(user_path), sizeof(path) - 1))
        return kEFAULT;
    path[sizeof(path) - 1] = 0;
    const auto* v = fs::fat32::Fat32Volume(0);
    if (v == nullptr)
        return kENOENT;
    fs::fat32::DirEntry entry;
    return fs::fat32::Fat32LookupPath(v, StripFatPrefix(path), &entry) ? 0 : kENOENT;
}

// Linux: readlink(path, buf, bufsiz). We don't have real symlinks
// yet, but musl / glibc query /proc/self/exe (and /proc/PID/exe)
// during CRT init to recover the program path. Special-case that
// to return the current process's name with a leading "/", which
// is enough for argv[0] / dlopen's relative-path resolution to
// work. Everything else: -EINVAL ("not a symlink").
i64 DoReadlink(u64 user_path, u64 user_buf, u64 bufsiz)
{
    char path[64];
    for (u32 i = 0; i < sizeof(path); ++i)
        path[i] = 0;
    if (!mm::CopyFromUser(path, reinterpret_cast<const void*>(user_path), sizeof(path) - 1))
        return kEFAULT;
    path[sizeof(path) - 1] = 0;

    // Match exactly "/proc/self/exe". /proc/<PID>/exe is not
    // recognised yet — glibc's fallback uses /proc/self/exe too.
    const char kSelf[] = "/proc/self/exe";
    bool matches = true;
    for (u32 i = 0; i < sizeof(kSelf); ++i)
    {
        if (path[i] != kSelf[i])
        {
            matches = false;
            break;
        }
    }
    if (!matches)
        return kEINVAL;

    core::Process* p = core::CurrentProcess();
    if (p == nullptr || p->name == nullptr)
        return kEINVAL;

    char out[64];
    u64 out_len = 0;
    out[out_len++] = '/';
    const char* n = p->name;
    while (*n != '\0' && out_len + 1 < sizeof(out))
    {
        out[out_len++] = *n++;
    }
    if (bufsiz == 0)
        return 0;
    const u64 to_copy = (out_len < bufsiz) ? out_len : bufsiz;
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_buf), out, to_copy))
        return kEFAULT;
    // readlink does not write a trailing NUL; the return value is
    // the byte count the caller uses to terminate.
    return i64(to_copy);
}

// Linux: getcwd(buf, size). Returns the per-process cwd stored
// on Process::linux_cwd — written by chdir / fchdir, defaults to
// "/". POSIX getcwd returns the byte length INCLUDING the NUL
// terminator (so "/" → 2). -ERANGE if the buffer is too small.
// DoGetcwd moved to syscall_path.cpp.

// Linux: futex(uaddr, op, val, ...).
//
// Single-threaded processes have no contention, so we never
// actually block. The real Linux semantics we respect:
//   FUTEX_WAIT (0): if *uaddr != val, return -EAGAIN — tells the
//                   caller "the value already changed, try again".
//                   Otherwise return 0 (spurious wakeup — musl
//                   retries the condition).
//   FUTEX_WAKE (1): return 0 (no waiters, nothing to wake).
//
// FUTEX_PRIVATE_FLAG (0x80) masks off — it's a hint to the kernel
// about shared-memory scope, and for our single-address-space
// case it's a no-op.
i64 DoFutex(u64 uaddr, u64 op, u64 val, u64 timeout, u64 uaddr2, u64 val3)
{
    (void)timeout;
    (void)uaddr2;
    (void)val3;
    constexpr u64 kFutexWait = 0;
    constexpr u64 kFutexWake = 1;
    constexpr u64 kFutexOpMask = 0x7F;
    const u64 base_op = op & kFutexOpMask;
    if (base_op == kFutexWait)
    {
        // Validate the caller's pointer and compare against `val`.
        // Copy fails with -EFAULT so a buggy program (e.g. null
        // uaddr) gets a specific error instead of a silent zero.
        u32 cur = 0;
        if (!mm::CopyFromUser(&cur, reinterpret_cast<const void*>(uaddr), sizeof(cur)))
            return kEFAULT;
        if (cur != u32(val))
            return -11; // -EAGAIN
        return 0;       // "spurious" wake — caller retries
    }
    if (base_op == kFutexWake)
    {
        return 0; // no waiters in single-thread v0
    }
    // Unknown op — reject so a test-suite like LTP gets -EINVAL
    // rather than silent success.
    (void)uaddr;
    (void)val;
    return kEINVAL;
}

// ReadTsc moved to syscall_time.cpp alongside the rest of the
// time / clock plumbing.

// Linux: getrandom(buf, count, flags). Routes through the shared
// kernel entropy pool (RDSEED → RDRAND → splitmix) so a Linux
// userland's stack-cookie / pointer-mangling / crypto init get
// the same hardware backing the rest of the kernel uses. Real
// glibc / musl treat this syscall as cryptographic; we match
// that contract when the CPU supports RDSEED/RDRAND.
i64 DoGetRandom(u64 user_buf, u64 count, u64 flags)
{
    (void)flags;
    if (count == 0)
        return 0;
    if (count > 4096)
        count = 4096; // cap per call, same as Linux default for unseeded
    static u8 tmp[4096];
    core::RandomFillBytes(tmp, count);
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_buf), tmp, count))
        return kEFAULT;
    return static_cast<i64>(count);
}

// NowNs / DoClockGetTime / DoGettimeofday moved to syscall_time.cpp.

// Linux: sysinfo(info). Fills the kernel's current memory + uptime
// + load info. v0 reports:
//   * uptime: real seconds since boot (NowNs / 1e9).
//   * loads:  zero (no load tracking yet).
//   * totalram / freeram: derived from the physical frame
//     allocator at 4 KiB granularity. mem_unit=4096 so callers
//     reading `totalram * mem_unit` see real bytes.
//   * sharedram / bufferram: zero (no page cache yet).
//   * totalswap / freeswap / *high: zero (no swap, no high-mem
//     split on x86_64).
//   * procs: pulled from sched::AliveTaskCount() — best v0
//     estimate of "running processes" since each Process has at
//     least one task.
i64 DoSysinfo(u64 user_info)
{
    if (user_info == 0)
        return kEFAULT;
    struct Info
    {
        i64 uptime;
        u64 loads[3];
        u64 totalram;
        u64 freeram;
        u64 sharedram;
        u64 bufferram;
        u64 totalswap;
        u64 freeswap;
        u16 procs;
        u16 pad;
        u64 totalhigh;
        u64 freehigh;
        u32 mem_unit;
        u8 pad2[4];
    } info;
    info.uptime = static_cast<i64>(NowNs() / 1'000'000'000ull);
    info.loads[0] = 0;
    info.loads[1] = 0;
    info.loads[2] = 0;
    info.totalram = mm::TotalFrames();
    info.freeram = mm::FreeFramesCount();
    info.sharedram = 0;
    info.bufferram = 0;
    info.totalswap = 0;
    info.freeswap = 0;
    info.totalhigh = 0;
    info.freehigh = 0;
    info.procs = 1;
    info.pad = 0;
    info.mem_unit = 4096;
    for (u64 i = 0; i < sizeof(info.pad2); ++i)
        info.pad2[i] = 0;
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_info), &info, sizeof(info)))
        return kEFAULT;
    return 0;
}

// Linux: fsync(fd) / fdatasync(fd). v0 FAT32 writes are
// synchronous (no page cache, every write hits the block device
// before returning), so flushing is a no-op. Validate the fd —
// Linux returns -EBADF for bogus fds even when the operation
// would otherwise succeed.
i64 DoFsync(u64 fd)
{
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd >= 16)
        return kEBADF;
    if (p->linux_fds[fd].state == 0)
        return kEBADF;
    return 0;
}

i64 DoFdatasync(u64 fd)
{
    return DoFsync(fd);
}

// Linux: madvise(addr, len, advice). Hint to the kernel about
// expected access patterns. v0 has no swap, no readahead engine,
// and no compact/cold-page reclaim — so any sane hint is a clean
// no-op. The actively-destructive hints (MADV_DONTNEED, MADV_FREE)
// would zero pages on real Linux; we don't honour them — programs
// that rely on the zero are still safe because they re-touch the
// pages and re-read whatever bytes are there. This matches what a
// MADV_NORMAL response would look like.
//
// The most common bad-input case is a non-page-aligned addr; mirror
// Linux's -EINVAL on that.
// DoMadvise moved to syscall_mm.cpp.

// DoGetpgrp moved to syscall_proc.cpp.

// Resource-limit handlers (DoGetrlimit / DoSetrlimit /
// DoPrlimit64) plus the kRlimit* / kRlimInfinity constants and
// RlimitDefaultsFor helper live in syscall_rlimit.cpp. The
// `using namespace internal;` directive at the top of this TU
// keeps the dispatcher's references unqualified.

// DoTime / DoNanosleep moved to syscall_time.cpp.

// Linux: pread64(fd, buf, count, offset). Read at an explicit
// offset without mutating the fd's position cursor. Implemented
// as a save-restore around the existing offset — simplest way
// to reuse DoRead without duplicating the FAT32 walk.
i64 DoPread64(u64 fd, u64 user_buf, u64 len, i64 offset)
{
    if (fd >= 16)
        return kEBADF;
    core::Process* p = core::CurrentProcess();
    if (p == nullptr)
        return kEBADF;
    if (offset < 0)
        return kEINVAL;
    const u64 saved = p->linux_fds[fd].offset;
    p->linux_fds[fd].offset = static_cast<u64>(offset);
    const i64 n = DoRead(fd, user_buf, len);
    p->linux_fds[fd].offset = saved;
    return n;
}

// Linux: pwrite64(fd, buf, count, offset). Mirror of pread64.
i64 DoPwrite64(u64 fd, u64 user_buf, u64 len, i64 offset)
{
    if (fd >= 16)
        return kEBADF;
    core::Process* p = core::CurrentProcess();
    if (p == nullptr)
        return kEBADF;
    if (offset < 0)
        return kEINVAL;
    const u64 saved = p->linux_fds[fd].offset;
    p->linux_fds[fd].offset = static_cast<u64>(offset);
    const i64 n = DoWrite(fd, user_buf, len);
    p->linux_fds[fd].offset = saved;
    return n;
}

// CopyFdSlot + DoDup / DoDup2 / DoFcntl moved to syscall_fd.cpp
// alongside DoDup3.

// Linux: chdir(path). Copies the user path into the process's
// linux_cwd buffer, byte-for-byte (no canonicalisation — every
// FAT32 / ramfs lookup already strips the prefix at use site).
// -ENAMETOOLONG if the path doesn't fit; -ENOENT if the target
// directory doesn't actually exist on the FAT32 volume (when the
// path looks like a FAT32 path); otherwise success.
// DoChdir / DoFchdir moved to syscall_path.cpp.

// Linux: mprotect(addr, len, prot). v0 maps all user pages RW
// and has no MapProtect helper, so the protections themselves
// stay advisory — but the call validates inputs the way Linux
// does so a buggy program sees -EINVAL instead of a phantom
// success.
//
// Validation:
//   * addr must be page-aligned (4 KiB).
//   * (addr + len) must not overflow.
//   * The whole range must lie in the canonical low half — same
//     gate CopyFromUser uses to refuse kernel-VA pointers.
//   * len == 0 is success in Linux; mirror that.
//   * prot has 4 valid bits (PROT_READ=1, PROT_WRITE=2,
//     PROT_EXEC=4, PROT_NONE=0; PROT_GROWSDOWN/UP at 0x01000000
//     and 0x02000000 are accepted by Linux so musl's stack-
//     guard tweak doesn't get rejected).
// DoMprotect moved to syscall_mm.cpp.

// DoSigaltstack / DoRtSigreturn moved to syscall_sig.cpp.

// DoSchedYield / DoGetTid / DoTgkill / DoKill / DoGetPpid /
// DoGetPgid / DoGetSid / DoSetPgid moved to syscall_proc.cpp.

// Identity stubs (DoGetUid / DoGetGid / DoGetEuid / DoGetEgid)
// moved to syscall_cred.cpp alongside the rest of the credential
// handlers. The `using namespace internal;` directive at the top
// of this TU keeps the dispatcher's references unqualified.

// PageUp helper + DoBrk + DoMmap + DoMunmap moved to syscall_mm.cpp.

// Linux: openat(dirfd, pathname, flags, mode). Modern glibc's
// `open()` is usually `openat(AT_FDCWD, ...)` under the hood —
// this handler is what real compiled-C binaries actually hit.
// v0 only honours AT_FDCWD; any other dirfd is -EBADF until
// per-fd directory state lands (same limitation fchdir has).
i64 DoOpenat(i64 dirfd, u64 user_path, u64 flags, u64 mode)
{
    if (dirfd != kAtFdCwd)
        return kEBADF;
    return DoOpen(user_path, flags, mode);
}

// Linux: newfstatat(dirfd, pathname, statbuf, flags).
// Shape: if AT_EMPTY_PATH (0x1000) is set + dirfd is a valid fd,
// stat the fd (≡ fstat). Else resolve `pathname` relative to
// dirfd (we only accept AT_FDCWD for now). No-follow-symlink
// flag (0x100) is accepted + ignored — we have no symlinks.
i64 DoNewFstatat(i64 dirfd, u64 user_path, u64 user_buf, u64 flags)
{
    constexpr u64 kAtEmptyPath = 0x1000;
    if ((flags & kAtEmptyPath) != 0)
    {
        if (dirfd < 0)
            return kEBADF;
        return DoFstat(static_cast<u64>(dirfd), user_buf);
    }
    if (dirfd != kAtFdCwd)
        return kEBADF;
    return DoStat(user_path, user_buf);
}

// DoDup3 moved to syscall_fd.cpp.

// Linux: getrusage(who, usage). Returns resource-usage stats
// for self/children/thread. We don't have a kernel/user split
// in our tick accounting, so the (utime + stime) sum reflects
// total CPU time and we put it all in utime — matches what a
// SCHED_OTHER task's accounting would look like in practice.
// All other fields stay zero (no I/O accounting, no page-fault
// counters, no signal counters tracked at this layer yet).
//
// Struct layout (144 bytes): {ru_utime:16, ru_stime:16, 14×u64}.
constexpr i64 kRusageSelf = 0;
constexpr i64 kRusageChildren = -1;
constexpr i64 kRusageThread = 1;
i64 DoGetrusage(u64 who, u64 user_buf)
{
    if (user_buf == 0)
        return kEFAULT;
    const i64 who_signed = static_cast<i64>(who);
    if (who_signed != kRusageSelf && who_signed != kRusageChildren && who_signed != kRusageThread)
        return kEINVAL;

    struct Rusage
    {
        i64 ru_utime_sec, ru_utime_usec;
        i64 ru_stime_sec, ru_stime_usec;
        i64 ru_pad[14];
    } ru;
    ru.ru_utime_sec = 0;
    ru.ru_utime_usec = 0;
    ru.ru_stime_sec = 0;
    ru.ru_stime_usec = 0;
    for (u64 i = 0; i < 14; ++i)
        ru.ru_pad[i] = 0;
    if (who_signed == kRusageSelf || who_signed == kRusageThread)
    {
        const core::Process* p = core::CurrentProcess();
        if (p != nullptr)
        {
            // 100 Hz scheduler tick → each tick = 10 ms.
            const u64 ticks = p->ticks_used;
            ru.ru_utime_sec = static_cast<i64>(ticks / 100ull);
            ru.ru_utime_usec = static_cast<i64>((ticks % 100ull) * 10'000ull);
        }
    }
    // RUSAGE_CHILDREN: no children tracking → all zero, which
    // matches what wait()-less programs see in practice.
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_buf), &ru, sizeof(ru)))
        return kEFAULT;
    return 0;
}

// Linux: poll(fds, nfds, timeout_ms). Returns count of fds that
// are ready. v0 has no event-driven fd machinery (all fds are
// either ttys that "block" on read and return immediately on
// write, or regular files that are always "ready" for read
// with available bytes). Matching caller expectations:
//   - If any pollfd has POLLIN/POLLOUT requested for a live
//     fd, mark it ready in revents and count it. That's what a
//     caller like "wait until stdin has input" would see on a
//     tty — immediately ready, non-blocking.
//   - A zero-nfds poll with a non-negative timeout is a
//     Linux-idiomatic nanosleep; we accept + return 0.
// All edge cases (POLLHUP, POLLERR, negative timeout = "wait
// forever") are returned as 0 revents (=no event), which is
// honest — we'd need a proper wait-queue per fd to do more.
constexpr i64 kPollIn = 0x0001;
constexpr i64 kPollOut = 0x0004;
i64 DoPoll(u64 user_fds, u64 nfds, i64 timeout_ms)
{
    (void)timeout_ms;
    if (nfds == 0)
        return 0;
    if (user_fds == 0)
        return kEFAULT;
    // Cap at 16 — matches our per-process fd table; larger polls
    // are surely bogus until we support more. Each pollfd is
    // 8 bytes: {int fd, short events, short revents}.
    if (nfds > 16)
        return kEINVAL;

    struct PollFd
    {
        i32 fd;
        i16 events;
        i16 revents;
    } fds[16];
    if (!mm::CopyFromUser(&fds[0], reinterpret_cast<const void*>(user_fds), nfds * sizeof(PollFd)))
        return kEFAULT;

    core::Process* p = core::CurrentProcess();
    i64 ready = 0;
    for (u64 i = 0; i < nfds; ++i)
    {
        fds[i].revents = 0;
        if (fds[i].fd < 0 || fds[i].fd >= 16)
            continue;
        if (p == nullptr)
            continue;
        const u8 state = p->linux_fds[static_cast<u64>(fds[i].fd)].state;
        if (state == 0)
        {
            // Closed slot — POSIX says revents=POLLNVAL (0x20).
            fds[i].revents = 0x20;
            ++ready;
            continue;
        }
        if ((fds[i].events & kPollIn) != 0 || (fds[i].events & kPollOut) != 0)
        {
            fds[i].revents = fds[i].events & (kPollIn | kPollOut);
            ++ready;
        }
    }
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_fds), &fds[0], nfds * sizeof(PollFd)))
        return kEFAULT;
    return ready;
}

// Linux: select(nfds, readfds, writefds, exceptfds, timeout).
// Boundary-probe stub — we don't implement real fd bitmap
// dispatch. Return "0 ready" which tells the caller "your
// timeout expired without any event" — harmless, lets the
// caller loop or move on. Real implementations rarely reach
// select() anymore (poll/epoll dominate); synxtest probes it
// to show the stub is present.
i64 DoSelect(u64 nfds, u64 rfds, u64 wfds, u64 efds, u64 timeout)
{
    (void)nfds;
    (void)rfds;
    (void)wfds;
    (void)efds;
    (void)timeout;
    return 0;
}

// Linux: getdents64(fd, dirp, count). Read directory entries
// into the user buffer. v0 has no readable per-fd directory
// state — when we get a dirfd we don't know where we are in
// the enumeration. Returning 0 means "end of directory", which
// makes `ls` print nothing rather than looping. Honest partial
// implementation; a real one requires a per-fd cursor into the
// FAT32 root, which the existing fd state doesn't carry.
i64 DoGetdents64(u64 fd, u64 user_buf, u64 count)
{
    (void)fd;
    (void)user_buf;
    (void)count;
    return 0;
}

// Linux: set_robust_list(head, len). musl's thread init calls
// this. We have no robust-futex wake-on-exit machinery, so
// accepting + no-op is the honest glibc-compat move.
i64 DoSetRobustList(u64 head, u64 len)
{
    (void)head;
    (void)len;
    return 0;
}
i64 DoGetRobustList(u64 pid, u64 user_head_ptr, u64 user_len_ptr)
{
    (void)pid;
    (void)user_head_ptr;
    (void)user_len_ptr;
    return 0;
}

// Linux: arch_prctl(code, addr). Used almost exclusively by musl's
// CRT at _start to plant the thread-local-storage anchor in
// FS.base: `arch_prctl(ARCH_SET_FS, &thread_block)`. Without this,
// every %fs:[...] access in musl hits an unmapped VA and #PF.
//
// v0 scope:
//   ARCH_SET_FS — write `addr` to MSR_FS_BASE.
//   ARCH_GET_FS — read MSR_FS_BASE, write to *(u64*)addr.
//   ARCH_SET_GS / GET_GS — return -EINVAL (we use MSR_GS_BASE
//     for our own swapgs dance; exposing it to user mode would
//     let a malicious task alias our per-CPU area).
//
// Note: we don't save/restore MSR_FS_BASE across context switches
// yet. Works because v0 has at most one Linux-ABI task running at
// a time (and kernel workers don't touch FS.base). Multi-Linux-
// task support will need per-Task fs_base storage.
i64 DoArchPrctl(u64 code, u64 addr)
{
    switch (code)
    {
    case kArchSetFs:
        WriteMsr(kMsrFsBase, addr);
        return 0;
    case kArchGetFs:
    {
        u32 lo, hi;
        asm volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(kMsrFsBase));
        const u64 v = (static_cast<u64>(hi) << 32) | lo;
        if (!mm::CopyToUser(reinterpret_cast<void*>(addr), &v, sizeof(v)))
        {
            return kEFAULT;
        }
        return 0;
    }
    case kArchSetGs:
    case kArchGetGs:
        return kEINVAL;
    default:
        return kEINVAL;
    }
}

// Linux: uname(buf). Fills a struct utsname with six NUL-padded
// 65-char fields: sysname, nodename, release, version, machine,
// domainname. Total 6 * 65 = 390 bytes. musl reads this at
// startup for diagnostics (`uname -a` etc.) and for platform
// dispatch in a few places. Static response: a real kernel
// would plumb nodename to a runtime-configurable hostname.
i64 DoUname(u64 user_buf)
{
    constexpr u64 kFieldLen = 65;
    constexpr u64 kFields = 6;
    constexpr u64 kTotalLen = kFieldLen * kFields;
    u8 kbuf[kTotalLen];
    for (u64 i = 0; i < kTotalLen; ++i)
        kbuf[i] = 0;
    auto set_field = [&](u64 field_idx, const char* s)
    {
        u8* dst = kbuf + field_idx * kFieldLen;
        for (u64 i = 0; s[i] != 0 && i < kFieldLen - 1; ++i)
        {
            dst[i] = static_cast<u8>(s[i]);
        }
    };
    set_field(0, "DuetOS");
    set_field(1, "duetos");
    set_field(2, "0.1");
    set_field(3, "duetos-v0 #1");
    set_field(4, "x86_64");
    set_field(5, "localdomain");
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_buf), kbuf, kTotalLen))
    {
        return kEFAULT;
    }
    return 0;
}

// ---------------------------------------------------------------
// Batch 55 — compat-stub + FAT32-backed handlers for the most-
// commonly-probed unimplemented syscalls. See the kSys* enum
// block at the top for the list and rationale.
// ---------------------------------------------------------------

// kENOMEM_ shadow constant removed — DoMremap moved to syscall_mm.cpp,
// which uses the kENOMEM in syscall_internal.h directly.

// lstat is identical to stat in v0 — there are no symlinks.
i64 DoLstat(u64 user_path, u64 user_buf)
{
    return DoStat(user_path, user_buf);
}

// pause(): suspend until a signal arrives. v0 has no signal
// delivery, so this would block forever. Sleep in big chunks
// instead of a tight yield loop so the scheduler isn't burning
// cycles on us. Returns -EINTR conventionally on wake; since we
// never wake, the return is unreachable.
i64 DoPause()
{
    constexpr u64 kHugeTicks = 1ull << 30; // ~3.4 yrs at 100 Hz
    for (;;)
    {
        sched::SchedSleepTicks(kHugeTicks);
    }
    return 0;
}

// DoMremap / DoMsync / DoMincore moved to syscall_mm.cpp.

// flock(fd, op): advisory file lock. v0 is single-process for
// the FAT32 mount; advisory locks are no-ops by definition.
i64 DoFlock(u64 fd, u64 op)
{
    (void)fd;
    (void)op;
    return 0;
}

// chmod / fchmod / chown / fchown / lchown: v0 has no permission
// model and no uid/gid model. Accept the call but verify the
// target exists — install scripts that chmod a missing file
// expect -ENOENT, not silent success that masks a typo'd path.
i64 DoChmod(u64 user_path, u64 mode)
{
    (void)mode;
    char kbuf[64];
    const char* leaf = nullptr;
    if (!CopyAndStripFatPath(user_path, kbuf, leaf))
        return kEFAULT;
    const auto* v = fs::fat32::Fat32Volume(0);
    if (v == nullptr)
        return 0;
    fs::fat32::DirEntry probe;
    if (!fs::fat32::Fat32LookupPath(v, leaf, &probe))
        return kENOENT;
    return 0;
}
i64 DoFchmod(u64 fd, u64 mode)
{
    (void)mode;
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd >= 16 || p->linux_fds[fd].state == 0)
        return kEBADF;
    return 0;
}
i64 DoChown(u64 user_path, u64 uid, u64 gid)
{
    (void)uid;
    (void)gid;
    return DoChmod(user_path, 0);
}
i64 DoFchown(u64 fd, u64 uid, u64 gid)
{
    (void)uid;
    (void)gid;
    return DoFchmod(fd, 0);
}
i64 DoLchown(u64 user_path, u64 uid, u64 gid)
{
    return DoChown(user_path, uid, gid);
}

// times(buf): fill struct tms with user/system/cuser/csys clock
// counts in clock ticks (Linux: 100 Hz, 1 tick = 10 ms — matches
// our scheduler tick exactly). Per-task accounting comes from
// Process::ticks_used; cuser/cstime tracking would need a wait()
// path we don't have, so they stay zero. The return value is the
// canonical "ticks since boot" the kernel TimerTicks counter
// reports.
// DoTimes moved to syscall_time.cpp.

// Credential handlers (DoSetuid / DoSetgid / DoSetreuid /
// DoSetregid / DoSetresuid / DoSetresgid / DoGetresuid /
// DoGetresgid / DoSetfsuid / DoSetfsgid / DoGetgroups /
// DoSetgroups / DoCapget / DoCapset) live in syscall_cred.cpp.
// The `using namespace internal;` directive at the top of this
// TU keeps the dispatcher's references unqualified.

// utime(path, buf): set atime/mtime on a file. v0 doesn't track
// either, so accept as no-op — but verify the path is real before
// pretending success. A program that utimes a nonexistent file
// expects -ENOENT, not silent success.
i64 DoUtime(u64 user_path, u64 user_buf)
{
    (void)user_buf;
    char kbuf[64];
    const char* leaf = nullptr;
    if (!CopyAndStripFatPath(user_path, kbuf, leaf))
        return kEFAULT;
    const auto* v = fs::fat32::Fat32Volume(0);
    if (v == nullptr)
        return 0; // No FAT32 — pretend success (path may be ramfs).
    fs::fat32::DirEntry probe;
    if (!fs::fat32::Fat32LookupPath(v, leaf, &probe))
        return kENOENT;
    return 0;
}

// mknod(path, mode, dev): create a special file (FIFO, char,
// block, etc.). v0 has none of these. -EPERM is the standard
// "you don't have CAP_MKNOD" return; honest enough.
i64 DoMknod(u64 user_path, u64 mode, u64 dev)
{
    (void)user_path;
    (void)mode;
    (void)dev;
    return kEPERM;
}

// personality(persona): query/set the process's execution
// personality (32-bit emulation, address-space layout quirks,
// etc.). v0 only ever runs as the default Linux personality;
// return 0 as both "current persona" and "set succeeded".
i64 DoPersonality(u64 persona)
{
    (void)persona;
    return 0;
}

// getpriority / setpriority: nice-value query/set. v0 scheduler
// is a flat round-robin with no priority levels. Return 0 (the
// neutral nice value) on get; accept any set as a no-op.
i64 DoGetpriority(u64 which, u64 who)
{
    (void)which;
    (void)who;
    return 0;
}
i64 DoSetpriority(u64 which, u64 who, u64 prio)
{
    (void)which;
    (void)who;
    (void)prio;
    return 0;
}

// DoMlock / DoMunlock / DoMlockall / DoMunlockall moved to syscall_mm.cpp.

// FAT32-backed filesystem ops. All four route through the
// existing Fat32*AtPath primitives. Path strip mirrors DoOpen:
// musl uses absolute paths, FAT32 wants volume-relative.

// Helper: copy a user path into a 64-byte kernel buffer +
// strip the FAT32 mount prefix. Returns true on success, false
// if the copy failed or the path is unterminated. Out points
// inside `kbuf`; lifetime tracks `kbuf`.
bool CopyAndStripFatPath(u64 user_path, char (&kbuf)[64], const char*& out_leaf)
{
    for (u32 i = 0; i < sizeof(kbuf); ++i)
        kbuf[i] = 0;
    if (!mm::CopyFromUser(kbuf, reinterpret_cast<const void*>(user_path), sizeof(kbuf) - 1))
        return false;
    kbuf[sizeof(kbuf) - 1] = 0;
    bool has_nul = false;
    for (u32 i = 0; i < sizeof(kbuf); ++i)
    {
        if (kbuf[i] == 0)
        {
            has_nul = true;
            break;
        }
    }
    if (!has_nul)
        return false;
    out_leaf = StripFatPrefix(kbuf);
    return true;
}

// truncate(path, length): shrink/grow a file to `length` bytes.
i64 DoTruncate(u64 user_path, u64 length)
{
    char kbuf[64];
    const char* leaf = nullptr;
    if (!CopyAndStripFatPath(user_path, kbuf, leaf))
        return kEFAULT;
    const auto* v = fs::fat32::Fat32Volume(0);
    if (v == nullptr)
        return kENOENT;
    const i64 rc = fs::fat32::Fat32TruncateAtPath(v, leaf, length);
    if (rc < 0)
        return kEIO;
    return 0;
}

// ftruncate(fd, length): same as truncate but by fd. Use the
// cached path on the LinuxFd entry.
i64 DoFtruncate(u64 fd, u64 length)
{
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd >= 16 || p->linux_fds[fd].state != 2)
        return kEBADF;
    const auto* v = fs::fat32::Fat32Volume(0);
    if (v == nullptr)
        return kENOENT;
    const i64 rc = fs::fat32::Fat32TruncateAtPath(v, p->linux_fds[fd].path, length);
    if (rc < 0)
        return kEIO;
    // Keep the cached size in sync — a future read/write needs it.
    p->linux_fds[fd].size = static_cast<u32>(length);
    return 0;
}

// unlink(path): delete a file. Returns 0 on success, -ENOENT
// if the file doesn't exist.
i64 DoUnlink(u64 user_path)
{
    char kbuf[64];
    const char* leaf = nullptr;
    if (!CopyAndStripFatPath(user_path, kbuf, leaf))
        return kEFAULT;
    const auto* v = fs::fat32::Fat32Volume(0);
    if (v == nullptr)
        return kENOENT;
    if (!fs::fat32::Fat32DeleteAtPath(v, leaf))
        return kENOENT;
    return 0;
}

// mkdir(path, mode): create a directory. Mode is ignored (no
// permission model).
i64 DoMkdir(u64 user_path, u64 mode)
{
    (void)mode;
    char kbuf[64];
    const char* leaf = nullptr;
    if (!CopyAndStripFatPath(user_path, kbuf, leaf))
        return kEFAULT;
    const auto* v = fs::fat32::Fat32Volume(0);
    if (v == nullptr)
        return kENOENT;
    if (!fs::fat32::Fat32MkdirAtPath(v, leaf))
        return kEIO;
    return 0;
}

// rmdir(path): remove an empty directory.
i64 DoRmdir(u64 user_path)
{
    char kbuf[64];
    const char* leaf = nullptr;
    if (!CopyAndStripFatPath(user_path, kbuf, leaf))
        return kEFAULT;
    const auto* v = fs::fat32::Fat32Volume(0);
    if (v == nullptr)
        return kENOENT;
    if (!fs::fat32::Fat32RmdirAtPath(v, leaf))
        return kEIO;
    return 0;
}

// ---------------------------------------------------------------
// Batch 56 — additional compat stubs + *at-family delegations.
// ---------------------------------------------------------------

// AT_REMOVEDIR flag for unlinkat.
constexpr u64 kAtRemoveDir = 0x200;

// Helper: for *at syscalls, v0 only supports AT_FDCWD. Returns
// kEBADF for any other dirfd value, 0 otherwise. Logged so a
// caller that happens to pass a real dirfd sees why the call
// fails instead of chasing a phantom bug.
i64 AtFdCwdOnly(i64 dirfd)
{
    if (dirfd == kAtFdCwd)
        return 0;
    arch::SerialWrite("[linux] *at-family: unsupported dirfd=");
    arch::SerialWriteHex(static_cast<u64>(dirfd));
    arch::SerialWrite(" (AT_FDCWD-only in v0)\n");
    return kEBADF;
}

// DoPtrace / DoSyslog / DoVhangup / DoAcct / DoMount / DoUmount2 /
// DoSync / DoSyncfs / DoRename / DoLink / DoSymlink / DoSetThreadArea
// / DoGetThreadArea / DoIoprioGet / DoIoprioSet moved to
// syscall_stub.cpp.

// Scheduler-policy handlers (DoSchedSetaffinity / DoSchedGetaffinity
// / DoSchedGetscheduler / DoSchedSetscheduler / DoSchedGetparam /
// DoSchedSetparam / DoSchedGetPriorityMax/Min / DoSchedRrGetInterval)
// plus the SCHED_* constants live in syscall_sched.cpp. The
// `using namespace internal;` directive at the top of this TU
// keeps the dispatcher's references unqualified.

// DoClockGetres / DoClockNanosleep moved to syscall_time.cpp.

// getcpu(cpu, node, tcache): which CPU are we on. BSP-only — 0.
i64 DoGetcpu(u64 user_cpu, u64 user_node, u64 user_tcache)
{
    (void)user_tcache;
    const u32 zero = 0;
    if (user_cpu != 0 && !mm::CopyToUser(reinterpret_cast<void*>(user_cpu), &zero, sizeof(zero)))
        return kEFAULT;
    if (user_node != 0 && !mm::CopyToUser(reinterpret_cast<void*>(user_node), &zero, sizeof(zero)))
        return kEFAULT;
    return 0;
}

// *at-family delegations. Every one of these routes through the
// non-*at handler when dirfd == AT_FDCWD, or returns -EBADF.

// mkdirat(dirfd, path, mode)
i64 DoMkdirat(i64 dirfd, u64 user_path, u64 mode)
{
    if (const i64 rv = AtFdCwdOnly(dirfd); rv != 0)
        return rv;
    return DoMkdir(user_path, mode);
}

// unlinkat(dirfd, path, flags): flags & AT_REMOVEDIR -> rmdir.
i64 DoUnlinkat(i64 dirfd, u64 user_path, u64 flags)
{
    if (const i64 rv = AtFdCwdOnly(dirfd); rv != 0)
        return rv;
    if (flags & kAtRemoveDir)
        return DoRmdir(user_path);
    return DoUnlink(user_path);
}

// linkat / symlinkat / renameat / renameat2 — all map onto the
// non-*at stubs that already return -ENOSYS.
i64 DoLinkat(i64 olddirfd, u64 oldpath, i64 newdirfd, u64 newpath, u64 flags)
{
    if (const i64 rv = AtFdCwdOnly(olddirfd); rv != 0)
        return rv;
    if (const i64 rv = AtFdCwdOnly(newdirfd); rv != 0)
        return rv;
    (void)flags;
    return DoLink(oldpath, newpath);
}
i64 DoSymlinkat(u64 target, i64 newdirfd, u64 linkpath)
{
    if (const i64 rv = AtFdCwdOnly(newdirfd); rv != 0)
        return rv;
    return DoSymlink(target, linkpath);
}
i64 DoRenameat(i64 olddirfd, u64 oldpath, i64 newdirfd, u64 newpath)
{
    if (const i64 rv = AtFdCwdOnly(olddirfd); rv != 0)
        return rv;
    if (const i64 rv = AtFdCwdOnly(newdirfd); rv != 0)
        return rv;
    return DoRename(oldpath, newpath);
}
i64 DoRenameat2(i64 olddirfd, u64 oldpath, i64 newdirfd, u64 newpath, u64 flags)
{
    (void)flags;
    return DoRenameat(olddirfd, oldpath, newdirfd, newpath);
}

// fchownat / futimesat / fchmodat / faccessat — identity/ACL
// mutations the caller wants; v0 has no permission model, so
// the non-*at versions are already no-ops. Delegate.
i64 DoFchownat(i64 dirfd, u64 user_path, u64 uid, u64 gid, u64 flags)
{
    if (const i64 rv = AtFdCwdOnly(dirfd); rv != 0)
        return rv;
    (void)flags;
    return DoChown(user_path, uid, gid);
}
i64 DoFutimesat(i64 dirfd, u64 user_path, u64 user_times)
{
    if (const i64 rv = AtFdCwdOnly(dirfd); rv != 0)
        return rv;
    return DoUtime(user_path, user_times);
}
i64 DoFchmodat(i64 dirfd, u64 user_path, u64 mode, u64 flags)
{
    if (const i64 rv = AtFdCwdOnly(dirfd); rv != 0)
        return rv;
    (void)flags;
    return DoChmod(user_path, mode);
}
i64 DoFaccessat(i64 dirfd, u64 user_path, u64 mode, u64 flags)
{
    if (const i64 rv = AtFdCwdOnly(dirfd); rv != 0)
        return rv;
    (void)flags;
    return DoAccess(user_path, mode);
}
i64 DoFaccessat2(i64 dirfd, u64 user_path, u64 mode, u64 flags)
{
    return DoFaccessat(dirfd, user_path, mode, flags);
}

// utimensat(dirfd, path, times, flags): set atime/mtime to
// nanosecond-precision values. No time-tracking in v0, but mirror
// utime's path-validation flow so a typo'd path surfaces -ENOENT
// and a bogus dirfd surfaces -EBADF.
i64 DoUtimensat(i64 dirfd, u64 user_path, u64 user_times, u64 flags)
{
    if (dirfd != kAtFdCwd && user_path != 0)
        return kEBADF;
    (void)user_times;
    (void)flags;
    if (user_path != 0)
    {
        // path-relative form: validate the target exists when it
        // looks like a FAT32 path. NUL path means "use the dirfd
        // directly" — accept since we already validated the fd.
        char kbuf[64];
        const char* leaf = nullptr;
        if (!CopyAndStripFatPath(user_path, kbuf, leaf))
            return kEFAULT;
        const auto* v = fs::fat32::Fat32Volume(0);
        if (v != nullptr)
        {
            fs::fat32::DirEntry probe;
            if (!fs::fat32::Fat32LookupPath(v, leaf, &probe))
                return kENOENT;
        }
    }
    return 0;
}

// ---------------------------------------------------------------
// Batch 67 — minimal stubs for previously-unwired common syscalls.
// Each one returns a Linux-shaped error/zero so a caller that
// probes the syscall sees a clean answer instead of the
// "unhandled syscall" panic line.
// ---------------------------------------------------------------

// kENFILE / kECHILD / kEINTR moved to syscall_internal.h with the
// rest of the errno constants.

// DoPipe / DoPipe2 / DoWait4 / DoWaitid / DoEventfd / DoTimerfd* /
// DoSignalfd / DoFadvise64 / DoReadahead / DoEpoll* / DoInotifyInit*
// moved to syscall_stub.cpp.

// DoRtSigpending / DoRtSigsuspend / DoRtSigtimedwait moved to
// syscall_sig.cpp.

// ppoll / pselect6: poll/select with a sigmask + timeout. Reuse
// the existing poll/select handlers; the sigmask is silently
// ignored (matches what we do for plain rt_sigprocmask anyway).
i64 DoPpoll(u64 user_fds, u64 nfds, u64 user_ts, u64 user_sigmask, u64 sigsetsize)
{
    (void)user_sigmask;
    (void)sigsetsize;
    // Convert nanosecond timeout to ms if user_ts is non-null.
    i64 timeout_ms = -1;
    if (user_ts != 0)
    {
        struct
        {
            i64 sec;
            i64 nsec;
        } ts;
        if (!mm::CopyFromUser(&ts, reinterpret_cast<const void*>(user_ts), sizeof(ts)))
            return kEFAULT;
        timeout_ms = ts.sec * 1000 + ts.nsec / 1'000'000;
    }
    return DoPoll(user_fds, nfds, timeout_ms);
}
i64 DoPselect6(u64 nfds, u64 r, u64 w, u64 e, u64 user_ts, u64 user_sigmask)
{
    (void)user_sigmask;
    (void)user_ts;
    return DoSelect(nfds, r, w, e, 0);
}


// prctl(option, arg2, arg3, arg4, arg5): wide multiplexed call.
// We accept the most common options that musl + bionic exercise
// at startup and ignore the rest with -EINVAL.
//   PR_SET_NAME (15) — copy up to 16 bytes into Process::name.
//                       Accepting silently lets logging tools rename
//                       their threads (e.g. "musl-thread-pool-1").
//   PR_GET_NAME (16) — return the stored name.
//   PR_SET_DUMPABLE (4) / PR_GET_DUMPABLE (3) — accept; we have no
//                       core-dumps anyway.
//   PR_SET_PDEATHSIG (1) — accept; no parent-death tracking.
//   PR_GET_PDEATHSIG (2) — return 0.
//   PR_SET_SECCOMP (22) — refuse with -EINVAL (no filter engine).
i64 DoPrctl(u64 option, u64 arg2, u64 arg3, u64 arg4, u64 arg5)
{
    (void)arg3;
    (void)arg4;
    (void)arg5;
    constexpr u64 kPrSetPdeathsig = 1;
    constexpr u64 kPrGetPdeathsig = 2;
    constexpr u64 kPrGetDumpable = 3;
    constexpr u64 kPrSetDumpable = 4;
    constexpr u64 kPrSetName = 15;
    constexpr u64 kPrGetName = 16;
    constexpr u64 kPrSetSeccomp = 22;
    switch (option)
    {
    case kPrSetPdeathsig:
    case kPrSetDumpable:
        return 0;
    case kPrGetPdeathsig:
        return 0;
    case kPrGetDumpable:
        return 1; // dumpable by default in Linux too
    case kPrGetName:
    {
        if (arg2 == 0)
            return kEFAULT;
        const core::Process* p = core::CurrentProcess();
        char buf[16];
        for (u32 i = 0; i < sizeof(buf); ++i)
            buf[i] = 0;
        if (p != nullptr && p->name != nullptr)
        {
            for (u32 i = 0; i + 1 < sizeof(buf) && p->name[i] != 0; ++i)
                buf[i] = p->name[i];
        }
        if (!mm::CopyToUser(reinterpret_cast<void*>(arg2), buf, sizeof(buf)))
            return kEFAULT;
        return 0;
    }
    case kPrSetName:
        // No way to mutate Process::name (it's a const char*) so
        // we accept silently. Future: add a writable name buffer.
        return 0;
    case kPrSetSeccomp:
        return kEINVAL;
    default:
        return kEINVAL;
    }
}

} // namespace

// ---------------------------------------------------------------
// Public wrappers exposed to the translation unit. The anonymous-
// namespace Do* helpers have internal linkage; these forward to
// them so another TU can compose larger syscalls from the
// primitives (e.g. readv = iterate iovecs calling LinuxRead).
// ---------------------------------------------------------------
i64 LinuxRead(u64 fd, u64 user_buf, u64 len)
{
    return DoRead(fd, user_buf, len);
}
i64 LinuxWrite(u64 fd, u64 user_buf, u64 len)
{
    return DoWrite(fd, user_buf, len);
}
i64 LinuxClockGetTime(u64 clk_id, u64 user_ts)
{
    return DoClockGetTime(clk_id, user_ts);
}
u64 LinuxNowNs()
{
    return NowNs();
}

// Additional wrappers exposed for the NT→Linux translator. The
// Do* primitives they call through are in the anonymous namespace
// above, so cross-TU access has to go through these. Keep them
// thin — arg marshalling (NTSTATUS → errno, FILE_HANDLE → fd,
// LARGE_INTEGER → timespec) stays in the translator.
i64 LinuxClose(u64 fd)
{
    return DoClose(fd);
}
i64 LinuxOpen(u64 user_path, u64 flags, u64 mode)
{
    return DoOpen(user_path, flags, mode);
}
i64 LinuxLseek(u64 fd, i64 offset, u64 whence)
{
    return DoLseek(fd, offset, whence);
}
i64 LinuxFstat(u64 fd, u64 user_buf)
{
    return DoFstat(fd, user_buf);
}
i64 LinuxFsync(u64 fd)
{
    return DoFsync(fd);
}
i64 LinuxNanosleep(u64 user_req, u64 user_rem)
{
    return DoNanosleep(user_req, user_rem);
}
i64 LinuxSchedYield()
{
    sched::SchedYield();
    return 0;
}
[[noreturn]] void LinuxExit(u64 status)
{
    DoExitGroup(status);
    // DoExitGroup calls sched::SchedExit which is [[noreturn]].
    for (;;)
    {
        asm volatile("hlt");
    }
}
i64 LinuxGetPid()
{
    return DoGetPid();
}
i64 LinuxMmap(u64 addr, u64 len, u64 prot, u64 flags, u64 fd, u64 off)
{
    return DoMmap(addr, len, prot, flags, fd, off);
}
i64 LinuxMunmap(u64 addr, u64 len)
{
    return DoMunmap(addr, len);
}
i64 LinuxMprotect(u64 addr, u64 len, u64 prot)
{
    return DoMprotect(addr, len, prot);
}

extern "C" void LinuxSyscallDispatch(arch::TrapFrame* frame)
{
    if constexpr (kTraceLinuxSyscallDispatch)
    {
        KLOG_TRACE_SCOPE("linux/syscall", "LinuxSyscallDispatch");
    }

    const u64 nr = frame->rax;
    const core::Process* proc = core::CurrentProcess();
    const u64 pid = (proc != nullptr) ? proc->pid : 0;
    core::CleanroomTraceRecord("syscall", "linux-dispatch", nr, pid, frame->rip);
    i64 rv = kENOSYS;
    switch (nr)
    {
    case kSysWrite:
        rv = DoWrite(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysRead:
        rv = DoRead(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysOpen:
        rv = DoOpen(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysClose:
        rv = DoClose(frame->rdi);
        break;
    case kSysStat:
        rv = DoStat(frame->rdi, frame->rsi);
        break;
    case kSysLstat:
        rv = DoLstat(frame->rdi, frame->rsi);
        break;
    case kSysFstat:
        rv = DoFstat(frame->rdi, frame->rsi);
        break;
    case kSysLseek:
        rv = DoLseek(frame->rdi, static_cast<i64>(frame->rsi), frame->rdx);
        break;
    case kSysRtSigaction:
        rv = DoRtSigaction(frame->rdi, frame->rsi, frame->rdx, frame->r10);
        break;
    case kSysRtSigprocmask:
        rv = DoRtSigprocmask(frame->rdi, frame->rsi, frame->rdx, frame->r10);
        break;
    case kSysIoctl:
        rv = DoIoctl(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysReadv:
        rv = DoReadv(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysWritev:
        rv = DoWritev(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysGetUid:
        rv = DoGetUid();
        break;
    case kSysGetGid:
        rv = DoGetGid();
        break;
    case kSysGetEuid:
        rv = DoGetEuid();
        break;
    case kSysGetEgid:
        rv = DoGetEgid();
        break;
    case kSysSetTidAddress:
        rv = DoSetTidAddress(frame->rdi);
        break;
    case kSysAccess:
        rv = DoAccess(frame->rdi, frame->rsi);
        break;
    case kSysReadlink:
        rv = DoReadlink(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysGetcwd:
        rv = DoGetcwd(frame->rdi, frame->rsi);
        break;
    case kSysFutex:
        rv = DoFutex(frame->rdi, frame->rsi, frame->rdx, frame->r10, frame->r8, frame->r9);
        break;
    case kSysGetRandom:
        rv = DoGetRandom(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysClockGetTime:
        rv = DoClockGetTime(frame->rdi, frame->rsi);
        break;
    case kSysGettimeofday:
        rv = DoGettimeofday(frame->rdi, frame->rsi);
        break;
    case kSysSysinfo:
        rv = DoSysinfo(frame->rdi);
        break;
    case kSysTime:
        rv = DoTime(frame->rdi);
        break;
    case kSysNanosleep:
        rv = DoNanosleep(frame->rdi, frame->rsi);
        break;
    case kSysMprotect:
        rv = DoMprotect(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysPread:
        rv = DoPread64(frame->rdi, frame->rsi, frame->rdx, static_cast<i64>(frame->r10));
        break;
    case kSysPwrite:
        rv = DoPwrite64(frame->rdi, frame->rsi, frame->rdx, static_cast<i64>(frame->r10));
        break;
    case kSysDup:
        rv = DoDup(frame->rdi);
        break;
    case kSysDup2:
        rv = DoDup2(frame->rdi, frame->rsi);
        break;
    case kSysFcntl:
        rv = DoFcntl(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysFsync:
        rv = DoFsync(frame->rdi);
        break;
    case kSysFdatasync:
        rv = DoFdatasync(frame->rdi);
        break;
    case kSysMadvise:
        rv = DoMadvise(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysGetrlimit:
        rv = DoGetrlimit(frame->rdi, frame->rsi);
        break;
    case kSysSetrlimit:
        rv = DoSetrlimit(frame->rdi, frame->rsi);
        break;
    case kSysPrlimit64:
        rv = DoPrlimit64(frame->rdi, frame->rsi, frame->rdx, frame->r10);
        break;
    case kSysChdir:
        rv = DoChdir(frame->rdi);
        break;
    case kSysFchdir:
        rv = DoFchdir(frame->rdi);
        break;
    case kSysRtSigreturn:
        rv = DoRtSigreturn();
        break;
    case kSysSigaltstack:
        rv = DoSigaltstack(frame->rdi, frame->rsi);
        break;
    case kSysSchedYield:
        rv = DoSchedYield();
        break;
    case kSysGetTid:
        rv = DoGetTid();
        break;
    case kSysTgkill:
        rv = DoTgkill(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysKill:
        rv = DoKill(frame->rdi, frame->rsi);
        break;
    case kSysGetPpid:
        rv = DoGetPpid();
        break;
    case kSysGetpgrp:
        rv = DoGetpgrp();
        break;
    case kSysGetPgid:
        rv = DoGetPgid(frame->rdi);
        break;
    case kSysGetSid:
        rv = DoGetSid(frame->rdi);
        break;
    case kSysSetPgid:
        rv = DoSetPgid(frame->rdi, frame->rsi);
        break;
    case kSysOpenat:
        rv = DoOpenat(static_cast<i64>(frame->rdi), frame->rsi, frame->rdx, frame->r10);
        break;
    case kSysNewFstatat:
        rv = DoNewFstatat(static_cast<i64>(frame->rdi), frame->rsi, frame->rdx, frame->r10);
        break;
    case kSysDup3:
        rv = DoDup3(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysGetrusage:
        rv = DoGetrusage(frame->rdi, frame->rsi);
        break;
    case kSysPoll:
        rv = DoPoll(frame->rdi, frame->rsi, static_cast<i64>(frame->rdx));
        break;
    case kSysSelect:
        rv = DoSelect(frame->rdi, frame->rsi, frame->rdx, frame->r10, frame->r8);
        break;
    case kSysGetdents64:
        rv = DoGetdents64(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysSetRobustList:
        rv = DoSetRobustList(frame->rdi, frame->rsi);
        break;
    case kSysGetRobustList:
        rv = DoGetRobustList(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysBrk:
        rv = DoBrk(frame->rdi);
        break;
    case kSysMmap:
        // Linux: addr, len, prot, flags, fd, offset — rdi..r9.
        rv = DoMmap(frame->rdi, frame->rsi, frame->rdx, frame->r10, frame->r8, frame->r9);
        break;
    case kSysMunmap:
        rv = DoMunmap(frame->rdi, frame->rsi);
        break;
    case kSysArchPrctl:
        rv = DoArchPrctl(frame->rdi, frame->rsi);
        break;
    case kSysUname:
        rv = DoUname(frame->rdi);
        break;
    case kSysExit:
        DoExit(frame->rdi);
        // Exit paths don't return; keep the compiler happy.
        rv = 0;
        break;
    case kSysExitGroup:
        DoExitGroup(frame->rdi);
        // Exit paths don't return; keep the compiler happy.
        rv = 0;
        break;
    case kSysGetPid:
        rv = DoGetPid();
        break;

    // Batch 55 dispatch — compat stubs + FAT32-backed FS ops.
    case kSysPause:
        rv = DoPause();
        break;
    case kSysMremap:
        rv = DoMremap(frame->rdi, frame->rsi, frame->rdx, frame->r10, frame->r8);
        break;
    case kSysMsync:
        rv = DoMsync(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysMincore:
        rv = DoMincore(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysFlock:
        rv = DoFlock(frame->rdi, frame->rsi);
        break;
    case kSysTruncate:
        rv = DoTruncate(frame->rdi, frame->rsi);
        break;
    case kSysFtruncate:
        rv = DoFtruncate(frame->rdi, frame->rsi);
        break;
    case kSysMkdir:
        rv = DoMkdir(frame->rdi, frame->rsi);
        break;
    case kSysRmdir:
        rv = DoRmdir(frame->rdi);
        break;
    case kSysUnlink:
        rv = DoUnlink(frame->rdi);
        break;
    case kSysChmod:
        rv = DoChmod(frame->rdi, frame->rsi);
        break;
    case kSysFchmod:
        rv = DoFchmod(frame->rdi, frame->rsi);
        break;
    case kSysChown:
        rv = DoChown(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysFchown:
        rv = DoFchown(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysLchown:
        rv = DoLchown(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysTimes:
        rv = DoTimes(frame->rdi);
        break;
    case kSysSetuid:
        rv = DoSetuid(frame->rdi);
        break;
    case kSysSetgid:
        rv = DoSetgid(frame->rdi);
        break;
    case kSysSetreuid:
        rv = DoSetreuid(frame->rdi, frame->rsi);
        break;
    case kSysSetregid:
        rv = DoSetregid(frame->rdi, frame->rsi);
        break;
    case kSysGetgroups:
        rv = DoGetgroups(frame->rdi, frame->rsi);
        break;
    case kSysSetgroups:
        rv = DoSetgroups(frame->rdi, frame->rsi);
        break;
    case kSysSetresuid:
        rv = DoSetresuid(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysGetresuid:
        rv = DoGetresuid(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysSetresgid:
        rv = DoSetresgid(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysGetresgid:
        rv = DoGetresgid(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysSetfsuid:
        rv = DoSetfsuid(frame->rdi);
        break;
    case kSysSetfsgid:
        rv = DoSetfsgid(frame->rdi);
        break;
    case kSysCapget:
        rv = DoCapget(frame->rdi, frame->rsi);
        break;
    case kSysCapset:
        rv = DoCapset(frame->rdi, frame->rsi);
        break;
    case kSysUtime:
        rv = DoUtime(frame->rdi, frame->rsi);
        break;
    case kSysMknod:
        rv = DoMknod(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysPersonality:
        rv = DoPersonality(frame->rdi);
        break;
    case kSysGetpriority:
        rv = DoGetpriority(frame->rdi, frame->rsi);
        break;
    case kSysSetpriority:
        rv = DoSetpriority(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysMlock:
        rv = DoMlock(frame->rdi, frame->rsi);
        break;
    case kSysMunlock:
        rv = DoMunlock(frame->rdi, frame->rsi);
        break;
    case kSysMlockall:
        rv = DoMlockall(frame->rdi);
        break;
    case kSysMunlockall:
        rv = DoMunlockall();
        break;

    // Batch 56 dispatch.
    case kSysPtrace:
        rv = DoPtrace(frame->rdi, frame->rsi, frame->rdx, frame->r10);
        break;
    case kSysSyslog:
        rv = DoSyslog(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysSetsid:
        rv = DoSetsid();
        break;
    case kSysVhangup:
        rv = DoVhangup();
        break;
    case kSysAcct:
        rv = DoAcct(frame->rdi);
        break;
    case kSysMount:
        rv = DoMount(frame->rdi, frame->rsi, frame->rdx, frame->r10, frame->r8);
        break;
    case kSysUmount2:
        rv = DoUmount2(frame->rdi, frame->rsi);
        break;
    case kSysSync:
        rv = DoSync();
        break;
    case kSysSyncfs:
        rv = DoSyncfs(frame->rdi);
        break;
    case kSysRename:
        rv = DoRename(frame->rdi, frame->rsi);
        break;
    case kSysLink:
        rv = DoLink(frame->rdi, frame->rsi);
        break;
    case kSysSymlink:
        rv = DoSymlink(frame->rdi, frame->rsi);
        break;
    case kSysSetThreadArea:
        rv = DoSetThreadArea(frame->rdi);
        break;
    case kSysGetThreadArea:
        rv = DoGetThreadArea(frame->rdi);
        break;
    case kSysIoprioGet:
        rv = DoIoprioGet(frame->rdi, frame->rsi);
        break;
    case kSysIoprioSet:
        rv = DoIoprioSet(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysSchedSetaffinity:
        rv = DoSchedSetaffinity(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysSchedGetaffinity:
        rv = DoSchedGetaffinity(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysSchedGetscheduler:
        rv = DoSchedGetscheduler(frame->rdi);
        break;
    case kSysSchedSetscheduler:
        rv = DoSchedSetscheduler(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysSchedGetparam:
        rv = DoSchedGetparam(frame->rdi, frame->rsi);
        break;
    case kSysSchedSetparam:
        rv = DoSchedSetparam(frame->rdi, frame->rsi);
        break;
    case kSysSchedGetPriorityMax:
        rv = DoSchedGetPriorityMax(frame->rdi);
        break;
    case kSysSchedGetPriorityMin:
        rv = DoSchedGetPriorityMin(frame->rdi);
        break;
    case kSysSchedRrGetInterval:
        rv = DoSchedRrGetInterval(frame->rdi, frame->rsi);
        break;
    case kSysClockGetres:
        rv = DoClockGetres(frame->rdi, frame->rsi);
        break;
    case kSysClockNanosleep:
        rv = DoClockNanosleep(frame->rdi, frame->rsi, frame->rdx, frame->r10);
        break;
    case kSysGetcpu:
        rv = DoGetcpu(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysMkdirat:
        rv = DoMkdirat(static_cast<i64>(frame->rdi), frame->rsi, frame->rdx);
        break;
    case kSysUnlinkat:
        rv = DoUnlinkat(static_cast<i64>(frame->rdi), frame->rsi, frame->rdx);
        break;
    case kSysLinkat:
        rv = DoLinkat(static_cast<i64>(frame->rdi), frame->rsi, static_cast<i64>(frame->rdx), frame->r10, frame->r8);
        break;
    case kSysSymlinkat:
        rv = DoSymlinkat(frame->rdi, static_cast<i64>(frame->rsi), frame->rdx);
        break;
    case kSysRenameat:
        rv = DoRenameat(static_cast<i64>(frame->rdi), frame->rsi, static_cast<i64>(frame->rdx), frame->r10);
        break;
    case kSysRenameat2:
        rv = DoRenameat2(static_cast<i64>(frame->rdi), frame->rsi, static_cast<i64>(frame->rdx), frame->r10, frame->r8);
        break;
    case kSysFchownat:
        rv = DoFchownat(static_cast<i64>(frame->rdi), frame->rsi, frame->rdx, frame->r10, frame->r8);
        break;
    case kSysFutimesat:
        rv = DoFutimesat(static_cast<i64>(frame->rdi), frame->rsi, frame->rdx);
        break;
    case kSysFchmodat:
        rv = DoFchmodat(static_cast<i64>(frame->rdi), frame->rsi, frame->rdx, frame->r10);
        break;
    case kSysFaccessat:
        rv = DoFaccessat(static_cast<i64>(frame->rdi), frame->rsi, frame->rdx, frame->r10);
        break;
    case kSysFaccessat2:
        rv = DoFaccessat2(static_cast<i64>(frame->rdi), frame->rsi, frame->rdx, frame->r10);
        break;
    case kSysUtimensat:
        rv = DoUtimensat(static_cast<i64>(frame->rdi), frame->rsi, frame->rdx, frame->r10);
        break;

    // Batch 67 — common stubs.
    case kSysPipe:
        rv = DoPipe(frame->rdi);
        break;
    case kSysPipe2:
        rv = DoPipe2(frame->rdi, frame->rsi);
        break;
    case kSysWait4:
        rv = DoWait4(frame->rdi, frame->rsi, frame->rdx, frame->r10);
        break;
    case kSysWaitid:
        rv = DoWaitid(frame->rdi, frame->rsi, frame->rdx, frame->r10, frame->r8);
        break;
    case kSysRtSigpending:
        rv = DoRtSigpending(frame->rdi, frame->rsi);
        break;
    case kSysRtSigsuspend:
        rv = DoRtSigsuspend(frame->rdi, frame->rsi);
        break;
    case kSysRtSigtimedwait:
        rv = DoRtSigtimedwait(frame->rdi, frame->rsi, frame->rdx, frame->r10);
        break;
    case kSysPpoll:
        rv = DoPpoll(frame->rdi, frame->rsi, frame->rdx, frame->r10, frame->r8);
        break;
    case kSysPselect6:
        rv = DoPselect6(frame->rdi, frame->rsi, frame->rdx, frame->r10, frame->r8, frame->r9);
        break;
    case kSysEventfd:
    case kSysEventfd2:
        rv = DoEventfd(frame->rdi, frame->rsi);
        break;
    case kSysTimerfdCreate:
        rv = DoTimerfdCreate(frame->rdi, frame->rsi);
        break;
    case kSysTimerfdSettime:
        rv = DoTimerfdSettime(frame->rdi, frame->rsi, frame->rdx, frame->r10);
        break;
    case kSysTimerfdGettime:
        rv = DoTimerfdGettime(frame->rdi, frame->rsi);
        break;
    case kSysSignalfd:
    case kSysSignalfd4:
        rv = DoSignalfd(frame->rdi, frame->rsi, frame->rdx, frame->r10);
        break;
    case kSysFadvise64:
        rv = DoFadvise64(frame->rdi, frame->rsi, frame->rdx, frame->r10);
        break;
    case kSysReadahead:
        rv = DoReadahead(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysEpollCreate:
        rv = DoEpollCreate(frame->rdi);
        break;
    case kSysEpollCreate1:
        rv = DoEpollCreate1(frame->rdi);
        break;
    case kSysEpollCtl:
        rv = DoEpollCtl(frame->rdi, frame->rsi, frame->rdx, frame->r10);
        break;
    case kSysEpollWait:
        rv = DoEpollWait(frame->rdi, frame->rsi, frame->rdx, frame->r10);
        break;
    case kSysEpollPwait:
        rv = DoEpollPwait(frame->rdi, frame->rsi, frame->rdx, frame->r10, frame->r8, frame->r9);
        break;
    case kSysInotifyInit:
        rv = DoInotifyInit();
        break;
    case kSysInotifyInit1:
        rv = DoInotifyInit1(frame->rdi);
        break;
    case kSysPrctl:
        rv = DoPrctl(frame->rdi, frame->rsi, frame->rdx, frame->r10, frame->r8);
        break;

    // Batch 68 — BSD-socket family. No userland socket layer;
    // socket() returns -ENETDOWN, others -EBADF (no fd to act on).
    case kSysSocket:
    case kSysSocketpair:
        rv = -100; // -ENETDOWN
        break;
    case kSysAccept:
    case kSysAccept4:
    case kSysConnect:
    case kSysBind:
    case kSysListen:
    case kSysShutdown:
    case kSysGetsockname:
    case kSysGetpeername:
    case kSysSetsockopt:
    case kSysGetsockopt:
    case kSysSendto:
    case kSysRecvfrom:
    case kSysSendmsg:
    case kSysRecvmsg:
    case kSysSendmmsg:
    case kSysRecvmmsg:
        rv = kEBADF;
        break;

    // Batch 69 — process control. Linux fork/vfork/clone +
    // execve don't have a v0 implementation; return -ENOSYS.
    case kSysClone:
    case kSysFork:
    case kSysVfork:
        rv = kENOSYS;
        break;
    case kSysExecve:
    case kSysExecveat:
        rv = kENOSYS;
        break;
    case kSysChroot:
    case kSysPivotRoot:
        rv = kEPERM;
        break;
    case kSysUmask:
        // Most v0 callers want the "old umask" return — Linux
        // contract is "always returns the previous value, never
        // -1". Default umask is 022, which matches what musl's
        // CRT expects on a fresh system.
        rv = 022;
        break;
    // SysV IPC + POSIX MQ — no IPC engine.
    case kSysShmget:
    case kSysShmat:
    case kSysShmctl:
    case kSysShmdt:
    case kSysSemget:
    case kSysSemop:
    case kSysSemctl:
    case kSysSemtimedop:
    case kSysMsgget:
    case kSysMsgsnd:
    case kSysMsgrcv:
    case kSysMsgctl:
    case kSysMqOpen:
    case kSysMqUnlink:
    case kSysMqTimedsend:
    case kSysMqTimedreceive:
    case kSysMqNotify:
    case kSysMqGetsetattr:
        rv = kENOSYS;
        break;
    case kSysInotifyAddWatch:
    case kSysInotifyRmWatch:
        rv = kENOSYS;
        break;
    // libaio — no async-I/O engine.
    case kSysIoSetup:
    case kSysIoDestroy:
    case kSysIoGetevents:
    case kSysIoSubmit:
    case kSysIoCancel:
        rv = kENOSYS;
        break;
    // System-mutation calls — refuse so a misbehaving program
    // can't reboot the box or twiddle privileged knobs from
    // ring-3 Linux ABI. Reboot has its own native path.
    case kSysSwapon:
    case kSysSwapoff:
    case kSysReboot:
    case kSysSethostname:
    case kSysSetdomainname:
    case kSysIopl:
    case kSysIoperm:
    case kSysQuotactl:
        rv = kEPERM;
        break;

    default:
    {
        // Primary dispatch missed — offer to the translation unit
        // before surfacing -ENOSYS. When the TU fills the gap it
        // logs the specific translation; when it doesn't, it
        // logs the miss + we fall through to ENOSYS behaviour.
        const auto t = translation::LinuxGapFill(frame);
        if (t.handled)
        {
            rv = t.rv;
        }
        // If the TU didn't handle it, rv is still the kENOSYS
        // default from above, and the TU already logged the
        // gap. No further log here — keeps the boot log clean
        // while still being able to grep "[translate] ...
        // unimplemented" for the full missing-syscall set.
        break;
    }
    }
    frame->rax = static_cast<u64>(rv);
}

void SyscallInit()
{
    using arch::SerialWrite;
    KLOG_TRACE_SCOPE("linux/syscall", "SyscallInit");

    // MSR_STAR: high 32 bits control CS/SS selectors.
    //   bits 47..32: SYSCALL target — kernel CS = 0x08 (GDT entry 1).
    //                The CPU also auto-loads SS = CS+8 = 0x10.
    //   bits 63..48: SYSRET target — user CS = 0x1B (GDT entry 3
    //                with RPL=3). The CPU loads SS = CS+8 = 0x23.
    //                NB: per spec, sysret adds 16 to the high-16
    //                selector value to get the 64-bit CS. We write
    //                0x10 here so the CPU derives 0x10+16=0x1B with
    //                RPL=3 for ring-3 return; SS = 0x10+8=0x18 with
    //                RPL=3 → 0x1B|0x3... actually the spec wants
    //                the base value (user CS - 16) which is 0x10.
    // Concrete layout: STAR[63:48]=0x10 (user base), STAR[47:32]=0x08.
    const u64 star = (u64(0x10) << 48) | (u64(0x08) << 32);
    WriteMsr(kMsrStar, star);

    // LSTAR: the RIP the CPU jumps to on `syscall` from 64-bit mode.
    const u64 lstar = reinterpret_cast<u64>(&linux_syscall_entry);
    WriteMsr(kMsrLstar, lstar);

    // SFMASK: RFLAGS bits cleared at syscall entry. Clear IF (bit 9)
    // so the entry stub runs with interrupts disabled, DF (bit 10)
    // for SysV ABI "direction flag = 0", and TF (bit 8) so a stray
    // trace flag from user mode doesn't single-step the kernel.
    const u64 sfmask = (1u << 9) | (1u << 10) | (1u << 8);
    WriteMsr(kMsrSfmask, sfmask);

    // KERNEL_GS_BASE: what `swapgs` will install into GS_BASE on
    // entry. Point it at this CPU's PerCpu struct so the entry
    // stub's `gs:[kPerCpuKernelRsp]` reads the right thing.
    //
    // On SMP, every AP will write its own PerCpu address at bring-
    // up. v0 is BSP-only.
    const u64 percpu_addr = reinterpret_cast<u64>(cpu::CurrentCpu());
    WriteMsr(kMsrKernelGsBase, percpu_addr);

    SerialWrite("[linux] syscall MSRs programmed (entry@");
    arch::SerialWriteHex(lstar);
    SerialWrite(", kernel_gs@");
    arch::SerialWriteHex(percpu_addr);
    SerialWrite(")\n");
}

void LinuxLogAbiCoverage()
{
    // Re-walk the generated table at boot so a future refactor that
    // renames a Do* handler out of classifier reach is visible in the
    // boot log (count drops). The generated header also bakes compile-
    // time primary/effective counts so drift is obvious at boot.
    u32 primary = 0;
    u32 effective = 0;
    for (u32 i = 0; i < kLinuxSyscallCount; ++i)
    {
        if (kLinuxSyscalls[i].state == HandlerState::Implemented)
        {
            ++primary;
        }
    }
    effective = kLinuxSyscallHandlersImplementedEffective;

    arch::SerialWrite("[linux] ABI coverage: ");
    arch::SerialWrite("primary=");
    arch::SerialWriteHex(primary);
    arch::SerialWrite(" / ");
    arch::SerialWriteHex(kLinuxSyscallCount);
    arch::SerialWrite(", effective=");
    arch::SerialWriteHex(effective);
    arch::SerialWrite(" / ");
    arch::SerialWriteHex(kLinuxSyscallCount);
    arch::SerialWrite(" (generated primary=");
    arch::SerialWriteHex(kLinuxSyscallHandlersImplementedPrimary);
    arch::SerialWrite(", generated effective=");
    arch::SerialWriteHex(kLinuxSyscallHandlersImplementedEffective);
    arch::SerialWrite(")\n");
}

} // namespace duetos::subsystems::linux
