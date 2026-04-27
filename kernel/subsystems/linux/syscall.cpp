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
 * FILE LAYOUT
 *   The handler implementations themselves live in per-domain
 *   sibling translation units (syscall_<area>.cpp), each defining
 *   its handlers in the duetos::subsystems::linux::internal
 *   namespace. The list (cred, fd, file, fs_mut, io, misc, mm,
 *   path, pathutil, proc, rlimit, sched, sig, stub, time) +
 *   their decls live in syscall_internal.h.
 *
 *   This TU keeps:
 *     - the syscall-number enum (kSys*) — the ABI-stable inputs
 *       to the dispatch switch;
 *     - the LinuxSyscallDispatch switch itself;
 *     - SyscallInit + the MSR / SFMASK / KERNEL_GS_BASE wiring;
 *     - LinuxLogAbiCoverage (boot-time coverage scoreboard);
 *     - thin Linux* public wrappers exposed to the NT→Linux
 *       translator and to other kernel callers.
 *
 *   `using namespace internal;` at the top hoists every Do*
 *   handler back into this TU's outer namespace so the dispatch
 *   switch keeps reading like the in-TU layout the file used
 *   to have.
 */

#include "subsystems/linux/syscall.h"

#include "subsystems/linux/linux_syscall_table_generated.h"
#include "subsystems/linux/syscall_internal.h"

#include "arch/x86_64/hpet.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/timer.h"
#include "arch/x86_64/traps.h"
#include "diag/kdbg.h"
#include "log/klog.h"
#include "diag/cleanroom_trace.h"
#include "diag/log_names.h"
#include "proc/process.h"
#include "util/random.h"
#include "cpu/percpu.h"
#include "fs/fat32.h"
#include "mm/address_space.h"
#include "mm/frame_allocator.h"
#include "mm/page.h"
#include "mm/paging.h"
#include "sched/sched.h"
#include "subsystems/translation/translate.h"

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
// kMsrFsBase moved with DoArchPrctl into syscall_misc.cpp.
constexpr u32 kMsrSfmask = 0xC0000084;       // RFLAGS mask applied at entry
constexpr u32 kMsrKernelGsBase = 0xC0000102; // swapgs source for kernel GS

// Linux errno constants live in syscall_internal.h so sibling
// translation units (syscall_cred.cpp, etc.) can return them
// without redeclaring. The `using namespace internal;` directive
// above makes them visible here without qualification.

// Linux mmap flag bits (kMapPrivate / kMapAnonymous) moved with
// DoMmap into syscall_mm.cpp.

// kLinuxIoMax (per-call read/write byte cap) moved with DoRead /
// DoWrite into syscall_io.cpp.

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
    kSysClone3 = 435,
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

// kAtFdCwd / kAtRemoveDir constants moved to syscall_internal.h
// alongside the StripFatPrefix / CopyAndStripFatPath / AtFdCwdOnly
// declarations they pair with.

// All Do* handler bodies live in per-domain sibling TUs; see
// syscall_internal.h for the full duetos::subsystems::linux::internal
// roster. The dispatch switch below calls them unqualified via the
// `using namespace internal;` directive at the top of this TU.

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
        rv = DoEventfd(frame->rdi);
        break;
    case kSysEventfd2:
        rv = DoEventfd2(frame->rdi, frame->rsi);
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

    // Batch 68 — BSD-socket family. Two-stage gate:
    //
    //   1. kCapNet check first. A sandboxed process WITHOUT the
    //      cap gets -EACCES — the same shape Linux returns when
    //      a SECCOMP filter or LSM denies the call. Distinguishable
    //      from the "no socket layer" code below, which the call
    //      WITH the cap would see, so test code can tell "denied
    //      by sandbox" from "stack offline".
    //   2. With the cap, fall through to the "no userland socket
    //      layer yet" path: socket()/socketpair() report -ENETDOWN
    //      so callers fall back gracefully; the rest of the family
    //      reports -EBADF (the fd they were handed never existed).
    case kSysSocket:
    case kSysSocketpair:
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
    {
        // Reuse the outer-dispatch `proc`; the cap check needs no
        // mutation, just CapSetHas. Avoids shadowing the const
        // proc declared at the top of LinuxSyscallDispatch.
        if (proc == nullptr || !duetos::core::CapSetHas(proc->caps, duetos::core::kCapNet))
        {
            duetos::core::RecordSandboxDenial(duetos::core::kCapNet);
            if (proc != nullptr && duetos::core::ShouldLogDenial(proc->sandbox_denials))
            {
                arch::SerialWrite("[linux] denied socket-family pid=");
                arch::SerialWriteHex(pid);
                arch::SerialWrite(" syscall=");
                arch::SerialWriteHex(nr);
                arch::SerialWrite(" cap=Net denial_idx=");
                arch::SerialWriteHex(proc->sandbox_denials);
                arch::SerialWrite("\n");
            }
            rv = kEACCES;
            break;
        }
        if (nr == kSysSocket || nr == kSysSocketpair)
        {
            rv = -100; // -ENETDOWN — stack not online
        }
        else
        {
            rv = kEBADF; // no socket fd ever issued
        }
        break;
    }

    // Batch 69 — process control. v0 implements CLONE_THREAD
    // same-AS thread create only; full fork (CLONE_THREAD clear)
    // and execve stay -ENOSYS pending §11.10 follow-ups.
    case kSysClone:
        rv = DoClone(frame->rdi, frame->rsi, frame->rdx, frame->r10, frame->r8);
        break;
    case kSysFork:
    case kSysVfork:
        rv = kENOSYS;
        break;
    case kSysClone3:
    {
        // clone3 packs the equivalent of clone()'s positional
        // args into a struct clone_args read out of user memory.
        // v0 honours the same CLONE_THREAD subset DoClone does,
        // by reading only the prefix of the struct that contains
        // the fields we care about (flags / pidfd / child_tid /
        // parent_tid / exit_signal / stack / stack_size / tls).
        struct CloneArgsPrefix
        {
            u64 flags;
            u64 pidfd;
            u64 child_tid;
            u64 parent_tid;
            u64 exit_signal;
            u64 stack;
            u64 stack_size;
            u64 tls;
        } args = {};
        const u64 user_args = frame->rdi;
        const u64 size = frame->rsi;
        // Read at most sizeof(prefix) bytes; tolerate older
        // callers that pass a smaller struct.
        u64 to_copy = sizeof(args);
        if (size < to_copy)
            to_copy = size;
        if (!mm::CopyFromUser(&args, reinterpret_cast<const void*>(user_args), to_copy))
        {
            rv = kEFAULT;
            break;
        }
        // clone3 stack is `stack` + `stack_size` (caller hands
        // us the BASE; the kernel computes the top). DoClone's
        // child_stack arg expects a top-of-stack pointer.
        const u64 stack_top = args.stack + args.stack_size;
        rv = DoClone(args.flags, stack_top, args.parent_tid, args.child_tid, args.tls);
        break;
    }
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
