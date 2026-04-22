#include "translate.h"

#include "../../arch/x86_64/serial.h"
#include "../../arch/x86_64/traps.h"
#include "../../core/klog.h"
#include "../../core/process.h"
#include "../../mm/paging.h"
#include "../linux/syscall.h"
#include "../win32/heap.h"

namespace customos::subsystems::translation
{

namespace
{

// Subset of errno we hand back. Match Linux's values so callers
// see consistent numbers regardless of which path they came in
// through.
constexpr i64 kEFAULT = -14;
constexpr i64 kEINVAL = -22;

// Linux syscall numbers we recognise here. Keep in sync with the
// primary dispatcher's enum — this is a PEER table for syscalls
// the primary doesn't handle, so overlap is fine but silent
// redundancy is waste.
enum : u64
{
    kSysPipe = 22,
    kSysReadv = 19,
    kSysMadvise = 28,
    kSysSocket = 41,
    kSysFsync = 74,
    kSysFdatasync = 75,
    kSysUmask = 95,
    kSysGettimeofday = 96,
    kSysGetrlimit = 97,
    kSysSysinfo = 99,
    kSysGetpgrp = 111,
    kSysStatfs = 137,
    kSysFstatfs = 138,
    kSysSetrlimit = 160,
    kSysPipe2 = 293,
    kSysPrlimit64 = 302,
    kSysRseq = 334,
};

// Per-direction hit counters. Bucketed on syscall_nr & 0x3FF so
// both dispatch tables fit (Linux ~0..400, native 0..30). Simple
// static table — no dynamic growth needed at this scale.
constinit HitTable g_linux_hits = {};
constinit HitTable g_native_hits = {};

void BumpHits(HitTable& t, u64 nr)
{
    if (t.buckets[nr & 0x3FF] != 0xFFFFFFFFu)
    {
        ++t.buckets[nr & 0x3FF];
    }
}

// Log prefix so boot-log grep is easy.
void LogTranslation(const char* origin, u64 nr, const char* target)
{
    arch::SerialWrite("[translate] ");
    arch::SerialWrite(origin);
    arch::SerialWrite("/");
    arch::SerialWriteHex(nr);
    arch::SerialWrite(" -> ");
    arch::SerialWrite(target);
    arch::SerialWrite("\n");
}

// Linux syscall-number-to-name table. Covers:
//   - everything the primary dispatcher implements (so a regression
//     that accidentally routes a known call through the miss path
//     still prints a recognisable name),
//   - everything the TU implements,
//   - a curated set of common-but-unimplemented calls a real Linux
//     binary is likely to hit (openat, getdents64, clone, epoll_*,
//     poll/select, fork/execve/wait4, etc.).
// Entries are sorted by nr for linear-scan legibility but the lookup
// is O(n). Table currently ~80 entries — dwarfed by the serial cost
// of actually emitting the miss line, so speed is not the concern.
struct LinuxSysName
{
    u64 nr;
    const char* name;
};
constexpr LinuxSysName kLinuxNames[] = {
    {0, "read"},
    {1, "write"},
    {2, "open"},
    {3, "close"},
    {4, "stat"},
    {5, "fstat"},
    {6, "lstat"},
    {7, "poll"},
    {8, "lseek"},
    {9, "mmap"},
    {10, "mprotect"},
    {11, "munmap"},
    {12, "brk"},
    {13, "rt_sigaction"},
    {14, "rt_sigprocmask"},
    {15, "rt_sigreturn"},
    {16, "ioctl"},
    {17, "pread64"},
    {18, "pwrite64"},
    {19, "readv"},
    {20, "writev"},
    {21, "access"},
    {22, "pipe"},
    {23, "select"},
    {24, "sched_yield"},
    {25, "mremap"},
    {28, "madvise"},
    {32, "dup"},
    {33, "dup2"},
    {35, "nanosleep"},
    {39, "getpid"},
    {41, "socket"},
    {56, "clone"},
    {57, "fork"},
    {58, "vfork"},
    {59, "execve"},
    {60, "exit"},
    {61, "wait4"},
    {62, "kill"},
    {63, "uname"},
    {72, "fcntl"},
    {74, "fsync"},
    {75, "fdatasync"},
    {78, "getdents"},
    {79, "getcwd"},
    {80, "chdir"},
    {81, "fchdir"},
    {82, "rename"},
    {83, "mkdir"},
    {84, "rmdir"},
    {87, "unlink"},
    {89, "readlink"},
    {90, "chmod"},
    {95, "umask"},
    {96, "gettimeofday"},
    {97, "getrlimit"},
    {99, "sysinfo"},
    {102, "getuid"},
    {104, "getgid"},
    {107, "geteuid"},
    {108, "getegid"},
    {109, "setpgid"},
    {110, "getppid"},
    {111, "getpgrp"},
    {121, "getpgid"},
    {124, "getsid"},
    {131, "sigaltstack"},
    {137, "statfs"},
    {138, "fstatfs"},
    {158, "arch_prctl"},
    {160, "setrlimit"},
    {186, "gettid"},
    {201, "time"},
    {202, "futex"},
    {217, "getdents64"},
    {218, "set_tid_address"},
    {228, "clock_gettime"},
    {231, "exit_group"},
    {232, "epoll_wait"},
    {233, "epoll_ctl"},
    {234, "tgkill"},
    {257, "openat"},
    {262, "newfstatat"},
    {263, "unlinkat"},
    {269, "faccessat"},
    {281, "epoll_pwait"},
    {291, "epoll_create1"},
    {293, "pipe2"},
    {302, "prlimit64"},
    {318, "getrandom"},
    {334, "rseq"},
    {435, "clone3"},
    {439, "faccessat2"},
};

struct NativeSysName
{
    u64 nr;
    const char* name;
};
constexpr NativeSysName kNativeNames[] = {
    {0, "SYS_EXIT"},
    {1, "SYS_GETPID"},
    {2, "SYS_WRITE"},
    {3, "SYS_YIELD"},
    {4, "SYS_STAT"},
    {5, "SYS_READ"},
    {6, "SYS_DROPCAPS"},
    {7, "SYS_SPAWN"},
    {8, "SYS_GETPROCID"},
    {9, "SYS_GETLASTERROR"},
    {10, "SYS_SETLASTERROR"},
    {11, "SYS_HEAP_ALLOC"},
    {12, "SYS_HEAP_FREE"},
    {13, "SYS_PERF_COUNTER"},
    {14, "SYS_HEAP_SIZE"},
    {15, "SYS_HEAP_REALLOC"},
    {16, "SYS_WIN32_MISS_LOG"},
    {0x200, "NativeClockNs"},
    {0x201, "NativeGetRandom"},
    {0x210, "NativeWin32Alloc"},
    {0x211, "NativeWin32Free"},
};

const char* LinuxName(u64 nr)
{
    for (const auto& e : kLinuxNames)
    {
        if (e.nr == nr)
            return e.name;
    }
    return nullptr;
}
const char* NativeName(u64 nr)
{
    for (const auto& e : kNativeNames)
    {
        if (e.nr == nr)
            return e.name;
    }
    return nullptr;
}

// Miss log — rich single-line record so one `grep '[<origin>-miss]'`
// tells you the number, name (when known), caller RIP, and all six
// syscall-ABI arg registers. Arg interpretation varies per syscall,
// but having the raw values in the log is usually enough to figure
// out what the user program was trying to do (e.g. seeing rdi=0x3,
// rsi=<ptr>, rdx=0x200 on an `openat` miss tells you fd=3, some
// path pointer, flags=O_RDWR|O_CLOEXEC).
//
// Linux ABI: rax=nr, args in rdi, rsi, rdx, r10, r8, r9.
// Native ABI (int 0x80): rax=nr, args in rdi, rsi, rdx.
void LogMiss(const char* origin, arch::TrapFrame* f, const char* name)
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    SerialWrite("[");
    SerialWrite(origin);
    SerialWrite("-miss] nr=");
    SerialWriteHex(f->rax);
    SerialWrite(" name=\"");
    SerialWrite(name ? name : "<unknown>");
    SerialWrite("\" rip=");
    SerialWriteHex(f->rip);
    SerialWrite(" args=[");
    SerialWriteHex(f->rdi);
    SerialWrite(",");
    SerialWriteHex(f->rsi);
    SerialWrite(",");
    SerialWriteHex(f->rdx);
    SerialWrite(",");
    SerialWriteHex(f->r10);
    SerialWrite(",");
    SerialWriteHex(f->r8);
    SerialWrite(",");
    SerialWriteHex(f->r9);
    SerialWrite("]\n");
}

// readv(fd, iov, iovcnt) — the same shape as writev. The primary
// Linux dispatcher has writev but never shipped readv; synthesise
// by iterating iovecs and calling LinuxRead per entry.
i64 TranslateReadv(arch::TrapFrame* f)
{
    const u64 fd = f->rdi;
    const u64 iov_ptr = f->rsi;
    const u64 iovcnt = f->rdx;
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
        if (!mm::CopyFromUser(&iov, reinterpret_cast<const void*>(iov_ptr + i * 16), sizeof(iov)))
        {
            return total > 0 ? total : kEFAULT;
        }
        if (iov.len == 0)
            continue;
        const i64 n = linux::LinuxRead(fd, iov.base, iov.len);
        if (n < 0)
            return total > 0 ? total : n;
        total += n;
        if (static_cast<u64>(n) < iov.len)
            break;
    }
    return total;
}

// gettimeofday(tv, tz) — older than clock_gettime but still used
// by legacy libc paths and autotools-style probes. Synthesize
// from LinuxNowNs(); ignore the timezone argument (modern
// kernels do the same — tz is always NULL in practice).
i64 TranslateGettimeofday(arch::TrapFrame* f)
{
    const u64 user_tv = f->rdi;
    (void)f->rsi; // tz is obsolete per Linux uapi comments
    if (user_tv == 0)
        return 0; // caller wants nothing
    const u64 ns = linux::LinuxNowNs();
    struct
    {
        i64 tv_sec;
        i64 tv_usec;
    } tv;
    tv.tv_sec = static_cast<i64>(ns / 1'000'000'000ull);
    tv.tv_usec = static_cast<i64>((ns / 1000ull) % 1'000'000ull);
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_tv), &tv, sizeof(tv)))
        return kEFAULT;
    return 0;
}

// sysinfo(info) — uptime + memory stats + load averages. v0
// fills a zeroed struct (52 bytes on x86_64 with padding) with
// the one field we can fake meaningfully: uptime. musl uses
// this mostly for uptime + totalram in diagnostic paths.
i64 TranslateSysinfo(arch::TrapFrame* f)
{
    const u64 user_info = f->rdi;
    if (user_info == 0)
        return kEFAULT;
    struct Info
    {
        i64 uptime;   // seconds since boot
        u64 loads[3]; // 1/5/15 min load averages (all 0)
        u64 totalram;
        u64 freeram;
        u64 sharedram;
        u64 bufferram;
        u64 totalswap;
        u64 freeswap;
        u16 procs;
        u16 _pad;
        u64 totalhigh;
        u64 freehigh;
        u32 mem_unit;
        u8 _pad2[4];
    };
    Info info;
    for (u64 i = 0; i < sizeof(info); ++i)
        reinterpret_cast<u8*>(&info)[i] = 0;
    info.uptime = static_cast<i64>(linux::LinuxNowNs() / 1'000'000'000ull);
    info.procs = 1;
    info.mem_unit = 1;
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_info), &info, sizeof(info)))
        return kEFAULT;
    return 0;
}

// prlimit64(pid, resource, new, old) — resource limit query.
// v0 returns infinite limits ({RLIM64_INFINITY, RLIM64_INFINITY})
// for old if non-null, no-ops new if non-null. Fine for anything
// that only consults the getter.
i64 TranslatePrlimit64(arch::TrapFrame* f)
{
    (void)f->rdi; // pid; always current-process in v0
    (void)f->rsi; // resource id; treated uniformly
    const u64 user_old = f->r10;
    if (user_old != 0)
    {
        constexpr u64 kRlimInfinity = 0xFFFFFFFFFFFFFFFFull;
        struct
        {
            u64 cur;
            u64 max;
        } old{kRlimInfinity, kRlimInfinity};
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_old), &old, sizeof(old)))
            return kEFAULT;
    }
    // new limits ignored.
    return 0;
}

// Plain-accept no-ops. Their common pattern is "the kernel should
// do something but v0 doesn't need to — return success so the
// caller keeps going." fsync / fdatasync: we don't buffer writes,
// so they're always durable. madvise: hints are advisory.
i64 TranslateNoOp(arch::TrapFrame* /*f*/)
{
    return 0;
}

// umask(mask) — returns the OLD umask. Linux-standard default is
// 022. We have no permission model so nothing actually enforces
// it; the value is purely for compat with programs that track +
// restore the process's umask during setup.
i64 TranslateUmask(arch::TrapFrame* /*f*/)
{
    return 022;
}

// getpgrp() — process group id of the calling process. v0 has no
// job-control model; return 0 (same as getpgid(0)).
i64 TranslateGetpgrp(arch::TrapFrame* /*f*/)
{
    return 0;
}

// getrlimit(resource, rlimit*) / setrlimit(resource, rlimit*) —
// older shape than prlimit64. We use the same "infinite limits"
// story for both: reads return RLIM_INFINITY, writes accepted
// but ignored.
i64 TranslateGetrlimit(arch::TrapFrame* f)
{
    (void)f->rdi;
    const u64 user_old = f->rsi;
    if (user_old == 0)
        return kEFAULT;
    constexpr u64 kRlimInfinity = 0xFFFFFFFFFFFFFFFFull;
    struct
    {
        u64 cur;
        u64 max;
    } old{kRlimInfinity, kRlimInfinity};
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_old), &old, sizeof(old)))
        return kEFAULT;
    return 0;
}

i64 TranslateSetrlimit(arch::TrapFrame* /*f*/)
{
    // Accept + no-op. Writing rlim values against our no-limits
    // model would be storage-only; skip until a consumer reads
    // back its own set value.
    return 0;
}

// statfs(path, buf) / fstatfs(fd, buf) — filesystem statistics.
// Fill a zeroed struct statfs with sensible-looking FAT32 totals
// (we don't track exact block counts per-mount) so musl's `df`
// / "is enough space available" probes don't choke.
i64 TranslateStatfs(arch::TrapFrame* f)
{
    const u64 user_buf = f->rsi;
    if (user_buf == 0)
        return kEFAULT;
    struct Statfs
    {
        i64 f_type;
        i64 f_bsize;
        u64 f_blocks;
        u64 f_bfree;
        u64 f_bavail;
        u64 f_files;
        u64 f_ffree;
        u64 f_fsid[2];
        i64 f_namelen;
        i64 f_frsize;
        i64 f_flags;
        i64 f_spare[4];
    };
    Statfs s;
    for (u64 i = 0; i < sizeof(s); ++i)
        reinterpret_cast<u8*>(&s)[i] = 0;
    s.f_type = 0x4d44;   // "MD" — MS-DOS/FAT magic
    s.f_bsize = 4096;    // our cluster size
    s.f_blocks = 0x1000; // 16 MiB notional
    s.f_bfree = 0x800;   // half-free
    s.f_bavail = 0x800;
    s.f_namelen = 255;
    s.f_frsize = 4096;
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_buf), &s, sizeof(s)))
        return kEFAULT;
    return 0;
}

// pipe / pipe2 / socket: deliberate -ENOSYS. We have no pipe,
// no socket. Logging as TU-handled (vs. primary-unhandled)
// makes it clear we've considered these and aren't silently
// returning zeros.
i64 TranslateDeliberateEnosys(arch::TrapFrame* /*f*/)
{
    return -38;
}

// rseq: restartable sequences. glibc and newer musl register an
// rseq structure at startup for high-perf per-CPU data. v0
// doesn't implement the machinery; return -ENOSYS and let the
// caller fall back to non-rseq paths.
i64 TranslateRseq(arch::TrapFrame* /*f*/)
{
    // -ENOSYS is also what no-translation produces; the
    // difference is this one is DELIBERATE — we've considered
    // rseq and decided not to wire it up. Log as such.
    return -38;
}

// ----- native → Linux/Win32 translations -----

// Experimental native syscall numbers whose body we synthesise
// by borrowing from Linux. The native dispatch table hasn't
// committed to specific numbers for these, so we're picking
// un-used ones well past the current SYS_* range. Any native
// caller using them is doing so ahead of a formal primary
// handler — useful in practice for kernel-side probes.
enum : u64
{
    kNativeClockNs = 0x200,    // returns NowNs() directly in rax
    kNativeGetRandom = 0x201,  // u64 buf, u64 count -> count (via xorshift)
    kNativeWin32Alloc = 0x210, // u64 size -> user_ptr (via Win32 heap)
    kNativeWin32Free = 0x211,  // u64 user_ptr -> 0
};

// Native: "give me monotonic nanoseconds" — trivially available
// via the already-exposed LinuxNowNs helper.
i64 NativeClockNs(arch::TrapFrame* /*f*/)
{
    return static_cast<i64>(linux::LinuxNowNs());
}

// Native: getrandom(buf, count) — not implemented in core/syscall,
// but the Linux handler exists. Reinvoke via a synthetic inner
// frame: stash the arguments where LinuxGetRandom would expect
// them and call the existing helper.
// Simpler: just inline the logic (xorshift64 seeded from rdtsc),
// matching Linux's v0 getrandom.
i64 NativeGetRandom(arch::TrapFrame* f)
{
    const u64 user_buf = f->rdi;
    u64 count = f->rsi;
    if (count == 0)
        return 0;
    if (count > 4096)
        count = 4096;
    u32 lo, hi;
    asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
    u64 state = ((static_cast<u64>(hi) << 32) | lo) ^ 0xDEADBEEFCAFEBABEull;
    static u8 tmp[4096];
    for (u64 i = 0; i < count; ++i)
    {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        tmp[i] = static_cast<u8>(state >> 24);
    }
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_buf), tmp, count))
        return -14; // -EFAULT
    return static_cast<i64>(count);
}

// Native: Win32HeapAlloc proxy — a non-Win32 process that wants
// Win32-style heap semantics can reach it through the TU. Uses
// the same per-process heap the Win32 PE loader sets up; caller
// gets back an 8-aligned user pointer or 0 on failure.
i64 NativeWin32Alloc(arch::TrapFrame* f)
{
    auto* p = core::CurrentProcess();
    if (p == nullptr)
        return 0;
    return static_cast<i64>(win32::Win32HeapAlloc(p, f->rdi));
}

// Native: Win32HeapFree proxy.
i64 NativeWin32Free(arch::TrapFrame* f)
{
    auto* p = core::CurrentProcess();
    if (p == nullptr)
        return 0;
    win32::Win32HeapFree(p, f->rdi);
    return 0;
}

} // namespace

const HitTable& LinuxHitsRead()
{
    return g_linux_hits;
}
const HitTable& NativeHitsRead()
{
    return g_native_hits;
}

Result LinuxGapFill(arch::TrapFrame* frame)
{
    KLOG_TRACE_SCOPE("translate", "LinuxGapFill");
    const u64 nr = frame->rax;
    Result r{false, 0};
    switch (nr)
    {
    case kSysReadv:
        LogTranslation("linux", nr, "linux-self:loop-over-read");
        r = {true, TranslateReadv(frame)};
        break;
    case kSysGettimeofday:
        LogTranslation("linux", nr, "linux-self:clock_gettime-reshape");
        r = {true, TranslateGettimeofday(frame)};
        break;
    case kSysSysinfo:
        LogTranslation("linux", nr, "synthetic:zeroed+uptime");
        r = {true, TranslateSysinfo(frame)};
        break;
    case kSysPrlimit64:
        LogTranslation("linux", nr, "synthetic:rlim-infinity");
        r = {true, TranslatePrlimit64(frame)};
        break;
    case kSysFsync:
    case kSysFdatasync:
        LogTranslation("linux", nr, "noop:writes-unbuffered");
        r = {true, TranslateNoOp(frame)};
        break;
    case kSysMadvise:
        LogTranslation("linux", nr, "noop:advisory-hint");
        r = {true, TranslateNoOp(frame)};
        break;
    case kSysRseq:
        LogTranslation("linux", nr, "synthetic:enosys-deliberate");
        r = {true, TranslateRseq(frame)};
        break;
    case kSysUmask:
        LogTranslation("linux", nr, "synthetic:022-default");
        r = {true, TranslateUmask(frame)};
        break;
    case kSysGetpgrp:
        LogTranslation("linux", nr, "synthetic:pgrp=0");
        r = {true, TranslateGetpgrp(frame)};
        break;
    case kSysGetrlimit:
        LogTranslation("linux", nr, "synthetic:rlim-infinity");
        r = {true, TranslateGetrlimit(frame)};
        break;
    case kSysSetrlimit:
        LogTranslation("linux", nr, "noop:limits-unenforced");
        r = {true, TranslateSetrlimit(frame)};
        break;
    case kSysStatfs:
    case kSysFstatfs:
        LogTranslation("linux", nr, "synthetic:fat32-style-statfs");
        r = {true, TranslateStatfs(frame)};
        break;
    case kSysPipe:
    case kSysPipe2:
    case kSysSocket:
        LogTranslation("linux", nr, "synthetic:enosys-no-ipc");
        r = {true, TranslateDeliberateEnosys(frame)};
        break;
    default:
        LogMiss("linux", frame, LinuxName(nr));
        break;
    }
    if (r.handled)
        BumpHits(g_linux_hits, nr);
    return r;
}

Result NativeGapFill(arch::TrapFrame* frame)
{
    KLOG_TRACE_SCOPE("translate", "NativeGapFill");
    const u64 nr = frame->rax;
    Result r{false, 0};
    switch (nr)
    {
    case kNativeClockNs:
        LogTranslation("native", nr, "linux-self:NowNs");
        r = {true, NativeClockNs(frame)};
        break;
    case kNativeGetRandom:
        LogTranslation("native", nr, "synthetic:xorshift-from-rdtsc");
        r = {true, NativeGetRandom(frame)};
        break;
    case kNativeWin32Alloc:
        LogTranslation("native", nr, "win32:HeapAlloc");
        r = {true, NativeWin32Alloc(frame)};
        break;
    case kNativeWin32Free:
        LogTranslation("native", nr, "win32:HeapFree");
        r = {true, NativeWin32Free(frame)};
        break;
    default:
        LogMiss("native", frame, NativeName(nr));
        break;
    }
    if (r.handled)
        BumpHits(g_native_hits, nr);
    return r;
}

} // namespace customos::subsystems::translation
