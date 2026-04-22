#include "translate.h"

#include "../../arch/x86_64/serial.h"
#include "../../arch/x86_64/traps.h"
#include "../../core/klog.h"
#include "../../mm/paging.h"
#include "../linux/syscall.h"

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
    kSysReadv = 19,
    kSysMadvise = 28,
    kSysFsync = 74,
    kSysFdatasync = 75,
    kSysGettimeofday = 96,
    kSysSysinfo = 99,
    kSysPrlimit64 = 302,
    kSysRseq = 334,
};

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

void LogMiss(const char* origin, u64 nr)
{
    arch::SerialWrite("[translate] ");
    arch::SerialWrite(origin);
    arch::SerialWrite("/");
    arch::SerialWriteHex(nr);
    arch::SerialWrite(" unimplemented -- no translation\n");
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

} // namespace

Result LinuxGapFill(arch::TrapFrame* frame)
{
    KLOG_TRACE_SCOPE("translate", "LinuxGapFill");
    const u64 nr = frame->rax;
    switch (nr)
    {
    case kSysReadv:
        LogTranslation("linux", nr, "linux-self:loop-over-read");
        return {true, TranslateReadv(frame)};
    case kSysGettimeofday:
        LogTranslation("linux", nr, "linux-self:clock_gettime-reshape");
        return {true, TranslateGettimeofday(frame)};
    case kSysSysinfo:
        LogTranslation("linux", nr, "synthetic:zeroed+uptime");
        return {true, TranslateSysinfo(frame)};
    case kSysPrlimit64:
        LogTranslation("linux", nr, "synthetic:rlim-infinity");
        return {true, TranslatePrlimit64(frame)};
    case kSysFsync:
    case kSysFdatasync:
        LogTranslation("linux", nr, "noop:writes-unbuffered");
        return {true, TranslateNoOp(frame)};
    case kSysMadvise:
        LogTranslation("linux", nr, "noop:advisory-hint");
        return {true, TranslateNoOp(frame)};
    case kSysRseq:
        LogTranslation("linux", nr, "synthetic:enosys-deliberate");
        return {true, TranslateRseq(frame)};
    default:
        LogMiss("linux", nr);
        return {false, 0};
    }
}

} // namespace customos::subsystems::translation
