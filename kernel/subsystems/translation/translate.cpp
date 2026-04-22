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
    kSysReadv = 19,
    kSysMadvise = 28,
    kSysFsync = 74,
    kSysFdatasync = 75,
    kSysGettimeofday = 96,
    kSysSysinfo = 99,
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
    default:
        LogMiss("linux", nr);
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
        LogMiss("native", nr);
        break;
    }
    if (r.handled)
        BumpHits(g_native_hits, nr);
    return r;
}

} // namespace customos::subsystems::translation
