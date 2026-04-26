/*
 * DuetOS — Linux ABI: miscellaneous handlers.
 *
 * Sibling TU of syscall.cpp. Catch-all for handlers that don't
 * fit any of the per-domain slices (cred, fd, file, fs_mut,
 * io, mm, path, proc, rlimit, sched, sig, stub, time): arch_prctl,
 * uname, set_tid_address, sysinfo, getrandom, futex, personality,
 * pause, flock, get/setpriority, getcpu, prctl, getrusage,
 * poll/ppoll/select/pselect6, getdents64, set/get_robust_list,
 * readlink (with the /proc/self/exe special case).
 *
 * arch_prctl(ARCH_SET_FS) plants the musl TLS anchor in MSR_FS_BASE;
 * the rdmsr/wrmsr scaffolding is duplicated TU-locally so this
 * file doesn't depend on syscall.cpp's anon-namespace WriteMsr.
 */

#include "syscall_internal.h"

#include "../../core/process.h"
#include "../../core/random.h"
#include "../../mm/address_space.h"
#include "../../mm/frame_allocator.h"
#include "../../sched/sched.h"

namespace duetos::subsystems::linux::internal
{

namespace
{

// MSR number for FS.base — the musl TLS anchor that arch_prctl
// (ARCH_SET_FS) writes. Duplicated here from syscall.cpp's anon
// namespace so this TU is self-contained.
constexpr u32 kMsrFsBase = 0xC0000100;

// ARCH_* codes for arch_prctl (linux/arch/x86/include/uapi/asm/prctl.h).
constexpr u64 kArchSetGs = 0x1001;
constexpr u64 kArchSetFs = 0x1002;
constexpr u64 kArchGetFs = 0x1003;
constexpr u64 kArchGetGs = 0x1004;

void WriteMsr(u32 msr, u64 value)
{
    const u32 lo = static_cast<u32>(value & 0xFFFFFFFFu);
    const u32 hi = static_cast<u32>(value >> 32);
    asm volatile("wrmsr" : : "c"(msr), "a"(lo), "d"(hi));
}

} // namespace

i64 DoSetTidAddress(u64 user_tid_ptr)
{
    (void)user_tid_ptr;
    return static_cast<i64>(sched::CurrentTaskId());
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
    return i64(to_copy);
}

// Linux: futex(uaddr, op, val, ...).
//   FUTEX_WAIT (0): if *uaddr != val, return -EAGAIN.
//   FUTEX_WAKE (1): return 0 (no waiters, nothing to wake).
// FUTEX_PRIVATE_FLAG (0x80) masks off (no shared-memory model).
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
        u32 cur = 0;
        if (!mm::CopyFromUser(&cur, reinterpret_cast<const void*>(uaddr), sizeof(cur)))
            return kEFAULT;
        if (cur != u32(val))
            return -11; // -EAGAIN
        return 0;
    }
    if (base_op == kFutexWake)
    {
        return 0;
    }
    (void)uaddr;
    (void)val;
    return kEINVAL;
}

// Linux: getrandom(buf, count, flags). Routes through the shared
// kernel entropy pool (RDSEED → RDRAND → splitmix).
i64 DoGetRandom(u64 user_buf, u64 count, u64 flags)
{
    (void)flags;
    if (count == 0)
        return 0;
    if (count > 4096)
        count = 4096;
    static u8 tmp[4096];
    core::RandomFillBytes(tmp, count);
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_buf), tmp, count))
        return kEFAULT;
    return static_cast<i64>(count);
}

// Linux: sysinfo(info). Fills the kernel's current memory + uptime
// + load info. mem_unit=4096 so callers reading totalram*mem_unit
// see real bytes.
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

// Linux: getrusage(who, usage). Returns resource-usage stats.
namespace
{
constexpr i64 kRusageSelf = 0;
constexpr i64 kRusageChildren = -1;
constexpr i64 kRusageThread = 1;
} // namespace

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
            const u64 ticks = p->ticks_used;
            ru.ru_utime_sec = static_cast<i64>(ticks / 100ull);
            ru.ru_utime_usec = static_cast<i64>((ticks % 100ull) * 10'000ull);
        }
    }
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_buf), &ru, sizeof(ru)))
        return kEFAULT;
    return 0;
}

// Linux: poll(fds, nfds, timeout_ms). Returns count of fds that
// are ready. v0 marks live fds as immediately ready for the
// requested events (no real wait machinery yet).
namespace
{
constexpr i64 kPollIn = 0x0001;
constexpr i64 kPollOut = 0x0004;
} // namespace

i64 DoPoll(u64 user_fds, u64 nfds, i64 timeout_ms)
{
    (void)timeout_ms;
    if (nfds == 0)
        return 0;
    if (user_fds == 0)
        return kEFAULT;
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
            fds[i].revents = 0x20; // POLLNVAL
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

// Linux: select. Boundary-probe stub.
i64 DoSelect(u64 nfds, u64 rfds, u64 wfds, u64 efds, u64 timeout)
{
    (void)nfds;
    (void)rfds;
    (void)wfds;
    (void)efds;
    (void)timeout;
    return 0;
}

// Linux: getdents64. v0 has no per-fd directory cursor; return 0
// for "end of directory".
i64 DoGetdents64(u64 fd, u64 user_buf, u64 count)
{
    (void)fd;
    (void)user_buf;
    (void)count;
    return 0;
}

// Linux: set_robust_list / get_robust_list. No robust-futex
// machinery — accept set as no-op, return success on get.
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

// Linux: arch_prctl(code, addr). musl's CRT plants the TLS anchor
// in FS.base via ARCH_SET_FS. ARCH_GET_FS reads it back.
// ARCH_SET_GS / ARCH_GET_GS are refused — exposing MSR_GS_BASE to
// user mode would alias our per-CPU area.
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

// Linux: uname(buf). Static six-field utsname response.
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

// pause(): suspend until a signal arrives. v0 has no signal
// delivery, so this would block forever. Sleep in big chunks
// instead of a tight yield loop.
i64 DoPause()
{
    constexpr u64 kHugeTicks = 1ull << 30; // ~3.4 yrs at 100 Hz
    for (;;)
    {
        sched::SchedSleepTicks(kHugeTicks);
    }
    return 0;
}

// flock(fd, op): advisory file lock. v0 is single-process; no-op.
i64 DoFlock(u64 fd, u64 op)
{
    (void)fd;
    (void)op;
    return 0;
}

// personality(persona): query/set the process's execution
// personality. v0 only ever runs as the default Linux personality.
i64 DoPersonality(u64 persona)
{
    (void)persona;
    return 0;
}

// getpriority / setpriority: nice-value query/set. Flat
// scheduler — return 0 (neutral nice value); accept set as no-op.
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

// ppoll / pselect6: poll/select with a sigmask + timeout. Reuse
// the existing poll/select handlers; the sigmask is silently
// ignored.
i64 DoPpoll(u64 user_fds, u64 nfds, u64 user_ts, u64 user_sigmask, u64 sigsetsize)
{
    (void)user_sigmask;
    (void)sigsetsize;
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
// Accept the most common options musl + bionic exercise at startup;
// reject the rest with -EINVAL.
//   PR_SET_NAME (15) / PR_GET_NAME (16) — accept; PR_GET_NAME
//                       returns Process::name.
//   PR_SET_DUMPABLE (4) / PR_GET_DUMPABLE (3) — accept (no core dumps).
//   PR_SET_PDEATHSIG (1) / PR_GET_PDEATHSIG (2) — accept (no parent
//                       death tracking).
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
        return 1;
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
        return 0;
    case kPrSetSeccomp:
        return kEINVAL;
    default:
        return kEINVAL;
    }
}

} // namespace duetos::subsystems::linux::internal
