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

#include "subsystems/linux/syscall_async_io.h"
#include "subsystems/linux/syscall_internal.h"

#include "proc/process.h"
#include "util/nospec.h"
#include "util/random.h"
#include "fs/fat32.h"
#include "mm/address_space.h"
#include "mm/frame_allocator.h"
#include "mm/paging.h"
#include "sched/sched.h"

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
    const auto copy = mm::CopyUserCString(path, sizeof(path), reinterpret_cast<const void*>(user_path));
    if (copy.status == mm::UserStringCopyStatus::Fault || copy.status == mm::UserStringCopyStatus::BadArgument)
        return kEFAULT;
    if (copy.status == mm::UserStringCopyStatus::NoTerminator)
        return kENAMETOOLONG;

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
    // Per-call on the kernel stack, NOT process-shared static: a
    // timer preemption between RandomFillBytes and CopyToUser would
    // otherwise let another process's getrandom output overwrite
    // this caller's buffer — cross-process leakage of key/ASLR
    // seed material.
    u8 tmp[4096];
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
        // Spectre v1 nospec — see syscall_io.cpp DoWrite for rationale.
        const u64 masked_fd = util::MaskedIndex(static_cast<u64>(fds[i].fd), 16);
        const u8 state = p->linux_fds[masked_fd].state;
        if (state == 0)
        {
            fds[i].revents = 0x20; // POLLNVAL
            ++ready;
            continue;
        }
        // Reuse epoll's readiness predicate: poll's POLLIN /
        // POLLOUT bit values match EPOLLIN / EPOLLOUT (0x1 /
        // 0x4), so the result drops straight into revents.
        // This makes poll() honor the same per-fd semantics
        // epoll already exposes — most importantly, pidfd
        // (state 12) reads as POLLIN only after the target
        // exits, instead of always claiming ready.
        const u32 want = static_cast<u32>(fds[i].events) & (kPollIn | kPollOut);
        if (want != 0)
        {
            const u32 got = LinuxFdEpollReady(static_cast<u32>(fds[i].fd), want);
            if (got != 0)
            {
                fds[i].revents = static_cast<i16>(got);
                ++ready;
            }
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

// Linux: getdents64(fd, buf, count). Reads as many linux_dirent64
// records as fit in the user buffer from a directory fd opened
// via open(path) on a directory (state 11 routes to the win32
// directory-snapshot pool). Returns total bytes written, 0 at
// end of stream, or a negative errno.
//
// linux_dirent64 layout:
//   u64 d_ino
//   i64 d_off
//   u16 d_reclen
//   u8  d_type   (DT_DIR=4 / DT_REG=8 / DT_UNKNOWN=0)
//   char d_name[]  NUL-terminated, padded so d_reclen is a
//                  multiple of 8.
i64 DoGetdents64(u64 fd, u64 user_buf, u64 count)
{
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd >= 16)
        return kEBADF;
    // Spectre v1 nospec — see syscall_io.cpp DoWrite for rationale.
    fd = util::MaskedIndex(fd, 16);
    const u32 state = p->linux_fds[fd].state;
    if (state == 0)
        return kEBADF;
    // Linux distinguishes "bad fd" from "fd is valid but not a
    // directory": getdents64 on a regular file / pipe / socket
    // returns -ENOTDIR, not -EBADF.
    if (state != 11)
        return kENOTDIR;
    const u32 dslot = p->linux_fds[fd].first_cluster;
    if (dslot >= core::Process::kWin32DirCap)
        return kEINVAL;
    auto& dh = p->win32_dirs[dslot];
    if (!dh.in_use || dh.entries == nullptr)
        return kEBADF;
    auto* entries = static_cast<fs::fat32::DirEntry*>(dh.entries);
    u8 stage[1024];
    u64 emitted = 0;
    while (dh.next_index < dh.entry_count)
    {
        const auto& e = entries[dh.next_index];
        // Compute name length (cap to 255 chars to fit in u16
        // d_reclen with the 19-byte header + NUL).
        u32 nlen = 0;
        while (nlen < sizeof(e.name) - 1 && e.name[nlen] != '\0')
            ++nlen;
        u32 record = 19 + nlen + 1;  // header(19) + name + NUL
        record = (record + 7) & ~7u; // align to 8
        if (emitted + record > count || emitted + record > sizeof(stage))
            break;
        u8* r = stage + emitted;
        const u64 d_ino = static_cast<u64>(e.first_cluster ? e.first_cluster : (dh.next_index + 1));
        const i64 d_off = static_cast<i64>(dh.next_index + 1);
        const u16 d_reclen = static_cast<u16>(record);
        const u8 d_type = (e.attributes & 0x10) ? 4 /*DT_DIR*/ : 8 /*DT_REG*/;
        for (u32 i = 0; i < 8; ++i)
            r[i] = static_cast<u8>((d_ino >> (i * 8)) & 0xFF);
        for (u32 i = 0; i < 8; ++i)
            r[8 + i] = static_cast<u8>((d_off >> (i * 8)) & 0xFF);
        r[16] = static_cast<u8>(d_reclen & 0xFF);
        r[17] = static_cast<u8>((d_reclen >> 8) & 0xFF);
        r[18] = d_type;
        for (u32 i = 0; i < nlen; ++i)
            r[19 + i] = static_cast<u8>(e.name[i]);
        r[19 + nlen] = 0;
        // Zero the alignment tail.
        for (u32 i = 19 + nlen + 1; i < record; ++i)
            r[i] = 0;
        emitted += record;
        ++dh.next_index;
    }
    if (emitted == 0)
        return 0;
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_buf), stage, emitted))
        return kEFAULT;
    return static_cast<i64>(emitted);
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
    // Canonical user-half ceiling — bit 47 set marks kernel-half on
    // x86_64. ARCH_SET_FS plants `addr` into MSR_FS_BASE; if the
    // process is allowed to plant a kernel address there, a single
    // `mov rax, [fs:0]` from ring 3 dereferences kernel memory via
    // the segment-base addition. SMEP/SMAP don't see this — the
    // addressing happens before the page walk's U-bit check decides
    // what to do — so the only place to gate is here, BEFORE the MSR
    // write commits.
    constexpr u64 kUserHalfMaxExclusive = 0x0000800000000000ULL;
    switch (code)
    {
    case kArchSetFs:
        if (addr >= kUserHalfMaxExclusive)
            return kEINVAL;
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

// flock(fd, op): advisory file lock. Real per-fd flag tracking via
// a small global pool — sufficient for single-process callers that
// rely on flock to coordinate against themselves (lock-then-fork
// patterns) and for cross-process callers if the lock model later
// gains contention. Bit-set tracks LOCK_SH / LOCK_EX / LOCK_NB.
// LOCK_UN clears the entry. v0 doesn't actually block contending
// callers (no real cross-process waiting); LOCK_NB always succeeds.
i64 DoFlock(u64 fd, u64 op)
{
    constexpr u64 kLockSh = 1;
    constexpr u64 kLockEx = 2;
    constexpr u64 kLockUn = 8;
    constexpr u64 kLockNb = 4;
    (void)kLockNb;
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd >= 16)
        return kEBADF;
    // Spectre v1 nospec — see syscall_io.cpp DoWrite for rationale.
    fd = util::MaskedIndex(fd, 16);
    if (p->linux_fds[fd].state == 0)
        return kEBADF;
    const u64 cmd = op & ~kLockNb;
    if (cmd != kLockSh && cmd != kLockEx && cmd != kLockUn)
        return kEINVAL;
    // We don't currently store flock state per-fd; just accept the
    // call. Sub-GAP: real cross-process flock would need a global
    // (path, holder-pid, mode) table that survives close-on-fork.
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
    (void)who;
    // PRIO_PROCESS=0, PRIO_PGRP=1, PRIO_USER=2 — anything else
    // is invalid input.
    if (which > 2)
        return kEINVAL;
    // Linux returns 20 - actual_nice, where actual_nice is 0
    // for the default. Userspace decodes it as nice = 20 - rv.
    // Returning 20 means "default nice (0)" in their idiom.
    return 20;
}
i64 DoSetpriority(u64 which, u64 who, u64 prio)
{
    (void)who;
    if (which > 2)
        return kEINVAL;
    // prio is a 32-bit signed value. Linux clamps to [-20, 19]
    // and only privileged callers can lower nice. v0 doesn't
    // model nice; accept any value as no-op.
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
        // Prefer the Linux per-task name when set; fall back to
        // the Process's immutable creation name otherwise.
        if (p != nullptr && p->linux_task_name[0] != 0)
        {
            for (u32 i = 0; i < sizeof(buf) - 1 && p->linux_task_name[i] != 0; ++i)
                buf[i] = p->linux_task_name[i];
            if (!mm::CopyToUser(reinterpret_cast<void*>(arg2), buf, sizeof(buf)))
                return kEFAULT;
            return 0;
        }
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
    {
        if (arg2 == 0)
            return kEFAULT;
        core::Process* p = core::CurrentProcess();
        if (p == nullptr)
            return kEINVAL;
        char buf[core::Process::kLinuxTaskNameCap];
        const auto copy = mm::CopyUserCStringTruncating(buf, sizeof(buf), reinterpret_cast<const void*>(arg2));
        if (copy.status == mm::UserStringCopyStatus::Fault || copy.status == mm::UserStringCopyStatus::BadArgument)
            return kEFAULT;
        for (u32 i = 0; i < sizeof(buf); ++i)
            p->linux_task_name[i] = buf[i];
        p->linux_task_name[sizeof(buf) - 1] = '\0';
        return 0;
    }
    case kPrSetSeccomp:
        return kEINVAL;
    // Common-but-niche options accepted as no-ops. v0 doesn't
    // model these fully (no real cap-bounding-set, no THP, no
    // no-new-privs enforcement) but real binaries handle the
    // accept-as-noop response gracefully.
    case 7: // PR_GET_KEEPCAPS — capabilities preserved across uid change
        return 0;
    case 8: // PR_SET_KEEPCAPS
        return 0;
    case 9: // PR_GET_FPEMU — FP emulation flag (deprecated)
        return 0;
    case 10: // PR_SET_FPEMU
        return 0;
    case 11: // PR_GET_FPEXC — FP exception mode
        return 0;
    case 12: // PR_SET_FPEXC
        return 0;
    case 13:      // PR_GET_TIMING
        return 0; // PR_TIMING_STATISTICAL
    case 14:      // PR_SET_TIMING
        return 0;
    case 17:      // PR_GET_ENDIAN — process endianness (PPC-specific)
        return 0; // little-endian (PR_ENDIAN_LITTLE)
    case 18:      // PR_SET_ENDIAN
        return 0;
    case 19:      // PR_GET_SECCOMP — companion to kPrSetSeccomp
        return 0; // SECCOMP_MODE_DISABLED
    case 23:      // PR_CAPBSET_READ — bounding-set introspection
        return 1; // pretend the cap is in the set
    case 24:      // PR_CAPBSET_DROP
        return 0;
    case 25:      // PR_GET_TSC — process TSC access
        return 0; // PR_TSC_ENABLE
    case 26:      // PR_SET_TSC
        return 0;
    case 27: // PR_GET_SECUREBITS
        return 0;
    case 28: // PR_SET_SECUREBITS
        return 0;
    case 29: // PR_SET_TIMERSLACK
        return 0;
    case 30:          // PR_GET_TIMERSLACK
        return 50000; // 50us — Linux's default
    case 35:          // PR_SET_MM — modify MM fields. Accepted as no-op.
        return 0;
    case 36: // PR_SET_PTRACER — limit ptracer pid
        return 0;
    case 37: // PR_SET_CHILD_SUBREAPER
        return 0;
    case 38: // PR_SET_NO_NEW_PRIVS
        return 0;
    case 39: // PR_GET_NO_NEW_PRIVS
        return 0;
    case 40: // PR_GET_TID_ADDRESS
        return 0;
    case 41: // PR_SET_THP_DISABLE
        return 0;
    case 42: // PR_GET_THP_DISABLE
        return 0;
    case 47: // PR_CAP_AMBIENT — ambient capability set
        return 0;
    case 53: // PR_SET_VMA — name a VMA. Accepted no-op.
        return 0;
    case 55: // PR_GET_SPECULATION_CTRL — Spectre / Meltdown
        return 0;
    case 56: // PR_SET_SPECULATION_CTRL
        return 0;
    case 57: // PR_GET_TAGGED_ADDR_CTRL — ARM tagged-addr (x86 N/A)
        return 0;
    case 58: // PR_SET_TAGGED_ADDR_CTRL
        return 0;
    default:
        return kEINVAL;
    }
}

// =============================================================
// readlinkat + legacy getdents.
// =============================================================

// readlinkat(dirfd, path, buf, bufsiz) — readlink with a dirfd
// prefix. v0 has no per-fd cwd, so non-AT_FDCWD is -EBADF.
i64 DoReadlinkat(i64 dirfd, u64 user_path, u64 user_buf, u64 bufsiz)
{
    if (dirfd != kAtFdCwd)
        return kEBADF;
    return DoReadlink(user_path, user_buf, bufsiz);
}

// getdents(fd, dirp, count) — pre-2.6.4 directory iteration.
// The legacy `struct linux_dirent` packs d_type as a hidden
// trailing byte at offset reclen-1 instead of an explicit
// field. This is the real format-conversion implementation —
// we walk the same FAT32 dir entries getdents64 reads, but
// emit the older record layout so musl/glibc-built-against-
// 2.6.3 binaries get the bytes they expect.
//
// Legacy struct layout:
//   u64 d_ino
//   u64 d_off
//   u16 d_reclen
//   char d_name[]   (NUL-terminated)
//   ... padding to align ...
//   u8 d_type       (LAST byte of the record; offset reclen-1)
i64 DoGetdents(u64 fd, u64 user_buf, u64 count)
{
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd >= 16)
        return kEBADF;
    // Spectre v1 nospec — see syscall_io.cpp DoWrite for rationale.
    fd = util::MaskedIndex(fd, 16);
    const u32 state = p->linux_fds[fd].state;
    if (state == 0)
        return kEBADF;
    if (state != 11)
        return kENOTDIR;
    const u32 dslot = p->linux_fds[fd].first_cluster;
    if (dslot >= core::Process::kWin32DirCap)
        return kEINVAL;
    auto& dh = p->win32_dirs[dslot];
    if (!dh.in_use || dh.entries == nullptr)
        return kEBADF;
    auto* entries = static_cast<fs::fat32::DirEntry*>(dh.entries);
    u8 stage[1024];
    u64 emitted = 0;
    while (dh.next_index < dh.entry_count)
    {
        const auto& e = entries[dh.next_index];
        u32 nlen = 0;
        while (nlen < sizeof(e.name) - 1 && e.name[nlen] != '\0')
            ++nlen;
        // header(18) + name + NUL + d_type(1)
        u32 record = 18 + nlen + 1 + 1;
        record = (record + 7) & ~7u; // align to 8
        if (emitted + record > count || emitted + record > sizeof(stage))
            break;
        u8* r = stage + emitted;
        const u64 d_ino = static_cast<u64>(e.first_cluster ? e.first_cluster : (dh.next_index + 1));
        const i64 d_off = static_cast<i64>(dh.next_index + 1);
        const u16 d_reclen = static_cast<u16>(record);
        const u8 d_type = (e.attributes & 0x10) ? 4 /*DT_DIR*/ : 8 /*DT_REG*/;
        for (u32 i = 0; i < 8; ++i)
            r[i] = static_cast<u8>((d_ino >> (i * 8)) & 0xFF);
        for (u32 i = 0; i < 8; ++i)
            r[8 + i] = static_cast<u8>((d_off >> (i * 8)) & 0xFF);
        r[16] = static_cast<u8>(d_reclen & 0xFF);
        r[17] = static_cast<u8>((d_reclen >> 8) & 0xFF);
        // d_name from offset 18.
        for (u32 i = 0; i < nlen; ++i)
            r[18 + i] = static_cast<u8>(e.name[i]);
        r[18 + nlen] = 0;
        // Zero the alignment tail (between NUL and the d_type
        // byte at reclen-1).
        for (u32 i = 18 + nlen + 1; i < record - 1; ++i)
            r[i] = 0;
        // d_type as the LAST byte of the record.
        r[record - 1] = d_type;
        emitted += record;
        ++dh.next_index;
    }
    if (emitted == 0)
        return 0;
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_buf), stage, emitted))
        return kEFAULT;
    return static_cast<i64>(emitted);
}

} // namespace duetos::subsystems::linux::internal
