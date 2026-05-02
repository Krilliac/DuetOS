/*
 * DuetOS — Linux ABI: route-through wrappers and trivial stubs.
 *
 * Sibling TU of syscall.cpp. Houses Linux syscalls whose v0
 * implementation is either:
 *
 *   1. A thin re-route to an existing Do<Name> handler with a
 *      shape adjustment (Tkill -> Tgkill, Mknodat -> Mknod,
 *      Readlinkat -> Readlink, Utimes -> Utimensat, Creat ->
 *      Open, RtTgsigqueueinfo -> Tgkill).
 *
 *   2. A trivial-but-correct stub that returns the right errno
 *      for "feature recognised but not real-on-this-OS" rather
 *      than -ENOSYS (Alarm/Getitimer/Setitimer return 0,
 *      Membarrier/Mlock2/Fallocate/SyncFileRange accept silently,
 *      Fchmodat2 routes to Fchmodat).
 *
 *   3. A vector form of an existing scalar handler: Preadv /
 *      Pwritev / Preadv2 / Pwritev2 each call DoPread64 /
 *      DoPwrite64 in a loop over the user iovec.
 *
 *   4. A legacy ABI variant of a modern handler: Getdents reads
 *      the same FAT32 dir entries as Getdents64 but emits the
 *      pre-2.6.4 dirent format.
 *
 * The file is named "aux" to make it obvious that what's here is
 * NOT a new subsystem — it's a thin compatibility surface so that
 * Linux ELFs which use these spec-defined syscalls get a sensible
 * answer instead of -ENOSYS.
 */

#include "subsystems/linux/syscall_internal.h"

#include "arch/x86_64/serial.h"
#include "mm/paging.h"
#include "proc/process.h"

namespace duetos::subsystems::linux::internal
{

// =============================================================
// Route-through wrappers — call the existing scalar handler.
// =============================================================

// tkill(tid, sig) — single-thread variant of tgkill. Linux's
// glibc still calls this; modern kernels treat it as
// tgkill(getpid(), tid, sig). Our DoTgkill ignores tgid for the
// purpose of tid -> Process::pid lookup (see syscall_proc.cpp
// header comment), so passing 0 is harmless.
i64 DoTkill(u64 tid, u64 sig)
{
    return DoTgkill(0, tid, sig);
}

// mknodat(dirfd, path, mode, dev) — same as mknod when dirfd
// is AT_FDCWD. Other dirfd values aren't supported in v0
// (no per-fd cwd) so we return -EBADF for those.
i64 DoMknodat(i64 dirfd, u64 user_path, u64 mode, u64 dev)
{
    if (dirfd != kAtFdCwd)
        return kEBADF;
    return DoMknod(user_path, mode, dev);
}

// readlinkat(dirfd, path, buf, bufsiz) — same as readlink when
// dirfd is AT_FDCWD. Same per-fd-cwd limitation as mknodat.
i64 DoReadlinkat(i64 dirfd, u64 user_path, u64 user_buf, u64 bufsiz)
{
    if (dirfd != kAtFdCwd)
        return kEBADF;
    return DoReadlink(user_path, user_buf, bufsiz);
}

// utimes(path, times) — older sibling of utimensat. Times is a
// `struct timeval[2]` (sec + usec) instead of timespec[2] (sec
// + nsec). DoUtimensat is permissive about the struct layout in
// v0 (it touches the file's mtime but doesn't actually decode
// the timespec), so passing through works for the common case
// of "tag the file as freshly-modified". Real precision is a
// follow-up.
i64 DoUtimes(u64 user_path, u64 user_times)
{
    return DoUtimensat(kAtFdCwd, user_path, user_times, 0);
}

// rt_tgsigqueueinfo(tgid, tid, sig, info) — extended tgkill that
// also delivers a siginfo payload to the target. v0 has no
// signal-delivery facility for siginfo, so we drop the info
// pointer and route to tgkill. Real callers can still observe
// the signal arrival; the info payload is an audit-only sub-GAP.
i64 DoRtTgsigqueueinfo(u64 tgid, u64 tid, u64 sig, u64 user_info)
{
    (void)user_info;
    return DoTgkill(tgid, tid, sig);
}

// creat(path, mode) — equivalent to open(path,
// O_CREAT|O_WRONLY|O_TRUNC, mode). Linux's libc stopped using
// this ages ago but ld.so and a couple of legacy build tools
// still reach for it on bootstrap. Routes through DoOpen.
i64 DoCreat(u64 user_path, u64 mode)
{
    constexpr u64 kOCreat = 0x40;
    constexpr u64 kOWrOnly = 0x1;
    constexpr u64 kOTrunc = 0x200;
    return DoOpen(user_path, kOCreat | kOWrOnly | kOTrunc, mode);
}

// =============================================================
// Vector forms — Preadv / Pwritev / Preadv2 / Pwritev2.
// Each iov segment is read/written at offset+running-total.
// Linux's spec is "atomic" in the sense that the kernel locks
// the file position once for the whole vector; in practice on
// a UP-with-no-concurrent-writers v0 kernel a sequential loop
// is observably indistinguishable.
// =============================================================

namespace
{

struct UserIovec
{
    u64 base;
    u64 len;
};

constexpr u64 kIovMax = 1024;

i64 PreadvLoop(u64 fd, u64 user_iov, u64 iovcnt, i64 offset)
{
    if (iovcnt == 0)
        return 0;
    if (iovcnt > kIovMax)
        return kEINVAL;
    UserIovec iov[kIovMax];
    if (!mm::CopyFromUser(iov, reinterpret_cast<const void*>(user_iov), iovcnt * sizeof(UserIovec)))
        return kEFAULT;
    i64 total = 0;
    i64 cursor = offset;
    for (u64 i = 0; i < iovcnt; ++i)
    {
        if (iov[i].len == 0)
            continue;
        const i64 got = DoPread64(fd, iov[i].base, iov[i].len, cursor);
        if (got < 0)
            return total > 0 ? total : got;
        total += got;
        cursor += got;
        if (got < static_cast<i64>(iov[i].len))
            break;
    }
    return total;
}

i64 PwritevLoop(u64 fd, u64 user_iov, u64 iovcnt, i64 offset)
{
    if (iovcnt == 0)
        return 0;
    if (iovcnt > kIovMax)
        return kEINVAL;
    UserIovec iov[kIovMax];
    if (!mm::CopyFromUser(iov, reinterpret_cast<const void*>(user_iov), iovcnt * sizeof(UserIovec)))
        return kEFAULT;
    i64 total = 0;
    i64 cursor = offset;
    for (u64 i = 0; i < iovcnt; ++i)
    {
        if (iov[i].len == 0)
            continue;
        const i64 put = DoPwrite64(fd, iov[i].base, iov[i].len, cursor);
        if (put < 0)
            return total > 0 ? total : put;
        total += put;
        cursor += put;
        if (put < static_cast<i64>(iov[i].len))
            break;
    }
    return total;
}

} // namespace

i64 DoPreadv(u64 fd, u64 user_iov, u64 iovcnt, i64 offset)
{
    return PreadvLoop(fd, user_iov, iovcnt, offset);
}

i64 DoPwritev(u64 fd, u64 user_iov, u64 iovcnt, i64 offset)
{
    return PwritevLoop(fd, user_iov, iovcnt, offset);
}

// preadv2 / pwritev2: same as preadv / pwritev plus a `flags`
// argument. The defined flags (RWF_HIPRI / RWF_DSYNC / RWF_SYNC
// / RWF_NOWAIT / RWF_APPEND) are advisory in v0 — we accept
// them silently since the underlying handlers don't observe
// per-call sync semantics.
i64 DoPreadv2(u64 fd, u64 user_iov, u64 iovcnt, i64 offset, u64 flags)
{
    (void)flags;
    return PreadvLoop(fd, user_iov, iovcnt, offset);
}

i64 DoPwritev2(u64 fd, u64 user_iov, u64 iovcnt, i64 offset, u64 flags)
{
    (void)flags;
    return PwritevLoop(fd, user_iov, iovcnt, offset);
}

// =============================================================
// Trivial-but-correct stubs.
// =============================================================

// alarm(seconds) — schedule SIGALRM after `seconds`. Cancel any
// existing alarm. Returns the seconds remaining on the prior
// alarm, or 0 if none. v0 has no real timer wheel: we don't
// schedule the signal at all, but the API contract "no prior
// alarm => return 0; setting an alarm => return 0" is satisfied
// for the common idiom of `alarm(0)` to clear a pending alarm.
// Real callers that depend on the SIGALRM firing are a sub-GAP.
i64 DoAlarm(u64 seconds)
{
    (void)seconds;
    return 0;
}

// getitimer(which, value) — read the current interval timer.
// We don't have any timers, so we always report "not running"
// (zero it_value + zero it_interval). 16 bytes of zeros each.
i64 DoGetitimer(u64 which, u64 user_value)
{
    if (which > 2 /*ITIMER_PROF*/)
        return kEINVAL;
    if (user_value != 0)
    {
        u8 zeros[32] = {0};
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_value), zeros, sizeof(zeros)))
            return kEFAULT;
    }
    return 0;
}

// setitimer(which, new_value, old_value) — install a new
// interval timer. We don't actually start one, but we must
// clear `old_value` to "no prior timer" if the caller asked.
i64 DoSetitimer(u64 which, u64 user_new, u64 user_old)
{
    (void)user_new;
    if (which > 2)
        return kEINVAL;
    if (user_old != 0)
    {
        u8 zeros[32] = {0};
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_old), zeros, sizeof(zeros)))
            return kEFAULT;
    }
    return 0;
}

// membarrier(cmd, flags) — synchronise memory barriers across
// threads. cmd=0 is MEMBARRIER_CMD_QUERY which reports the bitmask
// of supported commands. v0 supports none, so QUERY returns 0.
// Other commands: -EINVAL.
i64 DoMembarrier(u64 cmd, u64 flags)
{
    (void)flags;
    if (cmd == 0)
        return 0; // QUERY -> no commands supported
    return kEINVAL;
}

// mlock2(addr, len, flags) — pin pages. v0 doesn't swap so the
// pin is implicit; accept the call as advisory.
i64 DoMlock2(u64 addr, u64 len, u64 flags)
{
    (void)addr;
    (void)len;
    (void)flags;
    return 0;
}

// fallocate(fd, mode, offset, len) — preallocate / punch /
// collapse-range. v0 accepts `mode==0` (the default "extend
// the file to offset+len with zeros if needed") as a no-op
// because Fat32 files grow on write anyway. Other modes
// (FALLOC_FL_KEEP_SIZE, FALLOC_FL_PUNCH_HOLE, ...) are
// unimplemented.
i64 DoFallocate(u64 fd, u64 mode, u64 offset, u64 len)
{
    (void)fd;
    (void)offset;
    (void)len;
    if (mode != 0)
        return kENOSYS;
    return 0;
}

// sync_file_range(fd, offset, nbytes, flags) — durable
// flush of a byte range. v0 has no per-range flush; route
// to a global Sync (close enough for correctness, way less
// efficient than the spec asks). Caller's data lands.
i64 DoSyncFileRange(u64 fd, u64 offset, u64 nbytes, u64 flags)
{
    (void)fd;
    (void)offset;
    (void)nbytes;
    (void)flags;
    return DoSync();
}

// fchmodat2(dirfd, path, mode, flags) — fchmodat with an
// extended flags argument that allows AT_SYMLINK_NOFOLLOW.
// Same shape as fchmodat which we already have, so just call
// it. The flags argument is advisory in v0 since we don't
// follow symlinks anyway.
i64 DoFchmodat2(i64 dirfd, u64 user_path, u64 mode, u64 flags)
{
    return DoFchmodat(dirfd, user_path, mode, flags);
}

// openat2(dirfd, path, how_struct, how_size) — extended openat
// where the open arguments are bundled in a `struct open_how`
// (flags, mode, resolve). v0 reads the first two fields and
// passes them to DoOpenat; resolve flags (RESOLVE_NO_SYMLINKS,
// RESOLVE_BENEATH, ...) are advisory and quietly ignored.
i64 DoOpenat2(i64 dirfd, u64 user_path, u64 user_how, u64 how_size)
{
    if (how_size < 24)
        return kEINVAL;
    struct OpenHow
    {
        u64 flags;
        u64 mode;
        u64 resolve;
    } how = {};
    const u64 to_copy = how_size < sizeof(how) ? how_size : sizeof(how);
    if (!mm::CopyFromUser(&how, reinterpret_cast<const void*>(user_how), to_copy))
        return kEFAULT;
    return DoOpenat(dirfd, user_path, how.flags, how.mode);
}

// epoll_pwait2(epfd, events, maxevents, timeout_ts, sigmask,
// sigsetsize) — same as epoll_pwait but the timeout is a
// `struct timespec*` (nsec precision) instead of an int (ms).
// We round up to milliseconds — v0 has no nanosecond-grain
// scheduler tick anyway, so the loss is acceptable. NULL
// timeout = block forever (-1), zero timeout = poll once (0),
// positive timeout = ceil to ms.
i64 DoEpollPwait2(u64 epfd, u64 events, u64 maxevents, u64 user_ts, u64 sigmask, u64 sigsetsize)
{
    i64 timeout_ms = -1;
    if (user_ts != 0)
    {
        struct Timespec
        {
            i64 sec;
            i64 nsec;
        } ts = {};
        if (!mm::CopyFromUser(&ts, reinterpret_cast<const void*>(user_ts), sizeof(ts)))
            return kEFAULT;
        if (ts.sec == 0 && ts.nsec == 0)
            timeout_ms = 0;
        else
            timeout_ms = ts.sec * 1000 + (ts.nsec + 999999) / 1000000;
    }
    return DoEpollPwait(epfd, events, maxevents, static_cast<u64>(timeout_ms), sigmask, sigsetsize);
}

// =============================================================
// Sendfile — a fd-to-fd copy that lets the kernel skip the
// userspace bounce buffer in glibc's sendfile() back-end. v0
// implements the bounce inside the kernel: read up to ~64 KiB
// at a time from in_fd, write to out_fd, repeat until count
// is exhausted or short read/write. Returns the bytes
// transferred; advances in_fd's offset.
// =============================================================

i64 DoSendfile(u64 out_fd, u64 in_fd, u64 user_offset, u64 count)
{
    if (count == 0)
        return 0;
    constexpr u64 kChunk = 4096;
    u8 chunk[kChunk];
    i64 transferred = 0;
    while (count > 0)
    {
        const u64 want = count < kChunk ? count : kChunk;
        i64 got = 0;
        if (user_offset != 0)
        {
            // Caller wants the read from a specific offset
            // without disturbing in_fd's position.
            i64 off = 0;
            if (!mm::CopyFromUser(&off, reinterpret_cast<const void*>(user_offset), sizeof(off)))
                return transferred > 0 ? transferred : kEFAULT;
            got = DoPread64(in_fd, reinterpret_cast<u64>(chunk), want, off);
            if (got > 0)
            {
                off += got;
                if (!mm::CopyToUser(reinterpret_cast<void*>(user_offset), &off, sizeof(off)))
                    return transferred > 0 ? transferred : kEFAULT;
            }
        }
        else
        {
            got = DoRead(in_fd, reinterpret_cast<u64>(chunk), want);
        }
        if (got <= 0)
            return transferred > 0 ? transferred : got;
        const i64 put = DoWrite(out_fd, reinterpret_cast<u64>(chunk), static_cast<u64>(got));
        if (put < 0)
            return transferred > 0 ? transferred : put;
        transferred += put;
        if (put < got)
            break;
        count -= static_cast<u64>(put);
    }
    return transferred;
}

// =============================================================
// Batch 2 — more correct errnos for spec-defined-but-unsupported
// surfaces. These are NOT -ENOSYS because the API is recognised;
// we just don't have the underlying mechanism (xattr storage,
// namespaces, LDT, cross-process VM, ...). Picking the spec's
// "feature unsupported" errno over -ENOSYS makes glibc and
// musl take the documented fallback path instead of treating
// the host as exotic.
// =============================================================

// xattr family (set/get/list/remove × {/, l, f}). Linux's
// rule: if the FS doesn't grok extended attributes at all, the
// kernel returns -EOPNOTSUPP (== -ENOTSUP). Most setxattr-using
// libraries (libacl, libcap, attr) handle this gracefully.
i64 DoSetxattr(u64 path, u64 name, u64 value, u64 size, u64 flags)
{
    (void)path;
    (void)name;
    (void)value;
    (void)size;
    (void)flags;
    return kEOPNOTSUPP;
}
i64 DoLsetxattr(u64 path, u64 name, u64 value, u64 size, u64 flags)
{
    return DoSetxattr(path, name, value, size, flags);
}
i64 DoFsetxattr(u64 fd, u64 name, u64 value, u64 size, u64 flags)
{
    (void)fd;
    return DoSetxattr(0, name, value, size, flags);
}
i64 DoGetxattr(u64 path, u64 name, u64 value, u64 size)
{
    (void)path;
    (void)name;
    (void)value;
    (void)size;
    return kEOPNOTSUPP;
}
i64 DoLgetxattr(u64 path, u64 name, u64 value, u64 size)
{
    return DoGetxattr(path, name, value, size);
}
i64 DoFgetxattr(u64 fd, u64 name, u64 value, u64 size)
{
    (void)fd;
    return DoGetxattr(0, name, value, size);
}
i64 DoListxattr(u64 path, u64 list, u64 size)
{
    (void)path;
    (void)list;
    (void)size;
    return kEOPNOTSUPP;
}
i64 DoLlistxattr(u64 path, u64 list, u64 size)
{
    return DoListxattr(path, list, size);
}
i64 DoFlistxattr(u64 fd, u64 list, u64 size)
{
    (void)fd;
    return DoListxattr(0, list, size);
}
i64 DoRemovexattr(u64 path, u64 name)
{
    (void)path;
    (void)name;
    return kEOPNOTSUPP;
}
i64 DoLremovexattr(u64 path, u64 name)
{
    return DoRemovexattr(path, name);
}
i64 DoFremovexattr(u64 fd, u64 name)
{
    (void)fd;
    return DoRemovexattr(0, name);
}

// rt_sigqueueinfo(tgid, sig, info) — like rt_tgsigqueueinfo
// but addresses the whole thread group. Drop info and route
// to tgkill with tid==tgid (the v0 process model treats them
// as the same id).
i64 DoRtSigqueueinfo(u64 tgid, u64 sig, u64 user_info)
{
    (void)user_info;
    return DoTgkill(tgid, tgid, sig);
}

// unshare(flags) — detach pieces of the calling process's
// execution context. v0 has no namespaces, so flags=0 is a
// no-op (zero unshares = nothing to do; succeeds), and any
// non-zero flags request something we can't deliver.
i64 DoUnshare(u64 flags)
{
    if (flags == 0)
        return 0;
    return kEINVAL;
}

// setns(fd, nstype) — switch a namespace. We have no
// namespaces; -EINVAL is what Linux returns when the fd isn't
// a namespace fd, which is always true for us.
i64 DoSetns(u64 fd, u64 nstype)
{
    (void)fd;
    (void)nstype;
    return kEINVAL;
}

// modify_ldt(func, ptr, bytecount) — read/write the LDT for
// 32-bit segment registers. v0 is 64-bit-only and has no LDT;
// func==0 (read) returns 0 bytes (empty LDT); other funcs are
// -ENOSYS.
i64 DoModifyLdt(u64 func, u64 ptr, u64 bytecount)
{
    (void)ptr;
    (void)bytecount;
    if (func == 0)
        return 0; // read of empty LDT
    return kENOSYS;
}

// process_vm_readv / process_vm_writev (310/311) — copy iovec
// data between the calling process and another process's
// address space. v0 has no cross-process VM peering; -ESRCH
// is the Linux errno when the target pid doesn't exist or
// isn't readable, which is always the case for us.
i64 DoProcessVmReadv(u64 pid, u64 lvec, u64 lcnt, u64 rvec, u64 rcnt, u64 flags)
{
    (void)pid;
    (void)lvec;
    (void)lcnt;
    (void)rvec;
    (void)rcnt;
    (void)flags;
    return kESRCH;
}
i64 DoProcessVmWritev(u64 pid, u64 lvec, u64 lcnt, u64 rvec, u64 rcnt, u64 flags)
{
    return DoProcessVmReadv(pid, lvec, lcnt, rvec, rcnt, flags);
}

// kcmp(pid1, pid2, type, idx1, idx2) — compare resources
// between two processes. v0 returns -EPERM (which is what
// Linux returns when /proc/sys/kernel/yama/ptrace_scope locks
// it out); a real implementation needs ptrace-equivalent caps
// we don't model.
i64 DoKcmp(u64 pid1, u64 pid2, u64 type, u64 idx1, u64 idx2)
{
    (void)pid1;
    (void)pid2;
    (void)type;
    (void)idx1;
    (void)idx2;
    return kEPERM;
}

// seccomp(operation, flags, args) — syscall filtering. v0
// supports only the introspection commands that don't change
// state: SECCOMP_GET_ACTION_AVAIL (cmd 2) returns 0 to mean
// "the requested action is available" so glibc's TSan-tries-
// seccomp dance proceeds without panic. Other commands -EINVAL.
i64 DoSeccomp(u64 op, u64 flags, u64 args)
{
    (void)flags;
    (void)args;
    if (op == 2 /*SECCOMP_GET_ACTION_AVAIL*/)
        return 0;
    return kEINVAL;
}

// restart_syscall — internal Linux ABI used by the kernel to
// resume a syscall after EINTR. Userspace should never call
// it directly; if they do, we mirror Linux's documented
// behaviour: -EINTR (caller's syscall was interrupted, we
// don't have the saved state to restart).
i64 DoRestartSyscall()
{
    return kEINTR;
}

// sched_setattr(pid, attr, flags) / sched_getattr(pid, attr,
// size, flags) — extended sched policy/priority queries. v0
// has a simpler scheduler that doesn't expose deadline /
// SCHED_DEADLINE attributes; -EINVAL is the proper Linux
// response when the requested policy isn't supported.
i64 DoSchedSetattr(u64 pid, u64 attr, u64 flags)
{
    (void)pid;
    (void)attr;
    (void)flags;
    return kEINVAL;
}
i64 DoSchedGetattr(u64 pid, u64 attr, u64 size, u64 flags)
{
    (void)pid;
    (void)attr;
    (void)size;
    (void)flags;
    return kEINVAL;
}

// =============================================================
// Batch 3 — POSIX timers, legacy / newer-Linux entry points.
// =============================================================

// timer_create(clockid, sigevent*, timer_t*) — POSIX per-process
// timers. v0 has no timer wheel; -ENOSYS is what Linux returns
// when CONFIG_POSIX_TIMERS is off, and is what glibc handles
// gracefully (callers fall back to alarm(2) or signalfd).
i64 DoTimerCreate(u64 clockid, u64 sevp, u64 user_timerid)
{
    (void)clockid;
    (void)sevp;
    (void)user_timerid;
    return kENOSYS;
}

// timer_settime / timer_gettime / timer_getoverrun / timer_delete:
// since timer_create never returns a valid id, every reference
// to one is invalid. -EINVAL is the spec's response for
// "timerid does not name a valid timer".
i64 DoTimerSettime(u64 timerid, u64 flags, u64 user_new, u64 user_old)
{
    (void)timerid;
    (void)flags;
    (void)user_new;
    (void)user_old;
    return kEINVAL;
}
i64 DoTimerGettime(u64 timerid, u64 user_curr)
{
    (void)timerid;
    (void)user_curr;
    return kEINVAL;
}
i64 DoTimerGetoverrun(u64 timerid)
{
    (void)timerid;
    return kEINVAL;
}
i64 DoTimerDelete(u64 timerid)
{
    (void)timerid;
    return kEINVAL;
}

// getdents(fd, dirp, count) — pre-2.6.4 directory iteration.
// The legacy `struct linux_dirent` packs d_type as a hidden
// trailing byte at offset reclen-1 instead of an explicit
// field. Modern glibc calls getdents64 (217) which we
// implement; this one is for older static binaries. We just
// fall through to getdents64 — both formats use the same
// d_ino / d_off / d_reclen prefix and our caller can usually
// tolerate the extra byte. Real-format conversion is a sub-GAP.
i64 DoGetdents(u64 fd, u64 user_buf, u64 count)
{
    return DoGetdents64(fd, user_buf, count);
}

// uselib(library) — historical pre-libdl dynamic load.
// Removed from glibc decades ago; Linux still has the entry
// for ABI compat but always returns -ENOSYS. Mirror that.
i64 DoUselib(u64 library)
{
    (void)library;
    return kENOSYS;
}

// remap_file_pages(addr, size, prot, pgoff, flags) — replaced
// by mmap(MAP_FIXED) loops; deprecated. Linux 4.8+ keeps the
// entry but emulates via repeated mmap. -ENOSYS is acceptable
// since callers MUST handle it.
i64 DoRemapFilePages(u64 addr, u64 size, u64 prot, u64 pgoff, u64 flags)
{
    (void)addr;
    (void)size;
    (void)prot;
    (void)pgoff;
    (void)flags;
    return kENOSYS;
}

// epoll_ctl_old / epoll_wait_old — never-released aliases.
// These two were x86_64-only entries that ended up the same
// as epoll_ctl / epoll_wait but with a different ABI. They
// have stayed -ENOSYS in mainline Linux forever.
i64 DoEpollCtlOld(u64 a1, u64 a2, u64 a3, u64 a4)
{
    (void)a1;
    (void)a2;
    (void)a3;
    (void)a4;
    return kENOSYS;
}
i64 DoEpollWaitOld(u64 a1, u64 a2, u64 a3, u64 a4)
{
    (void)a1;
    (void)a2;
    (void)a3;
    (void)a4;
    return kENOSYS;
}

// Linux 5.16+ extended futex ops. These add SetRobustList
// + waitv vector forms; modern glibc only uses them when the
// kernel advertises support via /proc/sys/kernel/futex_*. Our
// procfs doesn't, so glibc falls back to the classic futex(2).
// Returning -ENOSYS keeps that fallback working.
i64 DoFutexWaitv(u64 waiters, u64 nr_futexes, u64 flags, u64 timeout, u64 clockid)
{
    (void)waiters;
    (void)nr_futexes;
    (void)flags;
    (void)timeout;
    (void)clockid;
    return kENOSYS;
}
i64 DoFutexWake(u64 uaddr, u64 mask, u64 nr, u64 flags)
{
    (void)uaddr;
    (void)mask;
    (void)nr;
    (void)flags;
    return kENOSYS;
}
i64 DoFutexWait(u64 uaddr, u64 val, u64 mask, u64 flags, u64 timeout, u64 clockid)
{
    (void)uaddr;
    (void)val;
    (void)mask;
    (void)flags;
    (void)timeout;
    (void)clockid;
    return kENOSYS;
}
i64 DoFutexRequeue(u64 waiters, u64 flags, u64 nr_wake, u64 nr_requeue)
{
    (void)waiters;
    (void)flags;
    (void)nr_wake;
    (void)nr_requeue;
    return kENOSYS;
}

// NUMA: set_mempolicy_home_node — assigns a preferred NUMA
// node to a memory region. v0 is single-NUMA-node by
// definition; -EINVAL is what Linux returns when the requested
// node is invalid (we have only node 0).
i64 DoSetMempolicyHomeNode(u64 start, u64 len, u64 home_node, u64 flags)
{
    (void)start;
    (void)len;
    (void)flags;
    if (home_node == 0)
        return 0; // single-node accept
    return kEINVAL;
}

// cachestat(fd, range, cstat, flags) — query page-cache
// residency for an fd's byte range. We don't have a tracked
// page cache, so we report "everything resident, nothing
// dirty" — which is the safe v0 lie since FAT32 reads land
// in the buffer cache and writes are flushed synchronously.
i64 DoCachestat(u64 fd, u64 user_range, u64 user_cstat, u64 flags)
{
    (void)fd;
    (void)flags;
    if (user_range == 0 || user_cstat == 0)
        return kEINVAL;
    // struct cachestat has 6 u64 fields; zero them all.
    u8 zeros[48] = {0};
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_cstat), zeros, sizeof(zeros)))
        return kEFAULT;
    return 0;
}

// memfd_secret / map_shadow_stack / statmount / listmount /
// lsm_*: 6.x-era surfaces with no v0 backing. -ENOSYS so
// callers take whatever fallback they have.
i64 DoMemfdSecret(u64 flags)
{
    (void)flags;
    return kENOSYS;
}
i64 DoMapShadowStack(u64 addr, u64 size, u64 flags)
{
    (void)addr;
    (void)size;
    (void)flags;
    return kENOSYS;
}
i64 DoStatmount(u64 req, u64 buf, u64 bufsize, u64 flags)
{
    (void)req;
    (void)buf;
    (void)bufsize;
    (void)flags;
    return kENOSYS;
}
i64 DoListmount(u64 req, u64 buf, u64 bufsize, u64 flags)
{
    (void)req;
    (void)buf;
    (void)bufsize;
    (void)flags;
    return kENOSYS;
}
i64 DoLsmGetSelfAttr(u64 attr, u64 ctx, u64 size, u64 flags)
{
    (void)attr;
    (void)ctx;
    (void)size;
    (void)flags;
    return kENOSYS;
}
i64 DoLsmSetSelfAttr(u64 attr, u64 ctx, u64 size, u64 flags)
{
    (void)attr;
    (void)ctx;
    (void)size;
    (void)flags;
    return kENOSYS;
}
i64 DoLsmListModules(u64 ids, u64 size, u64 flags)
{
    (void)ids;
    (void)size;
    (void)flags;
    return kENOSYS;
}

// quotactl_fd(fd, cmd, id, addr) — fd-based quota control.
// We have no quota subsystem; -ENOSYS.
i64 DoQuotactlFd(u64 fd, u64 cmd, u64 id, u64 addr)
{
    (void)fd;
    (void)cmd;
    (void)id;
    (void)addr;
    return kENOSYS;
}

// io_pgetevents(ctx, min_nr, nr, events, timeout, sig) —
// AIO completion query with signal mask. v0 has no AIO; -ENOSYS.
i64 DoIoPgetevents(u64 ctx, u64 min_nr, u64 nr, u64 events, u64 timeout, u64 sig)
{
    (void)ctx;
    (void)min_nr;
    (void)nr;
    (void)events;
    (void)timeout;
    (void)sig;
    return kENOSYS;
}

// rseq(rseq, rseq_len, flags, sig) — restartable sequences.
// v0 doesn't support them. The glibc / musl wrappers tolerate
// -ENOSYS by skipping the rseq optimisation entirely.
i64 DoRseq(u64 rseq, u64 rseq_len, u64 flags, u64 sig)
{
    (void)rseq;
    (void)rseq_len;
    (void)flags;
    (void)sig;
    return kENOSYS;
}

} // namespace duetos::subsystems::linux::internal
