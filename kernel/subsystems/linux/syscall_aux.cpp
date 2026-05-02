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

} // namespace duetos::subsystems::linux::internal
