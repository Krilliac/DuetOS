/*
 * DuetOS — Linux ABI: I/O handlers.
 *
 * Sibling TU of syscall.cpp. Houses read / write / lseek / ioctl
 * / fsync / fdatasync / pread64 / pwrite64 / readv / writev.
 *
 * fd 0 (stdin) reads return 0 (EOF). fd 1 / 2 (stdout / stderr)
 * writes go to COM1; reads return -EBADF. fd >= 3 are FAT32
 * file handles tracked in core::Process::linux_fds.
 *
 * write supports both in-bounds (Fat32WriteInPlace) and extending
 * (Fat32AppendAtPath) regions; off > size returns -EINVAL (FAT32
 * has no sparse-file support yet).
 *
 * read scratches the entire file (4 KiB cap), then slices from
 * the per-fd offset. A streaming offset-aware read helper in the
 * FAT32 driver is the next iteration.
 *
 * ioctl handles three TTY commands: TCGETS (returns a sane
 * termios so isatty passes), TCSETS / TCSETSW / TCSETSF (accept
 * + ignore), TIOCGWINSZ (fake 80×24).
 */

#include "subsystems/linux/fanotify.h"
#include "subsystems/linux/inotify.h"
#include "subsystems/linux/syscall_async_io.h"
#include "subsystems/linux/syscall_internal.h"
#include "subsystems/linux/syscall_pipe.h"
#include "subsystems/linux/syscall_socket.h"

#include "arch/x86_64/serial.h"
#include "fs/fat32.h"
#include "log/klog.h"
#include "mm/address_space.h"
#include "proc/process.h"
#include "security/canary.h"
#include "util/nospec.h"

namespace duetos::subsystems::linux::internal
{

namespace
{

// Per-process Linux fd cap on a single write/read. A real kernel
// wouldn't impose this but musl's newline-buffered stdout rarely
// issues writes over a few KiB. Cap matches the native int-0x80
// write path so behaviour stays predictable across ABIs.
constexpr u64 kLinuxIoMax = 4096;

constexpr u32 kOAccmode = 0x3;
constexpr u32 kOWronly = 0x1;
constexpr u32 kOAppend = 0x400;
constexpr u32 kONonblock = 0x800;

bool SnapshotAcquiredNonblocking(const core::LinuxFdAcquired& acquired, bool* nonblocking_out)
{
    if (nonblocking_out == nullptr)
        return false;
    *nonblocking_out = false;
    core::LinuxFdIoGuard guard{};
    if (!core::LinuxFdIoGuardEnter(&acquired, &guard))
        return false;
    u32 status_flags = 0;
    const bool valid = core::LinuxFdIoGuardGetStatusFlags(&guard, &status_flags);
    core::LinuxFdIoGuardExit(&guard);
    if (!valid)
        return false;
    *nonblocking_out = (status_flags & kONonblock) != 0;
    return true;
}

i64 FinishRegularIo(core::LinuxFdIoGuard* guard, core::LinuxFdAcquired* acquired, i64 result)
{
    core::LinuxFdIoGuardExit(guard);
    core::LinuxFdAcquiredRelease(acquired);
    return result;
}

i64 FinishRegularWrite(core::Process* process, core::LinuxFdIoGuard* guard, core::LinuxFdAcquired* acquired,
                       u64 written, i64 result)
{
    core::LinuxFdIoGuardExit(guard);
    core::LinuxFdAcquiredRelease(acquired);
    if (written != 0)
        core::RecordFsWrite(process, written);
    return result;
}

i64 ReadRegularAcquired(core::Process* process, u32 fd, core::LinuxFdAcquired* acquired, u64 user_buf, u64 len,
                        bool positioned, u64 position)
{
    core::LinuxFdIoGuard guard{};
    if (!core::LinuxFdIoGuardEnter(acquired, &guard))
    {
        core::LinuxFdAcquiredRelease(acquired);
        return kEBADF;
    }

    core::Process::LinuxFd snapshot{};
    u32 status_flags = 0;
    if (!core::LinuxFdRefreshAcquired(process, fd, acquired, &guard, &snapshot) ||
        !core::LinuxFdIoGuardGetStatusFlags(&guard, &status_flags))
        return FinishRegularIo(&guard, acquired, kEBADF);
    if ((status_flags & kOAccmode) == kOWronly)
        return FinishRegularIo(&guard, acquired, kEBADF);
    if (len == 0)
        return FinishRegularIo(&guard, acquired, 0);

    const auto* volume = fs::fat32::Fat32Volume(0);
    if (volume == nullptr)
        return FinishRegularIo(&guard, acquired, kEIO);

    u8 scratch[kLinuxIoMax];
    fs::fat32::DirEntry entry{};
    entry.first_cluster = snapshot.first_cluster;
    entry.size_bytes = snapshot.size;
    const i64 total = fs::fat32::Fat32ReadFile(volume, &entry, scratch, sizeof(scratch));
    if (total < 0)
        return FinishRegularIo(&guard, acquired, kEIO);

    u64 offset = position;
    if (!positioned && !core::LinuxFdIoGuardGetOffset(&guard, &offset))
        return FinishRegularIo(&guard, acquired, kEBADF);
    const u64 size = static_cast<u64>(total);
    if (offset >= size)
        return FinishRegularIo(&guard, acquired, 0);

    u64 to_copy = size - offset;
    if (to_copy > len)
        to_copy = len;
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_buf), scratch + offset, to_copy))
        return FinishRegularIo(&guard, acquired, kEFAULT);
    if (!positioned && !core::LinuxFdIoGuardSetOffset(&guard, offset + to_copy))
        return FinishRegularIo(&guard, acquired, kEBADF);
    return FinishRegularIo(&guard, acquired, static_cast<i64>(to_copy));
}

i64 WriteRegularAcquired(core::Process* process, u32 fd, core::LinuxFdAcquired* acquired, u64 user_buf, u64 len,
                         bool positioned, u64 position)
{
    // Canary is descriptor-local and immutable for the lifetime of this exact
    // receipt, so trip the wall before taking the sleepable OFD I/O guard.
    if ((acquired->snapshot.flags & core::Process::kLinuxFdFlagCanary) != 0)
    {
        ::duetos::security::CanaryTrip(acquired->snapshot.path, "write-existing");
        core::LinuxFdAcquiredRelease(acquired);
        return kEACCES;
    }
    if (!core::ProcessHasCap(process, core::kCapFsWrite))
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Linux, "linux/io", "write: kCapFsWrite gate REFUSED -> EACCES; fd", fd);
        core::RecordSandboxDenial(core::kCapFsWrite);
        core::LinuxFdAcquiredRelease(acquired);
        return kEACCES;
    }

    core::LinuxFdIoGuard guard{};
    if (!core::LinuxFdIoGuardEnter(acquired, &guard))
    {
        core::LinuxFdAcquiredRelease(acquired);
        return kEBADF;
    }

    core::Process::LinuxFd snapshot{};
    u32 status_flags = 0;
    if (!core::LinuxFdRefreshAcquired(process, fd, acquired, &guard, &snapshot) ||
        !core::LinuxFdIoGuardGetStatusFlags(&guard, &status_flags))
        return FinishRegularIo(&guard, acquired, kEBADF);
    if ((status_flags & kOAccmode) == 0)
        return FinishRegularIo(&guard, acquired, kEBADF);
    if (len == 0)
        return FinishRegularIo(&guard, acquired, 0);

    const u64 size = snapshot.size;
    u64 offset = position;
    if (!positioned)
    {
        if (!core::LinuxFdIoGuardGetOffset(&guard, &offset))
            return FinishRegularIo(&guard, acquired, kEBADF);
        if ((status_flags & kOAppend) != 0)
            offset = size;
    }
    if (offset > size)
        return FinishRegularIo(&guard, acquired, kEINVAL);

    u64 to_copy = len;
    if (to_copy > kLinuxIoMax)
        to_copy = kLinuxIoMax;
    constexpr u64 kFat32MaxFileSize = static_cast<u64>(~u32(0));
    if (to_copy > kFat32MaxFileSize - offset)
        return FinishRegularIo(&guard, acquired, kEFBIG);

    u8 kbuf[kLinuxIoMax];
    if (!mm::CopyFromUser(kbuf, reinterpret_cast<const void*>(user_buf), to_copy))
        return FinishRegularIo(&guard, acquired, kEFAULT);
    const auto* volume = fs::fat32::Fat32Volume(0);
    if (volume == nullptr)
        return FinishRegularIo(&guard, acquired, kEIO);

    u64 written = 0;
    if (offset < size)
    {
        const u64 in_bounds_len = (size - offset < to_copy) ? (size - offset) : to_copy;
        fs::fat32::DirEntry entry{};
        entry.first_cluster = snapshot.first_cluster;
        entry.size_bytes = snapshot.size;
        const i64 count = fs::fat32::Fat32WriteInPlace(volume, &entry, offset, kbuf, in_bounds_len);
        if (count < 0)
            return FinishRegularIo(&guard, acquired, kEIO);
        written = static_cast<u64>(count);
        if (written < in_bounds_len)
        {
            if (!positioned && !core::LinuxFdIoGuardSetOffset(&guard, offset + written))
                return FinishRegularWrite(process, &guard, acquired, written, kEBADF);
            return FinishRegularWrite(process, &guard, acquired, written, static_cast<i64>(written));
        }
    }

    bool clear_pending_create = false;
    bool update_first_cluster = false;
    u32 first_cluster = snapshot.first_cluster;
    if (written < to_copy)
    {
        const u64 extend_len = to_copy - written;
        i64 count = -1;
        if ((snapshot.flags & core::Process::kLinuxFdFlagPendingCreate) != 0)
        {
            count = fs::fat32::Fat32CreateAtPath(volume, snapshot.path, kbuf + written, extend_len);
            if (count >= 0)
            {
                clear_pending_create = true;
                fs::fat32::DirEntry created{};
                if (fs::fat32::Fat32LookupPath(volume, snapshot.path, &created))
                {
                    update_first_cluster = true;
                    first_cluster = created.first_cluster;
                }
            }
        }
        else
        {
            count = fs::fat32::Fat32AppendAtPath(volume, snapshot.path, kbuf + written, extend_len);
        }
        if (count < 0)
        {
            if (!positioned && !core::LinuxFdIoGuardSetOffset(&guard, offset + written))
                return FinishRegularWrite(process, &guard, acquired, written, kEBADF);
            const i64 result = written != 0 ? static_cast<i64>(written) : kEIO;
            return FinishRegularWrite(process, &guard, acquired, written, result);
        }
        written += static_cast<u64>(count);
    }

    const u64 final_end = offset + written;
    core::LinuxFdRegularMetadataCommit commit{};
    if (clear_pending_create)
    {
        commit.flags_mask = core::Process::kLinuxFdFlagPendingCreate;
        commit.flags_value = 0;
    }
    commit.update_first_cluster = update_first_cluster;
    commit.first_cluster = first_cluster;
    commit.update_size = final_end > size;
    commit.size = static_cast<u32>(commit.update_size ? final_end : size);
    if ((commit.flags_mask != 0 || commit.update_first_cluster || commit.update_size) &&
        !core::LinuxFdCommitRegularMetadataAcquired(process, fd, acquired, &guard, &commit))
        return FinishRegularWrite(process, &guard, acquired, written,
                                  written != 0 ? static_cast<i64>(written) : kEBADF);
    if (!positioned && !core::LinuxFdIoGuardSetOffset(&guard, final_end))
        return FinishRegularWrite(process, &guard, acquired, written,
                                  written != 0 ? static_cast<i64>(written) : kEBADF);
    return FinishRegularWrite(process, &guard, acquired, written, static_cast<i64>(written));
}

} // namespace

// Linux: write(fd, buf, count). v0 implements fd=1 (stdout) and
// fd=2 (stderr) only — both go to COM1. Everything else returns
// -EBADF so musl's perror / write-to-pipe error paths surface
// predictably.
i64 DoWrite(u64 fd, u64 user_buf, u64 len)
{
    KLOG_TRACE_AV(::duetos::core::LogArea::Linux, "linux/io", "write ENTRY; fd", fd);
    KLOG_TRACE_AV(::duetos::core::LogArea::Linux, "linux/io", "  len", len);
    // fd 1/2 -> COM1 (unchanged from v0).
    if (fd == 1 || fd == 2)
    {
        const u64 to_copy = (len > kLinuxIoMax) ? kLinuxIoMax : len;
        if (to_copy == 0)
            return 0;
        u8 kbuf[kLinuxIoMax];
        if (!mm::CopyFromUser(kbuf, reinterpret_cast<const void*>(user_buf), to_copy))
        {
            KLOG_WARN_AV(::duetos::core::LogArea::Linux, "linux/io",
                         "write(stdout/stderr): CopyFromUser failed -> EFAULT; user_buf", user_buf);
            return kEFAULT;
        }
        arch::SerialWriteN(reinterpret_cast<const char*>(kbuf), to_copy);
        return static_cast<i64>(to_copy);
    }
    // fd 0 (stdin) rejects write; unused fds too.
    if (fd == 0 || fd >= 16)
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Linux, "linux/io", "write: fd out of range or stdin -> EBADF; fd", fd);
        return kEBADF;
    }
    core::Process* p = core::CurrentProcess();
    if (p == nullptr)
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Linux, "linux/io", "write: no Process -> EBADF; fd", fd);
        return kEBADF;
    }
    // Spectre v1 nospec: even though the runtime check above proves
    // fd < 16, the speculator could redirect through the branch and
    // dereference linux_fds[fd] for an OOB fd. Mask the index so the
    // speculative load is bounded to [0, 16). wiki/security/Linux-CVE-Audit.md
    // class N.
    fd = util::MaskedIndex(fd, 16);
    core::LinuxFdAcquired acquired{};
    if (!core::LinuxFdAcquire(p, static_cast<u32>(fd), 0, &acquired))
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Linux, "linux/io", "write: fd not open (state=0) -> EBADF; fd", fd);
        return kEBADF;
    }
    const u8 state = acquired.snapshot.state;
    // Pipe-write end → dispatch to pipe pool.
    if (state == 4)
    {
        const i64 result = PipeWrite(acquired.snapshot.first_cluster, user_buf, len);
        core::LinuxFdAcquiredRelease(&acquired);
        return result;
    }
    // Eventfd → dispatch to eventfd pool (counter add).
    if (state == 5)
    {
        const i64 result = EventfdWrite(acquired.snapshot.first_cluster, user_buf, len);
        core::LinuxFdAcquiredRelease(&acquired);
        return result;
    }
    // Socket → dispatch to socket layer.
    if (state == 6)
    {
        const i64 result = SocketFdWrite(acquired.snapshot.first_cluster, user_buf, len);
        core::LinuxFdAcquiredRelease(&acquired);
        return result;
    }
    // Pipe-read end / timerfd / signalfd / epoll / inotify — all
    // read-only fd kinds reject writes with -EBADF, matching Linux.
    if (state == 3 || state == 7 || state == 8 || state == 9 || state == 10 || state == 12 || state == 13 ||
        state == 14 || state == 15)
    {
        core::LinuxFdAcquiredRelease(&acquired);
        return kEBADF;
    }
    if (state == 11)
    {
        core::LinuxFdAcquiredRelease(&acquired);
        return kEISDIR;
    }
    if (state != 2)
    {
        core::LinuxFdAcquiredRelease(&acquired);
        return kEBADF;
    }
    return WriteRegularAcquired(p, static_cast<u32>(fd), &acquired, user_buf, len, false, 0);
}

// Linux: read(fd, buf, count).
//   fd == 0 (stdin): always 0 (EOF).
//   fd == 1 / 2: -EBADF — you can't read stdout/stderr.
//   fd >= 3 file handle: read from the current offset into the
//     user buffer, advance the cursor, return the byte count.
//     Implementation reads the ENTIRE file into scratch and
//     slices — simple, bounded by 4 KiB (v0 file cap).
i64 DoRead(u64 fd, u64 user_buf, u64 len)
{
    KLOG_TRACE_AV(::duetos::core::LogArea::Linux, "linux/io", "read ENTRY; fd", fd);
    KLOG_TRACE_AV(::duetos::core::LogArea::Linux, "linux/io", "  len", len);
    if (fd == 0)
    {
        return 0;
    }
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd >= 16)
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Linux, "linux/io", "read: fd out of range -> EBADF; fd", fd);
        return kEBADF;
    }
    // Spectre v1 nospec — see DoWrite for the rationale.
    fd = util::MaskedIndex(fd, 16);
    core::LinuxFdAcquired acquired{};
    if (!core::LinuxFdAcquire(p, static_cast<u32>(fd), 0, &acquired))
        return kEBADF;
    const u8 state = acquired.snapshot.state;
    // Pipe-read end → dispatch to pipe pool.
    if (state == 3)
    {
        const i64 result = PipeRead(acquired.snapshot.first_cluster, user_buf, len);
        core::LinuxFdAcquiredRelease(&acquired);
        return result;
    }
    // Eventfd → dispatch to eventfd pool (counter read).
    if (state == 5)
    {
        const i64 result = EventfdRead(acquired.snapshot.first_cluster, user_buf, len);
        core::LinuxFdAcquiredRelease(&acquired);
        return result;
    }
    // Socket → dispatch to socket layer.
    if (state == 6)
    {
        const i64 result = SocketFdRead(acquired.snapshot.first_cluster, user_buf, len);
        core::LinuxFdAcquiredRelease(&acquired);
        return result;
    }
    // Timerfd / signalfd → dispatch to async-I/O pools.
    if (state == 7)
    {
        bool nonblocking = false;
        if (!SnapshotAcquiredNonblocking(acquired, &nonblocking))
        {
            core::LinuxFdAcquiredRelease(&acquired);
            return kEBADF;
        }
        const i64 result = TimerfdRead(acquired.snapshot.first_cluster, user_buf, len, nonblocking);
        core::LinuxFdAcquiredRelease(&acquired);
        return result;
    }
    if (state == 8)
    {
        bool nonblocking = false;
        if (!SnapshotAcquiredNonblocking(acquired, &nonblocking))
        {
            core::LinuxFdAcquiredRelease(&acquired);
            return kEBADF;
        }
        const i64 result = SignalfdRead(acquired.snapshot.first_cluster, user_buf, len, nonblocking);
        core::LinuxFdAcquiredRelease(&acquired);
        return result;
    }
    // Epoll instance — Linux returns -EINVAL on read.
    if (state == 9)
    {
        core::LinuxFdAcquiredRelease(&acquired);
        return kEINVAL;
    }
    // Inotify instance → drain event ring.
    if (state == 10)
    {
        bool nonblocking = false;
        if (!SnapshotAcquiredNonblocking(acquired, &nonblocking))
        {
            core::LinuxFdAcquiredRelease(&acquired);
            return kEBADF;
        }
        const i64 result = InotifyRead(acquired.snapshot.first_cluster, user_buf, len, nonblocking);
        core::LinuxFdAcquiredRelease(&acquired);
        return result;
    }
    // Directory iterator — read() on a dirfd is an error in Linux;
    // callers must use getdents64 instead.
    if (state == 11)
    {
        core::LinuxFdAcquiredRelease(&acquired);
        return kEISDIR;
    }
    // pidfd — read is unsupported on Linux too.
    if (state == 12)
    {
        core::LinuxFdAcquiredRelease(&acquired);
        return kEINVAL;
    }
    // POSIX message queue — must use mq_timedreceive, not read.
    if (state == 13)
    {
        core::LinuxFdAcquiredRelease(&acquired);
        return kEBADF;
    }
    // memfd — read/write only via mmap in v0.
    if (state == 14)
    {
        core::LinuxFdAcquiredRelease(&acquired);
        return kEBADF;
    }
    // fanotify instance — drain event ring.
    if (state == 15)
    {
        bool nonblocking = false;
        if (!SnapshotAcquiredNonblocking(acquired, &nonblocking))
        {
            core::LinuxFdAcquiredRelease(&acquired);
            return kEBADF;
        }
        const i64 result = FanotifyRead(acquired.snapshot.first_cluster, user_buf, len, nonblocking);
        core::LinuxFdAcquiredRelease(&acquired);
        return result;
    }
    // Pipe-write end is write-only.
    if (state == 4)
    {
        core::LinuxFdAcquiredRelease(&acquired);
        return kEBADF;
    }
    if (state != 2)
    {
        core::LinuxFdAcquiredRelease(&acquired);
        return kEBADF;
    }
    return ReadRegularAcquired(p, static_cast<u32>(fd), &acquired, user_buf, len, false, 0);
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
    if (user_iov > (~u64(0) - iovcnt * 16))
        return kEFAULT;
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
    if (user_iov > (~u64(0) - iovcnt * 16))
        return kEFAULT;
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
    KLOG_TRACE_AV(::duetos::core::LogArea::Linux, "linux/io", "lseek ENTRY; fd", fd);
    KLOG_TRACE_AV(::duetos::core::LogArea::Linux, "linux/io", "  offset", static_cast<u64>(offset));
    KLOG_TRACE_AV(::duetos::core::LogArea::Linux, "linux/io", "  whence", whence);
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd >= 16)
        return kEBADF;
    fd = util::MaskedIndex(fd, 16);
    core::LinuxFdAcquired acquired{};
    if (!core::LinuxFdAcquire(p, static_cast<u32>(fd), 0, &acquired))
        return kEBADF;
    if (acquired.snapshot.state == 1)
    {
        KLOG_DEBUG_AV(::duetos::core::LogArea::Linux, "linux/io", "lseek on tty -> ESPIPE; fd", fd);
        core::LinuxFdAcquiredRelease(&acquired);
        return kESPIPE; // tty: can't seek
    }
    if (acquired.snapshot.state != 2)
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Linux, "linux/io", "lseek: fd not a regular file -> EBADF; fd", fd);
        core::LinuxFdAcquiredRelease(&acquired);
        return kEBADF;
    }

    core::LinuxFdIoGuard guard{};
    if (!core::LinuxFdIoGuardEnter(&acquired, &guard))
    {
        core::LinuxFdAcquiredRelease(&acquired);
        return kEBADF;
    }
    core::Process::LinuxFd snapshot{};
    if (!core::LinuxFdRefreshAcquired(p, static_cast<u32>(fd), &acquired, &guard, &snapshot))
        return FinishRegularIo(&guard, &acquired, kEBADF);

    u64 base = 0;
    switch (whence)
    {
    case 0:
        break;
    case 1:
        if (!core::LinuxFdIoGuardGetOffset(&guard, &base))
            return FinishRegularIo(&guard, &acquired, kEBADF);
        break;
    case 2:
        base = snapshot.size;
        break;
    default:
        return FinishRegularIo(&guard, &acquired, kEINVAL);
    }

    u64 new_offset = 0;
    if (whence == 0)
    {
        if (offset < 0)
            return FinishRegularIo(&guard, &acquired, kEINVAL);
        new_offset = static_cast<u64>(offset);
    }
    else if (offset >= 0)
    {
        constexpr u64 kSignedOffsetMax = (~u64(0)) >> 1;
        const u64 delta = static_cast<u64>(offset);
        if (delta > kSignedOffsetMax - base)
            return FinishRegularIo(&guard, &acquired, kEOVERFLOW);
        new_offset = base + delta;
    }
    else
    {
        const u64 magnitude = static_cast<u64>(-(offset + 1)) + 1;
        if (magnitude > base)
            return FinishRegularIo(&guard, &acquired, kEINVAL);
        new_offset = base - magnitude;
        constexpr u64 kSignedOffsetMax = (~u64(0)) >> 1;
        if (new_offset > kSignedOffsetMax)
            return FinishRegularIo(&guard, &acquired, kEOVERFLOW);
    }
    if (!core::LinuxFdIoGuardSetOffset(&guard, new_offset))
        return FinishRegularIo(&guard, &acquired, kEBADF);
    return FinishRegularIo(&guard, &acquired, static_cast<i64>(new_offset));
}

// Linux: ioctl(fd, cmd, arg). Handle the three ioctls musl's
// stdio actually reaches under a CRT bring-up:
//   TCGETS      (0x5401) — "is this a tty?" probe.
//   TCSETS      (0x5402) — swallow.
//   TIOCGWINSZ  (0x5413) — report a fake 80×24 terminal.
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
    KLOG_TRACE_AV(::duetos::core::LogArea::Linux, "linux/io", "ioctl ENTRY; fd", fd);
    KLOG_TRACE_AV(::duetos::core::LogArea::Linux, "linux/io", "  cmd", cmd);
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd >= 16)
        return kEBADF;
    core::LinuxFdAcquired acquired{};
    if (!core::LinuxFdAcquire(p, static_cast<u32>(fd), 0, &acquired))
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Linux, "linux/io", "ioctl: fd not open -> EBADF; fd", fd);
        return kEBADF;
    }
    const bool is_tty = (acquired.snapshot.state == 1);
    if (!is_tty)
    {
        KLOG_DEBUG_AV(::duetos::core::LogArea::Linux, "linux/io", "ioctl: fd is not a tty -> ENOTTY; fd", fd);
        core::LinuxFdAcquiredRelease(&acquired);
        return kENOTTY;
    }
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
        t.c_cc[0] = 0x03; // VINTR
        t.c_cc[1] = 0x1C; // VQUIT
        t.c_cc[2] = 0x7F; // VERASE
        t.c_cc[3] = 0x15; // VKILL
        t.c_cc[4] = 0x04; // VEOF
        const bool copied = mm::CopyToUser(reinterpret_cast<void*>(arg), &t, sizeof(t));
        core::LinuxFdAcquiredRelease(&acquired);
        if (!copied)
            return kEFAULT;
        return 0;
    }
    case kTCSETS:
    case kTCSETSW:
    case kTCSETSF:
        // Accept + ignore. The cooked-mode / raw-mode distinction
        // has no observable effect on a serial-only tty today.
        (void)arg;
        core::LinuxFdAcquiredRelease(&acquired);
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
        const bool copied = mm::CopyToUser(reinterpret_cast<void*>(arg), &w, sizeof(w));
        core::LinuxFdAcquiredRelease(&acquired);
        if (!copied)
            return kEFAULT;
        return 0;
    }
    case kTIOCGPGRP:
    {
        // There's no process-group concept in v0; report pid back
        // as the foreground pgid so shells' "am I in the fg?" test
        // resolves to yes.
        const i32 pgid = i32(p->pid);
        const bool copied = mm::CopyToUser(reinterpret_cast<void*>(arg), &pgid, sizeof(pgid));
        core::LinuxFdAcquiredRelease(&acquired);
        if (!copied)
            return kEFAULT;
        return 0;
    }
    default:
        core::LinuxFdAcquiredRelease(&acquired);
        return kEINVAL;
    }
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
    core::LinuxFdAcquired acquired{};
    if (!core::LinuxFdAcquire(p, static_cast<u32>(fd), 0, &acquired))
        return kEBADF;
    core::LinuxFdAcquiredRelease(&acquired);
    return 0;
}
i64 DoFdatasync(u64 fd)
{
    return DoFsync(fd);
}

// Linux: pread64(fd, buf, count, offset). Read at an explicit
// offset without mutating the shared open-file-description cursor.
i64 DoPread64(u64 fd, u64 user_buf, u64 len, i64 offset)
{
    if (fd >= 16)
        return kEBADF;
    core::Process* p = core::CurrentProcess();
    if (p == nullptr)
        return kEBADF;
    if (offset < 0)
        return kEINVAL;
    fd = util::MaskedIndex(fd, 16);
    core::LinuxFdAcquired acquired{};
    if (!core::LinuxFdAcquire(p, static_cast<u32>(fd), 0, &acquired))
        return kEBADF;
    if (acquired.snapshot.state == 11)
    {
        core::LinuxFdAcquiredRelease(&acquired);
        return kEISDIR;
    }
    if (acquired.snapshot.state != 2)
    {
        core::LinuxFdAcquiredRelease(&acquired);
        return kESPIPE;
    }
    return ReadRegularAcquired(p, static_cast<u32>(fd), &acquired, user_buf, len, true, static_cast<u64>(offset));
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
    fd = util::MaskedIndex(fd, 16);
    core::LinuxFdAcquired acquired{};
    if (!core::LinuxFdAcquire(p, static_cast<u32>(fd), 0, &acquired))
        return kEBADF;
    if (acquired.snapshot.state == 11)
    {
        core::LinuxFdAcquiredRelease(&acquired);
        return kEISDIR;
    }
    if (acquired.snapshot.state != 2)
    {
        core::LinuxFdAcquiredRelease(&acquired);
        return kESPIPE;
    }
    return WriteRegularAcquired(p, static_cast<u32>(fd), &acquired, user_buf, len, true, static_cast<u64>(offset));
}

// =============================================================
// Vector forms of the scalar pread/pwrite + sendfile + the
// range-coarse sync_file_range. Each loop walks the user iovec
// with a running byte cursor.
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
    if (user_iov > (~u64(0) - iovcnt * sizeof(UserIovec)))
        return kEFAULT;
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
    if (user_iov > (~u64(0) - iovcnt * sizeof(UserIovec)))
        return kEFAULT;
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
// argument (RWF_HIPRI / RWF_DSYNC / RWF_SYNC / RWF_NOWAIT /
// RWF_APPEND). v0 accepts them silently — the underlying
// handlers don't observe per-call sync semantics.
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

// sendfile(out_fd, in_fd, offset_ptr, count) — fd-to-fd copy
// that lets glibc skip the userspace bounce buffer. v0 puts
// the bounce inside the kernel: read up to ~4 KiB at a time
// from in_fd, write to out_fd, repeat.
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

// sync_file_range(fd, offset, nbytes, flags) — durable flush
// of a byte range. v0 has no per-range flush; route to a
// global Sync (close enough for correctness, way less
// efficient than the spec asks). Caller's data lands.
i64 DoSyncFileRange(u64 fd, u64 offset, u64 nbytes, u64 flags)
{
    (void)offset;
    (void)nbytes;
    (void)flags;
    core::Process* process = core::CurrentProcess();
    if (process == nullptr || fd >= 16)
        return kEBADF;
    fd = util::MaskedIndex(fd, 16);
    core::LinuxFdAcquired acquired{};
    if (!core::LinuxFdAcquire(process, static_cast<u32>(fd), 0, &acquired))
        return kEBADF;
    const i64 result = DoSync();
    core::LinuxFdAcquiredRelease(&acquired);
    return result;
}

// fallocate(fd, mode, offset, len) — preallocate / punch /
// collapse-range. mode==0 is the default "extend the file to
// at least offset+len with zeros if needed" — we implement
// this by routing through Fat32TruncateAtPath when the
// requested end exceeds the current size. Other modes
// (FALLOC_FL_KEEP_SIZE, FALLOC_FL_PUNCH_HOLE, ...) are
// unimplemented (the FAT32 backend has no per-range cluster
// release).
i64 DoFallocate(u64 fd, u64 mode, u64 offset, u64 len)
{
    if (mode != 0)
        return kENOSYS;
    auto* p = ::duetos::core::CurrentProcess();
    if (p == nullptr || fd >= 16)
        return kEBADF;
    // Overflow-safe end computation. Without this, a caller passing
    // offset near u64-max with a small len would wrap `want_end` to
    // a tiny value, bypass the cached-size check, and truncate
    // the file via Fat32TruncateAtPath(..., wrapped_end). Reject
    // before the add.
    if (len > 0 && offset > (~u64(0)) - len)
        return kEINVAL;
    const u64 want_end = offset + len;

    fd = ::duetos::util::MaskedIndex(fd, 16);
    core::LinuxFdAcquired acquired{};
    if (!core::LinuxFdAcquire(p, static_cast<u32>(fd), 0, &acquired))
        return kEBADF;
    if (acquired.snapshot.state != 2)
    {
        core::LinuxFdAcquiredRelease(&acquired);
        return kEBADF;
    }
    if ((acquired.snapshot.flags & core::Process::kLinuxFdFlagCanary) != 0)
    {
        ::duetos::security::CanaryTrip(acquired.snapshot.path, "fallocate-existing");
        core::LinuxFdAcquiredRelease(&acquired);
        return kEACCES;
    }
    if (!core::ProcessHasCap(p, core::kCapFsWrite))
    {
        core::RecordSandboxDenial(core::kCapFsWrite);
        core::LinuxFdAcquiredRelease(&acquired);
        return kEACCES;
    }

    core::LinuxFdIoGuard guard{};
    if (!core::LinuxFdIoGuardEnter(&acquired, &guard))
    {
        core::LinuxFdAcquiredRelease(&acquired);
        return kEBADF;
    }
    core::Process::LinuxFd snapshot{};
    u32 status_flags = 0;
    if (!core::LinuxFdRefreshAcquired(p, static_cast<u32>(fd), &acquired, &guard, &snapshot) ||
        !core::LinuxFdIoGuardGetStatusFlags(&guard, &status_flags))
        return FinishRegularIo(&guard, &acquired, kEBADF);
    if ((status_flags & kOAccmode) == 0)
        return FinishRegularIo(&guard, &acquired, kEBADF);
    if (want_end <= snapshot.size)
        return FinishRegularIo(&guard, &acquired, 0);
    if (want_end > static_cast<u64>(~u32(0)))
        return FinishRegularIo(&guard, &acquired, kEFBIG);
    const auto* v = ::duetos::fs::fat32::Fat32Volume(0);
    if (v == nullptr)
        return FinishRegularIo(&guard, &acquired, kENOENT);
    const i64 rc = ::duetos::fs::fat32::Fat32TruncateAtPath(v, snapshot.path, want_end);
    if (rc < 0)
        return FinishRegularIo(&guard, &acquired, kEIO);

    core::LinuxFdRegularMetadataCommit commit{};
    commit.update_size = true;
    commit.size = static_cast<u32>(want_end);
    const u64 growth = want_end - snapshot.size;
    if (!core::LinuxFdCommitRegularMetadataAcquired(p, static_cast<u32>(fd), &acquired, &guard, &commit))
        return FinishRegularWrite(p, &guard, &acquired, growth, kEBADF);
    return FinishRegularWrite(p, &guard, &acquired, growth, 0);
}

} // namespace duetos::subsystems::linux::internal
