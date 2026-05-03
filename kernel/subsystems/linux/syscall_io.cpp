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

namespace duetos::subsystems::linux::internal
{

namespace
{

// Per-process Linux fd cap on a single write/read. A real kernel
// wouldn't impose this but musl's newline-buffered stdout rarely
// issues writes over a few KiB. Cap matches the native int-0x80
// write path so behaviour stays predictable across ABIs.
constexpr u64 kLinuxIoMax = 4096;

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
    if (p == nullptr || p->linux_fds[fd].state == 0)
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Linux, "linux/io", "write: fd not open (state=0) -> EBADF; fd", fd);
        return kEBADF;
    }
    // Pipe-write end → dispatch to pipe pool.
    if (p->linux_fds[fd].state == 4)
        return PipeWrite(p->linux_fds[fd].first_cluster, user_buf, len);
    // Eventfd → dispatch to eventfd pool (counter add).
    if (p->linux_fds[fd].state == 5)
        return EventfdWrite(p->linux_fds[fd].first_cluster, user_buf, len);
    // Socket → dispatch to socket layer.
    if (p->linux_fds[fd].state == 6)
        return SocketFdWrite(p->linux_fds[fd].first_cluster, user_buf, len);
    // Pipe-read end / timerfd / signalfd / epoll / inotify — all
    // read-only fd kinds reject writes with -EBADF, matching Linux.
    if (p->linux_fds[fd].state == 3 || p->linux_fds[fd].state == 7 || p->linux_fds[fd].state == 8 ||
        p->linux_fds[fd].state == 9 || p->linux_fds[fd].state == 10 || p->linux_fds[fd].state == 12 ||
        p->linux_fds[fd].state == 13 || p->linux_fds[fd].state == 14 || p->linux_fds[fd].state == 15)
        return kEBADF;
    if (p->linux_fds[fd].state == 11)
        return kEISDIR;
    if (p->linux_fds[fd].state != 2)
        return kEBADF;
    // Canary wall — handle-stamped variant. Stamped at open
    // time by `DoOpen`; closes the in-place-overwrite gap the
    // O_CREAT-time check couldn't cover. CanaryTrip will flag
    // the calling task for kill; we surface -EACCES so the
    // caller's strerror is consistent with other denials.
    if ((p->linux_fds[fd].flags & core::Process::kLinuxFdFlagCanary) != 0)
    {
        ::duetos::security::CanaryTrip(p->linux_fds[fd].path, "write-existing");
        return kEACCES;
    }
    // Subsystem isolation: file mutation requires kCapFsWrite —
    // same gate the native ABI's SYS_FILE_WRITE enforces. Linux
    // ELF binaries don't get to skip the gate by entering through
    // their ABI front-end. See
    // .claude/knowledge/subsystem-isolation-decision-v0.md.
    if (!core::CapSetHas(p->caps, core::kCapFsWrite))
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Linux, "linux/io", "write: kCapFsWrite gate REFUSED -> EACCES; fd", fd);
        core::RecordSandboxDenial(core::kCapFsWrite);
        return kEACCES;
    }

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
        // SPECIAL CASE: if the fd carries kLinuxFdFlagPendingCreate
        // (O_CREAT-on-not-yet-existing), the file's dir entry
        // doesn't exist on disk yet — route through
        // Fat32CreateAtPath instead, which allocates the entry +
        // first cluster + writes the bytes in one shot. Clear the
        // flag so subsequent writes go through the normal append
        // path.
        i64 n = -1;
        if (p->linux_fds[fd].flags & core::Process::kLinuxFdFlagPendingCreate)
        {
            n = fs::fat32::Fat32CreateAtPath(v, p->linux_fds[fd].path, kbuf + written, extend_len);
            if (n >= 0)
            {
                p->linux_fds[fd].flags =
                    static_cast<u8>(p->linux_fds[fd].flags & ~core::Process::kLinuxFdFlagPendingCreate);
                // Re-look up the just-created entry so first_cluster
                // is populated for subsequent in-bounds writes.
                fs::fat32::DirEntry e;
                if (fs::fat32::Fat32LookupPath(v, p->linux_fds[fd].path, &e))
                    p->linux_fds[fd].first_cluster = e.first_cluster;
            }
        }
        else
        {
            n = fs::fat32::Fat32AppendAtPath(v, p->linux_fds[fd].path, kbuf + written, extend_len);
        }
        if (n < 0)
        {
            p->linux_fds[fd].offset = off + written;
            return written > 0 ? static_cast<i64>(written) : kEIO;
        }
        written += static_cast<u64>(n);
        // Update the cached size — AppendAtPath / CreateAtPath just
        // extended the on-disk size; our cached copy follows.
        p->linux_fds[fd].size = static_cast<u32>(size + (to_copy - (size - off)));
    }
    p->linux_fds[fd].offset = off + written;
    // Ransomware-rate guard. Same hook the Win32 SYS_FILE_WRITE
    // path uses (see kernel/fs/file_route.cpp WriteForProcess).
    // Subsystem isolation: a Linux ELF turning malicious has to
    // pass the same byte-rate cap as a native or Win32 PE.
    ::duetos::core::RecordFsWrite(p, written);
    return static_cast<i64>(written);
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
    // Pipe-read end → dispatch to pipe pool.
    if (p->linux_fds[fd].state == 3)
        return PipeRead(p->linux_fds[fd].first_cluster, user_buf, len);
    // Eventfd → dispatch to eventfd pool (counter read).
    if (p->linux_fds[fd].state == 5)
        return EventfdRead(p->linux_fds[fd].first_cluster, user_buf, len);
    // Socket → dispatch to socket layer.
    if (p->linux_fds[fd].state == 6)
        return SocketFdRead(p->linux_fds[fd].first_cluster, user_buf, len);
    // Timerfd / signalfd → dispatch to async-I/O pools.
    if (p->linux_fds[fd].state == 7)
        return TimerfdRead(p->linux_fds[fd].first_cluster, user_buf, len);
    if (p->linux_fds[fd].state == 8)
        return SignalfdRead(p->linux_fds[fd].first_cluster, user_buf, len);
    // Epoll instance — Linux returns -EINVAL on read.
    if (p->linux_fds[fd].state == 9)
        return kEINVAL;
    // Inotify instance → drain event ring.
    if (p->linux_fds[fd].state == 10)
        return InotifyRead(p->linux_fds[fd].first_cluster, user_buf, len);
    // Directory iterator — read() on a dirfd is an error in Linux;
    // callers must use getdents64 instead.
    if (p->linux_fds[fd].state == 11)
        return kEISDIR;
    // pidfd — read is unsupported on Linux too.
    if (p->linux_fds[fd].state == 12)
        return kEINVAL;
    // POSIX message queue — must use mq_timedreceive, not read.
    if (p->linux_fds[fd].state == 13)
        return kEBADF;
    // memfd — read/write only via mmap in v0.
    if (p->linux_fds[fd].state == 14)
        return kEBADF;
    // fanotify instance — drain event ring.
    if (p->linux_fds[fd].state == 15)
        return FanotifyRead(p->linux_fds[fd].first_cluster, user_buf, len);
    // Pipe-write end is write-only.
    if (p->linux_fds[fd].state == 4)
        return kEBADF;
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
    KLOG_TRACE_AV(::duetos::core::LogArea::Linux, "linux/io", "lseek ENTRY; fd", fd);
    KLOG_TRACE_AV(::duetos::core::LogArea::Linux, "linux/io", "  offset", static_cast<u64>(offset));
    KLOG_TRACE_AV(::duetos::core::LogArea::Linux, "linux/io", "  whence", whence);
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd >= 16)
        return kEBADF;
    if (p->linux_fds[fd].state == 1)
    {
        KLOG_DEBUG_AV(::duetos::core::LogArea::Linux, "linux/io", "lseek on tty -> ESPIPE; fd", fd);
        return kESPIPE; // tty: can't seek
    }
    if (p->linux_fds[fd].state != 2)
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Linux, "linux/io", "lseek: fd not a regular file -> EBADF; fd", fd);
        return kEBADF;
    }

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
    if (p->linux_fds[fd].state == 0)
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Linux, "linux/io", "ioctl: fd not open -> EBADF; fd", fd);
        return kEBADF;
    }
    const bool is_tty = (p->linux_fds[fd].state == 1);
    if (!is_tty)
    {
        KLOG_DEBUG_AV(::duetos::core::LogArea::Linux, "linux/io", "ioctl: fd is not a tty -> ENOTTY; fd", fd);
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
    (void)fd;
    (void)offset;
    (void)nbytes;
    (void)flags;
    return DoSync();
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
    auto& slot = p->linux_fds[fd];
    if (slot.state != 2 /*regular file*/)
        return kEBADF;
    const u64 want_end = offset + len;
    if (want_end <= slot.size)
        return 0; // already large enough; mode==0 spec is satisfied.
    const auto* v = ::duetos::fs::fat32::Fat32Volume(0);
    if (v == nullptr)
        return kENOENT;
    const i64 rc = ::duetos::fs::fat32::Fat32TruncateAtPath(v, slot.path, want_end);
    if (rc < 0)
        return kEIO;
    slot.size = static_cast<u32>(want_end);
    return 0;
}

} // namespace duetos::subsystems::linux::internal
