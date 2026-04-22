#include "syscall.h"

#include "../../arch/x86_64/hpet.h"
#include "../../arch/x86_64/serial.h"
#include "../../arch/x86_64/traps.h"
#include "../../core/klog.h"
#include "../../core/process.h"
#include "../../cpu/percpu.h"
#include "../../fs/fat32.h"
#include "../../mm/address_space.h"
#include "../../mm/frame_allocator.h"
#include "../../mm/page.h"
#include "../../mm/paging.h"
#include "../../sched/sched.h"
#include "../translation/translate.h"

extern "C" void linux_syscall_entry();

namespace customos::subsystems::linux
{

namespace
{

// Linux x86_64 MSR numbers.
constexpr u32 kMsrStar = 0xC0000081;  // CS selectors for syscall/sysret
constexpr u32 kMsrLstar = 0xC0000082; // entry RIP for 64-bit syscall
// MSR_CSTAR (0xC0000083) is the compat-mode entry; we don't
// plan to run 32-bit code, so leave it unprogrammed.
constexpr u32 kMsrFsBase = 0xC0000100;       // user FS.base — musl TLS anchor
constexpr u32 kMsrSfmask = 0xC0000084;       // RFLAGS mask applied at entry
constexpr u32 kMsrKernelGsBase = 0xC0000102; // swapgs source for kernel GS

// Canonical Linux errno values used by the handlers we implement.
// Only the subset we actually return today; extend as needed.
constexpr i64 kENOSYS = -38;
constexpr i64 kEBADF = -9;
constexpr i64 kEFAULT = -14;
constexpr i64 kENOMEM = -12;
constexpr i64 kEINVAL = -22;
constexpr i64 kENOENT = -2;
constexpr i64 kEIO = -5;
constexpr i64 kEMFILE = -24;
constexpr i64 kEISDIR = -21;
constexpr i64 kENAMETOOLONG = -36;

// Linux mmap flag bits we care about (asm-generic definitions,
// matches x86_64 too).
constexpr u64 kMapPrivate = 0x02;
constexpr u64 kMapAnonymous = 0x20;

// Per-process Linux fd cap on a single write/read. A real kernel
// wouldn't impose this but musl's newline-buffered stdout rarely
// issues writes over a few KiB. Cap matches the native int-0x80
// write path so behaviour stays predictable across ABIs.
constexpr u64 kLinuxIoMax = 4096;

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
    kSysIoctl = 16,
    kSysWritev = 20,
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
    kSysFcntl = 72,
    kSysChdir = 80,
    kSysFchdir = 81,
    kSysSetPgid = 109,
    kSysGetPpid = 110,
    kSysGetPgid = 121,
    kSysGetSid = 124,
};

constexpr i64 kESRCH = -3;

constexpr i64 kESPIPE = -29;
constexpr i64 kENOTTY = -25;

// ARCH_* codes for arch_prctl (linux/arch/x86/include/uapi/asm/prctl.h).
constexpr u64 kArchSetGs = 0x1001;
constexpr u64 kArchSetFs = 0x1002;
constexpr u64 kArchGetFs = 0x1003;
constexpr u64 kArchGetGs = 0x1004;

i64 DoExitGroup(u64 status)
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    SerialWrite("[linux] exit_group status=");
    SerialWriteHex(status);
    SerialWrite("\n");
    sched::SchedExit();
    // sched::SchedExit is [[noreturn]]; this line is unreachable.
    return 0;
}

// Linux: write(fd, buf, count). v0 implements fd=1 (stdout) and
// fd=2 (stderr) only — both go to COM1. Everything else returns
// -EBADF so musl's perror / write-to-pipe error paths surface
// predictably. No cap-gating here yet: a Linux process that
// reached the dispatcher is trusted to the same degree a native
// ring-3 task reaching SYS_WRITE is. Gating by Process::caps
// gets bolted on when we need per-sandbox Linux policy.
i64 DoWrite(u64 fd, u64 user_buf, u64 len)
{
    // fd 1/2 -> COM1 (unchanged from v0).
    if (fd == 1 || fd == 2)
    {
        const u64 to_copy = (len > kLinuxIoMax) ? kLinuxIoMax : len;
        if (to_copy == 0)
            return 0;
        u8 kbuf[kLinuxIoMax];
        if (!mm::CopyFromUser(kbuf, reinterpret_cast<const void*>(user_buf), to_copy))
            return kEFAULT;
        for (u64 i = 0; i < to_copy; ++i)
        {
            const char two[2] = {static_cast<char>(kbuf[i]), '\0'};
            arch::SerialWrite(two);
        }
        return static_cast<i64>(to_copy);
    }
    // fd 0 (stdin) rejects write; unused fds too.
    if (fd == 0 || fd >= 16)
        return kEBADF;
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || p->linux_fds[fd].state != 2)
        return kEBADF;

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
        const i64 n = fs::fat32::Fat32AppendAtPath(v, p->linux_fds[fd].path, kbuf + written, extend_len);
        if (n < 0)
        {
            p->linux_fds[fd].offset = off + written;
            return written > 0 ? static_cast<i64>(written) : kEIO;
        }
        written += static_cast<u64>(n);
        // Update the cached size — AppendAtPath just extended the
        // on-disk size field; our cached copy needs to follow.
        p->linux_fds[fd].size = static_cast<u32>(size + (to_copy - (size - off)));
    }
    p->linux_fds[fd].offset = off + written;
    return static_cast<i64>(written);
}

// Skip the `/fat/` mount prefix (or a bare leading slash) so what
// we hand to Fat32LookupPath is volume-relative. musl and shell
// callers both use absolute-looking paths; the FAT32 driver
// doesn't understand mount-point naming.
const char* StripFatPrefix(const char* p)
{
    while (*p == '/')
        ++p;
    if (p[0] == 'f' && p[1] == 'a' && p[2] == 't' && p[3] == '/')
        return p + 4;
    return p;
}

// Linux: open(path, flags, mode). v0 scope:
//   - Read-only. Any write/create/truncate flag bits in `flags`
//     are silently ignored; the FAT32 entry has to exist already.
//   - Only FAT32 volume 0. Path may be absolute ("/HELLO.TXT"),
//     mount-prefixed ("/fat/HELLO.TXT"), or bare ("HELLO.TXT").
// Returns the new fd on success, -errno otherwise.
i64 DoOpen(u64 user_path, u64 flags, u64 mode)
{
    (void)flags;
    (void)mode;
    // Copy the path into a fixed-size kernel buffer. 63-char cap
    // covers v0's FAT32 path depth (basenames up to 128 chars are
    // possible via LFN; restrict the `open` path here since the
    // kernel scratch + syscall argument convention favour tight
    // bounds anyway).
    char path[64];
    for (u32 i = 0; i < sizeof(path); ++i)
        path[i] = 0;
    if (!mm::CopyFromUser(path, reinterpret_cast<const void*>(user_path), sizeof(path) - 1))
    {
        return kEFAULT;
    }
    path[sizeof(path) - 1] = 0;
    // Ensure there's a NUL somewhere in the copied region; a
    // missing NUL means the caller passed an over-long string
    // that'd spill past our buffer during matching.
    bool has_nul = false;
    for (u32 i = 0; i < sizeof(path); ++i)
    {
        if (path[i] == 0)
        {
            has_nul = true;
            break;
        }
    }
    if (!has_nul)
    {
        return kENAMETOOLONG;
    }

    const auto* v = fs::fat32::Fat32Volume(0);
    if (v == nullptr)
    {
        return kENOENT;
    }
    fs::fat32::DirEntry entry;
    const char* leaf = StripFatPrefix(path);
    if (!fs::fat32::Fat32LookupPath(v, leaf, &entry))
    {
        return kENOENT;
    }
    if (entry.attributes & 0x10)
    {
        return kEISDIR;
    }

    core::Process* p = core::CurrentProcess();
    if (p == nullptr)
    {
        return kEIO;
    }
    for (u32 i = 3; i < 16; ++i)
    {
        if (p->linux_fds[i].state == 0)
        {
            p->linux_fds[i].state = 2;
            p->linux_fds[i].first_cluster = entry.first_cluster;
            p->linux_fds[i].size = entry.size_bytes;
            p->linux_fds[i].offset = 0;
            // Remember the (stripped) volume-relative path so
            // sys_write can call Fat32AppendAtPath on extend.
            u32 pi = 0;
            while (leaf[pi] != 0 && pi + 1 < sizeof(p->linux_fds[i].path))
            {
                p->linux_fds[i].path[pi] = leaf[pi];
                ++pi;
            }
            p->linux_fds[i].path[pi] = 0;
            return static_cast<i64>(i);
        }
    }
    return kEMFILE;
}

// Linux: close(fd). Marks the slot unused. No destructor work —
// FAT32 entries are snapshotted into the fd at open() time; a
// close doesn't touch disk.
i64 DoClose(u64 fd)
{
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd >= 16)
    {
        return kEBADF;
    }
    // fd 0/1/2 are reserved-tty, never file handles; refuse close.
    if (fd < 3 || p->linux_fds[fd].state == 0)
    {
        return kEBADF;
    }
    p->linux_fds[fd].state = 0;
    p->linux_fds[fd].first_cluster = 0;
    p->linux_fds[fd].size = 0;
    p->linux_fds[fd].offset = 0;
    return 0;
}

// Linux: read(fd, buf, count).
//   fd == 0 (stdin): always 0 (EOF). See earlier comment.
//   fd == 1 / 2: -EBADF — you can't read stdout/stderr.
//   fd >= 3 file handle: read from the current offset into the
//     user buffer, advance the cursor, return the byte count.
//     Implementation reads the ENTIRE file into scratch and
//     slices — simple, bounded by 4 KiB (v0 file cap).
i64 DoRead(u64 fd, u64 user_buf, u64 len)
{
    if (fd == 0)
    {
        return 0;
    }
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd >= 16)
    {
        return kEBADF;
    }
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

    // Scratch read. 4 KiB accommodates HELLO.TXT / INNER.TXT /
    // LongFile.txt; larger files will truncate here. A streaming
    // read-with-offset helper in the FAT32 driver is the next
    // iteration.
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

// Fill a Linux struct stat from the given FAT32 directory entry.
// Layout matches uapi/asm-generic/stat.h for x86_64 (144 bytes).
// Times are zeroed — no RTC integration yet.
void FillStatFromEntry(const fs::fat32::DirEntry& e, u8* out_144)
{
    for (u64 i = 0; i < 144; ++i)
        out_144[i] = 0;
    auto put_u64 = [&](u64 off, u64 v)
    {
        for (u64 i = 0; i < 8; ++i)
            out_144[off + i] = static_cast<u8>(v >> (i * 8));
    };
    auto put_u32 = [&](u64 off, u32 v)
    {
        for (u64 i = 0; i < 4; ++i)
            out_144[off + i] = static_cast<u8>(v >> (i * 8));
    };
    // st_dev = 0 (no device namespace yet).
    put_u64(0, 0);
    // st_ino = first_cluster — stable identity per on-disk entry.
    put_u64(8, e.first_cluster);
    // st_nlink = 1 for files, 1 for dirs (no hard links).
    put_u64(16, 1);
    // st_mode: dir or regular file, default permissions rw-r--r-- / rwxr-xr-x.
    const u32 mode = (e.attributes & 0x10) ? 0x41EDu  /* S_IFDIR | 0755 */
                                           : 0x81A4u; /* S_IFREG | 0644 */
    put_u32(24, mode);
    // st_uid/gid/rdev = 0.
    // st_size at offset 48.
    put_u64(48, e.size_bytes);
    // st_blksize at offset 56.
    put_u64(56, 4096);
    // st_blocks (in 512-byte units) at offset 64.
    put_u64(64, (u64(e.size_bytes) + 511) / 512);
    // times: all zero — RTC integration follows.
}

// Linux: stat(path, buf) / lstat(path, buf).
// Looks up the path in FAT32 volume 0, fills a struct stat, copies
// it to user. Treats symlinks as regular files (we have none).
i64 DoStat(u64 user_path, u64 user_buf)
{
    char path[64];
    for (u32 i = 0; i < sizeof(path); ++i)
        path[i] = 0;
    if (!mm::CopyFromUser(path, reinterpret_cast<const void*>(user_path), sizeof(path) - 1))
        return kEFAULT;
    path[sizeof(path) - 1] = 0;

    const auto* v = fs::fat32::Fat32Volume(0);
    if (v == nullptr)
        return kENOENT;
    fs::fat32::DirEntry entry;
    if (!fs::fat32::Fat32LookupPath(v, StripFatPrefix(path), &entry))
        return kENOENT;

    u8 sbuf[144];
    FillStatFromEntry(entry, sbuf);
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_buf), sbuf, sizeof(sbuf)))
        return kEFAULT;
    return 0;
}

// Linux: fstat(fd, buf). Synthesises a DirEntry from the fd's
// cached state; doesn't re-read the directory.
i64 DoFstat(u64 fd, u64 user_buf)
{
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd >= 16)
        return kEBADF;
    const auto state = p->linux_fds[fd].state;
    fs::fat32::DirEntry entry;
    for (u64 i = 0; i < sizeof(entry.name); ++i)
        entry.name[i] = 0;
    if (state == 1)
    {
        // tty — character-device-ish. Mode S_IFCHR | 0600 = 020600 = 0x2180.
        u8 sbuf[144];
        for (u64 i = 0; i < sizeof(sbuf); ++i)
            sbuf[i] = 0;
        // st_mode at 24:
        sbuf[24] = 0x80;
        sbuf[25] = 0x21;
        // st_nlink=1 at 16:
        sbuf[16] = 1;
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_buf), sbuf, sizeof(sbuf)))
            return kEFAULT;
        return 0;
    }
    if (state != 2)
        return kEBADF;
    entry.attributes = 0;
    entry.first_cluster = p->linux_fds[fd].first_cluster;
    entry.size_bytes = p->linux_fds[fd].size;
    u8 sbuf[144];
    FillStatFromEntry(entry, sbuf);
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_buf), sbuf, sizeof(sbuf)))
        return kEFAULT;
    return 0;
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

// Linux: lseek(fd, offset, whence).
//   whence 0 = SEEK_SET — absolute
//   whence 1 = SEEK_CUR — relative to current
//   whence 2 = SEEK_END — relative to file size
// Only file fds support seek; tty fds return -ESPIPE so musl's
// isatty() heuristic works without extra plumbing.
i64 DoLseek(u64 fd, i64 offset, u64 whence)
{
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd >= 16)
        return kEBADF;
    if (p->linux_fds[fd].state == 1)
        return kESPIPE; // tty: can't seek
    if (p->linux_fds[fd].state != 2)
        return kEBADF;

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

// Linux: ioctl(fd, cmd, arg). v0 stub — no device drivers
// currently expose ioctls to Linux ABI. Return -ENOTTY for
// anything on tty fds (matches glibc/musl probe behaviour), -EBADF
// otherwise. Real implementations add specific cmd handling per
// device.
i64 DoIoctl(u64 fd, u64 cmd, u64 arg)
{
    (void)cmd;
    (void)arg;
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd >= 16)
        return kEBADF;
    if (p->linux_fds[fd].state == 1)
        return kENOTTY;
    if (p->linux_fds[fd].state == 0)
        return kEBADF;
    return kENOTTY;
}

// Linux: rt_sigaction / rt_sigprocmask / set_tid_address.
// v0 stubs — accept + succeed without actually wiring signal
// delivery or TID futex notification. musl calls these during
// CRT init; refusing them would abort startup. Behavior: signals
// are silently dropped (no delivery machinery yet); set_tid_address
// returns the current task ID but the kernel never clears the
// user memory on exit (no CLONE_CHILD_CLEARTID handling).
i64 DoRtSigaction(u64 signum, u64 new_act, u64 old_act, u64 sigsetsize)
{
    (void)signum;
    (void)new_act;
    (void)old_act;
    (void)sigsetsize;
    return 0;
}

i64 DoRtSigprocmask(u64 how, u64 user_set, u64 user_oldset, u64 sigsetsize)
{
    (void)how;
    (void)user_set;
    (void)user_oldset;
    (void)sigsetsize;
    return 0;
}

i64 DoSetTidAddress(u64 user_tid_ptr)
{
    (void)user_tid_ptr;
    return static_cast<i64>(sched::CurrentTaskId());
}

// Linux: access(path, mode). v0 implements as a presence probe —
// if FAT32LookupPath finds the entry, return 0 (success); else
// -ENOENT. The `mode` bits (R_OK, W_OK, X_OK, F_OK) are ignored:
// everything in FAT32 is effectively rwx from the Linux task's
// perspective.
i64 DoAccess(u64 user_path, u64 mode)
{
    (void)mode;
    char path[64];
    for (u32 i = 0; i < sizeof(path); ++i)
        path[i] = 0;
    if (!mm::CopyFromUser(path, reinterpret_cast<const void*>(user_path), sizeof(path) - 1))
        return kEFAULT;
    path[sizeof(path) - 1] = 0;
    const auto* v = fs::fat32::Fat32Volume(0);
    if (v == nullptr)
        return kENOENT;
    fs::fat32::DirEntry entry;
    return fs::fat32::Fat32LookupPath(v, StripFatPrefix(path), &entry) ? 0 : kENOENT;
}

// Linux: readlink(path, buf, bufsiz). We don't have symlinks;
// every path is a plain file or directory. Return -EINVAL per
// POSIX's "path is not a symlink" semantics — musl's
// realpath() fallback kicks in and uses the path as-is.
i64 DoReadlink(u64 user_path, u64 user_buf, u64 bufsiz)
{
    (void)user_path;
    (void)user_buf;
    (void)bufsiz;
    return kEINVAL;
}

// Linux: getcwd(buf, size). We don't have per-process cwd; the
// closest equivalent is the process's ramfs root. Return "/"
// for simplicity — matches what a chroot-like setup would
// report. musl uses getcwd only for realpath resolution in
// practice; a static "/" is enough for non-pathological programs.
i64 DoGetcwd(u64 user_buf, u64 size)
{
    const char* cwd = "/";
    const u64 len = 2; // "/" + NUL
    if (size < len)
        return kEINVAL;
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_buf), cwd, len))
        return kEFAULT;
    return static_cast<i64>(len);
}

// Linux: futex(uaddr, op, val, ...). v0 stub — single-threaded
// processes don't contend, so the futex is always uncontended
// when musl falls through to syscall. Returning 0 for FUTEX_WAIT
// says "woke up spuriously" (caller re-checks + retries).
// Returning 0 for FUTEX_WAKE says "woke zero waiters" (there are
// none). Safe no-op for a single-thread world.
i64 DoFutex(u64 uaddr, u64 op, u64 val, u64 timeout, u64 uaddr2, u64 val3)
{
    (void)uaddr;
    (void)op;
    (void)val;
    (void)timeout;
    (void)uaddr2;
    (void)val3;
    return 0;
}

// Read the CPU timestamp counter. Used as a seed for the tiny
// PRNG below — not intended as a clock.
u64 ReadTsc()
{
    u32 lo, hi;
    asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return (static_cast<u64>(hi) << 32) | lo;
}

// Linux: getrandom(buf, count, flags). Fills `count` bytes with
// a non-cryptographic PRNG stream seeded from rdtsc on each
// call. Good enough for musl's stack-cookie / pointer-mangling
// init. Real crypto-quality entropy needs a proper RNG driver —
// separate slice.
i64 DoGetRandom(u64 user_buf, u64 count, u64 flags)
{
    (void)flags;
    if (count == 0)
        return 0;
    if (count > 4096)
        count = 4096; // cap per call, same as Linux default for unseeded
    static u8 tmp[4096];
    u64 state = ReadTsc() ^ 0xDEADBEEFCAFEBABEull;
    for (u64 i = 0; i < count; ++i)
    {
        // xorshift64 — decent statistical mixing, not cryptographic.
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        tmp[i] = static_cast<u8>(state >> 24);
    }
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_buf), tmp, count))
        return kEFAULT;
    return static_cast<i64>(count);
}

// Current nanoseconds since boot, derived from the HPET main
// counter. Returns 0 if HPET didn't init (rare on modern x86).
u64 NowNs()
{
    const u64 counter = arch::HpetReadCounter();
    const u32 period_fs = arch::HpetPeriodFemtoseconds();
    if (period_fs == 0)
        return 0;
    // ns = counter * period_fs / 1_000_000 — split to avoid u64 overflow:
    // (counter / 1_000_000) * period_fs + ((counter % 1_000_000) * period_fs) / 1_000_000.
    // counter is typically < 2^40 and period_fs < 2^28, so direct
    // multiply fits in u64 as long as counter < 2^36 — guard with
    // the split form for safety over boot-time scales.
    const u64 million = 1000000ull;
    const u64 hi = (counter / million) * period_fs;
    const u64 lo = ((counter % million) * period_fs) / million;
    return hi + lo;
}

// Linux: clock_gettime(clk_id, ts). Fills struct timespec
// {tv_sec (i64), tv_nsec (i64)} with current time. v0 returns
// nanoseconds-since-boot for every clock id — musl uses this
// for relative-time primitives (monotonic deltas, sleep offsets)
// and tolerates the REALTIME-since-boot approximation when there's
// no RTC integration. Calendar time needs the RTC driver's UNIX
// epoch — separate slice.
i64 DoClockGetTime(u64 clk_id, u64 user_ts)
{
    (void)clk_id;
    const u64 ns = NowNs();
    struct
    {
        i64 tv_sec;
        i64 tv_nsec;
    } ts;
    ts.tv_sec = static_cast<i64>(ns / 1'000'000'000ull);
    ts.tv_nsec = static_cast<i64>(ns % 1'000'000'000ull);
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_ts), &ts, sizeof(ts)))
        return kEFAULT;
    return 0;
}

// Linux: time(tloc). Returns seconds-since-epoch; if tloc is
// non-null, writes the value there too. Without an RTC we return
// seconds-since-boot — matches the "CLOCK_REALTIME = boot" call
// above. Real epoch tracking waits for the RTC driver to lock on.
i64 DoTime(u64 user_tloc)
{
    const u64 secs = NowNs() / 1'000'000'000ull;
    if (user_tloc != 0)
    {
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_tloc), &secs, sizeof(secs)))
            return kEFAULT;
    }
    return static_cast<i64>(secs);
}

// Linux: nanosleep(req, rem). v0 rounds the request up to whole
// scheduler ticks (10 ms each at 100 Hz). The `rem` output — how
// much time is left if interrupted — is always zeroed; CustomOS
// doesn't deliver signals yet, so nothing can interrupt a sleep
// mid-flight.
i64 DoNanosleep(u64 user_req, u64 user_rem)
{
    struct
    {
        i64 tv_sec;
        i64 tv_nsec;
    } req;
    if (!mm::CopyFromUser(&req, reinterpret_cast<const void*>(user_req), sizeof(req)))
        return kEFAULT;
    if (req.tv_sec < 0 || req.tv_nsec < 0 || req.tv_nsec >= 1'000'000'000)
        return kEINVAL;
    const u64 ns = static_cast<u64>(req.tv_sec) * 1'000'000'000ull + static_cast<u64>(req.tv_nsec);
    // Scheduler tick = 10 ms = 10_000_000 ns. Round up so a sub-
    // tick sleep doesn't become zero.
    const u64 ticks = (ns + 9'999'999ull) / 10'000'000ull;
    if (ticks > 0)
        sched::SchedSleepTicks(ticks);
    if (user_rem != 0)
    {
        struct
        {
            i64 tv_sec;
            i64 tv_nsec;
        } zero{0, 0};
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_rem), &zero, sizeof(zero)))
            return kEFAULT;
    }
    return 0;
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

// Copy one fd slot into another (same process). Used by dup /
// dup2 / F_DUPFD. v0 semantics: the new fd is an INDEPENDENT
// copy — state + first_cluster + size + offset + path all
// mirrored. Real Linux dup() would share the file description
// (one shared offset + flag set), but our workloads don't hit
// the difference yet.
void CopyFdSlot(const core::Process::LinuxFd& src, core::Process::LinuxFd& dst)
{
    dst.state = src.state;
    dst.first_cluster = src.first_cluster;
    dst.size = src.size;
    dst.offset = src.offset;
    for (u32 i = 0; i < sizeof(dst.path); ++i)
        dst.path[i] = src.path[i];
}

// Linux: dup(fd). Allocate the lowest unused slot ≥ 3 and copy
// the source fd into it. Returns the new fd or -EMFILE if full.
i64 DoDup(u64 fd)
{
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd >= 16)
        return kEBADF;
    if (p->linux_fds[fd].state == 0)
        return kEBADF;
    for (u32 i = 3; i < 16; ++i)
    {
        if (p->linux_fds[i].state == 0)
        {
            CopyFdSlot(p->linux_fds[fd], p->linux_fds[i]);
            return static_cast<i64>(i);
        }
    }
    return kEMFILE;
}

// Linux: dup2(oldfd, newfd). If newfd == oldfd, returns newfd.
// Else closes newfd if in use, then copies. Returns newfd.
i64 DoDup2(u64 oldfd, u64 newfd)
{
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || oldfd >= 16 || newfd >= 16)
        return kEBADF;
    if (p->linux_fds[oldfd].state == 0)
        return kEBADF;
    if (oldfd == newfd)
        return static_cast<i64>(newfd);
    // newfd < 3 (stdin/stdout/stderr) — dup2 onto a tty slot is
    // legal in Linux (shell redirection pattern). Since we track
    // tty slots as state=1 (not a file), just overwrite.
    CopyFdSlot(p->linux_fds[oldfd], p->linux_fds[newfd]);
    return static_cast<i64>(newfd);
}

// Linux: fcntl(fd, cmd, arg). v0 supports:
//   F_DUPFD (0)      — dup the fd, returning a slot >= arg.
//   F_GETFD (1)      — returns 0 (no per-fd flags stored).
//   F_SETFD (2)      — accepts + returns 0.
//   F_GETFL (3)      — returns O_RDWR (2) for any live fd.
//   F_SETFL (4)      — accepts + returns 0.
// Everything else returns -EINVAL.
i64 DoFcntl(u64 fd, u64 cmd, u64 arg)
{
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd >= 16)
        return kEBADF;
    if (p->linux_fds[fd].state == 0)
        return kEBADF;
    switch (cmd)
    {
    case 0: // F_DUPFD
    {
        const u32 start = (arg < 3) ? 3 : (arg >= 16 ? 16 : static_cast<u32>(arg));
        for (u32 i = start; i < 16; ++i)
        {
            if (p->linux_fds[i].state == 0)
            {
                CopyFdSlot(p->linux_fds[fd], p->linux_fds[i]);
                return static_cast<i64>(i);
            }
        }
        return kEMFILE;
    }
    case 1: // F_GETFD
        return 0;
    case 2: // F_SETFD
        return 0;
    case 3:       // F_GETFL
        return 2; // O_RDWR
    case 4:       // F_SETFL
        return 0;
    default:
        return kEINVAL;
    }
}

// Linux: chdir(path) / fchdir(fd). v0 has no per-process cwd;
// accept the call + succeed so musl's `realpath()` + shells
// don't abort. When cwd lands, store the resolved directory's
// cluster on Process.
i64 DoChdir(u64 user_path)
{
    (void)user_path;
    return 0;
}
i64 DoFchdir(u64 fd)
{
    (void)fd;
    return 0;
}

// Linux: mprotect(addr, len, prot). v0 maps all user pages RW
// and treats prot as advisory. Return 0 to satisfy callers;
// actual flag updates wait for an MM-layer MapProtect helper.
i64 DoMprotect(u64 addr, u64 len, u64 prot)
{
    (void)addr;
    (void)len;
    (void)prot;
    return 0;
}

// Linux: sigaltstack(ss, old_ss). Stub — no signal delivery so
// no alt-stack semantics are observable. Returns 0.
i64 DoSigaltstack(u64 ss, u64 old_ss)
{
    (void)ss;
    (void)old_ss;
    return 0;
}

// Linux: rt_sigreturn. Called by user-mode signal trampolines
// at the end of a signal handler. Without signal delivery
// there's no frame to unwind; if a program ever calls this
// unexpectedly, kill it so we don't silently return garbage.
i64 DoRtSigreturn()
{
    arch::SerialWrite("[linux] rt_sigreturn on task without signal frame — exiting\n");
    sched::SchedExit();
    return 0;
}

// Linux: sched_yield. Direct passthrough to the native scheduler.
i64 DoSchedYield()
{
    sched::SchedYield();
    return 0;
}

// Linux: gettid. v0 has one task per process, so tid == pid.
i64 DoGetTid()
{
    return static_cast<i64>(sched::CurrentTaskId());
}

// Linux: tgkill(tgid, tid, sig). Used by musl's abort() to send
// SIGABRT to itself. v0 has no signal delivery — if the target
// is self, just exit with an abort-ish status; any other tid
// returns -ESRCH.
i64 DoTgkill(u64 tgid, u64 tid, u64 sig)
{
    (void)tgid;
    if (tid != sched::CurrentTaskId())
        return kESRCH;
    arch::SerialWrite("[linux] tgkill -> self; interpreting as abort. sig=");
    arch::SerialWriteHex(sig);
    arch::SerialWrite("\n");
    sched::SchedExit();
    return 0;
}

// Linux: kill(pid, sig). Same as tgkill in this single-threaded
// world — if targeting self, exit; else -ESRCH. A real signal
// implementation would look up the target Process and deliver
// via its sig queue.
i64 DoKill(u64 pid, u64 sig)
{
    if (pid != sched::CurrentTaskId())
        return kESRCH;
    arch::SerialWrite("[linux] kill(self) sig=");
    arch::SerialWriteHex(sig);
    arch::SerialWrite("\n");
    sched::SchedExit();
    return 0;
}

// Linux: getppid / getpgid / getsid / setpgid. v0 has a flat
// process namespace with no session/pg model; return 1 (init-
// like) for ppid and 0 for everything else. setpgid accepts and
// is silently a no-op.
i64 DoGetPpid()
{
    return 1;
}
i64 DoGetPgid(u64 pid)
{
    (void)pid;
    return 0;
}
i64 DoGetSid(u64 pid)
{
    (void)pid;
    return 0;
}
i64 DoSetPgid(u64 pid, u64 pgid)
{
    (void)pid;
    (void)pgid;
    return 0;
}

// Identity stubs. v0 presents every process as uid=0/gid=0 —
// CustomOS doesn't have a user-account model yet. Returning 0
// satisfies musl's libc.a startup without misleading it: programs
// that check for root will see "yes you're root," which is
// consistent with "there are no privilege boundaries here."
i64 DoGetUid()
{
    return 0;
}
i64 DoGetGid()
{
    return 0;
}
i64 DoGetEuid()
{
    return 0;
}
i64 DoGetEgid()
{
    return 0;
}

// Page-align `x` up. Our cluster size is 4 KiB, matching FAT32's
// native page; the mmap / brk paths map 4 KiB frames directly,
// so all lengths round up to a 4 KiB boundary before allocation.
u64 PageUp(u64 x)
{
    return (x + 0xFFFu) & ~0xFFFull;
}

// Linux: brk(addr). Three cases:
//   addr == 0 -> return current brk (the `sbrk(0)` query path).
//   addr < linux_brk_base -> ignore, return current. Linux
//     doesn't shrink past the initial segment end.
//   addr > linux_brk_current -> map fresh RW+U+NX pages to extend
//     the heap; return the new brk on success. Allocation failure
//     partway through is "treat as unchanged", which is what Linux
//     does — the caller checks the return == the requested addr.
i64 DoBrk(u64 new_brk)
{
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || p->abi_flavor != core::kAbiLinux)
    {
        return 0;
    }
    if (new_brk == 0)
    {
        return static_cast<i64>(p->linux_brk_current);
    }
    if (new_brk < p->linux_brk_base)
    {
        return static_cast<i64>(p->linux_brk_current);
    }
    const u64 cur_aligned = PageUp(p->linux_brk_current);
    const u64 new_aligned = PageUp(new_brk);
    if (new_aligned > cur_aligned)
    {
        for (u64 va = cur_aligned; va < new_aligned; va += mm::kPageSize)
        {
            const mm::PhysAddr frame = mm::AllocateFrame();
            if (frame == mm::kNullFrame)
            {
                // Roll back to the last successfully-mapped page.
                // Simplest: just don't update linux_brk_current
                // past whatever we managed to materialise.
                p->linux_brk_current = va;
                return static_cast<i64>(p->linux_brk_current);
            }
            mm::AddressSpaceMapUserPage(p->as, va, frame,
                                        mm::kPagePresent | mm::kPageWritable | mm::kPageUser | mm::kPageNoExecute);
        }
    }
    p->linux_brk_current = new_brk;
    arch::SerialWrite("[linux] brk -> ");
    arch::SerialWriteHex(p->linux_brk_current);
    arch::SerialWrite("\n");
    return static_cast<i64>(p->linux_brk_current);
}

// Linux: mmap(addr, len, prot, flags, fd, offset). v0 supports
// only anonymous + private mappings — the shape musl's malloc
// and static CRT actually issue. prot is ignored (all pages are
// mapped RW+NX); a real impl would respect PROT_READ-only and
// PROT_EXEC separately.
//
// Returns the chosen VA as a u64 on success, -errno on failure.
// `addr` (MAP_FIXED) is ignored in v0; we always pick from the
// per-process bump cursor.
i64 DoMmap(u64 addr, u64 len, u64 prot, u64 flags, u64 fd, u64 off)
{
    (void)addr;
    (void)prot;
    (void)fd;
    (void)off;
    if ((flags & kMapAnonymous) == 0)
    {
        return kENOSYS; // file-backed mmap not yet supported
    }
    if ((flags & kMapPrivate) == 0)
    {
        return kEINVAL; // MAP_SHARED without a file is meaningless
    }
    if (len == 0)
    {
        return kEINVAL;
    }
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || p->abi_flavor != core::kAbiLinux)
    {
        return kENOSYS;
    }
    const u64 aligned = PageUp(len);
    const u64 base = p->linux_mmap_cursor;
    for (u64 va = base; va < base + aligned; va += mm::kPageSize)
    {
        const mm::PhysAddr frame = mm::AllocateFrame();
        if (frame == mm::kNullFrame)
        {
            // Partial-map rollback would require tearing down the
            // mappings we already installed. v0 leaks on OOM — the
            // process is about to die anyway, and AS teardown on
            // task death will reclaim everything.
            return kENOMEM;
        }
        mm::AddressSpaceMapUserPage(p->as, va, frame,
                                    mm::kPagePresent | mm::kPageWritable | mm::kPageUser | mm::kPageNoExecute);
    }
    p->linux_mmap_cursor += aligned;
    arch::SerialWrite("[linux] mmap -> ");
    arch::SerialWriteHex(base);
    arch::SerialWrite(" len=");
    arch::SerialWriteHex(aligned);
    arch::SerialWrite("\n");
    return static_cast<i64>(base);
}

// Linux: munmap(addr, len). v0 stub — page unmap requires tearing
// down the AS entries, which the AS API doesn't yet expose. Return
// 0 so musl's free() paths don't error out; the mappings persist
// until the process dies (bounded leak — fine for short-lived
// ring-3 tasks).
i64 DoMunmap(u64 addr, u64 len)
{
    (void)addr;
    (void)len;
    return 0;
}

// Linux: arch_prctl(code, addr). Used almost exclusively by musl's
// CRT at _start to plant the thread-local-storage anchor in
// FS.base: `arch_prctl(ARCH_SET_FS, &thread_block)`. Without this,
// every %fs:[...] access in musl hits an unmapped VA and #PF.
//
// v0 scope:
//   ARCH_SET_FS — write `addr` to MSR_FS_BASE.
//   ARCH_GET_FS — read MSR_FS_BASE, write to *(u64*)addr.
//   ARCH_SET_GS / GET_GS — return -EINVAL (we use MSR_GS_BASE
//     for our own swapgs dance; exposing it to user mode would
//     let a malicious task alias our per-CPU area).
//
// Note: we don't save/restore MSR_FS_BASE across context switches
// yet. Works because v0 has at most one Linux-ABI task running at
// a time (and kernel workers don't touch FS.base). Multi-Linux-
// task support will need per-Task fs_base storage.
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

// Linux: uname(buf). Fills a struct utsname with six NUL-padded
// 65-char fields: sysname, nodename, release, version, machine,
// domainname. Total 6 * 65 = 390 bytes. musl reads this at
// startup for diagnostics (`uname -a` etc.) and for platform
// dispatch in a few places. Static response: a real kernel
// would plumb nodename to a runtime-configurable hostname.
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
    set_field(0, "CustomOS");
    set_field(1, "customos");
    set_field(2, "0.1");
    set_field(3, "customos-v0 #1");
    set_field(4, "x86_64");
    set_field(5, "localdomain");
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_buf), kbuf, kTotalLen))
    {
        return kEFAULT;
    }
    return 0;
}

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

extern "C" void LinuxSyscallDispatch(arch::TrapFrame* frame)
{
    KLOG_TRACE_SCOPE("linux/syscall", "LinuxSyscallDispatch");
    const u64 nr = frame->rax;
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
    case kSysLstat:
        rv = DoStat(frame->rdi, frame->rsi);
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
    case kSysGetPgid:
        rv = DoGetPgid(frame->rdi);
        break;
    case kSysGetSid:
        rv = DoGetSid(frame->rdi);
        break;
    case kSysSetPgid:
        rv = DoSetPgid(frame->rdi, frame->rsi);
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
    case kSysExitGroup:
        DoExitGroup(frame->rdi);
        // Exit paths don't return; keep the compiler happy.
        rv = 0;
        break;
    case kSysGetPid:
        rv = static_cast<i64>(sched::CurrentTaskId());
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

} // namespace customos::subsystems::linux
