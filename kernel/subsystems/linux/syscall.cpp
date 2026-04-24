#include "syscall.h"

#include "linux_syscall_table_generated.h"

#include "../../arch/x86_64/hpet.h"
#include "../../arch/x86_64/serial.h"
#include "../../arch/x86_64/timer.h"
#include "../../arch/x86_64/traps.h"
#include "../../core/klog.h"
#include "../../core/process.h"
#include "../../core/random.h"
#include "../../cpu/percpu.h"
#include "../../fs/fat32.h"
#include "../../mm/address_space.h"
#include "../../mm/frame_allocator.h"
#include "../../mm/page.h"
#include "../../mm/paging.h"
#include "../../sched/sched.h"
#include "../translation/translate.h"

extern "C" void linux_syscall_entry();

namespace duetos::subsystems::linux
{

namespace
{
// Hot-path tracing gate for LinuxSyscallDispatch. Debug keeps
// full trace scopes; release compiles them fully out so each
// syscall pays no trace RAII construction/destruction overhead.
#if defined(NDEBUG)
inline constexpr bool kTraceLinuxSyscallDispatch = false;
#else
inline constexpr bool kTraceLinuxSyscallDispatch = true;
#endif

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
    kSysReadv = 19,
    kSysIoctl = 16,
    kSysWritev = 20,
    kSysMadvise = 28,
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
    kSysFsync = 74,
    kSysFdatasync = 75,
    kSysFcntl = 72,
    kSysGettimeofday = 96,
    kSysGetrlimit = 97,
    kSysSysinfo = 99,
    kSysChdir = 80,
    kSysFchdir = 81,
    kSysSetPgid = 109,
    kSysGetPpid = 110,
    kSysGetpgrp = 111,
    kSysGetPgid = 121,
    kSysGetSid = 124,
    kSysSetrlimit = 160,
    kSysPrlimit64 = 302,
    // Batch 54 — modern *at-family + directory + poll/select + rusage.
    // Everything here routes through an existing primary handler
    // (openat → DoOpen with AT_FDCWD treatment, newfstatat → DoStat
    // / DoFstat, dup3 → DoDup2) or is a structural stub (poll /
    // select / getdents64 / getrusage returning valid-shaped
    // results so callers can progress instead of -ENOSYS-crashing).
    kSysPoll = 7,
    kSysSelect = 23,
    kSysGetrusage = 98,
    kSysGetdents64 = 217,
    kSysOpenat = 257,
    kSysNewFstatat = 262,
    kSysDup3 = 292,
    // set_robust_list / get_robust_list — musl calls set_robust_list
    // at thread init. Accepting + no-op is the usual glibc-compat
    // move (we have no robust-futex machinery).
    kSysSetRobustList = 273,
    kSysGetRobustList = 274,

    // Batch 55 — fill out the most commonly-probed unimplemented
    // syscalls. Two flavours:
    //
    //   * No-op compat stubs — calls whose v0 semantics are
    //     "we don't model that subsystem (permissions, uids,
    //     priorities, mlock, etc.); return success / sane
    //     default so static-musl + simple POSIX programs make
    //     forward progress instead of bailing on -ENOSYS."
    //
    //   * Real-ish FS ops — `truncate` / `ftruncate` / `unlink` /
    //     `mkdir` / `rmdir` route through the existing FAT32
    //     primitives (Fat32TruncateAtPath / Fat32DeleteAtPath /
    //     Fat32MkdirAtPath / Fat32RmdirAtPath). lstat aliases stat
    //     since we have no symlinks — see DoLstat below.
    kSysMremap = 25,
    kSysMsync = 26,
    kSysMincore = 27,
    kSysPause = 34,
    kSysFlock = 73,
    kSysTruncate = 76,
    kSysFtruncate = 77,
    kSysMkdir = 83,
    kSysRmdir = 84,
    kSysUnlink = 87,
    kSysChmod = 90,
    kSysFchmod = 91,
    kSysChown = 92,
    kSysFchown = 93,
    kSysLchown = 94,
    kSysTimes = 100,
    kSysSetuid = 105,
    kSysSetgid = 106,
    kSysSetreuid = 113,
    kSysSetregid = 114,
    kSysGetgroups = 115,
    kSysSetgroups = 116,
    kSysSetresuid = 117,
    kSysGetresuid = 118,
    kSysSetresgid = 119,
    kSysGetresgid = 120,
    kSysSetfsuid = 122,
    kSysSetfsgid = 123,
    kSysCapget = 125,
    kSysCapset = 126,
    kSysUtime = 132,
    kSysMknod = 133,
    kSysPersonality = 135,
    kSysGetpriority = 140,
    kSysSetpriority = 141,
    kSysMlock = 149,
    kSysMunlock = 150,
    kSysMlockall = 151,
    kSysMunlockall = 152,

    // Batch 56 — additional compat stubs + *at-family delegations.
    // Brings overall primary coverage further + gives common
    // POSIX/glibc idioms a landing spot so they don't `-ENOSYS`.
    //
    // *at-family notes: we have no per-process CWD, so AT_FDCWD
    // (the common case) resolves against the sandbox root exactly
    // like the non-*at variants. Other dirfd values — -EBADF.
    //
    // FS-mutation stubs that would need filesystem primitives we
    // don't have (rename, link, symlink) return -EPERM or -ENOSYS
    // as appropriate rather than silently pretending to succeed.
    kSysPtrace = 101,
    kSysSyslog = 103,
    kSysSetsid = 112,
    kSysVhangup = 153,
    kSysAcct = 163,
    kSysMount = 165,
    kSysUmount2 = 166,
    kSysSync = 162,
    kSysSyncfs = 306,
    kSysRename = 82,
    kSysLink = 86,
    kSysSymlink = 88,
    kSysSetThreadArea = 205,
    kSysGetThreadArea = 211,
    kSysIoprioGet = 252,
    kSysIoprioSet = 251,
    kSysSchedSetaffinity = 203,
    kSysSchedGetaffinity = 204,
    kSysClockGetres = 229,
    kSysClockNanosleep = 230,
    kSysGetcpu = 309,
    kSysMkdirat = 258,
    kSysUnlinkat = 263,
    kSysLinkat = 265,
    kSysSymlinkat = 266,
    kSysRenameat = 264,
    kSysRenameat2 = 316,
    kSysFchownat = 260,
    kSysFutimesat = 261,
    kSysFchmodat = 268,
    kSysFaccessat = 269,
    kSysFaccessat2 = 439,
    kSysUtimensat = 280,
};

// POSIX AT_FDCWD — used by the *at family to mean "resolve
// relative to the caller's CWD". v0 has no per-process CWD
// yet, so AT_FDCWD always resolves to the sandbox root; any
// other dirfd is -EBADF until per-fd CWDs land.
constexpr i64 kAtFdCwd = -100;

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

// Linux exit(status) has process-wide semantics for a single-thread
// process, which is exactly all we support in v0. Route it through
// exit_group so both numbers share the same teardown path.
i64 DoExit(u64 status)
{
    return DoExitGroup(status);
}

// Linux getpid() / gettid() on our current single-thread-per-process
// model both map to the scheduler task ID. Keep them separate helpers
// anyway so the dispatch table names track the Linux ABI directly and
// the syscall coverage generator can see a concrete DoGetPid handler.
i64 DoGetPid()
{
    return static_cast<i64>(sched::CurrentTaskId());
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
        arch::SerialWriteN(reinterpret_cast<const char*>(kbuf), to_copy);
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

// Linux: ioctl(fd, cmd, arg). Handle the three ioctls musl's
// stdio actually reaches under a CRT bring-up:
//   TCGETS      (0x5401) — "is this a tty?" probe. Returns a
//                         populated termios struct so isatty(fd)
//                         returns true; line-edit features are
//                         effectively disabled via the c_lflag
//                         bits we clear.
//   TCSETS      (0x5402) — swallow — we don't honour the
//                         settings, but returning success avoids
//                         aborting callers that set RAW mode.
//   TIOCGWINSZ  (0x5413) — report a fake 80×24 terminal so
//                         curses-style programs stop asking.
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
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd >= 16)
        return kEBADF;
    if (p->linux_fds[fd].state == 0)
        return kEBADF;
    const bool is_tty = (p->linux_fds[fd].state == 1);
    if (!is_tty)
        return kENOTTY;
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
        // c_cc: common control chars. VINTR=^C, VQUIT=^\, VERASE=^?,
        // VKILL=^U, VEOF=^D.
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

// Linux: rt_sigaction. Store the requested handler + mask + flags
// in the per-process signal table so a subsequent rt_sigaction
// with a nullptr new_act returns the value we just persisted.
// Signal DELIVERY is still not wired (no user-mode trampoline, no
// pending queue) but musl's CRT init relies on readback to decide
// whether SIGPIPE is SIG_IGN'd — returning the previous value
// matters even though we never actually raise a signal.
//
// Linux sigaction layout (offsets into the user struct):
//   0x00  sa_handler (u64) or sa_sigaction
//   0x08  sa_flags (u64)
//   0x10  sa_restorer (u64)
//   0x18  sa_mask (u64, first u64 of the sigset)
i64 DoRtSigaction(u64 signum, u64 new_act, u64 old_act, u64 sigsetsize)
{
    (void)sigsetsize; // we always store a single u64 mask
    if (signum == 0 || signum >= core::Process::kLinuxSignalCount)
        return kEINVAL;
    core::Process* p = core::CurrentProcess();
    if (p == nullptr)
        return kEINVAL;

    core::Process::LinuxSigAction& slot = p->linux_sigactions[signum];

    // Emit the previous value first — the syscall contract is
    // "atomic" so the oldact captures state from BEFORE the new
    // one is applied.
    if (old_act != 0)
    {
        u64 out[4] = {slot.handler_va, slot.flags, slot.restorer_va, slot.mask};
        if (!mm::CopyToUser(reinterpret_cast<void*>(old_act), out, sizeof(out)))
            return kEFAULT;
    }
    if (new_act != 0)
    {
        u64 in[4] = {0, 0, 0, 0};
        if (!mm::CopyFromUser(in, reinterpret_cast<const void*>(new_act), sizeof(in)))
            return kEFAULT;
        slot.handler_va = in[0];
        slot.flags = in[1];
        slot.restorer_va = in[2];
        slot.mask = in[3];
    }
    return 0;
}

// Linux: rt_sigprocmask(how, set, oldset, sigsetsize).
//   how == 0 SIG_BLOCK   — mask |= set
//   how == 1 SIG_UNBLOCK — mask &= ~set
//   how == 2 SIG_SETMASK — mask  = set
// No delivery yet; we just persist the mask so a subsequent
// rt_sigprocmask with set=NULL returns the value we stored.
i64 DoRtSigprocmask(u64 how, u64 user_set, u64 user_oldset, u64 sigsetsize)
{
    (void)sigsetsize;
    constexpr u64 kSigBlock = 0;
    constexpr u64 kSigUnblock = 1;
    constexpr u64 kSigSetMask = 2;
    core::Process* p = core::CurrentProcess();
    if (p == nullptr)
        return kEINVAL;
    const u64 prev = p->linux_signal_mask;
    if (user_oldset != 0)
    {
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_oldset), &prev, sizeof(prev)))
            return kEFAULT;
    }
    if (user_set != 0)
    {
        u64 set = 0;
        if (!mm::CopyFromUser(&set, reinterpret_cast<const void*>(user_set), sizeof(set)))
            return kEFAULT;
        switch (how)
        {
        case kSigBlock:
            p->linux_signal_mask = prev | set;
            break;
        case kSigUnblock:
            p->linux_signal_mask = prev & ~set;
            break;
        case kSigSetMask:
            p->linux_signal_mask = set;
            break;
        default:
            return kEINVAL;
        }
    }
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

    // Match exactly "/proc/self/exe". /proc/<PID>/exe is not
    // recognised yet — glibc's fallback uses /proc/self/exe too.
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
    // readlink does not write a trailing NUL; the return value is
    // the byte count the caller uses to terminate.
    return i64(to_copy);
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

// Linux: futex(uaddr, op, val, ...).
//
// Single-threaded processes have no contention, so we never
// actually block. The real Linux semantics we respect:
//   FUTEX_WAIT (0): if *uaddr != val, return -EAGAIN — tells the
//                   caller "the value already changed, try again".
//                   Otherwise return 0 (spurious wakeup — musl
//                   retries the condition).
//   FUTEX_WAKE (1): return 0 (no waiters, nothing to wake).
//
// FUTEX_PRIVATE_FLAG (0x80) masks off — it's a hint to the kernel
// about shared-memory scope, and for our single-address-space
// case it's a no-op.
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
        // Validate the caller's pointer and compare against `val`.
        // Copy fails with -EFAULT so a buggy program (e.g. null
        // uaddr) gets a specific error instead of a silent zero.
        u32 cur = 0;
        if (!mm::CopyFromUser(&cur, reinterpret_cast<const void*>(uaddr), sizeof(cur)))
            return kEFAULT;
        if (cur != u32(val))
            return -11; // -EAGAIN
        return 0;       // "spurious" wake — caller retries
    }
    if (base_op == kFutexWake)
    {
        return 0; // no waiters in single-thread v0
    }
    // Unknown op — reject so a test-suite like LTP gets -EINVAL
    // rather than silent success.
    (void)uaddr;
    (void)val;
    return kEINVAL;
}

// Read the CPU timestamp counter. Used as a seed for the tiny
// PRNG below — not intended as a clock.
[[maybe_unused]] u64 ReadTsc()
{
    u32 lo, hi;
    asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return (static_cast<u64>(hi) << 32) | lo;
}

// Linux: getrandom(buf, count, flags). Routes through the shared
// kernel entropy pool (RDSEED → RDRAND → splitmix) so a Linux
// userland's stack-cookie / pointer-mangling / crypto init get
// the same hardware backing the rest of the kernel uses. Real
// glibc / musl treat this syscall as cryptographic; we match
// that contract when the CPU supports RDSEED/RDRAND.
i64 DoGetRandom(u64 user_buf, u64 count, u64 flags)
{
    (void)flags;
    if (count == 0)
        return 0;
    if (count > 4096)
        count = 4096; // cap per call, same as Linux default for unseeded
    static u8 tmp[4096];
    core::RandomFillBytes(tmp, count);
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

// Linux: gettimeofday(tv, tz). tz is obsolete and ignored by modern
// kernels; we follow that contract and only fill timeval if non-null.
i64 DoGettimeofday(u64 user_tv, u64 user_tz)
{
    (void)user_tz;
    if (user_tv == 0)
        return 0;
    const u64 ns = NowNs();
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
    } info = {};
    info.uptime = static_cast<i64>(NowNs() / 1'000'000'000ull);
    info.procs = 1;
    info.mem_unit = 1;
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_info), &info, sizeof(info)))
        return kEFAULT;
    return 0;
}

i64 DoNoOp()
{
    return 0;
}

i64 DoFsync(u64 fd)
{
    (void)fd;
    return DoNoOp();
}

i64 DoFdatasync(u64 fd)
{
    (void)fd;
    return DoNoOp();
}

i64 DoMadvise(u64 addr, u64 len, u64 advice)
{
    (void)addr;
    (void)len;
    (void)advice;
    return DoNoOp();
}

i64 DoGetpgrp()
{
    return 0;
}

i64 DoGetrlimit(u64 user_old)
{
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

i64 DoPrlimit64(u64 user_old)
{
    if (user_old == 0)
        return 0;
    return DoGetrlimit(user_old);
}

i64 DoSetrlimit(u64 resource, u64 user_new)
{
    (void)resource;
    (void)user_new;
    return DoNoOp();
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
// much time is left if interrupted — is always zeroed; DuetOS
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
// DuetOS doesn't have a user-account model yet. Returning 0
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
// two cases:
//   1. Anonymous + private (musl malloc, static CRT bss growth).
//      Bumps a per-process VA cursor, allocates frames lazily,
//      maps RW+NX. PROT is ignored.
//   2. File-backed + private (MAP_PRIVATE without MAP_ANONYMOUS,
//      a regular fd). Loads the requested file extent into a
//      private writable copy — semantics matching Linux's
//      MAP_PRIVATE: writes go to the copy, never back to the
//      file. The reader's PROT_READ vs PROT_EXEC is honoured to
//      the extent the kernel can: PROT_EXEC clears the NX bit.
//      MAP_SHARED for files isn't supported — would need page-
//      cache + writeback we don't have.
//
// Returns the chosen VA as a u64 on success, -errno on failure.
// `addr` (MAP_FIXED) is ignored in v0; we always pick from the
// per-process bump cursor.
i64 DoMmap(u64 addr, u64 len, u64 prot, u64 flags, u64 fd, u64 off)
{
    (void)addr;
    if ((flags & kMapPrivate) == 0)
    {
        // MAP_SHARED without MAP_ANONYMOUS would need a page cache.
        // MAP_SHARED with MAP_ANONYMOUS would need shared frames.
        // Neither shape appears in our v0 workloads.
        return kEINVAL;
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

    // PTE flags: always present + user. Writable for anonymous
    // (callers expect to write to anonymous pages — that's what
    // they're for). For file-backed MAP_PRIVATE we still want
    // writable so MAP_PRIVATE write-fault semantics work as
    // "writes go to the private copy" without a CoW machinery —
    // we just hand out a writable private copy from the start.
    // NX is cleared only when PROT_EXEC is requested.
    u64 pte_flags = mm::kPagePresent | mm::kPageUser | mm::kPageWritable;
    constexpr u64 kProtExec = 0x4;
    if ((prot & kProtExec) == 0)
        pte_flags |= mm::kPageNoExecute;

    if ((flags & kMapAnonymous) != 0)
    {
        // Anonymous path — frames come up zero-filled (the frame
        // allocator scrubs them).
        for (u64 va = base; va < base + aligned; va += mm::kPageSize)
        {
            const mm::PhysAddr frame = mm::AllocateFrame();
            if (frame == mm::kNullFrame)
            {
                // Partial-map rollback would require tearing down the
                // mappings we already installed. v0 leaks on OOM —
                // the process is about to die, AS teardown reclaims.
                return kENOMEM;
            }
            mm::AddressSpaceMapUserPage(p->as, va, frame, pte_flags);
        }
        p->linux_mmap_cursor += aligned;
        arch::SerialWrite("[linux] mmap anon -> ");
        arch::SerialWriteHex(base);
        arch::SerialWrite(" len=");
        arch::SerialWriteHex(aligned);
        arch::SerialWrite("\n");
        return static_cast<i64>(base);
    }

    // File-backed: validate the fd is open against a regular
    // FAT32 file (state == 2). Special tty fds (state == 1) and
    // closed slots (state == 0) reject with -EBADF / -EACCES.
    if (fd >= 16)
        return kEBADF;
    // state==1 is a tty fd, state==0 is a closed slot. Both
    // invalid for mmap; collapse to -EBADF (real Linux returns
    // -EACCES for ttys, -EBADF for closed — we don't carry an
    // errno distinct enough to be worth a dedicated constant).
    if (p->linux_fds[fd].state != 2)
        return kEBADF;

    const auto* v = fs::fat32::Fat32Volume(0);
    if (v == nullptr)
        return kEIO;

    // Read the file. The existing DoRead path streams through a
    // 4 KiB scratch; for mmap we pull the whole file (up to a v0
    // cap matching the read scratch) so we can copy slices into
    // each freshly-allocated frame at the requested offset.
    static u8 file_scratch[4096];
    fs::fat32::DirEntry entry;
    for (u64 i = 0; i < sizeof(entry.name); ++i)
        entry.name[i] = 0;
    entry.attributes = 0;
    entry.first_cluster = p->linux_fds[fd].first_cluster;
    entry.size_bytes = p->linux_fds[fd].size;
    const i64 read_total = fs::fat32::Fat32ReadFile(v, &entry, file_scratch, sizeof(file_scratch));
    if (read_total < 0)
        return kEIO;
    const u64 file_size = static_cast<u64>(read_total);

    // Walk the requested range page by page. Each page is freshly
    // allocated (so this is a private copy), then either:
    //   - filled from file_scratch[off + page_off ..]   (in-range), or
    //   - left zero (if the page is past EOF — Linux MAP_PRIVATE
    //     pads past-EOF pages with zeros; the fault sees zero,
    //     a SIGBUS would only happen mid-page-of-EOF on real
    //     Linux, which we don't replicate at v0).
    for (u64 page_idx = 0; page_idx * mm::kPageSize < aligned; ++page_idx)
    {
        const u64 va = base + page_idx * mm::kPageSize;
        const mm::PhysAddr frame = mm::AllocateFrame();
        if (frame == mm::kNullFrame)
            return kENOMEM;
        // Frame allocator zeros the frame; we only need to copy
        // the bytes that fall inside the file.
        u8* dst = static_cast<u8*>(mm::PhysToVirt(frame));
        const u64 page_off_in_file = off + page_idx * mm::kPageSize;
        if (page_off_in_file < file_size)
        {
            u64 to_copy = file_size - page_off_in_file;
            if (to_copy > mm::kPageSize)
                to_copy = mm::kPageSize;
            for (u64 i = 0; i < to_copy; ++i)
                dst[i] = file_scratch[page_off_in_file + i];
        }
        mm::AddressSpaceMapUserPage(p->as, va, frame, pte_flags);
    }
    p->linux_mmap_cursor += aligned;
    arch::SerialWrite("[linux] mmap file fd=");
    arch::SerialWriteHex(fd);
    arch::SerialWrite(" -> ");
    arch::SerialWriteHex(base);
    arch::SerialWrite(" len=");
    arch::SerialWriteHex(aligned);
    arch::SerialWrite(" off=");
    arch::SerialWriteHex(off);
    arch::SerialWrite("\n");
    return static_cast<i64>(base);
}

// Linux: munmap(addr, len). Walks every 4 KiB page in
// [addr, addr+len) and asks the AS to release it. Pages that
// weren't mapped by mmap() (or were already unmapped) are silently
// ignored — matches Linux's relaxed behaviour where munmap of an
// un-mapped range is a no-op rather than -EINVAL.
i64 DoMunmap(u64 addr, u64 len)
{
    if (len == 0)
        return 0;
    if ((addr & 0xFFF) != 0)
        return kEINVAL;
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || p->as == nullptr)
        return kEINVAL;
    const u64 aligned_len = (len + 0xFFF) & ~u64(0xFFF);
    u64 freed = 0;
    for (u64 off = 0; off < aligned_len; off += mm::kPageSize)
    {
        if (mm::AddressSpaceUnmapUserPage(p->as, addr + off))
            ++freed;
    }
    arch::SerialWrite("[linux] munmap addr=");
    arch::SerialWriteHex(addr);
    arch::SerialWrite(" len=");
    arch::SerialWriteHex(aligned_len);
    arch::SerialWrite(" pages_released=");
    arch::SerialWriteHex(freed);
    arch::SerialWrite("\n");
    return 0;
}

// Linux: openat(dirfd, pathname, flags, mode). Modern glibc's
// `open()` is usually `openat(AT_FDCWD, ...)` under the hood —
// this handler is what real compiled-C binaries actually hit.
// v0 only honours AT_FDCWD; any other dirfd is -EBADF until
// per-fd directory state lands (same limitation fchdir has).
i64 DoOpenat(i64 dirfd, u64 user_path, u64 flags, u64 mode)
{
    if (dirfd != kAtFdCwd)
        return kEBADF;
    return DoOpen(user_path, flags, mode);
}

// Linux: newfstatat(dirfd, pathname, statbuf, flags).
// Shape: if AT_EMPTY_PATH (0x1000) is set + dirfd is a valid fd,
// stat the fd (≡ fstat). Else resolve `pathname` relative to
// dirfd (we only accept AT_FDCWD for now). No-follow-symlink
// flag (0x100) is accepted + ignored — we have no symlinks.
i64 DoNewFstatat(i64 dirfd, u64 user_path, u64 user_buf, u64 flags)
{
    constexpr u64 kAtEmptyPath = 0x1000;
    if ((flags & kAtEmptyPath) != 0)
    {
        if (dirfd < 0)
            return kEBADF;
        return DoFstat(static_cast<u64>(dirfd), user_buf);
    }
    if (dirfd != kAtFdCwd)
        return kEBADF;
    return DoStat(user_path, user_buf);
}

// Linux: dup3(oldfd, newfd, flags). Same as dup2 but requires
// oldfd != newfd (else -EINVAL) and optionally takes O_CLOEXEC
// (0x80000). We don't track CLOEXEC so the flag is accepted but
// a no-op. Everything else is DoDup2.
i64 DoDup3(u64 oldfd, u64 newfd, u64 flags)
{
    if (oldfd == newfd)
        return kEINVAL;
    constexpr u64 kOCloexec = 0x80000;
    if ((flags & ~kOCloexec) != 0)
        return kEINVAL;
    return DoDup2(oldfd, newfd);
}

// Linux: getrusage(who, usage). Returns resource-usage stats
// for self/children/thread. v0 has no per-task CPU-time
// accounting exposed here — zero the struct so any `usage.ru_*`
// read by the caller sees a well-defined 0 rather than garbage.
// Struct layout (144 bytes): {ru_utime:16, ru_stime:16, 14×u64}.
i64 DoGetrusage(u64 who, u64 user_buf)
{
    (void)who;
    if (user_buf == 0)
        return kEFAULT;
    u8 zeros[144];
    for (u64 i = 0; i < sizeof(zeros); ++i)
        zeros[i] = 0;
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_buf), zeros, sizeof(zeros)))
        return kEFAULT;
    return 0;
}

// Linux: poll(fds, nfds, timeout_ms). Returns count of fds that
// are ready. v0 has no event-driven fd machinery (all fds are
// either ttys that "block" on read and return immediately on
// write, or regular files that are always "ready" for read
// with available bytes). Matching caller expectations:
//   - If any pollfd has POLLIN/POLLOUT requested for a live
//     fd, mark it ready in revents and count it. That's what a
//     caller like "wait until stdin has input" would see on a
//     tty — immediately ready, non-blocking.
//   - A zero-nfds poll with a non-negative timeout is a
//     Linux-idiomatic nanosleep; we accept + return 0.
// All edge cases (POLLHUP, POLLERR, negative timeout = "wait
// forever") are returned as 0 revents (=no event), which is
// honest — we'd need a proper wait-queue per fd to do more.
constexpr i64 kPollIn = 0x0001;
constexpr i64 kPollOut = 0x0004;
i64 DoPoll(u64 user_fds, u64 nfds, i64 timeout_ms)
{
    (void)timeout_ms;
    if (nfds == 0)
        return 0;
    if (user_fds == 0)
        return kEFAULT;
    // Cap at 16 — matches our per-process fd table; larger polls
    // are surely bogus until we support more. Each pollfd is
    // 8 bytes: {int fd, short events, short revents}.
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
            // Closed slot — POSIX says revents=POLLNVAL (0x20).
            fds[i].revents = 0x20;
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

// Linux: select(nfds, readfds, writefds, exceptfds, timeout).
// Boundary-probe stub — we don't implement real fd bitmap
// dispatch. Return "0 ready" which tells the caller "your
// timeout expired without any event" — harmless, lets the
// caller loop or move on. Real implementations rarely reach
// select() anymore (poll/epoll dominate); synxtest probes it
// to show the stub is present.
i64 DoSelect(u64 nfds, u64 rfds, u64 wfds, u64 efds, u64 timeout)
{
    (void)nfds;
    (void)rfds;
    (void)wfds;
    (void)efds;
    (void)timeout;
    return 0;
}

// Linux: getdents64(fd, dirp, count). Read directory entries
// into the user buffer. v0 has no readable per-fd directory
// state — when we get a dirfd we don't know where we are in
// the enumeration. Returning 0 means "end of directory", which
// makes `ls` print nothing rather than looping. Honest partial
// implementation; a real one requires a per-fd cursor into the
// FAT32 root, which the existing fd state doesn't carry.
i64 DoGetdents64(u64 fd, u64 user_buf, u64 count)
{
    (void)fd;
    (void)user_buf;
    (void)count;
    return 0;
}

// Linux: set_robust_list(head, len). musl's thread init calls
// this. We have no robust-futex wake-on-exit machinery, so
// accepting + no-op is the honest glibc-compat move.
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

// ---------------------------------------------------------------
// Batch 55 — compat-stub + FAT32-backed handlers for the most-
// commonly-probed unimplemented syscalls. See the kSys* enum
// block at the top for the list and rationale.
// ---------------------------------------------------------------

constexpr i64 kEPERM = -1;
constexpr i64 kENOMEM_ = -12; // shadow-named to avoid collision with kENOMEM above

// lstat is identical to stat in v0 — there are no symlinks.
i64 DoLstat(u64 user_path, u64 user_buf)
{
    return DoStat(user_path, user_buf);
}

// pause(): suspend until a signal arrives. v0 has no signal
// delivery, so this would block forever. Sleep in big chunks
// instead of a tight yield loop so the scheduler isn't burning
// cycles on us. Returns -EINTR conventionally on wake; since we
// never wake, the return is unreachable.
i64 DoPause()
{
    constexpr u64 kHugeTicks = 1ull << 30; // ~3.4 yrs at 100 Hz
    for (;;)
    {
        sched::SchedSleepTicks(kHugeTicks);
    }
    return 0;
}

// mremap(): we have no remap-in-place machinery. -ENOMEM is the
// canonical "couldn't grow your mapping" return; callers fall
// back to alloc-new + memcpy + unmap, which already works via
// mmap/munmap.
i64 DoMremap(u64 old_addr, u64 old_len, u64 new_len, u64 flags, u64 new_addr)
{
    (void)old_addr;
    (void)old_len;
    (void)new_len;
    (void)flags;
    (void)new_addr;
    return kENOMEM_;
}

// msync(): write-back of a memory mapping. v0 mmap is anonymous-
// only; there's nothing to flush. Return success so MAP_SHARED
// emulation doesn't fail.
i64 DoMsync(u64 addr, u64 len, u64 flags)
{
    (void)addr;
    (void)len;
    (void)flags;
    return 0;
}

// mincore(addr, len, vec): mark every page in [addr, addr+len)
// as resident by writing 1 to each byte of the user vec. v0
// has no swap and no page reclaim, so every mapped page IS
// resident. Bad address surfaces as EFAULT.
i64 DoMincore(u64 addr, u64 len, u64 user_vec)
{
    (void)addr;
    if (user_vec == 0)
        return kEFAULT;
    const u64 pages = (len + 0xFFFu) / 0x1000u;
    if (pages == 0)
        return 0;
    // Cap at a reasonable batch so a hostile huge `len` doesn't
    // make us copy a multi-MiB byte vector. 4096 pages = 16 MiB
    // of mapping covered per call; larger ranges chunk caller-side.
    constexpr u64 kMaxPages = 4096;
    const u64 to_mark = (pages > kMaxPages) ? kMaxPages : pages;
    static u8 ones[kMaxPages];
    for (u64 i = 0; i < to_mark; ++i)
        ones[i] = 1;
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_vec), ones, to_mark))
        return kEFAULT;
    return 0;
}

// flock(fd, op): advisory file lock. v0 is single-process for
// the FAT32 mount; advisory locks are no-ops by definition.
i64 DoFlock(u64 fd, u64 op)
{
    (void)fd;
    (void)op;
    return 0;
}

// chmod / fchmod / chown / fchown / lchown: v0 has no permission
// model and no uid/gid model. Return 0 so install scripts and
// build tools (which routinely chmod +x their outputs) don't bail.
i64 DoChmod(u64 user_path, u64 mode)
{
    (void)user_path;
    (void)mode;
    return 0;
}
i64 DoFchmod(u64 fd, u64 mode)
{
    (void)fd;
    (void)mode;
    return 0;
}
i64 DoChown(u64 user_path, u64 uid, u64 gid)
{
    (void)user_path;
    (void)uid;
    (void)gid;
    return 0;
}
i64 DoFchown(u64 fd, u64 uid, u64 gid)
{
    (void)fd;
    (void)uid;
    (void)gid;
    return 0;
}
i64 DoLchown(u64 user_path, u64 uid, u64 gid)
{
    return DoChown(user_path, uid, gid);
}

// times(buf): fill struct tms with user/system/cuser/csys clock
// counts. v0 has no per-process accounting, so the same monotonic
// tick count goes in all four slots; the return value is the
// canonical "ticks since boot" Linux defines.
i64 DoTimes(u64 user_buf)
{
    const u64 t = arch::TimerTicks();
    if (user_buf != 0)
    {
        struct
        {
            u64 utime;
            u64 stime;
            u64 cutime;
            u64 cstime;
        } tms = {t, t, 0, 0};
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_buf), &tms, sizeof(tms)))
            return kEFAULT;
    }
    return static_cast<i64>(t);
}

// setuid / setgid / setreuid / setregid / setresuid / setresgid:
// v0 is uid 0 / gid 0 across the board. Accept the call as a
// no-op so setuid-root daemons started under us don't fail.
i64 DoSetuid(u64 uid)
{
    (void)uid;
    return 0;
}
i64 DoSetgid(u64 gid)
{
    (void)gid;
    return 0;
}
i64 DoSetreuid(u64 ruid, u64 euid)
{
    (void)ruid;
    (void)euid;
    return 0;
}
i64 DoSetregid(u64 rgid, u64 egid)
{
    (void)rgid;
    (void)egid;
    return 0;
}
i64 DoSetresuid(u64 ruid, u64 euid, u64 suid)
{
    (void)ruid;
    (void)euid;
    (void)suid;
    return 0;
}
i64 DoSetresgid(u64 rgid, u64 egid, u64 sgid)
{
    (void)rgid;
    (void)egid;
    (void)sgid;
    return 0;
}

// getresuid / getresgid (id_t* ruid, id_t* euid, id_t* suid):
// write three u32 zeros so the caller sees a consistent uid/gid
// triple. Bad pointers surface as EFAULT.
i64 DoGetresuid(u64 user_r, u64 user_e, u64 user_s)
{
    const u32 zero = 0;
    if (user_r != 0 && !mm::CopyToUser(reinterpret_cast<void*>(user_r), &zero, sizeof(zero)))
        return kEFAULT;
    if (user_e != 0 && !mm::CopyToUser(reinterpret_cast<void*>(user_e), &zero, sizeof(zero)))
        return kEFAULT;
    if (user_s != 0 && !mm::CopyToUser(reinterpret_cast<void*>(user_s), &zero, sizeof(zero)))
        return kEFAULT;
    return 0;
}
i64 DoGetresgid(u64 user_r, u64 user_e, u64 user_s)
{
    return DoGetresuid(user_r, user_e, user_s);
}

// setfsuid / setfsgid: returns the PREVIOUS fsuid/fsgid, which
// is always 0 in v0.
i64 DoSetfsuid(u64 uid)
{
    (void)uid;
    return 0;
}
i64 DoSetfsgid(u64 gid)
{
    (void)gid;
    return 0;
}

// getgroups(size, list): return the supplementary group list.
// v0 has none; return 0 (count of groups in the list). Linux
// allows size=0 as a "how many groups would there be" probe;
// our answer is still 0.
i64 DoGetgroups(u64 size, u64 user_list)
{
    (void)size;
    (void)user_list;
    return 0;
}
// setgroups(size, list): accept as no-op. Refusing would break
// setuid-style binaries that drop their groups before privsep.
i64 DoSetgroups(u64 size, u64 user_list)
{
    (void)size;
    (void)user_list;
    return 0;
}

// capget / capset: POSIX capabilities. v0 has no Linux-style
// capability model (we have our own CapSet, but it's not the
// same shape). Accept the call as a no-op so libcap-using
// programs initialise without complaining.
i64 DoCapget(u64 user_hdr, u64 user_data)
{
    (void)user_hdr;
    (void)user_data;
    return 0;
}
i64 DoCapset(u64 user_hdr, u64 user_data)
{
    (void)user_hdr;
    (void)user_data;
    return 0;
}

// utime(path, buf): set atime/mtime on a file. v0 doesn't track
// either, so accept as no-op.
i64 DoUtime(u64 user_path, u64 user_buf)
{
    (void)user_path;
    (void)user_buf;
    return 0;
}

// mknod(path, mode, dev): create a special file (FIFO, char,
// block, etc.). v0 has none of these. -EPERM is the standard
// "you don't have CAP_MKNOD" return; honest enough.
i64 DoMknod(u64 user_path, u64 mode, u64 dev)
{
    (void)user_path;
    (void)mode;
    (void)dev;
    return kEPERM;
}

// personality(persona): query/set the process's execution
// personality (32-bit emulation, address-space layout quirks,
// etc.). v0 only ever runs as the default Linux personality;
// return 0 as both "current persona" and "set succeeded".
i64 DoPersonality(u64 persona)
{
    (void)persona;
    return 0;
}

// getpriority / setpriority: nice-value query/set. v0 scheduler
// is a flat round-robin with no priority levels. Return 0 (the
// neutral nice value) on get; accept any set as a no-op.
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

// mlock / munlock / mlockall / munlockall: pin pages in RAM.
// v0 has no swap and no page reclaim — every mapped page is
// already pinned. Accept as no-op success.
i64 DoMlock(u64 addr, u64 len)
{
    (void)addr;
    (void)len;
    return 0;
}
i64 DoMunlock(u64 addr, u64 len)
{
    (void)addr;
    (void)len;
    return 0;
}
i64 DoMlockall(u64 flags)
{
    (void)flags;
    return 0;
}
i64 DoMunlockall()
{
    return 0;
}

// FAT32-backed filesystem ops. All four route through the
// existing Fat32*AtPath primitives. Path strip mirrors DoOpen:
// musl uses absolute paths, FAT32 wants volume-relative.

// Helper: copy a user path into a 64-byte kernel buffer +
// strip the FAT32 mount prefix. Returns true on success, false
// if the copy failed or the path is unterminated. Out points
// inside `kbuf`; lifetime tracks `kbuf`.
bool CopyAndStripFatPath(u64 user_path, char (&kbuf)[64], const char*& out_leaf)
{
    for (u32 i = 0; i < sizeof(kbuf); ++i)
        kbuf[i] = 0;
    if (!mm::CopyFromUser(kbuf, reinterpret_cast<const void*>(user_path), sizeof(kbuf) - 1))
        return false;
    kbuf[sizeof(kbuf) - 1] = 0;
    bool has_nul = false;
    for (u32 i = 0; i < sizeof(kbuf); ++i)
    {
        if (kbuf[i] == 0)
        {
            has_nul = true;
            break;
        }
    }
    if (!has_nul)
        return false;
    out_leaf = StripFatPrefix(kbuf);
    return true;
}

// truncate(path, length): shrink/grow a file to `length` bytes.
i64 DoTruncate(u64 user_path, u64 length)
{
    char kbuf[64];
    const char* leaf = nullptr;
    if (!CopyAndStripFatPath(user_path, kbuf, leaf))
        return kEFAULT;
    const auto* v = fs::fat32::Fat32Volume(0);
    if (v == nullptr)
        return kENOENT;
    const i64 rc = fs::fat32::Fat32TruncateAtPath(v, leaf, length);
    if (rc < 0)
        return kEIO;
    return 0;
}

// ftruncate(fd, length): same as truncate but by fd. Use the
// cached path on the LinuxFd entry.
i64 DoFtruncate(u64 fd, u64 length)
{
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd >= 16 || p->linux_fds[fd].state != 2)
        return kEBADF;
    const auto* v = fs::fat32::Fat32Volume(0);
    if (v == nullptr)
        return kENOENT;
    const i64 rc = fs::fat32::Fat32TruncateAtPath(v, p->linux_fds[fd].path, length);
    if (rc < 0)
        return kEIO;
    // Keep the cached size in sync — a future read/write needs it.
    p->linux_fds[fd].size = static_cast<u32>(length);
    return 0;
}

// unlink(path): delete a file. Returns 0 on success, -ENOENT
// if the file doesn't exist.
i64 DoUnlink(u64 user_path)
{
    char kbuf[64];
    const char* leaf = nullptr;
    if (!CopyAndStripFatPath(user_path, kbuf, leaf))
        return kEFAULT;
    const auto* v = fs::fat32::Fat32Volume(0);
    if (v == nullptr)
        return kENOENT;
    if (!fs::fat32::Fat32DeleteAtPath(v, leaf))
        return kENOENT;
    return 0;
}

// mkdir(path, mode): create a directory. Mode is ignored (no
// permission model).
i64 DoMkdir(u64 user_path, u64 mode)
{
    (void)mode;
    char kbuf[64];
    const char* leaf = nullptr;
    if (!CopyAndStripFatPath(user_path, kbuf, leaf))
        return kEFAULT;
    const auto* v = fs::fat32::Fat32Volume(0);
    if (v == nullptr)
        return kENOENT;
    if (!fs::fat32::Fat32MkdirAtPath(v, leaf))
        return kEIO;
    return 0;
}

// rmdir(path): remove an empty directory.
i64 DoRmdir(u64 user_path)
{
    char kbuf[64];
    const char* leaf = nullptr;
    if (!CopyAndStripFatPath(user_path, kbuf, leaf))
        return kEFAULT;
    const auto* v = fs::fat32::Fat32Volume(0);
    if (v == nullptr)
        return kENOENT;
    if (!fs::fat32::Fat32RmdirAtPath(v, leaf))
        return kEIO;
    return 0;
}

// ---------------------------------------------------------------
// Batch 56 — additional compat stubs + *at-family delegations.
// ---------------------------------------------------------------

// AT_REMOVEDIR flag for unlinkat.
constexpr u64 kAtRemoveDir = 0x200;

// Helper: for *at syscalls, v0 only supports AT_FDCWD. Returns
// kEBADF for any other dirfd value, 0 otherwise. Logged so a
// caller that happens to pass a real dirfd sees why the call
// fails instead of chasing a phantom bug.
i64 AtFdCwdOnly(i64 dirfd)
{
    if (dirfd == kAtFdCwd)
        return 0;
    arch::SerialWrite("[linux] *at-family: unsupported dirfd=");
    arch::SerialWriteHex(static_cast<u64>(dirfd));
    arch::SerialWrite(" (AT_FDCWD-only in v0)\n");
    return kEBADF;
}

// ptrace(request, pid, addr, data): process tracing. v0 has no
// ptrace machinery. -EPERM is the "tracing not permitted" return
// Linux gives to unprivileged callers.
i64 DoPtrace(u64 request, u64 pid, u64 addr, u64 data)
{
    (void)request;
    (void)pid;
    (void)addr;
    (void)data;
    return kEPERM;
}

// syslog(type, bufp, len): kernel log read/control. Every type
// is a no-op success in v0 — kernel log lives on COM1, not in a
// user-readable ring buffer. Returns 0 for "nothing written".
i64 DoSyslog(u64 type, u64 bufp, u64 len)
{
    (void)type;
    (void)bufp;
    (void)len;
    return 0;
}

// setsid: create a new session. v0 has no session/group model;
// accept as no-op success. Linux returns the new sid; 0 is fine
// as a stand-in.
i64 DoSetsid()
{
    return 0;
}

// vhangup: revoke the controlling terminal. No tty model — 0.
i64 DoVhangup()
{
    return 0;
}

// acct(filename): BSD process accounting. We do no accounting.
i64 DoAcct(u64 filename)
{
    (void)filename;
    return 0;
}

// mount(source, target, fstype, flags, data): mount a filesystem.
// v0 mounts FAT32 volume 0 implicitly at boot and does not expose
// a user-mode mount API. -EPERM is the appropriate return.
i64 DoMount(u64 source, u64 target, u64 fstype, u64 flags, u64 data)
{
    (void)source;
    (void)target;
    (void)fstype;
    (void)flags;
    (void)data;
    return kEPERM;
}
i64 DoUmount2(u64 target, u64 flags)
{
    (void)target;
    (void)flags;
    return kEPERM;
}

// sync / syncfs: flush cached writes to backing store. v0 FAT32
// writes are synchronous (no page cache), so there's nothing to
// flush.
i64 DoSync()
{
    return 0;
}
i64 DoSyncfs(u64 fd)
{
    (void)fd;
    return 0;
}

// rename(old, new) / link(old, new) / symlink(target, linkpath):
// no rename / link primitive in fat32 v0. -ENOSYS tells musl
// "this operation is not available on this kernel" — clearer
// than an -EPERM "you're not allowed" lie.
i64 DoRename(u64 old_path, u64 new_path)
{
    (void)old_path;
    (void)new_path;
    return kENOSYS;
}
i64 DoLink(u64 old_path, u64 new_path)
{
    (void)old_path;
    (void)new_path;
    return kENOSYS;
}
i64 DoSymlink(u64 target, u64 linkpath)
{
    (void)target;
    (void)linkpath;
    return kENOSYS;
}

// set_thread_area / get_thread_area: x86_32 LDT entry for TLS.
// 64-bit code uses arch_prctl(ARCH_SET_FS) instead. Reject cleanly.
i64 DoSetThreadArea(u64 u_info)
{
    (void)u_info;
    return kEINVAL;
}
i64 DoGetThreadArea(u64 u_info)
{
    (void)u_info;
    return kEINVAL;
}

// ioprio_get / ioprio_set: per-process I/O priority. Flat
// scheduler; accept + return 0 (the default "BE / nice=4" level).
i64 DoIoprioGet(u64 which, u64 who)
{
    (void)which;
    (void)who;
    return 0;
}
i64 DoIoprioSet(u64 which, u64 who, u64 ioprio)
{
    (void)which;
    (void)who;
    (void)ioprio;
    return 0;
}

// sched_setaffinity(pid, cpusetsize, mask): pin to CPU set.
// SMP is BSP-only in v0; CPU 0 is the only valid affinity.
// Accept any mask; the call is a no-op.
i64 DoSchedSetaffinity(u64 pid, u64 cpusetsize, u64 user_mask)
{
    (void)pid;
    (void)cpusetsize;
    (void)user_mask;
    return 0;
}

// sched_getaffinity: return a mask with only CPU 0 set. Linux's
// returns the number of bytes actually written (usually 8).
i64 DoSchedGetaffinity(u64 pid, u64 cpusetsize, u64 user_mask)
{
    (void)pid;
    if (user_mask == 0)
        return kEFAULT;
    // Write 8 bytes: bit 0 set for CPU 0, rest zero.
    const u64 bytes = (cpusetsize < 8) ? cpusetsize : 8;
    if (bytes == 0)
        return kEINVAL;
    u8 mask[8] = {0x01, 0, 0, 0, 0, 0, 0, 0};
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_mask), mask, bytes))
        return kEFAULT;
    return static_cast<i64>(bytes);
}

// clock_getres(clk_id, res): clock resolution. Scheduler tick is
// 10 ms; HPET-backed clocks are ~70 ns (see DoClockGetTime comment).
// Use the coarser scheduler grain as the reported resolution.
i64 DoClockGetres(u64 clk_id, u64 user_res)
{
    (void)clk_id;
    if (user_res == 0)
        return 0;
    struct
    {
        i64 tv_sec;
        i64 tv_nsec;
    } ts = {0, 10'000'000}; // 10 ms
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_res), &ts, sizeof(ts)))
        return kEFAULT;
    return 0;
}

// clock_nanosleep(clk_id, flags, req, rem): absolute or relative
// sleep. Ignore flags (TIMER_ABSTIME would need monotonic-clock
// diff math; we treat everything as relative for v0) and route
// through DoNanosleep.
i64 DoClockNanosleep(u64 clk_id, u64 flags, u64 user_req, u64 user_rem)
{
    (void)clk_id;
    (void)flags;
    return DoNanosleep(user_req, user_rem);
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

// *at-family delegations. Every one of these routes through the
// non-*at handler when dirfd == AT_FDCWD, or returns -EBADF.

// mkdirat(dirfd, path, mode)
i64 DoMkdirat(i64 dirfd, u64 user_path, u64 mode)
{
    if (const i64 rv = AtFdCwdOnly(dirfd); rv != 0)
        return rv;
    return DoMkdir(user_path, mode);
}

// unlinkat(dirfd, path, flags): flags & AT_REMOVEDIR -> rmdir.
i64 DoUnlinkat(i64 dirfd, u64 user_path, u64 flags)
{
    if (const i64 rv = AtFdCwdOnly(dirfd); rv != 0)
        return rv;
    if (flags & kAtRemoveDir)
        return DoRmdir(user_path);
    return DoUnlink(user_path);
}

// linkat / symlinkat / renameat / renameat2 — all map onto the
// non-*at stubs that already return -ENOSYS.
i64 DoLinkat(i64 olddirfd, u64 oldpath, i64 newdirfd, u64 newpath, u64 flags)
{
    if (const i64 rv = AtFdCwdOnly(olddirfd); rv != 0)
        return rv;
    if (const i64 rv = AtFdCwdOnly(newdirfd); rv != 0)
        return rv;
    (void)flags;
    return DoLink(oldpath, newpath);
}
i64 DoSymlinkat(u64 target, i64 newdirfd, u64 linkpath)
{
    if (const i64 rv = AtFdCwdOnly(newdirfd); rv != 0)
        return rv;
    return DoSymlink(target, linkpath);
}
i64 DoRenameat(i64 olddirfd, u64 oldpath, i64 newdirfd, u64 newpath)
{
    if (const i64 rv = AtFdCwdOnly(olddirfd); rv != 0)
        return rv;
    if (const i64 rv = AtFdCwdOnly(newdirfd); rv != 0)
        return rv;
    return DoRename(oldpath, newpath);
}
i64 DoRenameat2(i64 olddirfd, u64 oldpath, i64 newdirfd, u64 newpath, u64 flags)
{
    (void)flags;
    return DoRenameat(olddirfd, oldpath, newdirfd, newpath);
}

// fchownat / futimesat / fchmodat / faccessat — identity/ACL
// mutations the caller wants; v0 has no permission model, so
// the non-*at versions are already no-ops. Delegate.
i64 DoFchownat(i64 dirfd, u64 user_path, u64 uid, u64 gid, u64 flags)
{
    if (const i64 rv = AtFdCwdOnly(dirfd); rv != 0)
        return rv;
    (void)flags;
    return DoChown(user_path, uid, gid);
}
i64 DoFutimesat(i64 dirfd, u64 user_path, u64 user_times)
{
    if (const i64 rv = AtFdCwdOnly(dirfd); rv != 0)
        return rv;
    return DoUtime(user_path, user_times);
}
i64 DoFchmodat(i64 dirfd, u64 user_path, u64 mode, u64 flags)
{
    if (const i64 rv = AtFdCwdOnly(dirfd); rv != 0)
        return rv;
    (void)flags;
    return DoChmod(user_path, mode);
}
i64 DoFaccessat(i64 dirfd, u64 user_path, u64 mode, u64 flags)
{
    if (const i64 rv = AtFdCwdOnly(dirfd); rv != 0)
        return rv;
    (void)flags;
    return DoAccess(user_path, mode);
}
i64 DoFaccessat2(i64 dirfd, u64 user_path, u64 mode, u64 flags)
{
    return DoFaccessat(dirfd, user_path, mode, flags);
}

// utimensat(dirfd, path, times, flags): set atime/mtime to
// nanosecond-precision values. No time-tracking in v0 — 0.
i64 DoUtimensat(i64 dirfd, u64 user_path, u64 user_times, u64 flags)
{
    if (dirfd != kAtFdCwd && user_path != 0)
        return kEBADF;
    (void)user_path;
    (void)user_times;
    (void)flags;
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

// Additional wrappers exposed for the NT→Linux translator. The
// Do* primitives they call through are in the anonymous namespace
// above, so cross-TU access has to go through these. Keep them
// thin — arg marshalling (NTSTATUS → errno, FILE_HANDLE → fd,
// LARGE_INTEGER → timespec) stays in the translator.
i64 LinuxClose(u64 fd)
{
    return DoClose(fd);
}
i64 LinuxOpen(u64 user_path, u64 flags, u64 mode)
{
    return DoOpen(user_path, flags, mode);
}
i64 LinuxLseek(u64 fd, i64 offset, u64 whence)
{
    return DoLseek(fd, offset, whence);
}
i64 LinuxFstat(u64 fd, u64 user_buf)
{
    return DoFstat(fd, user_buf);
}
i64 LinuxFsync(u64 fd)
{
    return DoFsync(fd);
}
i64 LinuxNanosleep(u64 user_req, u64 user_rem)
{
    return DoNanosleep(user_req, user_rem);
}
i64 LinuxSchedYield()
{
    sched::SchedYield();
    return 0;
}
[[noreturn]] void LinuxExit(u64 status)
{
    DoExitGroup(status);
    // DoExitGroup calls sched::SchedExit which is [[noreturn]].
    for (;;)
    {
        asm volatile("hlt");
    }
}
i64 LinuxGetPid()
{
    return DoGetPid();
}
i64 LinuxMmap(u64 addr, u64 len, u64 prot, u64 flags, u64 fd, u64 off)
{
    return DoMmap(addr, len, prot, flags, fd, off);
}
i64 LinuxMunmap(u64 addr, u64 len)
{
    return DoMunmap(addr, len);
}
i64 LinuxMprotect(u64 addr, u64 len, u64 prot)
{
    return DoMprotect(addr, len, prot);
}

extern "C" void LinuxSyscallDispatch(arch::TrapFrame* frame)
{
    if constexpr (kTraceLinuxSyscallDispatch)
    {
        KLOG_TRACE_SCOPE("linux/syscall", "LinuxSyscallDispatch");
    }

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
        rv = DoStat(frame->rdi, frame->rsi);
        break;
    case kSysLstat:
        rv = DoLstat(frame->rdi, frame->rsi);
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
    case kSysReadv:
        rv = DoReadv(frame->rdi, frame->rsi, frame->rdx);
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
    case kSysGettimeofday:
        rv = DoGettimeofday(frame->rdi, frame->rsi);
        break;
    case kSysSysinfo:
        rv = DoSysinfo(frame->rdi);
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
    case kSysFsync:
        rv = DoFsync(frame->rdi);
        break;
    case kSysFdatasync:
        rv = DoFdatasync(frame->rdi);
        break;
    case kSysMadvise:
        rv = DoMadvise(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysGetrlimit:
        rv = DoGetrlimit(frame->rsi);
        break;
    case kSysSetrlimit:
        rv = DoSetrlimit(frame->rdi, frame->rsi);
        break;
    case kSysPrlimit64:
        rv = DoPrlimit64(frame->r10);
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
    case kSysGetpgrp:
        rv = DoGetpgrp();
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
    case kSysOpenat:
        rv = DoOpenat(static_cast<i64>(frame->rdi), frame->rsi, frame->rdx, frame->r10);
        break;
    case kSysNewFstatat:
        rv = DoNewFstatat(static_cast<i64>(frame->rdi), frame->rsi, frame->rdx, frame->r10);
        break;
    case kSysDup3:
        rv = DoDup3(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysGetrusage:
        rv = DoGetrusage(frame->rdi, frame->rsi);
        break;
    case kSysPoll:
        rv = DoPoll(frame->rdi, frame->rsi, static_cast<i64>(frame->rdx));
        break;
    case kSysSelect:
        rv = DoSelect(frame->rdi, frame->rsi, frame->rdx, frame->r10, frame->r8);
        break;
    case kSysGetdents64:
        rv = DoGetdents64(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysSetRobustList:
        rv = DoSetRobustList(frame->rdi, frame->rsi);
        break;
    case kSysGetRobustList:
        rv = DoGetRobustList(frame->rdi, frame->rsi, frame->rdx);
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
        DoExit(frame->rdi);
        // Exit paths don't return; keep the compiler happy.
        rv = 0;
        break;
    case kSysExitGroup:
        DoExitGroup(frame->rdi);
        // Exit paths don't return; keep the compiler happy.
        rv = 0;
        break;
    case kSysGetPid:
        rv = DoGetPid();
        break;

    // Batch 55 dispatch — compat stubs + FAT32-backed FS ops.
    case kSysPause:
        rv = DoPause();
        break;
    case kSysMremap:
        rv = DoMremap(frame->rdi, frame->rsi, frame->rdx, frame->r10, frame->r8);
        break;
    case kSysMsync:
        rv = DoMsync(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysMincore:
        rv = DoMincore(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysFlock:
        rv = DoFlock(frame->rdi, frame->rsi);
        break;
    case kSysTruncate:
        rv = DoTruncate(frame->rdi, frame->rsi);
        break;
    case kSysFtruncate:
        rv = DoFtruncate(frame->rdi, frame->rsi);
        break;
    case kSysMkdir:
        rv = DoMkdir(frame->rdi, frame->rsi);
        break;
    case kSysRmdir:
        rv = DoRmdir(frame->rdi);
        break;
    case kSysUnlink:
        rv = DoUnlink(frame->rdi);
        break;
    case kSysChmod:
        rv = DoChmod(frame->rdi, frame->rsi);
        break;
    case kSysFchmod:
        rv = DoFchmod(frame->rdi, frame->rsi);
        break;
    case kSysChown:
        rv = DoChown(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysFchown:
        rv = DoFchown(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysLchown:
        rv = DoLchown(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysTimes:
        rv = DoTimes(frame->rdi);
        break;
    case kSysSetuid:
        rv = DoSetuid(frame->rdi);
        break;
    case kSysSetgid:
        rv = DoSetgid(frame->rdi);
        break;
    case kSysSetreuid:
        rv = DoSetreuid(frame->rdi, frame->rsi);
        break;
    case kSysSetregid:
        rv = DoSetregid(frame->rdi, frame->rsi);
        break;
    case kSysGetgroups:
        rv = DoGetgroups(frame->rdi, frame->rsi);
        break;
    case kSysSetgroups:
        rv = DoSetgroups(frame->rdi, frame->rsi);
        break;
    case kSysSetresuid:
        rv = DoSetresuid(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysGetresuid:
        rv = DoGetresuid(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysSetresgid:
        rv = DoSetresgid(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysGetresgid:
        rv = DoGetresgid(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysSetfsuid:
        rv = DoSetfsuid(frame->rdi);
        break;
    case kSysSetfsgid:
        rv = DoSetfsgid(frame->rdi);
        break;
    case kSysCapget:
        rv = DoCapget(frame->rdi, frame->rsi);
        break;
    case kSysCapset:
        rv = DoCapset(frame->rdi, frame->rsi);
        break;
    case kSysUtime:
        rv = DoUtime(frame->rdi, frame->rsi);
        break;
    case kSysMknod:
        rv = DoMknod(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysPersonality:
        rv = DoPersonality(frame->rdi);
        break;
    case kSysGetpriority:
        rv = DoGetpriority(frame->rdi, frame->rsi);
        break;
    case kSysSetpriority:
        rv = DoSetpriority(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysMlock:
        rv = DoMlock(frame->rdi, frame->rsi);
        break;
    case kSysMunlock:
        rv = DoMunlock(frame->rdi, frame->rsi);
        break;
    case kSysMlockall:
        rv = DoMlockall(frame->rdi);
        break;
    case kSysMunlockall:
        rv = DoMunlockall();
        break;

    // Batch 56 dispatch.
    case kSysPtrace:
        rv = DoPtrace(frame->rdi, frame->rsi, frame->rdx, frame->r10);
        break;
    case kSysSyslog:
        rv = DoSyslog(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysSetsid:
        rv = DoSetsid();
        break;
    case kSysVhangup:
        rv = DoVhangup();
        break;
    case kSysAcct:
        rv = DoAcct(frame->rdi);
        break;
    case kSysMount:
        rv = DoMount(frame->rdi, frame->rsi, frame->rdx, frame->r10, frame->r8);
        break;
    case kSysUmount2:
        rv = DoUmount2(frame->rdi, frame->rsi);
        break;
    case kSysSync:
        rv = DoSync();
        break;
    case kSysSyncfs:
        rv = DoSyncfs(frame->rdi);
        break;
    case kSysRename:
        rv = DoRename(frame->rdi, frame->rsi);
        break;
    case kSysLink:
        rv = DoLink(frame->rdi, frame->rsi);
        break;
    case kSysSymlink:
        rv = DoSymlink(frame->rdi, frame->rsi);
        break;
    case kSysSetThreadArea:
        rv = DoSetThreadArea(frame->rdi);
        break;
    case kSysGetThreadArea:
        rv = DoGetThreadArea(frame->rdi);
        break;
    case kSysIoprioGet:
        rv = DoIoprioGet(frame->rdi, frame->rsi);
        break;
    case kSysIoprioSet:
        rv = DoIoprioSet(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysSchedSetaffinity:
        rv = DoSchedSetaffinity(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysSchedGetaffinity:
        rv = DoSchedGetaffinity(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysClockGetres:
        rv = DoClockGetres(frame->rdi, frame->rsi);
        break;
    case kSysClockNanosleep:
        rv = DoClockNanosleep(frame->rdi, frame->rsi, frame->rdx, frame->r10);
        break;
    case kSysGetcpu:
        rv = DoGetcpu(frame->rdi, frame->rsi, frame->rdx);
        break;
    case kSysMkdirat:
        rv = DoMkdirat(static_cast<i64>(frame->rdi), frame->rsi, frame->rdx);
        break;
    case kSysUnlinkat:
        rv = DoUnlinkat(static_cast<i64>(frame->rdi), frame->rsi, frame->rdx);
        break;
    case kSysLinkat:
        rv = DoLinkat(static_cast<i64>(frame->rdi), frame->rsi, static_cast<i64>(frame->rdx), frame->r10, frame->r8);
        break;
    case kSysSymlinkat:
        rv = DoSymlinkat(frame->rdi, static_cast<i64>(frame->rsi), frame->rdx);
        break;
    case kSysRenameat:
        rv = DoRenameat(static_cast<i64>(frame->rdi), frame->rsi, static_cast<i64>(frame->rdx), frame->r10);
        break;
    case kSysRenameat2:
        rv = DoRenameat2(static_cast<i64>(frame->rdi), frame->rsi, static_cast<i64>(frame->rdx), frame->r10, frame->r8);
        break;
    case kSysFchownat:
        rv = DoFchownat(static_cast<i64>(frame->rdi), frame->rsi, frame->rdx, frame->r10, frame->r8);
        break;
    case kSysFutimesat:
        rv = DoFutimesat(static_cast<i64>(frame->rdi), frame->rsi, frame->rdx);
        break;
    case kSysFchmodat:
        rv = DoFchmodat(static_cast<i64>(frame->rdi), frame->rsi, frame->rdx, frame->r10);
        break;
    case kSysFaccessat:
        rv = DoFaccessat(static_cast<i64>(frame->rdi), frame->rsi, frame->rdx, frame->r10);
        break;
    case kSysFaccessat2:
        rv = DoFaccessat2(static_cast<i64>(frame->rdi), frame->rsi, frame->rdx, frame->r10);
        break;
    case kSysUtimensat:
        rv = DoUtimensat(static_cast<i64>(frame->rdi), frame->rsi, frame->rdx, frame->r10);
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

void LinuxLogAbiCoverage()
{
    // Re-walk the generated table at boot so a future refactor that
    // renames a Do* handler out of classifier reach is visible in the
    // boot log (count drops). The generated header also bakes compile-
    // time primary/effective counts so drift is obvious at boot.
    u32 primary = 0;
    u32 effective = 0;
    for (u32 i = 0; i < kLinuxSyscallCount; ++i)
    {
        if (kLinuxSyscalls[i].state == HandlerState::Implemented)
        {
            ++primary;
        }
    }
    effective = kLinuxSyscallHandlersImplementedEffective;

    arch::SerialWrite("[linux] ABI coverage: ");
    arch::SerialWrite("primary=");
    arch::SerialWriteHex(primary);
    arch::SerialWrite(" / ");
    arch::SerialWriteHex(kLinuxSyscallCount);
    arch::SerialWrite(", effective=");
    arch::SerialWriteHex(effective);
    arch::SerialWrite(" / ");
    arch::SerialWriteHex(kLinuxSyscallCount);
    arch::SerialWrite(" (generated primary=");
    arch::SerialWriteHex(kLinuxSyscallHandlersImplementedPrimary);
    arch::SerialWrite(", generated effective=");
    arch::SerialWriteHex(kLinuxSyscallHandlersImplementedEffective);
    arch::SerialWrite(")\n");
}

} // namespace duetos::subsystems::linux
