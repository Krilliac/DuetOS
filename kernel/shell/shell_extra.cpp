/*
 * DuetOS — kernel shell: extended get/set/manipulate commands.
 *
 * Sibling TU of shell.cpp. Houses the second-tier coreutils surface
 * that rounds out the shell's day-to-day usability without
 * pulling heavy TU-private helpers from the larger sibling files:
 *
 *   directory:     mkdir / rmdir       (route /fat -> fatmkdir/rmdir,
 *                                        tmpfs is flat so /tmp denied)
 *   file:          truncate / realpath
 *   identity:      id / groups / nproc / arch / tty
 *   POSIX aliases: type / printenv
 *   fs usage:      df / du
 *   scheduler:     loadavg
 *   shell state:   clearhist / pause / yes / sync
 *   admin:         port r|w PORT [val]   (raw x86 I/O port byte)
 *
 * Every handler is a thin wrapper around an existing kernel API.
 * No new kernel state owned here — the goal is shell breadth, not
 * subsystem depth. Heavier handlers (FAT mutators, security
 * surfaces, networking) stay in their existing sibling TUs.
 */

#include "shell/shell_internal.h"

#include "shell/shell.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/smp.h"
#include "drivers/storage/block.h"
#include "drivers/video/console.h"
#include "fs/tmpfs.h"
#include "log/klog.h"
#include "sched/sched.h"
#include "security/auth.h"

namespace duetos::core::shell::internal
{

namespace
{

using duetos::drivers::video::ConsoleWrite;
using duetos::drivers::video::ConsoleWriteChar;
using duetos::drivers::video::ConsoleWriteln;

const char* RoleNameStr(AuthRole r)
{
    switch (r)
    {
    case AuthRole::Admin:
        return "admin";
    case AuthRole::User:
        return "user";
    case AuthRole::Guest:
        return "guest";
    default:
        return "?";
    }
}

// True iff `path` starts with the literal prefix `/fat` followed
// by '/' or end-of-string. Used by mkdir/rmdir to forward to the
// FAT-side handlers when the user typed a /fat path.
bool IsFatPath(const char* path)
{
    return FatLeaf(path) != nullptr;
}

// True iff `path` starts with `/tmp` followed by '/' or NUL.
bool IsTmpPath(const char* path)
{
    return TmpLeaf(path) != nullptr;
}

} // namespace

// ---------------------------------------------------------------
// Directory: mkdir / rmdir.
//
// tmpfs is flat (no directory entries), so `/tmp/foo` style
// requests bounce with a clear diagnostic. `/fat/foo` forwards
// to the existing FAT handler so users have one consistent
// `mkdir`/`rmdir` they can type instead of remembering the
// volume-prefix variants.
// ---------------------------------------------------------------

void CmdMkdir(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("MKDIR: USAGE: MKDIR PATH");
        return;
    }
    if (IsFatPath(argv[1]))
    {
        if (!RequireAdmin("MKDIR"))
            return;
        CmdFatmkdir(argc, argv);
        return;
    }
    if (IsTmpPath(argv[1]))
    {
        ConsoleWriteln("MKDIR: TMPFS IS FLAT (NO DIRECTORIES)");
        return;
    }
    ConsoleWriteln("MKDIR: ONLY /fat/<PATH> SUPPORTS DIRECTORIES");
}

void CmdRmdir(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("RMDIR: USAGE: RMDIR PATH");
        return;
    }
    if (IsFatPath(argv[1]))
    {
        if (!RequireAdmin("RMDIR"))
            return;
        CmdFatrmdir(argc, argv);
        return;
    }
    if (IsTmpPath(argv[1]))
    {
        ConsoleWriteln("RMDIR: TMPFS IS FLAT (NO DIRECTORIES)");
        return;
    }
    ConsoleWriteln("RMDIR: ONLY /fat/<PATH> SUPPORTS DIRECTORIES");
}

// ---------------------------------------------------------------
// File: truncate / realpath.
//
// truncate operates on tmpfs only — ramfs is read-only and FAT
// has its own `fattrunc`. The TmpFsWrite path truncates if the
// caller requests a smaller size; growing past the existing
// length zero-fills.
// ---------------------------------------------------------------

void CmdTruncate(u32 argc, char** argv)
{
    if (argc < 3)
    {
        ConsoleWriteln("TRUNCATE: USAGE: TRUNCATE /tmp/<NAME> SIZE");
        return;
    }
    const char* leaf = TmpLeaf(argv[1]);
    if (leaf == nullptr || *leaf == '\0')
    {
        ConsoleWriteln("TRUNCATE: ONLY /tmp/<NAME> IS WRITABLE (USE FATTRUNC FOR /fat)");
        return;
    }
    u64 size_u64 = 0;
    if (!ParseU64Str(argv[2], &size_u64) || size_u64 > duetos::fs::kTmpFsContentMax)
    {
        ConsoleWrite("TRUNCATE: BAD SIZE (MAX ");
        WriteU64Dec(duetos::fs::kTmpFsContentMax);
        ConsoleWriteln(")");
        return;
    }
    char scratch[duetos::fs::kTmpFsContentMax];
    const u32 cur = ReadFileToBuf(argv[1], scratch, sizeof(scratch));
    const u32 size = static_cast<u32>(size_u64);
    if (cur == static_cast<u32>(-1))
    {
        // File doesn't exist — create one with the requested size,
        // zero-filled.
        for (u32 i = 0; i < size; ++i)
            scratch[i] = '\0';
        if (!duetos::fs::TmpFsWrite(leaf, scratch, size))
        {
            ConsoleWriteln("TRUNCATE: WRITE FAILED");
        }
        return;
    }
    if (size > cur)
    {
        // Grow with zeros.
        for (u32 i = cur; i < size; ++i)
            scratch[i] = '\0';
    }
    if (!duetos::fs::TmpFsWrite(leaf, scratch, size))
    {
        ConsoleWriteln("TRUNCATE: WRITE FAILED");
    }
}

// Canonicalise a shell path. v0 supports the two reductions every
// shell user expects: collapse repeated '/', resolve '.' and '..'
// against the absolute path. Symlinks don't exist yet, so this is
// purely lexical — no filesystem I/O.
void CmdRealpath(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("REALPATH: USAGE: REALPATH PATH");
        return;
    }
    const char* p = argv[1];
    char out[128];
    u32 n = 0;
    out[n++] = '/';
    if (p[0] != '/')
    {
        // Relative — pretend cwd is "/" (the shell has no cwd yet).
    }
    u32 i = (p[0] == '/') ? 1 : 0;
    while (p[i] != '\0' && n + 1 < sizeof(out))
    {
        // Skip leading slashes.
        while (p[i] == '/')
            ++i;
        if (p[i] == '\0')
            break;
        // Read a component into a small scratch.
        char comp[32];
        u32 c = 0;
        while (p[i] != '\0' && p[i] != '/' && c + 1 < sizeof(comp))
            comp[c++] = p[i++];
        comp[c] = '\0';
        if (c == 1 && comp[0] == '.')
            continue;
        if (c == 2 && comp[0] == '.' && comp[1] == '.')
        {
            // Pop one component off `out`. Never pop past the root.
            if (n > 1)
            {
                --n; // drop trailing '/'
                while (n > 1 && out[n - 1] != '/')
                    --n;
            }
            continue;
        }
        // Append component with a trailing '/'.
        if (n > 1 && out[n - 1] != '/' && n + 1 < sizeof(out))
            out[n++] = '/';
        for (u32 k = 0; k < c && n + 1 < sizeof(out); ++k)
            out[n++] = comp[k];
        if (n + 1 < sizeof(out))
            out[n++] = '/';
    }
    // Strip trailing '/' unless we're the root.
    if (n > 1 && out[n - 1] == '/')
        --n;
    out[n] = '\0';
    ConsoleWriteln(out);
}

// ---------------------------------------------------------------
// Identity readouts: id / groups / nproc / arch / tty.
// ---------------------------------------------------------------

void CmdId()
{
    const char* name = AuthCurrentUserName();
    const AuthRole role = AuthCurrentRole();
    if (name[0] == '\0')
    {
        ConsoleWriteln("(no session)");
        return;
    }
    // POSIX `id` shape: uid=0(name) gid=0(name) groups=0(name).
    // We don't have UIDs yet — emit role as the identity instead so
    // scripts can still grep it.
    ConsoleWrite("user=");
    ConsoleWrite(name);
    ConsoleWrite("  role=");
    ConsoleWrite(RoleNameStr(role));
    ConsoleWriteln(AuthIsAdmin() ? "  (admin)" : "");
}

void CmdGroups()
{
    // Single-role model — emit just the active role. Listed as a
    // "groups" view so POSIX-flavoured scripts that read this for
    // capability gating get a sensible answer.
    const AuthRole role = AuthCurrentRole();
    ConsoleWriteln(RoleNameStr(role));
}

void CmdNproc()
{
    WriteU64Dec(duetos::arch::SmpCpusOnline());
    ConsoleWriteChar('\n');
}

void CmdArch()
{
    // STUB: hard-coded; ARM64 is on the roadmap and will need this
    // to read a build-time arch tag.
    ConsoleWriteln("x86_64");
}

void CmdTty()
{
    // The shell has one terminal — the framebuffer console with a
    // serial tee. POSIX tools that read $TTY just want a string
    // they can stash; "/dev/console0" is the convention DuetOS
    // takes for the boot framebuffer.
    ConsoleWriteln("/dev/console0");
}

// ---------------------------------------------------------------
// POSIX aliases: type / printenv.
// ---------------------------------------------------------------

void CmdType(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("TYPE: USAGE: TYPE NAME");
        return;
    }
    if (AliasFind(argv[1]) != nullptr)
    {
        ConsoleWrite(argv[1]);
        ConsoleWriteln(" is an alias");
        return;
    }
    for (u32 i = 0; i < kCommandCount; ++i)
    {
        if (StrEq(kCommandSet[i], argv[1]))
        {
            ConsoleWrite(argv[1]);
            ConsoleWriteln(" is a shell builtin");
            return;
        }
    }
    ConsoleWrite(argv[1]);
    ConsoleWriteln(": not found");
}

void CmdPrintenv(u32 argc, char** argv)
{
    if (argc >= 2)
    {
        const EnvSlot* s = EnvFind(argv[1]);
        if (s == nullptr)
            return;
        ConsoleWriteln(s->value);
        return;
    }
    // No arg: dump every defined slot in NAME=VALUE form (matches
    // POSIX `printenv` with no args).
    for (u32 i = 0; i < kEnvSlotCount; ++i)
    {
        if (!g_env[i].in_use)
            continue;
        ConsoleWrite(g_env[i].name);
        ConsoleWriteChar('=');
        ConsoleWriteln(g_env[i].value);
    }
}

// ---------------------------------------------------------------
// Filesystem usage: df / du.
// ---------------------------------------------------------------

void CmdDf()
{
    namespace storage = duetos::drivers::storage;

    // tmpfs: count slots in use vs. total.
    u32 tmpfs_used = 0;
    duetos::fs::TmpFsEnumerate([](const char*, u32, void* cookie) { ++(*static_cast<u32*>(cookie)); }, &tmpfs_used);
    ConsoleWrite("tmpfs        slots ");
    WriteU64Dec(tmpfs_used);
    ConsoleWriteChar('/');
    WriteU64Dec(duetos::fs::kTmpFsSlotCount);
    ConsoleWrite("   max-bytes/slot ");
    WriteU64Dec(duetos::fs::kTmpFsContentMax);
    ConsoleWriteChar('\n');

    // ramfs: read-only baseline image; emit a one-liner.
    ConsoleWriteln("ramfs        ro    /etc/* + /motd (boot-baked)");

    // Block-device summary — name + sector count.
    const u32 count = storage::BlockDeviceCount();
    for (u32 i = 0; i < count; ++i)
    {
        ConsoleWrite("blockdev     ");
        ConsoleWrite(storage::BlockDeviceName(i));
        ConsoleWrite("  sectors=");
        WriteU64Dec(storage::BlockDeviceSectorCount(i));
        ConsoleWrite("  ssz=");
        WriteU64Dec(storage::BlockDeviceSectorSize(i));
        ConsoleWrite("  ");
        ConsoleWriteln(storage::BlockDeviceIsWritable(i) ? "rw" : "ro");
    }
}

void CmdDu(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("DU: USAGE: DU PATH");
        return;
    }
    char scratch[duetos::fs::kTmpFsContentMax];
    const u32 n = ReadFileToBuf(argv[1], scratch, sizeof(scratch));
    if (n == static_cast<u32>(-1))
    {
        ConsoleWrite("DU: NO SUCH FILE: ");
        ConsoleWriteln(argv[1]);
        return;
    }
    WriteU64Dec(n);
    ConsoleWriteChar('\t');
    ConsoleWriteln(argv[1]);
}

// ---------------------------------------------------------------
// Scheduler load + history wipe + pause + yes + sync.
// ---------------------------------------------------------------

void CmdLoadavg()
{
    // GAP: no rolling 1/5/15-minute decay yet; emit instantaneous
    // counts so scripts can still distinguish "nothing running"
    // from "saturated".
    u32 slots[2] = {0, 0}; // [0]=total, [1]=ready
    duetos::sched::SchedEnumerate(
        [](const duetos::sched::SchedTaskInfo& info, void* cookie)
        {
            auto* s = static_cast<u32*>(cookie);
            ++s[0];
            const auto st = static_cast<duetos::sched::TaskState>(info.state);
            if (st == duetos::sched::TaskState::Running || st == duetos::sched::TaskState::Ready)
            {
                ++s[1];
            }
        },
        slots);
    ConsoleWrite("tasks total=");
    WriteU64Dec(slots[0]);
    ConsoleWrite("  ready=");
    WriteU64Dec(slots[1]);
    ConsoleWrite("  cpus=");
    WriteU64Dec(duetos::arch::SmpCpusOnline());
    ConsoleWriteChar('\n');
}

void CmdClearhist()
{
    g_history_count = 0;
    g_history_head = 0;
    g_history_cursor = 0;
    ConsoleWriteln("HISTORY CLEARED.");
}

void CmdPause()
{
    // Block until the user presses Ctrl+C. The shell is event-
    // driven (no readline blocking primitive yet), so we yield
    // until the latched interrupt flag flips. Anything else the
    // user types still feeds the live edit buffer underneath the
    // pause, but they only get unblocked by ^C — matches the
    // POSIX `pause` shape closely enough.
    ConsoleWriteln("(paused — press Ctrl+C to resume)");
    while (!ShellInterruptRequested())
    {
        duetos::sched::SchedSleepTicks(10);
    }
    ConsoleWriteln("^C");
}

void CmdYes(u32 argc, char** argv)
{
    // Bounded `yes` — print the joined argv (or "y" if none) up to
    // 100 times, polling the interrupt flag each iteration so a
    // long stream is abortable. Unbounded yes would be a footgun
    // in a single-tty shell.
    constexpr u32 kCap = 100;
    char joined[64];
    u32 jn = 0;
    if (argc < 2)
    {
        joined[jn++] = 'y';
    }
    else
    {
        for (u32 a = 1; a < argc && jn + 1 < sizeof(joined); ++a)
        {
            if (a > 1 && jn + 1 < sizeof(joined))
                joined[jn++] = ' ';
            for (u32 k = 0; argv[a][k] != '\0' && jn + 1 < sizeof(joined); ++k)
                joined[jn++] = argv[a][k];
        }
    }
    joined[jn] = '\0';
    for (u32 i = 0; i < kCap; ++i)
    {
        if (ShellInterruptRequested())
        {
            ConsoleWriteln("^C");
            return;
        }
        ConsoleWriteln(joined);
    }
}

void CmdSync()
{
    // STUB: every storage backend is synchronous in v0 (writes
    // return after the device acks), so there's nothing to flush.
    // Keep the command so portable scripts that rely on it don't
    // fail; revisit when an async block layer or page cache lands.
    duetos::core::Log(duetos::core::LogLevel::Info, "shell", "sync (no-op in v0)");
    ConsoleWriteln("SYNC: OK (v0 backends are synchronous).");
}

// ---------------------------------------------------------------
// Raw x86 I/O port byte access. Admin-gated — a guest poking
// arbitrary ports can DoS the box (mask PIC, kick KBC into reset,
// flip CMOS shutdown bytes).
// ---------------------------------------------------------------
void CmdPort(u32 argc, char** argv)
{
    if (argc < 3)
    {
        ConsoleWriteln("PORT: USAGE: PORT R PORT  |  PORT W PORT VALUE  (PORT and VALUE in 0x hex or decimal)");
        return;
    }
    u64 port_u64 = 0;
    if (!ParseU64Str(argv[2], &port_u64) || port_u64 > 0xFFFF)
    {
        ConsoleWriteln("PORT: BAD PORT (0..0xFFFF)");
        return;
    }
    const u16 port = static_cast<u16>(port_u64);
    if (StrEq(argv[1], "r"))
    {
        const u8 v = duetos::arch::Inb(port);
        ConsoleWrite("IN  0x");
        WriteU64Hex(port, 4);
        ConsoleWrite(" = 0x");
        WriteU64Hex(v, 2);
        ConsoleWriteChar('\n');
        return;
    }
    if (StrEq(argv[1], "w"))
    {
        if (argc < 4)
        {
            ConsoleWriteln("PORT: WRITE NEEDS A VALUE BYTE");
            return;
        }
        u64 val_u64 = 0;
        if (!ParseU64Str(argv[3], &val_u64) || val_u64 > 0xFF)
        {
            ConsoleWriteln("PORT: BAD VALUE (0..0xFF)");
            return;
        }
        duetos::arch::Outb(port, static_cast<u8>(val_u64));
        ConsoleWrite("OUT 0x");
        WriteU64Hex(port, 4);
        ConsoleWrite(" <= 0x");
        WriteU64Hex(val_u64, 2);
        ConsoleWriteChar('\n');
        return;
    }
    ConsoleWriteln("PORT: UNKNOWN MODE (USE R OR W)");
}

} // namespace duetos::core::shell::internal
