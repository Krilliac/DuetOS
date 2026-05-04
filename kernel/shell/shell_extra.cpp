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
#include "log/klog_persist.h"
#include "sched/loadavg.h"
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
        ShellSetExit(2);
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
        ShellSetExit(1);
        ConsoleWriteln("MKDIR: TMPFS IS FLAT (NO DIRECTORIES)");
        return;
    }
    ShellSetExit(1);
    ConsoleWriteln("MKDIR: ONLY /fat/<PATH> SUPPORTS DIRECTORIES");
}

void CmdRmdir(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ShellSetExit(2);
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
        ShellSetExit(1);
        ConsoleWriteln("RMDIR: TMPFS IS FLAT (NO DIRECTORIES)");
        return;
    }
    ShellSetExit(1);
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
        ShellSetExit(2);
        ConsoleWriteln("TRUNCATE: USAGE: TRUNCATE /tmp/<NAME> SIZE");
        return;
    }
    const char* leaf = TmpLeaf(argv[1]);
    if (leaf == nullptr || *leaf == '\0')
    {
        ShellSetExit(1);
        ConsoleWriteln("TRUNCATE: ONLY /tmp/<NAME> IS WRITABLE (USE FATTRUNC FOR /fat)");
        return;
    }
    u64 size_u64 = 0;
    if (!ParseU64Str(argv[2], &size_u64) || size_u64 > duetos::fs::kTmpFsContentMax)
    {
        ShellSetExit(2);
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
            ShellSetExit(1);
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
        ShellSetExit(2);
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
#if defined(__aarch64__)
    ConsoleWriteln("aarch64");
#elif defined(__x86_64__) || defined(_M_X64)
    ConsoleWriteln("x86_64");
#elif defined(__i386__) || defined(_M_IX86)
    ConsoleWriteln("i386");
#elif defined(__riscv) && (__riscv_xlen == 64)
    ConsoleWriteln("riscv64");
#else
    ConsoleWriteln("unknown");
#endif
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
        ShellSetExit(2);
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
    // POSIX `type`: no-match exits 1 so scripts can branch.
    ShellSetExit(1);
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
        ShellSetExit(2);
        ConsoleWriteln("DU: USAGE: DU PATH");
        return;
    }
    char scratch[duetos::fs::kTmpFsContentMax];
    const u32 n = ReadFileToBuf(argv[1], scratch, sizeof(scratch));
    if (n == static_cast<u32>(-1))
    {
        ShellSetExit(1);
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
    // Linux-style "X.YY X.YY X.YY tasks total=N ready=N cpus=N" line.
    // The three averages are EWMAs sampled every 5 seconds from the
    // scheduler tick handler — see kernel/sched/loadavg.cpp. Until
    // the first 5-second boundary after boot all three read 0.00,
    // which is also what Linux reports on a freshly-booted system.
    u32 one = 0;
    u32 five = 0;
    u32 fifteen = 0;
    duetos::sched::LoadavgSnapshot(&one, &five, &fifteen);
    char buf[16];
    duetos::sched::LoadavgFormat(buf, sizeof(buf), one);
    ConsoleWrite(buf);
    ConsoleWriteChar(' ');
    duetos::sched::LoadavgFormat(buf, sizeof(buf), five);
    ConsoleWrite(buf);
    ConsoleWriteChar(' ');
    duetos::sched::LoadavgFormat(buf, sizeof(buf), fifteen);
    ConsoleWrite(buf);

    // Keep the instantaneous counts as a trailing summary — useful
    // for scripts that want a one-line status without parsing the
    // moving averages.
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
    ConsoleWrite("  tasks total=");
    WriteU64Dec(slots[0]);
    ConsoleWrite(" ready=");
    WriteU64Dec(slots[1]);
    ConsoleWrite(" cpus=");
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
    // Every storage backend in v0 is synchronous — block-layer
    // writes return only after the device ACKs, and there is no
    // page cache to flush. So `sync` reduces to a structural
    // checkpoint: explicitly flush the persisted-log sink so any
    // buffered klog bytes hit FAT32 before the caller proceeds.
    // When an async block layer / page cache lands, additional
    // flush points (per-FS journal, dirty-page writeback) get
    // chained here.
    duetos::core::KlogPersistFlush();
    duetos::core::Log(duetos::core::LogLevel::Info, "shell", "sync: klog flushed; backends are synchronous");
    ConsoleWriteln("SYNC: OK (klog flushed; v0 backends are synchronous).");
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
        ShellSetExit(2);
        ConsoleWriteln("PORT: USAGE: PORT R PORT  |  PORT W PORT VALUE  (PORT and VALUE in 0x hex or decimal)");
        return;
    }
    u64 port_u64 = 0;
    if (!ParseU64Str(argv[2], &port_u64) || port_u64 > 0xFFFF)
    {
        ShellSetExit(2);
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
            ShellSetExit(2);
            ConsoleWriteln("PORT: WRITE NEEDS A VALUE BYTE");
            return;
        }
        u64 val_u64 = 0;
        if (!ParseU64Str(argv[3], &val_u64) || val_u64 > 0xFF)
        {
            ShellSetExit(2);
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
    ShellSetExit(2);
    ConsoleWriteln("PORT: UNKNOWN MODE (USE R OR W)");
}

// ---------------------------------------------------------------
// Scripting helpers: assert / watch / script.
//
// All three rebuild the rest-of-argv into a command line and recurse
// through Dispatch(). Sharing one helper keeps the bounded-buffer
// arithmetic in one spot — the per-handler paths just supply the
// surrounding wrapper logic (PASS/FAIL, periodic re-run, output
// capture).
// ---------------------------------------------------------------

namespace
{

// Join argv[start..argc-1] with single spaces into `out`. Caps at
// `cap` bytes and always nul-terminates. Returns the byte count
// written (excluding the nul). Used by assert / watch / script to
// reconstruct a command line the dispatcher can re-tokenise.
u32 JoinArgsToBuf(u32 argc, char** argv, u32 start, char* out, u32 cap)
{
    if (cap == 0)
        return 0;
    u32 n = 0;
    for (u32 i = start; i < argc; ++i)
    {
        if (i > start && n + 1 < cap)
            out[n++] = ' ';
        for (u32 k = 0; argv[i][k] != '\0' && n + 1 < cap; ++k)
            out[n++] = argv[i][k];
    }
    out[n] = '\0';
    return n;
}

} // namespace

void CmdAssert(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ShellSetExit(2);
        ConsoleWriteln("ASSERT: USAGE: ASSERT CMD [ARGS...]");
        return;
    }
    char buf[kInputMax];
    JoinArgsToBuf(argc, argv, 1, buf, sizeof(buf));
    Dispatch(buf);
    const i32 inner = ShellLastExit();
    if (inner == 0)
    {
        ConsoleWrite("ASSERT PASS: ");
        ConsoleWriteln(buf);
        ShellSetExit(0);
    }
    else
    {
        ConsoleWrite("ASSERT FAIL (exit=");
        WriteI64Dec(inner);
        ConsoleWrite("): ");
        ConsoleWriteln(buf);
        ShellSetExit(1);
    }
}

void CmdWatch(u32 argc, char** argv)
{
    if (argc < 3)
    {
        ShellSetExit(2);
        ConsoleWriteln("WATCH: USAGE: WATCH SECONDS CMD [ARGS...]");
        return;
    }
    u32 secs = 0;
    for (u32 i = 0; argv[1][i] != '\0'; ++i)
    {
        if (argv[1][i] < '0' || argv[1][i] > '9')
        {
            ShellSetExit(2);
            ConsoleWriteln("WATCH: BAD INTERVAL");
            return;
        }
        secs = secs * 10 + u32(argv[1][i] - '0');
    }
    if (secs == 0)
        secs = 1; // 0 would be a hot loop; bash watch defaults to 2
    char buf[kInputMax];
    JoinArgsToBuf(argc, argv, 2, buf, sizeof(buf));
    // Bound iterations so a wedged terminal doesn't loop forever.
    constexpr u32 kCap = 1000;
    for (u32 it = 0; it < kCap; ++it)
    {
        if (ShellInterruptRequested())
        {
            ConsoleWriteln("^C");
            return;
        }
        // Re-tokenise needs a writable copy each time; Dispatch
        // mutates its argument when it splits args.
        char run[kInputMax];
        for (u32 k = 0; k < sizeof(run); ++k)
            run[k] = buf[k];
        Dispatch(run);
        for (u32 s = 0; s < secs; ++s)
        {
            if (ShellInterruptRequested())
            {
                ConsoleWriteln("^C");
                return;
            }
            duetos::sched::SchedSleepTicks(100);
        }
    }
    ShellSetExit(0);
}

void CmdScript(u32 argc, char** argv)
{
    if (argc < 3)
    {
        ShellSetExit(2);
        ConsoleWriteln("SCRIPT: USAGE: SCRIPT /tmp/<NAME> CMD [ARGS...]");
        return;
    }
    const char* leaf = TmpLeaf(argv[1]);
    if (leaf == nullptr || *leaf == '\0')
    {
        ShellSetExit(1);
        ConsoleWriteln("SCRIPT: TARGET MUST BE /tmp/<NAME>");
        return;
    }
    char cmd[kInputMax];
    JoinArgsToBuf(argc, argv, 2, cmd, sizeof(cmd));
    // Capture into a stack buffer sized to the tmpfs slot cap, then
    // commit in one TmpFsWrite. ConsoleBeginCapture mirrors writes
    // into our buffer while still emitting them to the live console
    // — same pattern the pipe operator uses.
    char capbuf[duetos::fs::kTmpFsContentMax];
    u32 cap_used = 0;
    duetos::drivers::video::ConsoleBeginCapture(capbuf, sizeof(capbuf), &cap_used);
    Dispatch(cmd);
    const i32 inner = ShellLastExit();
    duetos::drivers::video::ConsoleEndCapture();
    if (!duetos::fs::TmpFsWrite(leaf, capbuf, cap_used))
    {
        ShellSetExit(1);
        ConsoleWriteln("SCRIPT: COULD NOT WRITE CAPTURE FILE");
        return;
    }
    ConsoleWrite("SCRIPT: wrote ");
    WriteU64Dec(cap_used);
    ConsoleWrite(" bytes to ");
    ConsoleWriteln(argv[1]);
    // Propagate the inner command's exit code so scripts can chain
    // `script /tmp/log foo && bar`.
    ShellSetExit(inner);
}

void CmdExit(u32 argc, char** argv)
{
    // `exit [N]` — short-circuit the enclosing script with code N
    // (default 0). Outside a script (typed at the prompt) this is
    // a no-op apart from setting $?: the kernel shell IS the user
    // surface, there is no parent process to terminate.
    i32 code = 0;
    if (argc >= 2)
    {
        const char* s = argv[1];
        bool neg = false;
        if (*s == '-')
        {
            neg = true;
            ++s;
        }
        if (*s == '\0')
        {
            ShellSetExit(2);
            ConsoleWriteln("EXIT: BAD CODE");
            return;
        }
        i32 v = 0;
        for (u32 i = 0; s[i] != '\0'; ++i)
        {
            if (s[i] < '0' || s[i] > '9')
            {
                ShellSetExit(2);
                ConsoleWriteln("EXIT: BAD CODE");
                return;
            }
            v = v * 10 + i32(s[i] - '0');
        }
        code = neg ? -v : v;
    }
    ScriptRequestExit(code);
}

} // namespace duetos::core::shell::internal
