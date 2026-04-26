/*
 * DuetOS — kernel shell: utility commands.
 *
 * Sibling TU of shell.cpp. Houses the lightweight commands that
 * touch one or two subsystems and don't pull a heavy chain of
 * TU-private helpers still living in shell.cpp.
 *
 *   basename / dirname  pure string
 *   flushtlb            CR3 reload
 *   mem                 frame-allocator totals
 *   mode                display-mode query
 *   history             reads the hoisted history ring
 *   sleep               scheduler tick block
 *   shutdown            ACPI S5 + halt fallback
 *   color               ConsoleSetColours
 *   rand                kernel entropy pool
 *   uuid                UuidV4 / UuidFormat
 *   checksum            FNV1a32 over a file body
 *   reset               console clear + /etc/motd reprint
 *   tac / nl / rev      line-wise file transformations
 *   expr                small integer calculator
 *   hexdump             classic 16-byte dump
 *   stat                tmpfs/ramfs metadata
 *   cal                 month grid via RTC
 *   beep                PC speaker
 *
 * Anything heavier (Repeat, which recurses through Dispatch;
 * Source, which recurses too; AttackSim, which is security-
 * specific) stays in shell.cpp until its caller moves with it.
 */

#include "shell_internal.h"

#include "../acpi/acpi.h"
#include "../arch/x86_64/cpu.h"
#include "../arch/x86_64/cpu_info.h"
#include "../arch/x86_64/rtc.h"
#include "../arch/x86_64/serial.h"
#include "../drivers/audio/pcspk.h"
#include "../drivers/video/console.h"
#include "../drivers/video/widget.h"
#include "../fs/ramfs.h"
#include "../fs/tmpfs.h"
#include "../fs/vfs.h"
#include "../mm/frame_allocator.h"
#include "../sched/sched.h"
#include "random.h"

#include "shell.h"

namespace duetos::core::shell::internal
{

namespace
{

using duetos::drivers::video::ConsoleWrite;
using duetos::drivers::video::ConsoleWriteChar;
using duetos::drivers::video::ConsoleWriteln;

} // namespace

void CmdBasename(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("BASENAME: USAGE: BASENAME PATH");
        return;
    }
    const char* p = argv[1];
    u32 last_slash = 0;
    bool have = false;
    for (u32 i = 0; p[i] != '\0'; ++i)
    {
        if (p[i] == '/')
        {
            last_slash = i;
            have = true;
        }
    }
    if (!have)
    {
        ConsoleWriteln(p);
        return;
    }
    // Everything after the last '/'. Empty (trailing slash) →
    // print the original path minus slashes, matching coreutils.
    const char* tail = p + last_slash + 1;
    if (*tail == '\0')
    {
        ConsoleWriteln(p);
    }
    else
    {
        ConsoleWriteln(tail);
    }
}

void CmdDirname(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("DIRNAME: USAGE: DIRNAME PATH");
        return;
    }
    const char* p = argv[1];
    u32 last_slash = 0;
    bool have = false;
    for (u32 i = 0; p[i] != '\0'; ++i)
    {
        if (p[i] == '/')
        {
            last_slash = i;
            have = true;
        }
    }
    if (!have)
    {
        ConsoleWriteln(".");
        return;
    }
    if (last_slash == 0)
    {
        ConsoleWriteln("/");
        return;
    }
    for (u32 i = 0; i < last_slash; ++i)
    {
        ConsoleWriteChar(p[i]);
    }
    ConsoleWriteChar('\n');
}

void CmdFlushTlb()
{
    // Reload CR3 with its current value — the classic x86_64
    // "flush every non-global TLB entry" primitive. Global
    // pages survive (they're typically kernel direct-map);
    // anything else is cold on next access.
    const u64 cr3 = duetos::arch::ReadCr3();
    asm volatile("mov %0, %%cr3" : : "r"(cr3) : "memory");
    ConsoleWriteln("TLB FLUSHED (CR3 RELOAD).");
}

void CmdMem()
{
    const u64 total = duetos::mm::TotalFrames();
    const u64 free_frames = duetos::mm::FreeFramesCount();
    const u64 used = total - free_frames;
    constexpr u64 kPageKiB = 4;
    ConsoleWrite("TOTAL  ");
    WriteU64Dec(total);
    ConsoleWrite(" FRAMES (");
    WriteU64Dec(total * kPageKiB);
    ConsoleWriteln(" KIB)");
    ConsoleWrite("USED   ");
    WriteU64Dec(used);
    ConsoleWrite(" FRAMES (");
    WriteU64Dec(used * kPageKiB);
    ConsoleWriteln(" KIB)");
    ConsoleWrite("FREE   ");
    WriteU64Dec(free_frames);
    ConsoleWrite(" FRAMES (");
    WriteU64Dec(free_frames * kPageKiB);
    ConsoleWriteln(" KIB)");
}

void CmdMode()
{
    const auto mode = duetos::drivers::video::GetDisplayMode();
    ConsoleWrite("CURRENT MODE: ");
    ConsoleWriteln(mode == duetos::drivers::video::DisplayMode::Tty ? "TTY (FULLSCREEN CONSOLE)"
                                                                    : "DESKTOP (WINDOWED SHELL)");
    ConsoleWriteln("PRESS CTRL+ALT+T TO TOGGLE.");
}

void CmdHistory()
{
    if (g_history_count == 0)
    {
        ConsoleWriteln("(NO HISTORY)");
        return;
    }
    // Display oldest-first so the numbers count in typing order —
    // readers intuit "1 is the first thing I ran" even though
    // internally `HistoryAt(1)` is the newest entry. Swap the
    // mapping here; callers of `!N` use the same convention.
    for (u32 i = g_history_count; i > 0; --i)
    {
        const u32 display_num = g_history_count - i + 1;
        ConsoleWrite("  ");
        WriteU64Dec(display_num);
        ConsoleWrite("  ");
        ConsoleWriteln(HistoryAt(i));
    }
}

void CmdSleep(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("SLEEP: USAGE: SLEEP SECONDS");
        return;
    }
    u32 secs = 0;
    for (u32 i = 0; argv[1][i] != '\0'; ++i)
    {
        if (argv[1][i] < '0' || argv[1][i] > '9')
        {
            ConsoleWriteln("SLEEP: BAD NUMBER");
            return;
        }
        secs = secs * 10 + static_cast<u32>(argv[1][i] - '0');
    }
    // 100 Hz scheduler tick → 100 ticks per second. Sleep via
    // the scheduler's block-on-tick primitive so the CPU
    // genuinely yields to other tasks, rather than spin-waiting.
    // Poll the interrupt flag in 1-second increments so Ctrl+C
    // can abort a long sleep.
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

[[noreturn]] void CmdShutdownNow()
{
    ConsoleWriteln("SHUTDOWN: evaluating AML \\_S5 + writing PM1a...");
    duetos::arch::SerialWrite("[shell] user invoked shutdown\n");
    // Flush any last bytes by driving a dummy serial write
    // before the PM1 write that may cut power mid-instruction.
    if (duetos::acpi::AcpiShutdown())
    {
        // AcpiShutdown returns true only on never-reached paths;
        // v0 implementation always returns after the write. Fall
        // through.
    }
    // Firmware didn't honour S5 (most common on QEMU TCG unless
    // -machine pc / q35 + the _PTS method runs, which we skip).
    // Fall back to reboot, then halt if that also fails.
    ConsoleWriteln("SHUTDOWN: S5 not honoured; falling back to halt.");
    duetos::arch::Halt();
}

void CmdColor(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("COLOR: USAGE: COLOR FG_HEX [BG_HEX]");
        ConsoleWriteln("  EXAMPLES: COLOR 00FFFF          (cyan on current bg)");
        ConsoleWriteln("            COLOR A0C8FF 101828  (light blue on dark navy)");
        ConsoleWriteln("  SHELL DEFAULTS: COLOR 80F088 181028");
        return;
    }
    u32 fg = 0, bg = 0;
    if (!ParseHex32(argv[1], &fg))
    {
        ConsoleWriteln("COLOR: BAD FG HEX");
        return;
    }
    // Default bg to whatever the shell console is using — we
    // don't expose a getter, so just read a sane fallback:
    // the existing shell bg (dark navy-ish). Users can pass
    // their own.
    bg = 0x00181028;
    if (argc >= 3)
    {
        if (!ParseHex32(argv[2], &bg))
        {
            ConsoleWriteln("COLOR: BAD BG HEX");
            return;
        }
    }
    duetos::drivers::video::ConsoleSetColours(fg, bg);
    ConsoleWriteln("COLOR: UPDATED. NEXT REDRAW USES THE NEW PALETTE.");
}

void CmdRand(u32 argc, char** argv)
{
    // Modes:
    //   rand           - one u64 from the kernel entropy pool
    //   rand N         - N u64s (cap 100)
    //   rand -s        - show entropy-pool stats + current tier
    //   rand -hex N    - N hex bytes (cap 512) on a single line
    // The pool is seeded once at boot by RandomInit; each `rand`
    // call drains fresh bytes (RDSEED/RDRAND/splitmix per tier).
    if (argc >= 2 && argv[1][0] == '-' && argv[1][1] == 's' && argv[1][2] == '\0')
    {
        const auto s = duetos::core::RandomStatsRead();
        const auto t = duetos::core::RandomCurrentTier();
        ConsoleWrite("TIER:          ");
        switch (t)
        {
        case duetos::core::EntropyTier::Rdseed:
            ConsoleWriteln("RDSEED (NIST TRNG)");
            break;
        case duetos::core::EntropyTier::Rdrand:
            ConsoleWriteln("RDRAND (NIST DRBG)");
            break;
        default:
            ConsoleWriteln("splitmix64 (NOT cryptographic)");
            break;
        }
        ConsoleWrite("RDSEED CALLS:  ");
        WriteU64Dec(s.rdseed_calls);
        ConsoleWriteChar('\n');
        ConsoleWrite("RDSEED OKS:    ");
        WriteU64Dec(s.rdseed_successes);
        ConsoleWriteChar('\n');
        ConsoleWrite("RDRAND CALLS:  ");
        WriteU64Dec(s.rdrand_calls);
        ConsoleWriteChar('\n');
        ConsoleWrite("RDRAND OKS:    ");
        WriteU64Dec(s.rdrand_successes);
        ConsoleWriteChar('\n');
        ConsoleWrite("SPLITMIX:      ");
        WriteU64Dec(s.splitmix_calls);
        ConsoleWriteChar('\n');
        ConsoleWrite("BYTES OUT:     ");
        WriteU64Dec(s.bytes_produced);
        ConsoleWriteChar('\n');
        return;
    }
    if (argc >= 3 && argv[1][0] == '-' && argv[1][1] == 'h' && argv[1][2] == 'e' && argv[1][3] == 'x' &&
        argv[1][4] == '\0')
    {
        u32 bytes = 0;
        for (u32 i = 0; argv[2][i] != '\0'; ++i)
        {
            if (argv[2][i] < '0' || argv[2][i] > '9')
            {
                ConsoleWriteln("RAND: BAD COUNT");
                return;
            }
            bytes = bytes * 10 + u32(argv[2][i] - '0');
        }
        if (bytes > 512)
            bytes = 512;
        u8 buf[512];
        duetos::core::RandomFillBytes(buf, bytes);
        for (u32 i = 0; i < bytes; ++i)
            WriteU64Hex(buf[i], 2);
        ConsoleWriteChar('\n');
        return;
    }
    u32 n = 1;
    if (argc >= 2)
    {
        n = 0;
        for (u32 i = 0; argv[1][i] != '\0'; ++i)
        {
            if (argv[1][i] < '0' || argv[1][i] > '9')
            {
                ConsoleWriteln("RAND: BAD COUNT");
                return;
            }
            n = n * 10 + static_cast<u32>(argv[1][i] - '0');
        }
    }
    if (n > 100)
    {
        n = 100;
    }
    for (u32 i = 0; i < n; ++i)
    {
        WriteU64Hex(duetos::core::RandomU64());
        ConsoleWriteChar('\n');
    }
}

void CmdUuid(u32 argc, char** argv)
{
    // Default: one UUID. `uuid N` prints N (cap 20).
    u32 n = 1;
    if (argc >= 2)
    {
        n = 0;
        for (u32 i = 0; argv[1][i] != '\0'; ++i)
        {
            if (argv[1][i] < '0' || argv[1][i] > '9')
            {
                ConsoleWriteln("UUID: BAD COUNT");
                return;
            }
            n = n * 10 + u32(argv[1][i] - '0');
        }
    }
    if (n > 20)
        n = 20;
    char buf[37];
    for (u32 i = 0; i < n; ++i)
    {
        const auto u = duetos::core::UuidV4();
        duetos::core::UuidFormat(u, buf);
        ConsoleWriteln(buf);
    }
}

void CmdChecksum(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("CHECKSUM: USAGE: CHECKSUM PATH");
        return;
    }
    char scratch[duetos::fs::kTmpFsContentMax];
    const u32 n = ReadFileToBuf(argv[1], scratch, sizeof(scratch));
    if (n == static_cast<u32>(-1))
    {
        ConsoleWrite("CHECKSUM: NO SUCH FILE: ");
        ConsoleWriteln(argv[1]);
        return;
    }
    // FNV-1a 32-bit. Fast, no allocation, good enough for
    // shell-level "did this file change" sanity.
    u32 h = 0x811C9DC5u;
    for (u32 i = 0; i < n; ++i)
    {
        h ^= static_cast<u8>(scratch[i]);
        h *= 0x01000193u;
    }
    ConsoleWrite("FNV1A32 ");
    WriteU64Hex(h, 8);
    ConsoleWriteChar(' ');
    ConsoleWriteln(argv[1]);
}

void CmdReset()
{
    // Wipe the console + reprint the boot banner. Same content
    // ShellInit emits; useful when the scrollback is cluttered
    // or the user just switched terminals.
    duetos::drivers::video::ConsoleClear();
    char scratch[duetos::fs::kTmpFsContentMax];
    const u32 n = ReadFileToBuf("/etc/motd", scratch, sizeof(scratch));
    if (n != static_cast<u32>(-1))
    {
        for (u32 i = 0; i < n; ++i)
        {
            ConsoleWriteChar(scratch[i]);
        }
    }
}

void CmdTac(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("TAC: USAGE: TAC PATH");
        return;
    }
    char scratch[duetos::fs::kTmpFsContentMax];
    const u32 n = ReadFileToBuf(argv[1], scratch, sizeof(scratch));
    if (n == static_cast<u32>(-1))
    {
        ConsoleWrite("TAC: NO SUCH FILE: ");
        ConsoleWriteln(argv[1]);
        return;
    }
    constexpr u32 kMaxLines = 128;
    u32 offs[kMaxLines];
    u32 lens[kMaxLines];
    const u32 count = SliceLines(scratch, n, offs, lens, kMaxLines);
    // Print lines in reverse order. Each line is a range
    // (offs[i], lens[i]) inside the original scratch.
    for (u32 i = count; i > 0; --i)
    {
        const u32 idx = i - 1;
        for (u32 k = 0; k < lens[idx]; ++k)
        {
            ConsoleWriteChar(scratch[offs[idx] + k]);
        }
        ConsoleWriteChar('\n');
    }
}

void CmdNl(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("NL: USAGE: NL PATH");
        return;
    }
    char scratch[duetos::fs::kTmpFsContentMax];
    const u32 n = ReadFileToBuf(argv[1], scratch, sizeof(scratch));
    if (n == static_cast<u32>(-1))
    {
        ConsoleWrite("NL: NO SUCH FILE: ");
        ConsoleWriteln(argv[1]);
        return;
    }
    u32 line_num = 1;
    u32 start = 0;
    for (u32 i = 0; i <= n; ++i)
    {
        const bool at_end = (i == n);
        if (at_end || scratch[i] == '\n')
        {
            const u32 len = i - start;
            // Right-align the line number in a 5-col field
            // to match standard `nl` output.
            char num[8];
            u32 nn = 0;
            u32 v = line_num;
            if (v == 0)
            {
                num[nn++] = '0';
            }
            else
            {
                while (v > 0)
                {
                    num[nn++] = static_cast<char>('0' + (v % 10));
                    v /= 10;
                }
            }
            for (u32 pad = nn; pad < 5; ++pad)
            {
                ConsoleWriteChar(' ');
            }
            for (u32 k = nn; k > 0; --k)
            {
                ConsoleWriteChar(num[k - 1]);
            }
            ConsoleWrite("  ");
            for (u32 k = 0; k < len; ++k)
            {
                ConsoleWriteChar(scratch[start + k]);
            }
            ConsoleWriteChar('\n');
            ++line_num;
            start = i + 1;
        }
    }
}

void CmdRev(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("REV: USAGE: REV PATH");
        return;
    }
    char scratch[duetos::fs::kTmpFsContentMax];
    const u32 n = ReadFileToBuf(argv[1], scratch, sizeof(scratch));
    if (n == static_cast<u32>(-1))
    {
        ConsoleWrite("REV: NO SUCH FILE: ");
        ConsoleWriteln(argv[1]);
        return;
    }
    u32 start = 0;
    for (u32 i = 0; i <= n; ++i)
    {
        const bool at_end = (i == n);
        if (at_end || scratch[i] == '\n')
        {
            const u32 len = i - start;
            for (u32 k = len; k > 0; --k)
            {
                ConsoleWriteChar(scratch[start + k - 1]);
            }
            ConsoleWriteChar('\n');
            start = i + 1;
        }
    }
}

void CmdExpr(u32 argc, char** argv)
{
    if (argc < 4)
    {
        ConsoleWriteln("EXPR: USAGE: EXPR A OP B   (OP = + - * / %)");
        return;
    }
    i64 a = 0, b = 0;
    if (!ParseI64(argv[1], &a) || !ParseI64(argv[3], &b))
    {
        ConsoleWriteln("EXPR: BAD NUMBER");
        return;
    }
    const char* op = argv[2];
    if (op[1] != '\0')
    {
        ConsoleWriteln("EXPR: BAD OPERATOR");
        return;
    }
    i64 r = 0;
    switch (op[0])
    {
    case '+':
        r = a + b;
        break;
    case '-':
        r = a - b;
        break;
    case '*':
        r = a * b;
        break;
    case '/':
        if (b == 0)
        {
            ConsoleWriteln("EXPR: DIVIDE BY ZERO");
            return;
        }
        r = a / b;
        break;
    case '%':
        if (b == 0)
        {
            ConsoleWriteln("EXPR: DIVIDE BY ZERO");
            return;
        }
        r = a % b;
        break;
    default:
        ConsoleWriteln("EXPR: BAD OPERATOR");
        return;
    }
    WriteI64Dec(r);
    ConsoleWriteChar('\n');
}

void CmdHexdump(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("HEXDUMP: USAGE: HEXDUMP PATH");
        return;
    }
    char scratch[duetos::fs::kTmpFsContentMax];
    const u32 n = ReadFileToBuf(argv[1], scratch, sizeof(scratch));
    if (n == static_cast<u32>(-1))
    {
        ConsoleWrite("HEXDUMP: NO SUCH FILE: ");
        ConsoleWriteln(argv[1]);
        return;
    }
    // Classic 16-byte row: "OFFSET  HH HH HH ... HH  |ascii...|".
    for (u32 row = 0; row < n; row += 16)
    {
        WriteU64Hex(row, 8);
        ConsoleWrite("  ");
        for (u32 i = 0; i < 16; ++i)
        {
            if (row + i < n)
            {
                WriteU64Hex(static_cast<u8>(scratch[row + i]), 2);
            }
            else
            {
                ConsoleWrite("  ");
            }
            ConsoleWriteChar(' ');
            if (i == 7)
            {
                ConsoleWriteChar(' ');
            }
        }
        ConsoleWrite(" |");
        for (u32 i = 0; i < 16 && row + i < n; ++i)
        {
            const char c = scratch[row + i];
            ConsoleWriteChar((c >= 0x20 && c <= 0x7E) ? c : '.');
        }
        ConsoleWriteln("|");
    }
}

void CmdStat(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("STAT: USAGE: STAT PATH");
        return;
    }
    const char* path = argv[1];
    // tmpfs first (flat namespace).
    if (const char* tmp_leaf = TmpLeaf(path); tmp_leaf != nullptr && *tmp_leaf != '\0')
    {
        const char* bytes = nullptr;
        u32 len = 0;
        if (!duetos::fs::TmpFsRead(tmp_leaf, &bytes, &len))
        {
            ConsoleWrite("STAT: NO SUCH FILE: ");
            ConsoleWriteln(path);
            return;
        }
        ConsoleWrite("  PATH:    ");
        ConsoleWriteln(path);
        ConsoleWrite("  TYPE:    FILE (tmpfs, writable)\n");
        ConsoleWrite("  SIZE:    ");
        WriteU64Dec(len);
        ConsoleWriteln(" bytes");
        return;
    }
    const auto* root = duetos::fs::RamfsTrustedRoot();
    const auto* node = duetos::fs::VfsLookup(root, path, 128);
    if (node == nullptr)
    {
        ConsoleWrite("STAT: NO SUCH PATH: ");
        ConsoleWriteln(path);
        return;
    }
    ConsoleWrite("  PATH:    ");
    ConsoleWriteln(path);
    ConsoleWrite("  NAME:    ");
    ConsoleWriteln(node->name[0] != '\0' ? node->name : "/");
    if (node->type == duetos::fs::RamfsNodeType::kDir)
    {
        ConsoleWrite("  TYPE:    DIRECTORY (ramfs, read-only)\n");
        u32 count = 0;
        if (node->children != nullptr)
        {
            while (node->children[count] != nullptr)
                ++count;
        }
        ConsoleWrite("  ENTRIES: ");
        WriteU64Dec(count);
        ConsoleWriteChar('\n');
    }
    else
    {
        ConsoleWrite("  TYPE:    FILE (ramfs, read-only)\n");
        ConsoleWrite("  SIZE:    ");
        WriteU64Dec(node->file_size);
        ConsoleWriteln(" bytes");
    }
}

void CmdCal()
{
    // Print the current month's calendar using RTC for today's
    // date. Simple: build the weekday of the 1st via Zeller,
    // emit a 7-column grid.
    duetos::arch::RtcTime t{};
    duetos::arch::RtcRead(&t);
    static const u8 kDaysPerMonth[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    const bool leap = ((t.year % 4 == 0) && (t.year % 100 != 0)) || (t.year % 400 == 0);
    u32 mlen = kDaysPerMonth[(t.month - 1) % 12];
    if (t.month == 2 && leap)
        mlen = 29;

    // Zeller's congruence gives day-of-week for year/month/day.
    // Classic Gregorian form: h = (q + 13(m+1)/5 + K + K/4 + J/4 + 5J) mod 7
    // where for Jan/Feb treat as month 13/14 of previous year.
    u32 y = t.year, m = t.month;
    if (m < 3)
    {
        m += 12;
        --y;
    }
    const u32 K = y % 100;
    const u32 J = y / 100;
    const u32 h = (1 + (13 * (m + 1)) / 5 + K + K / 4 + J / 4 + 5 * J) % 7;
    // h: 0=Sat, 1=Sun, 2=Mon, ..., 6=Fri — remap to Sun=0.
    const u32 dow_first = (h + 6) % 7;

    static const char* const kMonths[] = {"January", "February", "March",     "April",   "May",      "June",
                                          "July",    "August",   "September", "October", "November", "December"};
    ConsoleWrite("        ");
    ConsoleWrite(kMonths[(t.month - 1) % 12]);
    ConsoleWriteChar(' ');
    WriteU64Dec(t.year);
    ConsoleWriteChar('\n');
    ConsoleWriteln("Su Mo Tu We Th Fr Sa");
    for (u32 i = 0; i < dow_first; ++i)
    {
        ConsoleWrite("   ");
    }
    for (u32 day = 1; day <= mlen; ++day)
    {
        if (day == t.day)
        {
            ConsoleWriteChar('*');
        }
        else
        {
            ConsoleWriteChar(day < 10 ? ' ' : static_cast<char>('0' + day / 10));
        }
        if (day < 10)
        {
            ConsoleWriteChar(static_cast<char>('0' + day));
        }
        else
        {
            ConsoleWriteChar(day == t.day ? static_cast<char>('0' + day % 10) : static_cast<char>('0' + day % 10));
        }
        if (((day + dow_first) % 7) == 0)
        {
            ConsoleWriteChar('\n');
        }
        else
        {
            ConsoleWriteChar(' ');
        }
    }
    ConsoleWriteChar('\n');
}

void CmdBeep(u32 argc, char** argv)
{
    u32 freq = 1000; // default 1 kHz
    u32 ms = 200;    // default 200 ms
    if (argc >= 2)
    {
        u16 f = 0;
        if (!ParseU16Decimal(argv[1], &f))
        {
            ConsoleWriteln("BEEP: frequency must be decimal");
            return;
        }
        freq = f;
    }
    if (argc >= 3)
    {
        u16 d = 0;
        if (!ParseU16Decimal(argv[2], &d))
        {
            ConsoleWriteln("BEEP: duration must be decimal ms");
            return;
        }
        ms = d;
    }
    if (!duetos::drivers::audio::PcSpeakerBeep(freq, ms))
    {
        ConsoleWriteln("BEEP: frequency out of PIT divider range (20..1193181)");
        return;
    }
    ConsoleWrite("BEEP: ");
    WriteU64Dec(freq);
    ConsoleWrite(" Hz for ");
    WriteU64Dec(ms);
    ConsoleWriteln(" ms");
}

} // namespace duetos::core::shell::internal
