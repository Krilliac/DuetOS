/*
 * DuetOS — kernel shell: command dispatcher + tightly-coupled
 * companion commands.
 *
 * Carries everything the original shell.cpp kept clustered
 * around the central `Dispatch` if/else chain: the canonical
 * command-list table (kCommandSet[] — also referenced by the
 * tab-completer), the `!`-history + pipe + alias + $VAR
 * preprocessing, the per-command if/else dispatch, and the
 * companion handlers that were never able to leave shell.cpp
 * for a sibling TU because they (a) recurse through Dispatch
 * (CmdTime / CmdSource / CmdRepeat), (b) reference kCommandSet
 * (CmdWhich), (c) own a TU-private repaint helper (CmdTheme +
 * ApplyThemeAndRepaint), or (d) are long static text dumps
 * tightly coupled to the dispatch order (CmdHelp / CmdSysinfo /
 * CmdWindows). CmdRebootNow and CmdHaltNow ride along — they're
 * single-line wrappers around arch primitives that nothing else
 * calls.
 *
 * Public entry points (declared in shell_internal.h):
 *   - Dispatch(char* line)   — invoked by ShellSubmit + the
 *                              recursing-companion commands.
 *   - Prompt()                — invoked by ShellInit / ShellSubmit
 *                              and by the tab-completer's pretty-
 *                              print branch.
 *   - kCommandSet[]           — read by CmdWhich + by
 *                              CompleteCommandName.
 */

#include "shell/shell.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/rtc.h"
#include "arch/x86_64/serial.h"
#include "drivers/video/console.h"
#include "drivers/video/cursor.h"
#include "drivers/video/theme.h"
#include "drivers/video/widget.h"
#include "fs/tmpfs.h"
#include "fs/vfs.h"
#include "mm/frame_allocator.h"
#include "sched/sched.h"
#include "diag/cleanroom_trace.h"
#include "diag/crprobe.h"
#include "power/reboot.h"
#include "shell/shell_internal.h"

namespace duetos::core::shell::internal
{

namespace
{

using duetos::drivers::video::ConsoleWrite;
using duetos::drivers::video::ConsoleWriteChar;
using duetos::drivers::video::ConsoleWriteln;


// ============================================================
// Companion commands clustered with the dispatcher.
// ============================================================

void CmdHelp()
{
    ConsoleWriteln("AVAILABLE COMMANDS:");
    ConsoleWriteln("  HELP         LIST THIS HELP");
    ConsoleWriteln("  ABOUT        ABOUT DUETOS");
    ConsoleWriteln("  VERSION      DUETOS VERSION");
    ConsoleWriteln("  CLEAR        CLEAR THE CONSOLE");
    ConsoleWriteln("  UPTIME       SECONDS SINCE BOOT");
    ConsoleWriteln("  DATE         WALL TIME + DATE");
    ConsoleWriteln("  WINDOWS      LIST REGISTERED WINDOWS");
    ConsoleWriteln("  THEME [N|LIST|NEXT]  SHOW / SWITCH / CYCLE DESKTOP THEME");
    ConsoleWriteln("  MODE         SHOW CURRENT DISPLAY MODE");
    ConsoleWriteln("  LS [PATH]    LIST DIRECTORY CONTENTS");
    ConsoleWriteln("  CAT PATH     PRINT FILE CONTENTS");
    ConsoleWriteln("  TOUCH PATH   CREATE EMPTY /tmp FILE");
    ConsoleWriteln("  RM PATH      REMOVE /tmp FILE");
    ConsoleWriteln("  CP SRC DST   COPY FILE INTO /tmp");
    ConsoleWriteln("  MV SRC DST   MOVE /tmp FILE");
    ConsoleWriteln("  HEAD [-N] P  FIRST N LINES (DEFAULT 5)");
    ConsoleWriteln("  TAIL [-N] P  LAST N LINES (DEFAULT 5)");
    ConsoleWriteln("  WC PATH      LINES / WORDS / BYTES");
    ConsoleWriteln("  GREP PAT P   PRINT LINES OF P CONTAINING PAT");
    ConsoleWriteln("  FIND NAME    LIST PATHS WHOSE LEAF CONTAINS NAME");
    ConsoleWriteln("  SORT PATH    SORT LINES ALPHABETICALLY");
    ConsoleWriteln("  UNIQ PATH    SUPPRESS CONSECUTIVE DUPLICATE LINES");
    ConsoleWriteln("  WHICH CMD    SHOW WHETHER CMD IS A BUILTIN OR ALIAS");
    ConsoleWriteln("  TIME CMD..   MEASURE WALL TIME (10 MS RESOLUTION)");
    ConsoleWriteln("  SEQ N        PRINT 1..N (CAPPED AT 200)");
    ConsoleWriteln("  ECHO ..  > PATH   PRINT OR REDIRECT TO /tmp (>> TO APPEND)");
    ConsoleWriteln("  DMESG [TDIWE|C] DUMP KERNEL LOG RING (OR C=CLEAR)");
    ConsoleWriteln("  STATS        SCHEDULER STATISTICS");
    ConsoleWriteln("  MEM          PHYSICAL MEMORY USAGE");
    ConsoleWriteln("  HISTORY      LIST RECENT COMMANDS (!N RECALL, !! REPEAT)");
    ConsoleWriteln("  SET NAME VAL SET ENV VARIABLE  (SET PS1 '%' CUSTOMISES PROMPT)");
    ConsoleWriteln("  UNSET NAME   REMOVE ENV VARIABLE");
    ConsoleWriteln("  ENV          LIST ENV VARIABLES  (USE $NAME IN ARGS)");
    ConsoleWriteln("  ALIAS N CMD  CREATE ALIAS (BARE ALIAS LISTS ALL)");
    ConsoleWriteln("  UNALIAS N    REMOVE ALIAS");
    ConsoleWriteln("  SYSINFO      ONE-SHOT SYSTEM STATUS SUMMARY");
    ConsoleWriteln("  SOURCE PATH  RUN EACH LINE OF PATH AS A COMMAND");
    ConsoleWriteln("  MAN NAME     DETAILED HELP FOR ONE COMMAND");
    ConsoleWriteln("");
    ConsoleWriteln("SYSTEM INTROSPECTION:");
    ConsoleWriteln("  CPUID [LEAF] CPU VENDOR / FAMILY / FEATURES / BRAND");
    ConsoleWriteln("  CR           CONTROL REGISTERS CR0/CR2/CR3/CR4");
    ConsoleWriteln("  RFLAGS       CURRENT RFLAGS + DECODED BITS");
    ConsoleWriteln("  TSC          TIME-STAMP COUNTER (RDTSC)");
    ConsoleWriteln("  HPET         HPET COUNTER + PERIOD");
    ConsoleWriteln("  TICKS        TIMER + SCHEDULER TICK COUNTERS");
    ConsoleWriteln("  MSR HEX      READ ONE MODEL-SPECIFIC REGISTER");
    ConsoleWriteln("  LAPIC        LOCAL APIC ID / VERSION / TIMER");
    ConsoleWriteln("  SMP          CPUS ONLINE");
    ConsoleWriteln("  LSPCI        LIST PCI DEVICES");
    ConsoleWriteln("  HEAP         KERNEL HEAP USAGE");
    ConsoleWriteln("  PAGING       PAGE TABLE + MAPPING STATS");
    ConsoleWriteln("  FB           FRAMEBUFFER GEOMETRY");
    ConsoleWriteln("  KBDSTATS     PS/2 KEYBOARD IRQ COUNTERS");
    ConsoleWriteln("  MOUSESTATS   PS/2 MOUSE IRQ COUNTERS");
    ConsoleWriteln("  SMBIOS       BIOS / SYSTEM / CHASSIS INFO");
    ConsoleWriteln("  POWER        AC / BATTERY / THERMAL SNAPSHOT");
    ConsoleWriteln("  THERMAL      RE-READ MSR THERMAL SENSORS");
    ConsoleWriteln("  HWMON        UNIFIED SENSORS VIEW (SMBIOS + THERMAL + POWER + FANS)");
    ConsoleWriteln("  GPU          LIST DISCOVERED GPUS");
    ConsoleWriteln("  VBE [W H [B]]  QUERY / SET BOCHS-VBE DISPLAY MODE");
    ConsoleWriteln("  NIC          LIST NICS + MAC + LINK");
    ConsoleWriteln("  IFCONFIG     PER-IFACE: LINK / MAC / IP / GATEWAY / DNS / LEASE");
    ConsoleWriteln("  NETSCAN      LIST WIRELESS + WIRED NETWORKS WE COULD CONNECT TO");
    ConsoleWriteln("  DHCP [RENEW] SHOW LEASE; `DHCP RENEW` SENDS A FRESH DISCOVER");
    ConsoleWriteln("  ROUTE [-V]   DEFAULT GATEWAY + DNS  (-V = ALSO DUMP GATEWAY ARP)");
    ConsoleWriteln("  NET UP|STATUS|TEST  BRING UP / STATUS / END-TO-END SMOKE");
    ConsoleWriteln("  ARP          ARP CACHE + STATS");
    ConsoleWriteln("  PING IP      ICMP ECHO REQUEST + WAIT 1S FOR REPLY");
    ConsoleWriteln("  NSLOOKUP NAME DNS A-RECORD LOOKUP (RESOLVER 10.0.2.3)");
    ConsoleWriteln("  NTP [IP]     NTP QUERY (DEFAULT 216.239.35.0 — GOOGLE TIME1)");
    ConsoleWriteln("  HTTP IP [P [PATH]] TCP CONNECT + GET / AND PRINT 16 LINES");
    ConsoleWriteln("  IPV4         IPV4 RX COUNTERS");
    ConsoleWriteln("  HEALTH       RUN RUNTIME INVARIANT SCAN (HEAP/FRAMES/SCHED/CRX)");
    ConsoleWriteln("  UUID [N]     GENERATE N V4 UUIDS FROM THE ENTROPY POOL");
    ConsoleWriteln("  ATTACKSIM    RUN RED-TEAM ATTACK SUITE (IDT/GDT/LSTAR/CANARY/LBA0)");
    ConsoleWriteln("  MEMDUMP A [N]  HEX+ASCII DUMP OF KERNEL MEMORY -> SERIAL");
    ConsoleWriteln("  INSTR A [N]  INSTRUCTION-BYTE DUMP AT ADDRESS -> SERIAL");
    ConsoleWriteln("  INSPECT ...  RE / TRIAGE UMBRELLA (SYSCALLS|OPCODES|ARM) -> SERIAL");
    ConsoleWriteln("  BP ...       KERNEL BREAKPOINTS (SOFTWARE + HARDWARE)");
    ConsoleWriteln("  DUMPSTATE    SNAPSHOT EVERY KERNEL SUBSYSTEM -> SERIAL");
    ConsoleWriteln("");
    ConsoleWriteln("RUNTIME CONTROL:");
    ConsoleWriteln("  LOGLEVEL [L] GET / SET KLOG THRESHOLD (D/I/W/E)");
    ConsoleWriteln("  GETENV NAME  READ ONE ENV VARIABLE");
    ConsoleWriteln("  YIELD        FORCE A SCHEDULER YIELD");
    ConsoleWriteln("  REBOOT       RESET THE MACHINE (NO CONFIRM)");
    ConsoleWriteln("  HALT         STOP THE CPU (NO CONFIRM)");
    ConsoleWriteln("  SHUTDOWN     ACPI SOFT-OFF VIA _S5 (QEMU EXITS; HALT ON FALLBACK)");
    ConsoleWriteln("  BEEP [HZ [MS]]  PC SPEAKER TONE (DEFAULT 1000 HZ, 200 MS)");
    ConsoleWriteln("");
    ConsoleWriteln("ACCOUNTS / LOGIN:");
    ConsoleWriteln("  USERS / WHO  LIST ACCOUNTS (* = CURRENT SESSION)");
    ConsoleWriteln("  USERADD N P [ROLE]  CREATE ACCOUNT (ADMIN ONLY)");
    ConsoleWriteln("  USERDEL N    DELETE ACCOUNT (ADMIN ONLY)");
    ConsoleWriteln("  PASSWD OLD NEW           CHANGE OWN PASSWORD");
    ConsoleWriteln("  PASSWD USER NEW --force  ADMIN FORCE-RESET");
    ConsoleWriteln("  SU USER PW   SWITCH SESSION TO ANOTHER USER");
    ConsoleWriteln("  LOGIN U P    LOG IN NON-INTERACTIVELY");
    ConsoleWriteln("  LOGOUT       END SESSION + REOPEN LOGIN GATE");
    ConsoleWriteln("");
    ConsoleWriteln("COMPAT / IDENTITY:");
    ConsoleWriteln("  UNAME [-A]   KERNEL IDENTITY (-A VERBOSE)");
    ConsoleWriteln("  WHOAMI       EFFECTIVE USER");
    ConsoleWriteln("  HOSTNAME     HOST NAME (OR $HOSTNAME)");
    ConsoleWriteln("  PWD          CURRENT DIRECTORY (ALWAYS /)");
    ConsoleWriteln("  TRUE / FALSE NO-OP SUCCESS / FAILURE");
    ConsoleWriteln("  MOUNT        LIST FS MOUNTS");
    ConsoleWriteln("  LSMOD        LIST ACTIVE KERNEL SUBSYSTEMS");
    ConsoleWriteln("  LSBLK        LIST REGISTERED BLOCK DEVICES");
    ConsoleWriteln("  LSGPT        LIST PARTITIONS FROM GPT-PROBED DISKS");
    ConsoleWriteln("  METRICS      LOG RESOURCE SNAPSHOT (HEAP / FRAMES / TASKS)");
    ConsoleWriteln("  TRACE [ON|OFF] TOGGLE TRACE THRESHOLD + SHOW IN-FLIGHT SCOPES");
    ConsoleWriteln("  READ H LBA [C] HEXDUMP C SECTORS FROM BLOCK HANDLE H AT LBA");
    ConsoleWriteln("  GUARD [SUB]  SECURITY GUARD: STATUS OR ON/ENFORCE/OFF/TEST");
    ConsoleWriteln("  TOP          PER-TASK CPU% + SYSTEM IDLE FRACTION");
    ConsoleWriteln("  FATLS [VOL]  LIST ROOT DIR OF FAT32 VOLUME (default vol 0)");
    ConsoleWriteln("  FATCAT [VOL] NAME  READ FILE FROM FAT32 VOLUME TO CONSOLE");
    ConsoleWriteln("  FATWRITE PATH OFF BYTES  OVERWRITE EXISTING FILE BYTES IN-PLACE");
    ConsoleWriteln("  FATAPPEND NAME BYTES     APPEND BYTES TO EXISTING ROOT-DIR FILE (GROWS)");
    ConsoleWriteln("  FATNEW NAME [BYTES...]   CREATE NEW FAT32 FILE IN ROOT (8.3 NAME)");
    ConsoleWriteln("  FATRM NAME               DELETE A FAT32 FILE FROM ROOT");
    ConsoleWriteln("  FATTRUNC NAME NEW_SIZE   SHRINK OR ZERO-GROW AN EXISTING FILE");
    ConsoleWriteln("  FATMKDIR PATH            CREATE A NEW DIRECTORY");
    ConsoleWriteln("  FATRMDIR PATH            REMOVE AN EMPTY DIRECTORY");
    ConsoleWriteln("  LINUXEXEC PATH           LOAD ELF FROM FAT32 AS A LINUX-ABI PROCESS");
    ConsoleWriteln("  TRANSLATE                ABI TRANSLATION-UNIT HIT TABLE");
    ConsoleWriteln("  FREE         MEMORY USAGE (PHYS + HEAP)");
    ConsoleWriteln("  PS           LIST EVERY SCHEDULER TASK");
    ConsoleWriteln("  SPAWN KIND   LAUNCH A RING-3 TASK (hello/sandbox/jail/...)");
    ConsoleWriteln("  KILL PID     TERMINATE A TASK BY ID (USE `ps` TO FIND PIDS)");
    ConsoleWriteln("  EXEC PATH    DRY-RUN ELF64 LOAD PLAN (PRE-SYS_SPAWN)");
    ConsoleWriteln("  READELF PATH PARSE AN ELF64 HEADER + PROGRAM HEADERS");
    ConsoleWriteln("  HEXDUMP PATH 16-BYTE ROWS OF HEX + ASCII");
    ConsoleWriteln("  STAT PATH    FILE / DIR METADATA");
    ConsoleWriteln("  BASENAME P   STRIP LEADING DIRS");
    ConsoleWriteln("  DIRNAME P    STRIP TRAILING COMPONENT");
    ConsoleWriteln("  CAL          CURRENT MONTH CALENDAR");
    ConsoleWriteln("  SLEEP N      PAUSE FOR N SECONDS (^C ABORTS)");
    ConsoleWriteln("  RESET        CLEAR + REPRINT MOTD");
    ConsoleWriteln("  TAC PATH     PRINT LINES IN REVERSE ORDER");
    ConsoleWriteln("  NL PATH      NUMBER LINES");
    ConsoleWriteln("  REV PATH     REVERSE EACH LINE'S CHARACTERS");
    ConsoleWriteln("  EXPR A OP B  INTEGER ARITHMETIC (+ - * / %)");
    ConsoleWriteln("  COLOR FG[BG] SET SHELL CONSOLE PALETTE (HEX)");
    ConsoleWriteln("  RAND [N]     N PSEUDO-RANDOM 64-BIT HEX VALUES");
    ConsoleWriteln("  FLUSHTLB     RELOAD CR3 (FLUSH NON-GLOBAL TLB)");
    ConsoleWriteln("  CHECKSUM P   FNV1A-32 HASH OF FILE CONTENT");
    ConsoleWriteln("  REPEAT N CMD RUN CMD N TIMES (^C ABORTS)");
    ConsoleWriteln("");
    ConsoleWriteln("KEYS:  UP/DOWN = HISTORY   TAB = COMPLETE");
    ConsoleWriteln("       CTRL+ALT+T = TOGGLE MODE");
    ConsoleWriteln("       CTRL+ALT+F1 = SHELL   CTRL+ALT+F2 = KLOG");
    ConsoleWriteln("       ALT+TAB = CYCLE WINDOW  ALT+F4 = CLOSE WINDOW");
}

// CmdAbout / CmdVersion / CmdClear / CmdUptime / CmdDate moved
// to shell_core.cpp.

void CmdWindows()
{
    using namespace duetos::drivers::video;
    ConsoleWriteln("REGISTERED WINDOWS:");
    for (u32 h = 0; h < WindowRegistryCount(); ++h)
    {
        ConsoleWrite("  [");
        WriteU64Dec(h);
        ConsoleWrite("] ");
        ConsoleWrite(WindowIsAlive(h) ? "ALIVE  " : "DEAD   ");
        const char* t = WindowTitle(h);
        ConsoleWriteln((t != nullptr) ? t : "(UNTITLED)");
    }
}

// path in main.cpp: take the compositor lock, publish the new
// palette to every chrome surface, and force one DesktopCompose
// so the switch is visible in the same call. Separated so both
// the "name" and "next" branches share identical repaint logic.
void ApplyThemeAndRepaint()
{
    using namespace duetos::drivers::video;
    CompositorLock();
    ThemeApplyToAll();
    const bool is_tty = (GetDisplayMode() == DisplayMode::Tty);
    if (is_tty)
    {
        DesktopCompose(0x00000000, nullptr);
    }
    else
    {
        CursorHide();
        DesktopCompose(ThemeCurrent().desktop_bg, "WELCOME TO DUETOS   BOOT OK");
        CursorShow();
    }
    CompositorUnlock();
}


// `theme`                 — print the current theme.
// `theme list`            — list every registered theme, mark the current.
// `theme next` / `cycle`  — advance to the next theme and repaint.
// `theme <name>`          — switch by name (case-insensitive); no-op +
//                           error if the name doesn't match a registered
//                           theme.
void CmdTheme(u32 argc, char** argv)
{
    using namespace duetos::drivers::video;

    if (argc < 2)
    {
        ConsoleWrite("CURRENT THEME: ");
        ConsoleWriteln(ThemeIdName(ThemeCurrentId()));
        return;
    }

    const char* arg = argv[1];
    if (StrEq(arg, "list") || StrEq(arg, "-l"))
    {
        const ThemeId current = ThemeCurrentId();
        ConsoleWriteln("AVAILABLE THEMES:");
        for (u32 i = 0; i < static_cast<u32>(ThemeId::kCount); ++i)
        {
            const auto id = static_cast<ThemeId>(i);
            ConsoleWrite((id == current) ? "  * " : "    ");
            ConsoleWriteln(ThemeIdName(id));
        }
        return;
    }
    if (StrEq(arg, "next") || StrEq(arg, "cycle"))
    {
        ThemeCycle();
        ApplyThemeAndRepaint();
        ConsoleWrite("THEME -> ");
        ConsoleWriteln(ThemeIdName(ThemeCurrentId()));
        return;
    }

    ThemeId id;
    if (!ThemeIdFromName(arg, &id))
    {
        ConsoleWrite("THEME: UNKNOWN NAME '");
        ConsoleWrite(arg);
        ConsoleWriteln("' (try: theme list)");
        return;
    }
    if (id == ThemeCurrentId())
    {
        ConsoleWrite("THEME ALREADY ");
        ConsoleWriteln(ThemeIdName(id));
        return;
    }
    ThemeSet(id);
    ApplyThemeAndRepaint();
    ConsoleWrite("THEME -> ");
    ConsoleWriteln(ThemeIdName(ThemeCurrentId()));
}

void CmdWhich(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("WHICH: MISSING NAME");
        return;
    }
    for (u32 i = 0; i < kCommandCount; ++i)
    {
        if (StrEq(kCommandSet[i], argv[1]))
        {
            ConsoleWrite(argv[1]);
            ConsoleWriteln(": SHELL BUILTIN");
            return;
        }
    }
    if (AliasFind(argv[1]) != nullptr)
    {
        ConsoleWrite(argv[1]);
        ConsoleWriteln(": SHELL ALIAS");
        return;
    }
    ConsoleWrite(argv[1]);
    ConsoleWriteln(": NOT FOUND");
}

void CmdTime(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("TIME: USAGE: TIME CMD ARGS...");
        return;
    }
    // Reconstruct the inner command line from argv[1..]. The
    // sub-dispatch goes through the full pipeline (alias /
    // env / redirect), so `time alias` and `time ls /etc`
    // both work.
    char buf[kInputMax];
    u32 o = 0;
    for (u32 i = 1; i < argc; ++i)
    {
        if (i > 1 && o + 1 < sizeof(buf))
        {
            buf[o++] = ' ';
        }
        for (u32 j = 0; argv[i][j] != '\0' && o + 1 < sizeof(buf); ++j)
        {
            buf[o++] = argv[i][j];
        }
    }
    buf[o] = '\0';
    const u64 t0 = duetos::sched::SchedNowTicks();
    Dispatch(buf);
    const u64 t1 = duetos::sched::SchedNowTicks();
    // 100 Hz scheduler tick → each tick is 10 ms. Round-trip
    // resolution is therefore one tick; sub-tick durations
    // show as 0 ms, which is honest given the time source.
    const u64 ms = (t1 - t0) * 10;
    ConsoleWrite("real    ");
    WriteU64Dec(ms);
    ConsoleWriteln(" ms");
}

// CmdSource recurses via Dispatch (declared cross-TU above).
void CmdSource(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("SOURCE: MISSING PATH");
        return;
    }
    char scratch[duetos::fs::kTmpFsContentMax];
    const u32 n = ReadFileToBuf(argv[1], scratch, sizeof(scratch));
    if (n == static_cast<u32>(-1))
    {
        ConsoleWrite("SOURCE: NO SUCH FILE: ");
        ConsoleWriteln(argv[1]);
        return;
    }
    // Walk the content line by line. Each line dispatches
    // through the full shell pipeline (alias expansion, env
    // substitution, redirects). Lines starting with '#' are
    // comments. Blank lines are silently skipped.
    char line_buf[kInputMax];
    u32 i = 0;
    while (i < n)
    {
        u32 j = 0;
        while (i < n && scratch[i] != '\n' && j + 1 < sizeof(line_buf))
        {
            line_buf[j++] = scratch[i++];
        }
        // Skip to end-of-line if the line was too long.
        while (i < n && scratch[i] != '\n')
        {
            ++i;
        }
        if (i < n)
        {
            ++i; // consume '\n'
        }
        line_buf[j] = '\0';
        // Trim trailing whitespace for cleaner dispatch.
        while (j > 0 && (line_buf[j - 1] == ' ' || line_buf[j - 1] == '\t' || line_buf[j - 1] == '\r'))
        {
            line_buf[--j] = '\0';
        }
        if (j == 0 || line_buf[0] == '#')
        {
            continue;
        }
        Dispatch(line_buf);
    }
}

void CmdSysinfo()
{
    // One-shot dump of the introspection surface — saves a user
    // from typing version / uptime / date / mem / stats / windows
    // in sequence. Read-only; all data comes from the same
    // accessors the individual commands use.
    ConsoleWriteln("DUETOS v0  (WINDOWED DESKTOP SHELL)");
    ConsoleWrite("UPTIME:  ");
    const u64 secs = duetos::sched::SchedNowTicks() / 100;
    WriteU64Dec(secs);
    ConsoleWriteln(" SECONDS");
    duetos::arch::RtcTime t{};
    duetos::arch::RtcRead(&t);
    ConsoleWrite("WALL:    ");
    WriteU8TwoDigits(t.hour);
    ConsoleWriteChar(':');
    WriteU8TwoDigits(t.minute);
    ConsoleWriteChar(':');
    WriteU8TwoDigits(t.second);
    ConsoleWriteChar(' ');
    WriteU64Dec(t.year);
    ConsoleWriteChar('-');
    WriteU8TwoDigits(t.month);
    ConsoleWriteChar('-');
    WriteU8TwoDigits(t.day);
    ConsoleWriteChar('\n');
    const auto s = duetos::sched::SchedStatsRead();
    ConsoleWrite("TASKS:   ");
    WriteU64Dec(s.tasks_live);
    ConsoleWrite(" LIVE, ");
    WriteU64Dec(s.tasks_sleeping);
    ConsoleWrite(" SLEEPING, ");
    WriteU64Dec(s.tasks_blocked);
    ConsoleWriteln(" BLOCKED");
    const u64 total = duetos::mm::TotalFrames();
    const u64 free_frames = duetos::mm::FreeFramesCount();
    ConsoleWrite("MEMORY:  ");
    WriteU64Dec((total - free_frames) * 4);
    ConsoleWrite(" KIB USED / ");
    WriteU64Dec(total * 4);
    ConsoleWriteln(" KIB TOTAL");
    u32 alive = 0;
    for (u32 h = 0; h < duetos::drivers::video::WindowRegistryCount(); ++h)
    {
        if (duetos::drivers::video::WindowIsAlive(h))
            ++alive;
    }
    ConsoleWrite("WINDOWS: ");
    WriteU64Dec(alive);
    ConsoleWriteln(" ALIVE");
    ConsoleWrite("MODE:    ");
    ConsoleWriteln(duetos::drivers::video::GetDisplayMode() == duetos::drivers::video::DisplayMode::Tty ? "TTY"
                                                                                                        : "DESKTOP");
}

void CmdRepeat(u32 argc, char** argv)
{
    if (argc < 3)
    {
        ConsoleWriteln("REPEAT: USAGE: REPEAT N CMD...");
        return;
    }
    u32 n = 0;
    for (u32 i = 0; argv[1][i] != '\0'; ++i)
    {
        if (argv[1][i] < '0' || argv[1][i] > '9')
        {
            ConsoleWriteln("REPEAT: BAD COUNT");
            return;
        }
        n = n * 10 + static_cast<u32>(argv[1][i] - '0');
    }
    // Cap at 100 to keep the output bounded until we have
    // proper stdout throttling.
    if (n > 100)
    {
        n = 100;
    }
    // Join argv[2..] into one line for Dispatch. Tokenisation
    // of args is preserved verbatim on the join.
    char line[kInputMax];
    u32 o = 0;
    for (u32 i = 2; i < argc; ++i)
    {
        if (i > 2 && o + 1 < sizeof(line))
            line[o++] = ' ';
        for (u32 j = 0; argv[i][j] != '\0' && o + 1 < sizeof(line); ++j)
            line[o++] = argv[i][j];
    }
    line[o] = '\0';
    for (u32 i = 0; i < n; ++i)
    {
        if (ShellInterruptRequested())
        {
            ConsoleWriteln("^C");
            return;
        }
        // Dispatch mutates `line`, so we need a fresh copy
        // each iteration.
        char copy[kInputMax];
        for (u32 j = 0; j < sizeof(copy); ++j)
        {
            copy[j] = line[j];
            if (line[j] == '\0')
                break;
        }
        Dispatch(copy);
    }
}

[[noreturn]] void CmdRebootNow()
{
    ConsoleWriteln("REBOOTING...");
    // Serial also carries the notice so a headless run sees
    // the final line before the reset reg fires.
    duetos::arch::SerialWrite("[shell] user invoked reboot\n");
    duetos::core::KernelReboot();
}

[[noreturn]] void CmdHaltNow()
{
    ConsoleWriteln("HALTING. SAFE TO POWER OFF.");
    duetos::arch::SerialWrite("[shell] user invoked halt\n");
    // Infinite "cli; hlt" via arch::Halt. The scheduler will
    // never run again on this CPU. For multi-CPU this would
    // need an NMI broadcast; v0 is single-CPU so this is fine.
    duetos::arch::Halt();
}

constexpr u32 kMaxArgs = 8;

// Tokenize `buf` in place. Spaces and tabs are separators; runs
// of whitespace collapse to a single break. Mutates `buf` —
// separator bytes get NUL'd so each argv entry is a proper
// NUL-terminated string sitting inside the original buffer.
// Stops at kMaxArgs; trailing tokens past the cap are ignored.
u32 Tokenize(char* buf, char** argv)
{
    u32 count = 0;
    char* p = buf;
    while (*p != '\0' && count < kMaxArgs)
    {
        while (*p == ' ' || *p == '\t')
        {
            ++p;
        }
        if (*p == '\0')
        {
            break;
        }
        argv[count++] = p;
        while (*p != '\0' && *p != ' ' && *p != '\t')
        {
            ++p;
        }
        if (*p != '\0')
        {
            *p = '\0';
            ++p;
        }
    }
    return count;
}
} // namespace


// ============================================================
// Cross-TU surface.
// ============================================================

// Canonical built-in command list. Single source of truth used
// by CmdWhich and the tab-completer's CompleteCommandName.
// New commands added here + dispatched in Dispatch — keeping
// the two in sync is the price of not having reflection.
const char* const kCommandSet[] = {
    "help",      "about",    "version", "clear",    "uptime",   "date",      "windows",    "mode",       "ls",
    "cat",       "touch",    "rm",      "echo",     "cp",       "mv",        "wc",         "head",       "tail",
    "dmesg",     "stats",    "mem",     "history",  "set",      "unset",     "env",        "alias",      "unalias",
    "sysinfo",   "source",   "man",     "grep",     "find",     "time",      "which",      "seq",        "sort",
    "uniq",      "cpuid",    "cr",      "rflags",   "tsc",      "hpet",      "ticks",      "msr",        "lapic",
    "smp",       "lspci",    "heap",    "paging",   "fb",       "kbdstats",  "mousestats", "loglevel",   "logcolor",
    "kdbg",      "getenv",   "yield",   "reboot",   "halt",     "uname",     "whoami",     "hostname",   "pwd",
    "true",      "false",    "mount",   "lsmod",    "lsblk",    "lsgpt",     "free",       "ps",         "spawn",
    "readelf",   "hexdump",  "stat",    "basename", "dirname",  "cal",       "sleep",      "reset",      "tac",
    "nl",        "rev",      "expr",    "color",    "rand",     "flushtlb",  "checksum",   "repeat",     "kill",
    "exec",      "metrics",  "trace",   "read",     "guard",    "top",       "fatcat",     "fatls",      "fatwrite",
    "fatappend", "fatnew",   "fatrm",   "fattrunc", "fatmkdir", "fatrmdir",  "linuxexec",  "translate",  "smbios",
    "power",     "battery",  "thermal", "temp",     "gpu",      "lsgpu",     "gfx",        "nic",        "lsnic",
    "ip",        "arp",      "ipv4",    "uuid",     "uuidgen",  "health",    "checkup",    "attacksim",  "redteam",
    "memdump",   "ifconfig", "netinfo", "dhcp",     "route",    "netscan",   "wifi",       "fwpolicy",   "fwtrace",
    "crtrace",   "crprobe",  "net",     "usbnet",   "instr",    "dumpstate", "bp",         "breakpoint", "login",
    "logout",    "passwd",   "useradd", "userdel",  "users",    "who",       "su",         "hwmon",      "vbe",
    "ping",      "nslookup", "ntp",     "http",     "shutdown", "poweroff",  "beep",       "inspect",    "theme",
    "addr2sym",
};
const u32 kCommandCount = sizeof(kCommandSet) / sizeof(kCommandSet[0]);

void Prompt()
{
    // If the user sets $PS1, honour it as the prompt string.
    // Defaults to "$ " — the simplest POSIX-flavour prompt.
    const EnvSlot* s = EnvFind("PS1");
    if (s != nullptr && s->value[0] != '\0')
    {
        ConsoleWrite(s->value);
        return;
    }
    ConsoleWrite("$ ");
}


// ============================================================
// Dispatcher entry point.
// ============================================================

void Dispatch(char* line)
{
    // !N / !! history expansion — resolve before tokenizing so
    // the recalled text goes through the full command path as
    // if the user had typed it. Echo the recalled text first so
    // the user can see what they ran.
    if (line[0] == '!')
    {
        const char* recalled = HistoryExpand(line);
        if (recalled == nullptr)
        {
            ConsoleWriteln("SHELL: NO SUCH HISTORY ENTRY");
            return;
        }
        ConsoleWriteln(recalled);
        // Copy into g_input (it's the buffer `line` points into)
        // and recurse once into Dispatch with the new content.
        // Bounded recursion depth = 1 because the recalled entry
        // never starts with '!'.
        u32 i = 0;
        for (; recalled[i] != '\0' && i + 1 < kInputMax; ++i)
        {
            line[i] = recalled[i];
        }
        line[i] = '\0';
        Dispatch(line);
        return;
    }

    // Pipe dispatch — `A | B` (and multi-stage `A | B | C`)
    // routes each segment's output into the next segment as a
    // trailing path argument, via a tmpfs temp file. Detection
    // is the simplest possible: find an UNQUOTED '|' outside
    // any '>' or '>>' redirect. We don't have quotes yet, so
    // every '|' is unquoted; the redirect edge-case is the
    // only thing to skip. A whole-pipeline recursion keeps
    // the implementation self-contained.
    {
        u32 pipe_at = 0;
        bool have_pipe = false;
        for (u32 i = 0; line[i] != '\0'; ++i)
        {
            if (line[i] == '|')
            {
                pipe_at = i;
                have_pipe = true;
                break;
            }
        }
        if (have_pipe)
        {
            // Split into left / right halves at the first pipe.
            // Recursion on the right side handles multi-stage.
            char left[kInputMax];
            char right[kInputMax];
            u32 li = 0;
            for (u32 i = 0; i < pipe_at && li + 1 < sizeof(left); ++i)
            {
                left[li++] = line[i];
            }
            // Trim trailing whitespace from left so the redirect
            // we append below is tokenized correctly.
            while (li > 0 && (left[li - 1] == ' ' || left[li - 1] == '\t'))
                --li;
            left[li] = '\0';

            u32 start = pipe_at + 1;
            while (line[start] == ' ' || line[start] == '\t')
                ++start;
            u32 ri = 0;
            for (u32 i = start; line[i] != '\0' && ri + 1 < sizeof(right); ++i)
            {
                right[ri++] = line[i];
            }
            right[ri] = '\0';

            // Run the LEFT half with output captured.
            static constexpr u32 kPipeBufMax = duetos::fs::kTmpFsContentMax;
            static char g_pipe_buf[kPipeBufMax];
            u32 captured = 0;
            duetos::drivers::video::ConsoleBeginCapture(g_pipe_buf, kPipeBufMax, &captured);
            Dispatch(left);
            duetos::drivers::video::ConsoleEndCapture();

            // Stash captured output in a reserved tmpfs slot.
            // Use a well-known name so nested pipes share the
            // space — each level overwrites as it unwinds.
            constexpr const char* kPipeName = "__pipe__";
            duetos::fs::TmpFsWrite(kPipeName, g_pipe_buf, captured);

            // Append "/tmp/__pipe__" to the right command so it
            // receives the prior stage's output as its final arg.
            // Works for any command that takes a path last:
            // cat, grep, head, tail, wc, sort, uniq, find (for
            // find the needle is arg1 and the pipe-file becomes
            // a spurious extra arg it ignores — fine).
            char combined[kInputMax];
            u32 ci = 0;
            for (u32 i = 0; right[i] != '\0' && ci + 1 < sizeof(combined); ++i)
            {
                combined[ci++] = right[i];
            }
            const char suffix[] = " /tmp/__pipe__";
            for (u32 i = 0; suffix[i] != '\0' && ci + 1 < sizeof(combined); ++i)
            {
                combined[ci++] = suffix[i];
            }
            combined[ci] = '\0';

            // Recurse — the right half may itself contain
            // another pipe. Final stage writes to the console.
            Dispatch(combined);

            // Drop the temp file so `ls /tmp` stays clean.
            duetos::fs::TmpFsUnlink(kPipeName);
            return;
        }
    }

    // Alias expansion — runs before tokenize. If the first
    // whitespace-delimited token matches a registered alias,
    // substitute the alias's expansion and keep the remainder
    // of the line. One level of expansion; an alias that
    // references another alias is NOT recursively expanded,
    // matching bash's default (`shopt -u expand_aliases`
    // territory — recursive is a footgun).
    {
        u32 wend = 0;
        while (line[wend] != '\0' && line[wend] != ' ' && line[wend] != '\t')
            ++wend;
        const char saved = line[wend];
        line[wend] = '\0';
        AliasSlot* a = AliasFind(line);
        line[wend] = saved;
        if (a != nullptr)
        {
            char scratch[kInputMax + kAliasExpansionMax];
            u32 o = 0;
            for (u32 i = 0; a->expansion[i] != '\0' && o + 1 < sizeof(scratch); ++i)
                scratch[o++] = a->expansion[i];
            for (u32 i = wend; line[i] != '\0' && o + 1 < sizeof(scratch); ++i)
                scratch[o++] = line[i];
            scratch[o] = '\0';
            u32 j = 0;
            for (; scratch[j] != '\0' && j + 1 < kInputMax; ++j)
                line[j] = scratch[j];
            line[j] = '\0';
        }
    }

    char* argv[kMaxArgs] = {};
    const u32 argc = Tokenize(line, argv);
    if (argc == 0)
    {
        return; // empty submission — no diagnostic, just re-prompt
    }

    // $VAR substitution — only for whole-token matches. `$PATH`
    // becomes its env value; `/etc/$PATH` stays verbatim. Empty
    // value (undefined var) substitutes as "". Keeping the
    // whole-token rule makes substitution trivial + safe; a real
    // parser lands when someone needs quoted / concatenated
    // expansions.
    static char env_empty[1] = {'\0'};
    for (u32 i = 1; i < argc; ++i)
    {
        if (argv[i][0] != '$' || argv[i][1] == '\0')
            continue;
        EnvSlot* s = EnvFind(argv[i] + 1);
        argv[i] = (s != nullptr) ? s->value : env_empty;
    }

    const char* cmd = argv[0];
    duetos::core::CleanroomTraceRecord("shell", "command", duetos::core::CleanroomTraceHashToken(cmd), argc,
                                       duetos::core::CleanroomTraceHashToken((argc > 1) ? argv[1] : nullptr));
    if (StrEq(cmd, "help"))
    {
        CmdHelp();
        return;
    }
    if (StrEq(cmd, "about"))
    {
        CmdAbout();
        return;
    }
    if (StrEq(cmd, "version"))
    {
        CmdVersion();
        return;
    }
    if (StrEq(cmd, "clear"))
    {
        CmdClear();
        return;
    }
    if (StrEq(cmd, "uptime"))
    {
        CmdUptime();
        return;
    }
    if (StrEq(cmd, "date"))
    {
        CmdDate();
        return;
    }
    if (StrEq(cmd, "windows"))
    {
        CmdWindows();
        return;
    }
    if (StrEq(cmd, "theme"))
    {
        CmdTheme(argc, argv);
        return;
    }
    if (StrEq(cmd, "mode"))
    {
        CmdMode();
        return;
    }
    if (StrEq(cmd, "echo"))
    {
        CmdEcho(argc, argv);
        return;
    }
    if (StrEq(cmd, "ls"))
    {
        CmdLs(argc, argv);
        return;
    }
    if (StrEq(cmd, "cat"))
    {
        CmdCat(argc, argv);
        return;
    }
    if (StrEq(cmd, "touch"))
    {
        CmdTouch(argc, argv);
        return;
    }
    if (StrEq(cmd, "rm"))
    {
        CmdRm(argc, argv);
        return;
    }
    if (StrEq(cmd, "dmesg"))
    {
        CmdDmesg(argc, argv);
        return;
    }
    if (StrEq(cmd, "stats"))
    {
        CmdStats();
        return;
    }
    if (StrEq(cmd, "mem"))
    {
        CmdMem();
        return;
    }
    if (StrEq(cmd, "history"))
    {
        CmdHistory();
        return;
    }
    if (StrEq(cmd, "cp"))
    {
        CmdCp(argc, argv);
        return;
    }
    if (StrEq(cmd, "mv"))
    {
        CmdMv(argc, argv);
        return;
    }
    if (StrEq(cmd, "wc"))
    {
        CmdWc(argc, argv);
        return;
    }
    if (StrEq(cmd, "head"))
    {
        CmdHead(argc, argv);
        return;
    }
    if (StrEq(cmd, "tail"))
    {
        CmdTail(argc, argv);
        return;
    }
    if (StrEq(cmd, "set"))
    {
        CmdSet(argc, argv);
        return;
    }
    if (StrEq(cmd, "unset"))
    {
        CmdUnset(argc, argv);
        return;
    }
    if (StrEq(cmd, "env"))
    {
        CmdEnv();
        return;
    }
    if (StrEq(cmd, "alias"))
    {
        CmdAlias(argc, argv);
        return;
    }
    if (StrEq(cmd, "unalias"))
    {
        CmdUnalias(argc, argv);
        return;
    }
    if (StrEq(cmd, "sysinfo"))
    {
        CmdSysinfo();
        return;
    }
    if (StrEq(cmd, "source") || StrEq(cmd, "."))
    {
        CmdSource(argc, argv);
        return;
    }
    if (StrEq(cmd, "man"))
    {
        CmdMan(argc, argv);
        return;
    }
    if (StrEq(cmd, "grep"))
    {
        CmdGrep(argc, argv);
        return;
    }
    if (StrEq(cmd, "find"))
    {
        CmdFind(argc, argv);
        return;
    }
    if (StrEq(cmd, "sort"))
    {
        CmdSort(argc, argv);
        return;
    }
    if (StrEq(cmd, "uniq"))
    {
        CmdUniq(argc, argv);
        return;
    }
    if (StrEq(cmd, "time"))
    {
        CmdTime(argc, argv);
        return;
    }
    if (StrEq(cmd, "which"))
    {
        CmdWhich(argc, argv);
        return;
    }
    if (StrEq(cmd, "seq"))
    {
        CmdSeq(argc, argv);
        return;
    }
    if (StrEq(cmd, "cpuid"))
    {
        CmdCpuid(argc, argv);
        return;
    }
    if (StrEq(cmd, "cr"))
    {
        CmdCr();
        return;
    }
    if (StrEq(cmd, "rflags"))
    {
        CmdRflags();
        return;
    }
    if (StrEq(cmd, "tsc"))
    {
        CmdTsc();
        return;
    }
    if (StrEq(cmd, "hpet"))
    {
        CmdHpet();
        return;
    }
    if (StrEq(cmd, "ticks"))
    {
        CmdTicks();
        return;
    }
    if (StrEq(cmd, "msr"))
    {
        if (!RequireAdmin("MSR"))
            return;
        CmdMsr(argc, argv);
        return;
    }
    if (StrEq(cmd, "lapic"))
    {
        CmdLapic();
        return;
    }
    if (StrEq(cmd, "smp"))
    {
        CmdSmp();
        return;
    }
    if (StrEq(cmd, "lspci"))
    {
        CmdLspci();
        return;
    }
    if (StrEq(cmd, "heap"))
    {
        CmdHeap();
        return;
    }
    if (StrEq(cmd, "paging"))
    {
        CmdPaging();
        return;
    }
    if (StrEq(cmd, "fb"))
    {
        CmdFb();
        return;
    }
    if (StrEq(cmd, "kbdstats"))
    {
        CmdKbdStats();
        return;
    }
    if (StrEq(cmd, "mousestats"))
    {
        CmdMouseStats();
        return;
    }
    if (StrEq(cmd, "smbios"))
    {
        CmdSmbios();
        return;
    }
    if (StrEq(cmd, "power") || StrEq(cmd, "battery"))
    {
        CmdPower();
        return;
    }
    if (StrEq(cmd, "hwmon"))
    {
        CmdHwmon();
        return;
    }
    if (StrEq(cmd, "thermal") || StrEq(cmd, "temp"))
    {
        CmdThermal();
        return;
    }
    if (StrEq(cmd, "gpu") || StrEq(cmd, "lsgpu"))
    {
        CmdGpu();
        return;
    }
    if (StrEq(cmd, "gfx"))
    {
        CmdGfx();
        return;
    }
    if (StrEq(cmd, "vbe"))
    {
        CmdVbe(argc, argv);
        return;
    }
    if (StrEq(cmd, "ping"))
    {
        CmdPing(argc, argv);
        return;
    }
    if (StrEq(cmd, "nslookup"))
    {
        CmdNslookup(argc, argv);
        return;
    }
    if (StrEq(cmd, "ntp"))
    {
        CmdNtp(argc, argv);
        return;
    }
    if (StrEq(cmd, "http"))
    {
        CmdHttp(argc, argv);
        return;
    }
    if (StrEq(cmd, "nic") || StrEq(cmd, "lsnic") || StrEq(cmd, "ip"))
    {
        CmdNic();
        return;
    }
    if (StrEq(cmd, "arp"))
    {
        CmdArp();
        return;
    }
    if (StrEq(cmd, "ipv4"))
    {
        CmdIpv4();
        return;
    }
    if (StrEq(cmd, "ifconfig") || StrEq(cmd, "netinfo"))
    {
        CmdIfconfig();
        return;
    }
    if (StrEq(cmd, "dhcp"))
    {
        CmdDhcp(argc, argv);
        return;
    }
    if (StrEq(cmd, "route"))
    {
        CmdRoute(argc, argv);
        return;
    }
    if (StrEq(cmd, "netscan"))
    {
        CmdNetscan();
        return;
    }
    if (StrEq(cmd, "wifi"))
    {
        CmdWifi(argc, argv);
        return;
    }
    if (StrEq(cmd, "fwpolicy"))
    {
        CmdFwPolicy(argc, argv);
        return;
    }
    if (StrEq(cmd, "fwtrace"))
    {
        CmdFwTrace(argc, argv);
        return;
    }
    if (StrEq(cmd, "crtrace"))
    {
        CmdCrTrace(argc, argv);
        return;
    }
    if (StrEq(cmd, "crprobe"))
    {
        ConsoleWriteln("CRPROBE: firing wifi + fw-loader trace dispatch points");
        duetos::core::CrProbeRun();
        ConsoleWriteln("CRPROBE: done — try `crtrace show 32`");
        return;
    }
    if (StrEq(cmd, "net"))
    {
        CmdNet(argc, argv);
        return;
    }
    if (StrEq(cmd, "usbnet"))
    {
        CmdUsbNet(argc, argv);
        return;
    }
    if (StrEq(cmd, "health") || StrEq(cmd, "checkup"))
    {
        CmdHealth(argc, argv);
        return;
    }
    if (StrEq(cmd, "uuid") || StrEq(cmd, "uuidgen"))
    {
        CmdUuid(argc, argv);
        return;
    }
    if (StrEq(cmd, "attacksim") || StrEq(cmd, "redteam"))
    {
        if (!RequireAdmin("ATTACKSIM"))
            return;
        CmdAttackSim();
        return;
    }
    if (StrEq(cmd, "memdump"))
    {
        if (!RequireAdmin("MEMDUMP"))
            return;
        CmdMemDump(argc, argv);
        return;
    }
    if (StrEq(cmd, "bp") || StrEq(cmd, "breakpoint"))
    {
        if (!RequireAdmin("BP"))
            return;
        CmdBp(argc, argv);
        return;
    }
    if (StrEq(cmd, "probe"))
    {
        if (!RequireAdmin("PROBE"))
            return;
        CmdProbe(argc, argv);
        return;
    }
    if (StrEq(cmd, "instr"))
    {
        CmdInstr(argc, argv);
        return;
    }
    if (StrEq(cmd, "addr2sym"))
    {
        CmdAddr2Sym(argc, argv);
        return;
    }
    if (StrEq(cmd, "inspect"))
    {
        CmdInspect(argc, argv);
        return;
    }
    if (StrEq(cmd, "dumpstate"))
    {
        CmdDumpState();
        return;
    }
    if (StrEq(cmd, "logcolor"))
    {
        CmdLogcolor(argc, argv);
        return;
    }
    if (StrEq(cmd, "loglevel"))
    {
        // Non-admins would be able to silence forensic logs
        // (raise threshold to Error) while mounting further
        // attacks. Admin-only keeps klog evidence intact.
        if (!RequireAdmin("LOGLEVEL"))
            return;
        CmdLoglevel(argc, argv);
        return;
    }
    if (StrEq(cmd, "kdbg"))
    {
        // Same threat model as `loglevel` — KDBG channels can
        // surface per-syscall arg dumps and dir-walker traces,
        // useful for forensics. Gating to admin keeps malicious
        // ring-3 from quietly disabling diagnostic streams.
        if (!RequireAdmin("KDBG"))
            return;
        CmdKdbg(argc, argv);
        return;
    }
    if (StrEq(cmd, "getenv"))
    {
        CmdGetenv(argc, argv);
        return;
    }
    if (StrEq(cmd, "yield"))
    {
        CmdYield();
        return;
    }
    if (StrEq(cmd, "uname"))
    {
        CmdUname(argc, argv);
        return;
    }
    if (StrEq(cmd, "whoami"))
    {
        CmdWhoami();
        return;
    }
    if (StrEq(cmd, "users") || StrEq(cmd, "who"))
    {
        CmdUsers();
        return;
    }
    if (StrEq(cmd, "useradd"))
    {
        CmdUseradd(argc, argv);
        return;
    }
    if (StrEq(cmd, "userdel"))
    {
        CmdUserdel(argc, argv);
        return;
    }
    if (StrEq(cmd, "passwd"))
    {
        CmdPasswd(argc, argv);
        return;
    }
    if (StrEq(cmd, "logout"))
    {
        CmdLogout();
        return;
    }
    if (StrEq(cmd, "su"))
    {
        CmdSu(argc, argv);
        return;
    }
    if (StrEq(cmd, "login"))
    {
        CmdLoginCmd(argc, argv);
        return;
    }
    if (StrEq(cmd, "hostname"))
    {
        CmdHostname();
        return;
    }
    if (StrEq(cmd, "pwd"))
    {
        CmdPwd();
        return;
    }
    if (StrEq(cmd, "true"))
    {
        CmdTrue();
        return;
    }
    if (StrEq(cmd, "false"))
    {
        CmdFalse();
        return;
    }
    if (StrEq(cmd, "mount"))
    {
        if (!RequireAdmin("MOUNT"))
            return;
        CmdMount();
        return;
    }
    if (StrEq(cmd, "lsmod"))
    {
        CmdLsmod();
        return;
    }
    if (StrEq(cmd, "lsblk"))
    {
        CmdLsblk();
        return;
    }
    if (StrEq(cmd, "lsgpt"))
    {
        CmdLsgpt();
        return;
    }
    if (StrEq(cmd, "metrics"))
    {
        CmdMetrics();
        return;
    }
    if (StrEq(cmd, "trace"))
    {
        CmdTrace(argc, argv);
        return;
    }
    if (StrEq(cmd, "read"))
    {
        // Raw block-device read: returns arbitrary sectors from
        // NVMe / AHCI / xHCI MSC. Readable bytes may include
        // filesystem metadata or another user's data, so gate
        // on admin.
        if (!RequireAdmin("READ"))
            return;
        CmdRead(argc, argv);
        return;
    }
    if (StrEq(cmd, "guard"))
    {
        CmdGuard(argc, argv);
        return;
    }
    if (StrEq(cmd, "top"))
    {
        CmdTop();
        return;
    }
    if (StrEq(cmd, "fatls"))
    {
        CmdFatls(argc, argv);
        return;
    }
    if (StrEq(cmd, "fatcat"))
    {
        CmdFatcat(argc, argv);
        return;
    }
    if (StrEq(cmd, "fatwrite"))
    {
        if (!RequireAdmin("FATWRITE"))
            return;
        CmdFatwrite(argc, argv);
        return;
    }
    if (StrEq(cmd, "fatappend"))
    {
        if (!RequireAdmin("FATAPPEND"))
            return;
        CmdFatappend(argc, argv);
        return;
    }
    if (StrEq(cmd, "fatnew"))
    {
        if (!RequireAdmin("FATNEW"))
            return;
        CmdFatnew(argc, argv);
        return;
    }
    if (StrEq(cmd, "fatrm"))
    {
        if (!RequireAdmin("FATRM"))
            return;
        CmdFatrm(argc, argv);
        return;
    }
    if (StrEq(cmd, "fattrunc"))
    {
        if (!RequireAdmin("FATTRUNC"))
            return;
        CmdFattrunc(argc, argv);
        return;
    }
    if (StrEq(cmd, "fatmkdir"))
    {
        if (!RequireAdmin("FATMKDIR"))
            return;
        CmdFatmkdir(argc, argv);
        return;
    }
    if (StrEq(cmd, "fatrmdir"))
    {
        if (!RequireAdmin("FATRMDIR"))
            return;
        CmdFatrmdir(argc, argv);
        return;
    }
    if (StrEq(cmd, "translate"))
    {
        CmdTranslate();
        return;
    }
    if (StrEq(cmd, "linuxexec"))
    {
        // Spawns an ELF as a ring-3 task with arbitrary code.
        // Untrusted users must not be able to start new processes
        // from arbitrary bytes.
        if (!RequireAdmin("LINUXEXEC"))
            return;
        CmdLinuxexec(argc, argv);
        return;
    }
    if (StrEq(cmd, "free"))
    {
        CmdFree();
        return;
    }
    if (StrEq(cmd, "ps"))
    {
        CmdPs();
        return;
    }
    if (StrEq(cmd, "spawn"))
    {
        if (!RequireAdmin("SPAWN"))
            return;
        CmdSpawn(argc, argv);
        return;
    }
    if (StrEq(cmd, "kill"))
    {
        if (!RequireAdmin("KILL"))
            return;
        CmdKill(argc, argv);
        return;
    }
    if (StrEq(cmd, "readelf"))
    {
        CmdReadelf(argc, argv);
        return;
    }
    if (StrEq(cmd, "exec"))
    {
        if (!RequireAdmin("EXEC"))
            return;
        CmdExec(argc, argv);
        return;
    }
    if (StrEq(cmd, "hexdump"))
    {
        CmdHexdump(argc, argv);
        return;
    }
    if (StrEq(cmd, "stat"))
    {
        CmdStat(argc, argv);
        return;
    }
    if (StrEq(cmd, "basename"))
    {
        CmdBasename(argc, argv);
        return;
    }
    if (StrEq(cmd, "dirname"))
    {
        CmdDirname(argc, argv);
        return;
    }
    if (StrEq(cmd, "cal"))
    {
        CmdCal();
        return;
    }
    if (StrEq(cmd, "sleep"))
    {
        CmdSleep(argc, argv);
        return;
    }
    if (StrEq(cmd, "reset"))
    {
        CmdReset();
        return;
    }
    if (StrEq(cmd, "tac"))
    {
        CmdTac(argc, argv);
        return;
    }
    if (StrEq(cmd, "nl"))
    {
        CmdNl(argc, argv);
        return;
    }
    if (StrEq(cmd, "rev"))
    {
        CmdRev(argc, argv);
        return;
    }
    if (StrEq(cmd, "expr"))
    {
        CmdExpr(argc, argv);
        return;
    }
    if (StrEq(cmd, "color"))
    {
        CmdColor(argc, argv);
        return;
    }
    if (StrEq(cmd, "rand"))
    {
        CmdRand(argc, argv);
        return;
    }
    if (StrEq(cmd, "flushtlb") || StrEq(cmd, "flush-tlb"))
    {
        // Forcing a global TLB flush on every CPU is a real
        // performance hit + occasional side-channel probe; not
        // something a logged-in guest should control.
        if (!RequireAdmin("FLUSHTLB"))
            return;
        CmdFlushTlb();
        return;
    }
    if (StrEq(cmd, "checksum"))
    {
        CmdChecksum(argc, argv);
        return;
    }
    if (StrEq(cmd, "repeat"))
    {
        CmdRepeat(argc, argv);
        return;
    }
    if (StrEq(cmd, "reboot"))
    {
        if (!RequireAdmin("REBOOT"))
            return;
        CmdRebootNow();
        // unreachable
    }
    if (StrEq(cmd, "halt"))
    {
        if (!RequireAdmin("HALT"))
            return;
        CmdHaltNow();
        // unreachable
    }
    if (StrEq(cmd, "shutdown") || StrEq(cmd, "poweroff"))
    {
        if (!RequireAdmin("SHUTDOWN"))
            return;
        CmdShutdownNow();
        // unreachable
    }
    if (StrEq(cmd, "beep"))
    {
        CmdBeep(argc, argv);
        return;
    }
    ConsoleWrite("COMMAND NOT FOUND: ");
    ConsoleWriteln(cmd);
    ConsoleWriteln("TYPE HELP FOR A LIST OF COMMANDS.");
}

} // namespace duetos::core::shell::internal
