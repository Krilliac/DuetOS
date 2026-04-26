/*
 * DuetOS — kernel shell: implementation.
 *
 * Companion to shell.h — see there for the v0 scope (line-edit
 * model, command list, intentional limits like single global
 * line buffer, no piping).
 *
 * WHAT
 *   Reads keystrokes from the keyboard input thread, edits a
 *   line buffer, and on Enter dispatches to a fixed command
 *   table. Output goes to the framebuffer console (and to
 *   serial when the framebuffer is unavailable, e.g. early
 *   boot or headless).
 *
 * HOW
 *   Two-tier dispatch:
 *     1. Built-in commands matched by `CommandIs(line, "name")`
 *        in a long if/else chain near `ShellExecute`. Each
 *        command body inlines its own argument parsing — no
 *        argv tokeniser.
 *     2. External commands aren't supported in v0. An unknown
 *        first token prints "command not found" and returns.
 *
 *   Output helpers (WriteU64Dec, WriteU64Hex, etc.) live near
 *   the top — they're used by every command body. Section
 *   banners (`// === network commands`, `// === inspect`,
 *   `// === graphics`) group commands by domain so reading
 *   the file top-to-bottom finds related commands together.
 *
 * WHY THIS FILE IS HUGE (~9.5K LINES)
 *   The shell is the user's primary debug surface. Every
 *   subsystem grows a few `command` entries to expose state
 *   (`pci`, `acpi`, `mem`, `windows`, `ifconfig`, `ext4`,
 *   `nvme`, `inspect`, ...). At ~75-100 commands, each 30-150
 *   lines of body, the file naturally grows past the 500-line
 *   anti-bloat threshold. Splitting commands into per-domain
 *   TUs is on the table once a real text editor / pipe layer
 *   exists; until then, `Ctrl+F help` plus the section banners
 *   keep navigation tractable.
 */

#include "shell.h"

#include "../arch/x86_64/cpu.h"
#include "../arch/x86_64/cpu_info.h"
#include "../arch/x86_64/hpet.h"
#include "../arch/x86_64/lapic.h"
#include "../arch/x86_64/rtc.h"
#include "../arch/x86_64/serial.h"
#include "../arch/x86_64/smbios.h"
#include "../arch/x86_64/smp.h"
#include "../arch/x86_64/thermal.h"
#include "../arch/x86_64/timer.h"
#include "../acpi/acpi.h"
#include "../drivers/audio/pcspk.h"
#include "../drivers/gpu/bochs_vbe.h"
#include "../drivers/gpu/gpu.h"
#include "../drivers/gpu/virtio_gpu.h"
#include "../drivers/input/ps2kbd.h"
#include "../drivers/input/ps2mouse.h"
#include "../drivers/net/net.h"
#include "../drivers/pci/pci.h"
#include "../drivers/usb/cdc_ecm.h"
#include "../drivers/usb/rndis.h"
#include "../drivers/power/power.h"
#include "../net/stack.h"
#include "../net/wifi.h"
#include "../drivers/storage/block.h"
#include "../drivers/video/console.h"
#include "../drivers/video/cursor.h"
#include "../drivers/video/framebuffer.h"
#include "../drivers/video/theme.h"
#include "../drivers/video/widget.h"
#include "../fs/fat32.h"
#include "../subsystems/graphics/graphics.h"
#include "../subsystems/translation/translate.h"
#include "../fs/gpt.h"
#include "../fs/ramfs.h"
#include "../fs/tmpfs.h"
#include "../fs/vfs.h"
#include "../debug/breakpoints.h"
#include "../debug/probes.h"
#include "../debug/inspect.h"
#include "../mm/address_space.h"
#include "../mm/frame_allocator.h"
#include "../mm/kheap.h"
#include "../mm/paging.h"
#include "../sched/sched.h"
#include "../security/attack_sim.h"
#include "../security/guard.h"
#include "elf_loader.h"
#include "hexdump.h"
#include "cleanroom_trace.h"
#include "crprobe.h"
#include "firmware_loader.h"
#include "auth.h"
#include "kdbg.h"
#include "klog.h"
#include "login.h"
#include "symbols.h"
#include "process.h"
#include "random.h"
#include "reboot.h"
#include "ring3_smoke.h"
#include "runtime_checker.h"
#include "shell_internal.h"

namespace duetos::core
{

// Hoist the per-domain Cmd* handlers from the shell sibling TUs
// (shell_security.cpp, ...) back into this TU's outer namespace
// so the dispatch chain in Dispatch() keeps reading like the
// in-TU layout the file used to have.
using namespace shell::internal;

namespace
{

using duetos::drivers::video::ConsoleWrite;
using duetos::drivers::video::ConsoleWriteChar;
using duetos::drivers::video::ConsoleWriteln;

// kInputMax / kHistoryCap + StrEq / StrStartsWith moved to
// shell_internal.h. The history ring (g_history* + HistoryPush /
// HistoryAt / HistoryExpand) lives in shell_state.cpp.
constinit char g_input[kInputMax] = {};
constinit u32 g_len = 0;

// Latched Ctrl+C flag. Long-running commands poll via
// ShellInterruptRequested; the kbd reader flips it on from
// the Ctrl+C hotkey. Read/clear is atomic at word granularity
// on x86_64, which is good enough for the kbd-reader + shell-
// task single-producer / single-consumer pattern.
constinit bool g_interrupt = false;

// Wipe the current visible line (print '\b' len times) and load
// `text` into the edit buffer + echo it. `nullptr` just clears
// the line.
void ReplaceLine(const char* text)
{
    while (g_len > 0)
    {
        ConsoleWriteChar('\b');
        --g_len;
    }
    g_input[0] = '\0';
    if (text == nullptr)
    {
        return;
    }
    for (u32 i = 0; text[i] != '\0' && g_len + 1 < kInputMax; ++i)
    {
        g_input[g_len] = text[i];
        ConsoleWriteChar(text[i]);
        ++g_len;
    }
    g_input[g_len] = '\0';
}

// WriteU64Dec / WriteU8TwoDigits / WriteU64Hex / WriteI64Dec
// moved to shell_format.cpp; declared in shell_internal.h.

// Prompt() reads $PS1 from the env table if set; implementation
// lives after the env infrastructure is declared, further down.
void Prompt();

// ---------------------------------------------------------------
// Commands
// ---------------------------------------------------------------

// Gate sensitive command handlers behind the admin role. Called
// from the dispatch switch below (we gate at dispatch time rather
// than inside each handler so the handler stays a pure worker
// and the policy is visible in one place at the bottom of the
// file). Prints a denial line and klogs a warning so a guest
// brute-forcing commands leaves a serial trail.
bool RequireAdmin(const char* cmd)
{
    if (AuthIsAdmin())
    {
        return true;
    }
    ConsoleWrite("DENIED: ");
    ConsoleWrite(cmd);
    ConsoleWriteln(" REQUIRES ADMIN");
    duetos::core::Log(duetos::core::LogLevel::Warn, "shell", "admin-only command denied");
    duetos::arch::SerialWrite("[shell] denied (non-admin): ");
    duetos::arch::SerialWrite(cmd);
    duetos::arch::SerialWrite("\n");
    return false;
}

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

// Apply a theme change + repaint. Mirrors the Ctrl+Alt+Y hotkey
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

void CmdDmesg(duetos::u32 argc, char** argv)
{
    // Optional first arg picks the minimum severity. Matches the
    // single-letter `loglevel` command ("t" / "d" / "i" / "w" / "e").
    // Default (no arg) shows every entry. Special: `dmesg c` clears
    // the ring (shorthand for the hidden ClearLogRing API).
    duetos::core::LogLevel min_level = duetos::core::LogLevel::Trace;
    const char* banner_suffix = "";
    if (argc >= 2 && argv[1] != nullptr && argv[1][0] != 0)
    {
        const char c = argv[1][0];
        if (c == 'c' || c == 'C')
        {
            duetos::core::ClearLogRing();
            ConsoleWriteln("-- KERNEL LOG RING CLEARED --");
            return;
        }
        switch (c)
        {
        case 't':
        case 'T':
            min_level = duetos::core::LogLevel::Trace;
            banner_suffix = " [FILTER: T+]";
            break;
        case 'd':
        case 'D':
            min_level = duetos::core::LogLevel::Debug;
            banner_suffix = " [FILTER: D+]";
            break;
        case 'i':
        case 'I':
            min_level = duetos::core::LogLevel::Info;
            banner_suffix = " [FILTER: I+]";
            break;
        case 'w':
        case 'W':
            min_level = duetos::core::LogLevel::Warn;
            banner_suffix = " [FILTER: W+]";
            break;
        case 'e':
        case 'E':
            min_level = duetos::core::LogLevel::Error;
            banner_suffix = " [FILTER: E ONLY]";
            break;
        default:
            ConsoleWriteln("DMESG: USE [T|D|I|W|E] (severity) OR [C] (clear ring)");
            return;
        }
    }
    ConsoleWrite("-- KERNEL LOG RING (OLDEST FIRST)");
    ConsoleWriteln(banner_suffix);
    duetos::core::DumpLogRingToFiltered([](const char* s) { ConsoleWrite(s); }, min_level);
}

void CmdStats()
{
    const auto s = duetos::sched::SchedStatsRead();
    ConsoleWrite("CONTEXT SWITCHES ");
    WriteU64Dec(s.context_switches);
    ConsoleWriteChar('\n');
    ConsoleWrite("TASKS LIVE       ");
    WriteU64Dec(s.tasks_live);
    ConsoleWriteChar('\n');
    ConsoleWrite("TASKS SLEEPING   ");
    WriteU64Dec(s.tasks_sleeping);
    ConsoleWriteChar('\n');
    ConsoleWrite("TASKS BLOCKED    ");
    WriteU64Dec(s.tasks_blocked);
    ConsoleWriteChar('\n');
    ConsoleWrite("TASKS CREATED    ");
    WriteU64Dec(s.tasks_created);
    ConsoleWriteChar('\n');
    ConsoleWrite("TASKS EXITED     ");
    WriteU64Dec(s.tasks_exited);
    ConsoleWriteChar('\n');
    ConsoleWrite("TASKS REAPED     ");
    WriteU64Dec(s.tasks_reaped);
    ConsoleWriteChar('\n');
}

// Forwards — these helpers live further down but are used by
// the earlier command implementations / the Prompt helper.
// (TmpLeaf / FatLeaf are now declared in shell_internal.h.)
void Dispatch(char* line); // CmdTime + CmdSource recurse via this

// EnvSlot / g_env / EnvFind / EnvSet / EnvUnset and AliasSlot /
// g_aliases / AliasFind / AliasSet / AliasUnset moved to
// shell_state.cpp; declared in shell_internal.h. EnvNameEq +
// EnvCopy stay inline in the same header so any caller in
// either table reaches them through the using-directive at the
// top of this TU.

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

// Pull a file's bytes into an output buffer. Source can be
// either tmpfs (/tmp/<leaf>) or the read-only ramfs. Returns
// the number of bytes copied (up to `cap`) or u32 max on miss.
// Never dereferences a nullptr out buffer.
// ReadFileToBuf moved to shell_fsio.cpp.

// CmdCp moved to shell_filesystem.cpp.

// CmdMv / CmdWc / CmdHead / CmdTail moved to shell_filesystem.cpp.
// ParseLineCount / SubstringPresent / LineCompare moved with them.

// SliceLines moved to shell_fsio.cpp.

// CmdSort / CmdUniq / CmdGrep / CmdFind moved to shell_filesystem.cpp.
// FindWalk moved with them.

// Canonical built-in command list. Single source of truth used
// by ShellTabComplete + `which`. New commands added here +
// dispatched in Dispatch — keeping the two in sync is the
// price of not having reflection.
static const char* const kCommandSet[] = {
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
constexpr u32 kCommandCount = sizeof(kCommandSet) / sizeof(kCommandSet[0]);

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

void CmdSeq(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("SEQ: USAGE: SEQ N");
        return;
    }
    u32 n = 0;
    for (u32 i = 0; argv[1][i] != '\0'; ++i)
    {
        if (argv[1][i] < '0' || argv[1][i] > '9')
        {
            ConsoleWriteln("SEQ: BAD NUMBER");
            return;
        }
        n = n * 10 + static_cast<u32>(argv[1][i] - '0');
    }
    // Uncapped; check the Ctrl+C flag every iteration. A user
    // who mistakes `seq 100000` for `seq 100` can bail out the
    // moment the scroll starts. The interrupt latch is cleared
    // on consume, so a second command after ^C runs normally.
    for (u32 i = 1; i <= n; ++i)
    {
        if (ShellInterruptRequested())
        {
            ConsoleWriteln("^C");
            return;
        }
        WriteU64Dec(i);
        ConsoleWriteChar('\n');
    }
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

// CmdSet / CmdUnset / CmdAlias / CmdUnalias moved to
// shell_core.cpp.

// Forward declaration for mutual recursion: source -> dispatch
// -> (a sourced line could reference another command).
void Dispatch(char* line);

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

void CmdMan(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("MAN: MISSING COMMAND NAME");
        ConsoleWriteln("MAN: TRY `help` FOR A COMMAND LIST");
        return;
    }
    const char* name = argv[1];

    // Build "/etc/man/<name>" in a scratch buffer and cat it.
    // 6 ("/etc/man") + "/" + up to name-max (32 is plenty) +
    // NUL fits comfortably in 48 bytes.
    char path[64];
    const char prefix[] = "/etc/man/";
    u32 o = 0;
    for (; prefix[o] != '\0'; ++o)
    {
        path[o] = prefix[o];
    }
    for (u32 i = 0; name[i] != '\0' && o + 1 < sizeof(path); ++i)
    {
        path[o++] = name[i];
    }
    path[o] = '\0';

    char scratch[duetos::fs::kTmpFsContentMax];
    const u32 n = ReadFileToBuf(path, scratch, sizeof(scratch));
    if (n == static_cast<u32>(-1))
    {
        ConsoleWrite("MAN: NO PAGE FOR: ");
        ConsoleWriteln(name);
        ConsoleWriteln("MAN: TRY `help` FOR A COMMAND LIST");
        ConsoleWriteln("MAN: OR `ls /etc/man` TO SEE WHAT'S AVAILABLE");
        return;
    }
    for (u32 i = 0; i < n; ++i)
    {
        ConsoleWriteChar(scratch[i]);
    }
    if (n == 0 || scratch[n - 1] != '\n')
    {
        ConsoleWriteChar('\n');
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

// CmdEnv moved to shell_core.cpp.

// ---------------------------------------------------------------
// System introspection / manipulation commands.
// Raw views into CPU / MSR / APIC / PCI / paging / heap / input
// drivers, plus power-control (reboot, halt) + runtime setters
// (loglevel, getenv). Every getter is side-effect-free; power
// commands call the existing kernel primitives.
// ---------------------------------------------------------------

// CpuidRaw / ReadRflags / ReadTsc / ReadMsrRaw moved to
// shell_hardware.cpp.

// CmdCpuid / CmdCr / CmdRflags / CmdTsc / CmdHpet / CmdTicks
// moved to shell_hardware.cpp. kRflagsBitIdx / kRflagsBitNames
// followed.

// CmdMsr / CmdLapic / CmdSmp / CmdLspci / CmdHeap / CmdPaging /
// CmdFb / CmdKbdStats / CmdMouseStats moved to shell_hardware.cpp.

// ------ Observability commands for the v0 subsystems ------

// CmdSmbios / CmdPower / CmdThermal moved to shell_hardware.cpp.

// CmdHwmon moved to shell_hardware.cpp.

// CmdGpu / CmdGfx / CmdVbe moved to shell_hardware.cpp.


// Parse dotted-quad `a.b.c.d`. Returns true on exact 4-octet match.
// ParseIpv4 / WriteIpv4 / WriteMac / Ipv4IsZero hoisted to shell_network.cpp
// (declared in shell_internal.h). CmdPing / CmdHttp / CmdNtp / CmdNslookup
// / CmdNic / CmdIfconfig moved with them.


// Pure-status dump for the DHCP lease. `dhcp` shows; `dhcp renew`
// kicks a fresh DISCOVER on iface 0. Renewal is a one-shot — the
// stack's DhcpStart resets the state machine + sends DISCOVER, so
// calling it again from the shell is idempotent.
// CmdDhcp / CmdRoute / CmdNetscan / CmdWifi / CmdFwPolicy / CmdFwTrace /
// CmdCrTrace / CmdNet / CmdUsbNet moved to shell_network.cpp.


// CmdArp moved to shell_network.cpp.


void CmdHealth(u32 argc, char** argv)
{
    // Run a fresh scan (so the report reflects the current
    // moment, not the last heartbeat), then print the full
    // report: each issue kind with its cumulative count plus
    // this-scan and total-since-boot summaries.
    const u64 this_scan = duetos::core::RuntimeCheckerScan();
    const auto& h = duetos::core::RuntimeCheckerStatusRead();
    (void)argc;
    (void)argv;
    ConsoleWrite("SCANS RUN:        ");
    WriteU64Dec(h.scans_run);
    ConsoleWriteChar('\n');
    ConsoleWrite("THIS SCAN:        ");
    WriteU64Dec(this_scan);
    ConsoleWriteln(this_scan == 0 ? " issues (CLEAN)" : " issues");
    ConsoleWrite("TOTAL ISSUES:     ");
    WriteU64Dec(h.issues_found_total);
    ConsoleWriteChar('\n');
    ConsoleWrite("BASELINE CAPTURED:");
    ConsoleWriteln(h.baseline_captured ? " YES" : " NO");
    if (h.issues_found_total > 0)
    {
        ConsoleWriteln("PER-ISSUE BREAKDOWN:");
        for (u32 i = 1; i < u32(duetos::core::HealthIssue::Count); ++i)
        {
            const u64 c = h.per_issue_count[i];
            if (c == 0)
                continue;
            ConsoleWrite("  ");
            WriteU64Dec(c);
            ConsoleWrite(" x ");
            ConsoleWriteln(duetos::core::HealthIssueName(duetos::core::HealthIssue(i)));
        }
    }
}

void CmdMemDump(u32 argc, char** argv)
{
    // memdump <hex-addr> [len]   — dump arbitrary kernel memory.
    // Uses the SAFE variant: any line whose page is outside the
    // known-mapped kernel ranges emits "<unreadable>" instead of
    // faulting, so a typo'd address is a diagnostic, not a crash.
    // Output is written to COM1 (serial) — too wide for the 80-col
    // framebuffer console; the shell prompt confirms where to look.
    if (argc < 2)
    {
        ConsoleWriteln("MEMDUMP: USAGE: MEMDUMP <HEX-ADDR> [LEN-BYTES]");
        ConsoleWriteln("         OUTPUT GOES TO COM1 (SERIAL LOG)");
        return;
    }
    duetos::u64 addr = 0;
    if (!ParseU64Str(argv[1], &addr))
    {
        ConsoleWriteln("MEMDUMP: BAD ADDRESS");
        return;
    }
    duetos::u64 len = 64;
    if (argc >= 3 && !ParseU64Str(argv[2], &len))
    {
        ConsoleWriteln("MEMDUMP: BAD LENGTH");
        return;
    }
    if (len == 0)
    {
        ConsoleWriteln("MEMDUMP: ZERO LENGTH");
        return;
    }
    duetos::core::DumpHexRegionSafe("memdump", addr, static_cast<duetos::u32>(len), 0);
    ConsoleWriteln("MEMDUMP: WROTE TO COM1");
}

const char* BpKindName(duetos::debug::BpKind k)
{
    switch (k)
    {
    case duetos::debug::BpKind::Software:
        return "SW";
    case duetos::debug::BpKind::HwExecute:
        return "HW-X";
    case duetos::debug::BpKind::HwWrite:
        return "HW-W";
    case duetos::debug::BpKind::HwReadWrite:
        return "HW-RW";
    }
    return "?";
}

const char* BpErrName(duetos::debug::BpError e)
{
    switch (e)
    {
    case duetos::debug::BpError::None:
        return "OK";
    case duetos::debug::BpError::InvalidAddress:
        return "INVALID-ADDRESS";
    case duetos::debug::BpError::TableFull:
        return "TABLE-FULL";
    case duetos::debug::BpError::NoHwSlot:
        return "NO-HW-SLOT";
    case duetos::debug::BpError::BadKind:
        return "BAD-KIND";
    case duetos::debug::BpError::NotInstalled:
        return "NOT-INSTALLED";
    case duetos::debug::BpError::SmpUnsupported:
        return "SMP-UNSUPPORTED";
    }
    return "?";
}

// Consume a leading `--suspend` / `-s` flag from argv starting at
// `start`. If present, set *suspend and slide argv left by one so
// the remaining args are positional. Returns the new argc.
u32 TakeSuspendFlag(u32 argc, char** argv, u32 start, bool* suspend)
{
    if (argc <= start || argv[start] == nullptr)
        return argc;
    if (StrEq(argv[start], "--suspend") || StrEq(argv[start], "-s"))
    {
        *suspend = true;
        for (u32 i = start; i + 1 < argc; ++i)
            argv[i] = argv[i + 1];
        return argc - 1;
    }
    return argc;
}

void PrintBpRegs(const duetos::arch::TrapFrame& f)
{
    // Keep this dense — the framebuffer is 80 cols and the TrapFrame
    // has 15 GPRs + control. Group into rows the operator can scan.
    ConsoleWrite("  rip=");
    WriteU64Hex(f.rip, 16);
    ConsoleWrite(" cs=");
    WriteU64Hex(f.cs, 4);
    ConsoleWrite(" flags=");
    WriteU64Hex(f.rflags, 16);
    ConsoleWriteChar('\n');
    ConsoleWrite("  rsp=");
    WriteU64Hex(f.rsp, 16);
    ConsoleWrite(" ss=");
    WriteU64Hex(f.ss, 4);
    ConsoleWriteChar('\n');
    ConsoleWrite("  rax=");
    WriteU64Hex(f.rax, 16);
    ConsoleWrite(" rbx=");
    WriteU64Hex(f.rbx, 16);
    ConsoleWriteChar('\n');
    ConsoleWrite("  rcx=");
    WriteU64Hex(f.rcx, 16);
    ConsoleWrite(" rdx=");
    WriteU64Hex(f.rdx, 16);
    ConsoleWriteChar('\n');
    ConsoleWrite("  rsi=");
    WriteU64Hex(f.rsi, 16);
    ConsoleWrite(" rdi=");
    WriteU64Hex(f.rdi, 16);
    ConsoleWriteChar('\n');
    ConsoleWrite("  rbp=");
    WriteU64Hex(f.rbp, 16);
    ConsoleWrite(" r8 =");
    WriteU64Hex(f.r8, 16);
    ConsoleWriteChar('\n');
    ConsoleWrite("  r9 =");
    WriteU64Hex(f.r9, 16);
    ConsoleWrite(" r10=");
    WriteU64Hex(f.r10, 16);
    ConsoleWriteChar('\n');
    ConsoleWrite("  r11=");
    WriteU64Hex(f.r11, 16);
    ConsoleWrite(" r12=");
    WriteU64Hex(f.r12, 16);
    ConsoleWriteChar('\n');
    ConsoleWrite("  r13=");
    WriteU64Hex(f.r13, 16);
    ConsoleWrite(" r14=");
    WriteU64Hex(f.r14, 16);
    ConsoleWriteChar('\n');
    ConsoleWrite("  r15=");
    WriteU64Hex(f.r15, 16);
    ConsoleWrite(" vec=");
    WriteU64Hex(f.vector, 2);
    ConsoleWriteChar('\n');
}

void CmdBp(u32 argc, char** argv)
{
    // bp list                                 — list installed BPs
    // bp set    [--suspend] <hex-addr>        — software BP
    // bp hw     [--suspend] <hex-addr> [x|w|rw] [len]  — HW BP
    // bp clear  <id>                          — remove BP
    // bp test                                 — self-test
    // bp stopped                              — list suspended tasks
    // bp regs   <id>                          — dump stopped regs
    // bp mem    <id> <hex-addr> [len]         — dump stopped memory
    // bp resume <id>                          — resume stopped task
    // bp step   <id>                          — single-step + re-suspend
    if (argc < 2)
    {
        ConsoleWriteln("BP: USAGE:");
        ConsoleWriteln("    BP LIST");
        ConsoleWriteln("    BP SET    [--SUSPEND] <HEX-ADDR>               (SOFTWARE)");
        ConsoleWriteln("    BP HW     [--SUSPEND] <HEX-ADDR> [X|W|RW] [LEN] (HARDWARE)");
        ConsoleWriteln("    BP CLEAR  <ID>                                  (REMOVE)");
        ConsoleWriteln("    BP TEST                                         (SELF-TEST)");
        ConsoleWriteln("    BP STOPPED                                      (LIST SUSPENDED)");
        ConsoleWriteln("    BP REGS   <ID>                                  (DUMP REGS)");
        ConsoleWriteln("    BP MEM    <ID> <HEX-ADDR> [LEN]                 (DUMP USER MEM)");
        ConsoleWriteln("    BP RESUME <ID>                                  (WAKE STOPPED)");
        ConsoleWriteln("    BP STEP   <ID>                                  (STEP + RE-SUSPEND)");
        return;
    }

    const char* sub = argv[1];

    if (StrEq(sub, "list"))
    {
        duetos::debug::BpInfo infos[32];
        const usize n = duetos::debug::BpList(infos, 32);
        if (n == 0)
        {
            ConsoleWriteln("BP: NONE INSTALLED");
            return;
        }
        ConsoleWriteln("BP: ID KIND   ADDR              HITS  STATE");
        for (usize i = 0; i < n; ++i)
        {
            ConsoleWrite("  ");
            WriteU64Dec(infos[i].id.value);
            ConsoleWrite("  ");
            ConsoleWrite(BpKindName(infos[i].kind));
            ConsoleWrite("  ");
            WriteU64Hex(infos[i].address, 16);
            ConsoleWrite("  ");
            WriteU64Dec(infos[i].hit_count);
            ConsoleWrite("  ");
            if (infos[i].is_stopped)
            {
                ConsoleWrite("STOPPED(task=");
                WriteU64Dec(infos[i].stopped_task_id);
                ConsoleWriteChar(')');
            }
            else if (infos[i].suspend_on_hit)
            {
                ConsoleWrite("ARMED-SUSPEND");
            }
            else
            {
                ConsoleWrite("ARMED-LOG");
            }
            ConsoleWriteChar('\n');
        }
        return;
    }

    if (StrEq(sub, "set"))
    {
        bool suspend = false;
        argc = TakeSuspendFlag(argc, argv, 2, &suspend);
        if (argc < 3)
        {
            ConsoleWriteln("BP SET: NEED <HEX-ADDR>");
            return;
        }
        duetos::u64 addr = 0;
        if (!ParseU64Str(argv[2], &addr))
        {
            ConsoleWriteln("BP SET: BAD ADDRESS");
            return;
        }
        duetos::debug::BpError err = duetos::debug::BpError::None;
        const duetos::debug::BreakpointId id = duetos::debug::BpInstallSoftware(addr, suspend, &err);
        if (err != duetos::debug::BpError::None)
        {
            ConsoleWrite("BP SET: ");
            ConsoleWriteln(BpErrName(err));
            return;
        }
        ConsoleWrite("BP SET: OK ID=");
        WriteU64Dec(id.value);
        ConsoleWriteln(suspend ? " (SUSPEND-ON-HIT)" : "");
        return;
    }

    if (StrEq(sub, "hw"))
    {
        bool suspend = false;
        argc = TakeSuspendFlag(argc, argv, 2, &suspend);
        if (argc < 3)
        {
            ConsoleWriteln("BP HW: NEED <HEX-ADDR> [X|W|RW] [LEN]");
            return;
        }
        duetos::u64 addr = 0;
        if (!ParseU64Str(argv[2], &addr))
        {
            ConsoleWriteln("BP HW: BAD ADDRESS");
            return;
        }
        duetos::debug::BpKind kind = duetos::debug::BpKind::HwExecute;
        duetos::debug::BpLen len = duetos::debug::BpLen::One;
        if (argc >= 4)
        {
            if (StrEq(argv[3], "x"))
                kind = duetos::debug::BpKind::HwExecute;
            else if (StrEq(argv[3], "w"))
                kind = duetos::debug::BpKind::HwWrite;
            else if (StrEq(argv[3], "rw"))
                kind = duetos::debug::BpKind::HwReadWrite;
            else
            {
                ConsoleWriteln("BP HW: BAD KIND (USE X|W|RW)");
                return;
            }
        }
        if (argc >= 5 && kind != duetos::debug::BpKind::HwExecute)
        {
            duetos::u64 ln = 0;
            if (!ParseU64Str(argv[4], &ln))
            {
                ConsoleWriteln("BP HW: BAD LEN");
                return;
            }
            switch (ln)
            {
            case 1:
                len = duetos::debug::BpLen::One;
                break;
            case 2:
                len = duetos::debug::BpLen::Two;
                break;
            case 4:
                len = duetos::debug::BpLen::Four;
                break;
            case 8:
                len = duetos::debug::BpLen::Eight;
                break;
            default:
                ConsoleWriteln("BP HW: LEN MUST BE 1/2/4/8");
                return;
            }
        }
        duetos::debug::BpError err = duetos::debug::BpError::None;
        const duetos::debug::BreakpointId id =
            duetos::debug::BpInstallHardware(addr, kind, len, /*owner_pid=*/0, suspend, &err);
        if (err != duetos::debug::BpError::None)
        {
            ConsoleWrite("BP HW: ");
            ConsoleWriteln(BpErrName(err));
            return;
        }
        ConsoleWrite("BP HW: OK ID=");
        WriteU64Dec(id.value);
        ConsoleWriteln(suspend ? " (SUSPEND-ON-HIT)" : "");
        return;
    }

    if (StrEq(sub, "clear") || StrEq(sub, "rm"))
    {
        if (argc < 3)
        {
            ConsoleWriteln("BP CLEAR: NEED <ID>");
            return;
        }
        duetos::u64 id_val = 0;
        if (!ParseU64Str(argv[2], &id_val))
        {
            ConsoleWriteln("BP CLEAR: BAD ID");
            return;
        }
        const duetos::debug::BpError err =
            duetos::debug::BpRemove({static_cast<duetos::u32>(id_val)}, /*requester_pid=*/0);
        ConsoleWrite("BP CLEAR: ");
        ConsoleWriteln(BpErrName(err));
        return;
    }

    if (StrEq(sub, "test"))
    {
        const bool ok = duetos::debug::BpSelfTest();
        ConsoleWriteln(ok ? "BP TEST: OK" : "BP TEST: FAILED (SEE SERIAL LOG)");
        return;
    }

    if (StrEq(sub, "stopped"))
    {
        duetos::debug::BpInfo infos[32];
        const usize n = duetos::debug::BpList(infos, 32);
        usize any = 0;
        for (usize i = 0; i < n; ++i)
        {
            if (!infos[i].is_stopped)
                continue;
            if (any == 0)
                ConsoleWriteln("BP STOPPED: BP-ID  TASK  ADDR");
            ConsoleWrite("  ");
            WriteU64Dec(infos[i].id.value);
            ConsoleWrite("    ");
            WriteU64Dec(infos[i].stopped_task_id);
            ConsoleWrite("    ");
            WriteU64Hex(infos[i].address, 16);
            ConsoleWriteChar('\n');
            ++any;
        }
        if (any == 0)
            ConsoleWriteln("BP STOPPED: NONE");
        return;
    }

    if (StrEq(sub, "regs"))
    {
        if (argc < 3)
        {
            ConsoleWriteln("BP REGS: NEED <ID>");
            return;
        }
        duetos::u64 id_val = 0;
        if (!ParseU64Str(argv[2], &id_val))
        {
            ConsoleWriteln("BP REGS: BAD ID");
            return;
        }
        duetos::arch::TrapFrame f;
        if (!duetos::debug::BpReadRegs({static_cast<duetos::u32>(id_val)}, &f))
        {
            ConsoleWriteln("BP REGS: NO TASK STOPPED ON THAT ID");
            return;
        }
        ConsoleWrite("BP REGS ID=");
        WriteU64Dec(id_val);
        ConsoleWriteln(":");
        PrintBpRegs(f);
        return;
    }

    if (StrEq(sub, "mem"))
    {
        if (argc < 4)
        {
            ConsoleWriteln("BP MEM: NEED <ID> <HEX-ADDR> [LEN]");
            return;
        }
        duetos::u64 id_val = 0;
        duetos::u64 addr = 0;
        if (!ParseU64Str(argv[2], &id_val) || !ParseU64Str(argv[3], &addr))
        {
            ConsoleWriteln("BP MEM: BAD ARGS");
            return;
        }
        duetos::u64 len = 64; // default
        if (argc >= 5)
        {
            if (!ParseU64Str(argv[4], &len))
            {
                ConsoleWriteln("BP MEM: BAD LEN");
                return;
            }
        }
        if (len > 256)
            len = 256; // shell cap — longer dumps belong on serial
        duetos::u8 buf[256];
        const duetos::u64 got = duetos::debug::BpReadMem({static_cast<duetos::u32>(id_val)}, addr, buf, len);
        if (got == 0)
        {
            ConsoleWriteln("BP MEM: UNREADABLE (UNMAPPED OR NO STOPPED TASK)");
            return;
        }
        // Hex + ASCII, 16 bytes per line.
        for (duetos::u64 off = 0; off < got; off += 16)
        {
            WriteU64Hex(addr + off, 16);
            ConsoleWrite(": ");
            for (duetos::u64 i = 0; i < 16; ++i)
            {
                if (off + i < got)
                {
                    const duetos::u8 b = buf[off + i];
                    const char hi = static_cast<char>("0123456789abcdef"[(b >> 4) & 0xF]);
                    const char lo = static_cast<char>("0123456789abcdef"[b & 0xF]);
                    ConsoleWriteChar(hi);
                    ConsoleWriteChar(lo);
                }
                else
                {
                    ConsoleWrite("  ");
                }
                ConsoleWriteChar(' ');
            }
            ConsoleWriteChar(' ');
            for (duetos::u64 i = 0; i < 16 && off + i < got; ++i)
            {
                const duetos::u8 b = buf[off + i];
                ConsoleWriteChar((b >= 0x20 && b < 0x7F) ? static_cast<char>(b) : '.');
            }
            ConsoleWriteChar('\n');
        }
        return;
    }

    if (StrEq(sub, "resume"))
    {
        if (argc < 3)
        {
            ConsoleWriteln("BP RESUME: NEED <ID>");
            return;
        }
        duetos::u64 id_val = 0;
        if (!ParseU64Str(argv[2], &id_val))
        {
            ConsoleWriteln("BP RESUME: BAD ID");
            return;
        }
        const duetos::debug::BpError err = duetos::debug::BpResume({static_cast<duetos::u32>(id_val)});
        ConsoleWrite("BP RESUME: ");
        ConsoleWriteln(BpErrName(err));
        return;
    }

    if (StrEq(sub, "step"))
    {
        if (argc < 3)
        {
            ConsoleWriteln("BP STEP: NEED <ID>");
            return;
        }
        duetos::u64 id_val = 0;
        if (!ParseU64Str(argv[2], &id_val))
        {
            ConsoleWriteln("BP STEP: BAD ID");
            return;
        }
        const duetos::debug::BpError err = duetos::debug::BpStep({static_cast<duetos::u32>(id_val)});
        ConsoleWrite("BP STEP: ");
        ConsoleWriteln(BpErrName(err));
        return;
    }

    ConsoleWriteln("BP: UNKNOWN SUBCOMMAND (HELP: BP WITHOUT ARGS)");
}

const char* ProbeArmName(duetos::debug::ProbeArm a)
{
    switch (a)
    {
    case duetos::debug::ProbeArm::Disarmed:
        return "DISARMED";
    case duetos::debug::ProbeArm::ArmedLog:
        return "ARMED-LOG";
    case duetos::debug::ProbeArm::ArmedSuspend:
        return "ARMED-SUSPEND";
    }
    return "?";
}

void CmdProbe(u32 argc, char** argv)
{
    // probe list
    // probe arm <name> [--suspend]      — ArmedLog (or ArmedSuspend)
    // probe disarm <name>
    // probe arm-all                     — arm every probe ArmedLog
    // probe disarm-all                  — disarm everything
    if (argc < 2)
    {
        ConsoleWriteln("PROBE: USAGE:");
        ConsoleWriteln("    PROBE LIST                         LIST + COUNTS + ARM STATE");
        ConsoleWriteln("    PROBE ARM <NAME> [--SUSPEND]       ARM ONE PROBE");
        ConsoleWriteln("    PROBE DISARM <NAME>                DISARM ONE PROBE");
        ConsoleWriteln("    PROBE ARM-ALL                      ARM-LOG EVERY PROBE (NOISY)");
        ConsoleWriteln("    PROBE DISARM-ALL                   DISARM EVERYTHING");
        return;
    }
    const char* sub = argv[1];
    if (StrEq(sub, "list"))
    {
        duetos::debug::ProbeInfo infos[16];
        const duetos::u64 n = duetos::debug::ProbeList(infos, 16);
        if (n == 0)
        {
            ConsoleWriteln("PROBE: NONE REGISTERED");
            return;
        }
        ConsoleWriteln("PROBE: NAME                     ARM            FIRES");
        for (duetos::u64 i = 0; i < n; ++i)
        {
            ConsoleWrite("  ");
            ConsoleWrite(infos[i].name);
            // pad name to column
            for (duetos::u64 pad = 0; pad + 0 < 24; ++pad)
            {
                const char* p = infos[i].name;
                duetos::u64 len = 0;
                while (p[len] != 0)
                    ++len;
                if (pad + len >= 24)
                    break;
                if (pad + len < 24)
                {
                    ConsoleWriteChar(' ');
                }
                if (pad + len + 1 >= 24)
                    break;
            }
            ConsoleWrite(ProbeArmName(infos[i].arm));
            ConsoleWrite("  ");
            WriteU64Dec(infos[i].fire_count);
            ConsoleWriteChar('\n');
        }
        return;
    }
    if (StrEq(sub, "arm") || StrEq(sub, "disarm"))
    {
        if (argc < 3)
        {
            ConsoleWriteln("PROBE: NEED <NAME>");
            return;
        }
        const duetos::debug::ProbeId id = duetos::debug::ProbeByName(argv[2]);
        if (id == duetos::debug::ProbeId::kCount)
        {
            ConsoleWriteln("PROBE: UNKNOWN NAME (SEE `PROBE LIST`)");
            return;
        }
        duetos::debug::ProbeArm arm = duetos::debug::ProbeArm::Disarmed;
        if (StrEq(sub, "arm"))
        {
            arm = duetos::debug::ProbeArm::ArmedLog;
            if (argc >= 4 && (StrEq(argv[3], "--suspend") || StrEq(argv[3], "-s")))
                arm = duetos::debug::ProbeArm::ArmedSuspend;
        }
        duetos::debug::ProbeSetArm(id, arm);
        ConsoleWrite("PROBE ");
        ConsoleWrite(argv[2]);
        ConsoleWrite(": ");
        ConsoleWriteln(ProbeArmName(arm));
        return;
    }
    if (StrEq(sub, "arm-all"))
    {
        for (duetos::u32 i = 0; i < static_cast<duetos::u32>(duetos::debug::ProbeId::kCount); ++i)
            duetos::debug::ProbeSetArm(static_cast<duetos::debug::ProbeId>(i), duetos::debug::ProbeArm::ArmedLog);
        ConsoleWriteln("PROBE: ALL ARMED-LOG (MAY FLOOD LOG)");
        return;
    }
    if (StrEq(sub, "disarm-all"))
    {
        for (duetos::u32 i = 0; i < static_cast<duetos::u32>(duetos::debug::ProbeId::kCount); ++i)
            duetos::debug::ProbeSetArm(static_cast<duetos::debug::ProbeId>(i), duetos::debug::ProbeArm::Disarmed);
        ConsoleWriteln("PROBE: ALL DISARMED");
        return;
    }
    ConsoleWriteln("PROBE: UNKNOWN SUBCOMMAND");
}

void CmdInstr(u32 argc, char** argv)
{
    // instr <hex-addr> [len]   — dump instruction bytes at a code
    // address. Single line. Useful for staring at a fault RIP after
    // the fact, or for verifying a hot-patched function still has
    // the bytes it should. Default 16 covers any single x86_64
    // instruction (max length is 15).
    if (argc < 2)
    {
        ConsoleWriteln("INSTR: USAGE: INSTR <HEX-ADDR> [LEN-BYTES]");
        ConsoleWriteln("       OUTPUT GOES TO COM1 (SERIAL LOG)");
        return;
    }
    duetos::u64 addr = 0;
    if (!ParseU64Str(argv[1], &addr))
    {
        ConsoleWriteln("INSTR: BAD ADDRESS");
        return;
    }
    duetos::u64 len = 16;
    if (argc >= 3 && !ParseU64Str(argv[2], &len))
    {
        ConsoleWriteln("INSTR: BAD LENGTH");
        return;
    }
    duetos::core::DumpInstructionBytes("instr", addr, static_cast<duetos::u32>(len));
    ConsoleWriteln("INSTR: WROTE TO COM1");
}

// addr2sym <hex-addr> — resolve a kernel VA to function+offset (file:line)
// using the embedded symbol table. The same lookup the panic dump uses,
// exposed at the shell so an operator can decode a RIP off a serial log
// without leaving the running system. Output goes to BOTH the on-screen
// console (one truncated line) and COM1 (full annotated line). Mirrors
// the host-side `tools/symbolize.sh` for offline use, but doesn't need
// addr2line / llvm-symbolizer.
void CmdAddr2Sym(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("ADDR2SYM: USAGE: ADDR2SYM <HEX-ADDR>");
        ConsoleWriteln("         RESOLVE A KERNEL VA TO FN+OFFSET (FILE:LINE)");
        return;
    }
    duetos::u64 addr = 0;
    if (!ParseU64Str(argv[1], &addr))
    {
        ConsoleWriteln("ADDR2SYM: BAD ADDRESS");
        return;
    }
    // COM1: full canonical form (matches every other panic-dump line so
    // post-mortem grep sees the same shape).
    duetos::arch::SerialWrite("[addr2sym] ");
    duetos::core::WriteAddressWithSymbol(addr);
    duetos::arch::SerialWrite("\n");

    // Console: short summary, since the full file path often won't fit
    // in 80 cols. Fall back to "<unresolved>" when the lookup misses.
    duetos::core::SymbolResolution res{};
    if (!duetos::core::ResolveAddress(addr, &res) || res.entry == nullptr)
    {
        ConsoleWriteln("ADDR2SYM: <UNRESOLVED>");
        return;
    }
    char line[96];
    duetos::u32 i = 0;
    auto put = [&](const char* s)
    {
        for (duetos::u32 k = 0; s[k] != '\0' && i + 1 < sizeof(line); ++k)
            line[i++] = s[k];
    };
    auto put_hex = [&](duetos::u64 v)
    {
        char buf[18];
        buf[0] = '0';
        buf[1] = 'x';
        for (duetos::u32 d = 0; d < 16; ++d)
        {
            const duetos::u32 nib = static_cast<duetos::u32>((v >> ((15 - d) * 4)) & 0xF);
            buf[2 + d] = static_cast<char>(nib < 10 ? '0' + nib : 'a' + (nib - 10));
        }
        for (duetos::u32 k = 0; k < 18 && i + 1 < sizeof(line); ++k)
            line[i++] = buf[k];
    };
    put("ADDR2SYM ");
    put_hex(addr);
    put(" -> ");
    put(res.entry->name);
    put("+");
    put_hex(res.offset);
    line[i] = '\0';
    ConsoleWriteln(line);
}

void CmdInspectHelp()
{
    ConsoleWriteln("INSPECT: RE / TRIAGE UMBRELLA (SEE COM1 FOR REPORTS)");
    ConsoleWriteln("  INSPECT SYSCALLS KERNEL | <PATH>  FIND SYSCALL SITES + COVERAGE");
    ConsoleWriteln("  INSPECT OPCODES <PATH>            FIRST-BYTE HISTOGRAM + CLASS TALLY");
    ConsoleWriteln("  INSPECT ARM ON|OFF|STATUS         ONE-SHOT OPCODES SCAN ON NEXT SPAWN");
    ConsoleWriteln("  INSPECT HELP                      THIS LIST");
}

void CmdInspectSyscalls(u32 argc, char** argv)
{
    // argv[0]=inspect, argv[1]=syscalls, argv[2]=<target>
    if (argc < 3)
    {
        ConsoleWriteln("INSPECT SYSCALLS: USAGE: INSPECT SYSCALLS KERNEL | <PATH>");
        return;
    }
    if (StrEq(argv[2], "kernel"))
    {
        ConsoleWriteln("INSPECT SYSCALLS: SCANNING KERNEL .TEXT (SEE COM1)");
        (void)duetos::debug::SyscallScanKernelText();
        ConsoleWriteln("INSPECT SYSCALLS: DONE");
        return;
    }
    ConsoleWrite("INSPECT SYSCALLS: SCANNING FILE \"");
    ConsoleWrite(argv[2]);
    ConsoleWriteln("\" (SEE COM1)");
    (void)duetos::debug::SyscallScanFile(argv[2]);
    ConsoleWriteln("INSPECT SYSCALLS: DONE");
}

void CmdInspectOpcodes(u32 argc, char** argv)
{
    // argv[0]=inspect, argv[1]=opcodes, argv[2]=<path>
    if (argc < 3)
    {
        ConsoleWriteln("INSPECT OPCODES: USAGE: INSPECT OPCODES <PATH>");
        return;
    }
    ConsoleWrite("INSPECT OPCODES: SCANNING FILE \"");
    ConsoleWrite(argv[2]);
    ConsoleWriteln("\" (SEE COM1)");
    duetos::debug::OpcodeScanFile(argv[2]);
    ConsoleWriteln("INSPECT OPCODES: DONE");
}

void CmdInspectArm(u32 argc, char** argv)
{
    // argv[0]=inspect, argv[1]=arm, argv[2]=on|off|status
    if (argc < 3)
    {
        ConsoleWriteln("INSPECT ARM: USAGE: INSPECT ARM ON|OFF|STATUS");
        return;
    }
    if (StrEq(argv[2], "on"))
    {
        duetos::debug::InspectArmSet(true);
        ConsoleWriteln("INSPECT ARM: ARMED - OPCODES SCAN WILL FIRE ON NEXT SPAWN");
        return;
    }
    if (StrEq(argv[2], "off"))
    {
        duetos::debug::InspectArmSet(false);
        ConsoleWriteln("INSPECT ARM: DISARMED");
        return;
    }
    if (StrEq(argv[2], "status"))
    {
        ConsoleWriteln(duetos::debug::InspectArmActive() ? "INSPECT ARM: STATE=ON (ONE-SHOT)" //
                                                         : "INSPECT ARM: STATE=OFF");
        return;
    }
    ConsoleWriteln("INSPECT ARM: UNKNOWN MODE (USE ON/OFF/STATUS)");
}

void CmdInspect(u32 argc, char** argv)
{
    // inspect <sub> ...
    // Thin dispatcher — each subcommand handler parses its own
    // argv[2..]. Keeps subcommands independent so `inspect
    // opcodes /bin/foo.exe` can't be broken by a change to
    // `inspect syscalls`.
    if (argc < 2)
    {
        CmdInspectHelp();
        return;
    }
    if (StrEq(argv[1], "syscalls"))
    {
        CmdInspectSyscalls(argc, argv);
        return;
    }
    if (StrEq(argv[1], "opcodes"))
    {
        CmdInspectOpcodes(argc, argv);
        return;
    }
    if (StrEq(argv[1], "arm"))
    {
        CmdInspectArm(argc, argv);
        return;
    }
    if (StrEq(argv[1], "help"))
    {
        CmdInspectHelp();
        return;
    }
    ConsoleWrite("INSPECT: UNKNOWN SUBCOMMAND \"");
    ConsoleWrite(argv[1]);
    ConsoleWriteln("\"");
    CmdInspectHelp();
}

void CmdDumpState()
{
    // Single-shot snapshot of every major kernel subsystem's
    // counters. Lets an operator capture "what does this kernel
    // think the world looks like right now" in one log entry —
    // useful as a before/after when bisecting a flaky workload.
    duetos::arch::SerialWrite("\n=== DUETOS DUMPSTATE ===\n");

    {
        const auto s = duetos::mm::KernelHeapStatsRead();
        duetos::arch::SerialWrite("[heap] pool=");
        duetos::arch::SerialWriteHex(s.pool_bytes);
        duetos::arch::SerialWrite(" used=");
        duetos::arch::SerialWriteHex(s.used_bytes);
        duetos::arch::SerialWrite(" free=");
        duetos::arch::SerialWriteHex(s.free_bytes);
        duetos::arch::SerialWrite("\n[heap] alloc_count=");
        duetos::arch::SerialWriteHex(s.alloc_count);
        duetos::arch::SerialWrite(" free_count=");
        duetos::arch::SerialWriteHex(s.free_count);
        duetos::arch::SerialWrite(" largest_run=");
        duetos::arch::SerialWriteHex(s.largest_free_run);
        duetos::arch::SerialWrite(" free_chunks=");
        duetos::arch::SerialWriteHex(s.free_chunk_count);
        duetos::arch::SerialWrite("\n");
    }

    {
        const auto s = duetos::mm::PagingStatsRead();
        duetos::arch::SerialWrite("[paging] page_tables=");
        duetos::arch::SerialWriteHex(s.page_tables_allocated);
        duetos::arch::SerialWrite(" mapped=");
        duetos::arch::SerialWriteHex(s.mappings_installed);
        duetos::arch::SerialWrite(" unmapped=");
        duetos::arch::SerialWriteHex(s.mappings_removed);
        duetos::arch::SerialWrite(" mmio_used=");
        duetos::arch::SerialWriteHex(s.mmio_arena_used_bytes);
        duetos::arch::SerialWrite("\n");
    }

    {
        const auto s = duetos::sched::SchedStatsRead();
        duetos::arch::SerialWrite("[sched] ctx_switches=");
        duetos::arch::SerialWriteHex(s.context_switches);
        duetos::arch::SerialWrite(" live=");
        duetos::arch::SerialWriteHex(s.tasks_live);
        duetos::arch::SerialWrite(" sleeping=");
        duetos::arch::SerialWriteHex(s.tasks_sleeping);
        duetos::arch::SerialWrite(" blocked=");
        duetos::arch::SerialWriteHex(s.tasks_blocked);
        duetos::arch::SerialWrite("\n[sched] created=");
        duetos::arch::SerialWriteHex(s.tasks_created);
        duetos::arch::SerialWrite(" exited=");
        duetos::arch::SerialWriteHex(s.tasks_exited);
        duetos::arch::SerialWrite(" reaped=");
        duetos::arch::SerialWriteHex(s.tasks_reaped);
        duetos::arch::SerialWrite(" total_ticks=");
        duetos::arch::SerialWriteHex(s.total_ticks);
        duetos::arch::SerialWrite(" idle_ticks=");
        duetos::arch::SerialWriteHex(s.idle_ticks);
        duetos::arch::SerialWrite("\n");
    }

    {
        const auto& h = duetos::core::RuntimeCheckerStatusRead();
        duetos::arch::SerialWrite("[health] scans=");
        duetos::arch::SerialWriteHex(h.scans_run);
        duetos::arch::SerialWrite(" issues_total=");
        duetos::arch::SerialWriteHex(h.issues_found_total);
        duetos::arch::SerialWrite(" last_scan=");
        duetos::arch::SerialWriteHex(h.last_scan_issues);
        duetos::arch::SerialWrite(" baseline=");
        duetos::arch::SerialWrite(h.baseline_captured ? "yes" : "no");
        duetos::arch::SerialWrite("\n");
    }

    duetos::arch::SerialWrite("=== END DUMPSTATE ===\n");
    ConsoleWriteln("DUMPSTATE: WROTE TO COM1");
}

// CmdIpv4 moved to shell_network.cpp.


void CmdLoglevel(u32 argc, char** argv)
{
    if (argc < 2)
    {
        const auto cur = duetos::core::GetLogThreshold();
        ConsoleWrite("LOG THRESHOLD: ");
        switch (cur)
        {
        case duetos::core::LogLevel::Trace:
            ConsoleWriteln("TRACE (fn enter/exit + timing)");
            break;
        case duetos::core::LogLevel::Debug:
            ConsoleWriteln("DEBUG (show everything)");
            break;
        case duetos::core::LogLevel::Info:
            ConsoleWriteln("INFO");
            break;
        case duetos::core::LogLevel::Warn:
            ConsoleWriteln("WARN");
            break;
        case duetos::core::LogLevel::Error:
            ConsoleWriteln("ERROR (show only errors)");
            break;
        }
        ConsoleWriteln("USAGE: LOGLEVEL [T|D|I|W|E]");
        return;
    }
    const char c = argv[1][0];
    duetos::core::LogLevel lvl = duetos::core::LogLevel::Info;
    switch (c)
    {
    case 't':
    case 'T':
        lvl = duetos::core::LogLevel::Trace;
        break;
    case 'd':
    case 'D':
        lvl = duetos::core::LogLevel::Debug;
        break;
    case 'i':
    case 'I':
        lvl = duetos::core::LogLevel::Info;
        break;
    case 'w':
    case 'W':
        lvl = duetos::core::LogLevel::Warn;
        break;
    case 'e':
    case 'E':
        lvl = duetos::core::LogLevel::Error;
        break;
    default:
        ConsoleWriteln("LOGLEVEL: USE T / D / I / W / E");
        return;
    }
    duetos::core::SetLogThreshold(lvl);
    ConsoleWriteln("LOG THRESHOLD UPDATED");
}

void CmdLogcolor(u32 argc, char** argv)
{
    if (argc < 2)
    {
        const bool cur = duetos::core::GetLogColor();
        ConsoleWrite("SERIAL LOG COLOUR: ");
        ConsoleWriteln(cur ? "ON" : "OFF");
        ConsoleWriteln("USAGE: LOGCOLOR ON|OFF");
        return;
    }
    const char c = argv[1][0];
    const bool want = (c == 'o' || c == 'O') ? (argv[1][1] == 'n' || argv[1][1] == 'N') : false;
    // "on"  -> c='o', [1]='n'  -> true
    // "off" -> c='o', [1]='f'  -> false
    duetos::core::SetLogColor(want);
    ConsoleWrite("SERIAL LOG COLOUR: ");
    ConsoleWriteln(want ? "ON" : "OFF");
}

// Parse a hex u64 from "0x..." or bare "...". Returns false on
// any non-hex char or empty input. Local to the kdbg command
// because the shell doesn't ship a generic hex parser yet.
bool KdbgParseHex(const char* s, u64* out)
{
    if (s == nullptr || s[0] == 0)
        return false;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        s += 2;
    if (s[0] == 0)
        return false;
    u64 v = 0;
    for (u32 i = 0; s[i] != 0; ++i)
    {
        const char c = s[i];
        u8 nib = 0;
        if (c >= '0' && c <= '9')
            nib = static_cast<u8>(c - '0');
        else if (c >= 'a' && c <= 'f')
            nib = static_cast<u8>(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F')
            nib = static_cast<u8>(c - 'A' + 10);
        else
            return false;
        v = (v << 4) | nib;
    }
    *out = v;
    return true;
}

// `kdbg list` — show every channel + on/off + current mask.
// `kdbg on  <name>` / `kdbg off <name>` — toggle a single channel
// (use "all" to flip every bit).
// `kdbg mask <hex>` — set the mask outright (e.g. `kdbg mask 0x3` to
//                     enable Fat32Walker + Fat32Append).
void CmdKdbg(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("KDBG: USAGE");
        ConsoleWriteln("  KDBG LIST");
        ConsoleWriteln("  KDBG ON <CHANNEL>");
        ConsoleWriteln("  KDBG OFF <CHANNEL>");
        ConsoleWriteln("  KDBG MASK 0x<HEX>");
        ConsoleWriteln("  KDBG ON ALL  /  KDBG OFF ALL");
        return;
    }
    const char* sub = argv[1];
    if (StrEq(sub, "list"))
    {
        duetos::core::DbgListChannels();
        return;
    }
    if (StrEq(sub, "on"))
    {
        if (argc < 3)
        {
            ConsoleWriteln("KDBG ON: USE A CHANNEL NAME (OR \"ALL\")");
            return;
        }
        const auto ch = duetos::core::DbgChannelByName(argv[2]);
        if (ch == duetos::core::DbgChannel::None)
        {
            ConsoleWriteln("KDBG: UNKNOWN CHANNEL");
            return;
        }
        duetos::core::DbgEnable(static_cast<duetos::u32>(ch));
        ConsoleWriteln("KDBG: ENABLED");
        return;
    }
    if (StrEq(sub, "off"))
    {
        if (argc < 3)
        {
            ConsoleWriteln("KDBG OFF: USE A CHANNEL NAME (OR \"ALL\")");
            return;
        }
        const auto ch = duetos::core::DbgChannelByName(argv[2]);
        if (ch == duetos::core::DbgChannel::None)
        {
            ConsoleWriteln("KDBG: UNKNOWN CHANNEL");
            return;
        }
        duetos::core::DbgDisable(static_cast<duetos::u32>(ch));
        ConsoleWriteln("KDBG: DISABLED");
        return;
    }
    if (StrEq(sub, "mask"))
    {
        if (argc < 3)
        {
            ConsoleWriteln("KDBG MASK: USE 0x<HEX>");
            return;
        }
        u64 v = 0;
        if (!KdbgParseHex(argv[2], &v))
        {
            ConsoleWriteln("KDBG MASK: BAD HEX");
            return;
        }
        duetos::core::DbgSet(static_cast<duetos::u32>(v));
        ConsoleWriteln("KDBG: MASK SET");
        return;
    }
    ConsoleWriteln("KDBG: UNKNOWN SUBCOMMAND");
}

// CmdGetenv moved to shell_core.cpp.

// CmdYield / CmdUname / CmdWhoami / CmdHostname / CmdPwd /
// CmdTrue / CmdFalse moved to shell_core.cpp.

// CmdMount moved to shell_storage.cpp.

// ParseU64Str / ParseInt moved to shell_pathutil.cpp.

void CmdMetrics()
{
    // One-shot LogMetrics at Info level, tagged "shell" so the
    // origin is distinguishable from the boot-time checkpoints.
    duetos::core::LogMetrics(duetos::core::LogLevel::Info, "shell", "user-requested");
    ConsoleWriteln("(also logged to kernel ring at INFO)");
}

void CmdGuard(duetos::u32 argc, char** argv)
{
    // Show / control the security guard.
    //   guard                  status line
    //   guard on | advisory    switch to advisory mode
    //   guard enforce          switch to enforce mode (prompts on Warn/Deny)
    //   guard off              disable the guard entirely (use sparingly)
    //   guard test             re-run GuardSelfTest
    namespace sec = duetos::security;
    if (argc < 2)
    {
        ConsoleWrite("GUARD MODE   : ");
        ConsoleWriteln(sec::GuardModeName(sec::GuardMode()));
        ConsoleWrite("SCANS  : ");
        WriteU64Hex(sec::GuardScanCount(), 0);
        ConsoleWriteln("");
        ConsoleWrite("ALLOW  : ");
        WriteU64Hex(sec::GuardAllowCount(), 0);
        ConsoleWriteln("");
        ConsoleWrite("WARN   : ");
        WriteU64Hex(sec::GuardWarnCount(), 0);
        ConsoleWriteln("");
        ConsoleWrite("DENY   : ");
        WriteU64Hex(sec::GuardDenyCount(), 0);
        ConsoleWriteln("");
        const sec::Report* last = sec::GuardLastReport();
        if (last != nullptr && last->finding_count > 0)
        {
            ConsoleWrite("LAST REPORT FINDINGS: ");
            WriteU64Hex(last->finding_count, 0);
            ConsoleWriteln("");
        }
        ConsoleWriteln("USAGE: GUARD [ON|ADVISORY|ENFORCE|OFF|TEST]");
        return;
    }
    // Mutating subcommands change the kernel's security posture.
    // Status read above is harmless for non-admins (just counters),
    // but anything that flips mode or re-runs the self-test must
    // be admin-gated so a passwordless guest can't flip the guard
    // to Off and disable image-load protection.
    if (StrEq(argv[1], "on") || StrEq(argv[1], "advisory"))
    {
        if (!RequireAdmin("GUARD MODE"))
            return;
        sec::SetGuardMode(sec::Mode::Advisory);
        ConsoleWriteln("GUARD: ADVISORY (logs, never blocks)");
        return;
    }
    if (StrEq(argv[1], "enforce"))
    {
        if (!RequireAdmin("GUARD MODE"))
            return;
        sec::SetGuardMode(sec::Mode::Enforce);
        ConsoleWriteln("GUARD: ENFORCE (prompts on Warn/Deny, default-deny on timeout)");
        return;
    }
    if (StrEq(argv[1], "off"))
    {
        if (!RequireAdmin("GUARD MODE"))
            return;
        sec::SetGuardMode(sec::Mode::Off);
        ConsoleWriteln("GUARD: OFF (all images pass through)");
        return;
    }
    if (StrEq(argv[1], "test"))
    {
        if (!RequireAdmin("GUARD TEST"))
            return;
        sec::GuardSelfTest();
        ConsoleWriteln("(self-test output on COM1)");
        return;
    }
    ConsoleWriteln("GUARD: UNKNOWN SUBCOMMAND");
}

// CmdFatls / CmdFatcat / CmdFatwrite / CmdFatappend / CmdFatnew / CmdFatrm /
// CmdFattrunc / CmdFatmkdir / CmdFatrmdir moved to shell_filesystem.cpp.


void CmdLinuxexec(duetos::u32 argc, char** argv)
{
    // `linuxexec <path>` — read an ELF file from FAT32 volume 0,
    // hand the bytes to core::SpawnElfLinux, and queue the result
    // as a ring-3 task. A simple way to run "any Linux binary the
    // loader supports" once it's on disk. Accepts either a
    // volume-relative ("LINUX.ELF") or mount-prefixed
    // ("/fat/LINUX.ELF") path.
    namespace fat = duetos::fs::fat32;
    if (argc < 2)
    {
        ConsoleWriteln("LINUXEXEC: USAGE: LINUXEXEC PATH");
        return;
    }
    const char* path = argv[1];
    if (const char* leaf = FatLeaf(path); leaf != nullptr && *leaf != '\0')
    {
        path = leaf;
    }
    else if (path[0] == '/')
    {
        ++path;
    }
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
    {
        ConsoleWriteln("LINUXEXEC: FAT32 NOT MOUNTED");
        return;
    }
    fat::DirEntry entry;
    if (!fat::Fat32LookupPath(v, path, &entry))
    {
        ConsoleWrite("LINUXEXEC: NO SUCH FILE: ");
        ConsoleWriteln(path);
        return;
    }
    if (entry.attributes & 0x10)
    {
        ConsoleWriteln("LINUXEXEC: PATH IS A DIRECTORY");
        return;
    }
    // 16 KiB cap fits the v0 smoke ELF (~260 B) with plenty of
    // headroom. Larger binaries will hit the cap — expand once a
    // non-trivial musl program needs more.
    static duetos::u8 elf_buf[16384];
    const duetos::i64 n = fat::Fat32ReadFile(v, &entry, elf_buf, sizeof(elf_buf));
    if (n <= 0)
    {
        ConsoleWriteln("LINUXEXEC: READ ERROR OR EMPTY");
        return;
    }
    const duetos::u64 pid = duetos::core::SpawnElfLinux("linuxexec", elf_buf, static_cast<duetos::u64>(n),
                                                        duetos::core::CapSetEmpty(), duetos::fs::RamfsSandboxRoot(),
                                                        /*frame_budget=*/16, duetos::core::kTickBudgetSandbox);
    if (pid == 0)
    {
        ConsoleWriteln("LINUXEXEC: SPAWNELFLINUX FAILED");
        return;
    }
    ConsoleWrite("LINUXEXEC: SPAWNED PID=");
    WriteU64Dec(pid);
    ConsoleWrite(" PATH=");
    ConsoleWriteln(path);
}

void CmdTranslate()
{
    // `translate` — print the ABI translation unit's hit tables.
    // One row per bucket that has fired at least once, split by
    // direction. Buckets are syscall_nr & 0x3FF; overlaps between
    // Linux's wide numbering and native's narrow numbering are
    // rare enough to keep the 1024-slot scheme.
    namespace tx = duetos::subsystems::translation;
    const auto& linux = tx::LinuxHitsRead();
    const auto& native = tx::NativeHitsRead();
    ConsoleWriteln("TRANSLATION UNIT HIT TABLE");
    ConsoleWriteln("  DIR     NR     HITS");
    for (duetos::u32 i = 0; i < 1024; ++i)
    {
        if (linux.buckets[i] == 0)
            continue;
        ConsoleWrite("  linux   0x");
        WriteU64Hex(i, 3);
        ConsoleWrite("  ");
        WriteU64Dec(linux.buckets[i]);
        ConsoleWriteln("");
    }
    for (duetos::u32 i = 0; i < 1024; ++i)
    {
        if (native.buckets[i] == 0)
            continue;
        ConsoleWrite("  native  0x");
        WriteU64Hex(i, 3);
        ConsoleWrite("  ");
        WriteU64Dec(native.buckets[i]);
        ConsoleWriteln("");
    }
    ConsoleWriteln("-- end --");
}

void CmdRead(duetos::u32 argc, char** argv)
{
    // `read <handle> <lba> [count]` — reads up to one page (4096 B)
    // from the given block device and hexdumps it to the console.
    // Lets a user verify driver reads end-to-end without writing a
    // program. Parses handle/LBA as decimal or hex (0x prefix).
    if (argc < 3)
    {
        ConsoleWriteln("READ: USAGE: READ HANDLE LBA [COUNT]");
        ConsoleWriteln("      (count in sectors, default 1, max = 4096/sector_size)");
        return;
    }
    namespace storage = duetos::drivers::storage;
    duetos::u64 handle_u64 = 0;
    duetos::u64 lba = 0;
    duetos::u64 count = 1;
    if (!ParseU64Str(argv[1], &handle_u64) || handle_u64 >= 0x100000000ULL)
    {
        ConsoleWriteln("READ: BAD HANDLE");
        return;
    }
    if (!ParseU64Str(argv[2], &lba))
    {
        ConsoleWriteln("READ: BAD LBA");
        return;
    }
    if (argc >= 4 && !ParseU64Str(argv[3], &count))
    {
        ConsoleWriteln("READ: BAD COUNT");
        return;
    }
    const duetos::u32 handle = static_cast<duetos::u32>(handle_u64);
    const duetos::u32 ssize = storage::BlockDeviceSectorSize(handle);
    if (ssize == 0)
    {
        ConsoleWriteln("READ: INVALID HANDLE (no such block device)");
        return;
    }
    const duetos::u32 max_count = 4096u / ssize;
    if (count == 0 || count > max_count)
    {
        ConsoleWrite("READ: COUNT OUT OF RANGE (max ");
        WriteU64Hex(max_count, 0);
        ConsoleWriteln(")");
        return;
    }
    static duetos::u8 buf[4096];
    for (duetos::u64 i = 0; i < 4096; ++i)
        buf[i] = 0;
    if (storage::BlockDeviceRead(handle, lba, static_cast<duetos::u32>(count), buf) != 0)
    {
        ConsoleWriteln("READ: DRIVER RETURNED ERROR");
        return;
    }
    const duetos::u32 bytes = static_cast<duetos::u32>(count) * ssize;
    ConsoleWrite("READ ");
    WriteU64Hex(bytes, 0);
    ConsoleWrite(" BYTES FROM HANDLE ");
    WriteU64Hex(handle, 0);
    ConsoleWrite(" LBA ");
    WriteU64Hex(lba, 0);
    ConsoleWriteln(":");
    // Classic 16-byte hex + ASCII rows, mirroring CmdHexdump.
    for (duetos::u32 row = 0; row < bytes; row += 16)
    {
        WriteU64Hex(row, 8);
        ConsoleWrite("  ");
        for (duetos::u32 i = 0; i < 16; ++i)
        {
            if (row + i < bytes)
                WriteU64Hex(buf[row + i], 2);
            else
                ConsoleWrite("  ");
            ConsoleWriteChar(' ');
            if (i == 7)
                ConsoleWriteChar(' ');
        }
        ConsoleWrite(" |");
        for (duetos::u32 i = 0; i < 16 && row + i < bytes; ++i)
        {
            const char c = static_cast<char>(buf[row + i]);
            ConsoleWriteChar((c >= 0x20 && c <= 0x7E) ? c : '.');
        }
        ConsoleWriteln("|");
    }
}

void CmdTrace(duetos::u32 argc, char** argv)
{
    // `trace`              — show current threshold + in-flight scopes
    // `trace on` / `trace off` — shortcut for loglevel t / i
    if (argc < 2)
    {
        const auto cur = duetos::core::GetLogThreshold();
        ConsoleWrite("TRACE THRESHOLD: ");
        ConsoleWriteln(cur == duetos::core::LogLevel::Trace ? "ON" : "OFF");
        ConsoleWriteln("(IN-FLIGHT SCOPES LOGGED TO SERIAL BELOW)");
        duetos::core::DumpInflightScopes();
        ConsoleWriteln("USAGE: TRACE [ON|OFF]");
        return;
    }
    if (argv[1][0] == 'o' && (argv[1][1] == 'n' || argv[1][1] == 'N'))
    {
        duetos::core::SetLogThreshold(duetos::core::LogLevel::Trace);
        ConsoleWriteln("TRACE ON (threshold = TRACE)");
    }
    else if (argv[1][0] == 'o' && (argv[1][1] == 'f' || argv[1][1] == 'F'))
    {
        duetos::core::SetLogThreshold(duetos::core::LogLevel::Info);
        ConsoleWriteln("TRACE OFF (threshold = INFO)");
    }
    else
    {
        ConsoleWriteln("TRACE: USE ON|OFF");
    }
}

// CmdLsblk / CmdLsgpt / CmdLsmod moved to shell_storage.cpp.

// SchedStateName moved to shell_process.cpp alongside its only
// callers (CmdPs, CmdTop).

void CmdKill(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("KILL: USAGE: KILL PID");
        return;
    }
    u64 pid = 0;
    for (u32 i = 0; argv[1][i] != '\0'; ++i)
    {
        if (argv[1][i] < '0' || argv[1][i] > '9')
        {
            ConsoleWriteln("KILL: BAD PID");
            return;
        }
        pid = pid * 10 + static_cast<u64>(argv[1][i] - '0');
    }
    const auto r = duetos::sched::SchedKillByPid(pid);
    switch (r)
    {
    case duetos::sched::KillResult::Signaled:
        ConsoleWrite("KILL: SIGNALED PID ");
        WriteU64Dec(pid);
        ConsoleWriteln(" (WILL DIE ON NEXT SCHEDULE)");
        break;
    case duetos::sched::KillResult::NotFound:
        ConsoleWrite("KILL: NO SUCH PID: ");
        WriteU64Dec(pid);
        ConsoleWriteChar('\n');
        break;
    case duetos::sched::KillResult::Protected:
        ConsoleWrite("KILL: PID ");
        WriteU64Dec(pid);
        ConsoleWriteln(" IS PROTECTED (idle/reaper/boot)");
        break;
    case duetos::sched::KillResult::AlreadyDead:
        ConsoleWrite("KILL: PID ");
        WriteU64Dec(pid);
        ConsoleWriteln(" IS ALREADY DEAD");
        break;
    case duetos::sched::KillResult::Blocked:
        ConsoleWrite("KILL: PID ");
        WriteU64Dec(pid);
        ConsoleWriteln(" IS BLOCKED — FLAGGED, WILL DIE WHEN WOKEN");
        break;
    }
}

void CmdSpawn(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("SPAWN: USAGE: SPAWN <KIND>");
        ConsoleWriteln("  KINDS:  hello  sandbox  jail  nx  hog  hostile  dropcaps  priv  badint");
        ConsoleWriteln("          kread  ptrfuzz  writefuzz  hellope  winkill  winhello");
        ConsoleWriteln("  SEE `MAN SPAWN` FOR DETAILS.");
        return;
    }
    if (!duetos::core::SpawnOnDemand(argv[1]))
    {
        ConsoleWrite("SPAWN: UNKNOWN KIND: ");
        ConsoleWriteln(argv[1]);
        ConsoleWriteln("  KINDS:  hello  sandbox  jail  nx  hog  hostile  dropcaps  priv  badint");
        ConsoleWriteln("          kread  ptrfuzz  writefuzz  hellope  winkill  winhello");
        return;
    }
    ConsoleWrite("SPAWN: QUEUED ");
    ConsoleWriteln(argv[1]);
    ConsoleWriteln("  (RUN `PS` TO SEE IT, OR WATCH THE KERNEL LOG)");
}

// Little-endian u16/u32/u64 readers — the ELF parser walks
// raw bytes, so we don't rely on alignment or struct packing.
u16 LeU16(const u8* p)
{
    return u16(p[0]) | (u16(p[1]) << 8);
}
u32 LeU32(const u8* p)
{
    return u32(p[0]) | (u32(p[1]) << 8) | (u32(p[2]) << 16) | (u32(p[3]) << 24);
}
u64 LeU64(const u8* p)
{
    u64 lo = LeU32(p);
    u64 hi = LeU32(p + 4);
    return lo | (hi << 32);
}

const char* ElfTypeName(u16 t)
{
    switch (t)
    {
    case 0:
        return "NONE";
    case 1:
        return "REL";
    case 2:
        return "EXEC";
    case 3:
        return "DYN (shared or PIE)";
    case 4:
        return "CORE";
    default:
        return "OTHER";
    }
}

const char* ElfMachineName(u16 m)
{
    switch (m)
    {
    case 0x00:
        return "none";
    case 0x03:
        return "x86 (i386)";
    case 0x28:
        return "arm";
    case 0x3E:
        return "x86_64";
    case 0xB7:
        return "aarch64";
    case 0xF3:
        return "riscv";
    default:
        return "unknown";
    }
}

const char* ElfPtypeName(u32 t)
{
    switch (t)
    {
    case 0:
        return "NULL";
    case 1:
        return "LOAD";
    case 2:
        return "DYNAMIC";
    case 3:
        return "INTERP";
    case 4:
        return "NOTE";
    case 5:
        return "SHLIB";
    case 6:
        return "PHDR";
    case 7:
        return "TLS";
    case 0x6474E550:
        return "GNU_EH_FRAME";
    case 0x6474E551:
        return "GNU_STACK";
    case 0x6474E552:
        return "GNU_RELRO";
    default:
        return "OTHER";
    }
}

// ParseHex32 moved to shell_pathutil.cpp.

// CmdColor / CmdRand moved to shell_utilities.cpp.

void CmdAttackSim()
{
    duetos::security::AttackSimRun();
    const auto& s = duetos::security::AttackSimSummary();
    ConsoleWrite("ATTACK SIM COMPLETE: ");
    WriteU64Dec(s.passed);
    ConsoleWrite(" passed, ");
    WriteU64Dec(s.failed);
    ConsoleWrite(" failed, ");
    WriteU64Dec(s.skipped);
    ConsoleWriteln(" skipped");
    for (u64 i = 0; i < s.count; ++i)
    {
        ConsoleWrite("  [");
        ConsoleWrite(duetos::security::AttackOutcomeName(s.results[i].outcome));
        ConsoleWrite("] ");
        ConsoleWrite(s.results[i].name);
        ConsoleWrite(" -> ");
        ConsoleWriteln(s.results[i].detector);
    }
}

// CmdUuid moved to shell_utilities.cpp.

// CmdFlushTlb moved to shell_utilities.cpp.

// CmdChecksum moved to shell_utilities.cpp.

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

// CmdSleep moved to shell_utilities.cpp.

// CmdReset / CmdTac / CmdNl / CmdRev moved to shell_utilities.cpp.

// ParseI64 / WriteI64Dec moved to shell_pathutil.cpp +
// shell_format.cpp.

// CmdExpr / CmdHexdump / CmdStat moved to shell_utilities.cpp.

// CmdBasename / CmdDirname moved to shell_utilities.cpp.

// CmdCal moved to shell_utilities.cpp.

void CmdExec(u32 argc, char** argv)
{
    // Dry-run version of the ELF loader: validates the file and
    // prints the load plan (one line per PT_LOAD) — no actual
    // spawn yet. Once SYS_SPAWN lands, this becomes the mouth
    // of that pipeline.
    if (argc < 2)
    {
        ConsoleWriteln("EXEC: USAGE: EXEC PATH   (dry-run ELF loader)");
        return;
    }
    char scratch[duetos::fs::kTmpFsContentMax];
    const u32 n = ReadFileToBuf(argv[1], scratch, sizeof(scratch));
    if (n == static_cast<u32>(-1))
    {
        ConsoleWrite("EXEC: NO SUCH FILE: ");
        ConsoleWriteln(argv[1]);
        return;
    }
    const u8* file = reinterpret_cast<const u8*>(scratch);
    const duetos::core::ElfStatus st = duetos::core::ElfValidate(file, n);
    if (st != duetos::core::ElfStatus::Ok)
    {
        ConsoleWrite("EXEC: INVALID ELF: ");
        ConsoleWriteln(duetos::core::ElfStatusName(st));
        return;
    }
    ConsoleWrite("EXEC: OK. ENTRY = ");
    WriteU64Hex(duetos::core::ElfEntry(file));
    ConsoleWriteChar('\n');
    ConsoleWriteln("LOAD PLAN:");
    ConsoleWriteln("  VADDR             FILESZ    MEMSZ     FLAGS   FILE-OFFSET");
    struct Cookie
    {
        u32 count;
    };
    Cookie cookie{0};
    const u32 visited = duetos::core::ElfForEachPtLoad(
        file, n,
        [](const duetos::core::ElfSegment& seg, void* ck)
        {
            auto* c = static_cast<Cookie*>(ck);
            ++c->count;
            ConsoleWrite("  ");
            WriteU64Hex(seg.vaddr);
            ConsoleWrite("  ");
            WriteU64Hex(seg.filesz, 8);
            ConsoleWrite("  ");
            WriteU64Hex(seg.memsz, 8);
            ConsoleWrite("  ");
            ConsoleWriteChar((seg.flags & duetos::core::kElfPfR) ? 'R' : '-');
            ConsoleWriteChar((seg.flags & duetos::core::kElfPfW) ? 'W' : '-');
            ConsoleWriteChar((seg.flags & duetos::core::kElfPfX) ? 'X' : '-');
            ConsoleWrite("     ");
            WriteU64Hex(seg.file_offset, 8);
            ConsoleWriteChar('\n');
        },
        &cookie);
    ConsoleWrite("EXEC: ");
    WriteU64Dec(visited);
    ConsoleWriteln(" PT_LOAD SEGMENTS.");

    // Real spawn: ElfLoad + ProcessCreate + SchedCreateUser.
    // Inherits the shell's (kernel-task) default cap posture for
    // now — every manually-exec'd binary gets trusted caps +
    // the trusted ramfs root. When SYS_SPAWN arrives, ring-3
    // callers will inherit their own.
    const u64 new_pid =
        duetos::core::SpawnElfFile(argv[1], file, n, duetos::core::CapSetTrusted(), duetos::fs::RamfsTrustedRoot(),
                                   duetos::mm::kFrameBudgetTrusted, duetos::core::kTickBudgetTrusted);
    if (new_pid == 0)
    {
        ConsoleWriteln("EXEC: SPAWN FAILED (OOM or bad ELF layout).");
        return;
    }
    ConsoleWrite("EXEC: SPAWN pid=");
    WriteU64Dec(new_pid);
    ConsoleWriteln(" queued.");
    ConsoleWriteln("EXEC: (use `ps` to observe, kernel log for entry line.)");
}

void CmdReadelf(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("READELF: USAGE: READELF PATH");
        return;
    }
    char scratch[duetos::fs::kTmpFsContentMax];
    const u32 n = ReadFileToBuf(argv[1], scratch, sizeof(scratch));
    if (n == static_cast<u32>(-1))
    {
        ConsoleWrite("READELF: NO SUCH FILE: ");
        ConsoleWriteln(argv[1]);
        return;
    }
    if (n < 64)
    {
        ConsoleWriteln("READELF: FILE TOO SMALL FOR AN ELF HEADER");
        return;
    }
    const u8* b = reinterpret_cast<const u8*>(scratch);
    if (!(b[0] == 0x7F && b[1] == 'E' && b[2] == 'L' && b[3] == 'F'))
    {
        ConsoleWriteln("READELF: NOT AN ELF FILE (BAD MAGIC)");
        return;
    }
    const u8 ei_class = b[4];
    const u8 ei_data = b[5];
    if (ei_class != 2)
    {
        ConsoleWriteln("READELF: NOT ELF64 (ei_class != 2)");
        return;
    }
    if (ei_data != 1)
    {
        ConsoleWriteln("READELF: NOT LITTLE-ENDIAN (ei_data != 1)");
        return;
    }
    ConsoleWriteln("-- ELF HEADER --");
    ConsoleWrite("  CLASS:      ELF64\n");
    ConsoleWrite("  DATA:       LSB\n");
    ConsoleWrite("  VERSION:    ");
    WriteU64Dec(b[6]);
    ConsoleWriteChar('\n');
    ConsoleWrite("  OSABI:      ");
    WriteU64Dec(b[7]);
    ConsoleWriteChar('\n');
    const u16 e_type = LeU16(b + 16);
    ConsoleWrite("  TYPE:       ");
    WriteU64Hex(e_type, 4);
    ConsoleWrite("  (");
    ConsoleWrite(ElfTypeName(e_type));
    ConsoleWriteln(")");
    const u16 e_machine = LeU16(b + 18);
    ConsoleWrite("  MACHINE:    ");
    WriteU64Hex(e_machine, 4);
    ConsoleWrite("  (");
    ConsoleWrite(ElfMachineName(e_machine));
    ConsoleWriteln(")");
    const u64 e_entry = LeU64(b + 24);
    ConsoleWrite("  ENTRY:      ");
    WriteU64Hex(e_entry);
    ConsoleWriteChar('\n');
    const u64 e_phoff = LeU64(b + 32);
    const u64 e_shoff = LeU64(b + 40);
    ConsoleWrite("  PHOFF:      ");
    WriteU64Dec(e_phoff);
    ConsoleWrite("   SHOFF: ");
    WriteU64Dec(e_shoff);
    ConsoleWriteChar('\n');
    const u16 e_phentsize = LeU16(b + 54);
    const u16 e_phnum = LeU16(b + 56);
    const u16 e_shentsize = LeU16(b + 58);
    const u16 e_shnum = LeU16(b + 60);
    ConsoleWrite("  PHDRS:      ");
    WriteU64Dec(e_phnum);
    ConsoleWrite(" x ");
    WriteU64Dec(e_phentsize);
    ConsoleWrite(" bytes");
    ConsoleWriteChar('\n');
    ConsoleWrite("  SHDRS:      ");
    WriteU64Dec(e_shnum);
    ConsoleWrite(" x ");
    WriteU64Dec(e_shentsize);
    ConsoleWrite(" bytes");
    ConsoleWriteChar('\n');

    // Walk PT_LOAD (and any other) program headers.
    if (e_phnum == 0 || e_phentsize < 56 || e_phoff == 0)
    {
        return;
    }
    ConsoleWriteln("-- PROGRAM HEADERS --");
    ConsoleWriteln("   TYPE       FLAGS  OFFSET           VADDR            FILESZ    MEMSZ     ALIGN");
    for (u16 i = 0; i < e_phnum; ++i)
    {
        const u64 off = e_phoff + static_cast<u64>(i) * e_phentsize;
        if (off + 56 > n)
        {
            ConsoleWriteln("  <TRUNCATED>");
            break;
        }
        const u8* p = b + off;
        const u32 p_type = LeU32(p + 0);
        const u32 p_flags = LeU32(p + 4);
        const u64 p_offset = LeU64(p + 8);
        const u64 p_vaddr = LeU64(p + 16);
        // p_paddr = LeU64(p + 24) — skipped
        const u64 p_filesz = LeU64(p + 32);
        const u64 p_memsz = LeU64(p + 40);
        const u64 p_align = LeU64(p + 48);
        ConsoleWrite("  ");
        // Type — left-justify name to 10 cols.
        const char* tn = ElfPtypeName(p_type);
        ConsoleWrite(tn);
        for (u32 k = 0; k < 12; ++k)
        {
            if (tn[k] == '\0')
            {
                for (u32 j = k; j < 12; ++j)
                    ConsoleWriteChar(' ');
                break;
            }
        }
        // Flags as 3-char RWE.
        ConsoleWriteChar((p_flags & 4) ? 'R' : '-'); // PF_R
        ConsoleWriteChar((p_flags & 2) ? 'W' : '-'); // PF_W
        ConsoleWriteChar((p_flags & 1) ? 'X' : '-'); // PF_X
        ConsoleWrite("    ");
        WriteU64Hex(p_offset);
        ConsoleWrite(" ");
        WriteU64Hex(p_vaddr);
        ConsoleWrite(" ");
        WriteU64Hex(p_filesz, 8);
        ConsoleWrite("  ");
        WriteU64Hex(p_memsz, 8);
        ConsoleWrite("  ");
        WriteU64Hex(p_align, 5);
        ConsoleWriteChar('\n');
    }
}

// CmdPs / CmdTop / CmdFree moved to shell_process.cpp.

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

// CmdBeep moved to shell_utilities.cpp.

// CmdShutdownNow / CmdHistory / CmdMem / CmdMode moved to
// shell_utilities.cpp.

// TmpLeaf / FatLeaf moved to shell_pathutil.cpp.

// CmdEcho moved to shell_filesystem.cpp.

// CmdLs / CmdCat / CmdTouch / CmdRm moved to shell_filesystem.cpp.
// LsTmpDir moved with them.

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

// HistoryExpand moved to shell_state.cpp.

// ---------------------------------------------------------------
// Account management commands — useradd / userdel / passwd /
// users / login / logout / su — moved to shell_security.cpp.
// ---------------------------------------------------------------


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

} // namespace

void ShellInit()
{
    ConsoleWriteln("");

    // Print /etc/motd if present — human-facing welcome text,
    // replaces the tiny "DUETOS SHELL" banner the earlier
    // version used. If the file is missing (e.g. a stripped
    // sandbox tree), fall back to the minimum one-liner.
    char scratch[duetos::fs::kTmpFsContentMax];
    const u32 motd_len = ReadFileToBuf("/etc/motd", scratch, sizeof(scratch));
    if (motd_len != static_cast<u32>(-1))
    {
        for (u32 i = 0; i < motd_len; ++i)
        {
            ConsoleWriteChar(scratch[i]);
        }
        if (motd_len == 0 || scratch[motd_len - 1] != '\n')
        {
            ConsoleWriteChar('\n');
        }
    }
    else
    {
        ConsoleWriteln("DUETOS SHELL v0   TYPE HELP FOR COMMANDS.");
    }

    // Auto-source /etc/profile. Effect is identical to the user
    // running `source /etc/profile` manually — sets any boot-time
    // aliases / prompt / env vars the distribution wants. Silent
    // no-op if the file doesn't exist.
    char profile_line[] = "/etc/profile";
    char* argv[2] = {nullptr, profile_line};
    const char* bytes = nullptr;
    u32 plen = 0;
    const auto* prof = duetos::fs::VfsLookup(duetos::fs::RamfsTrustedRoot(), "/etc/profile", 64);
    if (prof != nullptr && prof->type == duetos::fs::RamfsNodeType::kFile)
    {
        (void)bytes;
        (void)plen;
        CmdSource(2, argv);
    }

    Prompt();
}

void ShellFeedChar(char c)
{
    if (c < 0x20 || c > 0x7E)
    {
        return; // non-printable ignored — Enter/Backspace have dedicated entries
    }
    if (g_len + 1 >= kInputMax)
    {
        return; // buffer full — silently drop trailing input
    }
    g_input[g_len++] = c;
    ConsoleWriteChar(c);
}

void ShellBackspace()
{
    if (g_len == 0)
    {
        return;
    }
    --g_len;
    g_input[g_len] = '\0';
    ConsoleWriteChar('\b');
}

void ShellSubmit()
{
    g_input[g_len] = '\0';
    ConsoleWriteChar('\n');
    HistoryPush(g_input);
    g_history_cursor = 0;
    Dispatch(g_input);
    g_len = 0;
    g_input[0] = '\0';
    Prompt();
}

u32 ShellHistoryCount()
{
    return g_history_count;
}

const char* ShellHistoryGet(u32 n)
{
    return HistoryAt(n);
}

void ShellHistoryPrev()
{
    if (g_history_count == 0)
    {
        return;
    }
    if (g_history_cursor >= g_history_count)
    {
        return; // already at the oldest entry
    }
    ++g_history_cursor;
    ReplaceLine(HistoryAt(g_history_cursor));
}

void ShellHistoryNext()
{
    if (g_history_cursor == 0)
    {
        return; // already at the live prompt
    }
    --g_history_cursor;
    if (g_history_cursor == 0)
    {
        ReplaceLine(nullptr); // back to empty live line
        return;
    }
    ReplaceLine(HistoryAt(g_history_cursor));
}

// Extend the edit buffer with the tail of `text` starting at
// offset `from`, optionally followed by a single `trailer`
// character. Echoes each byte to the console. Caps at kInputMax
// silently. Used by both command-name and path completion.
void ExtendLine(const char* text, u32 from, char trailer)
{
    u32 i = g_len;
    while (text[from] != '\0' && i + 1 < kInputMax)
    {
        g_input[i] = text[from];
        ConsoleWriteChar(text[from]);
        ++i;
        ++from;
    }
    if (trailer != '\0' && i + 1 < kInputMax)
    {
        g_input[i] = trailer;
        ConsoleWriteChar(trailer);
        ++i;
    }
    g_len = i;
    g_input[g_len] = '\0';
}

// True iff `name` starts with the first `plen` bytes of `prefix`
// (or `plen == 0`, in which case everything matches).
bool NamePrefixMatch(const char* name, const char* prefix, u32 plen)
{
    for (u32 i = 0; i < plen; ++i)
    {
        if (name[i] == '\0' || name[i] != prefix[i])
        {
            return false;
        }
    }
    return true;
}

void CompleteCommandName()
{
    constexpr u32 kCmdCount = kCommandCount;

    const char* match = nullptr;
    u32 match_count = 0;
    for (u32 i = 0; i < kCmdCount; ++i)
    {
        if (StrStartsWith(kCommandSet[i], g_input))
        {
            match = kCommandSet[i];
            ++match_count;
        }
    }
    if (match_count == 0)
    {
        return;
    }
    if (match_count == 1)
    {
        ExtendLine(match, g_len, ' ');
        return;
    }
    ConsoleWriteChar('\n');
    for (u32 i = 0; i < kCmdCount; ++i)
    {
        if (StrStartsWith(kCommandSet[i], g_input))
        {
            ConsoleWrite("  ");
            ConsoleWriteln(kCommandSet[i]);
        }
    }
    Prompt();
    ConsoleWrite(g_input);
}

// Walk-time candidate record used by the path completer. A
// candidate is either a ramfs node (borrowed pointer) or a
// tmpfs slot (name + isdir=false). We decouple from the
// backing storage so /tmp entries and static entries can
// both be matched in the same sweep.
struct CompleteCandidate
{
    const char* name;
    bool is_dir;
};

// Cap matches what a human can usefully scan and matches
// kTmpFsSlotCount + a handful of static entries.
constexpr u32 kCompleteMax = 24;

struct CompleteCollector
{
    CompleteCandidate items[kCompleteMax];
    u32 count;
    const char* leaf;
    u32 leaf_len;
};

// Complete an absolute path in the tail of the edit buffer. The
// `partial_start` argument is the index into g_input where the
// path begins (first char AFTER the separating whitespace).
// Leading character MUST be '/' for v0 — relative-path support
// lands with a CWD concept.
void CompletePath(u32 partial_start)
{
    const u32 partial_len = g_len - partial_start;
    if (partial_len == 0 || g_input[partial_start] != '/')
    {
        return;
    }
    u32 last_slash = 0;
    for (u32 i = 0; i < partial_len; ++i)
    {
        if (g_input[partial_start + i] == '/')
        {
            last_slash = i;
        }
    }
    char parent_buf[96];
    if (last_slash == 0)
    {
        parent_buf[0] = '/';
        parent_buf[1] = '\0';
    }
    else
    {
        u32 j = 0;
        for (; j < last_slash && j + 1 < sizeof(parent_buf); ++j)
        {
            parent_buf[j] = g_input[partial_start + j];
        }
        parent_buf[j] = '\0';
    }

    const char* leaf = &g_input[partial_start + last_slash + 1];
    const u32 leaf_len = partial_len - last_slash - 1;

    // Don't value-init the whole struct — `col{}` on a 400-
    // byte local emits a memset call, which doesn't exist in
    // this freestanding environment. Only `count` needs to
    // start at 0; `items[]` entries are written before read.
    CompleteCollector col;
    col.count = 0;
    col.leaf = leaf;
    col.leaf_len = leaf_len;

    // Populate candidates from the appropriate backing. /tmp is
    // the writable tier; everything else is the static ramfs;
    // root additionally surfaces a synthetic "tmp/" entry so
    // Tab at / yields both worlds.
    if (StrEq(parent_buf, "/tmp"))
    {
        auto cb = [](const char* name, u32 /*len*/, void* cookie)
        {
            auto* c = static_cast<CompleteCollector*>(cookie);
            if (c->count >= kCompleteMax)
                return;
            if (!NamePrefixMatch(name, c->leaf, c->leaf_len))
                return;
            c->items[c->count].name = name;
            c->items[c->count].is_dir = false;
            ++c->count;
        };
        duetos::fs::TmpFsEnumerate(cb, &col);
    }
    else
    {
        const auto* root = duetos::fs::RamfsTrustedRoot();
        const auto* parent = duetos::fs::VfsLookup(root, parent_buf, sizeof(parent_buf));
        if (parent == nullptr || parent->type != duetos::fs::RamfsNodeType::kDir || parent->children == nullptr)
        {
            return;
        }
        for (u32 i = 0; parent->children[i] != nullptr && col.count < kCompleteMax; ++i)
        {
            const auto* c = parent->children[i];
            if (!NamePrefixMatch(c->name, leaf, leaf_len))
                continue;
            col.items[col.count].name = c->name;
            col.items[col.count].is_dir = (c->type == duetos::fs::RamfsNodeType::kDir);
            ++col.count;
        }
        // Root also offers "tmp/" as a completion target — the
        // tmpfs mount point isn't a static ramfs child.
        if (StrEq(parent_buf, "/"))
        {
            const char* synth = "tmp";
            if (NamePrefixMatch(synth, leaf, leaf_len) && col.count < kCompleteMax)
            {
                col.items[col.count].name = synth;
                col.items[col.count].is_dir = true;
                ++col.count;
            }
        }
    }

    if (col.count == 0)
    {
        return;
    }
    if (col.count == 1)
    {
        const char trailer = col.items[0].is_dir ? '/' : ' ';
        ExtendLine(col.items[0].name, leaf_len, trailer);
        return;
    }
    ConsoleWriteChar('\n');
    for (u32 i = 0; i < col.count; ++i)
    {
        ConsoleWrite("  ");
        ConsoleWrite(col.items[i].name);
        if (col.items[i].is_dir)
        {
            ConsoleWriteln("/");
        }
        else
        {
            ConsoleWriteChar('\n');
        }
    }
    Prompt();
    ConsoleWrite(g_input);
}

void ShellInterrupt()
{
    g_interrupt = true;
}

bool ShellInterruptRequested()
{
    if (g_interrupt)
    {
        g_interrupt = false;
        return true;
    }
    return false;
}

void ShellTabComplete()
{
    if (g_len == 0)
    {
        return;
    }
    g_input[g_len] = '\0';

    // Split the buffer at the FIRST whitespace. If there isn't
    // one, this is command-name completion. Otherwise the first
    // token is a command name and we complete the last token as
    // a path — but only for commands that take a path.
    u32 first_ws = 0;
    bool has_ws = false;
    for (u32 i = 0; i < g_len; ++i)
    {
        if (g_input[i] == ' ' || g_input[i] == '\t')
        {
            first_ws = i;
            has_ws = true;
            break;
        }
    }
    if (!has_ws)
    {
        CompleteCommandName();
        return;
    }

    // Find the LAST whitespace so we know where the last token
    // begins. That's the token we're completing.
    u32 last_ws = first_ws;
    for (u32 i = first_ws + 1; i < g_len; ++i)
    {
        if (g_input[i] == ' ' || g_input[i] == '\t')
        {
            last_ws = i;
        }
    }

    // Temporarily terminate the first token so StrEq can read it.
    const char saved = g_input[first_ws];
    g_input[first_ws] = '\0';
    const bool path_cmd =
        StrEq(g_input, "ls") || StrEq(g_input, "cat") || StrEq(g_input, "touch") || StrEq(g_input, "rm") ||
        StrEq(g_input, "cp") || StrEq(g_input, "mv") || StrEq(g_input, "wc") || StrEq(g_input, "head") ||
        StrEq(g_input, "tail") || StrEq(g_input, "source") || StrEq(g_input, "grep") || StrEq(g_input, "sort") ||
        StrEq(g_input, "uniq") || StrEq(g_input, "readelf") || StrEq(g_input, "hexdump") || StrEq(g_input, "stat") ||
        StrEq(g_input, "tac") || StrEq(g_input, "nl") || StrEq(g_input, "rev") || StrEq(g_input, "checksum");
    g_input[first_ws] = saved;

    if (path_cmd)
    {
        CompletePath(last_ws + 1);
    }
}

} // namespace duetos::core
