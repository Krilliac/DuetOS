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
// HistoryAt / HistoryExpand) and the live input buffer (g_input /
// g_len / g_interrupt + ReplaceLine) live in shell_state.cpp.

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
// RequireAdmin moved to shell_security.cpp.

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

// CmdDmesg / CmdStats moved to shell_utilities.cpp.


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

// CmdSeq moved to shell_utilities.cpp.


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

// CmdMan moved to shell_utilities.cpp.


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


// CmdHealth / CmdLoglevel / CmdLogcolor / CmdKdbg / CmdMetrics moved
// to shell_debug.cpp. KdbgParseHex was redundant with the hoisted
// ParseU64Str and removed.


// CmdGuard moved to shell_security.cpp.


// CmdFatls / CmdFatcat / CmdFatwrite / CmdFatappend / CmdFatnew / CmdFatrm /
// CmdFattrunc / CmdFatmkdir / CmdFatrmdir moved to shell_filesystem.cpp.


// CmdLinuxexec / CmdTranslate / CmdRead moved to shell_exec.cpp.


// CmdTrace moved to shell_debug.cpp.


// CmdLsblk / CmdLsgpt / CmdLsmod moved to shell_storage.cpp.

// SchedStateName moved to shell_process.cpp alongside its only
// callers (CmdPs, CmdTop).

// CmdKill / CmdSpawn moved to shell_process.cpp.

// LeU16 / LeU32 / LeU64 / ElfTypeName / ElfMachineName / ElfPtypeName moved to shell_exec.cpp.


// ParseHex32 moved to shell_pathutil.cpp.

// CmdColor / CmdRand moved to shell_utilities.cpp.

// CmdAttackSim moved to shell_security.cpp.


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

// CmdExec / CmdReadelf moved to shell_exec.cpp.


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
