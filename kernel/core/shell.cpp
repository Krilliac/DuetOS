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

constexpr u32 kInputMax = 64;
constinit char g_input[kInputMax] = {};
constinit u32 g_len = 0;

// Latched Ctrl+C flag. Long-running commands poll via
// ShellInterruptRequested; the kbd reader flips it on from
// the Ctrl+C hotkey. Read/clear is atomic at word granularity
// on x86_64, which is good enough for the kbd-reader + shell-
// task single-producer / single-consumer pattern.
constinit bool g_interrupt = false;

// Command history. Ring buffer of the last `kHistoryCap`
// submitted lines. g_history_count saturates at the cap; newest
// entry lives at ((head - 1) mod cap). g_history_cursor is the
// recall index — 0 == "at the live prompt" (no recall), 1 == the
// most recent entry, etc. Walking Up goes back in history;
// Down walks forward until we reach the live prompt.
constexpr u32 kHistoryCap = 8;
constinit char g_history[kHistoryCap][kInputMax] = {};
constinit u32 g_history_head = 0;
constinit u32 g_history_count = 0;
constinit u32 g_history_cursor = 0;

bool StrEq(const char* a, const char* b)
{
    for (u32 i = 0;; ++i)
    {
        if (a[i] != b[i])
            return false;
        if (a[i] == '\0')
            return true;
    }
}

// Compare the first `n` characters of a and b. Used for the
// "echo <rest>" dispatch where we only know the command prefix.
bool StrStartsWith(const char* s, const char* prefix)
{
    for (u32 i = 0;; ++i)
    {
        if (prefix[i] == '\0')
            return true;
        if (s[i] != prefix[i])
            return false;
    }
}

void HistoryPush(const char* line)
{
    // Skip empty submissions and duplicates of the newest entry —
    // matches every shell users are used to.
    if (line[0] == '\0')
    {
        return;
    }
    if (g_history_count > 0)
    {
        const u32 newest = (g_history_head + kHistoryCap - 1) % kHistoryCap;
        if (StrEq(g_history[newest], line))
        {
            return;
        }
    }
    u32 i = 0;
    for (; i < kInputMax - 1 && line[i] != '\0'; ++i)
    {
        g_history[g_history_head][i] = line[i];
    }
    g_history[g_history_head][i] = '\0';
    g_history_head = (g_history_head + 1) % kHistoryCap;
    if (g_history_count < kHistoryCap)
    {
        ++g_history_count;
    }
}

// Look up the `n`th most-recent entry (n=1 newest, n=history_count
// oldest). Returns nullptr if n is out of range. Exposed externally
// via Shell{HistoryCount,HistoryGet} so the `history` command + the
// `!N` recall can share the same walker.
const char* HistoryAt(u32 n)
{
    if (n == 0 || n > g_history_count)
    {
        return nullptr;
    }
    const u32 idx = (g_history_head + kHistoryCap - n) % kHistoryCap;
    return g_history[idx];
}

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

void WriteU64Dec(u64 v)
{
    if (v == 0)
    {
        ConsoleWriteChar('0');
        return;
    }
    char tmp[24];
    u32 n = 0;
    while (v > 0 && n < sizeof(tmp))
    {
        tmp[n++] = static_cast<char>('0' + (v % 10));
        v /= 10;
    }
    for (u32 i = 0; i < n; ++i)
    {
        ConsoleWriteChar(tmp[n - 1 - i]);
    }
}

void WriteU8TwoDigits(u8 v)
{
    ConsoleWriteChar(static_cast<char>('0' + (v / 10)));
    ConsoleWriteChar(static_cast<char>('0' + (v % 10)));
}

// Forward declarations so commands defined earlier in the file
// can use shared helpers whose bodies live further down.
void WriteI64Dec(i64 v);
bool ParseU64Str(const char* s, duetos::u64* out);
duetos::i64 ParseInt(const char* s);

// Fixed-width hex writer: prints `digits` nibbles of `v`, high
// nibble first, with a leading "0x". digits == 0 trims leading
// zeros (min 1). Used by every register-dump / MSR / CPUID
// command.
void WriteU64Hex(u64 v, u32 digits = 16)
{
    ConsoleWrite("0x");
    if (digits == 0)
    {
        // Strip leading zeros — find highest non-zero nibble.
        digits = 1;
        for (u32 i = 16; i > 0; --i)
        {
            if (((v >> ((i - 1) * 4)) & 0xF) != 0)
            {
                digits = i;
                break;
            }
        }
    }
    if (digits > 16)
    {
        digits = 16;
    }
    for (u32 i = digits; i > 0; --i)
    {
        const u8 nib = static_cast<u8>((v >> ((i - 1) * 4)) & 0xF);
        const char c = (nib < 10) ? static_cast<char>('0' + nib) : static_cast<char>('A' + nib - 10);
        ConsoleWriteChar(c);
    }
}

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

void CmdAbout()
{
    ConsoleWriteln("DUETOS — A FROM-SCRATCH x86_64 KERNEL WITH A");
    ConsoleWriteln("NATIVE WINDOWED DESKTOP AND A FIRST-CLASS WIN32");
    ConsoleWriteln("SUBSYSTEM PLANNED. BOOT: MULTIBOOT2.  SHELL: YOU.");
}

void CmdVersion()
{
    ConsoleWriteln("DUETOS v0 (WINDOWED DESKTOP SHELL)");
}

void CmdClear()
{
    duetos::drivers::video::ConsoleClear();
}

void CmdUptime()
{
    const u64 secs = duetos::sched::SchedNowTicks() / 100;
    ConsoleWrite("UPTIME ");
    WriteU64Dec(secs);
    ConsoleWriteln(" SECONDS");
}

void CmdDate()
{
    duetos::arch::RtcTime t{};
    duetos::arch::RtcRead(&t);
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
}

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
const char* TmpLeaf(const char* path);
const char* FatLeaf(const char* path);
struct EnvSlot;
EnvSlot* EnvFind(const char* name);
void Dispatch(char* line); // CmdTime + CmdSource recurse via this

// ---------------------------------------------------------------
// Environment variables. Fixed 8-slot table, 32-byte names +
// 128-byte values. set / env / unset commands plus $VAR token
// substitution in Dispatch.
// ---------------------------------------------------------------

constexpr u32 kEnvSlotCount = 8;
constexpr u32 kEnvNameMax = 32;
constexpr u32 kEnvValueMax = 128;

struct EnvSlot
{
    bool in_use;
    char name[kEnvNameMax];
    char value[kEnvValueMax];
};

constinit EnvSlot g_env[kEnvSlotCount] = {};

bool EnvNameEq(const char* a, const char* b)
{
    for (u32 i = 0; i < kEnvNameMax; ++i)
    {
        if (a[i] != b[i])
            return false;
        if (a[i] == '\0')
            return true;
    }
    return true;
}

void EnvCopy(char* dst, const char* src, u32 cap)
{
    u32 i = 0;
    for (; i + 1 < cap && src[i] != '\0'; ++i)
    {
        dst[i] = src[i];
    }
    dst[i] = '\0';
}

EnvSlot* EnvFind(const char* name)
{
    for (u32 i = 0; i < kEnvSlotCount; ++i)
    {
        if (g_env[i].in_use && EnvNameEq(g_env[i].name, name))
        {
            return &g_env[i];
        }
    }
    return nullptr;
}

bool EnvSet(const char* name, const char* value)
{
    EnvSlot* s = EnvFind(name);
    if (s == nullptr)
    {
        for (u32 i = 0; i < kEnvSlotCount; ++i)
        {
            if (!g_env[i].in_use)
            {
                s = &g_env[i];
                s->in_use = true;
                break;
            }
        }
    }
    if (s == nullptr)
    {
        return false;
    }
    EnvCopy(s->name, name, kEnvNameMax);
    EnvCopy(s->value, value, kEnvValueMax);
    return true;
}

bool EnvUnset(const char* name)
{
    EnvSlot* s = EnvFind(name);
    if (s == nullptr)
    {
        return false;
    }
    s->in_use = false;
    s->name[0] = '\0';
    s->value[0] = '\0';
    return true;
}

// ---------------------------------------------------------------
// Aliases. Same shape as the env table — 8 slots, 32-byte names,
// 96-byte expansions. Dispatched BEFORE the env-var pass so an
// alias that includes $VAR references still gets expanded.
// ---------------------------------------------------------------

constexpr u32 kAliasSlotCount = 8;
constexpr u32 kAliasExpansionMax = 96;

struct AliasSlot
{
    bool in_use;
    char name[kEnvNameMax];
    char expansion[kAliasExpansionMax];
};

constinit AliasSlot g_aliases[kAliasSlotCount] = {};

AliasSlot* AliasFind(const char* name)
{
    for (u32 i = 0; i < kAliasSlotCount; ++i)
    {
        if (g_aliases[i].in_use && EnvNameEq(g_aliases[i].name, name))
        {
            return &g_aliases[i];
        }
    }
    return nullptr;
}

bool AliasSet(const char* name, const char* expansion)
{
    AliasSlot* s = AliasFind(name);
    if (s == nullptr)
    {
        for (u32 i = 0; i < kAliasSlotCount; ++i)
        {
            if (!g_aliases[i].in_use)
            {
                s = &g_aliases[i];
                s->in_use = true;
                break;
            }
        }
    }
    if (s == nullptr)
    {
        return false;
    }
    EnvCopy(s->name, name, kEnvNameMax);
    EnvCopy(s->expansion, expansion, kAliasExpansionMax);
    return true;
}

bool AliasUnset(const char* name)
{
    AliasSlot* s = AliasFind(name);
    if (s == nullptr)
    {
        return false;
    }
    s->in_use = false;
    s->name[0] = '\0';
    s->expansion[0] = '\0';
    return true;
}

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
u32 ReadFileToBuf(const char* path, char* buf, u32 cap)
{
    if (path == nullptr || buf == nullptr || cap == 0)
    {
        return static_cast<u32>(-1);
    }
    if (const char* tmp_leaf = TmpLeaf(path); tmp_leaf != nullptr && *tmp_leaf != '\0')
    {
        const char* bytes = nullptr;
        u32 len = 0;
        if (!duetos::fs::TmpFsRead(tmp_leaf, &bytes, &len))
        {
            return static_cast<u32>(-1);
        }
        const u32 n = (len > cap) ? cap : len;
        for (u32 i = 0; i < n; ++i)
        {
            buf[i] = bytes[i];
        }
        return n;
    }
    const auto* root = duetos::fs::RamfsTrustedRoot();
    const auto* node = duetos::fs::VfsLookup(root, path, 128);
    if (node == nullptr || node->type != duetos::fs::RamfsNodeType::kFile)
    {
        return static_cast<u32>(-1);
    }
    const u32 n = (node->file_size > cap) ? cap : static_cast<u32>(node->file_size);
    for (u32 i = 0; i < n; ++i)
    {
        buf[i] = static_cast<char>(node->file_bytes[i]);
    }
    return n;
}

void CmdCp(u32 argc, char** argv)
{
    if (argc < 3)
    {
        ConsoleWriteln("CP: USAGE: CP SRC DST");
        return;
    }
    const char* dst_leaf = TmpLeaf(argv[2]);
    if (dst_leaf == nullptr || *dst_leaf == '\0')
    {
        ConsoleWriteln("CP: DST MUST BE /tmp/<NAME>");
        return;
    }
    char scratch[duetos::fs::kTmpFsContentMax];
    const u32 n = ReadFileToBuf(argv[1], scratch, sizeof(scratch));
    if (n == static_cast<u32>(-1))
    {
        ConsoleWrite("CP: CANNOT READ: ");
        ConsoleWriteln(argv[1]);
        return;
    }
    if (!duetos::fs::TmpFsWrite(dst_leaf, scratch, n))
    {
        ConsoleWrite("CP: WRITE FAILED: ");
        ConsoleWriteln(argv[2]);
    }
}

void CmdMv(u32 argc, char** argv)
{
    if (argc < 3)
    {
        ConsoleWriteln("MV: USAGE: MV SRC DST");
        return;
    }
    const char* src_leaf = TmpLeaf(argv[1]);
    const char* dst_leaf = TmpLeaf(argv[2]);
    if (src_leaf == nullptr || *src_leaf == '\0' || dst_leaf == nullptr || *dst_leaf == '\0')
    {
        ConsoleWriteln("MV: SRC AND DST MUST BOTH BE /tmp/<NAME>");
        return;
    }
    const char* bytes = nullptr;
    u32 len = 0;
    if (!duetos::fs::TmpFsRead(src_leaf, &bytes, &len))
    {
        ConsoleWrite("MV: NO SUCH FILE: ");
        ConsoleWriteln(argv[1]);
        return;
    }
    // Copy through a scratch buffer so we don't alias the
    // tmpfs slot's own storage during write (a same-slot
    // rename collapses to the copy-back-into-self case).
    char scratch[duetos::fs::kTmpFsContentMax];
    const u32 n = (len > sizeof(scratch)) ? sizeof(scratch) : len;
    for (u32 i = 0; i < n; ++i)
    {
        scratch[i] = bytes[i];
    }
    if (!duetos::fs::TmpFsWrite(dst_leaf, scratch, n))
    {
        ConsoleWrite("MV: WRITE FAILED: ");
        ConsoleWriteln(argv[2]);
        return;
    }
    // Only unlink the source AFTER the write succeeded —
    // partial failure mustn't lose data.
    duetos::fs::TmpFsUnlink(src_leaf);
}

void CmdWc(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("WC: MISSING PATH");
        return;
    }
    char scratch[duetos::fs::kTmpFsContentMax];
    const u32 n = ReadFileToBuf(argv[1], scratch, sizeof(scratch));
    if (n == static_cast<u32>(-1))
    {
        ConsoleWrite("WC: NO SUCH FILE: ");
        ConsoleWriteln(argv[1]);
        return;
    }
    u32 lines = 0;
    u32 words = 0;
    bool in_word = false;
    for (u32 i = 0; i < n; ++i)
    {
        const char c = scratch[i];
        if (c == '\n')
        {
            ++lines;
        }
        const bool is_space = (c == ' ' || c == '\t' || c == '\n' || c == '\r');
        if (is_space)
        {
            in_word = false;
        }
        else if (!in_word)
        {
            in_word = true;
            ++words;
        }
    }
    // Treat an unterminated last line as a line for counting
    // purposes — matches `wc` on POSIX.
    if (n > 0 && scratch[n - 1] != '\n')
    {
        ++lines;
    }
    ConsoleWrite("  ");
    WriteU64Dec(lines);
    ConsoleWrite(" LINES  ");
    WriteU64Dec(words);
    ConsoleWrite(" WORDS  ");
    WriteU64Dec(n);
    ConsoleWrite(" BYTES  ");
    ConsoleWriteln(argv[1]);
}

// Parse an optional `-N` line count at argv[1]. Returns the
// parsed count (or default_n if no -N flag) and writes the
// path-arg index to `*path_idx_out`.
u32 ParseLineCount(u32 argc, char** argv, u32 default_n, u32* path_idx_out)
{
    if (argc >= 3 && argv[1][0] == '-')
    {
        u32 n = 0;
        for (u32 i = 1; argv[1][i] != '\0'; ++i)
        {
            if (argv[1][i] < '0' || argv[1][i] > '9')
            {
                n = default_n;
                break;
            }
            n = n * 10 + static_cast<u32>(argv[1][i] - '0');
        }
        *path_idx_out = 2;
        return (n == 0) ? default_n : n;
    }
    *path_idx_out = 1;
    return default_n;
}

void CmdHead(u32 argc, char** argv)
{
    u32 path_idx = 1;
    const u32 want = ParseLineCount(argc, argv, 5, &path_idx);
    if (path_idx >= argc)
    {
        ConsoleWriteln("HEAD: MISSING PATH");
        return;
    }
    char scratch[duetos::fs::kTmpFsContentMax];
    const u32 n = ReadFileToBuf(argv[path_idx], scratch, sizeof(scratch));
    if (n == static_cast<u32>(-1))
    {
        ConsoleWrite("HEAD: NO SUCH FILE: ");
        ConsoleWriteln(argv[path_idx]);
        return;
    }
    u32 lines = 0;
    for (u32 i = 0; i < n && lines < want; ++i)
    {
        ConsoleWriteChar(scratch[i]);
        if (scratch[i] == '\n')
        {
            ++lines;
        }
    }
    if (lines < want && n > 0 && scratch[n - 1] != '\n')
    {
        ConsoleWriteChar('\n');
    }
}

void CmdTail(u32 argc, char** argv)
{
    u32 path_idx = 1;
    const u32 want = ParseLineCount(argc, argv, 5, &path_idx);
    if (path_idx >= argc)
    {
        ConsoleWriteln("TAIL: MISSING PATH");
        return;
    }
    char scratch[duetos::fs::kTmpFsContentMax];
    const u32 n = ReadFileToBuf(argv[path_idx], scratch, sizeof(scratch));
    if (n == static_cast<u32>(-1))
    {
        ConsoleWrite("TAIL: NO SUCH FILE: ");
        ConsoleWriteln(argv[path_idx]);
        return;
    }
    // Count total newlines, then skip forward to reach
    // (total_lines - want) before printing. Unterminated last
    // line counts as a line.
    u32 total = 0;
    for (u32 i = 0; i < n; ++i)
    {
        if (scratch[i] == '\n')
        {
            ++total;
        }
    }
    if (n > 0 && scratch[n - 1] != '\n')
    {
        ++total;
    }
    const u32 skip = (total > want) ? total - want : 0;
    u32 seen = 0;
    u32 start = 0;
    for (; start < n && seen < skip; ++start)
    {
        if (scratch[start] == '\n')
        {
            ++seen;
        }
    }
    for (u32 i = start; i < n; ++i)
    {
        ConsoleWriteChar(scratch[i]);
    }
    if (n > 0 && scratch[n - 1] != '\n')
    {
        ConsoleWriteChar('\n');
    }
}

// True iff `needle` is a substring of `haystack[0..hay_len)`.
// Case-sensitive — all our commands run in a mostly-uppercase
// world already, and a lowercase option is a one-flag extension
// for later.
bool SubstringPresent(const char* haystack, u32 hay_len, const char* needle)
{
    if (needle == nullptr || needle[0] == '\0')
    {
        return true; // empty needle matches every line (`grep "" x`)
    }
    u32 nlen = 0;
    while (needle[nlen] != '\0')
        ++nlen;
    if (nlen > hay_len)
    {
        return false;
    }
    for (u32 i = 0; i + nlen <= hay_len; ++i)
    {
        u32 j = 0;
        for (; j < nlen; ++j)
        {
            if (haystack[i + j] != needle[j])
                break;
        }
        if (j == nlen)
            return true;
    }
    return false;
}

// Compare two byte ranges lexicographically. Returns -1/0/+1.
int LineCompare(const char* a, u32 alen, const char* b, u32 blen)
{
    const u32 min = (alen < blen) ? alen : blen;
    for (u32 i = 0; i < min; ++i)
    {
        if (a[i] != b[i])
        {
            return (a[i] < b[i]) ? -1 : 1;
        }
    }
    if (alen == blen)
        return 0;
    return (alen < blen) ? -1 : 1;
}

// Walk `scratch[0..n)` and populate `offs`/`lens` with one
// entry per line (excluding the terminating '\n'). Unterminated
// final line is counted. Returns number of lines written (capped).
u32 SliceLines(const char* scratch, u32 n, u32* offs, u32* lens, u32 cap)
{
    u32 count = 0;
    u32 start = 0;
    for (u32 i = 0; i <= n && count < cap; ++i)
    {
        const bool at_end = (i == n);
        if (at_end || scratch[i] == '\n')
        {
            offs[count] = start;
            lens[count] = i - start;
            ++count;
            start = i + 1;
        }
    }
    return count;
}

void CmdSort(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("SORT: MISSING PATH");
        return;
    }
    char scratch[duetos::fs::kTmpFsContentMax];
    const u32 n = ReadFileToBuf(argv[1], scratch, sizeof(scratch));
    if (n == static_cast<u32>(-1))
    {
        ConsoleWrite("SORT: NO SUCH FILE: ");
        ConsoleWriteln(argv[1]);
        return;
    }
    // Fixed cap of 128 lines — well over anything we can render
    // without scrolling far past the user's attention span, and
    // keeps the sort arrays comfortably on the stack.
    constexpr u32 kMaxLines = 128;
    u32 offs[kMaxLines];
    u32 lens[kMaxLines];
    const u32 count = SliceLines(scratch, n, offs, lens, kMaxLines);
    // Insertion sort — O(N^2) but N ≤ 128 and the line bodies
    // stay in place (we only swap the index pairs).
    for (u32 i = 1; i < count; ++i)
    {
        const u32 off_i = offs[i];
        const u32 len_i = lens[i];
        u32 j = i;
        while (j > 0 && LineCompare(&scratch[offs[j - 1]], lens[j - 1], &scratch[off_i], len_i) > 0)
        {
            offs[j] = offs[j - 1];
            lens[j] = lens[j - 1];
            --j;
        }
        offs[j] = off_i;
        lens[j] = len_i;
    }
    for (u32 i = 0; i < count; ++i)
    {
        for (u32 k = 0; k < lens[i]; ++k)
        {
            ConsoleWriteChar(scratch[offs[i] + k]);
        }
        ConsoleWriteChar('\n');
    }
}

void CmdUniq(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("UNIQ: MISSING PATH");
        return;
    }
    char scratch[duetos::fs::kTmpFsContentMax];
    const u32 n = ReadFileToBuf(argv[1], scratch, sizeof(scratch));
    if (n == static_cast<u32>(-1))
    {
        ConsoleWrite("UNIQ: NO SUCH FILE: ");
        ConsoleWriteln(argv[1]);
        return;
    }
    // Classic uniq: only suppress consecutive duplicates. Walk
    // line by line and remember the PREVIOUS line's range to
    // compare against the current. First line always prints.
    u32 prev_off = 0;
    u32 prev_len = 0;
    bool have_prev = false;
    u32 start = 0;
    for (u32 i = 0; i <= n; ++i)
    {
        const bool at_end = (i == n);
        if (at_end || scratch[i] == '\n')
        {
            const u32 len = i - start;
            const bool is_dup = have_prev && LineCompare(&scratch[prev_off], prev_len, &scratch[start], len) == 0;
            if (!is_dup)
            {
                for (u32 k = 0; k < len; ++k)
                {
                    ConsoleWriteChar(scratch[start + k]);
                }
                ConsoleWriteChar('\n');
                prev_off = start;
                prev_len = len;
                have_prev = true;
            }
            start = i + 1;
        }
    }
}

void CmdGrep(u32 argc, char** argv)
{
    if (argc < 3)
    {
        ConsoleWriteln("GREP: USAGE: GREP PATTERN PATH");
        return;
    }
    const char* pattern = argv[1];
    const char* path = argv[2];
    char scratch[duetos::fs::kTmpFsContentMax];
    const u32 n = ReadFileToBuf(path, scratch, sizeof(scratch));
    if (n == static_cast<u32>(-1))
    {
        ConsoleWrite("GREP: NO SUCH FILE: ");
        ConsoleWriteln(path);
        return;
    }
    // Walk line by line. A line runs from the last newline+1 to
    // the next newline (or EOF). For each line, substring-match
    // on `pattern`.
    u32 start = 0;
    for (u32 i = 0; i <= n; ++i)
    {
        const bool at_end = (i == n);
        if (at_end || scratch[i] == '\n')
        {
            const u32 len = i - start;
            if (SubstringPresent(&scratch[start], len, pattern))
            {
                for (u32 j = 0; j < len; ++j)
                {
                    ConsoleWriteChar(scratch[start + j]);
                }
                ConsoleWriteChar('\n');
            }
            start = i + 1;
        }
    }
}

// Recursive ramfs walker for `find`. Builds the absolute path
// in `path_buf` as it descends; restores the length on the way
// back so sibling subtrees see the correct prefix. Root's name
// is empty — we skip the name-match test there but still walk
// its children.
void FindWalk(const duetos::fs::RamfsNode* node, const char* needle, char* path_buf, u32& path_len, u32 path_cap)
{
    if (node == nullptr)
    {
        return;
    }
    if (node->name != nullptr && node->name[0] != '\0')
    {
        u32 nlen = 0;
        while (node->name[nlen] != '\0')
            ++nlen;
        if (SubstringPresent(node->name, nlen, needle))
        {
            for (u32 i = 0; i < path_len; ++i)
            {
                ConsoleWriteChar(path_buf[i]);
            }
            ConsoleWriteChar('\n');
        }
    }
    if (node->type != duetos::fs::RamfsNodeType::kDir || node->children == nullptr)
    {
        return;
    }
    for (u32 i = 0; node->children[i] != nullptr; ++i)
    {
        const auto* c = node->children[i];
        const u32 saved = path_len;
        if (path_len + 1 < path_cap)
        {
            path_buf[path_len++] = '/';
        }
        for (u32 k = 0; c->name[k] != '\0' && path_len + 1 < path_cap; ++k)
        {
            path_buf[path_len++] = c->name[k];
        }
        path_buf[path_len] = '\0';
        FindWalk(c, needle, path_buf, path_len, path_cap);
        path_len = saved;
        path_buf[path_len] = '\0';
    }
}

void CmdFind(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("FIND: USAGE: FIND NAME");
        return;
    }
    const char* needle = argv[1];
    char path_buf[128] = {};
    u32 path_len = 0;
    FindWalk(duetos::fs::RamfsTrustedRoot(), needle, path_buf, path_len, sizeof(path_buf));
    // tmpfs is flat under /tmp/ — enumerate directly.
    struct Cookie
    {
        const char* needle;
    };
    Cookie cookie{needle};
    duetos::fs::TmpFsEnumerate(
        [](const char* name, u32 /*len*/, void* ck)
        {
            auto* c = static_cast<Cookie*>(ck);
            u32 nlen = 0;
            while (name[nlen] != '\0')
                ++nlen;
            if (SubstringPresent(name, nlen, c->needle))
            {
                ConsoleWrite("/tmp/");
                ConsoleWriteln(name);
            }
        },
        &cookie);
}

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

void CmdSet(u32 argc, char** argv)
{
    if (argc < 3)
    {
        ConsoleWriteln("SET: USAGE: SET NAME VALUE");
        return;
    }
    if (!EnvSet(argv[1], argv[2]))
    {
        ConsoleWriteln("SET: ENV TABLE FULL");
    }
}

void CmdUnset(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("UNSET: MISSING NAME");
        return;
    }
    if (!EnvUnset(argv[1]))
    {
        ConsoleWrite("UNSET: NO SUCH VAR: ");
        ConsoleWriteln(argv[1]);
    }
}

void CmdAlias(u32 argc, char** argv)
{
    if (argc == 1)
    {
        // List all.
        bool any = false;
        for (u32 i = 0; i < kAliasSlotCount; ++i)
        {
            if (!g_aliases[i].in_use)
                continue;
            any = true;
            ConsoleWrite("  ");
            ConsoleWrite(g_aliases[i].name);
            ConsoleWrite("  = ");
            ConsoleWriteln(g_aliases[i].expansion);
        }
        if (!any)
        {
            ConsoleWriteln("(NO ALIASES)");
        }
        return;
    }
    if (argc == 2)
    {
        const AliasSlot* s = AliasFind(argv[1]);
        if (s == nullptr)
        {
            ConsoleWrite("ALIAS: NO SUCH ALIAS: ");
            ConsoleWriteln(argv[1]);
            return;
        }
        ConsoleWrite(argv[1]);
        ConsoleWrite(" = ");
        ConsoleWriteln(s->expansion);
        return;
    }
    // 3+ args — join args[2..argc] with single spaces into the
    // expansion, matching how the user typed it.
    char buf[kAliasExpansionMax];
    u32 out = 0;
    for (u32 i = 2; i < argc; ++i)
    {
        if (i > 2 && out + 1 < sizeof(buf))
            buf[out++] = ' ';
        for (u32 j = 0; argv[i][j] != '\0' && out + 1 < sizeof(buf); ++j)
            buf[out++] = argv[i][j];
    }
    buf[out] = '\0';
    if (!AliasSet(argv[1], buf))
    {
        ConsoleWriteln("ALIAS: TABLE FULL");
    }
}

void CmdUnalias(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("UNALIAS: MISSING NAME");
        return;
    }
    if (!AliasUnset(argv[1]))
    {
        ConsoleWrite("UNALIAS: NO SUCH ALIAS: ");
        ConsoleWriteln(argv[1]);
    }
}

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

void CmdEnv()
{
    bool any = false;
    for (u32 i = 0; i < kEnvSlotCount; ++i)
    {
        if (!g_env[i].in_use)
            continue;
        any = true;
        ConsoleWrite("  ");
        ConsoleWrite(g_env[i].name);
        ConsoleWriteChar('=');
        ConsoleWriteln(g_env[i].value);
    }
    if (!any)
    {
        ConsoleWriteln("(NO VARIABLES SET)");
    }
}

// ---------------------------------------------------------------
// System introspection / manipulation commands.
// Raw views into CPU / MSR / APIC / PCI / paging / heap / input
// drivers, plus power-control (reboot, halt) + runtime setters
// (loglevel, getenv). Every getter is side-effect-free; power
// commands call the existing kernel primitives.
// ---------------------------------------------------------------

// Inline CPUID wrapper. Returns eax/ebx/ecx/edx for the given
// leaf + sub-leaf. The kernel has no <cpuid.h>, so we roll the
// inline asm here.
void CpuidRaw(u32 leaf, u32 subleaf, u32& a, u32& b, u32& c, u32& d)
{
    u32 ra = leaf, rb = 0, rc = subleaf, rd = 0;
    asm volatile("cpuid" : "+a"(ra), "+b"(rb), "+c"(rc), "+d"(rd));
    a = ra;
    b = rb;
    c = rc;
    d = rd;
}

inline u64 ReadRflags()
{
    u64 v;
    asm volatile("pushfq; pop %0" : "=r"(v));
    return v;
}

inline u64 ReadTsc()
{
    u32 lo, hi;
    asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return (static_cast<u64>(hi) << 32) | lo;
}

inline u64 ReadMsrRaw(u32 msr)
{
    u32 lo, hi;
    asm volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return (static_cast<u64>(hi) << 32) | lo;
}

void CmdCpuid(u32 argc, char** argv)
{
    // Default: print vendor string + feature summary. With a
    // leaf arg, dump the raw eax/ebx/ecx/edx.
    u32 a = 0, b = 0, c = 0, d = 0;
    if (argc >= 2)
    {
        u32 leaf = 0;
        for (u32 i = 0; argv[1][i] != '\0'; ++i)
        {
            const char ch = argv[1][i];
            if (ch == 'x' || ch == 'X')
            {
                leaf = 0;
                continue;
            }
            if (ch >= '0' && ch <= '9')
                leaf = leaf * 16 + (ch - '0');
            else if (ch >= 'a' && ch <= 'f')
                leaf = leaf * 16 + (ch - 'a' + 10);
            else if (ch >= 'A' && ch <= 'F')
                leaf = leaf * 16 + (ch - 'A' + 10);
        }
        CpuidRaw(leaf, 0, a, b, c, d);
        ConsoleWrite("LEAF=");
        WriteU64Hex(leaf, 8);
        ConsoleWrite("  EAX=");
        WriteU64Hex(a, 8);
        ConsoleWrite(" EBX=");
        WriteU64Hex(b, 8);
        ConsoleWrite(" ECX=");
        WriteU64Hex(c, 8);
        ConsoleWrite(" EDX=");
        WriteU64Hex(d, 8);
        ConsoleWriteChar('\n');
        return;
    }
    // Leaf 0 — vendor string in EBX, EDX, ECX (in that order).
    CpuidRaw(0, 0, a, b, c, d);
    const u32 max_leaf = a;
    char vendor[13];
    vendor[0] = static_cast<char>(b & 0xFF);
    vendor[1] = static_cast<char>((b >> 8) & 0xFF);
    vendor[2] = static_cast<char>((b >> 16) & 0xFF);
    vendor[3] = static_cast<char>((b >> 24) & 0xFF);
    vendor[4] = static_cast<char>(d & 0xFF);
    vendor[5] = static_cast<char>((d >> 8) & 0xFF);
    vendor[6] = static_cast<char>((d >> 16) & 0xFF);
    vendor[7] = static_cast<char>((d >> 24) & 0xFF);
    vendor[8] = static_cast<char>(c & 0xFF);
    vendor[9] = static_cast<char>((c >> 8) & 0xFF);
    vendor[10] = static_cast<char>((c >> 16) & 0xFF);
    vendor[11] = static_cast<char>((c >> 24) & 0xFF);
    vendor[12] = '\0';
    ConsoleWrite("VENDOR:    ");
    ConsoleWriteln(vendor);
    ConsoleWrite("MAX LEAF:  ");
    WriteU64Hex(max_leaf, 8);
    ConsoleWriteChar('\n');

    // Leaf 1 — family/model + feature flags.
    CpuidRaw(1, 0, a, b, c, d);
    const u32 stepping = a & 0xF;
    const u32 model = (a >> 4) & 0xF;
    const u32 family = (a >> 8) & 0xF;
    const u32 ext_model = (a >> 16) & 0xF;
    const u32 ext_family = (a >> 20) & 0xFF;
    ConsoleWrite("FAMILY:    ");
    WriteU64Dec(family + (family == 0xF ? ext_family : 0));
    ConsoleWrite("   MODEL: ");
    WriteU64Dec(model | (ext_model << 4));
    ConsoleWrite("   STEP: ");
    WriteU64Dec(stepping);
    ConsoleWriteChar('\n');
    ConsoleWrite("FEAT ECX:  ");
    WriteU64Hex(c, 8);
    ConsoleWrite("   EDX: ");
    WriteU64Hex(d, 8);
    ConsoleWriteChar('\n');

    // Leaf 0x80000000 — max extended leaf + brand string.
    CpuidRaw(0x80000000u, 0, a, b, c, d);
    if (a >= 0x80000004u)
    {
        char brand[49];
        u32 off = 0;
        for (u32 leaf = 0x80000002u; leaf <= 0x80000004u; ++leaf)
        {
            CpuidRaw(leaf, 0, a, b, c, d);
            const u32 r[4] = {a, b, c, d};
            for (u32 k = 0; k < 4; ++k)
            {
                for (u32 m = 0; m < 4 && off + 1 < sizeof(brand); ++m)
                {
                    brand[off++] = static_cast<char>((r[k] >> (m * 8)) & 0xFF);
                }
            }
        }
        brand[off] = '\0';
        // Trim leading spaces (Intel pads the brand string).
        const char* p = brand;
        while (*p == ' ')
            ++p;
        ConsoleWrite("BRAND:     ");
        ConsoleWriteln(p);
    }
}

void CmdCr()
{
    ConsoleWrite("CR0:  ");
    WriteU64Hex(duetos::arch::ReadCr0());
    ConsoleWriteChar('\n');
    ConsoleWrite("CR2:  ");
    WriteU64Hex(duetos::arch::ReadCr2());
    ConsoleWriteChar('\n');
    ConsoleWrite("CR3:  ");
    WriteU64Hex(duetos::arch::ReadCr3());
    ConsoleWriteChar('\n');
    ConsoleWrite("CR4:  ");
    WriteU64Hex(duetos::arch::ReadCr4());
    ConsoleWriteChar('\n');
}

// Rflags bit positions + names, parallel arrays so the
// initialisers are trivial — a struct-array local would need
// memcpy from .rodata, which the freestanding kernel doesn't
// link.
constexpr u8 kRflagsBitIdx[] = {0, 2, 4, 6, 7, 8, 9, 10, 11, 14, 16, 17, 18, 19, 20, 21};
constexpr const char* kRflagsBitNames[] = {"CF", "PF", "AF", "ZF", "SF", "TF",  "IF",  "DF",
                                           "OF", "NT", "RF", "VM", "AC", "VIF", "VIP", "ID"};

void CmdRflags()
{
    const u64 f = ReadRflags();
    ConsoleWrite("RFLAGS: ");
    WriteU64Hex(f);
    ConsoleWriteChar('\n');
    ConsoleWrite("BITS:  ");
    bool any = false;
    for (u32 i = 0; i < sizeof(kRflagsBitIdx); ++i)
    {
        if ((f >> kRflagsBitIdx[i]) & 1)
        {
            if (any)
                ConsoleWriteChar(' ');
            ConsoleWrite(kRflagsBitNames[i]);
            any = true;
        }
    }
    if (!any)
    {
        ConsoleWrite("(none set)");
    }
    ConsoleWriteChar('\n');
}

void CmdTsc()
{
    ConsoleWrite("TSC:   ");
    WriteU64Hex(ReadTsc());
    ConsoleWriteChar('\n');
}

void CmdHpet()
{
    const u64 v = duetos::arch::HpetReadCounter();
    const u32 p = duetos::arch::HpetPeriodFemtoseconds();
    ConsoleWrite("HPET COUNTER: ");
    WriteU64Hex(v);
    ConsoleWriteChar('\n');
    ConsoleWrite("HPET PERIOD:  ");
    WriteU64Dec(p);
    ConsoleWriteln(" fs/tick");
    if (p > 0)
    {
        // Counter * period (fs) / 1e12 = seconds elapsed.
        const u64 secs = (v / 1'000'000ull) * p / 1'000'000ull;
        ConsoleWrite("APPROX SECS:  ");
        WriteU64Dec(secs);
        ConsoleWriteChar('\n');
    }
}

void CmdTicks()
{
    ConsoleWrite("TIMER TICKS: ");
    WriteU64Dec(duetos::arch::TimerTicks());
    ConsoleWriteChar('\n');
    ConsoleWrite("SCHED TICKS: ");
    WriteU64Dec(duetos::sched::SchedNowTicks());
    ConsoleWriteChar('\n');
}

void CmdMsr(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("MSR: USAGE: MSR <HEX-INDEX>");
        ConsoleWriteln("   EXAMPLES: MSR C0000080 (EFER)  MSR 1B (APIC BASE)");
        ConsoleWriteln("   ALLOWED: 10 1B C0000080 C0000081 C0000082 C0000084");
        ConsoleWriteln("            C0000100 C0000101 C0000102");
        return;
    }
    u32 idx = 0;
    for (u32 i = 0; argv[1][i] != '\0'; ++i)
    {
        const char ch = argv[1][i];
        if (ch == 'x' || ch == 'X')
            continue;
        if (ch >= '0' && ch <= '9')
            idx = idx * 16 + (ch - '0');
        else if (ch >= 'a' && ch <= 'f')
            idx = idx * 16 + (ch - 'a' + 10);
        else if (ch >= 'A' && ch <= 'F')
            idx = idx * 16 + (ch - 'A' + 10);
        else
        {
            ConsoleWriteln("MSR: BAD HEX");
            return;
        }
    }
    // rdmsr on a reserved / model-specific index raises #GP. The
    // kernel's trap handler will then panic and halt the box —
    // turning an interactive diagnostic into a denial-of-service
    // primitive for any operator with a keyboard. Gate reads to
    // the architectural indices the kernel already touches plus
    // the handful that are useful for boot-up diagnosis; anything
    // outside the list returns a polite "not allowed" and leaves
    // the CPU alone.
    //
    //   0x00000010            IA32_TSC
    //   0x0000001B            IA32_APIC_BASE
    //   0xC0000080            IA32_EFER
    //   0xC0000081..0xC0000084 IA32_STAR / LSTAR / CSTAR / FMASK
    //   0xC0000100..0xC0000102 IA32_FS_BASE / GS_BASE / KERNEL_GS_BASE
    //
    // Every entry above is guaranteed readable on any x86_64 CPU
    // the kernel supports; none can be made #GP by a guest-side
    // misconfiguration. Adding more is fine — the rule is "only
    // architectural MSRs the kernel itself relies on, never a
    // model-specific bank we haven't verified."
    static constexpr u32 kMsrWhitelist[] = {
        0x00000010u, 0x0000001Bu, 0xC0000080u, 0xC0000081u, 0xC0000082u,
        0xC0000083u, 0xC0000084u, 0xC0000100u, 0xC0000101u, 0xC0000102u,
    };
    bool allowed = false;
    for (u32 i = 0; i < sizeof(kMsrWhitelist) / sizeof(kMsrWhitelist[0]); ++i)
    {
        if (kMsrWhitelist[i] == idx)
        {
            allowed = true;
            break;
        }
    }
    if (!allowed)
    {
        ConsoleWrite("MSR ");
        WriteU64Hex(idx, 8);
        ConsoleWriteln(":  NOT ALLOWED (reserved index would #GP the kernel)");
        return;
    }
    ConsoleWrite("MSR ");
    WriteU64Hex(idx, 8);
    ConsoleWrite(":  ");
    WriteU64Hex(ReadMsrRaw(idx));
    ConsoleWriteChar('\n');
}

void CmdLapic()
{
    using namespace duetos::arch;
    const u32 id = LapicRead(kLapicRegId);
    const u32 ver = LapicRead(kLapicRegVersion);
    const u32 svr = LapicRead(kLapicRegSvr);
    const u32 lvt = LapicRead(kLapicRegLvtTimer);
    const u32 init = LapicRead(kLapicRegTimerInit);
    const u32 cur = LapicRead(kLapicRegTimerCount);
    ConsoleWrite("LAPIC ID:      ");
    WriteU64Hex(id, 8);
    ConsoleWrite("   (CPU# ");
    WriteU64Dec(id >> 24);
    ConsoleWriteln(")");
    ConsoleWrite("LAPIC VERSION: ");
    WriteU64Hex(ver, 8);
    ConsoleWriteChar('\n');
    ConsoleWrite("SVR:           ");
    WriteU64Hex(svr, 8);
    ConsoleWriteChar('\n');
    ConsoleWrite("LVT TIMER:     ");
    WriteU64Hex(lvt, 8);
    ConsoleWriteChar('\n');
    ConsoleWrite("TIMER INIT:    ");
    WriteU64Hex(init, 8);
    ConsoleWrite("   CUR: ");
    WriteU64Hex(cur, 8);
    ConsoleWriteChar('\n');
}

void CmdSmp()
{
    const u64 n = duetos::arch::SmpCpusOnline();
    ConsoleWrite("CPUS ONLINE:   ");
    WriteU64Dec(n);
    ConsoleWriteChar('\n');
    if (n == 1)
    {
        ConsoleWriteln("(BSP only; AP bring-up deferred — see decision log #021)");
    }
}

void CmdLspci()
{
    const u64 n = duetos::drivers::pci::PciDeviceCount();
    ConsoleWrite("PCI DEVICES:   ");
    WriteU64Dec(n);
    ConsoleWriteChar('\n');
    for (u64 i = 0; i < n; ++i)
    {
        const auto& d = duetos::drivers::pci::PciDevice(i);
        ConsoleWrite("  ");
        WriteU64Hex(d.addr.bus, 2);
        ConsoleWriteChar(':');
        WriteU64Hex(d.addr.device, 2);
        ConsoleWriteChar('.');
        WriteU64Hex(d.addr.function, 1);
        ConsoleWrite("  ");
        WriteU64Hex(d.vendor_id, 4);
        ConsoleWriteChar(':');
        WriteU64Hex(d.device_id, 4);
        ConsoleWrite("  class=");
        WriteU64Hex(d.class_code, 2);
        ConsoleWriteChar('.');
        WriteU64Hex(d.subclass, 2);
        ConsoleWriteChar(' ');
        ConsoleWriteln(duetos::drivers::pci::PciClassName(d.class_code));
    }
}

void CmdHeap()
{
    const auto s = duetos::mm::KernelHeapStatsRead();
    ConsoleWrite("POOL BYTES:       ");
    WriteU64Dec(s.pool_bytes);
    ConsoleWriteChar('\n');
    ConsoleWrite("USED BYTES:       ");
    WriteU64Dec(s.used_bytes);
    ConsoleWriteChar('\n');
    ConsoleWrite("FREE BYTES:       ");
    WriteU64Dec(s.free_bytes);
    ConsoleWriteChar('\n');
    ConsoleWrite("ALLOCATIONS:      ");
    WriteU64Dec(s.alloc_count);
    ConsoleWriteChar('\n');
    ConsoleWrite("FREES:            ");
    WriteU64Dec(s.free_count);
    ConsoleWriteChar('\n');
    ConsoleWrite("LARGEST FREE RUN: ");
    WriteU64Dec(s.largest_free_run);
    ConsoleWriteChar('\n');
    ConsoleWrite("FREE CHUNKS:      ");
    WriteU64Dec(s.free_chunk_count);
    ConsoleWriteChar('\n');
}

void CmdPaging()
{
    const auto s = duetos::mm::PagingStatsRead();
    ConsoleWrite("PAGE TABLES:       ");
    WriteU64Dec(s.page_tables_allocated);
    ConsoleWriteChar('\n');
    ConsoleWrite("MAPPINGS INSTALL:  ");
    WriteU64Dec(s.mappings_installed);
    ConsoleWriteChar('\n');
    ConsoleWrite("MAPPINGS REMOVE:   ");
    WriteU64Dec(s.mappings_removed);
    ConsoleWriteChar('\n');
    ConsoleWrite("MMIO ARENA USED:   ");
    WriteU64Dec(s.mmio_arena_used_bytes);
    ConsoleWriteln(" bytes");
}

void CmdFb()
{
    if (!duetos::drivers::video::FramebufferAvailable())
    {
        ConsoleWriteln("FB: NOT AVAILABLE");
        return;
    }
    const auto info = duetos::drivers::video::FramebufferGet();
    ConsoleWrite("FB PHYS:   ");
    WriteU64Hex(info.phys);
    ConsoleWriteChar('\n');
    ConsoleWrite("FB VIRT:   ");
    WriteU64Hex(reinterpret_cast<u64>(info.virt));
    ConsoleWriteChar('\n');
    ConsoleWrite("FB SIZE:   ");
    WriteU64Dec(info.width);
    ConsoleWrite(" x ");
    WriteU64Dec(info.height);
    ConsoleWrite(" @ ");
    WriteU64Dec(info.bpp);
    ConsoleWrite(" bpp  (pitch ");
    WriteU64Dec(info.pitch);
    ConsoleWriteln(")");
}

void CmdKbdStats()
{
    const auto s = duetos::drivers::input::Ps2KeyboardStats();
    ConsoleWrite("KBD IRQS:      ");
    WriteU64Dec(s.irqs_seen);
    ConsoleWriteChar('\n');
    ConsoleWrite("KBD BUFFERED:  ");
    WriteU64Dec(s.bytes_buffered);
    ConsoleWriteChar('\n');
    ConsoleWrite("KBD DROPPED:   ");
    WriteU64Dec(s.bytes_dropped);
    ConsoleWriteChar('\n');
}

void CmdMouseStats()
{
    const auto s = duetos::drivers::input::Ps2MouseStatsRead();
    ConsoleWrite("MOUSE IRQS:     ");
    WriteU64Dec(s.irqs_seen);
    ConsoleWriteChar('\n');
    ConsoleWrite("MOUSE PACKETS:  ");
    WriteU64Dec(s.packets_decoded);
    ConsoleWriteChar('\n');
    ConsoleWrite("MOUSE DROPPED:  ");
    WriteU64Dec(s.bytes_dropped);
    ConsoleWriteChar('\n');
}

// ------ Observability commands for the v0 subsystems ------

void CmdSmbios()
{
    const auto& s = duetos::arch::SmbiosGet();
    if (!s.present)
    {
        ConsoleWriteln("SMBIOS: (no entry point found)");
        return;
    }
    ConsoleWrite("BIOS:         ");
    ConsoleWrite(s.bios_vendor);
    ConsoleWrite(" ");
    ConsoleWriteln(s.bios_version);
    ConsoleWrite("SYSTEM:       ");
    ConsoleWrite(s.system_manufacturer);
    ConsoleWrite(" ");
    ConsoleWrite(s.system_product);
    ConsoleWrite(" v=");
    ConsoleWriteln(s.system_version);
    ConsoleWrite("CHASSIS:      ");
    ConsoleWrite(duetos::arch::ChassisTypeName(s.chassis_type));
    ConsoleWriteln(duetos::arch::SmbiosIsLaptopChassis() ? " (laptop-like)" : "");
    ConsoleWrite("CPU:          ");
    ConsoleWrite(s.cpu_manufacturer);
    ConsoleWrite(" ");
    ConsoleWriteln(s.cpu_version);
}

void CmdPower()
{
    const auto snap = duetos::drivers::power::PowerSnapshotRead();
    ConsoleWrite("CHASSIS:      ");
    ConsoleWriteln(snap.chassis_is_laptop ? "laptop-like" : "desktop/server");
    ConsoleWrite("AC:           ");
    ConsoleWriteln(duetos::drivers::power::AcStateName(snap.ac));
    ConsoleWrite("BATTERY:      ");
    ConsoleWriteln(duetos::drivers::power::BatteryStateName(snap.battery.state));
    ConsoleWrite("CPU TEMP:     ");
    if (snap.cpu_temp_c != 0)
    {
        WriteU64Dec(snap.cpu_temp_c);
        ConsoleWriteln("C");
    }
    else
    {
        ConsoleWriteln("(not available)");
    }
    ConsoleWrite("PACKAGE TEMP: ");
    if (snap.package_temp_c != 0)
    {
        WriteU64Dec(snap.package_temp_c);
        ConsoleWriteln("C");
    }
    else
    {
        ConsoleWriteln("(not available)");
    }
    ConsoleWrite("TJ MAX:       ");
    WriteU64Dec(snap.tj_max_c);
    ConsoleWriteln("C");
    ConsoleWrite("THROTTLE HIT: ");
    ConsoleWriteln(snap.thermal_throttle_hit ? "YES" : "NO");
    if (snap.backend_is_stub)
    {
        ConsoleWriteln("(backend is a stub — AC/battery need AML interpreter; thermal is real)");
    }
}

void CmdThermal()
{
    const auto r = duetos::arch::ThermalRead();
    if (!r.valid)
    {
        ConsoleWriteln("THERMAL: sensors report invalid (likely emulator)");
        return;
    }
    ConsoleWrite("CORE TEMP:    ");
    WriteU64Dec(r.core_temp_c);
    ConsoleWriteln("C");
    ConsoleWrite("PACKAGE TEMP: ");
    WriteU64Dec(r.package_temp_c);
    ConsoleWriteln("C");
    ConsoleWrite("TJ MAX:       ");
    WriteU64Dec(r.tj_max_c);
    ConsoleWriteln("C");
    ConsoleWrite("THROTTLE:     ");
    ConsoleWriteln(r.thermal_throttle_hit ? "HIT" : "clear");
}

// One-shot hardware-monitor view — aggregates every sensor /
// inventory source we have (SMBIOS, MSR thermal, AC / battery
// stub, ACPI state) so a user can grep one command for the
// whole picture. Mirrors `sensors + dmidecode + upower` on
// Linux at a very rough level.
void CmdHwmon()
{
    const auto snap = duetos::drivers::power::PowerSnapshotRead();
    const auto& smbios = duetos::arch::SmbiosGet();

    ConsoleWriteln("=== HWMON ===");
    ConsoleWrite("CHASSIS:      ");
    ConsoleWriteln(snap.chassis_is_laptop ? "laptop" : "desktop/unknown");
    if (smbios.present)
    {
        ConsoleWrite("SYSTEM:       ");
        ConsoleWrite(smbios.system_manufacturer);
        ConsoleWrite(" / ");
        ConsoleWriteln(smbios.system_product);
        ConsoleWrite("BIOS:         ");
        ConsoleWrite(smbios.bios_vendor);
        ConsoleWrite(" / ");
        ConsoleWriteln(smbios.bios_version);
        ConsoleWrite("CPU BRAND:    ");
        ConsoleWriteln(smbios.cpu_version);
    }
    else
    {
        ConsoleWriteln("SMBIOS:       (not present — boot firmware didn't expose it)");
    }

    ConsoleWriteln("-- thermal --");
    if (snap.cpu_temp_c != 0 || snap.package_temp_c != 0 || snap.tj_max_c != 0)
    {
        ConsoleWrite("CORE TEMP:    ");
        WriteU64Dec(snap.cpu_temp_c);
        ConsoleWrite("C  PKG: ");
        WriteU64Dec(snap.package_temp_c);
        ConsoleWrite("C  TJ_MAX: ");
        WriteU64Dec(snap.tj_max_c);
        ConsoleWriteln("C");
        ConsoleWrite("THROTTLE:     ");
        ConsoleWriteln(snap.thermal_throttle_hit ? "HIT" : "clear");
    }
    else
    {
        ConsoleWriteln("CORE TEMP:    (MSR thermal sensors unavailable — QEMU TCG / old CPU)");
    }

    ConsoleWriteln("-- power --");
    ConsoleWrite("AC STATE:     ");
    ConsoleWriteln(duetos::drivers::power::AcStateName(snap.ac));
    const auto& b = snap.battery;
    if (b.state == duetos::drivers::power::kBatNotPresent)
    {
        ConsoleWriteln("BATTERY:      (not present)");
    }
    else
    {
        ConsoleWrite("BATTERY:      ");
        ConsoleWrite(duetos::drivers::power::BatteryStateName(b.state));
        ConsoleWrite("  ");
        if (b.percent <= 100)
        {
            WriteU64Dec(b.percent);
            ConsoleWrite("%");
        }
        else
        {
            ConsoleWrite("?%");
        }
        if (b.rate_mw != 0)
        {
            ConsoleWrite("  rate=");
            if (b.rate_mw < 0)
            {
                ConsoleWriteChar('-');
                WriteU64Dec(static_cast<u64>(-b.rate_mw));
            }
            else
            {
                WriteU64Dec(static_cast<u64>(b.rate_mw));
            }
            ConsoleWrite("mW");
        }
        ConsoleWriteln("");
    }

    ConsoleWriteln("-- fans --");
    // Fan-speed readback requires either ACPI _FAN evaluation (we
    // have the AML parser but no _FAN caller) or a SuperIO / EC
    // driver for the host's hardware-monitor chip (Winbond /
    // Nuvoton / ITE). Neither is wired today. State the gap
    // explicitly so a boot log confirms the command ran and just
    // has no sensor to read.
    ConsoleWriteln("FAN RPM:      (n/a — ACPI _FAN + SuperIO not implemented)");

    if (snap.backend_is_stub)
    {
        ConsoleWriteln("");
        ConsoleWriteln("NOTE: AC + battery are stubbed until the AML control method");
        ConsoleWriteln("      evaluator lands; thermals come from MSR direct read.");
    }
}

void CmdGpu()
{
    const u64 n = duetos::drivers::gpu::GpuCount();
    if (n == 0)
    {
        ConsoleWriteln("GPU: (none discovered)");
        return;
    }
    bool saw_virtio = false;
    for (u64 i = 0; i < n; ++i)
    {
        const auto& g = duetos::drivers::gpu::Gpu(i);
        ConsoleWrite("GPU ");
        WriteU64Dec(i);
        ConsoleWrite(": vid=");
        WriteU64Hex(g.vendor_id, 4);
        ConsoleWrite(" did=");
        WriteU64Hex(g.device_id, 4);
        ConsoleWrite("  vendor=");
        ConsoleWrite(g.vendor);
        ConsoleWrite(" tier=");
        ConsoleWrite(g.tier);
        if (g.family != nullptr)
        {
            ConsoleWrite(" family=");
            ConsoleWrite(g.family);
        }
        ConsoleWriteChar('\n');
        if (g.mmio_size != 0)
        {
            ConsoleWrite("       BAR0=");
            WriteU64Hex(g.mmio_phys, 0);
            ConsoleWrite("/");
            WriteU64Hex(g.mmio_size, 0);
            if (g.mmio_live)
            {
                ConsoleWrite("  MMIO=LIVE  probe_reg=");
                WriteU64Hex(g.probe_reg, 8);
                if (g.arch != nullptr)
                {
                    ConsoleWrite(" arch=");
                    ConsoleWrite(g.arch);
                }
            }
            else if (g.mmio_virt != nullptr)
            {
                ConsoleWrite("  MMIO=DECODE-FAIL");
            }
            else
            {
                ConsoleWrite("  MMIO=unmapped");
            }
            ConsoleWriteChar('\n');
        }
        if (g.vendor_id == duetos::drivers::gpu::kVendorRedHatVirt && g.device_id == 0x1050)
            saw_virtio = true;
    }

    if (saw_virtio)
    {
        const auto v = duetos::drivers::gpu::VirtioGpuLastLayout();
        if (v.present)
        {
            ConsoleWriteln("virtio-gpu layout:");
            ConsoleWrite("  common_cfg phys=");
            WriteU64Hex(v.common_cfg_phys, 0);
            ConsoleWrite("  num_queues=");
            WriteU64Dec(v.num_queues);
            ConsoleWrite("  device_features_lo=");
            WriteU64Hex(v.device_features_lo, 8);
            ConsoleWrite("  status_after_reset=");
            WriteU64Hex(v.device_status_after_reset, 2);
            ConsoleWriteChar('\n');
        }
        else
        {
            ConsoleWriteln("virtio-gpu: device present but probe incomplete (no common_cfg)");
        }

        const auto& d = duetos::drivers::gpu::VirtioGpuLastDisplayInfo();
        if (d.valid)
        {
            ConsoleWrite("virtio-gpu displays: ");
            WriteU64Dec(d.active_scanouts);
            ConsoleWriteln(" active scanout(s)");
            for (u32 i = 0; i < duetos::drivers::gpu::kVirtioGpuMaxScanouts; ++i)
            {
                if (d.enabled[i] == 0)
                    continue;
                ConsoleWrite("  scanout ");
                WriteU64Dec(i);
                ConsoleWrite(": ");
                WriteU64Dec(d.rects[i].width);
                ConsoleWrite("x");
                WriteU64Dec(d.rects[i].height);
                ConsoleWrite(" @ (");
                WriteU64Dec(d.rects[i].x);
                ConsoleWrite(",");
                WriteU64Dec(d.rects[i].y);
                ConsoleWriteln(")");
            }
        }
        else
        {
            ConsoleWriteln("virtio-gpu displays: GET_DISPLAY_INFO not issued or failed");
        }

        const auto& sc = duetos::drivers::gpu::VirtioGpuScanoutInfo();
        if (sc.ready)
        {
            ConsoleWrite("virtio-gpu scanout ");
            WriteU64Dec(sc.scanout_id);
            ConsoleWrite(": resource=");
            WriteU64Dec(sc.resource_id);
            ConsoleWrite(" ");
            WriteU64Dec(sc.width);
            ConsoleWrite("x");
            WriteU64Dec(sc.height);
            ConsoleWrite("x32 BGRA  backing phys=");
            WriteU64Hex(sc.backing_phys, 0);
            ConsoleWrite(" / ");
            WriteU64Dec(sc.backing_bytes);
            ConsoleWriteln(" B");
        }
    }
}

void CmdGfx()
{
    // Surfaces the graphics ICD handle-table counters. The ICD is
    // a trace-only skeleton today (see subsystems/graphics/graphics.h),
    // so in the steady state all counts are zero unless something
    // has exercised the Vk*/D3D*/DXGI entry points.
    const auto s = duetos::subsystems::graphics::GraphicsStatsRead();
    ConsoleWriteln("Graphics ICD (skeleton — no real driver)");
    ConsoleWrite("  Vulkan instances: live=");
    WriteU64Dec(s.vk_instances_live);
    ConsoleWrite(" created=");
    WriteU64Dec(s.vk_instances_created);
    ConsoleWrite(" destroyed=");
    WriteU64Dec(s.vk_instances_destroyed);
    ConsoleWriteChar('\n');
    ConsoleWrite("  Vulkan devices:   live=");
    WriteU64Dec(s.vk_devices_live);
    ConsoleWrite(" created=");
    WriteU64Dec(s.vk_devices_created);
    ConsoleWrite(" destroyed=");
    WriteU64Dec(s.vk_devices_destroyed);
    ConsoleWriteChar('\n');
    ConsoleWrite("  D3D create calls: ");
    WriteU64Dec(s.d3d_create_calls);
    ConsoleWriteChar('\n');
    ConsoleWrite("  DXGI create calls: ");
    WriteU64Dec(s.dxgi_create_calls);
    ConsoleWriteChar('\n');

    const u64 ngpu = duetos::drivers::gpu::GpuCount();
    ConsoleWrite("  Physical devices visible to ICD: ");
    WriteU64Dec(ngpu);
    ConsoleWriteChar('\n');
}

// Parse a decimal u32 from `s` into `*out`. Returns true on full
// success. Accepts 1..5 digits (0..65535), which covers every
// reasonable display dimension.
bool ParseU16Decimal(const char* s, u16* out)
{
    if (s == nullptr || *s == '\0')
        return false;
    u32 v = 0;
    for (u32 i = 0; s[i] != '\0'; ++i)
    {
        if (s[i] < '0' || s[i] > '9')
            return false;
        v = v * 10 + u32(s[i] - '0');
        if (v > 0xFFFFu)
            return false;
    }
    *out = u16(v);
    return true;
}

void CmdVbe(u32 argc, char** argv)
{
    using duetos::drivers::gpu::VbeCaps;
    using duetos::drivers::gpu::VbeQuery;
    using duetos::drivers::gpu::VbeSetMode;

    if (argc == 1)
    {
        const VbeCaps c = VbeQuery();
        if (!c.present)
        {
            ConsoleWriteln("VBE: not present (no Bochs / BGA-compatible GPU found)");
            return;
        }
        ConsoleWrite("VBE: id=0xB0C");
        WriteU64Hex(c.version, 1);
        ConsoleWrite("  current=");
        WriteU64Dec(c.cur_xres);
        ConsoleWrite("x");
        WriteU64Dec(c.cur_yres);
        ConsoleWrite("x");
        WriteU64Dec(c.cur_bpp);
        ConsoleWrite(c.enabled ? " LIVE" : " DISABLED");
        ConsoleWrite("  max=");
        WriteU64Dec(c.max_xres);
        ConsoleWrite("x");
        WriteU64Dec(c.max_yres);
        ConsoleWrite("x");
        WriteU64Dec(c.max_bpp);
        ConsoleWriteChar('\n');
        ConsoleWriteln("Usage: vbe <width> <height> [bpp]   — set mode (bpp defaults to 32)");
        ConsoleWriteln("       vbe                          — show current + max");
        ConsoleWriteln("NOTE: mode-set programs the controller; the framebuffer driver");
        ConsoleWriteln("      keeps its original layout until the compositor rewires.");
        return;
    }

    if (argc < 3)
    {
        ConsoleWriteln("VBE: usage: vbe [width height [bpp]]");
        return;
    }
    u16 width = 0, height = 0, bpp = 32;
    if (!ParseU16Decimal(argv[1], &width) || !ParseU16Decimal(argv[2], &height))
    {
        ConsoleWriteln("VBE: width/height must be decimal integers");
        return;
    }
    if (argc >= 4 && !ParseU16Decimal(argv[3], &bpp))
    {
        ConsoleWriteln("VBE: bpp must be decimal (8, 15, 16, 24, or 32)");
        return;
    }
    if (VbeSetMode(width, height, bpp))
    {
        ConsoleWrite("VBE: mode set OK — ");
        WriteU64Dec(width);
        ConsoleWrite("x");
        WriteU64Dec(height);
        ConsoleWrite("x");
        WriteU64Dec(bpp);
        ConsoleWriteln("");

        // Rebind the kernel framebuffer driver to the Bochs-
        // stdvga BAR0 at the new dimensions so subsequent
        // paints land at the requested resolution. Find the
        // Bochs GPU in the discovery cache — BAR0 is the
        // linear framebuffer aperture.
        u64 lfb_phys = 0;
        const u64 gn = duetos::drivers::gpu::GpuCount();
        for (u64 i = 0; i < gn; ++i)
        {
            const auto& g = duetos::drivers::gpu::Gpu(i);
            if (g.vendor_id == duetos::drivers::gpu::kVendorQemuBochs && g.mmio_phys != 0)
            {
                lfb_phys = g.mmio_phys;
                break;
            }
        }
        if (lfb_phys == 0)
        {
            ConsoleWriteln("VBE: hardware programmed, but no Bochs BAR0 found — fb not rebound");
            return;
        }
        const u32 pitch = static_cast<u32>(width) * 4;
        if (duetos::drivers::video::FramebufferRebind(lfb_phys, width, height, pitch, static_cast<u8>(bpp)))
        {
            duetos::drivers::video::FramebufferClear(0);
            ConsoleWriteln("VBE: framebuffer rebound; next recompose paints at the new size");
            ConsoleWriteln("     (overlay widgets retain boot-time positions — known limitation)");
        }
        else
        {
            ConsoleWriteln("VBE: hardware programmed, but framebuffer rebind failed");
        }
    }
    else
    {
        ConsoleWriteln("VBE: mode-set rejected (dimensions exceed max, bpp unsupported, or no BGA)");
    }
}

// Parse dotted-quad `a.b.c.d`. Returns true on exact 4-octet match.
bool ParseIpv4(const char* s, duetos::net::Ipv4Address* out)
{
    u32 parts[4] = {};
    u32 idx = 0;
    u32 cur = 0;
    bool had_digit = false;
    for (u32 i = 0;; ++i)
    {
        const char c = s[i];
        if (c == '\0' || c == '.')
        {
            if (!had_digit)
                return false;
            if (idx >= 4)
                return false;
            parts[idx++] = cur;
            cur = 0;
            had_digit = false;
            if (c == '\0')
                break;
            continue;
        }
        if (c < '0' || c > '9')
            return false;
        cur = cur * 10 + u32(c - '0');
        if (cur > 255)
            return false;
        had_digit = true;
    }
    if (idx != 4)
        return false;
    for (u32 i = 0; i < 4; ++i)
        out->octets[i] = u8(parts[i]);
    return true;
}

void CmdPing(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("PING: usage: ping <ipv4>");
        return;
    }
    duetos::net::Ipv4Address dst = {};
    if (!ParseIpv4(argv[1], &dst))
    {
        ConsoleWriteln("PING: malformed IPv4 (expected dotted-quad)");
        return;
    }
    // Pick a deterministic id/seq so repeats are diagnosable from
    // a pcap — id changes per ping cycle, seq stays 1.
    static u16 next_id = 0x0100;
    const u16 id = next_id++;
    const u16 seq = 1;
    duetos::net::NetPingArm(id, seq);
    if (!duetos::net::NetIcmpSendEcho(/*iface_index=*/0, dst, id, seq))
    {
        ConsoleWriteln("PING: send failed (ARP cache miss? try reaching a peer first)");
        return;
    }
    // Wait up to ~1 second (100 ticks at 100 Hz) for a reply.
    // The ICMP RX path runs from the e1000 RX polling task, so
    // we just yield + poll.
    for (u32 i = 0; i < 100; ++i)
    {
        duetos::sched::SchedSleepTicks(1);
        const auto r = duetos::net::NetPingRead();
        if (r.replied)
        {
            ConsoleWrite("PING: reply from ");
            for (u64 j = 0; j < 4; ++j)
            {
                if (j != 0)
                    ConsoleWriteChar('.');
                WriteU64Dec(r.from.octets[j]);
            }
            ConsoleWrite("  rtt~=");
            WriteU64Dec(r.rtt_ticks * 10); // 100 Hz tick = 10 ms
            ConsoleWriteln("ms");
            return;
        }
    }
    ConsoleWriteln("PING: no reply within 1s");
}

void CmdHttp(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("HTTP: usage: http <ipv4> [port [path]]");
        return;
    }
    duetos::net::Ipv4Address dst = {};
    if (!ParseIpv4(argv[1], &dst))
    {
        ConsoleWriteln("HTTP: malformed IPv4");
        return;
    }
    u16 port = 80;
    if (argc >= 3)
    {
        u16 p = 0;
        if (!ParseU16Decimal(argv[2], &p))
        {
            ConsoleWriteln("HTTP: malformed port");
            return;
        }
        port = p;
    }
    const char* path = "/";
    if (argc >= 4)
        path = argv[3];

    // Build GET request. Host header uses the dotted-quad string
    // the caller passed in since we don't (yet) track reverse
    // DNS. Minimal HTTP/1.0 so we don't need keep-alive handling.
    char req[512];
    u32 ri = 0;
    auto put = [&](const char* s)
    {
        while (*s && ri + 1 < sizeof(req))
            req[ri++] = *s++;
    };
    put("GET ");
    put(path);
    put(" HTTP/1.0\r\nHost: ");
    put(argv[1]);
    put("\r\nConnection: close\r\n\r\n");

    if (!duetos::net::NetTcpConnect(/*iface_index=*/0, dst, port, reinterpret_cast<const u8*>(req), ri))
    {
        ConsoleWriteln("HTTP: connect failed (slot busy / ARP miss / oversized req)");
        return;
    }
    ConsoleWrite("HTTP: connecting to ");
    ConsoleWrite(argv[1]);
    ConsoleWriteln(" ...");

    // Poll up to 4 s for the response to arrive + FIN.
    for (u32 i = 0; i < 400; ++i)
    {
        duetos::sched::SchedSleepTicks(1);
        const auto s = duetos::net::NetTcpActiveSnapshot();
        if (s.response_complete)
        {
            // Print the captured bytes.
            u8 buf[2048];
            const u32 n = duetos::net::NetTcpActiveRead(buf, sizeof(buf));
            ConsoleWrite("HTTP: ");
            WriteU64Dec(n);
            ConsoleWriteln(" bytes received");
            // Print the first ~16 lines of the response so the
            // user can see headers + a bit of body.
            u32 lines = 0;
            for (u32 j = 0; j < n && lines < 16; ++j)
            {
                const char c = static_cast<char>(buf[j]);
                if (c == '\n')
                    ++lines;
                if (c == '\r')
                    continue;
                if (c == '\n' || (c >= 0x20 && c <= 0x7E))
                    ConsoleWriteChar(c);
            }
            ConsoleWriteln("");
            return;
        }
    }
    ConsoleWriteln("HTTP: no complete response within 4s");
}

void CmdNtp(u32 argc, char** argv)
{
    // QEMU SLIRP doesn't run its own NTP server; callers pointing
    // here need an IP SLIRP will forward to. Public stratum-1/2
    // servers on UDP/123 work when SLIRP's outbound-UDP path is
    // open (the default).
    duetos::net::Ipv4Address server{{216, 239, 35, 0}}; // Google time1.google.com
    if (argc >= 2 && !ParseIpv4(argv[1], &server))
    {
        ConsoleWriteln("NTP: malformed server IP");
        return;
    }
    if (!duetos::net::NetNtpQuery(/*iface_index=*/0, server))
    {
        ConsoleWriteln("NTP: send failed (ARP miss for server + gateway)");
        return;
    }
    for (u32 i = 0; i < 200; ++i) // up to ~2 s
    {
        duetos::sched::SchedSleepTicks(1);
        const auto r = duetos::net::NetNtpResultRead();
        if (r.synced)
        {
            ConsoleWrite("NTP: unix_secs=");
            WriteU64Dec(r.unix_secs);
            ConsoleWrite("  stratum=");
            WriteU64Dec(r.stratum);
            ConsoleWriteln("");
            // Rough UTC decode — pure second division; no month /
            // leap-year handling. Proves the epoch is sane enough
            // to surface a recognisable time.
            const u64 rem = r.unix_secs % 86400;
            const u64 h = rem / 3600;
            const u64 m = (rem / 60) % 60;
            const u64 s = rem % 60;
            ConsoleWrite("NTP: ~ ");
            if (h < 10)
                ConsoleWriteChar('0');
            WriteU64Dec(h);
            ConsoleWriteChar(':');
            if (m < 10)
                ConsoleWriteChar('0');
            WriteU64Dec(m);
            ConsoleWriteChar(':');
            if (s < 10)
                ConsoleWriteChar('0');
            WriteU64Dec(s);
            ConsoleWriteln(" UTC (time-of-day)");
            return;
        }
    }
    ConsoleWriteln("NTP: no response within 2s (SLIRP UDP/123 blocked? server down?)");
}

void CmdNslookup(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("NSLOOKUP: usage: nslookup <name> [resolver_ip]");
        return;
    }
    duetos::net::Ipv4Address resolver{{10, 0, 2, 3}}; // QEMU SLIRP default
    if (argc >= 3 && !ParseIpv4(argv[2], &resolver))
    {
        ConsoleWriteln("NSLOOKUP: malformed resolver IP");
        return;
    }
    if (!duetos::net::NetDnsQueryA(/*iface_index=*/0, resolver, argv[1]))
    {
        ConsoleWriteln("NSLOOKUP: send failed (ARP miss, name too long, or no iface)");
        return;
    }
    for (u32 i = 0; i < 200; ++i) // wait up to ~2 seconds
    {
        duetos::sched::SchedSleepTicks(1);
        const auto r = duetos::net::NetDnsResultRead();
        if (r.resolved)
        {
            ConsoleWrite("NSLOOKUP: ");
            ConsoleWrite(argv[1]);
            ConsoleWrite(" -> ");
            for (u64 j = 0; j < 4; ++j)
            {
                if (j != 0)
                    ConsoleWriteChar('.');
                WriteU64Dec(r.ip.octets[j]);
            }
            ConsoleWriteln("");
            return;
        }
    }
    ConsoleWriteln("NSLOOKUP: no response within 2s (NXDOMAIN, no route, or server down)");
}

void CmdNic()
{
    const u64 n = duetos::drivers::net::NicCount();
    if (n == 0)
    {
        ConsoleWriteln("NIC: (none discovered)");
        return;
    }
    for (u64 i = 0; i < n; ++i)
    {
        const auto& nic = duetos::drivers::net::Nic(i);
        ConsoleWrite("NIC ");
        WriteU64Dec(i);
        ConsoleWrite(": vid=");
        WriteU64Hex(nic.vendor_id, 4);
        ConsoleWrite(" did=");
        WriteU64Hex(nic.device_id, 4);
        ConsoleWrite("  vendor=");
        ConsoleWrite(nic.vendor);
        if (nic.family != nullptr)
        {
            ConsoleWrite(" family=");
            ConsoleWrite(nic.family);
        }
        if (nic.mac_valid)
        {
            ConsoleWrite(" mac=");
            for (u64 b = 0; b < 6; ++b)
            {
                if (b != 0)
                    ConsoleWrite(":");
                WriteU64Hex(nic.mac[b], 2);
            }
            ConsoleWrite(nic.link_up ? " link=UP" : " link=DOWN");
        }
        ConsoleWriteChar('\n');
    }
}

// Print "a.b.c.d" — used by every networking command that wants to
// surface IPs without each one re-implementing the dotted-quad
// formatter. Zero-tolerance for tabs (kernel console is fixed-width).
void WriteIpv4(duetos::net::Ipv4Address ip)
{
    for (u64 i = 0; i < 4; ++i)
    {
        if (i != 0)
            ConsoleWriteChar('.');
        WriteU64Dec(ip.octets[i]);
    }
}

void WriteMac(const duetos::u8 mac[6])
{
    for (u64 i = 0; i < 6; ++i)
    {
        if (i != 0)
            ConsoleWriteChar(':');
        WriteU64Hex(mac[i], 2);
    }
}

bool Ipv4IsZero(duetos::net::Ipv4Address ip)
{
    for (u64 i = 0; i < 4; ++i)
        if (ip.octets[i] != 0)
            return false;
    return true;
}

// Comprehensive per-interface dump — combines driver-layer NIC info
// (vendor / family / link state / MAC), stack-layer binding (IPv4
// address actually in use) and DHCP lease state (router / DNS /
// lease seconds) on one report. The shell `nic` command is the
// minimal driver-only view; this is the one the user runs when
// they want "what's my IP, am I online, who's my gateway".
void CmdIfconfig()
{
    const duetos::u64 nics = duetos::drivers::net::NicCount();
    if (nics == 0)
    {
        ConsoleWriteln("IFCONFIG: no network interfaces (no PCI NICs discovered)");
        ConsoleWriteln("         (Wi-Fi adapters need a vendor driver — none online yet)");
        return;
    }
    for (duetos::u64 i = 0; i < nics; ++i)
    {
        const auto& nic = duetos::drivers::net::Nic(i);
        const bool bound = duetos::net::InterfaceIsBound(static_cast<duetos::u32>(i));
        ConsoleWrite("net");
        WriteU64Dec(i);
        ConsoleWrite("  ");
        ConsoleWrite(nic.vendor);
        if (nic.family != nullptr)
        {
            ConsoleWriteChar(' ');
            ConsoleWrite(nic.family);
        }
        ConsoleWriteln("");
        ConsoleWrite("       link    ");
        ConsoleWriteln(nic.mac_valid && nic.link_up ? "UP" : "DOWN");
        if (nic.mac_valid)
        {
            ConsoleWrite("       ether   ");
            WriteMac(nic.mac);
            ConsoleWriteln("");
        }
        if (bound)
        {
            const auto ip = duetos::net::InterfaceIp(static_cast<duetos::u32>(i));
            ConsoleWrite("       inet    ");
            WriteIpv4(ip);
            if (Ipv4IsZero(ip))
                ConsoleWriteln(" (waiting for DHCP)");
            else
                ConsoleWriteln("");
        }
        else
        {
            ConsoleWriteln("       inet    (not bound to stack — driver hasn't called bind yet)");
        }
        // Lease detail (DHCP is single-iface in v0; only print on the
        // interface that owns the lease).
        const auto lease = duetos::net::DhcpLeaseRead();
        if (bound && lease.valid)
        {
            ConsoleWrite("       gateway ");
            WriteIpv4(lease.router);
            ConsoleWriteln("");
            ConsoleWrite("       dns     ");
            WriteIpv4(lease.dns);
            ConsoleWriteln("");
            ConsoleWrite("       dhcp    server=");
            WriteIpv4(lease.server);
            ConsoleWrite("  lease=");
            WriteU64Dec(lease.lease_secs);
            ConsoleWriteln("s");
        }
    }
    ConsoleWrite("ARP cache: ");
    WriteU64Dec(duetos::net::ArpEntryCount());
    ConsoleWriteln(" live entries");
}

// Pure-status dump for the DHCP lease. `dhcp` shows; `dhcp renew`
// kicks a fresh DISCOVER on iface 0. Renewal is a one-shot — the
// stack's DhcpStart resets the state machine + sends DISCOVER, so
// calling it again from the shell is idempotent.
void CmdDhcp(duetos::u32 argc, char** argv)
{
    if (argc >= 2 && (StrEq(argv[1], "renew") || StrEq(argv[1], "request") || StrEq(argv[1], "start")))
    {
        if (!duetos::net::InterfaceIsBound(0))
        {
            ConsoleWriteln("DHCP: iface 0 not bound (no NIC driver online?)");
            return;
        }
        if (!duetos::net::DhcpStart(0))
        {
            ConsoleWriteln("DHCP: start failed (transaction already in flight?)");
            return;
        }
        ConsoleWriteln("DHCP: DISCOVER sent — wait ~1s then re-run `dhcp` for the bound IP");
        // Best-effort wait so the user sees the result without a
        // second command. SLIRP replies in a few ms; real hardware
        // takes longer. We poll up to ~2s.
        for (duetos::u32 i = 0; i < 200; ++i)
        {
            duetos::sched::SchedSleepTicks(1);
            const auto poll = duetos::net::DhcpLeaseRead();
            if (poll.valid)
                break;
        }
    }
    const auto lease = duetos::net::DhcpLeaseRead();
    if (!lease.valid)
    {
        ConsoleWriteln("DHCP: no lease (server didn't respond, or transaction in flight)");
        ConsoleWriteln("      try: `dhcp renew`");
        return;
    }
    ConsoleWrite("DHCP: bound  ip=");
    WriteIpv4(lease.ip);
    ConsoleWriteln("");
    ConsoleWrite("      gateway=");
    WriteIpv4(lease.router);
    ConsoleWriteln("");
    ConsoleWrite("      dns    =");
    WriteIpv4(lease.dns);
    ConsoleWriteln("");
    ConsoleWrite("      server =");
    WriteIpv4(lease.server);
    ConsoleWriteln("");
    ConsoleWrite("      lease  =");
    WriteU64Dec(lease.lease_secs);
    ConsoleWriteln(" sec");
}

// Default-route view derived from the DHCP lease + ARP cache state.
// `route -v` (any extra arg) does an ARP lookup against the gateway
// to confirm L2 reachability without sending a packet.
void CmdRoute(duetos::u32 argc, char** argv)
{
    (void)argv;
    const auto lease = duetos::net::DhcpLeaseRead();
    if (!lease.valid)
    {
        ConsoleWriteln("ROUTE: no default route (DHCP not bound — try `dhcp renew`)");
        return;
    }
    ConsoleWrite("default via ");
    WriteIpv4(lease.router);
    ConsoleWrite(" dev net0  src ");
    WriteIpv4(lease.ip);
    ConsoleWriteln("");
    ConsoleWrite("DNS via ");
    WriteIpv4(lease.dns);
    ConsoleWriteln("");
    if (argc < 2)
        return;
    const auto* arp = duetos::net::ArpLookup(0, lease.router);
    ConsoleWrite("gateway L2: ");
    if (arp == nullptr)
    {
        ConsoleWriteln("not in ARP cache (peer hasn't replied to ARP yet)");
        return;
    }
    WriteMac(arp->mac.octets);
    ConsoleWriteln("  (ARP cached)");
}

// "List networks I can connect to". Today: walks every PCI NIC, lists
// wired link state. Wi-Fi is honest — we don't have a wireless driver
// online, so SSID scanning isn't possible; we say so explicitly
// instead of pretending the empty list means "no networks".
void CmdNetscan()
{
    const duetos::u64 nics = duetos::drivers::net::NicCount();
    bool any_wifi = false;
    bool any_eth = false;
    for (duetos::u64 i = 0; i < nics; ++i)
    {
        const auto& nic = duetos::drivers::net::Nic(i);
        // PCI subclass 0x80 ("other") is what the ath9k / iwlwifi /
        // rtl88xx wireless families historically advertise. Real
        // wireless NICs would also expose family strings starting
        // with "iwlwifi" / "rtl8821" — match either.
        const bool wifiish = nic.subclass == 0x80 || (nic.family != nullptr && (StrStartsWith(nic.family, "iwlwifi") ||
                                                                                StrStartsWith(nic.family, "rtl8821") ||
                                                                                StrStartsWith(nic.family, "bcm4")));
        if (wifiish)
            any_wifi = true;
        else
            any_eth = true;
    }
    ConsoleWriteln("WIRELESS NETWORKS:");
    if (any_wifi)
    {
        const auto wifi = duetos::drivers::net::WirelessStatusRead();
        if (wifi.drivers_online > 0)
        {
            ConsoleWrite("  wireless driver shell online for ");
            WriteU64Dec(wifi.drivers_online);
            ConsoleWrite(" of ");
            WriteU64Dec(wifi.adapters_detected);
            ConsoleWriteln(" adapter(s)");
            ConsoleWrite("  firmware: ready=");
            WriteU64Dec(wifi.firmware_ready);
            ConsoleWrite(" missing=");
            WriteU64Dec(wifi.firmware_missing);
            ConsoleWrite(" incompatible=");
            WriteU64Dec(wifi.firmware_incompatible);
            ConsoleWrite(" load-error=");
            WriteU64Dec(wifi.firmware_load_error);
            ConsoleWriteln("");
            if (wifi.firmware_ready == 0)
            {
                ConsoleWriteln("  cannot scan SSIDs yet: no wireless adapter has a usable firmware blob loaded");
            }
            else
            {
                ConsoleWriteln(
                    "  firmware ready on at least one adapter; 802.11 scan/assoc datapath is still not implemented");
            }
        }
        else
        {
            ConsoleWriteln("  wireless adapter detected, but driver shell did not bind");
            ConsoleWriteln("  (device ID outside iwlwifi / rtl88xx / bcm43xx match tables)");
        }
    }
    else
    {
        ConsoleWriteln("  (no wireless adapter detected)");
    }
    ConsoleWriteln("WIRED NETWORKS:");
    if (!any_eth)
    {
        ConsoleWriteln("  (no wired adapter detected)");
        return;
    }
    for (duetos::u64 i = 0; i < nics; ++i)
    {
        const auto& nic = duetos::drivers::net::Nic(i);
        if (nic.subclass == 0x80)
            continue;
        ConsoleWrite("  net");
        WriteU64Dec(i);
        ConsoleWrite("  ");
        ConsoleWrite(nic.vendor);
        if (nic.family != nullptr)
        {
            ConsoleWriteChar(' ');
            ConsoleWrite(nic.family);
        }
        ConsoleWrite("  link=");
        ConsoleWrite(nic.mac_valid && nic.link_up ? "UP " : "DOWN ");
        if (duetos::net::InterfaceIsBound(static_cast<duetos::u32>(i)))
        {
            const auto ip = duetos::net::InterfaceIp(static_cast<duetos::u32>(i));
            if (!Ipv4IsZero(ip))
            {
                ConsoleWrite(" ip=");
                WriteIpv4(ip);
            }
        }
        ConsoleWriteln("");
    }
}

void CmdWifi(duetos::u32 argc, char** argv)
{
    if (argc < 2 || StrEq(argv[1], "status"))
    {
        const auto st = duetos::net::WifiStatusRead(0);
        ConsoleWrite("WIFI: iface0 backend=");
        ConsoleWrite(st.backend_present ? "yes" : "no");
        ConsoleWrite(" connected=");
        ConsoleWrite(st.connected ? "yes" : "no");
        if (st.connected)
        {
            ConsoleWrite(" ssid=\"");
            ConsoleWrite(st.ssid);
            ConsoleWrite("\" security=");
            ConsoleWrite(st.security == duetos::net::WifiSecurity::Wpa2Psk ? "wpa2-psk" : "open");
        }
        ConsoleWriteln("");
        if (!st.backend_present)
            ConsoleWriteln("WIFI: no registered Wi-Fi backend yet");
        return;
    }
    if (StrEq(argv[1], "scan"))
    {
        duetos::net::WifiScanResult results[duetos::net::kWifiMaxScanResults] = {};
        duetos::u32 count = 0;
        if (!duetos::net::WifiScan(0, results, duetos::net::kWifiMaxScanResults, &count))
        {
            ConsoleWriteln("WIFI: scan failed (backend unavailable or driver refused)");
            return;
        }
        ConsoleWrite("WIFI: ");
        WriteU64Dec(count);
        ConsoleWriteln(" network(s)");
        for (duetos::u32 i = 0; i < count; ++i)
        {
            ConsoleWrite("  ");
            ConsoleWrite(results[i].ssid);
            ConsoleWrite("  ");
            ConsoleWrite(results[i].security == duetos::net::WifiSecurity::Wpa2Psk ? "WPA2" : "OPEN");
            ConsoleWrite("  rssi=");
            WriteI64Dec(results[i].rssi_dbm);
            ConsoleWriteln(" dBm");
        }
        return;
    }
    if (StrEq(argv[1], "connect"))
    {
        if (argc < 3)
        {
            ConsoleWriteln("WIFI: usage: wifi connect <ssid> [psk]");
            return;
        }
        const char* ssid = argv[2];
        const bool has_psk = argc >= 4;
        const auto sec = has_psk ? duetos::net::WifiSecurity::Wpa2Psk : duetos::net::WifiSecurity::Open;
        const char* psk = has_psk ? argv[3] : nullptr;
        if (!duetos::net::WifiConnect(0, ssid, sec, psk))
        {
            ConsoleWriteln("WIFI: connect failed (backend missing, invalid auth, or driver rejected)");
            return;
        }
        ConsoleWriteln("WIFI: associated; requesting DHCP lease ...");
        if (!duetos::net::DhcpStart(0))
        {
            ConsoleWriteln("WIFI: DHCP start failed");
            return;
        }
        duetos::net::DhcpLease lease = {};
        for (duetos::u32 i = 0; i < 300; ++i)
        {
            duetos::sched::SchedSleepTicks(1);
            lease = duetos::net::DhcpLeaseRead();
            if (lease.valid)
                break;
        }
        if (!lease.valid)
        {
            ConsoleWriteln("WIFI: no DHCP ACK");
            return;
        }
        ConsoleWrite("WIFI: connected ip=");
        WriteIpv4(lease.ip);
        ConsoleWrite(" gw=");
        WriteIpv4(lease.router);
        ConsoleWriteln("");
        return;
    }
    if (StrEq(argv[1], "disconnect"))
    {
        if (!duetos::net::WifiDisconnect(0))
        {
            ConsoleWriteln("WIFI: disconnect failed (backend unavailable or driver refused)");
            return;
        }
        ConsoleWriteln("WIFI: disconnected");
        return;
    }
    ConsoleWriteln("WIFI: usage: wifi <status|scan|connect|disconnect>");
}

void CmdFwPolicy(duetos::u32 argc, char** argv)
{
    auto policy_name = [](duetos::core::FwSourcePolicy p) -> const char*
    {
        switch (p)
        {
        case duetos::core::FwSourcePolicy::OpenThenVendor:
            return "open-then-vendor";
        case duetos::core::FwSourcePolicy::OpenOnly:
            return "open-only";
        case duetos::core::FwSourcePolicy::VendorOnly:
            return "vendor-only";
        default:
            return "unknown";
        }
    };

    if (argc < 2 || StrEq(argv[1], "status"))
    {
        const auto s = duetos::core::FwBackendStatsRead();
        ConsoleWrite("FWPOLICY: ");
        ConsoleWrite(policy_name(s.policy));
        ConsoleWrite("  backend=");
        ConsoleWrite(s.kind == duetos::core::FwBackendKind::Vfs ? "vfs" : "none");
        ConsoleWrite("  lookups=");
        WriteU64Dec(s.lookups);
        ConsoleWrite("  hits=");
        WriteU64Dec(s.hits);
        ConsoleWrite("  misses=");
        WriteU64Dec(s.misses);
        ConsoleWriteln("");
        return;
    }

    if (StrEq(argv[1], "open-only"))
    {
        duetos::core::FwSetSourcePolicy(duetos::core::FwSourcePolicy::OpenOnly);
        ConsoleWriteln("FWPOLICY: set to open-only");
        return;
    }
    if (StrEq(argv[1], "vendor-only"))
    {
        duetos::core::FwSetSourcePolicy(duetos::core::FwSourcePolicy::VendorOnly);
        ConsoleWriteln("FWPOLICY: set to vendor-only");
        return;
    }
    if (StrEq(argv[1], "open-then-vendor"))
    {
        duetos::core::FwSetSourcePolicy(duetos::core::FwSourcePolicy::OpenThenVendor);
        ConsoleWriteln("FWPOLICY: set to open-then-vendor");
        return;
    }
    ConsoleWriteln("FWPOLICY: usage: fwpolicy <status|open-only|open-then-vendor|vendor-only>");
}

void CmdFwTrace(duetos::u32 argc, char** argv)
{
    if (argc >= 2 && StrEq(argv[1], "clear"))
    {
        duetos::core::FwTraceClear();
        ConsoleWriteln("FWTRACE: cleared");
        return;
    }

    duetos::u32 limit = duetos::core::FwTraceCount();
    if (argc >= 3 && StrEq(argv[1], "show"))
    {
        const duetos::i64 parsed = ParseInt(argv[2]);
        if (parsed > 0)
            limit = static_cast<duetos::u32>(parsed);
    }

    const duetos::u32 count = duetos::core::FwTraceCount();
    if (count == 0)
    {
        ConsoleWriteln("FWTRACE: empty");
        return;
    }

    if (limit > count)
        limit = count;
    const duetos::u32 start = count - limit;
    ConsoleWrite("FWTRACE: showing ");
    WriteU64Dec(limit);
    ConsoleWrite(" of ");
    WriteU64Dec(count);
    ConsoleWriteln(" entries");
    for (duetos::u32 i = start; i < count; ++i)
    {
        duetos::core::FwTraceEntry e{};
        if (!duetos::core::FwTraceRead(i, &e))
            continue;
        ConsoleWrite("  [");
        WriteU64Dec(i);
        ConsoleWrite("] policy=");
        switch (e.policy)
        {
        case duetos::core::FwSourcePolicy::OpenOnly:
            ConsoleWrite("open-only");
            break;
        case duetos::core::FwSourcePolicy::VendorOnly:
            ConsoleWrite("vendor-only");
            break;
        default:
            ConsoleWrite("open-then-vendor");
            break;
        }
        ConsoleWrite(" result=");
        ConsoleWrite(duetos::core::ErrorCodeName(e.result));
        ConsoleWrite(" vendor=\"");
        ConsoleWrite(e.vendor);
        ConsoleWrite("\" base=\"");
        ConsoleWrite(e.basename);
        ConsoleWrite("\" path=\"");
        ConsoleWrite(e.attempted_path);
        ConsoleWriteln("\"");
    }
}

void CmdCrTrace(duetos::u32 argc, char** argv)
{
    if (argc >= 2 && StrEq(argv[1], "clear"))
    {
        duetos::core::CleanroomTraceClear();
        ConsoleWriteln("CRTRACE: cleared");
        return;
    }

    duetos::u32 limit = duetos::core::CleanroomTraceCount();
    if (argc >= 3 && StrEq(argv[1], "show"))
    {
        const duetos::i64 parsed = ParseInt(argv[2]);
        if (parsed > 0)
            limit = static_cast<duetos::u32>(parsed);
    }

    const duetos::u32 count = duetos::core::CleanroomTraceCount();
    if (count == 0)
    {
        ConsoleWriteln("CRTRACE: empty");
        return;
    }
    if (limit > count)
        limit = count;

    const duetos::u32 start = count - limit;
    ConsoleWrite("CRTRACE: showing ");
    WriteU64Dec(limit);
    ConsoleWrite(" of ");
    WriteU64Dec(count);
    ConsoleWriteln(" entries");
    duetos::arch::SerialWrite("\n=== CRTRACE DUMP BEGIN ===\n");
    for (duetos::u32 i = start; i < count; ++i)
    {
        duetos::core::CleanroomTraceEntry e{};
        if (!duetos::core::CleanroomTraceRead(i, &e))
            continue;
        ConsoleWrite("  [");
        WriteU64Dec(i);
        ConsoleWrite("] ");
        ConsoleWrite(e.subsystem);
        ConsoleWrite("::");
        ConsoleWrite(e.event);
        ConsoleWrite(" a=");
        WriteU64Hex(e.a);
        ConsoleWrite(" b=");
        WriteU64Hex(e.b);
        ConsoleWrite(" c=");
        WriteU64Hex(e.c);
        ConsoleWriteln("");
        duetos::arch::SerialWrite("CRTRACE [");
        duetos::arch::SerialWriteHex(i);
        duetos::arch::SerialWrite("] ");
        duetos::arch::SerialWrite(e.subsystem);
        duetos::arch::SerialWrite("::");
        duetos::arch::SerialWrite(e.event);
        duetos::core::CleanroomTraceWriteDecoded(e);
        duetos::arch::SerialWrite("\n");
    }
    duetos::arch::SerialWrite("=== CRTRACE DUMP END ===\n");
}

// `net` umbrella: sub-commands `up`, `status`, `test`. Each one is a
// thin wrapper around the existing primitives so the user has a
// single place to "bring the network up + verify it works" without
// memorising every command name.
//
//   net up     — ensure DHCP is bound (kicks DISCOVER if not)
//   net status — print brief one-line status
//   net test   — full end-to-end smoke: lease + ARP gateway + DNS
//                lookup of a known name + ICMP echo to gateway
void CmdNet(duetos::u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("NET: usage: net <up|status|test>");
        return;
    }
    if (StrEq(argv[1], "up"))
    {
        if (!duetos::net::InterfaceIsBound(0))
        {
            ConsoleWriteln("NET UP: iface 0 not bound (no NIC driver?)");
            return;
        }
        auto lease = duetos::net::DhcpLeaseRead();
        if (lease.valid)
        {
            ConsoleWrite("NET UP: already bound  ip=");
            WriteIpv4(lease.ip);
            ConsoleWriteln("");
            return;
        }
        if (!duetos::net::DhcpStart(0))
        {
            ConsoleWriteln("NET UP: DHCP start failed");
            return;
        }
        ConsoleWriteln("NET UP: DHCP DISCOVER sent ...");
        for (duetos::u32 i = 0; i < 300; ++i)
        {
            duetos::sched::SchedSleepTicks(1);
            lease = duetos::net::DhcpLeaseRead();
            if (lease.valid)
                break;
        }
        if (!lease.valid)
        {
            ConsoleWriteln("NET UP: timeout — no DHCP ACK in 3s");
            return;
        }
        ConsoleWrite("NET UP: bound  ip=");
        WriteIpv4(lease.ip);
        ConsoleWrite("  gw=");
        WriteIpv4(lease.router);
        ConsoleWrite("  dns=");
        WriteIpv4(lease.dns);
        ConsoleWriteln("");
        return;
    }
    if (StrEq(argv[1], "status"))
    {
        const auto lease = duetos::net::DhcpLeaseRead();
        const bool bound = duetos::net::InterfaceIsBound(0);
        ConsoleWrite("NET: iface0=");
        ConsoleWrite(bound ? "UP" : "DOWN");
        ConsoleWrite("  dhcp=");
        ConsoleWrite(lease.valid ? "BOUND" : "PENDING");
        if (lease.valid)
        {
            ConsoleWrite("  ip=");
            WriteIpv4(lease.ip);
            ConsoleWrite("  gw=");
            WriteIpv4(lease.router);
        }
        ConsoleWrite("  arp=");
        WriteU64Dec(duetos::net::ArpEntryCount());
        ConsoleWriteln("");
        return;
    }
    if (StrEq(argv[1], "test"))
    {
        // 1. DHCP lease present?
        ConsoleWrite("NET TEST: dhcp ... ");
        auto lease = duetos::net::DhcpLeaseRead();
        if (!lease.valid)
        {
            duetos::net::DhcpStart(0);
            for (duetos::u32 i = 0; i < 300; ++i)
            {
                duetos::sched::SchedSleepTicks(1);
                lease = duetos::net::DhcpLeaseRead();
                if (lease.valid)
                    break;
            }
        }
        if (!lease.valid)
        {
            ConsoleWriteln("FAIL (no lease)");
            return;
        }
        ConsoleWrite("OK ip=");
        WriteIpv4(lease.ip);
        ConsoleWriteln("");

        // 2. ARP-resolve the gateway by sending a probe ping. The
        //    ICMP TX path triggers ARP-resolve internally; on QEMU
        //    SLIRP the gateway replies to ARP from boot, so the
        //    cache is already warm. On real hardware this primes it.
        ConsoleWrite("NET TEST: gateway ARP ... ");
        const auto* arp = duetos::net::ArpLookup(0, lease.router);
        if (arp == nullptr)
        {
            // Send a single ICMP echo to force ARP request out.
            duetos::net::NetIcmpSendEcho(0, lease.router, 0xBEEF, 1);
            for (duetos::u32 i = 0; i < 100; ++i)
            {
                duetos::sched::SchedSleepTicks(1);
                arp = duetos::net::ArpLookup(0, lease.router);
                if (arp != nullptr)
                    break;
            }
        }
        if (arp == nullptr)
        {
            ConsoleWriteln("FAIL (gateway didn't reply to ARP)");
            return;
        }
        ConsoleWrite("OK mac=");
        WriteMac(arp->mac.octets);
        ConsoleWriteln("");

        // 3. DNS A-record query against the lease's resolver.
        ConsoleWrite("NET TEST: dns ... ");
        if (!duetos::net::NetDnsQueryA(0, lease.dns, "example.com"))
        {
            ConsoleWriteln("FAIL (send rejected)");
            return;
        }
        duetos::net::DnsResult dr{};
        for (duetos::u32 i = 0; i < 300; ++i)
        {
            duetos::sched::SchedSleepTicks(1);
            dr = duetos::net::NetDnsResultRead();
            if (dr.resolved)
                break;
        }
        if (!dr.resolved)
        {
            ConsoleWriteln("FAIL (no reply)");
            return;
        }
        ConsoleWrite("OK example.com -> ");
        WriteIpv4(dr.ip);
        ConsoleWriteln("");

        // 4. ICMP echo to the gateway as a final reachability probe.
        ConsoleWrite("NET TEST: ping gateway ... ");
        duetos::net::NetPingArm(0xCAFE, 1);
        if (!duetos::net::NetIcmpSendEcho(0, lease.router, 0xCAFE, 1))
        {
            ConsoleWriteln("FAIL (send rejected)");
            return;
        }
        duetos::net::PingResult pr{};
        for (duetos::u32 i = 0; i < 200; ++i)
        {
            duetos::sched::SchedSleepTicks(1);
            pr = duetos::net::NetPingRead();
            if (pr.replied)
                break;
        }
        if (!pr.replied)
        {
            ConsoleWriteln("FAIL (no echo reply)");
            return;
        }
        ConsoleWrite("OK rtt~=");
        WriteU64Dec(pr.rtt_ticks * 10);
        ConsoleWriteln("ms");
        ConsoleWriteln("NET TEST: PASS — DuetOS is online");
        return;
    }
    ConsoleWriteln("NET: usage: net <up|status|test>");
}

// Manual USB-Ethernet probe. The auto-probe path is gated off in
// kernel_main because it interacts badly with the pre-poll xHCI
// event-ring state and regresses the e1000 wired DHCP. Calling
// this from the shell after boot completes runs the probe in a
// stable scheduler context.
//
//   usbnet probe — try CDC-ECM then RNDIS; bind iface 1 on first hit
//   usbnet status — show whichever USB-net driver is online
void CmdUsbNet(duetos::u32 argc, char** argv)
{
    if (argc < 2 || StrEq(argv[1], "status"))
    {
        const auto cdc = duetos::drivers::usb::CdcEcmStatsRead();
        const auto rn = duetos::drivers::usb::RndisStatsRead();
        ConsoleWrite("USBNET: cdc-ecm=");
        ConsoleWrite(cdc.online ? "UP" : "down");
        ConsoleWrite("  rndis=");
        ConsoleWrite(rn.online ? "UP" : "down");
        if (cdc.online)
        {
            ConsoleWrite("  cdc-ecm-mac=");
            WriteMac(cdc.mac);
        }
        if (rn.online)
        {
            ConsoleWrite("  rndis-mac=");
            WriteMac(rn.mac);
        }
        ConsoleWriteln("");
        return;
    }
    if (StrEq(argv[1], "probe"))
    {
        ConsoleWriteln("USBNET: probing CDC-ECM ...");
        const bool cdc_ok = duetos::drivers::usb::CdcEcmProbe();
        if (cdc_ok)
        {
            ConsoleWriteln("USBNET: CDC-ECM bound on iface 1 — DHCP started");
            return;
        }
        ConsoleWriteln("USBNET: no CDC-ECM device. probing RNDIS ...");
        const bool rn_ok = duetos::drivers::usb::RndisProbe();
        if (rn_ok)
        {
            ConsoleWriteln("USBNET: RNDIS bound on iface 1 — DHCP started");
            return;
        }
        ConsoleWriteln("USBNET: no compatible USB-Ethernet device found "
                       "(supported: CDC-ECM, RNDIS — Android tether default)");
        return;
    }
    ConsoleWriteln("USBNET: usage: usbnet <probe|status>");
}

void CmdArp()
{
    const auto s = duetos::net::ArpStatsRead();
    ConsoleWrite("ARP HITS:       ");
    WriteU64Dec(s.lookups_hit);
    ConsoleWriteChar('\n');
    ConsoleWrite("ARP MISSES:     ");
    WriteU64Dec(s.lookups_miss);
    ConsoleWriteChar('\n');
    ConsoleWrite("ARP INSERTS:    ");
    WriteU64Dec(s.inserts);
    ConsoleWriteChar('\n');
    ConsoleWrite("ARP EVICTIONS:  ");
    WriteU64Dec(s.evictions);
    ConsoleWriteChar('\n');
    ConsoleWrite("ARP RX:         ");
    WriteU64Dec(s.rx_packets);
    ConsoleWriteChar('\n');
    ConsoleWrite("ARP REJECTS:    ");
    WriteU64Dec(s.rx_rejects);
    ConsoleWriteChar('\n');
}

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

// Forward decl — definition is later in the file (used by FAT commands).
bool ParseU64Str(const char* s, duetos::u64* out);

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

void CmdIpv4()
{
    const auto s = duetos::net::Ipv4StatsRead();
    ConsoleWrite("IPV4 RX:        ");
    WriteU64Dec(s.rx_packets);
    ConsoleWriteChar('\n');
    ConsoleWrite("IPV4 BAD VER:   ");
    WriteU64Dec(s.rx_bad_version);
    ConsoleWriteChar('\n');
    ConsoleWrite("IPV4 BAD IHL:   ");
    WriteU64Dec(s.rx_bad_ihl);
    ConsoleWriteChar('\n');
    ConsoleWrite("IPV4 BAD LEN:   ");
    WriteU64Dec(s.rx_bad_length);
    ConsoleWriteChar('\n');
    ConsoleWrite("IPV4 BAD CSUM:  ");
    WriteU64Dec(s.rx_bad_checksum);
    ConsoleWriteChar('\n');
    ConsoleWrite("IPV4 RX UDP:    ");
    WriteU64Dec(s.rx_udp);
    ConsoleWriteChar('\n');
    ConsoleWrite("IPV4 RX TCP:    ");
    WriteU64Dec(s.rx_tcp);
    ConsoleWriteChar('\n');
    ConsoleWrite("IPV4 RX ICMP:   ");
    WriteU64Dec(s.rx_icmp);
    ConsoleWriteChar('\n');
    ConsoleWrite("IPV4 RX OTHER:  ");
    WriteU64Dec(s.rx_other_proto);
    ConsoleWriteChar('\n');
}

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

void CmdGetenv(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("GETENV: USAGE: GETENV NAME");
        return;
    }
    const EnvSlot* s = EnvFind(argv[1]);
    if (s == nullptr)
    {
        ConsoleWriteln("(UNSET)");
        return;
    }
    ConsoleWriteln(s->value);
}

void CmdYield()
{
    // Voluntary yield from the shell thread — useful for testing
    // cooperative scheduling behaviour by hand. No output.
    duetos::sched::SchedYield();
}

void CmdUname(u32 argc, char** argv)
{
    // uname default: kernel name. -a prints everything.
    const bool all = (argc >= 2 && argv[1][0] == '-' && argv[1][1] == 'a');
    if (all)
    {
        ConsoleWrite("DuetOS duetos v0 x86_64  (tick ");
        WriteU64Dec(duetos::sched::SchedNowTicks());
        ConsoleWriteln(")");
    }
    else
    {
        ConsoleWriteln("DuetOS");
    }
}

void CmdWhoami()
{
    const char* name = AuthCurrentUserName();
    if (name[0] == '\0')
    {
        ConsoleWriteln("(no session)");
    }
    else
    {
        ConsoleWriteln(name);
    }
}

void CmdHostname()
{
    const EnvSlot* s = EnvFind("HOSTNAME");
    ConsoleWriteln((s != nullptr) ? s->value : "duetos");
}

void CmdPwd()
{
    // No per-process CWD yet; every path in the shell is
    // absolute against the trusted ramfs root. `pwd` prints
    // "/" so scripts that consult it don't break.
    ConsoleWriteln("/");
}

void CmdTrue()
{
    // No-op success — useful in scripts: `cmd && true`.
}

void CmdFalse()
{
    // No-op failure placeholder. No exit codes yet; the
    // visual-only marker prints nothing (matches /bin/false).
}

// CmdMount moved to shell_storage.cpp.

// Shared helper: parse decimal (default) or hex (0x prefix) into u64.
// Returns true + writes `*out` on success. Used by `read` + any future
// command taking a sector number / address.
bool ParseU64Str(const char* s, duetos::u64* out)
{
    if (s == nullptr || out == nullptr || s[0] == 0)
        return false;
    duetos::u64 v = 0;
    duetos::u32 base = 10;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
    {
        s += 2;
        base = 16;
    }
    if (*s == 0)
        return false;
    for (; *s != 0; ++s)
    {
        duetos::u64 d;
        if (*s >= '0' && *s <= '9')
            d = static_cast<duetos::u64>(*s - '0');
        else if (base == 16 && *s >= 'a' && *s <= 'f')
            d = static_cast<duetos::u64>(*s - 'a' + 10);
        else if (base == 16 && *s >= 'A' && *s <= 'F')
            d = static_cast<duetos::u64>(*s - 'A' + 10);
        else
            return false;
        v = v * base + d;
    }
    *out = v;
    return true;
}

// Convenience integer parser used by commands that take a small
// positive count (e.g. `crtrace show 64`). Returns the parsed
// value on success; any parse failure or value above i64-max
// returns 0 so the caller's `if (parsed > 0)` guard falls
// through to the default. Reuses ParseU64Str so decimal +
// 0x-hex syntax stay aligned across the shell.
duetos::i64 ParseInt(const char* s)
{
    duetos::u64 v = 0;
    if (!ParseU64Str(s, &v))
        return 0;
    if (v > 0x7FFFFFFFFFFFFFFFull)
        return 0;
    return static_cast<duetos::i64>(v);
}

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

void CmdFatls(duetos::u32 argc, char** argv)
{
    // `fatls [vol_idx]` — list root-directory entries from a
    // probed FAT32 volume. Default volume 0. Columns mirror the
    // boot-time self-test: name, attr, first_cluster, size.
    namespace fat = duetos::fs::fat32;
    u32 vol_idx = 0;
    if (argc >= 2)
    {
        duetos::u64 v = 0;
        if (!ParseU64Str(argv[1], &v) || v >= fat::Fat32VolumeCount())
        {
            ConsoleWriteln("FATLS: BAD VOLUME INDEX");
            return;
        }
        vol_idx = static_cast<u32>(v);
    }
    const fat::Volume* v = fat::Fat32Volume(vol_idx);
    if (v == nullptr)
    {
        ConsoleWriteln("FATLS: NO VOLUMES (did FAT32 self-test find one?)");
        return;
    }
    ConsoleWriteln("NAME          ATTR  FIRST_CLUSTER  SIZE");
    for (duetos::u32 i = 0; i < v->root_entry_count; ++i)
    {
        const fat::DirEntry& e = v->root_entries[i];
        ConsoleWrite(e.name);
        // Pad name column to 13 chars.
        duetos::u32 len = 0;
        while (e.name[len] != 0)
            ++len;
        for (duetos::u32 p = len; p < 13; ++p)
            ConsoleWriteChar(' ');
        ConsoleWriteChar(' ');
        WriteU64Hex(e.attributes, 2);
        ConsoleWrite("    ");
        WriteU64Hex(e.first_cluster, 8);
        ConsoleWriteChar(' ');
        WriteU64Hex(e.size_bytes, 8);
        ConsoleWriteln("");
    }
}

void CmdFatcat(duetos::u32 argc, char** argv)
{
    // `fatcat [vol_idx] <name>` — read the named file from a FAT32
    // volume and write it to the console. Caps at 4 KiB (one scratch
    // buffer) for v0; larger reads are a follow-up that streams in
    // chunks. Volume index is optional and defaults to 0.
    namespace fat = duetos::fs::fat32;
    if (argc < 2)
    {
        ConsoleWriteln("FATCAT: USAGE: FATCAT [VOL] NAME");
        return;
    }
    u32 vol_idx = 0;
    const char* name = argv[1];
    if (argc >= 3)
    {
        duetos::u64 v = 0;
        if (ParseU64Str(argv[1], &v) && v < fat::Fat32VolumeCount())
        {
            vol_idx = static_cast<u32>(v);
            name = argv[2];
        }
    }
    const fat::Volume* v = fat::Fat32Volume(vol_idx);
    if (v == nullptr)
    {
        ConsoleWriteln("FATCAT: NO SUCH VOLUME");
        return;
    }
    const fat::DirEntry* e = fat::Fat32FindInRoot(v, name);
    if (e == nullptr)
    {
        ConsoleWrite("FATCAT: NO SUCH FILE: ");
        ConsoleWriteln(name);
        return;
    }
    // Streamed; no size cap. Non-printable bytes collapse to '.'
    // so operator-driven cat doesn't spray garbage on the console.
    struct StreamCtx
    {
        u8 last_byte;
        bool any;
    };
    StreamCtx ctx{0, false};
    const bool ok = fat::Fat32ReadFileStream(
        v, e,
        [](const duetos::u8* data, duetos::u64 len, void* cx) -> bool
        {
            auto* s = static_cast<StreamCtx*>(cx);
            for (duetos::u64 i = 0; i < len; ++i)
            {
                const char c = static_cast<char>(data[i]);
                ConsoleWriteChar((c >= 0x20 && c <= 0x7E) || c == '\n' || c == '\r' || c == '\t' ? c : '.');
            }
            if (len > 0)
            {
                s->last_byte = data[len - 1];
                s->any = true;
            }
            return true;
        },
        &ctx);
    if (!ok)
    {
        ConsoleWriteln("FATCAT: READ ERROR");
        return;
    }
    if (!ctx.any || ctx.last_byte != '\n')
    {
        ConsoleWriteln("");
    }
}

void CmdFatwrite(duetos::u32 argc, char** argv)
{
    // `fatwrite <path> <offset> <bytes>` — overwrite existing file
    // bytes in-place. `<bytes>` is taken as a literal ASCII string
    // (joined with spaces if multiple tokens). No size change, no
    // extension — matches the driver's v0 Fat32WriteInPlace scope.
    // Handy for demonstrating the write path without a user-space
    // editor. Destructive: runs directly against sata0p1 / nvme0n1p1.
    namespace fat = duetos::fs::fat32;
    if (argc < 4)
    {
        ConsoleWriteln("FATWRITE: USAGE: FATWRITE PATH OFFSET BYTES...");
        return;
    }
    const char* path = argv[1];
    duetos::u64 off = 0;
    if (!ParseU64Str(argv[2], &off))
    {
        ConsoleWriteln("FATWRITE: BAD OFFSET");
        return;
    }
    // Join argv[3..argc-1] with single spaces to form the payload.
    static duetos::u8 payload[1024];
    duetos::u64 plen = 0;
    for (u32 i = 3; i < argc; ++i)
    {
        if (i > 3 && plen + 1 < sizeof(payload))
        {
            payload[plen++] = ' ';
        }
        for (u32 j = 0; argv[i][j] != 0 && plen + 1 < sizeof(payload); ++j)
        {
            payload[plen++] = static_cast<duetos::u8>(argv[i][j]);
        }
    }
    // Fat32LookupPath wants a volume-relative path; our shell sniff
    // expects a /fat-prefixed one. Accept either form here for
    // operator convenience.
    const char* leaf = FatLeaf(path);
    if (leaf == nullptr)
        leaf = (path[0] == '/') ? path + 1 : path;
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
    {
        ConsoleWriteln("FATWRITE: FAT32 NOT MOUNTED");
        return;
    }
    fat::DirEntry entry;
    if (!fat::Fat32LookupPath(v, leaf, &entry))
    {
        ConsoleWrite("FATWRITE: NO SUCH FILE: ");
        ConsoleWriteln(path);
        return;
    }
    if (entry.attributes & 0x10)
    {
        ConsoleWriteln("FATWRITE: PATH IS A DIRECTORY");
        return;
    }
    const duetos::i64 rc = fat::Fat32WriteInPlace(v, &entry, off, payload, plen);
    if (rc < 0)
    {
        ConsoleWriteln("FATWRITE: WRITE FAILED (offset+len > size? backend RO?)");
        return;
    }
    ConsoleWrite("FATWRITE: WROTE ");
    WriteU64Dec(static_cast<duetos::u64>(rc));
    ConsoleWrite(" BYTES AT OFFSET ");
    WriteU64Dec(off);
    ConsoleWriteln("");
}

void CmdFatappend(duetos::u32 argc, char** argv)
{
    // `fatappend <name> <bytes...>` — append the trailing argv
    // tokens (joined with single spaces) to the end of a file in
    // FAT32 volume 0's root. Grows the file; allocates clusters as
    // needed. v0 scope is root-dir only — no path walking, no
    // subdirectory targets. The image rebuilds every boot-smoke,
    // so any appends are ephemeral across test cycles.
    namespace fat = duetos::fs::fat32;
    if (argc < 3)
    {
        ConsoleWriteln("FATAPPEND: USAGE: FATAPPEND NAME BYTES...");
        return;
    }
    const char* name = argv[1];
    // Strip a leading /fat/ if the operator gave a mount-rooted
    // path, matching CmdFatwrite's convenience policy.
    if (const char* leaf = FatLeaf(name); leaf != nullptr && *leaf != '\0')
    {
        name = leaf;
    }
    else if (name[0] == '/')
    {
        ++name;
    }
    static duetos::u8 payload[1024];
    duetos::u64 plen = 0;
    for (u32 i = 2; i < argc; ++i)
    {
        if (i > 2 && plen + 1 < sizeof(payload))
        {
            payload[plen++] = ' ';
        }
        for (u32 j = 0; argv[i][j] != 0 && plen + 1 < sizeof(payload); ++j)
        {
            payload[plen++] = static_cast<duetos::u8>(argv[i][j]);
        }
    }
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
    {
        ConsoleWriteln("FATAPPEND: FAT32 NOT MOUNTED");
        return;
    }
    bool has_slash = false;
    for (u32 i = 0; name[i] != 0; ++i)
    {
        if (name[i] == '/')
        {
            has_slash = true;
            break;
        }
    }
    const duetos::i64 rc =
        has_slash ? fat::Fat32AppendAtPath(v, name, payload, plen) : fat::Fat32AppendInRoot(v, name, payload, plen);
    if (rc < 0)
    {
        ConsoleWriteln("FATAPPEND: APPEND FAILED (backend RO? disk full? file not in root?)");
        return;
    }
    ConsoleWrite("FATAPPEND: APPENDED ");
    WriteU64Dec(static_cast<duetos::u64>(rc));
    ConsoleWrite(" BYTES TO ");
    ConsoleWriteln(name);
}

void CmdFatnew(duetos::u32 argc, char** argv)
{
    // `fatnew <name> [bytes...]` — create a new root-dir file
    // with optional initial content (joined argv). Name must fit
    // in the 8.3 SFN encoding; anything longer is rejected.
    namespace fat = duetos::fs::fat32;
    if (argc < 2)
    {
        ConsoleWriteln("FATNEW: USAGE: FATNEW NAME [BYTES...]");
        return;
    }
    const char* name = argv[1];
    if (const char* leaf = FatLeaf(name); leaf != nullptr && *leaf != '\0')
    {
        name = leaf;
    }
    else if (name[0] == '/')
    {
        ++name;
    }
    static duetos::u8 payload[1024];
    duetos::u64 plen = 0;
    for (u32 i = 2; i < argc; ++i)
    {
        if (i > 2 && plen + 1 < sizeof(payload))
        {
            payload[plen++] = ' ';
        }
        for (u32 j = 0; argv[i][j] != 0 && plen + 1 < sizeof(payload); ++j)
        {
            payload[plen++] = static_cast<duetos::u8>(argv[i][j]);
        }
    }
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
    {
        ConsoleWriteln("FATNEW: FAT32 NOT MOUNTED");
        return;
    }
    bool has_slash = false;
    for (u32 i = 0; name[i] != 0; ++i)
    {
        if (name[i] == '/')
        {
            has_slash = true;
            break;
        }
    }
    const duetos::i64 rc =
        has_slash ? fat::Fat32CreateAtPath(v, name, payload, plen) : fat::Fat32CreateInRoot(v, name, payload, plen);
    if (rc < 0)
    {
        ConsoleWriteln("FATNEW: CREATE FAILED (bad name? exists? full dir? disk full?)");
        return;
    }
    ConsoleWrite("FATNEW: CREATED ");
    ConsoleWrite(name);
    ConsoleWrite(" (");
    WriteU64Dec(static_cast<duetos::u64>(rc));
    ConsoleWriteln(" BYTES)");
}

void CmdFatrm(duetos::u32 argc, char** argv)
{
    // `fatrm <name>` — delete a root-dir file. Frees its cluster
    // chain, marks the directory entry deleted.
    namespace fat = duetos::fs::fat32;
    if (argc < 2)
    {
        ConsoleWriteln("FATRM: USAGE: FATRM NAME");
        return;
    }
    const char* name = argv[1];
    if (const char* leaf = FatLeaf(name); leaf != nullptr && *leaf != '\0')
    {
        name = leaf;
    }
    else if (name[0] == '/')
    {
        ++name;
    }
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
    {
        ConsoleWriteln("FATRM: FAT32 NOT MOUNTED");
        return;
    }
    bool has_slash = false;
    for (u32 i = 0; name[i] != 0; ++i)
    {
        if (name[i] == '/')
        {
            has_slash = true;
            break;
        }
    }
    const bool ok = has_slash ? fat::Fat32DeleteAtPath(v, name) : fat::Fat32DeleteInRoot(v, name);
    if (!ok)
    {
        ConsoleWrite("FATRM: FAILED: ");
        ConsoleWriteln(name);
        return;
    }
    ConsoleWrite("FATRM: DELETED ");
    ConsoleWriteln(name);
}

void CmdFattrunc(duetos::u32 argc, char** argv)
{
    // `fattrunc <name> <new_size>` — shrink or grow a file to
    // `new_size` bytes. Growth pads with zeros.
    namespace fat = duetos::fs::fat32;
    if (argc < 3)
    {
        ConsoleWriteln("FATTRUNC: USAGE: FATTRUNC NAME NEW_SIZE");
        return;
    }
    const char* name = argv[1];
    if (const char* leaf = FatLeaf(name); leaf != nullptr && *leaf != '\0')
    {
        name = leaf;
    }
    else if (name[0] == '/')
    {
        ++name;
    }
    duetos::u64 new_size = 0;
    if (!ParseU64Str(argv[2], &new_size))
    {
        ConsoleWriteln("FATTRUNC: BAD SIZE");
        return;
    }
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
    {
        ConsoleWriteln("FATTRUNC: FAT32 NOT MOUNTED");
        return;
    }
    bool has_slash = false;
    for (u32 i = 0; name[i] != 0; ++i)
    {
        if (name[i] == '/')
        {
            has_slash = true;
            break;
        }
    }
    const duetos::i64 rc =
        has_slash ? fat::Fat32TruncateAtPath(v, name, new_size) : fat::Fat32TruncateInRoot(v, name, new_size);
    if (rc < 0)
    {
        ConsoleWriteln("FATTRUNC: FAILED");
        return;
    }
    ConsoleWrite("FATTRUNC: ");
    ConsoleWrite(name);
    ConsoleWrite(" -> ");
    WriteU64Dec(static_cast<duetos::u64>(rc));
    ConsoleWriteln(" BYTES");
}

void CmdFatmkdir(duetos::u32 argc, char** argv)
{
    // `fatmkdir <path>` — create a directory in FAT32 volume 0.
    namespace fat = duetos::fs::fat32;
    if (argc < 2)
    {
        ConsoleWriteln("FATMKDIR: USAGE: FATMKDIR PATH");
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
        ConsoleWriteln("FATMKDIR: FAT32 NOT MOUNTED");
        return;
    }
    if (!fat::Fat32MkdirAtPath(v, path))
    {
        ConsoleWrite("FATMKDIR: FAILED: ");
        ConsoleWriteln(path);
        return;
    }
    ConsoleWrite("FATMKDIR: CREATED ");
    ConsoleWriteln(path);
}

void CmdFatrmdir(duetos::u32 argc, char** argv)
{
    // `fatrmdir <path>` — remove an empty directory.
    namespace fat = duetos::fs::fat32;
    if (argc < 2)
    {
        ConsoleWriteln("FATRMDIR: USAGE: FATRMDIR PATH");
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
        ConsoleWriteln("FATRMDIR: FAT32 NOT MOUNTED");
        return;
    }
    if (!fat::Fat32RmdirAtPath(v, path))
    {
        ConsoleWriteln("FATRMDIR: FAILED (not a dir? not empty? not found?)");
        return;
    }
    ConsoleWrite("FATRMDIR: REMOVED ");
    ConsoleWriteln(path);
}

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

// Parse a hex literal like "0xA0C8FF" or "A0C8FF" into a u32.
// Returns true + writes to *out on success.
bool ParseHex32(const char* s, u32* out)
{
    if (s == nullptr || s[0] == '\0')
        return false;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        s += 2;
    u32 v = 0;
    u32 n = 0;
    for (u32 i = 0; s[i] != '\0'; ++i)
    {
        const char c = s[i];
        u32 nib;
        if (c >= '0' && c <= '9')
            nib = c - '0';
        else if (c >= 'a' && c <= 'f')
            nib = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F')
            nib = c - 'A' + 10;
        else
            return false;
        if (++n > 8)
            return false;
        v = (v << 4) | nib;
    }
    *out = v;
    return true;
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

// Parse an optionally-signed decimal integer. On success writes
// into `*out` and returns true. Used by expr for A / B.
bool ParseI64(const char* s, i64* out)
{
    if (s == nullptr || s[0] == '\0')
        return false;
    bool neg = false;
    u32 i = 0;
    if (s[0] == '-')
    {
        neg = true;
        i = 1;
    }
    else if (s[0] == '+')
    {
        i = 1;
    }
    if (s[i] == '\0')
        return false;
    u64 acc = 0;
    for (; s[i] != '\0'; ++i)
    {
        if (s[i] < '0' || s[i] > '9')
            return false;
        acc = acc * 10 + static_cast<u32>(s[i] - '0');
    }
    *out = neg ? -static_cast<i64>(acc) : static_cast<i64>(acc);
    return true;
}

void WriteI64Dec(i64 v)
{
    if (v < 0)
    {
        ConsoleWriteChar('-');
        WriteU64Dec(static_cast<u64>(-v));
    }
    else
    {
        WriteU64Dec(static_cast<u64>(v));
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

// `/tmp` is served by the writable tmpfs, not the static
// ramfs. Returns nullptr if `path` doesn't name /tmp or a
// /tmp/<leaf>, otherwise a pointer to the leaf name inside
// the original string (empty when the path is exactly "/tmp").
// Hoisted above the commands so CmdEcho's redirect branch can
// reuse it without a forward declaration.
const char* TmpLeaf(const char* path)
{
    if (path == nullptr)
    {
        return nullptr;
    }
    const char prefix[] = "/tmp";
    u32 i = 0;
    for (; prefix[i] != '\0'; ++i)
    {
        if (path[i] != prefix[i])
        {
            return nullptr;
        }
    }
    if (path[i] == '\0')
    {
        return path + i; // ""
    }
    if (path[i] == '/')
    {
        return path + i + 1;
    }
    return nullptr;
}

// Same shape as TmpLeaf, but for the FAT32 mount surfaced at /fat.
// /fat          -> "" (list volume 0's root)
// /fat/FILE     -> "FILE"   (look up FILE in volume 0's root)
// anything else -> nullptr  (falls through to ramfs / tmpfs)
//
// Hard-coded to volume 0 for now: the shell has no syntax for
// picking a different mount, and the first (and only) FAT32 volume
// we probe in tests is at index 0. The `fatcat` raw command still
// lets an operator poke any volume by index if they need to.
const char* FatLeaf(const char* path)
{
    if (path == nullptr)
    {
        return nullptr;
    }
    const char prefix[] = "/fat";
    u32 i = 0;
    for (; prefix[i] != '\0'; ++i)
    {
        if (path[i] != prefix[i])
        {
            return nullptr;
        }
    }
    if (path[i] == '\0')
    {
        return path + i; // ""
    }
    if (path[i] == '/')
    {
        return path + i + 1;
    }
    return nullptr;
}

void CmdEcho(u32 argc, char** argv)
{
    // Scan for a ">" redirect token. If present, arguments
    // before it form the payload and the token immediately
    // after is the target path (tmpfs-only in v0). Plain echo
    // without a redirect just prints.
    u32 redirect_idx = argc;
    bool append = false;
    for (u32 i = 1; i < argc; ++i)
    {
        if (argv[i][0] == '>' && argv[i][1] == '\0')
        {
            redirect_idx = i;
            append = false;
            break;
        }
        if (argv[i][0] == '>' && argv[i][1] == '>' && argv[i][2] == '\0')
        {
            redirect_idx = i;
            append = true;
            break;
        }
    }

    if (redirect_idx < argc)
    {
        if (redirect_idx + 1 >= argc)
        {
            ConsoleWriteln("ECHO: MISSING REDIRECT TARGET");
            return;
        }
        const char* target = argv[redirect_idx + 1];
        const char* leaf = TmpLeaf(target);
        if (leaf == nullptr || *leaf == '\0')
        {
            ConsoleWriteln("ECHO: ONLY /tmp/<NAME> IS WRITABLE");
            return;
        }
        char buf[duetos::fs::kTmpFsContentMax];
        u32 out = 0;
        for (u32 i = 1; i < redirect_idx; ++i)
        {
            if (i > 1 && out < sizeof(buf))
            {
                buf[out++] = ' ';
            }
            for (u32 j = 0; argv[i][j] != '\0' && out < sizeof(buf); ++j)
            {
                buf[out++] = argv[i][j];
            }
        }
        if (out < sizeof(buf))
        {
            buf[out++] = '\n'; // match /bin/echo's trailing newline
        }
        const bool ok = append ? duetos::fs::TmpFsAppend(leaf, buf, out) : duetos::fs::TmpFsWrite(leaf, buf, out);
        if (!ok)
        {
            ConsoleWrite("ECHO: WRITE FAILED: ");
            ConsoleWriteln(target);
        }
        return;
    }

    // Plain print — each arg separated by a single space,
    // regardless of how the user spaced the input. Matches
    // /bin/echo defaults.
    for (u32 i = 1; i < argc; ++i)
    {
        if (i > 1)
        {
            ConsoleWriteChar(' ');
        }
        ConsoleWrite(argv[i]);
    }
    ConsoleWriteChar('\n');
}

void LsTmpDir()
{
    bool any = false;
    struct Cookie
    {
        bool* any;
    };
    auto cb = [](const char* name, u32 len, void* cookie)
    {
        auto* c = static_cast<Cookie*>(cookie);
        *c->any = true;
        ConsoleWrite("  ");
        ConsoleWrite(name);
        ConsoleWrite("   ");
        WriteU64Dec(len);
        ConsoleWriteln(" BYTES");
    };
    Cookie cookie{&any};
    duetos::fs::TmpFsEnumerate(cb, &cookie);
    if (!any)
    {
        ConsoleWriteln("(EMPTY DIRECTORY)");
    }
}

void CmdLs(u32 argc, char** argv)
{
    const char* path = (argc >= 2) ? argv[1] : "/";

    // Writable /tmp takes priority. "ls /tmp" lists the flat
    // namespace; "ls /tmp/FOO" looks up the single file.
    if (const char* tmp_leaf = TmpLeaf(path); tmp_leaf != nullptr)
    {
        if (*tmp_leaf == '\0')
        {
            LsTmpDir();
            return;
        }
        u32 len = 0;
        if (duetos::fs::TmpFsRead(tmp_leaf, nullptr, &len))
        {
            ConsoleWrite(tmp_leaf);
            ConsoleWrite("   ");
            WriteU64Dec(len);
            ConsoleWriteln(" BYTES");
        }
        else
        {
            ConsoleWrite("LS: NO SUCH PATH: ");
            ConsoleWriteln(path);
        }
        return;
    }

    // FAT32 mount at /fat → volume 0. `ls /fat[/subpath]` resolves
    // the full path via Fat32LookupPath so arbitrarily deep
    // directory trees work, not just the root.
    if (const char* fat_leaf = FatLeaf(path); fat_leaf != nullptr)
    {
        namespace fat = duetos::fs::fat32;
        const fat::Volume* v = fat::Fat32Volume(0);
        if (v == nullptr)
        {
            ConsoleWriteln("LS: FAT32 NOT MOUNTED (no probed volume)");
            return;
        }
        fat::DirEntry entry;
        if (!fat::Fat32LookupPath(v, fat_leaf, &entry))
        {
            ConsoleWrite("LS: NO SUCH PATH: ");
            ConsoleWriteln(path);
            return;
        }
        if ((entry.attributes & 0x10) == 0)
        {
            // Regular file — POSIX-style: print the name and size.
            ConsoleWrite(entry.name);
            ConsoleWrite("   ");
            WriteU64Dec(entry.size_bytes);
            ConsoleWriteln(" BYTES");
            return;
        }
        // Directory — enumerate. The on-disk walker returns a
        // fresh snapshot each call; cap at 32 entries for v0.
        static fat::DirEntry listing[32];
        const u32 count = fat::Fat32ListDirByCluster(v, entry.first_cluster, listing, 32);
        if (count == 0)
        {
            ConsoleWriteln("(EMPTY DIRECTORY)");
            return;
        }
        for (u32 i = 0; i < count; ++i)
        {
            const fat::DirEntry& e = listing[i];
            ConsoleWrite("  ");
            ConsoleWrite(e.name);
            if (e.attributes & 0x10)
            {
                ConsoleWriteln("/");
            }
            else
            {
                ConsoleWrite("   ");
                WriteU64Dec(e.size_bytes);
                ConsoleWriteln(" BYTES");
            }
        }
        return;
    }

    const auto* root = duetos::fs::RamfsTrustedRoot();
    const auto* node = duetos::fs::VfsLookup(root, path, 128);
    if (node == nullptr)
    {
        ConsoleWrite("LS: NO SUCH PATH: ");
        ConsoleWriteln(path);
        return;
    }
    if (node->type == duetos::fs::RamfsNodeType::kFile)
    {
        // POSIX-style: `ls file` prints the filename (no dir walk).
        ConsoleWrite(node->name);
        ConsoleWrite("   ");
        WriteU64Dec(node->file_size);
        ConsoleWriteln(" BYTES");
        return;
    }
    if (node->children == nullptr)
    {
        ConsoleWriteln("(EMPTY DIRECTORY)");
        return;
    }
    for (u32 i = 0; node->children[i] != nullptr; ++i)
    {
        const auto* c = node->children[i];
        ConsoleWrite("  ");
        ConsoleWrite(c->name);
        if (c->type == duetos::fs::RamfsNodeType::kDir)
        {
            ConsoleWriteln("/");
        }
        else
        {
            ConsoleWrite("   ");
            WriteU64Dec(c->file_size);
            ConsoleWriteln(" BYTES");
        }
    }
    // If the caller asked for the root, also surface /tmp and
    // /fat as directories so both are discoverable without the
    // operator needing to know the mount points are hard-coded.
    // Only show /fat when a volume has actually been probed —
    // don't advertise a mount that isn't there.
    if (StrEq(path, "/") || StrEq(path, ""))
    {
        ConsoleWriteln("  tmp/   (WRITABLE)");
        if (duetos::fs::fat32::Fat32VolumeCount() > 0)
        {
            ConsoleWriteln("  fat/   (READ-ONLY)");
        }
    }
}

void CmdCat(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("CAT: MISSING PATH");
        return;
    }
    const char* path = argv[1];

    // /tmp served from tmpfs; /fat served from FAT32 volume 0;
    // everything else from the read-only ramfs.
    if (const char* tmp_leaf = TmpLeaf(path); tmp_leaf != nullptr && *tmp_leaf != '\0')
    {
        const char* bytes = nullptr;
        u32 len = 0;
        if (!duetos::fs::TmpFsRead(tmp_leaf, &bytes, &len))
        {
            ConsoleWrite("CAT: NO SUCH FILE: ");
            ConsoleWriteln(path);
            return;
        }
        for (u32 i = 0; i < len; ++i)
        {
            ConsoleWriteChar(bytes[i]);
        }
        if (len == 0 || bytes[len - 1] != '\n')
        {
            ConsoleWriteChar('\n');
        }
        return;
    }

    if (const char* fat_leaf = FatLeaf(path); fat_leaf != nullptr && *fat_leaf != '\0')
    {
        namespace fat = duetos::fs::fat32;
        const fat::Volume* v = fat::Fat32Volume(0);
        if (v == nullptr)
        {
            ConsoleWriteln("CAT: FAT32 NOT MOUNTED");
            return;
        }
        fat::DirEntry entry;
        if (!fat::Fat32LookupPath(v, fat_leaf, &entry))
        {
            ConsoleWrite("CAT: NO SUCH FILE: ");
            ConsoleWriteln(path);
            return;
        }
        if (entry.attributes & 0x10)
        {
            ConsoleWrite("CAT: IS A DIRECTORY: ");
            ConsoleWriteln(path);
            return;
        }
        // Stream cluster-by-cluster so files larger than scratch
        // (4 KiB) are not truncated. The driver streams 4 KiB per
        // chunk; ConsoleWriteChar handles each byte synchronously,
        // so the chunk pointer (into FAT scratch) stays valid
        // for the whole callback.
        struct StreamCtx
        {
            u8 last_byte;
            bool any;
        };
        StreamCtx ctx{0, false};
        const bool ok = fat::Fat32ReadFileStream(
            v, &entry,
            [](const duetos::u8* data, duetos::u64 len, void* cx) -> bool
            {
                auto* s = static_cast<StreamCtx*>(cx);
                for (duetos::u64 i = 0; i < len; ++i)
                {
                    ConsoleWriteChar(static_cast<char>(data[i]));
                }
                if (len > 0)
                {
                    s->last_byte = data[len - 1];
                    s->any = true;
                }
                return true;
            },
            &ctx);
        if (!ok)
        {
            ConsoleWriteln("CAT: READ ERROR");
            return;
        }
        if (!ctx.any || ctx.last_byte != '\n')
        {
            ConsoleWriteChar('\n');
        }
        return;
    }

    const auto* root = duetos::fs::RamfsTrustedRoot();
    const auto* node = duetos::fs::VfsLookup(root, path, 128);
    if (node == nullptr)
    {
        ConsoleWrite("CAT: NO SUCH FILE: ");
        ConsoleWriteln(path);
        return;
    }
    if (node->type != duetos::fs::RamfsNodeType::kFile)
    {
        ConsoleWrite("CAT: NOT A FILE: ");
        ConsoleWriteln(path);
        return;
    }
    for (u64 i = 0; i < node->file_size; ++i)
    {
        ConsoleWriteChar(static_cast<char>(node->file_bytes[i]));
    }
    // Ensure the prompt lands on a fresh row if the file didn't
    // end in a newline. Most text files do; binary or generated
    // ones often don't.
    if (node->file_size == 0 || node->file_bytes[node->file_size - 1] != '\n')
    {
        ConsoleWriteChar('\n');
    }
}

void CmdTouch(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("TOUCH: MISSING PATH");
        return;
    }
    const char* leaf = TmpLeaf(argv[1]);
    if (leaf == nullptr || *leaf == '\0')
    {
        ConsoleWriteln("TOUCH: ONLY /tmp/<NAME> IS WRITABLE");
        return;
    }
    if (!duetos::fs::TmpFsTouch(leaf))
    {
        ConsoleWrite("TOUCH: FAILED: ");
        ConsoleWriteln(argv[1]);
    }
}

void CmdRm(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("RM: MISSING PATH");
        return;
    }
    const char* leaf = TmpLeaf(argv[1]);
    if (leaf == nullptr || *leaf == '\0')
    {
        ConsoleWriteln("RM: ONLY /tmp/<NAME> IS WRITABLE");
        return;
    }
    if (!duetos::fs::TmpFsUnlink(leaf))
    {
        ConsoleWrite("RM: NO SUCH FILE: ");
        ConsoleWriteln(argv[1]);
    }
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

// Resolve a `!` history-expansion token. Returns the string to
// dispatch, or nullptr if no valid recall applies (caller should
// print "NO SUCH HISTORY ENTRY" and continue with the original
// line). `!!` = most recent; `!N` = the Nth entry displayed by
// `history` (oldest is 1).
const char* HistoryExpand(const char* line)
{
    if (line[0] != '!')
    {
        return nullptr;
    }
    if (line[1] == '!' && line[2] == '\0')
    {
        return HistoryAt(1);
    }
    // !N — parse decimal.
    u32 n = 0;
    u32 i = 1;
    if (line[i] == '\0')
    {
        return nullptr;
    }
    for (; line[i] != '\0'; ++i)
    {
        if (line[i] < '0' || line[i] > '9')
        {
            return nullptr;
        }
        n = n * 10 + static_cast<u32>(line[i] - '0');
    }
    if (n == 0 || n > g_history_count)
    {
        return nullptr;
    }
    // Display index is oldest-first; convert to newest-first
    // for HistoryAt.
    const u32 inv = g_history_count - n + 1;
    return HistoryAt(inv);
}

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
