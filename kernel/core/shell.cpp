#include "shell.h"

#include "../arch/x86_64/cpu.h"
#include "../arch/x86_64/hpet.h"
#include "../arch/x86_64/lapic.h"
#include "../arch/x86_64/rtc.h"
#include "../arch/x86_64/serial.h"
#include "../arch/x86_64/smp.h"
#include "../arch/x86_64/timer.h"
#include "../drivers/input/ps2kbd.h"
#include "../drivers/input/ps2mouse.h"
#include "../drivers/pci/pci.h"
#include "../drivers/video/console.h"
#include "../drivers/video/framebuffer.h"
#include "../drivers/video/widget.h"
#include "../fs/ramfs.h"
#include "../fs/tmpfs.h"
#include "../fs/vfs.h"
#include "../mm/address_space.h"
#include "../mm/frame_allocator.h"
#include "../mm/kheap.h"
#include "../mm/paging.h"
#include "../sched/sched.h"
#include "elf_loader.h"
#include "klog.h"
#include "process.h"
#include "reboot.h"
#include "ring3_smoke.h"

namespace customos::core
{

namespace
{

using customos::drivers::video::ConsoleWrite;
using customos::drivers::video::ConsoleWriteChar;
using customos::drivers::video::ConsoleWriteln;

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

void CmdHelp()
{
    ConsoleWriteln("AVAILABLE COMMANDS:");
    ConsoleWriteln("  HELP         LIST THIS HELP");
    ConsoleWriteln("  ABOUT        ABOUT CUSTOMOS");
    ConsoleWriteln("  VERSION      CUSTOMOS VERSION");
    ConsoleWriteln("  CLEAR        CLEAR THE CONSOLE");
    ConsoleWriteln("  UPTIME       SECONDS SINCE BOOT");
    ConsoleWriteln("  DATE         WALL TIME + DATE");
    ConsoleWriteln("  WINDOWS      LIST REGISTERED WINDOWS");
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
    ConsoleWriteln("  DMESG        DUMP KERNEL LOG RING");
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
    ConsoleWriteln("");
    ConsoleWriteln("RUNTIME CONTROL:");
    ConsoleWriteln("  LOGLEVEL [L] GET / SET KLOG THRESHOLD (D/I/W/E)");
    ConsoleWriteln("  GETENV NAME  READ ONE ENV VARIABLE");
    ConsoleWriteln("  YIELD        FORCE A SCHEDULER YIELD");
    ConsoleWriteln("  REBOOT       RESET THE MACHINE (NO CONFIRM)");
    ConsoleWriteln("  HALT         STOP THE CPU (NO CONFIRM)");
    ConsoleWriteln("");
    ConsoleWriteln("COMPAT / IDENTITY:");
    ConsoleWriteln("  UNAME [-A]   KERNEL IDENTITY (-A VERBOSE)");
    ConsoleWriteln("  WHOAMI       EFFECTIVE USER");
    ConsoleWriteln("  HOSTNAME     HOST NAME (OR $HOSTNAME)");
    ConsoleWriteln("  PWD          CURRENT DIRECTORY (ALWAYS /)");
    ConsoleWriteln("  TRUE / FALSE NO-OP SUCCESS / FAILURE");
    ConsoleWriteln("  MOUNT        LIST FS MOUNTS");
    ConsoleWriteln("  LSMOD        LIST ACTIVE KERNEL SUBSYSTEMS");
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
    ConsoleWriteln("CUSTOMOS — A FROM-SCRATCH x86_64 KERNEL WITH A");
    ConsoleWriteln("NATIVE WINDOWED DESKTOP AND A FIRST-CLASS WIN32");
    ConsoleWriteln("SUBSYSTEM PLANNED. BOOT: MULTIBOOT2.  SHELL: YOU.");
}

void CmdVersion()
{
    ConsoleWriteln("CUSTOMOS v0 (WINDOWED DESKTOP SHELL)");
}

void CmdClear()
{
    customos::drivers::video::ConsoleClear();
}

void CmdUptime()
{
    const u64 secs = customos::sched::SchedNowTicks() / 100;
    ConsoleWrite("UPTIME ");
    WriteU64Dec(secs);
    ConsoleWriteln(" SECONDS");
}

void CmdDate()
{
    customos::arch::RtcTime t{};
    customos::arch::RtcRead(&t);
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
    using namespace customos::drivers::video;
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

void CmdDmesg()
{
    ConsoleWriteln("-- KERNEL LOG RING (OLDEST FIRST) --");
    customos::core::DumpLogRingTo([](const char* s) { ConsoleWrite(s); });
}

void CmdStats()
{
    const auto s = customos::sched::SchedStatsRead();
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
        if (!customos::fs::TmpFsRead(tmp_leaf, &bytes, &len))
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
    const auto* root = customos::fs::RamfsTrustedRoot();
    const auto* node = customos::fs::VfsLookup(root, path, 128);
    if (node == nullptr || node->type != customos::fs::RamfsNodeType::kFile)
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
    char scratch[customos::fs::kTmpFsContentMax];
    const u32 n = ReadFileToBuf(argv[1], scratch, sizeof(scratch));
    if (n == static_cast<u32>(-1))
    {
        ConsoleWrite("CP: CANNOT READ: ");
        ConsoleWriteln(argv[1]);
        return;
    }
    if (!customos::fs::TmpFsWrite(dst_leaf, scratch, n))
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
    if (!customos::fs::TmpFsRead(src_leaf, &bytes, &len))
    {
        ConsoleWrite("MV: NO SUCH FILE: ");
        ConsoleWriteln(argv[1]);
        return;
    }
    // Copy through a scratch buffer so we don't alias the
    // tmpfs slot's own storage during write (a same-slot
    // rename collapses to the copy-back-into-self case).
    char scratch[customos::fs::kTmpFsContentMax];
    const u32 n = (len > sizeof(scratch)) ? sizeof(scratch) : len;
    for (u32 i = 0; i < n; ++i)
    {
        scratch[i] = bytes[i];
    }
    if (!customos::fs::TmpFsWrite(dst_leaf, scratch, n))
    {
        ConsoleWrite("MV: WRITE FAILED: ");
        ConsoleWriteln(argv[2]);
        return;
    }
    // Only unlink the source AFTER the write succeeded —
    // partial failure mustn't lose data.
    customos::fs::TmpFsUnlink(src_leaf);
}

void CmdWc(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("WC: MISSING PATH");
        return;
    }
    char scratch[customos::fs::kTmpFsContentMax];
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
    char scratch[customos::fs::kTmpFsContentMax];
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
    char scratch[customos::fs::kTmpFsContentMax];
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
    char scratch[customos::fs::kTmpFsContentMax];
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
        while (j > 0 &&
               LineCompare(&scratch[offs[j - 1]], lens[j - 1], &scratch[off_i], len_i) > 0)
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
    char scratch[customos::fs::kTmpFsContentMax];
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
            const bool is_dup = have_prev &&
                                LineCompare(&scratch[prev_off], prev_len, &scratch[start], len) == 0;
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
    char scratch[customos::fs::kTmpFsContentMax];
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
void FindWalk(const customos::fs::RamfsNode* node, const char* needle, char* path_buf,
              u32& path_len, u32 path_cap)
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
    if (node->type != customos::fs::RamfsNodeType::kDir || node->children == nullptr)
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
    FindWalk(customos::fs::RamfsTrustedRoot(), needle, path_buf, path_len, sizeof(path_buf));
    // tmpfs is flat under /tmp/ — enumerate directly.
    struct Cookie
    {
        const char* needle;
    };
    Cookie cookie{needle};
    customos::fs::TmpFsEnumerate(
        [](const char* name, u32 /*len*/, void* ck) {
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
    "help",    "about",   "version", "clear",   "uptime",  "date",    "windows",
    "mode",    "ls",      "cat",     "touch",   "rm",      "echo",    "cp",
    "mv",      "wc",      "head",    "tail",    "dmesg",   "stats",   "mem",
    "history", "set",     "unset",   "env",     "alias",   "unalias", "sysinfo",
    "source",  "man",     "grep",    "find",    "time",    "which",   "seq",
    "sort",    "uniq",    "cpuid",   "cr",      "rflags",  "tsc",     "hpet",
    "ticks",   "msr",     "lapic",   "smp",     "lspci",   "heap",    "paging",
    "fb",      "kbdstats","mousestats","loglevel","getenv","yield",   "reboot",
    "halt",    "uname",   "whoami",  "hostname","pwd",     "true",    "false",
    "mount",   "lsmod",   "free",    "ps",      "spawn",   "readelf",
    "hexdump", "stat",    "basename","dirname", "cal",
    "sleep",   "reset",   "tac",     "nl",      "rev",     "expr",
    "color",   "rand",    "flushtlb","checksum","repeat",   "kill",
    "exec",
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
    const u64 t0 = customos::sched::SchedNowTicks();
    Dispatch(buf);
    const u64 t1 = customos::sched::SchedNowTicks();
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
    char scratch[customos::fs::kTmpFsContentMax];
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
        while (j > 0 && (line_buf[j - 1] == ' ' || line_buf[j - 1] == '\t' ||
                         line_buf[j - 1] == '\r'))
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

    char scratch[customos::fs::kTmpFsContentMax];
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
    ConsoleWriteln("CUSTOMOS v0  (WINDOWED DESKTOP SHELL)");
    ConsoleWrite("UPTIME:  ");
    const u64 secs = customos::sched::SchedNowTicks() / 100;
    WriteU64Dec(secs);
    ConsoleWriteln(" SECONDS");
    customos::arch::RtcTime t{};
    customos::arch::RtcRead(&t);
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
    const auto s = customos::sched::SchedStatsRead();
    ConsoleWrite("TASKS:   ");
    WriteU64Dec(s.tasks_live);
    ConsoleWrite(" LIVE, ");
    WriteU64Dec(s.tasks_sleeping);
    ConsoleWrite(" SLEEPING, ");
    WriteU64Dec(s.tasks_blocked);
    ConsoleWriteln(" BLOCKED");
    const u64 total = customos::mm::TotalFrames();
    const u64 free_frames = customos::mm::FreeFramesCount();
    ConsoleWrite("MEMORY:  ");
    WriteU64Dec((total - free_frames) * 4);
    ConsoleWrite(" KIB USED / ");
    WriteU64Dec(total * 4);
    ConsoleWriteln(" KIB TOTAL");
    u32 alive = 0;
    for (u32 h = 0; h < customos::drivers::video::WindowRegistryCount(); ++h)
    {
        if (customos::drivers::video::WindowIsAlive(h))
            ++alive;
    }
    ConsoleWrite("WINDOWS: ");
    WriteU64Dec(alive);
    ConsoleWriteln(" ALIVE");
    ConsoleWrite("MODE:    ");
    ConsoleWriteln(customos::drivers::video::GetDisplayMode() ==
                           customos::drivers::video::DisplayMode::Tty
                       ? "TTY"
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
    WriteU64Hex(customos::arch::ReadCr0());
    ConsoleWriteChar('\n');
    ConsoleWrite("CR2:  ");
    WriteU64Hex(customos::arch::ReadCr2());
    ConsoleWriteChar('\n');
    ConsoleWrite("CR3:  ");
    WriteU64Hex(customos::arch::ReadCr3());
    ConsoleWriteChar('\n');
    ConsoleWrite("CR4:  ");
    WriteU64Hex(customos::arch::ReadCr4());
    ConsoleWriteChar('\n');
}

// Rflags bit positions + names, parallel arrays so the
// initialisers are trivial — a struct-array local would need
// memcpy from .rodata, which the freestanding kernel doesn't
// link.
constexpr u8 kRflagsBitIdx[] = {0, 2, 4, 6, 7, 8, 9, 10, 11, 14, 16, 17, 18, 19, 20, 21};
constexpr const char* kRflagsBitNames[] = {"CF", "PF",  "AF",  "ZF", "SF", "TF", "IF", "DF",
                                            "OF", "NT",  "RF",  "VM", "AC", "VIF","VIP","ID"};

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
    const u64 v = customos::arch::HpetReadCounter();
    const u32 p = customos::arch::HpetPeriodFemtoseconds();
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
    WriteU64Dec(customos::arch::TimerTicks());
    ConsoleWriteChar('\n');
    ConsoleWrite("SCHED TICKS: ");
    WriteU64Dec(customos::sched::SchedNowTicks());
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
    using namespace customos::arch;
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
    const u64 n = customos::arch::SmpCpusOnline();
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
    const u64 n = customos::drivers::pci::PciDeviceCount();
    ConsoleWrite("PCI DEVICES:   ");
    WriteU64Dec(n);
    ConsoleWriteChar('\n');
    for (u64 i = 0; i < n; ++i)
    {
        const auto& d = customos::drivers::pci::PciDevice(i);
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
        ConsoleWriteln(customos::drivers::pci::PciClassName(d.class_code));
    }
}

void CmdHeap()
{
    const auto s = customos::mm::KernelHeapStatsRead();
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
    const auto s = customos::mm::PagingStatsRead();
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
    if (!customos::drivers::video::FramebufferAvailable())
    {
        ConsoleWriteln("FB: NOT AVAILABLE");
        return;
    }
    const auto info = customos::drivers::video::FramebufferGet();
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
    const auto s = customos::drivers::input::Ps2KeyboardStats();
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
    const auto s = customos::drivers::input::Ps2MouseStatsRead();
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

void CmdLoglevel(u32 argc, char** argv)
{
    if (argc < 2)
    {
        const auto cur = customos::core::GetLogThreshold();
        ConsoleWrite("LOG THRESHOLD: ");
        switch (cur)
        {
        case customos::core::LogLevel::Debug:
            ConsoleWriteln("DEBUG (show everything)");
            break;
        case customos::core::LogLevel::Info:
            ConsoleWriteln("INFO");
            break;
        case customos::core::LogLevel::Warn:
            ConsoleWriteln("WARN");
            break;
        case customos::core::LogLevel::Error:
            ConsoleWriteln("ERROR (show only errors)");
            break;
        }
        ConsoleWriteln("USAGE: LOGLEVEL [D|I|W|E]");
        return;
    }
    const char c = argv[1][0];
    customos::core::LogLevel lvl = customos::core::LogLevel::Info;
    switch (c)
    {
    case 'd':
    case 'D':
        lvl = customos::core::LogLevel::Debug;
        break;
    case 'i':
    case 'I':
        lvl = customos::core::LogLevel::Info;
        break;
    case 'w':
    case 'W':
        lvl = customos::core::LogLevel::Warn;
        break;
    case 'e':
    case 'E':
        lvl = customos::core::LogLevel::Error;
        break;
    default:
        ConsoleWriteln("LOGLEVEL: USE D / I / W / E");
        return;
    }
    customos::core::SetLogThreshold(lvl);
    ConsoleWriteln("LOG THRESHOLD UPDATED");
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
    customos::sched::SchedYield();
}

void CmdUname(u32 argc, char** argv)
{
    // uname default: kernel name. -a prints everything.
    const bool all = (argc >= 2 && argv[1][0] == '-' && argv[1][1] == 'a');
    if (all)
    {
        ConsoleWrite("CustomOS customos v0 x86_64  (tick ");
        WriteU64Dec(customos::sched::SchedNowTicks());
        ConsoleWriteln(")");
    }
    else
    {
        ConsoleWriteln("CustomOS");
    }
}

void CmdWhoami()
{
    ConsoleWriteln("root");
}

void CmdHostname()
{
    const EnvSlot* s = EnvFind("HOSTNAME");
    ConsoleWriteln((s != nullptr) ? s->value : "customos");
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

void CmdMount()
{
    // Show every mounted backend. v0: ramfs at /, tmpfs at
    // /tmp. Real mount table lands with multi-backend VFS.
    ConsoleWriteln("ramfs on /       type=ramfs (ro)");
    ConsoleWriteln("tmpfs on /tmp    type=tmpfs (rw, 16 slots, 512B each)");
}

void CmdLsmod()
{
    // Not real modules — just a static list of the subsystems
    // currently online. Still useful as a "what's loaded" view.
    static const char* const kModules[] = {
        "multiboot2", "gdt", "idt", "tss+ist", "paging",      "frame_alloc", "kheap",
        "acpi",       "pic", "lapic", "ioapic", "hpet",       "timer",       "scheduler",
        "percpu",     "ps2kbd", "ps2mouse", "pci",            "ahci",        "framebuffer",
        "cursor",     "font8x8", "console", "widget",         "taskbar",     "menu",
        "ramfs",      "tmpfs",   "vfs",     "rtc",            "klog",        "shell",
    };
    constexpr u32 kCount = sizeof(kModules) / sizeof(kModules[0]);
    for (u32 i = 0; i < kCount; ++i)
    {
        ConsoleWrite("  ");
        ConsoleWriteln(kModules[i]);
    }
}

const char* SchedStateName(u8 s)
{
    switch (s)
    {
    case 0:
        return "READY";
    case 1:
        return "RUN  ";
    case 2:
        return "SLEEP";
    case 3:
        return "BLOCK";
    case 4:
        return "DEAD ";
    default:
        return "?    ";
    }
}

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
    const auto r = customos::sched::SchedKillByPid(pid);
    switch (r)
    {
    case customos::sched::KillResult::Signaled:
        ConsoleWrite("KILL: SIGNALED PID ");
        WriteU64Dec(pid);
        ConsoleWriteln(" (WILL DIE ON NEXT SCHEDULE)");
        break;
    case customos::sched::KillResult::NotFound:
        ConsoleWrite("KILL: NO SUCH PID: ");
        WriteU64Dec(pid);
        ConsoleWriteChar('\n');
        break;
    case customos::sched::KillResult::Protected:
        ConsoleWrite("KILL: PID ");
        WriteU64Dec(pid);
        ConsoleWriteln(" IS PROTECTED (idle/reaper/boot)");
        break;
    case customos::sched::KillResult::AlreadyDead:
        ConsoleWrite("KILL: PID ");
        WriteU64Dec(pid);
        ConsoleWriteln(" IS ALREADY DEAD");
        break;
    case customos::sched::KillResult::Blocked:
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
        ConsoleWriteln("          kread  ptrfuzz  writefuzz  hellope");
        ConsoleWriteln("  SEE `MAN SPAWN` FOR DETAILS.");
        return;
    }
    if (!customos::core::SpawnOnDemand(argv[1]))
    {
        ConsoleWrite("SPAWN: UNKNOWN KIND: ");
        ConsoleWriteln(argv[1]);
        ConsoleWriteln("  KINDS:  hello  sandbox  jail  nx  hog  hostile  dropcaps  priv  badint");
        ConsoleWriteln("          kread  ptrfuzz  writefuzz  hellope");
        return;
    }
    ConsoleWrite("SPAWN: QUEUED ");
    ConsoleWriteln(argv[1]);
    ConsoleWriteln("  (RUN `PS` TO SEE IT, OR WATCH THE KERNEL LOG)");
}

// Little-endian u16/u32/u64 readers — the ELF parser walks
// raw bytes, so we don't rely on alignment or struct packing.
u16 LeU16(const u8* p) { return u16(p[0]) | (u16(p[1]) << 8); }
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
    customos::drivers::video::ConsoleSetColours(fg, bg);
    ConsoleWriteln("COLOR: UPDATED. NEXT REDRAW USES THE NEW PALETTE.");
}

void CmdRand(u32 argc, char** argv)
{
    // Simple splitmix64 seeded from the TSC. Not cryptographic.
    // Count defaults to 1; max 100 to keep output bounded.
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
    static u64 state = 0;
    if (state == 0)
    {
        u32 lo, hi;
        asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
        state = (static_cast<u64>(hi) << 32) | lo;
        if (state == 0)
            state = 0xCAFEBABE12345678ULL;
    }
    for (u32 i = 0; i < n; ++i)
    {
        state += 0x9E3779B97F4A7C15ULL;
        u64 z = state;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        z = z ^ (z >> 31);
        WriteU64Hex(z);
        ConsoleWriteChar('\n');
    }
}

void CmdFlushTlb()
{
    // Reload CR3 with its current value — the classic x86_64
    // "flush every non-global TLB entry" primitive. Global
    // pages survive (they're typically kernel direct-map);
    // anything else is cold on next access.
    const u64 cr3 = customos::arch::ReadCr3();
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
    char scratch[customos::fs::kTmpFsContentMax];
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
        customos::sched::SchedSleepTicks(100);
    }
}

void CmdReset()
{
    // Wipe the console + reprint the boot banner. Same content
    // ShellInit emits; useful when the scrollback is cluttered
    // or the user just switched terminals.
    customos::drivers::video::ConsoleClear();
    char scratch[customos::fs::kTmpFsContentMax];
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
    char scratch[customos::fs::kTmpFsContentMax];
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
    char scratch[customos::fs::kTmpFsContentMax];
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
    char scratch[customos::fs::kTmpFsContentMax];
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
    char scratch[customos::fs::kTmpFsContentMax];
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
        if (!customos::fs::TmpFsRead(tmp_leaf, &bytes, &len))
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
    const auto* root = customos::fs::RamfsTrustedRoot();
    const auto* node = customos::fs::VfsLookup(root, path, 128);
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
    if (node->type == customos::fs::RamfsNodeType::kDir)
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
    customos::arch::RtcTime t{};
    customos::arch::RtcRead(&t);
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

    static const char* const kMonths[] = {"January",  "February", "March",     "April",
                                           "May",      "June",     "July",      "August",
                                           "September","October",  "November",  "December"};
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
            ConsoleWriteChar(day == t.day ? static_cast<char>('0' + day % 10)
                                          : static_cast<char>('0' + day % 10));
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
    char scratch[customos::fs::kTmpFsContentMax];
    const u32 n = ReadFileToBuf(argv[1], scratch, sizeof(scratch));
    if (n == static_cast<u32>(-1))
    {
        ConsoleWrite("EXEC: NO SUCH FILE: ");
        ConsoleWriteln(argv[1]);
        return;
    }
    const u8* file = reinterpret_cast<const u8*>(scratch);
    const customos::core::ElfStatus st = customos::core::ElfValidate(file, n);
    if (st != customos::core::ElfStatus::Ok)
    {
        ConsoleWrite("EXEC: INVALID ELF: ");
        ConsoleWriteln(customos::core::ElfStatusName(st));
        return;
    }
    ConsoleWrite("EXEC: OK. ENTRY = ");
    WriteU64Hex(customos::core::ElfEntry(file));
    ConsoleWriteChar('\n');
    ConsoleWriteln("LOAD PLAN:");
    ConsoleWriteln("  VADDR             FILESZ    MEMSZ     FLAGS   FILE-OFFSET");
    struct Cookie
    {
        u32 count;
    };
    Cookie cookie{0};
    const u32 visited = customos::core::ElfForEachPtLoad(
        file, n,
        [](const customos::core::ElfSegment& seg, void* ck) {
            auto* c = static_cast<Cookie*>(ck);
            ++c->count;
            ConsoleWrite("  ");
            WriteU64Hex(seg.vaddr);
            ConsoleWrite("  ");
            WriteU64Hex(seg.filesz, 8);
            ConsoleWrite("  ");
            WriteU64Hex(seg.memsz, 8);
            ConsoleWrite("  ");
            ConsoleWriteChar((seg.flags & customos::core::kElfPfR) ? 'R' : '-');
            ConsoleWriteChar((seg.flags & customos::core::kElfPfW) ? 'W' : '-');
            ConsoleWriteChar((seg.flags & customos::core::kElfPfX) ? 'X' : '-');
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
    const u64 new_pid = customos::core::SpawnElfFile(
        argv[1], file, n, customos::core::CapSetTrusted(), customos::fs::RamfsTrustedRoot(),
        customos::mm::kFrameBudgetTrusted, customos::core::kTickBudgetTrusted);
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
    char scratch[customos::fs::kTmpFsContentMax];
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

void CmdPs()
{
    // Header row matches the classic ps widths — ID, STATE, PRI,
    // NAME. A future slice adds CPU time + memory once those
    // are tracked per-task.
    ConsoleWriteln(" PID  STATE  PRI  NAME");
    struct Cookie
    {
        u32 count;
    };
    Cookie cookie{0};
    customos::sched::SchedEnumerate(
        [](const customos::sched::SchedTaskInfo& info, void* ck) {
            auto* c = static_cast<Cookie*>(ck);
            // 4-digit PID aligned, status tag, priority, name.
            // Running task gets a '*' prefix so it's obvious.
            ConsoleWriteChar(info.is_running ? '*' : ' ');
            // Right-pad id to 3 digits.
            if (info.id < 10)
                ConsoleWriteChar(' ');
            if (info.id < 100)
                ConsoleWriteChar(' ');
            WriteU64Dec(info.id);
            ConsoleWriteChar(' ');
            ConsoleWriteChar(' ');
            ConsoleWrite(SchedStateName(info.state));
            ConsoleWriteChar(' ');
            ConsoleWriteChar(' ');
            ConsoleWriteChar(info.priority == 0 ? 'N' : 'I'); // Normal / Idle
            ConsoleWriteChar(' ');
            ConsoleWriteChar(' ');
            ConsoleWriteln(info.name != nullptr ? info.name : "(unnamed)");
            ++c->count;
        },
        &cookie);
    ConsoleWrite("TOTAL: ");
    WriteU64Dec(cookie.count);
    ConsoleWriteln(" tasks");
}

void CmdFree()
{
    // Compact "free -k"-ish output: one line each for memory
    // totals and the kernel heap.
    const u64 total = customos::mm::TotalFrames();
    const u64 free_f = customos::mm::FreeFramesCount();
    const u64 used = total - free_f;
    constexpr u64 kKiB = 4;
    ConsoleWriteln("           total         used         free");
    ConsoleWrite("PHYS  ");
    WriteU64Dec(total * kKiB);
    ConsoleWrite("K  ");
    WriteU64Dec(used * kKiB);
    ConsoleWrite("K  ");
    WriteU64Dec(free_f * kKiB);
    ConsoleWriteln("K");
    const auto h = customos::mm::KernelHeapStatsRead();
    ConsoleWrite("HEAP  ");
    WriteU64Dec(h.pool_bytes);
    ConsoleWrite("   ");
    WriteU64Dec(h.used_bytes);
    ConsoleWrite("   ");
    WriteU64Dec(h.free_bytes);
    ConsoleWriteChar('\n');
}

[[noreturn]] void CmdRebootNow()
{
    ConsoleWriteln("REBOOTING...");
    // Serial also carries the notice so a headless run sees
    // the final line before the reset reg fires.
    customos::arch::SerialWrite("[shell] user invoked reboot\n");
    customos::core::KernelReboot();
}

[[noreturn]] void CmdHaltNow()
{
    ConsoleWriteln("HALTING. SAFE TO POWER OFF.");
    customos::arch::SerialWrite("[shell] user invoked halt\n");
    // Infinite "cli; hlt" via arch::Halt. The scheduler will
    // never run again on this CPU. For multi-CPU this would
    // need an NMI broadcast; v0 is single-CPU so this is fine.
    customos::arch::Halt();
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
    const u64 total = customos::mm::TotalFrames();
    const u64 free_frames = customos::mm::FreeFramesCount();
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
    const auto mode = customos::drivers::video::GetDisplayMode();
    ConsoleWrite("CURRENT MODE: ");
    ConsoleWriteln(mode == customos::drivers::video::DisplayMode::Tty ? "TTY (FULLSCREEN CONSOLE)"
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
        char buf[customos::fs::kTmpFsContentMax];
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
        const bool ok = append ? customos::fs::TmpFsAppend(leaf, buf, out)
                                : customos::fs::TmpFsWrite(leaf, buf, out);
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
    auto cb = [](const char* name, u32 len, void* cookie) {
        auto* c = static_cast<Cookie*>(cookie);
        *c->any = true;
        ConsoleWrite("  ");
        ConsoleWrite(name);
        ConsoleWrite("   ");
        WriteU64Dec(len);
        ConsoleWriteln(" BYTES");
    };
    Cookie cookie{&any};
    customos::fs::TmpFsEnumerate(cb, &cookie);
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
        if (customos::fs::TmpFsRead(tmp_leaf, nullptr, &len))
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

    const auto* root = customos::fs::RamfsTrustedRoot();
    const auto* node = customos::fs::VfsLookup(root, path, 128);
    if (node == nullptr)
    {
        ConsoleWrite("LS: NO SUCH PATH: ");
        ConsoleWriteln(path);
        return;
    }
    if (node->type == customos::fs::RamfsNodeType::kFile)
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
        if (c->type == customos::fs::RamfsNodeType::kDir)
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
    // If the caller asked for the root, also surface /tmp as a
    // directory so it's discoverable without needing to know
    // the tmpfs mount point is hard-coded.
    if (StrEq(path, "/") || StrEq(path, ""))
    {
        ConsoleWriteln("  tmp/   (WRITABLE)");
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

    // /tmp served from tmpfs; everything else from the read-
    // only ramfs.
    if (const char* tmp_leaf = TmpLeaf(path); tmp_leaf != nullptr && *tmp_leaf != '\0')
    {
        const char* bytes = nullptr;
        u32 len = 0;
        if (!customos::fs::TmpFsRead(tmp_leaf, &bytes, &len))
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

    const auto* root = customos::fs::RamfsTrustedRoot();
    const auto* node = customos::fs::VfsLookup(root, path, 128);
    if (node == nullptr)
    {
        ConsoleWrite("CAT: NO SUCH FILE: ");
        ConsoleWriteln(path);
        return;
    }
    if (node->type != customos::fs::RamfsNodeType::kFile)
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
    if (!customos::fs::TmpFsTouch(leaf))
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
    if (!customos::fs::TmpFsUnlink(leaf))
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
            static constexpr u32 kPipeBufMax = customos::fs::kTmpFsContentMax;
            static char g_pipe_buf[kPipeBufMax];
            u32 captured = 0;
            customos::drivers::video::ConsoleBeginCapture(g_pipe_buf, kPipeBufMax, &captured);
            Dispatch(left);
            customos::drivers::video::ConsoleEndCapture();

            // Stash captured output in a reserved tmpfs slot.
            // Use a well-known name so nested pipes share the
            // space — each level overwrites as it unwinds.
            constexpr const char* kPipeName = "__pipe__";
            customos::fs::TmpFsWrite(kPipeName, g_pipe_buf, captured);

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
            customos::fs::TmpFsUnlink(kPipeName);
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
        CmdDmesg();
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
    if (StrEq(cmd, "loglevel"))
    {
        CmdLoglevel(argc, argv);
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
        CmdMount();
        return;
    }
    if (StrEq(cmd, "lsmod"))
    {
        CmdLsmod();
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
        CmdSpawn(argc, argv);
        return;
    }
    if (StrEq(cmd, "kill"))
    {
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
        CmdRebootNow();
        // unreachable
    }
    if (StrEq(cmd, "halt"))
    {
        CmdHaltNow();
        // unreachable
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
    // replaces the tiny "CUSTOMOS SHELL" banner the earlier
    // version used. If the file is missing (e.g. a stripped
    // sandbox tree), fall back to the minimum one-liner.
    char scratch[customos::fs::kTmpFsContentMax];
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
        ConsoleWriteln("CUSTOMOS SHELL v0   TYPE HELP FOR COMMANDS.");
    }

    // Auto-source /etc/profile. Effect is identical to the user
    // running `source /etc/profile` manually — sets any boot-time
    // aliases / prompt / env vars the distribution wants. Silent
    // no-op if the file doesn't exist.
    char profile_line[] = "/etc/profile";
    char* argv[2] = {nullptr, profile_line};
    const char* bytes = nullptr;
    u32 plen = 0;
    const auto* prof = customos::fs::VfsLookup(customos::fs::RamfsTrustedRoot(), "/etc/profile", 64);
    if (prof != nullptr && prof->type == customos::fs::RamfsNodeType::kFile)
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
        auto cb = [](const char* name, u32 /*len*/, void* cookie) {
            auto* c = static_cast<CompleteCollector*>(cookie);
            if (c->count >= kCompleteMax)
                return;
            if (!NamePrefixMatch(name, c->leaf, c->leaf_len))
                return;
            c->items[c->count].name = name;
            c->items[c->count].is_dir = false;
            ++c->count;
        };
        customos::fs::TmpFsEnumerate(cb, &col);
    }
    else
    {
        const auto* root = customos::fs::RamfsTrustedRoot();
        const auto* parent = customos::fs::VfsLookup(root, parent_buf, sizeof(parent_buf));
        if (parent == nullptr || parent->type != customos::fs::RamfsNodeType::kDir || parent->children == nullptr)
        {
            return;
        }
        for (u32 i = 0; parent->children[i] != nullptr && col.count < kCompleteMax; ++i)
        {
            const auto* c = parent->children[i];
            if (!NamePrefixMatch(c->name, leaf, leaf_len))
                continue;
            col.items[col.count].name = c->name;
            col.items[col.count].is_dir = (c->type == customos::fs::RamfsNodeType::kDir);
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
    const bool path_cmd = StrEq(g_input, "ls") || StrEq(g_input, "cat") ||
                          StrEq(g_input, "touch") || StrEq(g_input, "rm") ||
                          StrEq(g_input, "cp") || StrEq(g_input, "mv") ||
                          StrEq(g_input, "wc") || StrEq(g_input, "head") ||
                          StrEq(g_input, "tail") || StrEq(g_input, "source") ||
                          StrEq(g_input, "grep") || StrEq(g_input, "sort") ||
                          StrEq(g_input, "uniq") || StrEq(g_input, "readelf") ||
                          StrEq(g_input, "hexdump") || StrEq(g_input, "stat") ||
                          StrEq(g_input, "tac") || StrEq(g_input, "nl") ||
                          StrEq(g_input, "rev") || StrEq(g_input, "checksum");
    g_input[first_ws] = saved;

    if (path_cmd)
    {
        CompletePath(last_ws + 1);
    }
}

} // namespace customos::core
