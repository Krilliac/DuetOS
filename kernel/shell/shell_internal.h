#pragma once

// Private cross-TU surface for the kernel shell. Splits the
// command implementations across multiple sibling translation
// units that share declarations of the per-command Cmd*
// handlers below. Anything in `namespace duetos::core::shell::internal`
// is intended for the shell's own TUs only — never include this
// header from outside kernel/shell/.
//
// The dispatcher in shell.cpp pulls every Cmd* name back into
// its outer namespace via `using namespace shell::internal;`,
// so the existing if/else dispatch chain keeps reading like the
// in-TU layout the file used to have.

#include "proc/process.h"
#include "util/types.h"

namespace duetos::core::shell::internal
{

// ---------------------------------------------------------------
// Environment variables. Fixed 8-slot table, 32-byte names +
// 128-byte values. Backs the set / unset / env / getenv commands
// and the $VAR token-substitution path in Dispatch().
//
// Definitions live in shell_state.cpp; declared here so sibling
// TUs (CmdHostname in shell_core.cpp, future CmdEnv / CmdSet /
// CmdGetenv extractions) can read and mutate the table without
// going through a public API. EnvNameEq + EnvCopy are inline so
// the alias-table code in shell.cpp can keep using them.
// ---------------------------------------------------------------
inline constexpr u32 kEnvSlotCount = 8;
inline constexpr u32 kEnvNameMax = 32;
inline constexpr u32 kEnvValueMax = 128;

struct EnvSlot
{
    bool in_use;
    char name[kEnvNameMax];
    char value[kEnvValueMax];
};

extern EnvSlot g_env[kEnvSlotCount];

inline bool EnvNameEq(const char* a, const char* b)
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

inline void EnvCopy(char* dst, const char* src, u32 cap)
{
    u32 i = 0;
    for (; i + 1 < cap && src[i] != '\0'; ++i)
    {
        dst[i] = src[i];
    }
    dst[i] = '\0';
}

EnvSlot* EnvFind(const char* name);
bool EnvSet(const char* name, const char* value);
bool EnvUnset(const char* name);

// ---------------------------------------------------------------
// String utility helpers. Inline so every sibling TU reaches them
// without a back-edge dependency on shell.cpp.
//
// StrEq returns true iff a and b are equal C-strings. StrStartsWith
// returns true iff `s` begins with `prefix`. Both stop at the first
// '\0' on the shorter side.
// ---------------------------------------------------------------
inline bool StrEq(const char* a, const char* b)
{
    for (u32 i = 0;; ++i)
    {
        if (a[i] != b[i])
            return false;
        if (a[i] == '\0')
            return true;
    }
}

inline bool StrStartsWith(const char* s, const char* prefix)
{
    for (u32 i = 0;; ++i)
    {
        if (prefix[i] == '\0')
            return true;
        if (s[i] != prefix[i])
            return false;
    }
}

// ---------------------------------------------------------------
// Aliases. Same shape as the env table — 8 slots, 32-byte names,
// 96-byte expansions. Dispatched BEFORE the env-var pass so an
// alias that includes $VAR references still gets expanded.
//
// Definitions live in shell_state.cpp; declared here so sibling
// TUs can reach the table without going through a public API.
// AliasFind / AliasSet / AliasUnset reuse EnvNameEq / EnvCopy
// inline above.
// ---------------------------------------------------------------
inline constexpr u32 kAliasSlotCount = 8;
inline constexpr u32 kAliasExpansionMax = 96;

struct AliasSlot
{
    bool in_use;
    char name[kEnvNameMax];
    char expansion[kAliasExpansionMax];
};

extern AliasSlot g_aliases[kAliasSlotCount];

AliasSlot* AliasFind(const char* name);
bool AliasSet(const char* name, const char* expansion);
bool AliasUnset(const char* name);

// ---------------------------------------------------------------
// Command history. Ring buffer of the last `kHistoryCap` submitted
// lines. g_history_count saturates at the cap; the newest entry
// lives at ((head - 1) mod cap). g_history_cursor is the recall
// index — 0 == "at the live prompt", 1 == most recent, etc.
//
// kInputMax sizes both the per-line history slots and the live
// input buffer (g_input in shell.cpp); hoisted alongside so any
// sibling TU that needs to size a temporary line buffer matches
// the shell's input width.
//
// Definitions live in shell_state.cpp; declared here so the
// `history`, `!N` recall, Up/Down arrow recall, and any future
// CmdHistory extraction can share the same ring without going
// through a public API.
// ---------------------------------------------------------------
inline constexpr u32 kInputMax = 64;
inline constexpr u32 kHistoryCap = 8;

extern char g_history[kHistoryCap][kInputMax];
extern u32 g_history_head;
extern u32 g_history_count;
extern u32 g_history_cursor;

void HistoryPush(const char* line);
const char* HistoryAt(u32 n);
const char* HistoryExpand(const char* line);

// ---------------------------------------------------------------
// Live input edit buffer (g_input + g_len) and the latched
// Ctrl+C interrupt flag (g_interrupt). Definitions live in
// shell_state.cpp; declared here so the dispatch + tab-completion
// sibling TUs can read them without going through a public API.
//
// ReplaceLine wipes the visible line + reloads the buffer with
// `text` (or clears it if `text == nullptr`). Used by the
// history Prev / Next handlers and by the interactive completer.
// ---------------------------------------------------------------
extern char g_input[kInputMax];
extern u32 g_len;
extern bool g_interrupt;

void ReplaceLine(const char* text);

// ---------------------------------------------------------------
// Exit code of the most recently dispatched command. Surfaced to
// scripts via the special `$?` token in $VAR substitution.
// Definition lives in shell_state.cpp.
//
// Convention: 0 = success, 1 = generic failure, 2 = misuse of
// shell builtin (POSIX flavour), 127 = command not found.
// Handlers are not required to call ShellSetExit on success — the
// dispatcher resets to 0 before each command runs.
// ---------------------------------------------------------------
i32 ShellLastExit();
void ShellSetExit(i32 code);

// ---------------------------------------------------------------
// Top-level dispatcher (shell_dispatch.cpp). Splits a submitted
// line into pipe stages, expands `!` history references and the
// $VAR token-substitution, then walks the if/else chain that
// matches the canonical command list against argv[0].
//
// Definition lives in shell_dispatch.cpp; declared here so the
// public ShellSubmit wrapper in shell.cpp can call it.
// ---------------------------------------------------------------
void Dispatch(char* line);

// Render the current prompt. Reads $PS1 from the env table if
// set; defaults to "$ ". Definition lives in shell_dispatch.cpp;
// declared here so ShellInit / ShellSubmit (shell.cpp) and the
// tab-completer (shell_complete.cpp) can call it after dispatch
// or after a multi-candidate completion list.
void Prompt();

// Canonical built-in command list. Single source of truth used
// by the dispatcher (`which` matches against it) and the
// tab-completer (CompleteCommandName uses it for prefix walk).
// Definition lives in shell_dispatch.cpp.
extern const char* const kCommandSet[];
extern const u32 kCommandCount;

// ---------------------------------------------------------------
// Pure path / parse helpers (shell_pathutil.cpp). Used across the
// shell for string handling that has no other dependencies.
//
// TmpLeaf / FatLeaf strip the /tmp + /fat prefix off a path and
// hand back a pointer into the original string at the leaf name
// (or nullptr if the path doesn't match). ParseU64Str accepts
// decimal or 0x-hex; ParseInt is the i64 wrapper used by
// commands that take a small positive count.
// ---------------------------------------------------------------
const char* TmpLeaf(const char* path);
const char* FatLeaf(const char* path);
bool ParseU64Str(const char* s, u64* out);
i64 ParseInt(const char* s);
bool ParseI64(const char* s, i64* out);
bool ParseU16Decimal(const char* s, u16* out);
bool ParseHex32(const char* s, u32* out);

// ---------------------------------------------------------------
// Filesystem I/O helpers (shell_fsio.cpp). Read-only helpers
// that handle the standard "fetch file body into a stack buffer
// + walk lines" pattern shared by every shell command that
// processes file content.
//
// ReadFileToBuf returns the number of bytes copied (capped at
// `cap`) or u32(-1) if the path doesn't resolve in tmpfs or
// ramfs. Never dereferences a nullptr buf.
//
// SliceLines walks `scratch[0..n)` and populates parallel
// `offs[]`/`lens[]` arrays — one entry per line, excluding the
// terminating '\n'. The unterminated final line is counted.
// Returns the number of lines written (capped at `cap`).
// ---------------------------------------------------------------
u32 ReadFileToBuf(const char* path, char* buf, u32 cap);
u32 SliceLines(const char* scratch, u32 n, u32* offs, u32* lens, u32 cap);

// ---------------------------------------------------------------
// Networking primitives (shell_network.cpp). Pure helpers shared
// by every networking command — extracted so the heavier net
// commands still in shell.cpp (dhcp/route/wifi/net/usbnet) can
// reach them through this header.
// ---------------------------------------------------------------
} // namespace duetos::core::shell::internal

namespace duetos::net
{
struct Ipv4Address;
}

namespace duetos::core::shell::internal
{
bool ParseIpv4(const char* s, duetos::net::Ipv4Address* out);
void WriteIpv4(duetos::net::Ipv4Address ip);
void WriteMac(const u8 mac[6]);
bool Ipv4IsZero(duetos::net::Ipv4Address ip);

// ---------------------------------------------------------------
// Shared console-output formatters (shell_format.cpp). Numeric
// printers used by every command that emits a value. Hoisted so
// each sibling TU can reach them through this header instead of
// carrying its own local copy.
//
// WriteU64Dec / WriteU8TwoDigits / WriteU64Hex / WriteI64Dec all
// emit directly to the kernel console via ConsoleWriteChar /
// ConsoleWrite. WriteU64Hex defaults to 16-nibble width; pass 0
// to strip leading zeros.
// ---------------------------------------------------------------
void WriteU64Dec(u64 v);
void WriteU8TwoDigits(u8 v);
void WriteU64Hex(u64 v, u32 digits = 16);
void WriteI64Dec(i64 v);

// ---------------------------------------------------------------
// Trivial info / housekeeping commands (shell_core.cpp). Banner /
// status commands that need nothing beyond the console driver,
// RTC, scheduler tick clock, or the env table above.
// ---------------------------------------------------------------
void CmdAbout();
void CmdVersion();
void CmdClear();
void CmdUptime();
void CmdDate();
void CmdYield();
void CmdUname(u32 argc, char** argv);
void CmdWhoami();
void CmdPwd();
void CmdTrue();
void CmdFalse();
void CmdHostname();
void CmdSet(u32 argc, char** argv);
void CmdUnset(u32 argc, char** argv);
void CmdGetenv(u32 argc, char** argv);
void CmdEnv();
void CmdAlias(u32 argc, char** argv);
void CmdUnalias(u32 argc, char** argv);

// ---------------------------------------------------------------
// Filesystem-facing commands (shell_filesystem.cpp). Coreutils-
// style commands that walk tmpfs / ramfs / FAT32 mounts.
// ---------------------------------------------------------------
void CmdCp(u32 argc, char** argv);
void CmdMv(u32 argc, char** argv);
void CmdWc(u32 argc, char** argv);
void CmdHead(u32 argc, char** argv);
void CmdTail(u32 argc, char** argv);
void CmdSort(u32 argc, char** argv);
void CmdUniq(u32 argc, char** argv);
void CmdGrep(u32 argc, char** argv);
void CmdFind(u32 argc, char** argv);
void CmdLs(u32 argc, char** argv);
void CmdCat(u32 argc, char** argv);
void CmdTouch(u32 argc, char** argv);
void CmdRm(u32 argc, char** argv);
void CmdEcho(u32 argc, char** argv);
void CmdFatls(u32 argc, char** argv);
void CmdFatcat(u32 argc, char** argv);
void CmdFatwrite(u32 argc, char** argv);
void CmdFatappend(u32 argc, char** argv);
void CmdFatnew(u32 argc, char** argv);
void CmdFatrm(u32 argc, char** argv);
void CmdFattrunc(u32 argc, char** argv);
void CmdFatmkdir(u32 argc, char** argv);
void CmdFatrmdir(u32 argc, char** argv);

// ---------------------------------------------------------------
// Hardware introspection commands (shell_hardware.cpp). Direct
// readouts of x86 CPU state (CPUID / RFLAGS / TSC / MSR), local
// APIC, SMP topology, PCI inventory, kernel heap / paging stats,
// framebuffer + input + SMBIOS / power / thermal / GPU readouts,
// and the Bochs / BGA mode-set command.
// ---------------------------------------------------------------
void CmdCpuid(u32 argc, char** argv);
void CmdCr();
void CmdRflags();
void CmdTsc();
void CmdHpet();
void CmdTicks();
void CmdMsr(u32 argc, char** argv);
void CmdLapic();
void CmdSmp();
void CmdLspci();
void CmdHdaJacks();
void CmdMei();
void CmdHeap(u32 argc, char** argv);
void CmdPaging();
void CmdFb();
void CmdKbdStats();
void CmdMouseStats();
void CmdSmbios();
void CmdPower();
void CmdThermal();
void CmdHwmon();
void CmdHw(u32 argc, char** argv);
void CmdGpu();
void CmdGfx(u32 argc, char** argv);
void CmdVbe(u32 argc, char** argv);
void CmdMonitor(u32 argc, char** argv);

// ---------------------------------------------------------------
// Networking commands (shell_network.cpp). The simpler half of
// the network surface — wire-protocol probes (ping/http/ntp/
// nslookup), iface listing (nic/ifconfig), ARP/IP stats. The
// heavier networking commands (dhcp / route / wifi / net / fwtrace /
// usbnet) stay in shell.cpp until a follow-up slice extracts them.
// ---------------------------------------------------------------
void CmdPing(u32 argc, char** argv);
void CmdHttp(u32 argc, char** argv);
void CmdNtp(u32 argc, char** argv);
void CmdNslookup(u32 argc, char** argv);
void CmdNic();
void CmdIfconfig();
void CmdArp();
void CmdIpv4();
void CmdDhcp(u32 argc, char** argv);
void CmdRoute(u32 argc, char** argv);
void CmdNetscan();
void CmdWifi(u32 argc, char** argv);
void CmdFirewall(u32 argc, char** argv);
void CmdFwPolicy(u32 argc, char** argv);
void CmdFwTrace(u32 argc, char** argv);
void CmdCrTrace(u32 argc, char** argv);
void CmdNet(u32 argc, char** argv);
void CmdUsbNet(u32 argc, char** argv);
void CmdBt(u32 argc, char** argv);
void CmdDrshd(u32 argc, char** argv);

// ---------------------------------------------------------------
// Kernel debug + introspection commands (shell_debug.cpp).
// Memory dump, breakpoint interface, runtime probe arming,
// instruction decode, symbol resolver, RE/triage `inspect`,
// global state snapshot, log-threshold trace toggle.
// ---------------------------------------------------------------
void CmdMemDump(u32 argc, char** argv);
void CmdBp(u32 argc, char** argv);
void CmdDbg(u32 argc, char** argv);
void CmdProbe(u32 argc, char** argv);
void CmdInstr(u32 argc, char** argv);
void CmdAddr2Sym(u32 argc, char** argv);
void CmdInspect(u32 argc, char** argv);
void CmdLockdepPanic(u32 argc, char** argv);
void CmdCapAuditMode(u32 argc, char** argv);
void CmdTracer(u32 argc, char** argv);
void CmdPerf(u32 argc, char** argv);
void CmdDomain(u32 argc, char** argv);
void CmdModule(u32 argc, char** argv);
void CmdCpuFeatures();
void CmdDumpState();
void CmdTrace(u32 argc, char** argv);
void CmdHealth(u32 argc, char** argv);
void CmdLeakCheck(u32 argc, char** argv);
void CmdLoglevel(u32 argc, char** argv);
void CmdLogcolor(u32 argc, char** argv);
void CmdLogarea(u32 argc, char** argv);
void CmdKdbg(u32 argc, char** argv);
void CmdDfix(u32 argc, char** argv);
void CmdMetrics();

// ---------------------------------------------------------------
// Admin gate. Returns true if the current user has the admin role,
// otherwise prints a denial line, klogs a warning, and returns false.
// Used by the dispatcher's gate switch + the small handful of
// commands that do per-subcommand admin checks (e.g. `guard`).
// Definition lives in shell.cpp.
// ---------------------------------------------------------------
bool RequireAdmin(const char* cmd);

/// Cap-aware gate. Passes when:
///   (1) the active session is `AuthRole::Admin` (legacy admin
///       semantics — admin holds every cap implicitly), OR
///   (2) the shell's pseudo-process holds `cap` via a live grace-
///       cache grant (i.e. the user ran `elevate <cap>` recently).
/// On denial: prints DENIED + the missing cap name and, if the
/// active user's roles would grant this cap, hints at the elevate
/// command to use.
bool RequireCap(::duetos::core::Cap cap, const char* cmd);

// ---------------------------------------------------------------
// Executable + low-level read commands (shell_exec.cpp). Loaders
// for native ELF + Linux ELF + raw block-device peek + ABI
// translation table dump.
// ---------------------------------------------------------------
void CmdLinuxexec(u32 argc, char** argv);
void CmdTranslate();
void CmdRead(u32 argc, char** argv);
void CmdExec(u32 argc, char** argv);
void CmdReadelf(u32 argc, char** argv);

// ---------------------------------------------------------------
// Process + security commands. Kill / Spawn live in
// shell_process.cpp; Guard / AttackSim live in shell_security.cpp.
// ---------------------------------------------------------------
void CmdKill(u32 argc, char** argv);
void CmdSpawn(u32 argc, char** argv);
void CmdGuard(u32 argc, char** argv);
void CmdAttackSim();
void CmdSecEvents(u32 argc, char** argv);
void CmdPolicy(u32 argc, char** argv);
void CmdPurple();

// ---------------------------------------------------------------
// Misc trivial utility commands (shell_utilities.cpp). Commands
// that touch only one or two kernel subsystems and don't need
// any of the larger TU-private helpers in shell.cpp.
// ---------------------------------------------------------------
void CmdBasename(u32 argc, char** argv);
void CmdDirname(u32 argc, char** argv);
void CmdFlushTlb();
void CmdMem();
void CmdMode();
void CmdHistory();
void CmdSleep(u32 argc, char** argv);
[[noreturn]] void CmdShutdownNow();
void CmdColor(u32 argc, char** argv);
void CmdRand(u32 argc, char** argv);
void CmdUuid(u32 argc, char** argv);
void CmdChecksum(u32 argc, char** argv);
void CmdReset();
void CmdTac(u32 argc, char** argv);
void CmdNl(u32 argc, char** argv);
void CmdRev(u32 argc, char** argv);
void CmdExpr(u32 argc, char** argv);
void CmdHexdump(u32 argc, char** argv);
void CmdStat(u32 argc, char** argv);
void CmdCal();
void CmdBeep(u32 argc, char** argv);
void CmdSeq(u32 argc, char** argv);
void CmdDmesg(u32 argc, char** argv);
void CmdStats();
void CmdMan(u32 argc, char** argv);

// ---------------------------------------------------------------
// Account management commands (shell_security.cpp). Thin wrappers
// around auth.h. Admin-only paths are enforced inside each
// handler so the kernel-side API stays pure data-access.
// ---------------------------------------------------------------
void CmdUsers();
void CmdUseradd(u32 argc, char** argv);
void CmdUserdel(u32 argc, char** argv);
void CmdUnlock(u32 argc, char** argv);
void CmdPasswd(u32 argc, char** argv);
void CmdLogout();
void CmdSu(u32 argc, char** argv);
void CmdLoginCmd(u32 argc, char** argv);
void CmdIdleLock(u32 argc, char** argv);

// RBAC + elevation broker commands (shell_security.cpp).
void CmdElevate(u32 argc, char** argv);
void CmdRoles(u32 argc, char** argv);
void CmdRoleAdd(u32 argc, char** argv);
void CmdRoleDel(u32 argc, char** argv);
void CmdElevations();

// True iff the kernel shell currently has a live broker-granted
// elevation. Consulted by `RequireAdmin` so a non-admin who ran
// `elevate <cap>` can pass admin-gated commands for the grace
// window. Lazily expires the underlying broker grant.
bool ShellIsElevatedNow();

// ---------------------------------------------------------------
// Storage / mount / device-list commands (shell_storage.cpp).
// Thin views over the block layer + GPT parser + mount table.
// (Fat* commands and CmdRead are queued for a follow-up slice.)
// ---------------------------------------------------------------
void CmdMount();
void CmdLsblk();
void CmdLsgpt();
void CmdLsmod();
void CmdMkfs(u32 argc, char** argv);
void CmdMkfsDuetfs(u32 argc, char** argv);
void CmdInstall(u32 argc, char** argv);
void CmdLastdump();

// ---------------------------------------------------------------
// Extended get/set/manipulate commands (shell_extra.cpp).
// Coreutils-flavour additions that round out the shell's day-to-
// day surface — directory create/remove that routes between tmpfs
// and FAT, file truncate, path canonicalisation, identity readouts
// (id / groups / nproc / arch / tty), POSIX aliases (type /
// printenv), filesystem-usage views (df / du), scheduler load,
// history wipe, blocking pause, generator (yes), sync placeholder,
// raw x86 I/O port access (admin-gated).
// ---------------------------------------------------------------
void CmdMkdir(u32 argc, char** argv);
void CmdRmdir(u32 argc, char** argv);
void CmdTruncate(u32 argc, char** argv);
void CmdRealpath(u32 argc, char** argv);
void CmdId();
void CmdGroups();
void CmdNproc();
void CmdArch();
void CmdTty();
void CmdType(u32 argc, char** argv);
void CmdPrintenv(u32 argc, char** argv);
void CmdDf();
void CmdDu(u32 argc, char** argv);
void CmdLoadavg();
void CmdClearhist();
void CmdPause();
void CmdYes(u32 argc, char** argv);
void CmdSync();
void CmdPort(u32 argc, char** argv);
void CmdAssert(u32 argc, char** argv);
void CmdWatch(u32 argc, char** argv);
void CmdScript(u32 argc, char** argv);
void CmdExit(u32 argc, char** argv);

// ---------------------------------------------------------------
// Load / stress testing (shell_loadtest.cpp). Exercises the
// scheduler + kernel heap under sustained pressure so an operator
// can verify stability and ^C responsiveness on a hot path.
// Admin-gated inside the handler.
// ---------------------------------------------------------------
void CmdLoadTest(u32 argc, char** argv);

// Boot-time stress driver hooks (shell_loadtest.cpp). Same code path
// as the `loadtest` shell command, but reachable from the kernel boot
// hook in kernel/diag/stress_driver.cpp without going through the
// interactive shell or the admin gate. Called from a dedicated kernel
// task spawned after sched + heap are online.
void StressDriverCpu(u32 secs, u32 workers);
void StressDriverMem(u32 mib, u32 secs);
void StressDriverMix(u32 secs, u32 workers, u32 mib);
void StressDriverSpin(u32 secs);

// ---------------------------------------------------------------
// Microbenchmark harness (shell_bench.cpp). Measures cycles/ns
// per op on specific kernel hot paths (KMalloc, sched::Mutex,
// SyscallDispatch, KEvent wakeup). Complement to loadtest —
// stress vs measure. Admin-gated inside the handler.
// ---------------------------------------------------------------
void CmdBench(u32 argc, char** argv);

// ---------------------------------------------------------------
// Scripting language v0 (shell_script.cpp).
//
// A small line-indexed interpreter that adds POSIX-shell-flavoured
// control flow on top of the existing Dispatch() pipeline. Supports:
//
//   # comments
//   if CMD ; then ... [elif CMD ; then ... ] [else ... ] fi
//   while CMD ; do ... done
//   for VAR in WORD1 WORD2 ... ; do ... done
//
// Plain command lines are handed straight to Dispatch(). Branch
// conditions read $? after running their CMD: $? == 0 => true.
// Block keywords must lead a line ("if " / "while " / "for " / "fi"
// / "done" / "elif " / "else" / "then" / "do") — mid-line keywords
// are not parsed in v0. The `; then` and `; do` clauses must sit on
// the same line as their introducer (split across lines is v1).
//
// Scope limits (intentional):
//   - 64 lines per script (kScriptMaxLines), 64 bytes per line
//     (matches kInputMax). Source files larger than that get a
//     "TOO LONG" diagnostic.
//   - No functions; aliases cover the common cases.
//   - No quoting yet — for-words are whitespace-split.
//   - No here-docs, no command substitution, no backgrounding.
//
// Used by CmdSource. The tokeniser ScriptSplitLines() is exposed so
// future commands (e.g. a future `eval` or REPL-time block) can also
// feed the executor.
// ---------------------------------------------------------------
inline constexpr u32 kScriptMaxLines = 64;
inline constexpr u32 kScriptLineMax = kInputMax;

// Walk `body[0..body_n)` and execute it as a script. `body_lines` is
// a parallel array of nul-terminated string pointers, length
// `body_n`. Returns nothing — control flow is observable through
// $? on exit and through the side effects of each Dispatch() call.
void ScriptExecute(char (*body_lines)[kScriptLineMax], u32 body_n);

// Read `n` bytes from `scratch` and split into lines, copying each
// into `out_lines`. Drops trailing whitespace per line. Returns the
// number of lines populated (capped at `cap`). Lines longer than
// kScriptLineMax-1 are truncated and a warning is klogged.
u32 ScriptSplitLines(const char* scratch, u32 n, char (*out_lines)[kScriptLineMax], u32 cap);

// Script-side `exit N`. Sets a sticky flag the script executor
// checks before each statement; once set, the surrounding
// ExecuteRange / ExecuteIfBlock / ExecuteWhileBlock / ExecuteForBlock
// unwind cleanly and ScriptExecute returns. The exit code lands in
// $? for the caller (CmdSource → outer Dispatch). Outside a script
// (i.e. typed at the prompt) `exit N` just sets $? — there is no
// shell process to terminate.
//
// ScriptExecute() resets the flag at entry so a stale request from
// a previous script doesn't pollute a fresh `source`.
void ScriptRequestExit(i32 code);
bool ScriptExitRequested();

// ---------------------------------------------------------------
// Process / scheduler / memory observability (shell_process.cpp).
// ps / top render the per-task scheduler enumeration; free reports
// memory-frame and kernel-heap totals. (Spawn / Kill / Exec /
// Linuxexec / Translate / Readelf are queued for a follow-up
// slice — they share path-strip / FAT32-load helpers with the
// rest of the shell.)
// ---------------------------------------------------------------
void CmdPs();
void CmdTop();
void CmdFree();

} // namespace duetos::core::shell::internal
