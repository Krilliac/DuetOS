#pragma once

// Private cross-TU surface for the kernel shell. Splits the
// command implementations across multiple sibling translation
// units that share declarations of the per-command Cmd*
// handlers below. Anything in `namespace duetos::core::shell::internal`
// is intended for the shell's own TUs only — never include this
// header from outside kernel/core/.
//
// The dispatcher in shell.cpp pulls every Cmd* name back into
// its outer namespace via `using namespace shell::internal;`,
// so the existing if/else dispatch chain keeps reading like the
// in-TU layout the file used to have.

#include "../core/types.h"

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

// ---------------------------------------------------------------
// Account management commands (shell_security.cpp). Thin wrappers
// around auth.h. Admin-only paths are enforced inside each
// handler so the kernel-side API stays pure data-access.
// ---------------------------------------------------------------
void CmdUsers();
void CmdUseradd(u32 argc, char** argv);
void CmdUserdel(u32 argc, char** argv);
void CmdPasswd(u32 argc, char** argv);
void CmdLogout();
void CmdSu(u32 argc, char** argv);
void CmdLoginCmd(u32 argc, char** argv);

// ---------------------------------------------------------------
// Storage / mount / device-list commands (shell_storage.cpp).
// Thin views over the block layer + GPT parser + mount table.
// (Fat* commands and CmdRead are queued for a follow-up slice.)
// ---------------------------------------------------------------
void CmdMount();
void CmdLsblk();
void CmdLsgpt();
void CmdLsmod();

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
