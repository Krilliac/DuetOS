/*
 * DuetOS — kernel shell: cross-TU shell state.
 *
 * Definitions of the long-lived shell tables that need to be
 * visible from more than one shell sibling TU: the environment
 * table (g_env + EnvFind / EnvSet / EnvUnset), the alias table
 * (g_aliases + AliasFind / AliasSet / AliasUnset), the command
 * history ring (g_history + HistoryPush / HistoryAt /
 * HistoryExpand), and the live input edit buffer (g_input +
 * g_len + g_interrupt + ReplaceLine).
 *
 * Sized helpers (EnvNameEq / EnvCopy / StrEq / StrStartsWith)
 * live inline in shell_internal.h so callers in either table or
 * any sibling TU reach them through the same header without a
 * back-edge here.
 */

#include "shell_internal.h"

#include "../drivers/video/console.h"

namespace duetos::core::shell::internal
{

constinit EnvSlot g_env[kEnvSlotCount] = {};

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

constinit char g_history[kHistoryCap][kInputMax] = {};
constinit u32 g_history_head = 0;
constinit u32 g_history_count = 0;
constinit u32 g_history_cursor = 0;

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
// oldest). Returns nullptr if n is out of range.
const char* HistoryAt(u32 n)
{
    if (n == 0 || n > g_history_count)
    {
        return nullptr;
    }
    const u32 idx = (g_history_head + kHistoryCap - n) % kHistoryCap;
    return g_history[idx];
}

// Live input edit buffer. g_input holds the bytes the user has
// typed since the last submission; g_len is the number of bytes.
// g_interrupt is the latched Ctrl+C flag — long-running command
// handlers poll it via the public ShellInterruptRequested wrapper
// in shell.cpp.
constinit char g_input[kInputMax] = {};
constinit u32 g_len = 0;
constinit bool g_interrupt = false;

// Wipe the visible line (echo '\b' g_len times) and load `text`
// into the edit buffer. `nullptr` just clears the line.
void ReplaceLine(const char* text)
{
    using duetos::drivers::video::ConsoleWriteChar;
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

} // namespace duetos::core::shell::internal
