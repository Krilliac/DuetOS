/*
 * DuetOS — kernel shell: tab completion.
 *
 * Sibling TU of shell.cpp. Implements the Tab key handler that
 * either completes a command name (when nothing has been typed
 * yet, no whitespace in the buffer) or completes an absolute
 * path argument (when the line is "<known-path-cmd> <partial>").
 *
 * The completer reads the live edit buffer (g_input + g_len) +
 * the canonical command list (kCommandSet) + the ramfs / tmpfs
 * directory listings. On a single match it extends the line via
 * ExtendLine; on multiple matches it prints the candidate list,
 * re-issues the prompt, and re-echoes the typed prefix so the
 * user can keep typing.
 *
 * Public entry point (declared in shell.h):
 *   - ShellTabComplete()    — wired to the Tab key in main.cpp.
 *
 * Everything else is anonymous-namespace TU-private — nothing
 * outside this file calls into ExtendLine / NamePrefixMatch /
 * CompleteCommandName / CompletePath, and we keep that property
 * by hiding them behind the unnamed namespace.
 */

#include "shell/shell.h"

#include "drivers/video/console.h"
#include "fs/ramfs.h"
#include "fs/tmpfs.h"
#include "fs/vfs.h"
#include "shell/shell_internal.h"

namespace duetos::core
{

using namespace shell::internal;

namespace
{

using duetos::drivers::video::ConsoleWrite;
using duetos::drivers::video::ConsoleWriteChar;
using duetos::drivers::video::ConsoleWriteln;

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
    const u32 kCmdCount = kCommandCount;

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

} // namespace

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
