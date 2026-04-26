/*
 * DuetOS — kernel shell: filesystem commands.
 *
 * Sibling TU of shell.cpp. Houses the coreutils-flavoured
 * commands that walk the layered shell namespace:
 *
 *   /tmp/...    writable tmpfs
 *   /fat/...    read-only FAT32 mount (volume 0)
 *   anything else  read-only ramfs (the boot image)
 *
 * Commands moved here as one bucket because they share both the
 * mount-routing pattern and a small set of TU-private helpers
 * (ParseLineCount, SubstringPresent, LineCompare, FindWalk,
 * LsTmpDir). Hoisting the helpers as well as the commands keeps
 * the surface area declared in shell_internal.h limited to the
 * Cmd* entry points; helpers stay in this file's anon namespace.
 *
 * Cp / Mv / Wc / Head / Tail / Sort / Uniq / Grep / Find / Ls /
 * Cat / Touch / Rm / Echo. Any FS-adjacent command tightly tied
 * to the Dispatch path (Source, Repeat) stays in shell.cpp.
 */

#include "shell/shell_internal.h"

#include "drivers/video/console.h"
#include "fs/fat32.h"
#include "fs/ramfs.h"
#include "fs/tmpfs.h"
#include "fs/vfs.h"

namespace duetos::core::shell::internal
{

namespace
{

using duetos::drivers::video::ConsoleWrite;
using duetos::drivers::video::ConsoleWriteChar;
using duetos::drivers::video::ConsoleWriteln;

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

} // namespace

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

// ---------------------------------------------------------------
// FAT32 commands. Volume-0-rooted by default; some accept an
// explicit volume index. Operate against the read-write FAT
// driver (sata0p1 / nvme0n1p1 in QEMU).
// ---------------------------------------------------------------

void CmdFatls(u32 argc, char** argv)
{
    namespace fat = duetos::fs::fat32;
    u32 vol_idx = 0;
    if (argc >= 2)
    {
        u64 v = 0;
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
    for (u32 i = 0; i < v->root_entry_count; ++i)
    {
        const fat::DirEntry& e = v->root_entries[i];
        ConsoleWrite(e.name);
        u32 len = 0;
        while (e.name[len] != 0)
            ++len;
        for (u32 p = len; p < 13; ++p)
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

void CmdFatcat(u32 argc, char** argv)
{
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
        u64 v = 0;
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

void CmdFatwrite(u32 argc, char** argv)
{
    namespace fat = duetos::fs::fat32;
    if (argc < 4)
    {
        ConsoleWriteln("FATWRITE: USAGE: FATWRITE PATH OFFSET BYTES...");
        return;
    }
    const char* path = argv[1];
    u64 off = 0;
    if (!ParseU64Str(argv[2], &off))
    {
        ConsoleWriteln("FATWRITE: BAD OFFSET");
        return;
    }
    static u8 payload[1024];
    u64 plen = 0;
    for (u32 i = 3; i < argc; ++i)
    {
        if (i > 3 && plen + 1 < sizeof(payload))
        {
            payload[plen++] = ' ';
        }
        for (u32 j = 0; argv[i][j] != 0 && plen + 1 < sizeof(payload); ++j)
        {
            payload[plen++] = static_cast<u8>(argv[i][j]);
        }
    }
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
    const i64 rc = fat::Fat32WriteInPlace(v, &entry, off, payload, plen);
    if (rc < 0)
    {
        ConsoleWriteln("FATWRITE: WRITE FAILED (offset+len > size? backend RO?)");
        return;
    }
    ConsoleWrite("FATWRITE: WROTE ");
    WriteU64Dec(static_cast<u64>(rc));
    ConsoleWrite(" BYTES AT OFFSET ");
    WriteU64Dec(off);
    ConsoleWriteln("");
}

void CmdFatappend(u32 argc, char** argv)
{
    namespace fat = duetos::fs::fat32;
    if (argc < 3)
    {
        ConsoleWriteln("FATAPPEND: USAGE: FATAPPEND NAME BYTES...");
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
    static u8 payload[1024];
    u64 plen = 0;
    for (u32 i = 2; i < argc; ++i)
    {
        if (i > 2 && plen + 1 < sizeof(payload))
        {
            payload[plen++] = ' ';
        }
        for (u32 j = 0; argv[i][j] != 0 && plen + 1 < sizeof(payload); ++j)
        {
            payload[plen++] = static_cast<u8>(argv[i][j]);
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
    const i64 rc =
        has_slash ? fat::Fat32AppendAtPath(v, name, payload, plen) : fat::Fat32AppendInRoot(v, name, payload, plen);
    if (rc < 0)
    {
        ConsoleWriteln("FATAPPEND: APPEND FAILED (backend RO? disk full? file not in root?)");
        return;
    }
    ConsoleWrite("FATAPPEND: APPENDED ");
    WriteU64Dec(static_cast<u64>(rc));
    ConsoleWrite(" BYTES TO ");
    ConsoleWriteln(name);
}

void CmdFatnew(u32 argc, char** argv)
{
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
    static u8 payload[1024];
    u64 plen = 0;
    for (u32 i = 2; i < argc; ++i)
    {
        if (i > 2 && plen + 1 < sizeof(payload))
        {
            payload[plen++] = ' ';
        }
        for (u32 j = 0; argv[i][j] != 0 && plen + 1 < sizeof(payload); ++j)
        {
            payload[plen++] = static_cast<u8>(argv[i][j]);
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
    const i64 rc =
        has_slash ? fat::Fat32CreateAtPath(v, name, payload, plen) : fat::Fat32CreateInRoot(v, name, payload, plen);
    if (rc < 0)
    {
        ConsoleWriteln("FATNEW: CREATE FAILED (bad name? exists? full dir? disk full?)");
        return;
    }
    ConsoleWrite("FATNEW: CREATED ");
    ConsoleWrite(name);
    ConsoleWrite(" (");
    WriteU64Dec(static_cast<u64>(rc));
    ConsoleWriteln(" BYTES)");
}

void CmdFatrm(u32 argc, char** argv)
{
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

void CmdFattrunc(u32 argc, char** argv)
{
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
    u64 new_size = 0;
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
    const i64 rc =
        has_slash ? fat::Fat32TruncateAtPath(v, name, new_size) : fat::Fat32TruncateInRoot(v, name, new_size);
    if (rc < 0)
    {
        ConsoleWriteln("FATTRUNC: FAILED");
        return;
    }
    ConsoleWrite("FATTRUNC: ");
    ConsoleWrite(name);
    ConsoleWrite(" -> ");
    WriteU64Dec(static_cast<u64>(rc));
    ConsoleWriteln(" BYTES");
}

void CmdFatmkdir(u32 argc, char** argv)
{
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

void CmdFatrmdir(u32 argc, char** argv)
{
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

} // namespace duetos::core::shell::internal
