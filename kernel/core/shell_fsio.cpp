/*
 * DuetOS — kernel shell: filesystem I/O helpers.
 *
 * Sibling TU of shell.cpp. Houses the read-only file-to-buffer
 * + line-slicing helpers shared by every command that processes
 * file content (cat, sort, uniq, head, tail, wc, hexdump, stat,
 * tac, nl, checksum, source, exec, readelf, ...).
 *
 * Hoisted out of shell.cpp so the next round of command bucket
 * extractions has a public surface to share.
 */

#include "shell_internal.h"

#include "../fs/ramfs.h"
#include "../fs/tmpfs.h"
#include "../fs/vfs.h"

namespace duetos::core::shell::internal
{

// Read a tmpfs/ramfs file into a stack scratch buffer. Resolves
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

} // namespace duetos::core::shell::internal
