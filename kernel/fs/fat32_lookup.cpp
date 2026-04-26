/*
 * DuetOS — FAT32 filesystem driver: path lookup.
 *
 * Sibling to fat32.cpp / fat32_read.cpp / fat32_write.cpp. Houses
 * the multi-component path walker that volume-relative paths
 * resolve through. The cluster-chain walker, decoders, and root-
 * snapshot accessor live in fat32.cpp under namespace internal;
 * this TU only consumes them.
 *
 *   Fat32LookupPath  — public entry; descends '/'-separated
 *                      components from the volume root.
 *
 * The TU-private FindCtx / FindVisitor pair adapts WalkDirChain's
 * generic visitor signature to the per-component "match by name,
 * stash entry, stop" use case. Public fat32.h API unchanged.
 */

#include "fat32.h"

#include "../core/kdbg.h"
#include "fat32_internal.h"

namespace duetos::fs::fat32
{

using namespace internal;

namespace
{
// Path walker context: "looking for `want`; when the visitor sees
// it, stash the entry in `match` and stop."
struct FindCtx
{
    const char* want;
    DirEntry match;
    bool found;
};

bool FindVisitor(const DirEntry& e, void* cx)
{
    auto* c = static_cast<FindCtx*>(cx);
    if (NameIEqual(e.name, c->want))
    {
        CopyEntry(c->match, e);
        c->found = true;
        return false; // stop the walk
    }
    return true;
}
} // namespace

bool Fat32LookupPath(const Volume* v, const char* path, DirEntry* out)
{
    Fat32Guard guard;
    if (v == nullptr || path == nullptr || out == nullptr)
        return false;
    KDBG_S(Fat32Lookup, "fs/fat32", "lookup", "path", path);

    // Synthetic "root" entry: directory at v->root_cluster.
    DirEntry cur;
    VZero(&cur, sizeof(cur));
    cur.name[0] = '/';
    cur.name[1] = 0;
    cur.attributes = kAttrDirectory;
    cur.first_cluster = v->root_cluster;
    cur.size_bytes = 0;

    // Skip leading slashes. An empty/"/" path returns the root entry.
    while (*path == '/')
        ++path;
    if (*path == 0)
    {
        CopyEntry(*out, cur);
        return true;
    }

    // Component-by-component descent. We copy each component into
    // a 128-byte local buffer — matches DirEntry::name capacity
    // since LFN entries can carry names up to 127 chars. Avoids
    // mutating the caller's path.
    char comp[128];
    while (*path != 0)
    {
        u32 n = 0;
        while (*path != 0 && *path != '/')
        {
            if (n >= sizeof(comp) - 1)
                return false; // component exceeds LFN cap
            comp[n++] = *path++;
        }
        comp[n] = 0;
        if (n == 0)
            continue; // consecutive '/'
        while (*path == '/')
            ++path;

        if ((cur.attributes & kAttrDirectory) == 0)
            return false; // walking INTO a regular file

        FindCtx ctx;
        ctx.want = comp;
        ctx.found = false;
        VZero(&ctx.match, sizeof(ctx.match));
        if (!WalkDirChain(*v, cur.first_cluster, &FindVisitor, &ctx))
            return false;
        if (!ctx.found)
            return false;
        CopyEntry(cur, ctx.match);
    }

    CopyEntry(*out, cur);
    return true;
}

} // namespace duetos::fs::fat32
