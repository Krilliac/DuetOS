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

#include "fs/fat32.h"

#include "diag/kdbg.h"
#include "fs/fat32_internal.h"
#include "log/klog.h"

namespace duetos::fs::fat32
{

using namespace internal;

namespace
{
// --- Path-lookup result cache (see fat32_internal.h contract) ---
//
// Direct-mapped, generation-validated. An entry is a hit only when
// the volume pointer, the exact path bytes, AND the generation all
// match — so a missed invalidation degrades to a re-walk on the
// next gen bump, never to a wrong answer. Both positive and
// negative (component-not-found) resolutions are memoized; the
// boot self-test storm is dominated by repeated negative probes
// (NOTES.TXT / TEST.* / TRTEST.BIN) and repeated positive ones
// (KERNEL.FIX between flushes).
constexpr u32 kPathCacheSlots = 32;
constexpr u32 kPathCacheKeyMax = 128; // matches the 127-char LFN component cap

struct PathCacheEntry
{
    const Volume* v;
    u64 gen;
    bool valid;
    bool found;
    char path[kPathCacheKeyMax];
    DirEntry entry;
};

constinit PathCacheEntry g_path_cache[kPathCacheSlots] = {};
constinit u64 g_path_cache_gen = 1; // 0 reserved for "never filled"

u64 PathHash(const Volume* v, const char* p)
{
    // FNV-1a over the volume pointer bytes + path string.
    u64 h = 1469598103934665603ULL;
    const auto* vb = reinterpret_cast<const u8*>(&v);
    for (u32 i = 0; i < sizeof(v); ++i)
    {
        h = (h ^ vb[i]) * 1099511628211ULL;
    }
    for (const char* s = p; *s != 0; ++s)
    {
        h = (h ^ static_cast<u8>(*s)) * 1099511628211ULL;
    }
    return h;
}

bool PathStrEqual(const char* a, const char* b)
{
    for (u32 i = 0; i < kPathCacheKeyMax; ++i)
    {
        if (a[i] != b[i])
            return false;
        if (a[i] == 0)
            return true;
    }
    return false; // key longer than the cap — treat as miss
}

// Returns true and fills *out / *found_out on a live cache hit.
bool PathCacheGet(const Volume* v, const char* path, DirEntry* out, bool* found_out)
{
    const PathCacheEntry& e = g_path_cache[PathHash(v, path) % kPathCacheSlots];
    if (!e.valid || e.gen != g_path_cache_gen || e.v != v || !PathStrEqual(e.path, path))
        return false;
    *found_out = e.found;
    if (e.found)
        CopyEntry(*out, e.entry);
    return true;
}

void PathCachePut(const Volume* v, const char* path, bool found, const DirEntry* entry)
{
    u32 n = 0;
    while (path[n] != 0)
    {
        if (n >= kPathCacheKeyMax - 1)
            return; // un-cacheable key length; lookups still correct, just uncached
        ++n;
    }
    PathCacheEntry& e = g_path_cache[PathHash(v, path) % kPathCacheSlots];
    e.v = v;
    e.gen = g_path_cache_gen;
    e.valid = true;
    e.found = found;
    for (u32 i = 0; i <= n; ++i)
        e.path[i] = path[i];
    if (found && entry != nullptr)
        CopyEntry(e.entry, *entry);
}

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
    {
        KLOG_WARN_A(::duetos::core::LogArea::FS, "fs/fat32", "lookup: null volume / path / out");
        return false;
    }
    KDBG_S(Fat32Lookup, "fs/fat32", "lookup", "path", path);
    KLOG_DEBUG_AS(::duetos::core::LogArea::FS, "fs/fat32", "lookup", "path", path);

    // Memoized result? (Stable key = the caller's original path
    // bytes, before slash-stripping / component descent.)
    const char* const orig_path = path;
    {
        bool cached_found = false;
        if (PathCacheGet(v, orig_path, out, &cached_found))
            return cached_found;
    }

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
            {
                KLOG_WARN_A(::duetos::core::LogArea::FS, "fs/fat32", "lookup: path component exceeds 127-char LFN cap");
                return false; // component exceeds LFN cap
            }
            comp[n++] = *path++;
        }
        comp[n] = 0;
        if (n == 0)
            continue; // consecutive '/'
        while (*path == '/')
            ++path;

        // "." — stay. ".." — REJECTED. Mirror VfsLookup
        // (vfs.cpp:301-309): rejecting these here makes the
        // no-escape guarantee independent of WalkDirChain's
        // IsDotEntry filter, which runs on the decoded SFN BEFORE
        // the LFN name override — so a crafted image with an
        // innocuous SFN whose LFN assembles to ".." would otherwise
        // be matched by FindVisitor and descend to an
        // attacker-chosen cluster.
        if (n == 1 && comp[0] == '.')
            continue;
        if (n == 2 && comp[0] == '.' && comp[1] == '.')
        {
            KLOG_WARN_A(::duetos::core::LogArea::FS, "fs/fat32", "lookup: '..' component rejected");
            return false;
        }

        if ((cur.attributes & kAttrDirectory) == 0)
        {
            KLOG_WARN_AS(::duetos::core::LogArea::FS, "fs/fat32",
                         "lookup: traversing INTO a regular file (not a directory)", "comp", comp);
            return false; // walking INTO a regular file
        }

        FindCtx ctx;
        ctx.want = comp;
        ctx.found = false;
        VZero(&ctx.match, sizeof(ctx.match));
        if (!WalkDirChain(*v, cur.first_cluster, &FindVisitor, &ctx))
        {
            KLOG_WARN_AS(::duetos::core::LogArea::FS, "fs/fat32", "lookup: WalkDirChain failed mid-component", "comp",
                         comp);
            return false;
        }
        if (!ctx.found)
        {
            KLOG_DEBUG_AS(::duetos::core::LogArea::FS, "fs/fat32", "lookup: component not found", "comp", comp);
            PathCachePut(v, orig_path, /*found=*/false, nullptr); // negative cache
            return false;
        }
        CopyEntry(cur, ctx.match);
    }

    CopyEntry(*out, cur);
    PathCachePut(v, orig_path, /*found=*/true, &cur);
    return true;
}

namespace internal
{
void Fat32InvalidatePathCache()
{
    // O(1): bump the generation so every cached slot fails its
    // gen check on the next lookup. No array walk needed.
    ++g_path_cache_gen;
    if (g_path_cache_gen == 0)
        g_path_cache_gen = 1; // skip the "never filled" sentinel on wrap
}
} // namespace internal

} // namespace duetos::fs::fat32
