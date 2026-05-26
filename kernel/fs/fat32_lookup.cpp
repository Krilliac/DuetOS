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
#include "util/compiler.h"

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
    // Per-entry seqlock counter — odd while a writer is mid-update,
    // even when stable. Readers (the lock-free fast-path in
    // `PathCacheGetSeqlock` below) check `write_seq` twice across
    // the entry copy; if it changed or was odd, the snapshot was
    // racy and the reader falls through to the mutex-protected slow
    // path. Writers (`PathCachePut`, called under `Fat32Guard`)
    // atomically bump to odd, fence, write fields, fence, bump to
    // even — the classic seqlock pattern. Sized to u64 so a write
    // burst can't wrap into an even value that coincides with a
    // stale reader's prior even snapshot.
    u64 write_seq;
    const Volume* v;
    u64 gen;
    bool valid;
    bool found;
    char path[kPathCacheKeyMax];
    DirEntry entry;
};

constinit PathCacheEntry g_path_cache[kPathCacheSlots] = {};
constinit u64 g_path_cache_gen = 1; // 0 reserved for "never filled"

DUETOS_NO_SANITIZE_WRAP u64 PathHash(const Volume* v, const char* p)
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
// CALLER MUST HOLD `Fat32Guard`. The mutex-free fast path lives in
// `PathCacheGetSeqlock` below — this slow variant exists for code
// paths that already hold the guard (e.g. an internal walk that
// landed in the slow walker but wants to re-check the cache after
// a concurrent peer published a hit).
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

// Lock-free cache probe. Called BEFORE acquiring `Fat32Guard` so a
// boot-storm pattern (NOTES.TXT / TEST.* / TRTEST.BIN / KERNEL.FIX
// probes repeated dozens of times from the ring3-smoke + win32 PE
// + linux synfs paths) skips the mutex entirely once the entry is
// in the cache. Saves a `MutexLock` + held-stack push + cli/sti
// + `MutexUnlock` per cache hit — under SMP saturation this is the
// "win against driver-mutex contention" the Roadmap entry calls
// out as the smallest concrete FAT32 fix.
//
// Seqlock-style read: snapshot `write_seq` before + after the
// entry copy. A writer (`PathCachePut`) bumps the seq to ODD
// before mutating fields, back to EVEN after — so a reader that
// sees odd-before OR seq-after != seq-before knows its snapshot
// was racy and falls through to the mutex slow path. The
// generation counter `g_path_cache_gen` is checked AFTER the seq
// completes the read so a concurrent invalidation
// (`Fat32InvalidatePathCache`, called from every mutating API)
// downgrades to a miss instead of returning a stale entry.
//
// Memory ordering: ACQUIRE on both seq loads pairs with the
// RELEASE writes in `PathCachePut`. ACQUIRE on the gen load
// pairs with the RELEASE in `Fat32InvalidatePathCache` so an
// invalidation that landed BEFORE this reader started observes
// as a generation mismatch.
//
// Returns true (with `*found_out`/`*out` filled) on a clean hit;
// false otherwise — caller proceeds under the guard.
bool PathCacheGetSeqlock(const Volume* v, const char* path, DirEntry* out, bool* found_out)
{
    PathCacheEntry& e = g_path_cache[PathHash(v, path) % kPathCacheSlots];

    const u64 seq_before = __atomic_load_n(&e.write_seq, __ATOMIC_ACQUIRE);
    if ((seq_before & 1u) != 0)
    {
        // Writer mid-update — defer to slow path.
        return false;
    }

    // Snapshot the entry fields into stack locals so a concurrent
    // writer can't tear our values mid-read.
    const Volume* snap_v = e.v;
    const u64 snap_gen = e.gen;
    const bool snap_valid = e.valid;
    const bool snap_found = e.found;
    char snap_path[kPathCacheKeyMax];
    for (u32 i = 0; i < kPathCacheKeyMax; ++i)
    {
        snap_path[i] = e.path[i];
        if (snap_path[i] == 0)
            break;
    }
    DirEntry snap_entry;
    if (snap_valid && snap_found)
        CopyEntry(snap_entry, e.entry);

    const u64 seq_after = __atomic_load_n(&e.write_seq, __ATOMIC_ACQUIRE);
    if (seq_after != seq_before)
    {
        // A write completed during our copy — values may be torn.
        return false;
    }

    // Generation barrier (paired with the bump in
    // Fat32InvalidatePathCache). Catches the race
    // "writer invalidated cache → our snapshot is stale gen".
    const u64 global_gen = __atomic_load_n(&g_path_cache_gen, __ATOMIC_ACQUIRE);
    if (!snap_valid || snap_gen != global_gen || snap_v != v || !PathStrEqual(snap_path, path))
    {
        return false;
    }

    *found_out = snap_found;
    if (snap_found)
        CopyEntry(*out, snap_entry);
    return true;
}

// CALLER MUST HOLD `Fat32Guard`. Atomically replaces a cache slot
// using seqlock writes so the lock-free reader above can either
// see the old value or the new value, never a half-update.
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

    // Seqlock write: bump to odd FIRST so a concurrent reader sees
    // the in-flight write and bails. Release-store pairs with the
    // reader's acquire-load above.
    const u64 prev_seq = __atomic_load_n(&e.write_seq, __ATOMIC_RELAXED);
    const u64 odd_seq = (prev_seq | 1u);
    __atomic_store_n(&e.write_seq, odd_seq, __ATOMIC_RELEASE);

    e.v = v;
    e.gen = g_path_cache_gen;
    e.valid = true;
    e.found = found;
    for (u32 i = 0; i <= n; ++i)
        e.path[i] = path[i];
    if (found && entry != nullptr)
        CopyEntry(e.entry, *entry);

    // Bump to next even — reader that started before this update
    // either saw odd (bailed) or sees a different even (bails on
    // the seq-after check).
    __atomic_store_n(&e.write_seq, odd_seq + 1u, __ATOMIC_RELEASE);
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
    if (v == nullptr || path == nullptr || out == nullptr)
    {
        KLOG_WARN_A(::duetos::core::LogArea::FS, "fs/fat32", "lookup: null volume / path / out");
        return false;
    }

    // Lock-free fast path. Boot-storm workloads (ring3 + Linux
    // synfs + Win32 PE smokes all hitting FAT32 concurrently) repeat
    // the same dozen paths hundreds of times between mutations; the
    // seqlock probe avoids `Fat32Guard`'s mutex acquire on every
    // verified cache hit. Falls through to the locked slow path on
    // any racy / stale / missing entry. See `PathCacheGetSeqlock`
    // for the seqlock + generation-counter contract.
    {
        bool cached_found = false;
        if (PathCacheGetSeqlock(v, path, out, &cached_found))
        {
            return cached_found;
        }
    }

    Fat32Guard guard;
    KDBG_S(Fat32Lookup, "fs/fat32", "lookup", "path", path);
    // Trace — hundreds of these fire per boot from klog-persist
    // rotation, registry probes, and shell ls. DEBUG was too loud;
    // an operator chasing a lookup race can flip to Trace explicitly.
    KLOG_TRACE_AS(::duetos::core::LogArea::FS, "fs/fat32", "lookup", "path", path);

    // Memoized result? (Stable key = the caller's original path
    // bytes, before slash-stripping / component descent.) Re-probed
    // here under the guard in case a concurrent peer published
    // between our lock-free probe above and this point — saves the
    // full walk in the publish-during-fast-path window.
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
            // Trace — probe-style misses are the expected path for
            // klog-persist rotation slot lookups, the path cache's
            // negative-cache priming, and shell completion. DEBUG
            // flooded the serial console on every boot.
            KLOG_TRACE_AS(::duetos::core::LogArea::FS, "fs/fat32", "lookup: component not found", "comp", comp);
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
    //
    // Atomic store with RELEASE ordering — pairs with the ACQUIRE
    // load in `PathCacheGetSeqlock` so the lock-free reader on a
    // peer CPU observes the bumped generation as a miss instead of
    // returning a stale entry. Caller already holds `Fat32Guard`
    // (every mutating API does), so the read-modify-write doesn't
    // race a peer writer; the atomic is only for the publish edge
    // against fast-path readers.
    u64 next = g_path_cache_gen + 1;
    if (next == 0)
        next = 1; // skip the "never filled" sentinel on wrap
    __atomic_store_n(&g_path_cache_gen, next, __ATOMIC_RELEASE);
}
} // namespace internal

} // namespace duetos::fs::fat32
