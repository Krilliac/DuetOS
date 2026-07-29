#include "loader/sxs_dll.h"

#include "arch/x86_64/serial.h"
#include "fs/fat32.h"
#include "loader/pe_exports.h"
#include "loader/pe_loader.h"
#include "log/klog.h"
#include "mm/kheap.h"
#include "security/guard.h"
#include "util/random.h"

namespace duetos::loader
{

namespace
{

using duetos::arch::SerialLineGuard;
using duetos::arch::SerialWrite;
using duetos::arch::SerialWriteHex;
namespace fat = duetos::fs::fat32;

constexpr char AsciiLower(char c)
{
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c;
}

bool NameCiEqual(const char* a, const char* b)
{
    if (a == nullptr || b == nullptr)
        return false;
    u32 i = 0;
    while (a[i] != '\0' && b[i] != '\0')
    {
        if (AsciiLower(a[i]) != AsciiLower(b[i]))
            return false;
        ++i;
    }
    return a[i] == b[i];
}

// A DLL is "already in the set" when some loaded image's EAT-stamped
// name matches, with or without the ".dll" suffix on either side.
// This is what makes the recursive walk cycle-proof: a dependency
// graph with a loop revisits a name that is already present and stops.
u64 FindInSet(const DllSet& set, const char* dll_name)
{
    if (set.images == nullptr || set.count == nullptr || dll_name == nullptr)
        return 0;
    // Strip a trailing ".dll" from the wanted name once.
    char want[64];
    u32 n = 0;
    while (dll_name[n] != '\0' && n < sizeof(want) - 1)
    {
        want[n] = dll_name[n];
        ++n;
    }
    want[n] = '\0';
    if (n >= 4 && want[n - 4] == '.' && AsciiLower(want[n - 3]) == 'd' && AsciiLower(want[n - 2]) == 'l' &&
        AsciiLower(want[n - 1]) == 'l')
    {
        want[n - 4] = '\0';
    }

    for (u64 i = 0; i < *set.count; ++i)
    {
        const core::DllImage& img = set.images[i];
        if (!img.has_exports)
            continue;
        const char* have = core::PeExportsDllName(img.exports);
        if (have == nullptr)
            continue;
        char other[64];
        u32 m = 0;
        while (have[m] != '\0' && m < sizeof(other) - 1)
        {
            other[m] = have[m];
            ++m;
        }
        other[m] = '\0';
        if (m >= 4 && other[m - 4] == '.' && AsciiLower(other[m - 3]) == 'd' && AsciiLower(other[m - 2]) == 'l' &&
            AsciiLower(other[m - 1]) == 'l')
        {
            other[m - 4] = '\0';
        }
        if (NameCiEqual(want, other))
            return img.base_va;
    }
    return 0;
}

// ---------------------------------------------------------------
// File cache. DllImage BORROWS its `file` bytes for the lifetime of
// every process that mapped it (the parsed export table points into
// the buffer), so a side-by-side DLL's bytes can never be freed while
// any such process lives. Rather than leak one copy per spawn, keep a
// small never-freed cache keyed by volume + path: a second process
// launching the same app re-uses the same bytes.
//
// GAP: entries are never evicted - a refcounted cache with an unload
// path lands with process-teardown DLL unmapping, which does not
// exist yet. `kSxsCacheBudgetBytes` bounds the damage in the meantime.
// ---------------------------------------------------------------
constexpr u32 kCacheSlots = 16;

struct CacheEntry
{
    u32 volume;
    char path[64];
    u8* bytes;
    u64 len;
};

CacheEntry g_cache[kCacheSlots];
u64 g_cache_bytes = 0;

CacheEntry* CacheFind(u32 volume, const char* path)
{
    for (auto& e : g_cache)
    {
        if (e.bytes == nullptr || e.volume != volume)
            continue;
        if (NameCiEqual(e.path, path))
            return &e;
    }
    return nullptr;
}

bool CacheInsert(u32 volume, const char* path, u8* bytes, u64 len)
{
    for (auto& e : g_cache)
    {
        if (e.bytes != nullptr)
            continue;
        u32 i = 0;
        while (path[i] != '\0' && i + 1 < sizeof(e.path))
        {
            e.path[i] = path[i];
            ++i;
        }
        e.path[i] = '\0';
        e.volume = volume;
        e.bytes = bytes;
        e.len = len;
        g_cache_bytes += len;
        return true;
    }
    return false;
}

// Read `path` off `volume` into a cached, never-freed buffer.
// Returns false on any of: no such volume, no such file, empty /
// oversize file, cache full, budget exhausted, short read. Every one
// of those is a fail-closed outcome — the caller drops the DLL.
bool ReadCached(u32 volume, const char* path, const u8** out_bytes, u64* out_len)
{
    if (auto* hit = CacheFind(volume, path); hit != nullptr)
    {
        *out_bytes = hit->bytes;
        *out_len = hit->len;
        return true;
    }

    const fat::Volume* v = fat::Fat32Volume(volume);
    if (v == nullptr)
        return false;
    fat::DirEntry entry{};
    if (!fat::Fat32LookupPath(v, path, &entry))
        return false;
    if ((entry.attributes & 0x10) != 0)
        return false; // directory
    // Bound the advertised size BEFORE allocating: a corrupt or
    // hostile directory entry must not be able to request the heap.
    if (entry.size_bytes == 0 || entry.size_bytes > kSxsMaxDllBytes)
        return false;
    if (g_cache_bytes + entry.size_bytes > kSxsCacheBudgetBytes)
    {
        KLOG_WARN("sxs", "side-by-side DLL cache budget exhausted; refusing load");
        KLOG_DEBUG_S("sxs", "  refused", "path", path);
        return false;
    }

    auto* buf = static_cast<u8*>(mm::KMalloc(entry.size_bytes));
    if (buf == nullptr)
    {
        KLOG_WARN("sxs", "KMalloc for side-by-side DLL failed (OOM)");
        KLOG_DEBUG_S("sxs", "  refused", "path", path);
        return false;
    }
    const i64 got = fat::Fat32ReadFile(v, &entry, buf, entry.size_bytes);
    if (got != static_cast<i64>(entry.size_bytes))
    {
        // Short read == a torn FAT chain walk. Never hand a partial
        // image to the PE parser.
        mm::KFree(buf);
        return false;
    }
    if (!CacheInsert(volume, path, buf, entry.size_bytes))
    {
        mm::KFree(buf);
        return false;
    }
    *out_bytes = buf;
    *out_len = entry.size_bytes;
    return true;
}

// Map `bytes` into `as` with a collision-avoiding ASLR roll and
// append it to `set`. Mirrors the roll loop the preload path in
// spawn.cpp uses — two DLLs whose preferred bases are close would
// otherwise land on top of each other after jitter, and the LATER
// load silently overwrites the EARLIER one's pages.
u64 MapAndAppend(const char* label, const u8* bytes, u64 len, duetos::mm::AddressSpace* as, const DllSet& set)
{
    const bool dyn = core::PeIsDynamicBase(bytes, len);
    const u64 size = core::PeImageSizeOf(bytes, len);
    const u64 pref = core::PePreferredBaseOf(bytes, len);
    u64 delta = 0;
    core::DllLoadResult loaded{};
    loaded.status = core::DllLoadStatus::HeaderParseFailed;
    constexpr u32 kMaxRolls = 32;
    for (u32 attempt = 0; attempt < kMaxRolls; ++attempt)
    {
        const u64 trial = dyn ? (core::RandomU64() & 0xFF) * 4096ull : 0ull;
        if (size == 0 || pref == 0)
        {
            // Unparseable extents — let DllLoad re-detect and reject.
            delta = trial;
            loaded = core::DllLoad(bytes, len, as, delta);
            break;
        }
        bool collides = false;
        for (u64 j = 0; j < *set.count; ++j)
        {
            const u64 a_start = set.images[j].base_va;
            const u64 a_end = a_start + set.images[j].size;
            if (a_start < pref + trial + size && pref + trial < a_end)
            {
                collides = true;
                break;
            }
        }
        if (collides && dyn && attempt + 1 < kMaxRolls)
            continue;
        delta = trial;
        loaded = core::DllLoad(bytes, len, as, delta);
        break;
    }
    if (loaded.status != core::DllLoadStatus::Ok)
    {
        SerialLineGuard guard;
        SerialWrite("[sxs] DllLoad failed name=\"");
        SerialWrite(label);
        SerialWrite("\" status=");
        SerialWrite(core::DllLoadStatusName(loaded.status));
        SerialWrite("\n");
        return 0;
    }

    set.images[*set.count] = loaded.image;
    ++(*set.count);
    // Bind the new DLL's own IAT against everything loaded so far.
    // Without this its exports call through unpatched slots and the
    // first indirect call from inside it faults.
    (void)core::PeResolveImportsForLoadedImage(loaded.image.file, loaded.image.file_len, as, set.images,
                                               *set.count - 1);
    {
        SerialLineGuard guard;
        SerialWrite("[sxs] loaded name=\"");
        SerialWrite(label);
        SerialWrite("\" base=");
        SerialWriteHex(loaded.image.base_va);
        SerialWrite(" size=");
        SerialWriteHex(loaded.image.size);
        SerialWrite(" aslr_delta=");
        SerialWriteHex(delta);
        SerialWrite("\n");
    }
    return loaded.image.base_va;
}

// Append `name` to `dir` in `out` (capacity `cap`). Returns false if
// it would not fit — the caller then declines the load rather than
// searching a silently truncated path.
bool JoinPath(const char* dir, const char* name, char* out, u64 cap)
{
    u64 n = 0;
    for (u64 i = 0; dir[i] != '\0'; ++i)
    {
        if (n + 1 >= cap)
            return false;
        out[n++] = dir[i];
    }
    for (u64 i = 0; name[i] != '\0'; ++i)
    {
        if (n + 1 >= cap)
            return false;
        out[n++] = name[i];
    }
    out[n] = '\0';
    return n > 0;
}

// Derive the DOS 8.3 short name for `name` ("UnityPlayer.dll" ->
// "UNITYPLA.DLL").
//
// GAP: no "~1" tilde disambiguation - the kernel would have to
// enumerate the directory and count collisions to know which numbered
// alias Windows would have picked. Revisit when the FAT32 layer grows
// on-demand directory enumeration; today the image builder writes
// short names only, so the truncated form is the one on disk.
void ShortName83(const char* name, char* out, u64 cap)
{
    if (cap < 13)
    {
        out[0] = '\0';
        return;
    }
    u64 dot = 0;
    u64 len = 0;
    bool have_dot = false;
    for (; name[len] != '\0'; ++len)
    {
        if (name[len] == '.')
        {
            dot = len;
            have_dot = true;
        }
    }
    const u64 base_len = have_dot ? dot : len;
    u64 n = 0;
    for (u64 i = 0; i < base_len && n < 8; ++i)
        out[n++] = static_cast<char>(name[i] >= 'a' && name[i] <= 'z' ? name[i] - 32 : name[i]);
    if (have_dot)
    {
        out[n++] = '.';
        for (u64 i = dot + 1, e = 0; name[i] != '\0' && e < 3; ++i, ++e)
            out[n++] = static_cast<char>(name[i] >= 'a' && name[i] <= 'z' ? name[i] - 32 : name[i]);
    }
    out[n] = '\0';
}

} // namespace

bool SxsSourceFromPath(u32 volume, const char* image_path, SxsSource* out)
{
    if (out == nullptr)
        return false;
    out->valid = false;
    out->volume = volume;
    out->dir[0] = '\0';
    if (image_path == nullptr || image_path[0] == '\0')
        return false;

    u64 len = 0;
    i64 last_sep = -1;
    for (; image_path[len] != '\0'; ++len)
    {
        if (len >= sizeof(out->dir) + 64)
            return false; // absurdly long path: refuse rather than guess
        if (image_path[len] == '/' || image_path[len] == '\\')
            last_sep = static_cast<i64>(len);
    }
    if (last_sep == static_cast<i64>(len) - 1)
        return false; // path names a directory, not an image

    if (last_sep < 0)
    {
        // Bare basename ("FOO.EXE") == volume root.
        out->dir[0] = '/';
        out->dir[1] = '\0';
        out->valid = true;
        return true;
    }
    const u64 dir_len = static_cast<u64>(last_sep) + 1; // keep the separator
    if (dir_len >= sizeof(out->dir))
        return false;
    for (u64 i = 0; i < dir_len; ++i)
        out->dir[i] = image_path[i] == '\\' ? '/' : image_path[i];
    out->dir[dir_len] = '\0';
    out->valid = true;
    return true;
}

u64 SxsLoadNamed(const SxsSource& src, const char* dll_name, duetos::mm::AddressSpace* as, const DllSet& set)
{
    if (!src.valid || dll_name == nullptr || dll_name[0] == '\0' || as == nullptr)
        return 0;
    if (set.images == nullptr || set.count == nullptr)
        return 0;
    if (const u64 already = FindInSet(set, dll_name); already != 0)
        return already;
    if (*set.count >= set.cap)
        return 0;

    // API-set contract names ("api-ms-win-*") are not files on any
    // filesystem, on Windows or here. Never go to disk for one.
    if (core::IsApiSetContract(dll_name))
        return 0;

    char path[104];
    if (!JoinPath(src.dir, dll_name, path, sizeof(path)))
        return 0;

    const u8* bytes = nullptr;
    u64 len = 0;
    if (!ReadCached(src.volume, path, &bytes, &len))
    {
        // The image builder writes 8.3 short names, so an import
        // naming "UnityPlayer.dll" will not match the long form.
        // Retry against the truncated name before giving up.
        char sfn[16];
        ShortName83(dll_name, sfn, sizeof(sfn));
        if (sfn[0] == '\0' || NameCiEqual(sfn, dll_name))
            return 0;
        if (!JoinPath(src.dir, sfn, path, sizeof(path)))
            return 0;
        if (!ReadCached(src.volume, path, &bytes, &len))
            return 0;
    }

    // SECURITY GATE. These bytes came off a guest-writable volume and
    // are about to execute inside the process's address space with the
    // process's authority — exactly the exposure a disk-loaded .exe has
    // when `PeLoad` gates it. Same gate, same ImageKind. Advisory mode
    // logs and allows; Enforce mode prompts and can refuse.
    const security::ImageDescriptor gd{security::ImageKind::WindowsPE, path, bytes, len};
    if (!security::Gate(gd))
    {
        SerialLineGuard guard;
        SerialWrite("[sxs] security guard blocked path=\"");
        SerialWrite(path);
        SerialWrite("\"\n");
        return 0;
    }

    return MapAndAppend(path, bytes, len, as, set);
}

namespace
{

// Recursion carrier for PeEnumImportDlls' C-style callback.
struct WalkCtx
{
    const SxsSource* src;
    duetos::mm::AddressSpace* as;
    const DllSet* set;
    u32 depth;
    u32 loaded;
};

bool WalkImport(const char* dll_name, void* ctx);

// Depth- and count-bounded recursive walk. Both bounds are hard: a
// hostile import graph can be deep (self-referential chain), wide (64
// descriptors per image), or both, and neither may be allowed to
// exhaust the kernel stack or the address space.
u32 ResolveInto(const SxsSource& src, const u8* image, u64 image_len, duetos::mm::AddressSpace* as, const DllSet& set,
                u32 depth, u32 already_loaded)
{
    if (depth >= kSxsMaxDepth || image == nullptr || image_len == 0)
        return 0;
    WalkCtx ctx{&src, as, &set, depth, already_loaded};
    (void)core::PeEnumImportDlls(image, image_len, &WalkImport, &ctx);
    return ctx.loaded - already_loaded;
}

bool WalkImport(const char* dll_name, void* ctx)
{
    auto* c = static_cast<WalkCtx*>(ctx);
    if (c->loaded >= kSxsMaxLoads)
    {
        KLOG_WARN("sxs", "side-by-side load cap reached; remaining imports left to the preload set");
        return false; // stop the walk
    }
    if (*c->set->count >= c->set->cap)
        return false;
    // A name already satisfied by the preload set / an earlier
    // side-by-side load never goes to disk. This is also what makes a
    // cyclic dependency graph terminate.
    if (FindInSet(*c->set, dll_name) != 0)
        return true;

    const u64 base = SxsLoadNamed(*c->src, dll_name, c->as, *c->set);
    if (base == 0)
        return true; // miss: the normal thunk / api-set fallbacks still apply
    ++c->loaded;

    // The DLL we just loaded may itself ship beside further DLLs.
    const core::DllImage& just = c->set->images[*c->set->count - 1];
    c->loaded += ResolveInto(*c->src, just.file, just.file_len, c->as, *c->set, c->depth + 1, c->loaded);
    return true;
}

} // namespace

u32 SxsResolveImports(const SxsSource& src, const u8* image, u64 image_len, duetos::mm::AddressSpace* as,
                      const DllSet& set, u32 depth)
{
    if (!src.valid || as == nullptr || set.images == nullptr || set.count == nullptr)
        return 0;
    return ResolveInto(src, image, image_len, as, set, depth, /*already_loaded=*/0);
}

u32 SxsLoadDirectory(u32 volume, const char* dir_path, duetos::mm::AddressSpace* as, const DllSet& set)
{
    if (dir_path == nullptr || as == nullptr || set.images == nullptr || set.count == nullptr)
        return 0;
    const fat::Volume* v = fat::Fat32Volume(volume);
    if (v == nullptr)
        return 0;
    fat::DirEntry dir{};
    if (!fat::Fat32LookupPath(v, dir_path, &dir) || (dir.attributes & 0x10) == 0)
        return 0;

    constexpr u32 kMaxListing = 32;
    fat::DirEntry kids[kMaxListing];
    const u32 count = fat::Fat32ListDirByCluster(v, dir.first_cluster, kids, kMaxListing);

    SxsSource src{};
    if (!SxsSourceFromPath(volume, dir_path, &src))
        return 0;
    // SxsSourceFromPath strips the basename; for a directory path we
    // want the directory itself plus a separator.
    if (!JoinPath(dir_path, "/", src.dir, sizeof(src.dir)))
        return 0;

    u32 loaded = 0;
    for (u32 i = 0; i < count && *set.count < set.cap && loaded < kSxsMaxLoads; ++i)
    {
        if ((kids[i].attributes & 0x10) != 0)
            continue;
        const char* n = kids[i].name;
        u32 nl = 0;
        while (n[nl] != '\0')
            ++nl;
        if (nl < 4 || n[nl - 4] != '.' || AsciiLower(n[nl - 3]) != 'd' || AsciiLower(n[nl - 2]) != 'l' ||
            AsciiLower(n[nl - 1]) != 'l')
        {
            continue;
        }
        if (SxsLoadNamed(src, n, as, set) != 0)
            ++loaded;
    }
    return loaded;
}

u64 SxsCacheBytes()
{
    return g_cache_bytes;
}

void SxsSelfTest()
{
    const char* fail = nullptr;
    SxsSource s{};

    if (fail == nullptr && (!SxsSourceFromPath(0, "FOO.EXE", &s) || !s.valid || !NameCiEqual(s.dir, "/")))
        fail = "root-basename";
    if (fail == nullptr && (!SxsSourceFromPath(1, "/GAMES/FOO.EXE", &s) || !s.valid || !NameCiEqual(s.dir, "/GAMES/")))
        fail = "subdir";
    if (fail == nullptr && (!SxsSourceFromPath(0, "\\GAMES\\FOO.EXE", &s) || !NameCiEqual(s.dir, "/GAMES/")))
        fail = "backslash";
    // A path ending in a separator names a directory, not an image.
    if (fail == nullptr && SxsSourceFromPath(0, "/GAMES/", &s))
        fail = "dir-path-accepted";
    if (fail == nullptr && (SxsSourceFromPath(0, nullptr, &s) || SxsSourceFromPath(0, "", &s)))
        fail = "null-path-accepted";

    char sfn[16];
    ShortName83("UnityPlayer.dll", sfn, sizeof(sfn));
    if (fail == nullptr && !NameCiEqual(sfn, "UNITYPLA.DLL"))
        fail = "sfn-truncate";
    ShortName83("sxslib.dll", sfn, sizeof(sfn));
    if (fail == nullptr && !NameCiEqual(sfn, "SXSLIB.DLL"))
        fail = "sfn-passthrough";

    char joined[104];
    if (fail == nullptr &&
        (!JoinPath("/GAMES/", "a.dll", joined, sizeof(joined)) || !NameCiEqual(joined, "/GAMES/a.dll")))
    {
        fail = "join";
    }
    // Overflow must be refused, not truncated.
    char tiny[6];
    if (fail == nullptr && JoinPath("/GAMES/", "a.dll", tiny, sizeof(tiny)))
        fail = "join-overflow-accepted";

    if (fail == nullptr && SxsCacheBytes() > kSxsCacheBudgetBytes)
        fail = "budget-exceeded";

    SerialLineGuard guard;
    if (fail == nullptr)
    {
        SerialWrite("[sxs-selftest] PASS (path derivation, 8.3 fallback, join bounds, budget)\n");
    }
    else
    {
        SerialWrite("[sxs-selftest] FAIL ");
        SerialWrite(fail);
        SerialWrite("\n");
    }
}

} // namespace duetos::loader
