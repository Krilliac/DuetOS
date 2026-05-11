#include "fs/vfs.h"

#include "arch/x86_64/serial.h"
#include "fs/mount.h"
#include "log/klog.h"
#include "core/panic.h"
#include "util/saturating.h"

namespace duetos::fs
{

namespace
{

// Byte-wise NUL-terminated string compare with a hard length cap.
// Returns true iff both strings are identical and both terminate
// (either via NUL on `a` within `alen`, or on `b`).
bool StrEqN(const char* a, u64 alen, const char* b)
{
    if (a == nullptr || b == nullptr)
    {
        return false;
    }
    for (u64 i = 0; i < alen; ++i)
    {
        if (b[i] == '\0')
        {
            return false; // b is shorter than a's len
        }
        if (a[i] != b[i])
        {
            return false;
        }
    }
    // a's first `alen` bytes matched. Require b's next byte to be NUL
    // so the strings are actually the same length.
    return b[alen] == '\0';
}


u32 CStrLen(const char* s)
{
    u32 n = 0;
    if (s != nullptr)
    {
        while (s[n] != '\0')
        {
            ++n;
        }
    }
    return n;
}

bool CStrLenBounded(const char* s, u64 max, u32* out_len)
{
    if (s == nullptr || out_len == nullptr || max == 0)
    {
        return false;
    }
    u64 n = 0;
    while (n < max && s[n] != '\0')
    {
        ++n;
    }
    if (n > 0xFFFFFFFFULL)
    {
        return false;
    }
    *out_len = static_cast<u32>(n);
    return true;
}

bool MountPrefixMatch(const char* path, u32 path_len, const char* mount_point, u32 mount_len)
{
    if (path == nullptr || mount_point == nullptr || mount_len == 0 || mount_len > path_len)
    {
        return false;
    }
    for (u32 i = 0; i < mount_len; ++i)
    {
        if (path[i] != mount_point[i])
        {
            return false;
        }
    }
    if (mount_len == path_len)
    {
        return true;
    }
    return path[mount_len] == '\0' || path[mount_len] == '/';
}

// Dentry cache. Maps (parent, component_name) → child for ramfs
// directory lookups. The ramfs trees are constexpr / `.rodata` so
// we can't store hash links inside the nodes themselves; this is
// a side table of cached hits (only successful FindChild results
// land here). Subsequent lookups of the same component within
// the same parent skip the linear scan.
//
// Size: 128 slots × 24 B = ~3 KiB. Single-bucket open addressing
// — on collision the older entry is overwritten. Hit-only caching
// keeps the eviction policy trivial; misses always pay the
// linear scan, which is fine because the ramfs tree is small
// and each missed name is unlikely to be repeated under the
// same parent.
constexpr u32 kDentryCacheSize = 128;
static_assert((kDentryCacheSize & (kDentryCacheSize - 1)) == 0, "dentry cache size must be a power of two");

struct DentryCacheEntry
{
    const RamfsNode* parent; ///< nullptr = empty slot
    const RamfsNode* child;
    u32 name_hash; ///< Full hash; used as a quick tiebreaker against same-bucket misses.
};

constinit DentryCacheEntry g_dentry_cache[kDentryCacheSize] = {};
// Lifetime cache stats — saturating per class BB. Reported by
// inspect / shell; never used for modular arithmetic.
constinit util::SatU64 g_dentry_cache_hits = 0;
constinit util::SatU64 g_dentry_cache_misses = 0;

inline u32 DentryHash(const RamfsNode* parent, const char* name, u64 name_len)
{
    // Mix the parent pointer into the seed so identical component
    // names under different parents land in different buckets.
    u32 h = static_cast<u32>(reinterpret_cast<uptr>(parent) >> 4);
    for (u64 i = 0; i < name_len; ++i)
    {
        h = h * 131u + static_cast<u32>(static_cast<u8>(name[i]));
    }
    return h;
}

const RamfsNode* DentryCacheLookup(const RamfsNode* parent, const char* name, u64 name_len)
{
    const u32 hash = DentryHash(parent, name, name_len);
    const u32 bucket = hash & (kDentryCacheSize - 1);
    const DentryCacheEntry& e = g_dentry_cache[bucket];
    if (e.parent != parent || e.name_hash != hash || e.child == nullptr)
    {
        return nullptr;
    }
    // Verify the actual name bytes match — the hash + parent equality
    // is necessary but not sufficient (32-bit hash collisions exist).
    if (!StrEqN(name, name_len, e.child->name))
    {
        return nullptr;
    }
    ++g_dentry_cache_hits;
    return e.child;
}

void DentryCacheInsert(const RamfsNode* parent, const RamfsNode* child)
{
    if (parent == nullptr || child == nullptr || child->name == nullptr)
    {
        return;
    }
    const u64 name_len = CStrLen(child->name);
    const u32 hash = DentryHash(parent, child->name, name_len);
    const u32 bucket = hash & (kDentryCacheSize - 1);
    g_dentry_cache[bucket].parent = parent;
    g_dentry_cache[bucket].child = child;
    g_dentry_cache[bucket].name_hash = hash;
}

// Locate a child named [name, name+name_len) inside `dir`. Hits the
// dentry cache first; falls through to an O(children) linear scan
// on miss and seeds the cache with the result. Returns nullptr if
// dir is null, not a directory, has no children, or no match.
const RamfsNode* FindChild(const RamfsNode* dir, const char* name, u64 name_len)
{
    if (!RamfsIsDir(dir) || dir->children == nullptr)
    {
        return nullptr;
    }
    if (const RamfsNode* hit = DentryCacheLookup(dir, name, name_len))
    {
        return hit;
    }
    ++g_dentry_cache_misses;
    for (u64 i = 0; dir->children[i] != nullptr; ++i)
    {
        const RamfsNode* c = dir->children[i];
        if (StrEqN(name, name_len, c->name))
        {
            DentryCacheInsert(dir, c);
            return c;
        }
    }
    return nullptr;
}

} // namespace

const RamfsNode* VfsLookup(const RamfsNode* root, const char* path, u64 path_max)
{
    if (root == nullptr || path == nullptr || path_max == 0)
    {
        return nullptr;
    }

    const RamfsNode* cur = root;

    u64 i = 0;
    while (i < path_max && path[i] != '\0')
    {
        // Skip any run of '/'. Treats "/a//b", "//a/b", "a/b/"
        // identically to "/a/b".
        while (i < path_max && path[i] == '/')
        {
            ++i;
        }
        if (i >= path_max || path[i] == '\0')
        {
            break;
        }

        // Extract the next component [i .. j).
        u64 j = i;
        while (j < path_max && path[j] != '/' && path[j] != '\0')
        {
            ++j;
        }
        const u64 component_len = j - i;

        // "." — stay. ".." — REJECTED (would escape a jail; see
        // the header comment for rationale).
        if (component_len == 1 && path[i] == '.')
        {
            i = j;
            continue;
        }
        if (component_len == 2 && path[i] == '.' && path[i + 1] == '.')
        {
            return nullptr;
        }

        // Cannot walk through a file.
        if (!RamfsIsDir(cur))
        {
            return nullptr;
        }

        const RamfsNode* next = FindChild(cur, path + i, component_len);
        if (next == nullptr)
        {
            return nullptr;
        }
        cur = next;

        i = j;
    }

    return cur;
}

bool VfsFormatDiskMountPoint(u32 idx, char* dst, u64 dst_cap)
{
    if (dst == nullptr || dst_cap == 0)
    {
        return false;
    }
    dst[0] = '\0';

    constexpr const char prefix[] = "/disk/";
    u64 pos = 0;
    for (; pos < sizeof(prefix) - 1; ++pos)
    {
        if (pos + 1 >= dst_cap)
        {
            dst[0] = '\0';
            return false;
        }
        dst[pos] = prefix[pos];
    }

    char digits[10] = {};
    u32 n = idx;
    u32 count = 0;
    do
    {
        digits[count++] = static_cast<char>('0' + (n % 10));
        n /= 10;
    } while (n != 0 && count < sizeof(digits));

    if (pos + count >= dst_cap)
    {
        dst[0] = '\0';
        return false;
    }
    while (count > 0)
    {
        dst[pos++] = digits[--count];
    }
    dst[pos] = '\0';
    return true;
}

bool VfsMountVisibleFromRoot(const RamfsNode* root, const char* mount_point)
{
    if (root == nullptr || mount_point == nullptr || mount_point[0] != '/')
    {
        return false;
    }

    // v0 policy: the trusted boot namespace owns the global mount
    // table. Sandboxed / custom roots must opt in by materialising
    // the mount point as a ramfs directory in their own tree. This
    // keeps today's immutable ramfs small while preserving the shape
    // needed for future non-ramfs process roots.
    if (root == RamfsTrustedRoot())
    {
        return true;
    }

    const RamfsNode* graft = VfsLookup(root, mount_point, 64);
    return RamfsIsDir(graft);
}

namespace
{

struct VisibleMountResolveState
{
    const RamfsNode* root;
    const char* path;
    u32 path_len;
    const MountEntry* best;
    u32 best_len;
};

bool ConsiderVisibleMount(const MountEntry& entry, MountId, void* cookie)
{
    auto* st = static_cast<VisibleMountResolveState*>(cookie);
    const u32 mount_len = CStrLen(entry.mount_point);
    if (entry.fs_type == FsType::Ramfs || mount_len <= st->best_len)
    {
        return true;
    }
    if (!MountPrefixMatch(st->path, st->path_len, entry.mount_point, mount_len))
    {
        return true;
    }
    if (!VfsMountVisibleFromRoot(st->root, entry.mount_point))
    {
        return true;
    }
    st->best = &entry;
    st->best_len = mount_len;
    return true;
}

} // namespace

const MountEntry* VfsMountResolveVisible(const RamfsNode* root, const char* path, u64 path_max,
                                         const char** out_subpath)
{
    if (out_subpath != nullptr)
    {
        *out_subpath = nullptr;
    }
    if (root == nullptr || path == nullptr || path[0] != '/' || path_max == 0)
    {
        return nullptr;
    }

    VisibleMountResolveState st{};
    st.root = root;
    st.path = path;
    if (!CStrLenBounded(path, path_max, &st.path_len))
    {
        return nullptr;
    }
    VfsMountEnumerate(ConsiderVisibleMount, &st);
    if (st.best == nullptr)
    {
        return nullptr;
    }
    if (out_subpath != nullptr)
    {
        if (st.best_len == st.path_len)
        {
            *out_subpath = "/";
        }
        else
        {
            const char* tail = path + st.best_len;
            *out_subpath = (tail[0] == '\0') ? "/" : tail;
        }
    }
    return st.best;
}

// =====================================================
// Generic VfsNode helpers + cross-mount resolver.
// =====================================================

bool VfsNodeIsValid(const VfsNode& n)
{
    return n.backend != VfsBackend::Invalid;
}

bool VfsNodeIsDir(const VfsNode& n)
{
    if (n.backend == VfsBackend::Ramfs)
    {
        return RamfsIsDir(n.ramfs);
    }
    if (n.backend == VfsBackend::Fat32)
    {
        return (n.fat32_entry.attributes & 0x10) != 0;
    }
    if (n.backend == VfsBackend::DuetFs)
    {
        return n.duetfs_kind == 2; // duetfs::kKindDir
    }
    return false;
}

bool VfsNodeIsFile(const VfsNode& n)
{
    if (n.backend == VfsBackend::Ramfs)
    {
        return n.ramfs != nullptr && n.ramfs->type == RamfsNodeType::kFile;
    }
    if (n.backend == VfsBackend::Fat32)
    {
        return (n.fat32_entry.attributes & 0x10) == 0;
    }
    if (n.backend == VfsBackend::DuetFs)
    {
        return n.duetfs_kind == 1; // duetfs::kKindFile
    }
    return false;
}

u64 VfsNodeSize(const VfsNode& n)
{
    if (n.backend == VfsBackend::Ramfs)
    {
        return n.ramfs != nullptr ? n.ramfs->file_size : 0;
    }
    if (n.backend == VfsBackend::Fat32)
    {
        return n.fat32_entry.size_bytes;
    }
    if (n.backend == VfsBackend::DuetFs)
    {
        return n.duetfs_size_bytes;
    }
    return 0;
}

VfsNode VfsResolve(const RamfsNode* root, const char* path, u64 path_max)
{
    VfsNode out{};
    out.backend = VfsBackend::Invalid;
    if (path == nullptr || path_max == 0)
    {
        return out;
    }

    // Mount-registry dispatch only fires when the path is absolute
    // (a leading '/'). Relative paths are always ramfs-from-root —
    // sandbox roots stay sandbox roots. The mount registry is a
    // global namespace; relative paths are anchored to the caller
    // and must not climb out of it.
    if (path[0] == '/')
    {
        const char* sub = nullptr;
        const MountEntry* me = VfsMountResolveVisible(root, path, path_max, &sub);
        if (me != nullptr && sub != nullptr)
        {
            const VfsBackendOps* ops = VfsBackendForFsType(me->fs_type);
            if (ops != nullptr && ops->lookup != nullptr)
            {
                if (ops->lookup(me->block_handle, sub, &out))
                {
                    return out;
                }
            }
            // A visible mount matched, but lookup missed / no backend
            // is wired. Falling through to ramfs here would let a
            // ramfs node pierce a mounted subtree.
            out.backend = VfsBackend::Invalid;
            return out;
        }
    }

    // Ramfs fall-through: the explicit `root` arg is authoritative.
    const RamfsNode* n = VfsLookup(root, path, path_max);
    if (n == nullptr)
    {
        return out;
    }
    out.backend = VfsBackend::Ramfs;
    out.ramfs = n;
    return out;
}

namespace
{

void Expect(bool cond, const char* what)
{
    if (cond)
    {
        return;
    }
    ::duetos::arch::SerialWrite("[fs/vfs-selftest] FAIL ");
    ::duetos::arch::SerialWrite(what);
    ::duetos::arch::SerialWrite("\n");
    ::duetos::core::Panic("fs/vfs", "VfsSelfTest assertion failed");
}

} // namespace

void VfsSelfTest()
{
    KLOG_TRACE_SCOPE("fs/vfs", "VfsSelfTest");
    arch::SerialWrite("[fs/vfs] self-test start\n");

    const RamfsNode* trusted = RamfsTrustedRoot();
    const RamfsNode* sandbox = RamfsSandboxRoot();
    Expect(trusted != nullptr, "RamfsTrustedRoot non-null");
    Expect(sandbox != nullptr, "RamfsSandboxRoot non-null");
    Expect(RamfsIsDir(trusted), "trusted root is a directory");
    Expect(RamfsIsDir(sandbox), "sandbox root is a directory");

    // ----- Null / zero-length guard rails -----
    Expect(VfsLookup(nullptr, "/etc/version", 64) == nullptr, "null root rejected");
    Expect(VfsLookup(trusted, nullptr, 64) == nullptr, "null path rejected");
    Expect(VfsLookup(trusted, "/etc/version", 0) == nullptr, "path_max=0 rejected");

    // ----- Empty / root-only paths return the root unchanged -----
    Expect(VfsLookup(trusted, "", 64) == trusted, "empty string resolves to root");
    Expect(VfsLookup(trusted, "/", 64) == trusted, "single slash resolves to root");
    Expect(VfsLookup(trusted, "//", 64) == trusted, "double slash resolves to root");
    Expect(VfsLookup(trusted, "///", 64) == trusted, "triple slash resolves to root");
    Expect(VfsLookup(trusted, ".", 64) == trusted, "single dot resolves to root");
    Expect(VfsLookup(trusted, "./", 64) == trusted, "dot-slash resolves to root");
    Expect(VfsLookup(trusted, "/./", 64) == trusted, "slash-dot-slash resolves to root");
    Expect(VfsLookup(trusted, "././.", 64) == trusted, "multiple dots resolve to root");

    // ----- Positive lookups against the trusted tree -----
    const RamfsNode* etc = VfsLookup(trusted, "/etc", 64);
    Expect(etc != nullptr && RamfsIsDir(etc), "/etc resolves to a directory");
    const RamfsNode* version = VfsLookup(trusted, "/etc/version", 64);
    Expect(version != nullptr, "/etc/version resolves");
    Expect(!RamfsIsDir(version), "/etc/version is a file");
    Expect(version->file_size > 0, "/etc/version has bytes");
    Expect(VfsLookup(trusted, "/bin/hello", 64) != nullptr, "/bin/hello resolves");
    Expect(VfsLookup(trusted, "/bin/exit.elf", 64) != nullptr, "/bin/exit.elf resolves");
    Expect(VfsLookup(trusted, "/bin/hello.exe", 64) != nullptr, "/bin/hello.exe resolves");
    Expect(VfsLookup(trusted, "/etc/motd", 64) != nullptr, "/etc/motd resolves");
    Expect(VfsLookup(trusted, "/etc/profile", 64) != nullptr, "/etc/profile resolves");
    Expect(VfsLookup(trusted, "/etc/man/ls", 64) != nullptr, "/etc/man/ls resolves (3-deep)");
    Expect(VfsLookup(trusted, "/etc/man/cat", 64) != nullptr, "/etc/man/cat resolves");
    Expect(VfsMountVisibleFromRoot(trusted, "/disk/0"), "trusted root sees /disk/0 mount");
    Expect(VfsMountVisibleFromRoot(trusted, "/duetfs"), "trusted root sees /duetfs mount");
    Expect(VfsMountVisibleFromRoot(trusted, "/disks/duetfs0"), "trusted root sees /disks/duetfs0 mount");

    // ----- Relative lookups (no leading slash) start from root -----
    Expect(VfsLookup(trusted, "etc/version", 64) == version, "relative path matches absolute");
    Expect(VfsLookup(trusted, "bin/hello", 64) != nullptr, "relative /bin/hello resolves");

    // ----- Trailing slash tolerated on both file and dir -----
    Expect(VfsLookup(trusted, "/etc/version/", 64) == version, "trailing slash on file");
    Expect(VfsLookup(trusted, "/etc/", 64) == etc, "trailing slash on directory");
    Expect(VfsLookup(trusted, "/etc//", 64) == etc, "trailing double slash on directory");

    // ----- Empty components / consecutive slashes -----
    Expect(VfsLookup(trusted, "//etc//version", 64) != nullptr, "double-slash mid-path tolerated");
    Expect(VfsLookup(trusted, "///etc///version///", 64) != nullptr, "triple-slash mid-path tolerated");

    // ----- "." mid-path stays put -----
    Expect(VfsLookup(trusted, "/etc/./version", 64) == version, "dot mid-path preserved");
    Expect(VfsLookup(trusted, "/./etc/./version", 64) == version, "dots throughout preserved");

    // ----- ".." rejected at every position (jail invariant) -----
    Expect(VfsLookup(trusted, "..", 64) == nullptr, "bare .. rejected");
    Expect(VfsLookup(trusted, "/..", 64) == nullptr, "/.. rejected");
    Expect(VfsLookup(trusted, "/etc/..", 64) == nullptr, "/etc/.. rejected");
    Expect(VfsLookup(trusted, "/etc/../bin/hello", 64) == nullptr, "/etc/../bin/hello rejected");
    Expect(VfsLookup(trusted, "/etc/man/..", 64) == nullptr, "deep .. rejected");

    // ----- Cannot walk through a file -----
    Expect(VfsLookup(trusted, "/etc/version/foo", 64) == nullptr, "walk through file rejected");
    Expect(VfsLookup(trusted, "/bin/hello/x", 64) == nullptr, "walk through /bin/hello rejected");

    // ----- Missing components fail -----
    Expect(VfsLookup(trusted, "/nope", 64) == nullptr, "missing top-level rejected");
    Expect(VfsLookup(trusted, "/etc/nope", 64) == nullptr, "missing leaf rejected");
    Expect(VfsLookup(trusted, "/nope/version", 64) == nullptr, "missing intermediate rejected");

    // ----- path_max truncation: a short cap stops the scan early -----
    // "/etc/version" = 12 bytes; cap at 4 chars sees "/etc" only and resolves to the dir.
    Expect(VfsLookup(trusted, "/etc/version", 4) == etc, "path_max truncates at /etc");
    // Cap at 1 sees only the leading slash → root.
    Expect(VfsLookup(trusted, "/etc/version", 1) == trusted, "path_max=1 stops at root");

    // ----- Sandbox root: jail containment -----
    const RamfsNode* welcome = VfsLookup(sandbox, "/welcome.txt", 64);
    Expect(welcome != nullptr, "/welcome.txt resolves in sandbox");
    Expect(!RamfsIsDir(welcome), "/welcome.txt is a file");
    Expect(VfsLookup(sandbox, "welcome.txt", 64) == welcome, "relative welcome.txt resolves");
    Expect(VfsLookup(sandbox, "/etc/version", 64) == nullptr, "JAIL: sandbox cannot see /etc/version");
    Expect(VfsLookup(sandbox, "/bin/hello", 64) == nullptr, "JAIL: sandbox cannot see /bin/hello");
    Expect(VfsLookup(sandbox, "/bin", 64) == nullptr, "JAIL: sandbox cannot see /bin");
    Expect(VfsLookup(sandbox, "/etc", 64) == nullptr, "JAIL: sandbox cannot see /etc");
    Expect(!VfsMountVisibleFromRoot(sandbox, "/disk/0"), "JAIL: sandbox cannot see /disk/0 mount");
    Expect(!VfsMountVisibleFromRoot(sandbox, "/duetfs"), "JAIL: sandbox cannot see /duetfs mount");
    Expect(VfsLookup(sandbox, "..", 64) == nullptr, "JAIL: sandbox .. rejected");
    Expect(VfsLookup(sandbox, "/welcome.txt/..", 64) == nullptr, "JAIL: sandbox file/.. rejected");

    // ----- Cross-mount resolver (Stage 6 second slice) -----
    //
    // VfsResolve falls back to ramfs when no non-ramfs mount is in
    // the registry; the Fat32-mount path is exercised by the
    // routing self-test that runs after FAT32 auto-mount lands.
    // Here we just verify the ramfs-fall-through and Invalid-miss
    // shapes so a regression in the resolver shows up at this
    // level rather than only at the routing layer above.
    {
        VfsNode r = VfsResolve(trusted, "/etc/version", 64);
        Expect(VfsNodeIsValid(r), "VfsResolve /etc/version valid");
        Expect(r.backend == VfsBackend::Ramfs, "VfsResolve /etc/version is ramfs");
        Expect(r.ramfs == version, "VfsResolve /etc/version matches VfsLookup");
        Expect(VfsNodeIsFile(r), "VfsResolve /etc/version is file");
        Expect(VfsNodeSize(r) == version->file_size, "VfsResolve /etc/version size matches");

        VfsNode d = VfsResolve(trusted, "/etc", 64);
        Expect(VfsNodeIsValid(d), "VfsResolve /etc valid");
        Expect(VfsNodeIsDir(d), "VfsResolve /etc is dir");

        VfsNode m = VfsResolve(trusted, "/nope", 64);
        Expect(!VfsNodeIsValid(m), "VfsResolve /nope misses");
        Expect(m.backend == VfsBackend::Invalid, "VfsResolve /nope backend=Invalid");

        // Sandbox jail still applies to ramfs fall-through.
        VfsNode s = VfsResolve(sandbox, "/etc/version", 64);
        Expect(!VfsNodeIsValid(s), "VfsResolve sandbox-jail still rejects /etc/version");
        VfsNode sd = VfsResolve(sandbox, "/disk/0/HELLO.TXT", 64);
        Expect(!VfsNodeIsValid(sd), "VfsResolve sandbox-jail rejects hidden disk mount");

        // ".." rejection survives the resolver wrapping.
        VfsNode dd = VfsResolve(trusted, "/etc/..", 64);
        Expect(!VfsNodeIsValid(dd), "VfsResolve /etc/.. rejected");

        // Default-constructed node behaves correctly.
        VfsNode z{};
        Expect(!VfsNodeIsValid(z), "default VfsNode invalid");
        Expect(!VfsNodeIsDir(z), "default VfsNode not dir");
        Expect(!VfsNodeIsFile(z), "default VfsNode not file");
        Expect(VfsNodeSize(z) == 0, "default VfsNode size=0");
    }

    arch::SerialWrite("[fs/vfs] self-test OK (lookup + jail + .. + path_max + VfsResolve)\n");
}

void VfsResolveCrossMountSelfTest()
{
    arch::SerialWrite("[fs/vfs] cross-mount self-test\n");

    if (fat32::Fat32VolumeCount() == 0)
    {
        arch::SerialWrite("[fs/vfs] cross-mount self-test SKIP (no fat32 volume)\n");
        return;
    }

    // Find any FAT32 mount actually present in the registry. The
    // auto-mount loop in main.cpp skips volume 0 silently (its
    // block_handle == 0 is rejected by `VfsMount` — that's a
    // legacy invariant the routing layer covers via a hardcoded
    // `/disk/<N>` fallback parser). The cross-mount resolver
    // tests against whatever IS in the registry so this stays
    // green regardless of which volume index ended up mountable.
    struct DiscoverState
    {
        char mount_point[64];
        u32 block_handle;
        bool found;
    };
    DiscoverState st{};
    st.found = false;

    auto pick_first_fat32 = [](const MountEntry& entry, MountId, void* cookie) -> bool
    {
        auto* s = static_cast<DiscoverState*>(cookie);
        if (entry.fs_type != FsType::Fat32)
        {
            return true; // keep walking
        }
        for (u32 i = 0; i < sizeof(s->mount_point); ++i)
            s->mount_point[i] = 0;
        for (u32 i = 0; i < sizeof(s->mount_point) - 1 && entry.mount_point[i] != 0; ++i)
            s->mount_point[i] = entry.mount_point[i];
        s->block_handle = entry.block_handle;
        s->found = true;
        return false; // stop
    };
    VfsMountEnumerate(pick_first_fat32, &st);

    if (!st.found)
    {
        arch::SerialWrite("[fs/vfs] cross-mount self-test SKIP (no fat32 mount in registry)\n");
        return;
    }

    arch::SerialWrite("[fs/vfs] cross-mount self-test using mount=\"");
    arch::SerialWrite(st.mount_point);
    arch::SerialWrite("\" block_handle=");
    arch::SerialWriteHex(st.block_handle);
    arch::SerialWrite("\n");

    const RamfsNode* root = RamfsTrustedRoot();

    // Resolve the discovered mount-point path itself. The FAT32
    // root is synthesised by `Fat32LookupPath` whenever the
    // volume mounts (attributes = 0x10), so a successful resolve
    // proves the dispatch + backend wiring without depending on
    // any specific seeded file.
    VfsNode rootdir = VfsResolve(root, st.mount_point, sizeof(st.mount_point));
    Expect(VfsNodeIsValid(rootdir), "cross-mount: mount-point resolves");
    Expect(rootdir.backend == VfsBackend::Fat32, "cross-mount: mount-point lands on fat32 backend");
    Expect(VfsNodeIsDir(rootdir), "cross-mount: mount-point is dir");
    Expect(rootdir.fat32_volume_idx == st.block_handle, "cross-mount: volume idx matches mount entry");

    // Negative case: a path under the same mount that obviously
    // doesn't exist must return Invalid (proves the lookup is
    // running through the FAT32 backend rather than papering over
    // misses with a stale ramfs node).
    char miss_path[80];
    for (u32 i = 0; i < sizeof(miss_path); ++i)
        miss_path[i] = 0;
    u32 mi = 0;
    for (; mi < sizeof(miss_path) - 1 && st.mount_point[mi] != 0; ++mi)
        miss_path[mi] = st.mount_point[mi];
    const char suffix[] = "/_NONE_TEST_NOT_THERE_.X";
    for (u32 j = 0; mi + 1 < sizeof(miss_path) && suffix[j] != 0; ++j, ++mi)
        miss_path[mi] = suffix[j];
    VfsNode miss = VfsResolve(root, miss_path, sizeof(miss_path));
    Expect(!VfsNodeIsValid(miss), "cross-mount: missing fat32 file returns Invalid");
    Expect(miss.backend == VfsBackend::Invalid, "cross-mount: miss has Invalid backend");

    arch::SerialWrite("[fs/vfs] cross-mount self-test OK\n");
}

} // namespace duetos::fs
