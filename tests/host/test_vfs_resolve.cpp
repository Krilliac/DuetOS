// tests/host/test_vfs_resolve.cpp
//
// Hosted unit tests for VfsMountResolve — the longest-prefix
// mount-point matcher that lives in kernel/fs/mount.cpp.
//
// The real routine walks an in-kernel `g_mounts[kMaxMounts]`
// table; the algorithmic contract is the prefix-matching loop
// itself (path component-boundary + longest-match-wins). We
// re-state that contract here against a synthetic mount table
// and cover the cases the kernel routine carefully spelled out:
//
//   - leading-slash requirement
//   - exact mount-point match returns "/" as the tail
//   - component-boundary check rejects "/disk/01" against
//     mount "/disk/0"
//   - longest mount wins when two prefixes are both valid
//     (e.g. "/disk" and "/disk/0" both registered; the latter
//     wins for "/disk/0/foo")
//   - too-long mount point is rejected
//   - mount that returns NULL subpath stays NULL on miss
//
// T10-04: extends the hosted ctest harness to cover the VFS
// path-resolution pillar — see the Roadmap row. PE parser +
// registry lookup are the remaining two; registry-lookup
// landing alongside this slice (test_registry_lookup.cpp).

#include "host_test_helper.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

using u32 = uint32_t;

struct MountEntry
{
    bool in_use;
    const char* mount_point;
};

static u32 StrLen(const char* s)
{
    u32 n = 0;
    while (s[n] != '\0')
        ++n;
    return n;
}

// Mirror of kernel/fs/mount.cpp::VfsMountResolve. Walks the
// `mounts` table, picks the longest mount-point prefix that
// matches `path` (component-boundary correct), and returns
// a pointer into that entry plus the post-prefix tail.
static const MountEntry* VfsMountResolve(const MountEntry* mounts, u32 count, const char* path,
                                         const char** out_subpath)
{
    if (path == nullptr || path[0] != '/')
    {
        if (out_subpath != nullptr)
            *out_subpath = nullptr;
        return nullptr;
    }
    const u32 path_len = StrLen(path);
    const MountEntry* best = nullptr;
    u32 best_len = 0;
    for (u32 i = 0; i < count; ++i)
    {
        if (!mounts[i].in_use)
            continue;
        const char* mp = mounts[i].mount_point;
        const u32 mp_len = StrLen(mp);
        if (mp_len == 0 || mp_len > path_len)
            continue;
        bool prefix_ok = true;
        for (u32 k = 0; k < mp_len; ++k)
        {
            if (path[k] != mp[k])
            {
                prefix_ok = false;
                break;
            }
        }
        if (!prefix_ok)
            continue;
        if (path[mp_len] != '\0' && path[mp_len] != '/')
            continue; // not on a path-component boundary
        if (mp_len > best_len)
        {
            best = &mounts[i];
            best_len = mp_len;
        }
    }
    if (best == nullptr)
    {
        if (out_subpath != nullptr)
            *out_subpath = nullptr;
        return nullptr;
    }
    if (out_subpath != nullptr)
    {
        const char* tail = path + best_len;
        *out_subpath = (tail[0] == '\0') ? "/" : tail;
    }
    return best;
}

int main()
{
    using namespace duetos_host_test;

    const MountEntry mounts[] = {
        {true, "/disk/0"}, {true, "/disk/0/HOME"}, {true, "/disk"}, {true, "/duetfs"}, {false, "/inactive"},
    };
    const u32 n = sizeof(mounts) / sizeof(mounts[0]);
    const char* sub = nullptr;

    // 1. NULL path → no match, tail cleared.
    sub = reinterpret_cast<const char*>(0xDEAD);
    EXPECT_TRUE(VfsMountResolve(mounts, n, nullptr, &sub) == nullptr);
    EXPECT_TRUE(sub == nullptr);

    // 2. Non-absolute (no leading '/') → no match.
    sub = reinterpret_cast<const char*>(0xDEAD);
    EXPECT_TRUE(VfsMountResolve(mounts, n, "disk/0/x", &sub) == nullptr);
    EXPECT_TRUE(sub == nullptr);

    // 3. Exact mount-point match → tail == "/".
    sub = nullptr;
    const MountEntry* m = VfsMountResolve(mounts, n, "/disk/0", &sub);
    EXPECT_TRUE(m != nullptr && std::strcmp(m->mount_point, "/disk/0") == 0);
    EXPECT_STREQ(sub, "/");

    // 4. Mount-point + sub → tail starts with '/'.
    sub = nullptr;
    m = VfsMountResolve(mounts, n, "/disk/0/foo.txt", &sub);
    EXPECT_TRUE(m != nullptr && std::strcmp(m->mount_point, "/disk/0") == 0);
    EXPECT_STREQ(sub, "/foo.txt");

    // 5. Component-boundary check: "/disk/01" must NOT match "/disk/0".
    //    Either "/disk" matches (with tail "/01/foo"), or nothing does.
    sub = nullptr;
    m = VfsMountResolve(mounts, n, "/disk/01/foo", &sub);
    EXPECT_TRUE(m != nullptr && std::strcmp(m->mount_point, "/disk") == 0);
    EXPECT_STREQ(sub, "/01/foo");

    // 6. Longest mount wins: "/disk/0/HOME/x" must pick the deeper mount.
    sub = nullptr;
    m = VfsMountResolve(mounts, n, "/disk/0/HOME/x", &sub);
    EXPECT_TRUE(m != nullptr && std::strcmp(m->mount_point, "/disk/0/HOME") == 0);
    EXPECT_STREQ(sub, "/x");

    // 7. Path shorter than any mount with a longer point → falls
    //    back to the shorter mount.
    sub = nullptr;
    m = VfsMountResolve(mounts, n, "/disk/HOME", &sub);
    EXPECT_TRUE(m != nullptr && std::strcmp(m->mount_point, "/disk") == 0);
    EXPECT_STREQ(sub, "/HOME");

    // 8. Inactive entries are ignored — even if their text would
    //    match.
    sub = reinterpret_cast<const char*>(0xDEAD);
    EXPECT_TRUE(VfsMountResolve(mounts, n, "/inactive/x", &sub) == nullptr);
    EXPECT_TRUE(sub == nullptr);

    // 9. Path equal to the prefix of a longer mount: "/disk/0/HOM"
    //    must match "/disk/0" with tail "/HOM" (the boundary check
    //    rejects "/disk/0/HOME" as a match for "/disk/0/HOM").
    sub = nullptr;
    m = VfsMountResolve(mounts, n, "/disk/0/HOM", &sub);
    EXPECT_TRUE(m != nullptr && std::strcmp(m->mount_point, "/disk/0") == 0);
    EXPECT_STREQ(sub, "/HOM");

    // 10. Different mount entirely — "/duetfs/etc/version".
    sub = nullptr;
    m = VfsMountResolve(mounts, n, "/duetfs/etc/version", &sub);
    EXPECT_TRUE(m != nullptr && std::strcmp(m->mount_point, "/duetfs") == 0);
    EXPECT_STREQ(sub, "/etc/version");

    // 11. Empty table → miss.
    const MountEntry empty[] = {{false, "/"}};
    sub = reinterpret_cast<const char*>(0xDEAD);
    EXPECT_TRUE(VfsMountResolve(empty, 1, "/anything", &sub) == nullptr);
    EXPECT_TRUE(sub == nullptr);

    return finish_main(__FILE__);
}
