// tests/host/test_disk_path.cpp
//
// Hosted unit tests for the "/disk/<idx>/<rest>" path parser
// used by SYS_PROCESS_SPAWN / SYS_PROCESS_SPAWN_EX (see
// kernel/subsystems/win32/spawn_syscall.cpp::ParseDiskPath)
// and by the Fat32 file-route layer.
//
// The kernel-side parser is in an anonymous namespace inside
// spawn_syscall.cpp so it isn't directly linkable from the
// host. We re-state the same algorithm here — same parameter
// shape, same accept/reject decisions — and assert the
// behaviour against canonical inputs. If the kernel-side
// body changes shape, this test stays an algorithmic
// contract check.
//
// T10-04 partial: extends the host-test surface beyond the
// pure-utility set (Result / string / cvt / text_hash) into a
// path-parser primitive that real syscalls depend on. PE
// parser, VFS path resolution, registry lookup are still
// kernel-only; this is one bounded step toward the per-
// pillar coverage the row asks for.

#include "host_test_helper.h"

#include <cstdint>
#include <cstdio>
#include <cstring>

using u32 = uint32_t;

// Mirror of kernel/subsystems/win32/spawn_syscall.cpp's
// `ParseDiskPath`. Strip a "/disk/<idx>/" prefix; returns the
// volume index + a pointer past the prefix on hit. Returns
// false on miss.
static bool ParseDiskPath(const char* path, u32& out_idx, const char*& out_rest)
{
    if (path == nullptr)
        return false;
    if (path[0] != '/' || path[1] != 'd' || path[2] != 'i' || path[3] != 's' || path[4] != 'k' || path[5] != '/')
        return false;
    const char* p = path + 6;
    u32 idx = 0;
    bool any = false;
    while (*p >= '0' && *p <= '9')
    {
        idx = idx * 10 + static_cast<u32>(*p - '0');
        any = true;
        ++p;
    }
    if (!any)
        return false;
    if (*p != '/' && *p != '\0')
        return false;
    out_idx = idx;
    out_rest = p;
    return true;
}

int main()
{
    using namespace duetos_host_test;

    u32 idx = 0xFFFF'FFFFu;
    const char* rest = nullptr;

    // 1. Canonical hit: /disk/0/foo.exe → idx=0, rest="/foo.exe"
    EXPECT_TRUE(ParseDiskPath("/disk/0/foo.exe", idx, rest));
    EXPECT_TRUE(idx == 0);
    EXPECT_TRUE(rest != nullptr && std::strcmp(rest, "/foo.exe") == 0);

    // 2. Multi-digit volume: /disk/12/sub/x → idx=12, rest="/sub/x"
    idx = 0xFFFF'FFFFu;
    EXPECT_TRUE(ParseDiskPath("/disk/12/sub/x", idx, rest));
    EXPECT_TRUE(idx == 12);
    EXPECT_TRUE(rest != nullptr && std::strcmp(rest, "/sub/x") == 0);

    // 3. Bare prefix: /disk/3 (no trailing slash, no rest) → hit, idx=3, rest=""
    idx = 0xFFFF'FFFFu;
    EXPECT_TRUE(ParseDiskPath("/disk/3", idx, rest));
    EXPECT_TRUE(idx == 3);
    EXPECT_TRUE(rest != nullptr && rest[0] == '\0');

    // 4. Misses (every reject path).
    idx = 99;
    EXPECT_FALSE(ParseDiskPath(nullptr, idx, rest));        // null
    EXPECT_FALSE(ParseDiskPath("disk/0/foo", idx, rest));   // missing leading /
    EXPECT_FALSE(ParseDiskPath("/dis/0/foo", idx, rest));   // wrong prefix
    EXPECT_FALSE(ParseDiskPath("/disk//foo", idx, rest));   // no idx digits
    EXPECT_FALSE(ParseDiskPath("/disk/0a/foo", idx, rest)); // non-slash after idx
    EXPECT_FALSE(ParseDiskPath("/disk/", idx, rest));       // empty idx
    EXPECT_FALSE(ParseDiskPath("/disk", idx, rest));        // no trailing /

    // 5. Largest in-range volume index that fits a u32 — 4 billion-
    //    ish would overflow; we limit to a sensible 99999 here.
    idx = 0;
    EXPECT_TRUE(ParseDiskPath("/disk/99999/foo", idx, rest));
    EXPECT_TRUE(idx == 99999);
    EXPECT_TRUE(rest != nullptr && std::strcmp(rest, "/foo") == 0);

    return finish_main("test_disk_path");
}
