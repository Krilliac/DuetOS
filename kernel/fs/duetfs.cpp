// DuetFS — boot-time self-test of the Rust crate FFI.
//
// Exercises the four-call contract (probe / lookup / read_file /
// negative lookup) against the synthesized image from
// duetfs_image.cpp. Every assertion routes through Panic() with a
// `duetfs/selftest` subsystem tag — a clean boot is silent at
// default log levels; a regression leaves a crash dump grep-able
// in CI.

#include "core/panic.h"
#include "fs/duetfs.h"
#include "fs/duetfs/include/duetfs.h"
#include "log/klog.h"
#include "util/types.h"

namespace duetos::fs::duetfs
{

namespace
{

alignas(8) u8 g_self_test_image[kSelfTestImageBytes];

bool BytesEqual(const u8* a, const char* literal, usize n)
{
    for (usize i = 0; i < n; ++i)
    {
        if (a[i] != static_cast<u8>(literal[i]))
        {
            return false;
        }
    }
    return true;
}

usize CStrLen(const char* s)
{
    usize n = 0;
    while (s[n] != '\0')
    {
        ++n;
    }
    return n;
}

void Expect(bool cond, const char* what)
{
    if (!cond)
    {
        duetos::core::Panic("duetfs/selftest", what);
    }
}

} // namespace

void DuetFsSelfTest()
{
    BuildSelfTestImage(g_self_test_image);

    // 1. Probe — must accept the synthesized image.
    Expect(duetfs_probe(g_self_test_image, kSelfTestImageBytes) == 1, "probe rejected the synthesized image");

    // Also probe a buffer with the wrong magic — must reject.
    g_self_test_image[0] ^= 0xFFu;
    Expect(duetfs_probe(g_self_test_image, kSelfTestImageBytes) == 0, "probe accepted a corrupted superblock");
    g_self_test_image[0] ^= 0xFFu; // restore

    // 2. Lookup "/hello.txt" — must hit, kind=file, size=14.
    LookupResult res{};
    const char path_hello[] = "/hello.txt";
    Expect(duetfs_lookup(g_self_test_image, kSelfTestImageBytes, reinterpret_cast<const u8*>(path_hello),
                         CStrLen(path_hello) + 1, &res) == 1,
           "lookup /hello.txt failed");
    Expect(res.kind == kKindFile, "lookup result wrong kind");
    Expect(res.size_bytes == 14, "lookup result wrong size");

    // 3. Read the file — must equal "Hello, DuetFS!".
    u8 buf[32] = {};
    const usize got =
        duetfs_read_file(g_self_test_image, kSelfTestImageBytes, res.node_id, /*offset=*/0, buf, sizeof(buf));
    Expect(got == 14, "read_file returned wrong byte count");
    Expect(BytesEqual(buf, "Hello, DuetFS!", 14), "read_file returned wrong contents");

    // 4. Lookup of a non-existent path — must miss.
    const char path_missing[] = "/no_such_file";
    Expect(duetfs_lookup(g_self_test_image, kSelfTestImageBytes, reinterpret_cast<const u8*>(path_missing),
                         CStrLen(path_missing) + 1, &res) == 0,
           "lookup of /no_such_file unexpectedly succeeded");

    // 5. Lookup with ".." — must be rejected (no parent climb).
    const char path_dotdot[] = "/..";
    Expect(duetfs_lookup(g_self_test_image, kSelfTestImageBytes, reinterpret_cast<const u8*>(path_dotdot),
                         CStrLen(path_dotdot) + 1, &res) == 0,
           "lookup of /.. unexpectedly succeeded");

    KLOG_INFO("duetfs/selftest", "OK — Rust FFI round-trip + 5 cases passed");
}

} // namespace duetos::fs::duetfs
