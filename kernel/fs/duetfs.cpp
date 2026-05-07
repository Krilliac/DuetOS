// DuetFS — boot bring-up + self-test.
//
// DuetFsBoot creates the kernel's primary DuetFS volume on a 256 KiB
// RAM block device, formats it (mkfs), seeds /etc/version with the
// kernel build banner, and registers it in the VFS mount table at
// "/duetfs". Subsequent reads + writes go through the same Rust
// crate FFI any other caller would use — there's no privileged path.
//
// DuetFsSelfTest exercises the full v1 surface (mkfs, create file,
// write, read back, mkdir, nested file, lookup, unlink, truncate)
// against a SCRATCH RAM disk so the boot mount stays untouched.

#include "core/panic.h"
#include "drivers/storage/block.h"
#include "fs/duetfs.h"
#include "fs/duetfs/include/duetfs.h"
#include "fs/mount.h"
#include "log/klog.h"
#include "util/types.h"

namespace duetos::fs::duetfs
{

namespace
{

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

void ExpectStatus(u32 got, u32 want, const char* what)
{
    if (got != want)
    {
        duetos::core::PanicWithValue("duetfs/selftest", what, static_cast<u64>(got));
    }
}

// Boot RAM disk handle (set by DuetFsBoot, used by the VFS routing
// vtable in mount.cpp). u32 max == "unmounted".
constinit u32 g_boot_handle = 0xFFFFFFFFu;

// Boot RAM disk + scratch RAM disk live in .bss. mkfs zeroes them
// in place via the block-device read/write callbacks — no heap
// allocation in this slice.
alignas(8) u8 g_boot_image[kBootImageBytes];
alignas(8) u8 g_scratch_image[kBootImageBytes];

void SeedEtc(const Device& dev)
{
    // /etc dir
    u32 etc_id = 0;
    u32 st = duetfs_create_path(&dev, reinterpret_cast<const u8*>("/etc"), 5, kKindDir, &etc_id);
    ExpectStatus(st, kStatusOk, "boot mkdir /etc failed");

    // /etc/version file
    u32 ver_id = 0;
    st = duetfs_create_path(&dev, reinterpret_cast<const u8*>("/etc/version"), 13, kKindFile, &ver_id);
    ExpectStatus(st, kStatusOk, "boot create /etc/version failed");

    const char banner[] = "DuetFS v1 (kernel boot)\n";
    usize wrote = 0;
    st = duetfs_write_at(&dev, ver_id, 0, banner, sizeof(banner) - 1, &wrote);
    ExpectStatus(st, kStatusOk, "boot write /etc/version failed");
    Expect(wrote == sizeof(banner) - 1, "boot write /etc/version short");
}

} // namespace

u32 BootHandle()
{
    return g_boot_handle;
}

Device DeviceForMountHandle(u32 block_handle)
{
    if (block_handle == kBootHandleSentinel)
    {
        return MakeMemoryDevice(g_boot_image, kBootImageBytes, false);
    }
    return MakeBlockHandleDevice(block_handle);
}

u32 DuetFsBoot()
{
    // 1. Register the boot RAM block device. 4 KiB sector, 64 sectors
    //    = 256 KiB. Kernel's RamBlockDeviceCreate copies the storage
    //    into its own buffer, so we hand it ours and don't keep a
    //    second pointer.
    //
    // Actually: RamBlockDeviceCreate allocates its OWN buffer per
    //    the block.cpp implementation. So we need to use a memory
    //    Device pointing at g_boot_image directly, NOT a kernel ram
    //    block-device. The block-device adapter is exercised by the
    //    self-test on a second RAM disk allocated through the kernel
    //    block layer.
    Device dev = MakeMemoryDevice(g_boot_image, kBootImageBytes, false);

    // 2. Format.
    const u32 mkfs_st = duetfs_mkfs(&dev);
    if (mkfs_st != kStatusOk)
    {
        duetos::core::PanicWithValue("duetfs/boot", "mkfs failed", mkfs_st);
    }

    // 3. Seed /etc/version. Useful both as a smoke test and as a
    //    well-known kernel-readable file callers can grep for to
    //    confirm DuetFS is alive.
    SeedEtc(dev);

    // 4. Register in the VFS mount table. The block_handle field is
    //    overloaded: for memory-backed mounts, we use a sentinel
    //    handle (UINT32_MAX) and the routing layer (mount.cpp's
    //    DuetFsLookup) maps it back to MakeMemoryDevice via the same
    //    g_boot_image pointer. A future slice will land a registry
    //    of duetfs mounts so multiple volumes can coexist.
    g_boot_handle = 0xFFFFFFFFu;
    const auto mid = duetos::fs::VfsMount("/duetfs", duetos::fs::FsType::DuetFs, g_boot_handle);
    if (mid == duetos::fs::kInvalidMountId)
    {
        duetos::core::Panic("duetfs/boot", "VfsMount /duetfs failed");
    }
    KLOG_INFO("duetfs/boot", "OK — /duetfs mounted (256 KiB RAM, /etc/version seeded)");
    return g_boot_handle;
}

void DuetFsSelfTest()
{
    Device scratch = MakeMemoryDevice(g_scratch_image, kBootImageBytes, false);

    // 1. mkfs round-trip.
    Expect(duetfs_probe(&scratch) == 0, "fresh buffer probed as valid before mkfs");
    ExpectStatus(duetfs_mkfs(&scratch), kStatusOk, "mkfs failed");
    Expect(duetfs_probe(&scratch) == 1, "post-mkfs probe rejected");

    // 2. Resolve the root dir.
    LookupResult res{};
    ExpectStatus(duetfs_lookup(&scratch, reinterpret_cast<const u8*>("/"), 2, &res), kStatusOk, "lookup / failed");
    Expect(res.kind == kKindDir && res.node_id == kRootNodeId, "root not a dir");

    // 3. Create + write + read back a file.
    u32 hello_id = 0;
    ExpectStatus(duetfs_create_path(&scratch, reinterpret_cast<const u8*>("/hello.txt"), 11, kKindFile, &hello_id),
                 kStatusOk, "create /hello.txt failed");
    const char payload[] = "Hello, DuetFS v1!";
    usize wrote = 0;
    ExpectStatus(duetfs_write_at(&scratch, hello_id, 0, payload, sizeof(payload) - 1, &wrote), kStatusOk,
                 "write /hello.txt failed");
    Expect(wrote == sizeof(payload) - 1, "write short");

    u8 read_buf[64] = {};
    usize got = 0;
    ExpectStatus(duetfs_read_file(&scratch, hello_id, 0, read_buf, sizeof(read_buf), &got), kStatusOk,
                 "read /hello.txt failed");
    Expect(got == sizeof(payload) - 1, "read short");
    Expect(BytesEqual(read_buf, payload, got), "read payload mismatch");

    // 4. Nested directory + file.
    u32 etc_id = 0;
    ExpectStatus(duetfs_create_path(&scratch, reinterpret_cast<const u8*>("/etc"), 5, kKindDir, &etc_id), kStatusOk,
                 "mkdir /etc failed");
    u32 ver_id = 0;
    ExpectStatus(duetfs_create_path(&scratch, reinterpret_cast<const u8*>("/etc/version"), 13, kKindFile, &ver_id),
                 kStatusOk, "create /etc/version failed");
    const char ver[] = "v1.0\n";
    ExpectStatus(duetfs_write_at(&scratch, ver_id, 0, ver, sizeof(ver) - 1, &wrote), kStatusOk,
                 "write /etc/version failed");
    Expect(wrote == sizeof(ver) - 1, "etc/version write short");
    ExpectStatus(duetfs_lookup(&scratch, reinterpret_cast<const u8*>("/etc/version"), 13, &res), kStatusOk,
                 "lookup /etc/version failed");
    Expect(res.kind == kKindFile && res.size_bytes == sizeof(ver) - 1, "etc/version mis-stat");

    // 5. Unlink ordering — non-empty dir refused, file allowed,
    //    then empty dir allowed.
    Expect(duetfs_unlink_path(&scratch, reinterpret_cast<const u8*>("/etc"), 5) == kStatusDirNotEmpty,
           "unlink /etc on non-empty dir succeeded");
    ExpectStatus(duetfs_unlink_path(&scratch, reinterpret_cast<const u8*>("/etc/version"), 13), kStatusOk,
                 "unlink /etc/version failed");
    ExpectStatus(duetfs_unlink_path(&scratch, reinterpret_cast<const u8*>("/etc"), 5), kStatusOk,
                 "unlink /etc (empty) failed");
    ExpectStatus(duetfs_lookup(&scratch, reinterpret_cast<const u8*>("/etc/version"), 13, &res), kStatusNotFound,
                 "post-unlink lookup unexpectedly hit");

    // 6. Truncate — grow + shrink + read.
    ExpectStatus(duetfs_truncate(&scratch, hello_id, 8192), kStatusOk, "grow truncate failed");
    ExpectStatus(duetfs_lookup(&scratch, reinterpret_cast<const u8*>("/hello.txt"), 11, &res), kStatusOk,
                 "post-truncate lookup failed");
    Expect(res.size_bytes == 8192, "post-truncate size wrong");
    ExpectStatus(duetfs_truncate(&scratch, hello_id, 4), kStatusOk, "shrink truncate failed");

    // 7. ".." rejection.
    Expect(duetfs_lookup(&scratch, reinterpret_cast<const u8*>("/.."), 4, &res) == kStatusInvalid,
           "/.. unexpectedly accepted");

    KLOG_INFO("duetfs/selftest", "OK — v1 mkfs/create/write/read/mkdir/unlink/truncate passed");
}

} // namespace duetos::fs::duetfs
