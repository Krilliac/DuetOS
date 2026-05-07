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

    // Probe every registered kernel block device. Anything that
    // already holds a v2 DuetFS superblock gets mounted; blank
    // devices are left alone (auto-mkfs of a real disk is too
    // destructive to do silently). Skip partition-view handles —
    // they show up as their own entries and we'd double-count.
    const u32 dev_count = drivers::storage::BlockDeviceCount();
    u32 mounted = 0;
    for (u32 h = 0; h < dev_count; ++h)
    {
        if (drivers::storage::BlockDeviceIsPartition(h))
        {
            continue;
        }
        if (drivers::storage::BlockDeviceSectorCount(h) < kMinDiskBlocks)
        {
            continue;
        }
        if (!ProbeBlockHandle(h))
        {
            continue;
        }
        char mp[24] = {};
        // Build "/disks/duetfs<N>" — N up to 999 is plenty.
        const char prefix[] = "/disks/duetfs";
        for (u32 i = 0; i < sizeof(prefix) - 1; ++i)
        {
            mp[i] = prefix[i];
        }
        u32 n = mounted;
        u32 digits[3] = {};
        u32 nd = 0;
        do
        {
            digits[nd++] = n % 10;
            n /= 10;
        } while (n != 0 && nd < 3);
        for (u32 i = 0; i < nd; ++i)
        {
            mp[sizeof(prefix) - 1 + i] = static_cast<char>('0' + digits[nd - 1 - i]);
        }
        mp[sizeof(prefix) - 1 + nd] = '\0';
        const auto pmid = duetos::fs::VfsMount(mp, duetos::fs::FsType::DuetFs, h);
        if (pmid != duetos::fs::kInvalidMountId)
        {
            ++mounted;
            KLOG_INFO_V("duetfs/boot", "mounted on-disk DuetFS at /disks/duetfsN; handle", h);
        }
    }
    if (mounted > 0)
    {
        KLOG_INFO_V("duetfs/boot", "on-disk DuetFS volumes mounted", mounted);
    }
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

    // 8. Multi-extent grow. Truncate up past one extent's worth of
    //    blocks — the grow path should append a new extent rather
    //    than realloc-and-copy. Verify the file still reads back
    //    correctly across the extent boundary.
    u32 big_id = 0;
    ExpectStatus(duetfs_create_path(&scratch, reinterpret_cast<const u8*>("/big.bin"), 9, kKindFile, &big_id),
                 kStatusOk, "create /big.bin failed");
    // Write a recognisable 12 KiB pattern that spans 3 blocks. The
    // initial extent is 1 block; the second 4 KiB triggers grow.
    u8 pattern[12 * 1024];
    for (u32 i = 0; i < sizeof(pattern); ++i)
    {
        pattern[i] = static_cast<u8>((i * 7 + 13) & 0xFF);
    }
    ExpectStatus(duetfs_write_at(&scratch, big_id, 0, pattern, sizeof(pattern), &wrote), kStatusOk,
                 "write /big.bin failed");
    Expect(wrote == sizeof(pattern), "big write short");
    u8 readback[12 * 1024] = {};
    ExpectStatus(duetfs_read_file(&scratch, big_id, 0, readback, sizeof(readback), &got), kStatusOk,
                 "read /big.bin failed");
    Expect(got == sizeof(pattern), "big read short");
    for (u32 i = 0; i < sizeof(pattern); ++i)
    {
        if (readback[i] != pattern[i])
        {
            duetos::core::PanicWithValue("duetfs/selftest", "big readback mismatch", i);
        }
    }

    // 9. CRC32 corruption detection. Flip a bit in the on-disk
    //    superblock; the next probe should reject it (kStatusCorrupt
    //    on Fs::open).
    g_scratch_image[8] ^= 0x01u; // anywhere outside magic; trips CRC
    Expect(duetfs_probe(&scratch) == 0, "probe accepted a CRC-corrupted SB");
    g_scratch_image[8] ^= 0x01u; // restore; subsequent ops resume

    // 10. fsck on a clean post-mkfs FS — should report zero leaks
    //     AND zero per-block CRC mismatches AND zero link-count drift.
    FsckReport rep{};
    ExpectStatus(duetfs_fsck(&scratch, /*repair=*/0u, &rep), kStatusOk, "fsck clean failed");
    Expect(rep.leaked_blocks == 0 && rep.missing_blocks == 0 && rep.bad_extents == 0,
           "fsck bitmap reported issues on clean FS");
    Expect(rep.block_crc_mismatch == 0, "fsck found per-block CRC mismatch on clean FS");
    Expect(rep.link_count_mismatch == 0, "fsck found link_count drift on clean FS");

    // 11. Symbolic link: create /linkme.txt pointing at /big.bin,
    //     read it back through readlink + lookup the symlink.
    u32 sym_id = 0;
    ExpectStatus(duetfs_create_symlink(&scratch, reinterpret_cast<const u8*>("/linkme.txt"), 12,
                                       reinterpret_cast<const u8*>("/big.bin"), 9, &sym_id),
                 kStatusOk, "create_symlink failed");
    u8 lbuf[16] = {};
    usize lcopied = 0;
    ExpectStatus(duetfs_readlink(&scratch, sym_id, lbuf, sizeof(lbuf), &lcopied), kStatusOk, "readlink failed");
    Expect(lcopied == 8 && BytesEqual(lbuf, "/big.bin", 8), "readlink content wrong");
    ExpectStatus(duetfs_lookup(&scratch, reinterpret_cast<const u8*>("/linkme.txt"), 12, &res), kStatusOk,
                 "lookup symlink failed");
    Expect(res.kind == kKindSymlink, "lookup symlink kind wrong");

    // 12. Hard link: create /hl.bin (same name as the source so v3's
    //     name-must-match rule holds — first need to create a fresh
    //     file under that name then link a second dirent to it).
    u32 hl_id = 0;
    ExpectStatus(duetfs_create_path(&scratch, reinterpret_cast<const u8*>("/hl.bin"), 8, kKindFile, &hl_id), kStatusOk,
                 "create /hl.bin failed");
    // hl.bin's parent is root. Add a hard link in /etc (rebuilding
    // /etc since we unlinked it earlier).
    u32 etc2_id = 0;
    ExpectStatus(duetfs_create_path(&scratch, reinterpret_cast<const u8*>("/etc"), 5, kKindDir, &etc2_id), kStatusOk,
                 "rebuild /etc failed");
    // v3's hard-link rule: the target's name must equal the new
    // path's last component. So link /hl.bin into /etc/hl.bin.
    ExpectStatus(duetfs_link(&scratch, reinterpret_cast<const u8*>("/hl.bin"), 8,
                             reinterpret_cast<const u8*>("/etc/hl.bin"), 12),
                 kStatusOk, "duetfs_link failed");
    // Lookup both paths — same node id, link_count == 2.
    ExpectStatus(duetfs_lookup(&scratch, reinterpret_cast<const u8*>("/hl.bin"), 8, &res), kStatusOk,
                 "lookup /hl.bin post-link failed");
    Expect(res.node_id == hl_id, "hardlink node_id mismatch");
    ExpectStatus(duetfs_lookup(&scratch, reinterpret_cast<const u8*>("/etc/hl.bin"), 12, &res), kStatusOk,
                 "lookup /etc/hl.bin post-link failed");
    Expect(res.node_id == hl_id, "hardlink dual-path node_id mismatch");

    // 13. Per-block CRC corruption detection. Flip a byte in a known
    //     data block (the root dir's child-id block at LBA = data_lba)
    //     and run fsck — should report exactly one block_crc_mismatch.
    g_scratch_image[kDataLba * kBlockSize] ^= 0x01u; // data_lba = 15 in v5
    rep = FsckReport{};
    ExpectStatus(duetfs_fsck(&scratch, /*repair=*/0u, &rep), kStatusOk, "fsck post-corrupt failed");
    Expect(rep.block_crc_mismatch >= 1, "fsck missed per-block CRC corruption");
    g_scratch_image[kDataLba * kBlockSize] ^= 0x01u; // restore (data_lba = 15 in v5)

    // 14. fsck repair: run with repair=1, then a second clean pass
    //     should report zero again.
    rep = FsckReport{};
    ExpectStatus(duetfs_fsck(&scratch, /*repair=*/1u, &rep), kStatusOk, "fsck repair failed");
    Expect(rep.repaired == 1, "fsck didn't claim repaired");
    rep = FsckReport{};
    ExpectStatus(duetfs_fsck(&scratch, /*repair=*/0u, &rep), kStatusOk, "post-repair fsck failed");
    Expect(rep.block_crc_mismatch == 0, "post-repair still has CRC mismatch");

    // 15. Journal happy-path: write a known block via duetfs_journal_apply,
    //     read it back through duetfs_block_read, then check that the
    //     descriptor state is back to 0 (apply finished).
    {
        u8 jpayload[kBlockSize] = {};
        for (u32 i = 0; i < kBlockSize; ++i)
        {
            jpayload[i] = static_cast<u8>((i * 31 + 5) & 0xFF);
        }
        // Pick an unused tail block — the boot image's last block is
        // always free post-mkfs (we only allocate the root extent +
        // hello.txt's headroom + big.bin's 3 blocks + linkme + hl + etc).
        const u32 tail_lba = kBootImageBlocks - 1;
        ExpectStatus(duetfs_journal_apply(&scratch, tail_lba, jpayload), kStatusOk, "journal_apply happy-path failed");
        u8 jread[kBlockSize] = {};
        ExpectStatus(duetfs_block_read(&scratch, tail_lba, jread), kStatusOk, "block_read post-journal_apply failed");
        for (u32 i = 0; i < kBlockSize; ++i)
        {
            if (jread[i] != jpayload[i])
            {
                duetos::core::PanicWithValue("duetfs/selftest", "journal_apply readback mismatch", i);
            }
        }
        // Descriptor cleared.
        Expect(duetfs_journal_state(&scratch) == 0, "journal state non-zero post-apply");
    }

    // 16. Journal torn-write recovery: inject a COMMITTED descriptor
    //     pointing at a target block but DON'T finish the apply. The
    //     descriptor state should be 1 (committed). A subsequent
    //     duetfs_probe / duetfs_lookup re-opens the FS — Fs::open
    //     replays the journal and the target block reflects the
    //     staged payload.
    {
        u8 torn_payload[kBlockSize] = {};
        for (u32 i = 0; i < kBlockSize; ++i)
        {
            torn_payload[i] = static_cast<u8>(0xA0u ^ (i & 0xFFu));
        }
        const u32 tail_lba = kBootImageBlocks - 2;
        // Read the tail block's pre-injection contents.
        u8 pre[kBlockSize] = {};
        ExpectStatus(duetfs_block_read(&scratch, tail_lba, pre), kStatusOk, "pre-injection block_read failed");

        // Inject — descriptor goes COMMITTED; tail_lba unchanged on disk.
        ExpectStatus(duetfs_journal_inject_for_test(&scratch, tail_lba, torn_payload), kStatusOk,
                     "journal inject failed");
        Expect(duetfs_journal_state(&scratch) == 1, "journal state not COMMITTED after inject");

        // Tail block STILL holds pre-injection contents — apply hasn't run yet.
        u8 mid[kBlockSize] = {};
        ExpectStatus(duetfs_block_read(&scratch, tail_lba, mid), kStatusOk, "mid block_read failed");
        bool unchanged_pre_replay = true;
        for (u32 i = 0; i < kBlockSize; ++i)
        {
            if (mid[i] != pre[i])
            {
                unchanged_pre_replay = false;
                break;
            }
        }
        Expect(unchanged_pre_replay, "tail block changed before replay");

        // Trigger Fs::open via duetfs_probe — replays the journal.
        Expect(duetfs_probe(&scratch) == 1, "probe failed pre-replay");
        Expect(duetfs_journal_state(&scratch) == 0, "journal state non-zero post-replay");

        // Tail block now reflects the injected payload.
        u8 post[kBlockSize] = {};
        ExpectStatus(duetfs_block_read(&scratch, tail_lba, post), kStatusOk, "post block_read failed");
        for (u32 i = 0; i < kBlockSize; ++i)
        {
            if (post[i] != torn_payload[i])
            {
                duetos::core::PanicWithValue("duetfs/selftest", "torn-write replay mismatch", i);
            }
        }
    }

    // 17. Crypto primitives: AES-256-XTS round-trip — encrypt then
    //     decrypt should restore the original bytes.
    {
        u8 key[kXtsKeyBytes] = {};
        for (u32 i = 0; i < kXtsKeyBytes; ++i)
        {
            key[i] = static_cast<u8>(0x40u + i);
        }
        u8 plain[kBlockSize] = {};
        for (u32 i = 0; i < kBlockSize; ++i)
        {
            plain[i] = static_cast<u8>((i * 11 + 17) & 0xFF);
        }
        u8 cipher[kBlockSize] = {};
        for (u32 i = 0; i < kBlockSize; ++i)
        {
            cipher[i] = plain[i];
        }
        ExpectStatus(duetfs_xts_encrypt_block(key, /*sector=*/42, cipher), kStatusOk, "xts encrypt failed");
        // Differs from plaintext.
        bool any_diff = false;
        for (u32 i = 0; i < kBlockSize; ++i)
        {
            if (cipher[i] != plain[i])
            {
                any_diff = true;
                break;
            }
        }
        Expect(any_diff, "xts encrypt produced identity");
        // Round-trip back.
        ExpectStatus(duetfs_xts_decrypt_block(key, /*sector=*/42, cipher), kStatusOk, "xts decrypt failed");
        for (u32 i = 0; i < kBlockSize; ++i)
        {
            if (cipher[i] != plain[i])
            {
                duetos::core::PanicWithValue("duetfs/selftest", "xts round-trip mismatch", i);
            }
        }
    }

    // 18. Argon2id KDF determinism: same password+salt+params => same key.
    //     Use deliberately-tiny params (8 KiB, 1 iter, 1 lane) — proven
    //     correctness without paying ~100 ms in boot self-test path.
    {
        const u8 pw1[] = "correct horse battery staple";
        const u8 salt[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                             0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
        u8 k1[kXtsKeyBytes] = {};
        u8 k2[kXtsKeyBytes] = {};
        ExpectStatus(duetfs_kdf_argon2id(pw1, sizeof(pw1) - 1, salt, sizeof(salt),
                                         /*m=*/8u, /*t=*/1u, /*p=*/1u, k1),
                     kStatusOk, "argon2id #1 failed");
        ExpectStatus(duetfs_kdf_argon2id(pw1, sizeof(pw1) - 1, salt, sizeof(salt),
                                         /*m=*/8u, /*t=*/1u, /*p=*/1u, k2),
                     kStatusOk, "argon2id #2 failed");
        for (u32 i = 0; i < kXtsKeyBytes; ++i)
        {
            if (k1[i] != k2[i])
            {
                duetos::core::PanicWithValue("duetfs/selftest", "argon2id determinism failed", i);
            }
        }
        // Different password → different key.
        const u8 pw2[] = "incorrect horse battery staple";
        u8 k3[kXtsKeyBytes] = {};
        ExpectStatus(duetfs_kdf_argon2id(pw2, sizeof(pw2) - 1, salt, sizeof(salt),
                                         /*m=*/8u, /*t=*/1u, /*p=*/1u, k3),
                     kStatusOk, "argon2id #3 failed");
        bool diff_pw = false;
        for (u32 i = 0; i < kXtsKeyBytes; ++i)
        {
            if (k3[i] != k1[i])
            {
                diff_pw = true;
                break;
            }
        }
        Expect(diff_pw, "argon2id different passwords produced same key");
    }

    // 19. LZ4 round-trip on a redundant payload — compressed size
    //     should be smaller than uncompressed; decompression should
    //     reproduce the original bytes verbatim. Then write the
    //     compressed bytes through duetfs_write_at, read them back
    //     through duetfs_read_file, decompress, and verify — proving
    //     LZ4 + DuetFS storage compose end-to-end.
    {
        constexpr usize kPayloadLen = 4096;
        u8 lz_plain[kPayloadLen] = {};
        // Highly redundant pattern: 16-byte phrase repeated. LZ4
        // compresses this near-trivially (>20× ratio).
        const char phrase[] = "duetfs/lz4 v7! ";
        for (usize i = 0; i < kPayloadLen; ++i)
        {
            lz_plain[i] = static_cast<u8>(phrase[i % (sizeof(phrase) - 1)]);
        }
        const usize bound = duetfs_lz4_compress_bound(kPayloadLen);
        Expect(bound > 0 && bound < kPayloadLen + 256, "lz4 bound out of range");
        u8 compressed[4352] = {}; // > kPayloadLen + 256
        Expect(bound <= sizeof(compressed), "lz4 bound exceeds local buffer");
        usize comp_len = 0;
        ExpectStatus(duetfs_lz4_compress(lz_plain, kPayloadLen, compressed, sizeof(compressed), &comp_len), kStatusOk,
                     "lz4_compress failed");
        Expect(comp_len > 0 && comp_len < kPayloadLen, "lz4_compress produced no shrink");

        u8 decompressed[kPayloadLen] = {};
        usize decomp_len = 0;
        ExpectStatus(duetfs_lz4_decompress(compressed, comp_len, decompressed, sizeof(decompressed), &decomp_len),
                     kStatusOk, "lz4_decompress failed");
        Expect(decomp_len == kPayloadLen, "lz4 decompressed size wrong");
        for (usize i = 0; i < kPayloadLen; ++i)
        {
            if (decompressed[i] != lz_plain[i])
            {
                duetos::core::PanicWithValue("duetfs/selftest", "lz4 round-trip mismatch", i);
            }
        }

        // FS round-trip: write the compressed bytes into a new file
        // through duetfs_write_at, read them back, decompress, verify.
        u32 lz_id = 0;
        ExpectStatus(duetfs_create_path(&scratch, reinterpret_cast<const u8*>("/lz4.bin"), 9, kKindFile, &lz_id),
                     kStatusOk, "create /lz4.bin failed");
        usize lz_wrote = 0;
        ExpectStatus(duetfs_write_at(&scratch, lz_id, 0, compressed, comp_len, &lz_wrote), kStatusOk,
                     "write /lz4.bin failed");
        Expect(lz_wrote == comp_len, "lz4 fs write short");
        u8 lz_readback[4352] = {};
        usize lz_got = 0;
        ExpectStatus(duetfs_read_file(&scratch, lz_id, 0, lz_readback, sizeof(lz_readback), &lz_got), kStatusOk,
                     "read /lz4.bin failed");
        Expect(lz_got == comp_len, "lz4 fs read short");
        u8 final_decomp[kPayloadLen] = {};
        usize final_len = 0;
        ExpectStatus(duetfs_lz4_decompress(lz_readback, lz_got, final_decomp, sizeof(final_decomp), &final_len),
                     kStatusOk, "lz4 final decompress failed");
        Expect(final_len == kPayloadLen, "lz4 final decompressed size wrong");
        for (usize i = 0; i < kPayloadLen; ++i)
        {
            if (final_decomp[i] != lz_plain[i])
            {
                duetos::core::PanicWithValue("duetfs/selftest", "lz4 fs round-trip mismatch", i);
            }
        }
    }

    // 20. Snapshot round-trip: create a marker file, take a
    //     snapshot, modify the FS (create another file + write to
    //     existing file), restore the snapshot, verify the modified
    //     state is gone and the snapshotted state is back.
    {
        // Pre-snapshot state: create /snap_pre.bin with known bytes.
        u32 pre_id = 0;
        ExpectStatus(duetfs_create_path(&scratch, reinterpret_cast<const u8*>("/snap_pre.bin"), 14, kKindFile, &pre_id),
                     kStatusOk, "create /snap_pre.bin failed");
        const char pre_payload[] = "pre-snapshot";
        usize sw = 0;
        ExpectStatus(duetfs_write_at(&scratch, pre_id, 0, pre_payload, sizeof(pre_payload) - 1, &sw), kStatusOk,
                     "pre-snapshot write failed");

        // Take the snapshot.
        Expect(duetfs_snapshot_present(&scratch) == 0, "snapshot already present pre-create");
        ExpectStatus(duetfs_snapshot_create(&scratch, /*ts_ns=*/123456789u), kStatusOk, "snapshot_create failed");
        Expect(duetfs_snapshot_present(&scratch) == 1, "snapshot not present post-create");

        // Modify post-snapshot: add /snap_post.bin and overwrite snap_pre.
        u32 post_id = 0;
        ExpectStatus(
            duetfs_create_path(&scratch, reinterpret_cast<const u8*>("/snap_post.bin"), 15, kKindFile, &post_id),
            kStatusOk, "create /snap_post.bin failed");
        const char overwrite_payload[] = "post-overwrite";
        ExpectStatus(duetfs_write_at(&scratch, pre_id, 0, overwrite_payload, sizeof(overwrite_payload) - 1, &sw),
                     kStatusOk, "post-snapshot write failed");

        // Verify the post-snapshot state is in effect.
        ExpectStatus(duetfs_lookup(&scratch, reinterpret_cast<const u8*>("/snap_post.bin"), 15, &res), kStatusOk,
                     "post-snapshot lookup failed");
        u8 snap_buf[32] = {};
        usize rg = 0;
        ExpectStatus(duetfs_read_file(&scratch, pre_id, 0, snap_buf, sizeof(snap_buf), &rg), kStatusOk,
                     "post-snapshot read failed");
        Expect(BytesEqual(snap_buf, "post-overwrite", sizeof(overwrite_payload) - 1), "post-snapshot content wrong");

        // Restore the snapshot.
        ExpectStatus(duetfs_snapshot_restore(&scratch), kStatusOk, "snapshot_restore failed");

        // Snapshot stays present after restore (slot keeps its copy).
        Expect(duetfs_snapshot_present(&scratch) == 1, "snapshot vanished after restore");

        // /snap_post.bin should be gone (it was created post-snapshot).
        Expect(duetfs_lookup(&scratch, reinterpret_cast<const u8*>("/snap_post.bin"), 15, &res) == kStatusNotFound,
               "post-snapshot file survived restore");

        // /snap_pre.bin's content should be "pre-snapshot" again.
        for (u32 i = 0; i < sizeof(snap_buf); ++i)
            snap_buf[i] = 0;
        ExpectStatus(duetfs_read_file(&scratch, pre_id, 0, snap_buf, sizeof(snap_buf), &rg), kStatusOk,
                     "post-restore read failed");
        Expect(BytesEqual(snap_buf, "pre-snapshot", sizeof(pre_payload) - 1), "post-restore content wrong");
    }

    // 21. xattr / ACL round-trip on /hello.txt.
    //     a. Set system.posix_acl_access (mock 8-byte ACL payload).
    //     b. Set user.note (variable-length).
    //     c. Get + verify each.
    //     d. List names and verify both appear.
    //     e. Remove user.note, verify list shrinks.
    //     f. Probe a missing xattr (kStatusNotFound).
    {
        const char* xpath = "/hello.txt";
        const u8 acl_value[8] = {0x02, 0x00, 0x00, 0x00, 0x07, 0x00, 0xFF, 0xFF};
        const char* acl_name = "system.posix_acl_access";
        const usize acl_name_len = 23;
        const char* note_name = "user.note";
        const usize note_name_len = 9;
        const char note_value[] = "the quick brown fox";
        const usize note_value_len = sizeof(note_value) - 1;

        ExpectStatus(duetfs_xattr_set(&scratch, reinterpret_cast<const u8*>(xpath), 11,
                                      reinterpret_cast<const u8*>(acl_name), acl_name_len, acl_value,
                                      sizeof(acl_value)),
                     kStatusOk, "xattr_set acl failed");
        ExpectStatus(duetfs_xattr_set(&scratch, reinterpret_cast<const u8*>(xpath), 11,
                                      reinterpret_cast<const u8*>(note_name), note_name_len,
                                      reinterpret_cast<const u8*>(note_value), note_value_len),
                     kStatusOk, "xattr_set note failed");

        // Get acl.
        u8 xbuf[64] = {};
        usize xlen = 0;
        ExpectStatus(duetfs_xattr_get(&scratch, reinterpret_cast<const u8*>(xpath), 11,
                                      reinterpret_cast<const u8*>(acl_name), acl_name_len, xbuf, sizeof(xbuf), &xlen),
                     kStatusOk, "xattr_get acl failed");
        Expect(xlen == sizeof(acl_value), "xattr acl wrong size");
        for (usize i = 0; i < sizeof(acl_value); ++i)
        {
            Expect(xbuf[i] == acl_value[i], "xattr acl content mismatch");
        }

        // Get note.
        for (usize i = 0; i < sizeof(xbuf); ++i)
            xbuf[i] = 0;
        ExpectStatus(duetfs_xattr_get(&scratch, reinterpret_cast<const u8*>(xpath), 11,
                                      reinterpret_cast<const u8*>(note_name), note_name_len, xbuf, sizeof(xbuf), &xlen),
                     kStatusOk, "xattr_get note failed");
        Expect(xlen == note_value_len, "xattr note wrong size");
        Expect(BytesEqual(xbuf, note_value, note_value_len), "xattr note content mismatch");

        // List — both names, NUL-separated.
        u8 lbuf2[128] = {};
        usize llen = 0;
        ExpectStatus(duetfs_xattr_list(&scratch, reinterpret_cast<const u8*>(xpath), 11, lbuf2, sizeof(lbuf2), &llen),
                     kStatusOk, "xattr_list failed");
        // Each name + 1 byte NUL.
        Expect(llen == acl_name_len + 1 + note_name_len + 1, "xattr_list size wrong");

        // Remove note.
        ExpectStatus(duetfs_xattr_remove(&scratch, reinterpret_cast<const u8*>(xpath), 11,
                                         reinterpret_cast<const u8*>(note_name), note_name_len),
                     kStatusOk, "xattr_remove note failed");
        // Re-list — only acl now.
        llen = 0;
        ExpectStatus(duetfs_xattr_list(&scratch, reinterpret_cast<const u8*>(xpath), 11, lbuf2, sizeof(lbuf2), &llen),
                     kStatusOk, "xattr_list post-remove failed");
        Expect(llen == acl_name_len + 1, "xattr_list post-remove size wrong");

        // Probe missing xattr.
        Expect(duetfs_xattr_get(&scratch, reinterpret_cast<const u8*>(xpath), 11,
                                reinterpret_cast<const u8*>(note_name), note_name_len, xbuf, sizeof(xbuf),
                                &xlen) == kStatusNotFound,
               "xattr_get of removed name returned ok");
    }

    KLOG_INFO("duetfs/selftest", "OK — v8 xattrs + snapshots + LZ4 + AES-XTS + Argon2 + journal + CRC passed");
}

} // namespace duetos::fs::duetfs
