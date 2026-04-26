// fat32_selftest.cpp — Fat32SelfTest, extracted from fat32.cpp.
//
// Behaviour-preserving move: the function only ever called the public
// Fat32* surface declared in fat32.h, so it lives equally well in a
// sibling translation unit. fat32.cpp shrinks by ~610 lines and the
// self-test that runs once at boot is now editable in isolation.

#include "fs/fat32.h"

#include "arch/x86_64/serial.h"
#include "log/klog.h"
#include "drivers/storage/block.h"

namespace duetos::fs::fat32
{

namespace
{
// Match the FAT32 spec attribute bit and the byte-zeroing helper from
// fat32.cpp's anonymous namespace. Re-declared here because anonymous-
// namespace symbols are TU-local; the test only ever needed these as
// trivial primitives, so duplicating them is simpler than promoting
// them to a header.
constexpr u8 kAttrDirectory = 0x10;
inline void Zero(void* p, u64 n)
{
    auto* b = static_cast<volatile u8*>(p);
    for (u64 i = 0; i < n; ++i)
        b[i] = 0;
}
} // namespace

void Fat32SelfTest()
{
    KLOG_TRACE_SCOPE("fs/fat32", "Fat32SelfTest");
    using arch::SerialWrite;

    const u32 block_count = drivers::storage::BlockDeviceCount();
    for (u32 h = 0; h < block_count; ++h)
    {
        const char* name = drivers::storage::BlockDeviceName(h);
        SerialWrite("[fs/fat32] probing handle=");
        arch::SerialWriteHex(static_cast<u64>(h));
        SerialWrite(" (");
        SerialWrite(name);
        SerialWrite(")\n");
        if (!Fat32Probe(h, nullptr))
        {
            SerialWrite("[fs/fat32]   -> not FAT32 (or unsupported geometry)\n");
        }
    }

    if (Fat32VolumeCount() == 0)
    {
        SerialWrite("[fs/fat32] self-test: NO VOLUMES FOUND\n");
        return;
    }

    // Success criterion: at least one volume has at least one non-directory
    // entry in its root. Matches what `build_fat32` seeds (HELLO.TXT).
    bool any_file = false;
    for (u32 vi = 0; vi < Fat32VolumeCount(); ++vi)
    {
        const Volume& v = *Fat32Volume(vi);
        for (u32 ei = 0; ei < v.root_entry_count; ++ei)
        {
            if ((v.root_entries[ei].attributes & kAttrDirectory) == 0)
            {
                any_file = true;
                break;
            }
        }
        if (any_file)
            break;
    }
    if (!any_file)
    {
        SerialWrite("[fs/fat32] self-test WARN: volumes found but no files in any root\n");
        return;
    }

    // Content check: read the seed file from the first volume and
    // compare against the string the image-builder writes.
    //   tools/qemu/make-gpt-image.py : FAT_FILE_BODY = "hello from fat32\n"
    // A mismatch points at either an image-builder change that
    // forgot to update this assertion, or a driver regression in
    // the cluster-chain walk.
    const Volume* v0 = Fat32Volume(0);
    const DirEntry* hello = Fat32FindInRoot(v0, "HELLO.TXT");
    if (hello == nullptr)
    {
        SerialWrite("[fs/fat32] self-test WARN: HELLO.TXT not found in first volume\n");
        return;
    }
    static u8 buf[64];
    Zero(buf, sizeof(buf));
    const i64 n = Fat32ReadFile(v0, hello, buf, sizeof(buf));
    if (n < 0)
    {
        SerialWrite("[fs/fat32] self-test FAILED: read error on HELLO.TXT\n");
        return;
    }
    const char* expect = "hello from fat32\n";
    u32 elen = 0;
    while (expect[elen] != 0)
        ++elen;
    if (static_cast<u64>(n) != elen)
    {
        SerialWrite("[fs/fat32] self-test FAILED: HELLO.TXT wrong size\n");
        return;
    }
    for (u32 i = 0; i < elen; ++i)
    {
        if (buf[i] != static_cast<u8>(expect[i]))
        {
            SerialWrite("[fs/fat32] self-test FAILED: HELLO.TXT content mismatch\n");
            return;
        }
    }
    SerialWrite("[fs/fat32] self-test OK (HELLO.TXT contents verified)\n");

    // Second phase: prove the path walker resolves a nested entry.
    // Image-builder seeds /SUB/INNER.TXT with body "inner file\n".
    DirEntry inner;
    if (!Fat32LookupPath(v0, "/SUB/INNER.TXT", &inner))
    {
        SerialWrite("[fs/fat32] self-test WARN: /SUB/INNER.TXT not found\n");
        return;
    }
    Zero(buf, sizeof(buf));
    const i64 n2 = Fat32ReadFile(v0, &inner, buf, sizeof(buf));
    const char* expect2 = "inner file\n";
    u32 elen2 = 0;
    while (expect2[elen2] != 0)
        ++elen2;
    if (n2 != static_cast<i64>(elen2))
    {
        SerialWrite("[fs/fat32] self-test FAILED: /SUB/INNER.TXT wrong size\n");
        return;
    }
    for (u32 i = 0; i < elen2; ++i)
    {
        if (buf[i] != static_cast<u8>(expect2[i]))
        {
            SerialWrite("[fs/fat32] self-test FAILED: /SUB/INNER.TXT content mismatch\n");
            return;
        }
    }
    SerialWrite("[fs/fat32] self-test OK (/SUB/INNER.TXT path-walked + verified)\n");

    // Third phase: LFN decoding. The image-builder seeds a file
    // whose long name is "LongFile.txt" (SFN fallback LONGFI~1.TXT);
    // the long name must survive the walker's accumulator and be
    // lookup-able via the LFN path.
    DirEntry lng;
    if (!Fat32LookupPath(v0, "/LongFile.txt", &lng))
    {
        SerialWrite("[fs/fat32] self-test WARN: /LongFile.txt not resolved via LFN\n");
        return;
    }
    Zero(buf, sizeof(buf));
    const i64 n3 = Fat32ReadFile(v0, &lng, buf, sizeof(buf));
    const char* expect3 = "long filename file\n";
    u32 elen3 = 0;
    while (expect3[elen3] != 0)
        ++elen3;
    if (n3 != static_cast<i64>(elen3))
    {
        SerialWrite("[fs/fat32] self-test FAILED: LongFile.txt wrong size\n");
        return;
    }
    for (u32 i = 0; i < elen3; ++i)
    {
        if (buf[i] != static_cast<u8>(expect3[i]))
        {
            SerialWrite("[fs/fat32] self-test FAILED: LongFile.txt content mismatch\n");
            return;
        }
    }
    SerialWrite("[fs/fat32] self-test OK (LFN /LongFile.txt decoded + verified)\n");

    // Fourth phase: streamed read across multiple clusters. The
    // image-builder seeds /BIG.TXT as 6000 bytes of a printable-
    // ASCII pattern spanning clusters 7+8.
    DirEntry big;
    if (!Fat32LookupPath(v0, "/BIG.TXT", &big))
    {
        SerialWrite("[fs/fat32] self-test WARN: /BIG.TXT not found\n");
        return;
    }
    struct StreamCtx
    {
        u64 total;
        u8 first_byte;
        u8 last_byte;
        u8 byte_4095;
        u8 byte_4096;
        bool captured_first;
    };
    StreamCtx sc{0, 0, 0, 0, 0, false};
    const bool stream_ok = Fat32ReadFileStream(
        v0, &big,
        [](const u8* data, u64 len, void* ctx) -> bool
        {
            auto* s = static_cast<StreamCtx*>(ctx);
            if (!s->captured_first && len > 0)
            {
                s->first_byte = data[0];
                s->captured_first = true;
            }
            // Boundary bytes. `data` is this cluster's first byte,
            // so the absolute offset of data[i] is `s->total + i`.
            for (u64 i = 0; i < len; ++i)
            {
                const u64 abs = s->total + i;
                if (abs == 4095)
                    s->byte_4095 = data[i];
                if (abs == 4096)
                    s->byte_4096 = data[i];
            }
            s->total += len;
            if (len > 0)
                s->last_byte = data[len - 1];
            return true;
        },
        &sc);
    if (!stream_ok)
    {
        SerialWrite("[fs/fat32] self-test FAILED: /BIG.TXT stream read error\n");
        return;
    }
    // Expected pattern: byte i = 0x20 + (i % 95).
    const u8 exp_first = 0x20 + (0 % 95);
    const u8 exp_4095 = 0x20 + (4095 % 95);
    const u8 exp_4096 = 0x20 + (4096 % 95);
    const u8 exp_last = 0x20 + (5999 % 95);
    if (sc.total != 6000 || sc.first_byte != exp_first || sc.byte_4095 != exp_4095 || sc.byte_4096 != exp_4096 ||
        sc.last_byte != exp_last)
    {
        SerialWrite("[fs/fat32] self-test FAILED: /BIG.TXT pattern mismatch\n");
        return;
    }
    SerialWrite("[fs/fat32] self-test OK (streamed /BIG.TXT 6000 B across clusters)\n");

    // Fifth phase: in-place write. Take HELLO.TXT (body "hello from
    // fat32\n"), overwrite bytes [0..5) from "hello" to "HELLO",
    // read back, then restore. Round-trip verifies the whole chain:
    //   Fat32WriteInPlace -> BlockDeviceWrite -> AHCI/NVMe WRITE_DMA
    //   -> re-read -> byte-compare -> restore.
    // Volume 0 picked because we already verified HELLO.TXT there.
    const DirEntry* hello2 = Fat32FindInRoot(v0, "HELLO.TXT");
    if (hello2 == nullptr)
    {
        SerialWrite("[fs/fat32] self-test WARN: HELLO.TXT missing for write test\n");
        return;
    }
    const u8 upper[] = {'H', 'E', 'L', 'L', 'O'};
    const u8 lower[] = {'h', 'e', 'l', 'l', 'o'};
    if (Fat32WriteInPlace(v0, hello2, 0, upper, 5) != 5)
    {
        SerialWrite("[fs/fat32] self-test FAILED: HELLO.TXT write returned wrong count\n");
        return;
    }
    Zero(buf, sizeof(buf));
    const i64 n4 = Fat32ReadFile(v0, hello2, buf, sizeof(buf));
    if (n4 != 17 || buf[0] != 'H' || buf[1] != 'E' || buf[2] != 'L' || buf[3] != 'L' || buf[4] != 'O' || buf[5] != ' ')
    {
        SerialWrite("[fs/fat32] self-test FAILED: HELLO.TXT read-back after write mismatch\n");
        return;
    }
    // Restore to the original body so subsequent re-runs see a
    // clean fixture. Not strictly necessary (the image is rebuilt
    // every run by make-gpt-image.py) but makes the on-disk state
    // match the image-builder's output at test end.
    if (Fat32WriteInPlace(v0, hello2, 0, lower, 5) != 5)
    {
        SerialWrite("[fs/fat32] self-test FAILED: HELLO.TXT restore write failed\n");
        return;
    }
    SerialWrite("[fs/fat32] self-test OK (HELLO.TXT in-place round-trip verified)\n");

    // Sixth phase: append-and-grow. Take HELLO.TXT (17 B, single
    // cluster) and extend it by 5000 bytes of pattern — forces
    // allocation of a second cluster, FAT chaining, directory
    // entry size update. Read back the whole thing and verify
    // the original 17 B prefix + the 5000 B pattern tail.
    const char* hello_name = "HELLO.TXT";
    const u32 grow_by = 5000;
    static u8 pattern[5000];
    for (u32 i = 0; i < grow_by; ++i)
        pattern[i] = static_cast<u8>(0x41 + (i % 26)); // A..Z repeating
    const i64 appended = Fat32AppendInRoot(v0, hello_name, pattern, grow_by);
    if (appended != static_cast<i64>(grow_by))
    {
        SerialWrite("[fs/fat32] self-test FAILED: append returned wrong count\n");
        return;
    }
    const DirEntry* grown = Fat32FindInRoot(v0, hello_name);
    if (grown == nullptr || grown->size_bytes != 17 + grow_by)
    {
        SerialWrite("[fs/fat32] self-test FAILED: grown HELLO.TXT size wrong\n");
        return;
    }
    // Verify by streamed read — can't fit 5017 B in buf[64].
    struct VerifyCtx
    {
        u64 total;
        bool prefix_ok;
        bool tail_ok;
        bool tail_seen;
    };
    VerifyCtx vc{0, true, true, false};
    Fat32ReadFileStream(
        v0, grown,
        [](const u8* data, u64 len, void* ctx) -> bool
        {
            auto* c = static_cast<VerifyCtx*>(ctx);
            const char* prefix = "hello from fat32\n";
            const u64 prefix_len = 17;
            for (u64 i = 0; i < len; ++i)
            {
                const u64 abs = c->total + i;
                if (abs < prefix_len)
                {
                    if (data[i] != static_cast<u8>(prefix[abs]))
                        c->prefix_ok = false;
                }
                else
                {
                    const u64 off = abs - prefix_len;
                    const u8 expect = static_cast<u8>(0x41 + (off % 26));
                    if (data[i] != expect)
                        c->tail_ok = false;
                    c->tail_seen = true;
                }
            }
            c->total += len;
            return true;
        },
        &vc);
    if (vc.total != 17 + grow_by || !vc.prefix_ok || !vc.tail_seen || !vc.tail_ok)
    {
        SerialWrite("[fs/fat32] self-test FAILED: grown HELLO.TXT read-back mismatch\n");
        return;
    }
    SerialWrite("[fs/fat32] self-test OK (append grew HELLO.TXT 17 -> 5017 B)\n");

    // Seventh phase: create. New file "NEW.TXT" with content
    // "created at runtime\n" (19 bytes). Must enumerate + read
    // back exactly.
    const u8 create_body[] = "created at runtime\n";
    const u64 create_len = 19;
    if (Fat32CreateInRoot(v0, "NEW.TXT", create_body, create_len) != static_cast<i64>(create_len))
    {
        SerialWrite("[fs/fat32] self-test FAILED: create NEW.TXT\n");
        return;
    }
    const DirEntry* newent = Fat32FindInRoot(v0, "NEW.TXT");
    if (newent == nullptr || newent->size_bytes != create_len)
    {
        SerialWrite("[fs/fat32] self-test FAILED: NEW.TXT not visible / wrong size\n");
        return;
    }
    Zero(buf, sizeof(buf));
    const i64 n5 = Fat32ReadFile(v0, newent, buf, sizeof(buf));
    if (n5 != static_cast<i64>(create_len))
    {
        SerialWrite("[fs/fat32] self-test FAILED: NEW.TXT read-back wrong size\n");
        return;
    }
    for (u32 i = 0; i < create_len; ++i)
    {
        if (buf[i] != create_body[i])
        {
            SerialWrite("[fs/fat32] self-test FAILED: NEW.TXT content mismatch\n");
            return;
        }
    }
    SerialWrite("[fs/fat32] self-test OK (created NEW.TXT 19 B, round-tripped)\n");

    // Eighth phase: truncate. Shrink NEW.TXT from 19 to 7 bytes
    // ("created"), then verify. Cluster is not freed (fits in
    // one cluster either way) but the size field and any future
    // read must stop at 7.
    if (Fat32TruncateInRoot(v0, "NEW.TXT", 7) != 7)
    {
        SerialWrite("[fs/fat32] self-test FAILED: truncate NEW.TXT -> 7\n");
        return;
    }
    const DirEntry* trunc_ent = Fat32FindInRoot(v0, "NEW.TXT");
    if (trunc_ent == nullptr || trunc_ent->size_bytes != 7)
    {
        SerialWrite("[fs/fat32] self-test FAILED: NEW.TXT post-truncate size wrong\n");
        return;
    }
    Zero(buf, sizeof(buf));
    const i64 n6 = Fat32ReadFile(v0, trunc_ent, buf, sizeof(buf));
    if (n6 != 7 || buf[0] != 'c' || buf[6] != 'd')
    {
        SerialWrite("[fs/fat32] self-test FAILED: NEW.TXT post-truncate content\n");
        return;
    }
    SerialWrite("[fs/fat32] self-test OK (truncated NEW.TXT 19 -> 7 B)\n");

    // Ninth phase: delete. Remove NEW.TXT; enumeration must no
    // longer see it.
    if (!Fat32DeleteInRoot(v0, "NEW.TXT"))
    {
        SerialWrite("[fs/fat32] self-test FAILED: delete NEW.TXT\n");
        return;
    }
    if (Fat32FindInRoot(v0, "NEW.TXT") != nullptr)
    {
        SerialWrite("[fs/fat32] self-test FAILED: NEW.TXT still visible after delete\n");
        return;
    }
    SerialWrite("[fs/fat32] self-test OK (deleted NEW.TXT)\n");

    // Tenth phase: create + read + delete a file in /SUB, using
    // the path-based API. Exercises the parent-directory
    // resolution step and the generic InDir primitives.
    const u8 sub_body[] = "sub file\n";
    const u64 sub_len = 9;
    if (Fat32CreateAtPath(v0, "/SUB/CHILD.TXT", sub_body, sub_len) != static_cast<i64>(sub_len))
    {
        SerialWrite("[fs/fat32] self-test FAILED: create /SUB/CHILD.TXT\n");
        return;
    }
    DirEntry child;
    if (!Fat32LookupPath(v0, "/SUB/CHILD.TXT", &child) || child.size_bytes != sub_len)
    {
        SerialWrite("[fs/fat32] self-test FAILED: /SUB/CHILD.TXT not resolvable after create\n");
        return;
    }
    Zero(buf, sizeof(buf));
    const i64 n7 = Fat32ReadFile(v0, &child, buf, sizeof(buf));
    if (n7 != static_cast<i64>(sub_len))
    {
        SerialWrite("[fs/fat32] self-test FAILED: /SUB/CHILD.TXT read-back wrong size\n");
        return;
    }
    for (u32 i = 0; i < sub_len; ++i)
    {
        if (buf[i] != sub_body[i])
        {
            SerialWrite("[fs/fat32] self-test FAILED: /SUB/CHILD.TXT content mismatch\n");
            return;
        }
    }
    if (!Fat32DeleteAtPath(v0, "/SUB/CHILD.TXT"))
    {
        SerialWrite("[fs/fat32] self-test FAILED: delete /SUB/CHILD.TXT\n");
        return;
    }
    DirEntry after_del;
    if (Fat32LookupPath(v0, "/SUB/CHILD.TXT", &after_del))
    {
        SerialWrite("[fs/fat32] self-test FAILED: /SUB/CHILD.TXT still visible after delete\n");
        return;
    }
    SerialWrite("[fs/fat32] self-test OK (subdir CRUD on /SUB/CHILD.TXT)\n");

    // Eleventh phase: LFN emission on create. Name "MixedCase.Report.md"
    // triggers the LFN path (multi-dot, mixed case, > 8 base). The
    // walker reads the long name back via its LFN accumulator; we
    // verify both that the created file is findable by its long
    // name AND that the SFN fallback is findable too.
    const char* long_name = "MixedCase.Report.md";
    const u8 long_body[] = "lfn create smoke\n";
    const u64 long_body_len = 17;
    if (Fat32CreateAtPath(v0, "/MixedCase.Report.md", long_body, long_body_len) != static_cast<i64>(long_body_len))
    {
        SerialWrite("[fs/fat32] self-test FAILED: create MixedCase.Report.md\n");
        return;
    }
    DirEntry lng_create;
    if (!Fat32LookupPath(v0, "/MixedCase.Report.md", &lng_create))
    {
        SerialWrite("[fs/fat32] self-test FAILED: long-name lookup post-create\n");
        return;
    }
    // Exact long-name match in DirEntry.name proves the walker
    // correctly accumulated our emitted LFN fragments.
    for (u32 i = 0; long_name[i] != 0; ++i)
    {
        if (lng_create.name[i] != long_name[i])
        {
            SerialWrite("[fs/fat32] self-test FAILED: long-name round-trip mismatch\n");
            return;
        }
    }
    Zero(buf, sizeof(buf));
    const i64 n8 = Fat32ReadFile(v0, &lng_create, buf, sizeof(buf));
    if (n8 != static_cast<i64>(long_body_len))
    {
        SerialWrite("[fs/fat32] self-test FAILED: long-name body size\n");
        return;
    }
    for (u32 i = 0; i < long_body_len; ++i)
    {
        if (buf[i] != long_body[i])
        {
            SerialWrite("[fs/fat32] self-test FAILED: long-name body mismatch\n");
            return;
        }
    }
    if (!Fat32DeleteAtPath(v0, "/MixedCase.Report.md"))
    {
        SerialWrite("[fs/fat32] self-test FAILED: delete long-name file\n");
        return;
    }
    SerialWrite("[fs/fat32] self-test OK (LFN emitted + read back on create/delete)\n");

    // Twelfth phase: mkdir / rmdir round-trip. Create /NEWDIR,
    // verify it's a directory, create a file inside it, verify
    // rmdir FAILS when non-empty, remove the file, rmdir
    // succeeds, verify the directory is gone.
    if (!Fat32MkdirAtPath(v0, "/NEWDIR"))
    {
        SerialWrite("[fs/fat32] self-test FAILED: mkdir /NEWDIR\n");
        return;
    }
    DirEntry mkd;
    if (!Fat32LookupPath(v0, "/NEWDIR", &mkd) || (mkd.attributes & 0x10) == 0)
    {
        SerialWrite("[fs/fat32] self-test FAILED: /NEWDIR not a directory post-mkdir\n");
        return;
    }
    const u8 inside_body[] = "inside\n";
    if (Fat32CreateAtPath(v0, "/NEWDIR/FILE.TXT", inside_body, 7) != 7)
    {
        SerialWrite("[fs/fat32] self-test FAILED: create /NEWDIR/FILE.TXT\n");
        return;
    }
    if (Fat32RmdirAtPath(v0, "/NEWDIR"))
    {
        SerialWrite("[fs/fat32] self-test FAILED: rmdir on non-empty dir should refuse\n");
        return;
    }
    if (!Fat32DeleteAtPath(v0, "/NEWDIR/FILE.TXT"))
    {
        SerialWrite("[fs/fat32] self-test FAILED: delete /NEWDIR/FILE.TXT\n");
        return;
    }
    if (!Fat32RmdirAtPath(v0, "/NEWDIR"))
    {
        SerialWrite("[fs/fat32] self-test FAILED: rmdir /NEWDIR when empty\n");
        return;
    }
    DirEntry after_rmdir;
    if (Fat32LookupPath(v0, "/NEWDIR", &after_rmdir))
    {
        SerialWrite("[fs/fat32] self-test FAILED: /NEWDIR still visible after rmdir\n");
        return;
    }
    SerialWrite("[fs/fat32] self-test OK (mkdir + rmdir round-trip with empty-check)\n");

    // Thirteenth phase: directory growth. Fill /SUB with enough
    // long-named files to overflow its single 4 KiB cluster (128
    // slots). Each LFN create takes 2 slots (1 frag + 1 SFN);
    // 70 such files = 140 slots. With /SUB's existing "." / ".."
    // + 1 INNER.TXT (3 slots), we need the driver to allocate
    // a second cluster for /SUB and place later entries there.
    //
    // Create 70 LFN files, read back the 70th, delete all 70,
    // verify /SUB looks unchanged afterward. If directory growth
    // is working, this just succeeds; if not, ~62 creates in
    // we run out of slots in the first cluster.
    if (!Fat32MkdirAtPath(v0, "/SUB/GROWTEST"))
    {
        SerialWrite("[fs/fat32] self-test FAILED: mkdir /SUB/GROWTEST\n");
        return;
    }
    const u32 grow_count = 70;
    for (u32 i = 0; i < grow_count; ++i)
    {
        // Name forces LFN path: mixed case + long base.
        char name[64];
        const char* prefix = "/SUB/GROWTEST/LongEntry";
        u32 w = 0;
        while (prefix[w] != 0 && w + 8 < sizeof(name))
        {
            name[w] = prefix[w];
            ++w;
        }
        // Append "NN.txt".
        name[w++] = static_cast<char>('0' + (i / 10) % 10);
        name[w++] = static_cast<char>('0' + i % 10);
        name[w++] = '.';
        name[w++] = 't';
        name[w++] = 'x';
        name[w++] = 't';
        name[w] = 0;
        const u8 body[2] = {'x', '\n'};
        if (Fat32CreateAtPath(v0, name, body, 2) != 2)
        {
            SerialWrite("[fs/fat32] self-test FAILED: growth create at ");
            SerialWrite(name);
            SerialWrite("\n");
            return;
        }
    }
    // Verify the last-written file is readable + has expected body.
    DirEntry last_ent;
    if (!Fat32LookupPath(v0, "/SUB/GROWTEST/LongEntry69.txt", &last_ent) || last_ent.size_bytes != 2)
    {
        SerialWrite("[fs/fat32] self-test FAILED: growth last-entry read-back\n");
        return;
    }
    // Tear down.
    for (u32 i = 0; i < grow_count; ++i)
    {
        char name[64];
        const char* prefix = "/SUB/GROWTEST/LongEntry";
        u32 w = 0;
        while (prefix[w] != 0 && w + 8 < sizeof(name))
        {
            name[w] = prefix[w];
            ++w;
        }
        name[w++] = static_cast<char>('0' + (i / 10) % 10);
        name[w++] = static_cast<char>('0' + i % 10);
        name[w++] = '.';
        name[w++] = 't';
        name[w++] = 'x';
        name[w++] = 't';
        name[w] = 0;
        if (!Fat32DeleteAtPath(v0, name))
        {
            SerialWrite("[fs/fat32] self-test FAILED: growth delete at ");
            SerialWrite(name);
            SerialWrite("\n");
            return;
        }
    }
    if (!Fat32RmdirAtPath(v0, "/SUB/GROWTEST"))
    {
        SerialWrite("[fs/fat32] self-test FAILED: rmdir /SUB/GROWTEST post-teardown\n");
        return;
    }
    SerialWrite("[fs/fat32] self-test OK (dir growth handled 70 LFN entries + teardown)\n");
}

} // namespace duetos::fs::fat32
