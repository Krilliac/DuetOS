#include "apps/screenshot.h"

#include "arch/x86_64/serial.h"
#include "drivers/video/cursor.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/notify.h"
#include "drivers/video/sound_cue.h"
#include "fs/fat32.h"
#include "mm/kheap.h"
#include "util/bmp.h"
#include "util/tga.h"

namespace duetos::apps::screenshot
{

namespace
{

// 64 KiB fits header + 16 rows at 1024 px width, 8 rows at
// 2048 px, etc. — at least one row per chunk for any practical
// resolution. KMalloc satisfies a single 64 KiB request from a
// 2 MiB heap easily.
constexpr u64 kScratchBytes = 65536;

using duetos::util::kBmpFileHeaderBytes;
using duetos::util::kBmpHeaderBytes;
using duetos::util::kBmpInfoHeaderBytes;

// Format `n` (0..9999) + extension into a 13-byte SHOTNNNN.XXX
// filename buffer. Used by both the BMP and TGA capture paths.
void FormatShotName(char* out, u32 n, char e0, char e1, char e2)
{
    out[0] = 'S';
    out[1] = 'H';
    out[2] = 'O';
    out[3] = 'T';
    out[4] = static_cast<char>('0' + (n / 1000) % 10);
    out[5] = static_cast<char>('0' + (n / 100) % 10);
    out[6] = static_cast<char>('0' + (n / 10) % 10);
    out[7] = static_cast<char>('0' + n % 10);
    out[8] = '.';
    out[9] = e0;
    out[10] = e1;
    out[11] = e2;
    out[12] = '\0';
}

// Scan the FAT32 root for SHOTNNNN.{BMP,TGA} entries; return the
// next unused index (max+1 across both extensions, or 1 if none).
// Returns 0 when the next index would exceed 9999. Sharing the
// counter across formats means a sequence of mixed BMP/TGA captures
// produces strictly-increasing numbers — useful for after-the-fact
// chronological sorting.
u32 NextShotIndex(const fs::fat32::Volume* v)
{
    namespace fat = fs::fat32;
    fat::DirEntry entries[fat::kMaxDirEntries];
    const u32 n = fat::Fat32ListDirByCluster(v, v->root_cluster, entries, fat::kMaxDirEntries);
    u32 max_idx = 0;
    for (u32 i = 0; i < n; ++i)
    {
        const char* name = entries[i].name;
        if (!(name[0] == 'S' && name[1] == 'H' && name[2] == 'O' && name[3] == 'T'))
            continue;
        u32 num = 0;
        bool digits_ok = true;
        for (u32 d = 4; d < 8; ++d)
        {
            const char c = name[d];
            if (c < '0' || c > '9')
            {
                digits_ok = false;
                break;
            }
            num = num * 10 + static_cast<u32>(c - '0');
        }
        if (!digits_ok)
            continue;
        if (name[8] != '.')
            continue;
        const bool is_bmp = (name[9] == 'B' && name[10] == 'M' && name[11] == 'P');
        const bool is_tga = (name[9] == 'T' && name[10] == 'G' && name[11] == 'A');
        if (!(is_bmp || is_tga) || name[12] != '\0')
            continue;
        if (num > max_idx)
            max_idx = num;
    }
    const u32 next = max_idx + 1;
    return (next > 9999) ? 0 : next;
}

// Stream `width × height` pixels from `src_rows` (one pointer per
// row) to `path`, prefixed by a caller-provided header (BMP or
// TGA) of `header_len` bytes already laid down at scratch[0..]. On
// any I/O failure deletes the partial file. Returns true iff
// every chunk wrote successfully.
bool StreamRows(const fs::fat32::Volume* v, const char* path, u32 width, u32 height, u8* scratch, u64 header_len,
                const u8* const* src_rows)
{
    namespace fat = fs::fat32;
    u64 used = header_len;
    const u64 row_bytes = static_cast<u64>(width) * 4;

    u32 row = 0;
    bool first_chunk = true;
    bool ok = true;

    while (row < height && ok)
    {
        // Pack as many rows as fit in scratch.
        while (row < height && used + row_bytes <= kScratchBytes)
        {
            const u8* src = src_rows[row];
            for (u64 b = 0; b < row_bytes; ++b)
            {
                scratch[used + b] = src[b];
            }
            used += row_bytes;
            ++row;
        }
        if (first_chunk)
        {
            ok = (fat::Fat32CreateAtPath(v, path, scratch, used) >= 0);
            first_chunk = false;
        }
        else
        {
            ok = (fat::Fat32AppendAtPath(v, path, scratch, used) >= 0);
        }
        used = 0;
    }

    mm::KFree(scratch);

    if (!ok)
    {
        // Best-effort cleanup; if the create itself failed there's
        // nothing on disk to delete.
        fat::Fat32DeleteAtPath(v, path);
    }
    return ok;
}

} // namespace

bool ScreenshotCapture()
{
    namespace fat = fs::fat32;
    using arch::SerialWrite;
    using drivers::video::CursorPopWait;
    using drivers::video::CursorPushWait;
    using drivers::video::NotifyKind;
    using drivers::video::NotifyShow;
    using drivers::video::NotifyShowKind;

    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
    {
        SerialWrite("[shot] capture: no FAT32 volume\n");
        NotifyShow("screenshot: no disk");
        return false;
    }

    const auto fb = drivers::video::FramebufferGet();
    if (fb.virt == nullptr || fb.width == 0 || fb.height == 0 || fb.bpp != 32)
    {
        SerialWrite("[shot] capture: no usable 32-bpp framebuffer\n");
        NotifyShow("screenshot: no framebuffer");
        return false;
    }

    // Hourglass for the duration of the FAT32 streaming write —
    // a multi-MiB framebuffer dump can take long enough that the
    // user wonders if the keystroke registered.
    CursorPushWait();

    const u32 idx = NextShotIndex(v);
    if (idx == 0)
    {
        SerialWrite("[shot] capture: filename counter exhausted (>9999)\n");
        CursorPopWait();
        NotifyShow("screenshot: filename slots exhausted");
        return false;
    }
    char path[16];
    FormatShotName(path, idx, 'B', 'M', 'P');

    // Build a per-row pointer table on the stack. 1024 rows × 8 B
    // = 8 KiB on the kernel stack; 4096 rows would exceed the
    // 16 KiB stack budget, so cap. That cap is well above any
    // practical framebuffer height.
    constexpr u32 kMaxRows = 2048;
    if (fb.height > kMaxRows)
    {
        SerialWrite("[shot] capture: framebuffer too tall (>2048 rows)\n");
        CursorPopWait();
        NotifyShow("screenshot: too tall (>2048 rows)");
        return false;
    }
    const u8* rows[kMaxRows];
    const auto* fb_bytes = static_cast<const u8*>(fb.virt);
    for (u32 r = 0; r < fb.height; ++r)
    {
        rows[r] = fb_bytes + static_cast<u64>(r) * fb.pitch;
    }

    u8* scratch = static_cast<u8*>(mm::KMalloc(kScratchBytes));
    if (scratch == nullptr)
    {
        SerialWrite("[shot] capture: scratch alloc failed\n");
        CursorPopWait();
        NotifyShowKind("screenshot: out of memory", NotifyKind::Error);
        return false;
    }
    duetos::util::BmpWriteHeader32(scratch, fb.width, fb.height, /*top_down=*/true);
    if (!StreamRows(v, path, fb.width, fb.height, scratch, kBmpHeaderBytes, rows))
    {
        SerialWrite("[shot] capture: write failed (disk full?)\n");
        CursorPopWait();
        NotifyShowKind("screenshot: write failed", NotifyKind::Error);
        return false;
    }

    SerialWrite("[shot] capture: ");
    SerialWrite(path);
    SerialWrite("\n");
    CursorPopWait();
    // Toast the saved filename — the operator otherwise has no
    // confirmation the F-key actually wrote anything.
    char toast[40];
    u32 to = 0;
    const char* prefix = "saved ";
    while (prefix[to] != '\0' && to + 1 < sizeof(toast))
    {
        toast[to] = prefix[to];
        ++to;
    }
    for (u32 j = 0; path[j] != '\0' && to + 1 < sizeof(toast); ++j)
    {
        toast[to++] = path[j];
    }
    toast[to] = '\0';
    NotifyShowKind(toast, NotifyKind::Success);
    duetos::drivers::video::SoundCueChime();
    return true;
}

bool ScreenshotCaptureTga()
{
    namespace fat = fs::fat32;
    using arch::SerialWrite;
    using drivers::video::CursorPopWait;
    using drivers::video::CursorPushWait;
    using drivers::video::NotifyKind;
    using drivers::video::NotifyShow;
    using drivers::video::NotifyShowKind;

    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
    {
        SerialWrite("[shot] tga: no FAT32 volume\n");
        NotifyShow("screenshot: no disk");
        return false;
    }
    const auto fb = drivers::video::FramebufferGet();
    if (fb.virt == nullptr || fb.width == 0 || fb.height == 0 || fb.bpp != 32)
    {
        SerialWrite("[shot] tga: no usable 32-bpp framebuffer\n");
        NotifyShow("screenshot: no framebuffer");
        return false;
    }
    CursorPushWait();
    const u32 idx = NextShotIndex(v);
    if (idx == 0)
    {
        SerialWrite("[shot] tga: filename counter exhausted (>9999)\n");
        CursorPopWait();
        NotifyShow("screenshot: filename slots exhausted");
        return false;
    }
    char path[16];
    FormatShotName(path, idx, 'T', 'G', 'A');

    constexpr u32 kMaxRows = 2048;
    if (fb.height > kMaxRows)
    {
        SerialWrite("[shot] tga: framebuffer too tall (>2048 rows)\n");
        CursorPopWait();
        NotifyShow("screenshot: too tall (>2048 rows)");
        return false;
    }
    const u8* rows[kMaxRows];
    const auto* fb_bytes = static_cast<const u8*>(fb.virt);
    for (u32 r = 0; r < fb.height; ++r)
    {
        rows[r] = fb_bytes + static_cast<u64>(r) * fb.pitch;
    }

    u8* scratch = static_cast<u8*>(mm::KMalloc(kScratchBytes));
    if (scratch == nullptr)
    {
        SerialWrite("[shot] tga: scratch alloc failed\n");
        CursorPopWait();
        NotifyShowKind("screenshot: out of memory", NotifyKind::Error);
        return false;
    }
    if (!duetos::util::TgaWriteHeader32(scratch, fb.width, fb.height))
    {
        mm::KFree(scratch);
        SerialWrite("[shot] tga: header build failed (oversize dim?)\n");
        CursorPopWait();
        NotifyShowKind("screenshot: tga header failed", NotifyKind::Error);
        return false;
    }
    if (!StreamRows(v, path, fb.width, fb.height, scratch, duetos::util::kTgaHeaderBytes, rows))
    {
        SerialWrite("[shot] tga: write failed (disk full?)\n");
        CursorPopWait();
        NotifyShowKind("screenshot: write failed", NotifyKind::Error);
        return false;
    }

    SerialWrite("[shot] tga: ");
    SerialWrite(path);
    SerialWrite("\n");
    CursorPopWait();
    char toast[40];
    u32 to = 0;
    const char* prefix = "saved ";
    while (prefix[to] != '\0' && to + 1 < sizeof(toast))
    {
        toast[to] = prefix[to];
        ++to;
    }
    for (u32 j = 0; path[j] != '\0' && to + 1 < sizeof(toast); ++j)
    {
        toast[to++] = path[j];
    }
    toast[to] = '\0';
    NotifyShowKind(toast, NotifyKind::Success);
    duetos::drivers::video::SoundCueChime();
    return true;
}

void ScreenshotSelfTest()
{
    namespace fat = fs::fat32;
    using arch::SerialWrite;

    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
    {
        SerialWrite("[shot] self-test SKIP: no FAT32 volume\n");
        return;
    }
    constexpr const char kTestPath[] = "SHOTTEST.BMP";
    fat::DirEntry pre;
    if (fat::Fat32LookupPath(v, kTestPath, &pre))
    {
        // Stale test file from a previous run; don't trust it.
        fat::Fat32DeleteAtPath(v, kTestPath);
    }

    // 4×4 synthetic test pattern: a deterministic gradient so a
    // future tooling pass can byte-compare. 16 pixels × 4 bytes
    // = 64 bytes of pixel data; total file size = 54 + 64 = 118.
    constexpr u32 kW = 4;
    constexpr u32 kH = 4;
    u8 row_data[kH][kW * 4];
    for (u32 y = 0; y < kH; ++y)
    {
        for (u32 x = 0; x < kW; ++x)
        {
            row_data[y][x * 4 + 0] = static_cast<u8>(0x10 * (x + 1));
            row_data[y][x * 4 + 1] = static_cast<u8>(0x10 * (y + 1));
            row_data[y][x * 4 + 2] = 0x80;
            row_data[y][x * 4 + 3] = 0x00;
        }
    }
    const u8* rows[kH];
    for (u32 y = 0; y < kH; ++y)
    {
        rows[y] = row_data[y];
    }

    u8* test_scratch = static_cast<u8*>(mm::KMalloc(kScratchBytes));
    bool wrote = false;
    if (test_scratch != nullptr)
    {
        duetos::util::BmpWriteHeader32(test_scratch, kW, kH, /*top_down=*/true);
        wrote = StreamRows(v, kTestPath, kW, kH, test_scratch, kBmpHeaderBytes, rows);
    }

    // Verify the file landed at the expected size.
    bool size_ok = false;
    if (wrote)
    {
        fat::DirEntry e;
        if (fat::Fat32LookupPath(v, kTestPath, &e))
        {
            size_ok = (e.size_bytes == kBmpHeaderBytes + kW * kH * 4);
        }
    }

    fat::Fat32DeleteAtPath(v, kTestPath);

    if (wrote && size_ok)
    {
        SerialWrite("[shot] self-test OK (4x4 BMP round-trip)\n");
    }
    else
    {
        SerialWrite("[shot] self-test FAILED\n");
    }
}

} // namespace duetos::apps::screenshot
