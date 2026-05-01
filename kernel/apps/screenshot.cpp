#include "apps/screenshot.h"

#include "arch/x86_64/serial.h"
#include "drivers/video/framebuffer.h"
#include "fs/fat32.h"
#include "mm/kheap.h"

namespace duetos::apps::screenshot
{

namespace
{

// 64 KiB fits header + 16 rows at 1024 px width, 8 rows at
// 2048 px, etc. — at least one row per chunk for any practical
// resolution. KMalloc satisfies a single 64 KiB request from a
// 2 MiB heap easily.
constexpr u64 kScratchBytes = 65536;

constexpr u64 kBmpFileHeaderBytes = 14;
constexpr u64 kBmpInfoHeaderBytes = 40;
constexpr u64 kBmpHeaderBytes = kBmpFileHeaderBytes + kBmpInfoHeaderBytes;

// Little-endian byte stores. Reinterpret-cast onto a u8* would
// fail on builds that strict-alias; this is portable and the
// compiler folds it into single MOVs.
inline void StoreU16(u8* p, u16 v)
{
    p[0] = static_cast<u8>(v);
    p[1] = static_cast<u8>(v >> 8);
}

inline void StoreU32(u8* p, u32 v)
{
    p[0] = static_cast<u8>(v);
    p[1] = static_cast<u8>(v >> 8);
    p[2] = static_cast<u8>(v >> 16);
    p[3] = static_cast<u8>(v >> 24);
}

// 32-bpp top-down BMP: BITMAPFILEHEADER + BITMAPINFOHEADER. The
// negative DIB height tells decoders the rows are stored in
// framebuffer order (no flip), matching how we copy them out.
void WriteBmpHeader(u8* out, u32 width, u32 height)
{
    const u32 pixel_bytes = width * height * 4;
    const u32 file_size = static_cast<u32>(kBmpHeaderBytes) + pixel_bytes;

    // BITMAPFILEHEADER (14 bytes)
    out[0] = 'B';
    out[1] = 'M';
    StoreU32(out + 2, file_size);
    StoreU16(out + 6, 0); // reserved
    StoreU16(out + 8, 0); // reserved
    StoreU32(out + 10, static_cast<u32>(kBmpHeaderBytes));

    // BITMAPINFOHEADER (40 bytes)
    StoreU32(out + 14, static_cast<u32>(kBmpInfoHeaderBytes));
    StoreU32(out + 18, width);
    StoreU32(out + 22, static_cast<u32>(-static_cast<i32>(height)));
    StoreU16(out + 26, 1);  // planes
    StoreU16(out + 28, 32); // bpp
    StoreU32(out + 30, 0);  // BI_RGB (uncompressed)
    StoreU32(out + 34, pixel_bytes);
    StoreU32(out + 38, 2835); // ~72 DPI in pixels-per-metre
    StoreU32(out + 42, 2835);
    StoreU32(out + 46, 0); // colors used
    StoreU32(out + 50, 0); // colors important
}

// Format `n` (0..9999) into the four-digit slot of an SHOTNNNN
// filename buffer. Fills out[4..7]. Buffer convention is the
// 13-byte SHOTNNNN.BMP\0 form.
void FormatShotName(char* out, u32 n)
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
    out[9] = 'B';
    out[10] = 'M';
    out[11] = 'P';
    out[12] = '\0';
}

// Scan the FAT32 root for SHOTNNNN.BMP entries; return the next
// unused index (max+1, or 1 if none). Returns 0 when the next
// index would exceed 9999.
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
        if (name[8] != '.' || name[9] != 'B' || name[10] != 'M' || name[11] != 'P' || name[12] != '\0')
            continue;
        if (num > max_idx)
            max_idx = num;
    }
    const u32 next = max_idx + 1;
    return (next > 9999) ? 0 : next;
}

// Stream `width × height` pixels from `src_rows` (one pointer per
// row) to `path`. First chunk uses Fat32CreateAtPath (also
// emitting the BMP header), the rest use Fat32AppendAtPath.
// On any I/O failure deletes the partial file. Returns true iff
// every chunk wrote successfully.
bool StreamBmp(const fs::fat32::Volume* v, const char* path, u32 width, u32 height, const u8* const* src_rows)
{
    namespace fat = fs::fat32;
    u8* scratch = static_cast<u8*>(mm::KMalloc(kScratchBytes));
    if (scratch == nullptr)
    {
        return false;
    }

    WriteBmpHeader(scratch, width, height);
    u64 used = kBmpHeaderBytes;
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

    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
    {
        SerialWrite("[shot] capture: no FAT32 volume\n");
        return false;
    }

    const auto fb = drivers::video::FramebufferGet();
    if (fb.virt == nullptr || fb.width == 0 || fb.height == 0 || fb.bpp != 32)
    {
        SerialWrite("[shot] capture: no usable 32-bpp framebuffer\n");
        return false;
    }

    const u32 idx = NextShotIndex(v);
    if (idx == 0)
    {
        SerialWrite("[shot] capture: filename counter exhausted (>9999)\n");
        return false;
    }
    char path[16];
    FormatShotName(path, idx);

    // Build a per-row pointer table on the stack. 1024 rows × 8 B
    // = 8 KiB on the kernel stack; 4096 rows would exceed the
    // 16 KiB stack budget, so cap. That cap is well above any
    // practical framebuffer height.
    constexpr u32 kMaxRows = 2048;
    if (fb.height > kMaxRows)
    {
        SerialWrite("[shot] capture: framebuffer too tall (>2048 rows)\n");
        return false;
    }
    const u8* rows[kMaxRows];
    const auto* fb_bytes = static_cast<const u8*>(fb.virt);
    for (u32 r = 0; r < fb.height; ++r)
    {
        rows[r] = fb_bytes + static_cast<u64>(r) * fb.pitch;
    }

    if (!StreamBmp(v, path, fb.width, fb.height, rows))
    {
        SerialWrite("[shot] capture: write failed (disk full?)\n");
        return false;
    }

    SerialWrite("[shot] capture: ");
    SerialWrite(path);
    SerialWrite("\n");
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

    const bool wrote = StreamBmp(v, kTestPath, kW, kH, rows);

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
