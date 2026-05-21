#include "apps/imageview.h"

#include "arch/x86_64/serial.h"
#include "drivers/video/framebuffer.h"
#include "drivers/input/ps2kbd.h"
#include "drivers/video/dnd.h"
#include "drivers/video/notify.h"
#include "fs/fat32.h"
#include "mm/kheap.h"
#include "util/bmp.h"
#include "util/jpeg.h"
#include "util/png.h"
#include "util/saturating.h"
#include "util/tga.h"

namespace duetos::apps::imageview
{

namespace
{

using duetos::drivers::video::FramebufferBlit;
using duetos::drivers::video::FramebufferDrawString;
using duetos::drivers::video::FramebufferFillRect;
using duetos::drivers::video::FramebufferPutPixel;
using duetos::drivers::video::kWindowInvalid;
using duetos::drivers::video::WindowContentFn;
using duetos::drivers::video::WindowHandle;
using duetos::drivers::video::WindowSetContentDraw;

constexpr u32 kMaxFiles = 64; // ~64 BMPs in the root tracked at once
constexpr u32 kNameCap = 16;  // 8.3 = 12 chars + NUL, with slack
constexpr u32 kStatusCap = 96;
constexpr u32 kRowH = 10;      // 8x8 glyph + 2 px padding
constexpr u32 kHeaderRows = 2; // status line + filename / pos line

// BMP-format constants (BITMAPFILEHEADER + BITMAPINFOHEADER) +
// header parser now live in `kernel/util/bmp.h`. The aliases
// below keep the existing call sites unchanged.
using duetos::util::BmpInfo;
using duetos::util::kBmpFileHeaderBytes;
using duetos::util::kBmpHeaderBytes;
using duetos::util::kBmpInfoHeaderBytes;

constexpr u32 kInkFg = 0x00D0D8E0;
constexpr u32 kInkDim = 0x00808890;
constexpr u32 kInkErr = 0x00E08070;
constexpr u32 kBg = 0x00080A0E;

inline BmpInfo ParseBmpHeader(const u8* hdr)
{
    return duetos::util::BmpParseHeader(hdr);
}

// Zoom is independent of window size. The decoded thumbnail is
// sized to the *content area* (fit-to-window via FitThumbnail);
// `zoom_percent` then scales that fitted buffer at blit time, so
// the user can crank past 1:1 without re-decoding and without
// resizing the window. At zoom == 100% the blit path matches v0
// byte-for-byte (FramebufferBlit of the pre-fit buffer). For
// zoom > 100% we walk destination pixels and NN-sample the
// already-decoded source. Pan is applied as a destination
// top-left offset and only does work when the scaled image
// overhangs the content rect.
constexpr u32 kZoomMin = 25;
constexpr u32 kZoomMax = 400;
constexpr u32 kZoomFit = 100;
constexpr u32 kZoomStepPct = 25; // Ctrl+wheel and '+/-' grain
constexpr i32 kPanStepPx = 32;

struct State
{
    WindowHandle handle;
    char names[kMaxFiles][kNameCap];
    u32 count;
    u32 index;

    // Decoded thumbnail.
    u32* pixels; // owned via KMalloc; nullptr if no image decoded
    u32 disp_w;  // valid pixel rect (≤ alloc_w)
    u32 disp_h;
    u32 alloc_w; // size_of pixels (in u32 elements per row × disp_h)
    u32 alloc_h;
    char status[kStatusCap];
    bool needs_decode; // re-decode on next draw

    // Independent zoom + pan. 100 = fit-to-window (1:1 with the
    // decoded thumbnail); 25..400 is the user-reachable range.
    // Pan offsets are content-rect pixels (positive = shift the
    // image right / down inside the rect). Reset by '0' and
    // implicitly by a re-decode (next image / rescan).
    u32 zoom_percent;
    i32 pan_x;
    i32 pan_y;
};

constinit State g_state = {kWindowInvalid, {}, 0, 0, nullptr, 0, 0, 0, 0, {}, false, kZoomFit, 0, 0};

void StatusSet(const char* msg)
{
    u32 i = 0;
    for (; i + 1 < kStatusCap && msg[i] != '\0'; ++i)
    {
        g_state.status[i] = msg[i];
    }
    g_state.status[i] = '\0';
}

void StatusAppendDec(u32 v)
{
    char tmp[16];
    u32 n = 0;
    if (v == 0)
    {
        tmp[n++] = '0';
    }
    else
    {
        while (v > 0 && n < sizeof(tmp))
        {
            tmp[n++] = static_cast<char>('0' + (v % 10));
            v /= 10;
        }
    }
    u32 len = 0;
    while (g_state.status[len] != '\0' && len + 1 < kStatusCap)
        ++len;
    while (n > 0 && len + 1 < kStatusCap)
    {
        g_state.status[len++] = tmp[--n];
    }
    g_state.status[len] = '\0';
}

void StatusAppendStr(const char* s)
{
    u32 len = 0;
    while (g_state.status[len] != '\0' && len + 1 < kStatusCap)
        ++len;
    for (u32 i = 0; s[i] != '\0' && len + 1 < kStatusCap; ++i)
    {
        g_state.status[len++] = s[i];
    }
    g_state.status[len] = '\0';
}

// ImageFormat — set from the filename extension during scan;
// used by DecodeCurrent to dispatch to the BMP-streamed,
// TGA-in-memory, or PNG-in-memory decoder.
enum class ImageFormat : u8
{
    Unknown = 0,
    Bmp = 1,
    Tga = 2,
    Png = 3,
    Jpeg = 4,
};

ImageFormat ClassifyByName(const char* name)
{
    u32 len = 0;
    while (name[len] != '\0' && len < kNameCap)
        ++len;
    if (len < 5)
        return ImageFormat::Unknown;
    auto up = [](char c) { return (c >= 'a' && c <= 'z') ? static_cast<char>(c - ('a' - 'A')) : c; };
    // 3-char extension (.bmp / .tga / .png / .jpg) — look at the
    // last 4 chars.
    if (name[len - 4] == '.')
    {
        const char e0 = up(name[len - 3]);
        const char e1 = up(name[len - 2]);
        const char e2 = up(name[len - 1]);
        if (e0 == 'B' && e1 == 'M' && e2 == 'P')
            return ImageFormat::Bmp;
        if (e0 == 'T' && e1 == 'G' && e2 == 'A')
            return ImageFormat::Tga;
        if (e0 == 'P' && e1 == 'N' && e2 == 'G')
            return ImageFormat::Png;
        if (e0 == 'J' && e1 == 'P' && e2 == 'G')
            return ImageFormat::Jpeg;
    }
    // 4-char extension (.jpeg) — look at the last 5 chars.
    if (len >= 6 && name[len - 5] == '.')
    {
        const char e0 = up(name[len - 4]);
        const char e1 = up(name[len - 3]);
        const char e2 = up(name[len - 2]);
        const char e3 = up(name[len - 1]);
        if (e0 == 'J' && e1 == 'P' && e2 == 'E' && e3 == 'G')
            return ImageFormat::Jpeg;
    }
    return ImageFormat::Unknown;
}

// Re-scan FAT32 root for *.BMP and *.TGA filenames into
// g_state.names. Caps at kMaxFiles. Preserves the current
// selection by name when possible; otherwise resets to 0.
void RescanRoot()
{
    namespace fat = fs::fat32;
    char prev_name[kNameCap];
    bool had_prev = false;
    if (g_state.index < g_state.count)
    {
        for (u32 i = 0; i < kNameCap; ++i)
        {
            prev_name[i] = g_state.names[g_state.index][i];
        }
        had_prev = (prev_name[0] != '\0');
    }

    g_state.count = 0;
    g_state.index = 0;

    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
        return;
    fat::DirEntry entries[fat::kMaxDirEntries];
    const u32 n = fat::Fat32ListDirByCluster(v, v->root_cluster, entries, fat::kMaxDirEntries);
    for (u32 i = 0; i < n && g_state.count < kMaxFiles; ++i)
    {
        if ((entries[i].attributes & 0x10) != 0)
            continue;
        if (ClassifyByName(entries[i].name) == ImageFormat::Unknown)
            continue;
        const char* src = entries[i].name;
        char* dst = g_state.names[g_state.count];
        u32 j = 0;
        for (; j + 1 < kNameCap && src[j] != '\0'; ++j)
        {
            dst[j] = src[j];
        }
        dst[j] = '\0';
        ++g_state.count;
    }

    if (had_prev)
    {
        for (u32 i = 0; i < g_state.count; ++i)
        {
            const char* a = g_state.names[i];
            bool match = true;
            for (u32 k = 0; k < kNameCap; ++k)
            {
                if (a[k] != prev_name[k])
                {
                    match = false;
                    break;
                }
                if (a[k] == '\0')
                    break;
            }
            if (match)
            {
                g_state.index = i;
                break;
            }
        }
    }
}

void FreePixels()
{
    if (g_state.pixels != nullptr)
    {
        mm::KFree(g_state.pixels);
        g_state.pixels = nullptr;
    }
    g_state.disp_w = 0;
    g_state.disp_h = 0;
    g_state.alloc_w = 0;
    g_state.alloc_h = 0;
}

// Streaming decode state. Fat32ReadFileStream delivers cluster-
// sized chunks; we accumulate bytes, parse the header out of the
// first 54, then nearest-neighbour-sample source rows into the
// destination thumbnail.
struct DecodeCtx
{
    BmpInfo info;
    u8 hdr[kBmpHeaderBytes];
    u32 hdr_have;
    u32 file_off;      // total bytes seen so far
    u32 src_pixel_off; // bytes still to skip before pixel data starts
    u32 src_row_bytes; // width * 4 (bpp == 32 only)
    u8* row_buf;       // scratch for one source row
    u32 row_have;      // bytes accumulated in row_buf
    u32 src_y;         // next source row index to be filled
    u32 dst_w;
    u32 dst_h;
    u32* dst;   // points into State::pixels
    bool fatal; // hard error mid-stream — abort the walker
};

bool ConsumeBytes(DecodeCtx* c, const u8* data, u64 len);

bool DecodeChunkCb(const u8* data, u64 len, void* ctx)
{
    DecodeCtx* c = static_cast<DecodeCtx*>(ctx);
    if (c->fatal)
        return false;
    return ConsumeBytes(c, data, len);
}

void EmitSourceRow(DecodeCtx* c)
{
    // Map source row src_y → destination row dst_y via NN.
    // src_y ranges over [0, info.height), but the dst pixel order
    // matches "screen-top-to-bottom". For a top-down BMP, src_y==0
    // is the top row, so dst_y = src_y * dst_h / src_h. For a
    // bottom-up BMP, src_y==0 is the BOTTOM row, so we flip:
    // dst_y = (src_h - 1 - src_y) * dst_h / src_h.
    const u32 src_h = c->info.height;
    const u32 src_w = c->info.width;
    if (src_h == 0 || src_w == 0)
        return;
    const u32 logical_src_y = c->info.top_down ? c->src_y : (src_h - 1 - c->src_y);
    const u32 dst_y = (logical_src_y * c->dst_h) / src_h;
    if (dst_y >= c->dst_h)
        return;
    u32* drow = c->dst + static_cast<u64>(dst_y) * c->dst_w;
    // Horizontal NN: for each dst x, sample src x = (dst_x * src_w / dst_w).
    // We may overwrite the dst row multiple times when several src
    // rows map to the same dst_y; the visual effect is "last src
    // row wins", which is acceptable for a v0 nearest-neighbour
    // path. Future slice could average instead.
    const u32 dst_w = c->dst_w;
    const u8* srow = c->row_buf;
    for (u32 dx = 0; dx < dst_w; ++dx)
    {
        const u32 sx = (dx * src_w) / dst_w;
        const u8* px = srow + static_cast<u64>(sx) * 4;
        // BMP stores BGRA; framebuffer is 0x00RRGGBB. Reorder.
        drow[dx] = static_cast<u32>(px[0]) | (static_cast<u32>(px[1]) << 8) | (static_cast<u32>(px[2]) << 16);
    }
}

bool ConsumeBytes(DecodeCtx* c, const u8* data, u64 len)
{
    u64 i = 0;
    // 1) Header bytes.
    while (i < len && c->hdr_have < kBmpHeaderBytes)
    {
        c->hdr[c->hdr_have++] = data[i++];
    }
    if (c->hdr_have == kBmpHeaderBytes && !c->info.ok)
    {
        c->info = ParseBmpHeader(c->hdr);
        if (!c->info.ok || c->info.bpp != 32 || c->info.compression != 0)
        {
            c->fatal = true;
            return false;
        }
        c->src_row_bytes = c->info.width * 4;
        if (c->info.pixel_offset > kBmpHeaderBytes)
        {
            c->src_pixel_off = c->info.pixel_offset - static_cast<u32>(kBmpHeaderBytes);
        }
        else
        {
            c->src_pixel_off = 0;
        }
    }
    if (!c->info.ok)
    {
        c->file_off += static_cast<u32>(len);
        return true; // not yet enough header bytes; keep streaming
    }

    // 2) Optional skip from end-of-canonical-header to pixel-array
    //    start (when the file uses BITMAPV4HEADER / V5HEADER and
    //    bf_off lands past the 54-byte mark).
    while (i < len && c->src_pixel_off > 0)
    {
        ++i;
        --c->src_pixel_off;
    }

    // 3) Pixel rows.
    while (i < len && c->src_y < c->info.height)
    {
        const u32 need = c->src_row_bytes - c->row_have;
        const u32 avail = static_cast<u32>(len - i);
        const u32 take = (avail < need) ? avail : need;
        for (u32 k = 0; k < take; ++k)
        {
            c->row_buf[c->row_have + k] = data[i + k];
        }
        c->row_have += take;
        i += take;
        if (c->row_have == c->src_row_bytes)
        {
            EmitSourceRow(c);
            c->row_have = 0;
            ++c->src_y;
        }
    }
    c->file_off += static_cast<u32>(len);
    return true;
}

// Find the right thumbnail size for a content rect (cw × ch).
// Preserves aspect ratio. Never upscales: a 4×4 image stays 4×4.
void FitThumbnail(u32 src_w, u32 src_h, u32 cw, u32 ch, u32* out_w, u32* out_h)
{
    if (src_w == 0 || src_h == 0 || cw == 0 || ch == 0)
    {
        *out_w = 0;
        *out_h = 0;
        return;
    }
    // No upscale: cap at source dimensions.
    u32 max_w = (cw < src_w) ? cw : src_w;
    u32 max_h = (ch < src_h) ? ch : src_h;
    // Aspect-fit. Find the larger of the two scale factors via
    // cross-multiplication: src_w * out_h vs src_h * out_w.
    // We want out_w / out_h == src_w / src_h, i.e. out_h = out_w * src_h / src_w.
    u32 w = max_w;
    u32 h = (static_cast<u64>(w) * src_h) / src_w;
    if (h == 0)
        h = 1;
    if (h > max_h)
    {
        h = max_h;
        w = (static_cast<u64>(h) * src_w) / src_h;
        if (w == 0)
            w = 1;
    }
    *out_w = w;
    *out_h = h;
}

// Allocate + bg-prefill the thumbnail; sets g_state.pixels et al
// on success. Returns true if the allocation succeeded; the
// caller must populate the pixels and set g_state.disp_w/h.
bool AllocThumbnail(u32 dst_w, u32 dst_h)
{
    if (dst_w == 0 || dst_h == 0)
        return false;
    const u64 dst_bytes = static_cast<u64>(dst_w) * dst_h * 4;
    void* dst_alloc = mm::KMalloc(dst_bytes);
    if (dst_alloc == nullptr)
        return false;
    u32* dst = static_cast<u32*>(dst_alloc);
    for (u64 k = 0; k < static_cast<u64>(dst_w) * dst_h; ++k)
    {
        dst[k] = kBg;
    }
    g_state.pixels = dst;
    g_state.alloc_w = dst_w;
    g_state.alloc_h = dst_h;
    return true;
}

// BMP decode path — uses the streaming Fat32ReadFileStream so a
// 3 MiB screenshot doesn't have to fit in kheap.
bool DecodeBmp(const fs::fat32::Volume* v, const fs::fat32::DirEntry* e, const char* name, u32 cw, u32 ch)
{
    namespace fat = fs::fat32;
    u8 hdr[kBmpHeaderBytes];
    const i64 got = fat::Fat32ReadAt(v, e, 0, hdr, kBmpHeaderBytes);
    if (got < static_cast<i64>(kBmpHeaderBytes))
    {
        StatusSet("read header FAILED");
        return false;
    }
    BmpInfo info = ParseBmpHeader(hdr);
    if (!info.ok)
    {
        StatusSet("not a valid BMP: ");
        StatusAppendStr(name);
        return false;
    }
    if (info.bpp != 32 || info.compression != 0)
    {
        StatusSet("unsupported BMP (");
        StatusAppendDec(info.bpp);
        StatusAppendStr("bpp comp=");
        StatusAppendDec(info.compression);
        StatusAppendStr("): ");
        StatusAppendStr(name);
        return false;
    }

    u32 dst_w = 0;
    u32 dst_h = 0;
    FitThumbnail(info.width, info.height, cw, ch, &dst_w, &dst_h);
    if (!AllocThumbnail(dst_w, dst_h))
    {
        StatusSet("out of kheap memory");
        return false;
    }
    const u64 row_bytes = duetos::util::SatMul(static_cast<u64>(info.width), static_cast<u64>(4));
    if (row_bytes == 0xFFFFFFFFFFFFFFFFull)
    {
        StatusSet("image dimensions overflow");
        FreePixels();
        return false;
    }
    void* row_alloc = mm::KMalloc(row_bytes);
    if (row_alloc == nullptr)
    {
        FreePixels();
        StatusSet("out of kheap memory");
        return false;
    }

    DecodeCtx ctx = {};
    ctx.row_buf = static_cast<u8*>(row_alloc);
    ctx.dst = g_state.pixels;
    ctx.dst_w = dst_w;
    ctx.dst_h = dst_h;
    const bool stream_ok = fat::Fat32ReadFileStream(v, e, DecodeChunkCb, &ctx);

    mm::KFree(row_alloc);

    if (!stream_ok || ctx.fatal)
    {
        FreePixels();
        StatusSet("decode FAILED: ");
        StatusAppendStr(name);
        return false;
    }

    g_state.disp_w = dst_w;
    g_state.disp_h = dst_h;
    StatusSet(name);
    StatusAppendStr("  ");
    StatusAppendDec(info.width);
    StatusAppendStr("x");
    StatusAppendDec(info.height);
    return true;
}

// Cap on a TGA full-file load. 4 MiB covers any sane wallpaper /
// icon (a 1024×1024 32-bpp uncompressed file is exactly 4 MiB +
// 18 header bytes). Larger files are rejected before allocation
// so a malformed header can't exhaust the kernel heap.
constexpr u32 kTgaMaxFileBytes = 4u * 1024u * 1024u + 4096u;

// TGA decode path — reads the entire file into a kheap buffer,
// parses, decodes into a temporary intermediate, and nearest-
// neighbour-downsamples into the thumbnail.
bool DecodeTga(const fs::fat32::Volume* v, const fs::fat32::DirEntry* e, const char* name, u32 cw, u32 ch)
{
    namespace fat = fs::fat32;
    if (e->size_bytes > kTgaMaxFileBytes)
    {
        StatusSet("TGA too large (>4 MiB): ");
        StatusAppendStr(name);
        return false;
    }
    if (e->size_bytes < duetos::util::kTgaHeaderBytes)
    {
        StatusSet("TGA truncated: ");
        StatusAppendStr(name);
        return false;
    }
    void* file_alloc = mm::KMalloc(e->size_bytes);
    if (file_alloc == nullptr)
    {
        StatusSet("out of kheap memory");
        return false;
    }
    u8* file_buf = static_cast<u8*>(file_alloc);
    const i64 read = fat::Fat32ReadFile(v, e, file_buf, e->size_bytes);
    if (read < static_cast<i64>(duetos::util::kTgaHeaderBytes))
    {
        mm::KFree(file_alloc);
        StatusSet("TGA read failed: ");
        StatusAppendStr(name);
        return false;
    }

    duetos::util::TgaInfo info = duetos::util::TgaParseHeader(file_buf);
    if (!info.ok)
    {
        mm::KFree(file_alloc);
        StatusSet("not a supported TGA: ");
        StatusAppendStr(name);
        return false;
    }

    // Allocate the intermediate full-resolution decode buffer.
    // Saturating multiply guards against a crafted TGA header
    // claiming u32-max dimensions; an overflow saturates to
    // UINT64_MAX which we reject before reaching KMalloc.
    const u64 pixel_count = duetos::util::SatMul(static_cast<u64>(info.width), static_cast<u64>(info.height));
    const u64 inter_bytes = duetos::util::SatMul(pixel_count, static_cast<u64>(4));
    if (inter_bytes == 0xFFFFFFFFFFFFFFFFull)
    {
        mm::KFree(file_alloc);
        StatusSet("TGA dimensions overflow: ");
        StatusAppendStr(name);
        return false;
    }
    void* inter_alloc = mm::KMalloc(inter_bytes);
    if (inter_alloc == nullptr)
    {
        mm::KFree(file_alloc);
        StatusSet("out of kheap memory");
        return false;
    }
    u32* inter = static_cast<u32*>(inter_alloc);
    const bool ok = duetos::util::TgaDecodeUncompressed(file_buf, static_cast<u32>(read), info, inter);
    mm::KFree(file_alloc);
    if (!ok)
    {
        mm::KFree(inter_alloc);
        StatusSet("TGA decode FAILED: ");
        StatusAppendStr(name);
        return false;
    }

    u32 dst_w = 0;
    u32 dst_h = 0;
    FitThumbnail(info.width, info.height, cw, ch, &dst_w, &dst_h);
    if (!AllocThumbnail(dst_w, dst_h))
    {
        mm::KFree(inter_alloc);
        StatusSet("out of kheap memory");
        return false;
    }

    // NN-downsample BGRA32 intermediate → RGB888 thumbnail. The
    // tga.cpp output already has B in low byte / R in high byte,
    // but the framebuffer wants 0x00RRGGBB, so we swap channels
    // here just like the BMP path's EmitSourceRow does.
    u32* dst = g_state.pixels;
    for (u32 dy = 0; dy < dst_h; ++dy)
    {
        const u32 sy = (dy * info.height) / dst_h;
        u32* drow = dst + static_cast<u64>(dy) * dst_w;
        const u32* srow = inter + static_cast<u64>(sy) * info.width;
        for (u32 dx = 0; dx < dst_w; ++dx)
        {
            const u32 sx = (dx * info.width) / dst_w;
            const u32 px = srow[sx];
            const u32 b = px & 0xFFu;
            const u32 g = (px >> 8) & 0xFFu;
            const u32 r = (px >> 16) & 0xFFu;
            drow[dx] = b | (g << 8) | (r << 16);
        }
    }

    mm::KFree(inter_alloc);

    g_state.disp_w = dst_w;
    g_state.disp_h = dst_h;
    StatusSet(name);
    StatusAppendStr("  ");
    StatusAppendDec(info.width);
    StatusAppendStr("x");
    StatusAppendDec(info.height);
    StatusAppendStr(" TGA");
    return true;
}

// PNG decode path — same full-file-load shape as TGA. Caps file
// size so a malformed IHDR can't make us allocate gigabytes; the
// scratch budget is the bigger constraint and is bounded by the
// filtered-scanline byte count derived from IHDR.
constexpr u32 kPngMaxFileBytes = 4u * 1024u * 1024u + 4096u;

bool DecodePng(const fs::fat32::Volume* v, const fs::fat32::DirEntry* e, const char* name, u32 cw, u32 ch)
{
    namespace fat = fs::fat32;
    if (e->size_bytes > kPngMaxFileBytes)
    {
        StatusSet("PNG too large (>4 MiB): ");
        StatusAppendStr(name);
        return false;
    }
    if (e->size_bytes < duetos::util::kPngSignatureBytes + 8 + 13 + 4)
    {
        StatusSet("PNG truncated: ");
        StatusAppendStr(name);
        return false;
    }
    void* file_alloc = mm::KMalloc(e->size_bytes);
    if (file_alloc == nullptr)
    {
        StatusSet("out of kheap memory");
        return false;
    }
    u8* file_buf = static_cast<u8*>(file_alloc);
    const i64 read = fat::Fat32ReadFile(v, e, file_buf, e->size_bytes);
    if (read < static_cast<i64>(duetos::util::kPngSignatureBytes + 8 + 13 + 4))
    {
        mm::KFree(file_alloc);
        StatusSet("PNG read failed: ");
        StatusAppendStr(name);
        return false;
    }

    duetos::util::PngInfo info = duetos::util::PngParseHeader(file_buf, static_cast<u32>(read));
    if (!info.ok)
    {
        mm::KFree(file_alloc);
        StatusSet("not a supported PNG (need 8-bit RGB/RGBA, non-interlaced): ");
        StatusAppendStr(name);
        return false;
    }

    // PngDecode wants scratch large enough for IDAT-bytes +
    // (width*4 + 1) * height filtered scanlines. file_buf already
    // holds the IDAT; we add the filtered-rows bound. Use
    // SatMul/SatAdd so a crafted PNG IHDR claiming u32-max
    // dimensions saturates instead of wrapping into a tiny
    // KMalloc that PngDecode then overruns.
    const u64 w64 = static_cast<u64>(info.width);
    const u64 h64 = static_cast<u64>(info.height);
    const u64 row_bytes = duetos::util::SatAdd(duetos::util::SatMul(w64, static_cast<u64>(4)), static_cast<u64>(1));
    const u64 filtered_bytes = duetos::util::SatMul(row_bytes, h64);
    const u64 scratch_bytes = duetos::util::SatAdd(filtered_bytes, static_cast<u64>(read));
    const u64 inter_bytes = duetos::util::SatMul(duetos::util::SatMul(w64, h64), static_cast<u64>(4));
    if (scratch_bytes == 0xFFFFFFFFFFFFFFFFull || inter_bytes == 0xFFFFFFFFFFFFFFFFull)
    {
        mm::KFree(file_alloc);
        StatusSet("PNG dimensions overflow: ");
        StatusAppendStr(name);
        return false;
    }
    void* scratch_alloc = mm::KMalloc(scratch_bytes);
    void* inter_alloc = mm::KMalloc(inter_bytes);
    if (scratch_alloc == nullptr || inter_alloc == nullptr)
    {
        mm::KFree(file_alloc);
        if (scratch_alloc)
            mm::KFree(scratch_alloc);
        if (inter_alloc)
            mm::KFree(inter_alloc);
        StatusSet("out of kheap memory");
        return false;
    }
    u32* inter = static_cast<u32*>(inter_alloc);
    const bool ok = duetos::util::PngDecode(file_buf, static_cast<u32>(read), info, static_cast<u8*>(scratch_alloc),
                                            static_cast<u32>(scratch_bytes), inter);
    mm::KFree(scratch_alloc);
    mm::KFree(file_alloc);
    if (!ok)
    {
        mm::KFree(inter_alloc);
        StatusSet("PNG decode FAILED: ");
        StatusAppendStr(name);
        return false;
    }

    u32 dst_w = 0;
    u32 dst_h = 0;
    FitThumbnail(info.width, info.height, cw, ch, &dst_w, &dst_h);
    if (!AllocThumbnail(dst_w, dst_h))
    {
        mm::KFree(inter_alloc);
        StatusSet("out of kheap memory");
        return false;
    }

    // Same NN-downsample + BGRA→0x00RRGGBB swap as the TGA path.
    u32* dst = g_state.pixels;
    for (u32 dy = 0; dy < dst_h; ++dy)
    {
        const u32 sy = (dy * info.height) / dst_h;
        u32* drow = dst + static_cast<u64>(dy) * dst_w;
        const u32* srow = inter + static_cast<u64>(sy) * info.width;
        for (u32 dx = 0; dx < dst_w; ++dx)
        {
            const u32 sx = (dx * info.width) / dst_w;
            const u32 px = srow[sx];
            const u32 b = px & 0xFFu;
            const u32 g = (px >> 8) & 0xFFu;
            const u32 r = (px >> 16) & 0xFFu;
            drow[dx] = b | (g << 8) | (r << 16);
        }
    }

    mm::KFree(inter_alloc);

    g_state.disp_w = dst_w;
    g_state.disp_h = dst_h;
    StatusSet(name);
    StatusAppendStr("  ");
    StatusAppendDec(info.width);
    StatusAppendStr("x");
    StatusAppendDec(info.height);
    StatusAppendStr(" PNG");
    return true;
}

// JPEG decode path. Same full-file-load shape as PNG/TGA, with
// caps that bound both the file read and the decoder scratch.
constexpr u32 kJpegMaxFileBytes = 4u * 1024u * 1024u;

bool DecodeJpeg(const fs::fat32::Volume* v, const fs::fat32::DirEntry* e, const char* name, u32 cw, u32 ch)
{
    namespace fat = fs::fat32;
    if (e->size_bytes > kJpegMaxFileBytes)
    {
        StatusSet("JPEG too large (>4 MiB): ");
        StatusAppendStr(name);
        return false;
    }
    if (e->size_bytes < 4)
    {
        StatusSet("JPEG truncated: ");
        StatusAppendStr(name);
        return false;
    }
    void* file_alloc = mm::KMalloc(e->size_bytes);
    if (file_alloc == nullptr)
    {
        StatusSet("out of kheap memory");
        return false;
    }
    u8* file_buf = static_cast<u8*>(file_alloc);
    const i64 read = fat::Fat32ReadFile(v, e, file_buf, e->size_bytes);
    if (read < 4)
    {
        mm::KFree(file_alloc);
        StatusSet("JPEG read failed: ");
        StatusAppendStr(name);
        return false;
    }

    duetos::util::JpegInfo info = duetos::util::JpegParseHeader(file_buf, static_cast<u32>(read));
    if (!info.ok || info.precision != 8 || info.components > 3)
    {
        mm::KFree(file_alloc);
        StatusSet("unsupported JPEG (need 8-bit Baseline, <=3 components): ");
        StatusAppendStr(name);
        return false;
    }

    const u64 scratch_bytes = duetos::util::JpegEstimateScratch(info);
    const u64 inter_bytes = duetos::util::SatMul(
        duetos::util::SatMul(static_cast<u64>(info.width), static_cast<u64>(info.height)), static_cast<u64>(4));
    if (scratch_bytes == 0 || inter_bytes == 0xFFFFFFFFFFFFFFFFull)
    {
        mm::KFree(file_alloc);
        StatusSet("JPEG dimensions overflow: ");
        StatusAppendStr(name);
        return false;
    }
    void* scratch_alloc = mm::KMalloc(scratch_bytes);
    void* inter_alloc = mm::KMalloc(inter_bytes);
    if (scratch_alloc == nullptr || inter_alloc == nullptr)
    {
        mm::KFree(scratch_alloc);
        mm::KFree(inter_alloc);
        mm::KFree(file_alloc);
        StatusSet("out of kheap memory (JPEG): ");
        StatusAppendStr(name);
        return false;
    }
    const u64 n = duetos::util::JpegDecode(file_buf, static_cast<u32>(read), info, static_cast<u8*>(scratch_alloc),
                                           scratch_bytes, static_cast<u32*>(inter_alloc));
    mm::KFree(scratch_alloc);
    mm::KFree(file_alloc);
    if (n == 0)
    {
        mm::KFree(inter_alloc);
        StatusSet("JPEG decode failed: ");
        StatusAppendStr(name);
        return false;
    }

    // Fit-to-window NN downsample, matching the PNG path. The
    // decoder already wrote 0xFF000000 | (R<<16) | (G<<8) | B so
    // no channel swap is needed here.
    const u32 dst_w = (info.width <= cw) ? info.width : cw;
    const u32 dst_h = (info.height <= ch) ? info.height : ch;
    const u32* inter = static_cast<const u32*>(inter_alloc);
    u32* dst = g_state.pixels;
    for (u32 dy = 0; dy < dst_h; ++dy)
    {
        const u32 sy = (dy * info.height) / dst_h;
        u32* drow = dst + static_cast<u64>(dy) * dst_w;
        const u32* srow = inter + static_cast<u64>(sy) * info.width;
        for (u32 dx = 0; dx < dst_w; ++dx)
        {
            const u32 sx = (dx * info.width) / dst_w;
            drow[dx] = srow[sx] & 0x00FFFFFFu;
        }
    }
    mm::KFree(inter_alloc);

    g_state.disp_w = dst_w;
    g_state.disp_h = dst_h;
    StatusSet(name);
    StatusAppendStr("  ");
    StatusAppendDec(info.width);
    StatusAppendStr("x");
    StatusAppendDec(info.height);
    StatusAppendStr(" JPEG");
    return true;
}

// Decode the currently-selected file into g_state.pixels at the
// largest size that fits a (cw, ch) content rect. Returns true on
// success; on failure clears pixels and writes a status line.
bool DecodeCurrent(u32 cw, u32 ch)
{
    namespace fat = fs::fat32;
    FreePixels();
    StatusSet("");
    if (g_state.count == 0)
    {
        StatusSet("(no .BMP/.TGA/.PNG/.JPG files in root)");
        return false;
    }
    if (g_state.index >= g_state.count)
    {
        g_state.index = 0;
    }
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
    {
        StatusSet("(no FAT32 volume)");
        return false;
    }
    const char* name = g_state.names[g_state.index];
    fat::DirEntry e;
    if (!fat::Fat32LookupPath(v, name, &e))
    {
        StatusSet("lookup FAILED: ");
        StatusAppendStr(name);
        return false;
    }
    switch (ClassifyByName(name))
    {
    case ImageFormat::Bmp:
        return DecodeBmp(v, &e, name, cw, ch);
    case ImageFormat::Tga:
        return DecodeTga(v, &e, name, cw, ch);
    case ImageFormat::Png:
        return DecodePng(v, &e, name, cw, ch);
    case ImageFormat::Jpeg:
        return DecodeJpeg(v, &e, name, cw, ch);
    case ImageFormat::Unknown:
    default:
        StatusSet("unsupported extension: ");
        StatusAppendStr(name);
        return false;
    }
}

void DrawFn(u32 cx, u32 cy, u32 cw, u32 ch, void* /*cookie*/)
{
    FramebufferFillRect(cx, cy, cw, ch, kBg);

    // Reserve two text rows at the top for status / position.
    const u32 reserved = kRowH * kHeaderRows + 2;
    const u32 img_x = cx;
    const u32 img_y = cy + reserved;
    const u32 img_w = cw;
    const u32 img_h = (ch > reserved) ? (ch - reserved) : 0;

    // Lazy decode: re-decode iff requested AND the image area is
    // big enough to justify allocating a thumbnail. This runs on
    // the compositor tick (we hold the compositor lock indirectly
    // via WindowDrawAllOrdered).
    if (g_state.needs_decode)
    {
        DecodeCurrent(img_w, img_h);
        g_state.needs_decode = false;
    }

    // Header row 1: "[i/N]  filename WxH" via status string.
    char header[64];
    u32 h_off = 0;
    header[h_off++] = '[';
    {
        u32 v = (g_state.count == 0) ? 0 : (g_state.index + 1);
        char tmp[8];
        u32 n = 0;
        if (v == 0)
            tmp[n++] = '0';
        while (v > 0 && n < sizeof(tmp))
        {
            tmp[n++] = static_cast<char>('0' + (v % 10));
            v /= 10;
        }
        while (n > 0 && h_off + 1 < sizeof(header))
            header[h_off++] = tmp[--n];
    }
    if (h_off + 1 < sizeof(header))
        header[h_off++] = '/';
    {
        u32 v = g_state.count;
        char tmp[8];
        u32 n = 0;
        if (v == 0)
            tmp[n++] = '0';
        while (v > 0 && n < sizeof(tmp))
        {
            tmp[n++] = static_cast<char>('0' + (v % 10));
            v /= 10;
        }
        while (n > 0 && h_off + 1 < sizeof(header))
            header[h_off++] = tmp[--n];
    }
    if (h_off + 1 < sizeof(header))
        header[h_off++] = ']';
    header[h_off] = '\0';
    FramebufferDrawString(cx + 4, cy + 1, header, kInkDim, kBg);

    // Status line 2: filename and dimensions, or error.
    const u32 is_err = (g_state.pixels == nullptr) ? 1u : 0u;
    FramebufferDrawString(cx + 4, cy + 1 + kRowH, g_state.status, is_err ? kInkErr : kInkFg, kBg);

    // Image area. At zoom == 100% we use the direct FramebufferBlit
    // path (matches v0 byte-for-byte — the thumbnail is already
    // sized to fit the content rect, no upscaling). At any other
    // zoom we walk destination pixels and nearest-neighbour-sample
    // the decoded buffer; pan_x/pan_y shifts the scaled image's
    // top-left inside the content rect. The blit buffer is never
    // re-decoded for zoom — only the per-frame walk grows / shrinks.
    if (g_state.pixels != nullptr && img_w > 0 && img_h > 0)
    {
        if (g_state.zoom_percent == kZoomFit)
        {
            // Fast path: centred fit-blit, identical to v0.
            const u32 ox = (img_w > g_state.disp_w) ? (img_w - g_state.disp_w) / 2 : 0;
            const u32 oy = (img_h > g_state.disp_h) ? (img_h - g_state.disp_h) / 2 : 0;
            FramebufferBlit(img_x + ox, img_y + oy, g_state.pixels, g_state.disp_w, g_state.disp_h, g_state.disp_w);
        }
        else
        {
            // Scaled path. Compute the painted image's pixel size,
            // then for each destination pixel inside the content
            // rect that the (scaled, panned) image covers, sample
            // the decoded buffer via NN.
            const u64 z = static_cast<u64>(g_state.zoom_percent);
            const u32 painted_w = static_cast<u32>((static_cast<u64>(g_state.disp_w) * z) / 100);
            const u32 painted_h = static_cast<u32>((static_cast<u64>(g_state.disp_h) * z) / 100);
            if (painted_w > 0 && painted_h > 0)
            {
                // Centring offset when the painted image is smaller
                // than the content rect (small image, modest zoom);
                // pan adds on top. When the painted image is larger
                // than the rect, the centring offset is 0 and pan
                // moves which slice of the image is visible.
                const i32 base_ox = (img_w > painted_w) ? static_cast<i32>((img_w - painted_w) / 2) : 0;
                const i32 base_oy = (img_h > painted_h) ? static_cast<i32>((img_h - painted_h) / 2) : 0;
                const i32 origin_x = base_ox + g_state.pan_x;
                const i32 origin_y = base_oy + g_state.pan_y;
                // Iterate the dst pixels that intersect the content
                // rect. NN sample dst (dx, dy) → src (dx * disp_w /
                // painted_w, dy * disp_h / painted_h).
                for (u32 dy = 0; dy < painted_h; ++dy)
                {
                    const i32 sy_dst = origin_y + static_cast<i32>(dy);
                    if (sy_dst < 0 || sy_dst >= static_cast<i32>(img_h))
                        continue;
                    const u32 sy = (static_cast<u64>(dy) * g_state.disp_h) / painted_h;
                    const u32* srow = g_state.pixels + static_cast<u64>(sy) * g_state.disp_w;
                    for (u32 dx = 0; dx < painted_w; ++dx)
                    {
                        const i32 sx_dst = origin_x + static_cast<i32>(dx);
                        if (sx_dst < 0 || sx_dst >= static_cast<i32>(img_w))
                            continue;
                        const u32 sx = (static_cast<u64>(dx) * g_state.disp_w) / painted_w;
                        FramebufferPutPixel(img_x + static_cast<u32>(sx_dst), img_y + static_cast<u32>(sy_dst),
                                            srow[sx]);
                    }
                }
            }
        }
    }
    else if (img_w > 0 && img_h > 0 && g_state.count == 0)
    {
        // Soft hint when the root has no BMPs yet — guides users to
        // the screenshot chord rather than leaving a blank panel.
        FramebufferDrawString(cx + 4, img_y + 4, "Press Ctrl+Alt+P to take a screenshot,", kInkDim, kBg);
        FramebufferDrawString(cx + 4, img_y + 4 + kRowH, "then 'r' here to rescan.", kInkDim, kBg);
    }

    // Footer hint.
    if (ch > kRowH + 2)
    {
        FramebufferDrawString(cx + 4, cy + ch - kRowH - 1, "N:NEXT  P:PREV  R:RESCAN  +/-:ZOOM  0:RESET  ARROWS:PAN",
                              kInkDim, kBg);
    }
}

// Reset the zoom/pan triple to fit-to-window. Called whenever the
// user switches images, rescans, or hits '0' explicitly — anything
// where carrying the previous image's zoom into the new one would
// be surprising (a 4×4 icon at 400% zoom would render as a 16×16
// smear after switching to a 1024×768 screenshot).
void ZoomReset()
{
    g_state.zoom_percent = kZoomFit;
    g_state.pan_x = 0;
    g_state.pan_y = 0;
}

void StepIndex(bool forward)
{
    if (g_state.count == 0)
        return;
    if (forward)
    {
        g_state.index = (g_state.index + 1) % g_state.count;
    }
    else
    {
        g_state.index = (g_state.index == 0) ? (g_state.count - 1) : (g_state.index - 1);
    }
    g_state.needs_decode = true;
    ZoomReset();
}

// Apply a signed delta to zoom_percent, clamping to [kZoomMin,
// kZoomMax]. Returns true if zoom actually changed. Used by the
// Ctrl+wheel path and the '+'/'-' keys so the clamp + recentre
// behaviour is identical between input sources.
bool ApplyZoomDelta(duetos::i32 delta_pct)
{
    const duetos::i32 cur = static_cast<duetos::i32>(g_state.zoom_percent);
    duetos::i32 next = cur + delta_pct;
    if (next < static_cast<duetos::i32>(kZoomMin))
        next = static_cast<duetos::i32>(kZoomMin);
    if (next > static_cast<duetos::i32>(kZoomMax))
        next = static_cast<duetos::i32>(kZoomMax);
    if (next == cur)
        return false;
    g_state.zoom_percent = static_cast<duetos::u32>(next);
    // When zoom drops back to fit (or below it visually — the
    // painted image will fit the rect again), pan offsets no
    // longer have anywhere to push to. Recentre so a user who
    // panned at high zoom doesn't end up with the image shoved
    // off-screen after zooming back out.
    if (g_state.zoom_percent <= kZoomFit)
    {
        g_state.pan_x = 0;
        g_state.pan_y = 0;
    }
    return true;
}

} // namespace

void ImageViewInit(WindowHandle handle)
{
    g_state.handle = handle;
    g_state.count = 0;
    g_state.index = 0;
    g_state.pixels = nullptr;
    g_state.disp_w = 0;
    g_state.disp_h = 0;
    g_state.status[0] = '\0';
    g_state.needs_decode = true;
    g_state.zoom_percent = kZoomFit;
    g_state.pan_x = 0;
    g_state.pan_y = 0;
    RescanRoot();
    WindowSetContentDraw(handle, DrawFn, nullptr);
    duetos::drivers::video::WindowSetWheelHandler(handle, ImageViewOnWheel);
    // Drop target — accept FileEntry payloads. Loads BMP / PNG /
    // TGA via the same path the Files-app double-click uses.
    duetos::drivers::video::DndRegisterDropTarget(
        handle,
        [](const duetos::drivers::video::DndPayload& p, u32 /*cx*/, u32 /*cy*/) -> bool
        {
            if (p.kind != duetos::drivers::video::DndKind::FileEntry)
                return false;
            if (ImageViewSelectByName(p.text))
            {
                duetos::drivers::video::WindowRaise(g_state.handle);
                duetos::drivers::video::NotifyShow("loaded in image viewer");
                return true;
            }
            duetos::drivers::video::NotifyShowKind("imageview: load failed", duetos::drivers::video::NotifyKind::Error);
            return false;
        },
        1u << static_cast<u32>(duetos::drivers::video::DndKind::FileEntry));
}

void ImageViewOnWheel(duetos::i32 dz, duetos::u8 modifiers)
{
    if (dz == 0)
        return;
    using duetos::drivers::input::kKeyModCtrl;
    if ((modifiers & kKeyModCtrl) != 0)
    {
        // Ctrl+wheel — zoom the image without touching window
        // geometry. Each wheel tick moves zoom_percent by one
        // kZoomStepPct grain; clamping happens inside
        // ApplyZoomDelta. The decoded thumbnail buffer is left
        // alone; DrawFn rescales it on the next compose tick.
        const duetos::i32 steps = (dz > 0) ? dz : -dz;
        const duetos::i32 sign = (dz > 0) ? 1 : -1;
        ApplyZoomDelta(sign * static_cast<duetos::i32>(kZoomStepPct) * steps);
        return;
    }
    // Plain wheel — step image. Wheel down advances; wheel up
    // steps back.
    const bool forward = (dz < 0);
    const duetos::i32 steps = (dz > 0) ? dz : -dz;
    for (duetos::i32 i = 0; i < steps; ++i)
    {
        StepIndex(forward);
    }
}

WindowHandle ImageViewWindow()
{
    return g_state.handle;
}

bool ImageViewFeedChar(char c)
{
    if (c == 'n' || c == 'N')
    {
        StepIndex(true);
        return true;
    }
    if (c == 'p' || c == 'P')
    {
        StepIndex(false);
        return true;
    }
    if (c == 'r' || c == 'R')
    {
        RescanRoot();
        g_state.needs_decode = true;
        ZoomReset();
        drivers::video::NotifyShow("image: root rescan");
        return true;
    }
    if (c == '+' || c == '=' || c == '-' || c == '_')
    {
        // Keyboard zoom: '+' / '=' enlarges, '-' / '_' shrinks.
        // Mirrors the Ctrl+wheel grain (kZoomStepPct) and the
        // same clamp; window geometry is left alone — only
        // zoom_percent changes, and DrawFn rescales the
        // existing decoded buffer at the new factor.
        const duetos::i32 sign = (c == '+' || c == '=') ? 1 : -1;
        ApplyZoomDelta(sign * static_cast<duetos::i32>(kZoomStepPct));
        return true;
    }
    if (c == '0')
    {
        // Reset zoom + pan to fit-to-window. No re-decode is
        // needed — the thumbnail buffer is already sized for
        // the content rect; DrawFn picks the fast Blit path on
        // the next compose tick because zoom_percent ==
        // kZoomFit.
        ZoomReset();
        return true;
    }
    return false;
}

bool ImageViewFeedArrow(duetos::u16 keycode)
{
    using duetos::drivers::input::kKeyArrowDown;
    using duetos::drivers::input::kKeyArrowLeft;
    using duetos::drivers::input::kKeyArrowRight;
    using duetos::drivers::input::kKeyArrowUp;
    // When the user has zoomed past fit-to-window, arrows pan
    // the visible slice. At fit-to-window there's nothing to
    // pan; Left/Right fall back to prev/next image (preserving
    // the v0 behaviour) and Up/Down become no-ops (they had no
    // meaning at fit anyway).
    if (g_state.zoom_percent > kZoomFit)
    {
        switch (keycode)
        {
        case kKeyArrowLeft:
            g_state.pan_x += kPanStepPx;
            return true;
        case kKeyArrowRight:
            g_state.pan_x -= kPanStepPx;
            return true;
        case kKeyArrowUp:
            g_state.pan_y += kPanStepPx;
            return true;
        case kKeyArrowDown:
            g_state.pan_y -= kPanStepPx;
            return true;
        default:
            return false;
        }
    }
    if (keycode == kKeyArrowLeft || keycode == kKeyArrowRight)
    {
        if (g_state.count == 0)
            return false;
        StepIndex(keycode == kKeyArrowRight);
        return true;
    }
    return false;
}

bool ImageViewSelectByName(const char* name)
{
    if (name == nullptr || name[0] == '\0')
        return false;
    RescanRoot();
    auto up = [](char c) { return (c >= 'a' && c <= 'z') ? static_cast<char>(c - ('a' - 'A')) : c; };
    for (u32 i = 0; i < g_state.count; ++i)
    {
        const char* a = g_state.names[i];
        u32 k = 0;
        for (; a[k] != '\0' && name[k] != '\0'; ++k)
        {
            if (up(a[k]) != up(name[k]))
                break;
        }
        if (a[k] == '\0' && name[k] == '\0')
        {
            g_state.index = i;
            g_state.needs_decode = true;
            ZoomReset();
            return true;
        }
    }
    return false;
}

void ImageViewSelfTest()
{
    using arch::SerialWrite;

    // Build a synthetic 4×4 32-bpp top-down BMP in memory using the
    // exact byte layout the Screenshot app emits, then parse via
    // ParseBmpHeader. This is a pure-compute round-trip — no FAT32
    // read, no kheap allocation — so it runs unconditionally at
    // boot.
    constexpr u32 kW = 4;
    constexpr u32 kH = 4;
    constexpr u32 kPixels = kW * kH * 4;
    u8 buf[kBmpHeaderBytes + kPixels];
    // BITMAPFILEHEADER
    buf[0] = 'B';
    buf[1] = 'M';
    {
        const u32 fsz = static_cast<u32>(kBmpHeaderBytes) + kPixels;
        buf[2] = static_cast<u8>(fsz);
        buf[3] = static_cast<u8>(fsz >> 8);
        buf[4] = static_cast<u8>(fsz >> 16);
        buf[5] = static_cast<u8>(fsz >> 24);
    }
    buf[6] = buf[7] = buf[8] = buf[9] = 0; // reserved
    buf[10] = static_cast<u8>(kBmpHeaderBytes);
    buf[11] = buf[12] = buf[13] = 0;
    // BITMAPINFOHEADER (40 bytes)
    buf[14] = 40;
    buf[15] = buf[16] = buf[17] = 0;
    buf[18] = kW;
    buf[19] = buf[20] = buf[21] = 0;
    {
        const i32 neg_h = -static_cast<i32>(kH);
        const u32 raw = static_cast<u32>(neg_h);
        buf[22] = static_cast<u8>(raw);
        buf[23] = static_cast<u8>(raw >> 8);
        buf[24] = static_cast<u8>(raw >> 16);
        buf[25] = static_cast<u8>(raw >> 24);
    }
    buf[26] = 1; // planes
    buf[27] = 0;
    buf[28] = 32; // bpp
    buf[29] = 0;
    for (u32 k = 30; k < kBmpHeaderBytes; ++k)
        buf[k] = 0;

    BmpInfo info = ParseBmpHeader(buf);
    bool pass =
        info.ok && info.width == kW && info.height == kH && info.bpp == 32 && info.compression == 0 && info.top_down;
    // Negative case: swap the magic bytes.
    buf[0] = 'X';
    BmpInfo bad = ParseBmpHeader(buf);
    if (bad.ok)
        pass = false;
    buf[0] = 'B';
    // Negative case: 24bpp claim should still parse `ok` (header is
    // structurally fine) but we'd later reject for unsupported.
    buf[28] = 24;
    BmpInfo unsupported = ParseBmpHeader(buf);
    if (!unsupported.ok || unsupported.bpp != 24)
        pass = false;
    buf[28] = 32;

    // Bottom-up sign flip.
    buf[22] = static_cast<u8>(kH);
    buf[23] = buf[24] = buf[25] = 0;
    BmpInfo bottom_up = ParseBmpHeader(buf);
    if (!bottom_up.ok || bottom_up.top_down || bottom_up.height != kH)
        pass = false;

    // Aspect-fit math sanity: 1024×768 into a 320×240 rect should
    // produce an image with the same 4:3 ratio (within integer
    // truncation of one row). 320 / 1024 = 5/16, so width=320,
    // height = 768 * 320 / 1024 = 240 — exact.
    u32 fw = 0;
    u32 fh = 0;
    FitThumbnail(1024, 768, 320, 240, &fw, &fh);
    if (fw != 320 || fh != 240)
        pass = false;

    // No-upscale: 4×4 source into a 320×240 rect stays 4×4.
    FitThumbnail(4, 4, 320, 240, &fw, &fh);
    if (fw != 4 || fh != 4)
        pass = false;

    SerialWrite(pass ? "[image] self-test OK (BMP header round-trip + aspect-fit math)\n"
                     : "[image] self-test FAILED\n");
}

const char* ImageViewCurrentName()
{
    if (g_state.count == 0 || g_state.index >= g_state.count)
    {
        return "";
    }
    return g_state.names[g_state.index];
}

} // namespace duetos::apps::imageview
