#include "apps/imageview.h"

#include "arch/x86_64/serial.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/notify.h"
#include "fs/fat32.h"
#include "mm/kheap.h"

namespace duetos::apps::imageview
{

namespace
{

using duetos::drivers::video::FramebufferBlit;
using duetos::drivers::video::FramebufferDrawString;
using duetos::drivers::video::FramebufferFillRect;
using duetos::drivers::video::kWindowInvalid;
using duetos::drivers::video::WindowContentFn;
using duetos::drivers::video::WindowHandle;
using duetos::drivers::video::WindowSetContentDraw;

constexpr u32 kMaxFiles = 64; // ~64 BMPs in the root tracked at once
constexpr u32 kNameCap = 16;  // 8.3 = 12 chars + NUL, with slack
constexpr u32 kStatusCap = 96;
constexpr u32 kRowH = 10;      // 8x8 glyph + 2 px padding
constexpr u32 kHeaderRows = 2; // status line + filename / pos line

// BMP-format constants (BITMAPFILEHEADER + BITMAPINFOHEADER).
constexpr u64 kBmpFileHeaderBytes = 14;
constexpr u64 kBmpInfoHeaderBytes = 40;
constexpr u64 kBmpHeaderBytes = kBmpFileHeaderBytes + kBmpInfoHeaderBytes;

constexpr u32 kInkFg = 0x00D0D8E0;
constexpr u32 kInkDim = 0x00808890;
constexpr u32 kInkErr = 0x00E08070;
constexpr u32 kBg = 0x00080A0E;

inline u16 LoadU16(const u8* p)
{
    return static_cast<u16>(static_cast<u16>(p[0]) | (static_cast<u16>(p[1]) << 8));
}

inline u32 LoadU32(const u8* p)
{
    return static_cast<u32>(p[0]) | (static_cast<u32>(p[1]) << 8) | (static_cast<u32>(p[2]) << 16) |
           (static_cast<u32>(p[3]) << 24);
}

// Result of parsing the 54-byte BMP header. Negative `signed_height`
// signals a top-down DIB; we flip the sign before storing
// `height` and remember the orientation in `top_down`.
struct BmpInfo
{
    u32 width;
    u32 height;
    u32 bpp;          // bits per pixel (we accept 32; reject others)
    u32 compression;  // 0 = BI_RGB, anything else rejected
    u32 pixel_offset; // byte offset of the pixel array (from BITMAPFILEHEADER's bf_off)
    bool top_down;    // true when DIB height was negative
    bool ok;
};

// Parse the 54-byte canonical BMP header. Tolerant: accepts any
// BITMAPINFOHEADER size >= 40 (the additional fields just shift
// the pixel offset, which we read directly from bf_off).
BmpInfo ParseBmpHeader(const u8* hdr)
{
    BmpInfo info = {};
    if (hdr[0] != 'B' || hdr[1] != 'M')
    {
        return info;
    }
    info.pixel_offset = LoadU32(hdr + 10);
    const u32 dib_size = LoadU32(hdr + 14);
    if (dib_size < 40)
    {
        return info;
    }
    info.width = LoadU32(hdr + 18);
    const i32 signed_height = static_cast<i32>(LoadU32(hdr + 22));
    if (signed_height < 0)
    {
        info.height = static_cast<u32>(-signed_height);
        info.top_down = true;
    }
    else
    {
        info.height = static_cast<u32>(signed_height);
        info.top_down = false;
    }
    info.bpp = LoadU16(hdr + 28);
    info.compression = LoadU32(hdr + 30);
    // Sanity bounds: a 4 GiB-pixel image is hostile / corrupt.
    constexpr u32 kMaxDim = 16384;
    if (info.width == 0 || info.height == 0 || info.width > kMaxDim || info.height > kMaxDim)
    {
        return info;
    }
    info.ok = true;
    return info;
}

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
};

constinit State g_state = {kWindowInvalid, {}, 0, 0, nullptr, 0, 0, 0, 0, {}, false};

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

bool EndsWithBmpCi(const char* name)
{
    u32 len = 0;
    while (name[len] != '\0' && len < kNameCap)
        ++len;
    if (len < 5)
        return false;
    auto up = [](char c) { return (c >= 'a' && c <= 'z') ? static_cast<char>(c - ('a' - 'A')) : c; };
    return name[len - 4] == '.' && up(name[len - 3]) == 'B' && up(name[len - 2]) == 'M' && up(name[len - 1]) == 'P';
}

// Re-scan FAT32 root for *.BMP filenames into g_state.names. Caps
// at kMaxFiles. Preserves the current selection by name when
// possible; otherwise resets to 0.
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
        if (!EndsWithBmpCi(entries[i].name))
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
        StatusSet("(no .BMP files in root)");
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

    // Quick header pre-flight via Fat32ReadAt so we don't allocate
    // a thumbnail for an unsupported subformat.
    u8 hdr[kBmpHeaderBytes];
    const i64 got = fat::Fat32ReadAt(v, &e, 0, hdr, kBmpHeaderBytes);
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

    // Thumbnail target.
    u32 dst_w = 0;
    u32 dst_h = 0;
    FitThumbnail(info.width, info.height, cw, ch, &dst_w, &dst_h);
    if (dst_w == 0 || dst_h == 0)
    {
        StatusSet("content area too small for thumbnail");
        return false;
    }
    const u64 dst_bytes = static_cast<u64>(dst_w) * dst_h * 4;
    const u64 row_bytes = static_cast<u64>(info.width) * 4;
    void* dst_alloc = mm::KMalloc(dst_bytes);
    void* row_alloc = mm::KMalloc(row_bytes);
    if (dst_alloc == nullptr || row_alloc == nullptr)
    {
        if (dst_alloc != nullptr)
            mm::KFree(dst_alloc);
        if (row_alloc != nullptr)
            mm::KFree(row_alloc);
        StatusSet("out of kheap memory");
        return false;
    }
    // Pre-fill thumbnail with bg colour so any unrendered pixels
    // (e.g. truncated file) show as the panel ground rather than
    // garbage from a freshly-allocated chunk.
    u32* dst = static_cast<u32*>(dst_alloc);
    for (u64 k = 0; k < static_cast<u64>(dst_w) * dst_h; ++k)
    {
        dst[k] = kBg;
    }

    DecodeCtx ctx = {};
    ctx.row_buf = static_cast<u8*>(row_alloc);
    ctx.dst = dst;
    ctx.dst_w = dst_w;
    ctx.dst_h = dst_h;
    const bool stream_ok = fat::Fat32ReadFileStream(v, &e, DecodeChunkCb, &ctx);

    mm::KFree(row_alloc);

    if (!stream_ok || ctx.fatal)
    {
        mm::KFree(dst_alloc);
        StatusSet("decode FAILED: ");
        StatusAppendStr(name);
        return false;
    }

    g_state.pixels = dst;
    g_state.disp_w = dst_w;
    g_state.disp_h = dst_h;
    g_state.alloc_w = dst_w;
    g_state.alloc_h = dst_h;
    StatusSet(name);
    StatusAppendStr("  ");
    StatusAppendDec(info.width);
    StatusAppendStr("x");
    StatusAppendDec(info.height);
    return true;
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

    // Image area.
    if (g_state.pixels != nullptr && img_w > 0 && img_h > 0)
    {
        const u32 ox = (img_w > g_state.disp_w) ? (img_w - g_state.disp_w) / 2 : 0;
        const u32 oy = (img_h > g_state.disp_h) ? (img_h - g_state.disp_h) / 2 : 0;
        FramebufferBlit(img_x + ox, img_y + oy, g_state.pixels, g_state.disp_w, g_state.disp_h, g_state.disp_w);
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
        FramebufferDrawString(cx + 4, cy + ch - kRowH - 1, "N:NEXT  P:PREV  R:RESCAN", kInkDim, kBg);
    }
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
    RescanRoot();
    WindowSetContentDraw(handle, DrawFn, nullptr);
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
        drivers::video::NotifyShow("image: root rescan");
        return true;
    }
    return false;
}

bool ImageViewFeedArrow(bool left)
{
    if (g_state.count == 0)
        return false;
    StepIndex(!left);
    return true;
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

} // namespace duetos::apps::imageview
