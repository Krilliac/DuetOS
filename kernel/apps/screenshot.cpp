#include "apps/screenshot.h"

#include "arch/x86_64/serial.h"
#include "drivers/input/ps2mouse.h"
#include "drivers/video/app_widgets/app_button.h"
#include "drivers/video/app_widgets/app_label.h"
#include "drivers/video/app_widgets/app_panel.h"
#include "drivers/video/app_widgets/widget_group.h"
#include "drivers/video/chrome_text.h"
#include "drivers/video/cursor.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/notify.h"
#include "drivers/video/sound_cue.h"
#include "drivers/video/theme.h"
#include "fs/fat32.h"
#include "log/klog.h"
#include "mm/kheap.h"
#include "util/bmp.h"
#include "util/tga.h"

namespace duetos::apps::screenshot
{

namespace
{

using duetos::drivers::video::ChromeTextRole;
using duetos::drivers::video::ChromeTextWeight;
using duetos::drivers::video::ThemeCurrent;
using duetos::drivers::video::app_widgets::AppButton;
using duetos::drivers::video::app_widgets::AppLabel;
using duetos::drivers::video::app_widgets::AppPanel;
using duetos::drivers::video::app_widgets::Compose;
using duetos::drivers::video::app_widgets::Event;
using duetos::drivers::video::app_widgets::EventKind;
using duetos::drivers::video::app_widgets::EventResult;
using duetos::drivers::video::app_widgets::MakeWidgetGroup;
using duetos::drivers::video::app_widgets::Rect;

// ---------------------------------------------------------------
// Pass D chrome: Screenshot has no windowed surface today —
// captures fire from Ctrl+Alt+P (BMP) / Ctrl+Alt+T (TGA) bound in
// boot_tasks.cpp and from the boot self-test. The migration still
// stands the canonical capture/preview/filename/status chrome up
// behind the existing capture path so a future windowed "Capture &
// Save" surface can route through one WidgetGroup instead of re-
// deriving the layout. The current capture paths feed the live
// `g_last_path` / `g_last_status` buffers so the AppLabels
// reflect the most recent capture even when the chrome is only
// exercised by the self-test.
//
// Composition (in dispatch order):
//   - AppButton  "CAPTURE"  — would re-trigger ScreenshotCapture
//                              once the surface is wired to a
//                              window. on_click stays bound to a
//                              free function for the dispatch
//                              chain so the self-test hover edge
//                              works end-to-end.
//   - AppPanel              — preview frame around the (raw) most
//                              recent capture thumbnail. The
//                              thumbnail itself stays raw paint
//                              for now (no thumbnail cache in v0;
//                              the panel's job is the chrome
//                              border + tactility-on shadow).
//   - AppLabel  Body        — filename of the most recent capture
//                              ("SHOT0007.BMP") or "(no captures
//                              yet)" until the first save.
//   - AppLabel  Caption     — status footer ("saved" / "no disk" /
//                              "out of memory" / etc.) mirroring
//                              the NotifyShow text the capture
//                              paths already emit.

constexpr u32 kScCapBtnW = 80U;
constexpr u32 kScCapBtnH = 22U;
constexpr u32 kScPad = 4U;
constexpr u32 kScFilenameH = 14U;
constexpr u32 kScFooterH = 12U;

// AppLabel stores text by pointer so these buffers must outlive
// every Paint. Capture paths refresh them before the next paint.
constinit char g_last_path[16] = {'(', 'n', 'o', 'n', 'e', ')', '\0'};
constinit char g_last_status[48] = {};

// Forward decl for the capture-button click trampoline (defined
// below; it has to live above the constinit g_screenshot that
// captures it by function-pointer value).
void ClickCapture();

// Button (CAPTURE), then preview panel, then 2 AppLabels (path,
// status). Declaration order is dispatch order — the button gets
// first refusal on clicks.
constinit auto g_screenshot = MakeWidgetGroup(AppButton{}, AppPanel{}, AppLabel{}, AppLabel{});

constinit bool g_screenshot_bound = false;
constinit bool g_screenshot_prev_left_down = false;
constinit bool g_screenshot_self_test_passed = false;

// Walk the chain by hand to grab stable pointers. Chain order
// mirrors the MakeWidgetGroup argument list (button -> panel ->
// path-label -> status-label).
AppButton& ScCaptureButton()
{
    return g_screenshot.chain.head;
}
AppPanel& ScPreviewPanel()
{
    return g_screenshot.chain.tail.head;
}
AppLabel& ScPathLabel()
{
    return g_screenshot.chain.tail.tail.head;
}
AppLabel& ScStatusLabel()
{
    return g_screenshot.chain.tail.tail.tail.head;
}

void BindScreenshotOnce()
{
    if (g_screenshot_bound)
        return;
    g_screenshot_bound = true;

    AppButton& btn = ScCaptureButton();
    btn.label = "CAPTURE";
    btn.on_click = ClickCapture;
    btn.weight = ChromeTextWeight::Bold;
    btn.bg_rgb = 0; // theme role default
    btn.fg_rgb = 0x00101020U;

    const auto& th = ThemeCurrent();
    const u32 bg = 0x00181820U;
    const u32 fg = th.console_fg;
    const u32 dim = th.banner_fg;

    AppPanel& pan = ScPreviewPanel();
    // shadow_radius matches the toast: small enough that the
    // preview frame doesn't bloom past a 240 px wide chrome at
    // the tightest framebuffers.
    pan.shadow_radius = 8U;
    pan.bg_rgb = bg;
    pan.border_rgb = th.window_border;

    AppLabel& path = ScPathLabel();
    path.text = g_last_path;
    path.role = ChromeTextRole::Body;
    path.weight = ChromeTextWeight::Regular;
    path.fg_rgb = fg;
    path.bg_rgb = bg;
    path.align_left = true;

    AppLabel& status = ScStatusLabel();
    status.text = g_last_status;
    status.role = ChromeTextRole::Caption;
    status.weight = ChromeTextWeight::Regular;
    status.fg_rgb = dim;
    status.bg_rgb = bg;
    status.align_left = true;
}

// Re-anchor the button / panel / labels to the supplied client
// rect. Called by the self-test (and by a future windowed
// surface) so hit-tests + visuals stay consistent across moves /
// resizes.
void RebindScreenshotBounds(u32 cx, u32 cy, u32 cw, u32 ch)
{
    ScCaptureButton().bounds = Rect{cx + kScPad, cy + kScPad, kScCapBtnW, kScCapBtnH};

    // Preview panel sits below the capture button, leaving room
    // for the path + status labels along the bottom.
    const u32 below_btn_y = cy + kScPad + kScCapBtnH + kScPad;
    const u32 reserved_bottom = kScFilenameH + kScFooterH + kScPad;
    const u32 panel_h = (ch > (kScPad + kScCapBtnH + kScPad + reserved_bottom))
                            ? ch - kScPad - kScCapBtnH - kScPad - reserved_bottom
                            : 0U;
    const u32 panel_w = (cw > 2U * kScPad) ? cw - 2U * kScPad : cw;
    ScPreviewPanel().bounds = Rect{cx + kScPad, below_btn_y, panel_w, panel_h};

    const u32 path_y = (ch > kScFooterH + kScFilenameH) ? cy + ch - kScFooterH - kScFilenameH : cy;
    const u32 status_y = (ch > kScFooterH) ? cy + ch - kScFooterH : cy;
    const u32 label_w = (cw > 2U * kScPad) ? cw - 2U * kScPad : cw;
    ScPathLabel().bounds = Rect{cx + kScPad, path_y, label_w, kScFilenameH};
    ScStatusLabel().bounds = Rect{cx + kScPad, status_y, label_w, kScFooterH};
}

// Copy `src` into `dst[0..cap)` with NUL termination. Used by
// capture paths to refresh the path / status AppLabel buffers
// without dragging in a string-library dependency.
void CopyClipped(char* dst, u32 cap, const char* src)
{
    if (cap == 0)
        return;
    u32 i = 0;
    for (; i + 1 < cap && src[i] != '\0'; ++i)
        dst[i] = src[i];
    dst[i] = '\0';
}

void SetLastPath(const char* path)
{
    CopyClipped(g_last_path, sizeof(g_last_path), path);
}

void SetLastStatus(const char* status)
{
    CopyClipped(g_last_status, sizeof(g_last_status), status);
}

// ----- Pass D click trampoline ---------------------------------
// AppButton::on_click is a plain `void (*)()` so the constinit
// g_screenshot above captures it by function-pointer value. The
// trampoline mirrors the Ctrl+Alt+P keyboard binding — same code
// path the existing capture key triggers — so a future windowed
// surface gets the same behaviour for free.

void ClickCapture()
{
    (void)ScreenshotCapture();
}

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
        SetLastStatus("no disk");
        return false;
    }

    const auto fb = drivers::video::FramebufferGet();
    if (fb.virt == nullptr || fb.width == 0 || fb.height == 0 || fb.bpp != 32)
    {
        SerialWrite("[shot] capture: no usable 32-bpp framebuffer\n");
        NotifyShow("screenshot: no framebuffer");
        SetLastStatus("no framebuffer");
        return false;
    }

    // Hourglass for the duration of the FAT32 streaming write —
    // a multi-MiB framebuffer dump can take long enough that the
    // user wonders if the keystroke registered.
    CursorPushWait();

    const u32 idx = NextShotIndex(v);
    if (idx == 0)
    {
        // 4-digit screenshot counter overflowed (>9999). Klog
        // captures the saturation; the on-screen notify keeps
        // the user-facing signal as-is.
        KLOG_WARN("apps/screenshot", "filename counter exhausted (>9999)");
        CursorPopWait();
        NotifyShow("screenshot: filename slots exhausted");
        SetLastStatus("filename slots exhausted");
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
        // Framebuffer taller than our row-pointer-table cap. Klog
        // captures the offending height so a future regression
        // (e.g. compositor advertising a taller mode than the
        // capture path supports) is greppable.
        KLOG_WARN_V("apps/screenshot", "framebuffer height exceeds row-table cap", fb.height);
        CursorPopWait();
        NotifyShow("screenshot: too tall (>2048 rows)");
        SetLastStatus("framebuffer too tall");
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
        SetLastStatus("out of memory");
        return false;
    }
    duetos::util::BmpWriteHeader32(scratch, fb.width, fb.height, /*top_down=*/true);
    if (!StreamRows(v, path, fb.width, fb.height, scratch, kBmpHeaderBytes, rows))
    {
        SerialWrite("[shot] capture: write failed (disk full?)\n");
        CursorPopWait();
        NotifyShowKind("screenshot: write failed", NotifyKind::Error);
        SetLastStatus("write failed");
        return false;
    }

    SerialWrite("[shot] capture: ");
    SerialWrite(path);
    SerialWrite("\n");
    CursorPopWait();
    SetLastPath(path);
    SetLastStatus("saved");
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
        SetLastStatus("no disk");
        return false;
    }
    const auto fb = drivers::video::FramebufferGet();
    if (fb.virt == nullptr || fb.width == 0 || fb.height == 0 || fb.bpp != 32)
    {
        SerialWrite("[shot] tga: no usable 32-bpp framebuffer\n");
        NotifyShow("screenshot: no framebuffer");
        SetLastStatus("no framebuffer");
        return false;
    }
    CursorPushWait();
    const u32 idx = NextShotIndex(v);
    if (idx == 0)
    {
        SerialWrite("[shot] tga: filename counter exhausted (>9999)\n");
        CursorPopWait();
        NotifyShow("screenshot: filename slots exhausted");
        SetLastStatus("filename slots exhausted");
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
        SetLastStatus("framebuffer too tall");
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
        SetLastStatus("out of memory");
        return false;
    }
    if (!duetos::util::TgaWriteHeader32(scratch, fb.width, fb.height))
    {
        mm::KFree(scratch);
        SerialWrite("[shot] tga: header build failed (oversize dim?)\n");
        CursorPopWait();
        NotifyShowKind("screenshot: tga header failed", NotifyKind::Error);
        SetLastStatus("tga header failed");
        return false;
    }
    if (!StreamRows(v, path, fb.width, fb.height, scratch, duetos::util::kTgaHeaderBytes, rows))
    {
        SerialWrite("[shot] tga: write failed (disk full?)\n");
        CursorPopWait();
        NotifyShowKind("screenshot: write failed", NotifyKind::Error);
        SetLastStatus("write failed");
        return false;
    }

    SerialWrite("[shot] tga: ");
    SerialWrite(path);
    SerialWrite("\n");
    CursorPopWait();
    SetLastPath(path);
    SetLastStatus("saved");
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

    bool ok = true;

    // (1) Pass D chrome: drive a synthetic hover on the CAPTURE
    //     button via the WidgetGroup dispatch chain. The hover
    //     Consumed result proves the dispatch path + bounds
    //     hit-test are wired end-to-end. The self-test stops at
    //     the hover edge because the click would invoke
    //     ScreenshotCapture itself — a side-effectful FAT32
    //     write the BMP-round-trip leg below already covers.
    BindScreenshotOnce();
    // Anchor the chrome at (0, 0, 240, 200) — a plausible
    // future "Capture & Save" window size. CAPTURE is the only
    // button, sitting top-left within kScPad.
    RebindScreenshotBounds(0U, 0U, 240U, 200U);
    const u32 cap_cx = kScPad + kScCapBtnW / 2U;
    const u32 cap_cy = kScPad + kScCapBtnH / 2U;
    const Event move{EventKind::MouseMove, cap_cx, cap_cy, 0U, 0U};
    if (g_screenshot.DispatchEvent(move) != EventResult::Consumed)
        ok = false;

    // Header / footer composer parity: g_last_path / g_last_status
    // must be non-empty after a refresh (path defaults to "(none)"
    // until the first save, but is always populated).
    if (g_last_path[0] == '\0')
        ok = false;
    SetLastStatus("self-test running");
    if (g_last_status[0] == '\0')
        ok = false;

    // (2) Legacy 4×4 BMP round-trip — skipped silently if FAT32
    //     isn't mounted (the SKIP path used to be the whole
    //     contract). When the volume IS mounted, a write/read
    //     mismatch fails the umbrella.
    bool fs_skip = false;
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
    {
        fs_skip = true;
    }
    else
    {
        constexpr const char kTestPath[] = "SHOTTEST.BMP";
        fat::DirEntry pre;
        if (fat::Fat32LookupPath(v, kTestPath, &pre))
        {
            // Stale test file from a previous run; don't trust it.
            fat::Fat32DeleteAtPath(v, kTestPath);
        }

        // 4×4 synthetic test pattern: a deterministic gradient so
        // a future tooling pass can byte-compare. 16 pixels × 4
        // bytes = 64 bytes of pixel data; total file size = 54 +
        // 64 = 118.
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

        if (!wrote || !size_ok)
            ok = false;
    }

    g_screenshot_self_test_passed = ok;
    if (fs_skip && ok)
    {
        // FAT32 not mounted — chrome leg passed but the round-trip
        // leg was skipped. Keep the historical SKIP signal for the
        // log-analyzer + emit the canonical sentinel so the Pass D
        // umbrella aggregator still sees a PASS line.
        SerialWrite("[shot] self-test SKIP: no FAT32 volume\n");
        SerialWrite("[screenshot-selftest] PASS (chrome only; fs SKIP)\n");
    }
    else
    {
        SerialWrite(ok ? "[screenshot-selftest] PASS\n" : "[screenshot-selftest] FAIL\n");
    }
}

bool ScreenshotSelfTestPassed()
{
    return g_screenshot_self_test_passed;
}

void ScreenshotMouseInput(duetos::u32 cursor_x, duetos::u32 cursor_y, duetos::u8 button_mask)
{
    using duetos::drivers::input::kMouseButtonLeft;

    // Screenshot has no live windowed surface today. The chrome
    // WidgetGroup is bound + anchored to a notional (0,0,240,200)
    // client rect so a hover / press over those coordinates would
    // route through the CAPTURE button. The kernel mouse loop
    // never feeds those coordinates without a window registration,
    // so this is a no-op in practice — but the entry point exists
    // so a future "Capture & Save" surface can be wired without
    // adding a new boot_tasks dispatch case. Edge-detects left-
    // button state internally so a future caller can call
    // unconditionally per packet.
    BindScreenshotOnce();
    RebindScreenshotBounds(0U, 0U, 240U, 200U);

    const bool left_down = (button_mask & kMouseButtonLeft) != 0;
    const bool press_edge = left_down && !g_screenshot_prev_left_down;
    const bool release_edge = !left_down && g_screenshot_prev_left_down;
    g_screenshot_prev_left_down = left_down;

    const Event m{EventKind::MouseMove, cursor_x, cursor_y, 0U, 0U};
    g_screenshot.DispatchEvent(m);
    if (press_edge)
    {
        const Event d{EventKind::MouseDown, cursor_x, cursor_y, 0U, 0U};
        g_screenshot.DispatchEvent(d);
    }
    if (release_edge)
    {
        const Event u{EventKind::MouseUp, cursor_x, cursor_y, 0U, 0U};
        g_screenshot.DispatchEvent(u);
    }
}

} // namespace duetos::apps::screenshot
