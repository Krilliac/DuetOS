#include "apps/about.h"

#include "arch/x86_64/serial.h"
#include "drivers/input/ps2mouse.h"
#include "drivers/video/app_widgets/app_button.h"
#include "drivers/video/app_widgets/app_label.h"
#include "drivers/video/app_widgets/app_toolbar.h"
#include "drivers/video/app_widgets/widget_group.h"
#include "drivers/video/chrome_text.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/notify.h"
#include "drivers/video/theme.h"
#include "drivers/video/widget.h"
#include "fs/fat32.h"
#include "mm/kheap.h"
#include "time/tick.h"
#include "util/build_config.h"
#include "util/string.h"

namespace duetos::apps::about
{

namespace
{

using duetos::drivers::video::ChromeTextDraw;
using duetos::drivers::video::ChromeTextRole;
using duetos::drivers::video::ChromeTextWeight;
using duetos::drivers::video::FramebufferFillRect;
using duetos::drivers::video::kWindowInvalid;
using duetos::drivers::video::ThemeCurrent;
using duetos::drivers::video::ThemeIdName;
using duetos::drivers::video::ThemeRole;
using duetos::drivers::video::WindowHandle;
using duetos::drivers::video::WindowRegistryCount;
using duetos::drivers::video::WindowSetContentDraw;

constexpr u32 kRowH = 12;
constexpr u32 kPad = 4;

struct State
{
    WindowHandle handle;
};

constinit State g_state = {kWindowInvalid};

// Append a decimal u64 to `dst` at `*pos`, advancing `*pos`. Caps
// at `cap-1` to leave room for a NUL. Caller is responsible for
// terminating the string.
void AppendU64(char* dst, u32* pos, u32 cap, u64 v)
{
    char tmp[24];
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
    while (n > 0 && *pos + 1 < cap)
    {
        dst[(*pos)++] = tmp[--n];
    }
}

using duetos::core::AppendStr;

// Produce a human-friendly byte size. Picks the largest unit that
// keeps the integer part under 1024. e.g. 2_097_152 → "2 MiB",
// 65_536 → "64 KiB", 5 → "5 B". No fractional digits — keeps the
// formatter trivial and the common values (rounded-down) readable.
void AppendBytes(char* dst, u32* pos, u32 cap, u64 bytes)
{
    if (bytes >= (1ULL << 30))
    {
        AppendU64(dst, pos, cap, bytes >> 30);
        AppendStr(dst, pos, cap, " GiB");
    }
    else if (bytes >= (1ULL << 20))
    {
        AppendU64(dst, pos, cap, bytes >> 20);
        AppendStr(dst, pos, cap, " MiB");
    }
    else if (bytes >= (1ULL << 10))
    {
        AppendU64(dst, pos, cap, bytes >> 10);
        AppendStr(dst, pos, cap, " KiB");
    }
    else
    {
        AppendU64(dst, pos, cap, bytes);
        AppendStr(dst, pos, cap, " B");
    }
}

// HH:MM:SS form for an uptime expressed in scheduler ticks. Wraps
// at 99:59:59 (any longer uptime keeps showing 99:59:59 — for v0
// that's fine; nobody runs DuetOS for four days yet).
void AppendUptime(char* dst, u32* pos, u32 cap, u64 ticks, u64 hz)
{
    if (hz == 0)
    {
        AppendStr(dst, pos, cap, "(no tick)");
        return;
    }
    u64 secs = ticks / hz;
    if (secs > 99ULL * 3600 + 59 * 60 + 59)
    {
        secs = 99ULL * 3600 + 59 * 60 + 59;
    }
    const u64 hh = secs / 3600;
    const u64 mm = (secs / 60) % 60;
    const u64 ss = secs % 60;
    if (*pos + 9 < cap)
    {
        dst[(*pos)++] = static_cast<char>('0' + (hh / 10) % 10);
        dst[(*pos)++] = static_cast<char>('0' + hh % 10);
        dst[(*pos)++] = ':';
        dst[(*pos)++] = static_cast<char>('0' + (mm / 10) % 10);
        dst[(*pos)++] = static_cast<char>('0' + mm % 10);
        dst[(*pos)++] = ':';
        dst[(*pos)++] = static_cast<char>('0' + (ss / 10) % 10);
        dst[(*pos)++] = static_cast<char>('0' + ss % 10);
    }
}

// All body rows render through ChromeTextDraw with the requested
// role. Defaults to Body — the row labels + values that dominate
// the panel. Callers pick Caption for the footer hint.
void DrawLine(u32 cx, u32 y, const char* line, u32 fg, u32 bg, ChromeTextRole role = ChromeTextRole::Body,
              ChromeTextWeight weight = ChromeTextWeight::Regular)
{
    ChromeTextDraw(role, cx + 12, y, line, fg, bg, weight);
}

// ---------------------------------------------------------------
// Pass D chrome: AppToolbar (back) + 1 AppButton (RFRSH) + 2
// AppLabels (header "DUETOS v0 — system info", footer "Refreshes
// on every compositor tick."). RFRSH is read-only: About already
// re-samples kernel state on every paint, so the button just
// notifies the operator a refresh happened — it's a discoverable
// affordance for someone who hasn't read the footer hint.
//
// Carve-outs that stay raw paint:
//   - The BUILD / COMMIT / UPTIME / THEME / DISPLAY / DISK / HEAP /
//     WINDOWS rows: tabular labelled-value content with theme
//     colours, dynamic column count (HEAP wraps across 2 rows).
//     AppLabel has no multi-column / right-aligned-column model and
//     would lose the at-a-glance "label:    value" alignment.
//   The body rows paint inside the band DrawFn carves out between
//   the (toolbar + header) at the top and the AppLabel footer at
//   the bottom.

constexpr u32 kAboutToolbarH = 22U;
constexpr u32 kAboutToolbarBtnW = 52U;
constexpr u32 kAboutToolbarBtnH = 18U;
constexpr u32 kAboutToolbarBtnGap = 4U;
constexpr u32 kAboutToolbarPadX = 4U;
constexpr u32 kAboutToolbarPadY = 2U;
constexpr u32 kAboutHeaderH = kRowH + 4U;
constexpr u32 kAboutFooterH = kRowH;

using duetos::drivers::video::app_widgets::AppButton;
using duetos::drivers::video::app_widgets::AppLabel;
using duetos::drivers::video::app_widgets::AppToolbar;
using duetos::drivers::video::app_widgets::Compose;
using duetos::drivers::video::app_widgets::Event;
using duetos::drivers::video::app_widgets::EventKind;
using duetos::drivers::video::app_widgets::EventResult;
using duetos::drivers::video::app_widgets::MakeWidgetGroup;
using duetos::drivers::video::app_widgets::Rect;

// AppLabel stores text by pointer so the buffers must outlive
// every Paint. DrawFn re-renders them each frame.
constinit char g_header_text[48] = {};
constinit char g_footer_text[80] = {};

// Forward decl for the toolbar click trampoline (defined below;
// it has to live above the constinit g_about that captures it by
// function-pointer value).
void ClickRefresh();

// Toolbar (back), then 1 action AppButton, then 2 AppLabels
// (header, footer). Declaration order is dispatch order —
// buttons get first refusal on clicks.
constinit auto g_about = MakeWidgetGroup(AppToolbar{}, AppButton{}, AppLabel{}, AppLabel{});

constinit bool g_about_bound = false;
constinit bool g_about_prev_left_down = false;
constinit bool g_about_self_test_passed = false;

// Walk the recursive WidgetChain by hand to grab a stable
// pointer to the action button. Chain order mirrors the
// MakeWidgetGroup argument list (toolbar -> 1 button -> 2
// labels).
AppButton* AboutActionButton()
{
    return &g_about.chain.tail.head; // toolbar -> btn[0]
}

// AppLabel accessors — header / footer sit at chain positions
// 2, 3 (zero-indexed) after the 1 toolbar + 1 button.
AppLabel& AboutHeaderLabel()
{
    return g_about.chain.tail.tail.head;
}
AppLabel& AboutFooterLabel()
{
    return g_about.chain.tail.tail.tail.head;
}

void BindAboutOnce()
{
    if (g_about_bound)
        return;
    g_about_bound = true;

    auto& toolbar = g_about.chain.head;
    toolbar.bg_rgb = 0; // theme.taskbar_bg

    AppButton* btn = AboutActionButton();
    btn->label = "RFRSH";
    btn->on_click = ClickRefresh;
    btn->weight = ChromeTextWeight::Regular;
    btn->bg_rgb = 0; // theme role default
    btn->fg_rgb = 0x00101828U;

    const auto& th = ThemeCurrent();
    const u32 dim = th.banner_fg;
    const u32 bg = th.role_client[static_cast<u32>(ThemeRole::About)];

    auto& header = AboutHeaderLabel();
    header.text = g_header_text;
    header.role = ChromeTextRole::Title;
    header.weight = ChromeTextWeight::Bold;
    header.fg_rgb = dim;
    header.bg_rgb = bg;
    header.align_left = true;

    auto& footer = AboutFooterLabel();
    footer.text = g_footer_text;
    footer.role = ChromeTextRole::Caption;
    footer.weight = ChromeTextWeight::Regular;
    footer.fg_rgb = dim;
    footer.bg_rgb = bg;
    footer.align_left = true;
}

// Re-anchor the toolbar + button + labels to the live client
// rect. Called from DrawFn before PaintAll and from
// AboutMouseInput before DispatchEvent so hit-tests + visuals
// stay consistent across window moves / resizes.
void RebindAboutBounds(u32 cx, u32 cy, u32 cw, u32 ch)
{
    auto& toolbar = g_about.chain.head;
    toolbar.bounds = Rect{cx, cy, cw, kAboutToolbarH};

    {
        constexpr u32 i = 0U;
        const u32 bx = cx + kAboutToolbarPadX + i * (kAboutToolbarBtnW + kAboutToolbarBtnGap);
        AboutActionButton()->bounds = Rect{bx, cy + kAboutToolbarPadY, kAboutToolbarBtnW, kAboutToolbarBtnH};
    }

    // Header sits directly below the toolbar. Spans the client
    // width with a 12 px x-pad to match the raw-paint x-offset
    // ("cx + 12") used by the body rows below.
    const u32 header_y = cy + kAboutToolbarH;
    AboutHeaderLabel().bounds = Rect{cx + 12U, header_y, (cw > 12U) ? cw - 12U : cw, kAboutHeaderH};

    // Footer hint band along the bottom of the client area.
    const u32 fy = (ch > kAboutFooterH) ? cy + ch - kAboutFooterH : cy;
    const u32 fw = (cw > kPad) ? cw - kPad : cw;
    AboutFooterLabel().bounds = Rect{cx + 12U, fy, fw, kAboutFooterH};
}

void RefreshAboutHeader()
{
    static const char kHeader[] = "DUETOS v0 - system info";
    u32 i = 0;
    for (; kHeader[i] != '\0' && i + 1 < sizeof(g_header_text); ++i)
        g_header_text[i] = kHeader[i];
    g_header_text[i] = '\0';
}

void RefreshAboutFooter()
{
    // User-facing tagline. The previous "Refreshes on every
    // compositor tick." was a maintainer note about the data
    // pipeline that didn't belong in the About panel.
    static const char kHint[] = "DuetOS - a from-scratch desktop OS.";
    u32 i = 0;
    for (; kHint[i] != '\0' && i + 1 < sizeof(g_footer_text); ++i)
        g_footer_text[i] = kHint[i];
    g_footer_text[i] = '\0';
}

// ----- Pass D click trampoline ---------------------------------
// AppButton::on_click is a plain `void (*)()` so the constinit
// g_about above captures it by function-pointer value. RFRSH is
// intentionally read-only: About re-samples every paint, so the
// button just touches the snapshot APIs (so any lazy backing
// store warms up) and posts a notify so the user gets visual
// confirmation the click registered.

void ClickRefresh()
{
    // Touch the read-only snapshot APIs so any lazy backing
    // store warms up before the next paint. All calls are
    // side-effect-free at their contracts.
    (void)mm::KernelHeapStatsRead();
    (void)duetos::drivers::video::FramebufferGet();
    (void)time::TickCount();
    (void)time::TickHz();
    (void)duetos::drivers::video::ThemeCurrentId();
    (void)fs::fat32::Fat32Volume(0);
    duetos::drivers::video::NotifyShow("about: refreshed");
}

// Paint the raw About body (BUILD / COMMIT / UPTIME / THEME /
// DISPLAY / DISK / HEAP / WINDOWS rows) inside the band DrawFn
// carves out between the (toolbar + header) at the top and the
// AppLabel footer at the bottom.
void PaintAboutContent(u32 cx, u32 cy, u32 cw, u32 ch)
{
    namespace fat = fs::fat32;
    const auto& th = ThemeCurrent();
    const u32 bg = th.role_client[static_cast<u32>(ThemeRole::About)];
    const u32 fg = th.console_fg;
    FramebufferFillRect(cx, cy, cw, ch, bg);

    if (cw < 200 || ch < 60)
    {
        return; // band too small; nothing useful to paint
    }

    char line[96];
    u32 p = 0;
    u32 y = cy + 4;

    // Build banner / flavor.
    p = 0;
    AppendStr(line, &p, sizeof(line), "BUILD:    ");
#if defined(DUETOS_BUILD_FLAVOR) && DUETOS_BUILD_FLAVOR == 1
    AppendStr(line, &p, sizeof(line), "DEBUG");
#elif defined(DUETOS_BUILD_FLAVOR) && DUETOS_BUILD_FLAVOR == 2
    AppendStr(line, &p, sizeof(line), "RELEASE");
#else
    AppendStr(line, &p, sizeof(line), "(unspecified)");
#endif
#if defined(DUETOS_KASLR) && DUETOS_KASLR == 1
    AppendStr(line, &p, sizeof(line), " +KASLR");
#endif
#if defined(DUETOS_ASSERTS) && DUETOS_ASSERTS == 1
    AppendStr(line, &p, sizeof(line), " +ASSERT");
#endif
    line[p] = '\0';
    DrawLine(cx, y, line, fg, bg);
    y += kRowH;

    // Git commit hash (captured at configure time). Trailing '+'
    // means the working tree was dirty when CMake configured —
    // the running image is the named commit *plus* uncommitted
    // edits. "unknown" means CMake couldn't reach git (not a
    // checkout, or git not installed during configure).
    p = 0;
    AppendStr(line, &p, sizeof(line), "COMMIT:   ");
    AppendStr(line, &p, sizeof(line), duetos::core::BuildGitHash());
    line[p] = '\0';
    DrawLine(cx, y, line, fg, bg);
    y += kRowH;

    // Uptime.
    p = 0;
    AppendStr(line, &p, sizeof(line), "UPTIME:   ");
    AppendUptime(line, &p, sizeof(line), time::TickCount(), time::TickHz());
    line[p] = '\0';
    DrawLine(cx, y, line, fg, bg);
    y += kRowH;

    // Theme name.
    p = 0;
    AppendStr(line, &p, sizeof(line), "THEME:    ");
    AppendStr(line, &p, sizeof(line), ThemeIdName(duetos::drivers::video::ThemeCurrentId()));
    line[p] = '\0';
    DrawLine(cx, y, line, fg, bg);
    y += kRowH;

    // Framebuffer.
    const auto fb = duetos::drivers::video::FramebufferGet();
    p = 0;
    AppendStr(line, &p, sizeof(line), "DISPLAY:  ");
    AppendU64(line, &p, sizeof(line), fb.width);
    AppendStr(line, &p, sizeof(line), "x");
    AppendU64(line, &p, sizeof(line), fb.height);
    AppendStr(line, &p, sizeof(line), "  ");
    AppendU64(line, &p, sizeof(line), fb.bpp);
    AppendStr(line, &p, sizeof(line), "-bpp");
    line[p] = '\0';
    DrawLine(cx, y, line, fg, bg);
    y += kRowH;

    // FAT32 status.
    p = 0;
    AppendStr(line, &p, sizeof(line), "DISK:     ");
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
    {
        AppendStr(line, &p, sizeof(line), "(no FAT32 volume)");
    }
    else
    {
        AppendStr(line, &p, sizeof(line), "FAT32 mounted, root entries=");
        AppendU64(line, &p, sizeof(line), v->root_entry_count);
    }
    line[p] = '\0';
    DrawLine(cx, y, line, fg, bg);
    y += kRowH;

    // Heap.
    const auto h = mm::KernelHeapStatsRead();
    p = 0;
    AppendStr(line, &p, sizeof(line), "HEAP:     ");
    AppendBytes(line, &p, sizeof(line), h.used_bytes);
    AppendStr(line, &p, sizeof(line), " used, ");
    AppendBytes(line, &p, sizeof(line), h.free_bytes);
    AppendStr(line, &p, sizeof(line), " free / ");
    AppendBytes(line, &p, sizeof(line), h.pool_bytes);
    line[p] = '\0';
    DrawLine(cx, y, line, fg, bg);
    y += kRowH;

    p = 0;
    AppendStr(line, &p, sizeof(line), "          allocs=");
    AppendU64(line, &p, sizeof(line), h.alloc_count);
    AppendStr(line, &p, sizeof(line), " frees=");
    AppendU64(line, &p, sizeof(line), h.free_count);
    AppendStr(line, &p, sizeof(line), " frags=");
    AppendU64(line, &p, sizeof(line), h.free_chunk_count);
    line[p] = '\0';
    DrawLine(cx, y, line, fg, bg);
    y += kRowH;

    // Open-window count — only visible windows; users care about
    // what's actually on screen, not the hidden launchers the
    // Start menu raises on demand.
    u32 visible = 0;
    const u32 reg_n = WindowRegistryCount();
    for (u32 i = 0; i < reg_n; ++i)
    {
        if (duetos::drivers::video::WindowIsAlive(i) && duetos::drivers::video::WindowIsVisible(i))
            ++visible;
    }
    p = 0;
    AppendStr(line, &p, sizeof(line), "WINDOWS:  ");
    AppendU64(line, &p, sizeof(line), visible);
    AppendStr(line, &p, sizeof(line), " OPEN");
    line[p] = '\0';
    DrawLine(cx, y, line, fg, bg);
}

void DrawFn(u32 cx, u32 cy, u32 cw, u32 ch, void* /*cookie*/)
{
    const auto& th = ThemeCurrent();
    const u32 bg = th.role_client[static_cast<u32>(ThemeRole::About)];
    FramebufferFillRect(cx, cy, cw, ch, bg);

    // Pass D chrome: refresh the header / footer text (constant
    // for About — no per-state variation), re-anchor the toolbar /
    // labels to the current client rect, and paint the
    // WidgetGroup. The raw body rows (carve-out) sit in the band
    // between the header row and the AppLabel footer.
    BindAboutOnce();
    RefreshAboutHeader();
    RefreshAboutFooter();
    RebindAboutBounds(cx, cy, cw, ch);

    Compose compose_ctx{};
    g_about.PaintAll(compose_ctx);

    // Content band — between (toolbar + header) at the top and
    // the AppLabel footer at the bottom.
    const u32 top_band = kAboutToolbarH + kAboutHeaderH;
    const u32 bot_band = kAboutFooterH + kPad;
    const u32 list_x = cx;
    const u32 list_y = cy + top_band;
    const u32 list_w = cw;
    const u32 list_h = (ch > top_band + bot_band) ? (ch - top_band - bot_band) : 0;
    if (list_h > 0)
    {
        PaintAboutContent(list_x, list_y, list_w, list_h);
    }
}

} // namespace

void AboutInit(WindowHandle handle)
{
    g_state.handle = handle;
    WindowSetContentDraw(handle, DrawFn, nullptr);
    BindAboutOnce();
}

WindowHandle AboutWindow()
{
    return g_state.handle;
}

void AboutSelfTest()
{
    using arch::SerialWrite;
    bool ok = true;

    // AppendU64.
    char buf[64];
    u32 p = 0;
    AppendU64(buf, &p, sizeof(buf), 0);
    if (p != 1 || buf[0] != '0')
        ok = false;
    p = 0;
    AppendU64(buf, &p, sizeof(buf), 12345);
    buf[p] = '\0';
    if (p != 5 || buf[0] != '1' || buf[4] != '5')
        ok = false;

    // AppendBytes — boundary-test each tier.
    p = 0;
    AppendBytes(buf, &p, sizeof(buf), 5);
    buf[p] = '\0';
    if (buf[0] != '5' || buf[1] != ' ' || buf[2] != 'B')
        ok = false;
    p = 0;
    AppendBytes(buf, &p, sizeof(buf), 1024);
    buf[p] = '\0';
    if (buf[0] != '1' || buf[1] != ' ' || buf[2] != 'K')
        ok = false;
    p = 0;
    AppendBytes(buf, &p, sizeof(buf), 1ULL << 20);
    buf[p] = '\0';
    if (buf[0] != '1' || buf[2] != 'M')
        ok = false;
    p = 0;
    AppendBytes(buf, &p, sizeof(buf), 1ULL << 30);
    buf[p] = '\0';
    if (buf[0] != '1' || buf[2] != 'G')
        ok = false;

    // AppendUptime — 1h2m3s should produce "01:02:03".
    p = 0;
    AppendUptime(buf, &p, sizeof(buf), 100ULL * (3600 + 2 * 60 + 3), 100);
    buf[p] = '\0';
    if (p != 8 || buf[0] != '0' || buf[1] != '1' || buf[2] != ':' || buf[3] != '0' || buf[4] != '2' || buf[5] != ':' ||
        buf[6] != '0' || buf[7] != '3')
        ok = false;
    // Cap at 99:59:59 so a hostile / corrupt tick can't spam the screen.
    p = 0;
    AppendUptime(buf, &p, sizeof(buf), 100ULL * (1000 * 3600), 100);
    buf[p] = '\0';
    if (buf[0] != '9' || buf[1] != '9' || buf[3] != '5' || buf[4] != '9')
        ok = false;
    // hz==0 path emits a sentinel rather than dividing by zero.
    p = 0;
    AppendUptime(buf, &p, sizeof(buf), 1, 0);
    buf[p] = '\0';
    if (p == 0 || buf[0] != '(')
        ok = false;

    // Pass D: drive a synthetic click on the RFRSH toolbar button
    // via the WidgetGroup dispatch chain. ClickRefresh only calls
    // read-only snapshot APIs (KernelHeapStatsRead, FramebufferGet,
    // TickCount/Hz, ThemeCurrentId, Fat32Volume) + NotifyShow — it
    // never mutates kernel state, so this self-test is safe to run
    // unconditionally at boot.
    BindAboutOnce();
    // Anchor the toolbar at (0, 22, 360, 198) — same shape
    // boot_bringup.cpp registers the live about window with
    // (360x220 minus 22 px title bar). RFRSH is action index 0.
    RebindAboutBounds(0U, 22U, 360U, 198U);
    constexpr u32 kRfrshIdx = 0U;
    const u32 nx = kAboutToolbarPadX + kRfrshIdx * (kAboutToolbarBtnW + kAboutToolbarBtnGap) + kAboutToolbarBtnW / 2U;
    const u32 ny = 22U + kAboutToolbarPadY + kAboutToolbarBtnH / 2U;
    const Event a_move{EventKind::MouseMove, nx, ny, 0U, 0U};
    const Event a_down{EventKind::MouseDown, nx, ny, 0U, 0U};
    const Event a_up{EventKind::MouseUp, nx, ny, 0U, 0U};
    if (g_about.DispatchEvent(a_move) != EventResult::Consumed)
        ok = false;
    if (g_about.DispatchEvent(a_down) != EventResult::Consumed)
        ok = false;
    if (g_about.DispatchEvent(a_up) != EventResult::Consumed)
        ok = false;

    // Header / footer composers must produce non-empty text
    // after a refresh.
    RefreshAboutHeader();
    if (g_header_text[0] == '\0')
        ok = false;
    RefreshAboutFooter();
    if (g_footer_text[0] == '\0')
        ok = false;

    g_about_self_test_passed = ok;
    SerialWrite(ok ? "[about-selftest] PASS\n" : "[about-selftest] FAIL\n");
}

bool AboutSelfTestPassed()
{
    return g_about_self_test_passed;
}

void AboutMouseInput(duetos::u32 cx, duetos::u32 cy, duetos::u8 button_mask)
{
    using duetos::drivers::input::kMouseButtonLeft;
    if (g_state.handle == duetos::drivers::video::kWindowInvalid)
        return;
    duetos::u32 wx = 0, wy = 0, ww = 0, wh = 0;
    if (!duetos::drivers::video::WindowGetBounds(g_state.handle, &wx, &wy, &ww, &wh))
        return;
    // Title bar is 22 px; client origin sits below it. The
    // WidgetGroup dispatch path needs cursor coords in the same
    // frame RebindAboutBounds anchors the chrome to.
    constexpr duetos::u32 kTitleH = 22U;
    if (wh <= kTitleH)
        return;
    const duetos::u32 client_y = wy + kTitleH;
    const duetos::u32 client_h = wh - kTitleH;
    BindAboutOnce();
    RebindAboutBounds(wx, client_y, ww, client_h);

    const bool left_down = (button_mask & kMouseButtonLeft) != 0;
    const bool press_edge = left_down && !g_about_prev_left_down;
    const bool release_edge = !left_down && g_about_prev_left_down;
    g_about_prev_left_down = left_down;

    const bool inside_window = (cx >= wx && cx < wx + ww && cy >= client_y && cy < wy + wh);
    if (inside_window)
    {
        const Event m{EventKind::MouseMove, cx, cy, 0U, 0U};
        g_about.DispatchEvent(m);
    }
    if (press_edge && inside_window)
    {
        // Carve-out: the raw body rows (BUILD / COMMIT / UPTIME /
        // ...) sit below the toolbar / header rows the
        // WidgetGroup owns. DispatchEvent's hit-test naturally
        // short-circuits when the click misses the toolbar bounds
        // — the body rows have no per-row click semantics (About
        // is a read-only snapshot). MouseDown still fires for the
        // toolbar Pressed-state visual.
        const Event d{EventKind::MouseDown, cx, cy, 0U, 0U};
        g_about.DispatchEvent(d);
    }
    if (release_edge)
    {
        // Always dispatch MouseUp so a button pressed inside the
        // toolbar and dragged off clears its Pressed flag.
        const Event u{EventKind::MouseUp, cx, cy, 0U, 0U};
        g_about.DispatchEvent(u);
    }
}

} // namespace duetos::apps::about
