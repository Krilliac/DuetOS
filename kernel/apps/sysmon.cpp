#include "apps/sysmon.h"

#include "arch/x86_64/serial.h"
#include "arch/x86_64/smp.h"
#include "drivers/input/ps2mouse.h"
#include "drivers/video/app_widgets/app_button.h"
#include "drivers/video/app_widgets/app_label.h"
#include "drivers/video/app_widgets/app_toolbar.h"
#include "drivers/video/app_widgets/widget_group.h"
#include "drivers/video/chrome_text.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/notify.h"
#include "drivers/video/theme.h"
#include "mm/kheap.h"
#include "sched/sched.h"
#include "time/tick.h"
#include "util/string.h"

namespace duetos::apps::sysmon
{

namespace
{

using duetos::drivers::video::FramebufferDrawString;
using duetos::drivers::video::FramebufferFillRect;
using duetos::drivers::video::FramebufferPutPixel;
using duetos::drivers::video::kWindowInvalid;
using duetos::drivers::video::ThemeCurrent;
using duetos::drivers::video::WindowHandle;
using duetos::drivers::video::WindowRegistryCount;
using duetos::drivers::video::WindowSetContentDraw;

constexpr u32 kRowH = 12;
constexpr u32 kPad = 4;
constexpr u32 kPanelGap = 6;

/// Maximum per-core entries captured per sample. Physical CPUs beyond
/// this are aggregated only into the system-wide cpu_pct. 4 is enough
/// to show differentiation on a typical SMP=2..4 test guest without
/// adding unbounded storage to the ring.
inline constexpr u32 kSysmonMaxCores = 4;

// One ring slot. Fields are sized to the values they hold; the
// ring uses a flat-array circular buffer indexed by (head + i)
// modulo kSysmonRingDepth.
struct Sample
{
    u8 cpu_pct;        // 0..100, instantaneous CPU-busy over the last sample window
    u8 heap_used_pct;  // 0..100
    u8 frag_score;     // 0..100, clamped from free_chunk_count
    u16 alive_windows; // 0..kMaxWindows (16) but width-friendly
    // Per-core CPU-busy %, indexed by cpu_id. 0 when the CPU is
    // offline or the slot is beyond the observed cpu_id_limit.
    u8 core_pct[kSysmonMaxCores];
    // Number of valid entries in core_pct (≤ kSysmonMaxCores).
    u8 core_count;
    u8 _pad[2];
};

struct State
{
    WindowHandle handle;
    Sample ring[kSysmonRingDepth];
    u32 head;  // next-write index
    u32 count; // populated entries (≤ kSysmonRingDepth)
    // CPU-busy is published as lifetime tick counters; the
    // instantaneous percentage for each sample is the delta between
    // consecutive reads. These hold the previous read so CollectSample
    // can difference against it. Seeded on first Init.
    u64 prev_total_ticks;
    u64 prev_idle_ticks;
    // Per-core previous tick snapshots for the same differencing.
    u64 prev_core_total[kSysmonMaxCores];
    u64 prev_core_idle[kSysmonMaxCores];
    bool cpu_seeded;
    bool initted;
};

constinit State g_state = {
    .handle = kWindowInvalid,
    .ring = {},
    .head = 0,
    .count = 0,
    .prev_total_ticks = 0,
    .prev_idle_ticks = 0,
    .prev_core_total = {},
    .prev_core_idle = {},
    .cpu_seeded = false,
    .initted = false,
};

// -------------------------------------------------------------------
// Ring helpers — small + testable.
// -------------------------------------------------------------------

void RingPush(Sample s)
{
    g_state.ring[g_state.head] = s;
    g_state.head = (g_state.head + 1) % kSysmonRingDepth;
    if (g_state.count < kSysmonRingDepth)
    {
        ++g_state.count;
    }
}

// Read entry at logical index (0 = newest, count-1 = oldest).
Sample RingAt(u32 i)
{
    if (g_state.count == 0 || i >= g_state.count)
    {
        return Sample{};
    }
    // head points at the next-write slot; the most recent populated
    // slot is head-1 (modulo). i-th most recent is head - 1 - i.
    const u32 idx = (g_state.head + kSysmonRingDepth - 1 - i) % kSysmonRingDepth;
    return g_state.ring[idx];
}

void RingClear()
{
    g_state.head = 0;
    g_state.count = 0;
    for (u32 i = 0; i < kSysmonRingDepth; ++i)
    {
        g_state.ring[i] = Sample{};
    }
}

// -------------------------------------------------------------------
// Sample collection — pure read of kernel state. Cheap.
// -------------------------------------------------------------------

Sample CollectSample()
{
    Sample s{};
    // CPU-busy: difference the lifetime tick counters since the last
    // sample so the bar shows the *instantaneous* load over this
    // window rather than the since-boot average the tray pill shows.
    // busy = total - idle, both deltas; pct = busy_delta / total_delta.
    const auto sched_stats = ::duetos::sched::SchedStatsRead();
    // Save seeded flag before updating so both system-wide and per-core
    // blocks share the same "was this the first sample?" gate.
    const bool was_seeded = g_state.cpu_seeded;
    if (was_seeded)
    {
        const u64 total_delta = (sched_stats.total_ticks > g_state.prev_total_ticks)
                                    ? (sched_stats.total_ticks - g_state.prev_total_ticks)
                                    : 0;
        const u64 idle_delta =
            (sched_stats.idle_ticks > g_state.prev_idle_ticks) ? (sched_stats.idle_ticks - g_state.prev_idle_ticks) : 0;
        if (total_delta > 0)
        {
            const u64 busy_delta = (total_delta > idle_delta) ? (total_delta - idle_delta) : 0;
            const u64 pct = (busy_delta * 100ULL) / total_delta;
            s.cpu_pct = static_cast<u8>(pct > 100 ? 100 : pct);
        }
    }
    g_state.prev_total_ticks = sched_stats.total_ticks;
    g_state.prev_idle_ticks = sched_stats.idle_ticks;
    g_state.cpu_seeded = true;

    // Per-core CPU-busy: difference per-CPU lifetime tick counters
    // the same way the system-wide sparkline does. Uses `was_seeded`
    // to match the system-wide "skip the very first sample" gate.
    const u32 cpu_limit = ::duetos::arch::SmpCpuIdLimit();
    const u32 max_cores = (cpu_limit < kSysmonMaxCores) ? cpu_limit : kSysmonMaxCores;
    s.core_count = static_cast<u8>(max_cores);
    for (u32 c = 0; c < max_cores; ++c)
    {
        u64 ct = 0, ci = 0;
        if (::duetos::sched::SchedStatsReadCpu(c, &ct, &ci))
        {
            if (was_seeded)
            {
                const u64 td = (ct > g_state.prev_core_total[c]) ? (ct - g_state.prev_core_total[c]) : 0;
                const u64 id = (ci > g_state.prev_core_idle[c]) ? (ci - g_state.prev_core_idle[c]) : 0;
                if (td > 0)
                {
                    const u64 busy = (td > id) ? (td - id) : 0;
                    const u64 pct = (busy * 100ULL) / td;
                    s.core_pct[c] = static_cast<u8>(pct > 100 ? 100 : pct);
                }
            }
            g_state.prev_core_total[c] = ct;
            g_state.prev_core_idle[c] = ci;
        }
    }

    const auto h = mm::KernelHeapStatsRead();
    if (h.pool_bytes > 0)
    {
        const u64 pct = (h.used_bytes * 100ULL) / h.pool_bytes;
        s.heap_used_pct = static_cast<u8>(pct > 100 ? 100 : pct);
    }
    // Fragmentation proxy: more freelist nodes = more
    // fragmentation. 32 nodes maps to "100%" on the chart so a
    // healthy run sits near the bottom and a runaway alloc/free
    // cadence pushes the trace up visibly.
    const u64 frag = (h.free_chunk_count > 32) ? 32 : h.free_chunk_count;
    s.frag_score = static_cast<u8>((frag * 100) / 32);
    // Alive-window count: walk the registry cheaply.
    u16 alive = 0;
    const u32 n = WindowRegistryCount();
    for (u32 i = 0; i < n; ++i)
    {
        if (duetos::drivers::video::WindowIsAlive(i))
        {
            ++alive;
        }
    }
    s.alive_windows = alive;
    return s;
}

// -------------------------------------------------------------------
// Tiny formatting helpers — same convention as About / Files.
// -------------------------------------------------------------------

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

void AppendBytes(char* dst, u32* pos, u32 cap, u64 bytes)
{
    if (bytes >= (1ULL << 20))
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

// -------------------------------------------------------------------
// Sparkline panel painter (carve-out).
// -------------------------------------------------------------------
//
// Paints `count` samples right-aligned inside (x, y, w, h). Each
// sample is rendered as a 4-px-wide vertical bar whose height is
// proportional to its 0..100 value. Newest sample lands at the
// right edge — the trace scrolls left as new samples arrive.

void PaintSparkline(u32 x, u32 y, u32 w, u32 h, u32 trace_rgb, u32 axis_rgb, u8 (*read_field)(const Sample&))
{
    constexpr u32 kColW = 4;
    if (w == 0 || h == 0)
        return;
    // Frame.
    duetos::drivers::video::FramebufferDrawRect(x, y, w, h, axis_rgb, 1);
    if (g_state.count == 0)
        return;
    const u32 inner_x = x + 1;
    const u32 inner_y = y + 1;
    const u32 inner_w = (w >= 2) ? w - 2 : 0;
    const u32 inner_h = (h >= 2) ? h - 2 : 0;
    if (inner_w == 0 || inner_h == 0)
        return;
    // Number of bars that fit inside the frame.
    const u32 bars = inner_w / kColW;
    if (bars == 0)
        return;
    const u32 to_draw = (g_state.count < bars) ? g_state.count : bars;
    // i = 0 is the newest; we paint from right to left so newest
    // ends up at the right edge of the panel.
    for (u32 i = 0; i < to_draw; ++i)
    {
        const Sample s = RingAt(i);
        const u32 v = read_field(s);
        const u32 bar_h = (v * inner_h) / 100;
        if (bar_h == 0)
            continue;
        const u32 bar_x = inner_x + inner_w - (i + 1) * kColW;
        const u32 bar_y = inner_y + inner_h - bar_h;
        FramebufferFillRect(bar_x, bar_y, kColW - 1, bar_h, trace_rgb);
    }
}

// ---------------------------------------------------------------
// Pass D chrome: AppToolbar (back) + 2 AppButtons (SAMPLE, CLEAR)
// + 3 AppLabels (header summary, heap-usage detail, footer hint).
// The toolbar exposes both ring-mutating actions ('C' / clear and
// the F5 / force-sample shortcut from SysmonFeedChar) as
// discoverable buttons, so an operator who never reads the footer
// hint can still drive the app.
//
// Carve-outs that stay raw paint:
//   - Two stacked sparkline panels (HEAP USED %, FRAGMENTATION).
//     AppPanel has no time-series / per-sample bar model, the
//     trace colour varies per panel (green for heap-used, amber
//     for frag), and the right-aligned bar layout has no AppList
//     equivalent.
// AppLabel paints the header / heap-detail / footer lines; the
// carve-out band sits between the heap-detail label and the
// footer label.

constexpr u32 kSmToolbarH = 22U;
constexpr u32 kSmToolbarBtnW = 60U;
constexpr u32 kSmToolbarBtnH = 18U;
constexpr u32 kSmToolbarBtnGap = 4U;
constexpr u32 kSmToolbarPadX = 4U;
constexpr u32 kSmToolbarPadY = 2U;
constexpr u32 kSmActionBtnCount = 2U;
constexpr u32 kSmHeaderH = kRowH + 2U;
constexpr u32 kSmDetailH = kRowH + 2U;
constexpr u32 kSmFooterH = kRowH;

using duetos::drivers::video::ChromeTextRole;
using duetos::drivers::video::ChromeTextWeight;
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
constinit char g_header_text[96] = {};
constinit char g_detail_text[96] = {};
constinit char g_footer_text[64] = {};

// Forward decls for the toolbar click trampolines (defined below;
// they have to live above the constinit g_sysmon that captures
// them by function-pointer value).
void ClickSample();
void ClickClear();

// Toolbar (back), then 2 action AppButtons, then 3 AppLabels
// (header, detail, footer). Declaration order is dispatch order
// — buttons get first refusal on clicks.
constinit auto g_sysmon = MakeWidgetGroup(AppToolbar{}, AppButton{}, AppButton{}, AppLabel{}, AppLabel{}, AppLabel{});

constinit bool g_sysmon_bound = false;
constinit bool g_sysmon_prev_left_down = false;
constinit bool g_sysmon_self_test_passed = false;

// Walk the recursive WidgetChain by hand to grab stable pointers
// to each action button + label. Chain order mirrors the
// MakeWidgetGroup argument list (toolbar -> btn[0] -> btn[1] ->
// label[0] -> label[1] -> label[2]).
AppButton* SmActionButton(u32 idx)
{
    if (idx == 0)
        return &g_sysmon.chain.tail.head;  // toolbar -> btn[0]
    return &g_sysmon.chain.tail.tail.head; // toolbar -> btn[0] -> btn[1]
}

AppLabel& SmHeaderLabel()
{
    return g_sysmon.chain.tail.tail.tail.head;
}
AppLabel& SmDetailLabel()
{
    return g_sysmon.chain.tail.tail.tail.tail.head;
}
AppLabel& SmFooterLabel()
{
    return g_sysmon.chain.tail.tail.tail.tail.tail.head;
}

void BindSysmonOnce()
{
    if (g_sysmon_bound)
        return;
    g_sysmon_bound = true;

    auto& toolbar = g_sysmon.chain.head;
    toolbar.bg_rgb = 0; // theme.taskbar_bg

    static const char* const kBtnLabels[kSmActionBtnCount] = {"SAMPLE", "CLEAR"};
    static void (*const kBtnHandlers[kSmActionBtnCount])() = {ClickSample, ClickClear};
    for (u32 i = 0; i < kSmActionBtnCount; ++i)
    {
        AppButton* btn = SmActionButton(i);
        btn->label = kBtnLabels[i];
        btn->on_click = kBtnHandlers[i];
        btn->weight = ChromeTextWeight::Regular;
        btn->bg_rgb = 0; // theme role default
        btn->fg_rgb = 0x00101828U;
    }

    const auto& th = ThemeCurrent();
    const u32 fg = th.console_fg;
    const u32 dim = th.banner_fg;
    constexpr u32 kBg = 0x00101828U;

    auto& header = SmHeaderLabel();
    header.text = g_header_text;
    header.role = ChromeTextRole::Body;
    header.weight = ChromeTextWeight::Bold;
    header.fg_rgb = fg;
    header.bg_rgb = kBg;
    header.align_left = true;

    auto& detail = SmDetailLabel();
    detail.text = g_detail_text;
    detail.role = ChromeTextRole::Body;
    detail.weight = ChromeTextWeight::Regular;
    detail.fg_rgb = dim;
    detail.bg_rgb = kBg;
    detail.align_left = true;

    auto& footer = SmFooterLabel();
    footer.text = g_footer_text;
    footer.role = ChromeTextRole::Caption;
    footer.weight = ChromeTextWeight::Regular;
    footer.fg_rgb = dim;
    footer.bg_rgb = kBg;
    footer.align_left = true;
}

// Re-anchor the toolbar + buttons + labels to the live client
// rect. Called from DrawFn before PaintAll and from
// SysmonMouseInput before DispatchEvent so hit-tests + visuals
// stay consistent across window moves / resizes.
void RebindSysmonBounds(u32 cx, u32 cy, u32 cw, u32 ch)
{
    auto& toolbar = g_sysmon.chain.head;
    toolbar.bounds = Rect{cx, cy, cw, kSmToolbarH};

    for (u32 i = 0; i < kSmActionBtnCount; ++i)
    {
        const u32 bx = cx + kSmToolbarPadX + i * (kSmToolbarBtnW + kSmToolbarBtnGap);
        SmActionButton(i)->bounds = Rect{bx, cy + kSmToolbarPadY, kSmToolbarBtnW, kSmToolbarBtnH};
    }

    // Header sits directly below the toolbar.
    const u32 header_y = cy + kSmToolbarH;
    SmHeaderLabel().bounds = Rect{cx + kPad, header_y, (cw > kPad) ? cw - kPad : cw, kSmHeaderH};

    // Detail row directly below header.
    const u32 detail_y = header_y + kSmHeaderH;
    SmDetailLabel().bounds = Rect{cx + kPad, detail_y, (cw > kPad) ? cw - kPad : cw, kSmDetailH};

    // Footer hint band along the bottom of the client area.
    const u32 fy = (ch > kSmFooterH) ? cy + ch - kSmFooterH : cy;
    const u32 fw = (cw > kPad) ? cw - kPad : cw;
    SmFooterLabel().bounds = Rect{cx + kPad, fy, fw, kSmFooterH};
}

void RefreshSysmonHeader()
{
    const Sample latest = (g_state.count > 0) ? RingAt(0) : Sample{};
    const auto h = mm::KernelHeapStatsRead();
    u32 lp = 0;
    AppendStr(g_header_text, &lp, sizeof(g_header_text), "CPU ");
    AppendU64(g_header_text, &lp, sizeof(g_header_text), latest.cpu_pct);
    AppendStr(g_header_text, &lp, sizeof(g_header_text), "%  UPTIME ");
    AppendUptime(g_header_text, &lp, sizeof(g_header_text), time::TickCount(), time::TickHz());
    AppendStr(g_header_text, &lp, sizeof(g_header_text), "  WIN ");
    AppendU64(g_header_text, &lp, sizeof(g_header_text), latest.alive_windows);
    AppendStr(g_header_text, &lp, sizeof(g_header_text), "  POOL ");
    AppendBytes(g_header_text, &lp, sizeof(g_header_text), h.pool_bytes);
    g_header_text[(lp < sizeof(g_header_text)) ? lp : sizeof(g_header_text) - 1] = '\0';
}

void RefreshSysmonDetail()
{
    const Sample latest = (g_state.count > 0) ? RingAt(0) : Sample{};
    const auto h = mm::KernelHeapStatsRead();
    u32 lp = 0;
    AppendStr(g_detail_text, &lp, sizeof(g_detail_text), "USED ");
    AppendBytes(g_detail_text, &lp, sizeof(g_detail_text), h.used_bytes);
    AppendStr(g_detail_text, &lp, sizeof(g_detail_text), " (");
    AppendU64(g_detail_text, &lp, sizeof(g_detail_text), latest.heap_used_pct);
    AppendStr(g_detail_text, &lp, sizeof(g_detail_text), "%)  FREE ");
    AppendBytes(g_detail_text, &lp, sizeof(g_detail_text), h.free_bytes);
    AppendStr(g_detail_text, &lp, sizeof(g_detail_text), "  FRAG ");
    AppendU64(g_detail_text, &lp, sizeof(g_detail_text), h.free_chunk_count);
    g_detail_text[(lp < sizeof(g_detail_text)) ? lp : sizeof(g_detail_text) - 1] = '\0';
}

void RefreshSysmonFooter()
{
    static const char kHint[] = "SAMPLE=push now   CLEAR=reset ring   (kbd: R/C)";
    u32 i = 0;
    for (; kHint[i] != '\0' && i + 1 < sizeof(g_footer_text); ++i)
        g_footer_text[i] = kHint[i];
    g_footer_text[i] = '\0';
}

// Forwarding helper to keep SysmonTick / SysmonFeedChar from
// repeating the collect-then-push pattern. Stays in the
// anonymous namespace.
void PushNewSample()
{
    RingPush(CollectSample());
}

// ----- Pass D click trampolines --------------------------------
// AppButton::on_click is a plain `void (*)()` so the constinit
// g_sysmon above captures them by function-pointer value. SAMPLE
// pushes one new sample (mirrors the F5 / 'r' kbd shortcut),
// CLEAR resets the ring (mirrors the 'c' kbd shortcut). Both
// mutate only the sysmon-local ring — no cross-subsystem state
// touched.

void ClickSample()
{
    PushNewSample();
    duetos::drivers::video::NotifyShow("sysmon: sampled");
}

void ClickClear()
{
    RingClear();
    duetos::drivers::video::NotifyShow("sysmon: ring cleared");
}

// Render a compact per-core CPU% row: one "CN NN%" text badge per
// CPU, laid out horizontally. Each badge is a fixed-width cell so the
// row looks tabular regardless of the digit count. Height = kRowH.
// Called inside PaintSysmonContent after the CPU sparkline chart.
void PaintPerCoreBars(u32 x, u32 y, u32 w, const Sample& latest, u32 bg)
{
    constexpr u32 kCoreColW = 56; // px per core cell (label + 3-digit % + gap)
    const auto& th = ThemeCurrent();
    const u32 dim = th.banner_fg;

    const u32 n = (latest.core_count < kSysmonMaxCores) ? latest.core_count : kSysmonMaxCores;
    if (n == 0)
        return;

    u32 col_x = x;
    for (u32 c = 0; c < n && col_x + kCoreColW <= x + w; ++c)
    {
        // Build "C<n> NNN%" string.
        char cell[12];
        u32 cp = 0;
        cell[cp++] = 'C';
        cell[cp++] = static_cast<char>('0' + (c < 9 ? c : 9));
        cell[cp++] = ' ';
        const u8 pct = latest.core_pct[c];
        AppendU64(cell, &cp, sizeof(cell), pct);
        cell[cp++] = '%';
        cell[(cp < sizeof(cell)) ? cp : sizeof(cell) - 1] = '\0';

        // Colour: green if <30%, amber if <70%, red if >=70% — gives a
        // quick at-a-glance read without needing per-core sparklines.
        u32 fg = (pct >= 70) ? 0x00F06060U : (pct >= 30) ? 0x00E0A040U : 0x0050C050U;
        // Dim cores that show 0% (offline or never ticked) to grey.
        if (pct == 0)
            fg = dim;

        FramebufferDrawString(col_x, y, cell, fg, bg);
        col_x += kCoreColW;
    }
}

// Paint the raw sparkline content (carve-out) inside the band
// DrawFn carves out between the detail label at the top and the
// AppLabel footer at the bottom.
void PaintSysmonContent(u32 cx, u32 cy, u32 cw, u32 ch)
{
    constexpr u32 kBg = 0x00101828U;
    const auto& th = ThemeCurrent();
    const u32 dim = th.banner_fg;
    const u32 axis_rgb = 0x00404858;
    const u32 trace_cpu = 0x0040A0F0;  // blue — CPU-busy trace (the headline metric)
    const u32 trace_used = 0x0050C050; // green — heap-used trace
    const u32 trace_frag = 0x00E0A040; // amber — fragmentation trace
    FramebufferFillRect(cx, cy, cw, ch, kBg);

    // Layout: three stacked sparkline panels (CPU / HEAP USED / FRAG)
    // with a caption row above each. The CPU panel also gets a
    // per-core bar row between its caption and its sparkline so an
    // operator can see CPU0 vs CPU1 (etc.) differentiation.
    const u32 panels_w = (cw > 2 * kPad) ? cw - 2 * kPad : cw;
    const u32 gaps_total = 2 * kPanelGap;
    const u32 panel_h = (ch > gaps_total) ? (ch - gaps_total) / 3 : 0;
    if (panel_h > 8)
    {
        const Sample latest = (g_state.count > 0) ? RingAt(0) : Sample{};

        // ---- CPU panel ----
        // Caption line: "CPU NN%"
        char cpu_cap[20];
        u32 cp = 0;
        AppendStr(cpu_cap, &cp, sizeof(cpu_cap), "CPU ");
        AppendU64(cpu_cap, &cp, sizeof(cpu_cap), latest.cpu_pct);
        AppendStr(cpu_cap, &cp, sizeof(cpu_cap), "%");
        cpu_cap[(cp < sizeof(cpu_cap)) ? cp : sizeof(cpu_cap) - 1] = '\0';

        const u32 cpu_top = cy;
        FramebufferDrawString(cx + kPad, cpu_top, cpu_cap, dim, kBg);

        // Per-core bar row (F-023). Sits between the caption and the
        // sparkline. Consumes kRowH pixels; sparkline claims the rest.
        const u32 core_row_y = cpu_top + kRowH;
        PaintPerCoreBars(cx + kPad, core_row_y, panels_w, latest, kBg);

        // Sparkline starts one row lower to make room for the per-core
        // badges. Guard: only shrink if there's still room for a graph.
        const u32 sparkline_y = core_row_y + kRowH;
        const u32 sparkline_h = (panel_h > 2 * kRowH) ? panel_h - 2 * kRowH : 0;
        if (sparkline_h > 0)
        {
            PaintSparkline(cx + kPad, sparkline_y, panels_w, sparkline_h, trace_cpu, axis_rgb,
                           [](const Sample& s) -> u8 { return s.cpu_pct; });
        }

        // ---- HEAP USED panel ----
        const u32 panel_top = cpu_top + panel_h + kPanelGap;
        FramebufferDrawString(cx + kPad, panel_top, "HEAP USED %", dim, kBg);
        PaintSparkline(cx + kPad, panel_top + kRowH, panels_w, panel_h - kRowH, trace_used, axis_rgb,
                       [](const Sample& s) -> u8 { return s.heap_used_pct; });

        // ---- FRAGMENTATION panel ----
        const u32 panel2_top = panel_top + panel_h + kPanelGap;
        FramebufferDrawString(cx + kPad, panel2_top, "FRAGMENTATION", dim, kBg);
        PaintSparkline(cx + kPad, panel2_top + kRowH, panels_w, panel_h - kRowH, trace_frag, axis_rgb,
                       [](const Sample& s) -> u8 { return s.frag_score; });
    }
}

void DrawFn(u32 cx, u32 cy, u32 cw, u32 ch, void* /*cookie*/)
{
    constexpr u32 kBg = 0x00101828U;
    FramebufferFillRect(cx, cy, cw, ch, kBg);

    // Pass D chrome: refresh the header / detail / footer text
    // from live state, re-anchor the toolbar / labels to the
    // current client rect, and paint the WidgetGroup. The raw
    // sparkline panels (carve-out) sit in the band between the
    // detail label and the AppLabel footer.
    BindSysmonOnce();
    RefreshSysmonHeader();
    RefreshSysmonDetail();
    RefreshSysmonFooter();
    RebindSysmonBounds(cx, cy, cw, ch);

    Compose compose_ctx{};
    g_sysmon.PaintAll(compose_ctx);

    // Content band — between (toolbar + header + detail) at the
    // top and the AppLabel footer at the bottom.
    const u32 top_band = kSmToolbarH + kSmHeaderH + kSmDetailH + kPad;
    const u32 bot_band = kSmFooterH + kPad;
    const u32 list_x = cx;
    const u32 list_y = cy + top_band;
    const u32 list_w = cw;
    const u32 list_h = (ch > top_band + bot_band) ? (ch - top_band - bot_band) : 0;
    if (list_h > 0)
    {
        PaintSysmonContent(list_x, list_y, list_w, list_h);
    }
}

} // namespace

void SysmonInit(WindowHandle handle)
{
    g_state.handle = handle;
    g_state.head = 0;
    g_state.count = 0;
    g_state.initted = true;
    WindowSetContentDraw(handle, DrawFn, nullptr);
    BindSysmonOnce();
}

WindowHandle SysmonWindow()
{
    return g_state.handle;
}

void SysmonTick()
{
    if (!g_state.initted)
        return;
    PushNewSample();
}

bool SysmonFeedChar(char c)
{
    if (c == 'c' || c == 'C')
    {
        RingClear();
        return true;
    }
    // F5 arrives as char 0x14 in the kbd reader's "non-ASCII char"
    // slot — but we'd rather expose F5 via a dedicated arrow path.
    // For now, also accept 'r' / 'R' as a force-refresh shortcut.
    if (c == 'r' || c == 'R')
    {
        PushNewSample();
        return true;
    }
    return false;
}

void SysmonSelfTest()
{
    using arch::SerialWrite;
    // Save state so the operator's view (if Init already ran) is
    // not clobbered.
    const State save = g_state;
    g_state = State{};
    g_state.initted = true;

    bool ok = true;

    // Empty ring.
    ok = ok && (g_state.count == 0);
    Sample empty = RingAt(0);
    ok = ok && (empty.heap_used_pct == 0);

    // Push three known samples and assert newest-first ordering.
    Sample a{};
    a.cpu_pct = 11;
    a.heap_used_pct = 10;
    a.frag_score = 5;
    a.alive_windows = 1;
    Sample b{};
    b.cpu_pct = 22;
    b.heap_used_pct = 20;
    b.frag_score = 15;
    b.alive_windows = 2;
    Sample c{};
    c.cpu_pct = 33;
    c.heap_used_pct = 30;
    c.frag_score = 25;
    c.alive_windows = 3;
    RingPush(a);
    RingPush(b);
    RingPush(c);
    ok = ok && (g_state.count == 3);
    ok = ok && (RingAt(0).heap_used_pct == 30 && RingAt(0).cpu_pct == 33);
    ok = ok && (RingAt(1).heap_used_pct == 20 && RingAt(1).cpu_pct == 22);
    ok = ok && (RingAt(2).heap_used_pct == 10 && RingAt(2).cpu_pct == 11);

    // Wrap: push enough to evict the oldest.
    for (u32 i = 0; i < kSysmonRingDepth; ++i)
    {
        Sample s{};
        s.heap_used_pct = static_cast<u8>(i % 100);
        RingPush(s);
    }
    ok = ok && (g_state.count == kSysmonRingDepth);
    // Newest pushed value was kSysmonRingDepth - 1.
    ok = ok && (RingAt(0).heap_used_pct == static_cast<u8>((kSysmonRingDepth - 1) % 100));

    // Clear.
    RingClear();
    ok = ok && (g_state.count == 0);

    // Pass D: drive a synthetic click on each toolbar button via
    // the WidgetGroup dispatch chain. SAMPLE pushes one new
    // sample (collected from live heap state); CLEAR resets the
    // ring. Both are sysmon-local mutations of g_state.ring —
    // the surrounding `save` / `g_state = State{}` / restore
    // dance prevents leakage into the operator's view.
    BindSysmonOnce();
    // Anchor the toolbar at (0, 22, 380, 258) — same shape
    // boot_bringup.cpp registers the live sysmon window with
    // (380x280 minus 22 px title bar). Buttons sit at indices
    // 0 (SAMPLE) and 1 (CLEAR).
    RebindSysmonBounds(0U, 22U, 380U, 258U);

    auto click_button = [&ok](u32 btn_idx)
    {
        const u32 nx = kSmToolbarPadX + btn_idx * (kSmToolbarBtnW + kSmToolbarBtnGap) + kSmToolbarBtnW / 2U;
        const u32 ny = 22U + kSmToolbarPadY + kSmToolbarBtnH / 2U;
        const Event move{EventKind::MouseMove, nx, ny, 0U, 0U};
        const Event down{EventKind::MouseDown, nx, ny, 0U, 0U};
        const Event up{EventKind::MouseUp, nx, ny, 0U, 0U};
        if (g_sysmon.DispatchEvent(move) != EventResult::Consumed)
            ok = false;
        if (g_sysmon.DispatchEvent(down) != EventResult::Consumed)
            ok = false;
        if (g_sysmon.DispatchEvent(up) != EventResult::Consumed)
            ok = false;
    };

    // SAMPLE: starts from empty ring, must produce count == 1.
    RingClear();
    click_button(0);
    ok = ok && (g_state.count == 1);

    // CLEAR: starts from non-empty ring (1 from SAMPLE above +
    // 2 manual pushes = 3), must produce count == 0.
    PushNewSample();
    PushNewSample();
    ok = ok && (g_state.count == 3);
    click_button(1);
    ok = ok && (g_state.count == 0);

    // Header / detail / footer composers must produce non-empty
    // text after a refresh.
    RefreshSysmonHeader();
    if (g_header_text[0] == '\0')
        ok = false;
    RefreshSysmonDetail();
    if (g_detail_text[0] == '\0')
        ok = false;
    RefreshSysmonFooter();
    if (g_footer_text[0] == '\0')
        ok = false;

    // F-023: verify the per-core accessor. CPU 0 (BSP) must always be
    // reachable. We do NOT require c0_total > 0 here because this
    // self-test runs before the LAPIC timer fires its first tick —
    // the structural invariants (accessor returns true, total >= idle)
    // are sufficient at this point in boot.
    {
        u64 c0_total = 0, c0_idle = 0;
        const bool cpu0_ok = ::duetos::sched::SchedStatsReadCpu(0, &c0_total, &c0_idle);
        ok = ok && cpu0_ok;
        // total_ticks >= idle_ticks is the invariant: idle is a
        // subset of total, so idle can never exceed total.
        if (cpu0_ok)
        {
            ok = ok && (c0_total >= c0_idle);
        }
        // A freshly-pushed sample must carry at least CPU0 in core_count.
        RingClear();
        PushNewSample();
        const Sample pushed = (g_state.count > 0) ? RingAt(0) : Sample{};
        ok = ok && (pushed.core_count >= 1);
    }

    // Restore.
    g_state = save;
    g_sysmon_self_test_passed = ok;
    SerialWrite(ok ? "[sysmon-selftest] PASS\n" : "[sysmon-selftest] FAIL\n");
}

bool SysmonSelfTestPassed()
{
    return g_sysmon_self_test_passed;
}

void SysmonMouseInput(duetos::u32 cx, duetos::u32 cy, duetos::u8 button_mask)
{
    using duetos::drivers::input::kMouseButtonLeft;
    if (g_state.handle == duetos::drivers::video::kWindowInvalid)
        return;
    duetos::u32 wx = 0, wy = 0, ww = 0, wh = 0;
    if (!duetos::drivers::video::WindowGetBounds(g_state.handle, &wx, &wy, &ww, &wh))
        return;
    // Title bar is 22 px; client origin sits below it. The
    // WidgetGroup dispatch path needs cursor coords in the same
    // frame RebindSysmonBounds anchors the chrome to.
    constexpr duetos::u32 kTitleH = 22U;
    if (wh <= kTitleH)
        return;
    const duetos::u32 client_y = wy + kTitleH;
    const duetos::u32 client_h = wh - kTitleH;
    BindSysmonOnce();
    RebindSysmonBounds(wx, client_y, ww, client_h);

    const bool left_down = (button_mask & kMouseButtonLeft) != 0;
    const bool press_edge = left_down && !g_sysmon_prev_left_down;
    const bool release_edge = !left_down && g_sysmon_prev_left_down;
    g_sysmon_prev_left_down = left_down;

    const bool inside_window = (cx >= wx && cx < wx + ww && cy >= client_y && cy < wy + wh);
    if (inside_window)
    {
        const Event m{EventKind::MouseMove, cx, cy, 0U, 0U};
        g_sysmon.DispatchEvent(m);
    }
    if (press_edge && inside_window)
    {
        // Carve-out: the raw sparkline panels sit below the
        // toolbar / header / detail rows the WidgetGroup owns.
        // DispatchEvent's hit-test naturally short-circuits when
        // the click misses the toolbar bounds — the sparkline
        // panels have no per-bar click semantics (the panels are
        // an at-a-glance visualisation; mutating actions are on
        // the toolbar SAMPLE / CLEAR buttons).
        const Event d{EventKind::MouseDown, cx, cy, 0U, 0U};
        g_sysmon.DispatchEvent(d);
    }
    if (release_edge)
    {
        // Always dispatch MouseUp so a button pressed inside the
        // toolbar and dragged off clears its Pressed flag.
        const Event u{EventKind::MouseUp, cx, cy, 0U, 0U};
        g_sysmon.DispatchEvent(u);
    }
}

} // namespace duetos::apps::sysmon
