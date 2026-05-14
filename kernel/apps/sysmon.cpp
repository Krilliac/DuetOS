#include "apps/sysmon.h"

#include "arch/x86_64/serial.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/theme.h"
#include "mm/kheap.h"
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

// One ring slot. Fields are sized to the values they hold; the
// ring uses a flat-array circular buffer indexed by (head + i)
// modulo kSysmonRingDepth.
struct Sample
{
    u8 heap_used_pct;  // 0..100
    u8 frag_score;     // 0..100, clamped from free_chunk_count
    u16 alive_windows; // 0..kMaxWindows (16) but width-friendly
};

struct State
{
    WindowHandle handle;
    Sample ring[kSysmonRingDepth];
    u32 head;  // next-write index
    u32 count; // populated entries (≤ kSysmonRingDepth)
    bool initted;
};

constinit State g_state = {kWindowInvalid, {}, 0, 0, false};

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
// Sparkline panel painter.
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

void DrawFn(u32 cx, u32 cy, u32 cw, u32 ch, void* /*cookie*/)
{
    const auto& th = ThemeCurrent();
    const u32 bg = 0x00101828;
    const u32 fg = th.console_fg;
    const u32 dim = th.banner_fg;
    const u32 axis_rgb = 0x00404858;
    const u32 trace_used = 0x0050C050; // green — heap-used trace
    const u32 trace_frag = 0x00E0A040; // amber — fragmentation trace
    FramebufferFillRect(cx, cy, cw, ch, bg);

    // Header: 2 text rows = uptime + heap line.
    const auto h = mm::KernelHeapStatsRead();
    const Sample latest = (g_state.count > 0) ? RingAt(0) : Sample{};
    char line[96];
    u32 lp = 0;
    AppendStr(line, &lp, sizeof(line), "UPTIME ");
    AppendUptime(line, &lp, sizeof(line), time::TickCount(), time::TickHz());
    AppendStr(line, &lp, sizeof(line), "  WIN ");
    AppendU64(line, &lp, sizeof(line), latest.alive_windows);
    AppendStr(line, &lp, sizeof(line), "  POOL ");
    AppendBytes(line, &lp, sizeof(line), h.pool_bytes);
    line[(lp < sizeof(line)) ? lp : sizeof(line) - 1] = '\0';
    FramebufferDrawString(cx + kPad, cy + kPad, line, fg, bg);

    lp = 0;
    AppendStr(line, &lp, sizeof(line), "USED ");
    AppendBytes(line, &lp, sizeof(line), h.used_bytes);
    AppendStr(line, &lp, sizeof(line), " (");
    AppendU64(line, &lp, sizeof(line), latest.heap_used_pct);
    AppendStr(line, &lp, sizeof(line), "%)  FREE ");
    AppendBytes(line, &lp, sizeof(line), h.free_bytes);
    AppendStr(line, &lp, sizeof(line), "  FRAG ");
    AppendU64(line, &lp, sizeof(line), h.free_chunk_count);
    line[(lp < sizeof(line)) ? lp : sizeof(line) - 1] = '\0';
    FramebufferDrawString(cx + kPad, cy + kPad + kRowH, line, dim, bg);

    // Two stacked sparkline panels.
    const u32 panel_top = cy + kPad + kRowH * 2 + kPad;
    const u32 footer_h = kRowH + kPad;
    const u32 panels_w = (cw > 2 * kPad) ? cw - 2 * kPad : cw;
    const u32 panels_h_total = (ch > (panel_top - cy) + footer_h) ? ch - (panel_top - cy) - footer_h : 0;
    const u32 panel_h = (panels_h_total > kPanelGap) ? (panels_h_total - kPanelGap) / 2 : 0;
    if (panel_h > 8)
    {
        // Caption row above each panel.
        FramebufferDrawString(cx + kPad, panel_top, "HEAP USED %", dim, bg);
        PaintSparkline(cx + kPad, panel_top + kRowH, panels_w, panel_h - kRowH, trace_used, axis_rgb,
                       [](const Sample& s) -> u8 { return s.heap_used_pct; });
        const u32 panel2_top = panel_top + panel_h + kPanelGap;
        FramebufferDrawString(cx + kPad, panel2_top, "FRAGMENTATION", dim, bg);
        PaintSparkline(cx + kPad, panel2_top + kRowH, panels_w, panel_h - kRowH, trace_frag, axis_rgb,
                       [](const Sample& s) -> u8 { return s.frag_score; });
    }

    // Footer hint.
    if (ch > kRowH + 2)
    {
        FramebufferDrawString(cx + kPad, cy + ch - kRowH - 1, "F5=SAMPLE NOW   C=CLEAR RING", dim, bg);
    }
}

// Forwarding helper to keep SysmonTick / SysmonFeedChar from
// repeating the collect-then-push pattern. Stays in the
// anonymous namespace.
void PushNewSample()
{
    RingPush(CollectSample());
}

} // namespace

void SysmonInit(WindowHandle handle)
{
    g_state.handle = handle;
    g_state.head = 0;
    g_state.count = 0;
    g_state.initted = true;
    WindowSetContentDraw(handle, DrawFn, nullptr);
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
    a.heap_used_pct = 10;
    a.frag_score = 5;
    a.alive_windows = 1;
    Sample b{};
    b.heap_used_pct = 20;
    b.frag_score = 15;
    b.alive_windows = 2;
    Sample c{};
    c.heap_used_pct = 30;
    c.frag_score = 25;
    c.alive_windows = 3;
    RingPush(a);
    RingPush(b);
    RingPush(c);
    ok = ok && (g_state.count == 3);
    ok = ok && (RingAt(0).heap_used_pct == 30);
    ok = ok && (RingAt(1).heap_used_pct == 20);
    ok = ok && (RingAt(2).heap_used_pct == 10);

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

    // Restore.
    g_state = save;
    SerialWrite(ok ? "[sysmon] self-test OK\n" : "[sysmon] self-test FAILED\n");
}

} // namespace duetos::apps::sysmon
