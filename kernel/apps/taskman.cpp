#include "apps/taskman.h"

#include "arch/x86_64/serial.h"
#include "arch/x86_64/timer.h"
#include "drivers/input/ps2kbd.h"
#include "drivers/input/ps2mouse.h"
#include "drivers/video/app_widgets/app_button.h"
#include "drivers/video/app_widgets/app_label.h"
#include "drivers/video/app_widgets/app_toolbar.h"
#include "drivers/video/app_widgets/widget_group.h"
#include "drivers/video/dialog.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/notify.h"
#include "drivers/video/theme.h"
#include "mm/frame_allocator.h"
#include "sched/loadavg.h"
#include "sched/sched.h"

namespace duetos::apps::taskman
{

namespace
{

constexpr duetos::u32 kRowH = 10;    // 8x8 glyph + 2 px gap
constexpr duetos::u32 kHeaderH = 22; // header band: 2 lines
constexpr duetos::u32 kFooterH = 12; // hint footer
constexpr duetos::u32 kColPad = 6;   // left padding inside client

// Per-column character widths. The list view has five columns:
// PID (5 chars), NAME (16), STATE (5), CPU% (6), TICKS (10).
constexpr duetos::u32 kColPid = 5;
constexpr duetos::u32 kColName = 16;
constexpr duetos::u32 kColState = 5;
constexpr duetos::u32 kColCpu = 6;
constexpr duetos::u32 kColTicks = 10;

enum class SortMode : duetos::u8
{
    Cpu = 0,   // descending — highest CPU% at top
    Pid = 1,   // ascending
    Name = 2,  // ascending, case-insensitive
    State = 3, // Running > Ready > Sleeping > Blocked > Dead
    kCount = 4,
};

const char* SortModeName(SortMode m)
{
    switch (m)
    {
    case SortMode::Cpu:
        return "CPU%";
    case SortMode::Pid:
        return "PID ";
    case SortMode::Name:
        return "NAME";
    case SortMode::State:
        return "STAT";
    default:
        return "????";
    }
}

const char* StateGlyph(duetos::u8 state)
{
    using duetos::sched::TaskState;
    switch (static_cast<TaskState>(state))
    {
    case TaskState::Running:
        return "Run  ";
    case TaskState::Ready:
        return "Ready";
    case TaskState::Sleeping:
        return "Sleep";
    case TaskState::Blocked:
        return "Block";
    case TaskState::Dead:
        return "Dead ";
    default:
        return "?    ";
    }
}

// State priority for sort order. Higher = sorted earlier under
// SortMode::State (Running first, Dead last) — matches what an
// operator wants to see at a glance.
duetos::u8 StateSortKey(duetos::u8 state)
{
    using duetos::sched::TaskState;
    switch (static_cast<TaskState>(state))
    {
    case TaskState::Running:
        return 5;
    case TaskState::Ready:
        return 4;
    case TaskState::Sleeping:
        return 3;
    case TaskState::Blocked:
        return 2;
    case TaskState::Dead:
        return 1;
    default:
        return 0;
    }
}

// Snapshot of one task — copied out of SchedEnumerate's CLI
// window so the draw path can sort + render without holding
// the scheduler lock.
struct Row
{
    duetos::u64 task_id;
    duetos::u64 ticks_run;
    duetos::u64 owner_pid;
    char name[24];
    duetos::u8 state;
    duetos::u8 priority;
    bool is_running;
    bool has_process;
    duetos::u8 _pad[4];
};

// Module-private state. All of it is mutated under the
// compositor lock (caller holds it across DrawFn / FeedChar /
// FeedKey), so no extra locking is required.
constinit duetos::drivers::video::WindowHandle g_handle = duetos::drivers::video::kWindowInvalid;
constinit SortMode g_sort = SortMode::Cpu;
constinit duetos::u32 g_selected = 0;         // index into g_rows
constinit duetos::u32 g_first_visible = 0;    // top of viewport
constinit duetos::u32 g_row_count = 0;        // valid rows in g_rows
Row g_rows[kMaxRows];                         // last snapshot
constinit duetos::u64 g_total_ticks_snap = 1; // for CPU% denominator
constinit duetos::u64 g_idle_ticks_snap = 0;
constinit duetos::u64 g_kill_target_pid = 0; // pending kill-confirm

// View tabs. PROCESSES is the per-task list; PERFORMANCE is the
// system-wide line-graph view (Windows Resource Monitor-style).
// Cycle with Tab. Index into a tab name table for the title-bar
// suffix and the footer hint.
enum class Tab : duetos::u8
{
    Processes = 0,
    Performance = 1,
    kCount = 2,
};

constinit Tab g_tab = Tab::Processes;

const char* TabName(Tab t)
{
    switch (t)
    {
    case Tab::Processes:
        return "PROCESSES";
    case Tab::Performance:
        return "PERFORMANCE";
    default:
        return "?";
    }
}

// Sampling ring for the PERFORMANCE tab. Each entry is the
// instantaneous (delta-since-previous-sample) CPU busy percent
// and MEM used percent, in tenths of a percent (0..1000).
// `g_hist_head` is the index where the NEXT sample will land;
// `g_hist_count` saturates at kHistorySamples. The oldest
// sample is at `(g_hist_head - g_hist_count) mod N`.
struct HistorySample
{
    duetos::u16 cpu_tenths;
    duetos::u16 mem_tenths;
};

HistorySample g_history[kHistorySamples];
constinit duetos::u32 g_hist_head = 0;
constinit duetos::u32 g_hist_count = 0;

// Last sampled scheduler counters — used to compute the
// since-last-sample delta. Initialised to zero; first sample
// sees a delta from boot, which is fine for v0 — the curve
// settles into a real instantaneous reading after one tick.
constinit duetos::u64 g_last_total_ticks = 0;
constinit duetos::u64 g_last_idle_ticks = 0;
constinit duetos::u64 g_last_sample_tick = 0;

// Sampling cadence — minimum ticks between samples. The UI
// ticker repaints faster than once per second; rate-limiting
// here keeps the X-axis at 1 sample / second so the 60-sample
// ring covers a clean rolling minute. 100 ticks = 1 s at the
// kernel's 100 Hz scheduler tick.
constexpr duetos::u64 kSampleIntervalTicks = 100;

// ---- Pass D chrome: AppToolbar header + 4 mode/action buttons +
// AppLabel status footer. The process list rows (5-column —
// PID / NAME / STATE / CPU% / TICKS, with selection highlight
// and bright-green ink for the on-CPU task) stay as raw paint
// (DrawRows + DrawHeader), and the Performance-tab sparkline
// stack stays raw paint too (DrawPerformance) — neither fits
// AppListRow's single-Body-label contract without losing visual
// fidelity. Same judgment Files (Task 10) applied: chrome
// migrates, content band stays raw.
//
// Layout: 26 px AppToolbar at the top of the content area with
// four 64-px-wide AppButtons inset 4 px (TASKS/PERF/SORT/REFRESH).
// Below: the legacy header line + per-tab content paint. At the
// bottom: an AppLabel(Caption) covers the dynamic hotkey hint
// the legacy footer used to paint inline.

constexpr duetos::u32 kHdrToolbarH = 26U;
constexpr duetos::u32 kHdrBtnW = 64U;
constexpr duetos::u32 kHdrBtnH = 20U;
constexpr duetos::u32 kHdrBtnGap = 4U;
constexpr duetos::u32 kHdrPadX = 4U;
constexpr duetos::u32 kHdrPadY = 3U;
constexpr duetos::u32 kFooterBandH = 12U;
constexpr duetos::u32 kFooterPadX = 4U;

// Number of toolbar buttons (TASKS / PERF / SORT / REFRESH).
// KILL deliberately omitted — that's a destructive action that
// opens a confirm dialog, and the kill flow needs a row
// selected first. The keyboard 'K' / Del shortcuts stay as the
// only entry point so a stray click on a tactile toolbar
// button can't accidentally arm a process kill.
constexpr duetos::u32 kHdrBtnCount = 4U;

// Index of the REFRESH button — used by the self-test to drive
// a synthetic click on a known-safe slot (REFRESH is idempotent
// and never escalates to a kill dialog or destructive op).
constexpr duetos::u32 kBtnRefresh = 3U;

// Static footer text buffer — AppLabel stores text by pointer
// so the buffer must outlive every Paint. Re-rendered each
// frame from RefreshTaskmanStatus() based on the active sort
// mode (the cycling hotkey hint shows which sort key is live).
constinit char g_footer_text[96] = {};

// Self-test result flag for the Pass D umbrella aggregator. True
// iff the most recent TaskmanSelfTest() invocation ran every
// check (including the synthetic toolbar-button click) without
// error.
constinit bool g_self_test_passed = false;

// Mouse-state edge detector for TaskmanMouseInput. The existing
// keyboard surface (TaskmanFeedChar / TaskmanFeedKey) and the
// wheel handler stay the kernel's source of truth for selection
// + tab cycling — this only drives the toolbar widget chain so
// AppButton hover + press tracking works on tactility themes.
constinit bool g_prev_left_down = false;

// Toolbar click trampolines — AppButton's on_click is a plain
// `void (*)()` so we route through file-scope wrappers that
// re-enter TaskmanFeedChar with the matching keybind. Defined
// below; forward-declared so the constinit g_taskman (which
// captures them by function-pointer value) can be initialised.
void ClickTasksTab();
void ClickPerfTab();
void ClickSort();
void ClickRefresh();

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

// Toolbar first (back), then the 4 buttons in tab/action order,
// then the footer AppLabel last (overlays the bottom hint band).
// Reverse declaration order is the dispatch order, so buttons
// get first refusal on the click — exactly what we want.
constinit auto g_taskman =
    MakeWidgetGroup(AppToolbar{}, AppButton{}, AppButton{}, AppButton{}, AppButton{}, AppLabel{});

constinit bool g_taskman_bound = false;

// Walk the recursive WidgetChain by hand to grab a stable
// pointer to each button. The chain order matches the
// MakeWidgetGroup argument list: head = AppToolbar, then 4
// AppButton nodes, then the AppLabel.
AppButton* HdrButton(duetos::u32 i)
{
    auto& a = g_taskman.chain.tail; // toolbar -> btn[0]
    auto& b = a.tail;               // btn[0] -> btn[1]
    auto& c2 = b.tail;              // btn[1] -> btn[2]
    auto& d = c2.tail;              // btn[2] -> btn[3]
    AppButton* btns[kHdrBtnCount] = {&a.head, &b.head, &c2.head, &d.head};
    return btns[i];
}

void BindTaskmanOnce()
{
    if (g_taskman_bound)
        return;
    g_taskman_bound = true;

    auto& toolbar = g_taskman.chain.head;
    toolbar.bg_rgb = 0; // theme.taskbar_bg

    static const char* const kLabels[kHdrBtnCount] = {"TASKS", "PERF", "SORT", "REFRESH"};
    using ClickFn = void (*)();
    static constexpr ClickFn kClicks[kHdrBtnCount] = {ClickTasksTab, ClickPerfTab, ClickSort, ClickRefresh};
    for (duetos::u32 i = 0; i < kHdrBtnCount; ++i)
    {
        AppButton* btn = HdrButton(i);
        btn->label = kLabels[i];
        btn->on_click = kClicks[i];
        btn->weight = ChromeTextWeight::Regular;
        btn->bg_rgb = 0; // theme role default
        btn->fg_rgb = 0x00101828U;
    }

    auto& label = g_taskman.chain.tail.tail.tail.tail.tail.head;
    label.text = g_footer_text;
    label.role = ChromeTextRole::Caption;
    label.weight = ChromeTextWeight::Regular;
    label.fg_rgb = 0x00181828U;
    label.bg_rgb = 0x00C8C8B8U; // status band tone
    label.align_left = true;
}

// Re-anchor the toolbar + buttons + footer label to the live
// window's client rect. Called from DrawFn before PaintAll and
// from TaskmanMouseInput before DispatchEvent so hit-tests +
// visuals stay consistent across window moves / resizes.
void RebindTaskmanBounds(duetos::u32 cx, duetos::u32 cy, duetos::u32 cw, duetos::u32 ch)
{
    auto& toolbar = g_taskman.chain.head;
    toolbar.bounds = Rect{cx, cy, cw, kHdrToolbarH};

    for (duetos::u32 i = 0; i < kHdrBtnCount; ++i)
    {
        HdrButton(i)->bounds = Rect{cx + kHdrPadX + i * (kHdrBtnW + kHdrBtnGap), cy + kHdrPadY, kHdrBtnW, kHdrBtnH};
    }

    auto& label = g_taskman.chain.tail.tail.tail.tail.tail.head;
    const duetos::u32 fy = (ch > kFooterBandH) ? cy + ch - kFooterBandH : cy;
    const duetos::u32 fw = (cw > 2U * kFooterPadX) ? cw - 2U * kFooterPadX : cw;
    label.bounds = Rect{cx + kFooterPadX, fy, fw, kFooterBandH};
}

// Append `s` (NUL-terminated) onto `dst` at offset `*o`, capped
// at `cap - 1` bytes. Stops early if either runs out. Mirrors
// the Files RefreshFooterText helper shape so future passes can
// factor both into a shared util if a third app wants it.
void StatusAppend(char* dst, duetos::u32 cap, duetos::u32* o, const char* s)
{
    while (*s != '\0' && *o + 1 < cap)
    {
        dst[(*o)++] = *s++;
    }
}

// Re-compose g_footer_text from the active sort mode + tab.
// Called from DrawFn before PaintAll so the AppLabel sees the
// current frame's text. The legacy hotkey strip the inline
// footer used to paint moves here verbatim, with the live
// SORT- suffix updating per Tab cycle.
void RefreshTaskmanStatus()
{
    duetos::u32 o = 0;
    g_footer_text[0] = '\0';
    StatusAppend(g_footer_text, sizeof(g_footer_text), &o, "TAB:VIEW  UP/DN PGUP/PGDN  S:SORT-");
    StatusAppend(g_footer_text, sizeof(g_footer_text), &o, SortModeName(g_sort));
    StatusAppend(g_footer_text, sizeof(g_footer_text), &o, "  K:KILL  R:REFRESH");
    if (o < sizeof(g_footer_text))
        g_footer_text[o] = '\0';
    else
        g_footer_text[sizeof(g_footer_text) - 1] = '\0';
}

// String helpers — the kernel has no printf, so column
// formatting is done by hand. All formatters write at most
// `width` characters into `out` (NUL-terminated) and right- or
// left-align the value as documented.

void FmtU64Right(duetos::u64 v, char* out, duetos::u32 width)
{
    char tmp[24];
    duetos::u32 n = 0;
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
    duetos::u32 pad = (n < width) ? width - n : 0;
    duetos::u32 o = 0;
    for (duetos::u32 i = 0; i < pad && o < width; ++i)
        out[o++] = ' ';
    for (duetos::u32 i = 0; i < n && o < width; ++i)
        out[o++] = tmp[n - 1 - i];
    out[o] = '\0';
}

void FmtStrLeft(const char* s, char* out, duetos::u32 width)
{
    duetos::u32 o = 0;
    if (s != nullptr)
    {
        for (; o < width && s[o] != '\0'; ++o)
            out[o] = s[o];
    }
    while (o < width)
        out[o++] = ' ';
    out[o] = '\0';
}

// "%6s" for "  0.0" / " 12.3" / "100.0" — three integer digits
// + decimal + tenth, right-padded to 6. CPU% rolls over at
// 999.9% which never happens (single CPU bound).
void FmtCpuPercent(duetos::u64 num_ticks, duetos::u64 denom_ticks, char* out, duetos::u32 width)
{
    if (denom_ticks == 0)
        denom_ticks = 1;
    // Integer-only fixed-point: tenths of a percent.
    duetos::u64 tenths = (num_ticks * 1000ull) / denom_ticks;
    if (tenths > 9999ull)
        tenths = 9999ull;
    char tmp[8];
    duetos::u32 n = 0;
    const duetos::u64 whole = tenths / 10;
    const duetos::u64 frac = tenths % 10;
    if (whole == 0)
    {
        tmp[n++] = '0';
    }
    else
    {
        char digits[6];
        duetos::u32 d = 0;
        duetos::u64 v = whole;
        while (v > 0 && d < sizeof(digits))
        {
            digits[d++] = static_cast<char>('0' + (v % 10));
            v /= 10;
        }
        while (d > 0)
            tmp[n++] = digits[--d];
    }
    tmp[n++] = '.';
    tmp[n++] = static_cast<char>('0' + frac);
    duetos::u32 pad = (n < width) ? width - n : 0;
    duetos::u32 o = 0;
    for (duetos::u32 i = 0; i < pad && o < width; ++i)
        out[o++] = ' ';
    for (duetos::u32 i = 0; i < n && o < width; ++i)
        out[o++] = tmp[i];
    out[o] = '\0';
}

// SchedEnumerate callback: copy the task info into g_rows[].
void OnEnumTask(const duetos::sched::SchedTaskInfo& info, void* /*cookie*/)
{
    if (g_row_count >= kMaxRows)
        return;
    Row& r = g_rows[g_row_count++];
    r.task_id = info.id;
    r.ticks_run = info.ticks_run;
    r.owner_pid = info.has_process ? info.owner_pid : 0;
    r.state = info.state;
    r.priority = info.priority;
    r.is_running = info.is_running;
    r.has_process = info.has_process;
    duetos::u32 o = 0;
    if (info.name != nullptr)
    {
        for (; o + 1 < sizeof(r.name) && info.name[o] != '\0'; ++o)
            r.name[o] = info.name[o];
    }
    else
    {
        const char* nullname = "<noname>";
        for (; o + 1 < sizeof(r.name) && nullname[o] != '\0'; ++o)
            r.name[o] = nullname[o];
    }
    r.name[o] = '\0';
}

// Case-insensitive ASCII compare. Used by SortMode::Name. Returns
// negative / 0 / positive in the strcmp sense.
int CompareNamesCi(const char* a, const char* b)
{
    while (*a != '\0' && *b != '\0')
    {
        char ca = *a;
        char cb = *b;
        if (ca >= 'a' && ca <= 'z')
            ca = static_cast<char>(ca - 32);
        if (cb >= 'a' && cb <= 'z')
            cb = static_cast<char>(cb - 32);
        if (ca != cb)
            return static_cast<int>(static_cast<unsigned char>(ca)) - static_cast<int>(static_cast<unsigned char>(cb));
        ++a;
        ++b;
    }
    if (*a == *b)
        return 0;
    return *a == '\0' ? -1 : 1;
}

// Sort comparator for SortMode `m`. Returns true iff `a` should
// come before `b` in the sorted listing. Tie-breaks on task_id
// so the order is stable across redraws even when two tasks
// share the primary key.
bool RowLess(const Row& a, const Row& b, SortMode m)
{
    switch (m)
    {
    case SortMode::Cpu:
        if (a.ticks_run != b.ticks_run)
            return a.ticks_run > b.ticks_run; // descending
        return a.task_id < b.task_id;
    case SortMode::Pid:
    {
        const duetos::u64 ka = a.has_process ? a.owner_pid : (~0ull >> 1);
        const duetos::u64 kb = b.has_process ? b.owner_pid : (~0ull >> 1);
        if (ka != kb)
            return ka < kb;
        return a.task_id < b.task_id;
    }
    case SortMode::Name:
    {
        const int c = CompareNamesCi(a.name, b.name);
        if (c != 0)
            return c < 0;
        return a.task_id < b.task_id;
    }
    case SortMode::State:
    {
        const duetos::u8 ka = StateSortKey(a.state);
        const duetos::u8 kb = StateSortKey(b.state);
        if (ka != kb)
            return ka > kb; // higher key first
        return a.task_id < b.task_id;
    }
    default:
        return a.task_id < b.task_id;
    }
}

// In-place insertion sort. The list is small (≤ kMaxRows = 128)
// and nearly-sorted across consecutive frames (sort key changes
// slowly), so insertion sort is the right pick: O(n) on already-
// sorted data, O(n²) worst case, no recursion, no allocator.
void SortRows()
{
    for (duetos::u32 i = 1; i < g_row_count; ++i)
    {
        Row tmp = g_rows[i];
        duetos::u32 j = i;
        while (j > 0 && RowLess(tmp, g_rows[j - 1], g_sort))
        {
            g_rows[j] = g_rows[j - 1];
            --j;
        }
        g_rows[j] = tmp;
    }
}

void RebuildSnapshot()
{
    g_row_count = 0;
    duetos::sched::SchedEnumerate(&OnEnumTask, nullptr);
    const auto stats = duetos::sched::SchedStatsRead();
    g_total_ticks_snap = stats.total_ticks == 0 ? 1 : stats.total_ticks;
    g_idle_ticks_snap = stats.idle_ticks;
    SortRows();
    if (g_selected >= g_row_count)
        g_selected = g_row_count == 0 ? 0 : g_row_count - 1;
}

// Append one HistorySample to the ring if at least
// kSampleIntervalTicks have elapsed since the last sample.
// Cheap (unconditional read of stats + memory). Called from
// DrawFn before the tab body draws so the most recent sample
// is the rightmost point on the graph.
void MaybeSampleHistory()
{
    const duetos::u64 now = duetos::arch::TimerTicks();
    if (g_last_sample_tick != 0 && (now - g_last_sample_tick) < kSampleIntervalTicks)
        return;

    const auto stats = duetos::sched::SchedStatsRead();
    duetos::u16 cpu_tenths = 0;
    if (g_last_total_ticks != 0 && stats.total_ticks > g_last_total_ticks)
    {
        const duetos::u64 d_total = stats.total_ticks - g_last_total_ticks;
        const duetos::u64 d_idle = (stats.idle_ticks > g_last_idle_ticks) ? stats.idle_ticks - g_last_idle_ticks : 0;
        const duetos::u64 d_busy = d_total > d_idle ? d_total - d_idle : 0;
        duetos::u64 t = (d_busy * 1000ull) / (d_total == 0 ? 1ull : d_total);
        if (t > 1000ull)
            t = 1000ull;
        cpu_tenths = static_cast<duetos::u16>(t);
    }

    const duetos::u64 total = duetos::mm::TotalFrames();
    const duetos::u64 freef = duetos::mm::FreeFramesCount();
    const duetos::u64 used = (total > freef) ? total - freef : 0;
    duetos::u64 m = (total == 0) ? 0 : (used * 1000ull) / total;
    if (m > 1000ull)
        m = 1000ull;
    const duetos::u16 mem_tenths = static_cast<duetos::u16>(m);

    g_history[g_hist_head].cpu_tenths = cpu_tenths;
    g_history[g_hist_head].mem_tenths = mem_tenths;
    g_hist_head = (g_hist_head + 1) % kHistorySamples;
    if (g_hist_count < kHistorySamples)
        ++g_hist_count;

    g_last_total_ticks = stats.total_ticks;
    g_last_idle_ticks = stats.idle_ticks;
    g_last_sample_tick = now;
}

// ---------------------------------------------------------------
// Draw — header band, sortable column headings, scrollable rows,
// footer hint. Called from the compositor with the client-area
// rectangle; we never paint outside it.
// ---------------------------------------------------------------

void DrawHeader(duetos::u32 cx, duetos::u32 cy, duetos::u32 cw, duetos::u32 fg, duetos::u32 hl, duetos::u32 bg)
{
    using duetos::drivers::video::FramebufferDrawString;
    using duetos::drivers::video::FramebufferFillRect;
    FramebufferFillRect(cx, cy, cw, kHeaderH, bg);

    // Line 1: aggregate stats.
    //   "CPU 12.3%  IDLE 87.7%  MEM 1234/4096  TASKS 23"
    // Numbers are computed from the snapshot we just rebuilt.
    char num_cpu[8];
    char num_idle[8];
    const duetos::u64 nonidle = g_total_ticks_snap > g_idle_ticks_snap ? g_total_ticks_snap - g_idle_ticks_snap : 0;
    FmtCpuPercent(nonidle, g_total_ticks_snap, num_cpu, sizeof(num_cpu) - 1);
    FmtCpuPercent(g_idle_ticks_snap, g_total_ticks_snap, num_idle, sizeof(num_idle) - 1);
    char num_free[8];
    char num_total[8];
    const duetos::u64 free_kib = duetos::mm::FreeFramesCount() * 4ull; // 4 KiB / frame
    const duetos::u64 total_kib = duetos::mm::TotalFrames() * 4ull;
    FmtU64Right(free_kib / 1024ull, num_free, sizeof(num_free) - 1); // MiB
    FmtU64Right(total_kib / 1024ull, num_total, sizeof(num_total) - 1);
    char num_tasks[6];
    FmtU64Right(g_row_count, num_tasks, sizeof(num_tasks) - 1);

    char line[80];
    duetos::u32 o = 0;
    auto append = [&](const char* s)
    {
        while (*s != '\0' && o + 1 < sizeof(line))
            line[o++] = *s++;
    };
    append("[");
    append(TabName(g_tab));
    append("]  CPU ");
    append(num_cpu);
    append("%  IDLE ");
    append(num_idle);
    append("%  MEM ");
    append(num_free);
    append("/");
    append(num_total);
    append(" MIB  TASKS ");
    append(num_tasks);
    line[o] = '\0';
    FramebufferDrawString(cx + kColPad, cy + 2, line, fg, bg);

    // Line 2: column headers (PROCESSES tab only — the
    // PERFORMANCE tab paints labels inside the graph stack).
    if (g_tab != Tab::Processes)
        return;
    char col_pid[8];
    char col_name[24];
    char col_state[8];
    char col_cpu[8];
    char col_ticks[16];
    FmtStrLeft("PID", col_pid, kColPid);
    FmtStrLeft("NAME", col_name, kColName);
    FmtStrLeft("STATE", col_state, kColState);
    FmtStrLeft("  CPU%", col_cpu, kColCpu);
    FmtStrLeft("     TICKS", col_ticks, kColTicks);

    duetos::u32 x = cx + kColPad;
    const duetos::u32 y = cy + 12;
    auto draw_col = [&](const char* s, duetos::u32 w, SortMode key)
    {
        const duetos::u32 c = (g_sort == key) ? hl : fg;
        FramebufferDrawString(x, y, s, c, bg);
        x += w * 8 + 4;
    };
    draw_col(col_pid, kColPid, SortMode::Pid);
    draw_col(col_name, kColName, SortMode::Name);
    draw_col(col_state, kColState, SortMode::State);
    draw_col(col_cpu, kColCpu, SortMode::Cpu);
    FramebufferDrawString(x, y, col_ticks, fg, bg);
}

void DrawRows(duetos::u32 cx, duetos::u32 cy, duetos::u32 cw, duetos::u32 ch, duetos::u32 fg, duetos::u32 fg_run,
              duetos::u32 sel_bg, duetos::u32 bg)
{
    using duetos::drivers::video::FramebufferDrawString;
    using duetos::drivers::video::FramebufferFillRect;

    const duetos::u32 list_y = cy + kHeaderH;
    const duetos::u32 list_h = (ch > kHeaderH + kFooterH) ? ch - kHeaderH - kFooterH : 0;
    FramebufferFillRect(cx, list_y, cw, list_h, bg);

    if (g_row_count == 0 || list_h < kRowH)
        return;

    const duetos::u32 visible = list_h / kRowH;
    // Keep the selection inside the viewport.
    if (g_selected < g_first_visible)
        g_first_visible = g_selected;
    else if (g_selected >= g_first_visible + visible)
        g_first_visible = g_selected - visible + 1;
    if (g_first_visible + visible > g_row_count)
        g_first_visible = (g_row_count > visible) ? g_row_count - visible : 0;

    for (duetos::u32 v = 0; v < visible && (g_first_visible + v) < g_row_count; ++v)
    {
        const duetos::u32 idx = g_first_visible + v;
        const Row& r = g_rows[idx];
        const duetos::u32 row_y = list_y + v * kRowH;
        const bool selected = (idx == g_selected);
        if (selected)
            FramebufferFillRect(cx, row_y, cw, kRowH, sel_bg);

        char col_pid[8];
        char col_name[24];
        char col_state[8];
        char col_cpu[8];
        char col_ticks[16];
        if (r.has_process)
            FmtU64Right(r.owner_pid, col_pid, kColPid);
        else
            FmtStrLeft("  --", col_pid, kColPid);
        FmtStrLeft(r.name, col_name, kColName);
        FmtStrLeft(StateGlyph(r.state), col_state, kColState);
        FmtCpuPercent(r.ticks_run, g_total_ticks_snap, col_cpu, kColCpu);
        FmtU64Right(r.ticks_run, col_ticks, kColTicks);

        const duetos::u32 row_bg = selected ? sel_bg : bg;
        const duetos::u32 row_fg = r.is_running ? fg_run : fg;
        duetos::u32 x = cx + kColPad;
        FramebufferDrawString(x, row_y + 1, col_pid, row_fg, row_bg);
        x += kColPid * 8 + 4;
        FramebufferDrawString(x, row_y + 1, col_name, row_fg, row_bg);
        x += kColName * 8 + 4;
        FramebufferDrawString(x, row_y + 1, col_state, row_fg, row_bg);
        x += kColState * 8 + 4;
        FramebufferDrawString(x, row_y + 1, col_cpu, row_fg, row_bg);
        x += kColCpu * 8 + 4;
        FramebufferDrawString(x, row_y + 1, col_ticks, row_fg, row_bg);
    }
}

// DrawFooter was the legacy inline footer painter. The hotkey
// hint moved to the Pass D AppLabel footer (RefreshTaskmanStatus
// + g_taskman.PaintAll), so the inline painter is no longer
// called. Deleted to avoid an -Wunused-function break under
// -Werror; the live composer lives in RefreshTaskmanStatus().

// Render a single line graph into a rectangle. `samples` is the
// kHistorySamples-long ring at `g_history`; `field_offset` picks
// which u16 field per HistorySample to plot. Y values are tenths
// of a percent (0..1000); X is sample index, oldest on the left.
// Draws a 1-px frame, a 25%/50%/75% horizontal gridline triplet,
// then connects each adjacent pair of samples with FramebufferDrawLine.
void DrawSparkline(duetos::u32 x, duetos::u32 y, duetos::u32 w, duetos::u32 h, duetos::u32 fg, duetos::u32 grid,
                   duetos::u32 frame, duetos::u32 fill, bool plot_cpu)
{
    using duetos::drivers::video::FramebufferDrawLine;
    using duetos::drivers::video::FramebufferFillRect;
    if (w < 4 || h < 4)
        return;
    FramebufferFillRect(x, y, w, h, fill);
    // Top + bottom + left + right frame, 1 px thick.
    FramebufferFillRect(x, y, w, 1, frame);
    FramebufferFillRect(x, y + h - 1, w, 1, frame);
    FramebufferFillRect(x, y, 1, h, frame);
    FramebufferFillRect(x + w - 1, y, 1, h, frame);
    // Gridlines at 25 / 50 / 75 percent.
    for (duetos::u32 q = 1; q <= 3; ++q)
    {
        const duetos::u32 gy = y + (h * q) / 4;
        FramebufferFillRect(x + 1, gy, w - 2, 1, grid);
    }
    if (g_hist_count < 2)
        return;
    // Plot oldest -> newest left-to-right. Step = w / kHistorySamples
    // gives a stable X spacing that doesn't depend on g_hist_count.
    const duetos::u32 plot_w = w - 2;
    const duetos::u32 plot_h = (h > 2) ? h - 2 : 0;
    const duetos::u32 ox = x + 1;
    const duetos::u32 oy = y + 1;
    auto sample_at = [&](duetos::u32 i) -> duetos::u16
    {
        // i = 0 -> oldest sample. The ring head points at the
        // NEXT slot to write, so the oldest is head when count
        // == N, and the (head - count) slot otherwise.
        const duetos::u32 first = (g_hist_head + kHistorySamples - g_hist_count) % kHistorySamples;
        const duetos::u32 idx = (first + i) % kHistorySamples;
        return plot_cpu ? g_history[idx].cpu_tenths : g_history[idx].mem_tenths;
    };
    auto x_of = [&](duetos::u32 i) -> duetos::i32
    { return static_cast<duetos::i32>(ox + (i * plot_w) / (kHistorySamples - 1)); };
    auto y_of = [&](duetos::u16 t) -> duetos::i32
    {
        // t in [0..1000]. y=oy at 100%, y=oy+plot_h at 0%.
        const duetos::u32 yy = oy + plot_h - (t * plot_h) / 1000u;
        return static_cast<duetos::i32>(yy);
    };
    for (duetos::u32 i = 1; i < g_hist_count; ++i)
    {
        const duetos::i32 x0 = x_of(i - 1 + (kHistorySamples - g_hist_count));
        const duetos::i32 y0 = y_of(sample_at(i - 1));
        const duetos::i32 x1 = x_of(i + (kHistorySamples - g_hist_count));
        const duetos::i32 y1 = y_of(sample_at(i));
        FramebufferDrawLine(x0, y0, x1, y1, fg);
    }
}

void DrawPerformance(duetos::u32 cx, duetos::u32 cy, duetos::u32 cw, duetos::u32 ch, duetos::u32 fg, duetos::u32 fg_cpu,
                     duetos::u32 fg_mem, duetos::u32 grid, duetos::u32 frame, duetos::u32 fill, duetos::u32 bg)
{
    using duetos::drivers::video::FramebufferDrawString;
    using duetos::drivers::video::FramebufferFillRect;
    const duetos::u32 list_y = cy + kHeaderH;
    const duetos::u32 list_h = (ch > kHeaderH + kFooterH) ? ch - kHeaderH - kFooterH : 0;
    FramebufferFillRect(cx, list_y, cw, list_h, bg);
    if (list_h < 60)
        return;

    // Two equal-height graph stacks with a 12-px label band each.
    const duetos::u32 stack_h = list_h / 2;
    const duetos::u32 lbl_h = 12;
    const duetos::u32 graph_h = (stack_h > lbl_h + 4) ? stack_h - lbl_h : stack_h;

    // CPU graph header — current % + peak % from the ring.
    duetos::u16 cur_cpu = 0;
    duetos::u16 peak_cpu = 0;
    duetos::u16 cur_mem = 0;
    duetos::u16 peak_mem = 0;
    if (g_hist_count > 0)
    {
        const duetos::u32 newest = (g_hist_head + kHistorySamples - 1) % kHistorySamples;
        cur_cpu = g_history[newest].cpu_tenths;
        cur_mem = g_history[newest].mem_tenths;
        for (duetos::u32 i = 0; i < g_hist_count; ++i)
        {
            const duetos::u32 idx = (g_hist_head + kHistorySamples - g_hist_count + i) % kHistorySamples;
            if (g_history[idx].cpu_tenths > peak_cpu)
                peak_cpu = g_history[idx].cpu_tenths;
            if (g_history[idx].mem_tenths > peak_mem)
                peak_mem = g_history[idx].mem_tenths;
        }
    }

    auto fmt_tenths = [](duetos::u16 t, char* out)
    {
        const duetos::u16 whole = t / 10;
        const duetos::u16 frac = t % 10;
        char tmp[6];
        duetos::u32 n = 0;
        if (whole == 0)
        {
            tmp[n++] = '0';
        }
        else
        {
            duetos::u16 v = whole;
            while (v > 0 && n < sizeof(tmp))
            {
                tmp[n++] = static_cast<char>('0' + (v % 10));
                v = static_cast<duetos::u16>(v / 10);
            }
        }
        duetos::u32 o = 0;
        while (n > 0)
            out[o++] = tmp[--n];
        out[o++] = '.';
        out[o++] = static_cast<char>('0' + frac);
        out[o++] = '%';
        out[o] = '\0';
    };

    char cur_buf[8];
    char peak_buf[8];
    char line[80];

    // CPU header.
    fmt_tenths(cur_cpu, cur_buf);
    fmt_tenths(peak_cpu, peak_buf);
    duetos::u32 o = 0;
    auto append = [&](const char* s)
    {
        while (*s != '\0' && o + 1 < sizeof(line))
            line[o++] = *s++;
    };
    append("CPU  cur ");
    append(cur_buf);
    append("  peak ");
    append(peak_buf);
    append("  (60 s)");
    line[o] = '\0';
    FramebufferDrawString(cx + kColPad, list_y + 2, line, fg_cpu, bg);
    DrawSparkline(cx + kColPad, list_y + lbl_h, cw - 2 * kColPad, graph_h, fg_cpu, grid, frame, fill, true);

    // MEM header.
    o = 0;
    fmt_tenths(cur_mem, cur_buf);
    fmt_tenths(peak_mem, peak_buf);
    const duetos::u64 total = duetos::mm::TotalFrames();
    const duetos::u64 freef = duetos::mm::FreeFramesCount();
    const duetos::u64 used_kib = (total > freef) ? (total - freef) * 4ull : 0;
    char num_used[10];
    char num_total[10];
    FmtU64Right(used_kib / 1024ull, num_used, 5);
    FmtU64Right(total * 4ull / 1024ull, num_total, 5);
    append("MEM  cur ");
    append(cur_buf);
    append("  peak ");
    append(peak_buf);
    append("  ");
    append(num_used);
    append("/");
    append(num_total);
    append(" MIB");
    line[o] = '\0';
    FramebufferDrawString(cx + kColPad, list_y + stack_h + 2, line, fg_mem, bg);
    DrawSparkline(cx + kColPad, list_y + stack_h + lbl_h, cw - 2 * kColPad, graph_h, fg_mem, grid, frame, fill, false);

    // Below the graphs (inside the footer band — the actual
    // footer is `OPENS / GRAPH / TASKS` below this) we draw
    // load averages on the left of the footer hint. Use the
    // same row the footer's hint occupies but on the left.
    duetos::u32 one = 0;
    duetos::u32 five = 0;
    duetos::u32 fifteen = 0;
    duetos::sched::LoadavgSnapshot(&one, &five, &fifteen);
    char buf1[12];
    char buf5[12];
    char buf15[12];
    duetos::sched::LoadavgFormat(buf1, sizeof(buf1), one);
    duetos::sched::LoadavgFormat(buf5, sizeof(buf5), five);
    duetos::sched::LoadavgFormat(buf15, sizeof(buf15), fifteen);
    o = 0;
    append("LOAD ");
    append(buf1);
    append(" / ");
    append(buf5);
    append(" / ");
    append(buf15);
    line[o] = '\0';
    if (ch >= kFooterH + 12)
        FramebufferDrawString(cx + kColPad, cy + ch - kFooterH - 12, line, fg, bg);
}

void DrawFn(duetos::u32 cx, duetos::u32 cy, duetos::u32 cw, duetos::u32 ch, void* /*cookie*/)
{
    using duetos::drivers::video::FramebufferFillRect;
    const auto& theme = duetos::drivers::video::ThemeCurrent();
    const duetos::u32 bg = theme.role_client[static_cast<duetos::u32>(duetos::drivers::video::ThemeRole::TaskManager)];
    constexpr duetos::u32 kFg = 0x00C8E0FF;    // soft-blue text
    constexpr duetos::u32 kFgRun = 0x0080FF80; // bright green for the on-CPU task
    constexpr duetos::u32 kFgCpu = 0x0080FF80; // CPU graph line
    constexpr duetos::u32 kFgMem = 0x00FFD060; // MEM graph line
    constexpr duetos::u32 kHl = 0x00FFD060;    // amber — active sort key
    constexpr duetos::u32 kSelBg = 0x00204060; // selected-row band
    constexpr duetos::u32 kGrid = 0x00203040;  // graph gridlines
    constexpr duetos::u32 kFrame = 0x00405070; // graph border
    constexpr duetos::u32 kFill = 0x00081020;  // graph background
    FramebufferFillRect(cx, cy, cw, ch, bg);

    MaybeSampleHistory();
    RebuildSnapshot();

    // Pass D chrome: AppToolbar at top (kHdrToolbarH), legacy
    // header + rows + perf-graph paint in the middle, AppLabel
    // footer at the bottom (kFooterBandH). The middle slice is
    // what DrawHeader / DrawRows / DrawPerformance receive.
    BindTaskmanOnce();
    RebindTaskmanBounds(cx, cy, cw, ch);
    RefreshTaskmanStatus();
    // Pre-paint the footer band tone so the AppLabel glyphs sit
    // on a uniform bg (AppLabel paints only its glyphs, not a
    // full-width band).
    if (ch > kFooterBandH)
    {
        FramebufferFillRect(cx, cy + ch - kFooterBandH, cw, kFooterBandH, 0x00C8C8B8U);
    }
    Compose compose_ctx{};
    g_taskman.PaintAll(compose_ctx);

    // Middle slice for the legacy content paint. kHdrToolbarH
    // off the top, kFooterBandH off the bottom. The legacy
    // DrawHeader expects to paint its own header band at the
    // top of the slice it receives; passing my/mh achieves
    // that without changing DrawHeader / DrawRows.
    const duetos::u32 my = cy + kHdrToolbarH;
    const duetos::u32 mh = (ch > kHdrToolbarH + kFooterBandH) ? ch - kHdrToolbarH - kFooterBandH : 0U;
    if (mh == 0)
        return;
    DrawHeader(cx, my, cw, kFg, kHl, bg);
    if (g_tab == Tab::Processes)
        DrawRows(cx, my, cw, mh, kFg, kFgRun, kSelBg, bg);
    else
        DrawPerformance(cx, my, cw, mh, kFg, kFgCpu, kFgMem, kGrid, kFrame, kFill, bg);
    // The legacy DrawFooter painted the hotkey hint inside the
    // middle slice. That hint moved to the AppLabel footer
    // (RefreshTaskmanStatus + PaintAll), so DrawFooter is no
    // longer called.
}

// ---- Pass D toolbar click trampolines (forward-declared above
// the constinit g_taskman). Each routes through the equivalent
// TaskmanFeedChar keybind so the click + key surfaces stay in
// lock-step automatically — adding a new keybind branch
// propagates to the button for free. KILL is deliberately NOT
// wired to a toolbar slot: that action needs a row selected and
// opens a confirm dialog, so it's safer left to the K / Del
// keyboard path where the user has already committed to acting
// on the selection.

void ClickTasksTab()
{
    // Cycle to PROCESSES tab. TaskmanFeedChar('\t') cycles
    // PROCESSES <-> PERFORMANCE; force-set instead so a click
    // on TASKS always lands on the tab a user expects regardless
    // of where the cycle was.
    g_tab = Tab::Processes;
}

void ClickPerfTab()
{
    g_tab = Tab::Performance;
}

void ClickSort()
{
    duetos::apps::taskman::TaskmanFeedChar('s');
}

void ClickRefresh()
{
    duetos::apps::taskman::TaskmanFeedChar('r');
}

// ---------------------------------------------------------------
// Public API + input handlers
// ---------------------------------------------------------------

// Kill-confirm callback. Fires from the kbd-reader after the
// user resolves the dialog. On Ok we hand the recorded PID to
// SchedKillByPid; on Cancel we drop the request.
void OnKillConfirm(duetos::drivers::video::DialogResult r, const char* /*text*/, void* /*user*/)
{
    if (r != duetos::drivers::video::DialogResult::Ok)
    {
        g_kill_target_pid = 0;
        return;
    }
    if (g_kill_target_pid == 0)
        return;
    const auto kr = duetos::sched::SchedKillByPid(g_kill_target_pid);
    duetos::drivers::video::NotifyShow(duetos::sched::KillResultName(kr));
    g_kill_target_pid = 0;
}

void OpenKillDialogForSelected()
{
    if (g_row_count == 0 || g_selected >= g_row_count)
        return;
    const Row& r = g_rows[g_selected];
    if (!r.has_process || r.owner_pid <= 1)
    {
        duetos::drivers::video::NotifyShow("taskman: protected task");
        return;
    }
    g_kill_target_pid = r.owner_pid;
    // Body is a static buffer — DialogOpen stores the pointer
    // by reference, so it must outlive the modal.
    static char body[64];
    duetos::u32 o = 0;
    auto append = [&](const char* s)
    {
        while (*s != '\0' && o + 1 < sizeof(body))
            body[o++] = *s++;
    };
    append("Kill PID ");
    char num[16];
    FmtU64Right(r.owner_pid, num, 1);
    // FmtU64Right left-pads — strip the lead spaces for the body.
    for (duetos::u32 i = 0; num[i] != '\0'; ++i)
    {
        if (num[i] != ' ' && o + 1 < sizeof(body))
            body[o++] = num[i];
    }
    append(" (");
    append(r.name);
    append(") ?");
    body[o] = '\0';
    duetos::drivers::video::MessageBoxOpen("TASK MANAGER", body, OnKillConfirm, nullptr);
}

} // namespace

void TaskmanInit(duetos::drivers::video::WindowHandle handle)
{
    g_handle = handle;
    duetos::drivers::video::WindowSetContentDraw(handle, DrawFn, nullptr);
    duetos::drivers::video::WindowSetWheelHandler(handle, &TaskmanOnWheel);
}

duetos::drivers::video::WindowHandle TaskmanWindow()
{
    return g_handle;
}

bool TaskmanFeedChar(char c)
{
    if (c == '\t')
    {
        // Cycle PROCESSES <-> PERFORMANCE.
        const auto next = static_cast<duetos::u8>(g_tab) + 1;
        g_tab = (next >= static_cast<duetos::u8>(Tab::kCount)) ? Tab::Processes : static_cast<Tab>(next);
        return true;
    }
    if (c == 's' || c == 'S')
    {
        const auto next = static_cast<duetos::u8>(g_sort) + 1;
        g_sort = (next >= static_cast<duetos::u8>(SortMode::kCount)) ? SortMode::Cpu : static_cast<SortMode>(next);
        return true;
    }
    if (c == 'r' || c == 'R')
    {
        // Force a fresh snapshot on next paint by clearing the
        // viewport offset so the new ordering shows from row 0.
        g_first_visible = 0;
        return true;
    }
    if (c == 'k' || c == 'K')
    {
        OpenKillDialogForSelected();
        return true;
    }
    return false;
}

bool TaskmanFeedKey(duetos::u16 keycode)
{
    if (g_row_count == 0)
        return false;
    switch (keycode)
    {
    case duetos::drivers::input::kKeyArrowUp:
        if (g_selected > 0)
            --g_selected;
        return true;
    case duetos::drivers::input::kKeyArrowDown:
        if (g_selected + 1 < g_row_count)
            ++g_selected;
        return true;
    case duetos::drivers::input::kKeyPageUp:
    {
        const duetos::u32 step = 8;
        g_selected = (g_selected > step) ? g_selected - step : 0;
        return true;
    }
    case duetos::drivers::input::kKeyPageDown:
    {
        const duetos::u32 step = 8;
        g_selected = (g_selected + step >= g_row_count) ? g_row_count - 1 : g_selected + step;
        return true;
    }
    case duetos::drivers::input::kKeyHome:
        g_selected = 0;
        return true;
    case duetos::drivers::input::kKeyEnd:
        g_selected = g_row_count - 1;
        return true;
    case duetos::drivers::input::kKeyDelete:
        OpenKillDialogForSelected();
        return true;
    default:
        return false;
    }
}

void TaskmanOnWheel(duetos::i32 dz, duetos::u8 /*modifiers*/)
{
    if (g_row_count == 0)
        return;
    if (dz > 0)
    {
        // Wheel up — step toward row 0.
        const duetos::u32 step = static_cast<duetos::u32>(dz);
        g_selected = (g_selected > step) ? g_selected - step : 0;
    }
    else if (dz < 0)
    {
        const duetos::u32 step = static_cast<duetos::u32>(-dz);
        g_selected = (g_selected + step >= g_row_count) ? g_row_count - 1 : g_selected + step;
    }
}

void TaskmanSelfTest()
{
    using duetos::arch::SerialWrite;
    bool pass = true;

    // Build a synthetic 4-row table and run each sort mode.
    Row saved[kMaxRows];
    for (duetos::u32 i = 0; i < kMaxRows; ++i)
        saved[i] = g_rows[i];
    const duetos::u32 saved_count = g_row_count;
    const SortMode saved_mode = g_sort;

    g_row_count = 4;
    auto fill = [](Row& r, duetos::u64 id, duetos::u64 pid, const char* name, duetos::u64 ticks, duetos::u8 state)
    {
        r.task_id = id;
        r.owner_pid = pid;
        r.has_process = pid != 0;
        duetos::u32 o = 0;
        for (; o + 1 < sizeof(r.name) && name[o] != '\0'; ++o)
            r.name[o] = name[o];
        r.name[o] = '\0';
        r.ticks_run = ticks;
        r.state = state;
        r.priority = 0;
        r.is_running = false;
    };
    using duetos::sched::TaskState;
    fill(g_rows[0], 1, 10, "boot", 5, static_cast<duetos::u8>(TaskState::Sleeping));
    fill(g_rows[1], 2, 20, "alpha", 50, static_cast<duetos::u8>(TaskState::Running));
    fill(g_rows[2], 3, 30, "beta", 1, static_cast<duetos::u8>(TaskState::Ready));
    fill(g_rows[3], 4, 5, "Gamma", 100, static_cast<duetos::u8>(TaskState::Blocked));

    g_sort = SortMode::Cpu;
    SortRows();
    if (g_rows[0].task_id != 4 || g_rows[1].task_id != 2 || g_rows[2].task_id != 1 || g_rows[3].task_id != 3)
        pass = false;

    g_sort = SortMode::Pid;
    SortRows();
    // Expected ascending PID: 5(g), 10(b), 20(a), 30(beta)
    if (g_rows[0].owner_pid != 5 || g_rows[1].owner_pid != 10 || g_rows[2].owner_pid != 20 || g_rows[3].owner_pid != 30)
        pass = false;

    g_sort = SortMode::Name;
    SortRows();
    // Case-insensitive ascending: alpha, beta, boot, Gamma
    if (CompareNamesCi(g_rows[0].name, "alpha") != 0 || CompareNamesCi(g_rows[1].name, "beta") != 0 ||
        CompareNamesCi(g_rows[2].name, "boot") != 0 || CompareNamesCi(g_rows[3].name, "Gamma") != 0)
        pass = false;

    g_sort = SortMode::State;
    SortRows();
    // Expected order by StateSortKey desc: Running, Ready, Sleeping, Blocked
    if (static_cast<TaskState>(g_rows[0].state) != TaskState::Running ||
        static_cast<TaskState>(g_rows[1].state) != TaskState::Ready ||
        static_cast<TaskState>(g_rows[2].state) != TaskState::Sleeping ||
        static_cast<TaskState>(g_rows[3].state) != TaskState::Blocked)
        pass = false;

    // Restore the sort-comparator state before the Pass D click
    // test runs (the click trampoline may mutate g_tab, which is
    // independent of g_sort but cleaner to restore in one block).
    for (duetos::u32 i = 0; i < kMaxRows; ++i)
        g_rows[i] = saved[i];
    g_row_count = saved_count;
    g_sort = saved_mode;

    // Pass D: drive a synthetic click on the REFRESH toolbar
    // button (kBtnRefresh slot) via the WidgetGroup dispatch
    // chain. KILL is deliberately NOT in the toolbar set (it
    // would arm a destructive op on a row that may not exist
    // during the boot-time self-test), so REFRESH — which is
    // idempotent — is the safe target. Anchor the toolbar at
    // (0, 22, 520, 260) — the same shape boot_bringup.cpp
    // registers the live window with.
    const Tab saved_tab = g_tab;
    BindTaskmanOnce();
    RebindTaskmanBounds(0U, 22U, 520U, 260U);

    // REFRESH button click (index kBtnRefresh=3). The on_click
    // trampoline routes through TaskmanFeedChar('r') which
    // zeroes g_first_visible — verifying the dispatch path runs
    // end-to-end without crashing is the test.
    const duetos::u32 rx = kHdrPadX + kBtnRefresh * (kHdrBtnW + kHdrBtnGap) + kHdrBtnW / 2U;
    const duetos::u32 ry = 22U + kHdrPadY + kHdrBtnH / 2U;
    const Event m_move{EventKind::MouseMove, rx, ry, 0U, 0U};
    const Event m_down{EventKind::MouseDown, rx, ry, 0U, 0U};
    const Event m_up{EventKind::MouseUp, rx, ry, 0U, 0U};
    if (g_taskman.DispatchEvent(m_move) != EventResult::Consumed)
        pass = false;
    if (g_taskman.DispatchEvent(m_down) != EventResult::Consumed)
        pass = false;
    if (g_taskman.DispatchEvent(m_up) != EventResult::Consumed)
        pass = false;

    // TASKS tab click — should force g_tab back to Processes
    // regardless of the prior state. Start by setting it to
    // Performance so the click flip is observable.
    g_tab = Tab::Performance;
    const duetos::u32 tx = kHdrPadX + 0U * (kHdrBtnW + kHdrBtnGap) + kHdrBtnW / 2U;
    const duetos::u32 ty = 22U + kHdrPadY + kHdrBtnH / 2U;
    const Event t_move{EventKind::MouseMove, tx, ty, 0U, 0U};
    const Event t_down{EventKind::MouseDown, tx, ty, 0U, 0U};
    const Event t_up{EventKind::MouseUp, tx, ty, 0U, 0U};
    if (g_taskman.DispatchEvent(t_move) != EventResult::Consumed)
        pass = false;
    if (g_taskman.DispatchEvent(t_down) != EventResult::Consumed)
        pass = false;
    if (g_taskman.DispatchEvent(t_up) != EventResult::Consumed)
        pass = false;
    if (g_tab != Tab::Processes)
        pass = false;

    // Footer-text composer: must produce non-empty text for the
    // current sort mode. Mutating g_sort here is fine — it's
    // restored below as part of the saved-mode pair.
    RefreshTaskmanStatus();
    if (g_footer_text[0] == '\0')
        pass = false;

    g_tab = saved_tab;

    g_self_test_passed = pass;
    if (pass)
    {
        SerialWrite("[taskman] self-test OK (sort comparators, widget-click, footer-refresh)\n");
        SerialWrite("[taskman-selftest] PASS\n");
    }
    else
    {
        SerialWrite("[taskman] self-test FAILED\n");
        SerialWrite("[taskman-selftest] FAIL\n");
    }
}

bool TaskmanSelfTestPassed()
{
    return g_self_test_passed;
}

void TaskmanMouseInput(duetos::u32 cx, duetos::u32 cy, duetos::u8 button_mask)
{
    using duetos::drivers::input::kMouseButtonLeft;
    if (g_handle == duetos::drivers::video::kWindowInvalid)
        return;
    duetos::u32 wx = 0, wy = 0, ww = 0, wh = 0;
    if (!duetos::drivers::video::WindowGetBounds(g_handle, &wx, &wy, &ww, &wh))
        return;
    // Title bar is 22 px; client origin sits below it.
    // RebindTaskmanBounds works in client-relative coords so the
    // widget dispatch path needs cursor coords in the same frame.
    constexpr duetos::u32 kTitleH = 22U;
    if (wh <= kTitleH)
        return;
    const duetos::u32 client_y = wy + kTitleH;
    const duetos::u32 client_h = wh - kTitleH;
    BindTaskmanOnce();
    RebindTaskmanBounds(wx, client_y, ww, client_h);

    const bool left_down = (button_mask & kMouseButtonLeft) != 0;
    const bool press_edge = left_down && !g_prev_left_down;
    const bool release_edge = !left_down && g_prev_left_down;
    g_prev_left_down = left_down;

    const bool inside_window = (cx >= wx && cx < wx + ww && cy >= client_y && cy < wy + wh);
    if (inside_window)
    {
        const Event m{EventKind::MouseMove, cx, cy, 0U, 0U};
        g_taskman.DispatchEvent(m);
    }
    if (press_edge && inside_window)
    {
        const Event d{EventKind::MouseDown, cx, cy, 0U, 0U};
        g_taskman.DispatchEvent(d);
    }
    if (release_edge)
    {
        // Always dispatch MouseUp so a button pressed inside the
        // toolbar and dragged off clears its Pressed flag.
        const Event u{EventKind::MouseUp, cx, cy, 0U, 0U};
        g_taskman.DispatchEvent(u);
    }
}

} // namespace duetos::apps::taskman
