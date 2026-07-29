#include "apps/taskman.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"
#include "arch/x86_64/timer.h"
#include "log/klog.h"
#include "drivers/input/ps2kbd.h"
#include "drivers/input/ps2mouse.h"
#include "drivers/video/app_widgets/app_button.h"
#include "drivers/video/app_widgets/app_label.h"
#include "drivers/video/app_widgets/app_palette.h"
#include "diag/telemetry.h"
#include "drivers/video/app_widgets/app_text.h"
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

// 12-px rows: an 8x8 glyph with 2 px of air above and below. The
// design's process table is generously leaded; every row geometry
// (DrawRows, the perf stack, the scroll clamp) derives from this
// constant so it moves as one.
constexpr duetos::u32 kRowH = 12;
constexpr duetos::u32 kHeaderH = 22; // header band: 2 lines
constexpr duetos::u32 kFooterH = 12; // hint footer
constexpr duetos::u32 kColPad = 6;   // left padding inside client

// Height of the stats line above the column headings. Fixed in both
// layouts — the headings band is what grows for proportional type.
constexpr duetos::u32 kStatLineH = 12;

// Live app-interior palette for the Task Manager client area. Sampled
// per paint so a runtime theme cycle (Ctrl+Alt+Y) recolours the table.
duetos::drivers::video::app_widgets::AppPalette Pal()
{
    using duetos::drivers::video::ThemeCurrent;
    using duetos::drivers::video::ThemeRole;
    const duetos::u32 body = ThemeCurrent().role_client[static_cast<duetos::u32>(ThemeRole::TaskManager)];
    return duetos::drivers::video::app_widgets::AppPaletteFor(body);
}

// Live row pitch and header-band height. Aurora leads its rows for
// the proportional face; the flat palettes keep the historical 12 /
// 22 exactly. Every geometry site (paint, scroll clamp, hit-test)
// reads these, never the raw constants, so the two layouts can't
// disagree about where row N starts.
duetos::u32 RowH()
{
    using duetos::drivers::video::ChromeTextRole;
    return Pal().aurora ? duetos::drivers::video::app_widgets::AppRowHeight(ChromeTextRole::Body) : kRowH;
}

// Height of the aggregate-stats line above the column headings.
//
// Aurora folds that line away entirely: the reference's Task Manager
// carries its counts in the title-bar subtitle and the status bar, not
// as a third band between the tab strip and the table. Every site that
// offsets past it — HeaderH, DrawHeader's two fills, and the
// column-header hit-test — reads this, so the band cannot exist for
// the pixels and not for the click.
duetos::u32 StatLineH()
{
    return Pal().aurora ? 0U : kStatLineH;
}

duetos::u32 HeaderH()
{
    using duetos::drivers::video::ChromeTextRole;
    if (!Pal().aurora)
        return kHeaderH;
    return StatLineH() + duetos::drivers::video::app_widgets::AppRowHeight(ChromeTextRole::Caption);
}

// Strip leading / trailing spaces in place. The column formatters
// pad to a character count, which is exactly the wrong thing under a
// proportional face — Aurora right-aligns on the measured width
// instead, so it wants the bare value.
void TrimSpaces(char* s)
{
    duetos::u32 first = 0;
    while (s[first] == ' ')
        ++first;
    duetos::u32 n = 0;
    while (s[first + n] != '\0')
    {
        s[n] = s[first + n];
        ++n;
    }
    while (n > 0 && s[n - 1] == ' ')
        --n;
    s[n] = '\0';
}

// Per-column character widths. The list view has six columns:
// PID (5 chars), NAME (16), STATE (5), CPU% (6), TICKS (10), MEM (6).
constexpr duetos::u32 kColPid = 5;
constexpr duetos::u32 kColName = 16;
constexpr duetos::u32 kColState = 5;
constexpr duetos::u32 kColCpu = 6;
constexpr duetos::u32 kColTicks = 10;
constexpr duetos::u32 kColMem = 6; // per-process mapped KiB, right-justified

enum class SortMode : duetos::u8
{
    Cpu = 0,   // descending — highest CPU% at top
    Pid = 1,   // ascending
    Name = 2,  // ascending, case-insensitive
    State = 3, // Running > Ready > Sleeping > Blocked > Dead
    Mem = 4,   // descending — highest mapped KiB at top
    kCount = 5,
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
    case SortMode::Mem:
        return "MEM ";
    default:
        return "????";
    }
}

// ---------------------------------------------------------------
// Column model — ONE table, three consumers.
//
// The header paint, the row paint and the header-click hit-test all
// read `BuildCols`. They used to each re-derive `col_chars * 8 + 4`
// from the kCol* character widths, which is how the paint and the
// hit-test drifted out of phase. Deriving all three from one table
// makes that class of bug unrepresentable: if a column moves, it
// moves for the pixels and for the click at the same time.
//
// Two layouts share the table:
//   - flat palettes keep the historical character-cell arithmetic
//     verbatim (`chars * 8 + 4`, PID first), so Classic / Slate10 /
//     Amber / DuetClassic / HighContrast stay pixel-identical;
//   - Aurora measures every fixed column off the live proportional
//     font and gives NAME the slack, in the reference's order.
// ---------------------------------------------------------------
enum class ColId : duetos::u8
{
    Name = 0,
    Pid = 1,
    Abi = 2,
    Cpu = 3,
    Ticks = 4, // flat palettes only — raw on-CPU tick counter
    Mem = 5,
    State = 6,
    // Aurora only. The reference's process table counts THREADS where
    // ours counted TICKS. The value is not a new kernel reading: the
    // snapshot already enumerates one row per *task*, so the threads of
    // a process are the rows sharing its `owner_pid`. Ticks stays the
    // flat-palette column so those themes keep the pixels they had.
    Threads = 7,
};

struct Col
{
    ColId id;
    duetos::u32 x;    // absolute left edge of the cell + its hit zone
    duetos::u32 w;    // cell width; the hit zone is [x, x + w)
    SortMode sort;    // kCount = this column has no sort key
    bool right_align; // Aurora only: value's right edge sits at x + w
};

constexpr duetos::u32 kMaxCols = 7;

// Defined below with the other row formatters; declared here because
// the column table measures the STATE column over every label it can
// produce rather than over a hand-picked widest string.
const char* StateLabel(duetos::u8 state);

// Widest value a fixed column has to hold. Measured rather than
// assumed so the layout tracks whatever face the theme registered.
// Aurora renders PIDs in hex, per the reference. The bound is written
// with DIGITS, not with 'f': under a proportional face the hex letters
// are not all narrower than the digits — Liberation Sans puts 'e' at
// twice the advance of 'f' — so "0xffff" measures NARROWER than a real
// PID like "0xfeee", the cell overflowed its column, and
// AppTextCellRight dropped it silently. Six nibbles of digit width
// covers every PID the allocator hands out with room to spare.
constexpr const char* kWidestPidHex = "0x000000";
constexpr const char* kWidestCpu = "100.0%";
constexpr const char* kWidestThreads = "999";
constexpr const char* kWidestMem = "9999999";

// Minimum NAME width before the (optional) TICKS column is dropped.
// Below this a proportional name truncates so hard the table stops
// being readable, which is worse than losing the raw tick counter.
constexpr duetos::u32 kNameMinPx = 104;

const char* ColHeaderLabel(ColId id)
{
    switch (id)
    {
    case ColId::Name:
        return "NAME";
    case ColId::Pid:
        return "PID";
    case ColId::Abi:
        return "ABI";
    case ColId::Cpu:
        return "CPU";
    case ColId::Ticks:
        return "TICKS";
    case ColId::Threads:
        return "THREADS";
    case ColId::Mem:
        return "MEMORY";
    case ColId::State:
        return "STATE";
    }
    return "";
}

// ABI badge text for a row, or nullptr when the row's ABI genuinely
// cannot be determined (kernel-only tasks). Never guessed — the
// value comes off Process::pe_image_base / Process::abi_flavor via
// SchedTaskInfo::abi.
const char* AbiBadge(duetos::u8 abi)
{
    switch (abi)
    {
    case duetos::sched::kTaskAbiNative:
        return "NATIVE";
    case duetos::sched::kTaskAbiWin32Pe:
        return "WIN32 PE";
    case duetos::sched::kTaskAbiLinux:
        return "LINUX ELF";
    default:
        return nullptr;
    }
}

duetos::u32 BuildCols(duetos::u32 cx, duetos::u32 cw, bool aurora, Col* out)
{
    using duetos::drivers::video::ChromeTextRole;
    using duetos::drivers::video::app_widgets::AppPillWidth;
    using duetos::drivers::video::app_widgets::AppRowDotWidth;
    using duetos::drivers::video::app_widgets::AppTextMeasure;

    duetos::u32 n = 0;
    if (!aurora)
    {
        // Historical layout, byte-for-byte: PID NAME STATE CPU% TICKS MEM,
        // each `chars * 8 + 4` wide, starting at cx + kColPad.
        duetos::u32 x = cx + kColPad;
        const struct
        {
            ColId id;
            duetos::u32 chars;
            SortMode sort;
        } legacy[] = {
            {ColId::Pid, kColPid, SortMode::Pid},        {ColId::Name, kColName, SortMode::Name},
            {ColId::State, kColState, SortMode::State},  {ColId::Cpu, kColCpu, SortMode::Cpu},
            {ColId::Ticks, kColTicks, SortMode::kCount}, {ColId::Mem, kColMem, SortMode::Mem},
        };
        for (const auto& l : legacy)
        {
            out[n++] = Col{l.id, x, l.chars * 8U + 4U, l.sort, false};
            x += l.chars * 8U + 4U;
        }
        return n;
    }

    // Aurora: fixed columns measured off the live face, NAME flexes.
    constexpr duetos::u32 kGap = 10;
    const duetos::u32 pid_w = AppTextMeasure(ChromeTextRole::Body, kWidestPidHex);
    const duetos::u32 abi_w = AppPillWidth("WIN32 PE");
    const duetos::u32 cpu_w = AppTextMeasure(ChromeTextRole::Body, kWidestCpu);
    // THREADS is the reference's fifth column; it is also the narrowest,
    // so the "drop the optional column" branch below almost never fires
    // now that it is no longer a 10-digit tick counter.
    const duetos::u32 threads_w =
        AppTextMeasure(ChromeTextRole::Caption, "THREADS") > AppTextMeasure(ChromeTextRole::Body, kWidestThreads)
            ? AppTextMeasure(ChromeTextRole::Caption, "THREADS")
            : AppTextMeasure(ChromeTextRole::Body, kWidestThreads);
    const duetos::u32 mem_w = AppTextMeasure(ChromeTextRole::Body, kWidestMem);
    // The STATE bound is COMPUTED over every label, not written out as
    // a hand-picked widest string. Picking one by eye is how the PID
    // column lost its values: under a proportional face "unknown" is
    // wider than "sleeping" even though it is a character shorter.
    duetos::u32 state_w = 0;
    for (duetos::u32 st = 0; st <= static_cast<duetos::u32>(duetos::sched::TaskState::Dead) + 1; ++st)
    {
        const duetos::u32 sw = AppTextMeasure(ChromeTextRole::Body, StateLabel(static_cast<duetos::u8>(st)));
        if (sw > state_w)
            state_w = sw;
    }

    const duetos::u32 pad = kColPad;
    const duetos::u32 avail = (cw > 2U * pad) ? cw - 2U * pad : 0U;
    const duetos::u32 fixed_no_ticks = pid_w + abi_w + cpu_w + mem_w + state_w + 5U * kGap;
    // NAME also carries the row dot in its cell.
    const duetos::u32 dot = AppRowDotWidth();

    bool with_threads = false;
    duetos::u32 name_w = 0;
    if (avail > fixed_no_ticks + dot + threads_w + kGap &&
        avail - (fixed_no_ticks + dot + threads_w + kGap) >= kNameMinPx)
    {
        with_threads = true;
        name_w = avail - (fixed_no_ticks + dot + threads_w + kGap);
    }
    else if (avail > fixed_no_ticks + dot)
    {
        name_w = avail - (fixed_no_ticks + dot);
    }
    else
    {
        // Client too narrow for the full table — give NAME what is
        // left and let the right-aligned columns clip themselves.
        name_w = 0;
    }

    duetos::u32 x = cx + pad;
    auto push = [&](ColId id, duetos::u32 w, SortMode s, bool right)
    {
        out[n++] = Col{id, x, w, s, right};
        x += w + kGap;
    };
    push(ColId::Name, dot + name_w, SortMode::Name, false);
    push(ColId::Pid, pid_w, SortMode::Pid, true);
    push(ColId::Abi, abi_w, SortMode::kCount, false);
    push(ColId::Cpu, cpu_w, SortMode::Cpu, true);
    if (with_threads)
        push(ColId::Threads, threads_w, SortMode::kCount, true);
    push(ColId::Mem, mem_w, SortMode::Mem, true);
    push(ColId::State, state_w, SortMode::State, false);
    return n;
}

// Aurora state labels. The reference spells the state in lower case as
// prose ("running", "sleeping"), not as the flat table's fixed-width
// 5-cell glyph - which is right for a character grid and wrong under a
// proportional face. The flat themes keep StateGlyph verbatim.
const char* StateLabel(duetos::u8 state)
{
    using duetos::sched::TaskState;
    switch (static_cast<TaskState>(state))
    {
    case TaskState::Running:
        return "running";
    case TaskState::Ready:
        return "ready";
    case TaskState::Sleeping:
        return "sleeping";
    case TaskState::Blocked:
        return "blocked";
    case TaskState::Dead:
        return "dead";
    default:
        return "unknown";
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
    duetos::u32 mapped_kib; // per-process mapped user pages × 4 KiB
    // Threads in this row's owning process — the number of snapshot
    // rows sharing `owner_pid`. Kernel-only tasks (has_process false)
    // are one thread each and report 1; they are NOT pooled under
    // owner_pid 0, which would report the whole kernel task set on
    // every such row. Computed once per snapshot, not per paint.
    duetos::u32 threads;
    duetos::u8 state;
    duetos::u8 priority;
    duetos::u8 abi; // sched::kTaskAbi* — kTaskAbiNone means "no badge"
    bool is_running;
    bool has_process;
};

// Module-private state. All of it is mutated under the
// compositor lock (caller holds it across DrawFn / FeedChar /
// FeedKey), so no extra locking is required.
constinit duetos::drivers::video::WindowHandle g_handle = duetos::drivers::video::kWindowInvalid;
constinit SortMode g_sort = SortMode::Cpu;
// Sort direction: true = ascending, false = descending.
// Default is descending for CPU% and MEM (highest first), ascending
// for PID, NAME, STATE. Toggled when the user clicks the active
// column header again or presses S on an already-active column.
constinit bool g_sort_asc = false;
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
    // Aurora only — the reference's third tab. The view groups the
    // SAME snapshot by SchedTaskInfo::abi; it reads no new kernel
    // state, so it cannot show anything the process table couldn't.
    // The reference's fourth tab (Startup) has no data behind it in
    // DuetOS — there is no autostart registry — so it is deliberately
    // absent rather than rendered empty.
    AbiPeers = 2,
    kCount = 3,
};

constinit Tab g_tab = Tab::Processes;

// Tabs the active theme exposes. The flat palettes keep the historical
// two-tab cycle exactly; Aurora adds the ABI-peers view. Read by the
// keyboard cycle, by the header strip, and by the theme-change clamp.
duetos::u32 TabCount()
{
    return Pal().aurora ? 3U : 2U;
}

const char* TabName(Tab t)
{
    switch (t)
    {
    case Tab::Processes:
        return "PROCESSES";
    case Tab::Performance:
        return "PERFORMANCE";
    case Tab::AbiPeers:
        return "ABI PEERS";
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
void ClickAbiPeersTab();
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

// ---------------------------------------------------------------
// Header strip — ONE geometry table, four consumers.
//
// The reference replaces this app's chip-button toolbar with an
// underlined tab strip and a right-hand "live" cadence chip
// (`13-taskmanager-processes.png`). A tab is clickable, so its bounds
// are read by the widget hit-test AND by the paint; the underline is
// painted from the same rect the click lands in. `HdrStripFor` is the
// only place either is derived — the same discipline `ListGeomFor`
// applied to the Files list, and for the same reason.
//
// Consumers: RebindTaskmanBounds (button bounds -> hit-test),
// DrawFn (underline + live chip), and TaskmanSelfTest (synthetic
// click coordinates, which previously re-derived the chip pitch by
// hand and would have silently drifted).
//
// Both layouts share the table:
//   - flat palettes keep the historical 64x20 chip row verbatim;
//   - Aurora measures each tab off the live face, folds the unused
//     slot to zero width, and reserves the cadence chip.
// ---------------------------------------------------------------
constexpr duetos::u32 kTabPadX = 12;      // padding either side of a tab label
constexpr duetos::u32 kTabGap = 2;        // gap between adjacent tabs
constexpr duetos::u32 kTabUnderlineH = 2; // the design's active-tab rule
constexpr duetos::u32 kAuroraTabCount = 3;

// Sampling cadence rendered in the "live" chip. Derived from the
// history sampler's own interval so the chip cannot claim a rate the
// app does not actually poll at.
static_assert(kSampleIntervalTicks == 100, "live-chip label assumes a 1 s sampling cadence");
constexpr const char* kLiveChipLabel = "live 1s";

struct HdrStrip
{
    Rect band;               // whole strip, including the rule
    Rect slot[kHdrBtnCount]; // clickable slots; w == 0 = folded away
    Rect underline;          // active tab's rule; w == 0 on flat
    Rect live;               // cadence chip; w == 0 on flat
    duetos::u32 rule_y;      // 1-px rule under the strip; 0 on flat
};

const char* HdrSlotLabel(duetos::u32 i, bool aurora)
{
    // Aurora's slots are the reference's tab names; the flat palettes
    // keep the historical action chips. Slot 3 has no Aurora tab
    // behind it (see Tab::AbiPeers' note on Startup) and folds away.
    static const char* const kFlat[kHdrBtnCount] = {"TASKS", "PERF", "SORT", "REFRESH"};
    static const char* const kAurora[kHdrBtnCount] = {"Processes", "Performance", "ABI peers", ""};
    return aurora ? kAurora[i] : kFlat[i];
}

// Action behind slot `i`. SORT and REFRESH have no Aurora slot: the
// column headings are already the sort affordance (clicking one sets
// the key, clicking it again flips the direction) and every paint
// re-enumerates, so "refresh" is what the app does continuously —
// which is exactly what the reference's `live` chip announces. The
// 's' / 'r' keybinds are untouched on both branches.
using HdrClickFn = void (*)();

HdrClickFn HdrSlotClick(duetos::u32 i, bool aurora)
{
    static constexpr HdrClickFn kFlat[kHdrBtnCount] = {ClickTasksTab, ClickPerfTab, ClickSort, ClickRefresh};
    static constexpr HdrClickFn kAurora[kHdrBtnCount] = {ClickTasksTab, ClickPerfTab, ClickAbiPeersTab, nullptr};
    return aurora ? kAurora[i] : kFlat[i];
}

HdrStrip HdrStripFor(duetos::u32 cx, duetos::u32 cy, duetos::u32 cw)
{
    using duetos::drivers::video::ChromeTextRole;
    using duetos::drivers::video::app_widgets::AppRowDotWidth;
    using duetos::drivers::video::app_widgets::AppTextMeasure;

    HdrStrip s{};
    s.band = Rect{cx, cy, cw, kHdrToolbarH};

    if (!Pal().aurora)
    {
        for (duetos::u32 i = 0; i < kHdrBtnCount; ++i)
        {
            s.slot[i] = Rect{cx + kHdrPadX + i * (kHdrBtnW + kHdrBtnGap), cy + kHdrPadY, kHdrBtnW, kHdrBtnH};
        }
        return s;
    }

    // Aurora: tabs sit on the band's baseline with the active rule
    // hugging the strip's bottom edge, exactly as the reference draws
    // them. Height leaves room for the rule plus the 1-px hairline.
    const duetos::u32 tab_h = (kHdrToolbarH > kTabUnderlineH + 2) ? kHdrToolbarH - kTabUnderlineH - 2 : kHdrToolbarH;
    duetos::u32 x = cx + kHdrPadX;
    for (duetos::u32 i = 0; i < kAuroraTabCount; ++i)
    {
        const duetos::u32 w = AppTextMeasure(ChromeTextRole::Body, HdrSlotLabel(i, true)) + 2U * kTabPadX;
        // A tab that would run past the strip's right edge folds away
        // rather than overlapping the cadence chip.
        if (x + w > cx + cw)
        {
            break;
        }
        s.slot[i] = Rect{x, cy, w, tab_h};
        x += w + kTabGap;
    }

    const duetos::u32 active = static_cast<duetos::u32>(g_tab);
    if (active < kAuroraTabCount && s.slot[active].w != 0)
    {
        s.underline = Rect{s.slot[active].x, cy + tab_h, s.slot[active].w, kTabUnderlineH};
    }

    // Cadence chip, right-aligned. Dot + label + padding either side.
    const duetos::u32 dot = AppRowDotWidth();
    const duetos::u32 chip_w = dot + AppTextMeasure(ChromeTextRole::Caption, kLiveChipLabel) + 2U * kTabPadX;
    const duetos::u32 chip_h = (tab_h > 6) ? tab_h - 6 : tab_h;
    if (cw > kHdrPadX + chip_w && cx + cw - kHdrPadX - chip_w > x)
    {
        s.live = Rect{cx + cw - kHdrPadX - chip_w, cy + (tab_h - chip_h) / 2, chip_w, chip_h};
    }
    s.rule_y = cy + kHdrToolbarH - 1;
    return s;
}

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

// Resolve every widget colour against the active theme. Split out of
// BindTaskmanOnce (which is one-shot) so a runtime theme cycle
// recolours the tab strip and the status strip. The active tab takes
// the accent — the design's 2-px underline, expressed here as a tinted
// chip because the toolbar has no room for a separate rule.
void ApplyTaskmanPalette()
{
    const auto p = Pal();

    // A theme cycle out of Aurora retires the ABI-peers tab; clamp
    // before anything reads g_tab so the strip and the content paint
    // can never disagree about which view is live.
    if (static_cast<duetos::u32>(g_tab) >= TabCount())
        g_tab = Tab::Processes;

    auto& toolbar = g_taskman.chain.head;
    toolbar.bg_rgb = p.aurora ? p.wash : 0U; // 0 = theme.taskbar_bg

    for (duetos::u32 i = 0; i < kHdrBtnCount; ++i)
    {
        AppButton* btn = HdrButton(i);
        btn->label = HdrSlotLabel(i, p.aurora);
        btn->on_click = HdrSlotClick(i, p.aurora);
        if (!p.aurora)
        {
            btn->bg_rgb = 0; // theme role default
            btn->fg_rgb = 0x00101828U;
            btn->weight = ChromeTextWeight::Regular;
            continue;
        }
        // A tab is not a chip: it takes the strip's own ground so the
        // AppButton fill vanishes into the band, and carries its state
        // in the label weight plus the 2-px rule DrawFn paints from
        // the same slot rect. Hover still lifts the fill slightly,
        // which is what the reference does too.
        const bool active_tab = (i == static_cast<duetos::u32>(g_tab));
        btn->bg_rgb = p.wash;
        btn->fg_rgb = active_tab ? p.ink : p.ink_3;
        btn->weight = active_tab ? ChromeTextWeight::Bold : ChromeTextWeight::Regular;
    }

    auto& label = g_taskman.chain.tail.tail.tail.tail.tail.head;
    label.fg_rgb = p.aurora ? p.ink_3 : 0x00181828U;
    label.bg_rgb = p.aurora ? p.wash : 0x00C8C8B8U; // status band tone
}

void BindTaskmanOnce()
{
    if (g_taskman_bound)
        return;
    g_taskman_bound = true;

    // Labels, click actions and weights are branch-dependent and are
    // (re)applied every paint by ApplyTaskmanPalette, so a runtime
    // theme cycle swaps the chip row for the tab strip without a
    // rebind. Nothing button-specific is one-shot any more.
    auto& label = g_taskman.chain.tail.tail.tail.tail.tail.head;
    label.text = g_footer_text;
    label.role = ChromeTextRole::Caption;
    label.weight = ChromeTextWeight::Regular;
    label.align_left = true;

    ApplyTaskmanPalette();
}

// Re-anchor the toolbar + buttons + footer label to the live
// window's client rect. Called from DrawFn before PaintAll and
// from TaskmanMouseInput before DispatchEvent so hit-tests +
// visuals stay consistent across window moves / resizes.
void RebindTaskmanBounds(duetos::u32 cx, duetos::u32 cy, duetos::u32 cw, duetos::u32 ch)
{
    // Bounds come from HdrStripFor, which is also what DrawFn paints
    // the active-tab rule from and what the self-test aims its
    // synthetic clicks at. One table, so a tab cannot move for the
    // pixels without moving for the click.
    const HdrStrip strip = HdrStripFor(cx, cy, cw);
    auto& toolbar = g_taskman.chain.head;
    toolbar.bounds = strip.band;

    for (duetos::u32 i = 0; i < kHdrBtnCount; ++i)
    {
        HdrButton(i)->bounds = strip.slot[i];
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
// Defined below with the other column formatters; declared here so the
// Aurora status composer can use them.
void FmtU64Plain(duetos::u64 v, char* out, duetos::u32 cap);
void FmtCpuPercent(duetos::u64 part, duetos::u64 whole, char* out, duetos::u32 width);

// Distinct owning processes in the snapshot. Rows are tasks, so the
// process count is the number of distinct `owner_pid` values among the
// rows that have one — kernel-only tasks belong to no process and are
// deliberately not counted as one apiece.
duetos::u32 DistinctProcessCount()
{
    duetos::u32 n = 0;
    for (duetos::u32 i = 0; i < g_row_count; ++i)
    {
        if (!g_rows[i].has_process)
            continue;
        bool seen = false;
        for (duetos::u32 j = 0; j < i && !seen; ++j)
            seen = g_rows[j].has_process && g_rows[j].owner_pid == g_rows[i].owner_pid;
        if (!seen)
            ++n;
    }
    return n;
}

void RefreshTaskmanStatus()
{
    duetos::u32 o = 0;
    g_footer_text[0] = '\0';
    auto put = [&](const char* s) { StatusAppend(g_footer_text, sizeof(g_footer_text), &o, s); };

    if (Pal().aurora)
    {
        // The reference's status bar: counts, aggregate CPU, memory.
        // These are the numbers the flat palettes carry in the stats
        // line above the table, which Aurora folds away — same
        // readings, one band instead of two.
        // FmtU64Right / FmtCpuPercent write AT MOST `width` characters
        // and left-pad to it, so a status line wants the buffer width
        // and a trim, never width 1 - that silently keeps only the
        // leading digit ("14 threads" became "1 threads").
        char num[16];
        auto put_num = [&](duetos::u64 v)
        {
            FmtU64Plain(v, num, sizeof(num));
            put(num);
        };
        put_num(DistinctProcessCount());
        put(" processes  |  ");
        put_num(g_row_count);
        put(" threads  |  CPU ");
        const duetos::u64 nonidle = g_total_ticks_snap > g_idle_ticks_snap ? g_total_ticks_snap - g_idle_ticks_snap : 0;
        FmtCpuPercent(nonidle, g_total_ticks_snap, num, sizeof(num) - 1);
        TrimSpaces(num);
        put(num);
        put("%  |  Memory ");
        const duetos::u64 total_mib = (duetos::mm::TotalFrames() * 4ull) / 1024ull;
        const duetos::u64 free_mib = (duetos::mm::FreeFramesCount() * 4ull) / 1024ull;
        put_num(total_mib > free_mib ? total_mib - free_mib : 0);
        put(" / ");
        put_num(total_mib);
        put(" MiB");
    }
    else
    {
        put("TAB:VIEW  UP/DN PGUP/PGDN  S:SORT-");
        put(SortModeName(g_sort));
        put("  K:KILL  R:REFRESH");
    }

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

// Unpadded decimal. The column formatters above deliberately clamp to
// a fixed cell width, which is right for a table and wrong for prose:
// `FmtU64Right(14, buf, 1)` writes "1", not "14". A status line wants
// the whole number, so it gets its own formatter rather than a width
// argument a future edit can get wrong again.
void FmtU64Plain(duetos::u64 v, char* out, duetos::u32 cap)
{
    if (out == nullptr || cap == 0)
        return;
    char tmp[24];
    duetos::u32 n = 0;
    do
    {
        tmp[n++] = static_cast<char>('0' + (v % 10));
        v /= 10;
    } while (v > 0 && n < sizeof(tmp));
    duetos::u32 o = 0;
    for (duetos::u32 i = n; i > 0 && o + 1 < cap; --i)
        out[o++] = tmp[i - 1];
    out[o] = '\0';
}

// PID as the reference renders it: `0x01`, `0x1a`, `0x0120`. Lower-case
// digits, zero-padded to an even number of nibbles with a two-digit
// floor, so a table of small PIDs stays visually rectangular. Aurora
// only — the flat palettes keep the decimal, space-padded column.
void FmtPidHex(duetos::u64 v, char* out, duetos::u32 cap)
{
    char tmp[16];
    duetos::u32 n = 0;
    do
    {
        const duetos::u64 nib = v & 0xFull;
        tmp[n++] = static_cast<char>(nib < 10 ? '0' + nib : 'a' + (nib - 10));
        v >>= 4;
    } while (v != 0 && n < sizeof(tmp));
    if (n < 2)
        tmp[n++] = '0';
    if ((n & 1u) != 0 && n < sizeof(tmp))
        tmp[n++] = '0';

    duetos::u32 o = 0;
    auto put = [&](char ch)
    {
        if (o + 1 < cap)
            out[o++] = ch;
    };
    put('0');
    put('x');
    for (duetos::u32 i = n; i > 0; --i)
        put(tmp[i - 1]);
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
    r.mapped_kib = info.mapped_pages * 4u; // pages × 4 KiB/page
    r.state = info.state;
    r.priority = info.priority;
    r.is_running = info.is_running;
    r.has_process = info.has_process;
    r.abi = info.abi;
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

// Sort comparator for SortMode `m`, respecting g_sort_asc direction.
// Returns true iff `a` should come before `b` in the sorted listing.
// Tie-breaks on task_id so the order is stable across redraws even
// when two tasks share the primary key.
//
// g_sort_asc == false (descending) means the "natural" order for
// each mode — highest CPU% / MEM first, lowest PID first, etc. When
// g_sort_asc is true the primary comparison is flipped. Tie-break on
// task_id is always ascending so the list is deterministic.
bool RowLess(const Row& a, const Row& b, SortMode m)
{
    switch (m)
    {
    case SortMode::Cpu:
    {
        if (a.ticks_run != b.ticks_run)
            return g_sort_asc ? a.ticks_run < b.ticks_run : a.ticks_run > b.ticks_run;
        return a.task_id < b.task_id;
    }
    case SortMode::Pid:
    {
        const duetos::u64 ka = a.has_process ? a.owner_pid : (~0ull >> 1);
        const duetos::u64 kb = b.has_process ? b.owner_pid : (~0ull >> 1);
        if (ka != kb)
            // ascending = smaller PID first (ka < kb), descending = larger first
            return g_sort_asc ? ka < kb : ka > kb;
        return a.task_id < b.task_id;
    }
    case SortMode::Name:
    {
        const int c = CompareNamesCi(a.name, b.name);
        if (c != 0)
            // ascending = a < b (c < 0), descending = a > b (c > 0)
            return g_sort_asc ? c < 0 : c > 0;
        return a.task_id < b.task_id;
    }
    case SortMode::State:
    {
        const duetos::u8 ka = StateSortKey(a.state);
        const duetos::u8 kb = StateSortKey(b.state);
        if (ka != kb)
            // natural order: Running(5) first → descending by key; ascending inverts
            return g_sort_asc ? ka < kb : ka > kb;
        return a.task_id < b.task_id;
    }
    case SortMode::Mem:
    {
        if (a.mapped_kib != b.mapped_kib)
            return g_sort_asc ? a.mapped_kib < b.mapped_kib : a.mapped_kib > b.mapped_kib;
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

// Fill Row::threads for the whole snapshot. A process's threads are
// its tasks, and the enumerate already produced one row per task —
// so this counts what is already in hand rather than reading any new
// kernel state. Kernel-only tasks are one thread each; they are not
// pooled under the shared owner_pid 0.
void ComputeThreadCounts()
{
    for (duetos::u32 i = 0; i < g_row_count; ++i)
    {
        if (!g_rows[i].has_process)
        {
            g_rows[i].threads = 1;
            continue;
        }
        duetos::u32 n = 0;
        for (duetos::u32 j = 0; j < g_row_count; ++j)
        {
            if (g_rows[j].has_process && g_rows[j].owner_pid == g_rows[i].owner_pid)
                ++n;
        }
        g_rows[i].threads = n;
    }
}

void RebuildSnapshot()
{
    g_row_count = 0;
    duetos::sched::SchedEnumerate(&OnEnumTask, nullptr);
    ComputeThreadCounts();
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

// The historical flat-palette aggregate-stats line. Split out of
// DrawHeader when Aurora folded the band away — the composer is
// otherwise dead work on every Aurora paint. Byte-for-byte the same
// text and origin the flat themes have always drawn.
void DrawStatLine(duetos::u32 cx, duetos::u32 cy, duetos::u32 fg, duetos::u32 stat_bg)
{
    using duetos::drivers::video::FramebufferDrawString;

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
    FramebufferDrawString(cx + kColPad, cy + 2, line, fg, stat_bg);
}

void DrawHeader(duetos::u32 cx, duetos::u32 cy, duetos::u32 cw, duetos::u32 fg, duetos::u32 hl, duetos::u32 bg)
{
    using duetos::drivers::video::FramebufferDrawString;
    using duetos::drivers::video::FramebufferFillRect;
    const auto p = Pal();
    // Aurora: the stats line sits on the window's own ground while the
    // column headings sit on a `--glass-3` band with a hairline under
    // it — the design's sticky table header. Flat palettes keep the
    // single flat band.
    const duetos::u32 stat_h = StatLineH();
    const duetos::u32 stat_bg = p.aurora ? p.body : bg;
    const duetos::u32 head_bg = p.aurora ? p.wash : bg;
    const duetos::u32 header_h = HeaderH();
    if (stat_h != 0)
        FramebufferFillRect(cx, cy, cw, stat_h, stat_bg);
    FramebufferFillRect(cx, cy + stat_h, cw, header_h - stat_h, head_bg);
    if (p.aurora)
        FramebufferFillRect(cx, cy + header_h - 1, cw, 1, p.line);

    // Line 1: aggregate stats — flat palettes only.
    //   "CPU 12.3%  IDLE 87.7%  MEM 1234/4096  TASKS 23"
    // Aurora carries the same counts in its status bar instead (the
    // reference has no third band here), so the composer is skipped
    // rather than composed-and-discarded.
    if (stat_h != 0)
        DrawStatLine(cx, cy, fg, stat_bg);

    // Line 2: column headers (PROCESSES tab only — the
    // PERFORMANCE tab paints labels inside the graph stack).
    // The active sort column is drawn in the highlight colour.
    // A '^' (ascending) or 'v' (descending) indicator is appended
    // to the active column label so the sort direction is visible
    // without any extra row. Clicking a column header sets that
    // column as the sort key; clicking the active column again
    // toggles asc/desc (see TaskmanMouseInput HitTestColHeader).
    if (g_tab != Tab::Processes)
        return;

    // Helper: build a column label with a trailing sort indicator
    // on the active column. 'w' is the column character width; we
    // fit the indicator just inside the last char slot.
    auto make_col_label = [&](const char* base_label, duetos::u32 w, SortMode key, char* out)
    {
        duetos::u32 o = 0;
        for (; o < w && base_label[o] != '\0'; ++o)
            out[o] = base_label[o];
        while (o < w)
            out[o++] = ' ';
        // Overwrite the last character with the indicator when this
        // is the active sort column. '^' = ascending, 'v' = descending.
        if (g_sort == key)
            out[w - 1] = g_sort_asc ? '^' : 'v';
        out[w] = '\0';
    };

    // Uppercase headings in muted ink; the active sort column takes the
    // accent. The design spends no other colour on the header row.
    const duetos::u32 head_fg = p.aurora ? p.ink_3 : fg;
    const duetos::u32 head_hl = p.aurora ? p.accent : hl;

    Col cols[kMaxCols];
    const duetos::u32 ncols = BuildCols(cx, cw, p.aurora, cols);

    if (!p.aurora)
    {
        // Flat palettes: character-padded labels drawn at the table's
        // cell origins — the exact pixels this app has always painted.
        char label[24];
        const duetos::u32 y = cy + 13;
        for (duetos::u32 i = 0; i < ncols; ++i)
        {
            const Col& c = cols[i];
            const duetos::u32 chars = (c.w - 4U) / 8U;
            switch (c.id)
            {
            case ColId::Pid:
                make_col_label("PID", chars, SortMode::Pid, label);
                break;
            case ColId::Name:
                make_col_label("NAME", chars, SortMode::Name, label);
                break;
            case ColId::State:
                make_col_label("STATE", chars, SortMode::State, label);
                break;
            case ColId::Cpu:
                make_col_label("  CPU%", chars, SortMode::Cpu, label);
                break;
            case ColId::Ticks:
                // TICKS shares the CPU% sort key, so its indicator
                // would duplicate the one on CPU%. Plain label.
                FmtStrLeft("     TICKS", label, chars);
                break;
            case ColId::Mem:
                make_col_label("  MEM", chars, SortMode::Mem, label);
                break;
            default:
                label[0] = '\0';
                break;
            }
            const duetos::u32 colour = (c.sort != SortMode::kCount && g_sort == c.sort) ? head_hl : head_fg;
            FramebufferDrawString(c.x, y, label, colour, head_bg);
        }
        return;
    }

    // Aurora: measured labels at Caption size, right-aligned where the
    // column's values are. The sort indicator becomes a separate
    // glyph appended to the label rather than a character overwrite —
    // a proportional label has no "last cell" to overwrite.
    using duetos::drivers::video::ChromeTextRole;
    using duetos::drivers::video::app_widgets::AppTextCell;
    using duetos::drivers::video::app_widgets::AppTextCellRight;
    const duetos::u32 band_y = cy + stat_h;
    const duetos::u32 band_h = header_h - stat_h;
    for (duetos::u32 i = 0; i < ncols; ++i)
    {
        const Col& c = cols[i];
        const bool active = (c.sort != SortMode::kCount && g_sort == c.sort);
        char label[24];
        duetos::u32 lo = 0;
        for (const char* s = ColHeaderLabel(c.id); *s != '\0' && lo + 3 < sizeof(label); ++s)
            label[lo++] = *s;
        if (active)
        {
            label[lo++] = ' ';
            label[lo++] = g_sort_asc ? '^' : 'v';
        }
        label[lo] = '\0';
        const duetos::u32 colour = active ? head_hl : head_fg;
        if (c.right_align)
            AppTextCellRight(ChromeTextRole::Caption, c.x + c.w, c.x, band_y, band_h, label, colour, head_bg);
        else
            AppTextCell(ChromeTextRole::Caption, c.x, band_y, band_h, label, colour, head_bg);
    }
}

void DrawRows(duetos::u32 cx, duetos::u32 cy, duetos::u32 cw, duetos::u32 ch, duetos::u32 fg, duetos::u32 fg_run,
              duetos::u32 sel_bg, duetos::u32 bg)
{
    using duetos::drivers::video::FramebufferDrawString;
    using duetos::drivers::video::FramebufferFillRect;

    const auto p = Pal();
    const duetos::u32 row_h = RowH();
    const duetos::u32 header_h = HeaderH();
    const duetos::u32 list_bg = p.aurora ? p.body : bg;
    const duetos::u32 list_y = cy + header_h;
    const duetos::u32 list_h = (ch > header_h + kFooterH) ? ch - header_h - kFooterH : 0;
    FramebufferFillRect(cx, list_y, cw, list_h, list_bg);

    if (g_row_count == 0 || list_h < row_h)
        return;

    Col cols[kMaxCols];
    const duetos::u32 ncols = BuildCols(cx, cw, p.aurora, cols);

    const duetos::u32 visible = list_h / row_h;
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
        const duetos::u32 row_y = list_y + v * row_h;
        const bool selected = (idx == g_selected);
        // Aurora: `--glass-3` zebra with an accent-tinted selection and
        // a 2-px accent rail, per the design's process table. Flat
        // palettes keep the solid selected-row band and no zebra.
        if (p.aurora)
        {
            FramebufferFillRect(cx, row_y, cw, row_h, selected ? p.sel : ((v & 1u) ? p.wash : p.body));
            if (selected)
                FramebufferFillRect(cx, row_y, 2, row_h, p.accent);
        }
        else if (selected)
        {
            FramebufferFillRect(cx, row_y, cw, row_h, sel_bg);
        }

        char col_pid[12];
        char col_name[24];
        char col_state[12]; // fits the widest Aurora StateLabel ("sleeping")
        char col_cpu[8];
        char col_ticks[16];
        char col_threads[8];
        char col_mem[8];
        if (!r.has_process)
            FmtStrLeft("  --", col_pid, kColPid);
        else if (p.aurora)
            FmtPidHex(r.owner_pid, col_pid, sizeof(col_pid));
        else
            FmtU64Right(r.owner_pid, col_pid, kColPid);
        FmtU64Right(r.threads, col_threads, 3);
        FmtStrLeft(r.name, col_name, kColName);
        FmtStrLeft(StateGlyph(r.state), col_state, kColState);
        FmtCpuPercent(r.ticks_run, g_total_ticks_snap, col_cpu, kColCpu);
        FmtU64Right(r.ticks_run, col_ticks, kColTicks);
        // MEM: show KiB if < 9999, else show "  NNN K" style.
        // Kernel-only tasks (no user AS) show " ----".
        if (r.has_process)
            FmtU64Right(r.mapped_kib, col_mem, kColMem);
        else
            FmtStrLeft(" ----", col_mem, kColMem);

        duetos::u32 row_bg = selected ? sel_bg : bg;
        duetos::u32 row_fg = r.is_running ? fg_run : fg;
        // Aurora row ink: the process NAME carries the primary ink,
        // numeric columns the secondary, and the accent is spent only
        // on the running state — not on the whole row, which is what
        // made the old table read as green-on-black.
        duetos::u32 num_fg = row_fg;
        duetos::u32 state_fg = row_fg;
        if (p.aurora)
        {
            row_bg = selected ? p.sel : ((v & 1u) ? p.wash : p.body);
            row_fg = p.ink;
            num_fg = p.ink_2;
            state_fg = r.is_running ? p.accent : p.ink_3;
        }
        // Cell paint walks the SAME table the header and the
        // header-click hit-test walk. A column can no longer move for
        // the pixels without moving for the click.
        if (!p.aurora)
        {
            const duetos::u32 text_y = row_y + (row_h - 8) / 2;
            for (duetos::u32 i = 0; i < ncols; ++i)
            {
                const Col& c = cols[i];
                const char* s = "";
                duetos::u32 colour = num_fg;
                switch (c.id)
                {
                case ColId::Pid:
                    s = col_pid;
                    break;
                case ColId::Name:
                    s = col_name;
                    colour = row_fg;
                    break;
                case ColId::State:
                    s = col_state;
                    colour = state_fg;
                    break;
                case ColId::Cpu:
                    s = col_cpu;
                    break;
                case ColId::Ticks:
                    s = col_ticks;
                    break;
                case ColId::Mem:
                    s = col_mem;
                    break;
                default:
                    break;
                }
                FramebufferDrawString(c.x, text_y, s, colour, row_bg);
            }
            continue;
        }

        // Aurora: proportional content. The character padding the
        // formatters added is meaningless under a variable-width face,
        // so numeric cells are trimmed and right-aligned on their
        // measured width instead.
        using duetos::drivers::video::ChromeTextRole;
        using duetos::drivers::video::app_widgets::AppPillDraw;
        using duetos::drivers::video::app_widgets::AppRowDotDraw;
        using duetos::drivers::video::app_widgets::AppRowDotWidth;
        using duetos::drivers::video::app_widgets::AppTextCell;
        using duetos::drivers::video::app_widgets::AppTextCellRight;
        using duetos::drivers::video::app_widgets::AppTextFit;
        TrimSpaces(col_pid);
        TrimSpaces(col_cpu);
        // The reference prints the unit on the value ("1.4%"), not on
        // the column heading.
        {
            duetos::u32 n = 0;
            while (col_cpu[n] != '\0')
                ++n;
            if (n + 1 < sizeof(col_cpu))
            {
                col_cpu[n] = '%';
                col_cpu[n + 1] = '\0';
            }
        }
        FmtStrLeft(StateLabel(r.state), col_state, sizeof(col_state) - 1);
        TrimSpaces(col_ticks);
        TrimSpaces(col_threads);
        TrimSpaces(col_mem);
        TrimSpaces(col_state);
        for (duetos::u32 i = 0; i < ncols; ++i)
        {
            const Col& c = cols[i];
            switch (c.id)
            {
            case ColId::Name:
            {
                // Liveness dot then the process name, truncated on a
                // measured width rather than a character count.
                const duetos::u32 dot_w = AppRowDotWidth();
                AppRowDotDraw(c.x, row_y, row_h, r.is_running ? p.accent : p.ink_3);
                char fitted[32];
                const duetos::u32 name_budget = (c.w > dot_w) ? c.w - dot_w : 0;
                AppTextFit(ChromeTextRole::Body, r.name, fitted, sizeof(fitted), name_budget);
                AppTextCell(ChromeTextRole::Body, c.x + dot_w, row_y, row_h, fitted, row_fg, row_bg);
                break;
            }
            case ColId::Pid:
                AppTextCellRight(ChromeTextRole::Body, c.x + c.w, c.x, row_y, row_h, col_pid, num_fg, row_bg);
                break;
            case ColId::Abi:
            {
                // Rows whose ABI the kernel cannot name render no
                // badge at all — AbiBadge returns nullptr and
                // AppPillDraw is a no-op on it.
                const char* badge = AbiBadge(r.abi);
                const duetos::u32 ink = (r.abi == duetos::sched::kTaskAbiWin32Pe) ? p.accent_peer : p.accent;
                AppPillDraw(c.x, row_y, row_h, badge, ink, row_bg);
                break;
            }
            case ColId::Cpu:
                AppTextCellRight(ChromeTextRole::Body, c.x + c.w, c.x, row_y, row_h, col_cpu, num_fg, row_bg);
                break;
            case ColId::Ticks:
                AppTextCellRight(ChromeTextRole::Body, c.x + c.w, c.x, row_y, row_h, col_ticks, num_fg, row_bg);
                break;
            case ColId::Threads:
                AppTextCellRight(ChromeTextRole::Body, c.x + c.w, c.x, row_y, row_h, col_threads, num_fg, row_bg);
                break;
            case ColId::Mem:
                AppTextCellRight(ChromeTextRole::Body, c.x + c.w, c.x, row_y, row_h, col_mem, num_fg, row_bg);
                break;
            case ColId::State:
                AppTextCell(ChromeTextRole::Body, c.x, row_y, row_h, col_state, state_fg, row_bg);
                break;
            }
        }
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

// ---------------------------------------------------------------
// Performance-tab resource rail (Aurora only).
//
// One tile per logical CPU plus the aggregate, from the telemetry
// surface. The window is caller-owned by contract — this is the Task
// Manager's own, so a shell `top` polling at a different cadence
// cannot consume our delta and leave both readings wrong. The first
// sample against a fresh window reports valid == false; the rail then
// prints the core rows with no figure rather than a fabricated 0 %.
// ---------------------------------------------------------------
constexpr duetos::u32 kPerfRailW = 118;
constexpr duetos::u32 kPerfTileH = 26;

// This app's own rolling window. Zero-initialised once and kept —
// never re-zeroed per paint, or every sample would be the "first"
// one and the rail would never show a number.
constinit duetos::diag::TelemetryCpuWindow g_cpu_window{};

void DrawPerfRail(duetos::u32 x, duetos::u32 y, duetos::u32 w, duetos::u32 h,
                  const duetos::drivers::video::app_widgets::AppPalette& p)
{
    using duetos::drivers::video::ChromeTextRole;
    using duetos::drivers::video::FramebufferFillRect;
    using duetos::drivers::video::app_widgets::AppTextCell;
    using duetos::drivers::video::app_widgets::AppTextCellRight;

    FramebufferFillRect(x, y, w, h, p.recess);
    FramebufferFillRect(x + w - 1, y, 1, h, p.line);

    const duetos::diag::TelemetryCpuUsage usage = duetos::diag::TelemetryCpuUsageSample(g_cpu_window);

    duetos::u32 row_y = y;
    auto tile = [&](const char* label, bool has_value, duetos::u8 pct, bool accent)
    {
        if (row_y + kPerfTileH > y + h)
            return;
        // A busy meter behind the label: the tile's own fill scaled to
        // the reading, which is what makes the rail readable at a
        // glance without four more sparklines.
        if (has_value && pct > 0)
        {
            const duetos::u32 bar_w = (w - 2U) * pct / 100U;
            FramebufferFillRect(x + 1, row_y + kPerfTileH - 4, bar_w, 2, accent ? p.accent : p.ink_3);
        }
        AppTextCell(ChromeTextRole::Caption, x + 8, row_y, kPerfTileH - 6, label, p.ink_2, p.recess);
        if (has_value)
        {
            char num[8];
            duetos::u32 n = 0;
            if (pct >= 100)
                num[n++] = '1';
            if (pct >= 10)
                num[n++] = static_cast<char>('0' + (pct / 10) % 10);
            num[n++] = static_cast<char>('0' + pct % 10);
            num[n++] = '%';
            num[n] = '\0';
            AppTextCellRight(ChromeTextRole::Caption, x + w - 8, x, row_y, kPerfTileH - 6, num,
                             accent ? p.accent : p.ink_2, p.recess);
        }
        row_y += kPerfTileH;
    };

    tile("CPU", usage.valid, usage.aggregate_busy_pct, true);
    for (duetos::u32 i = 0; i < usage.core_count && i < duetos::diag::kTelemetryMaxCpus; ++i)
    {
        char label[12];
        label[0] = 'C';
        label[1] = 'o';
        label[2] = 'r';
        label[3] = 'e';
        label[4] = ' ';
        duetos::u32 n = 5;
        if (i >= 10)
            label[n++] = static_cast<char>('0' + i / 10);
        label[n++] = static_cast<char>('0' + i % 10);
        label[n] = '\0';
        tile(label, usage.valid && usage.core_valid[i], usage.core_busy_pct[i], false);
    }
}

void DrawPerformance(duetos::u32 cx, duetos::u32 cy, duetos::u32 cw, duetos::u32 ch, duetos::u32 fg, duetos::u32 fg_cpu,
                     duetos::u32 fg_mem, duetos::u32 grid, duetos::u32 frame, duetos::u32 fill, duetos::u32 bg)
{
    using duetos::drivers::video::FramebufferDrawString;
    using duetos::drivers::video::FramebufferFillRect;
    const auto p = Pal();
    const duetos::u32 list_bg = p.aurora ? p.body : bg;
    const duetos::u32 header_h = HeaderH();
    const duetos::u32 list_y = cy + header_h;
    const duetos::u32 list_h = (ch > header_h + kFooterH) ? ch - header_h - kFooterH : 0;
    FramebufferFillRect(cx, list_y, cw, list_h, list_bg);
    if (list_h < 60)
        return;

    // Aurora: the reference puts a resource rail down the left of the
    // Performance view, one tile per CPU core. The per-core numbers
    // come from the telemetry surface, whose window is CALLER-owned —
    // g_cpu_window below is this app's, so the shell's `top` polling
    // at a different cadence can't eat our delta. The first sample
    // against a fresh window is `valid == false` by contract; the rail
    // shows the core rows with no number until a second sample lands
    // rather than printing a fabricated 0 %.
    const duetos::u32 rail_w = (p.aurora && cw >= 340) ? kPerfRailW : 0U;
    if (rail_w != 0)
        DrawPerfRail(cx, list_y, rail_w, list_h, p);
    // Everything below paints into the slice right of the rail.
    const duetos::u32 gx = cx + rail_w;
    const duetos::u32 gw = cw - rail_w;

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
    FramebufferDrawString(gx + kColPad, list_y + 2, line, p.aurora ? p.ink_2 : fg_cpu, list_bg);
    DrawSparkline(gx + kColPad, list_y + lbl_h, gw - 2 * kColPad, graph_h, fg_cpu, grid, frame, fill, true);

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
    FramebufferDrawString(gx + kColPad, list_y + stack_h + 2, line, p.aurora ? p.ink_2 : fg_mem, list_bg);
    DrawSparkline(gx + kColPad, list_y + stack_h + lbl_h, gw - 2 * kColPad, graph_h, fg_mem, grid, frame, fill, false);

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
        FramebufferDrawString(gx + kColPad, cy + ch - kFooterH - 12, line, p.aurora ? p.ink_3 : fg, list_bg);
}

// ---------------------------------------------------------------
// ABI-peers tab (Aurora only) — `15-taskmanager-abi-peers.png`.
//
// One card per user ABI, each listing the snapshot rows whose
// SchedTaskInfo::abi names that channel. No new kernel reading: this
// is the process table grouped by a field it already carries, which
// is why a task the kernel cannot classify appears in no card rather
// than in a guessed one.
//
// The reference's per-card subtitles (DLL / export counts) have no
// backing reading in DuetOS, so the cards carry a name and a real
// count and nothing else.
// ---------------------------------------------------------------
void DrawAbiPeers(duetos::u32 cx, duetos::u32 cy, duetos::u32 cw, duetos::u32 ch)
{
    using duetos::drivers::video::ChromeTextRole;
    using duetos::drivers::video::ChromeTextWeight;
    using duetos::drivers::video::FramebufferFillRect;
    using duetos::drivers::video::FramebufferFillRoundRect;
    using duetos::drivers::video::app_widgets::AppRowDotDraw;
    using duetos::drivers::video::app_widgets::AppRowDotWidth;
    using duetos::drivers::video::app_widgets::AppTextCell;
    using duetos::drivers::video::app_widgets::AppTextCellRight;
    using duetos::drivers::video::app_widgets::AppTextFit;

    const auto p = Pal();
    FramebufferFillRect(cx, cy, cw, ch, p.body);

    constexpr duetos::u32 kCards = 3;
    constexpr duetos::u32 kCardGap = 8;
    constexpr duetos::u32 kCardPad = 10;
    static constexpr duetos::u8 kChannels[kCards] = {duetos::sched::kTaskAbiNative, duetos::sched::kTaskAbiWin32Pe,
                                                     duetos::sched::kTaskAbiLinux};
    static const char* const kNames[kCards] = {"Native", "Win32 PE", "Linux"};

    if (cw < kCards * 80U || ch < 60U)
        return;
    const duetos::u32 card_w = (cw - (kCards + 1U) * kCardGap) / kCards;
    const duetos::u32 card_h = (ch > 2U * kCardGap) ? ch - 2U * kCardGap : ch;
    const duetos::u32 row_h = RowH();

    for (duetos::u32 ci = 0; ci < kCards; ++ci)
    {
        const duetos::u32 x = cx + kCardGap + ci * (card_w + kCardGap);
        const duetos::u32 y = cy + kCardGap;
        FramebufferFillRoundRect(x, y, card_w, card_h, 6, p.wash);
        const duetos::u32 ink = (kChannels[ci] == duetos::sched::kTaskAbiNative)    ? p.accent
                                : (kChannels[ci] == duetos::sched::kTaskAbiWin32Pe) ? p.accent_peer
                                                                                    : p.ink_3;
        const duetos::u32 dot = AppRowDotWidth();
        AppRowDotDraw(x + kCardPad, y, row_h + 6, ink);
        AppTextCell(ChromeTextRole::Body, x + kCardPad + dot, y, row_h + 6, kNames[ci], p.ink, p.wash,
                    ChromeTextWeight::Bold);
        FramebufferFillRect(x, y + row_h + 6, card_w, 1, p.line);

        duetos::u32 listed = 0;
        const duetos::u32 list_top = y + row_h + 7;
        const duetos::u32 list_max = (card_h > row_h * 2 + 8) ? (card_h - (row_h + 7) - row_h) / row_h : 0;
        for (duetos::u32 i = 0; i < g_row_count && listed < list_max; ++i)
        {
            if (g_rows[i].abi != kChannels[ci])
                continue;
            const duetos::u32 ry = list_top + listed * row_h;
            char pid[12];
            FmtPidHex(g_rows[i].owner_pid, pid, sizeof(pid));
            char fitted[32];
            AppTextFit(ChromeTextRole::Body, g_rows[i].name, fitted, sizeof(fitted),
                       (card_w > 2 * kCardPad + 56) ? card_w - 2 * kCardPad - 56 : 0);
            AppTextCell(ChromeTextRole::Body, x + kCardPad, ry, row_h, fitted, p.ink_2, p.wash);
            AppTextCellRight(ChromeTextRole::Body, x + card_w - kCardPad, x, ry, row_h, pid, p.ink_3, p.wash);
            ++listed;
        }

        char foot[24];
        FmtU64Right(listed, foot, 1);
        char line[40];
        duetos::u32 o = 0;
        StatusAppend(line, sizeof(line), &o, foot);
        StatusAppend(line, sizeof(line), &o, listed == 1 ? " task" : " tasks");
        line[o] = '\0';
        AppTextCell(ChromeTextRole::Caption, x + kCardPad, y + card_h - row_h, row_h, line, p.ink_3, p.wash);
    }
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

    // Aurora sparkline card: the design's 60x26 cards sit on a
    // `--recess` ground with a hairline frame and accent / peer plot
    // lines — no saturated green wireframe.
    const auto p = Pal();
    const duetos::u32 ground = p.aurora ? p.body : bg;
    const duetos::u32 graph_grid = p.aurora ? p.line : kGrid;
    const duetos::u32 graph_frame = p.aurora ? p.line : kFrame;
    const duetos::u32 graph_fill = p.aurora ? p.recess : kFill;
    const duetos::u32 plot_cpu = p.aurora ? p.accent : kFgCpu;
    const duetos::u32 plot_mem = p.aurora ? p.accent_peer : kFgMem;
    FramebufferFillRect(cx, cy, cw, ch, ground);

    MaybeSampleHistory();
    RebuildSnapshot();

    // Pass D chrome: AppToolbar at top (kHdrToolbarH), legacy
    // header + rows + perf-graph paint in the middle, AppLabel
    // footer at the bottom (kFooterBandH). The middle slice is
    // what DrawHeader / DrawRows / DrawPerformance receive.
    BindTaskmanOnce();
    ApplyTaskmanPalette();
    RebindTaskmanBounds(cx, cy, cw, ch);
    RefreshTaskmanStatus();
    // Pre-paint the footer band tone so the AppLabel glyphs sit
    // on a uniform bg (AppLabel paints only its glyphs, not a
    // full-width band).
    if (ch > kFooterBandH)
    {
        if (p.aurora)
        {
            duetos::drivers::video::app_widgets::AppStatusBarDraw(cx, cy + ch - kFooterBandH, cw, kFooterBandH, p);
        }
        else
        {
            FramebufferFillRect(cx, cy + ch - kFooterBandH, cw, kFooterBandH, 0x00C8C8B8U);
        }
    }
    Compose compose_ctx{};
    g_taskman.PaintAll(compose_ctx);
    // Aurora strip decoration goes on top of the tab labels the widget
    // group just painted: the active tab's 2-px rule, the hairline
    // under the strip, and the cadence chip. All three come out of the
    // same HdrStripFor table the buttons were bound from.
    if (p.aurora)
    {
        using duetos::drivers::video::app_widgets::AppRowDotDraw;
        using duetos::drivers::video::app_widgets::AppRowDotWidth;
        using duetos::drivers::video::app_widgets::AppTextCell;
        const HdrStrip strip = HdrStripFor(cx, cy, cw);
        if (strip.underline.w != 0)
        {
            FramebufferFillRect(strip.underline.x, strip.underline.y, strip.underline.w, strip.underline.h, p.accent);
        }
        FramebufferFillRect(cx, strip.rule_y, cw, 1, p.line);
        if (strip.live.w != 0)
        {
            const duetos::u32 dot = AppRowDotWidth();
            duetos::drivers::video::FramebufferFillRoundRect(strip.live.x, strip.live.y, strip.live.w, strip.live.h,
                                                             strip.live.h / 2, p.recess);
            AppRowDotDraw(strip.live.x + kTabPadX, strip.live.y, strip.live.h, p.accent);
            AppTextCell(duetos::drivers::video::ChromeTextRole::Caption, strip.live.x + kTabPadX + dot, strip.live.y,
                        strip.live.h, kLiveChipLabel, p.ink_3, p.recess);
        }
    }

    // Middle slice for the legacy content paint. kHdrToolbarH
    // off the top, kFooterBandH off the bottom. The legacy
    // DrawHeader expects to paint its own header band at the
    // top of the slice it receives; passing my/mh achieves
    // that without changing DrawHeader / DrawRows.
    const duetos::u32 my = cy + kHdrToolbarH;
    const duetos::u32 mh = (ch > kHdrToolbarH + kFooterBandH) ? ch - kHdrToolbarH - kFooterBandH : 0U;
    if (mh == 0)
        return;
    if (g_tab == Tab::AbiPeers)
    {
        // The cards are the whole view — no column-header band above
        // them, exactly as the reference draws it.
        DrawAbiPeers(cx, my, cw, mh);
        return;
    }
    DrawHeader(cx, my, cw, kFg, kHl, ground);
    if (g_tab == Tab::Processes)
        DrawRows(cx, my, cw, mh, kFg, kFgRun, kSelBg, ground);
    else
        DrawPerformance(cx, my, cw, mh, kFg, plot_cpu, plot_mem, graph_grid, graph_frame, graph_fill, ground);
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

void ClickAbiPeersTab()
{
    // Only reachable while the Aurora strip exposes the slot; the
    // palette pass clamps g_tab back to Processes if the theme cycles
    // away from Aurora while this view is live.
    g_tab = Tab::AbiPeers;
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
// Column-header click hit-test (F-025).
//
// The PROCESSES tab column headings are painted in the band
//   [client_top + kHdrToolbarH + StatLineH(), client_top + kHdrToolbarH + HeaderH())
// `client_y` / `client_h` are the window manager's client rect
// (WindowGetClientRect) — never a hardcoded title-bar constant,
// which is per-theme.
//
// Column X origins come from `BuildCols` — the same table DrawHeader
// paints the labels with and DrawRows paints the cells with. Each
// column owns the half-open hit zone [x, x + w). Deriving the zones
// here instead of re-writing the arithmetic is what keeps the click
// and the pixels in phase.
//
// Returns kCount when the point is not inside any sortable column
// header zone.
// ---------------------------------------------------------------
SortMode HitTestColHeader(duetos::u32 px, duetos::u32 py, duetos::u32 client_x, duetos::u32 client_y,
                          duetos::u32 client_w, duetos::u32 client_h)
{
    // Column headings sit in the band that starts StatLineH() below
    // the header top and runs to the end of HeaderH() — the same two
    // accessors DrawHeader fills and paints into. Aurora folds the
    // stats line away, so StatLineH() is 0 there and the zone starts
    // at the top of the header band.
    const duetos::u32 header_top = client_y + kHdrToolbarH + StatLineH();
    const duetos::u32 header_bot = client_y + kHdrToolbarH + HeaderH();

    if (py < header_top || py >= header_bot)
        return SortMode::kCount;
    if (px < client_x || px >= client_x + client_w || client_h == 0)
        return SortMode::kCount;

    // Only active on the PROCESSES tab.
    if (g_tab != Tab::Processes)
        return SortMode::kCount;

    // Hit zones come from the SAME BuildCols table DrawHeader painted
    // and DrawRows filled. Each column owns [x, x + w); an unsortable
    // column (ABI, TICKS) reports kCount and the click falls through.
    Col cols[kMaxCols];
    const duetos::u32 ncols = BuildCols(client_x, client_w, Pal().aurora, cols);
    for (duetos::u32 i = 0; i < ncols; ++i)
    {
        if (px >= cols[i].x && px < cols[i].x + cols[i].w)
            return cols[i].sort;
    }
    return SortMode::kCount;
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
        // Cycle the tabs the active theme exposes: PROCESSES <->
        // PERFORMANCE on the flat palettes, plus ABI PEERS on Aurora.
        // TabCount() is the same accessor the header strip lays out
        // from, so the keyboard cycle can never reach a tab the strip
        // does not show.
        const duetos::u32 next = static_cast<duetos::u32>(g_tab) + 1U;
        g_tab = (next >= TabCount()) ? Tab::Processes : static_cast<Tab>(next);
        return true;
    }
    if (c == 's' || c == 'S')
    {
        // Cycle to the next sort mode and reset to that mode's
        // natural default direction (descending for CPU%/MEM,
        // ascending for PID/NAME/STATE).
        const auto next = static_cast<duetos::u8>(g_sort) + 1;
        g_sort = (next >= static_cast<duetos::u8>(SortMode::kCount)) ? SortMode::Cpu : static_cast<SortMode>(next);
        g_sort_asc = (g_sort == SortMode::Pid || g_sort == SortMode::Name || g_sort == SortMode::State);
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
    // First failing check, so a FAIL line names the check instead of
    // making the next session bisect a 200-line test by hand. 0 = clean.
    duetos::u32 fail_code = 0;
    auto fail = [&](duetos::u32 code)
    {
        pass = false;
        if (fail_code == 0)
            fail_code = code;
    };

    // Build a synthetic 4-row table and run each sort mode.
    Row saved[kMaxRows];
    for (duetos::u32 i = 0; i < kMaxRows; ++i)
        saved[i] = g_rows[i];
    const duetos::u32 saved_count = g_row_count;
    const SortMode saved_mode = g_sort;
    const bool saved_asc = g_sort_asc;

    g_row_count = 4;
    auto fill = [](Row& r, duetos::u64 id, duetos::u64 pid, const char* name, duetos::u64 ticks, duetos::u8 state,
                   duetos::u32 mem_kib)
    {
        r.task_id = id;
        r.owner_pid = pid;
        r.has_process = pid != 0;
        duetos::u32 o = 0;
        for (; o + 1 < sizeof(r.name) && name[o] != '\0'; ++o)
            r.name[o] = name[o];
        r.name[o] = '\0';
        r.ticks_run = ticks;
        r.mapped_kib = mem_kib;
        r.state = state;
        r.priority = 0;
        r.abi = pid != 0 ? duetos::sched::kTaskAbiNative : duetos::sched::kTaskAbiNone;
        r.is_running = false;
    };
    using duetos::sched::TaskState;
    // mapped_kib values: boot=8, alpha=64, beta=4, Gamma=128
    fill(g_rows[0], 1, 10, "boot", 5, static_cast<duetos::u8>(TaskState::Sleeping), 8u);
    fill(g_rows[1], 2, 20, "alpha", 50, static_cast<duetos::u8>(TaskState::Running), 64u);
    fill(g_rows[2], 3, 30, "beta", 1, static_cast<duetos::u8>(TaskState::Ready), 4u);
    fill(g_rows[3], 4, 5, "Gamma", 100, static_cast<duetos::u8>(TaskState::Blocked), 128u);

    // All sort tests run with descending as the default direction for
    // CPU%/MEM, ascending for PID/NAME/STATE.
    g_sort = SortMode::Cpu;
    g_sort_asc = false; // descending
    SortRows();
    if (g_rows[0].task_id != 4 || g_rows[1].task_id != 2 || g_rows[2].task_id != 1 || g_rows[3].task_id != 3)
        fail(1);

    g_sort = SortMode::Pid;
    g_sort_asc = true; // ascending
    SortRows();
    // Expected ascending PID: 5(g), 10(b), 20(a), 30(beta)
    if (g_rows[0].owner_pid != 5 || g_rows[1].owner_pid != 10 || g_rows[2].owner_pid != 20 || g_rows[3].owner_pid != 30)
        fail(2);

    g_sort = SortMode::Name;
    g_sort_asc = true; // ascending
    SortRows();
    // Case-insensitive ascending: alpha, beta, boot, Gamma
    if (CompareNamesCi(g_rows[0].name, "alpha") != 0 || CompareNamesCi(g_rows[1].name, "beta") != 0 ||
        CompareNamesCi(g_rows[2].name, "boot") != 0 || CompareNamesCi(g_rows[3].name, "Gamma") != 0)
        fail(3);

    g_sort = SortMode::State;
    g_sort_asc = false; // descending (Running > Ready > Sleeping > Blocked)
    SortRows();
    // Expected order by StateSortKey desc: Running, Ready, Sleeping, Blocked
    if (static_cast<TaskState>(g_rows[0].state) != TaskState::Running ||
        static_cast<TaskState>(g_rows[1].state) != TaskState::Ready ||
        static_cast<TaskState>(g_rows[2].state) != TaskState::Sleeping ||
        static_cast<TaskState>(g_rows[3].state) != TaskState::Blocked)
        fail(4);

    // SortMode::Mem descending: Gamma(128) > alpha(64) > boot(8) > beta(4)
    g_sort = SortMode::Mem;
    g_sort_asc = false;
    SortRows();
    if (g_rows[0].mapped_kib != 128u || g_rows[1].mapped_kib != 64u || g_rows[2].mapped_kib != 8u ||
        g_rows[3].mapped_kib != 4u)
        fail(5);

    // SortMode::Mem ascending: beta(4) > boot(8) > alpha(64) > Gamma(128)
    g_sort = SortMode::Mem;
    g_sort_asc = true;
    SortRows();
    if (g_rows[0].mapped_kib != 4u || g_rows[1].mapped_kib != 8u || g_rows[2].mapped_kib != 64u ||
        g_rows[3].mapped_kib != 128u)
        fail(6);

    // Hex PID rendering — the reference's `0x01` / `0x1a` / `0x0120`
    // shape. A table of PIDs that lost its zero padding stops reading
    // as a column, so the padding rule is pinned, not eyeballed.
    struct HexCase
    {
        duetos::u64 pid;
        const char* want;
    };
    static constexpr HexCase kHexCases[] = {
        {0, "0x00"}, {1, "0x01"}, {0x1a, "0x1a"}, {0xff, "0xff"}, {0x120, "0x0120"}};
    for (const auto& hc : kHexCases)
    {
        char got[12];
        FmtPidHex(hc.pid, got, sizeof(got));
        duetos::u32 k = 0;
        while (hc.want[k] != '\0' && got[k] == hc.want[k])
            ++k;
        if (hc.want[k] != '\0' || got[k] != '\0')
            fail(7);
    }

    // Unpadded decimals for the status line. The column formatter's
    // clamp-to-width is right for a cell and catastrophic for prose,
    // so the status line's formatter is pinned separately: this is
    // exactly the shape that turned "14 threads" into "1 threads".
    {
        struct DecCase
        {
            duetos::u64 v;
            const char* want;
        };
        static constexpr DecCase kDec[] = {{0, "0"}, {7, "7"}, {14, "14"}, {8128, "8128"}};
        for (const auto& dc : kDec)
        {
            char got[16];
            FmtU64Plain(dc.v, got, sizeof(got));
            duetos::u32 k = 0;
            while (dc.want[k] != '\0' && got[k] == dc.want[k])
                ++k;
            if (dc.want[k] != '\0' || got[k] != '\0')
                fail(8);
        }
    }

    // Every value a fixed column can hold must MEASURE no wider than
    // the column BuildCols reserved for it. AppTextCellRight drops a
    // run that would start left of its column, so an under-measured
    // bound does not clip - it renders nothing at all, which is how a
    // whole column of PIDs went missing while the table still looked
    // plausible. The bounds are strings, and under a proportional face
    // "0xffff" is NARROWER than "0xfeee", so eyeballing them is not a
    // check.
    {
        using duetos::drivers::video::ChromeTextRole;
        using duetos::drivers::video::app_widgets::AppTextMeasure;
        Col probe[kMaxCols];
        const duetos::u32 nprobe = BuildCols(0U, 520U, true, probe);
        duetos::u32 pid_w = 0;
        duetos::u32 state_w = 0;
        for (duetos::u32 i = 0; i < nprobe; ++i)
        {
            if (probe[i].id == ColId::Pid)
                pid_w = probe[i].w;
            if (probe[i].id == ColId::State)
                state_w = probe[i].w;
        }
        static constexpr duetos::u64 kPidProbes[] = {0x0ull, 0x1ull, 0x6ull, 0x64ull, 0xcafeull, 0xfeeeull, 0xffffull};
        for (duetos::u64 pv : kPidProbes)
        {
            char buf[12];
            FmtPidHex(pv, buf, sizeof(buf));
            if (AppTextMeasure(ChromeTextRole::Body, buf) > pid_w)
                fail(9);
        }
        for (duetos::u32 st = 0; st < 6; ++st)
        {
            if (AppTextMeasure(ChromeTextRole::Body, StateLabel(static_cast<duetos::u8>(st))) > state_w)
                fail(10);
        }
    }

    // Thread counts group by owner_pid over the rows already in hand.
    // Give two rows the same PID and check both report 2 while the
    // kernel-only shape reports 1 rather than pooling under PID 0.
    g_rows[1].owner_pid = 20;
    g_rows[1].has_process = true;
    g_rows[2].owner_pid = 20;
    g_rows[2].has_process = true;
    g_rows[3].has_process = false;
    g_rows[3].owner_pid = 0;
    ComputeThreadCounts();
    if (g_rows[0].threads != 1 || g_rows[1].threads != 2 || g_rows[2].threads != 2 || g_rows[3].threads != 1)
        fail(11);
    if (DistinctProcessCount() != 2)
        fail(12);

    // Restore the sort-comparator state before the Pass D click
    // test runs (the click trampoline may mutate g_tab, which is
    // independent of g_sort but cleaner to restore in one block).
    for (duetos::u32 i = 0; i < kMaxRows; ++i)
        g_rows[i] = saved[i];
    g_row_count = saved_count;
    g_sort = saved_mode;
    g_sort_asc = saved_asc;

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
    // Labels / click actions / weights are branch-dependent and are
    // applied per paint; drive that here too so the synthetic clicks
    // hit the same wiring a live paint would have installed.
    ApplyTaskmanPalette();
    RebindTaskmanBounds(0U, 22U, 520U, 260U);

    // Every synthetic click aims at HdrStripFor's slot rects — the
    // SAME table RebindTaskmanBounds bound the buttons from and DrawFn
    // paints the active rule from. The old test re-derived the chip
    // pitch from kHdrPadX / kHdrBtnW by hand, so a strip that moved
    // for the pixels but not for the click would still have passed.
    const HdrStrip strip = HdrStripFor(0U, 22U, 520U);

    // (a) The strip's slots must be inside the band and must not
    //     overlap; an overlap means two tabs share a click.
    duetos::u32 prev_right = 0;
    for (duetos::u32 i = 0; i < kHdrBtnCount; ++i)
    {
        const Rect& r = strip.slot[i];
        if (r.w == 0)
            continue;
        if (r.y < strip.band.y || r.y + r.h > strip.band.y + strip.band.h)
            fail(13);
        if (r.x < prev_right)
            fail(14);
        prev_right = r.x + r.w;
    }

    auto click_slot = [&](duetos::u32 i) -> bool
    {
        const Rect& r = strip.slot[i];
        if (r.w == 0)
            return true; // folded away on this branch — nothing to drive
        const duetos::u32 px = r.x + r.w / 2U;
        const duetos::u32 py = r.y + r.h / 2U;
        const Event mv{EventKind::MouseMove, px, py, 0U, 0U};
        const Event dn{EventKind::MouseDown, px, py, 0U, 0U};
        const Event up{EventKind::MouseUp, px, py, 0U, 0U};
        return g_taskman.DispatchEvent(mv) == EventResult::Consumed &&
               g_taskman.DispatchEvent(dn) == EventResult::Consumed &&
               g_taskman.DispatchEvent(up) == EventResult::Consumed;
    };

    // Slot 1 selects PERFORMANCE and slot 0 returns to PROCESSES on
    // BOTH branches — the flat chips and the Aurora tabs agree there,
    // so the assertion is branch-independent.
    g_tab = Tab::Processes;
    if (!click_slot(1) || g_tab != Tab::Performance)
        fail(15);
    if (!click_slot(0) || g_tab != Tab::Processes)
        fail(16);

    // Slot kBtnRefresh is the flat palettes' REFRESH chip (idempotent,
    // never destructive) and folds to zero width under Aurora, where
    // every paint re-enumerates already.
    if (!click_slot(kBtnRefresh))
        fail(17);

    // Footer-text composer: must produce non-empty text for the
    // current sort mode. Mutating g_sort here is fine — it's
    // restored below as part of the saved-mode pair.
    RefreshTaskmanStatus();
    if (g_footer_text[0] == '\0')
        fail(18);

    g_tab = saved_tab;

    g_self_test_passed = pass;
    if (pass)
    {
        SerialWrite("[taskman] self-test OK (sort comparators incl. Mem asc/desc, widget-click, footer-refresh)\n");
        SerialWrite("[taskman-selftest] PASS\n");
    }
    else
    {
        // Name the first failing check. The ordinal is the check's
        // position in this function, counting from 1 — enough to land
        // a reader on the exact assertion without re-running a bisect.
        char code[8];
        FmtU64Plain(fail_code, code, sizeof(code));
        SerialWrite("[taskman] self-test FAILED at check ");
        SerialWrite(code);
        SerialWrite("\n");
        SerialWrite("[taskman-selftest] FAIL\n");
        KBP_PROBE_V(duetos::debug::ProbeId::kBootSelftestFail, fail_code);
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
    // The client rect comes from the window manager — the title bar is
    // per-theme (22 on the flat palettes, 30 across the Duet family),
    // so a hardcoded constant puts every click out of phase with the
    // paint. RebindTaskmanBounds takes the same rect DrawFn receives.
    duetos::u32 wx = 0, client_y = 0, ww = 0, client_h = 0;
    if (!duetos::drivers::video::WindowGetClientRect(g_handle, &wx, &client_y, &ww, &client_h))
        return;
    if (client_h == 0)
        return;
    BindTaskmanOnce();
    RebindTaskmanBounds(wx, client_y, ww, client_h);

    const bool left_down = (button_mask & kMouseButtonLeft) != 0;
    const bool press_edge = left_down && !g_prev_left_down;
    const bool release_edge = !left_down && g_prev_left_down;
    g_prev_left_down = left_down;

    const bool inside_window = (cx >= wx && cx < wx + ww && cy >= client_y && cy < client_y + client_h);
    if (inside_window)
    {
        const Event m{EventKind::MouseMove, cx, cy, 0U, 0U};
        g_taskman.DispatchEvent(m);
    }
    if (press_edge && inside_window)
    {
        // F-025: column-header click sort. HitTestColHeader runs
        // before the toolbar widget dispatch so a click on a
        // column header takes priority over the toolbar (they are
        // in disjoint Y bands, but ordering is explicit here to
        // keep the two surfaces independent). If the hit lands on a
        // sortable column, update g_sort and g_sort_asc then return
        // — the compositor will repaint on the next tick.
        const SortMode hit = HitTestColHeader(cx, cy, wx, client_y, ww, client_h);
        if (hit != SortMode::kCount)
        {
            if (g_sort == hit)
            {
                // Same column clicked again: toggle asc/desc.
                g_sort_asc = !g_sort_asc;
            }
            else
            {
                // New column: set default direction for this mode.
                // CPU% and MEM default to descending (highest first);
                // PID, NAME, STATE default to ascending.
                g_sort = hit;
                g_sort_asc = (hit == SortMode::Pid || hit == SortMode::Name || hit == SortMode::State);
            }
            KLOG_DEBUG_S("taskman", "header-click sort", "mode", SortModeName(g_sort));
            // Don't fall through to DispatchEvent — the header band is
            // not a toolbar widget zone.
            return;
        }

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
