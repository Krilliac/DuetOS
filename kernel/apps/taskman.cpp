#include "apps/taskman.h"

#include "arch/x86_64/serial.h"
#include "drivers/input/ps2kbd.h"
#include "drivers/video/dialog.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/notify.h"
#include "drivers/video/theme.h"
#include "mm/frame_allocator.h"
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
    append("CPU ");
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

    // Line 2: column headers, with the active sort key highlighted.
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

void DrawFooter(duetos::u32 cx, duetos::u32 cy, duetos::u32 cw, duetos::u32 ch, duetos::u32 fg, duetos::u32 bg)
{
    using duetos::drivers::video::FramebufferDrawString;
    using duetos::drivers::video::FramebufferFillRect;
    if (ch < kFooterH)
        return;
    const duetos::u32 y = cy + ch - kFooterH;
    FramebufferFillRect(cx, y, cw, kFooterH, bg);
    char hint[80];
    duetos::u32 o = 0;
    auto append = [&](const char* s)
    {
        while (*s != '\0' && o + 1 < sizeof(hint))
            hint[o++] = *s++;
    };
    append("UP/DN PGUP/PGDN  S:SORT-");
    append(SortModeName(g_sort));
    append("  K:KILL  R:REFRESH");
    hint[o] = '\0';
    FramebufferDrawString(cx + kColPad, y + 2, hint, fg, bg);
}

void DrawFn(duetos::u32 cx, duetos::u32 cy, duetos::u32 cw, duetos::u32 ch, void* /*cookie*/)
{
    using duetos::drivers::video::FramebufferFillRect;
    const auto& theme = duetos::drivers::video::ThemeCurrent();
    const duetos::u32 bg = theme.role_client[static_cast<duetos::u32>(duetos::drivers::video::ThemeRole::TaskManager)];
    constexpr duetos::u32 kFg = 0x00C8E0FF;    // soft-blue text
    constexpr duetos::u32 kFgRun = 0x0080FF80; // bright green for the on-CPU task
    constexpr duetos::u32 kHl = 0x00FFD060;    // amber — active sort key
    constexpr duetos::u32 kSelBg = 0x00204060; // selected-row band
    FramebufferFillRect(cx, cy, cw, ch, bg);

    RebuildSnapshot();
    DrawHeader(cx, cy, cw, kFg, kHl, bg);
    DrawRows(cx, cy, cw, ch, kFg, kFgRun, kSelBg, bg);
    DrawFooter(cx, cy, cw, ch, kFg, bg);
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

    // Restore.
    for (duetos::u32 i = 0; i < kMaxRows; ++i)
        g_rows[i] = saved[i];
    g_row_count = saved_count;
    g_sort = saved_mode;

    SerialWrite(pass ? "[taskman] self-test OK (sort comparators)\n" : "[taskman] self-test FAILED\n");
}

} // namespace duetos::apps::taskman
