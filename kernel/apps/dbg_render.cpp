#include "apps/dbg_internal.h"

#include "apps/dbg_core.h"
#include "arch/x86_64/traps.h"
#include "debug/breakpoints.h"
#include "debug/disasm.h"
#include "drivers/video/framebuffer.h"
#include "util/types.h"

/*
 * DuetOS — debugger paint code.
 *
 * Receives the client-area rect from the compositor's content-
 * draw callback, walks the active tab's data via dbg_core, and
 * blits into the framebuffer with FramebufferDrawString +
 * FramebufferFillRect. Read-only — every state read goes through
 * `internal::g_state` (declared in `dbg_internal.h`).
 */

namespace duetos::apps::dbg::render
{

namespace
{

// 8x8 glyphs. The framebuffer renderer scales 1x by default.
constexpr u32 kRowPx = 10; // glyph + 2px gutter for legibility
constexpr u32 kTabBarH = 18;
constexpr u32 kStatusBarH = 12;

// Theme palette — picked to match DuetOS' Slate-10 default.
constexpr u32 kBgClient = 0x101418;
constexpr u32 kBgTab = 0x202830;
constexpr u32 kBgTabActive = 0x405060;
constexpr u32 kFgText = 0xC0C8D0;
constexpr u32 kFgAccent = 0x60E0FF;
constexpr u32 kFgWarn = 0xFFA060;

void DrawHexU64(u32 x, u32 y, u64 v, u32 fg, u32 bg)
{
    static const char kHex[] = "0123456789abcdef";
    char buf[19];
    buf[0] = '0';
    buf[1] = 'x';
    for (int i = 0; i < 16; ++i)
        buf[2 + i] = kHex[(v >> ((15 - i) * 4)) & 0xF];
    buf[18] = 0;
    duetos::drivers::video::FramebufferDrawString(x, y, buf, fg, bg);
}

void DrawDecU64(u32 x, u32 y, u64 v, u32 fg, u32 bg)
{
    char buf[24];
    if (v == 0)
    {
        buf[0] = '0';
        buf[1] = 0;
    }
    else
    {
        char tmp[24];
        u32 n = 0;
        while (v != 0 && n < sizeof(tmp))
        {
            tmp[n++] = (char)('0' + (v % 10));
            v /= 10;
        }
        u32 w = 0;
        while (n > 0 && w + 1 < sizeof(buf))
            buf[w++] = tmp[--n];
        buf[w] = 0;
    }
    duetos::drivers::video::FramebufferDrawString(x, y, buf, fg, bg);
}

void RenderTabBar(u32 x, u32 y, u32 w, Tab active)
{
    duetos::drivers::video::FramebufferFillRect(x, y, w, kTabBarH, kBgTab);
    static const char* const kLabels[] = {
        "1:Procs", "2:Mem", "3:Regs", "4:BP", "5:Watch", "6:Scan", "7:Disasm",
    };
    const u32 tab_w = w / 7;
    for (u32 i = 0; i < 7; ++i)
    {
        const u32 tx = x + i * tab_w;
        const u32 bg = (i == static_cast<u32>(active)) ? kBgTabActive : kBgTab;
        duetos::drivers::video::FramebufferFillRect(tx, y, tab_w - 1, kTabBarH, bg);
        duetos::drivers::video::FramebufferDrawString(tx + 4, y + 5, kLabels[i], kFgText, bg);
    }
}

void RenderStatusBar(u32 x, u32 y, u32 w)
{
    duetos::drivers::video::FramebufferFillRect(x, y, w, kStatusBarH, kBgTab);
    duetos::drivers::video::FramebufferDrawString(x + 4, y + 2, "TAB:nav  ESC:release  j/k:scroll  Enter:pick", kFgText,
                                                  kBgTab);
}

void RenderProcesses(u32 x, u32 y, u32 w, u32 h)
{
    duetos::drivers::video::FramebufferDrawString(x, y, "PID  STATE  TICKS       NAME", kFgAccent, kBgClient);
    core::ProcInfo rows[64];
    const u64 n = core::EnumerateProcesses(rows, 64);
    const u32 max_visible = (h - kRowPx) / kRowPx;
    const u32 sel = internal::g_state.proc_scroll_rows;
    for (u32 i = 0; i < n && i < max_visible; ++i)
    {
        const u32 ry = y + (i + 1) * kRowPx;
        const u32 bg = (i == sel) ? kBgTabActive : kBgClient;
        duetos::drivers::video::FramebufferFillRect(x, ry, w, kRowPx, bg);
        DrawDecU64(x, ry, rows[i].pid, kFgText, bg);
        const char* st = "?";
        switch (rows[i].state)
        {
        case 0:
            st = "run ";
            break;
        case 3:
            st = "zomb";
            break;
        }
        duetos::drivers::video::FramebufferDrawString(x + 40, ry, st, kFgText, bg);
        DrawDecU64(x + 88, ry, rows[i].ticks_used, kFgText, bg);
        duetos::drivers::video::FramebufferDrawString(x + 200, ry, rows[i].name, kFgText, bg);
    }
}

void RenderMemory(u32 x, u32 y, u32 w, u32 h)
{
    (void)w;
    duetos::drivers::video::FramebufferDrawString(x, y, "ADDRESS           BYTES", kFgAccent, kBgClient);
    if (internal::g_state.current_pid == 0 && internal::g_state.mem_cursor_va == 0)
    {
        duetos::drivers::video::FramebufferDrawString(x, y + kRowPx * 2, "Pick a process in the Procs tab first.",
                                                      kFgWarn, kBgClient);
        return;
    }
    const u64 base = internal::g_state.mem_cursor_va;
    const u32 max_visible = (h - kRowPx) / kRowPx;
    u8 buf[16];
    for (u32 i = 0; i < max_visible; ++i)
    {
        const u64 row_va = base + (u64)i * 16;
        const u32 ry = y + (i + 1) * kRowPx;
        DrawHexU64(x, ry, row_va, kFgText, kBgClient);
        const u64 got = core::ReadMem(internal::g_state.current_pid, row_va, buf, 16);
        if (got == 0)
        {
            duetos::drivers::video::FramebufferDrawString(x + 156, ry, "<unmapped>", kFgWarn, kBgClient);
            continue;
        }
        char hex_text[64] = {0};
        u32 hp = 0;
        static const char kHex[] = "0123456789abcdef";
        for (u64 b = 0; b < got && hp + 4 < sizeof(hex_text); ++b)
        {
            hex_text[hp++] = kHex[(buf[b] >> 4) & 0xF];
            hex_text[hp++] = kHex[buf[b] & 0xF];
            hex_text[hp++] = ' ';
        }
        hex_text[hp] = 0;
        duetos::drivers::video::FramebufferDrawString(x + 156, ry, hex_text, kFgText, kBgClient);
    }
}

void RenderRegs(u32 x, u32 y, u32 w, u32 h)
{
    (void)w;
    (void)h;
    duetos::drivers::video::FramebufferDrawString(x, y, "TRAP FRAME (suspended task)", kFgAccent, kBgClient);
    if (internal::g_state.active_bp.value == 0)
    {
        duetos::drivers::video::FramebufferDrawString(
            x, y + kRowPx * 2, "No breakpoint suspended a task. Set one in the BP tab.", kFgWarn, kBgClient);
        return;
    }
    arch::TrapFrame f{};
    if (!core::RegsRead(internal::g_state.active_bp, &f))
    {
        duetos::drivers::video::FramebufferDrawString(x, y + kRowPx * 2, "Active BP has no parked task.", kFgWarn,
                                                      kBgClient);
        return;
    }
    struct R
    {
        const char* n;
        u64 v;
    };
    const R rs[] = {{"rax", f.rax}, {"rbx", f.rbx}, {"rcx", f.rcx}, {"rdx", f.rdx}, {"rsi", f.rsi}, {"rdi", f.rdi},
                    {"rbp", f.rbp}, {"rsp", f.rsp}, {"r8 ", f.r8},  {"r9 ", f.r9},  {"r10", f.r10}, {"r11", f.r11},
                    {"r12", f.r12}, {"r13", f.r13}, {"r14", f.r14}, {"r15", f.r15}, {"rip", f.rip}, {"flg", f.rflags}};
    for (u32 i = 0; i < sizeof(rs) / sizeof(rs[0]); ++i)
    {
        const u32 col = i & 1;
        const u32 row = i / 2;
        const u32 cx = x + col * 240;
        const u32 cy = y + (row + 1) * kRowPx;
        duetos::drivers::video::FramebufferDrawString(cx, cy, rs[i].n, kFgAccent, kBgClient);
        DrawHexU64(cx + 32, cy, rs[i].v, kFgText, kBgClient);
    }
}

void RenderBreakpoints(u32 x, u32 y, u32 w, u32 h)
{
    (void)w;
    duetos::drivers::video::FramebufferDrawString(x, y, "ID   KIND   ADDRESS           HITS  STATE", kFgAccent,
                                                  kBgClient);
    debug::BpInfo infos[16];
    const u64 n = core::ListBp(infos, 16);
    const u32 max_visible = (h - kRowPx) / kRowPx;
    if (n == 0)
    {
        duetos::drivers::video::FramebufferDrawString(
            x, y + kRowPx * 2, "No breakpoints. Use 'dbg bp add ...' from the shell.", kFgText, kBgClient);
        return;
    }
    for (u32 i = 0; i < n && i < max_visible; ++i)
    {
        const u32 ry = y + (i + 1) * kRowPx;
        DrawDecU64(x, ry, infos[i].id.value, kFgText, kBgClient);
        const char* kind = "?";
        switch (infos[i].kind)
        {
        case debug::BpKind::Software:
            kind = "sw";
            break;
        case debug::BpKind::HwExecute:
            kind = "hwx";
            break;
        case debug::BpKind::HwWrite:
            kind = "hww";
            break;
        case debug::BpKind::HwReadWrite:
            kind = "hwrw";
            break;
        }
        duetos::drivers::video::FramebufferDrawString(x + 36, ry, kind, kFgText, kBgClient);
        DrawHexU64(x + 80, ry, infos[i].address, kFgText, kBgClient);
        DrawDecU64(x + 240, ry, infos[i].hit_count, kFgText, kBgClient);
        const char* state = infos[i].is_stopped ? "STOP" : "live";
        duetos::drivers::video::FramebufferDrawString(x + 304, ry, state, infos[i].is_stopped ? kFgWarn : kFgText,
                                                      kBgClient);
    }
}

void RenderWatch(u32 x, u32 y, u32 w, u32 h)
{
    (void)w;
    duetos::drivers::video::FramebufferDrawString(x, y, "NAME              VALUE", kFgAccent, kBgClient);
    const u32 max_visible = (h - kRowPx) / kRowPx;
    u32 visible = 0;
    for (u32 i = 0; i < core::kWatchMax && visible < max_visible; ++i)
    {
        const core::WatchEntry* e = core::WatchSlot(i);
        if (e == nullptr || !e->used)
            continue;
        const u32 ry = y + (visible + 1) * kRowPx;
        duetos::drivers::video::FramebufferDrawString(x, ry, e->name, kFgText, kBgClient);
        duetos::drivers::video::FramebufferDrawString(x + 144, ry, e->value, kFgAccent, kBgClient);
        ++visible;
    }
    if (visible == 0)
    {
        duetos::drivers::video::FramebufferDrawString(
            x, y + kRowPx * 2, "No watches. 'dbg watch add <pid> <addr> <type> <name>'", kFgText, kBgClient);
    }
}

void RenderScan(u32 x, u32 y, u32 w, u32 h)
{
    (void)w;
    (void)h;
    duetos::drivers::video::FramebufferDrawString(x, y, "BYTE-PATTERN SCAN", kFgAccent, kBgClient);
    duetos::drivers::video::FramebufferDrawString(
        x, y + kRowPx * 2, "Run from the kernel shell: 'dbg scan <pid> <hexbytes>'.", kFgText, kBgClient);
    duetos::drivers::video::FramebufferDrawString(
        x, y + kRowPx * 3, "Result table is rendered there; this tab is a stub for v0.", kFgText, kBgClient);
}

void RenderDisasm(u32 x, u32 y, u32 w, u32 h)
{
    (void)w;
    duetos::drivers::video::FramebufferDrawString(x, y, "DISASSEMBLY", kFgAccent, kBgClient);
    if (internal::g_state.current_pid == 0)
    {
        duetos::drivers::video::FramebufferDrawString(x, y + kRowPx * 2, "Pick a process in the Procs tab first.",
                                                      kFgWarn, kBgClient);
        return;
    }
    debug::disasm::DecodedInsn rows[32];
    const u64 n = core::DisasmRows(internal::g_state.current_pid, internal::g_state.mem_cursor_va, rows, 32);
    const u32 max_visible = (h - kRowPx) / kRowPx;
    if (n == 0)
    {
        duetos::drivers::video::FramebufferDrawString(x, y + kRowPx * 2, "<unmapped — adjust mem_cursor>", kFgWarn,
                                                      kBgClient);
        return;
    }
    for (u32 i = 0; i < n && i < max_visible; ++i)
    {
        const u32 ry = y + (i + 1) * kRowPx;
        DrawHexU64(x, ry, rows[i].addr, kFgText, kBgClient);
        duetos::drivers::video::FramebufferDrawString(x + 156, ry, rows[i].bytes_text, kFgText, kBgClient);
        duetos::drivers::video::FramebufferDrawString(x + 348, ry, rows[i].mnemonic, kFgAccent, kBgClient);
        duetos::drivers::video::FramebufferDrawString(x + 412, ry, rows[i].operands, kFgText, kBgClient);
    }
}

} // namespace

void Paint(u32 x, u32 y, u32 w, u32 h, void* cookie)
{
    (void)cookie;
    if (w < 80 || h < (kTabBarH + kStatusBarH + kRowPx * 4))
        return;
    duetos::drivers::video::FramebufferFillRect(x, y, w, h, kBgClient);
    RenderTabBar(x, y, w, internal::g_state.current_tab);

    const u32 cy = y + kTabBarH + 2;
    const u32 ch = h - kTabBarH - kStatusBarH - 4;
    switch (internal::g_state.current_tab)
    {
    case Tab::Processes:
        RenderProcesses(x + 4, cy, w - 8, ch);
        break;
    case Tab::Memory:
        RenderMemory(x + 4, cy, w - 8, ch);
        break;
    case Tab::Regs:
        RenderRegs(x + 4, cy, w - 8, ch);
        break;
    case Tab::Breakpoints:
        RenderBreakpoints(x + 4, cy, w - 8, ch);
        break;
    case Tab::Watch:
        RenderWatch(x + 4, cy, w - 8, ch);
        break;
    case Tab::Scan:
        RenderScan(x + 4, cy, w - 8, ch);
        break;
    case Tab::Disasm:
        RenderDisasm(x + 4, cy, w - 8, ch);
        break;
    default:
        break;
    }

    RenderStatusBar(x, y + h - kStatusBarH, w);
}

} // namespace duetos::apps::dbg::render
