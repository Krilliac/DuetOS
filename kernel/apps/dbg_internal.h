#pragma once

#include "apps/dbg.h"
#include "debug/breakpoints.h"
#include "drivers/video/widget.h"
#include "util/types.h"

/*
 * DuetOS — debugger app private state, shared between
 * `dbg.cpp` (lifecycle + event handling) and
 * `dbg_render.cpp` (paint code only). Not exported beyond this
 * pair — anything else should go through the public surface in
 * `dbg.h`.
 */

namespace duetos::apps::dbg::internal
{

struct DbgState
{
    duetos::drivers::video::WindowHandle window;
    Tab current_tab;
    u64 current_pid;
    u64 mem_cursor_va;
    debug::BreakpointId active_bp;
    u32 mem_scroll_rows;
    u32 proc_scroll_rows;
    u32 disasm_scroll_rows;
    bool inited;
};

extern DbgState g_state;

} // namespace duetos::apps::dbg::internal

namespace duetos::apps::dbg::render
{

/// WindowSetContentDraw callback. The compositor calls this with
/// the client-area rect on every recompose; it dispatches into
/// the per-tab paint functions based on `g_state.current_tab`.
void Paint(u32 x, u32 y, u32 w, u32 h, void* cookie);

} // namespace duetos::apps::dbg::render
