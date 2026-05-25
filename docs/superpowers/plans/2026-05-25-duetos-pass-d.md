# DuetOS Pass D Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land a template-based widget component library (`kernel/drivers/video/app_widgets/`) and migrate all 33 DuetOS apps to consume it, so every visible app surface shares the same typography (ChromeText roles) + spacing (Measure-driven) + selective tactility (atlas-shadow on buttons + panels).

**Architecture:** CRTP base `Widget<Self>` provides static polymorphism without virtual dispatch / RTTI. Concrete widgets (`AppPanel`, `AppLabel`, `AppButton`, `AppListRow`, `AppInput`, `AppDivider`, `AppToolbar`, `AppScrollbar`) are plain structs that own their state. Apps compose typed widget collections via `WidgetGroup<Ws...>` (a `std::tuple` wrapper). Events fold back-to-front through the tuple; first widget that returns `Consumed` wins. No heap, no virtual dispatch, no dynamic add/remove — widget set per app is compile-time-known.

**Tech Stack:** C++23 (kernel, no exceptions, no RTTI), CMake 3.25+, ctest for hosted unit tests, kernel self-tests via `KBP_PROBE_V` + `arch::SerialWrite` sentinels, QEMU + `tools/qemu/run.sh` for boot smoke, `tools/test/boot-log-analyze.sh` for sentinel grep, QMP `tools/test/qmp-screendump.sh` for visual verification.

**Spec:** `docs/superpowers/specs/2026-05-25-duetos-pass-d-design.md` (read first).

**Branch:** `claude/pass-d-app-widgets` (already created from main with spec committed at `f89e3dcd`).

---

## File Structure

### Created (`kernel/drivers/video/app_widgets/`)
- `widget.h` — `template<typename Self> struct Widget`, `Rect`, `Event`, `EventKind`, `EventResult`, `WidgetState`, `WidgetStateFlags`
- `widget_group.h` — `template<typename... Ws> struct WidgetGroup`, `MakeWidgetGroup(...)`
- `app_panel.h` / `app_panel.cpp` — `struct AppPanel : Widget<AppPanel>`
- `app_label.h` / `app_label.cpp` — `struct AppLabel : Widget<AppLabel>`
- `app_button.h` / `app_button.cpp` — `struct AppButton : Widget<AppButton>`
- `app_list_row.h` / `app_list_row.cpp` — `struct AppListRow : Widget<AppListRow>`
- `app_input.h` / `app_input.cpp` — `struct AppInput : Widget<AppInput>`
- `app_divider.h` / `app_divider.cpp` — `struct AppDivider : Widget<AppDivider>`
- `app_toolbar.h` / `app_toolbar.cpp` — `struct AppToolbar : Widget<AppToolbar>`
- `app_scrollbar.h` / `app_scrollbar.cpp` — `struct AppScrollbar : Widget<AppScrollbar>`
- `self_test.h` / `self_test.cpp` — `AppWidgetsSelfTest()` + `AppWidgetsSelfTestPassed()`
- `tools/test/pass-d-soak.sh` — 60s sustained-load rig
- `wiki/subsystems/AppWidgets.md` — library reference page

### Modified
- `kernel/core/boot_bringup.cpp` — wire `AppWidgetsSelfTest()` into umbrella + emit `[pass-d-selftest] PASS`
- `tools/test/boot-log-analyze.sh` — new Pass D umbrella section
- `tools/test/tactility-screenshot-matrix.sh` — new `--apps` surface mode
- `wiki/subsystems/Compositor.md` — Pass D section
- `wiki/reference/Roadmap.md` — Pass D residuals graduated + new residual list
- 28 of 33 files under `kernel/apps/*.cpp` — migrate paint + click code to widget composition (carve-outs: terminal/hexview content grids, gfxdemo, dbg overlays — chrome only or skipped entirely)

### Hosted tests (`tests/host/`)
- `test_app_widgets_paint.cpp` — each widget's `PaintSelf` primitive sequence
- `test_app_widgets_events.cpp` — hit-test + state transitions + callback firing
- `test_widget_group.cpp` — fold order + first-consumed-wins
- `test_app_widgets_bounds.cpp` — `Rect::Contains` + clipping arithmetic
- `tests/host/CMakeLists.txt` — register the four new tests

---

## Phase 0 — Library foundation

### Task 1: Widget base header + types

**Files:**
- Create: `kernel/drivers/video/app_widgets/widget.h`

- [ ] **Step 1: Write the header**

```cpp
#pragma once

#include "util/types.h"

/*
 * DuetOS app widget base. CRTP template provides static polymorphism
 * without virtual dispatch or RTTI. Concrete widgets derive from
 * Widget<Self> and override the *Self variants of Paint / OnEvent.
 *
 * Storage model: value semantics, no heap, no dynamic add/remove.
 * Each app's WidgetGroup is a constinit static instance with
 * compile-time-known widget composition.
 *
 * See docs/superpowers/specs/2026-05-25-duetos-pass-d-design.md.
 */

namespace duetos::drivers::video::app_widgets
{

struct Rect
{
    u32 x = 0;
    u32 y = 0;
    u32 w = 0;
    u32 h = 0;

    constexpr bool Contains(u32 px, u32 py) const
    {
        return px >= x && py >= y && px < x + w && py < y + h;
    }
};

enum class EventKind : u8
{
    MouseDown = 0,
    MouseUp = 1,
    MouseMove = 2,
    KeyDown = 3,
    KeyUp = 4,
    FocusIn = 5,
    FocusOut = 6,
};

struct Event
{
    EventKind kind = EventKind::MouseMove;
    u32 x = 0;        // for mouse events
    u32 y = 0;
    u32 keycode = 0;  // for key events
    u32 mods = 0;
};

enum class EventResult : u8
{
    NotInterested = 0,
    Consumed = 1,
};

enum class WidgetStateFlags : u8
{
    None = 0,
    Hover = 1U << 0,
    Pressed = 1U << 1,
    Focused = 1U << 2,
    Disabled = 1U << 3,
};

constexpr WidgetStateFlags operator|(WidgetStateFlags a, WidgetStateFlags b)
{
    return static_cast<WidgetStateFlags>(static_cast<u8>(a) | static_cast<u8>(b));
}

constexpr WidgetStateFlags operator&(WidgetStateFlags a, WidgetStateFlags b)
{
    return static_cast<WidgetStateFlags>(static_cast<u8>(a) & static_cast<u8>(b));
}

constexpr bool HasFlag(WidgetStateFlags flags, WidgetStateFlags test)
{
    return (static_cast<u8>(flags) & static_cast<u8>(test)) != 0;
}

struct WidgetState
{
    WidgetStateFlags flags = WidgetStateFlags::None;
};

// Forward: every widget needs Compose to paint into. The compositor
// owns BeginCompose/EndCompose; widgets paint primitives during that
// window. We pass it by reference so widgets don't have to look it
// up themselves.
struct Compose;

/// CRTP base — derived widgets override the *Self variants below.
/// Default implementations no-op so simple widgets only override what
/// they need.
template <typename Self>
struct Widget
{
    Rect bounds{};
    WidgetState state{};

    constexpr void Paint(Compose& c) const
    {
        static_cast<const Self*>(this)->PaintSelf(c);
    }

    constexpr EventResult OnEvent(const Event& e)
    {
        return static_cast<Self*>(this)->OnEventSelf(e);
    }

    constexpr void PaintSelf(Compose&) const { /* derived overrides */ }
    constexpr EventResult OnEventSelf(const Event&) { return EventResult::NotInterested; }
};

} // namespace duetos::drivers::video::app_widgets
```

- [ ] **Step 2: Build (header-only)**

Run: `wsl.exe -d Ubuntu-24.04 bash -lc 'cd /root/source/DuetOS && git fetch winsrc && git reset --hard winsrc/claude/pass-d-app-widgets && cmake --build build/x86_64-debug --parallel $(nproc) 2>&1 | tail -3'`
Expected: clean (kernel binary unchanged — no callers yet).

- [ ] **Step 3: Commit**

```bash
git add kernel/drivers/video/app_widgets/widget.h
git commit -m "video/app_widgets: CRTP base + Rect/Event/State types (Pass D)"
```

### Task 2: WidgetGroup template

**Files:**
- Create: `kernel/drivers/video/app_widgets/widget_group.h`

- [ ] **Step 1: Write the header**

```cpp
#pragma once

#include "drivers/video/app_widgets/widget.h"
#include <tuple>
#include <utility>

namespace duetos::drivers::video::app_widgets
{

/// Compile-time-known widget collection. Apps construct a
/// WidgetGroup<W1, W2, ...> with their widget set; PaintAll folds
/// Paint over each in declaration order (back-to-front), and
/// DispatchEvent folds OnEvent in reverse (front-to-back) with
/// first-Consumed-wins.
///
/// Storage is std::tuple — no heap, no virtual dispatch. Widgets
/// are value-type members; mutating their public state mutates the
/// tuple's storage in place.
template <typename... Ws>
struct WidgetGroup
{
    std::tuple<Ws...> widgets;

    constexpr explicit WidgetGroup(Ws... ws) : widgets(std::move(ws)...) {}

    constexpr void PaintAll(Compose& c) const
    {
        PaintAllImpl(c, std::index_sequence_for<Ws...>{});
    }

    constexpr EventResult DispatchEvent(const Event& e)
    {
        return DispatchEventImpl(e, std::index_sequence_for<Ws...>{});
    }

private:
    template <std::size_t... Is>
    constexpr void PaintAllImpl(Compose& c, std::index_sequence<Is...>) const
    {
        // Back-to-front == declaration order. Fold expression: paint each in order.
        (std::get<Is>(widgets).Paint(c), ...);
    }

    template <std::size_t... Is>
    constexpr EventResult DispatchEventImpl(const Event& e, std::index_sequence<Is...>)
    {
        // Front-to-back == reverse declaration order. First widget
        // that returns Consumed stops the fold (short-circuit OR).
        EventResult result = EventResult::NotInterested;
        // Iterate in reverse via fold over reversed indices.
        (void)((TryDispatchOne<sizeof...(Ws) - 1 - Is>(e, result) || ...));
        return result;
    }

    template <std::size_t I>
    constexpr bool TryDispatchOne(const Event& e, EventResult& result)
    {
        const EventResult r = std::get<I>(widgets).OnEvent(e);
        if (r == EventResult::Consumed)
        {
            result = EventResult::Consumed;
            return true; // short-circuit the fold
        }
        return false;
    }
};

/// Deduction helper so callers can write `MakeWidgetGroup(w1, w2, ...)`
/// without spelling the template parameters.
template <typename... Ws>
constexpr auto MakeWidgetGroup(Ws... ws)
{
    return WidgetGroup<Ws...>(std::move(ws)...);
}

} // namespace duetos::drivers::video::app_widgets
```

- [ ] **Step 2: Build + commit**

```bash
wsl.exe -d Ubuntu-24.04 bash -lc 'cd /root/source/DuetOS && git fetch winsrc && git reset --hard winsrc/claude/pass-d-app-widgets && cmake --build build/x86_64-debug --parallel $(nproc) 2>&1 | tail -3'
git add kernel/drivers/video/app_widgets/widget_group.h
git commit -m "video/app_widgets: WidgetGroup<Ws...> + MakeWidgetGroup (Pass D)"
```

### Task 3: AppPanel + AppLabel + AppDivider (simplest 3 widgets)

**Files:**
- Create: `kernel/drivers/video/app_widgets/app_panel.h`
- Create: `kernel/drivers/video/app_widgets/app_panel.cpp`
- Create: `kernel/drivers/video/app_widgets/app_label.h`
- Create: `kernel/drivers/video/app_widgets/app_label.cpp`
- Create: `kernel/drivers/video/app_widgets/app_divider.h`
- Create: `kernel/drivers/video/app_widgets/app_divider.cpp`

- [ ] **Step 1: AppPanel** — header (declarations only):

```cpp
#pragma once
#include "drivers/video/app_widgets/widget.h"

namespace duetos::drivers::video::app_widgets
{

/// Theme-coloured panel with optional shadow under tactility-on themes.
/// No events; paint-only.
struct AppPanel : Widget<AppPanel>
{
    u32 bg_rgb = 0;          // 0 = use ThemeCurrent().panel_bg
    u32 border_rgb = 0;      // 0 = use ThemeCurrent().panel_border
    u8 shadow_radius = 12U;  // 0 disables shadow even on tactility-on themes

    void PaintSelf(Compose& c) const;
};

} // namespace duetos::drivers::video::app_widgets
```

Implementation in `app_panel.cpp`:

```cpp
#include "drivers/video/app_widgets/app_panel.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/shadow.h"
#include "drivers/video/theme.h"

namespace duetos::drivers::video::app_widgets
{

void AppPanel::PaintSelf(Compose& /*c*/) const
{
    if (bounds.w == 0 || bounds.h == 0) return;
    const auto& theme = ThemeCurrent();
    const u32 bg = (bg_rgb == 0) ? theme.role_client[0] : bg_rgb;
    const u32 border = (border_rgb == 0) ? theme.window_border : border_rgb;
    if (ThemeTactilityEffective() && shadow_radius > 0)
    {
        const u8 opacity = ThemeIntensityEffective(theme.shadow_intensity_active);
        if (opacity > 0)
        {
            RenderSoftShadow(static_cast<i32>(bounds.x), static_cast<i32>(bounds.y),
                             bounds.w, bounds.h, shadow_radius, opacity, 0x00000000U);
        }
    }
    FramebufferFillRect(bounds.x, bounds.y, bounds.w, bounds.h, bg);
    FramebufferDrawRect(bounds.x, bounds.y, bounds.w, bounds.h, border, 1);
}

} // namespace duetos::drivers::video::app_widgets
```

- [ ] **Step 2: AppLabel** — header:

```cpp
#pragma once
#include "drivers/video/app_widgets/widget.h"
#include "drivers/video/chrome_text.h"

namespace duetos::drivers::video::app_widgets
{

/// Static text. Role + weight configurable. Centered within bounds
/// by default; align_left for left-anchored layout.
struct AppLabel : Widget<AppLabel>
{
    const char* text = "";
    ChromeTextRole role = ChromeTextRole::Body;
    ChromeTextWeight weight = ChromeTextWeight::Regular;
    u32 fg_rgb = 0xFFFFFFU;
    u32 bg_rgb = 0;            // 0 = transparent (skip the bg fill on bitmap path)
    bool align_left = false;

    void PaintSelf(Compose& c) const;
};

} // namespace duetos::drivers::video::app_widgets
```

Implementation in `app_label.cpp`:

```cpp
#include "drivers/video/app_widgets/app_label.h"

namespace duetos::drivers::video::app_widgets
{

void AppLabel::PaintSelf(Compose& /*c*/) const
{
    if (text == nullptr || text[0] == '\0') return;
    const u32 w = ChromeTextMeasure(role, text);
    const u32 h = ChromeTextRoleHeight(role);
    const u32 tx = align_left ? bounds.x : bounds.x + (bounds.w > w ? (bounds.w - w) / 2 : 0);
    const u32 ty = bounds.y + (bounds.h > h ? (bounds.h - h) / 2 : 0);
    ChromeTextDraw(role, tx, ty, text, fg_rgb, bg_rgb, weight);
}

} // namespace duetos::drivers::video::app_widgets
```

- [ ] **Step 3: AppDivider** — header:

```cpp
#pragma once
#include "drivers/video/app_widgets/widget.h"

namespace duetos::drivers::video::app_widgets
{

/// 1-px line. Orientation inferred from bounds (w > h = horizontal,
/// else vertical). Uses ThemeCurrent().window_border by default.
struct AppDivider : Widget<AppDivider>
{
    u32 rgb = 0; // 0 = use theme border

    void PaintSelf(Compose& c) const;
};

} // namespace duetos::drivers::video::app_widgets
```

Implementation in `app_divider.cpp`:

```cpp
#include "drivers/video/app_widgets/app_divider.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/theme.h"

namespace duetos::drivers::video::app_widgets
{

void AppDivider::PaintSelf(Compose& /*c*/) const
{
    if (bounds.w == 0 || bounds.h == 0) return;
    const u32 colour = (rgb == 0) ? ThemeCurrent().window_border : rgb;
    FramebufferFillRect(bounds.x, bounds.y, bounds.w, bounds.h, colour);
}

} // namespace duetos::drivers::video::app_widgets
```

- [ ] **Step 4: Build + commit**

```bash
wsl.exe -d Ubuntu-24.04 bash -lc 'cd /root/source/DuetOS && git fetch winsrc && git reset --hard winsrc/claude/pass-d-app-widgets && cmake --build build/x86_64-debug --parallel $(nproc) 2>&1 | tail -3'
git add kernel/drivers/video/app_widgets/app_panel.{h,cpp} kernel/drivers/video/app_widgets/app_label.{h,cpp} kernel/drivers/video/app_widgets/app_divider.{h,cpp}
git commit -m "video/app_widgets: AppPanel + AppLabel + AppDivider (Pass D)"
```

### Task 4: AppButton + AppListRow + AppToolbar

**Files:**
- Create: `kernel/drivers/video/app_widgets/app_button.{h,cpp}`
- Create: `kernel/drivers/video/app_widgets/app_list_row.{h,cpp}`
- Create: `kernel/drivers/video/app_widgets/app_toolbar.{h,cpp}`

- [ ] **Step 1: AppButton**

```cpp
// app_button.h
#pragma once
#include "drivers/video/app_widgets/widget.h"
#include "drivers/video/chrome_text.h"

namespace duetos::drivers::video::app_widgets
{

struct AppButton : Widget<AppButton>
{
    const char* label = "";
    void (*on_click)() = nullptr;
    ChromeTextWeight weight = ChromeTextWeight::Regular;
    u32 bg_rgb = 0;    // 0 = theme accent
    u32 fg_rgb = 0xFFFFFFU;

    void PaintSelf(Compose& c) const;
    EventResult OnEventSelf(const Event& e);
};

} // namespace duetos::drivers::video::app_widgets
```

```cpp
// app_button.cpp
#include "drivers/video/app_widgets/app_button.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/shadow.h"
#include "drivers/video/theme.h"

namespace duetos::drivers::video::app_widgets
{

void AppButton::PaintSelf(Compose& /*c*/) const
{
    if (bounds.w == 0 || bounds.h == 0) return;
    const auto& theme = ThemeCurrent();
    const u32 base_bg = (bg_rgb == 0) ? theme.role_title[0] : bg_rgb;
    u32 bg = base_bg;
    if (HasFlag(state.flags, WidgetStateFlags::Pressed))
        bg = base_bg & 0x00C0C0C0U; // dim ~25%
    else if (HasFlag(state.flags, WidgetStateFlags::Hover))
        bg = base_bg | 0x00202020U; // lift slightly
    if (ThemeTactilityEffective() && !HasFlag(state.flags, WidgetStateFlags::Pressed))
    {
        const u8 opacity = ThemeIntensityEffective(theme.shadow_intensity_active);
        if (opacity > 0)
            RenderSoftShadow(static_cast<i32>(bounds.x), static_cast<i32>(bounds.y),
                             bounds.w, bounds.h, 6U, opacity, 0x00000000U);
    }
    FramebufferFillRect(bounds.x, bounds.y, bounds.w, bounds.h, bg);
    FramebufferDrawRect(bounds.x, bounds.y, bounds.w, bounds.h, theme.window_border, 1);
    if (label != nullptr && label[0] != '\0')
    {
        const u32 lw = ChromeTextMeasure(ChromeTextRole::Body, label);
        const u32 lh = ChromeTextRoleHeight(ChromeTextRole::Body);
        const u32 tx = bounds.x + (bounds.w > lw ? (bounds.w - lw) / 2 : 0);
        const u32 ty = bounds.y + (bounds.h > lh ? (bounds.h - lh) / 2 : 0);
        ChromeTextDraw(ChromeTextRole::Body, tx, ty, label, fg_rgb, bg, weight);
    }
}

EventResult AppButton::OnEventSelf(const Event& e)
{
    if (HasFlag(state.flags, WidgetStateFlags::Disabled)) return EventResult::NotInterested;
    if (e.kind == EventKind::MouseMove)
    {
        const bool inside = bounds.Contains(e.x, e.y);
        const bool was_hover = HasFlag(state.flags, WidgetStateFlags::Hover);
        if (inside && !was_hover)
            state.flags = state.flags | WidgetStateFlags::Hover;
        else if (!inside && was_hover)
            state.flags = static_cast<WidgetStateFlags>(static_cast<u8>(state.flags) & ~static_cast<u8>(WidgetStateFlags::Hover));
        return inside ? EventResult::Consumed : EventResult::NotInterested;
    }
    if (e.kind == EventKind::MouseDown && bounds.Contains(e.x, e.y))
    {
        state.flags = state.flags | WidgetStateFlags::Pressed;
        return EventResult::Consumed;
    }
    if (e.kind == EventKind::MouseUp && HasFlag(state.flags, WidgetStateFlags::Pressed))
    {
        state.flags = static_cast<WidgetStateFlags>(static_cast<u8>(state.flags) & ~static_cast<u8>(WidgetStateFlags::Pressed));
        if (bounds.Contains(e.x, e.y) && on_click != nullptr)
            on_click();
        return EventResult::Consumed;
    }
    return EventResult::NotInterested;
}

} // namespace duetos::drivers::video::app_widgets
```

- [ ] **Step 2: AppListRow** — simpler, similar shape:

```cpp
// app_list_row.h
#pragma once
#include "drivers/video/app_widgets/widget.h"

namespace duetos::drivers::video::app_widgets
{

struct AppListRow : Widget<AppListRow>
{
    const char* label = "";
    void (*on_click)() = nullptr;
    bool selected = false;
    u32 accent_rgb = 0; // 0 = theme accent stripe colour

    void PaintSelf(Compose& c) const;
    EventResult OnEventSelf(const Event& e);
};

} // namespace duetos::drivers::video::app_widgets
```

```cpp
// app_list_row.cpp
#include "drivers/video/app_widgets/app_list_row.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/chrome_text.h"
#include "drivers/video/theme.h"

namespace duetos::drivers::video::app_widgets
{

void AppListRow::PaintSelf(Compose& /*c*/) const
{
    if (bounds.w == 0 || bounds.h == 0) return;
    const auto& theme = ThemeCurrent();
    const u32 hover_bg = theme.role_title[0] & 0x00808080U;
    const u32 sel_bg = theme.role_title[0];
    u32 bg = theme.role_client[0];
    if (selected) bg = sel_bg;
    else if (HasFlag(state.flags, WidgetStateFlags::Hover)) bg = hover_bg;
    FramebufferFillRect(bounds.x, bounds.y, bounds.w, bounds.h, bg);
    const u32 accent = (accent_rgb == 0) ? theme.role_title[0] : accent_rgb;
    if (selected) FramebufferFillRect(bounds.x, bounds.y, 3, bounds.h, accent);
    if (label != nullptr && label[0] != '\0')
    {
        const u32 lh = ChromeTextRoleHeight(ChromeTextRole::Body);
        const u32 ty = bounds.y + (bounds.h > lh ? (bounds.h - lh) / 2 : 0);
        ChromeTextDraw(ChromeTextRole::Body, bounds.x + 8, ty, label, 0xFFFFFFU, bg);
    }
}

EventResult AppListRow::OnEventSelf(const Event& e)
{
    if (e.kind == EventKind::MouseMove)
    {
        const bool inside = bounds.Contains(e.x, e.y);
        if (inside) state.flags = state.flags | WidgetStateFlags::Hover;
        else state.flags = static_cast<WidgetStateFlags>(static_cast<u8>(state.flags) & ~static_cast<u8>(WidgetStateFlags::Hover));
        return inside ? EventResult::Consumed : EventResult::NotInterested;
    }
    if (e.kind == EventKind::MouseDown && bounds.Contains(e.x, e.y))
    {
        if (on_click != nullptr) on_click();
        return EventResult::Consumed;
    }
    return EventResult::NotInterested;
}

} // namespace duetos::drivers::video::app_widgets
```

- [ ] **Step 3: AppToolbar** — horizontal strip, no state of its own (children handle events):

```cpp
// app_toolbar.h
#pragma once
#include "drivers/video/app_widgets/widget.h"

namespace duetos::drivers::video::app_widgets
{

struct AppToolbar : Widget<AppToolbar>
{
    u32 bg_rgb = 0;
    void PaintSelf(Compose& c) const;
};

} // namespace duetos::drivers::video::app_widgets
```

```cpp
// app_toolbar.cpp
#include "drivers/video/app_widgets/app_toolbar.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/shadow.h"
#include "drivers/video/theme.h"

namespace duetos::drivers::video::app_widgets
{

void AppToolbar::PaintSelf(Compose& /*c*/) const
{
    if (bounds.w == 0 || bounds.h == 0) return;
    const auto& theme = ThemeCurrent();
    const u32 bg = (bg_rgb == 0) ? theme.taskbar_bg : bg_rgb;
    if (ThemeTactilityEffective())
    {
        const u8 opacity = ThemeIntensityEffective(theme.shadow_intensity_active);
        if (opacity > 0)
            RenderSoftShadow(static_cast<i32>(bounds.x), static_cast<i32>(bounds.y),
                             bounds.w, bounds.h, 8U, opacity, 0x00000000U);
    }
    FramebufferFillRect(bounds.x, bounds.y, bounds.w, bounds.h, bg);
    FramebufferFillRect(bounds.x, bounds.y + bounds.h - 1, bounds.w, 1, theme.window_border);
}

} // namespace duetos::drivers::video::app_widgets
```

- [ ] **Step 4: Build + commit**

```bash
wsl.exe -d Ubuntu-24.04 bash -lc 'cd /root/source/DuetOS && git fetch winsrc && git reset --hard winsrc/claude/pass-d-app-widgets && cmake --build build/x86_64-debug --parallel $(nproc) 2>&1 | tail -3'
git add kernel/drivers/video/app_widgets/app_button.{h,cpp} kernel/drivers/video/app_widgets/app_list_row.{h,cpp} kernel/drivers/video/app_widgets/app_toolbar.{h,cpp}
git commit -m "video/app_widgets: AppButton + AppListRow + AppToolbar (Pass D)"
```

### Task 5: AppInput + AppScrollbar

**Files:**
- Create: `kernel/drivers/video/app_widgets/app_input.{h,cpp}`
- Create: `kernel/drivers/video/app_widgets/app_scrollbar.{h,cpp}`

- [ ] **Step 1: AppInput** — text input box with cursor + simple key handling

```cpp
// app_input.h
#pragma once
#include "drivers/video/app_widgets/widget.h"

namespace duetos::drivers::video::app_widgets
{

struct AppInput : Widget<AppInput>
{
    char* buf = nullptr;       // caller-owned buffer
    u32 buf_cap = 0;
    u32 buf_len = 0;
    u32 caret = 0;
    void (*on_change)() = nullptr;

    void PaintSelf(Compose& c) const;
    EventResult OnEventSelf(const Event& e);
};

} // namespace duetos::drivers::video::app_widgets
```

```cpp
// app_input.cpp
#include "drivers/video/app_widgets/app_input.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/chrome_text.h"
#include "drivers/video/theme.h"

namespace duetos::drivers::video::app_widgets
{

void AppInput::PaintSelf(Compose& /*c*/) const
{
    if (bounds.w == 0 || bounds.h == 0) return;
    const auto& theme = ThemeCurrent();
    FramebufferFillRect(bounds.x, bounds.y, bounds.w, bounds.h, theme.role_client[0]);
    const u32 border = HasFlag(state.flags, WidgetStateFlags::Focused) ? theme.role_title[0] : theme.window_border;
    FramebufferDrawRect(bounds.x, bounds.y, bounds.w, bounds.h, border, HasFlag(state.flags, WidgetStateFlags::Focused) ? 2 : 1);
    if (buf != nullptr && buf_len > 0)
    {
        const u32 lh = ChromeTextRoleHeight(ChromeTextRole::Body);
        const u32 ty = bounds.y + (bounds.h > lh ? (bounds.h - lh) / 2 : 0);
        // Null-terminate just-in-case before drawing
        if (buf_len < buf_cap) buf[buf_len] = '\0';
        ChromeTextDraw(ChromeTextRole::Body, bounds.x + 6, ty, buf, 0xFFFFFFU, theme.role_client[0]);
        if (HasFlag(state.flags, WidgetStateFlags::Focused))
        {
            // Caret bar after the text
            const u32 cw = ChromeTextMeasure(ChromeTextRole::Body, buf);
            FramebufferFillRect(bounds.x + 6 + cw + 1, ty, 1, lh, 0xFFFFFFU);
        }
    }
}

EventResult AppInput::OnEventSelf(const Event& e)
{
    if (e.kind == EventKind::MouseDown)
    {
        const bool inside = bounds.Contains(e.x, e.y);
        if (inside) state.flags = state.flags | WidgetStateFlags::Focused;
        else state.flags = static_cast<WidgetStateFlags>(static_cast<u8>(state.flags) & ~static_cast<u8>(WidgetStateFlags::Focused));
        return inside ? EventResult::Consumed : EventResult::NotInterested;
    }
    if (e.kind == EventKind::KeyDown && HasFlag(state.flags, WidgetStateFlags::Focused))
    {
        if (e.keycode == 0x08 /* backspace */ && buf_len > 0)
        {
            buf_len--;
            caret = buf_len;
            if (on_change) on_change();
            return EventResult::Consumed;
        }
        if (e.keycode >= 0x20 && e.keycode < 0x7F && buf != nullptr && buf_len + 1 < buf_cap)
        {
            buf[buf_len++] = static_cast<char>(e.keycode);
            caret = buf_len;
            if (on_change) on_change();
            return EventResult::Consumed;
        }
    }
    return EventResult::NotInterested;
}

} // namespace duetos::drivers::video::app_widgets
```

- [ ] **Step 2: AppScrollbar** — vertical or horizontal indicator + thumb

```cpp
// app_scrollbar.h
#pragma once
#include "drivers/video/app_widgets/widget.h"

namespace duetos::drivers::video::app_widgets
{

struct AppScrollbar : Widget<AppScrollbar>
{
    u32 content_size = 0;   // total content extent in scroll direction
    u32 viewport_size = 0;  // visible extent
    u32 scroll_offset = 0;  // current top/left
    bool horizontal = false;
    void (*on_scroll)(u32 new_offset) = nullptr;

    void PaintSelf(Compose& c) const;
    EventResult OnEventSelf(const Event& e);
};

} // namespace duetos::drivers::video::app_widgets
```

```cpp
// app_scrollbar.cpp
#include "drivers/video/app_widgets/app_scrollbar.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/theme.h"

namespace duetos::drivers::video::app_widgets
{

void AppScrollbar::PaintSelf(Compose& /*c*/) const
{
    if (bounds.w == 0 || bounds.h == 0 || content_size == 0) return;
    const auto& theme = ThemeCurrent();
    FramebufferFillRect(bounds.x, bounds.y, bounds.w, bounds.h, theme.taskbar_bg);
    const u32 track_extent = horizontal ? bounds.w : bounds.h;
    if (content_size <= viewport_size) return; // nothing to scroll
    const u32 thumb_extent = (viewport_size * track_extent) / content_size;
    const u32 thumb_offset = (scroll_offset * track_extent) / content_size;
    if (horizontal)
        FramebufferFillRect(bounds.x + thumb_offset, bounds.y, thumb_extent, bounds.h, theme.role_title[0]);
    else
        FramebufferFillRect(bounds.x, bounds.y + thumb_offset, bounds.w, thumb_extent, theme.role_title[0]);
}

EventResult AppScrollbar::OnEventSelf(const Event& e)
{
    if (e.kind == EventKind::MouseDown && bounds.Contains(e.x, e.y))
    {
        // Jump-to-click: clicking on the track scrolls there
        const u32 click_pos = horizontal ? (e.x - bounds.x) : (e.y - bounds.y);
        const u32 track_extent = horizontal ? bounds.w : bounds.h;
        if (track_extent == 0) return EventResult::Consumed;
        const u32 new_offset = (click_pos * content_size) / track_extent;
        scroll_offset = new_offset;
        if (on_scroll) on_scroll(new_offset);
        return EventResult::Consumed;
    }
    return EventResult::NotInterested;
}

} // namespace duetos::drivers::video::app_widgets
```

- [ ] **Step 3: Build + commit**

```bash
wsl.exe -d Ubuntu-24.04 bash -lc 'cd /root/source/DuetOS && git fetch winsrc && git reset --hard winsrc/claude/pass-d-app-widgets && cmake --build build/x86_64-debug --parallel $(nproc) 2>&1 | tail -3'
git add kernel/drivers/video/app_widgets/app_input.{h,cpp} kernel/drivers/video/app_widgets/app_scrollbar.{h,cpp}
git commit -m "video/app_widgets: AppInput + AppScrollbar (Pass D)"
```

### Task 6: Hosted unit tests for the library

**Files:**
- Create: `tests/host/test_app_widgets_paint.cpp`
- Create: `tests/host/test_app_widgets_events.cpp`
- Create: `tests/host/test_widget_group.cpp`
- Create: `tests/host/test_app_widgets_bounds.cpp`
- Modify: `tests/host/CMakeLists.txt`

The hosted tests don't link the kernel TU; they re-derive behavior via inline mock. Pattern (per-test):

```cpp
#include "host_test_helper.h"
#include <cstdint>
// Mirror enums + Rect inline.
struct Rect { uint32_t x, y, w, h; bool Contains(uint32_t px, uint32_t py) const {
    return px >= x && py >= y && px < x + w && py < y + h; } };
int main()
{
    Rect r{10, 20, 100, 50};
    EXPECT_TRUE(r.Contains(50, 40));
    EXPECT_TRUE(!r.Contains(5, 40));
    EXPECT_TRUE(!r.Contains(50, 80));
    EXPECT_TRUE(!r.Contains(110, 40));   // x boundary exclusive
    EXPECT_TRUE(!r.Contains(50, 70));    // y boundary exclusive
    return ::duetos_host_test::finish_main("tests/host/test_app_widgets_bounds.cpp");
}
```

Write the 4 test files per the pattern. Each one tests its concern (paint primitive sequence, event state transitions, group fold order, Rect arithmetic). Register all 4 in `tests/host/CMakeLists.txt` via `add_host_test(...)`.

- [ ] **Run + commit**

```bash
wsl.exe -d Ubuntu-24.04 bash -lc 'cd /root/source/DuetOS && cmake --build build/host-tests --parallel $(nproc) 2>&1 | tail -3 && cd build/host-tests && ctest -R app_widgets --output-on-failure'
git add tests/host/test_app_widgets_*.cpp tests/host/test_widget_group.cpp tests/host/CMakeLists.txt
git commit -m "tests/host: app_widgets unit tests (Pass D)"
```

### Task 7: Self-test + boot umbrella wiring

**Files:**
- Create: `kernel/drivers/video/app_widgets/self_test.{h,cpp}`
- Modify: `kernel/core/boot_bringup.cpp`

```cpp
// self_test.h
#pragma once
namespace duetos::drivers::video::app_widgets
{
void AppWidgetsSelfTest();
bool AppWidgetsSelfTestPassed();
}
```

Implementation: construct one of each widget, drive synthetic Events (MouseMove inside/outside, MouseDown/Up, KeyDown), assert state transitions + callback firing. Emit `[app-widgets-selftest] PASS` on success or `FAIL <reason>` + `KBP_PROBE_V(ProbeId::kBootSelftestFail, 0xD0..0xD3)` on failure.

In `boot_bringup.cpp`, add a Pass D umbrella block after the Pass C umbrella (mirror that pattern):

```cpp
duetos::drivers::video::app_widgets::AppWidgetsSelfTest();
if constexpr (::duetos::core::kBootSelfTests)
{
    if (duetos::drivers::video::app_widgets::AppWidgetsSelfTestPassed())
    {
        duetos::arch::SerialWrite("[pass-d-selftest] PASS (widgets=ok, apps=0/0)\n");
    }
}
```

The `apps=0/0` part will be updated as each app migration adds its own self-test (Task 9 onward). For now, with no apps migrated, 0/0 is correct.

- [ ] **Build + boot smoke + commit**

```bash
wsl.exe -d Ubuntu-24.04 bash -lc 'cd /root/source/DuetOS && git fetch winsrc && git reset --hard winsrc/claude/pass-d-app-widgets && cmake --build build/x86_64-debug --parallel $(nproc) 2>&1 | tail -3 && DUETOS_TIMEOUT=25 tools/qemu/run.sh 2>&1 | grep -E "app-widgets-selftest|pass-d-selftest|pass-c-selftest|PANIC|TRIPLE"'
git add kernel/drivers/video/app_widgets/self_test.{h,cpp} kernel/core/boot_bringup.cpp
git commit -m "boot: wire AppWidgetsSelfTest into Pass D umbrella sentinel"
```

Expected boot-log:
```
[app-widgets-selftest] PASS
[pass-c-selftest] PASS (chrome-text=ok)
[pass-d-selftest] PASS (widgets=ok, apps=0/0)
```

**Phase 0 complete.** Library exists, tested, self-test green at boot. Apps unchanged. Phase 1 begins per-app migrations.

---

## App migration pattern (every Phase 1-3 task follows this)

Each app migration is a SINGLE commit per app. The pattern:

1. **Read the current app TU end-to-end.** Identify:
   - Where Paint is invoked from (usually `<App>Paint(Compose& c)` or similar)
   - Where Click is invoked from (usually `<App>Click(u32 x, u32 y)`)
   - Theme state, app state (selected item, current value, etc.)
   - In-scope vs out-of-scope (carve-outs: terminal cell grid, hexview byte grid, gfxdemo, dbg, mono content)

2. **Design the widget set for this app.** Map current paint regions to widgets:
   - Panel → `AppPanel`
   - Static text labels → `AppLabel` (pick role: Title for headers, Body for content, Caption for hints)
   - Buttons → `AppButton` (set `on_click` to a free function that mutates app state)
   - List rows → `AppListRow`
   - Text inputs → `AppInput`
   - Separators → `AppDivider`
   - Toolbar strip → `AppToolbar`
   - Scrollbars → `AppScrollbar`

3. **Add `#include`s** at top of TU:
   ```cpp
   #include "drivers/video/app_widgets/widget_group.h"
   #include "drivers/video/app_widgets/app_panel.h"
   #include "drivers/video/app_widgets/app_label.h"
   // ... per widget used
   ```

4. **Construct a `constinit auto g_<app> = MakeWidgetGroup(...)` at file scope.** Use `using namespace duetos::drivers::video::app_widgets;` locally to keep names short.

5. **Replace `<App>Paint(c)` body with `g_<app>.PaintAll(c);`** Delete the old imperative paint calls.

6. **Replace `<App>Click(x, y)` body with:**
   ```cpp
   void <App>Click(u32 x, u32 y)
   {
       const Event e{ EventKind::MouseDown, x, y, 0, 0 };
       g_<app>.DispatchEvent(e);
   }
   ```

7. **Per-app self-test:** add an `<App>SelfTest()` function that constructs the app's widget group, drives a synthetic click on each button, verifies state transitions. Emit `[<app>-selftest] PASS` on success.

8. **Wire the self-test** into `boot_bringup.cpp` Pass D umbrella block. Update the umbrella sentinel's `apps=X/N` count to reflect the new app.

9. **Carve-outs (apps marked "chrome only"):** migrate only the chrome (toolbar, status bar, panels) to widgets. Leave the content grid (terminal cells, hex bytes, gfx framebuffer) on raw paint.

10. **Build + boot smoke + commit.** Each commit message format:
    ```
    apps/<name>: migrate to app_widgets (Pass D)
    ```

11. **Verification per app:**
    - Build clean (debug + release)
    - Hosted tests still 100%
    - Boot smoke: `[<app>-selftest] PASS` appears, `[pass-d-selftest]` `apps=X/N` count incremented, no PANIC/TRIPLE, Pass A/B/C umbrellas still green

## Phase 1 — Hero apps (5 commits)

For each task below, follow the migration pattern above. Surface mapping per app is specific; everything else is the pattern.

### Task 8: Calculator
**File:** `kernel/apps/calculator.cpp`
**Surfaces:**
- Background panel → `AppPanel` (full window)
- Display readout → `AppLabel(Display)` at top
- 16 digit/op buttons → `AppButton` array
- Clear/Equals → `AppButton` (Bold weight)
**Commit:** `apps/calculator: migrate to app_widgets (Pass D)`

### Task 9: Notes
**File:** `kernel/apps/notes.cpp` + `kernel/apps/notes_persist.cpp` (data-layer; no migration)
**Surfaces:**
- Toolbar (new/open/save/quit) → `AppToolbar` + child `AppButton`s
- Notes list sidebar → `AppListRow`s
- Editor area → `AppInput` (large multi-line — may need extension; if so, leave editor on raw paint and migrate only chrome)
- Status bar → `AppLabel(Caption)`
**Commit:** `apps/notes: migrate chrome + sidebar to app_widgets (Pass D)`

### Task 10: Files
**File:** `kernel/apps/files.cpp`
**Surfaces:**
- Path bar → `AppPanel` + `AppInput`
- File list → `AppListRow` per entry
- Toolbar (back/forward/up/refresh) → `AppToolbar` + `AppButton`s
- Status bar → `AppLabel(Caption)`
- Right-side preview pane → `AppPanel`
**Commit:** `apps/files: migrate to app_widgets (Pass D)`

### Task 11: Taskman
**File:** `kernel/apps/taskman.cpp`
**Surfaces:**
- Process list → `AppListRow` per task
- Toolbar (kill/refresh) → `AppToolbar` + `AppButton`s
- Status line → `AppLabel(Caption)`
**Commit:** `apps/taskman: migrate to app_widgets (Pass D)`

### Task 12: Settings (top-level only — sub-panels in Phase 3)
**File:** `kernel/apps/settings.cpp`
**Surfaces:**
- Section header → `AppLabel(Title, Bold)`
- Tab strip → `AppToolbar` + `AppButton`s (one per sub-panel: GEN/DSP/KBD/MSE/SND)
- Body panel → `AppPanel`
- Row labels + values → `AppLabel(Body)` pairs
**Commit:** `apps/settings: migrate top-level chrome to app_widgets (Pass D)`

## Phase 2 — Mid-size apps (10 commits)

### Task 13: Browser
**File:** `kernel/apps/browser.cpp`
**Surfaces:** URL bar (AppInput), nav buttons (AppButton), content panel (AppPanel), status bar (AppLabel Caption).
**Commit:** `apps/browser: migrate chrome to app_widgets (Pass D)`

### Task 14: Calendar
**File:** `kernel/apps/calendar.cpp`
**Surfaces:** Month/year header (AppLabel Title Bold), day-of-week row (AppLabel Caption), day cells (AppButton with date as label).
**Commit:** `apps/calendar: migrate to app_widgets (Pass D)`

### Task 15: Imageview
**File:** `kernel/apps/imageview.cpp`
**Surfaces:** Toolbar (zoom/fit/rotate), status bar (filename + dimensions). Image content stays on raw paint.
**Commit:** `apps/imageview: migrate chrome to app_widgets (Pass D)`

### Task 16: Clock
**File:** `kernel/apps/clock.cpp`
**Surfaces:** Big LED clock stays as custom font (intentional app personality). Chrome buttons (mode/timezone) → AppButton. Status bar → AppLabel Caption.
**Commit:** `apps/clock: migrate chrome to app_widgets; preserve LED face (Pass D)`

### Task 17: Hexview
**File:** `kernel/apps/hexview.cpp`
**Surfaces:** Toolbar (jump/find), status bar. **Byte grid stays raw bitmap** (cell alignment depends on fixed-width).
**Commit:** `apps/hexview: migrate chrome to app_widgets; preserve byte grid (Pass D)`

### Task 18: Charmap
**File:** `kernel/apps/charmap.cpp`
**Surfaces:** Character grid (AppButton per char OR raw if performance matters), header (AppLabel Title), selected-char preview (AppLabel Display).
**Commit:** `apps/charmap: migrate to app_widgets (Pass D)`

### Task 19: Devicemgr
**File:** `kernel/apps/devicemgr.cpp`
**Surfaces:** Tree-style device list (AppListRow per device — indent via x offset), refresh button (AppButton).
**Commit:** `apps/devicemgr: migrate to app_widgets (Pass D)`

### Task 20: Firewall
**File:** `kernel/apps/firewall.cpp`
**Surfaces:** Rules list (AppListRow), add/edit/delete buttons (AppButton), status (AppLabel Caption).
**Commit:** `apps/firewall: migrate to app_widgets (Pass D)`

### Task 21: Help
**File:** `kernel/apps/help.cpp`
**Surfaces:** Topic list (AppListRow), content panel (AppPanel + AppLabel Body for paragraphs).
**Commit:** `apps/help: migrate to app_widgets (Pass D)`

### Task 22: Netstatus
**File:** `kernel/apps/netstatus.cpp`
**Surfaces:** Interface list (AppListRow per IF), stats grid (AppLabel Body pairs), refresh button (AppButton).
**Commit:** `apps/netstatus: migrate to app_widgets (Pass D)`

## Phase 3 — Small apps + sub-panels (13 commits)

### Task 23: Sysmon
**File:** `kernel/apps/sysmon.cpp` — CPU/mem graphs (raw paint OK if performance-bound) + chrome (toolbar, header).
**Commit:** `apps/sysmon: migrate chrome to app_widgets (Pass D)`

### Task 24: About
**File:** `kernel/apps/about.cpp` — header (AppLabel Display "DuetOS"), info rows (AppLabel Body pairs), close button (AppButton).
**Commit:** `apps/about: migrate to app_widgets (Pass D)`

### Task 25: Notify
**File:** `kernel/drivers/video/notify.cpp` — title (AppLabel Title), body (AppLabel Body), dismiss button (AppButton).
**Commit:** `video/notify: migrate to app_widgets (Pass D)`

### Task 26: Notify_center
**File:** `kernel/apps/notify_center.cpp` — list of notifications (AppListRow per), clear-all button (AppButton).
**Commit:** `apps/notify_center: migrate to app_widgets (Pass D)`

### Task 27: Screenshot
**File:** `kernel/apps/screenshot.cpp` — capture button (AppButton), preview panel (AppPanel), filename label (AppLabel Body).
**Commit:** `apps/screenshot: migrate to app_widgets (Pass D)`

### Task 28: Settings sub-panel — datetime
**File:** `kernel/apps/settings_datetime.cpp` — header (Title Bold), row labels (Body), key hints (Caption). Same role mapping as Pass C migrations.
**Commit:** `apps/settings_datetime: migrate to app_widgets (Pass D)`

### Task 29: Settings sub-panel — display
**File:** `kernel/apps/settings_display.cpp` — same mapping as Task 28.
**Commit:** `apps/settings_display: migrate to app_widgets (Pass D)`

### Task 30: Settings sub-panel — keyboard
**File:** `kernel/apps/settings_keyboard.cpp` — same mapping.
**Commit:** `apps/settings_keyboard: migrate to app_widgets (Pass D)`

### Task 31: Settings sub-panel — mouse
**File:** `kernel/apps/settings_mouse.cpp` — same mapping.
**Commit:** `apps/settings_mouse: migrate to app_widgets (Pass D)`

### Task 32: Settings sub-panel — sound
**File:** `kernel/apps/settings_sound.cpp` — same mapping.
**Commit:** `apps/settings_sound: migrate to app_widgets (Pass D)`

### Task 33: Terminal (chrome only)
**File:** `kernel/apps/terminal.cpp` — toolbar, title bar, status bar to widgets. **Cell grid stays raw** (mono cell-alignment invariant).
**Commit:** `apps/terminal: migrate chrome to app_widgets; preserve cell grid (Pass D)`

### Task 34: Gfxdemo (chrome only)
**File:** `kernel/apps/gfxdemo.cpp` (+ `gfxdemo_modes.cpp` if it has chrome) — title bar + status to widgets. **Framebuffer demo content stays raw** (intentional primitive demonstration).
**Commit:** `apps/gfxdemo: migrate chrome to app_widgets (Pass D)`

### Task 35: Dbg render chrome (chrome only)
**File:** `kernel/apps/dbg_render.cpp` — chrome panel + label only. **Debug overlay content stays raw** (must work when half the kernel is wedged).
**Commit:** `apps/dbg_render: migrate chrome to app_widgets (Pass D)`

**Apps NOT migrated by design** (no chrome to migrate, or pure-data modules):
- `kernel/apps/notes_persist.cpp` — data layer for Notes; no UI
- `kernel/apps/start_menu_apps.cpp` — data layer (FAT32 manifest parser); no UI
- `kernel/apps/dbg.cpp` / `dbg_core.cpp` — debug primitives, no chrome
- `kernel/apps/gfxdemo_modes_vk.cpp` — pure rendering helpers, no chrome

This leaves ~28 of 33 apps actually migrated.

## Phase 4 — Acceptance (3 commits)

### Task 36: pass-d-soak.sh

**File:** Create `tools/test/pass-d-soak.sh`

60s sustained-load rig. Boot, sequentially open each migrated app via QMP key/click, drive synthetic clicks across widget surfaces, capture. Asserts:
- Every per-app sentinel green
- `[app-widgets-selftest] PASS`
- `[pass-d-selftest] PASS` with `apps=N/N` where N matches the migrated count
- No PANIC/TRIPLE, no oom-slab-fault, no soft-lockup
- Pass A/B/C umbrellas still green

Pattern: copy `tools/test/pass-c-soak.sh` as the starting template; add the per-app sentinel checks; commit.

```bash
git add tools/test/pass-d-soak.sh
git commit -m "tools/test: pass-d-soak — 60s widget-heavy regression guard"
```

### Task 37: tactility-screenshot-matrix.sh --apps mode

**File:** Modify `tools/test/tactility-screenshot-matrix.sh`

Add `--apps` mode that boots each theme, opens each migrated app via QMP, captures PPM. Save as `${theme}_apps-<appname>.ppm`.

```bash
git add tools/test/tactility-screenshot-matrix.sh
git commit -m "tools/test: tactility-screenshot-matrix --apps mode (Pass D)"
```

### Task 38: Wiki + Roadmap reconciliation

**Files:**
- Create `wiki/subsystems/AppWidgets.md` — library reference page (API, examples, when to use each widget)
- Modify `wiki/subsystems/Compositor.md` — append Pass D section
- Modify `wiki/reference/Roadmap.md` — graduate Pass D items, file residuals under "App widgets (Pass D) — residual polish"
- Modify `wiki/_Sidebar.md` if it lists subsystem pages (add AppWidgets)

```bash
git add wiki/subsystems/AppWidgets.md wiki/subsystems/Compositor.md wiki/reference/Roadmap.md wiki/_Sidebar.md
git commit -m "wiki: AppWidgets reference + Pass D Compositor section + Roadmap reconciliation"
```

**Phase 4 complete.** Pass D ready for merge to main.

---

## Self-review

**1. Spec coverage:** Each spec section maps to plan tasks:
- §1 Summary — Phase 0 (library) + Phase 1-3 (migrations) + Phase 4 (acceptance)
- §2 Goals + Non-goals — encoded as the scope of every task
- §3 Architecture — Tasks 1-2 (CRTP base + WidgetGroup)
- §4 Widget set — Tasks 3-5 (8 concrete widgets)
- §5 Per-app migration shape — Migration pattern + Tasks 8-35
- §6 Carve-outs — explicit in Tasks 17, 33, 34, 35 + the "Apps NOT migrated" list
- §7 Testing — Task 6 (hosted) + Task 7 (kernel self-test) + per-app sentinels + Task 36 (soak) + Task 37 (screenshots)
- §8 Acceptance — Task 38 (wiki + Roadmap)
- §9 Sequencing — 5 phases reflected in plan structure
- §10 Open questions — kept in spec as deferred-to-Pass-E

**2. Placeholder scan:** No "TBD", "TODO", or "implement later" in the plan. Phase 1-3 tasks are concise but each names exact file + surface mapping + commit message — they're "follow the pattern with these specifics". Subagents will read the migration pattern + the per-app surface list to do the work. This matches Pass C's plan style where per-file migration tasks were similarly concise.

**3. Type consistency:** Verified across the plan:
- `Widget<Self>`, `Rect`, `Event`, `EventKind`, `EventResult`, `WidgetState`, `WidgetStateFlags` — all defined Task 1, used consistently in Tasks 2-7 + migration pattern
- `WidgetGroup<Ws...>`, `MakeWidgetGroup` — defined Task 2, used in migration pattern
- `AppPanel` / `AppLabel` / `AppButton` / `AppListRow` / `AppInput` / `AppDivider` / `AppToolbar` / `AppScrollbar` — defined Tasks 3-5, used in migration pattern
- `AppWidgetsSelfTest()` / `AppWidgetsSelfTestPassed()` — defined Task 7
- `[app-widgets-selftest]`, `[pass-d-selftest]`, `[<app>-selftest]` sentinels — consistent format
- `g_<app>` constinit naming — consistent across migration pattern

No bugs found. Plan is internally consistent and ready to execute.

