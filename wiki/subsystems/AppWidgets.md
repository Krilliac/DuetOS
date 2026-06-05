# App Widgets

> **Audience:** Kernel hackers, in-kernel app authors, UI contributors
>
> **Execution context:** Kernel — value-typed widgets painted and
> dispatched from the app's draw / event hooks in process context
>
> **Maturity:** active — eight-widget library shipped (landed as
> "Pass D"); 28 of 33 in-tree apps migrated, five raw-paint carve-outs
> by design

The **app widgets library** at `kernel/drivers/video/app_widgets/`
collapses the imperative paint + click ladder every kernel app used
to hand-roll (FillRect → DrawRect → DrawString → if-bounds-contains
hit-test) into a small set of value-typed widget structs composed
into a per-app `WidgetGroup<…>`. Apps construct their widget set as
a `constinit static` instance, paint with `group.PaintAll(compose)`,
and dispatch input with `group.DispatchEvent(event)`. The library
ships zero virtual dispatch, zero RTTI, zero heap, and zero
exceptions — everything is CRTP + value semantics, exactly what the
freestanding kernel ABI allows.

Pass D migrated 28 of 33 in-tree apps to this library. The five
carve-outs (debug overlays, gfx-demo content modes, notes
persistence backend, trash facade) stay on raw paint by design —
see [Carve-outs](#carve-outs) below.

## Design Goals

The library exists to solve four concrete problems Pass A–C left
in place:

1. **Hit-test duplication.** Every app had its own `Click()` ladder
   doing `if (x >= bx && x < bx+bw && y >= by && y < by+bh)` for
   every button — easy to get the half-open interval wrong, easy
   to fall out of sync with the matching `Paint()` rectangle.
2. **Chrome paint duplication.** Every app re-derived its own
   theme-colour reads, role-text routing, and shadow rendering
   from scratch, so a Pass A tactility tweak (shadow radius,
   pressed-state offset) had to be replicated 28 times.
3. **Imperative-vs-declarative drift.** A widget's visual state
   (hover / pressed / focused / disabled) and its hit-test state
   were stored in separate scattered locals, allowing them to
   diverge across a paint/event boundary.
4. **No library for the next pass to extend.** Without a single
   home, every future widget-shape addition (Checkbox, Slider,
   Tabs) would land in every app independently.

Pass D is the foundation; future passes extend the widget set, not
the paint surface.

## CRTP Base + Storage Model

The base type is `Widget<Self>` (in `widget.h`). Concrete widgets
derive from it with their own type as `Self`, and override
`PaintSelf` / `OnEventSelf`. The base forwards `Paint` / `OnEvent`
through a `static_cast<Self*>(this)` — no virtual table, no
indirect call. The compiler inlines through the chain at `-O1`+.

```cpp
struct AppButton : Widget<AppButton>
{
    const char* label = "";
    void (*on_click)() = nullptr;
    ChromeTextWeight weight = ChromeTextWeight::Regular;
    u32 bg_rgb = 0;
    u32 fg_rgb = 0xFFFFFFU;

    void PaintSelf(Compose& c) const;
    EventResult OnEventSelf(const Event& e);
};
```

Each widget carries a `Rect bounds` and a `WidgetState{flags}`
inherited from the base. State is a bitfield over
`WidgetStateFlags::{None, Hover, Pressed, Focused, Disabled}`.

**Storage:** every widget is a plain value struct. No heap. No
shared pointer. No vtable. A widget weighs sizeof(its plain
members) + the inherited base; the smallest (AppDivider) is 32 B.

## WidgetGroup — Compile-Time Composition

`WidgetGroup<W1, W2, ...>` (in `widget_group.h`) is a compile-
time-known tuple substitute built from recursive inheritance
(`std::tuple` is unavailable in freestanding kernel TUs). Apps
declare the group as a `constinit static` initialised with every
widget by value:

```cpp
namespace {
constinit static auto g_calc = WidgetGroup<
    AppPanel, AppLabel, AppButton, AppButton, AppButton /* … */>{
        AppPanel{ .bounds = {0, 0, 240, 320} },
        AppLabel{ .bounds = {8, 8, 224, 16}, .text = "0.00" },
        AppButton{ .bounds = {8, 40, 56, 40}, .label = "1",
                   .on_click = +[]{ KeyDigit(1); } },
        // ...
    };
} // anon

void CalculatorPaint(Compose& c)    { g_calc.PaintAll(c); }
void CalculatorClick(const Event& e){ g_calc.DispatchEvent(e); }
```

**Paint order** is back-to-front in declaration order: the first
widget paints first (visually behind), later widgets paint on
top.

**Event dispatch** is front-to-back, first-Consumed-wins: the
last-declared widget gets first refusal on every event, falling
back through the chain. This matches Z-order intuition — a
button declared on top of a panel claims clicks even though the
panel is at the same x/y.

A `MakeWidgetGroup(w1, w2, w3)` deduction helper exists for
callers that don't want to spell out the template parameter pack.

## The Widget Set

Eight widgets ship in Pass D. Each is one .h/.cpp pair under
`kernel/drivers/video/app_widgets/`.

| Widget | Events | When to use |
|---|---|---|
| **AppPanel** | none (paint-only) | Window background fill + optional shadow. Always the first widget in the group. Reads `ThemeCurrent().role_client[0]` and the theme border by default; override `bg_rgb` / `border_rgb` to draw a tinted panel (e.g. titlebar strip). `shadow_radius` honours tactility-on themes. |
| **AppLabel** | none (paint-only) | Any chrome text. Routes through `ChromeTextDraw` (Pass C) so role + weight + theme dispatch are correct on every theme. `align_left = true` for left-aligned body text; default is centred for titles. |
| **AppDivider** | none (paint-only) | 1-px horizontal/vertical rule between groups. `rgb = 0` picks the theme border colour. |
| **AppButton** | MouseMove/Down/Up | Clickable rectangle with hover + pressed visuals + `on_click` callback. Free-function pointer (no captures — C-style callback semantics). Fires on MouseUp inside bounds, matching desktop UX. |
| **AppListRow** | MouseDown | Selectable row in a list (Files, Notes, Browser bookmarks, Help index). Fires `on_click` on press (rows are select-on-press by design), `selected = true` paints the accent stripe. |
| **AppToolbar** | none (paint-only) | Solid tinted strip used as a parent to position buttons + labels inside. Just a background fill — buttons declared after it in the group paint on top. |
| **AppInput** | KeyDown, MouseDown (focus) | Text-input box bound to a caller-owned `char[]` buffer + length. Caret + on_change callback. Single-line; multi-line editors (Notes body, Browser address bar) use raw paint per carve-out. |
| **AppScrollbar** | MouseDown (track + thumb) | Vertical or horizontal scrollbar with content / viewport size and a scroll offset. Calls `on_scroll(new_offset)` when the thumb is dragged. Used by Notes, Files, Browser, Help, Charmap. |

Every widget's `PaintSelf` reads theme colours through
`ThemeCurrent()` rather than baked constants, so all themes
(Pass A) and tactility on/off (Pass A residual) and the
typography roles (Pass C) work for free.

## Event Model

Events are plain values (`struct Event { kind, x, y, keycode, mods }`)
with a six-element `EventKind` enum (`MouseDown / MouseUp /
MouseMove / KeyDown / KeyUp / FocusIn / FocusOut`). The host
(typically the kernel's mouse + keyboard reader, the dialog box
event hook, or the per-app message pump) constructs one `Event`
per input edge and calls `group.DispatchEvent(event)`.

**Return:** `EventResult::{NotInterested, Consumed}`. The walker
stops at the first `Consumed` and returns immediately. If every
widget returned `NotInterested`, the host is free to fall back to
its raw paint region (Files' folder grid, terminal cell grid,
hexview byte grid).

State transitions happen inside `OnEventSelf` — a button hovered-
to-pressed sequence is three OnEvent calls (MouseMove ON,
MouseDown, MouseUp), each mutating `state.flags` and (on the up
edge) firing `on_click`.

## Self-Tests

Two layers:

- **Hosted unit tests** (`tests/host/test_app_widgets_*`): pure-C++
  Paint mocks, Rect arithmetic, WidgetGroup fold order,
  first-Consumed-wins, every widget's state machine. Run under
  CTest; no kernel context needed.
- **Boot self-test** (`AppWidgetsSelfTest()` in
  `kernel/drivers/video/app_widgets/self_test.cpp`): constructs
  each widget on the kernel stack, drives synthetic
  `Event{MouseMove/MouseDown/MouseUp}` through `OnEvent`, asserts
  the expected state-flag transitions + on_click fires. Emits
  `[app-widgets-selftest] PASS` on success;
  `[app-widgets-selftest] FAIL <reason>` + `KBP_PROBE_V(0xD0–0xD3)`
  on any failure.

**Umbrella:** `boot_bringup.cpp` reads
`AppWidgetsSelfTestPassed()` after every per-app self-test has
run; if the widget library passed and every migrated app's
self-test passed, it emits

```
[pass-d-selftest] PASS (widgets=ok, apps=28/28)
```

which is the canonical sentinel `boot-log-analyze.sh` and
`tools/test/pass-d-soak.sh` check for.

## Carve-outs

Pass D intentionally does **not** migrate:

- **Files' folder/list grid** — multi-mode raw paint with backend-
  specific rendering (FAT32 / DuetFS / Trash / ramfs each draw
  rows differently). Chrome toolbar + filter input are widgets;
  the grid stays raw.
- **Calendar's month/week/day cells** — calendar cell layout is
  expressed natively as a 2-D grid with custom hit-test for
  date selection. Widgets would add overhead without a win.
- **Terminal cell grid** — character cells need fixed-width
  alignment; the cell rendering loop must stay raw bitmap.
  Toolbar + status bar are widgets.
- **Hexview byte grid** — same as terminal: fixed-pitch
  monospace grid. Chrome migrated.
- **GFX demo modes** (`gfxdemo_modes.cpp` / `_vk.cpp`) — the
  point of the demo is to exercise the primitive APIs directly;
  widget chrome around them is fine, the demo content itself
  intentionally bypasses it.
- **Debug overlays** (`dbg.cpp`, `dbg_core.cpp`,
  `dbg_render.cpp`'s render layer) — debug surfaces must work
  when half the kernel is wedged, so they paint raw.
  `dbg_render.cpp`'s chrome is migrated; the overlay rendering
  stays raw.
- **Notes persistence** (`notes_persist.cpp`) — pure data layer,
  no paint surface to migrate.
- **Trash backend** (`trash.cpp`) — facade module providing
  Files' trash mode; no chrome of its own.

Apps marked "chrome only" in the design (Terminal, Hexview,
Gfxdemo, Dbg_render) migrated their toolbar / status bar /
title strip to widgets, leaving the content region on raw
paint. Files and Calendar carve out raw paint regions inside
otherwise-migrated apps using the same pattern — the widget
group paints the chrome, the app's `RenderContent()` paints
the grid into the carved-out rect after `group.PaintAll`.

The rule of thumb: **if a surface is a fixed grid or a debug
overlay, leave it raw; if it's chrome, migrate it.**

## Acceptance + Verification

- `[app-widgets-selftest] PASS` and
  `[pass-d-selftest] PASS (widgets=ok, apps=28/28)` fire under
  the `if constexpr (kBootSelfTests)` umbrella at boot.
- `tools/test/pass-d-soak.sh` — 60 s sustained-load regression
  guard. Asserts every per-app sentinel + both umbrella sentinels
  + Pass A/B/C umbrellas + no PANIC / TRIPLE / oom-slab-fault /
  non-deliberate soft-lockup.
- `tools/test/tactility-screenshot-matrix.sh --apps` — three
  chrome surfaces × 10 themes = 30 PPMs (login card, taskbar /
  desktop, lock card). Per-app window shots are deferred to
  VBox visual verification — qmp.sh can't open Calculator /
  Notes headlessly. See
  [`Roadmap`](../reference/Roadmap.md) "App widgets (Pass D) —
  residual polish".

## Known Limits / GAPs

- **Eight widgets only.** No Checkbox, Slider, Tabs, Dropdown, or
  multi-line text area yet — future passes extend the set (see
  Design Goals). Multi-line editors (Notes body, Browser address bar)
  stay on raw paint until a multi-line `AppInput` lands.
- **Five carve-outs stay raw by design** — debug overlays, gfx-demo
  content modes, notes persistence backend, and the trash facade are
  not migrated (see [Carve-outs](#carve-outs)); fixed grids (Files
  list, Calendar cells, Terminal / Hexview cells) keep raw content
  regions inside otherwise-migrated apps.
- **C-style callbacks only.** `on_click` / `on_change` / `on_scroll`
  are free-function pointers with no captures — state must live in
  the caller, not a closure.
- **Per-app window shots not headless-verified.** `qmp.sh` can't open
  Calculator / Notes headlessly, so per-app visual verification is
  deferred to VBox (see Acceptance + Verification).

## Related Pages

- [Compositor and Window Manager](Compositor.md) — Pass A
  tactility, Pass B first-impression moments, Pass C
  typography, Pass D widgets are co-equal layers of the chrome
  stack.
- [UI Toolkit](UI-Toolkit.md) — companion (older) toolkit
  surface; app_widgets supersedes it for kernel-side apps.
- [In-Kernel Apps](../kernel/Kernel-Apps.md) — the consumer
  side: which apps live where and how they wire into the
  window manager.
- [Duet Theme Spec](../specifications/Duet-Theme-Spec.md) —
  every widget reads its colours through `ThemeCurrent()`.
