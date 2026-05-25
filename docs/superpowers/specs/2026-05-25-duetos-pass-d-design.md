# DuetOS Pass D — App-level visual cohesion via template-based widget library

## §1 Summary

Pass D delivers visual cohesion across all 33 DuetOS apps by introducing a **template-based widget component library** (`kernel/drivers/video/app_widgets/`) and migrating every app to consume it. Widgets manage their own state and event routing internally; apps compose typed widget trees at compile time via `WidgetGroup<Widget1, Widget2, ...>`. The result: every visible app surface shares the same typography (ChromeText roles), the same spacing (Measure-driven layout), and the same depth treatment (selective atlas-shadow on buttons + panels) — nothing on screen looks out of place.

Pass A added chrome tactility, Pass B added first-impression moments, Pass C added the typography hierarchy. Pass D applies the same design language inside every window.

## §2 Goals and Non-goals

### Goals
- One coherent visual design language across every visible app surface.
- A declarative widget composition model that replaces per-app imperative paint loops.
- Future apps inherit the polish for free by composing widgets.
- All 33 apps migrated (with intentional carve-outs for content-grid surfaces).
- New `[pass-d-selftest]` boot umbrella sentinel + boot-log-analyze section parallel to Pass A/B/C.

### Non-goals
- App functionality changes — apps do what they already do, just look better.
- App framework / lifecycle / event-routing-hub overhaul — out of scope for Pass D; potential Pass E.
- New apps — none added.
- Layout managers / auto-layout — apps still pass explicit `Rect` bounds; auto-layout is Pass E candidate.
- Variable-length widget collections, parent-pointer trees, dynamic widget add/remove — explicitly ruled out by the storage model.
- Heap allocation in the widget system — all widgets are value-type structs.

## §3 Architecture

### CRTP base + derived widgets

```cpp
template <typename Self>
struct Widget
{
    Rect bounds{};
    WidgetState state{};   // hover / pressed / focused / disabled

    void Paint(Compose& c) const          { static_cast<const Self*>(this)->PaintSelf(c); }
    EventResult OnEvent(const Event& e)   { return static_cast<Self*>(this)->OnEventSelf(e); }

    // Defaults the Self may override:
    void PaintSelf(Compose&) const { /* no-op */ }
    EventResult OnEventSelf(const Event&) { return EventResult::NotInterested; }
};

struct AppButton : Widget<AppButton>
{
    const char* label = "";
    void (*on_click)() = nullptr;
    ChromeTextWeight weight = ChromeTextWeight::Regular;

    void PaintSelf(Compose& c) const;
    EventResult OnEventSelf(const Event& e);
};
```

No virtual dispatch; CRTP gives static polymorphism without RTTI. Each widget is a plain struct with public fields the app populates at construction.

### WidgetGroup — compile-time-known composition

```cpp
template <typename... Ws>
struct WidgetGroup
{
    std::tuple<Ws...> widgets;

    void PaintAll(Compose& c) const;             // fold paint over tuple, back-to-front
    EventResult DispatchEvent(const Event& e);   // fold event, first Consumed wins
};

// Calculator app:
constinit auto g_calc = MakeWidgetGroup(
    AppPanel  { Rect{px, py, pw, ph} },
    AppLabel  { Rect{px+8, py+10, pw-16, 24}, "0.00", ChromeTextRole::Display },
    AppButton { Rect{...}, "7", &OnDigit7 },
    /* ... one per button */
);
```

### Event flow

1. WM mouse/key handler produces an `Event` with coords/keycode.
2. App's `DispatchEvent(e)` walks the tuple back-to-front, hit-tests each widget.
3. First widget that returns `EventResult::Consumed` stops the fold.
4. Widget's internal state mutates (hover ON, pressed ON, click fires its `on_click`).
5. App calls `g_widgets.PaintAll(compose)` next frame to reflect new state.

### Storage model

- **Value semantics** — widgets are plain structs; no heap allocation. Each app's `WidgetGroup` is a single `constinit` static instance.
- **Bounds at construct time** — `Rect{x, y, w, h}` plain. Layout is the app's responsibility (no layout manager in Pass D).
- **Flat composition** — `WidgetGroup` is a single tuple, no nesting. Panel-contains-buttons is spatial overlap (buttons sit inside the panel's rect; both live in the same group).
- **No dynamic add/remove** — widget set per app is fixed at compile time. Conditional visibility uses the disabled state.

### Types
- `enum class EventResult : u8 { NotInterested = 0, Consumed = 1 };`
- `enum class WidgetStateFlags : u8 { None = 0, Hover = 1<<0, Pressed = 1<<1, Focused = 1<<2, Disabled = 1<<3 };`
- `struct Rect { u32 x; u32 y; u32 w; u32 h; bool Contains(u32 px, u32 py) const; };`
- `struct Event { EventKind kind; u32 x; u32 y; u32 keycode; u32 mods; };`
- `enum class EventKind : u8 { MouseDown, MouseUp, MouseMove, KeyDown, KeyUp, FocusIn, FocusOut };`

## §4 Widget set (Pass D ships these eight)

| Widget       | Role                                                       | Tactility | Events                  |
|--------------|------------------------------------------------------------|-----------|-------------------------|
| `AppPanel`   | Theme bg + border + optional shadow                        | yes       | none                    |
| `AppLabel`   | Static text (role + weight configurable)                   | no        | none                    |
| `AppButton`  | Label + accent fill + state-driven look                    | yes       | click, hover            |
| `AppListRow` | Row with hover bg + accent stripe + Body text              | no        | click, hover, select    |
| `AppInput`   | Text input box + cursor + selection                        | no        | key, focus              |
| `AppDivider` | Horizontal or vertical line, theme border color            | no        | none                    |
| `AppToolbar` | Horizontal strip; positions child buttons                  | yes       | delegates to children   |
| `AppScrollbar` | Vertical/horizontal scroll indicator + thumb             | no        | drag                    |

**Deferred (Pass E candidates):** Checkbox, Slider, ComboBox, ProgressBar, ScrollView container, Tabs. Apps needing them inline a one-off using existing primitives.

## §5 Per-app migration shape

### BEFORE (today, imperative paint)

```cpp
// kernel/apps/calculator.cpp — ~50 lines of imperative draws + a separate Click() function
void CalculatorPaint(Compose& c)
{
    FramebufferFillRect(px, py, pw, ph, bg);
    FramebufferFillRect(px, py, pw, 40, header_bg);
    FramebufferDrawString(px + 8, py + 10, "0.00", 0xFFFFFF, header_bg);
    for (each button) { /* FillRect + DrawRect + DrawString */ }
}
void CalculatorClick(u32 x, u32 y) { /* hit-test ladder */ }
```

### AFTER (declarative widget composition)

```cpp
constinit auto g_calc = MakeWidgetGroup(
    AppPanel  { Rect{px, py, pw, ph} },
    AppLabel  { Rect{px+8, py+10, pw-16, 24}, "0.00", ChromeTextRole::Display },
    AppButton { Rect{...}, "7", &OnDigit7 },
    /* ... one per button */
);

void CalculatorPaint(Compose& c)     { g_calc.PaintAll(c); }
void CalculatorClick(const Event& e) { g_calc.DispatchEvent(e); }
```

The migration deletes the imperative paint loop + the hit-test ladder; both collapse into widget composition.

## §6 Carve-outs (intentionally not migrated)

- **Terminal** — chrome moves to widgets (toolbar, status bar). Cell grid stays raw bitmap.
- **Hexview** — chrome to widgets, byte grid stays raw.
- **GFX demo / GFX demo modes** — intentionally raw FB to demonstrate primitive APIs.
- **Dbg / dbg_core / dbg_render** — debug overlays use raw paint by design (must work when half the kernel is wedged).
- **Mono path generally** — any cell-grid surface where alignment depends on fixed-width glyphs.

## §7 Testing

### Hosted unit tests (CTest)
- `test_app_widgets_paint` — each widget's `PaintSelf` with a mocked Compose; assert correct primitive sequence (fill, border, text).
- `test_app_widgets_events` — hit-test correctness, state transitions, callback firing.
- `test_widget_group` — back-to-front fold order, first-consumed-wins, paint enumeration.
- `test_app_widgets_bounds` — `Rect` arithmetic + clipping invariants.

### Kernel-side self-tests (boot umbrella)
- `AppWidgetsSelfTest()` — boot self-test phase; constructs each widget, drives synthetic events, verifies state machine. Emits `[app-widgets-selftest] PASS` on success / `FAIL <reason>` + `KBP_PROBE_V` on failure.
- Per-app boot smokes verify each migrated app still renders + responds: `[<app>-selftest] PASS` per app.
- Umbrella: `[pass-d-selftest] PASS (widgets=ok, apps=N/N)`.

### boot-log-analyze.sh Pass D section
- Widget library self-test (PASS/FAIL/MISSING).
- Per-app self-test count (X PASS / Y FAIL / Z SKIP).
- Umbrella sentinel (PASS/MISSING).
- Pass A/B/C umbrellas must stay green.

### Screenshot acceptance
- New `tools/test/tactility-screenshot-matrix.sh --apps` mode: boot, open each app via QMP key/click, capture PPM, kill.
- Up to 33 apps × 10 themes ≈ 330 PPMs (fewer in practice — some apps skip headless, some themes share output).
- Reference set copied to OneDrive logs folder for visual diff against baseline.

### pass-d-soak.sh
- 60s sustained-load rig: boot, launch every app via QMP, drive synthetic clicks across widget surfaces.
- Asserts: every per-app sentinel green, no PANIC/TRIPLE, no oom-slab-fault, no soft-lockup, no widget-state assertion fires, no compositor overruns.

### Per-commit verification rhythm (subagent-driven execution)
1. Implementer subagent migrates one app + writes its self-test.
2. Build clean (debug + release).
3. Hosted tests still 100%.
4. Boot smoke: app's sentinel PASS, no regressions in Pass A/B/C umbrellas.
5. Spec compliance review + code quality review (per-task).
6. Commit; next subagent dispatch.

## §8 Acceptance

The Pass D acceptance gate is met when:
- Library `kernel/drivers/video/app_widgets/{widget.h,widget_group.h,app_button.{h,cpp},...}` exists and is tested.
- All 33 apps (minus the carve-outs above) consume the library — no remaining `FramebufferDrawString` in app chrome.
- `[app-widgets-selftest] PASS` + `[pass-d-selftest] PASS (widgets=ok, apps=N/N)` fire at boot.
- `boot-log-analyze.sh` Pass D section reports widget-library + per-app + umbrella all green.
- `pass-d-soak.sh` PASSes.
- `tactility-screenshot-matrix.sh --apps` produces the reference set.
- Clean build debug + release, no warnings on Pass D TUs.
- All hosted tests green.
- New page `wiki/subsystems/AppWidgets.md` exists; `wiki/subsystems/Compositor.md` updated with Pass D section; `wiki/reference/Roadmap.md` reconciled (Pass D items graduated, residuals filed under "App widgets (Pass D) — residual polish").

## §9 Sequencing

- **Phase 0 — Library** (~5 commits): CRTP base + types, 8 concrete widgets, WidgetGroup, hosted tests, boot self-test wiring.
- **Phase 1 — Hero apps** (~5 commits): Calculator, Notes, Files, Taskman, Settings.
- **Phase 2 — Mid-size apps** (~10 commits): Browser, Calendar, Imageview, Clock, Hexview (chrome only), Charmap, Devicemgr, Firewall, Help, Netstatus.
- **Phase 3 — Small apps + sub-panels** (~13 commits): Sysmon, About, Notify, Notify_center, Screenshot, Dbg (chrome only), Gfxdemo (chrome only), Gfxdemo_modes (chrome only), settings sub-panels (datetime/display/keyboard/mouse/sound), Terminal (chrome only), Imageview helpers.
- **Phase 4 — Acceptance** (~3 commits): pass-d-soak harness, screenshot matrix --apps mode, wiki + Roadmap reconciliation.

~35–40 commits total on one branch `claude/pass-d-app-widgets`. Per-app boot smoke after each commit. Single merge at end after user review.

## §10 Open questions deferred to Roadmap

- Layout managers (auto-layout / flexbox-style) — Pass E candidate.
- Extended widget set (Checkbox / Slider / ComboBox / ProgressBar / Tabs / ScrollView) — add when first consumer needs them.
- Event-routing hub — Pass D dispatches events per-app (each app calls `widgets.DispatchEvent(e)` from its existing input hook). A centralized hub that routes events to the focused widget across apps is Pass E.
- Animation system for widget state transitions (hover fade, pressed dip) — Pass E candidate.

---

**See also:** `docs/superpowers/plans/2026-05-25-duetos-pass-d.md` for the implementation plan.
