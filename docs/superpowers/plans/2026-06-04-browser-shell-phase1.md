# Browser Shell Redesign — Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the redesigned in-kernel browser **shell** (tab strip, unified omnibox + ✦ Ask AI, the floating snap-dock surface, the DuetOS start page, the motif/token set) — a usable baseline with **no AI intelligence and no real multi-tab engine** (one live page; tabs store url/title/scroll). Phases 2 (AI + Privileged-Origin Mode) and 3 (multi-tab arena pool) are separate plans.

**Architecture:** New shell components are small, value-semantic, boot-self-tested modules under `kernel/apps/browser/` (`DockSurface`, `TabStrip`, `Omnibox`, `StartPage`, `tokens`). The novel core is `DockSurface` — one state machine (`Hidden`/`Floating`/`Docked(edge,size)`) reused for both the Assistant and the Library, with pure snap-zone geometry that is unit-tested *without* rendering. `browser.cpp`'s `DrawFn` is rewired last to compose these tested pieces. Verification = DuetOS boot self-tests (each module ships an `XSelfTest()` registered via `DUETOS_BOOT_SELFTEST`), built in WSL and confirmed in a headless boot; pixel appearance is validated separately (VBox/QMP screenshot).

**Tech Stack:** C++23 (kernel: no RTTI/exceptions, `Result<T,E>`), the existing `app_widgets` toolkit + `theme` + `chrome_text` + framebuffer primitives (`FillRoundRect`, `FillRectGradient`, `BlendFill`, soft-shadow atlas), the `DUETOS_BOOT_SELFTEST` harness. Build via the `wsl-build` skill; smoke via headless `tools/qemu/run.sh`.

---

## File structure

| File | Responsibility |
|------|----------------|
| `kernel/apps/browser/tokens.h` | Motif constants: corner radii, shadow tiers, accent roles (teal/amber), the `✦` spark draw helper decl. |
| `kernel/apps/browser/spark.cpp` | Draws the `✦` spark glyph at N sizes via framebuffer primitives. |
| `kernel/apps/browser/dock_surface.{h,cpp}` | The `DockSurface` state machine + snap-zone geometry + content-rect split. Pure logic + render hook. |
| `kernel/apps/browser/dock_surface_selftest.cpp` | `DockSurfaceSelfTest()` — geometry/state assertions. |
| `kernel/apps/browser/tab_strip.{h,cpp}` | `TabStrip` model (tabs, active, add/close/select) + layout math + hit-test. |
| `kernel/apps/browser/tab_strip_selftest.cpp` | `TabStripSelfTest()`. |
| `kernel/apps/browser/omnibox.{h,cpp}` | Unified omnibox state + ✦ Ask button geometry + edit transitions. |
| `kernel/apps/browser/start_page.{h,cpp}` | New-tab start-page model (tiles + prompt) + layout + render. |
| `kernel/apps/browser/start_page_selftest.cpp` | `StartPageSelfTest()` (tile layout math). |
| `kernel/apps/browser.cpp` (modify) | `DrawFn` rewired to the new shell; mouse routing for tabs + dock drag; retire footer/status band. |
| `kernel/core/boot_bringup.cpp` (modify) | Register the four new `*SelfTest()` calls. |
| `wiki/kernel/Web-Engine.md` / `Kernel-Apps.md` (modify) | Document the new shell + self-tests. |

**CMake:** kernel sources are gathered by glob (no per-file listing); new `.cpp` files under `kernel/apps/browser/` are picked up automatically. Verify on first build; if explicit, add entries.

---

## Task 1: DockSurface core (state machine + snap geometry)

The novel centerpiece. One movable surface; two instances later (Assistant, Library). Pure geometry/state — **no rendering in this task** — so it is fully unit-testable.

**Files:**
- Create: `kernel/apps/browser/dock_surface.h`
- Create: `kernel/apps/browser/dock_surface.cpp`
- Create: `kernel/apps/browser/dock_surface_selftest.cpp`
- Modify: `kernel/core/boot_bringup.cpp` (register self-test)

- [ ] **Step 1: Write the header (interface).**

```cpp
// kernel/apps/browser/dock_surface.h
#pragma once
#include "util/types.h"
#include "drivers/video/app_widgets/widget.h" // Rect

namespace duetos::apps::browser
{
using duetos::drivers::video::app_widgets::Rect;

enum class DockMode : duetos::u8 { Hidden = 0, Floating = 1, Docked = 2 };
enum class DockEdge : duetos::u8 { None = 0, Left = 1, Right = 2, Top = 3, Bottom = 4 };

// Pixels from a window edge within which a drag snaps to that edge.
constexpr duetos::u32 kDockGutter = 24;
// Default docked sizes as percent of the content rect.
constexpr duetos::u32 kDockSidePct = 34;   // left/right width %
constexpr duetos::u32 kDockBottomPct = 30; // bottom height %
constexpr duetos::u32 kDockTopPct = 18;    // top bar height %

struct DockSurface
{
    DockMode mode = DockMode::Hidden;
    DockEdge edge = DockEdge::None; // valid when mode==Docked
    Rect floatRect{};               // valid when mode==Floating (absolute, in client space)
    bool dragging = false;
    DockEdge hoverEdge = DockEdge::None; // ghost preview while dragging; None = no snap

    // Summon to its last state (Floating default if never shown).
    void Summon(const Rect& client);
    // Dismiss to Hidden (preserves last floatRect/edge for re-summon).
    void Dismiss();
    // Begin/continue/finish a header drag. `cx,cy` cursor in client space.
    void DragBegin();
    void DragUpdate(const Rect& client, duetos::u32 cx, duetos::u32 cy);
    void DragEnd(const Rect& client);

    // Which edge gutter does (cx,cy) fall in, if any (None otherwise).
    static DockEdge GutterHit(const Rect& client, duetos::u32 cx, duetos::u32 cy);
    // The surface's own rect for the current mode, given the client rect.
    Rect SurfaceRect(const Rect& client) const;
    // The content rect left for the web page after this surface docks
    // (== client when Hidden/Floating; reduced when Docked).
    Rect ContentRect(const Rect& client) const;
};

} // namespace duetos::apps::browser
```

- [ ] **Step 2: Write the failing self-test.**

```cpp
// kernel/apps/browser/dock_surface_selftest.cpp
#include "apps/browser/dock_surface.h"
#include "arch/x86_64/serial.h"
#include "debug/probes.h"

namespace duetos::apps::browser
{
using duetos::drivers::video::app_widgets::Rect;

void DockSurfaceSelfTest()
{
    auto fail = [](duetos::u32 c)
    {
        arch::SerialWrite("[dock-selftest] FAIL check=");
        arch::SerialWriteHex(c);
        arch::SerialWrite("\n");
        KBP_PROBE_V(duetos::debug::ProbeId::kBootSelftestFail, c);
    };
    const Rect client{0, 0, 1000, 600};

    // 1: gutter hits per edge, miss in the middle.
    if (DockSurface::GutterHit(client, 5, 300) != DockEdge::Left) { fail(1); return; }
    if (DockSurface::GutterHit(client, 995, 300) != DockEdge::Right) { fail(2); return; }
    if (DockSurface::GutterHit(client, 500, 5) != DockEdge::Top) { fail(3); return; }
    if (DockSurface::GutterHit(client, 500, 595) != DockEdge::Bottom) { fail(4); return; }
    if (DockSurface::GutterHit(client, 500, 300) != DockEdge::None) { fail(5); return; }

    // 2: docked-right surface takes ~34% width on the right; content takes the rest.
    DockSurface d;
    d.mode = DockMode::Docked;
    d.edge = DockEdge::Right;
    const Rect sr = d.SurfaceRect(client);
    const Rect cr = d.ContentRect(client);
    if (sr.w != 340 || sr.x != 660 || sr.h != 600) { fail(6); return; }
    if (cr.w != 660 || cr.x != 0) { fail(7); return; }

    // 3: floating surface leaves content == client (overlay, no reflow).
    DockSurface f;
    f.mode = DockMode::Floating;
    f.floatRect = Rect{700, 400, 250, 180};
    const Rect fcr = f.ContentRect(client);
    if (fcr.w != client.w || fcr.h != client.h) { fail(8); return; }

    // 4: drag into the left gutter then release => Docked Left.
    DockSurface g;
    g.Summon(client); // Floating
    g.DragBegin();
    g.DragUpdate(client, 5, 300);
    if (g.hoverEdge != DockEdge::Left) { fail(9); return; }
    g.DragEnd(client);
    if (g.mode != DockMode::Docked || g.edge != DockEdge::Left) { fail(10); return; }

    // 5: dragging a docked surface to the middle pops it back to Floating.
    g.DragBegin();
    g.DragUpdate(client, 500, 300);
    g.DragEnd(client);
    if (g.mode != DockMode::Floating) { fail(11); return; }

    arch::SerialWrite("[dock-selftest] PASS (gutter hit x4+miss, dock split L/R, float overlay, drag-snap, undock)\n");
}

} // namespace duetos::apps::browser
```

- [ ] **Step 3: Implement `dock_surface.cpp`** to satisfy the test. Key logic: `GutterHit` compares against `kDockGutter`; `SurfaceRect` computes the edge rect from the percent constants (`Right`: `x=client.x+client.w*(100-kDockSidePct)/100`, `w=client.w*kDockSidePct/100`, full height; symmetric for the others); `ContentRect` subtracts the docked surface (Hidden/Floating → return client unchanged); `DragUpdate` sets `hoverEdge = GutterHit(...)`; `DragEnd` → if `hoverEdge != None` set `Docked(hoverEdge)`, else `Floating` (recompute `floatRect` near the cursor, clamped to client); `Summon` → `Floating` with a default rect (bottom-right, `client.w*kDockSidePct/100` × `client.h*kDockBottomPct/100`) if never shown, else last state.

- [ ] **Step 4: Register + build + verify PASS.** Add `DUETOS_BOOT_SELFTEST(duetos::apps::browser::DockSurfaceSelfTest());` in `boot_bringup.cpp` (near the other app/web self-tests) with a forward decl. Build via `wsl-build`; headless boot; expect `[dock-selftest] PASS` and zero warnings.

- [ ] **Step 5: Commit.** `feat(browser): DockSurface snap-dock core (state machine + geometry + self-test)`.

---

## Task 2: TabStrip model + layout

**Files:** Create `kernel/apps/browser/tab_strip.{h,cpp}`, `tab_strip_selftest.cpp`; modify `boot_bringup.cpp`.

Model: `struct Tab { char url[kUrlCap]; char title[64]; AccentRole accent; i32 scrollY; bool live; }`; `struct TabStrip { Tab tabs[kMaxTabs]; u32 count; u32 active; ... }`. Methods: `AddTab(url)`, `CloseTab(i)` (never below 1 tab; re-home active), `Select(i)`, layout — `TabRect(i, stripRect)` shrink-to-fit (`w = clamp((stripW - newBtnW) / count, kTabMin, kTabMax)`), `NewTabRect`, `CloseRect(i)` (right end of each tab), and `HitTest(stripRect, cx, cy)` → `{TabIndex i | NewTab | CloseOf(i) | None}`.

Self-test (`[tabstrip-selftest]`): add 3 tabs → count/active correct; tab widths shrink as count grows but never below `kTabMin`; `HitTest` over tab 2's center → index 2; over the `+` rect → NewTab; over tab 1's close rect → CloseOf(1); `CloseTab(active)` re-homes active and never drops below 1. **GAP marker:** tabs are url/title/scroll only — the live render context (real multi-tab) is Phase 3; one page is live at a time.

Build, verify `[tabstrip-selftest] PASS`, commit `feat(browser): TabStrip model + layout + self-test`.

---

## Task 3: Omnibox model

**Files:** Create `kernel/apps/browser/omnibox.{h,cpp}` (+ fold the existing `UrlEdit` logic from `browser.cpp` into it); `omnibox_selftest.cpp`; modify `boot_bringup.cpp`.

Model: `struct Omnibox { char text[kUrlCap]; u32 len; bool editing; u32 caret; }`; methods `BeginEdit/EndEdit/InsertChar/Backspace/SetText`, geometry `PillRect(toolbarRect)` (flex between nav buttons and the Ask button), `AskButtonRect(toolbarRect)`, `LibraryButtonRect`, `MenuRect`, and `HitTest`. Self-test: edit transitions (begin → insert "abc" → caret/len; backspace), and that `AskButtonRect`/`PillRect` don't overlap. Build, verify PASS, commit.

---

## Task 4: Tokens + ✦ spark glyph

**Files:** Create `kernel/apps/browser/tokens.h` (radii: `kRadPill=13,kRadTab=7,kRadPanel=10,kRadBtn=6`; shadow tiers: `kShadowChrome=8,kShadowCard=10,kShadowFloat=16`; accent helpers `AccentTeal=0x2DD4BF`, `AccentAmber=0xE0A33A`, `AccentDanger=0xE0564A`), `spark.cpp` (`void DrawSpark(u32 cx, u32 cy, u32 r, u32 rgb)` — a 4-point star via `FramebufferFillCircle` center + four `FramebufferStrokeArc`/`DrawLine` rays), and a tiny `SparkSelfTest()` that asserts `DrawSpark` writes only within `[cx-r,cx+r]×[cy-r,cy+r]` of an off-screen test surface (bounds check). Build, verify PASS, commit.

---

## Task 5: StartPage (new-tab) model + render

**Files:** Create `kernel/apps/browser/start_page.{h,cpp}`, `start_page_selftest.cpp`; modify `boot_bringup.cpp`.

Model: `struct StartTile { char label[24]; char url[kUrlCap]; u32 accent; }`; `struct StartPage { StartTile tiles[kMaxTiles]; u32 tileCount; }` (default tiles: Home/Docs/GitHub/Wiki/Pin); layout `WordmarkRect`, `PromptRect` (centered, 62% width), `TileRect(i, content)` (centered row, `kTileW=58` + gap), `HitTest` → `{Prompt | Tile(i) | None}`. Render via round-rects + gradient bg (vertical-linear approximation of the radial glow) + `DrawSpark`. Self-test: tile-row centering math + `HitTest` over tile 2 and the prompt. Build, verify PASS, commit.

---

## Task 6: Chrome integration (wire the shell into browser.cpp DrawFn)

**Files:** Modify `kernel/apps/browser.cpp` (the big one) + `browser.h`.

This composes the tested modules into the live chrome. Sub-steps (commit each):
1. Add a top **tab strip** band (height 30) above the toolbar; render via `TabStrip` + tokens (active-tab teal top-accent, hover-close). Route press/move to `TabStrip::HitTest` (select / new-tab / close). Account for the strip in the content-rect math (the toolbar/omnibox shift down by 30).
2. Replace the 7-button toolbar + url label + status row + footer with the new toolbar: nav buttons → `Omnibox` pill → ✦ Ask button → ▤ Library button → ⋮ menu. **Retire** the footer hint band + status row (status → a transient toast; hints → `?` menu item).
3. Instantiate two `DockSurface`s (`g_assistant`, `g_library`) with placeholder panel content (Assistant: a stub "Ask anything…" card; Library: tabbed History/Bookmarks/Downloads reusing the existing history/bookmark lists). Render them via `SurfaceRect`; reflow the web content into `ContentRect` (intersect both surfaces' content rects). Wire the ✦/▤ toolbar buttons + shortcuts to `Summon`/`Dismiss`, and header-drag to `DragBegin/Update/End` with the ghost preview painted on `hoverEdge`.
4. New-tab → render `StartPage` into the content area instead of a fetched page.

Each sub-step: build via `wsl-build`, headless boot (no PANIC/FAIL; existing `[browser-selftest]`/`[browser-click-selftest]` still PASS), commit, push. Behavioral regressions (per CLAUDE.md) are fixed in-place.

---

## Task 7: Docs + recap

Update `wiki/kernel/Web-Engine.md` + `Kernel-Apps.md` (new shell, the four new self-tests, the DockSurface model, retired footer/status). Write a Phase-1 recap to `.remember/`. Commit `docs(browser): Phase 1 shell — wiki + recap`.
