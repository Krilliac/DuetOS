# DuetOS Browser — UI/UX Redesign (Design Spec)

**Date:** 2026-06-04
**Status:** Design approved (visual shell). AI functionality + multi-tab engine are follow-on specs.
**Scope of this spec:** the **visual + interaction shell** of the in-kernel browser (`kernel/apps/browser.cpp`). It does *not* implement AI intelligence or the multi-tab render engine — both are designed-for here and specced separately (see §10).

## 1. Vision

Redesign the in-kernel browser as a blend of three references:

- **Chrome** — clean tab strip, omnibox, fast/familiar, tight typography.
- **Perplexity Comet** — AI-native: an assistant surface, ask-anywhere, citation-first answers.
- **DuetOS itself** — kernel-owned rendering with the existing retro-modern "Duet" visual language (dual-accent identity, soft-shadow tactility, rounded chrome), so it reads as *part of the OS*, not a Chrome clone.

The defining idea that fell out of brainstorming: **one movable "dock surface" abstraction** powers both the AI assistant and the Library (history/bookmarks/downloads). Each is a floating card by default that the user can Aero-snap to any window edge to dock. This is the spine; everything else hangs off it.

## 2. Locked decisions

| Area | Decision |
|------|----------|
| **Assistant placement** | **Floating by default**, with **Aero-snap docking** (drag to L/R edge → side panel; top → bar; bottom → drawer). Dismissible + recallable via toolbar button **and** keyboard shortcut. |
| **Dockable surfaces** | **Assistant** and **Library** are two instances of one `DockSurface` (shared float/snap/dock mechanism). |
| **Omnibox** | **Unified bar** (URL + web search) + a teal **✦ Ask AI** button + shortcut. URL muscle-memory untouched; AI lives in the floating assistant. |
| **Default theme** | **Dark · Duet** (DuetLight ships, switchable in Settings). |
| **Library** | Unified **tabbed** panel (History / Bookmarks / Downloads) opened by a toolbar **▤** button, rendered in a `DockSurface`. |
| **New-tab page** | **DuetOS start page**: wordmark, centered Ask/URL prompt, dual-accent shortcut tiles, "continue where you left off" strip. |
| **Tabs** | **Real multi-tab** (each tab a live render context) — engine work deferred to the multi-tab spec (§10), but the strip is designed here. |
| **AI intelligence source** | **Deferred.** Shell designed with realistic placeholder content; the two real options are documented in §10 for the follow-on spec. |

## 3. The DockSurface model (core)

A `DockSurface` is a movable, dismissible chrome surface that renders arbitrary panel content. Two instances exist: **Assistant** (`✦`) and **Library** (`▤`).

**State:** `Hidden | Floating(x, y, w, h) | Docked(edge, size)` where `edge ∈ {Left, Right, Top, Bottom}`.

**Interaction:**
- **Summon/dismiss:** toolbar button (`✦` Assistant, `▤` Library) or shortcut (proposed `Ctrl+J` Assistant, `Ctrl+Y` Library). Dismiss = `Hidden`; re-summon restores the last `Floating`/`Docked` state.
- **Drag:** grab the surface's header. While dragging, when the cursor enters an **edge gutter** (~24 px from a window edge), paint a **ghost preview** of that dock region (teal dashed, per the mockup). Release in the gutter → `Docked(edge, size)`; release elsewhere → `Floating`.
- **Docked layout:** a docked surface **reflows the content area** (the web page lays out into the remaining rect). Side docks take ~30–40% width; bottom ~30% height; top a slim bar. A **floating** surface **overlays** content (no reflow).
- **Undock:** drag a docked surface off its edge → returns to `Floating`.
- **Two surfaces, two edges:** Assistant and Library may dock to *different* edges simultaneously (e.g. Library left + Assistant right). **GAP (v1):** two surfaces to the *same* edge — v1 has the newcomer bump the incumbent back to `Floating` rather than splitting/tabbing the edge; revisit if needed.

**Why this matters for the kernel:** it's one widget abstraction reused twice, sized off the client rect, mutating only its own state — no kernel coupling. Docking just recomputes the content rect handed to the web-engine layout (which already re-lays-out on demand via `RelayoutFromDoc`, landed 2026-06-04).

## 4. Shell anatomy

Top-to-bottom inside the WM-managed window (title bar is WM chrome):

1. **Tab strip** (~30 px). Chrome-style. Active tab is *connected* to the toolbar (no bottom border, shares toolbar bg `#1a212a`, carries a **2 px teal top-accent**, sits 2 px taller). Inactive tabs `#11161d`, muted text, 1 px border. Each tab: a favicon chip (accent-tinted — teal=native, amber=docs — until real favicon fetch exists; **GAP: favicon fetch**), title (Body), and a `✕` close on hover. New-tab `+` at the strip end. Width min ~120 / max ~150 px, shrink-to-fit; **GAP: overflow scroll** when tabs exceed strip width (v1 shrinks to min then clips).
2. **Toolbar** (~38 px, bg `#1a212a`). `◁ ▷ ⟳` nav buttons → **unified omnibox pill** (flex, lock glyph + URL/search + trailing `✦`) → **✦ Ask AI** button (teal-tint pill) → **▤** Library button → **⋮** overflow menu.
3. **Content area** — the web page, rendered by the existing engine into the rect left over after any docked surface. Light pages on dark chrome is the expected contrast.
4. **Floating surfaces** overlay the content (Assistant bottom-right by default); docked surfaces flank it.
5. **New-tab** replaces the content area with the **DuetOS start page** (§ tokens apply).

The legacy footer hint band and status row are **retired** into: status → a transient toast / the omnibox affordance; hints → discoverable UI (the footer's keyboard-cheatsheet moves to a `?` overflow item).

## 5. Design system — "the DuetOS touch"

Extends the existing Duet theme language (does **not** invent a parallel one).

**Accents (dual identity):**
- **Teal `#2DD4BF`** — interactive, AI, native content, focus, primary CTA.
- **Amber `#E0A33A`** — *secondary identity only* (doc-style content: docs tabs, bookmarks). **Never a CTA** — it must not compete with teal for "click me."

**Neutrals (dark):** canvas `#0B0E13`; panels `#11161d` / `#1a212a` / `#2A323C`; borders `#1b222b` / `#2b3440`; text tiers `#c2ccd6` (primary) / `#9aa6b2` (secondary) / `#6b7682` (muted).

**Corner radii (via `FramebufferFillRoundRect`):** pills **13** (omnibox, Ask AI, citation chips) · tabs **7** (top corners) · panels/cards **10** · start-page tiles **13** · buttons **6** · window **10**.

**Shadow tiers (9-slice soft-shadow atlas):**
- Chrome (tab strip / toolbar): radius **8**, low opacity (`shadow_intensity_inactive`).
- Cards / tiles: radius **10**.
- **Floating DockSurface:** radius **16** at `shadow_intensity_active` (255 dark) — reads as elevated. **Docked** surface: flatter (radius 8, no drop shadow; a 1 px teal edge line toward content instead).
- **Focus:** teal 1 px inner stroke + soft glow (`focus_glow_colour`, existing tactility) on omnibox focus, focused tab, assistant input.
- **Hover-lift / press-depress:** keep the existing bitwise lighten/darken + tactility alpha (`hover_lift_alpha` / `press_alpha`).

**The `✦` spark** — the single AI signifier, used on the Ask AI button, assistant header, omnibox trailing, and citation chips. The bitmap/TTF fonts have no such glyph: **new asset**, drawn with painter primitives (a 4-point star via `FramebufferFillCircle` center + `FramebufferDrawLine`/`StrokeArc` rays) at 2–3 sizes. **GAP: spark glyph asset.**

## 6. Typography (reuse Pass-C TTF roles)

- **Title (16 px TTF)** — window title, panel/DockSurface headers, start-page wordmark.
- **Body (13 px TTF)** — tab labels, omnibox text, button labels, list rows.
- **Caption (11 px TTF)** — citations, toasts, secondary metadata.
- **Display (72 px)** is reserved for hero numerals elsewhere; **not** used here (too large) — the wordmark uses Title-bold.
- TTF (Liberation Sans Regular/Bold) when the theme opts in (`font_kind == Ttf`, true for the Duet family); bitmap fallback otherwise. All chrome text routes through `ChromeTextDraw`/`ChromeTextMeasure`.

## 7. Motion (reuse Pass-B `motion_intensity`)

Subtle, and gated by `motion_intensity` (0 = instant): assistant **summon** (fade + 6 px rise), **snap-dock** transition (surface animates to the edge as the ghost resolves), **tab** open/close (width grow/shrink), **dock reflow** (content rect eases). Nothing decorative or looping.

## 8. Code-reuse map (grounded in the current tree)

**Reused as-is:**
- Theme system — `ThemeRole::Browser` (role 11), Duet/DuetLight palettes, the tactility fields (`shadow_intensity_*`, `hover_lift_alpha`, `press_alpha`, `focus_glow_colour`, `motion_intensity`), `ThemeCurrent()`/`ThemeTactilityEffective()`/`ThemeIntensityEffective()`.
- Widget toolkit — `AppButton`, `AppLabel`, `AppToolbar`, `WidgetGroup`, the `Widget<Self>` CRTP + `Hover/Pressed/Focused/Disabled` states + first-Consumed-wins event dispatch.
- Typography — `chrome_text` roles/APIs.
- Painter — `FramebufferFillRoundRect`, `FramebufferFillRectGradient` (vertical only), `FramebufferBlendFill`/`BlendRgba`, the soft-shadow atlas (`RenderSoftShadow[WithStroke]`), arcs/circles/lines.
- Web engine — the content area is the existing pipeline; the **layout-arena split + `RelayoutFromDoc()`** (landed 2026-06-04) already lets the content re-lay-out into an arbitrary rect, which docking needs.

**New components (this spec):**
- `TabStrip` widget — model: `Tab{ url, title, favicon_accent, scroll, render_ctx* }`; active-tab routing; new-tab/close affordances.
- `DockSurface` — the float/snap/dock abstraction (§3), instantiated for Assistant + Library; owns drag, gutter hit-testing, ghost preview, and the content-rect handoff.
- `Omnibox` widget — unified URL/search field + focus state + `✦` trailing; the **✦ Ask AI** button just focuses the Assistant surface.
- `StartPage` renderer — wordmark, prompt, tiles (top-sites model), continue strip.
- `✦` spark glyph asset.

**Painter constraints to respect (from the capability map):** gradients are **vertical-linear only** — the start-page "glow" is a top-tinted vertical gradient, not radial; no anti-aliased corners (round-rect is pixel-stepped); all CPU-drawn; the window redraws chrome each compose (no per-widget dirty tracking) — keep per-frame chrome cost modest (the snap ghost and shadows are the only heavy blends).

## 9. Architecture-isolation note

This is a **native kernel app** (`kernel/apps/`), not a subsystem facade — no isolation-rule surface. All network/file effects (favicon fetch, downloads, future AI requests) must continue to route through the existing cap-gated paths (`net::*`, `fs::fat32::*`), exactly as the current browser does. A docked AI panel issuing a network request later (§10) goes through the same `net` stack as a page fetch — no new privileged path.

## 10. Phasing & follow-on specs

**Phase 1 — Shell (this spec).** Tab strip, unified omnibox + Ask button, the `DockSurface` mechanism, Library panel, start page, the token/motif system, dark default. Placeholder assistant content. *Fully buildable without any AI or multi-tab-engine work* (one live tab; switching re-fetches).

**Phase 2 — AI assistant functionality (follow-on spec).** The deferred decision, with the two real options documented:
- **(a) External LLM over TLS** — the assistant POSTs the query (and optionally extracted page text) to an external LLM API over the existing net stack + `tls_socket`, streaming the answer + citations. Needs: an in-kernel JSON + SSE/stream client, an API-key store, and a **privacy gate** (page text leaves the box — must be explicit/opt-in per request). Most true to Comet.
- **(b) Local heuristic assistant** — no LLM: page-summarize (headings + lead sentences via the existing DOM), in-page find, search-result aggregation, "ask the page" through the in-kernel JS/DOM. Fully offline, no key, modest intelligence.
- These can coexist: (b) as the offline default, (a) when a key is configured.

**Phase 3 — Real multi-tab engine (follow-on spec).** Each tab a live render context. Needs an **arena-pool / cap design**: at ~1 MiB render-arena + ~1 MiB layout-arena + image arena per live page, N tabs = N×budget. Likely a small pool of live contexts (e.g. cap K) with LRU eviction to "url+title+scroll, re-fetch on focus" beyond K — i.e. the cheap "tab strip, one-ish live page" model is the graceful-degradation floor.

## 11. Out of scope

Favicon fetch/cache; tab overflow scrolling; same-edge surface splitting; real downloads-manager beyond the current Content-Disposition saves; sync/profiles; extensions. Each is a `// GAP:` or a later slice, noted above where relevant.

## 12. Open questions (non-blocking — defaults chosen)

- Shortcut bindings (`Ctrl+J`/`Ctrl+Y` proposed) — confirm against existing kernel shortcut map at implementation time.
- Exact dock size ratios (30–40% / 30%) — tune live.
- Whether the start-page tiles are user-pinned, most-visited-derived, or both (default: both — pinned + MRU fill).
