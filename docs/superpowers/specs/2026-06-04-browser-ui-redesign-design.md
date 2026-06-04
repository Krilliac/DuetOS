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
| **Privileged-Origin Mode** | Opt-in, off by default: an exact, TLS-pinned `claude.ai/code` origin can be *armed* for a scoped, audited, instantly-revocable system-access API (`window.duetos.*`). Arming skips the *prompt*, never the kernel cap gates. Full design in **§13**. |

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

The one deliberate exception — **Privileged-Origin Mode (§13)** — is *still* not a bypass of the cap model: it pre-authorises a *scoped subset of the browser app's own caps* for one armed origin without an interactive prompt, and every action still passes the kernel's `kCap*` gates and structural invariants. The armed page can never exceed what the browser app itself could do (§13.1).

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

---

# 13. Privileged-Origin Mode (claude.ai/code System Access)

> **Security-critical.** This section defines an *opt-in* mode in which a single, exact, TLS-verified origin — `https://claude.ai/code` — is granted a scoped, audited, instantly-revocable system-access API, so Claude (running in that web app, loaded in the in-kernel browser) can operate the DuetOS environment directly. It is the browser analogue of `claude --dangerously-skip-permissions`.

## 13.1 Design rationale & trust model

The user **is** the operator. Just as `--dangerously-skip-permissions` lets an operator delegate per-action approval to Claude on a machine they own, Privileged-Origin Mode lets the operator delegate it to the claude.ai/code page they explicitly trust and explicitly armed.

**The load-bearing invariant — what "privileged" does and does not mean:**

> Arming **skips the interactive user prompt**. It does **not** skip the kernel's capability gates, path scoping, input sanitization, or structural invariants. A privileged page is **not** root. It is a *delegate* that may invoke a **pre-authorized, scoped subset of the browser app's own already-held capabilities** without prompting — and **every** invocation still passes through the same cap-gated kernel syscalls (`SYS_FILE_WRITE`/`kCapFsWrite`, `SYS_THREAD_CREATE`/`kCapSpawnThread`, …) that any native DuetOS process uses.

This yields a hard safety ceiling, consistent with the project's [Subsystem-Isolation](../../../wiki/kernel/Subsystem-Isolation.md) rule "the kernel is the authority on every effect": the armed page can never do more than

```
effects ⊆ (browser-app capabilities) ∩ (armed scope) ∩ (kernel structural invariants)
```

The browser app holds bounded caps; the armed scope is a chosen subset; the kernel re-checks each syscall. So even a *fully malicious* armed page cannot escape its scoped roots, cannot `rm -rf /`, and cannot acquire a capability the browser app itself lacks. The mode trades *interactive friction* for *scoped, visible, audited, revocable* delegation — it does not trade away enforcement.

## 13.2 Threat model

| Threat | Mitigation |
|--------|-----------|
| A malicious page **impersonates** claude.ai/code | Exact-origin match + TLS cert verification + **SPKI pin** + **no-redirect** arming (§13.4). |
| A **genuinely compromised** claude.ai/code (or XSS within it) | Scope cap-set (§13.6) + structural invariants (kernel still enforces) + **session-only** lifetime (§13.10) + **kill switch** (§13.9) + audit (§13.8). Blast radius bounded, not eliminated. |
| **Spoofed** armed-state UI (page paints fake "safe" chrome) | Armed indicators are drawn by **kernel-owned browser chrome**, outside the page's pixel surface; the page cannot draw into or remove them (§13.5). |
| **Audit tampering** | `audit.log` is **excluded** from the fs capability scope (the API cannot read or write it); append-only; mirrored to klog. |
| **Privilege persistence** beyond intent | Per-tab, per-navigation; dropped on reload/close (§13.10). |
| **Confused-deputy** (page tricks broker into out-of-scope action) | Broker canonicalises + re-scopes every path/arg *before* the syscall; kernel re-checks independently (§13.7, §13.8). |

**Explicit non-goal:** protecting the operator from a claude.ai they *chose* to arm and that is *wholly* adversarial — that is the same trust the operator extends with `--dangerously-skip-permissions`. The architecture **bounds** that trust (scope, visibility, audit, instant revocation, structural invariants); it does not pretend to eliminate it.

## 13.3 Activation & gating (defense in depth)

Two independent gates, both required; **off by default**:

1. **Feature availability — kernel boot flag** `--allow-claude-system-access` (kernel cmdline). Absent ⇒ the feature does not exist: no `window.duetos` binding is ever installed, the arm UI is hidden, the boot log records `priv-origin: disabled`. This is the machine-owner's master switch (analogous to granting a boot-time capability).
2. **Per-tab arming — explicit user action with reconfirm.** Even when available, the mode is inert until the user, on a tab currently showing the exact privileged origin, arms it via a setting/affordance that triggers a **reconfirm dialog**:
   > ⚠ **Arm privileged system access for `https://claude.ai/code`?** This page will be able to read/write files in *<scoped roots>*, spawn processes, and read kernel state **without asking each time**. It is audited and you can disarm instantly (Ctrl+Shift+Esc). **[Cancel]  [Arm for this tab only]**
   The dialog shows the exact origin, the cap scope being granted, and the disarm shortcut. Arming `kernel.installHandler` (§13.6) requires a *second*, separate confirm.

## 13.4 Origin match & transport binding

Arming and the API are bound to a **privileged-origin predicate** that must hold *continuously* for the live navigation:

- `scheme == "https"` (never http).
- `host == "claude.ai"` **exact** — no subdomains (`*.claude.ai` is **not** a match), no IP literals, no punycode/homoglyph variants (host compared post-IDNA, ASCII-folded).
- `path` begins with `/code`.
- TLS chain verified by the existing `x509_verify` path **and** the server-leaf **SPKI is pinned** to claude.ai's known key (pin set shipped with the build; pin mismatch ⇒ fail closed, never arm).
- **No-redirect:** the privileged navigation must be a **direct** load of the exact URL. If the URL was reached via *any* redirect (3xx) or client-side `location` change, the tab is treated as untrusted and cannot arm — and an *already-armed* tab **auto-disarms** the instant a navigation leaves the predicate (different host/path/scheme, or a redirect is observed).

The predicate is evaluated by the **browser chrome** (kernel-owned), not the page.

## 13.5 Visible armed state (unspoofable)

While a tab is armed, the chrome makes it impossible to be unaware. All indicators are painted by **kernel-owned chrome at a z-order above the page content** — the page has no pixel access to them and cannot remove, cover, or fake them:

- **Omnibox tinted crimson** (`#C0392B` fill / red border) replacing the normal dark pill — the single most legible "this is not normal" cue.
- **Lock → red shield** glyph variant in the omnibox (distinct from the green padlock and the normal teal `✦`).
- **Persistent warning ribbon** directly under the toolbar, full width, crimson:
  `⚠ PRIVILEGED SYSTEM ACCESS ARMED — claude.ai/code can modify your system   ·   [ Disarm ⎋ ]`
  It cannot be dismissed while armed (only Disarm clears it).
- **Tab accent → red** in the strip (overriding the teal/amber identity accent), so the armed tab is obvious even when inactive.
- **Red hairline frame** around the content viewport, so the danger zone is visually bounded.

These are deliberately louder than any normal state. The contrast with the everyday teal accent is the whole point: privileged ≠ ordinary.

## 13.6 Capability scope

Each `window.duetos.*` namespace maps to an existing kernel cap gate and a structural constraint. The **default arm** grants the everyday set; `kernel.installHandler` is withheld and requires a second explicit confirm.

| Namespace | Kernel gate | Structural constraint | Default arm |
|-----------|-------------|-----------------------|:----------:|
| `fs.read` / `list` / `stat` | `kCapFsRead` | within **scoped roots** only; paths canonicalised, `..`-escape refused | ✅ |
| `fs.write` / `mkdir` / `remove` | `kCapFsWrite` | within scoped roots; `remove` never targets a root / `/` / device node; size bounds | ✅ |
| `proc.spawn` / `list` / `signal` | `kCapSpawnThread` (+ proc) | spawn only from allowed exec roots; `signal` only PIDs this session spawned | ✅ |
| `kernel.read` | read-only diag cap | introspection only (symbols, syscall scan, stats) — no mutation | ✅ |
| `kernel.installHandler` / ABI modify | highest `kCap*` | **separate second confirm**; off in default arm | ❌ |
| `net.fetch` / `connect` | `kCapNet` | the same net stack + policy as a page fetch | ✅ |
| *audit* | — | **not exposed** — the API can neither read nor write `audit.log` | 🚫 never |

**Scoped roots** are configured by the boot flag / setting (default e.g. a project root + the user home directory). They **never** include `/`, kernel/device nodes, or `audit.log`. Every fs call is contained to them at *both* the broker and the kernel.

## 13.7 API surface — `window.duetos.*` (chosen, with rationale)

**Decision:** a conditionally-installed **`window.duetos.*` host object**, synchronous, returning structured result records.

**Why this over the alternatives:**
- The in-kernel JS engine already installs host objects (`window`/`document` via `js_dom.cpp`). `window.duetos` is the **idiomatic, lowest-surface** extension — same binding path, just installed *only* on an armed tab's context and torn down on disarm.
- **postMessage → privileged worker** presumes Web Workers, which the tree-walking interpreter does not have — a large new runtime surface for no benefit. Rejected.
- **`duetos://` protocol** forces navigation/fetch semantics, is clumsy for a rich call/return API, and makes structured results + scoping awkward. Rejected as the primary surface (could back specific one-shot actions later).
- Calls are **synchronous** and return `{ok, …}` records (the interpreter is synchronous; it has no Promises). Each call is marshalled to the broker → cap-gated syscall → audited, then the record returns.

**Request flow (every call):**
1. Page calls e.g. `window.duetos.fs.writeFile(path, data)`.
2. Host binding marshals a `PrivilegedRequest{cap:"fs.write", args}` to the **broker** (browser app).
3. Broker re-checks: tab still armed? predicate (§13.4) still holds? cap in armed scope? → then **canonicalises** the path, enforces scoped-root containment + bounds + sanitisation.
4. Broker invokes the **cap-gated syscall** (`SYS_FILE_WRITE` / `kCapFsWrite`). The kernel **independently** re-checks the cap and structural invariants.
5. An **audit entry is written (success *or* fail)** before the result record returns to the page.

**Code example (page-side JS):**

```js
// `window.duetos` exists ONLY while this tab is armed for https://claude.ai/code.
if (window.duetos && window.duetos.armed) {
  window.duetos.origin;  // "https://claude.ai/code"
  window.duetos.scope;   // ["fs.read","fs.write","proc.spawn","kernel.read","net"]

  const r = window.duetos.fs.readFile("/home/user/project/notes.md");
  if (r.ok) {
    const w = window.duetos.fs.writeFile(
      "/home/user/project/notes.md", r.text + "\n## edited by Claude\n");
    if (!w.ok) console.error(w.error);   // structured failure, e.g. below
  }

  // Structural invariants refuse these regardless of arming:
  window.duetos.fs.writeFile("/etc/shadow", "x"); // {ok:false, error:"EPERM: outside scoped roots"}
  window.duetos.fs.remove("/");                   // {ok:false, error:"EINVAL: refused (structural invariant)"}

  // Cap-gated + audited process spawn:
  const p = window.duetos.proc.spawn("/bin/duet-build", ["--release"]); // {ok:true, pid:...}

  // Withheld under default arm:
  window.duetos.kernel.installHandler;            // undefined (needs the 2nd grant)
}
```

Every one of those calls appends a structured `audit.log` entry (§13.8).

## 13.8 Enforcement & audit logging

**Hardening still applies (the non-negotiable):** arming bypasses the *prompt*, nothing else. Both the broker **and** the kernel, on every call:
- **Canonicalise** paths (resolve `.`/`..` and symlinks; reject any escape) and **contain** within the scoped roots.
- **Bounds-check** every size/count/handle; **sanitise** all inputs (no embedded NULs, length caps, type checks).
- **Enforce structural invariants** that hold even with full caps: no `remove`/`write` of a scoped-root itself, `/`, device nodes, or kernel/proc pseudo-paths; spawn only from allowed exec roots; the kernel's `kCap*` gate is the **final** authority and the broker is belt-and-suspenders, never a replacement.

**Audit:** every privileged action appends one structured line to `audit.log` (same pattern as the DCC bot's audit trail):

```
{ "ts": "2026-06-04T18:22:07Z", "origin": "https://claude.ai/code", "tab": 3,
  "cap": "fs.write", "args": {"path":"/home/user/project/notes.md","bytes":412},
  "result": "ok", "ok": true }
```

`args` is bounded/redacted (no full payloads — sizes and paths, not contents). The log is **append-only**, **excluded from the fs scope** (the API cannot read or truncate it), and **mirrored to klog** (`KLOG_INFO` on success, `KLOG_WARN` + a `KBP_PROBE` on any failure/denial). A denied call is *as* important to log as an allowed one.

## 13.9 Kill switch

Instant, page-independent revocation:
- **Shortcut** `Ctrl+Shift+Esc` (proposed; confirm against the kernel shortcut map at implementation — fall back to `Ctrl+Shift+K` if reserved) **and** the red **[ Disarm ⎋ ]** button in the warning ribbon.
- On trigger: revoke the armed scope, **tear down `window.duetos`** on the tab's JS context, write a final `disarmed` audit entry, and **reload the page in sandboxed (unprivileged) mode**.
- Handled by **chrome / input routing, not the page's JS thread**, so it works even if the page is busy, looping, or hostile (it cannot trap or swallow the kill switch). This is the operator's always-available off-ramp.

## 13.10 Lifetime model — per-tab, per-navigation (recommended)

Privilege is bound to **(tab, navigation-instance)** and **does not survive**:
- a **page reload** (even to the identical URL),
- a **navigation** that leaves the §13.4 predicate (auto-disarm), or
- **tab close**.

Re-establishing privilege always requires the explicit arm dialog (§13.3) again. Rationale: this minimises the live-privilege window and prevents a stale armed tab from being repurposed by a later load — the smallest practical blast radius. **v1 has no persistent/always-armed mode**, even with the boot flag set; a future per-origin persistent grant would need its own threat review.

## 13.11 Non-goals / out of scope (v1)

Persistent or always-armed grants; more than the one privileged origin (only `claude.ai/code`); arming a non-foreground tab; the page reading/altering `audit.log`; sandbox-escape hardening beyond the kernel's existing invariants. Each is a later, separately-reviewed slice.

## 13.12 Implementation placement

Privileged-Origin Mode depends on the **shell** (§4, the armed-state chrome) and on the **JS host-binding mechanism** (`js_dom.cpp`), but is **independent of the AI intelligence source** (§10 Phase 2) — it ships as its own security-reviewed slice once the shell lands. It is gated behind `--allow-claude-system-access` so it can land dark (compiled, off, no binding installed) and be enabled deliberately. The reviewable signal from [Subsystem-Isolation](../../../wiki/kernel/Subsystem-Isolation.md) applies directly: *"could the armed page do something the browser app's own caps could not?"* — by construction (§13.1), **no**.
