# In-Kernel Web Engine

> **Audience:** Kernel hackers, browser/UI hackers, security reviewers
>
> **Execution context:** Kernel — runs in the calling thread's context
> (the browser app thread / its fetch worker). All parsing, styling,
> scripting, layout and paint happen over bump arenas; no global mutable
> state.
>
> **Maturity:** v0 — every stage is boot self-tested. Renders a useful
> subset of real HTML/CSS; the JS engine runs ES5-ish scripts. Many
> CSS/HTML/JS features are deliberately out of scope (see **Known
> limits**).

## Overview

DuetOS ships a from-scratch web rendering engine in
[`kernel/web/`](../../kernel/web/), driven by the
[`browser`](../../kernel/apps/browser.cpp) in-kernel app. It is **not** a
port of any existing engine — HTML parsing, the CSS cascade, a DOM, a
tree-walking JavaScript interpreter, block+inline layout, a paint /
display-list pass, and PNG/JPEG decoders are all native.

The pipeline for one page:

```
HTTP(S) fetch  ->  ParseHtml      ->  ComputeStyles   ->  run <script>s
(net/http,         (web/html.cpp,     (web/css*.cpp,      (web/js/* via
 tls_socket)        -> DOM tree)       cascade -> styles)  web/js_dom.cpp)
                                                              |
   framebuffer  <-  paint  <-  LayoutDocument  <-------------+
   (web/paint)      (display    (web/layout*.cpp: block +
                     list)       inline boxes -> DisplayList)
```

The fetch/transport half (DNS, TCP, TLS, HTTP redirects, cookies, the
test trust store) lives in the browser app; the engine proper is
fetch-agnostic — `LayoutDocument` consumes a styled DOM and emits a
device-pixel `DisplayList` that the painter rasterises into an off-screen
RGBA canvas, then blits to the window.

## Components

| Area | Files | What's REAL |
|------|-------|-------------|
| HTML | `html.cpp`, `entities.cpp`, `dom.{h,cpp}` | Tokeniser + tree builder, void elements, comments, named/numeric entities, `<p>`/`<li>` recovery. Fragment parse (`ParseHtmlFragment`) backs `innerHTML`. |
| CSS | `css*.cpp` (`parse`, `apply`, `values`, `ua`) | Selector parse, specificity cascade, inheritance, the UA sheet, `display:none`, the common box/text/colour properties. **Structural pseudo-classes** — `:first-child`/`:last-child`/`:nth-child(an+b\|even\|odd)`, the **of-type family** (`:first-of-type`/`:last-of-type`/`:nth-of-type`/`:only-of-type`), the **from-end variants** (`:nth-last-child`/`:nth-last-of-type`), and `:only-child` — **attribute selectors** (`[attr]`, `[attr=]`, `~=`/`^=`/`$=`/`*=`), the **`>`/`+`/`~` combinators**, and **`:not(simple)`**. |
| DOM bindings | `js_dom.cpp` | `document`/element host objects: `getElementById`, `getElementsByTagName`/`ClassName`, `querySelector`/`querySelectorAll` (single-compound), `classList` (`add`/`remove`/`contains`/`toggle`), a **programmatic event model** (`addEventListener`/`removeEventListener`/`dispatchEvent`/`click()` with capture-phase + bubbling, the `capture`/`once` options, and `stopPropagation`/`preventDefault`), `children`, `tagName`, `id`/`className`/`textContent` get+set, and `innerHTML` get **and set** (parse-and-replace). |
| JavaScript | `js/*` | Lexer → Pratt parser → tree-walking interp. Closures, `for`/`while`, recursion, objects/arrays, **`++`/`--` (prefix + postfix)**, **`try`/`catch`/`finally`/`throw`**, **prototype chain** (`Object.prototype`), **template literals**, object-to-primitive coercion, `JSON.parse`/`stringify`, **a bounded RegExp engine** (`regexp*.cpp` — bytecode + explicit backtrack stack, step-budget-bounded so a hostile pattern can't smash the kernel stack or hang), `new` (native ctors). Built-ins: `Array` (`map`/`filter`/`forEach`/`slice`/`join`/…), `String` (incl. regex `match`/`replace`/`split`/`search`), `Number` (`toFixed`, `toString(radix)`), `Math` (incl. `random`/`sin`/`cos`/`tan`/`log`/`exp`/`sqrt`/`pow`), **`Date`** (`new Date()`/`(ms)`, `Date.now`, UTC getters, `toISOString`), `Object.keys`, `parseInt(radix)`/`parseFloat`/`isNaN`/`isFinite`. Step budget + native-stack guard bound a hostile script. |
| Layout | `layout*.cpp`, `display_list.h` | Block formatting (vertical stacking, margin/border/padding box, width/height), inline formatting (line boxes, word wrap, text-align), `<img>` boxes, **anonymous-block wrapping**, the **block-in-inline split**, and **vertical margin collapsing** (adjacent-sibling + parent-child + empty-block). |
| Paint | `paint.cpp` | Fills, glyph runs, borders, image blits, clip rects, scroll offset → framebuffer. |
| Images | `png.cpp`, `jpeg.cpp` | PNG: greyscale/palette/truecolour ±alpha, bit depths **1/2/4/8/16**, **Adam7 interlacing**, tRNS. JPEG: baseline + progressive, 4:2:0 / 4:2:2 / greyscale. Both reject corrupt/truncated input. |

## Native-stack safety (important)

The JavaScript interpreter recurses on the **C++ kernel stack** — each JS
call level costs several native frames (measured ~15 KiB per level in the
debug build, with its no-inline + sanitizer-padded frames). The kernel's
arena stack is only **64 KiB usable** (16 pages + 1 guard page, see
[`kernel/mm/kstack.h`](../../kernel/mm/kstack.h)), so the logical
`maxCallDepth` cap **cannot** keep recursion from smashing the stack: a
deep `function rec(){ return rec(); }` would guard-fault long before the
count cap fires.

`CallFunction` ([`js/interp.cpp`](../../kernel/web/js/interp.cpp))
therefore carries a **native-stack guard**: when the current thread runs
on a kstack-arena slot, it returns `ErrorCode::Overflow` once the frame
descends within `kJsStackGuardMargin` of the slot's guard page. This is
build-independent (it measures bytes consumed via
`__builtin_frame_address`, not a frame count) and protects the real
threads that ever run untrusted script — notably the browser's fetch
worker. Boot-context threads (e.g. the self-test on the kernel's large
non-arena boot stack) are bounded by the logical `maxDepth` instead.

The practical consequence: **effective JS recursion depth is shallow in
the debug build (a few levels) and deeper in release** (smaller frames).
Lifting it would mean a heap-allocated interpreter stack or shrinking the
per-level native frame.

The **parser** recurses on the same native stack (the Pratt expression
chain *and* the statement-brace chain `ParseStatement`→`ParseBlock`,
whose frame carries a 2 KiB `tmp[256]`). Because per-level byte cost
differs ~10× between those paths, a single logical-depth cap can't be
both safe and non-rejecting — so `ParsePrimary` and `ParseStatement`
([`js/parser.cpp`](../../kernel/web/js/parser.cpp)) carry the **same
`__builtin_frame_address` guard** as `CallFunction`, bailing with a
graceful parse error (`p.Fail`, not a panic) near the guard page; a
coarse `kMaxParseDepth` backstop covers boot-context (non-arena) stacks.
This stops untrusted `(((…)))` / `{{{…}}}` from guard-faulting the
kernel. (Security audit SEC-007, CWE-674, 2026-06-07.)

## Self-tests

Every stage boots a self-test, registered in
[`kernel/core/boot_bringup.cpp`](../../kernel/core/boot_bringup.cpp) via
`DUETOS_BOOT_SELFTEST`. A clean boot prints one `PASS` line each:

- `[png-selftest]` — rgba, rgb-paeth, palette+tRNS, gray±alpha, gray4
  (sub-byte), gray16 (16-bit), adam7 (interlaced) + corrupt/truncated
  rejection.
- `[jpeg-selftest]` — 4:2:0 / 4:2:2 / gray, progressive, garbage
  rejection.
- `[html-dom-selftest]` — nesting, void elements, entities, `<p>`/`<li>`
  recovery, comments, doc text.
- `[js-selftest]` — 102 snippets: precedence, closures, recursion, loops,
  `++`/`--` (prefix + postfix, ident/member/index lvalues),
  `try`/`catch`/`finally`/`throw` (caught/uncaught/re-throw/finally-order,
  plus the guard case proving a runaway loop in `try` is **not** caught),
  string methods, JSON round-trip, template literals, object coercion,
  plus runaway-loop / depth-cap / syntax-error error paths.
- `[css-selftest]` — cascade, specificity, inline, inheritance, UA,
  `display:none`, colour, the structural pseudo-class families (incl. the
  `:nth-child` vs `:nth-of-type` divergence on mixed-tag siblings).
- `[js-dom-selftest]` — DOM queries and the `innerHTML` get/set round
  trip (14 checks).
- `[layout-selftest]` — bg rect, bold heading, wrap, stacked-y,
  `display:none`, center-align, anon-block-wrap.
- `[paint-selftest]` — fill, glyph pixels, borders, image blit, clip,
  scroll offset.
- `[browser-selftest]` — URL parse, HTTPS routing, cookies, redirect
  (loopback transport).
- `[dock-selftest]` / `[tabstrip-selftest]` / `[omnibox-selftest]` /
  `[startpage-selftest]` — the shell-redesign models (see below).

## Browser shell (Phase 1 redesign)

The browser app's chrome is a from-scratch redesign (Chrome × Comet ×
DuetOS — see the design spec
`docs/superpowers/specs/2026-06-04-browser-ui-redesign-design.md`). The
shell is built from small, value-semantic, boot-self-tested models under
[`kernel/apps/browser/`](../../kernel/apps/browser/), composed into the
live `DrawFn` / mouse routing in
[`browser.cpp`](../../kernel/apps/browser.cpp):

- **`DockSurface`** (`dock_surface.*`) — one movable surface with a
  Floating default and four Aero-snap dock targets, reused for both the
  **Assistant** (`✦`) and the **Library** (`▤`). State machine
  (`Hidden`/`Floating`/`Docked`) + snap-zone geometry; the toolbar buttons
  toggle them.
- **`TabStrip`** (`tab_strip.*`) — Chrome-style tabs with shrink-fit
  layout, dual-accent favicon chips, and new-tab/close hit-testing. One
  live page at a time (real per-tab render contexts are Phase 3).
- **`Omnibox`** (`omnibox.*`) — the unified URL/search field + the toolbar
  control geometry (nav / pill / Ask / Library / menu).
- **`StartPage`** (`start_page.*`) — the new-tab command-center (wordmark,
  Ask/URL prompt, dual-accent shortcut tiles).
- **`tokens.h`** — the "DuetOS touch" motif set (corner radii, soft-shadow
  tiers, dual-accent palette).

**GAPs (Phase 1):** ASCII glyph fallbacks (no `✦`/`◁`/`▤` glyphs yet); a
docked surface overlays the content instead of reflowing it, and the
drag/snap gesture + ghost preview aren't wired (the `DockSurface` model
supports both); no real multi-tab engine. The assistant dock now has a
live v1 backend (see **Assistant dock backend** below); the remaining
Phase 2 work is the RemoteLlm path + [Privileged-Origin
Mode](Privileged-Origin.md). Pixel layout is verified by VM screenshot, not
the headless self-tests.

## Assistant dock backend

The Assistant dock (`✦`) is no longer a placeholder. The backend
contract is one method —
[`AssistantRespond`](../../kernel/apps/browser/assistant_backend.h)
(`assistant_backend.h:20`), which maps a user message to a reply.
v1 ships a deterministic **LocalHeuristic**
([`assistant_heuristic.cpp`](../../kernel/apps/browser/assistant_heuristic.cpp)):
a small fixed intent set plus a graceful catch-all fallback, with no
external dependency. A reply that begins `navigate:<url>` is an
**intent** the dock host acts on (it performs the navigation); all
other replies are display text. The path is CI-testable —
`AssistantHeuristicSelfTest` (`assistant_heuristic_selftest.cpp`)
runs the intent set at boot.

A `RemoteLlm` direction (POST through the privileged `net.fetch`
executor) exists in the contract but is **inert in v1** — there is
no secret-store for an API key yet, so the heuristic is the only
live path.

## Known limits (greppable `// GAP:`)

- **JS:** the prototype chain is read-only — no `__proto__` /
  `Object.create` / `getPrototypeOf`; `Array`/`String`/`Number` methods
  dispatch through a special-cased path rather than real
  `Array.prototype` objects. `Number.toString(radix)` drops the fraction
  for non-decimal radixes; `toFixed` rounds half-away and carries only
  binary32 precision. No `Symbol.toPrimitive`. `try`/`catch`/`finally`/
  `throw` work, including the ES2019 optional catch binding (`catch {}`
  without `(e)`), and only an explicit `throw` is catchable —
  engine-raised faults real JS would surface as `TypeError`/`RangeError`
  (calling a non-callable, a bad assign target) are not catchable, and the
  step-budget `Timeout` / stack-guard `Overflow` propagate **through**
  `try`/`catch` by design.
  Arithmetic (incl. `++`/`--`, `-`/`*`/`/`) does not numeric-parse
  strings — `'5' - 1` and `'5'++` both yield `NaN` (only `+` coerces, as
  concatenation); numeric lvalues are unaffected. No
  automatic-semicolon-insertion before a postfix `++`/`--` (a newline
  between the operand and the operator does not break the expression).
  The **RegExp** engine is a bounded subset: no lookahead/lookbehind,
  backreferences, or named groups; the `s` (dotAll) flag is supported but
  `u`/`y` are not; ASCII-only; a backtrack/input-overflow safety valve may
  miss a match rather than hang.
  `Math` transcendentals carry soft-float (not double) precision;
  `Math.random` draws kernel entropy. **`Date`** is UTC-only — no setters,
  no date-string parsing (`Date.parse`/`new Date("…")` → Invalid-Date), no
  locale; `new` works only for native ctors (e.g. `Date`).
- **Layout:** no floats, positioning, flexbox/grid, or tables (CSS `float`
  is not yet parsed/laid out — a future slice).
- **CSS:** `:not()` takes a SIMPLE arg only; the of-type / from-end / only
  structural pseudo-classes are now supported, but there is still no
  `:nth-col`/column combinator (`||`) and no dynamic/state pseudo-classes
  (`:hover`/`:focus` parse but never match). Descendant/general-sibling
  steps now backtrack across every candidate (child/adjacent stay
  deterministic), so `a b a c`-shaped selectors resolve; `:has()` and other
  relational pseudo-classes remain unparsed.
- **DOM:** `querySelector`/`All` match a SINGLE compound (tag/`.class`/
  `#id`/`*`) only — they use a self-contained matcher, not the full CSS
  selector engine (whose parse/match entry points are file-private), so
  combinators/attribute/pseudo selectors and selector-lists are
  unsupported there. `getElementsBy*`/`querySelectorAll` return array
  snapshots, not live collections. Event listeners are **programmatic
  only** — `dispatchEvent`/`click()` fire them, but real WM mouse/keyboard
  input is not yet routed to DOM dispatch (the browser app would need a
  retained per-page script context + a click→Node hit-test). Dispatch runs
  a real **capture phase** then bubble, `addEventListener` honours the
  `capture`/`once` options (`once` auto-removes after the first fire), and
  `removeEventListener` matches on `(type, fn, capture)`; `passive` is
  recorded but not enforced (`preventDefault` from a passive listener still
  takes effect).
- **DOM:** `ParseHtmlFragment` seeds the element-specific *initial*
  insertion context (`table`/`tbody`/`thead`/`tfoot`/`tr`/`colgroup`/
  `select`), so `el.innerHTML = '<td>…'` on a `<tr>` parses correctly. It
  does not implement the full insertion-mode state machine (table
  foster-parenting, `<template>` content fragments).
- **Layout:** vertical margin collapsing handles adjacent-sibling +
  parent-child + empty-block, but parent-child re-seating is first-level
  only (a grandchild's larger margin lays out correctly but doesn't hoist
  the ancestor's border box); the block-in-inline split doesn't re-draw
  the inline element's own borders/padding. No floats, positioning,
  flexbox/grid, tables, z-index, overflow clipping; monospace metrics only.
- **PNG:** no APNG, gamma/ICC colour management, or ancillary chunks
  beyond tRNS.
- **TLS trust:** HTTPS verifies the server's full chain against x509's
  embedded **real** roots (incl. ISRG Root X1) — see
  `apps/browser.cpp::BrowserCertVerify`. GAP: no CRL/OCSP revocation, no
  name constraints, and the root set is a curated subset (sites chaining
  to any other root fail closed).

Re-derive the live inventory with `git grep -nE "// (STUB|GAP):"
kernel/web`.

## Threading & Locking Model

Every stage (parse, style, script, layout, paint) runs in the
**calling thread's context** — the browser app thread or its fetch
worker — over per-page bump arenas with no global mutable state, so
two pages on two threads do not contend. The JS interpreter recurses
on the C++ kernel stack and is bounded by the native-stack guard
described under **Native-stack safety** above; the relevant threads
are the fetch worker (kstack-arena, byte-measured guard) and the
boot-context self-test (large boot stack, logical-depth bound).
There is no engine-wide lock.

## Capability / Privilege Surface

The engine reaches the network only through the kernel HTTP/TLS
stack (`net/http`, `tls_socket`), which is cap-gated like any other
guest network access — the engine holds no capability of its own.
The Assistant's inert `RemoteLlm` direction would route through the
privileged `net.fetch` executor; elevated-origin behaviour is
deferred to [Privileged-Origin Mode](Privileged-Origin.md). See
[Capabilities](../security/Capabilities.md).

**Dense-array index bound.** Integer array indices `>= kMaxArrayIndex`
(`2^24`, in `js/object.h`) are treated as ordinary string-keyed
properties on both the write (`DoAssign`) and read (`EvalExpr` Index)
paths, and `ArrEnsure` grows capacity in `u64` with a clamp. This stops
a hostile script index such as `a[4294967295]` from wrapping a `u32`
capacity to 0 and driving an out-of-bounds kernel-heap write. Regression
cases live in `js/selftest.cpp` (snippets 24–26). (Security audit
SEC-002, CWE-787/190, 2026-06-07.)

## See also

- [In-Kernel Apps](Kernel-Apps.md) — the `browser` app shell, chrome, and
  navigation.
- [Subsystem Isolation](Subsystem-Isolation.md) — why the engine is a
  kernel-owned single source of truth, not a per-ABI facade.
- [Memory Management](Memory-Management.md) — the kstack arena the JS
  native-stack guard keys off.
