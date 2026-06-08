# DuetOS Browser — Render-Failure Diagnosis, Field Gap Analysis, and Roadmap

_2026-06-08. Produced by a multi-agent workflow; the web-research agents stalled in
the headless run (web/MCP tools don't reach workflow subagents), so the architectural
comparison rows are flagged **[research-pending]** and rest on well-established public
knowledge, not a freshly-cited corpus. The code diagnosis is verified against the live
tree._

---

## 1. Why nothing renders — root cause + fix

The symptom ("navigating to any page loads nothing / returns to the search bar") is
**not one bug but a stack of three gates**, any one of which yields an empty page.

### Gate 1 — The omnibox has no URL-vs-search routing (the "returns to the search bar" symptom)

`HandleUrlEditChar` (`kernel/apps/browser.cpp:3441`) commits the typed text on Enter
**verbatim** into `StartFetch` — there is **no branch** that asks "is this a hostname or
a search query?". So a bare term (`weather`, `news`) → `ParseUrl` treats it as host
`weather` → `ResolveHost` fails → `DoFetch` sets "DNS resolve failed" and renders nothing.
To the user this looks like the omnibox "did nothing / came back." **Most user-visible
defect, cheapest fix.**

### Gate 2 — Bare hosts default to plain HTTP, and real sites force an HTTPS redirect into the trust-store wall

`ParseUrl` (`browser.cpp:617-630`) defaults an unscheme'd host to **HTTP** (port 80).
Almost every real site answers port 80 with `301 → https://…`; the redirect lands on
Gate 3. Net effect: even a correctly-typed bare host can't render a modern site.

### Gate 3 — TLS verification fails closed against a near-empty, test-oriented trust store (root cause for HTTPS)

`x509::Verify` (`kernel/net/x509_verify.cpp:733`) **fails closed** on anything that
doesn't chain (depth ≤ 2) to an *embedded* anchor. The embedded store is synthetic test
roots **plus ~6 real roots** (DigiCert Global Root CA/G2, ISRG Root X1, DigiCert G3, ISRG
Root X2). Any other root → fail. Also deliberately narrow: **depth-2 max**,
`sha256WithRSA`/`ecdsa-with-SHA256/384` only (no RSA-PSS/Ed25519/SHA-1), P-256/P-384 only.
Google uses **GTS (Google Trust Services)** roots → not embedded → `CertUntrusted` → empty
body. **The crypto is real and correct; only the anchor set is test-oriented.**

### Prioritized fix

| # | Fix | File:line | Effort | Effect |
|---|-----|-----------|--------|--------|
| 1 | **Omnibox URL-vs-search classifier** before `StartFetch`. | `browser.cpp:3444-3449` (+ pill-submit ~5202) | S | Kills the "returns to search bar" symptom. TLS-independent. |
| 2 | **Default bare hosts to HTTPS** (keep HTTP→HTTPS upgrade). | `browser.cpp:641`, `617-630` | S | Removes the gratuitous 80→301 round trip. |
| 3 | **Solve the trust store** (real CA bundle, Subject-DN indexed). | `x509_verify.cpp:803+` | L | Unblocks real HTTPS. |
| 4 | **Disambiguate TLS error codes** (don't collapse connect/verify/handshake to -1). | `tls_socket.cpp`, `browser.cpp:1587` | S | Actionable errors. |

### Trust-store options (recommended order)

1. **Ship a real CA bundle (Mozilla/CCADB, ~150 roots), indexed by Subject-DN** — the
   header anticipates this ("verifier logic is anchor-agnostic", `x509_verify.cpp:803-806`).
   Must also raise **chain depth 2 → ≥4** and add **RSA-PSS**. Durable, correct end state.
2. **Trust-on-first-use / user-accept path** — on `CertUntrusted`, an explicit "proceed?"
   that pins the leaf SPKI for the session. Real MITM-acceptance surface; gate behind a
   click, never auto-accept. Good interim for reaching real sites pre-bundle.
3. **HTTP-only smoke target** — plain-HTTP render path is complete; point a smoke at an
   HTTP origin to prove the pipeline while the trust decision is made.

---

## 2. DuetOS browser vs the field — gap analysis

> **[research-pending]** — comparison rows rest on public knowledge of Chromium/Blink,
> Firefox/Gecko, WebKit, Servo, NetSurf, Ladybird, not a fresh cited corpus.

| Area | DuetOS today | Field reference | Verdict |
|------|--------------|-----------------|---------|
| Rendering pipeline | Full software path: HTML→DOM→CSS cascade→layout (incl inline)→display list→paint; PNG/JPEG. Runs in-kernel. | NetSurf / Ladybird | **Adequate for v0**; render is *not* the blocker. Missing: incremental/async layout, compositing, GPU paint. |
| Network / TLS + root store | Own TCP/IP + TLS, real X.509 (RSA+ECDSA, SAN, validity, name-chaining), HTTP redirects/chunked/cookies. | BoringSSL + Mozilla store, depth-N, PSS, OCSP/CT | **Verify logic adequate; trust store + depth + algo coverage are the gap.** The render blocker. |
| JavaScript | Own interpreter (lexer/parser/AST/interp/regexp/builtins/DOM bindings), step-budgeted, stack-guarded. | V8/SpiderMonkey/JSC (JIT) | Far behind on coverage/perf but correctly scoped for v0. |
| Layout | Block + inline flow, UA sheet, CSS cascade. | Blink/Gecko full CSS2.1+flex/grid | Usable for simple pages; modern layouts wrong (no flex/grid/complex float). |
| Security / process model | **Single in-kernel app**, no per-origin isolation; priv-origin predicate + cap-gated priv_exec. | Chromium multiprocess site isolation; Ladybird multiprocess | **Weakest structural gap** — a parser/JS bug is a *kernel* compromise. Long-term: move engine out of ring 0. |

---

## 3. Prioritized roadmap

1. **Omnibox URL-vs-search classifier** — S. Eliminates the dominant symptom. TLS-independent.
2. **HTTP smoke target + default-to-HTTPS for bare hosts** — S. Isolates "render works" from "trust is narrow."
3. **Ship a real CA root bundle (Mozilla/CCADB), Subject-DN indexed** — L. The actual root cause of no-real-HTTPS.
4. **Raise chain depth 2 → ≥4 and add RSA-PSS** — M. Real chains exceed depth 2 and use PSS. (`x509_verify.cpp:777`, `:627`.)
5. **Distinct TLS failure codes + Trust-On-First-Use accept path** — M. Actionable errors + reach arbitrary sites pre-bundle.
6. **Layout coverage: floats/positioning, then flexbox** — L.
7. **Move the web engine out of ring 0 (sandboxed renderer)** — L/XL. Closes the structural security gap; aligns with the subsystem-isolation pillar.

---

## 4. Highest-leverage next step

**Ship the omnibox URL-vs-search classifier (#1), and in the same slice point a smoke at a
plain-HTTP origin to prove the render pipeline end-to-end.** S-effort, removes the
most-reported symptom, decoupled from the hard TLS work, and produces the decisive
evidence that the engine is fine and only input-routing + the trust store need work — which
makes the larger trust-store/depth/PSS work safe to schedule.

Edit site: `HandleUrlEditChar` Enter branch, `browser.cpp:3444-3449` (mirror in the
pill-submit click path, `browser.cpp:~5202`).
