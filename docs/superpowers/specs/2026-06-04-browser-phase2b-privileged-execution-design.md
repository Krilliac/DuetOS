# Browser Phase 2b — Privileged Execution + Assistant Backend

**Date:** 2026-06-04
**Branch:** `claude/browser-phase2b-exec`
**Depends on:** Phase 2a §13 Privileged-Origin Mode (merged, PRs #389/#390)
**Spec parent:** `docs/superpowers/specs/2026-06-04-browser-ui-redesign-design.md` (§10, §13, §14)

## 1. Goal

Close the GAP at `kernel/web/priv_binding.cpp:272`: today `window.duetos.proc.spawn`
and `window.duetos.net.fetch` **validate + audit but do not execute** because the JS
methods carry no actionable arguments. This slice gives them real arguments and real
execution, and gives the existing Assistant dock a working conversational backend.

Two deliverables, one slice (operator chose A+B together):

- **Part A — Privileged execution.** `proc.spawn(path, args)` and `net.fetch(url, opts)`
  actually run, gated by the unchanged broker validator + a kernel cap re-check.
- **Part B — Assistant backend.** The `g_assistant` `DockSurface` gets a deterministic
  local heuristic responder, with LLM-ready (but inert) transport plumbing on top of
  Part A's net.fetch path.

## 2. Non-negotiable invariant

The broker validator (`security::privilege::ValidateRequest`) stays the pure security
keystone. Phase 2b adds execution **behind** it, never around it. Every privileged call
is **validate → audit → execute**, fail-closed, in that order — the exact shape
`FsValidate`/`ExecFsWrite` already proves for fs. The reviewable signal from
[Subsystem-Isolation](../../../wiki/kernel/Subsystem-Isolation.md) governs:
*"could the armed page do something the browser app's own caps could not?"* — answer
must remain **no**.

## 3. Architecture — the executor-hook

The execution helpers live in `kernel/apps` (browser app): the TLS transport opener
`OpenTransport` is **private to `browser.cpp`**, and the armed-scope→`kCap*` cap mapping
is app-layer policy. The privileged binding lives in `kernel/web` (the JS engine). To
let the engine reach the helpers **without coupling `kernel/web` to proc/net/TLS**, the
browser app registers executor function-pointers on `PrivBind`:

```cpp
// kernel/web/priv_binding.h — added to PrivBind
using SpawnExec = duetos::i64 (*)(const char* canonPath, const char* const* argv,
                                  duetos::u32 argc,
                                  const security::privilege::CapSet& armedScope, void* ctx);
// Returns child pid (>0) or -errno.

struct FetchReq { const char* url; const char* method; const char* body;
                  duetos::u32 bodyLen; const char* contentType; };
struct FetchRes { duetos::u32 status; char* body; duetos::u32 bodyLen; bool ok; };
using FetchExec = bool (*)(const FetchReq& req, FetchRes* out, void* ctx);

struct PrivBind { /* existing: tab, roots, origin, client */
    SpawnExec spawnExec = nullptr;
    FetchExec fetchExec = nullptr;
    void* execCtx = nullptr;
};
```

**Degradation contract:** when an executor pointer is null (self-test, or feature
mid-bring-up), the method returns today's validate+audit-only result — **no regression**.

**Approaches rejected:** (B) direct-in-engine — forces exposing `OpenTransport`, couples
`kernel/web` to proc/net/TLS, un-mockable in the engine self-test; (C) new `SYS_*`
syscalls — the binding is already in-kernel, a ring transition buys no isolation (the
kernel re-checks caps regardless). The hook is the lowest-surface, most-testable option
and matches spec §13.7 ("marshals to the broker (browser app)").

**Disarm contract (§13.9) is satisfied for free:** privileged calls are synchronous on
the single JS thread and the broker serialises per-tab, so there is no mid-call
interleave to abort. A post-disarm call fails at `ValidateRequest` step 1
(`tab.IsArmed()` false → `EPERM`); the kill switch tears down `window.duetos` entirely.

## 4. Part A — validator extension (`broker.cpp`)

`PrivRequest` gains `const char* url = nullptr` (the `path` field is reused as the spawn
target). Two new branches in `ValidateRequest`, after the existing armed + in-scope checks:

- **`Cap::ProcSpawn`** — require `r.path != nullptr` and
  `CanonicalizeAndContain(r.path, roots, canonOut, cap)`. v1 **exec-roots = scoped-roots**
  ("spawn only from allowed exec roots", §13.6). Reuses the keystone verbatim, so every
  `..`-escape / sibling-prefix / device-node / NUL refusal proven for fs applies
  identically — **no new adversarial surface**.
- **`Cap::Net`** — require `r.url != nullptr`, `ParseUrl(r.url)` succeeds, host non-empty,
  scheme `http`/`https` only, length-bounded. "Same policy as a page fetch" (§13.6) →
  arbitrary hosts allowed (the AI seam must reach an external endpoint); the kernel
  firewall remains the final net authority.

## 5. Part A — binding execution (`priv_binding.cpp`)

`MProcSpawn` / `MNetFetch` stop ignoring their args:

```js
window.duetos.proc.spawn("/home/user/bin/tool.elf", ["--flag"]); // {ok:true, pid:N} | {ok:false, error}
window.duetos.net.fetch("https://api.example.com/x",
    {method:"POST", body:"…", contentType:"application/json"});   // {ok:true, status:200, body:"…"} | {ok:false, error}
```

Flow (both): marshal `PrivRequest` → `ValidateRequest` → **audit (allow AND deny)** →
on allow, if the executor pointer is non-null, call it and build the result record; else
return validate-only `{ok}`.

- **Spawn audit args:** `path=<canon>,argc=<n>` — never the argv contents beyond count.
- **Fetch audit args:** `url=<url>,method=<m>` — **never the body**.
- **Fetch body bounce cap:** 256 KiB binding-local ceiling (independent of the broker's
  larger `kMaxPrivWriteBytes`), heap-freed after the result string is built.

## 6. Part A — executors (`kernel/apps/browser/priv_exec.{h,cpp}`)

**`SpawnExecImpl`:**
1. Map armed `sp::CapSet` → kernel `CapSet`: `fs.read→kCapFsRead`, `fs.write→kCapFsWrite`,
   `proc→kCapSpawnThread`, `net→kCapNet`, `kernel.read→`(diag read cap). **Child ⊆ broker
   — never `CapSetTrusted()`.** This is the subsystem-isolation crux.
2. `Fat32ReadFile(canonPath)` into a staging buffer (mirrors `files.cpp:1053`).
3. Sniff magic: `MZ`→`SpawnPeFile`, `\x7fELF`→`SpawnElfFile`. Anything else → `-EINVAL`.
4. Return child pid (`>0`) or `-errno`.

**`argv` GAP:** `SpawnPeFile`/`SpawnElfFile` carry no argv today. The executor *accepts*
argv (API matches the spec example) but drops it:
`// GAP: argv not delivered to child — spawn ABI carries no argv vector yet; revisit when SpawnElf/PeFile gain one.`
The JS surface stays stable; the limit is pinned and greppable.

**`FetchExecImpl`:** reuses the **exact page-fetch machinery** — `OpenTransport` → build
`HttpRequestSpec` (method/url/body/content-type) → `HttpRequest(...)` → `CloseTransport`.
One net stack, one TLS path, one cookie/redirect policy. v1 methods: **GET + POST** (POST
is what the LLM seam needs). Response body copied into a caller-owned buffer up to cap.

**Wiring (`browser.cpp`):** on arm (alongside the existing `g_priv_bind.tab = …` at
~line 2647), set `g_priv_bind.spawnExec = &SpawnExecImpl; g_priv_bind.fetchExec =
&FetchExecImpl; g_priv_bind.execCtx = …`. Cleared on disarm with the rest of the struct.

## 7. Part B — Assistant backend

The `g_assistant` `DockSurface` already renders; B gives it a conversational loop.
**Deliberately minimal** to avoid the AI-complexity trap the anti-bloat guide warns about.

- **`assistant_backend.h`** — one interface:
  `bool Respond(const char* userMsg, char* out, duetos::u32 cap);`
- **`LocalHeuristic`** (`assistant_heuristic.cpp`) — deterministic, CI-testable. A *small*
  fixed intent set and a graceful fallback. The intent set is the minimum that proves a
  working loop, **not** an NLU:
  - `help` / empty → capability summary line.
  - `open <url>` → emit a navigate intent (host drives the actual navigation).
  - page/arm status query → echo current page title + armed state.
  - fallback → a fixed "I can't do that yet locally; try `help`." reply.
- **`RemoteLlm` seam** — builds a POST `HttpRequestSpec` for a config-supplied endpoint and
  routes through Part A's `FetchExec`. Shipped **disabled**:
  `// GAP: RemoteLlm wired to transport but inert — no API-key/secret-store mechanism in v1; flip on once a key source lands.`
- **Dock input:** a text line in the Assistant surface; Enter → `backend->Respond` →
  append reply. Backend selected by config (heuristic default).

## 8. Testing

Boot self-tests, each emitting a grep-able `PASS` sentinel:

- **`priv_binding_selftest`** (extend) — register **mock** spawn/fetch executors; assert:
  armed + in-scope allow **reaches** the executor; disarmed → `EPERM` and **never** reaches
  it; out-of-root spawn path → `EPERM`; malformed URL → `EINVAL`; audit line emitted on
  **both** allow and deny.
- **`broker_selftest`** (extend) — `ProcSpawn` containment cases (in-root allow,
  `..`-escape deny, device-node deny) + `Net` URL-shape cases (good http/https allow,
  malformed/non-http deny).
- **`assistant_heuristic_selftest`** (new) — each intent → expected reply; fallback path.

No live net/proc stack is needed for any self-test (mock executors + pure heuristic).

## 9. Security checklist (the reviewable signal)

- Child caps ⊆ armed scope — asserted in the cap-map; never `CapSetTrusted()`. ✅
- Spawn target & fetch URL both pass keystone / `ParseUrl` **before** any side effect. ✅
- Disarm → fail-closed at validator step 1; executor unreachable post-disarm. ✅
- `audit.log` excluded from scope; spawn + fetch both audited; deny logged as importantly
  as allow (`KLOG_WARN` + `KBP_PROBE` on deny, per §13.8). ✅
- `net.fetch` reuses the one firewall-governed net stack — no parallel egress path. ✅

## 10. GAP inventory carried (pinned, honest)

- `argv` not delivered to spawned child (spawn ABI has no argv vector).
- `RemoteLlm` inert pending a secret-store mechanism for the API key.
- Symlink-TOCTOU still deferred to the fs layer (unchanged; FAT32 has no symlinks).

## 11. Files

**Engine (`kernel/web`):** `priv_binding.{h,cpp}` (hooks + real execution),
`priv_binding_selftest.cpp` (mock executors).
**Security (`kernel/security/privilege`):** `broker.{h,cpp}` (validator branches + `url`
field), `broker_selftest.cpp`.
**App (`kernel/apps`):** new `browser/priv_exec.{h,cpp}`, `browser/assistant_backend.h`,
`browser/assistant_heuristic.cpp` + selftest; `browser.cpp` (wire executors on arm + dock
input). CMake list updated for the new TUs.
**Docs:** `wiki/kernel/Privileged-Origin.md` (GAP→real); parent spec §10/§13 cross-ref.

## 12. Out of scope (later, separately reviewed)

Real LLM inference (needs secret-store); argv delivery (needs spawn-ABI change);
per-capability grant checkboxes; persistent/always-armed grants; `kernel.installHandler`.
