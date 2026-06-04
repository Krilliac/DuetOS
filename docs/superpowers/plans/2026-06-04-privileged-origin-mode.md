# Privileged-Origin Mode (claude.ai/code System Access) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (or subagent-driven-development) to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Implement spec §13 — an opt-in, off-by-default mode where the exact, TLS-pinned `https://claude.ai/code` origin can be *armed* for a scoped, audited, instantly-revocable system-access API (`window.duetos.*`). Arming skips the interactive prompt, **never** the kernel cap gates or structural invariants.

**Architecture:** Build the **pure, fully-self-tested security core first** under `kernel/apps/browser/privileged/`: the origin predicate, the capability-scope + path-canonicalisation/containment, the per-tab arm state machine, the audit-entry formatter, and the broker request *validator* (all pure → boot self-tested, no integration). Then wire the integration: a kernel boot flag (`--allow-claude-system-access[=roots]`), the `window.duetos.*` JS host binding (installed only on an armed tab), the broker's *execution* path (validated request → cap-gated syscall → audit), the unspoofable crimson armed chrome, and the `Ctrl+Shift+Esc` kill switch. The whole feature lands **dark** (compiled, off, no binding installed) unless the boot flag is set, so it can ship before it's enabled.

**Tech Stack:** C++23 kernel (no RTTI/exceptions, `Result<T,E>`), the existing `js_dom.cpp` host-object binding mechanism, the cap-gated syscall surface (`kCap*`, `fs::fat32::*`, `net::*`), the `DUETOS_BOOT_SELFTEST` harness, the Phase-1 browser shell (`DockSurface`/`Omnibox`/`TabStrip`, armed chrome extends `DrawToolbar`/`DrawTabStrip`). Build via `wsl-build`; smoke via headless `tools/qemu/run.sh`.

---

## Security posture (read first)

The load-bearing invariant (spec §13.1): **arming skips the interactive PROMPT, not enforcement.** Every `window.duetos.*` call still flows broker → cap-gated syscall; the kernel re-checks the cap + structural invariants. The broker is belt-and-suspenders, never a replacement. `kernel.installHandler` is **specified but NOT built in v1**. The page can never exceed `(browser-app caps) ∩ (armed scope) ∩ (kernel invariants)`.

## File structure

| File | Responsibility |
|------|----------------|
| `kernel/apps/browser/privileged/origin_predicate.{h,cpp}` (+`_selftest.cpp`) | Exact-origin + SPKI-pin + no-redirect privileged-origin predicate. Pure. |
| `kernel/apps/browser/privileged/scope.{h,cpp}` (+`_selftest.cpp`) | Capability set (`Cap` bitset), path canonicalisation, scoped-root containment, structural-invariant refusals. Pure. |
| `kernel/apps/browser/privileged/arm_state.{h,cpp}` (+`_selftest.cpp`) | Per-tab arm state machine (Disarmed/Armed + scope), reconfirm gating, auto-disarm conditions. Pure. |
| `kernel/apps/browser/privileged/audit.{h,cpp}` (+`_selftest.cpp`) | Structured audit-entry formatter (the JSON line) + the append-to-`audit.log` + klog-mirror sink. |
| `kernel/apps/browser/privileged/broker.{h,cpp}` (+`_selftest.cpp`) | Request **validator** (armed? cap in scope? canonicalise+contain? bounds?) → verdict, *without* executing. |
| `kernel/apps/browser/privileged/binding.{h,cpp}` | Installs/tears down `window.duetos.*` on a JS context; marshals a call to the broker; structured results. (js_dom integration) |
| `kernel/apps/browser/privileged/config.{h,cpp}` | Boot-flag parse (`--allow-claude-system-access[=roots]`) → `PrivConfig{available, roots}`. |
| `kernel/apps/browser.cpp` (modify) | Armed-state chrome (crimson omnibox/shield/ribbon/tab/frame), arm/disarm reconfirm + kill-switch routing, per-tab/per-navigation lifetime. |
| `kernel/core/boot_bringup.cpp` (modify) | Register the five new `*SelfTest()` calls; call `PrivConfigParse` at boot. |

**CMake:** `kernel/apps/browser/privileged/*.cpp` auto-glob (CONFIGURE_DEPENDS).

---

## Task 1: Origin predicate (exact-origin + SPKI pin + no-redirect)

**Files:** Create `kernel/apps/browser/privileged/origin_predicate.{h,cpp}`, `origin_predicate_selftest.cpp`; modify `boot_bringup.cpp`.

- [ ] **Step 1: Header.**

```cpp
// kernel/apps/browser/privileged/origin_predicate.h
#pragma once
#include "util/types.h"

namespace duetos::apps::browser::priv
{
// SHA-256 of the server-leaf SubjectPublicKeyInfo (the SPKI pin). 32 bytes.
struct SpkiPin { duetos::u8 sha256[32]; };

// All must hold for the live navigation (spec §13.4):
//  scheme=="https" · host=="claude.ai" (exact, no subdomain) · path begins "/code"
//  · NOT reached via any redirect · leaf SPKI matches the embedded pin.
struct OriginCheck
{
    const char* scheme;        // e.g. "https"
    const char* host;          // post-IDNA, ASCII-folded
    const char* path;          // e.g. "/code/abc"
    bool reachedViaRedirect;   // true if any 3xx / client redirect was observed
    const SpkiPin* leafPin;    // the server leaf's SPKI hash (null => fail)
};

// The single embedded pin set (claude.ai). Build-shipped; pin mismatch fails closed.
bool LeafPinMatches(const SpkiPin& leaf);

bool IsPrivilegedOrigin(const OriginCheck& c);

void OriginPredicateSelfTest();
} // namespace duetos::apps::browser::priv
```

- [ ] **Step 2: Failing self-test** (`origin_predicate_selftest.cpp`) — emits `[priv-origin-selftest] FAIL check=N` / `PASS`. Build a known-good pin (a fixed 32-byte array also embedded as THE pin for the test build), then assert: (1) exact `https`+`claude.ai`+`/code`+no-redirect+good-pin → true; (2) `http` → false; (3) `evil.com` → false; (4) `app.claude.ai` (subdomain) → false; (5) path `/` (not `/code`) → false; (6) `reachedViaRedirect=true` → false; (7) null/ wrong pin → false. Use the exact assertion/`KBP_PROBE_V(kBootSelftestFail,…)` pattern from `dock_surface_selftest.cpp`.

- [ ] **Step 3: Implement** `origin_predicate.cpp`: `IsPrivilegedOrigin` ANDs all five conditions (string compares via `duetos::core::StrEqual`; `host=="claude.ai"` exact; `path` prefix `"/code"`; `!reachedViaRedirect`; `c.leafPin && LeafPinMatches(*c.leafPin)`). `LeafPinMatches` does a constant-time 32-byte compare against the embedded pin. **GAP marker** on the pin: the v0 pin is a build constant (rotation/secondary-pin handling is a follow-up).

- [ ] **Step 4: Register + build + verify.** `DUETOS_BOOT_SELFTEST(duetos::apps::browser::priv::OriginPredicateSelfTest());` in `boot_bringup.cpp`; build via `wsl-build`; headless boot; expect `[priv-origin-selftest] PASS`, zero warnings.

- [ ] **Step 5: Commit** `feat(browser/priv): privileged-origin predicate (exact-origin + SPKI pin + no-redirect)`.

---

## Task 2: Capability scope + path canonicalisation + containment

**Files:** Create `kernel/apps/browser/privileged/scope.{h,cpp}`, `scope_selftest.cpp`; modify `boot_bringup.cpp`.

Interface:

```cpp
// scope.h
enum class Cap : duetos::u8 { FsRead=0, FsWrite=1, ProcSpawn=2, KernelRead=3, Net=4 };
struct CapSet { duetos::u16 bits = 0;
  void Add(Cap c){ bits |= (1u<<u16(c)); }
  bool Has(Cap c) const { return bits & (1u<<u16(c)); } };
// The default-arm set (spec §13.6): FsRead|FsWrite|ProcSpawn|KernelRead|Net. NEVER installHandler.
CapSet DefaultArmScope();

struct Roots { const char* root[4] = {}; duetos::u32 count = 0; };
// Canonicalise `in` (resolve '.'/'..'; reject any escape), require it lies within `roots`,
// and refuse structural-invariant paths ('/', '/sys','/dev','/proc', boot/EFI, 'audit.log').
// Returns true + writes a NUL-terminated canonical path into out[cap] on success.
bool CanonicalizeAndContain(const char* in, const Roots& roots, char* out, duetos::u32 cap);
```

Self-test (`[priv-scope-selftest]`): `DefaultArmScope()` has the five caps and NOT a 6th; `/home/user/p/notes.md` within roots `{"/home/user"}` → ok + canonical; `/home/user/../etc/shadow` → refused (escape); `/` → refused; `/etc/shadow` → refused (outside roots); a path resolving to `audit.log` → refused; `/dev/sda` → refused. Build, verify `[priv-scope-selftest] PASS`, commit `feat(browser/priv): capability scope + path canonicalisation + containment`.

---

## Task 3: Per-tab arm state machine

**Files:** Create `kernel/apps/browser/privileged/arm_state.{h,cpp}`, `arm_state_selftest.cpp`; modify `boot_bringup.cpp`.

Interface:

```cpp
// arm_state.h
enum class ArmState : duetos::u8 { Disarmed=0, Armed=1 };
struct PrivTab
{
    ArmState state = ArmState::Disarmed;
    CapSet scope{};            // valid when Armed
    void Arm(const CapSet& s){ state = ArmState::Armed; scope = s; }
    void Disarm(){ state = ArmState::Disarmed; scope = CapSet{}; }
    bool IsArmed() const { return state == ArmState::Armed; }
    // Auto-disarm when the live navigation no longer satisfies the predicate
    // (different origin/path, a redirect, or a reload).
    void OnNavigation(bool stillPrivilegedOrigin){ if (!stillPrivilegedOrigin) Disarm(); }
};
```

Self-test (`[priv-arm-selftest]`): a fresh tab is Disarmed; `Arm(DefaultArmScope())` → Armed + scope has FsWrite; `Disarm()` → Disarmed + empty scope; `OnNavigation(false)` auto-disarms an armed tab; `OnNavigation(true)` leaves it armed; the scope never contains an installHandler bit (there is none). Build, verify `[priv-arm-selftest] PASS`, commit.

---

## Task 4: Audit-entry formatter + sink

**Files:** Create `kernel/apps/browser/privileged/audit.{h,cpp}`, `audit_selftest.cpp`; modify `boot_bringup.cpp`.

Interface:

```cpp
// audit.h
struct AuditEntry
{
    const char* iso8601;   // "2026-06-04T18:22:07Z" (caller stamps; tests pass a fixed value)
    const char* origin;    // "https://claude.ai/code"
    duetos::u32 tab;
    const char* cap;       // "fs.write"
    const char* argsSummary; // bounded/redacted: "path=/home/user/x bytes=412" (no payloads)
    bool ok;
};
// Format one append-only JSON line into out[cap]. Returns the length written.
duetos::u32 FormatAuditLine(const AuditEntry& e, char* out, duetos::u32 cap);
// Append a formatted line to audit.log (cap-gated fs write) AND mirror to klog
// (KLOG_INFO ok / KLOG_WARN+KBP_PROBE on fail). audit.log is excluded from fs scope.
void AuditAppend(const AuditEntry& e);
```

Self-test (`[priv-audit-selftest]`): `FormatAuditLine` of a known entry produces the exact expected JSON substring (`"cap":"fs.write"`, `"ok":true`, the redacted args, the origin); a denied entry formats `"ok":false`; `argsSummary` is length-bounded. (The fs append is integration — the selftest covers the pure formatter only.) Build, verify `[priv-audit-selftest] PASS`, commit.

---

## Task 5: Broker request validator

**Files:** Create `kernel/apps/browser/privileged/broker.{h,cpp}`, `broker_selftest.cpp`; modify `boot_bringup.cpp`.

The validator is the pure heart of enforcement — it decides yes/no WITHOUT executing.

```cpp
// broker.h
struct PrivRequest { Cap cap; const char* path; duetos::u32 byteLen; /* …*/ };
struct Verdict { bool ok; const char* error; }; // error e.g. "EPERM: outside scoped roots"
// Validate: armed? cap in scope? (fs caps) canonicalise+contain path? bounds ok?
Verdict ValidateRequest(const PrivTab& tab, const Roots& roots, const PrivRequest& r, char* canonOut, duetos::u32 cap);
```

Self-test (`[priv-broker-selftest]`): armed + FsWrite-in-scope + in-roots path + ok bytes → `{ok:true}` + canonical path; a Disarmed tab → `{ok:false,"EPERM: not armed"}`; a cap not in scope → `{ok:false,"EPERM: capability not granted"}`; an escape path → `{ok:false,"EPERM: outside scoped roots"}`; `byteLen` over the cap → `{ok:false,"EINVAL: ..."}`; the structural-invariant refusals (`/`, `audit.log`) → refused. Build, verify `[priv-broker-selftest] PASS`, commit. **This task is the security keystone — its assertions are the contract the integration must not weaken.**

---

## Task 6: Boot flag + config (feature availability + roots)

**Files:** Create `kernel/apps/browser/privileged/config.{h,cpp}`; modify the kernel cmdline parser + `boot_bringup.cpp`.

`PrivConfig{ bool available; Roots roots; }`, a file-static `g_priv_config`. `PrivConfigParse(const char* cmdline)` scans for `--allow-claude-system-access` (sets `available=true`), and an optional `=root[:root2…]` (fills `roots`, default `{"/home/user"}` when bare). When absent: `available=false` (the binding is never installed; arm UI hidden). Log `priv-origin: disabled` / `priv-origin: enabled roots=[…]` at boot. Add a `[priv-config-selftest]` asserting: absent flag → not available; bare flag → available + default root; `=/work:/data` → those two roots; system paths still excluded by Task-2 containment regardless. Build, verify, commit.

---

## Task 7: `window.duetos.*` binding (js_dom integration)

**Files:** Create `kernel/apps/browser/privileged/binding.{h,cpp}`; modify `kernel/web/js_dom.cpp` (install/teardown hook).

`PrivBindingInstall(JsDomContext* ctx, duetos::u32 tabId, const PrivTab* tab)` installs a `window.duetos` host object exposing `armed`, `origin`, `scope`, and the namespaced methods (`fs.readFile/writeFile/list/stat/mkdir/remove`, `proc.spawn/list/signal`, `kernel.read`, `net.fetch/connect`) — each marshals `{cap,args}` to the broker (Task 8) and returns a structured `{ok,…}` JS object. `PrivBindingTeardown(ctx)` removes it. Installed ONLY when `g_priv_config.available && tab->IsArmed()`; absent otherwise (so a non-armed page sees `window.duetos === undefined`). Mirror the existing host-object pattern in `js_dom.cpp` (the `document`/element bindings). Verify via a `[priv-binding-selftest]` (js-dom style): an armed context exposes `window.duetos.armed===true` and `scope`; a disarmed context has `window.duetos===undefined`; `kernel.installHandler===undefined` always. Build, verify, commit. **GAP:** synchronous result records (the interpreter has no Promises).

---

## Task 8: Broker execution path (validated request → cap-gated syscall → audit)

**Files:** Modify `kernel/apps/browser/privileged/broker.{h,cpp}`.

`BrokerExecute(PrivTab& tab, duetos::u32 tabId, const PrivRequest& r)` = `ValidateRequest` (Task 5) → on ok, invoke the matching **cap-gated** kernel call (`fs::fat32::*` for fs, the proc-spawn path for proc, the net stack for net, read-only introspection for kernel.read) → build the `{ok,…}` result → `AuditAppend` (Task 4) for EVERY call (allow or deny) BEFORE returning. A denied validate still audits + returns the structured error. **Hardening:** the kernel re-checks its `kCap*` gate independently; the broker never bypasses it. No new task adds a path that the browser app's own caps don't already permit. Extend `broker_selftest.cpp` with an injected fake-executor to assert: an allowed request calls the executor with the canonical path + writes an `ok:true` audit; a denied request does NOT call the executor + writes an `ok:false` audit. Build, verify, commit.

---

## Task 9: Armed-state chrome + arm/disarm + kill switch

**Files:** Modify `kernel/apps/browser.cpp`.

Render the unspoofable armed state (spec §13.5) by extending `DrawToolbar`/`DrawTabStrip`: when the active tab is armed, tint the omnibox crimson (`tokens::kAccentDanger`), swap the lock for a red shield glyph, draw the full-width warning ribbon under the toolbar (`⚠ PRIVILEGED SYSTEM ACCESS ARMED — claude.ai/code … [Disarm]`), red tab accent, red content frame — all chrome-drawn (page can't touch). Arm flow: a press on the (future) arm affordance when the active tab is on the privileged origin opens the reconfirm dialog; a deliberate confirm calls `tab.Arm(DefaultArmScope())` + `PrivBindingInstall`. Disarm: the ribbon `[Disarm]` button OR the `Ctrl+Shift+Esc` chord (input-routed at highest priority, handled by chrome not the page) → abort in-flight, `tab.Disarm()` + `PrivBindingTeardown` + audit `disarmed` + reload sandboxed. Lifetime: on navigation/reload/close call `PrivTab::OnNavigation(IsPrivilegedOrigin(...))` so privilege never survives. Verify via a `[priv-chrome-selftest]` asserting the armed-state predicate drives the crimson flag + a simulated kill-switch transitions Armed→Disarmed and tears down the binding. Build (zero warnings), boot (all selftests PASS, no PANIC), commit. **Pixel layout needs VBox.**

---

## Task 10: Docs + recap

Add a "Privileged-Origin Mode" section to `wiki/kernel/Web-Engine.md` (or a new `wiki/kernel/Privileged-Origin.md`) summarising the security model + the boot flag + the self-tests, cross-linking `Subsystem-Isolation.md`. Update the Roadmap if present. Write the Privileged-Origin recap to `.remember/`. Commit `docs(browser/priv): Privileged-Origin Mode — wiki + recap`.
