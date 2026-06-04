# Privileged-Origin Mode (claude.ai/code System Access)

> **Audience:** Kernel/security reviewers, browser hackers
>
> **Execution context:** Kernel — the policy core (`kernel/security/privilege/`)
> is pure and JS-free; the JS bridge (`kernel/web/priv_binding.cpp`) runs in the
> page's interpreter context; the chrome + lifecycle run in the browser app
> thread (`kernel/apps/browser.cpp`).
>
> **Maturity:** Phase 2a complete — the full security core + the broker
> execution path + the armed chrome are built and boot self-tested. Ships
> **dark** (compiled, off, no binding installed) unless the boot flag is set.

## What it is

Spec §13. An opt-in, off-by-default mode where the exact, TLS-pinned
`https://claude.ai/code` origin can be **armed** for a scoped, audited,
instantly-revocable system-access API exposed to page JS as `window.duetos.*`.

The load-bearing invariant (spec §13.1): **arming skips the interactive prompt,
not enforcement.** Every `window.duetos.*` call still flows broker validator →
cap-gated kernel path → audit; the kernel re-checks the capability and the
structural invariants independently. The broker is belt-and-suspenders, never a
replacement for the cap gate. A page can never exceed
`(browser-app caps) ∩ (armed scope) ∩ (kernel invariants)`.

This is **Client A** of the "one Privilege Engine, many authenticated clients"
architecture: the engine core is client-agnostic so a future headless self-dev
agent (Client B) reuses the same validator, audit log, and kill switch with a
different authentication path. See [Subsystem Isolation](Subsystem-Isolation.md)
— a privileged page is still a guest; the kernel is the authority on every
effect.

## The boot flag (off by default)

The feature is fully off unless the kernel cmdline carries:

```
--allow-claude-system-access[=root1[:root2…]]
```

- absent → `PrivConfigCurrent().available == false`: the arm affordance is
  hidden, no binding is ever installed, `window.duetos === undefined`. Boot logs
  `[priv] config: disabled`.
- bare flag → available with the conservative default scoped root `/home/user`.
- `=…` → the colon-separated scoped roots (capped at 4). Boot logs
  `[priv] config: enabled (--allow-claude-system-access)`.

Parsed once at boot in `BootBringupDesktop` and published via
`security::privilege::PrivConfigSetCurrent` → `PrivConfigCurrent()` (the single
source of truth every client reads).

## Module map

| File | Responsibility |
|------|----------------|
| `kernel/apps/browser/privileged/origin_predicate.*` | Exact-origin + SPKI-pin + no-redirect predicate (Client-A auth). Pure. |
| `kernel/security/privilege/scope.*` | `Cap` set + path canonicalisation + scoped-root containment + structural-invariant refusals. The **security keystone**. Pure. |
| `kernel/security/privilege/arm_state.*` | Per-tab `PrivTab` arm machine (Disarmed/Armed + scope); per-navigation auto-disarm. Pure. |
| `kernel/security/privilege/broker.*` | `ValidateRequest` — the pure yes/no validator (armed? cap in scope? contained? bounded?). Decides **without** executing. |
| `kernel/security/privilege/audit.*` | Client-tagged JSON audit-line formatter + the serial mirror + the durable `/AUDIT.LOG` fs sink. |
| `kernel/security/privilege/config.*` | Boot-flag parse + `PrivConfigCurrent()`. |
| `kernel/web/priv_binding.*` | The `window.duetos.*` host-object tree; marshals each call → `ValidateRequest` → cap-gated fs syscall → audit. The JS bridge (engine stays JS-free). |
| `kernel/web/js_dom.cpp` | `JsDomContextInstallPrivBinding` — installs the binding onto a live page's JS global env on arm. |
| `kernel/apps/browser.cpp` | Armed crimson chrome, arm/disarm reconfirm, `Ctrl+Shift+Esc` kill switch, per-navigation lifetime. |

## The `window.duetos.*` surface

Installed onto the page's JS global env **only** when `available && tab.IsArmed()`:

- `duetos.armed` / `duetos.origin` / `duetos.scope` — read-only state.
- `duetos.fs.readFile(path)` → `{ok, data}` / `duetos.fs.writeFile(path, bytes)` → `{ok}`
  — validated + canonicalised + scope-contained, then executed via `fs::fat32`.
- `duetos.kernel.read()` → `{ok, uptimeNs}` — read-only introspection (monotonic
  uptime; no pointer / KASLR base / secret).
- `duetos.proc.spawn(path[, args])` → `{ok, pid}` — validated + canonicalised +
  **exec-root-contained** (v1: exec-roots = scoped-roots), audited, then executed via
  an app-layer **executor hook**: read the image from FAT32, sniff PE/ELF, and spawn
  it with caps **derived strictly from the armed scope** (child ⊆ broker — never
  trusted) into the sandbox ramfs namespace. _GAP: `argv` is validated/audited as a
  count but not delivered to the child — the spawn ABI carries no argv vector yet._
- `duetos.net.fetch(url[, opts])` → `{ok, status, body}` — URL shape-validated
  (`http`/`https`, non-empty host), audited (url + method, never the body), then run
  over the **same page-fetch transport** a normal load uses (`OpenTransport` +
  `HttpRequest` + TLS), reusing the one firewall-governed net stack. v1 issues GET;
  the executor already accepts POST (the LLM seam). Body bounded by a 256 KiB bounce.
- `kernel.installHandler` — **intentionally absent in v1** (spec §13.6); there is
  deliberately no such capability in the `Cap` enum.

### Broker execution path (the most security-sensitive wire)

`FsValidate` → `ValidateRequest` (verdict + canonical path) → audit (allow AND
deny, client-tagged, real ISO-8601 timestamp) → **on a denied verdict, return
without executing** → **symlink-TOCTOU re-check** (`CanonicalizeAndContain` on the
canonical path immediately before the syscall, closing the validate→execute
window) → execute on the re-validated path. Write payloads are bounded by a
64 KiB binding-local bounce buffer (the broker independently rejects
`> kMaxPrivWriteBytes` = 16 MiB).

## Unspoofable armed chrome + kill switch

When the active tab is armed the browser **chrome** (which a page can never draw)
renders the trust signal in `tokens::kAccentDanger` crimson: tinted omnibox, red
shield glyph, a full-width `[!] PRIVILEGED SYSTEM ACCESS ARMED — claude.ai/code
[Disarm]` ribbon, red tab accent, red content frame.

Disarm is total and instantaneous, by either path:

- the ribbon `[Disarm]` button, or
- **`Ctrl+Shift+Esc`** — routed at highest priority in the kernel input loop
  (`kernel/core/boot_tasks.cpp`), handled by the chrome **not** the page, so a
  hostile page can never swallow it. It revokes **all** armed clients (today: all
  browser tabs; a future client registry hooks the same switch).

Both clear the cap scope (so the broker fail-closes every call as
`"EPERM: not armed"`) and reload the page sandboxed. Disarm is also automatic on
any navigation that leaves the privileged origin (`PrivTab::OnNavigation`).

> **Why teardown is a no-op:** removing the host objects is unnecessary — the
> broker reads `tab.IsArmed()` on the **live** `PrivTab` on every call, so
> clearing the scope IS the atomic kill. A stale-but-installed `window.duetos.*`
> after disarm simply fail-closes.

## The audit trail

Every brokered call (allow and deny) emits one client-tagged JSON line:

```
[priv/audit] {"ts":"2026-06-04T13:43:09Z","client":"browser","origin":"https://claude.ai/code","tab":0,"cap":"fs.write","args":"path=/home/user/x","ok":true}
```

It is mirrored to serial **first** (a security audit must always be visible, even
if the file sink fails) and then appended to `/AUDIT.LOG` via a direct `fs::fat32`
write. `audit.log` is deliberately **outside** the fs scope and its basename is
refused by `CanonicalizeAndContain` case-insensitively, so page JS can neither
read, write, nor forge the trail. `args` records the path only — never payloads.

## Self-tests (boot-verified, headless)

All emit `[<name>] PASS` (or `FAIL check=N` + a `KBP_PROBE` fire):

`[priv-origin-selftest]`, `[priv-path-selftest]` (24-check adversarial battery),
`[priv-arm-selftest]`, `[priv-audit-selftest]`, `[priv-broker-selftest]`,
`[priv-config-selftest]`, `[priv-binding-selftest]` (brokered write invoke+audit,
disarmed fail-closed, ISO-8601 shape, volume-absent no-op),
`[priv-chrome-selftest]` (arm machine, auto-disarm, armed-chrome predicate,
`Ctrl+Shift+Esc` kill switch, affordance truth-table).

## Known limits / GAPs

- **Pixel layout of the armed chrome is unverified headless** — needs a VBox
  visual check (the self-test proves the logic, not the rendering).
- **Symlink-TOCTOU** is closed by string containment + a re-check, which is
  sufficient on FAT32 (no symlinks). A symlink-capable write backend (ext4) must
  re-enforce scope in the fs layer **after** path resolution.
- **`proc.spawn` argv** is validated/audited as a count but **not delivered** to the
  child — the `SpawnPe/ElfFile` ABI carries no argv vector yet. Revisit when it gains one.
- **Assistant `RemoteLlm` backend is inert** — the `net.fetch` transport seam is wired,
  but the off-device LLM path stays disabled until a secret-store for the API key lands;
  the live Assistant backend is the deterministic local heuristic (`assistant_heuristic.cpp`).
- **SPKI pin + redirect detection** in the origin predicate use a build-constant
  pin and a lexical origin check; tightening to live TLS-pin/redirect data awaits
  the TLS layer exposing the leaf SPKI.
- **`kernel.installHandler`** is specified (§13.6) but withheld from v1.

See also: [In-Kernel Web Engine](Web-Engine.md) · [Subsystem Isolation](Subsystem-Isolation.md)
