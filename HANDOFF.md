# DuetOS handoff — 2026-07-28 (session 2)

Branch `claude/host-app-compat`, based on `main` @ `37e8e03f`.

**Headline: DuetOS runs off-the-shelf Windows executables it did not
build.** Stock MSVC binaries and System32 tools now start, run and
terminate under their own control — three of them return *byte-identical
exit codes to real Windows*.

---

## Paste this into a new session

> Continue DuetOS work on `claude/host-app-compat` (based on `main` @
> `37e8e03f`). Read `HANDOFF.md` at the repo root first.
>
> Last session made off-the-shelf Windows .exes run: the blocker was
> `VirtualProtect` failing on every page outside a `VirtualAlloc`
> region, which killed the MSVC CRT before `main()`. Nine host binaries
> now load, run and exit under program control with zero crashes.
>
> **Highest-value next slice: side-by-side DLL loading** — see the new
> Roadmap section "Run a real 64-bit application - side-by-side DLL
> loading (next rung)". The Unity launchers on this dev host measure
> 98.5% import coverage with exactly ONE unresolved import each
> (`UnityPlayer.dll!UnityMain`). Every DLL DuetOS can bind is embedded
> in the kernel image; a PE that imports a DLL sitting beside it on the
> volume has no path at all.
>
> **Use the measurement rigs before guessing.**
> `tools/test/pe-compat-survey.py <dir>` ranks host binaries by how much
> of their import surface DuetOS implements;
> `tools/test/pe-corpus-run.sh <dir>` boots a corpus and grades each one.
> Both are new this session; "which app next" used to be guesswork.
>
> Read "Resolved: the `vulkaninfo.exe` NULL call" below before touching
> the Vulkan DLL — it names a whole bug CLASS worth a gate: the stub-DLL
> export list is a hand-written string in `kernel/CMakeLists.txt`,
> unchecked against the function bodies in the `.c`, and a name missing
> from it makes a guest call address 0.

---

## What landed

Two commits on `claude/host-app-compat`.

### The unlock: `VirtualProtect` on image pages

`DoVirtualProtect` resolved its target only through
`Process::vmap_regions` — the `VirtualAlloc` bookkeeping — so any other
address (the loaded image, the stack, a preloaded DLL) returned FALSE.

MSVC's UCRT caches resolved Win32 thunks in a table inside its own
`.data` and brackets each write with `VirtualProtect(PAGE_READWRITE)` /
`(PAGE_READONLY)`, checking both. The failure propagated:
`try_get_function_slow` → `__acrt_initialize_winapi_thunks` →
`__acrt_initialize` → `__scrt_initialize_crt`, and the CRT called
`__fastfail(FAST_FAIL_FATAL_APP_EXIT)` before `main()`.

**Import coverage was never the problem.** A 12-line `hello.c` with
**100%** of its imports resolved failed identically to a 2.4 MB
`vulkaninfo.exe`. That control is what turned this from log archaeology
into a two-step diagnosis, and it is the technique to reuse: build a
minimal MSVC binary with `/MAP`, and name the faulting RVA from the
linker map.

`ProtectMappedRange` is not a W^X relaxation — user half only, mapped
pages only, and `Win32ProtToPageFlags` still refuses every
`PAGE_EXECUTE_*`, so `PAGE_READWRITE` on a code page yields
writable+NX data as on Windows, never W+X.

### The two diagnostics that made it findable

- **`int 0x29` is `__fastfail`, not an access violation.** Vector 0x29
  has no IDT gate, so it arrived as `#GP` and was reported as
  `STATUS_ACCESS_VIOLATION` at a RIP inside the CRT — which reads like a
  loader bug. It is the CRT deliberately aborting with its reason in
  `ECX`. Now decoded to `STATUS_STACK_BUFFER_OVERRUN` with the reason in
  `ExceptionInformation[0]` and a named WARN line. Gated on ring 3 **and**
  `error_code == 0x29*8+2`, so a kernel-mode `int 0x29` still panics.
- **The `/GS` cookie had never been seeded for any ASLR'd image.**
  `SeedSecurityCookie` bounds-checked a link-time VA (read from the raw
  file's LoadConfig) against `h.image_base`, which the caller had already
  advanced by the ASLR delta — so the check failed for every non-zero
  delta and the seed was silently skipped.

### Smaller

- `SYS_DLL_LOAD_FROM_PATH` resolves api-set contracts through the same
  static table the import binder uses, returning the host module's base
  as Windows does. Bind-time and run-time name resolution had diverged.
  Kept after an A/B cleared it of causing the `vulkaninfo` fault — but
  note it is still not *proven to help*: the `VirtualProtect` fix was
  never tested without it, so none of the wins are attributable to it.
- `/lib/vulkan-1.dll` is published in ramfs, so a runtime `LoadLibrary`
  can find it. It is marked non-essential in the spawn preload set, so
  the `IsEmulator()` trim skipped it and `vulkaninfo` could not load the
  ICD on a kernel whose Vulkan ICD was online and self-tested.
- `api-ms-win-core-localization-obsolete-l1` added to the api-set table
  (a distinct contract head, not a version of `-localization-l1`).
- `run-exe.sh` honours `DUETOS_LOGDIR`. **`/tmp` is wiped between
  `wsl.exe` invocations on this host**, so a serial log written by one
  command is gone before the next greps it — which reads exactly like
  "the run produced no output".

---

## Corpus results (9 binaries, `x86_64-debug`, TCG)

| binary | grade | real Windows |
|---|---|---|
| `hello_mt.exe` (MSVC `/MT`) | **CLEAN** (exit 0) | 0 |
| `hello_md.exe` (MSVC `/MD`) | **CLEAN** (exit 0) | 0 |
| `timeout.exe` | EXIT-0x1 | **1 — exact match** |
| `waitfor.exe` | EXIT-0x1 | **1 — exact match** |
| `where.exe` | EXIT-0x2 | **2 — exact match** |
| `clip.exe` | EXIT-0x1 | 0 — differs |
| `sort.exe` | EXIT-0x1 | 0 — differs |
| `whoami.exe` | EXIT-0x1 | 0 — differs |
| `vulkaninfo.exe` | was EXIT-0xc0000005 | root-caused + fixed, see below |

Every one of these fast-failed before `main()` prior to this session.
Zero crashes, zero fastfails now. The three that differ from Windows all
plausibly trace to stdin/token surfaces (`clip`/`sort` read stdin;
`whoami` wants `LookupPrivilegeDisplayNameW`) — **not yet confirmed**,
and worth a slice, since matching the exit code is the cheapest
end-to-end correctness signal available for a real binary.

---

## Partly resolved: the `vulkaninfo.exe` NULL call

**Cleared:** it is *not* the api-set change. An A/B with that block
disabled reproduced the fault identically (every contract missed again,
still `rip=0`), so the api-set commit is exonerated and kept.

**Fixed one real cause:** `vulkan-1.dll`'s export list — a hand-written
comma-separated string passed inline to `duetos_stub_dll` in
`kernel/CMakeLists.txt` — carried `vkEnumerateInstanceVersion` but not
`vkEnumerateInstanceExtensionProperties` or
`vkEnumerateInstanceLayerProperties`, the two calls a Vulkan app makes
*before* `vkCreateInstance` to discover what it may ask for. Both now
exist and report a count of zero (the v0 ICD negotiates no instance
extensions and exposes no layers), added to the export list, the
function bodies, and `vkGetInstanceProcAddr`'s own name table.

**Still open:** `vulkaninfo` continues to fault at `rip=0`, so it is
resolving at least one more symbol that does not exist. Rather than
keep guessing, a permanent diagnostic now names every miss:
`SYS_DLL_PROC_ADDRESS` emits `[dll-load] GetProcAddress miss ... fn="X"`
at DEBUG level. Returning 0 is correct GetProcAddress semantics and apps
legitimately probe for optional APIs, which is why it is DEBUG and not a
warning — but a caller that does not null-check then executes `call 0`,
and the fault handler can only report "access violation at rip=0" with
nothing saying which symbol. **Read that line in the next run's log and
the remaining diagnosis is one grep.**

### The bug class, stated accurately

The stub-DLL export list lives in a CMake string
(`duetos_stub_dll(vulkan_1 <base> "vkCreateInstance,vk..." "vulkan-1")`),
entirely separate from the function bodies in the `.c`.

Be precise about what a gate would buy, though — **it would not have
caught this one**. `vkEnumerateInstanceExtensionProperties` was absent
from *both* the export string and the `.c`; it was simply never
implemented, and no consistency check between two lists catches a
function missing from both. `tools/test/check-dll-def-exports.py`
(already a host test, so already in CI) covers the `.def`-driven DLLs in
both directions; the `duetos_stub_dll` string-driven ones are uncovered.
Extending it there is still worth doing — the "defined but not in the
export list" direction is a silent hazard, since the function works and
is simply unreachable — but the honest framing is that the real gap here
was **API-surface completeness**, not list drift.

What actually shortens the next one of these is the diagnostic above:
a named `GetProcAddress` miss turns "access violation at rip=0" into the
symbol.

## Verification

- Kernel build: **0 warnings**.
- Host tests: **51/51 pass**.
- Fuzz: all **37 targets build**.
- `clang-format --dry-run --Werror` on every changed file: clean.
- Boot smoke (`ctest-boot-smoke.sh build/x86_64-debug`): PE-compat
  battery `passed=2 failed=1 skipped=134`. The one failure is
  `ring3-dx-demo-window why=no-verdict`, which the previous handoff
  established fails identically on unmodified `main` — **not a
  regression**, and still the best-value DX bug to chase.

### Verification gotchas (carried forward, still true)

1. The local kernel build covers neither host-tests nor fuzz. Run both.
2. `ctest-boot-smoke.sh` **takes a binary-dir argument** — with none it
   exits 2 on a usage line that is easy to mistake for a pass.
3. A TCG boot is ~2.5 min; a 9-binary corpus run is ~25 min. Budget it.
4. One clean boot proves nothing for intermittent faults.
5. `/tmp` is volatile between `wsl.exe` calls — use `DUETOS_LOGDIR`.

---

## Still carried from the previous handoff

The ~60-section Roadmap backlog; the 19 verified-redundant branches
awaiting `git branch -D`; `wip/preserved-worktree-2026-07-27` (**do not
merge** — reference only); the `ring3-hello-pe` guard-modal issue (a
security-policy call about when the guard may auto-escalate, deserving
its own slice); and the WaitQueue detach primitive that would unblock
R1-14 / R1-15 / C4 at once.
