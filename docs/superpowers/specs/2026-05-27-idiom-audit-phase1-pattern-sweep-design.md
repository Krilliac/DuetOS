# Idiom Audit — Phase 1 (Tree-wide Pattern Sweep)

## §1 Summary

Phase 1 of the "modernize the codebase" effort sweeps the kernel and userland C++ TUs for the CLAUDE.md-mandated idiom norms that aren't currently enforced — naked `new`/`delete`, sentinel returns where `Result<T, E>` is the right type, raw owning pointers, missing `m_` member prefix, missing `[[nodiscard]]` on `Result`-returning functions, and missing `const` on cross-subsystem API methods. The sweep is **subsystem-by-subsystem, leverage-ordered**: load-bearing headers (`util`, `log`, `sync`, `mm`, `core`) modernize first so downstream subsystems inherit clean signatures. Surfaced latent bugs — including preexisting boot failures or crashes — are fixed in the same PR per the no-deferring rule, with a soft cap of ≤8 ordinary surfaced-bug fixes per PR.

Phase 1 deliberately leaves Class-B mechanical idioms (`typedef`→`using`, C-style casts, C-style enums, `#define` constants, member-init style) to **track #4 (tooling tighten)** for clang-tidy enforcement. Phase 1 also leaves structural file splits of oversize TUs (sched.cpp, syscall.cpp, widget.cpp, boot_*.cpp, pe_loader.cpp) to **Phase 2 (file-driven splits)**, which lands as its own spec/plan cycle after Phase 1 is fully merged.

## §2 Goals and Non-goals

### Goals
- Enforce the CLAUDE.md-mandated idiom norms across every C++ TU in `kernel/` and `userland/` (Wave 6).
- Migrate every error channel currently spelled as a sentinel return to `Result<T, E>` (with per-subsystem error enums where justified).
- Eliminate naked `new`/`delete` in kernel code (route through `UniquePtr<T>::Make` / `kheap::Alloc` / `slab::Alloc<T>` / `Page::Allocate`); in userland C++, route through `std::make_unique`.
- Fix every latent error-handling bug the audit surfaces; fix every preexisting boot failure or crash the audit surfaces.
- Add `[[nodiscard]]` to every function declaration returning `Result<T, E>`.
- Establish a per-PR contract + verification gate that any Phase 1 PR must satisfy before merge.

### Non-goals
- **Pure-C TUs** (e.g., `userland/libs/user32/user32.c`, `wininet.c`, `d3d11.c`, `d3d12.c`, `kernel32_io.c`) — Phase 1 patterns are C++-specific. C TUs need their own track if they ever do.
- **Class B mechanical patterns** (`typedef`→`using`, C-style casts, C-style enums, `#define` constants, member-init style, trivial missing-`const`, trivial `constexpr`) — deferred to track #4.
- **Structural file splits** of oversize TUs — deferred to Phase 2.
- **C++ → Rust migration** of any subsystem — deferred to track #3.
- **C++23 standard uplift** (concepts at API boundaries, `if consteval`, deducing-this) — deferred to track #2.
- **Speculative refactoring** beyond the listed patterns — anti-bloat rules apply.
- **ABI changes** — no syscall numbers move; no kernel-userland error contract changes (kernel-to-userland error mapping at the syscall return remains its current shape).
- **Touching ASM TUs** — `kernel/arch/x86_64/*.S`, `kernel/arch/aarch64/*.S` stay hand-formatted; integer return codes are legitimate at that level.
- **Touching `kernel/util/result.h` itself** beyond additions forced by real call sites; the `ErrorCode` enum is closed unless a real migration forces a new variant.
- **Touching the 27 existing Rust crates** — already in the target language.
- **Touching `third_party/`** — vendored code stays as-is.

## §3 Decomposition Context

"Modernize the codebase" decomposes into four independent tracks, each its own spec/plan/implementation cycle:

| Track | Topic | Status | Notes |
|-------|-------|--------|-------|
| #1 Phase 1 | Idiom audit — tree-wide pattern sweep | **this spec** | The judgement-required and curated patterns. Manual sweep, subsystem-ordered. |
| #1 Phase 2 | Idiom audit — file-driven splits of oversize TUs | next, after Phase 1 lands | Sched/syscall/widget/boot_*/pe_loader; structural splits of the (by then smaller) files. |
| #4 | Tooling tighten | after Phase 1 | clang-tidy ruleset for Class B mechanical patterns, KASAN preset, CI gate tightening. Catches Phase 1's mechanical residue. |
| #3 | Next C++ → Rust subsystem | own cycle | Likely `kernel/net/stack.cpp` or a similarly-shaped target. CLAUDE.md-blessed subsystem with strong lifetime story. |
| #2 | C++23 standard uplift | last | Surgical adoption of concepts, deducing-this, `if consteval`, etc., in places #1 surfaced as wanting them. Speculative tree-wide adoption is anti-bloat. |

The decomposition was explicit in brainstorming: each track's complexity is large enough that bundling them produces a worse plan than four focused ones. This spec is the first.

## §4 Scope

### In scope for Phase 1 (manual sweep, per subsystem)

1. **Naked `new` / `delete`** in kernel TUs → explicit kernel allocators (`kheap::Alloc` / `slab::Alloc<T>()` / `Page::Allocate` / `UniquePtr<T>::Make`). In userland C++ → `std::make_unique` / `std::vector` / `std::unique_ptr`. Placement new is **not** covered.
2. **Sentinel returns** (`return -1;` / `return false;` / `return nullptr;`) representing an error channel → `Result<T, E>` with the appropriate `ErrorCode` (or a per-subsystem error enum where one is justified per §6.2). Call sites adopt `RESULT_TRY` / `RESULT_TRY_ASSIGN` or branch on `.has_value()`. **Excluded:** functions where the sentinel is legitimate semantic value (genuine boolean predicates, `find()`-style nullable returns with no error semantics).
3. **Raw owning pointers** (lifetimes owned by the holder) → `UniquePtr<T>` (kernel) / `std::unique_ptr<T>` (userland). Non-owning observer pointers (back-references, registry observers, kernel structures held in arrays) stay raw.
4. **Missing `m_` prefix** on class/struct member variables in C++ TUs. POD record-like structs with no private members and no methods are excluded (e.g., `struct Vec3 { f32 x, y, z; };`).
5. **Missing `[[nodiscard]]`** on every function declaration whose return type is `Result<T, E>` for any T, E.
6. **Missing `const`** on non-mutating methods *where the const-ness changes the API contract* (i.e., methods on classes whose public methods are consumed across subsystem headers). Trivial in-TU cases deferred to track #4.

### Explicitly deferred to track #4 (clang-tidy ruleset + auto-fix)
`typedef` → `using`; C-style casts → `static_cast`/`reinterpret_cast`/`bit_cast`; C-style `enum` → `enum class`; `#define` constants → `inline constexpr`; trivial missing-`const`; trivial `constexpr` opportunities; member-init-list vs constructor-body init.

### Explicitly deferred to Phase 2
Structural file splits of oversize TUs (sched.cpp 6024 lines, syscall.cpp 4276 lines, widget.cpp 4112 lines, boot_tasks.cpp 3508 lines, boot_bringup.cpp 3468 lines, pe_loader.cpp 3082 lines). Phase 1 modernizes idioms *within* the existing file structure; Phase 2 splits the resulting (smaller, more uniform) files.

### Explicitly deferred to track #3
Any C++ → Rust migration. The 27 existing Rust crates are not touched.

### Out of scope entirely
- `kernel/util/result.h` itself (the primitive). Additions to `ErrorCode` allowed only if a real call site forces it; redesign is not in Phase 1.
- ASM TUs (`kernel/arch/x86_64/*.S`, `kernel/arch/aarch64/*.S`).
- Pre-heap boot allocation surface (allocations that legitimately precede the kheap).
- `third_party/` vendored code.
- All pure-C userland `.c` TUs.
- Test code in `kernel/test/` and `tests/` (uses its own conventions).

## §5 Subsystem Walk Order & Sizing

The sweep proceeds in six waves. **Within a wave, PRs may be authored in parallel and merged in any order. Between waves, wave-(N+1) PRs cannot merge until wave-N is fully merged** — the rationale is that downstream subsystems consume upstream headers, and a wave-N header signature change (e.g., `KlogInit()` returning `Result<void>` instead of `int`) must land before downstream subsystems see those callers in their own sweep.

### Wave 1 — Load-bearing headers (~6 PRs)

These headers are consumed across the tree. Doing them first means every later wave inherits already-modernized signatures.

- `kernel/util/` — Result, types, debug helpers, defer, string helpers (1 PR; self-applies).
- `kernel/log/` — klog APIs used tree-wide (1 PR).
- `kernel/sync/` — spinlocks, mutexes, RW locks, RCU-lite (1 PR).
- `kernel/mm/` — physical frame allocator, paging, slab, kheap, kstack, address spaces (likely 2 PRs: mm-core + mm-paging based on header coupling).
- `kernel/core/` — boot, panic, early-init (1 PR).

### Wave 2 — Kernel runtime (~10-12 PRs)

Depends on Wave 1. These are the largest and most-coupled subsystems.

- `kernel/time/` (1 PR).
- `kernel/syscall/` — 4276 + 2494 lines; split (likely 3 PRs: dispatch / time-syscalls / handlers).
- `kernel/proc/` — 2866-line `ring3_smoke.cpp` + others (1-2 PRs).
- `kernel/sched/` — 6024-line `sched.cpp`; split (likely 2-3 PRs: core / runqueue / context-switch).
- `kernel/security/` (1 PR).
- `kernel/loader/` — 3082-line `pe_loader.cpp`; split (likely 2-3 PRs: pe / elf / dll).
- `kernel/ipc/` residue (1 PR; most of `ipc/` already uses `Result<T, E>` per the grep, but residue exists).

### Wave 3 — Service subsystems (~5-7 PRs)

- `kernel/fs/` non-Rust portions (1-2 PRs; `kernel/fs/duetfs/` is already Rust and is not touched).
- `kernel/net/` — 2131-line `stack.cpp`; split (2 PRs: stack + protocols). Note `net/wireless/` already uses `Result<T, E>` in the grep.
- `kernel/crypto/` (1 PR).
- `kernel/acpi/` non-Rust portions (1 PR; `kernel/acpi/acpi_rust/` is already Rust and is not touched).

### Wave 4 — Drivers not already Rust-fronted (~7-8 PRs)

- `kernel/drivers/video/` — 4112 + 2078 lines (2 PRs).
- `kernel/drivers/audio/` (1 PR).
- `kernel/drivers/input/` (1 PR).
- `kernel/drivers/pci/` (1 PR).
- `kernel/drivers/storage/` residue (1 PR).
- `kernel/drivers/usb/` residue (1 PR).
- Remaining driver classes (1 PR, batched).

`kernel/drivers/iommu/`, `kernel/drivers/gpu/{amd,nvidia}_gpu.cpp`, `kernel/drivers/net/*_fw.cpp` already use `Result<T, E>` and are skipped.

### Wave 5 — Subsystems, shell, apps (~10-12 PRs)

- `kernel/subsystems/win32/` — 2644-line `window_syscall.cpp` + others (3 PRs by file).
- `kernel/subsystems/linux/` — 2080-line `syscall.cpp` (2 PRs).
- `kernel/subsystems/graphics/` — 2434-line `graphics_vk.cpp` (2 PRs).
- `kernel/shell/` — ~9000 lines across multiple TUs (3 PRs by file group).
- `kernel/apps/` — 2687-line `files.cpp` + others (2 PRs).
- Small subsystems (`cpu`, `power`, `env`, `debug`, `diag`, `dlls`) batched (1-2 PRs).

### Wave 6 — Userland C++ TUs (~3-5 PRs)

Pure-C TUs are excluded entirely. C++ TUs (libc++ glue, some apps) are swept here.

- `userland/libc/` C++ glue (1 PR).
- `userland/init/`, `userland/shell/`, `userland/tools/`, `userland/apps/` C++ portions, batched by directory (2-4 PRs).

If the start-of-Wave-6 bloat check shows fewer C++ TUs than expected, this collapses to 1-2 PRs.

### Total estimate

~40-50 PRs over six waves. Each wave is sequential (wave-(N+1) cannot merge until wave-N is fully merged). Within a wave, PRs parallelize.

## §6 Migration Playbook per Pattern

Each pattern below specifies its mechanical rule, its skip rules, and pitfalls. The skip rules are what keep this from becoming a thoughtless `sed`-and-pray sweep.

### §6.1 Naked `new` / `delete` → allocators

**Mechanical (kernel):** Match the allocator to the use:
- Single-instance, owner-scoped lifetime → `UniquePtr<T>::Make(...)`.
- High-churn small type with a dedicated slab class → `slab::Alloc<T>()`.
- Raw byte buffer → `kheap::Alloc(size)`.
- Page-aligned buffer / DMA buffer → `Page::Allocate(count)`.

**Mechanical (userland C++):** `new T(...)` → `std::make_unique<T>(...)`. `new T[N]` → `std::vector<T>` or `std::make_unique<T[]>`. Matching `delete` removed.

**Skip rules:** Placement new (`new (ptr) T(...)`) is a different idiom — left alone. Arch bringup TUs allocating before kheap exists — out of scope per §4. Intentionally leaked globals — left alone with a comment explaining why.

**Pitfalls:** If callers observe the pointer non-owningly, convert the *owner* to `UniquePtr<T>` and pass raw `T*` (or a non-owning view type) to observers — do not propagate `UniquePtr<T>` everywhere. `delete this` patterns require a structural rethink, not a pointer swap — flag as out-of-PR scope and STUB/GAP-marker if encountered.

### §6.2 Sentinel returns → `Result<T, E>`

**Mechanical:**
```cpp
// Before
int Foo() { ...; return -1; }              // -1 = error
// After
Result<void> Foo() { ...; return Err{ErrorCode::Foo}; }
```
Callers adopt `RESULT_TRY(Foo());` or branch on `.has_value()`. Functions that returned dual-channel `int` (e.g., `int bytes_read; -1=error`) become `Result<usize>`, not preserved as awkward `int`.

**Skip rules:**
- Genuine boolean predicates (`bool IsLocked() const`) — stay `bool`.
- Nullable-pointer lookups with no error semantics (`User* FindById(id);`) — stay `T*`. Promote to `Result<T*, ErrorCode>` only when callers need to distinguish "not found" from "lookup failed."
- Measured hot paths where `Result` construction cost is observable — document with a comment, leave as-is.

**`ErrorCode` selection rule:** Pick the most specific existing variant. Do **not** add new variants without surfacing the case in the PR description. The kernel-wide enum has 18 variants today (see `kernel/util/result.h:93`); each addition needs justification.

**Per-subsystem error enum rule:** Define one (e.g., `fs::Error`, `mm::Error`) only when (a) the subsystem has 5+ failure modes that map awkwardly to `ErrorCode`, *or* (b) the subsystem's errors are consumed by other subsystems that should branch on the typed variant. Default to `ErrorCode`. The `Result<T, fs::Error>` shape works via CTAD; `RESULT_TRY` propagates the typed error through chained calls in the same E family.

**Pitfalls (aggressive bug-fix policy in action):**
- Callers ignoring the original sentinel → fix the caller in the same PR.
- Wrong sentinel checks (`== -1` when other negative values were also errors) → fix the caller.
- Conversions of widely-called functions (`KlogX`, `KheapAlloc`) — split into per-call-site sub-commits within the PR for reviewability.

### §6.3 Raw owning pointers → `UniquePtr<T>`

**Mechanical:** Member or local variable holding a heap-allocated object whose lifetime ends with the holder's → `UniquePtr<T> m_thing;` instead of `T* m_thing;`. Constructor sets via `UniquePtr<T>::Make(...)`. Destructor stops doing manual `delete`.

**Skip rules:**
- Non-owning observer pointers (back-pointers, cached lookups, registry references) — stay raw.
- Pointers whose lifetime is owned by another subsystem (kernel structures held in a global registry) — stay raw; document the owner.
- Pointers to statics / never-deallocated objects — stay raw.

**Pitfalls:** Manual nulling across function calls becomes `std::move(uptr)` or `UniquePtr::release()`. If the same heap object is held by `T*` in multiple structures, decide which is the owner *before* converting.

### §6.4 `m_` prefix on members

**Mechanical:** Class/struct member variables in C++ TUs get the `m_` prefix. Constructor initializer lists update: `: m_size(size)` instead of `: size(size)`. Every reference within the class follows.

**Skip rules:** POD record-like structs with no private members and no methods (`struct Vec3 { f32 x, y, z; };`). Union members. Public global structs that exist purely as ABI shapes (trap frame layouts touched from assembly — offsets must match).

**Pitfalls:** Rename-per-file, single commit per class — don't bundle multiple class renames into one mega-commit; they are not coupled and a single bad rename is easier to revert when isolated.

### §6.5 `[[nodiscard]]` on `Result<T, E>`-returning functions

**Mechanical:** Every function declaration whose return type is `Result<T, E>` gets `[[nodiscard]]` at the declaration site (header or in-class definition; not the definition site).

**Skip rules:** Lambdas, function pointer types (syntactically can't annotate). The `Result` class itself is already `[[nodiscard]]` (see `kernel/util/result.h:180`), so this only matters when the compiler diagnostic uses the function annotation rather than the type — which it does for many call patterns.

**Pitfalls (aggressive bug-fix policy):** The build surfaces callers that discard a `Result`. Each gets fixed: handle the error (`RESULT_TRY`, branch on `has_value()`, or `RESULT_LOG_AND_DROP`). Fire-and-forget calls where ignoring is genuinely correct get `RESULT_LOG_AND_DROP` *with a comment* explaining why dropping is right; `(void)foo()` without justification is not acceptable.

### §6.6 `const` on non-mutating methods (API contract)

**Mechanical:** Methods that don't modify non-`mutable` state, in classes whose public methods are consumed across subsystem headers, get `const`.

**Skip rules:** In-TU helpers and private utility methods that clang-tidy will catch later (deferred to track #4). Methods that return non-const pointers/references to members (these need a const-overload pair, which is real design work, not a pattern sweep).

**Pitfalls:** "Logical const" with a memoization cache requires `mutable` on the cache. That's a design decision, not a mechanical change — if encountered, surface in the PR description and decide explicitly.

### §6.7 Cross-cutting — surfaced-bug fix protocol

The aggressive policy covers three categories of surfaced bugs, all fixed in the same PR that surfaces them:

1. **Latent error-handling bugs** at sentinel-return sites (callers ignoring the sentinel, wrong sentinel check, dual-channel `int` mishandled).
2. **Preexisting boot failures or crashes** that the audit happens to surface (either via the gate's boot smoke or via the new shapes exercising a previously-untaken code path).
3. **Memory-ownership bugs** (mismatched `delete`/`delete[]`, leaks, use-after-free) that the `UniquePtr` migration exposes.

Each fix is its own commit within the PR titled `fix(<subsys>): <symptom>`, listed in the PR description's "Surfaced bugs" section. A subsystem-PR's commit log separates pattern-migration commits from bug-fix commits so a reviewer can mentally split the two.

**Boot failures/crashes are exempt from the §8 ≤8-surfaced-bug cap** (see §8 R1). They are severe enough that deferral is never the right call.

**Baseline rule:** If the baseline (origin/main, before any sweep) boot smoke fails when the PR opens, the PR fixes the baseline failure *before* adding any pattern migration on top. A clean baseline is the precondition for any sweep PR.

## §7 Per-PR Contract & Verification Gate

### §7.1 Branch and title shape

- Branch: `claude/idiom-audit-phase1-<subsystem>` (e.g., `claude/idiom-audit-phase1-mm`).
- Title: `idiom-audit(<subsystem>): phase-1 sweep` (e.g., `idiom-audit(kernel/mm): phase-1 sweep`).
- Multi-PR subsystems suffix with the sub-area: `idiom-audit(kernel/sched/runqueue): phase-1 sweep`.

### §7.2 PR description structure

Every Phase 1 PR description includes the following sections in order:

1. **Wave & dependency.** "Wave N. Depends on Wave N-1 merged (PRs #X, #Y, #Z)." Upstream PRs listed by number.
2. **Pattern coverage table.** For each Phase-1 pattern (§6.1 – §6.6): count of sites converted, count of sites deliberately skipped, with rationale grouped by skip-rule.
3. **Surfaced bugs.** Bulleted list, one per surfaced latent bug. Format: `<subsys>: <symptom> — fixed in <commit-sha>`. Each entry has a one-line description of the bug and a one-line description of the fix.
4. **ErrorCode additions.** Any new variants added to `duetos::core::ErrorCode` or to a per-subsystem error enum, each with justification (which call site forced it; why an existing variant didn't fit).
5. **Out-of-scope items spotted.** Deferred work surfaced by the audit that's NOT this PR's job. Each gets a `// STUB:` or `// GAP:` marker in code AND a row in `wiki/reference/Roadmap.md`.
6. **Verification gate.** Copy-paste of the verification-command output (or relevant tail), proving each gate passed locally. See §7.4.

### §7.3 Commit shape within the PR

The commit log inside one PR looks like:
```
idiom-audit(<subsys>): naked new → allocators
idiom-audit(<subsys>): sentinel returns → Result<T,E>
idiom-audit(<subsys>): raw owning ptrs → UniquePtr
idiom-audit(<subsys>): m_ prefix on members
idiom-audit(<subsys>): [[nodiscard]] on Result returners
idiom-audit(<subsys>): const on non-mutating API methods
fix(<subsys>): <surfaced bug 1>
fix(<subsys>): <surfaced bug 2>
test(<subsys>): regression test for <bug 1>
```

Rules:
- **Each commit compiles cleanly** — no "WIP" or "broken intermediate" commits. `git bisect` must work.
- **Each commit passes hosted ctest** — CI runs the gate per-commit, not just per-PR.
- Pattern commits go first (in any order), bug-fix commits next, regression-test commits last.
- Commits without surfaced patterns in their category are simply omitted (a subsystem with no raw owning pointers does not emit an empty `→ UniquePtr` commit).
- `Co-Authored-By:` trailer on every commit per CLAUDE.md's commit format.

### §7.4 Verification gate — mandatory before merge

The PR is mergeable only when every line below produces clean output. The gate is run locally (cheap, fast) and re-run by CI (authoritative). Discrepancies between local and CI block merge.

1. **Build clean (zero warnings, zero errors):**
   ```bash
   cmake --build build/x86_64-release --parallel $(nproc) 2>&1 | tail -50
   ```
   `-Wall -Wextra -Wpedantic -Werror` already enforces this; the gate verifies no new warnings.

2. **Format clean:**
   ```bash
   find kernel drivers subsystems userland \( -name '*.h' -o -name '*.hpp' -o -name '*.c' -o -name '*.cpp' \) \
     | xargs clang-format --dry-run --Werror
   ```
   Exit code 0. ASM (`.S`) files are not formatted (see CLAUDE.md).

3. **Hosted ctest clean:**
   ```bash
   cd build/x86_64-release && ctest --output-on-failure
   ```
   All previously-passing tests still pass. New regression tests for surfaced bugs added.

4. **Boot smoke clean — runs ≥3 times:**
   ```bash
   for i in 1 2 3; do
     DUETOS_TIMEOUT=20 tools/qemu/run.sh --headless build/duetos.img > /tmp/duet-smoke.$i.log
     tools/test/boot-log-analyze.sh /tmp/duet-smoke.$i.log || exit 1
   done
   ```
   All three runs exit 0. If any one fails, the PR investigates per CLAUDE.md's intermittent-bug pattern-matching — re-running until green and shipping is not acceptable.

5. **STUB/GAP discipline:**
   ```bash
   git diff origin/main..HEAD | grep -E "^\+.*// (STUB|GAP):" | head
   ```
   Every added STUB/GAP marker has a corresponding entry in the PR description's "Out-of-scope items spotted" section AND a row in `wiki/reference/Roadmap.md` when it represents future work.

6. **No new bypass of cap gates / safety checks:**
   ```bash
   git diff origin/main..HEAD -- 'kernel/subsystems/**'
   ```
   Reviewer (and author) confirms no subsystem code mutates kernel-internal state outside cap-gated syscalls (per CLAUDE.md's Subsystem-Isolation rules). Any new kernel-mediated syscall path is cap-gated.

### §7.5 Wave dependency enforcement

- A wave-N PR cannot be opened (and definitely cannot merge) until all wave-(N-1) PRs are merged into `main`. The PR description's "Wave & dependency" section lists upstream PR numbers explicitly so a reviewer can verify.
- Wave-N PRs may be drafted and tested in parallel locally during wave-(N-1) execution — but they don't land in CI as PRs until the wave gate opens.
- This is a spec rule, not tooling enforcement. The cost of breaking it is real (downstream PRs fight upstream header changes mid-flight).

### §7.6 Conflict resolution within a wave

- Two PRs in the same wave touching the same load-bearing header (e.g., `kernel/util/result.h` extensions, `kernel/sync/lock.h` signatures): the **earlier-opened PR** has right-of-way. The later one rebases onto `main` *after* the earlier one merges, re-running the verification gate.
- Two PRs in the same wave touching unrelated headers: merge in either order, no rebase needed.

### §7.7 Rollback policy

- A merged Phase 1 PR that breaks boot smoke or hosted ctest in CI gets **reverted within 24h** (a clean `git revert`), not patched forward. The reverted PR re-opens; the author fixes locally; the gate runs again; a fresh PR replaces the bad merge.
- Reason: patching forward against a broken base subsystem head means every downstream wave PR inherits the broken state.
- A revert is not a failure verdict on the PR — it is the load-bearing protection against waves drifting.

## §8 Risk, Hazard Subsystems, Deferrals

### §8.1 Top risks

**R1 — Sentinel migration surfaces too many latent bugs for one PR.**
The aggressive bug-fix policy (§6.7) assumes surfaced-bug count is bounded. If a subsystem (sched is the likely candidate) reveals 30+ broken error-handling sites, fixing them all in one PR makes it unreviewable.

*Mitigation:* per-PR soft cap of **≤8 ordinary surfaced bug fixes**. "Ordinary" means latent error-handling bugs at sentinel-return sites (§6.7 category 1) and non-crashing memory-ownership bugs (§6.7 category 3 that don't produce a baseline boot failure). If exceeded, split into a "pattern sweep" PR (mechanical `Result`-shape migration; callers use `RESULT_TRY` or get a temporary `// FIXME(idiom-audit): error path unhandled` comment) followed by a "bug-fix series" PR targeting the FIXMEs. The PR description records the cap was hit. This is the **only** sanctioned departure from the aggressive policy and does not generalize.

**Preexisting boot failures and crashes are exempt from the cap** (§6.7 category 2, plus any category-3 memory bug that produces a boot failure). They are severe enough that deferral is never the right call, and they are rare enough that PR-reviewability is dominated by the can't-ship-a-broken-boot rationale.

**R2 — ErrorCode enum bloats.**
The migration pressures the kernel-wide enum to grow with subsystem-specific failure modes.

*Mitigation:* ErrorCode additions require explicit justification per §6.2's selection rule. Per-subsystem error enums are the preferred relief valve. PR reviewer rejects unjustified additions.

**R3 — Wave drift: wave-(N+1) PR authored against a stale wave-N base.**
Wave-(N+1) work happens on local branches before the wave gate opens; `main` moves underneath.

*Mitigation:* a wave-(N+1) PR rebases onto `main` immediately before opening, then re-runs the full verification gate. If the rebase produces conflicts deeper than the PR's own diff, the author audits whether their local plan still applies before pushing.

**R4 — Surfaced bug requires a structural fix bigger than the subsystem PR.**
Some surfaced bugs ("the entire locking discipline in this TU is wrong") cannot be fixed in-place during a pattern sweep.

*Mitigation:* STUB/GAP-marker the symptom in code, file a Roadmap entry, AND raise it explicitly in the PR description's "Out-of-scope items spotted" section. The aggressive bug-fix policy does **not** apply to structural rewrites — those become their own slices, brainstormed separately.

**R5 — Boot smoke flake or genuine intermittent regression in the gate.**
Per the project's intermittent-bug protocol, intermittent symptoms are bugs (collision-class, refcount-asymmetry, scheduling-sensitive) — not flakes.

*Mitigation:* the gate runs boot smoke at least 3 times (§7.4 item 4). 3/3 green = pass. 1/3 fail = author investigates per CLAUDE.md's intermittent-bug pattern-matching (collision class, refcount asymmetry, etc.). "Re-run until green and ship" is not acceptable.

**R6 — Header signature change in a wave-N PR breaks a wave-N peer's diff.**
Two PRs in the same wave touch the same load-bearing header (e.g., `kernel/util/result.h`) and conflict.

*Mitigation:* §7.6's right-of-way rule. PR descriptions list affected headers explicitly so peers can spot conflicts before they bite.

### §8.2 Known-hazard subsystems (additional pre-flight beyond the standard gate)

- **`kernel/sched/`** — scheduler trampoline ABI is stack-align-sensitive (a primer-pad regression once produced UBSan flooding on tray-click; see `tools/test/tray-click-ubsan-repro.sh`). Phase 1 sweep here MUST run that repro and confirm UBSan count stays at 0. `Result`-shape conversion of context-switch / trampoline functions must preserve calling convention exactly.
- **`kernel/syscall/`** — syscall numbers are ABI-forever (CLAUDE.md). Phase 1 sweep MUST NOT change any syscall number, dispatch table index, or argument shape. `Result`-shape conversion is internal-only; the kernel↔userland error contract stays its current shape.
- **`kernel/subsystems/win32/`** — subsystem-isolation rules apply (see `wiki/kernel/Subsystem-Isolation.md`). The audit will surface historical violations (subsystem code touching kernel state outside cap-gated syscalls). Those are bugs to fix in the same PR per the aggressive policy. The reviewable signal: *"could a malicious PE use this path to do something a native DuetOS process couldn't?"*
- **`kernel/loader/pe_loader.cpp`** — correctness measured by PE smoke tests (mingw-built blobs in `tools/test/ring3-*`). Phase 1 sweep MUST keep every existing ring3 PE smoke test passing. New STUB markers in the loader are not acceptable — the loader is load-bearing for the entire Win32 subsystem.
- **`kernel/proc/`** — `ring3_smoke.cpp` (2866 lines) is the canonical surface for ring-3 regressions. Phase 1 sweep preserves every existing ring3_smoke pass line.

### §8.3 Open questions deferred to writing-plans

The writing-plans skill will produce per-wave implementation plans from this spec. The spec deliberately leaves these unresolved because they're best decided when the actual diff topology is in view:

- Exact per-subsystem PR breakdown for the large subsystems (sched, syscall, loader, video, win32, linux, graphics, shell, apps) — sub-area boundaries are decided by the writing-plans phase based on header coupling.
- Whether to introduce any per-subsystem error enums (`mm::Error`, `sched::Error`, `fs::Error` extensions, etc.) — decided per-subsystem during plan execution.
- The exact value of the surfaced-bug cap (§8 R1's "≤8") — calibrated empirically as Wave 1 lands; revisit if Wave 1 PRs consistently overflow or consistently use 0-1 of the budget.
- Whether Wave 6 (userland C++ TUs) actually has enough load-bearing C++ to warrant 3-5 PRs, or whether it collapses to 1-2 — confirmed by running the bloat check on `userland/` C++ TUs only at the start of Wave 6.

### §8.4 Calendar shape (indicative, not commitment)

| Wave | Subsystems | PR count | Focused-work estimate |
|------|-----------|----------|-----------------------|
| 1 | util, log, sync, mm, core | ~6 PRs | ~1 week |
| 2 | time, syscall, proc, sched, security, loader, ipc | ~10-12 PRs | ~2 weeks |
| 3 | fs, net, crypto, acpi | ~5-7 PRs | ~1 week |
| 4 | drivers (video, audio, input, pci, storage, usb) | ~7-8 PRs | ~1 week |
| 5 | subsystems/{win32,linux,graphics}, shell, apps, small subsystems | ~10-12 PRs | ~2 weeks |
| 6 | userland C++ TUs | ~3-5 PRs | ~3 days |

**Total ~6-8 weeks of focused work.** Real calendar likely longer (interruptions, surfaced bugs requiring deeper investigation, CI flakes investigated per the intermittent-bug protocol).

After Phase 1 lands, Phase 2 (file-driven splits of the now-uniform oversize files) gets its own spec/plan cycle.

## §9 Track Relationships

Phase 1 is sequenced relative to the other three "modernize" tracks. The relationships:

- **Phase 1 unblocks track #4** by giving clang-tidy a uniform tree to enforce against. Class B mechanical patterns deferred from Phase 1 land via clang-tidy rules in #4.
- **Phase 1 unblocks Phase 2** by reducing the oversize-file line counts and unifying their idioms. Phase 2's structural splits become judgement calls about API boundaries, not concurrent untangling of stylistic noise.
- **Phase 1 is independent of track #3** (next Rust subsystem). Subsystems migrated to Rust during or after Phase 1 are simply removed from later waves' scope.
- **Phase 1 is independent of track #2** (C++23 standard uplift). Track #2 is surgical and applies in places Phase 1 surfaced as wanting more expressive features.

The sequencing locked in at brainstorming: **#1 Phase 1 → #1 Phase 2 → #4 → #3 → #2**, each as its own spec/plan/implementation cycle.

## §10 Self-test sentinels

When implementation begins, each wave's first PR adds a boot-log sentinel via `arch::SerialWrite` from the subsystem's existing self-test hook:

- Wave 1: `[idiom-audit-selftest] PASS (wave-1)`
- Wave 2: `[idiom-audit-selftest] PASS (wave-2)`
- ... etc through Wave 6.

This gives the boot-log analyzer a grep-able PASS line per wave, matching the pattern used by Pass A/B/C/D in prior specs (`[pass-d-selftest] ...`). The sentinel fires from a representative subsystem in the wave (e.g., Wave 1's sentinel fires from `kernel/util/result.cpp`'s `ResultSelfTest()` once the wave-1 PRs are merged).

Wave-N gate: `tools/test/boot-log-analyze.sh` adds a row that the sentinels from waves 1..N are present in the log. Missing sentinel = wave gate fails.
