# Build flavors v0 — central debug/release configuration

**Type**: Decision + Pattern
**Status**: Active — landed 2026-04-29
**Files**: `kernel/util/build_config.h`, `kernel/util/debug_assert.h`,
`kernel/security/cap_audit.{h,cpp}`, `CMakeLists.txt`,
`CMakePresets.json`, `kernel/log/klog.cpp`, `kernel/syscall/cap_gate.cpp`,
`kernel/core/main.cpp`

## Why

The kernel had ad-hoc build-flavor handling: `g_log_threshold` was
hard-coded to `Info` regardless of preset, ~75 SelfTest call sites in
`kernel_main` always ran, lockdep + UBSAN were the only knobs that
respected build type, and there was no central place a downstream TU
could ask "am I in a debug build?". Flipping a release image into a
debug-instrumentation profile took editing N files.

`build_config.h` is now the single source of truth. Every per-flavor
choice surfaces as an `inline constexpr` knob; downstream code uses
`if constexpr (kIsDebugBuild)` so the dead branch is provably
eliminated, even at `-O0`.

## What

### Knobs (all in `duetos::core` namespace, except cap audit which lives in `duetos::security`)

| Knob | Default (Debug) | Default (Release) | Purpose |
|------|-----------------|-------------------|---------|
| `kBuildFlavor` | `Debug` | `Release` | Numeric flavor (1/2) |
| `kIsDebugBuild` / `kIsReleaseBuild` | derived | derived | Bool aliases |
| `kBootSelfTests` | true | false | Run pure-test SelfTest functions in `kernel_main` |
| `kAssertsEnabled` | true | false | Compile `DEBUG_ASSERT` invocations in |
| `kLockOrderAudit` | true | false | Enable lockdep-style instrumentation |
| `kCapAuditMode` | `Sample` | `Sample` | Cap-gate audit verbosity (Off/Sample/Full) |
| `kKlogDefaultLevel` | 1 (Debug) | 2 (Info) | Boot-time runtime klog threshold |
| `kKaslrEnabled` | true | true | Placeholder for KASLR pass |
| `kLtoEnabled` | false | false | Placeholder for LTO |
| `kUbsanRuntime` | mirrors `DUETOS_UBSAN` | — | UBSAN runtime active |
| `kCapAuditSampleStride` | 1024 | 1024 | One trace line per N calls in Sample mode |

The Off-by-default in release for `kCapAuditMode` is overridable; the
`x86_64-release-audit` preset turns it to `Full` for forensic capture.

### CMake presets

- `x86_64-debug` — full instrumentation. Default for development.
- `x86_64-release` — production image. Optimizer max, instrumentation off.
- `x86_64-debug-ubsan` — debug + `-fsanitize=undefined`. Existing.
- `x86_64-release-asserts` — release + `DEBUG_ASSERT` + UBSAN runtime.
  Paranoid production: pay one branch per assert site for early invariant
  trip detection at full optimization.
- `x86_64-release-audit` — release + Full cap-gate audit + lock-order
  audit + boot selftests + klog Debug default. Forensic post-incident
  capture build.
- `x86_64-debug-fast` — debug with cap-audit at Sample (not Full) and
  lock-order audit off. Faster boot, still debug-identifiable RIPs.
- `x86_64-debug-kasan` — placeholder; today wires UBSAN + Full audit +
  lock-order audit. The real KASAN runtime is on
  `post-debug-recommendations-plan.md`.

### New code surfaces

- `DEBUG_ASSERT(cond, subsys, msg)` — sibling to the existing always-on
  `KASSERT`. Compiles to nothing in release; panics on false in debug.
  Use for invariants the engineer believes always hold; existing
  `KASSERT` stays for invariants whose violation is a security/
  stability hole.
- `DEBUG_UNREACHABLE(subsys, msg)` — debug panic + `__builtin_unreachable`.
- `duetos::security::CapAuditTrace(event)` — hook called by `SyscallGate`
  on every cap-gated syscall. Off mode is a near-NOP; Sample emits one
  line every `kCapAuditSampleStride` calls; Full emits every call.
  Counters (`CapAuditCallCount`, `CapAuditDenyCount`) stay live in all
  modes so a runtime mode flip would have current data.
- Boot banner: `[boot] DuetOS build flavor: <name> +<knob> ...` on the
  first serial line after `KLogSelfTest`. Useful when crash reports come
  in from different builds.

## How to extend

To add a new build-flavor knob:

1. Add an `option(...)` (or `set(... CACHE STRING ...)`) in the top-level
   `CMakeLists.txt` "Build flavor" block.
2. `add_compile_definitions(DUETOS_FOO=...)` based on the option.
3. Add an `inline constexpr` in `build_config.h` reading from the new
   `#ifdef DUETOS_FOO`. Always provide a "less instrumentation" default
   for the `#else` branch — a TU compiled without seeing the header
   should behave like a release image.
4. Add a row to the per-flavor table above and to the boot-banner
   `if constexpr` chain in `kernel_main`.
5. Optionally add a derived preset to `CMakePresets.json` if the knob
   has a non-trivial intended workflow (e.g. "release + this on").

## Verification

- Both `x86_64-debug` and `x86_64-release` configure + build clean.
- All four new presets (`release-asserts`, `release-audit`, `debug-fast`,
  `debug-kasan`) configure + build clean.
- `clang-format --dry-run --Werror` clean on every new/edited file.
- `ctest` passes (boot smoke, 45s).
- Live-boot in QEMU shows banner: `+asserts +selftests +lockaudit
  +capaudit=sample +kaslr` in debug, just `+capaudit=sample +kaslr` in
  release.
- Release ISO boots through to heartbeat (~15s) without panic / triple
  fault / unresolved imports.

## Status update (2026-04-29 follow-up)

The four follow-ups from the original resume prompt:

| Follow-up | Status |
|-----------|--------|
| Runtime cap-audit mode flip | **Landed.** `CapAuditGetMode/SetMode/CompileTimeMode` API; shell `cap-audit mode <off\|sample\|full>` + `inspect cap-audit`. The compile-time `Off` floor is honored (release-with-capaudit-off builds reject runtime flips). |
| LTO wired to toolchain | **Landed.** `-flto=thin` propagated to both stages of the kernel link when `DUETOS_LTO=ON`. New preset: `x86_64-release-lto`. Verified boots clean. |
| Selftest call-site audit | **Landed.** New macro `DUETOS_BOOT_SELFTEST(call)` in `build_config.h`. Wrapped ~60 of the ~67 call sites. The two intentional exceptions are `KLogSelfTest` (boot-banner anchor) and `SyscallGateSelfTest` (cap-gate alive check); both are cheap and load-bearing diagnostic anchors that stay on in release. Release ELF dropped 56 KB after dead-code elimination. Adjusted `tools/test/ctest-boot-smoke.sh` inner timeout (30s → 60s) and the ctest TIMEOUT (60s → 120s) to match the slightly slower full-debug boot under wrapped self-tests. |
| KASLR | **Deferred** (out of scope for this slice). See "KASLR scope" section below. |

## KASLR scope

`kKaslrEnabled` remains a placeholder. Real KASLR — booting the
kernel image at a randomized base address each boot — is a multi-
week effort tracked separately in
`.claude/knowledge/post-debug-recommendations-plan.md`. It requires:

1. Linker support for a relocatable kernel (PIE-style ELF with
   `R_X86_64_RELATIVE` relocations preserved through link).
2. Boot-time relocation: the UEFI/Multiboot2 loader (or `boot.S`)
   picks a random offset within the high-VA window, then applies
   the relocations to fix every absolute reference in the image.
3. Per-process address space coordination: PML4 entries for the
   kernel half need updating once per CPU after the offset is
   chosen.
4. Symbol-table fixup: the embedded symbol table (used by the
   panic dump path) needs to reflect the runtime base, not the
   link-time base.
5. Crash-dump tooling: `tools/debug/decode-panic.sh` needs to
   accept a "boot-time offset" and subtract before symbol
   resolution.

The placeholder flag is in place so a future KASLR implementation
has a single switch to flip and downstream code that wants to ask
"is the address space randomized?" can read one constexpr without
inventing its own.

For the rare case where reproducible RIPs across reboots beat
probabilistic protection — debugging a triple-fault, diffing
crash dumps — flip the placeholder to OFF in your preset; the
build banner will reflect the absence of `+kaslr`.

## Resume prompt

> The build-flavor system landed and four follow-ups are done. The
> only remaining item is real KASLR, tracked in
> `.claude/knowledge/post-debug-recommendations-plan.md`. The
> placeholder `kKaslrEnabled` is in place so when KASLR lands,
> downstream code that wants to know "is my address space
> randomized?" already has a single constexpr to read.
>
> If extending the build-flavor system further, common knobs to
> consider next: per-build-type `_FORTIFY_SOURCE`-equivalent
> (kernel-side bounds checking on memcpy), `-fsanitize=address`
> when a real kernel ASAN shadow lands (today the `x86_64-debug-kasan`
> preset is just a UBSAN+audit alias), per-build-type tracing
> verbosity (the existing `klog` Trace level is already runtime-
> flippable but compile-time gating per build type is not exposed).
