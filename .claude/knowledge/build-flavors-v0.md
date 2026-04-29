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

## Resume prompt

> Continue extending the build-flavor system declared in
> `.claude/knowledge/build-flavors-v0.md`. Outstanding hooks:
> - Wire `kCapAuditMode` into the **runtime** (today it's compile-time
>   only); add a `inspect cap-audit` shell command that surfaces
>   `CapAuditCallCount/DenyCount` and a `cap-audit mode <off|sample|full>`
>   flip if a runtime knob is wanted.
> - Implement KASLR for real; today `kKaslrEnabled` is a placeholder.
> - Implement LTO; today `kLtoEnabled` doesn't propagate to the
>   toolchain. Wire `-flto=thin` + `-fuse-ld=lld` when on.
> - Audit the remaining ~70 `SelfTest` call sites in `kernel_main` and
>   wrap the pure-test ones in `if constexpr (kBootSelfTests)`. The
>   four Earlycon adapters are already gated; the rest are still always
>   on.
