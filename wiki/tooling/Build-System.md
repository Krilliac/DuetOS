# Build System

> **Audience:** All contributors
>
> **Execution context:** Host (Linux dev machine)
>
> **Maturity:** CMake + Clang baseline

## Overview

DuetOS uses CMake (3.25+) with Clang 18+ as both the freestanding
kernel compiler and the cross-compiler for the userland Windows PE
toolchain. The build produces:

- `kernel/duetos-kernel.elf` — the kernel ELF
- `userland/libs/<dll>/<dll>.dll` — userland Win32 DLLs (PE32+)
- `kernel/smoke-pes/<app>/<app>.exe` — generated Win32 smoke fixtures (PE32+)
- `duetos.iso` — hybrid ISO bootable on SeaBIOS + UEFI

## Presets

```bash
cmake --preset x86_64-debug       # Kernel + userland, debug (UBSAN + ASAN-equiv on)
cmake --preset x86_64-release     # Kernel + userland, release
cmake --preset x86_64-debug-san   # Debug + full sanitizer suite (incl. integer family)
cmake --preset x86_64-kasan       # Debug + KASAN-equivalent + full audits
```

Presets live in `CMakePresets.json` at the repo root. All configure
presets inherit `CMAKE_EXPORT_COMPILE_COMMANDS=ON`, so each build tree
contains a `compile_commands.json` database for clangd, clang-tidy, and
other source-indexing tools after configuration.

### Sanitizers in the debug build

The default `x86_64-debug` preset is the **maximum-diagnostics** build:
every check that can be on without making the kernel unbootable or
drowning its own signal is on. Beyond the build-type defaults (KASSERT,
boot self-tests, lock-order audit, klog compiled down to Trace, KASLR,
GDB server) it adds:

- `DUETOS_CAP_AUDIT=Full` — a trace hook on **every** cap-gated
  syscall (not the default every-1024th sample).
- `DUETOS_SHELL_SELFTEST=ON` — bakes `/etc/selftest.sh` into ramfs
  and auto-sources it on boot, so a headless boot exercises the
  shell scripting surface and emits grep-able PASS/FAIL markers.
- `-fstack-protector-all` (debug-scoped, applied in
  `kernel/CMakeLists.txt`) — a stack cookie on **every** function,
  not just the `-fstack-protector-strong` heuristic set. Release
  keeps `-strong` (the every-function prologue/epilogue is real
  per-call overhead the steady-state kernel shouldn't pay).

…plus **both** sanitizer families, the same way:

- `DUETOS_ENABLE_UBSAN=ON` — every kernel TU is built with
  `-fsanitize=undefined,nullability,float-divide-by-zero`
  `-fno-sanitize=function -fno-sanitize-trap=all`. The emitted
  `__ubsan_handle_*` calls resolve to the in-tree runtime in
  `kernel/diag/ubsan.cpp` (one klog WARN + serial line per incident,
  then execution continues — visibility, not enforcement).
- `DUETOS_KASAN=ON` — the in-tree **ASAN-equivalent** diagnostics
  (heap trailer canaries, freed-payload / freed-page poison, plus the
  `+kasan` boot banner). Real `-fsanitize=address` /
  `-fsanitize=kernel-address` cannot run in this freestanding
  `x86_64-unknown-elf` kernel (no shadow memory, no host-style
  runtime; clang rejects the flag for the target), so the in-tree
  layer is the ASan stand-in. TSan / MSan are infeasible for the same
  reason and are not provided.

Dedicated single-axis presets mirror this:

| Preset | What it adds over `x86_64-debug` |
|--------|----------------------------------|
| `x86_64-debug-ubsan` | re-asserts `DUETOS_ENABLE_UBSAN` only |
| `x86_64-debug-asan`  | re-asserts `DUETOS_KASAN` only |
| `x86_64-debug-san`   | the **full suite**: `-fsanitize=integer` family on (`DUETOS_ENABLE_UBSAN_INTEGER`), KASAN, lock-order audit, full cap audit |
| `x86_64-debug-conv`  | `DUETOS_ENABLE_CONVERSION_AUDIT=ON` — `-Wconversion`/`-Wsign-conversion` as **non-fatal** warnings (compile-time analogue of the integer sanitizer; see the conversion-audit note below) |
| `x86_64-debug-redteam` | `DUETOS_ATTACK_SIM=ON` — runs the AttackSim red-team suite at end of `kernel_main`. Escalates the security guard to Enforce and the block write-guard to Deny, which poisons every subsequent image-load / sensitive-LBA write for the session — **not a normal-boot build**. |

Knobs deliberately **not** in the default debug preset, because they
make the build unbootable or unusable rather than more-checked:

- The integer family (`unsigned-integer-overflow`,
  `implicit-conversion`, …). The kernel deliberately relies on
  unsigned wraparound; on the crypto paths (`blake2b`, `argon2id`,
  …) this is *thousands* of false-positive incidents per boot —
  enough to prevent the boot from completing inside the QEMU
  smoke window. Lives in `x86_64-debug-san` for targeted
  conversion/truncation hunts.
- `-Wconversion` / `-Wsign-conversion` as a build-floor gate. Same
  reason as the integer sanitizer above: the kernel narrows
  deliberately and pervasively (network header fields are `u16`,
  lengths live in `u32`, ring indices wrap), so ~150 sites are
  intentional, not bugs. A permanent `-Werror` gate would impose
  explicit-cast friction on every future net/fs line for almost no
  steady-state signal. Instead they are an **opt-in compile-time
  audit** (`x86_64-debug-conv` / `DUETOS_ENABLE_CONVERSION_AUDIT`):
  the flags surface as non-fatal warnings so one build lists every
  narrowing at once, and you eyeball the list for the dangerous
  cases — an oversize length truncated to `u32`, a negative reaching
  an unsigned `size`. (The first audit found zero such bugs; the
  fallout was entirely intentional narrowing and bounds-checked
  decoder paths.)
- `DUETOS_KLOG_DEFAULT=0` (Trace **runtime** default). The
  compile floor is already Trace in debug, so `loglevel t` at
  runtime exposes every trace site on demand; making Trace the
  *boot* default emits ~80 k lines before steady state and the
  smoke never finishes. Verbosity is not a check.
- `DUETOS_PANIC_DEMO` / `CANARY_DEMO` / `TRAP_DEMO` /
  `GDB_DEMO` — deliberate-crash injectors that panic/halt at end
  of `kernel_main`; driven per-invocation by their
  `tools/debug/test-*.sh` scripts, not a preset.
- `DUETOS_ATTACK_SIM` — see `x86_64-debug-redteam` above.

The `x86_64-kasan` preset is the heavier forensic variant (KASAN +
UBSAN + lock-order audit + **full** capability-gate audit);
`x86_64-debug-kasan` remains as a compatibility alias.

## Local Preflight Tools

Two repository-owned scripts cover the checks contributors most often
need before opening a PR:

```bash
# Read-only dependency check for the compiler, linker, PE fixture,
# ISO, and optional QEMU smoke-test toolchains.
tools/dev/doctor.sh --build
tools/dev/doctor.sh --live

# Local CI-style gate. Defaults to doctor + wiki checks +
# clang-format dry-run + CMake configure. Expensive steps are opt-in.
tools/dev/check-local.sh
tools/dev/check-local.sh --build --ctest
tools/dev/check-local.sh --all
```

Use `--preset <name>` with `check-local.sh` to validate one of the
non-default presets from `CMakePresets.json`. `--all` includes the QEMU
smoke harness, so it needs the live-test packages listed below.

## Build

```bash
cmake --build build/x86_64-debug --parallel $(nproc)
cmake --build build/x86_64-release --parallel $(nproc)
```

Output trees:
- `build/x86_64-debug/`
- `build/x86_64-release/`

## Toolchain Baseline

- **Clang 18+** (compiler)
- **CMake 3.25+** (build system)
- **lld** (linker, preferred — `-fuse-ld=lld`)
- **GNU assembler** via clang for `.S` files (Intel syntax)
- **NASM 2.16+** if/when hand-written boot ASM lands; not required
  today
- **MinGW-w64 x86_64 GCC** (`x86_64-w64-mingw32-gcc`) — *optional*.
  Used by `userland/apps/build-smokes.sh` to compile the Win32 smoke
  PE fixtures that CMake embeds into the kernel image. If it isn't
  on the host, CMake detects this at configure time, prints a STATUS
  message naming the install command, and emits each smoke-PE header
  as a `_len = 0` stub via `tools/build/embed-blob.py --empty`. The
  kernel's `SpawnPeFile` checks `pe_len == 0` and skips zero-length
  blobs, so missing fixtures don't break the build or the boot path;
  the smoke PEs simply don't run. Install with
  `sudo apt-get install -y gcc-mingw-w64-x86-64` and re-run CMake
  configure (or `cmake --build --fresh`) to pick it up.
- **Rust** via rustup nightly pinned in `rust-toolchain.toml` (when
  Rust subsystems land — see [Roadmap > Rust bring-up](../reference/Roadmap.md#rust-bring-up))

### Kernel warning floor

The kernel image builds `-Werror` with a floor that goes well beyond
`-Wall -Wextra -Wpedantic -Wshadow` (defined in
`cmake/toolchains/x86_64-kernel.cmake`). The additions are the warnings
that catch *freestanding-kernel* mistakes the base set misses — where
the wrong cast / promotion / stack shape is a fault on real hardware,
not a lint nit:

- **FP tripwires** — `-Wdouble-promotion -Wfloat-equal`. The kernel
  builds `-mgeneral-regs-only -mno-sse`, so any float in codegen is a
  latent `#UD` / corrupted-FPU-state bug.
- **Memory / cast hygiene** — `-Wcast-qual` (const/volatile drop — a
  volatile-drop silently breaks MMIO ordering), `-Wold-style-cast`
  (C++ casts only, so the cast's intent is explicit),
  `-Wpointer-arith`, `-Wover-aligned`, `-Wnull-dereference`,
  `-Wzero-as-null-pointer-constant`.
- **Stack safety** — `-Wvla` (a runtime-sized stack array on our small
  fixed kernel / IRQ stacks is a stack-overflow → triple-fault).
- **Control-flow / init** — `-Wconditional-uninitialized`,
  `-Wimplicit-fallthrough` (force `[[fallthrough]]`), `-Wundef`
  (typo'd config macro evaluating to 0).
- **Surface / format** — `-Wmissing-declarations` (link-surface drift),
  `-Wformat=2`, `-Wcomma`, `-Wextra-semi`, `-Wnon-virtual-dtor`,
  `-Woverloaded-virtual`.
- **`-Wthread-safety`** — clang's lock-capability analysis. Inert until
  headers carry `GUARDED_BY` / `REQUIRES` annotations, but on now so
  the enforcement lands the moment they do.

Intentionally **omitted**: `-Walloca` and `-Wredundant-decls` (clang
no-ops for this target), `-Wcast-align` (never fires on x86_64 — legal
unaligned access; revisit for the aarch64 tier), and the conversion
family (opt-in audit, see [Presets](#presets) above).

`-Wconversion`/`-Wsign-conversion` already gate the **host** tests
(`tests/host`) and `tools/`, where the code is ordinary rather than
hardware-narrowing.

## Live-test Tooling — Install on Demand

The dev host does not ship with `qemu-system-x86_64`,
`grub-mkrescue`, `xorriso`, `mtools`, or `ovmf`. Build-clean is the
only signal available until they are installed.

If a task **legitimately requires** a live-boot smoke test, install
the packages before proceeding:

```bash
sudo apt-get update
sudo apt-get install -y \
    qemu-system-x86 grub-common grub-pc-bin grub-efi-amd64-bin \
    xorriso mtools ovmf
```

Counts as "legitimately requires":

- The commit introduces or changes an observable runtime behaviour
  (scheduler ordering, new syscall return codes, new boot-log line,
  new trap path, new sandbox-policy refusal).
- The commit claims end-to-end correctness for a path that a
  compile-time check cannot prove (address-space isolation, TLB
  shootdown, IRQ routing, timer drift, PE-image execution).
- A previous slice's runtime claim has never been verified on this
  host and the new slice depends on it.

Does **not** count:

- Pure refactors with no behavioural delta.
- Docs / CLAUDE.md / `wiki/` changes only.
- Code that compiles but is not yet wired into any live path.

## Run

```bash
DUETOS_TIMEOUT=30 tools/qemu/run.sh build/x86_64-debug/duetos.iso
```

`DUETOS_QMP=1` (default) exposes a QMP control socket at
`build/<preset>/qmp.sock` — orthogonal to the serial log and the GDB
transport. Inspect or nudge a running guest with
`tools/qemu/qmp.sh status | screenshot <out.ppm> | quit`. Set
`DUETOS_QMP=0` to omit it.

See [QEMU Smoke Tests](QEMU-Smoke.md) for the smoke harness (including
the boot-observability phase ladder, structured `[boot-report]`, and
hierarchical exit codes) and
[Getting Started](../getting-started/Getting-Started.md) for the
end-to-end build + boot flow.

## Hosted Tests

```bash
cd build/x86_64-debug && ctest --output-on-failure && cd -
```

Hosted unit tests live under `tests/`. The on-target self-tests run
during the QEMU smoke boot.

## CI

CI is wired in `.github/workflows/`:

- `build.yml` runs format + debug/release builds and CI smoke checks.
- `release.yml` publishes rolling channels (`latest-debug`,
  `latest-release`) from `main` and `v*` tags.
- `lifetime-downloads.yml` maintains a cumulative download tally on
  a `stats` branch that the README's "lifetime downloads" badge
  reads via shields.io's `endpoint` type. Without it, the badge
  resets to zero every time CI republishes a rolling channel,
  because `softprops/action-gh-release@v2 overwrite_files: true`
  deletes the old asset object and uploads a fresh one with
  `download_count = 0`. The workflow runs before each publish to
  fold accumulated downloads into the tally, plus on a 30-minute
  schedule for organic downloads.

See [Architecture Overview > CI topology](../getting-started/Architecture-Overview.md#14-ci-topology-and-artifact-channels).

## Optional Knobs

| CMake option | Default | What it does |
|--------------|---------|--------------|
| `DUETOS_INSTALLER_KERNEL_EMBED` | `OFF` | Embed the stage-1 `duetos-kernel.elf` bytes into stage 2 via `.incbin` so the disk-installer's `install <handle> INSTALL` writes a real `/system/boot/duetos-kernel.elf` onto the freshly-formatted system partition. **Cost**: doubles the kernel binary size (~10 MiB → ~21 MiB on debug); ISO grows from ~18 MiB to ~28 MiB. **Boot caveat**: the larger kernel image consumes most of the 0..16 MiB DMA zone, currently tripping the `mm/zone` boot self-test. Closing that needs a linker-script change to place the blob at a higher physical region (e.g. 32 MiB+) — separate slice. Until then the option is "build-only" (image lays down, but the resulting kernel doesn't boot itself; the bytes are correct for an installer that targets a different machine).<br>Build with: `cmake -DDUETOS_INSTALLER_KERNEL_EMBED=ON --preset x86_64-debug`. |

## Build Optimisations

Effective speedups in current use:

- **`-DCMAKE_C_COMPILER_LAUNCHER=ccache`** + `-DCMAKE_CXX_COMPILER_LAUNCHER=ccache`
  for incremental rebuilds.
- **`-fuse-ld=lld`** as the linker; `lld` is ~2× `ld.bfd` on the
  full kernel link.
- **Parallel build** with `--parallel $(nproc)`.
- **clang-format**: `find kernel drivers subsystems userland \(
  -name '*.h' -o -name '*.hpp' -o -name '*.c' -o -name '*.cpp' \)
  | xargs clang-format -i` for the bulk format pass; CI runs
  `--dry-run --Werror` over the same set to enforce.

## Related Pages

- [Getting Started](../getting-started/Getting-Started.md)
- [QEMU Smoke Tests](QEMU-Smoke.md)
- [Coding Standards](Coding-Standards.md)
- [Git Workflow](Git-Workflow.md)
