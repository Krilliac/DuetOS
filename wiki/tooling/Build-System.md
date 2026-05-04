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
- `userland/apps/<app>/<app>.exe` — test fixtures (PE32+)
- `duetos.iso` — hybrid ISO bootable on SeaBIOS + UEFI

## Presets

```bash
cmake --preset x86_64-debug       # Kernel + userland, debug
cmake --preset x86_64-release     # Kernel + userland, release
cmake --preset x86_64-kasan       # Debug + KASAN-equivalent (when wired)
```

Presets live in `CMakePresets.json` at the repo root.

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
- **Rust** via rustup nightly pinned in `rust-toolchain.toml` (when
  Rust subsystems land — see [Roadmap > Rust bring-up](../reference/Roadmap.md#rust-bring-up))

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

See [QEMU Smoke Tests](QEMU-Smoke.md) for the smoke harness and
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
