# duet-pkg — DuetOS Federated Package Manager

> **Audience:** package authors, repo maintainers, daily-driver
> operators who want to install third-party software
>
> **Maturity:** Phase 1 (manifest parsing + local registry). No
> network, no crypto, no install path yet.

`duet-pkg` is the package manager DuetOS will eventually ship.
The implementation lands in seven phases (see
`DUETOS_PKG_IMPLEMENTATION.md` in the repo root for the full
spec); this page describes the **current** state of the
binary plus pointers to what's coming.

## What ships today (Phases 1–7 — complete)

| Subcommand | Status | Notes |
|------------|--------|-------|
| `list --installed` | Implemented | Reads `/var/lib/duet-pkg/installed/*.toml` (override with `DUET_PKG_REGISTRY`). |
| `info <repo.toml> <name>` | Implemented | Parses a local repo manifest and prints one package's fields. Phase 4 swaps the path argument out for a synced-repo lookup. |
| `--help` / `-h` | Implemented | Lists every documented subcommand + which phase implements each. |
| `install` / `remove` / `update` / `search` / `repo *` / `key *` / `install-local` / `build` | Stubs | Print `not yet implemented in this phase`. The verbs are recognised so misspellings still produce `unknown subcommand`; the implementations land in later phases. |

Phase 2 added the crypto core (`src/crypto/`):
SHA-256 (`Sha256HexOfFile`, `VerifySha256`), Ed25519 detached
signatures (`VerifySignature` + `VerifySignatureOfFile`), PEM
key loader (`LoadPublicKeyFromFile`), `ed25519:<base64>` parse +
round-trip (`ParsePublicKeyFromTomlString` /
`PublicKeyToTomlString`), and a canonical key fingerprint
(SHA-256 of raw 32 bytes, lowercase hex). All via libsodium —
no roll-your-own crypto.

Phase 3 added the network core (`src/net/`): `Download` over
HTTP/HTTPS via libcurl with progress callback + resume via
`Range:` headers (with automatic fallback to a full download
when the server returns 200 instead of 206). TLS verification
on by default; `FetchOptions::allow_insecure` is the only knob
that turns it off.

Phase 4 added the repo manager (`src/repo/repo_manager.{hpp,cpp}`):
`repo add/remove/list/sync` end-to-end, with `repo add` fetching
the remote `repo.toml` + `repo.toml.sig`, parsing the embedded
`signing_key`, checking its SHA-256 fingerprint matches the
caller's `--trust-key`, verifying the detached signature, then
caching everything to `$DUET_PKG_CONFIG_DIR` (default
`/etc/duet-pkg`). Trust DB primitives (`SaveTrustedKey`,
`LoadTrustedKey`, `RemoveTrustedKey`, `ListTrustedFingerprints`)
back the `key list/trust/revoke` subcommands.

Phase 5 added the resolver + installer + uninstaller. The
resolver (`src/resolve/resolver.{hpp,cpp}`) is Kahn's-algorithm
topo sort over the package dep graph, with stable name-sort
tie-breaking, repo-priority "first-write-wins" lookup, and hard
detection of cycles / missing deps / missing target. The
installer (`src/install/installer.{hpp,cpp}`) does the full
download → SHA-256-verify → Ed25519-verify-against-repo-key →
`tar xzf` → atomic `current` symlink → `/usr/local/bin/<leaf>`
shim → registry entry write pipeline, with rollback on any step
failure. The uninstaller (`src/install/uninstaller.{hpp,cpp}`)
runs the inverse, gated on a reverse-dep check that refuses
removal of a package any other installed package depends on
unless `--force`. The CLI's `install` / `remove` / `update`
subcommands all dispatch through these.

Phase 6 added the power-user paths.
`Installer::InstallLocal(tar)` accepts a local tarball,
extracts it, reads the in-tarball `manifest.toml`, hashes the
tarball for the registry record, and runs the same place +
symlink + register pipeline as the remote install — minus the
signature step (the operator passing a path is the trust gate;
a loud stderr warning surfaces the choice). The recipe
`Builder` in `src/build/builder.{hpp,cpp}` parses
`recipe.toml`, downloads + verifies the source tarball, runs
the build system (`cmake | make | script`) into a staging
prefix, packages staging into a `.tar.gz`, and hands the
result to `InstallLocal`. The CLI's `install-local` and
`build` subcommands wire both.

Phase 7 added the search surface + the maintainer-side
packaging tool + the validating CI workflow. The
`duet-pkg search <query>` subcommand does case-insensitive
substring match against name + description across all synced
repos, ranks by match-offset (name hit at byte 0 beats
description hit at byte 12), and tags each hit with its
installed-state. The `duet-pkg-pack` binary (separate target,
same lib) accepts `--name / --version / --bin / --dep` flags +
an Ed25519 private-key PEM (or `DUETOS_SIGNING_KEY` env), stages
the package, tars it, signs the tarball, and prints the exact
`[[packages]]` block + key fingerprint for the repo maintainer
to paste into `repo.toml`. The repo template at
`tools/pkg/repo-template/` ships a fully-working
`.github/workflows/validate.yml` (calls `validate.py`) that
re-parses every manifest, re-hashes every tarball, and
re-verifies every signature on every PR.

## Layout

```
tools/pkg/
├── CMakeLists.txt           # Standalone — fetches toml++ via FetchContent
├── src/
│   ├── main.cpp             # CLI entry point
│   ├── error.hpp / .cpp     # DuetPkgError + ErrorCode + Expected<T> alias
│   ├── cli/cli.hpp / .cpp   # Argument parser + dispatcher
│   ├── repo/
│   │   ├── repo_manifest.hpp / .cpp     # repo.toml parser
│   │   └── package_manifest.hpp / .cpp  # per-package manifest.toml parser
│   └── registry/registry.hpp / .cpp     # Local installed-package DB
└── tests/
    ├── test_manifest_parse.cpp           # Frameworkless unit tests
    └── fixtures/                         # repo_basic.toml + package_basic.toml
```

`tests/host/` and `tools/pkg/` share the same "standalone hosted
binary, separate from the freestanding kernel build" pattern.
Neither is pulled into the default root build because the kernel
toolchain (`cmake/toolchains/x86_64-kernel.cmake`) targets
`x86_64-unknown-none-elf` with no stdlib — hostile to anything
that wants `<filesystem>` or `<expected>`.

## Building

Two paths. The first is the recommended way for active iteration
on duet-pkg; the second matches the spec's
`option(DUETOS_BUILD_TOOLS ...)` knob.

### Standalone (fast, what most contributors use)

```bash
cmake -S tools/pkg -B build/duet-pkg -DCMAKE_BUILD_TYPE=Debug
cmake --build build/duet-pkg --parallel $(nproc)
ctest --test-dir build/duet-pkg --output-on-failure
./build/duet-pkg/duet-pkg --help
```

The first configure clones `toml++` (header-only) via
FetchContent. Subsequent configures are instant.

### Driven by the root build (`DUETOS_BUILD_TOOLS=ON`)

```bash
cmake -DDUETOS_BUILD_TOOLS=ON --preset x86_64-debug
cmake --build build/x86_64-debug --target duet-pkg-ext
```

This wires the standalone tree as an `ExternalProject_Add` so
the root build can fan it out without forcing the kernel
toolchain onto a hosted binary. Default is OFF — the kernel
ISO build doesn't depend on duet-pkg.

## Schemas

The full TOML schemas live in
[`DUETOS_PKG_IMPLEMENTATION.md`](../../DUETOS_PKG_IMPLEMENTATION.md)
in the repo root. The Phase-1 parser accepts all three:

- **`repo.toml`** — index of a repo's packages
  (`[repo]` table + `[[packages]]` array of tables)
- **per-package `manifest.toml`** — flat top-level fields
  (name, version, arch, …) plus an `[install]` table
- **registry entry** — one TOML file per installed package
  at `/var/lib/duet-pkg/installed/<name>.toml`

Fixtures: `tools/pkg/tests/fixtures/repo_basic.toml` and
`package_basic.toml` are the canonical happy-path examples;
look there for the exact field shapes.

## Error model

Every fallible function returns `std::expected<T,
DuetPkgError>`. Mirrors the kernel's `Result<T, E>` discipline,
adapted for a hosted binary that can pay for `std::string`. The
flat `ErrorCode` enum covers every phase up to 7 — codes for
later phases are inert today but stable so the surface doesn't
churn.

```cpp
auto repo_or = duet::repo::LoadRepoManifestFromFile(path);
if (!repo_or) {
    return std::unexpected(repo_or.error());
}
```

`main()` catches every error from `cli::Run`, prints the
`message`, and prints `detail` only when `--verbose` (`-v`) is
set. Exit codes: 0 on success, 2 for argument / shape errors,
1 for everything else.

## What lands next

All seven planned phases are complete. Future work:

- Per-process syscall integration when DuetOS hosts duet-pkg
  itself (the dev-host builds are the current verification).
- A native HLSL-aware build system for DirectX-bearing packages
  (depends on the Win32 graphics track).
- Mirror lists + per-package signature counts.
- `duet-pkg-pack create` from a recipe (currently it only
  packages already-built bins).

## Related Pages

- [`DUETOS_PKG_IMPLEMENTATION.md`](../../DUETOS_PKG_IMPLEMENTATION.md) — authoritative spec for all seven phases
- [`Daily-Driver-Readiness`](../reference/Daily-Driver-Readiness.md) — where duet-pkg fits in the daily-driver gap audit
- [`Build-System`](Build-System.md) — wider build-system reference
