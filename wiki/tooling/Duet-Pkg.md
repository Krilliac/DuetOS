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

## What ships today (Phases 1–3)

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

| Phase | Scope | Anchor row in [`Daily-Driver-Readiness`](../reference/Daily-Driver-Readiness.md) |
|-------|-------|----------------------------------------------------------------------------------|
| 2 | SHA-256 + Ed25519 verification (libsodium) | — |
| 3 | HTTP/HTTPS download via libcurl + resume | — |
| 4 | `repo add/remove/list/sync` + trust DB | — |
| 5 | Resolver + installer + uninstaller | — |
| 6 | `install-local` + build-from-recipe | — |
| 7 | `search` + repo-side CI + `duet-pkg-pack` | — |

Phases run strictly sequentially per the spec; each must build,
link, and pass its tests before the next is touched.

## Related Pages

- [`DUETOS_PKG_IMPLEMENTATION.md`](../../DUETOS_PKG_IMPLEMENTATION.md) — authoritative spec for all seven phases
- [`Daily-Driver-Readiness`](../reference/Daily-Driver-Readiness.md) — where duet-pkg fits in the daily-driver gap audit
- [`Build-System`](Build-System.md) — wider build-system reference
