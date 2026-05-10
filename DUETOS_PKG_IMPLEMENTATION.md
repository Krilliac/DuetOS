# DuetOS Package Manager — Claude Code Implementation Guide

## Overview

This document is the authoritative implementation spec for `duet-pkg`, the DuetOS federated package manager. Hand this file to a Claude Code session as the first message. It covers: what to build, in what order, the full architecture, file layout, and what you (Nathan) need to do manually on GitHub.

---

## What You Need To Do First (GitHub Side)

Before Claude Code touches a line of code, do these manually:

### 1. Create the packages repository

```
GitHub → New Repository
Name:        duetos-packages
Visibility:  Public
Description: Official DuetOS package repository
Init with:   README.md
```

### 2. Scaffold the repo structure (do this after Claude Code generates the tooling)

The final layout will be:

```
duetos-packages/
  repo.toml              ← repo manifest (index of all packages)
  packages/
    <name>/
      <name>-<version>.toml   ← per-package manifest
      <name>-<version>-x86_64.tar.gz  ← prebuilt binary (uploaded via CI)
  keys/
    official.pub          ← your Ed25519 public key (generated below)
  .github/
    workflows/
      validate.yml        ← CI that validates manifests on PR
```

### 3. Generate your signing keypair (do this once, keep private key offline)

```sh
# On your local machine — NOT in CI, NOT committed to any repo
openssl genpkey -algorithm ed25519 -out duetos-official.pem
openssl pkey -in duetos-official.pem -pubout -out official.pub
```

- `duetos-official.pem` → store offline (USB, password manager). Never commit.
- `official.pub` → commit to `duetos-packages/keys/official.pub`
- Add `duetos-official.pem` content as a GitHub Actions secret named `DUETOS_SIGNING_KEY` for CI signing automation later.

### 4. Enable GitHub Pages on duetos-packages

```
Repo Settings → Pages → Source: main branch → /root
```

This lets `duet-pkg repo add https://<yourname>.github.io/duetos-packages/repo.toml` work as the default repo URL.

---

## Claude Code Session — Opening Prompt

Paste this verbatim to start the session:

```
I'm implementing duet-pkg, the package manager for DuetOS (my custom C++ operating system).
Read DUETOS_PKG_IMPLEMENTATION.md in full before writing any code.
All implementations must be production-ready C++23, Clang 18+, freestanding-compatible where noted,
and follow the existing DuetOS code style from CLAUDE.md.
Start with Phase 1 only. Do not proceed to Phase 2 without my explicit instruction.
```

---

## Architecture

### Layering

```
duet-pkg CLI
    └── RepoManager       (add/remove/list/sync repos)
    └── Resolver          (dependency graph, topological sort)
    └── Fetcher           (HTTP download, progress, resume)
    └── Verifier          (SHA-256, Ed25519 signature)
    └── Installer         (unpack tarball, write to /pkg/<name>/<version>/)
    └── Registry          (local installed package database)
    └── Builder           (optional: build from source recipe)
```

### Install Prefix Convention

```
/pkg/<name>/<version>/
  bin/
  lib/
  share/
  manifest.toml     ← copy of the package manifest, for uninstall/audit
```

Symlinks from `/usr/local/bin/<name>` → `/pkg/<name>/current/bin/<name>` after install.
`current` symlink updated atomically on install/upgrade.

### Trust Model

Each repo has exactly one Ed25519 public key. The package manager stores trusted keys in:

```
/etc/duet-pkg/repos.toml          ← list of active repos + their trusted key fingerprints
/etc/duet-pkg/keys/<fingerprint>.pub ← actual public key files
```

No key = no install. This is non-negotiable regardless of `--force` flags.

---

## File Layout (in DuetOS repo)

```
tools/pkg/
  CMakeLists.txt
  src/
    main.cpp
    cli/
      cli.hpp / cli.cpp           ← argument parsing, subcommand dispatch
    repo/
      repo_manager.hpp / .cpp     ← add/remove/list/sync repos
      repo_manifest.hpp / .cpp    ← parse repo.toml
      package_manifest.hpp / .cpp ← parse per-package .toml
    net/
      fetcher.hpp / .cpp          ← HTTP(S) download
    crypto/
      verifier.hpp / .cpp         ← SHA-256 + Ed25519 verify
      keying.hpp / .cpp           ← key storage, fingerprint, trust DB
    install/
      installer.hpp / .cpp        ← unpack + place + symlink
      uninstaller.hpp / .cpp      ← remove + cleanup symlinks
    resolve/
      resolver.hpp / .cpp         ← dependency resolution
    registry/
      registry.hpp / .cpp         ← local installed-package DB (flat TOML files)
    build/
      builder.hpp / .cpp          ← Phase 6: source build from recipe
  tests/
    test_manifest_parse.cpp
    test_resolver.cpp
    test_verifier.cpp
```

---

## Manifest Formats

### repo.toml (hosted by repo maintainer, fetched by duet-pkg sync)

```toml
[repo]
name        = "official"
maintainer  = "Nathan"
version     = 1
signing_key = "ed25519:<base64-encoded-public-key>"
base_url    = "https://username.github.io/duetos-packages/packages/"

[[packages]]
name        = "neovim"
version     = "0.10.0"
description = "Hyperextensible Vim-based text editor"
arch        = "x86_64"
deps        = ["libc", "libz"]
binary_url  = "neovim-0.10.0-x86_64.tar.gz"   # relative to base_url
sha256      = "abc123..."
source_url  = "https://github.com/neovim/neovim"
license     = "Apache-2.0"
size_bytes  = 8388608
installed_size_bytes = 24117248

[[packages]]
name        = "libz"
version     = "1.3.1"
description = "zlib compression library"
arch        = "x86_64"
deps        = []
binary_url  = "libz-1.3.1-x86_64.tar.gz"
sha256      = "def456..."
source_url  = "https://github.com/madler/zlib"
license     = "Zlib"
size_bytes  = 204800
installed_size_bytes = 614400
```

### Per-package manifest (inside the .tar.gz, at manifest.toml)

```toml
name        = "neovim"
version     = "0.10.0"
arch        = "x86_64"
description = "Hyperextensible Vim-based text editor"
license     = "Apache-2.0"
maintainer  = "Nathan"
source_url  = "https://github.com/neovim/neovim"
deps        = ["libc", "libz"]

[install]
bin   = ["bin/nvim"]
lib   = []
share = ["share/nvim"]
```

### Local registry entry (/var/lib/duet-pkg/installed/<name>.toml)

```toml
name            = "neovim"
version         = "0.10.0"
installed_at    = "2026-05-08T12:00:00Z"
installed_from  = "official"
install_prefix  = "/pkg/neovim/0.10.0"
sha256          = "abc123..."
deps            = ["libc", "libz"]
```

### Source build recipe (recipe.toml)

```toml
name    = "myapp"
version = "1.0.0"
source  = "https://github.com/user/myapp/archive/v1.0.0.tar.gz"
source_sha256 = "..."

[build]
system    = "cmake"          # cmake | make | meson | script
configure = ["-DCMAKE_BUILD_TYPE=Release", "-DCMAKE_INSTALL_PREFIX=/pkg/myapp/1.0.0"]

[deps]
build   = ["cmake", "clang"]
runtime = ["libz"]
```

---

## CLI Interface

```
duet-pkg <subcommand> [options]

Subcommands:
  install   <name> [--repo <name>] [--version <ver>]
  remove    <name>
  update    [<name>]          # update one or all
  list      [--installed] [--available]
  search    <query>
  info      <name>

  repo add    <url> [--trust-key <fingerprint>]
  repo remove <name>
  repo list
  repo sync   [<name>]        # re-fetch repo.toml index

  install-local <path.tar.gz>
  build         <recipe.toml>

  key list
  key trust   <fingerprint>
  key revoke  <fingerprint>
```

---

## Implementation Phases

Implement strictly in order. Do not start the next phase until the current one compiles, links, and passes its tests.

### Phase 1 — Manifest Parsing + Registry (no network, no crypto)

**Goal:** Parse repo.toml and package manifests. Read/write local registry. No downloads.

**Files to create:**
- `tools/pkg/src/repo/repo_manifest.hpp/.cpp`
- `tools/pkg/src/repo/package_manifest.hpp/.cpp`
- `tools/pkg/src/registry/registry.hpp/.cpp`
- `tools/pkg/src/cli/cli.hpp/.cpp` (stub: just parse argv, dispatch)
- `tools/pkg/src/main.cpp`
- `tools/pkg/CMakeLists.txt`
- `tools/pkg/tests/test_manifest_parse.cpp`

**Deliverables:**
- `duet-pkg list --installed` works against a hand-crafted registry dir
- `duet-pkg info <name>` reads a local repo.toml and prints package info
- All manifest parse tests pass

**TOML library:** Use toml++ (header-only, include via FetchContent). Do not write a custom TOML parser.

**Constraints:**
- C++23
- No exceptions (use `std::expected<T, Error>` for all fallible operations)
- No RTTI
- No dynamic allocation in hot paths (manifests are parsed once at startup, heap is fine there)

### Phase 2 — Crypto: SHA-256 + Ed25519

**Goal:** Verify package hashes and repo signatures. No network yet.

**Files to create:**
- `tools/pkg/src/crypto/verifier.hpp/.cpp`
- `tools/pkg/src/crypto/keying.hpp/.cpp`
- `tools/pkg/tests/test_verifier.cpp`

**Crypto library:** Use libsodium for Ed25519 (`crypto_sign_verify_detached`). Link statically. Use SHA-256 from libsodium (`crypto_hash_sha256`). Do NOT roll your own crypto.

### Phase 3 — Fetcher (HTTP/HTTPS download)

**Goal:** Download files from URLs with progress reporting and resume support.

**HTTP library:** Use libcurl statically linked. Do not write HTTP from scratch.

### Phase 4 — Repo Management (sync + trust)

**Goal:** `repo add/remove/list/sync` fully working. Ties together Phases 1–3.

### Phase 5 — Resolver + Installer + Uninstaller

**Goal:** `install`, `remove`, `update` fully working end-to-end.

### Phase 6 — install-local + build from recipe

**Goal:** Power-user paths. Build from source, install local tarballs.

### Phase 7 — search + CI + packaging tool

**Goal:** `search`, repo validation CI, and `duet-pkg-pack` tool for repo maintainers.

---

## Error Handling Convention

All fallible functions return `std::expected<T, DuetPkgError>`.

```cpp
enum class ErrorCode {
    ManifestParseFailed,
    NetworkError,
    HashMismatch,
    SignatureInvalid,
    KeyNotTrusted,
    DependencyCycle,
    VersionConflict,
    InstallFailed,
    PermissionDenied,
    PackageNotFound,
    AlreadyInstalled,
};

struct DuetPkgError {
    ErrorCode   code;
    std::string message;
    std::string detail;
};
```

---

## Build System Integration

```cmake
if(DUETOS_BUILD_TOOLS)
  add_subdirectory(tools/pkg)
endif()
```

**Note (Phase 1 implementation choice):** the freestanding kernel
toolchain is hostile to a hosted binary, so `tools/pkg/` is a
**standalone** CMake project (mirrors `tests/host/`). The root
`DUETOS_BUILD_TOOLS=ON` knob drives it via `ExternalProject_Add`
instead of `add_subdirectory`, which keeps both paths working
without polluting the kernel's compiler flags.

---

## Testing Strategy

- Unit tests: `tools/pkg/tests/` — test each component in isolation with fixture files
- Integration tests: `tools/pkg/tests/integration/` — spin up a local HTTP server, serve a test repo, run full install/remove cycles
- Fixture data: `tools/pkg/tests/fixtures/` — sample manifests, test keys, test tarballs
