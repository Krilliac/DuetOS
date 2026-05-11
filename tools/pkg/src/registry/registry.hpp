#pragma once

#include "error.hpp"

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

/*
 * duet-pkg — local installed-package registry.
 *
 * The registry is a flat directory of per-package TOML files
 * (matching the spec at
 * `/var/lib/duet-pkg/installed/<name>.toml`). Phase 1 implements:
 *
 *   - `LoadAll()`   — enumerate every entry in the registry dir
 *   - `Find(name)`  — read one entry by package name
 *   - `Write(entry)`— write or overwrite a single entry
 *   - `Remove(name)`— delete one entry
 *
 * Schema (matches the spec):
 *
 *   name            = "neovim"
 *   version         = "0.10.0"
 *   installed_at    = "2026-05-08T12:00:00Z"
 *   installed_from  = "official"
 *   install_prefix  = "/pkg/neovim/0.10.0"
 *   sha256          = "abc123..."
 *   deps            = ["libc", "libz"]
 *
 * Tests can point at any path (env var `DUET_PKG_REGISTRY`
 * overrides; in tests we pass an explicit ctor arg) so we don't
 * need root to verify the round-trip.
 */

namespace duet::registry
{

struct RegistryEntry
{
    std::string name;
    std::string version;
    std::string installed_at;   // ISO 8601 UTC; opaque string for now
    std::string installed_from; // repo name
    std::string install_prefix; // e.g. /pkg/neovim/0.10.0
    std::string sha256;
    std::vector<std::string> deps;
};

class Registry
{
  public:
    // Caller-supplied root (typically /var/lib/duet-pkg/installed).
    // The directory is created on first write if it doesn't exist.
    explicit Registry(std::filesystem::path root) noexcept : m_root(std::move(root)) {}

    [[nodiscard]] const std::filesystem::path& Root() const noexcept { return m_root; }

    /// Resolve the canonical installed-registry root for the current
    /// process: `$DUET_PKG_REGISTRY` if set, otherwise
    /// `/var/lib/duet-pkg/installed`. Pure helper — does not create
    /// or touch the path.
    [[nodiscard]] static std::filesystem::path DefaultRoot() noexcept;

    /// Enumerate every entry. Ignores non-`.toml` files in the dir.
    /// Returns the entries in name order so output stays stable
    /// across runs (matters for tests + `duet-pkg list`).
    [[nodiscard]] Expected<std::vector<RegistryEntry>> LoadAll() const;

    /// Read one entry by name. Returns `PackageNotFound` if the
    /// `<name>.toml` file is absent. Returns `ManifestParseFailed`
    /// if it exists but won't parse.
    [[nodiscard]] Expected<RegistryEntry> Find(std::string_view name) const;

    /// Write an entry. Creates the registry directory if needed;
    /// overwrites any existing file for the same name. Writes
    /// atomically: serialise to `<name>.toml.tmp` then rename.
    [[nodiscard]] Expected<void> Write(const RegistryEntry& entry) const;

    /// Delete one entry. Returns `PackageNotFound` if it didn't
    /// exist; otherwise removes the file.
    [[nodiscard]] Expected<void> Remove(std::string_view name) const;

  private:
    [[nodiscard]] std::filesystem::path PathFor(std::string_view name) const;

    std::filesystem::path m_root;
};

} // namespace duet::registry
