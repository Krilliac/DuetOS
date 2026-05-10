#pragma once

#include "error.hpp"

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

/*
 * duet-pkg — repo.toml parser.
 *
 * A repo manifest indexes every package a repo offers. The
 * canonical shape (see DUETOS_PKG_IMPLEMENTATION.md):
 *
 *   [repo]
 *   name        = "official"
 *   maintainer  = "Nathan"
 *   version     = 1
 *   signing_key = "ed25519:<base64>"
 *   base_url    = "https://.../packages/"
 *
 *   [[packages]]
 *   name = "neovim"
 *   version = "0.10.0"
 *   ...
 *
 * Phase 1 parses every field but doesn't yet act on
 * `signing_key` (Phase 2) or `base_url` (Phase 3+). Both are
 * captured so later phases don't re-parse.
 */

namespace duet::repo
{

struct RepoPackageEntry
{
    std::string name;
    std::string version;
    std::string description;
    std::string arch;
    std::vector<std::string> deps;
    std::string binary_url;
    std::string sha256;
    std::string source_url;
    std::string license;
    std::uint64_t size_bytes = 0;
    std::uint64_t installed_size_bytes = 0;
};

struct RepoManifest
{
    std::string name;
    std::string maintainer;
    std::int64_t version = 0;
    std::string signing_key;
    std::string base_url;
    std::vector<RepoPackageEntry> packages;
};

/// Parse a repo manifest from a TOML string in memory. Returns
/// `ManifestParseFailed` for a malformed document and
/// `ManifestMissingField` / `ManifestBadType` for shape errors.
[[nodiscard]] Expected<RepoManifest> LoadRepoManifestFromString(std::string_view toml, std::string_view source_label);

/// Load + parse a repo manifest from a file on disk. Wraps
/// `LoadRepoManifestFromString`; surfaces I/O errors as
/// `ManifestParseFailed` with the OS message in `detail`.
[[nodiscard]] Expected<RepoManifest> LoadRepoManifestFromFile(const std::filesystem::path& path);

/// Lookup helper. Returns the matching package entry, or
/// `PackageNotFound`. Name match is case-sensitive.
[[nodiscard]] Expected<const RepoPackageEntry*> FindPackage(const RepoManifest& repo, std::string_view name) noexcept;

} // namespace duet::repo
