#pragma once

#include "error.hpp"
#include "repo/repo_manifest.hpp"

#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

/*
 * duet-pkg Phase 5 — dependency resolver.
 *
 * Given a target package name + a set of repo manifests, walks
 * the dep graph and returns the install order (deps first) via
 * Kahn's algorithm. Detects:
 *
 *   - Cycles                                   → DependencyCycle
 *   - Duplicate provides across repos          → VersionConflict
 *   - Two versions of the same package wanted  → VersionConflict
 *   - Missing dependency                       → PackageNotFound
 *
 * Repos are scanned in order; the first match wins so callers
 * can put "official" before "community" to express priority.
 *
 * `Resolve` does not consult the installed registry — the
 * installer queries that separately and skips already-satisfied
 * deps. Keeping the resolver pure makes it easy to test.
 */

namespace duet::resolve
{

struct ResolvedPackage
{
    // Which repo (by `[repo].name`) the manifest was sourced
    // from. Useful for the installer to record `installed_from`
    // in the registry entry.
    std::string repo;
    repo::RepoPackageEntry entry;
};

/// Resolve `target` against an ordered list of (repo_name,
/// manifest) pairs. Returns the install order — deps first,
/// target last.
[[nodiscard]] Expected<std::vector<ResolvedPackage>> Resolve(
    std::string_view target, const std::vector<std::pair<std::string, repo::RepoManifest>>& repos);

/// Same shape, but with a pre-built lookup table (the installer
/// builds it once and resolves many packages against it).
[[nodiscard]] Expected<std::vector<ResolvedPackage>> ResolveAgainstIndex(
    std::string_view target, const std::unordered_map<std::string, ResolvedPackage>& index);

/// Build the "name → ResolvedPackage" index in repo-priority order.
/// Earlier repos win on duplicate names — that's how a user
/// overrides "official" with "staging" if both repos export the
/// same package.
[[nodiscard]] std::unordered_map<std::string, ResolvedPackage> BuildIndex(
    const std::vector<std::pair<std::string, repo::RepoManifest>>& repos);

} // namespace duet::resolve
