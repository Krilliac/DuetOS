#pragma once

#include "error.hpp"
#include "registry/registry.hpp"
#include "repo/repo_manager.hpp"
#include "resolve/resolver.hpp"

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

/*
 * duet-pkg Phase 5 — installer.
 *
 * For each resolved package:
 *
 *   1. Download `<base_url>/<binary_url>` to
 *      `/var/cache/duet-pkg/<name>-<version>-<arch>.tar.gz`.
 *      Verify SHA-256.
 *   2. Download the sibling `.sig` file. Verify the Ed25519
 *      signature against the repo's trusted key.
 *   3. Unpack to `/pkg/<name>/<version>/`. Atomically update
 *      `/pkg/<name>/current` to point at the new version.
 *   4. For every `bin/<name>` entry in the package manifest,
 *      create `/usr/local/bin/<name>` → `/pkg/<name>/current/bin/<name>`.
 *   5. Write the registry entry to
 *      `/var/lib/duet-pkg/installed/<name>.toml`.
 *
 * On any step failure, roll back: remove the partially-unpacked
 * version dir, leave `current` pointing at the prior version (if
 * any), and don't touch the registry. Symlink updates use
 * "create + rename over" so an interrupted install doesn't leave
 * a broken `current`.
 *
 * Override knobs (env vars; useful for tests):
 *   - DUET_PKG_PREFIX        — base prefix (default `/pkg`)
 *   - DUET_PKG_CACHE         — tarball cache (default `/var/cache/duet-pkg`)
 *   - DUET_PKG_BIN_PREFIX    — symlink dest (default `/usr/local/bin`)
 *   - DUET_PKG_REGISTRY      — installed-entries DB (registry.hpp)
 */

namespace duet::install
{

struct InstallPaths
{
    std::filesystem::path pkg_prefix;    // /pkg
    std::filesystem::path bin_prefix;    // /usr/local/bin
    std::filesystem::path cache_dir;     // /var/cache/duet-pkg
    std::filesystem::path registry_root; // /var/lib/duet-pkg/installed
};

[[nodiscard]] InstallPaths DefaultInstallPaths() noexcept;

struct InstallReport
{
    std::vector<std::string> installed;
    std::vector<std::string> already_present;
};

class Installer
{
  public:
    Installer(InstallPaths paths, repo::RepoManager& mgr) noexcept : m_paths(std::move(paths)), m_mgr(mgr) {}

    /// Install a target package by name. Resolves deps across the
    /// supplied repos, downloads each missing one, and registers
    /// it in the local registry. Packages already at the requested
    /// version are skipped (the report lists them under
    /// `already_present`).
    ///
    /// `repos` must be in priority order — same shape the resolver
    /// consumes. Caller is responsible for syncing repos first.
    /// `allow_insecure` is forwarded to the fetcher.
    [[nodiscard]] Expected<InstallReport> Install(std::string_view target,
                                                  const std::vector<std::pair<std::string, repo::RepoManifest>>& repos,
                                                  bool allow_insecure = false);

  private:
    [[nodiscard]] Expected<void> InstallOne(const resolve::ResolvedPackage& pkg, bool allow_insecure);

    [[nodiscard]] std::filesystem::path VersionDir(std::string_view name, std::string_view version) const;
    [[nodiscard]] std::filesystem::path CurrentSymlink(std::string_view name) const;
    [[nodiscard]] std::filesystem::path CachePath(const repo::RepoPackageEntry& entry) const;

    InstallPaths m_paths;
    repo::RepoManager& m_mgr;
};

} // namespace duet::install
