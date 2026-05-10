#pragma once

#include "error.hpp"
#include "install/installer.hpp"

#include <string>
#include <string_view>
#include <vector>

/*
 * duet-pkg Phase 5 — uninstaller.
 *
 * Inverse of Installer. For a given package name:
 *
 *   1. Verify no other installed package depends on it
 *      (unless `force` is set; in which case a loud warning is
 *      emitted to stderr).
 *   2. Remove every `/usr/local/bin/<leaf>` symlink that points
 *      into this package's tree.
 *   3. Remove the install-prefix dir + `current` symlink if it
 *      points at this version.
 *   4. Remove the registry entry.
 *
 * `force=true` only bypasses the reverse-dep gate; it never
 * skips the actual file removal.
 */

namespace duet::install
{

struct UninstallReport
{
    std::vector<std::string> removed_bin_links;
    std::filesystem::path removed_version_dir;
    bool was_current = false;
};

class Uninstaller
{
  public:
    explicit Uninstaller(InstallPaths paths) noexcept : m_paths(std::move(paths)) {}

    [[nodiscard]] Expected<UninstallReport> Remove(std::string_view name, bool force);

  private:
    InstallPaths m_paths;
};

} // namespace duet::install
