#pragma once

#include "error.hpp"
#include "install/installer.hpp"

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

/*
 * duet-pkg Phase 6 — build-from-recipe.
 *
 * A recipe.toml describes how to build a package from a source
 * tarball. Shape (from DUETOS_PKG_IMPLEMENTATION.md):
 *
 *   name    = "myapp"
 *   version = "1.0.0"
 *   source  = "https://example.com/myapp-1.0.0.tar.gz"
 *   source_sha256 = "..."
 *
 *   [build]
 *   system    = "cmake"   # cmake | make | script
 *   configure = ["-DCMAKE_BUILD_TYPE=Release",
 *                "-DCMAKE_INSTALL_PREFIX=/pkg/myapp/1.0.0"]
 *
 *   [deps]
 *   build   = ["cmake", "clang"]
 *   runtime = ["libz"]
 *
 * `Build()` walks the recipe end-to-end: downloads + verifies
 * source, extracts to a scratch dir, runs the build system, lays
 * down the install tree, packages it as a tarball, and hands it
 * to `Installer::InstallLocal`. The `script` system runs an
 * operator-provided shell script (one entry per `configure`)
 * and assumes the script does its own `make install` —
 * intentional escape hatch for projects with bespoke build
 * setups.
 */

namespace duet::build
{

enum class BuildSystem
{
    Unknown,
    Cmake,
    Make,
    Script,
};

struct RecipeDeps
{
    std::vector<std::string> build;
    std::vector<std::string> runtime;
};

struct Recipe
{
    std::string name;
    std::string version;
    std::string source_url;
    std::string source_sha256;
    BuildSystem system = BuildSystem::Unknown;
    // For cmake: arguments to the configure step ("cmake -S src -B build <args>").
    // For make:  arguments appended to "make" ("make <args>").
    // For script: each entry is a separate shell command run in the source dir.
    std::vector<std::string> configure;
    RecipeDeps deps;
};

[[nodiscard]] Expected<Recipe> ParseRecipeFromString(std::string_view toml, std::string_view source_label);
[[nodiscard]] Expected<Recipe> ParseRecipeFromFile(const std::filesystem::path& path);

class Builder
{
  public:
    explicit Builder(install::Installer& installer) noexcept : m_installer(installer) {}

    /// Run the full build pipeline against `recipe`. Returns the
    /// installed package name on success. Steps:
    ///   1. Download `recipe.source_url` to
    ///      `/var/cache/duet-pkg/sources/`.
    ///   2. Verify SHA-256 if `recipe.source_sha256` is set.
    ///   3. Extract to a temp scratch dir.
    ///   4. Run the build system in the scratch dir, with
    ///      `--prefix` / `CMAKE_INSTALL_PREFIX` pointing at a
    ///      staging dir.
    ///   5. Run install into the staging dir, package staging
    ///      into a `.tar.gz`.
    ///   6. Generate `manifest.toml` inside the tarball.
    ///   7. Hand to `Installer::InstallLocal`.
    ///
    /// Build deps are NOT auto-installed by v0 — the recipe's
    /// `[deps].build` block is consulted only to error out when
    /// a required tool is missing from PATH. Auto-install of
    /// build deps lands once a workload depends on it.
    [[nodiscard]] Expected<std::string> Build(const Recipe& recipe, bool allow_insecure = false);

  private:
    install::Installer& m_installer;
};

[[nodiscard]] std::string_view BuildSystemName(BuildSystem s) noexcept;

} // namespace duet::build
