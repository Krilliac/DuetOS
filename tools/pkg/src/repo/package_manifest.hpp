#pragma once

#include "error.hpp"

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

/*
 * duet-pkg — per-package manifest.toml parser.
 *
 * Lives inside a package tarball at `manifest.toml`. Shape:
 *
 *   name        = "neovim"
 *   version     = "0.10.0"
 *   arch        = "x86_64"
 *   description = "Hyperextensible Vim-based text editor"
 *   license     = "Apache-2.0"
 *   maintainer  = "Nathan"
 *   source_url  = "https://..."
 *   deps        = ["libc", "libz"]
 *
 *   [install]
 *   bin   = ["bin/nvim"]
 *   lib   = []
 *   share = ["share/nvim"]
 */

namespace duet::repo
{

struct PackageManifestInstall
{
    std::vector<std::string> bin;
    std::vector<std::string> lib;
    std::vector<std::string> share;
};

struct PackageManifest
{
    std::string name;
    std::string version;
    std::string arch;
    std::string description;
    std::string license;
    std::string maintainer;
    std::string source_url;
    std::vector<std::string> deps;
    PackageManifestInstall install;
};

[[nodiscard]] Expected<PackageManifest> LoadPackageManifestFromString(std::string_view toml,
                                                                      std::string_view source_label);

[[nodiscard]] Expected<PackageManifest> LoadPackageManifestFromFile(const std::filesystem::path& path);

} // namespace duet::repo
