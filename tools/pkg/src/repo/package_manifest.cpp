#include "repo/package_manifest.hpp"

#include <toml++/toml.hpp>

#include <fstream>
#include <sstream>
#include <utility>

namespace duet::repo
{
namespace
{

[[nodiscard]] Expected<std::string> RequireString(const toml::table& table, std::string_view key,
                                                  std::string_view source_label)
{
    const auto* node = table.get(key);
    if (node == nullptr)
    {
        return std::unexpected(
            MakeError(ErrorCode::ManifestMissingField,
                      std::string{source_label} + ": missing required field '" + std::string{key} + "'"));
    }
    const auto* as_str = node->as_string();
    if (as_str == nullptr)
    {
        return std::unexpected(MakeError(ErrorCode::ManifestBadType, std::string{source_label} + ": field '" +
                                                                         std::string{key} + "' must be a string"));
    }
    return std::string{as_str->get()};
}

[[nodiscard]] Expected<std::string> OptionalString(const toml::table& table, std::string_view key,
                                                   std::string_view source_label)
{
    const auto* node = table.get(key);
    if (node == nullptr)
        return std::string{};
    const auto* as_str = node->as_string();
    if (as_str == nullptr)
    {
        return std::unexpected(MakeError(ErrorCode::ManifestBadType, std::string{source_label} + ": field '" +
                                                                         std::string{key} + "' must be a string"));
    }
    return std::string{as_str->get()};
}

[[nodiscard]] Expected<std::vector<std::string>> OptionalStringArray(const toml::table& table, std::string_view key,
                                                                     std::string_view source_label)
{
    std::vector<std::string> out;
    const auto* node = table.get(key);
    if (node == nullptr)
        return out;
    const auto* arr = node->as_array();
    if (arr == nullptr)
    {
        return std::unexpected(MakeError(ErrorCode::ManifestBadType, std::string{source_label} + ": field '" +
                                                                         std::string{key} + "' must be an array"));
    }
    out.reserve(arr->size());
    for (std::size_t i = 0; i < arr->size(); ++i)
    {
        const auto* elem_str = (*arr)[i].as_string();
        if (elem_str == nullptr)
        {
            return std::unexpected(
                MakeError(ErrorCode::ManifestBadType,
                          std::string{source_label} + ": field '" + std::string{key} + "' must contain only strings"));
        }
        out.emplace_back(elem_str->get());
    }
    return out;
}

} // namespace

Expected<PackageManifest> LoadPackageManifestFromString(std::string_view toml, std::string_view source_label)
{
    toml::parse_result result = toml::parse(toml, source_label);
    if (!result)
    {
        std::string detail{result.error().description()};
        return std::unexpected(MakeError(ErrorCode::ManifestParseFailed,
                                         std::string{source_label} + ": TOML parse failed", std::move(detail)));
    }
    const toml::table& root = result.table();

    PackageManifest manifest;

    auto name = RequireString(root, "name", source_label);
    if (!name)
        return std::unexpected(name.error());
    manifest.name = std::move(*name);

    auto version = RequireString(root, "version", source_label);
    if (!version)
        return std::unexpected(version.error());
    manifest.version = std::move(*version);

    auto arch = OptionalString(root, "arch", source_label);
    if (!arch)
        return std::unexpected(arch.error());
    manifest.arch = std::move(*arch);

    auto desc = OptionalString(root, "description", source_label);
    if (!desc)
        return std::unexpected(desc.error());
    manifest.description = std::move(*desc);

    auto license = OptionalString(root, "license", source_label);
    if (!license)
        return std::unexpected(license.error());
    manifest.license = std::move(*license);

    auto maintainer = OptionalString(root, "maintainer", source_label);
    if (!maintainer)
        return std::unexpected(maintainer.error());
    manifest.maintainer = std::move(*maintainer);

    auto source_url = OptionalString(root, "source_url", source_label);
    if (!source_url)
        return std::unexpected(source_url.error());
    manifest.source_url = std::move(*source_url);

    auto deps = OptionalStringArray(root, "deps", source_label);
    if (!deps)
        return std::unexpected(deps.error());
    manifest.deps = std::move(*deps);

    const auto* install_node = root.get("install");
    if (install_node != nullptr)
    {
        const auto* install_tbl = install_node->as_table();
        if (install_tbl == nullptr)
        {
            return std::unexpected(
                MakeError(ErrorCode::ManifestBadType, std::string{source_label} + ": [install] must be a table"));
        }
        auto bin = OptionalStringArray(*install_tbl, "bin", source_label);
        if (!bin)
            return std::unexpected(bin.error());
        manifest.install.bin = std::move(*bin);

        auto lib = OptionalStringArray(*install_tbl, "lib", source_label);
        if (!lib)
            return std::unexpected(lib.error());
        manifest.install.lib = std::move(*lib);

        auto share = OptionalStringArray(*install_tbl, "share", source_label);
        if (!share)
            return std::unexpected(share.error());
        manifest.install.share = std::move(*share);
    }

    return manifest;
}

Expected<PackageManifest> LoadPackageManifestFromFile(const std::filesystem::path& path)
{
    std::ifstream in{path};
    if (!in.is_open())
    {
        return std::unexpected(
            MakeError(ErrorCode::ManifestParseFailed, "cannot open package manifest: " + path.string()));
    }
    std::ostringstream buf;
    buf << in.rdbuf();
    return LoadPackageManifestFromString(buf.str(), path.string());
}

} // namespace duet::repo
