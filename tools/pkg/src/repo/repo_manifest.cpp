#include "repo/repo_manifest.hpp"

#include <toml++/toml.hpp>

#include <fstream>
#include <sstream>
#include <utility>

namespace duet::repo
{
namespace
{

// Pull a required string out of a TOML table, with a uniform
// missing/wrong-type error shape. The `source_label` is the file
// path or "<inline>" so the user sees where the bad manifest
// came from.
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

// Optional-string variant — returns an empty string if absent
// rather than an error. A wrong-type value still errors.
[[nodiscard]] Expected<std::string> OptionalString(const toml::table& table, std::string_view key,
                                                   std::string_view source_label)
{
    const auto* node = table.get(key);
    if (node == nullptr)
    {
        return std::string{};
    }
    const auto* as_str = node->as_string();
    if (as_str == nullptr)
    {
        return std::unexpected(MakeError(ErrorCode::ManifestBadType, std::string{source_label} + ": field '" +
                                                                         std::string{key} + "' must be a string"));
    }
    return std::string{as_str->get()};
}

[[nodiscard]] Expected<std::int64_t> OptionalInt(const toml::table& table, std::string_view key,
                                                 std::string_view source_label, std::int64_t fallback)
{
    const auto* node = table.get(key);
    if (node == nullptr)
    {
        return fallback;
    }
    const auto* as_int = node->as_integer();
    if (as_int == nullptr)
    {
        return std::unexpected(MakeError(ErrorCode::ManifestBadType, std::string{source_label} + ": field '" +
                                                                         std::string{key} + "' must be an integer"));
    }
    return as_int->get();
}

[[nodiscard]] Expected<std::uint64_t> OptionalU64(const toml::table& table, std::string_view key,
                                                  std::string_view source_label)
{
    auto i = OptionalInt(table, key, source_label, 0);
    if (!i)
        return std::unexpected(i.error());
    if (*i < 0)
    {
        return std::unexpected(MakeError(ErrorCode::ManifestBadType, std::string{source_label} + ": field '" +
                                                                         std::string{key} + "' must be non-negative"));
    }
    return static_cast<std::uint64_t>(*i);
}

[[nodiscard]] Expected<std::vector<std::string>> OptionalStringArray(const toml::table& table, std::string_view key,
                                                                     std::string_view source_label)
{
    std::vector<std::string> out;
    const auto* node = table.get(key);
    if (node == nullptr)
    {
        return out;
    }
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

[[nodiscard]] Expected<RepoPackageEntry> ParsePackageEntry(const toml::table& table, std::string_view source_label)
{
    RepoPackageEntry entry;

    auto name = RequireString(table, "name", source_label);
    if (!name)
        return std::unexpected(name.error());
    entry.name = std::move(*name);

    auto version = RequireString(table, "version", source_label);
    if (!version)
        return std::unexpected(version.error());
    entry.version = std::move(*version);

    auto desc = OptionalString(table, "description", source_label);
    if (!desc)
        return std::unexpected(desc.error());
    entry.description = std::move(*desc);

    auto arch = OptionalString(table, "arch", source_label);
    if (!arch)
        return std::unexpected(arch.error());
    entry.arch = std::move(*arch);

    auto deps = OptionalStringArray(table, "deps", source_label);
    if (!deps)
        return std::unexpected(deps.error());
    entry.deps = std::move(*deps);

    auto binary_url = OptionalString(table, "binary_url", source_label);
    if (!binary_url)
        return std::unexpected(binary_url.error());
    entry.binary_url = std::move(*binary_url);

    auto sha = OptionalString(table, "sha256", source_label);
    if (!sha)
        return std::unexpected(sha.error());
    entry.sha256 = std::move(*sha);

    auto source_url = OptionalString(table, "source_url", source_label);
    if (!source_url)
        return std::unexpected(source_url.error());
    entry.source_url = std::move(*source_url);

    auto license = OptionalString(table, "license", source_label);
    if (!license)
        return std::unexpected(license.error());
    entry.license = std::move(*license);

    auto sz = OptionalU64(table, "size_bytes", source_label);
    if (!sz)
        return std::unexpected(sz.error());
    entry.size_bytes = *sz;

    auto isz = OptionalU64(table, "installed_size_bytes", source_label);
    if (!isz)
        return std::unexpected(isz.error());
    entry.installed_size_bytes = *isz;

    return entry;
}

} // namespace

Expected<RepoManifest> LoadRepoManifestFromString(std::string_view toml, std::string_view source_label)
{
    toml::parse_result result = toml::parse(toml, source_label);
    if (!result)
    {
        std::string detail{result.error().description()};
        return std::unexpected(MakeError(ErrorCode::ManifestParseFailed,
                                         std::string{source_label} + ": TOML parse failed", std::move(detail)));
    }
    const toml::table& root = result.table();

    const auto* repo_node = root.get("repo");
    if (repo_node == nullptr || !repo_node->is_table())
    {
        return std::unexpected(
            MakeError(ErrorCode::ManifestMissingField, std::string{source_label} + ": missing top-level [repo] table"));
    }
    const toml::table& repo_table = *repo_node->as_table();

    RepoManifest manifest;

    auto repo_name = RequireString(repo_table, "name", source_label);
    if (!repo_name)
        return std::unexpected(repo_name.error());
    manifest.name = std::move(*repo_name);

    auto maintainer = OptionalString(repo_table, "maintainer", source_label);
    if (!maintainer)
        return std::unexpected(maintainer.error());
    manifest.maintainer = std::move(*maintainer);

    auto ver = OptionalInt(repo_table, "version", source_label, 0);
    if (!ver)
        return std::unexpected(ver.error());
    manifest.version = *ver;

    auto sig = OptionalString(repo_table, "signing_key", source_label);
    if (!sig)
        return std::unexpected(sig.error());
    manifest.signing_key = std::move(*sig);

    auto base_url = OptionalString(repo_table, "base_url", source_label);
    if (!base_url)
        return std::unexpected(base_url.error());
    manifest.base_url = std::move(*base_url);

    const auto* packages_node = root.get("packages");
    if (packages_node != nullptr)
    {
        const auto* packages_arr = packages_node->as_array();
        if (packages_arr == nullptr)
        {
            return std::unexpected(MakeError(ErrorCode::ManifestBadType,
                                             std::string{source_label} + ": [[packages]] must be an array of tables"));
        }
        manifest.packages.reserve(packages_arr->size());
        for (std::size_t i = 0; i < packages_arr->size(); ++i)
        {
            const auto* pkg_tbl = (*packages_arr)[i].as_table();
            if (pkg_tbl == nullptr)
            {
                return std::unexpected(MakeError(ErrorCode::ManifestBadType,
                                                 std::string{source_label} + ": [[packages]] element must be a table"));
            }
            auto entry = ParsePackageEntry(*pkg_tbl, source_label);
            if (!entry)
                return std::unexpected(entry.error());
            manifest.packages.push_back(std::move(*entry));
        }
    }

    return manifest;
}

Expected<RepoManifest> LoadRepoManifestFromFile(const std::filesystem::path& path)
{
    std::ifstream in{path};
    if (!in.is_open())
    {
        return std::unexpected(
            MakeError(ErrorCode::ManifestParseFailed, "cannot open repo manifest: " + path.string()));
    }
    std::ostringstream buf;
    buf << in.rdbuf();
    return LoadRepoManifestFromString(buf.str(), path.string());
}

Expected<const RepoPackageEntry*> FindPackage(const RepoManifest& repo, std::string_view name) noexcept
{
    for (const auto& p : repo.packages)
    {
        if (p.name == name)
        {
            return &p;
        }
    }
    return std::unexpected(
        MakeError(ErrorCode::PackageNotFound, std::string{name} + ": not found in repo '" + repo.name + "'"));
}

} // namespace duet::repo
