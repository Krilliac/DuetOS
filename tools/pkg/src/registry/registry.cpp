#include "registry/registry.hpp"

#include <toml++/toml.hpp>

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <system_error>
#include <utility>

namespace duet::registry
{
namespace
{

constexpr std::string_view kRegistryDefaultRoot = "/var/lib/duet-pkg/installed";
constexpr std::string_view kEnvRegistryOverride = "DUET_PKG_REGISTRY";

// Validate that a package name produces a safe filename — no
// path traversal, no separator, no NUL. Names are restricted to
// a conservative `[a-zA-Z0-9_-]+` set with a 128-byte cap; that
// covers every shipping package today and rules out the obvious
// path-traversal vectors (`..`, embedded slashes) without
// reaching for a regex. Tighten further if a real workload
// demands more characters.
[[nodiscard]] bool IsValidPackageName(std::string_view name) noexcept
{
    if (name.empty() || name.size() > 128)
        return false;
    for (char c : name)
    {
        const bool ok =
            (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-';
        if (!ok)
            return false;
    }
    return true;
}

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

[[nodiscard]] Expected<RegistryEntry> ParseEntryFromString(std::string_view toml_text, std::string_view source_label)
{
    toml::parse_result result = toml::parse(toml_text, source_label);
    if (!result)
    {
        std::string detail{result.error().description()};
        return std::unexpected(MakeError(ErrorCode::ManifestParseFailed,
                                         std::string{source_label} + ": TOML parse failed", std::move(detail)));
    }
    const toml::table& root = result.table();

    RegistryEntry entry;
    auto name = RequireString(root, "name", source_label);
    if (!name)
        return std::unexpected(name.error());
    entry.name = std::move(*name);

    auto version = RequireString(root, "version", source_label);
    if (!version)
        return std::unexpected(version.error());
    entry.version = std::move(*version);

    auto installed_at = OptionalString(root, "installed_at", source_label);
    if (!installed_at)
        return std::unexpected(installed_at.error());
    entry.installed_at = std::move(*installed_at);

    auto installed_from = OptionalString(root, "installed_from", source_label);
    if (!installed_from)
        return std::unexpected(installed_from.error());
    entry.installed_from = std::move(*installed_from);

    auto install_prefix = OptionalString(root, "install_prefix", source_label);
    if (!install_prefix)
        return std::unexpected(install_prefix.error());
    entry.install_prefix = std::move(*install_prefix);

    auto sha = OptionalString(root, "sha256", source_label);
    if (!sha)
        return std::unexpected(sha.error());
    entry.sha256 = std::move(*sha);

    auto deps = OptionalStringArray(root, "deps", source_label);
    if (!deps)
        return std::unexpected(deps.error());
    entry.deps = std::move(*deps);

    return entry;
}

[[nodiscard]] std::string SerializeEntry(const RegistryEntry& entry)
{
    // Build the file by hand. toml++ does have a TOML serialiser
    // but it pulls in formatting paths we don't need; a manual
    // emit is simpler, easier to diff, and keeps the file
    // human-readable.
    std::ostringstream out;
    out << "name            = \"" << entry.name << "\"\n";
    out << "version         = \"" << entry.version << "\"\n";
    out << "installed_at    = \"" << entry.installed_at << "\"\n";
    out << "installed_from  = \"" << entry.installed_from << "\"\n";
    out << "install_prefix  = \"" << entry.install_prefix << "\"\n";
    out << "sha256          = \"" << entry.sha256 << "\"\n";
    out << "deps            = [";
    for (std::size_t i = 0; i < entry.deps.size(); ++i)
    {
        if (i > 0)
            out << ", ";
        out << "\"" << entry.deps[i] << "\"";
    }
    out << "]\n";
    return out.str();
}

} // namespace

std::filesystem::path Registry::DefaultRoot() noexcept
{
    const char* override_env = std::getenv(std::string{kEnvRegistryOverride}.c_str());
    if (override_env != nullptr && override_env[0] != '\0')
    {
        return std::filesystem::path{override_env};
    }
    return std::filesystem::path{std::string{kRegistryDefaultRoot}};
}

std::filesystem::path Registry::PathFor(std::string_view name) const
{
    std::string filename{name};
    filename += ".toml";
    return m_root / filename;
}

Expected<std::vector<RegistryEntry>> Registry::LoadAll() const
{
    std::vector<RegistryEntry> out;
    std::error_code ec;
    if (!std::filesystem::exists(m_root, ec))
    {
        // Empty registry is a normal state. Return empty list,
        // not an error.
        return out;
    }
    if (!std::filesystem::is_directory(m_root, ec))
    {
        return std::unexpected(
            MakeError(ErrorCode::RegistryReadFailed, "registry root is not a directory: " + m_root.string()));
    }
    for (const auto& dir_entry : std::filesystem::directory_iterator{m_root, ec})
    {
        if (ec)
        {
            return std::unexpected(MakeError(ErrorCode::RegistryReadFailed,
                                             "directory_iterator failed: " + m_root.string(), ec.message()));
        }
        if (!dir_entry.is_regular_file(ec))
            continue;
        const auto& path = dir_entry.path();
        if (path.extension() != ".toml")
            continue;
        std::ifstream in{path};
        if (!in.is_open())
        {
            return std::unexpected(
                MakeError(ErrorCode::RegistryReadFailed, "cannot open registry file: " + path.string()));
        }
        std::ostringstream buf;
        buf << in.rdbuf();
        auto entry = ParseEntryFromString(buf.str(), path.string());
        if (!entry)
            return std::unexpected(entry.error());
        out.push_back(std::move(*entry));
    }
    std::sort(out.begin(), out.end(), [](const auto& a, const auto& b) { return a.name < b.name; });
    return out;
}

Expected<RegistryEntry> Registry::Find(std::string_view name) const
{
    if (!IsValidPackageName(name))
    {
        return std::unexpected(
            MakeError(ErrorCode::InvalidArgument, std::string{"invalid package name: '"} + std::string{name} + "'"));
    }
    const auto path = PathFor(name);
    std::error_code ec;
    if (!std::filesystem::exists(path, ec))
    {
        return std::unexpected(
            MakeError(ErrorCode::PackageNotFound, std::string{name} + ": not in installed registry"));
    }
    std::ifstream in{path};
    if (!in.is_open())
    {
        return std::unexpected(MakeError(ErrorCode::RegistryReadFailed, "cannot open registry file: " + path.string()));
    }
    std::ostringstream buf;
    buf << in.rdbuf();
    return ParseEntryFromString(buf.str(), path.string());
}

Expected<void> Registry::Write(const RegistryEntry& entry) const
{
    if (!IsValidPackageName(entry.name))
    {
        return std::unexpected(
            MakeError(ErrorCode::InvalidArgument, std::string{"invalid package name: '"} + entry.name + "'"));
    }
    std::error_code ec;
    std::filesystem::create_directories(m_root, ec);
    if (ec)
    {
        return std::unexpected(
            MakeError(ErrorCode::RegistryWriteFailed, "cannot create registry dir: " + m_root.string(), ec.message()));
    }
    const auto final_path = PathFor(entry.name);
    auto tmp_path = final_path;
    tmp_path += ".tmp";
    {
        std::ofstream out{tmp_path, std::ios::trunc};
        if (!out.is_open())
        {
            return std::unexpected(
                MakeError(ErrorCode::RegistryWriteFailed, "cannot open registry tmp file: " + tmp_path.string()));
        }
        out << SerializeEntry(entry);
        if (!out)
        {
            return std::unexpected(
                MakeError(ErrorCode::RegistryWriteFailed, "registry write failed: " + tmp_path.string()));
        }
    }
    std::filesystem::rename(tmp_path, final_path, ec);
    if (ec)
    {
        return std::unexpected(MakeError(ErrorCode::RegistryWriteFailed,
                                         "rename to final registry path failed: " + final_path.string(), ec.message()));
    }
    return {};
}

Expected<void> Registry::Remove(std::string_view name) const
{
    if (!IsValidPackageName(name))
    {
        return std::unexpected(
            MakeError(ErrorCode::InvalidArgument, std::string{"invalid package name: '"} + std::string{name} + "'"));
    }
    const auto path = PathFor(name);
    std::error_code ec;
    if (!std::filesystem::exists(path, ec))
    {
        return std::unexpected(
            MakeError(ErrorCode::PackageNotFound, std::string{name} + ": not in installed registry"));
    }
    std::filesystem::remove(path, ec);
    if (ec)
    {
        return std::unexpected(
            MakeError(ErrorCode::RegistryWriteFailed, "registry remove failed: " + path.string(), ec.message()));
    }
    return {};
}

} // namespace duet::registry
