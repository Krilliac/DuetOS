#include "install/uninstaller.hpp"

#include "registry/registry.hpp"
#include "repo/package_manifest.hpp"

#include <cstdio>
#include <system_error>

namespace duet::install
{

Expected<UninstallReport> Uninstaller::Remove(std::string_view name, bool force)
{
    duet::registry::Registry reg{m_paths.registry_root};
    auto entry = reg.Find(name);
    if (!entry)
        return std::unexpected(entry.error());

    // Reverse-dep check: refuse if any other registry entry
    // declares this package as a dep, unless force is set.
    auto all = reg.LoadAll();
    if (!all)
        return std::unexpected(all.error());
    std::vector<std::string> rdeps;
    for (const auto& e : *all)
    {
        if (e.name == name)
            continue;
        for (const auto& d : e.deps)
        {
            if (d == name)
            {
                rdeps.push_back(e.name);
                break;
            }
        }
    }
    if (!rdeps.empty() && !force)
    {
        std::string msg = std::string{name} + ": refusing to remove; dependents installed:";
        for (const auto& r : rdeps)
            msg += " " + r;
        msg += " (pass --force to override)";
        return std::unexpected(MakeError(ErrorCode::InstallFailed, msg));
    }
    if (!rdeps.empty() && force)
    {
        std::fprintf(stderr, "warning: --force removing %.*s while %zu dependent(s) remain installed\n",
                     static_cast<int>(name.size()), name.data(), rdeps.size());
    }

    UninstallReport report;
    report.removed_version_dir = std::filesystem::path{entry->install_prefix};

    // Walk the version dir's manifest (if present) to find the
    // bin shims we wrote at install time. If the manifest is
    // missing, fall back to the single-binary convention.
    std::vector<std::string> bin_targets;
    const auto inner_manifest = report.removed_version_dir / "manifest.toml";
    if (std::filesystem::exists(inner_manifest))
    {
        auto m = duet::repo::LoadPackageManifestFromFile(inner_manifest);
        if (m)
            bin_targets = m->install.bin;
    }
    if (bin_targets.empty())
    {
        bin_targets.push_back("bin/" + std::string{name});
    }
    std::error_code ec;
    for (const auto& rel : bin_targets)
    {
        const auto leaf = std::filesystem::path{rel}.filename();
        if (leaf.empty())
            continue;
        const auto link = m_paths.bin_prefix / leaf;
        if (std::filesystem::is_symlink(link))
        {
            std::filesystem::remove(link, ec);
            if (!ec)
                report.removed_bin_links.push_back(link.string());
        }
    }

    // Remove the version dir.
    std::filesystem::remove_all(report.removed_version_dir, ec);
    if (ec)
    {
        return std::unexpected(
            MakeError(ErrorCode::InstallFailed, "remove_all " + report.removed_version_dir.string(), ec.message()));
    }

    // If `<prefix>/<name>/current` pointed at this version,
    // remove the symlink + the parent dir if it's now empty.
    const auto current = m_paths.pkg_prefix / std::string{name} / "current";
    if (std::filesystem::is_symlink(current))
    {
        const auto target = std::filesystem::read_symlink(current, ec);
        if (!ec && target.filename().string() == entry->version)
        {
            std::filesystem::remove(current, ec);
            report.was_current = true;
        }
    }
    const auto name_dir = m_paths.pkg_prefix / std::string{name};
    if (std::filesystem::exists(name_dir, ec) && std::filesystem::is_directory(name_dir, ec))
    {
        if (std::filesystem::is_empty(name_dir, ec))
        {
            std::filesystem::remove(name_dir, ec);
        }
    }

    // Drop the registry entry.
    auto rm = reg.Remove(name);
    if (!rm)
        return std::unexpected(rm.error());
    return report;
}

} // namespace duet::install
