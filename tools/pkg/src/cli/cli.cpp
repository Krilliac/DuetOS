#include "cli/cli.hpp"

#include "crypto/keying.hpp"
#include "install/installer.hpp"
#include "install/uninstaller.hpp"
#include "registry/registry.hpp"
#include "repo/repo_manager.hpp"
#include "repo/repo_manifest.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <utility>

namespace duet::cli
{
namespace
{

// Subcommands that take a value-bearing option must be matched
// against this table before we look at positional args. Keeping
// it data-driven makes the parser dead simple.
struct ValueFlag
{
    std::string_view name;
    std::string_view ParsedArgs::*field;
};

constexpr ValueFlag kValueFlags[] = {
    {"--repo", &ParsedArgs::opt_repo},
    {"--version", &ParsedArgs::opt_version},
    {"--url", &ParsedArgs::opt_repo_url},
    {"--trust-key", &ParsedArgs::opt_trust_key},
};

// Boolean flags. Same pattern.
struct BoolFlag
{
    std::string_view name;
    bool ParsedArgs::*field;
};

constexpr BoolFlag kBoolFlags[] = {
    {"--installed", &ParsedArgs::flag_installed}, {"--available", &ParsedArgs::flag_available},
    {"--verbose", &ParsedArgs::flag_verbose},     {"-v", &ParsedArgs::flag_verbose},
    {"--help", &ParsedArgs::flag_help},           {"-h", &ParsedArgs::flag_help},
    {"--insecure", &ParsedArgs::flag_insecure},   {"--force", &ParsedArgs::flag_force},
};

[[nodiscard]] Expected<int> CmdNotYet(std::string_view subcommand)
{
    return std::unexpected(MakeError(ErrorCode::InvalidArgument, std::string{"subcommand '"} + std::string{subcommand} +
                                                                     "' is not yet implemented in this phase"));
}

[[nodiscard]] Expected<int> CmdRepo(const ParsedArgs& args)
{
    namespace repo = duet::repo;
    namespace crypto = duet::crypto;
    if (args.positional.empty())
    {
        return std::unexpected(
            MakeError(ErrorCode::InvalidArgument, "repo: missing action (add | remove | list | sync)"));
    }
    repo::RepoManager mgr{repo::RepoManager::DefaultConfigRoot()};
    const auto& action = args.positional[0];
    if (action == "list")
    {
        auto entries_or = mgr.LoadIndex();
        if (!entries_or)
            return std::unexpected(entries_or.error());
        if (entries_or->empty())
        {
            std::printf("no repos registered (config root: %s)\n", mgr.ConfigRoot().string().c_str());
            return 0;
        }
        std::printf("%-24s %-8s %-12s %-24s %s\n", "NAME", "PKGS", "TRUST_FP", "LAST_SYNCED", "URL");
        for (const auto& e : *entries_or)
        {
            std::string fp_short = e.trust_fingerprint.substr(0, std::min<std::size_t>(12, e.trust_fingerprint.size()));
            std::printf("%-24s %-8llu %-12s %-24s %s\n", e.name.c_str(),
                        static_cast<unsigned long long>(e.package_count), fp_short.c_str(),
                        e.last_synced.empty() ? "-" : e.last_synced.c_str(), e.url.c_str());
        }
        return 0;
    }
    if (action == "add")
    {
        if (args.positional.size() < 2 || args.opt_trust_key.empty())
        {
            return std::unexpected(
                MakeError(ErrorCode::InvalidArgument, "repo add: usage `repo add <url> --trust-key <fingerprint>`"));
        }
        auto entry = mgr.Add(args.positional[1], args.opt_trust_key, args.flag_insecure);
        if (!entry)
            return std::unexpected(entry.error());
        std::printf("added repo '%s' (%llu packages) trust=%s\n", entry->name.c_str(),
                    static_cast<unsigned long long>(entry->package_count), entry->trust_fingerprint.c_str());
        return 0;
    }
    if (action == "remove")
    {
        if (args.positional.size() < 2)
        {
            return std::unexpected(MakeError(ErrorCode::InvalidArgument, "repo remove: usage `repo remove <name>`"));
        }
        auto rc = mgr.Remove(args.positional[1]);
        if (!rc)
            return std::unexpected(rc.error());
        std::printf("removed repo '%s'\n", std::string{args.positional[1]}.c_str());
        return 0;
    }
    if (action == "sync")
    {
        const std::string_view only = args.positional.size() >= 2 ? args.positional[1] : std::string_view{};
        auto synced = mgr.Sync(only, args.flag_insecure);
        if (!synced)
            return std::unexpected(synced.error());
        if (synced->empty())
        {
            std::printf("no repos to sync\n");
            return 0;
        }
        for (const auto& e : *synced)
        {
            std::printf("synced %s (%llu packages, %s)\n", e.name.c_str(),
                        static_cast<unsigned long long>(e.package_count), e.last_synced.c_str());
        }
        return 0;
    }
    return std::unexpected(MakeError(ErrorCode::InvalidArgument, "repo: unknown action: " + std::string{action}));
}

[[nodiscard]] Expected<std::vector<std::pair<std::string, duet::repo::RepoManifest>>> LoadAllReposOrdered(
    const duet::repo::RepoManager& mgr)
{
    std::vector<std::pair<std::string, duet::repo::RepoManifest>> repos;
    auto index = mgr.LoadIndex();
    if (!index)
        return std::unexpected(index.error());
    for (const auto& e : *index)
    {
        auto m = mgr.LoadCachedManifest(e.name);
        if (!m)
            return std::unexpected(m.error());
        repos.emplace_back(e.name, std::move(*m));
    }
    return repos;
}

[[nodiscard]] Expected<int> CmdInstall(const ParsedArgs& args)
{
    if (args.positional.empty())
    {
        return std::unexpected(MakeError(ErrorCode::InvalidArgument, "install: missing package name"));
    }
    duet::repo::RepoManager mgr{duet::repo::RepoManager::DefaultConfigRoot()};
    auto repos = LoadAllReposOrdered(mgr);
    if (!repos)
        return std::unexpected(repos.error());
    duet::install::Installer installer{duet::install::DefaultInstallPaths(), mgr};
    auto report = installer.Install(args.positional[0], *repos, args.flag_insecure);
    if (!report)
        return std::unexpected(report.error());
    if (!report->installed.empty())
    {
        std::printf("installed:");
        for (const auto& n : report->installed)
            std::printf(" %s", n.c_str());
        std::printf("\n");
    }
    if (!report->already_present.empty())
    {
        std::printf("already at target version:");
        for (const auto& n : report->already_present)
            std::printf(" %s", n.c_str());
        std::printf("\n");
    }
    if (report->installed.empty() && report->already_present.empty())
    {
        std::printf("nothing to do\n");
    }
    return 0;
}

[[nodiscard]] Expected<int> CmdRemove(const ParsedArgs& args)
{
    if (args.positional.empty())
    {
        return std::unexpected(MakeError(ErrorCode::InvalidArgument, "remove: missing package name"));
    }
    duet::install::Uninstaller un{duet::install::DefaultInstallPaths()};
    auto report = un.Remove(args.positional[0], args.flag_force);
    if (!report)
        return std::unexpected(report.error());
    std::printf("removed %s (version dir: %s, current=%s)\n", std::string{args.positional[0]}.c_str(),
                report->removed_version_dir.string().c_str(), report->was_current ? "yes" : "no");
    if (!report->removed_bin_links.empty())
    {
        std::printf("  symlinks removed:");
        for (const auto& l : report->removed_bin_links)
            std::printf(" %s", l.c_str());
        std::printf("\n");
    }
    return 0;
}

[[nodiscard]] Expected<int> CmdUpdate(const ParsedArgs& args)
{
    duet::repo::RepoManager mgr{duet::repo::RepoManager::DefaultConfigRoot()};
    auto repos = LoadAllReposOrdered(mgr);
    if (!repos)
        return std::unexpected(repos.error());
    duet::install::Installer installer{duet::install::DefaultInstallPaths(), mgr};
    duet::install::InstallReport agg;
    duet::registry::Registry reg{duet::install::DefaultInstallPaths().registry_root};
    std::vector<std::string> targets;
    if (!args.positional.empty())
    {
        targets.emplace_back(args.positional[0]);
    }
    else
    {
        auto installed = reg.LoadAll();
        if (!installed)
            return std::unexpected(installed.error());
        for (const auto& e : *installed)
            targets.push_back(e.name);
    }
    for (const auto& t : targets)
    {
        auto r = installer.Install(t, *repos, args.flag_insecure);
        if (!r)
            return std::unexpected(r.error());
        for (auto& s : r->installed)
            agg.installed.push_back(std::move(s));
        for (auto& s : r->already_present)
            agg.already_present.push_back(std::move(s));
    }
    if (!agg.installed.empty())
    {
        std::printf("updated:");
        for (const auto& n : agg.installed)
            std::printf(" %s", n.c_str());
        std::printf("\n");
    }
    if (!agg.already_present.empty())
    {
        std::printf("up to date:");
        for (const auto& n : agg.already_present)
            std::printf(" %s", n.c_str());
        std::printf("\n");
    }
    return 0;
}

[[nodiscard]] Expected<int> CmdKey(const ParsedArgs& args)
{
    namespace repo = duet::repo;
    if (args.positional.empty())
    {
        return std::unexpected(MakeError(ErrorCode::InvalidArgument, "key: missing action (list | trust | revoke)"));
    }
    repo::RepoManager mgr{repo::RepoManager::DefaultConfigRoot()};
    const auto& action = args.positional[0];
    if (action == "list")
    {
        auto fps = mgr.ListTrustedFingerprints();
        if (!fps)
            return std::unexpected(fps.error());
        if (fps->empty())
        {
            std::printf("trust DB empty (keys dir: %s)\n", (mgr.ConfigRoot() / "keys").string().c_str());
            return 0;
        }
        for (const auto& fp : *fps)
            std::printf("%s\n", fp.c_str());
        return 0;
    }
    if (action == "trust")
    {
        if (args.positional.size() < 2)
        {
            return std::unexpected(
                MakeError(ErrorCode::InvalidArgument, "key trust: usage `key trust <pem-file-or-ed25519-string>`"));
        }
        const std::string_view src = args.positional[1];
        duet::crypto::PublicKey key{};
        if (src.starts_with("ed25519:"))
        {
            auto k = duet::crypto::ParsePublicKeyFromTomlString(src);
            if (!k)
                return std::unexpected(k.error());
            key = *k;
        }
        else
        {
            auto k = duet::crypto::LoadPublicKeyFromFile(std::filesystem::path{src});
            if (!k)
                return std::unexpected(k.error());
            key = *k;
        }
        auto rc = mgr.SaveTrustedKey(key);
        if (!rc)
            return std::unexpected(rc.error());
        std::printf("trusted key %s\n", duet::crypto::Fingerprint(key).c_str());
        return 0;
    }
    if (action == "revoke")
    {
        if (args.positional.size() < 2)
        {
            return std::unexpected(
                MakeError(ErrorCode::InvalidArgument, "key revoke: usage `key revoke <fingerprint>`"));
        }
        auto rc = mgr.RemoveTrustedKey(args.positional[1]);
        if (!rc)
            return std::unexpected(rc.error());
        std::printf("revoked %s\n", std::string{args.positional[1]}.c_str());
        return 0;
    }
    return std::unexpected(MakeError(ErrorCode::InvalidArgument, "key: unknown action: " + std::string{action}));
}

[[nodiscard]] Expected<int> CmdList(const ParsedArgs& args)
{
    // Phase 1 implements `list --installed` only.
    // `--available` arrives in Phase 4 with the repo cache.
    if (args.flag_available && !args.flag_installed)
    {
        return std::unexpected(MakeError(ErrorCode::InvalidArgument,
                                         "list --available requires the repo cache (Phase 4); "
                                         "use --installed today"));
    }
    duet::registry::Registry reg{duet::registry::Registry::DefaultRoot()};
    auto entries = reg.LoadAll();
    if (!entries)
        return std::unexpected(entries.error());
    if (entries->empty())
    {
        std::printf("no packages installed (registry root: %s)\n", reg.Root().string().c_str());
        return 0;
    }
    std::printf("%-32s %-16s %-24s %s\n", "NAME", "VERSION", "FROM", "PREFIX");
    for (const auto& e : *entries)
    {
        std::printf("%-32s %-16s %-24s %s\n", e.name.c_str(), e.version.c_str(),
                    e.installed_from.empty() ? "-" : e.installed_from.c_str(), e.install_prefix.c_str());
    }
    return 0;
}

[[nodiscard]] Expected<int> CmdInfo(const ParsedArgs& args)
{
    // Phase 1 takes the repo manifest path as the first positional
    // (typically a hand-crafted `repo.toml` on disk) plus the
    // package name as the second. The Phase-4 form is
    // `info <name>` against the synced repo cache; until that
    // cache exists, requiring the explicit path is the truthful
    // contract.
    if (args.positional.size() < 2)
    {
        return std::unexpected(MakeError(ErrorCode::InvalidArgument,
                                         "info: usage `info <repo.toml-path> <package-name>` "
                                         "(Phase 1 — repo cache lands in Phase 4)"));
    }
    const std::filesystem::path repo_path{args.positional[0]};
    auto repo_or = duet::repo::LoadRepoManifestFromFile(repo_path);
    if (!repo_or)
        return std::unexpected(repo_or.error());

    auto pkg_or = duet::repo::FindPackage(*repo_or, args.positional[1]);
    if (!pkg_or)
        return std::unexpected(pkg_or.error());

    const auto& pkg = **pkg_or;
    std::printf("name        : %s\n", pkg.name.c_str());
    std::printf("version     : %s\n", pkg.version.c_str());
    std::printf("arch        : %s\n", pkg.arch.c_str());
    std::printf("description : %s\n", pkg.description.c_str());
    std::printf("license     : %s\n", pkg.license.c_str());
    std::printf("source_url  : %s\n", pkg.source_url.c_str());
    std::printf("binary_url  : %s\n", pkg.binary_url.c_str());
    std::printf("sha256      : %s\n", pkg.sha256.c_str());
    std::printf("size        : %llu bytes (installed: %llu bytes)\n", static_cast<unsigned long long>(pkg.size_bytes),
                static_cast<unsigned long long>(pkg.installed_size_bytes));
    std::printf("deps        :");
    if (pkg.deps.empty())
    {
        std::printf(" (none)");
    }
    else
    {
        for (const auto& d : pkg.deps)
            std::printf(" %s", d.c_str());
    }
    std::printf("\n");
    std::printf("repo        : %s (maintainer: %s)\n", repo_or->name.c_str(),
                repo_or->maintainer.empty() ? "-" : repo_or->maintainer.c_str());
    return 0;
}

} // namespace

void PrintUsage()
{
    std::fprintf(stderr, "duet-pkg — DuetOS federated package manager\n"
                         "\n"
                         "usage: duet-pkg <subcommand> [options]\n"
                         "\n"
                         "Phase 1 subcommands (implemented):\n"
                         "  list --installed                 list locally installed packages\n"
                         "  info <repo.toml> <name>          show one package from a local repo manifest\n"
                         "\n"
                         "Phase 1 stubs (NotImplemented; arrive in later phases):\n"
                         "  install <name>                   Phase 5\n"
                         "  remove <name>                    Phase 5\n"
                         "  update [<name>]                  Phase 5\n"
                         "  search <query>                   Phase 7\n"
                         "  repo add/remove/list/sync        Phase 4\n"
                         "  key list/trust/revoke            Phase 4\n"
                         "  install-local <path>             Phase 6\n"
                         "  build <recipe.toml>              Phase 6\n"
                         "\n"
                         "Global flags:\n"
                         "  -v, --verbose                    show error detail\n"
                         "  -h, --help                       show this message\n");
}

Expected<ParsedArgs> ParseArgs(std::span<const std::string_view> argv)
{
    ParsedArgs out;
    // Accept `duet-pkg --help` / `-h` without a subcommand so a
    // bare `--help` doesn't trip "unknown subcommand". Verbose
    // alone also gets through — useful for "duet-pkg -v list".
    std::size_t cursor = 0;
    while (cursor < argv.size())
    {
        if (argv[cursor] == "--help" || argv[cursor] == "-h")
        {
            out.flag_help = true;
            ++cursor;
            continue;
        }
        if (argv[cursor] == "--verbose" || argv[cursor] == "-v")
        {
            out.flag_verbose = true;
            ++cursor;
            continue;
        }
        break;
    }
    if (cursor >= argv.size())
    {
        if (out.flag_help)
            return out;
        return std::unexpected(MakeError(ErrorCode::InvalidArgument, "no subcommand (try `duet-pkg --help`)"));
    }
    out.subcommand = argv[cursor++];
    for (std::size_t i = cursor; i < argv.size(); ++i)
    {
        const auto arg = argv[i];
        bool matched = false;
        for (const auto& vf : kValueFlags)
        {
            if (arg == vf.name)
            {
                if (i + 1 >= argv.size())
                {
                    return std::unexpected(MakeError(ErrorCode::InvalidArgument, std::string{arg} + ": missing value"));
                }
                out.*(vf.field) = argv[i + 1];
                ++i;
                matched = true;
                break;
            }
        }
        if (matched)
            continue;
        for (const auto& bf : kBoolFlags)
        {
            if (arg == bf.name)
            {
                out.*(bf.field) = true;
                matched = true;
                break;
            }
        }
        if (matched)
            continue;
        if (!arg.empty() && arg[0] == '-')
        {
            return std::unexpected(
                MakeError(ErrorCode::InvalidArgument, std::string{"unrecognised flag: "} + std::string{arg}));
        }
        out.positional.push_back(arg);
    }
    return out;
}

Expected<int> Run(const ParsedArgs& args)
{
    if (args.flag_help && args.subcommand.empty())
    {
        PrintUsage();
        return 0;
    }
    const auto& sub = args.subcommand;
    if (args.flag_help)
    {
        // `duet-pkg <sub> --help` — print usage, return 0. Future
        // phases can grow per-subcommand help blocks; the global
        // PrintUsage is enough for now.
        PrintUsage();
        return 0;
    }
    if (sub == "list")
        return CmdList(args);
    if (sub == "info")
        return CmdInfo(args);
    // Every other documented subcommand is a Phase-N stub. The
    // dispatcher recognises the verb (so misspellings still
    // produce "unknown subcommand") but returns NotImplemented
    // until the phase that owns it lands.
    if (sub == "repo")
        return CmdRepo(args);
    if (sub == "key")
        return CmdKey(args);
    if (sub == "install")
        return CmdInstall(args);
    if (sub == "remove")
        return CmdRemove(args);
    if (sub == "update")
        return CmdUpdate(args);
    if (sub == "search" || sub == "install-local" || sub == "build")
    {
        return CmdNotYet(sub);
    }
    PrintUsage();
    return std::unexpected(
        MakeError(ErrorCode::InvalidArgument, std::string{"unknown subcommand: "} + std::string{sub}));
}

} // namespace duet::cli
