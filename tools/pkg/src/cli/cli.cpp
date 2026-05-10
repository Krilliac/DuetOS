#include "cli/cli.hpp"

#include "registry/registry.hpp"
#include "repo/repo_manifest.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>

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
};

[[nodiscard]] Expected<int> CmdNotYet(std::string_view subcommand)
{
    return std::unexpected(MakeError(ErrorCode::InvalidArgument, std::string{"subcommand '"} + std::string{subcommand} +
                                                                     "' is not yet implemented in this phase"));
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
    if (sub == "install" || sub == "remove" || sub == "update" || sub == "search" || sub == "repo" || sub == "key" ||
        sub == "install-local" || sub == "build")
    {
        return CmdNotYet(sub);
    }
    PrintUsage();
    return std::unexpected(
        MakeError(ErrorCode::InvalidArgument, std::string{"unknown subcommand: "} + std::string{sub}));
}

} // namespace duet::cli
