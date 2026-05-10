#pragma once

#include "error.hpp"

#include <span>
#include <string_view>
#include <vector>

/*
 * duet-pkg CLI dispatcher.
 *
 * Phase 1 covers the subcommand parser + handlers for the two
 * Phase-1 deliverables (`list --installed`, `info <name>`).
 * Everything else dispatches to a "not implemented in Phase N"
 * stub so the CLI surface itself is stable; later phases just
 * fill in the corresponding handlers.
 */

namespace duet::cli
{

struct ParsedArgs
{
    std::string_view subcommand;
    std::vector<std::string_view> positional;
    bool flag_installed = false;
    bool flag_available = false;
    bool flag_verbose = false;
    bool flag_help = false;
    std::string_view opt_repo;    // --repo <name>
    std::string_view opt_version; // --version <ver>
    std::string_view opt_repo_url;
    std::string_view opt_trust_key; // --trust-key <fingerprint>
};

/// Parse `argv[1..argc]` into a `ParsedArgs`. Returns
/// `InvalidArgument` for malformed flag syntax (e.g. `--repo`
/// with no value).
[[nodiscard]] Expected<ParsedArgs> ParseArgs(std::span<const std::string_view> argv);

/// Run a parsed CLI invocation. Top-level main() converts the
/// returned status into the process exit code (0 on Ok, non-zero
/// otherwise) and prints the error message.
[[nodiscard]] Expected<int> Run(const ParsedArgs& args);

/// One-line description of every supported subcommand, mirroring
/// DUETOS_PKG_IMPLEMENTATION.md. Printed by `--help` and on
/// `unknown subcommand`.
void PrintUsage();

} // namespace duet::cli
