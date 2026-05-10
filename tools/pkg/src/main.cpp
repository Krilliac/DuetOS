#include "cli/cli.hpp"
#include "error.hpp"

#include <cstdio>
#include <span>
#include <string_view>
#include <vector>

namespace
{

[[nodiscard]] int ReportError(const duet::DuetPkgError& err, bool verbose) noexcept
{
    std::fprintf(stderr, "error: %s\n", err.message.c_str());
    if (verbose && !err.detail.empty())
    {
        std::fprintf(stderr, "       %s\n", err.detail.c_str());
    }
    // Use 2 for "argument / shape" errors so scripts can
    // distinguish CLI misuse from real failures; everything else
    // exits 1.
    return err.code == duet::ErrorCode::InvalidArgument ? 2 : 1;
}

} // namespace

int main(int argc, char** argv)
{
    std::vector<std::string_view> args;
    args.reserve(static_cast<std::size_t>(argc > 0 ? argc - 1 : 0));
    for (int i = 1; i < argc; ++i)
    {
        args.emplace_back(argv[i]);
    }

    auto parsed_or = duet::cli::ParseArgs(std::span<const std::string_view>{args});
    if (!parsed_or)
    {
        // We may not have a `--verbose` parsed yet — but the
        // detail string is best-effort anyway. Pass verbose=true
        // so the parse error reason isn't suppressed.
        return ReportError(parsed_or.error(), /*verbose=*/true);
    }
    const auto& parsed = *parsed_or;

    auto rc_or = duet::cli::Run(parsed);
    if (!rc_or)
    {
        return ReportError(rc_or.error(), parsed.flag_verbose);
    }
    return *rc_or;
}
