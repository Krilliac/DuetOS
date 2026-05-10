#include "build/builder.hpp"

#include "crypto/verifier.hpp"
#include "net/fetcher.hpp"

#include <toml++/toml.hpp>

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <random>
#include <sstream>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>

namespace duet::build
{
namespace
{

[[nodiscard]] Expected<std::string> RequireString(const toml::table& t, std::string_view key, std::string_view label)
{
    const auto* node = t.get(key);
    if (node == nullptr)
        return std::unexpected(MakeError(ErrorCode::ManifestMissingField,
                                         std::string{label} + ": missing required '" + std::string{key} + "'"));
    const auto* s = node->as_string();
    if (s == nullptr)
        return std::unexpected(MakeError(ErrorCode::ManifestBadType,
                                         std::string{label} + ": '" + std::string{key} + "' must be a string"));
    return std::string{s->get()};
}

[[nodiscard]] Expected<std::string> OptionalString(const toml::table& t, std::string_view key, std::string_view label)
{
    const auto* node = t.get(key);
    if (node == nullptr)
        return std::string{};
    const auto* s = node->as_string();
    if (s == nullptr)
        return std::unexpected(MakeError(ErrorCode::ManifestBadType,
                                         std::string{label} + ": '" + std::string{key} + "' must be a string"));
    return std::string{s->get()};
}

[[nodiscard]] Expected<std::vector<std::string>> OptionalStringArray(const toml::table& t, std::string_view key,
                                                                     std::string_view label)
{
    std::vector<std::string> out;
    const auto* node = t.get(key);
    if (node == nullptr)
        return out;
    const auto* arr = node->as_array();
    if (arr == nullptr)
        return std::unexpected(
            MakeError(ErrorCode::ManifestBadType, std::string{label} + ": '" + std::string{key} + "' must be array"));
    out.reserve(arr->size());
    for (std::size_t i = 0; i < arr->size(); ++i)
    {
        const auto* s = (*arr)[i].as_string();
        if (s == nullptr)
            return std::unexpected(MakeError(ErrorCode::ManifestBadType, std::string{label} + ": '" + std::string{key} +
                                                                             "' element must be string"));
        out.emplace_back(s->get());
    }
    return out;
}

[[nodiscard]] BuildSystem ParseBuildSystem(std::string_view s) noexcept
{
    if (s == "cmake")
        return BuildSystem::Cmake;
    if (s == "make")
        return BuildSystem::Make;
    if (s == "script")
        return BuildSystem::Script;
    return BuildSystem::Unknown;
}

[[nodiscard]] std::filesystem::path MakeTempScratch()
{
    static std::mt19937_64 rng{std::random_device{}()};
    const auto root = std::filesystem::temp_directory_path() / "duet-pkg-build";
    std::filesystem::create_directories(root);
    auto dir = root / ("scratch-" + std::to_string(rng()));
    std::filesystem::create_directories(dir);
    return dir;
}

// Run argv in `cwd`. Returns Ok on exit 0; otherwise InstallFailed
// with the exit code in `detail`. argv is NUL-terminated.
[[nodiscard]] Expected<void> RunProcess(const std::vector<std::string>& argv, const std::filesystem::path& cwd)
{
    if (argv.empty())
        return std::unexpected(MakeError(ErrorCode::InvalidArgument, "RunProcess: empty argv"));
    std::vector<char*> c_argv;
    c_argv.reserve(argv.size() + 1);
    for (const auto& s : argv)
        c_argv.push_back(const_cast<char*>(s.c_str()));
    c_argv.push_back(nullptr);
    pid_t pid = fork();
    if (pid < 0)
        return std::unexpected(MakeError(ErrorCode::InstallFailed, "fork for " + argv[0]));
    if (pid == 0)
    {
        if (!cwd.empty())
            ::chdir(cwd.c_str());
        ::execvp(c_argv[0], c_argv.data());
        std::_Exit(127);
    }
    int status = 0;
    if (::waitpid(pid, &status, 0) < 0)
        return std::unexpected(MakeError(ErrorCode::InstallFailed, "waitpid for " + argv[0]));
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    {
        std::string joined;
        for (std::size_t i = 0; i < argv.size(); ++i)
        {
            if (i)
                joined += ' ';
            joined += argv[i];
        }
        return std::unexpected(MakeError(ErrorCode::InstallFailed, "build step failed: " + argv[0],
                                         "exit=" + std::to_string(WIFEXITED(status) ? WEXITSTATUS(status) : -1) +
                                             " argv=[" + joined + "]"));
    }
    return {};
}

[[nodiscard]] bool ToolOnPath(const std::string& tool) noexcept
{
    const std::string cmd = "command -v " + tool + " > /dev/null 2>&1";
    return std::system(cmd.c_str()) == 0;
}

// Walk the extracted source dir. Most upstream tarballs contain
// a single top-level directory; if so, return that subdir as the
// "source root" so cmake/make commands run with the right layout.
[[nodiscard]] std::filesystem::path FindSourceRoot(const std::filesystem::path& extracted)
{
    std::vector<std::filesystem::path> children;
    std::error_code ec;
    for (const auto& de : std::filesystem::directory_iterator{extracted, ec})
    {
        if (ec)
            return extracted;
        children.push_back(de.path());
    }
    if (children.size() == 1 && std::filesystem::is_directory(children[0]))
        return children[0];
    return extracted;
}

} // namespace

std::string_view BuildSystemName(BuildSystem s) noexcept
{
    switch (s)
    {
    case BuildSystem::Unknown:
        return "unknown";
    case BuildSystem::Cmake:
        return "cmake";
    case BuildSystem::Make:
        return "make";
    case BuildSystem::Script:
        return "script";
    }
    return "?";
}

Expected<Recipe> ParseRecipeFromString(std::string_view toml, std::string_view label)
{
    toml::parse_result result = toml::parse(toml, label);
    if (!result)
        return std::unexpected(MakeError(ErrorCode::ManifestParseFailed, std::string{label} + ": TOML parse failed",
                                         std::string{result.error().description()}));
    const toml::table& root = result.table();

    Recipe r;
    auto name = RequireString(root, "name", label);
    if (!name)
        return std::unexpected(name.error());
    r.name = std::move(*name);

    auto version = RequireString(root, "version", label);
    if (!version)
        return std::unexpected(version.error());
    r.version = std::move(*version);

    auto src = OptionalString(root, "source", label);
    if (!src)
        return std::unexpected(src.error());
    r.source_url = std::move(*src);

    auto sha = OptionalString(root, "source_sha256", label);
    if (!sha)
        return std::unexpected(sha.error());
    r.source_sha256 = std::move(*sha);

    if (const auto* build_node = root.get_as<toml::table>("build"))
    {
        auto sys = RequireString(*build_node, "system", label);
        if (!sys)
            return std::unexpected(sys.error());
        r.system = ParseBuildSystem(*sys);
        if (r.system == BuildSystem::Unknown)
        {
            return std::unexpected(
                MakeError(ErrorCode::ManifestBadType, std::string{label} + ": [build].system unknown: " + *sys));
        }
        auto cfg = OptionalStringArray(*build_node, "configure", label);
        if (!cfg)
            return std::unexpected(cfg.error());
        r.configure = std::move(*cfg);
    }
    else
    {
        return std::unexpected(
            MakeError(ErrorCode::ManifestMissingField, std::string{label} + ": missing [build] table"));
    }

    if (const auto* deps_node = root.get_as<toml::table>("deps"))
    {
        auto bdeps = OptionalStringArray(*deps_node, "build", label);
        if (!bdeps)
            return std::unexpected(bdeps.error());
        r.deps.build = std::move(*bdeps);
        auto rdeps = OptionalStringArray(*deps_node, "runtime", label);
        if (!rdeps)
            return std::unexpected(rdeps.error());
        r.deps.runtime = std::move(*rdeps);
    }

    return r;
}

Expected<Recipe> ParseRecipeFromFile(const std::filesystem::path& path)
{
    std::ifstream in{path};
    if (!in.is_open())
        return std::unexpected(MakeError(ErrorCode::FilesystemError, "cannot open recipe: " + path.string()));
    std::ostringstream buf;
    buf << in.rdbuf();
    return ParseRecipeFromString(buf.str(), path.string());
}

Expected<std::string> Builder::Build(const Recipe& recipe, bool allow_insecure)
{
    // Build-deps gate: refuse if a declared build tool isn't on
    // PATH. Phase 6 doesn't auto-install build deps — that lands
    // when a real workload pulls a chain.
    for (const auto& tool : recipe.deps.build)
    {
        if (!ToolOnPath(tool))
        {
            return std::unexpected(MakeError(ErrorCode::InstallFailed, "build dep '" + tool + "' not on PATH",
                                             "install it via `duet-pkg install " + tool + "` first"));
        }
    }
    if (recipe.system == BuildSystem::Cmake && !ToolOnPath("cmake"))
    {
        return std::unexpected(MakeError(ErrorCode::InstallFailed, "cmake not on PATH"));
    }
    if (recipe.system == BuildSystem::Make && !ToolOnPath("make"))
    {
        return std::unexpected(MakeError(ErrorCode::InstallFailed, "make not on PATH"));
    }

    // 1. Download source.
    auto scratch = MakeTempScratch();
    const auto src_archive = scratch / "source.tar.gz";
    duet::net::FetchOptions opts;
    opts.allow_insecure = allow_insecure;
    auto dl = duet::net::Download(recipe.source_url, src_archive, opts, {});
    if (!dl)
    {
        std::filesystem::remove_all(scratch);
        return std::unexpected(dl.error());
    }
    if (!recipe.source_sha256.empty())
    {
        auto verify = duet::crypto::VerifySha256(src_archive, recipe.source_sha256);
        if (!verify)
        {
            std::filesystem::remove_all(scratch);
            return std::unexpected(verify.error());
        }
    }

    // 2. Extract.
    const auto extracted_root = scratch / "src";
    std::filesystem::create_directories(extracted_root);
    {
        const std::vector<std::string> tar_argv{"tar", "-xzf", src_archive.string(), "-C", extracted_root.string()};
        auto rc = RunProcess(tar_argv, {});
        if (!rc)
        {
            std::filesystem::remove_all(scratch);
            return std::unexpected(rc.error());
        }
    }
    const auto src_root = FindSourceRoot(extracted_root);
    const auto stage_root = scratch / "stage";
    std::filesystem::create_directories(stage_root);

    // 3. Run the build system. For cmake: configure into a
    // build dir, then `cmake --build`, then `cmake --install
    // --prefix <stage>`. For make: `make <configure args>` then
    // `make install PREFIX=<stage>`. For script: each `configure`
    // entry is a separate `sh -c <cmd>` in the source dir; the
    // last command is responsible for installing into <stage>.
    if (recipe.system == BuildSystem::Cmake)
    {
        const auto build_dir = scratch / "build";
        std::filesystem::create_directories(build_dir);
        std::vector<std::string> cfg{"cmake", "-S", src_root.string(), "-B", build_dir.string()};
        for (const auto& arg : recipe.configure)
            cfg.push_back(arg);
        if (auto rc = RunProcess(cfg, {}); !rc)
        {
            std::filesystem::remove_all(scratch);
            return std::unexpected(rc.error());
        }
        if (auto rc = RunProcess({"cmake", "--build", build_dir.string(), "--parallel"}, {}); !rc)
        {
            std::filesystem::remove_all(scratch);
            return std::unexpected(rc.error());
        }
        if (auto rc = RunProcess({"cmake", "--install", build_dir.string(), "--prefix", stage_root.string()}, {}); !rc)
        {
            std::filesystem::remove_all(scratch);
            return std::unexpected(rc.error());
        }
    }
    else if (recipe.system == BuildSystem::Make)
    {
        std::vector<std::string> argv{"make"};
        for (const auto& a : recipe.configure)
            argv.push_back(a);
        if (auto rc = RunProcess(argv, src_root); !rc)
        {
            std::filesystem::remove_all(scratch);
            return std::unexpected(rc.error());
        }
        if (auto rc = RunProcess({"make", "install", "PREFIX=" + stage_root.string()}, src_root); !rc)
        {
            std::filesystem::remove_all(scratch);
            return std::unexpected(rc.error());
        }
    }
    else if (recipe.system == BuildSystem::Script)
    {
        for (const auto& script : recipe.configure)
        {
            // Pass the script through `sh -c` so operators can
            // use shell features (pipes, vars). Expose
            // DUET_PKG_STAGE so the script knows where to
            // install.
            const std::string with_env = "DUET_PKG_STAGE=" + stage_root.string() + " ; " + script;
            if (auto rc = RunProcess({"sh", "-c", with_env}, src_root); !rc)
            {
                std::filesystem::remove_all(scratch);
                return std::unexpected(rc.error());
            }
        }
    }
    else
    {
        std::filesystem::remove_all(scratch);
        return std::unexpected(MakeError(ErrorCode::InvalidArgument,
                                         "unknown build system: " + std::string{BuildSystemName(recipe.system)}));
    }

    // 4. Drop a manifest.toml at the staging root so
    // InstallLocal can read it. The bin entries are the
    // executable files under stage/bin.
    {
        std::ostringstream m;
        m << "name = \"" << recipe.name << "\"\n";
        m << "version = \"" << recipe.version << "\"\n";
        m << "arch = \"x86_64\"\n";
        m << "deps = [";
        for (std::size_t i = 0; i < recipe.deps.runtime.size(); ++i)
        {
            if (i)
                m << ", ";
            m << "\"" << recipe.deps.runtime[i] << "\"";
        }
        m << "]\n";
        m << "[install]\n";
        std::vector<std::string> bins;
        const auto bin_dir = stage_root / "bin";
        std::error_code ec;
        if (std::filesystem::exists(bin_dir, ec))
        {
            for (const auto& de : std::filesystem::directory_iterator{bin_dir, ec})
            {
                if (ec)
                    break;
                if (de.is_regular_file())
                    bins.push_back("bin/" + de.path().filename().string());
            }
        }
        m << "bin = [";
        for (std::size_t i = 0; i < bins.size(); ++i)
        {
            if (i)
                m << ", ";
            m << "\"" << bins[i] << "\"";
        }
        m << "]\n";
        std::ofstream mf{stage_root / "manifest.toml", std::ios::trunc};
        mf << m.str();
    }

    // 5. Tar the stage dir.
    const auto out_tar = scratch / (recipe.name + "-" + recipe.version + "-x86_64.tar.gz");
    if (auto rc = RunProcess({"tar", "-czf", out_tar.string(), "-C", stage_root.string(), "."}, {}); !rc)
    {
        std::filesystem::remove_all(scratch);
        return std::unexpected(rc.error());
    }

    // 6. Hand to InstallLocal.
    auto name_or = m_installer.InstallLocal(out_tar);
    // Leave the scratch dir around on failure for forensic
    // inspection; clean on success.
    if (name_or)
        std::filesystem::remove_all(scratch);
    return name_or;
}

} // namespace duet::build
