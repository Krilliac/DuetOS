// duet-pkg Phase 6a — install-local integration test.
//
// Builds a real .tar.gz with a manifest, then invokes
// Installer::InstallLocal. Skips signature verification (by
// design); asserts the version dir + bin shim + registry entry
// all appear correctly. No network.
//
// SKIP (77) if tar isn't on PATH.

#include "install/installer.hpp"
#include "registry/registry.hpp"
#include "repo/repo_manager.hpp"

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace
{

int g_failures = 0;

#define EXPECT_TRUE(cond, msg)                                                                                         \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!(cond))                                                                                                   \
        {                                                                                                              \
            std::fprintf(stderr, "FAIL %s:%d: %s — expected true: %s\n", __FILE__, __LINE__, __func__, msg);           \
            ++g_failures;                                                                                              \
            return;                                                                                                    \
        }                                                                                                              \
    } while (0)

#define EXPECT_FALSE(cond, msg)                                                                                        \
    do                                                                                                                 \
    {                                                                                                                  \
        if ((cond))                                                                                                    \
        {                                                                                                              \
            std::fprintf(stderr, "FAIL %s:%d: %s — expected false: %s\n", __FILE__, __LINE__, __func__, msg);          \
            ++g_failures;                                                                                              \
            return;                                                                                                    \
        }                                                                                                              \
    } while (0)

[[nodiscard]] std::filesystem::path MakeTempDir(const char* slug)
{
    static std::mt19937_64 rng{std::random_device{}()};
    const auto root = std::filesystem::temp_directory_path() / "duet-pkg-local";
    std::filesystem::create_directories(root);
    auto d = root / (std::string{slug} + "-" + std::to_string(rng()));
    std::filesystem::create_directories(d);
    return d;
}

[[nodiscard]] bool BuildTar(const std::filesystem::path& staging, const std::filesystem::path& out_tar)
{
    pid_t pid = fork();
    if (pid < 0)
        return false;
    if (pid == 0)
    {
        ::chdir(staging.c_str());
        ::execlp("tar", "tar", "-czf", out_tar.c_str(), "bin", "manifest.toml", static_cast<char*>(nullptr));
        std::_Exit(127);
    }
    int st = 0;
    ::waitpid(pid, &st, 0);
    return WIFEXITED(st) && WEXITSTATUS(st) == 0;
}

void TestInstallLocalHappyPath()
{
    const auto pkg_prefix = MakeTempDir("pkg");
    const auto bin_prefix = MakeTempDir("bin");
    const auto cache = MakeTempDir("cache");
    const auto registry_root = MakeTempDir("reg");
    const auto cfg = MakeTempDir("cfg");
    const auto stage = MakeTempDir("stage");
    setenv("DUET_PKG_PREFIX", pkg_prefix.c_str(), 1);
    setenv("DUET_PKG_BIN_PREFIX", bin_prefix.c_str(), 1);
    setenv("DUET_PKG_CACHE", cache.c_str(), 1);
    setenv("DUET_PKG_REGISTRY", registry_root.c_str(), 1);
    setenv("DUET_PKG_CONFIG_DIR", cfg.c_str(), 1);

    std::filesystem::create_directories(stage / "bin");
    {
        std::ofstream b{stage / "bin" / "localpkg"};
        b << "#!/bin/sh\necho local\n";
    }
    ::chmod((stage / "bin" / "localpkg").c_str(), 0755);
    {
        std::ofstream m{stage / "manifest.toml"};
        m << "name = \"localpkg\"\n";
        m << "version = \"1.2.3\"\n";
        m << "arch = \"x86_64\"\n";
        m << "deps = []\n";
        m << "[install]\n";
        m << "bin = [\"bin/localpkg\"]\n";
    }
    const auto tar = MakeTempDir("tar") / "localpkg-1.2.3.tar.gz";
    EXPECT_TRUE(BuildTar(stage, tar), "tar built");

    duet::repo::RepoManager mgr{cfg};
    duet::install::Installer installer{duet::install::DefaultInstallPaths(), mgr};
    auto rc = installer.InstallLocal(tar);
    EXPECT_TRUE(rc.has_value(), "InstallLocal succeeds");

    EXPECT_TRUE(std::filesystem::exists(pkg_prefix / "localpkg" / "1.2.3" / "bin" / "localpkg"),
                "version dir + binary present");
    EXPECT_TRUE(std::filesystem::is_symlink(pkg_prefix / "localpkg" / "current"), "current symlink wired");
    EXPECT_TRUE(std::filesystem::is_symlink(bin_prefix / "localpkg"), "/usr/local/bin shim wired");

    duet::registry::Registry reg{registry_root};
    auto entry = reg.Find("localpkg");
    EXPECT_TRUE(entry.has_value(), "registry entry present");
    EXPECT_TRUE(entry->installed_from == "local", "installed_from = local");
    EXPECT_TRUE(!entry->sha256.empty(), "SHA-256 of tarball recorded");

    std::filesystem::remove_all(pkg_prefix);
    std::filesystem::remove_all(bin_prefix);
    std::filesystem::remove_all(cache);
    std::filesystem::remove_all(registry_root);
    std::filesystem::remove_all(cfg);
    std::filesystem::remove_all(stage);
    std::filesystem::remove_all(tar.parent_path());
}

void TestInstallLocalRejectsMissingManifest()
{
    const auto pkg_prefix = MakeTempDir("pkg");
    const auto bin_prefix = MakeTempDir("bin");
    const auto cache = MakeTempDir("cache");
    const auto registry_root = MakeTempDir("reg");
    const auto cfg = MakeTempDir("cfg");
    const auto stage = MakeTempDir("stage");
    setenv("DUET_PKG_PREFIX", pkg_prefix.c_str(), 1);
    setenv("DUET_PKG_BIN_PREFIX", bin_prefix.c_str(), 1);
    setenv("DUET_PKG_CACHE", cache.c_str(), 1);
    setenv("DUET_PKG_REGISTRY", registry_root.c_str(), 1);
    setenv("DUET_PKG_CONFIG_DIR", cfg.c_str(), 1);

    // Build a tar that's missing manifest.toml.
    std::filesystem::create_directories(stage / "bin");
    {
        std::ofstream b{stage / "bin" / "lonebin"};
        b << "#!/bin/sh\n";
    }
    const auto tar = MakeTempDir("tar") / "lone.tar.gz";
    pid_t pid = fork();
    if (pid == 0)
    {
        ::chdir(stage.c_str());
        ::execlp("tar", "tar", "-czf", tar.c_str(), "bin", static_cast<char*>(nullptr));
        std::_Exit(127);
    }
    int st = 0;
    ::waitpid(pid, &st, 0);

    duet::repo::RepoManager mgr{cfg};
    duet::install::Installer installer{duet::install::DefaultInstallPaths(), mgr};
    auto rc = installer.InstallLocal(tar);
    EXPECT_FALSE(rc.has_value(), "missing manifest must fail");
    EXPECT_TRUE(rc.error().code == duet::ErrorCode::ManifestMissingField, "code = ManifestMissingField");

    std::filesystem::remove_all(pkg_prefix);
    std::filesystem::remove_all(bin_prefix);
    std::filesystem::remove_all(cache);
    std::filesystem::remove_all(registry_root);
    std::filesystem::remove_all(cfg);
    std::filesystem::remove_all(stage);
    std::filesystem::remove_all(tar.parent_path());
}

} // namespace

int main()
{
    if (std::system("command -v tar > /dev/null 2>&1") != 0)
    {
        std::fprintf(stderr, "SKIP: tar must be on PATH\n");
        return 77;
    }
    TestInstallLocalHappyPath();
    TestInstallLocalRejectsMissingManifest();
    if (g_failures == 0)
    {
        std::printf("all install_local tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "%d install_local test(s) FAILED\n", g_failures);
    return 1;
}
