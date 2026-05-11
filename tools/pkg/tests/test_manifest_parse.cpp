// duet-pkg Phase 1 — manifest parse + registry round-trip tests.
//
// Frameworkless. The kernel's `tests/host/` directory uses the
// same pattern (no Google Test, no Catch2) and it scales fine
// for the unit-test surface we need. Each test is a plain
// function; main runs them in sequence and reports the first
// failure with file:line via a tiny assert helper.

#include "registry/registry.hpp"
#include "repo/package_manifest.hpp"
#include "repo/repo_manifest.hpp"

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <random>
#include <sstream>
#include <string>
#include <string_view>

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

#define EXPECT_EQ_STR(actual, expected)                                                                                \
    do                                                                                                                 \
    {                                                                                                                  \
        const std::string _a{(actual)};                                                                                \
        const std::string _e{(expected)};                                                                              \
        if (_a != _e)                                                                                                  \
        {                                                                                                              \
            std::fprintf(stderr, "FAIL %s:%d: %s — expected '%s' got '%s'\n", __FILE__, __LINE__, __func__,            \
                         _e.c_str(), _a.c_str());                                                                      \
            ++g_failures;                                                                                              \
            return;                                                                                                    \
        }                                                                                                              \
    } while (0)

#define EXPECT_EQ_INT(actual, expected)                                                                                \
    do                                                                                                                 \
    {                                                                                                                  \
        const long long _a = static_cast<long long>(actual);                                                           \
        const long long _e = static_cast<long long>(expected);                                                         \
        if (_a != _e)                                                                                                  \
        {                                                                                                              \
            std::fprintf(stderr, "FAIL %s:%d: %s — expected %lld got %lld\n", __FILE__, __LINE__, __func__, _e, _a);   \
            ++g_failures;                                                                                              \
            return;                                                                                                    \
        }                                                                                                              \
    } while (0)

[[nodiscard]] std::string FixturePath(const char* leaf)
{
    return std::string{DUET_PKG_FIXTURES_DIR} + "/" + leaf;
}

[[nodiscard]] std::filesystem::path MakeTempRegistry()
{
    static std::mt19937_64 rng{std::random_device{}()};
    const auto base = std::filesystem::temp_directory_path() / "duet-pkg-test";
    std::filesystem::create_directories(base);
    auto dir = base / ("reg-" + std::to_string(rng()));
    std::filesystem::create_directories(dir);
    return dir;
}

// =========================================================
// Repo manifest tests
// =========================================================

void TestRepoManifestBasic()
{
    auto repo_or = duet::repo::LoadRepoManifestFromFile(FixturePath("repo_basic.toml"));
    EXPECT_TRUE(repo_or.has_value(), "repo_basic.toml should parse");
    const auto& repo = *repo_or;
    EXPECT_EQ_STR(repo.name, "official");
    EXPECT_EQ_STR(repo.maintainer, "Nathan");
    EXPECT_EQ_INT(repo.version, 1);
    EXPECT_EQ_STR(repo.signing_key, "ed25519:AAAAC3NzaC1lZDI1NTE5AAAAITESTKEYBYTESDONOTUSE");
    EXPECT_EQ_STR(repo.base_url, "https://example.org/packages/");
    EXPECT_EQ_INT(repo.packages.size(), 2);

    // libz first (alphabetical in the fixture); but we don't
    // assume order — look both up.
    auto libz_or = duet::repo::FindPackage(repo, "libz");
    EXPECT_TRUE(libz_or.has_value(), "libz should be present");
    EXPECT_EQ_STR((*libz_or)->version, "1.3.1");
    EXPECT_EQ_INT((*libz_or)->deps.size(), 0);
    EXPECT_EQ_INT((*libz_or)->size_bytes, 204800);

    auto neovim_or = duet::repo::FindPackage(repo, "neovim");
    EXPECT_TRUE(neovim_or.has_value(), "neovim should be present");
    EXPECT_EQ_STR((*neovim_or)->version, "0.10.0");
    EXPECT_EQ_INT((*neovim_or)->deps.size(), 2);
    EXPECT_EQ_STR((*neovim_or)->deps[0], "libc");
    EXPECT_EQ_STR((*neovim_or)->deps[1], "libz");
    EXPECT_EQ_STR((*neovim_or)->sha256, "abc123");
    EXPECT_EQ_INT((*neovim_or)->size_bytes, 8388608);
    EXPECT_EQ_INT((*neovim_or)->installed_size_bytes, 24117248);
}

void TestRepoManifestMissingTopLevel()
{
    const std::string body = R"(
        [[packages]]
        name = "stray"
        version = "1.0.0"
    )";
    auto repo_or = duet::repo::LoadRepoManifestFromString(body, "<inline:missing-repo>");
    EXPECT_TRUE(!repo_or.has_value(), "should reject manifest with no [repo] table");
    EXPECT_EQ_INT(static_cast<int>(repo_or.error().code), static_cast<int>(duet::ErrorCode::ManifestMissingField));
}

void TestRepoManifestMissingRequired()
{
    // No `name` in the [repo] table is fatal — every repo MUST
    // identify itself.
    const std::string body = R"(
        [repo]
        version = 1
    )";
    auto repo_or = duet::repo::LoadRepoManifestFromString(body, "<inline:missing-repo-name>");
    EXPECT_TRUE(!repo_or.has_value(), "should reject manifest with no [repo].name");
    EXPECT_EQ_INT(static_cast<int>(repo_or.error().code), static_cast<int>(duet::ErrorCode::ManifestMissingField));
}

void TestRepoManifestWrongType()
{
    // `version` here is a string where we expect an integer.
    const std::string body = R"(
        [repo]
        name = "broken"
        version = "not-an-integer"
    )";
    auto repo_or = duet::repo::LoadRepoManifestFromString(body, "<inline:bad-version>");
    EXPECT_TRUE(!repo_or.has_value(), "should reject string in integer field");
    EXPECT_EQ_INT(static_cast<int>(repo_or.error().code), static_cast<int>(duet::ErrorCode::ManifestBadType));
}

void TestRepoManifestParseError()
{
    // Genuine TOML syntax error: dangling `=`.
    const std::string body = "[repo\nname = ";
    auto repo_or = duet::repo::LoadRepoManifestFromString(body, "<inline:syntax>");
    EXPECT_TRUE(!repo_or.has_value(), "should reject malformed TOML");
    EXPECT_EQ_INT(static_cast<int>(repo_or.error().code), static_cast<int>(duet::ErrorCode::ManifestParseFailed));
}

void TestFindPackageMiss()
{
    auto repo_or = duet::repo::LoadRepoManifestFromFile(FixturePath("repo_basic.toml"));
    EXPECT_TRUE(repo_or.has_value(), "fixture should parse");
    auto miss = duet::repo::FindPackage(*repo_or, "no-such-package");
    EXPECT_TRUE(!miss.has_value(), "lookup of missing name should fail");
    EXPECT_EQ_INT(static_cast<int>(miss.error().code), static_cast<int>(duet::ErrorCode::PackageNotFound));
}

// =========================================================
// Package manifest tests
// =========================================================

void TestPackageManifestBasic()
{
    auto pkg_or = duet::repo::LoadPackageManifestFromFile(FixturePath("package_basic.toml"));
    EXPECT_TRUE(pkg_or.has_value(), "package_basic.toml should parse");
    const auto& pkg = *pkg_or;
    EXPECT_EQ_STR(pkg.name, "neovim");
    EXPECT_EQ_STR(pkg.version, "0.10.0");
    EXPECT_EQ_STR(pkg.arch, "x86_64");
    EXPECT_EQ_STR(pkg.license, "Apache-2.0");
    EXPECT_EQ_INT(pkg.deps.size(), 2);
    EXPECT_EQ_INT(pkg.install.bin.size(), 1);
    EXPECT_EQ_STR(pkg.install.bin[0], "bin/nvim");
    EXPECT_EQ_INT(pkg.install.lib.size(), 0);
    EXPECT_EQ_INT(pkg.install.share.size(), 1);
    EXPECT_EQ_STR(pkg.install.share[0], "share/nvim");
}

void TestPackageManifestMissingRequired()
{
    const std::string body = R"(
        version = "1.0.0"
    )";
    auto pkg_or = duet::repo::LoadPackageManifestFromString(body, "<inline:pkg-no-name>");
    EXPECT_TRUE(!pkg_or.has_value(), "package manifest with no name must fail");
    EXPECT_EQ_INT(static_cast<int>(pkg_or.error().code), static_cast<int>(duet::ErrorCode::ManifestMissingField));
}

void TestPackageManifestInstallBadType()
{
    const std::string body = R"(
        name = "broken"
        version = "1.0.0"
        [install]
        bin = "not-an-array"
    )";
    auto pkg_or = duet::repo::LoadPackageManifestFromString(body, "<inline:bad-install>");
    EXPECT_TRUE(!pkg_or.has_value(), "install.bin must be an array");
    EXPECT_EQ_INT(static_cast<int>(pkg_or.error().code), static_cast<int>(duet::ErrorCode::ManifestBadType));
}

// =========================================================
// Registry round-trip tests
// =========================================================

void TestRegistryEmptyDirIsEmpty()
{
    auto dir = MakeTempRegistry();
    duet::registry::Registry reg{dir};
    auto all = reg.LoadAll();
    EXPECT_TRUE(all.has_value(), "LoadAll on empty registry should succeed");
    EXPECT_EQ_INT(all->size(), 0);
    std::filesystem::remove_all(dir);
}

void TestRegistryWriteFindRoundTrip()
{
    auto dir = MakeTempRegistry();
    duet::registry::Registry reg{dir};
    duet::registry::RegistryEntry e{};
    e.name = "neovim";
    e.version = "0.10.0";
    e.installed_at = "2026-05-08T12:00:00Z";
    e.installed_from = "official";
    e.install_prefix = "/pkg/neovim/0.10.0";
    e.sha256 = "abc123";
    e.deps = {"libc", "libz"};
    auto write_rc = reg.Write(e);
    EXPECT_TRUE(write_rc.has_value(), "Write should succeed");

    auto found = reg.Find("neovim");
    EXPECT_TRUE(found.has_value(), "Find after Write should succeed");
    EXPECT_EQ_STR(found->version, "0.10.0");
    EXPECT_EQ_STR(found->install_prefix, "/pkg/neovim/0.10.0");
    EXPECT_EQ_INT(found->deps.size(), 2);
    EXPECT_EQ_STR(found->deps[0], "libc");

    auto all = reg.LoadAll();
    EXPECT_TRUE(all.has_value(), "LoadAll after Write should succeed");
    EXPECT_EQ_INT(all->size(), 1);
    EXPECT_EQ_STR((*all)[0].name, "neovim");

    auto rm_rc = reg.Remove("neovim");
    EXPECT_TRUE(rm_rc.has_value(), "Remove should succeed");

    auto miss = reg.Find("neovim");
    EXPECT_TRUE(!miss.has_value(), "Find after Remove should fail");
    EXPECT_EQ_INT(static_cast<int>(miss.error().code), static_cast<int>(duet::ErrorCode::PackageNotFound));

    std::filesystem::remove_all(dir);
}

void TestRegistryRejectsBadName()
{
    auto dir = MakeTempRegistry();
    duet::registry::Registry reg{dir};
    auto bad = reg.Find("../etc/passwd");
    EXPECT_TRUE(!bad.has_value(), "path-traversal name must be rejected");
    EXPECT_EQ_INT(static_cast<int>(bad.error().code), static_cast<int>(duet::ErrorCode::InvalidArgument));
    std::filesystem::remove_all(dir);
}

void TestRegistryLoadAllSortsByName()
{
    auto dir = MakeTempRegistry();
    duet::registry::Registry reg{dir};
    auto write_one = [&](std::string_view name)
    {
        duet::registry::RegistryEntry e{};
        e.name = name;
        e.version = "1.0.0";
        return reg.Write(e);
    };
    EXPECT_TRUE(write_one("zoo").has_value(), "Write zoo");
    EXPECT_TRUE(write_one("alpha").has_value(), "Write alpha");
    EXPECT_TRUE(write_one("mango").has_value(), "Write mango");
    auto all = reg.LoadAll();
    EXPECT_TRUE(all.has_value(), "LoadAll succeed");
    EXPECT_EQ_INT(all->size(), 3);
    EXPECT_EQ_STR((*all)[0].name, "alpha");
    EXPECT_EQ_STR((*all)[1].name, "mango");
    EXPECT_EQ_STR((*all)[2].name, "zoo");
    std::filesystem::remove_all(dir);
}

} // namespace

int main()
{
    TestRepoManifestBasic();
    TestRepoManifestMissingTopLevel();
    TestRepoManifestMissingRequired();
    TestRepoManifestWrongType();
    TestRepoManifestParseError();
    TestFindPackageMiss();
    TestPackageManifestBasic();
    TestPackageManifestMissingRequired();
    TestPackageManifestInstallBadType();
    TestRegistryEmptyDirIsEmpty();
    TestRegistryWriteFindRoundTrip();
    TestRegistryRejectsBadName();
    TestRegistryLoadAllSortsByName();
    if (g_failures == 0)
    {
        std::printf("all manifest_parse tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "%d manifest_parse test(s) FAILED\n", g_failures);
    return 1;
}
