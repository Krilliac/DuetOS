// duet-pkg Phase 5 — resolver unit tests.
//
// Pure-function tests against hand-built RepoManifest fixtures.
// No network, no crypto.

#include "resolve/resolver.hpp"

#include <cstdio>
#include <string>
#include <utility>
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

duet::repo::RepoPackageEntry Pkg(std::string name, std::vector<std::string> deps)
{
    duet::repo::RepoPackageEntry e;
    e.name = std::move(name);
    e.version = "1.0.0";
    e.arch = "x86_64";
    e.deps = std::move(deps);
    return e;
}

duet::repo::RepoManifest Manifest(std::string name, std::vector<duet::repo::RepoPackageEntry> packages)
{
    duet::repo::RepoManifest m;
    m.name = std::move(name);
    m.packages = std::move(packages);
    return m;
}

void TestSinglePackageNoDeps()
{
    std::vector<std::pair<std::string, duet::repo::RepoManifest>> repos{
        {"official", Manifest("official", {Pkg("alpha", {})})},
    };
    auto out = duet::resolve::Resolve("alpha", repos);
    EXPECT_TRUE(out.has_value(), "single package resolves");
    EXPECT_TRUE(out->size() == 1, "exactly one resolved");
    EXPECT_EQ_STR((*out)[0].entry.name, "alpha");
}

void TestLinearChainDepsFirst()
{
    // gamma -> beta -> alpha; resolving gamma should emit
    // alpha, beta, gamma in that order.
    std::vector<std::pair<std::string, duet::repo::RepoManifest>> repos{
        {"official", Manifest("official", {Pkg("alpha", {}), Pkg("beta", {"alpha"}), Pkg("gamma", {"beta"})})},
    };
    auto out = duet::resolve::Resolve("gamma", repos);
    EXPECT_TRUE(out.has_value(), "linear chain resolves");
    EXPECT_TRUE(out->size() == 3, "three resolved");
    EXPECT_EQ_STR((*out)[0].entry.name, "alpha");
    EXPECT_EQ_STR((*out)[1].entry.name, "beta");
    EXPECT_EQ_STR((*out)[2].entry.name, "gamma");
}

void TestDiamond()
{
    // top depends on left + right, both depend on bottom.
    // Order must put bottom first, then left + right (alphabetical
    // because the resolver's tie-break is stable on name), then top.
    std::vector<std::pair<std::string, duet::repo::RepoManifest>> repos{
        {"official", Manifest("official", {Pkg("bottom", {}), Pkg("left", {"bottom"}), Pkg("right", {"bottom"}),
                                           Pkg("top", {"left", "right"})})},
    };
    auto out = duet::resolve::Resolve("top", repos);
    EXPECT_TRUE(out.has_value(), "diamond resolves");
    EXPECT_TRUE(out->size() == 4, "four resolved");
    EXPECT_EQ_STR((*out)[0].entry.name, "bottom");
    EXPECT_EQ_STR((*out)[1].entry.name, "left");
    EXPECT_EQ_STR((*out)[2].entry.name, "right");
    EXPECT_EQ_STR((*out)[3].entry.name, "top");
}

void TestCycleDetected()
{
    std::vector<std::pair<std::string, duet::repo::RepoManifest>> repos{
        {"official", Manifest("official", {Pkg("alpha", {"beta"}), Pkg("beta", {"gamma"}), Pkg("gamma", {"alpha"})})},
    };
    auto out = duet::resolve::Resolve("alpha", repos);
    EXPECT_FALSE(out.has_value(), "cycle must fail");
    EXPECT_TRUE(out.error().code == duet::ErrorCode::DependencyCycle, "code = DependencyCycle");
}

void TestSelfLoopDetected()
{
    std::vector<std::pair<std::string, duet::repo::RepoManifest>> repos{
        {"official", Manifest("official", {Pkg("alpha", {"alpha"})})},
    };
    auto out = duet::resolve::Resolve("alpha", repos);
    EXPECT_FALSE(out.has_value(), "self-loop must fail");
    EXPECT_TRUE(out.error().code == duet::ErrorCode::DependencyCycle, "code = DependencyCycle");
}

void TestMissingDep()
{
    std::vector<std::pair<std::string, duet::repo::RepoManifest>> repos{
        {"official", Manifest("official", {Pkg("alpha", {"missing"})})},
    };
    auto out = duet::resolve::Resolve("alpha", repos);
    EXPECT_FALSE(out.has_value(), "missing dep must fail");
    EXPECT_TRUE(out.error().code == duet::ErrorCode::PackageNotFound, "code = PackageNotFound");
}

void TestMissingTarget()
{
    std::vector<std::pair<std::string, duet::repo::RepoManifest>> repos{
        {"official", Manifest("official", {Pkg("alpha", {})})},
    };
    auto out = duet::resolve::Resolve("nope", repos);
    EXPECT_FALSE(out.has_value(), "missing target must fail");
    EXPECT_TRUE(out.error().code == duet::ErrorCode::PackageNotFound, "code = PackageNotFound");
}

void TestPriorityFirstRepoWins()
{
    // "official" lists alpha 1.0.0; "community" lists alpha 2.0.0.
    // Official wins.
    auto alpha_v1 = Pkg("alpha", {});
    auto alpha_v2 = Pkg("alpha", {});
    alpha_v2.version = "2.0.0";
    std::vector<std::pair<std::string, duet::repo::RepoManifest>> repos{
        {"official", Manifest("official", {alpha_v1})},
        {"community", Manifest("community", {alpha_v2})},
    };
    auto out = duet::resolve::Resolve("alpha", repos);
    EXPECT_TRUE(out.has_value(), "priority resolves");
    EXPECT_TRUE(out->size() == 1, "one resolved");
    EXPECT_EQ_STR((*out)[0].entry.version, "1.0.0");
    EXPECT_EQ_STR((*out)[0].repo, "official");
}

} // namespace

int main()
{
    TestSinglePackageNoDeps();
    TestLinearChainDepsFirst();
    TestDiamond();
    TestCycleDetected();
    TestSelfLoopDetected();
    TestMissingDep();
    TestMissingTarget();
    TestPriorityFirstRepoWins();
    if (g_failures == 0)
    {
        std::printf("all resolver tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "%d resolver test(s) FAILED\n", g_failures);
    return 1;
}
