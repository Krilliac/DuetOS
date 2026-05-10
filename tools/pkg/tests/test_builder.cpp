// duet-pkg Phase 6b — recipe parser unit tests + happy-path
// end-to-end build smoke (script-style).
//
// The cmake / make e2e paths are deliberately not covered here
// — they need a project checkout to compile. The script-style
// path exercises the full Builder pipeline (download → extract
// → run script → tar staging → InstallLocal) against a tiny
// local "source tarball" served by python http.server.
//
// SKIP (77) if python3 / tar are not on PATH.

#include "build/builder.hpp"
#include "install/installer.hpp"
#include "repo/repo_manager.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <random>
#include <signal.h>
#include <string>
#include <sys/stat.h>
#include <sys/wait.h>
#include <thread>
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

#define EXPECT_EQ_STR(a, b)                                                                                            \
    do                                                                                                                 \
    {                                                                                                                  \
        const std::string _a{(a)};                                                                                     \
        const std::string _b{(b)};                                                                                     \
        if (_a != _b)                                                                                                  \
        {                                                                                                              \
            std::fprintf(stderr, "FAIL %s:%d: %s — expected '%s' got '%s'\n", __FILE__, __LINE__, __func__,            \
                         _b.c_str(), _a.c_str());                                                                      \
            ++g_failures;                                                                                              \
            return;                                                                                                    \
        }                                                                                                              \
    } while (0)

[[nodiscard]] std::filesystem::path MakeTempDir(const char* slug)
{
    static std::mt19937_64 rng{std::random_device{}()};
    const auto root = std::filesystem::temp_directory_path() / "duet-pkg-builder";
    std::filesystem::create_directories(root);
    auto d = root / (std::string{slug} + "-" + std::to_string(rng()));
    std::filesystem::create_directories(d);
    return d;
}

// ---------- recipe parser tests ----------

void TestParseRecipeHappyPath()
{
    const std::string body = R"(
        name = "myapp"
        version = "1.0.0"
        source = "https://example.org/myapp-1.0.0.tar.gz"
        source_sha256 = "abc123"

        [build]
        system = "cmake"
        configure = ["-DCMAKE_BUILD_TYPE=Release"]

        [deps]
        build = ["cmake"]
        runtime = ["libz"]
    )";
    auto r = duet::build::ParseRecipeFromString(body, "<inline>");
    EXPECT_TRUE(r.has_value(), "happy recipe parses");
    EXPECT_EQ_STR(r->name, "myapp");
    EXPECT_EQ_STR(r->version, "1.0.0");
    EXPECT_TRUE(r->system == duet::build::BuildSystem::Cmake, "system = Cmake");
    EXPECT_TRUE(r->configure.size() == 1, "one configure arg");
    EXPECT_TRUE(r->deps.build.size() == 1, "one build dep");
    EXPECT_TRUE(r->deps.runtime.size() == 1, "one runtime dep");
}

void TestParseRecipeUnknownSystem()
{
    const std::string body = R"(
        name = "x"
        version = "1"
        [build]
        system = "bazel"
    )";
    auto r = duet::build::ParseRecipeFromString(body, "<inline>");
    EXPECT_FALSE(r.has_value(), "unknown system must fail");
}

void TestParseRecipeMissingBuild()
{
    const std::string body = R"(
        name = "x"
        version = "1"
    )";
    auto r = duet::build::ParseRecipeFromString(body, "<inline>");
    EXPECT_FALSE(r.has_value(), "missing [build] must fail");
}

// ---------- end-to-end script-build test ----------

struct HttpServerProc
{
    pid_t pid = -1;
    int port = 0;
    ~HttpServerProc() { Stop(); }
    [[nodiscard]] bool Start(const std::filesystem::path& dir)
    {
        int pp[2];
        if (::pipe(pp) != 0)
            return false;
        pid = fork();
        if (pid < 0)
        {
            ::close(pp[0]);
            ::close(pp[1]);
            return false;
        }
        if (pid == 0)
        {
            ::dup2(pp[1], 1);
            ::close(pp[0]);
            ::close(pp[1]);
            int dn = ::open("/dev/null", O_WRONLY);
            if (dn >= 0)
            {
                ::dup2(dn, 2);
                ::close(dn);
            }
            ::chdir(dir.c_str());
            const char* s = "import http.server, socketserver;"
                            "h=http.server.SimpleHTTPRequestHandler;"
                            "h.log_message=lambda *a, **k: None;"
                            "s=socketserver.TCPServer(('127.0.0.1', 0), h);"
                            "print(f'P={s.server_address[1]}', flush=True);"
                            "s.serve_forever()";
            ::execlp("python3", "python3", "-c", s, static_cast<char*>(nullptr));
            std::_Exit(127);
        }
        ::close(pp[1]);
        char buf[64] = {};
        ssize_t pos = 0;
        while (pos < static_cast<ssize_t>(sizeof(buf) - 1))
        {
            char c = 0;
            const ssize_t got = ::read(pp[0], &c, 1);
            if (got <= 0)
                break;
            if (c == '\n')
            {
                buf[pos] = '\0';
                break;
            }
            buf[pos++] = c;
        }
        ::close(pp[0]);
        const std::string s{buf};
        const auto eq = s.find('=');
        if (eq == std::string::npos)
            return false;
        port = std::atoi(s.c_str() + eq + 1);
        return port > 0;
    }
    void Stop() noexcept
    {
        if (pid > 0)
        {
            ::kill(pid, SIGTERM);
            int st = 0;
            ::waitpid(pid, &st, 0);
            pid = -1;
        }
    }
};

void TestBuildScriptEndToEnd(HttpServerProc& srv, const std::filesystem::path& serve_dir,
                             const std::filesystem::path& pkg_prefix, const std::filesystem::path& bin_prefix,
                             const std::filesystem::path& /*registry_root*/)
{
    // The "source" tarball we serve: src/hello.txt + an Install.
    // The recipe's script step copies hello.txt into
    // $DUET_PKG_STAGE/bin/scripted (chmod +x).
    const auto src_dir = MakeTempDir("src");
    std::filesystem::create_directories(src_dir / "buildme");
    {
        std::ofstream f{src_dir / "buildme" / "hello.txt"};
        f << "#!/bin/sh\necho hi from scripted\n";
    }
    pid_t pid = fork();
    if (pid == 0)
    {
        ::chdir(src_dir.c_str());
        ::execlp("tar", "tar", "-czf", (serve_dir / "src.tar.gz").c_str(), "buildme", static_cast<char*>(nullptr));
        std::_Exit(127);
    }
    int st = 0;
    ::waitpid(pid, &st, 0);
    EXPECT_TRUE(WIFEXITED(st) && WEXITSTATUS(st) == 0, "source tarball built");

    duet::build::Recipe recipe;
    recipe.name = "scripted";
    recipe.version = "0.1.0";
    recipe.source_url = "http://127.0.0.1:" + std::to_string(srv.port) + "/src.tar.gz";
    recipe.system = duet::build::BuildSystem::Script;
    recipe.configure = {// Single shell command that lays down the staged binary.
                        "mkdir -p \"$DUET_PKG_STAGE/bin\" && cp hello.txt \"$DUET_PKG_STAGE/bin/scripted\" && "
                        "chmod +x \"$DUET_PKG_STAGE/bin/scripted\""};

    duet::repo::RepoManager mgr{MakeTempDir("cfg")};
    duet::install::Installer installer{duet::install::DefaultInstallPaths(), mgr};
    duet::build::Builder builder{installer};
    auto rc = builder.Build(recipe);
    EXPECT_TRUE(rc.has_value(), "script build + install round-trip");
    if (rc)
        EXPECT_EQ_STR(*rc, "scripted");

    EXPECT_TRUE(std::filesystem::exists(pkg_prefix / "scripted" / "0.1.0" / "bin" / "scripted"),
                "scripted binary present");
    EXPECT_TRUE(std::filesystem::is_symlink(bin_prefix / "scripted"), "/usr/local/bin/scripted wired");

    std::filesystem::remove_all(src_dir);
}

} // namespace

int main()
{
    TestParseRecipeHappyPath();
    TestParseRecipeUnknownSystem();
    TestParseRecipeMissingBuild();

    if (std::system("command -v python3 > /dev/null 2>&1") != 0 || std::system("command -v tar > /dev/null 2>&1") != 0)
    {
        std::fprintf(stderr, "SKIP: python3 + tar needed for builder e2e — parser tests passed\n");
        return g_failures == 0 ? 77 : 1;
    }

    const auto serve = MakeTempDir("srv");
    const auto pkg = MakeTempDir("pkg");
    const auto bin = MakeTempDir("bin");
    const auto cache = MakeTempDir("cache");
    const auto reg = MakeTempDir("reg");
    setenv("DUET_PKG_PREFIX", pkg.c_str(), 1);
    setenv("DUET_PKG_BIN_PREFIX", bin.c_str(), 1);
    setenv("DUET_PKG_CACHE", cache.c_str(), 1);
    setenv("DUET_PKG_REGISTRY", reg.c_str(), 1);
    HttpServerProc srv;
    if (!srv.Start(serve))
    {
        std::fprintf(stderr, "FAIL: python http.server\n");
        return 1;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    TestBuildScriptEndToEnd(srv, serve, pkg, bin, reg);

    srv.Stop();
    std::filesystem::remove_all(serve);
    std::filesystem::remove_all(pkg);
    std::filesystem::remove_all(bin);
    std::filesystem::remove_all(cache);
    std::filesystem::remove_all(reg);

    if (g_failures == 0)
    {
        std::printf("all builder tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "%d builder test(s) FAILED\n", g_failures);
    return 1;
}
