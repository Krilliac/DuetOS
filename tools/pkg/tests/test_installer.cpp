// duet-pkg Phase 5 — installer end-to-end integration test.
//
// Spins up a Python http.server serving:
//   /repo.toml + /repo.toml.sig         signed repo index
//   /packages/<pkg>-<ver>-x86_64.tar.gz + .sig    each package
//
// Drives the full install pipeline:
//   - repo add
//   - install (with one transitive dep — verifies topo order)
//   - registry entry present, version dir laid down, bin
//     symlink wired into $DUET_PKG_BIN_PREFIX
//   - remove (declines if dependent present, then succeeds with
//     reverse-dep order)
//
// SKIP (exit 77) when python3 / tar are not on PATH.

#include "crypto/keying.hpp"
#include "crypto/verifier.hpp"
#include "install/installer.hpp"
#include "install/uninstaller.hpp"
#include "registry/registry.hpp"
#include "repo/repo_manager.hpp"

#include <sodium.h>

#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <sys/stat.h>
#include <random>
#include <signal.h>
#include <span>
#include <sstream>
#include <string>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
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

[[nodiscard]] std::filesystem::path MakeTempDir(const char* slug)
{
    static std::mt19937_64 rng{std::random_device{}()};
    const auto root = std::filesystem::temp_directory_path() / "duet-pkg-install";
    std::filesystem::create_directories(root);
    auto dir = root / (std::string{slug} + "-" + std::to_string(rng()));
    std::filesystem::create_directories(dir);
    return dir;
}

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
            const char* script = "import http.server, socketserver;"
                                 "h=http.server.SimpleHTTPRequestHandler;"
                                 "h.log_message=lambda *a, **k: None;"
                                 "s=socketserver.TCPServer(('127.0.0.1', 0), h);"
                                 "print(f'P={s.server_address[1]}', flush=True);"
                                 "s.serve_forever()";
            ::execlp("python3", "python3", "-c", script, static_cast<char*>(nullptr));
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

void WriteText(const std::filesystem::path& p, const std::string& body)
{
    std::ofstream out{p, std::ios::binary | std::ios::trunc};
    out.write(body.data(), static_cast<std::streamsize>(body.size()));
}

void WriteBytes(const std::filesystem::path& p, std::span<const std::uint8_t> body)
{
    std::ofstream out{p, std::ios::binary | std::ios::trunc};
    out.write(reinterpret_cast<const char*>(body.data()), static_cast<std::streamsize>(body.size()));
}

[[nodiscard]] std::vector<std::uint8_t> SlurpBytes(const std::filesystem::path& p)
{
    std::ifstream in{p, std::ios::binary};
    return std::vector<std::uint8_t>((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

void SignDetached(std::span<const std::uint8_t> data, std::span<const std::uint8_t> sk,
                  std::array<std::uint8_t, 64>& out)
{
    crypto_sign_detached(out.data(), nullptr, data.data(), data.size(), sk.data());
}

// Build a `.tar.gz` containing:
//   bin/<name>     (a tiny shell script "echo I am <name>")
//   manifest.toml  (declares the bin/<name> entry)
// Shells out to `tar czf`.
[[nodiscard]] bool BuildPackageTar(const std::filesystem::path& staging, std::string_view name,
                                   std::string_view version, const std::vector<std::string>& deps,
                                   const std::filesystem::path& out_tar)
{
    std::filesystem::create_directories(staging / "bin");
    {
        std::ofstream b{staging / "bin" / std::string{name}};
        b << "#!/bin/sh\necho I am " << name << "\n";
    }
    ::chmod((staging / "bin" / std::string{name}).c_str(), 0755);
    {
        std::ostringstream m;
        m << "name = \"" << name << "\"\n";
        m << "version = \"" << version << "\"\n";
        m << "arch = \"x86_64\"\n";
        m << "deps = [";
        for (std::size_t i = 0; i < deps.size(); ++i)
        {
            if (i)
                m << ", ";
            m << "\"" << deps[i] << "\"";
        }
        m << "]\n";
        m << "[install]\n";
        m << "bin = [\"bin/" << name << "\"]\n";
        WriteText(staging / "manifest.toml", m.str());
    }
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

[[nodiscard]] std::string Sha256OfFile(const std::filesystem::path& p)
{
    auto bytes = SlurpBytes(p);
    return duet::crypto::Sha256HexOfBytes(bytes);
}

struct E2EFixture
{
    std::filesystem::path serve_dir;
    std::filesystem::path cfg_dir;
    std::filesystem::path stage_root;
    std::filesystem::path pkg_prefix;
    std::filesystem::path bin_prefix;
    std::filesystem::path cache_dir;
    std::filesystem::path registry_root;
    HttpServerProc srv;

    std::array<std::uint8_t, 32> pubkey{};
    std::array<std::uint8_t, 64> seckey{};
    std::string fp;
};

[[nodiscard]] bool BuildSignedRepo(E2EFixture& fx)
{
    crypto_sign_keypair(fx.pubkey.data(), fx.seckey.data());
    duet::crypto::PublicKey pk{};
    pk.bytes = fx.pubkey;
    fx.fp = duet::crypto::Fingerprint(pk);
    const std::string pk_toml = duet::crypto::PublicKeyToTomlString(pk);

    // Build two packages: leaf (no deps), trunk (depends on leaf).
    std::filesystem::create_directories(fx.serve_dir / "packages");
    auto leaf_stage = MakeTempDir("leaf-stage");
    auto trunk_stage = MakeTempDir("trunk-stage");
    const auto leaf_tar = fx.serve_dir / "packages" / "leaf-1.0.0-x86_64.tar.gz";
    const auto trunk_tar = fx.serve_dir / "packages" / "trunk-1.0.0-x86_64.tar.gz";
    if (!BuildPackageTar(leaf_stage, "leaf", "1.0.0", {}, leaf_tar))
        return false;
    if (!BuildPackageTar(trunk_stage, "trunk", "1.0.0", {"leaf"}, trunk_tar))
        return false;

    const std::string leaf_sha = Sha256OfFile(leaf_tar);
    const std::string trunk_sha = Sha256OfFile(trunk_tar);

    // Sign each tarball.
    {
        auto bytes = SlurpBytes(leaf_tar);
        std::array<std::uint8_t, 64> s{};
        SignDetached(bytes, fx.seckey, s);
        WriteBytes(leaf_tar.string() + ".sig", s);
    }
    {
        auto bytes = SlurpBytes(trunk_tar);
        std::array<std::uint8_t, 64> s{};
        SignDetached(bytes, fx.seckey, s);
        WriteBytes(trunk_tar.string() + ".sig", s);
    }

    // Build repo.toml + sign.
    const int port = fx.srv.port;
    std::ostringstream m;
    m << "[repo]\n";
    m << "name = \"e2e\"\n";
    m << "version = 1\n";
    m << "signing_key = \"" << pk_toml << "\"\n";
    m << "base_url = \"http://127.0.0.1:" << port << "/packages/\"\n";
    m << "\n[[packages]]\n";
    m << "name = \"leaf\"\n";
    m << "version = \"1.0.0\"\n";
    m << "arch = \"x86_64\"\n";
    m << "deps = []\n";
    m << "binary_url = \"leaf-1.0.0-x86_64.tar.gz\"\n";
    m << "sha256 = \"" << leaf_sha << "\"\n";
    m << "\n[[packages]]\n";
    m << "name = \"trunk\"\n";
    m << "version = \"1.0.0\"\n";
    m << "arch = \"x86_64\"\n";
    m << "deps = [\"leaf\"]\n";
    m << "binary_url = \"trunk-1.0.0-x86_64.tar.gz\"\n";
    m << "sha256 = \"" << trunk_sha << "\"\n";
    const std::string repo_body = m.str();
    WriteText(fx.serve_dir / "repo.toml", repo_body);
    std::array<std::uint8_t, 64> repo_sig{};
    SignDetached(
        std::span<const std::uint8_t>{reinterpret_cast<const std::uint8_t*>(repo_body.data()), repo_body.size()},
        fx.seckey, repo_sig);
    WriteBytes(fx.serve_dir / "repo.toml.sig", repo_sig);

    std::filesystem::remove_all(leaf_stage);
    std::filesystem::remove_all(trunk_stage);
    return true;
}

void TestE2E(E2EFixture& fx)
{
    duet::repo::RepoManager mgr{fx.cfg_dir};
    const std::string url = "http://127.0.0.1:" + std::to_string(fx.srv.port);
    auto added = mgr.Add(url, fx.fp);
    EXPECT_TRUE(added.has_value(), "Add e2e repo");

    duet::install::InstallPaths paths;
    paths.pkg_prefix = fx.pkg_prefix;
    paths.bin_prefix = fx.bin_prefix;
    paths.cache_dir = fx.cache_dir;
    paths.registry_root = fx.registry_root;
    duet::install::Installer installer{paths, mgr};

    auto repos = mgr.LoadIndex();
    EXPECT_TRUE(repos.has_value(), "LoadIndex");
    std::vector<std::pair<std::string, duet::repo::RepoManifest>> rlist;
    for (const auto& e : *repos)
    {
        auto m = mgr.LoadCachedManifest(e.name);
        EXPECT_TRUE(m.has_value(), "LoadCachedManifest");
        rlist.emplace_back(e.name, std::move(*m));
    }

    auto report = installer.Install("trunk", rlist);
    EXPECT_TRUE(report.has_value(), "Install trunk");
    EXPECT_TRUE(report->installed.size() == 2, "two packages installed");
    EXPECT_TRUE(report->installed[0] == "leaf", "leaf first (dep)");
    EXPECT_TRUE(report->installed[1] == "trunk", "trunk second");

    // Verify on-disk artefacts.
    EXPECT_TRUE(std::filesystem::exists(fx.pkg_prefix / "leaf" / "1.0.0" / "bin" / "leaf"),
                "leaf binary in version dir");
    EXPECT_TRUE(std::filesystem::is_symlink(fx.pkg_prefix / "leaf" / "current"), "current symlink for leaf");
    EXPECT_TRUE(std::filesystem::is_symlink(fx.bin_prefix / "leaf"), "/usr/local/bin/leaf shim");
    EXPECT_TRUE(std::filesystem::exists(fx.pkg_prefix / "trunk" / "1.0.0" / "manifest.toml"), "trunk manifest");
    EXPECT_TRUE(std::filesystem::is_symlink(fx.bin_prefix / "trunk"), "/usr/local/bin/trunk shim");

    duet::registry::Registry reg{fx.registry_root};
    auto entries = reg.LoadAll();
    EXPECT_TRUE(entries.has_value(), "registry LoadAll");
    EXPECT_TRUE(entries->size() == 2, "registry has 2 entries");

    // Second install run should be a no-op (already at version).
    auto rerun = installer.Install("trunk", rlist);
    EXPECT_TRUE(rerun.has_value(), "second Install");
    EXPECT_TRUE(rerun->installed.empty(), "second run installs nothing");
    EXPECT_TRUE(rerun->already_present.size() == 2, "second run sees both already present");

    // Uninstall: removing 'leaf' must refuse because 'trunk' depends.
    duet::install::Uninstaller un{paths};
    auto leaf_rm = un.Remove("leaf", /*force=*/false);
    EXPECT_FALSE(leaf_rm.has_value(), "leaf has dependents -> refuse");
    EXPECT_TRUE(leaf_rm.error().code == duet::ErrorCode::InstallFailed, "code = InstallFailed");

    // Remove trunk first, then leaf succeeds.
    auto trunk_rm = un.Remove("trunk", /*force=*/false);
    EXPECT_TRUE(trunk_rm.has_value(), "trunk remove");
    EXPECT_FALSE(std::filesystem::exists(fx.bin_prefix / "trunk"), "trunk shim gone");

    auto leaf_rm2 = un.Remove("leaf", /*force=*/false);
    EXPECT_TRUE(leaf_rm2.has_value(), "leaf remove after trunk");
    EXPECT_FALSE(std::filesystem::exists(fx.bin_prefix / "leaf"), "leaf shim gone");

    auto entries_after = reg.LoadAll();
    EXPECT_TRUE(entries_after.has_value() && entries_after->empty(), "registry empty");
}

} // namespace

int main()
{
    if (std::system("command -v python3 > /dev/null 2>&1") != 0 || std::system("command -v tar > /dev/null 2>&1") != 0)
    {
        std::fprintf(stderr, "SKIP: python3 + tar must be on PATH for installer e2e test\n");
        return 77;
    }
    if (!duet::crypto::EnsureSodiumInit().has_value())
    {
        std::fprintf(stderr, "FAIL: libsodium init failed\n");
        return 1;
    }
    E2EFixture fx;
    fx.serve_dir = MakeTempDir("srv");
    fx.cfg_dir = MakeTempDir("cfg");
    fx.pkg_prefix = MakeTempDir("pkg");
    fx.bin_prefix = MakeTempDir("bin");
    fx.cache_dir = MakeTempDir("cache");
    fx.registry_root = MakeTempDir("reg");
    if (!fx.srv.Start(fx.serve_dir))
    {
        std::fprintf(stderr, "FAIL: python http.server\n");
        return 1;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    if (!BuildSignedRepo(fx))
    {
        std::fprintf(stderr, "FAIL: BuildSignedRepo\n");
        return 1;
    }
    setenv("DUET_PKG_CONFIG_DIR", fx.cfg_dir.c_str(), 1);
    setenv("DUET_PKG_REGISTRY", fx.registry_root.c_str(), 1);
    setenv("DUET_PKG_PREFIX", fx.pkg_prefix.c_str(), 1);
    setenv("DUET_PKG_BIN_PREFIX", fx.bin_prefix.c_str(), 1);
    setenv("DUET_PKG_CACHE", fx.cache_dir.c_str(), 1);

    TestE2E(fx);

    fx.srv.Stop();
    std::filesystem::remove_all(fx.serve_dir);
    std::filesystem::remove_all(fx.cfg_dir);
    std::filesystem::remove_all(fx.pkg_prefix);
    std::filesystem::remove_all(fx.bin_prefix);
    std::filesystem::remove_all(fx.cache_dir);
    std::filesystem::remove_all(fx.registry_root);

    if (g_failures == 0)
    {
        std::printf("all installer tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "%d installer test(s) FAILED\n", g_failures);
    return 1;
}
