// duet-pkg Phase 4 — repo manager integration tests.
//
// Generates a fresh Ed25519 keypair at startup, writes a signed
// repo.toml + repo.toml.sig pair to a temp dir, serves that dir
// via python3's http.server, and exercises
// `RepoManager::Add / Sync / Remove` end-to-end.
//
// SKIP (exit 77) when python3 is not on PATH.

#include "crypto/keying.hpp"
#include "crypto/verifier.hpp"
#include "repo/repo_manager.hpp"

#include <sodium.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <random>
#include <signal.h>
#include <span>
#include <sstream>
#include <string>
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

[[nodiscard]] std::filesystem::path MakeTempDir(const char* slug)
{
    static std::mt19937_64 rng{std::random_device{}()};
    const auto root = std::filesystem::temp_directory_path() / "duet-pkg-repo-mgr";
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

    [[nodiscard]] bool Start(const std::filesystem::path& serve_dir)
    {
        int port_pipe[2];
        if (::pipe(port_pipe) != 0)
            return false;
        pid = fork();
        if (pid < 0)
        {
            ::close(port_pipe[0]);
            ::close(port_pipe[1]);
            return false;
        }
        if (pid == 0)
        {
            ::dup2(port_pipe[1], 1);
            ::close(port_pipe[0]);
            ::close(port_pipe[1]);
            const int devnull = ::open("/dev/null", O_WRONLY);
            if (devnull >= 0)
            {
                ::dup2(devnull, 2);
                ::close(devnull);
            }
            ::chdir(serve_dir.c_str());
            const char* script = "import http.server, socketserver;"
                                 "h=http.server.SimpleHTTPRequestHandler;"
                                 "h.log_message=lambda *a, **k: None;"
                                 "s=socketserver.TCPServer(('127.0.0.1', 0), h);"
                                 "print(f'DUETPKG_PORT={s.server_address[1]}', flush=True);"
                                 "s.serve_forever()";
            ::execlp("python3", "python3", "-c", script, static_cast<char*>(nullptr));
            std::_Exit(127);
        }
        ::close(port_pipe[1]);
        char buf[64] = {};
        ssize_t pos = 0;
        while (pos < static_cast<ssize_t>(sizeof(buf) - 1))
        {
            char c = 0;
            const ssize_t got = ::read(port_pipe[0], &c, 1);
            if (got <= 0)
                break;
            if (c == '\n')
            {
                buf[pos] = '\0';
                break;
            }
            buf[pos++] = c;
        }
        ::close(port_pipe[0]);
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
            int status = 0;
            ::waitpid(pid, &status, 0);
            pid = -1;
        }
    }
};

// Build a valid repo.toml whose signing_key matches `pubkey_b64`.
// Two [[packages]] entries — enough to assert package_count.
[[nodiscard]] std::string MakeRepoToml(const std::string& pubkey_toml)
{
    std::ostringstream out;
    out << "[repo]\n";
    out << "name        = \"phase4test\"\n";
    out << "maintainer  = \"duet-pkg test harness\"\n";
    out << "version     = 1\n";
    out << "signing_key = \"" << pubkey_toml << "\"\n";
    out << "base_url    = \"http://example.invalid/packages/\"\n";
    out << "\n";
    out << "[[packages]]\n";
    out << "name        = \"alpha\"\n";
    out << "version     = \"1.0.0\"\n";
    out << "arch        = \"x86_64\"\n";
    out << "deps        = []\n";
    out << "sha256      = \"deadbeef\"\n";
    out << "\n";
    out << "[[packages]]\n";
    out << "name        = \"beta\"\n";
    out << "version     = \"2.0.0\"\n";
    out << "arch        = \"x86_64\"\n";
    out << "deps        = [\"alpha\"]\n";
    out << "sha256      = \"cafecafe\"\n";
    return out.str();
}

void WriteBinary(const std::filesystem::path& path, std::span<const std::uint8_t> body)
{
    std::ofstream out{path, std::ios::binary | std::ios::trunc};
    out.write(reinterpret_cast<const char*>(body.data()), static_cast<std::streamsize>(body.size()));
}

void WriteText(const std::filesystem::path& path, const std::string& body)
{
    WriteBinary(path, std::span<const std::uint8_t>{reinterpret_cast<const std::uint8_t*>(body.data()), body.size()});
}

struct SignedFixture
{
    std::array<std::uint8_t, 32> pubkey{};
    std::array<std::uint8_t, 64> seckey{};
    std::string repo_toml_body;
    std::vector<std::uint8_t> repo_toml_sig;
    std::string fingerprint_hex;
    std::filesystem::path serve_dir;
    HttpServerProc srv;
};

[[nodiscard]] bool BuildFixture(SignedFixture& fx)
{
    if (!duet::crypto::EnsureSodiumInit().has_value())
        return false;
    crypto_sign_keypair(fx.pubkey.data(), fx.seckey.data());
    duet::crypto::PublicKey pk{};
    pk.bytes = fx.pubkey;
    const std::string pk_toml = duet::crypto::PublicKeyToTomlString(pk);
    fx.fingerprint_hex = duet::crypto::Fingerprint(pk);
    fx.repo_toml_body = MakeRepoToml(pk_toml);
    fx.repo_toml_sig.resize(64);
    crypto_sign_detached(fx.repo_toml_sig.data(), nullptr,
                         reinterpret_cast<const std::uint8_t*>(fx.repo_toml_body.data()), fx.repo_toml_body.size(),
                         fx.seckey.data());
    fx.serve_dir = MakeTempDir("srv");
    WriteText(fx.serve_dir / "repo.toml", fx.repo_toml_body);
    WriteBinary(fx.serve_dir / "repo.toml.sig", fx.repo_toml_sig);
    return fx.srv.Start(fx.serve_dir);
}

// =========================================================
// Tests
// =========================================================

void TestAddSyncRemove(SignedFixture& fx, duet::repo::RepoManager& mgr)
{
    const std::string url = "http://127.0.0.1:" + std::to_string(fx.srv.port);

    // Add: signature verifies, fingerprint matches, index entry
    // populated.
    auto added = mgr.Add(url, fx.fingerprint_hex);
    EXPECT_TRUE(added.has_value(), "Add must succeed");
    EXPECT_EQ_STR(added->name, "phase4test");
    EXPECT_TRUE(added->package_count == 2, "package_count = 2");

    auto entries = mgr.LoadIndex();
    EXPECT_TRUE(entries.has_value(), "LoadIndex after Add");
    EXPECT_TRUE(entries->size() == 1, "index has 1 entry");
    EXPECT_EQ_STR((*entries)[0].name, "phase4test");

    auto manifest = mgr.LoadCachedManifest("phase4test");
    EXPECT_TRUE(manifest.has_value(), "cached manifest reads back");
    EXPECT_EQ_STR(manifest->name, "phase4test");
    EXPECT_TRUE(manifest->packages.size() == 2, "cached has 2 packages");

    // Sync: index gets a fresh last_synced. The remote body is
    // unchanged, so package_count stays 2.
    auto synced = mgr.Sync();
    EXPECT_TRUE(synced.has_value(), "Sync must succeed");
    EXPECT_TRUE(synced->size() == 1, "Sync of single repo");
    EXPECT_TRUE((*synced)[0].package_count == 2, "package_count survives sync");
    EXPECT_FALSE((*synced)[0].last_synced.empty(), "last_synced populated");

    // Remove: index entry + cached files + trusted key all gone.
    auto rm = mgr.Remove("phase4test");
    EXPECT_TRUE(rm.has_value(), "Remove must succeed");
    auto entries_after = mgr.LoadIndex();
    EXPECT_TRUE(entries_after.has_value(), "LoadIndex after Remove");
    EXPECT_TRUE(entries_after->empty(), "index is empty");

    const auto key_path = mgr.TrustedKeyPath(fx.fingerprint_hex);
    EXPECT_FALSE(std::filesystem::exists(key_path), "trusted key removed");
}

void TestAddRejectsWrongFingerprint(SignedFixture& fx, duet::repo::RepoManager& mgr)
{
    const std::string url = "http://127.0.0.1:" + std::to_string(fx.srv.port);
    const std::string bad_fp(64, '0');
    auto rc = mgr.Add(url, bad_fp);
    EXPECT_FALSE(rc.has_value(), "wrong fingerprint must fail");
    EXPECT_TRUE(rc.error().code == duet::ErrorCode::KeyNotTrusted, "code = KeyNotTrusted");
}

void TestAddRejectsBadFingerprintShape(SignedFixture& fx, duet::repo::RepoManager& mgr)
{
    const std::string url = "http://127.0.0.1:" + std::to_string(fx.srv.port);
    auto rc = mgr.Add(url, "not-hex");
    EXPECT_FALSE(rc.has_value(), "non-hex fingerprint must fail");
    EXPECT_TRUE(rc.error().code == duet::ErrorCode::KeyNotTrusted, "code = KeyNotTrusted");
}

void TestSyncDetectsTamperedRemote(SignedFixture& fx, duet::repo::RepoManager& mgr)
{
    const std::string url = "http://127.0.0.1:" + std::to_string(fx.srv.port);
    auto added = mgr.Add(url, fx.fingerprint_hex);
    EXPECT_TRUE(added.has_value(), "Add for tamper test");

    // Replace the served body with a slightly different one but
    // leave the .sig unchanged. Sync must reject.
    const std::string tampered = fx.repo_toml_body + "\n# extra line not signed\n";
    WriteText(fx.serve_dir / "repo.toml", tampered);

    auto synced = mgr.Sync();
    EXPECT_FALSE(synced.has_value(), "tampered body must fail sync");
    EXPECT_TRUE(synced.error().code == duet::ErrorCode::SignatureInvalid, "code = SignatureInvalid");

    // Restore body so subsequent tests against this fixture pass.
    WriteText(fx.serve_dir / "repo.toml", fx.repo_toml_body);
    (void)mgr.Remove("phase4test");
}

void TestTrustDb(duet::repo::RepoManager& mgr)
{
    // Fresh keypair → SaveTrustedKey → ListTrustedFingerprints
    // sees it → LoadTrustedKey returns the same bytes →
    // RemoveTrustedKey clears it.
    duet::crypto::PublicKey pk{};
    std::array<std::uint8_t, 64> sk{};
    crypto_sign_keypair(pk.bytes.data(), sk.data());
    const std::string fp = duet::crypto::Fingerprint(pk);

    auto save = mgr.SaveTrustedKey(pk);
    EXPECT_TRUE(save.has_value(), "SaveTrustedKey");

    auto fps = mgr.ListTrustedFingerprints();
    EXPECT_TRUE(fps.has_value(), "list trust DB");
    bool seen = false;
    for (const auto& s : *fps)
    {
        if (s == fp)
        {
            seen = true;
            break;
        }
    }
    EXPECT_TRUE(seen, "saved fingerprint enumerated");

    auto reloaded = mgr.LoadTrustedKey(fp);
    EXPECT_TRUE(reloaded.has_value(), "LoadTrustedKey");
    for (std::size_t i = 0; i < 32; ++i)
    {
        EXPECT_TRUE(reloaded->bytes[i] == pk.bytes[i], "byte matches");
    }

    auto rm = mgr.RemoveTrustedKey(fp);
    EXPECT_TRUE(rm.has_value(), "RemoveTrustedKey");
    auto miss = mgr.RemoveTrustedKey(fp);
    EXPECT_FALSE(miss.has_value(), "double-remove fails");
}

} // namespace

int main()
{
    if (std::system("command -v python3 > /dev/null 2>&1") != 0)
    {
        std::fprintf(stderr, "SKIP: python3 not on PATH; repo_manager integration test needs it\n");
        return 77;
    }
    if (!duet::crypto::EnsureSodiumInit().has_value())
    {
        std::fprintf(stderr, "FAIL: libsodium init failed\n");
        return 1;
    }
    SignedFixture fx;
    if (!BuildFixture(fx))
    {
        std::fprintf(stderr, "FAIL: could not start http server\n");
        return 1;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    const auto cfg = MakeTempDir("cfg");
    setenv("DUET_PKG_CONFIG_DIR", cfg.c_str(), 1);
    duet::repo::RepoManager mgr{cfg};

    TestAddSyncRemove(fx, mgr);
    TestAddRejectsWrongFingerprint(fx, mgr);
    TestAddRejectsBadFingerprintShape(fx, mgr);
    TestSyncDetectsTamperedRemote(fx, mgr);
    TestTrustDb(mgr);

    fx.srv.Stop();
    std::filesystem::remove_all(fx.serve_dir);
    std::filesystem::remove_all(cfg);

    if (g_failures == 0)
    {
        std::printf("all repo_manager tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "%d repo_manager test(s) FAILED\n", g_failures);
    return 1;
}
