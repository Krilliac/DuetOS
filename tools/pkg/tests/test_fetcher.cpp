// duet-pkg Phase 3 — HTTP fetcher integration tests.
//
// Spins up a one-shot Python `http.server` on 127.0.0.1:<random
// port>, serves the fixtures directory, and exercises the
// Download path against it. No real network, no test-server
// dependency on the wider environment — just a child process.
//
// If `python3` is not on PATH the harness reports SKIP via
// exit-code 77 (the CMake-recognised "skip" convention).

#include "crypto/verifier.hpp"
#include "net/fetcher.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <random>
#include <signal.h>
#include <span>
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

// =========================================================
// One-shot Python http.server fixture.
// Forks a child running python3's SimpleHTTPRequestHandler
// bound to an ephemeral port; the child prints the assigned
// port over a pipe so the parent can talk to it. SIGTERM at
// teardown joins the child.
// =========================================================

struct HttpServerProc
{
    FILE* pipe = nullptr;
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
            // Silence stderr.
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
        // Read one line from the port pipe.
        char buf[64] = {};
        ssize_t got = 0;
        ssize_t pos = 0;
        while (pos < static_cast<ssize_t>(sizeof(buf) - 1))
        {
            got = ::read(port_pipe[0], buf + pos, 1);
            if (got <= 0)
                break;
            if (buf[pos] == '\n')
            {
                buf[pos] = '\0';
                break;
            }
            ++pos;
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

[[nodiscard]] std::filesystem::path MakeServeDir()
{
    static std::mt19937_64 rng{std::random_device{}()};
    const auto root = std::filesystem::temp_directory_path() / "duet-pkg-fetcher";
    std::filesystem::create_directories(root);
    auto dir = root / ("srv-" + std::to_string(rng()));
    std::filesystem::create_directories(dir);
    return dir;
}

// SHA-256 of "duet-pkg fetcher fixture, version 0\n" — the body
// our server hands out. Recomputed once when we write the file.
std::string g_payload_sha256;

void WritePayload(const std::filesystem::path& dir, const std::string& body)
{
    std::ofstream out{dir / "fetch.bin", std::ios::binary | std::ios::trunc};
    out.write(body.data(), static_cast<std::streamsize>(body.size()));
    g_payload_sha256 = duet::crypto::Sha256HexOfBytes(
        std::span<const std::uint8_t>{reinterpret_cast<const std::uint8_t*>(body.data()), body.size()});
}

void TestDownloadHappyPath(HttpServerProc& srv, const std::filesystem::path& dest_root)
{
    const auto dest = dest_root / "ok.bin";
    std::filesystem::remove(dest);
    const std::string url = "http://127.0.0.1:" + std::to_string(srv.port) + "/fetch.bin";
    auto rc = duet::net::Download(url, dest);
    EXPECT_TRUE(rc.has_value(), "happy-path download");
    auto verify = duet::crypto::VerifySha256(dest, g_payload_sha256);
    EXPECT_TRUE(verify.has_value(), "downloaded bytes match expected SHA-256");
}

void TestDownload404(HttpServerProc& srv, const std::filesystem::path& dest_root)
{
    const auto dest = dest_root / "404.bin";
    std::filesystem::remove(dest);
    const std::string url = "http://127.0.0.1:" + std::to_string(srv.port) + "/does-not-exist";
    auto rc = duet::net::Download(url, dest);
    EXPECT_FALSE(rc.has_value(), "404 should fail");
    EXPECT_TRUE(rc.error().code == duet::ErrorCode::NetworkError, "404 -> NetworkError");
}

void TestDownloadResume(HttpServerProc& srv, const std::filesystem::path& dest_root, const std::string& full_body)
{
    const auto dest = dest_root / "resume.bin";
    // Pre-populate the dest with the first half so the next
    // Download has to issue a Range request. SimpleHTTPRequestHandler
    // honours Range out of the box.
    const auto half = full_body.size() / 2;
    {
        std::ofstream out{dest, std::ios::binary | std::ios::trunc};
        out.write(full_body.data(), static_cast<std::streamsize>(half));
    }
    const std::string url = "http://127.0.0.1:" + std::to_string(srv.port) + "/fetch.bin";
    bool any_progress = false;
    auto rc = duet::net::Download(url, dest, duet::net::FetchOptions{},
                                  [&](std::uint64_t dn, std::uint64_t tot)
                                  {
                                      if (dn >= half)
                                          any_progress = true;
                                      (void)tot;
                                  });
    if (!rc)
    {
        std::fprintf(stderr, "  resume download error: %s | %s\n", rc.error().message.c_str(),
                     rc.error().detail.c_str());
    }
    EXPECT_TRUE(rc.has_value(), "resume download");
    EXPECT_TRUE(any_progress, "progress callback fires");
    auto verify = duet::crypto::VerifySha256(dest, g_payload_sha256);
    EXPECT_TRUE(verify.has_value(), "resumed bytes match expected SHA-256");
}

void TestDownloadProgress(HttpServerProc& srv, const std::filesystem::path& dest_root)
{
    const auto dest = dest_root / "progress.bin";
    std::filesystem::remove(dest);
    const std::string url = "http://127.0.0.1:" + std::to_string(srv.port) + "/fetch.bin";
    std::atomic<int> calls{0};
    auto rc = duet::net::Download(url, dest, duet::net::FetchOptions{}, [&](std::uint64_t, std::uint64_t) { ++calls; });
    EXPECT_TRUE(rc.has_value(), "progress download");
    EXPECT_TRUE(calls.load() > 0, "progress callback invoked at least once");
}

void TestDownloadConnectTimeout(const std::filesystem::path& dest_root)
{
    // 127.0.0.2 with a high random port — no listener should
    // exist there. Connect should fail; verify NetworkError
    // (which we ALWAYS get for a connect failure, whether by
    // timeout or by RST).
    const auto dest = dest_root / "timeout.bin";
    std::filesystem::remove(dest);
    duet::net::FetchOptions opts;
    opts.connect_timeout_seconds = 2;
    auto rc = duet::net::Download("http://127.0.0.2:1/never-listens", dest, opts, {});
    EXPECT_FALSE(rc.has_value(), "connect to dead port should fail");
    EXPECT_TRUE(rc.error().code == duet::ErrorCode::NetworkError, "dead port -> NetworkError");
}

} // namespace

int main()
{
    // SKIP if python3 isn't on PATH — the integration harness
    // needs it.
    if (std::system("command -v python3 > /dev/null 2>&1") != 0)
    {
        std::fprintf(stderr, "SKIP: python3 not on PATH; fetcher integration test needs it\n");
        return 77;
    }

    const auto serve_dir = MakeServeDir();
    const std::string body = "duet-pkg fetcher fixture, version 0\n" + std::string(8192, 'x'); // make resume meaningful
    WritePayload(serve_dir, body);

    HttpServerProc srv;
    if (!srv.Start(serve_dir))
    {
        std::fprintf(stderr, "FAIL: could not start python3 http.server\n");
        return 1;
    }

    // Wait briefly for the server to begin listening. The Python
    // process prints the port BEFORE serve_forever returns, but
    // we still want the socket to be in the listen state.
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    const auto dest_root = std::filesystem::temp_directory_path() / "duet-pkg-fetcher-dl";
    std::filesystem::create_directories(dest_root);

    TestDownloadHappyPath(srv, dest_root);
    TestDownload404(srv, dest_root);
    TestDownloadResume(srv, dest_root, body);
    TestDownloadProgress(srv, dest_root);
    TestDownloadConnectTimeout(dest_root);

    srv.Stop();
    std::filesystem::remove_all(dest_root);
    std::filesystem::remove_all(serve_dir);

    if (g_failures == 0)
    {
        std::printf("all fetcher tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "%d fetcher test(s) FAILED\n", g_failures);
    return 1;
}
