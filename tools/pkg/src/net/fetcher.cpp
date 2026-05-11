#include "net/fetcher.hpp"

#include <curl/curl.h>

#include <atomic>
#include <cstdio>
#include <fstream>
#include <mutex>
#include <string>
#include <utility>

namespace duet::net
{
namespace
{

std::once_flag g_curl_init_flag;
std::atomic<bool> g_curl_initialised{false};
std::atomic<int> g_curl_init_rc{0};

constexpr const char* kDefaultUserAgent = "duet-pkg/phase3";

// Per-transfer state stashed in libcurl's xfer-info userdata.
// Tracks the file handle (so the write callback can persist to
// disk) + the progress cb (so we can forward libcurl's notion
// of "total + downloaded" to the caller).
struct DownloadState
{
    std::ofstream out;
    ProgressCb progress;
    std::uint64_t resume_offset = 0;
};

std::size_t WriteCallback(char* ptr, std::size_t size, std::size_t nmemb, void* userdata) noexcept
{
    const std::size_t bytes = size * nmemb;
    auto* state = static_cast<DownloadState*>(userdata);
    if (state == nullptr || !state->out)
        return 0;
    state->out.write(ptr, static_cast<std::streamsize>(bytes));
    if (!state->out)
        return 0;
    return bytes;
}

int XferInfoCallback(void* userdata, curl_off_t dl_total, curl_off_t dl_now, curl_off_t /*ul_total*/,
                     curl_off_t /*ul_now*/) noexcept
{
    auto* state = static_cast<DownloadState*>(userdata);
    if (state == nullptr || !state->progress)
        return 0;
    const std::uint64_t total =
        dl_total > 0 ? state->resume_offset + static_cast<std::uint64_t>(dl_total) : state->resume_offset;
    const std::uint64_t downloaded = state->resume_offset + static_cast<std::uint64_t>(dl_now);
    state->progress(downloaded, total);
    return 0;
}

[[nodiscard]] std::uint64_t SizeIfExists(const std::filesystem::path& path) noexcept
{
    std::error_code ec;
    if (!std::filesystem::exists(path, ec))
        return 0;
    if (!std::filesystem::is_regular_file(path, ec))
        return 0;
    const auto sz = std::filesystem::file_size(path, ec);
    if (ec)
        return 0;
    return sz;
}

} // namespace

Expected<void> EnsureCurlGlobalInit() noexcept
{
    std::call_once(g_curl_init_flag,
                   []
                   {
                       const int rc = curl_global_init(CURL_GLOBAL_DEFAULT);
                       g_curl_init_rc.store(rc, std::memory_order_release);
                       g_curl_initialised.store(rc == 0, std::memory_order_release);
                   });
    if (!g_curl_initialised.load(std::memory_order_acquire))
    {
        return std::unexpected(MakeError(ErrorCode::NetworkError, "curl_global_init failed",
                                         "rc=" + std::to_string(g_curl_init_rc.load())));
    }
    return {};
}

void ShutdownCurlGlobal() noexcept
{
    if (g_curl_initialised.exchange(false, std::memory_order_acq_rel))
    {
        curl_global_cleanup();
    }
}

namespace
{

// One-shot download attempt. Returns CURLcode + final HTTP
// status so the outer Download function can decide whether to
// retry without Range when the server doesn't honour it.
struct AttemptResult
{
    CURLcode curl_rc;
    long http_status;
    std::string strerror;
};

[[nodiscard]] AttemptResult DoOnePerform(const std::string& url_str, const std::filesystem::path& dest_path,
                                         std::uint64_t resume_offset, const FetchOptions& opts, ProgressCb progress)
{
    AttemptResult result{CURLE_OK, 0, {}};
    CURL* curl = curl_easy_init();
    if (curl == nullptr)
    {
        result.curl_rc = CURLE_FAILED_INIT;
        result.strerror = "curl_easy_init failed";
        return result;
    }
    DownloadState state;
    state.progress = std::move(progress);
    state.resume_offset = resume_offset;
    const auto open_mode = resume_offset > 0 ? (std::ios::binary | std::ios::out | std::ios::app)
                                             : (std::ios::binary | std::ios::out | std::ios::trunc);
    state.out.open(dest_path, open_mode);
    if (!state.out.is_open())
    {
        curl_easy_cleanup(curl);
        result.curl_rc = CURLE_WRITE_ERROR;
        result.strerror = "cannot open dest: " + dest_path.string();
        return result;
    }

    const std::string ua = opts.user_agent.empty() ? std::string{kDefaultUserAgent} : opts.user_agent;
    curl_easy_setopt(curl, CURLOPT_URL, url_str.c_str());
    curl_easy_setopt(curl, CURLOPT_USERAGENT, ua.c_str());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 8L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, static_cast<long>(opts.connect_timeout_seconds));
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, static_cast<long>(opts.transfer_timeout_seconds));
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
    if (opts.allow_insecure)
    {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &state);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, state.progress ? 0L : 1L);
    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, &XferInfoCallback);
    curl_easy_setopt(curl, CURLOPT_XFERINFODATA, &state);
    if (resume_offset > 0)
    {
        curl_easy_setopt(curl, CURLOPT_RESUME_FROM_LARGE, static_cast<curl_off_t>(resume_offset));
    }

    result.curl_rc = curl_easy_perform(curl);
    state.out.flush();
    state.out.close();
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &result.http_status);
    if (result.curl_rc != CURLE_OK)
    {
        const char* msg = curl_easy_strerror(result.curl_rc);
        result.strerror = msg != nullptr ? msg : "";
    }
    curl_easy_cleanup(curl);
    return result;
}

} // namespace

Expected<void> Download(std::string_view url, const std::filesystem::path& dest_path, const FetchOptions& opts,
                        ProgressCb progress)
{
    auto init = EnsureCurlGlobalInit();
    if (!init)
        return std::unexpected(init.error());

    const std::string url_str{url};
    const std::uint64_t resume_offset = SizeIfExists(dest_path);

    AttemptResult r = DoOnePerform(url_str, dest_path, resume_offset, opts, progress);

    // Servers that don't honour Range produce CURLE_RANGE_ERROR
    // (33). When that happens AND we asked for a range, truncate
    // the dest and re-do the perform from byte 0. Anything else
    // is a real failure.
    if (r.curl_rc == CURLE_RANGE_ERROR && resume_offset > 0)
    {
        std::error_code ec;
        std::filesystem::remove(dest_path, ec);
        r = DoOnePerform(url_str, dest_path, 0, opts, progress);
    }

    if (r.curl_rc != CURLE_OK)
    {
        std::string detail = "curl_rc=" + std::to_string(static_cast<int>(r.curl_rc));
        if (r.http_status > 0)
            detail += " http_status=" + std::to_string(r.http_status);
        if (!r.strerror.empty())
            detail += std::string{" ("} + r.strerror + ")";
        return std::unexpected(MakeError(ErrorCode::NetworkError, "download failed: " + std::string{url}, detail));
    }
    if (r.http_status >= 400 || r.http_status == 0)
    {
        return std::unexpected(MakeError(ErrorCode::NetworkError, "download non-2xx status: " + std::string{url},
                                         "http_status=" + std::to_string(r.http_status)));
    }
    return {};
}

Expected<void> Download(std::string_view url, const std::filesystem::path& dest_path)
{
    return Download(url, dest_path, FetchOptions{}, ProgressCb{});
}

} // namespace duet::net
