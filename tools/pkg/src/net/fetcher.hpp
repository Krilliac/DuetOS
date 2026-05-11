#pragma once

#include "error.hpp"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <string_view>

/*
 * duet-pkg Phase 3 — HTTP/HTTPS download via libcurl.
 *
 * The fetcher is the only path packages enter the system from.
 * v0 supports a single GET per call; resume is automatic when
 * `dest` already contains a partial file (libcurl's
 * `CURLOPT_RESUME_FROM_LARGE`). Progress is reported via an
 * optional callback so the CLI can render a bar.
 *
 * TLS: enabled by default, peer-cert + hostname verification on.
 * `--insecure` (the CLI flag, plumbed through `FetchOptions`)
 * turns off peer + host verification only — never the protocol
 * itself. Used for self-hosted HTTP repos and CI smoke tests.
 */

namespace duet::net
{

using ProgressCb = std::function<void(std::uint64_t downloaded, std::uint64_t total)>;

struct FetchOptions
{
    // Connect timeout in seconds. Past this, the connect attempt
    // is aborted and the call returns `NetworkError`. Default
    // matches the spec.
    int connect_timeout_seconds = 30;
    // Overall transfer timeout in seconds. 0 = no timeout (the
    // default). The CLI does not currently expose this knob.
    int transfer_timeout_seconds = 0;
    // Disable TLS peer + host verification. Use ONLY for
    // self-hosted HTTP / staging mirrors that the operator
    // explicitly trusts.
    bool allow_insecure = false;
    // If non-empty, libcurl's user-agent header is set to this
    // string. Default is `duet-pkg/<phase>`.
    std::string user_agent;
};

/// Download a single URL to `dest_path`. Resumes from a partial
/// file at `dest_path` if it exists and the server honours a
/// Range request; otherwise restarts from byte 0.
///
/// Returns `Ok` on a 2xx response; `NetworkError` for any
/// transport / DNS / TLS failure, non-2xx HTTP status, or
/// timeout. The HTTP status code lands in the error `detail`
/// for `--verbose`.
///
/// `progress` may be empty; libcurl polls it on its internal
/// progress cadence (~once per second under default settings).
[[nodiscard]] Expected<void> Download(std::string_view url, const std::filesystem::path& dest_path,
                                      const FetchOptions& opts, ProgressCb progress);

/// Convenience wrapper: no progress callback, default options.
[[nodiscard]] Expected<void> Download(std::string_view url, const std::filesystem::path& dest_path);

/// Initialise libcurl globally. Safe to call repeatedly; the
/// internal flag makes the second+ calls no-ops. Most callers
/// don't need this — `Download` calls it on first use.
[[nodiscard]] Expected<void> EnsureCurlGlobalInit() noexcept;

/// Global teardown — matches `curl_global_cleanup`. Optional;
/// safe at process exit. Not needed for short-lived CLI runs
/// but kept around so a long-running service can release the
/// global state cleanly.
void ShutdownCurlGlobal() noexcept;

} // namespace duet::net
