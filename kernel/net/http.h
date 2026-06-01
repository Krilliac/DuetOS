/*
 * DuetOS — HTTP/1.1 client (transport-abstracted).
 *
 * A reusable HTTP/1.1 request engine that talks bytes through a
 * caller-supplied `HttpTransport`. Production wires the transport
 * to a plain TCP socket or to a TLS connection (same callback
 * shape `tls` uses); the boot self-test wires it to an in-memory
 * canned-response transport. This TU has NO dependency on the
 * `tls`, `socket`, `cookies`, or `browser` modules — it is pure
 * byte I/O over the transport plus request build / response parse.
 *
 * Scope:
 *   REAL — GET/POST, header build, status-line + header parse,
 *          Content-Length bodies, Transfer-Encoding: chunked
 *          (full decoder, hostile-length-safe), 3xx redirect
 *          following with absolute + relative Location resolution
 *          (hop-capped), Set-Cookie callback hook, caller-supplied
 *          Cookie header, optional body sink for over-cap streaming.
 *   GAP  — gzip/deflate content-encoding, HTTP/2, trailers,
 *          100-continue, multipart bodies, connection pooling /
 *          reuse across hosts.
 *
 * Threading: all state is on the caller-owned spec/result structs
 * or the stack. No global mutable state.
 */

#pragma once

#include "util/types.h"

namespace duetos::net::http
{

// -----------------------------------------------------------------
// Bounds. Headers and URLs live in fixed-size buffers so a hostile
// server can't drive an unbounded allocation. Bodies up to the
// caller's cap are buffered; beyond the cap they stream to a sink.
// -----------------------------------------------------------------
inline constexpr u32 kMaxHeaders = 32;       // parsed response header slots
inline constexpr u32 kMaxHeaderNameLen = 64; // per-header name
inline constexpr u32 kMaxHeaderValueLen = 1024;
inline constexpr u32 kMaxUrlLen = 1024;  // scheme+host+port+path
inline constexpr u32 kMaxHostLen = 256;  // host portion
inline constexpr u32 kMaxPathLen = 1024; // path+query portion
inline constexpr u32 kMaxReasonLen = 64; // status reason phrase
inline constexpr u32 kDefaultMaxRedirects = 5;
inline constexpr u32 kRequestBufCap = 4096; // outbound request bytes

// -----------------------------------------------------------------
// Byte transport. Mirrors the callback shape `tls` uses so a TLS
// connection or a raw socket can be plugged in without HTTP knowing
// which. `read`/`write` return bytes transferred, 0 on orderly EOF
// (read) or would-block, and a negative value on error.
// -----------------------------------------------------------------
struct HttpTransport
{
    i64 (*read)(void* ctx, u8* buf, u32 len);
    i64 (*write)(void* ctx, const u8* buf, u32 len);
    void* ctx;
};

enum class HttpMethod : u8
{
    Get,
    Post,
};

enum class HttpError : u8
{
    None = 0,
    TransportWrite,   // transport->write failed
    TransportRead,    // transport->read failed
    MalformedStatus,  // status line not "HTTP/1.x SSS ..."
    HeadersTooLarge,  // header block exceeded buffers
    BadChunk,         // chunked framing violated / hostile length
    BodyOverflow,     // body exceeded cap and no sink provided
    TooManyRedirects, // hop cap exhausted
    BadRedirect,      // 3xx without a usable Location
    BadUrl,           // could not parse target URL
    TransportConnect, // caller's connect hook failed for a redirect
};

// -----------------------------------------------------------------
// Body sink: invoked with each chunk of body bytes once the buffered
// `body` would exceed `body_cap`. Returns true to continue, false to
// abort the transfer. If null and the body exceeds the cap, the
// request fails with HttpError::BodyOverflow.
// -----------------------------------------------------------------
using HttpBodySink = bool (*)(const u8* data, u32 len, void* ctx);

// Set-Cookie hook: invoked once per `Set-Cookie` response header
// with the raw header value (decoupled from the cookie module).
using HttpSetCookie = void (*)(const char* header_value, void* ctx);

// -----------------------------------------------------------------
// Connect hook for redirect following. When a redirect points at a
// host/port/scheme, HTTP needs a fresh transport. The caller
// supplies a hook that opens a transport to (scheme_https, host,
// port) and writes it into *out. Returns true on success. If null,
// any redirect fails with HttpError::TransportConnect (v0 always
// opens fresh — no connection reuse).
// -----------------------------------------------------------------
using HttpConnect = bool (*)(bool scheme_https, const char* host, u16 port, HttpTransport* out, void* ctx);

struct HttpRequestSpec
{
    HttpMethod method = HttpMethod::Get;

    // Target. Either set url (parsed into host/port/path) OR set the
    // pre-split fields. If url[0] != 0 it wins.
    char url[kMaxUrlLen] = {};

    bool scheme_https = false;
    char host[kMaxHostLen] = {};
    u16 port = 80;
    char path[kMaxPathLen] = {"/"};

    const char* user_agent = "DuetOS/1.0";
    const char* accept = "*/*";
    bool keep_alive = false;             // Connection: keep-alive vs close
    const char* cookie_header = nullptr; // caller-supplied Cookie: value

    // POST body (ignored for GET).
    const char* content_type = nullptr;
    const u8* body = nullptr;
    u32 body_len = 0;

    // Redirect policy.
    u32 max_redirects = kDefaultMaxRedirects;
    HttpConnect on_connect = nullptr;
    void* connect_ctx = nullptr;

    // Body handling.
    u8* body_buf = nullptr; // caller-owned buffer for the response body
    u32 body_cap = 0;       // capacity of body_buf
    HttpBodySink body_sink = nullptr;
    void* sink_ctx = nullptr;

    // Cookie hook.
    HttpSetCookie on_set_cookie = nullptr;
    void* cookie_ctx = nullptr;
};

struct HttpHeader
{
    char name[kMaxHeaderNameLen];
    char value[kMaxHeaderValueLen];
};

struct HttpResult
{
    HttpError error = HttpError::None;
    u32 status_code = 0;
    char reason[kMaxReasonLen] = {};

    HttpHeader headers[kMaxHeaders];
    u32 header_count = 0;

    u32 body_len = 0;            // bytes buffered into body_buf
    bool body_truncated = false; // body exceeded cap and went to sink

    u32 redirect_count = 0;          // hops followed
    char final_url[kMaxUrlLen] = {}; // URL of the response actually returned

    // Case-insensitive header lookup. Returns nullptr if absent.
    const char* FindHeader(const char* name) const;
};

// -----------------------------------------------------------------
// Drive a full request/response (including redirect following) over
// `transport`. The transport supplied is used for the FIRST request;
// redirects use spec.on_connect to obtain a new transport. Returns
// the final response in *out.
// -----------------------------------------------------------------
bool HttpRequest(const HttpRequestSpec& spec, HttpTransport* transport, HttpResult* out);

// Parse a URL ("http[s]://host[:port][/path]" or "host[:port][/path]")
// into the split fields. Returns false on malformed input.
bool ParseUrl(const char* url, bool* scheme_https, char* host, u32 host_cap, u16* port, char* path, u32 path_cap);

// Resolve a (possibly relative) Location against a base origin into
// an absolute URL string. Handles "http://...", "//host/...",
// "/abs/path", and "rel/path". Returns false on overflow / malformed.
bool ResolveLocation(bool base_https, const char* base_host, u16 base_port, const char* base_path, const char* location,
                     char* out_url, u32 out_cap);

// Boot-time self-test. Drives an in-memory transport with canned
// HTTP/1.1 byte streams and asserts framing/parse correctness.
// Emits "[net/http-selftest] PASS (...)"; on failure emits FAIL and
// fires kBootSelftestFail.
void HttpSelfTest();

} // namespace duetos::net::http
