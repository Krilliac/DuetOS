/*
 * DuetOS — HTTP/1.1 client (transport-abstracted). See http.h for
 * the design contract and the REAL/GAP scope boundary.
 *
 * The engine is a straight-line: build request bytes -> transport
 * write -> read+parse status line -> read+parse header block ->
 * read body (Content-Length or chunked) into a bounded buffer (or
 * a sink past the cap) -> follow 3xx redirects up to the hop cap.
 *
 * Hostile-input discipline: every length read off the wire is
 * bounds-checked against a fixed buffer before it is used; chunk
 * sizes are parsed with overflow guards; the header count and the
 * redirect count are capped; nothing here calls into an allocator.
 */

#include "net/http.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"
#include "util/string.h"

namespace duetos::net::http
{

namespace
{

using duetos::core::StrEqualCaseInsensitive;
using duetos::core::StrLen;

// ---- small char helpers (no libc in kernel) ----

bool IsDigit(char c)
{
    return c >= '0' && c <= '9';
}

bool IsHexDigit(char c)
{
    return IsDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

u32 HexVal(char c)
{
    if (IsDigit(c))
    {
        return static_cast<u32>(c - '0');
    }
    if (c >= 'a' && c <= 'f')
    {
        return static_cast<u32>(c - 'a' + 10);
    }
    return static_cast<u32>(c - 'A' + 10);
}

// Byte compare; returns 0 iff the first n bytes match.
int MemCmp(const void* a, const void* b, u32 n)
{
    const u8* pa = static_cast<const u8*>(a);
    const u8* pb = static_cast<const u8*>(b);
    for (u32 i = 0; i < n; ++i)
    {
        if (pa[i] != pb[i])
        {
            return static_cast<int>(pa[i]) - static_cast<int>(pb[i]);
        }
    }
    return 0;
}

// Case-insensitive prefix match: does `s` start with `pre`?
bool HasPrefixCi(const char* s, const char* pre)
{
    for (u32 i = 0; pre[i] != '\0'; ++i)
    {
        char a = s[i];
        char b = pre[i];
        if (a >= 'A' && a <= 'Z')
        {
            a = static_cast<char>(a - 'A' + 'a');
        }
        if (b >= 'A' && b <= 'Z')
        {
            b = static_cast<char>(b - 'A' + 'a');
        }
        if (a != b)
        {
            return false;
        }
    }
    return true;
}

// Copy a NUL-terminated string into dst[cap], always NUL-terminating.
void CopyStr(char* dst, u32 cap, const char* src)
{
    if (cap == 0)
    {
        return;
    }
    u32 i = 0;
    if (src != nullptr)
    {
        for (; src[i] != '\0' && i + 1 < cap; ++i)
        {
            dst[i] = src[i];
        }
    }
    dst[i] = '\0';
}

// Append a base-10 number into a growing buffer.
void AppendU32(char* dst, u32* pos, u32 cap, u32 v)
{
    char tmp[12];
    u32 n = 0;
    if (v == 0)
    {
        tmp[n++] = '0';
    }
    while (v > 0 && n < sizeof(tmp))
    {
        tmp[n++] = static_cast<char>('0' + (v % 10));
        v /= 10;
    }
    while (n > 0 && *pos + 1 < cap)
    {
        dst[(*pos)++] = tmp[--n];
    }
}

void Append(char* dst, u32* pos, u32 cap, const char* s)
{
    duetos::core::AppendStr(dst, pos, cap, s);
}

// Decimal string -> u32, stopping at first non-digit. Saturates.
u32 ParseU32(const char* s, u32 len)
{
    u64 v = 0;
    for (u32 i = 0; i < len && IsDigit(s[i]); ++i)
    {
        v = v * 10 + static_cast<u64>(s[i] - '0');
        if (v > 0xFFFFFFFFull)
        {
            return 0xFFFFFFFFu;
        }
    }
    return static_cast<u32>(v);
}

} // namespace

// -----------------------------------------------------------------
// HttpResult::FindHeader — case-insensitive lookup.
// -----------------------------------------------------------------
const char* HttpResult::FindHeader(const char* name) const
{
    for (u32 i = 0; i < header_count; ++i)
    {
        if (StrEqualCaseInsensitive(headers[i].name, name))
        {
            return headers[i].value;
        }
    }
    return nullptr;
}

// -----------------------------------------------------------------
// ParseUrl — "http[s]://host[:port][/path]" or "host[:port][/path]".
// -----------------------------------------------------------------
bool ParseUrl(const char* url, bool* scheme_https, char* host, u32 host_cap, u16* port, char* path, u32 path_cap)
{
    if (url == nullptr || host == nullptr || path == nullptr || host_cap == 0 || path_cap == 0)
    {
        return false;
    }

    bool https = false;
    const char* p = url;

    // Scheme (optional).
    if (HasPrefixCi(url, "https://"))
    {
        https = true;
        p = url + 8;
    }
    else if (HasPrefixCi(url, "http://"))
    {
        https = false;
        p = url + 7;
    }

    // Host: up to ':' or '/' or end.
    u32 hi = 0;
    while (*p != '\0' && *p != ':' && *p != '/' && hi + 1 < host_cap)
    {
        host[hi++] = *p++;
    }
    host[hi] = '\0';
    if (hi == 0)
    {
        return false;
    }
    // If host field overflowed (next char is still a host char), reject.
    if (*p != '\0' && *p != ':' && *p != '/')
    {
        return false;
    }

    // Port (optional).
    u16 prt = https ? 443 : 80;
    if (*p == ':')
    {
        ++p;
        u32 v = 0;
        u32 digits = 0;
        while (IsDigit(*p))
        {
            v = v * 10 + static_cast<u32>(*p - '0');
            ++digits;
            if (v > 65535 || digits > 5)
            {
                return false;
            }
            ++p;
        }
        if (digits == 0)
        {
            return false;
        }
        prt = static_cast<u16>(v);
    }

    // Path: rest (default "/").
    u32 pi = 0;
    if (*p == '/')
    {
        while (*p != '\0' && pi + 1 < path_cap)
        {
            path[pi++] = *p++;
        }
        if (*p != '\0')
        {
            return false; // path overflow
        }
    }
    else if (*p == '\0')
    {
        path[pi++] = '/';
    }
    else
    {
        return false; // garbage after host/port
    }
    path[pi] = '\0';

    if (scheme_https != nullptr)
    {
        *scheme_https = https;
    }
    if (port != nullptr)
    {
        *port = prt;
    }
    return true;
}

// -----------------------------------------------------------------
// ResolveLocation — fold a Location header against the base origin.
// -----------------------------------------------------------------
bool ResolveLocation(bool base_https, const char* base_host, u16 base_port, const char* base_path, const char* location,
                     char* out_url, u32 out_cap)
{
    if (location == nullptr || out_url == nullptr || out_cap == 0)
    {
        return false;
    }

    // Absolute URL ("http://..." / "https://...") — pass through.
    u32 pos = 0;
    if (HasPrefixCi(location, "http://") || HasPrefixCi(location, "https://"))
    {
        CopyStr(out_url, out_cap, location);
        return StrLen(location) + 1 <= out_cap;
    }

    // Scheme-relative ("//host/path").
    Append(out_url, &pos, out_cap, base_https ? "https://" : "http://");
    if (location[0] == '/' && location[1] == '/')
    {
        Append(out_url, &pos, out_cap, location + 2);
        out_url[pos < out_cap ? pos : out_cap - 1] = '\0';
        return pos + 1 < out_cap;
    }

    // Origin prefix: host[:port].
    Append(out_url, &pos, out_cap, base_host);
    const bool default_port = (base_https && base_port == 443) || (!base_https && base_port == 80);
    if (!default_port)
    {
        Append(out_url, &pos, out_cap, ":");
        AppendU32(out_url, &pos, out_cap, base_port);
    }

    if (location[0] == '/')
    {
        // Absolute path.
        Append(out_url, &pos, out_cap, location);
    }
    else
    {
        // Relative path: replace the last segment of base_path.
        char dir[kMaxPathLen];
        CopyStr(dir, sizeof(dir), base_path != nullptr ? base_path : "/");
        u32 cut = 0;
        for (u32 i = 0; dir[i] != '\0'; ++i)
        {
            if (dir[i] == '/')
            {
                cut = i + 1;
            }
        }
        dir[cut] = '\0';
        if (dir[0] != '/')
        {
            Append(out_url, &pos, out_cap, "/");
        }
        Append(out_url, &pos, out_cap, dir);
        Append(out_url, &pos, out_cap, location);
    }
    if (pos + 1 > out_cap)
    {
        return false;
    }
    out_url[pos] = '\0';
    return true;
}

namespace
{

// -----------------------------------------------------------------
// Build the request bytes into buf[cap]. Returns the byte count, or
// 0 on overflow.
// -----------------------------------------------------------------
u32 BuildRequest(const HttpRequestSpec& spec, const char* host, const char* path, char* buf, u32 cap)
{
    u32 pos = 0;
    Append(buf, &pos, cap, spec.method == HttpMethod::Post ? "POST " : "GET ");
    Append(buf, &pos, cap, path);
    Append(buf, &pos, cap, " HTTP/1.1\r\nHost: ");
    Append(buf, &pos, cap, host);
    Append(buf, &pos, cap, "\r\nUser-Agent: ");
    Append(buf, &pos, cap, spec.user_agent != nullptr ? spec.user_agent : "DuetOS/1.0");
    Append(buf, &pos, cap, "\r\nAccept: ");
    Append(buf, &pos, cap, spec.accept != nullptr ? spec.accept : "*/*");
    Append(buf, &pos, cap, "\r\nConnection: ");
    Append(buf, &pos, cap, spec.keep_alive ? "keep-alive" : "close");

    if (spec.cookie_header != nullptr && spec.cookie_header[0] != '\0')
    {
        Append(buf, &pos, cap, "\r\nCookie: ");
        Append(buf, &pos, cap, spec.cookie_header);
    }

    if (spec.method == HttpMethod::Post)
    {
        if (spec.content_type != nullptr)
        {
            Append(buf, &pos, cap, "\r\nContent-Type: ");
            Append(buf, &pos, cap, spec.content_type);
        }
        Append(buf, &pos, cap, "\r\nContent-Length: ");
        AppendU32(buf, &pos, cap, spec.body_len);
    }

    Append(buf, &pos, cap, "\r\n\r\n");

    // Detect overflow: AppendStr stops one short of cap; if we hit
    // that ceiling we can't trust the request was complete.
    if (pos + 1 >= cap)
    {
        return 0;
    }
    return pos;
}

bool WriteAll(HttpTransport* t, const u8* data, u32 len)
{
    u32 off = 0;
    while (off < len)
    {
        const i64 n = t->write(t->ctx, data + off, len - off);
        if (n <= 0)
        {
            return false;
        }
        off += static_cast<u32>(n);
    }
    return true;
}

// -----------------------------------------------------------------
// Buffered byte reader over a transport. The header block is read
// into a fixed in-buffer; body bytes are pulled on demand. `eof` is
// set once read() returns 0/negative with the buffer drained.
// -----------------------------------------------------------------
inline constexpr u32 kRecvCap = 8192;

struct Reader
{
    HttpTransport* t = nullptr;
    u8 buf[kRecvCap];
    u32 head = 0; // next unread byte
    u32 tail = 0; // one past last valid byte
    bool eof = false;
    bool err = false;

    void Fill()
    {
        if (head < tail || eof || err)
        {
            return;
        }
        head = 0;
        tail = 0;
        const i64 n = t->read(t->ctx, buf, kRecvCap);
        if (n < 0)
        {
            err = true;
            return;
        }
        if (n == 0)
        {
            eof = true;
            return;
        }
        tail = static_cast<u32>(n);
    }

    // -1 on EOF/error, else the next byte (0..255).
    int GetByte()
    {
        if (head >= tail)
        {
            Fill();
            if (head >= tail)
            {
                return -1;
            }
        }
        return static_cast<int>(buf[head++]);
    }

    // Read up to len bytes into dst; returns count (0 at EOF).
    u32 GetBytes(u8* dst, u32 len)
    {
        u32 got = 0;
        while (got < len)
        {
            if (head >= tail)
            {
                Fill();
                if (head >= tail)
                {
                    break;
                }
            }
            u32 avail = tail - head;
            u32 take = (len - got < avail) ? (len - got) : avail;
            duetos::core::MemcpyChecked(dst + got, buf + head, take);
            head += take;
            got += take;
        }
        return got;
    }
};

// Read one CRLF-terminated line into line[cap] (NUL-terminated, CRLF
// stripped). Returns the length, or -1 on EOF/error/overflow.
int ReadLine(Reader& r, char* line, u32 cap)
{
    u32 n = 0;
    bool saw_cr = false;
    for (;;)
    {
        const int c = r.GetByte();
        if (c < 0)
        {
            return -1;
        }
        if (c == '\n')
        {
            // Strip a trailing CR if present.
            if (n > 0 && line[n - 1] == '\r')
            {
                --n;
            }
            line[n] = '\0';
            (void)saw_cr;
            return static_cast<int>(n);
        }
        if (c == '\r')
        {
            saw_cr = true;
        }
        if (n + 1 >= cap)
        {
            return -1; // line overflow
        }
        line[n++] = static_cast<char>(c);
    }
}

// Trim leading spaces/tabs in-place by advancing the pointer.
const char* SkipWs(const char* s)
{
    while (*s == ' ' || *s == '\t')
    {
        ++s;
    }
    return s;
}

// Parse "HTTP/1.x SSS Reason". Returns false on malformed input.
bool ParseStatusLine(const char* line, u32* code, char* reason, u32 reason_cap)
{
    // Must start with "HTTP/".
    if (!(line[0] == 'H' && line[1] == 'T' && line[2] == 'T' && line[3] == 'P' && line[4] == '/'))
    {
        return false;
    }
    // Skip to first space.
    const char* p = line + 5;
    while (*p != '\0' && *p != ' ')
    {
        ++p;
    }
    if (*p != ' ')
    {
        return false;
    }
    p = SkipWs(p);
    if (!IsDigit(p[0]) || !IsDigit(p[1]) || !IsDigit(p[2]))
    {
        return false;
    }
    *code = static_cast<u32>((p[0] - '0') * 100 + (p[1] - '0') * 10 + (p[2] - '0'));
    p += 3;
    p = SkipWs(p);
    CopyStr(reason, reason_cap, p);
    return true;
}

// Split "Name: value" into out. Fires the Set-Cookie hook here so we
// don't have to retain duplicate headers. Returns false on malformed.
bool ParseHeaderLine(const char* line, const HttpRequestSpec& spec, HttpResult* out)
{
    // Find the colon.
    u32 ci = 0;
    while (line[ci] != '\0' && line[ci] != ':')
    {
        ++ci;
    }
    if (line[ci] != ':' || ci == 0 || ci >= kMaxHeaderNameLen)
    {
        return false;
    }

    char name[kMaxHeaderNameLen];
    duetos::core::MemcpyChecked(name, line, ci);
    name[ci] = '\0';

    const char* value = SkipWs(line + ci + 1);

    // Set-Cookie: fire the hook (once per header) and don't bother
    // storing it in the bounded map — callers consume via the hook.
    if (StrEqualCaseInsensitive(name, "Set-Cookie"))
    {
        if (spec.on_set_cookie != nullptr)
        {
            spec.on_set_cookie(value, spec.cookie_ctx);
        }
        return true;
    }

    if (out->header_count < kMaxHeaders)
    {
        HttpHeader& h = out->headers[out->header_count++];
        CopyStr(h.name, sizeof(h.name), name);
        CopyStr(h.value, sizeof(h.value), value);
    }
    // Over the cap we silently drop extra headers — bounded, not an
    // error (a hostile server can't force unbounded storage).
    return true;
}

// Append body bytes either into the bounded buffer or, once the cap
// is exceeded, to the sink. Returns false if neither path can take
// the bytes (overflow with no sink, or sink aborted).
bool SinkBody(const HttpRequestSpec& spec, HttpResult* out, const u8* data, u32 len)
{
    if (len == 0)
    {
        return true;
    }
    // Fill the buffer first.
    if (!out->body_truncated && spec.body_buf != nullptr && out->body_len < spec.body_cap)
    {
        u32 room = spec.body_cap - out->body_len;
        u32 take = (len < room) ? len : room;
        duetos::core::MemcpyChecked(spec.body_buf + out->body_len, data, take);
        out->body_len += take;
        data += take;
        len -= take;
        if (len == 0)
        {
            return true;
        }
    }
    // Overflow.
    out->body_truncated = true;
    if (spec.body_sink != nullptr)
    {
        return spec.body_sink(data, len, spec.sink_ctx);
    }
    return false; // BodyOverflow
}

// Read a Content-Length (or unknown-length, read-to-EOF) body.
HttpError ReadFixedBody(Reader& r, const HttpRequestSpec& spec, HttpResult* out, bool have_len, u32 content_len)
{
    u8 chunk[1024];
    u32 remaining = content_len;
    for (;;)
    {
        if (have_len && remaining == 0)
        {
            return HttpError::None;
        }
        u32 want = sizeof(chunk);
        if (have_len && remaining < want)
        {
            want = remaining;
        }
        u32 got = r.GetBytes(chunk, want);
        if (got == 0)
        {
            if (r.err)
            {
                return HttpError::TransportRead;
            }
            return HttpError::None; // EOF
        }
        if (!SinkBody(spec, out, chunk, got))
        {
            return HttpError::BodyOverflow;
        }
        if (have_len)
        {
            remaining -= got;
        }
    }
}

// Read a Transfer-Encoding: chunked body. Hostile-length-safe: chunk
// sizes are hex-parsed with an overflow guard and a sane upper bound.
inline constexpr u32 kMaxChunkSize = 16u * 1024u * 1024u; // 16 MiB/chunk ceiling

HttpError ReadChunkedBody(Reader& r, const HttpRequestSpec& spec, HttpResult* out)
{
    for (;;)
    {
        // Chunk-size line: hex digits, optional ";ext", CRLF.
        char line[128];
        const int ll = ReadLine(r, line, sizeof(line));
        if (ll < 0)
        {
            return HttpError::BadChunk;
        }
        // Parse hex up to ';' or end.
        u64 size = 0;
        u32 i = 0;
        if (!IsHexDigit(line[0]))
        {
            return HttpError::BadChunk;
        }
        for (; line[i] != '\0' && line[i] != ';'; ++i)
        {
            if (!IsHexDigit(line[i]))
            {
                return HttpError::BadChunk;
            }
            size = (size << 4) | HexVal(line[i]);
            if (size > kMaxChunkSize)
            {
                return HttpError::BadChunk; // hostile / absurd chunk
            }
        }

        if (size == 0)
        {
            // Last chunk. Consume the trailing header block (we GAP
            // trailers — just drain CRLF-terminated lines until empty).
            for (;;)
            {
                char trailer[256];
                const int tl = ReadLine(r, trailer, sizeof(trailer));
                if (tl < 0)
                {
                    return HttpError::None; // EOF after last chunk: tolerate
                }
                if (tl == 0)
                {
                    return HttpError::None; // blank line terminates
                }
                // GAP: trailers — drained, not surfaced.
            }
        }

        // Read exactly `size` body bytes, then the trailing CRLF.
        u32 remaining = static_cast<u32>(size);
        u8 buf[1024];
        while (remaining > 0)
        {
            u32 want = (remaining < sizeof(buf)) ? remaining : sizeof(buf);
            u32 got = r.GetBytes(buf, want);
            if (got == 0)
            {
                return HttpError::BadChunk; // truncated chunk
            }
            if (!SinkBody(spec, out, buf, got))
            {
                return HttpError::BodyOverflow;
            }
            remaining -= got;
        }
        // Trailing CRLF after the chunk data.
        char crlf[4];
        const int cl = ReadLine(r, crlf, sizeof(crlf));
        if (cl != 0)
        {
            return HttpError::BadChunk; // expected bare CRLF
        }
    }
}

// Drive ONE request/response over `transport`. Fills *out. Returns
// the parsed error (None on success). Redirect handling lives in the
// caller (HttpRequest).
HttpError DoOne(const HttpRequestSpec& spec, const char* host, const char* path, HttpTransport* transport,
                HttpResult* out)
{
    char req[kRequestBufCap];
    const u32 req_len = BuildRequest(spec, host, path, req, sizeof(req));
    if (req_len == 0)
    {
        return HttpError::BadUrl; // request didn't fit
    }
    if (!WriteAll(transport, reinterpret_cast<const u8*>(req), req_len))
    {
        return HttpError::TransportWrite;
    }
    if (spec.method == HttpMethod::Post && spec.body != nullptr && spec.body_len > 0)
    {
        if (!WriteAll(transport, spec.body, spec.body_len))
        {
            return HttpError::TransportWrite;
        }
    }

    Reader r;
    r.t = transport;

    // Status line.
    char line[kMaxHeaderValueLen];
    if (ReadLine(r, line, sizeof(line)) < 0)
    {
        return r.err ? HttpError::TransportRead : HttpError::MalformedStatus;
    }
    if (!ParseStatusLine(line, &out->status_code, out->reason, sizeof(out->reason)))
    {
        return HttpError::MalformedStatus;
    }

    // Header block until a blank line.
    out->header_count = 0;
    u32 header_lines = 0;
    for (;;)
    {
        const int n = ReadLine(r, line, sizeof(line));
        if (n < 0)
        {
            return HttpError::HeadersTooLarge; // EOF/overflow mid-headers
        }
        if (n == 0)
        {
            break; // end of header block
        }
        if (++header_lines > kMaxHeaders * 4)
        {
            return HttpError::HeadersTooLarge; // hostile flood
        }
        if (!ParseHeaderLine(line, spec, out))
        {
            return HttpError::HeadersTooLarge; // malformed header
        }
    }

    // Determine body framing.
    const char* te = out->FindHeader("Transfer-Encoding");
    if (te != nullptr && StrEqualCaseInsensitive(te, "chunked"))
    {
        return ReadChunkedBody(r, spec, out);
    }

    const char* cl = out->FindHeader("Content-Length");
    if (cl != nullptr)
    {
        const u32 len = ParseU32(cl, StrLen(cl));
        return ReadFixedBody(r, spec, out, /*have_len=*/true, len);
    }

    // No framing header. For a body-bearing status, read to EOF
    // (Connection: close semantics). 1xx/204/304 carry no body.
    if (out->status_code == 204 || out->status_code == 304 || (out->status_code >= 100 && out->status_code < 200))
    {
        return HttpError::None;
    }
    return ReadFixedBody(r, spec, out, /*have_len=*/false, 0);
}

bool IsRedirect(u32 code)
{
    return code == 301 || code == 302 || code == 303 || code == 307 || code == 308;
}

} // namespace

// -----------------------------------------------------------------
// HttpRequest — drive the first request on `transport`, then follow
// 3xx redirects (up to spec.max_redirects) on transports obtained
// from spec.on_connect.
// -----------------------------------------------------------------
bool HttpRequest(const HttpRequestSpec& spec, HttpTransport* transport, HttpResult* out)
{
    if (transport == nullptr || out == nullptr || transport->read == nullptr || transport->write == nullptr)
    {
        if (out != nullptr)
        {
            out->error = HttpError::BadUrl;
        }
        return false;
    }

    *out = HttpResult{};

    // Resolve the initial target. url[] (if set) overrides the split
    // fields.
    bool https = spec.scheme_https;
    char host[kMaxHostLen];
    char path[kMaxPathLen];
    u16 port = spec.port;
    if (spec.url[0] != '\0')
    {
        if (!ParseUrl(spec.url, &https, host, sizeof(host), &port, path, sizeof(path)))
        {
            out->error = HttpError::BadUrl;
            return false;
        }
    }
    else
    {
        CopyStr(host, sizeof(host), spec.host);
        CopyStr(path, sizeof(path), spec.path[0] != '\0' ? spec.path : "/");
        if (host[0] == '\0')
        {
            out->error = HttpError::BadUrl;
            return false;
        }
    }

    const u32 max_redirects = spec.max_redirects;
    HttpTransport* cur = transport;
    HttpTransport owned{}; // transport opened by on_connect for a redirect

    for (u32 hop = 0;; ++hop)
    {
        // Reset per-response fields (keep redirect_count).
        out->status_code = 0;
        out->reason[0] = '\0';
        out->header_count = 0;
        out->body_len = 0;
        out->body_truncated = false;

        // Record the URL this response corresponds to.
        out->final_url[0] = '\0';
        u32 fp = 0;
        Append(out->final_url, &fp, sizeof(out->final_url), https ? "https://" : "http://");
        Append(out->final_url, &fp, sizeof(out->final_url), host);
        const bool default_port = (https && port == 443) || (!https && port == 80);
        if (!default_port)
        {
            Append(out->final_url, &fp, sizeof(out->final_url), ":");
            AppendU32(out->final_url, &fp, sizeof(out->final_url), port);
        }
        Append(out->final_url, &fp, sizeof(out->final_url), path);

        const HttpError e = DoOne(spec, host, path, cur, out);
        if (e != HttpError::None)
        {
            out->error = e;
            return false;
        }

        if (!IsRedirect(out->status_code))
        {
            out->error = HttpError::None;
            return true;
        }

        // Redirect.
        if (hop >= max_redirects)
        {
            out->error = HttpError::TooManyRedirects;
            return false;
        }
        const char* loc = out->FindHeader("Location");
        if (loc == nullptr || loc[0] == '\0')
        {
            out->error = HttpError::BadRedirect;
            return false;
        }

        char next_url[kMaxUrlLen];
        if (!ResolveLocation(https, host, port, path, loc, next_url, sizeof(next_url)))
        {
            out->error = HttpError::BadRedirect;
            return false;
        }
        if (!ParseUrl(next_url, &https, host, sizeof(host), &port, path, sizeof(path)))
        {
            out->error = HttpError::BadRedirect;
            return false;
        }

        // Open a fresh transport for the next hop. (v0 always opens
        // fresh — no connection reuse; see GAP in http.h.)
        if (spec.on_connect == nullptr)
        {
            out->error = HttpError::TransportConnect;
            return false;
        }
        owned = HttpTransport{};
        if (!spec.on_connect(https, host, port, &owned, spec.connect_ctx))
        {
            out->error = HttpError::TransportConnect;
            return false;
        }
        cur = &owned;
        out->redirect_count = hop + 1;
    }
}

// =================================================================
// Boot-time self-test.
// =================================================================
namespace
{

void EmitPass(const char* label)
{
    arch::SerialWrite("[net/http-selftest] PASS (");
    arch::SerialWrite(label);
    arch::SerialWrite(")\n");
}

void EmitFail(const char* label)
{
    arch::SerialWrite("[net/http-selftest] FAIL (");
    arch::SerialWrite(label);
    arch::SerialWrite(")\n");
    KBP_PROBE_V(duetos::debug::ProbeId::kBootSelftestFail, 0xF09Au);
}

// In-memory transport: hands out a canned response, discards the
// request. Multiple responses can be queued so a redirect chain can
// be driven without a real socket. `responses[idx]` is the body for
// hop `idx`; on_connect advances `idx`.
struct CannedTransport
{
    const char* data;
    u32 len;
    u32 pos;
};

i64 CannedRead(void* ctx, u8* buf, u32 len)
{
    auto* c = static_cast<CannedTransport*>(ctx);
    if (c->pos >= c->len)
    {
        return 0; // EOF
    }
    u32 avail = c->len - c->pos;
    u32 take = (len < avail) ? len : avail;
    duetos::core::MemcpyChecked(buf, c->data + c->pos, take);
    c->pos += take;
    return static_cast<i64>(take);
}

i64 CannedWrite(void* ctx, const u8* buf, u32 len)
{
    (void)ctx;
    (void)buf;
    return static_cast<i64>(len); // swallow the request
}

// Redirect harness: a queue of canned responses; each on_connect
// hands out the next one.
struct RedirectHarness
{
    const char* responses[4];
    CannedTransport canned[4];
    u32 next;
};

bool RedirectConnect(bool /*https*/, const char* /*host*/, u16 /*port*/, HttpTransport* out, void* ctx)
{
    auto* h = static_cast<RedirectHarness*>(ctx);
    if (h->next >= 4 || h->responses[h->next] == nullptr)
    {
        return false;
    }
    u32 i = h->next++;
    h->canned[i].data = h->responses[i];
    h->canned[i].len = static_cast<u32>(StrLen(h->responses[i]));
    h->canned[i].pos = 0;
    out->read = CannedRead;
    out->write = CannedWrite;
    out->ctx = &h->canned[i];
    return true;
}

// Cookie counter for the Set-Cookie hook assertions.
struct CookieCounter
{
    u32 count;
    char first[128];
    char second[128];
};

void CookieHook(const char* value, void* ctx)
{
    auto* cc = static_cast<CookieCounter*>(ctx);
    if (cc->count == 0)
    {
        CopyStr(cc->first, sizeof(cc->first), value);
    }
    else if (cc->count == 1)
    {
        CopyStr(cc->second, sizeof(cc->second), value);
    }
    ++cc->count;
}

} // namespace

void HttpSelfTest()
{
    u8 body_buf[512];

    // --- Test 1: 200 + Content-Length body, exact. ---
    {
        const char* resp = "HTTP/1.1 200 OK\r\n"
                           "Content-Type: text/plain\r\n"
                           "Content-Length: 13\r\n"
                           "\r\n"
                           "Hello, world!";
        CannedTransport ct{resp, static_cast<u32>(StrLen(resp)), 0};
        HttpTransport t{CannedRead, CannedWrite, &ct};

        HttpRequestSpec spec;
        CopyStr(spec.host, sizeof(spec.host), "example.com");
        spec.body_buf = body_buf;
        spec.body_cap = sizeof(body_buf);

        HttpResult res;
        if (!HttpRequest(spec, &t, &res) || res.status_code != 200 || res.body_len != 13 ||
            MemCmp(body_buf, "Hello, world!", 13) != 0 || res.FindHeader("content-type") == nullptr)
        {
            EmitFail("content-length");
            return;
        }
        EmitPass("content-length");
    }

    // --- Test 2: 200 + chunked, multi-chunk, exact decode. ---
    {
        // "Wikipedia in\r\n\r\nchunks." style — 3 chunks.
        const char* resp = "HTTP/1.1 200 OK\r\n"
                           "Transfer-Encoding: chunked\r\n"
                           "\r\n"
                           "5\r\nHello\r\n"
                           "1\r\n \r\n"
                           "6\r\nworld!\r\n"
                           "0\r\n\r\n";
        CannedTransport ct{resp, static_cast<u32>(StrLen(resp)), 0};
        HttpTransport t{CannedRead, CannedWrite, &ct};

        HttpRequestSpec spec;
        CopyStr(spec.host, sizeof(spec.host), "example.com");
        spec.body_buf = body_buf;
        spec.body_cap = sizeof(body_buf);

        HttpResult res;
        if (!HttpRequest(spec, &t, &res) || res.status_code != 200 || res.body_len != 12 ||
            MemCmp(body_buf, "Hello world!", 12) != 0)
        {
            EmitFail("chunked");
            return;
        }
        EmitPass("chunked");
    }

    // --- Test 3: 301 -> 200 redirect; final body returned. ---
    {
        const char* first = "HTTP/1.1 301 Moved Permanently\r\n"
                            "Location: http://example.com/final\r\n"
                            "Content-Length: 0\r\n"
                            "\r\n";
        const char* final_resp = "HTTP/1.1 200 OK\r\n"
                                 "Content-Length: 5\r\n"
                                 "\r\n"
                                 "Final";
        CannedTransport ct{first, static_cast<u32>(StrLen(first)), 0};
        HttpTransport t{CannedRead, CannedWrite, &ct};

        RedirectHarness harness{};
        harness.responses[0] = final_resp;
        harness.next = 0;

        HttpRequestSpec spec;
        CopyStr(spec.host, sizeof(spec.host), "example.com");
        spec.path[0] = '/';
        spec.path[1] = '\0';
        spec.body_buf = body_buf;
        spec.body_cap = sizeof(body_buf);
        spec.on_connect = RedirectConnect;
        spec.connect_ctx = &harness;

        HttpResult res;
        if (!HttpRequest(spec, &t, &res) || res.status_code != 200 || res.redirect_count != 1 || res.body_len != 5 ||
            MemCmp(body_buf, "Final", 5) != 0 || !StrEqualCaseInsensitive(res.final_url, "http://example.com/final"))
        {
            EmitFail("redirect");
            return;
        }
        EmitPass("redirect");
    }

    // --- Test 4: two Set-Cookie headers fire the hook twice. ---
    {
        const char* resp = "HTTP/1.1 200 OK\r\n"
                           "Set-Cookie: session=abc; Path=/\r\n"
                           "Set-Cookie: pref=dark; Max-Age=3600\r\n"
                           "Content-Length: 2\r\n"
                           "\r\n"
                           "OK";
        CannedTransport ct{resp, static_cast<u32>(StrLen(resp)), 0};
        HttpTransport t{CannedRead, CannedWrite, &ct};

        CookieCounter cc{};
        HttpRequestSpec spec;
        CopyStr(spec.host, sizeof(spec.host), "example.com");
        spec.body_buf = body_buf;
        spec.body_cap = sizeof(body_buf);
        spec.on_set_cookie = CookieHook;
        spec.cookie_ctx = &cc;

        HttpResult res;
        if (!HttpRequest(spec, &t, &res) || res.status_code != 200 || cc.count != 2 ||
            !StrEqualCaseInsensitive(cc.first, "session=abc; Path=/") ||
            !StrEqualCaseInsensitive(cc.second, "pref=dark; Max-Age=3600"))
        {
            EmitFail("set-cookie");
            return;
        }
        EmitPass("set-cookie");
    }

    // --- Test 5: malformed status line rejected, no overrun. ---
    {
        const char* resp = "NOTHTTP garbage\r\n\r\n";
        CannedTransport ct{resp, static_cast<u32>(StrLen(resp)), 0};
        HttpTransport t{CannedRead, CannedWrite, &ct};

        HttpRequestSpec spec;
        CopyStr(spec.host, sizeof(spec.host), "example.com");
        spec.body_buf = body_buf;
        spec.body_cap = sizeof(body_buf);

        HttpResult res;
        if (HttpRequest(spec, &t, &res) || res.error != HttpError::MalformedStatus)
        {
            EmitFail("malformed-status");
            return;
        }
        EmitPass("malformed-status");
    }

    // --- Test 6: hostile/oversize chunk size rejected. ---
    {
        const char* resp = "HTTP/1.1 200 OK\r\n"
                           "Transfer-Encoding: chunked\r\n"
                           "\r\n"
                           "FFFFFFFF\r\n"; // 4 GiB chunk claim
        CannedTransport ct{resp, static_cast<u32>(StrLen(resp)), 0};
        HttpTransport t{CannedRead, CannedWrite, &ct};

        HttpRequestSpec spec;
        CopyStr(spec.host, sizeof(spec.host), "example.com");
        spec.body_buf = body_buf;
        spec.body_cap = sizeof(body_buf);

        HttpResult res;
        if (HttpRequest(spec, &t, &res) || res.error != HttpError::BadChunk)
        {
            EmitFail("oversize-chunk");
            return;
        }
        EmitPass("oversize-chunk");
    }

    // --- Test 7: oversize body with no sink -> BodyOverflow. ---
    {
        u8 tiny[4];
        const char* resp = "HTTP/1.1 200 OK\r\n"
                           "Content-Length: 100\r\n"
                           "\r\n"
                           "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                           "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        CannedTransport ct{resp, static_cast<u32>(StrLen(resp)), 0};
        HttpTransport t{CannedRead, CannedWrite, &ct};

        HttpRequestSpec spec;
        CopyStr(spec.host, sizeof(spec.host), "example.com");
        spec.body_buf = tiny;
        spec.body_cap = sizeof(tiny);
        spec.body_sink = nullptr; // no sink: overflow must be reported

        HttpResult res;
        if (HttpRequest(spec, &t, &res) || res.error != HttpError::BodyOverflow)
        {
            EmitFail("body-overflow");
            return;
        }
        EmitPass("body-overflow");
    }

    EmitPass("all");
}

} // namespace duetos::net::http
