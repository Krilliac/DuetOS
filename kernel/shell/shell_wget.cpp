/*
 * DuetOS — shell `wget` / `curl` commands.
 *
 * Unix-style file downloader for the kernel shell. v0 speaks
 * plain HTTP/1.1 over the kernel net stack (TCP + DNS already
 * working — see `wiki/networking/Live-Internet.md` for the
 * proof-of-concept that reaches www.google.com over QEMU SLIRP).
 *
 * HTTPS is gated on the TLS 1.2 Connection state machine; every
 * primitive it needs is already in `kernel/net/tls.h` (see
 * `wiki/networking/TLS-Roadmap.md`). When that wiring lands,
 * this same command parses the `https://` scheme, hands the
 * socket to TlsClient*, and the rest of the body-read loop is
 * unchanged.
 *
 * Syntax:
 *
 *   wget <url>              Print response body to console.
 *   wget <url> <dest_path>  Save response body to /unzip/-style
 *                           FAT32 path. Volume 0 is assumed; the
 *                           file is created with Fat32CreateAtPath
 *                           (auto-mkdirs intermediate components).
 *   wget -O <dest> <url>    Same as above, GNU-wget compat form.
 *
 * Limits:
 *   - HTTP only (HTTPS pending TLS state machine).
 *   - Body capped at 256 KiB to keep the heap allocation
 *     bounded — typical for an installer / config file fetch.
 *   - No redirects (3xx). Reports the Location header and
 *     exits 1 so the user can re-run with the new URL.
 *   - No conditional requests (If-Modified-Since etc.).
 *   - No HTTP/2.
 *
 * `curl` is registered as an alias with identical semantics so
 * users coming from the Unix world don't have to think about
 * which one to type.
 */

#include "shell/shell_internal.h"

#include "drivers/video/console.h"
#include "drivers/video/notify.h"
#include "fs/fat32.h"
#include "mm/kheap.h"
#include "net/socket.h"
#include "net/stack.h"
#include "sched/sched.h"

namespace duetos::core::shell::internal
{

namespace
{

using duetos::drivers::video::ConsoleWrite;
using duetos::drivers::video::ConsoleWriteChar;
using duetos::drivers::video::ConsoleWriteln;

constexpr u32 kBodyCapBytes = 256 * 1024;
constexpr u16 kDefaultHttpPort = 80;
constexpr u16 kDefaultHttpsPort = 443;
constexpr u32 kSchemeHttp = 1;
constexpr u32 kSchemeHttps = 2;

struct ParsedUrl
{
    u32 scheme; // kSchemeHttp / kSchemeHttps
    char host[128];
    u16 port;
    char path[256];
};

bool StrCaseEqN(const char* a, const char* b, u32 n)
{
    for (u32 i = 0; i < n; ++i)
    {
        char ca = a[i];
        char cb = b[i];
        if (ca >= 'A' && ca <= 'Z')
            ca = static_cast<char>(ca + 32);
        if (cb >= 'A' && cb <= 'Z')
            cb = static_cast<char>(cb + 32);
        if (ca != cb)
            return false;
    }
    return true;
}

// Tiny URL parser. Accepts:
//   http://host/path
//   http://host:port/path
//   https://host/path  (passed through; HTTPS execution rejects)
// Path defaults to "/". Port defaults to 80 (http) / 443 (https).
bool ParseUrl(const char* url, ParsedUrl* out)
{
    *out = ParsedUrl{};
    if (url == nullptr)
        return false;
    u32 cur = 0;
    if (StrCaseEqN(url, "http://", 7))
    {
        out->scheme = kSchemeHttp;
        out->port = kDefaultHttpPort;
        cur = 7;
    }
    else if (StrCaseEqN(url, "https://", 8))
    {
        out->scheme = kSchemeHttps;
        out->port = kDefaultHttpsPort;
        cur = 8;
    }
    else
    {
        return false;
    }
    // Host: read until ':' or '/' or end.
    u32 host_len = 0;
    while (url[cur] != '\0' && url[cur] != ':' && url[cur] != '/')
    {
        if (host_len + 1 >= sizeof(out->host))
            return false;
        out->host[host_len++] = url[cur++];
    }
    out->host[host_len] = '\0';
    if (host_len == 0)
        return false;
    // Optional port
    if (url[cur] == ':')
    {
        ++cur;
        u32 port = 0;
        while (url[cur] >= '0' && url[cur] <= '9')
        {
            port = port * 10 + u32(url[cur++] - '0');
            if (port > 65535)
                return false;
        }
        if (port == 0)
            return false;
        out->port = static_cast<u16>(port);
    }
    // Path
    if (url[cur] == '\0')
    {
        out->path[0] = '/';
        out->path[1] = '\0';
        return true;
    }
    if (url[cur] != '/')
        return false;
    u32 path_len = 0;
    while (url[cur] != '\0')
    {
        if (path_len + 1 >= sizeof(out->path))
            return false;
        out->path[path_len++] = url[cur++];
    }
    out->path[path_len] = '\0';
    return true;
}

// Resolve `host` via the kernel DNS path. Times out after 2s.
bool ResolveHost(const char* host, duetos::net::Ipv4Address* out_ip)
{
    // QEMU SLIRP default resolver — matches what `nslookup`
    // uses with no second argument.
    duetos::net::Ipv4Address resolver{{10, 0, 2, 3}};
    if (!duetos::net::NetDnsQueryA(/*iface_index=*/0, resolver, host))
        return false;
    for (u32 i = 0; i < 200; ++i)
    {
        duetos::sched::SchedSleepTicks(1);
        const auto r = duetos::net::NetDnsResultRead();
        if (r.resolved)
        {
            *out_ip = r.ip;
            return true;
        }
    }
    return false;
}

void AppendString(char* buf, u32 cap, u32* off, const char* s)
{
    while (*s != '\0' && *off + 1 < cap)
        buf[(*off)++] = *s++;
}

void AppendU16(char* buf, u32 cap, u32* off, u16 v)
{
    char tmp[6];
    u32 t = 0;
    if (v == 0)
        tmp[t++] = '0';
    else
    {
        while (v > 0 && t < sizeof(tmp))
        {
            tmp[t++] = static_cast<char>('0' + (v % 10));
            v /= 10;
        }
    }
    while (t > 0 && *off + 1 < cap)
        buf[(*off)++] = tmp[--t];
}

// Build the HTTP request bytes. Returns the request length.
u32 BuildHttpRequest(const ParsedUrl& url, char* buf, u32 cap)
{
    u32 off = 0;
    AppendString(buf, cap, &off, "GET ");
    AppendString(buf, cap, &off, url.path);
    AppendString(buf, cap, &off, " HTTP/1.1\r\nHost: ");
    AppendString(buf, cap, &off, url.host);
    if ((url.scheme == kSchemeHttp && url.port != kDefaultHttpPort) ||
        (url.scheme == kSchemeHttps && url.port != kDefaultHttpsPort))
    {
        AppendString(buf, cap, &off, ":");
        AppendU16(buf, cap, &off, url.port);
    }
    AppendString(buf, cap, &off,
                 "\r\nUser-Agent: DuetOS-wget/0.1\r\nAccept: */*\r\n"
                 "Connection: close\r\n\r\n");
    return off;
}

// Look for the end-of-headers sequence "\r\n\r\n" in `buf[0..len)`.
// Returns the offset of the FIRST body byte (just past the
// 4-byte separator), or `len` if not found.
u32 FindBodyStart(const u8* buf, u32 len)
{
    if (len < 4)
        return len;
    for (u32 i = 0; i + 3 < len; ++i)
    {
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n')
            return i + 4;
    }
    return len;
}

// Parse the "HTTP/1.x XXX ..." status line; returns the 3-digit
// status code or 0 on parse failure.
u32 ParseStatusCode(const u8* buf, u32 len)
{
    if (len < 12)
        return 0;
    if (buf[0] != 'H' || buf[1] != 'T' || buf[2] != 'T' || buf[3] != 'P' || buf[4] != '/')
        return 0;
    // Skip "HTTP/x.y SP".
    u32 i = 5;
    while (i < len && buf[i] != ' ')
        ++i;
    while (i < len && buf[i] == ' ')
        ++i;
    u32 code = 0;
    for (u32 d = 0; d < 3 && i < len && buf[i] >= '0' && buf[i] <= '9'; ++d, ++i)
        code = code * 10 + u32(buf[i] - '0');
    return code;
}

// Mkdir each intermediate directory of `path` on FAT32 vol 0.
// Mirrors the same loop used by `unzip` so /foo/bar/baz.dat
// works even if /foo and /foo/bar don't exist yet.
void MkdirParents(const duetos::fs::fat32::Volume* vol, const char* path)
{
    char tmp[256];
    u32 i = 0;
    while (path[i] != '\0' && i + 1 < sizeof(tmp))
    {
        tmp[i] = path[i];
        ++i;
    }
    tmp[i] = '\0';
    for (u32 j = 1; j < i; ++j)
    {
        if (tmp[j] == '/')
        {
            tmp[j] = '\0';
            (void)duetos::fs::fat32::Fat32MkdirAtPath(vol, tmp);
            tmp[j] = '/';
        }
    }
}

} // namespace

void CmdWget(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("WGET: usage: wget [-O <dest>] <url>");
        ConsoleWriteln("       wget <url>                 print body to console");
        ConsoleWriteln("       wget <url> <dest>          save body to FAT32 path");
        ConsoleWriteln("       wget -O <dest> <url>       same as above (GNU-wget)");
        ConsoleWriteln("       HTTPS pending TLS state machine — see");
        ConsoleWriteln("       wiki/networking/TLS-Roadmap.md");
        return;
    }

    // Argv variants:
    //   wget URL
    //   wget URL DEST
    //   wget -O DEST URL
    const char* url_str = nullptr;
    const char* dest = nullptr;
    if (argc == 2)
    {
        url_str = argv[1];
    }
    else if (argc == 3)
    {
        url_str = argv[1];
        dest = argv[2];
    }
    else if (argc == 4 && argv[1][0] == '-' && argv[1][1] == 'O' && argv[1][2] == '\0')
    {
        dest = argv[2];
        url_str = argv[3];
    }
    else
    {
        ConsoleWriteln("WGET: too many args");
        return;
    }

    ParsedUrl url{};
    if (!ParseUrl(url_str, &url))
    {
        ConsoleWriteln("WGET: malformed URL (need http://host[:port]/path)");
        return;
    }
    if (url.scheme == kSchemeHttps)
    {
        ConsoleWriteln("WGET: https:// not yet supported — TLS state machine pending");
        ConsoleWriteln("      every TLS primitive is in tree (see [tls] PASS at boot)");
        ConsoleWriteln("      next slice glues them into a Connection state machine");
        return;
    }

    duetos::net::Ipv4Address ip{};
    ConsoleWrite("WGET: resolving ");
    ConsoleWrite(url.host);
    ConsoleWriteln(" ...");
    if (!ResolveHost(url.host, &ip))
    {
        ConsoleWriteln("WGET: DNS lookup failed (NXDOMAIN, no route, or resolver down)");
        return;
    }
    ConsoleWrite("WGET:   -> ");
    for (u32 j = 0; j < 4; ++j)
    {
        if (j != 0)
            ConsoleWriteChar('.');
        WriteU64Dec(ip.octets[j]);
    }
    ConsoleWrite(":");
    WriteU64Dec(url.port);
    ConsoleWriteln("");

    const i32 sock = duetos::net::SocketAlloc(duetos::net::kSocketDomainInet, duetos::net::kSocketTypeStream);
    if (sock < 0)
    {
        ConsoleWriteln("WGET: SocketAlloc failed (pool exhausted)");
        return;
    }
    if (!duetos::net::SocketConnect(static_cast<u32>(sock), ip, url.port))
    {
        duetos::net::SocketRelease(static_cast<u32>(sock));
        ConsoleWriteln("WGET: TCP connect failed (no route, firewall, server down)");
        return;
    }

    char req[768];
    const u32 req_len = BuildHttpRequest(url, req, sizeof(req));
    {
        u32 sent = 0;
        while (sent < req_len)
        {
            const i64 n = duetos::net::SocketSendStream(static_cast<u32>(sock), reinterpret_cast<const u8*>(req) + sent,
                                                        req_len - sent);
            if (n <= 0)
            {
                duetos::net::SocketRelease(static_cast<u32>(sock));
                ConsoleWriteln("WGET: send failed mid-request");
                return;
            }
            sent += static_cast<u32>(n);
        }
    }
    duetos::net::SocketShutdown(static_cast<u32>(sock), /*how=*/1);

    auto* buf = static_cast<u8*>(duetos::mm::KMalloc(kBodyCapBytes));
    if (buf == nullptr)
    {
        duetos::net::SocketRelease(static_cast<u32>(sock));
        ConsoleWriteln("WGET: OOM staging response buffer");
        return;
    }

    u32 got = 0;
    // Read until connection close, EOB cap, or 30s idle timeout
    // (300 ticks × 100 ms = ~30s).
    u32 idle_ticks = 0;
    while (got < kBodyCapBytes && idle_ticks < 300)
    {
        const i64 n = duetos::net::SocketRecvStream(static_cast<u32>(sock), buf + got, kBodyCapBytes - got);
        if (n > 0)
        {
            got += static_cast<u32>(n);
            idle_ticks = 0;
            continue;
        }
        if (n == 0)
            break; // peer closed
        // n < 0: no bytes ready right now. Sleep and retry.
        duetos::sched::SchedSleepTicks(1);
        ++idle_ticks;
    }
    duetos::net::SocketRelease(static_cast<u32>(sock));

    const u32 status = ParseStatusCode(buf, got);
    const u32 body_off = FindBodyStart(buf, got);
    const u32 body_len = got - body_off;

    ConsoleWrite("WGET: HTTP ");
    WriteU64Dec(status);
    ConsoleWrite("  ");
    WriteU64Dec(got);
    ConsoleWrite(" bytes total, ");
    WriteU64Dec(body_len);
    ConsoleWriteln(" body");

    if (status == 0)
    {
        ConsoleWriteln("WGET: malformed response (no HTTP status line)");
        duetos::mm::KFree(buf);
        return;
    }
    if (status >= 300 && status < 400)
    {
        // Surface the Location header so the user can redirect
        // manually. Not auto-following keeps the command
        // predictable and avoids amplification loops.
        ConsoleWriteln("WGET: redirect — Location header (re-run wget with this URL):");
        // Walk the headers looking for "Location:".
        u32 i = 0;
        while (i + 9 < body_off)
        {
            // Line start: i==0 or previous "\r\n".
            const bool at_line_start = (i == 0) || (buf[i - 1] == '\n');
            if (at_line_start && StrCaseEqN(reinterpret_cast<const char*>(buf + i), "Location:", 9))
            {
                u32 k = i + 9;
                while (k < body_off && (buf[k] == ' ' || buf[k] == '\t'))
                    ++k;
                ConsoleWrite("        ");
                while (k < body_off && buf[k] != '\r' && buf[k] != '\n')
                    ConsoleWriteChar(static_cast<char>(buf[k++]));
                ConsoleWriteln("");
                break;
            }
            ++i;
        }
        duetos::mm::KFree(buf);
        return;
    }

    if (dest == nullptr)
    {
        // Print body to console. Cap at 4 KiB to avoid blowing
        // out the framebuffer console buffer.
        constexpr u32 kPrintCap = 4096;
        const u32 print_len = body_len > kPrintCap ? kPrintCap : body_len;
        for (u32 i = 0; i < print_len; ++i)
            ConsoleWriteChar(static_cast<char>(buf[body_off + i]));
        if (body_len > kPrintCap)
        {
            ConsoleWrite("\n[... ");
            WriteU64Dec(body_len - kPrintCap);
            ConsoleWriteln(" more bytes elided; pass a dest path to save full body]");
        }
        else
        {
            ConsoleWriteln("");
        }
        duetos::mm::KFree(buf);
        return;
    }

    // Save to FAT32. Auto-mkdir intermediate directories.
    const auto* vol = duetos::fs::fat32::Fat32Volume(0);
    if (vol == nullptr)
    {
        ConsoleWriteln("WGET: NO FAT32 VOLUME MOUNTED");
        duetos::mm::KFree(buf);
        return;
    }
    MkdirParents(vol, dest);
    const auto written = duetos::fs::fat32::Fat32CreateAtPath(vol, dest, buf + body_off, body_len);
    if (written != static_cast<duetos::i64>(body_len))
    {
        ConsoleWrite("WGET: CREATE FAIL ");
        ConsoleWriteln(dest);
        duetos::mm::KFree(buf);
        return;
    }
    ConsoleWrite("WGET: saved ");
    WriteU64Dec(body_len);
    ConsoleWrite(" bytes to ");
    ConsoleWriteln(dest);
    duetos::mm::KFree(buf);
}

} // namespace duetos::core::shell::internal
