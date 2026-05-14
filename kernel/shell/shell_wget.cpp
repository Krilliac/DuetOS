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

#include "crypto/sha256.h"
#include "drivers/video/console.h"
#include "drivers/video/notify.h"
#include "fs/fat32.h"
#include "fs/ramfs.h"
#include "fs/tmpfs.h"
#include "mm/kheap.h"
#include "net/socket.h"
#include "net/stack.h"
#include "net/tls.h"
#include "sched/sched.h"
#include "util/crc32.h"
#include "util/random.h"

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

// Find a header line by name (case-insensitive) in `[buf..buf+header_len)`
// and copy its value (whitespace-trimmed) into `out[0..out_cap)`. Returns
// the number of bytes written (excluding NUL), or 0 if the header is
// absent / value too long for `out_cap`.
u32 FindHeader(const u8* buf, u32 header_len, const char* name, char* out, u32 out_cap)
{
    if (out_cap == 0)
        return 0;
    out[0] = '\0';
    const u32 name_len = [&]() -> u32
    {
        u32 n = 0;
        while (name[n] != '\0')
            ++n;
        return n;
    }();
    u32 i = 0;
    while (i + name_len + 1 < header_len)
    {
        const bool line_start = (i == 0) || (buf[i - 1] == '\n');
        if (line_start && StrCaseEqN(reinterpret_cast<const char*>(buf + i), name, name_len) &&
            buf[i + name_len] == ':')
        {
            u32 k = i + name_len + 1;
            while (k < header_len && (buf[k] == ' ' || buf[k] == '\t'))
                ++k;
            u32 w = 0;
            while (k < header_len && buf[k] != '\r' && buf[k] != '\n' && w + 1 < out_cap)
                out[w++] = static_cast<char>(buf[k++]);
            out[w] = '\0';
            return w;
        }
        ++i;
    }
    return 0;
}

// Decode an HTTP chunked-transfer-encoding stream IN-PLACE.
// `src` points at the body bytes, `src_len` is the chunked-encoded
// length. On success returns the decoded payload length and writes
// the bytes to `dst` (which can alias src). Returns 0 on any
// malformed input — caller falls back to "treat body as already-
// decoded" since most plain-static servers reply Content-Length.
u32 DecodeChunked(const u8* src, u32 src_len, u8* dst, u32 dst_cap)
{
    u32 in = 0;
    u32 out = 0;
    while (in < src_len)
    {
        // Parse the hex length line.
        u32 chunk_len = 0;
        bool digit_seen = false;
        while (in < src_len && src[in] != '\r' && src[in] != ';')
        {
            const u8 c = src[in++];
            u32 d = 0;
            if (c >= '0' && c <= '9')
                d = c - '0';
            else if (c >= 'a' && c <= 'f')
                d = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F')
                d = c - 'A' + 10;
            else
                return 0;
            chunk_len = (chunk_len << 4) | d;
            digit_seen = true;
            if (chunk_len > 16u * 1024u * 1024u)
                return 0;
        }
        if (!digit_seen)
            return 0;
        // Skip optional chunk-extension (";name=value") + CRLF.
        while (in < src_len && src[in] != '\n')
            ++in;
        if (in >= src_len)
            return 0;
        ++in; // past '\n'
        if (chunk_len == 0)
            return out; // last chunk; ignore trailers
        if (in + chunk_len > src_len || out + chunk_len > dst_cap)
            return 0;
        for (u32 k = 0; k < chunk_len; ++k)
            dst[out + k] = src[in + k];
        in += chunk_len;
        out += chunk_len;
        // Trailing CRLF after the chunk data.
        if (in + 2 > src_len || src[in] != '\r' || src[in + 1] != '\n')
            return 0;
        in += 2;
    }
    return out;
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

// RandomByteFn callback for TLS: yields a non-zero byte by
// pulling from the kernel CSPRNG. PKCS#1 v1.5 type-2 padding
// requires every PS byte to be non-zero, so the helper loops
// until it gets one.
u8 NonZeroRandByte()
{
    for (u32 tries = 0; tries < 32; ++tries)
    {
        const u64 v = duetos::core::RandomU64();
        for (u32 i = 0; i < 8; ++i)
        {
            const u8 b = static_cast<u8>((v >> (i * 8)) & 0xFFu);
            if (b != 0)
                return b;
        }
    }
    return 1; // give up; PKCS#1 PS only needs non-zero, value doesn't matter
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

// Walks the TLS handshake against a connected stream socket.
// Sends ClientHello, receives server records into a heap stage
// buffer until a server flight is complete, hands the bytes to
// ConnectionFeed, sends whatever the state machine emits in
// reply, and loops until c->state hits Established or Failed.
// Returns true once Established, false on timeout / error.
bool TlsHandshakeOverSocket(u32 sock, duetos::net::tls::Connection* c, const u8 client_random[32], const u8 pms[48],
                            const char* sni_hostname)
{
    u8 out_buf[2048];
    u32 out_len = duetos::net::tls::ConnectionStart(c, client_random, pms, sni_hostname, out_buf, sizeof(out_buf));
    if (out_len == 0)
        return false;
    {
        u32 sent = 0;
        while (sent < out_len)
        {
            const i64 n = duetos::net::SocketSendStream(sock, out_buf + sent, out_len - sent);
            if (n <= 0)
                return false;
            sent += static_cast<u32>(n);
        }
    }

    // Server flight buffer. ServerHello + Certificate +
    // ServerHelloDone can run a few KiB once a real cert
    // chain shows up; 32 KiB stages a single full handshake
    // flight comfortably.
    constexpr u32 kFlightCap = 32 * 1024;
    auto* flight = static_cast<u8*>(duetos::mm::KMalloc(kFlightCap));
    if (flight == nullptr)
        return false;
    u32 flight_len = 0;
    u32 idle_ticks = 0;
    while (c->state != duetos::net::tls::State::Established && c->state != duetos::net::tls::State::Failed)
    {
        const i64 n = duetos::net::SocketRecvStream(sock, flight + flight_len, kFlightCap - flight_len);
        if (n > 0)
        {
            flight_len += static_cast<u32>(n);
            idle_ticks = 0;
            // Feed everything we have. ConnectionFeed will
            // bail early if it needs more bytes; we keep
            // looping the socket recv until the state
            // advances.
            out_len =
                duetos::net::tls::ConnectionFeed(c, flight, flight_len, out_buf, sizeof(out_buf), &NonZeroRandByte);
            if (c->state == duetos::net::tls::State::Failed)
                break;
            if (out_len > 0)
            {
                u32 sent = 0;
                while (sent < out_len)
                {
                    const i64 m = duetos::net::SocketSendStream(sock, out_buf + sent, out_len - sent);
                    if (m <= 0)
                    {
                        c->state = duetos::net::tls::State::Failed;
                        c->err = "socket send failed mid-handshake";
                        break;
                    }
                    sent += static_cast<u32>(m);
                }
                // Reset the flight buffer — we've consumed
                // and replied. Subsequent recvs feed a fresh
                // server flight (the encrypted Finished round).
                flight_len = 0;
            }
            continue;
        }
        if (n == 0)
        {
            // Peer closed mid-handshake.
            c->state = duetos::net::tls::State::Failed;
            c->err = "peer closed mid-handshake";
            break;
        }
        // n < 0 — nothing to read. Sleep + retry; ~10s ceiling.
        duetos::sched::SchedSleepTicks(1);
        if (++idle_ticks > 100)
        {
            c->state = duetos::net::tls::State::Failed;
            c->err = "handshake timeout";
            break;
        }
    }
    duetos::mm::KFree(flight);
    return c->state == duetos::net::tls::State::Established;
}

void DoHttpsFetch(const ParsedUrl& url, const char* dest)
{
    duetos::net::Ipv4Address ip{};
    ConsoleWrite("WGET: resolving ");
    ConsoleWrite(url.host);
    ConsoleWriteln(" (https) ...");
    if (!ResolveHost(url.host, &ip))
    {
        ConsoleWriteln("WGET: DNS lookup failed");
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
    ConsoleWriteln(" (TLS 1.2)");

    const i32 sock = duetos::net::SocketAlloc(duetos::net::kSocketDomainInet, duetos::net::kSocketTypeStream);
    if (sock < 0)
    {
        ConsoleWriteln("WGET: SocketAlloc failed");
        return;
    }
    if (!duetos::net::SocketConnect(static_cast<u32>(sock), ip, url.port))
    {
        duetos::net::SocketRelease(static_cast<u32>(sock));
        ConsoleWriteln("WGET: TCP connect failed");
        return;
    }

    // Seed the client_random + pre_master_secret from the
    // kernel CSPRNG. PMS first two bytes are the offered TLS
    // version (RFC 5246 §7.4.7.1).
    u8 client_random[32];
    u8 pms[48];
    duetos::core::RandomFillBytes(client_random, sizeof(client_random));
    duetos::core::RandomFillBytes(pms, sizeof(pms));
    pms[0] = 0x03;
    pms[1] = 0x03;

    auto* c = static_cast<duetos::net::tls::Connection*>(duetos::mm::KMalloc(sizeof(duetos::net::tls::Connection)));
    if (c == nullptr)
    {
        duetos::net::SocketRelease(static_cast<u32>(sock));
        ConsoleWriteln("WGET: OOM tls connection state");
        return;
    }

    ConsoleWriteln("WGET: starting TLS handshake (RSA + AES-128-GCM)...");
    const bool handshake_ok = TlsHandshakeOverSocket(static_cast<u32>(sock), c, client_random, pms, url.host);
    if (!handshake_ok)
    {
        ConsoleWrite("WGET: TLS handshake FAILED");
        if (c->err != nullptr)
        {
            ConsoleWrite(" — ");
            ConsoleWrite(c->err);
        }
        ConsoleWriteln("");
        ConsoleWriteln("      Note: v0 only offers TLS_RSA_WITH_AES_128_GCM_SHA256.");
        ConsoleWriteln("      Most modern CDNs only accept ECDHE. ECDHE support");
        ConsoleWriteln("      lands when Tier 2 of the TLS roadmap ships.");
        duetos::net::SocketRelease(static_cast<u32>(sock));
        duetos::mm::KFree(c);
        return;
    }
    ConsoleWriteln("WGET: TLS handshake established");

    // Build the HTTP request and encrypt it under the
    // post-Finished client_write_key + client_iv_salt.
    char req[768];
    const u32 req_len = BuildHttpRequest(url, req, sizeof(req));
    u8 enc_req[1024];
    const u32 enc_req_len =
        duetos::net::tls::ConnectionEncryptApp(c, reinterpret_cast<const u8*>(req), req_len, enc_req, sizeof(enc_req));
    if (enc_req_len == 0)
    {
        ConsoleWriteln("WGET: failed to encrypt HTTP request");
        duetos::net::SocketRelease(static_cast<u32>(sock));
        duetos::mm::KFree(c);
        return;
    }
    {
        u32 sent = 0;
        while (sent < enc_req_len)
        {
            const i64 n = duetos::net::SocketSendStream(static_cast<u32>(sock), enc_req + sent, enc_req_len - sent);
            if (n <= 0)
                break;
            sent += static_cast<u32>(n);
        }
    }
    // Half-close removed in the encrypted path — TLS Alerts
    // are how a clean close works. We just rely on the
    // server's "Connection: close" Response + an idle
    // timeout to terminate the read loop.

    // Read encrypted records, decrypt, accumulate plaintext.
    auto* enc_in = static_cast<u8*>(duetos::mm::KMalloc(kBodyCapBytes));
    auto* plain = static_cast<u8*>(duetos::mm::KMalloc(kBodyCapBytes));
    if (enc_in == nullptr || plain == nullptr)
    {
        if (enc_in != nullptr)
            duetos::mm::KFree(enc_in);
        if (plain != nullptr)
            duetos::mm::KFree(plain);
        duetos::net::SocketRelease(static_cast<u32>(sock));
        duetos::mm::KFree(c);
        ConsoleWriteln("WGET: OOM read buffers");
        return;
    }
    u32 enc_in_len = 0;
    u32 plain_len = 0;
    u32 idle_ticks = 0;
    while (plain_len < kBodyCapBytes && idle_ticks < 300)
    {
        const i64 n =
            duetos::net::SocketRecvStream(static_cast<u32>(sock), enc_in + enc_in_len, kBodyCapBytes - enc_in_len);
        if (n > 0)
        {
            enc_in_len += static_cast<u32>(n);
            idle_ticks = 0;
            // Peel off as many complete TLS records as we can.
            u32 off = 0;
            while (off + 5 < enc_in_len)
            {
                duetos::net::tls::RecordView rv{};
                if (!duetos::net::tls::TlsPeekRecord(enc_in + off, enc_in_len - off, &rv))
                    break;
                const u32 record_total = 5u + rv.length;
                if (off + record_total > enc_in_len)
                    break; // partial; wait for more
                u32 pt_chunk = 0;
                if (rv.type == duetos::net::tls::kContentApplicationData)
                {
                    if (duetos::net::tls::ConnectionDecryptApp(c, enc_in + off, record_total, plain + plain_len,
                                                               kBodyCapBytes - plain_len, &pt_chunk))
                    {
                        plain_len += pt_chunk;
                    }
                    else
                    {
                        ConsoleWriteln("WGET: TLS record decrypt failed");
                        goto done;
                    }
                }
                else if (rv.type == duetos::net::tls::kContentAlert)
                {
                    // Server-initiated close_notify (level=1)
                    // or fatal alert. Either way, stop reading.
                    goto done;
                }
                off += record_total;
            }
            // Shift unconsumed bytes to front of buffer.
            if (off > 0)
            {
                for (u32 i = 0; i + off < enc_in_len; ++i)
                    enc_in[i] = enc_in[i + off];
                enc_in_len -= off;
            }
            continue;
        }
        if (n == 0)
            break; // peer closed
        duetos::sched::SchedSleepTicks(1);
        ++idle_ticks;
    }
done:
    duetos::net::SocketRelease(static_cast<u32>(sock));
    duetos::mm::KFree(c);
    duetos::mm::KFree(enc_in);

    // Same HTTP-response handling as the HTTP path. Surface
    // status, headers, then write/print body.
    const u32 status = ParseStatusCode(plain, plain_len);
    const u32 body_off = FindBodyStart(plain, plain_len);
    u32 body_len = plain_len - body_off;
    char ctype[96];
    char clen[32];
    char xfer[32];
    const u32 ctype_n = FindHeader(plain, body_off, "Content-Type", ctype, sizeof(ctype));
    const u32 clen_n = FindHeader(plain, body_off, "Content-Length", clen, sizeof(clen));
    const u32 xfer_n = FindHeader(plain, body_off, "Transfer-Encoding", xfer, sizeof(xfer));
    ConsoleWrite("WGET: HTTPS ");
    WriteU64Dec(status);
    if (ctype_n > 0)
    {
        ConsoleWrite("  type=");
        ConsoleWrite(ctype);
    }
    if (clen_n > 0)
    {
        ConsoleWrite("  length=");
        ConsoleWrite(clen);
    }
    ConsoleWriteln("");
    if (xfer_n > 0 && StrCaseEqN(xfer, "chunked", 7))
    {
        const u32 decoded = DecodeChunked(plain + body_off, body_len, plain + body_off, kBodyCapBytes - body_off);
        if (decoded == 0)
        {
            ConsoleWriteln("WGET: chunked decode failed");
            duetos::mm::KFree(plain);
            return;
        }
        body_len = decoded;
    }
    ConsoleWrite("WGET: total wire=");
    WriteU64Dec(plain_len);
    ConsoleWrite("  body=");
    WriteU64Dec(body_len);
    ConsoleWriteln("");

    if (dest == nullptr)
    {
        constexpr u32 kPrintCap = 4096;
        const u32 print_len = body_len > kPrintCap ? kPrintCap : body_len;
        for (u32 i = 0; i < print_len; ++i)
            ConsoleWriteChar(static_cast<char>(plain[body_off + i]));
        if (body_len > kPrintCap)
        {
            ConsoleWrite("\n[... ");
            WriteU64Dec(body_len - kPrintCap);
            ConsoleWriteln(" more bytes elided]");
        }
        else
        {
            ConsoleWriteln("");
        }
        duetos::mm::KFree(plain);
        return;
    }
    const auto* vol = duetos::fs::fat32::Fat32Volume(0);
    if (vol == nullptr)
    {
        ConsoleWriteln("WGET: NO FAT32 VOLUME for dst");
        duetos::mm::KFree(plain);
        return;
    }
    MkdirParents(vol, dest);
    const auto written = duetos::fs::fat32::Fat32CreateAtPath(vol, dest, plain + body_off, body_len);
    if (written != static_cast<duetos::i64>(body_len))
    {
        ConsoleWrite("WGET: CREATE FAIL ");
        ConsoleWriteln(dest);
    }
    else
    {
        ConsoleWrite("WGET: saved ");
        WriteU64Dec(body_len);
        ConsoleWrite(" bytes to ");
        ConsoleWriteln(dest);
    }
    duetos::mm::KFree(plain);
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
        DoHttpsFetch(url, dest);
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
    u32 body_len = got - body_off;

    // Surface Content-Type / Content-Length so the user sees
    // what they're getting BEFORE the body prints / writes.
    char ctype[96];
    char clen[32];
    char xfer[32];
    const u32 ctype_n = FindHeader(buf, body_off, "Content-Type", ctype, sizeof(ctype));
    const u32 clen_n = FindHeader(buf, body_off, "Content-Length", clen, sizeof(clen));
    const u32 xfer_n = FindHeader(buf, body_off, "Transfer-Encoding", xfer, sizeof(xfer));

    ConsoleWrite("WGET: HTTP ");
    WriteU64Dec(status);
    if (ctype_n > 0)
    {
        ConsoleWrite("  type=");
        ConsoleWrite(ctype);
    }
    if (clen_n > 0)
    {
        ConsoleWrite("  length=");
        ConsoleWrite(clen);
    }
    ConsoleWriteln("");

    // Chunked transfer-encoding: decode the body in place. Most
    // static-file servers reply with Content-Length when given
    // Connection: close (we send that), but some (esp. dynamic
    // content / load balancers) still send chunked even so.
    if (xfer_n > 0 && StrCaseEqN(xfer, "chunked", 7))
    {
        const u32 decoded = DecodeChunked(buf + body_off, body_len, buf + body_off, kBodyCapBytes - body_off);
        if (decoded == 0)
        {
            ConsoleWriteln("WGET: chunked decode failed (malformed Transfer-Encoding)");
            duetos::mm::KFree(buf);
            return;
        }
        ConsoleWrite("WGET: chunked-decoded ");
        WriteU64Dec(body_len);
        ConsoleWrite(" -> ");
        WriteU64Dec(decoded);
        ConsoleWriteln(" bytes");
        body_len = decoded;
    }

    ConsoleWrite("WGET: total wire=");
    WriteU64Dec(got);
    ConsoleWrite("  body=");
    WriteU64Dec(body_len);
    ConsoleWriteln("");

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

// ---------------------------------------------------------------------------
// sha256sum — Unix-style file hash. Output format mirrors coreutils:
//   "<lowercase-hex-digest>  <path>".
// Streams the file in chunks via Fat32ReadFileStream so multi-MiB
// archives don't need a heap allocation the size of the file. The
// kernel SHA-256 implementation already exists (crypto/sha256.h) —
// this is the shell-facing surface.
// ---------------------------------------------------------------------------

namespace
{

void WriteHexLower(u8 b)
{
    static constexpr char kHex[] = "0123456789abcdef";
    ConsoleWriteChar(kHex[(b >> 4) & 0xF]);
    ConsoleWriteChar(kHex[b & 0xF]);
}

struct Sha256StreamCtx
{
    duetos::crypto::Sha256Ctx hash;
    u64 byte_count;
};

bool Sha256ChunkCb(const u8* data, u64 len, void* ctx)
{
    auto* s = static_cast<Sha256StreamCtx*>(ctx);
    // Sha256Update takes u32; chunk loop handles large clusters
    // by splitting if needed (FAT32 cluster max is 32 KiB though).
    u64 off = 0;
    while (off < len)
    {
        const u32 take = (len - off > 0xFFFFFFFFull) ? 0xFFFFFFFFu : static_cast<u32>(len - off);
        duetos::crypto::Sha256Update(s->hash, data + off, take);
        off += take;
    }
    s->byte_count += len;
    return true;
}

} // namespace

void CmdSha256Sum(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("SHA256SUM: usage: sha256sum <path>");
        ConsoleWriteln("           Prints '<digest>  <path>' on success.");
        ConsoleWriteln("           Works on ramfs (/etc, /bin, /lib) AND FAT32 disk paths.");
        return;
    }
    for (u32 a = 1; a < argc; ++a)
    {
        const char* path = argv[a];
        Sha256StreamCtx sctx{};
        duetos::crypto::Sha256Init(sctx.hash);

        // Prefer FAT32 (real disk) — file sizes there are
        // unbounded relative to the ramfs scratch cap. Fall
        // back to ReadFileToBuf for ramfs / tmpfs paths.
        const auto* vol = duetos::fs::fat32::Fat32Volume(0);
        duetos::fs::fat32::DirEntry ent;
        bool used_fat32 = false;
        if (vol != nullptr && duetos::fs::fat32::Fat32LookupPath(vol, path, &ent))
        {
            if ((ent.attributes & 0x10) != 0)
            {
                ConsoleWrite("SHA256SUM: IS A DIRECTORY: ");
                ConsoleWriteln(path);
                continue;
            }
            if (!duetos::fs::fat32::Fat32ReadFileStream(vol, &ent, &Sha256ChunkCb, &sctx))
            {
                ConsoleWrite("SHA256SUM: I/O ERROR: ");
                ConsoleWriteln(path);
                continue;
            }
            used_fat32 = true;
        }
        else
        {
            char scratch[duetos::fs::kTmpFsContentMax];
            const u32 n = ReadFileToBuf(path, scratch, sizeof(scratch));
            if (n == static_cast<u32>(-1))
            {
                ConsoleWrite("SHA256SUM: NO SUCH FILE: ");
                ConsoleWriteln(path);
                continue;
            }
            duetos::crypto::Sha256Update(sctx.hash, reinterpret_cast<const u8*>(scratch), n);
            sctx.byte_count = n;
        }

        u8 digest[duetos::crypto::kSha256DigestBytes];
        duetos::crypto::Sha256Final(sctx.hash, digest);
        for (u32 i = 0; i < duetos::crypto::kSha256DigestBytes; ++i)
            WriteHexLower(digest[i]);
        ConsoleWrite("  ");
        ConsoleWrite(path);
        if (!used_fat32)
        {
            // Annotate ramfs reads so the user knows the
            // 512-byte ramfs scratch cap might have truncated.
            ConsoleWrite("  (ramfs; cap=");
            WriteU64Dec(duetos::fs::kTmpFsContentMax);
            ConsoleWriteChar(')');
        }
        ConsoleWriteln("");
    }
}

// ---------------------------------------------------------------------------
// base64 — Unix-style encode/decode. Uses the standard alphabet
// (A-Z a-z 0-9 + /) with `=` padding per RFC 4648 §4.
//
// Usage:
//   base64 <file>              encode file contents to console
//   base64 -d <file>           decode base64 text to console
//   base64 -d <src> <dst>      decode to FAT32 path
//   base64 <src> <dst>         encode to FAT32 path
//
// Source can be a ramfs path (capped at kTmpFsContentMax) or a
// FAT32 path (capped by a 64 KiB heap stage — base64 of a 48 KiB
// payload is exactly 64 KiB).
// ---------------------------------------------------------------------------

namespace
{

constexpr char kB64Alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

i32 B64DecodeChar(u8 c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return 26 + (c - 'a');
    if (c >= '0' && c <= '9')
        return 52 + (c - '0');
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;
    return -1;
}

u32 Base64Encode(const u8* src, u32 src_len, u8* dst, u32 dst_cap)
{
    const u32 need = ((src_len + 2) / 3) * 4;
    if (dst_cap < need)
        return 0;
    u32 si = 0;
    u32 di = 0;
    while (si + 3 <= src_len)
    {
        const u32 v = (u32(src[si]) << 16) | (u32(src[si + 1]) << 8) | u32(src[si + 2]);
        dst[di++] = kB64Alphabet[(v >> 18) & 0x3F];
        dst[di++] = kB64Alphabet[(v >> 12) & 0x3F];
        dst[di++] = kB64Alphabet[(v >> 6) & 0x3F];
        dst[di++] = kB64Alphabet[v & 0x3F];
        si += 3;
    }
    if (si + 1 == src_len)
    {
        const u32 v = u32(src[si]) << 16;
        dst[di++] = kB64Alphabet[(v >> 18) & 0x3F];
        dst[di++] = kB64Alphabet[(v >> 12) & 0x3F];
        dst[di++] = '=';
        dst[di++] = '=';
    }
    else if (si + 2 == src_len)
    {
        const u32 v = (u32(src[si]) << 16) | (u32(src[si + 1]) << 8);
        dst[di++] = kB64Alphabet[(v >> 18) & 0x3F];
        dst[di++] = kB64Alphabet[(v >> 12) & 0x3F];
        dst[di++] = kB64Alphabet[(v >> 6) & 0x3F];
        dst[di++] = '=';
    }
    return di;
}

// Returns decoded length, or 0 on malformed input. Skips
// whitespace (per coreutils -d compatibility).
u32 Base64Decode(const u8* src, u32 src_len, u8* dst, u32 dst_cap)
{
    u32 quad[4];
    u32 qi = 0;
    u32 di = 0;
    u32 pad = 0;
    for (u32 i = 0; i < src_len; ++i)
    {
        const u8 c = src[i];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
            continue;
        if (c == '=')
        {
            quad[qi++] = 0;
            ++pad;
        }
        else
        {
            const i32 v = B64DecodeChar(c);
            if (v < 0)
                return 0;
            if (pad > 0)
                return 0; // base64 char after padding
            quad[qi++] = static_cast<u32>(v);
        }
        if (qi == 4)
        {
            const u32 v = (quad[0] << 18) | (quad[1] << 12) | (quad[2] << 6) | quad[3];
            if (di + 3 - pad > dst_cap)
                return 0;
            dst[di++] = static_cast<u8>((v >> 16) & 0xFF);
            if (pad < 2)
                dst[di++] = static_cast<u8>((v >> 8) & 0xFF);
            if (pad < 1)
                dst[di++] = static_cast<u8>(v & 0xFF);
            qi = 0;
            if (pad > 0)
                break;
        }
    }
    if (qi != 0 && pad == 0)
        return 0; // truncated input (not byte-aligned)
    return di;
}

// Read a file into a heap buffer. Tries FAT32 first, then
// ramfs (via ReadFileToBuf — capped at kTmpFsContentMax).
// Returns nullptr on failure; on success, `*out_len` is the
// data size and the caller must KFree the returned pointer.
u8* ReadAnyFile(const char* path, u32* out_len)
{
    *out_len = 0;
    const auto* vol = duetos::fs::fat32::Fat32Volume(0);
    duetos::fs::fat32::DirEntry ent;
    if (vol != nullptr && duetos::fs::fat32::Fat32LookupPath(vol, path, &ent) && (ent.attributes & 0x10) == 0)
    {
        if (ent.size_bytes == 0 || ent.size_bytes > 64 * 1024)
            return nullptr;
        auto* buf = static_cast<u8*>(duetos::mm::KMalloc(ent.size_bytes));
        if (buf == nullptr)
            return nullptr;
        const auto got = duetos::fs::fat32::Fat32ReadFile(vol, &ent, buf, ent.size_bytes);
        if (got != static_cast<duetos::i64>(ent.size_bytes))
        {
            duetos::mm::KFree(buf);
            return nullptr;
        }
        *out_len = ent.size_bytes;
        return buf;
    }
    // Fallback: ramfs / tmpfs via 512-byte scratch.
    auto* buf = static_cast<u8*>(duetos::mm::KMalloc(duetos::fs::kTmpFsContentMax));
    if (buf == nullptr)
        return nullptr;
    const u32 n = ReadFileToBuf(path, reinterpret_cast<char*>(buf), duetos::fs::kTmpFsContentMax);
    if (n == static_cast<u32>(-1))
    {
        duetos::mm::KFree(buf);
        return nullptr;
    }
    *out_len = n;
    return buf;
}

} // namespace

void CmdBase64(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("BASE64: usage: base64 [-d] <src> [<dst>]");
        ConsoleWriteln("        -d     decode (default: encode)");
        ConsoleWriteln("        <src>  source path (FAT32 or ramfs)");
        ConsoleWriteln("        <dst>  optional FAT32 destination path");
        return;
    }
    bool decode = false;
    u32 arg = 1;
    if (argv[1][0] == '-' && argv[1][1] == 'd' && argv[1][2] == '\0')
    {
        decode = true;
        ++arg;
        if (arg >= argc)
        {
            ConsoleWriteln("BASE64: -d needs a source path");
            return;
        }
    }
    const char* src_path = argv[arg++];
    const char* dst_path = (arg < argc) ? argv[arg] : nullptr;

    u32 src_len = 0;
    auto* src = ReadAnyFile(src_path, &src_len);
    if (src == nullptr)
    {
        ConsoleWrite("BASE64: NO SUCH FILE: ");
        ConsoleWriteln(src_path);
        return;
    }

    constexpr u32 kStageCap = 128 * 1024;
    auto* stage = static_cast<u8*>(duetos::mm::KMalloc(kStageCap));
    if (stage == nullptr)
    {
        duetos::mm::KFree(src);
        ConsoleWriteln("BASE64: OOM staging buffer");
        return;
    }

    u32 out_len = 0;
    if (decode)
    {
        out_len = Base64Decode(src, src_len, stage, kStageCap);
        if (out_len == 0 && src_len > 0)
        {
            ConsoleWriteln("BASE64: malformed input (bad char / truncated)");
            duetos::mm::KFree(src);
            duetos::mm::KFree(stage);
            return;
        }
    }
    else
    {
        out_len = Base64Encode(src, src_len, stage, kStageCap);
        if (out_len == 0 && src_len > 0)
        {
            ConsoleWriteln("BASE64: encode buffer overflow");
            duetos::mm::KFree(src);
            duetos::mm::KFree(stage);
            return;
        }
    }
    duetos::mm::KFree(src);

    if (dst_path == nullptr)
    {
        // Print to console.
        for (u32 i = 0; i < out_len; ++i)
            ConsoleWriteChar(static_cast<char>(stage[i]));
        if (out_len == 0 || stage[out_len - 1] != '\n')
            ConsoleWriteChar('\n');
        duetos::mm::KFree(stage);
        return;
    }

    const auto* vol = duetos::fs::fat32::Fat32Volume(0);
    if (vol == nullptr)
    {
        ConsoleWriteln("BASE64: NO FAT32 VOLUME MOUNTED for dst");
        duetos::mm::KFree(stage);
        return;
    }
    MkdirParents(vol, dst_path);
    const auto wrote = duetos::fs::fat32::Fat32CreateAtPath(vol, dst_path, stage, out_len);
    if (wrote != static_cast<duetos::i64>(out_len))
    {
        ConsoleWrite("BASE64: CREATE FAIL ");
        ConsoleWriteln(dst_path);
        duetos::mm::KFree(stage);
        return;
    }
    ConsoleWrite("BASE64: ");
    ConsoleWrite(decode ? "decoded " : "encoded ");
    WriteU64Dec(out_len);
    ConsoleWrite(" bytes to ");
    ConsoleWriteln(dst_path);
    duetos::mm::KFree(stage);
}

// ---------------------------------------------------------------------------
// xxd — xxd-style hex dump. Differs from `hexdump` in two ways:
//   1. Reads via FAT32 streaming (no 512-byte cap; works on
//      multi-MiB files).
//   2. Output is xxd-compatible: lowercase hex, 16-byte rows
//      grouped in pairs (4-char groups), 8-character offset
//      column, and a trailing printable-ASCII gutter.
// ---------------------------------------------------------------------------

namespace
{

void WriteHex2Lower(u8 b)
{
    static constexpr char kHex[] = "0123456789abcdef";
    ConsoleWriteChar(kHex[(b >> 4) & 0xF]);
    ConsoleWriteChar(kHex[b & 0xF]);
}

void WriteHex8Lower(u32 v)
{
    for (int s = 28; s >= 0; s -= 4)
    {
        static constexpr char kHex[] = "0123456789abcdef";
        ConsoleWriteChar(kHex[(v >> s) & 0xF]);
    }
}

void DumpXxdRow(u32 offset, const u8* row, u32 row_len)
{
    WriteHex8Lower(offset);
    ConsoleWriteChar(':');
    ConsoleWriteChar(' ');
    for (u32 i = 0; i < 16; ++i)
    {
        if (i < row_len)
            WriteHex2Lower(row[i]);
        else
            ConsoleWrite("  ");
        if ((i & 1) == 1 && i < 15)
            ConsoleWriteChar(' ');
    }
    ConsoleWrite("  ");
    for (u32 i = 0; i < row_len; ++i)
    {
        const u8 c = row[i];
        ConsoleWriteChar((c >= 0x20 && c <= 0x7E) ? static_cast<char>(c) : '.');
    }
    ConsoleWriteln("");
}

struct XxdStreamCtx
{
    u32 offset;
    u8 carry[16];
    u32 carry_len;
};

bool XxdChunkCb(const u8* data, u64 len, void* ctx)
{
    auto* s = static_cast<XxdStreamCtx*>(ctx);
    u64 i = 0;
    while (i < len)
    {
        // Fill from carry first.
        while (s->carry_len < 16 && i < len)
            s->carry[s->carry_len++] = data[i++];
        if (s->carry_len == 16)
        {
            DumpXxdRow(s->offset, s->carry, 16);
            s->offset += 16;
            s->carry_len = 0;
        }
    }
    return true;
}

} // namespace

void CmdXxd(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("XXD: usage: xxd <path>");
        ConsoleWriteln("     Streams a FAT32 / ramfs file as 16-byte hex rows.");
        return;
    }
    const char* path = argv[1];
    XxdStreamCtx s{};
    bool used_fat32 = false;
    const auto* vol = duetos::fs::fat32::Fat32Volume(0);
    duetos::fs::fat32::DirEntry ent;
    if (vol != nullptr && duetos::fs::fat32::Fat32LookupPath(vol, path, &ent) && (ent.attributes & 0x10) == 0)
    {
        if (!duetos::fs::fat32::Fat32ReadFileStream(vol, &ent, &XxdChunkCb, &s))
        {
            ConsoleWrite("XXD: I/O ERROR: ");
            ConsoleWriteln(path);
            return;
        }
        used_fat32 = true;
    }
    else
    {
        char scratch[duetos::fs::kTmpFsContentMax];
        const u32 n = ReadFileToBuf(path, scratch, sizeof(scratch));
        if (n == static_cast<u32>(-1))
        {
            ConsoleWrite("XXD: NO SUCH FILE: ");
            ConsoleWriteln(path);
            return;
        }
        XxdChunkCb(reinterpret_cast<const u8*>(scratch), n, &s);
    }
    if (s.carry_len > 0)
    {
        DumpXxdRow(s.offset, s.carry, s.carry_len);
        s.offset += s.carry_len;
    }
    (void)used_fat32;
}

// ---------------------------------------------------------------------------
// wc — line / word / byte counts (coreutils-shaped output).
//   wc <path>          newlines  words  bytes  path
//   wc -l <path>       newlines only
//   wc -w <path>       words only
//   wc -c <path>       bytes only
// Streams via Fat32ReadFileStream so multi-MiB files don't
// hit the 512-byte ramfs scratch cap.
// ---------------------------------------------------------------------------

namespace
{

struct WcCtx
{
    u64 lines;
    u64 words;
    u64 bytes;
    bool in_word;
};

void WcAccumulate(WcCtx* w, const u8* data, u64 n)
{
    for (u64 i = 0; i < n; ++i)
    {
        const u8 c = data[i];
        ++w->bytes;
        if (c == '\n')
            ++w->lines;
        const bool is_ws = (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f');
        if (!is_ws && !w->in_word)
        {
            ++w->words;
            w->in_word = true;
        }
        else if (is_ws)
        {
            w->in_word = false;
        }
    }
}

bool WcChunkCb(const u8* data, u64 len, void* ctx)
{
    WcAccumulate(static_cast<WcCtx*>(ctx), data, len);
    return true;
}

} // namespace

void CmdWc(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("WC: usage: wc [-l|-w|-c] <path> [<path>...]");
        return;
    }
    bool only_lines = false;
    bool only_words = false;
    bool only_bytes = false;
    u32 first = 1;
    if (argv[1][0] == '-' && argv[1][1] != '\0' && argv[1][2] == '\0')
    {
        switch (argv[1][1])
        {
        case 'l':
            only_lines = true;
            ++first;
            break;
        case 'w':
            only_words = true;
            ++first;
            break;
        case 'c':
            only_bytes = true;
            ++first;
            break;
        default:
            ConsoleWrite("WC: bad flag ");
            ConsoleWriteln(argv[1]);
            return;
        }
    }
    if (first >= argc)
    {
        ConsoleWriteln("WC: need a path");
        return;
    }
    for (u32 a = first; a < argc; ++a)
    {
        WcCtx w{};
        const auto* vol = duetos::fs::fat32::Fat32Volume(0);
        duetos::fs::fat32::DirEntry ent;
        if (vol != nullptr && duetos::fs::fat32::Fat32LookupPath(vol, argv[a], &ent) && (ent.attributes & 0x10) == 0)
        {
            if (!duetos::fs::fat32::Fat32ReadFileStream(vol, &ent, &WcChunkCb, &w))
            {
                ConsoleWrite("WC: I/O ERROR: ");
                ConsoleWriteln(argv[a]);
                continue;
            }
        }
        else
        {
            char scratch[duetos::fs::kTmpFsContentMax];
            const u32 n = ReadFileToBuf(argv[a], scratch, sizeof(scratch));
            if (n == static_cast<u32>(-1))
            {
                ConsoleWrite("WC: NO SUCH FILE: ");
                ConsoleWriteln(argv[a]);
                continue;
            }
            WcAccumulate(&w, reinterpret_cast<const u8*>(scratch), n);
        }
        if (only_lines)
        {
            WriteU64Dec(w.lines);
        }
        else if (only_words)
        {
            WriteU64Dec(w.words);
        }
        else if (only_bytes)
        {
            WriteU64Dec(w.bytes);
        }
        else
        {
            WriteU64Dec(w.lines);
            ConsoleWriteChar(' ');
            WriteU64Dec(w.words);
            ConsoleWriteChar(' ');
            WriteU64Dec(w.bytes);
        }
        ConsoleWriteChar(' ');
        ConsoleWriteln(argv[a]);
    }
}

// ---------------------------------------------------------------------------
// tr — translate / squeeze / delete characters in console
// stream form. v0 reads source from a file path (no real stdin
// pipeline yet) and writes to console / FAT32. Supports:
//   tr <from> <to> <src>            translate set1->set2
//   tr -d <set> <src>               delete every char in set
//   tr -s <char> <src>              squeeze runs of `char` to one
//
// Sets are literal byte strings (no [a-z] ranges or [:class:]).
// Practical for stripping CRs, lowercasing ASCII when sets are
// equal-length, etc.
// ---------------------------------------------------------------------------

namespace
{

bool ContainsByte(const char* set, u8 b)
{
    for (u32 i = 0; set[i] != '\0'; ++i)
        if (static_cast<u8>(set[i]) == b)
            return true;
    return false;
}

i32 IndexOfByte(const char* set, u8 b)
{
    for (i32 i = 0; set[i] != '\0'; ++i)
        if (static_cast<u8>(set[i]) == b)
            return i;
    return -1;
}

} // namespace

void CmdTr(u32 argc, char** argv)
{
    if (argc < 3)
    {
        ConsoleWriteln("TR: usage:");
        ConsoleWriteln("    tr <from> <to> <src>     translate bytes (sets must match length)");
        ConsoleWriteln("    tr -d <set> <src>        delete bytes in set");
        ConsoleWriteln("    tr -s <char> <src>       squeeze runs of char to one");
        return;
    }
    bool del = false;
    bool squeeze = false;
    u32 idx = 1;
    if (argv[1][0] == '-' && argv[1][1] == 'd' && argv[1][2] == '\0')
    {
        del = true;
        ++idx;
    }
    else if (argv[1][0] == '-' && argv[1][1] == 's' && argv[1][2] == '\0')
    {
        squeeze = true;
        ++idx;
    }
    if (del || squeeze)
    {
        if (argc < idx + 2)
        {
            ConsoleWriteln("TR: missing args");
            return;
        }
    }
    else
    {
        if (argc < 4)
        {
            ConsoleWriteln("TR: missing args");
            return;
        }
    }
    const char* set1 = argv[idx];
    const char* set2 = (del || squeeze) ? nullptr : argv[idx + 1];
    const char* path = (del || squeeze) ? argv[idx + 1] : argv[idx + 2];

    if (!del && !squeeze)
    {
        u32 n1 = 0, n2 = 0;
        while (set1[n1] != '\0')
            ++n1;
        while (set2[n2] != '\0')
            ++n2;
        if (n1 != n2)
        {
            ConsoleWriteln("TR: <from> and <to> sets must be equal length");
            return;
        }
    }

    u32 src_len = 0;
    auto* src = ReadAnyFile(path, &src_len);
    if (src == nullptr)
    {
        ConsoleWrite("TR: NO SUCH FILE: ");
        ConsoleWriteln(path);
        return;
    }
    u8 last_emit = 0;
    bool have_last = false;
    for (u32 i = 0; i < src_len; ++i)
    {
        u8 b = src[i];
        if (del)
        {
            if (ContainsByte(set1, b))
                continue;
        }
        else if (squeeze)
        {
            if (have_last && last_emit == b && ContainsByte(set1, b))
                continue;
        }
        else
        {
            const i32 k = IndexOfByte(set1, b);
            if (k >= 0)
                b = static_cast<u8>(set2[k]);
        }
        ConsoleWriteChar(static_cast<char>(b));
        last_emit = b;
        have_last = true;
    }
    if (!have_last || last_emit != '\n')
        ConsoleWriteChar('\n');
    duetos::mm::KFree(src);
}

// ---------------------------------------------------------------------------
// dd — bytewise file copy with skip / count / bs flags.
// Coreutils-shaped subset:
//   dd if=<src> [of=<dst>] [bs=N] [skip=N] [count=N]
// Default block size 512 bytes (POSIX). Without `of=` writes to
// console. count counts BLOCKS of bs bytes; skip skips that many
// blocks of input.
// ---------------------------------------------------------------------------

namespace
{

bool ParseKeyEq(const char* arg, const char* key, const char** out_value)
{
    u32 i = 0;
    while (key[i] != '\0' && arg[i] != '\0' && arg[i] == key[i])
        ++i;
    if (key[i] != '\0' || arg[i] != '=')
        return false;
    *out_value = arg + i + 1;
    return true;
}

bool ParseU64Dec(const char* s, u64* out)
{
    if (s == nullptr || *s == '\0')
        return false;
    u64 v = 0;
    for (u32 i = 0; s[i] != '\0'; ++i)
    {
        if (s[i] < '0' || s[i] > '9')
            return false;
        v = v * 10 + u64(s[i] - '0');
    }
    *out = v;
    return true;
}

} // namespace

void CmdDd(u32 argc, char** argv)
{
    const char* in_path = nullptr;
    const char* out_path = nullptr;
    u64 bs = 512;
    u64 skip = 0;
    u64 count = ~u64(0); // until EOF
    for (u32 i = 1; i < argc; ++i)
    {
        const char* v = nullptr;
        if (ParseKeyEq(argv[i], "if", &v))
            in_path = v;
        else if (ParseKeyEq(argv[i], "of", &v))
            out_path = v;
        else if (ParseKeyEq(argv[i], "bs", &v))
        {
            u64 n = 0;
            if (!ParseU64Dec(v, &n) || n == 0 || n > 65536)
            {
                ConsoleWriteln("DD: bs out of range (1..65536)");
                return;
            }
            bs = n;
        }
        else if (ParseKeyEq(argv[i], "skip", &v))
        {
            if (!ParseU64Dec(v, &skip))
            {
                ConsoleWriteln("DD: bad skip=");
                return;
            }
        }
        else if (ParseKeyEq(argv[i], "count", &v))
        {
            if (!ParseU64Dec(v, &count))
            {
                ConsoleWriteln("DD: bad count=");
                return;
            }
        }
        else
        {
            ConsoleWrite("DD: unknown arg ");
            ConsoleWriteln(argv[i]);
            return;
        }
    }
    if (in_path == nullptr)
    {
        ConsoleWriteln("DD: usage: dd if=<src> [of=<dst>] [bs=N] [skip=N] [count=N]");
        return;
    }
    u32 src_len = 0;
    auto* src = ReadAnyFile(in_path, &src_len);
    if (src == nullptr)
    {
        ConsoleWrite("DD: NO SUCH FILE: ");
        ConsoleWriteln(in_path);
        return;
    }
    const u64 skip_bytes = skip * bs;
    if (skip_bytes >= src_len)
    {
        duetos::mm::KFree(src);
        ConsoleWriteln("DD: 0+0 records in / out (skip past EOF)");
        return;
    }
    const u64 want_bytes_max = (count == ~u64(0)) ? (src_len - skip_bytes) : (count * bs);
    const u64 want_bytes = (want_bytes_max < src_len - skip_bytes) ? want_bytes_max : (src_len - skip_bytes);
    const u8* payload = src + skip_bytes;
    if (out_path != nullptr)
    {
        const auto* vol = duetos::fs::fat32::Fat32Volume(0);
        if (vol == nullptr)
        {
            ConsoleWriteln("DD: NO FAT32 VOLUME for of=");
            duetos::mm::KFree(src);
            return;
        }
        MkdirParents(vol, out_path);
        const auto wrote = duetos::fs::fat32::Fat32CreateAtPath(vol, out_path, payload, want_bytes);
        if (wrote != static_cast<duetos::i64>(want_bytes))
        {
            ConsoleWrite("DD: CREATE FAIL ");
            ConsoleWriteln(out_path);
            duetos::mm::KFree(src);
            return;
        }
    }
    else
    {
        for (u64 i = 0; i < want_bytes; ++i)
            ConsoleWriteChar(static_cast<char>(payload[i]));
        if (want_bytes == 0 || payload[want_bytes - 1] != '\n')
            ConsoleWriteChar('\n');
    }
    const u64 records = (want_bytes + bs - 1) / bs;
    WriteU64Dec(records);
    ConsoleWrite("+0 records in/out, ");
    WriteU64Dec(want_bytes);
    ConsoleWriteln(" bytes");
    duetos::mm::KFree(src);
}

// ---------------------------------------------------------------------------
// crc32 — IEEE 802.3 reflected CRC-32 (polynomial 0xEDB88320).
// Same construction zlib / GPT / PKZIP / Ethernet FCS use, and
// the same backing implementation as the kernel's own
// `util::Crc32`. Output mirrors GNU `cksum` line format:
//
//   <crc-hex-8>  <bytes>  <path>
//
// Streams from FAT32 to avoid the 512-byte ramfs scratch cap.
// ---------------------------------------------------------------------------

namespace
{

struct CrcStreamCtx
{
    u8* buf; // accumulator (KMalloc'd, freed by caller)
    u64 buf_off;
    u64 buf_cap;
    u64 total;
};

bool CrcChunkCb(const u8* data, u64 len, void* ctx)
{
    auto* s = static_cast<CrcStreamCtx*>(ctx);
    if (s->buf_off + len > s->buf_cap)
        return false; // overflow
    for (u64 i = 0; i < len; ++i)
        s->buf[s->buf_off + i] = data[i];
    s->buf_off += len;
    s->total += len;
    return true;
}

} // namespace

void CmdCrc32(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("CRC32: usage: crc32 <path> [<path>...]");
        ConsoleWriteln("       Prints '<8-hex-digest>  <bytes>  <path>' per file.");
        return;
    }
    for (u32 a = 1; a < argc; ++a)
    {
        const char* path = argv[a];
        // Cap at 4 MiB for crc32 — predictable scratch.
        constexpr u64 kCrcCap = 4u * 1024 * 1024;
        auto* buf = static_cast<u8*>(duetos::mm::KMalloc(kCrcCap));
        if (buf == nullptr)
        {
            ConsoleWriteln("CRC32: OOM");
            return;
        }
        CrcStreamCtx s{};
        s.buf = buf;
        s.buf_cap = kCrcCap;
        const auto* vol = duetos::fs::fat32::Fat32Volume(0);
        duetos::fs::fat32::DirEntry ent;
        bool ok = false;
        if (vol != nullptr && duetos::fs::fat32::Fat32LookupPath(vol, path, &ent) && (ent.attributes & 0x10) == 0)
        {
            ok = duetos::fs::fat32::Fat32ReadFileStream(vol, &ent, &CrcChunkCb, &s);
        }
        if (!ok)
        {
            char scratch[duetos::fs::kTmpFsContentMax];
            const u32 n = ReadFileToBuf(path, scratch, sizeof(scratch));
            if (n == static_cast<u32>(-1))
            {
                ConsoleWrite("CRC32: NO SUCH FILE: ");
                ConsoleWriteln(path);
                duetos::mm::KFree(buf);
                continue;
            }
            for (u32 i = 0; i < n; ++i)
                buf[i] = static_cast<u8>(scratch[i]);
            s.buf_off = n;
            s.total = n;
        }
        const u32 crc = duetos::util::Crc32(buf, s.total);
        // 8-hex output.
        static constexpr char kHex[] = "0123456789abcdef";
        for (int sh = 28; sh >= 0; sh -= 4)
            ConsoleWriteChar(kHex[(crc >> sh) & 0xF]);
        ConsoleWrite("  ");
        WriteU64Dec(s.total);
        ConsoleWrite("  ");
        ConsoleWriteln(path);
        duetos::mm::KFree(buf);
    }
}

// ---------------------------------------------------------------------------
// cmp — byte-wise file comparison. Standard POSIX shapes:
//   cmp <file1> <file2>
//   cmp -s <file1> <file2>     silent (exit-only result)
//
// Reports the offset (1-based) of the first differing byte, or
// confirms equal-size + equal-content match. Streams via
// Fat32ReadFile.
// ---------------------------------------------------------------------------

void CmdCmp(u32 argc, char** argv)
{
    bool silent = false;
    u32 first = 1;
    if (argc >= 2 && argv[1][0] == '-' && argv[1][1] == 's' && argv[1][2] == '\0')
    {
        silent = true;
        ++first;
    }
    if (argc < first + 2)
    {
        ConsoleWriteln("CMP: usage: cmp [-s] <file1> <file2>");
        return;
    }
    u32 a_len = 0;
    u32 b_len = 0;
    auto* a = ReadAnyFile(argv[first + 0], &a_len);
    if (a == nullptr)
    {
        if (!silent)
        {
            ConsoleWrite("CMP: NO SUCH FILE: ");
            ConsoleWriteln(argv[first + 0]);
        }
        return;
    }
    auto* b = ReadAnyFile(argv[first + 1], &b_len);
    if (b == nullptr)
    {
        duetos::mm::KFree(a);
        if (!silent)
        {
            ConsoleWrite("CMP: NO SUCH FILE: ");
            ConsoleWriteln(argv[first + 1]);
        }
        return;
    }
    const u32 n = a_len < b_len ? a_len : b_len;
    for (u32 i = 0; i < n; ++i)
    {
        if (a[i] != b[i])
        {
            if (!silent)
            {
                ConsoleWrite("CMP: ");
                ConsoleWrite(argv[first + 0]);
                ConsoleWrite(" ");
                ConsoleWrite(argv[first + 1]);
                ConsoleWrite(" differ at byte ");
                WriteU64Dec(i + 1);
                ConsoleWriteln("");
            }
            duetos::mm::KFree(a);
            duetos::mm::KFree(b);
            return;
        }
    }
    if (a_len != b_len)
    {
        if (!silent)
        {
            ConsoleWrite("CMP: ");
            ConsoleWrite(a_len < b_len ? argv[first + 0] : argv[first + 1]);
            ConsoleWrite(" is shorter (sizes ");
            WriteU64Dec(a_len);
            ConsoleWrite(" vs ");
            WriteU64Dec(b_len);
            ConsoleWriteln(")");
        }
        duetos::mm::KFree(a);
        duetos::mm::KFree(b);
        return;
    }
    if (!silent)
    {
        ConsoleWrite("CMP: files match (");
        WriteU64Dec(a_len);
        ConsoleWriteln(" bytes)");
    }
    duetos::mm::KFree(a);
    duetos::mm::KFree(b);
}

// ---------------------------------------------------------------------------
// tee — read a source file and write it BOTH to console AND to
// a destination file. v0 doesn't have pipes yet, so this isn't
// "read stdin and split"; it's more like a copy that also
// prints. Useful for "extract this download AND show me what
// it contained".
//
//   tee <src> <dst>           write src to console + dst
//   tee -a <src> <dst>        append to dst (no-op for now — same
//                             as the no-flag form; FAT32 append
//                             requires a separate API path)
// ---------------------------------------------------------------------------

void CmdTee(u32 argc, char** argv)
{
    u32 first = 1;
    bool append = false;
    if (argc >= 2 && argv[1][0] == '-' && argv[1][1] == 'a' && argv[1][2] == '\0')
    {
        append = true;
        ++first;
    }
    if (argc < first + 2)
    {
        ConsoleWriteln("TEE: usage: tee [-a] <src> <dst>");
        return;
    }
    u32 src_len = 0;
    auto* src = ReadAnyFile(argv[first + 0], &src_len);
    if (src == nullptr)
    {
        ConsoleWrite("TEE: NO SUCH FILE: ");
        ConsoleWriteln(argv[first + 0]);
        return;
    }
    // Print to console (always).
    for (u32 i = 0; i < src_len; ++i)
        ConsoleWriteChar(static_cast<char>(src[i]));
    if (src_len == 0 || src[src_len - 1] != '\n')
        ConsoleWriteChar('\n');
    // Write to dst on FAT32.
    const auto* vol = duetos::fs::fat32::Fat32Volume(0);
    if (vol == nullptr)
    {
        ConsoleWriteln("TEE: NO FAT32 VOLUME for dst");
        duetos::mm::KFree(src);
        return;
    }
    MkdirParents(vol, argv[first + 1]);
    // For v0: -a falls through to create-replace. Real FAT32
    // append-to-existing requires routing through
    // Fat32AppendInRoot, which is root-dir-only; expose that
    // properly in a follow-on once nested append lands.
    (void)append;
    const auto wrote = duetos::fs::fat32::Fat32CreateAtPath(vol, argv[first + 1], src, src_len);
    if (wrote != static_cast<duetos::i64>(src_len))
    {
        ConsoleWrite("TEE: CREATE FAIL ");
        ConsoleWriteln(argv[first + 1]);
    }
    else
    {
        ConsoleWrite("TEE: wrote ");
        WriteU64Dec(src_len);
        ConsoleWrite(" bytes to ");
        ConsoleWriteln(argv[first + 1]);
    }
    duetos::mm::KFree(src);
}

} // namespace duetos::core::shell::internal
