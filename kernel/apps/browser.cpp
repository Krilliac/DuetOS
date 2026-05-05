#include "apps/browser.h"

#include "arch/x86_64/serial.h"
#include "drivers/input/ps2kbd.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/notify.h"
#include "drivers/video/scrollbar.h"
#include "drivers/video/theme.h"
#include "fs/fat32.h"
#include "mm/kheap.h"
#include "net/socket.h"
#include "net/stack.h"
#include "sched/sched.h"

namespace duetos::apps::browser
{

namespace
{

using duetos::drivers::input::kKeyArrowDown;
using duetos::drivers::input::kKeyArrowUp;
using duetos::drivers::video::FramebufferDrawString;
using duetos::drivers::video::FramebufferFillRect;
using duetos::drivers::video::kWindowInvalid;
using duetos::drivers::video::ThemeCurrent;
using duetos::drivers::video::ThemeRole;
using duetos::drivers::video::WindowHandle;
using duetos::drivers::video::WindowSetContentDraw;

constexpr u32 kUrlCap = 256;
// Body cap covers the post-strip plain text. Sized to match the
// raw TCP receive buffer (kTcpActiveBufBytes = 64 KiB) so a fully-
// filled response still fits even if the HTML stripper happens
// to be a no-op (worst case: server sent already-plaintext bytes).
constexpr u32 kBodyCap = net::kTcpActiveBufBytes + 256;
constexpr u32 kStatusCap = 96;
constexpr u32 kHistoryCap = 32;
constexpr u32 kBookmarkCap = 32;
constexpr u32 kRowH = 10;
constexpr const char kBookmarkPath[] = "BOOKMARK.TXT";

enum class Mode : u8
{
    View = 0,
    UrlEdit = 1,
    History = 2,
    Bookmarks = 3,
};

struct State
{
    WindowHandle handle;
    Mode mode;

    // URL bar — visible in every mode; in UrlEdit it's the live
    // edit target.
    char url[kUrlCap];
    u32 url_len;

    // Loaded body (HTML-stripped plain text). Wraps lines on
    // paint; no pre-wrapped layout to keep the painter simple.
    char body[kBodyCap];
    u32 body_len;
    bool truncated; // true when the response filled the TCP buffer

    // Last status line (errors / progress / "OK 200").
    char status[kStatusCap];
    u32 status_code; // last HTTP status if known

    // Vertical scroll offset (in wrapped rows). Reset to 0 on a
    // successful fetch.
    u32 scroll_row;

    // History — circular buffer of visited URLs. `idx` points
    // past the most-recent entry; back/forward decrement/increment
    // through `count` entries until either end. Push truncates any
    // forward history (Chrome / Firefox semantics).
    char history[kHistoryCap][kUrlCap];
    u32 history_count;
    u32 history_idx; // current position; 0..history_count

    // Bookmarks — persisted on FAT32 root.
    char bookmarks[kBookmarkCap][kUrlCap];
    u32 bookmark_count;

    // Selection within the active modal list (History or Bookmarks).
    u32 list_selection;

    // Fetch worker handshake. The input thread sets `fetch_url`
    // and `fetch_pending=true`; the worker swaps it to in_flight,
    // runs, then clears the in_flight flag. DrawFn checks
    // `fetch_in_flight` to decide what to paint.
    char fetch_url[kUrlCap];
    volatile bool fetch_in_flight;
};

constinit State g_state = {};

// Forward declarations.
void DoFetch(const char* url);
void RescanBookmarks();
void SaveBookmarks();
bool TryParseDottedQuad(const char* host, net::Ipv4Address* out);

// ---------------------------------------------------------------
// String helpers — kept self-contained so the browser doesn't
// need a dependency on whatever string library evolves.
// ---------------------------------------------------------------

u32 StrLen(const char* s)
{
    u32 n = 0;
    while (s[n] != '\0')
        ++n;
    return n;
}

bool StrEqI(const char* a, const char* b)
{
    auto up = [](char c) { return (c >= 'a' && c <= 'z') ? static_cast<char>(c - ('a' - 'A')) : c; };
    while (*a != '\0' && *b != '\0')
    {
        if (up(*a) != up(*b))
            return false;
        ++a;
        ++b;
    }
    return *a == '\0' && *b == '\0';
}

void StrCopyCap(char* dst, u32 cap, const char* src)
{
    u32 i = 0;
    for (; i + 1 < cap && src[i] != '\0'; ++i)
        dst[i] = src[i];
    dst[i] = '\0';
}

void StrAppend(char* dst, u32 cap, const char* src)
{
    u32 len = StrLen(dst);
    for (u32 i = 0; src[i] != '\0' && len + 1 < cap; ++i)
    {
        dst[len++] = src[i];
    }
    dst[len] = '\0';
}

void StatusSet(const char* msg)
{
    StrCopyCap(g_state.status, kStatusCap, msg);
}

// ---------------------------------------------------------------
// URL parsing.
//
// Supported forms:
//   scheme://host[:port][/path]
//   host[:port][/path]            (scheme defaulted to http)
//
// Output:
//   `scheme_https`: true if scheme is "https" (rejected by fetch)
//   `host`:        zero-terminated, lower-case-tolerant
//   `port`:        80 default, parsed otherwise
//   `path`:        starts with '/'; defaults to "/"
// ---------------------------------------------------------------

struct ParsedUrl
{
    bool ok;
    bool scheme_https;
    char host[128];
    u16 port;
    char path[160];
};

ParsedUrl ParseUrl(const char* url)
{
    ParsedUrl out{};
    if (url == nullptr || url[0] == '\0')
        return out;

    const char* p = url;
    // Skip whitespace.
    while (*p == ' ' || *p == '\t')
        ++p;

    // Scheme detection. Tolerant: accept either "http://" or
    // "https://"; if neither, assume http.
    if (StrLen(p) >= 7 && p[0] == 'h' && p[1] == 't' && p[2] == 't' && p[3] == 'p' && p[4] == ':' && p[5] == '/' &&
        p[6] == '/')
    {
        p += 7;
    }
    else if (StrLen(p) >= 8 && p[0] == 'h' && p[1] == 't' && p[2] == 't' && p[3] == 'p' && p[4] == 's' && p[5] == ':' &&
             p[6] == '/' && p[7] == '/')
    {
        out.scheme_https = true;
        p += 8;
    }
    // else: bare "host[:port]/path" — keep p where it is.

    // Host (and optional :port). Stop at '/' or end-of-string.
    u32 hi = 0;
    while (*p != '\0' && *p != '/' && hi + 1 < sizeof(out.host))
    {
        out.host[hi++] = *p++;
    }
    out.host[hi] = '\0';
    // Trim and parse :port.
    out.port = 80;
    for (u32 i = 0; i < hi; ++i)
    {
        if (out.host[i] == ':')
        {
            out.host[i] = '\0';
            u32 port = 0;
            for (u32 j = i + 1; j < hi; ++j)
            {
                const char c = out.host[j];
                if (c < '0' || c > '9')
                {
                    return out;
                }
                port = port * 10 + static_cast<u32>(c - '0');
            }
            if (port == 0 || port > 0xFFFFu)
            {
                return out;
            }
            out.port = static_cast<u16>(port);
            break;
        }
    }
    if (out.host[0] == '\0')
        return out;

    // Path. Default "/". Skip past any '?' fragment until end so
    // the request line is well-formed (the kernel TCP buffer
    // doesn't care, but echo of the URL stays clean).
    if (*p == '\0')
    {
        out.path[0] = '/';
        out.path[1] = '\0';
    }
    else
    {
        u32 pi = 0;
        while (*p != '\0' && pi + 1 < sizeof(out.path))
        {
            out.path[pi++] = *p++;
        }
        out.path[pi] = '\0';
    }

    out.ok = true;
    return out;
}

// IPv4 dotted-quad detector. Used to skip DNS when the host is a
// raw address.
bool TryParseDottedQuad(const char* host, net::Ipv4Address* out)
{
    u32 octets[4] = {0, 0, 0, 0};
    u32 oi = 0;
    bool any_digit = false;
    for (u32 i = 0; host[i] != '\0'; ++i)
    {
        const char c = host[i];
        if (c >= '0' && c <= '9')
        {
            octets[oi] = octets[oi] * 10 + static_cast<u32>(c - '0');
            if (octets[oi] > 255)
                return false;
            any_digit = true;
        }
        else if (c == '.')
        {
            if (!any_digit)
                return false;
            ++oi;
            if (oi >= 4)
                return false;
            any_digit = false;
        }
        else
        {
            return false;
        }
    }
    if (oi != 3 || !any_digit)
        return false;
    for (u32 i = 0; i < 4; ++i)
        out->octets[i] = static_cast<u8>(octets[i]);
    return true;
}

// ---------------------------------------------------------------
// HTML stripping.
//
// Walk the input, drop tag content (<...>), decode known entities,
// and emit a newline at every block-level close. The output is a
// plaintext stream the painter line-wraps on the fly.
// ---------------------------------------------------------------

// Block-level open/close tags whose presence implies a paragraph
// break. Compared case-insensitively against the first 16 bytes
// of the tag content (between '<' and '>').
constexpr const char* kBlockTags[] = {
    "/p", "/div", "/li", "/tr", "/h1", "/h2", "/h3", "/h4", "/h5", "/h6", "br",  "br/", "p",   "tr",    "li",     "h1",
    "h2", "h3",   "h4",  "h5",  "h6",  "/td", "/dl", "/dt", "/dd", "ul",  "/ul", "ol",  "/ol", "table", "/table",
};

bool TagIsBlock(const char* tag_inner)
{
    for (auto* t : kBlockTags)
    {
        // Case-insensitive prefix compare against the first
        // alphabetic-or-slash run; ignore trailing attributes.
        u32 i = 0;
        auto up = [](char c) { return (c >= 'a' && c <= 'z') ? static_cast<char>(c - ('a' - 'A')) : c; };
        for (; t[i] != '\0' && tag_inner[i] != '\0'; ++i)
        {
            if (up(tag_inner[i]) != up(t[i]))
                break;
        }
        if (t[i] == '\0')
        {
            const char nxt = tag_inner[i];
            if (nxt == '\0' || nxt == ' ' || nxt == '\t' || nxt == '/' || nxt == '>')
                return true;
        }
    }
    return false;
}

void EmitChar(char* out, u32 cap, u32* len, char c)
{
    if (*len + 1 >= cap)
        return;
    out[(*len)++] = c;
    out[*len] = '\0';
}

// Common HTML entities. v0 covers the cases real pages use most;
// numeric entities (&#NN;) decode in-band by reading the digits.
struct EntityRow
{
    const char* name;
    char repl;
};
constexpr EntityRow kEntities[] = {
    {"amp", '&'}, {"lt", '<'}, {"gt", '>'}, {"quot", '"'}, {"apos", '\''}, {"nbsp", ' '}, {"copy", 'C'}, {"reg", 'R'},
};

bool DecodeEntity(const char*& p, char* out, u32 cap, u32* len)
{
    // Caller has already consumed '&'. Read until ';' or 8 chars.
    char name[10];
    u32 n = 0;
    while (*p != '\0' && *p != ';' && n + 1 < sizeof(name))
    {
        name[n++] = *p++;
    }
    name[n] = '\0';
    if (*p == ';')
        ++p;
    if (n == 0)
        return false;

    if (name[0] == '#' && n >= 2)
    {
        u32 v = 0;
        const u32 base = (name[1] == 'x' || name[1] == 'X') ? 16 : 10;
        const u32 start = (base == 16) ? 2 : 1;
        for (u32 i = start; i < n; ++i)
        {
            const char c = name[i];
            u32 d;
            if (c >= '0' && c <= '9')
                d = static_cast<u32>(c - '0');
            else if (base == 16 && c >= 'a' && c <= 'f')
                d = static_cast<u32>(c - 'a' + 10);
            else if (base == 16 && c >= 'A' && c <= 'F')
                d = static_cast<u32>(c - 'A' + 10);
            else
                return false;
            v = v * base + d;
        }
        EmitChar(out, cap, len, (v >= 0x20 && v < 0x7F) ? static_cast<char>(v) : '?');
        return true;
    }
    for (auto& e : kEntities)
    {
        if (StrEqI(name, e.name))
        {
            EmitChar(out, cap, len, e.repl);
            return true;
        }
    }
    return false;
}

void StripHtml(const u8* src, u32 src_len, char* dst, u32 dst_cap, u32* dst_len)
{
    *dst_len = 0;
    bool in_tag = false;
    bool in_script = false;
    char tag_buf[20];
    u32 tag_n = 0;
    bool prev_blank = true; // collapse leading whitespace
    for (u32 i = 0; i < src_len && *dst_len + 1 < dst_cap; ++i)
    {
        const char c = static_cast<char>(src[i]);
        if (in_script)
        {
            // Skip everything until "</script". Cheap: look for
            // "</s" followed by "cript" anywhere.
            if (c == '<' && i + 8 < src_len && src[i + 1] == '/' && (src[i + 2] == 's' || src[i + 2] == 'S') &&
                (src[i + 3] == 'c' || src[i + 3] == 'C') && (src[i + 4] == 'r' || src[i + 4] == 'R') &&
                (src[i + 5] == 'i' || src[i + 5] == 'I') && (src[i + 6] == 'p' || src[i + 6] == 'P') &&
                (src[i + 7] == 't' || src[i + 7] == 'T'))
            {
                in_script = false;
                in_tag = true;
                tag_n = 0;
            }
            continue;
        }
        if (in_tag)
        {
            if (c == '>')
            {
                in_tag = false;
                tag_buf[tag_n] = '\0';
                if (TagIsBlock(tag_buf))
                {
                    if (!prev_blank)
                    {
                        EmitChar(dst, dst_cap, dst_len, '\n');
                        prev_blank = true;
                    }
                }
                // Detect <script ...> openers — the tag-content
                // starts with "script" (or "SCRIPT").
                if ((tag_buf[0] == 's' || tag_buf[0] == 'S') && (tag_buf[1] == 'c' || tag_buf[1] == 'C') &&
                    (tag_buf[2] == 'r' || tag_buf[2] == 'R') && (tag_buf[3] == 'i' || tag_buf[3] == 'I') &&
                    (tag_buf[4] == 'p' || tag_buf[4] == 'P') && (tag_buf[5] == 't' || tag_buf[5] == 'T') &&
                    (tag_buf[6] == ' ' || tag_buf[6] == '>' || tag_buf[6] == '\0' || tag_buf[6] == '\t'))
                {
                    in_script = true;
                }
                tag_n = 0;
            }
            else if (tag_n + 1 < sizeof(tag_buf))
            {
                tag_buf[tag_n++] = c;
            }
            continue;
        }
        if (c == '<')
        {
            in_tag = true;
            tag_n = 0;
            continue;
        }
        if (c == '&')
        {
            const char* p = reinterpret_cast<const char*>(src + i + 1);
            const char* before = p;
            if (DecodeEntity(p, dst, dst_cap, dst_len))
            {
                i += static_cast<u32>(p - before);
                prev_blank = false;
                continue;
            }
            // Fall through — emit the raw '&'.
        }
        // Whitespace collapse: convert tabs/CR to space, skip
        // runs of whitespace.
        const bool is_space = (c == ' ' || c == '\t' || c == '\r' || c == '\n');
        if (is_space)
        {
            if (!prev_blank)
            {
                EmitChar(dst, dst_cap, dst_len, ' ');
                prev_blank = true;
            }
        }
        else
        {
            EmitChar(dst, dst_cap, dst_len, c);
            prev_blank = false;
        }
    }
}

// ---------------------------------------------------------------
// History.
// ---------------------------------------------------------------

void HistoryPush(const char* url)
{
    // Truncate any forward history — Chrome / Firefox semantics.
    if (g_state.history_idx < g_state.history_count)
    {
        g_state.history_count = g_state.history_idx;
    }
    if (g_state.history_count >= kHistoryCap)
    {
        // Shift down by one — drop the oldest.
        for (u32 i = 1; i < kHistoryCap; ++i)
        {
            for (u32 j = 0; j < kUrlCap; ++j)
                g_state.history[i - 1][j] = g_state.history[i][j];
        }
        --g_state.history_count;
        if (g_state.history_idx > 0)
            --g_state.history_idx;
    }
    StrCopyCap(g_state.history[g_state.history_count], kUrlCap, url);
    ++g_state.history_count;
    g_state.history_idx = g_state.history_count;
}

// ---------------------------------------------------------------
// Bookmarks load / save.
// ---------------------------------------------------------------

void RescanBookmarks()
{
    namespace fat = fs::fat32;
    g_state.bookmark_count = 0;
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
        return;
    fat::DirEntry e;
    if (!fat::Fat32LookupPath(v, kBookmarkPath, &e))
        return;
    if ((e.attributes & 0x10) != 0)
        return;
    // 32 bookmarks * 256 bytes = ~8 KiB — heap-allocate to keep
    // the kernel stack small. Cap reads to whatever the live
    // bookmark roster could possibly need plus slack for stray
    // newlines / comments.
    constexpr u64 kBufBytes = static_cast<u64>(kBookmarkCap) * (kUrlCap + 4);
    char* tmp = static_cast<char*>(mm::KMalloc(kBufBytes));
    if (tmp == nullptr)
        return;
    const u64 cap = (e.size_bytes < kBufBytes) ? e.size_bytes : kBufBytes;
    const i64 n = fat::Fat32ReadFile(v, &e, tmp, cap);
    if (n <= 0)
    {
        mm::KFree(tmp);
        return;
    }
    u32 line_start = 0;
    for (u32 i = 0; i < static_cast<u32>(n) && g_state.bookmark_count < kBookmarkCap; ++i)
    {
        if (tmp[i] == '\n' || i == static_cast<u32>(n) - 1)
        {
            const u32 end = (tmp[i] == '\n') ? i : i + 1;
            const u32 len = end - line_start;
            if (len > 0 && len + 1 < kUrlCap)
            {
                u32 j = 0;
                for (; j < len; ++j)
                {
                    g_state.bookmarks[g_state.bookmark_count][j] = tmp[line_start + j];
                }
                g_state.bookmarks[g_state.bookmark_count][j] = '\0';
                if (g_state.bookmarks[g_state.bookmark_count][0] != '\0' &&
                    g_state.bookmarks[g_state.bookmark_count][0] != '#')
                {
                    ++g_state.bookmark_count;
                }
            }
            line_start = i + 1;
        }
    }
    mm::KFree(tmp);
}

void SaveBookmarks()
{
    namespace fat = fs::fat32;
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
        return;
    // 32 * 260 = ~8 KiB — heap-allocate so the kernel stack
    // (which is intentionally small) doesn't carry it.
    constexpr u64 kBufBytes = static_cast<u64>(kBookmarkCap) * (kUrlCap + 4);
    char* buf = static_cast<char*>(mm::KMalloc(kBufBytes));
    if (buf == nullptr)
        return;
    u32 off = 0;
    for (u32 i = 0; i < g_state.bookmark_count; ++i)
    {
        const char* u = g_state.bookmarks[i];
        for (u32 j = 0; u[j] != '\0' && off + 1 < kBufBytes; ++j)
        {
            buf[off++] = u[j];
        }
        if (off + 1 < kBufBytes)
            buf[off++] = '\n';
    }
    fat::DirEntry probe;
    if (fat::Fat32LookupPath(v, kBookmarkPath, &probe))
    {
        fat::Fat32DeleteAtPath(v, kBookmarkPath);
    }
    fat::Fat32CreateAtPath(v, kBookmarkPath, buf, off);
    mm::KFree(buf);
}

bool BookmarkContains(const char* url)
{
    for (u32 i = 0; i < g_state.bookmark_count; ++i)
    {
        if (StrEqI(g_state.bookmarks[i], url))
            return true;
    }
    return false;
}

// ---------------------------------------------------------------
// Download.
// ---------------------------------------------------------------

u32 NextDownloadIndex(const fs::fat32::Volume* v)
{
    namespace fat = fs::fat32;
    fat::DirEntry tmp[fat::kMaxDirEntries];
    const u32 n = fat::Fat32ListDirByCluster(v, v->root_cluster, tmp, fat::kMaxDirEntries);
    u32 max_idx = 0;
    for (u32 i = 0; i < n; ++i)
    {
        const char* nm = tmp[i].name;
        if (!(nm[0] == 'D' && nm[1] == 'L'))
            continue;
        u32 num = 0;
        bool digits_ok = true;
        for (u32 d = 2; d < 6; ++d)
        {
            const char c = nm[d];
            if (c < '0' || c > '9')
            {
                digits_ok = false;
                break;
            }
            num = num * 10 + static_cast<u32>(c - '0');
        }
        if (!digits_ok)
            continue;
        if (nm[6] != '.')
            continue;
        if (num > max_idx)
            max_idx = num;
    }
    return (max_idx + 1 > 9999) ? 0 : (max_idx + 1);
}

void SaveDownload()
{
    namespace fat = fs::fat32;
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
    {
        StatusSet("save: no FAT32 volume");
        return;
    }
    if (g_state.body_len == 0)
    {
        StatusSet("save: no content to save");
        return;
    }
    const u32 idx = NextDownloadIndex(v);
    if (idx == 0)
    {
        StatusSet("save: counter exhausted (>9999)");
        return;
    }
    char path[16];
    path[0] = 'D';
    path[1] = 'L';
    path[2] = static_cast<char>('0' + (idx / 1000) % 10);
    path[3] = static_cast<char>('0' + (idx / 100) % 10);
    path[4] = static_cast<char>('0' + (idx / 10) % 10);
    path[5] = static_cast<char>('0' + idx % 10);
    path[6] = '.';
    path[7] = 'H';
    path[8] = 'T';
    path[9] = 'M';
    path[10] = '\0';
    const i64 rc = fat::Fat32CreateAtPath(v, path, g_state.body, g_state.body_len);
    if (rc < 0)
    {
        StatusSet("save: write failed");
    }
    else
    {
        StatusSet("saved: ");
        StrAppend(g_state.status, kStatusCap, path);
    }
}

// ---------------------------------------------------------------
// Fetch worker.
// ---------------------------------------------------------------

bool ResolveHost(const char* host, net::Ipv4Address* out)
{
    if (TryParseDottedQuad(host, out))
        return true;
    const auto lease = net::DhcpLeaseRead();
    if (!lease.valid)
        return false;
    if (!net::NetDnsQueryA(0, lease.dns, host))
        return false;
    // Poll 5 seconds.
    for (u32 i = 0; i < 500; ++i)
    {
        sched::SchedSleepTicks(1);
        const auto r = net::NetDnsResultRead();
        if (r.resolved)
        {
            *out = r.ip;
            return true;
        }
    }
    return false;
}

void FetchWorker(void* arg_v)
{
    const char* url = static_cast<const char*>(arg_v);
    DoFetch(url);
    g_state.fetch_in_flight = false;
    sched::SchedExit();
}

void DoFetch(const char* url)
{
    g_state.body_len = 0;
    g_state.body[0] = '\0';
    g_state.truncated = false;
    g_state.scroll_row = 0;
    g_state.status_code = 0;

    const auto p = ParseUrl(url);
    if (!p.ok)
    {
        StatusSet("bad URL");
        return;
    }
    if (p.scheme_https)
    {
        StatusSet("HTTPS not supported (no TLS in v0)");
        return;
    }

    StatusSet("resolving ");
    StrAppend(g_state.status, kStatusCap, p.host);

    net::Ipv4Address ip;
    if (!ResolveHost(p.host, &ip))
    {
        StatusSet("DNS resolve failed: ");
        StrAppend(g_state.status, kStatusCap, p.host);
        return;
    }

    StatusSet("connecting...");

    // Hand-built minimal HTTP/1.0 GET. Avoid HTTP/1.1 — keep-alive
    // / chunked / Transfer-Encoding aren't worth the bytes here.
    char request[512];
    u32 off = 0;
    const char* parts[] = {"GET ", p.path, " HTTP/1.0\r\nHost: ", p.host,
                           "\r\nUser-Agent: DuetOS-Browser/0.1\r\nAccept: text/html,*/*\r\nConnection: close\r\n\r\n"};
    for (const char* part : parts)
    {
        for (u32 i = 0; part[i] != '\0' && off + 1 < sizeof(request); ++i)
            request[off++] = part[i];
    }

    if (!net::NetTcpConnect(0, ip, p.port, reinterpret_cast<const u8*>(request), off))
    {
        StatusSet("TCP connect rejected (slot busy / ARP miss)");
        return;
    }

    StatusSet("fetching...");

    // Wait up to 10 seconds for the response to complete.
    for (u32 i = 0; i < 1000; ++i)
    {
        sched::SchedSleepTicks(1);
        const auto snap = net::NetTcpActiveSnapshot();
        if (snap.response_complete)
            break;
        // Bail early when buffer is full — we can't grow the
        // 2 KB slot, so further waiting won't add bytes.
        if (snap.response_len >= net::kTcpActiveBufBytes)
        {
            g_state.truncated = true;
            break;
        }
    }

    // 64 KiB scratch — too large for the kernel stack, so heap-
    // allocate. Freed before this function returns; on the
    // failure paths below the same Free runs in the cleanup tail.
    u8* raw = static_cast<u8*>(mm::KMalloc(net::kTcpActiveBufBytes));
    if (raw == nullptr)
    {
        StatusSet("OOM (heap exhausted)");
        return;
    }
    const u32 got = net::NetTcpActiveRead(raw, net::kTcpActiveBufBytes);
    if (got == 0)
    {
        mm::KFree(raw);
        StatusSet("no response (timeout)");
        return;
    }

    // Parse the HTTP status line + skip headers.
    u32 i = 0;
    if (got >= 12 && raw[0] == 'H' && raw[1] == 'T' && raw[2] == 'T' && raw[3] == 'P')
    {
        u32 code = 0;
        for (u32 j = 9; j < 12 && j < got; ++j)
        {
            if (raw[j] >= '0' && raw[j] <= '9')
                code = code * 10 + static_cast<u32>(raw[j] - '0');
        }
        g_state.status_code = code;
    }
    while (i + 3 < got)
    {
        if (raw[i] == '\r' && raw[i + 1] == '\n' && raw[i + 2] == '\r' && raw[i + 3] == '\n')
        {
            i += 4;
            break;
        }
        ++i;
    }
    if (i >= got)
    {
        // Headers ran past the end of the buffer — body got
        // truncated. Still strip whatever HTML preceded the cut.
        i = 0;
    }

    StripHtml(raw + i, got - i, g_state.body, kBodyCap, &g_state.body_len);
    mm::KFree(raw);

    char status_buf[kStatusCap];
    u32 sp = 0;
    auto append = [&](const char* s)
    {
        for (u32 k = 0; s[k] != '\0' && sp + 1 < sizeof(status_buf); ++k)
            status_buf[sp++] = s[k];
        status_buf[sp] = '\0';
    };
    append("HTTP ");
    {
        u32 c = g_state.status_code;
        if (c == 0)
        {
            append("(no code)");
        }
        else
        {
            char d[6];
            u32 dn = 0;
            while (c > 0 && dn < sizeof(d))
            {
                d[dn++] = static_cast<char>('0' + c % 10);
                c /= 10;
            }
            while (dn > 0)
                status_buf[sp++] = d[--dn];
            status_buf[sp] = '\0';
        }
    }
    if (g_state.truncated)
        append(" (truncated to 64 KiB)");
    StatusSet(status_buf);

    // Add to history if this was a fresh navigation (not a
    // back/forward replay — those reuse the slot in-place).
    HistoryPush(url);
}

// ---------------------------------------------------------------
// UI / paint.
// ---------------------------------------------------------------

void DrawHeader(u32 cx, u32 cy, u32 /*cw*/, u32 fg, u32 dim, u32 bg)
{
    // URL bar — always visible, single line.
    char bar[kUrlCap + 8];
    u32 bp = 0;
    bar[bp++] = (g_state.mode == Mode::UrlEdit) ? '>' : ' ';
    bar[bp++] = ' ';
    for (u32 i = 0; i < g_state.url_len && bp + 1 < sizeof(bar); ++i)
        bar[bp++] = g_state.url[i];
    if (g_state.mode == Mode::UrlEdit && bp + 1 < sizeof(bar))
        bar[bp++] = '_'; // crude cursor
    bar[bp] = '\0';
    FramebufferDrawString(cx + 4, cy + 4, bar, fg, bg);

    // Status line.
    FramebufferDrawString(cx + 4, cy + 4 + kRowH, g_state.status, dim, bg);
}

void DrawBody(u32 cx, u32 cy, u32 cw, u32 ch, u32 fg, u32 bg)
{
    // Reserve URL bar + status row at the top + footer at bottom.
    const u32 top_reserved = 4 + kRowH + kRowH + 2;
    const u32 bot_reserved = kRowH + 2;
    if (ch < top_reserved + bot_reserved)
        return;
    const u32 view_h = ch - top_reserved - bot_reserved;
    const u32 chars_per_row = (cw > 12) ? (cw - 8) / 8 : 1;
    const u32 rows_visible = view_h / kRowH;

    // Wrap body on the fly. Maintain a row counter so we can skip
    // ahead by `scroll_row` and stop after `rows_visible` rows.
    u32 row = 0;
    u32 col = 0;
    char line[200];
    u32 line_n = 0;

    auto flush_line = [&]()
    {
        line[line_n] = '\0';
        if (row >= g_state.scroll_row && row < g_state.scroll_row + rows_visible)
        {
            const u32 y = cy + top_reserved + (row - g_state.scroll_row) * kRowH;
            FramebufferDrawString(cx + 4, y, line, fg, bg);
        }
        ++row;
        line_n = 0;
        col = 0;
    };

    for (u32 i = 0; i < g_state.body_len; ++i)
    {
        const char c = g_state.body[i];
        if (c == '\n')
        {
            flush_line();
            continue;
        }
        if (col >= chars_per_row)
        {
            flush_line();
        }
        if (line_n + 1 < sizeof(line))
        {
            line[line_n++] = c;
        }
        ++col;
        // Don't break early — keep counting rows past the
        // visible range so the scrollbar's "total" reflects the
        // full body. The flush_line bounds-check above already
        // prevents writes outside the visible window.
    }
    if (line_n > 0)
        flush_line();
    // Scrollbar at the right edge of the body view. `total` is
    // the final row count; `visible` is rows_visible; `first`
    // is scroll_row.
    if (rows_visible > 0 && cw > duetos::drivers::video::kScrollbarWidth)
    {
        duetos::drivers::video::ScrollbarPaint(cx + cw - duetos::drivers::video::kScrollbarWidth, cy + top_reserved,
                                               duetos::drivers::video::kScrollbarWidth, rows_visible * kRowH,
                                               {row, rows_visible, g_state.scroll_row});
    }
}

void DrawList(u32 cx, u32 cy, u32 cw, u32 ch, const char* title, char list[][kUrlCap], u32 count, u32 fg, u32 dim,
              u32 bg)
{
    FramebufferDrawString(cx + 4, cy + 4, title, fg, bg);
    if (count == 0)
    {
        FramebufferDrawString(cx + 4, cy + 4 + kRowH * 2, "(empty)", dim, bg);
        return;
    }
    const u32 top = cy + 4 + kRowH * 2;
    const u32 max_rows = (ch > (top - cy) + kRowH) ? (ch - (top - cy)) / kRowH : 0;
    u32 first = 0;
    if (count > max_rows && g_state.list_selection >= max_rows)
        first = g_state.list_selection - (max_rows - 1);
    for (u32 i = 0; i < max_rows && first + i < count; ++i)
    {
        const u32 idx = first + i;
        const u32 y = top + i * kRowH;
        if (idx == g_state.list_selection)
        {
            FramebufferFillRect(cx, y, cw, kRowH, 0x00C0C888);
            FramebufferDrawString(cx + 4, y + 1, list[idx], 0x00101020, 0x00C0C888);
        }
        else
        {
            FramebufferDrawString(cx + 4, y + 1, list[idx], fg, bg);
        }
    }
}

void DrawFn(u32 cx, u32 cy, u32 cw, u32 ch, void* /*cookie*/)
{
    const auto& th = ThemeCurrent();
    const u32 bg = th.role_client[static_cast<u32>(ThemeRole::Browser)];
    const u32 fg = th.console_fg;
    const u32 dim = th.banner_fg;
    FramebufferFillRect(cx, cy, cw, ch, bg);

    DrawHeader(cx, cy, cw, fg, dim, bg);

    if (g_state.fetch_in_flight)
    {
        FramebufferDrawString(cx + 4, cy + 4 + kRowH * 3, "Fetching... please wait.", dim, bg);
    }
    else if (g_state.mode == Mode::History)
    {
        DrawList(cx, cy + kRowH * 2 + 4, cw, ch - kRowH * 2 - 4, "HISTORY (Enter:load Esc:back):", g_state.history,
                 g_state.history_count, fg, dim, bg);
    }
    else if (g_state.mode == Mode::Bookmarks)
    {
        DrawList(cx, cy + kRowH * 2 + 4, cw, ch - kRowH * 2 - 4,
                 "BOOKMARKS (Enter:load X:remove Esc:back):", g_state.bookmarks, g_state.bookmark_count, fg, dim, bg);
    }
    else
    {
        DrawBody(cx, cy, cw, ch, fg, bg);
    }

    // Footer hint.
    if (ch > kRowH + 2)
    {
        const char* hint = "U:URL  B:BACK  F:FWD  R:RELOAD  H:HIST  L:BMARK  M:MARK  S:SAVE  J/K:SCROLL";
        FramebufferDrawString(cx + 4, cy + ch - kRowH - 1, hint, dim, bg);
    }
}

void StartFetch(const char* url)
{
    if (g_state.fetch_in_flight)
        return;
    StrCopyCap(g_state.fetch_url, kUrlCap, url);
    g_state.fetch_in_flight = true;
    sched::SchedCreate(FetchWorker, g_state.fetch_url, "browser-fetch");
}

void Reload()
{
    if (g_state.history_idx == 0)
        return;
    char tmp[kUrlCap];
    StrCopyCap(tmp, kUrlCap, g_state.history[g_state.history_idx - 1]);
    // Pop the duplicate that DoFetch will push, by setting idx
    // back so HistoryPush replaces the slot.
    --g_state.history_idx;
    g_state.history_count = g_state.history_idx;
    StartFetch(tmp);
}

void NavigateBackForward(bool forward)
{
    if (forward)
    {
        if (g_state.history_idx >= g_state.history_count)
            return;
        const char* u = g_state.history[g_state.history_idx];
        char tmp[kUrlCap];
        StrCopyCap(tmp, kUrlCap, u);
        // Pop the slot that DoFetch will push so we don't duplicate.
        g_state.history_count = g_state.history_idx;
        StartFetch(tmp);
    }
    else
    {
        if (g_state.history_idx < 2)
        {
            StatusSet("at start of history");
            return;
        }
        const char* u = g_state.history[g_state.history_idx - 2];
        char tmp[kUrlCap];
        StrCopyCap(tmp, kUrlCap, u);
        g_state.history_idx -= 2;
        g_state.history_count = g_state.history_idx;
        StartFetch(tmp);
    }
}

void BookmarkCurrent()
{
    if (g_state.url_len == 0)
    {
        StatusSet("no URL to bookmark");
        return;
    }
    if (g_state.bookmark_count >= kBookmarkCap)
    {
        StatusSet("bookmarks full (16)");
        return;
    }
    if (BookmarkContains(g_state.url))
    {
        StatusSet("already bookmarked");
        return;
    }
    StrCopyCap(g_state.bookmarks[g_state.bookmark_count], kUrlCap, g_state.url);
    ++g_state.bookmark_count;
    SaveBookmarks();
    StatusSet("bookmarked");
}

void BookmarkRemoveSelected()
{
    if (g_state.list_selection >= g_state.bookmark_count)
        return;
    for (u32 i = g_state.list_selection + 1; i < g_state.bookmark_count; ++i)
    {
        for (u32 j = 0; j < kUrlCap; ++j)
            g_state.bookmarks[i - 1][j] = g_state.bookmarks[i][j];
    }
    --g_state.bookmark_count;
    if (g_state.list_selection >= g_state.bookmark_count && g_state.list_selection > 0)
        --g_state.list_selection;
    SaveBookmarks();
}

void EnterUrlEdit()
{
    g_state.mode = Mode::UrlEdit;
}

void HandleUrlEditChar(char c)
{
    const u8 uc = static_cast<u8>(c);
    if (uc == 0x0A) // Enter
    {
        StrCopyCap(g_state.url, kUrlCap, g_state.url); // no-op, just clarity
        g_state.mode = Mode::View;
        StartFetch(g_state.url);
        return;
    }
    if (uc == 0x1B) // Esc
    {
        g_state.mode = Mode::View;
        return;
    }
    if (uc == 0x08) // Backspace
    {
        if (g_state.url_len > 0)
        {
            --g_state.url_len;
            g_state.url[g_state.url_len] = '\0';
        }
        return;
    }
    if (uc >= 0x20 && uc <= 0x7E && g_state.url_len + 1 < kUrlCap)
    {
        g_state.url[g_state.url_len++] = c;
        g_state.url[g_state.url_len] = '\0';
    }
}

} // namespace

void BrowserInit(WindowHandle handle)
{
    g_state.handle = handle;
    g_state.mode = Mode::View;
    g_state.url[0] = '\0';
    g_state.url_len = 0;
    g_state.body[0] = '\0';
    g_state.body_len = 0;
    g_state.status[0] = '\0';
    g_state.status_code = 0;
    g_state.scroll_row = 0;
    g_state.history_count = 0;
    g_state.history_idx = 0;
    g_state.bookmark_count = 0;
    g_state.list_selection = 0;
    g_state.fetch_in_flight = false;
    StatusSet("Press U for URL bar.  HTTP only (no HTTPS).");
    WindowSetContentDraw(handle, DrawFn, nullptr);
    duetos::drivers::video::WindowSetWheelHandler(handle, BrowserOnWheel);
}

void BrowserOnWheel(duetos::i32 dz)
{
    if (dz == 0)
        return;
    // Wheel-up (dz > 0) maps to "scroll content up" which means
    // ARROW UP in our viewport (smaller scroll_row).
    const u16 key = (dz > 0) ? kKeyArrowUp : kKeyArrowDown;
    const duetos::i32 steps = (dz > 0) ? dz : -dz;
    for (duetos::i32 i = 0; i < steps; ++i)
    {
        BrowserFeedArrow(key);
    }
}

void BrowserFocusUrl()
{
    EnterUrlEdit();
}

void BrowserNavBack()
{
    NavigateBackForward(false);
}

void BrowserNavForward()
{
    NavigateBackForward(true);
}

bool BrowserOnDoubleClick(duetos::u32 sx, duetos::u32 sy)
{
    // Only meaningful in Bookmarks mode — DC follows the hit row.
    // History mode could mirror this but isn't on the v1 critical
    // path (less common navigation pattern).
    if (g_state.mode != Mode::Bookmarks || g_state.bookmark_count == 0)
        return false;
    duetos::u32 wx = 0, wy = 0, ww = 0, wh = 0;
    if (!duetos::drivers::video::WindowGetBounds(g_state.handle, &wx, &wy, &ww, &wh))
        return false;
    // Mirror the geometry from DrawFn → DrawList. Client area
    // starts 22 px below the window origin (title bar) + 2 px
    // border. DrawList is invoked at (cy + kRowH * 2 + 4); inside
    // it the list rows start at top = cy_inner + 4 + kRowH * 2.
    constexpr u32 kTitle = 22;
    constexpr u32 kBorder = 2;
    const u32 client_y = wy + kTitle + kBorder;
    const u32 list_y0 = client_y + kRowH * 2 + 4 + 4 + kRowH * 2;
    if (sy < list_y0)
        return false;
    const u32 row = (sy - list_y0) / kRowH;
    // Re-derive `first` the same way DrawList does so the hit row
    // matches what's painted.
    const u32 max_rows_h = (wh > kTitle + kBorder * 2 + kRowH) ? (wh - kTitle - kBorder * 2) / kRowH : 0;
    u32 first = 0;
    if (g_state.bookmark_count > max_rows_h && g_state.list_selection >= max_rows_h)
        first = g_state.list_selection - (max_rows_h - 1);
    const u32 idx = first + row;
    if (idx >= g_state.bookmark_count)
        return false;
    char tmp[kUrlCap];
    StrCopyCap(tmp, kUrlCap, g_state.bookmarks[idx]);
    g_state.mode = Mode::View;
    StartFetch(tmp);
    duetos::arch::SerialWrite("[browser] double-click bookmark idx=");
    duetos::arch::SerialWriteHex(idx);
    duetos::arch::SerialWrite("\n");
    return true;
}

WindowHandle BrowserWindow()
{
    return g_state.handle;
}

bool BrowserFeedArrow(u16 keycode)
{
    if (g_state.mode == Mode::View)
    {
        if (keycode == kKeyArrowUp)
        {
            if (g_state.scroll_row > 0)
                --g_state.scroll_row;
        }
        else if (keycode == kKeyArrowDown)
        {
            ++g_state.scroll_row;
        }
        return true;
    }
    if (g_state.mode == Mode::History || g_state.mode == Mode::Bookmarks)
    {
        const u32 cap = (g_state.mode == Mode::History) ? g_state.history_count : g_state.bookmark_count;
        if (cap == 0)
            return true;
        if (keycode == kKeyArrowUp)
        {
            if (g_state.list_selection > 0)
                --g_state.list_selection;
        }
        else if (keycode == kKeyArrowDown)
        {
            if (g_state.list_selection + 1 < cap)
                ++g_state.list_selection;
        }
        return true;
    }
    return false;
}

bool BrowserFeedChar(char c)
{
    const u8 uc = static_cast<u8>(c);

    if (g_state.mode == Mode::UrlEdit)
    {
        HandleUrlEditChar(c);
        return true;
    }

    if (g_state.mode == Mode::History || g_state.mode == Mode::Bookmarks)
    {
        if (uc == 0x1B || (g_state.mode == Mode::History && (c == 'h' || c == 'H')) ||
            (g_state.mode == Mode::Bookmarks && (c == 'l' || c == 'L')))
        {
            g_state.mode = Mode::View;
            return true;
        }
        if (uc == 0x0A) // Enter
        {
            const u32 cap = (g_state.mode == Mode::History) ? g_state.history_count : g_state.bookmark_count;
            if (g_state.list_selection >= cap)
                return true;
            const char* u = (g_state.mode == Mode::History) ? g_state.history[g_state.list_selection]
                                                            : g_state.bookmarks[g_state.list_selection];
            char tmp[kUrlCap];
            StrCopyCap(tmp, kUrlCap, u);
            StrCopyCap(g_state.url, kUrlCap, tmp);
            g_state.url_len = StrLen(g_state.url);
            g_state.mode = Mode::View;
            StartFetch(tmp);
            return true;
        }
        if (g_state.mode == Mode::Bookmarks && (c == 'x' || c == 'X'))
        {
            BookmarkRemoveSelected();
            return true;
        }
        if (c == 'j' || c == 'J')
            return BrowserFeedArrow(kKeyArrowDown);
        if (c == 'k' || c == 'K')
            return BrowserFeedArrow(kKeyArrowUp);
        return true;
    }

    // View mode.
    if (g_state.fetch_in_flight)
        return true; // swallow keys while a fetch is running

    if (uc == 0x09 || c == 'u' || c == 'U') // Tab or U -> URL edit
    {
        EnterUrlEdit();
        return true;
    }
    if (c == 'b' || c == 'B' || uc == 0x08)
    {
        NavigateBackForward(false);
        return true;
    }
    if (c == 'f' || c == 'F')
    {
        NavigateBackForward(true);
        return true;
    }
    if (c == 'r' || c == 'R')
    {
        Reload();
        return true;
    }
    if (c == 'h' || c == 'H')
    {
        g_state.mode = Mode::History;
        g_state.list_selection = (g_state.history_count > 0) ? g_state.history_count - 1 : 0;
        return true;
    }
    if (c == 'l' || c == 'L')
    {
        g_state.mode = Mode::Bookmarks;
        RescanBookmarks();
        g_state.list_selection = 0;
        return true;
    }
    if (c == 'm' || c == 'M')
    {
        BookmarkCurrent();
        return true;
    }
    if (c == 's' || c == 'S')
    {
        SaveDownload();
        return true;
    }
    if (c == 'j' || c == 'J')
        return BrowserFeedArrow(kKeyArrowDown);
    if (c == 'k' || c == 'K')
        return BrowserFeedArrow(kKeyArrowUp);
    if (uc == 0x1B)
    {
        StatusSet("");
        return true;
    }
    return false;
}

void BrowserSelfTest()
{
    using arch::SerialWrite;
    bool pass = true;

    // URL parsing.
    {
        const auto p = ParseUrl("http://example.com/foo");
        if (!p.ok || p.scheme_https || p.port != 80 || !StrEqI(p.host, "example.com") || !StrEqI(p.path, "/foo"))
            pass = false;
    }
    {
        const auto p = ParseUrl("https://example.com:8443/x");
        if (!p.ok || !p.scheme_https || p.port != 8443 || !StrEqI(p.host, "example.com") || !StrEqI(p.path, "/x"))
            pass = false;
    }
    {
        const auto p = ParseUrl("example.com");
        if (!p.ok || p.scheme_https || p.port != 80 || !StrEqI(p.host, "example.com") || !StrEqI(p.path, "/"))
            pass = false;
    }
    {
        const auto p = ParseUrl("");
        if (p.ok)
            pass = false;
    }

    // Dotted-quad parser.
    {
        net::Ipv4Address ip;
        if (!TryParseDottedQuad("8.8.8.8", &ip) || ip.octets[0] != 8 || ip.octets[3] != 8)
            pass = false;
        if (TryParseDottedQuad("hello", &ip))
            pass = false;
        if (TryParseDottedQuad("1.2.3", &ip))
            pass = false;
        if (TryParseDottedQuad("256.0.0.0", &ip))
            pass = false;
    }

    // HTML strip — basic case + entity decode + tag block break.
    {
        const char html[] = "<html><body><p>Hello, &amp; world!</p><p>Second.</p></body></html>";
        char out[128];
        u32 ol = 0;
        StripHtml(reinterpret_cast<const u8*>(html), sizeof(html) - 1, out, sizeof(out), &ol);
        // Should contain "Hello, & world!" and "Second."
        bool found_amp = false;
        bool found_second = false;
        bool found_break = false;
        for (u32 i = 0; i + 1 < ol; ++i)
        {
            if (out[i] == '&' && out[i + 1] == ' ')
                found_amp = true;
            if (out[i] == 'S' && out[i + 1] == 'e')
                found_second = true;
            if (out[i] == '\n')
                found_break = true;
        }
        if (!found_amp || !found_second || !found_break)
            pass = false;
    }

    // HTML strip — script tag content is dropped.
    {
        const char html[] = "<p>before</p><script>var x = 1; alert('hi');</script><p>after</p>";
        char out[128];
        u32 ol = 0;
        StripHtml(reinterpret_cast<const u8*>(html), sizeof(html) - 1, out, sizeof(out), &ol);
        out[ol] = '\0';
        // Result should not contain "alert" or "var x".
        bool leaked = false;
        for (u32 i = 0; i + 4 < ol; ++i)
        {
            if (out[i] == 'a' && out[i + 1] == 'l' && out[i + 2] == 'e' && out[i + 3] == 'r' && out[i + 4] == 't')
                leaked = true;
        }
        if (leaked)
            pass = false;
    }

    SerialWrite(pass ? "[browser] self-test OK (URL parse + dotted-quad + HTML strip)\n"
                     : "[browser] self-test FAILED\n");
}

} // namespace duetos::apps::browser
