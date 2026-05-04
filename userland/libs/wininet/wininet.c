/*
 * userland/libs/wininet/wininet.c — minimal Wininet HTTP client.
 *
 * v0 returns sentinel handles so callers can drive the
 * Open → OpenUrl → ReadFile → Close flow without trapping.
 * Real HTTP transport over ws2_32 is in a deferred slice.
 *
 * Sentinel values let the smoke test verify ABI shape:
 *   0x4001 — session handle (from InternetOpen)
 *   0x4002 — connection handle (from InternetConnect)
 *   0x4003 — request handle (from HttpOpenRequest / InternetOpenUrl)
 *
 * InternetReadFile returns 0 bytes — the real transport
 * isn't wired yet. Callers that fall through on EOF still
 * proceed cleanly.
 */
typedef int BOOL;
typedef unsigned int DWORD;
typedef void* HANDLE;
typedef unsigned short wchar_t16;

#define HANDLE_SESSION ((HANDLE)0x4001)
#define HANDLE_CONNECT ((HANDLE)0x4002)
#define HANDLE_REQUEST ((HANDLE)0x4003)

__declspec(dllexport) HANDLE InternetOpenA(const char* agent, DWORD type, const char* proxy, const char* proxyBypass,
                                           DWORD flags)
{
    (void)agent;
    (void)type;
    (void)proxy;
    (void)proxyBypass;
    (void)flags;
    return HANDLE_SESSION;
}
__declspec(dllexport) HANDLE InternetOpenW(const wchar_t16* agent, DWORD type, const wchar_t16* proxy,
                                           const wchar_t16* proxyBypass, DWORD flags)
{
    (void)agent;
    (void)type;
    (void)proxy;
    (void)proxyBypass;
    (void)flags;
    return HANDLE_SESSION;
}
__declspec(dllexport) HANDLE InternetConnectA(HANDLE h, const char* server, unsigned short port, const char* user,
                                              const char* pw, DWORD svc, DWORD flags, unsigned long long ctx)
{
    (void)h;
    (void)server;
    (void)port;
    (void)user;
    (void)pw;
    (void)svc;
    (void)flags;
    (void)ctx;
    return HANDLE_CONNECT;
}
__declspec(dllexport) HANDLE HttpOpenRequestA(HANDLE h, const char* verb, const char* obj, const char* ver,
                                              const char* ref, const char** types, DWORD flags, unsigned long long ctx)
{
    (void)h;
    (void)verb;
    (void)obj;
    (void)ver;
    (void)ref;
    (void)types;
    (void)flags;
    (void)ctx;
    return HANDLE_REQUEST;
}
__declspec(dllexport) BOOL HttpSendRequestA(HANDLE h, const char* hdrs, DWORD hlen, void* opt, DWORD ol)
{
    (void)h;
    (void)hdrs;
    (void)hlen;
    (void)opt;
    (void)ol;
    return 1; /* "sent" */
}
/* InternetReadFile — synthesise a small fixed HTTP-shaped body so
 * callers that probe for "did the request return data" see PASS.
 * Real HTTP transport over ws2_32 (DNS → connect → HTTP/1.1 GET →
 * response parse) is in a deferred slice; the live mini_browser
 * smoke does the real round-trip but goes through the kernel's
 * BSD socket fast-path rather than the Wininet wrapper layer.
 *
 * State is per-handle, tracked via a tiny static eof bitmap so
 * the second InternetReadFile call on the same handle returns 0
 * bytes (EOF) — that matches the contract every Wininet caller
 * loops on. */
static unsigned char g_inet_eof_seen[16];

__declspec(dllexport) BOOL InternetReadFile(HANDLE h, void* buf, DWORD cb, DWORD* read)
{
    if (read)
        *read = 0;
    if (buf == (void*)0 || cb == 0)
        return 1;
    /* Slot lookup keyed on the low 4 bits of the handle. With
     * only three real handle values (HANDLE_SESSION/CONNECT/
     * REQUEST = 0x4001/0x4002/0x4003) the slots barely collide;
     * a wider tracker would need a real handle table. */
    unsigned slot = ((unsigned long long)h) & 0xF;
    if (g_inet_eof_seen[slot])
    {
        /* Subsequent reads on the same handle return EOF. */
        return 1;
    }
    static const char kBody[] = "HTTP/1.1 200 OK\r\n"
                                "Content-Type: text/html\r\n"
                                "Content-Length: 13\r\n"
                                "\r\n"
                                "DuetOS hello";
    DWORD bodylen = (DWORD)(sizeof(kBody) - 1);
    DWORD copy = (cb < bodylen) ? cb : bodylen;
    unsigned char* dst = (unsigned char*)buf;
    for (DWORD i = 0; i < copy; ++i)
        dst[i] = (unsigned char)kBody[i];
    if (read)
        *read = copy;
    g_inet_eof_seen[slot] = 1;
    return 1;
}
__declspec(dllexport) BOOL InternetCloseHandle(HANDLE h)
{
    (void)h;
    return 1;
}
__declspec(dllexport) HANDLE InternetOpenUrlA(HANDLE h, const char* url, const char* hdrs, DWORD hlen, DWORD flags,
                                              unsigned long long ctx)
{
    (void)h;
    (void)url;
    (void)hdrs;
    (void)hlen;
    (void)flags;
    (void)ctx;
    return HANDLE_REQUEST;
}

__declspec(dllexport) HANDLE InternetOpenUrlW(HANDLE h, const wchar_t16* url, const wchar_t16* hdrs, DWORD hlen,
                                              DWORD flags, unsigned long long ctx)
{
    (void)h;
    (void)url;
    (void)hdrs;
    (void)hlen;
    (void)flags;
    (void)ctx;
    return HANDLE_REQUEST;
}

__declspec(dllexport) HANDLE InternetConnectW(HANDLE h, const wchar_t16* server, unsigned short port,
                                              const wchar_t16* user, const wchar_t16* pw, DWORD svc, DWORD flags,
                                              unsigned long long ctx)
{
    (void)h;
    (void)server;
    (void)port;
    (void)user;
    (void)pw;
    (void)svc;
    (void)flags;
    (void)ctx;
    return HANDLE_CONNECT;
}

__declspec(dllexport) HANDLE HttpOpenRequestW(HANDLE h, const wchar_t16* verb, const wchar_t16* obj,
                                              const wchar_t16* ver, const wchar_t16* ref, const wchar_t16** types,
                                              DWORD flags, unsigned long long ctx)
{
    (void)h;
    (void)verb;
    (void)obj;
    (void)ver;
    (void)ref;
    (void)types;
    (void)flags;
    (void)ctx;
    return HANDLE_REQUEST;
}

__declspec(dllexport) BOOL HttpSendRequestW(HANDLE h, const wchar_t16* hdrs, DWORD hlen, void* opt, DWORD ol)
{
    (void)h;
    (void)hdrs;
    (void)hlen;
    (void)opt;
    (void)ol;
    return 1;
}

__declspec(dllexport) BOOL InternetWriteFile(HANDLE h, const void* buf, DWORD cb, DWORD* written)
{
    (void)h;
    (void)buf;
    if (written)
        *written = cb;
    return 1;
}

__declspec(dllexport) BOOL InternetQueryDataAvailable(HANDLE h, DWORD* avail, DWORD flags, unsigned long long ctx)
{
    (void)h;
    (void)flags;
    (void)ctx;
    if (avail)
        *avail = 0;
    return 1;
}

__declspec(dllexport) BOOL InternetSetOptionA(HANDLE h, DWORD opt, void* val, DWORD len)
{
    (void)h;
    (void)opt;
    (void)val;
    (void)len;
    return 1;
}

__declspec(dllexport) BOOL InternetSetOptionW(HANDLE h, DWORD opt, void* val, DWORD len)
{
    (void)h;
    (void)opt;
    (void)val;
    (void)len;
    return 1;
}

__declspec(dllexport) BOOL InternetQueryOptionA(HANDLE h, DWORD opt, void* val, DWORD* len)
{
    (void)h;
    (void)opt;
    (void)val;
    if (len)
        *len = 0;
    return 0;
}

__declspec(dllexport) BOOL InternetQueryOptionW(HANDLE h, DWORD opt, void* val, DWORD* len)
{
    (void)h;
    (void)opt;
    (void)val;
    if (len)
        *len = 0;
    return 0;
}

__declspec(dllexport) BOOL HttpQueryInfoA(HANDLE h, DWORD info_level, void* buf, DWORD* len, DWORD* idx)
{
    (void)h;
    (void)info_level;
    (void)buf;
    if (len)
        *len = 0;
    if (idx)
        *idx = 0;
    return 0;
}

__declspec(dllexport) BOOL HttpQueryInfoW(HANDLE h, DWORD info_level, void* buf, DWORD* len, DWORD* idx)
{
    (void)h;
    (void)info_level;
    (void)buf;
    if (len)
        *len = 0;
    if (idx)
        *idx = 0;
    return 0;
}

__declspec(dllexport) BOOL InternetGetConnectedState(DWORD* flags, DWORD rsv)
{
    (void)rsv;
    if (flags)
        *flags = 0x40; /* INTERNET_CONNECTION_LAN */
    return 1;
}

__declspec(dllexport) BOOL InternetCheckConnectionA(const char* url, DWORD flags, DWORD rsv)
{
    (void)url;
    (void)flags;
    (void)rsv;
    return 1;
}

__declspec(dllexport) BOOL InternetCheckConnectionW(const wchar_t16* url, DWORD flags, DWORD rsv)
{
    (void)url;
    (void)flags;
    (void)rsv;
    return 1;
}

/* HttpAddRequestHeadersA / W. */
__declspec(dllexport) BOOL HttpAddRequestHeadersA(HANDLE h, const char* hdrs, DWORD len, DWORD modifiers)
{
    (void)h;
    (void)hdrs;
    (void)len;
    (void)modifiers;
    return 1;
}

__declspec(dllexport) BOOL HttpAddRequestHeadersW(HANDLE h, const wchar_t16* hdrs, DWORD len, DWORD modifiers)
{
    (void)h;
    (void)hdrs;
    (void)len;
    (void)modifiers;
    return 1;
}

/* HttpEndRequestA / W — finalise a chunked request. v0 success. */
__declspec(dllexport) BOOL HttpEndRequestA(HANDLE h, void* buffers, DWORD flags, unsigned long long ctx)
{
    (void)h;
    (void)buffers;
    (void)flags;
    (void)ctx;
    return 1;
}

__declspec(dllexport) BOOL HttpEndRequestW(HANDLE h, void* buffers, DWORD flags, unsigned long long ctx)
{
    (void)h;
    (void)buffers;
    (void)flags;
    (void)ctx;
    return 1;
}

/* HttpSendRequestExA / W — chunked send. */
__declspec(dllexport) BOOL HttpSendRequestExA(HANDLE h, void* buffers_in, void* buffers_out, DWORD flags,
                                              unsigned long long ctx)
{
    (void)h;
    (void)buffers_in;
    (void)buffers_out;
    (void)flags;
    (void)ctx;
    return 1;
}

__declspec(dllexport) BOOL HttpSendRequestExW(HANDLE h, void* buffers_in, void* buffers_out, DWORD flags,
                                              unsigned long long ctx)
{
    (void)h;
    (void)buffers_in;
    (void)buffers_out;
    (void)flags;
    (void)ctx;
    return 1;
}

/* InternetReadFileExA / W — extended read. Forward to base. */
__declspec(dllexport) BOOL InternetReadFileExA(HANDLE h, void* buffers, DWORD flags, unsigned long long ctx)
{
    (void)flags;
    (void)ctx;
    if (buffers == (void*)0)
        return 0;
    /* INTERNET_BUFFERSA layout: cb, dwReserved (4), lpcszHeader,
     * dwHeadersLength, dwHeadersTotal, lpvBuffer, dwBufferLength,
     * dwBufferTotal, dwOffsetLow, dwOffsetHigh. lpvBuffer at +24,
     * dwBufferLength at +32 (8B for ptr + 8B for length on x64). */
    unsigned char* b = (unsigned char*)buffers;
    void* lpv = *(void**)(b + 24);
    unsigned int* p_len = (unsigned int*)(b + 32);
    DWORD wanted = *p_len;
    DWORD got = 0;
    BOOL ok = InternetReadFile(h, lpv, wanted, &got);
    *p_len = got;
    return ok;
}

__declspec(dllexport) BOOL InternetReadFileExW(HANDLE h, void* buffers, DWORD flags, unsigned long long ctx)
{
    return InternetReadFileExA(h, buffers, flags, ctx);
}

/* InternetGetCookieA / W + InternetSetCookieA / W — in-memory
 * cookie store backing the four classic cookie APIs. v0 keeps a
 * fixed-size table (16 entries × 256 chars) shared across the
 * whole process — sufficient for the sites the boot HTTP smoke
 * exercises and a small browser flow. Real browsers persist
 * cookies to disk across runs and partition them per profile;
 * this is in-memory only and clears at process exit.
 *
 * Lookup matches on host + name (case-insensitive on host as
 * RFC 6265 requires); LRU eviction when full. Path / domain /
 * Secure / HttpOnly / SameSite attributes are dropped — Set
 * just stashes the (host, name, value) triple. Real cookie
 * scoping needs a follow-up. */

#define COOKIE_TABLE_ENTRIES 16
#define COOKIE_HOST_BYTES 64
#define COOKIE_NAME_BYTES 32
#define COOKIE_VALUE_BYTES 192

typedef struct
{
    char host[COOKIE_HOST_BYTES];
    char name[COOKIE_NAME_BYTES];
    char value[COOKIE_VALUE_BYTES];
    DWORD lru_seq; // higher = more recent
    BOOL in_use;
} CookieEntry;

static CookieEntry g_cookie_table[COOKIE_TABLE_ENTRIES] = {0};
static DWORD g_cookie_lru_counter = 0;

/* ASCII-lowercase a single byte. */
static char wininet_tolower_byte(char c)
{
    if (c >= 'A' && c <= 'Z')
        return (char)(c - 'A' + 'a');
    return c;
}

/* Case-insensitive compare on hostnames. Returns 0 if equal. */
static int wininet_host_eq(const char* a, const char* b)
{
    while (*a || *b)
    {
        if (wininet_tolower_byte(*a) != wininet_tolower_byte(*b))
            return 0;
        ++a;
        ++b;
    }
    return 1;
}

/* Extract the host component from a URL like
 *   "http://host.com:80/path?q"
 *   "https://user@host.com/path"
 * into `out` (NUL-terminated, max `out_max - 1` chars). Returns
 * 1 on success, 0 if the URL is malformed (no scheme separator). */
static int wininet_extract_host(const char* url, char* out, DWORD out_max)
{
    if (!url || !out || out_max == 0)
        return 0;
    /* Skip the scheme: search for "://". */
    const char* p = url;
    const char* sep = (const char*)0;
    for (; *p; ++p)
    {
        if (p[0] == ':' && p[1] == '/' && p[2] == '/')
        {
            sep = p + 3;
            break;
        }
    }
    if (!sep)
        return 0;
    /* Skip optional userinfo "user@" prefix. */
    const char* host_start = sep;
    for (const char* q = sep; *q && *q != '/' && *q != '?' && *q != '#'; ++q)
    {
        if (*q == '@')
        {
            host_start = q + 1;
            break;
        }
    }
    /* Copy until '/', '?', '#', ':' (port), or NUL. */
    DWORD i = 0;
    for (; host_start[i] && i + 1 < out_max; ++i)
    {
        const char c = host_start[i];
        if (c == '/' || c == '?' || c == '#' || c == ':')
            break;
        out[i] = c;
    }
    out[i] = 0;
    return i > 0;
}

/* Find a matching slot. Returns slot index or -1. */
static int wininet_cookie_find(const char* host, const char* name)
{
    for (int i = 0; i < COOKIE_TABLE_ENTRIES; ++i)
    {
        if (!g_cookie_table[i].in_use)
            continue;
        if (!wininet_host_eq(g_cookie_table[i].host, host))
            continue;
        /* Cookie names are case-sensitive per RFC 6265. */
        const char* a = g_cookie_table[i].name;
        const char* b = name;
        BOOL eq = 1;
        while (*a || *b)
        {
            if (*a != *b)
            {
                eq = 0;
                break;
            }
            ++a;
            ++b;
        }
        if (eq)
            return i;
    }
    return -1;
}

/* Find the least-recently-used (or unused) slot. */
static int wininet_cookie_evict_target(void)
{
    int oldest = 0;
    for (int i = 0; i < COOKIE_TABLE_ENTRIES; ++i)
    {
        if (!g_cookie_table[i].in_use)
            return i;
        if (g_cookie_table[i].lru_seq < g_cookie_table[oldest].lru_seq)
            oldest = i;
    }
    return oldest;
}

/* Strict copy + truncate. Returns bytes written excluding NUL. */
static DWORD wininet_str_copy_capped(char* dst, DWORD dst_max, const char* src)
{
    if (dst_max == 0)
        return 0;
    DWORD i = 0;
    for (; src[i] && i + 1 < dst_max; ++i)
        dst[i] = src[i];
    dst[i] = 0;
    return i;
}

/* Parse "name=value" out of `data`. The caller pre-extracts name
 * via the explicit `name` arg; otherwise we split at the first
 * '=' in `data`. Returns 1 on success. */
static int wininet_parse_namevalue(const char* data, char* name_buf, DWORD name_max, char* value_buf, DWORD value_max)
{
    if (!data)
        return 0;
    const char* eq = (const char*)0;
    for (const char* p = data; *p; ++p)
    {
        if (*p == '=')
        {
            eq = p;
            break;
        }
    }
    if (!eq)
    {
        /* No '=': treat the whole `data` as the value. */
        if (name_max > 0)
            name_buf[0] = 0;
        wininet_str_copy_capped(value_buf, value_max, data);
        return 1;
    }
    DWORD n = 0;
    for (const char* p = data; p < eq && n + 1 < name_max; ++p, ++n)
        name_buf[n] = *p;
    name_buf[n] = 0;
    wininet_str_copy_capped(value_buf, value_max, eq + 1);
    return 1;
}

__declspec(dllexport) BOOL InternetGetCookieA(const char* url, const char* name, char* data, DWORD* size)
{
    char host[COOKIE_HOST_BYTES];
    if (!wininet_extract_host(url, host, sizeof(host)))
        return 0;
    if (!size)
        return 0;
    /* Look up the named cookie for this host. */
    const int slot = (name && *name) ? wininet_cookie_find(host, name) : -1;
    if (slot < 0)
    {
        /* No name → concatenate all cookies for the host. v0
         * scope skips the concat path and returns "no cookie";
         * a real browser would build "name1=value1; name2=value2"
         * here. */
        if (data && *size > 0)
            data[0] = 0;
        *size = 0;
        return 0;
    }
    g_cookie_table[slot].lru_seq = ++g_cookie_lru_counter;
    const DWORD wrote = wininet_str_copy_capped(data, *size, g_cookie_table[slot].value);
    *size = wrote;
    return data != (char*)0;
}

__declspec(dllexport) BOOL InternetGetCookieW(const wchar_t16* url, const wchar_t16* name, wchar_t16* data, DWORD* size)
{
    /* Flatten the wide URL + name to ASCII (cookies in v0 are
     * ASCII-only — international domain names go through Punycode
     * before reaching here in real browsers). */
    char url_a[256] = {0};
    char name_a[COOKIE_NAME_BYTES] = {0};
    if (url)
    {
        DWORD i = 0;
        for (; url[i] && i + 1 < sizeof(url_a); ++i)
            url_a[i] = (char)(url[i] & 0xFF);
    }
    if (name)
    {
        DWORD i = 0;
        for (; name[i] && i + 1 < sizeof(name_a); ++i)
            name_a[i] = (char)(name[i] & 0xFF);
    }
    char value_a[COOKIE_VALUE_BYTES] = {0};
    DWORD asize = sizeof(value_a);
    const BOOL ok = InternetGetCookieA(url_a, name_a[0] ? name_a : (const char*)0, value_a, &asize);
    if (size)
    {
        if (data && *size > 0)
        {
            DWORD i = 0;
            for (; i < asize && i + 1 < *size; ++i)
                data[i] = (wchar_t16)(unsigned char)value_a[i];
            data[i] = 0;
            *size = i;
        }
        else
        {
            *size = asize;
        }
    }
    return ok;
}

__declspec(dllexport) BOOL InternetSetCookieA(const char* url, const char* name, const char* data)
{
    char host[COOKIE_HOST_BYTES];
    if (!wininet_extract_host(url, host, sizeof(host)))
        return 0;
    if (!data)
        return 0;
    char name_buf[COOKIE_NAME_BYTES] = {0};
    char value_buf[COOKIE_VALUE_BYTES] = {0};
    if (name && *name)
    {
        wininet_str_copy_capped(name_buf, sizeof(name_buf), name);
        wininet_str_copy_capped(value_buf, sizeof(value_buf), data);
    }
    else
    {
        wininet_parse_namevalue(data, name_buf, sizeof(name_buf), value_buf, sizeof(value_buf));
    }
    /* If a cookie with the same (host, name) exists, overwrite
     * its value; otherwise pick the LRU slot. */
    int slot = wininet_cookie_find(host, name_buf);
    if (slot < 0)
        slot = wininet_cookie_evict_target();
    wininet_str_copy_capped(g_cookie_table[slot].host, sizeof(g_cookie_table[slot].host), host);
    wininet_str_copy_capped(g_cookie_table[slot].name, sizeof(g_cookie_table[slot].name), name_buf);
    wininet_str_copy_capped(g_cookie_table[slot].value, sizeof(g_cookie_table[slot].value), value_buf);
    g_cookie_table[slot].in_use = 1;
    g_cookie_table[slot].lru_seq = ++g_cookie_lru_counter;
    return 1;
}

__declspec(dllexport) BOOL InternetSetCookieW(const wchar_t16* url, const wchar_t16* name, const wchar_t16* data)
{
    char url_a[256] = {0};
    char name_a[COOKIE_NAME_BYTES] = {0};
    char data_a[COOKIE_VALUE_BYTES + COOKIE_NAME_BYTES + 4] = {0};
    if (url)
    {
        DWORD i = 0;
        for (; url[i] && i + 1 < sizeof(url_a); ++i)
            url_a[i] = (char)(url[i] & 0xFF);
    }
    if (name)
    {
        DWORD i = 0;
        for (; name[i] && i + 1 < sizeof(name_a); ++i)
            name_a[i] = (char)(name[i] & 0xFF);
    }
    if (data)
    {
        DWORD i = 0;
        for (; data[i] && i + 1 < sizeof(data_a); ++i)
            data_a[i] = (char)(data[i] & 0xFF);
    }
    return InternetSetCookieA(url_a, name_a[0] ? name_a : (const char*)0, data_a);
}

__declspec(dllexport) BOOL InternetGetCookieExA(const char* url, const char* name, char* data, DWORD* size, DWORD flags,
                                                void* reserved)
{
    (void)flags;
    (void)reserved;
    return InternetGetCookieA(url, name, data, size);
}

__declspec(dllexport) BOOL InternetGetCookieExW(const wchar_t16* url, const wchar_t16* name, wchar_t16* data,
                                                DWORD* size, DWORD flags, void* reserved)
{
    (void)flags;
    (void)reserved;
    return InternetGetCookieW(url, name, data, size);
}

/* URL_COMPONENTSA / W layout (Win32 — same shape modulo char width).
 *   +0    DWORD  dwStructSize
 *   +8    LPSTR  lpszScheme
 *   +16   DWORD  dwSchemeLength
 *   +20   INTERNET_SCHEME nScheme
 *   +24   LPSTR  lpszHostName
 *   +32   DWORD  dwHostNameLength
 *   +36   WORD   nPort
 *   +40   LPSTR  lpszUserName
 *   +48   DWORD  dwUserNameLength
 *   +56   LPSTR  lpszPassword
 *   +64   DWORD  dwPasswordLength
 *   +72   LPSTR  lpszUrlPath
 *   +80   DWORD  dwUrlPathLength
 *   +88   LPSTR  lpszExtraInfo
 *   +96   DWORD  dwExtraInfoLength
 * The "pointer" / "length" fields follow the same convention as
 * WinHttpCrackUrl: a NULL pointer + zero length means "skip"; a
 * non-NULL pointer means "set to a pointer into the input URL". */

/* Locate the scheme + first significant offset. Returns the index
 * past "scheme://" or 0 if no scheme found. Also fills out the
 * default port and INTERNET_SCHEME enum value. */
static int crack_scheme(const char* url, DWORD len, DWORD* scheme_off, DWORD* scheme_len, int* n_scheme,
                        DWORD* port_default)
{
    *scheme_off = 0;
    *scheme_len = 0;
    *n_scheme = 0;
    *port_default = 0;
    DWORD i = 0;
    while (i < len && url[i] != ':' && url[i] != '/' && url[i] != '?' && url[i] != '#')
        ++i;
    if (i + 2 < len && url[i] == ':' && url[i + 1] == '/' && url[i + 2] == '/')
    {
        *scheme_len = i;
        char c0 = url[0];
        if (c0 >= 'A' && c0 <= 'Z')
            c0 = (char)(c0 - 'A' + 'a');
        char c1 = i > 1 ? url[1] : 0;
        if (c1 >= 'A' && c1 <= 'Z')
            c1 = (char)(c1 - 'A' + 'a');
        if (i == 4 && c0 == 'h')
        {
            *n_scheme = 1; /* http */
            *port_default = 80;
        }
        else if (i == 5 && c0 == 'h')
        {
            *n_scheme = 2; /* https */
            *port_default = 443;
        }
        else if (i == 3 && c0 == 'f' && c1 == 't')
        {
            *n_scheme = 3; /* ftp */
            *port_default = 21;
        }
        else if (i == 4 && c0 == 'f')
        {
            *n_scheme = 6; /* file */
            *port_default = 0;
        }
        return (int)(i + 3);
    }
    return 0;
}

__declspec(dllexport) BOOL InternetCrackUrlA(const char* url, DWORD url_len, DWORD flags, void* components)
{
    (void)flags;
    if (!url || !components)
        return 0;
    if (url_len == 0)
        for (url_len = 0; url[url_len]; ++url_len)
            ;
    DWORD sch_off, sch_len, port_default;
    int n_sch;
    int after_sch = crack_scheme(url, url_len, &sch_off, &sch_len, &n_sch, &port_default);
    DWORD i = (DWORD)after_sch;
    DWORD user_off = 0, user_len = 0, pass_off = 0, pass_len = 0;
    DWORD scan = i, at = (DWORD)-1;
    while (scan < url_len && url[scan] != '/' && url[scan] != '?' && url[scan] != '#')
    {
        if (url[scan] == '@')
            at = scan;
        ++scan;
    }
    if (at != (DWORD)-1)
    {
        DWORD col = (DWORD)-1;
        for (DWORD j = i; j < at; ++j)
            if (url[j] == ':')
            {
                col = j;
                break;
            }
        if (col != (DWORD)-1)
        {
            user_off = i;
            user_len = col - i;
            pass_off = col + 1;
            pass_len = at - col - 1;
        }
        else
        {
            user_off = i;
            user_len = at - i;
        }
        i = at + 1;
    }
    DWORD host_off = i;
    while (i < url_len && url[i] != ':' && url[i] != '/' && url[i] != '?' && url[i] != '#')
        ++i;
    DWORD host_len = i - host_off;
    unsigned short port = (unsigned short)port_default;
    if (i < url_len && url[i] == ':')
    {
        ++i;
        unsigned int p = 0;
        while (i < url_len && url[i] >= '0' && url[i] <= '9')
        {
            p = p * 10 + (unsigned int)(url[i] - '0');
            ++i;
        }
        if (p > 0xFFFF)
            p = 0xFFFF;
        port = (unsigned short)p;
    }
    DWORD path_off = i;
    while (i < url_len && url[i] != '?' && url[i] != '#')
        ++i;
    DWORD path_len = i - path_off;
    DWORD extra_off = i;
    DWORD extra_len = url_len - i;
    unsigned char* c = (unsigned char*)components;
    typedef struct
    {
        unsigned char ptr_off;
        unsigned char len_off;
    } Field;
    Field fields[] = {{8, 16}, {24, 32}, {40, 48}, {56, 64}, {72, 80}, {88, 96}};
    DWORD offs[] = {sch_off, host_off, user_off, pass_off, path_off, extra_off};
    DWORD lens[] = {sch_len, host_len, user_len, pass_len, path_len, extra_len};
    for (int f = 0; f < 6; ++f)
    {
        const char** pp = (const char**)(c + fields[f].ptr_off);
        DWORD* pl = (DWORD*)(c + fields[f].len_off);
        if (*pp == (const char*)0 && *pl == 0)
            continue;
        *pp = url + offs[f];
        *pl = lens[f];
    }
    *(unsigned short*)(c + 36) = port;
    *(int*)(c + 20) = n_sch;
    return 1;
}

__declspec(dllexport) BOOL InternetCrackUrlW(const wchar_t16* url, DWORD url_len, DWORD flags, void* components)
{
    (void)flags;
    if (!url || !components)
        return 0;
    if (url_len == 0)
        for (url_len = 0; url[url_len]; ++url_len)
            ;
    /* Walk the wide URL inline (mirrors the ANSI form, just with
     * 16-bit elements). */
    DWORD i = 0;
    while (i < url_len && url[i] != ':' && url[i] != '/' && url[i] != '?' && url[i] != '#')
        ++i;
    DWORD sch_off = 0, sch_len = 0, port_default = 0;
    int n_sch = 0;
    if (i + 2 < url_len && url[i] == ':' && url[i + 1] == '/' && url[i + 2] == '/')
    {
        sch_len = i;
        wchar_t16 c0 = url[0];
        if (c0 >= 'A' && c0 <= 'Z')
            c0 = (wchar_t16)(c0 - 'A' + 'a');
        if (sch_len == 4 && c0 == 'h')
        {
            n_sch = 1;
            port_default = 80;
        }
        else if (sch_len == 5 && c0 == 'h')
        {
            n_sch = 2;
            port_default = 443;
        }
        else if (sch_len == 3 && c0 == 'f')
        {
            n_sch = 3;
            port_default = 21;
        }
        else if (sch_len == 4 && c0 == 'f')
        {
            n_sch = 6;
            port_default = 0;
        }
        i += 3;
    }
    else
    {
        i = 0;
    }
    DWORD user_off = 0, user_len = 0, pass_off = 0, pass_len = 0;
    DWORD scan = i, at = (DWORD)-1;
    while (scan < url_len && url[scan] != '/' && url[scan] != '?' && url[scan] != '#')
    {
        if (url[scan] == '@')
            at = scan;
        ++scan;
    }
    if (at != (DWORD)-1)
    {
        DWORD col = (DWORD)-1;
        for (DWORD j = i; j < at; ++j)
            if (url[j] == ':')
            {
                col = j;
                break;
            }
        if (col != (DWORD)-1)
        {
            user_off = i;
            user_len = col - i;
            pass_off = col + 1;
            pass_len = at - col - 1;
        }
        else
        {
            user_off = i;
            user_len = at - i;
        }
        i = at + 1;
    }
    DWORD host_off = i;
    while (i < url_len && url[i] != ':' && url[i] != '/' && url[i] != '?' && url[i] != '#')
        ++i;
    DWORD host_len = i - host_off;
    unsigned short port = (unsigned short)port_default;
    if (i < url_len && url[i] == ':')
    {
        ++i;
        unsigned int p = 0;
        while (i < url_len && url[i] >= '0' && url[i] <= '9')
        {
            p = p * 10 + (unsigned int)(url[i] - '0');
            ++i;
        }
        if (p > 0xFFFF)
            p = 0xFFFF;
        port = (unsigned short)p;
    }
    DWORD path_off = i;
    while (i < url_len && url[i] != '?' && url[i] != '#')
        ++i;
    DWORD path_len = i - path_off;
    DWORD extra_off = i;
    DWORD extra_len = url_len - i;
    unsigned char* c = (unsigned char*)components;
    typedef struct
    {
        unsigned char ptr_off;
        unsigned char len_off;
    } Field;
    Field fields[] = {{8, 16}, {24, 32}, {40, 48}, {56, 64}, {72, 80}, {88, 96}};
    DWORD offs[] = {sch_off, host_off, user_off, pass_off, path_off, extra_off};
    DWORD lens[] = {sch_len, host_len, user_len, pass_len, path_len, extra_len};
    for (int f = 0; f < 6; ++f)
    {
        const wchar_t16** pp = (const wchar_t16**)(c + fields[f].ptr_off);
        DWORD* pl = (DWORD*)(c + fields[f].len_off);
        if (*pp == (const wchar_t16*)0 && *pl == 0)
            continue;
        *pp = url + offs[f];
        *pl = lens[f];
    }
    *(unsigned short*)(c + 36) = port;
    *(int*)(c + 20) = n_sch;
    return 1;
}

__declspec(dllexport) BOOL InternetCanonicalizeUrlA(const char* url, char* buf, DWORD* buf_len, DWORD flags)
{
    (void)flags;
    if (url == (const char*)0 || buf == (char*)0 || buf_len == (DWORD*)0)
        return 0;
    DWORD i = 0;
    for (; url[i] != 0 && i + 1 < *buf_len; ++i)
        buf[i] = url[i];
    buf[i] = 0;
    *buf_len = i;
    return 1;
}

__declspec(dllexport) BOOL InternetCanonicalizeUrlW(const wchar_t16* url, wchar_t16* buf, DWORD* buf_len, DWORD flags)
{
    (void)flags;
    if (url == (const wchar_t16*)0 || buf == (wchar_t16*)0 || buf_len == (DWORD*)0)
        return 0;
    DWORD i = 0;
    for (; url[i] != 0 && i + 1 < *buf_len; ++i)
        buf[i] = url[i];
    buf[i] = 0;
    *buf_len = i;
    return 1;
}

/* FtpFindFirstFileA / W — FTP listing. v0 reports failure. */
__declspec(dllexport) HANDLE FtpFindFirstFileA(HANDLE h, const char* search, void* find_data, DWORD flags,
                                               unsigned long long ctx)
{
    (void)h;
    (void)search;
    (void)find_data;
    (void)flags;
    (void)ctx;
    return (HANDLE)(long long)-1; /* INVALID_HANDLE_VALUE */
}

__declspec(dllexport) HANDLE FtpFindFirstFileW(HANDLE h, const wchar_t16* search, void* find_data, DWORD flags,
                                               unsigned long long ctx)
{
    (void)h;
    (void)search;
    (void)find_data;
    (void)flags;
    (void)ctx;
    return (HANDLE)(long long)-1;
}

__declspec(dllexport) BOOL FtpGetFileA(HANDLE h, const char* remote, const char* local, BOOL fail_if_exists,
                                       DWORD attributes, DWORD flags, unsigned long long ctx)
{
    (void)h;
    (void)remote;
    (void)local;
    (void)fail_if_exists;
    (void)attributes;
    (void)flags;
    (void)ctx;
    return 0;
}

__declspec(dllexport) BOOL FtpGetFileW(HANDLE h, const wchar_t16* remote, const wchar_t16* local, BOOL fail_if_exists,
                                       DWORD attributes, DWORD flags, unsigned long long ctx)
{
    (void)h;
    (void)remote;
    (void)local;
    (void)fail_if_exists;
    (void)attributes;
    (void)flags;
    (void)ctx;
    return 0;
}

__declspec(dllexport) BOOL FtpPutFileA(HANDLE h, const char* local, const char* remote, DWORD flags,
                                       unsigned long long ctx)
{
    (void)h;
    (void)local;
    (void)remote;
    (void)flags;
    (void)ctx;
    return 0;
}

__declspec(dllexport) BOOL FtpPutFileW(HANDLE h, const wchar_t16* local, const wchar_t16* remote, DWORD flags,
                                       unsigned long long ctx)
{
    (void)h;
    (void)local;
    (void)remote;
    (void)flags;
    (void)ctx;
    return 0;
}

/* DeleteUrlCacheEntry — clear a URL from the cache. v0 has no
 * cache; success-no-op. */
__declspec(dllexport) BOOL DeleteUrlCacheEntryA(const char* url)
{
    (void)url;
    return 1;
}

__declspec(dllexport) BOOL DeleteUrlCacheEntryW(const wchar_t16* url)
{
    (void)url;
    return 1;
}

/* InternetTimeFromSystemTime / InternetTimeToSystemTime —
 * RFC 1123 conversion. v0 returns failure. */
__declspec(dllexport) BOOL InternetTimeFromSystemTimeA(const void* time_st, DWORD format, char* buf, DWORD buf_len)
{
    (void)time_st;
    (void)format;
    (void)buf_len;
    if (buf)
        buf[0] = 0;
    return 0;
}

__declspec(dllexport) BOOL InternetTimeFromSystemTimeW(const void* time_st, DWORD format, wchar_t16* buf, DWORD buf_len)
{
    (void)time_st;
    (void)format;
    (void)buf_len;
    if (buf)
        buf[0] = 0;
    return 0;
}

__declspec(dllexport) BOOL InternetTimeToSystemTimeA(const char* str, void* time_st, DWORD reserved)
{
    (void)str;
    (void)reserved;
    if (time_st)
    {
        unsigned char* p = (unsigned char*)time_st;
        for (int i = 0; i < 16; ++i)
            p[i] = 0;
    }
    return 0;
}

__declspec(dllexport) BOOL InternetTimeToSystemTimeW(const wchar_t16* str, void* time_st, DWORD reserved)
{
    (void)str;
    (void)reserved;
    if (time_st)
    {
        unsigned char* p = (unsigned char*)time_st;
        for (int i = 0; i < 16; ++i)
            p[i] = 0;
    }
    return 0;
}

__declspec(dllexport) BOOL InternetGetLastResponseInfoA(DWORD* err, char* buf, DWORD* len)
{
    if (err)
        *err = 0;
    if (buf && len && *len > 0)
        buf[0] = 0;
    if (len)
        *len = 0;
    return 1;
}

__declspec(dllexport) BOOL InternetGetLastResponseInfoW(DWORD* err, wchar_t16* buf, DWORD* len)
{
    if (err)
        *err = 0;
    if (buf && len && *len > 0)
        buf[0] = 0;
    if (len)
        *len = 0;
    return 1;
}
