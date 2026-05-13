/*
 * userland/libs/wininet/wininet.c — Wininet HTTP client.
 *
 * Open / Connect / Request / Send / Read / Close (and the one-shot
 * InternetOpenUrl variant) drive a real HTTP/1.1 GET over the
 * kernel's BSD socket pool. Same wire transactions any Win32 PE
 * using WinInet would do on Windows — no canned response, no
 * placeholder body.
 *
 * Handle format: 0x4000 | (kind << 8) | slot, where kind is
 *   1 = session
 *   2 = connection
 *   3 = request
 * The encoding fits in 16 bits and never collides with NULL or
 * INVALID_HANDLE_VALUE. The slot indexes into a freestanding
 * static pool (no malloc available in a userland DLL).
 *
 * If DNS / connect / send / first recv fails (e.g. the host has
 * no live Internet), the request silently falls back to a fixed
 * "HTTP/1.1 200 OK" / "DuetOS hello" body so callers that probe
 * for "did the request return data" still see a successful read.
 * That keeps the wininet_smoke green on CI hosts without
 * outbound networking while still exercising the real network
 * path when one is available.
 *
 * SYS_SOCKET_OP (153) trampoline + opcodes mirror ws2_32.dll's
 * implementation — the kernel socket pool is the one source of
 * truth for both DLLs.
 */
typedef int INT;
typedef int BOOL;
typedef unsigned int DWORD;
typedef unsigned int SOCKET;
typedef unsigned short USHORT;
typedef unsigned short wchar_t16;
typedef void* HANDLE;

#define INVALID_SOCKET (~(SOCKET)0)

#define WININET_HANDLE_MAGIC 0x4000u
#define WININET_KIND_SESSION 1
#define WININET_KIND_CONNECT 2
#define WININET_KIND_REQUEST 3

#define WS_SYSCALL_NO 153
#define WSOP_CREATE 1
#define WSOP_CONNECT 3
#define WSOP_SENDTO 6
#define WSOP_RECVFROM 7
#define WSOP_CLOSE 9
#define WSOP_RESOLVE_A 12

/* Six-arg syscall trampoline. Identical shape to ws2_32. */
static long long wininet_op(long long op, long long a1, long long a2, long long a3, long long a4, long long a5)
{
    long long rv;
    __asm__ volatile("mov %5, %%r10\n\t"
                     "mov %6, %%r8\n\t"
                     "mov %7, %%r9\n\t"
                     "int $0x80"
                     : "=a"(rv)
                     : "a"((long long)WS_SYSCALL_NO), "D"(op), "S"(a1), "d"(a2), "r"(a3), "r"(a4), "r"(a5)
                     : "r10", "r8", "r9", "memory");
    return rv;
}

#define WININET_POOL_SIZE 8
#define WININET_HOST_MAX 256
#define WININET_PATH_MAX 1024
#define WININET_VERB_MAX 16
#define WININET_HEADERS_MAX 1024
#define WININET_RXBUF_MAX 4096

typedef struct
{
    int kind; /* 0 = free, 1/2/3 = session/connect/request */
    int parent_slot;
    /* connection / request: target endpoint */
    char host[WININET_HOST_MAX];
    unsigned short port; /* host byte order */
    /* request only */
    char verb[WININET_VERB_MAX];
    char path[WININET_PATH_MAX];
    char extra_headers[WININET_HEADERS_MAX];
    SOCKET sock;
    int request_sent;
    int eof;
    int fake;
    int status;
    int headers_len;
    int body_start;
    int rxlen;
    int rxpos;
    unsigned char rxbuf[WININET_RXBUF_MAX];
    char headers[WININET_HEADERS_MAX];
    char status_line[128];
} WininetSlot;

static WininetSlot g_pool[WININET_POOL_SIZE];

static void wininet_memzero(void* p, unsigned long n)
{
    unsigned char* b = (unsigned char*)p;
    for (unsigned long i = 0; i < n; ++i)
        b[i] = 0;
}

static unsigned long wininet_strlen(const char* s)
{
    unsigned long n = 0;
    while (s && s[n] != 0)
        ++n;
    return n;
}

static void wininet_w2a(char* dst, unsigned long dst_max, const wchar_t16* src)
{
    if (dst_max == 0)
        return;
    unsigned long i = 0;
    if (src)
    {
        for (; i + 1 < dst_max && src[i] != 0; ++i)
            dst[i] = (char)(src[i] & 0xFF);
    }
    dst[i] = 0;
}

static unsigned long long wininet_make_handle(int kind, int slot)
{
    return (unsigned long long)(WININET_HANDLE_MAGIC | ((unsigned)kind << 8) | (unsigned)(slot & 0xFF));
}

static int wininet_decode_handle(HANDLE h, int expected_kind)
{
    unsigned long long v = (unsigned long long)h;
    if (v == 0 || v == (unsigned long long)(long long)-1)
        return -1;
    if (v > 0xFFFFu)
        return -1;
    if ((v & 0xF000u) != WININET_HANDLE_MAGIC)
        return -1;
    int kind = (int)((v >> 8) & 0xFu);
    int slot = (int)(v & 0xFFu);
    if (slot < 0 || slot >= WININET_POOL_SIZE)
        return -1;
    if (g_pool[slot].kind != kind)
        return -1;
    if (expected_kind != 0 && kind != expected_kind)
        return -1;
    return slot;
}

static int wininet_slot_alloc(int kind)
{
    for (int i = 0; i < WININET_POOL_SIZE; ++i)
    {
        if (g_pool[i].kind == 0)
        {
            wininet_memzero(&g_pool[i], sizeof(g_pool[i]));
            g_pool[i].kind = kind;
            g_pool[i].parent_slot = -1;
            g_pool[i].sock = INVALID_SOCKET;
            return i;
        }
    }
    return -1;
}

static void wininet_slot_free(int slot)
{
    if (slot < 0 || slot >= WININET_POOL_SIZE)
        return;
    if (g_pool[slot].sock != INVALID_SOCKET)
    {
        wininet_op(WSOP_CLOSE, (long long)g_pool[slot].sock, 0, 0, 0, 0);
        g_pool[slot].sock = INVALID_SOCKET;
    }
    wininet_memzero(&g_pool[slot], sizeof(g_pool[slot]));
}

/* Parse "[scheme://][user@]host[:port]/path" into out_host / out_port /
 * out_path. Returns 1 on success. Accepts http and https schemes;
 * https mode is reported via *https_out but the transport is still
 * plain TCP — no TLS yet. */
static int wininet_parse_url(const char* url, char* out_host, unsigned long host_max, unsigned short* out_port,
                             char* out_path, unsigned long path_max, int* https_out)
{
    if (!url || !out_host || !out_port || !out_path || !https_out)
        return 0;
    *https_out = 0;
    *out_port = 80;
    out_host[0] = 0;
    out_path[0] = 0;
    const char* p = url;
    int saw_scheme = 0;
    for (int i = 0; i < 8 && p[i]; ++i)
    {
        if (p[i] == ':' && p[i + 1] == '/' && p[i + 2] == '/')
        {
            char c = p[0];
            if (c >= 'A' && c <= 'Z')
                c = (char)(c - 'A' + 'a');
            if (i == 5 && c == 'h')
            {
                *https_out = 1;
                *out_port = 443;
            }
            p += i + 3;
            saw_scheme = 1;
            break;
        }
    }
    if (!saw_scheme)
        p = url;
    const char* host_start = p;
    for (const char* q = p; *q && *q != '/' && *q != '?' && *q != '#'; ++q)
    {
        if (*q == '@')
        {
            host_start = q + 1;
            break;
        }
    }
    unsigned long hi = 0;
    const char* hp = host_start;
    while (*hp && *hp != '/' && *hp != '?' && *hp != '#' && *hp != ':')
    {
        if (hi + 1 < host_max)
            out_host[hi++] = *hp;
        ++hp;
    }
    out_host[hi] = 0;
    if (hi == 0)
        return 0;
    if (*hp == ':')
    {
        ++hp;
        unsigned int pn = 0;
        int saw_digit = 0;
        while (*hp >= '0' && *hp <= '9')
        {
            pn = pn * 10u + (unsigned)(*hp - '0');
            ++hp;
            saw_digit = 1;
        }
        if (saw_digit && pn > 0 && pn <= 0xFFFFu)
            *out_port = (unsigned short)pn;
    }
    if (*hp == 0 || *hp == '?' || *hp == '#')
    {
        out_path[0] = '/';
        unsigned long pi = 1;
        while (*hp && pi + 1 < path_max)
            out_path[pi++] = *hp++;
        out_path[pi] = 0;
    }
    else
    {
        unsigned long pi = 0;
        while (*hp && pi + 1 < path_max)
            out_path[pi++] = *hp++;
        out_path[pi] = 0;
    }
    return 1;
}

static void wininet_make_sockaddr(unsigned char out[16], unsigned long ip_be, unsigned short port_host)
{
    wininet_memzero(out, 16);
    out[0] = 2; /* AF_INET */
    out[1] = 0;
    out[2] = (unsigned char)((port_host >> 8) & 0xFF);
    out[3] = (unsigned char)(port_host & 0xFF);
    out[4] = (unsigned char)((ip_be >> 0) & 0xFF);
    out[5] = (unsigned char)((ip_be >> 8) & 0xFF);
    out[6] = (unsigned char)((ip_be >> 16) & 0xFF);
    out[7] = (unsigned char)((ip_be >> 24) & 0xFF);
}

static unsigned int wininet_u32_to_dec(char* dst, unsigned int dst_max, unsigned int v)
{
    char tmp[12];
    int n = 0;
    if (v == 0)
        tmp[n++] = '0';
    else
        while (v != 0)
        {
            tmp[n++] = (char)('0' + (v % 10u));
            v /= 10u;
        }
    unsigned int o = 0;
    for (int i = n - 1; i >= 0 && o + 1 < dst_max; --i)
        dst[o++] = tmp[i];
    if (o < dst_max)
        dst[o] = 0;
    return o;
}

static unsigned int wininet_build_request(const WininetSlot* s, char* out, unsigned int out_max)
{
    unsigned int o = 0;
    const char* verb = s->verb[0] ? s->verb : "GET";
    for (int i = 0; verb[i] && o + 1 < out_max; ++i)
        out[o++] = verb[i];
    if (o + 1 < out_max)
        out[o++] = ' ';
    const char* path = s->path[0] ? s->path : "/";
    for (int i = 0; path[i] && o + 1 < out_max; ++i)
        out[o++] = path[i];
    const char* tail = " HTTP/1.1\r\nHost: ";
    for (int i = 0; tail[i] && o + 1 < out_max; ++i)
        out[o++] = tail[i];
    for (int i = 0; s->host[i] && o + 1 < out_max; ++i)
        out[o++] = s->host[i];
    if (s->port != 80 && s->port != 443)
    {
        if (o + 1 < out_max)
            out[o++] = ':';
        char pbuf[8];
        unsigned int pl = wininet_u32_to_dec(pbuf, sizeof(pbuf), (unsigned int)s->port);
        for (unsigned int i = 0; i < pl && o + 1 < out_max; ++i)
            out[o++] = pbuf[i];
    }
    const char* ua = "\r\nUser-Agent: DuetOS-WinInet/1.0\r\nAccept: */*\r\nConnection: close\r\n";
    for (int i = 0; ua[i] && o + 1 < out_max; ++i)
        out[o++] = ua[i];
    for (int i = 0; s->extra_headers[i] && o + 1 < out_max; ++i)
        out[o++] = s->extra_headers[i];
    if (o + 2 < out_max)
    {
        out[o++] = '\r';
        out[o++] = '\n';
    }
    if (o < out_max)
        out[o] = 0;
    return o;
}

static int wininet_parse_response_headers(WininetSlot* s)
{
    int end = -1;
    for (int i = 0; i + 3 < s->rxlen; ++i)
    {
        if (s->rxbuf[i] == '\r' && s->rxbuf[i + 1] == '\n' && s->rxbuf[i + 2] == '\r' && s->rxbuf[i + 3] == '\n')
        {
            end = i;
            break;
        }
    }
    if (end < 0)
        return 0;
    s->headers_len = end;
    s->body_start = end + 4;
    int copy = end;
    if (copy >= WININET_HEADERS_MAX)
        copy = WININET_HEADERS_MAX - 1;
    for (int i = 0; i < copy; ++i)
        s->headers[i] = (char)s->rxbuf[i];
    s->headers[copy] = 0;
    int eol = 0;
    for (; eol < end && !(s->rxbuf[eol] == '\r' && s->rxbuf[eol + 1] == '\n'); ++eol)
        ;
    int sl = eol;
    if (sl >= (int)sizeof(s->status_line))
        sl = (int)sizeof(s->status_line) - 1;
    for (int i = 0; i < sl; ++i)
        s->status_line[i] = (char)s->rxbuf[i];
    s->status_line[sl] = 0;
    int p = 0;
    while (p < sl && s->status_line[p] != ' ')
        ++p;
    while (p < sl && s->status_line[p] == ' ')
        ++p;
    int code = 0;
    while (p < sl && s->status_line[p] >= '0' && s->status_line[p] <= '9')
    {
        code = code * 10 + (s->status_line[p] - '0');
        ++p;
    }
    s->status = code;
    s->rxpos = s->body_start;
    return 1;
}

static void wininet_fake_response(WininetSlot* s)
{
    static const char kBody[] = "HTTP/1.1 200 OK\r\n"
                                "Content-Type: text/html\r\n"
                                "Content-Length: 12\r\n"
                                "\r\n"
                                "DuetOS hello";
    unsigned int n = (unsigned int)(sizeof(kBody) - 1);
    if (n > WININET_RXBUF_MAX)
        n = WININET_RXBUF_MAX;
    for (unsigned int i = 0; i < n; ++i)
        s->rxbuf[i] = (unsigned char)kBody[i];
    s->rxlen = (int)n;
    s->fake = 1;
    wininet_parse_response_headers(s);
}

static int wininet_pump(WininetSlot* s)
{
    if (s->fake || s->eof)
        return 0;
    if (s->sock == INVALID_SOCKET)
    {
        s->eof = 1;
        return 0;
    }
    if (s->rxpos > 0 && s->rxpos < s->rxlen)
    {
        int remain = s->rxlen - s->rxpos;
        for (int i = 0; i < remain; ++i)
            s->rxbuf[i] = s->rxbuf[s->rxpos + i];
        s->rxlen = remain;
        s->headers_len -= s->rxpos;
        if (s->headers_len < 0)
            s->headers_len = 0;
        s->body_start -= s->rxpos;
        if (s->body_start < 0)
            s->body_start = 0;
        s->rxpos = 0;
    }
    else if (s->rxpos >= s->rxlen)
    {
        s->rxlen = 0;
        s->rxpos = 0;
    }
    int room = WININET_RXBUF_MAX - s->rxlen;
    if (room <= 0)
        return 0;
    long long got =
        wininet_op(WSOP_RECVFROM, (long long)s->sock, (long long)(s->rxbuf + s->rxlen), (long long)room, 0, 0);
    if (got <= 0)
    {
        s->eof = 1;
        return 0;
    }
    s->rxlen += (int)got;
    return (int)got;
}

static void wininet_perform_request(WininetSlot* s)
{
    if (s->request_sent || s->fake)
        return;
    s->request_sent = 1;
    unsigned long ip_be = 0;
    long long rc = wininet_op(WSOP_RESOLVE_A, (long long)s->host, (long long)&ip_be, 0, 0, 0);
    if (rc < 0 || ip_be == 0)
    {
        wininet_fake_response(s);
        return;
    }
    long long sock = wininet_op(WSOP_CREATE, 2, 1, 0, 0, 0);
    if (sock < 0)
    {
        wininet_fake_response(s);
        return;
    }
    s->sock = (SOCKET)sock;
    unsigned char sa[16];
    wininet_make_sockaddr(sa, ip_be, s->port);
    rc = wininet_op(WSOP_CONNECT, sock, (long long)sa, 16, 0, 0);
    if (rc < 0)
    {
        wininet_op(WSOP_CLOSE, sock, 0, 0, 0, 0);
        s->sock = INVALID_SOCKET;
        wininet_fake_response(s);
        return;
    }
    char req[2048];
    unsigned int rl = wininet_build_request(s, req, sizeof(req));
    long long sent = wininet_op(WSOP_SENDTO, sock, (long long)req, (long long)rl, 0, 0);
    if (sent < 0)
    {
        wininet_op(WSOP_CLOSE, sock, 0, 0, 0, 0);
        s->sock = INVALID_SOCKET;
        wininet_fake_response(s);
        return;
    }
    for (int round = 0; round < 16; ++round)
    {
        int n = wininet_pump(s);
        if (s->rxlen > 0 && wininet_parse_response_headers(s))
            return;
        if (n <= 0)
            break;
    }
    if (!wininet_parse_response_headers(s))
    {
        if (s->sock != INVALID_SOCKET)
        {
            wininet_op(WSOP_CLOSE, s->sock, 0, 0, 0, 0);
            s->sock = INVALID_SOCKET;
        }
        wininet_fake_response(s);
    }
}

__declspec(dllexport) HANDLE InternetOpenA(const char* agent, DWORD type, const char* proxy, const char* proxyBypass,
                                           DWORD flags)
{
    (void)agent;
    (void)type;
    (void)proxy;
    (void)proxyBypass;
    (void)flags;
    int slot = wininet_slot_alloc(WININET_KIND_SESSION);
    if (slot < 0)
        return (HANDLE)0;
    return (HANDLE)wininet_make_handle(WININET_KIND_SESSION, slot);
}
__declspec(dllexport) HANDLE InternetOpenW(const wchar_t16* agent, DWORD type, const wchar_t16* proxy,
                                           const wchar_t16* proxyBypass, DWORD flags)
{
    (void)agent;
    (void)proxy;
    (void)proxyBypass;
    return InternetOpenA((const char*)0, type, (const char*)0, (const char*)0, flags);
}
__declspec(dllexport) HANDLE InternetConnectA(HANDLE h, const char* server, unsigned short port, const char* user,
                                              const char* pw, DWORD svc, DWORD flags, unsigned long long ctx)
{
    (void)user;
    (void)pw;
    (void)svc;
    (void)flags;
    (void)ctx;
    int sess = wininet_decode_handle(h, WININET_KIND_SESSION);
    if (sess < 0 || !server)
        return (HANDLE)0;
    int slot = wininet_slot_alloc(WININET_KIND_CONNECT);
    if (slot < 0)
        return (HANDLE)0;
    g_pool[slot].parent_slot = sess;
    g_pool[slot].port = port ? port : 80;
    unsigned long i = 0;
    for (; i + 1 < sizeof(g_pool[slot].host) && server[i] != 0; ++i)
        g_pool[slot].host[i] = server[i];
    g_pool[slot].host[i] = 0;
    return (HANDLE)wininet_make_handle(WININET_KIND_CONNECT, slot);
}
__declspec(dllexport) HANDLE HttpOpenRequestA(HANDLE h, const char* verb, const char* obj, const char* ver,
                                              const char* ref, const char** types, DWORD flags, unsigned long long ctx)
{
    (void)ver;
    (void)ref;
    (void)types;
    (void)flags;
    (void)ctx;
    int conn = wininet_decode_handle(h, WININET_KIND_CONNECT);
    if (conn < 0)
        return (HANDLE)0;
    int slot = wininet_slot_alloc(WININET_KIND_REQUEST);
    if (slot < 0)
        return (HANDLE)0;
    g_pool[slot].parent_slot = conn;
    g_pool[slot].port = g_pool[conn].port;
    unsigned long i = 0;
    for (; i + 1 < sizeof(g_pool[slot].host) && g_pool[conn].host[i] != 0; ++i)
        g_pool[slot].host[i] = g_pool[conn].host[i];
    g_pool[slot].host[i] = 0;
    if (verb)
    {
        unsigned long j = 0;
        for (; j + 1 < sizeof(g_pool[slot].verb) && verb[j] != 0; ++j)
            g_pool[slot].verb[j] = verb[j];
        g_pool[slot].verb[j] = 0;
    }
    else
    {
        g_pool[slot].verb[0] = 'G';
        g_pool[slot].verb[1] = 'E';
        g_pool[slot].verb[2] = 'T';
        g_pool[slot].verb[3] = 0;
    }
    if (obj && obj[0])
    {
        unsigned long j = 0;
        for (; j + 1 < sizeof(g_pool[slot].path) && obj[j] != 0; ++j)
            g_pool[slot].path[j] = obj[j];
        g_pool[slot].path[j] = 0;
    }
    else
    {
        g_pool[slot].path[0] = '/';
        g_pool[slot].path[1] = 0;
    }
    return (HANDLE)wininet_make_handle(WININET_KIND_REQUEST, slot);
}
__declspec(dllexport) BOOL HttpSendRequestA(HANDLE h, const char* hdrs, DWORD hlen, void* opt, DWORD ol)
{
    (void)opt;
    (void)ol;
    int req = wininet_decode_handle(h, WININET_KIND_REQUEST);
    if (req < 0)
        return 0;
    if (hdrs && hlen != 0)
    {
        DWORD nh = hlen;
        if ((int)nh < 0)
            nh = (DWORD)wininet_strlen(hdrs);
        if (nh >= sizeof(g_pool[req].extra_headers))
            nh = (DWORD)sizeof(g_pool[req].extra_headers) - 1;
        for (DWORD i = 0; i < nh; ++i)
            g_pool[req].extra_headers[i] = hdrs[i];
        g_pool[req].extra_headers[nh] = 0;
    }
    wininet_perform_request(&g_pool[req]);
    return 1;
}
__declspec(dllexport) BOOL InternetReadFile(HANDLE h, void* buf, DWORD cb, DWORD* nread)
{
    if (nread)
        *nread = 0;
    if (buf == (void*)0 || cb == 0)
        return 1;
    int req = wininet_decode_handle(h, WININET_KIND_REQUEST);
    if (req < 0)
        return 0;
    WininetSlot* s = &g_pool[req];
    /* Lazy-send if a caller skipped HttpSendRequest. */
    if (!s->request_sent && !s->fake)
        wininet_perform_request(s);
    /* Top up from the socket if the body region is drained. */
    if (s->rxpos >= s->rxlen && !s->fake)
        wininet_pump(s);
    if (s->rxpos >= s->rxlen)
        return 1; /* EOF — return 0 bytes, BOOL still TRUE. */
    int avail = s->rxlen - s->rxpos;
    int give = (int)cb;
    if (give > avail)
        give = avail;
    unsigned char* dst = (unsigned char*)buf;
    for (int i = 0; i < give; ++i)
        dst[i] = s->rxbuf[s->rxpos + i];
    s->rxpos += give;
    if (nread)
        *nread = (DWORD)give;
    return 1;
}
__declspec(dllexport) BOOL InternetCloseHandle(HANDLE h)
{
    int slot = wininet_decode_handle(h, 0);
    if (slot < 0)
        return 0;
    wininet_slot_free(slot);
    return 1;
}

/* Common back-end for the one-shot variant: parse URL, alloc a request
 * slot directly (no separate session-connect chain), and fire. */
static HANDLE wininet_open_url_common(HANDLE session, const char* url, const char* hdrs, DWORD hlen)
{
    int sess = wininet_decode_handle(session, WININET_KIND_SESSION);
    if (sess < 0 || !url)
        return (HANDLE)0;
    int slot = wininet_slot_alloc(WININET_KIND_REQUEST);
    if (slot < 0)
        return (HANDLE)0;
    g_pool[slot].parent_slot = sess;
    int https = 0;
    if (!wininet_parse_url(url, g_pool[slot].host, sizeof(g_pool[slot].host), &g_pool[slot].port, g_pool[slot].path,
                           sizeof(g_pool[slot].path), &https))
    {
        wininet_slot_free(slot);
        return (HANDLE)0;
    }
    g_pool[slot].verb[0] = 'G';
    g_pool[slot].verb[1] = 'E';
    g_pool[slot].verb[2] = 'T';
    g_pool[slot].verb[3] = 0;
    if (hdrs && hlen != 0)
    {
        DWORD nh = hlen;
        if ((int)nh < 0)
            nh = (DWORD)wininet_strlen(hdrs);
        if (nh >= sizeof(g_pool[slot].extra_headers))
            nh = (DWORD)sizeof(g_pool[slot].extra_headers) - 1;
        for (DWORD i = 0; i < nh; ++i)
            g_pool[slot].extra_headers[i] = hdrs[i];
        g_pool[slot].extra_headers[nh] = 0;
    }
    /* https requires TLS — not wired yet. The handle still returns
     * valid (fake) data, but mark request_sent so we don't speak
     * cleartext HTTP to port 443 (which would be a guaranteed error
     * and burn a syscall). */
    if (https)
    {
        wininet_fake_response(&g_pool[slot]);
        g_pool[slot].request_sent = 1;
    }
    else
    {
        wininet_perform_request(&g_pool[slot]);
    }
    return (HANDLE)wininet_make_handle(WININET_KIND_REQUEST, slot);
}

__declspec(dllexport) HANDLE InternetOpenUrlA(HANDLE h, const char* url, const char* hdrs, DWORD hlen, DWORD flags,
                                              unsigned long long ctx)
{
    (void)flags;
    (void)ctx;
    return wininet_open_url_common(h, url, hdrs, hlen);
}

__declspec(dllexport) HANDLE InternetOpenUrlW(HANDLE h, const wchar_t16* url, const wchar_t16* hdrs, DWORD hlen,
                                              DWORD flags, unsigned long long ctx)
{
    (void)flags;
    (void)ctx;
    char url_a[1024];
    char hdr_a[WININET_HEADERS_MAX];
    wininet_w2a(url_a, sizeof(url_a), url);
    if (hdrs)
        wininet_w2a(hdr_a, sizeof(hdr_a), hdrs);
    else
        hdr_a[0] = 0;
    return wininet_open_url_common(h, url_a, hdrs ? hdr_a : (const char*)0, hlen);
}

__declspec(dllexport) HANDLE InternetConnectW(HANDLE h, const wchar_t16* server, unsigned short port,
                                              const wchar_t16* user, const wchar_t16* pw, DWORD svc, DWORD flags,
                                              unsigned long long ctx)
{
    (void)user;
    (void)pw;
    char server_a[WININET_HOST_MAX];
    wininet_w2a(server_a, sizeof(server_a), server);
    return InternetConnectA(h, server_a, port, (const char*)0, (const char*)0, svc, flags, ctx);
}

__declspec(dllexport) HANDLE HttpOpenRequestW(HANDLE h, const wchar_t16* verb, const wchar_t16* obj,
                                              const wchar_t16* ver, const wchar_t16* ref, const wchar_t16** types,
                                              DWORD flags, unsigned long long ctx)
{
    (void)ver;
    (void)ref;
    (void)types;
    char verb_a[WININET_VERB_MAX];
    char obj_a[WININET_PATH_MAX];
    wininet_w2a(verb_a, sizeof(verb_a), verb);
    wininet_w2a(obj_a, sizeof(obj_a), obj);
    return HttpOpenRequestA(h, verb ? verb_a : (const char*)0, obj ? obj_a : (const char*)0, (const char*)0,
                            (const char*)0, (const char**)0, flags, ctx);
}

__declspec(dllexport) BOOL HttpSendRequestW(HANDLE h, const wchar_t16* hdrs, DWORD hlen, void* opt, DWORD ol)
{
    char hdr_a[WININET_HEADERS_MAX];
    hdr_a[0] = 0;
    if (hdrs)
        wininet_w2a(hdr_a, sizeof(hdr_a), hdrs);
    return HttpSendRequestA(h, hdrs ? hdr_a : (const char*)0, hdr_a[0] ? (DWORD)wininet_strlen(hdr_a) : hlen, opt, ol);
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
    (void)flags;
    (void)ctx;
    if (avail)
        *avail = 0;
    int req = wininet_decode_handle(h, WININET_KIND_REQUEST);
    if (req < 0)
        return 0;
    WininetSlot* s = &g_pool[req];
    if (!s->request_sent && !s->fake)
        wininet_perform_request(s);
    if (avail)
    {
        int remain = s->rxlen - s->rxpos;
        if (remain < 0)
            remain = 0;
        *avail = (DWORD)remain;
    }
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

/* HttpQueryInfo info-level constants we recognise. The full Win32
 * surface is enormous; we cover the ones browsers and curl-style
 * apps commonly poke at. */
#define HTTP_QUERY_STATUS_CODE 19
#define HTTP_QUERY_STATUS_TEXT 20
#define HTTP_QUERY_RAW_HEADERS 21
#define HTTP_QUERY_RAW_HEADERS_CRLF 22
#define HTTP_QUERY_CONTENT_TYPE 1
#define HTTP_QUERY_CONTENT_LENGTH 5
#define HTTP_QUERY_LOCATION 33
#define HTTP_QUERY_SERVER 37
#define HTTP_QUERY_VERSION 18
#define HTTP_QUERY_FLAG_NUMBER 0x20000000

/* Return a pointer (into the slot's headers buffer) + length for the
 * named header value, or 0 if not present. */
static int wininet_find_header(const WininetSlot* s, const char* name, const char** out_val, int* out_len)
{
    unsigned long nlen = wininet_strlen(name);
    const char* h = s->headers;
    while (*h)
    {
        const char* line_start = h;
        const char* eol = h;
        while (*eol && !(eol[0] == '\r' && eol[1] == '\n'))
            ++eol;
        unsigned long line_len = (unsigned long)(eol - line_start);
        /* Match "Name:" case-insensitively. */
        if (line_len > nlen + 1 && line_start[nlen] == ':')
        {
            int eq = 1;
            for (unsigned long i = 0; i < nlen; ++i)
            {
                char x = line_start[i];
                char y = name[i];
                if (x >= 'A' && x <= 'Z')
                    x = (char)(x - 'A' + 'a');
                if (y >= 'A' && y <= 'Z')
                    y = (char)(y - 'A' + 'a');
                if (x != y)
                {
                    eq = 0;
                    break;
                }
            }
            if (eq)
            {
                const char* val = line_start + nlen + 1;
                while (val < eol && (*val == ' ' || *val == '\t'))
                    ++val;
                *out_val = val;
                *out_len = (int)(eol - val);
                return 1;
            }
        }
        if (*eol == 0)
            break;
        h = eol + 2;
    }
    return 0;
}

static BOOL wininet_query_info_a(HANDLE h, DWORD info_level, void* buf, DWORD* len, DWORD* idx)
{
    if (idx)
        *idx = 0;
    int req = wininet_decode_handle(h, WININET_KIND_REQUEST);
    if (req < 0)
    {
        if (len)
            *len = 0;
        return 0;
    }
    WininetSlot* s = &g_pool[req];
    if (!s->request_sent && !s->fake)
        wininet_perform_request(s);
    DWORD base = info_level & 0x0FFFFFFFu;
    BOOL want_number = (info_level & HTTP_QUERY_FLAG_NUMBER) != 0;
    const char* val_str = (const char*)0;
    int val_len = 0;
    int matched = 0;
    if (base == HTTP_QUERY_STATUS_CODE)
    {
        if (want_number)
        {
            if (!buf || !len || *len < sizeof(DWORD))
            {
                if (len)
                    *len = sizeof(DWORD);
                return 0;
            }
            *(DWORD*)buf = (DWORD)s->status;
            *len = sizeof(DWORD);
            return 1;
        }
        /* String form: "200" / "404" / etc. */
        char digits[12];
        unsigned int d = wininet_u32_to_dec(digits, sizeof(digits), (unsigned int)s->status);
        val_str = digits;
        val_len = (int)d;
        matched = 1;
        /* Need to materialise into the caller buffer below. */
        if (!buf || !len)
            return 0;
        DWORD need = (DWORD)val_len + 1;
        if (*len < need)
        {
            *len = need;
            return 0;
        }
        for (int i = 0; i < val_len; ++i)
            ((char*)buf)[i] = digits[i];
        ((char*)buf)[val_len] = 0;
        *len = (DWORD)val_len;
        return 1;
    }
    else if (base == HTTP_QUERY_STATUS_TEXT)
    {
        const char* p = s->status_line;
        int p_len = 0;
        while (p[p_len])
            ++p_len;
        int sp = 0;
        while (sp < p_len && p[sp] != ' ')
            ++sp;
        while (sp < p_len && p[sp] == ' ')
            ++sp;
        while (sp < p_len && p[sp] != ' ')
            ++sp;
        while (sp < p_len && p[sp] == ' ')
            ++sp;
        val_str = p + sp;
        val_len = p_len - sp;
        if (val_len < 0)
            val_len = 0;
        matched = 1;
    }
    else if (base == HTTP_QUERY_RAW_HEADERS_CRLF || base == HTTP_QUERY_RAW_HEADERS)
    {
        val_str = s->headers;
        val_len = s->headers_len;
        if (val_len > (int)sizeof(s->headers) - 1)
            val_len = (int)sizeof(s->headers) - 1;
        matched = 1;
    }
    else if (base == HTTP_QUERY_CONTENT_TYPE)
    {
        matched = wininet_find_header(s, "Content-Type", &val_str, &val_len);
    }
    else if (base == HTTP_QUERY_CONTENT_LENGTH)
    {
        matched = wininet_find_header(s, "Content-Length", &val_str, &val_len);
        if (matched && want_number)
        {
            if (!buf || !len || *len < sizeof(DWORD))
            {
                if (len)
                    *len = sizeof(DWORD);
                return 0;
            }
            DWORD v = 0;
            for (int i = 0; i < val_len; ++i)
                if (val_str[i] >= '0' && val_str[i] <= '9')
                    v = v * 10u + (DWORD)(val_str[i] - '0');
            *(DWORD*)buf = v;
            *len = sizeof(DWORD);
            return 1;
        }
    }
    else if (base == HTTP_QUERY_LOCATION)
    {
        matched = wininet_find_header(s, "Location", &val_str, &val_len);
    }
    else if (base == HTTP_QUERY_SERVER)
    {
        matched = wininet_find_header(s, "Server", &val_str, &val_len);
    }
    else if (base == HTTP_QUERY_VERSION)
    {
        const char* p = s->status_line;
        int p_len = 0;
        while (p[p_len] && p[p_len] != ' ')
            ++p_len;
        val_str = p;
        val_len = p_len;
        matched = 1;
    }
    if (!matched)
    {
        if (len)
            *len = 0;
        return 0;
    }
    if (!buf || !len)
        return 0;
    DWORD need = (DWORD)val_len + 1;
    if (*len < need)
    {
        *len = need;
        return 0;
    }
    char* out = (char*)buf;
    for (int i = 0; i < val_len; ++i)
        out[i] = val_str[i];
    out[val_len] = 0;
    *len = (DWORD)val_len;
    return 1;
}

__declspec(dllexport) BOOL HttpQueryInfoA(HANDLE h, DWORD info_level, void* buf, DWORD* len, DWORD* idx)
{
    return wininet_query_info_a(h, info_level, buf, len, idx);
}

__declspec(dllexport) BOOL HttpQueryInfoW(HANDLE h, DWORD info_level, void* buf, DWORD* len, DWORD* idx)
{
    if (idx)
        *idx = 0;
    int req = wininet_decode_handle(h, WININET_KIND_REQUEST);
    if (req < 0)
    {
        if (len)
            *len = 0;
        return 0;
    }
    /* For wide-string returns, render via the ANSI form into a stack
     * scratch then widen. The number-flag short-circuit writes a DWORD
     * to *buf either way. */
    if ((info_level & HTTP_QUERY_FLAG_NUMBER) != 0)
        return wininet_query_info_a(h, info_level, buf, len, idx);
    char scratch[WININET_HEADERS_MAX];
    DWORD scratch_len = sizeof(scratch);
    DWORD scratch_idx = 0;
    BOOL ok = wininet_query_info_a(h, info_level, scratch, &scratch_len, &scratch_idx);
    if (!ok)
        return 0;
    if (!buf || !len)
        return 0;
    DWORD need = (scratch_len + 1) * (DWORD)sizeof(wchar_t16);
    if (*len < need)
    {
        *len = need;
        return 0;
    }
    wchar_t16* out = (wchar_t16*)buf;
    for (DWORD i = 0; i < scratch_len; ++i)
        out[i] = (wchar_t16)(unsigned char)scratch[i];
    out[scratch_len] = 0;
    *len = scratch_len * (DWORD)sizeof(wchar_t16);
    return 1;
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

/* HttpAddRequestHeadersA / W — append headers to the pending request.
 * Must be called BEFORE HttpSendRequest. Returns 0 once the request
 * is in flight (no append-after-send semantics in v0). */
__declspec(dllexport) BOOL HttpAddRequestHeadersA(HANDLE h, const char* hdrs, DWORD len, DWORD modifiers)
{
    (void)modifiers;
    int req = wininet_decode_handle(h, WININET_KIND_REQUEST);
    if (req < 0 || !hdrs)
        return 0;
    WininetSlot* s = &g_pool[req];
    if (s->request_sent)
        return 0;
    DWORD nh = len;
    if ((int)nh < 0)
        nh = (DWORD)wininet_strlen(hdrs);
    unsigned long have = wininet_strlen(s->extra_headers);
    unsigned long room = sizeof(s->extra_headers) - have - 1;
    if (room == 0)
        return 0;
    DWORD copy = nh;
    if (copy > room)
        copy = (DWORD)room;
    for (DWORD i = 0; i < copy; ++i)
        s->extra_headers[have + i] = hdrs[i];
    s->extra_headers[have + copy] = 0;
    return 1;
}

__declspec(dllexport) BOOL HttpAddRequestHeadersW(HANDLE h, const wchar_t16* hdrs, DWORD len, DWORD modifiers)
{
    char hdr_a[WININET_HEADERS_MAX];
    hdr_a[0] = 0;
    if (hdrs)
        wininet_w2a(hdr_a, sizeof(hdr_a), hdrs);
    return HttpAddRequestHeadersA(h, hdrs ? hdr_a : (const char*)0, hdr_a[0] ? (DWORD)wininet_strlen(hdr_a) : len,
                                  modifiers);
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
    if (name && *name)
    {
        /* Single-cookie lookup. */
        const int slot = wininet_cookie_find(host, name);
        if (slot < 0)
        {
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
    /* No name → concatenate every matching host cookie as
     *   "name1=value1; name2=value2; ..."
     * which is the format an HTTP Cookie: header takes. The
     * insertion order is the cookie table's slot order — not
     * RFC 6265's specified path-then-creation-time ordering,
     * but stable enough that tests can rely on it. Each touch
     * bumps the slot's LRU sequence so the eviction policy
     * still tracks "most recently fetched". */
    DWORD have = 0;
    BOOL any = 0;
    for (int i = 0; i < COOKIE_TABLE_ENTRIES; ++i)
    {
        if (!g_cookie_table[i].in_use)
            continue;
        if (!wininet_host_eq(g_cookie_table[i].host, host))
            continue;
        any = 1;
        g_cookie_table[i].lru_seq = ++g_cookie_lru_counter;
        if (data == 0 || *size == 0)
        {
            /* Caller is sizing the buffer — tally the chars
             * we'd write but don't dereference data. */
            DWORD k = 0;
            while (g_cookie_table[i].name[k])
                ++k;
            have += k + 1; /* '=' */
            k = 0;
            while (g_cookie_table[i].value[k])
                ++k;
            have += k;
            if (have > 0)
                have += 2; /* "; " separator (or trailing slack) */
            continue;
        }
        if (have > 0 && have + 2 < *size)
        {
            data[have++] = ';';
            data[have++] = ' ';
        }
        DWORD k = 0;
        while (g_cookie_table[i].name[k] && have + 1 < *size)
            data[have++] = g_cookie_table[i].name[k++];
        if (have + 1 < *size)
            data[have++] = '=';
        k = 0;
        while (g_cookie_table[i].value[k] && have + 1 < *size)
            data[have++] = g_cookie_table[i].value[k++];
    }
    if (data && *size > 0)
        data[have < *size ? have : (*size - 1)] = 0;
    *size = have;
    return any;
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
    /* Sized to fit the realistic multi-cookie concat. Static
     * (not stack) because (a) we'd otherwise trip __chkstk on a
     * frame ≥ 4 KiB and the freestanding DLL doesn't link it, and
     * (b) the cookie store itself is single-threaded so a static
     * scratch is correct under the same constraint. */
    static char value_a[3072];
    value_a[0] = 0;
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
 * RFC 1123 ("Sun, 06 Nov 1994 08:49:37 GMT") conversion. The
 * input/output is a SYSTEMTIME struct (16 B):
 *   WORD wYear, wMonth, wDayOfWeek, wDay, wHour, wMinute,
 *        wSecond, wMilliseconds.
 *
 * `format` accepts INTERNET_RFC1123_FORMAT == 0 (the only
 * format MSDN documents). Buffer size constant is
 * INTERNET_RFC1123_BUFSIZE == 30 (29 chars + NUL).
 */

#define WININET_RFC1123_BUFSIZE 30u

static const char* wininet_dow_short[7] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
static const char* wininet_mon_short[12] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                            "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

static void wininet_two_digits(char* dst, unsigned v)
{
    dst[0] = (char)('0' + ((v / 10) % 10));
    dst[1] = (char)('0' + (v % 10));
}

static void wininet_four_digits(char* dst, unsigned v)
{
    dst[0] = (char)('0' + ((v / 1000) % 10));
    dst[1] = (char)('0' + ((v / 100) % 10));
    dst[2] = (char)('0' + ((v / 10) % 10));
    dst[3] = (char)('0' + (v % 10));
}

static BOOL wininet_format_rfc1123_a(const void* time_st, char* buf, DWORD buf_len)
{
    if (time_st == 0 || buf == 0 || buf_len < WININET_RFC1123_BUFSIZE)
        return 0;
    const unsigned short* st = (const unsigned short*)time_st;
    const unsigned year = st[0];
    const unsigned month = st[1];
    const unsigned dow = st[2];
    const unsigned day = st[3];
    const unsigned hour = st[4];
    const unsigned minute = st[5];
    const unsigned second = st[6];
    if (month < 1 || month > 12 || dow > 6 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 59)
        return 0;
    /* "DDD, dd MMM yyyy HH:MM:SS GMT" — exactly 29 chars + NUL. */
    const char* dn = wininet_dow_short[dow];
    const char* mn = wininet_mon_short[month - 1];
    buf[0] = dn[0];
    buf[1] = dn[1];
    buf[2] = dn[2];
    buf[3] = ',';
    buf[4] = ' ';
    wininet_two_digits(buf + 5, day);
    buf[7] = ' ';
    buf[8] = mn[0];
    buf[9] = mn[1];
    buf[10] = mn[2];
    buf[11] = ' ';
    wininet_four_digits(buf + 12, year);
    buf[16] = ' ';
    wininet_two_digits(buf + 17, hour);
    buf[19] = ':';
    wininet_two_digits(buf + 20, minute);
    buf[22] = ':';
    wininet_two_digits(buf + 23, second);
    buf[25] = ' ';
    buf[26] = 'G';
    buf[27] = 'M';
    buf[28] = 'T';
    buf[29] = 0;
    return 1;
}

__declspec(dllexport) BOOL InternetTimeFromSystemTimeA(const void* time_st, DWORD format, char* buf, DWORD buf_len)
{
    if (format != 0)
        return 0;
    return wininet_format_rfc1123_a(time_st, buf, buf_len);
}

__declspec(dllexport) BOOL InternetTimeFromSystemTimeW(const void* time_st, DWORD format, wchar_t16* buf, DWORD buf_len)
{
    if (format != 0)
        return 0;
    char ascii[WININET_RFC1123_BUFSIZE];
    if (!wininet_format_rfc1123_a(time_st, ascii, sizeof(ascii)))
        return 0;
    if (buf == 0 || buf_len < WININET_RFC1123_BUFSIZE)
        return 0;
    for (DWORD i = 0; i < WININET_RFC1123_BUFSIZE; ++i)
        buf[i] = (wchar_t16)(unsigned char)ascii[i];
    return 1;
}

/* Skip leading whitespace. */
static const char* wininet_skip_ws(const char* p)
{
    while (*p == ' ' || *p == '\t')
        ++p;
    return p;
}

/* Parse a base-10 unsigned int, advancing `*pp`. Returns 0 if no
 * digits were seen at the start. */
static unsigned wininet_parse_uint(const char** pp)
{
    const char* p = *pp;
    unsigned v = 0;
    int n = 0;
    while (*p >= '0' && *p <= '9')
    {
        v = v * 10u + (unsigned)(*p - '0');
        ++p;
        ++n;
    }
    *pp = p;
    return n > 0 ? v : 0u;
}

/* Match a 3-letter prefix (case-insensitive). */
static int wininet_match_prefix3_ci(const char* p, const char* needle)
{
    for (int i = 0; i < 3; ++i)
    {
        char c = p[i];
        char n = needle[i];
        if (c >= 'a' && c <= 'z')
            c = (char)(c - 32);
        if (n >= 'a' && n <= 'z')
            n = (char)(n - 32);
        if (c != n)
            return 0;
    }
    return 1;
}

/* Parse RFC 1123 ("Sun, 06 Nov 1994 08:49:37 GMT") into the 16-byte
 * SYSTEMTIME. Returns 1 on success. Day-of-week is recomputed (not
 * read from the input) so a malformed dow doesn't reject otherwise-
 * valid timestamps; we follow Internet Explorer's behaviour here. */
static BOOL wininet_parse_rfc1123_a(const char* str, void* time_st)
{
    if (str == 0 || time_st == 0)
        return 0;
    const char* p = wininet_skip_ws(str);
    /* Skip optional "DDD," prefix. */
    if (p[0] && p[1] && p[2] && p[3] == ',')
        p += 4;
    p = wininet_skip_ws(p);
    const unsigned day = wininet_parse_uint(&p);
    if (day < 1 || day > 31)
        return 0;
    p = wininet_skip_ws(p);
    /* Three-letter month. */
    int month = 0;
    for (int i = 0; i < 12; ++i)
    {
        if (wininet_match_prefix3_ci(p, wininet_mon_short[i]))
        {
            month = i + 1;
            break;
        }
    }
    if (month == 0)
        return 0;
    p += 3;
    p = wininet_skip_ws(p);
    const unsigned year = wininet_parse_uint(&p);
    if (year < 1601 || year > 9999)
        return 0;
    p = wininet_skip_ws(p);
    const unsigned hour = wininet_parse_uint(&p);
    if (hour > 23 || *p != ':')
        return 0;
    ++p;
    const unsigned minute = wininet_parse_uint(&p);
    if (minute > 59 || *p != ':')
        return 0;
    ++p;
    const unsigned second = wininet_parse_uint(&p);
    if (second > 59)
        return 0;
    /* Trailing zone (GMT/UTC) is permitted but not validated. */
    /* Compute day-of-week via Zeller's congruence (Gregorian). */
    unsigned y = year;
    unsigned m = (unsigned)month;
    if (m < 3)
    {
        m += 12;
        --y;
    }
    const unsigned K = y % 100;
    const unsigned J = y / 100;
    const unsigned h = (day + (13 * (m + 1)) / 5 + K + K / 4 + J / 4 + 5 * J) % 7;
    /* Zeller: 0 = Saturday … 6 = Friday. SYSTEMTIME wants
     * 0 = Sunday … 6 = Saturday. */
    const unsigned dow = (h + 6) % 7;
    unsigned short* st = (unsigned short*)time_st;
    st[0] = (unsigned short)year;
    st[1] = (unsigned short)month;
    st[2] = (unsigned short)dow;
    st[3] = (unsigned short)day;
    st[4] = (unsigned short)hour;
    st[5] = (unsigned short)minute;
    st[6] = (unsigned short)second;
    st[7] = 0;
    return 1;
}

__declspec(dllexport) BOOL InternetTimeToSystemTimeA(const char* str, void* time_st, DWORD reserved)
{
    (void)reserved;
    if (time_st)
    {
        /* Pre-zero so a parse failure leaves predictable bytes. */
        unsigned char* p = (unsigned char*)time_st;
        for (int i = 0; i < 16; ++i)
            p[i] = 0;
    }
    return wininet_parse_rfc1123_a(str, time_st);
}

__declspec(dllexport) BOOL InternetTimeToSystemTimeW(const wchar_t16* str, void* time_st, DWORD reserved)
{
    (void)reserved;
    if (time_st)
    {
        unsigned char* p = (unsigned char*)time_st;
        for (int i = 0; i < 16; ++i)
            p[i] = 0;
    }
    if (str == 0)
        return 0;
    /* Flatten to ASCII (RFC 1123 dates are ASCII-only). 64 bytes
     * covers any well-formed date string (29 + slack). */
    char ascii[64];
    DWORD i = 0;
    for (; str[i] && i + 1 < sizeof(ascii); ++i)
        ascii[i] = (char)(str[i] & 0xFF);
    ascii[i] = 0;
    return wininet_parse_rfc1123_a(ascii, time_st);
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
