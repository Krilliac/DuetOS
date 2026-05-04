/*
 * winhttp.dll — modern HTTP client. v0 returns sentinel handles
 * so callers can drive Open → Connect → Request → Send → Receive
 * → Read → Close without trapping. Real HTTP transport over
 * ws2_32 deferred to a later slice.
 *
 * Sentinel values:
 *   0x5001 — session
 *   0x5002 — connection
 *   0x5003 — request
 */
typedef int BOOL;
typedef unsigned int DWORD;
typedef void* HANDLE;
typedef unsigned short wchar_t16;

#define WHTTP_SESSION ((HANDLE)0x5001)
#define WHTTP_CONNECT ((HANDLE)0x5002)
#define WHTTP_REQUEST ((HANDLE)0x5003)

__declspec(dllexport) HANDLE WinHttpOpen(const wchar_t16* agent, DWORD accessType, const wchar_t16* proxy,
                                         const wchar_t16* bypass, DWORD flags)
{
    (void)agent;
    (void)accessType;
    (void)proxy;
    (void)bypass;
    (void)flags;
    return WHTTP_SESSION;
}
__declspec(dllexport) HANDLE WinHttpConnect(HANDLE h, const wchar_t16* server, unsigned short port, DWORD rsv)
{
    (void)h;
    (void)server;
    (void)port;
    (void)rsv;
    return WHTTP_CONNECT;
}
__declspec(dllexport) HANDLE WinHttpOpenRequest(HANDLE h, const wchar_t16* verb, const wchar_t16* obj,
                                                const wchar_t16* ver, const wchar_t16* ref, const wchar_t16** types,
                                                DWORD flags)
{
    (void)h;
    (void)verb;
    (void)obj;
    (void)ver;
    (void)ref;
    (void)types;
    (void)flags;
    return WHTTP_REQUEST;
}
__declspec(dllexport) BOOL WinHttpSendRequest(HANDLE h, const wchar_t16* hdrs, DWORD hlen, void* opt, DWORD ol,
                                              DWORD total, unsigned long long ctx)
{
    (void)h;
    (void)hdrs;
    (void)hlen;
    (void)opt;
    (void)ol;
    (void)total;
    (void)ctx;
    return 1;
}
__declspec(dllexport) BOOL WinHttpReceiveResponse(HANDLE h, void* rsv)
{
    (void)h;
    (void)rsv;
    return 1;
}
/* WinHttpReadData — synthesise a small fixed body on the first
 * read of each handle, EOF on subsequent reads. Mirrors the
 * Wininet equivalent; real WinHttp transport over ws2_32 lands
 * with the same slice that wires Wininet for real. */
static unsigned char g_winhttp_eof_seen[16];

__declspec(dllexport) BOOL WinHttpReadData(HANDLE h, void* buf, DWORD cb, DWORD* read)
{
    if (read)
        *read = 0;
    if (buf == (void*)0 || cb == 0)
        return 1;
    unsigned slot = ((unsigned long long)h) & 0xF;
    if (g_winhttp_eof_seen[slot])
        return 1;
    static const char kBody[] = "DuetOS WinHttp hello";
    DWORD bodylen = (DWORD)(sizeof(kBody) - 1);
    DWORD copy = (cb < bodylen) ? cb : bodylen;
    unsigned char* dst = (unsigned char*)buf;
    for (DWORD i = 0; i < copy; ++i)
        dst[i] = (unsigned char)kBody[i];
    if (read)
        *read = copy;
    g_winhttp_eof_seen[slot] = 1;
    return 1;
}
__declspec(dllexport) BOOL WinHttpCloseHandle(HANDLE h)
{
    (void)h;
    return 1;
}

__declspec(dllexport) BOOL WinHttpQueryDataAvailable(HANDLE h, DWORD* avail)
{
    (void)h;
    if (avail)
        *avail = 0;
    return 0;
}

__declspec(dllexport) BOOL WinHttpQueryHeaders(HANDLE h, DWORD info_level, const wchar_t16* name, void* buf, DWORD* len,
                                               DWORD* idx)
{
    (void)h;
    (void)info_level;
    (void)name;
    (void)buf;
    if (len)
        *len = 0;
    if (idx)
        *idx = 0;
    return 0;
}

__declspec(dllexport) BOOL WinHttpAddRequestHeaders(HANDLE h, const wchar_t16* hdrs, DWORD len, DWORD modifiers)
{
    (void)h;
    (void)hdrs;
    (void)len;
    (void)modifiers;
    return 1;
}

__declspec(dllexport) BOOL WinHttpSetOption(HANDLE h, DWORD opt, const void* val, DWORD len)
{
    (void)h;
    (void)opt;
    (void)val;
    (void)len;
    return 1;
}

__declspec(dllexport) BOOL WinHttpQueryOption(HANDLE h, DWORD opt, void* val, DWORD* len)
{
    (void)h;
    (void)opt;
    (void)val;
    if (len)
        *len = 0;
    return 0;
}

__declspec(dllexport) BOOL WinHttpSetTimeouts(HANDLE h, int resolve, int connect, int send, int receive)
{
    (void)h;
    (void)resolve;
    (void)connect;
    (void)send;
    (void)receive;
    return 1;
}

__declspec(dllexport) BOOL WinHttpSetStatusCallback(HANDLE h, void* cb, DWORD flags, unsigned long long rsv)
{
    (void)h;
    (void)cb;
    (void)flags;
    (void)rsv;
    return 1;
}

__declspec(dllexport) BOOL WinHttpCheckPlatform(void)
{
    return 1;
}

/* URL_COMPONENTS layout (Win32):
 *   +0   DWORD dwStructSize
 *   +8   LPWSTR lpszScheme
 *   +16  DWORD  dwSchemeLength
 *   +20  INTERNET_SCHEME nScheme
 *   +24  LPWSTR lpszHostName
 *   +32  DWORD  dwHostNameLength
 *   +36  WORD   nPort
 *   +40  LPWSTR lpszUserName
 *   +48  DWORD  dwUserNameLength
 *   +56  LPWSTR lpszPassword
 *   +64  DWORD  dwPasswordLength
 *   +72  LPWSTR lpszUrlPath
 *   +80  DWORD  dwUrlPathLength
 *   +88  LPWSTR lpszExtraInfo
 *   +96  DWORD  dwExtraInfoLength
 *
 * For each (lpsz, dwLen) pair the documented protocol is:
 *   - if lpsz is NULL: caller wants the lengths only.
 *   - if lpsz is non-NULL && dwLen == 0: lpsz is a NUL-terminated
 *     output buffer; we set lpsz to point at the URL substring and
 *     write the length to dwLen.
 * v0 implements "pointer-into-URL" for both modes (real WinHTTP
 * also uses this protocol — the URL string must remain live until
 * the components are consumed).
 */
__declspec(dllexport) BOOL WinHttpCrackUrl(const wchar_t16* url, DWORD len, DWORD flags, void* components)
{
    (void)flags;
    if (!url || !components)
        return 0;
    if (len == 0)
        for (len = 0; url[len]; ++len)
            ;
    DWORD i = 0;
    /* Scheme: chars up to ':' followed by "//". */
    DWORD scheme_off = 0;
    DWORD scheme_len = 0;
    int n_scheme = 0; /* INTERNET_SCHEME_HTTP = 1, HTTPS = 2, FTP = 3, FILE = 6 */
    DWORD port_default = 80;
    while (i < len && url[i] != ':')
        ++i;
    if (i + 2 < len && url[i] == ':' && url[i + 1] == '/' && url[i + 2] == '/')
    {
        scheme_len = i;
        /* Sniff scheme name. */
        if (scheme_len == 4 && (url[0] == 'h' || url[0] == 'H'))
        {
            n_scheme = 1; /* http */
            port_default = 80;
        }
        else if (scheme_len == 5 && (url[0] == 'h' || url[0] == 'H'))
        {
            n_scheme = 2; /* https */
            port_default = 443;
        }
        else if (scheme_len == 3 && (url[0] == 'f' || url[0] == 'F') && (url[1] == 't' || url[1] == 'T'))
        {
            n_scheme = 3; /* ftp */
            port_default = 21;
        }
        else if (scheme_len == 4 && (url[0] == 'f' || url[0] == 'F'))
        {
            n_scheme = 6; /* file */
            port_default = 0;
        }
        i += 3;
    }
    else
    {
        i = 0;
    }
    /* Optional userinfo: chars up to '@', stop at '/' or '?' or '#'. */
    DWORD user_off = 0, user_len = 0;
    DWORD pass_off = 0, pass_len = 0;
    DWORD scan = i;
    DWORD at_pos = (DWORD)-1;
    while (scan < len && url[scan] != '/' && url[scan] != '?' && url[scan] != '#')
    {
        if (url[scan] == '@')
            at_pos = scan;
        ++scan;
    }
    if (at_pos != (DWORD)-1)
    {
        DWORD colon = (DWORD)-1;
        for (DWORD j = i; j < at_pos; ++j)
        {
            if (url[j] == ':')
            {
                colon = j;
                break;
            }
        }
        if (colon != (DWORD)-1)
        {
            user_off = i;
            user_len = colon - i;
            pass_off = colon + 1;
            pass_len = at_pos - colon - 1;
        }
        else
        {
            user_off = i;
            user_len = at_pos - i;
        }
        i = at_pos + 1;
    }
    /* Host: up to ':' (port), '/' (path), '?' (query), '#' (frag), or end. */
    DWORD host_off = i;
    while (i < len && url[i] != ':' && url[i] != '/' && url[i] != '?' && url[i] != '#')
        ++i;
    DWORD host_len = i - host_off;
    /* Optional port. */
    unsigned short port = (unsigned short)port_default;
    if (i < len && url[i] == ':')
    {
        ++i;
        unsigned int p = 0;
        while (i < len && url[i] >= '0' && url[i] <= '9')
        {
            p = p * 10 + (unsigned int)(url[i] - '0');
            ++i;
        }
        if (p > 0xFFFF)
            p = 0xFFFF;
        port = (unsigned short)p;
    }
    /* Path: up to '?' or '#' or end. */
    DWORD path_off = i;
    while (i < len && url[i] != '?' && url[i] != '#')
        ++i;
    DWORD path_len = i - path_off;
    /* Extra: '?...' or '#...' to end. */
    DWORD extra_off = i;
    DWORD extra_len = len - i;
    /* Write into URL_COMPONENTS. */
    unsigned char* c = (unsigned char*)components;
    /* Helper to write a (ptr, len) pair, honouring the "pointer-into-URL"
     * convention. The component is written iff the structure carried a
     * non-NULL pointer or a non-zero length pre-call. */
    typedef struct
    {
        unsigned char ptr_off;
        unsigned char len_off;
    } Field;
    Field fields[] = {
        {8, 16}, {24, 32}, {40, 48}, {56, 64}, {72, 80}, {88, 96},
    };
    DWORD offs[] = {scheme_off, host_off, user_off, pass_off, path_off, extra_off};
    DWORD lens[] = {scheme_len, host_len, user_len, pass_len, path_len, extra_len};
    for (int f = 0; f < 6; ++f)
    {
        const wchar_t16** pp = (const wchar_t16**)(c + fields[f].ptr_off);
        DWORD* pl = (DWORD*)(c + fields[f].len_off);
        if (*pp == (const wchar_t16*)0 && *pl == 0)
            continue; /* component not requested */
        *pp = (const wchar_t16*)(url + offs[f]);
        *pl = lens[f];
    }
    /* nPort at +36 (WORD). */
    *(unsigned short*)(c + 36) = port;
    /* nScheme at +20 (INTERNET_SCHEME = enum, int-sized). */
    *(int*)(c + 20) = n_scheme;
    return 1;
}

/* WinHttpQueryAuthSchemes — auth-mechanism probe. v0 reports
 * "no auth schemes" so callers fall through to anonymous. */
__declspec(dllexport) BOOL WinHttpQueryAuthSchemes(HANDLE h, DWORD* supported, DWORD* first, DWORD* target)
{
    (void)h;
    if (supported)
        *supported = 0;
    if (first)
        *first = 0;
    if (target)
        *target = 0;
    return 0;
}

__declspec(dllexport) BOOL WinHttpSetCredentials(HANDLE h, DWORD auth_targets, DWORD auth_scheme, const wchar_t16* user,
                                                 const wchar_t16* pass, void* p_auth_params)
{
    (void)h;
    (void)auth_targets;
    (void)auth_scheme;
    (void)user;
    (void)pass;
    (void)p_auth_params;
    return 1;
}

__declspec(dllexport) BOOL WinHttpDetectAutoProxyConfigUrl(DWORD detect_flags, wchar_t16** url)
{
    (void)detect_flags;
    if (url)
        *url = (wchar_t16*)0;
    return 0;
}

__declspec(dllexport) BOOL WinHttpGetIEProxyConfigForCurrentUser(void* config)
{
    if (config)
    {
        unsigned char* p = (unsigned char*)config;
        for (int i = 0; i < 32; ++i)
            p[i] = 0;
    }
    return 1;
}

__declspec(dllexport) BOOL WinHttpGetProxyForUrl(HANDLE session, const wchar_t16* url, void* p_auto_proxy_options,
                                                 void* p_proxy_info)
{
    (void)session;
    (void)url;
    (void)p_auto_proxy_options;
    if (p_proxy_info)
    {
        unsigned char* p = (unsigned char*)p_proxy_info;
        for (int i = 0; i < 24; ++i)
            p[i] = 0;
    }
    return 0;
}

__declspec(dllexport) BOOL WinHttpGetDefaultProxyConfiguration(void* p_proxy_info)
{
    if (p_proxy_info)
    {
        unsigned char* p = (unsigned char*)p_proxy_info;
        for (int i = 0; i < 24; ++i)
            p[i] = 0;
    }
    return 1;
}

__declspec(dllexport) BOOL WinHttpSetDefaultProxyConfiguration(void* p_proxy_info)
{
    (void)p_proxy_info;
    return 1;
}

__declspec(dllexport) BOOL WinHttpResetAutoProxy(HANDLE session, DWORD flags)
{
    (void)session;
    (void)flags;
    return 1;
}

/* WinHttpCreateUrl — assemble URL from components. v0 reports
 * 0-length / failure. */
__declspec(dllexport) BOOL WinHttpCreateUrl(void* components, DWORD flags, wchar_t16* url, DWORD* url_len)
{
    (void)components;
    (void)flags;
    if (url && url_len && *url_len > 0)
        url[0] = 0;
    if (url_len)
        *url_len = 0;
    return 0;
}

/* WinHttpTimeFromSystemTime / WinHttpTimeToSystemTime — RFC 1123
 * date conversion. SYSTEMTIME is 8 WORDs (Year, Month [1-12],
 * DayOfWeek [0=Sun], Day, Hour, Minute, Second, Milliseconds).
 * The HTTP-date string is fixed-width "Wkd, DD Mon YYYY HH:MM:SS GMT"
 * = 29 chars + NUL. The output buffer must accommodate at least
 * WINHTTP_TIME_FORMAT_BUFSIZE (= 62 bytes / 31 wchars per docs). */
static const char* k_dow_short[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
static const char* k_mon_short[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

static int month_index(const char* name)
{
    for (int m = 0; m < 12; ++m)
    {
        if (name[0] == k_mon_short[m][0] && name[1] == k_mon_short[m][1] && name[2] == k_mon_short[m][2])
            return m + 1;
    }
    return 0;
}

__declspec(dllexport) BOOL WinHttpTimeFromSystemTime(const void* time_st, wchar_t16* http_time)
{
    if (!time_st || !http_time)
        return 0;
    const unsigned short* st = (const unsigned short*)time_st;
    unsigned short year = st[0];
    unsigned short month = st[1];
    unsigned short dow = st[2];
    unsigned short day = st[3];
    unsigned short hour = st[4];
    unsigned short min = st[5];
    unsigned short sec = st[6];
    if (month < 1 || month > 12 || dow > 6)
        return 0;
    char buf[32];
    const char* dow_s = k_dow_short[dow];
    const char* mon_s = k_mon_short[month - 1];
    int p = 0;
    buf[p++] = dow_s[0];
    buf[p++] = dow_s[1];
    buf[p++] = dow_s[2];
    buf[p++] = ',';
    buf[p++] = ' ';
    buf[p++] = '0' + (day / 10);
    buf[p++] = '0' + (day % 10);
    buf[p++] = ' ';
    buf[p++] = mon_s[0];
    buf[p++] = mon_s[1];
    buf[p++] = mon_s[2];
    buf[p++] = ' ';
    buf[p++] = '0' + (year / 1000) % 10;
    buf[p++] = '0' + (year / 100) % 10;
    buf[p++] = '0' + (year / 10) % 10;
    buf[p++] = '0' + year % 10;
    buf[p++] = ' ';
    buf[p++] = '0' + (hour / 10) % 10;
    buf[p++] = '0' + hour % 10;
    buf[p++] = ':';
    buf[p++] = '0' + (min / 10) % 10;
    buf[p++] = '0' + min % 10;
    buf[p++] = ':';
    buf[p++] = '0' + (sec / 10) % 10;
    buf[p++] = '0' + sec % 10;
    buf[p++] = ' ';
    buf[p++] = 'G';
    buf[p++] = 'M';
    buf[p++] = 'T';
    buf[p] = 0;
    for (int i = 0; i <= p; ++i)
        http_time[i] = (wchar_t16)(unsigned char)buf[i];
    return 1;
}

__declspec(dllexport) BOOL WinHttpTimeToSystemTime(const wchar_t16* http_time, void* time_st)
{
    if (!http_time || !time_st)
        return 0;
    unsigned short* st = (unsigned short*)time_st;
    for (int i = 0; i < 8; ++i)
        st[i] = 0;
    /* Skip leading day-of-week + ',' + space.  Tolerate either
     * "Wkd, " or "Weekday, " or no day-of-week at all (date-first). */
    int i = 0;
    while (http_time[i] && http_time[i] != ',')
        ++i;
    if (http_time[i] == ',')
    {
        ++i;
        while (http_time[i] == ' ')
            ++i;
    }
    else
    {
        i = 0;
    }
    /* DD or D-of-month, 1-2 digits */
    if (http_time[i] < '0' || http_time[i] > '9')
        return 0;
    unsigned short day = (unsigned short)(http_time[i++] - '0');
    if (http_time[i] >= '0' && http_time[i] <= '9')
        day = (unsigned short)(day * 10 + (http_time[i++] - '0'));
    while (http_time[i] == ' ' || http_time[i] == '-')
        ++i;
    /* Mon */
    char mon_buf[3];
    if (!http_time[i] || !http_time[i + 1] || !http_time[i + 2])
        return 0;
    mon_buf[0] = (char)http_time[i];
    mon_buf[1] = (char)http_time[i + 1];
    mon_buf[2] = (char)http_time[i + 2];
    int m = month_index(mon_buf);
    if (m == 0)
        return 0;
    i += 3;
    while (http_time[i] == ' ' || http_time[i] == '-')
        ++i;
    /* YYYY (or YY — interpret as 1900+YY for [70, 99], 2000+YY otherwise) */
    if (http_time[i] < '0' || http_time[i] > '9')
        return 0;
    unsigned int year = 0;
    int year_digits = 0;
    while (http_time[i] >= '0' && http_time[i] <= '9' && year_digits < 4)
    {
        year = year * 10 + (unsigned int)(http_time[i++] - '0');
        ++year_digits;
    }
    if (year_digits == 2)
        year += (year >= 70) ? 1900 : 2000;
    while (http_time[i] == ' ')
        ++i;
    /* HH:MM:SS */
    if (http_time[i] < '0' || http_time[i] > '9')
        return 0;
    unsigned short hh = (unsigned short)(http_time[i++] - '0');
    if (http_time[i] >= '0' && http_time[i] <= '9')
        hh = (unsigned short)(hh * 10 + (http_time[i++] - '0'));
    if (http_time[i] != ':')
        return 0;
    ++i;
    unsigned short mm = (unsigned short)(http_time[i++] - '0');
    if (http_time[i] >= '0' && http_time[i] <= '9')
        mm = (unsigned short)(mm * 10 + (http_time[i++] - '0'));
    if (http_time[i] != ':')
        return 0;
    ++i;
    unsigned short ss = (unsigned short)(http_time[i++] - '0');
    if (http_time[i] >= '0' && http_time[i] <= '9')
        ss = (unsigned short)(ss * 10 + (http_time[i++] - '0'));
    st[0] = (unsigned short)year;
    st[1] = (unsigned short)m;
    /* DayOfWeek — recompute via Zeller's congruence so the field
     * is correct even when the input omitted the leading "Wkd,". */
    {
        int Y = (int)year;
        int M = m;
        int D = day;
        if (M < 3)
        {
            M += 12;
            Y -= 1;
        }
        int K = Y % 100;
        int J = Y / 100;
        int h = (D + (13 * (M + 1)) / 5 + K + K / 4 + J / 4 + 5 * J) % 7;
        /* Zeller's h: 0=Sat,1=Sun,2=Mon,...,6=Fri. SYSTEMTIME wants 0=Sun. */
        int dow = (h + 6) % 7;
        st[2] = (unsigned short)dow;
    }
    st[3] = day;
    st[4] = hh;
    st[5] = mm;
    st[6] = ss;
    st[7] = 0;
    return 1;
}

/* WinHttpReadDataEx — extended read variant. */
__declspec(dllexport) DWORD WinHttpReadDataEx(HANDLE h, void* buf, DWORD cb, DWORD* read, unsigned long long flags,
                                              DWORD prop_buf_size, const void* prop_buf)
{
    (void)flags;
    (void)prop_buf_size;
    (void)prop_buf;
    return WinHttpReadData(h, buf, cb, read) ? 0 : 1;
}

/* WinHttpWriteData — POST body bytes. v0 reports success
 * regardless of whether the bytes go anywhere. */
__declspec(dllexport) BOOL WinHttpWriteData(HANDLE h, const void* buf, DWORD cb, DWORD* written)
{
    (void)h;
    (void)buf;
    if (written)
        *written = cb;
    return 1;
}

__declspec(dllexport) BOOL WinHttpQueryDataAvailable2(HANDLE h, DWORD* avail)
{
    (void)h;
    if (avail)
        *avail = 0;
    return 1;
}

/* WinHttpWebSocketCompleteUpgrade etc. — WebSocket support. v0
 * has no WS layer; report failure. */
__declspec(dllexport) HANDLE WinHttpWebSocketCompleteUpgrade(HANDLE h, unsigned long long ctx)
{
    (void)h;
    (void)ctx;
    return (HANDLE)0;
}

__declspec(dllexport) DWORD WinHttpWebSocketSend(HANDLE h, int buf_type, void* buf, DWORD cb)
{
    (void)h;
    (void)buf_type;
    (void)buf;
    (void)cb;
    return 0xC0000002UL;
}

__declspec(dllexport) DWORD WinHttpWebSocketReceive(HANDLE h, void* buf, DWORD cb, DWORD* read, int* buf_type)
{
    (void)h;
    (void)buf;
    (void)cb;
    if (read)
        *read = 0;
    if (buf_type)
        *buf_type = 0;
    return 0xC0000002UL;
}

__declspec(dllexport) DWORD WinHttpWebSocketClose(HANDLE h, unsigned short status, void* reason, DWORD reason_len)
{
    (void)h;
    (void)status;
    (void)reason;
    (void)reason_len;
    return 0;
}

__declspec(dllexport) DWORD WinHttpWebSocketShutdown(HANDLE h, unsigned short status, void* reason, DWORD reason_len)
{
    (void)h;
    (void)status;
    (void)reason;
    (void)reason_len;
    return 0;
}
