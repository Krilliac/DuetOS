/*
 * userland/libs/ole32/ole32.c — 15 COM init + CoTaskMem stubs.
 * CoInitialize family returns S_OK. CoCreateInstance etc. return
 * E_NOTIMPL. CoTaskMem{Alloc,Free,Realloc} route to SYS_HEAP_*.
 */

typedef int BOOL;
typedef unsigned int DWORD;
typedef unsigned long long SIZE_T;
typedef unsigned long HRESULT;
typedef unsigned short wchar_t16;

#define S_OK 0UL
#define S_FALSE 1UL
#define E_NOTIMPL 0x80004001UL
#define E_INVALIDARG 0x80070057UL
#define E_OUTOFMEMORY 0x8007000EUL
#define CLASS_E_CLASSNOTAVAILABLE 0x80040111UL

/* Forward decl — CoTaskMemAlloc is defined later in this TU. */
__declspec(dllexport) void* CoTaskMemAlloc(SIZE_T cb);

__declspec(dllexport) HRESULT CoInitialize(void* reserved)
{
    (void)reserved;
    return S_OK;
}

__declspec(dllexport) HRESULT CoInitializeEx(void* reserved, DWORD dwCoInit)
{
    (void)reserved;
    (void)dwCoInit;
    return S_OK;
}

__declspec(dllexport) void CoUninitialize(void) {}

__declspec(dllexport) HRESULT OleInitialize(void* reserved)
{
    (void)reserved;
    return S_OK;
}

__declspec(dllexport) void OleUninitialize(void) {}

__declspec(dllexport) HRESULT CoCreateInstance(const void* rclsid, void* pUnkOuter, DWORD dwClsCtx, const void* riid,
                                               void** ppv)
{
    (void)rclsid;
    (void)pUnkOuter;
    (void)dwClsCtx;
    (void)riid;
    if (ppv)
        *ppv = (void*)0;
    return CLASS_E_CLASSNOTAVAILABLE;
}

__declspec(dllexport) HRESULT CoCreateInstanceEx(const void* rclsid, void* pUnkOuter, DWORD dwClsCtx, void* pServerInfo,
                                                 DWORD cmq, void* pResults)
{
    (void)rclsid;
    (void)pUnkOuter;
    (void)dwClsCtx;
    (void)pServerInfo;
    (void)cmq;
    (void)pResults;
    return CLASS_E_CLASSNOTAVAILABLE;
}

__declspec(dllexport) HRESULT CoGetClassObject(const void* rclsid, DWORD dwClsCtx, void* pvReserved, const void* riid,
                                               void** ppv)
{
    (void)rclsid;
    (void)dwClsCtx;
    (void)pvReserved;
    (void)riid;
    if (ppv)
        *ppv = (void*)0;
    return CLASS_E_CLASSNOTAVAILABLE;
}

/* Parse a single hex nibble. Returns 0..15 on success, -1 on miss. */
static int clsid_hex_nibble(wchar_t16 c)
{
    if (c >= '0' && c <= '9')
        return (int)(c - '0');
    if (c >= 'a' && c <= 'f')
        return (int)(c - 'a') + 10;
    if (c >= 'A' && c <= 'F')
        return (int)(c - 'A') + 10;
    return -1;
}

/* Reads `count` hex chars from sz starting at *idx, packs them as
 * a big-endian unsigned. Returns 1 on success, 0 on parse error.
 * Advances *idx past the consumed chars. */
static int clsid_read_hex(const wchar_t16* sz, int* idx, int count, unsigned long long* out)
{
    unsigned long long v = 0;
    for (int i = 0; i < count; ++i)
    {
        int n = clsid_hex_nibble(sz[*idx + i]);
        if (n < 0)
            return 0;
        v = (v << 4) | (unsigned long long)n;
    }
    *idx += count;
    *out = v;
    return 1;
}

__declspec(dllexport) HRESULT CLSIDFromString(const wchar_t16* sz, void* out)
{
    if (!out)
        return E_INVALIDARG;
    unsigned char* b = (unsigned char*)out;
    for (int i = 0; i < 16; ++i)
        b[i] = 0;
    if (!sz)
        return E_INVALIDARG;
    /* Accept either "{XXXX...XXXX}" (38 chars) or unbraced "XXXX...XXXX" (36). */
    int i = 0;
    int has_brace = 0;
    if (sz[i] == '{')
    {
        has_brace = 1;
        ++i;
    }
    unsigned long long d1, d2, d3;
    if (!clsid_read_hex(sz, &i, 8, &d1))
        return 0x800401F9UL; /* CO_E_CLASSSTRING */
    if (sz[i++] != '-')
        return 0x800401F9UL;
    if (!clsid_read_hex(sz, &i, 4, &d2))
        return 0x800401F9UL;
    if (sz[i++] != '-')
        return 0x800401F9UL;
    if (!clsid_read_hex(sz, &i, 4, &d3))
        return 0x800401F9UL;
    if (sz[i++] != '-')
        return 0x800401F9UL;
    unsigned long long d4hi;
    if (!clsid_read_hex(sz, &i, 4, &d4hi))
        return 0x800401F9UL;
    if (sz[i++] != '-')
        return 0x800401F9UL;
    /* data4 last 6 bytes = 12 hex chars. */
    unsigned long long d4lo_a, d4lo_b, d4lo_c;
    if (!clsid_read_hex(sz, &i, 4, &d4lo_a))
        return 0x800401F9UL;
    if (!clsid_read_hex(sz, &i, 4, &d4lo_b))
        return 0x800401F9UL;
    if (!clsid_read_hex(sz, &i, 4, &d4lo_c))
        return 0x800401F9UL;
    if (has_brace && sz[i++] != '}')
        return 0x800401F9UL;
    /* GUID memory layout: data1 (LE u32), data2 (LE u16), data3 (LE u16), data4 (8 bytes BE). */
    b[0] = (unsigned char)(d1 & 0xFF);
    b[1] = (unsigned char)((d1 >> 8) & 0xFF);
    b[2] = (unsigned char)((d1 >> 16) & 0xFF);
    b[3] = (unsigned char)((d1 >> 24) & 0xFF);
    b[4] = (unsigned char)(d2 & 0xFF);
    b[5] = (unsigned char)((d2 >> 8) & 0xFF);
    b[6] = (unsigned char)(d3 & 0xFF);
    b[7] = (unsigned char)((d3 >> 8) & 0xFF);
    b[8] = (unsigned char)((d4hi >> 8) & 0xFF);
    b[9] = (unsigned char)(d4hi & 0xFF);
    b[10] = (unsigned char)((d4lo_a >> 8) & 0xFF);
    b[11] = (unsigned char)(d4lo_a & 0xFF);
    b[12] = (unsigned char)((d4lo_b >> 8) & 0xFF);
    b[13] = (unsigned char)(d4lo_b & 0xFF);
    b[14] = (unsigned char)((d4lo_c >> 8) & 0xFF);
    b[15] = (unsigned char)(d4lo_c & 0xFF);
    return S_OK;
}

__declspec(dllexport) HRESULT CLSIDFromProgID(const wchar_t16* id, void* clsid)
{
    /* No registry-backed ProgID -> CLSID lookup yet. Real Windows reads
     * HKCR\<id>\CLSID; we'd need a registry implementation. Return the
     * "ProgID not registered" status so callers can fall through. */
    (void)id;
    if (clsid)
    {
        unsigned char* b = (unsigned char*)clsid;
        for (int i = 0; i < 16; ++i)
            b[i] = 0;
    }
    return 0x800401F3UL; /* CO_E_CLASSSTRING */
}

__declspec(dllexport) HRESULT IIDFromString(const wchar_t16* sz, void* iid)
{
    return CLSIDFromString(sz, iid);
}

__declspec(dllexport) HRESULT StringFromCLSID(const void* clsid, wchar_t16** psz)
{
    if (psz == (wchar_t16**)0)
        return E_INVALIDARG;
    if (clsid == (const void*)0)
    {
        *psz = (wchar_t16*)0;
        return E_INVALIDARG;
    }
    /* Format: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX} = 38 chars + NUL */
    wchar_t16* buf = (wchar_t16*)CoTaskMemAlloc(39 * sizeof(wchar_t16));
    if (buf == (wchar_t16*)0)
    {
        *psz = (wchar_t16*)0;
        return E_OUTOFMEMORY;
    }
    static const wchar_t16 hex[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    const unsigned char* p = (const unsigned char*)clsid;
    /* GUID: 4-byte data1 (LE), 2-byte data2 (LE), 2-byte data3 (LE),
     *       8-byte data4. Display: data1 (8 hex), data2 (4), data3
     *       (4), then first 2 bytes of data4, dash, last 6 bytes. */
    int i = 0;
    buf[i++] = '{';
    /* data1 — read as little-endian uint32, print high nybble first. */
    unsigned int d1 =
        (unsigned int)p[0] | ((unsigned int)p[1] << 8) | ((unsigned int)p[2] << 16) | ((unsigned int)p[3] << 24);
    for (int j = 7; j >= 0; --j)
        buf[i++] = hex[(d1 >> (j * 4)) & 0xF];
    buf[i++] = '-';
    unsigned short d2 = (unsigned short)p[4] | ((unsigned short)p[5] << 8);
    for (int j = 3; j >= 0; --j)
        buf[i++] = hex[(d2 >> (j * 4)) & 0xF];
    buf[i++] = '-';
    unsigned short d3 = (unsigned short)p[6] | ((unsigned short)p[7] << 8);
    for (int j = 3; j >= 0; --j)
        buf[i++] = hex[(d3 >> (j * 4)) & 0xF];
    buf[i++] = '-';
    /* data4[0..1] then dash then data4[2..7] */
    for (int k = 8; k < 10; ++k)
    {
        buf[i++] = hex[(p[k] >> 4) & 0xF];
        buf[i++] = hex[p[k] & 0xF];
    }
    buf[i++] = '-';
    for (int k = 10; k < 16; ++k)
    {
        buf[i++] = hex[(p[k] >> 4) & 0xF];
        buf[i++] = hex[p[k] & 0xF];
    }
    buf[i++] = '}';
    buf[i] = 0;
    *psz = buf;
    return S_OK;
}

/* CoTaskMem* -> heap aliases */

__declspec(dllexport) void* CoTaskMemAlloc(SIZE_T cb)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)11), "D"((long long)cb) : "memory");
    return (void*)rv;
}

__declspec(dllexport) void CoTaskMemFree(void* pv)
{
    if (!pv)
        return;
    long long discard;
    __asm__ volatile("int $0x80" : "=a"(discard) : "a"((long long)12), "D"((long long)pv) : "memory");
}

__declspec(dllexport) void* CoTaskMemRealloc(void* pv, SIZE_T cb)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)15), "D"((long long)pv), "S"((long long)cb) : "memory");
    return (void*)rv;
}

/* CoGetMalloc — return a sentinel "IMalloc" pointer that callers
 * occasionally compare against null. v0 has no real IMalloc COM
 * object, so the alias is safe-but-non-callable; the caller must
 * call CoTaskMemAlloc directly anyway in any path that survives
 * v0. */
__declspec(dllexport) HRESULT CoGetMalloc(DWORD context, void** ppMalloc)
{
    (void)context;
    if (ppMalloc)
        *ppMalloc = (void*)0;
    return E_NOTIMPL;
}

/* CoRegisterClassObject / CoRevokeClassObject — class-factory
 * registration. v0 has no class-table; accept and return a fake
 * cookie so unregister doesn't trip an assert. */
__declspec(dllexport) HRESULT CoRegisterClassObject(const void* rclsid, void* unk, DWORD context, DWORD flags,
                                                    DWORD* cookie)
{
    (void)rclsid;
    (void)unk;
    (void)context;
    (void)flags;
    if (cookie)
        *cookie = 0xC0DE0001u;
    return S_OK;
}

__declspec(dllexport) HRESULT CoRevokeClassObject(DWORD cookie)
{
    (void)cookie;
    return S_OK;
}

__declspec(dllexport) HRESULT CoResumeClassObjects(void)
{
    return S_OK;
}

__declspec(dllexport) HRESULT CoSuspendClassObjects(void)
{
    return S_OK;
}

__declspec(dllexport) DWORD CoAddRefServerProcess(void)
{
    return 1;
}

__declspec(dllexport) DWORD CoReleaseServerProcess(void)
{
    return 0;
}

__declspec(dllexport) HRESULT CoSetProxyBlanket(void* proxy, DWORD authn, DWORD authz, wchar_t16* svr_principal,
                                                DWORD authn_lvl, DWORD imp_lvl, void* auth_info, DWORD capabilities)
{
    (void)proxy;
    (void)authn;
    (void)authz;
    (void)svr_principal;
    (void)authn_lvl;
    (void)imp_lvl;
    (void)auth_info;
    (void)capabilities;
    return S_OK;
}

__declspec(dllexport) HRESULT CoInitializeSecurity(void* sec_desc, long auth_svc, void* auth_svc_arr, void* reserved1,
                                                   DWORD authn_lvl, DWORD imp_lvl, void* auth_info, DWORD capabilities,
                                                   void* reserved3)
{
    (void)sec_desc;
    (void)auth_svc;
    (void)auth_svc_arr;
    (void)reserved1;
    (void)authn_lvl;
    (void)imp_lvl;
    (void)auth_info;
    (void)capabilities;
    (void)reserved3;
    return S_OK;
}

/* CreateStreamOnHGlobal / GetHGlobalFromStream: IStream over a
 * memory buffer. We don't have a real IStream impl; return
 * E_NOTIMPL so callers that fall back to CoTaskMemAlloc still
 * get a path through. */
__declspec(dllexport) HRESULT CreateStreamOnHGlobal(void* hglobal, BOOL delete_on_release, void** stream)
{
    (void)hglobal;
    (void)delete_on_release;
    if (stream)
        *stream = (void*)0;
    return E_NOTIMPL;
}

__declspec(dllexport) HRESULT GetHGlobalFromStream(void* stream, void** hglobal)
{
    (void)stream;
    if (hglobal)
        *hglobal = (void*)0;
    return E_NOTIMPL;
}

__declspec(dllexport) HRESULT GetRunningObjectTable(DWORD reserved, void** prot)
{
    (void)reserved;
    if (prot)
        *prot = (void*)0;
    return E_NOTIMPL;
}

/* OLE drag/drop: register the window as a drop target. v0 has
 * no DnD wired, but accept silently so PE programs that register
 * + unregister around their window lifetime don't trip. */
__declspec(dllexport) HRESULT RegisterDragDrop(void* hwnd, void* drop_target)
{
    (void)hwnd;
    (void)drop_target;
    return S_OK;
}

__declspec(dllexport) HRESULT RevokeDragDrop(void* hwnd)
{
    (void)hwnd;
    return S_OK;
}

/* StringFromGUID2 — like StringFromCLSID but writes into caller buffer. */
__declspec(dllexport) int StringFromGUID2(const void* guid, wchar_t16* buf, int cch)
{
    if (guid == 0 || buf == 0 || cch < 39)
        return 0;
    static const wchar_t16 hex[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    const unsigned char* p = (const unsigned char*)guid;
    int i = 0;
    buf[i++] = '{';
    unsigned int d1 =
        (unsigned int)p[0] | ((unsigned int)p[1] << 8) | ((unsigned int)p[2] << 16) | ((unsigned int)p[3] << 24);
    for (int j = 7; j >= 0; --j)
        buf[i++] = hex[(d1 >> (j * 4)) & 0xF];
    buf[i++] = '-';
    unsigned short d2 = (unsigned short)p[4] | ((unsigned short)p[5] << 8);
    for (int j = 3; j >= 0; --j)
        buf[i++] = hex[(d2 >> (j * 4)) & 0xF];
    buf[i++] = '-';
    unsigned short d3 = (unsigned short)p[6] | ((unsigned short)p[7] << 8);
    for (int j = 3; j >= 0; --j)
        buf[i++] = hex[(d3 >> (j * 4)) & 0xF];
    buf[i++] = '-';
    for (int k = 8; k < 10; ++k)
    {
        buf[i++] = hex[(p[k] >> 4) & 0xF];
        buf[i++] = hex[p[k] & 0xF];
    }
    buf[i++] = '-';
    for (int k = 10; k < 16; ++k)
    {
        buf[i++] = hex[(p[k] >> 4) & 0xF];
        buf[i++] = hex[p[k] & 0xF];
    }
    buf[i++] = '}';
    buf[i] = 0;
    return 39;
}
