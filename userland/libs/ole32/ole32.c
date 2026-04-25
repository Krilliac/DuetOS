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
#define CLASS_E_CLASSNOTAVAILABLE 0x80040111UL

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

__declspec(dllexport) HRESULT CLSIDFromString(const wchar_t16* sz, void* out)
{
    (void)sz;
    if (out)
    {
        unsigned char* b = (unsigned char*)out;
        for (int i = 0; i < 16; ++i)
            b[i] = 0;
    }
    return E_NOTIMPL;
}

__declspec(dllexport) HRESULT CLSIDFromProgID(const wchar_t16* id, void* clsid)
{
    (void)id;
    if (clsid)
    {
        unsigned char* b = (unsigned char*)clsid;
        for (int i = 0; i < 16; ++i)
            b[i] = 0;
    }
    return E_NOTIMPL;
}

__declspec(dllexport) HRESULT IIDFromString(const wchar_t16* sz, void* iid)
{
    return CLSIDFromString(sz, iid);
}

__declspec(dllexport) HRESULT StringFromCLSID(const void* clsid, wchar_t16** psz)
{
    (void)clsid;
    if (psz)
        *psz = (wchar_t16*)0;
    return E_NOTIMPL;
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
