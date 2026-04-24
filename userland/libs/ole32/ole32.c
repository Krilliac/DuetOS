/*
 * userland/libs/ole32/ole32.c — 15 COM init + CoTaskMem stubs.
 * CoInitialize family returns S_OK. CoCreateInstance etc. return
 * E_NOTIMPL. CoTaskMem{Alloc,Free,Realloc} route to SYS_HEAP_*.
 */

typedef int                BOOL;
typedef unsigned int       DWORD;
typedef unsigned long long SIZE_T;
typedef unsigned long      HRESULT;
typedef unsigned short     wchar_t16;

#define S_OK        0UL
#define S_FALSE     1UL
#define E_NOTIMPL   0x80004001UL
#define CLASS_E_CLASSNOTAVAILABLE 0x80040111UL

__declspec(dllexport) HRESULT CoInitialize(void* reserved)
{
    (void) reserved;
    return S_OK;
}

__declspec(dllexport) HRESULT CoInitializeEx(void* reserved, DWORD dwCoInit)
{
    (void) reserved;
    (void) dwCoInit;
    return S_OK;
}

__declspec(dllexport) void CoUninitialize(void)
{
}

__declspec(dllexport) HRESULT OleInitialize(void* reserved)
{
    (void) reserved;
    return S_OK;
}

__declspec(dllexport) void OleUninitialize(void)
{
}

__declspec(dllexport) HRESULT CoCreateInstance(const void* rclsid, void* pUnkOuter, DWORD dwClsCtx,
                                               const void* riid, void** ppv)
{
    (void) rclsid;
    (void) pUnkOuter;
    (void) dwClsCtx;
    (void) riid;
    if (ppv)
        *ppv = (void*) 0;
    return CLASS_E_CLASSNOTAVAILABLE;
}

__declspec(dllexport) HRESULT CoCreateInstanceEx(const void* rclsid, void* pUnkOuter, DWORD dwClsCtx,
                                                 void* pServerInfo, DWORD cmq, void* pResults)
{
    (void) rclsid;
    (void) pUnkOuter;
    (void) dwClsCtx;
    (void) pServerInfo;
    (void) cmq;
    (void) pResults;
    return CLASS_E_CLASSNOTAVAILABLE;
}

__declspec(dllexport) HRESULT CoGetClassObject(const void* rclsid, DWORD dwClsCtx, void* pvReserved,
                                               const void* riid, void** ppv)
{
    (void) rclsid;
    (void) dwClsCtx;
    (void) pvReserved;
    (void) riid;
    if (ppv)
        *ppv = (void*) 0;
    return CLASS_E_CLASSNOTAVAILABLE;
}

__declspec(dllexport) HRESULT CLSIDFromString(const wchar_t16* sz, void* out)
{
    (void) sz;
    if (out)
    {
        unsigned char* b = (unsigned char*) out;
        for (int i = 0; i < 16; ++i)
            b[i] = 0;
    }
    return E_NOTIMPL;
}

__declspec(dllexport) HRESULT CLSIDFromProgID(const wchar_t16* id, void* clsid)
{
    (void) id;
    if (clsid)
    {
        unsigned char* b = (unsigned char*) clsid;
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
    (void) clsid;
    if (psz)
        *psz = (wchar_t16*) 0;
    return E_NOTIMPL;
}

/* CoTaskMem* -> heap aliases */

__declspec(dllexport) void* CoTaskMemAlloc(SIZE_T cb)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long) 11), "D"((long long) cb) : "memory");
    return (void*) rv;
}

__declspec(dllexport) void CoTaskMemFree(void* pv)
{
    if (!pv)
        return;
    long long discard;
    __asm__ volatile("int $0x80" : "=a"(discard) : "a"((long long) 12), "D"((long long) pv) : "memory");
}

__declspec(dllexport) void* CoTaskMemRealloc(void* pv, SIZE_T cb)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long) 15), "D"((long long) pv), "S"((long long) cb)
                     : "memory");
    return (void*) rv;
}
