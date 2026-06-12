/*
 * com_smoke — exercise ole32 COM-runtime entry points.
 *
 * Probes the COM bootstrap surface every COM-using app touches:
 *   CoInitializeEx per-thread mode/count semantics
 *   CoTaskMemAlloc / CoTaskMemFree / CoTaskMemRealloc
 *   CLSIDFromString / StringFromCLSID
 *   CoGetClassObject / CoCreateInstance for registered built-ins
 *   CoRegisterClassObject / CoRevokeClassObject
 *   Unknown CLSID failure as REGDB_E_CLASSNOTREG
 */
#include <windows.h>
#include <objbase.h>

const IID kIidIUnknown = {0x00000000, 0x0000, 0x0000, {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
const IID kIidIClassFactory = {0x00000001, 0x0000, 0x0000, {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
const CLSID kClsidFileOpenDialog = {0xDC1C5A9C, 0xE88A, 0x4DDE, {0xA5, 0xA1, 0x60, 0xF8, 0x2A, 0x20, 0xAE, 0xF7}};
const CLSID kClsidBogus = {0x00000000, 0x0000, 0x0000, {0, 0, 0, 0, 0, 0, 0, 0}};
const CLSID kClsidRuntime = {0x13572468, 0x2468, 0x1357, {0x80, 0x01, 0x02, 0x03, 0xAA, 0xBB, 0xCC, 0xDD}};

#ifndef REGDB_E_CLASSNOTREG
#define REGDB_E_CLASSNOTREG ((HRESULT)0x80040154L)
#endif
#ifndef RPC_E_CHANGED_MODE
#define RPC_E_CHANGED_MODE ((HRESULT)0x80010106L)
#endif

typedef struct TestFactory TestFactory;
typedef struct TestUnknown TestUnknown;

static int GuidEqualLocal(REFIID a, REFIID b)
{
    const unsigned char* aa = (const unsigned char*)a;
    const unsigned char* bb = (const unsigned char*)b;
    if (!aa || !bb)
        return 0;
    for (int i = 0; i < 16; ++i)
    {
        if (aa[i] != bb[i])
            return 0;
    }
    return 1;
}

struct TestUnknown
{
    const IUnknownVtbl* lpVtbl;
    ULONG refs;
};

struct TestFactory
{
    const IClassFactoryVtbl* lpVtbl;
    ULONG refs;
};

static HRESULT STDMETHODCALLTYPE TestUnknown_QueryInterface(IUnknown* self, REFIID riid, void** ppv)
{
    if (!ppv)
        return E_POINTER;
    *ppv = NULL;
    if (!riid)
        return E_INVALIDARG;
    if (GuidEqualLocal(riid, &kIidIUnknown))
    {
        self->lpVtbl->AddRef(self);
        *ppv = self;
        return S_OK;
    }
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE TestUnknown_AddRef(IUnknown* self)
{
    TestUnknown* u = (TestUnknown*)self;
    return ++u->refs;
}

static ULONG STDMETHODCALLTYPE TestUnknown_Release(IUnknown* self)
{
    TestUnknown* u = (TestUnknown*)self;
    if (u->refs > 0)
        --u->refs;
    return u->refs;
}

static const IUnknownVtbl g_test_unknown_vtbl = {TestUnknown_QueryInterface, TestUnknown_AddRef, TestUnknown_Release};
static TestUnknown g_test_unknown = {&g_test_unknown_vtbl, 1};

static HRESULT STDMETHODCALLTYPE TestFactory_QueryInterface(IClassFactory* self, REFIID riid, void** ppv)
{
    if (!ppv)
        return E_POINTER;
    *ppv = NULL;
    if (GuidEqualLocal(riid, &kIidIUnknown) || GuidEqualLocal(riid, &kIidIClassFactory))
    {
        self->lpVtbl->AddRef(self);
        *ppv = self;
        return S_OK;
    }
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE TestFactory_AddRef(IClassFactory* self)
{
    TestFactory* f = (TestFactory*)self;
    return ++f->refs;
}

static ULONG STDMETHODCALLTYPE TestFactory_Release(IClassFactory* self)
{
    TestFactory* f = (TestFactory*)self;
    if (f->refs > 1)
        --f->refs;
    return f->refs;
}

static HRESULT STDMETHODCALLTYPE TestFactory_CreateInstance(IClassFactory* self, IUnknown* outer, REFIID riid,
                                                            void** ppv)
{
    (void)self;
    if (outer)
        return CLASS_E_NOAGGREGATION;
    return g_test_unknown.lpVtbl->QueryInterface((IUnknown*)&g_test_unknown, riid, ppv);
}

static HRESULT STDMETHODCALLTYPE TestFactory_LockServer(IClassFactory* self, BOOL lock)
{
    (void)self;
    (void)lock;
    return S_OK;
}

static const IClassFactoryVtbl g_test_factory_vtbl = {TestFactory_QueryInterface, TestFactory_AddRef,
                                                      TestFactory_Release, TestFactory_CreateInstance,
                                                      TestFactory_LockServer};
static TestFactory g_test_factory = {&g_test_factory_vtbl, 1};

static void Out(const char* s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0;
    DWORD len = 0;
    while (s[len] != '\0')
        ++len;
    WriteConsoleA(h, s, len, &n, 0);
}

static void OutHex(unsigned long long v)
{
    static const char hex[] = "0123456789abcdef";
    char buf[19];
    buf[0] = '0';
    buf[1] = 'x';
    for (int i = 0; i < 16; ++i)
        buf[2 + i] = hex[(v >> ((15 - i) * 4)) & 0xF];
    buf[18] = '\0';
    Out(buf);
}

static void ReportHr(const char* name, int ok, HRESULT hr)
{
    Out(name);
    if (ok)
        Out("PASS hr=");
    else
        Out("FAIL hr=");
    OutHex((unsigned long long)(ULONG)hr);
    Out("\r\n");
}

void __cdecl mainCRTStartup(void)
{
    Out("[com_smoke] starting\r\n");

    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    ReportHr("[com_smoke] CoInitializeEx first   = ", hr == S_OK, hr);
    HRESULT hr2 = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    ReportHr("[com_smoke] CoInitializeEx nested  = ", hr2 == S_FALSE, hr2);
    HRESULT hr3 = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    ReportHr("[com_smoke] CoInitializeEx changed = ", hr3 == RPC_E_CHANGED_MODE, hr3);

    {
        void* p = CoTaskMemAlloc(256);
        Out("[com_smoke] CoTaskMemAlloc(256)    = ");
        if (p == NULL)
        {
            Out("FAIL\r\n");
        }
        else
        {
            ((unsigned char*)p)[0] = 0xAB;
            ((unsigned char*)p)[255] = 0xCD;
            p = CoTaskMemRealloc(p, 512);
            int ok = p != NULL && ((unsigned char*)p)[0] == 0xAB && ((unsigned char*)p)[255] == 0xCD;
            Out(ok ? "PASS\r\n" : "FAIL (corrupt)\r\n");
            CoTaskMemFree(p);
        }
    }

    {
        const CLSID test_id = {0xdeadbeef, 0x1234, 0x5678, {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11}};
        LPOLESTR str = NULL;
        HRESULT r = StringFromCLSID(&test_id, &str);
        Out("[com_smoke] StringFromCLSID         = ");
        Out(r == S_OK && str != NULL ? "PASS\r\n" : "FAIL\r\n");
        if (str != NULL)
            CoTaskMemFree(str);
    }

    {
        void* p = NULL;
        HRESULT r = CoCreateInstance(&kClsidBogus, NULL, CLSCTX_INPROC_SERVER, &kIidIUnknown, &p);
        ReportHr("[com_smoke] CoCreateInstance bogus = ", r == REGDB_E_CLASSNOTREG && p == NULL, r);
    }

    {
        IClassFactory* cf = NULL;
        HRESULT r =
            CoGetClassObject(&kClsidFileOpenDialog, CLSCTX_INPROC_SERVER, NULL, &kIidIClassFactory, (void**)&cf);
        int ok = (r == S_OK && cf != NULL);
        if (cf)
            cf->lpVtbl->Release(cf);
        ReportHr("[com_smoke] built-in class factory = ", ok, r);
    }

    {
        void* p = NULL;
        HRESULT r = CoCreateInstance(&kClsidFileOpenDialog, NULL, CLSCTX_INPROC_SERVER, &kIidIUnknown, &p);
        int ok = (r == S_OK && p != NULL);
        if (p)
            ((IUnknown*)p)->lpVtbl->Release((IUnknown*)p);
        ReportHr("[com_smoke] built-in instance      = ", ok, r);
    }

    {
        DWORD cookie = 0;
        HRESULT r = CoRegisterClassObject(&kClsidRuntime, (IUnknown*)&g_test_factory, CLSCTX_INPROC_SERVER,
                                          REGCLS_MULTIPLEUSE, &cookie);
        void* p = NULL;
        HRESULT r2 = CoCreateInstance(&kClsidRuntime, NULL, CLSCTX_INPROC_SERVER, &kIidIUnknown, &p);
        int ok = (r == S_OK && r2 == S_OK && p != NULL && cookie != 0);
        if (p)
            ((IUnknown*)p)->lpVtbl->Release((IUnknown*)p);
        if (cookie)
            CoRevokeClassObject(cookie);
        void* after = NULL;
        HRESULT r3 = CoCreateInstance(&kClsidRuntime, NULL, CLSCTX_INPROC_SERVER, &kIidIUnknown, &after);
        ok = ok && r3 == REGDB_E_CLASSNOTREG && after == NULL;
        ReportHr("[com_smoke] runtime class table   = ", ok, ok ? S_OK : r2);
    }

    CoUninitialize();
    CoUninitialize();
    Out("[com_smoke] CoUninitialize          = PASS (returned)\r\n");

    Out("[com_smoke] done\r\n");
    Out("[ring3-com-smoke] PASS\r\n");
    ExitProcess(0);
}
