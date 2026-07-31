/*
 * userland/libs/comtest/comtest.c — minimal COM in-proc server for
 * testing the DLL-backed CoCreateInstance path end-to-end.
 *
 * Exports DllGetClassObject and DllCanUnloadNow. When ole32's
 * CoGetClassObject resolves CLSID_ComTest through the CLSID-to-DLL
 * table, it LoadLibrary("comtest.dll"), GetProcAddress("DllGetClassObject"),
 * and calls into here. The factory creates a trivial IUnknown object.
 *
 * Freestanding — no CRT, no imports; syscalls go through int 0x80.
 */

typedef unsigned long HRESULT;
typedef unsigned long ULONG;
typedef int BOOL;

#define S_OK 0UL
#define S_FALSE 1UL
#define E_NOINTERFACE 0x80004002UL
#define E_POINTER 0x80004003UL
#define E_INVALIDARG 0x80070057UL
#define CLASS_E_NOAGGREGATION 0x80040110UL
#define REGDB_E_CLASSNOTREG 0x80040154UL

struct Guid
{
    unsigned int data1;
    unsigned short data2;
    unsigned short data3;
    unsigned char data4[8];
};

static int guid_eq(const void* a, const void* b)
{
    const unsigned char* aa = (const unsigned char*)a;
    const unsigned char* bb = (const unsigned char*)b;
    for (int i = 0; i < 16; ++i)
    {
        if (aa[i] != bb[i])
            return 0;
    }
    return 1;
}

static const struct Guid kIID_IUnknown = {
    0x00000000u, 0x0000u, 0x0000u, {0xC0u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x46u}};
static const struct Guid kIID_IClassFactory = {
    0x00000001u, 0x0000u, 0x0000u, {0xC0u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x46u}};

/* CLSID_ComTest — {1234ABCD-0001-0001-0001-000000000001}. Must
 * match the entry in ole32.c's g_clsid_dll_table. */
static const struct Guid kCLSID_ComTest = {
    0x1234ABCDu, 0x0001u, 0x0001u, {0x00u, 0x01u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x01u}};

/* ---- IUnknown instances ---- */

typedef struct TestObj
{
    const void* lpVtbl;
    ULONG refs;
} TestObj;

static HRESULT __stdcall obj_qi(TestObj* self, const struct Guid* riid, void** ppv)
{
    if (!ppv)
        return E_POINTER;
    *ppv = (void*)0;
    if (guid_eq(riid, &kIID_IUnknown))
    {
        ++self->refs;
        *ppv = self;
        return S_OK;
    }
    return E_NOINTERFACE;
}

static ULONG __stdcall obj_addref(TestObj* self)
{
    return ++self->refs;
}

static ULONG __stdcall obj_release(TestObj* self)
{
    if (self->refs > 0)
        --self->refs;
    return self->refs;
    /* v0: never frees — process-static. CoTaskMemFree would need
     * an ole32 import, creating a circular DLL dependency. */
}

typedef struct
{
    HRESULT(__stdcall* QueryInterface)(TestObj*, const struct Guid*, void**);
    ULONG(__stdcall* AddRef)(TestObj*);
    ULONG(__stdcall* Release)(TestObj*);
} ObjVtbl;

static const ObjVtbl g_obj_vtbl = {obj_qi, obj_addref, obj_release};
static TestObj g_instance = {&g_obj_vtbl, 1};

/* ---- IClassFactory ---- */

typedef struct TestFactory
{
    const void* lpVtbl;
    ULONG refs;
} TestFactory;

static HRESULT __stdcall cf_qi(TestFactory* self, const struct Guid* riid, void** ppv)
{
    if (!ppv)
        return E_POINTER;
    *ppv = (void*)0;
    if (guid_eq(riid, &kIID_IUnknown) || guid_eq(riid, &kIID_IClassFactory))
    {
        ++self->refs;
        *ppv = self;
        return S_OK;
    }
    return E_NOINTERFACE;
}

static ULONG __stdcall cf_addref(TestFactory* self)
{
    return ++self->refs;
}

static ULONG __stdcall cf_release(TestFactory* self)
{
    if (self->refs > 1)
        --self->refs;
    return self->refs;
}

static HRESULT __stdcall cf_create(TestFactory* self, void* outer, const struct Guid* riid, void** ppv)
{
    (void)self;
    if (outer)
        return CLASS_E_NOAGGREGATION;
    if (!ppv)
        return E_POINTER;
    *ppv = (void*)0;
    return obj_qi(&g_instance, riid, ppv);
}

static HRESULT __stdcall cf_lock(TestFactory* self, BOOL lock)
{
    (void)self;
    (void)lock;
    return S_OK;
}

typedef struct
{
    HRESULT(__stdcall* QueryInterface)(TestFactory*, const struct Guid*, void**);
    ULONG(__stdcall* AddRef)(TestFactory*);
    ULONG(__stdcall* Release)(TestFactory*);
    HRESULT(__stdcall* CreateInstance)(TestFactory*, void*, const struct Guid*, void**);
    HRESULT(__stdcall* LockServer)(TestFactory*, BOOL);
} CfVtbl;

static const CfVtbl g_cf_vtbl = {cf_qi, cf_addref, cf_release, cf_create, cf_lock};
static TestFactory g_factory = {&g_cf_vtbl, 1};

/* ---- DLL entry points ---- */

__declspec(dllexport) HRESULT DllGetClassObject(const struct Guid* rclsid, const struct Guid* riid, void** ppv)
{
    if (!ppv)
        return E_POINTER;
    *ppv = (void*)0;
    if (!rclsid || !riid)
        return E_INVALIDARG;
    if (guid_eq(rclsid, &kCLSID_ComTest))
        return cf_qi(&g_factory, riid, ppv);
    return REGDB_E_CLASSNOTREG;
}

__declspec(dllexport) HRESULT DllCanUnloadNow(void)
{
    return S_FALSE;
}
