/*
 * com3_smoke — end-to-end COM lifecycle through a DLL-backed coclass.
 *
 * Exercises the real COM path: CoInitializeEx(MTA) -> CoCreateInstance
 * on CLSID_ComTest (resolved via ole32's CLSID-to-DLL table ->
 * LoadLibrary("comtest.dll") -> DllGetClassObject) -> QueryInterface
 * for IUnknown -> AddRef/Release -> CoUninitialize.
 *
 * Also validates CoGetMalloc returns a usable IMalloc.
 */
#include <windows.h>
#include <objbase.h>

/* CLSID_ComTest — {1234ABCD-0001-0001-0001-000000000001}. Must match
 * comtest.dll + ole32.c's CLSID-to-DLL table entry. */
const CLSID kClsidComTest = {0x1234ABCD, 0x0001, 0x0001, {0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}};
const IID kIidIUnknown = {0x00000000, 0x0000, 0x0000, {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
const IID kIidIClassFactory = {0x00000001, 0x0000, 0x0000, {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};

static void Out(const char* s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0;
    DWORD len = 0;
    while (s[len] != '\0')
        ++len;
    WriteConsoleA(h, s, len, &n, 0);
}

static int g_pass = 1;

static void Check(const char* label, int ok)
{
    Out(label);
    Out(ok ? "PASS\r\n" : "FAIL\r\n");
    if (!ok)
        g_pass = 0;
}

void __cdecl mainCRTStartup(void)
{
    Out("[com3_smoke] starting\r\n");

    /* 1. Initialize COM in MTA mode. */
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    Check("[com3_smoke] CoInitializeEx(MTA)      = ", hr == S_OK);

    /* 2. CoCreateInstance on the DLL-backed test coclass. ole32
     *    looks up CLSID_ComTest in its static CLSID-to-DLL table,
     *    LoadLibrary("comtest.dll"), resolves DllGetClassObject,
     *    and calls it. */
    IUnknown* obj = NULL;
    hr = CoCreateInstance(&kClsidComTest, NULL, CLSCTX_INPROC_SERVER, &kIidIUnknown, (void**)&obj);
    Check("[com3_smoke] CoCreateInstance(ComTest) = ", hr == S_OK && obj != NULL);

    if (obj)
    {
        /* 3. QueryInterface for IUnknown (identity). */
        IUnknown* obj2 = NULL;
        hr = obj->lpVtbl->QueryInterface(obj, &kIidIUnknown, (void**)&obj2);
        Check("[com3_smoke] QueryInterface(IUnknown) = ", hr == S_OK && obj2 != NULL);

        if (obj2)
        {
            /* 4. AddRef / Release round-trip. */
            ULONG r1 = obj2->lpVtbl->AddRef(obj2);
            ULONG r2 = obj2->lpVtbl->Release(obj2);
            Check("[com3_smoke] AddRef/Release            = ", r1 > 0 && r2 > 0);
            obj2->lpVtbl->Release(obj2);
        }

        /* 5. CoGetClassObject — verify the factory is reachable. */
        IClassFactory* cf = NULL;
        hr = CoGetClassObject(&kClsidComTest, CLSCTX_INPROC_SERVER, NULL, &kIidIClassFactory, (void**)&cf);
        Check("[com3_smoke] CoGetClassObject          = ", hr == S_OK && cf != NULL);
        if (cf)
            cf->lpVtbl->Release(cf);

        obj->lpVtbl->Release(obj);
    }

    /* 6. CoGetMalloc — verify the IMalloc interface works. */
    IMalloc* pMalloc = NULL;
    hr = CoGetMalloc(1, &pMalloc);
    if (hr == S_OK && pMalloc != NULL)
    {
        void* p = pMalloc->lpVtbl->Alloc(pMalloc, 128);
        int alloc_ok = (p != NULL);
        if (p)
        {
            ((unsigned char*)p)[0] = 0xAB;
            ((unsigned char*)p)[127] = 0xCD;
            pMalloc->lpVtbl->Free(pMalloc, p);
        }
        Check("[com3_smoke] CoGetMalloc+Alloc+Free    = ", alloc_ok);
        pMalloc->lpVtbl->Release(pMalloc);
    }
    else
    {
        Check("[com3_smoke] CoGetMalloc               = ", 0);
    }

    /* 7. CoUninitialize. */
    CoUninitialize();
    Out("[com3_smoke] CoUninitialize            = PASS\r\n");

    Out(g_pass ? "[ring3-com3-smoke] PASS\r\n" : "[ring3-com3-smoke] FAIL\r\n");
    ExitProcess(0);
}
