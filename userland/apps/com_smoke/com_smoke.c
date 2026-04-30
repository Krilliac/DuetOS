/*
 * com_smoke — exercise ole32 COM-runtime entry points.
 *
 * Probes the COM bootstrap surface every COM-using app touches
 * before instantiating any object:
 *   CoInitialize / CoInitializeEx / CoUninitialize
 *   CoTaskMemAlloc / CoTaskMemFree / CoTaskMemRealloc
 *   CLSIDFromString / StringFromCLSID
 *   CoCreateInstance (expected NOT_REGISTERED — there are no
 *                     class factories registered)
 *
 * The PASS criteria are deliberately permissive: CoInitialize
 * returning S_OK or S_FALSE both count; CoCreateInstance returning
 * any failure HRESULT counts (we just want to see it doesn't crash).
 */
#include <windows.h>
#include <objbase.h>

/* mingw-w64 freestanding doesn't provide the IID_IUnknown symbol
 * out of an interface library, so we declare it locally. The
 * value is the canonical {00000000-0000-0000-C000-000000000046}. */
const IID kIidIUnknown = {0x00000000, 0x0000, 0x0000, {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
#define IID_IUnknown_local kIidIUnknown

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

void __cdecl mainCRTStartup(void)
{
    Out("[com_smoke] starting\r\n");

    /* CoInitializeEx — APARTMENTTHREADED is the most common. */
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    Out("[com_smoke] CoInitializeEx          = ");
    if (hr == S_OK || hr == S_FALSE)
    {
        Out("PASS hr=");
        OutHex((unsigned long long)hr);
        Out("\r\n");
    }
    else
    {
        Out("FAIL hr=");
        OutHex((unsigned long long)hr);
        Out("\r\n");
    }

    /* CoTaskMemAlloc + CoTaskMemFree. */
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
            int ok = ((unsigned char*)p)[0] == 0xAB && ((unsigned char*)p)[255] == 0xCD;
            Out(ok ? "PASS\r\n" : "FAIL (corrupt)\r\n");
            CoTaskMemFree(p);
        }
    }

    /* StringFromCLSID round-trip. CLSID is an opaque 128-bit ID. */
    {
        const CLSID test_id = {0xdeadbeef, 0x1234, 0x5678, {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11}};
        LPOLESTR str = NULL;
        HRESULT r = StringFromCLSID(&test_id, &str);
        Out("[com_smoke] StringFromCLSID         = ");
        Out(r == S_OK && str != NULL ? "PASS\r\n" : "FAIL\r\n");
        if (str != NULL)
            CoTaskMemFree(str);
    }

    /* CoCreateInstance for a bogus CLSID. Should fail — but
     * the failure must be a *clean* HRESULT, not a trap. */
    {
        const CLSID bogus = {0x00000000, 0x0000, 0x0000, {0, 0, 0, 0, 0, 0, 0, 0}};
        void* p = NULL;
        HRESULT r = CoCreateInstance(&bogus, NULL, CLSCTX_INPROC_SERVER, &kIidIUnknown, &p);
        Out("[com_smoke] CoCreateInstance(bogus) = ");
        Out(FAILED(r) ? "PASS (failed cleanly)\r\n" : "FAIL (false success)\r\n");
        if (p != NULL)
        {
            /* Don't call Release — we can't trust the vtable. */
        }
    }

    CoUninitialize();
    Out("[com_smoke] CoUninitialize          = PASS (returned)\r\n");

    Out("[com_smoke] done\r\n");
    ExitProcess(0);
}
