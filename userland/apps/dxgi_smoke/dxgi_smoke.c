/*
 * dxgi_smoke — exercise DXGI factory / adapter enumeration.
 *
 *   CreateDXGIFactory / CreateDXGIFactory1
 *   IDXGIFactory::EnumAdapters (skipped — needs vtable call)
 *
 * v0: every DXGI entry returns E_NOTIMPL. Smoke value =
 * "doesn't trap when D3D-using app initialises".
 */
#include <windows.h>

extern long __stdcall CreateDXGIFactory(const void* iid, void** factory);
extern long __stdcall CreateDXGIFactory1(const void* iid, void** factory);

static void Out(const char* s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0;
    DWORD len = 0;
    while (s[len] != '\0')
        ++len;
    WriteConsoleA(h, s, len, &n, 0);
}

static const GUID kIidDxgiFactory = {0x7b7166ec, 0x21c7, 0x44ae, {0xb2, 0x1a, 0xc9, 0xae, 0x32, 0x1a, 0xe3, 0x69}};

void __cdecl mainCRTStartup(void)
{
    Out("[dxgi_smoke] starting\r\n");

    void* factory = NULL;
    long hr = CreateDXGIFactory(&kIidDxgiFactory, &factory);
    Out("[dxgi_smoke] CreateDXGIFactory      = ");
    /* PASS = call returned (without trap). Either S_OK with handle
     * or a clean failure HRESULT both count. */
    Out("PASS (returned)\r\n");
    (void)hr;

    long hr2 = CreateDXGIFactory1(&kIidDxgiFactory, &factory);
    Out("[dxgi_smoke] CreateDXGIFactory1     = ");
    Out("PASS (returned)\r\n");
    (void)hr2;

    Out("[dxgi_smoke] done\r\n");
    Out("[ring3-dxgi-smoke] PASS\r\n");
    ExitProcess(0);
}
