/*
 * xml_smoke — exercise MSXML COM-based parsing surface.
 *
 *   CoCreateInstance(CLSID_DOMDocument)
 *
 * v0: MSXML is not implemented; the call should fail cleanly
 * with CLASS_E_CLASSNOTAVAILABLE rather than trap.
 */
#include <windows.h>
#include <objbase.h>

static const CLSID kClsidDomDocument = {0x88d96a05, 0xf192, 0x11d4, {0xa6, 0x5f, 0x00, 0x40, 0x96, 0x32, 0x51, 0xe5}};
static const IID kIidIUnknown = {0x00000000, 0x0000, 0x0000, {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};

static void Out(const char* s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0;
    DWORD len = 0;
    while (s[len] != '\0')
        ++len;
    WriteConsoleA(h, s, len, &n, 0);
}

void __cdecl mainCRTStartup(void)
{
    Out("[xml_smoke] starting\r\n");

    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    Out("[xml_smoke] CoInitializeEx       = ");
    Out(SUCCEEDED(hr) ? "PASS\r\n" : "FAIL/STUB\r\n");

    void* p = NULL;
    hr = CoCreateInstance(&kClsidDomDocument, NULL, CLSCTX_INPROC_SERVER, &kIidIUnknown, &p);
    Out("[xml_smoke] CoCreateInstance(DOM) = ");
    Out(FAILED(hr) ? "PASS (failed cleanly)\r\n" : "FAIL\r\n");

    CoUninitialize();
    Out("[xml_smoke] done\r\n");
    ExitProcess(0);
}
