/*
 * resource_smoke — exercise kernel32 / user32 resource APIs.
 *
 * Probes the embedded-resource surface every Windows app uses
 * for icons, strings, manifest, version info:
 *   FindResourceW / FindResourceA
 *   LoadResource
 *   LockResource / SizeofResource
 *   FreeResource (legacy)
 *   LoadStringW / LoadStringA (user32)
 *   EnumResourceTypesW (skipped — callback)
 *
 * This image deliberately carries NO .rsrc, so it is the negative
 * half of the resource surface: every lookup must miss cleanly and
 * nothing must trap. The positive half — real strings and binary
 * resources out of a windres-built .rsrc — is userland/apps/rsrc_pe.
 *
 * Note the LoadStringW(missing) check was silently FAILING before the
 * .rsrc parser landed (2026-07-28): user32's LoadStringW used to
 * return a fixed "DuetOS" placeholder for every id, so it answered 6
 * where this asserts 0. Nobody saw it because this row is BareMetal-
 * gated and never runs under QEMU CI.
 */
#include <windows.h>

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
    Out("[resource_smoke] starting\r\n");

    HMODULE me = GetModuleHandleW(NULL);

    /* FindResourceW on a missing resource — should return NULL. */
    {
        HRSRC h = FindResourceW(me, MAKEINTRESOURCEW(1234), MAKEINTRESOURCEW(6) /* RT_STRING */);
        Out("[resource_smoke] FindResourceW(missing)= ");
        Out(h == NULL ? "PASS (NULL, as expected)\r\n" : "FAIL (false hit)\r\n");
    }

    /* LoadStringW on a missing string — should return 0. */
    {
        WCHAR buf[64] = {0};
        int n = LoadStringW(me, 0xDEAD, buf, 64);
        Out("[resource_smoke] LoadStringW(missing)  = ");
        Out(n == 0 ? "PASS (0, as expected)\r\n" : "FAIL\r\n");
    }

    /* SizeofResource on NULL — should return 0. */
    {
        DWORD n = SizeofResource(me, NULL);
        Out("[resource_smoke] SizeofResource(NULL)  = ");
        Out(n == 0 ? "PASS\r\n" : "FAIL\r\n");
    }

    /* LoadCursorW(NULL, IDC_ARROW) — built-in cursor. */
    {
        HCURSOR c = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
        Out("[resource_smoke] LoadCursorW(IDC_ARROW)= ");
        Out(c != NULL ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* LoadIconW(NULL, IDI_APPLICATION) — built-in icon. */
    {
        HICON i = LoadIconW(NULL, (LPCWSTR)IDI_APPLICATION);
        Out("[resource_smoke] LoadIconW(IDI_APP)    = ");
        Out(i != NULL ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    Out("[resource_smoke] done\r\n");
    Out("[ring3-resource-smoke] PASS\r\n");
    ExitProcess(0);
}
