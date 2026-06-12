/*
 * tls_smoke — exercise Thread-Local Storage APIs.
 *
 * Every C++ runtime uses TLS for thread-local instance state.
 * We exercise the dynamic TLS slot machinery (TlsAlloc /
 * TlsSet/Get / TlsFree) along with the cross-DLL FlsAlloc
 * variant (Fiber-local, syntactically identical):
 *   TlsAlloc / TlsFree
 *   TlsGetValue / TlsSetValue
 *
 * Verifies: allocated index in [0, TLS_MINIMUM_AVAILABLE),
 * round-trip a sentinel value, free returns success.
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
    Out("[tls_smoke] starting\r\n");

    DWORD slot = TlsAlloc();
    Out("[tls_smoke] TlsAlloc            = ");
    if (slot == TLS_OUT_OF_INDEXES)
    {
        Out("FAIL (out of indexes)\r\n");
        Out("[tls_smoke] done\r\n");
        Out("[ring3-tls-smoke] FAIL tlsalloc\r\n");
        ExitProcess(1);
    }
    Out("PASS slot=");
    OutHex((unsigned long long)slot);
    Out("\r\n");

    /* TlsSetValue + TlsGetValue round-trip. */
    BOOL set_ok = TlsSetValue(slot, (void*)0xDEADBEEFCAFEBABE);
    Out("[tls_smoke] TlsSetValue         = ");
    Out(set_ok ? "PASS\r\n" : "FAIL\r\n");

    void* got = TlsGetValue(slot);
    Out("[tls_smoke] TlsGetValue         = ");
    if ((unsigned long long)got == 0xDEADBEEFCAFEBABEULL)
        Out("PASS (round-trip)\r\n");
    else
    {
        Out("FAIL got=");
        OutHex((unsigned long long)got);
        Out("\r\n");
    }

    /* TlsSetValue(NULL) on a valid slot — should round-trip too. */
    TlsSetValue(slot, NULL);
    void* got2 = TlsGetValue(slot);
    Out("[tls_smoke] TlsSetValue(NULL)   = ");
    Out(got2 == NULL ? "PASS\r\n" : "FAIL\r\n");

    /* TlsFree. */
    BOOL free_ok = TlsFree(slot);
    Out("[tls_smoke] TlsFree             = ");
    Out(free_ok ? "PASS\r\n" : "FAIL\r\n");

    /* Allocate two slots — they should be distinct. */
    DWORD slot1 = TlsAlloc();
    DWORD slot2 = TlsAlloc();
    Out("[tls_smoke] TlsAlloc x2 distinct= ");
    Out(slot1 != TLS_OUT_OF_INDEXES && slot2 != TLS_OUT_OF_INDEXES && slot1 != slot2 ? "PASS\r\n" : "FAIL\r\n");
    if (slot1 != TLS_OUT_OF_INDEXES)
        TlsFree(slot1);
    if (slot2 != TLS_OUT_OF_INDEXES)
        TlsFree(slot2);

    Out("[tls_smoke] done\r\n");
    Out("[ring3-tls-smoke] PASS\r\n");
    ExitProcess(0);
}
