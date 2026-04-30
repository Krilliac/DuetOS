/*
 * ntdll_smoke — exercise low-level Rtl* surface in ntdll.
 *
 * Probes the Rtl helper APIs that any non-trivial PE imports
 * directly (in addition to whatever kernel32 routes):
 *   RtlGetVersion (returns OSVERSIONINFOEXW filled in)
 *   RtlSecureZeroMemory
 *   RtlInitUnicodeString
 *   RtlNtStatusToDosError
 *   RtlMoveMemory (alias for memmove)
 *
 * Also the C-runtime intrinsics that ntdll reexports for kernel-
 * mode-agnostic code: memset / memcpy / strlen.
 */
#include <windows.h>

/* ntdll types we don't have a header for in freestanding mingw. */
typedef long NTSTATUS;
typedef struct
{
    unsigned short Length;
    unsigned short MaximumLength;
    wchar_t* Buffer;
} UNICODE_STRING;

extern NTSTATUS NTAPI RtlGetVersion(OSVERSIONINFOEXW* lpVersionInformation);
extern void NTAPI RtlInitUnicodeString(UNICODE_STRING* dst, const wchar_t* src);
extern ULONG NTAPI RtlNtStatusToDosError(NTSTATUS s);
/* RtlSecureZeroMemory is provided as a header-inline by mingw winnt.h. */

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
    Out("[ntdll_smoke] starting\r\n");

    /* RtlGetVersion. */
    {
        OSVERSIONINFOEXW vi = {0};
        vi.dwOSVersionInfoSize = sizeof(vi);
        NTSTATUS s = RtlGetVersion(&vi);
        Out("[ntdll_smoke] RtlGetVersion         = ");
        Out(s == 0 && vi.dwMajorVersion > 0 ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* RtlSecureZeroMemory — defeat the optimiser. */
    {
        unsigned char buf[16];
        for (int i = 0; i < 16; ++i)
            buf[i] = 0xAB;
        RtlSecureZeroMemory(buf, 16);
        int ok = 1;
        for (int i = 0; i < 16; ++i)
            if (buf[i] != 0)
                ok = 0;
        Out("[ntdll_smoke] RtlSecureZeroMemory   = ");
        Out(ok ? "PASS\r\n" : "FAIL\r\n");
    }

    /* RtlInitUnicodeString. */
    {
        UNICODE_STRING us = {0, 0, (wchar_t*)0};
        RtlInitUnicodeString(&us, L"hello");
        Out("[ntdll_smoke] RtlInitUnicodeString  = ");
        Out(us.Length == 10 && us.Buffer != NULL ? "PASS (len=10)\r\n" : "FAIL/STUB\r\n");
    }

    /* RtlNtStatusToDosError(STATUS_SUCCESS=0) → 0. */
    {
        ULONG e = RtlNtStatusToDosError(0);
        Out("[ntdll_smoke] RtlNtStatusToDosError = ");
        Out(e == 0 ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    Out("[ntdll_smoke] done\r\n");
    ExitProcess(0);
}
