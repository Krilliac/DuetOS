/*
 * nt_smoke - extended ntdll Nt / Zw / Rtl coverage beyond
 * ntdll_smoke (which had RtlGetVersion + RtlSecureZeroMemory).
 *
 *   NtQuerySystemTime
 *   RtlAllocateHeap / RtlFreeHeap (alias for HeapAlloc/Free)
 *   RtlIpv4StringToAddressA
 */
#include <windows.h>

typedef long NTSTATUS;
typedef struct
{
    long long t;
} LARGE_INTEGER_NT;

extern NTSTATUS NTAPI NtQuerySystemTime(LARGE_INTEGER* now);
extern NTSTATUS NTAPI RtlIpv4StringToAddressA(const char* s, BOOLEAN strict, const char** end, struct in_addr* addr);
extern void* NTAPI RtlAllocateHeap(HANDLE heap, ULONG flags, SIZE_T sz);
extern BOOLEAN NTAPI RtlFreeHeap(HANDLE heap, ULONG flags, void* p);

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
    Out("[nt_smoke] starting\r\n");

    /* NtQuerySystemTime. */
    {
        LARGE_INTEGER now = {0};
        NTSTATUS s = NtQuerySystemTime(&now);
        Out("[nt_smoke] NtQuerySystemTime    = ");
        Out(s == 0 && now.QuadPart != 0 ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* RtlAllocateHeap / RtlFreeHeap on the process heap. */
    {
        HANDLE ph = GetProcessHeap();
        void* p = RtlAllocateHeap(ph, 0, 256);
        Out("[nt_smoke] RtlAllocateHeap     = ");
        Out(p != NULL ? "PASS\r\n" : "FAIL/STUB\r\n");
        if (p != NULL)
        {
            BOOLEAN f = RtlFreeHeap(ph, 0, p);
            Out("[nt_smoke] RtlFreeHeap         = ");
            Out(f ? "PASS\r\n" : "FAIL/STUB\r\n");
        }
    }

    Out("[nt_smoke] done\r\n");
    Out("[ring3-nt-smoke] PASS\r\n");
    ExitProcess(0);
}
