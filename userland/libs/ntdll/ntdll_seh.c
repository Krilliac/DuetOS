#include "ntdll_internal.h"

/* ------------------------------------------------------------------
 * SEH unwind helpers
 *
 * Real ntdll walks .pdata RUNTIME_FUNCTION tables to support
 * unwinding and stack traces. v0 has no unwind machinery; all
 * of these return "no match" / zero so callers (typically CRT
 * crash handlers) gracefully give up.
 * ------------------------------------------------------------------ */

__declspec(dllexport) void* RtlLookupFunctionEntry(unsigned long long ControlPc, unsigned long long* ImageBase,
                                                   void* HistoryTable)
{
    (void)ControlPc;
    (void)HistoryTable;
    if (ImageBase != (unsigned long long*)0)
        *ImageBase = 0;
    return (void*)0; /* No RUNTIME_FUNCTION found. */
}

__declspec(dllexport) void* RtlVirtualUnwind(unsigned long HandlerType, unsigned long long ImageBase,
                                             unsigned long long ControlPc, void* FunctionEntry, void* ContextRecord,
                                             void** HandlerData, unsigned long long* EstablisherFrame,
                                             void* ContextPointers)
{
    (void)HandlerType;
    (void)ImageBase;
    (void)ControlPc;
    (void)FunctionEntry;
    (void)ContextRecord;
    (void)ContextPointers;
    if (HandlerData != (void**)0)
        *HandlerData = (void*)0;
    if (EstablisherFrame != (unsigned long long*)0)
        *EstablisherFrame = 0;
    return (void*)0; /* No exception handler found. */
}

/* RtlCaptureContext captures the current thread's register
 * state to a CONTEXT struct (1232 bytes on x64). We zero the
 * caller's struct; crash handlers that walk it see an "empty"
 * context. */
__declspec(dllexport) void RtlCaptureContext(void* ContextRecord)
{
    if (ContextRecord == (void*)0)
        return;
    unsigned char* b = (unsigned char*)ContextRecord;
    for (int i = 0; i < 1232; ++i)
        b[i] = 0;
}

__declspec(dllexport) unsigned short RtlCaptureStackBackTrace(unsigned long FramesToSkip, unsigned long FramesToCapture,
                                                              void** BackTrace, unsigned long* BackTraceHash)
{
    (void)FramesToSkip;
    (void)FramesToCapture;
    (void)BackTrace;
    if (BackTraceHash != (unsigned long*)0)
        *BackTraceHash = 0;
    return 0; /* No frames captured. */
}

__declspec(dllexport) void RtlUnwind(void* TargetFrame, void* TargetIp, void* ExceptionRecord, void* ReturnValue)
{
    (void)TargetFrame;
    (void)TargetIp;
    (void)ExceptionRecord;
    (void)ReturnValue;
    /* Can't unwind; terminate. */
    __asm__ volatile("int $0x80" : : "a"((long long)0), "D"((long long)3));
}

__declspec(dllexport) void RtlUnwindEx(void* TargetFrame, void* TargetIp, void* ExceptionRecord, void* ReturnValue,
                                       void* ContextRecord, void* HistoryTable)
{
    (void)TargetFrame;
    (void)TargetIp;
    (void)ExceptionRecord;
    (void)ReturnValue;
    (void)ContextRecord;
    (void)HistoryTable;
    __asm__ volatile("int $0x80" : : "a"((long long)0), "D"((long long)3));
}

/* RtlGetVersion / RtlVerifyVersionInfo — same v0 build as
 * kernel32 GetVersionEx, but with NTSTATUS returns. Used by
 * Vista+ apps that bypass the deprecated GetVersionEx and ask
 * RtlGetVersion directly. Win10 build 19041 matches the
 * registry stub in advapi32. */
__declspec(dllexport) NTSTATUS RtlGetVersion(void* info)
{
    if (!info)
        return 0xC000000DUL;
    DWORD* p = (DWORD*)info;
    DWORD struct_size = p[0];
    if (struct_size < 276)
        return 0xC0000023UL;
    p[1] = 10;
    p[2] = 0;
    p[3] = 19041;
    p[4] = 2;
    unsigned short* csd = (unsigned short*)((unsigned char*)info + 20);
    csd[0] = 0;
    if (struct_size >= 284)
    {
        unsigned short* tail = (unsigned short*)((unsigned char*)info + 276);
        tail[0] = 0;
        tail[1] = 0;
        tail[2] = 0;
        tail[3] = 1;
    }
    return 0;
}

__declspec(dllexport) NTSTATUS RtlVerifyVersionInfo(void* info, DWORD type_mask, unsigned long long cond_mask)
{
    (void)info;
    (void)type_mask;
    (void)cond_mask;
    return 0;
}

/* RtlComputeCrc32. Reflected polynomial 0xEDB88320. */
__declspec(dllexport) DWORD RtlComputeCrc32(DWORD seed, const unsigned char* buf, ULONG len)
{
    DWORD crc = seed ^ 0xFFFFFFFFu;
    for (ULONG i = 0; i < len; ++i)
    {
        crc ^= buf[i];
        for (int j = 0; j < 8; ++j)
            crc = (crc >> 1) ^ (0xEDB88320u & -(int)(crc & 1));
    }
    return crc ^ 0xFFFFFFFFu;
}

/* RtlGenRandom. Mixes SYS_PERF_COUNTER ticks per call.
 * NOT formally cryptographic. */
static unsigned long long g_rtl_rand = 0xCAFEBABEDEADBEEFULL;
__declspec(dllexport) BOOL RtlGenRandom(void* buf, ULONG len)
{
    if (!buf || len == 0)
        return 1;
    long long ticks;
    __asm__ volatile("int $0x80" : "=a"(ticks) : "a"((long long)13) : "memory");
    g_rtl_rand ^= (unsigned long long)ticks;
    unsigned char* p = (unsigned char*)buf;
    for (ULONG i = 0; i < len; ++i)
    {
        g_rtl_rand = g_rtl_rand * 6364136223846793005ULL + 1442695040888963407ULL;
        p[i] = (unsigned char)(g_rtl_rand >> 56);
    }
    return 1;
}

/* RtlSecureZeroMemory: same as RtlZeroMemory but the compiler
 * isn't allowed to optimise it away. The no-builtin attribute
 * already prevents that for our RtlZeroMemory; alias it. */
__declspec(dllexport) void* RtlSecureZeroMemory(void* dst, SIZE_T n)
{
    unsigned char volatile* d = (unsigned char volatile*)dst;
    for (SIZE_T i = 0; i < n; ++i)
        d[i] = 0;
    return dst;
}

/* RtlIpv4StringToAddressA / W — parse "a.b.c.d" into a 32-bit IN_ADDR.
 * Strict==TRUE rejects shorthand forms (a, a.b, a.b.c); strict==FALSE
 * tolerates them per the original inet_addr semantics:
 *   "a"        -> 0.0.0.0 with high 32 = a
 *   "a.b"      -> a.0.0.b
 *   "a.b.c"    -> a.b.0.c
 *   "a.b.c.d"  -> a.b.c.d
 * Returns NTSTATUS 0 (STATUS_SUCCESS) on success, STATUS_INVALID_PARAMETER
 * (0xC000000D) otherwise. *terminator points past the last consumed byte. */
__declspec(dllexport) NTSTATUS RtlIpv4StringToAddressA(const char* s, BOOL strict, const char** terminator,
                                                       unsigned char* addr_be)
{
    if (!s || !addr_be)
        return 0xC000000DUL;
    unsigned int parts[4];
    int part_count = 0;
    const char* p = s;
    while (part_count < 4)
    {
        if (*p < '0' || *p > '9')
            return 0xC000000DUL;
        unsigned int n = 0;
        int hex = 0, octal = 0;
        if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X') && !strict)
        {
            hex = 1;
            p += 2;
            while ((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F'))
            {
                int v = (*p >= '0' && *p <= '9') ? *p - '0' : ((*p | 0x20) - 'a' + 10);
                if (n > 0xFFFFFFFFu / 16u)
                    return 0xC000000DUL;
                n = n * 16 + (unsigned int)v;
                ++p;
            }
        }
        else if (p[0] == '0' && p[1] >= '0' && p[1] <= '7' && !strict)
        {
            octal = 1;
            ++p;
            while (*p >= '0' && *p <= '7')
            {
                if (n > 0xFFFFFFFFu / 8u)
                    return 0xC000000DUL;
                n = n * 8 + (unsigned int)(*p - '0');
                ++p;
            }
        }
        else
        {
            while (*p >= '0' && *p <= '9')
            {
                if (n > 0xFFFFFFFFu / 10u)
                    return 0xC000000DUL;
                n = n * 10 + (unsigned int)(*p - '0');
                ++p;
            }
        }
        (void)hex;
        (void)octal;
        parts[part_count++] = n;
        if (*p != '.')
            break;
        ++p;
    }
    if (strict && part_count != 4)
        return 0xC000000DUL;
    unsigned int out;
    switch (part_count)
    {
    case 1:
        out = parts[0];
        break;
    case 2:
        if (parts[0] > 0xFF || parts[1] > 0xFFFFFFu)
            return 0xC000000DUL;
        out = (parts[0] << 24) | parts[1];
        break;
    case 3:
        if (parts[0] > 0xFF || parts[1] > 0xFF || parts[2] > 0xFFFFu)
            return 0xC000000DUL;
        out = (parts[0] << 24) | (parts[1] << 16) | parts[2];
        break;
    case 4:
        if (parts[0] > 0xFF || parts[1] > 0xFF || parts[2] > 0xFF || parts[3] > 0xFF)
            return 0xC000000DUL;
        out = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
        break;
    default:
        return 0xC000000DUL;
    }
    addr_be[0] = (unsigned char)((out >> 24) & 0xFF);
    addr_be[1] = (unsigned char)((out >> 16) & 0xFF);
    addr_be[2] = (unsigned char)((out >> 8) & 0xFF);
    addr_be[3] = (unsigned char)(out & 0xFF);
    if (terminator)
        *terminator = p;
    return 0;
}

__declspec(dllexport) NTSTATUS RtlIpv4StringToAddressW(const wchar_t16* s, BOOL strict, const wchar_t16** terminator,
                                                       unsigned char* addr_be)
{
    if (!s || !addr_be)
        return 0xC000000DUL;
    /* Re-encode to ASCII on the stack — IPv4 strings are at most
     * 15 chars + NUL; cap at 64 to be defensive. */
    char buf[64];
    int i = 0;
    for (; i < 63 && s[i]; ++i)
    {
        if (s[i] > 0x7F)
            return 0xC000000DUL;
        buf[i] = (char)s[i];
    }
    buf[i] = 0;
    const char* term = (const char*)0;
    NTSTATUS rc = RtlIpv4StringToAddressA(buf, strict, &term, addr_be);
    if (rc == 0 && terminator)
        *terminator = s + (term - buf);
    return rc;
}

/* RtlIpv4AddressToStringA / W — print 4-byte BE IPv4 as "a.b.c.d".
 * Returns pointer past the last char written (per Windows docs). */
__declspec(dllexport) char* RtlIpv4AddressToStringA(const unsigned char* addr_be, char* out)
{
    if (!addr_be || !out)
        return out;
    char* p = out;
    for (int i = 0; i < 4; ++i)
    {
        unsigned int v = addr_be[i];
        if (v >= 100)
        {
            *p++ = '0' + (v / 100);
            *p++ = '0' + (v / 10) % 10;
            *p++ = '0' + v % 10;
        }
        else if (v >= 10)
        {
            *p++ = '0' + (v / 10);
            *p++ = '0' + v % 10;
        }
        else
        {
            *p++ = '0' + v;
        }
        if (i < 3)
            *p++ = '.';
    }
    *p = 0;
    return p;
}

__declspec(dllexport) wchar_t16* RtlIpv4AddressToStringW(const unsigned char* addr_be, wchar_t16* out)
{
    if (!addr_be || !out)
        return out;
    char tmp[16];
    char* end = RtlIpv4AddressToStringA(addr_be, tmp);
    int n = (int)(end - tmp);
    for (int i = 0; i <= n; ++i)
        out[i] = (wchar_t16)(unsigned char)tmp[i];
    return out + n;
}
