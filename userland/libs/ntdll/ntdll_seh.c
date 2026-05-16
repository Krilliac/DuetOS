#include "ntdll_internal.h"

/* ------------------------------------------------------------------
 * SEH unwind helpers
 *
 * RtlCaptureContext (real register snapshot) and
 * RtlLookupFunctionEntry (real table-based .pdata lookup for the
 * main EXE) are implemented — the T6-02 unwinder foundation.
 * RtlVirtualUnwind / RtlUnwindEx and the kernel fault -> user
 * dispatch are the next slice and still stub (return "no match" /
 * terminate) so callers along the un-handled path degrade
 * gracefully rather than mis-unwind.
 * ------------------------------------------------------------------ */

/* SYS_DLL_BASE_BY_NAME = 172, empty name => calling EXE's base
 * (post-ASLR). Same trampoline kernel32 GetModuleHandleW(NULL)
 * uses; ntdll issues it directly to stay the bottom layer. */
static unsigned long long ntdll_exe_base(void)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)172), "D"((long long)0), "S"((long long)0) : "memory");
    return (unsigned long long)rv;
}

/* x64 IMAGE_RUNTIME_FUNCTION_ENTRY — three RVAs. */
typedef struct
{
    unsigned int BeginAddress;
    unsigned int EndAddress;
    unsigned int UnwindInfoAddress;
} RUNTIME_FUNCTION;

/* Real table-based RtlLookupFunctionEntry: find the
 * RUNTIME_FUNCTION whose [Begin,End) covers ControlPc by reading
 * the module's in-memory .pdata (IMAGE_DIRECTORY_ENTRY_EXCEPTION).
 * v0 resolves only the main EXE module (Chrome's primary case +
 * every single-module PE); DLL .pdata is the follow-on. Pure
 * reads of the already-mapped image — no control-flow effect. */
__declspec(dllexport) void* RtlLookupFunctionEntry(unsigned long long ControlPc, unsigned long long* ImageBase,
                                                   void* HistoryTable)
{
    (void)HistoryTable;
    const unsigned long long base = ntdll_exe_base();
    if (ImageBase != (unsigned long long*)0)
        *ImageBase = base;
    if (base == 0 || ControlPc < base)
        return (void*)0;
    const unsigned char* img = (const unsigned char*)base;
    if (img[0] != 'M' || img[1] != 'Z')
        return (void*)0;
    const unsigned int e_lfanew = *(const unsigned int*)(img + 0x3C);
    const unsigned char* nt = img + e_lfanew;
    if (nt[0] != 'P' || nt[1] != 'E' || nt[2] != 0 || nt[3] != 0)
        return (void*)0;
    const unsigned char* opt = nt + 0x18;
    if (*(const unsigned short*)opt != 0x20B) /* PE32+ only */
        return (void*)0;
    /* DataDirectory[3] = IMAGE_DIRECTORY_ENTRY_EXCEPTION. PE32+
     * optional header: DataDirectory begins at opt+0x70. */
    const unsigned int* dd = (const unsigned int*)(opt + 0x70 + 3 * 8);
    const unsigned int pdata_rva = dd[0];
    const unsigned int pdata_sz = dd[1];
    if (pdata_rva == 0 || pdata_sz < sizeof(RUNTIME_FUNCTION))
        return (void*)0;
    const RUNTIME_FUNCTION* fns = (const RUNTIME_FUNCTION*)(img + pdata_rva);
    const unsigned int n = pdata_sz / (unsigned int)sizeof(RUNTIME_FUNCTION);
    const unsigned int off = (unsigned int)(ControlPc - base);
    /* .pdata is sorted by BeginAddress — binary search. */
    unsigned int lo = 0, hi = n;
    while (lo < hi)
    {
        const unsigned int mid = lo + (hi - lo) / 2;
        if (off < fns[mid].BeginAddress)
            hi = mid;
        else if (off >= fns[mid].EndAddress)
            lo = mid + 1;
        else
            return (void*)&fns[mid];
    }
    return (void*)0;
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

/* Real RtlCaptureContext: snapshot the caller's register state
 * into the Microsoft x64 CONTEXT (rcx = record, MS ABI). Rip =
 * return address, Rsp = the caller's rsp *after* this returns.
 * Naked so the prologue can't perturb the captured state.
 * CONTEXT field offsets are the fixed Windows x64 layout. */
__attribute__((naked)) __declspec(dllexport) void RtlCaptureContext(void* ContextRecord)
{
    __asm__ volatile("movq %%rax, 0x78(%%rcx)\n\t"
                     "movq %%rdx, 0x88(%%rcx)\n\t"
                     "movq %%rbx, 0x90(%%rcx)\n\t"
                     "movq %%rbp, 0xA0(%%rcx)\n\t"
                     "movq %%rsi, 0xA8(%%rcx)\n\t"
                     "movq %%rdi, 0xB0(%%rcx)\n\t"
                     "movq %%r8,  0xB8(%%rcx)\n\t"
                     "movq %%r9,  0xC0(%%rcx)\n\t"
                     "movq %%r10, 0xC8(%%rcx)\n\t"
                     "movq %%r11, 0xD0(%%rcx)\n\t"
                     "movq %%r12, 0xD8(%%rcx)\n\t"
                     "movq %%r13, 0xE0(%%rcx)\n\t"
                     "movq %%r14, 0xE8(%%rcx)\n\t"
                     "movq %%r15, 0xF0(%%rcx)\n\t"
                     "movq %%rcx, 0x80(%%rcx)\n\t" /* captured Rcx = record ptr */
                     "leaq 8(%%rsp), %%rax\n\t"
                     "movq %%rax, 0x98(%%rcx)\n\t" /* Rsp after return */
                     "movq (%%rsp), %%rax\n\t"
                     "movq %%rax, 0xF8(%%rcx)\n\t" /* Rip = return addr */
                     "pushfq\n\t"
                     "popq %%rax\n\t"
                     "movl %%eax, 0x44(%%rcx)\n\t"       /* EFlags */
                     "movl $0x0010000F, 0x30(%%rcx)\n\t" /* ContextFlags */
                     "movq 0x78(%%rcx), %%rax\n\t"       /* restore rax */
                     "ret\n\t" ::
                         : "memory");
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
