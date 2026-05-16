#include "ntdll_internal.h"

/* ------------------------------------------------------------------
 * Rtl* — Win32 equivalents, inlined
 * ------------------------------------------------------------------ */

__declspec(dllexport) DWORD RtlGetLastWin32Error(void)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)9) : "memory");
    return (DWORD)rv;
}

__declspec(dllexport) void RtlSetLastWin32Error(DWORD err)
{
    long long discard;
    __asm__ volatile("int $0x80" : "=a"(discard) : "a"((long long)10), "D"((long long)err) : "memory");
}

__declspec(dllexport) ULONG RtlNtStatusToDosError(NTSTATUS s)
{
    (void)s;
    /* v0: every NTSTATUS maps to ERROR_SUCCESS (0). Matches
     * the flat kOffReturnZero registration. */
    return 0;
}

/* Rtl heap aliases — same syscall bindings as HeapAlloc etc. */
__declspec(dllexport) void* RtlAllocateHeap(HANDLE heap, ULONG flags, SIZE_T size)
{
    (void)heap;
    (void)flags;
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)11), "D"((long long)size) : "memory");
    return (void*)rv;
}

__declspec(dllexport) BOOL RtlFreeHeap(HANDLE heap, ULONG flags, void* mem)
{
    (void)heap;
    (void)flags;
    if (mem == (void*)0)
        return 1;
    long long discard;
    __asm__ volatile("int $0x80" : "=a"(discard) : "a"((long long)12), "D"((long long)mem) : "memory");
    return 1;
}

__declspec(dllexport) SIZE_T RtlSizeHeap(HANDLE heap, ULONG flags, const void* mem)
{
    (void)heap;
    (void)flags;
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)14), "D"((long long)mem) : "memory");
    return (SIZE_T)rv;
}

__declspec(dllexport) void* RtlReAllocateHeap(HANDLE heap, ULONG flags, void* mem, SIZE_T size)
{
    (void)heap;
    (void)flags;
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)15), "D"((long long)mem), "S"((long long)size) : "memory");
    return (void*)rv;
}

__declspec(dllexport) HANDLE RtlCreateHeap(ULONG flags, void* base, SIZE_T reserve, SIZE_T commit, void* lock,
                                           void* params)
{
    (void)flags;
    (void)base;
    (void)reserve;
    (void)commit;
    (void)lock;
    (void)params;
    return (HANDLE)0x50000000ULL;
}

__declspec(dllexport) void* RtlDestroyHeap(HANDLE heap)
{
    (void)heap;
    return (void*)0; /* NULL = success per Windows. */
}

/* Rtl memory helpers — plain C loops. These are exported by
 * ntdll but conventionally also in winapi as macros; we
 * implement them explicitly. */
#define NO_BUILTIN_RTLMEM __attribute__((no_builtin("memset", "memcpy", "memmove")))

__declspec(dllexport) NO_BUILTIN_RTLMEM void RtlZeroMemory(void* dst, SIZE_T n)
{
    unsigned char* d = (unsigned char*)dst;
    for (SIZE_T i = 0; i < n; ++i)
        d[i] = 0;
}

__declspec(dllexport) NO_BUILTIN_RTLMEM void RtlFillMemory(void* dst, SIZE_T n, unsigned char fill)
{
    unsigned char* d = (unsigned char*)dst;
    for (SIZE_T i = 0; i < n; ++i)
        d[i] = fill;
}

__declspec(dllexport) NO_BUILTIN_RTLMEM void RtlCopyMemory(void* dst, const void* src, SIZE_T n)
{
    unsigned char* d = (unsigned char*)dst;
    const unsigned char* s = (const unsigned char*)src;
    for (SIZE_T i = 0; i < n; ++i)
        d[i] = s[i];
}

__declspec(dllexport) NO_BUILTIN_RTLMEM void RtlMoveMemory(void* dst, const void* src, SIZE_T n)
{
    unsigned char* d = (unsigned char*)dst;
    const unsigned char* s = (const unsigned char*)src;
    if (d == s || n == 0)
        return;
    if (d < s)
    {
        for (SIZE_T i = 0; i < n; ++i)
            d[i] = s[i];
    }
    else
    {
        for (SIZE_T i = n; i > 0; --i)
            d[i - 1] = s[i - 1];
    }
}

__declspec(dllexport) SIZE_T RtlCompareMemory(const void* a, const void* b, SIZE_T n)
{
    const unsigned char* x = (const unsigned char*)a;
    const unsigned char* y = (const unsigned char*)b;
    for (SIZE_T i = 0; i < n; ++i)
        if (x[i] != y[i])
            return i;
    return n;
}

/* UNICODE_STRING / ANSI_STRING init helpers. The flat stubs
 * already initialise the struct: Length = byte-length without
 * NUL; MaximumLength = Length + sizeof(terminator); Buffer =
 * input pointer. UNICODE_STRING itself lives in
 * ntdll_internal.h (shared with the reg / token slices). */
typedef struct
{
    unsigned short Length;
    unsigned short MaximumLength;
    char* Buffer;
} ANSI_STRING;

__declspec(dllexport) void RtlInitUnicodeString(UNICODE_STRING* dst, const wchar_t16* src)
{
    if (dst == (UNICODE_STRING*)0)
        return;
    if (src == (const wchar_t16*)0)
    {
        dst->Length = 0;
        dst->MaximumLength = 0;
        dst->Buffer = (wchar_t16*)0;
        return;
    }
    unsigned short len = 0;
    while (src[len] != 0 && len < 0x7FFF)
        ++len;
    dst->Length = (unsigned short)(len * 2);
    dst->MaximumLength = (unsigned short)((len + 1) * 2);
    dst->Buffer = (wchar_t16*)src;
}

__declspec(dllexport) void RtlInitAnsiString(ANSI_STRING* dst, const char* src)
{
    if (dst == (ANSI_STRING*)0)
        return;
    if (src == (const char*)0)
    {
        dst->Length = 0;
        dst->MaximumLength = 0;
        dst->Buffer = (char*)0;
        return;
    }
    unsigned short len = 0;
    while (src[len] != 0 && len < 0xFFFF)
        ++len;
    dst->Length = len;
    dst->MaximumLength = (unsigned short)(len + 1);
    dst->Buffer = (char*)src;
}

__declspec(dllexport) void RtlFreeUnicodeString(UNICODE_STRING* s)
{
    /* The flat stub is kOffReturnZero — caller-allocated
     * string, nothing to free. Matches. */
    (void)s;
}

/* Rtl critical section — alias to the caller-owned atomic
 * protocol from kernel32's CriticalSection. Implemented
 * inline so ntdll.dll doesn't depend on kernel32 ordering. */

typedef long long volatile* CritSecPtr_t;

static long long ntdll_syscall_get_tid(void)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)1) : "memory");
    return rv;
}

static void ntdll_syscall_yield(void)
{
    long long discard;
    __asm__ volatile("int $0x80" : "=a"(discard) : "a"((long long)3) : "memory");
}

__declspec(dllexport) NTSTATUS RtlInitializeCriticalSection(void* cs)
{
    if (cs != (void*)0)
    {
        unsigned char* b = (unsigned char*)cs;
        for (int i = 0; i < 40; ++i)
            b[i] = 0;
    }
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) void RtlDeleteCriticalSection(void* cs)
{
    (void)cs;
}

__declspec(dllexport) NTSTATUS RtlEnterCriticalSection(void* cs)
{
    long long tid = ntdll_syscall_get_tid();
    CritSecPtr_t owner = (CritSecPtr_t)cs;
    long long volatile* recur = (long long volatile*)cs + 1;
    for (;;)
    {
        long long expected = 0;
        if (__atomic_compare_exchange_n(owner, &expected, tid, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
        {
            *recur = 1;
            return NTSTATUS_SUCCESS;
        }
        if (expected == tid)
        {
            *recur = *recur + 1;
            return NTSTATUS_SUCCESS;
        }
        ntdll_syscall_yield();
    }
}

__declspec(dllexport) NTSTATUS RtlLeaveCriticalSection(void* cs)
{
    CritSecPtr_t owner = (CritSecPtr_t)cs;
    long long volatile* recur = (long long volatile*)cs + 1;
    long long next = *recur - 1;
    *recur = next;
    if (next == 0)
        *owner = 0;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) BOOL RtlTryEnterCriticalSection(void* cs)
{
    long long tid = ntdll_syscall_get_tid();
    CritSecPtr_t owner = (CritSecPtr_t)cs;
    long long volatile* recur = (long long volatile*)cs + 1;
    long long expected = 0;
    if (__atomic_compare_exchange_n(owner, &expected, tid, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
    {
        *recur = 1;
        return 1;
    }
    if (expected == tid)
    {
        *recur = *recur + 1;
        return 1;
    }
    return 0;
}

typedef BOOL (*RtlRunOnceFn)(void* RunOnce, void* Parameter, void** Context);

__declspec(dllexport) NTSTATUS RtlRunOnceExecuteOnce(void* RunOnce, RtlRunOnceFn InitFn, void* Parameter,
                                                     void** Context)
{
    long long volatile* slot = (long long volatile*)RunOnce;
    long long expected = 0;
    if (__atomic_compare_exchange_n(slot, &expected, 1LL, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
    {
        if (InitFn != (RtlRunOnceFn)0)
            InitFn(RunOnce, Parameter, Context);
        *slot = 2;
        return NTSTATUS_SUCCESS;
    }
    while (__atomic_load_n(slot, __ATOMIC_SEQ_CST) != 2)
        ntdll_syscall_yield();
    return NTSTATUS_SUCCESS;
}
