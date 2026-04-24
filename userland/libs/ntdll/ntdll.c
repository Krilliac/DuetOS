/*
 * userland/libs/ntdll/ntdll.c
 *
 * Freestanding CustomOS ntdll.dll — the foundational Windows
 * DLL. Retires the batch-42-and-later flat-stub rows for
 * ntdll.dll / __chkstk / Nt* / Zw* / Rtl* / Ldr*.
 *
 * Layout:
 *   1. __chkstk — x86_64 stack probe (no-op on v0: PeLoad
 *      maps the stack up front, so no page-crossing faults).
 *   2. Nt* primitives with real syscall bindings (NtClose,
 *      NtYield, NtDelay, NtQueryPerfCounter / SystemTime,
 *      NtTerminate{Process,Thread}, NtAllocateVirtualMemory,
 *      NtFreeVirtualMemory, NtSetEvent / ResetEvent,
 *      NtWaitForSingleObject, NtReleaseMutant).
 *   3. Nt* with no real backing — all forward to a single
 *      `NtReturnNotImpl` function returning
 *      STATUS_NOT_IMPLEMENTED (0xC00000BB).
 *   4. Zw* aliases emitted via lld-link /export:Zw=Nt (done
 *      in the build script — keeps one copy of each function
 *      but exposes both names).
 *   5. Rtl* — kernel32.dll equivalents, inlined here so we
 *      don't depend on kernel32 being loaded first.
 *   6. Ldr* — return STATUS_NOT_IMPLEMENTED.
 *
 * Build: tools/build-ntdll-dll.sh at /base:0x10060000.
 */

typedef unsigned int       DWORD;
typedef unsigned int       UINT;
typedef int                BOOL;
typedef void*              HANDLE;
typedef unsigned long      ULONG;
typedef unsigned long long SIZE_T;
typedef unsigned long      NTSTATUS; /* 32-bit on MSVC LLP64 */
typedef unsigned short     wchar_t16;

#define NTSTATUS_SUCCESS             0x00000000UL
#define NTSTATUS_NOT_IMPLEMENTED     0xC00000BBUL
#define NTSTATUS_NO_MEMORY           0xC0000017UL
#define NTSTATUS_INVALID_PARAMETER   0xC000000DUL

#define NTDLL_NORETURN __attribute__((noreturn))

/* ------------------------------------------------------------------
 * __chkstk — x86_64 stack probe
 *
 * MSVC emits a call to __chkstk at every function with a stack
 * frame ≥ 4 KiB. On real Windows it touches each intermediate
 * page so the OS can lazy-grow the stack. Our PE loader maps
 * the full stack region up front, so the probe is a no-op.
 * Return paths: ret (rax unchanged; msvcrt doesn't observe).
 * ------------------------------------------------------------------ */

__declspec(dllexport) void __chkstk(void)
{
    /* Nothing to do. */
}

/* ------------------------------------------------------------------
 * STATUS_NOT_IMPLEMENTED sink — every Nt / Zw / Ldr entry
 * without a real impl aliases to this via
 * /export:Name=NtReturnNotImpl.
 * ------------------------------------------------------------------ */

__declspec(dllexport) NTSTATUS NtReturnNotImpl(void)
{
    return NTSTATUS_NOT_IMPLEMENTED;
}

/* ------------------------------------------------------------------
 * Real Nt* primitives
 *
 * Native syscall bindings (same as kernel32.dll's Win32 calls —
 * Nt* is just the NT ABI underneath):
 *   SYS_EXIT         = 0  — NtTerminateProcess / Thread / NtContinue
 *   SYS_YIELD        = 3  — NtYieldExecution
 *   SYS_FILE_CLOSE   = 22 — NtClose
 *   SYS_VMAP         = 28 — NtAllocateVirtualMemory
 *   SYS_VUNMAP       = 29 — NtFreeVirtualMemory
 *   SYS_EVENT_SET    = 31 — NtSetEvent
 *   SYS_EVENT_RESET  = 32 — NtResetEvent
 *   SYS_EVENT_WAIT   = 33 / SYS_MUTEX_WAIT = 26 / SYS_SEM_WAIT = 53 /
 *                    SYS_THREAD_WAIT = 54 — NtWaitForSingleObject
 *   SYS_MUTEX_RELEASE= 27 — NtReleaseMutant
 *   SYS_GETTIME_FT   = 17 — NtQuerySystemTime
 *   SYS_NOW_NS       = 18 — NtQueryPerformanceCounter
 *   SYS_SLEEP_MS     = 19 — NtDelayExecution (ms slice)
 *   SYS_GETLASTERROR = 9, SYS_SETLASTERROR = 10 — Rtl* aliases
 * ------------------------------------------------------------------ */

__declspec(dllexport) NTSTATUS NtClose(HANDLE h)
{
    long long discard;
    __asm__ volatile("int $0x80" : "=a"(discard) : "a"((long long) 22), "D"((long long) h) : "memory");
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtYieldExecution(void)
{
    long long discard;
    __asm__ volatile("int $0x80" : "=a"(discard) : "a"((long long) 3) : "memory");
    return NTSTATUS_SUCCESS;
}

/* NtDelayExecution(bAlertable=rcx, DelayInterval=rdx).
 * DelayInterval is a pointer to LARGE_INTEGER (100 ns units).
 * Negative value = relative; positive = absolute. v0 converts
 * relative intervals to milliseconds and issues SYS_SLEEP_MS;
 * absolute times are approximated as a zero-delay yield. */
__declspec(dllexport) NTSTATUS NtDelayExecution(BOOL bAlertable, const long long* DelayInterval)
{
    (void) bAlertable;
    if (DelayInterval == (const long long*) 0)
        return NtYieldExecution();
    long long ns100 = *DelayInterval;
    unsigned long long ms;
    if (ns100 < 0)
        ms = (unsigned long long) (-ns100) / 10000ULL; /* 100 ns -> ms */
    else
        ms = 0; /* Absolute time — approximate as yield. */
    long long discard;
    __asm__ volatile("int $0x80" : "=a"(discard) : "a"((long long) 19), "D"((long long) ms) : "memory");
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtQueryPerformanceCounter(long long* counter, long long* freq)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long) 18) : "memory");
    if (counter != (long long*) 0)
        *counter = rv;
    if (freq != (long long*) 0)
        *freq = 1000000000LL; /* 1 GHz — pairs with SYS_NOW_NS returning ns. */
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtQuerySystemTime(long long* SystemTime)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long) 17) : "memory");
    if (SystemTime != (long long*) 0)
        *SystemTime = rv;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTDLL_NORETURN NTSTATUS NtTerminateProcess(HANDLE hProcess, NTSTATUS exit_status)
{
    (void) hProcess;
    __asm__ volatile("int $0x80" : : "a"((long long) 0), "D"((long long) exit_status));
    __builtin_unreachable();
}

__declspec(dllexport) NTDLL_NORETURN NTSTATUS NtTerminateThread(HANDLE hThread, NTSTATUS exit_status)
{
    (void) hThread;
    __asm__ volatile("int $0x80" : : "a"((long long) 0), "D"((long long) exit_status));
    __builtin_unreachable();
}

/* NtContinue — restores a CONTEXT. v0 can't actually do it;
 * fall through to termination (matching the flat stub which
 * forwards to kOffExitProcess). */
__declspec(dllexport) NTDLL_NORETURN NTSTATUS NtContinue(void* context, BOOL bTestAlert)
{
    (void) context;
    (void) bTestAlert;
    __asm__ volatile("int $0x80" : : "a"((long long) 0), "D"((long long) 0));
    __builtin_unreachable();
}

/* NtAllocateVirtualMemory — read *RegionSize, hand to SYS_VMAP,
 * write result into *BaseAddress; echo size back. Matches the
 * flat-stub semantics at kOffNtAllocateVirtualMemory. */
__declspec(dllexport) NTSTATUS NtAllocateVirtualMemory(HANDLE hProcess, void** BaseAddress, SIZE_T ZeroBits,
                                                      SIZE_T* RegionSize, ULONG AllocationType, ULONG Protect)
{
    (void) hProcess;
    (void) ZeroBits;
    (void) AllocationType;
    (void) Protect;
    if (RegionSize == (SIZE_T*) 0 || BaseAddress == (void**) 0)
        return NTSTATUS_INVALID_PARAMETER;
    long long sz = (long long) *RegionSize;
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long) 28), "D"(sz) : "memory");
    if (rv == 0)
        return NTSTATUS_NO_MEMORY;
    *BaseAddress = (void*) rv;
    /* *RegionSize stays unchanged — v0 honours exactly what was asked. */
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtFreeVirtualMemory(HANDLE hProcess, void** BaseAddress, SIZE_T* RegionSize,
                                                  ULONG FreeType)
{
    (void) hProcess;
    (void) FreeType;
    if (BaseAddress == (void**) 0 || RegionSize == (SIZE_T*) 0)
        return NTSTATUS_INVALID_PARAMETER;
    long long va = (long long) *BaseAddress;
    long long sz = (long long) *RegionSize;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long) 29), "D"(va), "S"(sz)
                     : "memory");
    return rv == 0 ? NTSTATUS_SUCCESS : NTSTATUS_INVALID_PARAMETER;
}

__declspec(dllexport) NTSTATUS NtSetEvent(HANDLE h, long* previous_state)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long) 31), "D"((long long) h) : "memory");
    if (previous_state != (long*) 0)
        *previous_state = 0;
    return rv == 0 ? NTSTATUS_SUCCESS : NTSTATUS_INVALID_PARAMETER;
}

__declspec(dllexport) NTSTATUS NtResetEvent(HANDLE h, long* previous_state)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long) 32), "D"((long long) h) : "memory");
    if (previous_state != (long*) 0)
        *previous_state = 0;
    return rv == 0 ? NTSTATUS_SUCCESS : NTSTATUS_INVALID_PARAMETER;
}

/* NtReleaseMutant -> SYS_MUTEX_RELEASE (27). */
__declspec(dllexport) NTSTATUS NtReleaseMutant(HANDLE h, long* previous_count)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long) 27), "D"((long long) h) : "memory");
    if (previous_count != (long*) 0)
        *previous_count = 0;
    return rv == 0 ? NTSTATUS_SUCCESS : NTSTATUS_INVALID_PARAMETER;
}

/* NtWaitForSingleObject — dispatch by handle range (same as
 * kernel32!WaitForSingleObject). */
__declspec(dllexport) NTSTATUS NtWaitForSingleObject(HANDLE h, BOOL bAlertable, const long long* timeout100ns)
{
    (void) bAlertable;
    unsigned long long handle = (unsigned long long) h;
    long long syscall_num;
    if (handle >= 0x200 && handle < 0x208)
        syscall_num = 26; /* SYS_MUTEX_WAIT */
    else if (handle >= 0x300 && handle < 0x308)
        syscall_num = 33; /* SYS_EVENT_WAIT */
    else if (handle >= 0x500 && handle < 0x508)
        syscall_num = 53; /* SYS_SEM_WAIT */
    else if (handle >= 0x400 && handle < 0x408)
        syscall_num = 54; /* SYS_THREAD_WAIT */
    else
        return NTSTATUS_SUCCESS; /* Unknown — pseudo-signal. */
    /* Convert 100 ns units to ms. Negative = relative; positive =
     * absolute (we approximate as 0 = no-wait). NULL = INFINITE. */
    unsigned long long ms;
    if (timeout100ns == (const long long*) 0)
        ms = 0xFFFFFFFFull; /* INFINITE */
    else if (*timeout100ns < 0)
        ms = (unsigned long long) (-*timeout100ns) / 10000ULL;
    else
        ms = 0;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"(syscall_num), "D"((long long) h), "S"((long long) ms)
                     : "memory");
    return (NTSTATUS) rv;
}

/* ------------------------------------------------------------------
 * Rtl* — Win32 equivalents, inlined
 * ------------------------------------------------------------------ */

__declspec(dllexport) DWORD RtlGetLastWin32Error(void)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long) 9) : "memory");
    return (DWORD) rv;
}

__declspec(dllexport) void RtlSetLastWin32Error(DWORD err)
{
    long long discard;
    __asm__ volatile("int $0x80"
                     : "=a"(discard)
                     : "a"((long long) 10), "D"((long long) err)
                     : "memory");
}

__declspec(dllexport) ULONG RtlNtStatusToDosError(NTSTATUS s)
{
    (void) s;
    /* v0: every NTSTATUS maps to ERROR_SUCCESS (0). Matches
     * the flat kOffReturnZero registration. */
    return 0;
}

/* Rtl heap aliases — same syscall bindings as HeapAlloc etc. */
__declspec(dllexport) void* RtlAllocateHeap(HANDLE heap, ULONG flags, SIZE_T size)
{
    (void) heap;
    (void) flags;
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long) 11), "D"((long long) size) : "memory");
    return (void*) rv;
}

__declspec(dllexport) BOOL RtlFreeHeap(HANDLE heap, ULONG flags, void* mem)
{
    (void) heap;
    (void) flags;
    if (mem == (void*) 0)
        return 1;
    long long discard;
    __asm__ volatile("int $0x80" : "=a"(discard) : "a"((long long) 12), "D"((long long) mem) : "memory");
    return 1;
}

__declspec(dllexport) SIZE_T RtlSizeHeap(HANDLE heap, ULONG flags, const void* mem)
{
    (void) heap;
    (void) flags;
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long) 14), "D"((long long) mem) : "memory");
    return (SIZE_T) rv;
}

__declspec(dllexport) void* RtlReAllocateHeap(HANDLE heap, ULONG flags, void* mem, SIZE_T size)
{
    (void) heap;
    (void) flags;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long) 15), "D"((long long) mem), "S"((long long) size)
                     : "memory");
    return (void*) rv;
}

__declspec(dllexport) HANDLE RtlCreateHeap(ULONG flags, void* base, SIZE_T reserve, SIZE_T commit, void* lock,
                                          void* params)
{
    (void) flags;
    (void) base;
    (void) reserve;
    (void) commit;
    (void) lock;
    (void) params;
    return (HANDLE) 0x50000000ULL;
}

__declspec(dllexport) void* RtlDestroyHeap(HANDLE heap)
{
    (void) heap;
    return (void*) 0; /* NULL = success per Windows. */
}

/* Rtl memory helpers — plain C loops. These are exported by
 * ntdll but conventionally also in winapi as macros; we
 * implement them explicitly. */
#define NO_BUILTIN_RTLMEM __attribute__((no_builtin("memset", "memcpy", "memmove")))

__declspec(dllexport) NO_BUILTIN_RTLMEM void RtlZeroMemory(void* dst, SIZE_T n)
{
    unsigned char* d = (unsigned char*) dst;
    for (SIZE_T i = 0; i < n; ++i)
        d[i] = 0;
}

__declspec(dllexport) NO_BUILTIN_RTLMEM void RtlFillMemory(void* dst, SIZE_T n, unsigned char fill)
{
    unsigned char* d = (unsigned char*) dst;
    for (SIZE_T i = 0; i < n; ++i)
        d[i] = fill;
}

__declspec(dllexport) NO_BUILTIN_RTLMEM void RtlCopyMemory(void* dst, const void* src, SIZE_T n)
{
    unsigned char*       d = (unsigned char*) dst;
    const unsigned char* s = (const unsigned char*) src;
    for (SIZE_T i = 0; i < n; ++i)
        d[i] = s[i];
}

__declspec(dllexport) NO_BUILTIN_RTLMEM void RtlMoveMemory(void* dst, const void* src, SIZE_T n)
{
    unsigned char*       d = (unsigned char*) dst;
    const unsigned char* s = (const unsigned char*) src;
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
    const unsigned char* x = (const unsigned char*) a;
    const unsigned char* y = (const unsigned char*) b;
    for (SIZE_T i = 0; i < n; ++i)
        if (x[i] != y[i])
            return i;
    return n;
}

/* UNICODE_STRING / ANSI_STRING init helpers. The flat stubs
 * already initialise the struct: Length = byte-length without
 * NUL; MaximumLength = Length + sizeof(terminator); Buffer =
 * input pointer. */
typedef struct
{
    unsigned short Length;
    unsigned short MaximumLength;
    wchar_t16*     Buffer;
} UNICODE_STRING;

typedef struct
{
    unsigned short Length;
    unsigned short MaximumLength;
    char*          Buffer;
} ANSI_STRING;

__declspec(dllexport) void RtlInitUnicodeString(UNICODE_STRING* dst, const wchar_t16* src)
{
    if (dst == (UNICODE_STRING*) 0)
        return;
    if (src == (const wchar_t16*) 0)
    {
        dst->Length        = 0;
        dst->MaximumLength = 0;
        dst->Buffer        = (wchar_t16*) 0;
        return;
    }
    unsigned short len = 0;
    while (src[len] != 0 && len < 0x7FFF)
        ++len;
    dst->Length        = (unsigned short) (len * 2);
    dst->MaximumLength = (unsigned short) ((len + 1) * 2);
    dst->Buffer        = (wchar_t16*) src;
}

__declspec(dllexport) void RtlInitAnsiString(ANSI_STRING* dst, const char* src)
{
    if (dst == (ANSI_STRING*) 0)
        return;
    if (src == (const char*) 0)
    {
        dst->Length        = 0;
        dst->MaximumLength = 0;
        dst->Buffer        = (char*) 0;
        return;
    }
    unsigned short len = 0;
    while (src[len] != 0 && len < 0xFFFF)
        ++len;
    dst->Length        = len;
    dst->MaximumLength = (unsigned short) (len + 1);
    dst->Buffer        = (char*) src;
}

__declspec(dllexport) void RtlFreeUnicodeString(UNICODE_STRING* s)
{
    /* The flat stub is kOffReturnZero — caller-allocated
     * string, nothing to free. Matches. */
    (void) s;
}

/* Rtl critical section — alias to the caller-owned atomic
 * protocol from kernel32's CriticalSection. Implemented
 * inline so ntdll.dll doesn't depend on kernel32 ordering. */

typedef long long volatile* CritSecPtr_t;

static long long ntdll_syscall_get_tid(void)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long) 1) : "memory");
    return rv;
}

static void ntdll_syscall_yield(void)
{
    long long discard;
    __asm__ volatile("int $0x80" : "=a"(discard) : "a"((long long) 3) : "memory");
}

__declspec(dllexport) NTSTATUS RtlInitializeCriticalSection(void* cs)
{
    if (cs != (void*) 0)
    {
        unsigned char* b = (unsigned char*) cs;
        for (int i = 0; i < 40; ++i)
            b[i] = 0;
    }
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) void RtlDeleteCriticalSection(void* cs)
{
    (void) cs;
}

__declspec(dllexport) NTSTATUS RtlEnterCriticalSection(void* cs)
{
    long long  tid     = ntdll_syscall_get_tid();
    CritSecPtr_t owner = (CritSecPtr_t) cs;
    long long volatile* recur = (long long volatile*) cs + 1;
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
    CritSecPtr_t        owner = (CritSecPtr_t) cs;
    long long volatile* recur = (long long volatile*) cs + 1;
    long long           next  = *recur - 1;
    *recur                    = next;
    if (next == 0)
        *owner = 0;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) BOOL RtlTryEnterCriticalSection(void* cs)
{
    long long  tid     = ntdll_syscall_get_tid();
    CritSecPtr_t owner = (CritSecPtr_t) cs;
    long long volatile* recur = (long long volatile*) cs + 1;
    long long           expected = 0;
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
    long long volatile* slot     = (long long volatile*) RunOnce;
    long long           expected = 0;
    if (__atomic_compare_exchange_n(slot, &expected, 1LL, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
    {
        if (InitFn != (RtlRunOnceFn) 0)
            InitFn(RunOnce, Parameter, Context);
        *slot = 2;
        return NTSTATUS_SUCCESS;
    }
    while (__atomic_load_n(slot, __ATOMIC_SEQ_CST) != 2)
        ntdll_syscall_yield();
    return NTSTATUS_SUCCESS;
}

/* ------------------------------------------------------------------
 * SEH unwind helpers (slice 32)
 *
 * Real ntdll walks .pdata RUNTIME_FUNCTION tables to support
 * unwinding and stack traces. v0 has no unwind machinery; all
 * of these return "no match" / zero so callers (typically CRT
 * crash handlers) gracefully give up.
 * ------------------------------------------------------------------ */

__declspec(dllexport) void* RtlLookupFunctionEntry(unsigned long long ControlPc, unsigned long long* ImageBase,
                                                   void* HistoryTable)
{
    (void) ControlPc;
    (void) HistoryTable;
    if (ImageBase != (unsigned long long*) 0)
        *ImageBase = 0;
    return (void*) 0; /* No RUNTIME_FUNCTION found. */
}

__declspec(dllexport) void* RtlVirtualUnwind(unsigned long HandlerType, unsigned long long ImageBase,
                                            unsigned long long ControlPc, void* FunctionEntry, void* ContextRecord,
                                            void** HandlerData, unsigned long long* EstablisherFrame,
                                            void* ContextPointers)
{
    (void) HandlerType;
    (void) ImageBase;
    (void) ControlPc;
    (void) FunctionEntry;
    (void) ContextRecord;
    (void) ContextPointers;
    if (HandlerData != (void**) 0)
        *HandlerData = (void*) 0;
    if (EstablisherFrame != (unsigned long long*) 0)
        *EstablisherFrame = 0;
    return (void*) 0; /* No exception handler found. */
}

/* RtlCaptureContext captures the current thread's register
 * state to a CONTEXT struct (1232 bytes on x64). We zero the
 * caller's struct; crash handlers that walk it see an "empty"
 * context. */
__declspec(dllexport) void RtlCaptureContext(void* ContextRecord)
{
    if (ContextRecord == (void*) 0)
        return;
    unsigned char* b = (unsigned char*) ContextRecord;
    for (int i = 0; i < 1232; ++i)
        b[i] = 0;
}

__declspec(dllexport) unsigned short RtlCaptureStackBackTrace(unsigned long FramesToSkip, unsigned long FramesToCapture,
                                                              void** BackTrace, unsigned long* BackTraceHash)
{
    (void) FramesToSkip;
    (void) FramesToCapture;
    (void) BackTrace;
    if (BackTraceHash != (unsigned long*) 0)
        *BackTraceHash = 0;
    return 0; /* No frames captured. */
}

__declspec(dllexport) void RtlUnwind(void* TargetFrame, void* TargetIp, void* ExceptionRecord, void* ReturnValue)
{
    (void) TargetFrame;
    (void) TargetIp;
    (void) ExceptionRecord;
    (void) ReturnValue;
    /* Can't unwind; terminate. */
    __asm__ volatile("int $0x80" : : "a"((long long) 0), "D"((long long) 3));
}

__declspec(dllexport) void RtlUnwindEx(void* TargetFrame, void* TargetIp, void* ExceptionRecord, void* ReturnValue,
                                      void* ContextRecord, void* HistoryTable)
{
    (void) TargetFrame;
    (void) TargetIp;
    (void) ExceptionRecord;
    (void) ReturnValue;
    (void) ContextRecord;
    (void) HistoryTable;
    __asm__ volatile("int $0x80" : : "a"((long long) 0), "D"((long long) 3));
}
