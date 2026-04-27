/*
 * userland/libs/ntdll/ntdll.c
 *
 * Freestanding DuetOS ntdll.dll — the foundational Windows
 * DLL. Retires the prior flat-stub rows for
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
 * Build: tools/build/build-ntdll-dll.sh at /base:0x10060000.
 */

typedef unsigned int DWORD;
typedef unsigned int UINT;
typedef int BOOL;
typedef void* HANDLE;
typedef unsigned long ULONG;
typedef unsigned long long SIZE_T;
typedef unsigned long NTSTATUS; /* 32-bit on MSVC LLP64 */
typedef unsigned short wchar_t16;

#define NTSTATUS_SUCCESS 0x00000000UL
#define NTSTATUS_NOT_IMPLEMENTED 0xC00000BBUL
#define NTSTATUS_NO_MEMORY 0xC0000017UL
#define NTSTATUS_INVALID_PARAMETER 0xC000000DUL

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
 *   SYS_SLEEP_MS     = 19 — NtDelayExecution (millisecond delay)
 *   SYS_GETLASTERROR = 9, SYS_SETLASTERROR = 10 — Rtl* aliases
 * ------------------------------------------------------------------ */

__declspec(dllexport) NTSTATUS NtClose(HANDLE h)
{
    long long discard;
    __asm__ volatile("int $0x80" : "=a"(discard) : "a"((long long)22), "D"((long long)h) : "memory");
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtYieldExecution(void)
{
    long long discard;
    __asm__ volatile("int $0x80" : "=a"(discard) : "a"((long long)3) : "memory");
    return NTSTATUS_SUCCESS;
}

/* NtDelayExecution(bAlertable=rcx, DelayInterval=rdx).
 * DelayInterval is a pointer to LARGE_INTEGER (100 ns units).
 * Negative value = relative; positive = absolute. v0 converts
 * relative intervals to milliseconds and issues SYS_SLEEP_MS;
 * absolute times are approximated as a zero-delay yield. */
__declspec(dllexport) NTSTATUS NtDelayExecution(BOOL bAlertable, const long long* DelayInterval)
{
    (void)bAlertable;
    if (DelayInterval == (const long long*)0)
        return NtYieldExecution();
    long long ns100 = *DelayInterval;
    unsigned long long ms;
    if (ns100 < 0)
        ms = (unsigned long long)(-ns100) / 10000ULL; /* 100 ns -> ms */
    else
        ms = 0; /* Absolute time — approximate as yield. */
    long long discard;
    __asm__ volatile("int $0x80" : "=a"(discard) : "a"((long long)19), "D"((long long)ms) : "memory");
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtQueryPerformanceCounter(long long* counter, long long* freq)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)18) : "memory");
    if (counter != (long long*)0)
        *counter = rv;
    if (freq != (long long*)0)
        *freq = 1000000000LL; /* 1 GHz — pairs with SYS_NOW_NS returning ns. */
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtQuerySystemTime(long long* SystemTime)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)17) : "memory");
    if (SystemTime != (long long*)0)
        *SystemTime = rv;
    return NTSTATUS_SUCCESS;
}

/* NtTerminateProcess: kill an entire process (every thread).
 *   hProcess = (HANDLE)-1 → self-process, every sibling thread
 *              brought down before the calling thread exits.
 *   hProcess = foreign Win32 process handle from NtOpenProcess
 *              → SYS_PROCESS_TERMINATE (cap-gated on kCapDebug).
 * Self path is [[noreturn]]; foreign path returns the count of
 * tasks signalled (NTSTATUS_SUCCESS proxy — caller usually
 * ignores it). */
__declspec(dllexport) NTSTATUS NtTerminateProcess(HANDLE hProcess, NTSTATUS exit_status)
{
    long long status;
    /* SYS_PROCESS_TERMINATE = 145. Self-handle is -1; the
     * kernel's self path calls SchedExit and never returns, so
     * the asm below uses a non-noreturn pattern but the self
     * branch effectively never falls through. */
    __asm__ volatile("int $0x80"
                     : "=a"(status)
                     : "a"((long long)145), "D"((long long)hProcess), "S"((long long)exit_status)
                     : "memory");
    return (NTSTATUS)status;
}

/* NtTerminateThread:
 *   hThread = (HANDLE)-2 → self-thread, equivalent to SYS_EXIT.
 *   hThread = local thread handle from CreateThread →
 *              SYS_THREAD_TERMINATE, no extra cap.
 *   hThread = foreign thread handle from NtOpenThread →
 *              SYS_THREAD_TERMINATE, cap-gated on kCapDebug.
 * Self path is effectively [[noreturn]]. */
__declspec(dllexport) NTSTATUS NtTerminateThread(HANDLE hThread, NTSTATUS exit_status)
{
    long long status;
    /* SYS_THREAD_TERMINATE = 146. */
    __asm__ volatile("int $0x80"
                     : "=a"(status)
                     : "a"((long long)146), "D"((long long)hThread), "S"((long long)exit_status)
                     : "memory");
    return (NTSTATUS)status;
}

/* NtContinue — restores a CONTEXT. v0 can't actually do it;
 * fall through to termination (matching the flat stub which
 * forwards to kOffExitProcess). */
__declspec(dllexport) NTDLL_NORETURN NTSTATUS NtContinue(void* context, BOOL bTestAlert)
{
    (void)context;
    (void)bTestAlert;
    __asm__ volatile("int $0x80" : : "a"((long long)0), "D"((long long)0));
    __builtin_unreachable();
}

/* NtAllocateVirtualMemory — read *RegionSize, hand to SYS_VMAP,
 * write result into *BaseAddress; echo size back. Matches the
 * flat-stub semantics at kOffNtAllocateVirtualMemory. */
__declspec(dllexport) NTSTATUS NtAllocateVirtualMemory(HANDLE hProcess, void** BaseAddress, SIZE_T ZeroBits,
                                                       SIZE_T* RegionSize, ULONG AllocationType, ULONG Protect)
{
    (void)hProcess;
    (void)ZeroBits;
    (void)AllocationType;
    (void)Protect;
    if (RegionSize == (SIZE_T*)0 || BaseAddress == (void**)0)
        return NTSTATUS_INVALID_PARAMETER;
    long long sz = (long long)*RegionSize;
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)28), "D"(sz) : "memory");
    if (rv == 0)
        return NTSTATUS_NO_MEMORY;
    *BaseAddress = (void*)rv;
    /* *RegionSize stays unchanged — v0 honours exactly what was asked. */
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtFreeVirtualMemory(HANDLE hProcess, void** BaseAddress, SIZE_T* RegionSize,
                                                   ULONG FreeType)
{
    (void)hProcess;
    (void)FreeType;
    if (BaseAddress == (void**)0 || RegionSize == (SIZE_T*)0)
        return NTSTATUS_INVALID_PARAMETER;
    long long va = (long long)*BaseAddress;
    long long sz = (long long)*RegionSize;
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)29), "D"(va), "S"(sz) : "memory");
    return rv == 0 ? NTSTATUS_SUCCESS : NTSTATUS_INVALID_PARAMETER;
}

__declspec(dllexport) NTSTATUS NtSetEvent(HANDLE h, long* previous_state)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)31), "D"((long long)h) : "memory");
    if (previous_state != (long*)0)
        *previous_state = 0;
    return rv == 0 ? NTSTATUS_SUCCESS : NTSTATUS_INVALID_PARAMETER;
}

__declspec(dllexport) NTSTATUS NtResetEvent(HANDLE h, long* previous_state)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)32), "D"((long long)h) : "memory");
    if (previous_state != (long*)0)
        *previous_state = 0;
    return rv == 0 ? NTSTATUS_SUCCESS : NTSTATUS_INVALID_PARAMETER;
}

/* NtReleaseMutant -> SYS_MUTEX_RELEASE (27). */
__declspec(dllexport) NTSTATUS NtReleaseMutant(HANDLE h, long* previous_count)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)27), "D"((long long)h) : "memory");
    if (previous_count != (long*)0)
        *previous_count = 0;
    return rv == 0 ? NTSTATUS_SUCCESS : NTSTATUS_INVALID_PARAMETER;
}

/* NtWaitForSingleObject — dispatch by handle range (same as
 * kernel32!WaitForSingleObject). */
__declspec(dllexport) NTSTATUS NtWaitForSingleObject(HANDLE h, BOOL bAlertable, const long long* timeout100ns)
{
    (void)bAlertable;
    unsigned long long handle = (unsigned long long)h;
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
    if (timeout100ns == (const long long*)0)
        ms = 0xFFFFFFFFull; /* INFINITE */
    else if (*timeout100ns < 0)
        ms = (unsigned long long)(-*timeout100ns) / 10000ULL;
    else
        ms = 0;
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"(syscall_num), "D"((long long)h), "S"((long long)ms) : "memory");
    return (NTSTATUS)rv;
}

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
 * input pointer. */
typedef struct
{
    unsigned short Length;
    unsigned short MaximumLength;
    wchar_t16* Buffer;
} UNICODE_STRING;

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

/* ------------------------------------------------------------------
 * Registry — NtOpenKey + NtQueryValueKey
 *
 * These wrap SYS_REGISTRY (= 130) which is op-multiplexed by rdi:
 *   op=1 (kOpOpenKey)    rsi=parent, rdx=ASCII-path, r10=&out_handle
 *   op=2 (kOpClose)      rsi=handle  — already reachable via NtClose
 *                                       (SYS_FILE_CLOSE dispatches by
 *                                        handle range)
 *   op=3 (kOpQueryValue) rsi=handle, rdx=ASCII-name, r10=buf,
 *                        r8=buf_cap, r9=&packed (size:32 | type:32)
 *
 * Win32 callers pass UNICODE_STRING + OBJECT_ATTRIBUTES; the kernel
 * registry only takes ASCII paths. The thunks below do the conversion
 * inline (low-byte strip; non-ASCII becomes '?'). The path also gets
 * the leading "\\Registry\\Machine\\" / "\\Registry\\User\\" prefix
 * stripped so the kernel sees the same path advapi32 already serves
 * (HKLM\\Software\\... etc. — the leading-prefix-and-HKEY pair is
 * how Windows turns a UNICODE path into an HKEY-rooted lookup).
 * ------------------------------------------------------------------ */

/* UNICODE_STRING reuses the typedef declared earlier in this TU
 * (line ~408). The OBJECT_ATTRIBUTES struct is registry-specific
 * so it lives next to the registry thunks instead. */
typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;               /* sizeof(OBJECT_ATTRIBUTES) — 48 on x64 */
    HANDLE RootDirectory;       /* parent HKEY (predefined or previously-opened) */
    UNICODE_STRING* ObjectName; /* full registry path; sometimes NULL */
    ULONG Attributes;
    void* SecurityDescriptor;
    void* SecurityQualityOfService;
} OBJECT_ATTRIBUTES;

/* KEY_VALUE_INFORMATION_CLASS values used by NtQueryValueKey. v0
 * supports only KeyValuePartialInformation (the one MSVC PE startup
 * + advapi32 + every common Windows-side caller asks for). */
#define KeyValueBasicInformation 0
#define KeyValueFullInformation 1
#define KeyValuePartialInformation 2

#define NTSTATUS_OBJECT_NAME_NOT_FOUND 0xC0000034UL
#define NTSTATUS_INVALID_HANDLE 0xC0000008UL
#define NTSTATUS_BUFFER_TOO_SMALL 0xC0000023UL

#define HKEY_CLASSES_ROOT_NT ((HANDLE)(unsigned long long)0x80000000ULL)
#define HKEY_CURRENT_USER_NT ((HANDLE)(unsigned long long)0x80000001ULL)
#define HKEY_LOCAL_MACHINE_NT ((HANDLE)(unsigned long long)0x80000002ULL)
#define HKEY_USERS_NT ((HANDLE)(unsigned long long)0x80000003ULL)

static unsigned ntdll_strlen_a(const char* s)
{
    unsigned n = 0;
    while (s && s[n])
        ++n;
    return n;
}

/* ASCII case-insensitive prefix match. Returns the length of the
 * prefix on success (so the caller can advance past it) or 0 on
 * miss. `prefix` is NUL-terminated; `s` is a wide buffer of length
 * `s_chars` and is treated as ASCII (low-byte strip). */
static unsigned ntdll_w_starts_with_ci(const wchar_t16* s, unsigned s_chars, const char* prefix)
{
    const unsigned plen = ntdll_strlen_a(prefix);
    if (s_chars < plen)
        return 0;
    for (unsigned i = 0; i < plen; ++i)
    {
        char a = (char)(s[i] & 0xFF);
        char b = prefix[i];
        if (a >= 'A' && a <= 'Z')
            a = (char)(a + ('a' - 'A'));
        if (b >= 'A' && b <= 'Z')
            b = (char)(b + ('a' - 'A'));
        if (a != b)
            return 0;
    }
    return plen;
}

/* Translate a Windows-shape registry path into a (parent_hkey,
 * ASCII subkey) pair the kernel-side SYS_REGISTRY recognises.
 *
 * Input contract (from OBJECT_ATTRIBUTES):
 *   - If RootDirectory is one of the predefined HKEY sentinels,
 *     the ObjectName is the subkey path with no \Registry\
 *     prefix.
 *   - If RootDirectory is NULL, the ObjectName must start with
 *     \Registry\Machine\ (→ HKLM) or \Registry\User\ (→ HKCU).
 *     We strip the prefix and pick the matching sentinel.
 *
 * Output: writes ASCII path into `dst` (cap bytes), returns the
 * resolved parent HKEY sentinel (or NULL on parse failure).
 */
static HANDLE ntdll_reg_resolve(HANDLE root_dir, const UNICODE_STRING* name, char* dst, unsigned cap)
{
    if (cap == 0 || dst == (char*)0 || name == (const UNICODE_STRING*)0 || name->Buffer == (wchar_t16*)0)
        return (HANDLE)0;

    const unsigned chars = (unsigned)(name->Length / 2);
    const wchar_t16* s = name->Buffer;
    unsigned skip = 0;
    HANDLE parent = root_dir;

    if (root_dir == (HANDLE)0)
    {
        unsigned p = ntdll_w_starts_with_ci(s, chars, "\\Registry\\Machine\\");
        if (p != 0)
        {
            parent = HKEY_LOCAL_MACHINE_NT;
            skip = p;
        }
        else if ((p = ntdll_w_starts_with_ci(s, chars, "\\Registry\\User\\")) != 0)
        {
            parent = HKEY_CURRENT_USER_NT;
            skip = p;
        }
        else
        {
            return (HANDLE)0; /* unrecognised root — only Machine/User in v0 */
        }
    }

    unsigned o = 0;
    for (unsigned i = skip; i < chars; ++i)
    {
        if (o + 1 >= cap)
            return (HANDLE)0; /* path too long for the kernel buffer */
        unsigned short w = s[i];
        char c = (w <= 0x7F) ? (char)w : '?';
        dst[o++] = c;
    }
    dst[o] = 0;
    return parent;
}

__declspec(dllexport) NTSTATUS NtOpenKey(HANDLE* KeyHandle, ULONG DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes)
{
    (void)DesiredAccess;
    if (KeyHandle == (HANDLE*)0 || ObjectAttributes == (OBJECT_ATTRIBUTES*)0)
        return NTSTATUS_INVALID_PARAMETER;

    char path[256];
    HANDLE parent =
        ntdll_reg_resolve(ObjectAttributes->RootDirectory, ObjectAttributes->ObjectName, path, sizeof(path));
    if (parent == (HANDLE)0)
        return NTSTATUS_OBJECT_NAME_NOT_FOUND;

    long long out_handle = 0;
    long long status;
    /* SYS_REGISTRY = 130, op = 1 (kOpOpenKey).
     * Operand indexing: %0=status(rax), %1=130(rax-in), %2=1(rdi),
     * %3=parent(rsi), %4=&out_handle(r), %5=path(rdx). */
    __asm__ volatile("mov %4, %%r10\n\t"
                     "int $0x80"
                     : "=a"(status)
                     : "a"((long long)130), "D"((long long)1), "S"((long long)parent), "r"((long long)&out_handle),
                       "d"((long long)path)
                     : "r10", "memory");
    if (status != 0)
        return (NTSTATUS)status;
    *KeyHandle = (HANDLE)out_handle;
    return NTSTATUS_SUCCESS;
}

/* Same surface, narrowed: OpenKeyEx adds an Attributes ULONG before
 * RootDirectory in some headers but the runtime ABI (3 args) is
 * identical for our purposes — just forward. */
__declspec(dllexport) NTSTATUS NtOpenKeyEx(HANDLE* KeyHandle, ULONG DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes,
                                           ULONG OpenOptions)
{
    (void)OpenOptions;
    return NtOpenKey(KeyHandle, DesiredAccess, ObjectAttributes);
}

/* ------------------------------------------------------------------
 * NtOpenProcess — open a handle to another process by PID.
 *
 * Win32 NT signature:
 *   NTSTATUS NtOpenProcess(
 *     PHANDLE             ProcessHandle,
 *     ACCESS_MASK         DesiredAccess,
 *     POBJECT_ATTRIBUTES  ObjectAttributes,  // initialised but unused
 *     PCLIENT_ID          ClientId);          // { HANDLE Pid; HANDLE Tid; }
 *
 * v0 only honours the PID; thread-targeted opens (Pid == 0) are
 * STATUS_INVALID_PARAMETER. ACCESS_MASK + ObjectAttributes are
 * accepted but ignored — we have no ACL machinery, and the
 * kernel-side cap-gates via kCapDebug.
 * ------------------------------------------------------------------ */
typedef struct
{
    HANDLE Pid;
    HANDLE Tid;
} CLIENT_ID;

__declspec(dllexport) NTSTATUS NtOpenProcess(HANDLE* ProcessHandle, ULONG DesiredAccess,
                                             OBJECT_ATTRIBUTES* ObjectAttributes, CLIENT_ID* ClientId)
{
    (void)DesiredAccess;
    (void)ObjectAttributes;
    if (ProcessHandle == (HANDLE*)0 || ClientId == (CLIENT_ID*)0)
        return NTSTATUS_INVALID_PARAMETER;
    if (ClientId->Pid == (HANDLE)0)
        return NTSTATUS_INVALID_PARAMETER;
    long long handle = 0;
    /* SYS_PROCESS_OPEN = 131; rdi = pid. rax = handle (0 on failure). */
    __asm__ volatile("int $0x80" : "=a"(handle) : "a"((long long)131), "D"((long long)ClientId->Pid) : "memory");
    if (handle == 0)
        return (NTSTATUS)NTSTATUS_INVALID_PARAMETER;
    *ProcessHandle = (HANDLE)handle;
    return NTSTATUS_SUCCESS;
}

/* ------------------------------------------------------------------
 * NtOpenThread — open a handle to a target thread by TID.
 *
 * Win32 NT signature:
 *   NTSTATUS NtOpenThread(
 *     PHANDLE             ThreadHandle,
 *     ACCESS_MASK         DesiredAccess,
 *     POBJECT_ATTRIBUTES  ObjectAttributes,
 *     PCLIENT_ID          ClientId);  // { HANDLE Pid; HANDLE Tid; }
 *
 * v0 only honours Tid; the Pid field is accepted but unused — the
 * kernel resolves Tid against every live task regardless of PID.
 * ACCESS_MASK + ObjectAttributes are accepted but ignored (no
 * ACL machinery; the kernel cap-gates via kCapDebug). The
 * returned handle plugs into NtSuspendThread / NtResumeThread /
 * NtGetContextThread / NtSetContextThread for cross-process
 * thread inspection — completes the malware "thread hijack"
 * pipeline against a target outside the caller's process.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtOpenThread(HANDLE* ThreadHandle, ULONG DesiredAccess,
                                            OBJECT_ATTRIBUTES* ObjectAttributes, CLIENT_ID* ClientId)
{
    (void)DesiredAccess;
    (void)ObjectAttributes;
    if (ThreadHandle == (HANDLE*)0 || ClientId == (CLIENT_ID*)0)
        return NTSTATUS_INVALID_PARAMETER;
    if (ClientId->Tid == (HANDLE)0)
        return NTSTATUS_INVALID_PARAMETER;
    long long handle = 0;
    /* SYS_THREAD_OPEN = 139; rdi = tid. rax = handle (0 on failure). */
    __asm__ volatile("int $0x80" : "=a"(handle) : "a"((long long)139), "D"((long long)ClientId->Tid) : "memory");
    if (handle == 0)
        return (NTSTATUS)NTSTATUS_INVALID_PARAMETER;
    *ThreadHandle = (HANDLE)handle;
    return NTSTATUS_SUCCESS;
}

/* ------------------------------------------------------------------
 * NtCreateSection — allocate an anonymous (pagefile-backed)
 * section of `*MaximumSize` bytes.
 *
 * Win32 NT signature:
 *   NTSTATUS NtCreateSection(
 *     PHANDLE             SectionHandle,
 *     ACCESS_MASK         DesiredAccess,
 *     POBJECT_ATTRIBUTES  ObjectAttributes,
 *     PLARGE_INTEGER      MaximumSize,           // bytes
 *     ULONG               SectionPageProtection, // PAGE_*
 *     ULONG               AllocationAttributes,
 *     HANDLE              FileHandle);            // 0 = anonymous
 *
 * v0 only honours anonymous (FileHandle == 0); file-backed
 * sections return STATUS_NOT_IMPLEMENTED. AllocationAttributes
 * + ObjectAttributes are accepted but ignored (no SEC_RESERVE
 * separation; every section is committed on creation).
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtCreateSection(HANDLE* SectionHandle, ULONG DesiredAccess,
                                               OBJECT_ATTRIBUTES* ObjectAttributes, unsigned long long* MaximumSize,
                                               ULONG SectionPageProtection, ULONG AllocationAttributes,
                                               HANDLE FileHandle)
{
    (void)DesiredAccess;
    (void)ObjectAttributes;
    (void)AllocationAttributes;
    if (SectionHandle == (HANDLE*)0 || MaximumSize == (unsigned long long*)0)
        return NTSTATUS_INVALID_PARAMETER;
    if (FileHandle != (HANDLE)0)
        return (NTSTATUS)0xC0000002UL; /* STATUS_NOT_IMPLEMENTED */
    long long handle = 0;
    /* SYS_SECTION_CREATE = 140; rdi = size, rsi = page_protect. */
    __asm__ volatile("int $0x80"
                     : "=a"(handle)
                     : "a"((long long)140), "D"(*MaximumSize), "S"((long long)SectionPageProtection)
                     : "memory");
    if (handle == 0)
        return NTSTATUS_INVALID_PARAMETER;
    *SectionHandle = (HANDLE)handle;
    return NTSTATUS_SUCCESS;
}

/* ------------------------------------------------------------------
 * NtMapViewOfSection — install a view of `SectionHandle` into
 * the address space of `ProcessHandle` at `*BaseAddress`.
 *
 * Win32 NT signature:
 *   NTSTATUS NtMapViewOfSection(
 *     HANDLE    SectionHandle,
 *     HANDLE    ProcessHandle,        // -1 = NtCurrentProcess()
 *     PVOID*    BaseAddress,           // in/out, 0 hint = kernel-picks
 *     ULONG_PTR ZeroBits,
 *     SIZE_T    CommitSize,
 *     PLARGE_INTEGER SectionOffset,    // v0: must be 0
 *     PSIZE_T   ViewSize,              // in/out, kernel writes actual
 *     SECTION_INHERIT InheritDisposition,
 *     ULONG     AllocationType,
 *     ULONG     Win32Protect);         // PAGE_*
 *
 * v0 honours the section→AS mapping but ignores ZeroBits,
 * CommitSize, SectionOffset (must be 0), InheritDisposition,
 * and AllocationType. The kernel always maps the section's
 * full size; partial views land later.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, void** BaseAddress,
                                                  unsigned long long ZeroBits, unsigned long long CommitSize,
                                                  unsigned long long* SectionOffset, unsigned long long* ViewSize,
                                                  unsigned long Inherit, unsigned long AllocationType,
                                                  unsigned long Win32Protect)
{
    (void)ZeroBits;
    (void)CommitSize;
    (void)Inherit;
    (void)AllocationType;
    if (BaseAddress == (void**)0 || ViewSize == (unsigned long long*)0)
        return NTSTATUS_INVALID_PARAMETER;
    if (SectionOffset != (unsigned long long*)0 && *SectionOffset != 0)
        return NTSTATUS_INVALID_PARAMETER;
    long long status = 0;
    register long long r10 __asm__("r10") = (long long)ViewSize;
    register long long r8 __asm__("r8") = (long long)Win32Protect;
    /* SYS_SECTION_MAP = 141; rdi = sect, rsi = proc, rdx = &base, r10 = &size, r8 = protect. */
    __asm__ volatile("int $0x80"
                     : "=a"(status)
                     : "a"((long long)141), "D"((long long)SectionHandle), "S"((long long)ProcessHandle),
                       "d"((long long)BaseAddress), "r"(r10), "r"(r8)
                     : "memory");
    return (NTSTATUS)status;
}

/* ------------------------------------------------------------------
 * NtUnmapViewOfSection — tear down a view previously installed
 * by NtMapViewOfSection. The kernel walks every live section
 * pool entry to find which one's first frame lives at
 * BaseAddress in the target AS, unmaps that section's view,
 * and drops one section refcount.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtUnmapViewOfSection(HANDLE ProcessHandle, void* BaseAddress)
{
    long long status = 0;
    /* SYS_SECTION_UNMAP = 142; rdi = proc, rsi = base. */
    __asm__ volatile("int $0x80"
                     : "=a"(status)
                     : "a"((long long)142), "D"((long long)ProcessHandle), "S"((long long)BaseAddress)
                     : "memory");
    return (NTSTATUS)status;
}

/* ------------------------------------------------------------------
 * NtDeleteFile — delete a file by OBJECT_ATTRIBUTES path.
 *
 * Win32 NT signature:
 *   NTSTATUS NtDeleteFile(POBJECT_ATTRIBUTES ObjectAttributes);
 *
 * v0 narrows the wide ObjectName to ASCII, drops the
 * "\??\" / "\DosDevices\" Win32 namespace prefix if present
 * (callers built on top of RtlDosPathNameToNtPathName_U
 * routinely emit it), and forwards the result to
 * SYS_FILE_UNLINK. Names exceeding 255 chars truncate.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtDeleteFile(OBJECT_ATTRIBUTES* ObjectAttributes)
{
    if (ObjectAttributes == (OBJECT_ATTRIBUTES*)0)
        return NTSTATUS_INVALID_PARAMETER;
    UNICODE_STRING* name = ObjectAttributes->ObjectName;
    if (name == (UNICODE_STRING*)0 || name->Buffer == (wchar_t16*)0)
        return NTSTATUS_INVALID_PARAMETER;
    char ascii[256];
    int wlen = (int)(name->Length / 2);
    int start = 0;
    /* Strip "\??\" and "\DosDevices\" Win32-namespace prefixes. */
    if (wlen >= 4 && name->Buffer[0] == '\\' && name->Buffer[1] == '?' && name->Buffer[2] == '?' &&
        name->Buffer[3] == '\\')
        start = 4;
    int i = 0;
    while (i < 255 && (start + i) < wlen)
    {
        ascii[i] = (char)(name->Buffer[start + i] & 0xFF);
        ++i;
    }
    ascii[i] = '\0';
    long long status;
    __asm__ volatile("int $0x80"
                     : "=a"(status)
                     : "a"((long long)143), /* SYS_FILE_UNLINK */
                       "D"((long long)ascii), "S"((long long)i)
                     : "memory");
    return (NTSTATUS)status;
}

/* ------------------------------------------------------------------
 * NtReadVirtualMemory — read another process's user memory through
 * a previously-opened process handle.
 *
 * Win32 NT signature:
 *   NTSTATUS NtReadVirtualMemory(
 *     HANDLE   ProcessHandle,
 *     PVOID    BaseAddress,        // VA inside target's AS
 *     PVOID    Buffer,             // VA inside caller's AS
 *     SIZE_T   NumberOfBytesToRead,
 *     PSIZE_T  NumberOfBytesRead);  // optional out-pointer
 *
 * Backed by SYS_PROCESS_VM_READ (132). The kernel caps any single
 * call at kSyscallProcessVmMax (16 KiB); larger transfers chunk on
 * this side. v0 does not surface STATUS_PARTIAL_COPY — a partial
 * transfer returns STATUS_ACCESS_VIOLATION, with the
 * NumberOfBytesRead out-pointer carrying the actual count moved.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtReadVirtualMemory(HANDLE ProcessHandle, void* BaseAddress, void* Buffer,
                                                   unsigned long long NumberOfBytesToRead,
                                                   unsigned long long* NumberOfBytesRead)
{
    long long status;
    /* SYS_PROCESS_VM_READ = 132. Args: rdi=handle, rsi=target_va,
     * rdx=caller_buf, r10=len, r8=out_count_va. */
    __asm__ volatile("mov %5, %%r10\n\t"
                     "mov %6, %%r8\n\t"
                     "int $0x80"
                     : "=a"(status)
                     : "a"((long long)132), "D"((long long)ProcessHandle), "S"((long long)BaseAddress),
                       "d"((long long)Buffer), "r"((long long)NumberOfBytesToRead), "r"((long long)NumberOfBytesRead)
                     : "r10", "r8", "memory");
    return (NTSTATUS)status;
}

/* NtWriteVirtualMemory — symmetric to the read path.
 *
 * Win32 NT signature:
 *   NTSTATUS NtWriteVirtualMemory(
 *     HANDLE   ProcessHandle,
 *     PVOID    BaseAddress,
 *     PVOID    Buffer,
 *     SIZE_T   NumberOfBytesToWrite,
 *     PSIZE_T  NumberOfBytesWritten);
 *
 * Backed by SYS_PROCESS_VM_WRITE (133). Same cap, same partial-
 * copy contract.  */
__declspec(dllexport) NTSTATUS NtWriteVirtualMemory(HANDLE ProcessHandle, void* BaseAddress, void* Buffer,
                                                    unsigned long long NumberOfBytesToWrite,
                                                    unsigned long long* NumberOfBytesWritten)
{
    long long status;
    __asm__ volatile("mov %5, %%r10\n\t"
                     "mov %6, %%r8\n\t"
                     "int $0x80"
                     : "=a"(status)
                     : "a"((long long)133), "D"((long long)ProcessHandle), "S"((long long)BaseAddress),
                       "d"((long long)Buffer), "r"((long long)NumberOfBytesToWrite),
                       "r"((long long)NumberOfBytesWritten)
                     : "r10", "r8", "memory");
    return (NTSTATUS)status;
}

/* NtQueryVirtualMemory — probe one VA in a target process.
 *
 * Win32 NT signature (we serve only MemoryBasicInformation = 0):
 *   NTSTATUS NtQueryVirtualMemory(
 *     HANDLE   ProcessHandle,
 *     PVOID    BaseAddress,
 *     int      MemoryInformationClass,  // 0 = MemoryBasicInformation
 *     PVOID    MemoryInformation,        // MEMORY_BASIC_INFORMATION
 *     SIZE_T   MemoryInformationLength,
 *     PSIZE_T  ReturnLength);            // optional
 *
 * Backed by SYS_PROCESS_VM_QUERY (134). v0 returns a single-page
 * region (RegionSize = 4096) — Windows would coalesce adjacent
 * pages with identical attributes, but the v0 region table doesn't
 * track per-page protection, so we can't honestly coalesce.
 * STATUS_INVALID_INFO_CLASS for any class != MemoryBasicInformation.
 * ------------------------------------------------------------------ */
/* ------------------------------------------------------------------
 * NtSuspendThread / NtResumeThread — bump or decrement a target
 * thread's suspend count.
 *
 * Win32 NT signature:
 *   NTSTATUS NtSuspendThread(HANDLE ThreadHandle, PULONG PrevCount);
 *   NTSTATUS NtResumeThread(HANDLE ThreadHandle, PULONG PrevCount);
 *
 * Both back onto SYS_THREAD_SUSPEND / SYS_THREAD_RESUME. v0 only
 * accepts caller-local thread handles (kWin32ThreadBase + idx in
 * the calling Process's win32_threads[] table — i.e. the same
 * handles CreateThread returned). Cross-process thread suspend
 * needs NtOpenThread, which is its own slice.
 *
 * Kernel returns rax = previous suspend count (a small non-
 * negative number) on success or u64(-1) on any error. We map
 * (-1) to STATUS_INVALID_HANDLE because that's the only error
 * the kernel surfaces today.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtSuspendThread(HANDLE ThreadHandle, unsigned long* PreviousSuspendCount)
{
    long long rc;
    /* SYS_THREAD_SUSPEND = 135 */
    __asm__ volatile("int $0x80" : "=a"(rc) : "a"((long long)135), "D"((long long)ThreadHandle) : "memory");
    if (rc == -1)
        return (NTSTATUS)0xC0000008L; /* STATUS_INVALID_HANDLE */
    if (PreviousSuspendCount != (unsigned long*)0)
        *PreviousSuspendCount = (unsigned long)rc;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtResumeThread(HANDLE ThreadHandle, unsigned long* PreviousSuspendCount)
{
    long long rc;
    /* SYS_THREAD_RESUME = 136 */
    __asm__ volatile("int $0x80" : "=a"(rc) : "a"((long long)136), "D"((long long)ThreadHandle) : "memory");
    if (rc == -1)
        return (NTSTATUS)0xC0000008L;
    if (PreviousSuspendCount != (unsigned long*)0)
        *PreviousSuspendCount = (unsigned long)rc;
    return NTSTATUS_SUCCESS;
}

/* NtAlertResumeThread is documented as "resume thread and signal
 * any pending alert." v0 has no alert/APC machinery, so the
 * resume part is the entire effect — alias to NtResumeThread. */
__declspec(dllexport) NTSTATUS NtAlertResumeThread(HANDLE ThreadHandle, unsigned long* PreviousSuspendCount)
{
    return NtResumeThread(ThreadHandle, PreviousSuspendCount);
}

/* ------------------------------------------------------------------
 * NtGetContextThread / NtSetContextThread — read or rewrite a
 * suspended target's user-mode register state. Backs the
 * malware "thread hijack" pattern's CONTEXT-manipulation step
 * (the freeze half lives in NtSuspendThread, the patch-bytes
 * half in NtWriteVirtualMemory).
 *
 * Win32 NT signature:
 *   NTSTATUS NtGetContextThread(HANDLE Thread, PCONTEXT Context);
 *   NTSTATUS NtSetContextThread(HANDLE Thread, PCONTEXT Context);
 *
 * Caller passes a CONTEXT* whose ContextFlags member tells the
 * kernel which classes to honour (CONTEXT_INTEGER, CONTEXT_CONTROL,
 * CONTEXT_FULL, etc.). Kernel reads ContextFlags from rdx and
 * the buffer pointer from rsi; the v0 implementation honours
 * INTEGER + CONTROL fully and ignores the FLOATING_POINT /
 * DEBUG_REGISTERS classes (the buffer is left untouched on GET
 * for those classes; the corresponding bytes are read but not
 * applied on SET).
 *
 * Returns:
 *   STATUS_SUCCESS on full success
 *   STATUS_INVALID_HANDLE — handle not in caller's table /
 *     target dead
 *   STATUS_INVALID_PARAMETER — target not suspended OR no user
 *     trap frame yet (target hasn't entered user mode)
 *   STATUS_ACCESS_DENIED — caller missing kCapDebug
 *   STATUS_ACCESS_VIOLATION — Context buffer unmapped /
 *     unwritable
 *
 * The caller must hand a fully-sized CONTEXT (1232 bytes); the
 * kernel only writes the first 0x100 bytes (the integer +
 * control region — Microsoft's CONTEXT layout has the integer
 * registers there and Rip at +0xF8). The remaining bytes
 * (XMM0..XMM15, AVX vectors, DR* mirrors) are left as the caller
 * supplied them on GET.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtGetContextThread(HANDLE ThreadHandle, void* Context)
{
    long long rc;
    /* SYS_THREAD_GET_CONTEXT = 137. Read ContextFlags out of
     * the caller's CONTEXT to forward to the kernel via rdx. */
    if (Context == (void*)0)
        return (NTSTATUS)0xC000000DL; /* STATUS_INVALID_PARAMETER */
    /* ContextFlags lives at +0x30 in the canonical CONTEXT
     * layout. Read directly without dragging in winnt.h. */
    unsigned int flags = *(unsigned int*)((unsigned char*)Context + 0x30);
    __asm__ volatile("int $0x80"
                     : "=a"(rc)
                     : "a"((long long)137), "D"((long long)ThreadHandle), "S"((long long)Context), "d"((long long)flags)
                     : "memory");
    return (NTSTATUS)rc;
}

__declspec(dllexport) NTSTATUS NtSetContextThread(HANDLE ThreadHandle, const void* Context)
{
    long long rc;
    if (Context == (const void*)0)
        return (NTSTATUS)0xC000000DL;
    unsigned int flags = *(const unsigned int*)((const unsigned char*)Context + 0x30);
    __asm__ volatile("int $0x80"
                     : "=a"(rc)
                     : "a"((long long)138), "D"((long long)ThreadHandle), "S"((long long)Context), "d"((long long)flags)
                     : "memory");
    return (NTSTATUS)rc;
}

__declspec(dllexport) NTSTATUS NtQueryVirtualMemory(HANDLE ProcessHandle, void* BaseAddress, int MemoryInformationClass,
                                                    void* MemoryInformation, unsigned long long MemoryInformationLength,
                                                    unsigned long long* ReturnLength)
{
    /* MemoryBasicInformation = 0. Anything else returns
     * STATUS_INVALID_INFO_CLASS without crossing the syscall
     * boundary. */
    if (MemoryInformationClass != 0)
        return (NTSTATUS)0xC0000003L; /* STATUS_INVALID_INFO_CLASS */
    if (MemoryInformation == (void*)0)
        return NTSTATUS_INVALID_PARAMETER;
    if (MemoryInformationLength < 48)
        return (NTSTATUS)0xC0000023L; /* STATUS_BUFFER_TOO_SMALL */

    long long status;
    /* SYS_PROCESS_VM_QUERY = 134. Args: rdi=handle, rsi=probe_va,
     * rdx=out_buf. */
    __asm__ volatile("int $0x80"
                     : "=a"(status)
                     : "a"((long long)134), "D"((long long)ProcessHandle), "S"((long long)BaseAddress),
                       "d"((long long)MemoryInformation)
                     : "memory");
    if (status == 0 && ReturnLength != (unsigned long long*)0)
        *ReturnLength = 48;
    return (NTSTATUS)status;
}

__declspec(dllexport) NTSTATUS NtQueryValueKey(HANDLE KeyHandle, UNICODE_STRING* ValueName, ULONG InfoClass,
                                               void* KeyValueInformation, ULONG Length, ULONG* ResultLength)
{
    if (ValueName == (UNICODE_STRING*)0 || ValueName->Buffer == (wchar_t16*)0)
        return NTSTATUS_INVALID_PARAMETER;

    /* Strip the value name to ASCII. */
    char name[64];
    {
        const unsigned chars = (unsigned)(ValueName->Length / 2);
        if (chars + 1 > sizeof(name))
            return NTSTATUS_INVALID_PARAMETER;
        for (unsigned i = 0; i < chars; ++i)
        {
            unsigned short w = ValueName->Buffer[i];
            name[i] = (w <= 0x7F) ? (char)w : '?';
        }
        name[chars] = 0;
    }

    /* First trip: size-only query. The kernel-side QueryValue
     * writes a packed [size:32 | type:32] u64 to r9 even on
     * STATUS_BUFFER_TOO_SMALL, so we know how much to allocate /
     * advertise even if the caller's buffer is short. */
    long long packed = 0;
    long long status;
    /* SYS_REGISTRY = 130, op = 3 (kOpQueryValue) */
    /* Args: rdi=op, rsi=handle, rdx=name, r10=buf (0 = size-only),
     *       r8=cap (0), r9=&packed. */
    __asm__ volatile("mov %4, %%r10\n\t"
                     "mov %5, %%r8\n\t"
                     "mov %6, %%r9\n\t"
                     "int $0x80"
                     : "=a"(status)
                     : "a"((long long)130), "D"((long long)3), "S"((long long)KeyHandle), "r"((long long)0),
                       "r"((long long)0), "r"((long long)&packed), "d"((long long)name)
                     : "r10", "r8", "r9", "memory");
    if (status != 0)
        return (NTSTATUS)status;

    const unsigned data_size = (unsigned)(packed >> 32);
    const unsigned data_type = (unsigned)(packed & 0xFFFFFFFFu);

    /* Compute output size in the requested info-class layout.
     * Only KeyValuePartialInformation is implemented in v0;
     * other classes return STATUS_NOT_IMPLEMENTED so callers
     * fall back rather than misinterpret. */
    if (InfoClass != KeyValuePartialInformation)
        return (NTSTATUS)NTSTATUS_NOT_IMPLEMENTED;

    /* KEY_VALUE_PARTIAL_INFORMATION:
     *   ULONG TitleIndex;   // 0
     *   ULONG Type;         // value type
     *   ULONG DataLength;   // bytes of Data
     *   UCHAR Data[1];      // VLA */
    const ULONG header_size = 12;
    const ULONG total_size = header_size + (ULONG)data_size;
    if (ResultLength != (ULONG*)0)
        *ResultLength = total_size;
    if (Length < total_size)
        return (NTSTATUS)NTSTATUS_BUFFER_TOO_SMALL;
    if (KeyValueInformation == (void*)0)
        return NTSTATUS_INVALID_PARAMETER;

    unsigned char* out = (unsigned char*)KeyValueInformation;
    /* TitleIndex = 0 */
    out[0] = 0;
    out[1] = 0;
    out[2] = 0;
    out[3] = 0;
    /* Type */
    out[4] = (unsigned char)(data_type & 0xFF);
    out[5] = (unsigned char)((data_type >> 8) & 0xFF);
    out[6] = (unsigned char)((data_type >> 16) & 0xFF);
    out[7] = (unsigned char)((data_type >> 24) & 0xFF);
    /* DataLength */
    out[8] = (unsigned char)(data_size & 0xFF);
    out[9] = (unsigned char)((data_size >> 8) & 0xFF);
    out[10] = (unsigned char)((data_size >> 16) & 0xFF);
    out[11] = (unsigned char)((data_size >> 24) & 0xFF);

    /* Second trip: copy bytes into the Data[] tail. */
    long long status2;
    __asm__ volatile("mov %4, %%r10\n\t"
                     "mov %5, %%r8\n\t"
                     "mov %6, %%r9\n\t"
                     "int $0x80"
                     : "=a"(status2)
                     : "a"((long long)130), "D"((long long)3), "S"((long long)KeyHandle),
                       "r"((long long)(out + header_size)), "r"((long long)data_size), "r"((long long)&packed),
                       "d"((long long)name)
                     : "r10", "r8", "r9", "memory");
    if (status2 != 0)
        return (NTSTATUS)status2;
    return NTSTATUS_SUCCESS;
}

/* ------------------------------------------------------------------
 * NtSetValueKey — write a value into a previously-opened key.
 *
 * Win32 NT signature:
 *   NTSTATUS NtSetValueKey(
 *     HANDLE          KeyHandle,
 *     PUNICODE_STRING ValueName,
 *     ULONG           TitleIndex,
 *     ULONG           Type,
 *     PVOID           Data,
 *     ULONG           DataSize);
 *
 * v0 forwards to SYS_REGISTRY op=4 (kOpSetValue). Cap on
 * data size = 256 bytes per value (kSidecarDataMax kernel-side);
 * larger requests return STATUS_INSUFFICIENT_RESOURCES. The
 * kernel writes the value into a sidecar pool that shadows the
 * static tree on subsequent NtQueryValueKey reads.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtSetValueKey(HANDLE KeyHandle, UNICODE_STRING* ValueName, ULONG TitleIndex, ULONG Type,
                                             void* Data, ULONG DataSize)
{
    (void)TitleIndex;
    if (ValueName == (UNICODE_STRING*)0 || ValueName->Buffer == (wchar_t16*)0)
        return NTSTATUS_INVALID_PARAMETER;
    char name[64];
    const unsigned chars = (unsigned)(ValueName->Length / 2);
    if (chars + 1 > sizeof(name))
        return NTSTATUS_INVALID_PARAMETER;
    for (unsigned i = 0; i < chars; ++i)
    {
        unsigned short w = ValueName->Buffer[i];
        name[i] = (w <= 0x7F) ? (char)w : '?';
    }
    name[chars] = 0;
    long long status;
    /* SYS_REGISTRY = 130, op = 4 (kOpSetValue).
     * Args: rdi=op, rsi=handle, rdx=name, r10=data, r8=size, r9=type. */
    __asm__ volatile("mov %4, %%r10\n\t"
                     "mov %5, %%r8\n\t"
                     "mov %6, %%r9\n\t"
                     "int $0x80"
                     : "=a"(status)
                     : "a"((long long)130), "D"((long long)4), "S"((long long)KeyHandle), "r"((long long)Data),
                       "r"((long long)DataSize), "r"((long long)Type), "d"((long long)name)
                     : "r10", "r8", "r9", "memory");
    return (NTSTATUS)status;
}

/* ------------------------------------------------------------------
 * NtDeleteValueKey — remove a value from a previously-opened key.
 *
 * Win32 NT signature:
 *   NTSTATUS NtDeleteValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName);
 *
 * v0 only deletes values previously written via NtSetValueKey
 * (the sidecar). Static-tree values cannot be deleted (live in
 * .rodata) — the kernel returns STATUS_INSUFFICIENT_RESOURCES
 * for that case as the closest signal that the value exists but
 * is unmodifiable.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtDeleteValueKey(HANDLE KeyHandle, UNICODE_STRING* ValueName)
{
    if (ValueName == (UNICODE_STRING*)0 || ValueName->Buffer == (wchar_t16*)0)
        return NTSTATUS_INVALID_PARAMETER;
    char name[64];
    const unsigned chars = (unsigned)(ValueName->Length / 2);
    if (chars + 1 > sizeof(name))
        return NTSTATUS_INVALID_PARAMETER;
    for (unsigned i = 0; i < chars; ++i)
    {
        unsigned short w = ValueName->Buffer[i];
        name[i] = (w <= 0x7F) ? (char)w : '?';
    }
    name[chars] = 0;
    long long status;
    /* SYS_REGISTRY = 130, op = 5 (kOpDeleteValue). */
    __asm__ volatile("int $0x80"
                     : "=a"(status)
                     : "a"((long long)130), "D"((long long)5), "S"((long long)KeyHandle), "d"((long long)name)
                     : "memory");
    return (NTSTATUS)status;
}

/* ------------------------------------------------------------------
 * NtFlushKey — persist any pending writes for the key.
 *
 * v0 has no on-disk hive, so flush is a success-no-op. Provided
 * for API completeness — well-behaved app installers call it
 * after a batch of NtSetValueKey calls to ensure the writes
 * land before the installer exits.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtFlushKey(HANDLE KeyHandle)
{
    long long status;
    /* SYS_REGISTRY = 130, op = 6 (kOpFlushKey). */
    __asm__ volatile("int $0x80"
                     : "=a"(status)
                     : "a"((long long)130), "D"((long long)6), "S"((long long)KeyHandle)
                     : "memory");
    return (NTSTATUS)status;
}

/* ------------------------------------------------------------------
 * NtQueryInformationProcess — read per-process state.
 *
 * Win32 NT signature:
 *   NTSTATUS NtQueryInformationProcess(
 *     HANDLE ProcessHandle,
 *     ULONG  ProcessInformationClass,
 *     PVOID  ProcessInformation,
 *     ULONG  ProcessInformationLength,
 *     PULONG ReturnLength);
 *
 * v0 honours the ProcessBasicInformation class only — that's
 * what every real Win32 caller asks for first (PEB pointer +
 * UniqueProcessId discovery). Other classes return
 * STATUS_NOT_IMPLEMENTED so callers fall back rather than
 * misinterpret zeros.
 *
 * The buffer layout the kernel writes is exactly the 48-byte
 * PROCESS_BASIC_INFORMATION on x64 — no userland repacking.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtQueryInformationProcess(HANDLE ProcessHandle, ULONG ProcessInformationClass,
                                                         void* ProcessInformation, ULONG ProcessInformationLength,
                                                         ULONG* ReturnLength)
{
    long long status;
    /* SYS_PROCESS_QUERY_INFO = 147.
     * Args: rdi=handle, rsi=class, rdx=buf, r10=cap, r8=&retlen. */
    __asm__ volatile("mov %4, %%r10\n\t"
                     "mov %5, %%r8\n\t"
                     "int $0x80"
                     : "=a"(status)
                     : "a"((long long)147), "D"((long long)ProcessHandle), "S"((long long)ProcessInformationClass),
                       "r"((long long)ProcessInformationLength), "r"((long long)ReturnLength),
                       "d"((long long)ProcessInformation)
                     : "r10", "r8", "memory");
    return (NTSTATUS)status;
}

__declspec(dllexport) NTSTATUS ZwQueryInformationProcess(HANDLE ProcessHandle, ULONG ProcessInformationClass,
                                                         void* ProcessInformation, ULONG ProcessInformationLength,
                                                         ULONG* ReturnLength)
{
    return NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation,
                                     ProcessInformationLength, ReturnLength);
}
