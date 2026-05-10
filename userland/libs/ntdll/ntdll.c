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
#define DUET_USER_TRAP_UNREACHABLE()                                                                                   \
    do                                                                                                                 \
    {                                                                                                                  \
        __asm__ volatile("ud2" ::: "memory");                                                                          \
        __builtin_unreachable();                                                                                       \
    } while (0)

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
    DUET_USER_TRAP_UNREACHABLE();
}

/* NtAllocateVirtualMemory — honours hProcess (NtCurrentProcess()
 * = -1 for self; foreign Win32 process handle gated on
 * kCapDebug). Routes through SYS_VM_ALLOCATE = 148 which lands
 * a fresh user-VA range with the requested protection (W^X
 * silently downgrades RWX to RW + NX).
 *
 * Args (rdi=op-handle, rsi=hint, rdx=size, r10=type, r8=protect, r9=&out_base). */
__declspec(dllexport) NTSTATUS NtAllocateVirtualMemory(HANDLE hProcess, void** BaseAddress, SIZE_T ZeroBits,
                                                       SIZE_T* RegionSize, ULONG AllocationType, ULONG Protect)
{
    (void)ZeroBits;
    if (RegionSize == (SIZE_T*)0 || BaseAddress == (void**)0)
        return NTSTATUS_INVALID_PARAMETER;
    long long hint = (long long)*BaseAddress;
    long long sz = (long long)*RegionSize;
    long long out_base = 0;
    long long status;
    __asm__ volatile("mov %4, %%r10\n\t"
                     "mov %5, %%r8\n\t"
                     "mov %6, %%r9\n\t"
                     "int $0x80"
                     : "=a"(status)
                     : "a"((long long)148), "D"((long long)hProcess), "S"(hint), "d"(sz),
                       "r"((long long)AllocationType), "r"((long long)Protect), "r"((long long)&out_base)
                     : "r10", "r8", "r9", "memory");
    if (status != 0)
        return (NTSTATUS)status;
    *BaseAddress = (void*)out_base;
    /* *RegionSize stays as-passed — v0 honours exactly what was
     * asked, page-aligned upward inside the kernel. */
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS ZwAllocateVirtualMemory(HANDLE hProcess, void** BaseAddress, SIZE_T ZeroBits,
                                                       SIZE_T* RegionSize, ULONG AllocationType, ULONG Protect)
{
    return NtAllocateVirtualMemory(hProcess, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

__declspec(dllexport) NTSTATUS NtFreeVirtualMemory(HANDLE hProcess, void** BaseAddress, SIZE_T* RegionSize,
                                                   ULONG FreeType)
{
    if (BaseAddress == (void**)0 || RegionSize == (SIZE_T*)0)
        return NTSTATUS_INVALID_PARAMETER;
    long long va = (long long)*BaseAddress;
    long long sz = (long long)*RegionSize;
    long long status;
    __asm__ volatile("mov %4, %%r10\n\t"
                     "int $0x80"
                     : "=a"(status)
                     : "a"((long long)149), "D"((long long)hProcess), "S"(va), "d"(sz), "r"((long long)FreeType)
                     : "r10", "memory");
    return (NTSTATUS)status;
}

__declspec(dllexport) NTSTATUS ZwFreeVirtualMemory(HANDLE hProcess, void** BaseAddress, SIZE_T* RegionSize,
                                                   ULONG FreeType)
{
    return NtFreeVirtualMemory(hProcess, BaseAddress, RegionSize, FreeType);
}

/* NtProtectVirtualMemory — change page protection on an
 * already-mapped range. v0 honours self + foreign (cap-gated).
 * The kernel-side handler walks pages in the range and calls
 * AddressSpaceProtectUserPage on each; W^X is enforced. */
__declspec(dllexport) NTSTATUS NtProtectVirtualMemory(HANDLE hProcess, void** BaseAddress, SIZE_T* RegionSize,
                                                      ULONG NewProtect, ULONG* OldProtect)
{
    if (BaseAddress == (void**)0 || RegionSize == (SIZE_T*)0)
        return NTSTATUS_INVALID_PARAMETER;
    long long va = (long long)*BaseAddress;
    long long sz = (long long)*RegionSize;
    long long status;
    __asm__ volatile("mov %4, %%r10\n\t"
                     "mov %5, %%r8\n\t"
                     "int $0x80"
                     : "=a"(status)
                     : "a"((long long)150), "D"((long long)hProcess), "S"(va), "d"(sz), "r"((long long)NewProtect),
                       "r"((long long)OldProtect)
                     : "r10", "r8", "memory");
    return (NTSTATUS)status;
}

__declspec(dllexport) NTSTATUS ZwProtectVirtualMemory(HANDLE hProcess, void** BaseAddress, SIZE_T* RegionSize,
                                                      ULONG NewProtect, ULONG* OldProtect)
{
    return NtProtectVirtualMemory(hProcess, BaseAddress, RegionSize, NewProtect, OldProtect);
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

/* ------------------------------------------------------------------
 * NtCreateMutant / NtOpenMutant / NtReleaseMutant — Win32 mutexes.
 *
 * Mutant is the NT-internal name for what Win32 calls a mutex.
 * NtCreateMutant forwards directly to SYS_MUTEX_CREATE; v0
 * doesn't honour OBJECT_ATTRIBUTES (no named-object table yet),
 * so the returned handle is unnamed and can't be opened by
 * NtOpenMutant. Sub-GAP.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtCreateMutant(HANDLE* MutantHandle, ULONG DesiredAccess, void* ObjectAttributes,
                                              BOOL InitialOwner)
{
    (void)DesiredAccess;
    (void)ObjectAttributes;
    if (MutantHandle == (HANDLE*)0)
        return NTSTATUS_INVALID_PARAMETER;
    long long handle;
    /* SYS_MUTEX_CREATE = 25. rdi = bInitialOwner. */
    __asm__ volatile("int $0x80" : "=a"(handle) : "a"((long long)25), "D"((long long)InitialOwner) : "memory");
    if (handle < 0)
        return NTSTATUS_NO_MEMORY;
    *MutantHandle = (HANDLE)handle;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS ZwCreateMutant(HANDLE* MutantHandle, ULONG DesiredAccess, void* ObjectAttributes,
                                              BOOL InitialOwner)
{
    return NtCreateMutant(MutantHandle, DesiredAccess, ObjectAttributes, InitialOwner);
}

__declspec(dllexport) NTSTATUS NtOpenMutant(HANDLE* MutantHandle, ULONG DesiredAccess, void* ObjectAttributes)
{
    (void)MutantHandle;
    (void)DesiredAccess;
    (void)ObjectAttributes;
    /* No named-object table yet. */
    return (NTSTATUS)0xC0000034; /* STATUS_OBJECT_NAME_NOT_FOUND */
}

__declspec(dllexport) NTSTATUS ZwOpenMutant(HANDLE* MutantHandle, ULONG DesiredAccess, void* ObjectAttributes)
{
    return NtOpenMutant(MutantHandle, DesiredAccess, ObjectAttributes);
}

/* ------------------------------------------------------------------
 * NtCreateEvent / NtOpenEvent — Win32 events.
 *
 * EVENT_TYPE: 0 = NotificationEvent (manual reset),
 *             1 = SynchronizationEvent (auto reset).
 *
 * Maps to SYS_EVENT_CREATE which takes (bManualReset,
 * bInitialState). NtOpenEvent stays NotImpl pending named-
 * object plumbing.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtCreateEvent(HANDLE* EventHandle, ULONG DesiredAccess, void* ObjectAttributes,
                                             ULONG EventType, BOOL InitialState)
{
    (void)DesiredAccess;
    (void)ObjectAttributes;
    if (EventHandle == (HANDLE*)0)
        return NTSTATUS_INVALID_PARAMETER;
    long long handle;
    /* SYS_EVENT_CREATE = 30. rdi = bManualReset, rsi = bInitialState. */
    const long long manual_reset = (EventType == 0) ? 1 : 0;
    __asm__ volatile("int $0x80"
                     : "=a"(handle)
                     : "a"((long long)30), "D"(manual_reset), "S"((long long)InitialState)
                     : "memory");
    if (handle < 0)
        return NTSTATUS_NO_MEMORY;
    *EventHandle = (HANDLE)handle;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS ZwCreateEvent(HANDLE* EventHandle, ULONG DesiredAccess, void* ObjectAttributes,
                                             ULONG EventType, BOOL InitialState)
{
    return NtCreateEvent(EventHandle, DesiredAccess, ObjectAttributes, EventType, InitialState);
}

__declspec(dllexport) NTSTATUS NtOpenEvent(HANDLE* EventHandle, ULONG DesiredAccess, void* ObjectAttributes)
{
    (void)EventHandle;
    (void)DesiredAccess;
    (void)ObjectAttributes;
    return (NTSTATUS)0xC0000034;
}

__declspec(dllexport) NTSTATUS ZwOpenEvent(HANDLE* EventHandle, ULONG DesiredAccess, void* ObjectAttributes)
{
    return NtOpenEvent(EventHandle, DesiredAccess, ObjectAttributes);
}

/* NtReleaseMutant -> SYS_MUTEX_RELEASE (27). The existing
 * NtReleaseMutant thunk lives further down in this file —
 * declared here as a forward so the create/open block reads
 * cohesively without scrolling. */

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
 * negative number) on success or a negative errno on any error.
 * We map every negative value to STATUS_INVALID_HANDLE because
 * that is the only NTSTATUS this v0 surface distinguishes today.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtSuspendThread(HANDLE ThreadHandle, unsigned long* PreviousSuspendCount)
{
    long long rc;
    /* SYS_THREAD_SUSPEND = 135 */
    __asm__ volatile("int $0x80" : "=a"(rc) : "a"((long long)135), "D"((long long)ThreadHandle) : "memory");
    if (rc < 0)
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
    if (rc < 0)
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
/* ------------------------------------------------------------------
 * NtQueryObject — derive object metadata from a kernel handle.
 *
 * Win32 NT signature:
 *   NTSTATUS NtQueryObject(
 *     HANDLE Handle,
 *     OBJECT_INFORMATION_CLASS ObjectInformationClass,
 *     PVOID ObjectInformation,
 *     ULONG ObjectInformationLength,
 *     PULONG ReturnLength);
 *
 * v0 honours ObjectTypeInformation (class 2) only — that's the
 * class every malware-shape PE uses to confirm a handle's
 * underlying type. The implementation lives entirely in userland:
 * the kernel's handle bases are stable u64 ranges
 * (0x200..0x208 = Mutant, 0x300..0x308 = Event,
 *  0x400..0x408 = Thread, 0x600..0x608 = Key,
 *  0x700..0x708 = Process, 0x800..0x808 = Thread (foreign),
 *  0x900..0x908 = Section), so range-matching produces the
 *  right type name without a syscall.
 *
 *  Output layout for ObjectTypeInformation: a UNICODE_STRING
 *  header (16 bytes on x64) followed by the UTF-16 type name
 *  + trailing NUL, with Buffer pointing into the same buffer.
 *  This matches the "alloc one block, header self-references"
 *  shape every Windows caller assumes.
 * ------------------------------------------------------------------ */
static const wchar_t16* HandleRangeToTypeName(unsigned long long handle)
{
    static const wchar_t16 mutant[] = {'M', 'u', 't', 'a', 'n', 't', 0};
    static const wchar_t16 event[] = {'E', 'v', 'e', 'n', 't', 0};
    static const wchar_t16 thread[] = {'T', 'h', 'r', 'e', 'a', 'd', 0};
    static const wchar_t16 key[] = {'K', 'e', 'y', 0};
    static const wchar_t16 process[] = {'P', 'r', 'o', 'c', 'e', 's', 's', 0};
    static const wchar_t16 section[] = {'S', 'e', 'c', 't', 'i', 'o', 'n', 0};
    if (handle >= 0x200 && handle < 0x208)
        return mutant;
    if (handle >= 0x300 && handle < 0x308)
        return event;
    if (handle >= 0x400 && handle < 0x408)
        return thread;
    if (handle >= 0x600 && handle < 0x608)
        return key;
    if (handle >= 0x700 && handle < 0x708)
        return process;
    if (handle >= 0x800 && handle < 0x808)
        return thread; /* foreign-thread handles are still threads */
    if (handle >= 0x900 && handle < 0x908)
        return section;
    return (const wchar_t16*)0;
}

static unsigned WStr16Len(const wchar_t16* s)
{
    unsigned n = 0;
    while (s[n] != 0)
        ++n;
    return n;
}

__declspec(dllexport) NTSTATUS NtQueryObject(HANDLE Handle, ULONG ObjectInformationClass, void* ObjectInformation,
                                             ULONG ObjectInformationLength, ULONG* ReturnLength)
{
    /* ObjectTypeInformation = 2. Other classes (Basic, Name,
     * AllInformation, DataInformation, …) return NOT_IMPLEMENTED
     * so callers fall back rather than misinterpret zeros. */
    if (ObjectInformationClass != 2)
        return (NTSTATUS)0xC0000002; /* STATUS_NOT_IMPLEMENTED */

    const wchar_t16* type_name = HandleRangeToTypeName((unsigned long long)Handle);
    if (type_name == (const wchar_t16*)0)
        return (NTSTATUS)0xC0000008; /* STATUS_INVALID_HANDLE */

    const unsigned name_chars = WStr16Len(type_name);
    const unsigned name_bytes = name_chars * 2;
    /* OBJECT_TYPE_INFORMATION starts with a 16-byte UNICODE_STRING
     * (Length:2, MaximumLength:2, _pad:4, Buffer:8) on x64. The
     * UTF-16 string body follows immediately after, with a
     * trailing NUL. */
    const unsigned header = 16;
    const unsigned total = header + name_bytes + 2;
    if (ReturnLength != (ULONG*)0)
        *ReturnLength = total;
    if (ObjectInformationLength < total)
        return (NTSTATUS)0xC0000023; /* STATUS_BUFFER_TOO_SMALL */
    if (ObjectInformation == (void*)0)
        return NTSTATUS_INVALID_PARAMETER;

    unsigned char* out = (unsigned char*)ObjectInformation;
    /* UNICODE_STRING.Length (bytes used, excluding NUL). */
    out[0] = (unsigned char)(name_bytes & 0xFF);
    out[1] = (unsigned char)((name_bytes >> 8) & 0xFF);
    /* UNICODE_STRING.MaximumLength (bytes including NUL). */
    out[2] = (unsigned char)((name_bytes + 2) & 0xFF);
    out[3] = (unsigned char)(((name_bytes + 2) >> 8) & 0xFF);
    /* 4-byte padding zeroed. */
    out[4] = 0;
    out[5] = 0;
    out[6] = 0;
    out[7] = 0;
    /* UNICODE_STRING.Buffer — pointer to the body inside this
     * same allocation. */
    void** buf_slot = (void**)(out + 8);
    *buf_slot = (void*)(out + header);

    /* Copy the UTF-16 type name body + trailing NUL. */
    wchar_t16* body = (wchar_t16*)(out + header);
    for (unsigned i = 0; i < name_chars; ++i)
        body[i] = type_name[i];
    body[name_chars] = 0;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS ZwQueryObject(HANDLE Handle, ULONG ObjectInformationClass, void* ObjectInformation,
                                             ULONG ObjectInformationLength, ULONG* ReturnLength)
{
    return NtQueryObject(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);
}

/* NtQuerySystemTime + NtQueryPerformanceCounter live earlier in
 * this file (around line 127). Zw* aliases below for export
 * completeness. */
__declspec(dllexport) NTSTATUS ZwQuerySystemTime(long long* SystemTime)
{
    return NtQuerySystemTime(SystemTime);
}

__declspec(dllexport) NTSTATUS ZwQueryPerformanceCounter(long long* counter, long long* freq)
{
    return NtQueryPerformanceCounter(counter, freq);
}

/* ------------------------------------------------------------------
 * NtQuerySystemInformation — multiplexed system info read.
 * Honours SystemBasicInformation (0) + SystemTimeOfDayInformation (3);
 * other classes return NotImpl. The real hardware/topology data
 * lives in the kernel — this thunk only adapts the ABI shape.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtQuerySystemInformation(ULONG SystemInformationClass, void* SystemInformation,
                                                        ULONG SystemInformationLength, ULONG* ReturnLength)
{
    if (SystemInformation == (void*)0)
        return NTSTATUS_INVALID_PARAMETER;
    if (SystemInformationClass == 0 /* SystemBasicInformation */)
    {
        const unsigned total = 56;
        if (ReturnLength != (ULONG*)0)
            *ReturnLength = total;
        if (SystemInformationLength < total)
            return (NTSTATUS)0xC0000004;
        unsigned char* out = (unsigned char*)SystemInformation;
        for (unsigned i = 0; i < total; ++i)
            out[i] = 0;
        out[4] = 0x10;
        out[5] = 0x27; /* TimerResolution */
        out[8] = 0x00;
        out[9] = 0x10; /* PageSize = 4096 */
        out[24] = 0x00;
        out[25] = 0x00;
        out[26] = 0x01;
        out[27] = 0x00; /* AllocationGranularity = 65536 */
        out[52] = 1;    /* NumberOfProcessors = 1 */
        return NTSTATUS_SUCCESS;
    }
    if (SystemInformationClass == 3 /* SystemTimeOfDayInformation */)
    {
        const unsigned total = 32;
        if (ReturnLength != (ULONG*)0)
            *ReturnLength = total;
        if (SystemInformationLength < total)
            return (NTSTATUS)0xC0000004;
        unsigned char* out = (unsigned char*)SystemInformation;
        for (unsigned i = 0; i < total; ++i)
            out[i] = 0;
        long long ft, ns;
        __asm__ volatile("int $0x80" : "=a"(ft) : "a"((long long)17) : "memory");
        __asm__ volatile("int $0x80" : "=a"(ns) : "a"((long long)18) : "memory");
        long long boot = ft - (ns / 100);
        for (unsigned i = 0; i < 8; ++i)
            out[i] = (unsigned char)((boot >> (i * 8)) & 0xFF);
        for (unsigned i = 0; i < 8; ++i)
            out[8 + i] = (unsigned char)((ft >> (i * 8)) & 0xFF);
        return NTSTATUS_SUCCESS;
    }
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS ZwQuerySystemInformation(ULONG SystemInformationClass, void* SystemInformation,
                                                        ULONG SystemInformationLength, ULONG* ReturnLength)
{
    return NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}

__declspec(dllexport) NTSTATUS NtSetSystemInformation(ULONG SystemInformationClass, void* SystemInformation,
                                                      ULONG SystemInformationLength)
{
    (void)SystemInformationClass;
    (void)SystemInformation;
    (void)SystemInformationLength;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS ZwSetSystemInformation(ULONG SystemInformationClass, void* SystemInformation,
                                                      ULONG SystemInformationLength)
{
    return NtSetSystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength);
}

/* ------------------------------------------------------------------
 * NT LPC / ALPC — explicit NotImpl facades.
 *
 * v0 has no LPC/ALPC inter-process port engine. Every Win32 RPC
 * lands kernel-side via SYS_* directly, not via Win32 ports.
 * These thunks return NotImpl so any RPC-shaped probe gets a
 * clean answer. Architectural note: cross-process IPC in DuetOS
 * goes through kernel-mediated, cap-gated SYS_* — the LPC port
 * surface is a façade, not a parallel IPC path.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtCreatePort(HANDLE* PortHandle, void* ObjectAttributes, ULONG MaxConnectionInfoLength,
                                            ULONG MaxMessageLength, ULONG MaxPoolUsage)
{
    (void)PortHandle;
    (void)ObjectAttributes;
    (void)MaxConnectionInfoLength;
    (void)MaxMessageLength;
    (void)MaxPoolUsage;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtConnectPort(HANDLE* ClientPortHandle, void* PortName, void* SecurityQos,
                                             void* ClientView, void* ServerView, void* MaxMessageLength,
                                             void* ConnectionInformation, void* ConnectionInformationLength)
{
    (void)ClientPortHandle;
    (void)PortName;
    (void)SecurityQos;
    (void)ClientView;
    (void)ServerView;
    (void)MaxMessageLength;
    (void)ConnectionInformation;
    (void)ConnectionInformationLength;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtListenPort(HANDLE PortHandle, void* ConnectionRequest)
{
    (void)PortHandle;
    (void)ConnectionRequest;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtAcceptConnectPort(HANDLE* ServerPortHandle, void* PortContext, void* ConnectionRequest,
                                                   BOOL AcceptConnection, void* ServerView, void* ClientView)
{
    (void)ServerPortHandle;
    (void)PortContext;
    (void)ConnectionRequest;
    (void)AcceptConnection;
    (void)ServerView;
    (void)ClientView;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtCompleteConnectPort(HANDLE PortHandle)
{
    (void)PortHandle;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtRequestPort(HANDLE PortHandle, void* RequestMessage)
{
    (void)PortHandle;
    (void)RequestMessage;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtRequestWaitReplyPort(HANDLE PortHandle, void* RequestMessage, void* ReplyMessage)
{
    (void)PortHandle;
    (void)RequestMessage;
    (void)ReplyMessage;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtReplyPort(HANDLE PortHandle, void* ReplyMessage)
{
    (void)PortHandle;
    (void)ReplyMessage;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtReplyWaitReceivePort(HANDLE PortHandle, void** PortContext, void* ReplyMessage,
                                                      void* ReceiveMessage)
{
    (void)PortHandle;
    (void)PortContext;
    (void)ReplyMessage;
    (void)ReceiveMessage;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtAlpcCreatePort(HANDLE* PortHandle, void* ObjectAttributes, void* PortAttributes)
{
    (void)PortHandle;
    (void)ObjectAttributes;
    (void)PortAttributes;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtAlpcConnectPort(HANDLE* PortHandle, void* PortName, void* ObjectAttributes,
                                                 void* PortAttributes, ULONG Flags, void* RequiredServerSid,
                                                 void* ConnectionMessage, void* BufferLength,
                                                 void* OutMessageAttributes, void* InMessageAttributes, void* Timeout)
{
    (void)PortHandle;
    (void)PortName;
    (void)ObjectAttributes;
    (void)PortAttributes;
    (void)Flags;
    (void)RequiredServerSid;
    (void)ConnectionMessage;
    (void)BufferLength;
    (void)OutMessageAttributes;
    (void)InMessageAttributes;
    (void)Timeout;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtAlpcSendWaitReceivePort(HANDLE PortHandle, ULONG Flags, void* SendMessage,
                                                         void* SendMessageAttributes, void* ReceiveMessage,
                                                         void* BufferLength, void* ReceiveMessageAttributes,
                                                         void* Timeout)
{
    (void)PortHandle;
    (void)Flags;
    (void)SendMessage;
    (void)SendMessageAttributes;
    (void)ReceiveMessage;
    (void)BufferLength;
    (void)ReceiveMessageAttributes;
    (void)Timeout;
    return (NTSTATUS)0xC0000002;
}

/* ------------------------------------------------------------------
 * NT atom / symbolic-link / directory-object — explicit NotImpl
 * facades. All four are name-table primitives that v0 doesn't
 * have a backing store for. Architectural note: the kernel owns
 * naming; these thunks don't synthesize a parallel namespace.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtAddAtom(void* AtomName, ULONG Length, void* Atom)
{
    (void)AtomName;
    (void)Length;
    (void)Atom;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtFindAtom(void* AtomName, ULONG Length, void* Atom)
{
    (void)AtomName;
    (void)Length;
    (void)Atom;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtDeleteAtom(unsigned short Atom)
{
    (void)Atom;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtCreateSymbolicLinkObject(HANDLE* LinkHandle, ULONG DesiredAccess,
                                                          void* ObjectAttributes, void* LinkTarget)
{
    (void)LinkHandle;
    (void)DesiredAccess;
    (void)ObjectAttributes;
    (void)LinkTarget;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtOpenSymbolicLinkObject(HANDLE* LinkHandle, ULONG DesiredAccess, void* ObjectAttributes)
{
    (void)LinkHandle;
    (void)DesiredAccess;
    (void)ObjectAttributes;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtQuerySymbolicLinkObject(HANDLE LinkHandle, void* LinkTarget, void* ReturnedLength)
{
    (void)LinkHandle;
    (void)LinkTarget;
    (void)ReturnedLength;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtCreateDirectoryObject(HANDLE* DirectoryHandle, ULONG DesiredAccess,
                                                       void* ObjectAttributes)
{
    (void)DirectoryHandle;
    (void)DesiredAccess;
    (void)ObjectAttributes;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtOpenDirectoryObject(HANDLE* DirectoryHandle, ULONG DesiredAccess,
                                                     void* ObjectAttributes)
{
    (void)DirectoryHandle;
    (void)DesiredAccess;
    (void)ObjectAttributes;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtQueryDirectoryObject(HANDLE DirectoryHandle, void* Buffer, ULONG Length,
                                                      BOOL ReturnSingleEntry, BOOL RestartScan, void* Context,
                                                      void* ReturnLength)
{
    (void)DirectoryHandle;
    (void)Buffer;
    (void)Length;
    (void)ReturnSingleEntry;
    (void)RestartScan;
    (void)Context;
    (void)ReturnLength;
    return (NTSTATUS)0xC0000002;
}

/* ------------------------------------------------------------------
 * NT extended-file ops — explicit NotImpl facades.
 * Lock / EA / NotifyChange families. v0 has no byte-range lock
 * table, no extended-attribute store, and no inotify-style watch
 * dispatch. Returning NotImpl is the right answer; callers fall
 * back rather than spin.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtLockFile(HANDLE FileHandle, HANDLE Event, void* ApcRoutine, void* ApcContext,
                                          void* IoStatusBlock, void* ByteOffset, void* Length, ULONG Key,
                                          BOOL FailImmediately, BOOL ExclusiveLock)
{
    (void)FileHandle;
    (void)Event;
    (void)ApcRoutine;
    (void)ApcContext;
    (void)IoStatusBlock;
    (void)ByteOffset;
    (void)Length;
    (void)Key;
    (void)FailImmediately;
    (void)ExclusiveLock;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtUnlockFile(HANDLE FileHandle, void* IoStatusBlock, void* ByteOffset, void* Length,
                                            ULONG Key)
{
    (void)FileHandle;
    (void)IoStatusBlock;
    (void)ByteOffset;
    (void)Length;
    (void)Key;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtQueryEaFile(HANDLE FileHandle, void* IoStatusBlock, void* Buffer, ULONG Length,
                                             BOOL ReturnSingleEntry, void* EaList, ULONG EaListLength, void* EaIndex,
                                             BOOL RestartScan)
{
    (void)FileHandle;
    (void)IoStatusBlock;
    (void)Buffer;
    (void)Length;
    (void)ReturnSingleEntry;
    (void)EaList;
    (void)EaListLength;
    (void)EaIndex;
    (void)RestartScan;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtSetEaFile(HANDLE FileHandle, void* IoStatusBlock, void* Buffer, ULONG Length)
{
    (void)FileHandle;
    (void)IoStatusBlock;
    (void)Buffer;
    (void)Length;
    return (NTSTATUS)0xC0000002;
}

/* NtNotifyChangeDirectoryFile — backed by SYS_DIR_NOTIFY (= 157).
 * Synchronous: blocks until the watched directory has at least
 * one change matching CompletionFilter, then writes a single
 * FILE_NOTIFY_INFORMATION record and returns. Real Windows packs
 * many records and supports async via Event / APC; v0 caller
 * loops to drain. Event / ApcRoutine / ApcContext accepted but
 * ignored — sub-GAP. */
__declspec(dllexport) NTSTATUS NtNotifyChangeDirectoryFile(HANDLE FileHandle, HANDLE Event, void* ApcRoutine,
                                                           void* ApcContext, void* IoStatusBlock, void* Buffer,
                                                           ULONG Length, ULONG CompletionFilter, BOOL WatchTree)
{
    (void)Event;
    (void)ApcRoutine;
    (void)ApcContext;
    if (Buffer == (void*)0 || Length == 0)
        return NTSTATUS_INVALID_PARAMETER;
    long long rv;
    __asm__ volatile("mov %4, %%r10\n\t"
                     "mov %5, %%r8\n\t"
                     "int $0x80"
                     : "=a"(rv)
                     : "a"((long long)157), /* SYS_DIR_NOTIFY */
                       "D"((long long)FileHandle), "S"((long long)CompletionFilter), "d"((long long)WatchTree),
                       "r"((long long)Buffer), "r"((long long)Length)
                     : "r10", "r8", "memory");
    if (rv < 0)
        return (NTSTATUS)0xC0000008ULL; /* STATUS_INVALID_HANDLE */
    if (IoStatusBlock != (void*)0)
    {
        unsigned long long* iosb = (unsigned long long*)IoStatusBlock;
        iosb[0] = 0;                      /* NTSTATUS_SUCCESS */
        iosb[1] = (unsigned long long)rv; /* bytes written */
    }
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtCancelIoFile(HANDLE FileHandle, void* IoStatusBlock)
{
    (void)FileHandle;
    if (IoStatusBlock != (void*)0)
    {
        unsigned long long* iosb = (unsigned long long*)IoStatusBlock;
        iosb[0] = 0;
        iosb[1] = 0;
    }
    /* No async I/O to cancel; success no-op. */
    return NTSTATUS_SUCCESS;
}

/* ------------------------------------------------------------------
 * NT extended-IO + tracing + locale + final misc facades.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtCancelIoFileEx(HANDLE FileHandle, void* IoRequestToCancel, void* IoStatusBlock)
{
    (void)FileHandle;
    (void)IoRequestToCancel;
    if (IoStatusBlock != (void*)0)
    {
        unsigned long long* iosb = (unsigned long long*)IoStatusBlock;
        iosb[0] = 0;
        iosb[1] = 0;
    }
    /* No async I/O to cancel. */
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtCancelSynchronousIoFile(HANDLE ThreadHandle, void* IoRequestToCancel,
                                                         void* IoStatusBlock)
{
    (void)ThreadHandle;
    (void)IoRequestToCancel;
    if (IoStatusBlock != (void*)0)
    {
        unsigned long long* iosb = (unsigned long long*)IoStatusBlock;
        iosb[0] = 0;
        iosb[1] = 0;
    }
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtReadFileScatter(HANDLE FileHandle, HANDLE Event, void* ApcRoutine, void* ApcContext,
                                                 void* IoStatusBlock, void* SegmentArray, ULONG Length,
                                                 void* ByteOffset, void* Key)
{
    (void)FileHandle;
    (void)Event;
    (void)ApcRoutine;
    (void)ApcContext;
    (void)SegmentArray;
    (void)Length;
    (void)ByteOffset;
    (void)Key;
    if (IoStatusBlock != (void*)0)
    {
        unsigned long long* iosb = (unsigned long long*)IoStatusBlock;
        iosb[0] = 0xC0000002;
        iosb[1] = 0;
    }
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtWriteFileGather(HANDLE FileHandle, HANDLE Event, void* ApcRoutine, void* ApcContext,
                                                 void* IoStatusBlock, void* SegmentArray, ULONG Length,
                                                 void* ByteOffset, void* Key)
{
    (void)FileHandle;
    (void)Event;
    (void)ApcRoutine;
    (void)ApcContext;
    (void)SegmentArray;
    (void)Length;
    (void)ByteOffset;
    (void)Key;
    if (IoStatusBlock != (void*)0)
    {
        unsigned long long* iosb = (unsigned long long*)IoStatusBlock;
        iosb[0] = 0xC0000002;
        iosb[1] = 0;
    }
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtTraceEvent(HANDLE TraceHandle, ULONG Flags, ULONG FieldSize, void* Fields)
{
    (void)TraceHandle;
    (void)Flags;
    (void)FieldSize;
    (void)Fields;
    /* No ETW; success no-op so tracing shapes don't error. */
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtTraceControl(ULONG TraceCode, void* InputBuffer, ULONG InputBufferLength,
                                              void* OutputBuffer, ULONG OutputBufferLength, ULONG* ReturnLength)
{
    (void)TraceCode;
    (void)InputBuffer;
    (void)InputBufferLength;
    (void)OutputBuffer;
    (void)OutputBufferLength;
    if (ReturnLength != (ULONG*)0)
        *ReturnLength = 0;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtGetMUIRegistryInfo(ULONG Flags, ULONG* OutputResourceCount, void* OutputBuffer)
{
    (void)Flags;
    if (OutputResourceCount != (ULONG*)0)
        *OutputResourceCount = 0;
    (void)OutputBuffer;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtQueryDefaultLocale(BOOL UserProfile, ULONG* DefaultLocaleId)
{
    (void)UserProfile;
    if (DefaultLocaleId != (ULONG*)0)
        *DefaultLocaleId = 0x0409; /* en-US */
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtSetDefaultLocale(BOOL UserProfile, ULONG DefaultLocaleId)
{
    (void)UserProfile;
    (void)DefaultLocaleId;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtQueryDefaultUILanguage(unsigned short* DefaultUILanguageId)
{
    if (DefaultUILanguageId != (unsigned short*)0)
        *DefaultUILanguageId = 0x0409;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtSetDefaultUILanguage(unsigned short DefaultUILanguageId)
{
    (void)DefaultUILanguageId;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtQueryInstallUILanguage(unsigned short* InstallUILanguageId)
{
    if (InstallUILanguageId != (unsigned short*)0)
        *InstallUILanguageId = 0x0409;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtSetUuidSeed(void* Seed)
{
    (void)Seed;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtAllocateUuids(void* Time, ULONG* Range, ULONG* Sequence, void* Seed)
{
    (void)Time;
    (void)Seed;
    if (Range != (ULONG*)0)
        *Range = 0;
    if (Sequence != (ULONG*)0)
        *Sequence = 0;
    return (NTSTATUS)0xC0000002;
}

/* NtSecureConnectPort — LPC variant. NotImpl. */
__declspec(dllexport) NTSTATUS NtSecureConnectPort(HANDLE* ClientPortHandle, void* PortName, void* SecurityQos,
                                                   void* ClientView, void* ServerSid, void* ServerView,
                                                   void* MaxMessageLength, void* ConnectionInformation,
                                                   void* ConnectionInformationLength)
{
    (void)ClientPortHandle;
    (void)PortName;
    (void)SecurityQos;
    (void)ClientView;
    (void)ServerSid;
    (void)ServerView;
    (void)MaxMessageLength;
    (void)ConnectionInformation;
    (void)ConnectionInformationLength;
    return (NTSTATUS)0xC0000002;
}

/* NtDuplicateToken — duplicates a token for impersonation. v0
 * has one static token; duplication just hands back the same
 * sentinel handle (0xA00 — see DUETOS_TOKEN_HANDLE further
 * down). */
__declspec(dllexport) NTSTATUS NtDuplicateToken(HANDLE ExistingTokenHandle, ULONG DesiredAccess, void* ObjectAttributes,
                                                BOOL EffectiveOnly, ULONG TokenType, HANDLE* NewTokenHandle)
{
    (void)ExistingTokenHandle;
    (void)DesiredAccess;
    (void)ObjectAttributes;
    (void)EffectiveOnly;
    (void)TokenType;
    if (NewTokenHandle == (HANDLE*)0)
        return NTSTATUS_INVALID_PARAMETER;
    *NewTokenHandle = (HANDLE)0xA00;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtFilterToken(HANDLE ExistingTokenHandle, ULONG Flags, void* SidsToDisable,
                                             void* PrivilegesToDelete, void* RestrictedSids, HANDLE* NewTokenHandle)
{
    (void)ExistingTokenHandle;
    (void)Flags;
    (void)SidsToDisable;
    (void)PrivilegesToDelete;
    (void)RestrictedSids;
    if (NewTokenHandle == (HANDLE*)0)
        return NTSTATUS_INVALID_PARAMETER;
    *NewTokenHandle = (HANDLE)0xA00;
    return NTSTATUS_SUCCESS;
}

/* ------------------------------------------------------------------
 * NT mailslot + named-pipe + power-info + write-watch + profile
 * + PnP + VDM facades.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtCreateMailslotFile(HANDLE* FileHandle, ULONG DesiredAccess, void* ObjectAttributes,
                                                    void* IoStatusBlock, ULONG CreateOptions, ULONG MailslotQuota,
                                                    ULONG MaximumMessageSize, void* ReadTimeout)
{
    (void)FileHandle;
    (void)DesiredAccess;
    (void)ObjectAttributes;
    (void)IoStatusBlock;
    (void)CreateOptions;
    (void)MailslotQuota;
    (void)MaximumMessageSize;
    (void)ReadTimeout;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtCreateNamedPipeFile(HANDLE* FileHandle, ULONG DesiredAccess, void* ObjectAttributes,
                                                     void* IoStatusBlock, ULONG ShareAccess, ULONG CreateDisposition,
                                                     ULONG CreateOptions, BOOL NamedPipeType, BOOL ReadMode,
                                                     BOOL CompletionMode, ULONG MaximumInstances, ULONG InboundQuota,
                                                     ULONG OutboundQuota, void* DefaultTimeout)
{
    (void)FileHandle;
    (void)DesiredAccess;
    (void)ObjectAttributes;
    (void)IoStatusBlock;
    (void)ShareAccess;
    (void)CreateDisposition;
    (void)CreateOptions;
    (void)NamedPipeType;
    (void)ReadMode;
    (void)CompletionMode;
    (void)MaximumInstances;
    (void)InboundQuota;
    (void)OutboundQuota;
    (void)DefaultTimeout;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtImpersonateClientOfPort(HANDLE PortHandle, void* Message)
{
    (void)PortHandle;
    (void)Message;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtPowerInformation(ULONG InformationLevel, void* InputBuffer, ULONG InputBufferLength,
                                                  void* OutputBuffer, ULONG OutputBufferLength)
{
    (void)InformationLevel;
    (void)InputBuffer;
    (void)InputBufferLength;
    if (OutputBuffer != (void*)0 && OutputBufferLength > 0)
    {
        unsigned char* out = (unsigned char*)OutputBuffer;
        for (ULONG i = 0; i < OutputBufferLength; ++i)
            out[i] = 0;
    }
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtGetWriteWatch(HANDLE ProcessHandle, ULONG Flags, void* BaseAddress, SIZE_T RegionSize,
                                               void** UserAddressArray, SIZE_T* EntriesInUserAddressArray,
                                               ULONG* Granularity)
{
    (void)ProcessHandle;
    (void)Flags;
    (void)BaseAddress;
    (void)RegionSize;
    (void)UserAddressArray;
    if (EntriesInUserAddressArray != (SIZE_T*)0)
        *EntriesInUserAddressArray = 0;
    if (Granularity != (ULONG*)0)
        *Granularity = 4096;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtResetWriteWatch(HANDLE ProcessHandle, void* BaseAddress, SIZE_T RegionSize)
{
    (void)ProcessHandle;
    (void)BaseAddress;
    (void)RegionSize;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtCreateProfile(HANDLE* ProfileHandle, HANDLE ProcessHandle, void* RangeBase,
                                               SIZE_T RangeSize, ULONG BucketSize, void* Buffer, ULONG BufferSize,
                                               ULONG ProfileSource, ULONG Affinity)
{
    (void)ProfileHandle;
    (void)ProcessHandle;
    (void)RangeBase;
    (void)RangeSize;
    (void)BucketSize;
    (void)Buffer;
    (void)BufferSize;
    (void)ProfileSource;
    (void)Affinity;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtStartProfile(HANDLE ProfileHandle)
{
    (void)ProfileHandle;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtStopProfile(HANDLE ProfileHandle)
{
    (void)ProfileHandle;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtSetIntervalProfile(ULONG Interval, ULONG Source)
{
    (void)Interval;
    (void)Source;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtQueryIntervalProfile(ULONG ProfileSource, ULONG* Interval)
{
    (void)ProfileSource;
    if (Interval != (ULONG*)0)
        *Interval = 0;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtPlugPlayControl(ULONG PnPControlClass, void* PnPControlData,
                                                 ULONG PnPControlDataLength)
{
    (void)PnPControlClass;
    (void)PnPControlData;
    (void)PnPControlDataLength;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtVdmControl(ULONG Service, void* ServiceData)
{
    (void)Service;
    (void)ServiceData;
    return (NTSTATUS)0xC0000002;
}

/* ------------------------------------------------------------------
 * NT additional VM + driver-load + system-power thunks.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtFlushVirtualMemory(HANDLE ProcessHandle, void** BaseAddress, SIZE_T* RegionSize,
                                                    void* IoStatus)
{
    (void)ProcessHandle;
    (void)BaseAddress;
    (void)RegionSize;
    if (IoStatus != (void*)0)
    {
        unsigned long long* iosb = (unsigned long long*)IoStatus;
        iosb[0] = 0;
        iosb[1] = 0;
    }
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtLockVirtualMemory(HANDLE ProcessHandle, void** BaseAddress, SIZE_T* RegionSize,
                                                   ULONG MapType)
{
    (void)ProcessHandle;
    (void)BaseAddress;
    (void)RegionSize;
    (void)MapType;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtUnlockVirtualMemory(HANDLE ProcessHandle, void** BaseAddress, SIZE_T* RegionSize,
                                                     ULONG MapType)
{
    (void)ProcessHandle;
    (void)BaseAddress;
    (void)RegionSize;
    (void)MapType;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtAreMappedFilesTheSame(void* File1MappedAsAnImage, void* File2MappedAsFile)
{
    (void)File1MappedAsAnImage;
    (void)File2MappedAsFile;
    return (NTSTATUS)0xC0000055; /* STATUS_NOT_SAME_DEVICE */
}

__declspec(dllexport) NTSTATUS NtLoadDriver(void* DriverServiceName)
{
    (void)DriverServiceName;
    /* Architectural note: drivers are kernel-internal, not
     * subsystem-internal. Userland never gets to load drivers.
     * STATUS_PRIVILEGE_NOT_HELD = 0xC0000061. */
    return (NTSTATUS)0xC0000061;
}

__declspec(dllexport) NTSTATUS NtUnloadDriver(void* DriverServiceName)
{
    (void)DriverServiceName;
    return (NTSTATUS)0xC0000061;
}

__declspec(dllexport) NTSTATUS NtShutdownSystem(ULONG Action)
{
    (void)Action;
    /* Power management is kernel-owned. */
    return (NTSTATUS)0xC0000061;
}

__declspec(dllexport) NTSTATUS NtRaiseHardError(NTSTATUS ErrorStatus, ULONG NumberOfParameters,
                                                ULONG UnicodeStringParameterMask, void* Parameters,
                                                ULONG ValidResponseOptions, ULONG* Response)
{
    (void)ErrorStatus;
    (void)NumberOfParameters;
    (void)UnicodeStringParameterMask;
    (void)Parameters;
    (void)ValidResponseOptions;
    if (Response != (ULONG*)0)
        *Response = 0;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtSetTimerResolution(ULONG DesiredResolution, BOOL SetResolution,
                                                    ULONG* CurrentResolution)
{
    (void)SetResolution;
    if (CurrentResolution != (ULONG*)0)
        *CurrentResolution = DesiredResolution;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtQueryTimerResolution(ULONG* MaximumTime, ULONG* MinimumTime, ULONG* CurrentTime)
{
    if (MaximumTime != (ULONG*)0)
        *MaximumTime = 156250;
    if (MinimumTime != (ULONG*)0)
        *MinimumTime = 5000;
    if (CurrentTime != (ULONG*)0)
        *CurrentTime = 100000;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) ULONG NtGetCurrentProcessorNumber(void)
{
    return 0;
}

/* ------------------------------------------------------------------
 * NT misc sync + APC + event extras + token write surface
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtPulseEvent(HANDLE EventHandle, long* PreviousState)
{
    long long rv1, rv2;
    __asm__ volatile("int $0x80" : "=a"(rv1) : "a"((long long)31), "D"((long long)EventHandle) : "memory");
    __asm__ volatile("int $0x80" : "=a"(rv2) : "a"((long long)32), "D"((long long)EventHandle) : "memory");
    if (PreviousState != (long*)0)
        *PreviousState = 0;
    if (rv1 != 0 || rv2 != 0)
        return (NTSTATUS)0xC0000008;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtClearEvent(HANDLE EventHandle)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)32), "D"((long long)EventHandle) : "memory");
    return rv == 0 ? NTSTATUS_SUCCESS : (NTSTATUS)0xC0000008;
}

__declspec(dllexport) NTSTATUS NtQueryEvent(HANDLE EventHandle, ULONG EventInformationClass, void* EventInformation,
                                            ULONG EventInformationLength, ULONG* ReturnLength)
{
    (void)EventHandle;
    (void)EventInformationClass;
    if (EventInformation == (void*)0 || EventInformationLength < 8)
        return NTSTATUS_INVALID_PARAMETER;
    unsigned char* out = (unsigned char*)EventInformation;
    for (unsigned i = 0; i < 8; ++i)
        out[i] = 0;
    if (ReturnLength != (ULONG*)0)
        *ReturnLength = 8;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtSignalAndWaitForSingleObject(HANDLE ObjectToSignal, HANDLE WaitableObject,
                                                              BOOL Alertable, void* Time)
{
    /* Best-effort: signal first object, then wait on second.
     * Atomicity not preserved (sub-GAP). */
    unsigned long long sig_handle = (unsigned long long)ObjectToSignal;
    long long sig_status = 0;
    if (sig_handle >= 0x200 && sig_handle < 0x208)
        __asm__ volatile("int $0x80"
                         : "=a"(sig_status)
                         : "a"((long long)27), "D"((long long)ObjectToSignal)
                         : "memory");
    else if (sig_handle >= 0x300 && sig_handle < 0x308)
        __asm__ volatile("int $0x80"
                         : "=a"(sig_status)
                         : "a"((long long)31), "D"((long long)ObjectToSignal)
                         : "memory");
    if (sig_status != 0)
        return (NTSTATUS)0xC0000008;
    return NtWaitForSingleObject(WaitableObject, Alertable, (const long long*)Time);
}

/* NtQueueApcThread / NtQueueApcThreadEx — route user-mode APCs
 * through the kernel-resident queue (SYS_QUEUE_USER_APC = 187).
 * The native Win32 contract: ApcRoutine is invoked as
 *   ApcRoutine(NormalContext, SystemArgument1, SystemArgument2)
 * when the target enters an alertable wait. The kernel queue
 * carries a single ulData payload; we pack NormalContext as that
 * payload and ignore SystemArgument1/2 in v0 — the same SDK
 * shape kernel32!QueueUserAPC uses (single ulData). PE callers
 * that need the three-arg shape can fall back to a userland
 * shim that recovers SA1/SA2 from a side table.
 *
 * Returns STATUS_SUCCESS on success, STATUS_NOT_IMPLEMENTED
 * on cross-process / unknown-tid (kernel returns -1). The
 * thread handle is opaque; v0 takes the low 32 bits as the
 * target tid, the same convention kernel32!QueueUserAPC uses.
 */
__declspec(dllexport) NTSTATUS NtQueueApcThread(HANDLE ThreadHandle, void* ApcRoutine, void* NormalContext,
                                                void* SystemArgument1, void* SystemArgument2)
{
    (void)SystemArgument1;
    (void)SystemArgument2;
    if (ApcRoutine == (void*)0)
        return (NTSTATUS)0xC000000DL; /* STATUS_INVALID_PARAMETER */
    long long target_tid = (long long)(unsigned long long)ThreadHandle;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)187), /* SYS_QUEUE_USER_APC */
                       "D"(target_tid), "S"((long long)ApcRoutine), "d"((long long)NormalContext)
                     : "memory");
    if (rv != 0)
        return (NTSTATUS)0xC0000002L; /* STATUS_NOT_IMPLEMENTED — caller falls back */
    return (NTSTATUS)0;
}

__declspec(dllexport) NTSTATUS NtQueueApcThreadEx(HANDLE ThreadHandle, HANDLE ReserveHandle, void* ApcRoutine,
                                                  void* NormalContext, void* SystemArgument1, void* SystemArgument2)
{
    (void)ReserveHandle;
    return NtQueueApcThread(ThreadHandle, ApcRoutine, NormalContext, SystemArgument1, SystemArgument2);
}

__declspec(dllexport) NTSTATUS NtAlertThread(HANDLE ThreadHandle)
{
    (void)ThreadHandle;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtCallbackReturn(void* OutputBuffer, ULONG OutputLength, NTSTATUS Status)
{
    (void)OutputBuffer;
    (void)OutputLength;
    return Status;
}

__declspec(dllexport) NTSTATUS NtAdjustGroupsToken(HANDLE TokenHandle, BOOL ResetToDefault, void* NewState,
                                                   ULONG BufferLength, void* PreviousState, ULONG* ReturnLength)
{
    (void)TokenHandle;
    (void)ResetToDefault;
    (void)NewState;
    (void)BufferLength;
    (void)PreviousState;
    if (ReturnLength != (ULONG*)0)
        *ReturnLength = 0;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtSetInformationToken(HANDLE TokenHandle, ULONG TokenInformationClass,
                                                     void* TokenInformation, ULONG TokenInformationLength)
{
    (void)TokenHandle;
    (void)TokenInformationClass;
    (void)TokenInformation;
    (void)TokenInformationLength;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtCheckTokenMembership(HANDLE TokenHandle, void* SidToCheck, BOOL* IsMember)
{
    (void)TokenHandle;
    (void)SidToCheck;
    if (IsMember != (BOOL*)0)
        *IsMember = 1;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtPrivilegeObjectAuditAlarm(void* SubsystemName, void* HandleId, HANDLE ClientToken,
                                                           ULONG DesiredAccess, void* Privileges, BOOL AccessGranted)
{
    (void)SubsystemName;
    (void)HandleId;
    (void)ClientToken;
    (void)DesiredAccess;
    (void)Privileges;
    (void)AccessGranted;
    return NTSTATUS_SUCCESS;
}

/* ------------------------------------------------------------------
 * NT timer family — explicit NotImpl facades.
 *
 * Win32 NT timers are kernel-coordinated dispatcher objects.
 * v0 has no APC dispatch + no kernel timer queue exposed via
 * the timer-handle ABI. Callers wanting time-based wakes use
 * Sleep / NtDelayExecution (already implemented).
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtCreateTimer(HANDLE* TimerHandle, ULONG DesiredAccess, void* ObjectAttributes,
                                             ULONG TimerType)
{
    (void)TimerHandle;
    (void)DesiredAccess;
    (void)ObjectAttributes;
    (void)TimerType;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtSetTimer(HANDLE TimerHandle, void* DueTime, void* TimerApcRoutine, void* TimerContext,
                                          BOOL ResumeTimer, ULONG Period, BOOL* PreviousState)
{
    (void)TimerHandle;
    (void)DueTime;
    (void)TimerApcRoutine;
    (void)TimerContext;
    (void)ResumeTimer;
    (void)Period;
    (void)PreviousState;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtCancelTimer(HANDLE TimerHandle, BOOL* CurrentState)
{
    (void)TimerHandle;
    if (CurrentState != (BOOL*)0)
        *CurrentState = 0;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtOpenTimer(HANDLE* TimerHandle, ULONG DesiredAccess, void* ObjectAttributes)
{
    (void)TimerHandle;
    (void)DesiredAccess;
    (void)ObjectAttributes;
    return (NTSTATUS)0xC0000034;
}

/* ------------------------------------------------------------------
 * NT IO-completion family — explicit NotImpl facades.
 * Used by Win32 IOCP server frameworks. v0 has no async-I/O
 * completion queue.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtCreateIoCompletion(HANDLE* IoCompletionHandle, ULONG DesiredAccess,
                                                    void* ObjectAttributes, ULONG NumberOfConcurrentThreads)
{
    (void)DesiredAccess;
    (void)ObjectAttributes;
    (void)NumberOfConcurrentThreads;
    if (IoCompletionHandle == (HANDLE*)0)
        return NTSTATUS_INVALID_PARAMETER;
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)159) : "memory"); /* SYS_IOCP_CREATE */
    if (rv < 0)
        return (NTSTATUS)0xC0000002;
    *IoCompletionHandle = (HANDLE)rv;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtOpenIoCompletion(HANDLE* IoCompletionHandle, ULONG DesiredAccess,
                                                  void* ObjectAttributes)
{
    (void)IoCompletionHandle;
    (void)DesiredAccess;
    (void)ObjectAttributes;
    /* No named-object table — open-by-name returns NAME_NOT_FOUND. */
    return (NTSTATUS)0xC0000034;
}

__declspec(dllexport) NTSTATUS NtSetIoCompletion(HANDLE IoCompletionHandle, void* CompletionKey, void* CompletionValue,
                                                 NTSTATUS CompletionStatus, ULONG NumberOfBytesTransferred)
{
    long long rv;
    __asm__ volatile("mov %4, %%r10\n\t"
                     "mov %5, %%r8\n\t"
                     "int $0x80"
                     : "=a"(rv)
                     : "a"((long long)160), /* SYS_IOCP_SET */
                       "D"((long long)IoCompletionHandle), "S"((long long)CompletionKey),
                       "d"((long long)CompletionValue), "r"((long long)CompletionStatus),
                       "r"((long long)NumberOfBytesTransferred)
                     : "r10", "r8", "memory");
    if (rv < 0)
        return (NTSTATUS)0xC0000008; /* INVALID_HANDLE */
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtRemoveIoCompletion(HANDLE IoCompletionHandle, void* CompletionKey,
                                                    void* CompletionValue, void* IoStatusBlock, void* Timeout)
{
    /* Timeout is a pointer to a LARGE_INTEGER (NT 100ns ticks).
     * v0 collapses to "infinite if non-null, immediate if null".
     * Sub-GAP: real timeout integration not wired. */
    const unsigned long long timeout_ms = (Timeout != (void*)0) ? (unsigned long long)-1 : 0;
    long long rv;
    __asm__ volatile("mov %4, %%r10\n\t"
                     "mov %5, %%r8\n\t"
                     "int $0x80"
                     : "=a"(rv)
                     : "a"((long long)161), /* SYS_IOCP_REMOVE */
                       "D"((long long)IoCompletionHandle), "S"((long long)CompletionKey),
                       "d"((long long)CompletionValue), "r"((long long)IoStatusBlock), "r"(timeout_ms)
                     : "r10", "r8", "memory");
    if (rv < 0)
        return (NTSTATUS)0xC0000008;
    if (rv == 0)
        return (NTSTATUS)0x00000102; /* STATUS_TIMEOUT */
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtRemoveIoCompletionEx(HANDLE IoCompletionHandle, void* IoCompletionInformation,
                                                      ULONG Count, ULONG* NumEntriesRemoved, void* Timeout,
                                                      BOOL Alertable)
{
    (void)Alertable;
    if (NumEntriesRemoved != (ULONG*)0)
        *NumEntriesRemoved = 0;
    if (Count == 0 || IoCompletionInformation == (void*)0)
        return NTSTATUS_INVALID_PARAMETER;
    /* Loop NtRemoveIoCompletion to fill the caller's array. Each
     * record is 32 bytes (key + apcctx + IO_STATUS_BLOCK). The
     * shape matches OVERLAPPED_ENTRY {lpCompletionKey, lpOverlapped,
     * Internal, dwNumberOfBytesTransferred}. */
    unsigned char* out = (unsigned char*)IoCompletionInformation;
    unsigned filled = 0;
    for (unsigned i = 0; i < Count; ++i)
    {
        unsigned long long iosb[2];
        unsigned long long key = 0;
        unsigned long long apc = 0;
        const unsigned long long timeout_ms = (i == 0 && Timeout != (void*)0) ? (unsigned long long)-1 : 0;
        long long rv;
        __asm__ volatile("mov %4, %%r10\n\t"
                         "mov %5, %%r8\n\t"
                         "int $0x80"
                         : "=a"(rv)
                         : "a"((long long)161), "D"((long long)IoCompletionHandle), "S"((long long)&key),
                           "d"((long long)&apc), "r"((long long)iosb), "r"(timeout_ms)
                         : "r10", "r8", "memory");
        if (rv != 1)
            break;
        unsigned base = i * 32;
        for (unsigned j = 0; j < 8; ++j)
        {
            out[base + j] = (unsigned char)((key >> (j * 8)) & 0xFF);
            out[base + 8 + j] = (unsigned char)((apc >> (j * 8)) & 0xFF);
            out[base + 16 + j] = (unsigned char)((iosb[0] >> (j * 8)) & 0xFF);
            out[base + 24 + j] = (unsigned char)((iosb[1] >> (j * 8)) & 0xFF);
        }
        ++filled;
    }
    if (NumEntriesRemoved != (ULONG*)0)
        *NumEntriesRemoved = filled;
    return filled > 0 ? NTSTATUS_SUCCESS : (NTSTATUS)0x00000102;
}

/* ------------------------------------------------------------------
 * NT transaction (KTM) family — explicit NotImpl facades.
 * Kernel Transaction Manager surface. v0 has no KTM.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtCreateTransaction(HANDLE* TransactionHandle, ULONG DesiredAccess,
                                                   void* ObjectAttributes, void* Uow, HANDLE TmHandle,
                                                   ULONG CreateOptions, ULONG IsolationLevel, ULONG IsolationFlags,
                                                   void* Timeout, void* Description)
{
    (void)TransactionHandle;
    (void)DesiredAccess;
    (void)ObjectAttributes;
    (void)Uow;
    (void)TmHandle;
    (void)CreateOptions;
    (void)IsolationLevel;
    (void)IsolationFlags;
    (void)Timeout;
    (void)Description;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtCommitTransaction(HANDLE TransactionHandle, BOOL Wait)
{
    (void)TransactionHandle;
    (void)Wait;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtRollbackTransaction(HANDLE TransactionHandle, BOOL Wait)
{
    (void)TransactionHandle;
    (void)Wait;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtOpenTransaction(HANDLE* TransactionHandle, ULONG DesiredAccess, void* ObjectAttributes,
                                                 void* Uow, HANDLE TmHandle)
{
    (void)TransactionHandle;
    (void)DesiredAccess;
    (void)ObjectAttributes;
    (void)Uow;
    (void)TmHandle;
    return (NTSTATUS)0xC0000034;
}

/* ------------------------------------------------------------------
 * NT misc — NtRaiseException, NtContinue (already exists),
 * NtYieldExecution, NtFlushInstructionCache, NtTestAlert.
 * Most are tractable as success no-ops or simple forwards.
 * ------------------------------------------------------------------ */
/* NtYieldExecution lives at line ~99 (forwards to SYS_YIELD). */

__declspec(dllexport) NTSTATUS NtFlushInstructionCache(HANDLE ProcessHandle, void* BaseAddress, SIZE_T Length)
{
    (void)ProcessHandle;
    (void)BaseAddress;
    (void)Length;
    /* x86_64 has coherent I-cache vs D-cache; flush is a no-op. */
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtTestAlert(void)
{
    /* No APC / alert engine — always returns NO_ALERT (a success
     * status meaning "nothing pending"). */
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtRaiseException(void* ExceptionRecord, void* ContextRecord, BOOL HandleException)
{
    (void)ExceptionRecord;
    (void)ContextRecord;
    (void)HandleException;
    /* No SEH dispatch in v0; the right answer is "we couldn't
     * raise it" — Windows uses STATUS_UNHANDLED_EXCEPTION
     * (0xC0000144) on the unhandled path. */
    return (NTSTATUS)0xC0000144;
}

/* ------------------------------------------------------------------
 * NT process-creation thunks — explicit NotImpl facades.
 *
 * v0 has no Win32 PE process spawn pipeline. Process creation
 * happens at boot via the loader; runtime PE spawn via Win32 API
 * needs a section-from-file path that doesn't exist yet (sub-GAP
 * in §11.8). NtCreateUserProcess (the modern Vista+ API) gets
 * the same treatment.
 *
 * NtSuspendProcess / NtResumeProcess work at the per-process
 * granularity by walking every thread; v0 returns NotImpl
 * because that walk needs the §11.7-style suspend infrastructure
 * extended to whole-process scope. Per-thread NtSuspendThread is
 * the working alternative.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtCreateProcess(HANDLE* ProcessHandle, ULONG DesiredAccess, void* ObjectAttributes,
                                               HANDLE ParentProcess, BOOL InheritObjectTable, HANDLE SectionHandle,
                                               HANDLE DebugPort, HANDLE ExceptionPort)
{
    (void)ProcessHandle;
    (void)DesiredAccess;
    (void)ObjectAttributes;
    (void)ParentProcess;
    (void)InheritObjectTable;
    (void)SectionHandle;
    (void)DebugPort;
    (void)ExceptionPort;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS ZwCreateProcess(HANDLE* ProcessHandle, ULONG DesiredAccess, void* ObjectAttributes,
                                               HANDLE ParentProcess, BOOL InheritObjectTable, HANDLE SectionHandle,
                                               HANDLE DebugPort, HANDLE ExceptionPort)
{
    return NtCreateProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, InheritObjectTable,
                           SectionHandle, DebugPort, ExceptionPort);
}

__declspec(dllexport) NTSTATUS NtCreateProcessEx(HANDLE* ProcessHandle, ULONG DesiredAccess, void* ObjectAttributes,
                                                 HANDLE ParentProcess, ULONG Flags, HANDLE SectionHandle,
                                                 HANDLE DebugPort, HANDLE ExceptionPort, ULONG JobMemberLevel)
{
    (void)ProcessHandle;
    (void)DesiredAccess;
    (void)ObjectAttributes;
    (void)ParentProcess;
    (void)Flags;
    (void)SectionHandle;
    (void)DebugPort;
    (void)ExceptionPort;
    (void)JobMemberLevel;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS ZwCreateProcessEx(HANDLE* ProcessHandle, ULONG DesiredAccess, void* ObjectAttributes,
                                                 HANDLE ParentProcess, ULONG Flags, HANDLE SectionHandle,
                                                 HANDLE DebugPort, HANDLE ExceptionPort, ULONG JobMemberLevel)
{
    return NtCreateProcessEx(ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, Flags, SectionHandle,
                             DebugPort, ExceptionPort, JobMemberLevel);
}

/* RTL_USER_PROCESS_PARAMETERS — Windows process-parameters block.
 * Only the fields v0 actually consumes are named; the rest is
 * skipped via byte-offset reads so we don't need the full layout
 * here. ImagePathName is the path to the .exe we're spawning;
 * everything else (CommandLine, environment, current directory,
 * console handles) is accepted but unused — sub-GAP.
 *
 * UNICODE_STRING layout on x64:
 *   +0x00  Length        (USHORT, byte count, NOT including NUL)
 *   +0x02  MaximumLength (USHORT)
 *   +0x04  Padding
 *   +0x08  Buffer        (PWSTR — 8 bytes)
 *
 * Inside RTL_USER_PROCESS_PARAMETERS, ImagePathName lives at +0x60.
 * Independently verified against ntdll.dll on Windows 10 / 11 25H2.
 */
#define NTDLL_PP_OFFSET_IMAGE_PATH 0x60

/* Translate a Windows-shaped image path (UNICODE_STRING.Buffer +
 * Length-in-bytes) into the kernel's "/disk/N/..." form. Mirrors
 * the kernel32 NormalizePathW translator inline so ntdll stays
 * freestanding (kernel32 isn't guaranteed loaded yet at the time
 * a PE may issue NtCreateUserProcess).
 *
 * Strips up to one "\??\" or "\\?\" extended-length prefix, maps
 * a drive letter ("C:") to "/disk/N" (C → /disk/0, D → /disk/1,
 * ...), and converts "\" to "/" for the rest. Non-ASCII codepoints
 * become '?'. Returns 1 on success, 0 on capacity overrun / no
 * recognisable shape. */
static int ntdll_translate_image_path(const wchar_t16* buf, unsigned chars, char* out, unsigned cap)
{
    if (out == (char*)0 || cap == 0)
        return 0;
    out[0] = '\0';
    if (buf == (wchar_t16*)0 || chars == 0)
        return 0;

    unsigned ci = 0;
    /* "\??\" or "\\?\" extended-length prefix — strip once. */
    if (chars >= 4)
    {
        unsigned short a = buf[0];
        unsigned short b = buf[1];
        unsigned short c = buf[2];
        unsigned short d = buf[3];
        if ((a == L'\\' || a == L'/') && (b == L'\\' || b == L'?' || b == L'/') && (c == L'?' || c == L'\\') &&
            (d == L'\\' || d == L'/'))
        {
            ci = 4;
        }
    }

    unsigned oi = 0;
    /* Drive-letter prefix? */
    if (ci + 1 < chars)
    {
        unsigned short letter = buf[ci];
        unsigned short colon = buf[ci + 1];
        if (((letter >= L'A' && letter <= L'Z') || (letter >= L'a' && letter <= L'z')) && colon == L':')
        {
            char upper = (letter >= L'a' && letter <= L'z') ? (char)(letter - L'a' + L'A') : (char)letter;
            int idx = (upper < 'C') ? 0 : (upper - 'C');
            const char* prefix = "/disk/";
            for (unsigned p = 0; prefix[p] != '\0'; ++p)
            {
                if (oi + 1 >= cap)
                    return 0;
                out[oi++] = prefix[p];
            }
            if (idx >= 10)
            {
                if (oi + 1 >= cap)
                    return 0;
                out[oi++] = (char)('0' + (idx / 10));
            }
            if (oi + 1 >= cap)
                return 0;
            out[oi++] = (char)('0' + (idx % 10));
            ci += 2;
        }
    }

    while (ci < chars)
    {
        unsigned short w = buf[ci++];
        char c;
        if (w == L'\\')
            c = '/';
        else if (w <= 0x7F)
            c = (char)w;
        else
            c = '?';
        if (oi + 1 >= cap)
            return 0;
        out[oi++] = c;
    }
    out[oi] = '\0';
    return 1;
}

/* NtCreateUserProcess — backed by SYS_PROCESS_SPAWN = 158.
 *
 * Pulls ImagePathName out of RTL_USER_PROCESS_PARAMETERS, translates
 * the Windows-shaped path to the kernel's "/disk/N/..." form, and
 * issues SYS_PROCESS_SPAWN. Writes the new pid (cast to HANDLE) to
 * *ProcessHandle. ThreadHandle is set to -1 — the new thread's tid
 * is the same as its pid in v0 (single-thread-per-process at spawn),
 * so callers wanting a real thread handle can NtOpenThread the pid.
 *
 * Sub-GAPs (accepted but unused): CommandLine (kernel doesn't pass
 * arguments yet); ProcessFlags / ThreadFlags (no PROCESS_CREATE_*
 * semantics); CreateInfo / AttributeList (PS_ATTRIBUTE list is
 * Windows-internal); object attributes (no NT object-namespace yet).
 */
__declspec(dllexport) NTSTATUS NtCreateUserProcess(HANDLE* ProcessHandle, HANDLE* ThreadHandle,
                                                   ULONG ProcessDesiredAccess, ULONG ThreadDesiredAccess,
                                                   void* ProcessObjectAttributes, void* ThreadObjectAttributes,
                                                   ULONG ProcessFlags, ULONG ThreadFlags, void* ProcessParameters,
                                                   void* CreateInfo, void* AttributeList)
{
    (void)ProcessDesiredAccess;
    (void)ThreadDesiredAccess;
    (void)ProcessObjectAttributes;
    (void)ThreadObjectAttributes;
    (void)ProcessFlags;
    (void)ThreadFlags;
    (void)CreateInfo;
    (void)AttributeList;
    if (ProcessHandle == (HANDLE*)0 || ThreadHandle == (HANDLE*)0 || ProcessParameters == (void*)0)
        return NTSTATUS_INVALID_PARAMETER;

    const unsigned char* pp = (const unsigned char*)ProcessParameters;
    const unsigned char* image = pp + NTDLL_PP_OFFSET_IMAGE_PATH;
    const unsigned short length_bytes = *(const unsigned short*)(image + 0);
    const wchar_t16* buffer = *(const wchar_t16* const*)(image + 8);
    if (buffer == (wchar_t16*)0 || length_bytes == 0)
        return NTSTATUS_INVALID_PARAMETER;

    char path[128];
    const unsigned chars = (unsigned)(length_bytes / 2);
    if (!ntdll_translate_image_path(buffer, chars, path, sizeof(path)))
        return NTSTATUS_INVALID_PARAMETER;

    long long pid;
    /* SYS_PROCESS_SPAWN = 158: rdi = const char* path, rsi = u64 flags. */
    __asm__ volatile("int $0x80" : "=a"(pid) : "a"((long long)158), "D"((long long)path), "S"((long long)0) : "memory");
    if (pid < 0)
        return (NTSTATUS)0xC0000022; /* STATUS_ACCESS_DENIED — most likely cap miss */

    *ProcessHandle = (HANDLE)pid;
    *ThreadHandle = (HANDLE)-1; /* sub-GAP: caller can NtOpenThread(pid) for a real handle */
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS ZwCreateUserProcess(HANDLE* ProcessHandle, HANDLE* ThreadHandle,
                                                   ULONG ProcessDesiredAccess, ULONG ThreadDesiredAccess,
                                                   void* ProcessObjectAttributes, void* ThreadObjectAttributes,
                                                   ULONG ProcessFlags, ULONG ThreadFlags, void* ProcessParameters,
                                                   void* CreateInfo, void* AttributeList)
{
    return NtCreateUserProcess(ProcessHandle, ThreadHandle, ProcessDesiredAccess, ThreadDesiredAccess,
                               ProcessObjectAttributes, ThreadObjectAttributes, ProcessFlags, ThreadFlags,
                               ProcessParameters, CreateInfo, AttributeList);
}

__declspec(dllexport) NTSTATUS NtSuspendProcess(HANDLE ProcessHandle)
{
    (void)ProcessHandle;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtResumeProcess(HANDLE ProcessHandle)
{
    (void)ProcessHandle;
    return (NTSTATUS)0xC0000002;
}

/* ------------------------------------------------------------------
 * NT access-check / privilege / impersonation — explicit
 * NotImpl / accept-pass facades. v0 cap-gates on kCapDebug etc.
 * at the kernel; the Win32 access-check surface is a façade.
 * NtAccessCheck returns granted=true so callers don't loop on
 * a stuck "permission denied"; the real gating is kernel-side.
 * NtRevertToSelf is success-no-op (no impersonation token to
 * revert from).
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtAccessCheck(void* SecurityDescriptor, HANDLE ClientToken, ULONG DesiredAccess,
                                             void* GenericMapping, void* PrivilegeSet, ULONG* PrivilegeSetLength,
                                             ULONG* GrantedAccess, BOOL* AccessStatus)
{
    (void)SecurityDescriptor;
    (void)ClientToken;
    (void)GenericMapping;
    (void)PrivilegeSet;
    (void)PrivilegeSetLength;
    if (GrantedAccess != (ULONG*)0)
        *GrantedAccess = DesiredAccess;
    if (AccessStatus != (BOOL*)0)
        *AccessStatus = 1;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtPrivilegeCheck(HANDLE ClientToken, void* RequiredPrivileges, BOOL* Result)
{
    (void)ClientToken;
    (void)RequiredPrivileges;
    if (Result != (BOOL*)0)
        *Result = 1;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtImpersonateThread(HANDLE ServerThreadHandle, HANDLE ClientThreadHandle,
                                                   void* SecurityQos)
{
    (void)ServerThreadHandle;
    (void)ClientThreadHandle;
    (void)SecurityQos;
    /* No impersonation engine in v0. Returning success keeps
     * RPC-shaped probes happy; the actual identity of every
     * task is the same single-user model. */
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtImpersonateAnonymousToken(HANDLE ThreadHandle)
{
    (void)ThreadHandle;
    return NTSTATUS_SUCCESS;
}

/* RtlSetImpersonationToken — referenced by some Win32 callers
 * for thread-token swap; same single-user façade. */
__declspec(dllexport) NTSTATUS NtSetInformationThread(HANDLE ThreadHandle, ULONG ThreadInformationClass,
                                                      void* ThreadInformation, ULONG ThreadInformationLength)
{
    (void)ThreadHandle;
    (void)ThreadInformationClass;
    (void)ThreadInformation;
    (void)ThreadInformationLength;
    /* Most callers set ThreadHideFromDebugger or ThreadAffinity-
     * Mask. v0 has no debugger and a single CPU; both are no-op
     * success. */
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtQueryInformationThread(HANDLE ThreadHandle, ULONG ThreadInformationClass,
                                                        void* ThreadInformation, ULONG ThreadInformationLength,
                                                        ULONG* ReturnLength)
{
    (void)ThreadHandle;
    (void)ThreadInformation;
    (void)ThreadInformationLength;
    if (ReturnLength != (ULONG*)0)
        *ReturnLength = 0;
    /* ThreadBasicInformation (0): the canonical first probe.
     * Returns a 48-byte struct; v0 emits zeros. Callers that
     * need real values land in §11.7's Get/SetContext path
     * instead, which IS implemented. */
    if (ThreadInformationClass == 0 && ThreadInformation != (void*)0 && ThreadInformationLength >= 48)
    {
        unsigned char* out = (unsigned char*)ThreadInformation;
        for (unsigned i = 0; i < 48; ++i)
            out[i] = 0;
        if (ReturnLength != (ULONG*)0)
            *ReturnLength = 48;
        return NTSTATUS_SUCCESS;
    }
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS ZwSetInformationThread(HANDLE ThreadHandle, ULONG ThreadInformationClass,
                                                      void* ThreadInformation, ULONG ThreadInformationLength)
{
    return NtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
}

__declspec(dllexport) NTSTATUS ZwQueryInformationThread(HANDLE ThreadHandle, ULONG ThreadInformationClass,
                                                        void* ThreadInformation, ULONG ThreadInformationLength,
                                                        ULONG* ReturnLength)
{
    return NtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength,
                                    ReturnLength);
}

/* NtSetInformationProcess — write counterpart to NtQueryInformationProcess.
 * Most callers set ProcessBasicInformation (write-back of PEB)
 * or ProcessIoCounters; both are no-op success. v0 doesn't gate
 * on any of these for actual behaviour. */
__declspec(dllexport) NTSTATUS NtSetInformationProcess(HANDLE ProcessHandle, ULONG ProcessInformationClass,
                                                       void* ProcessInformation, ULONG ProcessInformationLength)
{
    (void)ProcessHandle;
    (void)ProcessInformationClass;
    (void)ProcessInformation;
    (void)ProcessInformationLength;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS ZwSetInformationProcess(HANDLE ProcessHandle, ULONG ProcessInformationClass,
                                                       void* ProcessInformation, ULONG ProcessInformationLength)
{
    return NtSetInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation,
                                   ProcessInformationLength);
}

/* ------------------------------------------------------------------
 * NT keyed-event surface — explicit NotImpl. KEs are a
 * Vista-era kernel-coordinated wait primitive used internally by
 * RtlAcquireSRWLockShared etc. v0's mutex/event surface covers
 * the same use cases through SYS_MUTEX_* / SYS_EVENT_*.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtCreateKeyedEvent(HANDLE* KeyedEventHandle, ULONG DesiredAccess, void* ObjectAttributes,
                                                  ULONG Flags)
{
    (void)KeyedEventHandle;
    (void)DesiredAccess;
    (void)ObjectAttributes;
    (void)Flags;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtOpenKeyedEvent(HANDLE* KeyedEventHandle, ULONG DesiredAccess, void* ObjectAttributes)
{
    (void)KeyedEventHandle;
    (void)DesiredAccess;
    (void)ObjectAttributes;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtWaitForKeyedEvent(HANDLE KeyedEventHandle, void* Key, BOOL Alertable, void* Timeout)
{
    (void)KeyedEventHandle;
    (void)Key;
    (void)Alertable;
    (void)Timeout;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtReleaseKeyedEvent(HANDLE KeyedEventHandle, void* Key, BOOL Alertable, void* Timeout)
{
    (void)KeyedEventHandle;
    (void)Key;
    (void)Alertable;
    (void)Timeout;
    return (NTSTATUS)0xC0000002;
}

/* ------------------------------------------------------------------
 * NT debug surface — userland-only NotImpl stubs.
 *
 * v0 has no debug-event engine (no DBG_PRINTEXCEPTION_C dispatch,
 * no debug-port queue, no Wait-for-debug-event blocking). The
 * Win32 cap-gating model — kCapDebug — is what gates cross-
 * process inspection (via NtOpenProcess / NtOpenThread / VM read
 * + write / Get/SetContext). The classic NtDebug* family that
 * a Windows debugger uses is a separate rope; v0 doesn't pull
 * it. These stubs return STATUS_NOT_IMPLEMENTED explicitly so
 * callers see a clean "no debugger here" instead of generic
 * kSysNtNotImpl noise.
 *
 * NB: this is a FACADE per the subsystem-isolation rule. The
 * Win32 NtDebug* surface does not gate DuetOS-level debug
 * authority — that's still kCapDebug, enforced kernel-side on
 * SYS_PROCESS_VM_READ / SYS_THREAD_GET_CONTEXT / etc.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtCreateDebugObject(HANDLE* DebugObjectHandle, ULONG DesiredAccess,
                                                   void* ObjectAttributes, ULONG Flags)
{
    (void)DebugObjectHandle;
    (void)DesiredAccess;
    (void)ObjectAttributes;
    (void)Flags;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS ZwCreateDebugObject(HANDLE* DebugObjectHandle, ULONG DesiredAccess,
                                                   void* ObjectAttributes, ULONG Flags)
{
    return NtCreateDebugObject(DebugObjectHandle, DesiredAccess, ObjectAttributes, Flags);
}

__declspec(dllexport) NTSTATUS NtDebugActiveProcess(HANDLE ProcessHandle, HANDLE DebugObjectHandle)
{
    (void)ProcessHandle;
    (void)DebugObjectHandle;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS ZwDebugActiveProcess(HANDLE ProcessHandle, HANDLE DebugObjectHandle)
{
    return NtDebugActiveProcess(ProcessHandle, DebugObjectHandle);
}

__declspec(dllexport) NTSTATUS NtDebugContinue(HANDLE DebugObjectHandle, void* ClientId, ULONG ContinueStatus)
{
    (void)DebugObjectHandle;
    (void)ClientId;
    (void)ContinueStatus;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS ZwDebugContinue(HANDLE DebugObjectHandle, void* ClientId, ULONG ContinueStatus)
{
    return NtDebugContinue(DebugObjectHandle, ClientId, ContinueStatus);
}

__declspec(dllexport) NTSTATUS NtWaitForDebugEvent(HANDLE DebugObjectHandle, BOOL Alertable, void* Timeout,
                                                   void* WaitStateChange)
{
    (void)DebugObjectHandle;
    (void)Alertable;
    (void)Timeout;
    (void)WaitStateChange;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS ZwWaitForDebugEvent(HANDLE DebugObjectHandle, BOOL Alertable, void* Timeout,
                                                   void* WaitStateChange)
{
    return NtWaitForDebugEvent(DebugObjectHandle, Alertable, Timeout, WaitStateChange);
}

__declspec(dllexport) NTSTATUS NtRemoveProcessDebug(HANDLE ProcessHandle, HANDLE DebugObjectHandle)
{
    (void)ProcessHandle;
    (void)DebugObjectHandle;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS ZwRemoveProcessDebug(HANDLE ProcessHandle, HANDLE DebugObjectHandle)
{
    return NtRemoveProcessDebug(ProcessHandle, DebugObjectHandle);
}

__declspec(dllexport) NTSTATUS NtSetInformationDebugObject(HANDLE DebugObjectHandle, ULONG DebugObjectInformationClass,
                                                           void* DebugInformation, ULONG DebugInformationLength,
                                                           ULONG* ReturnLength)
{
    (void)DebugObjectHandle;
    (void)DebugObjectInformationClass;
    (void)DebugInformation;
    (void)DebugInformationLength;
    (void)ReturnLength;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS ZwSetInformationDebugObject(HANDLE DebugObjectHandle, ULONG DebugObjectInformationClass,
                                                           void* DebugInformation, ULONG DebugInformationLength,
                                                           ULONG* ReturnLength)
{
    return NtSetInformationDebugObject(DebugObjectHandle, DebugObjectInformationClass, DebugInformation,
                                       DebugInformationLength, ReturnLength);
}

__declspec(dllexport) NTSTATUS NtQueryDebugFilterState(ULONG ComponentId, ULONG Level)
{
    (void)ComponentId;
    (void)Level;
    /* TRUE = component logging enabled. v0 returns FALSE
     * uniformly — no debug logging filter. */
    return 0;
}

/* ------------------------------------------------------------------
 * NT job-object surface — userland-only NotImpl stubs.
 *
 * Job objects are a Win32 mechanism for grouping processes for
 * resource limits + bulk termination. v0 has no job engine; the
 * kernel cap-set already handles the per-process limit cases we
 * care about. These stubs return STATUS_NOT_IMPLEMENTED so a
 * sandboxed PE checking for a job assignment gets a clean
 * answer.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtCreateJobObject(HANDLE* JobHandle, ULONG DesiredAccess, void* ObjectAttributes)
{
    (void)DesiredAccess;
    (void)ObjectAttributes;
    if (JobHandle == (HANDLE*)0)
        return NTSTATUS_INVALID_PARAMETER;
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)163) : "memory"); /* SYS_JOB_CREATE */
    if (rv < 0)
        return (NTSTATUS)0xC0000002;
    *JobHandle = (HANDLE)rv;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS ZwCreateJobObject(HANDLE* JobHandle, ULONG DesiredAccess, void* ObjectAttributes)
{
    return NtCreateJobObject(JobHandle, DesiredAccess, ObjectAttributes);
}

__declspec(dllexport) NTSTATUS NtAssignProcessToJobObject(HANDLE JobHandle, HANDLE ProcessHandle)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)164), /* SYS_JOB_ASSIGN */
                       "D"((long long)JobHandle), "S"((long long)ProcessHandle)
                     : "memory");
    if (rv < 0)
        return (NTSTATUS)0xC0000022; /* STATUS_ACCESS_DENIED */
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS ZwAssignProcessToJobObject(HANDLE JobHandle, HANDLE ProcessHandle)
{
    return NtAssignProcessToJobObject(JobHandle, ProcessHandle);
}

__declspec(dllexport) NTSTATUS NtIsProcessInJob(HANDLE ProcessHandle, HANDLE JobHandle)
{
    /* Returns STATUS_PROCESS_IN_JOB (1) or STATUS_PROCESS_NOT_IN_JOB (0). */
    unsigned int out = 0;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)165), /* SYS_JOB_IS_IN */
                       "D"((long long)JobHandle), "S"((long long)ProcessHandle), "d"((long long)&out)
                     : "memory");
    if (rv < 0)
        return (NTSTATUS)0xC0000008;
    return (NTSTATUS)(out ? 0x00000001 : 0x00000000);
}

__declspec(dllexport) NTSTATUS NtTerminateJobObject(HANDLE JobHandle, NTSTATUS ExitStatus)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)166), /* SYS_JOB_TERMINATE */
                       "D"((long long)JobHandle), "S"((long long)ExitStatus)
                     : "memory");
    if (rv < 0)
        return (NTSTATUS)0xC0000008;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS ZwTerminateJobObject(HANDLE JobHandle, NTSTATUS ExitStatus)
{
    return NtTerminateJobObject(JobHandle, ExitStatus);
}

__declspec(dllexport) NTSTATUS NtQueryInformationJobObject(HANDLE JobHandle, ULONG JobObjectInformationClass,
                                                           void* JobObjectInformation, ULONG JobObjectInformationLength,
                                                           ULONG* ReturnLength)
{
    long long rv;
    __asm__ volatile("mov %4, %%r10\n\t"
                     "int $0x80"
                     : "=a"(rv)
                     : "a"((long long)167), /* SYS_JOB_QUERY */
                       "D"((long long)JobHandle), "S"((long long)JobObjectInformationClass),
                       "d"((long long)JobObjectInformation), "r"((long long)JobObjectInformationLength)
                     : "r10", "memory");
    if (rv < 0)
        return (NTSTATUS)0xC0000004; /* STATUS_INFO_LENGTH_MISMATCH */
    if (ReturnLength != (ULONG*)0)
        *ReturnLength = (ULONG)rv;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS ZwQueryInformationJobObject(HANDLE JobHandle, ULONG JobObjectInformationClass,
                                                           void* JobObjectInformation, ULONG JobObjectInformationLength,
                                                           ULONG* ReturnLength)
{
    return NtQueryInformationJobObject(JobHandle, JobObjectInformationClass, JobObjectInformation,
                                       JobObjectInformationLength, ReturnLength);
}

__declspec(dllexport) NTSTATUS NtSetInformationJobObject(HANDLE JobHandle, ULONG JobObjectInformationClass,
                                                         void* JobObjectInformation, ULONG JobObjectInformationLength)
{
    (void)JobHandle;
    (void)JobObjectInformationClass;
    (void)JobObjectInformation;
    (void)JobObjectInformationLength;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS ZwSetInformationJobObject(HANDLE JobHandle, ULONG JobObjectInformationClass,
                                                         void* JobObjectInformation, ULONG JobObjectInformationLength)
{
    return NtSetInformationJobObject(JobHandle, JobObjectInformationClass, JobObjectInformation,
                                     JobObjectInformationLength);
}

/* NtTerminateJobObject / ZwTerminateJobObject / NtIsProcessInJob /
 * ZwIsProcessInJob now have real implementations earlier in this
 * file (backed by SYS_JOB_TERMINATE / SYS_JOB_IS_IN). The old
 * NotImpl stubs were removed; this comment is here so a grep for
 * the legacy stub returns the new spot. */

__declspec(dllexport) NTSTATUS ZwIsProcessInJob(HANDLE ProcessHandle, HANDLE JobHandle)
{
    return NtIsProcessInJob(ProcessHandle, JobHandle);
}

/* ------------------------------------------------------------------
 * Win32 token surface — userland-only static "system token".
 *
 * v0 has no auth model; every process runs with the same
 * effective identity. We expose a single-token handle range
 * (0xA00..0xA07 reserved; v0 returns 0xA00 unconditionally)
 * and answer NtQueryInformationToken with constant data
 * sufficient to keep malware-shape PEs probing the surface
 * happy:
 *
 *   - TokenUser (1)               -> S-1-5-21-1-1-1-1000
 *   - TokenIntegrityLevel (25)    -> S-1-16-12288 (High)
 *   - everything else             -> STATUS_NOT_IMPLEMENTED
 *
 * NtAdjustPrivilegesToken returns success no-op so callers
 * that try to enable SeDebugPrivilege get an "OK" — we have
 * no privilege model to actually grant or refuse.
 *
 * NtOpenProcessToken / NtOpenThreadToken always succeed and
 * hand back the same constant token handle. NtClose on this
 * handle range is a userland-only no-op (the static token is
 * never destroyed).
 * ------------------------------------------------------------------ */
#define DUETOS_TOKEN_HANDLE ((HANDLE)0xA00)

__declspec(dllexport) NTSTATUS NtOpenProcessToken(HANDLE ProcessHandle, ULONG DesiredAccess, HANDLE* TokenHandle)
{
    (void)ProcessHandle;
    (void)DesiredAccess;
    if (TokenHandle == (HANDLE*)0)
        return NTSTATUS_INVALID_PARAMETER;
    *TokenHandle = DUETOS_TOKEN_HANDLE;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS ZwOpenProcessToken(HANDLE ProcessHandle, ULONG DesiredAccess, HANDLE* TokenHandle)
{
    return NtOpenProcessToken(ProcessHandle, DesiredAccess, TokenHandle);
}

__declspec(dllexport) NTSTATUS NtOpenProcessTokenEx(HANDLE ProcessHandle, ULONG DesiredAccess, ULONG HandleAttributes,
                                                    HANDLE* TokenHandle)
{
    (void)HandleAttributes;
    return NtOpenProcessToken(ProcessHandle, DesiredAccess, TokenHandle);
}

__declspec(dllexport) NTSTATUS NtOpenThreadToken(HANDLE ThreadHandle, ULONG DesiredAccess, BOOL OpenAsSelf,
                                                 HANDLE* TokenHandle)
{
    (void)ThreadHandle;
    (void)DesiredAccess;
    (void)OpenAsSelf;
    if (TokenHandle == (HANDLE*)0)
        return NTSTATUS_INVALID_PARAMETER;
    /* No per-thread token impersonation in v0 — return the
     * same process-wide static token. */
    *TokenHandle = DUETOS_TOKEN_HANDLE;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS ZwOpenThreadToken(HANDLE ThreadHandle, ULONG DesiredAccess, BOOL OpenAsSelf,
                                                 HANDLE* TokenHandle)
{
    return NtOpenThreadToken(ThreadHandle, DesiredAccess, OpenAsSelf, TokenHandle);
}

__declspec(dllexport) NTSTATUS NtOpenThreadTokenEx(HANDLE ThreadHandle, ULONG DesiredAccess, BOOL OpenAsSelf,
                                                   ULONG HandleAttributes, HANDLE* TokenHandle)
{
    (void)HandleAttributes;
    return NtOpenThreadToken(ThreadHandle, DesiredAccess, OpenAsSelf, TokenHandle);
}

/* Static SID encoding: rev=1, sub_count, identifier_authority=6 bytes
 * BIG-ENDIAN (Windows quirk), then sub_count u32 sub-authorities LE. */
static const unsigned char k_user_sid[28] = {
    1,    5,             /* rev, sub_count */
    0,    0, 0, 0, 0, 5, /* IdentifierAuthority = 5 (NT_AUTHORITY) */
    21,   0, 0, 0,       /* sub-auth 0: 21 */
    1,    0, 0, 0,       /* sub-auth 1: 1 */
    1,    0, 0, 0,       /* sub-auth 2: 1 */
    1,    0, 0, 0,       /* sub-auth 3: 1 */
    0xE8, 3, 0, 0        /* sub-auth 4: 1000 */
};

static const unsigned char k_integrity_high_sid[12] = {
    1, 1,                 /* rev, sub_count */
    0, 0,    0, 0, 0, 16, /* IdentifierAuthority = 16 (MANDATORY_LABEL_AUTHORITY) */
    0, 0x30, 0, 0         /* SECURITY_MANDATORY_HIGH_RID = 0x3000 */
};

__declspec(dllexport) NTSTATUS NtQueryInformationToken(HANDLE TokenHandle, ULONG TokenInformationClass,
                                                       void* TokenInformation, ULONG TokenInformationLength,
                                                       ULONG* ReturnLength)
{
    (void)TokenHandle; /* v0 has only one token; ignore */
    /* TOKEN_INFORMATION_CLASS values: */
    enum
    {
        TokenUser = 1,
        TokenIntegrityLevel = 25
    };
    if (TokenInformationClass == TokenUser)
    {
        /* TOKEN_USER { SID_AND_ATTRIBUTES User; } where
         * SID_AND_ATTRIBUTES = { PSID Sid; DWORD Attributes; }.
         * On x64: 16-byte struct (8-byte ptr + 4-byte attr +
         * 4-byte padding), followed by the SID body. Layout:
         *   [0..16) SID_AND_ATTRIBUTES (Sid ptr -> body, attrs=0)
         *   [16..16+sizeof(sid)) SID body
         */
        const unsigned hdr = 16;
        const unsigned total = hdr + (unsigned)sizeof(k_user_sid);
        if (ReturnLength != (ULONG*)0)
            *ReturnLength = total;
        if (TokenInformationLength < total)
            return (NTSTATUS)0xC0000023; /* BUFFER_TOO_SMALL */
        unsigned char* out = (unsigned char*)TokenInformation;
        void** sid_slot = (void**)(out + 0);
        *sid_slot = (void*)(out + hdr);
        out[8] = 0;
        out[9] = 0;
        out[10] = 0;
        out[11] = 0;                     /* Attributes = 0 */
        for (unsigned i = 0; i < 4; ++i) /* trailing pad */
            out[12 + i] = 0;
        for (unsigned i = 0; i < sizeof(k_user_sid); ++i)
            out[hdr + i] = k_user_sid[i];
        return NTSTATUS_SUCCESS;
    }
    if (TokenInformationClass == TokenIntegrityLevel)
    {
        /* TOKEN_MANDATORY_LABEL { SID_AND_ATTRIBUTES Label; }
         * Same shape as TokenUser; SID body is shorter. */
        const unsigned hdr = 16;
        const unsigned total = hdr + (unsigned)sizeof(k_integrity_high_sid);
        if (ReturnLength != (ULONG*)0)
            *ReturnLength = total;
        if (TokenInformationLength < total)
            return (NTSTATUS)0xC0000023;
        unsigned char* out = (unsigned char*)TokenInformation;
        void** sid_slot = (void**)(out + 0);
        *sid_slot = (void*)(out + hdr);
        out[8] = 0;
        out[9] = 0;
        out[10] = 0;
        out[11] = 0x20; /* SE_GROUP_INTEGRITY = 0x20 */
        for (unsigned i = 0; i < 4; ++i)
            out[12 + i] = 0;
        for (unsigned i = 0; i < sizeof(k_integrity_high_sid); ++i)
            out[hdr + i] = k_integrity_high_sid[i];
        return NTSTATUS_SUCCESS;
    }
    return (NTSTATUS)0xC0000002; /* NOT_IMPLEMENTED */
}

__declspec(dllexport) NTSTATUS ZwQueryInformationToken(HANDLE TokenHandle, ULONG TokenInformationClass,
                                                       void* TokenInformation, ULONG TokenInformationLength,
                                                       ULONG* ReturnLength)
{
    return NtQueryInformationToken(TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength,
                                   ReturnLength);
}

/* NtAdjustPrivilegesToken — backed by SYS_TOKEN_ADJUST = 169.
 *
 * Translates the requested privilege adjustments into kernel
 * CapSet operations. Mappings (kernel/subsystems/win32/token_syscall.h):
 *   SeIncreaseBasePriorityPrivilege (LUID 14) → kCapSpawnThread
 *   SeBackupPrivilege               (LUID 17) → kCapFsRead
 *   SeRestorePrivilege              (LUID 18) → kCapFsWrite
 *   SeDebugPrivilege                (LUID 20) → kCapDebug
 *
 * Enabling a privilege whose mapped cap isn't held returns
 * STATUS_NOT_ALL_ASSIGNED (0x00000106) — NOT a failure, just an
 * "info" status. The kernel never adds caps from user space.
 * Disable / SE_PRIVILEGE_REMOVED / DisableAllPrivileges all drop
 * the mapped cap. Privileges with no mapping (SeShutdown, etc.)
 * are silently accepted.
 *
 * Returns: STATUS_SUCCESS (0), STATUS_NOT_ALL_ASSIGNED (0x106), or
 * STATUS_INVALID_PARAMETER on a malformed blob.
 */
__declspec(dllexport) NTSTATUS NtAdjustPrivilegesToken(HANDLE TokenHandle, BOOL DisableAllPrivileges, void* NewState,
                                                       ULONG BufferLength, void* PreviousState, ULONG* ReturnLength)
{
    (void)TokenHandle;
    long long rv;
    __asm__ volatile("mov %5, %%r10\n\t"
                     "mov %6, %%r8\n\t"
                     "int $0x80"
                     : "=a"(rv)
                     : "a"((long long)169), /* SYS_TOKEN_ADJUST */
                       "D"((long long)(DisableAllPrivileges ? 1 : 0)), "S"((long long)NewState),
                       "d"((long long)BufferLength), "r"((long long)PreviousState), "r"((long long)BufferLength)
                     : "r10", "r8", "memory");
    if (rv < 0)
        return NTSTATUS_INVALID_PARAMETER;
    if (ReturnLength != (ULONG*)0)
        *ReturnLength = BufferLength;
    if (rv == 1)
        return (NTSTATUS)0x00000106UL; /* STATUS_NOT_ALL_ASSIGNED — info, not failure */
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS ZwAdjustPrivilegesToken(HANDLE TokenHandle, BOOL DisableAllPrivileges, void* NewState,
                                                       ULONG BufferLength, void* PreviousState, ULONG* ReturnLength)
{
    return NtAdjustPrivilegesToken(TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState,
                                   ReturnLength);
}

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
 * NtEnumerateValueKey — walk values of an open key. v0 honours
 * KeyValueBasicInformation (class 0); other classes return
 * NotImpl. STATUS_NO_MORE_ENTRIES (0x8000001A) past end so for-
 * loops terminate cleanly.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtEnumerateValueKey(HANDLE KeyHandle, ULONG Index, ULONG KeyValueInformationClass,
                                                   void* KeyValueInformation, ULONG Length, ULONG* ResultLength)
{
    if (KeyValueInformationClass != 0)
        return (NTSTATUS)0xC0000002;
    if (KeyValueInformation == (void*)0)
        return NTSTATUS_INVALID_PARAMETER;
    unsigned char stage[96];
    long long status;
    __asm__ volatile("mov %4, %%r10\n\t"
                     "mov %5, %%r8\n\t"
                     "int $0x80"
                     : "=a"(status)
                     : "a"((long long)130), "D"((long long)7), "S"((long long)KeyHandle), "d"((long long)Index),
                       "r"((long long)stage), "r"((long long)sizeof(stage))
                     : "r10", "r8", "memory");
    if (status != 0)
        return (NTSTATUS)status;
    const unsigned title_index = (unsigned)*(unsigned*)(stage + 0);
    const unsigned type = (unsigned)*(unsigned*)(stage + 4);
    const unsigned name_chars = (unsigned)*(unsigned*)(stage + 12);
    const ULONG name_bytes = (ULONG)(name_chars * 2);
    const ULONG total = 12 + name_bytes;
    if (ResultLength != (ULONG*)0)
        *ResultLength = total;
    if (Length < total)
        return (NTSTATUS)0xC0000023;
    unsigned char* out = (unsigned char*)KeyValueInformation;
    *(unsigned*)(out + 0) = title_index;
    *(unsigned*)(out + 4) = type;
    *(unsigned*)(out + 8) = name_bytes;
    const char* src = (const char*)(stage + 32);
    wchar_t16* dst = (wchar_t16*)(out + 12);
    for (unsigned i = 0; i < name_chars; ++i)
        dst[i] = (unsigned char)src[i];
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS ZwEnumerateValueKey(HANDLE KeyHandle, ULONG Index, ULONG KeyValueInformationClass,
                                                   void* KeyValueInformation, ULONG Length, ULONG* ResultLength)
{
    return NtEnumerateValueKey(KeyHandle, Index, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
}

/* NtQueryKey — KeyFullInformation only. Kernel-side SYS_REGISTRY
 * op=8 returns 5 u64 fields: SubKeys / Values / MaxNameLen /
 * MaxValueNameLen / MaxValueDataLen (40 bytes total). The thunk
 * maps these onto KEY_FULL_INFORMATION's offsets. ClassOffset /
 * ClassLength / MaxClassLen stay zero — v0 has no class strings. */
__declspec(dllexport) NTSTATUS NtQueryKey(HANDLE KeyHandle, ULONG KeyInformationClass, void* KeyInformation,
                                          ULONG Length, ULONG* ResultLength)
{
    if (KeyInformationClass != 2)
        return (NTSTATUS)0xC0000002;
    if (KeyInformation == (void*)0)
        return NTSTATUS_INVALID_PARAMETER;
    const ULONG total = 44;
    if (ResultLength != (ULONG*)0)
        *ResultLength = total;
    if (Length < total)
        return (NTSTATUS)0xC0000023;
    unsigned long long fields[5] = {0, 0, 0, 0, 0};
    long long status;
    __asm__ volatile("mov %3, %%r10\n\t"
                     "int $0x80"
                     : "=a"(status)
                     : "a"((long long)130), "D"((long long)8), "S"((long long)KeyHandle), "r"((long long)40),
                       "d"((long long)fields)
                     : "r10", "memory");
    if (status != 0)
        return (NTSTATUS)status;
    unsigned char* out = (unsigned char*)KeyInformation;
    for (unsigned i = 0; i < total; ++i)
        out[i] = 0;
    /* KEY_FULL_INFORMATION fields:
     *   [20..24) SubKeys
     *   [24..28) MaxNameLen      (chars)
     *   [28..32) MaxClassLen     (chars, always 0 in v0)
     *   [32..36) Values
     *   [36..40) MaxValueNameLen (chars)
     *   [40..44) MaxValueDataLen (bytes)
     */
    *(unsigned*)(out + 20) = (unsigned)fields[0];
    *(unsigned*)(out + 24) = (unsigned)fields[2];
    *(unsigned*)(out + 32) = (unsigned)fields[1];
    *(unsigned*)(out + 36) = (unsigned)fields[3];
    *(unsigned*)(out + 40) = (unsigned)fields[4];
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS ZwQueryKey(HANDLE KeyHandle, ULONG KeyInformationClass, void* KeyInformation,
                                          ULONG Length, ULONG* ResultLength)
{
    return NtQueryKey(KeyHandle, KeyInformationClass, KeyInformation, Length, ResultLength);
}

/* NtCreateKey / NtDeleteKey — NotImpl facades. v0 has no
 * mutable key tree; only mutable VALUES on existing static keys
 * (via NtSetValueKey). */
__declspec(dllexport) NTSTATUS NtCreateKey(HANDLE* KeyHandle, ULONG DesiredAccess, void* ObjectAttributes,
                                           ULONG TitleIndex, void* Class, ULONG CreateOptions, ULONG* Disposition)
{
    (void)KeyHandle;
    (void)DesiredAccess;
    (void)ObjectAttributes;
    (void)TitleIndex;
    (void)Class;
    (void)CreateOptions;
    (void)Disposition;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtDeleteKey(HANDLE KeyHandle)
{
    (void)KeyHandle;
    return (NTSTATUS)0xC0000002;
}

/* NtEnumerateKey — list direct children of an open key. v0 honours
 * KeyBasicInformation (class 0); other classes return NotImpl.
 * STATUS_NO_MORE_ENTRIES (0x8000001A) past end so for-loops
 * terminate cleanly. The kernel side (SYS_REGISTRY op=9) walks the
 * static tree's prefix + terminal entries to derive direct
 * children. */
__declspec(dllexport) NTSTATUS NtEnumerateKey(HANDLE KeyHandle, ULONG Index, ULONG KeyInformationClass,
                                              void* KeyInformation, ULONG Length, ULONG* ResultLength)
{
    if (KeyInformationClass != 0)
        return (NTSTATUS)0xC0000002;
    if (KeyInformation == (void*)0)
        return NTSTATUS_INVALID_PARAMETER;
    unsigned char stage[96];
    long long status;
    __asm__ volatile("mov %4, %%r10\n\t"
                     "mov %5, %%r8\n\t"
                     "int $0x80"
                     : "=a"(status)
                     : "a"((long long)130), "D"((long long)9), "S"((long long)KeyHandle), "d"((long long)Index),
                       "r"((long long)stage), "r"((long long)sizeof(stage))
                     : "r10", "r8", "memory");
    if (status != 0)
    {
        if (ResultLength != (ULONG*)0)
            *ResultLength = 0;
        return (NTSTATUS)status;
    }
    /* KEY_BASIC_INFORMATION layout:
     *   LARGE_INTEGER LastWriteTime;  (8 bytes)
     *   ULONG TitleIndex;             (4 bytes)
     *   ULONG NameLength;             (4 bytes, byte count of UTF-16)
     *   WCHAR Name[1];                (UTF-16 LE name body, no NUL)
     */
    const unsigned name_chars = (unsigned)*(unsigned*)(stage + 16);
    const ULONG name_bytes = (ULONG)(name_chars * 2);
    const ULONG total = 16 + name_bytes;
    if (ResultLength != (ULONG*)0)
        *ResultLength = total;
    if (Length < total)
        return (NTSTATUS)0xC0000023;
    unsigned char* out = (unsigned char*)KeyInformation;
    /* LastWriteTime — zero in v0 (no mtime tracking). */
    *(unsigned long long*)(out + 0) = 0;
    *(unsigned*)(out + 8) = (unsigned)Index;
    *(unsigned*)(out + 12) = name_bytes;
    const char* src = (const char*)(stage + 32);
    wchar_t16* dst = (wchar_t16*)(out + 16);
    for (unsigned i = 0; i < name_chars; ++i)
        dst[i] = (unsigned char)src[i];
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS ZwEnumerateKey(HANDLE KeyHandle, ULONG Index, ULONG KeyInformationClass,
                                              void* KeyInformation, ULONG Length, ULONG* ResultLength)
{
    return NtEnumerateKey(KeyHandle, Index, KeyInformationClass, KeyInformation, Length, ResultLength);
}

/* ------------------------------------------------------------------
 * NtCreateFile / NtOpenFile / NtReadFile / NtWriteFile — Win32 PE
 * file I/O via the NT-namespace API.
 *
 * These thunks are pure ABI adapters: they translate Win32-shaped
 * arguments (OBJECT_ATTRIBUTES, IO_STATUS_BLOCK, CreateDisposition)
 * into the kernel's native SYS_FILE_OPEN / SYS_FILE_CREATE /
 * SYS_FILE_READ / SYS_FILE_WRITE syscalls. The kernel is the
 * authority on what's allowed (kCapFsRead / kCapFsWrite gates
 * apply) — the NT layer cannot bypass them.
 *
 * Architectural rule: Win32 subsystem is for executing PE
 * binaries, not for driving DuetOS. Every effect a PE has on the
 * filesystem goes through the same kernel mediation a native
 * DuetOS program does.
 *
 * v0 honours CreateDisposition = FILE_OPEN, FILE_CREATE, and
 * FILE_OPEN_IF. SUPERSEDE / OVERWRITE / OVERWRITE_IF return
 * STATUS_NOT_IMPLEMENTED.
 * ------------------------------------------------------------------ */
/* Forward declaration — definition lives further down with the
 * NtQueryAttributesFile thunks. The helper is shared between the
 * path-based file-stat surface and the NtCreateFile / NtOpenFile
 * adapter family. */
static int ExtractAsciiPathFromObjectAttributes(void* ObjectAttributes, char* out, unsigned cap, unsigned* out_len);

__declspec(dllexport) NTSTATUS NtCreateFile(HANDLE* FileHandle, ULONG DesiredAccess, void* ObjectAttributes,
                                            void* IoStatusBlock, void* AllocationSize, ULONG FileAttributes,
                                            ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions,
                                            void* EaBuffer, ULONG EaLength)
{
    (void)DesiredAccess;
    (void)AllocationSize;
    (void)FileAttributes;
    (void)ShareAccess;
    (void)EaBuffer;
    (void)EaLength;
    if (FileHandle == (HANDLE*)0)
        return NTSTATUS_INVALID_PARAMETER;
    char path[256];
    unsigned path_len = 0;
    if (!ExtractAsciiPathFromObjectAttributes(ObjectAttributes, path, sizeof(path), &path_len))
        return NTSTATUS_INVALID_PARAMETER;
    /* CreateOptions:
     *   FILE_DIRECTORY_FILE     = 0x00000001 — caller wants a dir
     *                             handle for NtQueryDirectoryFile
     *   FILE_NON_DIRECTORY_FILE = 0x00000040 — must NOT be a dir
     * If FILE_DIRECTORY_FILE is set, route to SYS_DIR_OPEN and
     * return the resulting kWin32DirBase handle. NtQueryDirectoryFile
     * recognises this handle range. */
    long long handle = -1;
    long long status = 0;
    if ((CreateOptions & 0x00000001) != 0)
    {
        if (CreateDisposition != 1 /* OPEN */ && CreateDisposition != 3 /* OPEN_IF */)
            return NTSTATUS_INVALID_PARAMETER;
        /* SYS_DIR_OPEN = 154. */
        __asm__ volatile("int $0x80" : "=a"(handle) : "a"((long long)154), "D"((long long)path) : "memory");
        if (handle < 0)
            return (NTSTATUS)0xC0000034ULL; /* OBJECT_NAME_NOT_FOUND */
        *FileHandle = (HANDLE)handle;
        if (IoStatusBlock != (void*)0)
        {
            unsigned long long* iosb = (unsigned long long*)IoStatusBlock;
            iosb[0] = 0;
            iosb[1] = 1; /* FILE_OPENED */
        }
        return NTSTATUS_SUCCESS;
    }
    /* CreateDisposition codes:
     *   0 = SUPERSEDE       (NotImpl in v0)
     *   1 = FILE_OPEN
     *   2 = FILE_CREATE
     *   3 = FILE_OPEN_IF
     *   4 = FILE_OVERWRITE  (NotImpl)
     *   5 = FILE_OVERWRITE_IF (NotImpl) */
    if (CreateDisposition == 1 /* OPEN */ || CreateDisposition == 3 /* OPEN_IF */)
    {
        /* SYS_FILE_OPEN = 20. */
        __asm__ volatile("int $0x80"
                         : "=a"(handle)
                         : "a"((long long)20), "D"((long long)path), "S"((long long)(path_len + 1))
                         : "memory");
        if (handle < 0 && CreateDisposition == 3)
        {
            /* OPEN_IF: open failed -> create. */
            __asm__ volatile("mov %4, %%r10\n\t"
                             "int $0x80"
                             : "=a"(handle)
                             : "a"((long long)44), "D"((long long)path), "S"((long long)(path_len + 1)),
                               "d"((long long)0), "r"((long long)0)
                             : "r10", "memory");
        }
        if (handle < 0)
            status = (long long)0xC0000034ULL; /* OBJECT_NAME_NOT_FOUND */
    }
    else if (CreateDisposition == 2 /* CREATE */)
    {
        /* SYS_FILE_CREATE = 44. */
        __asm__ volatile("mov %4, %%r10\n\t"
                         "int $0x80"
                         : "=a"(handle)
                         : "a"((long long)44), "D"((long long)path), "S"((long long)(path_len + 1)), "d"((long long)0),
                           "r"((long long)0)
                         : "r10", "memory");
        if (handle < 0)
            status = (long long)0xC0000035ULL; /* OBJECT_NAME_COLLISION */
    }
    else
    {
        return (NTSTATUS)0xC0000002; /* NOT_IMPLEMENTED */
    }
    if (handle < 0)
        return (NTSTATUS)status;
    *FileHandle = (HANDLE)handle;
    /* IO_STATUS_BLOCK is { Status; Information } — write success
     * + a per-disposition Information value:
     *   FILE_OPEN     -> FILE_OPENED        (1)
     *   FILE_CREATE   -> FILE_CREATED       (2)
     *   FILE_OPEN_IF  -> caller-discovered  (1 or 2; we report 1) */
    if (IoStatusBlock != (void*)0)
    {
        unsigned long long* iosb = (unsigned long long*)IoStatusBlock;
        iosb[0] = 0; /* NTSTATUS_SUCCESS */
        iosb[1] = (CreateDisposition == 2) ? 2 : 1;
    }
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS ZwCreateFile(HANDLE* FileHandle, ULONG DesiredAccess, void* ObjectAttributes,
                                            void* IoStatusBlock, void* AllocationSize, ULONG FileAttributes,
                                            ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions,
                                            void* EaBuffer, ULONG EaLength)
{
    return NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes,
                        ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

__declspec(dllexport) NTSTATUS NtOpenFile(HANDLE* FileHandle, ULONG DesiredAccess, void* ObjectAttributes,
                                          void* IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions)
{
    (void)DesiredAccess;
    (void)ShareAccess;
    (void)OpenOptions;
    if (FileHandle == (HANDLE*)0)
        return NTSTATUS_INVALID_PARAMETER;
    char path[256];
    unsigned path_len = 0;
    if (!ExtractAsciiPathFromObjectAttributes(ObjectAttributes, path, sizeof(path), &path_len))
        return NTSTATUS_INVALID_PARAMETER;
    long long handle;
    /* SYS_FILE_OPEN = 20. */
    __asm__ volatile("int $0x80"
                     : "=a"(handle)
                     : "a"((long long)20), "D"((long long)path), "S"((long long)(path_len + 1))
                     : "memory");
    if (handle < 0)
        return (NTSTATUS)0xC0000034;
    *FileHandle = (HANDLE)handle;
    if (IoStatusBlock != (void*)0)
    {
        unsigned long long* iosb = (unsigned long long*)IoStatusBlock;
        iosb[0] = 0;
        iosb[1] = 1; /* FILE_OPENED */
    }
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS ZwOpenFile(HANDLE* FileHandle, ULONG DesiredAccess, void* ObjectAttributes,
                                          void* IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions)
{
    return NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
}

__declspec(dllexport) NTSTATUS NtReadFile(HANDLE FileHandle, HANDLE Event, void* ApcRoutine, void* ApcContext,
                                          void* IoStatusBlock, void* Buffer, ULONG Length, void* ByteOffset, void* Key)
{
    (void)Event;
    (void)ApcRoutine;
    (void)ApcContext;
    (void)Key;
    /* ByteOffset is honoured only for the special "no-cursor-update"
     * marker (-1, -1) which means "read at current cursor". v0
     * always uses the per-handle cursor — explicit-offset reads
     * would need a SYS_FILE_PREAD which doesn't exist yet. Sub-
     * GAP. */
    (void)ByteOffset;
    long long n;
    /* SYS_FILE_READ = 21. */
    __asm__ volatile("int $0x80"
                     : "=a"(n)
                     : "a"((long long)21), "D"((long long)FileHandle), "S"((long long)Buffer), "d"((long long)Length)
                     : "memory");
    if (n < 0)
    {
        if (IoStatusBlock != (void*)0)
        {
            unsigned long long* iosb = (unsigned long long*)IoStatusBlock;
            iosb[0] = 0xC0000008; /* INVALID_HANDLE */
            iosb[1] = 0;
        }
        return (NTSTATUS)0xC0000008;
    }
    if (IoStatusBlock != (void*)0)
    {
        unsigned long long* iosb = (unsigned long long*)IoStatusBlock;
        iosb[0] = 0;
        iosb[1] = (unsigned long long)n;
    }
    if (n == 0)
        return (NTSTATUS)0xC0000011; /* END_OF_FILE */
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS ZwReadFile(HANDLE FileHandle, HANDLE Event, void* ApcRoutine, void* ApcContext,
                                          void* IoStatusBlock, void* Buffer, ULONG Length, void* ByteOffset, void* Key)
{
    return NtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
}

__declspec(dllexport) NTSTATUS NtWriteFile(HANDLE FileHandle, HANDLE Event, void* ApcRoutine, void* ApcContext,
                                           void* IoStatusBlock, void* Buffer, ULONG Length, void* ByteOffset, void* Key)
{
    (void)Event;
    (void)ApcRoutine;
    (void)ApcContext;
    (void)Key;
    (void)ByteOffset;
    long long n;
    /* SYS_FILE_WRITE = 43. */
    __asm__ volatile("int $0x80"
                     : "=a"(n)
                     : "a"((long long)43), "D"((long long)FileHandle), "S"((long long)Buffer), "d"((long long)Length)
                     : "memory");
    if (n < 0)
    {
        if (IoStatusBlock != (void*)0)
        {
            unsigned long long* iosb = (unsigned long long*)IoStatusBlock;
            iosb[0] = 0xC0000008;
            iosb[1] = 0;
        }
        return (NTSTATUS)0xC0000008;
    }
    if (IoStatusBlock != (void*)0)
    {
        unsigned long long* iosb = (unsigned long long*)IoStatusBlock;
        iosb[0] = 0;
        iosb[1] = (unsigned long long)n;
    }
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS ZwWriteFile(HANDLE FileHandle, HANDLE Event, void* ApcRoutine, void* ApcContext,
                                           void* IoStatusBlock, void* Buffer, ULONG Length, void* ByteOffset, void* Key)
{
    return NtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
}

/* ------------------------------------------------------------------
 * NtQueryInformationFile / NtSetInformationFile —
 * handle-based file metadata read + write.
 *
 * The Win32 NT API multiplexes many information classes through
 * one syscall. v0 covers the two everyone touches:
 *   - FileStandardInformation   (5)  -> file size + dir flag
 *   - FilePositionInformation   (14) -> read/write cursor
 * Setters honour FilePositionInformation via SYS_FILE_SEEK.
 * Other classes return STATUS_NOT_IMPLEMENTED so callers fall
 * back rather than misinterpret zero-filled output.
 *
 * Architectural rule: the kernel is the authority on file state;
 * these thunks only translate the Win32 ABI shape.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtQueryInformationFile(HANDLE FileHandle, void* IoStatusBlock, void* FileInformation,
                                                      ULONG Length, ULONG FileInformationClass)
{
    if (FileInformation == (void*)0)
        return NTSTATUS_INVALID_PARAMETER;
    if (FileInformationClass == 5 /* FileStandardInformation */)
    {
        if (Length < 24)
            return (NTSTATUS)0xC0000004;
        long long size_out = 0;
        long long status;
        __asm__ volatile("int $0x80"
                         : "=a"(status)
                         : "a"((long long)24), "D"((long long)FileHandle), "S"((long long)&size_out)
                         : "memory");
        if (status != 0)
            return (NTSTATUS)0xC0000008;
        unsigned char* out = (unsigned char*)FileInformation;
        const unsigned long long aligned = ((unsigned long long)size_out + 4095ULL) & ~4095ULL;
        for (unsigned i = 0; i < 8; ++i)
            out[i] = (unsigned char)((aligned >> (i * 8)) & 0xFF);
        for (unsigned i = 0; i < 8; ++i)
            out[8 + i] = (unsigned char)(((unsigned long long)size_out >> (i * 8)) & 0xFF);
        out[16] = 1;
        out[17] = 0;
        out[18] = 0;
        out[19] = 0;
        out[20] = 0;
        out[21] = 0;
        out[22] = 0;
        out[23] = 0;
        if (IoStatusBlock != (void*)0)
        {
            unsigned long long* iosb = (unsigned long long*)IoStatusBlock;
            iosb[0] = 0;
            iosb[1] = 24;
        }
        return NTSTATUS_SUCCESS;
    }
    if (FileInformationClass == 14 /* FilePositionInformation */)
    {
        if (Length < 8)
            return (NTSTATUS)0xC0000004;
        long long cur;
        __asm__ volatile("int $0x80"
                         : "=a"(cur)
                         : "a"((long long)23), "D"((long long)FileHandle), "S"((long long)0), "d"((long long)1)
                         : "memory");
        if (cur < 0)
            return (NTSTATUS)0xC0000008;
        unsigned char* out = (unsigned char*)FileInformation;
        unsigned long long ucur = (unsigned long long)cur;
        for (unsigned i = 0; i < 8; ++i)
            out[i] = (unsigned char)((ucur >> (i * 8)) & 0xFF);
        if (IoStatusBlock != (void*)0)
        {
            unsigned long long* iosb = (unsigned long long*)IoStatusBlock;
            iosb[0] = 0;
            iosb[1] = 8;
        }
        return NTSTATUS_SUCCESS;
    }
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS ZwQueryInformationFile(HANDLE FileHandle, void* IoStatusBlock, void* FileInformation,
                                                      ULONG Length, ULONG FileInformationClass)
{
    return NtQueryInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
}

__declspec(dllexport) NTSTATUS NtSetInformationFile(HANDLE FileHandle, void* IoStatusBlock, void* FileInformation,
                                                    ULONG Length, ULONG FileInformationClass)
{
    if (FileInformation == (void*)0)
        return NTSTATUS_INVALID_PARAMETER;
    if (FileInformationClass == 14 /* FilePositionInformation */)
    {
        if (Length < 8)
            return (NTSTATUS)0xC0000004;
        unsigned char* in = (unsigned char*)FileInformation;
        unsigned long long pos = 0;
        for (unsigned i = 0; i < 8; ++i)
            pos |= ((unsigned long long)in[i]) << (i * 8);
        long long rv;
        __asm__ volatile("int $0x80"
                         : "=a"(rv)
                         : "a"((long long)23), "D"((long long)FileHandle), "S"((long long)pos), "d"((long long)0)
                         : "memory");
        if (rv < 0)
            return (NTSTATUS)0xC0000008;
        if (IoStatusBlock != (void*)0)
        {
            unsigned long long* iosb = (unsigned long long*)IoStatusBlock;
            iosb[0] = 0;
            iosb[1] = 0;
        }
        return NTSTATUS_SUCCESS;
    }
    if (FileInformationClass == 4 /* FileBasicInformation */)
    {
        /* FILE_BASIC_INFORMATION: 4 LARGE_INTEGER timestamps +
         * u32 attributes + u32 pad. v0 doesn't track times on
         * disk (FAT32 cluster-time updates aren't wired through
         * the SYS_FILE_WRITE path), so the safe shape is
         * accept-as-success — the caller's expectation is "the
         * timestamps are now what I set" but most callers only
         * use this to bump LastAccess / LastWrite which we'd
         * silently lose anyway. Length must cover at least the
         * 4 timestamps (32 bytes). Sub-GAP: timestamps unobserved. */
        if (Length < 32)
            return (NTSTATUS)0xC0000004;
        if (IoStatusBlock != (void*)0)
        {
            unsigned long long* iosb = (unsigned long long*)IoStatusBlock;
            iosb[0] = 0;
            iosb[1] = Length;
        }
        return NTSTATUS_SUCCESS;
    }
    /* FileEndOfFileInformation (20) — truncate-by-handle.
     * FileRenameInformation (10) — rename-by-handle.
     * FileDispositionInformation (13) — delete-on-close.
     * Each needs a new kernel syscall (SYS_FILE_TRUNCATE,
     * handle->path resolution, per-handle flags) — separate slices. */
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS ZwSetInformationFile(HANDLE FileHandle, void* IoStatusBlock, void* FileInformation,
                                                    ULONG Length, ULONG FileInformationClass)
{
    return NtSetInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
}

__declspec(dllexport) NTSTATUS NtFlushBuffersFile(HANDLE FileHandle, void* IoStatusBlock)
{
    (void)FileHandle;
    if (IoStatusBlock != (void*)0)
    {
        unsigned long long* iosb = (unsigned long long*)IoStatusBlock;
        iosb[0] = 0;
        iosb[1] = 0;
    }
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS ZwFlushBuffersFile(HANDLE FileHandle, void* IoStatusBlock)
{
    return NtFlushBuffersFile(FileHandle, IoStatusBlock);
}

__declspec(dllexport) NTSTATUS NtFsControlFile(HANDLE FileHandle, HANDLE Event, void* ApcRoutine, void* ApcContext,
                                               void* IoStatusBlock, ULONG IoControlCode, void* InputBuffer,
                                               ULONG InputBufferLength, void* OutputBuffer, ULONG OutputBufferLength)
{
    (void)FileHandle;
    (void)Event;
    (void)ApcRoutine;
    (void)ApcContext;
    (void)IoControlCode;
    (void)InputBuffer;
    (void)InputBufferLength;
    (void)OutputBuffer;
    (void)OutputBufferLength;
    if (IoStatusBlock != (void*)0)
    {
        unsigned long long* iosb = (unsigned long long*)IoStatusBlock;
        iosb[0] = 0xC0000002;
        iosb[1] = 0;
    }
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS ZwFsControlFile(HANDLE FileHandle, HANDLE Event, void* ApcRoutine, void* ApcContext,
                                               void* IoStatusBlock, ULONG IoControlCode, void* InputBuffer,
                                               ULONG InputBufferLength, void* OutputBuffer, ULONG OutputBufferLength)
{
    return NtFsControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer,
                           InputBufferLength, OutputBuffer, OutputBufferLength);
}

__declspec(dllexport) NTSTATUS NtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, void* ApcRoutine,
                                                     void* ApcContext, void* IoStatusBlock, ULONG IoControlCode,
                                                     void* InputBuffer, ULONG InputBufferLength, void* OutputBuffer,
                                                     ULONG OutputBufferLength)
{
    return NtFsControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer,
                           InputBufferLength, OutputBuffer, OutputBufferLength);
}

__declspec(dllexport) NTSTATUS ZwDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, void* ApcRoutine,
                                                     void* ApcContext, void* IoStatusBlock, ULONG IoControlCode,
                                                     void* InputBuffer, ULONG InputBufferLength, void* OutputBuffer,
                                                     ULONG OutputBufferLength)
{
    return NtDeviceIoControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer,
                                 InputBufferLength, OutputBuffer, OutputBufferLength);
}

/* ------------------------------------------------------------------
 * NtQueryAttributesFile / NtQueryFullAttributesFile — path-based
 * file stat. Both forward to SYS_FILE_QUERY_ATTRIBUTES (151).
 *
 * NtQueryAttributesFile fills a 40-byte FILE_BASIC_INFORMATION
 * (Times×4 + Attrs); NtQueryFullAttributesFile fills the 56-byte
 * FILE_NETWORK_OPEN_INFORMATION which adds AllocationSize +
 * EndOfFile. The kernel writes the larger struct; the Basic
 * variant truncates locally.
 * ------------------------------------------------------------------ */
static int ExtractAsciiPathFromObjectAttributes(void* ObjectAttributes, char* out, unsigned cap, unsigned* out_len)
{
    if (ObjectAttributes == (void*)0)
        return 0;
    unsigned char* base = (unsigned char*)ObjectAttributes;
    UNICODE_STRING* name = *(UNICODE_STRING**)(base + 16);
    if (name == (UNICODE_STRING*)0 || name->Buffer == (wchar_t16*)0)
        return 0;
    const unsigned chars = (unsigned)(name->Length / 2);
    unsigned start = 0;
    if (chars >= 4 && name->Buffer[0] == '\\' && name->Buffer[1] == '?' && name->Buffer[2] == '?' &&
        name->Buffer[3] == '\\')
        start = 4;
    if (chars - start + 1 > cap)
        return 0;
    for (unsigned i = start; i < chars; ++i)
    {
        unsigned short w = name->Buffer[i];
        out[i - start] = (w <= 0x7F) ? (char)w : '?';
    }
    out[chars - start] = 0;
    if (out_len != (unsigned*)0)
        *out_len = chars - start;
    return 1;
}

__declspec(dllexport) NTSTATUS NtQueryAttributesFile(void* ObjectAttributes, void* FileInformation)
{
    char path[256];
    unsigned path_len = 0;
    if (!ExtractAsciiPathFromObjectAttributes(ObjectAttributes, path, sizeof(path), &path_len))
        return NTSTATUS_INVALID_PARAMETER;
    if (FileInformation == (void*)0)
        return NTSTATUS_INVALID_PARAMETER;
    unsigned char stage[56];
    long long status;
    __asm__ volatile("mov %4, %%r10\n\t"
                     "int $0x80"
                     : "=a"(status)
                     : "a"((long long)151), "D"((long long)path), "S"((long long)path_len), "d"((long long)stage),
                       "r"((long long)sizeof(stage))
                     : "r10", "memory");
    if (status != 0)
        return (NTSTATUS)status;
    /* FILE_BASIC_INFORMATION: 4×FILETIME + Attributes + 4-byte pad. */
    unsigned char* out = (unsigned char*)FileInformation;
    for (unsigned i = 0; i < 32; ++i)
        out[i] = stage[i];
    for (unsigned i = 0; i < 4; ++i)
        out[32 + i] = stage[48 + i];
    out[36] = 0;
    out[37] = 0;
    out[38] = 0;
    out[39] = 0;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS ZwQueryAttributesFile(void* ObjectAttributes, void* FileInformation)
{
    return NtQueryAttributesFile(ObjectAttributes, FileInformation);
}

__declspec(dllexport) NTSTATUS NtQueryFullAttributesFile(void* ObjectAttributes, void* FileInformation)
{
    char path[256];
    unsigned path_len = 0;
    if (!ExtractAsciiPathFromObjectAttributes(ObjectAttributes, path, sizeof(path), &path_len))
        return NTSTATUS_INVALID_PARAMETER;
    if (FileInformation == (void*)0)
        return NTSTATUS_INVALID_PARAMETER;
    long long status;
    __asm__ volatile("mov %4, %%r10\n\t"
                     "int $0x80"
                     : "=a"(status)
                     : "a"((long long)151), "D"((long long)path), "S"((long long)path_len),
                       "d"((long long)FileInformation), "r"((long long)56)
                     : "r10", "memory");
    return (NTSTATUS)status;
}

__declspec(dllexport) NTSTATUS ZwQueryFullAttributesFile(void* ObjectAttributes, void* FileInformation)
{
    return NtQueryFullAttributesFile(ObjectAttributes, FileInformation);
}

/* ------------------------------------------------------------------
 * NtCreateThreadEx — same-process thread create.
 *
 * Win32 NT signature:
 *   NTSTATUS NtCreateThreadEx(
 *     PHANDLE     ThreadHandle,
 *     ACCESS_MASK DesiredAccess,
 *     POBJECT_ATTRIBUTES ObjectAttributes,
 *     HANDLE      ProcessHandle,
 *     PVOID       StartRoutine,
 *     PVOID       Argument,
 *     ULONG       CreateFlags,
 *     ULONG_PTR   ZeroBits,
 *     SIZE_T      StackSize,
 *     SIZE_T      MaximumStackSize,
 *     PPS_ATTRIBUTE_LIST AttributeList);
 *
 * v0 honours ProcessHandle == NtCurrentProcess() (-1) only —
 * cross-process thread injection (the substrate of process
 * hollowing's kick-off path) needs cross-AS handle plumbing
 * we don't have on the SYS_THREAD_CREATE side yet. CreateFlags
 * other than 0 (no CREATE_SUSPENDED yet — needs an extra
 * arg to SchedCreateUser to start the task pre-suspended)
 * return NOT_IMPLEMENTED.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtCreateThreadEx(HANDLE* ThreadHandle, ULONG DesiredAccess, void* ObjectAttributes,
                                                HANDLE hProcess, void* StartRoutine, void* Argument, ULONG CreateFlags,
                                                SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize,
                                                void* AttributeList)
{
    (void)DesiredAccess;
    (void)ObjectAttributes;
    (void)ZeroBits;
    (void)StackSize;
    (void)MaximumStackSize;
    (void)AttributeList;
    if (hProcess != (HANDLE)-1)
        return NTSTATUS_NOT_IMPLEMENTED;
    if (CreateFlags != 0)
        return NTSTATUS_NOT_IMPLEMENTED;
    long long handle;
    /* SYS_THREAD_CREATE = 45. Args: rdi = start RIP, rsi = param. */
    __asm__ volatile("int $0x80"
                     : "=a"(handle)
                     : "a"((long long)45), "D"((long long)StartRoutine), "S"((long long)Argument)
                     : "memory");
    if (handle < 0)
        return NTSTATUS_NO_MEMORY;
    if (ThreadHandle != (HANDLE*)0)
        *ThreadHandle = (HANDLE)handle;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS ZwCreateThreadEx(HANDLE* ThreadHandle, ULONG DesiredAccess, void* ObjectAttributes,
                                                HANDLE hProcess, void* StartRoutine, void* Argument, ULONG CreateFlags,
                                                SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize,
                                                void* AttributeList)
{
    return NtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, hProcess, StartRoutine, Argument,
                            CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
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

/* ------------------------------------------------------------------
 * Bulk-generated NT thunks — completes the Bedrock Win-XP→Win11 NT
 * call coverage. Each thunk returns STATUS_NOT_IMPLEMENTED
 * (0xC0000002). The x64 calling convention places caller args in
 * RCX/RDX/R8/R9/stack; we ignore them and only set RAX.
 *
 * Architectural rule (wiki/kernel/Subsystem-Isolation.md):
 * Win32 is a façade for executing PE binaries — NotImpl thunks
 * satisfy malware-shape probes without offering any real DuetOS
 * effect. Real implementations replace each stub when the
 * underlying engine lands kernel-side. Until then, the explicit
 * NotImpl is more honest than the catch-all kSysNtNotImpl.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtAccessCheckAndAuditAlarm(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAccessCheckByType(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAccessCheckByTypeAndAuditAlarm(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAccessCheckByTypeResultList(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAccessCheckByTypeResultListAndAuditAlarm(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAccessCheckByTypeResultListAndAuditAlarmByHandle(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAcquireCMFViewOwnership(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAcquireCrossVmMutant(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAcquireProcessActivityReference(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAddAtomEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAddBootEntry(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAddDriverEntry(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAdjustTokenClaimsAndDeviceGroups(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAlertMultipleThreadByThreadId(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAlertThreadByThreadId(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAlertThreadByThreadIdEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAllocateLocallyUniqueId(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAllocateReserveObject(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAllocateUserPhysicalPages(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAllocateUserPhysicalPagesEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAllocateVirtualMemoryEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAlpcAcceptConnectPort(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAlpcCancelMessage(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAlpcConnectPortEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAlpcCreatePortSection(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAlpcCreateResourceReserve(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAlpcCreateSectionView(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAlpcCreateSecurityContext(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAlpcDeletePortSection(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAlpcDeleteResourceReserve(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAlpcDeleteSectionView(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAlpcDeleteSecurityContext(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAlpcDisconnectPort(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAlpcImpersonateClientContainerOfPort(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAlpcImpersonateClientOfPort(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAlpcOpenSenderProcess(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAlpcOpenSenderThread(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAlpcQueryInformation(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAlpcQueryInformationMessage(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAlpcRevokeSecurityContext(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAlpcSetInformation(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtApphelpCacheControl(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtAssociateWaitCompletionPacket(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCallEnclave(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCancelDeviceWakeupRequest(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCancelTimer2(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCancelWaitCompletionPacket(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtChangeProcessState(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtChangeThreadState(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtClearAllSavepointsTransaction(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtClearSavepointTransaction(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCloseObjectAuditAlarm(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCommitComplete(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCommitEnlistment(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCommitRegistryTransaction(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCompactKeys(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCompareObjects(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCompareSigningLevels(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCompareTokens(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCompressKey(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtContinueEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtConvertBetweenAuxiliaryCounterAndPerformanceCounter(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCopyFileChunk(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateCpuPartition(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateCrossVmEvent(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateCrossVmMutant(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateDirectoryObjectEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateEnclave(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateEnlistment(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateEventPair(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateIRTimer(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateIoRing(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateJobSet(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateKeyTransacted(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateLowBoxToken(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreatePagingFile(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreatePartition(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreatePrivateNamespace(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateProcessStateChange(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateProfileEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateRegistryTransaction(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateResourceManager(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateSectionEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateSemaphore(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateThread(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateThreadStateChange(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateTimer2(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateToken(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateTokenEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateTransactionManager(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateWaitCompletionPacket(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateWaitablePort(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateWnfStateName(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtCreateWorkerFactory(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtDeleteBootEntry(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtDeleteDriverEntry(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtDeleteObjectAuditAlarm(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtDeletePrivateNamespace(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtDeleteWnfStateData(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtDeleteWnfStateName(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtDirectGraphicsCall(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtDisableLastKnownGood(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtDisplayString(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtDrawText(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtDuplicateObject(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtEnableLastKnownGood(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtEnumerateBootEntries(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtEnumerateDriverEntries(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtEnumerateSystemEnvironmentValuesEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtEnumerateTransactionObject(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtExtendSection(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtFilterBootOption(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtFilterTokenEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtFlushBuffersFileEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtFlushInstallUILanguage(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtFlushProcessWriteBuffers(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtFlushWriteBuffer(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtFreeUserPhysicalPages(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtFreezeRegistry(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtFreezeTransactions(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtGetCachedSigningLevel(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtGetCompleteWnfStateSubscription(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtGetCurrentProcessorNumberEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtGetDevicePowerState(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtGetNextProcess(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtGetNextThread(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtGetNlsSectionPtr(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtGetNotificationResourceManager(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtGetPlugPlayEvent(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtInitializeEnclave(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtInitializeNlsFiles(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtInitializeRegistry(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtInitiatePowerAction(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtIsSystemResumeAutomatic(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtIsUILanguageComitted(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtListTransactions(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtLoadEnclaveData(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtLoadHotPatch(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtLoadKey(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtLoadKey2(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtLoadKey3(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtLoadKeyEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtLockProductActivationKeys(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtLockRegistryKey(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtMakePermanentObject(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtMakeTemporaryObject(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtManageHotPatch(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtManagePartition(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtMapCMFModule(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtMapUserPhysicalPages(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtMapUserPhysicalPagesScatter(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtMapViewOfSectionEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtMarshallTransaction(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtModifyBootEntry(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtModifyDriverEntry(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtNotifyChangeDirectoryFileEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtNotifyChangeKey(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtNotifyChangeMultipleKeys(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtNotifyChangeSession(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtOpenCpuPartition(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtOpenEnlistment(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtOpenEventPair(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtOpenJobObject(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtOpenKeyTransacted(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtOpenKeyTransactedEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtOpenObjectAuditAlarm(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtOpenPartition(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtOpenPrivateNamespace(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtOpenRegistryTransaction(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtOpenResourceManager(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtOpenSection(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtOpenSemaphore(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtOpenSession(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtOpenTransactionManager(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtPrePrepareComplete(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtPrePrepareEnlistment(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtPrepareComplete(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtPrepareEnlistment(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtPrivilegedServiceAuditAlarm(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtPropagationComplete(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtPropagationFailed(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtPssCaptureVaSpaceBulk(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtPullTransaction(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryAuxiliaryCounterFrequency(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryBootEntryOrder(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryBootOptions(void)
{
    return (NTSTATUS)0xC0000002;
}
/* NtQueryDirectoryFile — real implementation backed by SYS_DIR_NEXT.
 *
 * Real Windows packs many entries into the caller's buffer; v0
 * returns ONE entry per call (NextEntryOffset = 0). Callers loop
 * until STATUS_NO_MORE_FILES — same observable contract, just one
 * round-trip per entry. RestartScan = TRUE issues SYS_DIR_REWIND
 * before fetching.
 *
 * Supported FILE_INFORMATION_CLASS values:
 *   1 = FileDirectoryInformation        (header 64 bytes + name)
 *   2 = FileFullDirectoryInformation    (header 68 bytes + name)
 *   3 = FileBothDirectoryInformation    (header 94 bytes + name)
 *  12 = FileNamesInformation            (header 12 bytes + name)
 *
 * Other classes return STATUS_NOT_IMPLEMENTED. The 4 classes above
 * cover every common Windows enumerator (FindFirstFile fallback +
 * direct-NT malware probes).
 *
 * The kernel-side SYS_DIR_NEXT report carries name + attributes +
 * size only; timestamps + EaSize + ShortName fields are zero-filled
 * (v0 has no ctime/atime/mtime tracking). */
struct Win32DirEntryReport_t
{
    char name[64];
    unsigned int attributes;
    unsigned int _pad;
    unsigned long long size_bytes;
    unsigned char _reserved[16];
};

__declspec(dllexport) NTSTATUS NtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, void* ApcRoutine, void* ApcContext,
                                                    void* IoStatusBlock, void* FileInformation, ULONG Length,
                                                    ULONG FileInformationClass, BOOL ReturnSingleEntry, void* FileName,
                                                    BOOL RestartScan)
{
    (void)Event;
    (void)ApcRoutine;
    (void)ApcContext;
    (void)ReturnSingleEntry;
    (void)FileName; /* glob filter not honoured; sub-GAP */
    if (FileInformation == (void*)0 || Length == 0)
        return NTSTATUS_INVALID_PARAMETER;
    /* Accept only the directory-handle range. Other handles
     * (regular files via NtCreateFile without FILE_DIRECTORY_FILE)
     * → STATUS_INVALID_HANDLE — Windows returns the same. */
    unsigned long long h = (unsigned long long)(long long)FileHandle;
    if (h < 0xA00 || h > 0xA07)
        return (NTSTATUS)0xC0000008ULL; /* STATUS_INVALID_HANDLE */
    if (RestartScan)
    {
        long long rv;
        __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)156), "D"((long long)h) : "memory");
        if (rv < 0)
            return (NTSTATUS)0xC0000008ULL;
    }
    struct Win32DirEntryReport_t r;
    long long got;
    __asm__ volatile("int $0x80" : "=a"(got) : "a"((long long)155), "D"((long long)h), "S"((long long)&r) : "memory");
    if (got < 0)
        return (NTSTATUS)0xC0000008ULL;
    if (got == 0)
        return (NTSTATUS)0x80000006ULL; /* STATUS_NO_MORE_FILES */

    /* Compute the byte length of the wide-char name we'll emit
     * (NUL is NOT counted in FileNameLength on Windows). */
    unsigned name_chars = 0;
    while (name_chars < 64 && r.name[name_chars] != '\0')
        ++name_chars;
    const unsigned name_bytes = name_chars * 2; /* UTF-16 */

    /* Emit per the requested class. Output a single record;
     * NextEntryOffset = 0 marks end-of-record. */
    unsigned char* out = (unsigned char*)FileInformation;
    unsigned needed = 0;
    if (FileInformationClass == 1) /* FileDirectoryInformation */
    {
        needed = 64 + name_bytes;
        if (Length < needed)
            return (NTSTATUS)0xC0000023ULL; /* STATUS_BUFFER_TOO_SMALL */
        unsigned* u32p = (unsigned*)out;
        unsigned long long* u64p = (unsigned long long*)out;
        u32p[0] = 0;                                                   /* NextEntryOffset */
        u32p[1] = 0;                                                   /* FileIndex */
        u64p[1] = 0;                                                   /* CreationTime  */
        u64p[2] = 0;                                                   /* LastAccessTime */
        u64p[3] = 0;                                                   /* LastWriteTime  */
        u64p[4] = 0;                                                   /* ChangeTime */
        u64p[5] = r.size_bytes;                                        /* EndOfFile  */
        u64p[6] = (r.size_bytes + 4095) & ~((unsigned long long)4095); /* AllocationSize */
        u32p[14] = r.attributes;                                       /* FileAttributes */
        u32p[15] = name_bytes;                                         /* FileNameLength */
    }
    else if (FileInformationClass == 2) /* FileFullDirectoryInformation */
    {
        needed = 68 + name_bytes;
        if (Length < needed)
            return (NTSTATUS)0xC0000023ULL;
        unsigned* u32p = (unsigned*)out;
        unsigned long long* u64p = (unsigned long long*)out;
        u32p[0] = 0;
        u32p[1] = 0;
        u64p[1] = 0;
        u64p[2] = 0;
        u64p[3] = 0;
        u64p[4] = 0;
        u64p[5] = r.size_bytes;
        u64p[6] = (r.size_bytes + 4095) & ~((unsigned long long)4095);
        u32p[14] = r.attributes;
        u32p[15] = name_bytes;
        u32p[16] = 0; /* EaSize */
    }
    else if (FileInformationClass == 3) /* FileBothDirectoryInformation */
    {
        needed = 94 + name_bytes;
        if (Length < needed)
            return (NTSTATUS)0xC0000023ULL;
        unsigned* u32p = (unsigned*)out;
        unsigned long long* u64p = (unsigned long long*)out;
        u32p[0] = 0;
        u32p[1] = 0;
        u64p[1] = 0;
        u64p[2] = 0;
        u64p[3] = 0;
        u64p[4] = 0;
        u64p[5] = r.size_bytes;
        u64p[6] = (r.size_bytes + 4095) & ~((unsigned long long)4095);
        u32p[14] = r.attributes;
        u32p[15] = name_bytes;
        u32p[16] = 0; /* EaSize */
        out[68] = 0;  /* ShortNameLength (bytes) */
        out[69] = 0;  /* _pad */
        for (unsigned i = 0; i < 24; ++i)
            out[70 + i] = 0; /* ShortName[12] WCHARs */
    }
    else if (FileInformationClass == 12) /* FileNamesInformation */
    {
        needed = 12 + name_bytes;
        if (Length < needed)
            return (NTSTATUS)0xC0000023ULL;
        unsigned* u32p = (unsigned*)out;
        u32p[0] = 0;          /* NextEntryOffset */
        u32p[1] = 0;          /* FileIndex */
        u32p[2] = name_bytes; /* FileNameLength */
    }
    else
    {
        return (NTSTATUS)0xC0000002ULL; /* STATUS_NOT_IMPLEMENTED for other classes */
    }

    /* Append the FileName as UTF-16 right after the class header. */
    unsigned name_off = (FileInformationClass == 1)   ? 64
                        : (FileInformationClass == 2) ? 68
                        : (FileInformationClass == 3) ? 94
                                                      : 12;
    unsigned short* wname = (unsigned short*)(out + name_off);
    for (unsigned i = 0; i < name_chars; ++i)
        wname[i] = (unsigned short)(unsigned char)r.name[i];

    if (IoStatusBlock != (void*)0)
    {
        unsigned long long* iosb = (unsigned long long*)IoStatusBlock;
        iosb[0] = 0;
        iosb[1] = needed;
    }
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtQueryDirectoryFileEx(HANDLE FileHandle, HANDLE Event, void* ApcRoutine,
                                                      void* ApcContext, void* IoStatusBlock, void* FileInformation,
                                                      ULONG Length, ULONG FileInformationClass, ULONG QueryFlags,
                                                      void* FileName)
{
    /* SL_RESTART_SCAN = 0x01 in QueryFlags. Forward as the
     * RestartScan bool to NtQueryDirectoryFile. */
    return NtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length,
                                FileInformationClass, /*ReturnSingleEntry=*/(QueryFlags & 0x02) != 0, FileName,
                                /*RestartScan=*/(QueryFlags & 0x01) != 0);
}

__declspec(dllexport) NTSTATUS ZwQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, void* ApcRoutine, void* ApcContext,
                                                    void* IoStatusBlock, void* FileInformation, ULONG Length,
                                                    ULONG FileInformationClass, BOOL ReturnSingleEntry, void* FileName,
                                                    BOOL RestartScan)
{
    return NtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length,
                                FileInformationClass, ReturnSingleEntry, FileName, RestartScan);
}
__declspec(dllexport) NTSTATUS NtQueryDriverEntryOrder(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryInformationAtom(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryInformationByName(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryInformationCpuPartition(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryInformationEnlistment(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryInformationPort(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryInformationResourceManager(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryInformationTransaction(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryInformationTransactionManager(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryInformationWorkerFactory(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryIoCompletion(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryIoRingCapabilities(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryLicenseValue(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryMultipleValueKey(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryMutant(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryOpenSubKeys(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryOpenSubKeysEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryPortInformationProcess(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryQuotaInformationFile(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQuerySection(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQuerySecurityAttributesToken(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQuerySecurityObject(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQuerySecurityPolicy(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQuerySemaphore(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQuerySystemEnvironmentValue(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQuerySystemEnvironmentValueEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQuerySystemInformationEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryTimer(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryVolumeInformationFile(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryWnfStateData(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueryWnfStateNameInformation(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtQueueApcThreadEx2(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtReadOnlyEnlistment(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtReadRequestData(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtReadVirtualMemoryEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtRecoverEnlistment(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtRecoverResourceManager(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtRecoverTransactionManager(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtRegisterProtocolAddressInformation(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtRegisterThreadTerminatePort(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtReleaseCMFViewOwnership(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtReleaseSemaphore(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtReleaseWorkerFactoryWorker(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtRenameKey(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtRenameTransactionManager(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtReplaceKey(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtReplacePartitionUnit(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtReplyWaitReceivePortEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtReplyWaitReplyPort(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtRequestDeviceWakeup(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtRequestWakeupLatency(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtRestoreKey(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtRevertContainerImpersonation(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtRollbackComplete(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtRollbackEnlistment(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtRollbackRegistryTransaction(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtRollbackSavepointTransaction(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtRollforwardTransactionManager(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSaveKey(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSaveKeyEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSaveMergedKeys(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSavepointComplete(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSavepointTransaction(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSerializeBoot(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetBootEntryOrder(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetBootOptions(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetCachedSigningLevel(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetCachedSigningLevel2(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetDebugFilterState(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetDefaultHardErrorPort(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetDriverEntryOrder(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetEventBoostPriority(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetEventEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetHighEventPair(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetHighWaitLowEventPair(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetIRTimer(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetInformationCpuPartition(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetInformationEnlistment(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetInformationIoRing(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetInformationKey(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetInformationObject(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetInformationResourceManager(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetInformationSymbolicLink(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetInformationTransaction(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetInformationTransactionManager(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetInformationVirtualMemory(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetInformationWorkerFactory(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetIoCompletionEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetLdtEntries(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetLowEventPair(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetLowWaitHighEventPair(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetQuotaInformationFile(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetSecurityObject(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetSystemEnvironmentValue(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetSystemEnvironmentValueEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetSystemPowerState(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetSystemTime(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetThreadExecutionState(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetTimer2(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetTimerEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetVolumeInformationFile(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSetWnfProcessNotificationEvent(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtShutdownWorkerFactory(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSinglePhaseReject(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtStartTm(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSubmitIoRing(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSubscribeWnfStateChange(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtSystemDebugControl(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtTerminateEnclave(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtThawRegistry(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtThawTransactions(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtTranslateFilePath(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtUmsThreadYield(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtUnloadKey(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtUnloadKey2(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtUnloadKeyEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtUnmapViewOfSectionEx(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtUnsubscribeWnfStateChange(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtUpdateWnfStateData(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtWaitForAlertByThreadId(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtWaitForMultipleObjects(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtWaitForMultipleObjects32(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtWaitForWnfNotifications(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtWaitForWorkViaWorkerFactory(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtWaitHighEventPair(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtWaitLowEventPair(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtWorkerFactoryWorkerReady(void)
{
    return (NTSTATUS)0xC0000002;
}
__declspec(dllexport) NTSTATUS NtWriteRequestData(void)
{
    return (NTSTATUS)0xC0000002;
}
