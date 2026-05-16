#include "ntdll_internal.h"

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
 * NtCreateMutant forwards directly to SYS_MUTEX_CREATE (unnamed
 * variant). NtOpenMutant routes through SYS_NAMED_KOBJ_OPEN_OR_CREATE
 * (=185) with open_only=1 so a Create+Open pair on the same name
 * resolves through the kernel-resident named-object table.
 * OBJECT_ATTRIBUTES->ObjectName carries the UNICODE_STRING; ASCII
 * subset only (matches kernel32 CreateMutexW path).
 * ------------------------------------------------------------------ */

/* Copy the wide ObjectName into an ASCII buffer (low byte) and
 * dispatch SYS_NAMED_KOBJ_OPEN_OR_CREATE with open_only=1.
 *  type: 0=mutex, 1=event, 2=semaphore.
 *  Returns the type-biased handle on success, or 0 (treated as
 *  STATUS_OBJECT_NAME_NOT_FOUND by the caller) on miss / bad input.
 *
 * UNICODE_STRING / OBJECT_ATTRIBUTES layouts are inlined here so
 * this helper can live above the full typedefs further down in the
 * TU; field order matches the Win32 ABI exactly. */
static long long ntdll_named_kobj_open(unsigned int type, void* object_attributes)
{
    typedef struct
    {
        unsigned short Length;
        unsigned short MaximumLength;
        unsigned short* Buffer;
    } _OA_UniStr;
    typedef struct
    {
        unsigned long Length;
        void* RootDirectory;
        _OA_UniStr* ObjectName;
        unsigned long Attributes;
        void* SecurityDescriptor;
        void* SecurityQualityOfService;
    } _OA_View;
    if (object_attributes == (void*)0)
        return 0;
    _OA_View* oa = (_OA_View*)object_attributes;
    if (oa->ObjectName == (_OA_UniStr*)0 || oa->ObjectName->Buffer == (unsigned short*)0 || oa->ObjectName->Length == 0)
        return 0;
    char name[64] = {0};
    const unsigned short wchars = (unsigned short)(oa->ObjectName->Length / 2);
    unsigned short i = 0;
    for (; i < wchars && i < 63; ++i)
        name[i] = (char)(unsigned char)(oa->ObjectName->Buffer[i] & 0xFF);
    name[i] = 0;
    if (name[0] == 0)
        return 0;
    long long rv;
    register long long r10 __asm__("r10") = 0;
    register long long r8 __asm__("r8") = 1; /* open_only */
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)185), "D"((long long)type), "S"((long long)name), "d"((long long)64), "r"(r10),
                       "r"(r8)
                     : "memory");
    return rv;
}

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
    (void)DesiredAccess;
    if (MutantHandle == (HANDLE*)0)
        return NTSTATUS_INVALID_PARAMETER;
    const long long handle = ntdll_named_kobj_open(0, ObjectAttributes);
    if (handle <= 0)
        return (NTSTATUS)0xC0000034; /* STATUS_OBJECT_NAME_NOT_FOUND */
    *MutantHandle = (HANDLE)handle;
    return NTSTATUS_SUCCESS;
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
    (void)DesiredAccess;
    if (EventHandle == (HANDLE*)0)
        return NTSTATUS_INVALID_PARAMETER;
    const long long handle = ntdll_named_kobj_open(1, ObjectAttributes);
    if (handle <= 0)
        return (NTSTATUS)0xC0000034;
    *EventHandle = (HANDLE)handle;
    return NTSTATUS_SUCCESS;
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
