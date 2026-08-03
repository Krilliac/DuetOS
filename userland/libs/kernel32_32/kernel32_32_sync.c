/*
 * userland/libs/kernel32_32/kernel32_32_sync.c
 *
 * Synchronisation surface for the i386 (PE32) kernel32 companion:
 * mutexes, events, semaphores, waits, critical sections, SRW locks
 * and CreateThread. Mirrors userland/libs/kernel32/kernel32_sync.c
 * (the x86_64 sibling) in syscall usage and handle-band routing.
 *
 * THE i386 STRUCT-LAYOUT HAZARD, stated once for the whole file
 * -----------------------------------------------------------
 * Every caller-owned Win32 lock struct is HALF THE SIZE on i386,
 * because each of its fields is pointer-sized:
 *
 *     CRITICAL_SECTION   40 bytes on x86_64,  24 bytes on i386
 *     SRWLOCK             8 bytes on x86_64,   4 bytes on i386
 *     INIT_ONCE           8 bytes on x86_64,   4 bytes on i386
 *
 * The x86_64 sibling stores its private bookkeeping in `long long`
 * slots. Copying that here would write 8 bytes into a 4-byte SRWLOCK
 * and smash whatever the guest placed after it — a silent
 * memory-corruption bug that compiles clean and only shows up as a
 * wild fault somewhere else. Every slot below is therefore a 32-bit
 * `int`, and every offset is expressed in 4-byte units.
 *
 * The private layouts (both fit inside the real struct):
 *     CRITICAL_SECTION: [cs+0] owner TID (0 = unowned)
 *                       [cs+4] recursion count
 *     SRWLOCK:          [lock+0] owner TID (0 = unheld)
 */

#include "kernel32_32_internal.h"

#define WAIT_OBJECT_0 0u
#define WAIT_TIMEOUT 0x102u
#define WAIT_FAILED 0xFFFFFFFFu

/* Per-type handle span — the kernel's ipc::kHandleTableCapacity.
 * Mirrored here because a freestanding DLL cannot include the kernel
 * header; keep in sync with the same constant in the x86_64 sibling. */
#define WIN32_HANDLE_CAP_PER_TYPE 0x40u
#define DUET_KOBJECT_TAG_MASK 0xFFFu
#define DUET_KOBJECT_POSITIVE_MAX 0x7FFFFFFFu

static int duet32_is_kobject_handle(unsigned handle, unsigned tag_base)
{
    const unsigned low_tag = handle & DUET_KOBJECT_TAG_MASK;
    const unsigned generation = handle >> 12;
    return handle != 0 && handle <= DUET_KOBJECT_POSITIVE_MAX && generation != 0 && low_tag > tag_base &&
           low_tag < tag_base + WIN32_HANDLE_CAP_PER_TYPE;
}

static inline unsigned duet32_tid(void)
{
    return (unsigned)duet_syscall0(1 /* SYS_GETPID */);
}

/* ------------------------------------------------------------------
 * Named-object bookkeeping
 *
 * SYS_NAMED_KOBJ_OPEN_OR_CREATE (185) is the cross-process namespace:
 * rdi = type (0 mutex / 1 event / 2 semaphore), rsi = name, rdx =
 * name cap, r10 = type-specific init word, r8 = open_only.
 *
 * i386 ABI LIMIT: the kernel reads `init` as a u64, and the
 * semaphore encoding packs initial in the low half and maximum in the
 * HIGH half. arg4 arrives from esi zero-extended, so the high half is
 * unconditionally zero from a 32-bit caller — a named semaphore
 * created through 185 would come back with max_count == 0 and reject
 * every release. Named semaphores therefore take the unnamed
 * SYS_SEM_CREATE (51) path and are registered in the process-local
 * table below instead.
 *
 * GAP: named semaphores are process-local on i386 - two processes
 * opening the same semaphore name get two distinct objects. Mutexes
 * and events (whose init word fits in 32 bits) do reach the kernel
 * namespace and are shared correctly. Revisit if the kernel grows a
 * 6-argument named-create that splits initial/maximum across two
 * slots.
 * ------------------------------------------------------------------ */

#define DUET32_NAME_LEN 32
#define DUET32_NAME_SLOTS 16

#define DUET32_KIND_MUTEX 0
#define DUET32_KIND_EVENT 1
#define DUET32_KIND_SEM 2

static char g_name_text[DUET32_NAME_SLOTS][DUET32_NAME_LEN];
static unsigned g_name_kind[DUET32_NAME_SLOTS];
static unsigned g_name_handle[DUET32_NAME_SLOTS]; /* 0 = free slot */

/* Narrow a UTF-16 name to ASCII. Empty / NULL input yields "", which
 * every caller treats as "unnamed". */
static void duet32_name_w_to_a(const wchar_t16* w, char* dst)
{
    int i = 0;
    if (w != (const wchar_t16*)0)
    {
        for (; i < DUET32_NAME_LEN - 1 && w[i] != 0; ++i)
            dst[i] = (char)(w[i] & 0xFF);
    }
    dst[i] = 0;
}

static int duet32_name_eq(const char* a, const char* b)
{
    for (int i = 0; i < DUET32_NAME_LEN; ++i)
    {
        if (a[i] != b[i])
            return 0;
        if (a[i] == 0)
            return 1;
    }
    return 1;
}

static HANDLE duet32_name_lookup(unsigned kind, const char* name)
{
    for (int i = 0; i < DUET32_NAME_SLOTS; ++i)
    {
        if (g_name_handle[i] != 0 && g_name_kind[i] == kind && duet32_name_eq(g_name_text[i], name))
            return (HANDLE)(unsigned long)g_name_handle[i];
    }
    return (HANDLE)0;
}

static void duet32_name_register(unsigned kind, const char* name, HANDLE h)
{
    if (h == (HANDLE)0)
        return;
    for (int i = 0; i < DUET32_NAME_SLOTS; ++i)
    {
        if (g_name_handle[i] != 0)
            continue;
        int j = 0;
        for (; j < DUET32_NAME_LEN - 1 && name[j] != 0; ++j)
            g_name_text[i][j] = name[j];
        g_name_text[i][j] = 0;
        g_name_kind[i] = kind;
        g_name_handle[i] = (unsigned)(unsigned long)h;
        return;
    }
    /* Table full — the object still works, it just cannot be found
     * again by name from this process. */
}

/* Kernel namespace call. `init` is 32 bits wide here by construction;
 * see the ABI note above. */
static int duet32_named_kobj(unsigned kind, const char* name, unsigned init, int open_only)
{
    return duet_syscall5(185 /* SYS_NAMED_KOBJ_OPEN_OR_CREATE */, kind, (unsigned)(unsigned long)name, DUET32_NAME_LEN,
                         init, (unsigned)open_only);
}

/* ------------------------------------------------------------------
 * Mutexes — SYS_MUTEX_CREATE 25 / WAIT 26 / RELEASE 27
 * ------------------------------------------------------------------ */

__declspec(dllexport) HANDLE __stdcall CreateMutexA(void* sec, BOOL bInitialOwner, const char* name)
{
    (void)sec;
    if (name != (const char*)0 && name[0] != 0)
    {
        const int rv = duet32_named_kobj(DUET32_KIND_MUTEX, name, (unsigned)(bInitialOwner ? 1 : 0), 0);
        if (rv != -1)
        {
            duet32_name_register(DUET32_KIND_MUTEX, name, (HANDLE)(unsigned long)(unsigned)rv);
            return (HANDLE)(unsigned long)(unsigned)rv;
        }
        /* Kernel table full — fall through to an unnamed object so
         * the caller still gets something usable. */
    }
    const int rv = duet_syscall1(25 /* SYS_MUTEX_CREATE */, (unsigned)(bInitialOwner ? 1 : 0));
    if (rv < 0)
        return (HANDLE)0;
    HANDLE h = (HANDLE)(unsigned long)(unsigned)rv;
    if (name != (const char*)0 && name[0] != 0)
        duet32_name_register(DUET32_KIND_MUTEX, name, h);
    return h;
}

__declspec(dllexport) HANDLE __stdcall CreateMutexW(void* sec, BOOL bInitialOwner, const wchar_t16* name)
{
    char a_name[DUET32_NAME_LEN];
    duet32_name_w_to_a(name, a_name);
    return CreateMutexA(sec, bInitialOwner, a_name);
}

/* CreateMutexExW(sec, name, dwFlags, dwDesiredAccess) — the Vista+
 * spelling. CREATE_MUTEX_INITIAL_OWNER (0x1) carries what
 * bInitialOwner used to; dwDesiredAccess is not enforced (v0 tracks
 * no per-handle access masks, same as the x86_64 sibling's
 * OpenMutex*). */
__declspec(dllexport) HANDLE __stdcall CreateMutexExW(void* sec, const wchar_t16* name, DWORD dwFlags,
                                                      DWORD dwDesiredAccess)
{
    (void)dwDesiredAccess;
    return CreateMutexW(sec, (dwFlags & 0x00000001u) != 0 ? 1 : 0, name);
}

__declspec(dllexport) HANDLE __stdcall OpenMutexW(DWORD dwDesiredAccess, BOOL bInheritHandle, const wchar_t16* name)
{
    (void)dwDesiredAccess;
    (void)bInheritHandle;
    char a_name[DUET32_NAME_LEN];
    duet32_name_w_to_a(name, a_name);
    if (a_name[0] == 0)
        return (HANDLE)0;
    HANDLE local = duet32_name_lookup(DUET32_KIND_MUTEX, a_name);
    if (local != (HANDLE)0)
        return local;
    const int rv = duet32_named_kobj(DUET32_KIND_MUTEX, a_name, 0, 1 /* open_only */);
    if (rv == -1)
        return (HANDLE)0;
    duet32_name_register(DUET32_KIND_MUTEX, a_name, (HANDLE)(unsigned long)(unsigned)rv);
    return (HANDLE)(unsigned long)(unsigned)rv;
}

__declspec(dllexport) BOOL __stdcall ReleaseMutex(HANDLE h)
{
    return duet_syscall1(27 /* SYS_MUTEX_RELEASE */, (unsigned)(unsigned long)h) == 0 ? 1 : 0;
}

/* ------------------------------------------------------------------
 * Events — SYS_EVENT_CREATE 30 / SET 31 / RESET 32 / WAIT 33
 * ------------------------------------------------------------------ */

__declspec(dllexport) HANDLE __stdcall CreateEventA(void* sec, BOOL bManualReset, BOOL bInitialState, const char* name)
{
    (void)sec;
    if (name != (const char*)0 && name[0] != 0)
    {
        const unsigned init = (unsigned)((bManualReset ? 1 : 0) | (bInitialState ? 2 : 0));
        const int rv = duet32_named_kobj(DUET32_KIND_EVENT, name, init, 0);
        if (rv != -1)
        {
            duet32_name_register(DUET32_KIND_EVENT, name, (HANDLE)(unsigned long)(unsigned)rv);
            return (HANDLE)(unsigned long)(unsigned)rv;
        }
    }
    const int rv =
        duet_syscall2(30 /* SYS_EVENT_CREATE */, (unsigned)(bManualReset ? 1 : 0), (unsigned)(bInitialState ? 1 : 0));
    if (rv < 0)
        return (HANDLE)0;
    HANDLE h = (HANDLE)(unsigned long)(unsigned)rv;
    if (name != (const char*)0 && name[0] != 0)
        duet32_name_register(DUET32_KIND_EVENT, name, h);
    return h;
}

__declspec(dllexport) HANDLE __stdcall CreateEventW(void* sec, BOOL bManualReset, BOOL bInitialState,
                                                    const wchar_t16* name)
{
    char a_name[DUET32_NAME_LEN];
    duet32_name_w_to_a(name, a_name);
    return CreateEventA(sec, bManualReset, bInitialState, a_name);
}

__declspec(dllexport) BOOL __stdcall SetEvent(HANDLE h)
{
    return duet_syscall1(31 /* SYS_EVENT_SET */, (unsigned)(unsigned long)h) == 0 ? 1 : 0;
}

__declspec(dllexport) BOOL __stdcall ResetEvent(HANDLE h)
{
    return duet_syscall1(32 /* SYS_EVENT_RESET */, (unsigned)(unsigned long)h) == 0 ? 1 : 0;
}

/* ------------------------------------------------------------------
 * Semaphores — SYS_SEM_CREATE 51 / RELEASE 52 / WAIT 53
 * ------------------------------------------------------------------ */

__declspec(dllexport) HANDLE __stdcall CreateSemaphoreA(void* sec, long initial, long maximum, const char* name)
{
    (void)sec;
    /* Named semaphores stay process-local — see the ABI note at the
     * top of the named-object section. */
    if (name != (const char*)0 && name[0] != 0)
    {
        HANDLE local = duet32_name_lookup(DUET32_KIND_SEM, name);
        if (local != (HANDLE)0)
            return local;
    }
    const int rv = duet_syscall2(51 /* SYS_SEM_CREATE */, (unsigned)initial, (unsigned)maximum);
    if (rv < 0)
        return (HANDLE)0;
    HANDLE h = (HANDLE)(unsigned long)(unsigned)rv;
    if (name != (const char*)0 && name[0] != 0)
        duet32_name_register(DUET32_KIND_SEM, name, h);
    return h;
}

__declspec(dllexport) HANDLE __stdcall CreateSemaphoreW(void* sec, long initial, long maximum, const wchar_t16* name)
{
    char a_name[DUET32_NAME_LEN];
    duet32_name_w_to_a(name, a_name);
    return CreateSemaphoreA(sec, initial, maximum, a_name);
}

/* CreateSemaphoreExW(sec, initial, maximum, name, dwFlags, access) —
 * dwFlags is documented as reserved-must-be-zero, so it is accepted
 * and ignored rather than validated. */
__declspec(dllexport) HANDLE __stdcall CreateSemaphoreExW(void* sec, long initial, long maximum, const wchar_t16* name,
                                                          DWORD dwFlags, DWORD dwDesiredAccess)
{
    (void)dwFlags;
    (void)dwDesiredAccess;
    return CreateSemaphoreW(sec, initial, maximum, name);
}

__declspec(dllexport) HANDLE __stdcall OpenSemaphoreW(DWORD dwDesiredAccess, BOOL bInheritHandle, const wchar_t16* name)
{
    (void)dwDesiredAccess;
    (void)bInheritHandle;
    char a_name[DUET32_NAME_LEN];
    duet32_name_w_to_a(name, a_name);
    if (a_name[0] == 0)
        return (HANDLE)0;
    return duet32_name_lookup(DUET32_KIND_SEM, a_name);
}

/* ReleaseSemaphore — SYS_SEM_RELEASE returns the PREVIOUS count on
 * success and u64(-1) on failure (see DoSemRelease in
 * kernel/subsystems/win32/semaphore_syscall.cpp). A non-zero previous
 * count is therefore SUCCESS, not failure, and it is exactly what
 * lpPreviousCount wants. */
__declspec(dllexport) BOOL __stdcall ReleaseSemaphore(HANDLE h, long releaseCount, long* lpPreviousCount)
{
    const int rv = duet_syscall2(52 /* SYS_SEM_RELEASE */, (unsigned)(unsigned long)h, (unsigned)releaseCount);
    if (rv < 0)
        return 0;
    if (lpPreviousCount != (long*)0)
        *lpPreviousCount = (long)rv;
    return 1;
}

/* ------------------------------------------------------------------
 * Waits — dispatch by handle band, matching the x86_64 sibling
 * ------------------------------------------------------------------ */

__declspec(dllexport) DWORD __stdcall WaitForSingleObject(HANDLE h, DWORD timeout_ms)
{
    const unsigned handle = (unsigned)(unsigned long)h;
    int syscall_num;
    if (duet32_is_kobject_handle(handle, 0x200u))
        syscall_num = 26; /* SYS_MUTEX_WAIT */
    else if (duet32_is_kobject_handle(handle, 0x300u))
        syscall_num = 33; /* SYS_EVENT_WAIT */
    else if (duet32_is_kobject_handle(handle, 0x500u))
        syscall_num = 53; /* SYS_SEM_WAIT */
    else if (handle >= 0x400u && handle < 0x400u + WIN32_HANDLE_CAP_PER_TYPE)
        syscall_num = 54; /* SYS_THREAD_WAIT */
    else
        return WAIT_OBJECT_0; /* Unknown handle — pseudo-signal, as on x86_64. */
    return (DWORD)duet_syscall2(syscall_num, handle, timeout_ms);
}

/* WaitForSingleObjectEx — the i386 companion has no APC queue (no
 * QueueUserAPC export), so an alertable wait has nothing to be
 * alerted by and degrades to the plain wait. */
// GAP: bAlertable is accepted but never returns WAIT_IO_COMPLETION -
// the i386 set exports no QueueUserAPC, so no APC can ever be pending.
// Revisit together with a 32-bit QueueUserAPC.
__declspec(dllexport) DWORD __stdcall WaitForSingleObjectEx(HANDLE h, DWORD timeout_ms, BOOL bAlertable)
{
    (void)bAlertable;
    return WaitForSingleObject(h, timeout_ms);
}

/* ------------------------------------------------------------------
 * Critical sections — 24-byte i386 struct, 4-byte private slots
 * ------------------------------------------------------------------ */

__declspec(dllexport) void __stdcall InitializeCriticalSection(void* cs)
{
    if (cs == (void*)0)
        return;
    unsigned char* b = (unsigned char*)cs;
    for (int i = 0; i < 24; ++i) /* sizeof(RTL_CRITICAL_SECTION) on i386 */
        b[i] = 0;
}

__declspec(dllexport) BOOL __stdcall InitializeCriticalSectionAndSpinCount(void* cs, DWORD dwSpinCount)
{
    (void)dwSpinCount; /* Spin count is advisory; we always spin-and-yield. */
    InitializeCriticalSection(cs);
    return 1;
}

__declspec(dllexport) BOOL __stdcall InitializeCriticalSectionEx(void* cs, DWORD dwSpinCount, DWORD dwFlags)
{
    (void)dwSpinCount;
    (void)dwFlags;
    InitializeCriticalSection(cs);
    return 1;
}

__declspec(dllexport) void __stdcall DeleteCriticalSection(void* cs)
{
    (void)cs; /* Nothing was allocated; nothing to release. */
}

__declspec(dllexport) void __stdcall EnterCriticalSection(void* cs)
{
    if (cs == (void*)0)
        return;
    int volatile* owner = (int volatile*)cs;
    int volatile* recursion = owner + 1;
    const int tid = (int)duet32_tid();
    for (;;)
    {
        int expected = 0;
        if (__atomic_compare_exchange_n(owner, &expected, tid, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
        {
            *recursion = 1;
            return;
        }
        if (expected == tid)
        {
            *recursion = *recursion + 1; /* Win32 critical sections are recursive. */
            return;
        }
        duet_syscall0(3 /* SYS_YIELD */);
    }
}

__declspec(dllexport) BOOL __stdcall TryEnterCriticalSection(void* cs)
{
    if (cs == (void*)0)
        return 0;
    int volatile* owner = (int volatile*)cs;
    int volatile* recursion = owner + 1;
    const int tid = (int)duet32_tid();
    int expected = 0;
    if (__atomic_compare_exchange_n(owner, &expected, tid, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
    {
        *recursion = 1;
        return 1;
    }
    if (expected == tid)
    {
        *recursion = *recursion + 1;
        return 1;
    }
    return 0; /* Contended — do NOT spin, that is the whole contract. */
}

__declspec(dllexport) void __stdcall LeaveCriticalSection(void* cs)
{
    if (cs == (void*)0)
        return;
    int volatile* owner = (int volatile*)cs;
    int volatile* recursion = owner + 1;
    const int next = *recursion - 1;
    *recursion = next;
    if (next <= 0)
        __atomic_store_n(owner, 0, __ATOMIC_RELEASE);
}

/* ------------------------------------------------------------------
 * SRW locks — 4-byte i386 struct, exclusive only
 *
 * Real Win32 SRW locks are NOT recursive: a second exclusive acquire
 * from the owning thread deadlocks. That contract is preserved (the
 * CAS below never matches its own TID as a success case), so a guest
 * that misuses one hangs here exactly as it would on Windows rather
 * than silently proceeding.
 * ------------------------------------------------------------------ */

__declspec(dllexport) void __stdcall InitializeSRWLock(void* lock)
{
    if (lock != (void*)0)
        __atomic_store_n((int volatile*)lock, 0, __ATOMIC_RELEASE);
}

__declspec(dllexport) void __stdcall AcquireSRWLockExclusive(void* lock)
{
    if (lock == (void*)0)
        return;
    int volatile* p = (int volatile*)lock;
    const int tid = (int)duet32_tid();
    for (;;)
    {
        int expected = 0;
        if (__atomic_compare_exchange_n(p, &expected, tid, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
            return;
        duet_syscall0(3 /* SYS_YIELD */);
    }
}

__declspec(dllexport) void __stdcall ReleaseSRWLockExclusive(void* lock)
{
    if (lock != (void*)0)
        __atomic_store_n((int volatile*)lock, 0, __ATOMIC_RELEASE);
}

__declspec(dllexport) BOOL __stdcall TryAcquireSRWLockExclusive(void* lock)
{
    if (lock == (void*)0)
        return 0;
    int volatile* p = (int volatile*)lock;
    int expected = 0;
    return __atomic_compare_exchange_n(p, &expected, (int)duet32_tid(), 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST) ? 1 : 0;
}

/* Shared acquires collapse to exclusive in v0 — correctness over
 * concurrency, same choice as the x86_64 sibling. */
__declspec(dllexport) void __stdcall AcquireSRWLockShared(void* lock)
{
    AcquireSRWLockExclusive(lock);
}

__declspec(dllexport) void __stdcall ReleaseSRWLockShared(void* lock)
{
    ReleaseSRWLockExclusive(lock);
}

/* ------------------------------------------------------------------
 * Threads — SYS_THREAD_CREATE 45
 * ------------------------------------------------------------------ */

typedef DWORD(__stdcall* Duet32ThreadStartFn)(void*);

__declspec(dllexport) HANDLE __stdcall CreateThread(void* lpThreadAttributes, unsigned dwStackSize,
                                                    Duet32ThreadStartFn lpStartAddress, void* lpParameter,
                                                    DWORD dwCreationFlags, DWORD* lpThreadId)
{
    (void)lpThreadAttributes;
    (void)dwStackSize;     /* The kernel picks the ring-3 stack size. */
    (void)dwCreationFlags; /* CREATE_SUSPENDED is not modelled; see ResumeThread. */
    const int rv = duet_syscall2(45 /* SYS_THREAD_CREATE */, (unsigned)(unsigned long)lpStartAddress,
                                 (unsigned)(unsigned long)lpParameter);
    if (rv < 0)
    {
        if (lpThreadId != (DWORD*)0)
            *lpThreadId = 0;
        return (HANDLE)0;
    }
    if (lpThreadId != (DWORD*)0)
        *lpThreadId = (DWORD)rv;
    return (HANDLE)(unsigned long)(unsigned)rv;
}
