#include "kernel32_internal.h"

/* ------------------------------------------------------------------
 * Time queries
 *
 * SYS_GETTIME_FT = 17 — Windows FILETIME (100 ns ticks since 1601).
 * SYS_NOW_NS     = 18 — nanoseconds since boot (HPET-backed).
 *
 * QueryPerformanceFrequency reports 1 GHz so QPC/QPF division
 * yields seconds with ~70 ns granularity.
 * ------------------------------------------------------------------ */

__declspec(dllexport) void GetSystemTimeAsFileTime(long long* lpFileTime)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)17) : "memory");
    if (lpFileTime != (long long*)0)
        *lpFileTime = rv;
}

__declspec(dllexport) BOOL QueryPerformanceCounter(long long* lpPerformanceCount)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)18) : "memory");
    if (lpPerformanceCount != (long long*)0)
        *lpPerformanceCount = rv;
    return 1;
}

__declspec(dllexport) BOOL QueryPerformanceFrequency(long long* lpFrequency)
{
    /* 1 GHz — pairs with QPC's nanosecond return so subtraction
     * + division yields seconds. */
    if (lpFrequency != (long long*)0)
        *lpFrequency = 1000000000LL;
    return 1;
}

/* ------------------------------------------------------------------
 * Heap aliases
 *
 * These all alias to the per-process heap via SYS_HEAP_*.
 * GetProcessHeap returns a sentinel; HeapAlloc/Free/Size/ReAlloc
 * ignore the heap handle (single-heap-per-process v0). HeapCreate /
 * HeapDestroy pretend to succeed.
 * ------------------------------------------------------------------ */

__declspec(dllexport) HANDLE GetProcessHeap(void)
{
    /* Sentinel — matches the kernel-side default-heap base
     * (kWin32HeapVa = 0x50000000). The kernel resolves both 0
     * and 0x50000000 to the default heap; either value is
     * legal for routing. */
    return (HANDLE)0x50000000ULL;
}

/* HeapAlloc / HeapFree / HeapSize / HeapReAlloc — route through
 * SYS_HEAPEX_* (192-197) so a HeapCreate-supplied heap handle
 * targets the right secondary heap. The default-heap sentinel
 * (0x50000000) and 0 both resolve to the per-process default
 * heap on the kernel side. dwFlags is honoured for HEAP_ZERO_MEMORY
 * (0x00000008) — the alloc paths zero the payload before
 * returning. Other flags (HEAP_GENERATE_EXCEPTIONS,
 * HEAP_NO_SERIALIZE) are ignored.
 */
#define HEAP_ZERO_MEMORY 0x00000008u

__declspec(dllexport) void* HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)194), /* SYS_HEAPEX_ALLOC */
                       "D"((long long)(unsigned long long)(UINT_PTR)hHeap), "S"((long long)dwBytes)
                     : "memory");
    if (rv != 0 && (dwFlags & HEAP_ZERO_MEMORY) != 0)
    {
        unsigned char* dst = (unsigned char*)(unsigned long long)rv;
        for (SIZE_T i = 0; i < dwBytes; ++i)
            dst[i] = 0;
    }
    return (void*)rv;
}

__declspec(dllexport) BOOL HeapFree(HANDLE hHeap, DWORD dwFlags, void* lpMem)
{
    (void)dwFlags;
    if (lpMem == (void*)0)
        return 1;
    long long discard;
    __asm__ volatile("int $0x80"
                     : "=a"(discard)
                     : "a"((long long)195), /* SYS_HEAPEX_FREE */
                       "D"((long long)(unsigned long long)(UINT_PTR)hHeap), "S"((long long)lpMem)
                     : "memory");
    return 1;
}

__declspec(dllexport) SIZE_T HeapSize(HANDLE hHeap, DWORD dwFlags, const void* lpMem)
{
    (void)dwFlags;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)196), /* SYS_HEAPEX_SIZE */
                       "D"((long long)(unsigned long long)(UINT_PTR)hHeap), "S"((long long)lpMem)
                     : "memory");
    return (SIZE_T)rv;
}

__declspec(dllexport) void* HeapReAlloc(HANDLE hHeap, DWORD dwFlags, void* lpMem, SIZE_T dwBytes)
{
    (void)dwFlags;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)197), /* SYS_HEAPEX_REALLOC */
                       "D"((long long)(unsigned long long)(UINT_PTR)hHeap), "S"((long long)lpMem),
                       "d"((long long)dwBytes)
                     : "memory");
    return (void*)rv;
}

__declspec(dllexport) HANDLE HeapCreate(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize)
{
    (void)flOptions;
    (void)dwMaximumSize;
    /* Round initial size up to pages (4 KiB). Cap at 16 pages
     * (kWin32ExtraHeapPagesMax) on the kernel side; passing more
     * is silently clamped. dwInitialSize == 0 -> 1 page. */
    unsigned long long pages = ((unsigned long long)dwInitialSize + 0xFFFULL) >> 12;
    if (pages == 0)
        pages = 1;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)192), /* SYS_HEAPEX_CREATE */
                       "D"((long long)pages)
                     : "memory");
    if (rv == 0)
        return (HANDLE)0;
    return (HANDLE)(UINT_PTR)rv;
}

__declspec(dllexport) BOOL HeapDestroy(HANDLE hHeap)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)193), /* SYS_HEAPEX_DESTROY */
                       "D"((long long)(unsigned long long)(UINT_PTR)hHeap)
                     : "memory");
    return rv != 0;
}

/* ------------------------------------------------------------------
 * Locale / code page
 *
 * v0 reports a US-English / Latin-1 locale across the board.
 * Programs that branch on these mostly just want a sane default.
 * ------------------------------------------------------------------ */

__declspec(dllexport) UINT GetACP(void)
{
    return 1252; /* Western European Latin-1 ANSI code page. */
}

__declspec(dllexport) UINT GetOEMCP(void)
{
    return 437; /* Same as GetConsoleCP. */
}

__declspec(dllexport) BOOL IsValidCodePage(UINT codepage)
{
    /* Accept 437 / 1252 (the two we report) and 65001 (UTF-8). */
    return (codepage == 437 || codepage == 1252 || codepage == 65001) ? 1 : 0;
}

/* ------------------------------------------------------------------
 * MultiByteToWideChar / WideCharToMultiByte
 *
 * v0 only supports a 1:1 byte-to-wchar conversion (low byte of
 * the wchar = the source byte). Sufficient for ASCII and
 * passable for Latin-1; ignores codepage entirely. The flat
 * stubs at kOffMBtoWC / kOffWCtoMB do the same.
 * ------------------------------------------------------------------ */

__declspec(dllexport) int MultiByteToWideChar(UINT codepage, DWORD dwFlags, const char* lpMultiByteStr, int cbMultiByte,
                                              wchar_t16* lpWideCharStr, int cchWideChar)
{
    (void)codepage;
    (void)dwFlags;
    if (lpMultiByteStr == (const char*)0)
        return 0;
    /* cbMultiByte == -1 means "input is NUL-terminated; include
     * the terminator in the output". Compute length first. */
    int in_len;
    if (cbMultiByte < 0)
    {
        int n = 0;
        while (lpMultiByteStr[n] != 0)
            ++n;
        in_len = n + 1; /* include the NUL */
    }
    else
        in_len = cbMultiByte;
    if (cchWideChar == 0 || lpWideCharStr == (wchar_t16*)0)
        return in_len; /* Caller is asking for required size. */
    int copy = in_len < cchWideChar ? in_len : cchWideChar;
    for (int i = 0; i < copy; ++i)
        lpWideCharStr[i] = (wchar_t16)(unsigned char)lpMultiByteStr[i];
    return copy;
}

__declspec(dllexport) int WideCharToMultiByte(UINT codepage, DWORD dwFlags, const wchar_t16* lpWideCharStr,
                                              int cchWideChar, char* lpMultiByteStr, int cbMultiByte,
                                              const char* lpDefaultChar, BOOL* lpUsedDefaultChar)
{
    (void)codepage;
    (void)dwFlags;
    (void)lpDefaultChar;
    if (lpUsedDefaultChar != (BOOL*)0)
        *lpUsedDefaultChar = 0;
    if (lpWideCharStr == (const WCHAR_t*)0)
        return 0;
    int in_len;
    if (cchWideChar < 0)
    {
        int n = 0;
        while (lpWideCharStr[n] != 0)
            ++n;
        in_len = n + 1;
    }
    else
        in_len = cchWideChar;
    if (cbMultiByte == 0 || lpMultiByteStr == (char*)0)
        return in_len;
    int copy = in_len < cbMultiByte ? in_len : cbMultiByte;
    for (int i = 0; i < copy; ++i)
        lpMultiByteStr[i] = (char)(lpWideCharStr[i] & 0xFF);
    return copy;
}

/* ------------------------------------------------------------------
 * TLS slots
 *
 * SYS_TLS_ALLOC = 34 / FREE = 35 / GET = 36 / SET = 37.
 * Per-process TLS table backs all four. TLS_OUT_OF_INDEXES =
 * 0xFFFFFFFF returned on alloc failure / invalid slot.
 * ------------------------------------------------------------------ */

__declspec(dllexport) DWORD TlsAlloc(void)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)34) : "memory");
    /* Kernel returns u32(-1) on failure; pass through. */
    return (DWORD)rv;
}

__declspec(dllexport) BOOL TlsFree(DWORD slot)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)35), "D"((long long)slot) : "memory");
    return rv == 0 ? 1 : 0;
}

__declspec(dllexport) void* TlsGetValue(DWORD slot)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)36), "D"((long long)slot) : "memory");
    return (void*)rv;
}

__declspec(dllexport) BOOL TlsSetValue(DWORD slot, void* value)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)37), "D"((long long)slot), "S"((long long)value)
                     : "memory");
    return rv == 0 ? 1 : 0;
}

/* ------------------------------------------------------------------
 * Win32 sync primitives — handle-based
 *
 * Kernel state lives in Process tables (mutex, event,
 * semaphore, thread). Handles are kWin32{Mutex,Event,Sem,Thread}
 * Base + slot index. Each Create/Release/Wait routes to the
 * matching SYS_* call.
 *
 * NAMED PRIMITIVES (T6-04 v0):
 *   The kernel doesn't yet have a cross-process named-namespace,
 *   so the table below is process-local. CreateMutex/Event/
 *   Semaphore with a non-NULL name first scans the table; on hit
 *   the existing handle is returned (with refcount semantics so
 *   the second caller's CloseHandle doesn't leak the kernel-side
 *   primitive). On miss, a fresh kernel handle is allocated and a
 *   slot recorded. OpenMutex/Event/Semaphore consult the same
 *   table and fail with NULL if the name isn't present in this
 *   process. Cross-process named sync waits for a kernel-resident
 *   namespace (T6-04 follow-on).
 * ------------------------------------------------------------------ */

#define WIN32_NAME_SLOTS 32
#define WIN32_NAME_KIND_MUTEX 1
#define WIN32_NAME_KIND_EVENT 2
#define WIN32_NAME_KIND_SEM 3
#define WIN32_NAME_LEN 64

typedef struct Win32NamedHandleSlot
{
    int in_use;
    int kind; /* WIN32_NAME_KIND_* */
    HANDLE handle;
    char name[WIN32_NAME_LEN];
} Win32NamedHandleSlot;

static Win32NamedHandleSlot g_named_handles[WIN32_NAME_SLOTS];

static int win32_name_eq(const char* a, const char* b)
{
    int i = 0;
    while (a[i] && b[i] && a[i] == b[i] && i < WIN32_NAME_LEN - 1)
        ++i;
    return a[i] == b[i];
}

static void win32_name_copy(const char* src, char* dst)
{
    int i = 0;
    if (!src)
    {
        dst[0] = 0;
        return;
    }
    for (; src[i] && i < WIN32_NAME_LEN - 1; ++i)
        dst[i] = src[i];
    dst[i] = 0;
}

static HANDLE win32_named_lookup(int kind, const char* name)
{
    if (!name || name[0] == 0)
        return (HANDLE)0;
    for (int i = 0; i < WIN32_NAME_SLOTS; ++i)
    {
        if (g_named_handles[i].in_use && g_named_handles[i].kind == kind &&
            win32_name_eq(g_named_handles[i].name, name))
        {
            return g_named_handles[i].handle;
        }
    }
    return (HANDLE)0;
}

static void win32_named_register(int kind, const char* name, HANDLE handle)
{
    if (!name || name[0] == 0)
        return;
    for (int i = 0; i < WIN32_NAME_SLOTS; ++i)
    {
        if (!g_named_handles[i].in_use)
        {
            g_named_handles[i].in_use = 1;
            g_named_handles[i].kind = kind;
            g_named_handles[i].handle = handle;
            win32_name_copy(name, g_named_handles[i].name);
            return;
        }
    }
    /* Table full — caller still gets the handle, just no name lookup. */
}

/* Convert a wide name to char buffer (low byte). NULL → empty. */
static void win32_name_w_to_a(const WCHAR_t* w, char* dst)
{
    if (!w)
    {
        dst[0] = 0;
        return;
    }
    int i = 0;
    for (; w[i] && i < WIN32_NAME_LEN - 1; ++i)
        dst[i] = (char)(unsigned char)(w[i] & 0xFF);
    dst[i] = 0;
}

/* SYS_NAMED_KOBJ_OPEN_OR_CREATE = 185. type: 0=mutex, 1=event,
 * 2=semaphore. open_only=1 for the Open* family (fail with -1
 * if no existing entry); 0 for the Create* family. Returns the
 * type-biased handle on success, (long long)-1 on failure. */
static long long win32_named_kobj_call(unsigned int type, const char* name, unsigned long long init, int open_only)
{
    long long rv;
    register long long r10 __asm__("r10") = (long long)init;
    register long long r8 __asm__("r8") = (long long)open_only;
    /* Pass the maximum cap (64) as length cap so the kernel
     * walks at most 64 bytes — bounded by the user's NUL. */
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)185), "D"((long long)type), "S"((long long)name), "d"((long long)WIN32_NAME_LEN),
                       "r"(r10), "r"(r8)
                     : "memory");
    return rv;
}

__declspec(dllexport) HANDLE CreateMutexW(void* sec, BOOL bInitialOwner, const WCHAR_t* name)
{
    (void)sec;
    char a_name[WIN32_NAME_LEN];
    win32_name_w_to_a(name, a_name);
    if (a_name[0] != 0)
    {
        /* Named — route through the kernel-resident namespace
         * (T6-04). Two processes opening the same name see the
         * same kernel object. */
        long long rv = win32_named_kobj_call(0 /*mutex*/, a_name, (unsigned long long)bInitialOwner, 0);
        if (rv != -1)
        {
            win32_named_register(WIN32_NAME_KIND_MUTEX, a_name, (HANDLE)rv);
            return (HANDLE)rv;
        }
        /* Kernel-side dedup failed (table full / OOM) — fall
         * through to the unnamed create path so the caller
         * still gets a usable handle. */
    }
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)25), "D"((long long)bInitialOwner) : "memory");
    HANDLE h = (HANDLE)rv;
    if (a_name[0] != 0 && h != (HANDLE)0)
        win32_named_register(WIN32_NAME_KIND_MUTEX, a_name, h);
    return h;
}

__declspec(dllexport) HANDLE CreateMutexA(void* sec, BOOL bInitialOwner, const char* name)
{
    (void)sec;
    if (name && name[0] != 0)
    {
        long long rv = win32_named_kobj_call(0 /*mutex*/, name, (unsigned long long)bInitialOwner, 0);
        if (rv != -1)
        {
            win32_named_register(WIN32_NAME_KIND_MUTEX, name, (HANDLE)rv);
            return (HANDLE)rv;
        }
    }
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)25), "D"((long long)bInitialOwner) : "memory");
    HANDLE h = (HANDLE)rv;
    if (name && name[0] != 0 && h != (HANDLE)0)
        win32_named_register(WIN32_NAME_KIND_MUTEX, name, h);
    return h;
}

/* OpenMutexA/W — look up the kernel-resident named-object table.
 * dwDesiredAccess + bInheritHandle are accepted but not enforced;
 * v0 doesn't track per-handle access masks. Returns NULL with
 * ERROR_FILE_NOT_FOUND-equivalent semantics on miss. */
__declspec(dllexport) HANDLE OpenMutexA(DWORD dwDesiredAccess, BOOL bInheritHandle, const char* name)
{
    (void)dwDesiredAccess;
    (void)bInheritHandle;
    if (!name || name[0] == 0)
        return (HANDLE)0;
    /* Process-local cache hit short-circuits the syscall. */
    HANDLE local = win32_named_lookup(WIN32_NAME_KIND_MUTEX, name);
    if (local)
        return local;
    long long rv = win32_named_kobj_call(0 /*mutex*/, name, 0, 1 /*open_only*/);
    if (rv == -1)
        return (HANDLE)0;
    win32_named_register(WIN32_NAME_KIND_MUTEX, name, (HANDLE)rv);
    return (HANDLE)rv;
}

__declspec(dllexport) HANDLE OpenMutexW(DWORD dwDesiredAccess, BOOL bInheritHandle, const WCHAR_t* name)
{
    (void)dwDesiredAccess;
    (void)bInheritHandle;
    char a_name[WIN32_NAME_LEN];
    win32_name_w_to_a(name, a_name);
    if (a_name[0] == 0)
        return (HANDLE)0;
    HANDLE local = win32_named_lookup(WIN32_NAME_KIND_MUTEX, a_name);
    if (local)
        return local;
    long long rv = win32_named_kobj_call(0 /*mutex*/, a_name, 0, 1 /*open_only*/);
    if (rv == -1)
        return (HANDLE)0;
    win32_named_register(WIN32_NAME_KIND_MUTEX, a_name, (HANDLE)rv);
    return (HANDLE)rv;
}

__declspec(dllexport) BOOL ReleaseMutex(HANDLE h)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)27), "D"((long long)h) : "memory");
    return rv == 0 ? 1 : 0;
}

__declspec(dllexport) HANDLE CreateEventW(void* sec, BOOL bManualReset, BOOL bInitialState, const WCHAR_t* name)
{
    (void)sec;
    char a_name[WIN32_NAME_LEN];
    win32_name_w_to_a(name, a_name);
    if (a_name[0] != 0)
    {
        unsigned long long init = (unsigned long long)((bManualReset ? 1 : 0) | (bInitialState ? 2 : 0));
        long long rv = win32_named_kobj_call(1 /*event*/, a_name, init, 0);
        if (rv != -1)
        {
            win32_named_register(WIN32_NAME_KIND_EVENT, a_name, (HANDLE)rv);
            return (HANDLE)rv;
        }
    }
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)30), "D"((long long)bManualReset), "S"((long long)bInitialState)
                     : "memory");
    HANDLE h = (HANDLE)rv;
    if (a_name[0] != 0 && h != (HANDLE)0)
        win32_named_register(WIN32_NAME_KIND_EVENT, a_name, h);
    return h;
}

__declspec(dllexport) HANDLE CreateEventA(void* sec, BOOL bManualReset, BOOL bInitialState, const char* name)
{
    (void)sec;
    if (name && name[0] != 0)
    {
        unsigned long long init = (unsigned long long)((bManualReset ? 1 : 0) | (bInitialState ? 2 : 0));
        long long rv = win32_named_kobj_call(1 /*event*/, name, init, 0);
        if (rv != -1)
        {
            win32_named_register(WIN32_NAME_KIND_EVENT, name, (HANDLE)rv);
            return (HANDLE)rv;
        }
    }
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)30), "D"((long long)bManualReset), "S"((long long)bInitialState)
                     : "memory");
    HANDLE h = (HANDLE)rv;
    if (name && name[0] != 0 && h != (HANDLE)0)
        win32_named_register(WIN32_NAME_KIND_EVENT, name, h);
    return h;
}

__declspec(dllexport) HANDLE OpenEventA(DWORD dwDesiredAccess, BOOL bInheritHandle, const char* name)
{
    (void)dwDesiredAccess;
    (void)bInheritHandle;
    if (!name || name[0] == 0)
        return (HANDLE)0;
    HANDLE local = win32_named_lookup(WIN32_NAME_KIND_EVENT, name);
    if (local)
        return local;
    long long rv = win32_named_kobj_call(1 /*event*/, name, 0, 1 /*open_only*/);
    if (rv == -1)
        return (HANDLE)0;
    win32_named_register(WIN32_NAME_KIND_EVENT, name, (HANDLE)rv);
    return (HANDLE)rv;
}

__declspec(dllexport) HANDLE OpenEventW(DWORD dwDesiredAccess, BOOL bInheritHandle, const WCHAR_t* name)
{
    (void)dwDesiredAccess;
    (void)bInheritHandle;
    char a_name[WIN32_NAME_LEN];
    win32_name_w_to_a(name, a_name);
    if (a_name[0] == 0)
        return (HANDLE)0;
    HANDLE local = win32_named_lookup(WIN32_NAME_KIND_EVENT, a_name);
    if (local)
        return local;
    long long rv = win32_named_kobj_call(1 /*event*/, a_name, 0, 1 /*open_only*/);
    if (rv == -1)
        return (HANDLE)0;
    win32_named_register(WIN32_NAME_KIND_EVENT, a_name, (HANDLE)rv);
    return (HANDLE)rv;
}

__declspec(dllexport) BOOL SetEvent(HANDLE h)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)31), "D"((long long)h) : "memory");
    return rv == 0 ? 1 : 0;
}

__declspec(dllexport) BOOL ResetEvent(HANDLE h)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)32), "D"((long long)h) : "memory");
    return rv == 0 ? 1 : 0;
}

__declspec(dllexport) HANDLE CreateSemaphoreW(void* sec, long initial, long maximum, const WCHAR_t* name)
{
    (void)sec;
    char a_name[WIN32_NAME_LEN];
    win32_name_w_to_a(name, a_name);
    if (a_name[0] != 0)
    {
        unsigned long long init =
            ((unsigned long long)(unsigned long)initial) | (((unsigned long long)(unsigned long)maximum) << 32);
        long long rv = win32_named_kobj_call(2 /*sem*/, a_name, init, 0);
        if (rv != -1)
        {
            win32_named_register(WIN32_NAME_KIND_SEM, a_name, (HANDLE)rv);
            return (HANDLE)rv;
        }
    }
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)51), "D"((long long)initial), "S"((long long)maximum)
                     : "memory");
    HANDLE h = (HANDLE)rv;
    if (a_name[0] != 0 && h != (HANDLE)0)
        win32_named_register(WIN32_NAME_KIND_SEM, a_name, h);
    return h;
}

__declspec(dllexport) HANDLE CreateSemaphoreA(void* sec, long initial, long maximum, const char* name)
{
    (void)sec;
    if (name && name[0] != 0)
    {
        unsigned long long init =
            ((unsigned long long)(unsigned long)initial) | (((unsigned long long)(unsigned long)maximum) << 32);
        long long rv = win32_named_kobj_call(2 /*sem*/, name, init, 0);
        if (rv != -1)
        {
            win32_named_register(WIN32_NAME_KIND_SEM, name, (HANDLE)rv);
            return (HANDLE)rv;
        }
    }
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)51), "D"((long long)initial), "S"((long long)maximum)
                     : "memory");
    HANDLE h = (HANDLE)rv;
    if (name && name[0] != 0 && h != (HANDLE)0)
        win32_named_register(WIN32_NAME_KIND_SEM, name, h);
    return h;
}

__declspec(dllexport) HANDLE OpenSemaphoreA(DWORD dwDesiredAccess, BOOL bInheritHandle, const char* name)
{
    (void)dwDesiredAccess;
    (void)bInheritHandle;
    if (!name || name[0] == 0)
        return (HANDLE)0;
    HANDLE local = win32_named_lookup(WIN32_NAME_KIND_SEM, name);
    if (local)
        return local;
    long long rv = win32_named_kobj_call(2 /*sem*/, name, 0, 1 /*open_only*/);
    if (rv == -1)
        return (HANDLE)0;
    win32_named_register(WIN32_NAME_KIND_SEM, name, (HANDLE)rv);
    return (HANDLE)rv;
}

__declspec(dllexport) HANDLE OpenSemaphoreW(DWORD dwDesiredAccess, BOOL bInheritHandle, const WCHAR_t* name)
{
    (void)dwDesiredAccess;
    (void)bInheritHandle;
    char a_name[WIN32_NAME_LEN];
    win32_name_w_to_a(name, a_name);
    if (a_name[0] == 0)
        return (HANDLE)0;
    HANDLE local = win32_named_lookup(WIN32_NAME_KIND_SEM, a_name);
    if (local)
        return local;
    long long rv = win32_named_kobj_call(2 /*sem*/, a_name, 0, 1 /*open_only*/);
    if (rv == -1)
        return (HANDLE)0;
    win32_named_register(WIN32_NAME_KIND_SEM, a_name, (HANDLE)rv);
    return (HANDLE)rv;
}

__declspec(dllexport) BOOL ReleaseSemaphore(HANDLE h, long releaseCount, long* lpPreviousCount)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)52), "D"((long long)h), "S"((long long)releaseCount)
                     : "memory");
    if (lpPreviousCount != (long*)0)
        *lpPreviousCount = 0; /* v0 doesn't track previous count. */
    return rv == 0 ? 1 : 0;
}

/* ------------------------------------------------------------------
 * WaitForSingleObject — dispatch by handle range
 *
 * Mutex (0x200..0x23F)    -> SYS_MUTEX_WAIT (26)
 * Event (0x300..0x33F)    -> SYS_EVENT_WAIT (33)
 * Semaphore (0x500..0x53F) -> SYS_SEM_WAIT (53)
 * Thread (0x400..0x43F)   -> SYS_THREAD_WAIT (54)
 * Anything else            -> WAIT_OBJECT_0 (0) — pseudo-signal
 *                             (matches the flat-stub fallback)
 *
 * The per-type span is WIN32_HANDLE_CAP_PER_TYPE = the kernel's
 * kHandleTableCapacity (64). It was 8, which silently routed any
 * handle past the 8th of its type to the pseudo-signal else-branch:
 * WaitForSingleObject returned WAIT_OBJECT_0 without acquiring, so a
 * later ReleaseMutex hit the kernel's non-owner reject. The
 * hello-winapi stress loop creates 4 mutexes that land at
 * 0x205/0x207/0x209/0x20b, and 0x209/0x20b tripped this. The span
 * stays below the 0x100 base spacing so the four ranges are disjoint.
 * Freestanding DLL — can't include the kernel header, so the value is
 * mirrored here; keep it in sync with ipc::kHandleTableCapacity.
 * ------------------------------------------------------------------ */

#define WAIT_OBJECT_0 0u
#define WAIT_TIMEOUT 0x102u
#define WIN32_HANDLE_CAP_PER_TYPE 0x40u /* = kernel kHandleTableCapacity (64) */

__declspec(dllexport) DWORD WaitForSingleObject(HANDLE h, DWORD timeout_ms)
{
    unsigned long long handle = (unsigned long long)h;
    long long rv;
    long long syscall_num;
    if (handle >= 0x200 && handle < 0x200 + WIN32_HANDLE_CAP_PER_TYPE)
        syscall_num = 26; /* SYS_MUTEX_WAIT */
    else if (handle >= 0x300 && handle < 0x300 + WIN32_HANDLE_CAP_PER_TYPE)
        syscall_num = 33; /* SYS_EVENT_WAIT */
    else if (handle >= 0x500 && handle < 0x500 + WIN32_HANDLE_CAP_PER_TYPE)
        syscall_num = 53; /* SYS_SEM_WAIT */
    else if (handle >= 0x400 && handle < 0x400 + WIN32_HANDLE_CAP_PER_TYPE)
        syscall_num = 54; /* SYS_THREAD_WAIT */
    else
        return WAIT_OBJECT_0; /* Unknown handle — pseudo-signal. */
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"(syscall_num), "D"((long long)h), "S"((long long)timeout_ms)
                     : "memory");
    return (DWORD)rv;
}

/* ------------------------------------------------------------------
 * APC queue v0 (T8-02 — single-thread, process-local)
 *
 * The Win32 contract: QueueUserAPC(pfn, hThread, ulData) appends
 * a user-mode APC to the target thread's queue. If the target is
 * inside an alertable wait (SleepEx(_, TRUE), WaitForSingleObjectEx
 * with bAlertable=TRUE), the wait returns WAIT_IO_COMPLETION
 * (0x000000C0) immediately and the queued callbacks execute in
 * order before control returns.
 *
 * v0 ships a process-local queue indexed by target TID. The
 * single-threaded case (caller queues to itself) works correctly:
 * SleepEx with bAlertable drains the queue, fires each callback,
 * and returns WAIT_IO_COMPLETION. Multi-thread cross-thread APC
 * delivery requires kernel-side per-thread APC queue + scheduler
 * wake — that's the T8-02 follow-on.
 * ------------------------------------------------------------------ */

#define WAIT_IO_COMPLETION 0xC0u
#define WIN32_APC_QUEUE_SLOTS 16

typedef void(__stdcall* PAPCFUNC)(unsigned long long ulData);

typedef struct Win32ApcSlot
{
    DWORD target_tid;
    PAPCFUNC pfn;
    unsigned long long data;
    int in_use;
} Win32ApcSlot;

static Win32ApcSlot g_apc_queue[WIN32_APC_QUEUE_SLOTS];


__declspec(dllexport) DWORD QueueUserAPC(PAPCFUNC pfn, HANDLE hThread, unsigned long long dwData)
{
    if (pfn == (PAPCFUNC)0)
        return 0;
    /* hThread is opaque; v0 dispatches by TID. The CRT typically
     * maps thread handles to TIDs via a shadow table; we treat
     * the low 32 bits of the handle as the target TID. -1 (the
     * GetCurrentThread pseudo-handle) routes to the caller. */
    DWORD target_tid = (hThread == (HANDLE)(long long)-2 || hThread == (HANDLE)0) ? (DWORD)syscall_get_tid()
                                                                                  : (DWORD)(unsigned long long)hThread;
    /* Try the kernel-resident queue first — that path delivers
     * across kernel-blocked alertable waits without relying on the
     * 10ms slice-poll. Fall through to the legacy user-space queue
     * on any failure (queue full, foreign tid, kCapSpawnThread
     * denied) so single-threaded callers still see the same
     * happy-path semantics they did before T8-02 wiring.
     *
     * QueueUserAPC carries a single ulData (PAPCFUNC shape).
     * Zero r10 / r8 explicitly so the kernel stores SA1=SA2=0
     * for the slot rather than reading the compiler's leftover
     * register state — this is how a future drain path
     * distinguishes "no SA1/SA2 was ever supplied" from "the
     * caller passed SystemArgument*=0". */
    register long long r10 __asm__("r10") = 0;
    register long long r8 __asm__("r8") = 0;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)187), /* SYS_QUEUE_USER_APC */
                       "D"((long long)target_tid), "S"((long long)pfn), "d"((long long)dwData), "r"(r10), "r"(r8)
                     : "memory");
    if (rv == 0)
        return 1;

    for (int i = 0; i < WIN32_APC_QUEUE_SLOTS; ++i)
    {
        if (!g_apc_queue[i].in_use)
        {
            g_apc_queue[i].target_tid = target_tid;
            g_apc_queue[i].pfn = pfn;
            g_apc_queue[i].data = dwData;
            g_apc_queue[i].in_use = 1;
            return 1;
        }
    }
    return 0; /* Queue full. */
}

/* Drain APCs queued for the calling thread. Returns the count
 * fired. Called by SleepEx / WaitForSingleObjectEx when
 * bAlertable=TRUE. Drains both the kernel-resident queue
 * (SYS_DRAIN_USER_APC = 188) and the legacy user-space queue.
 *
 * Reads the full (pfn, NormalContext, SA1, SA2) tuple from the
 * kernel slot so an NtQueueApcThread caller that supplied
 * SystemArgument1 / SystemArgument2 gets all three args delivered
 * to the routine. Single-arg PAPCFUNC pfns simply ignore the
 * trailing register inputs — Microsoft x64 ABI puts each arg in
 * a dedicated register, so a callee that only reads RCX is
 * unaffected by writes to RDX / R8. */
static unsigned int win32_drain_apc_queue(void)
{
    DWORD self_tid = (DWORD)syscall_get_tid();
    unsigned int fired = 0;
    /* Drain the kernel queue first. Each successful pop returns
     * the (pfn, NormalContext, SA1, SA2) tuple; we invoke from
     * user mode. */
    for (;;)
    {
        unsigned long long pfn_raw = 0;
        unsigned long long data = 0;
        unsigned long long arg1 = 0;
        unsigned long long arg2 = 0;
        /* SYS_DRAIN_USER_APC contract:
         *   rdi = &pfn  rsi = &data  rdx = &arg1  r10 = &arg2.
         * arg1/arg2 sinks are optional in the kernel; we pass real
         * pointers here so a 3-arg NtQueueApcThread caller's
         * SystemArgument* values reach the routine. */
        register long long r10 __asm__("r10") = (long long)&arg2;
        long long rv;
        __asm__ volatile("int $0x80"
                         : "=a"(rv)
                         : "a"((long long)188), /* SYS_DRAIN_USER_APC */
                           "D"((long long)&pfn_raw), "S"((long long)&data), "d"((long long)&arg1), "r"(r10)
                         : "memory");
        if (rv != 1)
            break;
        typedef void (*PIO_APC_ROUTINE)(unsigned long long, unsigned long long, unsigned long long);
        PIO_APC_ROUTINE pfn3 = (PIO_APC_ROUTINE)(void*)(unsigned long long)pfn_raw;
        if (pfn3 != (PIO_APC_ROUTINE)0)
        {
            /* Microsoft x64 ABI: arg0=RCX, arg1=RDX, arg2=R8.
             * A PAPCFUNC (single-arg) callee reads RCX only; the
             * extra register writes are inert. */
            pfn3(data, arg1, arg2);
            ++fired;
        }
    }
    /* Then drain the legacy user-space overflow queue. */
    for (int i = 0; i < WIN32_APC_QUEUE_SLOTS; ++i)
    {
        if (g_apc_queue[i].in_use && g_apc_queue[i].target_tid == self_tid)
        {
            PAPCFUNC pfn = g_apc_queue[i].pfn;
            unsigned long long data = g_apc_queue[i].data;
            g_apc_queue[i].in_use = 0;
            g_apc_queue[i].pfn = (PAPCFUNC)0;
            g_apc_queue[i].data = 0;
            pfn(data);
            ++fired;
        }
    }
    return fired;
}

__declspec(dllexport) DWORD WaitForSingleObjectEx(HANDLE h, DWORD timeout_ms, BOOL bAlertable)
{
    if (!bAlertable)
        return WaitForSingleObject(h, timeout_ms);
    /* Alertable: chunk the wait into 10ms slices so a peer-queued
     * APC observed in g_apc_queue fires promptly. Same rationale as
     * SleepEx — without chunking, a peer thread's QueueUserAPC
     * couldn't break the calling thread out of an INFINITE wait.
     * The inner WaitForSingleObject returns WAIT_TIMEOUT (0x102) on
     * a slice-level timeout; loop until either the overall budget
     * is exhausted, an APC fires, or the wait actually signals. */
    if (win32_drain_apc_queue() > 0)
        return WAIT_IO_COMPLETION;
    DWORD remaining = timeout_ms;
    const DWORD kSliceMs = 10;
    for (;;)
    {
        DWORD chunk = kSliceMs;
        if (timeout_ms != 0xFFFFFFFFu)
        {
            if (remaining == 0)
                return WAIT_TIMEOUT;
            if (remaining < kSliceMs)
                chunk = remaining;
        }
        DWORD rv = WaitForSingleObject(h, chunk);
        if (rv != WAIT_TIMEOUT)
            return rv; /* signaled / abandoned / failed */
        if (win32_drain_apc_queue() > 0)
            return WAIT_IO_COMPLETION;
        if (timeout_ms != 0xFFFFFFFFu)
        {
            if (remaining <= chunk)
                remaining = 0;
            else
                remaining -= chunk;
        }
    }
}

/* SleepEx(dwMilliseconds, bAlertable) — alertable variant of Sleep.
 * If bAlertable=TRUE and APCs are pending, fire them and return
 * WAIT_IO_COMPLETION; otherwise sleep the requested duration.
 *
 * Cross-thread APC delivery: when alertable, the sleep is chunked
 * into 10ms slices so an APC queued from another thread (which
 * lands in the process-wide g_apc_queue table) is observed within
 * one slice. Without chunking, a thread asleep in SleepEx(INFINITE,
 * TRUE) would never observe an APC queued from a peer until its
 * own timer fired. The chunk size is small enough to keep the
 * cross-thread wake latency bounded but large enough that the
 * syscall traffic from a long Sleep is still amortised. */
__declspec(dllexport) DWORD SleepEx(DWORD dwMilliseconds, BOOL bAlertable)
{
    if (bAlertable && win32_drain_apc_queue() > 0)
        return WAIT_IO_COMPLETION;
    if (!bAlertable)
    {
        /* Non-alertable Sleep — single SYS_SLEEP syscall. */
        long long discard;
        __asm__ volatile("int $0x80" : "=a"(discard) : "a"((long long)19), "D"((long long)dwMilliseconds) : "memory");
        return 0;
    }
    /* Alertable: chunk into 10ms slices, polling the APC queue
     * between each. INFINITE (0xFFFFFFFF) loops until an APC fires.
     * After the last partial slice expires, return 0 (timeout) as
     * the contract requires. */
    DWORD remaining = dwMilliseconds;
    const DWORD kSliceMs = 10;
    for (;;)
    {
        if (win32_drain_apc_queue() > 0)
            return WAIT_IO_COMPLETION;
        if (remaining == 0 && dwMilliseconds != 0xFFFFFFFFu)
            return 0;
        DWORD chunk = kSliceMs;
        if (dwMilliseconds != 0xFFFFFFFFu && remaining < kSliceMs)
            chunk = remaining;
        long long discard;
        __asm__ volatile("int $0x80" : "=a"(discard) : "a"((long long)19), "D"((long long)chunk) : "memory");
        if (dwMilliseconds != 0xFFFFFFFFu)
        {
            if (remaining <= chunk)
                remaining = 0;
            else
                remaining -= chunk;
        }
    }
}

/* ------------------------------------------------------------------
 * CriticalSection
 *
 * CRITICAL_SECTION is a 40-byte caller-owned struct. v0 uses the
 * first 16 bytes as:
 *   [cs + 0]: owner TID (0 = unowned)
 *   [cs + 8]: recursion count
 *
 * Same TID = SYS_GETPID (1). Spin-CAS with SYS_YIELD on
 * contention. Recursive re-entry just bumps the count.
 * Matches the flat-stub semantics at kOffEnterCritSecReal.
 * ------------------------------------------------------------------ */

typedef long long volatile* CritSecPtr;


__declspec(dllexport) BOOL InitializeCriticalSection(void* cs)
{
    /* Zero the 40-byte CRITICAL_SECTION. Byte loop keeps this
     * independent of memset. */
    if (cs != (void*)0)
    {
        unsigned char* b = (unsigned char*)cs;
        for (int i = 0; i < 40; ++i)
            b[i] = 0;
    }
    return 1;
}

__declspec(dllexport) BOOL InitializeCriticalSectionEx(void* cs, DWORD spin, DWORD flags)
{
    (void)spin;
    (void)flags;
    return InitializeCriticalSection(cs);
}

__declspec(dllexport) BOOL InitializeCriticalSectionAndSpinCount(void* cs, DWORD spin)
{
    (void)spin;
    return InitializeCriticalSection(cs);
}

__declspec(dllexport) void DeleteCriticalSection(void* cs)
{
    (void)cs;
    /* No allocations to free; flat stub is also a no-op. */
}

__declspec(dllexport) void EnterCriticalSection(void* cs)
{
    long long tid = syscall_get_tid();
    CritSecPtr owner = (CritSecPtr)cs;
    long long volatile* recur = (long long volatile*)cs + 1;
    for (;;)
    {
        long long expected = 0;
        if (__atomic_compare_exchange_n(owner, &expected, tid, /*weak=*/0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
        {
            /* First acquire: recursion := 1. */
            *recur = 1;
            return;
        }
        if (expected == tid)
        {
            /* Already held by us — bump recursion. */
            *recur = *recur + 1;
            return;
        }
        /* Contended — yield and retry. */
        syscall_yield();
    }
}

__declspec(dllexport) void LeaveCriticalSection(void* cs)
{
    CritSecPtr owner = (CritSecPtr)cs;
    long long volatile* recur = (long long volatile*)cs + 1;
    long long next = *recur - 1;
    *recur = next;
    if (next == 0)
        *owner = 0; /* Release: next acquirer's CAS wins. */
}

__declspec(dllexport) BOOL TryEnterCriticalSection(void* cs)
{
    long long tid = syscall_get_tid();
    CritSecPtr owner = (CritSecPtr)cs;
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
    return 0; /* Contended; do NOT spin. */
}

/* ------------------------------------------------------------------
 * SRWLock — single 8-byte slot, exclusive only
 *
 * v0 collapses shared/exclusive to exclusive. Real Win32 SRW
 * locks are NOT reentrant — second acquire from the same thread
 * deadlocks. We preserve that contract.
 * ------------------------------------------------------------------ */

__declspec(dllexport) void InitializeSRWLock(void* lock)
{
    if (lock != (void*)0)
        *(long long volatile*)lock = 0;
}

__declspec(dllexport) void AcquireSRWLockExclusive(void* lock)
{
    long long tid = syscall_get_tid();
    long long volatile* p = (long long volatile*)lock;
    for (;;)
    {
        long long expected = 0;
        if (__atomic_compare_exchange_n(p, &expected, tid, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
            return;
        syscall_yield();
    }
}

__declspec(dllexport) void ReleaseSRWLockExclusive(void* lock)
{
    if (lock != (void*)0)
        *(long long volatile*)lock = 0;
}

__declspec(dllexport) BOOL TryAcquireSRWLockExclusive(void* lock)
{
    long long tid = syscall_get_tid();
    long long volatile* p = (long long volatile*)lock;
    long long expected = 0;
    if (__atomic_compare_exchange_n(p, &expected, tid, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
        return 1;
    return 0;
}

/* SRW shared aliases collapse to exclusive in v0. */
__declspec(dllexport) void AcquireSRWLockShared(void* lock)
{
    AcquireSRWLockExclusive(lock);
}

__declspec(dllexport) void ReleaseSRWLockShared(void* lock)
{
    ReleaseSRWLockExclusive(lock);
}

__declspec(dllexport) BOOL TryAcquireSRWLockShared(void* lock)
{
    return TryAcquireSRWLockExclusive(lock);
}

/* ------------------------------------------------------------------
 * InitOnceExecuteOnce
 *
 * INIT_ONCE is an 8-byte slot we interpret as:
 *     0 = untouched
 *     1 = initialiser running
 *     2 = done
 *
 * Single CAS 0->1 picks the initialiser; losers spin-yield
 * until the slot reaches 2. Null InitFn legitimately marks
 * "complete without running anything".
 * ------------------------------------------------------------------ */

typedef BOOL (*InitOnceFn)(void* InitOnce, void* Parameter, void** Context);

__declspec(dllexport) BOOL InitOnceExecuteOnce(void* InitOnce, InitOnceFn InitFn, void* Parameter, void** Context)
{
    long long volatile* slot = (long long volatile*)InitOnce;
    long long expected = 0;
    if (__atomic_compare_exchange_n(slot, &expected, 1LL, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
    {
        /* We won the CAS — run the initialiser (if any). */
        if (InitFn != (InitOnceFn)0)
            InitFn(InitOnce, Parameter, Context);
        *slot = 2; /* Mark done. */
        return 1;
    }
    /* Lost the CAS — wait for the winner to mark it done. */
    while (__atomic_load_n(slot, __ATOMIC_SEQ_CST) != 2)
        syscall_yield();
    return 1;
}

/* ------------------------------------------------------------------
 * Address-keyed wait — WaitOnAddress / WakeByAddress*.
 *
 * The futex-shaped primitive V8 / Chrome build SRW + condition
 * variables on. SYS_WAIT_ON_ADDRESS = 208 (rdi=addr, rsi=expected
 * value, rdx=size, r10=timeout-ms), SYS_WAKE_BY_ADDRESS = 209
 * (rdi=addr, rsi=0 single / 1 all). The kernel allows spurious
 * wakeups, exactly as Win32 documents, so every caller that needs
 * an exact predicate loops.
 * ------------------------------------------------------------------ */

static long long waitaddr_load(const volatile void* p, unsigned long long size)
{
    switch (size)
    {
    case 1:
        return (long long)*(const volatile unsigned char*)p;
    case 2:
        return (long long)*(const volatile unsigned short*)p;
    case 4:
        return (long long)*(const volatile unsigned int*)p;
    case 8:
        return (long long)*(const volatile unsigned long long*)p;
    default:
        return 0;
    }
}

__declspec(dllexport) BOOL WaitOnAddress(volatile void* Address, void* CompareAddress, SIZE_T AddressSize,
                                         DWORD dwMilliseconds)
{
    if (Address == (void*)0 || CompareAddress == (void*)0)
        return 0;
    long long expected = waitaddr_load(CompareAddress, (unsigned long long)AddressSize);
    register long long _r10 asm("r10") = (long long)(unsigned long long)dwMilliseconds;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)208), /* SYS_WAIT_ON_ADDRESS */
                       "D"((long long)(unsigned long long)(UINT_PTR)Address), "S"(expected),
                       "d"((long long)(unsigned long long)AddressSize), "r"(_r10)
                     : "memory");
    return rv ? 1 : 0; /* 0 == timed out */
}

__declspec(dllexport) void WakeByAddressSingle(void* Address)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)209), /* SYS_WAKE_BY_ADDRESS */
                       "D"((long long)(unsigned long long)(UINT_PTR)Address), "S"((long long)0)
                     : "memory");
    (void)rv;
}

__declspec(dllexport) void WakeByAddressAll(void* Address)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)209), "D"((long long)(unsigned long long)(UINT_PTR)Address), "S"((long long)1)
                     : "memory");
    (void)rv;
}

/* ------------------------------------------------------------------
 * Condition variables — the standard sequence-counter algorithm
 * over WaitOnAddress. CONDITION_VARIABLE is pointer-sized; we use
 * its low 32 bits as a wake sequence. A sleeper samples the
 * sequence WHILE holding the associated lock, drops the lock, then
 * WaitOnAddress(&seq, sampled): if a waker bumped the sequence in
 * the gap, WaitOnAddress returns immediately — no lost wakeup. The
 * lock is always re-acquired before returning, in the same mode.
 *
 * SRW shared-vs-exclusive is still aliased to exclusive in v0
 * (pre-existing), so SleepConditionVariableSRW re-takes exclusive
 * regardless of flags — correct, just not maximally concurrent.
 * ------------------------------------------------------------------ */

/* EnterCriticalSection / LeaveCriticalSection / the SRW lock
 * helpers are all defined earlier in this TU, so they're already
 * in scope here — no forward declaration needed. */

#define CONDITION_VARIABLE_LOCKMODE_SHARED 0x1u

__declspec(dllexport) void InitializeConditionVariable(void* cv)
{
    if (cv != (void*)0)
        *(volatile unsigned*)cv = 0;
}

__declspec(dllexport) BOOL SleepConditionVariableCS(void* cv, void* cs, DWORD dwMilliseconds)
{
    if (cv == (void*)0 || cs == (void*)0)
        return 0;
    unsigned seq = *(volatile unsigned*)cv;
    LeaveCriticalSection(cs);
    BOOL woken = WaitOnAddress(cv, &seq, 4, dwMilliseconds);
    EnterCriticalSection(cs);
    return woken;
}

__declspec(dllexport) BOOL SleepConditionVariableSRW(void* cv, void* srw, DWORD dwMilliseconds, unsigned long Flags)
{
    if (cv == (void*)0 || srw == (void*)0)
        return 0;
    unsigned seq = *(volatile unsigned*)cv;
    const int shared = (Flags & CONDITION_VARIABLE_LOCKMODE_SHARED) != 0;
    if (shared)
        ReleaseSRWLockShared(srw);
    else
        ReleaseSRWLockExclusive(srw);
    BOOL woken = WaitOnAddress(cv, &seq, 4, dwMilliseconds);
    if (shared)
        AcquireSRWLockShared(srw);
    else
        AcquireSRWLockExclusive(srw);
    return woken;
}

__declspec(dllexport) void WakeConditionVariable(void* cv)
{
    if (cv == (void*)0)
        return;
    __atomic_add_fetch((volatile unsigned*)cv, 1u, __ATOMIC_SEQ_CST);
    WakeByAddressSingle(cv);
}

__declspec(dllexport) void WakeAllConditionVariable(void* cv)
{
    if (cv == (void*)0)
        return;
    __atomic_add_fetch((volatile unsigned*)cv, 1u, __ATOMIC_SEQ_CST);
    WakeByAddressAll(cv);
}

/* ------------------------------------------------------------------
 * InitOnceBeginInitialize / InitOnceComplete — the explicit
 * two-call form of one-time init (InitOnceExecuteOnce above is the
 * callback form). Synchronous subset only.
 *
 * Block encoding matches NT's RtlRunOnce: the pointer-sized INIT_ONCE
 * word packs a 2-bit state into the low bits and the caller's context
 * pointer into the high bits (a Win32 INIT_ONCE context is required
 * to be 4-byte aligned, so the low 2 bits are free):
 *     state 0 = uninitialized
 *     state 1 = synchronous init in progress
 *     state 2 = done   (high bits = context pointer)
 *     state 3 = async init in progress (treated as synchronous here)
 * Losers on state 1/3 block on WaitOnAddress(slot) until the winner
 * bumps the word.
 *
 * Preserving the context is load-bearing, not cosmetic: a caller that
 * stores a context via InitOnceComplete and re-enters
 * InitOnceBeginInitialize on the already-done path expects its context
 * back. The prior version discarded it (returned NULL), and the
 * caller's caller dereferenced that NULL — observed as a charmap.exe
 * 0xc0000005 the second time its run-once-initialised singleton was
 * fetched (caller does `mov 0x8(%rax),%rax` on the returned context).
 *
 * GAP: INIT_ONCE_ASYNC is folded onto the synchronous path — revisit
 * if a real caller needs genuine pending async init.
 * ------------------------------------------------------------------ */

#define INIT_ONCE_CHECK_ONLY 0x1u
#define INIT_ONCE_INIT_FAILED 0x4u
#define INIT_ONCE_STATE_MASK 0x3ull

__declspec(dllexport) BOOL InitOnceBeginInitialize(void* InitOnce, unsigned long dwFlags, BOOL* fPending,
                                                   void** lpContext)
{
    if (InitOnce == (void*)0 || fPending == (BOOL*)0)
        return 0;
    volatile unsigned long long* slot = (volatile unsigned long long*)InitOnce;
    for (;;)
    {
        unsigned long long cur = __atomic_load_n(slot, __ATOMIC_SEQ_CST);
        unsigned state = (unsigned)(cur & INIT_ONCE_STATE_MASK);
        if (state == 2)
        {
            /* Done — hand back the preserved context. */
            *fPending = 0;
            if (lpContext != (void**)0)
                *lpContext = (void*)(cur & ~INIT_ONCE_STATE_MASK);
            return 1;
        }
        if (dwFlags & INIT_ONCE_CHECK_ONLY)
        {
            /* Not finished and caller only wants a peek. */
            return 0;
        }
        if (state == 0)
        {
            unsigned long long expected = cur; /* == 0 */
            if (__atomic_compare_exchange_n(slot, &expected, 1ull, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
            {
                *fPending = 1; /* caller is the initialiser */
                if (lpContext != (void**)0)
                    *lpContext = (void*)0;
                return 1;
            }
            continue; /* lost the race — re-evaluate */
        }
        /* state 1/3: another thread is initialising. Park until it
         * bumps the slot, then loop to observe the new state. The
         * in-progress word is exactly 1, so a 4-byte compare on the
         * low word detects the transition. */
        unsigned running = 1u;
        WaitOnAddress((void*)slot, &running, 4, 0xFFFFFFFFu);
    }
}

__declspec(dllexport) BOOL InitOnceComplete(void* InitOnce, unsigned long dwFlags, void* lpContext)
{
    if (InitOnce == (void*)0)
        return 0;
    volatile unsigned long long* slot = (volatile unsigned long long*)InitOnce;
    if (dwFlags & INIT_ONCE_INIT_FAILED)
    {
        __atomic_store_n(slot, 0ull, __ATOMIC_SEQ_CST); /* let another thread retry */
    }
    else
    {
        /* Pack context | done. Context is 4-byte aligned per the
         * INIT_ONCE contract, so masking the low 2 bits is lossless. */
        unsigned long long packed = ((unsigned long long)lpContext & ~INIT_ONCE_STATE_MASK) | 2ull;
        __atomic_store_n(slot, packed, __ATOMIC_SEQ_CST);
    }
    WakeByAddressAll(InitOnce);
    return 1;
}

/* ------------------------------------------------------------------
 * Thread management
 *
 * SYS_THREAD_CREATE = 45 (rdi=start_va, rsi=param) -> handle
 * SYS_THREAD_EXIT_CODE = 55 (rdi=handle) -> exit code
 * SYS_EXIT = 0 (rdi=code, [[noreturn]])
 *
 * ResumeThread is registered as kOffReturnZero in the flat
 * stubs (we don't pause threads at create time today, so
 * Resume is a no-op). Same here.
 * ------------------------------------------------------------------ */

typedef DWORD (*ThreadStartFn)(void*);

__declspec(dllexport) HANDLE CreateThread(void* lpThreadAttributes, SIZE_T dwStackSize, ThreadStartFn lpStartAddress,
                                          void* lpParameter, DWORD dwCreationFlags, DWORD* lpThreadId)
{
    (void)lpThreadAttributes;
    (void)dwStackSize;
    (void)dwCreationFlags;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)45), "D"((long long)lpStartAddress), "S"((long long)lpParameter)
                     : "memory");
    /* Win32 contract: NULL on failure. The kernel returns a
     * negative errno on failure; translate every negative value. */
    if (rv < 0)
    {
        if (lpThreadId != (DWORD*)0)
            *lpThreadId = 0;
        return (HANDLE)0;
    }
    if (lpThreadId != (DWORD*)0)
        *lpThreadId = (DWORD)rv;
    return (HANDLE)rv;
}

__declspec(dllexport) DWORD ResumeThread(HANDLE hThread)
{
    (void)hThread;
    /* No suspended-thread state in v0 — every CreateThread runs
     * immediately. Return 0 (= "thread was not previously
     * suspended"), matching the flat stub's behaviour. */
    return 0;
}

/* SetThreadStackGuarantee — Windows reserves additional stack
 * space for SEH unwinding under low-memory conditions. DuetOS
 * doesn't model SEH guard pages today (the user stack is a
 * single page); the request can't be granted.
 *
 * If `fake_ok_stack_guarantee` is set in the per-process compat
 * sidecar we lie and return TRUE without touching the stack —
 * real Windows binaries that gate their startup on a non-zero
 * stack guarantee (e.g. the VC runtime, mscorlib) thread on
 * unchanged. Without the policy, the call fails with
 * ERROR_INVALID_PARAMETER so the caller knows the request was
 * rejected.
 *
 * `pStackSizeInBytes` is an in/out: on success it should be
 * overwritten with the previous (now-replaced) value. We don't
 * have a previous value to report, so we leave the slot alone
 * (most callers ignore the out-write anyway). */
__declspec(dllexport) BOOL SetThreadStackGuarantee(unsigned long* pStackSizeInBytes)
{
    if ((duet_compat_query() & DUETOS_COMPAT_BIT_FAKE_OK_STACK_GUARANTEE) != 0)
    {
        (void)pStackSizeInBytes;
        return 1;
    }
    SetLastError(87u); /* ERROR_INVALID_PARAMETER */
    return 0;
}

/* Waitable-timer v0. CreateWaitableTimerW allocates a manual-reset
 * Event in the unsignaled state and reserves a slot in the per-process
 * timer table. SetWaitableTimer records the absolute due time (and
 * period for periodic timers), then resets the event. A single
 * lazily-spawned service thread polls the table every 10 ms and calls
 * SetEvent on any timer whose due time has arrived. CancelWaitableTimer
 * marks the slot inactive without touching the event signal state.
 *
 * Out of scope:
 *   - APC completion routines (the `completion`/`arg` parameters are
 *     accepted but never invoked — needs cross-thread APC delivery,
 *     Track 8-02).
 *   - Resume from suspend (`fResume == TRUE` is silently ignored —
 *     ACPI S3 not implemented).
 *   - Sub-10ms resolution. The polling cadence is the floor.
 */
typedef struct
{
    HANDLE event_handle;
    unsigned long long due_ms;    /* absolute boot-relative ms */
    unsigned long long period_ms; /* 0 = single-shot */
    int active;
} DUETOS_WTIMER_SLOT;
#define DUETOS_WTIMER_MAX 16
static DUETOS_WTIMER_SLOT g_wtimers[DUETOS_WTIMER_MAX];
static volatile int g_wtimer_thread_started = 0;

static int wtimer_find_slot(HANDLE h)
{
    for (int i = 0; i < DUETOS_WTIMER_MAX; ++i)
    {
        if (g_wtimers[i].event_handle == h)
            return i;
    }
    return -1;
}

static int wtimer_alloc_slot(HANDLE h)
{
    for (int i = 0; i < DUETOS_WTIMER_MAX; ++i)
    {
        if (g_wtimers[i].event_handle == (HANDLE)0)
        {
            g_wtimers[i].event_handle = h;
            g_wtimers[i].due_ms = 0;
            g_wtimers[i].period_ms = 0;
            g_wtimers[i].active = 0;
            return i;
        }
    }
    return -1;
}

static DWORD wtimer_service_thread(void* arg)
{
    (void)arg;
    /* Poll every 10 ms — same cadence as the kernel scheduler tick.
     * Sub-tick resolution would just spin the CPU without delivering
     * a finer signal. */
    for (;;)
    {
        ULONGLONG now = GetTickCount64();
        for (int i = 0; i < DUETOS_WTIMER_MAX; ++i)
        {
            if (g_wtimers[i].active && now >= g_wtimers[i].due_ms)
            {
                SetEvent(g_wtimers[i].event_handle);
                if (g_wtimers[i].period_ms > 0)
                {
                    /* Re-arm: bump due_ms by period so a slow service
                     * pass that misses several intervals catches up
                     * by firing once at the next quantum rather than
                     * burst-firing every missed interval. */
                    g_wtimers[i].due_ms = now + g_wtimers[i].period_ms;
                }
                else
                {
                    g_wtimers[i].active = 0;
                }
            }
        }
        Sleep(10);
    }
    return 0;
}

static void wtimer_ensure_service(void)
{
    /* Single-flag race is acceptable: spawning two service threads
     * by accident still produces correct behaviour (both threads see
     * the same table); the only cost is one extra thread of memory.
     * A real CompareAndSwap would be overkill for this case. */
    if (g_wtimer_thread_started)
        return;
    g_wtimer_thread_started = 1;
    DWORD tid = 0;
    HANDLE h = CreateThread((void*)0, 0, wtimer_service_thread, (void*)0, 0, &tid);
    (void)h;
}

__declspec(dllexport) HANDLE CreateWaitableTimerW(void* sa, BOOL manualReset, const WCHAR_t* name)
{
    (void)sa;
    (void)name;
    /* Allocate via SYS_HANDLE_CREATE_EVENT (caller-chosen reset
     * mode, INITIALLY UNSIGNALED — flips signaled when the timer
     * fires). */
    long long h;
    __asm__ volatile("int $0x80"
                     : "=a"(h)
                     : "a"((long long)33),                                      /* SYS_HANDLE_CREATE_EVENT */
                       "D"((long long)(manualReset ? 1 : 0)), "S"((long long)0) /* initially unsignaled */
                     : "memory");
    if (h == 0)
        return (HANDLE)0;
    int slot = wtimer_alloc_slot((HANDLE)h);
    if (slot < 0)
    {
        /* Out of slots — return failure. The event is leaked, but
         * the leak is bounded by DUETOS_WTIMER_MAX failures. */
        return (HANDLE)0;
    }
    return (HANDLE)h;
}

__declspec(dllexport) HANDLE CreateWaitableTimerA(void* sa, BOOL manualReset, const char* name)
{
    (void)name;
    return CreateWaitableTimerW(sa, manualReset, (const WCHAR_t*)0);
}

__declspec(dllexport) BOOL SetWaitableTimer(HANDLE t, void* due, long period, void* completion, void* arg, BOOL resume)
{
    (void)completion; /* APC completion routines: GAP — Track 8-02 */
    (void)arg;
    (void)resume; /* fResume: GAP — ACPI S3 not implemented */
    if (t == (HANDLE)0 || due == (void*)0)
        return 0;
    int slot = wtimer_find_slot(t);
    if (slot < 0)
        return 0;
    /* due is a LARGE_INTEGER*: positive => absolute FILETIME (100-ns
     * units since 1601), negative => relative 100-ns intervals from
     * now. v0 only supports the relative form (the absolute form
     * needs a FILETIME → boot-relative-ms conversion that depends on
     * the system time being set, which v0 doesn't yet do). */
    long long lq = *(long long*)due;
    unsigned long long delay_ms;
    if (lq < 0)
    {
        /* -lq is relative 100-ns intervals → ms */
        delay_ms = (unsigned long long)(-lq) / 10000ULL;
    }
    else
    {
        /* Absolute FILETIME — no conversion table; treat as "fire
         * immediately" so callers don't hang forever. */
        delay_ms = 0;
    }
    ResetEvent(t);
    g_wtimers[slot].due_ms = GetTickCount64() + delay_ms;
    g_wtimers[slot].period_ms = (period > 0) ? (unsigned long long)period : 0;
    g_wtimers[slot].active = 1;
    wtimer_ensure_service();
    return 1;
}

__declspec(dllexport) BOOL CancelWaitableTimer(HANDLE t)
{
    if (t == (HANDLE)0)
        return 0;
    int slot = wtimer_find_slot(t);
    if (slot < 0)
        return 0;
    g_wtimers[slot].active = 0;
    return 1;
}

__declspec(dllexport) BOOL GetExitCodeThread(HANDLE hThread, DWORD* lpExitCode)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)55), "D"((long long)hThread) : "memory");
    /* SYS_THREAD_EXIT_CODE returns a negative errno on bad handle
     * and the actual exit code (or STILL_ACTIVE = 0x103) otherwise.
     * Win32 contract: BOOL TRUE on success regardless of
     * STILL_ACTIVE; we always claim success (matches flat
     * stub's optimism). */
    if (lpExitCode != (DWORD*)0)
        *lpExitCode = (rv < 0) ? 0x103 : (DWORD)rv;
    return 1;
}

__declspec(dllexport) WIN32_NORETURN void ExitThread(DWORD dwExitCode)
{
    /* For our single-thread-per-process model ExitThread ==
     * ExitProcess. Match the flat stub's behaviour. */
    __asm__ volatile("int $0x80" : : "a"((long long)0), "D"((long long)dwExitCode));
    DUET_USER_TRAP_UNREACHABLE();
}

__declspec(dllexport) BOOL GetExitCodeProcess(HANDLE hProcess, DWORD* lpExitCode)
{
    /* No cross-process query in v0 — pretend the queried
     * process is still running. Matches the flat stub's
     * STILL_ACTIVE behaviour. */
    (void)hProcess;
    if (lpExitCode != (DWORD*)0)
        *lpExitCode = 0x103; /* STILL_ACTIVE */
    return 1;
}
