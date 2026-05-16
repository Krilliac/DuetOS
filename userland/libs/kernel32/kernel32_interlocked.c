#include "kernel32_internal.h"

/* ------------------------------------------------------------------
 * Interlocked* family — atomic read/modify/write primitives.
 *
 * All of these are pure-CPU (no syscall). The Win32 semantics
 * are well-defined against x86 atomics:
 *   - Increment/Decrement return the NEW value.
 *   - Exchange returns the OLD value.
 *   - CompareExchange returns the OLD value (regardless of
 *     whether the swap succeeded).
 *   - ExchangeAdd returns the OLD value.
 *   - And / Or / Xor return the OLD value.
 *
 * Clang's __atomic_* intrinsics on x86-64 emit a single
 * `lock xadd` / `lock cmpxchg` / `xchg` instruction inline —
 * no libcall — so -nodefaultlib links cleanly.
 * ------------------------------------------------------------------ */

__declspec(dllexport) LONG InterlockedIncrement(LONG volatile* addend)
{
    return __atomic_add_fetch(addend, 1, __ATOMIC_SEQ_CST);
}

__declspec(dllexport) LONG InterlockedDecrement(LONG volatile* addend)
{
    return __atomic_sub_fetch(addend, 1, __ATOMIC_SEQ_CST);
}

__declspec(dllexport) LONG InterlockedExchange(LONG volatile* target, LONG value)
{
    return __atomic_exchange_n(target, value, __ATOMIC_SEQ_CST);
}

__declspec(dllexport) LONG InterlockedCompareExchange(LONG volatile* dest, LONG exch, LONG comp)
{
    __atomic_compare_exchange_n(dest, &comp, exch,
                                /*weak=*/0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    /* comp is updated in place to the actual pre-CAS value —
     * which is exactly what Win32 InterlockedCompareExchange
     * returns. */
    return comp;
}

__declspec(dllexport) LONG InterlockedExchangeAdd(LONG volatile* addend, LONG value)
{
    return __atomic_fetch_add(addend, value, __ATOMIC_SEQ_CST);
}

__declspec(dllexport) LONG InterlockedAnd(LONG volatile* dest, LONG value)
{
    return __atomic_fetch_and(dest, value, __ATOMIC_SEQ_CST);
}

__declspec(dllexport) LONG InterlockedOr(LONG volatile* dest, LONG value)
{
    return __atomic_fetch_or(dest, value, __ATOMIC_SEQ_CST);
}

__declspec(dllexport) LONG InterlockedXor(LONG volatile* dest, LONG value)
{
    return __atomic_fetch_xor(dest, value, __ATOMIC_SEQ_CST);
}

typedef long long LONG64;

__declspec(dllexport) LONG64 InterlockedIncrement64(LONG64 volatile* addend)
{
    return __atomic_add_fetch(addend, 1, __ATOMIC_SEQ_CST);
}

__declspec(dllexport) LONG64 InterlockedDecrement64(LONG64 volatile* addend)
{
    return __atomic_sub_fetch(addend, 1, __ATOMIC_SEQ_CST);
}

__declspec(dllexport) LONG64 InterlockedExchange64(LONG64 volatile* target, LONG64 value)
{
    return __atomic_exchange_n(target, value, __ATOMIC_SEQ_CST);
}

__declspec(dllexport) LONG64 InterlockedCompareExchange64(LONG64 volatile* dest, LONG64 exch, LONG64 comp)
{
    __atomic_compare_exchange_n(dest, &comp, exch, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    return comp;
}

__declspec(dllexport) LONG64 InterlockedExchangeAdd64(LONG64 volatile* addend, LONG64 value)
{
    return __atomic_fetch_add(addend, value, __ATOMIC_SEQ_CST);
}

__declspec(dllexport) LONG64 InterlockedAnd64(LONG64 volatile* dest, LONG64 value)
{
    return __atomic_fetch_and(dest, value, __ATOMIC_SEQ_CST);
}

__declspec(dllexport) LONG64 InterlockedOr64(LONG64 volatile* dest, LONG64 value)
{
    return __atomic_fetch_or(dest, value, __ATOMIC_SEQ_CST);
}

__declspec(dllexport) LONG64 InterlockedXor64(LONG64 volatile* dest, LONG64 value)
{
    return __atomic_fetch_xor(dest, value, __ATOMIC_SEQ_CST);
}

/* ------------------------------------------------------------------
 * Console / system introspection
 *
 * Most of these are constant-returning shims that report sane
 * "you're on x86_64 Windows 10, code page 437, no Wow64" values
 * so CRT startup + typical console programs proceed without
 * branching onto obscure alt paths.
 * ------------------------------------------------------------------ */

__declspec(dllexport) BOOL GetConsoleMode(HANDLE hConsole, DWORD* lpMode)
{
    (void)hConsole;
    if (lpMode != (DWORD*)0)
        *lpMode = 3; /* ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT */
    return 1;
}

/* Code pages: report CP_UTF8 (65001). Callers that serialise
 * via WriteConsoleW don't actually care; callers that ASK
 * expect a sane answer, and UTF-8 is closer to our actual
 * "pass through" stdout than OEM 437. The console-API
 * smoke test in hello_winapi.exe pins this at 65001. */
__declspec(dllexport) UINT GetConsoleCP(void)
{
    return 65001;
}

__declspec(dllexport) UINT GetConsoleOutputCP(void)
{
    return 65001;
}

__declspec(dllexport) BOOL SetConsoleMode(HANDLE hConsole, DWORD mode)
{
    (void)hConsole;
    (void)mode;
    return 1;
}

__declspec(dllexport) BOOL SetConsoleOutputCP(UINT cp)
{
    (void)cp;
    return 1;
}

/* OutputDebugStringA/W — route to SYS_DEBUG_PRINT (46) which
 * emits `[odbg] <text>` to COM1. Silently tolerates NULL. */
__declspec(dllexport) void OutputDebugStringA(const char* str)
{
    if (!str)
        return;
    long long discard;
    __asm__ volatile("int $0x80" : "=a"(discard) : "a"((long long)46), "D"((long long)str) : "memory");
}

typedef unsigned short WCHAR_t;
__declspec(dllexport) void OutputDebugStringW(const WCHAR_t* wstr)
{
    if (!wstr)
        return;
    /* Strip to ASCII into a 256-byte stack buffer. */
    char buf[256];
    size_t i = 0;
    while (i < 255 && wstr[i])
    {
        buf[i] = (char)(wstr[i] & 0xFF);
        ++i;
    }
    buf[i] = 0;
    long long discard;
    __asm__ volatile("int $0x80" : "=a"(discard) : "a"((long long)46), "D"((long long)buf) : "memory");
}

__declspec(dllexport) DWORD GetLogicalDrives(void)
{
    /* Bit 23 set = X: — same sentinel the flat stub returns. */
    return 0x00800000u;
}

__declspec(dllexport) UINT GetDriveTypeA(const char* root)
{
    (void)root;
    return 3; /* DRIVE_FIXED */
}

__declspec(dllexport) UINT GetDriveTypeW(const void* root)
{
    (void)root;
    return 3; /* DRIVE_FIXED */
}

__declspec(dllexport) BOOL IsWow64Process(HANDLE hProc, BOOL* Wow64Process)
{
    (void)hProc;
    if (Wow64Process != (BOOL*)0)
        *Wow64Process = 0; /* Native x64, not Wow64. */
    return 1;
}

__declspec(dllexport) BOOL IsWow64Process2(HANDLE hProc, unsigned short* proc_machine, unsigned short* native_machine)
{
    (void)hProc;
    if (proc_machine != (unsigned short*)0)
        *proc_machine = 0; /* IMAGE_FILE_MACHINE_UNKNOWN — not Wow64. */
    if (native_machine != (unsigned short*)0)
        *native_machine = 0x8664; /* IMAGE_FILE_MACHINE_AMD64 */
    return 1;
}

/* SYS_DLL_BASE_BY_NAME = 172. Looks up a DLL in the calling
 * process's image table and returns its base VA, or 0 on miss.
 * Case-insensitive; tolerant of `.dll` suffix on either side.
 * An empty name (len = 0) requests the calling EXE's image base
 * — backs GetModuleHandleW(NULL). */
static unsigned long long sys_dll_base_by_name(const char* name)
{
    int len = 0;
    if (name != (const char*)0)
    {
        while (name[len] != 0 && len < 63)
            ++len;
    }
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)172), "D"((long long)name), "S"((long long)len)
                     : "memory");
    return (unsigned long long)rv;
}

/* HMODULE GetModuleHandleW / GetModuleHandleA — return the base
 * VA of a loaded DLL, or the calling EXE's base when name is
 * NULL. The kernel handler maps an empty name to the Process's
 * pe_image_base field (recorded by SpawnPeFile post-ASLR), so a
 * single SYS_DLL_BASE_BY_NAME call covers both cases. */
__declspec(dllexport) void* GetModuleHandleW(const WCHAR_t* name)
{
    if (name == (const WCHAR_t*)0)
        return (void*)(unsigned long long)sys_dll_base_by_name("");
    char abuf[64];
    int i = 0;
    while (i < 63 && name[i] != 0)
    {
        abuf[i] = (char)(name[i] & 0xFF);
        ++i;
    }
    abuf[i] = 0;
    return (void*)(unsigned long long)sys_dll_base_by_name(abuf);
}

__declspec(dllexport) void* GetModuleHandleA(const char* name)
{
    if (name == (const char*)0)
        return (void*)(unsigned long long)sys_dll_base_by_name("");
    return (void*)(unsigned long long)sys_dll_base_by_name(name);
}

/* SYS_DLL_LOAD_FROM_PATH wrapper: ask the kernel to walk
 * `/lib/<name>` in the trusted ramfs, hand the bytes to DllLoad,
 * register the resulting image in the process's DLL table, and
 * return the base VA. Idempotent on the kernel side; safe to call
 * after a successful GetModuleHandleW miss.
 *
 * The name is ASCII (caller already widened/narrowed); kernel
 * caps length at 63 + NUL. Zero return = miss (no /lib/<name>
 * file, DllLoad failure, image table full). */
static unsigned long long sys_dll_load_from_path(const char* name)
{
    int len = 0;
    if (name != (const char*)0)
    {
        while (name[len] != 0 && len < 63)
            ++len;
    }
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)205), "D"((long long)name), "S"((long long)len)
                     : "memory");
    return (unsigned long long)rv;
}

/* LoadLibraryW / LoadLibraryA — Win32 dynamic DLL load by name.
 *
 * Search order matches Windows-on-disk semantics:
 *   1. Already-loaded module in the process's image table
 *      (covers every preloaded DLL: kernel32, user32, ntdll,
 *      ucrtbase, vcruntime140, msvcp140, advapi32, ...). Fast
 *      path; no syscall round-trip beyond SYS_DLL_BASE_BY_NAME.
 *   2. Filesystem `/lib/<name>` via SYS_DLL_LOAD_FROM_PATH. The
 *      kernel maps the DLL into this process's AS, parses the
 *      EAT, and adds it to the image table — so a follow-up
 *      GetModuleHandleW returns the same base.
 *
 * Returns NULL only if both lookups miss. `LoadLibraryExW`'s
 * `hFile` (reserved on Windows) and `flags` (DONT_RESOLVE_DLL_REFERENCES,
 * LOAD_LIBRARY_AS_DATAFILE, ...) are accepted but ignored in v0
 * — the kernel always maps + resolves the same way regardless. */
__declspec(dllexport) void* LoadLibraryA(const char* name)
{
    if (name == (const char*)0)
        return (void*)(unsigned long long)sys_dll_base_by_name("");
    void* h = (void*)(unsigned long long)sys_dll_base_by_name(name);
    if (h != (void*)0)
        return h;
    return (void*)(unsigned long long)sys_dll_load_from_path(name);
}

__declspec(dllexport) void* LoadLibraryW(const WCHAR_t* name)
{
    if (name == (const WCHAR_t*)0)
        return (void*)(unsigned long long)sys_dll_base_by_name("");
    char abuf[64];
    int i = 0;
    while (i < 63 && name[i] != 0)
    {
        abuf[i] = (char)(name[i] & 0xFF);
        ++i;
    }
    abuf[i] = 0;
    return LoadLibraryA(abuf);
}

__declspec(dllexport) void* LoadLibraryExW(const WCHAR_t* name, void* hFile, DWORD flags)
{
    (void)hFile;
    (void)flags;
    return LoadLibraryW(name);
}

__declspec(dllexport) void* LoadLibraryExA(const char* name, void* hFile, DWORD flags)
{
    (void)hFile;
    (void)flags;
    return LoadLibraryA(name);
}

/* GetModuleHandleExW / GetModuleHandleExA — the *Ex* variants
 * accept the same name set as GetModuleHandleW above and write
 * the result through the out-pointer; the v0 implementation
 * delegates to the named-lookup helper rather than the previous
 * "always not found" stub. The flags argument's pin-or-refcount
 * tier (GET_MODULE_HANDLE_EX_FLAG_PIN, ..._UNCHANGED_REFCOUNT)
 * is documented as harmless for static + preloaded DLLs, which
 * is the only kind we have today. */
__declspec(dllexport) BOOL GetModuleHandleExW(DWORD flags, const WCHAR_t* name, void** phmodule)
{
    (void)flags;
    if (phmodule == (void**)0)
        return 0;
    void* h = GetModuleHandleW(name);
    *phmodule = h;
    return h != (void*)0 ? 1 : 0;
}

__declspec(dllexport) BOOL GetModuleHandleExA(DWORD flags, const char* name, void** phmodule)
{
    (void)flags;
    if (phmodule == (void**)0)
        return 0;
    void* h = GetModuleHandleA(name);
    *phmodule = h;
    return h != (void*)0 ? 1 : 0;
}

__declspec(dllexport) BOOL FreeLibrary(void* hModule)
{
    (void)hModule;
    return 1; /* Pretend success — we don't refcount mapped DLLs yet. */
}

/* ------------------------------------------------------------------
 * SList family — slim-list intrusive stack. v0 returns NULL /
 * 0, matching the flat kOffReturnZero registration for these.
 * Any non-null use would panic with a null pointer today; real
 * callers all have a "what if SList isn't supported" fallback.
 * ------------------------------------------------------------------ */

typedef struct SLIST_ENTRY
{
    struct SLIST_ENTRY* Next;
} SLIST_ENTRY;

__declspec(dllexport) void InterlockedPushEntrySList(void* head, SLIST_ENTRY* entry)
{
    (void)head;
    (void)entry;
}

__declspec(dllexport) SLIST_ENTRY* InterlockedPopEntrySList(void* head)
{
    (void)head;
    return (SLIST_ENTRY*)0;
}

__declspec(dllexport) SLIST_ENTRY* InterlockedFlushSList(void* head)
{
    (void)head;
    return (SLIST_ENTRY*)0;
}

__declspec(dllexport) void InitializeSListHead(void* head)
{
    /* Zero the 16-byte SLIST_HEADER (one pointer + one u64
     * aligned pair on x64). Byte loop keeps this independent
     * of memset. */
    if (head != (void*)0)
    {
        unsigned char* b = (unsigned char*)head;
        for (int i = 0; i < 16; ++i)
            b[i] = 0;
    }
}

/* ------------------------------------------------------------------
 * SEH unwinder foundation (T6-02). Windows forwards these from
 * kernel32 to ntdll; we can't emit PE forwarders, so kernel32
 * carries its own copy (ntdll exports the same — whichever the
 * PE imports resolves via-dll). RtlCaptureContext is a real
 * register snapshot; RtlLookupFunctionEntry is a real
 * table-based .pdata lookup for the main EXE. Pure routines —
 * no kernel fault dispatch yet (that is the next slice).
 * ------------------------------------------------------------------ */

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
                     "movq %%rcx, 0x80(%%rcx)\n\t"
                     "leaq 8(%%rsp), %%rax\n\t"
                     "movq %%rax, 0x98(%%rcx)\n\t"
                     "movq (%%rsp), %%rax\n\t"
                     "movq %%rax, 0xF8(%%rcx)\n\t"
                     "pushfq\n\t"
                     "popq %%rax\n\t"
                     "movl %%eax, 0x44(%%rcx)\n\t"
                     "movl $0x0010000F, 0x30(%%rcx)\n\t"
                     "movq 0x78(%%rcx), %%rax\n\t"
                     "ret\n\t" ::
                         : "memory");
}

typedef struct
{
    unsigned int BeginAddress;
    unsigned int EndAddress;
    unsigned int UnwindInfoAddress;
} K32_RUNTIME_FUNCTION;

__declspec(dllexport) void* RtlLookupFunctionEntry(unsigned long long ControlPc, unsigned long long* ImageBase,
                                                   void* HistoryTable)
{
    (void)HistoryTable;
    const unsigned long long base = sys_dll_base_by_name("");
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
    if (*(const unsigned short*)opt != 0x20B)
        return (void*)0;
    const unsigned int* dd = (const unsigned int*)(opt + 0x70 + 3 * 8);
    const unsigned int pdata_rva = dd[0];
    const unsigned int pdata_sz = dd[1];
    if (pdata_rva == 0 || pdata_sz < sizeof(K32_RUNTIME_FUNCTION))
        return (void*)0;
    const K32_RUNTIME_FUNCTION* fns = (const K32_RUNTIME_FUNCTION*)(img + pdata_rva);
    const unsigned int n = pdata_sz / (unsigned int)sizeof(K32_RUNTIME_FUNCTION);
    const unsigned int off = (unsigned int)(ControlPc - base);
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
