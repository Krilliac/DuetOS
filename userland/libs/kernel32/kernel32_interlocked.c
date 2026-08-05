#include "kernel32_internal.h"

#include "../common/pe_unwind_bounds.h"

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

/* Per-handle console mode tracking. STD_INPUT_HANDLE (-10),
 * STD_OUTPUT_HANDLE (-11), STD_ERROR_HANDLE (-12) each get
 * their own mode word. Index: 0=stdin, 1=stdout, 2=stderr.
 *
 * Default modes match Windows defaults:
 *   stdin:  ENABLE_PROCESSED_INPUT(1) | ENABLE_LINE_INPUT(2)
 *           | ENABLE_ECHO_INPUT(4) = 0x07
 *   stdout: ENABLE_PROCESSED_OUTPUT(1) | ENABLE_WRAP_AT_EOL_OUTPUT(2) = 0x03
 *   stderr: same as stdout = 0x03
 */
static DWORD g_console_mode[3] = {0x07, 0x03, 0x03};

static int console_mode_index(HANDLE h)
{
    unsigned long long v = (unsigned long long)(UINT_PTR)h;
    if (v == 0xFFFFFFF6ULL)
        return 0; /* STD_INPUT_HANDLE  = -10 */
    if (v == 0xFFFFFFF5ULL)
        return 1; /* STD_OUTPUT_HANDLE = -11 */
    if (v == 0xFFFFFFF4ULL)
        return 2; /* STD_ERROR_HANDLE  = -12 */
    return -1;
}

/* Cross-TU accessor (declared in kernel32_internal.h): the console
 * VT tracker (kernel32_locale.c) and the console-input surface
 * (kernel32_console.c) key their behaviour off the per-handle mode
 * word this TU owns. Same defaulting as GetConsoleMode below. */
DWORD kernel32_console_mode_of(HANDLE h)
{
    const int idx = console_mode_index(h);
    return (idx >= 0) ? g_console_mode[idx] : 0x03u;
}

__declspec(dllexport) BOOL GetConsoleMode(HANDLE hConsole, DWORD* lpMode)
{
    if (lpMode == (DWORD*)0)
        return 0;
    int idx = console_mode_index(hConsole);
    if (idx >= 0)
        *lpMode = g_console_mode[idx];
    else
        *lpMode = 0x03; /* default for unknown handles */
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
    int idx = console_mode_index(hConsole);
    if (idx >= 0)
        g_console_mode[idx] = mode;
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

/* RtlCaptureContext lives in seh_capture.S — same pattern as
 * ntdll's seh_trampolines.S and for the same reason (string-
 * literal asm body, hand-copied CONTEXT offsets per entry). Both
 * DLLs ship a body so whichever the PE importer resolves to has
 * a real export. They MUST stay byte-identical — audit on every
 * change. */
__declspec(dllexport) void RtlCaptureContext(void* ContextRecord);

typedef struct
{
    unsigned int BeginAddress;
    unsigned int EndAddress;
    unsigned int UnwindInfoAddress;
} K32_RUNTIME_FUNCTION;

static unsigned long long k32_module_base_by_va(unsigned long long va)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)207), "D"(va) : "memory");
    return (unsigned long long)rv;
}

__declspec(dllexport) void* RtlLookupFunctionEntry(unsigned long long ControlPc, unsigned long long* ImageBase,
                                                   void* HistoryTable)
{
    (void)HistoryTable;
    const unsigned long long base = k32_module_base_by_va(ControlPc);
    if (base == 0 || ControlPc < base)
        return (void*)0;
    DUET_PE_VIEW view;
    if (!duet_pe_parse((const void*)base, &view) || ControlPc - base >= view.size)
        return (void*)0;
    if (ImageBase != (unsigned long long*)0)
        *ImageBase = base;
    const K32_RUNTIME_FUNCTION* fns = (const K32_RUNTIME_FUNCTION*)(view.base + view.pdata_rva);
    const unsigned int n = view.pdata_size / (unsigned int)sizeof(K32_RUNTIME_FUNCTION);
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

/* ------------------------------------------------------------------
 * RtlVirtualUnwind (T6-02 slice 2) — x64 table-based frame unwind.
 *
 * Interprets the function's UNWIND_INFO unwind codes to transform
 * ContextRecord from "in this frame" to "in the caller's frame":
 * pops PUSH_NONVOL saves, undoes stack allocs, follows SET_FPREG /
 * SAVE_NONVOL / SAVE_XMM128 / PUSH_MACHFRAME / chained info,
 * then pops the return address into Rip. Pure computation — no
 * control flow transfer. CodeOffset gates operations for a PC in
 * the prologue. GAP: epilogue instruction decoding; body/call-site
 * and partial-prologue unwinds are table-driven.
 * ------------------------------------------------------------------ */

/* CONTEXT GPR offsets, indexed by the x64 unwind register number
 * (0=RAX..15=R15). RSP is index 4. */
static const unsigned short k_ctx_gpr_off[16] = {0x78, 0x80, 0x88, 0x90, 0x98, 0xA0, 0xA8, 0xB0,
                                                 0xB8, 0xC0, 0xC8, 0xD0, 0xD8, 0xE0, 0xE8, 0xF0};
#define K32_CTX_RSP_OFF 0x98
#define K32_CTX_RIP_OFF 0xF8

static unsigned long long* k32_ctx_reg(void* ctx, int idx)
{
    return (unsigned long long*)((unsigned char*)ctx + k_ctx_gpr_off[idx & 15]);
}
static unsigned long long* k32_ctx_rsp(void* ctx)
{
    return (unsigned long long*)((unsigned char*)ctx + K32_CTX_RSP_OFF);
}
static unsigned long long* k32_ctx_rip(void* ctx)
{
    return (unsigned long long*)((unsigned char*)ctx + K32_CTX_RIP_OFF);
}
static void k32_restore_xmm(void* ctx, int idx, const void* saved)
{
    /* CONTEXT.Xmm0 begins at 0x1a0; copy without imposing a C
     * alignment requirement on the unwind save slot. */
    unsigned char* dst = (unsigned char*)ctx + 0x1A0 + (unsigned)(idx & 15) * 16u;
    const unsigned char* src = (const unsigned char*)saved;
    for (unsigned j = 0; j < 16u; ++j)
        dst[j] = src[j];
}
static int k32_nonvolatile_gpr(unsigned reg)
{
    return reg == 3u || reg == 5u || reg == 6u || reg == 7u || reg >= 12u;
}
static int k32_unwind_op_width(unsigned short code, unsigned frreg, unsigned* width)
{
    const unsigned op = (code >> 8) & 0x0Fu;
    const unsigned info = (code >> 12) & 0x0Fu;
    if (op == 0u)
    {
        if (!k32_nonvolatile_gpr(info))
            return 0;
        *width = 1u;
    }
    else if (op == 1u)
    {
        if (info > 1u)
            return 0;
        *width = info == 0u ? 2u : 3u;
    }
    else if (op == 2u)
    {
        *width = 1u;
    }
    else if (op == 3u)
    {
        if (info != 0u || frreg == 0u || !k32_nonvolatile_gpr(frreg))
            return 0;
        *width = 1u;
    }
    else if (op == 4u || op == 5u)
    {
        if (!k32_nonvolatile_gpr(info))
            return 0;
        *width = op == 4u ? 2u : 3u;
    }
    else if (op == 8u || op == 9u)
    {
        if (info < 6u)
            return 0;
        *width = op == 8u ? 2u : 3u;
    }
    else if (op == 10u)
    {
        if (info > 1u)
            return 0;
        *width = 1u;
    }
    else
    {
        return 0;
    }
    return 1;
}
static int k32_validate_unwind_chain(const DUET_PE_VIEW* view, const K32_RUNTIME_FUNCTION* first)
{
    return duet_pe_validate_unwind_chain(view, first);
}
static unsigned k32_prolog_offset(const unsigned char* ui, unsigned long long image_base,
                                  const K32_RUNTIME_FUNCTION* rf, unsigned long long control_pc)
{
    const unsigned long long begin = image_base + rf->BeginAddress;
    if (control_pc <= begin)
        return 0u;
    const unsigned long long offset = control_pc - begin;
    return offset >= (unsigned long long)ui[1] ? 0xFFu : (unsigned)offset;
}
static int k32_chain_frame_established(const DUET_PE_VIEW* view, const K32_RUNTIME_FUNCTION* first,
                                       unsigned long long image_base, unsigned long long control_pc)
{
    return duet_pe_chain_frame_established(view, first, image_base, control_pc);
}

__declspec(dllexport) void* RtlVirtualUnwind(unsigned long HandlerType, unsigned long long ImageBase,
                                             unsigned long long ControlPc, void* FunctionEntry, void* ContextRecord,
                                             void** HandlerData, unsigned long long* EstablisherFrame,
                                             void* ContextPointers)
{
    (void)HandlerType;
    (void)ContextPointers;
    if (HandlerData != (void**)0)
        *HandlerData = (void*)0;
    if (FunctionEntry == (void*)0 || ContextRecord == (void*)0)
        return (void*)0;
    const K32_RUNTIME_FUNCTION* rf = (const K32_RUNTIME_FUNCTION*)FunctionEntry;
    DUET_PE_VIEW view;
    if (k32_module_base_by_va(ControlPc) != ImageBase || !duet_pe_parse((const void*)ImageBase, &view) ||
        ControlPc < ImageBase || ControlPc - ImageBase >= view.size || !k32_validate_unwind_chain(&view, rf))
        return (void*)0;
    DUET_PE_UNWIND_LAYOUT head;
    if (!duet_pe_unwind_layout(&view, rf, &head))
        return (void*)0;
    const int frame_established = k32_chain_frame_established(&view, rf, ImageBase, ControlPc);
    const unsigned long long frame_base =
        frame_established ? (*k32_ctx_reg(ContextRecord, (int)head.frreg) - (unsigned long long)head.froff * 16ULL)
                          : *k32_ctx_rsp(ContextRecord);

    for (int chain_guard = 0; chain_guard < 32; ++chain_guard)
    {
        const unsigned char* ui = (const unsigned char*)(ImageBase + rf->UnwindInfoAddress);
        const unsigned char flags = (unsigned char)(ui[0] >> 3);
        const unsigned char count = ui[2];
        const unsigned char frreg = (unsigned char)(ui[3] & 0x0F);
        const unsigned char froff = (unsigned char)(ui[3] >> 4);
        const unsigned short* codes = (const unsigned short*)(ui + 4);
        const unsigned prolog_offset = chain_guard == 0 ? k32_prolog_offset(ui, ImageBase, rf, ControlPc) : 0xFFu;
        const unsigned long long fb = frame_base;

        unsigned i = 0;
        while (i < count)
        {
            const unsigned short cw = codes[i];
            const unsigned op = (cw >> 8) & 0x0F;
            const unsigned info = (cw >> 12) & 0x0F;
            const unsigned code_offset = cw & 0xFFu;
            unsigned width = 0;
            if (!k32_unwind_op_width(cw, frreg, &width) || width > count - i)
                return (void*)0;
            if (code_offset > prolog_offset)
            {
                i += width;
                continue;
            }
            unsigned long long* rsp = k32_ctx_rsp(ContextRecord);
            if (op == 0) /* PUSH_NONVOL */
            {
                *k32_ctx_reg(ContextRecord, (int)info) = *(unsigned long long*)(*rsp);
                *rsp += 8;
            }
            else if (op == 1) /* ALLOC_LARGE */
            {
                if (info == 0)
                    *rsp += (unsigned long long)codes[i + 1] * 8ULL;
                else
                    *rsp += (unsigned long long)duet_pe_u32(&codes[i + 1]);
            }
            else if (op == 2) /* ALLOC_SMALL */
            {
                *rsp += (unsigned long long)info * 8ULL + 8ULL;
            }
            else if (op == 3) /* SET_FPREG */
            {
                *rsp = *k32_ctx_reg(ContextRecord, (int)frreg) - (unsigned long long)froff * 16ULL;
            }
            else if (op == 4) /* SAVE_NONVOL */
            {
                const unsigned long long off = (unsigned long long)codes[i + 1] * 8ULL;
                *k32_ctx_reg(ContextRecord, (int)info) = *(unsigned long long*)(fb + off);
            }
            else if (op == 5) /* SAVE_NONVOL_FAR */
            {
                const unsigned long long off = (unsigned long long)duet_pe_u32(&codes[i + 1]);
                *k32_ctx_reg(ContextRecord, (int)info) = *(unsigned long long*)(fb + off);
            }
            else if (op == 8) /* SAVE_XMM128 */
            {
                const unsigned long long off = (unsigned long long)codes[i + 1] * 16ULL;
                k32_restore_xmm(ContextRecord, (int)info, (const void*)(fb + off));
            }
            else if (op == 9) /* SAVE_XMM128_FAR */
            {
                const unsigned long long off = (unsigned long long)duet_pe_u32(&codes[i + 1]);
                k32_restore_xmm(ContextRecord, (int)info, (const void*)(fb + off));
            }
            else if (op == 10) /* PUSH_MACHFRAME */
            {
                const unsigned long long base = *rsp + (info ? 8ULL : 0ULL);
                *k32_ctx_rip(ContextRecord) = *(unsigned long long*)base;
                *rsp = *(unsigned long long*)(base + 24ULL);
                if (EstablisherFrame != (unsigned long long*)0)
                    *EstablisherFrame = fb;
                return (void*)0; /* machine frame: Rip/Rsp already final */
            }
            else
            {
                return (void*)0;
            }
            i += width;
        }

        if (flags & 0x4) /* UNW_FLAG_CHAININFO */
        {
            const unsigned even = (unsigned)((count + 1) & ~1u);
            rf = (const K32_RUNTIME_FUNCTION*)(codes + even);
            continue;
        }
        break;
    }

    /* Pop the return address. */
    unsigned long long* rsp = k32_ctx_rsp(ContextRecord);
    *k32_ctx_rip(ContextRecord) = *(unsigned long long*)(*rsp);
    *rsp += 8;
    if (EstablisherFrame != (unsigned long long*)0)
        *EstablisherFrame = *rsp;
    return (void*)0;
}

/* Real RtlCaptureStackBackTrace: capture + repeatedly
 * RtlLookupFunctionEntry / RtlVirtualUnwind. Leaf functions with
 * no .pdata entry terminate the walk (return-addr-on-rsp
 * fallback for a leaf, then stop). */
__declspec(dllexport) unsigned short RtlCaptureStackBackTrace(unsigned long FramesToSkip, unsigned long FramesToCapture,
                                                              void** BackTrace, unsigned long* BackTraceHash)
{
    if (BackTrace == (void**)0 || FramesToCapture == 0)
        return 0;
    unsigned char ctxbuf[1232] __attribute__((aligned(16)));
    for (int z = 0; z < 1232; ++z)
        ctxbuf[z] = 0;
    RtlCaptureContext(ctxbuf);
    unsigned long hash = 0;
    unsigned short n = 0;
    for (unsigned long depth = 0; depth < FramesToSkip + FramesToCapture && n < 0xFFFF; ++depth)
    {
        unsigned long long pc = *k32_ctx_rip(ctxbuf);
        if (pc == 0)
            break;
        unsigned long long ib = 0;
        void* fe = RtlLookupFunctionEntry(pc, &ib, (void*)0);
        if (fe == (void*)0)
            break; /* leaf / no .pdata — stop the walk */
        unsigned long long est = 0;
        RtlVirtualUnwind(0, ib, pc, fe, ctxbuf, (void**)0, &est, (void*)0);
        unsigned long long npc = *k32_ctx_rip(ctxbuf);
        if (npc == 0 || npc == pc)
            break;
        if (depth >= FramesToSkip)
        {
            BackTrace[n++] = (void*)npc;
            hash += (unsigned long)npc;
        }
    }
    if (BackTraceHash != (unsigned long*)0)
        *BackTraceHash = hash;
    return n;
}
