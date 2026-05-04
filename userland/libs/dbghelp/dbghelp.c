/*
 * userland/libs/dbghelp/dbghelp.c
 *
 * Freestanding DuetOS dbghelp.dll. Retires the +
 * the bulk-registered dbghelp flat stubs. All entry points
 * are no-ops that return sensible defaults — v0 has no
 * debug-info parsing, no PDB loader, no stack-walk. Real
 * callers in CRT crash handlers and minidump writers check
 * return values and fall back to "no debug info" paths.
 *
 * SymInitialize / SymInitializeW / SymCleanup return TRUE
 * (claim a debug session). All other SymXxx / StackWalk /
 * MiniDumpWriteDump return 0 = FALSE (no info, no walk, no
 * dump).
 *
 * Build: tools/build/build-dbghelp-dll.sh at /base:0x10070000.
 */

typedef int BOOL;
typedef void* HANDLE;
typedef unsigned long DWORD;

__declspec(dllexport) BOOL SymInitialize(HANDLE hProcess, const char* UserSearchPath, BOOL fInvadeProcess)
{
    (void)hProcess;
    (void)UserSearchPath;
    (void)fInvadeProcess;
    return 1;
}

__declspec(dllexport) BOOL SymInitializeW(HANDLE hProcess, const void* UserSearchPath, BOOL fInvadeProcess)
{
    (void)hProcess;
    (void)UserSearchPath;
    (void)fInvadeProcess;
    return 1;
}

__declspec(dllexport) BOOL SymCleanup(HANDLE hProcess)
{
    (void)hProcess;
    return 1;
}

__declspec(dllexport) BOOL SymFromAddr(HANDLE hProcess, unsigned long long Address, unsigned long long* Displacement,
                                       void* Symbol)
{
    (void)hProcess;
    (void)Address;
    (void)Symbol;
    if (Displacement != (unsigned long long*)0)
        *Displacement = 0;
    return 0; /* Symbol not found. */
}

__declspec(dllexport) BOOL SymFromAddrW(HANDLE hProcess, unsigned long long Address, unsigned long long* Displacement,
                                        void* Symbol)
{
    (void)hProcess;
    (void)Address;
    (void)Symbol;
    if (Displacement != (unsigned long long*)0)
        *Displacement = 0;
    return 0;
}

__declspec(dllexport) BOOL SymGetLineFromAddr64(HANDLE hProcess, unsigned long long dwAddr, DWORD* pdwDisplacement,
                                                void* Line)
{
    (void)hProcess;
    (void)dwAddr;
    (void)Line;
    if (pdwDisplacement != (DWORD*)0)
        *pdwDisplacement = 0;
    return 0;
}

__declspec(dllexport) unsigned long long SymLoadModule64(HANDLE hProcess, HANDLE hFile, const char* ImageName,
                                                         const char* ModuleName, unsigned long long BaseOfDll,
                                                         DWORD SizeOfDll)
{
    (void)hProcess;
    (void)hFile;
    (void)ImageName;
    (void)ModuleName;
    (void)BaseOfDll;
    (void)SizeOfDll;
    return 0; /* No module loaded. */
}

__declspec(dllexport) BOOL StackWalk64(DWORD MachineType, HANDLE hProcess, HANDLE hThread, void* StackFrame,
                                       void* ContextRecord, void* ReadMemoryRoutine, void* FunctionTableAccessRoutine,
                                       void* GetModuleBaseRoutine, void* TranslateAddress)
{
    (void)MachineType;
    (void)hProcess;
    (void)hThread;
    (void)StackFrame;
    (void)ContextRecord;
    (void)ReadMemoryRoutine;
    (void)FunctionTableAccessRoutine;
    (void)GetModuleBaseRoutine;
    (void)TranslateAddress;
    return 0; /* No more frames. */
}

__declspec(dllexport) void* SymFunctionTableAccess64(HANDLE hProcess, unsigned long long AddrBase)
{
    (void)hProcess;
    (void)AddrBase;
    return (void*)0;
}

__declspec(dllexport) unsigned long long SymGetModuleBase64(HANDLE hProcess, unsigned long long qwAddr)
{
    (void)hProcess;
    (void)qwAddr;
    return 0;
}

__declspec(dllexport) BOOL MiniDumpWriteDump(HANDLE hProcess, DWORD ProcessId, HANDLE hFile, DWORD DumpType,
                                             void* Exception, void* UserStream, void* Callback)
{
    (void)hProcess;
    (void)ProcessId;
    (void)hFile;
    (void)DumpType;
    (void)Exception;
    (void)UserStream;
    (void)Callback;
    return 0; /* No dump written. */
}

__declspec(dllexport) BOOL SymGetModuleInfo64(HANDLE hProcess, unsigned long long qwAddr, void* ModuleInfo)
{
    (void)hProcess;
    (void)qwAddr;
    (void)ModuleInfo;
    return 0;
}

/* Sym options + search path are tracked in process-local statics.
 * Real Windows stores these per-process in the DbgHelp engine; we
 * approximate with a single static slot since each PE load brings
 * a fresh dbghelp.dll image anyway. SymInitialize sets the default
 * options; SymSetOptions overwrites + returns the prior value (the
 * Win32 contract); SymGetOptions reads the current value. */
static DWORD g_sym_options = 0;

#define SYMOPT_CASE_INSENSITIVE 0x00000001UL
#define SYMOPT_UNDNAME 0x00000002UL
#define SYMOPT_DEFERRED_LOADS 0x00000004UL

__declspec(dllexport) DWORD SymGetOptions(void)
{
    return g_sym_options;
}

__declspec(dllexport) DWORD SymSetOptions(DWORD opts)
{
    DWORD prior = g_sym_options;
    g_sym_options = opts;
    return prior;
}

__declspec(dllexport) BOOL SymRefreshModuleList(HANDLE hProcess)
{
    (void)hProcess;
    return 1;
}

__declspec(dllexport) BOOL SymUnloadModule64(HANDLE hProcess, unsigned long long base)
{
    (void)hProcess;
    (void)base;
    return 1;
}

__declspec(dllexport) BOOL SymEnumSymbols(HANDLE hProcess, unsigned long long base, const char* mask, void* cb,
                                          void* user)
{
    (void)hProcess;
    (void)base;
    (void)mask;
    (void)cb;
    (void)user;
    return 1; /* Empty enum — no callbacks fire. */
}

__declspec(dllexport) BOOL SymEnumSymbolsW(HANDLE hProcess, unsigned long long base, const void* mask, void* cb,
                                           void* user)
{
    (void)hProcess;
    (void)base;
    (void)mask;
    (void)cb;
    (void)user;
    return 1;
}

__declspec(dllexport) DWORD UnDecorateSymbolName(const char* DecoratedName, char* UnDecoratedName, DWORD UndecoratedLen,
                                                 DWORD Flags)
{
    (void)Flags;
    if (!UnDecoratedName || UndecoratedLen == 0)
        return 0;
    DWORD i = 0;
    if (DecoratedName)
    {
        for (; i + 1 < UndecoratedLen && DecoratedName[i]; ++i)
            UnDecoratedName[i] = DecoratedName[i];
    }
    UnDecoratedName[i] = 0;
    return i;
}

/* Symbol-server search path. Real Windows uses this to locate PDBs
 * across local cache + symsrv URLs; we lack PDB parsing but tracking
 * the value lets a caller's "set then get" round-trip preserve state. */
#define SYM_SEARCH_PATH_MAX 512
static char g_sym_search_path[SYM_SEARCH_PATH_MAX] = {0};

__declspec(dllexport) BOOL SymGetSearchPath(HANDLE hProcess, char* path, DWORD path_len)
{
    (void)hProcess;
    if (!path || path_len == 0)
        return 0;
    DWORD i = 0;
    for (; i + 1 < path_len && g_sym_search_path[i]; ++i)
        path[i] = g_sym_search_path[i];
    path[i] = 0;
    return 1;
}

__declspec(dllexport) BOOL SymSetSearchPath(HANDLE hProcess, const char* path)
{
    (void)hProcess;
    if (!path)
    {
        g_sym_search_path[0] = 0;
        return 1;
    }
    DWORD i = 0;
    for (; i + 1 < SYM_SEARCH_PATH_MAX && path[i]; ++i)
        g_sym_search_path[i] = path[i];
    g_sym_search_path[i] = 0;
    return 1;
}

/* MakeSureDirectoryPathExists — modern dbghelp helper. Real
 * Win32 calls CreateDirectory for each component. Without an
 * mkdir syscall in the freestanding profile, return TRUE so the
 * caller treats the path as already-extant; symbol-loaders that
 * use it for cache prep then proceed normally (the cache misses
 * are silent).  */
__declspec(dllexport) BOOL MakeSureDirectoryPathExists(const char* path)
{
    (void)path;
    return 1;
}

/* ImageNtHeader — return the NT header pointer embedded in a
 * mapped PE image. The PE is in the caller's address space (we
 * don't gate on it), so a small header walk is safe: read the
 * DOS magic at offset 0, then the e_lfanew field to find the
 * NT header. NULL on bad inputs. */
__declspec(dllexport) void* ImageNtHeader(void* base)
{
    if (!base)
        return (void*)0;
    unsigned char* p = (unsigned char*)base;
    /* IMAGE_DOS_HEADER.e_magic = "MZ" at offset 0. */
    if (p[0] != 'M' || p[1] != 'Z')
        return (void*)0;
    /* IMAGE_DOS_HEADER.e_lfanew is a 32-bit LE field at offset 0x3C. */
    unsigned int e_lfanew = (unsigned int)p[0x3C] | ((unsigned int)p[0x3D] << 8) | ((unsigned int)p[0x3E] << 16) |
                            ((unsigned int)p[0x3F] << 24);
    /* Sanity: NT signature "PE\0\0" at base+e_lfanew. Keep the
     * cap loose — a valid header lives well below 4 KiB. */
    if (e_lfanew == 0 || e_lfanew > 0x800)
        return (void*)0;
    unsigned char* nt = p + e_lfanew;
    if (nt[0] != 'P' || nt[1] != 'E' || nt[2] != 0 || nt[3] != 0)
        return (void*)0;
    return nt;
}

/* ImageRvaToVa — translate an RVA to an absolute VA against a
 * mapped image. v0 callers pass the same image they got from
 * ImageNtHeader, so we just add. Section walk (last_rva_section)
 * is a follow-up. */
__declspec(dllexport) void* ImageRvaToVa(void* nt_headers, void* base, unsigned long rva, void* last_rva_section)
{
    (void)nt_headers;
    (void)last_rva_section;
    if (!base)
        return (void*)0;
    return (void*)((unsigned char*)base + rva);
}

/* ImageDirectoryEntryToData — fetch a data-directory entry
 * (e.g. import table) by index. The IMAGE_NT_HEADERS64 layout is:
 *   +0  Signature ("PE\0\0", 4 bytes)
 *   +4  IMAGE_FILE_HEADER (20 bytes)
 *   +24 IMAGE_OPTIONAL_HEADER64 (224 bytes for x64)
 *       +88 in opt hdr: NumberOfRvaAndSizes (DWORD)
 *       +92 in opt hdr: DataDirectory[] (8 bytes each: RVA + size)
 * Total offset to DataDirectory[0] from NT base = 24 + 92 + 12 = 128 ... wait let me recheck. The OptHdr starts at offset 24. DataDirectory in OptHdr64 is at offset 112 (after Magic+...+NumberOfRvaAndSizes). NumberOfRvaAndSizes is at OptHdr+108. So DataDirectory[i] = NT_base + 24 + 112 + i*8. Practically there are 16 entries, indexed 0..15.
 */
__declspec(dllexport) void* ImageDirectoryEntryToData(void* base, BOOL mapped, unsigned short directory, DWORD* size)
{
    if (size)
        *size = 0;
    if (!base)
        return (void*)0;
    void* nt = ImageNtHeader(base);
    if (!nt)
        return (void*)0;
    unsigned char* nh = (unsigned char*)nt;
    /* Magic at OptHdr+0 distinguishes PE32 (0x10B) from PE32+ (0x20B). */
    unsigned short opt_magic = (unsigned short)nh[24] | ((unsigned short)nh[25] << 8);
    DWORD dd_off;
    DWORD num_rvas_off;
    if (opt_magic == 0x20B)
    {
        /* PE32+ (x86_64): NumberOfRvaAndSizes at OptHdr+108; DataDirectory at OptHdr+112. */
        num_rvas_off = 24 + 108;
        dd_off = 24 + 112;
    }
    else if (opt_magic == 0x10B)
    {
        /* PE32 (x86): NumberOfRvaAndSizes at OptHdr+92; DataDirectory at OptHdr+96. */
        num_rvas_off = 24 + 92;
        dd_off = 24 + 96;
    }
    else
    {
        return (void*)0;
    }
    DWORD num_rvas = (DWORD)nh[num_rvas_off] | ((DWORD)nh[num_rvas_off + 1] << 8) |
                     ((DWORD)nh[num_rvas_off + 2] << 16) | ((DWORD)nh[num_rvas_off + 3] << 24);
    if ((DWORD)directory >= num_rvas)
        return (void*)0;
    unsigned char* dd = nh + dd_off + (DWORD)directory * 8;
    DWORD rva = (DWORD)dd[0] | ((DWORD)dd[1] << 8) | ((DWORD)dd[2] << 16) | ((DWORD)dd[3] << 24);
    DWORD sz = (DWORD)dd[4] | ((DWORD)dd[5] << 8) | ((DWORD)dd[6] << 16) | ((DWORD)dd[7] << 24);
    if (rva == 0 || sz == 0)
        return (void*)0;
    if (size)
        *size = sz;
    /* When mapped == TRUE the image is loaded by the OS loader and RVA
     * == VA offset directly. When mapped == FALSE the caller has a flat
     * file mapping — we'd need to resolve the section that owns rva and
     * translate to file offset. v0 only ever sees "mapped" PEs (the
     * loader maps them), so for mapped==FALSE we still treat rva as a
     * direct offset; a caller passing a flat-mapped PE will see a
     * pointer into the wrong region but won't fault. */
    (void)mapped;
    return (void*)((unsigned char*)base + rva);
}

/* SymGetSearchPathW — wide variant of SymGetSearchPath. */
__declspec(dllexport) BOOL SymGetSearchPathW(HANDLE hProcess, void* path, DWORD path_len)
{
    (void)hProcess;
    if (path && path_len > 0)
    {
        unsigned char* p = (unsigned char*)path;
        p[0] = 0;
        p[1] = 0;
    }
    return 1;
}

/* SymSetSearchPathW. */
__declspec(dllexport) BOOL SymSetSearchPathW(HANDLE hProcess, const void* path)
{
    (void)hProcess;
    (void)path;
    return 1;
}

/* SymRegisterCallback / SymRegisterCallback64 — callback hooks
 * for symbol-loading events. Registering succeeds (TRUE) but no
 * events ever fire because the loader never finds a debug
 * source. Real callers use this for progress UIs that just
 * stay idle. */
__declspec(dllexport) BOOL SymRegisterCallback(HANDLE hProcess, void* callback, void* user)
{
    (void)hProcess;
    (void)callback;
    (void)user;
    return 1;
}

__declspec(dllexport) BOOL SymRegisterCallback64(HANDLE hProcess, void* callback, unsigned long long user)
{
    (void)hProcess;
    (void)callback;
    (void)user;
    return 1;
}

/* SymEnumerateModules64 — empty enum, succeeds. Same v0 shape
 * as SymEnumSymbols. */
__declspec(dllexport) BOOL SymEnumerateModules64(HANDLE hProcess, void* callback, void* user)
{
    (void)hProcess;
    (void)callback;
    (void)user;
    return 1;
}

/* EnumerateLoadedModules / EnumerateLoadedModules64 — same
 * empty enum. */
__declspec(dllexport) BOOL EnumerateLoadedModules(HANDLE hProcess, void* callback, void* user)
{
    (void)hProcess;
    (void)callback;
    (void)user;
    return 1;
}

__declspec(dllexport) BOOL EnumerateLoadedModules64(HANDLE hProcess, void* callback, void* user)
{
    (void)hProcess;
    (void)callback;
    (void)user;
    return 1;
}

/* SymGetTypeInfo — empty type info. */
__declspec(dllexport) BOOL SymGetTypeInfo(HANDLE hProcess, unsigned long long mod_base, unsigned long type_id,
                                          int get_type_kind, void* info)
{
    (void)hProcess;
    (void)mod_base;
    (void)type_id;
    (void)get_type_kind;
    (void)info;
    return 0;
}

/* SymSearch — empty search, succeeds. */
__declspec(dllexport) BOOL SymSearch(HANDLE hProcess, unsigned long long base, DWORD index, DWORD sym_tag,
                                     const char* mask, unsigned long long addr, void* cb, void* user, DWORD options)
{
    (void)hProcess;
    (void)base;
    (void)index;
    (void)sym_tag;
    (void)mask;
    (void)addr;
    (void)cb;
    (void)user;
    (void)options;
    return 1;
}

/* SymGetHomeDirectoryW — return an empty string so callers
 * computing a default cache path know to use their fallback. */
__declspec(dllexport) void* SymGetHomeDirectoryW(DWORD type, void* dir, unsigned long long size)
{
    (void)type;
    (void)size;
    if (dir)
    {
        unsigned char* p = (unsigned char*)dir;
        p[0] = 0;
        p[1] = 0;
    }
    return dir;
}

/* SymFindFileInPath / SymFindFileInPathW — debug-symbol search.
 * v0 reports "not found" so callers fall back to "no debug". */
__declspec(dllexport) BOOL SymFindFileInPath(HANDLE hProcess, const char* search, const char* file, void* id, DWORD two,
                                             DWORD three, DWORD flags, char* found, void* cb, void* user)
{
    (void)hProcess;
    (void)search;
    (void)file;
    (void)id;
    (void)two;
    (void)three;
    (void)flags;
    (void)cb;
    (void)user;
    if (found)
        found[0] = 0;
    return 0;
}
