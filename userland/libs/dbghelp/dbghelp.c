/*
 * userland/libs/dbghelp/dbghelp.c
 *
 * Freestanding DuetOS dbghelp.dll. Retires the batch-47 +
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
 * Build: tools/build-dbghelp-dll.sh at /base:0x10070000.
 */

typedef int    BOOL;
typedef void*  HANDLE;
typedef unsigned long DWORD;

__declspec(dllexport) BOOL SymInitialize(HANDLE hProcess, const char* UserSearchPath, BOOL fInvadeProcess)
{
    (void) hProcess;
    (void) UserSearchPath;
    (void) fInvadeProcess;
    return 1;
}

__declspec(dllexport) BOOL SymInitializeW(HANDLE hProcess, const void* UserSearchPath, BOOL fInvadeProcess)
{
    (void) hProcess;
    (void) UserSearchPath;
    (void) fInvadeProcess;
    return 1;
}

__declspec(dllexport) BOOL SymCleanup(HANDLE hProcess)
{
    (void) hProcess;
    return 1;
}

__declspec(dllexport) BOOL SymFromAddr(HANDLE hProcess, unsigned long long Address, unsigned long long* Displacement,
                                      void* Symbol)
{
    (void) hProcess;
    (void) Address;
    (void) Symbol;
    if (Displacement != (unsigned long long*) 0)
        *Displacement = 0;
    return 0; /* Symbol not found. */
}

__declspec(dllexport) BOOL SymFromAddrW(HANDLE hProcess, unsigned long long Address,
                                       unsigned long long* Displacement, void* Symbol)
{
    (void) hProcess;
    (void) Address;
    (void) Symbol;
    if (Displacement != (unsigned long long*) 0)
        *Displacement = 0;
    return 0;
}

__declspec(dllexport) BOOL SymGetLineFromAddr64(HANDLE hProcess, unsigned long long dwAddr,
                                               DWORD* pdwDisplacement, void* Line)
{
    (void) hProcess;
    (void) dwAddr;
    (void) Line;
    if (pdwDisplacement != (DWORD*) 0)
        *pdwDisplacement = 0;
    return 0;
}

__declspec(dllexport) unsigned long long SymLoadModule64(HANDLE hProcess, HANDLE hFile, const char* ImageName,
                                                        const char* ModuleName, unsigned long long BaseOfDll,
                                                        DWORD SizeOfDll)
{
    (void) hProcess;
    (void) hFile;
    (void) ImageName;
    (void) ModuleName;
    (void) BaseOfDll;
    (void) SizeOfDll;
    return 0; /* No module loaded. */
}

__declspec(dllexport) BOOL StackWalk64(DWORD MachineType, HANDLE hProcess, HANDLE hThread, void* StackFrame,
                                      void* ContextRecord, void* ReadMemoryRoutine,
                                      void* FunctionTableAccessRoutine, void* GetModuleBaseRoutine,
                                      void* TranslateAddress)
{
    (void) MachineType;
    (void) hProcess;
    (void) hThread;
    (void) StackFrame;
    (void) ContextRecord;
    (void) ReadMemoryRoutine;
    (void) FunctionTableAccessRoutine;
    (void) GetModuleBaseRoutine;
    (void) TranslateAddress;
    return 0; /* No more frames. */
}

__declspec(dllexport) void* SymFunctionTableAccess64(HANDLE hProcess, unsigned long long AddrBase)
{
    (void) hProcess;
    (void) AddrBase;
    return (void*) 0;
}

__declspec(dllexport) unsigned long long SymGetModuleBase64(HANDLE hProcess, unsigned long long qwAddr)
{
    (void) hProcess;
    (void) qwAddr;
    return 0;
}

__declspec(dllexport) BOOL MiniDumpWriteDump(HANDLE hProcess, DWORD ProcessId, HANDLE hFile, DWORD DumpType,
                                            void* Exception, void* UserStream, void* Callback)
{
    (void) hProcess;
    (void) ProcessId;
    (void) hFile;
    (void) DumpType;
    (void) Exception;
    (void) UserStream;
    (void) Callback;
    return 0; /* No dump written. */
}
