/*
 * userland/libs/customdll2/customdll2.c
 *
 * Second freestanding test DLL — exercises the multi-DLL
 * preload path in SpawnPeFile. The
 * full/bare-metal loader policy pre-maps BOTH customdll.dll and
 * customdll2.dll into Win32-imports PE address spaces, and
 * ResolveImports walks the full array on each import lookup.
 *
 * Exports two functions:
 *     CustomDouble(int n) -> int
 *     CustomImportedTick() -> kernel32!GetTickCount()
 *
 * Deliberately disjoint from customdll.dll's export set so a
 * PE that imports CustomDouble HAS to find it in customdll2 —
 * proves the resolver walks past the first DLL on a miss.
 *
 * Built with lld-link /dll /noentry /base:0x10010000 — well
 * below customdll.dll's 0x10000000 load base (3 pages), but
 * still in an unused VA band. Emulator policy leaves this non-essential DLL
 * lazy, so CustomImportedTick gives the strict runtime LoadLibrary profile an
 * import table that must be patched before the module is published.
 */

typedef unsigned long DWORD;
__declspec(dllimport) DWORD GetTickCount(void);

__declspec(dllexport) int CustomDouble(int n)
{
    return n * 2;
}

__declspec(dllexport) DWORD CustomImportedTick(void)
{
    return GetTickCount();
}
