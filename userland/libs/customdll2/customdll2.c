/*
 * userland/libs/customdll2/customdll2.c
 *
 * Second freestanding test DLL — exercises the multi-DLL
 * preload path in SpawnPeFile. The
 * loader now pre-maps BOTH customdll.dll and customdll2.dll
 * into every Win32-imports PE's address space, and
 * ResolveImports walks the full array on each import lookup.
 *
 * Exports one function:
 *     CustomDouble(int n) -> int
 *
 * Deliberately disjoint from customdll.dll's export set so a
 * PE that imports CustomDouble HAS to find it in customdll2 —
 * proves the resolver walks past the first DLL on a miss.
 *
 * Built with lld-link /dll /noentry /base:0x10010000 — well
 * below customdll.dll's 0x10000000 load base (3 pages), but
 * still in an unused VA band.
 */

__declspec(dllexport) int CustomDouble(int n)
{
    return n * 2;
}
