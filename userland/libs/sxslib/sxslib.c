/*
 * sxslib.dll — companion DLL for the side-by-side loader fixture.
 *
 * Deliberately trivial and deliberately NOT embedded in the kernel
 * image: this DLL exists only as a file staged next to sxstest.exe on
 * the FAT32 volume. If sxstest.exe can call SxsAnswer(), the kernel
 * found a DLL that ships beside the .exe, read it off the volume,
 * passed it through the security guard, mapped it, and bound the
 * import — which is the whole point of the fixture.
 *
 * Freestanding: no CRT, no imports of its own. DuetOS's DllLoad does
 * not dispatch DllMain, so the entry point exists purely to satisfy
 * the linker.
 */

__declspec(dllexport) unsigned int SxsAnswer(void)
{
    return 4242u;
}

/* Second export, imported by name from the .exe alongside the first,
 * so the fixture proves EAT lookup rather than a single lucky hit. */
__declspec(dllexport) unsigned int SxsDouble(unsigned int v)
{
    return v * 2u;
}

int __stdcall DllMainCRTStartup(void* inst, unsigned long reason, void* reserved)
{
    (void)inst;
    (void)reason;
    (void)reserved;
    return 1;
}
