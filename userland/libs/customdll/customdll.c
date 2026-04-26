/*
 * userland/libs/customdll/customdll.c
 *
 * Tiny freestanding Windows PE DLL used as the end-to-end test
 * fixture for the stage-2 EAT parser + DLL loader. No imports,
 * no CRT, no TLS, no DllMain. Its entire purpose is to carry a
 * non-empty IMAGE_EXPORT_DIRECTORY through lld-link so the
 * kernel's parser has something real to walk on boot.
 *
 * Exports (in declaration order — lld-link sorts them
 * alphabetically in the ENT, so the absolute ordinals the
 * parser sees are NOT this order):
 *
 *     CustomAdd(int, int)     -> int
 *     CustomMul(int, int)     -> int
 *     CustomVersion()         -> unsigned  (= 0x0200, stage-2 marker)
 *
 * Build (host): see tools/build/build-customdll.sh. The produced DLL
 * is linked with /dll /noentry so no DllMain stub is required;
 * the kernel's DLL loader does not dispatch DllMain yet
 * anyway.
 */

__declspec(dllexport) int CustomAdd(int a, int b)
{
    return a + b;
}

__declspec(dllexport) int CustomMul(int a, int b)
{
    return a * b;
}

__declspec(dllexport) unsigned CustomVersion(void)
{
    return 0x00000200u;
}
