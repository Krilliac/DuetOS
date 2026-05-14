/* shell32_32.c — i386 shell32.dll v0 stubs. */
typedef unsigned int DWORD;
typedef int INT;
typedef void* HANDLE;
typedef unsigned short wchar_t16;

__declspec(dllexport) wchar_t16** __stdcall CommandLineToArgvW(const wchar_t16* cmdline, INT* argc)
{
    /* v0: hand back a single-element argv with the program name.
     * Static so the pointer remains live across the caller's use. */
    static wchar_t16 prog[] = {'a', '.', 'e', 'x', 'e', 0};
    static wchar_t16* argv[2] = {prog, 0};
    (void)cmdline;
    if (argc)
        *argc = 1;
    return argv;
}

__declspec(dllexport) int __stdcall SHGetFolderPathA(HANDLE hwnd, INT csidl, HANDLE token, DWORD flags, char* path)
{
    (void)hwnd;
    (void)csidl;
    (void)token;
    (void)flags;
    if (path)
        path[0] = 0;
    return 0x80004005; /* E_FAIL — caller's not-found path runs */
}
