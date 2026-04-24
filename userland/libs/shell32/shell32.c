/*
 * userland/libs/shell32/shell32.c — 13 stubs: CommandLineToArgvW,
 * Extract/File/Folder/ShellExecute. All return NULL / -1 / FAIL.
 */

typedef int BOOL;
typedef unsigned int UINT;
typedef unsigned int DWORD;
typedef unsigned long HRESULT;
typedef void* HANDLE;
typedef unsigned short wchar_t16;

#define S_OK 0UL
#define E_FAIL 0x80004005UL

__declspec(dllexport) wchar_t16** CommandLineToArgvW(const wchar_t16* cmd, int* argc)
{
    (void)cmd;
    if (argc)
        *argc = 0;
    return (wchar_t16**)0; /* v0 doesn't allocate; caller sees NULL */
}

__declspec(dllexport) UINT ExtractIconW(HANDLE h, const wchar_t16* file, UINT idx)
{
    (void)h;
    (void)file;
    (void)idx;
    return 0; /* NULL HICON */
}

__declspec(dllexport) UINT ExtractIconExW(const wchar_t16* file, int idx, HANDLE* large, HANDLE* small, UINT n)
{
    (void)file;
    (void)idx;
    (void)large;
    (void)small;
    (void)n;
    return 0;
}

__declspec(dllexport) int SHCreateDirectoryW(HANDLE parent, const wchar_t16* path)
{
    (void)parent;
    (void)path;
    return 5; /* ERROR_ACCESS_DENIED — close enough for v0 */
}

__declspec(dllexport) int SHCreateDirectoryExW(HANDLE parent, const wchar_t16* path, void* sec)
{
    (void)parent;
    (void)path;
    (void)sec;
    return 5;
}

__declspec(dllexport) int SHFileOperationW(void* lpFileOp)
{
    (void)lpFileOp;
    return 5;
}

__declspec(dllexport) HRESULT SHGetFolderPathA(HANDLE hWnd, int folder, HANDLE hToken, DWORD flags, char* path)
{
    (void)hWnd;
    (void)folder;
    (void)hToken;
    (void)flags;
    if (path)
        path[0] = 0;
    return E_FAIL;
}

__declspec(dllexport) HRESULT SHGetFolderPathW(HANDLE hWnd, int folder, HANDLE hToken, DWORD flags, wchar_t16* path)
{
    (void)hWnd;
    (void)folder;
    (void)hToken;
    (void)flags;
    if (path)
        path[0] = 0;
    return E_FAIL;
}

__declspec(dllexport) HRESULT SHGetKnownFolderPath(const void* rfid, DWORD flags, HANDLE hToken, wchar_t16** out)
{
    (void)rfid;
    (void)flags;
    (void)hToken;
    if (out)
        *out = (wchar_t16*)0;
    return E_FAIL;
}

__declspec(dllexport) BOOL SHGetPathFromIDListW(const void* pidl, wchar_t16* path)
{
    (void)pidl;
    if (path)
        path[0] = 0;
    return 0;
}

__declspec(dllexport) BOOL SHGetSpecialFolderPathW(HANDLE hWnd, wchar_t16* path, int csidl, BOOL create)
{
    (void)hWnd;
    (void)csidl;
    (void)create;
    if (path)
        path[0] = 0;
    return 0;
}

__declspec(dllexport) HANDLE ShellExecuteW(HANDLE hWnd, const wchar_t16* verb, const wchar_t16* file,
                                           const wchar_t16* params, const wchar_t16* dir, int nShow)
{
    (void)hWnd;
    (void)verb;
    (void)file;
    (void)params;
    (void)dir;
    (void)nShow;
    return (HANDLE)(long long)31; /* SE_ERR_NOASSOC — "no association" */
}

__declspec(dllexport) BOOL ShellExecuteExW(void* info)
{
    (void)info;
    return 0;
}
