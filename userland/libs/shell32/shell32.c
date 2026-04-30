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

/* CommandLineToArgvW — minimal whitespace-split parser.
 * Allocates a single LocalAlloc block holding the argv pointer
 * array followed by a parallel buffer of the parsed tokens. */
__declspec(dllexport) wchar_t16** CommandLineToArgvW(const wchar_t16* cmd, int* argc)
{
    if (argc == (int*)0)
        return (wchar_t16**)0;
    *argc = 0;
    if (cmd == (const wchar_t16*)0)
        return (wchar_t16**)0;
    /* First pass: count tokens, total chars. */
    int n = 0, total = 0;
    int i = 0;
    while (cmd[i] != 0)
    {
        while (cmd[i] == ' ' || cmd[i] == '\t')
            ++i;
        if (cmd[i] == 0)
            break;
        ++n;
        while (cmd[i] != 0 && cmd[i] != ' ' && cmd[i] != '\t')
        {
            ++i;
            ++total;
        }
        ++total; /* NUL */
    }
    /* Allocate via SYS_HEAP_ALLOC — argv pointers + parallel chars. */
    unsigned long bytes = (unsigned long)n * sizeof(wchar_t16*) + (unsigned long)total * sizeof(wchar_t16);
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)11), "D"((long long)bytes) : "memory");
    if (rv == 0)
        return (wchar_t16**)0;
    wchar_t16** argv = (wchar_t16**)rv;
    wchar_t16* str_buf = (wchar_t16*)((unsigned char*)rv + n * sizeof(wchar_t16*));
    /* Second pass: copy. */
    int k = 0, w = 0;
    i = 0;
    while (cmd[i] != 0)
    {
        while (cmd[i] == ' ' || cmd[i] == '\t')
            ++i;
        if (cmd[i] == 0)
            break;
        argv[k++] = &str_buf[w];
        while (cmd[i] != 0 && cmd[i] != ' ' && cmd[i] != '\t')
        {
            str_buf[w++] = cmd[i++];
        }
        str_buf[w++] = 0;
    }
    *argc = n;
    return argv;
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

/* SHGetFolderPathA/W: pre-Vista folder lookup. v0 returns
 * "X:\Users\duetos" for any folder so callers that need a real
 * answer (writable config dir, app-data, etc.) get something. */
static const char kFolder[] = "X:\\Users\\duetos";

__declspec(dllexport) HRESULT SHGetFolderPathA(HANDLE hWnd, int folder, HANDLE hToken, DWORD flags, char* path)
{
    (void)hWnd;
    (void)folder;
    (void)hToken;
    (void)flags;
    if (!path)
        return E_FAIL;
    int i = 0;
    for (; kFolder[i] && i < 259; ++i)
        path[i] = kFolder[i];
    path[i] = 0;
    return S_OK;
}

__declspec(dllexport) HRESULT SHGetFolderPathW(HANDLE hWnd, int folder, HANDLE hToken, DWORD flags, wchar_t16* path)
{
    (void)hWnd;
    (void)folder;
    (void)hToken;
    (void)flags;
    if (!path)
        return E_FAIL;
    int i = 0;
    for (; kFolder[i] && i < 259; ++i)
        path[i] = (wchar_t16)kFolder[i];
    path[i] = 0;
    return S_OK;
}

/* SHGetKnownFolderPath: Vista+ replacement. v0 doesn't allocate
 * memory across the API boundary, so still fail — callers that
 * need a real folder path should use SHGetFolderPathW. */
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
    if (!path)
        return 0;
    int i = 0;
    for (; kFolder[i] && i < 259; ++i)
        path[i] = (wchar_t16)kFolder[i];
    path[i] = 0;
    return 1;
}

__declspec(dllexport) BOOL SHGetSpecialFolderPathA(HANDLE hWnd, char* path, int csidl, BOOL create)
{
    (void)hWnd;
    (void)csidl;
    (void)create;
    if (!path)
        return 0;
    int i = 0;
    for (; kFolder[i] && i < 259; ++i)
        path[i] = kFolder[i];
    path[i] = 0;
    return 1;
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

__declspec(dllexport) HANDLE ShellExecuteA(HANDLE hWnd, const char* verb, const char* file, const char* params,
                                           const char* dir, int nShow)
{
    (void)hWnd;
    (void)verb;
    (void)file;
    (void)params;
    (void)dir;
    (void)nShow;
    return (HANDLE)(long long)31;
}

__declspec(dllexport) BOOL ShellExecuteExA(void* info)
{
    (void)info;
    return 0;
}

__declspec(dllexport) DWORD SHGetFileInfoA(const char* path, DWORD attrs, void* psfi, UINT cbSize, UINT flags)
{
    (void)path;
    (void)attrs;
    (void)psfi;
    (void)cbSize;
    (void)flags;
    return 0;
}

__declspec(dllexport) DWORD SHGetFileInfoW(const wchar_t16* path, DWORD attrs, void* psfi, UINT cbSize, UINT flags)
{
    (void)path;
    (void)attrs;
    (void)psfi;
    (void)cbSize;
    (void)flags;
    return 0;
}

__declspec(dllexport) BOOL Shell_NotifyIconA(DWORD msg, void* data)
{
    (void)msg;
    (void)data;
    return 0;
}

__declspec(dllexport) BOOL Shell_NotifyIconW(DWORD msg, void* data)
{
    (void)msg;
    (void)data;
    return 0;
}

__declspec(dllexport) UINT DragQueryFileA(HANDLE hDrop, UINT idx, char* path, UINT path_len)
{
    (void)hDrop;
    (void)idx;
    (void)path_len;
    if (path && path_len > 0)
        path[0] = 0;
    return 0;
}

__declspec(dllexport) UINT DragQueryFileW(HANDLE hDrop, UINT idx, wchar_t16* path, UINT path_len)
{
    (void)hDrop;
    (void)idx;
    (void)path_len;
    if (path && path_len > 0)
        path[0] = 0;
    return 0;
}

__declspec(dllexport) void DragAcceptFiles(HANDLE hWnd, BOOL accept)
{
    (void)hWnd;
    (void)accept;
}

__declspec(dllexport) void DragFinish(HANDLE hDrop)
{
    (void)hDrop;
}
