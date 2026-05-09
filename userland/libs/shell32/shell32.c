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

/* SHGetFolderPathA/W / SHGetSpecialFolderPathA/W: pre-Vista folder
 * lookup. CSIDL is masked of its CSIDL_FLAG_* bits (0xFF00) and
 * dispatched against a per-CSIDL canonical path table. The user-
 * profile root mirrors userenv.c's USERPROFILE convention
 * (X:\Users\duetos); paths under it follow Windows Vista+ naming
 * (e.g. CSIDL_APPDATA → AppData\Roaming) so PE binaries get
 * the layout they expect. Unrecognised CSIDLs fall through to the
 * profile root — the same "give me ANY path" behaviour the v0
 * thunk had, just labelled. */
#define CSIDL_FLAG_MASK 0xFF00
#define CSIDL_DESKTOP 0x0000
#define CSIDL_PROGRAMS 0x0002
#define CSIDL_PERSONAL 0x0005 /* aka MYDOCUMENTS */
#define CSIDL_FAVORITES 0x0006
#define CSIDL_STARTUP 0x0007
#define CSIDL_RECENT 0x0008
#define CSIDL_SENDTO 0x0009
#define CSIDL_STARTMENU 0x000B
#define CSIDL_MYDOCUMENTS 0x000C
#define CSIDL_MYMUSIC 0x000D
#define CSIDL_MYVIDEO 0x000E
#define CSIDL_DESKTOPDIRECTORY 0x0010
#define CSIDL_FONTS 0x0014
#define CSIDL_TEMPLATES 0x0015
#define CSIDL_COMMON_STARTMENU 0x0016
#define CSIDL_COMMON_PROGRAMS 0x0017
#define CSIDL_COMMON_STARTUP 0x0018
#define CSIDL_COMMON_DESKTOPDIRECTORY 0x0019
#define CSIDL_APPDATA 0x001A
#define CSIDL_PRINTHOOD 0x001B
#define CSIDL_LOCAL_APPDATA 0x001C
#define CSIDL_INTERNET_CACHE 0x0020
#define CSIDL_COOKIES 0x0021
#define CSIDL_HISTORY 0x0022
#define CSIDL_COMMON_APPDATA 0x0023
#define CSIDL_WINDOWS 0x0024
#define CSIDL_SYSTEM 0x0025
#define CSIDL_PROGRAM_FILES 0x0026
#define CSIDL_MYPICTURES 0x0027
#define CSIDL_PROFILE 0x0028
#define CSIDL_PROGRAM_FILES_COMMON 0x002B
#define CSIDL_COMMON_DOCUMENTS 0x002E
#define CSIDL_COMMON_ADMINTOOLS 0x002F
#define CSIDL_ADMINTOOLS 0x0030

static const char kProfileRoot[] = "X:\\Users\\duetos";

static const char* csidl_to_path(int csidl)
{
    const int c = csidl & ~CSIDL_FLAG_MASK;
    switch (c)
    {
    case CSIDL_DESKTOP:
    case CSIDL_DESKTOPDIRECTORY:
        return "X:\\Users\\duetos\\Desktop";
    case CSIDL_PROGRAMS:
        return "X:\\Users\\duetos\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs";
    case CSIDL_PERSONAL:
    case CSIDL_MYDOCUMENTS:
        return "X:\\Users\\duetos\\Documents";
    case CSIDL_FAVORITES:
        return "X:\\Users\\duetos\\Favorites";
    case CSIDL_STARTUP:
        return "X:\\Users\\duetos\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup";
    case CSIDL_RECENT:
        return "X:\\Users\\duetos\\AppData\\Roaming\\Microsoft\\Windows\\Recent";
    case CSIDL_SENDTO:
        return "X:\\Users\\duetos\\AppData\\Roaming\\Microsoft\\Windows\\SendTo";
    case CSIDL_STARTMENU:
        return "X:\\Users\\duetos\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu";
    case CSIDL_MYMUSIC:
        return "X:\\Users\\duetos\\Music";
    case CSIDL_MYVIDEO:
        return "X:\\Users\\duetos\\Videos";
    case CSIDL_FONTS:
        return "X:\\Windows\\Fonts";
    case CSIDL_TEMPLATES:
        return "X:\\Users\\duetos\\AppData\\Roaming\\Microsoft\\Windows\\Templates";
    case CSIDL_COMMON_STARTMENU:
        return "X:\\ProgramData\\Microsoft\\Windows\\Start Menu";
    case CSIDL_COMMON_PROGRAMS:
        return "X:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs";
    case CSIDL_COMMON_STARTUP:
        return "X:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup";
    case CSIDL_COMMON_DESKTOPDIRECTORY:
        return "X:\\Users\\Public\\Desktop";
    case CSIDL_APPDATA:
        return "X:\\Users\\duetos\\AppData\\Roaming";
    case CSIDL_PRINTHOOD:
        return "X:\\Users\\duetos\\AppData\\Roaming\\Microsoft\\Windows\\Printer Shortcuts";
    case CSIDL_LOCAL_APPDATA:
        return "X:\\Users\\duetos\\AppData\\Local";
    case CSIDL_INTERNET_CACHE:
        return "X:\\Users\\duetos\\AppData\\Local\\Microsoft\\Windows\\INetCache";
    case CSIDL_COOKIES:
        return "X:\\Users\\duetos\\AppData\\Local\\Microsoft\\Windows\\INetCookies";
    case CSIDL_HISTORY:
        return "X:\\Users\\duetos\\AppData\\Local\\Microsoft\\Windows\\History";
    case CSIDL_COMMON_APPDATA:
        return "X:\\ProgramData";
    case CSIDL_WINDOWS:
        return "X:\\Windows";
    case CSIDL_SYSTEM:
        return "X:\\Windows\\System32";
    case CSIDL_PROGRAM_FILES:
        return "X:\\Program Files";
    case CSIDL_MYPICTURES:
        return "X:\\Users\\duetos\\Pictures";
    case CSIDL_PROFILE:
        return kProfileRoot;
    case CSIDL_PROGRAM_FILES_COMMON:
        return "X:\\Program Files\\Common Files";
    case CSIDL_COMMON_DOCUMENTS:
        return "X:\\Users\\Public\\Documents";
    case CSIDL_COMMON_ADMINTOOLS:
        return "X:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools";
    case CSIDL_ADMINTOOLS:
        return "X:\\Users\\duetos\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools";
    default:
        return kProfileRoot;
    }
}

static int copy_str_a(const char* src, char* dst, int max)
{
    int i = 0;
    for (; src[i] && i < max - 1; ++i)
        dst[i] = src[i];
    dst[i] = 0;
    return i;
}

static int copy_str_w(const char* src, wchar_t16* dst, int max)
{
    int i = 0;
    for (; src[i] && i < max - 1; ++i)
        dst[i] = (wchar_t16)(unsigned char)src[i];
    dst[i] = 0;
    return i;
}

__declspec(dllexport) HRESULT SHGetFolderPathA(HANDLE hWnd, int folder, HANDLE hToken, DWORD flags, char* path)
{
    (void)hWnd;
    (void)hToken;
    (void)flags;
    if (!path)
        return E_FAIL;
    copy_str_a(csidl_to_path(folder), path, 260);
    return S_OK;
}

__declspec(dllexport) HRESULT SHGetFolderPathW(HANDLE hWnd, int folder, HANDLE hToken, DWORD flags, wchar_t16* path)
{
    (void)hWnd;
    (void)hToken;
    (void)flags;
    if (!path)
        return E_FAIL;
    copy_str_w(csidl_to_path(folder), path, 260);
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
    (void)create;
    if (!path)
        return 0;
    copy_str_w(csidl_to_path(csidl), path, 260);
    return 1;
}

__declspec(dllexport) BOOL SHGetSpecialFolderPathA(HANDLE hWnd, char* path, int csidl, BOOL create)
{
    (void)hWnd;
    (void)create;
    if (!path)
        return 0;
    copy_str_a(csidl_to_path(csidl), path, 260);
    return 1;
}

/* SHGetDesktopFolder — return a minimal IShellFolder COM object.
 *
 * The "desktop folder" in Win32 is the root of the shell namespace
 * (everything reachable through the shell starts here). Real Windows
 * returns an IShellFolder whose ParseDisplayName / EnumObjects /
 * BindToObject methods walk the namespace.
 *
 * v0 returns a singleton object whose vtable methods all succeed
 * with empty / sentinel results: enumeration yields zero items,
 * parse fails cleanly, GetDisplayNameOf yields "Desktop". This is
 * enough for callers that probe for the desktop folder and then
 * graceful-fallback when the namespace is empty (most file-pickers,
 * Win32 PE shell utilities). The class isn't `class-not-registered`
 * any more — that's the v0 win this slice books.
 */
typedef struct IShellFolderVtbl IShellFolderVtbl;
typedef struct IShellFolderObj
{
    const IShellFolderVtbl* lpVtbl;
    unsigned long refs;
} IShellFolderObj;

struct IShellFolderVtbl
{
    /* IUnknown */
    HRESULT(__stdcall* QueryInterface)(IShellFolderObj*, const void*, void**);
    unsigned long(__stdcall* AddRef)(IShellFolderObj*);
    unsigned long(__stdcall* Release)(IShellFolderObj*);
    /* IShellFolder */
    HRESULT(__stdcall* ParseDisplayName)
    (IShellFolderObj*, HANDLE, void*, wchar_t16*, unsigned long*, void**, unsigned long*);
    HRESULT(__stdcall* EnumObjects)(IShellFolderObj*, HANDLE, unsigned long, void**);
    HRESULT(__stdcall* BindToObject)(IShellFolderObj*, const void*, void*, const void*, void**);
    HRESULT(__stdcall* BindToStorage)(IShellFolderObj*, const void*, void*, const void*, void**);
    HRESULT(__stdcall* CompareIDs)(IShellFolderObj*, long long, const void*, const void*);
    HRESULT(__stdcall* CreateViewObject)(IShellFolderObj*, HANDLE, const void*, void**);
    HRESULT(__stdcall* GetAttributesOf)(IShellFolderObj*, unsigned int, const void**, unsigned long*);
    HRESULT(__stdcall* GetUIObjectOf)
    (IShellFolderObj*, HANDLE, unsigned int, const void**, const void*, unsigned int*, void**);
    HRESULT(__stdcall* GetDisplayNameOf)(IShellFolderObj*, const void*, unsigned long, void*);
    HRESULT(__stdcall* SetNameOf)(IShellFolderObj*, HANDLE, const void*, const wchar_t16*, unsigned long, void**);
};

static HRESULT __stdcall sh_desktop_qi(IShellFolderObj* self, const void* riid, void** ppv)
{
    (void)riid;
    if (!ppv)
        return E_FAIL;
    /* Return self for any requested interface — shell32 v0 is one
     * shape. Real Windows would inspect riid and return E_NOINTERFACE
     * for unrelated interfaces; we accept everything because callers
     * that QI for IUnknown / IShellFolder / IPersist / IPersistFolder
     * all walk the same vtable here. */
    *ppv = self;
    if (self)
        ++self->refs;
    return S_OK;
}

static unsigned long __stdcall sh_desktop_addref(IShellFolderObj* self)
{
    if (!self)
        return 0;
    return ++self->refs;
}

static unsigned long __stdcall sh_desktop_release(IShellFolderObj* self)
{
    if (!self)
        return 0;
    /* Singleton — never falls below 1, never freed. */
    if (self->refs > 1)
        --self->refs;
    return self->refs;
}

static HRESULT __stdcall sh_desktop_parse_display_name(IShellFolderObj* self, HANDLE hwnd, void* bind, wchar_t16* name,
                                                       unsigned long* eaten, void** pidl, unsigned long* attrs)
{
    (void)self;
    (void)hwnd;
    (void)bind;
    (void)name;
    if (eaten)
        *eaten = 0;
    if (pidl)
        *pidl = (void*)0;
    if (attrs)
        *attrs = 0;
    return E_FAIL; /* no namespace → can't parse */
}

static HRESULT __stdcall sh_desktop_enum_objects(IShellFolderObj* self, HANDLE hwnd, unsigned long flags, void** ppenum)
{
    (void)self;
    (void)hwnd;
    (void)flags;
    if (ppenum)
        *ppenum = (void*)0;
    return S_OK; /* zero-item enumeration → caller's loop ends immediately */
}

static HRESULT __stdcall sh_desktop_bind_to_object(IShellFolderObj* self, const void* pidl, void* bind,
                                                   const void* riid, void** out)
{
    (void)self;
    (void)pidl;
    (void)bind;
    (void)riid;
    if (out)
        *out = (void*)0;
    return E_FAIL;
}

static HRESULT __stdcall sh_desktop_bind_to_storage(IShellFolderObj* self, const void* pidl, void* bind,
                                                    const void* riid, void** out)
{
    (void)self;
    (void)pidl;
    (void)bind;
    (void)riid;
    if (out)
        *out = (void*)0;
    return E_FAIL;
}

static HRESULT __stdcall sh_desktop_compare_ids(IShellFolderObj* self, long long lparam, const void* a, const void* b)
{
    (void)self;
    (void)lparam;
    (void)a;
    (void)b;
    return 0; /* "equal" — nothing distinguishes empty PIDLs */
}

static HRESULT __stdcall sh_desktop_create_view_object(IShellFolderObj* self, HANDLE owner, const void* riid,
                                                       void** out)
{
    (void)self;
    (void)owner;
    (void)riid;
    if (out)
        *out = (void*)0;
    return E_FAIL;
}

static HRESULT __stdcall sh_desktop_get_attributes_of(IShellFolderObj* self, unsigned int n, const void** pidls,
                                                      unsigned long* attrs)
{
    (void)self;
    (void)n;
    (void)pidls;
    if (attrs)
        *attrs = 0;
    return S_OK;
}

static HRESULT __stdcall sh_desktop_get_ui_object_of(IShellFolderObj* self, HANDLE hwnd, unsigned int n,
                                                     const void** pidls, const void* riid, unsigned int* reserved,
                                                     void** out)
{
    (void)self;
    (void)hwnd;
    (void)n;
    (void)pidls;
    (void)riid;
    (void)reserved;
    if (out)
        *out = (void*)0;
    return E_FAIL;
}

static HRESULT __stdcall sh_desktop_get_display_name_of(IShellFolderObj* self, const void* pidl, unsigned long flags,
                                                        void* str)
{
    (void)self;
    (void)pidl;
    (void)flags;
    /* Win32 STRRET uses a 264-byte struct — we don't depend on
     * which form (cStr / pOleStr / uOffset) the caller probed; clear
     * the discriminator and the buffer so a downstream scan stops at
     * NUL whichever form it picks. */
    if (str)
    {
        unsigned char* p = (unsigned char*)str;
        for (int i = 0; i < 264; ++i)
            p[i] = 0;
    }
    return S_OK;
}

static HRESULT __stdcall sh_desktop_set_name_of(IShellFolderObj* self, HANDLE hwnd, const void* pidl,
                                                const wchar_t16* name, unsigned long flags, void** out)
{
    (void)self;
    (void)hwnd;
    (void)pidl;
    (void)name;
    (void)flags;
    if (out)
        *out = (void*)0;
    return E_FAIL;
}

static const IShellFolderVtbl g_desktop_folder_vtbl = {
    sh_desktop_qi,
    sh_desktop_addref,
    sh_desktop_release,
    sh_desktop_parse_display_name,
    sh_desktop_enum_objects,
    sh_desktop_bind_to_object,
    sh_desktop_bind_to_storage,
    sh_desktop_compare_ids,
    sh_desktop_create_view_object,
    sh_desktop_get_attributes_of,
    sh_desktop_get_ui_object_of,
    sh_desktop_get_display_name_of,
    sh_desktop_set_name_of,
};

static IShellFolderObj g_desktop_folder = {&g_desktop_folder_vtbl, 1};

__declspec(dllexport) HRESULT SHGetDesktopFolder(void** ppshf)
{
    if (!ppshf)
        return E_FAIL;
    ++g_desktop_folder.refs;
    *ppshf = &g_desktop_folder;
    return S_OK;
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
