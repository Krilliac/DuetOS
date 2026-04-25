/* comctl32.dll — common controls. No UI; all no-op success. */
typedef int BOOL;
typedef unsigned int DWORD;
typedef void* HANDLE;
typedef unsigned short wchar_t16;

__declspec(dllexport) BOOL InitCommonControls(void)
{
    return 1;
}
__declspec(dllexport) BOOL InitCommonControlsEx(const void* picce)
{
    (void)picce;
    return 1;
}
__declspec(dllexport) HANDLE CreateStatusWindowA(long style, const char* text, HANDLE parent, unsigned int id)
{
    (void)style;
    (void)text;
    (void)parent;
    (void)id;
    return (HANDLE)0;
}
__declspec(dllexport) HANDLE CreateStatusWindowW(long style, const wchar_t16* text, HANDLE parent, unsigned int id)
{
    (void)style;
    (void)text;
    (void)parent;
    (void)id;
    return (HANDLE)0;
}
__declspec(dllexport) BOOL PropertySheetA(const void* hdr)
{
    (void)hdr;
    return 0;
}
__declspec(dllexport) BOOL PropertySheetW(const void* hdr)
{
    (void)hdr;
    return 0;
}
__declspec(dllexport) HANDLE ImageList_Create(int cx, int cy, unsigned int flags, int initial, int grow)
{
    (void)cx;
    (void)cy;
    (void)flags;
    (void)initial;
    (void)grow;
    return (HANDLE)0;
}
__declspec(dllexport) BOOL ImageList_Destroy(HANDLE h)
{
    (void)h;
    return 1;
}

/* ImageList_AddIcon / ImageList_ReplaceIcon: report -1 (failure)
 * since we have no real list to add to. */
__declspec(dllexport) int ImageList_AddIcon(HANDLE list, HANDLE icon)
{
    (void)list;
    (void)icon;
    return -1;
}

__declspec(dllexport) int ImageList_ReplaceIcon(HANDLE list, int index, HANDLE icon)
{
    (void)list;
    (void)index;
    (void)icon;
    return -1;
}

__declspec(dllexport) BOOL ImageList_Draw(HANDLE list, int index, HANDLE dc, int x, int y, unsigned int style)
{
    (void)list;
    (void)index;
    (void)dc;
    (void)x;
    (void)y;
    (void)style;
    return 1;
}

__declspec(dllexport) int ImageList_GetImageCount(HANDLE list)
{
    (void)list;
    return 0;
}

/* DefSubclassProc — passthrough. */
__declspec(dllexport) long long DefSubclassProc(HANDLE hwnd, unsigned int msg, unsigned long long wp,
                                                unsigned long long lp)
{
    (void)hwnd;
    (void)msg;
    (void)wp;
    (void)lp;
    return 0;
}

__declspec(dllexport) BOOL SetWindowSubclass(HANDLE hwnd, void* subclass, unsigned long long id, unsigned long long ref)
{
    (void)hwnd;
    (void)subclass;
    (void)id;
    (void)ref;
    return 1;
}

__declspec(dllexport) BOOL RemoveWindowSubclass(HANDLE hwnd, void* subclass, unsigned long long id)
{
    (void)hwnd;
    (void)subclass;
    (void)id;
    return 1;
}

__declspec(dllexport) BOOL GetWindowSubclass(HANDLE hwnd, void* subclass, unsigned long long id,
                                             unsigned long long* ref)
{
    (void)hwnd;
    (void)subclass;
    (void)id;
    if (ref)
        *ref = 0;
    return 0;
}

/* TaskDialog: minimal Vista+ task dialog. v0 has no window
 * manager wired here, so we return S_OK and fill out the result
 * with IDOK so the caller's "OK clicked" path runs. */
__declspec(dllexport) long TaskDialog(HANDLE owner, HANDLE inst, const wchar_t16* title, const wchar_t16* main_inst,
                                      const wchar_t16* content, int common_btns, const wchar_t16* icon, int* button)
{
    (void)owner;
    (void)inst;
    (void)title;
    (void)main_inst;
    (void)content;
    (void)common_btns;
    (void)icon;
    if (button)
        *button = 1; /* IDOK */
    return 0;        /* S_OK */
}
