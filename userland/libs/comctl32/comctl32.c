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
