/* comctl32_32.c — i386 comctl32.dll v0 stubs. */
typedef unsigned int DWORD;
typedef int BOOL;
typedef int INT;
typedef void* HANDLE;
typedef HANDLE HIMAGELIST;
typedef HANDLE HBITMAP;
typedef unsigned long COLORREF;

__declspec(dllexport) HIMAGELIST __stdcall ImageList_Create(int cx, int cy, DWORD flags, int n_init, int n_grow)
{
    (void)cx;
    (void)cy;
    (void)flags;
    (void)n_init;
    (void)n_grow;
    return (HIMAGELIST)0x20001;
}

__declspec(dllexport) BOOL __stdcall ImageList_Destroy(HIMAGELIST h)
{
    (void)h;
    return 1;
}

__declspec(dllexport) int __stdcall ImageList_AddMasked(HIMAGELIST h, HBITMAP bmp, COLORREF mask)
{
    (void)h;
    (void)bmp;
    (void)mask;
    return 0;
}

__declspec(dllexport) BOOL __stdcall InitCommonControlsEx(const void* lpInitCtrls)
{
    (void)lpInitCtrls;
    return 1;
}

__declspec(dllexport) INT __stdcall PropertySheetA(const void* lpsh)
{
    (void)lpsh;
    return 0;
}
