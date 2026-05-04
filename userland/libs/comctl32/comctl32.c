/* comctl32.dll — common controls. No UI; all no-op success. */
typedef int BOOL;
typedef unsigned int DWORD;
typedef unsigned long HRESULT;
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

/* TaskDialogIndirect — richer variant. Same v0 semantics. */
__declspec(dllexport) long TaskDialogIndirect(const void* config, int* button, int* radio_button, int* verification)
{
    (void)config;
    if (button)
        *button = 1; /* IDOK */
    if (radio_button)
        *radio_button = 0;
    if (verification)
        *verification = 0;
    return 0;
}

/* _TrackMouseEvent — mouse-leave tracking. v0 reports success;
 * the WM_MOUSELEAVE never fires because no real tracker. */
__declspec(dllexport) BOOL _TrackMouseEvent(void* track_info)
{
    (void)track_info;
    return 1;
}

/* DrawStatusTextA / DrawStatusTextW — status-bar text. */
__declspec(dllexport) void DrawStatusTextA(HANDLE dc, const void* rect, const char* text, unsigned int flags)
{
    (void)dc;
    (void)rect;
    (void)text;
    (void)flags;
}

__declspec(dllexport) void DrawStatusTextW(HANDLE dc, const void* rect, const wchar_t16* text, unsigned int flags)
{
    (void)dc;
    (void)rect;
    (void)text;
    (void)flags;
}

/* CreateToolbarEx / CreateUpDownControl / CreateMappedBitmap —
 * legacy control constructors. NULL is the failure signal that
 * older code already handles. */
__declspec(dllexport) HANDLE CreateToolbarEx(HANDLE parent, DWORD style, unsigned int id, int bmp_count, HANDLE inst,
                                             unsigned long long bmp_id, const void* buttons, int btn_count, int dxbmp,
                                             int dybmp, int dxnbmp, int dynbmp, unsigned int struct_size)
{
    (void)parent;
    (void)style;
    (void)id;
    (void)bmp_count;
    (void)inst;
    (void)bmp_id;
    (void)buttons;
    (void)btn_count;
    (void)dxbmp;
    (void)dybmp;
    (void)dxnbmp;
    (void)dynbmp;
    (void)struct_size;
    return (HANDLE)0;
}

__declspec(dllexport) HANDLE CreateUpDownControl(DWORD style, int x, int y, int cx, int cy, HANDLE parent, int id,
                                                 HANDLE inst, HANDLE buddy, int max, int min, int pos)
{
    (void)style;
    (void)x;
    (void)y;
    (void)cx;
    (void)cy;
    (void)parent;
    (void)id;
    (void)inst;
    (void)buddy;
    (void)max;
    (void)min;
    (void)pos;
    return (HANDLE)0;
}

__declspec(dllexport) HANDLE CreateMappedBitmap(HANDLE inst, unsigned long long id, unsigned int flags, void* info,
                                                int map_size)
{
    (void)inst;
    (void)id;
    (void)flags;
    (void)info;
    (void)map_size;
    return (HANDLE)0;
}

/* DPA_* helpers — dynamic pointer arrays. v0 returns NULL handle
 * for create + 0 / FALSE for everything else. */
__declspec(dllexport) HANDLE DPA_Create(int grow)
{
    (void)grow;
    return (HANDLE)0;
}

__declspec(dllexport) BOOL DPA_Destroy(HANDLE dpa)
{
    (void)dpa;
    return 1;
}

__declspec(dllexport) int DPA_GetPtrCount(HANDLE dpa)
{
    (void)dpa;
    return 0;
}

__declspec(dllexport) void* DPA_GetPtr(HANDLE dpa, int idx)
{
    (void)dpa;
    (void)idx;
    return (void*)0;
}

/* DSA_* — dynamic structure arrays. */
__declspec(dllexport) HANDLE DSA_Create(int item_size, int grow)
{
    (void)item_size;
    (void)grow;
    return (HANDLE)0;
}

__declspec(dllexport) BOOL DSA_Destroy(HANDLE dsa)
{
    (void)dsa;
    return 1;
}

__declspec(dllexport) int DSA_GetItemCount(HANDLE dsa)
{
    (void)dsa;
    return 0;
}

/* GetMUILanguage / SetMUILanguage / InitMUILanguage — multilingual
 * UI helpers. v0 reports en-US (LANG_NEUTRAL_SUBLANG_NEUTRAL = 0)
 * so callers settle on default-language strings. */
__declspec(dllexport) unsigned short GetMUILanguage(void)
{
    return 0; /* MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL) */
}

__declspec(dllexport) void SetMUILanguage(unsigned short lang)
{
    (void)lang;
}

__declspec(dllexport) void InitMUILanguage(unsigned short lang)
{
    (void)lang;
}

/* HIMAGELIST helpers (extra) — ImageList_GetIconSize, _ReadEx,
 * _SetImageCount. */
__declspec(dllexport) BOOL ImageList_GetIconSize(HANDLE list, int* cx, int* cy)
{
    (void)list;
    if (cx)
        *cx = 0;
    if (cy)
        *cy = 0;
    return 1;
}

__declspec(dllexport) BOOL ImageList_SetImageCount(HANDLE list, unsigned int count)
{
    (void)list;
    (void)count;
    return 1;
}

__declspec(dllexport) HANDLE ImageList_LoadImageA(HANDLE inst, const char* file, int cx, int grow,
                                                  unsigned int mask_color, unsigned int type, unsigned int flags)
{
    (void)inst;
    (void)file;
    (void)cx;
    (void)grow;
    (void)mask_color;
    (void)type;
    (void)flags;
    return (HANDLE)0;
}

__declspec(dllexport) HANDLE ImageList_LoadImageW(HANDLE inst, const wchar_t16* file, int cx, int grow,
                                                  unsigned int mask_color, unsigned int type, unsigned int flags)
{
    (void)inst;
    (void)file;
    (void)cx;
    (void)grow;
    (void)mask_color;
    (void)type;
    (void)flags;
    return (HANDLE)0;
}

__declspec(dllexport) BOOL ImageList_BeginDrag(HANDLE list, int track_idx, int dx_hotspot, int dy_hotspot)
{
    (void)list;
    (void)track_idx;
    (void)dx_hotspot;
    (void)dy_hotspot;
    return 1;
}

__declspec(dllexport) void ImageList_EndDrag(void) {}

__declspec(dllexport) BOOL ImageList_DragEnter(HANDLE wnd_lock, int x, int y)
{
    (void)wnd_lock;
    (void)x;
    (void)y;
    return 1;
}

__declspec(dllexport) BOOL ImageList_DragLeave(HANDLE wnd_lock)
{
    (void)wnd_lock;
    return 1;
}

__declspec(dllexport) BOOL ImageList_DragMove(int x, int y)
{
    (void)x;
    (void)y;
    return 1;
}

__declspec(dllexport) BOOL FlatSB_GetScrollInfo(HANDLE wnd, int bar, void* si)
{
    (void)wnd;
    (void)bar;
    (void)si;
    return 0;
}

__declspec(dllexport) int FlatSB_SetScrollInfo(HANDLE wnd, int bar, void* si, BOOL redraw)
{
    (void)wnd;
    (void)bar;
    (void)si;
    (void)redraw;
    return 0;
}

__declspec(dllexport) BOOL InitializeFlatSB(HANDLE wnd)
{
    (void)wnd;
    return 0;
}

__declspec(dllexport) HRESULT UninitializeFlatSB(HANDLE wnd)
{
    (void)wnd;
    return 0;
}

/* MakeDragList / DrawInsert — list-box drag UI. */
__declspec(dllexport) BOOL MakeDragList(HANDLE wnd_lb)
{
    (void)wnd_lb;
    return 0;
}

__declspec(dllexport) void DrawInsert(HANDLE wnd_parent, HANDLE wnd_lb, int item)
{
    (void)wnd_parent;
    (void)wnd_lb;
    (void)item;
}

__declspec(dllexport) int LBItemFromPt(HANDLE wnd_lb, long ppt_packed, BOOL auto_scroll)
{
    (void)wnd_lb;
    (void)ppt_packed;
    (void)auto_scroll;
    return -1; /* LB_ERR */
}
