/* dwmapi.dll — Desktop Window Manager. No compositor; all stubs. */
typedef int BOOL;
typedef unsigned long DWORD;
typedef void* HANDLE;
typedef unsigned long HRESULT;

#define S_OK 0UL
#define DWM_EC_DISABLECOMPOSITION 0UL

__declspec(dllexport) HRESULT DwmIsCompositionEnabled(BOOL* enabled)
{
    if (enabled)
        *enabled = 0;
    return S_OK;
}
__declspec(dllexport) HRESULT DwmEnableComposition(DWORD enable)
{
    (void)enable;
    return S_OK;
}
__declspec(dllexport) HRESULT DwmExtendFrameIntoClientArea(HANDLE wnd, const void* margins)
{
    (void)wnd;
    (void)margins;
    return S_OK;
}
__declspec(dllexport) HRESULT DwmGetWindowAttribute(HANDLE wnd, DWORD attr, void* attr_data, DWORD attr_size)
{
    (void)wnd;
    (void)attr;
    (void)attr_data;
    (void)attr_size;
    return S_OK;
}
__declspec(dllexport) HRESULT DwmSetWindowAttribute(HANDLE wnd, DWORD attr, const void* attr_data, DWORD attr_size)
{
    (void)wnd;
    (void)attr;
    (void)attr_data;
    (void)attr_size;
    return S_OK;
}
__declspec(dllexport) HRESULT DwmFlush(void)
{
    return S_OK;
}

/* DwmGetColorizationColor — return a fixed black with no
 * transparency. Apps that read this for accent-painting see a
 * stable answer instead of garbage. */
__declspec(dllexport) HRESULT DwmGetColorizationColor(DWORD* color, BOOL* opaque)
{
    if (color)
        *color = 0xFF000000UL;
    if (opaque)
        *opaque = 1;
    return S_OK;
}

__declspec(dllexport) HRESULT DwmEnableBlurBehindWindow(HANDLE wnd, const void* bb)
{
    (void)wnd;
    (void)bb;
    return S_OK;
}

__declspec(dllexport) HRESULT DwmRegisterThumbnail(HANDLE dst, HANDLE src, HANDLE* thumb)
{
    (void)dst;
    (void)src;
    if (thumb)
        *thumb = (HANDLE)0;
    return 0x80004001UL; /* E_NOTIMPL */
}

__declspec(dllexport) HRESULT DwmUnregisterThumbnail(HANDLE thumb)
{
    (void)thumb;
    return S_OK;
}

__declspec(dllexport) HRESULT DwmInvalidateIconicBitmaps(HANDLE wnd)
{
    (void)wnd;
    return S_OK;
}

__declspec(dllexport) HRESULT DwmSetIconicThumbnail(HANDLE wnd, HANDLE bmp, DWORD flags)
{
    (void)wnd;
    (void)bmp;
    (void)flags;
    return S_OK;
}

__declspec(dllexport) HRESULT DwmSetIconicLivePreviewBitmap(HANDLE wnd, HANDLE bmp, void* origin, DWORD flags)
{
    (void)wnd;
    (void)bmp;
    (void)origin;
    (void)flags;
    return S_OK;
}
