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
