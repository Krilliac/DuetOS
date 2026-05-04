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

/* DwmEnableMMCSS — multimedia-class scheduler. With no DWM
 * compositor running, "enabling" the MMCSS-driven render
 * ticker is a successful no-op. */
__declspec(dllexport) HRESULT DwmEnableMMCSS(BOOL enable)
{
    (void)enable;
    return S_OK;
}

/* DwmDefWindowProc — pass-through. Real Win32 lets DWM steal
 * non-client hit-tests (caption drag, frame resize). With no
 * compositor we never claim the message; callers fall through
 * to DefWindowProc. */
__declspec(dllexport) BOOL DwmDefWindowProc(HANDLE wnd, unsigned int msg, unsigned long long wp, unsigned long long lp,
                                            unsigned long long* result)
{
    (void)wnd;
    (void)msg;
    (void)wp;
    (void)lp;
    if (result)
        *result = 0;
    return 0; /* not handled */
}

/* DwmGetTransportAttributes — DWM transport status. v0 reports
 * "not remote, no software fallback" so RDP-aware callers fall
 * through to local-render paths. */
__declspec(dllexport) HRESULT DwmGetTransportAttributes(BOOL* remoting, BOOL* terminal, DWORD* speed)
{
    if (remoting)
        *remoting = 0;
    if (terminal)
        *terminal = 0;
    if (speed)
        *speed = 0;
    return S_OK;
}

/* DwmRegisterThumbnail callbacks. The Unregister/Update path is
 * already wired above; add the Update / DwmShowContact for
 * touch-aware apps. */
__declspec(dllexport) HRESULT DwmUpdateThumbnailProperties(HANDLE thumb, const void* props)
{
    (void)thumb;
    (void)props;
    return S_OK;
}

__declspec(dllexport) HRESULT DwmShowContact(DWORD pointer_id, DWORD events)
{
    (void)pointer_id;
    (void)events;
    return S_OK;
}

/* DwmAttachMilContent / DwmDetachMilContent — Direct3D MIL
 * binding. v0 has no MIL; report "not implemented" so callers
 * fall through to GDI-only paint. */
#define E_NOTIMPL 0x80004001UL

__declspec(dllexport) HRESULT DwmAttachMilContent(HANDLE wnd)
{
    (void)wnd;
    return E_NOTIMPL;
}

__declspec(dllexport) HRESULT DwmDetachMilContent(HANDLE wnd)
{
    (void)wnd;
    return E_NOTIMPL;
}

/* DwmGetCompositionTimingInfo — frame-pacing telemetry. v0
 * has no compositor frame counter; zero everything but report
 * S_OK so callers see "no jank". The structure is large
 * (~80 bytes) but treated opaquely on this side. */
__declspec(dllexport) HRESULT DwmGetCompositionTimingInfo(HANDLE wnd, void* timing_info)
{
    (void)wnd;
    if (timing_info)
    {
        unsigned char* p = (unsigned char*)timing_info;
        for (int i = 0; i < 96; ++i)
            p[i] = 0;
    }
    return S_OK;
}

/* DwmModifyPreviousFrame / DwmTransitionOwnedWindow — Vista
 * Aero compatibility shims. */
__declspec(dllexport) HRESULT DwmModifyPreviousFrame(HANDLE wnd, DWORD action, DWORD param)
{
    (void)wnd;
    (void)action;
    (void)param;
    return S_OK;
}

__declspec(dllexport) HRESULT DwmTransitionOwnedWindow(HANDLE wnd, int target)
{
    (void)wnd;
    (void)target;
    return S_OK;
}

/* DwmGetUnmetTabRequirements — Win10 build 17134+. */
__declspec(dllexport) HRESULT DwmGetUnmetTabRequirements(HANDLE wnd, void* requirements)
{
    (void)wnd;
    if (requirements)
        *(unsigned int*)requirements = 0;
    return S_OK;
}

/* DwmpActivateLivePreview — undocumented; some apps poke it. */
__declspec(dllexport) HRESULT DwmpActivateLivePreview(BOOL activate, HANDLE wnd, HANDLE topmost, DWORD flags)
{
    (void)activate;
    (void)wnd;
    (void)topmost;
    (void)flags;
    return S_OK;
}
