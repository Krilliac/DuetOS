/* d3d11.dll — no D3D11. Both entry points return E_NOTIMPL. */
typedef unsigned long HRESULT;
#define E_NOTIMPL 0x80004001UL

__declspec(dllexport) HRESULT D3D11CreateDevice(void* adapter, int driver_type, void* software, unsigned int flags,
                                                const void* feature_levels, unsigned int num_feature_levels,
                                                unsigned int sdk, void** device, void* out_fl, void** ctx)
{
    (void)adapter;
    (void)driver_type;
    (void)software;
    (void)flags;
    (void)feature_levels;
    (void)num_feature_levels;
    (void)sdk;
    (void)out_fl;
    if (device)
        *device = (void*)0;
    if (ctx)
        *ctx = (void*)0;
    return E_NOTIMPL;
}

__declspec(dllexport) HRESULT D3D11CreateDeviceAndSwapChain(void* adapter, int driver_type, void* software,
                                                            unsigned int flags, const void* feature_levels,
                                                            unsigned int num, unsigned int sdk, const void* desc,
                                                            void** swap, void** device, void* out_fl, void** ctx)
{
    (void)adapter;
    (void)driver_type;
    (void)software;
    (void)flags;
    (void)feature_levels;
    (void)num;
    (void)sdk;
    (void)desc;
    (void)out_fl;
    if (swap)
        *swap = (void*)0;
    if (device)
        *device = (void*)0;
    if (ctx)
        *ctx = (void*)0;
    return E_NOTIMPL;
}
