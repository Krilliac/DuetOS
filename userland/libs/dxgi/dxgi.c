/* dxgi.dll — no DXGI. All 3 factory entries return E_NOTIMPL. */
typedef unsigned long HRESULT;
#define E_NOTIMPL 0x80004001UL

__declspec(dllexport) HRESULT CreateDXGIFactory(const void* riid, void** factory)
{
    (void) riid;
    if (factory) *factory = (void*) 0;
    return E_NOTIMPL;
}

__declspec(dllexport) HRESULT CreateDXGIFactory1(const void* riid, void** factory)
{
    return CreateDXGIFactory(riid, factory);
}

__declspec(dllexport) HRESULT CreateDXGIFactory2(unsigned int flags, const void* riid, void** factory)
{
    (void) flags;
    return CreateDXGIFactory(riid, factory);
}
