/* d3d9.dll — no D3D9 implementation. Callers check the return
 * of Direct3DCreate9 for NULL and gracefully exit / fall back. */
typedef void* IDirect3D9Ptr;
typedef unsigned long HRESULT;
#define E_NOTIMPL 0x80004001UL

__declspec(dllexport) IDirect3D9Ptr Direct3DCreate9(unsigned int sdk_version)
{
    (void)sdk_version;
    return (IDirect3D9Ptr)0;
}

__declspec(dllexport) HRESULT Direct3DCreate9Ex(unsigned int sdk_version, void** out)
{
    (void)sdk_version;
    if (out)
        *out = (void*)0;
    return E_NOTIMPL;
}
