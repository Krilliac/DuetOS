/* d3d12.dll — no D3D12. All 3 entry points return E_NOTIMPL. */
typedef unsigned long HRESULT;
#define E_NOTIMPL 0x80004001UL

__declspec(dllexport) HRESULT D3D12CreateDevice(void* adapter, unsigned int min_feature_level, const void* riid,
                                                void** device)
{
    (void) adapter; (void) min_feature_level; (void) riid;
    if (device) *device = (void*) 0;
    return E_NOTIMPL;
}

__declspec(dllexport) HRESULT D3D12GetDebugInterface(const void* riid, void** dbg)
{
    (void) riid;
    if (dbg) *dbg = (void*) 0;
    return E_NOTIMPL;
}

__declspec(dllexport) HRESULT D3D12SerializeRootSignature(const void* root_sig, unsigned int version, void** blob,
                                                         void** err_blob)
{
    (void) root_sig; (void) version;
    if (blob) *blob = (void*) 0;
    if (err_blob) *err_blob = (void*) 0;
    return E_NOTIMPL;
}
