/*
 * userland/libs/d3d9/d3d9.c — DuetOS D3D9 v0.
 *
 * Real IDirect3D9 + IDirect3DDevice9 with a working Clear-and-
 * Present pipeline. Higher-level state (texture stages, vertex
 * shaders, etc.) returns D3DERR-style codes via DX_HSTUB.
 *
 * Build: tools/build/build-stub-dll.sh (base 0x10120000).
 */

#include "../dx_shared.h"
#include "../dx_raster.h"

/* IIDs */
static const DxGuid kIID_IDirect3D9 = {0x81bdcbca, 0x64d4, 0x426d, {0xae, 0x8d, 0xad, 0x01, 0x47, 0xf4, 0x27, 0x5c}};
static const DxGuid kIID_IDirect3D9Ex = {0x02177241, 0x69fc, 0x400c, {0x8f, 0xf1, 0x93, 0xa4, 0x4d, 0xf6, 0x86, 0x1d}};
static const DxGuid kIID_IDirect3DDevice9 = {
    0xd0223b96, 0xbf7a, 0x43fd, {0x92, 0xbd, 0xa4, 0x3b, 0x0d, 0x82, 0xb9, 0xeb}};
static const DxGuid kIID_IDirect3DResource9 = {
    0x05eec05d, 0x8f7d, 0x4362, {0xb9, 0x99, 0xd1, 0xba, 0xf3, 0x57, 0xc7, 0x04}};
static const DxGuid kIID_IDirect3DVertexBuffer9 = {
    0xb64bb1b5, 0xfd70, 0x4df6, {0xbf, 0x91, 0x19, 0xd0, 0xa1, 0x24, 0x55, 0xe3}};
static const DxGuid kIID_IDirect3DIndexBuffer9 = {
    0x7c9dd65e, 0xd3f7, 0x4529, {0xac, 0xee, 0x78, 0x58, 0x30, 0xac, 0xde, 0x35}};
static const DxGuid kIID_IDirect3DTexture9 = {
    0x85c31227, 0x3de5, 0x4f00, {0x9b, 0x3a, 0xf1, 0x1a, 0xc3, 0x8c, 0x18, 0xb5}};

/* ---------------------------------------------------------------- *
 * IDirect3DResource9 / IDirect3DVertexBuffer9 / IDirect3DIndexBuf9 *
 *                                                                  *
 * Backing-store COM objects for the geometry side of the FF        *
 * pipeline. Each carries a refcount, byte size, and its bytes      *
 * trailing the COM head — same shape as D3D11's buffer impl.       *
 *                                                                  *
 * Vtable shape (matches IDirect3DResource9 + the per-buffer        *
 * subclass):                                                       *
 *   IUnknown(3) + Resource9(8: GetDevice, SetPrivateData,          *
 *     GetPrivateData, FreePrivateData, SetPriority, GetPriority,   *
 *     PreLoad, GetType) + Buffer9(4: Lock, Unlock, GetDesc).       *
 * Total: 14 slots for VB/IB; texture is bigger (we use 18 slots).  *
 * ---------------------------------------------------------------- */

#define D9_BUF_VTBL_SLOTS 16

typedef struct D9BufImpl
{
    void* const* lpVtbl;
    ULONG refcount;
    UINT kind; /* 0 = VB, 1 = IB, 2 = texture */
    UINT bytes;
    UINT stride;     /* VB: vertex stride; IB: 2 (16-bit) or 4 (32-bit); tex: row pitch */
    UINT format_fvf; /* VB: FVF; IB: 16/32-bit format; tex: D3DFORMAT */
    UINT width;      /* texture only */
    UINT height;     /* texture only */
    BYTE storage[1];
} D9BufImpl;

static void* g_d9_vb_vtbl[D9_BUF_VTBL_SLOTS];
static void* g_d9_ib_vtbl[D9_BUF_VTBL_SLOTS];
static void* g_d9_tex_vtbl[D9_BUF_VTBL_SLOTS];

static HRESULT d9buf_QueryInterface(D9BufImpl* self, REFIID riid, void** out)
{
    if (!out)
        return DX_E_POINTER;
    if (dx_guid_eq(riid, &kIID_IUnknown) || dx_guid_eq(riid, &kIID_IDirect3DResource9))
    {
        self->refcount++;
        *out = self;
        return DX_S_OK;
    }
    if (self->kind == 0 && dx_guid_eq(riid, &kIID_IDirect3DVertexBuffer9))
    {
        self->refcount++;
        *out = self;
        return DX_S_OK;
    }
    if (self->kind == 1 && dx_guid_eq(riid, &kIID_IDirect3DIndexBuffer9))
    {
        self->refcount++;
        *out = self;
        return DX_S_OK;
    }
    if (self->kind == 2 && dx_guid_eq(riid, &kIID_IDirect3DTexture9))
    {
        self->refcount++;
        *out = self;
        return DX_S_OK;
    }
    *out = NULL;
    return DX_E_NOINTERFACE;
}
static ULONG d9buf_AddRef(D9BufImpl* self)
{
    return ++self->refcount;
}
static ULONG d9buf_Release(D9BufImpl* self)
{
    if (--self->refcount == 0)
    {
        dx_heap_free(self);
        return 0;
    }
    return self->refcount;
}

/* Lock(offset, sizeToLock, **ppData, flags) — slot 11 for VB/IB. */
static HRESULT d9buf_Lock(D9BufImpl* self, UINT offset, UINT size, void** out, DWORD flags)
{
    (void)size;
    (void)flags;
    if (!out)
        return DX_E_POINTER;
    if (offset >= self->bytes)
    {
        *out = NULL;
        return DX_E_INVALIDARG;
    }
    *out = self->storage + offset;
    return DX_S_OK;
}
static HRESULT d9buf_Unlock(D9BufImpl* self)
{
    (void)self;
    return DX_S_OK;
}

/* GetDesc — slot 13 for VB. D3DVERTEXBUFFER_DESC: Format(0), Type(4),
 * Usage(8), Pool(12), Size(16) = 20 bytes. */
static HRESULT d9vb_GetDesc(D9BufImpl* self, void* desc)
{
    if (!desc)
        return DX_E_POINTER;
    BYTE* d = (BYTE*)desc;
    dx_memzero(d, 20);
    *(UINT*)(d + 0) = 0;            /* Format = D3DFMT_VERTEXDATA */
    *(UINT*)(d + 4) = 1;            /* Type = D3DRTYPE_VERTEXBUFFER */
    *(UINT*)(d + 8) = 0;            /* Usage */
    *(UINT*)(d + 12) = 0;           /* Pool = D3DPOOL_DEFAULT */
    *(UINT*)(d + 16) = self->bytes; /* Size */
    return DX_S_OK;
}
/* IB GetDesc: Format(0), Type(4), Usage(8), Pool(12), Size(16). */
static HRESULT d9ib_GetDesc(D9BufImpl* self, void* desc)
{
    if (!desc)
        return DX_E_POINTER;
    BYTE* d = (BYTE*)desc;
    dx_memzero(d, 20);
    *(UINT*)(d + 0) = self->format_fvf; /* D3DFMT_INDEX16 = 101 / INDEX32 = 102 */
    *(UINT*)(d + 4) = 1;                /* Type */
    *(UINT*)(d + 16) = self->bytes;
    return DX_S_OK;
}

static void d9buf_init_vtbl_once(void)
{
    static int g_inited = 0;
    if (g_inited)
        return;
    g_inited = 1;
    for (int i = 0; i < D9_BUF_VTBL_SLOTS; ++i)
    {
        g_d9_vb_vtbl[i] = DX_HSTUB;
        g_d9_ib_vtbl[i] = DX_HSTUB;
        g_d9_tex_vtbl[i] = DX_HSTUB;
    }
    g_d9_vb_vtbl[0] = (void*)d9buf_QueryInterface;
    g_d9_vb_vtbl[1] = (void*)d9buf_AddRef;
    g_d9_vb_vtbl[2] = (void*)d9buf_Release;
    g_d9_vb_vtbl[11] = (void*)d9buf_Lock; /* slot 11 = Lock */
    g_d9_vb_vtbl[12] = (void*)d9buf_Unlock;
    g_d9_vb_vtbl[13] = (void*)d9vb_GetDesc;
    g_d9_ib_vtbl[0] = (void*)d9buf_QueryInterface;
    g_d9_ib_vtbl[1] = (void*)d9buf_AddRef;
    g_d9_ib_vtbl[2] = (void*)d9buf_Release;
    g_d9_ib_vtbl[11] = (void*)d9buf_Lock;
    g_d9_ib_vtbl[12] = (void*)d9buf_Unlock;
    g_d9_ib_vtbl[13] = (void*)d9ib_GetDesc;
    g_d9_tex_vtbl[0] = (void*)d9buf_QueryInterface;
    g_d9_tex_vtbl[1] = (void*)d9buf_AddRef;
    g_d9_tex_vtbl[2] = (void*)d9buf_Release;
}

static D9BufImpl* d9_buf_alloc(UINT kind, UINT bytes, UINT stride, UINT format_fvf)
{
    d9buf_init_vtbl_once();
    if (bytes == 0)
        bytes = 1;
    D9BufImpl* b = (D9BufImpl*)dx_heap_alloc(sizeof(D9BufImpl) + bytes);
    if (!b)
        return NULL;
    dx_memzero(b, sizeof(D9BufImpl));
    b->lpVtbl = (kind == 0) ? g_d9_vb_vtbl : (kind == 1) ? g_d9_ib_vtbl : g_d9_tex_vtbl;
    b->refcount = 1;
    b->kind = kind;
    b->bytes = bytes;
    b->stride = stride;
    b->format_fvf = format_fvf;
    return b;
}

/* ---------------------------------------------------------------- *
 * IDirect3DDevice9                                                 *
 *                                                                  *
 * 119-method vtable. v0.1 follows the canonical Win SDK d3d9.h     *
 * slot ordering (earlier revisions had off-by-N drift):            *
 *                                                                  *
 *   0..2  IUnknown                                                 *
 *   3     TestCooperativeLevel                                     *
 *   4     GetAvailableTextureMem                                   *
 *   ...                                                            *
 *   17    Present                                                  *
 *   23    CreateTexture                                            *
 *   26    CreateVertexBuffer                                       *
 *   27    CreateIndexBuffer                                        *
 *   41    BeginScene                                               *
 *   42    EndScene                                                 *
 *   43    Clear                                                    *
 *   44    SetTransform                                             *
 *   45    GetTransform                                             *
 *   47    SetViewport                                              *
 *   57    SetRenderState                                           *
 *   58    GetRenderState                                           *
 *   65    SetTexture                                               *
 *   81    DrawPrimitive                                            *
 *   82    DrawIndexedPrimitive                                     *
 *   83    DrawPrimitiveUP                                          *
 *   89    SetFVF                                                   *
 *   90    GetFVF                                                   *
 *   100   SetStreamSource                                          *
 *   104   SetIndices                                               *
 *                                                                  *
 * Everything else returns E_NOTIMPL via DX_HSTUB / void via DX_VSTUB.*
 * ---------------------------------------------------------------- */

#define DEV9_VTBL_SLOTS 119
#define D9_RENDERSTATE_MAX 256

typedef struct D9DeviceImpl D9DeviceImpl;
struct D9DeviceImpl
{
    void* const* lpVtbl;
    ULONG refcount;
    HWND hwnd;
    DxBackBuffer* bb;

    /* Fixed-function pipeline state. Transforms are 4x4 row-major
     * (D3D9 uses row vectors: out = in * M). Render states are kept
     * by index in a small array; only the FVF / stream source / index
     * buffer / world matrix are read by the draw path in v0. */
    DxMat4 transform_world;
    DxMat4 transform_view;
    DxMat4 transform_proj;
    DWORD render_state[D9_RENDERSTATE_MAX];
    DWORD fvf;
    D9BufImpl* stream_vb;
    UINT stream_offset;
    UINT stream_stride;
    D9BufImpl* index_buffer;
    int viewport_x, viewport_y, viewport_w, viewport_h;
};

static HRESULT d9d_QueryInterface(D9DeviceImpl* self, REFIID riid, void** out)
{
    if (!out)
        return DX_E_POINTER;
    if (dx_guid_eq(riid, &kIID_IUnknown) || dx_guid_eq(riid, &kIID_IDirect3DDevice9))
    {
        self->refcount++;
        *out = self;
        return DX_S_OK;
    }
    *out = NULL;
    return DX_E_NOINTERFACE;
}
static ULONG d9d_AddRef(D9DeviceImpl* self)
{
    return ++self->refcount;
}
static ULONG d9d_Release(D9DeviceImpl* self)
{
    if (--self->refcount == 0)
    {
        if (self->bb)
            dx_bb_destroy(self->bb);
        dx_heap_free(self);
        return 0;
    }
    return self->refcount;
}

static HRESULT d9d_BeginScene(D9DeviceImpl* self)
{
    (void)self;
    return DX_S_OK;
}
static HRESULT d9d_EndScene(D9DeviceImpl* self)
{
    (void)self;
    return DX_S_OK;
}

/* Clear(count, rects, flags, color, z, stencil). Color is a packed
 * D3DCOLOR (0xAARRGGBB). */
static HRESULT d9d_Clear(D9DeviceImpl* self, DWORD count, const void* rects, DWORD flags, DWORD color, float z,
                         DWORD stencil)
{
    (void)count;
    (void)rects;
    (void)flags;
    (void)z;
    (void)stencil;
    if (!self || !self->bb)
        return DX_E_FAIL;
    /* Convert D3DCOLOR ARGB → BGRA float and reuse dx_bb_clear_rgba. */
    BYTE a = (BYTE)((color >> 24) & 0xFF);
    BYTE r = (BYTE)((color >> 16) & 0xFF);
    BYTE g = (BYTE)((color >> 8) & 0xFF);
    BYTE b = (BYTE)(color & 0xFF);
    dx_bb_clear_rgba(self->bb, (float)r / 255.0f, (float)g / 255.0f, (float)b / 255.0f, (float)a / 255.0f);
    return DX_S_OK;
}

/* Present(srcRect, dstRect, hwndOverride, dirtyRgn) — slot 17. */
static HRESULT d9d_Present(D9DeviceImpl* self, const void* src, const void* dst, HWND hwnd_override, const void* dirty)
{
    (void)src;
    (void)dst;
    (void)dirty;
    if (!self || !self->bb)
        return DX_E_FAIL;
    HWND saved = self->bb->hwnd;
    if (hwnd_override)
        self->bb->hwnd = hwnd_override;
    dx_gfx_trace(4);
    dx_bb_present(self->bb);
    self->bb->hwnd = saved;
    return DX_S_OK;
}

/* CreateVertexBuffer(length, usage, fvf, pool, ppVB, sharedHandle) — slot 26. */
static HRESULT d9d_CreateVertexBuffer(D9DeviceImpl* self, UINT length, DWORD usage, DWORD fvf, DWORD pool,
                                      D9BufImpl** ppvb, void* shared)
{
    (void)self;
    (void)usage;
    (void)pool;
    (void)shared;
    if (!ppvb)
        return DX_E_POINTER;
    *ppvb = d9_buf_alloc(0, length, 0, fvf);
    return *ppvb ? DX_S_OK : DX_E_OUTOFMEMORY;
}

/* CreateIndexBuffer(length, usage, format, pool, ppIB, sharedHandle) — slot 27.
 * format: D3DFMT_INDEX16 = 101, D3DFMT_INDEX32 = 102. */
static HRESULT d9d_CreateIndexBuffer(D9DeviceImpl* self, UINT length, DWORD usage, DWORD format, DWORD pool,
                                     D9BufImpl** ppib, void* shared)
{
    (void)self;
    (void)usage;
    (void)pool;
    (void)shared;
    if (!ppib)
        return DX_E_POINTER;
    UINT stride = (format == 102) ? 4 : 2;
    *ppib = d9_buf_alloc(1, length, stride, format);
    return *ppib ? DX_S_OK : DX_E_OUTOFMEMORY;
}

/* CreateTexture(w, h, levels, usage, format, pool, ppTex, shared) — slot 23. */
static HRESULT d9d_CreateTexture(D9DeviceImpl* self, UINT w, UINT h, UINT levels, DWORD usage, DWORD format, DWORD pool,
                                 D9BufImpl** pptex, void* shared)
{
    (void)self;
    (void)levels;
    (void)usage;
    (void)pool;
    (void)shared;
    if (!pptex)
        return DX_E_POINTER;
    UINT bytes = w * h * 4;
    D9BufImpl* t = d9_buf_alloc(2, bytes, w * 4, format);
    if (!t)
    {
        *pptex = NULL;
        return DX_E_OUTOFMEMORY;
    }
    t->width = w;
    t->height = h;
    *pptex = t;
    return DX_S_OK;
}

/* SetTransform(state, matrix) / GetTransform — slots 44 / 45.
 * D3DTS_VIEW = 2, D3DTS_PROJECTION = 3, D3DTS_WORLD = 256.
 * Matrix is 16 floats. */
static HRESULT d9d_SetTransform(D9DeviceImpl* self, DWORD state, const void* matrix)
{
    if (!self || !matrix)
        return DX_E_POINTER;
    DxMat4 m;
    dx_memcpy(&m, matrix, sizeof(m));
    if (state == 256)
        self->transform_world = m;
    else if (state == 2)
        self->transform_view = m;
    else if (state == 3)
        self->transform_proj = m;
    return DX_S_OK;
}
static HRESULT d9d_GetTransform(D9DeviceImpl* self, DWORD state, void* out)
{
    if (!self || !out)
        return DX_E_POINTER;
    DxMat4* src = NULL;
    if (state == 256)
        src = &self->transform_world;
    else if (state == 2)
        src = &self->transform_view;
    else if (state == 3)
        src = &self->transform_proj;
    if (!src)
        return DX_E_INVALIDARG;
    dx_memcpy(out, src, sizeof(DxMat4));
    return DX_S_OK;
}

/* SetViewport — slot 47. D3DVIEWPORT9: X(0,4), Y(4,4), Width(8,4),
 * Height(12,4), MinZ(16,4), MaxZ(20,4). */
static HRESULT d9d_SetViewport(D9DeviceImpl* self, const void* vp)
{
    if (!self || !vp)
        return DX_E_POINTER;
    const DWORD* v = (const DWORD*)vp;
    self->viewport_x = (int)v[0];
    self->viewport_y = (int)v[1];
    self->viewport_w = (int)v[2];
    self->viewport_h = (int)v[3];
    return DX_S_OK;
}

/* SetRenderState / GetRenderState — slots 57 / 58. */
static HRESULT d9d_SetRenderState(D9DeviceImpl* self, DWORD state, DWORD value)
{
    if (!self)
        return DX_E_FAIL;
    if (state < D9_RENDERSTATE_MAX)
        self->render_state[state] = value;
    return DX_S_OK;
}
static HRESULT d9d_GetRenderState(D9DeviceImpl* self, DWORD state, DWORD* out)
{
    if (!self || !out)
        return DX_E_POINTER;
    *out = (state < D9_RENDERSTATE_MAX) ? self->render_state[state] : 0;
    return DX_S_OK;
}

/* SetFVF / GetFVF — slots 89 / 90. */
static HRESULT d9d_SetFVF(D9DeviceImpl* self, DWORD fvf)
{
    if (self)
        self->fvf = fvf;
    return DX_S_OK;
}
static HRESULT d9d_GetFVF(D9DeviceImpl* self, DWORD* out)
{
    if (!out)
        return DX_E_POINTER;
    *out = self ? self->fvf : 0;
    return DX_S_OK;
}

/* SetStreamSource(streamNumber, vb, offset, stride) — slot 100. */
static HRESULT d9d_SetStreamSource(D9DeviceImpl* self, UINT stream, D9BufImpl* vb, UINT offset, UINT stride)
{
    if (!self || stream != 0)
        return DX_S_OK; /* multi-stream not in v0; quietly accept */
    self->stream_vb = (vb && vb->lpVtbl == g_d9_vb_vtbl) ? vb : NULL;
    self->stream_offset = offset;
    self->stream_stride = stride;
    return DX_S_OK;
}

/* SetIndices(ib) — slot 104. */
static HRESULT d9d_SetIndices(D9DeviceImpl* self, D9BufImpl* ib)
{
    if (!self)
        return DX_E_FAIL;
    self->index_buffer = (ib && ib->lpVtbl == g_d9_ib_vtbl) ? ib : NULL;
    return DX_S_OK;
}

/* SetTexture(stage, tex) — slot 65. v0 doesn't sample textures; the
 * binding is a no-op. */
static HRESULT d9d_SetTexture(D9DeviceImpl* self, DWORD stage, D9BufImpl* tex)
{
    (void)self;
    (void)stage;
    (void)tex;
    return DX_S_OK;
}

/* FVF helpers — figure out POSITION + COLOR offsets. The bottom 3
 * bits encode position type:
 *   D3DFVF_XYZ    = 0x002 → 12 B at offset 0
 *   D3DFVF_XYZRHW = 0x004 → 16 B (homogeneous, pre-transformed) at 0
 * D3DFVF_DIFFUSE = 0x040 → DWORD ARGB next.
 * We compute positions and colours starting from offset 0. */
static int d9_fvf_has_diffuse(DWORD fvf)
{
    return (fvf & 0x40) != 0;
}
static int d9_fvf_pos_bytes(DWORD fvf)
{
    if (fvf & 0x004)
        return 16; /* XYZRHW */
    if (fvf & 0x002)
        return 12; /* XYZ */
    return 0;
}

/* Project a single vertex through the world * view * projection
 * matrices (or pass-through if all are identity / FVF is XYZRHW)
 * and viewport-map. Returns 0 if the vertex is behind the near
 * plane. Honours the bound viewport; falls back to the full back
 * buffer if SetViewport was never called. */
static int d9_project_vertex(D9DeviceImpl* self, const float* xyz, BOOL pretransformed, int* out_x, int* out_y)
{
    DxVec4 v;
    if (pretransformed)
    {
        v.x = xyz[0];
        v.y = xyz[1];
        v.z = xyz[2];
        v.w = xyz[3];
    }
    else
    {
        v.x = xyz[0];
        v.y = xyz[1];
        v.z = xyz[2];
        v.w = 1.0f;
        DxMat4 wv = dxr_mat_mul(&self->transform_world, &self->transform_view);
        DxMat4 wvp = dxr_mat_mul(&wv, &self->transform_proj);
        v = dxr_vec_mul_mat(&v, &wvp);
    }
    int vp_x = self->viewport_x, vp_y = self->viewport_y;
    int vp_w = self->viewport_w, vp_h = self->viewport_h;
    if (vp_w <= 0 || vp_h <= 0)
    {
        if (!self->bb)
            return 0;
        vp_x = 0;
        vp_y = 0;
        vp_w = (int)self->bb->width;
        vp_h = (int)self->bb->height;
    }
    if (pretransformed)
    {
        /* XYZRHW vertices are already in screen space; viewport-map
         * is a passthrough except for the y flip. */
        *out_x = vp_x + (int)v.x;
        *out_y = vp_y + (int)v.y;
        return 1;
    }
    return dxr_project(&v, vp_x, vp_y, vp_w, vp_h, out_x, out_y);
}

/* Pull (x, y, color) for a vertex from raw bytes via the bound FVF. */
static int d9_read_vertex(D9DeviceImpl* self, const BYTE* base, UINT idx, UINT stride, int* out_x, int* out_y,
                          DWORD* out_color)
{
    const BYTE* p = base + (SIZE_T)idx * stride;
    BOOL pretransformed = (self->fvf & 0x004) != 0;
    int pos_bytes = d9_fvf_pos_bytes(self->fvf);
    if (pos_bytes == 0)
        return 0;
    float xyz[4] = {0};
    dx_memcpy(xyz, p, pos_bytes);
    if (!d9_project_vertex(self, xyz, pretransformed, out_x, out_y))
        return 0;
    if (out_color)
    {
        if (d9_fvf_has_diffuse(self->fvf))
        {
            DWORD argb;
            dx_memcpy(&argb, p + pos_bytes, 4);
            *out_color = dxr_pack_d3dcolor(argb);
        }
        else
        {
            *out_color = 0xFFFFFFFFu;
        }
    }
    return 1;
}

static UINT d9_primcount_to_indexcount(UINT type, UINT primcount)
{
    /* D3DPT: POINTLIST=1, LINELIST=2, LINESTRIP=3, TRIANGLELIST=4,
     * TRIANGLESTRIP=5, TRIANGLEFAN=6. */
    if (type == 4)
        return primcount * 3;
    if (type == 5 || type == 6)
        return primcount + 2;
    if (type == 2)
        return primcount * 2;
    if (type == 3)
        return primcount + 1;
    if (type == 1)
        return primcount;
    return 0;
}

/* Walk a primitive batch, calling raster on each triangle. base is
 * the pointer to the first vertex; idx_lookup maps a primitive-local
 * index to a vertex-buffer-relative index. */
static void d9_emit_prims(D9DeviceImpl* self, const BYTE* base, UINT stride, UINT type, UINT vstart, UINT primcount,
                          const void* indices, UINT index_stride)
{
    UINT v0_off = vstart;
    if (!self->bb)
        return;
    DxBackBuffer* bb = self->bb;

    UINT total_idx = d9_primcount_to_indexcount(type, primcount);
    if (total_idx == 0)
        return;

    if (type == 4 || type == 5 || type == 6) /* triangles */
    {
        UINT triangles = primcount;
        for (UINT t = 0; t < triangles; ++t)
        {
            UINT a, b, c;
            if (type == 4)
            {
                a = t * 3;
                b = t * 3 + 1;
                c = t * 3 + 2;
            }
            else if (type == 5) /* strip */
            {
                a = t;
                b = t + 1;
                c = t + 2;
                if (t & 1)
                {
                    UINT tmp = b;
                    b = c;
                    c = tmp;
                }
            }
            else /* fan */
            {
                a = 0;
                b = t + 1;
                c = t + 2;
            }
            UINT ia = a, ib = b, ic = c;
            if (indices)
            {
                if (index_stride == 4)
                {
                    ia = ((const UINT*)indices)[a];
                    ib = ((const UINT*)indices)[b];
                    ic = ((const UINT*)indices)[c];
                }
                else
                {
                    ia = ((const WORD*)indices)[a];
                    ib = ((const WORD*)indices)[b];
                    ic = ((const WORD*)indices)[c];
                }
            }
            int x0, y0, x1, y1, x2, y2;
            DWORD c0, c1, c2;
            if (!d9_read_vertex(self, base, ia + v0_off, stride, &x0, &y0, &c0))
                continue;
            if (!d9_read_vertex(self, base, ib + v0_off, stride, &x1, &y1, &c1))
                continue;
            if (!d9_read_vertex(self, base, ic + v0_off, stride, &x2, &y2, &c2))
                continue;
            if (c0 == c1 && c1 == c2)
                dxr_fill_tri(bb, x0, y0, x1, y1, x2, y2, c0);
            else
                dxr_shade_tri(bb, x0, y0, x1, y1, x2, y2, c0, c1, c2);
        }
    }
    else if (type == 2 || type == 3) /* lines */
    {
        UINT lines = primcount;
        for (UINT l = 0; l < lines; ++l)
        {
            UINT a = (type == 2) ? l * 2 : l;
            UINT b = a + 1;
            UINT ia = a, ib = b;
            if (indices)
            {
                if (index_stride == 4)
                {
                    ia = ((const UINT*)indices)[a];
                    ib = ((const UINT*)indices)[b];
                }
                else
                {
                    ia = ((const WORD*)indices)[a];
                    ib = ((const WORD*)indices)[b];
                }
            }
            int x0, y0, x1, y1;
            DWORD c0, c1;
            if (!d9_read_vertex(self, base, ia + v0_off, stride, &x0, &y0, &c0))
                continue;
            if (!d9_read_vertex(self, base, ib + v0_off, stride, &x1, &y1, &c1))
                continue;
            (void)c1;
            dxr_line(bb, x0, y0, x1, y1, c0);
        }
    }
}

/* DrawPrimitive(type, startVertex, primcount) — slot 81. */
static HRESULT d9d_DrawPrimitive(D9DeviceImpl* self, UINT type, UINT vstart, UINT primcount)
{
    if (!self || !self->stream_vb || self->stream_stride == 0)
        return DX_E_FAIL;
    const BYTE* base = self->stream_vb->storage + self->stream_offset;
    d9_emit_prims(self, base, self->stream_stride, type, vstart, primcount, NULL, 0);
    return DX_S_OK;
}

/* DrawIndexedPrimitive(type, baseVertex, minVtxIdx, numVerts, startIdx, primcount) — slot 82. */
static HRESULT d9d_DrawIndexedPrimitive(D9DeviceImpl* self, UINT type, INT base_vertex, UINT min_vtx, UINT num_verts,
                                        UINT start_idx, UINT primcount)
{
    (void)min_vtx;
    (void)num_verts;
    if (!self || !self->stream_vb || self->stream_stride == 0 || !self->index_buffer)
        return DX_E_FAIL;
    const BYTE* vb_base = self->stream_vb->storage + self->stream_offset;
    UINT index_stride = self->index_buffer->stride;
    const BYTE* idx_base = self->index_buffer->storage + start_idx * index_stride;
    /* d9_emit_prims expects vstart as an offset added to each
     * primitive-local index AFTER index lookup; baseVertex is added
     * here. */
    d9_emit_prims(self, vb_base, self->stream_stride, type, (UINT)base_vertex, primcount, idx_base, index_stride);
    return DX_S_OK;
}

/* DrawPrimitiveUP(type, primcount, vertexData, vertexStride) — slot 83. */
static HRESULT d9d_DrawPrimitiveUP(D9DeviceImpl* self, UINT type, UINT primcount, const void* data, UINT stride)
{
    if (!self || !data || stride == 0)
        return DX_E_FAIL;
    d9_emit_prims(self, (const BYTE*)data, stride, type, 0, primcount, NULL, 0);
    return DX_S_OK;
}

static void* g_d9d_vtbl[DEV9_VTBL_SLOTS];
static void d9d_init_vtbl_once(void)
{
    static int g_inited = 0;
    if (g_inited)
        return;
    g_inited = 1;
    for (int i = 0; i < DEV9_VTBL_SLOTS; ++i)
        g_d9d_vtbl[i] = DX_HSTUB;
    g_d9d_vtbl[0] = (void*)d9d_QueryInterface;
    g_d9d_vtbl[1] = (void*)d9d_AddRef;
    g_d9d_vtbl[2] = (void*)d9d_Release;
    /* Canonical IDirect3DDevice9 slot map per Win SDK d3d9.h. */
    g_d9d_vtbl[17] = (void*)d9d_Present;
    g_d9d_vtbl[23] = (void*)d9d_CreateTexture;
    g_d9d_vtbl[26] = (void*)d9d_CreateVertexBuffer;
    g_d9d_vtbl[27] = (void*)d9d_CreateIndexBuffer;
    g_d9d_vtbl[41] = (void*)d9d_BeginScene;
    g_d9d_vtbl[42] = (void*)d9d_EndScene;
    g_d9d_vtbl[43] = (void*)d9d_Clear;
    g_d9d_vtbl[44] = (void*)d9d_SetTransform;
    g_d9d_vtbl[45] = (void*)d9d_GetTransform;
    g_d9d_vtbl[47] = (void*)d9d_SetViewport;
    g_d9d_vtbl[57] = (void*)d9d_SetRenderState;
    g_d9d_vtbl[58] = (void*)d9d_GetRenderState;
    g_d9d_vtbl[65] = (void*)d9d_SetTexture;
    g_d9d_vtbl[81] = (void*)d9d_DrawPrimitive;
    g_d9d_vtbl[82] = (void*)d9d_DrawIndexedPrimitive;
    g_d9d_vtbl[83] = (void*)d9d_DrawPrimitiveUP;
    g_d9d_vtbl[89] = (void*)d9d_SetFVF;
    g_d9d_vtbl[90] = (void*)d9d_GetFVF;
    g_d9d_vtbl[100] = (void*)d9d_SetStreamSource;
    g_d9d_vtbl[104] = (void*)d9d_SetIndices;
}

/* ---------------------------------------------------------------- *
 * IDirect3D9                                                       *
 *                                                                  *
 * 17-method vtable.                                                *
 *   slot 4  GetAdapterCount                                        *
 *   slot 5  GetAdapterIdentifier                                   *
 *   slot 6  GetAdapterModeCount                                    *
 *   slot 16 CreateDevice                                           *
 * ---------------------------------------------------------------- */

#define D9_VTBL_SLOTS 17

typedef struct D9Impl D9Impl;
struct D9Impl
{
    void* const* lpVtbl;
    ULONG refcount;
};

static HRESULT d9_QueryInterface(D9Impl* self, REFIID riid, void** out)
{
    if (!out)
        return DX_E_POINTER;
    if (dx_guid_eq(riid, &kIID_IUnknown) || dx_guid_eq(riid, &kIID_IDirect3D9) || dx_guid_eq(riid, &kIID_IDirect3D9Ex))
    {
        self->refcount++;
        *out = self;
        return DX_S_OK;
    }
    *out = NULL;
    return DX_E_NOINTERFACE;
}
static ULONG d9_AddRef(D9Impl* self)
{
    return ++self->refcount;
}
static ULONG d9_Release(D9Impl* self)
{
    if (--self->refcount == 0)
    {
        dx_heap_free(self);
        return 0;
    }
    return self->refcount;
}

static UINT d9_GetAdapterCount(D9Impl* self)
{
    (void)self;
    return 1;
}

/* CreateDevice(adapter, devType, hwndFocus, behaviorFlags,
 *   D3DPRESENT_PARAMETERS*, IDirect3DDevice9** dev).
 * D3DPRESENT_PARAMETERS layout (start):
 *   UINT BackBufferWidth    (0)
 *   UINT BackBufferHeight   (4)
 *   D3DFORMAT BackBufferFormat (8)
 *   UINT BackBufferCount    (12)
 *   D3DMULTISAMPLE_TYPE     (16)
 *   DWORD MultiSampleQuality(20)
 *   D3DSWAPEFFECT           (24)
 *   HWND hDeviceWindow      (32, after pad to 8-align)
 */
static HRESULT d9_CreateDevice(D9Impl* self, UINT adapter, UINT dev_type, HWND focus, DWORD flags, void* present_params,
                               D9DeviceImpl** out)
{
    (void)self;
    (void)adapter;
    (void)dev_type;
    (void)flags;
    if (!out)
        return DX_E_POINTER;
    *out = NULL;
    UINT w = 640, h = 480;
    HWND hwnd = focus;
    if (present_params)
    {
        const BYTE* p = (const BYTE*)present_params;
        UINT bw = *(const UINT*)(p + 0);
        UINT bh = *(const UINT*)(p + 4);
        if (bw)
            w = bw;
        if (bh)
            h = bh;
        HWND hp = *(const HWND*)(p + 32);
        if (hp)
            hwnd = hp;
    }
    d9d_init_vtbl_once();
    D9DeviceImpl* d = (D9DeviceImpl*)dx_heap_alloc(sizeof(*d));
    if (!d)
        return DX_E_OUTOFMEMORY;
    dx_memzero(d, sizeof(*d));
    d->lpVtbl = g_d9d_vtbl;
    d->refcount = 1;
    d->hwnd = hwnd;
    d->transform_world = dxr_mat_identity();
    d->transform_view = dxr_mat_identity();
    d->transform_proj = dxr_mat_identity();
    d->bb = dx_bb_create(hwnd, w, h);
    if (!d->bb)
    {
        dx_heap_free(d);
        return DX_E_OUTOFMEMORY;
    }
    *out = d;
    return DX_S_OK;
}

static void* g_d9_vtbl[D9_VTBL_SLOTS];
static void d9_init_vtbl_once(void)
{
    static int g_inited = 0;
    if (g_inited)
        return;
    g_inited = 1;
    for (int i = 0; i < D9_VTBL_SLOTS; ++i)
        g_d9_vtbl[i] = DX_HSTUB;
    g_d9_vtbl[0] = (void*)d9_QueryInterface;
    g_d9_vtbl[1] = (void*)d9_AddRef;
    g_d9_vtbl[2] = (void*)d9_Release;
    g_d9_vtbl[4] = (void*)d9_GetAdapterCount;
    g_d9_vtbl[16] = (void*)d9_CreateDevice;
}

static D9Impl* d9_alloc(void)
{
    d9_init_vtbl_once();
    D9Impl* p = (D9Impl*)dx_heap_alloc(sizeof(*p));
    if (!p)
        return NULL;
    dx_memzero(p, sizeof(*p));
    p->lpVtbl = g_d9_vtbl;
    p->refcount = 1;
    return p;
}

/* Exported entry points */

__declspec(dllexport) void* Direct3DCreate9(UINT sdk_version)
{
    (void)sdk_version;
    dx_gfx_trace(4);
    return d9_alloc();
}

__declspec(dllexport) HRESULT Direct3DCreate9Ex(UINT sdk_version, void** out)
{
    (void)sdk_version;
    if (!out)
        return DX_E_POINTER;
    D9Impl* p = d9_alloc();
    if (!p)
    {
        *out = NULL;
        return DX_E_OUTOFMEMORY;
    }
    *out = p;
    return DX_S_OK;
}
