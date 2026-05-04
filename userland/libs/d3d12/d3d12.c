/*
 * userland/libs/d3d12/d3d12.c — DuetOS D3D12 v0.
 *
 * Real ID3D12Device + command-queue / allocator / list / fence /
 * descriptor-heap / committed-resource that produce a working
 * Clear-and-Present pipeline. Same shape as the D3D11 v0:
 *   D3D12CreateDevice → ID3D12Device
 *   ID3D12Device::CreateCommandQueue / CreateCommandAllocator /
 *     CreateGraphicsCommandList / CreateFence /
 *     CreateDescriptorHeap / CreateCommittedResource (RT bind)
 *   ID3D12GraphicsCommandList::ClearRenderTargetView fills the
 *     resource's BGRA8 backing buffer immediately (no real command
 *     queue replay; the queue is metadata-only in v0).
 *   IDXGISwapChain on top of D3D12 lives in dxgi.dll; this DLL
 *     also accepts a swap-chain pointer through Present-style
 *     paths but is otherwise self-contained.
 *
 * Build: tools/build/build-stub-dll.sh (base 0x10140000).
 */

#include "../dx_shared.h"
#include "../dx_raster.h"

/* ---------------------------------------------------------------- *
 * IIDs                                                             *
 * ---------------------------------------------------------------- */

static const DxGuid kIID_ID3D12Device = {0x189819f1, 0x1db6, 0x4b57, {0xbe, 0x54, 0x18, 0x21, 0x33, 0x9b, 0x85, 0xf7}};
static const DxGuid kIID_ID3D12CommandQueue = {
    0x0ec870a6, 0x5d7e, 0x4c22, {0x8c, 0xfc, 0x5b, 0xaa, 0xe0, 0x76, 0x16, 0xed}};
static const DxGuid kIID_ID3D12CommandAllocator = {
    0x6102dee4, 0xaf59, 0x4b09, {0xb9, 0x99, 0xb4, 0x4d, 0x73, 0xf0, 0x9b, 0x24}};
static const DxGuid kIID_ID3D12GraphicsCommandList = {
    0x5b160d0f, 0xac1b, 0x4185, {0x8b, 0xa8, 0xb3, 0xae, 0x42, 0xa5, 0xa4, 0x55}};
static const DxGuid kIID_ID3D12CommandList = {
    0x7116d91c, 0xe7e4, 0x47ce, {0xb8, 0xc6, 0xec, 0x81, 0x68, 0xf4, 0x37, 0xe5}};
static const DxGuid kIID_ID3D12Fence = {0x0a753dcf, 0xc4d8, 0x4b91, {0xad, 0xf6, 0xbe, 0x5a, 0x60, 0xd9, 0x5a, 0x76}};
static const DxGuid kIID_ID3D12DescriptorHeap = {
    0x8efb471d, 0x616c, 0x4f49, {0x90, 0xf7, 0x12, 0x7b, 0xb7, 0x63, 0xfa, 0x51}};
static const DxGuid kIID_ID3D12Resource = {
    0x696442be, 0xa72e, 0x4059, {0xbc, 0x79, 0x5b, 0x5c, 0x98, 0x04, 0x0f, 0xad}};
static const DxGuid kIID_ID3D12Debug = {0x344488b7, 0x6846, 0x474b, {0xb9, 0x89, 0xf0, 0x27, 0x44, 0x82, 0x45, 0xe0}};

/* ---------------------------------------------------------------- *
 * Forward                                                          *
 * ---------------------------------------------------------------- */

typedef struct D12DeviceImpl D12DeviceImpl;
typedef struct D12QueueImpl D12QueueImpl;
typedef struct D12AllocImpl D12AllocImpl;
typedef struct D12ListImpl D12ListImpl;
typedef struct D12FenceImpl D12FenceImpl;
typedef struct D12HeapImpl D12HeapImpl;
typedef struct D12ResImpl D12ResImpl;

/* ---------------------------------------------------------------- *
 * ID3D12Resource — committed BGRA8 texture OR linear buffer.       *
 * Vtable: IUnknown(3) + ID3D12Object(4) + DeviceChild(1) +         *
 * ID3D12Pageable(0) + ID3D12Resource(7 = Map, Unmap, GetDesc,      *
 *   GetGPUVirtualAddress, WriteToSubresource, ReadFromSubresource, *
 *   GetHeapProperties).                                            *
 * Total: 15 slots.                                                 *
 *                                                                  *
 * `kind` is 0 for a 2D texture (uses bb) or 1 for a buffer (uses   *
 * linear / linear_bytes). The two paths share the COM head so      *
 * Map/Unmap/GetGPUVirtualAddress can present a single interface to *
 * callers.                                                         *
 * ---------------------------------------------------------------- */

#define RES_VTBL_SLOTS 18

struct D12ResImpl
{
    void* const* lpVtbl;
    ULONG refcount;
    UINT kind;          /* 0 = texture (BGRA8 2D), 1 = buffer (linear bytes) */
    UINT current_state; /* D3D12_RESOURCE_STATES bitmask, updated by ResourceBarrier */
    DxBackBuffer* bb;
    BOOL owns_bb;
    UINT format;
    UINT width;
    UINT height;
    BYTE* linear;      /* used when kind == 1 */
    UINT linear_bytes; /* used when kind == 1 */
};

static HRESULT res_QueryInterface(D12ResImpl* self, REFIID riid, void** out)
{
    if (!out)
        return DX_E_POINTER;
    if (dx_guid_eq(riid, &kIID_IUnknown) || dx_guid_eq(riid, &kIID_ID3D12Resource))
    {
        self->refcount++;
        *out = self;
        return DX_S_OK;
    }
    *out = NULL;
    return DX_E_NOINTERFACE;
}
static ULONG res_AddRef(D12ResImpl* self)
{
    return ++self->refcount;
}
static ULONG res_Release(D12ResImpl* self)
{
    if (--self->refcount == 0)
    {
        if (self->owns_bb && self->bb)
            dx_bb_destroy(self->bb);
        if (self->linear)
            dx_heap_free(self->linear);
        dx_heap_free(self);
        return 0;
    }
    return self->refcount;
}

/* GetDesc — slot 10. D3D12_RESOURCE_DESC is 72 bytes. */
static void res_GetDesc(D12ResImpl* self, void* desc)
{
    if (!desc)
        return;
    BYTE* d = (BYTE*)desc;
    dx_memzero(d, 72);
    if (self->kind == 1)
    {
        *(UINT*)(d + 0) = 1;                    /* Dimension = BUFFER */
        *(UINT64*)(d + 8) = self->linear_bytes; /* Width = byte count */
        *(UINT*)(d + 16) = 1;                   /* Height */
        *(WORD*)(d + 20) = 1;                   /* DepthOrArraySize */
        *(WORD*)(d + 22) = 1;                   /* MipLevels */
        *(UINT*)(d + 24) = 0;                   /* Format = UNKNOWN */
    }
    else
    {
        *(UINT*)(d + 0) = 4;             /* Dimension = TEXTURE2D */
        *(UINT*)(d + 4) = 0;             /* Alignment */
        *(UINT64*)(d + 8) = self->width; /* Width */
        *(UINT*)(d + 16) = self->height; /* Height */
        *(WORD*)(d + 20) = 1;            /* DepthOrArraySize */
        *(WORD*)(d + 22) = 1;            /* MipLevels */
        *(UINT*)(d + 24) = self->format;
    }
}

/* Map(Subresource, ReadRange*, void**) — slot 8. */
static HRESULT res_Map(D12ResImpl* self, UINT sub, const void* range, void** out)
{
    (void)sub;
    (void)range;
    if (!out)
        return DX_E_POINTER;
    if (self->kind == 1)
    {
        if (!self->linear)
            return DX_E_FAIL;
        *out = self->linear;
        return DX_S_OK;
    }
    if (!self->bb)
        return DX_E_FAIL;
    *out = self->bb->pixels;
    return DX_S_OK;
}
/* Unmap — slot 9. */
static void res_Unmap(D12ResImpl* self, UINT sub, const void* range)
{
    (void)self;
    (void)sub;
    (void)range;
}

/* GetGPUVirtualAddress — slot 11. Software path: returns a pointer
 * into the backing buffer, masked to look like a virtual address.
 * For buffers this is what the IB / VB views target; the command
 * list will read it back to find the bytes. */
static UINT64 res_GetGPUVirtualAddress(D12ResImpl* self)
{
    if (self->kind == 1)
        return self->linear ? (UINT64)(unsigned long long)self->linear : 0;
    return self->bb ? (UINT64)(unsigned long long)self->bb->pixels : 0;
}

static void* g_res_vtbl[RES_VTBL_SLOTS];
static void res_init_vtbl_once(void)
{
    static int g_inited = 0;
    if (g_inited)
        return;
    g_inited = 1;
    for (int i = 0; i < RES_VTBL_SLOTS; ++i)
        g_res_vtbl[i] = DX_HSTUB;
    g_res_vtbl[0] = (void*)res_QueryInterface;
    g_res_vtbl[1] = (void*)res_AddRef;
    g_res_vtbl[2] = (void*)res_Release;
    g_res_vtbl[8] = (void*)res_Map;
    g_res_vtbl[9] = (void*)res_Unmap;
    g_res_vtbl[10] = (void*)res_GetDesc;
    g_res_vtbl[11] = (void*)res_GetGPUVirtualAddress;
}

static D12ResImpl* res_alloc_tex2d(UINT w, UINT h, UINT format, UINT initial_state)
{
    res_init_vtbl_once();
    D12ResImpl* r = (D12ResImpl*)dx_heap_alloc(sizeof(*r));
    if (!r)
        return NULL;
    dx_memzero(r, sizeof(*r));
    r->lpVtbl = g_res_vtbl;
    r->refcount = 1;
    r->kind = 0;
    r->current_state = initial_state;
    r->bb = dx_bb_create(NULL, w ? w : 1, h ? h : 1);
    if (!r->bb)
    {
        dx_heap_free(r);
        return NULL;
    }
    r->owns_bb = 1;
    r->width = w;
    r->height = h;
    r->format = format ? format : 87;
    return r;
}

static D12ResImpl* res_alloc_buffer(UINT bytes, UINT initial_state)
{
    res_init_vtbl_once();
    if (bytes == 0)
        bytes = 1;
    D12ResImpl* r = (D12ResImpl*)dx_heap_alloc(sizeof(*r));
    if (!r)
        return NULL;
    dx_memzero(r, sizeof(*r));
    r->lpVtbl = g_res_vtbl;
    r->refcount = 1;
    r->kind = 1;
    r->current_state = initial_state;
    r->linear = (BYTE*)dx_heap_alloc(bytes);
    if (!r->linear)
    {
        dx_heap_free(r);
        return NULL;
    }
    dx_memzero(r->linear, bytes);
    r->linear_bytes = bytes;
    return r;
}

/* ---------------------------------------------------------------- *
 * ID3D12DescriptorHeap — array of descriptors. Each "descriptor"   *
 * is a void* + a tag (RTV / SRV / etc.). The CPU/GPU handles are  *
 * encoded as offsets into the heap's descriptor array.             *
 * ---------------------------------------------------------------- */

#define HEAP_VTBL_SLOTS                                                                                                \
    13 /* IUnknown(3) + ID3D12Object(4) + DeviceChild(1) +
                                ID3D12Pageable(0) + DescHeap(2 = GetDesc + the two
                                handle accessors). With 4-byte alignment slop. */

struct D12HeapImpl
{
    void* const* lpVtbl;
    ULONG refcount;
    UINT type; /* 0=CBV/SRV/UAV, 1=Sampler, 2=RTV, 3=DSV */
    UINT num_descriptors;
    UINT inc_size; /* descriptor slot stride */
    BYTE* base;    /* num_descriptors * inc_size bytes */
};

static HRESULT heap_QueryInterface(D12HeapImpl* self, REFIID riid, void** out)
{
    if (!out)
        return DX_E_POINTER;
    if (dx_guid_eq(riid, &kIID_IUnknown) || dx_guid_eq(riid, &kIID_ID3D12DescriptorHeap))
    {
        self->refcount++;
        *out = self;
        return DX_S_OK;
    }
    *out = NULL;
    return DX_E_NOINTERFACE;
}
static ULONG heap_AddRef(D12HeapImpl* self)
{
    return ++self->refcount;
}
static ULONG heap_Release(D12HeapImpl* self)
{
    if (--self->refcount == 0)
    {
        if (self->base)
            dx_heap_free(self->base);
        dx_heap_free(self);
        return 0;
    }
    return self->refcount;
}

/* GetCPUDescriptorHandleForHeapStart — slot 9. Returns a struct
 * containing one SIZE_T (the CPU handle, basically a raw pointer
 * into the heap's descriptor array). MSVC ABI: aggregate <= 8B is
 * returned in rax. */
static SIZE_T heap_GetCPUStart(D12HeapImpl* self)
{
    return (SIZE_T)(unsigned long long)self->base;
}
/* GetGPUDescriptorHandleForHeapStart — slot 10. Same shape. */
static UINT64 heap_GetGPUStart(D12HeapImpl* self)
{
    return (UINT64)(unsigned long long)self->base;
}

static void* g_heap_vtbl[HEAP_VTBL_SLOTS];
static void heap_init_vtbl_once(void)
{
    static int g_inited = 0;
    if (g_inited)
        return;
    g_inited = 1;
    for (int i = 0; i < HEAP_VTBL_SLOTS; ++i)
        g_heap_vtbl[i] = DX_HSTUB;
    g_heap_vtbl[0] = (void*)heap_QueryInterface;
    g_heap_vtbl[1] = (void*)heap_AddRef;
    g_heap_vtbl[2] = (void*)heap_Release;
    g_heap_vtbl[9] = (void*)heap_GetCPUStart;
    g_heap_vtbl[10] = (void*)heap_GetGPUStart;
}

/* Each descriptor slot is sizeof(void*) — we store a D12ResImpl*
 * for RTV slots so ClearRenderTargetView can find its target. */
#define D12_DESC_STRIDE (sizeof(void*))

static D12HeapImpl* heap_alloc(UINT type, UINT num)
{
    heap_init_vtbl_once();
    if (num == 0)
        num = 1;
    D12HeapImpl* h = (D12HeapImpl*)dx_heap_alloc(sizeof(*h));
    if (!h)
        return NULL;
    dx_memzero(h, sizeof(*h));
    h->lpVtbl = g_heap_vtbl;
    h->refcount = 1;
    h->type = type;
    h->num_descriptors = num;
    h->inc_size = (UINT)D12_DESC_STRIDE;
    h->base = (BYTE*)dx_heap_alloc((SIZE_T)num * D12_DESC_STRIDE);
    if (!h->base)
    {
        dx_heap_free(h);
        return NULL;
    }
    dx_memzero(h->base, (SIZE_T)num * D12_DESC_STRIDE);
    return h;
}

/* ---------------------------------------------------------------- *
 * ID3D12Fence                                                      *
 * Vtable: IUnknown(3)+Object(4)+DeviceChild(1)+Pageable(0)+Fence(3).*
 * = 11 slots.                                                      *
 * ---------------------------------------------------------------- */

#define FENCE_VTBL_SLOTS 11

struct D12FenceImpl
{
    void* const* lpVtbl;
    ULONG refcount;
    UINT64 value;
};

static HRESULT fence_QueryInterface(D12FenceImpl* self, REFIID riid, void** out)
{
    if (!out)
        return DX_E_POINTER;
    if (dx_guid_eq(riid, &kIID_IUnknown) || dx_guid_eq(riid, &kIID_ID3D12Fence))
    {
        self->refcount++;
        *out = self;
        return DX_S_OK;
    }
    *out = NULL;
    return DX_E_NOINTERFACE;
}
static ULONG fence_AddRef(D12FenceImpl* self)
{
    return ++self->refcount;
}
static ULONG fence_Release(D12FenceImpl* self)
{
    if (--self->refcount == 0)
    {
        dx_heap_free(self);
        return 0;
    }
    return self->refcount;
}
static UINT64 fence_GetCompletedValue(D12FenceImpl* self)
{
    return self ? self->value : 0;
}
static HRESULT fence_SetEventOnCompletion(D12FenceImpl* self, UINT64 v, HANDLE evt)
{
    (void)v;
    (void)evt;
    /* In v0 every queued op completes synchronously, so any value
     * up to `self->value` is "already complete" — the event would
     * be signalled immediately. We don't have an event API here;
     * apps that wait on events should poll GetCompletedValue. */
    (void)self;
    return DX_S_OK;
}
static HRESULT fence_Signal(D12FenceImpl* self, UINT64 v)
{
    if (!self)
        return DX_E_FAIL;
    self->value = v;
    return DX_S_OK;
}

static void* g_fence_vtbl[FENCE_VTBL_SLOTS];
static void fence_init_vtbl_once(void)
{
    static int g_inited = 0;
    if (g_inited)
        return;
    g_inited = 1;
    for (int i = 0; i < FENCE_VTBL_SLOTS; ++i)
        g_fence_vtbl[i] = DX_HSTUB;
    g_fence_vtbl[0] = (void*)fence_QueryInterface;
    g_fence_vtbl[1] = (void*)fence_AddRef;
    g_fence_vtbl[2] = (void*)fence_Release;
    g_fence_vtbl[8] = (void*)fence_GetCompletedValue;
    g_fence_vtbl[9] = (void*)fence_SetEventOnCompletion;
    g_fence_vtbl[10] = (void*)fence_Signal;
}

static D12FenceImpl* fence_alloc(UINT64 initial)
{
    fence_init_vtbl_once();
    D12FenceImpl* f = (D12FenceImpl*)dx_heap_alloc(sizeof(*f));
    if (!f)
        return NULL;
    dx_memzero(f, sizeof(*f));
    f->lpVtbl = g_fence_vtbl;
    f->refcount = 1;
    f->value = initial;
    return f;
}

/* ---------------------------------------------------------------- *
 * ID3D12CommandAllocator — IUnknown(3)+Object(4)+DeviceChild(1)+   *
 * Pageable(0)+Allocator(1=Reset). = 9 slots.                       *
 * ---------------------------------------------------------------- */

#define ALLOC_VTBL_SLOTS 9

struct D12AllocImpl
{
    void* const* lpVtbl;
    ULONG refcount;
    UINT type;
};

static HRESULT alloc_QueryInterface(D12AllocImpl* self, REFIID riid, void** out)
{
    if (!out)
        return DX_E_POINTER;
    if (dx_guid_eq(riid, &kIID_IUnknown) || dx_guid_eq(riid, &kIID_ID3D12CommandAllocator))
    {
        self->refcount++;
        *out = self;
        return DX_S_OK;
    }
    *out = NULL;
    return DX_E_NOINTERFACE;
}
static ULONG alloc_AddRef(D12AllocImpl* self)
{
    return ++self->refcount;
}
static ULONG alloc_Release(D12AllocImpl* self)
{
    if (--self->refcount == 0)
    {
        dx_heap_free(self);
        return 0;
    }
    return self->refcount;
}
static HRESULT alloc_Reset(D12AllocImpl* self)
{
    (void)self;
    return DX_S_OK;
}

static void* g_alloc_vtbl[ALLOC_VTBL_SLOTS];
static void alloc_init_vtbl_once(void)
{
    static int g_inited = 0;
    if (g_inited)
        return;
    g_inited = 1;
    for (int i = 0; i < ALLOC_VTBL_SLOTS; ++i)
        g_alloc_vtbl[i] = DX_HSTUB;
    g_alloc_vtbl[0] = (void*)alloc_QueryInterface;
    g_alloc_vtbl[1] = (void*)alloc_AddRef;
    g_alloc_vtbl[2] = (void*)alloc_Release;
    g_alloc_vtbl[8] = (void*)alloc_Reset;
}

static D12AllocImpl* allocator_alloc(UINT type)
{
    alloc_init_vtbl_once();
    D12AllocImpl* a = (D12AllocImpl*)dx_heap_alloc(sizeof(*a));
    if (!a)
        return NULL;
    dx_memzero(a, sizeof(*a));
    a->lpVtbl = g_alloc_vtbl;
    a->refcount = 1;
    a->type = type;
    return a;
}

/* ---------------------------------------------------------------- *
 * ID3D12RootSignature — opaque handle. v0 doesn't constrain root   *
 * parameters since none of our draws actually consume root-bound   *
 * resources, but the COM shape is required so SetGraphicsRootSig   *
 * + Release work without crashing.                                 *
 *                                                                  *
 * Vtable: IUnknown(3) + Object(4) + DeviceChild(1) + Pageable(0).  *
 * = 8 slots. (No methods of its own.)                              *
 * ---------------------------------------------------------------- */

#define ROOTSIG_VTBL_SLOTS 8

static const DxGuid kIID_ID3D12RootSignature = {
    0xc54a6b66, 0x72df, 0x4ee8, {0x8b, 0xe5, 0xa9, 0x46, 0xa1, 0x42, 0x92, 0x14}};

typedef struct D12RootSigImpl
{
    void* const* lpVtbl;
    ULONG refcount;
} D12RootSigImpl;

static void* g_rootsig_vtbl[ROOTSIG_VTBL_SLOTS];

static HRESULT rs_QueryInterface(D12RootSigImpl* self, REFIID riid, void** out)
{
    if (!out)
        return DX_E_POINTER;
    if (dx_guid_eq(riid, &kIID_IUnknown) || dx_guid_eq(riid, &kIID_ID3D12RootSignature))
    {
        self->refcount++;
        *out = self;
        return DX_S_OK;
    }
    *out = NULL;
    return DX_E_NOINTERFACE;
}
static ULONG rs_AddRef(D12RootSigImpl* self)
{
    return ++self->refcount;
}
static ULONG rs_Release(D12RootSigImpl* self)
{
    if (--self->refcount == 0)
    {
        dx_heap_free(self);
        return 0;
    }
    return self->refcount;
}

static void rs_init_vtbl_once(void)
{
    static int g_inited = 0;
    if (g_inited)
        return;
    g_inited = 1;
    for (int i = 0; i < ROOTSIG_VTBL_SLOTS; ++i)
        g_rootsig_vtbl[i] = DX_HSTUB;
    g_rootsig_vtbl[0] = (void*)rs_QueryInterface;
    g_rootsig_vtbl[1] = (void*)rs_AddRef;
    g_rootsig_vtbl[2] = (void*)rs_Release;
}

static D12RootSigImpl* rootsig_alloc(void)
{
    rs_init_vtbl_once();
    D12RootSigImpl* r = (D12RootSigImpl*)dx_heap_alloc(sizeof(*r));
    if (!r)
        return NULL;
    dx_memzero(r, sizeof(*r));
    r->lpVtbl = g_rootsig_vtbl;
    r->refcount = 1;
    return r;
}

/* ---------------------------------------------------------------- *
 * ID3D12PipelineState (PSO) — bundles input layout, shader stages, *
 * blend / depth / raster states. v0 only inspects the input layout *
 * to extract POSITION / COLOR offsets so the command list's draw   *
 * methods can decode vertex data.                                  *
 *                                                                  *
 * Vtable: IUnknown(3) + Object(4) + DeviceChild(1) + Pageable(0) + *
 * PipelineState(1=GetCachedBlob). = 9 slots.                       *
 * ---------------------------------------------------------------- */

#define PSO_VTBL_SLOTS 9

static const DxGuid kIID_ID3D12PipelineState = {
    0x765a30f3, 0xf624, 0x4c6f, {0xa8, 0x28, 0xac, 0xe9, 0x48, 0x62, 0x24, 0x45}};

typedef struct D12PsoImpl
{
    void* const* lpVtbl;
    ULONG refcount;
    UINT position_offset; /* 0xFFFF if no POSITION element */
    UINT color_offset;    /* 0xFFFF if no COLOR element */
    UINT color_kind;      /* 0=R32G32B32A32_FLOAT, 1=B8G8R8A8_UNORM, 2=R8G8B8A8_UNORM */
    UINT topology_type;   /* D3D12_PRIMITIVE_TOPOLOGY_TYPE: 0 undef, 1 point, 2 line, 3 tri */
} D12PsoImpl;

static void* g_pso_vtbl[PSO_VTBL_SLOTS];

static HRESULT pso_QueryInterface(D12PsoImpl* self, REFIID riid, void** out)
{
    if (!out)
        return DX_E_POINTER;
    if (dx_guid_eq(riid, &kIID_IUnknown) || dx_guid_eq(riid, &kIID_ID3D12PipelineState))
    {
        self->refcount++;
        *out = self;
        return DX_S_OK;
    }
    *out = NULL;
    return DX_E_NOINTERFACE;
}
static ULONG pso_AddRef(D12PsoImpl* self)
{
    return ++self->refcount;
}
static ULONG pso_Release(D12PsoImpl* self)
{
    if (--self->refcount == 0)
    {
        dx_heap_free(self);
        return 0;
    }
    return self->refcount;
}
static void pso_init_vtbl_once(void)
{
    static int g_inited = 0;
    if (g_inited)
        return;
    g_inited = 1;
    for (int i = 0; i < PSO_VTBL_SLOTS; ++i)
        g_pso_vtbl[i] = DX_HSTUB;
    g_pso_vtbl[0] = (void*)pso_QueryInterface;
    g_pso_vtbl[1] = (void*)pso_AddRef;
    g_pso_vtbl[2] = (void*)pso_Release;
}

/* Case-insensitive ASCIIZ compare without pulling in <string.h>. */
static int pso_name_eq(const char* a, const char* b)
{
    if (!a || !b)
        return 0;
    while (*a && *b)
    {
        char ca = *a++, cb = *b++;
        if (ca >= 'a' && ca <= 'z')
            ca = (char)(ca - 32);
        if (cb >= 'a' && cb <= 'z')
            cb = (char)(cb - 32);
        if (ca != cb)
            return 0;
    }
    return *a == *b;
}

/* D3D12_INPUT_ELEMENT_DESC (32 bytes on x86_64):
 *   const char* SemanticName       (8)
 *   UINT SemanticIndex             (4)
 *   DXGI_FORMAT Format             (4)
 *   UINT InputSlot                 (4)
 *   UINT AlignedByteOffset         (4)
 *   D3D12_INPUT_CLASSIFICATION Cls (4)
 *   UINT InstanceDataStepRate      (4) — pads to 32 with align(8). */
static D12PsoImpl* pso_alloc_from_desc(const void* il_descs, UINT il_count, UINT topology_type)
{
    pso_init_vtbl_once();
    D12PsoImpl* p = (D12PsoImpl*)dx_heap_alloc(sizeof(*p));
    if (!p)
        return NULL;
    dx_memzero(p, sizeof(*p));
    p->lpVtbl = g_pso_vtbl;
    p->refcount = 1;
    p->position_offset = 0xFFFF;
    p->color_offset = 0xFFFF;
    p->color_kind = 0;
    p->topology_type = topology_type;
    if (il_descs)
    {
        const BYTE* q = (const BYTE*)il_descs;
        for (UINT i = 0; i < il_count; ++i)
        {
            const BYTE* e = q + (SIZE_T)i * 32;
            const char* name = *(const char* const*)(e + 0);
            UINT format = *(const UINT*)(e + 12);
            UINT offset = *(const UINT*)(e + 20);
            if (pso_name_eq(name, "POSITION") || pso_name_eq(name, "SV_POSITION"))
                p->position_offset = offset;
            else if (pso_name_eq(name, "COLOR") || pso_name_eq(name, "COLOUR"))
            {
                p->color_offset = offset;
                if (format == 2)
                    p->color_kind = 0;
                else if (format == 87)
                    p->color_kind = 1;
                else
                    p->color_kind = 2;
            }
        }
    }
    return p;
}

/* ---------------------------------------------------------------- *
 * ID3D12GraphicsCommandList                                        *
 *                                                                  *
 * Inheritance chain (canonical D3D12 ABI):                         *
 *   IUnknown(0..2) + ID3D12Object(3..6) + ID3D12DeviceChild(7) +   *
 *   ID3D12Pageable() + ID3D12CommandList(8=GetType) +              *
 *   ID3D12GraphicsCommandList(9..59).                              *
 *                                                                  *
 * v0.1 implements (all at CANONICAL slot positions):               *
 *   8  GetType                                                     *
 *   9  Close                                                       *
 *   10 Reset                                                       *
 *   12 DrawInstanced                                               *
 *   13 DrawIndexedInstanced                                        *
 *   20 IASetPrimitiveTopology                                      *
 *   21 RSSetViewports                                              *
 *   22 RSSetScissorRects (no-op)                                   *
 *   25 SetPipelineState                                            *
 *   26 ResourceBarrier (no-op)                                     *
 *   29 SetComputeRootSignature (no-op)                             *
 *   30 SetGraphicsRootSignature                                    *
 *   43 IASetIndexBuffer                                            *
 *   44 IASetVertexBuffers                                          *
 *   46 OMSetRenderTargets                                          *
 *   47 ClearDepthStencilView (no-op success)                       *
 *   48 ClearRenderTargetView                                       *
 *                                                                  *
 * Everything else is DX_HSTUB / DX_VSTUB.                           *
 * ---------------------------------------------------------------- */

#define LIST_VTBL_SLOTS 80

struct D12ListImpl
{
    void* const* lpVtbl;
    ULONG refcount;
    UINT type;
    BOOL closed;

    /* Pipeline state set by IASet* / RSSet* / SetPipelineState /
     * OMSetRenderTargets and consumed by Draw* / ClearRTV. The PSO
     * supplies the input layout; the VB / IB views supply the bytes;
     * the render-target slot supplies the surface. None of these
     * pointers are AddRef'd — the caller keeps the resources alive
     * for the duration of the recording. */
    D12PsoImpl* current_pso;
    UINT current_topology;     /* D3D_PRIMITIVE_TOPOLOGY: 4 = TRIANGLELIST, 5 = STRIP */
    UINT64 current_vb_address; /* GPU VA from the bound vertex-buffer view */
    UINT current_vb_size;
    UINT current_vb_stride;
    UINT64 current_ib_address;
    UINT current_ib_size;
    UINT current_ib_format; /* DXGI_FORMAT_R16_UINT = 57, R32_UINT = 42 */
    int viewport_x, viewport_y, viewport_w, viewport_h;
    D12ResImpl* current_rt;

    /* Bumped by ResourceBarrier when a TRANSITION barrier's StateBefore
     * doesn't match the resource's recorded current_state. Read back via
     * DuetOS_D3D12_PeekBarrierMismatchCount so the dx_demo can verify
     * the validation fires on a deliberate mismatch and stays at zero
     * on a clean transition. */
    UINT barrier_mismatch_count;
};

static HRESULT list_QueryInterface(D12ListImpl* self, REFIID riid, void** out)
{
    if (!out)
        return DX_E_POINTER;
    if (dx_guid_eq(riid, &kIID_IUnknown) || dx_guid_eq(riid, &kIID_ID3D12CommandList) ||
        dx_guid_eq(riid, &kIID_ID3D12GraphicsCommandList))
    {
        self->refcount++;
        *out = self;
        return DX_S_OK;
    }
    *out = NULL;
    return DX_E_NOINTERFACE;
}
static ULONG list_AddRef(D12ListImpl* self)
{
    return ++self->refcount;
}
static ULONG list_Release(D12ListImpl* self)
{
    if (--self->refcount == 0)
    {
        dx_heap_free(self);
        return 0;
    }
    return self->refcount;
}

static UINT list_GetType(D12ListImpl* self)
{
    return self ? self->type : 0;
}
static HRESULT list_Close(D12ListImpl* self)
{
    self->closed = 1;
    return DX_S_OK;
}
static HRESULT list_Reset(D12ListImpl* self, void* alloc, void* pso)
{
    (void)alloc;
    self->closed = 0;
    self->current_pso = (pso && ((D12PsoImpl*)pso)->lpVtbl == g_pso_vtbl) ? (D12PsoImpl*)pso : NULL;
    return DX_S_OK;
}
/* Emit a single mismatch diagnostic via SYS_DEBUG_PRINT. The DX DLLs
 * don't link a printf, so the formatting is done by hand into a
 * stack buffer. Format:
 *   "[d3d12] ResourceBarrier StateBefore mismatch: recorded=0xXXXXXXXX
 *    declared=0xXXXXXXXX after=0xXXXXXXXX"
 * Throttled by the caller (first three mismatches per list) so a
 * pathological caller can't flood the serial log. */
static void list_emit_barrier_mismatch(UINT recorded, UINT declared, UINT after)
{
    static const char kHex[] = "0123456789abcdef";
    char buf[112];
    UINT i = 0;
    const char* prefix = "[d3d12] ResourceBarrier StateBefore mismatch: recorded=0x";
    for (UINT k = 0; prefix[k]; ++k)
        buf[i++] = prefix[k];
    for (int k = 0; k < 8; ++k)
        buf[i++] = kHex[(recorded >> ((7 - k) * 4)) & 0xF];
    const char* mid1 = " declared=0x";
    for (UINT k = 0; mid1[k]; ++k)
        buf[i++] = mid1[k];
    for (int k = 0; k < 8; ++k)
        buf[i++] = kHex[(declared >> ((7 - k) * 4)) & 0xF];
    const char* mid2 = " after=0x";
    for (UINT k = 0; mid2[k]; ++k)
        buf[i++] = mid2[k];
    for (int k = 0; k < 8; ++k)
        buf[i++] = kHex[(after >> ((7 - k) * 4)) & 0xF];
    buf[i] = 0;
    dx_dbg(buf);
}

/* ResourceBarrier(numBarriers, *barriers) — slot 26.
 *
 * D3D12_RESOURCE_BARRIER (40 B):
 *   +0  D3D12_RESOURCE_BARRIER_TYPE Type   (UINT)
 *   +4  D3D12_RESOURCE_BARRIER_FLAGS Flags (UINT)
 *   +8  union (32 B):
 *     TRANSITION:
 *       +8  ID3D12Resource* pResource  (8 B)
 *       +16 UINT Subresource           (4 B)
 *       +20 D3D12_RESOURCE_STATES Before(4 B)
 *       +24 D3D12_RESOURCE_STATES After (4 B)
 *     ALIASING:
 *       +8  ID3D12Resource* pBefore    (8 B)
 *       +16 ID3D12Resource* pAfter     (8 B)
 *     UAV:
 *       +8  ID3D12Resource* pResource  (8 B)
 *
 * v0 only honours TRANSITION (Type == 0); ALIASING / UAV are
 * no-op success. For TRANSITION barriers we now also validate
 * that StateBefore matches the resource's recorded current_state;
 * mismatches bump self->barrier_mismatch_count and surface a
 * one-line diagnostic on the first three (throttled to keep the
 * log bounded). The state update lands either way so a caller that
 * gets the sequencing wrong stays consistent on the next barrier
 * — the counter is the regression signal, not a hard error. */
static void list_ResourceBarrier(D12ListImpl* self, UINT n, const void* barriers)
{
    if (!self || n == 0 || !barriers)
        return;
    const BYTE* p = (const BYTE*)barriers;
    for (UINT i = 0; i < n; ++i)
    {
        const BYTE* b = p + (SIZE_T)i * 40;
        UINT type = *(const UINT*)(b + 0);
        if (type != 0) /* TRANSITION = 0 */
            continue;
        D12ResImpl* res = *(D12ResImpl* const*)(b + 8);
        UINT state_before = *(const UINT*)(b + 20);
        UINT state_after = *(const UINT*)(b + 24);
        if (res && res->lpVtbl == g_res_vtbl)
        {
            if (res->current_state != state_before)
            {
                self->barrier_mismatch_count++;
                if (self->barrier_mismatch_count <= 3)
                    list_emit_barrier_mismatch(res->current_state, state_before, state_after);
            }
            res->current_state = state_after;
        }
    }
}

/* IASetPrimitiveTopology(topology) — slot 20. */
static void list_IASetPrimitiveTopology(D12ListImpl* self, UINT topology)
{
    if (self)
        self->current_topology = topology;
}

/* RSSetViewports(num, viewports) — slot 21. D3D12_VIEWPORT (24 B):
 * TopLeftX(0,f32), TopLeftY(4,f32), Width(8,f32), Height(12,f32),
 * MinDepth(16,f32), MaxDepth(20,f32). */
static void list_RSSetViewports(D12ListImpl* self, UINT n, const void* vp)
{
    if (!self || n == 0 || !vp)
        return;
    const float* v = (const float*)vp;
    self->viewport_x = (int)v[0];
    self->viewport_y = (int)v[1];
    self->viewport_w = (int)v[2];
    self->viewport_h = (int)v[3];
}

/* SetPipelineState(pso) — slot 25. */
static void list_SetPipelineState(D12ListImpl* self, D12PsoImpl* pso)
{
    if (!self)
        return;
    self->current_pso = (pso && pso->lpVtbl == g_pso_vtbl) ? pso : NULL;
}

/* SetGraphicsRootSignature(rootSig) — slot 30. v0 doesn't read root
 * params during draw, so the binding is a no-op. The shape exists so
 * caller code paths don't hit a nil vtable slot. */
static void list_SetGraphicsRootSignature(D12ListImpl* self, void* rootsig)
{
    (void)self;
    (void)rootsig;
}

/* IASetIndexBuffer(view) — slot 43. D3D12_INDEX_BUFFER_VIEW (16 B):
 *   UINT64 BufferLocation (0)
 *   UINT SizeInBytes (8)
 *   DXGI_FORMAT Format (12). */
static void list_IASetIndexBuffer(D12ListImpl* self, const void* view)
{
    if (!self || !view)
    {
        if (self)
        {
            self->current_ib_address = 0;
            self->current_ib_size = 0;
        }
        return;
    }
    const BYTE* v = (const BYTE*)view;
    self->current_ib_address = *(const UINT64*)(v + 0);
    self->current_ib_size = *(const UINT*)(v + 8);
    self->current_ib_format = *(const UINT*)(v + 12);
}

/* IASetVertexBuffers(startSlot, num, views) — slot 44.
 * D3D12_VERTEX_BUFFER_VIEW (16 B):
 *   UINT64 BufferLocation (0)
 *   UINT SizeInBytes (8)
 *   UINT StrideInBytes (12).
 * v0 only honours the first view (slot 0). */
static void list_IASetVertexBuffers(D12ListImpl* self, UINT start_slot, UINT n, const void* views)
{
    (void)start_slot;
    if (!self || n == 0 || !views)
    {
        if (self)
        {
            self->current_vb_address = 0;
            self->current_vb_size = 0;
            self->current_vb_stride = 0;
        }
        return;
    }
    const BYTE* v = (const BYTE*)views;
    self->current_vb_address = *(const UINT64*)(v + 0);
    self->current_vb_size = *(const UINT*)(v + 8);
    self->current_vb_stride = *(const UINT*)(v + 12);
}

/* OMSetRenderTargets(numRTV, ppCpuHandles, singleRange, dsvHandle) — slot 46.
 * D3D12 passes the CPU handles either as an array of pointers (single = FALSE)
 * or as a base + stride (single = TRUE). v0 reads the first descriptor either
 * way and binds it as the colour target. */
static void list_OMSetRenderTargets(D12ListImpl* self, UINT n, const void* cpu_handles, BOOL single_range,
                                    const void* dsv)
{
    (void)dsv;
    if (!self || n == 0 || !cpu_handles)
    {
        if (self)
            self->current_rt = NULL;
        return;
    }
    SIZE_T h0 = single_range ? *(const SIZE_T*)cpu_handles : ((const SIZE_T*)cpu_handles)[0];
    if (h0 == 0)
    {
        self->current_rt = NULL;
        return;
    }
    void** slot = (void**)(unsigned long long)h0;
    D12ResImpl* res = (D12ResImpl*)(*slot);
    self->current_rt = (res && res->lpVtbl == g_res_vtbl && res->kind == 0) ? res : NULL;
}

/* ClearDepthStencilView — slot 47. v0 has no depth buffer; success
 * is a no-op. */
static void list_ClearDepthStencilView(D12ListImpl* self, SIZE_T cpu_handle, UINT clear_flags, float depth,
                                       BYTE stencil, UINT n_rects, const void* rects)
{
    (void)self;
    (void)cpu_handle;
    (void)clear_flags;
    (void)depth;
    (void)stencil;
    (void)n_rects;
    (void)rects;
}

/* Pull (x, y) screen-space from a vertex via the bound PSO's input
 * layout + the bound VB. Returns 0 on out-of-range. */
static int list_read_vertex(D12ListImpl* self, UINT idx, int* out_x, int* out_y, DWORD* out_color)
{
    if (!self || !self->current_pso || self->current_vb_address == 0 || self->current_vb_stride == 0)
        return 0;
    if (self->current_pso->position_offset == 0xFFFF)
        return 0;
    const BYTE* base = (const BYTE*)(unsigned long long)self->current_vb_address;
    if (!base)
        return 0;
    SIZE_T pos_off = (SIZE_T)idx * self->current_vb_stride + self->current_pso->position_offset;
    if (pos_off + 12 > self->current_vb_size)
        return 0;
    float xyz[3];
    dx_memcpy(xyz, base + pos_off, 12);
    DxVec4 clip;
    clip.x = xyz[0];
    clip.y = xyz[1];
    clip.z = xyz[2];
    clip.w = 1.0f;
    int vp_x = self->viewport_x, vp_y = self->viewport_y;
    int vp_w = self->viewport_w, vp_h = self->viewport_h;
    if (vp_w <= 0 || vp_h <= 0)
    {
        if (self->current_rt && self->current_rt->bb)
        {
            vp_x = 0;
            vp_y = 0;
            vp_w = (int)self->current_rt->bb->width;
            vp_h = (int)self->current_rt->bb->height;
        }
        else
        {
            return 0;
        }
    }
    if (!dxr_project(&clip, vp_x, vp_y, vp_w, vp_h, out_x, out_y))
        return 0;
    if (out_color)
    {
        if (self->current_pso->color_offset != 0xFFFF)
        {
            SIZE_T col_off = (SIZE_T)idx * self->current_vb_stride + self->current_pso->color_offset;
            if (self->current_pso->color_kind == 0 && col_off + 16 <= self->current_vb_size)
            {
                float c[4];
                dx_memcpy(c, base + col_off, 16);
                *out_color = dxr_pack_rgba(c[0], c[1], c[2], c[3]);
            }
            else if (col_off + 4 <= self->current_vb_size)
            {
                DWORD c;
                dx_memcpy(&c, base + col_off, 4);
                if (self->current_pso->color_kind == 1)
                    *out_color = c;
                else
                {
                    BYTE r = (BYTE)(c & 0xFF), g = (BYTE)((c >> 8) & 0xFF);
                    BYTE b = (BYTE)((c >> 16) & 0xFF), a = (BYTE)((c >> 24) & 0xFF);
                    *out_color = ((DWORD)a << 24) | ((DWORD)r << 16) | ((DWORD)g << 8) | (DWORD)b;
                }
            }
            else
            {
                *out_color = 0xFFFFFFFFu;
            }
        }
        else
        {
            *out_color = 0xFFFFFFFFu;
        }
    }
    return 1;
}

static int list_read_index(D12ListImpl* self, UINT idx, INT base_vertex, UINT* out_vertex_index)
{
    if (!self || self->current_ib_address == 0)
        return 0;
    UINT stride = (self->current_ib_format == 42) ? 4 : 2;
    SIZE_T off = (SIZE_T)idx * stride;
    if (off + stride > self->current_ib_size)
        return 0;
    const BYTE* base = (const BYTE*)(unsigned long long)self->current_ib_address;
    if (!base)
        return 0;
    UINT v;
    if (stride == 4)
    {
        dx_memcpy(&v, base + off, 4);
    }
    else
    {
        WORD vw;
        dx_memcpy(&vw, base + off, 2);
        v = vw;
    }
    long long vi = (long long)v + (long long)base_vertex;
    if (vi < 0)
        return 0;
    if (out_vertex_index)
        *out_vertex_index = (UINT)vi;
    return 1;
}

static void list_emit_tri(D12ListImpl* self, UINT i0, UINT i1, UINT i2)
{
    int x0, y0, x1, y1, x2, y2;
    DWORD c0, c1, c2;
    if (!list_read_vertex(self, i0, &x0, &y0, &c0))
        return;
    if (!list_read_vertex(self, i1, &x1, &y1, &c1))
        return;
    if (!list_read_vertex(self, i2, &x2, &y2, &c2))
        return;
    if (!self->current_rt || !self->current_rt->bb)
        return;
    DxBackBuffer* bb = self->current_rt->bb;
    if (c0 == c1 && c1 == c2)
        dxr_fill_tri(bb, x0, y0, x1, y1, x2, y2, c0);
    else
        dxr_shade_tri(bb, x0, y0, x1, y1, x2, y2, c0, c1, c2);
}

/* DrawInstanced(VertexCountPerInstance, InstanceCount, StartVertex, StartInstance) — slot 12. */
static void list_DrawInstanced(D12ListImpl* self, UINT vcount, UINT icount, UINT vstart, UINT istart)
{
    (void)istart;
    if (!self || vcount == 0 || icount == 0)
        return;
    UINT topology = self->current_topology ? self->current_topology : 4;
    for (UINT inst = 0; inst < icount; ++inst)
    {
        if (topology == 4)
        {
            UINT triangles = vcount / 3;
            for (UINT t = 0; t < triangles; ++t)
                list_emit_tri(self, vstart + t * 3, vstart + t * 3 + 1, vstart + t * 3 + 2);
        }
        else if (topology == 5)
        {
            if (vcount < 3)
                continue;
            for (UINT t = 0; t + 2 < vcount; ++t)
            {
                UINT a = vstart + t, b = vstart + t + 1, c = vstart + t + 2;
                if (t & 1)
                {
                    UINT tmp = b;
                    b = c;
                    c = tmp;
                }
                list_emit_tri(self, a, b, c);
            }
        }
    }
}

/* DrawIndexedInstanced(IndexCountPerInstance, InstanceCount, StartIndex,
 *   BaseVertexLocation, StartInstance) — slot 13. */
static void list_DrawIndexedInstanced(D12ListImpl* self, UINT icount, UINT instance_count, UINT istart, INT base_vertex,
                                      UINT inst_start)
{
    (void)inst_start;
    if (!self || icount == 0 || instance_count == 0)
        return;
    UINT topology = self->current_topology ? self->current_topology : 4;
    for (UINT inst = 0; inst < instance_count; ++inst)
    {
        if (topology == 4)
        {
            UINT triangles = icount / 3;
            for (UINT t = 0; t < triangles; ++t)
            {
                UINT a, b, c;
                if (!list_read_index(self, istart + t * 3, base_vertex, &a))
                    continue;
                if (!list_read_index(self, istart + t * 3 + 1, base_vertex, &b))
                    continue;
                if (!list_read_index(self, istart + t * 3 + 2, base_vertex, &c))
                    continue;
                list_emit_tri(self, a, b, c);
            }
        }
        else if (topology == 5)
        {
            if (icount < 3)
                continue;
            for (UINT t = 0; t + 2 < icount; ++t)
            {
                UINT a, b, c;
                if (!list_read_index(self, istart + t, base_vertex, &a))
                    continue;
                if (!list_read_index(self, istart + t + 1, base_vertex, &b))
                    continue;
                if (!list_read_index(self, istart + t + 2, base_vertex, &c))
                    continue;
                if (t & 1)
                {
                    UINT tmp = b;
                    b = c;
                    c = tmp;
                }
                list_emit_tri(self, a, b, c);
            }
        }
    }
}

/* ClearRenderTargetView(cpuHandle, color[4], numRects, rects) — slot 48.
 * cpuHandle is a SIZE_T-sized struct (the value of the descriptor
 * slot). The descriptor slot stores D12ResImpl*. */
static void list_ClearRenderTargetView(D12ListImpl* self, SIZE_T cpu_handle, const float color[4], UINT n_rects,
                                       const void* rects)
{
    (void)self;
    (void)n_rects;
    (void)rects;
    if (!cpu_handle || !color)
        return;
    void** slot = (void**)(unsigned long long)cpu_handle;
    D12ResImpl* res = (D12ResImpl*)(*slot);
    if (!res || res->lpVtbl != g_res_vtbl)
        return;
    if (res->kind != 0 || !res->bb)
        return;
    dx_bb_clear_rgba(res->bb, color[0], color[1], color[2], color[3]);
}

static void* g_list_vtbl[LIST_VTBL_SLOTS];
static void list_init_vtbl_once(void)
{
    static int g_inited = 0;
    if (g_inited)
        return;
    g_inited = 1;
    for (int i = 0; i < LIST_VTBL_SLOTS; ++i)
        g_list_vtbl[i] = DX_HSTUB;
    g_list_vtbl[0] = (void*)list_QueryInterface;
    g_list_vtbl[1] = (void*)list_AddRef;
    g_list_vtbl[2] = (void*)list_Release;
    /* Canonical ID3D12GraphicsCommandList vtable layout per the
     * Win SDK d3d12.h. Off-by-N slot drift in earlier versions of
     * this DLL was the reason real Win32 PE apps that didn't share
     * the smoke test's mistaken slot map could not call it. */
    g_list_vtbl[8] = (void*)list_GetType;                   /* ID3D12CommandList::GetType */
    g_list_vtbl[9] = (void*)list_Close;                     /* ID3D12GraphicsCommandList */
    g_list_vtbl[10] = (void*)list_Reset;                    /* */
    g_list_vtbl[12] = (void*)list_DrawInstanced;            /* */
    g_list_vtbl[13] = (void*)list_DrawIndexedInstanced;     /* */
    g_list_vtbl[20] = (void*)list_IASetPrimitiveTopology;   /* */
    g_list_vtbl[21] = (void*)list_RSSetViewports;           /* */
    g_list_vtbl[22] = (void*)DX_VSTUB;                      /* RSSetScissorRects */
    g_list_vtbl[25] = (void*)list_SetPipelineState;         /* */
    g_list_vtbl[26] = (void*)list_ResourceBarrier;          /* */
    g_list_vtbl[29] = (void*)DX_VSTUB;                      /* SetComputeRootSignature */
    g_list_vtbl[30] = (void*)list_SetGraphicsRootSignature; /* */
    g_list_vtbl[43] = (void*)list_IASetIndexBuffer;         /* */
    g_list_vtbl[44] = (void*)list_IASetVertexBuffers;       /* */
    g_list_vtbl[46] = (void*)list_OMSetRenderTargets;       /* */
    g_list_vtbl[47] = (void*)list_ClearDepthStencilView;    /* */
    g_list_vtbl[48] = (void*)list_ClearRenderTargetView;    /* */
}

static D12ListImpl* list_alloc(UINT type)
{
    list_init_vtbl_once();
    D12ListImpl* l = (D12ListImpl*)dx_heap_alloc(sizeof(*l));
    if (!l)
        return NULL;
    dx_memzero(l, sizeof(*l));
    l->lpVtbl = g_list_vtbl;
    l->refcount = 1;
    l->type = type;
    return l;
}

/* ---------------------------------------------------------------- *
 * ID3D12CommandQueue                                               *
 *                                                                  *
 * v0 doesn't run a deferred command stream — every command list is *
 * already realized in its target's backing buffer at the time of   *
 * ClearRenderTargetView (etc.). ExecuteCommandLists is therefore a *
 * no-op success; Signal forwards to the fence's value.             *
 *                                                                  *
 * Vtable: IUnknown(3)+Object(4)+DeviceChild(1)+Pageable(0)+        *
 * CommandQueue(8). = 16 slots.                                     *
 * ---------------------------------------------------------------- */

#define QUEUE_VTBL_SLOTS 19 /* IUnknown(3)+Object(4)+DeviceChild(1)+Pageable(0)+CommandQueue(11) */

struct D12QueueImpl
{
    void* const* lpVtbl;
    ULONG refcount;
    UINT type;
};

static HRESULT q_QueryInterface(D12QueueImpl* self, REFIID riid, void** out)
{
    if (!out)
        return DX_E_POINTER;
    if (dx_guid_eq(riid, &kIID_IUnknown) || dx_guid_eq(riid, &kIID_ID3D12CommandQueue))
    {
        self->refcount++;
        *out = self;
        return DX_S_OK;
    }
    *out = NULL;
    return DX_E_NOINTERFACE;
}
static ULONG q_AddRef(D12QueueImpl* self)
{
    return ++self->refcount;
}
static ULONG q_Release(D12QueueImpl* self)
{
    if (--self->refcount == 0)
    {
        dx_heap_free(self);
        return 0;
    }
    return self->refcount;
}
static void q_ExecuteCommandLists(D12QueueImpl* self, UINT n, void* const* lists)
{
    (void)self;
    (void)n;
    (void)lists;
    /* All commands ran during their record phase. */
}
static HRESULT q_Signal(D12QueueImpl* self, D12FenceImpl* fence, UINT64 value)
{
    (void)self;
    if (fence && fence->lpVtbl == g_fence_vtbl)
        fence->value = value;
    return DX_S_OK;
}
static HRESULT q_Wait(D12QueueImpl* self, D12FenceImpl* fence, UINT64 value)
{
    (void)self;
    (void)fence;
    (void)value;
    return DX_S_OK;
}
static UINT64 q_GetTimestampFrequency(D12QueueImpl* self)
{
    (void)self;
    return 1000000;
}

static void* g_q_vtbl[QUEUE_VTBL_SLOTS];
static void q_init_vtbl_once(void)
{
    static int g_inited = 0;
    if (g_inited)
        return;
    g_inited = 1;
    for (int i = 0; i < QUEUE_VTBL_SLOTS; ++i)
        g_q_vtbl[i] = DX_HSTUB;
    g_q_vtbl[0] = (void*)q_QueryInterface;
    g_q_vtbl[1] = (void*)q_AddRef;
    g_q_vtbl[2] = (void*)q_Release;
    /* Canonical ID3D12CommandQueue vtable: 8 UpdateTileMappings,
     * 9 CopyTileMappings, 10 ExecuteCommandLists, 11 SetMarker,
     * 12 BeginEvent, 13 EndEvent, 14 Signal, 15 Wait,
     * 16 GetTimestampFrequency, 17 GetClockCalibration, 18 GetDesc. */
    g_q_vtbl[10] = (void*)q_ExecuteCommandLists;
    g_q_vtbl[14] = (void*)q_Signal;
    g_q_vtbl[15] = (void*)q_Wait;
    g_q_vtbl[16] = (void*)q_GetTimestampFrequency;
}

static D12QueueImpl* queue_alloc(UINT type)
{
    q_init_vtbl_once();
    D12QueueImpl* q = (D12QueueImpl*)dx_heap_alloc(sizeof(*q));
    if (!q)
        return NULL;
    dx_memzero(q, sizeof(*q));
    q->lpVtbl = g_q_vtbl;
    q->refcount = 1;
    q->type = type;
    return q;
}

/* ---------------------------------------------------------------- *
 * ID3D12Device                                                     *
 *                                                                  *
 * 44-method vtable. v0 implements:                                 *
 *   slot 8  GetNodeCount                                           *
 *   slot 9  CreateCommandQueue                                     *
 *   slot 10 CreateCommandAllocator                                 *
 *   slot 11 CreateGraphicsPipelineState (E_NOTIMPL — but we still  *
 *           need to put the right thing in slot 11 since slot 12   *
 *           is CreateComputePipelineState etc.; the stub already   *
 *           makes that fine)                                       *
 *   slot 13 CreateCommandList                                      *
 *   slot 14 CheckFeatureSupport                                    *
 *   slot 15 CreateDescriptorHeap                                   *
 *   slot 16 GetDescriptorHandleIncrementSize                       *
 *   slot 22 CreateFence                                            *
 *   slot 23 GetDeviceRemovedReason                                 *
 *   slot 27 CreateCommittedResource                                *
 *   slot 28 CreateRenderTargetView                                 *
 * ---------------------------------------------------------------- */

#define DEV12_VTBL_SLOTS 44

struct D12DeviceImpl
{
    void* const* lpVtbl;
    ULONG refcount;
};

static HRESULT d12dev_QueryInterface(D12DeviceImpl* self, REFIID riid, void** out)
{
    if (!out)
        return DX_E_POINTER;
    if (dx_guid_eq(riid, &kIID_IUnknown) || dx_guid_eq(riid, &kIID_ID3D12Device))
    {
        self->refcount++;
        *out = self;
        return DX_S_OK;
    }
    *out = NULL;
    return DX_E_NOINTERFACE;
}
static ULONG d12dev_AddRef(D12DeviceImpl* self)
{
    return ++self->refcount;
}
static ULONG d12dev_Release(D12DeviceImpl* self)
{
    if (--self->refcount == 0)
    {
        dx_heap_free(self);
        return 0;
    }
    return self->refcount;
}

static UINT d12dev_GetNodeCount(D12DeviceImpl* self)
{
    (void)self;
    return 1;
}

static HRESULT d12dev_CreateCommandQueue(D12DeviceImpl* self, const void* desc, REFIID riid, void** out)
{
    (void)self;
    (void)riid;
    if (!out)
        return DX_E_POINTER;
    *out = NULL;
    UINT type = desc ? *(const UINT*)desc : 0;
    D12QueueImpl* q = queue_alloc(type);
    if (!q)
        return DX_E_OUTOFMEMORY;
    *out = q;
    return DX_S_OK;
}

static HRESULT d12dev_CreateCommandAllocator(D12DeviceImpl* self, UINT type, REFIID riid, void** out)
{
    (void)self;
    (void)riid;
    if (!out)
        return DX_E_POINTER;
    *out = NULL;
    D12AllocImpl* a = allocator_alloc(type);
    if (!a)
        return DX_E_OUTOFMEMORY;
    *out = a;
    return DX_S_OK;
}

static HRESULT d12dev_CreateCommandList(D12DeviceImpl* self, UINT mask, UINT type, void* alloc, void* pso, REFIID riid,
                                        void** out)
{
    (void)self;
    (void)mask;
    (void)alloc;
    (void)pso;
    (void)riid;
    if (!out)
        return DX_E_POINTER;
    *out = NULL;
    D12ListImpl* l = list_alloc(type);
    if (!l)
        return DX_E_OUTOFMEMORY;
    *out = l;
    return DX_S_OK;
}

static HRESULT d12dev_CheckFeatureSupport(D12DeviceImpl* self, UINT feat, void* data, UINT n)
{
    (void)self;
    (void)feat;
    if (data && n > 0 && n < 4096)
        dx_memzero(data, n);
    return DX_S_OK;
}

/* D3D12_DESCRIPTOR_HEAP_DESC: Type(0), NumDescriptors(4), Flags(8), NodeMask(12). */
static HRESULT d12dev_CreateDescriptorHeap(D12DeviceImpl* self, const void* desc, REFIID riid, void** out)
{
    (void)self;
    (void)riid;
    if (!out)
        return DX_E_POINTER;
    *out = NULL;
    if (!desc)
        return DX_E_INVALIDARG;
    UINT type = *(const UINT*)((const BYTE*)desc + 0);
    UINT num = *(const UINT*)((const BYTE*)desc + 4);
    D12HeapImpl* h = heap_alloc(type, num);
    if (!h)
        return DX_E_OUTOFMEMORY;
    *out = h;
    return DX_S_OK;
}

static UINT d12dev_GetDescriptorHandleIncrementSize(D12DeviceImpl* self, UINT type)
{
    (void)self;
    (void)type;
    return (UINT)D12_DESC_STRIDE;
}

static HRESULT d12dev_CreateFence(D12DeviceImpl* self, UINT64 initial, UINT flags, REFIID riid, void** out)
{
    (void)self;
    (void)flags;
    (void)riid;
    if (!out)
        return DX_E_POINTER;
    *out = NULL;
    D12FenceImpl* f = fence_alloc(initial);
    if (!f)
        return DX_E_OUTOFMEMORY;
    *out = f;
    return DX_S_OK;
}

static HRESULT d12dev_GetDeviceRemovedReason(D12DeviceImpl* self)
{
    (void)self;
    return DX_S_OK;
}

/* CreateCommittedResource(heapProps, heapFlags, desc, initialState,
 *   optimizedClear, riid, ppResource).
 * D3D12_RESOURCE_DESC: Dimension(0,4B), Alignment(4,4B), Width(8,8B),
 *   Height(16,4B), DepthOrArraySize(20,2B), MipLevels(22,2B),
 *   Format(24,4B), ...
 *
 * D3D12_RESOURCE_DIMENSION: 0 UNKNOWN, 1 BUFFER, 2 TEXTURE1D,
 *   3 TEXTURE2D (legacy), 4 TEXTURE2D, 5 TEXTURE3D. We treat 1 as
 *   buffer (linear bytes = Width); everything else as a 2D texture. */
static HRESULT d12dev_CreateCommittedResource(D12DeviceImpl* self, const void* heap_props, UINT heap_flags,
                                              const void* desc, UINT initial_state, const void* opt_clear, REFIID riid,
                                              void** out)
{
    (void)self;
    (void)heap_props;
    (void)heap_flags;
    (void)opt_clear;
    (void)riid;
    if (!out)
        return DX_E_POINTER;
    *out = NULL;
    if (!desc)
        return DX_E_INVALIDARG;
    const BYTE* d = (const BYTE*)desc;
    UINT dim = *(const UINT*)(d + 0);
    UINT64 w64 = *(const UINT64*)(d + 8);
    UINT h = *(const UINT*)(d + 16);
    UINT fmt = *(const UINT*)(d + 24);
    UINT w = (UINT)(w64 & 0xFFFFFFFFu);
    if (dim == 1)
    {
        D12ResImpl* r = res_alloc_buffer(w, initial_state);
        if (!r)
            return DX_E_OUTOFMEMORY;
        *out = r;
        return DX_S_OK;
    }
    if (w == 0)
        w = 1;
    if (h == 0)
        h = 1;
    D12ResImpl* r = res_alloc_tex2d(w, h, fmt, initial_state);
    if (!r)
        return DX_E_OUTOFMEMORY;
    *out = r;
    return DX_S_OK;
}

/* CreateRenderTargetView(resource, desc, cpuHandle).
 * cpuHandle is a SIZE_T-sized aggregate (D3D12_CPU_DESCRIPTOR_HANDLE).
 * MSVC x64 passes 8-byte aggregates by value in the register slot.
 * Effect: write the resource pointer into the heap slot at cpuHandle. */
static void d12dev_CreateRenderTargetView(D12DeviceImpl* self, void* resource, const void* desc, SIZE_T cpu_handle)
{
    (void)self;
    (void)desc;
    if (!cpu_handle)
        return;
    void** slot = (void**)(unsigned long long)cpu_handle;
    *slot = resource; /* may be NULL — that's fine */
}

/* CreateRootSignature(nodeMask, blob, blobSize, riid, ppRootSig) — slot 16. */
static HRESULT d12dev_CreateRootSignature(D12DeviceImpl* self, UINT node_mask, const void* blob, SIZE_T blob_size,
                                          REFIID riid, void** out)
{
    (void)self;
    (void)node_mask;
    (void)blob;
    (void)blob_size;
    (void)riid;
    if (!out)
        return DX_E_POINTER;
    *out = NULL;
    D12RootSigImpl* r = rootsig_alloc();
    if (!r)
        return DX_E_OUTOFMEMORY;
    *out = r;
    return DX_S_OK;
}

/* CreateGraphicsPipelineState(desc, riid, ppPSO) — slot 10.
 * D3D12_GRAPHICS_PIPELINE_STATE_DESC layout (the ABI is huge — we
 * only read what we need to honour the input-layout extraction):
 *   +0   ID3D12RootSignature* pRootSignature        (8)
 *   +8   D3D12_SHADER_BYTECODE VS                   (16: pCode + len)
 *   +24  D3D12_SHADER_BYTECODE PS                   (16)
 *   +40  D3D12_SHADER_BYTECODE DS                   (16)
 *   +56  D3D12_SHADER_BYTECODE HS                   (16)
 *   +72  D3D12_SHADER_BYTECODE GS                   (16)
 *   +88  D3D12_STREAM_OUTPUT_DESC StreamOutput      (40)
 *   +128 D3D12_BLEND_DESC BlendState                (132)
 *   +260 UINT SampleMask                             (4)
 *   +264 D3D12_RASTERIZER_DESC RasterizerState      (40)
 *   +304 D3D12_DEPTH_STENCIL_DESC DepthStencilState (44)
 *   +348 D3D12_INPUT_LAYOUT_DESC InputLayout        (16: pDescs + numElems)
 *   +364 D3D12_INDEX_BUFFER_STRIP_CUT_VALUE          (4)
 *   +368 D3D12_PRIMITIVE_TOPOLOGY_TYPE              (4)
 *   ... (RTV formats, DSV format, sample desc, node mask, cached PSO, flags)
 *
 * Many SDK versions tweak field padding; the offsets above match
 * the canonical Win SDK layout for the v1 desc shape. */
static HRESULT d12dev_CreateGraphicsPipelineState(D12DeviceImpl* self, const void* desc, REFIID riid, void** out)
{
    (void)self;
    (void)riid;
    if (!out)
        return DX_E_POINTER;
    *out = NULL;
    if (!desc)
        return DX_E_INVALIDARG;
    const BYTE* d = (const BYTE*)desc;
    /* InputLayout = D3D12_INPUT_LAYOUT_DESC at offset 348:
     *   D3D12_INPUT_ELEMENT_DESC* pInputElementDescs (8)
     *   UINT NumElements (4) — pads to 16 */
    const void* il_descs = *(const void* const*)(d + 348);
    UINT il_count = *(const UINT*)(d + 356);
    UINT topology_type = *(const UINT*)(d + 368);
    D12PsoImpl* p = pso_alloc_from_desc(il_descs, il_count, topology_type);
    if (!p)
        return DX_E_OUTOFMEMORY;
    *out = p;
    return DX_S_OK;
}

static HRESULT d12dev_CreateComputePipelineState(D12DeviceImpl* self, const void* desc, REFIID riid, void** out)
{
    (void)self;
    (void)desc;
    (void)riid;
    if (!out)
        return DX_E_POINTER;
    /* No compute-shader path in v0; hand out a topology-undef PSO so
     * Release / Reset don't crash. */
    D12PsoImpl* p = pso_alloc_from_desc(NULL, 0, 0);
    if (!p)
    {
        *out = NULL;
        return DX_E_OUTOFMEMORY;
    }
    *out = p;
    return DX_S_OK;
}

static void* g_d12dev_vtbl[DEV12_VTBL_SLOTS];
static void d12dev_init_vtbl_once(void)
{
    static int g_inited = 0;
    if (g_inited)
        return;
    g_inited = 1;
    for (int i = 0; i < DEV12_VTBL_SLOTS; ++i)
        g_d12dev_vtbl[i] = DX_HSTUB;
    g_d12dev_vtbl[0] = (void*)d12dev_QueryInterface;
    g_d12dev_vtbl[1] = (void*)d12dev_AddRef;
    g_d12dev_vtbl[2] = (void*)d12dev_Release;
    /* Canonical ID3D12Device vtable layout (Win SDK d3d12.h):
     *   3..6  ID3D12Object (GetPrivateData, SetPrivateData,
     *         SetPrivateDataInterface, SetName)
     *   7     GetNodeCount
     *   8     CreateCommandQueue
     *   9     CreateCommandAllocator
     *   10    CreateGraphicsPipelineState
     *   11    CreateComputePipelineState
     *   12    CreateCommandList
     *   13    CheckFeatureSupport
     *   14    CreateDescriptorHeap
     *   15    GetDescriptorHandleIncrementSize
     *   16    CreateRootSignature
     *   17..19 CreateConstantBufferView / SRV / UAV
     *   20    CreateRenderTargetView
     *   21    CreateDepthStencilView
     *   22    CreateSampler
     *   23..26 CopyDescriptors{,Simple} / GetResourceAllocationInfo /
     *         GetCustomHeapProperties
     *   27    CreateCommittedResource
     *   28..35 CreateHeap / CreatePlacedResource / CreateReservedResource /
     *         CreateSharedHandle / OpenSharedHandle{,ByName} / MakeResident /
     *         Evict
     *   36    CreateFence
     *   37    GetDeviceRemovedReason
     *   38..43 GetCopyableFootprints / CreateQueryHeap /
     *         SetStablePowerState / CreateCommandSignature /
     *         GetResourceTiling / GetAdapterLuid
     *
     * Earlier revisions of this DLL had drifted-by-N slot numbers;
     * fixed here so a real Win32 PE compiled against d3d12.h works. */
    g_d12dev_vtbl[7] = (void*)d12dev_GetNodeCount;
    g_d12dev_vtbl[8] = (void*)d12dev_CreateCommandQueue;
    g_d12dev_vtbl[9] = (void*)d12dev_CreateCommandAllocator;
    g_d12dev_vtbl[10] = (void*)d12dev_CreateGraphicsPipelineState;
    g_d12dev_vtbl[11] = (void*)d12dev_CreateComputePipelineState;
    g_d12dev_vtbl[12] = (void*)d12dev_CreateCommandList;
    g_d12dev_vtbl[13] = (void*)d12dev_CheckFeatureSupport;
    g_d12dev_vtbl[14] = (void*)d12dev_CreateDescriptorHeap;
    g_d12dev_vtbl[15] = (void*)d12dev_GetDescriptorHandleIncrementSize;
    g_d12dev_vtbl[16] = (void*)d12dev_CreateRootSignature;
    g_d12dev_vtbl[20] = (void*)d12dev_CreateRenderTargetView;
    g_d12dev_vtbl[27] = (void*)d12dev_CreateCommittedResource;
    g_d12dev_vtbl[36] = (void*)d12dev_CreateFence;
    g_d12dev_vtbl[37] = (void*)d12dev_GetDeviceRemovedReason;
}

static D12DeviceImpl* d12dev_alloc(void)
{
    d12dev_init_vtbl_once();
    D12DeviceImpl* d = (D12DeviceImpl*)dx_heap_alloc(sizeof(*d));
    if (!d)
        return NULL;
    dx_memzero(d, sizeof(*d));
    d->lpVtbl = g_d12dev_vtbl;
    d->refcount = 1;
    return d;
}

/* ---------------------------------------------------------------- *
 * ID3D12Debug — IUnknown(3) + EnableDebugLayer(1). 4 slots.        *
 * ---------------------------------------------------------------- */

#define DBG_VTBL_SLOTS 4
typedef struct D12DebugImpl
{
    void* const* lpVtbl;
    ULONG refcount;
} D12DebugImpl;

static HRESULT dbg_QueryInterface(D12DebugImpl* self, REFIID riid, void** out)
{
    if (!out)
        return DX_E_POINTER;
    if (dx_guid_eq(riid, &kIID_IUnknown) || dx_guid_eq(riid, &kIID_ID3D12Debug))
    {
        self->refcount++;
        *out = self;
        return DX_S_OK;
    }
    *out = NULL;
    return DX_E_NOINTERFACE;
}
static ULONG dbg_AddRef(D12DebugImpl* self)
{
    return ++self->refcount;
}
static ULONG dbg_Release(D12DebugImpl* self)
{
    if (--self->refcount == 0)
    {
        dx_heap_free(self);
        return 0;
    }
    return self->refcount;
}
static void dbg_EnableDebugLayer(D12DebugImpl* self)
{
    (void)self;
}

static void* g_dbg_vtbl[DBG_VTBL_SLOTS];
static void dbg_init_vtbl_once(void)
{
    static int g_inited = 0;
    if (g_inited)
        return;
    g_inited = 1;
    g_dbg_vtbl[0] = (void*)dbg_QueryInterface;
    g_dbg_vtbl[1] = (void*)dbg_AddRef;
    g_dbg_vtbl[2] = (void*)dbg_Release;
    g_dbg_vtbl[3] = (void*)dbg_EnableDebugLayer;
}

/* ---------------------------------------------------------------- *
 * Exported entry points                                            *
 * ---------------------------------------------------------------- */

__declspec(dllexport) HRESULT D3D12CreateDevice(void* adapter, UINT min_feature_level, REFIID riid, void** device)
{
    (void)adapter;
    (void)min_feature_level;
    (void)riid;
    dx_gfx_trace(2);
    if (!device)
        return DX_E_POINTER;
    D12DeviceImpl* d = d12dev_alloc();
    if (!d)
    {
        *device = NULL;
        return DX_E_OUTOFMEMORY;
    }
    *device = d;
    return DX_S_OK;
}

__declspec(dllexport) HRESULT D3D12GetDebugInterface(REFIID riid, void** dbg)
{
    (void)riid;
    dbg_init_vtbl_once();
    if (!dbg)
        return DX_E_POINTER;
    D12DebugImpl* d = (D12DebugImpl*)dx_heap_alloc(sizeof(*d));
    if (!d)
    {
        *dbg = NULL;
        return DX_E_OUTOFMEMORY;
    }
    dx_memzero(d, sizeof(*d));
    d->lpVtbl = g_dbg_vtbl;
    d->refcount = 1;
    *dbg = d;
    return DX_S_OK;
}

/* SerializeRootSignature: produce a tiny opaque blob the caller
 * passes to CreateRootSignature later. We use an ID3DBlob-shaped
 * vtable: GetBufferPointer / GetBufferSize. */
typedef struct DxBlobImpl
{
    void* const* lpVtbl;
    ULONG refcount;
    SIZE_T size;
    BYTE data[1];
} DxBlobImpl;

static HRESULT blob_QueryInterface(DxBlobImpl* self, REFIID riid, void** out)
{
    (void)riid;
    if (!out)
        return DX_E_POINTER;
    self->refcount++;
    *out = self;
    return DX_S_OK;
}
static ULONG blob_AddRef(DxBlobImpl* self)
{
    return ++self->refcount;
}
static ULONG blob_Release(DxBlobImpl* self)
{
    if (--self->refcount == 0)
    {
        dx_heap_free(self);
        return 0;
    }
    return self->refcount;
}
static void* blob_GetBufferPointer(DxBlobImpl* self)
{
    return self ? self->data : NULL;
}
static SIZE_T blob_GetBufferSize(DxBlobImpl* self)
{
    return self ? self->size : 0;
}

static void* g_blob_vtbl[5];
static void blob_init_vtbl_once(void)
{
    static int g_inited = 0;
    if (g_inited)
        return;
    g_inited = 1;
    g_blob_vtbl[0] = (void*)blob_QueryInterface;
    g_blob_vtbl[1] = (void*)blob_AddRef;
    g_blob_vtbl[2] = (void*)blob_Release;
    g_blob_vtbl[3] = (void*)blob_GetBufferPointer;
    g_blob_vtbl[4] = (void*)blob_GetBufferSize;
}

__declspec(dllexport) HRESULT D3D12SerializeRootSignature(const void* root_sig, UINT version, void** blob,
                                                          void** err_blob)
{
    (void)root_sig;
    (void)version;
    blob_init_vtbl_once();
    if (err_blob)
        *err_blob = NULL;
    if (!blob)
        return DX_E_POINTER;
    /* 8-byte placeholder body — enough for any caller that only
     * passes the blob back to CreateRootSignature. */
    DxBlobImpl* b = (DxBlobImpl*)dx_heap_alloc(sizeof(DxBlobImpl) + 8);
    if (!b)
    {
        *blob = NULL;
        return DX_E_OUTOFMEMORY;
    }
    dx_memzero(b, sizeof(*b) + 8);
    b->lpVtbl = g_blob_vtbl;
    b->refcount = 1;
    b->size = 8;
    *blob = b;
    return DX_S_OK;
}

/* Non-Win32 introspection helper: read back an ID3D12Resource's
 * current_state. Used by the dx_demo to verify ResourceBarrier
 * actually updates the field. Callers must hold a reference to
 * the resource for the duration of the call. Returns 0xFFFFFFFF
 * if the pointer doesn't look like one of our resources. */
__declspec(dllexport) UINT DuetOS_D3D12_PeekResourceState(void* resource)
{
    if (!resource)
        return 0xFFFFFFFFu;
    D12ResImpl* r = (D12ResImpl*)resource;
    if (r->lpVtbl != g_res_vtbl)
        return 0xFFFFFFFFu;
    return r->current_state;
}

/* Non-Win32 introspection helper: read back the count of TRANSITION
 * barriers a command list has seen whose StateBefore did not match
 * the resource's recorded current_state. Used by the dx_demo to
 * verify the validation fires on a deliberate mismatch and stays at
 * zero on a clean transition. Returns 0xFFFFFFFF if the pointer
 * doesn't look like one of our command lists. */
__declspec(dllexport) UINT DuetOS_D3D12_PeekBarrierMismatchCount(void* list)
{
    if (!list)
        return 0xFFFFFFFFu;
    D12ListImpl* l = (D12ListImpl*)list;
    if (l->lpVtbl != g_list_vtbl)
        return 0xFFFFFFFFu;
    return l->barrier_mismatch_count;
}
