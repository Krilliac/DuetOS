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
 * Build: tools/build-stub-dll.sh (base 0x10140000).
 */

#include "../dx_shared.h"

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
 * ID3D12Resource — committed BGRA8 buffer.                         *
 * Vtable: IUnknown(3) + ID3D12Object(4) + DeviceChild(1) +         *
 * ID3D12Pageable(0) + ID3D12Resource(8 = Map, Unmap, GetDesc,      *
 *   GetGPUVirtualAddress, WriteToSubresource, ReadFromSubresource, *
 *   GetHeapProperties).                                            *
 * Total: 18 slots.                                                 *
 * ---------------------------------------------------------------- */

#define RES_VTBL_SLOTS 18

struct D12ResImpl
{
    void* const* lpVtbl;
    ULONG refcount;
    DxBackBuffer* bb;
    BOOL owns_bb;
    UINT format;
    UINT width;
    UINT height;
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
    *(UINT*)(d + 0) = 4;             /* Dimension = TEXTURE2D */
    *(UINT*)(d + 4) = 0;             /* Alignment */
    *(UINT64*)(d + 8) = self->width; /* Width — 64-bit on D12 */
    *(UINT*)(d + 16) = self->height; /* Height */
    *(WORD*)(d + 20) = 1;            /* DepthOrArraySize */
    *(WORD*)(d + 22) = 1;            /* MipLevels */
    *(UINT*)(d + 24) = self->format;
}

/* Map(Subresource, ReadRange*, void**) — slot 8. */
static HRESULT res_Map(D12ResImpl* self, UINT sub, const void* range, void** out)
{
    (void)sub;
    (void)range;
    if (!out)
        return DX_E_POINTER;
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
 * into the backing buffer, masked to look like a virtual address. */
static UINT64 res_GetGPUVirtualAddress(D12ResImpl* self)
{
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

static D12ResImpl* res_alloc(UINT w, UINT h, UINT format)
{
    res_init_vtbl_once();
    D12ResImpl* r = (D12ResImpl*)dx_heap_alloc(sizeof(*r));
    if (!r)
        return NULL;
    dx_memzero(r, sizeof(*r));
    r->lpVtbl = g_res_vtbl;
    r->refcount = 1;
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
 * ID3D12GraphicsCommandList                                        *
 *                                                                  *
 * The full vtable has 60+ methods. v0 implements only:             *
 *   slot 8 : Close                                                 *
 *   slot 9 : Reset                                                 *
 *   slot 13: ResourceBarrier (no-op success)                       *
 *   slot 23: ClearRenderTargetView (real)                          *
 *   slot 25: OMSetRenderTargets (stores current RTV)               *
 * Everything else is DX_HSTUB / DX_VSTUB.                           *
 * ---------------------------------------------------------------- */

#define LIST_VTBL_SLOTS 80

struct D12ListImpl
{
    void* const* lpVtbl;
    ULONG refcount;
    UINT type;
    BOOL closed;
    /* Track the most recent RTV slot pointed at by OMSetRenderTargets
     * so a subsequent ClearRenderTargetView with a CPU descriptor
     * handle can find its target. The handle is a SIZE_T pointer
     * into a heap's descriptor array; the slot stores a D12ResImpl*. */
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
    (void)pso;
    self->closed = 0;
    return DX_S_OK;
}
static void list_ResourceBarrier(D12ListImpl* self, UINT n, const void* barriers)
{
    (void)self;
    (void)n;
    (void)barriers;
}

/* ClearRenderTargetView(cpuHandle, color[4], numRects, rects) — slot 23.
 * cpuHandle is a SIZE_T-sized struct (the value of the descriptor
 * slot). The descriptor slot stores D12ResImpl*. MSVC ABI passes a
 * <=8-byte aggregate by value — but at the call site the caller
 * actually built it from `heap->GetCPUStart() + idx * stride`, so
 * we can read the resource pointer through the SIZE_T. */
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
    if (!res->bb)
        return;
    dx_bb_clear_rgba(res->bb, color[0], color[1], color[2], color[3]);
}

static void list_OMSetRenderTargets(D12ListImpl* self, UINT n, const void* rtvs, BOOL single_handle, const void* dsv)
{
    (void)self;
    (void)n;
    (void)rtvs;
    (void)single_handle;
    (void)dsv;
    /* No-op: ClearRenderTargetView gets the CPU handle directly so
     * we don't need to track binding state to make Clear work. */
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
    g_list_vtbl[7] = (void*)list_GetType; /* ID3D12CommandList::GetType */
    g_list_vtbl[8] = (void*)list_Close;
    g_list_vtbl[9] = (void*)list_Reset;
    g_list_vtbl[13] = (void*)list_ResourceBarrier;
    g_list_vtbl[23] = (void*)list_ClearRenderTargetView;
    g_list_vtbl[25] = (void*)list_OMSetRenderTargets;
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

#define QUEUE_VTBL_SLOTS 16

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
    g_q_vtbl[10] = (void*)q_ExecuteCommandLists;
    g_q_vtbl[11] = (void*)q_Signal;
    g_q_vtbl[12] = (void*)q_Wait;
    g_q_vtbl[13] = (void*)q_GetTimestampFrequency;
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
 *   Format(24,4B), ... */
static HRESULT d12dev_CreateCommittedResource(D12DeviceImpl* self, const void* heap_props, UINT heap_flags,
                                              const void* desc, UINT initial_state, const void* opt_clear, REFIID riid,
                                              void** out)
{
    (void)self;
    (void)heap_props;
    (void)heap_flags;
    (void)initial_state;
    (void)opt_clear;
    (void)riid;
    if (!out)
        return DX_E_POINTER;
    *out = NULL;
    if (!desc)
        return DX_E_INVALIDARG;
    const BYTE* d = (const BYTE*)desc;
    UINT64 w64 = *(const UINT64*)(d + 8);
    UINT h = *(const UINT*)(d + 16);
    UINT fmt = *(const UINT*)(d + 24);
    UINT w = (UINT)(w64 & 0xFFFFFFFFu);
    if (w == 0)
        w = 1;
    if (h == 0)
        h = 1;
    D12ResImpl* r = res_alloc(w, h, fmt);
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
    g_d12dev_vtbl[8] = (void*)d12dev_GetNodeCount;
    g_d12dev_vtbl[9] = (void*)d12dev_CreateCommandQueue;
    g_d12dev_vtbl[10] = (void*)d12dev_CreateCommandAllocator;
    g_d12dev_vtbl[13] = (void*)d12dev_CreateCommandList;
    g_d12dev_vtbl[14] = (void*)d12dev_CheckFeatureSupport;
    g_d12dev_vtbl[15] = (void*)d12dev_CreateDescriptorHeap;
    g_d12dev_vtbl[16] = (void*)d12dev_GetDescriptorHandleIncrementSize;
    g_d12dev_vtbl[22] = (void*)d12dev_CreateFence;
    g_d12dev_vtbl[23] = (void*)d12dev_GetDeviceRemovedReason;
    g_d12dev_vtbl[27] = (void*)d12dev_CreateCommittedResource;
    g_d12dev_vtbl[28] = (void*)d12dev_CreateRenderTargetView;
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
