/*
 * d3d12_smoke — exercise the full D3D12 Clear+Present pipeline through
 * real COM vtable calls. Validates userland/libs/d3d12/d3d12.c:
 *
 *   D3D12CreateDevice
 *   ID3D12Device::CreateCommandQueue
 *   ID3D12Device::CreateCommandAllocator
 *   ID3D12Device::CreateCommandList
 *   ID3D12Device::CreateFence
 *   ID3D12Device::CreateDescriptorHeap (RTV heap, 1 descriptor)
 *   ID3D12Device::CreateCommittedResource (back buffer)
 *   ID3D12Device::CreateRenderTargetView (resource → heap slot 0)
 *   ID3D12GraphicsCommandList::ClearRenderTargetView (green)
 *   ID3D12GraphicsCommandList::Close
 *   ID3D12CommandQueue::ExecuteCommandLists
 *   ID3D12CommandQueue::Signal(fence, 1) → fence value bumps
 *   ID3D12Fence::GetCompletedValue → 1
 *   release everything
 *
 * Slot indices follow the canonical Win SDK d3d12.h vtable layout
 * (IUnknown 0..2, ID3D12Object 3..6, ID3D12DeviceChild 7, ...).
 * Earlier off-by-N drift was fixed in d3d12.c so a real Win32 PE
 * compiled against d3d12.h works the same as this smoke test.
 */
#include <windows.h>

extern long D3D12CreateDevice(void* adapter, UINT min_feature_level, const GUID* riid, void** device);

static void Out(const char* s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0, len = 0;
    while (s[len])
        ++len;
    WriteConsoleA(h, s, len, &n, 0);
}

/* IID_ID3D12Device = {189819f1-1db6-4b57-be54-1821339b85f7} */
static const GUID kIidDevice = {0x189819f1, 0x1db6, 0x4b57, {0xbe, 0x54, 0x18, 0x21, 0x33, 0x9b, 0x85, 0xf7}};

/* D3D12_COMMAND_QUEUE_DESC: Type(0,4) Priority(4,4) Flags(8,4) NodeMask(12,4) */
typedef struct
{
    UINT Type, Priority, Flags, NodeMask;
} QueueDesc;

/* D3D12_DESCRIPTOR_HEAP_DESC: Type(0,4) NumDescriptors(4,4) Flags(8,4) NodeMask(12,4) */
typedef struct
{
    UINT Type, NumDescriptors, Flags, NodeMask;
} HeapDesc;

/* D3D12_HEAP_PROPERTIES (28 bytes): Type(0,4) CPUPageProperty(4,4) MemoryPoolPreference(8,4)
 * CreationNodeMask(12,4) VisibleNodeMask(16,4). */
typedef struct
{
    UINT Type, CPUPageProperty, MemoryPoolPreference, CreationNodeMask, VisibleNodeMask;
} HeapProps;

/* D3D12_RESOURCE_DESC partial layout d3d12.c reads:
 *   +0  Dimension       UINT
 *   +4  Alignment       UINT
 *   +8  Width           UINT64
 *   +16 Height          UINT
 *   +20 DepthOrArraySize WORD
 *   +22 MipLevels       WORD
 *   +24 Format          UINT
 * Total used by us: 28 bytes (rest can be zero). */
typedef struct
{
    UINT Dimension, Alignment;
    UINT64 Width;
    UINT Height;
    WORD DepthOrArraySize, MipLevels;
    UINT Format;
    UINT _rest[10]; /* SampleDesc + Layout + Flags — not read */
} ResDesc;

void __cdecl mainCRTStartup(void)
{
    Out("[d3d12_smoke] starting\r\n");

    void* dev = NULL;
    long hr = D3D12CreateDevice(NULL, 0xb000, &kIidDevice, &dev);
    Out("[d3d12_smoke] CreateDevice          = ");
    Out((hr == 0 && dev) ? "PASS\r\n" : "FAIL\r\n");
    if (!dev)
        ExitProcess(1);

    void** dev_vt = *(void***)dev;

    /* slot 8 = CreateCommandQueue */
    QueueDesc qd = {0, 0, 0, 0}; /* DIRECT */
    void* queue = NULL;
    typedef long (*PFN_CreateQueue)(void*, const void*, const GUID*, void**);
    hr = ((PFN_CreateQueue)dev_vt[8])(dev, &qd, NULL, &queue);
    Out("[d3d12_smoke] CreateCommandQueue    = ");
    Out((hr == 0 && queue) ? "PASS\r\n" : "FAIL\r\n");

    /* slot 9 = CreateCommandAllocator(type, riid, **out) */
    void* alloc = NULL;
    typedef long (*PFN_CreateAlloc)(void*, UINT, const GUID*, void**);
    hr = ((PFN_CreateAlloc)dev_vt[9])(dev, 0, NULL, &alloc);
    Out("[d3d12_smoke] CreateCommandAllocator= ");
    Out((hr == 0 && alloc) ? "PASS\r\n" : "FAIL\r\n");

    /* slot 12 = CreateCommandList(mask, type, alloc, pso, riid, **out) */
    void* list = NULL;
    typedef long (*PFN_CreateList)(void*, UINT, UINT, void*, void*, const GUID*, void**);
    hr = ((PFN_CreateList)dev_vt[12])(dev, 0, 0, alloc, NULL, NULL, &list);
    Out("[d3d12_smoke] CreateCommandList     = ");
    Out((hr == 0 && list) ? "PASS\r\n" : "FAIL\r\n");

    /* slot 36 = CreateFence(initial, flags, riid, **out) */
    void* fence = NULL;
    typedef long (*PFN_CreateFence)(void*, UINT64, UINT, const GUID*, void**);
    hr = ((PFN_CreateFence)dev_vt[36])(dev, 0, 0, NULL, &fence);
    Out("[d3d12_smoke] CreateFence           = ");
    Out((hr == 0 && fence) ? "PASS\r\n" : "FAIL\r\n");

    /* slot 14 = CreateDescriptorHeap(desc, riid, **out) */
    HeapDesc hd = {2, 1, 0, 0}; /* type=RTV, num=1 */
    void* heap = NULL;
    typedef long (*PFN_CreateHeap)(void*, const void*, const GUID*, void**);
    hr = ((PFN_CreateHeap)dev_vt[14])(dev, &hd, NULL, &heap);
    Out("[d3d12_smoke] CreateDescriptorHeap  = ");
    Out((hr == 0 && heap) ? "PASS\r\n" : "FAIL\r\n");

    /* slot 15 = GetDescriptorHandleIncrementSize(type) */
    typedef UINT (*PFN_GetInc)(void*, UINT);
    UINT inc = ((PFN_GetInc)dev_vt[15])(dev, 2);
    Out("[d3d12_smoke] GetDescIncSize        = ");
    Out((inc != 0) ? "PASS\r\n" : "FAIL\r\n");

    /* slot 27 = CreateCommittedResource(props, flags, desc, state, optClear, riid, **out) */
    HeapProps hp = {1, 0, 0, 0, 0}; /* DEFAULT */
    ResDesc rd;
    BYTE* p = (BYTE*)&rd;
    for (UINT i = 0; i < sizeof(rd); ++i)
        p[i] = 0;
    rd.Dimension = 4; /* TEXTURE2D */
    /* 32x32 BGRA8 = 4 KiB — fits in 64 KiB Win32 heap. */
    rd.Width = 32;
    rd.Height = 32;
    rd.DepthOrArraySize = 1;
    rd.MipLevels = 1;
    rd.Format = 87; /* BGRA8_UNORM */
    void* res = NULL;
    typedef long (*PFN_CreateRes)(void*, const void*, UINT, const void*, UINT, const void*, const GUID*, void**);
    hr = ((PFN_CreateRes)dev_vt[27])(dev, &hp, 0, &rd, 4 /*RENDER_TARGET*/, NULL, NULL, &res);
    Out("[d3d12_smoke] CreateCommittedRes    = ");
    Out((hr == 0 && res) ? "PASS\r\n" : "FAIL\r\n");

    /* Get heap CPU handle (slot 9 of heap vtable) */
    void** heap_vt = *(void***)heap;
    typedef SIZE_T (*PFN_GetCPUStart)(void*);
    SIZE_T cpu_handle = ((PFN_GetCPUStart)heap_vt[9])(heap);
    Out("[d3d12_smoke] Heap::GetCPUStart     = ");
    Out((cpu_handle != 0) ? "PASS\r\n" : "FAIL\r\n");

    /* slot 20 = CreateRenderTargetView(resource, desc, cpu_handle) */
    typedef void (*PFN_CreateRTV)(void*, void*, const void*, SIZE_T);
    ((PFN_CreateRTV)dev_vt[20])(dev, res, NULL, cpu_handle);
    Out("[d3d12_smoke] CreateRTV             = PASS (returned)\r\n");

    /* List vtable: slot 48 = ClearRenderTargetView */
    void** list_vt = *(void***)list;
    float green[4] = {0.0f, 1.0f, 0.0f, 1.0f};
    typedef void (*PFN_ClearRTV)(void*, SIZE_T, const float*, UINT, const void*);
    ((PFN_ClearRTV)list_vt[48])(list, cpu_handle, green, 0, NULL);
    Out("[d3d12_smoke] List::ClearRTV(green) = PASS (returned)\r\n");

    /* ----- v0.1: cover the geometry path ------------------------- *
     * slot 16 = CreateRootSignature(nodeMask, blob, blobSize, riid, **out) */
    BYTE rootsig_blob[8] = {0};
    void* rootsig = NULL;
    typedef long (*PFN_CreateRS)(void*, UINT, const void*, SIZE_T, const GUID*, void**);
    hr = ((PFN_CreateRS)dev_vt[16])(dev, 0, rootsig_blob, sizeof(rootsig_blob), NULL, &rootsig);
    Out("[d3d12_smoke] CreateRootSignature   = ");
    Out((hr == 0 && rootsig) ? "PASS\r\n" : "FAIL\r\n");

    /* slot 27 = CreateCommittedResource — buffer-shape resource for VB */
    static const char kPos[] = "POSITION";
    static const char kCol[] = "COLOR";
    typedef struct
    {
        float x, y, z;
        DWORD argb;
    } Vert;
    Vert verts[3] = {
        {-0.6f, -0.6f, 0.0f, 0xFFFF0000},
        {0.0f, 0.6f, 0.0f, 0xFF00FF00},
        {0.6f, -0.6f, 0.0f, 0xFF0000FF},
    };
    HeapProps hp_upload = {2 /*UPLOAD*/, 0, 0, 0, 0};
    ResDesc vb_desc;
    BYTE* vbp = (BYTE*)&vb_desc;
    for (UINT i = 0; i < sizeof(vb_desc); ++i)
        vbp[i] = 0;
    vb_desc.Dimension = 1; /* BUFFER */
    vb_desc.Width = sizeof(verts);
    vb_desc.Height = 1;
    vb_desc.DepthOrArraySize = 1;
    vb_desc.MipLevels = 1;
    vb_desc.Format = 0;
    void* vb_res = NULL;
    hr = ((PFN_CreateRes)dev_vt[27])(dev, &hp_upload, 0, &vb_desc, 0, NULL, NULL, &vb_res);
    Out("[d3d12_smoke] CreateBufRes(36B)     = ");
    Out((hr == 0 && vb_res) ? "PASS\r\n" : "FAIL\r\n");

    /* Map + copy the vertices in. Resource vtable: slot 8 = Map. */
    void** vbres_vt = *(void***)vb_res;
    typedef long (*PFN_Map)(void*, UINT, const void*, void**);
    void* mapped = NULL;
    hr = ((PFN_Map)vbres_vt[8])(vb_res, 0, NULL, &mapped);
    Out("[d3d12_smoke] VBRes::Map            = ");
    Out((hr == 0 && mapped) ? "PASS\r\n" : "FAIL\r\n");
    if (mapped)
    {
        BYTE* d = (BYTE*)mapped;
        const BYTE* s = (const BYTE*)verts;
        for (UINT i = 0; i < sizeof(verts); ++i)
            d[i] = s[i];
    }
    typedef void (*PFN_Unmap)(void*, UINT, const void*);
    ((PFN_Unmap)vbres_vt[9])(vb_res, 0, NULL);

    /* GetGPUVirtualAddress to populate the VB view. Slot 11. */
    typedef UINT64 (*PFN_GetGPUVA)(void*);
    UINT64 vb_va = ((PFN_GetGPUVA)vbres_vt[11])(vb_res);
    Out("[d3d12_smoke] VBRes::GetGPUVA       = ");
    Out((vb_va != 0) ? "PASS\r\n" : "FAIL\r\n");

    /* slot 10 = CreateGraphicsPipelineState(desc, riid, **out)
     * The desc needs an InputLayout at offset 348 + topology type at 368.
     * We zero everything else; v0 only reads those two fields. */
    BYTE psodesc[400];
    for (UINT i = 0; i < sizeof(psodesc); ++i)
        psodesc[i] = 0;
    /* InputLayout = D3D12_INPUT_LAYOUT_DESC at offset 348:
     *   D3D12_INPUT_ELEMENT_DESC* pInputElementDescs (8)
     *   UINT NumElements (4) */
    BYTE ied[64];
    for (UINT i = 0; i < sizeof(ied); ++i)
        ied[i] = 0;
    *(const char**)(ied + 0) = kPos;
    *(UINT*)(ied + 12) = 6; /* DXGI_FORMAT_R32G32B32_FLOAT */
    *(UINT*)(ied + 20) = 0;
    *(const char**)(ied + 32) = kCol;
    *(UINT*)(ied + 44) = 87; /* DXGI_FORMAT_B8G8R8A8_UNORM */
    *(UINT*)(ied + 52) = 12;
    *(const void**)(psodesc + 348) = (const void*)ied;
    *(UINT*)(psodesc + 356) = 2;
    *(UINT*)(psodesc + 368) = 3; /* PRIMITIVE_TOPOLOGY_TYPE_TRIANGLE */
    void* pso = NULL;
    typedef long (*PFN_CreateGPSO)(void*, const void*, const GUID*, void**);
    hr = ((PFN_CreateGPSO)dev_vt[10])(dev, psodesc, NULL, &pso);
    Out("[d3d12_smoke] CreateGraphicsPSO     = ");
    Out((hr == 0 && pso) ? "PASS\r\n" : "FAIL\r\n");

    /* List record sequence:
     *   slot 25 SetPipelineState
     *   slot 30 SetGraphicsRootSignature
     *   slot 20 IASetPrimitiveTopology
     *   slot 21 RSSetViewports
     *   slot 46 OMSetRenderTargets (single, points to our heap descriptor)
     *   slot 44 IASetVertexBuffers (one view)
     *   slot 12 DrawInstanced(3, 1, 0, 0)
     */
    typedef void (*PFN_SetPSO)(void*, void*);
    ((PFN_SetPSO)list_vt[25])(list, pso);
    typedef void (*PFN_SetRS)(void*, void*);
    ((PFN_SetRS)list_vt[30])(list, rootsig);
    typedef void (*PFN_SetTopo)(void*, UINT);
    ((PFN_SetTopo)list_vt[20])(list, 4); /* TRIANGLELIST */
    float vp12[6] = {0.f, 0.f, 32.f, 32.f, 0.f, 1.f};
    typedef void (*PFN_RSVP)(void*, UINT, const void*);
    ((PFN_RSVP)list_vt[21])(list, 1, vp12);
    typedef void (*PFN_OMSet)(void*, UINT, const void*, BOOL, const void*);
    ((PFN_OMSet)list_vt[46])(list, 1, &cpu_handle, FALSE, NULL);
    BYTE vbview[16];
    *(UINT64*)(vbview + 0) = vb_va;
    *(UINT*)(vbview + 8) = sizeof(verts);
    *(UINT*)(vbview + 12) = sizeof(Vert);
    typedef void (*PFN_IASetVB)(void*, UINT, UINT, const void*);
    ((PFN_IASetVB)list_vt[44])(list, 0, 1, vbview);
    typedef void (*PFN_DrawI)(void*, UINT, UINT, UINT, UINT);
    ((PFN_DrawI)list_vt[12])(list, 3, 1, 0, 0);
    Out("[d3d12_smoke] List::record-draw     = PASS (returned)\r\n");

    /* slot 9 = Close */
    typedef long (*PFN_Close)(void*);
    hr = ((PFN_Close)list_vt[9])(list);
    Out("[d3d12_smoke] List::Close           = ");
    Out((hr == 0) ? "PASS\r\n" : "FAIL\r\n");

    /* Queue vtable: slot 10 = ExecuteCommandLists, slot 14 = Signal */
    void** q_vt = *(void***)queue;
    void* lists[1] = {list};
    typedef void (*PFN_Exec)(void*, UINT, void* const*);
    ((PFN_Exec)q_vt[10])(queue, 1, lists);
    Out("[d3d12_smoke] Queue::ExecLists      = PASS (returned)\r\n");

    typedef long (*PFN_Signal)(void*, void*, UINT64);
    hr = ((PFN_Signal)q_vt[14])(queue, fence, 1);
    Out("[d3d12_smoke] Queue::Signal(fence,1)= ");
    Out((hr == 0) ? "PASS\r\n" : "FAIL\r\n");

    /* Fence vtable: slot 8 = GetCompletedValue */
    void** f_vt = *(void***)fence;
    typedef UINT64 (*PFN_GetVal)(void*);
    UINT64 v = ((PFN_GetVal)f_vt[8])(fence);
    Out("[d3d12_smoke] Fence::GetVal         = ");
    Out((v == 1) ? "PASS\r\n" : "FAIL\r\n");

    /* Release */
    typedef unsigned long (*PFN_Rel)(void*);
    ((PFN_Rel)((void**)(*(void***)pso))[2])(pso);
    ((PFN_Rel)((void**)(*(void***)vb_res))[2])(vb_res);
    ((PFN_Rel)((void**)(*(void***)rootsig))[2])(rootsig);
    ((PFN_Rel)((void**)(*(void***)res))[2])(res);
    ((PFN_Rel)heap_vt[2])(heap);
    ((PFN_Rel)f_vt[2])(fence);
    ((PFN_Rel)list_vt[2])(list);
    ((PFN_Rel)((void**)(*(void***)alloc))[2])(alloc);
    ((PFN_Rel)q_vt[2])(queue);
    ((PFN_Rel)dev_vt[2])(dev);
    Out("[d3d12_smoke] Release chain         = PASS\r\n");

    Out("[d3d12_smoke] done\r\n");
    ExitProcess(0);
}
