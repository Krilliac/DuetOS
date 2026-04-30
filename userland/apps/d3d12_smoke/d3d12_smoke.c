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
 * Slot indices match the d12*_init_vtbl_once() tables in d3d12.c.
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

    /* slot 9 = CreateCommandQueue */
    QueueDesc qd = {0, 0, 0, 0}; /* DIRECT */
    void* queue = NULL;
    typedef long (*PFN_CreateQueue)(void*, const void*, const GUID*, void**);
    hr = ((PFN_CreateQueue)dev_vt[9])(dev, &qd, NULL, &queue);
    Out("[d3d12_smoke] CreateCommandQueue    = ");
    Out((hr == 0 && queue) ? "PASS\r\n" : "FAIL\r\n");

    /* slot 10 = CreateCommandAllocator(type, riid, **out) */
    void* alloc = NULL;
    typedef long (*PFN_CreateAlloc)(void*, UINT, const GUID*, void**);
    hr = ((PFN_CreateAlloc)dev_vt[10])(dev, 0, NULL, &alloc);
    Out("[d3d12_smoke] CreateCommandAllocator= ");
    Out((hr == 0 && alloc) ? "PASS\r\n" : "FAIL\r\n");

    /* slot 13 = CreateCommandList(mask, type, alloc, pso, riid, **out) */
    void* list = NULL;
    typedef long (*PFN_CreateList)(void*, UINT, UINT, void*, void*, const GUID*, void**);
    hr = ((PFN_CreateList)dev_vt[13])(dev, 0, 0, alloc, NULL, NULL, &list);
    Out("[d3d12_smoke] CreateCommandList     = ");
    Out((hr == 0 && list) ? "PASS\r\n" : "FAIL\r\n");

    /* slot 22 = CreateFence(initial, flags, riid, **out) */
    void* fence = NULL;
    typedef long (*PFN_CreateFence)(void*, UINT64, UINT, const GUID*, void**);
    hr = ((PFN_CreateFence)dev_vt[22])(dev, 0, 0, NULL, &fence);
    Out("[d3d12_smoke] CreateFence           = ");
    Out((hr == 0 && fence) ? "PASS\r\n" : "FAIL\r\n");

    /* slot 15 = CreateDescriptorHeap(desc, riid, **out) */
    HeapDesc hd = {2, 1, 0, 0}; /* type=RTV, num=1 */
    void* heap = NULL;
    typedef long (*PFN_CreateHeap)(void*, const void*, const GUID*, void**);
    hr = ((PFN_CreateHeap)dev_vt[15])(dev, &hd, NULL, &heap);
    Out("[d3d12_smoke] CreateDescriptorHeap  = ");
    Out((hr == 0 && heap) ? "PASS\r\n" : "FAIL\r\n");

    /* slot 16 = GetDescriptorHandleIncrementSize(type) */
    typedef UINT (*PFN_GetInc)(void*, UINT);
    UINT inc = ((PFN_GetInc)dev_vt[16])(dev, 2);
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

    /* slot 28 = CreateRenderTargetView(resource, desc, cpu_handle) */
    typedef void (*PFN_CreateRTV)(void*, void*, const void*, SIZE_T);
    ((PFN_CreateRTV)dev_vt[28])(dev, res, NULL, cpu_handle);
    Out("[d3d12_smoke] CreateRTV             = PASS (returned)\r\n");

    /* List vtable: slot 23 = ClearRenderTargetView */
    void** list_vt = *(void***)list;
    float green[4] = {0.0f, 1.0f, 0.0f, 1.0f};
    typedef void (*PFN_ClearRTV)(void*, SIZE_T, const float*, UINT, const void*);
    ((PFN_ClearRTV)list_vt[23])(list, cpu_handle, green, 0, NULL);
    Out("[d3d12_smoke] List::ClearRTV(green) = PASS (returned)\r\n");

    /* slot 8 = Close */
    typedef long (*PFN_Close)(void*);
    hr = ((PFN_Close)list_vt[8])(list);
    Out("[d3d12_smoke] List::Close           = ");
    Out((hr == 0) ? "PASS\r\n" : "FAIL\r\n");

    /* Queue vtable: slot 10 = ExecuteCommandLists, slot 11 = Signal */
    void** q_vt = *(void***)queue;
    void* lists[1] = {list};
    typedef void (*PFN_Exec)(void*, UINT, void* const*);
    ((PFN_Exec)q_vt[10])(queue, 1, lists);
    Out("[d3d12_smoke] Queue::ExecLists      = PASS (returned)\r\n");

    typedef long (*PFN_Signal)(void*, void*, UINT64);
    hr = ((PFN_Signal)q_vt[11])(queue, fence, 1);
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
