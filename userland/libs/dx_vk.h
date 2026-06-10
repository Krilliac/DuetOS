/*
 * userland/libs/dx_vk.h
 *
 * D3D11→Vulkan thunk back end (v0). Sits beside dx_shared.h; the
 * d3d11 DLL includes it as:
 *
 *   #include "../dx_shared.h"
 *   #include "../dx_vk.h"
 *
 * The DX DLLs are freestanding single-.c builds
 * (tools/build/build-stub-dll.sh) with no import table beyond the
 * kernel thunks — they cannot import vulkan-1.dll. This header
 * therefore issues SYS_VK_CALL (syscall 211) directly: the same
 * vk_syscallN inline-asm shapes as userland/libs/vulkan_1/
 * vulkan_1.c plus the VkOp subset the back end needs.
 *
 * Register convention (matches kernel/syscall/syscall_vk.cpp —
 * the authority): rax = 211, rdi = VkOp, and the per-op arguments
 * ride in rdx / r10 / r8 / r9. rsi is NOT read by any kernel
 * handler, so every call below passes 0 as the first payload arg.
 * (Several vulkan_1.c call sites put their first argument in rsi
 * instead — those entries are latently misaligned with the
 * kernel; do not copy their argument placement.)
 *
 * What the back end owns (one per process in v0):
 *   - instance → physical device → device → queue,
 *   - a non-scanout BGRA8 VkImage + host-visible memory mapped at
 *     `pixels` (the kernel-painted back buffer),
 *   - one command buffer (re-armed by Begin each frame),
 *   - a 64 KiB host-visible vertex staging buffer mapped at
 *     `vb_map`, cursor-bump allocated per frame.
 *
 * Frame model: the first ClearRenderTargetView of a frame opens
 * the command buffer; Clear / Draw record tape ops; Present (or a
 * CPU readback Map) ends + submits, after which the kernel
 * rasterizer has painted `pixels`.
 */

#ifndef DUETOS_DX_VK_H
#define DUETOS_DX_VK_H

#include "dx_shared.h"

/* ---------------------------------------------------------------- *
 * SYS_VK_CALL thunks (int 0x80, rax = 211)                          *
 * ---------------------------------------------------------------- */

static DX_NO_BUILTIN inline long long vk_syscall2(long long op, long long a1, long long a2)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)211), "D"(op), "S"(a1), "d"(a2) : "memory");
    return rv;
}

static DX_NO_BUILTIN inline long long vk_syscall3(long long op, long long a1, long long a2, long long a3)
{
    long long rv;
    register long long r10 __asm__("r10") = a3;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)211), "D"(op), "S"(a1), "d"(a2), "r"(r10) : "memory");
    return rv;
}

static DX_NO_BUILTIN inline long long vk_syscall4(long long op, long long a1, long long a2, long long a3, long long a4)
{
    long long rv;
    register long long r10 __asm__("r10") = a3;
    register long long r8 __asm__("r8") = a4;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)211), "D"(op), "S"(a1), "d"(a2), "r"(r10), "r"(r8)
                     : "memory");
    return rv;
}

static DX_NO_BUILTIN inline long long vk_syscall5(long long op, long long a1, long long a2, long long a3, long long a4,
                                                  long long a5)
{
    long long rv;
    register long long r10 __asm__("r10") = a3;
    register long long r8 __asm__("r8") = a4;
    register long long r9 __asm__("r9") = a5;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)211), "D"(op), "S"(a1), "d"(a2), "r"(r10), "r"(r8), "r"(r9)
                     : "memory");
    return rv;
}

/* VkOp subset — values must stay in sync with `enum VkOp` in
 * kernel/syscall/syscall.h (ABI: append-only, never renumber). */
enum
{
    DxVkOp_CreateInstance = 0,
    DxVkOp_DestroyInstance = 1,
    DxVkOp_EnumeratePhysicalDevices = 2,
    DxVkOp_CreateDevice = 3,
    DxVkOp_DestroyDevice = 4,
    DxVkOp_GetDeviceQueue = 5,
    DxVkOp_GetStatsCounter = 9,
    DxVkOp_AllocateMemory = 15,
    DxVkOp_FreeMemory = 16,
    DxVkOp_CreateBuffer = 17,
    DxVkOp_DestroyBuffer = 19,
    DxVkOp_BindBufferMemory = 20,
    DxVkOp_MapMemory = 21,
    DxVkOp_UnmapMemory = 22,
    DxVkOp_CreateImage = 23,
    DxVkOp_DestroyImage = 24,
    DxVkOp_BindImageMemory = 25,
    DxVkOp_CreateCommandPool = 26,
    DxVkOp_DestroyCommandPool = 27,
    DxVkOp_AllocateCommandBuffer = 28,
    DxVkOp_BeginCommandBuffer = 29,
    DxVkOp_EndCommandBuffer = 30,
    DxVkOp_CmdClearColorImage = 31,
    DxVkOp_QueueSubmit = 32,
    DxVkOp_CmdDraw = 41,
    DxVkOp_CmdBindVertexBuffer = 43,
    DxVkOp_FreeCommandBuffer = 52,
};

/* VkStatsCounter ids for DxVkOp_GetStatsCounter — same ABI file. */
enum
{
    DxVkStat_TrianglesDrawn = 8,
    DxVkStat_QueueSubmits = 9,
    DxVkStat_ImageClearPixels = 10,
};

/* Kernel software-rasterizer v0 vertex record (8 bytes): pixel
 * coordinates + packed 0xAARRGGBB. See graphics_vk_raster.cpp. */
typedef struct DxVkVertexV0
{
    short x_px;
    short y_px;
    DWORD argb;
} DxVkVertexV0;

#define DX_VK_VB_BYTES (64u * 1024u)

/* ---------------------------------------------------------------- *
 * Backend state + lifecycle                                         *
 * ---------------------------------------------------------------- */

typedef struct DxVkBackend
{
    UINT64 instance;
    UINT64 phys;
    UINT64 device;
    UINT64 queue;
    UINT64 image;     /* kernel back-buffer image (non-scanout BGRA8) */
    UINT64 image_mem; /* host-visible memory backing the image */
    UINT64 cmd_pool;
    UINT64 cmd_buf;
    UINT64 vb;     /* vertex staging buffer */
    UINT64 vb_mem; /* host-visible memory backing it */
    BYTE* pixels;  /* mapped image backing (width * height * 4) */
    BYTE* vb_map;  /* mapped vertex staging (DX_VK_VB_BYTES) */
    UINT vb_cursor;
    UINT width, height;
    int active;  /* full ladder is live */
    int cb_open; /* a frame's command buffer is recording */
} DxVkBackend;

static DX_NO_BUILTIN inline void dx_vk_backend_destroy(DxVkBackend* be)
{
    if (!be)
        return;
    /* Each step tolerates a 0 handle so a partially-built ladder
     * (create failed midway) tears down cleanly. */
    if (be->cmd_buf)
        (void)vk_syscall5(DxVkOp_FreeCommandBuffer, 0, (long long)be->device, (long long)be->cmd_pool,
                          (long long)be->cmd_buf, 0);
    if (be->cmd_pool)
        (void)vk_syscall3(DxVkOp_DestroyCommandPool, 0, (long long)be->device, (long long)be->cmd_pool);
    if (be->vb_map)
        (void)vk_syscall3(DxVkOp_UnmapMemory, 0, (long long)be->device, (long long)be->vb_mem);
    if (be->vb)
        (void)vk_syscall3(DxVkOp_DestroyBuffer, 0, (long long)be->device, (long long)be->vb);
    if (be->vb_mem)
        (void)vk_syscall3(DxVkOp_FreeMemory, 0, (long long)be->device, (long long)be->vb_mem);
    if (be->pixels)
        (void)vk_syscall3(DxVkOp_UnmapMemory, 0, (long long)be->device, (long long)be->image_mem);
    if (be->image)
        (void)vk_syscall3(DxVkOp_DestroyImage, 0, (long long)be->device, (long long)be->image);
    if (be->image_mem)
        (void)vk_syscall3(DxVkOp_FreeMemory, 0, (long long)be->device, (long long)be->image_mem);
    if (be->device)
        (void)vk_syscall2(DxVkOp_DestroyDevice, 0, (long long)be->device);
    if (be->instance)
        (void)vk_syscall2(DxVkOp_DestroyInstance, 0, (long long)be->instance);
    dx_memzero(be, sizeof(*be));
}

/* Build the full ladder for a w*h BGRA8 back buffer. Returns 1 and
 * sets be->active on success; returns 0 with the backend zeroed on
 * any failure (caller falls back to the software path). */
static DX_NO_BUILTIN inline int dx_vk_backend_create(DxVkBackend* be, UINT w, UINT h)
{
    if (!be || w == 0 || h == 0)
        return 0;
    dx_memzero(be, sizeof(*be));
    if (vk_syscall2(DxVkOp_CreateInstance, 0, (long long)(SIZE_T)&be->instance) != 1 || be->instance == 0)
        goto fail;
    {
        UINT32 count = 1;
        if (vk_syscall4(DxVkOp_EnumeratePhysicalDevices, 0, (long long)be->instance, (long long)(SIZE_T)&count,
                        (long long)(SIZE_T)&be->phys) != 1 ||
            count == 0 || be->phys == 0)
            goto fail;
    }
    if (vk_syscall3(DxVkOp_CreateDevice, 0, (long long)be->phys, (long long)(SIZE_T)&be->device) != 1 ||
        be->device == 0)
        goto fail;
    if (vk_syscall3(DxVkOp_GetDeviceQueue, 0, (long long)be->device, (long long)(SIZE_T)&be->queue) != 1 ||
        be->queue == 0)
        goto fail;
    be->image_mem =
        (UINT64)vk_syscall3(DxVkOp_AllocateMemory, 0, (long long)be->device, (long long)((UINT64)w * h * 4u));
    if (be->image_mem == 0)
        goto fail;
    /* flags = 0: the kernel masks the scanout flag from this path
     * anyway (userland must not mint whole-screen images). */
    be->image = (UINT64)vk_syscall5(DxVkOp_CreateImage, 0, (long long)be->device, (long long)w, (long long)h, 0);
    if (be->image == 0)
        goto fail;
    if (vk_syscall5(DxVkOp_BindImageMemory, 0, (long long)be->device, (long long)be->image, (long long)be->image_mem,
                    0) != 1)
        goto fail;
    be->pixels = (BYTE*)(SIZE_T)vk_syscall3(DxVkOp_MapMemory, 0, (long long)be->device, (long long)be->image_mem);
    if (!be->pixels)
        goto fail;
    be->cmd_pool = (UINT64)vk_syscall2(DxVkOp_CreateCommandPool, 0, (long long)be->device);
    if (be->cmd_pool == 0)
        goto fail;
    be->cmd_buf = (UINT64)vk_syscall3(DxVkOp_AllocateCommandBuffer, 0, (long long)be->device, (long long)be->cmd_pool);
    if (be->cmd_buf == 0)
        goto fail;
    be->vb_mem = (UINT64)vk_syscall3(DxVkOp_AllocateMemory, 0, (long long)be->device, (long long)DX_VK_VB_BYTES);
    if (be->vb_mem == 0)
        goto fail;
    be->vb = (UINT64)vk_syscall3(DxVkOp_CreateBuffer, 0, (long long)be->device, (long long)DX_VK_VB_BYTES);
    if (be->vb == 0)
        goto fail;
    if (vk_syscall5(DxVkOp_BindBufferMemory, 0, (long long)be->device, (long long)be->vb, (long long)be->vb_mem, 0) !=
        1)
        goto fail;
    be->vb_map = (BYTE*)(SIZE_T)vk_syscall3(DxVkOp_MapMemory, 0, (long long)be->device, (long long)be->vb_mem);
    if (!be->vb_map)
        goto fail;
    /* Match dx_bb_create's zero-filled starting contents. */
    dx_memzero(be->pixels, (SIZE_T)w * h * 4u);
    be->width = w;
    be->height = h;
    be->active = 1;
    return 1;
fail:
    dx_vk_backend_destroy(be);
    return 0;
}

/* ---------------------------------------------------------------- *
 * Per-frame recording                                               *
 * ---------------------------------------------------------------- */

/* Lazily open the frame's command buffer. The kernel's
 * VkBeginCommandBuffer re-arms a previously-submitted buffer
 * (state -> Recording, tape cursor -> 0), so one cb serves every
 * frame. Resets the vertex-staging cursor with it. */
static DX_NO_BUILTIN inline int dx_vk_frame_open(DxVkBackend* be)
{
    if (!be->active)
        return 0;
    if (be->cb_open)
        return 1;
    if (vk_syscall2(DxVkOp_BeginCommandBuffer, 0, (long long)be->cmd_buf) != 1)
        return 0;
    be->cb_open = 1;
    be->vb_cursor = 0;
    return 1;
}

/* Record a full-image clear (opens the frame if needed). */
static DX_NO_BUILTIN inline int dx_vk_record_clear(DxVkBackend* be, DWORD argb)
{
    if (!dx_vk_frame_open(be))
        return 0;
    return vk_syscall4(DxVkOp_CmdClearColorImage, 0, (long long)be->cmd_buf, (long long)be->image, (long long)argb) ==
           1;
}

/* Record one triangle-list draw covering `vertex_count` records
 * starting at byte `first_offset` of the staging buffer. */
static DX_NO_BUILTIN inline int dx_vk_record_draw(DxVkBackend* be, UINT first_offset, UINT vertex_count)
{
    if (!be->cb_open || vertex_count == 0)
        return 0;
    if (vk_syscall5(DxVkOp_CmdBindVertexBuffer, 0, (long long)be->cmd_buf, 0 /*binding*/, (long long)be->vb,
                    (long long)first_offset) != 1)
        return 0;
    /* r10 packs (vertex_count << 32) | first_vertex. first_vertex
     * stays 0 — the bind offset already addressed the records. */
    return vk_syscall3(DxVkOp_CmdDraw, 0, (long long)be->cmd_buf, (long long)(((UINT64)vertex_count << 32) | 0u)) == 1;
}

/* End + submit the open frame so the kernel rasterizer paints
 * `pixels`. Safe to call with no frame open (returns 1). */
static DX_NO_BUILTIN inline int dx_vk_flush(DxVkBackend* be)
{
    if (!be->active || !be->cb_open)
        return 1;
    be->cb_open = 0;
    if (vk_syscall2(DxVkOp_EndCommandBuffer, 0, (long long)be->cmd_buf) != 1)
        return 0;
    return vk_syscall3(DxVkOp_QueueSubmit, 0, (long long)be->queue, (long long)be->cmd_buf) == 1;
}

#endif /* DUETOS_DX_VK_H */
