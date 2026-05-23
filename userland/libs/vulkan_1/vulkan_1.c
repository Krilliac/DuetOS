/*
 * userland/libs/vulkan_1/vulkan_1.c — DuetOS vulkan-1.dll v0.
 *
 * Win32 PE binaries that depend on Vulkan import their entries
 * from `vulkan-1.dll`. This DLL provides those exports as thin
 * thunks over `SYS_VK_CALL` (syscall 211) into the in-kernel
 * Vulkan ICD (see `kernel/subsystems/graphics/graphics_vk.cpp`).
 *
 * v0 scope — the trivial bind set:
 *   - vkCreateInstance / vkDestroyInstance
 *   - vkEnumeratePhysicalDevices
 *   - vkCreateDevice / vkDestroyDevice
 *   - vkGetDeviceQueue
 *   - vkDeviceWaitIdle / vkQueueWaitIdle
 *   - vkEnumerateInstanceVersion
 *   - vkGetInstanceProcAddr (string -> function-pointer table)
 *   - vkGetDeviceProcAddr   (same lookup, gated by device)
 *
 * Out of scope for v0 (return VK_ERROR_INITIALIZATION_FAILED so
 * a caller's `if (result != VK_SUCCESS) return;` early-exit
 * works cleanly):
 *   - vkCreateBuffer / vkAllocateMemory / vkBindBufferMemory and
 *     friends — need user-mappable shared memory.
 *   - vkCreateImage / vkBindImageMemory.
 *   - Command buffer record + submit.
 *   - Swapchain / surface / WSI.
 *   - SPIR-V module create — needs to copy the word stream in.
 *
 * Build: tools/build/build-stub-dll.sh with the 6th arg set to
 * `vulkan-1` so the embedded DLL file name uses the canonical
 * Windows dash form. The source dir / .c basename stay
 * `vulkan_1` because the build script's bash expansions don't
 * tolerate dashes.
 */

/* ---------------------------------------------------------------- *
 * Minimal Win32 / Vulkan type aliases                              *
 * ---------------------------------------------------------------- */

typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned int DWORD;
typedef unsigned int UINT32;
typedef unsigned long long UINT64;
typedef unsigned long long SIZE_T;
typedef int INT;
typedef int BOOL;

#ifndef NULL
#define NULL ((void*)0)
#endif

/* VkResult — canonical Vulkan return codes used by the v0 surface. */
typedef int VkResult;
#define VK_SUCCESS 0
#define VK_NOT_READY 1
#define VK_ERROR_INITIALIZATION_FAILED (-3)
#define VK_ERROR_OUT_OF_HOST_MEMORY (-1)

/* Handles are 64-bit dispatchable per Vulkan spec; we use the same
 * id values the kernel ICD hands out, so a userland VkInstance is a
 * direct alias of the kernel-side u64 handle. */
typedef unsigned long long VkInstance;
typedef unsigned long long VkPhysicalDevice;
typedef unsigned long long VkDevice;
typedef unsigned long long VkQueue;

/* ---------------------------------------------------------------- *
 * SYS_VK_CALL syscall thunk (int 0x80)                             *
 *                                                                  *
 * Linux-like calling convention used across the DuetOS userland    *
 * DLLs: syscall number in `rax`, args in rdi/rsi/rdx/r10/r8.       *
 * Returns the kernel-set rax. SYS_VK_CALL is 211; the op-code in   *
 * rdi selects which Vulkan entry the kernel forwards to.           *
 * ---------------------------------------------------------------- */

#define DV_NO_BUILTIN __attribute__((no_builtin("memset", "memcpy", "memcmp", "memmove")))

static DV_NO_BUILTIN inline long long vk_syscall1(long long op, long long a1)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)211), "D"(op), "S"(a1) : "memory");
    return rv;
}

static DV_NO_BUILTIN inline long long vk_syscall2(long long op, long long a1, long long a2)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)211), "D"(op), "S"(a1), "d"(a2) : "memory");
    return rv;
}

static DV_NO_BUILTIN inline long long vk_syscall3(long long op, long long a1, long long a2, long long a3)
{
    long long rv;
    register long long r10 __asm__("r10") = a3;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)211), "D"(op), "S"(a1), "d"(a2), "r"(r10) : "memory");
    return rv;
}

static DV_NO_BUILTIN inline long long vk_syscall4(long long op, long long a1, long long a2, long long a3, long long a4)
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

/* SYS_VK_CALL op-codes — must stay in sync with VkOp in
 * kernel/syscall/syscall.h. */
enum
{
    VkOp_CreateInstance = 0,
    VkOp_DestroyInstance = 1,
    VkOp_EnumeratePhysicalDevices = 2,
    VkOp_CreateDevice = 3,
    VkOp_DestroyDevice = 4,
    VkOp_GetDeviceQueue = 5,
    VkOp_DeviceWaitIdle = 6,
    VkOp_QueueWaitIdle = 7,
    VkOp_GetInstanceVersion = 8,
    VkOp_GetStatsCounter = 9,
    VkOp_ClearFramebufferRgba = 10,
    VkOp_CreateSurfaceDuet = 11,
    VkOp_DestroySurface = 12,
    VkOp_Present = 13,
    VkOp_CreateShaderModule = 14,
    VkOp_AllocateMemory = 15,
    VkOp_FreeMemory = 16,
    VkOp_CreateBuffer = 17,
    VkOp_DestroyShaderModule = 18,
    VkOp_DestroyBuffer = 19,
};

/* Additional Vulkan types we need for the create paths. */
typedef unsigned long long VkShaderModule;
typedef unsigned long long VkDeviceMemory;
typedef unsigned long long VkBuffer;

/* ---------------------------------------------------------------- *
 * Vulkan entry points                                              *
 * ---------------------------------------------------------------- */

/* vkEnumerateInstanceVersion — Vulkan 1.1+ entry that returns the
 * implementation's supported API version as a packed u32
 * (variant << 29 | major << 22 | minor << 12 | patch). */
VkResult vkEnumerateInstanceVersion(UINT32* pApiVersion)
{
    const long long ok = vk_syscall1(VkOp_GetInstanceVersion, (long long)(SIZE_T)pApiVersion);
    return (ok == 1) ? VK_SUCCESS : VK_ERROR_INITIALIZATION_FAILED;
}

/* The Vulkan `VkInstanceCreateInfo` struct is a tagged union with
 * a pNext chain. For v0 we ignore both — the kernel ICD has no
 * extensions to negotiate and the instance is a no-arg create. */
VkResult vkCreateInstance(const void* pCreateInfo, const void* pAllocator, VkInstance* pInstance)
{
    (void)pCreateInfo;
    (void)pAllocator;
    if (pInstance == NULL)
        return VK_ERROR_INITIALIZATION_FAILED;
    const long long ok = vk_syscall2(VkOp_CreateInstance, 0, (long long)(SIZE_T)pInstance);
    return (ok == 1) ? VK_SUCCESS : VK_ERROR_INITIALIZATION_FAILED;
}

void vkDestroyInstance(VkInstance instance, const void* pAllocator)
{
    (void)pAllocator;
    (void)vk_syscall2(VkOp_DestroyInstance, 0, (long long)instance);
}

VkResult vkEnumeratePhysicalDevices(VkInstance instance, UINT32* pPhysicalDeviceCount,
                                    VkPhysicalDevice* pPhysicalDevices)
{
    if (pPhysicalDeviceCount == NULL)
        return VK_ERROR_INITIALIZATION_FAILED;
    const long long ok = vk_syscall4(VkOp_EnumeratePhysicalDevices, (long long)instance,
                                     (long long)(SIZE_T)pPhysicalDeviceCount, (long long)(SIZE_T)pPhysicalDevices, 0);
    return (ok == 1) ? VK_SUCCESS : VK_ERROR_INITIALIZATION_FAILED;
}

VkResult vkCreateDevice(VkPhysicalDevice physicalDevice, const void* pCreateInfo, const void* pAllocator,
                        VkDevice* pDevice)
{
    (void)pCreateInfo;
    (void)pAllocator;
    if (pDevice == NULL)
        return VK_ERROR_INITIALIZATION_FAILED;
    const long long ok = vk_syscall3(VkOp_CreateDevice, (long long)physicalDevice, (long long)(SIZE_T)pDevice, 0);
    return (ok == 1) ? VK_SUCCESS : VK_ERROR_INITIALIZATION_FAILED;
}

void vkDestroyDevice(VkDevice device, const void* pAllocator)
{
    (void)pAllocator;
    (void)vk_syscall2(VkOp_DestroyDevice, 0, (long long)device);
}

void vkGetDeviceQueue(VkDevice device, UINT32 queueFamilyIndex, UINT32 queueIndex, VkQueue* pQueue)
{
    (void)queueFamilyIndex;
    (void)queueIndex;
    if (pQueue == NULL)
        return;
    (void)vk_syscall3(VkOp_GetDeviceQueue, (long long)device, (long long)(SIZE_T)pQueue, 0);
}

VkResult vkDeviceWaitIdle(VkDevice device)
{
    const long long ok = vk_syscall1(VkOp_DeviceWaitIdle, (long long)device);
    return (ok == 1) ? VK_SUCCESS : VK_ERROR_INITIALIZATION_FAILED;
}

VkResult vkQueueWaitIdle(VkQueue queue)
{
    const long long ok = vk_syscall1(VkOp_QueueWaitIdle, (long long)queue);
    return (ok == 1) ? VK_SUCCESS : VK_ERROR_INITIALIZATION_FAILED;
}

/* ---------------------------------------------------------------- *
 * vkGetInstanceProcAddr / vkGetDeviceProcAddr — string lookup.     *
 *                                                                  *
 * The Vulkan spec's preferred entry-point lookup. Returns a        *
 * function pointer to any Vulkan call by name; lets a caller       *
 * dlopen vulkan-1.dll, fetch one well-known entry by name, then    *
 * walk the rest indirectly. We match against the v0 set; unknown   *
 * names return NULL.                                               *
 * ---------------------------------------------------------------- */

typedef void (*PFN_vkVoidFunction)(void);

/* Forward declarations for the resource-create functions defined
 * after vkGetInstanceProcAddr — needed because the string-lookup
 * table refers to them by symbol. */
VkResult vkCreateShaderModule(VkDevice device, const void* pCreateInfo, const void* pAllocator,
                              VkShaderModule* pShaderModule);
void vkDestroyShaderModule(VkDevice device, VkShaderModule module, const void* pAllocator);
VkResult vkAllocateMemory(VkDevice device, const void* pAllocateInfo, const void* pAllocator, VkDeviceMemory* pMemory);
void vkFreeMemory(VkDevice device, VkDeviceMemory memory, const void* pAllocator);
VkResult vkCreateBuffer(VkDevice device, const void* pCreateInfo, const void* pAllocator, VkBuffer* pBuffer);
void vkDestroyBuffer(VkDevice device, VkBuffer buffer, const void* pAllocator);

static DV_NO_BUILTIN inline int dv_streq(const char* a, const char* b)
{
    if (a == NULL || b == NULL)
        return 0;
    while (*a != '\0' && *a == *b)
    {
        ++a;
        ++b;
    }
    return (*a == '\0') && (*b == '\0');
}

PFN_vkVoidFunction vkGetInstanceProcAddr(VkInstance instance, const char* pName)
{
    (void)instance;
    if (pName == NULL)
        return NULL;
    if (dv_streq(pName, "vkCreateInstance"))
        return (PFN_vkVoidFunction)vkCreateInstance;
    if (dv_streq(pName, "vkDestroyInstance"))
        return (PFN_vkVoidFunction)vkDestroyInstance;
    if (dv_streq(pName, "vkEnumeratePhysicalDevices"))
        return (PFN_vkVoidFunction)vkEnumeratePhysicalDevices;
    if (dv_streq(pName, "vkCreateDevice"))
        return (PFN_vkVoidFunction)vkCreateDevice;
    if (dv_streq(pName, "vkDestroyDevice"))
        return (PFN_vkVoidFunction)vkDestroyDevice;
    if (dv_streq(pName, "vkGetDeviceQueue"))
        return (PFN_vkVoidFunction)vkGetDeviceQueue;
    if (dv_streq(pName, "vkDeviceWaitIdle"))
        return (PFN_vkVoidFunction)vkDeviceWaitIdle;
    if (dv_streq(pName, "vkQueueWaitIdle"))
        return (PFN_vkVoidFunction)vkQueueWaitIdle;
    if (dv_streq(pName, "vkEnumerateInstanceVersion"))
        return (PFN_vkVoidFunction)vkEnumerateInstanceVersion;
    if (dv_streq(pName, "vkGetInstanceProcAddr"))
        return (PFN_vkVoidFunction)vkGetInstanceProcAddr;
    if (dv_streq(pName, "vkGetDeviceProcAddr"))
        return (PFN_vkVoidFunction)vkGetInstanceProcAddr; /* same table for v0 */
    if (dv_streq(pName, "vkCreateShaderModule"))
        return (PFN_vkVoidFunction)vkCreateShaderModule;
    if (dv_streq(pName, "vkDestroyShaderModule"))
        return (PFN_vkVoidFunction)vkDestroyShaderModule;
    if (dv_streq(pName, "vkAllocateMemory"))
        return (PFN_vkVoidFunction)vkAllocateMemory;
    if (dv_streq(pName, "vkFreeMemory"))
        return (PFN_vkVoidFunction)vkFreeMemory;
    if (dv_streq(pName, "vkCreateBuffer"))
        return (PFN_vkVoidFunction)vkCreateBuffer;
    if (dv_streq(pName, "vkDestroyBuffer"))
        return (PFN_vkVoidFunction)vkDestroyBuffer;
    return NULL;
}

PFN_vkVoidFunction vkGetDeviceProcAddr(VkDevice device, const char* pName)
{
    (void)device;
    return vkGetInstanceProcAddr(0, pName);
}

/* DuetOS-only diagnostic accessor: read one Vulkan stats counter
 * by id. Mirrors the kernel-side VkStatsCounter enum. Useful for
 * a userland smoke test to verify the syscall path is alive. */
UINT64 DuetOS_Vk_GetStatsCounter(UINT32 counter_id)
{
    return (UINT64)vk_syscall1(VkOp_GetStatsCounter, (long long)counter_id);
}

/* DuetOS-only proof-of-concept thunk: clear the framebuffer to
 * a packed 0xAARRGGBB color via the Vulkan ICD's same path that
 * vkCmdClearColorImage takes for scanout-backed images. Lets
 * d3d11's ClearRenderTargetView route through Vulkan without
 * building the full Instance->Device->CmdBuf->Submit ladder.
 * Returns 1 on success, 0 if the framebuffer is unavailable. */
INT DuetOS_Vk_ClearFramebufferRgba(DWORD argb)
{
    return (INT)vk_syscall1(VkOp_ClearFramebufferRgba, (long long)argb);
}

/* DuetOS-only WSI v0 thunks. The full vkCreateSwapchainKHR /
 * vkAcquireNextImageKHR / vkQueuePresentKHR ladder needs
 * shared-memory marshalling that v0 SYS_VK_CALL doesn't cover;
 * for now the simpler "create a Duet-flavoured surface + flush
 * the framebuffer" pair lets a Vulkan PE drive the compositor
 * presentation path without building the full ladder. */

/* Create a DuetOS Vulkan surface — the single platform-agnostic
 * surface bound to the kernel framebuffer (see Vulkan-ICD wiki's
 * WSI section). Returns 1 on success and writes the VkSurfaceKHR
 * handle to *pSurfaceOut. */
INT DuetOS_Vk_CreateSurface(VkInstance instance, UINT64* pSurfaceOut)
{
    if (pSurfaceOut == NULL)
        return 0;
    return (INT)vk_syscall3(VkOp_CreateSurfaceDuet, 0, (long long)instance, (long long)(SIZE_T)pSurfaceOut);
}

void DuetOS_Vk_DestroySurface(VkInstance instance, UINT64 surface)
{
    (void)vk_syscall3(VkOp_DestroySurface, 0, (long long)instance, (long long)surface);
}

/* Flush whatever's currently in the framebuffer through the
 * compositor present hook. Equivalent to vkQueuePresentKHR on a
 * single-image swapchain. */
INT DuetOS_Vk_Present(void)
{
    return (INT)vk_syscall1(VkOp_Present, 0);
}

/* ---------------------------------------------------------------- *
 * Resource create / destroy thunks                                 *
 * ---------------------------------------------------------------- */

/* vkCreateShaderModule — copy the SPIR-V word stream in via a
 * syscall argument; the kernel ICD takes its own copy and parses
 * for the v1 interpreter. Returns VK_SUCCESS / a Vulkan error. */
VkResult vkCreateShaderModule(VkDevice device, const void* pCreateInfo, const void* pAllocator,
                              VkShaderModule* pShaderModule)
{
    (void)pAllocator;
    if (pCreateInfo == NULL || pShaderModule == NULL)
        return VK_ERROR_INITIALIZATION_FAILED;
    /* VkShaderModuleCreateInfo layout: sType(4), pNext(8 — pointer
     * pad), flags(4), codeSize(8 — SIZE_T), pCode(8 — pointer).
     * We pull the codeSize + pCode by hand to avoid pulling in the
     * full Vulkan headers.
     *
     *   offset 0:  VkStructureType sType
     *   offset 4:  padding (alignment to pNext)
     *   offset 8:  const void* pNext
     *   offset 16: VkShaderModuleCreateFlags flags
     *   offset 24: size_t codeSize
     *   offset 32: const u32* pCode
     */
    const BYTE* ci = (const BYTE*)pCreateInfo;
    const SIZE_T code_size = *(const SIZE_T*)(ci + 24);
    const void* code = *(const void* const*)(ci + 32);
    const long long h = vk_syscall4(VkOp_CreateShaderModule, (long long)device, (long long)(SIZE_T)code,
                                    (long long)code_size, 0);
    if (h == 0)
        return VK_ERROR_INITIALIZATION_FAILED;
    *pShaderModule = (VkShaderModule)h;
    return VK_SUCCESS;
}

void vkDestroyShaderModule(VkDevice device, VkShaderModule module, const void* pAllocator)
{
    (void)pAllocator;
    (void)vk_syscall3(VkOp_DestroyShaderModule, 0, (long long)device, (long long)module);
}

/* vkAllocateMemory — fixed memory type 1 (host-visible coherent
 * in the v0 ICD). pAllocateInfo's allocationSize is at offset 16
 * in VkMemoryAllocateInfo. */
VkResult vkAllocateMemory(VkDevice device, const void* pAllocateInfo, const void* pAllocator, VkDeviceMemory* pMemory)
{
    (void)pAllocator;
    if (pAllocateInfo == NULL || pMemory == NULL)
        return VK_ERROR_INITIALIZATION_FAILED;
    const BYTE* ai = (const BYTE*)pAllocateInfo;
    const UINT64 size = *(const UINT64*)(ai + 16);
    const long long h = vk_syscall3(VkOp_AllocateMemory, (long long)device, (long long)size, 0);
    if (h == 0)
        return VK_ERROR_OUT_OF_HOST_MEMORY;
    *pMemory = (VkDeviceMemory)h;
    return VK_SUCCESS;
}

void vkFreeMemory(VkDevice device, VkDeviceMemory memory, const void* pAllocator)
{
    (void)pAllocator;
    (void)vk_syscall3(VkOp_FreeMemory, 0, (long long)device, (long long)memory);
}

/* vkCreateBuffer — pCreateInfo VkBufferCreateInfo: size at offset 24. */
VkResult vkCreateBuffer(VkDevice device, const void* pCreateInfo, const void* pAllocator, VkBuffer* pBuffer)
{
    (void)pAllocator;
    if (pCreateInfo == NULL || pBuffer == NULL)
        return VK_ERROR_INITIALIZATION_FAILED;
    const BYTE* ci = (const BYTE*)pCreateInfo;
    const UINT64 size = *(const UINT64*)(ci + 24);
    const long long h = vk_syscall3(VkOp_CreateBuffer, (long long)device, (long long)size, 0);
    if (h == 0)
        return VK_ERROR_INITIALIZATION_FAILED;
    *pBuffer = (VkBuffer)h;
    return VK_SUCCESS;
}

void vkDestroyBuffer(VkDevice device, VkBuffer buffer, const void* pAllocator)
{
    (void)pAllocator;
    (void)vk_syscall3(VkOp_DestroyBuffer, 0, (long long)device, (long long)buffer);
}
