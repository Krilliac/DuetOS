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

/* MSVC PE link-time marker: any TU that touches floating-point
 * (vkCmdClearColorImage takes a float[4] color) must define
 * `_fltused` for the linker to be happy. */
__attribute__((used)) int _fltused = 0;

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

static DV_NO_BUILTIN inline long long vk_syscall5(long long op, long long a1, long long a2, long long a3, long long a4,
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
    VkOp_BindBufferMemory = 20,
    VkOp_MapMemory = 21,
    VkOp_UnmapMemory = 22,
    VkOp_CreateImage = 23,
    VkOp_DestroyImage = 24,
    VkOp_BindImageMemory = 25,
    VkOp_CreateCommandPool = 26,
    VkOp_DestroyCommandPool = 27,
    VkOp_AllocateCommandBuffer = 28,
    VkOp_BeginCommandBuffer = 29,
    VkOp_EndCommandBuffer = 30,
    VkOp_CmdClearColorImage = 31,
    VkOp_QueueSubmit = 32,
    VkOp_CreatePipelineLayout = 33,
    VkOp_DestroyPipelineLayout = 34,
    VkOp_CreateRenderPass = 35,
    VkOp_DestroyRenderPass = 36,
    VkOp_CreateGraphicsPipeline = 37,
    VkOp_CreateComputePipeline = 38,
    VkOp_DestroyPipeline = 39,
    VkOp_CmdBindPipeline = 40,
    VkOp_CmdDraw = 41,
    VkOp_CmdDispatch = 42,
    VkOp_CmdBindVertexBuffer = 43,
    VkOp_CmdBindIndexBuffer = 44,
    VkOp_UpdateDescriptorSet = 45,
    VkOp_CreateDescriptorSetLayout = 46,
    VkOp_DestroyDescriptorSetLayout = 47,
    VkOp_CreateDescriptorPool = 48,
    VkOp_DestroyDescriptorPool = 49,
    VkOp_AllocateDescriptorSet = 50,
    VkOp_CmdBindDescriptorSet = 51,
};

/* Additional Vulkan types we need for the create paths. */
typedef unsigned long long VkShaderModule;
typedef unsigned long long VkDeviceMemory;
typedef unsigned long long VkBuffer;
typedef unsigned long long VkImage;
typedef unsigned long long VkDeviceSize;
typedef unsigned long long VkCommandPool;
typedef unsigned long long VkCommandBuffer;
typedef unsigned long long VkPipelineLayout;
typedef unsigned long long VkRenderPass;
typedef unsigned long long VkPipeline;
typedef unsigned long long VkDescriptorSetLayout;
typedef unsigned long long VkDescriptorPool;
typedef unsigned long long VkDescriptorSet;

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
VkResult vkBindBufferMemory(VkDevice device, VkBuffer buffer, VkDeviceMemory memory, VkDeviceSize memoryOffset);
VkResult vkMapMemory(VkDevice device, VkDeviceMemory memory, VkDeviceSize offset, VkDeviceSize size, DWORD flags,
                     void** ppData);
void vkUnmapMemory(VkDevice device, VkDeviceMemory memory);
VkResult vkCreateImage(VkDevice device, const void* pCreateInfo, const void* pAllocator, VkImage* pImage);
void vkDestroyImage(VkDevice device, VkImage image, const void* pAllocator);
VkResult vkBindImageMemory(VkDevice device, VkImage image, VkDeviceMemory memory, VkDeviceSize memoryOffset);
VkResult vkCreateCommandPool(VkDevice device, const void* pCreateInfo, const void* pAllocator, VkCommandPool* pPool);
void vkDestroyCommandPool(VkDevice device, VkCommandPool pool, const void* pAllocator);
VkResult vkAllocateCommandBuffers(VkDevice device, const void* pAllocateInfo, VkCommandBuffer* pCommandBuffers);
VkResult vkBeginCommandBuffer(VkCommandBuffer cb, const void* pBeginInfo);
VkResult vkEndCommandBuffer(VkCommandBuffer cb);
void vkCmdClearColorImage(VkCommandBuffer cb, VkImage image, DWORD imageLayout, const void* pColor, UINT32 rangeCount,
                          const void* pRanges);
VkResult vkQueueSubmit(VkQueue queue, UINT32 submitCount, const void* pSubmits, UINT64 fence);
VkResult vkCreatePipelineLayout(VkDevice device, const void* pCreateInfo, const void* pAllocator,
                                VkPipelineLayout* pPipelineLayout);
void vkDestroyPipelineLayout(VkDevice device, VkPipelineLayout layout, const void* pAllocator);
VkResult vkCreateRenderPass(VkDevice device, const void* pCreateInfo, const void* pAllocator,
                            VkRenderPass* pRenderPass);
void vkDestroyRenderPass(VkDevice device, VkRenderPass renderPass, const void* pAllocator);
VkResult vkCreateGraphicsPipelines(VkDevice device, UINT64 pipelineCache, UINT32 createInfoCount,
                                   const void* pCreateInfos, const void* pAllocator, VkPipeline* pPipelines);
VkResult vkCreateComputePipelines(VkDevice device, UINT64 pipelineCache, UINT32 createInfoCount,
                                  const void* pCreateInfos, const void* pAllocator, VkPipeline* pPipelines);
void vkDestroyPipeline(VkDevice device, VkPipeline pipeline, const void* pAllocator);
void vkCmdBindPipeline(VkCommandBuffer cb, DWORD pipelineBindPoint, VkPipeline pipeline);
void vkCmdDraw(VkCommandBuffer cb, UINT32 vertexCount, UINT32 instanceCount, UINT32 firstVertex, UINT32 firstInstance);
void vkCmdDispatch(VkCommandBuffer cb, UINT32 groupCountX, UINT32 groupCountY, UINT32 groupCountZ);
void vkCmdBindVertexBuffers(VkCommandBuffer cb, UINT32 firstBinding, UINT32 bindingCount, const VkBuffer* pBuffers,
                            const UINT64* pOffsets);
void vkCmdBindIndexBuffer(VkCommandBuffer cb, VkBuffer buffer, UINT64 offset, DWORD indexType);
void vkUpdateDescriptorSets(VkDevice device, UINT32 writeCount, const void* pWrites, UINT32 copyCount,
                            const void* pCopies);
VkResult vkCreateDescriptorSetLayout(VkDevice device, const void* pCreateInfo, const void* pAllocator,
                                     VkDescriptorSetLayout* pSetLayout);
void vkDestroyDescriptorSetLayout(VkDevice device, VkDescriptorSetLayout layout, const void* pAllocator);
VkResult vkCreateDescriptorPool(VkDevice device, const void* pCreateInfo, const void* pAllocator,
                                VkDescriptorPool* pDescriptorPool);
void vkDestroyDescriptorPool(VkDevice device, VkDescriptorPool pool, const void* pAllocator);
VkResult vkAllocateDescriptorSets(VkDevice device, const void* pAllocateInfo, VkDescriptorSet* pDescriptorSets);
void vkCmdBindDescriptorSets(VkCommandBuffer cb, DWORD pipelineBindPoint, VkPipelineLayout layout, UINT32 firstSet,
                             UINT32 descriptorSetCount, const VkDescriptorSet* pDescriptorSets,
                             UINT32 dynamicOffsetCount, const UINT32* pDynamicOffsets);

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
    if (dv_streq(pName, "vkBindBufferMemory"))
        return (PFN_vkVoidFunction)vkBindBufferMemory;
    if (dv_streq(pName, "vkMapMemory"))
        return (PFN_vkVoidFunction)vkMapMemory;
    if (dv_streq(pName, "vkUnmapMemory"))
        return (PFN_vkVoidFunction)vkUnmapMemory;
    if (dv_streq(pName, "vkCreateImage"))
        return (PFN_vkVoidFunction)vkCreateImage;
    if (dv_streq(pName, "vkDestroyImage"))
        return (PFN_vkVoidFunction)vkDestroyImage;
    if (dv_streq(pName, "vkBindImageMemory"))
        return (PFN_vkVoidFunction)vkBindImageMemory;
    if (dv_streq(pName, "vkCreateCommandPool"))
        return (PFN_vkVoidFunction)vkCreateCommandPool;
    if (dv_streq(pName, "vkDestroyCommandPool"))
        return (PFN_vkVoidFunction)vkDestroyCommandPool;
    if (dv_streq(pName, "vkAllocateCommandBuffers"))
        return (PFN_vkVoidFunction)vkAllocateCommandBuffers;
    if (dv_streq(pName, "vkBeginCommandBuffer"))
        return (PFN_vkVoidFunction)vkBeginCommandBuffer;
    if (dv_streq(pName, "vkEndCommandBuffer"))
        return (PFN_vkVoidFunction)vkEndCommandBuffer;
    if (dv_streq(pName, "vkCmdClearColorImage"))
        return (PFN_vkVoidFunction)vkCmdClearColorImage;
    if (dv_streq(pName, "vkQueueSubmit"))
        return (PFN_vkVoidFunction)vkQueueSubmit;
    if (dv_streq(pName, "vkCreatePipelineLayout"))
        return (PFN_vkVoidFunction)vkCreatePipelineLayout;
    if (dv_streq(pName, "vkDestroyPipelineLayout"))
        return (PFN_vkVoidFunction)vkDestroyPipelineLayout;
    if (dv_streq(pName, "vkCreateRenderPass"))
        return (PFN_vkVoidFunction)vkCreateRenderPass;
    if (dv_streq(pName, "vkDestroyRenderPass"))
        return (PFN_vkVoidFunction)vkDestroyRenderPass;
    if (dv_streq(pName, "vkCreateGraphicsPipelines"))
        return (PFN_vkVoidFunction)vkCreateGraphicsPipelines;
    if (dv_streq(pName, "vkCreateComputePipelines"))
        return (PFN_vkVoidFunction)vkCreateComputePipelines;
    if (dv_streq(pName, "vkDestroyPipeline"))
        return (PFN_vkVoidFunction)vkDestroyPipeline;
    if (dv_streq(pName, "vkCmdBindPipeline"))
        return (PFN_vkVoidFunction)vkCmdBindPipeline;
    if (dv_streq(pName, "vkCmdDraw"))
        return (PFN_vkVoidFunction)vkCmdDraw;
    if (dv_streq(pName, "vkCmdDispatch"))
        return (PFN_vkVoidFunction)vkCmdDispatch;
    if (dv_streq(pName, "vkCmdBindVertexBuffers"))
        return (PFN_vkVoidFunction)vkCmdBindVertexBuffers;
    if (dv_streq(pName, "vkCmdBindIndexBuffer"))
        return (PFN_vkVoidFunction)vkCmdBindIndexBuffer;
    if (dv_streq(pName, "vkUpdateDescriptorSets"))
        return (PFN_vkVoidFunction)vkUpdateDescriptorSets;
    if (dv_streq(pName, "vkCreateDescriptorSetLayout"))
        return (PFN_vkVoidFunction)vkCreateDescriptorSetLayout;
    if (dv_streq(pName, "vkDestroyDescriptorSetLayout"))
        return (PFN_vkVoidFunction)vkDestroyDescriptorSetLayout;
    if (dv_streq(pName, "vkCreateDescriptorPool"))
        return (PFN_vkVoidFunction)vkCreateDescriptorPool;
    if (dv_streq(pName, "vkDestroyDescriptorPool"))
        return (PFN_vkVoidFunction)vkDestroyDescriptorPool;
    if (dv_streq(pName, "vkAllocateDescriptorSets"))
        return (PFN_vkVoidFunction)vkAllocateDescriptorSets;
    if (dv_streq(pName, "vkCmdBindDescriptorSets"))
        return (PFN_vkVoidFunction)vkCmdBindDescriptorSets;
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
    const long long h =
        vk_syscall4(VkOp_CreateShaderModule, (long long)device, (long long)(SIZE_T)code, (long long)code_size, 0);
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

VkResult vkBindBufferMemory(VkDevice device, VkBuffer buffer, VkDeviceMemory memory, VkDeviceSize memoryOffset)
{
    const long long ok = vk_syscall5(VkOp_BindBufferMemory, 0, (long long)device, (long long)buffer, (long long)memory,
                                     (long long)memoryOffset);
    return (ok == 1) ? VK_SUCCESS : VK_ERROR_INITIALIZATION_FAILED;
}

VkResult vkMapMemory(VkDevice device, VkDeviceMemory memory, VkDeviceSize offset, VkDeviceSize size, DWORD flags,
                     void** ppData)
{
    (void)offset;
    (void)size;
    (void)flags;
    if (ppData == NULL)
        return VK_ERROR_INITIALIZATION_FAILED;
    const long long p = vk_syscall3(VkOp_MapMemory, 0, (long long)device, (long long)memory);
    if (p == 0)
        return VK_ERROR_INITIALIZATION_FAILED;
    *ppData = (void*)(SIZE_T)p;
    return VK_SUCCESS;
}

void vkUnmapMemory(VkDevice device, VkDeviceMemory memory)
{
    (void)vk_syscall3(VkOp_UnmapMemory, 0, (long long)device, (long long)memory);
}

/* vkCreateImage — pCreateInfo VkImageCreateInfo: imageType at
 * offset 24, format at offset 28, extent (3 uints) at offset 32,
 * mipLevels at offset 44, arrayLayers at offset 48, samples at
 * offset 52, tiling at offset 56, usage at offset 60. v0 only
 * looks at extent.width / extent.height; everything else falls
 * back to ICD defaults (2D, BGRA8, 1 mip, 1 layer, 1x sample). */
VkResult vkCreateImage(VkDevice device, const void* pCreateInfo, const void* pAllocator, VkImage* pImage)
{
    (void)pAllocator;
    if (pCreateInfo == NULL || pImage == NULL)
        return VK_ERROR_INITIALIZATION_FAILED;
    const BYTE* ci = (const BYTE*)pCreateInfo;
    const UINT32 width = *(const UINT32*)(ci + 32);
    const UINT32 height = *(const UINT32*)(ci + 36);
    const long long h = vk_syscall5(VkOp_CreateImage, 0, (long long)device, (long long)width, (long long)height, 0);
    if (h == 0)
        return VK_ERROR_INITIALIZATION_FAILED;
    *pImage = (VkImage)h;
    return VK_SUCCESS;
}

void vkDestroyImage(VkDevice device, VkImage image, const void* pAllocator)
{
    (void)pAllocator;
    (void)vk_syscall3(VkOp_DestroyImage, 0, (long long)device, (long long)image);
}

VkResult vkBindImageMemory(VkDevice device, VkImage image, VkDeviceMemory memory, VkDeviceSize memoryOffset)
{
    const long long ok = vk_syscall5(VkOp_BindImageMemory, 0, (long long)device, (long long)image, (long long)memory,
                                     (long long)memoryOffset);
    return (ok == 1) ? VK_SUCCESS : VK_ERROR_INITIALIZATION_FAILED;
}

/* Command pool / buffer / submit ladder. */

VkResult vkCreateCommandPool(VkDevice device, const void* pCreateInfo, const void* pAllocator, VkCommandPool* pPool)
{
    (void)pCreateInfo;
    (void)pAllocator;
    if (pPool == NULL)
        return VK_ERROR_INITIALIZATION_FAILED;
    const long long h = vk_syscall1(VkOp_CreateCommandPool, (long long)device);
    if (h == 0)
        return VK_ERROR_INITIALIZATION_FAILED;
    *pPool = (VkCommandPool)h;
    return VK_SUCCESS;
}

void vkDestroyCommandPool(VkDevice device, VkCommandPool pool, const void* pAllocator)
{
    (void)pAllocator;
    (void)vk_syscall3(VkOp_DestroyCommandPool, 0, (long long)device, (long long)pool);
}

/* vkAllocateCommandBuffers — pAllocateInfo VkCommandBufferAllocateInfo:
 * commandPool at offset 16, commandBufferCount at offset 28.
 * v0 honors only the first one (returns one VkCommandBuffer). */
VkResult vkAllocateCommandBuffers(VkDevice device, const void* pAllocateInfo, VkCommandBuffer* pCommandBuffers)
{
    if (pAllocateInfo == NULL || pCommandBuffers == NULL)
        return VK_ERROR_INITIALIZATION_FAILED;
    const BYTE* ai = (const BYTE*)pAllocateInfo;
    const VkCommandPool pool = *(const VkCommandPool*)(ai + 16);
    const UINT32 count = *(const UINT32*)(ai + 28);
    const UINT32 n = (count == 0) ? 1u : count;
    for (UINT32 i = 0; i < n; ++i)
    {
        const long long h = vk_syscall3(VkOp_AllocateCommandBuffer, 0, (long long)device, (long long)pool);
        if (h == 0)
            return VK_ERROR_INITIALIZATION_FAILED;
        pCommandBuffers[i] = (VkCommandBuffer)h;
    }
    return VK_SUCCESS;
}

VkResult vkBeginCommandBuffer(VkCommandBuffer cb, const void* pBeginInfo)
{
    (void)pBeginInfo;
    const long long ok = vk_syscall1(VkOp_BeginCommandBuffer, (long long)cb);
    return (ok == 1) ? VK_SUCCESS : VK_ERROR_INITIALIZATION_FAILED;
}

VkResult vkEndCommandBuffer(VkCommandBuffer cb)
{
    const long long ok = vk_syscall1(VkOp_EndCommandBuffer, (long long)cb);
    return (ok == 1) ? VK_SUCCESS : VK_ERROR_INITIALIZATION_FAILED;
}

/* vkCmdClearColorImage — VkClearColorValue is a union; v0 takes
 * the float32[4] components, scales to 0..255, and packs ARGB. */
void vkCmdClearColorImage(VkCommandBuffer cb, VkImage image, DWORD /*VkImageLayout*/ imageLayout, const void* pColor,
                          UINT32 rangeCount, const void* pRanges)
{
    (void)imageLayout;
    (void)rangeCount;
    (void)pRanges;
    if (pColor == NULL)
        return;
    const float* color = (const float*)pColor;
    /* clamp + pack */
    UINT32 argb = 0;
    for (int i = 0; i < 4; ++i)
    {
        float c = color[i];
        if (c < 0.f)
            c = 0.f;
        else if (c > 1.f)
            c = 1.f;
        UINT32 q = (UINT32)(c * 255.f);
        if (q > 255)
            q = 255;
        /* Order: R G B A -> shift positions 16 8 0 24 */
        const int sh = (i == 0) ? 16 : (i == 1) ? 8 : (i == 2) ? 0 : 24;
        argb |= (q << sh);
    }
    (void)vk_syscall4(VkOp_CmdClearColorImage, (long long)cb, (long long)image, (long long)argb, 0);
}

VkResult vkQueueSubmit(VkQueue queue, UINT32 submitCount, const void* pSubmits, UINT64 fence)
{
    (void)submitCount;
    (void)pSubmits;
    (void)fence;
    /* v0 single-cmd-buffer path: pSubmits is a VkSubmitInfo with
     * pCommandBuffers at offset 32 + commandBufferCount at offset 24.
     * We honor the first command buffer of the first submit. */
    if (pSubmits == NULL)
        return VK_ERROR_INITIALIZATION_FAILED;
    const BYTE* s = (const BYTE*)pSubmits;
    const VkCommandBuffer* cbs = *(const VkCommandBuffer* const*)(s + 32);
    if (cbs == NULL)
        return VK_ERROR_INITIALIZATION_FAILED;
    const long long ok = vk_syscall3(VkOp_QueueSubmit, 0, (long long)queue, (long long)cbs[0]);
    return (ok == 1) ? VK_SUCCESS : VK_ERROR_INITIALIZATION_FAILED;
}

/* Pipeline / render pass / draw. v0 ignores most of the
 * pCreateInfo fields — only the handles in the per-op signature
 * are honoured (descriptor set layouts, render pass attachments,
 * shader stages, vertex input descriptions). The pipeline-layout
 * + render-pass + pipeline handles still flow through so a real
 * Vulkan PE's create chain compiles cleanly. */

VkResult vkCreatePipelineLayout(VkDevice device, const void* pCreateInfo, const void* pAllocator,
                                VkPipelineLayout* pPipelineLayout)
{
    (void)pCreateInfo;
    (void)pAllocator;
    if (pPipelineLayout == NULL)
        return VK_ERROR_INITIALIZATION_FAILED;
    const long long h = vk_syscall1(VkOp_CreatePipelineLayout, (long long)device);
    if (h == 0)
        return VK_ERROR_INITIALIZATION_FAILED;
    *pPipelineLayout = (VkPipelineLayout)h;
    return VK_SUCCESS;
}

void vkDestroyPipelineLayout(VkDevice device, VkPipelineLayout layout, const void* pAllocator)
{
    (void)pAllocator;
    (void)vk_syscall3(VkOp_DestroyPipelineLayout, 0, (long long)device, (long long)layout);
}

VkResult vkCreateRenderPass(VkDevice device, const void* pCreateInfo, const void* pAllocator, VkRenderPass* pRenderPass)
{
    (void)pCreateInfo;
    (void)pAllocator;
    if (pRenderPass == NULL)
        return VK_ERROR_INITIALIZATION_FAILED;
    const long long h = vk_syscall1(VkOp_CreateRenderPass, (long long)device);
    if (h == 0)
        return VK_ERROR_INITIALIZATION_FAILED;
    *pRenderPass = (VkRenderPass)h;
    return VK_SUCCESS;
}

void vkDestroyRenderPass(VkDevice device, VkRenderPass renderPass, const void* pAllocator)
{
    (void)pAllocator;
    (void)vk_syscall3(VkOp_DestroyRenderPass, 0, (long long)device, (long long)renderPass);
}

/* vkCreateGraphicsPipelines — v0 takes the first VkGraphicsPipelineCreateInfo
 * out of the array and pulls VS/FS shader modules from its
 * pStages[] array (VkPipelineShaderStageCreateInfo: module at
 * offset 24, stage at offset 12 — 0x01=VS, 0x10=FS). */
VkResult vkCreateGraphicsPipelines(VkDevice device, UINT64 pipelineCache, UINT32 createInfoCount,
                                   const void* pCreateInfos, const void* pAllocator, VkPipeline* pPipelines)
{
    (void)pipelineCache;
    (void)pAllocator;
    if (pCreateInfos == NULL || pPipelines == NULL || createInfoCount == 0)
        return VK_ERROR_INITIALIZATION_FAILED;
    const BYTE* ci = (const BYTE*)pCreateInfos;
    /* VkGraphicsPipelineCreateInfo: stageCount at offset 20, pStages at 24,
     * ..., layout at offset 0x88 (136 — Vulkan spec layout). */
    const UINT32 stage_count = *(const UINT32*)(ci + 20);
    const void* const* p_stages = *(const void* const* const*)(ci + 24);
    const VkPipelineLayout layout = *(const VkPipelineLayout*)(ci + 0x88);
    VkShaderModule vs = 0, fs = 0;
    if (p_stages != NULL)
    {
        for (UINT32 i = 0; i < stage_count; ++i)
        {
            const BYTE* st = (const BYTE*)p_stages[i];
            if (st == NULL)
                continue;
            const UINT32 stage_bits = *(const UINT32*)(st + 12);
            const VkShaderModule m = *(const VkShaderModule*)(st + 24);
            if (stage_bits == 0x01)
                vs = m; // VERTEX
            else if (stage_bits == 0x10)
                fs = m; // FRAGMENT
        }
    }
    const long long h =
        vk_syscall5(VkOp_CreateGraphicsPipeline, 0, (long long)device, (long long)layout, (long long)vs, (long long)fs);
    if (h == 0)
        return VK_ERROR_INITIALIZATION_FAILED;
    pPipelines[0] = (VkPipeline)h;
    /* v0 only creates one pipeline per call — extra entries get
     * 0 so the caller sees the create failed for those. */
    for (UINT32 i = 1; i < createInfoCount; ++i)
        pPipelines[i] = 0;
    return VK_SUCCESS;
}

VkResult vkCreateComputePipelines(VkDevice device, UINT64 pipelineCache, UINT32 createInfoCount,
                                  const void* pCreateInfos, const void* pAllocator, VkPipeline* pPipelines)
{
    (void)pipelineCache;
    (void)pAllocator;
    if (pCreateInfos == NULL || pPipelines == NULL || createInfoCount == 0)
        return VK_ERROR_INITIALIZATION_FAILED;
    /* VkComputePipelineCreateInfo: stage at offset 16 (inline VkPipelineShaderStageCreateInfo),
     * layout at offset 96.  Stage's module at offset (16 + 24) = 40. */
    const BYTE* ci = (const BYTE*)pCreateInfos;
    const VkShaderModule cs = *(const VkShaderModule*)(ci + 40);
    const VkPipelineLayout layout = *(const VkPipelineLayout*)(ci + 96);
    const long long h = vk_syscall4(VkOp_CreateComputePipeline, (long long)device, (long long)layout, (long long)cs, 0);
    if (h == 0)
        return VK_ERROR_INITIALIZATION_FAILED;
    pPipelines[0] = (VkPipeline)h;
    for (UINT32 i = 1; i < createInfoCount; ++i)
        pPipelines[i] = 0;
    return VK_SUCCESS;
}

void vkDestroyPipeline(VkDevice device, VkPipeline pipeline, const void* pAllocator)
{
    (void)pAllocator;
    (void)vk_syscall3(VkOp_DestroyPipeline, 0, (long long)device, (long long)pipeline);
}

void vkCmdBindPipeline(VkCommandBuffer cb, DWORD pipelineBindPoint, VkPipeline pipeline)
{
    (void)pipelineBindPoint;
    (void)vk_syscall3(VkOp_CmdBindPipeline, 0, (long long)cb, (long long)pipeline);
}

void vkCmdDraw(VkCommandBuffer cb, UINT32 vertexCount, UINT32 instanceCount, UINT32 firstVertex, UINT32 firstInstance)
{
    (void)instanceCount;
    (void)firstInstance;
    const long long packed = ((long long)vertexCount << 32) | (long long)firstVertex;
    (void)vk_syscall3(VkOp_CmdDraw, 0, (long long)cb, packed);
}

void vkCmdDispatch(VkCommandBuffer cb, UINT32 groupCountX, UINT32 groupCountY, UINT32 groupCountZ)
{
    (void)vk_syscall5(VkOp_CmdDispatch, 0, (long long)cb, (long long)groupCountX, (long long)groupCountY,
                      (long long)groupCountZ);
}

/* vkCmdBindVertexBuffers — bind a single buffer at firstBinding;
 * multi-binding callers go via the standard Vulkan API but only
 * the first binding+buffer gets through the v0 thunk. */
void vkCmdBindVertexBuffers(VkCommandBuffer cb, UINT32 firstBinding, UINT32 bindingCount, const VkBuffer* pBuffers,
                            const UINT64* pOffsets)
{
    if (bindingCount == 0 || pBuffers == NULL)
        return;
    const UINT64 offset = (pOffsets != NULL) ? pOffsets[0] : 0u;
    (void)vk_syscall5(VkOp_CmdBindVertexBuffer, 0, (long long)cb, (long long)firstBinding, (long long)pBuffers[0],
                      (long long)offset);
}

void vkCmdBindIndexBuffer(VkCommandBuffer cb, VkBuffer buffer, UINT64 offset, DWORD indexType)
{
    (void)vk_syscall5(VkOp_CmdBindIndexBuffer, 0, (long long)cb, (long long)buffer, (long long)offset,
                      (long long)indexType);
}

/* vkUpdateDescriptorSets — multi-write API; v0 walks the array
 * and forwards one Update per entry. VkWriteDescriptorSet:
 *   dstSet at offset 16, dstBinding at 24, descriptorType at 36,
 *   pImageInfo at 40 (8-byte ptr), pBufferInfo at 48.
 * v0 supports image-info (CombinedImageSampler) — extract the
 * image-view from pImageInfo->imageView (at offset 8 of
 * VkDescriptorImageInfo). */
void vkUpdateDescriptorSets(VkDevice device, UINT32 writeCount, const void* pWrites, UINT32 copyCount,
                            const void* pCopies)
{
    (void)device;
    (void)copyCount;
    (void)pCopies;
    if (pWrites == NULL)
        return;
    const BYTE* w = (const BYTE*)pWrites;
    for (UINT32 i = 0; i < writeCount; ++i)
    {
        const BYTE* this_w = w + i * 64u; /* VkWriteDescriptorSet is 64 bytes */
        const VkDescriptorSet set = *(const VkDescriptorSet*)(this_w + 16);
        const UINT32 binding = *(const UINT32*)(this_w + 24);
        const UINT32 type = *(const UINT32*)(this_w + 36);
        const void* p_image = *(const void* const*)(this_w + 40);
        UINT64 handle = 0;
        if (p_image != NULL)
        {
            /* VkDescriptorImageInfo: sampler at offset 0, imageView at offset 8, imageLayout at offset 16 */
            handle = *(const UINT64*)((const BYTE*)p_image + 8);
        }
        (void)vk_syscall5(VkOp_UpdateDescriptorSet, 0, (long long)set, (long long)binding, (long long)type,
                          (long long)handle);
    }
}

VkResult vkCreateDescriptorSetLayout(VkDevice device, const void* pCreateInfo, const void* pAllocator,
                                     VkDescriptorSetLayout* pSetLayout)
{
    (void)pCreateInfo;
    (void)pAllocator;
    if (pSetLayout == NULL)
        return VK_ERROR_INITIALIZATION_FAILED;
    const long long h = vk_syscall1(VkOp_CreateDescriptorSetLayout, (long long)device);
    if (h == 0)
        return VK_ERROR_INITIALIZATION_FAILED;
    *pSetLayout = (VkDescriptorSetLayout)h;
    return VK_SUCCESS;
}

void vkDestroyDescriptorSetLayout(VkDevice device, VkDescriptorSetLayout layout, const void* pAllocator)
{
    (void)pAllocator;
    (void)vk_syscall3(VkOp_DestroyDescriptorSetLayout, 0, (long long)device, (long long)layout);
}

/* vkCreateDescriptorPool — maxSets at offset 24 in VkDescriptorPoolCreateInfo. */
VkResult vkCreateDescriptorPool(VkDevice device, const void* pCreateInfo, const void* pAllocator,
                                VkDescriptorPool* pDescriptorPool)
{
    (void)pAllocator;
    if (pCreateInfo == NULL || pDescriptorPool == NULL)
        return VK_ERROR_INITIALIZATION_FAILED;
    const BYTE* ci = (const BYTE*)pCreateInfo;
    const UINT32 max_sets = *(const UINT32*)(ci + 24);
    const long long h = vk_syscall3(VkOp_CreateDescriptorPool, 0, (long long)device, (long long)max_sets);
    if (h == 0)
        return VK_ERROR_INITIALIZATION_FAILED;
    *pDescriptorPool = (VkDescriptorPool)h;
    return VK_SUCCESS;
}

void vkDestroyDescriptorPool(VkDevice device, VkDescriptorPool pool, const void* pAllocator)
{
    (void)pAllocator;
    (void)vk_syscall3(VkOp_DestroyDescriptorPool, 0, (long long)device, (long long)pool);
}

/* vkAllocateDescriptorSets — VkDescriptorSetAllocateInfo:
 *   descriptorPool at offset 16, descriptorSetCount at offset 24,
 *   pSetLayouts (pointer to VkDescriptorSetLayout[]) at offset 32.
 * v0 honors only the first layout / set. */
VkResult vkAllocateDescriptorSets(VkDevice device, const void* pAllocateInfo, VkDescriptorSet* pDescriptorSets)
{
    if (pAllocateInfo == NULL || pDescriptorSets == NULL)
        return VK_ERROR_INITIALIZATION_FAILED;
    const BYTE* ai = (const BYTE*)pAllocateInfo;
    const VkDescriptorPool pool = *(const VkDescriptorPool*)(ai + 16);
    const VkDescriptorSetLayout* layouts = *(const VkDescriptorSetLayout* const*)(ai + 32);
    if (layouts == NULL)
        return VK_ERROR_INITIALIZATION_FAILED;
    const long long h =
        vk_syscall4(VkOp_AllocateDescriptorSet, (long long)device, (long long)pool, (long long)layouts[0], 0);
    if (h == 0)
        return VK_ERROR_INITIALIZATION_FAILED;
    pDescriptorSets[0] = (VkDescriptorSet)h;
    return VK_SUCCESS;
}

/* vkCmdBindDescriptorSets — bind one set at firstSet to the
 * matching pipeline layout. dynamic offsets not honored in v0. */
void vkCmdBindDescriptorSets(VkCommandBuffer cb, DWORD pipelineBindPoint, VkPipelineLayout layout, UINT32 firstSet,
                             UINT32 descriptorSetCount, const VkDescriptorSet* pDescriptorSets,
                             UINT32 dynamicOffsetCount, const UINT32* pDynamicOffsets)
{
    (void)pipelineBindPoint;
    (void)dynamicOffsetCount;
    (void)pDynamicOffsets;
    if (descriptorSetCount == 0 || pDescriptorSets == NULL)
        return;
    (void)vk_syscall5(VkOp_CmdBindDescriptorSet, 0, (long long)cb, (long long)layout, (long long)firstSet,
                      (long long)pDescriptorSets[0]);
}
