#pragma once

#include "util/types.h"

/*
 * DuetOS — Graphics subsystem, v0.
 *
 * The native Vulkan ICD implements a CPU-side lifecycle for the
 * full Vulkan 1.3 happy path: Instance/Device creation succeeds,
 * physical-device queries return properties sourced from
 * `drivers/video/display_info::Query()`, command buffers record a
 * tape of opcodes that `VkQueueSubmit` replays, descriptor sets
 * pin resources for shaders that don't yet exist, and
 * `vkQueuePresentKHR` flushes the framebuffer through the
 * compositor's damage rect.  vkCmdClearColorImage is the one
 * tape opcode that produces visible output today — when the
 * image was created with the kImageScanoutBacked flag (which is
 * automatic for swapchain images), the submit forwards the
 * clear to `FramebufferFillRect`; otherwise the op is recorded
 * for stats and discarded.  No GPU command-ring submission, no
 * SPIR-V execution.  SPIR-V modules are validated (magic word)
 * + parsed (entry-point / capability / decoration counts via
 * `VkGetShaderModuleInfoDuet`).
 *
 * Where the pieces live in the final system:
 *
 *     userland application            (d3d / vulkan / opengl caller)
 *              |
 *              |  vulkan / d3d11 / d3d12 / opengl entry points
 *              v
 *     subsystems/graphics/ (kernel today, user-mode later)
 *              |
 *              |  command submission via kernel gate
 *              v
 *     kernel/drivers/gpu/<vendor>/  (drivers/gpu/gpu.cpp today)
 *              |
 *              |  direct MMIO + rings to hardware
 *              v
 *            GPU
 *
 * Scope (v0):
 *   - Vulkan instance/device/queue lifecycle (Success-returning).
 *   - Physical-device properties / features / memory / queue-family
 *     queries; properties are sourced from display_info::Query().
 *   - Shader module create with SPIR-V magic validation
 *     (0x07230203 little-endian); blob is stored, not executed.
 *   - Graphics + compute pipeline create (state recorded only).
 *   - Render pass + framebuffer + image + image-view + buffer +
 *     device-memory create; all are tracked handles, no real
 *     storage layout.
 *   - Command pool + command buffer allocation.
 *   - Command tape: vkCmdClearColorImage, vkCmdBeginRenderPass,
 *     vkCmdEndRenderPass, vkCmdBindPipeline, vkCmdDraw recorded.
 *   - vkQueueSubmit replays the tape.  Clears against an image
 *     that was tagged with kImageScanoutBacked land on the
 *     framebuffer via FramebufferFillRect.
 *   - Fence + semaphore create/destroy (signalling is a no-op,
 *     vkWaitForFences returns Success immediately).
 *   - Self-test (`GraphicsIcdSelfTest`) runs the canonical
 *     CreateInstance -> CreateDevice -> CreateCommandPool ->
 *     AllocateCommandBuffers -> Begin -> CmdClearColorImage ->
 *     End -> Submit -> WaitIdle -> Free -> Destroy* pipeline and
 *     asserts every live handle counter returns to zero.
 *
 * Out of scope — deferred:
 *   - Real GPU command-ring submission (blocked on per-vendor
 *     firmware bring-up: Intel GuC/HuC, AMD MEC/RLC, NVIDIA GSP).
 *   - SPIR-V execution / shader translation.
 *   - Multi-queue, multi-device, multi-pipeline.
 *   - Synchronization primitives that actually block.
 *   - WSI present modes other than Fifo, surface formats other
 *     than B8G8R8A8_UNORM, multi-monitor swapchains.
 *   - VkUpdateDescriptorSets variants beyond the single-binding
 *     `VkUpdateDescriptorSet` we expose.
 *
 * D3D translation surface stays as it was (counters + E_FAIL
 * sentinels).  Wiring D3D11/D3D12 thunks into this Vulkan ICD is
 * a follow-on slice.
 *
 * References to study when this becomes real work:
 *   ValveSoftware/wine (github)
 *     - dlls/wined3d/    — D3D9/10 support
 *     - dxvk/            — D3D9/10/11 -> Vulkan
 *     - vkd3d-proton/    — D3D12 -> Vulkan (used in Steam Play)
 *
 * Context: kernel.  No locking — boot-time ICD init plus a tiny
 * fixed-size handle table; concurrent vkQueueSubmit from multiple
 * tasks is a future slice's concern.
 */

namespace duetos::subsystems::graphics
{

// -------------------------------------------------------------------
// Vulkan ICD surface
// -------------------------------------------------------------------
//
// Mirrors a subset of the Vulkan 1.3 spec.  Handles are u64 rather
// than the spec's dispatchable pointers — every handle this ICD
// hands out lives in a fixed-size per-kind slot table indexed by
// the low 8 bits of the handle so Destroy can validate cheaply.

using VkInstance = u64;
using VkPhysicalDevice = u64;
using VkDevice = u64;
using VkQueue = u64;
using VkCommandPool = u64;
using VkCommandBuffer = u64;
using VkShaderModule = u64;
using VkPipelineLayout = u64;
using VkPipeline = u64;
using VkRenderPass = u64;
using VkFramebuffer = u64;
using VkImage = u64;
using VkImageView = u64;
using VkBuffer = u64;
using VkDeviceMemory = u64;
using VkFence = u64;
using VkSemaphore = u64;
using VkDescriptorSetLayout = u64;
using VkDescriptorPool = u64;
using VkDescriptorSet = u64;
using VkSurfaceKHR = u64;
using VkSwapchainKHR = u64;

// Return codes (subset).
enum class VkResult : i32
{
    Success = 0,
    NotReady = 1,
    Timeout = 2,
    EventSet = 3,
    EventReset = 4,
    Incomplete = 5,
    ErrorOutOfHostMemory = -1,
    ErrorOutOfDeviceMemory = -2,
    ErrorInitializationFailed = -3,
    ErrorDeviceLost = -4,
    ErrorMemoryMapFailed = -5,
    ErrorLayerNotPresent = -6,
    ErrorExtensionNotPresent = -7,
    ErrorFeatureNotPresent = -8,
    ErrorIncompatibleDriver = -9,
    ErrorTooManyObjects = -10,
    ErrorFormatNotSupported = -11,
    ErrorFragmentedPool = -12,
    ErrorInvalidShaderNV = -1000012000,
};

// Image flags.  We only track scanout-backing today; a real ICD
// would carry usage / tiling / aspect masks.
inline constexpr u32 kImageScanoutBacked = 1u << 0;

// Pipeline stage shape, recorded but not actioned.
enum class VkPipelineBindPoint : u32
{
    Graphics = 0,
    Compute = 1,
};

// Memory property flags (subset; matches the spec's bit layout).
inline constexpr u32 kMemoryPropertyDeviceLocal = 0x00000001;
inline constexpr u32 kMemoryPropertyHostVisible = 0x00000002;
inline constexpr u32 kMemoryPropertyHostCoherent = 0x00000004;

// Queue capability flags.
inline constexpr u32 kQueueGraphicsBit = 0x00000001;
inline constexpr u32 kQueueComputeBit = 0x00000002;
inline constexpr u32 kQueueTransferBit = 0x00000004;

struct VkOffset2D
{
    i32 x;
    i32 y;
};
struct VkExtent2D
{
    u32 width;
    u32 height;
};
struct VkExtent3D
{
    u32 width;
    u32 height;
    u32 depth;
};
struct VkRect2D
{
    VkOffset2D offset;
    VkExtent2D extent;
};

// Spec-shaped union — a real ICD picks the field that matches
// the image format.  The kernel ICD has no float runtime
// (`-mno-sse -mgeneral-regs-only`) and reads only `uint32[]`,
// where the low byte of each lane is the 0-255 colour
// component.  `float32[]` is kept for ABI compatibility so a
// caller using the spec's float-init pattern still compiles.
union VkClearColorValue
{
    float float32[4];
    u32 uint32[4]; // RRGGBBAA in lane low-bytes (UNORM 8-bit)
    i32 int32[4];
};

struct VkPhysicalDeviceLimits
{
    u32 maxImageDimension2D;
    u32 maxFramebufferWidth;
    u32 maxFramebufferHeight;
    u32 maxBoundDescriptorSets;
    u32 maxPushConstantsSize;
    u32 maxComputeWorkGroupCount[3];
};

// API version macro shape.  Encoded the same way as
// VK_MAKE_API_VERSION(variant, major, minor, patch).
inline constexpr u32 MakeApiVersion(u32 variant, u32 major, u32 minor, u32 patch)
{
    return (variant << 29) | (major << 22) | (minor << 12) | patch;
}
inline constexpr u32 kApiVersion1_3 = MakeApiVersion(0, 1, 3, 0);

inline constexpr u32 kMaxDeviceName = 64;

struct VkPhysicalDeviceProperties
{
    u32 apiVersion;    // VK_API_VERSION_1_3 today
    u32 driverVersion; // DuetOS ICD epoch
    u32 vendorID;      // PCI vendor ID from display_info
    u32 deviceID;      // 0 for our skeleton
    u32 deviceType;    // 0=Other, 1=IntegratedGPU, 2=DiscreteGPU, 3=VirtualGpu, 4=CPU
    char deviceName[kMaxDeviceName];
    VkPhysicalDeviceLimits limits;
};

struct VkPhysicalDeviceFeatures
{
    u32 robustBufferAccess; // Vulkan booleans are 32-bit ints.
    u32 fullDrawIndexUint32;
    u32 imageCubeArray;
    u32 geometryShader;
    u32 tessellationShader;
};

struct VkMemoryHeap
{
    u64 size;
    u32 flags;
};
struct VkMemoryType
{
    u32 propertyFlags;
    u32 heapIndex;
};
inline constexpr u32 kMaxMemoryHeaps = 4;
inline constexpr u32 kMaxMemoryTypes = 8;
struct VkPhysicalDeviceMemoryProperties
{
    u32 memoryHeapCount;
    VkMemoryHeap memoryHeaps[kMaxMemoryHeaps];
    u32 memoryTypeCount;
    VkMemoryType memoryTypes[kMaxMemoryTypes];
};

struct VkQueueFamilyProperties
{
    u32 queueFlags;
    u32 queueCount;
    u32 timestampValidBits;
    VkExtent3D minImageTransferGranularity;
};

// -------------------------------------------------------------------
// Init + diagnostics
// -------------------------------------------------------------------

/// Bring up the graphics ICD.  Logs "graphics ICD present (v0)"
/// and reports physical devices + the active display.  No driver
/// is loaded — this is a CPU-side ICD whose deepest visible op
/// is a framebuffer-backed clear.
void GraphicsIcdInit();

/// Boot-time self-test: drives the canonical Create -> Submit ->
/// Destroy pipeline and asserts every live counter returns to
/// zero.  Returns Success on a clean run; the boot harness
/// converts failures into the standard `[selftest:graphics]`
/// boot-log line.  Safe to call once after `GraphicsIcdInit`.
VkResult GraphicsIcdSelfTest();

// -------------------------------------------------------------------
// Vulkan instance / physical-device / device
// -------------------------------------------------------------------

VkResult VkCreateInstance(VkInstance* out);
void VkDestroyInstance(VkInstance inst);

VkResult VkEnumeratePhysicalDevices(VkInstance inst, u32* count, VkPhysicalDevice* devs);

VkResult VkGetPhysicalDeviceProperties(VkPhysicalDevice phys, VkPhysicalDeviceProperties* out);
VkResult VkGetPhysicalDeviceFeatures(VkPhysicalDevice phys, VkPhysicalDeviceFeatures* out);
VkResult VkGetPhysicalDeviceMemoryProperties(VkPhysicalDevice phys, VkPhysicalDeviceMemoryProperties* out);
VkResult VkGetPhysicalDeviceQueueFamilyProperties(VkPhysicalDevice phys, u32* count, VkQueueFamilyProperties* out);

VkResult VkEnumerateInstanceExtensionProperties(u32* count);
VkResult VkEnumerateInstanceLayerProperties(u32* count);
VkResult VkEnumerateDeviceExtensionProperties(VkPhysicalDevice phys, u32* count);

VkResult VkCreateDevice(VkPhysicalDevice phys, VkDevice* out);
void VkDestroyDevice(VkDevice dev);

VkResult VkGetDeviceQueue(VkDevice dev, VkQueue* out);
VkResult VkQueueWaitIdle(VkQueue q);
VkResult VkDeviceWaitIdle(VkDevice dev);

// -------------------------------------------------------------------
// Memory + buffers + images + views
// -------------------------------------------------------------------

VkResult VkAllocateMemory(VkDevice dev, u64 size, u32 memory_type_index, VkDeviceMemory* out);
void VkFreeMemory(VkDevice dev, VkDeviceMemory mem);

VkResult VkCreateBuffer(VkDevice dev, u64 size, VkBuffer* out);
void VkDestroyBuffer(VkDevice dev, VkBuffer buf);
VkResult VkBindBufferMemory(VkDevice dev, VkBuffer buf, VkDeviceMemory mem, u64 offset);

/// Create an image.  When `flags & kImageScanoutBacked` is set, a
/// later `vkCmdClearColorImage` against this image will paint the
/// active framebuffer via `FramebufferFillRect` — our v0 swapchain
/// shortcut.  `extent.depth` is recorded but unused.
VkResult VkCreateImage(VkDevice dev, VkExtent3D extent, u32 flags, VkImage* out);
void VkDestroyImage(VkDevice dev, VkImage img);
VkResult VkBindImageMemory(VkDevice dev, VkImage img, VkDeviceMemory mem, u64 offset);

VkResult VkCreateImageView(VkDevice dev, VkImage img, VkImageView* out);
void VkDestroyImageView(VkDevice dev, VkImageView view);

// -------------------------------------------------------------------
// Render pass + framebuffer
// -------------------------------------------------------------------

VkResult VkCreateRenderPass(VkDevice dev, VkRenderPass* out);
void VkDestroyRenderPass(VkDevice dev, VkRenderPass rp);

VkResult VkCreateFramebuffer(VkDevice dev, VkRenderPass rp, VkImageView attachment, VkExtent2D extent,
                             VkFramebuffer* out);
void VkDestroyFramebuffer(VkDevice dev, VkFramebuffer fb);

// -------------------------------------------------------------------
// Shader + pipeline
// -------------------------------------------------------------------

/// Validates the SPIR-V magic word (0x07230203 LE) and stores
/// the blob length.  The bytecode is not executed; a small
/// header walker (see `VkGetShaderModuleInfoDuet`) runs at
/// create time to extract entry points, capabilities, and
/// decorations for diagnostics.
VkResult VkCreateShaderModule(VkDevice dev, const u32* code, u64 code_size_bytes, VkShaderModule* out);
void VkDestroyShaderModule(VkDevice dev, VkShaderModule module);

inline constexpr u32 kMaxEntryPointName = 32;

/// SPIR-V parse result attached to every shader module that
/// passed the magic-word check.  Populated by the v1 parser at
/// `VkCreateShaderModule` time — walks the instruction stream
/// once and aggregates counts; does not execute the bytecode.
///
/// Non-spec entry point — DuetOS diagnostic surface only.
struct ShaderModuleInfo
{
    bool valid;                                // false = parse failed (malformed)
    u32 word_count;                            // module size in 32-bit words
    u32 generator;                             // header word 2 (generator magic)
    u32 bound;                                 // header word 3 (ID upper bound)
    u32 entry_point_count;                     // OpEntryPoint instructions
    u32 execution_mode_count;                  // OpExecutionMode instructions
    u32 capability_count;                      // OpCapability instructions
    u32 decoration_count;                      // OpDecorate + OpMemberDecorate
    u32 first_execution_model;                 // first OpEntryPoint's model
                                               // (0=Vertex, 4=Fragment, 5=GLCompute)
    char first_entry_name[kMaxEntryPointName]; // null-terminated UTF-8
};

VkResult VkGetShaderModuleInfoDuet(VkShaderModule module, ShaderModuleInfo* out);

VkResult VkCreatePipelineLayout(VkDevice dev, VkPipelineLayout* out);
void VkDestroyPipelineLayout(VkDevice dev, VkPipelineLayout layout);

/// Records pipeline state.  The shader modules and layout are
/// not introspected; the handle is just a "draw will succeed"
/// token until the SPIR-V execution slice lands.
VkResult VkCreateGraphicsPipeline(VkDevice dev, VkPipelineLayout layout, VkShaderModule vs, VkShaderModule fs,
                                  VkPipeline* out);
VkResult VkCreateComputePipeline(VkDevice dev, VkPipelineLayout layout, VkShaderModule cs, VkPipeline* out);
void VkDestroyPipeline(VkDevice dev, VkPipeline pipe);

// -------------------------------------------------------------------
// Command pool + command buffer + recording
// -------------------------------------------------------------------

VkResult VkCreateCommandPool(VkDevice dev, VkCommandPool* out);
void VkDestroyCommandPool(VkDevice dev, VkCommandPool pool);

VkResult VkAllocateCommandBuffers(VkDevice dev, VkCommandPool pool, u32 count, VkCommandBuffer* out);
VkResult VkFreeCommandBuffers(VkDevice dev, VkCommandPool pool, u32 count, const VkCommandBuffer* cbs);

VkResult VkBeginCommandBuffer(VkCommandBuffer cb);
VkResult VkEndCommandBuffer(VkCommandBuffer cb);
VkResult VkResetCommandBuffer(VkCommandBuffer cb);

VkResult VkCmdBeginRenderPass(VkCommandBuffer cb, VkRenderPass rp, VkFramebuffer fb, VkRect2D area,
                              VkClearColorValue clear);
VkResult VkCmdEndRenderPass(VkCommandBuffer cb);
VkResult VkCmdBindPipeline(VkCommandBuffer cb, VkPipelineBindPoint bind_point, VkPipeline pipe);
VkResult VkCmdClearColorImage(VkCommandBuffer cb, VkImage image, VkClearColorValue clear);
VkResult VkCmdDraw(VkCommandBuffer cb, u32 vertex_count, u32 instance_count, u32 first_vertex, u32 first_instance);

// -------------------------------------------------------------------
// Submission + sync
// -------------------------------------------------------------------

/// Replay every command tape associated with the supplied
/// command buffers, in order.  The only opcode that produces
/// visible output today is vkCmdClearColorImage against an image
/// tagged with kImageScanoutBacked; everything else updates
/// stat counters and is dropped.
VkResult VkQueueSubmit(VkQueue q, u32 cb_count, const VkCommandBuffer* cbs, VkFence signal_fence);

VkResult VkCreateFence(VkDevice dev, bool signalled, VkFence* out);
void VkDestroyFence(VkDevice dev, VkFence fence);
VkResult VkResetFences(VkDevice dev, u32 count, const VkFence* fences);
VkResult VkWaitForFences(VkDevice dev, u32 count, const VkFence* fences, u64 timeout_ns);

VkResult VkCreateSemaphore(VkDevice dev, VkSemaphore* out);
void VkDestroySemaphore(VkDevice dev, VkSemaphore sem);

// -------------------------------------------------------------------
// Descriptor sets + pools.
// -------------------------------------------------------------------
//
// Real Vulkan descriptor sets pin GPU-visible resources for a
// shader pipeline.  Our v0 ICD records the layout + bindings as
// stats only — there's no shader execution to feed yet.  The
// surface is here so a downstream caller (DXVK, dxgi -> Vulkan
// thunks, native compute path) finds a complete API ladder
// today, with rendering plumbed in by a later slice.

enum class VkDescriptorType : u32
{
    Sampler = 0,
    CombinedImageSampler = 1,
    SampledImage = 2,
    StorageImage = 3,
    UniformTexelBuffer = 4,
    StorageTexelBuffer = 5,
    UniformBuffer = 6,
    StorageBuffer = 7,
    UniformBufferDynamic = 8,
    StorageBufferDynamic = 9,
    InputAttachment = 10,
};

inline constexpr u32 kMaxDescriptorBindings = 8;

struct VkDescriptorSetLayoutBinding
{
    u32 binding;
    VkDescriptorType type;
    u32 count;
    u32 stage_flags;
};

VkResult VkCreateDescriptorSetLayout(VkDevice dev, u32 binding_count, const VkDescriptorSetLayoutBinding* bindings,
                                     VkDescriptorSetLayout* out);
void VkDestroyDescriptorSetLayout(VkDevice dev, VkDescriptorSetLayout layout);

struct VkDescriptorPoolSize
{
    VkDescriptorType type;
    u32 count;
};

VkResult VkCreateDescriptorPool(VkDevice dev, u32 max_sets, u32 pool_size_count, const VkDescriptorPoolSize* pool_sizes,
                                VkDescriptorPool* out);
void VkDestroyDescriptorPool(VkDevice dev, VkDescriptorPool pool);
VkResult VkResetDescriptorPool(VkDevice dev, VkDescriptorPool pool);

VkResult VkAllocateDescriptorSets(VkDevice dev, VkDescriptorPool pool, u32 count, const VkDescriptorSetLayout* layouts,
                                  VkDescriptorSet* out);
VkResult VkFreeDescriptorSets(VkDevice dev, VkDescriptorPool pool, u32 count, const VkDescriptorSet* sets);

/// Update a descriptor set's binding to point at a buffer or
/// image-view resource.  The resource handle is stored against
/// the binding for stat purposes; no shader will ever read it
/// in v0.
VkResult VkUpdateDescriptorSet(VkDescriptorSet set, u32 binding, VkDescriptorType type, u64 resource_handle);

VkResult VkCmdBindDescriptorSets(VkCommandBuffer cb, VkPipelineBindPoint bind_point, VkPipelineLayout layout,
                                 u32 first_set, u32 set_count, const VkDescriptorSet* sets);

// -------------------------------------------------------------------
// Surface + swapchain (WSI subset).
// -------------------------------------------------------------------
//
// Real Vulkan WSI is a per-platform extension surface (KHR_surface
// + KHR_win32_surface / KHR_xcb_surface / etc.) that hands the
// presentation engine a window-system handle.  On DuetOS the
// "window system" is the kernel framebuffer, so a single
// `VkCreateDuetSurfaceKHR` covers the bring-up — no per-platform
// branching.  The swapchain rotates through N scanout-backed
// images; `vkQueuePresentKHR` calls `FramebufferPresent` so the
// damage rect from the last clear is flushed to the live display.
//
// Out of scope:
//   - VK_KHR_swapchain_maintenance1 (resize / dynamic format).
//   - VK_PRESENT_MODE_MAILBOX_KHR (we expose Fifo only).
//   - Multi-monitor presentation (one display per ICD instance).

inline constexpr u32 kMaxSwapchainImages = 4;

enum class VkPresentModeKHR : u32
{
    Immediate = 0,
    Mailbox = 1,
    Fifo = 2, // the only mode this ICD advertises
    FifoRelaxed = 3,
};

enum class VkColorSpaceKHR : u32
{
    SrgbNonlinear = 0, // VK_COLOR_SPACE_SRGB_NONLINEAR_KHR
};

struct VkSurfaceFormatKHR
{
    u32 format; // 0 = VK_FORMAT_B8G8R8A8_UNORM (only one we expose)
    VkColorSpaceKHR colorSpace;
};

struct VkSurfaceCapabilitiesKHR
{
    u32 minImageCount;
    u32 maxImageCount;
    VkExtent2D currentExtent;
    VkExtent2D minImageExtent;
    VkExtent2D maxImageExtent;
    u32 maxImageArrayLayers;
    u32 supportedTransforms;
    u32 currentTransform;
    u32 supportedCompositeAlpha;
    u32 supportedUsageFlags;
};

VkResult VkCreateDuetSurfaceKHR(VkInstance inst, VkSurfaceKHR* out);
void VkDestroySurfaceKHR(VkInstance inst, VkSurfaceKHR surface);

VkResult VkGetPhysicalDeviceSurfaceCapabilitiesKHR(VkPhysicalDevice phys, VkSurfaceKHR surface,
                                                   VkSurfaceCapabilitiesKHR* out);
VkResult VkGetPhysicalDeviceSurfaceFormatsKHR(VkPhysicalDevice phys, VkSurfaceKHR surface, u32* count,
                                              VkSurfaceFormatKHR* formats);
VkResult VkGetPhysicalDeviceSurfacePresentModesKHR(VkPhysicalDevice phys, VkSurfaceKHR surface, u32* count,
                                                   VkPresentModeKHR* modes);

VkResult VkCreateSwapchainKHR(VkDevice dev, VkSurfaceKHR surface, u32 min_image_count, VkExtent2D extent,
                              VkSwapchainKHR* out);
void VkDestroySwapchainKHR(VkDevice dev, VkSwapchainKHR sc);

VkResult VkGetSwapchainImagesKHR(VkDevice dev, VkSwapchainKHR sc, u32* count, VkImage* images);

VkResult VkAcquireNextImageKHR(VkDevice dev, VkSwapchainKHR sc, u64 timeout_ns, VkSemaphore signal_semaphore,
                               VkFence signal_fence, u32* image_index_out);

VkResult VkQueuePresentKHR(VkQueue q, VkSwapchainKHR sc, u32 image_index);

// -------------------------------------------------------------------
// D3D11 / D3D12 -> Vulkan translation (still skeleton)
// -------------------------------------------------------------------
//
// Wiring D3D thunks into the new Vulkan path is a follow-on slice.
// Today they continue to return E_FAIL + bump call counters.

u32 D3D11CreateDeviceStub();
u32 D3D12CreateDeviceStub();
u32 DxgiCreateFactoryStub();
u32 D3d9CreateStub();
u32 Dinput8CreateStub();
u32 XinputCreateStub();
u32 Xaudio2CreateStub();
u32 DsoundCreateStub();
u32 DdrawCreateStub();
u32 D2d1CreateStub();
u32 DwriteCreateStub();

// -------------------------------------------------------------------
// Diagnostics
// -------------------------------------------------------------------

/// Diagnostic snapshot — handle-table counters for every kind of
/// object the ICD hands out.  The boot self-test asserts every
/// `*_live` counter returns to 0 after a Create -> Destroy round
/// trip.  The `gfx` shell command formats this for an operator.
struct GraphicsStats
{
    u32 vk_instances_live;
    u32 vk_instances_created;
    u32 vk_instances_destroyed;
    u32 vk_devices_live;
    u32 vk_devices_created;
    u32 vk_devices_destroyed;
    u32 vk_command_pools_live;
    u32 vk_command_buffers_live;
    u32 vk_shader_modules_live;
    u32 vk_pipelines_live;
    u32 vk_render_passes_live;
    u32 vk_framebuffers_live;
    u32 vk_images_live;
    u32 vk_image_views_live;
    u32 vk_buffers_live;
    u32 vk_device_memory_live;
    u32 vk_fences_live;
    u32 vk_semaphores_live;
    u32 vk_pipeline_layouts_live;
    u32 vk_descriptor_set_layouts_live;
    u32 vk_descriptor_pools_live;
    u32 vk_descriptor_sets_live;
    u32 vk_descriptor_writes; // total VkUpdateDescriptorSet calls
    u32 vk_surfaces_live;
    u32 vk_swapchains_live;
    u32 vk_swapchain_acquires;         // total vkAcquireNextImageKHR calls
    u32 vk_swapchain_presents;         // total vkQueuePresentKHR calls
    u32 vk_queue_submits;              // total VkQueueSubmit calls
    u32 vk_command_recorded;           // total vkCmd* opcodes recorded
    u32 vk_command_replayed;           // total vkCmd* opcodes replayed in submit
    u32 vk_clear_pixels_painted;       // sum of pixels actually painted by scanout-backed clears
    u32 vk_invalid_spirv_rejections;   // VkCreateShaderModule rejections (bad magic / 0 size)
    u32 vk_spirv_modules_parsed;       // shaders successfully parsed by the v1 walker
    u32 vk_spirv_entry_points_seen;    // sum across all parsed modules
    u32 vk_spirv_capabilities_seen;    // sum
    u32 vk_spirv_decorations_seen;     // sum
    u32 vk_spirv_execution_modes_seen; // sum
    u32 d3d_create_calls;
    u32 dxgi_create_calls;
    u32 d3d9_create_calls;
    u32 dinput8_create_calls;
    u32 xinput_create_calls;
    u32 xaudio2_create_calls;
    u32 dsound_create_calls;
    u32 ddraw_create_calls;
    u32 d2d1_create_calls;
    u32 dwrite_create_calls;
};
GraphicsStats GraphicsStatsRead();

} // namespace duetos::subsystems::graphics
