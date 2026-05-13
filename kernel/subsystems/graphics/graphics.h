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
 *   - vkCmdDraw against a scanout-backed render target runs a
 *     CPU triangle rasterizer (edge-function, integer math,
 *     flat-shaded with the colour of vertex 0).  Vertex buffers
 *     bound at binding 0 are interpreted in the DuetOS v0 fixed
 *     vertex format: 8 bytes per vertex, packed as
 *     `{i16 x_px; i16 y_px; u32 argb;}` (0xAARRGGBB; alpha is
 *     recorded but not blended).  Three consecutive vertices
 *     form one triangle (TriangleList only).  The rasterizer is
 *     skipped — but `vk_triangles_drawn` still ticks — when the
 *     render target isn't scanout-backed or the vertex buffer
 *     isn't host-visible, so the dispatch chain is observable
 *     without painting pixels.
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
using VkSampler = u64;
using VkEvent = u64;
using VkPipelineCache = u64;
using VkQueryPool = u64;

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

// VkIndexType — for vkCmdBindIndexBuffer.
enum class VkIndexType : u32
{
    Uint16 = 0,
    Uint32 = 1,
};

enum class VkFilter : u32
{
    Nearest = 0,
    Linear = 1,
};

enum class VkSamplerAddressMode : u32
{
    Repeat = 0,
    MirroredRepeat = 1,
    ClampToEdge = 2,
    ClampToBorder = 3,
};

// Push constant payload size cap — covers the spec's
// minimum-mandated 128 bytes.  Keeps the per-cb tape entry a
// fixed size.
inline constexpr u32 kMaxPushConstantBytes = 128;

struct VkViewport
{
    float x;
    float y;
    float width;
    float height;
    float minDepth;
    float maxDepth;
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

/// Loader-style proc-address resolver.  Returns a stable opaque
/// token (the entry-point id) that a caller can cross-reference
/// against the kernel-side dispatch table.  Returns 0 for
/// unrecognised names.
VkResult VkEnumerateInstanceVersion(u32* api_version);
u64 VkGetInstanceProcAddr(VkInstance inst, const char* name);
u64 VkGetDeviceProcAddr(VkDevice dev, const char* name);

// Vulkan 1.1 / 1.2 -shaped extended queries.  pNext chain is
// accepted but ignored — no extensions are advertised yet.
struct VkPhysicalDeviceProperties2
{
    void* pNext;
    VkPhysicalDeviceProperties properties;
};
struct VkPhysicalDeviceFeatures2
{
    void* pNext;
    VkPhysicalDeviceFeatures features;
};
struct VkPhysicalDeviceMemoryProperties2
{
    void* pNext;
    VkPhysicalDeviceMemoryProperties memoryProperties;
};
VkResult VkGetPhysicalDeviceProperties2(VkPhysicalDevice phys, VkPhysicalDeviceProperties2* out);
VkResult VkGetPhysicalDeviceFeatures2(VkPhysicalDevice phys, VkPhysicalDeviceFeatures2* out);
VkResult VkGetPhysicalDeviceMemoryProperties2(VkPhysicalDevice phys, VkPhysicalDeviceMemoryProperties2* out);

// -------------------------------------------------------------------
// Format properties.
// -------------------------------------------------------------------
//
// Reports which features are supported for a given pixel
// format.  Our v0 ICD recognises only one format
// (VK_FORMAT_B8G8R8A8_UNORM, encoded as 0) and reports a
// minimal feature set against it.

inline constexpr u32 kFormatFeatureSampledImage = 0x0001;
inline constexpr u32 kFormatFeatureColorAttachment = 0x0080;
inline constexpr u32 kFormatFeatureTransferSrc = 0x4000;
inline constexpr u32 kFormatFeatureTransferDst = 0x8000;

struct VkFormatProperties
{
    u32 linearTilingFeatures;
    u32 optimalTilingFeatures;
    u32 bufferFeatures;
};

VkResult VkGetPhysicalDeviceFormatProperties(VkPhysicalDevice phys, u32 format, VkFormatProperties* out);

struct VkImageFormatProperties
{
    VkExtent3D maxExtent;
    u32 maxMipLevels;
    u32 maxArrayLayers;
    u32 sampleCounts; // VK_SAMPLE_COUNT_1_BIT only
    u64 maxResourceSize;
};

VkResult VkGetPhysicalDeviceImageFormatProperties(VkPhysicalDevice phys, u32 format, u32 type, u32 tiling, u32 usage,
                                                  u32 flags, VkImageFormatProperties* out);

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

/// Map host-visible memory.  The pointer returned is the kernel
/// heap allocation that backed the memory at allocate time;
/// only memory_type_index 1 (HOST_VISIBLE+COHERENT) supports
/// mapping today.  Map calls are reference-counted but the
/// pointer never moves.
VkResult VkMapMemory(VkDevice dev, VkDeviceMemory mem, u64 offset, u64 size, void** out_ptr);
void VkUnmapMemory(VkDevice dev, VkDeviceMemory mem);

/// Flush / invalidate cache lines that span the supplied memory
/// ranges.  HOST_COHERENT memory makes these no-ops; the entries
/// exist for spec compatibility.
VkResult VkFlushMappedMemoryRanges(VkDevice dev, u32 count, const VkDeviceMemory* mems);
VkResult VkInvalidateMappedMemoryRanges(VkDevice dev, u32 count, const VkDeviceMemory* mems);

VkResult VkCreateBuffer(VkDevice dev, u64 size, VkBuffer* out);
void VkDestroyBuffer(VkDevice dev, VkBuffer buf);
VkResult VkBindBufferMemory(VkDevice dev, VkBuffer buf, VkDeviceMemory mem, u64 offset);

struct VkMemoryRequirements
{
    u64 size;
    u64 alignment;
    u32 memoryTypeBits; // bitmask of allowed memory type indices
};

VkResult VkGetBufferMemoryRequirements(VkDevice dev, VkBuffer buffer, VkMemoryRequirements* out);
VkResult VkGetImageMemoryRequirements(VkDevice dev, VkImage image, VkMemoryRequirements* out);

/// Returns the memory commit (live bound size) for a memory
/// allocation.  v0 reports the full allocation size for any
/// memory whose host pointer was successfully allocated.
VkResult VkGetDeviceMemoryCommitment(VkDevice dev, VkDeviceMemory mem, u64* committed);

/// Vulkan 1.2 buffer device address.  Returns the kernel-side
/// host pointer cast to u64 — in our v0 the "device" address
/// space and the host address space are the same since memory
/// is just kheap-backed.  Returns 0 for unbound or
/// device-local-only buffers.
u64 VkGetBufferDeviceAddress(VkDevice dev, VkBuffer buffer);

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

/// Reset every command buffer in the pool to the Initial state.
/// `flags` is accepted for spec compatibility (RELEASE_RESOURCES
/// is a no-op in v0 — there's no per-cb storage to release).
VkResult VkResetCommandPool(VkDevice dev, VkCommandPool pool, u32 flags);

VkResult VkCmdBeginRenderPass(VkCommandBuffer cb, VkRenderPass rp, VkFramebuffer fb, VkRect2D area,
                              VkClearColorValue clear);
VkResult VkCmdEndRenderPass(VkCommandBuffer cb);
VkResult VkCmdBindPipeline(VkCommandBuffer cb, VkPipelineBindPoint bind_point, VkPipeline pipe);
VkResult VkCmdClearColorImage(VkCommandBuffer cb, VkImage image, VkClearColorValue clear);
VkResult VkCmdDraw(VkCommandBuffer cb, u32 vertex_count, u32 instance_count, u32 first_vertex, u32 first_instance);
VkResult VkCmdDrawIndexed(VkCommandBuffer cb, u32 index_count, u32 instance_count, u32 first_index, i32 vertex_offset,
                          u32 first_instance);

// Dynamic state — recorded only.  A real ICD feeds these into
// the rasterizer at draw time.
VkResult VkCmdSetViewport(VkCommandBuffer cb, u32 first_viewport, u32 count, const VkViewport* viewports);
VkResult VkCmdSetScissor(VkCommandBuffer cb, u32 first_scissor, u32 count, const VkRect2D* scissors);

// Vertex / index binding — recorded only (no shader to consume
// the streams yet).  vkCmdBindVertexBuffers takes parallel
// arrays of buffers + per-buffer offsets like the spec.
VkResult VkCmdBindVertexBuffers(VkCommandBuffer cb, u32 first_binding, u32 count, const VkBuffer* buffers,
                                const u64* offsets);
VkResult VkCmdBindIndexBuffer(VkCommandBuffer cb, VkBuffer buffer, u64 offset, VkIndexType type);

// Buffer transfer / fill — recorded; replay copies bytes
// between buffer-bound memory when both buffers are mapped.
VkResult VkCmdCopyBuffer(VkCommandBuffer cb, VkBuffer src, VkBuffer dst, u64 src_offset, u64 dst_offset, u64 size);
VkResult VkCmdFillBuffer(VkCommandBuffer cb, VkBuffer dst, u64 dst_offset, u64 size, u32 data);

// Pipeline barrier — recorded only.  Required for spec
// compliance even when there's no GPU-side hazard tracking.
VkResult VkCmdPipelineBarrier(VkCommandBuffer cb, u32 src_stage_mask, u32 dst_stage_mask, u32 dependency_flags);

// Push constants — small per-pipeline-layout payload that
// shaders read.  Recorded into the cb's tape; replay never
// dispatches anywhere today.
VkResult VkCmdPushConstants(VkCommandBuffer cb, VkPipelineLayout layout, u32 stage_flags, u32 offset, u32 size,
                            const void* values);

// Compute dispatch — recorded only.
VkResult VkCmdDispatch(VkCommandBuffer cb, u32 group_count_x, u32 group_count_y, u32 group_count_z);

/// Copy a contiguous range of host-visible buffer memory into
/// an image's pixel store.  When the image is scanout-backed
/// the replay path actually paints those bytes through
/// `FramebufferBlit` — turning this into a real texture-upload
/// path.  When the image is non-scanout, the bytes are
/// recorded but discarded (no real image storage in v0).
VkResult VkCmdCopyBufferToImage(VkCommandBuffer cb, VkBuffer src_buffer, VkImage dst_image, u64 src_offset, u32 width,
                                u32 height);

/// Image-to-image copy.  Recorded only.
VkResult VkCmdCopyImage(VkCommandBuffer cb, VkImage src_image, VkImage dst_image, u32 width, u32 height);

/// Filtered image copy.  Recorded only.
VkResult VkCmdBlitImage(VkCommandBuffer cb, VkImage src_image, VkImage dst_image, VkRect2D src_rect, VkRect2D dst_rect,
                        VkFilter filter);

/// Image-to-buffer transfer.  Recorded only.
VkResult VkCmdCopyImageToBuffer(VkCommandBuffer cb, VkImage src_image, VkBuffer dst_buffer, u64 dst_offset, u32 width,
                                u32 height);

/// Multi-sample resolve.  Recorded only.
VkResult VkCmdResolveImage(VkCommandBuffer cb, VkImage src_image, VkImage dst_image, u32 width, u32 height);

/// Inline buffer update — small payload (<=64 KiB per spec).
/// Real bytes move when the buffer is bound to host-visible
/// memory; otherwise recorded only.
VkResult VkCmdUpdateBuffer(VkCommandBuffer cb, VkBuffer dst, u64 dst_offset, u64 size, const void* data);

/// Clear sub-region of bound attachments mid-pass.  Recorded only.
VkResult VkCmdClearAttachments(VkCommandBuffer cb, u32 attachment_count, u32 rect_count, VkClearColorValue clear);

/// Depth/stencil image clear.  Recorded only — no depth buffer.
VkResult VkCmdClearDepthStencilImage(VkCommandBuffer cb, VkImage image, float depth, u32 stencil);

// -------------------------------------------------------------------
// Dynamic state setters (recorded only).
// -------------------------------------------------------------------
//
// Most of these touch a single pipeline state register that the
// rasterizer would consume; v0 has no rasterizer state, so the
// calls are recorded for stats and dropped.  The shapes match
// the spec so a downstream caller's draw setup runs through.

VkResult VkCmdSetLineWidth(VkCommandBuffer cb, float line_width);
VkResult VkCmdSetDepthBias(VkCommandBuffer cb, float constant_factor, float clamp, float slope_factor);
VkResult VkCmdSetBlendConstants(VkCommandBuffer cb, const float blend_constants[4]);
VkResult VkCmdSetDepthBounds(VkCommandBuffer cb, float min_depth_bounds, float max_depth_bounds);
VkResult VkCmdSetStencilCompareMask(VkCommandBuffer cb, u32 face_mask, u32 compare_mask);
VkResult VkCmdSetStencilWriteMask(VkCommandBuffer cb, u32 face_mask, u32 write_mask);
VkResult VkCmdSetStencilReference(VkCommandBuffer cb, u32 face_mask, u32 reference);

// -------------------------------------------------------------------
// Indirect draw / dispatch (VK 1.0 core).
// -------------------------------------------------------------------
//
// The "indirect" forms read their parameters from a buffer at
// replay time instead of from the cb's tape. v0 records the
// buffer handle + offset; the replay walks them when the draw
// reaches the pipeline, treating non-mapped buffers as zero
// draws.
VkResult VkCmdDrawIndirect(VkCommandBuffer cb, VkBuffer buffer, u64 offset, u32 draw_count, u32 stride);
VkResult VkCmdDrawIndexedIndirect(VkCommandBuffer cb, VkBuffer buffer, u64 offset, u32 draw_count, u32 stride);
VkResult VkCmdDispatchIndirect(VkCommandBuffer cb, VkBuffer buffer, u64 offset);

// -------------------------------------------------------------------
// VK 1.3 core dynamic state ("dynamic state 2").
// -------------------------------------------------------------------
//
// Promoted from VK_EXT_extended_dynamic_state{1,2,3} into core in
// 1.3. v0 records the value into the cb's tape so submission stats
// see the call; the rasterizer doesn't consume any of them yet.
VkResult VkCmdSetCullMode(VkCommandBuffer cb, u32 cull_mode);
VkResult VkCmdSetFrontFace(VkCommandBuffer cb, u32 front_face);
VkResult VkCmdSetPrimitiveTopology(VkCommandBuffer cb, u32 topology);
VkResult VkCmdSetDepthTestEnable(VkCommandBuffer cb, u32 enable);
VkResult VkCmdSetDepthWriteEnable(VkCommandBuffer cb, u32 enable);
VkResult VkCmdSetDepthCompareOp(VkCommandBuffer cb, u32 compare_op);
VkResult VkCmdSetStencilTestEnable(VkCommandBuffer cb, u32 enable);
VkResult VkCmdSetStencilOp(VkCommandBuffer cb, u32 face_mask, u32 fail_op, u32 pass_op, u32 depth_fail_op,
                           u32 compare_op);
VkResult VkCmdSetDepthBoundsTestEnable(VkCommandBuffer cb, u32 enable);
VkResult VkCmdSetViewportWithCount(VkCommandBuffer cb, u32 count, const VkViewport* viewports);
VkResult VkCmdSetScissorWithCount(VkCommandBuffer cb, u32 count, const VkRect2D* scissors);
VkResult VkCmdBindVertexBuffers2(VkCommandBuffer cb, u32 first_binding, u32 count, const VkBuffer* buffers,
                                 const u64* offsets, const u64* sizes, const u64* strides);

// -------------------------------------------------------------------
// Render-pass subpass advance (VK 1.0 core).
// -------------------------------------------------------------------
//
// Multi-subpass passes need a transition point between subpasses.
// v0 has single-subpass passes today; the call is recorded for
// stats and advances the cb's subpass counter so downstream
// asserts don't trip.
VkResult VkCmdNextSubpass(VkCommandBuffer cb, u32 contents);

// -------------------------------------------------------------------
// Query — extended forms.
// -------------------------------------------------------------------

/// Copy query-pool results into a host-visible buffer at submit
/// time. v0 records the (pool, range, dst_buffer, dst_offset,
/// stride, flags) tuple; replay walks the pool's result array and
/// writes 64-bit zeros for each slot when flags carry the WAIT bit
/// (the bit demands a blocking wait on a pool with no producer —
/// v0's queries never get written, so zero is the documented
/// "result not yet available" value).
VkResult VkCmdCopyQueryPoolResults(VkCommandBuffer cb, VkQueryPool pool, u32 first_query, u32 query_count,
                                   VkBuffer dst_buffer, u64 dst_offset, u64 stride, u32 flags);

/// Indexed query begin / end — VK_EXT_transform_feedback. The
/// `index` selects a transform-feedback stream; v0 has no XFB
/// pipeline so the index is recorded but unused.
VkResult VkCmdBeginQueryIndexed(VkCommandBuffer cb, VkQueryPool pool, u32 query, u32 flags, u32 index);
VkResult VkCmdEndQueryIndexed(VkCommandBuffer cb, VkQueryPool pool, u32 query, u32 index);

// -------------------------------------------------------------------
// Synchronization2 (VK 1.3 core, promoted from VK_KHR_synchronization2).
// -------------------------------------------------------------------
//
// Replace the legacy single-stage-mask APIs with a unified
// VkDependencyInfo that carries memory + buffer + image barriers
// in one call. v0 doesn't do real GPU-side hazard tracking; the
// calls are recorded into the cb's tape so submit stats see them.
VkResult VkCmdSetEvent2(VkCommandBuffer cb, VkEvent event, u64 stage_mask);
VkResult VkCmdResetEvent2(VkCommandBuffer cb, VkEvent event, u64 stage_mask);
VkResult VkCmdWaitEvents2(VkCommandBuffer cb, u32 count, const VkEvent* events);
VkResult VkCmdPipelineBarrier2(VkCommandBuffer cb, u64 src_stage_mask, u64 dst_stage_mask, u32 dependency_flags);

// -------------------------------------------------------------------
// Physical-device sparse image queries.
// -------------------------------------------------------------------
//
// Sparse resources are not supported in v0; the count returned
// is always zero (which the spec defines as "no sparse formats
// supported for this combination").
VkResult VkGetPhysicalDeviceSparseImageFormatProperties(VkPhysicalDevice phys, u32 format, u32 type, u32 samples,
                                                        u32 usage, u32 tiling, u32* count);

// -------------------------------------------------------------------
// VK_KHR_dynamic_rendering — render passes without VkRenderPass.
// -------------------------------------------------------------------
//
// Dynamic rendering lets a caller submit a draw without going
// through the heavyweight VkCreateRenderPass / VkCreateFramebuffer
// dance.  Our v0 records the begin / end pair into the tape and,
// for the begin call, paints the clear value across the
// attachment image when the latter is scanout-backed (same
// machinery as VkCmdBeginRenderPass).

struct VkRenderingAttachmentInfo
{
    VkImageView imageView;
    u32 loadOp; // 0=LoadOp_Load, 1=LoadOp_Clear, 2=LoadOp_DontCare
    VkClearColorValue clearValue;
};

VkResult VkCmdBeginRendering(VkCommandBuffer cb, VkRect2D render_area, u32 color_attachment_count,
                             const VkRenderingAttachmentInfo* color_attachments);
VkResult VkCmdEndRendering(VkCommandBuffer cb);

// -------------------------------------------------------------------
// VK_EXT_debug_utils — object naming for tooling.
// -------------------------------------------------------------------
//
// Lets a caller attach a string label to any kernel-side handle.
// The label is stored in a small fixed-size table indexed by
// handle; `VkGetDebugUtilsObjectNameDuet` reads it back.  No
// validator hooks the names today, but the surface lets an
// external tracer correlate handles to source code.

inline constexpr u32 kMaxDebugLabelLen = 32;

struct VkDebugUtilsObjectNameInfoEXT
{
    u64 objectHandle;
    const char* pObjectName; // null-terminated UTF-8, copied
};

VkResult VkSetDebugUtilsObjectNameEXT(VkDevice dev, const VkDebugUtilsObjectNameInfoEXT* info);
VkResult VkGetDebugUtilsObjectNameDuet(u64 object_handle, char* out_buf, u32 buf_len);

/// Debug-label brackets in the cmd stream (VK_EXT_debug_utils).
/// `vkCmdInsertDebugUtilsLabelEXT` records a single labelled
/// marker; the begin/end pair brackets a region.  The label
/// strings ride along inside the cb's tape (reuse the
/// push-constants byte slot).
VkResult VkCmdBeginDebugUtilsLabelEXT(VkCommandBuffer cb, const char* label);
VkResult VkCmdEndDebugUtilsLabelEXT(VkCommandBuffer cb);
VkResult VkCmdInsertDebugUtilsLabelEXT(VkCommandBuffer cb, const char* label);

// -------------------------------------------------------------------
// DuetOS extension: rasterizer vertex format.
// -------------------------------------------------------------------
//
// Selects the in-memory layout the software rasterizer assumes
// for binding-0 vertex buffers on subsequent Draw / DrawIndexed
// dispatches. `format`:
//   0 — v0 (8 bytes per vertex): `{i16 x_px; i16 y_px; u32 argb;}`.
//       Z is treated as 0 for every vertex; depth test is
//       effectively disabled regardless of the depth-test bit.
//   1 — v1 (12 bytes per vertex): `{i16 x_px; i16 y_px; i16 z;
//       u16 _reserved; u32 argb;}`. Z is interpolated
//       barycentrically and compared against the shared depth
//       surface when `vkCmdSetDepthTestEnable(1)` is in effect.
// State is per-command-buffer; the default is v0. Recording-only —
// the rasterizer reads the format during replay.
VkResult VkCmdSetVertexFormatDuet(VkCommandBuffer cb, u32 format);

// -------------------------------------------------------------------
// Push descriptors (VK_KHR_push_descriptor).
// -------------------------------------------------------------------
//
// Pushes a descriptor write straight onto the command buffer
// without going through a descriptor pool — handy for "I just
// want to bind one resource for one draw" cases.  Recorded only;
// no shader to consume.

struct VkWriteDescriptorSet; // defined further down in the descriptor section
VkResult VkCmdPushDescriptorSetKHR(VkCommandBuffer cb, VkPipelineBindPoint bind_point, VkPipelineLayout layout, u32 set,
                                   u32 write_count, const VkWriteDescriptorSet* writes);

// -------------------------------------------------------------------
// Secondary command buffers + execute.
// -------------------------------------------------------------------
//
// vkAllocateCommandBuffers v0 always returns "primary" cbs; this
// slice introduces a separate Allocate2 path that takes a
// "level" hint, plus vkCmdExecuteCommands which records "execute
// the supplied secondary cbs as if their tape were inlined".
// Replay simply walks the secondary cb's tape inside the
// primary's replay so the recorded ops actually run.

enum class VkCommandBufferLevel : u32
{
    Primary = 0,
    Secondary = 1,
};

VkResult VkAllocateCommandBuffers2(VkDevice dev, VkCommandPool pool, VkCommandBufferLevel level, u32 count,
                                   VkCommandBuffer* out);

VkResult VkCmdExecuteCommands(VkCommandBuffer cb, u32 count, const VkCommandBuffer* secondaries);

// -------------------------------------------------------------------
// Bind-memory-2 array forms (Vulkan 1.1).
// -------------------------------------------------------------------

struct VkBindBufferMemoryInfo
{
    VkBuffer buffer;
    VkDeviceMemory memory;
    u64 memoryOffset;
};

struct VkBindImageMemoryInfo
{
    VkImage image;
    VkDeviceMemory memory;
    u64 memoryOffset;
};

VkResult VkBindBufferMemory2(VkDevice dev, u32 count, const VkBindBufferMemoryInfo* infos);
VkResult VkBindImageMemory2(VkDevice dev, u32 count, const VkBindImageMemoryInfo* infos);

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

/// Spec-form descriptor write — same shape Vulkan callers
/// expect: an array of writes, each describing a (set, binding,
/// type, resource handle) tuple.  Internally this dispatches to
/// `VkUpdateDescriptorSet` per-element so the per-set write
/// counter increments correctly.
struct VkWriteDescriptorSet
{
    VkDescriptorSet dstSet;
    u32 dstBinding;
    VkDescriptorType type;
    u64 resourceHandle; // VkBuffer / VkImageView / VkSampler
};

VkResult VkUpdateDescriptorSets(VkDevice dev, u32 write_count, const VkWriteDescriptorSet* writes, u32 copy_count,
                                const void* copies);

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
// Sampler.
// -------------------------------------------------------------------
//
// Texture sampler — handle bookkeeping only.  No shader will
// actually read through the sampler in v0; the surface exists
// so a downstream caller's descriptor-set wiring lines up.

struct VkSamplerCreateInfo
{
    VkFilter magFilter;
    VkFilter minFilter;
    VkSamplerAddressMode addressModeU;
    VkSamplerAddressMode addressModeV;
    VkSamplerAddressMode addressModeW;
};

VkResult VkCreateSampler(VkDevice dev, const VkSamplerCreateInfo* info, VkSampler* out);
void VkDestroySampler(VkDevice dev, VkSampler sampler);

// -------------------------------------------------------------------
// Event.
// -------------------------------------------------------------------
//
// Host-signallable / device-signallable sync.  vkSet/Reset toggle
// the device-visible bit; vkGetEventStatus reads it; the cb-side
// CmdSetEvent / CmdResetEvent / CmdWaitEvents are recorded into
// the tape (no-op replay — there's no real GPU pipeline to gate).

VkResult VkCreateEvent(VkDevice dev, VkEvent* out);
void VkDestroyEvent(VkDevice dev, VkEvent event);
VkResult VkSetEvent(VkDevice dev, VkEvent event);
VkResult VkResetEvent(VkDevice dev, VkEvent event);
VkResult VkGetEventStatus(VkDevice dev, VkEvent event); // returns Success when set, NotReady when reset
VkResult VkCmdSetEvent(VkCommandBuffer cb, VkEvent event, u32 stage_mask);
VkResult VkCmdResetEvent(VkCommandBuffer cb, VkEvent event, u32 stage_mask);
VkResult VkCmdWaitEvents(VkCommandBuffer cb, u32 count, const VkEvent* events);

// -------------------------------------------------------------------
// Pipeline cache.
// -------------------------------------------------------------------
//
// Real Vulkan pipeline caches store compiled shader binaries so
// repeated vkCreateGraphicsPipelines calls don't recompile from
// SPIR-V.  Our v0 ICD doesn't compile, so the cache is a tracked
// handle only — Merge accepts source caches but writes nothing.
// GetData reports a 16-byte header (matches the spec's
// VkPipelineCacheHeaderVersionOne shape) so a caller's
// "round-trip the cache to disk" path doesn't trip.

VkResult VkCreatePipelineCache(VkDevice dev, const void* initial_data, u64 initial_size, VkPipelineCache* out);
void VkDestroyPipelineCache(VkDevice dev, VkPipelineCache cache);
VkResult VkMergePipelineCaches(VkDevice dev, VkPipelineCache dst, u32 src_count, const VkPipelineCache* sources);
VkResult VkGetPipelineCacheData(VkDevice dev, VkPipelineCache cache, u64* size, void* data);

// -------------------------------------------------------------------
// Query pool.
// -------------------------------------------------------------------
//
// Timestamp / occlusion queries.  Storage is a small array of
// u64 results per pool; vkCmdBeginQuery / vkCmdEndQuery /
// vkCmdResetQueryPool are recorded into the tape and replayed
// to update the result array.  vkGetQueryPoolResults copies
// out.  No real GPU is sampled — timestamps come from the
// kernel time source so the values move predictably across
// queries (good enough for the self-test to assert ordering).

enum class VkQueryType : u32
{
    Occlusion = 0,
    PipelineStatistics = 1,
    Timestamp = 2,
};

VkResult VkCreateQueryPool(VkDevice dev, VkQueryType type, u32 query_count, VkQueryPool* out);
void VkDestroyQueryPool(VkDevice dev, VkQueryPool pool);
VkResult VkResetQueryPool(VkDevice dev, VkQueryPool pool, u32 first_query, u32 query_count);
VkResult VkCmdResetQueryPool(VkCommandBuffer cb, VkQueryPool pool, u32 first_query, u32 query_count);
VkResult VkCmdBeginQuery(VkCommandBuffer cb, VkQueryPool pool, u32 query, u32 flags);
VkResult VkCmdEndQuery(VkCommandBuffer cb, VkQueryPool pool, u32 query);
VkResult VkCmdWriteTimestamp(VkCommandBuffer cb, u32 stage, VkQueryPool pool, u32 query);
VkResult VkGetQueryPoolResults(VkDevice dev, VkQueryPool pool, u32 first_query, u32 query_count, u64* data, u32 stride,
                               u32 flags);

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
    u32 vk_swapchain_acquires;   // total vkAcquireNextImageKHR calls
    u32 vk_swapchain_presents;   // total vkQueuePresentKHR calls
    u32 vk_buffer_copy_bytes;    // bytes moved by vkCmdCopyBuffer replay
    u32 vk_buffer_fill_bytes;    // bytes written by vkCmdFillBuffer replay
    u32 vk_push_constant_writes; // count of vkCmdPushConstants ops recorded
    u32 vk_pipeline_barriers;    // count of vkCmdPipelineBarrier ops recorded
    u32 vk_dispatches;           // count of vkCmdDispatch ops recorded
    u32 vk_image_upload_pixels;  // pixels uploaded by vkCmdCopyBufferToImage replay
    u32 vk_triangles_drawn;      // count of triangles dispatched to the software rasterizer by vkCmdDraw replay
    u32 vk_samplers_live;
    u32 vk_events_live;
    u32 vk_pipeline_caches_live;
    u32 vk_query_pools_live;
    u32 vk_queries_executed;           // total CmdEndQuery / CmdWriteTimestamp replays
    u32 vk_memory_maps;                // total VkMapMemory calls
    u32 vk_dynamic_renderings;         // total CmdBeginRendering replays
    u32 vk_debug_labels;               // total VkSetDebugUtilsObjectNameEXT calls
    u32 vk_secondary_executes;         // total VkCmdExecuteCommands replays
    u32 vk_secondary_ops_replayed;     // total ops replayed inside a secondary
    u32 vk_push_descriptor_writes;     // total VkCmdPushDescriptorSetKHR writes
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
