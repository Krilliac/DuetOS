# GPU Graphics Techniques — Part 1

> **Audience:** GPU driver authors, Vulkan ICD contributors, D3D translation
> layer maintainers
>
> **Scope:** Resolution management, textures, anti-aliasing, shadows, ambient
> occlusion, ray tracing — what each technique IS, what the hardware provides,
> what the DRIVER must implement, and what DuetOS specifically needs to build
>
> **Status:** Reference document; update as DuetOS GPU slices land

This page covers six core GPU graphics techniques from a **driver
implementer's** perspective. It is not a textbook — it focuses on
the register-level, command-buffer, and memory-management work that
a DuetOS GPU driver and Vulkan ICD must perform. Application-side
concerns (game engine shaders, render-graph design) are noted only
where they constrain or inform the driver interface.

For the current DuetOS GPU driver state, see
[Graphics Drivers](../drivers/Graphics-Drivers.md). For the Vulkan
ICD internals, see [Vulkan ICD](../subsystems/Vulkan-ICD.md). For
per-vendor prior art and bring-up gates, see
[GPU Implementation Notes](../reference/GPU-Implementation-Notes.md).

---

## 1. Resolution Management

### What it is

Resolution management covers the full pipeline from enumerating
what a display can show, through negotiating timings, to
programming the GPU's display engine to scan out at a chosen
resolution and refresh rate. In the Linux DRM/KMS model this is
called **modesetting**.

### Hardware display pipeline

Every modern GPU has a display engine separate from the 3D/compute
engines. The pipeline:

```
Framebuffer memory
    |
  Plane(s)         -- fetch pixel data, apply scaling/rotation/CSC
    |
  CRTC / Pipe      -- generates pixel clock + sync signals (h/v timing)
    |
  Encoder          -- converts digital pixel stream to a protocol
    |               (TMDS for HDMI, main-link for DP, LVDS, etc.)
  Connector/Port   -- physical output (HDMI, DP, eDP, VGA)
    |
  PHY              -- electrical signalling
```

**Intel** calls these Planes, Pipes, Transcoders, DDI ports, and
combo/TypeC PHYs. **AMD** uses Display Core Next (DCN) with
hubp (hub pipes), opp (output pixel processors), optc (output
timing controllers), and dio (display I/O). **NVIDIA** uses
nvdisplay with heads, SORs (serial output resources), and DPAUXs.

### Mode enumeration

The driver builds the list of valid display modes from three
sources:

1. **EDID** — 128-byte (+ extension blocks) binary blob read over
   DDC/I2C (HDMI/VGA) or DPCD AUX channel (DisplayPort). Contains
   established timings, standard timings, and detailed timing
   descriptors. CEA-861 extension blocks add the short video
   descriptors (SVDs) that list every CEA mode the display supports.
   DuetOS already parses EDID and CEA-861 — see
   `kernel/drivers/gpu/edid.{h,cpp}` and `cea861.{h,cpp}`.

2. **CVT (Coordinated Video Timings)** — an algorithm that
   generates pixel clock, h/v front-porch/sync/back-porch from
   just (width, height, refresh). Used when EDID doesn't list a
   desired mode explicitly. DuetOS has `kernel/drivers/gpu/cvt.cpp`.

3. **GTF (Generalised Timing Formula)** — older algorithm,
   superseded by CVT for flat panels. GTF can still be needed for
   legacy CRTs.

### What the driver must implement

**Mode validation:** not every EDID mode is achievable — the GPU's
PLLs have a discrete set of achievable pixel clocks. The driver
must compute whether a PLL configuration can hit the requested
pixel clock within tolerance (typically 0.5%). Intel documents
DPLL divisor tables in the PRM; AMD's DCN has `dce_clk_mgr` with
frequency tables; NVIDIA programs PLLs via GSP RPCs on Turing+.

**Modeset sequence (Intel Gen9-12 example):**

1. Disable the current plane (`PLANE_CTL` = 0, arm via
   `PLANE_SURF` write).
2. Disable the pipe (`PIPECONF` bit 31 = 0, wait for pipe-off via
   `PIPECONF` bit 30).
3. Disable the transcoder's DDI port (`DDI_BUF_CTL` bit 31 = 0).
4. Disable the PLL (`DPLL_CTRL1` / `DPLL_CFGCR1/2` on SKL).
5. Program new PLL parameters (divisors, SSC if needed).
6. Enable PLL, wait for lock (`DPLL_STATUS` lock bit).
7. Program transcoder timing registers (`HTOTAL`, `HBLANK`,
   `HSYNC`, `VTOTAL`, `VBLANK`, `VSYNC`, `PIPESRC`).
8. Map transcoder to DDI (`TRANS_DDI_FUNC_CTL`).
9. Enable DDI port (`DDI_BUF_CTL` bit 31 = 1).
10. Enable pipe (`PIPECONF` bit 31 = 1, wait for pipe-on).
11. Program plane registers (`PLANE_CTL` format+tiling,
    `PLANE_STRIDE`, `PLANE_OFFSET`, `PLANE_SIZE`), arm via
    `PLANE_SURF` = framebuffer GGTT address.
12. Wait for vblank to confirm the new mode is scanning out.

**AMD modeset (DCN):**
AMD's display engine is programmed through the DCN programming
model. The amdgpu kernel driver's `dc` (Display Core) component
handles: `hubp` (fetch from memory), `dpp` (pixel processing —
scaling, CSC, gamma), `opp` (output formatting — dither, bit
depth), `optc` (timing generator), and `dio` (HDMI/DP encoder).
Modesets go through `dc_commit_state()` which validates the entire
display state as an atomic transaction.

**NVIDIA modeset:**
On Turing+, display programming is mediated by GSP-RM. The host
driver sends RPC messages (`NV2080_CTRL_CMD_INTERNAL_DISPLAY_*`)
for mode changes. The actual register programming (head timing,
SOR configuration, DP link training) happens inside the GSP
firmware. nouveau's `nvkm/disp` implements the host side.

### The libdrm / DRM kernel interface

On Linux, modesetting goes through the DRM subsystem's **KMS
(Kernel Mode Setting)** interface:

- `DRM_IOCTL_MODE_GETRESOURCES` — enumerate CRTCs, encoders,
  connectors.
- `DRM_IOCTL_MODE_GETCONNECTOR` — get connector status (connected
  / disconnected), available modes, EDID property.
- `DRM_IOCTL_MODE_SETCRTC` — legacy single-CRTC modeset.
- `DRM_IOCTL_MODE_ATOMIC` — atomic modeset (preferred; all-or-
  nothing commit of a full display state).
- `DRM_IOCTL_MODE_ADDFB2` — register a framebuffer object with
  format + modifier (tiling).

libdrm is a thin userland wrapper around these ioctls. It provides
`drmModeGetResources()`, `drmModeSetCrtc()`, `drmModeAtomicCommit()`,
etc. The real work is in the kernel DRM driver.

### Vulkan WSI and display

Vulkan's WSI (Window System Integration) extensions handle the
connection between the rendering pipeline and display:

- `VK_KHR_surface` — abstract handle for a "thing to present to."
- `VK_KHR_swapchain` — double/triple buffering of presentable
  images.
- `VK_KHR_display` — direct-to-display mode (no window system),
  enumerating display modes and creating surfaces on physical
  outputs.
- `VK_EXT_display_control` — vsync control, display power state.

Mesa's WSI implementation (`src/vulkan/wsi/`) handles the
platform glue. On Linux/DRM, `wsi_drm.c` uses
`DRM_IOCTL_MODE_ADDFB2` + page-flip ioctls. On Windows, WSI goes
through DXGI underneath.

### What DuetOS needs

DuetOS already has:
- EDID + CEA-861 parsing
- CVT timing calculation
- virtio-gpu runtime modeset (`VirtioGpuResetScanout`)
- `DisplaySetMode()` coordinator in `modeset.{h,cpp}`
- Intel display plane reprogram (v0 — keeps firmware timings)

Still needed for real GPU modeset:
- **PLL programming** per vendor (the hard part — Intel DPLL
  divisor computation, AMD DFS clock calculation).
- **DDI/DP/HDMI link training** — establishing the physical link
  parameters.
- **Atomic modeset** — committing plane + CRTC + connector state
  as a single transaction (prevents tearing during mode changes).
- **Hotplug detection** — interrupt-driven connector state change
  notifications.
- **Multi-monitor** — assigning CRTCs to connectors with
  non-overlapping pixel clocks.

DuetOS does NOT need the full DRM/KMS ioctl surface. The kernel
owns modesetting directly; userland requests resolution changes
through `SYS_DISPLAY_SETMODE` and the kernel validates + commits.

---

## 2. Textures

### What it is

Textures are 2D (or 1D/3D/cube/array) images sampled by shaders
during rendering. The driver's job: manage texture memory layout,
configure the hardware's texture sampling units (TMUs / samplers),
and expose these through the Vulkan/D3D descriptor model.

### Memory layout and tiling

GPUs do not store textures in row-major (linear) order. They use
**tiled** layouts that improve spatial locality for 2D access
patterns:

**Intel tiling modes:**
- **Linear** — row-major, used for CPU-visible staging buffers.
- **X-tiling** — 512-byte rows, 8 rows per tile (4 KB tiles).
  Good for scanout and display planes. Legacy; Gen12+ prefers
  Y-tiling.
- **Y-tiling** — 128-byte rows, 32 rows per tile (4 KB tiles).
  Better 2D locality for 3D textures. Preferred for render
  targets and textures on Gen9+.
- **Yf-tiling (tile4)** — finer-grained Y variant for Gen12+.
- **Tile64** — Gen12.5+ (DG2/MTL) 64 KB tiles.

The tiling mode is encoded in the surface state descriptor and
in the GGTT/PPGTT PTE (for Intel, tiling fences or the tile
mode field in the PTE on Gen12+).

**AMD tiling (GFX9+):**
- **Linear** — row-major.
- **1D thinl** — micro-tiled only, 256-byte blocks. Used for
  1D textures and small buffers.
- **2D thinl** — micro-tiled + macro-tiled. The micro-tile is a
  small block (e.g. 8x8 pixels for 32bpp), and macro-tiles group
  micro-tiles into larger power-of-two blocks. AMD calls this the
  "swizzle mode" and encodes it in the surface descriptor.
- **3D** — 3D-optimised tiling for volume textures.

AMD's `addrlib` (address library) computes the exact byte offset
for any (x, y, mip, slice) coordinate given the swizzle mode and
surface dimensions. The open-source version lives in
`src/amd/addrlib/` in Mesa.

**NVIDIA tiling:**
- **Pitch-linear** — row-major.
- **Block-linear** — GOBs (Groups of Bytes, 64 bytes wide x
  varying height) tiled into larger blocks. Block height varies
  by mip level.
- Format-dependent: compressed textures use different GOB layouts.

### Texture formats

GPUs support a wide range of pixel formats. The ones that matter
most for a driver implementer:

**Uncompressed:** R8, RG8, RGBA8, BGRA8, R16F, RGBA16F, R32F,
RGBA32F, R11G11B10F, RGB10A2, D16, D24S8, D32F, D32FS8.

**Block-compressed (BCn / DXT):**

| Format | Block | Bits/pixel | Use case |
|--------|-------|------------|----------|
| BC1 (DXT1) | 4x4 | 4 bpp | RGB, 1-bit alpha |
| BC2 (DXT3) | 4x4 | 8 bpp | RGB + sharp alpha |
| BC3 (DXT5) | 4x4 | 8 bpp | RGB + smooth alpha |
| BC4 (ATI1) | 4x4 | 4 bpp | Single channel (normals) |
| BC5 (ATI2) | 4x4 | 8 bpp | Two channels (normals) |
| BC6H | 4x4 | 8 bpp | HDR RGB (float) |
| BC7 | 4x4 | 8 bpp | High-quality RGBA |

**ASTC (Adaptive Scalable Texture Compression):**
Variable block sizes from 4x4 to 12x12. Required by Vulkan on
mobile (Android). Desktop GPUs support it on Intel Gen9+ and AMD
GFX9+; NVIDIA support varies. Block sizes and bit rates are
configurable per-texture.

**What the driver does with formats:**
The hardware decodes block-compressed textures in the texture
sampling unit — no driver-side decompression needed. The driver
must:
1. Encode the format enum into the surface state / texture
   descriptor.
2. Compute the correct pitch / alignment for compressed blocks
   (pitch is in blocks, not pixels — a 128x128 BC1 texture has
   a pitch of 32 blocks, each 8 bytes = 256 byte pitch).
3. Report supported formats via `vkGetPhysicalDeviceFormatProperties`.

### Mipmaps

A mipmap chain is a sequence of progressively halved copies of a
texture: level 0 is the full resolution, level 1 is half, etc.,
down to 1x1. The hardware selects the appropriate level based on
the projected screen-space size of the textured surface.

**Memory layout:** all mip levels are stored contiguously in the
same allocation. The driver computes the offset and pitch of each
level. For tiled textures, each level may need different alignment
depending on the tile format. Intel uses a "mip tail" region where
the smallest levels are packed into a single tile. AMD's addrlib
computes per-level offsets factoring in the swizzle mode.

**Driver responsibilities:**
- Compute per-level byte offset and row pitch during
  `vkCreateImage` / `CreateTexture2D`.
- Fill the surface state / descriptor with base address + per-level
  offset table.
- Set `baseMipLevel` and `levelCount` in image views so the
  sampler can select the correct range.
- Report `maxMipLevels = floor(log2(max(w,h,d))) + 1` as a device
  limit.

### Texture sampling hardware (TMUs)

The Texture Mapping Unit is fixed-function hardware that, given a
(u, v) coordinate and a sampler configuration, fetches and filters
texels. The driver configures:

**Sampler state:**
- **Filter mode:** nearest (point), bilinear, trilinear
  (bilinear + mip interpolation), anisotropic.
- **Address mode:** repeat (wrap), mirrored repeat, clamp to edge,
  clamp to border.
- **Anisotropic max:** 1x-16x. Hardware computes the anisotropy
  ratio from screen-space derivatives (dFdx/dFdy of texture
  coords) and takes multiple bilinear samples along the axis of
  greatest compression.
- **LOD bias / clamp:** offset the automatic mip level selection.
- **Compare function:** for depth/shadow textures, compare the
  sampled depth against a reference value (used for PCF — see
  Shadows section).
- **Border colour:** for clamp-to-border mode.

**How it works in hardware:** the shader issues a texture sample
instruction. The TMU receives the coordinates, computes the LOD
from screen-space derivatives (or uses an explicit LOD), fetches
2-8 texels from the appropriate mip level(s), applies the filter
kernel, and returns the result. For anisotropic filtering, the TMU
takes up to `maxAniso` bilinear samples along the anisotropy axis,
averaging them. This is entirely fixed-function — the driver just
configures the sampler state.

### Texture descriptors in Mesa drivers

**RADV (AMD Vulkan):**
AMD GFX9+ uses a 256-bit (8-DWORD) image descriptor called an
SQ_IMG_RSRC. It encodes: base address (bits 0-39 of DWORD0-1),
format (DWORD1 bits 20-25 + data format), width/height/depth,
number of mip levels, tiling/swizzle mode, texture type (1D/2D/3D/
cube), and BC swizzle. The driver fills this descriptor in
`radv_make_texture_descriptor()` and uploads it to a descriptor
buffer that the shader references via a user-data SGPR.

Sampler state is a separate 128-bit (4-DWORD) SQ_IMG_SAMP
descriptor: clamp modes, filter modes, LOD bias/clamp, aniso
ratio, border colour, depth compare function.

**ANV (Intel Vulkan):**
Intel uses SURFACE_STATE (16 DWORDs / 64 bytes on Gen9+) and
SAMPLER_STATE (4 DWORDs / 16 bytes). SURFACE_STATE encodes the
surface base address (via a binding table pointing into the surface
state heap), format, tiling mode, dimensions, mip range, array
range. SAMPLER_STATE encodes filter, address mode, LOD, aniso,
compare. The binding table + surface state + sampler state are
populated into a state heap that the hardware indexes via binding
table indices emitted in 3DSTATE_BINDING_TABLE_POINTERS.

**NVK (NVIDIA Vulkan):**
NVIDIA uses TIC (Texture Image Control) entries — 8 DWORDs / 32
bytes per texture, encoding address, format, dimensions, mip
range, tiling parameters. TSC (Texture Sampler Control) entries —
8 DWORDs / 32 bytes per sampler. TIC and TSC entries live in a
descriptor pool; shaders reference them by index.

### What DuetOS needs

DuetOS currently has:
- SPIR-V `OpImageSampleImplicitLod` / `OpImageSampleExplicitLod`
  with bilinear filtering and address modes (REPEAT, MIRRORED,
  CLAMP_TO_EDGE, CLAMP_TO_BORDER) in the CPU interpreter.
- `VkCreateSampler` records sampler state into `SamplerRecord`.
- No mipmap chain support (single-level images only).
- Software texture sampling (CPU-side, in the SPIR-V executor).

Still needed:
- **Mipmap chain layout computation** — per-format, per-tiling-mode
  offset/pitch calculations.
- **Per-vendor texture descriptor encoding** — SQ_IMG_RSRC for AMD,
  SURFACE_STATE for Intel, TIC for NVIDIA.
- **Tiled memory support** — at minimum linear + one tiled mode per
  vendor (Intel Y-tile, AMD 2D thin, NVIDIA block-linear).
- **BCn format decode** — for the CPU software path, a simple
  BC1-BC7 block decoder; for GPU paths, just set the format enum.
- **LOD computation** — screen-space derivative based mip level
  selection in the SPIR-V interpreter (currently `OpDPdx`/`OpDPdy`
  return zero, blocking automatic LOD).

---

## 3. Anti-Aliasing

### What it is

Anti-aliasing reduces the jagged edges ("jaggies") caused by
rasterising continuous geometry onto a discrete pixel grid. The
techniques fall into two categories: **geometry-based** (operate
during rasterisation) and **post-process** (operate on the final
image).

### MSAA (Multisample Anti-Aliasing)

**How it works:** each pixel is sampled at multiple sub-pixel
locations (2x, 4x, 8x, 16x). The rasteriser evaluates triangle
coverage at each sample position but runs the fragment shader only
once per pixel (at the pixel centre). Samples inside the triangle
get the shader's colour; samples outside keep their previous value.
The result is resolved (averaged) to produce the final pixel
colour.

**What the hardware provides:**
- **Sample positions:** fixed or programmable per-pixel sample
  locations. Standard patterns defined by D3D/Vulkan specs.
  Programmable positions via `VK_EXT_sample_locations`.
- **Coverage mask:** per-pixel bitmask of which samples are covered
  by the triangle. Hardware rasteriser produces this.
- **MSAA render targets:** each pixel stores N colour values + N
  depth/stencil values. A 4x MSAA 1920x1080 RGBA8 target uses
  4x the memory of a non-MSAA target.
- **Resolve operation:** dedicated hardware or shader-based
  averaging of N samples into one pixel. Intel and AMD have
  fixed-function resolve units; NVIDIA does it via a blit.

**What the driver must implement:**
1. **MSAA surface allocation:** multiply the surface size by the
   sample count. Account for per-vendor alignment requirements
   (AMD requires CMASK + FMASK auxiliary surfaces for fast MSAA
   clear and resolve).
2. **Sample position programming:** write the standard sample
   pattern to hardware registers or surface state.
3. **Render target state:** encode the sample count into the
   render target descriptor / surface state.
4. **Resolve path:** either trigger a hardware resolve blit or
   emit a fullscreen shader pass that reads from the MSAA surface
   and averages.
5. **Report capabilities:** `vkGetPhysicalDeviceProperties` must
   report `framebufferColorSampleCounts`,
   `framebufferDepthSampleCounts`.

**MSAA in Mesa drivers:**
- **RADV:** AMD hardware uses FMASK (fast fragment mask) and CMASK
  (colour compression metadata) surfaces alongside the MSAA colour
  buffer. FMASK maps sample indices to fragment indices — when all
  samples share the same colour, only one fragment is stored,
  saving bandwidth. CMASK tracks per-tile clear state for fast
  clears. The resolve path uses a compute shader
  (`radv_meta_resolve_cs.c`).
- **ANV:** Intel uses CCS (Colour Compression State) auxiliary
  surfaces for MSAA. MCS (Multisample Control Surface) stores
  per-sample metadata. ANV allocates these alongside the main
  surface in `anv_image.c`.

### FXAA (Fast Approximate Anti-Aliasing)

**How it works:** a post-process fullscreen shader pass that
detects edges by comparing luma contrast between neighbouring
pixels, then blurs along the detected edge direction. It operates
on the final image — no MSAA render targets needed.

**What the driver needs to provide:** nothing FXAA-specific. FXAA
is a standard fragment shader that reads from a sampled image and
writes to another. The driver needs:
- Working texture sampling (bilinear filter).
- Render-to-texture capability.
- Fullscreen triangle / quad rendering.

FXAA is entirely application-side. The driver's job is to make
texture sampling and render passes fast.

### TAA (Temporal Anti-Aliasing)

**How it works:** each frame is rendered with a sub-pixel jitter
offset applied to the projection matrix. Over multiple frames, the
jitter positions cover the pixel area. A resolve pass combines the
current frame with the history buffer (previous frame's resolved
output), using motion vectors to reproject the history to the
current frame's perspective. The result is an effectively
supersampled image accumulated over time.

**What the driver needs to provide:**
- **Motion vectors:** hardware support for writing per-pixel
  velocity to a render target during the geometry pass. D3D12
  and Vulkan expose this as a standard output from the vertex/
  geometry shader — no special driver support beyond the normal
  render target mechanism. However, the driver must support
  `VK_FORMAT_R16G16_SFLOAT` or similar as a render target format.
- **Sub-pixel jitter:** application-side (modify the projection
  matrix). No driver involvement.
- **History buffer management:** application-side. The driver
  just needs to support keeping two full-resolution render
  targets alive simultaneously.

TAA is application-side. The driver's contribution is fast texture
sampling, motion-vector render targets, and efficient render-to-
texture.

### SMAA (Subpixel Morphological Anti-Aliasing)

**How it works:** a multi-pass post-process technique. Pass 1
detects edges (luma or colour-based). Pass 2 computes blending
weights using lookup textures that encode analytically precomputed
coverage patterns. Pass 3 blends neighbours according to the
computed weights. Produces higher quality than FXAA with similar
performance characteristics.

**What the driver needs to provide:**
- Texture sampling.
- Render-to-texture.
- Pre-computed lookup textures (application provides the data;
  the driver just needs `vkCreateImage` + `vkUpdateDescriptorSets`
  to work correctly for R8/RG8 formats).

SMAA is application-side. Like FXAA, the driver provides the
rendering infrastructure.

### What DuetOS needs

For anti-aliasing support in the Vulkan ICD:

- **MSAA (driver-side):** the v0 software rasteriser currently
  has no multisampling. Adding MSAA to the CPU rasteriser would
  mean running coverage tests at N sample positions per pixel
  and maintaining per-sample colour/depth buffers. For real GPU
  paths, the driver needs per-vendor MSAA surface state encoding
  + resolve operations. This is a mid-priority item — MSAA is
  mandatory for Vulkan conformance.
- **FXAA/TAA/SMAA (application-side):** these work automatically
  once the Vulkan ICD supports texture sampling + render-to-
  texture + fullscreen draw. The SPIR-V interpreter already handles
  `OpImageSampleImplicitLod`; the remaining gap is render-to-
  texture (creating a `VkFramebuffer` backed by a regular image,
  not just the scanout surface).

---

## 4. Shadows

### What it is

Real-time shadows in 3D graphics are almost universally implemented
via **shadow mapping**: render the scene from the light's point of
view into a depth-only buffer (the shadow map), then during the
main render pass, project each fragment into the light's space and
compare its depth against the stored shadow-map depth. If the
fragment is farther than the stored value, it is in shadow.

### What the driver provides vs what is application-side

Shadow mapping is **overwhelmingly application-side**. The
application sets up the light-space projection, renders the depth
pass, and writes the comparison shader. The driver's role is to
provide the infrastructure:

**Driver-side requirements:**

1. **Depth render targets:** the driver must support creating images
   with depth-only formats:
   - `VK_FORMAT_D16_UNORM` — 16-bit depth, smallest shadow maps.
   - `VK_FORMAT_D32_SFLOAT` — 32-bit float depth, highest
     precision, recommended for large scenes.
   - `VK_FORMAT_D24_UNORM_S8_UINT` — 24-bit depth + 8-bit stencil.
   - `VK_FORMAT_D32_SFLOAT_S8_UINT` — 32-bit depth + 8-bit stencil.

   DuetOS already has a 16-bit software depth surface
   (`graphics_vk_depth.cpp`). D32F is needed for production
   shadow maps.

2. **Depth comparison samplers:** the sampler hardware can compare
   a reference depth value against the stored depth and return a
   0.0 or 1.0 result. This is **PCF (Percentage-Closer Filtering)**
   at the hardware level:

   ```
   VkSamplerCreateInfo sampler = {
       .compareEnable = VK_TRUE,
       .compareOp = VK_COMPARE_OP_LESS_OR_EQUAL,
       .magFilter = VK_FILTER_LINEAR,  // hardware PCF
   };
   ```

   With `compareEnable` and a linear filter, the hardware samples
   4 neighbouring depth texels, compares each against the reference
   depth, and returns the average of the 0/1 results. This gives
   2x2 PCF for free in hardware — no shader work. The shader uses
   `texture(shadowSampler, vec3(uv, refDepth))` which maps to
   SPIR-V `OpImageSampleDrefImplicitLod`.

   **This is the single most important shadow-related driver feature.**
   Without hardware depth comparison, applications must do per-texel
   comparisons in the shader, which is significantly slower.

3. **Depth bias:** hardware-applied offset to depth values during
   the shadow-map render pass, preventing self-shadowing artifacts
   ("shadow acne"). Configured via `vkCmdSetDepthBias()` /
   `VkPipelineRasterizationStateCreateInfo::depthBias*`. The
   rasteriser applies `depth += constantFactor + slopeFactor *
   maxDepthSlope` per fragment. This is fixed-function hardware
   on all modern GPUs.

4. **Render-to-texture:** the shadow map must be renderable as a
   depth attachment and then samplable as a texture in the main
   pass. This requires image layout transitions
   (`VK_IMAGE_LAYOUT_DEPTH_STENCIL_ATTACHMENT_OPTIMAL` to
   `VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL`) and correct
   synchronization.

**Application-side (NOT the driver's problem):**
- Shadow map projection matrix setup.
- Cascaded Shadow Maps (CSM) — splitting the view frustum into
  distance-based cascades with one shadow map per cascade. The
  driver just sees N depth render passes + N texture bindings.
- Variance Shadow Maps (VSM), Moment Shadow Maps (MSM) — store
  depth moments instead of raw depth. Uses standard RGBA render
  targets; no special driver support.
- Shadow filtering beyond hardware PCF (Poisson disk sampling,
  PCSS for variable-width penumbras) — application shader work.

### Shadow buffer memory management

Shadow maps are typically large: a 4096x4096 D32F shadow map is
64 MB. Cascaded shadow maps (3-4 cascades) multiply that. The
driver must support:
- Efficient depth-only render target allocation.
- Fast depth clears (AMD uses htile metadata for fast clears;
  Intel uses HiZ; NVIDIA uses ZBC — all enable clearing depth
  without touching every texel).
- Depth compression — AMD's htile, Intel's HiZ/CCS, NVIDIA's
  ZBC all compress depth data to reduce memory bandwidth. These
  are transparent to the application but the driver must allocate
  the auxiliary metadata surfaces and program the hardware to
  use them.

### What DuetOS needs

1. **D32F depth format** — extend the existing D16 software depth
   surface to support 32-bit float depth.
2. **Depth comparison in sampler** — implement `compareEnable` in
   the SPIR-V interpreter's texture sampling path. When the
   sampler has comparison enabled, `OpImageSampleDrefImplicitLod`
   should compare the fetched depth against the reference value
   and return the comparison result. Hardware depth comparison
   will come with real GPU sampler programming.
3. **Depth bias in rasteriser** — add `depthBias` state to the
   software rasteriser's pipeline state.
4. **Render-to-depth** — support creating `VkFramebuffer` with a
   depth-only attachment (not just colour + depth).

---

## 5. Ambient Occlusion

### What it is

Ambient occlusion (AO) approximates the darkening that occurs in
creases, crevices, and areas where geometry occludes ambient light.
Screen-space techniques (SSAO, HBAO, GTAO) compute this from the
depth buffer in a post-process pass, without needing scene geometry
information.

### Techniques

**SSAO (Screen-Space Ambient Occlusion):**
For each pixel, sample N random points in a hemisphere oriented
along the surface normal. For each sample point, project it to
screen space and compare its depth with the depth buffer. Points
that are behind geometry (depth buffer is closer) contribute
occlusion. Average the occlusion over all samples.

GPU features required:
- Depth buffer access as a texture.
- Normal buffer (or reconstruct normals from depth via `dFdx`/
  `dFdy`).
- Random/noise texture for sample jittering (to reduce banding
  with fewer samples).
- Blur pass to smooth the noisy raw AO result.

**HBAO / HBAO+ (Horizon-Based Ambient Occlusion):**
Instead of random hemisphere samples, HBAO ray-marches along
screen-space directions to find the horizon angle. For each pixel,
it traces rays in several screen-space directions and uses the
depth buffer to find the highest occluding angle (the horizon).
The occlusion for each direction is `sin(horizon) - sin(tangent)`.
This produces more physically plausible results than SSAO.

GPU features required: same as SSAO. HBAO is purely a shader
technique — it makes more sophisticated use of the same depth
buffer data. NVIDIA's HBAO+ library uses compute shaders for the
ray-march + interleaved rendering for cache efficiency.

**GTAO (Ground-Truth Ambient Occlusion):**
A refinement of HBAO that uses the full cosine-weighted integral
over the visible horizon rather than a simplified sine difference.
GTAO also integrates a multi-bounce approximation (ambient light
bouncing between occluding surfaces) with a simple empirical
formula. Compute-shader-based.

GPU features required:
- Compute shaders.
- `groupshared` / `shared` memory for tile-based processing.
- Depth buffer as a storage image or sampled image.
- Often uses a half-resolution AO buffer for performance, then
  bilateral upsample.

### What the driver provides

All AO techniques are **application-side post-process shaders**.
The driver provides:

1. **Depth buffer as a texture** — the application must be able to
   bind the depth attachment as a sampled image in a subsequent
   pass. Requires image layout transition support.
2. **Compute shader dispatch** — `vkCmdDispatch` for HBAO+/GTAO.
   The SPIR-V interpreter already handles basic compute dispatch.
3. **Shared memory** for compute shaders (`OpVariable` with
   `Workgroup` storage class). Currently a gap in the SPIR-V
   interpreter.
4. **Screen-space derivatives** — `dFdx`/`dFdy` for normal
   reconstruction from depth. Currently returns zero in the SPIR-V
   interpreter (noted in GPU Implementation Notes).
5. **Noise/random textures** — just standard texture creation and
   sampling; no special driver support.

### What DuetOS needs

AO techniques are post-process shaders. They will work once the
Vulkan ICD supports:
- Render-to-texture (binding a rendered depth buffer as a
  sampled image).
- Compute shaders with shared memory (`Workgroup` storage class
  in SPIR-V).
- Screen-space derivatives (`OpDPdx`/`OpDPdy` — requires 2x2
  quad fragment execution in the SPIR-V interpreter).

None of these are AO-specific — they are general Vulkan features
that many techniques depend on. The priority order is render-to-
texture first (unblocks shadows + AO + reflections + bloom + every
other post-process), then compute shared memory, then derivatives.

---

## 6. Ray Tracing

### What it is

Ray tracing computes light transport by tracing rays through a
scene and testing for intersections with geometry. Real-time ray
tracing uses dedicated hardware acceleration structures (BVH —
Bounding Volume Hierarchy) and specialised shader stages.

### Hardware

**NVIDIA RT Cores (Turing, Ampere, Ada Lovelace, Blackwell):**
Dedicated fixed-function units that traverse BVH trees and test
ray-triangle / ray-box intersections. The shader issues a
`traceRay` instruction; the RT core traverses the BVH autonomously
and returns the closest hit (or miss) to the shader. Each SM
(Streaming Multiprocessor) has RT cores that operate concurrently
with the CUDA/shader cores.

On Turing (first generation), RT cores handle BVH traversal and
ray-box intersection in hardware; ray-triangle intersection falls
back to shader execution. On Ampere+, both ray-box and ray-
triangle are fully hardware-accelerated, roughly doubling RT
performance.

**AMD Ray Accelerators (RDNA 2, RDNA 3, RDNA 4):**
Each Compute Unit (CU) includes a Ray Accelerator that handles
BVH traversal and ray-box intersection. On RDNA 2, ray-triangle
intersection is shader-computed. On RDNA 3+, ray-triangle
intersection is also hardware-accelerated. The instruction is
`image_bvh_intersect_ray` / `image_bvh64_intersect_ray` — it
takes a ray origin, direction, and BVH node pointer and returns
intersection results.

**Intel Ray Tracing (Xe HPG / Arc):**
Each Xe core includes ray tracing units. Intel's approach uses a
"thread-spawning" model: the hardware traverses the BVH and spawns
shader threads at hit/miss points rather than returning results to
the calling shader. This reduces register pressure but requires
different driver scheduling.

### Acceleration Structures

A BVH (Bounding Volume Hierarchy) is a tree of axis-aligned
bounding boxes (AABBs). Internal nodes contain AABBs that bound
their children. Leaf nodes contain triangles (or custom
intersection primitives). Two levels:

- **BLAS (Bottom-Level Acceleration Structure):** contains the
  geometry of one object (mesh). Multiple BLAS can share geometry
  data (instancing).
- **TLAS (Top-Level Acceleration Structure):** contains instances
  of BLAS with per-instance transforms, shader binding table
  offsets, and instance masks. One TLAS per scene.

**What the driver must implement for acceleration structures:**

1. **Build:** compute the BVH from input geometry. This is a GPU
   compute workload — the driver emits compute shader dispatches
   (or vendor-specific build commands) that read vertex/index
   data and produce the BVH node tree. The internal BVH format is
   vendor-specific and opaque to the application.

   - **RADV (AMD):** builds BVH on the GPU using a compute shader
     pipeline. The build process: (1) encode leaf nodes from
     geometry, (2) compute Morton codes for spatial sorting, (3)
     radix sort the primitives, (4) build internal nodes via the
     LBVH (Linear BVH) algorithm, (5) optionally refit/compact.
     The BVH node format is RADV's own internal layout, matching
     what `image_bvh_intersect_ray` expects.

   - **ANV (Intel):** uses a similar GPU-driven build pipeline.
     The BVH format must match Intel's hardware traversal unit
     expectations.

   - **NVK (NVIDIA):** NVIDIA's proprietary BVH format. On
     open-source NVK, the build is done via compute shaders that
     emit the hardware-expected node layout.

2. **Memory management:** acceleration structures are GPU-visible
   buffers. The driver must:
   - Report build-time size requirements
     (`vkGetAccelerationStructureBuildSizesKHR`).
   - Allocate device memory for the structure.
   - Handle scratch memory for the build process.
   - Support compaction (`VK_BUILD_ACCELERATION_STRUCTURE_ALLOW_COMPACTION_BIT`)
     to reclaim unused space after build.

3. **Update:** for animated geometry, the application can request
   a refit (update bounding boxes without rebuilding the tree
   structure). The driver must support both full rebuilds and
   refits.

### RT pipeline state

The Vulkan ray tracing pipeline
(`VK_KHR_ray_tracing_pipeline`) introduces new shader stages:

| Stage | Purpose |
|-------|---------|
| Ray Generation | Entry point — launches rays |
| Closest Hit | Invoked for the nearest intersection |
| Any Hit | Invoked for every potential intersection (alpha test) |
| Miss | Invoked when a ray hits nothing |
| Intersection | Custom intersection test (for non-triangle geometry) |
| Callable | Utility function callable from other RT shaders |

**Shader Binding Table (SBT):**
A GPU buffer containing shader group handles + per-group data. The
SBT maps (instance, geometry, ray type) tuples to shader groups.
The driver must:
- Compile each RT shader stage.
- Link shader groups (closest-hit + any-hit + intersection form
  a "hit group").
- Write shader handles (vendor-specific opaque data) into the SBT
  buffer at application-specified offsets.
- Report `shaderGroupHandleSize` and `shaderGroupHandleAlignment`.

**How `vkCmdTraceRaysKHR` works:**
The application specifies SBT regions for raygen, miss, hit, and
callable. The driver launches a raygen shader grid. Each raygen
invocation can call `traceRayEXT()` (GLSL) / `OpTraceRayKHR`
(SPIR-V), which triggers hardware BVH traversal. On intersection
or miss, the hardware (or driver) invokes the corresponding SBT
shader.

### How open-source drivers implement RT

**RADV (AMD RDNA 2+):**
RADV was the first open-source driver to ship Vulkan ray tracing.
Key implementation details:
- BVH is built entirely with compute shaders (no
  hardware-specific build command).
- The BVH node format stores box nodes (internal) and triangle
  nodes (leaf) in a flat buffer. Box nodes contain 4 child AABBs
  (BVH4 — each internal node has up to 4 children, reducing tree
  depth).
- `image_bvh_intersect_ray` is the ISA instruction that the
  Ray Accelerator executes. It takes a ray + node pointer and
  returns intersection results (child node indices + distances).
- The traversal loop is a shader loop: fetch node, call
  `image_bvh_intersect_ray`, push children onto a stack, repeat
  until a leaf is reached or the stack is empty. The Ray
  Accelerator handles the per-node math; the shader handles the
  traversal logic.
- SBT lookup uses a formula: `sbt_offset + sbt_stride *
  (instance.sbtOffset + geometry_index * sbt_stride_multiplier)`.
- RT pipeline compilation generates a monolithic shader that
  inlines the traversal loop, all hit/miss shaders, and the SBT
  dispatch logic into a single compute-like dispatch.
- `VK_KHR_ray_query` (inline RT in any shader stage) is also
  supported — the same traversal loop is inserted into the
  calling shader.

**ANV (Intel Arc):**
- Intel's hardware traversal unit is async — it spawns shader
  threads at hit/miss points.
- The driver sets up a "BTD" (Bindless Thread Dispatch) region
  that maps SBT entries to shader kernels.
- BVH build uses compute shaders similar to RADV.

**NVK (NVIDIA):**
- NVK's RT support is newer. NVIDIA hardware does full traversal
  + intersection in the RT cores; the driver just sets up the
  BVH, SBT, and launches the RT pipeline.
- NVIDIA's BVH format is documented in the open kernel modules
  only partially — the build algorithm itself is still largely
  opaque.

### DXR (DirectX Raytracing) translation

VKD3D-Proton translates D3D12 DXR calls to Vulkan RT:
- `ID3D12Device5::CreateRaytracingPipelineState` maps to
  `vkCreateRayTracingPipelinesKHR`.
- `DispatchRays` maps to `vkCmdTraceRaysKHR`.
- DXIL ray tracing shaders are translated to SPIR-V via
  dxil-spirv (part of VKD3D-Proton).
- Acceleration structure builds map 1:1 from D3D12's
  `BuildRaytracingAccelerationStructure` to
  `vkCmdBuildAccelerationStructuresKHR`.

DuetOS's D3D12 translation layer will need to implement the same
mapping once the Vulkan ICD supports `VK_KHR_ray_tracing_pipeline`.

### What DuetOS needs

Ray tracing is a longer-term goal. The dependency chain:

1. **Real GPU compute dispatch** — RT BVH builds are compute
   workloads. The SPIR-V interpreter handles basic compute; real
   GPU compute submission is the prerequisite.
2. **Per-vendor ISA compilation** — RT shaders need to compile to
   actual GPU ISA (AMD GCN/RDNA shader ISA, Intel EU ISA, NVIDIA
   SM ISA). The current SPIR-V interpreter cannot run RT workloads
   at viable performance.
3. **BVH build pipeline** — compute shaders for LBVH construction.
   This is vendor-agnostic (runs on the compute pipe) but needs
   working compute with atomics, shared memory, and indirect
   dispatch.
4. **Hardware traversal instruction support** — AMD's
   `image_bvh_intersect_ray`, Intel's BTD, NVIDIA's RT core
   instructions must be encoded in the vendor-specific command
   buffer.
5. **SBT management** — shader handle generation, SBT buffer
   layout, and the SBT lookup formula.
6. **RT pipeline compilation** — linking raygen/hit/miss/
   intersection stages into a dispatchable pipeline.

Realistic timeline: RT support depends on a working GPU compute
pipeline with real ISA compilation. It is post-Vulkan-1.1-
conformance work. For early testing, a CPU-traced fallback
(software BVH traversal in the SPIR-V interpreter) could validate
the API surface without GPU hardware.

---

## Summary: driver-side vs application-side

| Technique | Driver-side | Application-side |
|-----------|-------------|------------------|
| Resolution management | PLL programming, modeset sequencing, EDID parsing, plane/CRTC/DDI state | Requesting a mode, UI for mode selection |
| Textures | Tiled memory layout, descriptor encoding, format support, sampler state HW programming | Texture content, UV mapping, shader sampling logic |
| MSAA | MSAA surface allocation, sample positions, auxiliary surfaces (FMASK/CCS/HiZ), resolve | Requesting MSAA sample count, MSAA-aware shaders |
| FXAA / TAA / SMAA | Nothing specific | Everything (post-process shaders) |
| Shadows | Depth render targets, depth comparison samplers, depth bias, depth compression (htile/HiZ/ZBC) | Shadow map passes, CSM cascade splitting, filtering shaders |
| Ambient Occlusion | Nothing specific (relies on compute, depth access, derivatives) | Everything (screen-space compute/fragment shaders) |
| Ray Tracing | BVH build, acceleration structure memory, hardware traversal instructions, SBT, RT pipeline compilation | Scene setup, ray generation shaders, hit/miss shaders, denoising |

---

## Related Pages

- [Graphics Drivers](../drivers/Graphics-Drivers.md) — per-vendor
  driver scaffolds and bring-up state.
- [Vulkan ICD](../subsystems/Vulkan-ICD.md) — in-kernel Vulkan
  implementation details.
- [GPU Implementation Notes](../reference/GPU-Implementation-Notes.md)
  — per-vendor prior art, register-level detail, and next gates.
- [DirectX](../subsystems/DirectX.md) — D3D translation layer
  state (D3D9/11/12).
- [Compositor](../subsystems/Compositor.md) — window manager and
  display compositor.
- [EDID](../drivers/EDID.md) — EDID parsing details.
