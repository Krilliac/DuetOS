# GPU Graphics Techniques — Part 2 (Driver Implementation Reference)

> **Audience:** DuetOS GPU driver authors
>
> **Scope:** Upscaling, VSync/frame pacing, HDR, motion blur,
> post-processing, and level-of-detail — from the **driver and
> hardware register** perspective, not the application perspective.
> Part 1 covers resolution/EDID, texture formats, anti-aliasing,
> shadow mapping, ambient occlusion, and ray tracing.

---

## 1. Upscaling (DLSS, FSR, XeSS)

Upscaling renders at a lower internal resolution then reconstructs a
higher-resolution output.  From the driver's perspective the key
question is: where does the reconstruction run, and what hardware
resources does it consume?

### NVIDIA DLSS (Deep Learning Super Sampling)

DLSS runs on **Tensor Cores**, not shader ALUs.  The driver's role:

- **Model loading.**  DLSS models ship as encrypted blobs
  (`nvngx_dlss.dll` on Windows).  The driver loads the model into
  GPU VRAM via the NGX framework.  Model selection is keyed on
  (resolution, quality-preset, game-profile).
- **Tensor Core dispatch.**  The driver submits inference workloads
  to the Tensor Core pipeline.  On Turing this shares SM occupancy
  with graphics; on Ampere+ dedicated Tensor Core scheduling reduces
  contention.
- **Inputs the driver must wire:**
  - Low-resolution colour buffer (the rendered frame).
  - Motion vectors (per-pixel screen-space velocity, 16-bit float RG).
  - Depth buffer (reverse-Z float).
  - Exposure / auto-exposure value.
  - Jitter offsets (the sub-pixel jitter applied to the projection
    matrix each frame — DLSS uses temporal accumulation across
    jittered samples).
- **Output.**  A single upscaled colour buffer at the display
  resolution, written to a driver-allocated render target.
- **Frame Generation (DLSS 3+).**  An additional Optical Flow
  Accelerator (OFA) engine generates an interpolated frame between
  two rendered frames.  The driver submits to the OFA unit via a
  dedicated command queue and synchronises the interpolated frame
  into the present queue.

### AMD FSR (FidelityFX Super Resolution)

FSR 1.0 is a **spatial-only** upscaler — a single compute shader
dispatch.  FSR 2.0+ is temporal, requiring motion vectors and depth.

- **FSR 1.0 (EASU + RCAS).**  Two compute passes:
  1. EASU (Edge-Adaptive Spatial Upsampling): samples the low-res
     input with a Lanczos-derived kernel that adapts to detected
     edges.  One dispatch, `ceil(outW/16) × ceil(outH/16)` thread
     groups.
  2. RCAS (Robust Contrast-Adaptive Sharpening): a sharpening pass
     on the upscaled output.  Same dispatch dimensions.
  The driver provides the compute shader (HLSL/GLSL source is open;
  compile to SPIR-V or DXBC).  No special hardware — runs on any
  GPU with compute shader support.
- **FSR 2.0+ (temporal).**  Multiple compute passes:
  - Depth-clip, motion-vector preparation.
  - Luminance-instability detection.
  - Accumulation (temporal blend of current + history).
  - Sharpening (RCAS).
  The driver must allocate persistent history buffers (one per
  swapchain image) and manage their lifetime across frames.
  Motion vectors and jitter offsets are required inputs.
- **FSR 3 Frame Generation.**  Like DLSS 3, generates an
  interpolated frame.  Runs as compute shaders (no dedicated
  hardware).  The driver inserts the generated frame into the
  present queue between real frames.

### Intel XeSS (Xe Super Sampling)

- **XMX path.**  On Xe HPG (Arc) hardware with XMX (Xe Matrix
  Extensions) units, XeSS runs inference on the matrix engines —
  analogous to DLSS on Tensor Cores.  The driver loads the model
  and dispatches to XMX via the compute command streamer.
- **DP4a fallback.**  On non-XMX hardware (older Intel, AMD, NVIDIA),
  XeSS falls back to `DP4a` (dot-product-accumulate of 4 × int8)
  instructions in a compute shader.  Any GPU supporting `DP4a` can
  run it, but quality and performance are reduced.
- **Inputs:** same as DLSS (colour, depth, motion vectors, jitter).

### Driver implementation notes

For DuetOS the upscaling surface is exposed through the Vulkan ICD:
- Application creates render targets at internal resolution.
- Application (or engine middleware) dispatches the upscaling passes.
- The driver's job is correct compute dispatch, barrier insertion
  between the upscaling passes, and synchronisation with the
  present path.
- DLSS/XeSS XMX paths need the driver to program the dedicated
  inference hardware — this is vendor-specific register work beyond
  generic compute.
- FSR needs nothing beyond a working compute shader pipeline.

---

## 2. VSync, Frame Pacing, and Tearing Control

### Display scanout model

The display controller reads pixels from a **scanout buffer** (the
framebuffer or front buffer) line by line, left to right, top to
bottom, at the display's refresh rate.  Between the last line of one
frame and the first line of the next is the **vertical blanking
interval** (VBI / VBLANK).

### VSync modes from the driver's perspective

| Mode | Driver behaviour | Tearing? | Latency |
|------|-----------------|----------|---------|
| VSync OFF | Flip/blit immediately | Yes — mid-scanout update | Lowest |
| VSync ON (double-buffer) | Queue flip for next VBLANK | No | Up to 1 frame |
| Triple-buffer VSync | Flip to most-recent completed back buffer at VBLANK | No | Lower than double |
| Adaptive VSync | VSync ON if fps ≥ refresh; OFF if fps < refresh | Sometimes | Variable |
| G-Sync / FreeSync (VRR) | Display adapts refresh to GPU frame rate | No | Very low |

### VBLANK interrupt and flip scheduling

The display controller raises a **VBLANK interrupt** at the start of
each blanking interval.  The driver's ISR:

1. Acknowledges the interrupt (vendor-specific MMIO).
2. Programs the scanout address register to the new front buffer
   (the "page flip").
3. Signals completion to user-mode (via a fence or event).

**Intel:** `PIPE_FLIPDONESTA` / `DSPSURF` (plane surface address
register).  The flip is double-buffered in hardware — writing
`DSPSURF` takes effect at the next VBLANK automatically.

**AMD:** `mmCRTC_UPDATE_LOCK` + `mmGRPH_PRIMARY_SURFACE_ADDRESS` +
`mmCRTC_UPDATE_LOCK` release.  The lock mechanism ensures the address
update is atomic with respect to scanout.

**NVIDIA:** Page flip is programmed through the display engine's
channel-based command interface.  The `NvKmsFlip` structure carries
the flip parameters.

### Variable Refresh Rate (VRR / FreeSync / G-Sync Compatible)

VRR requires:
1. **Monitor capability detection** via EDID/DisplayID extension
   blocks — the `Adaptive-Sync` or `FreeSync` block declares the
   supported refresh range (e.g. 48–144 Hz).
2. **Display controller programming:**
   - AMD: `mmCRTC_V_TOTAL_CONTROL` to vary the vertical total
     (extending VBLANK to slow the refresh rate).
     `mmCRTC_V_TOTAL_MIN` / `_MAX` set the allowed range.
   - Intel: `TRANS_VRR_CTL` register — `VRR Enable`, `Flipline`,
     `Pipeline Full`, `Guardband`.  The `Flipline` is the scanline
     at which the display controller checks whether a new frame is
     ready; if not, it extends VBLANK until one arrives or the
     maximum VTOTAL is reached.
3. **Frame pacing.**  The driver defers the flip until the frame is
   ready rather than aligning to a fixed VBLANK.  This eliminates
   both tearing and the latency penalty of waiting for the next
   fixed VBLANK.

### Mailbox present mode (Vulkan `VK_PRESENT_MODE_MAILBOX_KHR`)

The driver maintains a single-entry mailbox: each present replaces
the pending image.  At VBLANK the display controller picks up
whatever is in the mailbox.  If the application renders faster than
the display refreshes, intermediate frames are silently dropped.
This gives VSync-quality tearfree output with lower latency than
FIFO (the application never blocks waiting for a present slot).

---

## 3. HDR (High Dynamic Range)

### What the driver must handle

HDR is a **display pipeline** feature, not a rendering technique.
The driver's responsibilities:

1. **Detect HDR capability** from the monitor's EDID/CTA-861
   extension:
   - **HDR Static Metadata (CTA-861.3 block, tag 0x06):** declares
     supported EOTFs (SDR gamma, HDR gamma, SMPTE ST 2084 / PQ,
     HLG), max luminance, max frame-average luminance, min
     luminance.
   - **Colorimetry Data Block (tag 0x05):** declares supported
     colour spaces (BT.709, BT.2020, DCI-P3).
2. **Program the display output** for HDR10 or HDR10+:
   - Set the **EOTF** (Electro-Optical Transfer Function) to PQ
     (Perceptual Quantizer, SMPTE ST 2084).
   - Set the **colour space** to BT.2020.
   - Set the **bit depth** to 10 bpc (or 12 bpc if supported).
   - Send **HDR infoframe** via HDMI or DP SDP (Secondary Data
     Packet) carrying the static metadata (mastering display
     primaries, max/min luminance, MaxCLL, MaxFALL).
3. **Framebuffer format:**
   - HDR10 typically uses `R10G10B10A2_UNORM` or
     `R16G16B16A16_FLOAT` (scRGB).
   - The driver must support 10-bit or float scanout in the display
     controller.

### HDMI HDR infoframe (InfoFrame type 0x87, version 1)

The driver constructs a Dynamic Range and Mastering InfoFrame:

| Field | Bytes | Description |
|-------|-------|-------------|
| EOTF | 1 | 0=SDR, 2=SMPTE ST 2084 (PQ), 3=HLG |
| Static Metadata Descriptor ID | 1 | 0 = Type 1 |
| Display Primaries | 16 | xy chromaticity of R, G, B, white point (CIE 1931), 0.00002 units |
| Max Display Mastering Luminance | 2 | cd/m² |
| Min Display Mastering Luminance | 2 | 0.0001 cd/m² units |
| Maximum Content Light Level (MaxCLL) | 2 | cd/m² |
| Maximum Frame-Average Light Level (MaxFALL) | 2 | cd/m² |

**DisplayPort:** The same metadata is sent via a VSC (Video Stream
Configuration) SDP extension or an HDR metadata SDP (DP 1.4+).

### Per-vendor display controller HDR programming

**AMD:**
- `mmFMT_CONTROL` — set `FMT_PIXEL_ENCODING` to 4:4:4 or 4:2:2,
  `FMT_SPATIAL_DITHER_DEPTH` for 10-bit output.
- `mmOUTPUT_CSC_CONTROL` — colour space conversion matrix (BT.709
  to BT.2020 if the compositor works in 709).
- `mmAFMT_GENERIC_HDR` — HDMI infoframe registers.
- `mmDP_SEC_*` — DP secondary data packet registers for HDR metadata.

**Intel:**
- `PIPE_CSC_COEFF_*` — 3×3 colour space conversion matrix.
- `PIPE_CSC_MODE` — select CSC precision (12-bit).
- `GAMMA_MODE` — select the EOTF degamma LUT or bypass.
- `HDMI_DIP_CTL` / `VIDEO_DIP_CTL` — infoframe transmission control.
- `HDMI_DIP_DATA` — infoframe payload registers.
- `DP_TP_CTL` / `DP_MSA_MISC` — DP MSA (Main Stream Attribute)
  bits for colour space and bit depth.

**NVIDIA:**
- HDR metadata is programmed through the display engine's
  channel-based API (NvKms).  The `NvKmsHDRStaticMetadata` structure
  mirrors the HDMI infoframe fields.
- The display engine's output LUT can be programmed for PQ or
  bypassed when the application provides PQ-encoded content directly.

### Tone mapping

Tone mapping (compressing HDR scene values to the display's luminance
range) is an **application or compositor responsibility**, not a
driver function.  The driver's role is limited to:
- Providing the display's luminance capabilities (from EDID) so the
  compositor can make informed tone-mapping decisions.
- Programming the display output path's gamma/degamma LUTs if the
  compositor requests a hardware LUT curve.
- **Never** silently applying a tone-mapping curve the application
  didn't request.

---

## 4. Motion Blur

Motion blur is entirely a **rendering technique** — the GPU hardware
has no dedicated motion blur unit.  The driver's involvement is
limited to providing the compute/graphics pipeline the application
uses.

### Per-object motion blur (velocity buffer approach)

1. **Velocity buffer generation.**  The application renders a
   screen-space velocity buffer: each pixel stores the 2D motion
   vector (dx, dy) of the surface at that pixel, derived from the
   difference between the current and previous frame's MVP
   transforms.  Format: typically `R16G16_FLOAT` or
   `R16G16_SNORM`.
2. **Blur pass.**  A full-screen post-process shader samples the
   colour buffer along each pixel's velocity vector, blending
   multiple samples to simulate the motion streak.  This is a
   standard compute or fragment shader dispatch.
3. **Tile-based optimization.**  The velocity buffer is downsampled
   to tiles (e.g. 20×20 pixels).  Each tile records its maximum
   velocity magnitude.  Tiles with zero velocity skip the blur
   entirely; tiles with small velocity use fewer samples.

### Camera motion blur

Simpler: derived from the frame-to-frame camera transform rather
than per-object velocities.  A single full-screen pass applies a
directional blur based on the camera's angular velocity.

### Driver requirements

- Correct barrier insertion between the velocity-buffer render pass
  and the blur pass (read-after-write hazard).
- Efficient `R16G16_FLOAT` render target support.
- Compute shader dispatch for tile classification if the application
  uses the tiled approach.
- No special hardware programming.

---

## 5. Post-Processing Pipeline

Post-processing effects (bloom, colour grading, film grain, lens
flare, chromatic aberration, vignette, depth of field) are all
**shader-driven**.  The driver provides:

### Compute shader dispatch

Most modern engines run post-processing as compute shaders rather
than fragment shaders, because compute shaders:
- Can read/write UAVs (unordered access views) — no render target
  binding overhead.
- Support arbitrary dispatch dimensions (not locked to triangle
  rasterization).
- Can share data via LDS/shared memory within a workgroup.

The driver must support:
- `vkCmdDispatch` / `ID3D12GraphicsCommandList::Dispatch`.
- UAV/storage-image binds on the colour buffer.
- Barriers between each post-process pass.

### Render target ping-pong

Post-processing chains typically alternate between two render
targets (ping-pong): pass 1 reads A, writes B; pass 2 reads B,
writes A.  The driver must handle:
- Efficient render target transitions (e.g. `VK_IMAGE_LAYOUT_GENERAL`
  for compute, or `COLOR_ATTACHMENT_OPTIMAL` → `SHADER_READ_ONLY_OPTIMAL`
  transitions for fragment-based passes).
- Avoiding unnecessary full-surface clears between passes.

### Bloom

Bloom is a multi-pass effect:
1. **Threshold:** extract pixels above a brightness threshold.
2. **Downsample chain:** progressively halve the resolution (4–6
   levels), applying a box or tent filter at each level.
3. **Upsample chain:** progressively double back up, blending each
   level with the next.
4. **Composite:** add the blurred result to the original image.

The driver provides mip-chain render targets and the dispatch
infrastructure.  The downsample/upsample passes are compute or
fragment shader dispatches.

### Colour grading (LUT-based)

A 3D colour lookup table (typically 32³ or 64³ RGB, stored as a 3D
texture or a 2D atlas of slices) maps input colours to graded
output.  The driver must support:
- 3D texture sampling with trilinear filtering.
- `R10G10B10A2` or `R16G16B16A16_FLOAT` precision in the grading
  pass to avoid banding.

### Hardware-accelerated post-processing (vendor-specific)

Some post-processing is offloaded to fixed-function hardware:
- **NVIDIA NVENC/NVDEC video processing:**  Film grain can be
  applied by the video processor unit during decode.
- **Display engine degamma/gamma LUTs:**  Simple colour curves can
  be applied in the display scanout path via programmable LUTs
  (Intel `PREC_PAL_*`, AMD `mmDC_LUT_*`), saving a shader pass.
- **AMD CAS (Contrast Adaptive Sharpening):**  Can run as a
  display-engine sharpening filter on some APUs.

---

## 6. Level of Detail (LOD)

### Texture LOD (mip selection)

Texture LOD is handled **entirely in hardware** by the texture
sampling unit.  The driver's role is descriptor setup:

- **Mip chain allocation.**  The driver computes the memory layout
  for all mip levels.  Each level is half the dimensions of the
  previous, rounded up.  BCn levels are rounded up to 4×4 block
  boundaries.
- **Descriptor fields** that control mip selection:
  - `BASE_LEVEL` / `LAST_LEVEL` (AMD), `RES_VIEW_MIN_MIP_LEVEL` /
    `RES_VIEW_MAX_MIP_LEVEL` (NVIDIA), `Min LOD` / `MIP Count`
    (Intel) — clamp the accessible mip range.
  - `MIN_LOD` in the image descriptor (AMD word 1, 12-bit 4.8
    fixed-point) — hardware minimum LOD clamp.
  - Sampler `LOD_BIAS` — additive bias to the hardware-computed LOD.
  - Sampler `MIN_LOD` / `MAX_LOD` — clamp range in the sampler state.
  - Sampler `MIP_FILTER` — none (single level), point (nearest
    level), or linear (blend between two levels = trilinear
    filtering).

**Hardware LOD computation** (all vendors, per the D3D/Vulkan spec):

```
LOD = log₂(max(|du/dx|, |du/dy|, |dv/dx|, |dv/dy|, ...))
LOD_clamped = clamp(LOD + LOD_bias, minLOD, maxLOD)
```

The texture unit computes screen-space derivatives of the texture
coordinates across the 2×2 pixel quad, selects the mip level(s)
that best match the sampling rate, and interpolates if trilinear
filtering is enabled.

### Mesh LOD

Mesh LOD is an **application-side** technique — the application
selects which mesh variant to render based on distance to camera.
The driver has no dedicated mesh LOD hardware, with one exception:

**Mesh shaders (NVIDIA Turing+, AMD RDNA 2+, Intel Xe HPG):**
Mesh shaders can implement LOD selection in the GPU pipeline itself:
- The task shader (amplification shader in D3D12) runs per-meshlet
  and decides how many mesh shader workgroups to emit.
- A simple distance/screen-size test in the task shader can cull
  distant meshlets entirely or select a lower-detail meshlet set.
- The driver must support the mesh shader pipeline
  (`VK_EXT_mesh_shader` / D3D12 mesh shaders).

**GPU-driven LOD selection** (compute-based):
- A compute shader reads per-object bounding spheres, computes
  screen-space size, selects an LOD index, and writes
  `VkDrawIndexedIndirectCommand` structs to a buffer.
- `vkCmdDrawIndexedIndirect` / `ExecuteIndirect` dispatches the
  draws.
- The driver must support indirect draw and compute-to-draw
  barriers.

### Nanite-style virtualised geometry (UE5)

Nanite uses a GPU-driven pipeline that:
1. Computes per-cluster (128-triangle) visibility and LOD in
   compute shaders.
2. Rasterizes visible clusters via a software rasterizer (compute
   shader) for small triangles and hardware rasterization for
   larger ones.
3. Uses a visibility buffer (triangle ID + instance ID per pixel)
   instead of a traditional G-buffer.

From the driver's perspective this is "lots of compute dispatches +
indirect draws + atomic operations on UAVs."  No special hardware
support is needed beyond:
- 64-bit atomics on storage buffers (for the visibility buffer).
- Large UAV bind counts.
- Efficient indirect dispatch.

---

## Summary: What DuetOS GPU Drivers Need for These Techniques

| Technique | Driver work | Hardware-specific? |
|-----------|------------|-------------------|
| **FSR** | Compile and dispatch compute shaders | No — generic compute |
| **DLSS** | Tensor Core inference dispatch, NGX model loading | NVIDIA only |
| **XeSS** | XMX inference dispatch or DP4a compute fallback | Intel XMX, or generic compute |
| **VSync** | VBLANK interrupt, flip scheduling, scanout address programming | Yes — display controller |
| **VRR** | VTOTAL adjustment, flip timing, EDID capability parsing | Yes — display controller |
| **HDR** | EDID HDR metadata parsing, infoframe programming, 10-bit scanout, CSC matrix | Yes — display controller |
| **Motion blur** | Standard render target + compute dispatch | No — generic shaders |
| **Post-processing** | Compute dispatch, render target management, barriers | No — generic shaders |
| **Bloom** | Mip-chain render targets, compute/fragment dispatch chain | No |
| **Colour grading** | 3D texture sampling, precision render targets | No |
| **Texture LOD** | Descriptor mip range fields, sampler LOD params | Yes — TMU configuration |
| **Mesh LOD** | Mesh shader pipeline support, indirect draw | Mesh shaders are vendor-specific |
| **GPU-driven LOD** | Compute + indirect draw + barriers | No — generic compute |

The pattern: **display pipeline** features (VSync, VRR, HDR) are
hardware-register-heavy and vendor-specific.  **Rendering
techniques** (motion blur, post-processing, upscaling via FSR,
mesh LOD) are shader-driven and run on generic compute/graphics
pipelines.  **Vendor inference engines** (DLSS Tensor Cores, XeSS
XMX) are the exception — dedicated hardware that needs vendor-specific
driver programming.

---

## Sources

- [AMD GPUOpen — FidelityFX SDK](https://gpuopen.com/fidelityfx-sdk/)
- [NVIDIA DLSS Programming Guide](https://developer.nvidia.com/rtx/dlss/get-started)
- [Intel XeSS SDK](https://github.com/intel/xess)
- [Vulkan VK_EXT_hdr_metadata](https://registry.khronos.org/vulkan/specs/latest/man/html/VK_EXT_hdr_metadata.html)
- [CTA-861-H Standard (HDR infoframe)](https://www.cta.tech/Resources/Standards/CTA-861-H)
- [Intel PRM — Display Engine](https://cdrdv2-public.intel.com/684462/)
- [AMD Display Core (DC) — Mesa](https://docs.mesa3d.org/drivers/amdgpu/display/index.html)
- [Jimenez "Next Generation Post Processing in Call of Duty" (SIGGRAPH 2014)](https://www.iryoku.com/next-generation-post-processing-in-call-of-duty-advanced-warfare/)
- [Karis "High Quality Temporal Supersampling" (SIGGRAPH 2014)](https://advances.realtimerendering.com/)
- [Wihlidal "Optimizing the Graphics Pipeline with Compute" (GDC 2016)](https://gpuopen.com/)
- [Nanite — UE5 Documentation](https://dev.epicgames.com/documentation/en-us/unreal-engine/nanite-virtualized-geometry)
- [VK_EXT_mesh_shader Specification](https://registry.khronos.org/vulkan/specs/latest/man/html/VK_EXT_mesh_shader.html)
