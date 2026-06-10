# DirectX v0.2 Path

> **Audience:** PE/Win32 devs, graphics hackers
>
> **Execution context:** Userland (D3D DLLs) -> kernel Vulkan ICD (D3D11) or shared software rasterizer (D3D9/12) -> SYS_GDI_BITBLT -> compositor
>
> **Maturity:** v0.2 — `D3D{9,11,12}CreateDevice` -> `Clear` + `Draw*` -> `Present` works on the canonical Win SDK ABI. D3D11 swap chains record Clear/Draw as real VkOps replayed by the kernel ICD; D3D9/D3D12 stay on the userland software rasterizer. No real GPU, no app-shader execution, no Z-buffer.

## Overview

`d3d9`, `d3d11`, `d3d12`, `dxgi`, `d2d1` userland DLLs in
`userland/libs/` hand out real COM objects whose vtables match the
canonical Win SDK slot layout (an off-by-N drift in earlier d3d9 /
d3d12 revisions was fixed in v0.1).

`D3D11CreateDeviceAndSwapChain`, `IDXGIFactory*::CreateSwapChain*`,
`D3D12CreateDevice`, `Direct3DCreate9`, `D2D1CreateFactory` all work
end-to-end. Beyond `Clear` + `Present`, v0.1 added a shared software
rasterizer (`userland/libs/dx_raster.h`) that lets `Draw*` /
`DrawIndexed*` / `DrawPrimitive*` actually rasterize triangles into
the BGRA8 back buffer.

v0.2 puts the D3D11 swap chain on a **Vulkan back end**: under
driver types UNKNOWN / HARDWARE / REFERENCE the DLL builds a
`SYS_VK_CALL` ladder (`userland/libs/dx_vk.h`) whose back buffer is
a kernel `VkImage` with host-visible backing. `ClearRenderTargetView`
and triangle `Draw*` record real VkOps into the kernel command tape;
`Present` submits it and the **kernel** rasterizer
(`kernel/subsystems/graphics/graphics_vk_raster.cpp`) paints the
pixels, which are then synced into the user-heap back buffer for the
existing BitBlt present. Driver types NULL / SOFTWARE / WARP — and
any vk-setup failure (one `[d3d11] vk backend unavailable; software
fallback` debug line) — keep the software path. The
`DuetOS_D3D11_PeekBackendKind(swapchain)` export reports which back
end is live (0 = software, 1 = vulkan).

## What Works

```cpp
// Compiles and runs end-to-end on DuetOS:
ID3D11Device* device;
ID3D11DeviceContext* ctx;
IDXGISwapChain* swap;
DXGI_SWAP_CHAIN_DESC desc = { /* ... */ };
D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, 0,
    NULL, 0, D3D11_SDK_VERSION, &desc, &swap, &device, NULL, &ctx);

ID3D11RenderTargetView* rtv;
ID3D11Texture2D* backbuf;
swap->GetBuffer(0, IID_PPV_ARGS(&backbuf));
device->CreateRenderTargetView(backbuf, NULL, &rtv);

float color[4] = {0.1f, 0.2f, 0.3f, 1.0f};
ctx->ClearRenderTargetView(rtv, color);

// v0.1 — real geometry:
D3D11_BUFFER_DESC bd = { sizeof(verts), D3D11_USAGE_DEFAULT, D3D11_BIND_VERTEX_BUFFER, ... };
D3D11_SUBRESOURCE_DATA srd = { verts };
ID3D11Buffer* vb;
device->CreateBuffer(&bd, &srd, &vb);

D3D11_INPUT_ELEMENT_DESC ied[] = {
    { "POSITION", 0, DXGI_FORMAT_R32G32B32_FLOAT, 0, 0, ... },
    { "COLOR",    0, DXGI_FORMAT_R8G8B8A8_UNORM,  0, 12, ... },
};
ID3D11InputLayout* il;
device->CreateInputLayout(ied, 2, NULL, 0, &il);

UINT stride = 16, offset = 0;
ctx->IASetInputLayout(il);
ctx->IASetVertexBuffers(0, 1, &vb, &stride, &offset);
ctx->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
ctx->OMSetRenderTargets(1, &rtv, NULL);
D3D11_VIEWPORT vp = { 0, 0, 640, 480, 0, 1 };
ctx->RSSetViewports(1, &vp);
ctx->Draw(3, 0);

swap->Present(0, 0);
```

This rasterizes a coloured triangle into the back buffer and
BitBlts it to the owning HWND via `SYS_GDI_BITBLT`.

## HLSL compilation — `d3dcompiler.dll`

The userland `d3dcompiler.dll` (source:
`userland/libs/d3dcompiler/d3dcompiler.c`) implements
`D3DCompile` / `D3DCompile2` / `D3DCreateBlob` /
`D3DReflect` / `D3DDisassemble`. The compiler is real but the
HLSL subset is small:

- Lexer recognises the `float`/`floatN`/`int`/`uint`/`half`/
  `Texture2D`/`SamplerState` keyword set, identifiers, decimal
  numbers (with optional `f` / `h` suffix), line + block
  comments, and the punctuation needed for the supported
  grammar.
- Parser is recursive-descent over a top-level grammar of
  struct declarations, `cbuffer` blocks, and function
  definitions; statements are `return`, local-decl with
  optional initialiser, and expression-statements; expressions
  are arithmetic with `+ - * /`, unary `-`, parenthesisation,
  field access (`.xyzw`), function calls, and type
  constructors (`float4(x, y, z, w)`).
- Bytecode emitter produces a deterministic DXBC-shaped blob:
  `DXBC` magic + 16-byte FNV-1a-derived hash + reserved + total
  size + chunk directory pointing at SHEX (executable opcode
  stream), ISGN (input signature), OSGN (output signature),
  and STAT (node + token totals).

The blob is wrapped in an `ID3DBlob` with the canonical COM
shape (IUnknown + GetBufferPointer + GetBufferSize). v0
downstream code in `d3d11.dll` still ignores the bytecode at
draw time — the rasterizer remains pass-through —  but the
compiler is real enough that:

- A second compile of identical source produces a byte-exact
  blob (deterministic hash).
- `D3DReflect` round-trips the blob (echoes the source bytes
  in a refcounted blob the caller can poke directly).
- `DuetOS_D3DCompiler_PeekBlobMagic(blob)` returns the `DXBC`
  magic for smoke tests.

## What Returns E_NOTIMPL

- HLSL bytecode is **compiled** by `d3dcompiler.dll` but
  **not executed** by the d3d11 / d3d12 draw path — the
  rasterizer always uses pass-through position + per-vertex
  colour.
- Texture sampling (SRVs, samplers).
- Geometry / hull / domain / compute shaders.
- Multi-stream input (only slot 0 of `IASetVertexBuffers` honoured).
- Cross-DLL DXGI <-> D3D11/12 swap-chain marriage (each DLL's
  swap chain is self-contained today).
- Fence-driven GPU sync beyond software-immediate completion.
- Z-buffer / depth test (the rasterizer paints in submission
  order — no `OMSetDepthStencilState` effect).
- D3D9 fixed-function lighting / texture stages.

Each of those is its own multi-slice implementation track. The
DLL surface is the scaffolding that makes them possible.

## Architecture

D3D11 (Vulkan back end, driver type UNKNOWN / HARDWARE / REFERENCE):

```
[ PE: D3D11CreateDeviceAndSwapChain ]
        |
[ d3d11.dll: COM device + swap-chain; dx_vk.h ladder via SYS_VK_CALL ]
        |        (instance→device→queue→VkImage(+map)→cmd buf→vertex staging)
[ Per-frame: ClearRenderTargetView -> CmdClearColorImage on the kernel tape ]
        |
[ Per-frame: Draw / DrawIndexed -> v0 vertex records into mapped staging
        |    + CmdBindVertexBuffer + CmdDraw on the tape (dx_raster.h OFF) ]
[ Present / CPU Map -> EndCommandBuffer + QueueSubmit ]
        |
[ Kernel ICD replay: graphics_vk_raster.cpp paints the image backing ]
        |
[ d3d11.dll syncs backing -> user-heap back buffer -> SYS_GDI_BITBLT ]
        |
[ Kernel compositor BitBlt path ]                  kernel/drivers/video/
        |
[ Framebuffer / virtio-gpu scanout ]
```

D3D9 / D3D12 / dxgi-created swap chains (and D3D11 under NULL /
SOFTWARE / WARP or vk-setup failure) keep the v0.1 software shape:

```
[ Clear / Draw -> dx_raster.h fills the user-memory back buffer ]
        |
[ Present -> SYS_GDI_BITBLT -> compositor -> scanout ]
```

The DLLs share infrastructure via:

- `userland/libs/dx_shared.h` — COM vtable shapes, syscall thunks,
  `DxBackBuffer` (BGRA8 row-major back buffer).
- `userland/libs/dx_raster.h` — header-only software rasterizer
  (Pineda triangle fill with top-left rule, Bresenham line, 4x4
  matrix math, NDC -> viewport mapping).
- `userland/libs/dx_vk.h` — the D3D11 Vulkan back end: SYS_VK_CALL
  thunks (kernel register convention: op in rdi, args in
  rdx/r10/r8/r9), the VkOp subset, the `DxVkBackend` ladder, and
  per-frame record/flush helpers. The DX DLLs are freestanding
  single-.c builds and cannot import vulkan-1.dll, hence direct
  syscalls.

DirectX gap-fill landed in v0 also covers DirectInput
keyboard/mouse via `SYS_WIN_GET_KEYSTATE` / `SYS_WIN_CURSOR`,
D2D1 `FillEllipse` / `DrawEllipse` / `DrawRectangle` / `DrawLine`
(now joined by `FillTriangles` and `Set/GetTransform`), and DWrite
`GetMetrics` (monospace approximation against the kernel font).

## Canonical ABI alignment

D3D9 and D3D12 vtable slot numbers in v0.1 follow the canonical
Win SDK `d3d9.h` / `d3d12.h` declaration order. Earlier revisions
of these DLLs had off-by-N slot drift (e.g. D3D12's
`ClearRenderTargetView` was at slot 23 instead of 48); a real
Win32 PE compiled against the canonical headers would have called
the wrong methods. The smoke tests in
`userland/apps/d3d{9,12}_smoke/` were updated together with the
DLLs to use canonical slot numbers, so they continue to pass and
also validate the canonical ABI.

D3D11's vtable was canonical from v0; nothing changed there beyond
the new method additions.

## Threading & Locking Model

The D3D DLLs run in the calling PE's user-mode context. COM device
and context objects are **not** internally synchronised — D3D11's
`ID3D11DeviceContext` is single-threaded by contract, matching the
real API. The software rasterizer in `dx_raster.h` is header-only
and stateless per call; it writes only the caller-owned
`DxBackBuffer` in user memory. The only kernel crossing per frame is
`Present` → `SYS_GDI_BITBLT`, which serialises through the one
kernel compositor BitBlt path shared with native and GDI clients.
No D3D-private kernel lock exists.

## Capability / Privilege Surface

These DLLs hold no privilege of their own. Every effect on the
system crosses a cap-gated syscall: back-buffer presentation goes
through `SYS_GDI_BITBLT`, DirectInput through `SYS_WIN_GET_KEYSTATE`
/ `SYS_WIN_CURSOR`. A PE can only present to an HWND it legitimately
owns, gated by the kernel's window-manager mediation — the D3D ABI
adds no privilege the PE's `Process::caps` (`kCap*`) did not already
grant. See [`security/Capabilities.md`](../security/Capabilities.md)
and [Subsystem Isolation](../kernel/Subsystem-Isolation.md).

## Known Limits / GAPs / STUBs

The DirectX DLLs carry **zero** `// STUB:` / `// GAP:` markers in
source — this page is the authoritative limit inventory. See
[What Returns E_NOTIMPL](#what-returns-e_notimpl) above for the
per-feature list (no shader execution, no texture sampling, no
Z-buffer, no cross-DLL DXGI marriage, no fixed-function D3D9
lighting). `d3dcompiler.dll` compiles a small HLSL subset to a
DXBC-shaped blob, but the d3d11/d3d12 draw path ignores the
bytecode on BOTH back ends — the Vulkan path is fixed-function
pass-through too (app HLSL is still not executed).

D3D11 Vulkan back-end limits (v0):

- **One backend per process** — the first vk-eligible swap chain
  takes it; later swap chains in the same process stay software
  until it's destroyed.
- **Draw-before-Clear** — a frame whose first recorded op would be
  a Draw has no open command buffer; that frame falls back to the
  software rasterizer (one debug line, documented limit).
- **Triangle topologies only on the tape** — strips are expanded to
  triangle lists in userland (winding-corrected) and `DrawIndexed`
  expands indices into the linear vertex stream; points/lines from
  other entry points never reach the D3D11 draw path. Instancing
  replays the draw per instance, as the software path does.
- **Bounded per-frame capacity** — a 64 KiB vertex staging buffer
  (~2730 triangles) and the kernel's 32-op command tape. Overflow
  submits what's recorded and finishes the draw in software (kept
  ordering-correct by the flush-then-sync step).
- **No texture sampling / SRVs** on either back end.
- **Pixel sync copy** — the kernel-painted image backing is copied
  into the user-heap back buffer at flush, because
  `SYS_GDI_BITBLT` (correctly) rejects kernel-half pointers. One
  w*h*4 copy per present.
- **D3D12 next** — d3d12.dll still paints in userland; the DXGI
  factory's own swap chains are also unchanged.

## Related Pages

- [Win32 DLLs](Win32-DLLs.md)
- [Compositor and Window Manager](Compositor.md)
- [Graphics Drivers](../drivers/Graphics-Drivers.md)
- [Roadmap — DirectX real device backends](../reference/Roadmap.md#directx-real-device-backends)
