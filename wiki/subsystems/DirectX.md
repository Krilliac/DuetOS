# DirectX v0.1 Path

> **Audience:** PE/Win32 devs, graphics hackers
>
> **Execution context:** Userland (D3D DLLs) -> shared software rasterizer -> SYS_GDI_BITBLT -> compositor
>
> **Maturity:** v0.1 — `D3D{9,11,12}CreateDevice` -> `Clear` + `Draw*` -> `Present` works on the canonical Win SDK ABI; no real GPU, no shaders, no Z-buffer.

## Overview

`d3d9`, `d3d11`, `d3d12`, `dxgi`, `d2d1` userland DLLs in
`userland/libs/` hand out real COM objects whose vtables match the
canonical Win SDK slot layout (an off-by-N drift in earlier d3d9 /
d3d12 revisions was fixed in v0.1).

`D3D11CreateDeviceAndSwapChain`, `IDXGIFactory*::CreateSwapChain*`,
`D3D12CreateDevice`, `Direct3DCreate9`, `D2D1CreateFactory` all work
end-to-end. Beyond `Clear` + `Present`, v0.1 adds a shared software
rasterizer (`userland/libs/dx_raster.h`) that lets `Draw*` /
`DrawIndexed*` / `DrawPrimitive*` actually rasterize triangles into
the BGRA8 back buffer.

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

```
[ PE: D3D11CreateDeviceAndSwapChain ]
        |
[ d3d11.dll: returns COM device + swap-chain ]    userland/libs/d3d11/
        |
[ Per-frame: ClearRenderTargetView -> back buffer fill in user memory ]
        |
[ Per-frame: Draw / DrawIndexed -> dx_raster.h triangle fill into back buffer ]
        |
[ Present -> SYS_GDI_BITBLT ]
        |
[ Kernel compositor BitBlt path ]                  kernel/drivers/video/
        |
[ Framebuffer / virtio-gpu scanout ]
```

The DLLs share infrastructure via:

- `userland/libs/dx_shared.h` — COM vtable shapes, syscall thunks,
  `DxBackBuffer` (BGRA8 row-major back buffer).
- `userland/libs/dx_raster.h` — header-only software rasterizer
  (Pineda triangle fill with top-left rule, Bresenham line, 4x4
  matrix math, NDC -> viewport mapping).

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

## Related Pages

- [Win32 DLLs](Win32-DLLs.md)
- [Compositor and Window Manager](Compositor.md)
- [Graphics Drivers](../drivers/Graphics-Drivers.md)
- [Roadmap — DirectX real device backends](../reference/Roadmap.md#directx-real-device-backends)
