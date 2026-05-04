# DirectX v0 Path

> **Audience:** PE/Win32 devs, graphics hackers
>
> **Execution context:** Userland (D3D DLLs) -> SYS_GDI_BITBLT -> compositor
>
> **Maturity:** v0 — `D3D11CreateDevice` -> `Clear` -> `Present` works; real `Draw*` returns `E_NOTIMPL`

## Overview

`d3d9`, `d3d11`, `d3d12`, and `dxgi` userland DLLs in `userland/libs/`
hand out real COM objects with vtables.
`D3D11CreateDeviceAndSwapChain`, `IDXGIFactory*::CreateSwapChain*`,
`D3D12CreateDevice`, `Direct3DCreate9` all work.
`ClearRenderTargetView` fills a BGRA8 back buffer in user-mode memory
and `Present` BitBlts it to the owning HWND via `SYS_GDI_BITBLT`.

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

swap->Present(0, 0);
```

This calls down through `SYS_GDI_BITBLT` and the BGRA8 back buffer
appears in the owning HWND via the same compositor path the native
apps use.

## What Returns E_NOTIMPL

- Vertex / pixel shaders
- Real `Draw*` calls (`DrawIndexed`, `DrawInstanced`, …)
- Fence-driven GPU sync
- Cross-DLL DXGI <-> D3D11/12 swap-chain marriage

Each of those is its own multi-slice implementation track. The DLL
surface is the scaffolding that makes them possible.

## Architecture

```
[ PE: D3D11CreateDeviceAndSwapChain ]
        |
[ d3d11.dll: returns COM device + swap-chain ]    userland/libs/d3d11/
        |
[ Per-frame: ClearRenderTargetView -> back buffer fill in user memory ]
        |
[ Present -> SYS_GDI_BITBLT ]
        |
[ Kernel compositor BitBlt path ]                  kernel/drivers/video/
        |
[ Framebuffer / virtio-gpu scanout ]
```

The DLLs share infrastructure via `userland/libs/dx_shared.h` (COM
vtable shapes, common types).

DirectX gap-fill landed as part of v0 also covers DirectInput
keyboard/mouse via `SYS_WIN_GET_KEYSTATE` / `SYS_WIN_CURSOR`,
D2D1 `FillEllipse` / `DrawEllipse` / `DrawRectangle` / `DrawLine`,
and DWrite `GetMetrics` (monospace approximation against the kernel
font).

## Related Pages

- [Win32 DLLs](Win32-DLLs.md)
- [Compositor and Window Manager](Compositor.md)
- [Graphics Drivers](../drivers/Graphics-Drivers.md)
- [Roadmap — DirectX real device backends](../reference/Roadmap.md#directx-real-device-backends)
