# DirectX v0 — real COM-vtable d3d9/d3d11/d3d12/dxgi DLLs

**Last updated:** 2026-04-24
**Type:** Observation + Decision
**Status:** Active — `D3D11CreateDeviceAndSwapChain → ClearRenderTargetView → Present` and equivalent D3D9/D3D12 paths return real interfaces, fill BGRA8 back buffers, and BitBlt to the owning HWND via SYS_GDI_BITBLT (102).

## Headline

Before v0 the four DirectX DLLs (`d3d9`, `d3d11`, `d3d12`, `dxgi`) were
≤ 50-line E_NOTIMPL stubs — every entry point returned `NULL` /
`E_NOTIMPL` and every game-style PE that probed for a device exited
on the spot.

After v0 each DLL hands out **real COM objects with real vtables**
that produce a working "create device → clear render target →
present" pipeline:

| DLL    | base VA      | size  | Coverage                                                                                                        |
| ------ | ------------ | ----- | --------------------------------------------------------------------------------------------------------------- |
| d3d9   | 0x10120000   | 4.6 K | `IDirect3D9` + `IDirect3DDevice9::Clear` + `Present` + `Begin/EndScene`                                         |
| d3d11  | 0x10130000   | 9.2 K | `ID3D11Device` (CreateBuffer/Tex2D/RTV, CheckFormat/Multisample/Feature, GetImmediateContext) + `ID3D11DeviceContext::ClearRenderTargetView/OMSetRenderTargets/RSSetViewports` + `IDXGISwapChain::GetBuffer/Present/ResizeBuffers` |
| d3d12  | 0x10140000   | 9.2 K | `ID3D12Device` (Queue/Allocator/List/Fence/DescriptorHeap/CommittedResource/RTV) + `ID3D12GraphicsCommandList::ClearRenderTargetView/OMSetRenderTargets/ResourceBarrier/Close/Reset` + `ID3D12CommandQueue::ExecuteCommandLists/Signal/Wait` + `ID3D12Fence::GetCompletedValue/Signal/SetEventOnCompletion` + `ID3D12Resource::Map/Unmap/GetDesc` + `ID3D12Debug` + `D3D12SerializeRootSignature → ID3DBlob` |
| dxgi   | 0x10150000   | 8.2 K | `IDXGIFactory/1/2` (EnumAdapters/CreateSwapChain/CreateSwapChainForHwnd) + `IDXGIAdapter/1` (EnumOutputs, GetDesc) + `IDXGIOutput` (GetDesc) + `IDXGISwapChain/1` (Present, GetBuffer, ResizeBuffers, GetDesc) + `DXGIGetDebugInterface[1]` + `DXGIDeclareAdapterRemovalSupport` |

## Architecture

**The model is a shared, software-rasterized back buffer**:

- `userland/libs/dx_shared.h` defines a tiny `DxBackBuffer { width,
  height, pitch, buffer_bytes, pixels (BGRA8 row-major), hwnd }`
  struct + helpers (`dx_bb_create`, `dx_bb_clear_rgba`, `dx_bb_present`).
- Every swap chain across the four DLLs owns a `DxBackBuffer`.
- `Present` calls `dx_bb_present`, which calls
  `dx_gdi_bitblt(hwnd, 0, 0, w, h, pixels)` → `SYS_GDI_BITBLT` (102),
  routing the pixels through the existing compositor display-list
  infrastructure that the v3+ render-drivers already paint via
  virtio-gpu.
- `ClearRenderTargetView` calls `dx_bb_clear_rgba` to fill the back
  buffer in user-mode memory, no kernel round-trip.

This means no shader compilation, no GPU command submission, no
synchronization primitives — the whole pipeline is a software
rasterizer that fills BGRA8 and BitBlts. That's the smallest path
that lets a real Win32 PE step through the canonical D3D11 hello
flow without an E_FAIL or NULL pointer.

## Cross-DLL boundary

DLLs only call each other through COM interfaces:

- `D3D11CreateDeviceAndSwapChain` makes both the device and the
  swap chain entirely inside d3d11.dll. The returned
  `IDXGISwapChain*` is layout-compatible with DXGI's; vtable
  pointers are absolute, so it doesn't matter which DLL the vtable
  bytes live in.
- `CreateDXGIFactory* → factory->CreateSwapChain*` produces a swap
  chain entirely inside dxgi.dll.
- D3D12 swap chains are app-flexible: `IDXGIFactory2::Create-
  SwapChainForHwnd` creates a DXGI-side chain; the app's command
  queue talks to it through `ExecuteCommandLists` (which is a no-op
  in v0 because every record-time call already realized into the
  resource's backing buffer).

## MSVC ABI specifics

- All four DLLs build with `clang --target=x86_64-pc-windows-msvc`.
  COM methods follow the MS x64 ABI (`this` in `rcx`, args in
  `rdx`/`r8`/`r9` then stack), regardless of vtable slot.
- `_fltused = 0` is defined once in `dx_shared.h` because the
  `dx_bb_clear_rgba` path uses floats. Each DLL is a single .c file
  including the header once, so we end up with one `_fltused` per
  PE image.
- Mass-stub vtables: cold slots are filled with `dx_stub_hresult`
  (returns `E_NOTIMPL`), `dx_stub_uint` (returns 0), or
  `dx_stub_void` (no-op). The MS x64 ABI lets the same function
  pointer fill any slot of matching return type because extra args
  passed in unused regs/stack are simply not read.
- `DescriptorHandle` aggregates ≤ 8 B return in `rax` (CPU/GPU
  handle accessors); CreateRenderTargetView's `cpuHandle` parameter
  rides in a register slot too.
- `__attribute__((no_builtin("memset","memcpy","memmove","memcmp")))`
  on `dx_memzero/dx_memcpy/dx_guid_eq` keeps clang from rewriting
  the byte loops into self-recursive memset calls when the freestanding
  toolchain has no `vcruntime140` import to satisfy.

## Vtable slot tables (subset implemented)

### `ID3D11Device` (44 slots; v0 implements 8)
| slot | method | v0 |
|-----:|---|---|
| 0..2 | QI / AddRef / Release | real |
| 3 | CreateBuffer | real (mem-only) |
| 5 | CreateTexture2D | real (BGRA8 backbuffer) |
| 9 | CreateRenderTargetView | real |
| 29 | CheckFormatSupport | real (BGRA8 only) |
| 30 | CheckMultisampleQualityLevels | real (1 sample) |
| 33 | CheckFeatureSupport | real (zero-fill OK) |
| 37 | GetFeatureLevel | `D3D_FEATURE_LEVEL_11_0 = 0xb000` |
| 40 | GetImmediateContext | real |
| other | DX_HSTUB | E_NOTIMPL |

### `ID3D11DeviceContext` (144 slots; v0 implements 5)
| slot | method | v0 |
|-----:|---|---|
| 0..2 | QI / AddRef / Release | real |
| 33 | OMSetRenderTargets | real (stores current RTV) |
| 44 | RSSetViewports | no-op success |
| 50 | ClearRenderTargetView | **real fill** |
| 110 | Flush | no-op success |
| 113 | GetType | returns IMMEDIATE = 0 |
| other | DX_VSTUB / DX_HSTUB | no-op |

### `ID3D12Device` (44 slots; v0 implements 11)
| slot | method | v0 |
|-----:|---|---|
| 0..2 | QI / AddRef / Release | real |
| 8 | GetNodeCount | returns 1 |
| 9 | CreateCommandQueue | real |
| 10 | CreateCommandAllocator | real |
| 13 | CreateCommandList | real |
| 14 | CheckFeatureSupport | real (zero-fill OK) |
| 15 | CreateDescriptorHeap | real (heap is a `void*[]`) |
| 16 | GetDescriptorHandleIncrementSize | returns `sizeof(void*)` |
| 22 | CreateFence | real |
| 23 | GetDeviceRemovedReason | S_OK |
| 27 | CreateCommittedResource | real |
| 28 | CreateRenderTargetView | writes resource* into descriptor slot |

### `IDXGISwapChain/1` (17 slots; v0 implements 8)
| slot | method | v0 |
|-----:|---|---|
| 0..2 | QI / AddRef / Release | real |
| 8 | Present | **real BitBlt** |
| 9 | GetBuffer | hands out back-buffer ID3D11Texture2D / DxBackBuffer* |
| 12 | GetDesc | zero-fill success |
| 13 | ResizeBuffers | real (rebuilds back buffer) |

## Trace integration with `gfx` shell

Every `Create*` and `Present` call hits `SYS_GFX_D3D_STUB` (101)
with `kind = {1: D3D11, 2: D3D12, 3: DXGI, 4: D3D9}`, so the
existing `gfx` shell command continues to count entries per API.

## What this v0 does **not** do

- **No shader compilation, no DrawInstanced/DrawIndexed**: vertex
  buffers and shaders compile/upload nominally but Draw calls are
  E_NOTIMPL. A PE that only Clears + Presents works; a PE that
  tries to actually render geometry hits the hresult stub.
- **No real swap-chain → command-queue handshake on D3D12**:
  `ExecuteCommandLists` is a no-op because `ClearRenderTargetView`
  already wrote the resource at record time.
- **No fences in any real sense**: `GetCompletedValue` returns
  whatever `Signal` last wrote. Apps that wait on actual GPU work
  see immediate completion.
- **No DXGI ↔ D3D11/12 cross-DLL swap-chain marriage**: a
  DXGI-side `IDXGISwapChain` returns a raw `DxBackBuffer*` from
  `GetBuffer` instead of an `ID3D11Texture2D` / `ID3D12Resource`.
  D3D11 apps that go through `D3D11CreateDeviceAndSwapChain` get a
  swap chain that hands out a real `ID3D11Texture2D`.

## Files

- `userland/libs/dx_shared.h` — types, IIDs, syscall wrappers,
  back-buffer helpers, `_fltused`, stub trio.
- `userland/libs/dxgi/dxgi.c`   — DXGI factory/adapter/output/swap chain.
- `userland/libs/d3d11/d3d11.c` — D3D11 device/context/tex2d/RTV/swap chain.
- `userland/libs/d3d12/d3d12.c` — D3D12 device/queue/list/fence/heap/resource/debug/blob.
- `userland/libs/d3d9/d3d9.c`   — D3D9 IDirect3D9 + IDirect3DDevice9.
- `kernel/CMakeLists.txt:623-628` — `duetos_stub_dll(...)` lines
  with the expanded export sets.

## Build verification

```
cmake --preset x86_64-release
cmake --build build/x86_64-release --parallel $(nproc)
```

Produces `build/x86_64-release/kernel/{d3d9,d3d11,d3d12,dxgi}/*.dll`
embedded into the kernel ELF (~1.5 MB). All four DLLs link with
`/dll /noentry /nodefaultlib`, no CRT, no imports.
