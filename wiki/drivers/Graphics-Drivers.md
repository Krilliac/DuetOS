# Graphics Drivers

> **Audience:** Driver authors, compositor authors
>
> **Execution context:** Kernel — IRQ + process; pixel ops in compositor pass
>
> **Maturity:** virtio-gpu v0 scanout; Intel/AMD/NVIDIA discovery only

## Overview

The DuetOS graphics stack:

```
[ App pixel ops ]                  user32/gdi32 -> SYS_WIN_*/SYS_GDI_*
        |
[ Kernel compositor + WM ]         kernel/drivers/video/
        |
[ Framebuffer / scanout ]
        |
[ GPU driver ]                     kernel/drivers/gpu/{virtio-gpu, intel, amd, nvidia}/
```

The compositor is in-kernel for hot-path latency. Userland reaches it
through `SYS_WIN_*` (window lifecycle) and `SYS_GDI_*` (pixel
primitives). See [Compositor and Window Manager](../subsystems/Compositor.md).

## virtio-gpu v0

`kernel/drivers/gpu/virtio-gpu/` (referenced from
`kernel/drivers/video/`).

- Establishes the virtio device, maps the framebuffer scanout
  resource.
- 2D scanout cycle: write pixels, request a `RESOURCE_FLUSH`, present.
- Used as the default GPU for QEMU smoke tests
  (`-vga virtio` / `-display sdl,gl=on`).

See `.claude/knowledge/render-drivers-v6.md` for the current state of
the render stack.

## GPU Discovery

`kernel/drivers/gpu/` walks the PCI device list at boot:

- Identifies Intel iGPU (Gen9+ recognised), AMD Radeon (GFX9+
  recognised), NVIDIA (Turing+ recognised).
- Maps BARs (deferred MMIO probe).
- Records the device for future driver bringup.

Real driver implementations beyond discovery are not landed — see
`.claude/knowledge/gpu-discovery-v0.md` and
`.claude/knowledge/driver-shells-v0.md`.

## Compositor Primitives

The compositor exposes:

- `FramebufferPutPixel`, `FramebufferFillRect`, `FillRgba`
- `DrawLine`, `DrawCircle`, `DrawRoundRectOutline`,
  `DrawDropShadow`
- Window-chrome primitives (titlebar gradient, X-glyph close,
  taskbar gradient)

These are the same primitives the DirectX v0 DLLs (`d3d9` / `d3d11` /
`d3d12` / `dxgi`) call into when an MSVC PE goes
`D3D11CreateDeviceAndSwapChain -> ClearRenderTargetView -> Present`.

See [DirectX v0 Path](../subsystems/DirectX.md) and
`.claude/knowledge/desktop-chrome-polish-v0.md` /
`.claude/knowledge/gfxdemo-multimode-v0.md`.

## Themes

`kernel/drivers/video/theme.cpp` is a flat token table the window
registry, taskbar, console, and cursor backing all sample on every
recompose. Four themes ship:

- **Classic** — teal / slate-blue (the original)
- **Slate10** — Win10 x Unreal Slate hybrid
- **Amber** — single-hue retro-CRT tribute
- **Duet** — slate-charcoal with two accents (teal for native
  DuetOS, amber for Win32 PE / document apps)

`Ctrl+Alt+Y` cycles themes. See
[Duet Theme Spec](../specifications/Duet-Theme-Spec.md).

## Known Limits / GAPs

- **No real Intel/AMD/NVIDIA driver beyond discovery.** virtio-gpu is
  the only path that produces pixels today.
- **No GPU command queue.** Submission is direct register writes for
  virtio-gpu's tiny command set; a real GPU driver will need a
  proper queue.
- **No Vulkan ICD yet.** Skeleton lives in
  `kernel/subsystems/graphics/`.

## Related Pages

- [Driver Overview](Driver-Overview.md)
- [Compositor and Window Manager](../subsystems/Compositor.md)
- [DirectX v0 Path](../subsystems/DirectX.md)
- [Duet Theme Spec](../specifications/Duet-Theme-Spec.md)
