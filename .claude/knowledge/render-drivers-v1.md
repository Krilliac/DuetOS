# render/drivers v1 — virtio-gpu bring-up + D3D IAT routing + vendor MMIO reads

**Last updated:** 2026-04-24
**Type:** Observation + Pattern
**Status:** Active — `kernel/drivers/gpu/` and
`kernel/subsystems/graphics/` both past their v0 skeletons.

## What landed

### Vendor MMIO probe reads (`drivers/gpu/gpu.cpp`)

- NVIDIA: read `PMC_BOOT_0` at `BAR0 + 0x000000` (canonical chip-id
  register since NV4). Decode arch nibble `(boot0 >> 20) & 0xFF`
  against a small table (TU/GA/AD/GB/...), plus implementation
  (`bits 19:16`) and revision (`bits 7:0`).
- Intel: single dword read of BAR0 as MMIO liveness check. No
  per-gen identity register — register layouts drift across Gen9,
  Gen11, Gen12+, and a single probe read would be fragile.
- AMD GFX9+: BAR0 is VRAM framebuffer, registers live at BAR5.
  Probe documents the gap; v1 doesn't map BAR5.
- `GpuInfo` grew `probe_reg` / `mmio_live` / `arch` fields.
  Surfaced in the `gpu` shell command as a second line per GPU.

### virtio-gpu v1 — controlq + GET_DISPLAY_INFO (`drivers/gpu/virtio_gpu.cpp`)

- `VirtioGpuBringUp()` runs the full virtio 1.0 §3.1.1 handshake:
  `ACK` → `DRIVER` → write `driver_features[hi/lo] = 0` →
  `FEATURES_OK` → read back and confirm → queue 0 setup →
  `DRIVER_OK`. No features accepted (GET_DISPLAY_INFO has none).
- Allocates five 4 KiB physically-contiguous pages via the frame
  allocator: desc ring (32 entries × 16 B), avail ring, used ring,
  request buffer, response buffer. At queue_size=32 every ring
  fits in one page with room to spare.
- Notify address computed from `queue_notify_off *
  notify_off_multiplier` (virtio 1.0 §4.1.4.4). On QEMU with
  `notify_off_multiplier == 0`, every queue shares one MMIO u16
  and you distinguish by the value written.
- `VirtioGpuGetDisplayInfo()` builds a 2-descriptor chain (request
  header `kDescNext`, response `kDescWrite`), publishes on the
  avail ring, writes queue 0 to the notify register, polls
  `used->idx` with a 1M-iter bound, parses the
  `RESP_OK_DISPLAY_INFO` reply into a file-scope
  `VirtioDisplayInfo`. Logged per-scanout at TRACE.
- Exposed through `gpu` shell command.

### D3D IAT routing (`subsystems/win32/stubs.cpp` + `core/syscall.cpp`)

- New syscall `SYS_GFX_D3D_STUB = 101`. `rdi = kind` (1=D3D11,
  2=D3D12, 3=DXGI). Forwards to
  `subsystems::graphics::D3D11CreateDeviceStub` /
  `D3D12CreateDeviceStub` / `DxgiCreateFactoryStub`. Returns
  HRESULT E_FAIL (0x80004005).
- Three new 13-byte IAT landing pads (0xC91 / 0xC9E / 0xCAB).
  `mov edi, kind; mov eax, 101; int 0x80; ret`. Page end advanced
  to 0xCB8 (well under 4 KiB).
- IAT table retargeted: every D3D11 / D3D12 / DXGI import now lands
  on the kind-specific stub instead of the shared E_FAIL stub.
  The graphics ICD's handle-table counters now tick; `gfx` shell
  command surfaces them.

## Pattern — kernel is freestanding; avoid compiler-emitted libc

While writing virtio-gpu v1 I hit `ld.lld: undefined symbol:
memcpy / memset` when doing aggregate struct assignments like:

```cpp
VirtioDisplayInfo out = {};        // clang emits memset
out.rects[i] = {x, y, w, h};       // clang emits memcpy for the 16 B rect
g_last_display = out;              // clang emits memcpy for the ~1.7 KB struct
return out;                         // same
```

The kernel is freestanding (no libc), so any compiler-synthesised
`memcpy` / `memset` call is a link-time failure. The accessor
APIs had to be reworked to:

- Populate file-scope state directly; never use a large local
  struct as scratch.
- Return `const T&` where the original instinct was to return by
  value for large types.
- Zero-init structs field-by-field (explicit `= 0` per field) or
  via a small loop instead of `T x = {};`.
- Assign sub-structs field-by-field instead of brace-initialising
  a whole sub-struct.

Treat every struct wider than ~64 B as "no aggregate copy from
here" when the code path matters at link time. Checking with
`clang++ -S` in doubt shows whether the compiler emitted a
`call memcpy@PLT` (user binaries) or equivalent reloc.

## Observation — vendor BAR conventions

From this slice's probes (confirmed against open-source driver
trees):

| Vendor  | BAR 0           | BAR 2              | BAR 5       |
|---------|-----------------|--------------------|-------------|
| Intel   | register file   | GMADR (GTT aperture)| —          |
| NVIDIA  | register file   | framebuffer (VRAM) | —           |
| AMD GFX9+| VRAM framebuffer| doorbell aperture  | register file |
| QEMU Bochs | LFB (VRAM)    | —                  | —           |
| virtio-gpu | first virtio-pci cap | —            | —           |

So "read BAR 0 for a chip-id register" works for Intel + NVIDIA +
QEMU, but not for AMD, and for virtio-gpu you have to walk the PCI
cap list because there is no natural BAR 0. Any future "universal"
probe function needs to switch by vendor.

## Where the next slices land

1. **virtio-gpu v2: RESOURCE_CREATE_2D + ATTACH_BACKING +
   SET_SCANOUT + TRANSFER_TO_HOST_2D + RESOURCE_FLUSH** — the full
   2D blit cycle. Would let the kernel framebuffer point at a
   virtio-gpu resource instead of the Multiboot2 buffer.
2. **virtio-gpu interrupt path** — replace polling of `used->idx`
   with MSI-X. `pci::PciMsixFind` is already in place.
3. **AMD BAR5 mapping** — needed for any AMD register read.
4. **Real Intel probe** — per-Gen decode of `GEN_INFO` /
   `GT_CAPABILITY` depending on dev_id range.
5. **Graphics ICD → real driver** — `subsystems::graphics` can
   now measure D3D call rate, but every entry point still returns
   an error. First real Vulkan path would be a virtio-gpu virgl
   context (feature `VIRTIO_GPU_F_VIRGL`).

## References

- `kernel/drivers/gpu/gpu.{h,cpp}` — vendor MMIO probe + shell view
- `kernel/drivers/gpu/virtio_gpu.{h,cpp}` — v0 + v1
- `kernel/subsystems/graphics/graphics.{h,cpp}` — ICD surface + counters
- `kernel/subsystems/win32/stubs.cpp` — D3D IAT landing pads
  (0xC91 / 0xC9E / 0xCAB)
- `kernel/core/syscall.{h,cpp}` — `SYS_GFX_D3D_STUB = 101`
- virtio 1.0 spec §2.6 (split virtqueues), §3.1.1 (init sequence),
  §4.1.4 (pci transport), §5.7 (virtio-gpu)
- NVIDIA open-gpu-kernel-modules: `src/common/inc/swref/published/`
  for `NV_PMC_BOOT_0` bit layout across generations
