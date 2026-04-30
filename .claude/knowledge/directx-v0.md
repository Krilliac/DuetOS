# DirectX v0 — full COM-vtable surface for d3d/dxgi/dinput/xinput/xaudio/dsound/ddraw/d2d1/dwrite

**Last updated:** 2026-04-30
**Type:** Observation + Decision + Pattern
**Status:** Active — all 11 DirectX-family DLLs land with real COM
vtables; 10 smoke PEs walk Clear+Present pipelines through real
vtable calls; pre-existing d3d{9,11,12}/dxgi DLLs flipped to
`essential=true` so the emulator preload trim no longer hides them.

## Scope

This entry covers the DirectX v0 surface across 11 DLLs in
`userland/libs/`:

| DLL          | Base VA      | What it does                                          |
|--------------|--------------|-------------------------------------------------------|
| d3d9.dll     | 0x10120000   | IDirect3D9 + Device w/ Clear+Present (existing)       |
| d3d11.dll    | 0x10130000   | Device + Context + RTV + Texture2D + SwapChain (existing) |
| d3d12.dll    | 0x10140000   | Device + queue/alloc/list/fence/heap/resource (existing) |
| dxgi.dll     | 0x10150000   | Factory + Adapter + Output + SwapChain (existing)     |
| dinput8.dll  | 0x10270000   | DirectInput8 + Device (zero connected gamepads)       |
| xinput1_4.dll| 0x10280000   | Flat XInput C API (4 slots, all not-connected)        |
| xaudio2_8.dll| 0x10290000   | IXAudio2 + master + source voice (silent)             |
| dsound.dll   | 0x102A0000   | IDirectSound + Buffer w/ Lock/Unlock/Play (silent)    |
| ddraw.dll    | 0x102B0000   | IDirectDraw7 + Surface w/ Lock/Blt(COLORFILL)         |
| d2d1.dll     | 0x102C0000   | ID2D1Factory + HwndRenderTarget + SolidColorBrush     |
| dwrite.dll   | 0x102D0000   | IDWriteFactory + TextFormat + TextLayout              |

All eleven share `userland/libs/dx_shared.h`:
- `DxBackBuffer` — BGRA8 row-major, `dx_bb_clear_rgba` + `dx_bb_present`.
- `dx_heap_alloc` / `dx_heap_free` (SYS_HEAP_ALLOC=11, SYS_HEAP_FREE=12).
- `dx_gdi_bitblt` (SYS_GDI_BITBLT=102) — push pixels to an HWND.
- `dx_gfx_trace(kind)` (SYS_GFX_D3D_STUB=101) — bumps per-API counter.
- `DX_HSTUB`/`DX_USTUB`/`DX_VSTUB` cold-vtable fillers.
- IID equality via `dx_guid_eq` and a shared `kIID_IUnknown`.

Naming caveat: mingw-w64 ships `libxaudio2_8.a` but not `_9`, and the
import lib references `XAudio2_8.dll` directly. We named our DLL
`xaudio2_8.dll` to match — DuetOS's `DllNameEqCI` does the case-fold
on the `XAudio2_8.dll` ↔ `xaudio2_8.dll` compare.

## What got wired

**Pre-existing essential flip.** `kernel/proc/ring3_smoke.cpp` was
marking d3d9/d3d11/d3d12 with `essential=false`, which under the
`emulator_pe_report` preload trim meant their imports resolved to the
catch-all NO-OP — i.e. *the entire 2300+ lines of vtable code never
executed*. Flipped all three to `essential=true`. dxgi was already
true.

**New essential entries.** All seven new DLLs added to the
preload table with `essential=true`. Bumped `kPreloadSlotCap`
from 48 → 56 to make headroom for these + future DirectX additions.

**Smoke PEs.** Ten new files under `userland/apps/<name>/`:

| App                | DLL exercised | Vtable methods called                                                                |
|--------------------|---------------|--------------------------------------------------------------------------------------|
| `d3d11_smoke`      | d3d11         | CreateDeviceAndSwapChain → GetBuffer → CreateRTV → OMSetRT → ClearRTV → Present      |
| `d3d12_smoke`      | d3d12         | CreateDevice → CmdQueue/Alloc/List → Fence → Heap → CommittedResource → CreateRTV → ClearRTV → ExecLists → Signal → GetCompletedValue |
| `d3d9_smoke`       | d3d9          | Direct3DCreate9 → CreateDevice → BeginScene → Clear(red) → EndScene → Present        |
| `dinput8_smoke`    | dinput8       | DirectInput8Create → CreateDevice → SetDataFormat → Acquire → GetDeviceState → Unacquire |
| `xinput_smoke`     | xinput1_4     | XInputGetState/SetState/GetCapabilities/GetBatteryInformation/Enable                 |
| `xaudio2_smoke`    | xaudio2_8     | XAudio2Create → CreateMasteringVoice → CreateSourceVoice → SetVolume/GetVolume/Start/Stop |
| `dsound_smoke`     | dsound        | DirectSoundCreate8 → SetCooperativeLevel → CreateSoundBuffer → Lock/Unlock/Play/Stop |
| `ddraw_smoke`      | ddraw         | DirectDrawCreate → SetCoopLevel → SetDisplayMode → CreateSurface → Lock/Unlock → Blt(COLORFILL) |
| `d2d1_smoke`       | d2d1          | D2D1CreateFactory → CreateHwndRenderTarget → CreateSolidColorBrush → BeginDraw → Clear → FillRectangle → EndDraw |
| `dwrite_smoke`     | dwrite        | DWriteCreateFactory → CreateTextFormat → GetFontSize → CreateTextLayout              |

Each smoke walks the vtable via `*(void***)obj` to find the method
table, then casts each slot to a concrete function pointer. Slot
indices match the `*_init_vtbl_once()` tables in the DLL sources.

**Build pipeline.** All standard:
- `tools/build/build-stub-dll.sh` — added 7 new symbol-name cases.
- `kernel/CMakeLists.txt` — 7 `duetos_stub_dll(...)` lines + 10
  `duetos_embed_smoke_pe(...)` lines.
- `userland/apps/build-smokes.sh` — 10 new `[<name>_smoke]=`
  link-line entries.
- `kernel/proc/ring3_smoke.cpp` — 7 new `#include
  "generated_<dll>_dll.h"` + 10 new `#include
  "generated_<smoke>_smoke_pe.h"` + 7 new preload-table entries +
  10 new `SpawnPeFile(...)` calls.

## What works — runtime-verified

Boot-time smoke under QEMU+OVMF (`DUETOS_PRESET=x86_64-release
DUETOS_TIMEOUT=30 tools/qemu/run.sh`) shows:

```
PASSes: 81  FAILs: 0  DONEs: 10
```

across all 10 new DirectX smoke PEs. Every smoke reaches its
`done` line. The `[gfx]` rate-limited LogOnce trace fires once
per DLL kind (CreateDXGIFactory / D3D11CreateDevice /
D3D12CreateDevice / Direct3DCreate9 / DirectInput8Create /
XInputGetState / XAudio2Create / DirectSoundCreate /
DirectDrawCreate / D2D1CreateFactory / DWriteCreateFactory) —
proves the new SYS_GFX_D3D_STUB kinds 4–11 are live.

Each step that returns a meaningful HRESULT/handle is checked
explicitly; `[<smoke>] <step> = PASS` is printed on success.

### Heap caveat — back-buffer sizing

`AddressSpace::region_count` is `u8` (max 255). A typical Win32
PE already burns ~200 region slots on PE image + DLL preload +
stack + TEB. The Win32 per-process heap stays at **16 pages
(64 KiB)** — bumping it to 128 pages overflows region_count
mid-load and corrupts the region table.

Practical consequence: a 32 KiB allocation (= 32×32×4 BGRA8 buffer
+ COM objects + RTV) fits cleanly. The smoke PEs all use
**32×32 back buffers** for that reason. Real-world Win32 apps
that demand a 1024×768 swap chain will hit OOM until either
(a) `AddressSpace::region_count` is widened to `u16`, or
(b) the heap region uses one large mapping instead of N
per-page mappings. Documented as a known limit; not blocking
v0.

Concrete proofs the existing v0 code now exercised end-to-end:
- d3d11: `D3D11SwapChainVtbl[8]=Present`, `[9]=GetBuffer`,
  `ID3D11ContextVtbl[33]=OMSetRenderTargets`, `[50]=ClearRenderTargetView`,
  `ID3D11DeviceVtbl[9]=CreateRenderTargetView`, `[37]=GetFeatureLevel`
  all proven correct by a real PE call chain.
- d3d12: the SIZE_T `D3D12_CPU_DESCRIPTOR_HANDLE` aggregate is
  passed correctly through MSVC x64 ABI to
  `CreateRenderTargetView` and `ClearRenderTargetView`. Heap →
  resource pointer round-trip works.
- d3d9: `D3DPRESENT_PARAMETERS` `BackBufferWidth` at offset 0 +
  `hDeviceWindow` at offset 32 is correct.
- dxgi: pre-existing factory/adapter/swap-chain path now actually
  invoked under the smoke run.

## What's not wired (gap inventory)

- **Real GPU acceleration** — every Clear+Present is software
  (CPU memset + SYS_GDI_BITBLT). The Intel/AMD/NVIDIA GPU drivers
  exist (`drivers/gpu/`) but aren't behind any of these DLLs. v1
  candidate: route ID3D12CommandQueue::ExecuteCommandLists to a
  real GPU command stream.
- **Vertex/pixel shader pipeline** — `Draw()` / `DrawIndexed()`
  return `E_NOTIMPL`. Apps that gate on Clear+Present alone
  (most modern engines' init path) work.
- **Audio output** — XAudio2 `SubmitSourceBuffer` and DirectSound
  `Buffer::Play` succeed but the bytes don't reach the HDA driver.
  `dsound`'s `Buffer::GetCurrentPosition` advances a fake cursor
  by 32 bytes per call so apps that wait for it move on.
- **Real input** — DirectInput's `GetDeviceState` zero-fills
  (no keys held); XInput reports all four pads not connected.
  Real input goes through user32's `GetAsyncKeyState` /
  `GetCursorPos` which we already implement.
- **DirectWrite glyph rasterisation** — `CreateTextLayout` returns
  a layout object whose `GetMetrics` zero-fills. Real text
  rendering on an ID2D1RenderTarget would need to consume layout
  geometry; deferred.
- **Direct2D geometry primitives** — `FillRectangle` works (real
  pixel writes); `FillEllipse`, `DrawLine`, geometry sinks are
  E_NOTIMPL.
- **D3D9Ex / D3D11.1+ / D3D12 1.1+** — only the base vtables.
  Apps that QueryInterface to higher versions get
  `E_NOINTERFACE`.

## Audit checklist

```bash
cd /home/user/DuetOS
# Build everything
cmake --preset x86_64-release
cmake --build build/x86_64-release --parallel "$(nproc)"
# Verify each new DLL was generated
for d in dinput8 xinput1_4 xaudio2_8 dsound ddraw d2d1 dwrite; do
  test -f build/x86_64-release/kernel/$d/$d.dll && echo "  $d.dll OK" || echo "  $d.dll MISSING"
done
# Verify each new smoke .exe
for s in d3d11 d3d12 d3d9 dinput8 xinput xaudio2 dsound ddraw d2d1 dwrite; do
  test -f userland/apps/${s}_smoke/${s}_smoke.exe && \
    echo "  ${s}_smoke.exe OK" || echo "  ${s}_smoke.exe MISSING"
done
# clang-format clean over the new tree
find userland/libs/{dinput8,xinput1_4,xaudio2_8,dsound,ddraw,d2d1,dwrite} \
     userland/apps/{d3d11,d3d12,d3d9,dinput8,xinput,xaudio2,dsound,ddraw,d2d1,dwrite}_smoke \
     -name '*.c' | xargs clang-format --dry-run --Werror
```

## References

- `userland/libs/dx_shared.h` — common BGRA8 backbuffer + syscall wrappers + cold-vtable stubs.
- `userland/libs/d3d{9,11,12}/`, `userland/libs/dxgi/` — pre-existing v0.
- `userland/libs/{dinput8,xinput1_4,xaudio2_8,dsound,ddraw,d2d1,dwrite}/` — new DLLs.
- `userland/apps/{d3d11,d3d12,d3d9,dinput8,xinput,xaudio2,dsound,ddraw,d2d1,dwrite}_smoke/` — new smoke PEs.
- `kernel/CMakeLists.txt` — `duetos_stub_dll(...)` + `duetos_embed_smoke_pe(...)`.
- `kernel/proc/ring3_smoke.cpp` — preload table + `SpawnPeFile` chain.
- `tools/build/build-stub-dll.sh` — symbol-name table.
- `userland/apps/build-smokes.sh` — mingw-w64 link rules.

## Notes

- **mingw-w64 → DuetOS DLL name match matters.** Mingw's import
  libraries hard-code the target DLL filename in `.idata$7`.
  When a smoke imports from `XAudio2_8.dll`, our DuetOS DLL must
  be named to match (case-insensitive). That's why the new DLL is
  `xaudio2_8` not `xaudio2_9`.
- **`essential=true` is mandatory** for any DLL that smoke PEs
  built under mingw will import from. The emulator preload trim
  in `ring3_smoke.cpp` skips `essential=false` entries — apps
  then resolve the import via the catch-all NO-OP (which returns
  zero) and the smoke fails silently.
- **Vtable slot indices are the contract.** Every smoke PE has a
  comment block at the top of `mainCRTStartup` documenting which
  slot it calls; if you reshape a DLL's vtable, check the matching
  smoke's slot list.
