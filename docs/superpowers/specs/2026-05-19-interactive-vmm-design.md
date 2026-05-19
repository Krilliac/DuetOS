# Interactive duetos-vmm — Design Spec

**Date:** 2026-05-19
**Status:** Approved (brainstorming) — pending implementation plan
**Scope owner:** `tools/vmm/` (host tooling; outside kernel subsystem-isolation rules)

## 1. Problem

`duetos-vmm.exe` today is a headless, serial-only Windows Hypervisor Platform
(WHP) VMM. It boots the freestanding DuetOS kernel ELF via a multiboot2 shim and
exposes a GDB stub for Visual Studio attach. There is **no window and no input** —
the kernel runs but its desktop has nowhere to draw, so there is "nothing to see
or interact with."

The goal: evolve it into a real interactive VM tailored to the Windows dev cycle —
run one `.exe`, point it at the kernel/ISO, get a window rendering the DuetOS
desktop with working mouse + keyboard, with the VS debugger optionally attachable
*without* blocking the boot.

## 2. Root cause (verified)

- `kernel/arch/x86_64/boot.S` (line ~51-67) **requests** a framebuffer via
  multiboot2 header tag **type 5**. The comment at line 58 states the kernel-side
  framebuffer driver treats *"no tag 8"* as *"no graphics"*.
- `tools/vmm/src/multiboot2.cpp` / `BuildMultiboot2Info` emits tags
  cmdline(1), basic-meminfo(4), mmap(6), RSDP(15), end(0) — **no framebuffer
  info tag (type 8)**. Hence the kernel boots graphics-less.
- `kernel/drivers/video/framebuffer.cpp` consumes tag 8 directly (bootloader
  provides a linear FB; the kernel does not mode-set a VGA/GPU device for the
  desktop).
- `kernel/drivers/input/ps2kbd.cpp` + `ps2mouse.cpp` exist and
  `kernel/core/boot_tasks.cpp` already runs a mouse-reader task feeding the
  desktop cursor from `Ps2MouseReadPacket()`.

**Consequence:** the entire feature is **VMM-side only — zero kernel changes.**

## 3. Approach (chosen)

**A — Bootloader-style linear framebuffer via MB2 tag 8 + Win32/GDI window.**
Reserve a 32bpp linear buffer in guest RAM, advertise it in MB2 tag 8, blit that
host-mapped guest memory to a Win32 window with `StretchDIBits`. No VGA / Bochs-
BGA / virtio-gpu device emulation. Keeps the exe dependency footprint at
`WinHvPlatform + ws2_32 (+ gdi32/user32)`.

Rejected: (B) emulate Bochs/BGA VBE or stdvga — more device code, kernel desktop
path is MB2-fb-tag based, no benefit. (C) virtio-gpu — heaviest, overkill for a
dev viewer.

Boot model (chosen): **accept `.iso`, parse ISO9660, extract
`/boot/duetos-kernel.elf` + the default menuentry's `boot=`/`theme=` cmdline,
direct-boot via the existing MB2 shim.** No BIOS/GRUB firmware emulation.
`--kernel <elf>` retained for the raw-ELF path.

## 4. v1 scope (locked)

In: framebuffer window; PS/2 keyboard + mouse; optional non-blocking VS GDB
attach; ISO9660 direct-boot.
Deferred (NOT v1): storage (NVMe/AHCI), networking (e1000e), audio (HDA), USB
(xHCI). No double-buffering unless tearing visibly regresses (YAGNI).

## 5. Components (new, under `tools/vmm/src/`)

| File | Responsibility | Depends on |
|------|----------------|-----------|
| `display/window.{h,cpp}` | Win32 window class, message pump, `StretchDIBits` blit of a BGRA buffer; emits input events to a sink | user32, gdi32 |
| `devices/ps2_i8042.{h,cpp}` | i8042 controller: ports 0x60/0x64, kbd+aux FIFOs, IRQ1/IRQ12 via `RaiseGuestLine` | `IoApic`, mirrors `Pit8254` shape |
| `loader/iso9660.{h,cpp}` | Read-only ISO9660(+Joliet) walk; return kernel ELF span + grub.cfg-derived cmdline | `GuestMemory` consumes the span |

Modified: `multiboot2.{h,cpp}` (tag 8 + `Mb2Params` fb fields), `guest_memory.*`
(reserve FB region), `vmm.{h,cpp}` (UI thread, PS/2 device member, `HandleIoPort`
0x60/0x64 cases, window-close → `m_stop`), `main.cpp` (new CLI flags),
`CMakeLists.txt` (sources + `user32`/`gdi32`).

## 6. Framebuffer wiring

1. `GuestMemory` reserves `width*height*4` bytes, page-aligned, placed just under
   the top of `--mem`. Region added to the MB2 memory-map as **reserved**
   (extend existing `reservedEnd`/mmap logic) so the kernel frame allocator never
   reclaims it.
2. `Mb2Params` gains `fbAddr, fbPitch, fbWidth, fbHeight, fbBpp`.
   `BuildMultiboot2Info` emits a well-formed **framebuffer info tag (type 8)**,
   `framebuffer_type = 1` (direct RGB), 32bpp, channel masks for BGRA
   (`StretchDIBits`-native, no per-pixel swizzle).
3. Default mode `1280x1024x32`; `--res WxH` override. MB2 type-5 request leaves
   mode choice to the bootloader, so the VMM is authoritative.

## 7. Threading model

- **Main thread:** unchanged WHP vCPU exit loop (`Vmm::Run`).
- **UI thread (`m_uiThread`):** creates the window (Win32 requires the pump on the
  creating thread), runs `GetMessage`/`DispatchMessage`, on a ~16 ms `WM_TIMER`
  blits host-mapped guest FB → window. Lockless read of guest FB (tearing
  acceptable for a dev viewer).
- **Input path:** UI thread translates window events → PS/2 bytes, pushed onto
  the i8042 FIFOs under one small mutex (low-rate, uncontended). vCPU thread
  drains FIFOs in `HandleIoPort`; IRQs raised via the existing record/replay-aware
  `RaiseGuestLine(irq)` funnel through the emulated `IoApic`.
- **Shutdown:** `WM_DESTROY` / window close sets the existing `m_stop` atomic;
  vCPU loop unwinds exactly like the idle-watchdog path does today.

## 8. PS/2 i8042 detail

- Status/cmd port 0x64, data port 0x60. Controller cmds: `0x20`/`0x60` (read/
  write config byte), `0xA8` (enable aux), `0xAB` (iface test), `0xAA` (self-
  test), `0xD4` (next byte → aux).
- Keyboard device: `0xFF` reset (→ `0xFA 0xAA`), `0xF4` enable, `0xF0` scan-set
  select. **Scan set verified against `ps2kbd.cpp` at implementation time** —
  spec commits to "emit what the driver selects," default set 2 with `0xE0`
  extended prefixes for nav keys.
- Mouse device: `0xFF` reset, `0xF4` enable, `0xF6` defaults, `0xF3` sample-rate.
  Implement the **IntelliMouse 200/100/80 sample-rate knock** → 4-byte (Z)
  packets *iff* `ps2mouse.cpp` performs it; otherwise 3-byte. Verified against
  `ps2mouse.cpp` at implementation time.
- Win32 → PS/2 translation: `WM_KEYDOWN/UP` (+ `WM_SYSKEY*`) → set-2 make/break
  with `0xE0`; `WM_MOUSEMOVE` deltas + button state + `WM_MOUSEWHEEL` →
  movement packets. Pointer is captured/relative while the window is focused.

## 9. ISO9660 loader detail

- PVD @ LBA 16; walk root dir to `/boot/duetos-kernel.elf`; return `{offset,len}`
  span fed to the existing ELF loader unchanged.
- Read `/boot/grub/grub.cfg`, take the `set default=N` entry, lift its
  `boot=…`/`theme=…` tokens into the kernel cmdline so `duetos.iso` reproduces
  the GRUB default desktop boot.
- **Joliet/Rock Ridge:** grub-mkrescue ISOs are typically ISO9660 + Joliet
  (± RR). Prefer the **Joliet SVD** (UCS-2, exact lowercase paths) when present;
  else ISO9660 with case-insensitive match and `;1` version-suffix stripping.
  This is the single implementation unknown — validated first against the real
  `build/x86_64-release/duetos.iso`.

## 10. CLI / UX

- `--iso <path>` — new, mutually exclusive with `--kernel`.
- `--res WxH` — default `1280x1024`.
- `--no-window` — retain today's headless serial behavior (CI/ smoke).
- `--gdb <port>` — opens the stub but **does not stop the guest**; attach a
  running guest anytime. `--gdb-wait` additionally stops-before-first-instruction
  (the existing VS `stopAtConnect` flow).
- Window title: `DuetOS — <image name> — [running|paused|gdb-attached]`.

## 11. Error handling

- WHP unavailable / kernel-not-found: existing clear fatal messages, unchanged.
- ISO parse failure: explicit `couldn't find /boot/duetos-kernel.elf in <iso>
  (joliet=<y/n> rr=<y/n>)` — never a silent headless fallback.
- Window create failure: warn to stderr, fall back to headless; do **not** abort
  the guest.

## 12. Testing

- **Host unit (no WHP):** ISO9660 loader vs. a committed tiny fixture ISO *and*
  the real `duetos.iso`; MB2 builder byte-exact golden for tag 8; PS/2
  scancode/mouse-packet translation table.
- **Integration (manual — this is a dev tool):**
  `duetos-vmm.exe --iso build/x86_64-release/duetos.iso` → desktop renders,
  mouse moves the cursor, keyboard reaches a shell; `--gdb 1234` → VS attaches
  to a *running* guest.
- `--no-window` keeps the existing serial smoke path unaffected.

## 13. Non-goals / risks

- Not a faithful PC: no BIOS, no VGA, no ACPI beyond what exists, no PCI devices
  in v1.
- Risk: ISO9660 name encoding (Joliet/RR) — mitigated by validating against the
  real ISO first.
- Risk: exact PS/2 scan-set / IntelliMouse handshake — mitigated by reading the
  kernel drivers, not guessing.
- Risk: tearing from lockless blit — accepted for v1; double-buffer is a cheap
  follow-up if it regresses.
