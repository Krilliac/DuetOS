# Interactive duetos-vmm — Design Spec

**Date:** 2026-05-19
**Status:** Approved (brainstorming) — pending implementation plan
**Revision:** 2 (added monitor-matched res, minimized start, Win32 control dialog)
**Scope owner:** `tools/vmm/` (host tooling; outside kernel subsystem-isolation rules)

## 1. Problem

`duetos-vmm.exe` today is a headless, serial-only Windows Hypervisor Platform
(WHP) VMM. It boots the freestanding DuetOS kernel ELF via a multiboot2 shim and
exposes a GDB stub for Visual Studio attach. There is **no window, no input, and
no control surface** — the kernel runs but its desktop has nowhere to draw, so
there is "nothing to see or interact with."

Goal: an interactive VM tailored to the Windows dev cycle — run one `.exe`, point
it at the kernel/ISO, get a window rendering the DuetOS desktop with working
mouse + keyboard, a native settings/control dialog to configure and manipulate
the VMM/guest, with the VS debugger optionally attachable *without* blocking the
boot.

## 2. Root cause (verified)

- `kernel/arch/x86_64/boot.S` (~line 51-67) **requests** a framebuffer via
  multiboot2 header tag **type 5**. Its comment (line 58) states the kernel-side
  framebuffer driver treats *"no tag 8"* as *"no graphics"*.
- `tools/vmm/src/multiboot2.cpp` / `BuildMultiboot2Info` emits tags
  cmdline(1), basic-meminfo(4), mmap(6), RSDP(15), end(0) — **no framebuffer
  info tag (type 8)**. Hence graphics-less boot.
- `kernel/drivers/video/framebuffer.cpp` consumes tag 8 directly (bootloader
  provides a linear FB; the kernel does not mode-set a VGA/GPU device).
- `kernel/drivers/input/ps2kbd.cpp` + `ps2mouse.cpp` exist;
  `kernel/core/boot_tasks.cpp` already runs a mouse-reader feeding the desktop
  cursor from `Ps2MouseReadPacket()`.

**Consequence:** the entire feature is **VMM-side only — zero kernel changes.**
This property is preserved deliberately; OS-side configuration is limited to the
multiboot2 `boot=`/`theme=` cmdline (no kernel-side cooperator).

## 3. Approach (chosen)

**A — Bootloader-style linear framebuffer via MB2 tag 8 + Win32/GDI window +
native Win32 control dialog.** Reserve a 32bpp linear buffer in guest RAM,
advertise it in MB2 tag 8, blit that host-mapped guest memory to a Win32 window
with `StretchDIBits`. No VGA / Bochs-BGA / virtio-gpu emulation. A tabbed Win32
dialog (comctl32, ships with Windows) provides the control surface. Exe
dependency footprint stays `WinHvPlatform + ws2_32 + user32/gdi32/comctl32`.

Rejected: (B) emulate Bochs/BGA VBE or stdvga — more device code, no benefit
since the kernel desktop path is MB2-fb-tag based. (C) virtio-gpu — heaviest,
overkill for a dev viewer.

Boot model (chosen): **accept `.iso`, parse ISO9660, extract
`/boot/duetos-kernel.elf` + the default menuentry's `boot=`/`theme=` cmdline,
direct-boot via the existing MB2 shim.** No BIOS/GRUB firmware emulation.
`--kernel <elf>` retained for the raw-ELF path.

## 4. v1 scope (locked)

In:
- Framebuffer window; resolution **auto-matched to the primary monitor's native
  mode** (`--res WxH` overrides); window **starts minimized**, user restores.
- PS/2 keyboard + mouse.
- Optional **non-blocking** VS GDB attach.
- ISO9660 direct-boot.
- **Win32 tabbed control dialog (all four buckets v1):** Runtime controls,
  Exception/fault toggles, Debug/introspect, Config + log/crash paths.

Deferred (NOT v1): storage (NVMe/AHCI), networking (e1000e), audio (HDA), USB
(xHCI); save-state/snapshots; screenshot capture; dialog scripting/automation;
multi-guest profiles; double-buffering (only if tearing visibly regresses).

## 5. Components (new, under `tools/vmm/src/`)

| File | Responsibility | Depends on |
|------|----------------|-----------|
| `display/window.{h,cpp}` | Win32 window, message pump, `StretchDIBits` blit, menu/hotkeys, emits input events | user32, gdi32 |
| `devices/ps2_i8042.{h,cpp}` | i8042: ports 0x60/0x64, kbd+aux FIFOs, IRQ1/IRQ12 via `RaiseGuestLine` | `IoApic`; mirrors `Pit8254` |
| `loader/iso9660.{h,cpp}` | Read-only ISO9660(+Joliet) walk → kernel ELF span + grub.cfg cmdline | `GuestMemory` |
| `control/vmm_control.{h,cpp}` | **Shared control core**: typed get/set/action API + state; the single source of truth the dialog *and* gdb `monitor` are thin front-ends over. No Win32/WHP includes — unit-testable headless. | (none) |
| `ui/settings_dialog.{h,cpp}` | Tabbed modeless Win32 dialog (comctl32) rendering `vmm_control` state; widgets call control-core setters/actions | comctl32, `vmm_control` |

Modified: `multiboot2.{h,cpp}` (tag 8 + `Mb2Params` fb fields), `guest_memory.*`
(reserve FB region), `vmm.{h,cpp}` (UI thread, PS/2 member, `HandleIoPort`
0x60/0x64, window-close → `m_stop`, own `Vmm::Monitor` re-expressed over
`vmm_control`), `main.cpp` (CLI flags), `CMakeLists.txt` (sources + libs).

## 6. Framebuffer wiring

1. `GuestMemory` reserves `width*height*4` bytes, page-aligned, just under the
   top of `--mem`. Region added to the MB2 memory-map as **reserved** (extend
   existing `reservedEnd`/mmap logic) so the kernel frame allocator never
   reclaims it.
2. `Mb2Params` gains `fbAddr, fbPitch, fbWidth, fbHeight, fbBpp`.
   `BuildMultiboot2Info` emits a well-formed **framebuffer info tag (type 8)**,
   `framebuffer_type = 1` (direct RGB), 32bpp, BGRA channel masks
   (`StretchDIBits`-native, no per-pixel swizzle).
3. Resolution: **default = primary monitor native mode** via
   `EnumDisplaySettings(ENUM_CURRENT_SETTINGS)` (fallback `1280x1024` if the
   query fails); `--res WxH` overrides. MB2 type-5 request leaves mode choice to
   the bootloader, so the VMM is authoritative.

## 7. Threading model

- **Main thread:** unchanged WHP vCPU exit loop (`Vmm::Run`).
- **UI thread (`m_uiThread`):** creates the window **minimized**
  (`SW_SHOWMINIMIZED`), runs `GetMessage`/`DispatchMessage`, on a ~16 ms
  `WM_TIMER` blits host-mapped guest FB → window (skipped while minimized).
  Owns the menu/hotkeys and the modeless settings dialog (`IsDialogMessage`
  pumped here). Lockless FB read (tearing acceptable for a dev viewer).
- **Input path:** UI thread translates window events → PS/2 bytes onto the
  i8042 FIFOs under one small mutex (low-rate). vCPU thread drains in
  `HandleIoPort`; IRQs via the record/replay-aware `RaiseGuestLine(irq)` →
  emulated `IoApic`.
- **Control core:** `vmm_control` owns its state behind a mutex; dialog
  (UI thread) and gdb `monitor` (gdb thread) both call its thread-safe API.
  Actions that touch the vCPU (pause/reset/NMI) post to the vCPU loop via an
  atomic request flag drained at the top of each exit iteration — no WHP call
  off the vCPU thread.
- **Shutdown:** `WM_DESTROY`/close or control-core power-off sets `m_stop`;
  vCPU loop unwinds like today's idle-watchdog path.

## 8. PS/2 i8042 detail

- Status/cmd 0x64, data 0x60. Controller cmds: `0x20`/`0x60` (cfg byte r/w),
  `0xA8` (enable aux), `0xAB` (iface test), `0xAA` (self-test), `0xD4`
  (next byte → aux).
- Keyboard: `0xFF` reset (→ `0xFA 0xAA`), `0xF4` enable, `0xF0` scan-set.
  **Scan set matched to `ps2kbd.cpp` at impl time**; default set 2 with `0xE0`
  extended prefixes.
- Mouse: `0xFF` reset, `0xF4` enable, `0xF6` defaults, `0xF3` sample-rate.
  **IntelliMouse 200/100/80 knock → 4-byte (Z) packets iff `ps2mouse.cpp`
  performs it**; else 3-byte. Matched to `ps2mouse.cpp` at impl time.
- Win32 → PS/2: `WM_KEYDOWN/UP` (+ `WM_SYSKEY*`) → set-2 make/break with
  `0xE0`; `WM_MOUSEMOVE` deltas + buttons + `WM_MOUSEWHEEL` → movement packets.
  Pointer captured/relative while the window is focused.

## 9. ISO9660 loader detail

- PVD @ LBA 16; walk root → `/boot/duetos-kernel.elf`; return `{offset,len}`
  span fed to the existing ELF loader unchanged.
- Read `/boot/grub/grub.cfg`, take `set default=N`, lift its `boot=`/`theme=`
  tokens into the kernel cmdline so `duetos.iso` reproduces the GRUB default
  desktop boot.
- **Joliet/Rock Ridge:** grub-mkrescue ISOs are typically ISO9660 + Joliet
  (± RR). Prefer the **Joliet SVD** (UCS-2, exact lowercase paths) when present;
  else ISO9660 case-insensitive + `;1` suffix stripping. Single implementation
  unknown — validated first against the real `build/x86_64-release/duetos.iso`
  (WSL branch `build-iso`, commit `ccb22407`).

## 10. Control surface — Win32 tabbed dialog

Opened from a window menu (`Debug ▸ Settings…`) and a hotkey (default `F12`);
modeless so the guest keeps running. All tabs read/write through
`control/vmm_control` (never poke WHP/Win32 directly). RAM and other
creation-time WHP attributes are shown as **next-boot** values with a
**Reset-to-apply** action (WHP fixes partition memory at creation).

**Tab: Config + Logs (v1)** — next-boot res / mem / `boot=`+`theme=` cmdline;
paths for serial log, crash dump, and `--record` file (browse + apply);
read-only image path + git hash banner.

**Tab: Runtime (v1)** — Pause/Resume, Reset (reboot guest), Inject NMI,
Power-off. Live state badge (running/paused/gdb-attached) mirrored into the
window title.

**Tab: Exceptions (v1)** — checkboxes break-on-#GP/#PF/#UD/#DE (wire the
existing gdb stop-on-vector plumbing); rolling fault-log list (vector, RIP,
symbol via `ElfSymbols`).

**Tab: Debug (v1)** — register dump, memory peek/poke (GVA/GPA),
symbolized exit-trace view, exit-reason histogram — surfaced from the existing
`Monitor`/`introspect`/`exit_trace` code through `vmm_control`.

Every control has a `vmm_control` getter+setter/action so the same surface is
reachable via the gdb `monitor` text channel (parity, scriptability) and
exercisable in headless unit tests.

## 11. CLI / UX

- `--iso <path>` (mutually exclusive with `--kernel`).
- `--res WxH` — default = primary monitor native mode.
- `--no-window` — headless serial behavior (CI/smoke); dialog + window disabled.
- `--gdb <port>` — opens stub, **does not stop the guest**; attach anytime.
  `--gdb-wait` additionally stop-before-first-instruction (VS `stopAtConnect`).
  `launch.vs.json` "Attach (in-house VMM)" updated to pass `--gdb-wait`.
- Window **starts minimized**; title `DuetOS — <image> — [state]`.
- Hotkeys: `F12` settings, `F8` pause/resume, `Ctrl+Alt+Del`→guest,
  host-release of captured pointer via a configurable combo.

## 12. Error handling

- WHP unavailable / kernel-not-found: existing clear fatal messages, unchanged.
- ISO parse failure: explicit `couldn't find /boot/duetos-kernel.elf in <iso>
  (joliet=<y/n> rr=<y/n>)` — never a silent headless fallback.
- Window/dialog create failure: warn to stderr, fall back to headless; do **not**
  abort the guest.
- Control-core setter rejects invalid input (bad path, out-of-range mem) with a
  message surfaced both in the dialog and on the `monitor` channel.

## 13. Testing

- **Host unit (no WHP/Win32):** `vmm_control` get/set/action matrix incl.
  rejection paths; ISO9660 loader vs. a committed tiny fixture ISO *and* the
  real `duetos.iso`; MB2 builder byte-exact golden for tag 8; PS/2
  scancode/mouse-packet translation table.
- **Integration (manual — dev tool):**
  `duetos-vmm.exe --iso build/x86_64-release/duetos.iso` → (restore window)
  desktop renders, mouse moves cursor, keyboard reaches a shell;
  `F12` dialog: Pause/Reset/NMI act, exception toggles fire, log path applies;
  `--gdb 1234` → VS attaches to a *running* guest.
- `--no-window` keeps the existing serial smoke path unaffected.

## 14. Non-goals / risks

- Not a faithful PC: no BIOS, no VGA, no PCI devices, no save-state in v1.
- "Configuring the OS" is bounded to the `boot=`/`theme=` cmdline — going deeper
  would need a kernel-side cooperator and break the zero-kernel-changes
  property; explicitly out of scope.
- Risk: ISO9660 name encoding (Joliet/RR) — mitigated by validating against the
  real ISO first.
- Risk: exact PS/2 scan-set / IntelliMouse handshake — mitigated by reading the
  kernel drivers, not guessing.
- Risk: control-dialog scope creep (4 tabs in v1) — mitigated by the shared
  `vmm_control` core (tabs are thin views) and a phased plan: control core +
  dialog shell first, then tabs landed one per slice, each independently
  testable headless.
- Risk: tearing from lockless blit — accepted for v1; double-buffer is a cheap
  follow-up.
