# DuetOS Roadmap — pending and deferred work

> **Audience:** Maintainers, contributors picking the next slice
>
> **Maturity:** Living document; edit when an item lands or a new gap is found

This page consolidates every multi-session work item that is not
yet in tree. Each entry names the surface that owns the gap so a
contributor can pick one without re-deriving the field. Items that
have landed are recorded in `wiki/reference/Design-Decisions.md`
or [`History`](../getting-started/History.md), not here.

When you land a roadmap item, **delete its entry from this page in
the same commit** that delivers the code.

---

## Kernel / runtime

### B2 — SMP: per-CPU runqueues + work stealing

- **Scope:** bring the scheduler from BSP-only to genuine SMP.
  Per-CPU runqueues, AP bringup synchronisation, work-stealing
  across CPUs, IPI-based reschedule.
- **Blocks on:** nothing. The per-CPU shape is in place across
  lockdep / soft-lockup / event-trace / perf, all keyed on
  `g_per_cpu[0]` aliases that just need to index by current CPU
  ID. SMP AP bringup itself (`SmpStartAps`) already exists; see
  [`SMP-AP-Bringup-Scope`](../advanced/SMP-AP-Bringup-Scope.md).
- **Cascading items unlocked when this lands:**
  - Index `g_per_cpu` lockdep array by current-CPU ID.
  - Index event-trace `g_per_cpu` by current-CPU ID.
  - Index soft-lockup `g_per_cpu` by current-CPU ID.
  - SMP-stress versions of the RwLock + SeqLock + KMailbox
    contention self-tests (current cooperative-single-CPU
    forms cover the wakeup paths; AP bringup unlocks real
    concurrent-acquire stress).
  - Move LAPIC-divider + tick-frequency programming out of
    `arch::TimerInit` into `time::TimerConfigure(hz)` once an
    ARM64 / generic-timer backend justifies the abstraction.
- **When to land:** when a workload genuinely benefits from
  parallelism — typical native userland workloads or any
  non-trivial PE binary.

### Slab allocator + freed-object poison + real KASAN

- **Scope:** implement a slab allocator (currently kheap is the
  only allocator), then stamp `kSlabFreedObjectPoison = 0xCC`
  across freed slab objects on free + verify on alloc. Real
  KASAN is a much bigger lift (shadow-memory mapping, compiler
  plugin integration, per-access shadow lookup).
- **Blocks on:** slab allocator existence. Today's kheap red-zone
  + frame poison + UBSAN cover most needs.
- **When to land:** when a hot-path consumer demands sub-page
  allocations and a slab cache is justified.

### ABI handle-table migration

- **Status:** Win32 side complete. SYS_MUTEX_* migrated first;
  SYS_EVENT_* and SYS_SEM_* followed via `event_syscall.cpp` +
  the new `semaphore_syscall.{h,cpp}`, with the WaitForMultiple-
  Objects probe + auto-reset-consume passes refactored onto
  `HandleTableLookup` + `KEventIsSignaled` /
  `KEventClearAutoReset` / `KSemaphoreCount`. The legacy
  `Win32MutexHandle`, `Win32EventHandle`, `Win32SemaphoreHandle`
  arrays on `Process` are all removed; KMutex / KEvent /
  KSemaphore carry the wait-time + holder refcounting that
  makes the "close every handle while a primitive is held /
  contended" scenario safe (`HandleTableLookupRef` for the
  syscall side, `KObjectAcquire` on wait-entry / hold transition
  for the internal side). CloseHandle's semaphore arm — which
  did not exist pre-migration — was added incidentally, fixing
  a slot leak that pre-dated this work.
- **Linux side — first slice landed:** `KFile` extended with a
  `KFileKind` enum + per-state `pool_index` slot + per-kind
  release callback fired by `KFileDestroy` (kfile.{h,cpp}). New
  per-process helpers in `proc/process.{h,cpp}` consolidate the
  thirteen open-coded "scan for lowest free fd ≥ N" loops behind
  `LinuxFdAllocLowest`, add a `Handle kf_handle` sidecar to every
  `LinuxFd` slot, and route close / dup / fork through
  `LinuxFdClose` / `LinuxFdDup` / `LinuxFdInheritFromParent` —
  which themselves drive `HandleTableRemove` / `HandleTableDuplicate`
  on `Process::kobj_handles`. FD_CLOEXEC is a real per-fd bit now
  (was a sub-GAP); honoured at every creation site that takes a
  CLOEXEC-style flag (open's O_CLOEXEC, pipe2's O_CLOEXEC,
  eventfd2's EFD_CLOEXEC, dup3's O_CLOEXEC, fcntl(F_SETFD,
  FD_CLOEXEC)) and read by `LinuxFdCloseOnExec` (wired for the
  future execve handler; today exists for the boot-time self-test).
  Eleven of the twelve pool-backed kinds — pipe (states 3 / 4),
  eventfd (5), socket (6), timerfd (7), signalfd (8), epoll (9),
  inotify (10), pidfd (12), POSIX MQ (13), memfd (14), and
  fanotify (15) — are migrated end-to-end. `LinuxFdAttachKFile`
  parks a `KFile` carrying the per-kind release callback in
  `kobj_handles`, the `LinuxFd` slot stores the resulting handle,
  and the per-pool release fires once via the `KFile` destroy
  callback when the last reference drops. Every migrated creator
  honours its CLOEXEC flag bit (O_CLOEXEC, EFD_CLOEXEC,
  TFD_CLOEXEC, SFD_CLOEXEC, EPOLL_CLOEXEC, IN_CLOEXEC,
  SOCK_CLOEXEC, PIDFD_NONBLOCK, MQ O_CLOEXEC, MFD_CLOEXEC,
  FAN_CLOEXEC) — was a documented sub-GAP, now real. The
  previous v0 sub-GAP — dup of a pipe / eventfd / socket / etc.
  silently leaking the pool ref — is closed across every
  migrated kind: both fds now hold an independent KFile
  reference and the per-pool wakeup-on-disconnect semantics
  are preserved verbatim. Pidfd's adapter (`PidfdRelease`)
  takes the target pid as `pool_index`, looks the target up
  via `SchedFindProcessByPid`, and drops the `ProcessRetain`
  taken at open — same shape as the legacy DoClose arm but
  routed through the unified KObject refcount. The fork-time
  legacy `*Retain` block in `syscall_clone.cpp` collapsed from
  ten arms to one — only state 11 (dirfd) remains.
- **Remaining state-kind:** dirfd (state 11) is the lone
  hold-out. Its release frees a `win32_dirs[]` snapshot owned
  by the calling Process — the uniform `void(u32)` KFile
  callback can't reach the owning `Process*` without a richer
  callback shape. The legacy DoClose arm continues to handle
  it explicitly (one `SysDirClose(p, dh)` call gated on
  state == 11 && kf_handle == invalid). Migrating dirfd needs
  either a `void(Process*, u32)` callback variant in KFile or
  promoting the directory snapshot itself onto KFile (vnode +
  entries pointer) so the destroy callback no longer needs
  the parent process at all — both are bigger changes than
  the uniform-shape migration.
- **When to land:** opportunistic, gated on a Linux-ABI workload
  that benefits from the unified surface; the dual-track shape
  means each remaining kind is a self-contained slice.

### Intel CET enable

- **Scope:** write `IA32_S_CET` / `IA32_PL0_SSP`, allocate
  shadow stacks, recompile with `-fcf-protection=branch`.
- **Blocks on:** kernel-image rebuild flag wiring + per-task
  shadow-stack allocator + per-IDT-vector ENDBR64 prologue.
  Probe (`arch::CetGet`) is in place to gate the enable code on
  a real signal.
- **When to land:** when a target machine in the test fleet
  advertises CET-SS / CET-IBT and a workload benefits from
  software-enforced CFI on top of the silicon's built-in
  protection.

### KPTI enable (settled — DEFERRED)

- **Status:** runtime probe (`arch::CpuMitigationsGet().needs_kpti`)
  is in tree; on a `RDCL_NO=0` boot the probe emits a loud
  serial WARN block stating the mitigation is not implemented.
- **Why deferred:** every CPU in
  [`hardware-target-matrix`](../advanced/Linux-Networking-Port-Opportunities.md)
  reports `RDCL_NO=1` in silicon, making KPTI a 5–30% syscall
  cost mitigating an attack the hardware already prevents. See
  [`WX-Enforcement`](../security/WX-Enforcement.md).
- **Re-open triggers:** target-fleet CPU lacking `RDCL_NO=1`,
  or a workload that crosses a trust boundary the hardware
  can't enforce.

---

## Storage and filesystem

### Stage 6 — VFS mount path

- **First two slices landed:** `fs::VfsMount(mount_point,
  FsType, block_handle) -> MountId` registry; longest-prefix
  `VfsMountResolve(path)` resolver; FAT32 volumes auto-mount
  at `/disk/<idx>` during boot; `fs::routing::ParseDiskPath`
  consults the mount registry first before falling back to
  the hard-coded prefix. Today every Win32 file syscall that
  resolves to FAT32 gets there via the mount table.
- **Remaining work:** teach the ramfs-side `VfsLookup` itself
  to walk across mount points (return a generic `VfsNode`
  handle instead of `const RamfsNode*`), so `cd /disk/0/SUB`
  in the kernel shell goes through one VFS API rather than
  the routing-layer detour. That's the per-FS-type lookup
  vtable mentioned in the original Stage 6 plan.
- **Per-process namespace roots** continue to work — `Process::root`
  stays a `const RamfsNode*` today, but grows into a generic
  `VfsDir*` handle once on-disk FS is mountable.

### Stage 7+ — Writable FS / native FS / NTFS read

In rough priority:

1. **Native DuetOS FS** — our own design, journalled, ext-like.
   Done in Rust from scratch (see Rust bring-up below).
2. **NTFS read-only** — required by the Windows-PE pillar once
   we want to load a `.exe` from a real NTFS partition.

### Crash-dump persistence to disk

- **Today:** Windows-format `.dmp` files are emitted byte-by-byte
  over QEMU's debugcon (port 0xE9 → `${BUILD_DIR}/duetos.dmp`
  host file). Loadable in WinDbg / VSCode / Python `minidump`.
  The built dump bytes are exposed via
  `diag::minidump::AccessLastMinidump(*out_bytes, *out_len)` so
  any panic-time consumer (disk writer, network pusher, etc.)
  can ship the same bytes the debugcon path already wrote.
- **Deferred:** real-hardware persistence (raw-block write to a
  reserved LBA range). The bytes-access foundation is in place;
  remaining work is the panic-time block writer that runs
  without the slab allocator or scheduler — likely an
  NVMe / AHCI polled-completion path that bypasses the regular
  block layer.

---

## Drivers

### Audio — HDA codec / stream programming

- **Today:** Intel HDA register probe only (`kernel/drivers/audio/audio.cpp`).
  PC speaker still works through `pcspk.cpp`. Codec walker exists
  but stream / amplifier wiring is `// GAP:`-marked.
- **Blocks:** Settings volume slider, system beep on
  notifications, WAV / OGG playback app.
- **Owner:** `kernel/drivers/audio/`.

### Wireless — real-hardware verification

- **Today:** data-decode tier (envelope parsers + beacon walker)
  AND control tier (crypto + EAPOL + 4-way handshake +
  wdev/MLME + per-vendor upload + ring scaffolds + DMA-coherent
  ring allocation + AES key wrap for encrypted M3 KeyData) all
  landed. 13 boot self-tests pass; ~95M libFuzzer executions
  with zero crashes.
- **Blocks on:** real-hardware verification cycles. IRQ wiring
  on per-vendor MSI/MSI-X. iwlwifi TFD descriptor build /
  doorbell / per-RBD data buffers.
- **Unlocks:** Network flyout SSID picker, Settings → Network →
  Wi-Fi tab, captive-portal handler.
- **Owner:** `kernel/drivers/net/wireless/` (per-vendor upload +
  ring setup), `kernel/net/wireless/` (MLME state machine).

### USB mouse — high-DPI 16-bit XY

- **Today:** boot-protocol + extended boot-protocol decoding
  is wired end-to-end. `xhci_init.cpp`'s polling loop computes
  the actual transfer length from the TRB residual and calls
  `HidMouseInjectN(buf, len)` in `xhci_input.cpp`, which
  decodes 3 / 4 / 5+ byte reports — wheel (Z axis), buttons
  4 / 5, and standard left/right/middle. `MousePacket` carries
  `dz` and the `kMouseButton4 / kMouseButton5` bits; the
  Win32 mouse-input accumulator already accepts the wheel
  delta.
- **Deferred:** descriptor-driven decoding for layouts with
  16-bit X / Y (high-DPI gaming mice), digitizer / absolute
  pointers, and horizontal tilt. Needs `HidParseDescriptor`
  to expose per-field offsets — today it sums Report Size ×
  Report Count without recording where each field lands. The
  next slice extends the parser, fetches the report
  descriptor at enumeration time, and passes the layout
  table into `HidMouseInjectN`.
- **Blocks on:** a workload that legitimately needs high-DPI
  precision or digitizer events — extended boot covers wheel
  + 5 buttons.
- **Owner:** `kernel/drivers/usb/`.

### Multi-monitor / runtime resolution change

- **Today:** single linear framebuffer; mode set at boot via
  Bochs VBE. EDID parser landed; hot-plug detect missing.
- **Blocks on:** per-vendor GPU drivers (Intel/AMD/NVIDIA all
  probe-only), mode-set negotiation.
- **Owner:** `kernel/drivers/gpu/`.

### Brightness — ACPI EC driver

- **Today:** Fn-keys dead; no backlight driver.
- **Blocks on:** ACPI EC driver (does not exist), per-vendor
  backlight register paths.

### Battery + ACPI suspend

- **Today:** `kernel/drivers/power/power.cpp` flags
  `backend_is_stub = true`. ACPI battery state unknown.
- **Blocks on:** ACPI AML interpreter (only static tables
  parsed today), EC battery status registers, S3/S0ix wake
  plumbing.
- **Unlocks:** battery tray icon, lid-close suspend.

### Bluetooth, Printer, Webcam

- **Bluetooth:** HCI host-controller driver + L2CAP / RFCOMM /
  GATT stack.
- **Printer:** USB printer-class driver + IPP / PostScript /
  raster pipeline.
- **Webcam:** UVC USB-Video class driver.

### Source-tree GAP markers

The following `// GAP:` markers in source code track edge
cases that the v0 happy path skips:

- `kernel/drivers/net/iwlwifi_rings.cpp` — legacy <7000-series
  RBD format; TX completion polling.
- `kernel/mm/dma.cpp` — ARM64 port (`dsb ishst` + per-line
  `dc cvac`).
- `kernel/subsystems/translation/translate.cpp` — `rseq`
  (restartable sequences).

Find the live inventory with `git grep -nE "// (STUB|GAP):"`.

---

## Win32 / NT subsystem

### COM apartments and runtime

- **Today:** `CoInitialize` / `CoCreateInstance` are facades.
  No real apartment model.
- **Owner:** `userland/libs/ole32/`.

### DirectX real device backends

- **Today:** D3D9/11/12 DLLs ship real COM-vtable shapes at
  canonical Win SDK ABI slot positions, with a shared software
  rasterizer (`userland/libs/dx_raster.h`) honouring `Draw*` /
  `DrawIndexed*` / `DrawPrimitive*`. Vertex/index buffers carry
  real backing storage; input layouts pull POSITION + COLOR from
  the bound VB; triangle list / strip / fan all rasterize.
- **Still gated:** HLSL compilation, texture sampling, geometry/
  hull/domain/compute shaders, multi-stream input, Z-buffer,
  D3D9 fixed-function lighting, real GPU command-ring submission.
- **Blocks on:** per-vendor GPU drivers landing real command-
  ring submission; Vulkan-first ICD then D3D translation layer.

### Windowing — modal dialogs, common controls

- Modal dialogs, common controls, scroll bars, outline fonts,
  multi-threaded message queues remain unimplemented.
  Per the [`Win32-DLLs`](../subsystems/Win32-DLLs.md) doc:
  the DLL surface ships real EATs; behind each export the
  implementation can be a doc-error sentinel today.
- **Menus shipped (v0):** popup menus + WM_CONTEXTMENU
  dispatch + the Win32 menu API surface land on
  `claude/right-click-context-menu-mPDDD`. Residual GAPs:
  interactive Move / Size (need modal-input mode), submenu
  marshaling across `SYS_WIN_TRACK_POPUP`, `TPM_*` flags
  beyond `TPM_RETURNCMD`, Files-app rename UI (needs a
  text-input modal), Trash / ramfs Files context menus,
  menubars + `LoadMenu` resource loading. See
  [`Compositor`](../subsystems/Compositor.md) §"Popup Menus"
  for the live state.

### Winsock async surface

- **Today:** synchronous BSD-socket subset works.
- **Deferred:** WSAEventSelect + overlapped I/O + completion
  ports.

---

## End-user features

### Firewall subsystem

- **Today:** no kernel firewall — every packet a bound NIC
  accepts reaches the stack. The Start menu's FIREWALL entry
  opens an empty-state placeholder window
  (`kernel/apps/firewall.cpp`) that documents the gap.
- **Blocks on:** filter hook points at L2 ingress / L3 egress,
  a rule table data structure, and a `kCapNetAdmin` capability
  for editing.
- **Owner:** `kernel/net/` plus a real `kernel/apps/firewall.cpp`
  body. Roadmap detail in
  [Firewall Roadmap](../networking/Firewall-Roadmap.md).

### ACPI S5 / soft-off shutdown

- **Today:** Start menu's SHUT DOWN action calls `KernelHalt`
  in `kernel/power/reboot.cpp` — logs a sentinel, masks
  interrupts, and parks the boot CPU in `arch::Halt()`. Chipset
  stays powered; the operator (or a VM `quit`) cuts power.
- **Blocks on:** AML interpreter to evaluate `_PTS` / `_GTS` /
  `\_S5_`. Without that we can't drive the chipset's soft-off
  state. Same blocker the per-CPU sleep state work has.

### Lock screen — same-user-only unlock

- **Today:** Start menu's LOCK action calls `LoginLock` which
  brings the gate up without clearing the auth session. Any
  valid user can unlock (Win9x-style).
- **Blocks on:** per-user lock policy + idle-timeout auto-lock
  + on-screen "switch user" affordance distinct from logout.

### Device Manager — class tree + eject

- **Today:** read-only flat PCI list backing the Start menu's
  DEVICE MANAGER entry (`kernel/apps/devicemgr.cpp`).
- **Blocks on:** USB / virtio child enumeration to merge into
  a single tree, `Eject` capability gating, and a hot-unplug
  driver path that the AHCI / xHCI controllers don't yet
  support.

### Network Status — per-iface counters and Wi-Fi scan

- **Today:** read-only iface table (index, MAC, IPv4, bound
  state) backing the Start menu's NETWORK STATUS entry
  (`kernel/apps/netstatus.cpp`).
- **Blocks on:** rx/tx counters in the L2 driver layer (NICs
  don't aggregate them yet), Wi-Fi scan results from
  `kernel/net/wifi.cpp`, and a routing/DNS surface for the
  display layer.

### Terminal emulator (windowed userland shell)

- **Today:** `Ctrl+Alt+T` opens the kernel shell (ring-0).
- **Blocks on:** console-multiplex refactor — kernel shell is
  wired to a single global `ConsoleWrite`. A windowed terminal
  needs the shell to take a per-session sink.
- **Owner:** `userland/shell/`, plus a PTY layer.

### PNG / JPEG / PDF / video viewers

- **Today:** BMP works (`kernel/apps/imageview.cpp`); ImageView
  dispatches by extension.
- **Blocks on:** PNG needs a zlib port (none in tree). JPEG
  needs a Huffman+IDCT decoder. PDF is huge. Video needs HDA.

### IME / non-Latin input

- **Today:** PS/2 + xHCI HID drivers hardcode US layout.
- **Blocks on:** input-method framework refactor.

### Locale / language switching

- **Today:** UI strings are C++ literals in
  `kernel/apps/*.cpp`.
- **Blocks on:** string-table layer with id → text indirection.
- **Effort:** refactor across all apps.

### Disk installer

- **Today:** boots from ISO only. Live system; no install. The
  building blocks exist — `fs::gpt::GptInitDisk` writes a fresh
  GPT (PMBR + primary header + entries + backup header),
  `fs::fat32::Fat32Format` lays down a FAT32 BPB on a partition,
  and `fs::gpt::FormatGuid` renders 16-byte GUIDs for diagnostics
  / installer-step UI.
- **Blocks on:** the orchestration layer (a userland or shell
  installer that walks "pick disk → confirm erase → GPT-init →
  FAT32-format → copy kernel + initrd → install bootloader") and
  bootloader copy (a writer that puts a UEFI-loadable image into
  the ESP). The DESTRUCTIVE primitives intentionally don't ship
  user-facing surfaces yet — that's the shell-command slice.

### System updater

- **Blocks on:** code-signing infrastructure + A/B kernel-slot
  layout.

### Accessibility

- **Today:** magnifier landed. Screen reader + on-screen
  keyboard deferred.
- **Blocks on:** AT-SPI-equivalent kernel surface for the screen
  reader; widget-slot bump for the on-screen keyboard.

---

## Rust bring-up

DuetOS is C++23 / ASM today. The first Rust subsystem lands
when **any** of these is true:

1. **Real on-disk filesystem** — our native FS, NTFS read
   path, ext4 read path. Trigger when a slice actually starts
   parsing on-disk metadata from an attacker-controllable byte
   stream.
2. **USB class drivers with descriptor parsing** — xHCI host
   controller is fine in C++; the USB *class* drivers (HID,
   MSC, hub) parse device-supplied descriptor chains.
3. **TCP/IP stack** — packet headers from untrusted peers.
   Skip Rust for the link-layer drivers but start at the
   protocol stack boundary.
4. **Anything else with non-trivial parsing of attacker-supplied
   structured bytes** — image formats, compression, font files,
   crypto framings.

**Not** triggers:

- "Memory safety is cool" — the slice has to have a real
  lifetime problem, not an aesthetic one.
- "A library exists in Rust" — porting one subsystem so we can
  use a single crate is a rewrite tax for a dependency.

### Tree layout when the trigger fires

```
fs/customfs/                  (NEW — Rust crate)
├── Cargo.toml                (no_std, panic-abort)
├── build.rs                  (emit static lib, link to kernel)
├── src/
│   ├── lib.rs                (entry: pub extern "C" fn customfs_*)
│   └── ...
└── include/
    └── customfs.h            (C header, hand-written — DO NOT bindgen)

rust-toolchain.toml           (NEW — pin nightly date)
```

### Rules

- **One crate per subsystem.** Never a shared "rust-utils"
  crate until a second subsystem actually needs the shared
  bits.
- **No Rust in the middle of a C++ call chain.** The kernel C++
  side calls Rust through a narrow C FFI; never C++ → Rust →
  C++ → Rust.
- **No `unsafe` outside the FFI wall.** Internal subsystem code
  that uses `unsafe` needs a 1-line comment explaining which
  kernel invariant justifies it.
- **Header is hand-written.** Bindgen pulls in cbindgen-style
  automation noise and makes the contract implicit.
- **Pin nightly by date.** `-Zbuild-std` is needed for `no_std`
  against `x86_64-unknown-none`. Bump the pin in a dedicated
  PR, never in a subsystem PR.
- **Adopt CMake side as a leaf custom command** that calls
  `cargo build --release --target x86_64-unknown-none -Z
  build-std=core,alloc` and wraps the resulting `.a` as an
  IMPORTED static library.
- **`panic = "abort"`** — kernel can't unwind. Same policy
  Linux uses for Rust-for-Linux.
- **`lto = "thin"`** — fat LTO interacts badly with CMake +
  multiple object files.

### Do not

- Install a Rust toolchain on the dev host speculatively. Add
  it the same way QEMU is added: when a task legitimately
  requires it.
- Adopt a Rust-native build system (Bazel, Nix, Meson). CMake
  is the project's build system; the Rust subsystem is a leaf
  CMake target that happens to call `cargo` internally.
- Use Rust for a kernel driver that's mostly MMIO bit-bashing
  with no parsing surface.

---

## How to graduate an item

When a roadmap item lands:

1. Delete its section from this page.
2. Add a Design Decisions entry in
   [`Design-Decisions`](Design-Decisions.md) (one per
   non-trivial commit).
3. Update [`History`](../getting-started/History.md) if the
   landing changes a project-level milestone.
4. Update the relevant subsystem wiki page's "Known Limits"
   section.

If an item turns out to be wrong-sized for a single commit,
write a slice plan into the relevant wiki page (e.g. an SMP
plan section under [`Scheduler`](../kernel/Scheduler.md)) and
keep this entry as the index pointer.
