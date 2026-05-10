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

### B2-followup — split `g_sched_lock` per-CPU

- **Status:** SMP per-CPU runqueues + work-stealing + reschedule-IPI
  + per-AP TSS/IST landed (see
  [`SMP-AP-Bringup-Scope`](../advanced/SMP-AP-Bringup-Scope.md)).
  APs run kernel tasks; cross-CPU wakes route via `last_cpu` and
  fire `kReschedIpiVector` (0xF8); idle CPUs steal Normal-band
  tasks from peers via `StealNormalFromPeer`.
- **Remaining scope:** the per-CPU runqueue head/tail pointers
  live in `cpu::PerCpu`, but every mutation still serialises on
  one global `g_sched_lock`. Splitting the lock per-CPU drops the
  steady-state contention to local-only Schedule() calls. Wake
  paths take target CPU's lock briefly; work-stealing uses
  try-lock to avoid AB/BA deadlock.
- **Blocks on:** nothing technical; defer until profiles show
  contention on `g_sched_lock`.
- **Cascading items unlocked when this lands:**
  - Index `g_per_cpu` lockdep array by current-CPU ID (currently
    keyed on `g_per_cpu[0]` aliases).
  - Index event-trace `g_per_cpu` by current-CPU ID.
  - Index soft-lockup `g_per_cpu` by current-CPU ID.
  - SMP-stress versions of the RwLock + SeqLock + KMailbox
    contention self-tests (current cooperative-single-CPU
    forms cover the wakeup paths).
  - Move LAPIC-divider + tick-frequency programming out of
    `arch::TimerInit` into `time::TimerConfigure(hz)` once an
    ARM64 / generic-timer backend justifies the abstraction.
- **When to land:** when a workload exposes lock contention. For
  most workloads the global lock is acceptable.

### Topology-driven follow-ons (post-clustering v0)

- **Status:** v0 clustering landed — `cpu::Topology` + SRAT parser
  + cluster-aware two-pass `StealNormalFromPeer`. NUMA-aware
  frame allocator landed in this slice (`acpi::srat` now records
  Memory-Affinity records; `FrameAllocatorBuildNumaRanges`
  consumes them; `AllocateFrame` biases toward the calling CPU's
  local node before falling back to the global pool). UMA boots
  (no SRAT) keep the historical global linear-scan path
  byte-for-byte. **Placement affinity at wake landed** —
  `RunqueuePush` now redirects from `last_cpu` to the least-
  loaded same-cluster peer when the delta exceeds a 2-task
  margin, using a new `runq_normal_len` counter on `PerCpu`.
  See [CPU Topology](../kernel/CPU-Topology.md).
- **Remaining scope:** one profile-driven follow-on left:
  - **Cluster-broadcast IPIs** — extend `arch::SmpSendIpi` with
    cluster-scoped destination bits when x2APIC cluster mode is
    in use; lets a wake or shootdown fan out within a cluster
    in one ICR write.
- **Blocks on:** profile evidence — workload-triggered, not
  pre-emptive.

### Slab allocator + freed-object poison + real KASAN

- **Status:** **Slab allocator landed** — `kernel/mm/slab.{h,cpp}`.
  Each `SlabCache` hands out fixed-size objects from 16 KiB
  slabs carved out of the kheap, with a per-cache intrusive
  freelist. O(1) alloc / free, zero per-object header.
  Boot self-test runs in Phase::Sched.
- **Freed-object poison landed** — `SlabFree` stamps
  `kSlabFreedObjectPoison = 0xCC` across the trailing payload of
  every freed slab object (skipping the first `sizeof(void*)`
  bytes that hold the freelist link); fresh-slab carve uses the
  same helper so every free object on the cache freelist looks
  identical. `SlabAlloc` verifies the band before handing the
  object out and panics on mismatch. Boot self-test checks that
  re-allocated objects come back with the poison still present.
  Helpers live in `mm/poison.h` (`PoisonSlabFreedObject` /
  `CheckSlabFreedObjectPoison`).
- **Remaining scope:**
  - **KMalloc routing** — small KMalloc calls could route through
    pre-built size-classed caches automatically. Existing call
    sites are unchanged today; opt-in via direct `SlabAlloc`.
  - **Real KASAN** — shadow-memory mapping, compiler plugin
    integration, per-access shadow lookup. Big lift; defer.

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

### Stage 6 — per-process namespace roots

- **Status (Stage 6 complete for the global namespace):**
  `fs::VfsMount` registry + longest-prefix `VfsMountResolve`
  + FAT32 auto-mount at `/disk/<idx>` landed first; the
  cross-mount resolver (`fs::VfsResolve(root, path) -> VfsNode`)
  + per-FsType `VfsBackendOps` vtable + boot-time cross-mount
  self-test landed alongside this entry. Mount crossings now run
  through `VfsMountVisibleFromRoot`: the trusted boot namespace can
  see the global mount table, while sandbox/custom roots only see
  mounts they explicitly materialise as ramfs graft directories.
  Resolution picks the longest visible mount rather than the longest
  global mount: hidden mounts are ignored instead of shadowing shorter
  visible mounts or root-local ramfs paths. This keeps sandbox roots
  from reaching global mounts merely by
  spelling an absolute path without bloating the immutable ramfs tree
  with synthetic mount directories. `cd /disk/0/SUB` and every other
  "give me the resolved node" caller now goes through one VFS API;
  backend dispatch is a vtable hop.
- **Remaining scope:** teach `Process::root` to carry a
  `VfsNode` (or a `VfsDir*` thin handle) so a sandboxed
  process can be rooted at a non-ramfs subtree (e.g. `/disk/0/SANDBOX`).
  Today every process root is a `const RamfsNode*`; trusted roots
  see the global mount namespace by policy and custom roots can
  expose individual graft points, but the root still cannot itself be
  a non-ramfs backend node. The wider syscall surface (open / stat /
  readdir) still lands in `RamfsNode*` for ramfs fall-through —
  migrating those is a per-syscall follow-on once a workload demands
  a non-ramfs sandbox root.

### Stage 7+ — Writable FS / native FS / NTFS read

In rough priority:

1. **Native DuetOS FS** — our own design, journalled, ext-like.
   Done in Rust from scratch (see Rust bring-up below).
2. **NTFS read-only** — required by the Windows-PE pillar once
   we want to load a `.exe` from a real NTFS partition.

### Crash-dump persistence — AHCI / GPT reservation

- **Today:** Windows-format `.dmp` files are emitted byte-by-byte
  over QEMU's debugcon (port 0xE9 → `${BUILD_DIR}/duetos.dmp`
  host file). On systems with an NVMe namespace, the same
  bytes are also persisted to the LAST
  `kNvmeDumpReservedSectors` (4 MiB at 512B sectors) of
  namespace 1 via `NvmePanicWriteDump` — a polled-completion
  path that reuses the driver's existing staging buffer +
  CQ phase-tag wait, with no scheduler / slab dependencies.
  **AHCI/SATA fallback also landed:** `AhciPanicWriteDump` /
  `AhciDumpReservedLba` / `AhciAvailable` provide the same
  contract — polled completion via the existing per-port
  command list + FIS receive area, no allocations, GPT-first
  + tail-of-drive fallback for the reserved region.
  `minidump.cpp` consults NVMe first and AHCI as the
  fallback when no NVMe namespace is online. Both paths are
  exercised at every boot via `DiskPersistSelfTest` so a
  regression surfaces in the boot log instead of waiting for
  a real panic. The `lastdump` shell command surfaces the
  on-disk LBA + byte count alongside the in-RAM minidump
  status.
- **Deferred:** real partition-table reservation so the disk
  installer can allocate the dump region explicitly instead
  of trusting the last 4 MiB to be unused. Waits for the
  installer slice (Disk installer → orchestration layer).

---

## Drivers

### Audio — HDA codec / stream programming

- **Today:** Intel HDA register probe + codec walker
  (`kernel/drivers/audio/audio.cpp` + `hda.cpp`). Stream
  descriptor `StreamArm` programs BDLPL/BDLPU/CBL/LVI/FORMAT;
  RUN bit toggled via `StreamRun`. Codec configuration verbs
  `CodecSetConverterFormat` / `CodecSetAmpGainMute` use the
  4-bit-verb / 16-bit-payload encoding (verb 0x2 / 0x3) — the
  full 16-bit format value reaches the codec instead of the
  truncated 8-bit form. `ConfigureOutputPath` stitches the
  five-verb sequence (DAC format → DAC amp → pin amp → pin
  widget control → converter stream tag) so a future "play
  system beep" path doesn't have to know the order. Boot self-
  test exercises the verb-encoding helpers against canonical
  inputs.
- **Blocks (still pending):** allocating real audio buffer
  pages + populating a BDL with sample data + flipping RUN +
  observing samples land at the codec — needs a DMA-coherent
  buffer allocator path that's wired through the audio shell
  (or a system-beep driver), plus QEMU's `-device hda-output`
  to verify the byte-level path. `FindFirstOutputPath()` now
  supplies the bootstrap `dac_node` / `pin_node` pair for the
  first speaker / headphone / line-out pin; the remaining gap is
  a consumer that allocates real buffers and calls it as part of
  playback.
- **Owner:** `kernel/drivers/audio/`.

### Wireless — real-hardware verification

- **Today:** data-decode tier (envelope parsers + beacon walker)
  AND control tier (crypto + EAPOL + 4-way handshake +
  wdev/MLME + per-vendor upload + ring scaffolds + DMA-coherent
  ring allocation + AES key wrap for encrypted M3 KeyData) all
  landed. Firmware parsers cover iwlwifi / rtl88xx / b43 envelopes,
  and the firmware-source policy matrix now classifies open firmware
  (ath9k_htc, b43/OpenFWWF) vs runtime-only closed blobs (Intel
  iwlwifi, Intel GPU GuC/HuC/DMC, Realtek) vs research-only patch
  frameworks. The iwlwifi TLV image builder now emits `.ucode`-style
  containers from caller-owned sections, and the DuetOS firmware
  package envelope (`DUETFWPK`) carries source flags + SHA-256 payload
  verification with explicit opt-in for custom/lab images. 16
  wireless/firmware boot self-tests pass; ~95M libFuzzer executions
  completed before the policy/package/builder slices with zero crashes.
- **Blocks on:** real-hardware verification cycles. Firmware package
  signing root / key IDs. IRQ wiring on per-vendor
  MSI/MSI-X. iwlwifi TFD descriptor build / doorbell / per-RBD
  data buffers. Installer integration for the offline Wi-Fi firmware kit
  (`tools/firmware/prepare-wifi-firmware.py` output staged from install
  media or USB before the network picker opens). Recommended first
  open-firmware loop: AR9271/AR7010 `ath9k_htc` USB adapter, then return
  to Intel iwlwifi.
- **Unlocks:** Network flyout SSID picker, Settings → Network →
  Wi-Fi tab, captive-portal handler.
- **Owner:** `kernel/drivers/net/wireless/` (per-vendor upload +
  ring setup), `kernel/net/wireless/` (MLME state machine).

### USB mouse — high-DPI 16-bit XY (parser + injector landed)

- **Today:** descriptor-driven decoding is in tree and wired
  into xHCI mouse bring-up. `HidExtractMouseLayout` walks a HID
  report descriptor and records per-field bit offsets / sizes /
  sign for X / Y / Wheel / AC Pan / Button-mask + the optional
  Report ID byte. `ParseConfigForHidBoot` now captures the HID
  class descriptor's Report descriptor length, and
  `BringUpHidKeyboard` issues `GET_DESCRIPTOR(Report)`
  (kDescTypeReport = 0x22) for boot mice before endpoint
  configuration. On success, `dev.hid_mouse_layout` is populated
  and the polling loop calls `HidMouseInjectWithLayout`; on
  failure, it still falls back to boot-protocol `HidMouseInjectN`.
- **Self-tested:** boot-keyboard / boot-mouse / a synthetic
  high-DPI 5-button + 16-bit-XY + wheel + AC-Pan descriptor
  all round-trip through `HidExtractMouseLayout` with the
  expected bit offsets at boot. xHCI descriptor self-tests also
  cover HID class-descriptor report-length extraction for mouse
  and keyboard configuration trees.
- **Remaining (gated on real hardware):** plug in a high-DPI USB
  mouse and verify the device-supplied Report descriptor produces
  the expected 12/16-bit X/Y layout, button mask, wheel, and AC
  Pan fields on real interrupt-IN reports.
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
  GATT stack. (HCI command/event packet parser landed in
  `kernel/net/bluetooth/hci.{h,cpp}` — covers HCI_Reset / Read
  Local Version / Read BD_ADDR / LE Set Scan Params + Enable on
  the encode side, Command_Complete / Command_Status / event
  header on the decode side. Boot self-test asserts every shape.
  Real bring-up still needs a btusb / btuart transport driver.)
- **Printer:** USB printer-class driver + IPP / PostScript /
  raster pipeline.
- **Webcam:** UVC USB-Video class driver.

### Source-tree GAP markers

The following `// GAP:` markers in source code track edge
cases that the v0 happy path skips:

- `kernel/drivers/net/iwlwifi_rings.cpp` — legacy <7000-series
  RBD format. (TX completion polling landed via
  `IwlRingsPollTxCompletions` / `IwlRingsApplyTxCompletions`;
  the IRQ wiring that calls them is the next slice.)
- `kernel/mm/dma.cpp` — ARM64 port (`dsb ishst` + per-line
  `dc cvac`).
- `kernel/subsystems/translation/translate.cpp` — `rseq`
  (restartable sequences).

Find the live inventory with `git grep -nE "// (STUB|GAP):"`.

---

## Win32 / NT subsystem

### DirectX real device backends

- **Today:** D3D9/11/12 DLLs ship real COM-vtable shapes at
  canonical Win SDK ABI slot positions, with a shared software
  rasterizer (`userland/libs/dx_raster.h`) honouring `Draw*` /
  `DrawIndexed*` / `DrawPrimitive*`. Vertex/index buffers carry
  real backing storage; input layouts pull POSITION + COLOR from
  the bound VB; triangle list / strip / fan all rasterize.
- **Compiler landed (frontend only):** `d3dcompiler.dll` lexes +
  parses a tiny HLSL subset and emits a deterministic DXBC-shaped
  blob (SHEX/ISGN/OSGN/STAT). The d3d11 / d3d12 draw path still
  ignores the bytecode — execution is the next slice.
- **Still gated:** HLSL bytecode execution, texture sampling,
  geometry/hull/domain/compute shaders, multi-stream input,
  Z-buffer, D3D9 fixed-function lighting, real GPU command-ring
  submission.
- **Blocks on:** per-vendor GPU drivers landing real command-
  ring submission; D3D-to-Vulkan thunk wiring (the Vulkan ICD
  v0 lifecycle landed on `claude/native-vulkan-graphics-eoh5N`
  — the D3D side still returns `E_FAIL` and needs to redirect
  through the Vulkan path).

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

- **Today:** synchronous BSD-socket subset works. Async surface
  v0 ships in `userland/libs/ws2_32/ws2_32.c`: `WSACreateEvent`
  / `WSACloseEvent` / `WSASetEvent` / `WSAResetEvent` /
  `WSAEventSelect` / `WSAEnumNetworkEvents` /
  `WSAWaitForMultipleEvents` exist and route through a
  process-local `WsaEventBinding[32]` table. Callers can
  register their interest in network events without crashing
  on a NULL-import lookup.
- **Deferred:** Real async event delivery — the v0 ws2_32
  binding registry has no producer side. The TCP stack
  doesn't yet drive `pending` mask changes when a socket
  becomes readable / writable / accepts a connection, so
  `WSAEnumNetworkEvents` always reports zero events and
  `WSAWaitForMultipleEvents` returns `WSA_WAIT_TIMEOUT`.
  Overlapped I/O + IOCP-backed socket reads still pending
  (kernel32's IOCP plumbing exists but isn't wired into the
  socket read path).

---

## End-user features

### ACPI S5 / soft-off shutdown

- **Today:** Start menu's SHUT DOWN action calls `KernelHalt`
  in `kernel/power/reboot.cpp` — logs a sentinel, masks
  interrupts, and parks the boot CPU in `arch::Halt()`. Chipset
  stays powered; the operator (or a VM `quit`) cuts power.
- **Blocks on:** AML interpreter to evaluate `_PTS` / `_GTS` /
  `\_S5_`. Without that we can't drive the chipset's soft-off
  state. Same blocker the per-CPU sleep state work has.

### Device Manager — virtio + eject + hot-unplug

- **Today:** Device Manager renders two sections: a PCI
  device table (vendor:device, class label) and a USB
  device table that walks every xHCI controller's port
  records (vendor:product, speed, class label,
  HID kbd/mouse hint). Read-only.
- **Blocks on:** virtio child enumeration to merge in (no
  virtio bus walker exists today), `Eject` capability
  gating, and a hot-unplug driver path that the AHCI /
  xHCI controllers don't yet support.

### Network Status — Wi-Fi scan

- **Today:** Iface table (index, MAC, IPv4, bound state),
  rx/tx packet + byte counters, the firewall's per-iface
  `tx_dropped_firewall` column, a routing/DNS section
  (gateway + DNS resolver + DHCP server + lease seconds)
  pulled from `DhcpLeaseRead()`, AND a `WI-FI SCAN`
  section that calls `WifiScan(0, ...)` and renders the
  resulting SSID / SEC / RSSI table. With no wireless
  backend registered the section shows a placeholder hint.
  All back the Start menu's NETWORK STATUS entry
  (`kernel/apps/netstatus.cpp`).
- **Blocks on:** real-hardware wireless backend (per the
  Wireless roadmap row) so the SSID list reflects an actual
  RF scan rather than the empty placeholder. Routing surface
  is single-lease today — multi-iface lease tracking happens
  when more than one DHCP transaction can be live at once.

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

## Rust bring-up — bootstrapped

The Rust toolchain is **now wired into the kernel build** via the
DuetFS slice (trigger #1 — on-disk filesystem parsing). See
[`filesystem/DuetFS.md`](../filesystem/DuetFS.md). The toolchain is
pinned in `/rust-toolchain.toml`; CMake builds drive cargo through
each crate's leaf `CMakeLists.txt`.

The second and third Rust subsystems are now live: USB HID report-descriptor
parsing (`kernel/drivers/usb/hid_rust/`) and USB class configuration parsing
(`kernel/drivers/usb/class_rust/`) are standalone Rust rlibs called through
hand-written C ABIs from the existing C++ USB class-driver surfaces. The USB
class parser recognizes MSC bulk-only, hub, UVC, and Bluetooth USB descriptor
sets. Remaining triggers for **future** Rust subsystems:

1. **Deeper USB class payload parsers** — MSC sense / hub status change / UVC
   class-specific descriptor bodies beyond endpoint binding.
2. **TCP/IP stack** — packet headers from untrusted peers; start at
   the protocol stack boundary, not the link layer.
3. **Anything else with non-trivial parsing of attacker-supplied
   structured bytes** — image formats, compression, font files,
   crypto framings.

**Not** triggers (unchanged):

- "Memory safety is cool" — needs a real lifetime problem.
- "A library exists in Rust" — porting one subsystem so we can
  use a single crate is a rewrite tax for a dependency.

### Rules for new Rust crates

- **One crate per subsystem.** No shared "rust-utils" until a
  second subsystem actually needs the shared bits.
- **No Rust in the middle of a C++ call chain.** Kernel C++ side
  calls Rust through a narrow C FFI; never C++ → Rust → C++ → Rust.
- **No `unsafe` outside the FFI wall.** Internal `unsafe` needs a
  1-line comment explaining which kernel invariant justifies it.
- **Header is hand-written.** Bindgen / cbindgen are forbidden —
  the FFI contract should be readable from the header alone.
- **Toolchain pin lives in `/rust-toolchain.toml`.** Bumping it is
  its own PR.
- **Workspace first.** Add the crate to `/Cargo.toml`; the root
  workspace owns profiles and `/.cargo/config.toml` owns the
  freestanding target / `build-std` defaults.
- **One Rust staticlib link unit.** Subsystem crates are rlibs; add them
  as dependencies of `/kernel/rust/Cargo.toml`. Only `/kernel/rust` calls
  `duetos_add_rust_staticlib(...)`, preventing duplicate `core` / `alloc`
  objects at the C++ kernel link.
- **`panic = "abort"`** — kernel can't unwind. The aggregate crate owns
  the single `#[panic_handler]`; subsystem rlibs must not define one.
- **`lto = "thin"`** — fat LTO interacts badly with CMake.
- **Forbidden:** Bazel / Nix / Meson; cbindgen; speculative deps.

### DuetFS follow-ups

v3 ships per-block CRCs (fsck-verified), symbolic links, hard links
with `link_count` refcount, fsck with link-count drift detection,
and the same on-disk auto-mount path. Image cap dropped from 128 MiB
to 4 MiB to make room for the single-block CRC table; future slice
extends. Next:

1. **Multi-block CRC table** — restore the 32 MiB / 128 MiB image cap.
2. **CoW + journal** — durability / crash safety on file data writes.
3. ~~**Userland syscall surface**~~ — landed. `kernel/fs/file_route.cpp`
   recognises `/duetfs` and `/disks/duetfsN` mount paths via
   `ParseDuetFsPath`, materialises a `duetfs::Device` per call,
   and routes SYS_FILE_OPEN / SYS_FILE_READ / SYS_FILE_WRITE /
   SYS_FILE_CREATE / SYS_OPEN / SYS_READ / SYS_FILE_LINK /
   SYS_FILE_SYMLINK / SYS_FILE_READLINK through the matching
   `duetfs_*` FFI calls. PE and ELF binaries see DuetFS volumes
   through the same syscall surface as ramfs and FAT32 paths.
4. **Separate dirent table** — decouples hard-link names from the
   inode's `name` (today's v3 caveat).
5. **Auto-symlink resolution in `lookup_path`** with cycle detection.
6. **Indirect extents** — files needing > 8 extents.
7. **Multi-block dirs + B-tree directory index** — bump the 1024-child cap.
8. ~~**Auto-mkfs of a blank disk via shell command**~~ — `mkfs.duetfs <handle> ERASE`
   landed alongside the existing FAT32 `mkfs`. Same admin / confirmation-token
   contract; uses `MakeBlockHandleDevice` to wrap the kernel block-device
   handle and calls `duetfs_mkfs` followed by a probe re-validate. The
   formatted volume isn't auto-mounted at runtime — the boot probe path
   only mounts pre-formatted volumes; runtime auto-mount is a follow-on.
9. **AES-XTS encryption + Argon2 KDF** — full-disk encryption tier.
10. **LZ4 compression** — optional per-file compression.

---

## Full Project TODO import (2026-05-09)

> **Source:** maintainer-provided "DuetOS — Full Project TODO" handoff.
>
> **Policy:** these entries are the canonical backlog index for the imported
> task list. When a task lands, delete its row here, update the owning subsystem
> wiki page, and add a design/history note when the change is project-visible.
> Syscall numbers mentioned below are ABI; do not reuse retired numbers.

### Track 1 — Win32 windowing (message pump + GDI paint)

> **T1-01** (per-window message queue + GetMessage/PeekMessage/PostMessage/
> DispatchMessage) and **T1-02** (BeginPaint / EndPaint / TextOut /
> InvalidateRect / UpdateWindow) landed and are exercised by
> `windowed_hello` end-to-end + `msg_smoke` / `wndmsg_smoke` /
> `gdi_smoke`. Syscalls 62/63/64 (`SYS_WIN_PEEK_MSG` /
> `SYS_WIN_GET_MSG` / `SYS_WIN_POST_MSG`) carry messages;
> `DispatchMessage` is pure-userland (calls the WNDPROC directly).
> **T1-03** keyboard/mouse routing closed: the kernel mouse-reader
> + kbd-reader in `kernel/core/main.cpp` post `WM_KEYDOWN` /
> `WM_SYSKEYDOWN` / `WM_KEYUP` / `WM_SYSKEYUP` / `WM_CHAR` /
> `WM_SYSCHAR` (Alt held flips KEYDOWN/KEYUP/CHAR to their SYS
> variants and sets lParam bit 29) plus `WM_MOUSEMOVE` (0x0200) /
> `WM_LBUTTONDOWN` (0x0201) / `WM_LBUTTONUP` (0x0202) /
> `WM_LBUTTONDBLCLK` (0x0203) / `WM_MOUSEWHEEL` (0x020A) to the
> focused PE, with client-coordinate lParam packing. The mouse
> route consults `WindowGetCapture()` first so a `SetCapture()`d
> window keeps receiving events after the cursor leaves;
> `SetForegroundWindow` plumbs through `SetActiveWindow` →
> `SYS_WIN_SET_ACTIVE` → `WindowRaise` and rewrites
> `g_active_window`.
> **T1-04** chrome interactions shipped: the kernel mouse-reader in
> `kernel/core/main.cpp` posts `WindowRaise` on any in-window press
> for Z-order, runs `WindowPointInMinBox` / `WindowPointInMaxBox` /
> the close-glyph hit-test for click-to-min / click-to-max-restore /
> click-to-close, double-click in the title-bar toggles
> max ↔ restore, Alt+F4 closes (with the Notes dirty-prompt), and
> Ctrl+Alt+Arrow drives the snap shortcuts (Left/Right halves, Up
> maximize, Down restore-or-minimize). Title-bar press-and-drag
> moves the window through `WindowMoveTo`. The system-menu (NC
> right-click) Move / Size entries fall through `ModalInputBegin`
> for the cursor-follow interactive forms.
> **T1-05** memory-DC + BitBlt landed: `gdi32!CreateCompatibleDC` /
> `CreateCompatibleBitmap` / `SelectObject` / `DeleteDC` /
> `DeleteObject` / `BitBlt` route through SYS_GDI_CREATE_COMPAT_DC
> (106) / SYS_GDI_CREATE_COMPAT_BITMAP (107) / SYS_GDI_SELECT_OBJECT
> (110) / SYS_GDI_DELETE_DC (111) / SYS_GDI_DELETE_OBJECT (112) /
> SYS_GDI_BITBLT_DC (113) into the per-process MemDC + Bitmap
> tables in `kernel/subsystems/win32/gdi_objects.cpp`.
>
> Track 1 has no remaining roadmap rows.

### Track 2 — COM infrastructure

> Path helpers (`SHGetSpecialFolderPath{A,W}`, `SHGetFolderPath{A,W}`),
> `SHGetDesktopFolder`, and the IFileDialog / IFileOpenDialog /
> IFileSaveDialog vtables on the FileOpenDialog / FileSaveDialog
> factory registrations all ship — see
> [`Win32-Surface-Status`](Win32-Surface-Status.md) §"shell32.dll"
> and §"ole32.dll". `IFileDialog::Show` returns `S_FALSE` (user
> cancelled) and `GetResult` fails cleanly so callers' fallback
> branch runs without a real picker UI; setters succeed silently.
> Track 2 has no remaining roadmap rows — a real picker UI is
> Compositor.md follow-up work, not COM infrastructure.

### Track 3 — Networking

> **T3-02** DHCP client + iphlpapi exposure shipped: `kernel/net/stack.{h,cpp}`
> runs `DhcpStart` against the e1000 iface at boot and stores the bound
> lease (IP / router / DNS / lease seconds) in `DhcpLeaseRead`. New
> `kSockOpGetLease = 13` op on `SYS_SOCKET_OP = 153` snapshots the
> lease into a userland-supplied `SocketLeaseInfo` buffer (40 bytes —
> see syscall.h for layout). `userland/libs/iphlpapi/iphlpapi.c::GetAdaptersInfo`
> consumes the new op and emits a two-record chain: an ethernet
> adapter populated from the live lease (IP / netmask / gateway /
> DhcpEnabled / MAC) followed by the loopback adapter that callers
> rely on for 127.0.0.1.
> **T3-03** DNS resolver + cache shipped: kernel-side DNS already
> routed through `kSockOpResolveA` (`NetDnsQueryA` against the
> DHCP-supplied resolver). `userland/libs/ws2_32/ws2_32.c::getaddrinfo`
> now resolves IP literals through `inet_addr`, special-cases
> "localhost" → 127.0.0.1, and falls through a 16-entry LRU cache
> + the kernel resolver for everything else; `freeaddrinfo` releases
> the single-block addrinfo + sockaddr_in pair. The smaller
> 16-slot cap (vs. the row's original "64-entry LRU" target) is
> lifted on demand — the data structure is a flat scan, not a
> hash, so growth is mechanical.

| ID | Scope | Priority | Task | Acceptance |
| --- | --- | --- | --- | --- |
| T3-01 | net | P1 | Implement IPv4 TCP/UDP socket stack over e1000 and wire `ws2_32` APIs: ARP, ICMP echo, TCP handshake/data/teardown, UDP, kernel socket objects/handles, socket syscalls, `WSAStartup`, `socket`, `connect`, `send`, `recv`, `select`, name-resolution stubs, per-thread WSA error. | A PE can `socket(AF_INET, SOCK_STREAM, 0)` → connect to `127.0.0.1:port` → send/recv data in loopback. |

### Track 4 — DirectX / graphics

> **T4-01** D3D11/DXGI swap-chain presentation into compositor windows
> shipped: `userland/libs/d3d11/d3d11.c` (`d3d11sc_Present` /
> `d3d11sc_GetBuffer` / `d3d11sc_ResizeBuffers`) and the matching
> dxgi paths route through `dx_bb_present` / `dx_win_get_rect`
> (the latter wraps `SYS_WIN_GET_RECT` = 70, the renamed
> equivalent of the row's original `SYS_WIN_HWND_TO_RECT (68)`
> reference). The screenshot-harness PE `dx_demo_window` renders
> a 24-vertex cube into a real compositor window and Presents
> it via SYS_GDI_BITBLT, exercising the full path.
> **T4-02** Vulkan ICD v0 shipped: `kernel/subsystems/graphics/`
> exposes the Vulkan entry-point table (`vkCreateInstance` /
> `vkCreateDevice` / `vkAcquireNextImageKHR` / per-stage WSI
> primitives) backed by a software device. Boot self-test
> (`graphics_vk_selftest.cpp`) walks the create / queue / swap-
> chain / present lifecycle without crashing; unimplemented paths
> return `VK_ERROR_INITIALIZATION_FAILED`.
> **T4-04** AMD / NVIDIA / Intel probes shipped with graceful
> software fallback: `kernel/drivers/gpu/{amd,nvidia,intel}_gpu.cpp`
> all probe their PCIe controllers, log vendor / device / probe
> register state, and return `Err{Unsupported}` on the command-
> submission path. The D3D11 / Vulkan layers stay on the
> shared software rasterizer because nothing attempts to
> submit a real command ring. The `// STUB:` markers on
> `amd_gpu.cpp:CP_RB0` / `intel_gpu.cpp:RCS_TAIL` / `nvidia_gpu.cpp`
> document the per-vendor next steps without breaking today's
> degrade-to-software contract.

| ID | Scope | Priority | Task | Acceptance |
| --- | --- | --- | --- | --- |
| T4-03 | gfx | P2 | Implement Intel iGPU Gen9+/Xe driver basics: PCI probe, MMIO BAR, GTT setup, command ring, 2D blitter acceleration. (Probe + register peek landed; GTT, command ring, blitter still pending.) | BitBlt-heavy paths can use Intel blitter acceleration instead of framebuffer software fills. |

### Track 5 — Memory manager

| ID | Scope | Priority | Task | Acceptance |
| --- | --- | --- | --- | --- |
| T5-01 | mm | P1 | Complete `NtAllocateVirtualMemory` / `VirtualAlloc` / `VirtualFree` / `VirtualProtect`: reserve/commit split, release, guard pages, correct protection flags, `VirtualQuery` / `NtQueryVirtualMemory`, and `MEM_WRITE_WATCH` rejection. (`VirtualQuery` / `NtQueryVirtualMemory` ship; `MEM_WRITE_WATCH` rejection ships — `VirtualAlloc` returns NULL when the flag is set rather than silently dropping the watch contract. Reserve/commit split, guard pages, and protection-bit enforcement still pending kernel-side region bookkeeping.) | MSVC stack-probing apps survive first-thread stack setup. |
| T5-02 | mm | P1 | Implement multi-heap process allocator: `HeapCreate`, `HeapAlloc`, `HeapFree`, `HeapReAlloc`, `HeapSize`, `GetProcessHeap`, `HeapDestroy`, validation/compact no-ops, CRT malloc/free through the default heap. | A PE can allocate from and destroy a secondary heap without corrupting the default heap. |
| T5-03 | mm | P2 | Implement real KASLR in the UEFI loader: memory-map scan, random 2 MiB-aligned base within a 64 MiB window, boot-info handoff, and boot-log reporting. | Two cold boots show different kernel `.text` load addresses. |
| T5-04 | mm | P2 | Audit/complete buddy + slab allocators: coalescing, slab freelists or magazines, IRQ-safe `kmalloc` / `kfree`, and documentation of IRQ/process context safety. | Allocator behavior and context guarantees are tested and documented. |

### Track 6 — Process and thread model

| ID | Scope | Priority | Task | Acceptance |
| --- | --- | --- | --- | --- |
| T6-01 | kernel | P0 | Implement PE TLS: parse `IMAGE_DIRECTORY_ENTRY_TLS`, call callbacks before entry/DllMain, allocate per-thread TLS templates, set TEB TLS slot pointer, and implement `TlsAlloc` / `TlsSetValue` / `TlsGetValue` / `TlsFree`. | A PE with `__declspec(thread) int x = 42` reads independent `42` values from two threads. |
| T6-02 | kernel | P1 | Implement x64 SEH: parse `.pdata`, implement `RtlLookupFunctionEntry`, `RtlVirtualUnwind`, `RtlUnwindEx`, `NtRaiseException`, context capture/restore, user exception dispatch for faults. | A PE `__try`/`__except` null write is caught and continues in the exception handler. |
| T6-03 | kernel | P1 | Implement `CreateProcessA/W` and process/thread waiting/exit/open/terminate/duplicate handle semantics. | A parent PE creates a child PE, waits, and observes the child's exit code. |
| T6-04 | kernel | P1 | Implement named mutex/event/semaphore namespace and open/create semantics with refcounted kernel objects. (Process-local name dedup landed in `kernel32!Create{Mutex,Event,Semaphore}{A,W}` + `Open{Mutex,Event,Semaphore}{A,W}`; cross-process namespace still pending kernel-resident name table.) | Parent/child PEs synchronize through a named event. |

### Track 7 — File system

> **T7-01** (FindFirstFile{A,W}, FindNextFile{A,W}, FindClose,
> wildcard matching, iterator handles, full WIN32_FIND_DATA)
> landed. **T7-02** namespace + path APIs ship: GetLogicalDrives,
> GetDriveType{A,W}, GetCurrentDirectory{A,W}, SetCurrentDirectory{A,W},
> GetFullPathName{A,W}, GetDiskFreeSpace{A,W}, GetVolumeInformation{A,W}.
> The `C:` drive maps onto the ramfs root and System32 DLL paths
> resolve through the Win32 thunks page. **T7-05** (FAT32 LFN read +
> write for VFAT 0x0F entries) shipped: `kernel/fs/fat32_dir.cpp`
> walks LFN fragment chains and stitches the UTF-16 codepoints into
> `DirEntry::name`; `kernel/fs/fat32_create.cpp` writes the
> SFN-checksummed LFN sequence + 8.3 fallback for any name that
> needs case preservation, lower-case characters, or > 8.3 length.
> Mixed 8.3 / LFN reads round-trip; UTF-16 / UTF-8 conversion runs
> through the shared LFN encode/decode helpers.

| ID | Scope | Priority | Task | Acceptance |
| --- | --- | --- | --- | --- |
| T7-03 | fs | P1 | Complete `CreateFileA/W` sharing and overlapped I/O: IOCP, `ERROR_IO_PENDING`, overlapped events, and share-mode enforcement. | A PE using overlapped file reads receives completion through `GetQueuedCompletionStatus`. |
| T7-04 | fs | P2 | Add scoped NTFS write support: create, write, truncate, delete, rename with MFT/index/journal/bitmap updates; no compression/encryption/ADS for v0. | PEs can perform basic writes to NTFS volumes. |

### Track 8 — Scheduler

| ID | Scope | Priority | Task | Acceptance |
| --- | --- | --- | --- | --- |
| T8-01 | sched | P1 | Complete MLFQ priority aging/decay, Win32 priority class/thread mappings, and work-stealing priority behavior. | A high-priority thread preempts a low-priority thread within one 10 ms tick. |
| T8-02 | sched | P1 | Implement APC queues and alertable waits for `QueueUserAPC`, `SleepEx`, `WaitForSingleObjectEx`, and `NtQueueApcThread`. (Process-local APC queue landed: `QueueUserAPC` enqueues callbacks into a 16-slot per-process table; `SleepEx(_, TRUE)` and `WaitForSingleObjectEx(_, _, TRUE)` both chunk into 10ms slices and poll the queue between each, so APCs queued from a peer thread fire within ~10ms — including the `INFINITE` case. `NtQueueApcThread` and a kernel-resident per-thread APC list still pending — that pair only matters once a workload depends on APC delivery into a kernel-blocked wait that can't be sliced from user space.) | `QueueUserAPC` wakes a target in `SleepEx(INFINITE, TRUE)` and executes the APC. |

### Track 9 — Security

> **T9-01** shipped: ring3 spawn checks `PeIsDynamicBase` on the
> Optional Header DllCharacteristics; if set, picks a 64 KiB-aligned
> delta in [0, 64 MiB) from `RandomU64`; otherwise loads at preferred
> base. **Per-DLL randomisation also shipped** — every preloaded DLL
> now draws its own `RandomU64`-derived 4 KiB-aligned delta in
> [0, 1 MiB) when its DllCharacteristics has `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE`,
> and the DllLoad call passes that delta through. The smaller
> per-DLL window keeps each DLL inside the gap between its preferred
> base and the next DLL's preferred base (typical Windows DLLs are
> spaced by tens of MiB) while still adding 8 bits of independent
> entropy per DLL. Boot log surfaces both the resulting `base_va`
> and `aslr_delta` for every DLL preload.
> **T9-02** shipped: vcruntime140 ships `__security_cookie` /
> `__security_check_cookie` / `__report_gsfailure` /
> `__report_rangefailure`, AND the PE loader's
> `SeedSecurityCookie` reads `IMAGE_LOAD_CONFIG_DIRECTORY.SecurityCookie`
> and stamps a fresh per-image cookie from the kernel RNG before
> ring-3 entry. PEs without a load config (or with a pre-/GS
> layout) silently skip the seed — the compiler-emitted save/check
> pair still holds because it compares the cookie to itself across
> one function call.
>
> **T9-03** (CFG no-op guard stubs) shipped: vcruntime140 exports
> `_guard_check_icall`, `_guard_dispatch_icall`,
> `_guard_xfg_check_icall`, and `_guard_xfg_dispatch_icall`. Bitmap
> enforcement still GAP — see `// GAP: CFG not enforced` discipline
> in the source.

### Track 10 — Build and CI

> **T10-01** GitHub Actions CI shipped — see
> `.github/workflows/build.yml` (check-format + build-debug +
> build-release + qemu-smoke jobs) and `.github/workflows/release.yml`
> (rolling channel ISO publishing). README carries the build-flavors
> + per-channel + lifetime-downloads badges.
> **T10-02** `x86_64-kasan` preset shipped — `CMakePresets.json` defines
> the configure preset (inherits `x86_64-debug`) with `DUETOS_KASAN=ON`
> and the matching `x86_64-kasan` build preset.
> **T10-03** ThinLTO release preset shipped — `CMakePresets.json` defines
> `x86_64-release-lto` with `DUETOS_LTO=ON`; the kernel link succeeds
> through lld.

| ID | Scope | Priority | Task | Acceptance |
| --- | --- | --- | --- | --- |
| T10-04 | build | P2 | Extend the hosted `ctest` harness to cover the four listed pillars. (Result, string, syscall_error, cvt, text_hash, d3dcompiler, damage_rect, wild_address are wired today; PE parser, VFS path resolution, registry lookup are still kernel-only.) | Host `ctest` runs without QEMU and covers Result + PE parser + VFS path resolution + registry lookup + string helpers. |

### Track 11 — Kernel infrastructure gaps

> **T11-01** ACPI parser coverage landed: RSDP/XSDT/RSDT discovery,
> MADT (LAPIC + I/O APIC + Interrupt Source Override + LAPIC Address
> Override), FADT (PM1A/B control, reset register, ACPI enable),
> HPET (validation + main-counter enable), SRAT (CPU + Memory
> Affinity for NUMA). AML interpreter remains the documented gap
> for ACPI S5 / battery / lid-close (Track 11-05 + Drivers).
> **T11-03** registry hive persistence landed:
> `RegistryHiveLoad` runs at boot, every successful registry mutation
> calls `RegistryHiveSave` (throttled by byte-compare). HKLM / HKCU
> / HKU + the full Reg* CRUD + enumeration surface advapi32 + the
> in-kernel registry serialise to the configured FAT32 hive.
> **T11-04** waitable + multimedia timers shipped:
> `userland/libs/kernel32/kernel32.c` allocates a manual-reset Event
> per `CreateWaitableTimer{A,W}` call and reserves a slot in the
> per-process timer table; `SetWaitableTimer` records the absolute
> due time + period and resets the event; a single lazily-spawned
> service thread polls the table every 10 ms and fires `SetEvent`
> for any timer whose due time has arrived. Periodic timers re-arm
> from the fire instant. `userland/libs/winmm/winmm.c` mirrors the
> same pattern for `timeSetEvent` — the registered TIMECALLBACK
> fires from a winmm-owned service thread, with TIME_PERIODIC
> re-arming and `timeKillEvent` deactivating the slot. Out of
> scope: APC completion routines for waitable timers (Track 8-02
> covers cross-thread APC delivery), TIME_CALLBACK_EVENT_SET /
> EVENT_PULSE flags for `timeSetEvent`, sub-10 ms resolution.

| ID | Scope | Priority | Task | Acceptance |
| --- | --- | --- | --- | --- |
| T11-02 | kernel | P1 | Implement IPC pipes/mailslots: anonymous pipes, named pipes, connect/disconnect, ring-buffer semantics, EOF, and CreateProcess stdio redirection support. | Pipe-backed stdin/stdout/stderr redirection works across parent/child processes. |
| T11-05 | kernel | P2 | Implement power management: ACPI S5 shutdown, ACPI/FADT reset fallback, and S3 stubs or suspend/resume path. | `ExitWindowsEx(EWX_POWEROFF)` powers off through ACPI S5 where supported. |

### Track 12 — Userland infrastructure

> **T12-01** (LoadLibrary / GetProcAddress / FreeLibrary /
> GetModuleHandle / GetModuleFileName) and **T12-02** (Windows 10
> 19041 system + version info via GetSystemInfo /
> GetNativeSystemInfo / GetVersionEx{A,W} / RtlGetVersion /
> IsWow64Process=FALSE) landed. **T12-04** prioritised stdio
> (`sscanf`, `fprintf`, `setvbuf`, `setbuf`, `fflush`, `tmpfile`,
> `tmpnam`, `tmpnam_s`) ships in `ucrtbase`; the long tail
> (positional args, multi-byte format directives, file-stream
> buffering) waits for a workload that exercises it.

| ID | Scope | Priority | Task | Acceptance |
| --- | --- | --- | --- | --- |
| T12-03 | win32 | P2 | Implement `winmm` waveOut APIs over HDA/audio mixer: open, prepare/write/unprepare, close, and capabilities. | A PE can play 44.1/48 kHz 16-bit stereo through `waveOut*`. |

### Track 13 — Documentation / wiki

| ID | Scope | Priority | Task | Acceptance |
| --- | --- | --- | --- | --- |
| T13-01 | docs | P2 | Complete `wiki/reference/Win32-Surface-Status.md` by auditing DLL exports and live `// STUB:` / `// GAP:` inventory. | The page has a complete REAL/STUB/GAP/MISSING table for the Win32 surface. |
| T13-02 | docs | P2 | Keep this Roadmap populated from the full project TODO and remove landed entries in the landing commit. | All imported tasks are represented here and removed as they land. |
| T13-03 | docs | P2 | Document every assigned syscall number in `wiki/specifications/Syscall-ABI.md` with args, return, subsystem, and status. | New syscall work can detect ABI number collisions from the table. |

### Track 14 — Testing

> **T14-02** (win32 pump test) is covered today by `windowed_hello`
> (CreateWindowExA → ShowWindow → message pump → InvalidateRect →
> WM_PAINT round-trip → SetTimer / WM_TIMER → SendMessage →
> KillTimer) plus `msg_smoke`, `wndmsg_smoke`, and `gdi_smoke`. A
> dedicated single-binary `win32_pump_test` would be a thin
> consolidation of those probes — book that under T14-01 if a
> regression-stress fixture is needed.

| ID | Scope | Priority | Task | Acceptance |
| --- | --- | --- | --- | --- |
| T14-01 | test | P1 | Add PE stress fixture covering threads, mutexes, events, file I/O, registry, heap, and printf for 30 seconds. | The stress PE exits 0 and joins the smoke corpus. |
| T14-03 | test | P2 | Add network loopback test once T3-01 lands: listener + connector exchange 1 MiB and verify CRC32. | The loopback test exits 0 after integrity verification. |

### Imported quick wins

All twelve imported quick wins (QW-01..QW-12) shipped — see
[`Win32-Surface-Status`](Win32-Surface-Status.md) for the per-DLL
inventory and [`Design-Decisions`](Design-Decisions.md) for the
landing notes. The table is removed; future regressions surface
through the per-DLL smoke tests in `userland/apps/*_smoke/`.

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
