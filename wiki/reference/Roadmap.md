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
  byte-for-byte. See [CPU Topology](../kernel/CPU-Topology.md).
- **Remaining scope:** the topology + cluster machinery has two
  more profile-driven follow-ons:
  - **Cluster-broadcast IPIs** — extend `arch::SmpSendIpi` with
    cluster-scoped destination bits when x2APIC cluster mode is
    in use; lets a wake or shootdown fan out within a cluster
    in one ICR write.
  - **Placement affinity at spawn / wake** — at task creation
    (and on `WaitQueueWakeOne`), route to the parent's cluster's
    least-loaded CPU rather than just `last_cpu`. Adds a per-
    cluster load counter.
- **Blocks on:** profile evidence — both items are workload-
  triggered, not pre-emptive.

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
  self-test landed alongside this entry. `cd /disk/0/SUB` and
  every other "give me the resolved node" caller now goes
  through one VFS API; backend dispatch is a vtable hop.
- **Remaining scope:** teach `Process::root` to carry a
  `VfsNode` (or a `VfsDir*` thin handle) so a sandboxed
  process can be rooted at a non-ramfs subtree (e.g. `/disk/0/SANDBOX`).
  Today every process root is a `const RamfsNode*` and the
  cross-mount path always falls through to ramfs at the leaf.
  The wider syscall surface (open / stat / readdir) still
  lands in `RamfsNode*` — migrating those is a per-syscall
  follow-on once a workload demands a non-ramfs sandbox root.

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
  The path is exercised at every boot via
  `DiskPersistSelfTest` so a regression surfaces in the
  boot log instead of waiting for a real panic. The
  `lastdump` shell command surfaces the on-disk LBA + byte
  count alongside the in-RAM minidump status.
- **Deferred:** the same persistence story for AHCI/SATA
  namespaces (the AHCI driver doesn't have a panic-write
  helper yet), and a real partition-table reservation so
  the disk installer can allocate the dump region
  explicitly instead of trusting the last 4 MiB to be
  unused. Both items wait for a workload that legitimately
  exercises a real-hardware AHCI disk; QEMU's NVMe path
  covers the v0 verification.

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
  to verify the byte-level path. Also: a "find first speaker
  pin" heuristic that picks the dac_node / pin_node pair to
  hand `ConfigureOutputPath`. Today the helper is called by
  no one — it's plumbing waiting for a consumer.
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

### USB mouse — high-DPI 16-bit XY (parser + injector landed)

- **Today:** descriptor-driven decoding is in tree.
  `HidExtractMouseLayout` walks a HID report descriptor and
  records per-field bit offsets / sizes / sign for X / Y /
  Wheel / AC Pan / Button-mask + the optional Report ID byte.
  `HidMouseInjectWithLayout` extracts each named field at the
  recorded bit offset (8 / 12 / 16 bits — sign-extended for
  signed axes) and injects a `MousePacket`. The xHCI polling
  loop calls the layout-aware path when
  `dev.hid_mouse_layout_valid`, otherwise falls back to the
  existing boot-protocol `HidMouseInjectN`.
- **Self-tested:** boot-keyboard / boot-mouse / a synthetic
  high-DPI 5-button + 16-bit-XY + wheel + AC-Pan descriptor
  all round-trip through `HidExtractMouseLayout` with the
  expected bit offsets at boot.
- **Remaining (gated on real hardware):** wire
  `GET_DESCRIPTOR(Report)` (kDescTypeReport = 0x22) into
  the HID enumeration step in `xhci_enum.cpp` so
  `dev.hid_mouse_layout` is populated for real mice — today
  the layout slot stays invalid and the polling loop uses
  the boot-protocol fallback. The HID class descriptor
  inside the Configuration tree carries the report-descriptor
  length; the fetch is one extra `DoControlIn` call. Defer
  until the test fleet includes a high-DPI mouse to verify
  the byte-level decode.
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

- **Today:** synchronous BSD-socket subset works.
- **Deferred:** WSAEventSelect + overlapped I/O + completion
  ports.

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
  `tx_dropped_firewall` column, and a routing/DNS section
  (gateway + DNS resolver + DHCP server + lease seconds)
  pulled from `DhcpLeaseRead()` back the Start menu's
  NETWORK STATUS entry (`kernel/apps/netstatus.cpp`).
- **Blocks on:** Wi-Fi scan results from `kernel/net/wifi.cpp`
  for an SSID picker. Routing surface is single-lease
  today — multi-iface lease tracking happens when more than
  one DHCP transaction can be live at once.

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
