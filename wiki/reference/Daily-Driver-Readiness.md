# Daily-Driver Readiness — Gap Audit

> **Audience:** project planners, contributors picking the next slice,
> anyone asking "could I run this on my laptop next month?"
>
> **Maturity:** living document; refresh when a row lands or a new
> gap is found

This page consolidates the user-visible gaps between today's
DuetOS and a state where a non-developer could install it on a
commodity laptop and use it as their primary OS. It is a digest
of [`Roadmap`](Roadmap.md) and the wider wiki, organised by
"what stops the box being usable in normal life" rather than by
subsystem.

If a row here lands, **delete it from this page** in the same
commit and update [`Roadmap`](Roadmap.md) (delete or shrink its
section) and the relevant subsystem page.

---

## Tier 0 — install + persistence (without these you cannot actually use the OS)

| Topic | Today | What's needed | Roadmap row |
|-------|-------|---------------|-------------|
| **Disk installer — orchestration + UEFI loader copy** | `install <handle> INSTALL` shell command lays down a 3-partition GPT (ESP / system / crash-dump), formats ESP and system as FAT32, seeds `/esp/boot/grub/grub.cfg` with a chainload stub, **stamps the embedded `BOOTX64.EFI` into `/esp/EFI/BOOT/BOOTX64.EFI`** (the canonical UEFI fall-back removable-media path), and mounts the new partitions at `/esp` + `/system`. Admin-gated; requires the literal `INSTALL` confirmation token. Pure-math `PlanLayout` self-test runs at every boot (`100 MiB / 1 GiB / 1 TiB / undersized-refused`) so a layout regression surfaces immediately. Source: `kernel/fs/installer.{h,cpp}`, `kernel/shell/shell_storage.cpp::CmdInstall`. | **Kernel-ELF copy** — write a real `duetos-kernel.elf` into `/system/boot/`. Embedding the running kernel into the ramfs is the bootstrap problem (kernel.elf bytes change after you embed them; classic two-stage build). Out-of-band staging (USB / network / ISO chainload / `cp` from an attached source) is the likely first cut. The grub.cfg + BOOTX64.EFI on disk already point at the expected on-disk path, so once the kernel bytes land there boot just works. | End-user features → Disk installer (shrunken to kernel-ELF residual) |
| **Writable native FS** | FAT32 read+write (LFN both directions), ramfs, DuetFS read; ext4 / NTFS read-only. Crashes still surface a `KERNEL.FIX` write attempt against a missing FAT32 disk. | A journalled, writable native FS as the system root + boot path. Rust `duetfs` crate is the planned home. | Filesystem → Stage 7+ writable FS, DuetFS |
| **NTFS write** | NTFS read works for PE loading from a real NTFS partition. | Scoped NTFS write (create, write, truncate, delete, rename). | Track 7 → T7-04 |
| **System updater** | None. | Code-signing infrastructure + A/B kernel-slot layout. The disk-installer ships the partition skeleton the A/B layout will hang off (ESP + system + crash-dump are mountable + addressable today). | End-user features → System updater |
| **ACPI S5 / soft-off** | `AcpiShutdown()` parses both `Name(_S5_, Package(...))` AND `Method(_S5_) { Return(Package(...)) }` shapes via `AmlReadS5`; the QEMU path + consumer firmware that defines `_S5_` as a method both reach the PM1 control register write. Method bodies more complex than `Return(Package{...})` (sub-method calls, conditionals, integer expressions) are still beyond the AML walker. `_PTS` / `_GTS` Method evaluation is still pending — chipsets that pre-evaluate them at firmware time work; chipsets that require runtime evaluation may stay powered. | A small AML method interpreter — enough to evaluate `_PTS` / `_GTS` (and later `_PSW`, `_PRW`, `_STA`) on real hardware. Out of scope for v0. | End-user features → ACPI S5 / soft-off |

## Tier 1 — basic hardware support (without these the laptop is unpleasant)

| Topic | Today | What's needed | Roadmap row |
|-------|-------|---------------|-------------|
| **Audio playback** | HDA register probe + codec walker + verb-encoding helpers. `winmm!waveOut*` API surface is partial: probes return a real handle, headers stamp `WHDR_PREPARED` / `WHDR_DONE`, samples are accepted and silently dropped. | DMA-coherent buffer pool + BDL programming + RUN-bit toggle so samples actually reach the codec. | Drivers → Audio; Track 12 → T12-03 |
| **Wi-Fi on real hardware** | Data + control tier complete (parsers, 4-way handshake, MLME/WDEV state machine, ring scaffolds, AES key wrap, firmware envelope verification). All exercised by self-tests; libFuzzer corpus clean. NIC MMIO paths still log "mmio_virt is null". | Real-hardware verification cycles (recommended: AR9271/AR7010 `ath9k_htc` USB first, then Intel iwlwifi). IRQ wiring on per-vendor MSI/MSI-X. iwlwifi TFD descriptor build / doorbell / per-RBD data buffers. Installer integration for offline firmware kit. | Drivers → Wireless; End-user features → Network Status |
| **Bluetooth** | HCI command/event packet parser. No transport. | btusb / btuart transport driver; L2CAP / RFCOMM / GATT stack. | Drivers → Bluetooth |
| **Battery + suspend** | Power backend flagged `backend_is_stub`. No EC / battery state surfaced. | ACPI EC driver + AML method interpreter so battery / lid / S3 work. | Drivers → Battery + ACPI suspend |
| **Brightness / Fn-keys** | Dead. | ACPI EC driver + per-vendor backlight register paths. | Drivers → Brightness |
| **Multi-monitor / hot-plug display** | Single linear framebuffer; mode set at boot via Bochs VBE. EDID parser landed; hot-plug detection missing. | Per-vendor GPU drivers + mode-set negotiation. | Drivers → Multi-monitor |
| **Real GPU acceleration** | AMD/NVIDIA/Intel probe + register peek; D3D11/D3D12/Vulkan all fall back to a software rasterizer. | Per-vendor command-ring submission (Intel RCS, AMD CP, NVIDIA GSP). | Win32 → DirectX backends; Drivers → GPU |
| **Printer / Webcam** | None. | USB printer-class driver + IPP pipeline; UVC USB-Video class driver. | Drivers → Bluetooth / Printer / Webcam |
| **High-DPI USB mouse** | Descriptor-driven decoder ships and is wired through xHCI bring-up; boot-protocol fallback works. | Real-hardware verification with a high-DPI 5-button + wheel + AC-Pan device. | Drivers → USB mouse |

## Tier 2 — common application paths (without these third-party software can't run)

| Topic | Today | What's needed | Roadmap row |
|-------|-------|---------------|-------------|
| **Static TLS (`__declspec(thread)`)** | Dynamic TLS works (`TlsAlloc` / `TlsSetValue` per-thread). Static-TLS template parsing + `TEB.ThreadLocalStoragePointer` setup + TLS callbacks not yet wired. PE loader rejects PEs with non-empty TLS callback arrays. | `IMAGE_DIRECTORY_ENTRY_TLS` parsed into per-thread template; callbacks invoked before entry / DllMain. | Track 6 → T6-01 (static-TLS half) |
| **Structured Exception Handling** | `__try` / `__except` blocks unwind nothing. | `.pdata` parser, `RtlLookupFunctionEntry`, `RtlVirtualUnwind`, `RtlUnwindEx`, `NtRaiseException`, context capture/restore, user dispatch on faults. | Track 6 → T6-02 |
| **GDI accelerated paint** | Software fills via `FramebufferPutPixel` / `FillRgba`. | Intel iGPU 2D blitter (Gen9+/Xe). | Track 4 → T4-03 |
| **Async sockets** | Synchronous BSD subset works; `WSAEvent*` plumbing landed but never fires events (TCP stack doesn't drive `pending` mask changes). | Producer side: socket readiness transitions raise `FD_*` events on registered bindings; IOCP overlapped socket reads. | Win32 → Winsock async |
| **HLSL / shader execution** | DirectX DLLs ship real COM vtables; shaders are parsed by `d3dcompiler` to a DXBC-shaped blob but never executed. | Bytecode interpreter (or JIT) + texture sampling + Z-buffer. | Win32 → DirectX backends |
| **Modal dialogs / common controls** | Popup menus + `WM_CONTEXTMENU` ship; menus / scroll bars / outline fonts / multi-thread message queues missing. | Modal-input loop + remaining USER controls + menubar `LoadMenu`. | Win32 → Windowing |
| **Image viewers (PNG / JPEG)** | BMP works (`kernel/util/png.cpp` + `gzip.cpp` + `deflate.cpp` + `crc32.cpp` exist in tree but ImageView only dispatches for BMP). | Wire the existing PNG decoder through ImageView; add Huffman + IDCT for JPEG. | End-user features → Image viewers |
| **PDF / video viewers** | None. | Out of scope until base apps mature; PDF is large. | End-user features → PDF / video |

## Tier 3 — quality-of-life (without these the OS feels unfinished)

| Topic | Today | What's needed | Roadmap row |
|-------|-------|---------------|-------------|
| **Terminal emulator (windowed shell)** | `Ctrl+Alt+T` opens the kernel shell (ring-0). | Console-multiplex refactor so the shell takes a per-session sink + a windowed userland host. | End-user features → Terminal emulator |
| **IME / non-Latin input** | PS/2 + xHCI HID drivers hardcode US layout. | Input-method framework refactor. | End-user features → IME |
| **Locale / language switching** | UI strings are C++ literals in `kernel/apps/*.cpp`. | String-table layer with id → text indirection. | End-user features → Locale |
| **Accessibility** | Magnifier landed. | Screen reader (AT-SPI-equivalent kernel surface), on-screen keyboard. | End-user features → Accessibility |
| **Device Manager — virtio + eject + hot-unplug** | PCI + USB tables, read-only. | Virtio bus walker, `Eject` capability gating, hot-unplug paths in AHCI / xHCI. | End-user features → Device Manager |
| **Per-process namespace roots (full)** | Global mount table works. Sandbox roots can graft individual mounts but can't themselves be a non-ramfs backend node. | `Process::root` carries a `VfsNode*` + open / stat / readdir lift to that abstraction. | Storage → Stage 6 |

## Tier 4 — kernel hardening (transparent to a daily-driver user; matters for production)

| Topic | Today | What's needed | Roadmap row |
|-------|-------|---------------|-------------|
| **Per-CPU scheduler lock** | SMP per-CPU runqueues + work-stealing live; mutations still serialise on a global `g_sched_lock`. Acceptable for current workloads. | Split the lock per-CPU once profiles show contention. Unlocks priority-band scheduling (T8-01-followon). | Kernel/runtime → B2-followup |
| **Buddy coalescing + per-CPU slab magazines** | IRQ-safe `KMalloc` / `KFree` ship with documented context contract. | Buddy coalescing on the kheap; per-CPU slab magazines once a workload demands them. | Kernel/runtime → Slab/buddy; Track 5 → T5-04 |
| **Real KASLR** | KASLR enabled in flavour; UEFI loader doesn't yet pick a random kernel base. | Memory-map scan in UEFI loader, random 2 MiB-aligned base in 64 MiB window, boot-info handoff. | Track 5 → T5-03 |
| **Intel CET enable** | Off in CR4 protection bits. | Validate IBT / shadow-stack interaction with our context switch + signal-equivalent paths. | Kernel/runtime → CET enable |
| **Crash-dump persistence on installed disk** | NVMe + AHCI panic-write paths land; reserve via tail-of-drive fallback. | Real GPT partition reservation once the installer ships. | Storage → Crash-dump persistence |
| **Cluster-broadcast IPIs** | UMA + SRAT-aware NUMA frame allocator + cluster-aware work-stealing live. | x2APIC cluster-mode broadcast for fan-out wakes / shootdowns. | Kernel/runtime → Topology follow-ons |

## Tier 5 — verification gaps (matters for whether the above can be trusted)

| Topic | Today | What's needed |
|-------|-------|---------------|
| **Hosted ctest pillars** | 9 hosted tests pass: `result`, `string`, `syscall_error`, `cvt`, `text_hash`, `d3dcompiler`, `damage_rect`, `wild_address`, `disk_path`. | PE parser + VFS path resolve + registry lookup get hosted shims as their kernel headers stop pulling in transitive kernel-only includes. (See Track 10 → T10-04.) |
| **CI smoke ISO** | `tools/test/ctest-boot-smoke.sh` runs the debug ISO under QEMU and asserts ~30 sentinel signatures from `ring3_smoke.cpp`. Default 90s timeout sometimes truncates winkill output on slow hosts. | Bump the default timeout above 90s on CI hosts where TCG is slow, or convert the harness from "string-search the serial log" to "boot-completion sentinel + structured assertions". |
| **Real-hardware bring-up** | All hardware verification is QEMU-only. | Bring-up runs on at least one Intel-NUC-class machine + one AMD laptop + one ARM64 board (post-port). |

---

## Cross-cutting prerequisites

A handful of items unblock several tiers at once. Land them
before the dependent rows:

- **AML method interpreter** — unblocks ACPI S5, ACPI EC (battery
  + brightness), per-CPU sleep states. Today's AML walker reads
  Names; it doesn't evaluate Methods. (Tier 0, Tier 1.)
- **Disk installer orchestration** — unblocks GPT partition
  reservation for crash dumps and the writable-FS rollout. (Tier 0,
  Tier 4.)
- **Per-CPU `g_sched_lock` split** — unblocks MLFQ priority bands
  (T8-01-followon), real Win32 priority class effects, lockdep
  arrays keyed by current-CPU. (Tier 4, Tier 2.)
- **Per-vendor GPU command-ring submission** — unblocks DirectX
  real-device backends, GPU-accelerated GDI paint (T4-03), and
  hot-plug / mode-set on multi-monitor setups. (Tier 1, Tier 2.)

---

## Audit cadence

Refresh this page when:

1. A row in [`Roadmap`](Roadmap.md) lands and removes a daily-driver gap.
2. New hardware bring-up surfaces a category of failure not currently listed.
3. A user-visible feature graduates from "works in QEMU" to "works on real hardware."

Cross-check with `git grep -nE "// (STUB|GAP):"` for the kernel-side
marker count, and with [`Win32-Surface-Status`](Win32-Surface-Status.md)
for the user-mode DLL inventory.
