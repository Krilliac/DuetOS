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
| **Disk installer — orchestration + UEFI loader + kernel-ELF (gated)** | `install <handle> INSTALL [--duetfs]` shell command lays down a 3-partition GPT (ESP / system / crash-dump), formats ESP as FAT32 and system as FAT32 (default) or DuetFS (`--duetfs`), seeds `/esp/boot/grub/grub.cfg` with a chainload stub, **stamps the embedded `BOOTX64.EFI` into `/esp/EFI/BOOT/BOOTX64.EFI`** (canonical UEFI fall-back removable-media path), **writes `/system/boot/duetos-kernel.elf` from an `.incbin`-embedded blob when `DUETOS_INSTALLER_KERNEL_EMBED=ON`** (off by default; doubles binary size), and mounts the new partitions at `/esp` + `/system`. Admin-gated; literal `INSTALL` confirmation token. Pure-math `PlanLayout` self-test runs every boot. Source: `kernel/fs/installer.{h,cpp}`, `kernel/shell/shell_storage.cpp::CmdInstall`, `tools/build/gen-kernel-blob.sh`. | **None — embed path self-boots.** The embedded ELF now sits in a dedicated `.kernel_elf_blob` section pinned at physical 32 MiB by `kernel/arch/x86_64/linker.ld` (separate PT_LOAD, clear of the 0..16 MiB DMA zone). `_kernel_end_phys` is byte-identical with the embed ON vs OFF, so `DUETOS_INSTALLER_KERNEL_EMBED=ON` no longer starves the legacy-ISA DMA zone or trips `mm/zone`. `kernel/mm/frame_allocator.cpp` reserves the blob's physical extent separately (no-op when OFF). | Done |
| **Writable native FS** | DuetFS shipped with the full write surface: `duetfs_write_at`, `duetfs_create_path`, `duetfs_unlink_path`, `duetfs_truncate`, `duetfs_link`, `duetfs_create_symlink`, journal (`duetfs_journal_apply` / `duetfs_journal_state`), CRC-checked blocks, AES-XTS sector encryption + Argon2id KDF, LZ4 compression, snapshots. RAM-backed `/duetfs` mount is online on every boot; on-disk `/disks/duetfsN` mounts auto-register. The disk installer's `--duetfs` flag formats the system partition as DuetFS instead of FAT32 — gives operators a journalled, encryption-capable system filesystem out of the box. FAT32 read+write (LFN both directions) and ramfs also writable. ext4 / NTFS read-only. | Boot kernel directly from a DuetFS root rather than chainloading FAT32-then-DuetFS. Requires GRUB / UEFI to grow a DuetFS reader, OR a multi-stage handoff where a tiny FAT32 ESP boots a kernel that pivots to DuetFS as `/`. The pivot half is mechanical once the kernel-ELF embed lands on the installer (current installer caps at filesystem skeleton; kernel-ELF copy still pending). | Filesystem → DuetFS follow-ups |
| **NTFS write** | NTFS read works for PE loading from a real NTFS partition. | Scoped NTFS write (create, write, truncate, delete, rename). | Track 7 → T7-04 |
| **System updater** | None. | Code-signing infrastructure + A/B kernel-slot layout. The disk-installer ships the partition skeleton the A/B layout will hang off (ESP + system + crash-dump are mountable + addressable today). | End-user features → System updater |
| **ACPI S5 / soft-off** | `AcpiShutdown()` parses both `Name(_S5_, Package(...))` AND `Method(_S5_) { Return(Package(...)) }` shapes via `AmlReadS5`; the QEMU path + consumer firmware that defines `_S5_` as a method both reach the PM1 control register write. Method bodies more complex than `Return(Package{...})` (sub-method calls, conditionals, integer expressions) are still beyond the AML walker. `AcpiShutdown` now runs `\_PTS(5)` + legacy `\_GTS(5)` through the AML interpreter (`AcpiRunSleepPrep`) **before** the PM1 SLP_TYP/SLP_EN write, in ACPI §7 order — the step real laptops need to actually power off (EC poke / SMI arm in `_PTS`). | S3/S0ix suspend-to-RAM wake-vector + context save/restore; `_Qxx` GPE/SCI event dispatch. Real-hardware soft-off validation pending (no HW in CI; QEMU declares no root `\_PTS`/`\_GTS`, so the new call is a verified no-op there and the `_S5_`+PM1 path drives the QEMU soft-off). | End-user features → ACPI S5 / soft-off |

## Tier 1 — basic hardware support (without these the laptop is unpleasant)

| Topic | Today | What's needed | Roadmap row |
|-------|-------|---------------|-------------|
| **Audio playback** | DMA-coherent BDL + PCM ring allocated, BDL filled, stream armed + RUN toggled by `subsystems/audio/audio_backend`; producer path live (`SYS_AUDIO_WRITE` 210 ← winmm `waveOutWrite`); QEMU smoke runs `-device intel-hda -device hda-output`; backend active + self-test PASS (silence/sine/Start/Stop/LPIB) every boot. | **Audible output**: HDA codec walker reads `SubordinateNodeCount==0` on QEMU's `hda-output` (node-0 VendorId verb works), so no DAC→pin route — suspected RIRB poll/timing in `IssueVerbAndPoll` for the 2nd+ verb. Bytes still DMA on real HW with a working codec walk. Real-HW audible validation pending (no HW in CI). Separately-tracked follow-up slice. | Drivers → Audio; Track 12 → T12-03 |
| **Wi-Fi on real hardware** | Data + control tier complete (parsers, 4-way handshake, MLME/WDEV state machine, ring scaffolds, AES key wrap, firmware envelope verification). All exercised by self-tests; libFuzzer corpus clean. NIC MMIO paths still log "mmio_virt is null". | Real-hardware verification cycles (recommended: AR9271/AR7010 `ath9k_htc` USB first, then Intel iwlwifi). IRQ wiring on per-vendor MSI/MSI-X. iwlwifi TFD descriptor build / doorbell / per-RBD data buffers. Installer integration for offline firmware kit. | Drivers → Wireless; End-user features → Network Status |
| **Bluetooth** | HCI command/event packet parser. No transport. | btusb / btuart transport driver; L2CAP / RFCOMM / GATT stack. | Drivers → Bluetooth |
| **Battery + suspend** | ACPI EC driver (`kernel/acpi/ec.{h,cpp}`) registers the EmbeddedControl region handler; `kernel/acpi/acpi_power.cpp` decodes `_STA`/`_BIF`/`_BST` (battery), `_PSR` (AC), `_LID` (lid) through the AML interpreter and feeds `drivers/power` — `backend_is_stub` is cleared whenever live ACPI data exists, re-polled each `PowerSnapshotRead`. QEMU (no power AML) falls back to the SMBIOS heuristic. | S3/S0ix suspend-to-RAM wake plumbing; `_Qxx` GPE/SCI query dispatch for lid-close *events* (lid *state* already readable). EC port discovery uses the de-facto 0x66/0x62 rather than ECDT/`_CRS` (GAP). Real-hardware validation pending (no HW in CI). | Drivers → Battery + ACPI suspend |
| **Brightness / Fn-keys** | ACPI path landed: `AcpiBacklight{Levels,Get,Set}` drive `_BCL`/`_BQC`/`_BCM` via the interpreter. | Per-vendor *register* backlight (Intel/AMD PWM, vendor WMI) for non-ACPI laptops; wiring the UI control + Fn-key hotkey events to `AcpiBacklightSet`. | Drivers → Brightness |
| **Multi-monitor / hot-plug display** | Single linear framebuffer; mode set at boot via Bochs VBE. EDID parser landed; hot-plug detection missing. | Per-vendor GPU drivers + mode-set negotiation. | Drivers → Multi-monitor |
| **Real GPU acceleration** | AMD/NVIDIA/Intel probe + register peek; D3D11/D3D12/Vulkan all fall back to a software rasterizer. | Per-vendor command-ring submission (Intel RCS, AMD CP, NVIDIA GSP). | Win32 → DirectX backends; Drivers → GPU |
| **Printer / Webcam** | None. | USB printer-class driver + IPP pipeline; UVC USB-Video class driver. | Drivers → Bluetooth / Printer / Webcam |
| **High-DPI USB mouse** | Descriptor-driven decoder ships and is wired through xHCI bring-up; boot-protocol fallback works. | Real-hardware verification with a high-DPI 5-button + wheel + AC-Pan device. | Drivers → USB mouse |

## Tier 2 — common application paths (without these third-party software can't run)

| Topic | Today | What's needed | Roadmap row |
|-------|-------|---------------|-------------|
| **Structured Exception Handling** | **Landed (T6-02 slices 1-3).** Unwinder (`RtlCaptureContext` / `RtlLookupFunctionEntry` — now cross-module via `SYS_MODULE_BASE_BY_VA` / `RtlVirtualUnwind` / `RtlCaptureStackBackTrace`) plus the full kernel-fault → user dispatch: a ring-3 #DE/#UD/#GP/#PF in a Win32 PE is delivered as a Microsoft `EXCEPTION_RECORD`+`CONTEXT` resumed at `ntdll!KiUserExceptionDispatcher`, which runs the Vectored Exception Handler chain then the frame-based `__C_specific_handler`/`RtlUnwindEx`/`RtlRestoreContext` walk; `NtContinue`/`NtRaiseException` real. Verified by `userland/apps/seh_pe` (VEH, `smoke=pe-hello`) **and** `userland/apps/seh_try_pe` — real MSVC `__try`/`__except`/`__finally` built with `clang --target=x86_64-pc-windows-msvc -fasync-exceptions` against our own `kernel32.lib`/`ntdll.lib`: null-write #PF, divide-by-zero #DE, `__finally`-on-unwind, and a repeatable case all PASS; zero browser regression. | C++ EH (`__CxxFrameHandler*` / `_CxxThrowException`) still terminates — needs the MSVC C++ EH funclet model + throw machinery (separate slice). | Track 6 → C++ EH (`__CxxFrameHandler4`) |
| **Win32 synchronization (V8/Chrome thread-pool)** | **Landed.** Address-keyed wait is real end-to-end: kernel `SYS_WAIT_ON_ADDRESS` / `SYS_WAKE_BY_ADDRESS` futex (address-hashed wait queues, spurious-but-never-lost wakeups) backs userland `WaitOnAddress` / `WakeByAddressSingle` / `WakeByAddressAll`, condition variables (`InitializeConditionVariable`, `SleepConditionVariableCS`/`SRW`, `WakeConditionVariable`, `WakeAllConditionVariable`, sequence-counter algorithm), and the explicit `InitOnceBeginInitialize` / `InitOnceComplete`. Modern APIs bind through a new api-set host resolver — an `api-ms-win-*` / `ext-ms-win-*` import is resolved by function name against the preloaded base DLL that hosts it (unblocks the whole synch contract for Chrome, not just these). Verified by `userland/apps/sync_smoke` (`smoke=pe-hello`): cross-thread CV producer/consumer, WaitOnAddress handshake, two-call InitOnce — all PASS; zero browser regression. | SRW shared still aliases exclusive (no reader/writer split). Cross-process futex (shared-section addresses across processes) is in-process only. api-set host resolution is "first preloaded export by name" — a heuristic, not a real api-set schema. | Win10 API breadth → synchronization follow-ups (SRW reader/writer; cross-process futex) |
| **GDI accelerated paint** | Software fills via `FramebufferPutPixel` / `FillRgba`. | Intel iGPU 2D blitter (Gen9+/Xe). | Track 4 → T4-03 |
| **Async sockets** | Synchronous BSD subset works; `WSAEvent*` plumbing now has a real producer side — `kSockOpPollEvents` reports FD_READ/WRITE/ACCEPT/CLOSE per socket; `WSAEnumNetworkEvents` queries it inline; `WSAWaitForMultipleEvents` runs a 10 ms-cadence polling loop that signals event handles when sockets become ready. | IOCP overlapped socket reads (kernel32 IOCP plumbing exists but isn't wired into the socket read path); kernel-direct event signaling at the moment of socket activity to retire the polling cadence. | Win32 → Winsock async |
| **HLSL / shader execution** | DirectX DLLs ship real COM vtables; shaders are parsed by `d3dcompiler` to a DXBC-shaped blob but never executed. | Bytecode interpreter (or JIT) + texture sampling + Z-buffer. | Win32 → DirectX backends |
| **Modal dialogs / common controls** | Popup menus + `WM_CONTEXTMENU` ship; menus / scroll bars / outline fonts / multi-thread message queues missing. | Modal-input loop + remaining USER controls + menubar `LoadMenu`. | Win32 → Windowing |
| **Image viewers (PNG / JPEG / TGA)** | BMP, **TGA, and PNG all decode + display through ImageView** (`kernel/apps/imageview.cpp::DecodePng` reads the file, calls `util::PngParseHeader` + `util::PngDecode` from `kernel/util/png.{h,cpp}` which lean on `util/gzip` + `util/deflate` + `util/crc32`). Supports 8-bit RGB / RGBA, non-interlaced. The .png / .tga / .bmp extension dispatcher in ImageView already routes correctly. | JPEG — needs Huffman + IDCT decoder; out of scope for v0. Interlaced PNG (Adam7) + palette / grayscale colour types + ancillary chunks beyond IHDR/IDAT/IEND. | End-user features → Image viewers (now JPEG only) |
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
| **Crash-dump persistence on installed disk** | End-to-end. **NVMe + AHCI panic-write paths consult `GptFindCrashDumpRegion` first** (matches the installer's `kDuetCrashDumpTypeGuid` 4 MiB tail partition), then fall back to tail-of-drive when the installer hasn't run. `lastdump` shell command surfaces the on-disk LBA + byte count. `DiskPersistSelfTest` exercises both paths at boot. | None for v0 — the row closes once a real-hardware panic dumps successfully on an installed disk and `lastdump` reads the bytes back. | Storage → Crash-dump persistence (closed) |
| **Cluster-broadcast IPIs** | UMA + SRAT-aware NUMA frame allocator + cluster-aware work-stealing live. | x2APIC cluster-mode broadcast for fan-out wakes / shootdowns. | Kernel/runtime → Topology follow-ons |

## Tier 5 — verification gaps (matters for whether the above can be trusted)

| Topic | Today | What's needed |
|-------|-------|---------------|
| **Hosted ctest pillars** | 9 hosted tests pass: `result`, `string`, `syscall_error`, `cvt`, `text_hash`, `d3dcompiler`, `damage_rect`, `wild_address`, `disk_path`. | PE parser + VFS path resolve + registry lookup get hosted shims as their kernel headers stop pulling in transitive kernel-only includes. (See Track 10 → T10-04.) |
| **CI smoke ISO** | `tools/test/ctest-boot-smoke.sh` runs the debug ISO under QEMU and asserts **41 sentinel signatures** (PE smoke + boot self-tests + installer layout self-test + the three portable native apps). Inner DUETOS_TIMEOUT default bumped from 90s → 150s; outer CTest TIMEOUT bumped from 120s → 200s so neither flakes when QEMU TCG runs a hair slow on CI. | Convert the harness from "string-search the serial log" to "structured `[smoke] profile=… complete` event + assertions" — single sentinel, no per-signature pattern matching. Out of scope for v0. |
| **Real-hardware bring-up** | All hardware verification is QEMU-only. | Bring-up runs on at least one Intel-NUC-class machine + one AMD laptop + one ARM64 board (post-port). |

---

## Cross-cutting prerequisites

A handful of items unblock several tiers at once. Land them
before the dependent rows:

- ~~**AML method interpreter**~~ — **LANDED**
  (`kernel/acpi/aml_eval.{h,cpp}`): a v0 tree-walking interpreter
  (operands / arithmetic / control flow / Field + OperationRegion
  access / nested method calls) with a registrable
  EmbeddedControl region handler and a boot self-test. (Tier 0,
  Tier 1.)
- ~~**ACPI EC driver + battery/AC/lid/brightness**~~ — **LANDED**
  (`kernel/acpi/ec.{h,cpp}` + `kernel/acpi/acpi_power.{h,cpp}`):
  EmbeddedControl handler registered; `_STA`/`_BIF`/`_BST`/`_PSR`/
  `_LID`/`_BCL`/`_BQC`/`_BCM` decoded and surfaced through
  `drivers/power`. Remaining: S3 suspend, `_Qxx` GPE events,
  per-vendor register backlight, real-HW validation. (Tier 1.)
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
