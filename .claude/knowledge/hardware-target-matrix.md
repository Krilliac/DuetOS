# Hardware Target Matrix

**Last updated:** 2026-04-20
**Type:** Decision
**Status:** Active

## Description

CustomOS targets **typical commodity PC hardware**. This entry records the specific CPU / GPU / chipset / IO combinations we commit to supporting, in tiers. The matrix is the forcing function for driver work — we do not build a driver for hardware that is not on the matrix.

## Context

Applies to every driver directory (`drivers/`), the HAL layer (`kernel/arch/`), and the GPU user-mode stack (`subsystems/graphics/`). Also constrains the Win32 subsystem: it can assume that the hardware underneath is one of these tiers.

---

## Details

### CPU tiers

| Tier | Architecture | Minimum baseline | Notes |
|------|--------------|------------------|-------|
| 1 | x86_64 (Intel) | Haswell (2013) — AVX2, BMI1/2, FMA3 | Assume SSE4.2, AVX2, POPCNT, CMPXCHG16B. |
| 1 | x86_64 (AMD) | Ryzen 1xxx (Zen 1, 2017) | Same feature baseline as Intel Haswell. |
| 2 | x86_64 (Intel) | Skylake (2015) + | Additional optional features: AVX-512 subsets, TSX (disabled by default). |
| 2 | x86_64 (AMD) | Zen 2 / Zen 3 / Zen 4 | Full AMD64v3 microarchitecture level. |
| 3 | aarch64 | ARMv8.2-A + | Planned. Apple Silicon + Ampere / Cavium server. Not started. |

Tier 1 is the **baseline** — everything must work here. Tier 2 can opt into extra features via runtime CPUID checks.

Sub-Haswell Intel and sub-Zen AMD are **not** supported. No 32-bit x86. No Itanium. No pre-ARMv8.2 aarch64.

### GPU tiers

| Tier | Vendor | Family | Minimum baseline | Driver strategy |
|------|--------|--------|------------------|-----------------|
| 1 | Intel | iGPU | Gen9 (Skylake) → Gen12 (Tiger Lake / Alder Lake) | First-party kernel driver, Vulkan user-mode. |
| 1 | AMD | Radeon | GFX9 (Vega) → RDNA3 | First-party kernel driver. Reference: AMDGPU open docs. |
| 1 | NVIDIA | GeForce / RTX | Turing (RTX 20xx) + | First-party kernel driver via NVIDIA's open-source kernel modules interface, or reverse-engineered for older cards. |
| 2 | Intel | Arc (Alchemist+) | Xe-HPG | Planned after Tier 1 Gen9–12 is done. |
| 2 | AMD | RDNA4 (future) | TBD | Slot held. |
| 2 | NVIDIA | Ada / Blackwell | TBD | Slot held. Expect no official support path for older closed generations. |
| 3 | VM / software | Virtio-GPU, QEMU stdvga, Bochs VBE | — | Mandatory for dev. Boot path must not *require* a real GPU. |

Tier 3 is critical: bring-up happens in QEMU long before any of Tier 1 gets touched. A software rasterizer (lavapipe-style, but written in-house or via a minimal Mesa embed) fills in where no GPU driver is present.

### Storage / IO tiers

| Class | Baseline | Notes |
|-------|----------|-------|
| NVMe | Mandatory | Primary storage driver. |
| AHCI / SATA | Mandatory | Legacy storage support. |
| USB | xHCI mandatory | HID + MSC classes mandatory; hubs required. EHCI/OHCI/UHCI not supported. |
| Ethernet | Intel e1000/e1000e, Realtek rtl8169, and one USB-Ethernet class driver | Mandatory for networking stack bring-up. |
| Wi-Fi | iwlwifi first | Deferred until native network stack is real. |
| Audio | Intel HDA | AC'97 not supported. |
| Input | PS/2 keyboard + mouse (legacy), USB HID | PS/2 is a legacy fallback for bring-up in QEMU. |
| Display | UEFI GOP, VESA / VBE | Required for early console before any GPU driver loads. |

### Firmware / boot

- **UEFI is mandatory** for Tier 1. `BOOTX64.EFI` in `boot/uefi/`.
- **Legacy BIOS** is not supported in new work. A stub may be added later *if* a target machine requires it.
- **Secure Boot**: boot loader is signable. Enabling is future work; disabling Secure Boot is not a supported recommendation for end users.

### Memory baseline

- **4 GiB minimum** (we'll aim for 2 GiB-usable after reserves, pinned allocations, etc.).
- **IOMMU**: Intel VT-d or AMD-Vi required for GPU passthrough, DMA-remapping safety. If absent, the kernel refuses to load untrusted drivers by default.
- **NX + SMEP + SMAP**: required. W^X enforced. If a CPU lacks these, CustomOS refuses to boot.

---

## Implications

- **Drivers not in the matrix are not written.** An AMD HD 7000 (GCN1) driver is not on the roadmap. We do not accept PRs for hardware outside the matrix without the matrix being updated first (via a new decision entry revising this one).
- **CPU feature assumptions** can be baked into the kernel compile flags for Tier 1: `-march=haswell` or `-march=znver1` at minimum. Runtime dispatch is only needed for Tier 2 extras.
- **QEMU + virtio-gpu is the primary dev path.** A driver dev who lacks the real hardware can still make progress against the Tier 3 line.
- **ARM64 is a second tier**, explicitly. No x86-isms should leak into the kernel's architecture-neutral layers, even today, so porting cost stays bounded when Tier 3 CPUs move up.

---

## Notes

- This matrix is a **living decision**. Any addition or removal is a new edit to this entry, committed alongside whatever driver work it enables.
- If a future matrix revision removes a tier or generation, **keep the old row as `Status: Superseded`** in this entry — the commit history alone is not enough; future sessions should see what we used to support and why we stopped.
- **See also:** [win32-subsystem-design.md](win32-subsystem-design.md) — the Win32 subsystem assumes this matrix for its DXGI/D3D11/D3D12 translation layer.
