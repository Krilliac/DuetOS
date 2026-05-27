# Open Firmware Landscape — 2026 Snapshot

> **Audience:** firmware-loader maintainers, hardware-support
> planners, security reviewers
>
> **Maturity:** survey — refresh quarterly. The "next-step" rows
> are recommendations, not commitments
>
> **Why this page exists:** every project below was evaluated for
> "can DuetOS load this, today, without compromising on
> redistributability?" Capturing the current state here means the
> next planning session doesn't have to re-walk the world

## Decision summary

| Family | Verdict | Why |
|--------|---------|-----|
| Qualcomm AR9271 / AR7010 (`ath9k_htc`) | **Adopt now** | Only open Wi-Fi firmware that runs on commodity hardware you can actually buy. Last commit 2023-11; build still works. First-target dongle. |
| MediaTek `mt76` (MT76xx/MT79xx/MT792x/MT799x) | **Adopt (closed-redist)** | Open driver, closed-but-redistributable firmware in `linux-firmware/mediatek/`. Best modern hardware coverage per redistribution license. |
| Realtek `rtw88` / `rtw89` | **Adopt (closed-redist)** | No open alternative exists or is coming. Closed-redist via `linux-firmware/rtw88`,`rtw89/`. |
| Intel `iwlwifi` | **Adopt (closed-signed)** | Retail Intel devices require Intel-signed firmware. Stage from `linux-firmware` at install time with a per-blob consent prompt. Our `.ucode` builder is for lab/unsigned only. |
| Broadcom + Cypress FullMAC + Nexmon | **Watch** | Nexmon is still active (Pixel 8 firmware patches landed June 2025) but only a patcher over closed Broadcom base images. Relevant when DuetOS targets Raspberry Pi. |
| Broadcom OpenFWWF / `b43-openfwwf` | **Skip** | Last update 2009-era. Hardware list is 802.11b/g, ~2008. Document in the wiki as the cautionary tale; do not invest. |
| openwifi (open-sdr) | **Watch** | The only truly-open Wi-Fi NIC stack — SDR-on-Zynq FPGA. v1.5.0 shipped August 2025. Not a user-target; useful CI / research signal. |
| ESP32-Open-MAC | **Cite, don't adopt** | Reverse-engineered MAC on ESP32 silicon. Methodology is the most credible recent open-Wi-Fi work; not a host NIC. |
| NVIDIA Turing+ GPUs | **Adopt (closed-signed GSP)** | `open-gpu-kernel-modules` is the open kernel half; GSP firmware is NVIDIA-signed. No open replacement is plausible. Match `linux-firmware` blob paths. |
| AMD GPUs (RDNA2/3/4) | **Adopt (closed-redist)** | `amdgpu` driver open; PSP/SMU/GFX/SDMA/MEC/etc. all closed-redist. Best balance for modern open-driver + redist-firmware. |
| Intel GPUs (Gen9+ + Xe) | **Adopt (closed-signed GuC/HuC/DMC)** | GuC mandatory from Gen12 onward; `xe` driver cannot run without it. Stage from `linux-firmware/{i915,xe}/`. |
| Coreboot + Intel FSP | **Adopt (closed FSP)** | "Fully open coreboot" is essentially pre-Sandy-Bridge Intel + a few pre-PSP AMD chipsets. Modern x86 always pulls FSP + microcode. Practical answer: stage them at build time. |
| Libreboot deguard (T480 / T480s) | **Watch** | Newest modern x86 laptop with usable libre boot path; landed Dec 2024. Worth tracking as the dev-machine option for "no closed firmware in the boot chain". |
| OpenPOWER POWER9 (Talos II / Blackbird) | **Reference target** | The only modern mainstream CPU with end-to-end open firmware (Hostboot + Skiboot + OCC). Use as the "fully open" verification target. |
| RISC-V (VisionFive 2, HiFive Premier P550, Milk-V Megrez) | **Watch** | Closest to fully-open at the silicon level; mainline kernel + EDK2; some DDR/secure-boot bits still vendor-supplied. Right second-tier target for DuetOS ARM/RISC-V work. |
| OpenBMC | **Cite (not yet relevant)** | Shipping stock on HPE / MiTAC / Dell Open Server Manager / AMI MegaRAC OneTree. Useful if DuetOS ever becomes a server OS. |

## Practical "build a fully-open DuetOS box" recipe

The only credible end-to-end open-firmware combo in 2026 is:

- **CPU + boot:** Raptor Talos II / Blackbird (POWER9, Hostboot + Skiboot + OCC + self-boot engine, fully libre).
- **GPU:** ASPEED AST2500 BMC framebuffer for console (the GPU on Talos boards). For 3D, accept a closed AMD blob.
- **Wi-Fi:** AR9271 USB dongle (`qca/open-ath9k-htc-firmware`).
- **Wired:** Intel I210 / I225 / I226 (no host firmware).
- **Storage:** any NVMe (firmware onboard; treat as opaque).

No fully-open x86 mainstream box exists. ThinkPad T480 with Libreboot + deguard is the closest second-place option but still needs CPU microcode and ME stubs.

## Practical "pragmatic DuetOS box" recipe

For "open driver, all closed firmware is redistributable, fits the
DuetOS installer's blob-staging UX":

- **CPU + boot:** any Coreboot-supported Intel 12-14th gen or AMD Ryzen 7000 / Ryzen AI 300 board (FSP + microcode staged at build time).
- **GPU:** AMD Radeon RX 7000 / 9000 (RDNA3/4) — open `amdgpu`, redist firmware bundle.
- **Wi-Fi:** Intel AX210 / BE200 or MediaTek MT7922 / MT7925 — open driver, redist firmware in `linux-firmware`.
- **Wired:** Intel I225 / I226 (2.5G, no host firmware).
- **Storage:** any NVMe (ZNS NVMe if explicit data placement matters).

## Firmware-package signing recommendation

`.duetfw` packages should carry:

- **Signer-key-ID format:** SHA-256 of the DER-encoded SubjectPublicKeyInfo, truncated to 16 bytes, displayed as lowercase hex with `:` every 4 bytes (`a1b2:c3d4:...`). Matches Sigstore's Fulcio cert fingerprint convention.
- **Dual-tier trust:**
  - DuetOS project root (Ed25519, offline HSM), rarely used.
  - Intermediate signing keys, rolled yearly, sign actual `.duetfw` blobs.
  - Optional third-party root anchors for OEMs (compiled into the kernel, **not** loaded from disk).
- **Transparency:** publish every signed `.duetfw` digest to an append-only log. Start with a git-hosted log; graduate to Sigstore Rekor v2 once CI can talk to it. Verification does not *require* a transparency proof (would brick offline installs); a `firmwarectl verify --transparency-required` strict mode should exist.
- **Hash agility:** SHA-256 today, but encode the digest algorithm as a tagged field so a future flip to SHA-3 or BLAKE3 is a one-byte change.

LVFS / fwupd is the right ecosystem for **system** firmware
(UEFI, dock, NIC option ROM) but is not currently used for the
per-NIC blob distribution path; don't take a hard dependency on
it for `.duetfw`.

## Hard truths captured here so the next session doesn't re-learn them

1. **Every modern GPU requires a vendor-signed firmware blob.**
   There is no clean-room exit. Plan blob-staging as a first-
   class subsystem, not a feature.
2. **Every modern x86 CPU requires microcode + FSP (Intel) or
   AGESA+PSP (AMD).** "Fully open x86" stops at Sandy Bridge / pre-
   PSP AMD. POWER9 is the only modern fully-open mainstream CPU.
3. **Wi-Fi is structurally closed.** Either accept the redist
   blob or restrict to AR9271 / openwifi-SDR. No middle ground.
4. **Realtek has no open-firmware project anywhere.** Unusual for
   a vendor with this much footprint; don't waste cycles looking
   for one.
5. **No Intel Wi-Fi chip has open firmware.** Period. Signing
   chain is enforced; nothing has leaked or been published.
6. **`linux-firmware.git` is the de facto open-source ABI for
   firmware blobs.** Match its file paths and the firmware tree
   drops in unchanged — that single decision removes a class of
   integration work.

## Sources

- [NVIDIA/open-gpu-kernel-modules](https://github.com/NVIDIA/open-gpu-kernel-modules)
- [Nova GPU Driver — Rust for Linux](https://rust-for-linux.com/nova-gpu-driver)
- [AMD PSP firmware (Phoronix)](https://www.phoronix.com/news/AMDGPU-FW-PSP-13.0.8-GC-10.3.7)
- [Intel Panther Lake Xe3 GuC/HuC upstreamed](https://www.phoronix.com/news/Intel-PTL-Xe3-GuC-HuC-Firmware)
- [qca/open-ath9k-htc-firmware](https://github.com/qca/open-ath9k-htc-firmware)
- [seemoo-lab/nexmon (2025 activity)](https://github.com/seemoo-lab/nexmon/commits/master)
- [open-sdr/openwifi 1.5.0 (Aug 2025)](https://github.com/open-sdr/openwifi)
- [esp32-open-mac](https://esp32-open-mac.be/)
- [openwrt/mt76](https://github.com/openwrt/mt76)
- [lwfinger/rtw88](https://github.com/lwfinger/rtw88) / [rtw89](https://github.com/lwfinger/rtw89)
- [Coreboot 25.09](https://www.phoronix.com/news/Coreboot-25.09-Released)
- [Libreboot](https://libreboot.org/) / [Canoeboot](https://canoeboot.org/)
- [LinuxBoot](https://www.linuxboot.org/) / [Heads](https://github.com/linuxboot/heads) / [oreboot](https://github.com/oreboot/oreboot)
- [tianocore/edk2-platforms](https://github.com/tianocore/edk2-platforms)
- [Raptor OpenPOWER firmware wiki](https://wiki.raptorcs.com/wiki/OpenPOWER_Firmware)
- [OpenBMC 2.18](https://www.phoronix.com/news/OpenBMC-2.18-Released)
- [VisionFive 2 open-source path](https://cakehonolulu.github.io/open-source-ifying-the-visionfive-2/)
- [Sigstore Rekor v2 GA](https://blog.sigstore.dev/rekor-v2-ga/)
- [iRISC ConnectX firmware RE](https://irisc-research-syndicate.github.io/2025/02/06/initial-firmware-analysis/)
- [CustomProcessingUnit — Intel microcode RE](https://pietroborrello.com/publication/woot23/woot23.pdf)
