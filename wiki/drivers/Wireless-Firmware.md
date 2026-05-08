# Wireless and GPU Firmware Research

> **Audience:** driver authors, firmware-loader maintainers, security reviewers
>
> **Execution context:** kernel probe/init and future userland firmware-package tooling
>
> **Maturity:** research-backed policy + source-classification table; real hardware upload still pending

## Executive summary

Commodity Wi-Fi and modern Intel GPUs are not "driver only" devices. The
host driver usually has to stage device-side microcode before scan,
authentication, association, TX/RX DMA, media decode, or GPU scheduling work.
For DuetOS this means firmware handling is part of the hardware ABI, not an
optional packaging afterthought.

The practical path is:

1. **Keep clean-room host drivers in tree.** Existing iwlwifi / rtl88xx / b43
   parsers already decode public firmware container formats; do not import
   Linux driver bodies.
2. **Do not commit closed blobs.** Redistributable Intel/Realtek/GPU firmware
   should be loaded from a user-provided or distro-provided firmware package.
3. **Prefer genuinely open firmware where it exists.** The usable open Wi-Fi
   set is old but valuable for bring-up: Qualcomm Atheros `ath9k_htc` USB
   devices and Broadcom b43/OpenFWWF-era devices.
4. **Treat patch frameworks as research inputs.** Nexmon-style Broadcom
   FullMAC patching is useful prior art for reversing command/mailbox paths,
   but its normal workflow starts from proprietary vendor images; it is not a
   DuetOS production firmware source.
5. **Make policy machine-readable.** The kernel now has a tiny immutable
   policy matrix in `kernel/drivers/net/firmware_policy.*` so future firmware
   loaders can make the same bundle/load/reject decision every time.
6. **Build actual firmware containers, but do not fake signed Intel payloads.**
   `kernel/drivers/net/iwlwifi_ucode_builder.*` and `tools/firmware/mkiwlucode.py`
   can generate iwlwifi-style `.ucode` TLV images from caller-supplied
   instruction/data sections. Retail Intel Wi-Fi devices still require
   Intel-signed operational firmware, so DuetOS-built iwlwifi images are for
   parser/upload tests or unsigned lab targets, not production laptops.
7. **Wrap custom/source-built firmware before loading it.** `tools/firmware/mkduetfw.py`
   creates a DuetOS firmware package with source flags and a SHA-256 payload
   digest; `kernel/loader/firmware_package.*` verifies that envelope before
   upload code sees the payload bytes.

## Source landscape

| Family | Practical DuetOS role | Firmware openness | Notes |
|--------|-----------------------|-------------------|-------|
| Intel `iwlwifi` | Tier-1 laptop Wi-Fi target | Redistributable binary, not open source | Linux Wireless documents that iwlwifi firmware is distributed separately under Intel's firmware license, and Intel's support page states Intel wireless devices require firmware. Use `linux-firmware`-style packages as runtime inputs; never vendor the blobs in tree. |
| Intel GPU GuC/HuC/DMC/GSC | Tier-1 graphics/media dependency | Redistributable binary, not open source | Linux i915 docs describe Gen9+ GuC/HuC/DMC microcontrollers and that the driver loads their firmware. Fedora packages describe Intel GPU firmware as GuC/HuC/DMC firmware for Skylake+ and flag it as redistributable/no-modification-permitted. |
| Qualcomm Atheros `ath9k_htc` | Best open-firmware Wi-Fi bring-up dongle | Source available | Linux Wireless links the open `qca/open-ath9k-htc-firmware` tree and lists AR9271 / AR7010 support. This is the best first real-hardware target when we want open firmware that can be studied, rebuilt, and instrumented. |
| Broadcom b43/OpenFWWF | Legacy open-firmware reference target | Source available, limited | Fedora/Guix/openSUSE package OpenFWWF as GPL firmware for older BCM43xx devices. Feature limits matter: openSUSE documents missing RTS/CTS, hardware crypto, QoS, and some PCMCIA support. |
| Broadcom/Cypress FullMAC + Nexmon | Reverse-engineering reference only | Open patch framework over proprietary base images | Nexmon's papers and project describe C-based firmware patching for Broadcom FullMAC chips. Useful for command-trace ideas and vulnerability research, not for bundling firmware. |
| Realtek rtlwifi/rtw88/rtw89 | Tier-2 pragmatic hardware path | Redistributable binary, not open source | Keep the existing parser/upload scaffolds, but expect runtime packages rather than open microcode. |

## Driver architecture decision

Add a firmware-loader pipeline with four layers:

1. **Source policy** — `FirmwarePolicyFind()` classifies a firmware family as
   `Preferred`, `RuntimePackage`, `ResearchOnly`, or `Reject`.
2. **Image construction** — `IwlFirmwareBuild()` emits the same outer TLV
   `.ucode` file shape used by Intel iwlwifi blobs, with clean-room payload
   sections supplied by the caller.
3. **DuetOS package envelope** — `FwPackageParse()` validates `DUETFWPK`
   packages, verifies SHA-256 over the payload, and denies custom/lab images
   unless the caller explicitly opts in.
4. **Package lookup** — the VFS firmware loader searches DuetOS/open firmware
   paths before vendor paths, and now unwraps verified DuetOS packages so
   drivers receive the payload bytes rather than the envelope.
5. **Container parse** — existing per-family parsers (`IwlFirmwareParse`,
   `RtlFirmwareParse`, `BcmFirmwareParse`) validate the vendor byte envelope and
   expose zero-copy views.
6. **Upload state machine** — per-family upload code stages DMA-visible sections,
   rings the required doorbells, waits for ALIVE/ready, and records `wifi-diag`
   events for every MMIO transition.

The policy layer deliberately lives under `kernel/drivers/net/` today because
all concrete consumers are Wi-Fi drivers. Intel GPU firmware is included in the
matrix so the same source-classification rules can be lifted into a shared
`kernel/loader/firmware_policy.*` once the GPU driver starts loading GuC/HuC/DMC
images.

## Building an iwlwifi-style `.ucode` image

The iwlwifi `.ucode` files in firmware collections are TLV containers. DuetOS
can now build that outer container from clean-room section bytes:

```bash
tools/firmware/mkiwlucode.py \
  --output duet-iwl-lab.ucode \
  --name "DuetOS custom unsigned lab ucode" \
  --version 0x00010002 \
  --build 0x20260508 \
  --flags 0xA5A50001 \
  --num-of-cpu 2 \
  --fw-version 0x00010002 \
  --section inst=inst.bin \
  --section data=data.bin \
  --section sec-rt=runtime.bin
```

This produces an actual iwlwifi TLV image that `IwlFirmwareParse()` can parse
and the upload path can stage. It intentionally does **not** claim retail Intel
hardware will execute it: those devices enforce Intel's firmware signing chain.
Use this for clean-room section experiments, synthetic upload tests, and any
future lab device or FPGA shim that accepts unsigned payloads.

## Building a source-aware firmware package

For an open AR9271 firmware build output, wrap the raw target image before
placing it under `/lib/firmware/duetos/open/ath9k-htc/`:

```bash
tools/firmware/mkduetfw.py \
  --input htc_9271.fw \
  --output htc_9271.duetfw \
  --family ath9k-htc \
  --source-kind open-source \
  --short-name ath9k-htc-open \
  --upstream qca/open-ath9k-htc-firmware \
  --source-rebuildable \
  --may-bundle \
  --regulatory-locked
```

If you intentionally modify firmware for a lab experiment, add
`--custom-lab-image --allow-lab-image`. The package will carry
`CustomLabImage` + `RequiresExplicitOptIn`, and normal `FwLoad()` callers will
refuse it unless they set `allow_custom_lab_image` in the request. Do not use
that path for normal boot or distribution images.

## Recommended first hardware loop

Use an **AR9271/AR7010 USB adapter** as the open-firmware bring-up device:

- USB enumeration and xHCI already exist in DuetOS.
- The open firmware source can be rebuilt and instrumented.
- The Linux `ath9k_htc` host/firmware split is simpler than modern Intel CNVi.
- The target avoids PCIe MSI/MSI-X and iwlwifi TFD/RBD complexity during the
  first Wi-Fi frame-to-air test.

After that loop proves firmware package lookup + upload + scan diagnostics,
move back to Intel iwlwifi for the tier-1 laptop path.

## Clean-room and security rules

- Numeric register offsets, firmware TLV identifiers, and byte layouts are
  hardware ABI facts; copying whole driver logic or comments is not.
- Keep reverse-engineering notes in the wiki or clean-room trace logs, not mixed
  with copied Linux implementation text.
- Load closed firmware only from an explicit runtime package, with a recorded
  license/disposition and a hash in the future package manifest.
- Do not use or ship modified regulatory-domain firmware. Regulatory behavior
  must stay within vendor firmware or source-available firmware that we can audit
  and configure legally.
- Any future "research firmware" switch must be lab-only and off by default.

## References

- Linux Wireless iwlwifi documentation: <https://wireless.docs.kernel.org/en/latest/en/users/drivers/iwlwifi.html>
- Intel wireless Linux support matrix: <https://www.intel.com/content/www/us/en/support/articles/000005511/wireless.html>
- Intel iwlwifi firmware license in `linux-firmware`: <https://kernel.googlesource.com/pub/scm/linux/kernel/git/firmware/linux-firmware/+/refs/heads/main/LICENCE.iwlwifi_firmware>
- Linux i915 GPU firmware documentation: <https://docs.kernel.org/gpu/i915.html>
- Fedora `intel-gpu-firmware` package metadata: <https://packages.fedoraproject.org/pkgs/linux-firmware/intel-gpu-firmware/>
- Linux Wireless `ath9k_htc` documentation: <https://wireless.docs.kernel.org/en/latest/en/users/drivers/ath9k_htc.html>
- Qualcomm Atheros open firmware tree: <https://github.com/qca/open-ath9k-htc-firmware>
- Fedora `b43-openfwwf` package metadata: <https://packages.fedoraproject.org/pkgs/b43-openfwwf/b43-openfwwf>
- openSUSE `b43-openfwwf` feature/limit notes: <https://build.opensuse.org/package/show/hardware/b43-openfwwf>
- Nexmon firmware patching framework paper: <https://www.sciencedirect.com/science/article/pii/S014036641731294X>

## Next implementation steps

1. Add an `ath9k_htc` USB probe skeleton and HTC firmware-download path for
   AR9271/AR7010, using `.duetfw` packages for source-built firmware.
2. Extend the package manifest/header with an optional signer key ID once the
   project has a firmware signing root.
3. Teach `IwlUploadDrive()` to consume all `SEC_RT` sections, not just the first
   parsed section, then wire PCIe doorbells and per-RBD receive buffers.
4. Add a shell command that prints retained `FwTraceEntry` records and package
   source flags for field debugging.
