# Wi-Fi Onboarding and Offline Firmware Kit

> **Audience:** installer authors, release engineers, networking-driver owners
>
> **Execution context:** release build host, installer media, first boot
>
> **Maturity:** release workflow contract; real-hardware Wi-Fi verification still follows the wireless roadmap

## Goal

A user installing DuetOS on a laptop must be able to reach the Wi-Fi network
picker without already having working Wi-Fi. Commodity Intel/Realtek Wi-Fi
adapters usually need device firmware before scan or association works, so the
installer must treat firmware as an offline dependency of networking setup.

The user-facing requirement is simple:

1. Boot installer media.
2. Firmware is already present on the media, or can be loaded from a second USB.
3. The installer stages matching firmware before opening the Wi-Fi setup page.
4. The Wi-Fi page shows missing-firmware diagnostics only when all local sources
   fail.

DuetOS does **not** bypass vendor firmware signatures. Closed firmware remains
an unmodified runtime/release artifact with a license notice and exact hash.

## Release artifacts

Ship two media profiles:

| Artifact | Contents | Intended use |
|----------|----------|--------------|
| `duetos-base.iso` | OS only, no closed firmware | clean/source-only development and jurisdictions/distributions that do not want redistributable binary firmware |
| `duetos-installer-with-firmware.iso` | OS + `wifi-firmware-kit/` | normal laptop install path |

Also publish a standalone `duetos-wifi-firmware-kit-<date>.zip` so users can
put firmware on a second USB when they already have base media.

## Offline kit layout

`tools/firmware/prepare-wifi-firmware.py` creates this layout from a local
`linux-firmware`-style tree:

```text
wifi-firmware-kit/
  manifest.json
  README.txt
  licenses/
    intel-iwlwifi-LICENCE.iwlwifi_firmware
    ...
  lib/firmware/
    intel-iwlwifi/
      iwlwifi-*.ucode.duetfw
      iwlwifi-*.pnvm.duetfw
    realtek-rtl88xx/
      <rtl/rtw firmware>.duetfw
    ath9k-htc/
      htc_9271.fw.duetfw
      htc_7010.fw.duetfw
```

Every `.duetfw` file is a `DUETFWPK` package. The payload bytes are not changed;
the package adds metadata and SHA-256 verification. At runtime, `FwLoad()`
unwraps the package and gives the driver the original vendor/open firmware
payload.

## Building the kit

From a release host with a checked-out `linux-firmware` tree or distro firmware
package installed:

```sh
tools/firmware/prepare-wifi-firmware.py \
  --source /lib/firmware \
  --output build/release/wifi-firmware-kit \
  --families intel-iwlwifi,realtek-rtl88xx,ath9k-htc \
  --build-id 0x20260508 \
  --clean
```

Release builds must not use `--allow-missing-license` for redistributable binary
firmware. That flag exists only for local lab media where a developer is testing
loader behavior with synthetic files.

Run the tool's self-test before cutting release media:

```sh
python3 tools/firmware/prepare-wifi-firmware.py --self-test
```

## Installer flow

The installer should run this sequence before showing the network picker:

1. Probe PCI/USB devices and collect Wi-Fi candidates.
2. Build a firmware request list from the driver match table.
3. Search these roots in order:
   - installer media: `/wifi-firmware-kit/lib/firmware/`
   - attached USB storage: `/wifi-firmware-kit/lib/firmware/`
   - target-system staging area if a previous install attempt copied firmware
4. Read `manifest.json` and verify:
   - schema is `duetos.wifi-firmware-kit.v1`
   - `installer_policy.require_sha256_match` is true
   - every staged file's package SHA-256 and payload SHA-256 match the manifest
   - redistributable binary entries have a license path
5. Show license text for redistributable binary firmware once per install.
6. Copy matching `.duetfw` packages to the target `/lib/firmware/<vendor>/`.
7. Start the driver probe/upload path and then show the Wi-Fi network picker.

If no matching firmware is found, the installer should show an actionable error:

- adapter name / PCI ID / USB ID
- expected vendor namespace, for example `intel-iwlwifi`
- expected firmware basenames if known
- a short instruction to download `duetos-wifi-firmware-kit-<date>.zip` on
  another device and copy it to USB

## Policy boundary

The firmware-source matrix intentionally distinguishes three different things:

- **in-tree source content:** only open firmware may be committed
- **release artifact:** unmodified redistributable binary firmware may be shipped
  with license notices and exact hashes
- **runtime load:** the kernel loader may load verified packages from
  `/lib/firmware`, subject to the source policy

This keeps DuetOS source clean while giving normal laptop users a streamlined
installer path.

## Acceptance checklist

Before calling laptop Wi-Fi onboarding "ready":

- `prepare-wifi-firmware.py --self-test` passes.
- Release media includes `wifi-firmware-kit/manifest.json`.
- Intel iwlwifi license text is present when Intel firmware is present.
- The installer can stage firmware without an Internet connection.
- The network picker opens after firmware staging on at least one real Intel
  laptop and one open-firmware `ath9k_htc` USB adapter.
- Missing firmware diagnostics name the exact USB/offline-kit recovery path.
