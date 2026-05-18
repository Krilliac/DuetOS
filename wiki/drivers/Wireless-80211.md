# 802.11 Wireless Stack

> **Audience:** Driver authors, Wi-Fi onboarding contributors
>
> **Execution context:** Kernel — MLME runs in process context; RX path
> fires from the underlying NIC's IRQ tail
>
> **Maturity:** v0 — Open / WPA2-PSK / WPA3-SAE scan + associate + 4-way
> handshake functional against the loopback test harness; post-association
> **data plane** (GCMP-128-encrypted 802.11 ↔ 802.3, bridged into the IP
> stack) functional against the fake-AP + software-gateway harness — a
> client acquires a DHCP lease and pings the gateway over the encrypted
> link; live silicon RX path driver-specific

## Overview

The 802.11 stack on DuetOS sits **between** the per-NIC driver
(iwlwifi, ath9k_htc, rtl88xx, bcm43xx, mt76) and the network stack.
Each driver knows how to push frames to its hardware; the 802.11 stack
above it knows the protocol — scanning, authentication, association,
group-key handshakes, deauthentication.

```
   network stack (IPv4/IPv6, ARP, DHCP)
                |
           wireless device (wdev)
                |
        MLME / EAPOL / 4-way / beacon parser
                |
           per-driver TX/RX shims
                |
           hardware (iwlwifi / ath9k / rtl88xx / ...)
```

The split lets new vendor drivers join without touching the protocol
state machine. Conversely, the protocol layer can evolve (add WPA3-OWE,
add 6 GHz scanning) without per-driver edits.

Sources live at [`kernel/net/wireless/`](../../kernel/net/wireless/);
each driver lives at `kernel/drivers/net/<chip>/`. The two are
connected through the `WirelessDeviceOps` vtable.

## File Layout

| File | Purpose |
|------|---------|
| [`ieee80211.h`](../../kernel/net/wireless/ieee80211.h) | Spec constants — frame types, subtypes, IE IDs, reason codes |
| [`beacon.h`](../../kernel/net/wireless/beacon.h) / `.cpp` | Beacon + probe-response parser. SSID / DS channel / HT operation / rates / RSN / WPA-1 IE / capability bits |
| [`wdev.h`](../../kernel/net/wireless/wdev.h) / `.cpp` | The `WirelessDevice` abstraction, `WirelessDeviceOps` vtable, per-device state machine |
| [`mlme.h`](../../kernel/net/wireless/mlme.h) / `.cpp` | MLME — `MlmeConnect`, `MlmeDisconnect`, `MlmeScan` |
| [`fourway.h`](../../kernel/net/wireless/fourway.h) / `.cpp` | WPA / WPA2 4-way handshake (EAPOL-Key M1-M4) |
| [`eapol.h`](../../kernel/net/wireless/eapol.h) / `.cpp` | EAPoL frame builder + parser |
| [`gcmp.h`](../../kernel/net/wireless/gcmp.h) / `.cpp` | GCMP-128 MPDU protect/unprotect (AES-GCM AEAD) for the data plane |
| [`wnetif.h`](../../kernel/net/wireless/wnetif.h) / `.cpp` | 802.3 ↔ 802.11+GCMP conversion + IP-stack netif binding |
| [`mock_isp.h`](../../kernel/net/wireless/mock_isp.h) / `.cpp` | Live "mock ISP" `WifiBackendOps` — makes the SSID scannable + joinable on a normal boot, with a pump thread |
| [`inventory.h`](../../kernel/net/wireless/inventory.h) / `.cpp` | Hardware inventory — walks PCI + USB NICs to emit a boot-log block |
| [`wifi_diag.h`](../../kernel/net/wireless/wifi_diag.h) / `.cpp` | Wi-Fi diagnostic ring (state transitions, RX/TX, errors) |
| [`wifi80211_rust/`](../../kernel/net/wifi80211_rust/) | Rust crate for fixed-shape decoders (see [Rust Subsystems](../tooling/Rust-Subsystems.md)) |
| [`parsers_rust/`](../../kernel/net/parsers_rust/) | Rust crate for shared TLV / IE parsing used by both beacon and EAPOL paths |
| `test/` | Loopback + fake-AP + fake-gateway harness (control tier + GCMP data plane) — see [Testing](../advanced/Testing.md) |

## The `WirelessDevice` Abstraction

Every NIC the wireless stack manages presents itself as a
`WirelessDevice`. The driver implements the `WirelessDeviceOps`
vtable:

```cpp
struct WirelessDeviceOps {
    Result<void> (*Scan)(WirelessDevice&, ScanRequest);
    Result<void> (*Auth)(WirelessDevice&, AuthRequest);
    Result<void> (*Assoc)(WirelessDevice&, AssocRequest);
    Result<void> (*SendMgmt)(WirelessDevice&, span<const u8> frame);
    Result<void> (*InstallKey)(WirelessDevice&, KeyDescriptor);
    Result<void> (*Disconnect)(WirelessDevice&);
    // RX callbacks — the driver calls these from its IRQ tail
    void          (*OnBeaconRx)(WirelessDevice&, span<const u8>);
    void          (*OnEapolRx)(WirelessDevice&, span<const u8>);
};
```

Per-device state:

- Up to 38 channels (11 on 2.4 GHz + 25 on 5 GHz; 6 GHz pending the
  regulatory database)
- Up to 32 scan results
- Up to 8 cipher suites + 8 AKM suites per BSS
- State machine: `Down → Idle → Scanning → Authenticating →
  Associating → Handshaking → Connected | Failed | Disconnecting`

Every state transition logs to the Wi-Fi diagnostic ring with the
reason code (802.11-2020 Table 9-49).

## Beacon Parser

[`beacon.cpp`](../../kernel/net/wireless/beacon.cpp) decodes the
information elements out of a beacon or probe-response frame. The
output is a struct of spans **back into the frame bytes** — no
allocations.

Recognised IEs:

- SSID (IE 0)
- Supported Rates (IE 1) + Extended Supported Rates (IE 50)
- DS Parameter Set (IE 3) — channel
- TIM (IE 5) — DTIM count / period
- HT Capabilities + HT Operation (IE 45 / 61) — 11n features
- VHT Capabilities + VHT Operation (IE 191 / 192) — 11ac features
- RSN (IE 48) — WPA2 / WPA3 cipher + AKM suites
- WPA-1 vendor (IE 221 with Microsoft OUI) — legacy WPA

The `WirelessSecurity` enum classifies the BSS:

| Value | Meaning |
|-------|---------|
| `Open` | No RSN, no WPA-1 |
| `WEP` | Legacy WEP (Privacy bit only) |
| `WPA` | WPA-1 vendor IE present |
| `WPA2` | RSN with PSK AKM |
| `WPA3` | RSN with SAE AKM |
| `Wpa2Ent` | RSN with 802.1X AKM |
| `Wpa3Ent` | RSN with SAE-EAP AKM |

The classifier is what the [WiFi Onboarding](WiFi-Onboarding.md) UI
shows next to each SSID.

## MLME Flow

`MlmeConnect(wdev, ssid, passphrase, desired_bssid?, channel?)` walks
the full sequence:

1. **Pick BSS** — scan results filtered by SSID (and optionally
   BSSID + channel). Highest RSSI wins.
2. **Derive PMK** — for WPA2-PSK: PBKDF2-HMAC-SHA1(passphrase, ssid,
   4096, 32) via [`crypto/pbkdf2`](../kernel/Crypto.md). For WPA3-SAE:
   the SAE exchange runs first to produce a PMK.
3. **Auth** — Open System auth (Open / WPA2) or SAE auth (WPA3). The
   driver's `Auth` op pushes the management frame.
4. **Assoc** — driver's `Assoc` op. The AP returns AssocResp with the
   negotiated capabilities.
5. **4-way handshake** — `fourway.cpp` runs M1 → M4. The driver
   delivers received EAPOL frames via the `OnEapolRx` callback; the
   handshake module replies through `SendMgmt`.
6. **InstallKey** — the negotiated PTK + GTK go to the hardware via
   `InstallKey`. On most chips this means programming a key index in
   the MAC.
7. **Transition to `Connected`** — the network stack can now use the
   wdev as a normal interface.

Failure at any step transitions to `Failed` with a 802.11 reason code
in the diagnostic ring. A timeout in step 5 is the most common failure
on real APs — usually a passphrase mismatch.

`MlmeDisconnect(wdev, reason)` sends Deauth + Disassoc and the driver
tears its hardware keys down.

## 4-Way Handshake Detail

[`fourway.cpp`](../../kernel/net/wireless/fourway.cpp) implements the
802.11i 4-way handshake on top of the
[`crypto/`](../kernel/Crypto.md) primitives:

| Message | Direction | Carries |
|---------|-----------|---------|
| M1 | AP → STA | ANonce |
| M2 | STA → AP | SNonce, RSN IE, MIC |
| M3 | AP → STA | ANonce, RSN IE, GTK (wrapped with AES-Key-Wrap), MIC |
| M4 | STA → AP | MIC (handshake-complete ack) |

Key derivation:

- PTK = PRF-384(PMK, "Pairwise key expansion", min(SPA,APA) ‖ max(SPA,APA) ‖ min(SNonce,ANonce) ‖ max(SNonce,ANonce))
- KCK = PTK[0..15] (MIC key)
- KEK = PTK[16..31] (key encryption key — for unwrapping GTK in M3)
- TK = PTK[32..47] (data confidentiality key)
- GTK is unwrapped from M3 using AES-Key-Wrap with KEK as the wrapping key

The MIC algorithm is HMAC-SHA1 for WPA2 (legacy PSK), HMAC-SHA256 for
WPA3 / modern AKM suites. The fourway module picks based on the AKM
negotiated in step 4 of MLME.

## EAPOL Frame Layer

[`eapol.cpp`](../../kernel/net/wireless/eapol.cpp) is the byte-level
frame builder / parser. The fourway module composes its messages here;
the parser side feeds the fourway state machine from driver RX.

`EapolBuildKeyFrame(...)` returns a span into a caller-provided buffer;
`EapolParseKeyFrame(span)` returns a view struct with no copies.

## Hardware Inventory

`WirelessInventoryRefresh()` walks both PCI and USB device tables and
emits a boot-log block:

```
[wifi-inventory]
  pci  00:14.0 8086:9d2f iwlwifi    driver_online=yes fw_state=loaded basename=iwlwifi-7265D-29
  usb  bus0-2  0bda:8812 rtl88xx    driver_online=yes fw_state=requested basename=rtlwifi/rtl8812aufw_NIC.bin
```

The `fw_state` column reflects the firmware loader's view:
`absent`, `requested`, `denied`, `loaded`. The `openness` column on
the per-driver inventory tracks `OpenSource` / `Redistributable` /
`None`; see [Wireless Firmware](Wireless-Firmware.md) for the trust
model.

## Threading and Locking

- **MLME ops** run in process context on a worker thread. Drivers
  must be safe to call from process context.
- **`OnBeaconRx` / `OnEapolRx`** fire from the driver's IRQ tail.
  The handlers copy the relevant fields and queue work for the MLME
  worker; they do not run the state machine themselves.
- **Per-wdev spinlock** guards the state-machine transition. All op
  callbacks acquire it with IRQs masked.

## Capability Gates

Wireless management is gated on `kCapNetAdmin`. The default user
cannot scan or connect; elevation is required (see
[Capabilities](../security/Capabilities.md) and
[Auth and Login](../security/Auth-and-Login.md)).

## Known Limits / GAPs

- **No regulatory database.** Channels are baked in for the US table;
  international regions not modelled.
- **No 6 GHz / Wi-Fi 6E / Wi-Fi 7.** 5 GHz top.
- **No monitor mode, no AP mode, no IBSS.** STA only.
- **WPA3-SAE simplified.** v0 implements SAE-H2E for the most-common
  curve; full RFC 7664 not exercised across all curves.
- **No FT (fast transition / 802.11r).** Roaming requires a fresh
  full handshake.
- **PMF not enforced.** The code recognises the bit but does not
  reject unprotected mgmt frames.
- **Live driver RX path varies.** ath9k_htc / iwlwifi / rtl88xx
  driver-side RX completeness is per-driver; the test harness covers
  the control tier *and* the post-association data plane end-to-end
  on a software loopback (fake AP + fake gateway).
- **Data plane is GCMP-128 only, 3-address frames.** The loopback
  negotiates GCMP-128 (not CCMP) because the kernel already ships a
  tested AES-GCM primitive; QoS-Data / A4 / WDS header shapes and an
  upstream NAT beyond the fake gateway are not modelled (the gateway
  is the whole reachable network, like SLIRP `restrict=on`).
- **Live mock-ISP backend is one WPA2-PSK network.** `mock_isp`
  registers `WifiBackendOps` at boot so `wifi scan` lists
  `DuetOS-ISP` and `wifi connect DuetOS-ISP <psk>` runs the real
  4-way handshake + DHCP (wrong PSK is rejected). Open / multi-SSID
  live association is a follow-up — the data plane is GCMP-keyed, so
  an unencrypted open data path is separate work.

## Related Pages

- [Networking Drivers](Networking-Drivers.md) — per-NIC drivers
- [Wireless Firmware](Wireless-Firmware.md) — firmware loader trust
  model
- [WiFi Onboarding](WiFi-Onboarding.md) — operator UX for picking
  an SSID and entering a passphrase
- [Crypto](../kernel/Crypto.md) — PBKDF2, HMAC, AES-Key-Wrap
- [Network Stack](../networking/Network-Stack.md) — what runs on top
- [Rust Subsystems](../tooling/Rust-Subsystems.md) — `wifi80211_rust`,
  `parsers_rust`
- [Capabilities](../security/Capabilities.md) — `kCapNetAdmin`
