# IEEE 802.11 frame headers + beacon parser v0

**Last updated:** 2026-05-01
**Type:** Observation + Decision
**Status:** Active — beacon/probe-response parsing only; frame TX, RX dispatch, and management-frame protocol still deferred

## Description

First piece of on-air 802.11 frame logic on DuetOS. Phase 3 of the
"full wireless networking" roadmap captured in
`feature-gaps-end-user-v0.md`. The kernel can now take a raw
beacon or probe-response frame (which is what an associated
firmware will deliver as the user-facing scan result) and produce
a structured `BeaconParsed` view with SSID, channel, security
classification (Open / WEP / WPA / WPA2 / WPA3 / -Ent variants),
supported rates, and capability flags.

This is the "data side" of the wireless stack — the part that
knows what bytes mean. The "control side" (driver TX paths,
RX dispatch, firmware notifications, MLME state machine,
EAPOL/4-way handshake) is still deferred and will need real
hardware to verify.

## Files

- `kernel/net/wireless/ieee80211.h` — frame header constants:
  Frame Control bits (8 flags + Type/Subtype encoding), Type
  enum (Mgmt / Ctrl / Data / Reserved), MgmtSubtype enum (14
  variants), Capability Info bits (16), Information Element IDs
  (35 recognised + 4 ID Extensions), 802.11 cipher suite types
  (12 from WEP-40 through BIP-CMAC-256), AKM suite types (12
  from 802.1X through OWE), and helper inlines `FcType()` /
  `FcSubtype()`.
- `kernel/net/wireless/beacon.{h,cpp}` — `BeaconParse` walker
  + `BeaconParsed` output struct + boot self-test + 1-line log
  helper.

## Scope

### Covered

- **Frame validation:** rejects non-Management frames with
  `Corrupt`, rejects subtypes that aren't Beacon or
  ProbeResponse with `Corrupt`, rejects buffers smaller than
  MAC header + fixed body with `InvalidArgument`.
- **MAC header capture:** BSSID and source address read from
  Address 2 / Address 3 (correct for beacons since
  `ToDS=0, FromDS=0`).
- **Fixed body prefix:** 64-bit timestamp, 16-bit beacon
  interval (TUs), 16-bit capability info.
- **IE walk** with bounds-checked length: a truncated IE stops
  the walk but keeps everything walked so far.
- **Recognised IEs:**
  - SSID (id=0): up to 32 bytes, sanitized to printable ASCII;
    length 0 → `hidden_ssid=true`.
  - Supported Rates (id=1) + Extended Supported Rates (id=50):
    captured into a 16-element table with the basic-rate bit
    preserved; `max_basic_rate_500kbps` tracks the top
    Basic-marked rate.
  - DS Parameter Set (id=3): 2.4 GHz channel.
  - HT Operation (id=61): 5 GHz primary channel — used as
    fallback when DS isn't present.
  - RSN (id=48): version, group cipher (packed as 4-byte u32),
    pairwise cipher list (up to 4), AKM suite list (up to 4),
    capabilities. Each cipher / AKM is stored as
    `(oui[0]<<24)|(oui[1]<<16)|(oui[2]<<8)|type` so equality
    comparisons are constant-folded against the
    `kCipher*` / `kAkm*` constants.
  - Vendor Specific (id=221): WPA-1 IE (OUI 00:50:F2 type 1)
    detected; everything else increments `unknown_ies`.
- **Security taxonomy** (`DeriveSecurity`):
  - No RSN, no WPA1 IE → `Open` if Privacy bit clear, `Wep` if set.
  - WPA1 IE only → `Wpa`.
  - RSN with any AKM in `{SAE, FT-SAE, OWE}` → `Wpa3`
    (or `Wpa3Ent` if 802.1X also present).
  - RSN with any AKM in `{802.1X, 802.1X-SHA256, FT-802.1X,
    FT-802.1X-SHA384, FILS}` → `Wpa2Ent`.
  - RSN with PSK / PSK-SHA256 / FT-PSK → `Wpa2`.
  - Any other RSN → `Wpa2` (default for unknown AKM).
- **Boot self-test:** synthesises 4 frames in static buffers:
  - Positive: 5-IE WPA2-PSK beacon at channel 6 with rates
    1/2/5.5/11 Mbps. Verifies SSID, channel, capabilities,
    rates, RSN parse, derived `Wpa2` security.
  - Negative: data frame → `Corrupt`.
  - Negative: short frame (16 bytes) → `InvalidArgument`.
  - Hidden SSID (length-0 IE) + Privacy=0 → `hidden_ssid=true`,
    derived `Open`.
  - WPA3-SAE beacon (RSN with AKM=8) → derived `Wpa3`.

### Deliberately not in scope

- Frame TX. The driver-side path that takes a `BeaconParsed`
  and crafts a probe-request / auth / assoc frame in response
  is the next slice — gated on per-vendor TX ring setup which
  itself is gated on microcode upload.
- RX frame dispatch. Today no driver delivers RX frames to
  this parser — they all stop at chip-ID-only probing. When the
  upload + ring slices land, a driver-internal RX bottom-half
  will hand beacons to `BeaconParse`.
- MLME state machine. This parser produces input for state
  transitions; it doesn't run them. Auth, Assoc Req/Resp
  handling, deauth processing, all separate slices.
- HT / VHT / HE capability parse. The IE bytes are recorded
  via `ie_count`, but the channel-width / spatial-stream /
  guard-interval fields aren't extracted yet.
- TIM (Traffic Indication Map) parse — needed for power
  management.
- Country IE — needed for regulatory compliance.
- Vendor-specific WPS / Wi-Fi Direct / WMM / Apple / MS IEs
  beyond WPA-1 detection.
- IE-level CRC / FCS validation (FCS is the driver's job; we
  assume it was stripped before delivery).
- Multi-link operation (MLO) for Wi-Fi 7.

## Integration points

- `kernel/core/main.cpp` runs `BeaconSelfTest()` at boot
  immediately after the three vendor-firmware self-tests
  (iwlwifi / rtl / bcm). Single new include of
  `net/wireless/beacon.h`. The self-test is gated by
  `DUETOS_BOOT_SELFTESTS=1`, so release builds skip it.
- `kernel/CMakeLists.txt` — no change. The kernel uses
  `GLOB_RECURSE` over `kernel/**/*.cpp`, so the new
  `kernel/net/wireless/beacon.cpp` TU is picked up
  automatically.
- `kernel/net/wifi.{h,cpp}` (the cfg80211-equivalent skeleton)
  is unchanged for now. The future scan-results delivery
  surface will populate `WifiScanResult` from `BeaconParsed`,
  but that lives in the MLME slice, not here.

## Observable

Boot log:

```
[80211] beacon selftest pass
```

When a real driver eventually feeds frames to the parser, it
will log per-frame:

```
[80211] beacon ssid="MyHomeNetwork" channel=0x6 sec=wpa2 cap=0x431
        beacon_int=0x64 rates=0x4 ies=0x9 unknown=0x2
```

## Edge cases / what to remember

- **Hidden SSID is a real beacon, not an error.** APs configured
  to hide their SSID send a 0-length SSID IE. The parser flags
  `hidden_ssid=true` but still returns Ok — a UI can choose to
  display "<hidden>" or filter the result.
- **Channel from DS vs HT Operation.** 2.4 GHz APs publish their
  channel in DS Parameter Set (id=3); 5 GHz APs publish it in
  the first byte of HT Operation (id=61). The parser uses DS
  if present, falls back to HT. If neither is present
  (extremely rare), `channel = 0`.
- **The `kFcOrder` bit means +HTC, not "ordered service class".**
  Older 802.11 specs called bit 15 of Frame Control "Order"; in
  802.11n+ it's repurposed as "+HT Control present", which adds
  a 4-byte HT Control field after Sequence Control. v0 doesn't
  parse HTC — beacons don't carry it.
- **Address 4 is only present when both ToDS and FromDS are 1.**
  Beacons have ToDS=0 / FromDS=0, so the parser ignores Address
  4 entirely.
- **RSN parse is best-effort length-bounded.** If the RSN IE is
  truncated mid-suite list, the parser stops at the last
  complete suite and returns what it has — the AP is
  technically malformed but real-world APs occasionally emit
  truncated RSN IEs after firmware upgrades, and refusing the
  whole beacon is worse UX than silent partial.
- **`unknown_ies` is informational.** Beacons routinely carry
  20+ IEs we don't parse (Country, ERP, Extended Cap, HT/VHT/HE,
  TPC, BSS Load, AP Channel Report, Vendor MS/Apple/WMM, etc.).
  The counter exists so a future audit can confirm we're not
  silently dropping anything semantically important.

## Source attribution

The 802.11 frame format and IE numbering are stable IEEE-802.11
standard. The cipher / AKM OUI assignments come from the
Wi-Fi Alliance RSN Selector registry. Linux references for the
constants:

- `include/linux/ieee80211.h` — frame headers, FC bits, IE IDs.
- `include/uapi/linux/wireless.h` — capability flags.
- `net/wireless/util.c` — security taxonomy logic shape.

DuetOS implementation is clean-room; only the IEEE-defined byte
layouts and identifier numbers are carried over.

## See also

- `feature-gaps-end-user-v0.md` — P0 #4 Wi-Fi entry; this slice
  closes Phase 3 of the multi-phase plan.
- `wireless-fw-parsers-v0.md` — Phase 1b: per-vendor envelope
  parsers (iwlwifi / rtl88xx / bcm43xx). Together with this
  beacon parser, the data-decode tier is now complete; the
  control-side tier (upload + MLME) is deferred to a real-HW
  session.
- `kernel/net/wifi.{h,cpp}` — cfg80211-equivalent skeleton.
  Future MLME slice populates its `WifiScanResult` from
  `BeaconParsed`.
