# Wireless Regulatory Database

> **Audience:** Wi-Fi driver authors, MLME / scan code maintainers
>
> **Execution context:** Kernel — intended to be read by MLME scan,
> channel selection, and TX gating (not yet wired in; see Known Limits)
>
> **Maturity:** v0 — three built-in domains (US / EU / JP), 802.11d
> Country IE intersector, boot self-test

## Overview

`kernel/net/wireless/regdb.{h,cpp}` is the in-kernel regulatory
database. Every site that asks "is this frequency allowed?" or
"what's the EIRP cap here?" routes through this layer so the
answer is consistent and the radio-law policy doesn't get
re-derived in three places.

The tables are `constexpr` C++ arrays compiled into the kernel
image. No runtime `regulatory.db` lookup, no PKCS#7 wrapper —
that complexity buys nothing until DuetOS ships signed,
updateable firmware bundles, which is a separate slice.

```
   MLME / scan code
         |
   regdb::FreeqAllowed / MaxEirpMbm
         |
   constexpr rule tables: kDomainUS / kDomainEU / kDomainJP
```

## Built-in Domains

| Code | Source | Notes |
|------|--------|-------|
| `US` | FCC Part 15.247 + Part 15.407 | 30 dBm on 2.4 GHz; UNII-1 / UNII-2 / UNII-2-extended / UNII-3 all populated; DFS required on UNII-2 + extended. |
| `EU` | ETSI EN 300 328 + EN 301 893 | 20 dBm on 2.4 GHz; UNII-1 indoor-only (NO_IR + Indoor flag); DFS on UNII-2 + extended; no UNII-3. |
| `JP` | Radio Law / ARIB STD-T66 | 2.4 GHz extends to 2484 MHz (channel 14, **OFDM prohibited** — 802.11b only); UNII-1 + UNII-2; UNII-2-extended capped at 23 dBm. |

Each rule carries `start_freq_khz`, `end_freq_khz`, `max_bw_khz`,
`max_eirp_mbm` (0.01 dBm), and a flag bitmask:

| Flag | Meaning |
|------|---------|
| `kRuleFlagNoIr` | No initiating radiation (passive scan only). |
| `kRuleFlagDfs` | Dynamic Frequency Selection — radar avoidance mandatory. |
| `kRuleFlagNoOfdm` | OFDM disallowed (e.g. JP ch14). |
| `kRuleFlagAutoBw` | Bandwidth may auto-extend across adjacent rules. |
| `kRuleFlagIndoorOnly` | Hard indoor restriction (separate from NO_IR). |

To add a new region, append a `constexpr Domain k<region>` literal
in `regdb.cpp` and add it to `kDomains[]`. Re-run the boot self-
test on each addition.

## Country IE Intersection (802.11d)

A beacon may carry a Country Information Element (802.11-2020
§9.4.2.10) advertising the access point's regulatory triplets.
`regdb::ParseCountryIe` decodes the payload into a
`CountryIeView`; `regdb::IntersectWithCountryIe(base, ie, out)`
produces an effective domain that:

1. **Never relaxes** what the base domain allowed — a hostile
   beacon cannot grant frequencies the operator's region
   forbids.
2. **Lowers EIRP caps** to `min(base, ie)` on overlapping
   bands.
3. **Preserves base-only bands** — if the IE is silent on a band
   the base regulates (e.g. the AP only describes 2.4 GHz but the
   base also covers 5 GHz), the base rule passes through. To
   force pure intersection, set the active domain to a narrower
   one before connecting.

The operating-class triplet form (first byte ≥ 201) is parsed
but ignored on the intersect path — sub-band triplets carry
enough signal for the v0 workload, and silently skipping
operating-class triplets only ever narrows the safety surface.

## Public Surface

```cpp
namespace duetos::net::wireless::regdb {

u32 DomainCount();
const Domain* DomainAt(u32 i);
const Domain* DomainByCode(const char alpha2[2]);
const Domain* ActiveDomain();             // defaults to "US"
bool SetActiveDomain(const char alpha2[2]);

const Rule* RuleForFreq(const Domain&, u32 freq_khz);
bool        FreqAllowed(const Domain&, u32 freq_khz);
i32         MaxEirpMbm(const Domain&, u32 freq_khz); // or kEirpNotAllowed

u32  ChannelToFreq2GHz(u8 channel);  // 1..14
u32  ChannelToFreq5GHz(u8 channel);  // 36..165
bool FreqToChannel(u32 freq_khz, u8* out_band, u8* out_channel);

bool ParseCountryIe(const u8* ie_payload, u32 len, CountryIeView* out);
void IntersectWithCountryIe(const Domain& base, const CountryIeView& ie, Domain* out);

void SelfTest(); // boot self-test — emits "[regdb-selftest] PASS"

} // namespace
```

## Boot Self-Test

`regdb::SelfTest()` runs during the wireless boot block (after
`GcmpSelfTest`, before `WdevSelfTest`) and asserts:

- All three built-in domains parse and `DomainByCode` is case-
  insensitive.
- 2.4 GHz channels 1–14 and a 5 GHz sample set round-trip
  `ChannelToFreq*` ↔ `FreqToChannel`.
- JP channel 14 (2484 MHz) carries `kRuleFlagNoOfdm`.
- US 5280 MHz (UNII-2) carries `kRuleFlagDfs`.
- EU UNII-1 carries `kRuleFlagNoIr`.
- A synthetic Country IE that limits US to channels 1–11 at 18 dBm
  intersects correctly: 2.4 GHz EIRP cap drops to 1800 mBm and
  the 5 GHz base bands pass through.

A clean run emits one line:

```
[regdb-selftest] PASS (domains=0x00000003 us_rules=0x00000005 eu_rules=0x00000004 jp_rules=0x00000005)
```

A regression fires `kBootSelftestFail` via the probe table.

## Known Limits / GAPs

- **Built but not yet consumed by the MLME.** The tables, the 802.11d
  intersector, and the boot self-test all exist and pass, but no caller
  in the wireless stack invokes `regdb::FreqAllowed` / `MaxEirpMbm` /
  `ActiveDomain` yet — a `git grep` for those symbols across
  `mlme.cpp` / `wdev.cpp` / `beacon.cpp` returns zero hits. Until the
  scan / channel-selection / TX-gating path is wired through this layer,
  the database is dormant infrastructure and the effective channel set
  is still the baked-in 802.11 table (see
  [802.11 Wireless Stack](Wireless-80211.md#known-limits--gaps)). Wiring
  it in is the next slice.
- **Only 3 regions.** Add `kDomainXX` literals as DuetOS gains
  users in those regions. The `kRulesMaxPerDomain = 8` cap allows
  three more rules per region; bump if a domain needs > 8 rules.
- **No 6 GHz / Wi-Fi 6E / Wi-Fi 7.** Tables stop at 5.835 GHz.
  Adding 6 GHz (5925–7125 MHz, sub-bands U-NII-5..8) is a future
  slice and pairs with the 802.11ax MLME work.
- **No regulatory updates via beacon.** A roaming station that
  enters a different regulatory domain (Country IE alpha-2 differs
  from `ActiveDomain`) currently just intersects against the
  active domain. Auto-switching the active region on a strong
  Country-IE signal is policy decision deferred until we have a
  geolocation source (GPS, IP-geo, operator UI).
- **No PKCS#7 signed regulatory.db loader.** The Linux model
  (`/lib/firmware/regulatory.db` + Wireless Regulatory DB Agent
  signing) makes sense once DuetOS ships firmware delivery; until
  then, in-tree tables avoid that complexity.

## Related Pages

- [802.11 Wireless Stack](Wireless-80211.md) — MLME consumer
- [Networking Drivers](Networking-Drivers.md) — per-NIC TX gating
- [Wireless Firmware](Wireless-Firmware.md) — runtime firmware
  bundle policy (different concern: which microcode runs on the
  radio, not which frequencies it may use)
