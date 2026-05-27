#pragma once

#include "util/types.h"

/*
 * DuetOS — Wireless regulatory database.
 *
 * Three built-in domains (US / EU / JP) plus the 802.11d Country
 * Information Element intersector. The point of this layer is to
 * keep MLME / channel scan code free of policy: every TX or scan
 * site asks "what is the EIRP limit at this freq?" or "is this
 * channel allowed?" and the regulatory tables answer.
 *
 * Frequencies are kHz throughout (matches the on-the-wire 802.11d
 * Country IE granularity and avoids fractional-MHz channels). EIRP
 * is mBm (1/100 dBm). Bandwidths are kHz.
 *
 * Design constraints:
 *
 *   - Rule tables are `constexpr` arrays compiled into the kernel
 *     image. No firmware-supplied `regulatory.db`, no PKCS#7 wrapper
 *     — those make sense once the project ships updateable firmware
 *     packages; in-tree tables cover the bring-up workload.
 *
 *   - Rule lookup is O(rules) — ≤ 5 rules per domain, ≤ 16 total.
 *     A frequency-sorted binary search adds complexity without
 *     measurable win at this scale.
 *
 *   - The 802.11d intersector takes the *active* domain and a
 *     beacon-supplied Country IE and produces a new effective
 *     domain. Intersection (not replacement) is the safety
 *     property: a beacon can only further restrict, never relax.
 *
 * Reference: 802.11-2020 §9.4.2.10 (Country element), Linux
 * `net/wireless/reg.c` (the kernel-side regulatory framework — we
 * mirror the rule structure but ship the tables in-tree).
 */

namespace duetos::net::wireless::regdb
{

// Flags on a single regulatory rule. Mirror of the
// `NL80211_RRF_*` set used by `wireless-regdb`.
inline constexpr u32 kRuleFlagNone = 0;
inline constexpr u32 kRuleFlagNoIr = 1u << 0;       ///< No initiating radiation — indoor-only, passive scan.
inline constexpr u32 kRuleFlagDfs = 1u << 1;        ///< Dynamic Frequency Selection (radar avoidance) required.
inline constexpr u32 kRuleFlagNoOfdm = 1u << 2;     ///< OFDM disallowed (JP ch14: 802.11b only).
inline constexpr u32 kRuleFlagAutoBw = 1u << 3;     ///< Bandwidth may be auto-extended across adjacent rules.
inline constexpr u32 kRuleFlagIndoorOnly = 1u << 4; ///< Hard indoor restriction (separate from NO_IR scan-only).

struct Rule
{
    u32 start_freq_khz; ///< Inclusive lower bound (e.g. 2'402'000).
    u32 end_freq_khz;   ///< Inclusive upper bound (e.g. 2'472'000).
    u32 max_bw_khz;     ///< Maximum channel bandwidth (e.g. 40'000 for 40 MHz).
    i32 max_eirp_mbm;   ///< Maximum EIRP in 0.01 dBm units (3000 = 30 dBm).
    u32 flags;          ///< OR of kRuleFlag*.
};

// Cap chosen so US / EU / JP fit with room for one extra region
// before a follow-up slice. Bump if the table grows past it.
inline constexpr u32 kRulesMaxPerDomain = 8;

struct Domain
{
    char alpha2[2]; ///< ISO 3166-1 alpha-2 country code.
    u8 n_rules;     ///< Number of valid entries in `rules`.
    u8 _pad;
    Rule rules[kRulesMaxPerDomain];
};

// -------------------------------------------------------------------
// Lookup + accessor surface.
// -------------------------------------------------------------------

/// Number of compiled-in domains.
u32 DomainCount();

/// Return the domain at index `i`, or nullptr on out-of-range. Order
/// is implementation-defined; callers should iterate to find a code.
const Domain* DomainAt(u32 i);

/// Look up a domain by ISO 3166-1 alpha-2 country code (case-
/// insensitive). Returns nullptr if no matching domain exists.
const Domain* DomainByCode(const char alpha2[2]);

/// Read the currently active domain. Defaults to "US" at boot.
const Domain* ActiveDomain();

/// Set the active domain by code. Returns false if the code is not
/// in the table.
bool SetActiveDomain(const char alpha2[2]);

// -------------------------------------------------------------------
// Frequency / channel queries — used by MLME scan + TX gating.
// -------------------------------------------------------------------

/// Find the rule covering `freq_khz` in `dom`. Returns nullptr if no
/// rule contains the freq (i.e. the freq is outside the domain's
/// allowed bands).
const Rule* RuleForFreq(const Domain& dom, u32 freq_khz);

/// True iff `freq_khz` is permitted under `dom` (at least one rule
/// covers it). Shorthand over RuleForFreq.
bool FreqAllowed(const Domain& dom, u32 freq_khz);

/// Sentinel returned by `MaxEirpMbm` when the frequency is not
/// allowed under the queried domain. Distinct from any plausible
/// real EIRP cap so a caller can branch on it without ambiguity.
inline constexpr i32 kEirpNotAllowed = static_cast<i32>(0x80000000u);

/// EIRP cap (mBm) for `freq_khz`, or `kEirpNotAllowed` if not allowed.
i32 MaxEirpMbm(const Domain& dom, u32 freq_khz);

/// 2.4 GHz channel number (1..14) → centre freq in kHz. Returns 0
/// for invalid channels. Channels 1..13 use 5 MHz spacing from
/// 2412 MHz; channel 14 is 2484 MHz (JP only).
u32 ChannelToFreq2GHz(u8 channel);

/// 5 GHz channel number (36, 40, 44, ..., 165) → centre freq in
/// kHz. Returns 0 for invalid channels.
u32 ChannelToFreq5GHz(u8 channel);

/// Inverse of ChannelToFreq*: classify a centre freq into (band,
/// channel). Out args populated only on success.
bool FreqToChannel(u32 freq_khz, u8* out_band, u8* out_channel);

// -------------------------------------------------------------------
// 802.11d Country Information Element intersection.
//
// The CountryIe view points into beacon bytes — caller owns the
// memory. Each `triplet` is the 802.11-2020 §9.4.2.10 sub-band /
// regulatory triplet (first_channel, num_channels, max_tx_power_dbm).
// We model only the sub-band form; operating-triplet form (first
// byte ≥ 201) is parsed but ignored on the intersect path.
// -------------------------------------------------------------------

struct CountryIeTriplet
{
    u8 first_channel; ///< First channel covered.
    u8 num_channels;  ///< Number of contiguous channels (1..N).
    i8 max_tx_dbm;    ///< Max TX power, dBm (signed; can be < 0).
};

struct CountryIeView
{
    char alpha2[2];                ///< Country code from the IE.
    u8 environment;                ///< 'I' indoor / 'O' outdoor / ' ' both.
    u8 n_triplets;                 ///< Filled entries in `triplets`.
    CountryIeTriplet triplets[16]; ///< Capped at 16 sub-bands.
};

/// Parse a Country IE payload (the bytes AFTER the 2-byte
/// element-id/length header — i.e. the contents Beacon::CountryIe
/// returns). Returns true on a well-formed IE.
bool ParseCountryIe(const u8* ie_payload, u32 len, CountryIeView* out);

/// Intersect `base` (the operator-selected domain) with the
/// constraints expressed in `ie`. The result is written to `out` —
/// it may equal `base` (if the IE adds nothing more restrictive) or
/// be tighter (fewer rules, lower EIRP caps).
///
/// Intersection is the safety property: a beacon CAN ONLY reduce
/// what's allowed, never allow more than the operator domain
/// permits. The output domain inherits `base.alpha2`.
void IntersectWithCountryIe(const Domain& base, const CountryIeView& ie, Domain* out);

// -------------------------------------------------------------------
// Boot self-test. Validates that:
//   - The three built-in domains parse and lookup work
//   - Channel ↔ freq conversion is inverse on every channel
//   - JP channel 14 is NO_OFDM
//   - US 5 GHz 5250-5330 carries DFS
//   - A synthetic Country IE that disallows ch 12-13 round-trips
//     through intersection and FreqAllowed returns false for those
//
// Emits `[regdb-selftest] PASS (...)` on success. Called from boot.
// -------------------------------------------------------------------

void SelfTest();

} // namespace duetos::net::wireless::regdb
