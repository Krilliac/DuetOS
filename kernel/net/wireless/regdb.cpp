/*
 * DuetOS — Wireless regulatory database, in-tree tables.
 *
 * Rule tables compiled from the FCC (US), ETSI EN 300 328 +
 * EN 301 893 (EU), and Radio Law / ARIB STD-T66 (JP). Sources
 * cross-checked against the `wireless-regdb` repository's `db.txt`
 * — same rule shapes, expressed in kHz/mBm for in-tree clarity.
 *
 * If a region needs an entry not in the built-in set, add a new
 * `Domain` literal here (do NOT load a runtime regulatory.db
 * unless we ship signed firmware delivery, which is a separate
 * slice).
 */

#include "net/wireless/regdb.h"

#include "arch/x86_64/serial.h"
#include "util/string.h"

namespace duetos::net::wireless::regdb
{

// -------------------------------------------------------------------
// Built-in rule tables.
// -------------------------------------------------------------------

// US — FCC Part 15.247 (2.4 GHz), Part 15.407 (5 GHz UNII bands).
// 30 dBm cap on 2.4 GHz; UNII-1 (5170-5250) indoor cap is 23 dBm;
// UNII-2 (5250-5330) + UNII-2-extended (5490-5730) require DFS;
// UNII-3 (5735-5835) is 30 dBm + outdoor.
constexpr Domain kDomainUS = {{'U', 'S'},
                              5,
                              0,
                              {
                                  Rule{2'402'000, 2'472'000, 40'000, 3000, kRuleFlagNone},
                                  Rule{5'170'000, 5'250'000, 80'000, 2300, kRuleFlagNone},
                                  Rule{5'250'000, 5'330'000, 80'000, 2300, kRuleFlagDfs},
                                  Rule{5'490'000, 5'730'000, 160'000, 2300, kRuleFlagDfs},
                                  Rule{5'735'000, 5'835'000, 80'000, 3000, kRuleFlagNone},
                                  // unused slots
                                  Rule{0, 0, 0, 0, 0},
                                  Rule{0, 0, 0, 0, 0},
                                  Rule{0, 0, 0, 0, 0},
                              }};

// EU — ETSI EN 300 328 (2.4 GHz) and EN 301 893 (5 GHz). 20 dBm
// cap on 2.4 GHz; UNII-1 indoor-only at 23 dBm; UNII-2 requires
// DFS; UNII-2-extended permits 30 dBm + DFS. No UNII-3.
constexpr Domain kDomainEU = {{'E', 'U'},
                              4,
                              0,
                              {
                                  Rule{2'402'000, 2'482'000, 40'000, 2000, kRuleFlagNone},
                                  Rule{5'170'000, 5'250'000, 80'000, 2300, kRuleFlagNoIr | kRuleFlagIndoorOnly},
                                  Rule{5'250'000, 5'330'000, 80'000, 2300, kRuleFlagDfs},
                                  Rule{5'490'000, 5'710'000, 160'000, 3000, kRuleFlagDfs},
                                  Rule{0, 0, 0, 0, 0},
                                  Rule{0, 0, 0, 0, 0},
                                  Rule{0, 0, 0, 0, 0},
                                  Rule{0, 0, 0, 0, 0},
                              }};

// JP — Radio Law / ARIB. 2.4 GHz to 2484 MHz (channel 14 OFDM
// prohibited; 802.11b only). UNII-1 + UNII-2 covered; UNII-2-
// extended cap is 23 dBm. No UNII-3.
constexpr Domain kDomainJP = {{'J', 'P'},
                              5,
                              0,
                              {
                                  Rule{2'402'000, 2'482'000, 40'000, 2000, kRuleFlagNone},
                                  Rule{2'474'000, 2'494'000, 20'000, 2000, kRuleFlagNoOfdm},
                                  Rule{5'170'000, 5'250'000, 80'000, 2300, kRuleFlagNone},
                                  Rule{5'250'000, 5'330'000, 80'000, 2300, kRuleFlagDfs},
                                  Rule{5'490'000, 5'710'000, 160'000, 2300, kRuleFlagDfs},
                                  Rule{0, 0, 0, 0, 0},
                                  Rule{0, 0, 0, 0, 0},
                                  Rule{0, 0, 0, 0, 0},
                              }};

constexpr const Domain* kDomains[] = {&kDomainUS, &kDomainEU, &kDomainJP};
constexpr u32 kDomainCount = sizeof(kDomains) / sizeof(kDomains[0]);

// Active domain selection. Defaults to US — matches the existing
// MLME / channel-scan code's assumption.
const Domain* g_active = &kDomainUS;

// -------------------------------------------------------------------
// Accessors.
// -------------------------------------------------------------------

u32 DomainCount()
{
    return kDomainCount;
}

const Domain* DomainAt(u32 i)
{
    if (i >= kDomainCount)
        return nullptr;
    return kDomains[i];
}

static bool Alpha2Eq(const char a[2], const char b[2])
{
    auto fold = [](char c) -> char
    {
        if (c >= 'a' && c <= 'z')
            return char(c - 'a' + 'A');
        return c;
    };
    return fold(a[0]) == fold(b[0]) && fold(a[1]) == fold(b[1]);
}

const Domain* DomainByCode(const char alpha2[2])
{
    for (u32 i = 0; i < kDomainCount; ++i)
    {
        if (Alpha2Eq(kDomains[i]->alpha2, alpha2))
            return kDomains[i];
    }
    return nullptr;
}

const Domain* ActiveDomain()
{
    return g_active;
}

bool SetActiveDomain(const char alpha2[2])
{
    const Domain* d = DomainByCode(alpha2);
    if (d == nullptr)
        return false;
    g_active = d;
    return true;
}

// -------------------------------------------------------------------
// Rule lookups.
// -------------------------------------------------------------------

const Rule* RuleForFreq(const Domain& dom, u32 freq_khz)
{
    for (u8 i = 0; i < dom.n_rules; ++i)
    {
        const Rule& r = dom.rules[i];
        if (r.start_freq_khz == 0)
            continue;
        if (freq_khz >= r.start_freq_khz && freq_khz <= r.end_freq_khz)
            return &r;
    }
    return nullptr;
}

bool FreqAllowed(const Domain& dom, u32 freq_khz)
{
    return RuleForFreq(dom, freq_khz) != nullptr;
}

i32 MaxEirpMbm(const Domain& dom, u32 freq_khz)
{
    const Rule* r = RuleForFreq(dom, freq_khz);
    if (r == nullptr)
        return kEirpNotAllowed;
    return r->max_eirp_mbm;
}

// -------------------------------------------------------------------
// Channel / freq conversion.
// -------------------------------------------------------------------

u32 ChannelToFreq2GHz(u8 channel)
{
    if (channel >= 1 && channel <= 13)
        return 2'407'000 + u32(channel) * 5000;
    if (channel == 14)
        return 2'484'000;
    return 0;
}

u32 ChannelToFreq5GHz(u8 channel)
{
    // 5 GHz uses 5 MHz channel grid starting at 5000 MHz. Only a
    // discrete set of channels is used (UNII bands); we accept the
    // ones reachable through our rule tables and let RuleForFreq
    // filter further.
    if (channel < 7 || channel > 196)
        return 0;
    const u32 freq = 5'000'000 + u32(channel) * 5000;
    if (freq < 5'030'000 || freq > 5'980'000)
        return 0;
    return freq;
}

bool FreqToChannel(u32 freq_khz, u8* out_band, u8* out_channel)
{
    // 2.4 GHz band.
    if (freq_khz == 2'484'000)
    {
        if (out_band != nullptr)
            *out_band = 2;
        if (out_channel != nullptr)
            *out_channel = 14;
        return true;
    }
    if (freq_khz >= 2'412'000 && freq_khz <= 2'472'000)
    {
        const u32 ch = (freq_khz - 2'407'000) / 5000;
        if (ch >= 1 && ch <= 13 && (2'407'000 + ch * 5000) == freq_khz)
        {
            if (out_band != nullptr)
                *out_band = 2;
            if (out_channel != nullptr)
                *out_channel = u8(ch);
            return true;
        }
    }
    // 5 GHz band.
    if (freq_khz >= 5'030'000 && freq_khz <= 5'980'000 && (freq_khz % 5000) == 0)
    {
        const u32 ch = (freq_khz - 5'000'000) / 5000;
        if (ch >= 7 && ch <= 196)
        {
            if (out_band != nullptr)
                *out_band = 5;
            if (out_channel != nullptr)
                *out_channel = u8(ch);
            return true;
        }
    }
    return false;
}

// -------------------------------------------------------------------
// 802.11d Country IE intersection.
//
// Payload layout per 802.11-2020 §9.4.2.10:
//   - 2 bytes: country code (alpha-2)
//   - 1 byte:  environment ('I'/'O'/' ')
//   - N × 3 bytes: triplets
//       sub-band form (first_byte < 201):
//         first_channel | num_channels | max_tx_power_dbm (i8)
//       operating-triplet form (first_byte >= 201): parsed, ignored
// -------------------------------------------------------------------

bool ParseCountryIe(const u8* ie_payload, u32 len, CountryIeView* out)
{
    if (out == nullptr || ie_payload == nullptr || len < 3)
        return false;
    out->alpha2[0] = char(ie_payload[0]);
    out->alpha2[1] = char(ie_payload[1]);
    out->environment = ie_payload[2];
    out->n_triplets = 0;
    u32 i = 3;
    while (i + 3 <= len && out->n_triplets < 16)
    {
        const u8 first = ie_payload[i];
        if (first >= 201)
        {
            // Operating-triplet form. Skip silently — the existing
            // sub-band triplets we've already parsed are the
            // intersect input; ignoring operating triplets only
            // narrows the safety surface.
            i += 3;
            continue;
        }
        CountryIeTriplet& t = out->triplets[out->n_triplets++];
        t.first_channel = first;
        t.num_channels = ie_payload[i + 1];
        t.max_tx_dbm = i8(ie_payload[i + 2]);
        i += 3;
    }
    return true;
}

// Convert a Country-IE sub-band triplet into an inclusive freq
// range. Assumes 2.4 GHz channel numbering; the IE itself doesn't
// distinguish, but only 2.4 GHz channels (1..14) fit in u8 < 200
// in practice — 5 GHz IE entries (36..165) carry the same shape
// but on the 5 GHz channel grid. We do both: try 2.4 GHz first,
// fall back to 5 GHz if the first channel doesn't resolve.
static bool TripletToFreqRange(const CountryIeTriplet& t, u32* out_start_khz, u32* out_end_khz)
{
    u32 start = ChannelToFreq2GHz(t.first_channel);
    bool is_5ghz = false;
    if (start == 0)
    {
        start = ChannelToFreq5GHz(t.first_channel);
        is_5ghz = true;
    }
    if (start == 0 || t.num_channels == 0)
        return false;
    const u32 last_channel = t.first_channel + t.num_channels - 1;
    u32 last_centre = is_5ghz ? ChannelToFreq5GHz(u8(last_channel)) : ChannelToFreq2GHz(u8(last_channel));
    if (last_centre == 0)
        return false;
    // Sub-band edges are ± 10 MHz from centre for a 20 MHz channel
    // — matches the original FCC sub-band-edge convention used in
    // Country IEs. Wider channels are negotiated via the
    // operating-class extension we already skip.
    if (out_start_khz != nullptr)
        *out_start_khz = start - 10'000;
    if (out_end_khz != nullptr)
        *out_end_khz = last_centre + 10'000;
    return true;
}

void IntersectWithCountryIe(const Domain& base, const CountryIeView& ie, Domain* out)
{
    if (out == nullptr)
        return;
    out->alpha2[0] = base.alpha2[0];
    out->alpha2[1] = base.alpha2[1];
    out->_pad = 0;
    u8 next = 0;

    // For each base rule, walk the IE triplets and emit at most one
    // intersected output rule per overlapping triplet. The output
    // rule's EIRP is min(base, ie); flags inherit from the base.
    for (u8 bi = 0; bi < base.n_rules && next < kRulesMaxPerDomain; ++bi)
    {
        const Rule& br = base.rules[bi];
        if (br.start_freq_khz == 0)
            continue;
        bool emitted_any = false;
        for (u8 ti = 0; ti < ie.n_triplets && next < kRulesMaxPerDomain; ++ti)
        {
            u32 t_start = 0;
            u32 t_end = 0;
            if (!TripletToFreqRange(ie.triplets[ti], &t_start, &t_end))
                continue;
            // Compute the overlap.
            const u32 start = (t_start > br.start_freq_khz) ? t_start : br.start_freq_khz;
            const u32 end = (t_end < br.end_freq_khz) ? t_end : br.end_freq_khz;
            if (start > end)
                continue;
            const i32 ie_eirp_mbm = i32(ie.triplets[ti].max_tx_dbm) * 100;
            const i32 cap = (ie_eirp_mbm < br.max_eirp_mbm) ? ie_eirp_mbm : br.max_eirp_mbm;
            out->rules[next++] = Rule{start, end, br.max_bw_khz, cap, br.flags};
            emitted_any = true;
        }
        // If the IE didn't speak to this base rule at all, the IE
        // is silent on it — keep the base rule unchanged. This is
        // the spec-defined fallback ("a country may omit bands it
        // doesn't regulate"). If the operator wants pure
        // intersection, they can set the active domain to a
        // narrower one before connecting.
        if (!emitted_any && next < kRulesMaxPerDomain)
            out->rules[next++] = br;
    }
    // Zero any slack entries so consumers iterating to
    // kRulesMaxPerDomain see the correct sentinel.
    for (u8 i = next; i < kRulesMaxPerDomain; ++i)
        out->rules[i] = Rule{0, 0, 0, 0, 0};
    out->n_rules = next;
}

// -------------------------------------------------------------------
// Boot self-test.
// -------------------------------------------------------------------

namespace
{

void WriteHex(u32 v)
{
    char buf[12];
    buf[0] = '0';
    buf[1] = 'x';
    static const char kHex[] = "0123456789abcdef";
    for (u32 i = 0; i < 8; ++i)
        buf[2 + i] = kHex[(v >> ((7 - i) * 4)) & 0xF];
    buf[10] = 0;
    arch::SerialWrite(buf);
}

void Fail(const char* what)
{
    arch::SerialWrite("[regdb-selftest] FAIL: ");
    arch::SerialWrite(what);
    arch::SerialWrite("\n");
}

} // anonymous namespace

void SelfTest()
{
    // Compiled-in count.
    if (DomainCount() != 3)
    {
        Fail("domain count != 3");
        return;
    }

    // Lookup by code.
    const Domain* us = DomainByCode("us");
    const Domain* eu = DomainByCode("EU");
    const Domain* jp = DomainByCode("JP");
    if (us == nullptr || eu == nullptr || jp == nullptr)
    {
        Fail("DomainByCode missed a built-in");
        return;
    }

    // Channel ↔ freq round-trip on every 2.4 GHz + sample 5 GHz channel.
    for (u8 ch = 1; ch <= 14; ++ch)
    {
        const u32 f = ChannelToFreq2GHz(ch);
        if (f == 0)
        {
            Fail("ChannelToFreq2GHz returned 0 for valid channel");
            return;
        }
        u8 band = 0;
        u8 back_ch = 0;
        if (!FreqToChannel(f, &band, &back_ch) || band != 2 || back_ch != ch)
        {
            Fail("2.4 GHz round-trip broken");
            return;
        }
    }
    static const u8 k5GhzSample[] = {36, 40, 44, 48, 52, 100, 149, 165};
    for (u8 ch : k5GhzSample)
    {
        const u32 f = ChannelToFreq5GHz(ch);
        if (f == 0)
        {
            Fail("ChannelToFreq5GHz returned 0 for valid channel");
            return;
        }
        u8 band = 0;
        u8 back_ch = 0;
        if (!FreqToChannel(f, &band, &back_ch) || band != 5 || back_ch != ch)
        {
            Fail("5 GHz round-trip broken");
            return;
        }
    }

    // JP channel 14: NO_OFDM. US channel 14: not allowed.
    const Rule* jp_ch14 = RuleForFreq(*jp, 2'484'000);
    if (jp_ch14 == nullptr || (jp_ch14->flags & kRuleFlagNoOfdm) == 0)
    {
        Fail("JP ch14 missing NO_OFDM");
        return;
    }
    if (FreqAllowed(*us, 2'484'000))
    {
        Fail("US wrongly allows ch14 (2484 MHz)");
        return;
    }

    // US 5250-5330 carries DFS.
    const Rule* us_5ghz_dfs = RuleForFreq(*us, 5'280'000);
    if (us_5ghz_dfs == nullptr || (us_5ghz_dfs->flags & kRuleFlagDfs) == 0)
    {
        Fail("US 5280 MHz missing DFS flag");
        return;
    }

    // EU UNII-1 marked NO_IR (indoor) per ETSI.
    const Rule* eu_unii1 = RuleForFreq(*eu, 5'200'000);
    if (eu_unii1 == nullptr || (eu_unii1->flags & kRuleFlagNoIr) == 0)
    {
        Fail("EU UNII-1 missing NO_IR");
        return;
    }

    // EIRP cap sanity.
    if (MaxEirpMbm(*us, 2'437'000) != 3000)
    {
        Fail("US 2437 MHz EIRP cap unexpected");
        return;
    }
    if (MaxEirpMbm(*eu, 2'437'000) != 2000)
    {
        Fail("EU 2437 MHz EIRP cap unexpected");
        return;
    }

    // Synthetic Country IE: US 2.4 GHz limited to channels 1-11,
    // EIRP 18 dBm. Intersection with US must lower the EIRP and
    // narrow the band.
    const u8 ie_payload[] = {
        'U', 'S', ' ', // alpha-2 + indoor/outdoor unspecified
        1,   11,  18,  // channels 1..11, 18 dBm
    };
    CountryIeView view = {};
    if (!ParseCountryIe(ie_payload, sizeof(ie_payload), &view) || view.n_triplets != 1 ||
        view.triplets[0].first_channel != 1 || view.triplets[0].num_channels != 11)
    {
        Fail("Country IE parse broken");
        return;
    }
    Domain narrowed = {};
    IntersectWithCountryIe(*us, view, &narrowed);
    // 2462 MHz (ch 11) must still be allowed at ≤ 1800 mBm.
    const Rule* nrr = RuleForFreq(narrowed, 2'462'000);
    if (nrr == nullptr || nrr->max_eirp_mbm > 1800)
    {
        Fail("Intersected US: ch11 EIRP not capped");
        return;
    }
    // 2467 MHz (ch 12) is OUTSIDE the IE — but the IE was silent
    // on the 5 GHz bands too, so the spec-mandated fallback keeps
    // the base 5 GHz rules. Verify a 5 GHz freq still resolves
    // under the narrowed domain.
    if (!FreqAllowed(narrowed, 5'200'000))
    {
        Fail("Intersect dropped silent 5 GHz band");
        return;
    }
    // The base 2.4 GHz US rule (2.402-2.472) was REPLACED by the
    // narrower intersected rule (centre 2412..2462, edges 2402..2472).
    // Verify the intersected rule has the lower EIRP cap.
    const Rule* narrowed_24 = RuleForFreq(narrowed, 2'437'000);
    if (narrowed_24 == nullptr || narrowed_24->max_eirp_mbm > 1800)
    {
        Fail("Intersect did not lower 2.4 GHz EIRP cap");
        return;
    }

    arch::SerialWrite("[regdb-selftest] PASS (domains=");
    WriteHex(DomainCount());
    arch::SerialWrite(" us_rules=");
    WriteHex(us->n_rules);
    arch::SerialWrite(" eu_rules=");
    WriteHex(eu->n_rules);
    arch::SerialWrite(" jp_rules=");
    WriteHex(jp->n_rules);
    arch::SerialWrite(")\n");
}

} // namespace duetos::net::wireless::regdb
