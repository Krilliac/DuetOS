#include "net/wireless/beacon.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "log/klog.h"
#include "net/wifi80211_rust/include/wifi80211_rust.h"

namespace duetos::net::wireless
{

namespace
{

u16 ReadLe16(const u8* buf, u32 off)
{
    return static_cast<u16>(buf[off]) | static_cast<u16>(static_cast<u16>(buf[off + 1]) << 8);
}

// Encode a 4-byte cipher/AKM suite (3-byte OUI + 1-byte type) as
// a packed u32 — easier to compare against constant-folded
// constants without lugging arrays around.
u32 PackSuite(const u8* oui3, u8 type)
{
    return (static_cast<u32>(oui3[0]) << 24) | (static_cast<u32>(oui3[1]) << 16) | (static_cast<u32>(oui3[2]) << 8) |
           static_cast<u32>(type);
}

bool OuiMatches(const u8* oui3, const u8* expect3)
{
    return oui3[0] == expect3[0] && oui3[1] == expect3[1] && oui3[2] == expect3[2];
}

void CopySanitizedSsid(char* dst, const u8* src, u8 len)
{
    u8 i = 0;
    for (; i < len && i < kSsidMaxBytes; ++i)
    {
        const u8 c = src[i];
        // Hidden / probe-only beacons sometimes carry NUL bytes;
        // collapse anything outside printable ASCII to '?' so the
        // value is safe to forward to a log / picker UI.
        dst[i] = (c >= 0x20 && c < 0x7F) ? static_cast<char>(c) : '?';
    }
    dst[i] = '\0';
}

void DeriveSecurity(BeaconParsed* p)
{
    if (!p->rsn_present && !p->wpa1_present)
    {
        p->security = (p->capability_info & kCapPrivacy) ? WirelessSecurity::Wep : WirelessSecurity::Open;
        return;
    }
    if (p->rsn_present)
    {
        // WPA3 if ANY AKM is SAE / FT-SAE / OWE; WPA2-Ent if 802.1X
        // family; WPA2 if PSK; otherwise still WPA2.
        bool has_sae = false;
        bool has_ent = false;
        for (u32 i = 0; i < p->rsn_akm_count; ++i)
        {
            const u8 type = static_cast<u8>(p->rsn_akm_suites[i] & 0xFFu);
            if (type == kAkmSae || type == kAkmFtSae || type == kAkmOwe)
                has_sae = true;
            else if (type == kAkm8021x || type == kAkm8021xSha256 || type == kAkmFt8021x || type == kAkmFt8021xSha384 ||
                     type == kAkmFils)
                has_ent = true;
        }
        if (has_sae)
            p->security = has_ent ? WirelessSecurity::Wpa3Ent : WirelessSecurity::Wpa3;
        else if (has_ent)
            p->security = WirelessSecurity::Wpa2Ent;
        else
            // PSK, or an RSN IE with no AKM we recognise: an RSN IE
            // present implies at least WPA2-class security either way.
            p->security = WirelessSecurity::Wpa2;
        return;
    }
    p->security = WirelessSecurity::Wpa;
}

void ParseRsnIe(const u8* ie_payload, u8 ie_len, BeaconParsed* p)
{
    // RSN IE (id=48) v2.4-2020 §9.4.2.24:
    //   2 ver + 4 group + 2 pcount + 4*pcount pairs + 2 acount +
    //   4*acount akm + 2 caps + (optional PMKID + group-mgmt-cipher)
    //
    // A truncated RSN IE used to set `rsn_present=true` early then
    // bail mid-walk, which left the parsed beacon with an empty
    // cipher / AKM list but the security state derived as WPA2.
    // A crafted beacon could exploit that to coerce association.
    // Now we only commit `rsn_present=true` after the AKM walk
    // completes — if the IE is truncated mid-parse we leave the
    // beacon as if no RSN IE were present and let WPA1 vendor-IE
    // / Privacy-bit fallback decide.
    if (ie_len < 2)
        return;
    u32 off = 0;
    const u16 version = ReadLe16(ie_payload, off);
    off += 2;
    if (off + 4 > ie_len)
    {
        ++p->rsn_truncated_ies;
        return;
    }
    const u32 group_cipher = PackSuite(ie_payload + off, ie_payload[off + 3]);
    off += 4;
    if (off + 2 > ie_len)
    {
        ++p->rsn_truncated_ies;
        return;
    }
    const u16 pair_count = ReadLe16(ie_payload, off);
    off += 2;
    u8 pair_recorded = 0;
    u32 pair_buf[kBeaconMaxCipherSuites] = {};
    for (u16 i = 0; i < pair_count; ++i)
    {
        if (off + 4 > ie_len)
        {
            ++p->rsn_truncated_ies;
            return;
        }
        if (pair_recorded < kBeaconMaxCipherSuites)
        {
            pair_buf[pair_recorded] = PackSuite(ie_payload + off, ie_payload[off + 3]);
            ++pair_recorded;
        }
        off += 4;
    }
    if (off + 2 > ie_len)
    {
        ++p->rsn_truncated_ies;
        return;
    }
    const u16 akm_count = ReadLe16(ie_payload, off);
    off += 2;
    u8 akm_recorded = 0;
    u32 akm_buf[kBeaconMaxAkmSuites] = {};
    for (u16 i = 0; i < akm_count; ++i)
    {
        if (off + 4 > ie_len)
        {
            ++p->rsn_truncated_ies;
            return;
        }
        if (akm_recorded < kBeaconMaxAkmSuites)
        {
            akm_buf[akm_recorded] = PackSuite(ie_payload + off, ie_payload[off + 3]);
            ++akm_recorded;
        }
        off += 4;
    }

    // Full walk done — commit to the parsed beacon.
    p->rsn_present = true;
    p->rsn_version = version;
    p->rsn_group_cipher = group_cipher;
    p->rsn_pairwise_count = pair_recorded;
    for (u8 i = 0; i < pair_recorded; ++i)
        p->rsn_pairwise_ciphers[i] = pair_buf[i];
    p->rsn_akm_count = akm_recorded;
    for (u8 i = 0; i < akm_recorded; ++i)
        p->rsn_akm_suites[i] = akm_buf[i];
    if (off + 2 <= ie_len)
        p->rsn_capabilities = ReadLe16(ie_payload, off);
}

void ParseRatesIe(const u8* ie_payload, u8 ie_len, BeaconParsed* p)
{
    for (u8 i = 0; i < ie_len; ++i)
    {
        const u8 raw = ie_payload[i];
        const u8 rate = raw & 0x7Fu; // strip the basic-rate bit
        const bool basic = (raw & 0x80u) != 0;
        if (p->supported_rates_count < kBeaconMaxRates)
        {
            p->supported_rates[p->supported_rates_count] = raw;
            ++p->supported_rates_count;
        }
        if (basic && rate > p->max_basic_rate_500kbps)
            p->max_basic_rate_500kbps = rate;
    }
}

void ParseVendorIe(const u8* ie_payload, u8 ie_len, BeaconParsed* p)
{
    // WPA-1 IE: OUI 00:50:F2 type 1 (Microsoft / Wi-Fi Alliance).
    static const u8 kWpaOui[3] = {0x00, 0x50, 0xF2};
    if (ie_len >= 4 && OuiMatches(ie_payload, kWpaOui) && ie_payload[3] == 1)
        p->wpa1_present = true;
}

} // namespace

const char* WirelessSecurityName(WirelessSecurity s)
{
    switch (s)
    {
    case WirelessSecurity::Open:
        return "open";
    case WirelessSecurity::Wep:
        return "wep";
    case WirelessSecurity::Wpa:
        return "wpa";
    case WirelessSecurity::Wpa2:
        return "wpa2";
    case WirelessSecurity::Wpa3:
        return "wpa3";
    case WirelessSecurity::Wpa2Ent:
        return "wpa2-ent";
    case WirelessSecurity::Wpa3Ent:
        return "wpa3-ent";
    default:
        return "?";
    }
}

::duetos::core::Result<void> BeaconParse(const u8* frame, u32 frame_size, BeaconParsed* parsed)
{
    if (frame == nullptr || parsed == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    *parsed = {};
    if (frame_size < kFrameMacHeaderBytes + kBeaconFixedBodyBytes)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};

    // First gate: the Rust frame-header walker rejects extension
    // frames + truncated headers in one shot. Beacon/Probe-Response
    // are management frames (type=0); the subtype check happens
    // immediately below.
    ::duetos::net::wifi80211::DuetosWifiFrameHeader rust_hdr{};
    if (!::duetos::net::wifi80211::duetos_wifi80211_parse_frame_header(frame, frame_size, &rust_hdr) ||
        rust_hdr.ok == 0)
        return ::duetos::core::Err{::duetos::core::ErrorCode::Corrupt};

    parsed->frame_control = ReadLe16(frame, 0);
    if (rust_hdr.frame_type != 0)
        return ::duetos::core::Err{::duetos::core::ErrorCode::Corrupt};

    parsed->subtype = static_cast<MgmtSubtype>(rust_hdr.frame_subtype);
    if (parsed->subtype != MgmtSubtype::Beacon && parsed->subtype != MgmtSubtype::ProbeResponse)
        return ::duetos::core::Err{::duetos::core::ErrorCode::Corrupt};

    // MAC header: addr1 = broadcast for beacon, addr2 = source,
    // addr3 = BSSID. The Rust walker has already validated the
    // 24-byte minimum length.
    for (u32 i = 0; i < 6; ++i)
    {
        parsed->source[i] = rust_hdr.addr2[i];
        parsed->bssid[i] = rust_hdr.addr3[i];
    }

    // Fixed body prefix: also from Rust.
    ::duetos::net::wifi80211::DuetosWifiBeaconBody rust_body{};
    if (!::duetos::net::wifi80211::duetos_wifi80211_parse_beacon_body(frame, frame_size, &rust_body) ||
        rust_body.ok == 0)
        return ::duetos::core::Err{::duetos::core::ErrorCode::Corrupt};
    parsed->timestamp = rust_body.timestamp;
    parsed->beacon_interval = rust_body.beacon_interval;
    parsed->capability_info = rust_body.capability_info;
    // IE walk — each step goes through the Rust IE decoder so a
    // malformed length field can't slip past the bounds check.
    u32 off = rust_body.ie_list_offset;
    while (off + 2 <= frame_size)
    {
        ::duetos::net::wifi80211::DuetosWifiIe rust_ie{};
        if (!::duetos::net::wifi80211::duetos_wifi80211_parse_ie(frame, frame_size, off, &rust_ie) || rust_ie.ok == 0)
        {
            // Truncated IE — stop walking but keep what we have.
            break;
        }
        const u8 id = rust_ie.id;
        const u8 len = rust_ie.len;
        const u8* payload = frame + rust_ie.payload_offset;
        ++parsed->ie_count;

        switch (id)
        {
        case kIeSsid:
            CopySanitizedSsid(parsed->ssid, payload, len);
            parsed->ssid_length = len;
            parsed->hidden_ssid = (len == 0);
            break;
        case kIeSupportedRates:
        case kIeExtendedSupportedRates:
            ParseRatesIe(payload, len, parsed);
            break;
        case kIeDsParamSet:
            if (len >= 1)
                parsed->channel = payload[0];
            break;
        case kIeHtOperation:
            // First byte is the primary channel — overrides DS
            // when the AP is on 5 GHz (no DS Parameter Set there).
            if (len >= 1 && parsed->channel == 0)
                parsed->channel = payload[0];
            break;
        case kIeRsn:
            ParseRsnIe(payload, len, parsed);
            break;
        case kIeVendorSpecific:
            ParseVendorIe(payload, len, parsed);
            break;
        default:
            ++parsed->unknown_ies;
            break;
        }

        off += 2 + static_cast<u32>(len);
    }

    parsed->walked_bytes = off;
    DeriveSecurity(parsed);
    parsed->valid = true;
    if (parsed->rsn_truncated_ies != 0)
        KLOG_WARN_V("net/wireless/beacon", "beacon RSN IE truncated mid-parse — RSN view discarded",
                    static_cast<u64>(parsed->rsn_truncated_ies));
    return ::duetos::core::Result<void>{};
}

void BeaconLog(const BeaconParsed& parsed)
{
    arch::SerialWrite("[80211] beacon ssid=\"");
    arch::SerialWrite(parsed.hidden_ssid ? "<hidden>" : parsed.ssid);
    arch::SerialWrite("\" channel=");
    arch::SerialWriteHex(parsed.channel);
    arch::SerialWrite(" sec=");
    arch::SerialWrite(WirelessSecurityName(parsed.security));
    arch::SerialWrite(" cap=");
    arch::SerialWriteHex(parsed.capability_info);
    arch::SerialWrite(" beacon_int=");
    arch::SerialWriteHex(parsed.beacon_interval);
    arch::SerialWrite(" rates=");
    arch::SerialWriteHex(parsed.supported_rates_count);
    arch::SerialWrite(" ies=");
    arch::SerialWriteHex(parsed.ie_count);
    arch::SerialWrite(" unknown=");
    arch::SerialWriteHex(parsed.unknown_ies);
    arch::SerialWrite("\n");
}

namespace
{

// Tiny builder helpers for the synthetic beacon used in
// `BeaconSelfTest`. These intentionally don't share code with
// the rtl/bcm/iwl helpers — they're test-local and stay local.
void WriteLe16(u8* buf, u32 off, u16 v)
{
    buf[off] = static_cast<u8>(v & 0xFF);
    buf[off + 1] = static_cast<u8>((v >> 8) & 0xFF);
}

void WriteLe64(u8* buf, u32 off, u64 v)
{
    for (u32 i = 0; i < 8; ++i)
        buf[off + i] = static_cast<u8>((v >> (8 * i)) & 0xFFu);
}

u32 AppendIe(u8* buf, u32 off, u8 id, const u8* payload, u8 len)
{
    buf[off] = id;
    buf[off + 1] = len;
    for (u8 i = 0; i < len; ++i)
        buf[off + 2 + i] = payload[i];
    return off + 2u + static_cast<u32>(len);
}

} // namespace

void BeaconSelfTest()
{
    constexpr u32 kBufBytes = 256;
    static u8 buf[kBufBytes] = {};
    for (u32 i = 0; i < kBufBytes; ++i)
        buf[i] = 0;

    // MAC header — beacon, no protection, addr1=ff..ff, addr2/addr3
    // = test BSSID 02:11:22:33:44:55.
    const u16 fc = (static_cast<u16>(FrameType::Management) << kFcTypeShift) |
                   (static_cast<u16>(MgmtSubtype::Beacon) << kFcSubtypeShift);
    WriteLe16(buf, 0, fc);
    // Duration.
    WriteLe16(buf, 2, 0);
    // Address 1 — broadcast.
    for (u32 i = 0; i < 6; ++i)
        buf[4 + i] = 0xFF;
    // Address 2/3.
    const u8 mac[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    for (u32 i = 0; i < 6; ++i)
    {
        buf[10 + i] = mac[i];
        buf[16 + i] = mac[i];
    }
    // Sequence ctrl.
    WriteLe16(buf, 22, 0);

    // Fixed body: timestamp + bcn_int + cap.
    u32 off = kFrameMacHeaderBytes;
    WriteLe64(buf, off, 0xCAFEBABEDEADBEEFULL);
    off += 8;
    WriteLe16(buf, off, 100); // 100 TU
    off += 2;
    const u16 cap = kCapEss | kCapPrivacy | kCapShortPreamble | kCapShortSlotTime;
    WriteLe16(buf, off, cap);
    off += 2;

    // IE: SSID = "DuetOS-test"
    const char* ssid = "DuetOS-test";
    u8 ssid_bytes[12] = {};
    u8 ssid_len = 0;
    for (; ssid[ssid_len] != '\0' && ssid_len < 12; ++ssid_len)
        ssid_bytes[ssid_len] = static_cast<u8>(ssid[ssid_len]);
    off = AppendIe(buf, off, kIeSsid, ssid_bytes, ssid_len);

    // IE: Supported Rates — 1, 2, 5.5, 11 Mbps with basic-rate bit.
    const u8 rates[4] = {0x82, 0x84, 0x8B, 0x96};
    off = AppendIe(buf, off, kIeSupportedRates, rates, 4);

    // IE: DS Parameter Set — channel 6.
    const u8 ds[1] = {6};
    off = AppendIe(buf, off, kIeDsParamSet, ds, 1);

    // IE: RSN — WPA2-PSK with CCMP-128 group + pairwise + AKM PSK.
    u8 rsn[24] = {};
    u32 rsn_off = 0;
    // Version = 1
    rsn[rsn_off++] = 0x01;
    rsn[rsn_off++] = 0x00;
    // Group cipher: 00:0F:AC:04 (CCMP-128)
    rsn[rsn_off++] = 0x00;
    rsn[rsn_off++] = 0x0F;
    rsn[rsn_off++] = 0xAC;
    rsn[rsn_off++] = kCipherCcmp128;
    // Pairwise count = 1
    rsn[rsn_off++] = 0x01;
    rsn[rsn_off++] = 0x00;
    // Pairwise[0] = CCMP-128
    rsn[rsn_off++] = 0x00;
    rsn[rsn_off++] = 0x0F;
    rsn[rsn_off++] = 0xAC;
    rsn[rsn_off++] = kCipherCcmp128;
    // AKM count = 1
    rsn[rsn_off++] = 0x01;
    rsn[rsn_off++] = 0x00;
    // AKM[0] = PSK
    rsn[rsn_off++] = 0x00;
    rsn[rsn_off++] = 0x0F;
    rsn[rsn_off++] = 0xAC;
    rsn[rsn_off++] = kAkmPsk;
    // RSN capabilities = 0
    rsn[rsn_off++] = 0x00;
    rsn[rsn_off++] = 0x00;
    off = AppendIe(buf, off, kIeRsn, rsn, static_cast<u8>(rsn_off));

    // IE: Vendor Specific (unrelated — exercises unknown_ies counter).
    const u8 vs[5] = {0x00, 0x50, 0xF2, 0x99, 0x00};
    off = AppendIe(buf, off, kIeVendorSpecific, vs, 5);

    KASSERT(off <= kBufBytes, "net/wireless/beacon", "selftest buffer overflow");

    BeaconParsed parsed{};
    auto r = BeaconParse(buf, off, &parsed);
    KASSERT(r.has_value(), "net/wireless/beacon", "beacon selftest parse error");
    KASSERT(parsed.valid, "net/wireless/beacon", "beacon selftest valid=false");
    KASSERT(parsed.subtype == MgmtSubtype::Beacon, "net/wireless/beacon", "beacon selftest wrong subtype");
    KASSERT(parsed.ssid_length == ssid_len, "net/wireless/beacon", "beacon selftest ssid_length mismatch");
    KASSERT(!parsed.hidden_ssid, "net/wireless/beacon", "beacon selftest unexpected hidden_ssid");
    bool ssid_ok = true;
    for (u8 i = 0; i < ssid_len; ++i)
        if (parsed.ssid[i] != ssid[i])
            ssid_ok = false;
    KASSERT(ssid_ok, "net/wireless/beacon", "beacon selftest ssid byte mismatch");
    KASSERT(parsed.channel == 6, "net/wireless/beacon", "beacon selftest wrong channel");
    KASSERT(parsed.beacon_interval == 100, "net/wireless/beacon", "beacon selftest wrong bcn_int");
    KASSERT(parsed.capability_info == cap, "net/wireless/beacon", "beacon selftest wrong cap_info");
    KASSERT(parsed.supported_rates_count == 4, "net/wireless/beacon", "beacon selftest wrong rate count");
    KASSERT(parsed.max_basic_rate_500kbps == 0x16, "net/wireless/beacon", "beacon selftest wrong max basic rate");
    KASSERT(parsed.rsn_present, "net/wireless/beacon", "beacon selftest rsn_present=false");
    KASSERT(parsed.rsn_version == 1, "net/wireless/beacon", "beacon selftest wrong rsn version");
    KASSERT(parsed.rsn_pairwise_count == 1, "net/wireless/beacon", "beacon selftest wrong pairwise count");
    KASSERT(parsed.rsn_akm_count == 1, "net/wireless/beacon", "beacon selftest wrong akm count");
    KASSERT(parsed.security == WirelessSecurity::Wpa2, "net/wireless/beacon", "beacon selftest derived wrong security");

    // Negative case: data frame should be rejected.
    {
        u8 data_frame[kFrameMacHeaderBytes + kBeaconFixedBodyBytes] = {};
        const u16 dfc = static_cast<u16>(FrameType::Data) << kFcTypeShift;
        WriteLe16(data_frame, 0, dfc);
        BeaconParsed p{};
        auto r2 = BeaconParse(data_frame, sizeof(data_frame), &p);
        KASSERT(!r2.has_value() && r2.error() == ::duetos::core::ErrorCode::Corrupt, "net/wireless/beacon",
                "beacon selftest data-frame should return Corrupt");
    }

    // Negative case: too short for MAC header + fixed body.
    {
        u8 short_frame[16] = {};
        BeaconParsed p{};
        auto r3 = BeaconParse(short_frame, sizeof(short_frame), &p);
        KASSERT(!r3.has_value() && r3.error() == ::duetos::core::ErrorCode::InvalidArgument, "net/wireless/beacon",
                "beacon selftest short-frame should return InvalidArgument");
    }

    // Hidden SSID (length 0) → hidden_ssid=true.
    {
        static u8 hid[kBufBytes] = {};
        for (u32 i = 0; i < kBufBytes; ++i)
            hid[i] = 0;
        WriteLe16(hid, 0, fc);
        u32 ho = kFrameMacHeaderBytes;
        WriteLe64(hid, ho, 0);
        ho += 8;
        WriteLe16(hid, ho, 100);
        ho += 2;
        WriteLe16(hid, ho, kCapEss);
        ho += 2;
        ho = AppendIe(hid, ho, kIeSsid, nullptr, 0);
        BeaconParsed p{};
        auto r4 = BeaconParse(hid, ho, &p);
        KASSERT(r4.has_value(), "net/wireless/beacon", "beacon selftest hidden parse error");
        KASSERT(p.hidden_ssid, "net/wireless/beacon", "beacon selftest hidden_ssid=false");
        KASSERT(p.security == WirelessSecurity::Open, "net/wireless/beacon",
                "beacon selftest hidden+open should derive Open");
    }

    // WPA3-SAE IE.
    {
        static u8 sae[kBufBytes] = {};
        for (u32 i = 0; i < kBufBytes; ++i)
            sae[i] = 0;
        WriteLe16(sae, 0, fc);
        u32 so = kFrameMacHeaderBytes;
        WriteLe64(sae, so, 0);
        so += 8;
        WriteLe16(sae, so, 100);
        so += 2;
        WriteLe16(sae, so, kCapEss | kCapPrivacy);
        so += 2;
        const u8 nm[2] = {'h', 'i'};
        so = AppendIe(sae, so, kIeSsid, nm, 2);
        u8 rsn3[24] = {};
        u32 ro = 0;
        rsn3[ro++] = 0x01;
        rsn3[ro++] = 0x00;
        rsn3[ro++] = 0x00;
        rsn3[ro++] = 0x0F;
        rsn3[ro++] = 0xAC;
        rsn3[ro++] = kCipherCcmp128;
        rsn3[ro++] = 0x01;
        rsn3[ro++] = 0x00;
        rsn3[ro++] = 0x00;
        rsn3[ro++] = 0x0F;
        rsn3[ro++] = 0xAC;
        rsn3[ro++] = kCipherCcmp128;
        rsn3[ro++] = 0x01;
        rsn3[ro++] = 0x00;
        rsn3[ro++] = 0x00;
        rsn3[ro++] = 0x0F;
        rsn3[ro++] = 0xAC;
        rsn3[ro++] = kAkmSae;
        rsn3[ro++] = 0x00;
        rsn3[ro++] = 0x00;
        so = AppendIe(sae, so, kIeRsn, rsn3, static_cast<u8>(ro));
        BeaconParsed p{};
        auto r5 = BeaconParse(sae, so, &p);
        KASSERT(r5.has_value(), "net/wireless/beacon", "beacon selftest sae parse error");
        KASSERT(p.security == WirelessSecurity::Wpa3, "net/wireless/beacon", "beacon selftest SAE should derive Wpa3");
    }

    arch::SerialWrite("[80211] beacon selftest pass\n");
}

} // namespace duetos::net::wireless
