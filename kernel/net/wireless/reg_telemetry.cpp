#include "net/wireless/reg_telemetry.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "net/wireless/regdb.h"

namespace duetos::net::wireless
{

using namespace regdb;

namespace
{

// Representative mid-band channels for the per-band cap sample.
constexpr u8 kChan24 = 6; // 2437 MHz
constexpr u8 kChan5 = 36; // 5180 MHz

// mBm (0.01 dBm) -> whole dBm, rounded to nearest.
i16 MbmToDbmRounded(i32 mbm)
{
    const i32 rounded = (mbm >= 0) ? (mbm + 50) / 100 : (mbm - 50) / 100;
    return static_cast<i16>(rounded);
}

} // namespace

RegTelemetryReading RegTelemetryRead()
{
    RegTelemetryReading r = {};
    const Domain* dom = ActiveDomain();
    if (dom == nullptr)
        return r;

    r.country[0] = dom->alpha2[0];
    r.country[1] = dom->alpha2[1];
    r.domain_count = static_cast<u8>(DomainCount());

    const u32 f24 = ChannelToFreq2GHz(kChan24);
    const i32 e24 = MaxEirpMbm(*dom, f24);
    if (e24 != kEirpNotAllowed)
    {
        r.band_24_valid = true;
        r.max_eirp_24_dbm = MbmToDbmRounded(e24);
    }

    const u32 f5 = ChannelToFreq5GHz(kChan5);
    const i32 e5 = MaxEirpMbm(*dom, f5);
    if (e5 != kEirpNotAllowed)
    {
        r.band_5_valid = true;
        r.max_eirp_5_dbm = MbmToDbmRounded(e5);
    }

    r.valid = true;
    return r;
}

void RegTelemetryProbe()
{
    const RegTelemetryReading r = RegTelemetryRead();
    using arch::SerialWrite;
    if (!r.valid)
    {
        SerialWrite("[reg] no active regulatory domain\n");
        return;
    }
    SerialWrite("[reg] domain=");
    arch::SerialWriteByte(static_cast<u8>(r.country[0]));
    arch::SerialWriteByte(static_cast<u8>(r.country[1]));
    if (r.band_24_valid)
    {
        SerialWrite(" 2.4GHz_max_dbm=");
        arch::SerialWriteHex(static_cast<u64>(static_cast<u16>(r.max_eirp_24_dbm)));
    }
    if (r.band_5_valid)
    {
        SerialWrite(" 5GHz_max_dbm=");
        arch::SerialWriteHex(static_cast<u64>(static_cast<u16>(r.max_eirp_5_dbm)));
    }
    SerialWrite("\n");
}

void RegTelemetrySelfTest()
{
    using core::PanicWithValue;

    // The channel→freq helpers are the contract the reader samples at.
    if (ChannelToFreq2GHz(kChan24) != 2437000u)
        PanicWithValue("net/reg", "ch6 != 2437 MHz", ChannelToFreq2GHz(kChan24));
    if (ChannelToFreq5GHz(kChan5) != 5180000u)
        PanicWithValue("net/reg", "ch36 != 5180 MHz", ChannelToFreq5GHz(kChan5));

    // mBm rounding: 2000 mBm == 20 dBm, 2300 == 23, negative clamps round.
    if (MbmToDbmRounded(2000) != 20 || MbmToDbmRounded(2300) != 23 || MbmToDbmRounded(2350) != 24)
        PanicWithValue("net/reg", "mBm->dBm rounding wrong", static_cast<u64>(MbmToDbmRounded(2350)));

    // The active domain must exist and carry a plausible alpha-2 code,
    // and its 2.4 GHz cap must land in the legal 10..30 dBm window.
    const RegTelemetryReading r = RegTelemetryRead();
    if (!r.valid)
        PanicWithValue("net/reg", "no active domain at boot", 0);
    const bool code_ok = (r.country[0] >= 'A' && r.country[0] <= 'Z') && (r.country[1] >= 'A' && r.country[1] <= 'Z');
    if (!code_ok)
        PanicWithValue("net/reg", "active domain code not A-Z", static_cast<u64>(static_cast<u8>(r.country[0])));
    if (r.band_24_valid && (r.max_eirp_24_dbm < 10 || r.max_eirp_24_dbm > 30))
        PanicWithValue("net/reg", "2.4GHz cap out of 10..30 dBm", static_cast<u64>(r.max_eirp_24_dbm));

    arch::SerialWrite("[reg-telemetry-selftest] PASS (domain lookup + channel freq + EIRP caps)\n");
}

} // namespace duetos::net::wireless
