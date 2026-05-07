#include "drivers/audio/hda_jack.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"

namespace duetos::drivers::audio::hda
{

namespace
{

template <typename E> E ToEnum4(u32 raw, u32 shift)
{
    return static_cast<E>((raw >> shift) & 0xF);
}

template <typename E> E ToEnum2(u32 raw, u32 shift)
{
    return static_cast<E>((raw >> shift) & 0x3);
}

void Eq(u64 actual, u64 expected, const char* what)
{
    if (actual == expected)
        return;
    arch::SerialWrite("[hda-jack] MISMATCH ");
    arch::SerialWrite(what);
    arch::SerialWrite(" actual=");
    arch::SerialWriteHex(actual);
    arch::SerialWrite(" expected=");
    arch::SerialWriteHex(expected);
    arch::SerialWrite("\n");
    core::PanicWithValue("drivers/audio/hda-jack", "HDA jack self-test mismatch", actual);
}

} // namespace

HdaPinConfigDefault HdaDecodePinConfigDefault(u32 raw)
{
    HdaPinConfigDefault c{};
    c.raw = raw;
    c.port_connectivity = ToEnum2<HdaPortConnectivity>(raw, 30);
    c.location_gross = u8((raw >> 28) & 0x3);
    c.location_geometric = u8((raw >> 24) & 0xF);
    c.default_device = ToEnum4<HdaDefaultDevice>(raw, 20);
    c.connection_type = ToEnum4<HdaConnectionType>(raw, 16);
    c.color = ToEnum4<HdaJackColor>(raw, 12);
    c.default_association = u8((raw >> 4) & 0xF);
    c.sequence = u8(raw & 0xF);
    c.jack_detect_override = ((raw >> 8) & 0x1) != 0;
    return c;
}

const char* HdaDefaultDeviceTag(HdaDefaultDevice d)
{
    switch (d)
    {
    case HdaDefaultDevice::LineOut:
        return "line-out";
    case HdaDefaultDevice::Speaker:
        return "speaker";
    case HdaDefaultDevice::HpOut:
        return "hp-out";
    case HdaDefaultDevice::Cd:
        return "cd";
    case HdaDefaultDevice::SpdifOut:
        return "spdif-out";
    case HdaDefaultDevice::DigitalOtherOut:
        return "dig-out";
    case HdaDefaultDevice::ModemLineSide:
        return "modem-line";
    case HdaDefaultDevice::ModemHandsetSide:
        return "modem-handset";
    case HdaDefaultDevice::LineIn:
        return "line-in";
    case HdaDefaultDevice::Aux:
        return "aux";
    case HdaDefaultDevice::MicIn:
        return "mic-in";
    case HdaDefaultDevice::Telephony:
        return "telephony";
    case HdaDefaultDevice::SpdifIn:
        return "spdif-in";
    case HdaDefaultDevice::DigitalOtherIn:
        return "dig-in";
    case HdaDefaultDevice::Reserved:
        return "reserved";
    case HdaDefaultDevice::Other:
        return "other";
    }
    return "?";
}

const char* HdaConnectionTypeTag(HdaConnectionType c)
{
    switch (c)
    {
    case HdaConnectionType::Unknown:
        return "unknown";
    case HdaConnectionType::OneEighthInch:
        return "1/8\"";
    case HdaConnectionType::OneQuarterInch:
        return "1/4\"";
    case HdaConnectionType::AtapiInternal:
        return "atapi";
    case HdaConnectionType::Rca:
        return "rca";
    case HdaConnectionType::Optical:
        return "optical";
    case HdaConnectionType::OtherDigital:
        return "other-dig";
    case HdaConnectionType::OtherAnalog:
        return "other-ana";
    case HdaConnectionType::MultichannelAnalogDin:
        return "din";
    case HdaConnectionType::Xlr:
        return "xlr";
    case HdaConnectionType::Rj11:
        return "rj-11";
    case HdaConnectionType::Combination:
        return "combo";
    case HdaConnectionType::Other:
        return "other";
    }
    return "?";
}

const char* HdaJackColorTag(HdaJackColor c)
{
    switch (c)
    {
    case HdaJackColor::Unknown:
        return "unknown";
    case HdaJackColor::Black:
        return "black";
    case HdaJackColor::Grey:
        return "grey";
    case HdaJackColor::Blue:
        return "blue";
    case HdaJackColor::Green:
        return "green";
    case HdaJackColor::Red:
        return "red";
    case HdaJackColor::Orange:
        return "orange";
    case HdaJackColor::Yellow:
        return "yellow";
    case HdaJackColor::Purple:
        return "purple";
    case HdaJackColor::Pink:
        return "pink";
    case HdaJackColor::White:
        return "white";
    case HdaJackColor::Other:
        return "other";
    }
    return "?";
}

const char* HdaPortConnectivityTag(HdaPortConnectivity p)
{
    switch (p)
    {
    case HdaPortConnectivity::Jack:
        return "jack";
    case HdaPortConnectivity::NoPhysicalConn:
        return "no-conn";
    case HdaPortConnectivity::FixedFunction:
        return "internal";
    case HdaPortConnectivity::JackAndInternal:
        return "jack+internal";
    }
    return "?";
}

namespace
{

const char* LocationGrossTag(u8 g)
{
    switch (g)
    {
    case 0:
        return "ext";
    case 1:
        return "int";
    case 2:
        return "sep";
    case 3:
        return "?gross";
    }
    return "?";
}

const char* LocationGeometricTag(u8 g)
{
    switch (g)
    {
    case 0x0:
        return "na";
    case 0x1:
        return "rear";
    case 0x2:
        return "front";
    case 0x3:
        return "left";
    case 0x4:
        return "right";
    case 0x5:
        return "top";
    case 0x6:
        return "bottom";
    case 0x7:
        return "special";
    case 0xA:
        return "lid";
    case 0xB:
        return "riser";
    case 0xF:
        return "other";
    }
    return "?";
}

} // namespace

void HdaPinConfigDefaultLog(u8 codec, u8 pin_node, const HdaPinConfigDefault& cfg)
{
    arch::SerialWrite("[hda-jack] codec=");
    arch::SerialWriteHex(codec);
    arch::SerialWrite(" pin=");
    arch::SerialWriteHex(pin_node);
    arch::SerialWrite(" raw=");
    arch::SerialWriteHex(cfg.raw);
    arch::SerialWrite(" port=");
    arch::SerialWrite(HdaPortConnectivityTag(cfg.port_connectivity));
    arch::SerialWrite(" loc=");
    arch::SerialWrite(LocationGrossTag(cfg.location_gross));
    arch::SerialWrite("/");
    arch::SerialWrite(LocationGeometricTag(cfg.location_geometric));
    arch::SerialWrite(" device=");
    arch::SerialWrite(HdaDefaultDeviceTag(cfg.default_device));
    arch::SerialWrite(" conn=");
    arch::SerialWrite(HdaConnectionTypeTag(cfg.connection_type));
    arch::SerialWrite(" color=");
    arch::SerialWrite(HdaJackColorTag(cfg.color));
    arch::SerialWrite(" assoc=");
    arch::SerialWriteHex(cfg.default_association);
    arch::SerialWrite(" seq=");
    arch::SerialWriteHex(cfg.sequence);
    arch::SerialWrite("\n");
}

void HdaJackSelfTest()
{
    // Build five canonical configs from the published HDA "Codec
    // Vendor Implementation Notes" examples:
    //
    //   1. Rear green 1/8" line-out, association 1, seq 0
    //      port_conn=jack(0), loc=ext/rear (0/1), device=line_out (0),
    //      conn=1/8" (1), color=green (4), assoc=1, seq=0
    //      = (0<<30) | (0<<28) | (1<<24) | (0<<20) | (1<<16) | (4<<12)
    //        | (0<<8) | (1<<4) | 0 = 0x01014010
    //   2. Internal speaker, fixed function
    //      port=fixed(2)=0x80000000, loc=int/na, device=speaker(1)
    //      = 0x80000000 | (1<<28)=0x10000000 | (0<<24) | (1<<20)
    //        | (0<<16) | (0<<12) | (1<<4) = 0x90100010
    //   3. Front pink 1/8" mic-in
    //      port=jack(0), loc=ext/front (0/2), device=mic_in (A),
    //      conn=1/8" (1), color=pink (9), assoc=2, seq=0
    //      = 0x02A19020
    //   4. S/PDIF optical out, rear, no color
    //      port=jack(0), loc=ext/rear (0/1), device=spdif_out (4),
    //      conn=optical (5), color=unknown (0), assoc=3, seq=0
    //      = 0x01450030
    //   5. No physical connection pin (codec exposes pin but board
    //      didn't wire it). port_conn=no_conn(1)
    //      = 0x40000000
    //
    // Hand-derive each, then run the decoder.
    {
        const u32 raw = 0x01014010u;
        const HdaPinConfigDefault c = HdaDecodePinConfigDefault(raw);
        Eq(static_cast<u64>(c.port_connectivity), 0, "rear-green port_conn");
        Eq(c.location_gross, 0, "rear-green loc gross");
        Eq(c.location_geometric, 0x1, "rear-green loc geo");
        Eq(static_cast<u64>(c.default_device), static_cast<u64>(HdaDefaultDevice::LineOut),
           "rear-green default_device");
        Eq(static_cast<u64>(c.connection_type), static_cast<u64>(HdaConnectionType::OneEighthInch),
           "rear-green conn_type");
        Eq(static_cast<u64>(c.color), static_cast<u64>(HdaJackColor::Green), "rear-green color");
        Eq(c.default_association, 0x1, "rear-green assoc");
        Eq(c.sequence, 0x0, "rear-green seq");
        Eq(u64(c.jack_detect_override ? 1 : 0), 0, "rear-green override");
        Eq(c.raw, raw, "rear-green raw");
    }
    {
        const u32 raw = 0x90100010u;
        const HdaPinConfigDefault c = HdaDecodePinConfigDefault(raw);
        Eq(static_cast<u64>(c.port_connectivity), static_cast<u64>(HdaPortConnectivity::FixedFunction),
           "internal-speaker port_conn");
        Eq(c.location_gross, 1, "internal-speaker gross");
        Eq(static_cast<u64>(c.default_device), static_cast<u64>(HdaDefaultDevice::Speaker),
           "internal-speaker default_device");
        Eq(static_cast<u64>(c.color), static_cast<u64>(HdaJackColor::Unknown), "internal-speaker color");
        Eq(c.default_association, 0x1, "internal-speaker assoc");
    }
    {
        const u32 raw = 0x02A19020u;
        const HdaPinConfigDefault c = HdaDecodePinConfigDefault(raw);
        Eq(c.location_geometric, 0x2, "front-mic loc geo=front");
        Eq(static_cast<u64>(c.default_device), static_cast<u64>(HdaDefaultDevice::MicIn), "front-mic default_device");
        Eq(static_cast<u64>(c.connection_type), static_cast<u64>(HdaConnectionType::OneEighthInch), "front-mic conn");
        Eq(static_cast<u64>(c.color), static_cast<u64>(HdaJackColor::Pink), "front-mic color");
        Eq(c.default_association, 0x2, "front-mic assoc");
    }
    {
        const u32 raw = 0x01450030u;
        const HdaPinConfigDefault c = HdaDecodePinConfigDefault(raw);
        Eq(static_cast<u64>(c.default_device), static_cast<u64>(HdaDefaultDevice::SpdifOut),
           "spdif-out default_device");
        Eq(static_cast<u64>(c.connection_type), static_cast<u64>(HdaConnectionType::Optical), "spdif-out conn=optical");
        Eq(c.default_association, 0x3, "spdif-out assoc");
    }
    {
        const u32 raw = 0x40000000u;
        const HdaPinConfigDefault c = HdaDecodePinConfigDefault(raw);
        Eq(static_cast<u64>(c.port_connectivity), static_cast<u64>(HdaPortConnectivity::NoPhysicalConn),
           "noconn port_conn");
        Eq(c.default_association, 0, "noconn assoc");
        Eq(c.sequence, 0, "noconn seq");
    }

    // Jack-presence accessor — bit 31 of GET_PIN_SENSE response.
    Eq(u64(HdaJackPresent(0x80000000u) ? 1 : 0), 1, "jack-present hi-bit set");
    Eq(u64(HdaJackPresent(0x7FFFFFFFu) ? 1 : 0), 0, "jack-present hi-bit clear");

    // Tag-table round-trip on the entries operators actually see.
    // We compare by pointer-not-equal-null and content equality
    // through the Eq() string-checker pattern in msc_scsi if needed,
    // but a simple length probe is enough — every tag function above
    // returns a non-empty literal and a "?" fallback only on enum
    // values outside the spec.
    Eq(u64(HdaDefaultDeviceTag(HdaDefaultDevice::Speaker)[0]), u64('s'), "tag speaker[0]");
    Eq(u64(HdaConnectionTypeTag(HdaConnectionType::Optical)[0]), u64('o'), "tag optical[0]");
    Eq(u64(HdaJackColorTag(HdaJackColor::Green)[0]), u64('g'), "tag green[0]");
    Eq(u64(HdaPortConnectivityTag(HdaPortConnectivity::Jack)[0]), u64('j'), "tag jack[0]");

    arch::SerialWrite("[hda-jack] selftest pass\n");
}

} // namespace duetos::drivers::audio::hda
