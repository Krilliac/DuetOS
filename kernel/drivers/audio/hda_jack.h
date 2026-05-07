#pragma once

#include "util/types.h"

/*
 * DuetOS — HDA pin-widget configuration-default + jack-detect
 * decoder, v0.
 *
 * Every HDA pin-complex widget exposes a 32-bit "Configuration
 * Default" register whose bytewise layout is fixed by Intel's
 * High-Definition Audio specification §7.3.3.31. The integrator
 * (laptop / motherboard vendor) programs this dword to describe
 * the *physical* jack the pin is wired to: where it lives on the
 * chassis, what it's coloured, what kind of connector it is, and
 * which internal device it drives by default (speaker, headphone,
 * line-in, microphone, S/PDIF, ...).
 *
 * The OS uses it to:
 *   - render a friendly inventory ("rear green 1/8\" line-out")
 *   - choose which pin to drive when an operator says "play to
 *     headphones" (the headphone-out pin is whatever pin's
 *     default-device == 0x2)
 *   - filter "no physical connection" pins from the jack picker
 *
 * Pin-sense (jack-presence-detect) lives in a separate verb
 * (GET_PIN_SENSE = 0xF09). The response's bit 31 is "jack
 * present" — every modern codec implements this. We expose a tiny
 * accessor for the bit so a future jack-event handler doesn't
 * re-derive it.
 *
 * This module is freestanding. The decoder takes a 32-bit dword
 * and a pin index; the inventory walker does NOT live here —
 * `hda.cpp` will call it once per pin during codec walk to
 * populate a kernel-owned table. v0 ships only the decoder + log
 * helper + self-test; the inventory wiring is a follow-up that
 * needs the HDA controller online to produce real values.
 *
 * Threading: pure functions. No global state. Safe from any
 * context.
 *
 * Reference: Intel HDA Spec rev 1.0a, §7.3.3.31 (Pin Default
 * Configuration), §7.3.3.15 (Pin Sense).
 */

namespace duetos::drivers::audio::hda
{

inline constexpr u32 kHdaVerbGetConfigDefault = 0xF1C;
inline constexpr u32 kHdaVerbGetPinSense = 0xF09;
inline constexpr u32 kHdaPinSensePresentBit = 1u << 31;

// Port-Connectivity values (bits[31:30] of CONFIG_DEFAULT).
enum class HdaPortConnectivity : u8
{
    Jack = 0x0,           // physical connector
    NoPhysicalConn = 0x1, // pin not wired to anything
    FixedFunction = 0x2,  // internal speaker / mic
    JackAndInternal = 0x3,
};

// Default-Device values (bits[23:20]).
enum class HdaDefaultDevice : u8
{
    LineOut = 0x0,
    Speaker = 0x1,
    HpOut = 0x2,
    Cd = 0x3,
    SpdifOut = 0x4,
    DigitalOtherOut = 0x5,
    ModemLineSide = 0x6,
    ModemHandsetSide = 0x7,
    LineIn = 0x8,
    Aux = 0x9,
    MicIn = 0xA,
    Telephony = 0xB,
    SpdifIn = 0xC,
    DigitalOtherIn = 0xD,
    Reserved = 0xE,
    Other = 0xF,
};

// Connection-Type values (bits[19:16]).
enum class HdaConnectionType : u8
{
    Unknown = 0x0,
    OneEighthInch = 0x1, // 3.5 mm stereo / mono
    OneQuarterInch = 0x2,
    AtapiInternal = 0x3,
    Rca = 0x4,
    Optical = 0x5,
    OtherDigital = 0x6,
    OtherAnalog = 0x7,
    MultichannelAnalogDin = 0x8,
    Xlr = 0x9,
    Rj11 = 0xA,
    Combination = 0xB,
    Other = 0xF,
};

// Color values (bits[15:12]).
enum class HdaJackColor : u8
{
    Unknown = 0x0,
    Black = 0x1,
    Grey = 0x2,
    Blue = 0x3,
    Green = 0x4,
    Red = 0x5,
    Orange = 0x6,
    Yellow = 0x7,
    Purple = 0x8,
    Pink = 0x9,
    White = 0xE,
    Other = 0xF,
};

// Decoded pin Configuration Default. The wire format is a single
// 32-bit dword; this struct is the field-by-field view of it.
struct HdaPinConfigDefault
{
    u32 raw; // original dword (for diagnostics)

    HdaPortConnectivity port_connectivity;
    HdaDefaultDevice default_device;
    HdaConnectionType connection_type;
    HdaJackColor color;

    // Gross location (bits[29:28]):
    //   0=external_chassis 1=internal 2=separate 3=other
    // Geometric location (bits[27:24]):
    //   0=na 1=rear 2=front 3=left 4=right 5=top 6=bottom 7=special
    //   0xA=internal_lid 0xB=internal_riser 0xF=other
    u8 location_gross;
    u8 location_geometric;

    // Default Association (bits[7:4]) and Sequence (bits[3:0]).
    // Pins with the same association group are part of the same
    // jack panel; sequence orders them within the group. Used by
    // codec firmware to know that, say, the front 3.5-mm green and
    // pink jacks share one ground.
    u8 default_association;
    u8 sequence;

    // Misc bit 0 — jack-detect override (bits[11:8]).
    bool jack_detect_override;
};

/// Decode a CONFIG_DEFAULT dword. The dword is the verb response
/// from `GET_CONFIG_DEFAULT` (0xF1C). Always succeeds — invalid
/// configurations land in their respective `*::Other` / `*::Unknown`
/// enum values.
HdaPinConfigDefault HdaDecodePinConfigDefault(u32 raw);

/// True iff the bit-31 jack-presence flag is set in a
/// `GET_PIN_SENSE` response.
inline bool HdaJackPresent(u32 pin_sense_response)
{
    return (pin_sense_response & kHdaPinSensePresentBit) != 0;
}

/// Short tag for a default-device value, suitable for serial log.
const char* HdaDefaultDeviceTag(HdaDefaultDevice d);

/// Short tag for a connection-type value, suitable for serial log.
const char* HdaConnectionTypeTag(HdaConnectionType c);

/// Short tag for a color value, suitable for serial log.
const char* HdaJackColorTag(HdaJackColor c);

/// Short tag for a port-connectivity value.
const char* HdaPortConnectivityTag(HdaPortConnectivity p);

/// Pretty-print a one-line jack inventory entry to the kernel
/// serial log. Idempotent / no allocation.
void HdaPinConfigDefaultLog(u8 codec, u8 pin_node, const HdaPinConfigDefault& cfg);

/// Boot self-test. Asserts the decoder against a handful of
/// known configurations (rear green line-out, internal speaker,
/// front pink mic, S/PDIF optical, no-physical-connection pin),
/// plus the jack-presence bit accessor and every tag table. Logs
/// `[hda-jack] selftest pass/fail` and panics on failure.
void HdaJackSelfTest();

} // namespace duetos::drivers::audio::hda
