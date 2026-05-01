#pragma once

#include "util/types.h"

/*
 * DuetOS — IEEE 802.11 frame format definitions.
 *
 * Frame structure per IEEE 802.11-2020 §9 (formerly §8 in older
 * editions). Layout is on-air bit/byte order, little-endian
 * everywhere except OUIs (which are written in standard MAC
 * notation but interpreted byte-by-byte on the wire).
 *
 *   Frame Control (2):
 *     bit 0..1   Protocol Version (always 0 today)
 *     bit 2..3   Type (00=Mgmt, 01=Ctrl, 10=Data, 11=Reserved)
 *     bit 4..7   Subtype
 *     bit 8      To DS
 *     bit 9      From DS
 *     bit 10     More Fragments
 *     bit 11     Retry
 *     bit 12     Power Management
 *     bit 13     More Data
 *     bit 14     Protected Frame
 *     bit 15     +HTC / Order
 *   Duration / ID (2)
 *   Address 1 (6)   Receiver / DA
 *   Address 2 (6)   Transmitter / SA
 *   Address 3 (6)   BSSID / DA / SA depending on To/From DS
 *   Sequence Ctrl (2)
 *   [Address 4 (6) when ToDS=1 && FromDS=1]
 *   [QoS Control (2) when QoS Data subtype]
 *   [HT Control (4) when Order/+HTC bit set]
 *   Frame Body (0..2304)
 *   FCS (4)         (usually stripped before driver hand-off)
 *
 * Information Elements (in management-frame bodies) are
 * `(u8 id, u8 length, u8 data[length])` triples back-to-back. The
 * "extension" IE space (id == 255) carries an extra `u8 ext_id`
 * that prefixes the payload — used for HE Capabilities (35),
 * HE Operation (36), HE 6 GHz Band Capabilities (59), etc.
 *
 * Threading: pure constants. No state.
 */

namespace duetos::net::wireless
{

// Frame Control type/subtype.
enum class FrameType : u8
{
    Management = 0,
    Control = 1,
    Data = 2,
    Reserved = 3,
};

enum class MgmtSubtype : u8
{
    AssocRequest = 0,
    AssocResponse = 1,
    ReassocRequest = 2,
    ReassocResponse = 3,
    ProbeRequest = 4,
    ProbeResponse = 5,
    TimingAdv = 6,
    Beacon = 8,
    Atim = 9,
    Disassoc = 10,
    Authentication = 11,
    Deauthentication = 12,
    Action = 13,
    ActionNoAck = 14,
};

// Frame Control bit positions inside the 16-bit field.
inline constexpr u16 kFcProtocolVersionMask = 0x0003;
inline constexpr u16 kFcTypeMask = 0x000C;
inline constexpr u16 kFcTypeShift = 2;
inline constexpr u16 kFcSubtypeMask = 0x00F0;
inline constexpr u16 kFcSubtypeShift = 4;
inline constexpr u16 kFcToDs = 1u << 8;
inline constexpr u16 kFcFromDs = 1u << 9;
inline constexpr u16 kFcMoreFrag = 1u << 10;
inline constexpr u16 kFcRetry = 1u << 11;
inline constexpr u16 kFcPowerMgmt = 1u << 12;
inline constexpr u16 kFcMoreData = 1u << 13;
inline constexpr u16 kFcProtected = 1u << 14;
inline constexpr u16 kFcOrder = 1u << 15;

// Capability Information field bits (in beacon / probe-response /
// assoc-request bodies).
inline constexpr u16 kCapEss = 1u << 0;
inline constexpr u16 kCapIbss = 1u << 1;
inline constexpr u16 kCapCfPollable = 1u << 2;
inline constexpr u16 kCapCfPollRequest = 1u << 3;
inline constexpr u16 kCapPrivacy = 1u << 4;
inline constexpr u16 kCapShortPreamble = 1u << 5;
inline constexpr u16 kCapPbcc = 1u << 6;
inline constexpr u16 kCapChannelAgility = 1u << 7;
inline constexpr u16 kCapSpectrumMgmt = 1u << 8;
inline constexpr u16 kCapQos = 1u << 9;
inline constexpr u16 kCapShortSlotTime = 1u << 10;
inline constexpr u16 kCapApsd = 1u << 11;
inline constexpr u16 kCapRadioMeasurement = 1u << 12;
inline constexpr u16 kCapDsssOfdm = 1u << 13;
inline constexpr u16 kCapDelayedBlockAck = 1u << 14;
inline constexpr u16 kCapImmediateBlockAck = 1u << 15;

// Information Element IDs (subset — the parser walks every ID and
// records the ones it recognises; unknown IDs increment a counter
// but don't fail the parse).
inline constexpr u8 kIeSsid = 0;
inline constexpr u8 kIeSupportedRates = 1;
inline constexpr u8 kIeFhParamSet = 2;
inline constexpr u8 kIeDsParamSet = 3;
inline constexpr u8 kIeCfParamSet = 4;
inline constexpr u8 kIeTim = 5;
inline constexpr u8 kIeIbssParamSet = 6;
inline constexpr u8 kIeCountry = 7;
inline constexpr u8 kIeRequest = 10;
inline constexpr u8 kIeBssLoad = 11;
inline constexpr u8 kIeChallengeText = 16;
inline constexpr u8 kIePowerConstraint = 32;
inline constexpr u8 kIePowerCapability = 33;
inline constexpr u8 kIeTpcRequest = 34;
inline constexpr u8 kIeTpcReport = 35;
inline constexpr u8 kIeChannelSwitch = 37;
inline constexpr u8 kIeQuiet = 40;
inline constexpr u8 kIeIbssDfs = 41;
inline constexpr u8 kIeErpInfo = 42;
inline constexpr u8 kIeHtCapabilities = 45;
inline constexpr u8 kIeRsn = 48;
inline constexpr u8 kIeExtendedSupportedRates = 50;
inline constexpr u8 kIeApChannelReport = 51;
inline constexpr u8 kIeMobilityDomain = 54;
inline constexpr u8 kIeHtOperation = 61;
inline constexpr u8 kIeRsni = 65;
inline constexpr u8 kIeMeasurementPilot = 66;
inline constexpr u8 kIeBssAvailableCapacity = 67;
inline constexpr u8 kIeMeshConfig = 113;
inline constexpr u8 kIeMeshId = 114;
inline constexpr u8 kIeExtendedCapabilities = 127;
inline constexpr u8 kIeVhtCapabilities = 191;
inline constexpr u8 kIeVhtOperation = 192;
inline constexpr u8 kIeVendorSpecific = 221;
inline constexpr u8 kIeElementIdExtension = 255;

// Element ID Extensions (when IE == kIeElementIdExtension, the
// first payload byte is one of these).
inline constexpr u8 kIeExtHeCapabilities = 35;
inline constexpr u8 kIeExtHeOperation = 36;
inline constexpr u8 kIeExtHe6GhzBandCap = 59;

// Standard 802.11 cipher / AKM OUI: 00-0F-AC.
inline constexpr u8 kRsnOui[3] = {0x00, 0x0F, 0xAC};

// Cipher suite types (last byte of a 4-byte cipher OUI).
inline constexpr u8 kCipherUseGroup = 0;
inline constexpr u8 kCipherWep40 = 1;
inline constexpr u8 kCipherTkip = 2;
inline constexpr u8 kCipherCcmp128 = 4;
inline constexpr u8 kCipherWep104 = 5;
inline constexpr u8 kCipherBipCmac128 = 6;
inline constexpr u8 kCipherGcmp128 = 8;
inline constexpr u8 kCipherGcmp256 = 9;
inline constexpr u8 kCipherCcmp256 = 10;
inline constexpr u8 kCipherBipGmac128 = 11;
inline constexpr u8 kCipherBipGmac256 = 12;
inline constexpr u8 kCipherBipCmac256 = 13;

// AKM (Authentication and Key Management) suite types.
inline constexpr u8 kAkm8021x = 1;
inline constexpr u8 kAkmPsk = 2;
inline constexpr u8 kAkmFt8021x = 3;
inline constexpr u8 kAkmFtPsk = 4;
inline constexpr u8 kAkm8021xSha256 = 5;
inline constexpr u8 kAkmPskSha256 = 6;
inline constexpr u8 kAkmTdls = 7;
inline constexpr u8 kAkmSae = 8;
inline constexpr u8 kAkmFtSae = 9;
inline constexpr u8 kAkmApPeerKey = 10;
inline constexpr u8 kAkmFils = 14;
inline constexpr u8 kAkmFt8021xSha384 = 13;
inline constexpr u8 kAkmOwe = 18;

// Minimum / maximum frame body bytes for a sane beacon. The MAC
// header alone for a beacon is 24 bytes (no Address 4, no QoS,
// no HT Control). The fixed body prefix (Timestamp + BcnInt +
// CapInfo) is 12 bytes.
inline constexpr u32 kFrameMacHeaderBytes = 24;
inline constexpr u32 kBeaconFixedBodyBytes = 8 + 2 + 2;

// Maximum SSID length per spec (32 bytes; some firmware extends
// to 36 bytes for ext-SSID but we never expose more than 32).
inline constexpr u32 kSsidMaxBytes = 32;

// Forward-declared Frame Control helpers.
inline FrameType FcType(u16 fc)
{
    return static_cast<FrameType>((fc & kFcTypeMask) >> kFcTypeShift);
}
inline u8 FcSubtype(u16 fc)
{
    return static_cast<u8>((fc & kFcSubtypeMask) >> kFcSubtypeShift);
}

} // namespace duetos::net::wireless
