#pragma once

#include "drivers/gpu/edid.h"
#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — CEA-861 EDID extension-block parser, v0.
 *
 * Clean-room implementation of the CEA-861 (a.k.a. CTA-861)
 * extension-block format, as referenced from EDID 1.4 byte 126
 * ("number of extension blocks"). Reference material:
 * CEA-861-E (HDMI 1.4) and CEA-861-F (HDMI 2.0) public specs,
 * Wikipedia "Extended Display Identification Data", VESA E-EDID
 * spec §5 (Extension Block Format). No code copied from
 * Linux drm_edid_cea.c, FreeBSD, or ReactOS.
 *
 * Scope (v0):
 *   - 128-byte block: tag + revision + DTD offset + global flags +
 *     Data Block Collection walk + 18-byte DTD list + checksum.
 *   - Data Block tags 1 (Audio) / 2 (Video) / 3 (Vendor-Specific,
 *     including HDMI VSDB OUI 0x000C03) / 4 (Speaker Allocation) /
 *     7 (Extended).
 *   - Extended-tag entries: HDR Static Metadata, Colorimetry.
 *   - Short Video Descriptor (SVD) → VIC enum + native flag.
 *   - Short Audio Descriptor (SAD) → format + channels + sample
 *     rates + bit-depth/bitrate (3 bytes).
 *   - HDMI VSDB: source physical address (CEC), max TMDS clock,
 *     support flags.
 *
 * Out of scope:
 *   - HDMI Forum VSDB (OUI 0xC45DD8), HDMI 2.0 audio extensions,
 *     full SCDC (Status and Control Data Channel) parsing.
 *   - VESA DTC (Display Transfer Characteristic) data block.
 *   - Per-VIC pixel-clock+timing material — that's a CTA-861-F
 *     mode table; v0 emits the VIC number + a friendly name and
 *     leaves CVT to fill in the timings if a mode-set wants them.
 *
 * Context: kernel. Pure compute; no allocations, no IRQ.
 */

namespace duetos::drivers::gpu
{

inline constexpr u64 kCea861BlockBytes = 128;
inline constexpr u64 kCea861MaxVics = 16;
inline constexpr u64 kCea861MaxSads = 8;
inline constexpr u64 kCea861MaxDtds = 6;

/// Data Block Collection tag values (CEA-861 §7.5).
enum class CeaTag : u8
{
    Audio = 1,
    Video = 2,
    VendorSpecific = 3,
    SpeakerAllocation = 4,
    VesaDtc = 5,
    Extended = 7,
};

/// Extended-tag values (CEA-861-F §7.5.6+).
enum class CeaExtendedTag : u8
{
    VideoCapability = 0,
    VendorSpecificVideo = 1,
    Colorimetry = 5,
    HdrStaticMetadata = 6,
    HdrDynamicMetadata = 7,
    YcbcrQuantization = 0x0F,
    Unknown = 0xFF,
};

/// Audio format codes (CEA-861 §7.5.2).
enum class CeaAudioFormat : u8
{
    Reserved = 0,
    Lpcm = 1,
    Ac3 = 2,
    Mpeg1 = 3,
    Mp3 = 4,
    Mpeg2 = 5,
    AacLc = 6,
    Dts = 7,
    Atrac = 8,
    OneBitAudio = 9,
    Eac3 = 10,
    DtsHd = 11,
    MatMlp = 12,
    Dst = 13,
    WmaPro = 14,
    Extended = 15,
};

const char* CeaAudioFormatName(CeaAudioFormat f);

/// Short Video Descriptor (1 byte). Top bit = native indicator,
/// bottom 7 bits = VIC (Video Identification Code).
struct CeaSvd
{
    u8 vic;
    bool native;
};

/// Short Audio Descriptor (3 bytes).
struct CeaSad
{
    CeaAudioFormat format;
    u8 channels;          // 1..8
    u8 sample_rate_flags; // bit i set = the i-th rate (32/44.1/48/88.2/96/176.4/192 kHz)
    /// LPCM: bits 0..2 = 16/20/24-bit support flags. Other formats:
    /// max bitrate / 8 kbit/s, scaled to a u8 directly.
    u8 byte2;
};

/// HDMI VSDB (OUI 0x000C03). Subset captured.
struct HdmiVsdb
{
    bool present;
    u16 source_physical_address; // CEC (a.b.c.d packed)
    u8 max_tmds_clock_5mhz;      // multiply by 5 to get MHz
    u8 support_flags;            // dvi-dual / Y'Cb'Cr / 30/36/48-bit, etc.
    u8 audio_latency_ms;
    u8 video_latency_ms;
};

/// HDR Static Metadata (CEA-861.3, extended tag 6).
struct HdrStaticMetadata
{
    bool present;
    u8 eotf_supported_bitmap;        // bit 0 = SDR, 1 = HDR-HLG, 2 = HDR-PQ (ST 2084)
    u8 metadata_descriptor_bitmap;   // bit 0 = static-metadata-type1
    u8 max_luminance_code;           // 0..255, decode via HDR formula
    u8 max_frame_avg_luminance_code; // ditto
    u8 min_luminance_code;           // ditto
};

/// Colorimetry (CEA-861.3, extended tag 5).
struct CeaColorimetry
{
    bool present;
    u16 supported_bitmap; // bit 0 = xvYCC601, 1 = xvYCC709, 4 = BT.2020 cYCC, 5 = BT.2020 YCC, 6 = BT.2020 RGB, etc.
    u8 metadata_bitmap;
};

/// Speaker Allocation (CEA-861 §7.5.3).
struct CeaSpeakerAllocation
{
    bool present;
    u8 layout_byte;
    bool fl_fr;
    bool lfe;
    bool fc;
    bool rl_rr;
    bool rc;
    bool flc_frc;
    bool rlc_rrc;
    bool flw_frw;
};

/// Top-level decoded extension-block payload.
struct Cea861ExtBlock
{
    bool tag_valid; // byte 0 == 0x02
    bool checksum_valid;
    u8 stored_checksum;
    u8 computed_checksum;

    u8 revision;
    u8 dtd_start_offset; // byte 2; 0 = no DTDs in this block
    bool supports_underscan;
    bool supports_audio;
    bool supports_ycbcr_444;
    bool supports_ycbcr_422;
    u8 native_dtd_count; // byte 3 bits 3:0

    u32 vid_count;
    CeaSvd vids[kCea861MaxVics];

    u32 aud_count;
    CeaSad auds[kCea861MaxSads];

    CeaSpeakerAllocation speaker_allocation;
    HdmiVsdb hdmi;
    HdrStaticMetadata hdr_static;
    CeaColorimetry colorimetry;

    u32 dtd_count;
    EdidDtd dtds[kCea861MaxDtds];

    /// Byte offset within the input buffer where parsing stopped
    /// (helpful for diagnostics on a malformed DBC).
    u8 parse_end_offset;
};

/// Parse a 128-byte CEA-861 extension block.
::duetos::core::Result<Cea861ExtBlock> Cea861ParseBlock(const u8* data, u64 length);

/// Look up the human-readable name for a CEA VIC. Covers VIC 1..64
/// (CEA-861-E era). Out-of-range or unknown VICs return "vic-N"
/// formatted into the supplied scratch buffer (16 bytes).
const char* CeaVicName(u8 vic, char scratch[16]);

/// Render decoded fields onto the kernel console.
void Cea861DumpToConsole(const Cea861ExtBlock& blk);

/// Boot-time self-test: parses one positive fixture (HDMI 2.0
/// monitor with 6 VICs / 2 SADs / HDMI VSDB / HDR static-metadata)
/// and one bad-checksum case.
void Cea861SelfTest();

} // namespace duetos::drivers::gpu
