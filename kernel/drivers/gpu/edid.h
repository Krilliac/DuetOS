#pragma once

#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — VESA E-EDID parser, v0.
 *
 * Clean-room implementation of the VESA Enhanced Extended Display
 * Identification Data (E-EDID) base block parser, specified in
 * VESA E-EDID Standard Release A2 (EDID 1.4) and the prior 1.3
 * release. Reference material: VESA spec, OSDev Wiki EDID page,
 * Wikipedia EDID article. No code copied from Linux drm_edid /
 * FreeBSD drm_edid / ReactOS — only the public byte-layout in the
 * spec was used.
 *
 * Scope (v0):
 *   - 128-byte base block: header / vendor identity / video input
 *     parameters / screen size / gamma / feature support /
 *     established timings / standard timings / four 18-byte
 *     descriptors (DTD or monitor descriptor) / extension count /
 *     checksum.
 *   - Manufacturer ID decode (3-letter PnP code via 5-bit ASCII).
 *   - Detailed Timing Descriptor (DTD) decode: pixel clock, active
 *     + blanking, sync offsets, sync polarity, interlace flag.
 *   - Monitor descriptor decode: 0xFF serial / 0xFE ASCII /
 *     0xFD range limits / 0xFC monitor name.
 *   - Established timing bitmap (bytes 35-37).
 *   - Standard timing slots (bytes 38-53, 8 × 2-byte entries).
 *
 * Out of scope — deferred to follow-on slices:
 *   - CEA-861 / DisplayID extension blocks (byte 126 advertises
 *     them; v0 surfaces the count but does not parse the trailing
 *     128-byte blocks).
 *   - HDMI vendor-specific data blocks (CEA-861 Sec 8 / HDMI VSDB).
 *   - DDC / I2C transport — this parser is fed bytes; getting the
 *     bytes off the wire is a per-vendor GPU driver job.
 *   - CVT / GTF timing math — we surface what the EDID stores
 *     verbatim. Synthesising new modes from CVT formulas is a
 *     separate compute layer.
 *
 * Context: kernel. Pure compute, no allocations, no IRQ, no DMA.
 * Safe to call from any process / IRQ context.
 */

namespace duetos::drivers::gpu
{

inline constexpr u64 kEdidBaseBlockBytes = 128;
inline constexpr u64 kEdidDtdBytes = 18;
inline constexpr u64 kEdidStandardTimingSlots = 8;
inline constexpr u64 kEdidDtdCount = 4;

/// Identification of every monitor descriptor block ("non-DTD"
/// shape — bytes 0-1 are zero, byte 3 carries the descriptor
/// type).
enum class EdidDescriptorKind : u8
{
    Dtd = 0x00,          // Real detailed timing (bytes 0-1 != 0)
    SerialNumber = 0xFF, // ASCII serial (bytes 5-17, NUL/LF-terminated)
    AsciiString = 0xFE,  // Free-form ASCII string
    RangeLimits = 0xFD,  // Monitor frequency range limits
    MonitorName = 0xFC,  // Friendly name ("DELL U2412M") in 5-17
    AdditionalWhite = 0xFB,
    AdditionalStdTimings = 0xFA,
    DcmData = 0xF9,
    Cvt3ByteCodes = 0xF8,
    AdditionalStdTimings3 = 0xF7,
    EstablishedTimingsIii = 0xF7, // alias used by some specs
    DcmDisplay = 0xF0,
    Dummy = 0x10,
    Unknown = 0xFE + 1, // fits in u8; sentinel
};

const char* EdidDescriptorKindName(EdidDescriptorKind k);

/// Subset of EDID feature bitmap (byte 24) we surface to callers.
struct EdidFeatures
{
    bool dpms_standby;
    bool dpms_suspend;
    bool dpms_active_off;
    bool srgb_default;
    bool preferred_timing_in_dtd1;
    bool continuous_frequency;
    /// Display type encoding (byte 24 bits 4:3). Meaning depends
    /// on whether the input is analog or digital — see
    /// EdidVideoInput.
    u8 display_type_bits;
};

/// Video input definition (byte 20).
struct EdidVideoInput
{
    bool digital;
    /// Analog: bit-encoded sync types (separate / composite / on
    /// green / serration). Digital: zero. v0 stashes the raw byte
    /// for callers that need finer detail.
    u8 raw_byte;
    /// Digital only (EDID 1.4): bit depth per primary colour.
    /// 0=undefined, 6/8/10/12/14/16 bpc. -1 for analog.
    i8 digital_bit_depth;
    /// Digital only (EDID 1.4): video interface enum.
    /// 0=undefined, 1=DVI, 2=HDMI-a, 3=HDMI-b, 4=MDDI, 5=DisplayPort.
    u8 digital_interface;
};

/// 18-byte detailed timing descriptor decoded into engineering
/// units. Hertz is computed from pixel clock + horiz/vert totals.
struct EdidDtd
{
    /// Pixel clock in kHz. 0 means "this slot is a monitor
    /// descriptor, not a timing".
    u32 pixel_clock_khz;
    u16 h_active;
    u16 h_blanking;
    u16 v_active;
    u16 v_blanking;
    u16 h_sync_offset;
    u16 h_sync_pulse;
    u16 v_sync_offset;
    u16 v_sync_pulse;
    u16 h_image_mm;
    u16 v_image_mm;
    bool interlaced;
    bool h_sync_positive; // valid only when sync_type == digital separate
    bool v_sync_positive; // ditto
    /// Sync type (byte 17 bits 4:3): 0 = analog comp, 1 = bipolar
    /// analog comp, 2 = digital composite, 3 = digital separate.
    u8 sync_type;
    /// Refresh rate in milli-hertz (Hz × 1000), computed as
    ///   pixel_clock_khz * 1_000_000 / ((h_active+h_blanking)*(v_active+v_blanking))
    /// truncated to integer. 0 if either total is zero.
    u32 refresh_mhz;
};

/// Non-DTD descriptor (monitor name / serial / range limits / ...).
struct EdidMonitorDescriptor
{
    EdidDescriptorKind kind;
    /// Bytes 5-17 of the descriptor, NUL-terminated. For
    /// MonitorName / SerialNumber / AsciiString this is the
    /// string. For RangeLimits the first 6 bytes are min v / max
    /// v / min h / max h / max pixel clock / timing standard.
    /// Other kinds: opaque payload, look at raw_payload[].
    char text[14];
    /// Range-limit fields, valid only when kind == RangeLimits.
    u8 v_min_hz;
    u8 v_max_hz;
    u8 h_min_khz;
    u8 h_max_khz;
    u16 max_pixel_clock_mhz;
    /// Raw 13-byte payload (descriptor bytes 5-17) for callers
    /// that need bit-exact access.
    u8 raw_payload[13];
};

/// One slot of the standard-timings block (bytes 38-53). Empty
/// slots are reported with width == 0.
struct EdidStandardTiming
{
    u16 width;     // active pixels
    u16 height;    // computed from aspect ratio
    u8 refresh_hz; // 60..123
    /// Aspect ratio enum (byte 1 bits 7:6):
    /// 0 = 16:10 (1.3+) / 1:1 (1.0), 1 = 4:3, 2 = 5:4, 3 = 16:9.
    u8 aspect_bits;
};

/// Established Timing bitmap (bytes 35-37) reported as bools so
/// downstream code doesn't have to memorise bit positions. Each
/// flag corresponds to a fixed VESA-defined mode — see
/// EdidEstablishedTimingName().
struct EdidEstablishedTimings
{
    // Byte 35
    bool t_720x400_70;
    bool t_720x400_88;
    bool t_640x480_60;
    bool t_640x480_67;
    bool t_640x480_72;
    bool t_640x480_75;
    bool t_800x600_56;
    bool t_800x600_60;
    // Byte 36
    bool t_800x600_72;
    bool t_800x600_75;
    bool t_832x624_75;
    bool t_1024x768_87i;
    bool t_1024x768_60;
    bool t_1024x768_70;
    bool t_1024x768_75;
    bool t_1280x1024_75;
    // Byte 37 (only bit 7 is VESA-assigned; remainder is mfg-specific)
    bool t_1152x870_75;
};

/// One descriptor slot in the four 18-byte descriptor area
/// (bytes 54-125). Either `dtd` is meaningful (kind == Dtd) or
/// `monitor_descriptor` is.
struct EdidDescriptor
{
    EdidDescriptorKind kind;
    EdidDtd dtd;
    EdidMonitorDescriptor monitor_descriptor;
};

/// Fully-decoded EDID base block.
struct EdidBaseBlock
{
    bool header_valid;    // bytes 0-7 == 00 FF FF FF FF FF FF 00
    bool checksum_valid;  // sum of all 128 bytes is 0 mod 256
    u8 stored_checksum;   // byte 127 as-read
    u8 computed_checksum; // 256 - (sum of bytes 0-126) mod 256

    char manufacturer_id[4]; // 3-letter PnP code + NUL
    u16 product_code;
    u32 serial_number;
    u8 week_of_manufacture;  // 0xFF = "model year flag"
    u16 year_of_manufacture; // 1990 + byte17, OR model year if week==0xFF
    bool model_year;         // true iff week_of_manufacture was 0xFF

    u8 edid_version;  // typically 1
    u8 edid_revision; // typically 3 or 4

    EdidVideoInput video_input;
    u8 h_image_cm; // 0 = portrait or undefined
    u8 v_image_cm; // 0 = landscape or undefined
    /// Gamma * 100 - 100; 0xFF means "use DI-EXT block". v0
    /// returns the raw byte; converting to a float is caller-side.
    u8 gamma_raw;
    EdidFeatures features;

    EdidEstablishedTimings established_timings;
    EdidStandardTiming standard_timings[kEdidStandardTimingSlots];
    EdidDescriptor descriptors[kEdidDtdCount];

    u8 extension_block_count; // byte 126
};

/// Parse a 128-byte EDID base block. Always returns a populated
/// `EdidBaseBlock`; the caller checks `header_valid` and
/// `checksum_valid` before trusting the rest. Pre-condition:
/// `data` points to at least 128 readable bytes.
::duetos::core::Result<EdidBaseBlock> EdidParseBaseBlock(const u8* data, u64 length);

/// Look up the human-readable name for an established-timing flag.
/// Index 0..16 corresponds to the EdidEstablishedTimings fields in
/// declaration order. Returns nullptr for out-of-range indices.
const char* EdidEstablishedTimingName(u32 index);

/// Compute the height implied by a standard-timing slot's aspect
/// ratio bits + the EDID major version (1.0 vs 1.3+ encode aspect
/// 00 differently). v0 assumes 1.3+.
u16 EdidStandardTimingHeight(u16 width, u8 aspect_bits);

/// Render an EdidBaseBlock into a human-readable summary on the
/// kernel console (one line per major field). Used by the
/// `monitor` shell command and by the boot self-test for visual
/// confirmation.
void EdidDumpToConsole(const EdidBaseBlock& blk);

/// Boot-time self-test: parses three known-good and three known-
/// bad fixtures, asserting on every field that matters. Compiled
/// out when `kBootSelfTests` is false.
void EdidSelfTest();

} // namespace duetos::drivers::gpu
