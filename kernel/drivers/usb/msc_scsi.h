#pragma once

#include "util/types.h"

/*
 * DuetOS — USB MSC / SCSI Bulk-only transport helpers, v0.
 *
 * A USB mass-storage device speaks the "Bulk-Only Transport"
 * (BBB) wire protocol: the host sends a Command Block Wrapper
 * (CBW, 31 bytes) on the OUT bulk endpoint, optionally exchanges
 * data on one of the bulk endpoints, and finally reads a Command
 * Status Wrapper (CSW, 13 bytes) on the IN bulk endpoint. The CBW
 * carries a SCSI Command Descriptor Block (CDB).
 *
 * This module is the byte-level encoder / decoder: given a SCSI
 * opcode + parameters, build a CBW ready to hand to the host
 * controller; given a CSW, decode the device's reported status.
 * No host-controller dependency. When a real xHCI slice delivers
 * bulk transfers, MscBuildCbw / MscParseCsw are what it calls.
 *
 * Scope (v0):
 *   - Encode CBW for TEST UNIT READY, INQUIRY, READ CAPACITY(10),
 *     READ(10).
 *   - Decode a CSW and extract status + residue.
 *   - Decode an INQUIRY response (36-byte standard data) to the
 *     peripheral type + vendor/product/rev strings.
 *   - Decode a READ CAPACITY(10) response to last-LBA + block-size.
 *
 * Not in scope:
 *   - Write CDBs (WRITE(10), WRITE(16)). Read-only today.
 *   - 16-byte CDBs (READ(16) / WRITE(16)) for >2 TiB LUNs.
 *   - REQUEST SENSE (CBW-stall recovery) — needs the stall signal
 *     from the bulk transport first.
 *
 * References:
 *   - USB MSC BBB 1.0
 *   - T10 SPC-4 (INQUIRY / TUR) and SBC-3 (READ/WRITE CAPACITY)
 */

namespace duetos::drivers::usb::msc
{

inline constexpr u32 kCbwSignature = 0x43425355; // "USBC"
inline constexpr u32 kCswSignature = 0x53425355; // "USBS"
inline constexpr u32 kCbwSize = 31;
inline constexpr u32 kCswSize = 13;

// CSW status byte values.
inline constexpr u8 kCswStatusPass = 0x00;
inline constexpr u8 kCswStatusFail = 0x01;
inline constexpr u8 kCswStatusPhaseError = 0x02;

// Direction of the data phase encoded in bmCBWFlags bit 7.
inline constexpr u8 kCbwFlagIn = 0x80;
inline constexpr u8 kCbwFlagOut = 0x00;

// SCSI opcodes we build CDBs for.
inline constexpr u8 kScsiTestUnitReady = 0x00;
inline constexpr u8 kScsiInquiry = 0x12;
inline constexpr u8 kScsiReadCapacity10 = 0x25;
inline constexpr u8 kScsiRead10 = 0x28;

// MMC (optical-drive) opcodes. Built per T10 MMC-6:
//   0x43 READ TOC/PMA/ATIP  — table-of-contents probe
//   0x46 GET CONFIGURATION  — feature-set walk (CD/DVD/BD detection)
//   0x51 READ DISC INFORMATION — disc-status / session count
//   0xA8 READ(12)           — 32-bit transfer-length read
//   0x35 SYNCHRONIZE CACHE(10) — flush write cache on read-write media
inline constexpr u8 kScsiReadTocPmaAtip = 0x43;
inline constexpr u8 kScsiGetConfiguration = 0x46;
inline constexpr u8 kScsiReadDiscInformation = 0x51;
inline constexpr u8 kScsiRead12 = 0xA8;
inline constexpr u8 kScsiSynchronizeCache10 = 0x35;

// Peripheral-device types reported in INQUIRY byte 0[4:0]. The
// existing direct-access (0x00) is handled implicitly; the optical
// kinds let a caller branch on what they're talking to without
// re-deriving the table.
inline constexpr u8 kScsiPeripheralDirectAccess = 0x00; // disk
inline constexpr u8 kScsiPeripheralCdRomDvd = 0x05;     // optical drive
inline constexpr u8 kScsiPeripheralUnknown = 0x1F;

// GET CONFIGURATION request types (MMC-6 §6.6).
//   0 = "all" features regardless of current status
//   1 = features whose Current bit is set
//   2 = a specific feature (caller passes feature_code)
inline constexpr u8 kGetCfgRtAll = 0x00;
inline constexpr u8 kGetCfgRtCurrent = 0x01;
inline constexpr u8 kGetCfgRtOne = 0x02;

// Profile-list feature codes the boot probe cares about. The full
// list is in MMC-6 Table 90; we keep only the ones that actually
// flip behaviour ("which kind of media is loaded").
inline constexpr u16 kProfileNone = 0x0000;
inline constexpr u16 kProfileCdRom = 0x0008;
inline constexpr u16 kProfileCdR = 0x0009;
inline constexpr u16 kProfileCdRw = 0x000A;
inline constexpr u16 kProfileDvdRom = 0x0010;
inline constexpr u16 kProfileDvdR = 0x0011;
inline constexpr u16 kProfileDvdRw = 0x0014;
inline constexpr u16 kProfileBdRom = 0x0040;
inline constexpr u16 kProfileBdR = 0x0041;
inline constexpr u16 kProfileBdRe = 0x0043;

// Decoded CSW.
struct Csw
{
    u32 tag;
    u32 data_residue; // bytes the device didn't consume/produce
    u8 status;        // kCswStatusPass / Fail / PhaseError
    bool signature_valid;
};

// Decoded INQUIRY standard data (36 bytes input).
struct InquiryData
{
    u8 peripheral_type;  // 0 = direct-access (disk), 0x1F = unknown
    u8 removable;        // 1 if removable media
    u8 version;          // SPC version (0..7)
    char vendor_id[9];   // 8 chars + NUL
    char product_id[17]; // 16 chars + NUL
    char product_rev[5]; // 4 chars + NUL
};

// Decoded READ CAPACITY(10) response (8 bytes input).
struct ReadCapacity10
{
    u32 last_lba;   // highest addressable logical block
    u32 block_size; // bytes per logical block
};

// Decoded GET CONFIGURATION feature-header (8 bytes input — first
// 8 bytes of the response). The current-profile dword names what
// kind of media is loaded; "0" means no media. We don't walk the
// per-feature descriptor stream in v0.
struct GetConfigHeader
{
    u32 data_length;     // total response length minus this field's 4 bytes
    u16 current_profile; // kProfileCdRom / kProfileDvdRom / kProfileBdRom / 0
};

// Decoded READ TOC/PMA/ATIP "format 0" header (4 bytes input).
// Track-list rows live past byte 3; the v0 parser doesn't decode
// them, but the header gives the (first, last) track range a
// caller needs to build a follow-up read.
struct ReadTocHeader
{
    u16 toc_data_length; // bytes after this field
    u8 first_track;      // first track number on disc
    u8 last_track;       // last track number on disc
};

// Decoded READ DISC INFORMATION standard-format response
// (first 12 bytes). Captures the fields a v0 driver actually
// branches on: erasable / state-of-last-session / disc-status.
// The full response is up to 34 bytes; we ignore the trailing
// timestamp + manufacturer disc-id payload.
struct DiscInformation
{
    u16 length;             // BE u16 at offset 0
    u8 disc_status;         // 0=empty 1=incomplete 2=finalized 3=other
    u8 state_of_last_sess;  // 0=empty 1=incomplete 2=damaged 3=complete
    u8 erasable;            // bit 4 of byte 2: media is rewritable
    u8 first_track_on_disc; // byte 3
    u8 num_sessions_lsb;    // byte 4
    u8 first_track_in_last_session_lsb;
    u8 last_track_in_last_session_lsb;
    u8 disc_type; // byte 8: media type code (CD-DA, CD-ROM, …)
};

/// Build a CBW for a TEST UNIT READY probe. Zero data phase.
/// Returns false if `out` is too small (must be >= kCbwSize).
bool MscBuildCbwTestUnitReady(u8* out, u32 out_size, u32 tag, u8 lun);

/// Build a CBW for an INQUIRY probe. Data phase: device -> host,
/// caller's buffer receives `alloc_len` bytes (36 recommended for
/// standard inquiry).
bool MscBuildCbwInquiry(u8* out, u32 out_size, u32 tag, u8 lun, u8 alloc_len);

/// Build a CBW for a READ CAPACITY(10) probe. Data phase: device
/// -> host, 8 bytes.
bool MscBuildCbwReadCapacity10(u8* out, u32 out_size, u32 tag, u8 lun);

/// Build a CBW for a READ(10) data read. `lba` is the starting
/// logical block; `num_blocks` is the transfer length (in blocks).
/// `block_size` is used to compute the data-transfer-length in
/// the CBW header. Returns false on buffer too small or num_blocks
/// > 0xFFFF (the 16-bit field in the CDB).
bool MscBuildCbwRead10(u8* out, u32 out_size, u32 tag, u8 lun, u32 lba, u16 num_blocks, u32 block_size);

/// Build a CBW for a READ(12). 32-bit transfer-length variant
/// MMC drives use for sectors past the 16-bit-blocks limit. Returns
/// false on null/short buffer or `block_size==0`.
bool MscBuildCbwRead12(u8* out, u32 out_size, u32 tag, u8 lun, u32 lba, u32 num_blocks, u32 block_size);

/// Build a CBW for GET CONFIGURATION (MMC-6 §6.6). `request_type`
/// is one of `kGetCfgRtAll`/`kGetCfgRtCurrent`/`kGetCfgRtOne`;
/// when `kGetCfgRtOne`, `feature_code` is the BE u16 starting
/// feature. `alloc_len` is the IN-data buffer size (caller must
/// provide a buffer that big).
bool MscBuildCbwGetConfiguration(u8* out, u32 out_size, u32 tag, u8 lun, u8 request_type, u16 feature_code,
                                 u16 alloc_len);

/// Build a CBW for READ TOC/PMA/ATIP (MMC-6 §6.27). `format`
/// selects the response shape — 0 (TOC), 1 (multisession), 2 (raw),
/// 3 (PMA), 4 (ATIP), 5 (CD-TEXT). `msf` selects MSF or LBA
/// addressing. `alloc_len` is the IN-data buffer size.
bool MscBuildCbwReadTocPmaAtip(u8* out, u32 out_size, u32 tag, u8 lun, u8 format, bool msf, u8 starting_track,
                               u16 alloc_len);

/// Build a CBW for READ DISC INFORMATION (MMC-6 §6.22). `data_type`
/// 0 = standard, 1 = track resources, 2 = POW resources. `alloc_len`
/// is the IN-data buffer size.
bool MscBuildCbwReadDiscInformation(u8* out, u32 out_size, u32 tag, u8 lun, u8 data_type, u16 alloc_len);

/// Build a CBW for SYNCHRONIZE CACHE(10) — flush the device's
/// write cache. `lba`/`num_blocks=0` means "flush everything".
bool MscBuildCbwSynchronizeCache10(u8* out, u32 out_size, u32 tag, u8 lun, u32 lba, u16 num_blocks);

/// Parse the 13-byte CSW at `buf`. Returns true if the signature
/// matches; false on short buffer or bad signature. Always writes
/// the decoded fields into `*out` on return true.
bool MscParseCsw(const u8* buf, u32 len, Csw* out);

/// Parse a standard INQUIRY response (36 bytes). Returns true if
/// `len >= 36`. Strings are space-trimmed and NUL-terminated.
bool MscParseInquiryData(const u8* buf, u32 len, InquiryData* out);

/// Parse a READ CAPACITY(10) response (8 bytes). Returns true if
/// `len >= 8`.
bool MscParseReadCapacity10(const u8* buf, u32 len, ReadCapacity10* out);

/// Parse the first 8 bytes of a GET CONFIGURATION response (the
/// feature header). Returns true if `len >= 8`.
bool MscParseGetConfigHeader(const u8* buf, u32 len, GetConfigHeader* out);

/// Parse the 4-byte READ TOC/PMA/ATIP response header. Returns true
/// if `len >= 4`.
bool MscParseReadTocHeader(const u8* buf, u32 len, ReadTocHeader* out);

/// Parse the first 12 bytes of a READ DISC INFORMATION response
/// (standard format). Returns true if `len >= 12`.
bool MscParseDiscInformation(const u8* buf, u32 len, DiscInformation* out);

/// Map a profile code to a short tag suitable for serial logging.
/// Returns "cd-rom" / "dvd-rom" / "bd-rom" / "none" / "?".
const char* MscProfileTag(u16 profile);

/// Boot-time sanity test. Builds each CBW, verifies the on-wire
/// bytes match SPC/SBC canonical layouts, then feeds a canned CSW
/// and canned INQUIRY/READ-CAPACITY data through the parsers and
/// KASSERTs the decoded fields. PASS/FAIL line on COM1.
void MscSelfTest();

} // namespace duetos::drivers::usb::msc
