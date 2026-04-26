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

/// Boot-time sanity test. Builds each CBW, verifies the on-wire
/// bytes match SPC/SBC canonical layouts, then feeds a canned CSW
/// and canned INQUIRY/READ-CAPACITY data through the parsers and
/// KASSERTs the decoded fields. PASS/FAIL line on COM1.
void MscSelfTest();

} // namespace duetos::drivers::usb::msc
