// DuetOS USB MSC SCSI parsers C FFI — hand-written.
// Mirrors kernel/drivers/usb/msc_scsi_rust/src/lib.rs.
//
// Each parser:
//   - validates `len` against the minimum-required size for the
//     response type;
//   - zero-initialises `*out` on entry so a partial parse leaves
//     well-defined state;
//   - reads only the bounded prefix the SCSI spec defines (later
//     bytes are caller-handled).

#pragma once

#include "util/types.h"

namespace duetos::drivers::usb::msc::rust
{

// Out-structs are intentionally distinct types from the C++
// msc::InquiryData / etc. — the C++ wrapper does a field-by-field
// copy on the way out so layout drift between Rust and C++ can't
// silently break callers.
struct DuetosMscInquiryData
{
    u8 peripheral_type;
    u8 removable;
    u8 version;
    u8 vendor_id[9];
    u8 product_id[17];
    u8 product_rev[5];
};

struct DuetosMscReadCapacity10
{
    u32 last_lba;
    u32 block_size;
};

struct DuetosMscGetConfigHeader
{
    u32 data_length;
    u16 current_profile;
};

struct DuetosMscReadTocHeader
{
    u16 toc_data_length;
    u8 first_track;
    u8 last_track;
};

struct DuetosMscDiscInformation
{
    u16 length;
    u8 disc_status;
    u8 state_of_last_sess;
    u8 erasable;
    u8 first_track_on_disc;
    u8 num_sessions_lsb;
    u8 first_track_in_last_session_lsb;
    u8 last_track_in_last_session_lsb;
    u8 disc_type;
};

extern "C"
{
    /// Parse a 36-byte SPC-4 INQUIRY standard response. Strings are
    /// space-trimmed and NUL-terminated. Returns false if `len < 36`,
    /// `buf == nullptr`, or `out == nullptr`.
    bool duetos_msc_parse_inquiry(const u8* buf, usize len, DuetosMscInquiryData* out);

    /// Parse the 8-byte SBC-3 READ CAPACITY(10) response. Returns
    /// false if `len < 8`.
    bool duetos_msc_parse_read_capacity_10(const u8* buf, usize len, DuetosMscReadCapacity10* out);

    /// Parse the 8-byte MMC-6 §6.6 GET CONFIGURATION feature header.
    /// Returns false if `len < 8`.
    bool duetos_msc_parse_get_config_header(const u8* buf, usize len, DuetosMscGetConfigHeader* out);

    /// Parse the 4-byte MMC-6 §6.27 READ TOC/PMA/ATIP format-0
    /// header. Returns false if `len < 4`.
    bool duetos_msc_parse_read_toc_header(const u8* buf, usize len, DuetosMscReadTocHeader* out);

    /// Parse the first 12 bytes of an MMC-6 §6.22 READ DISC
    /// INFORMATION standard response. Returns false if `len < 12`.
    bool duetos_msc_parse_disc_information(const u8* buf, usize len, DuetosMscDiscInformation* out);
}

} // namespace duetos::drivers::usb::msc::rust
