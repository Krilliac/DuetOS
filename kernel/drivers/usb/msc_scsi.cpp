#include "drivers/usb/msc_scsi.h"

#include "arch/x86_64/serial.h"
#include "log/klog.h"
#include "core/panic.h"

namespace duetos::drivers::usb::msc
{

namespace
{

void ByteZero(void* dst, u64 n)
{
    auto* d = static_cast<volatile u8*>(dst);
    for (u64 i = 0; i < n; ++i)
        d[i] = 0;
}

void WriteLeU32(u8* dst, u32 v)
{
    dst[0] = u8(v);
    dst[1] = u8(v >> 8);
    dst[2] = u8(v >> 16);
    dst[3] = u8(v >> 24);
}

// SCSI CDBs store multi-byte fields BIG-endian, not little — the
// opposite convention from the CBW header. Keep them in separate
// helpers so the distinction is obvious at call sites.
void WriteBeU16(u8* dst, u16 v)
{
    dst[0] = u8(v >> 8);
    dst[1] = u8(v);
}
void WriteBeU32(u8* dst, u32 v)
{
    dst[0] = u8(v >> 24);
    dst[1] = u8(v >> 16);
    dst[2] = u8(v >> 8);
    dst[3] = u8(v);
}

u32 ReadLeU32(const u8* p)
{
    return u32(p[0]) | (u32(p[1]) << 8) | (u32(p[2]) << 16) | (u32(p[3]) << 24);
}
u32 ReadBeU32(const u8* p)
{
    return u32(p[3]) | (u32(p[2]) << 8) | (u32(p[1]) << 16) | (u32(p[0]) << 24);
}
u16 ReadBeU16(const u8* p)
{
    return u16(u16(p[0]) << 8 | p[1]);
}

// Fill the CBW header bytes 0..14; caller fills bytes 15..30 with
// the CDB.
void CbwHeader(u8* out, u32 tag, u32 data_len, u8 flags, u8 lun, u8 cb_length)
{
    ByteZero(out, kCbwSize);
    WriteLeU32(out + 0, kCbwSignature);
    WriteLeU32(out + 4, tag);
    WriteLeU32(out + 8, data_len);
    out[12] = flags;
    out[13] = lun & 0x0F;
    out[14] = cb_length & 0x1F;
}

// Trim trailing spaces from a 'n'-wide fixed-string field and
// copy to `dst` (n+1 bytes, NUL-terminated).
void CopyTrimmed(char* dst, const u8* src, u32 n)
{
    u32 end = n;
    while (end > 0 && src[end - 1] == ' ')
        --end;
    for (u32 i = 0; i < end; ++i)
        dst[i] = char(src[i]);
    dst[end] = '\0';
}

} // namespace

bool MscBuildCbwTestUnitReady(u8* out, u32 out_size, u32 tag, u8 lun)
{
    if (out == nullptr || out_size < kCbwSize)
        return false;
    CbwHeader(out, tag, /*data_len=*/0, /*flags=*/kCbwFlagIn, lun, /*cb_length=*/6);
    out[15] = kScsiTestUnitReady;
    // TUR 6-byte CDB: opcode, LUN (legacy, 0), 0, 0, 0, control.
    // All remaining bytes already zero from CbwHeader.
    return true;
}

bool MscBuildCbwInquiry(u8* out, u32 out_size, u32 tag, u8 lun, u8 alloc_len)
{
    if (out == nullptr || out_size < kCbwSize)
        return false;
    CbwHeader(out, tag, /*data_len=*/alloc_len, kCbwFlagIn, lun, /*cb_length=*/6);
    // INQUIRY 6-byte CDB:
    //   0: opcode 0x12
    //   1: EVPD (bit 0), reserved
    //   2: page code (0 for standard inquiry)
    //   3: reserved (upper), allocation length high (only for CDB16)
    //   4: allocation length
    //   5: control
    out[15] = kScsiInquiry;
    out[16] = 0;
    out[17] = 0;
    out[18] = 0;
    out[19] = alloc_len;
    out[20] = 0;
    return true;
}

bool MscBuildCbwReadCapacity10(u8* out, u32 out_size, u32 tag, u8 lun)
{
    if (out == nullptr || out_size < kCbwSize)
        return false;
    CbwHeader(out, tag, /*data_len=*/8, kCbwFlagIn, lun, /*cb_length=*/10);
    // READ CAPACITY(10) 10-byte CDB:
    //   0: opcode 0x25
    //   1..8: zero (LBA ignored when PMI=0)
    //   9: control
    out[15] = kScsiReadCapacity10;
    return true;
}

bool MscBuildCbwRead10(u8* out, u32 out_size, u32 tag, u8 lun, u32 lba, u16 num_blocks, u32 block_size)
{
    if (out == nullptr || out_size < kCbwSize)
        return false;
    if (num_blocks == 0)
        return false;
    const u64 data_len_u64 = u64(num_blocks) * u64(block_size);
    if (data_len_u64 > 0xFFFFFFFFu)
        return false;
    CbwHeader(out, tag, /*data_len=*/u32(data_len_u64), kCbwFlagIn, lun, /*cb_length=*/10);
    // READ(10) 10-byte CDB:
    //   0: opcode 0x28
    //   1: RDPROTECT/DPO/FUA/RARC/Obsolete/Obsolete (all zero for v0)
    //   2..5: BE u32 LBA
    //   6: group number (0)
    //   7..8: BE u16 transfer length (num_blocks)
    //   9: control
    out[15] = kScsiRead10;
    out[16] = 0;
    WriteBeU32(out + 17, lba);
    out[21] = 0;
    WriteBeU16(out + 22, num_blocks);
    out[24] = 0;
    return true;
}

bool MscBuildCbwRead12(u8* out, u32 out_size, u32 tag, u8 lun, u32 lba, u32 num_blocks, u32 block_size)
{
    if (out == nullptr || out_size < kCbwSize)
        return false;
    if (num_blocks == 0 || block_size == 0)
        return false;
    const u64 data_len_u64 = u64(num_blocks) * u64(block_size);
    if (data_len_u64 > 0xFFFFFFFFu)
        return false;
    CbwHeader(out, tag, /*data_len=*/u32(data_len_u64), kCbwFlagIn, lun, /*cb_length=*/12);
    // READ(12) 12-byte CDB:
    //   0:    opcode 0xA8
    //   1:    RDPROTECT/DPO/FUA/RARC (zero v0)
    //   2..5: BE u32 LBA
    //   6..9: BE u32 transfer length (num_blocks)
    //   10:   group number / streaming
    //   11:   control
    out[15] = kScsiRead12;
    out[16] = 0;
    WriteBeU32(out + 17, lba);
    WriteBeU32(out + 21, num_blocks);
    out[25] = 0;
    out[26] = 0;
    return true;
}

bool MscBuildCbwGetConfiguration(u8* out, u32 out_size, u32 tag, u8 lun, u8 request_type, u16 feature_code,
                                 u16 alloc_len)
{
    if (out == nullptr || out_size < kCbwSize)
        return false;
    if (request_type > kGetCfgRtOne)
        return false;
    CbwHeader(out, tag, /*data_len=*/alloc_len, kCbwFlagIn, lun, /*cb_length=*/10);
    // GET CONFIGURATION 10-byte CDB (MMC-6 §6.6):
    //   0:    opcode 0x46
    //   1:    RT[1:0] in low bits — request type
    //   2..3: BE u16 starting feature
    //   4..6: reserved
    //   7..8: BE u16 allocation length
    //   9:    control
    out[15] = kScsiGetConfiguration;
    out[16] = u8(request_type & 0x03);
    WriteBeU16(out + 17, feature_code);
    out[19] = 0;
    out[20] = 0;
    out[21] = 0;
    WriteBeU16(out + 22, alloc_len);
    out[24] = 0;
    return true;
}

bool MscBuildCbwReadTocPmaAtip(u8* out, u32 out_size, u32 tag, u8 lun, u8 format, bool msf, u8 starting_track,
                               u16 alloc_len)
{
    if (out == nullptr || out_size < kCbwSize)
        return false;
    if (format > 0x05)
        return false;
    CbwHeader(out, tag, /*data_len=*/alloc_len, kCbwFlagIn, lun, /*cb_length=*/10);
    // READ TOC/PMA/ATIP 10-byte CDB (MMC-6 §6.27):
    //   0:    opcode 0x43
    //   1:    bit 1 = MSF (else LBA addressing)
    //   2:    format (low 4 bits)
    //   3..5: reserved
    //   6:    starting track / session number
    //   7..8: BE u16 allocation length
    //   9:    control
    out[15] = kScsiReadTocPmaAtip;
    out[16] = msf ? u8(1u << 1) : 0;
    out[17] = u8(format & 0x0F);
    out[18] = 0;
    out[19] = 0;
    out[20] = 0;
    out[21] = starting_track;
    WriteBeU16(out + 22, alloc_len);
    out[24] = 0;
    return true;
}

bool MscBuildCbwReadDiscInformation(u8* out, u32 out_size, u32 tag, u8 lun, u8 data_type, u16 alloc_len)
{
    if (out == nullptr || out_size < kCbwSize)
        return false;
    if (data_type > 0x02)
        return false;
    CbwHeader(out, tag, /*data_len=*/alloc_len, kCbwFlagIn, lun, /*cb_length=*/10);
    // READ DISC INFORMATION 10-byte CDB (MMC-6 §6.22):
    //   0:    opcode 0x51
    //   1:    data type (low 3 bits)
    //   2..6: reserved
    //   7..8: BE u16 allocation length
    //   9:    control
    out[15] = kScsiReadDiscInformation;
    out[16] = u8(data_type & 0x07);
    out[17] = 0;
    out[18] = 0;
    out[19] = 0;
    out[20] = 0;
    out[21] = 0;
    WriteBeU16(out + 22, alloc_len);
    out[24] = 0;
    return true;
}

bool MscBuildCbwSynchronizeCache10(u8* out, u32 out_size, u32 tag, u8 lun, u32 lba, u16 num_blocks)
{
    if (out == nullptr || out_size < kCbwSize)
        return false;
    CbwHeader(out, tag, /*data_len=*/0, kCbwFlagOut, lun, /*cb_length=*/10);
    // SYNCHRONIZE CACHE(10) 10-byte CDB (SBC-3 §5.21):
    //   0:    opcode 0x35
    //   1:    IMMED/SYNC_NV (zero v0)
    //   2..5: BE u32 LBA
    //   6:    group number (zero)
    //   7..8: BE u16 num blocks (0 = "all blocks past LBA")
    //   9:    control
    out[15] = kScsiSynchronizeCache10;
    out[16] = 0;
    WriteBeU32(out + 17, lba);
    out[21] = 0;
    WriteBeU16(out + 22, num_blocks);
    out[24] = 0;
    return true;
}

bool MscParseCsw(const u8* buf, u32 len, Csw* out)
{
    if (out == nullptr)
        return false;
    ByteZero(out, sizeof(*out));
    if (buf == nullptr || len < kCswSize)
        return false;
    const u32 sig = ReadLeU32(buf + 0);
    out->signature_valid = (sig == kCswSignature);
    out->tag = ReadLeU32(buf + 4);
    out->data_residue = ReadLeU32(buf + 8);
    out->status = buf[12];
    return out->signature_valid;
}

bool MscParseInquiryData(const u8* buf, u32 len, InquiryData* out)
{
    if (out == nullptr || buf == nullptr || len < 36)
        return false;
    ByteZero(out, sizeof(*out));
    out->peripheral_type = u8(buf[0] & 0x1F);
    out->removable = (buf[1] & 0x80) ? 1 : 0;
    out->version = u8(buf[2] & 0x07);
    CopyTrimmed(out->vendor_id, buf + 8, 8);
    CopyTrimmed(out->product_id, buf + 16, 16);
    CopyTrimmed(out->product_rev, buf + 32, 4);
    return true;
}

bool MscParseReadCapacity10(const u8* buf, u32 len, ReadCapacity10* out)
{
    if (out == nullptr || buf == nullptr || len < 8)
        return false;
    out->last_lba = ReadBeU32(buf + 0);
    out->block_size = ReadBeU32(buf + 4);
    return true;
}

bool MscParseGetConfigHeader(const u8* buf, u32 len, GetConfigHeader* out)
{
    if (out == nullptr)
        return false;
    ByteZero(out, sizeof(*out));
    if (buf == nullptr || len < 8)
        return false;
    // GET CONFIGURATION feature header (MMC-6 §6.6.2):
    //   [0..4) BE u32 data_length (excludes itself)
    //   [4..6) reserved
    //   [6..8) BE u16 current_profile
    out->data_length = ReadBeU32(buf + 0);
    out->current_profile = u16(u16(buf[6]) << 8 | buf[7]);
    return true;
}

bool MscParseReadTocHeader(const u8* buf, u32 len, ReadTocHeader* out)
{
    if (out == nullptr)
        return false;
    ByteZero(out, sizeof(*out));
    if (buf == nullptr || len < 4)
        return false;
    // READ TOC format-0 header:
    //   [0..2) BE u16 toc_data_length (excludes itself)
    //   [2]    first track
    //   [3]    last track
    out->toc_data_length = u16(u16(buf[0]) << 8 | buf[1]);
    out->first_track = buf[2];
    out->last_track = buf[3];
    return true;
}

bool MscParseDiscInformation(const u8* buf, u32 len, DiscInformation* out)
{
    if (out == nullptr)
        return false;
    ByteZero(out, sizeof(*out));
    if (buf == nullptr || len < 12)
        return false;
    // READ DISC INFORMATION standard format (MMC-6 §6.22.3.2):
    //   [0..2) BE u16 length (excludes itself)
    //   [2]    bit[7:5] DataType, bit[4] Erasable, bit[3:2] State of last session, bit[1:0] Disc status
    //   [3]    first track on disc
    //   [4]    number of sessions (LSB)
    //   [5]    first track in last session (LSB)
    //   [6]    last track in last session (LSB)
    //   [7]    DID_V/DBC_V/URU/DAC_V/Reserved/Legacy/BG_FORMAT_STATUS
    //   [8]    disc type
    out->length = u16(u16(buf[0]) << 8 | buf[1]);
    const u8 b2 = buf[2];
    out->disc_status = u8(b2 & 0x03);
    out->state_of_last_sess = u8((b2 >> 2) & 0x03);
    out->erasable = u8((b2 >> 4) & 0x01);
    out->first_track_on_disc = buf[3];
    out->num_sessions_lsb = buf[4];
    out->first_track_in_last_session_lsb = buf[5];
    out->last_track_in_last_session_lsb = buf[6];
    out->disc_type = buf[8];
    return true;
}

const char* MscProfileTag(u16 profile)
{
    switch (profile)
    {
    case kProfileNone:
        return "none";
    case kProfileCdRom:
        return "cd-rom";
    case kProfileCdR:
        return "cd-r";
    case kProfileCdRw:
        return "cd-rw";
    case kProfileDvdRom:
        return "dvd-rom";
    case kProfileDvdR:
        return "dvd-r";
    case kProfileDvdRw:
        return "dvd-rw";
    case kProfileBdRom:
        return "bd-rom";
    case kProfileBdR:
        return "bd-r";
    case kProfileBdRe:
        return "bd-re";
    default:
        return "?";
    }
}

// ---------------------------------------------------------------
// Self-test.
// ---------------------------------------------------------------

namespace
{

void ExpectEq(u64 actual, u64 expected, const char* what)
{
    if (actual == expected)
        return;
    arch::SerialWrite("[msc-selftest] MISMATCH ");
    arch::SerialWrite(what);
    arch::SerialWrite(" actual=");
    arch::SerialWriteHex(actual);
    arch::SerialWrite(" expected=");
    arch::SerialWriteHex(expected);
    arch::SerialWrite("\n");
    core::PanicWithValue("drivers/usb/msc", "MSC/SCSI parser self-test mismatch", actual);
}

void ExpectStr(const char* actual, const char* expected, const char* what)
{
    for (u32 i = 0; actual[i] != '\0' || expected[i] != '\0'; ++i)
    {
        if (actual[i] == expected[i])
            continue;
        arch::SerialWrite("[msc-selftest] STRING MISMATCH ");
        arch::SerialWrite(what);
        arch::SerialWrite("  actual=\"");
        arch::SerialWrite(actual);
        arch::SerialWrite("\" expected=\"");
        arch::SerialWrite(expected);
        arch::SerialWrite("\"\n");
        core::PanicWithValue("drivers/usb/msc", "MSC/SCSI string self-test mismatch", 0);
    }
}

} // namespace

void MscSelfTest()
{
    KLOG_TRACE_SCOPE("drivers/usb/msc", "MscSelfTest");

    // CBW TEST UNIT READY.
    {
        u8 cbw[kCbwSize] = {};
        const bool ok = MscBuildCbwTestUnitReady(cbw, sizeof(cbw), 0xDEADBEEF, /*lun=*/0);
        ExpectEq(u64(ok), 1, "TUR build ok");
        ExpectEq(ReadLeU32(cbw + 0), kCbwSignature, "TUR signature");
        ExpectEq(ReadLeU32(cbw + 4), 0xDEADBEEF, "TUR tag");
        ExpectEq(ReadLeU32(cbw + 8), 0, "TUR data_len");
        ExpectEq(cbw[12], kCbwFlagIn, "TUR flags");
        ExpectEq(cbw[13], 0, "TUR lun");
        ExpectEq(cbw[14], 6, "TUR cb_length");
        ExpectEq(cbw[15], kScsiTestUnitReady, "TUR opcode");
    }

    // CBW INQUIRY.
    {
        u8 cbw[kCbwSize] = {};
        const bool ok = MscBuildCbwInquiry(cbw, sizeof(cbw), 0x12345678, /*lun=*/0, /*alloc=*/36);
        ExpectEq(u64(ok), 1, "INQUIRY build ok");
        ExpectEq(ReadLeU32(cbw + 8), 36, "INQUIRY data_len");
        ExpectEq(cbw[12], kCbwFlagIn, "INQUIRY flags");
        ExpectEq(cbw[14], 6, "INQUIRY cb_length");
        ExpectEq(cbw[15], kScsiInquiry, "INQUIRY opcode");
        ExpectEq(cbw[19], 36, "INQUIRY alloc length");
    }

    // CBW READ CAPACITY(10).
    {
        u8 cbw[kCbwSize] = {};
        const bool ok = MscBuildCbwReadCapacity10(cbw, sizeof(cbw), 0xAABBCCDD, /*lun=*/0);
        ExpectEq(u64(ok), 1, "RC10 build ok");
        ExpectEq(ReadLeU32(cbw + 8), 8, "RC10 data_len");
        ExpectEq(cbw[14], 10, "RC10 cb_length");
        ExpectEq(cbw[15], kScsiReadCapacity10, "RC10 opcode");
    }

    // CBW READ(10) — 4 blocks × 512 bytes starting at LBA 0x42.
    {
        u8 cbw[kCbwSize] = {};
        const bool ok = MscBuildCbwRead10(cbw, sizeof(cbw), /*tag=*/7,
                                          /*lun=*/0, /*lba=*/0x42,
                                          /*num_blocks=*/4, /*block_size=*/512);
        ExpectEq(u64(ok), 1, "R10 build ok");
        ExpectEq(ReadLeU32(cbw + 8), 4 * 512, "R10 data_len");
        ExpectEq(cbw[14], 10, "R10 cb_length");
        ExpectEq(cbw[15], kScsiRead10, "R10 opcode");
        // LBA is big-endian at bytes 17..20.
        ExpectEq(ReadBeU32(cbw + 17), 0x42, "R10 LBA");
        ExpectEq(u32(cbw[22]) << 8 | cbw[23], 4u, "R10 num_blocks");
    }

    // CSW parse.
    {
        const u8 csw_bytes[] = {
            0x55, 0x53, 0x42, 0x53, // signature "USBS"
            0x78, 0x56, 0x34, 0x12, // tag = 0x12345678
            0x00, 0x02, 0x00, 0x00, // residue = 0x200
            0x00,                   // status = PASS
        };
        Csw csw;
        const bool ok = MscParseCsw(csw_bytes, sizeof(csw_bytes), &csw);
        ExpectEq(u64(ok), 1, "CSW parse ok");
        ExpectEq(csw.tag, 0x12345678, "CSW tag");
        ExpectEq(csw.data_residue, 0x200, "CSW residue");
        ExpectEq(csw.status, kCswStatusPass, "CSW status");
        ExpectEq(u64(csw.signature_valid), 1, "CSW signature_valid");
    }

    // INQUIRY data parse — synthetic "QEMU USB-DISK 0.01" reply.
    {
        u8 data[36] = {};
        data[0] = 0x00; // direct-access peripheral device type
        data[1] = 0x80; // removable bit
        data[2] = 0x04; // SPC-2
        // Vendor "QEMU    ", product "USB-DISK        ", rev "0.01".
        const char vid[] = "QEMU    ";
        const char pid[] = "USB-DISK        ";
        const char rev[] = "0.01";
        for (u32 i = 0; i < 8; ++i)
            data[8 + i] = u8(vid[i]);
        for (u32 i = 0; i < 16; ++i)
            data[16 + i] = u8(pid[i]);
        for (u32 i = 0; i < 4; ++i)
            data[32 + i] = u8(rev[i]);

        InquiryData inq;
        const bool ok = MscParseInquiryData(data, sizeof(data), &inq);
        ExpectEq(u64(ok), 1, "INQUIRY parse ok");
        ExpectEq(inq.peripheral_type, 0, "INQUIRY peripheral_type=disk");
        ExpectEq(inq.removable, 1, "INQUIRY removable");
        ExpectStr(inq.vendor_id, "QEMU", "INQUIRY vendor");
        ExpectStr(inq.product_id, "USB-DISK", "INQUIRY product");
        ExpectStr(inq.product_rev, "0.01", "INQUIRY rev");
    }

    // READ CAPACITY(10) — 512-byte blocks, 4 KiB total (8 blocks, last LBA 7).
    {
        const u8 rc[8] = {0, 0, 0, 7, 0, 0, 2, 0};
        ReadCapacity10 out;
        const bool ok = MscParseReadCapacity10(rc, sizeof(rc), &out);
        ExpectEq(u64(ok), 1, "RC10 parse ok");
        ExpectEq(out.last_lba, 7, "RC10 last_lba");
        ExpectEq(out.block_size, 512, "RC10 block_size");
    }

    // CBW READ(12) — 4 GiB read at LBA 0x10000000, 512-byte blocks.
    {
        u8 cbw[kCbwSize] = {};
        const bool ok = MscBuildCbwRead12(cbw, sizeof(cbw), /*tag=*/0x99, /*lun=*/0, /*lba=*/0x10000000u, /*nb=*/0x800u,
                                          /*block_size=*/512);
        ExpectEq(u64(ok), 1, "READ(12) build ok");
        ExpectEq(cbw[14], 12, "READ(12) cb_length");
        ExpectEq(cbw[15], kScsiRead12, "READ(12) opcode");
        ExpectEq(ReadBeU32(cbw + 17), 0x10000000u, "READ(12) lba");
        ExpectEq(ReadBeU32(cbw + 21), 0x800u, "READ(12) nb");
        // Data length is num_blocks * block_size = 0x800 * 0x200 = 0x100000.
        ExpectEq(ReadLeU32(cbw + 8), 0x100000u, "READ(12) data_len");
    }

    // CBW READ(12) — overflow rejection (num_blocks * block_size > 4 GiB).
    {
        u8 cbw[kCbwSize] = {};
        const bool ok = MscBuildCbwRead12(cbw, sizeof(cbw), /*tag=*/1, 0, 0, /*nb=*/0x80000000u, /*block_size=*/256);
        ExpectEq(u64(ok), 0, "READ(12) overflow rejected");
    }

    // CBW GET CONFIGURATION — request-type=current, 64-byte alloc.
    {
        u8 cbw[kCbwSize] = {};
        const bool ok =
            MscBuildCbwGetConfiguration(cbw, sizeof(cbw), /*tag=*/0xC0FE, /*lun=*/0, kGetCfgRtCurrent, /*feat=*/0, 64);
        ExpectEq(u64(ok), 1, "GET CONFIG build ok");
        ExpectEq(cbw[14], 10, "GET CONFIG cb_length");
        ExpectEq(cbw[15], kScsiGetConfiguration, "GET CONFIG opcode");
        ExpectEq(cbw[16], kGetCfgRtCurrent, "GET CONFIG RT");
        ExpectEq(ReadLeU32(cbw + 8), 64, "GET CONFIG alloc length");
    }

    // GET CONFIGURATION header parse — synthesize "DVD-ROM loaded".
    {
        const u8 hdr[8] = {0, 0, 0, 0x10 /* data_length=16 */, 0, 0, 0x00, 0x10 /* profile = DVD-ROM */};
        GetConfigHeader gh;
        const bool ok = MscParseGetConfigHeader(hdr, sizeof(hdr), &gh);
        ExpectEq(u64(ok), 1, "GET CONFIG parse ok");
        ExpectEq(gh.data_length, 16, "GET CONFIG data_length");
        ExpectEq(gh.current_profile, kProfileDvdRom, "GET CONFIG profile=DVD-ROM");
    }

    // CBW READ TOC/PMA/ATIP — format=0 (TOC), MSF, starting=1, alloc=12.
    {
        u8 cbw[kCbwSize] = {};
        const bool ok = MscBuildCbwReadTocPmaAtip(cbw, sizeof(cbw), /*tag=*/2, /*lun=*/0, /*format=*/0, /*msf=*/true,
                                                  /*starting=*/1, /*alloc=*/12);
        ExpectEq(u64(ok), 1, "READ TOC build ok");
        ExpectEq(cbw[15], kScsiReadTocPmaAtip, "READ TOC opcode");
        ExpectEq(cbw[16], 0x02, "READ TOC MSF bit");
        ExpectEq(cbw[17], 0x00, "READ TOC format=0");
        ExpectEq(cbw[21], 1, "READ TOC starting track");
        ExpectEq(ReadBeU16(cbw + 22), 12, "READ TOC alloc length");
    }

    // READ TOC header parse — first track 1, last track 14.
    {
        const u8 hdr[4] = {0x00, 0x72 /* len=0x72 */, 0x01, 0x0E};
        ReadTocHeader th;
        const bool ok = MscParseReadTocHeader(hdr, sizeof(hdr), &th);
        ExpectEq(u64(ok), 1, "READ TOC parse ok");
        ExpectEq(th.toc_data_length, 0x72, "READ TOC length");
        ExpectEq(th.first_track, 1, "READ TOC first_track");
        ExpectEq(th.last_track, 14, "READ TOC last_track");
    }

    // CBW READ DISC INFORMATION.
    {
        u8 cbw[kCbwSize] = {};
        const bool ok = MscBuildCbwReadDiscInformation(cbw, sizeof(cbw), /*tag=*/3, /*lun=*/0, /*data_type=*/0,
                                                       /*alloc=*/32);
        ExpectEq(u64(ok), 1, "READ DISC INFO build ok");
        ExpectEq(cbw[15], kScsiReadDiscInformation, "READ DISC INFO opcode");
        ExpectEq(cbw[16], 0, "READ DISC INFO data_type");
        ExpectEq(ReadBeU16(cbw + 22), 32, "READ DISC INFO alloc");
    }

    // READ DISC INFORMATION parse — finalised pressed CD-ROM.
    //   length=32, byte2=0x0E (status=2 finalised, last_sess=3 complete, erasable=0)
    //   first_track_on_disc=1, num_sessions_lsb=1, first/last track in last session=1/N, disc_type=0x00 (CD-DA / CD-ROM).
    {
        u8 di[12] = {};
        di[0] = 0;
        di[1] = 32;
        di[2] = 0x0E;
        di[3] = 0x01;
        di[4] = 0x01;
        di[5] = 0x01;
        di[6] = 0x0E;
        di[8] = 0x00;
        DiscInformation d;
        const bool ok = MscParseDiscInformation(di, sizeof(di), &d);
        ExpectEq(u64(ok), 1, "DISC INFO parse ok");
        ExpectEq(d.length, 32, "DISC INFO length");
        ExpectEq(d.disc_status, 2, "DISC INFO status=finalised");
        ExpectEq(d.state_of_last_sess, 3, "DISC INFO last sess=complete");
        ExpectEq(d.erasable, 0, "DISC INFO erasable=no");
        ExpectEq(d.first_track_on_disc, 1, "DISC INFO first track");
        ExpectEq(d.num_sessions_lsb, 1, "DISC INFO sessions");
        ExpectEq(d.last_track_in_last_session_lsb, 0x0E, "DISC INFO last track in last sess");
    }

    // CBW SYNCHRONIZE CACHE(10) — flush-all (lba=0, num_blocks=0).
    {
        u8 cbw[kCbwSize] = {};
        const bool ok =
            MscBuildCbwSynchronizeCache10(cbw, sizeof(cbw), /*tag=*/4, /*lun=*/0, /*lba=*/0, /*num_blocks=*/0);
        ExpectEq(u64(ok), 1, "SYNC CACHE build ok");
        ExpectEq(cbw[12], kCbwFlagOut, "SYNC CACHE flags=OUT");
        ExpectEq(cbw[15], kScsiSynchronizeCache10, "SYNC CACHE opcode");
        ExpectEq(ReadLeU32(cbw + 8), 0, "SYNC CACHE data_len");
    }

    // Profile-tag round-trip.
    ExpectStr(MscProfileTag(kProfileCdRom), "cd-rom", "tag CD-ROM");
    ExpectStr(MscProfileTag(kProfileDvdRom), "dvd-rom", "tag DVD-ROM");
    ExpectStr(MscProfileTag(kProfileBdRom), "bd-rom", "tag BD-ROM");
    ExpectStr(MscProfileTag(0xFFFFu), "?", "tag unknown");

    arch::SerialWrite("[msc-selftest] PASS (CBW build + CSW parse + INQUIRY + READ CAPACITY + MMC/optical)\n");
}

} // namespace duetos::drivers::usb::msc
