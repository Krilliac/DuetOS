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

    arch::SerialWrite("[msc-selftest] PASS (CBW build + CSW parse + INQUIRY + READ CAPACITY)\n");
}

} // namespace duetos::drivers::usb::msc
