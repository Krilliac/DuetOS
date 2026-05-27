#include "drivers/net/bcm43xx_fw.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "duetos_bcm43xx_fw.h"

namespace duetos::drivers::net
{

namespace
{

// Big-endian dword writer — only used by the self-test below to
// synthesize records. Reader + record-type recognizer moved to
// the Rust crate.
void WriteBe32(u8* buf, u32 off, u32 v)
{
    buf[off] = static_cast<u8>((v >> 24) & 0xFF);
    buf[off + 1] = static_cast<u8>((v >> 16) & 0xFF);
    buf[off + 2] = static_cast<u8>((v >> 8) & 0xFF);
    buf[off + 3] = static_cast<u8>(v & 0xFF);
}

} // namespace

const char* BcmFwTypeName(u8 type)
{
    switch (type)
    {
    case kB43FwTypeUcode:
        return "ucode";
    case kB43FwTypePcm:
        return "pcm";
    case kB43FwTypeIv:
        return "iv";
    default:
        return "unknown";
    }
}

::duetos::core::Result<void> BcmFirmwareParse(const u8* blob, u32 blob_size, BcmFirmwareParsed* parsed)
{
    // Byte parsing delegated to `duetos_bcm43xx_fw` Rust crate
    // (kernel/drivers/net/bcm43xx_fw_rust/). Untrusted firmware
    // bytes — Rust-Subsystems P1. Checked arithmetic in Rust
    // catches the next length-overflow before it becomes a
    // wild pointer.
    if (parsed == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};

    DuetosBcmFirmwareParsed rs{};
    const i32 rc = duetos_bcm43xx_fw_parse(blob, blob_size, &rs);

    *parsed = BcmFirmwareParsed{};
    parsed->valid = rs.valid;
    parsed->truncated = rs.truncated;
    parsed->record_count = rs.record_count;
    parsed->walked_bytes = rs.walked_bytes;
    parsed->dropped_records = rs.dropped_records;
    for (u32 i = 0; i < rs.record_count && i < kBcmMaxRecords; ++i)
    {
        parsed->records[i].type = rs.records[i].type;
        parsed->records[i].version = rs.records[i].version;
        parsed->records[i].size = rs.records[i].size;
        parsed->records[i].payload = rs.records[i].payload;
    }
    // Set the convenience pointers to point into THIS struct's
    // records array (not the Rust caller's, which would be a
    // dangling reference after this function returns).
    constexpr u32 kIndexNone = ~0u;
    if (rs.ucode_index != kIndexNone && rs.ucode_index < parsed->record_count)
        parsed->ucode = &parsed->records[rs.ucode_index];
    if (rs.pcm_index != kIndexNone && rs.pcm_index < parsed->record_count)
        parsed->pcm = &parsed->records[rs.pcm_index];
    if (rs.iv_index != kIndexNone && rs.iv_index < parsed->record_count)
        parsed->iv = &parsed->records[rs.iv_index];

    if (rc == 0)
        return {};
    if (rc == 1)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    return ::duetos::core::Err{::duetos::core::ErrorCode::Corrupt};
}

void BcmFirmwareLog(const BcmFirmwareParsed& parsed)
{
    arch::SerialWrite("[bcm-fw] records=");
    arch::SerialWriteHex(parsed.record_count);
    if (parsed.dropped_records != 0)
    {
        arch::SerialWrite(" dropped=");
        arch::SerialWriteHex(parsed.dropped_records);
    }
    if (parsed.truncated)
        arch::SerialWrite(" (truncated)");
    for (u32 i = 0; i < parsed.record_count; ++i)
    {
        const BcmFwRecord& r = parsed.records[i];
        arch::SerialWrite(" [");
        arch::SerialWrite(BcmFwTypeName(r.type));
        arch::SerialWrite(" ver=");
        arch::SerialWriteHex(r.version);
        arch::SerialWrite(" size=");
        arch::SerialWriteHex(r.size);
        arch::SerialWrite("]");
    }
    arch::SerialWrite("\n");
}

void BcmFirmwareSelfTest()
{
    constexpr u32 kBufBytes = 256;
    static u8 buf[kBufBytes] = {};

    // Three records: ucode (32 B), pcm (16 B), iv (8 B).
    u32 off = 0;
    auto write_record = [&](u8 type, u8 ver, u32 payload_size, u8 fill)
    {
        buf[off] = type;
        buf[off + 1] = ver;
        buf[off + 2] = 0;
        buf[off + 3] = 0;
        WriteBe32(buf, off + 4, payload_size);
        for (u32 i = 0; i < payload_size; ++i)
            buf[off + kB43FwRecordHeaderBytes + i] = fill;
        off += kB43FwRecordHeaderBytes + payload_size;
    };

    write_record(kB43FwTypeUcode, /*ver=*/1, /*size=*/32, /*fill=*/0xAA);
    write_record(kB43FwTypePcm, /*ver=*/1, /*size=*/16, /*fill=*/0xBB);
    write_record(kB43FwTypeIv, /*ver=*/1, /*size=*/8, /*fill=*/0xCC);

    BcmFirmwareParsed parsed{};
    auto r = BcmFirmwareParse(buf, off, &parsed);
    KASSERT(r.has_value(), "drivers/net/bcm43xx_fw", "bcm selftest parse error");
    KASSERT(parsed.valid, "drivers/net/bcm43xx_fw", "bcm selftest valid=false");
    KASSERT(parsed.record_count == 3u, "drivers/net/bcm43xx_fw", "bcm selftest record_count != 3");
    KASSERT(parsed.ucode != nullptr && parsed.ucode->size == 32u, "drivers/net/bcm43xx_fw",
            "bcm selftest missing ucode record");
    KASSERT(parsed.pcm != nullptr && parsed.pcm->size == 16u, "drivers/net/bcm43xx_fw",
            "bcm selftest missing pcm record");
    KASSERT(parsed.iv != nullptr && parsed.iv->size == 8u, "drivers/net/bcm43xx_fw", "bcm selftest missing iv record");
    KASSERT(parsed.ucode->payload[0] == 0xAA && parsed.ucode->payload[31] == 0xAA, "drivers/net/bcm43xx_fw",
            "bcm selftest ucode payload mismatch");
    KASSERT(!parsed.truncated, "drivers/net/bcm43xx_fw", "bcm selftest unexpected truncation");

    // Negative cases. Bad first-byte type.
    {
        u8 bad[16] = {};
        bad[0] = 0xDE;
        BcmFirmwareParsed p{};
        auto r2 = BcmFirmwareParse(bad, sizeof(bad), &p);
        KASSERT(!r2.has_value() && r2.error() == ::duetos::core::ErrorCode::Corrupt, "drivers/net/bcm43xx_fw",
                "bcm selftest bad-type should return Corrupt");
    }
    // Truncated header.
    {
        u8 small[4] = {};
        BcmFirmwareParsed p{};
        auto r3 = BcmFirmwareParse(small, sizeof(small), &p);
        KASSERT(!r3.has_value() && r3.error() == ::duetos::core::ErrorCode::InvalidArgument, "drivers/net/bcm43xx_fw",
                "bcm selftest short-header should return InvalidArgument");
    }
    // Length overflow — single record claims giant payload.
    {
        static u8 ov[64] = {};
        ov[0] = kB43FwTypeUcode;
        ov[1] = 1;
        WriteBe32(ov, 4, 0xFFFFFF00u);
        BcmFirmwareParsed p{};
        auto r4 = BcmFirmwareParse(ov, sizeof(ov), &p);
        // The first record overflows but we have no earlier records,
        // so .valid stays false → Corrupt.
        KASSERT(!r4.has_value() && r4.error() == ::duetos::core::ErrorCode::Corrupt, "drivers/net/bcm43xx_fw",
                "bcm selftest overflow-only should return Corrupt");
    }
    arch::SerialWrite("[bcm-fw] selftest pass\n");
}

} // namespace duetos::drivers::net
