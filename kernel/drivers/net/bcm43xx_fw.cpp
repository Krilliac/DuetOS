#include "drivers/net/bcm43xx_fw.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"

namespace duetos::drivers::net
{

namespace
{

// Big-endian dword read at byte offset `off` of `buf`. b43 headers
// are documented as big-endian (Broadcom's ARM-side firmware tools
// emit them that way regardless of host endianness).
u32 ReadBe32(const u8* buf, u32 off)
{
    return (static_cast<u32>(buf[off]) << 24) | (static_cast<u32>(buf[off + 1]) << 16) |
           (static_cast<u32>(buf[off + 2]) << 8) | static_cast<u32>(buf[off + 3]);
}

void WriteBe32(u8* buf, u32 off, u32 v)
{
    buf[off] = static_cast<u8>((v >> 24) & 0xFF);
    buf[off + 1] = static_cast<u8>((v >> 16) & 0xFF);
    buf[off + 2] = static_cast<u8>((v >> 8) & 0xFF);
    buf[off + 3] = static_cast<u8>(v & 0xFF);
}

bool RecognisedRecordType(u8 t)
{
    return t == kB43FwTypeUcode || t == kB43FwTypePcm || t == kB43FwTypeIv;
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
    if (blob == nullptr || parsed == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    *parsed = {};
    if (blob_size < kB43FwRecordHeaderBytes)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};

    // First byte must be a recognised record type. b43 blobs
    // never start with anything else; an out-of-range byte here is
    // the cleanest "this isn't a b43 blob" signal we can give.
    if (!RecognisedRecordType(blob[0]))
        return ::duetos::core::Err{::duetos::core::ErrorCode::Corrupt};

    u32 off = 0;
    while (off + kB43FwRecordHeaderBytes <= blob_size)
    {
        const u8 type = blob[off];
        const u8 version = blob[off + 1];
        // bytes [off+2 .. off+4) are reserved (be16); ignored.
        const u32 size = ReadBe32(blob, off + 4);
        const u32 payload_off = off + kB43FwRecordHeaderBytes;

        // Bounds + type check. A record whose size pushes past the
        // blob is fatal — we truncate the parse but still report
        // any earlier records that walked cleanly.
        if (size > blob_size || payload_off + size > blob_size)
        {
            parsed->truncated = true;
            break;
        }
        if (!RecognisedRecordType(type))
        {
            // An unrecognised record TYPE in the middle of an
            // otherwise valid stream is a stop signal — Broadcom
            // docs do not define new types and we don't want to
            // walk garbage. Mark truncated and stop.
            parsed->truncated = true;
            break;
        }

        if (parsed->record_count < kBcmMaxRecords)
        {
            BcmFwRecord& r = parsed->records[parsed->record_count];
            r.type = type;
            r.version = version;
            r.size = size;
            r.payload = blob + payload_off;
            ++parsed->record_count;
        }
        else
        {
            ++parsed->dropped_records;
        }

        off = payload_off + size;
    }

    parsed->walked_bytes = off;

    // Convenience pointers.
    for (u32 i = 0; i < parsed->record_count; ++i)
    {
        const BcmFwRecord* r = &parsed->records[i];
        if (r->type == kB43FwTypeUcode && parsed->ucode == nullptr)
            parsed->ucode = r;
        else if (r->type == kB43FwTypePcm && parsed->pcm == nullptr)
            parsed->pcm = r;
        else if (r->type == kB43FwTypeIv && parsed->iv == nullptr)
            parsed->iv = r;
    }

    parsed->valid = (parsed->record_count > 0);
    if (!parsed->valid)
        return ::duetos::core::Err{::duetos::core::ErrorCode::Corrupt};
    return ::duetos::core::Result<void>{};
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
