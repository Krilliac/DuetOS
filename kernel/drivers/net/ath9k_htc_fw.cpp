#include "drivers/net/ath9k_htc_fw.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"

namespace duetos::drivers::net
{

namespace
{

// Open-source ath9k_htc firmware sizes observed in `linux-firmware`
// over the AR9271 / AR7010 lifetime. The bands are wider than the
// canonical builds to absorb minor packaging differences (debug
// builds add a few KiB; stripped builds shave a few hundred bytes).
constexpr u32 kAr9271SizeLo = 24u * 1024;
constexpr u32 kAr9271SizeHi = 96u * 1024;
constexpr u32 kAr7010SizeLo = 56u * 1024;
constexpr u32 kAr7010SizeHi = 160u * 1024;

// Fletcher-32 over the payload, interpreting the bytes as a stream
// of little-endian u16 words (padding the tail byte with 0). Used
// for stable boot-log fingerprinting — NOT a cryptographic check;
// the SHA-256 digest in the DuetOS package envelope is the actual
// integrity gate.
u32 Fletcher32(const u8* data, u32 size)
{
    u32 sum1 = 0xFFFFu;
    u32 sum2 = 0xFFFFu;
    u32 i = 0;
    while (i + 1 < size)
    {
        const u16 word = static_cast<u16>(data[i]) | (static_cast<u16>(data[i + 1]) << 8);
        sum1 = (sum1 + word) % 0xFFFFu;
        sum2 = (sum2 + sum1) % 0xFFFFu;
        i += 2;
    }
    if (i < size)
    {
        const u16 word = static_cast<u16>(data[i]);
        sum1 = (sum1 + word) % 0xFFFFu;
        sum2 = (sum2 + sum1) % 0xFFFFu;
    }
    return (sum2 << 16) | sum1;
}

} // namespace

const char* AthHtcTargetName(AthHtcTarget target)
{
    switch (target)
    {
    case AthHtcTarget::Ar9271:
        return "ar9271";
    case AthHtcTarget::Ar7010:
        return "ar7010";
    case AthHtcTarget::Unknown:
    default:
        return "unknown";
    }
}

AthHtcTarget AthHtcTargetFromSize(u32 blob_size)
{
    if (blob_size >= kAr9271SizeLo && blob_size <= kAr9271SizeHi)
        return AthHtcTarget::Ar9271;
    if (blob_size >= kAr7010SizeLo && blob_size <= kAr7010SizeHi)
        return AthHtcTarget::Ar7010;
    return AthHtcTarget::Unknown;
}

u32 AthHtcLoadAddressForTarget(AthHtcTarget target)
{
    switch (target)
    {
    case AthHtcTarget::Ar9271:
        return kAthHtcLoadAddrAr9271;
    case AthHtcTarget::Ar7010:
        return kAthHtcLoadAddrAr7010;
    case AthHtcTarget::Unknown:
    default:
        return 0u;
    }
}

::duetos::core::Result<void> AthHtcFirmwareParse(const u8* blob, u32 blob_size, AthHtcFirmwareParsed* parsed)
{
    if (blob == nullptr || parsed == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    *parsed = {};
    if (blob_size < kAthHtcMinBytes || blob_size > kAthHtcMaxBytes)
        return ::duetos::core::Err{::duetos::core::ErrorCode::Corrupt};

    parsed->declared_size = blob_size;
    parsed->target = AthHtcTargetFromSize(blob_size);
    parsed->load_address = AthHtcLoadAddressForTarget(parsed->target);
    parsed->fletcher32 = Fletcher32(blob, blob_size);
    parsed->chunk_count = (blob_size + kAthHtcDownloadChunkBytes - 1) / kAthHtcDownloadChunkBytes;
    const u32 remainder = blob_size % kAthHtcDownloadChunkBytes;
    parsed->tail_chunk_bytes = (remainder == 0) ? kAthHtcDownloadChunkBytes : remainder;
    parsed->valid = true;
    return ::duetos::core::Result<void>{};
}

void AthHtcFirmwareLog(const AthHtcFirmwareParsed& parsed)
{
    arch::SerialWrite("[ath9k-htc-fw] target=");
    arch::SerialWrite(AthHtcTargetName(parsed.target));
    arch::SerialWrite(" size=");
    arch::SerialWriteHex(parsed.declared_size);
    arch::SerialWrite(" load_addr=");
    arch::SerialWriteHex(parsed.load_address);
    arch::SerialWrite(" chunks=");
    arch::SerialWriteHex(parsed.chunk_count);
    arch::SerialWrite(" tail=");
    arch::SerialWriteHex(parsed.tail_chunk_bytes);
    arch::SerialWrite(" fletcher32=");
    arch::SerialWriteHex(parsed.fletcher32);
    arch::SerialWrite("\n");
}

void AthHtcFirmwareSelfTest()
{
    // Synthetic AR9271-sized blob: 51 KiB filled with a counting
    // byte pattern so Fletcher-32 isn't trivially zero.
    constexpr u32 kSize = 51u * 1024;
    static u8 buf[kSize];
    for (u32 i = 0; i < kSize; ++i)
        buf[i] = static_cast<u8>((i * 31u + 7u) & 0xFFu);

    AthHtcFirmwareParsed parsed{};
    auto r = AthHtcFirmwareParse(buf, kSize, &parsed);
    KASSERT(r.has_value(), "drivers/net/ath9k_htc_fw", "synthetic AR9271 blob should parse");
    KASSERT(parsed.valid, "drivers/net/ath9k_htc_fw", "synthetic blob valid flag");
    KASSERT(parsed.target == AthHtcTarget::Ar9271, "drivers/net/ath9k_htc_fw", "synthetic size should map to AR9271");
    KASSERT(parsed.load_address == kAthHtcLoadAddrAr9271, "drivers/net/ath9k_htc_fw", "AR9271 load address mismatch");
    KASSERT(parsed.declared_size == kSize, "drivers/net/ath9k_htc_fw", "declared size mismatch");
    // 51 KiB / 4 KiB chunks = 12.75 -> 13 chunks, tail = 3 KiB.
    KASSERT(parsed.chunk_count == 13u, "drivers/net/ath9k_htc_fw", "chunk_count mismatch");
    KASSERT(parsed.tail_chunk_bytes == 3u * 1024, "drivers/net/ath9k_htc_fw", "tail_chunk_bytes mismatch");

    // AR7010-sized blob: 70 KiB. Same pattern, different band.
    constexpr u32 kSize7010 = 70u * 1024;
    static u8 buf7010[kSize7010];
    for (u32 i = 0; i < kSize7010; ++i)
        buf7010[i] = static_cast<u8>((i * 13u + 11u) & 0xFFu);
    AthHtcFirmwareParsed p7010{};
    auto r7010 = AthHtcFirmwareParse(buf7010, kSize7010, &p7010);
    KASSERT(r7010.has_value(), "drivers/net/ath9k_htc_fw", "AR7010 synthetic should parse");
    KASSERT(p7010.target == AthHtcTarget::Ar7010, "drivers/net/ath9k_htc_fw", "AR7010 size should map to AR7010");
    KASSERT(p7010.load_address == kAthHtcLoadAddrAr7010, "drivers/net/ath9k_htc_fw", "AR7010 load addr mismatch");

    // Below the minimum band — must Reject as Corrupt.
    {
        u8 small[8] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0x12, 0x34};
        AthHtcFirmwareParsed p{};
        auto rs = AthHtcFirmwareParse(small, sizeof(small), &p);
        KASSERT(!rs.has_value() && rs.error() == ::duetos::core::ErrorCode::Corrupt, "drivers/net/ath9k_htc_fw",
                "tiny blob should be rejected as Corrupt");
    }

    // Above the maximum band.
    {
        static u8 huge[kAthHtcMaxBytes + 16] = {};
        AthHtcFirmwareParsed p{};
        auto rh = AthHtcFirmwareParse(huge, sizeof(huge), &p);
        KASSERT(!rh.has_value() && rh.error() == ::duetos::core::ErrorCode::Corrupt, "drivers/net/ath9k_htc_fw",
                "over-cap blob should be rejected as Corrupt");
    }

    // Null inputs.
    {
        AthHtcFirmwareParsed p{};
        auto rn = AthHtcFirmwareParse(nullptr, 32u * 1024, &p);
        KASSERT(!rn.has_value() && rn.error() == ::duetos::core::ErrorCode::InvalidArgument, "drivers/net/ath9k_htc_fw",
                "null blob should return InvalidArgument");
    }

    // A size between the two known bands (e.g. 40 KiB) maps to
    // AR9271 because the upper band is wide; a size in no band
    // returns Unknown.
    KASSERT(AthHtcTargetFromSize(48u * 1024) == AthHtcTarget::Ar9271, "drivers/net/ath9k_htc_fw",
            "48 KiB should land in AR9271 band");
    KASSERT(AthHtcTargetFromSize(200u * 1024) == AthHtcTarget::Unknown, "drivers/net/ath9k_htc_fw",
            "200 KiB outside both bands should be Unknown");
    KASSERT(AthHtcLoadAddressForTarget(AthHtcTarget::Unknown) == 0u, "drivers/net/ath9k_htc_fw",
            "Unknown target should return load address 0");

    arch::SerialWrite("[ath9k-htc-fw] selftest pass\n");
}

} // namespace duetos::drivers::net
