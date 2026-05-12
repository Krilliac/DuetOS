#include "drivers/net/mt76_fw.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"

namespace duetos::drivers::net
{

namespace
{

// v3 container magic. MediaTek tooling pads the leading bytes to
// 12 characters; the recognisable prefix is "__MT76__" in ASCII
// (0x5F 0x5F 0x4D 0x54 0x37 0x36 0x5F 0x5F).
constexpr u8 kMagicHdrV3[8] = {0x5F, 0x5F, 0x4D, 0x54, 0x37, 0x36, 0x5F, 0x5F};

// ROM patch magic used by the patch loader for MT7921+.
constexpr u8 kMagicRomPatch[8] = {0x4D, 0x54, 0x4B, 0x5F, 0x50, 0x41, 0x54, 0x43};

bool BytesEqual(const u8* a, const u8* b, u32 n)
{
    for (u32 i = 0; i < n; ++i)
    {
        if (a[i] != b[i])
            return false;
    }
    return true;
}

u32 ReadLe32(const u8* p)
{
    return static_cast<u32>(p[0]) | (static_cast<u32>(p[1]) << 8) | (static_cast<u32>(p[2]) << 16) |
           (static_cast<u32>(p[3]) << 24);
}

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

const char* Mt76FwFlavourName(Mt76FwFlavour f)
{
    switch (f)
    {
    case Mt76FwFlavour::HdrV3:
        return "hdr-v3";
    case Mt76FwFlavour::RomPatch:
        return "rom-patch";
    case Mt76FwFlavour::Raw:
        return "raw";
    case Mt76FwFlavour::Unknown:
    default:
        return "unknown";
    }
}

const char* Mt76FirmwareBasenameForFamily(Mt76Family family)
{
    switch (family)
    {
    case Mt76Family::Mt7615:
        return "mediatek/mt7615_n9.bin";
    case Mt76Family::Mt7663:
        return "mediatek/mt7663pr2h.bin";
    case Mt76Family::Mt7915:
        return "mediatek/mt7915_wm.bin";
    case Mt76Family::Mt7916:
        return "mediatek/mt7916_wm.bin";
    case Mt76Family::Mt7921:
        return "mediatek/WIFI_RAM_CODE_MT7961_1.bin";
    case Mt76Family::Mt7922:
        return "mediatek/WIFI_RAM_CODE_MT7922_1.bin";
    case Mt76Family::Mt7925:
        return "mediatek/mt7925/WIFI_RAM_CODE_MT7925_1_1.bin";
    case Mt76Family::Unknown:
    default:
        return nullptr;
    }
}

::duetos::core::Result<void> Mt76FirmwareParse(const u8* blob, u32 blob_size, Mt76FirmwareParsed* parsed)
{
    if (blob == nullptr || parsed == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    *parsed = {};
    if (blob_size < kMt76FwMinBytes || blob_size > kMt76FwMaxBytes)
        return ::duetos::core::Err{::duetos::core::ErrorCode::Corrupt};

    parsed->declared_size = blob_size;
    parsed->fletcher32 = Fletcher32(blob, blob_size);

    if (blob_size >= 0x18 && BytesEqual(blob, kMagicHdrV3, sizeof(kMagicHdrV3)))
    {
        parsed->flavour = Mt76FwFlavour::HdrV3;
        parsed->fw_version = ReadLe32(blob + 0x0C);
        parsed->build_date = ReadLe32(blob + 0x10);
        parsed->region_count = ReadLe32(blob + 0x14);
        // A region_count of 0 or > 64 indicates a corrupt v3 header.
        if (parsed->region_count == 0 || parsed->region_count > 64)
            return ::duetos::core::Err{::duetos::core::ErrorCode::Corrupt};
    }
    else if (BytesEqual(blob, kMagicRomPatch, sizeof(kMagicRomPatch)))
    {
        parsed->flavour = Mt76FwFlavour::RomPatch;
    }
    else
    {
        parsed->flavour = Mt76FwFlavour::Raw;
    }

    parsed->valid = true;
    return ::duetos::core::Result<void>{};
}

void Mt76FirmwareLog(const Mt76FirmwareParsed& parsed)
{
    arch::SerialWrite("[mt76-fw] flavour=");
    arch::SerialWrite(Mt76FwFlavourName(parsed.flavour));
    arch::SerialWrite(" size=");
    arch::SerialWriteHex(parsed.declared_size);
    if (parsed.flavour == Mt76FwFlavour::HdrV3)
    {
        arch::SerialWrite(" ver=");
        arch::SerialWriteHex(parsed.fw_version);
        arch::SerialWrite(" build=");
        arch::SerialWriteHex(parsed.build_date);
        arch::SerialWrite(" regions=");
        arch::SerialWriteHex(parsed.region_count);
    }
    arch::SerialWrite(" fletcher32=");
    arch::SerialWriteHex(parsed.fletcher32);
    arch::SerialWrite("\n");
}

void Mt76FirmwareSelfTest()
{
    // Build a synthetic v3 container: 8-byte magic + 4 padding +
    // version + build date + region count + minimum payload tail.
    constexpr u32 kSize = 32u * 1024;
    static u8 buf[kSize] = {};
    for (u32 i = 0; i < sizeof(kMagicHdrV3); ++i)
        buf[i] = kMagicHdrV3[i];
    // pad bytes 8..11 with zero, then write version/build/regions
    buf[0x0C] = 0x12;
    buf[0x0D] = 0x34;
    buf[0x0E] = 0x56;
    buf[0x0F] = 0x78;
    buf[0x10] = 0x01;
    buf[0x11] = 0x02;
    buf[0x12] = 0x03;
    buf[0x13] = 0x04;
    buf[0x14] = 0x02; // region_count = 2
    buf[0x15] = 0x00;
    buf[0x16] = 0x00;
    buf[0x17] = 0x00;
    // Fill payload tail with a counting pattern so Fletcher-32 is non-trivial.
    for (u32 i = 0x18; i < kSize; ++i)
        buf[i] = static_cast<u8>((i * 7u + 3u) & 0xFFu);

    Mt76FirmwareParsed parsed{};
    auto r = Mt76FirmwareParse(buf, kSize, &parsed);
    KASSERT(r.has_value(), "drivers/net/mt76_fw", "synthetic v3 blob should parse");
    KASSERT(parsed.valid, "drivers/net/mt76_fw", "synthetic v3 parsed.valid");
    KASSERT(parsed.flavour == Mt76FwFlavour::HdrV3, "drivers/net/mt76_fw", "synthetic v3 should detect HdrV3 magic");
    KASSERT(parsed.fw_version == 0x78563412u, "drivers/net/mt76_fw", "v3 version mismatch");
    KASSERT(parsed.build_date == 0x04030201u, "drivers/net/mt76_fw", "v3 build mismatch");
    KASSERT(parsed.region_count == 2u, "drivers/net/mt76_fw", "v3 region_count mismatch");

    // ROM patch magic — a synthetic blob starting with `MTK_PATC`
    // should classify as RomPatch.
    static u8 rom[16u * 1024] = {};
    for (u32 i = 0; i < sizeof(kMagicRomPatch); ++i)
        rom[i] = kMagicRomPatch[i];
    Mt76FirmwareParsed prom{};
    auto rp = Mt76FirmwareParse(rom, sizeof(rom), &prom);
    KASSERT(rp.has_value() && prom.flavour == Mt76FwFlavour::RomPatch, "drivers/net/mt76_fw",
            "synthetic ROM patch should detect RomPatch flavour");

    // Raw blob (no magic) — must be accepted as Raw, not rejected.
    static u8 raw[16u * 1024];
    for (u32 i = 0; i < sizeof(raw); ++i)
        raw[i] = static_cast<u8>(i & 0xFFu);
    Mt76FirmwareParsed praw{};
    auto rr = Mt76FirmwareParse(raw, sizeof(raw), &praw);
    KASSERT(rr.has_value() && praw.flavour == Mt76FwFlavour::Raw, "drivers/net/mt76_fw",
            "raw blob should classify as Raw, not be rejected");

    // Under-size: rejected.
    {
        u8 tiny[64] = {};
        Mt76FirmwareParsed p{};
        auto rt = Mt76FirmwareParse(tiny, sizeof(tiny), &p);
        KASSERT(!rt.has_value() && rt.error() == ::duetos::core::ErrorCode::Corrupt, "drivers/net/mt76_fw",
                "tiny blob should be rejected");
    }

    // v3 with absurd region_count: rejected.
    {
        static u8 bad[16u * 1024] = {};
        for (u32 i = 0; i < sizeof(kMagicHdrV3); ++i)
            bad[i] = kMagicHdrV3[i];
        bad[0x14] = 0xFF;
        bad[0x15] = 0xFF;
        bad[0x16] = 0xFF;
        bad[0x17] = 0xFF;
        Mt76FirmwareParsed p{};
        auto rb = Mt76FirmwareParse(bad, sizeof(bad), &p);
        KASSERT(!rb.has_value() && rb.error() == ::duetos::core::ErrorCode::Corrupt, "drivers/net/mt76_fw",
                "v3 with absurd region_count should be rejected");
    }

    // Basename mapping spot-check.
    KASSERT(Mt76FirmwareBasenameForFamily(Mt76Family::Mt7921) != nullptr, "drivers/net/mt76_fw",
            "MT7921 basename should be set");
    KASSERT(Mt76FirmwareBasenameForFamily(Mt76Family::Unknown) == nullptr, "drivers/net/mt76_fw",
            "Unknown family basename should be null");

    arch::SerialWrite("[mt76-fw] selftest pass\n");
}

} // namespace duetos::drivers::net
