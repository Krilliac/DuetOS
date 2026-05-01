#include "drivers/net/rtl88xx_fw.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"

namespace duetos::drivers::net
{

namespace
{

u16 ReadLe16(const u8* buf, u32 off)
{
    return static_cast<u16>(buf[off]) | static_cast<u16>(static_cast<u16>(buf[off + 1]) << 8);
}

u32 ReadLe32(const u8* buf, u32 off)
{
    return static_cast<u32>(buf[off]) | (static_cast<u32>(buf[off + 1]) << 8) | (static_cast<u32>(buf[off + 2]) << 16) |
           (static_cast<u32>(buf[off + 3]) << 24);
}

void WriteLe16(u8* buf, u32 off, u16 v)
{
    buf[off] = static_cast<u8>(v & 0xFF);
    buf[off + 1] = static_cast<u8>((v >> 8) & 0xFF);
}

void WriteLe32(u8* buf, u32 off, u32 v)
{
    buf[off] = static_cast<u8>(v & 0xFF);
    buf[off + 1] = static_cast<u8>((v >> 8) & 0xFF);
    buf[off + 2] = static_cast<u8>((v >> 16) & 0xFF);
    buf[off + 3] = static_cast<u8>((v >> 24) & 0xFF);
}

RtlFwGeneration ClassifySignature(u16 sig)
{
    // Wi-Fi 6E silicon (rtw89). Note: this match is overly inclusive
    // — the rtw89 family also covers some 0x88xx values via
    // the rtw89-specific naming, but those collide with rtw88's
    // signatures. For v0 we report rtw88 vs rtw89 by the
    // signature's high nibble (0x88 → rtw88, 0x88B*/8852 → rtw89).
    if (sig == kRtlSig8852a)
        return RtlFwGeneration::Rtw89;
    if (sig == kRtlSig8822b)
        return RtlFwGeneration::Rtw88;
    if (sig == kRtlSig8192c || sig == kRtlSig8192d || sig == kRtlSig8723b || sig == kRtlSig8723d ||
        sig == kRtlSig8821 || sig == kRtlSig8812 || sig == kRtlSig8814)
        return RtlFwGeneration::Rtlwifi;
    return RtlFwGeneration::Unknown;
}

} // namespace

const char* RtlFwGenerationName(RtlFwGeneration g)
{
    switch (g)
    {
    case RtlFwGeneration::Rtlwifi:
        return "rtlwifi";
    case RtlFwGeneration::Rtw88:
        return "rtw88";
    case RtlFwGeneration::Rtw89:
        return "rtw89";
    default:
        return "unknown";
    }
}

::duetos::core::Result<void> RtlFirmwareParse(const u8* blob, u32 blob_size, RtlFirmwareParsed* parsed)
{
    if (blob == nullptr || parsed == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    *parsed = {};
    if (blob_size < kRtlFwHeaderBytes)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};

    parsed->signature = ReadLe16(blob, 0x00);
    parsed->generation = ClassifySignature(parsed->signature);
    if (parsed->generation == RtlFwGeneration::Unknown)
        return ::duetos::core::Err{::duetos::core::ErrorCode::Corrupt};

    parsed->category = blob[0x02];
    parsed->function = blob[0x03];
    parsed->version = ReadLe16(blob, 0x04);
    parsed->subversion = blob[0x06];
    parsed->subsubversion = blob[0x07];
    parsed->date_month = blob[0x08];
    parsed->date_day = blob[0x09];
    parsed->date_hour = blob[0x0A];
    parsed->date_minute = blob[0x0B];
    parsed->ramcode_size = ReadLe16(blob, 0x0C);
    parsed->svn_index = ReadLe32(blob, 0x10);

    parsed->payload = blob + kRtlFwHeaderBytes;
    parsed->payload_size = blob_size - kRtlFwHeaderBytes;

    // Realtek's `ramcodesize` field can be either bytes or kbytes
    // depending on family — rtlwifi v1 uses raw bytes, rtw88
    // sometimes encodes it scaled. We accept either if it agrees
    // within a 4 KiB tolerance, otherwise flag the mismatch.
    const u32 declared = static_cast<u32>(parsed->ramcode_size);
    const u32 declared_scaled = declared * 1024u;
    const u32 tol = 4096u;
    bool agrees = false;
    if (declared == 0)
        agrees = true;
    if (parsed->payload_size >= declared && parsed->payload_size - declared <= tol)
        agrees = true;
    if (parsed->payload_size >= declared_scaled && parsed->payload_size - declared_scaled <= tol)
        agrees = true;
    parsed->size_mismatch = !agrees;
    parsed->valid = true;
    return ::duetos::core::Result<void>{};
}

void RtlFirmwareLog(const RtlFirmwareParsed& parsed)
{
    arch::SerialWrite("[rtl-fw] gen=");
    arch::SerialWrite(RtlFwGenerationName(parsed.generation));
    arch::SerialWrite(" sig=");
    arch::SerialWriteHex(parsed.signature);
    arch::SerialWrite(" ver=");
    arch::SerialWriteHex(parsed.version);
    arch::SerialWrite(" sub=");
    arch::SerialWriteHex(parsed.subversion);
    arch::SerialWrite(".");
    arch::SerialWriteHex(parsed.subsubversion);
    arch::SerialWrite(" payload=");
    arch::SerialWriteHex(parsed.payload_size);
    if (parsed.size_mismatch)
        arch::SerialWrite(" (size-mismatch)");
    arch::SerialWrite("\n");
}

void RtlFirmwareSelfTest()
{
    // Synthesize a minimal valid v1 (rtlwifi) blob.
    constexpr u32 kPayloadBytes = 256;
    constexpr u32 kBufBytes = kRtlFwHeaderBytes + kPayloadBytes;
    static u8 buf[kBufBytes] = {};

    WriteLe16(buf, 0x00, kRtlSig8821);
    buf[0x02] = 0x01;             // category
    buf[0x03] = 0x02;             // function
    WriteLe16(buf, 0x04, 0x4321); // version
    buf[0x06] = 0x12;             // subversion
    buf[0x07] = 0x34;             // subsubversion
    buf[0x08] = 0x05;             // month
    buf[0x09] = 0x01;             // day
    buf[0x0A] = 0x12;             // hour
    buf[0x0B] = 0x30;             // minute
    WriteLe16(buf, 0x0C, kPayloadBytes);
    WriteLe32(buf, 0x10, 0xCAFEBABE);

    // Plausible payload bytes.
    for (u32 i = 0; i < kPayloadBytes; ++i)
        buf[kRtlFwHeaderBytes + i] = static_cast<u8>(i & 0xFF);

    RtlFirmwareParsed parsed{};
    auto r = RtlFirmwareParse(buf, kBufBytes, &parsed);
    KASSERT(r.has_value(), "drivers/net/rtl88xx_fw", "rtl selftest parse error");
    KASSERT(parsed.valid, "drivers/net/rtl88xx_fw", "rtl selftest valid=false");
    KASSERT(parsed.generation == RtlFwGeneration::Rtlwifi, "drivers/net/rtl88xx_fw", "rtl selftest wrong generation");
    KASSERT(parsed.signature == kRtlSig8821, "drivers/net/rtl88xx_fw", "rtl selftest wrong sig");
    KASSERT(parsed.version == 0x4321u, "drivers/net/rtl88xx_fw", "rtl selftest wrong version");
    KASSERT(parsed.subversion == 0x12 && parsed.subsubversion == 0x34, "drivers/net/rtl88xx_fw",
            "rtl selftest wrong sub-version");
    KASSERT(parsed.svn_index == 0xCAFEBABEu, "drivers/net/rtl88xx_fw", "rtl selftest wrong svn");
    KASSERT(parsed.payload != nullptr && parsed.payload_size == kPayloadBytes, "drivers/net/rtl88xx_fw",
            "rtl selftest wrong payload size");
    KASSERT(parsed.payload[0] == 0 && parsed.payload[255] == 255, "drivers/net/rtl88xx_fw",
            "rtl selftest payload byte mismatch");
    KASSERT(!parsed.size_mismatch, "drivers/net/rtl88xx_fw", "rtl selftest unexpected size-mismatch");

    // rtw89 variant — different signature, otherwise identical layout.
    static u8 buf89[kBufBytes] = {};
    WriteLe16(buf89, 0x00, kRtlSig8852a);
    WriteLe16(buf89, 0x0C, kPayloadBytes);
    RtlFirmwareParsed p89{};
    auto r89 = RtlFirmwareParse(buf89, kBufBytes, &p89);
    KASSERT(r89.has_value(), "drivers/net/rtl88xx_fw", "rtl selftest rtw89 parse error");
    KASSERT(p89.generation == RtlFwGeneration::Rtw89, "drivers/net/rtl88xx_fw", "rtl selftest rtw89 wrong generation");

    // Negative cases. Bad signature.
    {
        static u8 bad[kBufBytes] = {};
        WriteLe16(bad, 0x00, 0xDEAD);
        RtlFirmwareParsed p{};
        auto r2 = RtlFirmwareParse(bad, kBufBytes, &p);
        KASSERT(!r2.has_value() && r2.error() == ::duetos::core::ErrorCode::Corrupt, "drivers/net/rtl88xx_fw",
                "rtl selftest bad-sig should return Corrupt");
    }
    // Truncated header.
    {
        u8 small[16] = {};
        RtlFirmwareParsed p{};
        auto r3 = RtlFirmwareParse(small, sizeof(small), &p);
        KASSERT(!r3.has_value() && r3.error() == ::duetos::core::ErrorCode::InvalidArgument, "drivers/net/rtl88xx_fw",
                "rtl selftest short-header should return InvalidArgument");
    }
    arch::SerialWrite("[rtl-fw] selftest pass\n");
}

} // namespace duetos::drivers::net
