#include "drivers/net/rtl88xx_fw.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "duetos_rtl88xx_fw.h"
#include "log/klog.h"

namespace duetos::drivers::net
{

namespace
{

// LE writers — only used by the self-test below to synthesize
// blobs. Readers + classifier moved to the Rust crate.
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
    // Byte parsing delegated to `duetos_rtl88xx_fw` Rust crate.
    // Untrusted firmware bytes — Rust-Subsystems P1.
    if (parsed == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};

    DuetosRtlFirmwareParsed rs{};
    const i32 rc = duetos_rtl88xx_fw_parse(blob, blob_size, &rs);

    *parsed = RtlFirmwareParsed{};
    parsed->valid = rs.valid;
    parsed->generation = static_cast<RtlFwGeneration>(rs.generation);
    parsed->signature = rs.signature;
    parsed->category = rs.category;
    parsed->function = rs.function;
    parsed->version = rs.version;
    parsed->subversion = rs.subversion;
    parsed->subsubversion = rs.subsubversion;
    parsed->date_month = rs.date_month;
    parsed->date_day = rs.date_day;
    parsed->date_hour = rs.date_hour;
    parsed->date_minute = rs.date_minute;
    parsed->ramcode_size = rs.ramcode_size;
    parsed->svn_index = rs.svn_index;
    parsed->payload = rs.payload;
    parsed->payload_size = rs.payload_size;
    parsed->size_mismatch = rs.size_mismatch;

    if (rc == 0)
        return {};
    if (rc == 1)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    return ::duetos::core::Err{::duetos::core::ErrorCode::Corrupt};
}

void RtlFirmwareLog(const RtlFirmwareParsed& parsed)
{
    KLOG_INFO_S("drivers/net/rtl88xx", parsed.size_mismatch ? "firmware parsed (size-mismatch)" : "firmware parsed",
                "gen", RtlFwGenerationName(parsed.generation));
    KLOG_DEBUG_V("drivers/net/rtl88xx", "firmware sig", parsed.signature);
    KLOG_DEBUG_V("drivers/net/rtl88xx", "firmware ver", parsed.version);
    KLOG_DEBUG_V("drivers/net/rtl88xx", "firmware subversion", parsed.subversion);
    KLOG_DEBUG_V("drivers/net/rtl88xx", "firmware subsubversion", parsed.subsubversion);
    KLOG_DEBUG_V("drivers/net/rtl88xx", "firmware payload size", parsed.payload_size);
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
