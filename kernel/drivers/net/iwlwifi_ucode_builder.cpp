#include "drivers/net/iwlwifi_ucode_builder.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"

namespace duetos::drivers::net
{

namespace
{

u32 RoundUp4(u32 n)
{
    return (n + 3u) & ~3u;
}

void WriteLe32(u8* out, u32 off, u32 v)
{
    out[off] = static_cast<u8>(v & 0xFFu);
    out[off + 1] = static_cast<u8>((v >> 8) & 0xFFu);
    out[off + 2] = static_cast<u8>((v >> 16) & 0xFFu);
    out[off + 3] = static_cast<u8>((v >> 24) & 0xFFu);
}

bool WriteBoundedAscii64(u8* out, const char* s)
{
    if (out == nullptr || s == nullptr || s[0] == '\0')
        return false;
    u32 i = 0;
    for (; i < kIwlTlvHumanReadableLen && s[i] != '\0'; ++i)
        out[i] = static_cast<u8>(s[i]);
    if (i == kIwlTlvHumanReadableLen && s[i] != '\0')
        return false;
    for (; i < kIwlTlvHumanReadableLen; ++i)
        out[i] = 0;
    return true;
}

::duetos::core::Result<void> AppendTlv(u8* out, u32 out_cap, u32* off, IwlTlvType type, const u8* payload,
                                       u32 payload_size)
{
    if (out == nullptr || off == nullptr || (payload_size != 0 && payload == nullptr))
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    const u32 padded = RoundUp4(payload_size);
    if (payload_size > 0x7FFFFFF0u || *off > out_cap || 8u + padded > out_cap - *off)
        return ::duetos::core::Err{::duetos::core::ErrorCode::BufferTooSmall};

    WriteLe32(out, *off, static_cast<u32>(type));
    WriteLe32(out, *off + 4, payload_size);
    for (u32 i = 0; i < payload_size; ++i)
        out[*off + 8 + i] = payload[i];
    for (u32 i = payload_size; i < padded; ++i)
        out[*off + 8 + i] = 0;
    *off += 8 + padded;
    return ::duetos::core::Result<void>{};
}

::duetos::core::Result<void> AppendDwordTlv(u8* out, u32 out_cap, u32* off, IwlTlvType type, u32 value)
{
    u8 payload[4] = {};
    WriteLe32(payload, 0, value);
    return AppendTlv(out, out_cap, off, type, payload, sizeof(payload));
}

bool SectionTypeAllowed(IwlTlvType type)
{
    switch (type)
    {
    case IwlTlvType::Inst:
    case IwlTlvType::Data:
    case IwlTlvType::Init:
    case IwlTlvType::InitData:
    case IwlTlvType::SecRt:
    case IwlTlvType::SecInit:
    case IwlTlvType::SecWowlan:
    case IwlTlvType::SecureSecRt:
    case IwlTlvType::SecureSecInit:
    case IwlTlvType::SecureSecWowlan:
        return true;
    default:
        return false;
    }
}

} // namespace

::duetos::core::Result<IwlFirmwareBuildResult> IwlFirmwareBuild(const IwlFirmwareBuildRequest& req, u8* out,
                                                                u32 out_cap)
{
    if (out == nullptr || out_cap < kIwlFwHeaderBytes || req.sections == nullptr || req.section_count == 0)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};

    for (u32 i = 0; i < out_cap; ++i)
        out[i] = 0;

    WriteLe32(out, 0, 0);
    WriteLe32(out, 4, kIwlFwTlvMagic);
    if (!WriteBoundedAscii64(out + 8, req.human_readable))
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    WriteLe32(out, 72, req.ver_packed);
    WriteLe32(out, 76, req.build);
    // bytes [80,88) remain zero (ignored field in the iwlwifi TLV header).

    u32 off = kIwlFwHeaderBytes;
    u32 records = 0;

    if (req.flags != 0)
    {
        RESULT_TRY(AppendDwordTlv(out, out_cap, &off, IwlTlvType::Flags, req.flags));
        ++records;
    }
    if (req.num_of_cpu != 0)
    {
        RESULT_TRY(AppendDwordTlv(out, out_cap, &off, IwlTlvType::NumOfCpu, req.num_of_cpu));
        ++records;
    }
    if (req.fw_version != 0)
    {
        RESULT_TRY(AppendDwordTlv(out, out_cap, &off, IwlTlvType::FwVersion, req.fw_version));
        ++records;
    }

    for (u32 i = 0; i < req.section_count; ++i)
    {
        const IwlFirmwareBuildSection& s = req.sections[i];
        if (!SectionTypeAllowed(s.type) || s.data == nullptr || s.size == 0)
            return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
        RESULT_TRY(AppendTlv(out, out_cap, &off, s.type, s.data, s.size));
        ++records;
    }

    return IwlFirmwareBuildResult{off, records};
}

void IwlFirmwareBuilderSelfTest()
{
    constexpr u32 kBufBytes = 256;
    static u8 image[kBufBytes] = {};
    const u8 inst[] = {0x13, 0x37, 0xC0, 0xDE, 0x01, 0x02, 0x03, 0x04};
    const u8 data[] = {0x55, 0xAA, 0x10, 0x20};
    const u8 sec_rt[] = {0xD0, 0xE7, 0x00, 0x51, 0x99};
    const IwlFirmwareBuildSection sections[] = {
        {IwlTlvType::Inst, inst, sizeof(inst)},
        {IwlTlvType::Data, data, sizeof(data)},
        {IwlTlvType::SecRt, sec_rt, sizeof(sec_rt)},
    };
    const IwlFirmwareBuildRequest req{"DuetOS custom unsigned lab ucode",
                                      0x00010002u,
                                      0x20260508u,
                                      0xA5A50001u,
                                      2,
                                      0x00010002u,
                                      sections,
                                      static_cast<u32>(sizeof(sections) / sizeof(sections[0]))};

    auto build = IwlFirmwareBuild(req, image, sizeof(image));
    KASSERT(build.has_value(), "drivers/net/iwlwifi_ucode_builder", "build failed");
    KASSERT(build.value().tlv_records == 6, "drivers/net/iwlwifi_ucode_builder", "wrong record count");

    IwlFirmwareParsed parsed{};
    auto parse = IwlFirmwareParse(image, build.value().bytes_written, &parsed);
    KASSERT(parse.has_value(), "drivers/net/iwlwifi_ucode_builder", "parse failed");
    KASSERT(parsed.valid, "drivers/net/iwlwifi_ucode_builder", "parsed valid=false");
    KASSERT(parsed.flags == 0xA5A50001u, "drivers/net/iwlwifi_ucode_builder", "flags mismatch");
    KASSERT(parsed.num_of_cpu == 2, "drivers/net/iwlwifi_ucode_builder", "cpu count mismatch");
    KASSERT(parsed.inst.size == sizeof(inst) && parsed.inst.data[0] == 0x13, "drivers/net/iwlwifi_ucode_builder",
            "inst mismatch");
    KASSERT(parsed.data.size == sizeof(data) && parsed.data.data[1] == 0xAA, "drivers/net/iwlwifi_ucode_builder",
            "data mismatch");
    KASSERT(parsed.sec_rt_count == 1 && parsed.sec_rt_first.size == sizeof(sec_rt), "drivers/net/iwlwifi_ucode_builder",
            "sec_rt mismatch");

    auto small = IwlFirmwareBuild(req, image, kIwlFwHeaderBytes + 8);
    KASSERT(!small.has_value() && small.error() == ::duetos::core::ErrorCode::BufferTooSmall,
            "drivers/net/iwlwifi_ucode_builder", "small buffer should fail");

    arch::SerialWrite("[iwl-fw-build] selftest pass\n");
}

} // namespace duetos::drivers::net
