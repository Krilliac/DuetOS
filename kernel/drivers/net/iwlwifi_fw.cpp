#include "drivers/net/iwlwifi_fw.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "duetos_iwlwifi_fw.h"
#include "log/klog.h"

namespace duetos::drivers::net
{

::duetos::core::Result<void> IwlFirmwareParse(const u8* blob, u32 blob_size, IwlFirmwareParsed* parsed)
{
    // Byte parsing delegated to `duetos_iwlwifi_fw` Rust crate.
    // Untrusted firmware bytes — Rust-Subsystems P1. The Rust
    // walker uses checked_add for every (off + 8 + length)
    // arithmetic so a hostile TLV length can't wrap to a
    // smaller value that "fits the blob."
    if (parsed == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};

    DuetosIwlFirmwareParsed rs{};
    const i32 rc = duetos_iwlwifi_fw_parse(blob, blob_size, &rs);

    *parsed = IwlFirmwareParsed{};
    parsed->valid = rs.valid;
    // Copy the 64-byte name (NUL-terminated) and sanitize for
    // serial-print: replace any non-printable byte with '?' so a
    // mangled blob can't slip control chars into the log.
    for (u32 i = 0; i < kIwlTlvHumanReadableLen; ++i)
    {
        const u8 c = rs.human_readable[i];
        if (c == 0)
        {
            parsed->human_readable[i] = '\0';
            break;
        }
        parsed->human_readable[i] = (c >= 0x20 && c < 0x7F) ? static_cast<char>(c) : '?';
    }
    parsed->human_readable[kIwlTlvHumanReadableLen] = '\0';
    parsed->ver_packed = rs.ver_packed;
    parsed->build = rs.build;
    parsed->inst = {rs.inst.data, rs.inst.size};
    parsed->data = {rs.data.data, rs.data.size};
    parsed->init = {rs.init.data, rs.init.size};
    parsed->init_data = {rs.init_data.data, rs.init_data.size};
    parsed->sec_rt_first = {rs.sec_rt_first.data, rs.sec_rt_first.size};
    parsed->sec_rt_count = rs.sec_rt_count;
    parsed->flags = rs.flags;
    parsed->num_of_cpu = rs.num_of_cpu;
    parsed->fw_version = rs.fw_version;
    parsed->phy_sku = rs.phy_sku;
    parsed->hw_type = rs.hw_type;
    parsed->total_records = rs.total_records;
    parsed->unknown_records = rs.unknown_records;
    parsed->walked_bytes = rs.walked_bytes;
    parsed->invalid_records = rs.invalid_records;

    if (rc == 0)
        return {};
    if (rc == 1)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    return ::duetos::core::Err{::duetos::core::ErrorCode::Corrupt};
}

void IwlFirmwareLog(const IwlFirmwareParsed& parsed)
{
    arch::SerialWrite("[iwl-fw] name=\"");
    arch::SerialWrite(parsed.human_readable);
    arch::SerialWrite("\" ver=");
    arch::SerialWriteHex(parsed.ver_packed);
    arch::SerialWrite(" build=");
    arch::SerialWriteHex(parsed.build);
    arch::SerialWrite(" tlvs=");
    arch::SerialWriteHex(parsed.total_records);
    arch::SerialWrite(" unknown=");
    arch::SerialWriteHex(parsed.unknown_records);
    arch::SerialWrite(" inst=");
    arch::SerialWriteHex(parsed.inst.size);
    arch::SerialWrite(" data=");
    arch::SerialWriteHex(parsed.data.size);
    arch::SerialWrite(" init=");
    arch::SerialWriteHex(parsed.init.size);
    arch::SerialWrite(" init_data=");
    arch::SerialWriteHex(parsed.init_data.size);
    arch::SerialWrite(" sec_rt=");
    arch::SerialWriteHex(parsed.sec_rt_count);
    arch::SerialWrite("\n");
}

namespace
{

// Helper: write a little-endian dword into a static buffer.
void WriteLe32(u8* buf, u32 off, u32 v)
{
    buf[off] = static_cast<u8>(v & 0xFF);
    buf[off + 1] = static_cast<u8>((v >> 8) & 0xFF);
    buf[off + 2] = static_cast<u8>((v >> 16) & 0xFF);
    buf[off + 3] = static_cast<u8>((v >> 24) & 0xFF);
}

// Append a TLV record (type, length, copy `len` bytes from `src`)
// into `buf` starting at `*off`. Pads to dword alignment to match
// what the iwlwifi blob format requires. Returns the new offset.
u32 AppendTlv(u8* buf, u32 off, u32 type, const u8* src, u32 len)
{
    WriteLe32(buf, off, type);
    WriteLe32(buf, off + 4, len);
    for (u32 i = 0; i < len; ++i)
        buf[off + 8 + i] = src[i];
    // Pad with zeros up to a dword boundary.
    const u32 padded = (len + 3u) & ~3u;
    for (u32 i = len; i < padded; ++i)
        buf[off + 8 + i] = 0;
    return off + 8 + padded;
}

} // namespace

void IwlFirmwareSelfTest()
{
    // Synthetic TLV blob in a static buffer (no heap allocation).
    constexpr u32 kBufBytes = 384;
    static u8 buf[kBufBytes] = {};
    for (u32 i = 0; i < kBufBytes; ++i)
        buf[i] = 0;

    // Header.
    WriteLe32(buf, 0, 0);              // zero
    WriteLe32(buf, 4, kIwlFwTlvMagic); // magic
    const char* name = "iwlwifi-selftest-fake-46";
    for (u32 i = 0; name[i] != '\0' && i < kIwlTlvHumanReadableLen; ++i)
        buf[8 + i] = static_cast<u8>(name[i]);
    WriteLe32(buf, 72, 0x12345678); // ver
    WriteLe32(buf, 76, 0xDEADBEEF); // build

    // TLV stream starts at offset 88.
    u32 off = 88;
    const u8 inst_payload[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    off = AppendTlv(buf, off, static_cast<u32>(IwlTlvType::Inst), inst_payload, 8);
    const u8 data_payload[4] = {0xAA, 0xBB, 0xCC, 0xDD};
    off = AppendTlv(buf, off, static_cast<u32>(IwlTlvType::Data), data_payload, 4);
    u8 flags_payload[4] = {};
    WriteLe32(flags_payload, 0, 0xCAFEBABE);
    off = AppendTlv(buf, off, static_cast<u32>(IwlTlvType::Flags), flags_payload, 4);
    const u8 sec_rt_a[12] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B};
    off = AppendTlv(buf, off, static_cast<u32>(IwlTlvType::SecRt), sec_rt_a, 12);
    const u8 sec_rt_b[8] = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27};
    off = AppendTlv(buf, off, static_cast<u32>(IwlTlvType::SecRt), sec_rt_b, 8);
    u8 unknown_payload[4] = {};
    WriteLe32(unknown_payload, 0, 0x55555555);
    off = AppendTlv(buf, off, /*type=*/9999u, unknown_payload, 4);
    const u8 init_payload[8] = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37};
    off = AppendTlv(buf, off, static_cast<u32>(IwlTlvType::Init), init_payload, 8);
    u8 num_cpu_payload[4] = {};
    WriteLe32(num_cpu_payload, 0, 2);
    off = AppendTlv(buf, off, static_cast<u32>(IwlTlvType::NumOfCpu), num_cpu_payload, 4);

    KASSERT(off <= kBufBytes, "drivers/net/iwlwifi_fw", "selftest buffer overflow");

    IwlFirmwareParsed parsed{};
    auto r = IwlFirmwareParse(buf, off, &parsed);
    KASSERT(r.has_value(), "drivers/net/iwlwifi_fw", "selftest parse returned error");
    KASSERT(parsed.valid, "drivers/net/iwlwifi_fw", "selftest parsed.valid=false");
    KASSERT(parsed.ver_packed == 0x12345678u, "drivers/net/iwlwifi_fw", "selftest ver mismatch");
    KASSERT(parsed.build == 0xDEADBEEFu, "drivers/net/iwlwifi_fw", "selftest build mismatch");
    KASSERT(parsed.flags == 0xCAFEBABEu, "drivers/net/iwlwifi_fw", "selftest flags mismatch");
    KASSERT(parsed.num_of_cpu == 2u, "drivers/net/iwlwifi_fw", "selftest num_of_cpu mismatch");
    KASSERT(parsed.inst.size == 8u && parsed.inst.data != nullptr, "drivers/net/iwlwifi_fw",
            "selftest inst section missing");
    KASSERT(parsed.inst.data[0] == 0x01 && parsed.inst.data[7] == 0x08, "drivers/net/iwlwifi_fw",
            "selftest inst payload mismatch");
    KASSERT(parsed.data.size == 4u, "drivers/net/iwlwifi_fw", "selftest data size mismatch");
    KASSERT(parsed.init.size == 8u, "drivers/net/iwlwifi_fw", "selftest init size mismatch");
    KASSERT(parsed.sec_rt_count == 2u, "drivers/net/iwlwifi_fw", "selftest sec_rt_count != 2");
    KASSERT(parsed.sec_rt_first.size == 12u, "drivers/net/iwlwifi_fw", "selftest sec_rt_first size mismatch");
    KASSERT(parsed.unknown_records == 1u, "drivers/net/iwlwifi_fw", "selftest unknown_records mismatch");
    KASSERT(parsed.total_records == 8u, "drivers/net/iwlwifi_fw", "selftest total_records mismatch");

    // human_readable should round-trip exactly.
    bool name_ok = true;
    for (u32 i = 0; name[i] != '\0'; ++i)
    {
        if (parsed.human_readable[i] != name[i])
        {
            name_ok = false;
            break;
        }
    }
    KASSERT(name_ok, "drivers/net/iwlwifi_fw", "selftest human_readable mismatch");

    // Negative cases. Bad magic.
    {
        u8 bad[kIwlFwHeaderBytes + 8] = {};
        WriteLe32(bad, 4, 0xDEADBEEF);
        IwlFirmwareParsed p{};
        auto r2 = IwlFirmwareParse(bad, sizeof(bad), &p);
        KASSERT(!r2.has_value() && r2.error() == ::duetos::core::ErrorCode::Corrupt, "drivers/net/iwlwifi_fw",
                "selftest bad-magic should return Corrupt");
    }

    // Truncated header.
    {
        u8 small[16] = {};
        IwlFirmwareParsed p{};
        auto r3 = IwlFirmwareParse(small, sizeof(small), &p);
        KASSERT(!r3.has_value() && r3.error() == ::duetos::core::ErrorCode::InvalidArgument, "drivers/net/iwlwifi_fw",
                "selftest short-header should return InvalidArgument");
    }

    // TLV length overflow (declared length pushes past end).
    {
        static u8 ov[128] = {};
        WriteLe32(ov, 0, 0);
        WriteLe32(ov, 4, kIwlFwTlvMagic);
        // First TLV claims 0xFFFFFFF0 bytes — must fail Corrupt.
        WriteLe32(ov, 88, static_cast<u32>(IwlTlvType::Inst));
        WriteLe32(ov, 92, 0xFFFFFFF0u);
        IwlFirmwareParsed p{};
        auto r4 = IwlFirmwareParse(ov, 100, &p);
        KASSERT(!r4.has_value() && r4.error() == ::duetos::core::ErrorCode::Corrupt, "drivers/net/iwlwifi_fw",
                "selftest tlv-overflow should return Corrupt");
    }

    arch::SerialWrite("[iwl-fw] selftest pass\n");
}

} // namespace duetos::drivers::net
