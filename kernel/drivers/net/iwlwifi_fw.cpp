#include "drivers/net/iwlwifi_fw.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "log/klog.h"

namespace duetos::drivers::net
{

namespace
{

// Little-endian dword read at byte offset `off` of `buf`. The blob
// is treated as raw bytes — vendor microcode is shipped in LE form
// regardless of host endianness, and the parser MUST not assume
// alignment beyond byte. (iwlwifi blobs are 4-byte-aligned in
// practice, but we don't take that on faith.)
u32 ReadLe32(const u8* buf, u32 off)
{
    return static_cast<u32>(buf[off]) | (static_cast<u32>(buf[off + 1]) << 8) | (static_cast<u32>(buf[off + 2]) << 16) |
           (static_cast<u32>(buf[off + 3]) << 24);
}

// Round `n` up to the next 4-byte boundary. iwlwifi pads every TLV
// payload to dword alignment, regardless of the declared length.
u32 RoundUp4(u32 n)
{
    return (n + 3u) & ~3u;
}

void CopyHumanReadable(char* dst, const u8* src, u32 max_in)
{
    u32 i = 0;
    for (; i < max_in && i < kIwlTlvHumanReadableLen && src[i] != 0; ++i)
    {
        const u8 c = src[i];
        // Sanitize — the field is printed to serial. Reject every
        // byte outside the 7-bit printable ASCII range so a
        // mangled blob can't slip control characters into the log.
        dst[i] = (c >= 0x20 && c < 0x7F) ? static_cast<char>(c) : '?';
    }
    dst[i] = '\0';
}

} // namespace

::duetos::core::Result<void> IwlFirmwareParse(const u8* blob, u32 blob_size, IwlFirmwareParsed* parsed)
{
    if (blob == nullptr || parsed == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    *parsed = {};
    if (blob_size < kIwlFwHeaderBytes)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};

    // Header preamble.
    //   bytes [0..4)  : zero (distinguishes TLV format from v1/v2).
    //   bytes [4..8)  : magic 0x0A4C5749 ("IWL\n" LE).
    //   bytes [8..72) : 64-byte human-readable name.
    //   bytes [72..76): version dword.
    //   bytes [76..80): build dword.
    //   bytes [80..88): 8 bytes ignore.
    // TLV stream begins immediately at +88 (no further alignment).
    const u32 zero_word = ReadLe32(blob, 0);
    const u32 magic = ReadLe32(blob, 4);
    if (zero_word != 0 || magic != kIwlFwTlvMagic)
        return ::duetos::core::Err{::duetos::core::ErrorCode::Corrupt};

    CopyHumanReadable(parsed->human_readable, blob + 8, kIwlTlvHumanReadableLen);
    parsed->ver_packed = ReadLe32(blob, 8 + kIwlTlvHumanReadableLen);
    parsed->build = ReadLe32(blob, 8 + kIwlTlvHumanReadableLen + 4);

    // The 8-byte "ignore" field is officially at +80; the TLV stream
    // begins at +88. We don't add the 4 alignment bytes — the spec
    // (and Linux's iwl-drv) walks TLVs starting at offset 88.
    constexpr u32 kTlvStreamStart = 88;
    u32 off = kTlvStreamStart;

    // TLV walk. Each record:
    //   u32 type, u32 length, u8 payload[length], pad to dword.
    while (off + 8 <= blob_size)
    {
        const u32 type = ReadLe32(blob, off);
        const u32 length = ReadLe32(blob, off + 4);
        const u32 payload_off = off + 8;

        // Bounds check. A length that would push the payload past
        // the blob end is fatal — we can't trust further records.
        if (length > blob_size || payload_off + length > blob_size)
        {
            ++parsed->invalid_records;
            return ::duetos::core::Err{::duetos::core::ErrorCode::Corrupt};
        }

        ++parsed->total_records;
        const u8* payload = blob + payload_off;

        switch (static_cast<IwlTlvType>(type))
        {
        case IwlTlvType::Inst:
            parsed->inst = {payload, length};
            break;
        case IwlTlvType::Data:
            parsed->data = {payload, length};
            break;
        case IwlTlvType::Init:
            parsed->init = {payload, length};
            break;
        case IwlTlvType::InitData:
            parsed->init_data = {payload, length};
            break;
        case IwlTlvType::SecRt:
        case IwlTlvType::SecureSecRt:
            if (parsed->sec_rt_count == 0)
                parsed->sec_rt_first = {payload, length};
            ++parsed->sec_rt_count;
            break;
        case IwlTlvType::Flags:
            if (length >= 4)
                parsed->flags = ReadLe32(blob, payload_off);
            break;
        case IwlTlvType::NumOfCpu:
            if (length >= 4)
                parsed->num_of_cpu = ReadLe32(blob, payload_off);
            break;
        case IwlTlvType::FwVersion:
            if (length >= 4)
                parsed->fw_version = ReadLe32(blob, payload_off);
            break;
        case IwlTlvType::PhySku:
            if (length >= 4)
                parsed->phy_sku = ReadLe32(blob, payload_off);
            break;
        case IwlTlvType::HwType:
            if (length >= 4)
                parsed->hw_type = ReadLe32(blob, payload_off);
            break;
        default:
            ++parsed->unknown_records;
            break;
        }

        // Advance past payload, then up to dword boundary.
        const u32 advance = 8 + RoundUp4(length);
        // Defensive: a 0-length record advances by 8 and we keep
        // going. A length so large it caused payload_off+length to
        // wrap can't get here — the bounds check above already
        // ruled it out.
        off += advance;
    }

    parsed->walked_bytes = off;
    parsed->valid = (parsed->total_records > 0);
    return ::duetos::core::Result<void>{};
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
