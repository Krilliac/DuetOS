#include "drivers/gpu/amd_gfx_fw.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"
#include "duetos_amd_gfx_fw.h"
#include "log/klog.h"

/*
 * DuetOS — AMD GFX9+ microcode-image parser implementation.
 *
 * Header layout (matches amdgpu_ucode.h, common_firmware_header +
 * gfx_firmware_header_v1_0; little-endian). See the .h for the field
 * map and v0 scope.
 *
 * The parser reads each field through an `Le*` helper rather than
 * casting to a packed struct — keeps the implementation portable
 * across endianness debates and makes the byte offsets obvious to
 * a reviewer reading the AMD spec side-by-side.
 */

namespace duetos::drivers::gpu::amd
{

::duetos::core::Result<void> AmdGfxFwParse(const u8* blob, u32 blob_size, AmdGfxFwParsed* parsed)
{
    // Byte parsing delegated to the `duetos_amd_gfx_fw` Rust
    // crate (kernel/drivers/gpu/amd_gfx_fw_rust/). Firmware
    // blobs are attacker-controllable when the install media or
    // staging path is hostile — Rust-Subsystems P1. Checked
    // arithmetic Rust catches the next ucode_size_bytes /
    // jt_offset_dwords overflow before it becomes a wild
    // pointer.
    if (parsed == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};

    DuetosAmdGfxFwParsed rs{};
    const i32 rc = duetos_amd_gfx_fw_parse(blob, blob_size, &rs);

    // Copy fields from the Rust shape to the public struct.
    *parsed = AmdGfxFwParsed{};
    parsed->valid = rs.valid;
    parsed->is_v1_gfx_header = rs.is_v1_gfx_header;
    parsed->size_bytes = rs.size_bytes;
    parsed->header_size_bytes = rs.header_size_bytes;
    parsed->header_version_major = rs.header_version_major;
    parsed->header_version_minor = rs.header_version_minor;
    parsed->ip_version_major = rs.ip_version_major;
    parsed->ip_version_minor = rs.ip_version_minor;
    parsed->ucode_version = rs.ucode_version;
    parsed->ucode_size_bytes = rs.ucode_size_bytes;
    parsed->ucode_array_offset = rs.ucode_array_offset;
    parsed->crc32 = rs.crc32;
    parsed->ucode_feature_version = rs.ucode_feature_version;
    parsed->jt_offset_dwords = rs.jt_offset_dwords;
    parsed->jt_size_dwords = rs.jt_size_dwords;
    parsed->ucode = rs.ucode;
    parsed->ucode_dword_count = rs.ucode_dword_count;
    parsed->reject_reason = rs.reject_reason;

    if (rc == 0)
        return {};
    if (rc == 1)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    return ::duetos::core::Err{::duetos::core::ErrorCode::Corrupt};
}

void AmdGfxFwLog(const char* basename, const AmdGfxFwParsed& parsed)
{
    if (!parsed.valid)
        return;
    arch::SerialWrite("[gpu/amd-fw] ");
    arch::SerialWrite(basename);
    arch::SerialWrite(" hv=");
    arch::SerialWriteHex(parsed.header_version_major);
    arch::SerialWrite(".");
    arch::SerialWriteHex(parsed.header_version_minor);
    arch::SerialWrite(" ip=");
    arch::SerialWriteHex(parsed.ip_version_major);
    arch::SerialWrite(".");
    arch::SerialWriteHex(parsed.ip_version_minor);
    arch::SerialWrite(" ucode_ver=");
    arch::SerialWriteHex(parsed.ucode_version);
    arch::SerialWrite(" ucode_bytes=");
    arch::SerialWriteHex(parsed.ucode_size_bytes);
    if (parsed.is_v1_gfx_header)
    {
        arch::SerialWrite(" feat=");
        arch::SerialWriteHex(parsed.ucode_feature_version);
        arch::SerialWrite(" jt=");
        arch::SerialWriteHex(parsed.jt_offset_dwords);
        arch::SerialWrite("+");
        arch::SerialWriteHex(parsed.jt_size_dwords);
    }
    arch::SerialWrite("\n");
}

namespace
{
// Write a u16 / u32 into a synthetic buffer in little-endian order.
// Used by the self-test to construct on-the-fly images that match
// the parser's byte layout.
void PutU16(u8* p, u16 v)
{
    p[0] = static_cast<u8>(v & 0xFFu);
    p[1] = static_cast<u8>((v >> 8) & 0xFFu);
}
void PutU32(u8* p, u32 v)
{
    p[0] = static_cast<u8>(v & 0xFFu);
    p[1] = static_cast<u8>((v >> 8) & 0xFFu);
    p[2] = static_cast<u8>((v >> 16) & 0xFFu);
    p[3] = static_cast<u8>((v >> 24) & 0xFFu);
}

// Build a synthetic v1 gfx-firmware image into `buf` (caller-supplied,
// must be at least `header_size + ucode_size` bytes). Returns total
// bytes used. Used both by the happy-path self-test and by the
// reject-case self-tests (which then mutate one field to provoke a
// specific reject_reason).
u32 BuildSyntheticImage(u8* buf, u32 ucode_size_bytes, u32 jt_offset_dwords, u32 jt_size_dwords)
{
    const u32 header_size = kAmdGfxFwHeaderV1Bytes;
    const u32 total = header_size + ucode_size_bytes;
    // common header.
    PutU32(buf + 0x00, total);
    PutU32(buf + 0x04, header_size);
    PutU16(buf + 0x08, 1);           // header_version_major
    PutU16(buf + 0x0A, 0);           // header_version_minor
    PutU16(buf + 0x0C, 9);           // ip_version_major (GFX9)
    PutU16(buf + 0x0E, 0);           // ip_version_minor
    PutU32(buf + 0x10, 0xCAFEC0DEu); // ucode_version
    PutU32(buf + 0x14, ucode_size_bytes);
    PutU32(buf + 0x18, header_size); // ucode_array_offset
    PutU32(buf + 0x1C, 0xDEADBEEFu); // crc32
    // v1 gfx header.
    PutU32(buf + 0x20, 0x42u); // ucode_feature_version
    PutU32(buf + 0x24, jt_offset_dwords);
    PutU32(buf + 0x28, jt_size_dwords);
    // Stamp the payload with the dword index so a later upload
    // sequence has something concrete to verify against.
    for (u32 i = 0; i < ucode_size_bytes / 4u; ++i)
        PutU32(buf + header_size + i * 4u, 0x10000000u | i);
    return total;
}

void Fail(const char* tag, u32 detail)
{
    KBP_PROBE_V(::duetos::debug::ProbeId::kBootSelftestFail, detail);
    KLOG_WARN_V("drivers/gpu/amd-fw", tag, detail);
}

} // namespace

void AmdGfxFwSelfTest()
{
    // 256-byte synthetic ucode + 44-byte v1 header = 300 bytes total.
    static u8 buf[1024];
    const u32 ucode_bytes = 256;
    const u32 total = BuildSyntheticImage(buf, ucode_bytes, /*jt_offset_dwords=*/8,
                                          /*jt_size_dwords=*/16);

    // Happy path.
    AmdGfxFwParsed p{};
    auto r = AmdGfxFwParse(buf, total, &p);
    if (!r.has_value() || !p.valid)
    {
        Fail("happy-path parse rejected", p.reject_reason);
        return;
    }
    if (!p.is_v1_gfx_header)
    {
        Fail("happy-path missed v1 header", 0);
        return;
    }
    if (p.ucode_dword_count != ucode_bytes / 4u)
    {
        Fail("happy-path ucode_dword_count mismatch", p.ucode_dword_count);
        return;
    }
    if (p.ucode == nullptr || p.ucode[0] != 0x10000000u || p.ucode[1] != 0x10000001u)
    {
        Fail("happy-path ucode payload offset wrong", 0);
        return;
    }
    if (p.ucode_version != 0xCAFEC0DEu || p.ucode_feature_version != 0x42u)
    {
        Fail("happy-path version fields wrong", p.ucode_version);
        return;
    }
    if (p.jt_offset_dwords != 8u || p.jt_size_dwords != 16u)
    {
        Fail("happy-path jt fields wrong", (p.jt_offset_dwords << 16) | p.jt_size_dwords);
        return;
    }

    // Reject path: blob shorter than the common header.
    p = AmdGfxFwParsed{};
    r = AmdGfxFwParse(buf, kAmdCommonFwHeaderBytes - 1u, &p);
    if (r.has_value() || (p.reject_reason & kAmdFwRejectBlobTooShort) == 0)
    {
        Fail("short-blob check did not trip", p.reject_reason);
        return;
    }

    // Reject path: ucode declared past the blob end. Mutate
    // ucode_size_bytes to exceed the remaining space.
    BuildSyntheticImage(buf, ucode_bytes, 0, 0);
    PutU32(buf + 0x14, ucode_bytes + 0x10000u); // way past EOF
    p = AmdGfxFwParsed{};
    r = AmdGfxFwParse(buf, total, &p);
    if (r.has_value() || (p.reject_reason & kAmdFwRejectUcodeOverflow) == 0)
    {
        Fail("ucode-overflow check did not trip", p.reject_reason);
        return;
    }

    // Reject path: jump-table extends past the payload. Rebuild with
    // jt_offset placing the jump table off the end.
    BuildSyntheticImage(buf, ucode_bytes, /*jt_offset=*/(ucode_bytes / 4u), /*jt_size=*/1u);
    p = AmdGfxFwParsed{};
    r = AmdGfxFwParse(buf, total, &p);
    if (r.has_value() || (p.reject_reason & kAmdFwRejectJtOverflow) == 0)
    {
        Fail("jt-overflow check did not trip", p.reject_reason);
        return;
    }

    // Reject path: header smaller than the common-header floor.
    BuildSyntheticImage(buf, ucode_bytes, 0, 0);
    PutU32(buf + 0x04, kAmdCommonFwHeaderBytes - 1u);
    p = AmdGfxFwParsed{};
    r = AmdGfxFwParse(buf, total, &p);
    if (r.has_value() || (p.reject_reason & kAmdFwRejectHeaderShort) == 0)
    {
        Fail("header-short check did not trip", p.reject_reason);
        return;
    }

    // Reject path: size_bytes smaller than header_size_bytes.
    BuildSyntheticImage(buf, ucode_bytes, 0, 0);
    PutU32(buf + 0x00, kAmdGfxFwHeaderV1Bytes - 1u); // total < header
    p = AmdGfxFwParsed{};
    r = AmdGfxFwParse(buf, total, &p);
    if (r.has_value() || (p.reject_reason & kAmdFwRejectHeaderInconsistent) == 0)
    {
        Fail("header-inconsistent check did not trip", p.reject_reason);
        return;
    }

    // Reject path: oversized size_bytes triggers the sanity cap.
    BuildSyntheticImage(buf, ucode_bytes, 0, 0);
    PutU32(buf + 0x00, kAmdMaxFwSizeBytes + 1u);
    p = AmdGfxFwParsed{};
    r = AmdGfxFwParse(buf, total, &p);
    if (r.has_value() || (p.reject_reason & kAmdFwRejectOversize) == 0)
    {
        Fail("oversize check did not trip", p.reject_reason);
        return;
    }

    arch::SerialWrite("[gpu/amd-fw] selftest PASS (parse + 6 reject paths)\n");
}

} // namespace duetos::drivers::gpu::amd
