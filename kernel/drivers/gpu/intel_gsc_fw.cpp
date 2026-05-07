#include "drivers/gpu/intel_gsc_fw.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "log/klog.h"

namespace duetos::drivers::gpu::intel
{

namespace
{

// Little-endian dword read at byte offset `off` of `buf`. The image
// is treated as raw bytes — Intel GSC images are LE regardless of
// host endianness, and the parser MUST not assume alignment beyond
// byte. (FPT entries are 32-byte aligned in practice; we don't
// take that on faith.)
u32 ReadLe32(const u8* buf, u32 off)
{
    return static_cast<u32>(buf[off]) | (static_cast<u32>(buf[off + 1]) << 8) | (static_cast<u32>(buf[off + 2]) << 16) |
           (static_cast<u32>(buf[off + 3]) << 24);
}

// Compare 4 bytes against an ASCII tag. The FPT entry name field
// is fixed-width (4 bytes, no NUL) so we never read past the
// declared bound.
bool NameEq(const u8* p, const char* tag)
{
    return p[0] == static_cast<u8>(tag[0]) && p[1] == static_cast<u8>(tag[1]) && p[2] == static_cast<u8>(tag[2]) &&
           p[3] == static_cast<u8>(tag[3]);
}

void NameCopy(char* dst, const u8* src)
{
    for (u32 i = 0; i < kIntelGscPartitionNameBytes; ++i)
    {
        const u8 c = src[i];
        // Sanitize — sanitise control bytes the same way the
        // iwlwifi parser does. The field is printed to serial.
        dst[i] = (c >= 0x20 && c < 0x7F) ? static_cast<char>(c) : '?';
    }
    dst[kIntelGscPartitionNameBytes] = '\0';
}

// Locate the `$FPT` marker. Modern GSC images place it at byte 0;
// older Intel ME images prepend a 16-byte "ROM-bypass" vector and
// the marker sits at byte 16. We accept either.
bool FindFptHeader(const u8* blob, u32 blob_size, u32* hdr_off, bool* rom_bypass_present)
{
    if (blob_size >= 4 && ReadLe32(blob, 0) == kIntelGscFptMarker)
    {
        *hdr_off = 0;
        *rom_bypass_present = false;
        return true;
    }
    if (blob_size >= kIntelGscRomBypassBytes + 4 && ReadLe32(blob, kIntelGscRomBypassBytes) == kIntelGscFptMarker)
    {
        *hdr_off = kIntelGscRomBypassBytes;
        *rom_bypass_present = true;
        return true;
    }
    return false;
}

} // namespace

IntelGscPartitionKind IntelGscClassifyName(const char* four_bytes)
{
    if (four_bytes == nullptr)
        return IntelGscPartitionKind::Unknown;
    const u8* p = reinterpret_cast<const u8*>(four_bytes);
    if (NameEq(p, "FTPR"))
        return IntelGscPartitionKind::Ftpr;
    if (NameEq(p, "OPRO"))
        return IntelGscPartitionKind::Oprom;
    if (NameEq(p, "OPRC"))
        return IntelGscPartitionKind::OpromC;
    if (NameEq(p, "IAFW"))
        return IntelGscPartitionKind::IaFw;
    if (NameEq(p, "MDMV"))
        return IntelGscPartitionKind::Mdmv;
    if (NameEq(p, "GLUT"))
        return IntelGscPartitionKind::Glut;
    if (NameEq(p, "MFTP"))
        return IntelGscPartitionKind::Mftp;
    if (NameEq(p, "DLMP"))
        return IntelGscPartitionKind::Dlmp;
    if (NameEq(p, "FPFS"))
        return IntelGscPartitionKind::Fpfs;
    if (NameEq(p, "PMCP"))
        return IntelGscPartitionKind::Pmcp;
    return IntelGscPartitionKind::Unknown;
}

::duetos::core::Result<void> IntelGscFwParse(const u8* blob, u32 blob_size, IntelGscFwParsed* parsed)
{
    if (blob == nullptr || parsed == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    *parsed = {};

    // Smallest possible legal image: header + one entry, no rom-
    // bypass prelude. Reject anything below that outright.
    if (blob_size < kIntelGscFptHeaderBytes + kIntelGscFptEntryBytes)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};

    u32 hdr_off = 0;
    if (!FindFptHeader(blob, blob_size, &hdr_off, &parsed->rom_bypass_present))
        return ::duetos::core::Err{::duetos::core::ErrorCode::Corrupt};

    // Need the full header inside the blob.
    if (hdr_off + kIntelGscFptHeaderBytes > blob_size)
        return ::duetos::core::Err{::duetos::core::ErrorCode::Corrupt};

    // FPT header layout (32 bytes), starting at hdr_off:
    //   [+0..+4)   marker = "$FPT"
    //   [+4..+8)   num_entries
    //   [+8]       header_version
    //   [+9]       entry_version
    //   [+10]      header_length
    //   [+11]      header_checksum
    //   [+12..+14) ticks_to_add
    //   [+14..+16) tokens_to_add
    //   [+16..+20) reserved / uma_size
    //   [+20..+24) flash-layout CRC32
    //   [+24]      fitc_major
    //   [+25]      fitc_minor
    //   [+26]      fitc_hotfix
    //   [+27]      fitc_build
    //   [+28..+32) reserved
    parsed->num_entries_declared = ReadLe32(blob, hdr_off + 4);
    parsed->header_version = blob[hdr_off + 8];
    parsed->entry_version = blob[hdr_off + 9];
    parsed->header_length = blob[hdr_off + 10];
    parsed->header_checksum = blob[hdr_off + 11];
    parsed->fitc_version_packed = ReadLe32(blob, hdr_off + 24);

    // A reasonable upper bound. Real GSC images carry well under
    // 32 entries; values past the cap are almost certainly a corrupt
    // blob's first 4 bytes interpreted as count.
    if (parsed->num_entries_declared == 0 || parsed->num_entries_declared > kIntelGscMaxEntries)
        return ::duetos::core::Err{::duetos::core::ErrorCode::Corrupt};

    // Verify the entry array fits inside the blob.
    const u64 entries_off = static_cast<u64>(hdr_off) + kIntelGscFptHeaderBytes;
    const u64 entries_end =
        entries_off + static_cast<u64>(parsed->num_entries_declared) * static_cast<u64>(kIntelGscFptEntryBytes);
    if (entries_end > blob_size)
        return ::duetos::core::Err{::duetos::core::ErrorCode::Corrupt};

    // Walk every entry. Each is 32 bytes:
    //   [+0..+4)   name (ASCII, 4 bytes)
    //   [+4..+8)   reserved1
    //   [+8..+12)  offset (image-relative)
    //   [+12..+16) length
    //   [+16..+28) reserved2
    //   [+28..+32) partition_flags
    for (u32 i = 0; i < parsed->num_entries_declared; ++i)
    {
        const u32 e_off = static_cast<u32>(entries_off) + i * kIntelGscFptEntryBytes;
        const u8* e = blob + e_off;
        IntelGscFwEntry& slot = parsed->entries[i];
        NameCopy(slot.name, e);
        slot.kind = IntelGscClassifyName(slot.name);
        slot.offset = ReadLe32(e, 8);
        slot.length = ReadLe32(e, 12);
        slot.partition_flags = ReadLe32(e, 28);

        // Bounds check the partition span against the image. An
        // out-of-range entry doesn't kill the parse — many real
        // GSC images list "future-use" entries with
        // length=0 / offset=0; mark only those whose declared span
        // genuinely escapes the blob.
        const u64 part_end = static_cast<u64>(slot.offset) + static_cast<u64>(slot.length);
        const bool span_ok = (slot.length == 0) || (slot.offset < blob_size && part_end <= blob_size);

        if (!span_ok)
        {
            ++parsed->invalid_entries;
            // Defensive: we still walk the remainder so the caller
            // sees the count correctly. Don't store a bogus view.
            continue;
        }

        IntelGscFwSection sec{};
        sec.data = (slot.length > 0) ? (blob + slot.offset) : nullptr;
        sec.size = slot.length;
        sec.image_offset = slot.offset;

        switch (slot.kind)
        {
        case IntelGscPartitionKind::Ftpr:
            parsed->ftpr = sec;
            break;
        case IntelGscPartitionKind::Oprom:
            parsed->oprom = sec;
            break;
        case IntelGscPartitionKind::OpromC:
            parsed->oprom_code = sec;
            break;
        case IntelGscPartitionKind::IaFw:
            parsed->ia_fw = sec;
            break;
        case IntelGscPartitionKind::Mftp:
            parsed->manufacturing_flags |= 0x1u;
            break;
        case IntelGscPartitionKind::Dlmp:
            parsed->manufacturing_flags |= 0x2u;
            break;
        case IntelGscPartitionKind::Unknown:
            ++parsed->unknown_entries;
            break;
        default:
            break;
        }

        ++parsed->num_entries_walked;
    }

    parsed->walked_bytes = static_cast<u32>(entries_end);
    parsed->valid = (parsed->num_entries_walked > 0);
    return ::duetos::core::Result<void>{};
}

void IntelGscFwLog(const IntelGscFwParsed& parsed)
{
    arch::SerialWrite("[intel-gsc-fw] entries=");
    arch::SerialWriteHex(parsed.num_entries_walked);
    arch::SerialWrite("/");
    arch::SerialWriteHex(parsed.num_entries_declared);
    arch::SerialWrite(" rom_bypass=");
    arch::SerialWrite(parsed.rom_bypass_present ? "yes" : "no");
    arch::SerialWrite(" fitc=");
    arch::SerialWriteHex(parsed.fitc_version_packed);
    arch::SerialWrite(" ftpr=");
    arch::SerialWriteHex(parsed.ftpr.size);
    arch::SerialWrite(" oprom=");
    arch::SerialWriteHex(parsed.oprom.size);
    arch::SerialWrite(" oprom_code=");
    arch::SerialWriteHex(parsed.oprom_code.size);
    arch::SerialWrite(" ia_fw=");
    arch::SerialWriteHex(parsed.ia_fw.size);
    arch::SerialWrite(" unknown=");
    arch::SerialWriteHex(parsed.unknown_entries);
    arch::SerialWrite(" invalid=");
    arch::SerialWriteHex(parsed.invalid_entries);
    arch::SerialWrite(" mfg=");
    arch::SerialWriteHex(parsed.manufacturing_flags);
    arch::SerialWrite("\n");

    if (parsed.manufacturing_flags != 0)
    {
        // GAP: Manufacturing partitions (MFTP / DLMP) on a deployed
        // image is a strong signal an operator dropped a debug
        // build into /lib/firmware. Surface it once at WARN; a
        // follow-up slice can extend Image-Guard to block these.
        KLOG_WARN("drivers/gpu/intel-gsc-fw", "image carries manufacturing partitions — refuse for production deploys");
    }
}

namespace
{

void WriteLe32(u8* buf, u32 off, u32 v)
{
    buf[off] = static_cast<u8>(v & 0xFF);
    buf[off + 1] = static_cast<u8>((v >> 8) & 0xFF);
    buf[off + 2] = static_cast<u8>((v >> 16) & 0xFF);
    buf[off + 3] = static_cast<u8>((v >> 24) & 0xFF);
}

void WriteName(u8* buf, u32 off, const char* tag)
{
    for (u32 i = 0; i < kIntelGscPartitionNameBytes; ++i)
        buf[off + i] = static_cast<u8>(tag[i]);
}

// Build a synthetic FPT image into `buf`, with three entries: FTPR,
// OPRO, and one unknown name. Returns the total used byte count.
u32 BuildSyntheticImage(u8* buf, u32 cap, u32 fitc_packed, bool with_rom_bypass)
{
    for (u32 i = 0; i < cap; ++i)
        buf[i] = 0;

    const u32 hdr_off = with_rom_bypass ? kIntelGscRomBypassBytes : 0;
    if (with_rom_bypass)
    {
        for (u32 i = 0; i < kIntelGscRomBypassBytes; ++i)
            buf[i] = 0xFFu;
    }

    constexpr u32 kEntries = 3;
    WriteLe32(buf, hdr_off + 0, kIntelGscFptMarker);
    WriteLe32(buf, hdr_off + 4, kEntries);
    buf[hdr_off + 8] = 0x20;  // header_version
    buf[hdr_off + 9] = 0x10;  // entry_version
    buf[hdr_off + 10] = 0x20; // header_length = 32
    buf[hdr_off + 11] = 0xAB; // header_checksum (not validated by parser yet)
    WriteLe32(buf, hdr_off + 24, fitc_packed);

    const u32 entries_off = hdr_off + kIntelGscFptHeaderBytes;
    const u32 ftpr_off = entries_off + kEntries * kIntelGscFptEntryBytes;
    const u32 ftpr_size = 64;
    const u32 oprom_off = ftpr_off + ftpr_size;
    const u32 oprom_size = 32;
    const u32 unk_off = oprom_off + oprom_size;
    const u32 unk_size = 16;

    auto write_entry = [&](u32 idx, const char* tag, u32 part_off, u32 part_size, u32 flags)
    {
        const u32 e_off = entries_off + idx * kIntelGscFptEntryBytes;
        WriteName(buf, e_off + 0, tag);
        WriteLe32(buf, e_off + 8, part_off);
        WriteLe32(buf, e_off + 12, part_size);
        WriteLe32(buf, e_off + 28, flags);
    };
    write_entry(0, "FTPR", ftpr_off, ftpr_size, 0x1);
    write_entry(1, "OPRO", oprom_off, oprom_size, 0x2);
    write_entry(2, "ZZZZ", unk_off, unk_size, 0x0);

    // Stamp partition payloads with recognisable bytes.
    for (u32 i = 0; i < ftpr_size; ++i)
        buf[ftpr_off + i] = static_cast<u8>(0xA0 | (i & 0xF));
    for (u32 i = 0; i < oprom_size; ++i)
        buf[oprom_off + i] = static_cast<u8>(0xB0 | (i & 0xF));
    for (u32 i = 0; i < unk_size; ++i)
        buf[unk_off + i] = static_cast<u8>(0xC0 | (i & 0xF));

    return unk_off + unk_size;
}

} // namespace

void IntelGscFwSelfTest()
{
    // Synthetic image in a static buffer (no heap allocation).
    constexpr u32 kBufBytes = 384;
    static u8 buf[kBufBytes] = {};
    const u32 used = BuildSyntheticImage(buf, kBufBytes, 0x04030201u, /*with_rom_bypass=*/false);
    KASSERT(used <= kBufBytes, "drivers/gpu/intel-gsc-fw", "selftest buffer overflow");

    IntelGscFwParsed parsed{};
    auto r = IntelGscFwParse(buf, used, &parsed);
    KASSERT(r.has_value(), "drivers/gpu/intel-gsc-fw", "selftest parse returned error");
    KASSERT(parsed.valid, "drivers/gpu/intel-gsc-fw", "selftest parsed.valid=false");
    KASSERT(parsed.num_entries_declared == 3u, "drivers/gpu/intel-gsc-fw", "selftest declared count mismatch");
    KASSERT(parsed.num_entries_walked == 3u, "drivers/gpu/intel-gsc-fw", "selftest walked count mismatch");
    KASSERT(parsed.fitc_version_packed == 0x04030201u, "drivers/gpu/intel-gsc-fw", "selftest fitc version mismatch");
    KASSERT(parsed.ftpr.size == 64u && parsed.ftpr.data != nullptr, "drivers/gpu/intel-gsc-fw",
            "selftest FTPR section missing");
    KASSERT(parsed.ftpr.data[0] == 0xA0u, "drivers/gpu/intel-gsc-fw", "selftest FTPR payload mismatch");
    KASSERT(parsed.oprom.size == 32u, "drivers/gpu/intel-gsc-fw", "selftest OPRO size mismatch");
    KASSERT(parsed.oprom.data[0] == 0xB0u, "drivers/gpu/intel-gsc-fw", "selftest OPRO payload mismatch");
    KASSERT(parsed.unknown_entries == 1u, "drivers/gpu/intel-gsc-fw", "selftest unknown count != 1");
    KASSERT(parsed.invalid_entries == 0u, "drivers/gpu/intel-gsc-fw", "selftest invalid count != 0");
    KASSERT(parsed.manufacturing_flags == 0u, "drivers/gpu/intel-gsc-fw", "selftest mfg flags should be 0");
    KASSERT(parsed.entries[0].kind == IntelGscPartitionKind::Ftpr, "drivers/gpu/intel-gsc-fw", "entry[0] kind != FTPR");
    KASSERT(parsed.entries[2].kind == IntelGscPartitionKind::Unknown, "drivers/gpu/intel-gsc-fw",
            "entry[2] kind != Unknown");

    // ROM-bypass-prefixed variant must round-trip identically.
    {
        static u8 b2[kBufBytes] = {};
        const u32 used2 = BuildSyntheticImage(b2, kBufBytes, 0x10203040u, /*with_rom_bypass=*/true);
        IntelGscFwParsed p2{};
        auto r2 = IntelGscFwParse(b2, used2, &p2);
        KASSERT(r2.has_value(), "drivers/gpu/intel-gsc-fw", "selftest rom-bypass parse failed");
        KASSERT(p2.rom_bypass_present, "drivers/gpu/intel-gsc-fw", "selftest rom-bypass flag should be set");
        KASSERT(p2.fitc_version_packed == 0x10203040u, "drivers/gpu/intel-gsc-fw", "selftest rom-bypass fitc mismatch");
        KASSERT(p2.ftpr.size == 64u, "drivers/gpu/intel-gsc-fw", "selftest rom-bypass FTPR size mismatch");
    }

    // Negative case: missing marker.
    {
        u8 bad[kIntelGscFptHeaderBytes + kIntelGscFptEntryBytes] = {};
        WriteLe32(bad, 0, 0xDEADBEEFu);
        IntelGscFwParsed p{};
        auto rr = IntelGscFwParse(bad, sizeof(bad), &p);
        KASSERT(!rr.has_value() && rr.error() == ::duetos::core::ErrorCode::Corrupt, "drivers/gpu/intel-gsc-fw",
                "selftest bad-marker should return Corrupt");
    }

    // Negative case: header present, num_entries way too large.
    {
        u8 oversize[kIntelGscFptHeaderBytes + kIntelGscFptEntryBytes] = {};
        WriteLe32(oversize, 0, kIntelGscFptMarker);
        WriteLe32(oversize, 4, 0x80000000u);
        IntelGscFwParsed p{};
        auto rr = IntelGscFwParse(oversize, sizeof(oversize), &p);
        KASSERT(!rr.has_value() && rr.error() == ::duetos::core::ErrorCode::Corrupt, "drivers/gpu/intel-gsc-fw",
                "selftest oversize-num-entries should return Corrupt");
    }

    // Negative case: entry array overflows declared blob size.
    {
        u8 ov[kIntelGscFptHeaderBytes + kIntelGscFptEntryBytes] = {};
        WriteLe32(ov, 0, kIntelGscFptMarker);
        WriteLe32(ov, 4, 4); // claims 4 entries but blob only fits 1
        IntelGscFwParsed p{};
        auto rr = IntelGscFwParse(ov, sizeof(ov), &p);
        KASSERT(!rr.has_value() && rr.error() == ::duetos::core::ErrorCode::Corrupt, "drivers/gpu/intel-gsc-fw",
                "selftest entry-array-overflow should return Corrupt");
    }

    // Negative case: short input.
    {
        u8 small[8] = {};
        IntelGscFwParsed p{};
        auto rr = IntelGscFwParse(small, sizeof(small), &p);
        KASSERT(!rr.has_value() && rr.error() == ::duetos::core::ErrorCode::InvalidArgument, "drivers/gpu/intel-gsc-fw",
                "selftest short-input should return InvalidArgument");
    }

    // Negative case: a single entry whose declared span leaves the
    // blob. The parse itself succeeds; that one entry is counted as
    // invalid, the FTPR slot is empty.
    {
        constexpr u32 kImg = kIntelGscFptHeaderBytes + kIntelGscFptEntryBytes;
        u8 bogus[kImg] = {};
        WriteLe32(bogus, 0, kIntelGscFptMarker);
        WriteLe32(bogus, 4, 1);
        WriteName(bogus, kIntelGscFptHeaderBytes + 0, "FTPR");
        WriteLe32(bogus, kIntelGscFptHeaderBytes + 8, 0xFFFF0000u); // offset way past blob
        WriteLe32(bogus, kIntelGscFptHeaderBytes + 12, 0x10);
        IntelGscFwParsed p{};
        auto rr = IntelGscFwParse(bogus, kImg, &p);
        KASSERT(rr.has_value(), "drivers/gpu/intel-gsc-fw", "selftest bogus-span parse should succeed");
        KASSERT(p.invalid_entries == 1u, "drivers/gpu/intel-gsc-fw", "selftest bogus-span invalid != 1");
        KASSERT(p.ftpr.data == nullptr && p.ftpr.size == 0u, "drivers/gpu/intel-gsc-fw",
                "selftest bogus-span FTPR slot should be empty");
    }

    // Manufacturing-flag detection: synthesize an image whose only
    // non-skeleton entry is MFTP. The parse must set bit 0.
    {
        constexpr u32 kImg = kIntelGscFptHeaderBytes + kIntelGscFptEntryBytes + 16;
        u8 mfg[kImg] = {};
        WriteLe32(mfg, 0, kIntelGscFptMarker);
        WriteLe32(mfg, 4, 1);
        WriteName(mfg, kIntelGscFptHeaderBytes + 0, "MFTP");
        WriteLe32(mfg, kIntelGscFptHeaderBytes + 8, kIntelGscFptHeaderBytes + kIntelGscFptEntryBytes);
        WriteLe32(mfg, kIntelGscFptHeaderBytes + 12, 16);
        IntelGscFwParsed p{};
        auto rr = IntelGscFwParse(mfg, kImg, &p);
        KASSERT(rr.has_value(), "drivers/gpu/intel-gsc-fw", "selftest mfg-detect parse should succeed");
        KASSERT((p.manufacturing_flags & 0x1u) != 0u, "drivers/gpu/intel-gsc-fw",
                "selftest mfg-detect bit 0 should be set");
    }

    arch::SerialWrite("[intel-gsc-fw] selftest pass\n");
}

} // namespace duetos::drivers::gpu::intel
