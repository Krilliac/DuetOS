#include "drivers/gpu/nvidia_gsp_fw.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"
#include "log/klog.h"

/*
 * DuetOS — NVIDIA GSP firmware-image (nvfw_bin_hdr) parser
 * implementation.
 *
 * Container layout described in `nvidia_gsp_fw.h`. The 24-byte
 * outer header is followed by a per-arch inner descriptor; the
 * descriptor's size (data_offset - header_offset) is what tells
 * us whether we're looking at a Turing/GA100 image (76 bytes) or
 * a GA102+ one (84 bytes). The actual descriptor fields differ
 * per arch and aren't decoded by v0 — the next slice (HS header +
 * WPR layout builder) handles them.
 */

namespace duetos::drivers::gpu::nvidia
{

namespace
{

u32 LeU32(const u8* p)
{
    return static_cast<u32>(p[0]) | (static_cast<u32>(p[1]) << 8) | (static_cast<u32>(p[2]) << 16) |
           (static_cast<u32>(p[3]) << 24);
}

} // namespace

NvidiaGspArchClass NvidiaGspClassifyDescriptor(u32 descriptor_size)
{
    if (descriptor_size == kNvidiaDescBytesTuringGa100)
        return NvidiaGspArchClass::TuringOrGa100;
    if (descriptor_size == kNvidiaDescBytesGa102Plus)
        return NvidiaGspArchClass::Ga102OrNewer;
    return NvidiaGspArchClass::Unknown;
}

::duetos::core::Result<void> NvidiaGspFwParse(const u8* blob, u32 blob_size, NvidiaGspFwParsed* parsed)
{
    if (parsed == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    *parsed = NvidiaGspFwParsed{};

    if (blob == nullptr || blob_size < kNvidiaBinHdrBytes)
    {
        parsed->reject_reason |= kNvFwRejectBlobTooShort;
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    }

    parsed->bin_magic = LeU32(blob + 0x00);
    parsed->bin_ver = LeU32(blob + 0x04);
    parsed->bin_size = LeU32(blob + 0x08);
    parsed->header_offset = LeU32(blob + 0x0C);
    parsed->data_offset = LeU32(blob + 0x10);
    parsed->data_size = LeU32(blob + 0x14);

    if (parsed->bin_magic != kNvidiaBinHdrMagic)
    {
        parsed->reject_reason |= kNvFwRejectBadMagic;
        return ::duetos::core::Err{::duetos::core::ErrorCode::Corrupt};
    }
    if (parsed->bin_ver != kNvidiaBinHdrVerExpected)
    {
        // Newer container revisions might rearrange fields; refuse
        // them rather than silently mis-parsing.
        parsed->reject_reason |= kNvFwRejectBadVersion;
        return ::duetos::core::Err{::duetos::core::ErrorCode::Corrupt};
    }
    if (parsed->data_size > kNvidiaMaxGspImageBytes)
    {
        parsed->reject_reason |= kNvFwRejectOversize;
        return ::duetos::core::Err{::duetos::core::ErrorCode::Corrupt};
    }
    if (parsed->header_offset != kNvidiaBinHdrBytes)
    {
        // The publicly-documented layout puts the inner descriptor
        // immediately after the outer header. Anything else means a
        // pre/post amendment we don't understand.
        parsed->reject_reason |= kNvFwRejectHeaderOffset;
        return ::duetos::core::Err{::duetos::core::ErrorCode::Corrupt};
    }
    if (parsed->data_offset < parsed->header_offset + kNvidiaDescBytesTuringGa100)
    {
        parsed->reject_reason |= kNvFwRejectDescTooSmall;
        return ::duetos::core::Err{::duetos::core::ErrorCode::Corrupt};
    }
    const u64 data_end = static_cast<u64>(parsed->data_offset) + parsed->data_size;
    if (parsed->data_offset >= blob_size || data_end > blob_size)
    {
        parsed->reject_reason |= kNvFwRejectDataBounds;
        return ::duetos::core::Err{::duetos::core::ErrorCode::Corrupt};
    }

    parsed->descriptor_offset = parsed->header_offset;
    parsed->descriptor_size = parsed->data_offset - parsed->header_offset;
    parsed->arch_class = NvidiaGspClassifyDescriptor(parsed->descriptor_size);

    parsed->payload = blob + parsed->data_offset;
    parsed->payload_size = parsed->data_size;
    // ELF magic check is advisory — a payload that doesn't start
    // with `\x7fELF` is still structurally valid at the container
    // level. The ELF walker (next slice) is the place to enforce.
    parsed->payload_looks_elf = (parsed->data_size >= 4 && parsed->payload[0] == 0x7Fu && parsed->payload[1] == 'E' &&
                                 parsed->payload[2] == 'L' && parsed->payload[3] == 'F');

    parsed->valid = true;
    return {};
}

void NvidiaGspFwLog(const char* basename, const NvidiaGspFwParsed& parsed)
{
    if (!parsed.valid)
        return;
    const char* arch_tag = "unknown-arch";
    switch (parsed.arch_class)
    {
    case NvidiaGspArchClass::TuringOrGa100:
        arch_tag = "TU10x/GA100";
        break;
    case NvidiaGspArchClass::Ga102OrNewer:
        arch_tag = "GA102+";
        break;
    case NvidiaGspArchClass::Unknown:
    default:
        arch_tag = "unknown-desc-size";
        break;
    }
    arch::SerialWrite("[gpu/nvidia-fw] ");
    arch::SerialWrite(basename);
    arch::SerialWrite(" arch=");
    arch::SerialWrite(arch_tag);
    arch::SerialWrite(" desc_bytes=");
    arch::SerialWriteHex(parsed.descriptor_size);
    arch::SerialWrite(" payload_bytes=");
    arch::SerialWriteHex(parsed.payload_size);
    arch::SerialWrite(parsed.payload_looks_elf ? " elf=yes" : " elf=no");
    arch::SerialWrite("\n");
}

namespace
{

void PutU32(u8* p, u32 v)
{
    p[0] = static_cast<u8>(v & 0xFFu);
    p[1] = static_cast<u8>((v >> 8) & 0xFFu);
    p[2] = static_cast<u8>((v >> 16) & 0xFFu);
    p[3] = static_cast<u8>((v >> 24) & 0xFFu);
}

// Build a synthetic GSP container into `buf` (caller-supplied,
// large enough for the header + descriptor + payload). Returns the
// total bytes used. The descriptor and payload bytes are filled
// with index-derived patterns so a later upload sequence has
// something concrete to verify against.
u32 BuildSyntheticImage(u8* buf, u32 descriptor_size, u32 payload_size, bool elf_magic)
{
    const u32 header_offset = kNvidiaBinHdrBytes;
    const u32 data_offset = header_offset + descriptor_size;
    const u32 total = data_offset + payload_size;
    PutU32(buf + 0x00, kNvidiaBinHdrMagic);
    PutU32(buf + 0x04, kNvidiaBinHdrVerExpected);
    PutU32(buf + 0x08, total);
    PutU32(buf + 0x0C, header_offset);
    PutU32(buf + 0x10, data_offset);
    PutU32(buf + 0x14, payload_size);
    // Descriptor body (opaque to v0).
    for (u32 i = 0; i < descriptor_size; ++i)
        buf[header_offset + i] = static_cast<u8>(0xA0u + (i & 0xFu));
    // Payload — optionally led by ELF magic so the parser flags it.
    for (u32 i = 0; i < payload_size; ++i)
        buf[data_offset + i] = static_cast<u8>(i & 0xFFu);
    if (elf_magic && payload_size >= 4)
    {
        buf[data_offset + 0] = 0x7Fu;
        buf[data_offset + 1] = 'E';
        buf[data_offset + 2] = 'L';
        buf[data_offset + 3] = 'F';
    }
    return total;
}

void Fail(const char* tag, u32 detail)
{
    KBP_PROBE_V(::duetos::debug::ProbeId::kBootSelftestFail, detail);
    KLOG_WARN_V("drivers/gpu/nvidia-fw", tag, detail);
}

} // namespace

void NvidiaGspFwSelfTest()
{
    static u8 buf[4096];

    // Happy path 1: TU10x-class image (76-byte descriptor).
    {
        const u32 total =
            BuildSyntheticImage(buf, kNvidiaDescBytesTuringGa100, /*payload_size=*/512, /*elf_magic=*/true);
        NvidiaGspFwParsed p{};
        auto r = NvidiaGspFwParse(buf, total, &p);
        if (!r.has_value() || !p.valid)
        {
            Fail("TU10x parse rejected", p.reject_reason);
            return;
        }
        if (p.arch_class != NvidiaGspArchClass::TuringOrGa100)
        {
            Fail("TU10x arch_class wrong", static_cast<u32>(p.arch_class));
            return;
        }
        if (p.descriptor_size != kNvidiaDescBytesTuringGa100 || p.payload_size != 512u)
        {
            Fail("TU10x descriptor/payload size wrong", p.descriptor_size);
            return;
        }
        if (!p.payload_looks_elf)
        {
            Fail("TU10x payload ELF magic missed", 0);
            return;
        }
    }

    // Happy path 2: GA102+-class image (84-byte descriptor), no ELF.
    {
        const u32 total =
            BuildSyntheticImage(buf, kNvidiaDescBytesGa102Plus, /*payload_size=*/1024, /*elf_magic=*/false);
        NvidiaGspFwParsed p{};
        auto r = NvidiaGspFwParse(buf, total, &p);
        if (!r.has_value() || !p.valid)
        {
            Fail("GA102 parse rejected", p.reject_reason);
            return;
        }
        if (p.arch_class != NvidiaGspArchClass::Ga102OrNewer)
        {
            Fail("GA102 arch_class wrong", static_cast<u32>(p.arch_class));
            return;
        }
        if (p.payload_looks_elf)
        {
            Fail("GA102 payload ELF magic false positive", 0);
            return;
        }
    }

    // Reject: short blob.
    {
        NvidiaGspFwParsed p{};
        auto r = NvidiaGspFwParse(buf, kNvidiaBinHdrBytes - 1u, &p);
        if (r.has_value() || (p.reject_reason & kNvFwRejectBlobTooShort) == 0)
        {
            Fail("short-blob check did not trip", p.reject_reason);
            return;
        }
    }

    // Reject: bad magic.
    {
        BuildSyntheticImage(buf, kNvidiaDescBytesTuringGa100, 256, false);
        PutU32(buf + 0x00, 0xDEAD0000u);
        NvidiaGspFwParsed p{};
        auto r = NvidiaGspFwParse(buf, kNvidiaBinHdrBytes + kNvidiaDescBytesTuringGa100 + 256u, &p);
        if (r.has_value() || (p.reject_reason & kNvFwRejectBadMagic) == 0)
        {
            Fail("bad-magic check did not trip", p.reject_reason);
            return;
        }
    }

    // Reject: bad version.
    {
        BuildSyntheticImage(buf, kNvidiaDescBytesTuringGa100, 256, false);
        PutU32(buf + 0x04, 99u);
        NvidiaGspFwParsed p{};
        auto r = NvidiaGspFwParse(buf, kNvidiaBinHdrBytes + kNvidiaDescBytesTuringGa100 + 256u, &p);
        if (r.has_value() || (p.reject_reason & kNvFwRejectBadVersion) == 0)
        {
            Fail("bad-version check did not trip", p.reject_reason);
            return;
        }
    }

    // Reject: header_offset isn't 24.
    {
        BuildSyntheticImage(buf, kNvidiaDescBytesTuringGa100, 256, false);
        PutU32(buf + 0x0C, 32u);
        NvidiaGspFwParsed p{};
        auto r = NvidiaGspFwParse(buf, kNvidiaBinHdrBytes + kNvidiaDescBytesTuringGa100 + 256u, &p);
        if (r.has_value() || (p.reject_reason & kNvFwRejectHeaderOffset) == 0)
        {
            Fail("header-offset check did not trip", p.reject_reason);
            return;
        }
    }

    // Reject: descriptor too small (less than 76 bytes between
    // header_offset and data_offset).
    {
        // Manually build a header with too-small descriptor span.
        const u32 desc = 32u;
        const u32 payload = 128u;
        const u32 data_off = kNvidiaBinHdrBytes + desc;
        const u32 total = data_off + payload;
        PutU32(buf + 0x00, kNvidiaBinHdrMagic);
        PutU32(buf + 0x04, kNvidiaBinHdrVerExpected);
        PutU32(buf + 0x08, total);
        PutU32(buf + 0x0C, kNvidiaBinHdrBytes);
        PutU32(buf + 0x10, data_off);
        PutU32(buf + 0x14, payload);
        NvidiaGspFwParsed p{};
        auto r = NvidiaGspFwParse(buf, total, &p);
        if (r.has_value() || (p.reject_reason & kNvFwRejectDescTooSmall) == 0)
        {
            Fail("desc-too-small check did not trip", p.reject_reason);
            return;
        }
    }

    // Reject: data_offset + data_size leaves the blob.
    {
        const u32 desc = kNvidiaDescBytesTuringGa100;
        const u32 payload = 256u;
        const u32 data_off = kNvidiaBinHdrBytes + desc;
        // Declared payload way past the actual blob end.
        PutU32(buf + 0x00, kNvidiaBinHdrMagic);
        PutU32(buf + 0x04, kNvidiaBinHdrVerExpected);
        PutU32(buf + 0x08, data_off + payload);
        PutU32(buf + 0x0C, kNvidiaBinHdrBytes);
        PutU32(buf + 0x10, data_off);
        PutU32(buf + 0x14, 0x10000u); // claim 64 KiB but only 256 B follow
        NvidiaGspFwParsed p{};
        auto r = NvidiaGspFwParse(buf, data_off + payload, &p);
        if (r.has_value() || (p.reject_reason & kNvFwRejectDataBounds) == 0)
        {
            Fail("data-bounds check did not trip", p.reject_reason);
            return;
        }
    }

    // Reject: oversize sanity cap (data_size > 64 MiB).
    {
        PutU32(buf + 0x00, kNvidiaBinHdrMagic);
        PutU32(buf + 0x04, kNvidiaBinHdrVerExpected);
        PutU32(buf + 0x08, kNvidiaBinHdrBytes + kNvidiaDescBytesTuringGa100 + 256u);
        PutU32(buf + 0x0C, kNvidiaBinHdrBytes);
        PutU32(buf + 0x10, kNvidiaBinHdrBytes + kNvidiaDescBytesTuringGa100);
        PutU32(buf + 0x14, kNvidiaMaxGspImageBytes + 1u);
        NvidiaGspFwParsed p{};
        auto r = NvidiaGspFwParse(buf, kNvidiaBinHdrBytes + kNvidiaDescBytesTuringGa100 + 256u, &p);
        if (r.has_value() || (p.reject_reason & kNvFwRejectOversize) == 0)
        {
            Fail("oversize check did not trip", p.reject_reason);
            return;
        }
    }

    arch::SerialWrite("[gpu/nvidia-fw] selftest PASS (2 arches + 7 reject paths)\n");
}

} // namespace duetos::drivers::gpu::nvidia
