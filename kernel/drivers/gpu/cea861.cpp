#include "drivers/gpu/cea861.h"

#include "core/panic.h"
#include "drivers/video/console.h"

/*
 * Implementation reference: CEA-861-E §7 (Data Block Collection),
 * §A.4 (Extension format), CEA-861.3 (HDR static metadata + BT.2020
 * colorimetry). Cross-checked against Wikipedia EDID page and
 * VESA E-EDID Standard §5.
 *
 * No code from Linux drm_edid_cea, FreeBSD, ReactOS — only the
 * documented public byte-and-bit layout from the CEA spec.
 */

namespace duetos::drivers::gpu
{

namespace
{

// Pre-declared in this anonymous namespace so the parser can use
// it before the public Cea861ParseBlock exists.
EdidDtd DecodeDtd18(const u8* d);

bool IsTagValid(u8 b)
{
    return b == 0x02;
}

u8 ComputeChecksum(const u8* d)
{
    u32 sum = 0;
    for (u32 i = 0; i < 127; ++i)
        sum += d[i];
    return static_cast<u8>((256u - (sum & 0xFFu)) & 0xFFu);
}

void DecodeAudioBlock(const u8* payload, u32 length, Cea861ExtBlock& out)
{
    // Each SAD is exactly 3 bytes.
    for (u32 off = 0; off + 3 <= length && out.aud_count < kCea861MaxSads; off += 3)
    {
        const u8 b0 = payload[off];
        const u8 b1 = payload[off + 1];
        const u8 b2 = payload[off + 2];
        CeaSad& s = out.auds[out.aud_count++];
        s.format = static_cast<CeaAudioFormat>((b0 >> 3) & 0x0F);
        s.channels = static_cast<u8>((b0 & 0x07) + 1);
        s.sample_rate_flags = static_cast<u8>(b1 & 0x7F);
        s.byte2 = b2;
    }
}

void DecodeVideoBlock(const u8* payload, u32 length, Cea861ExtBlock& out)
{
    for (u32 i = 0; i < length && out.vid_count < kCea861MaxVics; ++i)
    {
        CeaSvd& s = out.vids[out.vid_count++];
        s.native = (payload[i] & 0x80) != 0;
        s.vic = static_cast<u8>(payload[i] & 0x7F);
    }
}

void DecodeSpeakerAllocation(const u8* payload, u32 length, Cea861ExtBlock& out)
{
    if (length < 3)
        return;
    out.speaker_allocation.present = true;
    const u8 b = payload[0];
    out.speaker_allocation.layout_byte = b;
    out.speaker_allocation.fl_fr = (b & 0x01) != 0;
    out.speaker_allocation.lfe = (b & 0x02) != 0;
    out.speaker_allocation.fc = (b & 0x04) != 0;
    out.speaker_allocation.rl_rr = (b & 0x08) != 0;
    out.speaker_allocation.rc = (b & 0x10) != 0;
    out.speaker_allocation.flc_frc = (b & 0x20) != 0;
    out.speaker_allocation.rlc_rrc = (b & 0x40) != 0;
    out.speaker_allocation.flw_frw = (b & 0x80) != 0;
}

void DecodeVsdb(const u8* payload, u32 length, Cea861ExtBlock& out)
{
    if (length < 3)
        return;
    // OUI is 24-bit little-endian at the start of the payload.
    const u32 oui =
        static_cast<u32>(payload[0]) | (static_cast<u32>(payload[1]) << 8) | (static_cast<u32>(payload[2]) << 16);
    if (oui != 0x000C03u)
        return; // not HDMI 1.4-style VSDB

    out.hdmi.present = true;
    if (length >= 5)
    {
        // Source physical address: 16 bits, big-endian. Often
        // rendered as "a.b.c.d" with each hex nibble.
        out.hdmi.source_physical_address = static_cast<u16>((static_cast<u32>(payload[3]) << 8) | payload[4]);
    }
    if (length >= 6)
        out.hdmi.support_flags = payload[5];
    if (length >= 7)
        out.hdmi.max_tmds_clock_5mhz = payload[6];
    if (length >= 9)
        out.hdmi.video_latency_ms = payload[7];
    if (length >= 9)
        out.hdmi.audio_latency_ms = payload[8];
}

void DecodeExtended(const u8* payload, u32 length, Cea861ExtBlock& out)
{
    if (length < 1)
        return;
    const CeaExtendedTag etag = static_cast<CeaExtendedTag>(payload[0]);
    switch (etag)
    {
    case CeaExtendedTag::HdrStaticMetadata:
    {
        // Layout (CEA-861.3 §7.5.13):
        //   payload[1] = EOTF supported bitmap
        //   payload[2] = metadata descriptor bitmap
        //   payload[3] = max luminance code (optional)
        //   payload[4] = max frame avg luminance code (optional)
        //   payload[5] = min luminance code (optional)
        out.hdr_static.present = true;
        if (length >= 2)
            out.hdr_static.eotf_supported_bitmap = payload[1];
        if (length >= 3)
            out.hdr_static.metadata_descriptor_bitmap = payload[2];
        if (length >= 4)
            out.hdr_static.max_luminance_code = payload[3];
        if (length >= 5)
            out.hdr_static.max_frame_avg_luminance_code = payload[4];
        if (length >= 6)
            out.hdr_static.min_luminance_code = payload[5];
        break;
    }
    case CeaExtendedTag::Colorimetry:
    {
        // payload[1] = colorimetry-supported bitmap (low byte)
        // payload[2] = bit map continuation + metadata bits
        out.colorimetry.present = true;
        if (length >= 2)
            out.colorimetry.supported_bitmap = payload[1];
        if (length >= 3)
        {
            // Per spec, byte 2 carries 8 more colorimetry bits plus
            // a 4-bit metadata profile. We capture the metadata bits
            // in a separate byte; the supported_bitmap is the union.
            out.colorimetry.supported_bitmap |= static_cast<u16>((payload[2] & 0xF0) << 4);
            out.colorimetry.metadata_bitmap = static_cast<u8>(payload[2] & 0x0F);
        }
        break;
    }
    default:
        break;
    }
}

EdidDtd DecodeDtd18(const u8* d)
{
    // Same shape as EDID base-block DTD. Inline a minimal decode
    // here so cea861.cpp doesn't need to be a friend of the
    // base-block parser's anon-namespace helpers.
    EdidDtd t = {};
    const u16 px = static_cast<u16>(d[0] | (d[1] << 8));
    t.pixel_clock_khz = static_cast<u32>(px) * 10u;
    t.h_active = static_cast<u16>(d[2] | ((d[4] & 0xF0u) << 4));
    t.h_blanking = static_cast<u16>(d[3] | ((d[4] & 0x0Fu) << 8));
    t.v_active = static_cast<u16>(d[5] | ((d[7] & 0xF0u) << 4));
    t.v_blanking = static_cast<u16>(d[6] | ((d[7] & 0x0Fu) << 8));
    t.h_sync_offset = static_cast<u16>(d[8] | (((d[11] >> 6) & 0x03u) << 8));
    t.h_sync_pulse = static_cast<u16>(d[9] | (((d[11] >> 4) & 0x03u) << 8));
    const u8 v_off_low = (d[10] >> 4) & 0x0F;
    const u8 v_pulse_low = d[10] & 0x0F;
    t.v_sync_offset = static_cast<u16>(v_off_low | (((d[11] >> 2) & 0x03u) << 4));
    t.v_sync_pulse = static_cast<u16>(v_pulse_low | ((d[11] & 0x03u) << 4));
    t.h_image_mm = static_cast<u16>(d[12] | ((d[14] & 0xF0u) << 4));
    t.v_image_mm = static_cast<u16>(d[13] | ((d[14] & 0x0Fu) << 8));
    const u8 flags = d[17];
    t.interlaced = (flags & 0x80) != 0;
    t.sync_type = static_cast<u8>((flags >> 3) & 0x03);
    if (t.sync_type == 3)
    {
        t.v_sync_positive = (flags & 0x04) != 0;
        t.h_sync_positive = (flags & 0x02) != 0;
    }
    const u32 h_total = static_cast<u32>(t.h_active) + t.h_blanking;
    const u32 v_total = static_cast<u32>(t.v_active) + t.v_blanking;
    if (h_total != 0 && v_total != 0)
    {
        const u64 num = static_cast<u64>(t.pixel_clock_khz) * 1000000ULL;
        t.refresh_mhz = static_cast<u32>(num / (static_cast<u64>(h_total) * v_total));
    }
    return t;
}

bool LooksLikeDtd(const u8* d)
{
    // Real DTD ⇔ bytes 0-1 != 0 (pixel clock != 0).
    return !(d[0] == 0 && d[1] == 0);
}

void WriteDec(u32 v)
{
    using ::duetos::drivers::video::ConsoleWrite;
    char buf[12];
    u32 i = 0;
    if (v == 0)
    {
        ConsoleWrite("0");
        return;
    }
    while (v != 0 && i < sizeof(buf))
    {
        buf[i++] = static_cast<char>('0' + (v % 10));
        v /= 10;
    }
    char rev[12];
    for (u32 j = 0; j < i; ++j)
        rev[j] = buf[i - 1 - j];
    rev[i] = '\0';
    ConsoleWrite(rev);
}

void WriteHex2(u8 v)
{
    using ::duetos::drivers::video::ConsoleWrite;
    const char* d = "0123456789ABCDEF";
    char hx[3] = {d[(v >> 4) & 0xF], d[v & 0xF], 0};
    ConsoleWrite("0x");
    ConsoleWrite(hx);
}

} // namespace

const char* CeaAudioFormatName(CeaAudioFormat f)
{
    switch (f)
    {
    case CeaAudioFormat::Lpcm:
        return "LPCM";
    case CeaAudioFormat::Ac3:
        return "AC-3";
    case CeaAudioFormat::Mpeg1:
        return "MPEG-1";
    case CeaAudioFormat::Mp3:
        return "MP3";
    case CeaAudioFormat::Mpeg2:
        return "MPEG-2";
    case CeaAudioFormat::AacLc:
        return "AAC-LC";
    case CeaAudioFormat::Dts:
        return "DTS";
    case CeaAudioFormat::Atrac:
        return "ATRAC";
    case CeaAudioFormat::OneBitAudio:
        return "OneBit";
    case CeaAudioFormat::Eac3:
        return "E-AC-3";
    case CeaAudioFormat::DtsHd:
        return "DTS-HD";
    case CeaAudioFormat::MatMlp:
        return "MAT/MLP";
    case CeaAudioFormat::Dst:
        return "DST";
    case CeaAudioFormat::WmaPro:
        return "WMA Pro";
    case CeaAudioFormat::Extended:
        return "ext";
    default:
        return "rsvd";
    }
}

const char* CeaVicName(u8 vic, char scratch[16])
{
    // Subset table covering CEA-861-E's first ~32 modes (the most
    // common). Beyond that, format into the scratch buffer.
    static const char* const k[] = {
        nullptr,
        "640x480p@60",
        "720x480p@60 4:3",
        "720x480p@60 16:9",
        "1280x720p@60",
        "1920x1080i@60",
        "720(1440)x480i@60 4:3",
        "720(1440)x480i@60 16:9",
        "720(1440)x240p@60 4:3",
        "720(1440)x240p@60 16:9",
        "2880x480i@60 4:3",
        "2880x480i@60 16:9",
        "2880x240p@60 4:3",
        "2880x240p@60 16:9",
        "1440x480p@60 4:3",
        "1440x480p@60 16:9",
        "1920x1080p@60",
        "720x576p@50 4:3",
        "720x576p@50 16:9",
        "1280x720p@50",
        "1920x1080i@50",
        "720(1440)x576i@50 4:3",
        "720(1440)x576i@50 16:9",
        "720(1440)x288p@50 4:3",
        "720(1440)x288p@50 16:9",
        "2880x576i@50 4:3",
        "2880x576i@50 16:9",
        "2880x288p@50 4:3",
        "2880x288p@50 16:9",
        "1440x576p@50 4:3",
        "1440x576p@50 16:9",
        "1920x1080p@50",
        "1920x1080p@24",
        "1920x1080p@25",
        "1920x1080p@30",
    };
    if (vic < sizeof(k) / sizeof(k[0]) && k[vic] != nullptr)
        return k[vic];
    // Format "vic-N" into scratch.
    if (scratch == nullptr)
        return "vic-?";
    const char* p = "vic-";
    u32 i = 0;
    while (p[i] != 0 && i < 15)
    {
        scratch[i] = p[i];
        ++i;
    }
    char dec[6];
    u32 di = 0;
    u32 v = vic;
    if (v == 0)
        dec[di++] = '0';
    while (v != 0 && di < sizeof(dec))
    {
        dec[di++] = static_cast<char>('0' + (v % 10));
        v /= 10;
    }
    while (di > 0 && i < 15)
        scratch[i++] = dec[--di];
    scratch[i] = '\0';
    return scratch;
}

::duetos::core::Result<Cea861ExtBlock> Cea861ParseBlock(const u8* data, u64 length)
{
    if (data == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    if (length < kCea861BlockBytes)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};

    Cea861ExtBlock blk = {};
    blk.tag_valid = IsTagValid(data[0]);
    blk.computed_checksum = ComputeChecksum(data);
    blk.stored_checksum = data[127];
    blk.checksum_valid = (blk.computed_checksum == blk.stored_checksum);
    blk.revision = data[1];
    blk.dtd_start_offset = data[2];

    const u8 flags = data[3];
    blk.supports_underscan = (flags & 0x80) != 0;
    blk.supports_audio = (flags & 0x40) != 0;
    blk.supports_ycbcr_444 = (flags & 0x20) != 0;
    blk.supports_ycbcr_422 = (flags & 0x10) != 0;
    blk.native_dtd_count = static_cast<u8>(flags & 0x0F);

    // Walk the DBC. Bytes 4..(dtd_start - 1) carry data blocks; if
    // dtd_start == 0 ("no DTDs"), the DBC runs through byte 126.
    const u32 dbc_end = (blk.dtd_start_offset == 0) ? 127 : blk.dtd_start_offset;
    if (dbc_end < 4 || dbc_end > 127)
    {
        blk.parse_end_offset = 4;
        return blk;
    }

    u32 off = 4;
    while (off < dbc_end)
    {
        const u8 hdr = data[off];
        const u32 length_bytes = hdr & 0x1F;
        const CeaTag tag = static_cast<CeaTag>((hdr >> 5) & 0x07);
        const u32 next_off = off + 1 + length_bytes;
        if (next_off > dbc_end)
        {
            // Truncated DBC entry — record the parse stop point so
            // the diagnostic dump shows where the malformation
            // begins, then bail.
            blk.parse_end_offset = static_cast<u8>(off);
            break;
        }
        const u8* payload = &data[off + 1];

        switch (tag)
        {
        case CeaTag::Audio:
            DecodeAudioBlock(payload, length_bytes, blk);
            break;
        case CeaTag::Video:
            DecodeVideoBlock(payload, length_bytes, blk);
            break;
        case CeaTag::VendorSpecific:
            DecodeVsdb(payload, length_bytes, blk);
            break;
        case CeaTag::SpeakerAllocation:
            DecodeSpeakerAllocation(payload, length_bytes, blk);
            break;
        case CeaTag::Extended:
            DecodeExtended(payload, length_bytes, blk);
            break;
        default:
            // Unknown / reserved tag: skip the payload.
            break;
        }
        off = next_off;
    }
    blk.parse_end_offset = static_cast<u8>(off);

    // Walk the DTD list. DTDs are 18 bytes, packed from
    // dtd_start_offset to byte 126. Stop when we hit a zero-clock
    // DTD or run out of room.
    if (blk.dtd_start_offset >= 4 && blk.dtd_start_offset <= 126 - 18)
    {
        u32 dtd_off = blk.dtd_start_offset;
        while (dtd_off + 18 <= 127 && blk.dtd_count < kCea861MaxDtds)
        {
            if (!LooksLikeDtd(&data[dtd_off]))
                break;
            blk.dtds[blk.dtd_count++] = DecodeDtd18(&data[dtd_off]);
            dtd_off += 18;
        }
    }

    return blk;
}

void Cea861DumpToConsole(const Cea861ExtBlock& blk)
{
    using ::duetos::drivers::video::ConsoleWrite;
    using ::duetos::drivers::video::ConsoleWriteln;

    ConsoleWrite("CEA-861  tag=");
    ConsoleWrite(blk.tag_valid ? "OK" : "BAD");
    ConsoleWrite("  checksum=");
    ConsoleWrite(blk.checksum_valid ? "OK" : "BAD");
    ConsoleWrite("  rev=");
    WriteDec(blk.revision);
    ConsoleWrite("  flags=");
    if (blk.supports_underscan)
        ConsoleWrite("under ");
    if (blk.supports_audio)
        ConsoleWrite("audio ");
    if (blk.supports_ycbcr_444)
        ConsoleWrite("ycbcr444 ");
    if (blk.supports_ycbcr_422)
        ConsoleWrite("ycbcr422 ");
    ConsoleWrite(" native-dtds=");
    WriteDec(blk.native_dtd_count);
    ConsoleWriteln("");

    if (blk.vid_count != 0)
    {
        ConsoleWrite("  video[");
        WriteDec(blk.vid_count);
        ConsoleWrite("]:");
        for (u32 i = 0; i < blk.vid_count; ++i)
        {
            char scratch[16];
            ConsoleWrite("  ");
            ConsoleWrite(CeaVicName(blk.vids[i].vic, scratch));
            if (blk.vids[i].native)
                ConsoleWrite("*");
        }
        ConsoleWriteln("");
    }
    if (blk.aud_count != 0)
    {
        ConsoleWrite("  audio[");
        WriteDec(blk.aud_count);
        ConsoleWrite("]:");
        for (u32 i = 0; i < blk.aud_count; ++i)
        {
            ConsoleWrite("  ");
            ConsoleWrite(CeaAudioFormatName(blk.auds[i].format));
            ConsoleWrite("/");
            WriteDec(blk.auds[i].channels);
            ConsoleWrite("ch");
        }
        ConsoleWriteln("");
    }
    if (blk.speaker_allocation.present)
    {
        ConsoleWrite("  speakers:");
        if (blk.speaker_allocation.fl_fr)
            ConsoleWrite(" FL/FR");
        if (blk.speaker_allocation.lfe)
            ConsoleWrite(" LFE");
        if (blk.speaker_allocation.fc)
            ConsoleWrite(" FC");
        if (blk.speaker_allocation.rl_rr)
            ConsoleWrite(" RL/RR");
        if (blk.speaker_allocation.rc)
            ConsoleWrite(" RC");
        ConsoleWriteln("");
    }
    if (blk.hdmi.present)
    {
        ConsoleWrite("  HDMI VSDB:  source-phys=");
        WriteHex2(static_cast<u8>(blk.hdmi.source_physical_address >> 8));
        WriteHex2(static_cast<u8>(blk.hdmi.source_physical_address & 0xFF));
        ConsoleWrite("  max-tmds=");
        WriteDec(static_cast<u32>(blk.hdmi.max_tmds_clock_5mhz) * 5);
        ConsoleWrite(" MHz  flags=");
        WriteHex2(blk.hdmi.support_flags);
        ConsoleWriteln("");
    }
    if (blk.hdr_static.present)
    {
        ConsoleWrite("  HDR static:  EOTF=");
        WriteHex2(blk.hdr_static.eotf_supported_bitmap);
        ConsoleWrite("  max-lum-code=");
        WriteDec(blk.hdr_static.max_luminance_code);
        ConsoleWrite("  min-lum-code=");
        WriteDec(blk.hdr_static.min_luminance_code);
        ConsoleWriteln("");
    }
    if (blk.colorimetry.present)
    {
        ConsoleWrite("  colorimetry: bitmap=");
        WriteHex2(static_cast<u8>(blk.colorimetry.supported_bitmap & 0xFF));
        ConsoleWriteln("");
    }
    if (blk.dtd_count != 0)
    {
        ConsoleWrite("  DTDs[");
        WriteDec(blk.dtd_count);
        ConsoleWriteln("]:");
        for (u32 i = 0; i < blk.dtd_count; ++i)
        {
            const EdidDtd& t = blk.dtds[i];
            ConsoleWrite("    ");
            WriteDec(t.h_active);
            ConsoleWrite("x");
            WriteDec(t.v_active);
            ConsoleWrite(t.interlaced ? "i" : "p");
            ConsoleWrite(" @ ");
            WriteDec(t.refresh_mhz / 1000);
            ConsoleWrite(" Hz");
            ConsoleWriteln("");
        }
    }
}

} // namespace duetos::drivers::gpu
