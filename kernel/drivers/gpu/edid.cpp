#include "drivers/gpu/edid.h"

#include "drivers/video/console.h"

/*
 * Implementation reference: VESA E-EDID Standard Release A2 (2006)
 * §3 (base block layout) and §3.10 (detailed timing descriptor).
 * Cross-checked against the OSDev Wiki EDID page and the Wikipedia
 * EDID article for established-timings bit assignments.
 *
 * No code is taken from Linux drm_edid.c, FreeBSD's drm_edid, or
 * ReactOS — only the documented bit-and-byte layout from the VESA
 * spec is used.
 */

namespace duetos::drivers::gpu
{

namespace
{

constexpr u8 kHeader[8] = {0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00};

bool IsHeaderValid(const u8* data)
{
    for (u32 i = 0; i < 8; ++i)
    {
        if (data[i] != kHeader[i])
            return false;
    }
    return true;
}

u8 ComputeChecksum(const u8* data)
{
    u32 sum = 0;
    for (u32 i = 0; i < 127; ++i)
        sum += data[i];
    return static_cast<u8>((256u - (sum & 0xFFu)) & 0xFFu);
}

void DecodeManufacturerId(u16 be_word, char out[4])
{
    // Bytes 8-9 are big-endian: byte 8 holds char1 high bits.
    // Each character is 5 bits, mapped onto 'A'..'Z' as 1..26.
    // A value of 0 or > 26 is reserved; we still emit a printable
    // glyph ('?') so logs don't show a NUL.
    const u8 c1 = static_cast<u8>((be_word >> 10) & 0x1F);
    const u8 c2 = static_cast<u8>((be_word >> 5) & 0x1F);
    const u8 c3 = static_cast<u8>(be_word & 0x1F);
    auto map = [](u8 v) -> char
    {
        if (v >= 1 && v <= 26)
            return static_cast<char>('A' + (v - 1));
        return '?';
    };
    out[0] = map(c1);
    out[1] = map(c2);
    out[2] = map(c3);
    out[3] = '\0';
}

EdidVideoInput DecodeVideoInput(u8 byte)
{
    EdidVideoInput v = {};
    v.raw_byte = byte;
    v.digital = (byte & 0x80) != 0;
    if (v.digital)
    {
        // EDID 1.4 layout. Bit 6:4 = bit depth; 3:0 = interface.
        // Older EDID 1.3 digital input only sets bit 0 (DFP 1.x);
        // bit_depth field reads as 0 (= "undefined") then.
        const u8 depth_bits = (byte >> 4) & 0x07;
        switch (depth_bits)
        {
        case 0:
            v.digital_bit_depth = 0;
            break;
        case 1:
            v.digital_bit_depth = 6;
            break;
        case 2:
            v.digital_bit_depth = 8;
            break;
        case 3:
            v.digital_bit_depth = 10;
            break;
        case 4:
            v.digital_bit_depth = 12;
            break;
        case 5:
            v.digital_bit_depth = 14;
            break;
        case 6:
            v.digital_bit_depth = 16;
            break;
        default:
            v.digital_bit_depth = 0; // reserved
            break;
        }
        v.digital_interface = byte & 0x0F;
    }
    else
    {
        v.digital_bit_depth = -1;
        v.digital_interface = 0;
    }
    return v;
}

EdidFeatures DecodeFeatures(u8 byte)
{
    EdidFeatures f = {};
    f.dpms_standby = (byte & 0x80) != 0;
    f.dpms_suspend = (byte & 0x40) != 0;
    f.dpms_active_off = (byte & 0x20) != 0;
    f.display_type_bits = static_cast<u8>((byte >> 3) & 0x03);
    f.srgb_default = (byte & 0x04) != 0;
    f.preferred_timing_in_dtd1 = (byte & 0x02) != 0;
    f.continuous_frequency = (byte & 0x01) != 0;
    return f;
}

EdidEstablishedTimings DecodeEstablishedTimings(u8 b0, u8 b1, u8 b2)
{
    EdidEstablishedTimings t = {};
    t.t_720x400_70 = (b0 & 0x80) != 0;
    t.t_720x400_88 = (b0 & 0x40) != 0;
    t.t_640x480_60 = (b0 & 0x20) != 0;
    t.t_640x480_67 = (b0 & 0x10) != 0;
    t.t_640x480_72 = (b0 & 0x08) != 0;
    t.t_640x480_75 = (b0 & 0x04) != 0;
    t.t_800x600_56 = (b0 & 0x02) != 0;
    t.t_800x600_60 = (b0 & 0x01) != 0;
    t.t_800x600_72 = (b1 & 0x80) != 0;
    t.t_800x600_75 = (b1 & 0x40) != 0;
    t.t_832x624_75 = (b1 & 0x20) != 0;
    t.t_1024x768_87i = (b1 & 0x10) != 0;
    t.t_1024x768_60 = (b1 & 0x08) != 0;
    t.t_1024x768_70 = (b1 & 0x04) != 0;
    t.t_1024x768_75 = (b1 & 0x02) != 0;
    t.t_1280x1024_75 = (b1 & 0x01) != 0;
    t.t_1152x870_75 = (b2 & 0x80) != 0;
    return t;
}

EdidStandardTiming DecodeStandardTiming(u8 b0, u8 b1)
{
    EdidStandardTiming s = {};
    if (b0 == 0x01 && b1 == 0x01)
        return s; // unused slot
    if (b0 == 0x00 && b1 == 0x00)
        return s; // also legal "unused" encoding seen in the wild
    s.width = static_cast<u16>((static_cast<u32>(b0) + 31u) * 8u);
    s.aspect_bits = static_cast<u8>((b1 >> 6) & 0x03);
    s.refresh_hz = static_cast<u8>((b1 & 0x3F) + 60);
    s.height = EdidStandardTimingHeight(s.width, s.aspect_bits);
    return s;
}

EdidDtd DecodeDtd(const u8* d)
{
    EdidDtd t = {};
    const u16 px_clk_units = static_cast<u16>(d[0] | (d[1] << 8));
    t.pixel_clock_khz = static_cast<u32>(px_clk_units) * 10u;

    // Active + blanking are 12-bit values split across three
    // bytes. Low 8 bits sit in their own byte; high 4 bits live
    // in the upper or lower nibble of a shared byte (byte 4 for
    // horizontal, byte 7 for vertical).
    t.h_active = static_cast<u16>(d[2] | ((d[4] & 0xF0u) << 4));
    t.h_blanking = static_cast<u16>(d[3] | ((d[4] & 0x0Fu) << 8));
    t.v_active = static_cast<u16>(d[5] | ((d[7] & 0xF0u) << 4));
    t.v_blanking = static_cast<u16>(d[6] | ((d[7] & 0x0Fu) << 8));

    // Sync offsets/widths: 10-bit each, packed across bytes 8-11.
    //   d[8]      = h_sync_offset[7:0]
    //   d[9]      = h_sync_pulse[7:0]
    //   d[10] hi  = v_sync_offset[3:0]   (low nibble of 6-bit)
    //   d[10] lo  = v_sync_pulse[3:0]
    //   d[11] 7:6 = h_sync_offset[9:8]
    //   d[11] 5:4 = h_sync_pulse[9:8]
    //   d[11] 3:2 = v_sync_offset[5:4]
    //   d[11] 1:0 = v_sync_pulse[5:4]
    t.h_sync_offset = static_cast<u16>(d[8] | (((d[11] >> 6) & 0x03u) << 8));
    t.h_sync_pulse = static_cast<u16>(d[9] | (((d[11] >> 4) & 0x03u) << 8));
    const u8 v_off_low = (d[10] >> 4) & 0x0F;
    const u8 v_pulse_low = d[10] & 0x0F;
    t.v_sync_offset = static_cast<u16>(v_off_low | (((d[11] >> 2) & 0x03u) << 4));
    t.v_sync_pulse = static_cast<u16>(v_pulse_low | ((d[11] & 0x03u) << 4));

    // Image size in mm: 12-bit each, similar split across byte 14.
    t.h_image_mm = static_cast<u16>(d[12] | ((d[14] & 0xF0u) << 4));
    t.v_image_mm = static_cast<u16>(d[13] | ((d[14] & 0x0Fu) << 8));

    const u8 flags = d[17];
    t.interlaced = (flags & 0x80) != 0;
    t.sync_type = static_cast<u8>((flags >> 3) & 0x03);
    if (t.sync_type == 3) // digital separate
    {
        t.v_sync_positive = (flags & 0x04) != 0;
        t.h_sync_positive = (flags & 0x02) != 0;
    }
    else
    {
        t.v_sync_positive = false;
        t.h_sync_positive = false;
    }

    const u32 h_total = static_cast<u32>(t.h_active) + t.h_blanking;
    const u32 v_total = static_cast<u32>(t.v_active) + t.v_blanking;
    if (h_total != 0 && v_total != 0)
    {
        // pixel_clock is in kHz (so pclk_kHz * 1000 = pixels-per-second).
        // Refresh frequency in Hz = pixels_per_sec / (h_total * v_total).
        // We report refresh in milli-hertz so callers can render
        // "59.940 Hz" without dragging in floats; multiply the
        // numerator by an extra 1000.
        const u64 num = static_cast<u64>(t.pixel_clock_khz) * 1000000ULL;
        const u64 den = static_cast<u64>(h_total) * v_total;
        t.refresh_mhz = static_cast<u32>(num / den);
    }

    return t;
}

EdidMonitorDescriptor DecodeMonitorDescriptor(const u8* d)
{
    EdidMonitorDescriptor m = {};
    m.kind = static_cast<EdidDescriptorKind>(d[3]);

    // Payload is bytes 5-17 (13 bytes).
    for (u32 i = 0; i < 13; ++i)
        m.raw_payload[i] = d[5 + i];

    // For string-bearing descriptors, copy + NUL-terminate at the
    // first 0x0A (LF) or end-of-payload, per the spec.
    auto copy_string = [&]()
    {
        u32 j = 0;
        for (u32 i = 0; i < 13 && j < 13; ++i)
        {
            const u8 c = m.raw_payload[i];
            if (c == 0x0A) // LF terminator
                break;
            // Spec says ASCII printable + space; allow control
            // chars through but render them as '?' to keep logs
            // sane.
            const char ch = (c >= 0x20 && c <= 0x7E) ? static_cast<char>(c) : '?';
            m.text[j++] = ch;
        }
        m.text[j] = '\0';
    };

    switch (m.kind)
    {
    case EdidDescriptorKind::SerialNumber:
    case EdidDescriptorKind::AsciiString:
    case EdidDescriptorKind::MonitorName:
        copy_string();
        break;
    case EdidDescriptorKind::RangeLimits:
        // Bytes 5..10: vmin, vmax, hmin, hmax, max_pixel_clock_10MHz, timing_std
        // (max_pixel_clock unit is 10 MHz, value range 0..255 → 0..2550 MHz).
        m.v_min_hz = m.raw_payload[0];
        m.v_max_hz = m.raw_payload[1];
        m.h_min_khz = m.raw_payload[2];
        m.h_max_khz = m.raw_payload[3];
        m.max_pixel_clock_mhz = static_cast<u16>(m.raw_payload[4]) * 10u;
        m.text[0] = '\0';
        break;
    default:
        m.text[0] = '\0';
        break;
    }
    return m;
}

void DecodeDescriptorSlot(const u8* d, EdidDescriptor& out)
{
    // A "monitor descriptor" has bytes 0-1-2 == 0; byte 3 is the
    // type tag. Anything else is a real DTD.
    if (d[0] == 0 && d[1] == 0 && d[2] == 0)
    {
        out.kind = static_cast<EdidDescriptorKind>(d[3]);
        out.monitor_descriptor = DecodeMonitorDescriptor(d);
        out.dtd = {};
    }
    else
    {
        out.kind = EdidDescriptorKind::Dtd;
        out.dtd = DecodeDtd(d);
        out.monitor_descriptor = {};
    }
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

} // namespace

const char* EdidDescriptorKindName(EdidDescriptorKind k)
{
    switch (k)
    {
    case EdidDescriptorKind::Dtd:
        return "dtd";
    case EdidDescriptorKind::SerialNumber:
        return "serial";
    case EdidDescriptorKind::AsciiString:
        return "ascii";
    case EdidDescriptorKind::RangeLimits:
        return "range-limits";
    case EdidDescriptorKind::MonitorName:
        return "monitor-name";
    case EdidDescriptorKind::AdditionalWhite:
        return "additional-white";
    case EdidDescriptorKind::AdditionalStdTimings:
        return "additional-std-timings";
    case EdidDescriptorKind::DcmData:
        return "dcm-data";
    case EdidDescriptorKind::Cvt3ByteCodes:
        return "cvt-3byte";
    case EdidDescriptorKind::DcmDisplay:
        return "dcm-display";
    case EdidDescriptorKind::Dummy:
        return "dummy";
    default:
        return "unknown";
    }
}

const char* EdidEstablishedTimingName(u32 index)
{
    static const char* const kNames[] = {
        "720x400@70",  "720x400@88",  "640x480@60",  "640x480@67",   "640x480@72",  "640x480@75",
        "800x600@56",  "800x600@60",  "800x600@72",  "800x600@75",   "832x624@75",  "1024x768@87i",
        "1024x768@60", "1024x768@70", "1024x768@75", "1280x1024@75", "1152x870@75",
    };
    if (index >= sizeof(kNames) / sizeof(kNames[0]))
        return nullptr;
    return kNames[index];
}

u16 EdidStandardTimingHeight(u16 width, u8 aspect_bits)
{
    // EDID 1.3+ assigns 16:10 to bits 00. EDID 1.0 used 1:1; we
    // assume 1.3+ since that's the era of every plausible monitor
    // a DuetOS install would meet.
    switch (aspect_bits & 0x03)
    {
    case 0: // 16:10
        return static_cast<u16>((static_cast<u32>(width) * 10u) / 16u);
    case 1: // 4:3
        return static_cast<u16>((static_cast<u32>(width) * 3u) / 4u);
    case 2: // 5:4
        return static_cast<u16>((static_cast<u32>(width) * 4u) / 5u);
    case 3: // 16:9
        return static_cast<u16>((static_cast<u32>(width) * 9u) / 16u);
    }
    return 0;
}

::duetos::core::Result<EdidBaseBlock> EdidParseBaseBlock(const u8* data, u64 length)
{
    if (data == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    if (length < kEdidBaseBlockBytes)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};

    EdidBaseBlock blk = {};
    blk.header_valid = IsHeaderValid(data);
    blk.computed_checksum = ComputeChecksum(data);
    blk.stored_checksum = data[127];
    blk.checksum_valid = (blk.computed_checksum == blk.stored_checksum);

    const u16 mfg_be = static_cast<u16>((static_cast<u16>(data[8]) << 8) | data[9]);
    DecodeManufacturerId(mfg_be, blk.manufacturer_id);

    blk.product_code = static_cast<u16>(data[10] | (data[11] << 8));
    blk.serial_number = static_cast<u32>(data[12]) | (static_cast<u32>(data[13]) << 8) |
                        (static_cast<u32>(data[14]) << 16) | (static_cast<u32>(data[15]) << 24);

    blk.week_of_manufacture = data[16];
    if (blk.week_of_manufacture == 0xFF)
    {
        blk.model_year = true;
        blk.year_of_manufacture = static_cast<u16>(1990u + data[17]);
    }
    else
    {
        blk.model_year = false;
        blk.year_of_manufacture = static_cast<u16>(1990u + data[17]);
    }
    blk.edid_version = data[18];
    blk.edid_revision = data[19];

    blk.video_input = DecodeVideoInput(data[20]);
    blk.h_image_cm = data[21];
    blk.v_image_cm = data[22];
    blk.gamma_raw = data[23];
    blk.features = DecodeFeatures(data[24]);

    blk.established_timings = DecodeEstablishedTimings(data[35], data[36], data[37]);

    for (u32 i = 0; i < kEdidStandardTimingSlots; ++i)
        blk.standard_timings[i] = DecodeStandardTiming(data[38 + i * 2], data[39 + i * 2]);

    for (u32 i = 0; i < kEdidDtdCount; ++i)
        DecodeDescriptorSlot(&data[54 + i * kEdidDtdBytes], blk.descriptors[i]);

    blk.extension_block_count = data[126];
    return blk;
}

void EdidDumpToConsole(const EdidBaseBlock& blk)
{
    using ::duetos::drivers::video::ConsoleWrite;
    using ::duetos::drivers::video::ConsoleWriteln;

    ConsoleWrite("EDID  header=");
    ConsoleWrite(blk.header_valid ? "OK" : "BAD");
    ConsoleWrite("  checksum=");
    ConsoleWrite(blk.checksum_valid ? "OK" : "BAD");
    ConsoleWrite(" (computed=0x");
    {
        char hx[3] = {0};
        const u8 v = blk.computed_checksum;
        const char* d = "0123456789ABCDEF";
        hx[0] = d[(v >> 4) & 0xF];
        hx[1] = d[v & 0xF];
        ConsoleWrite(hx);
    }
    ConsoleWrite(" stored=0x");
    {
        char hx[3] = {0};
        const u8 v = blk.stored_checksum;
        const char* d = "0123456789ABCDEF";
        hx[0] = d[(v >> 4) & 0xF];
        hx[1] = d[v & 0xF];
        ConsoleWrite(hx);
    }
    ConsoleWriteln(")");

    ConsoleWrite("  vendor=");
    ConsoleWrite(blk.manufacturer_id);
    ConsoleWrite(" product=");
    WriteDec(blk.product_code);
    ConsoleWrite(" serial=");
    WriteDec(blk.serial_number);
    ConsoleWrite(blk.model_year ? " model-year=" : " mfg-year=");
    WriteDec(blk.year_of_manufacture);
    if (!blk.model_year)
    {
        ConsoleWrite(" wk=");
        WriteDec(blk.week_of_manufacture);
    }
    ConsoleWrite(" edid=");
    WriteDec(blk.edid_version);
    ConsoleWrite(".");
    WriteDec(blk.edid_revision);
    ConsoleWriteln("");

    ConsoleWrite("  input=");
    ConsoleWrite(blk.video_input.digital ? "digital" : "analog");
    if (blk.video_input.digital && blk.video_input.digital_bit_depth > 0)
    {
        ConsoleWrite(" ");
        WriteDec(static_cast<u32>(blk.video_input.digital_bit_depth));
        ConsoleWrite("bpc");
    }
    ConsoleWrite("  size=");
    WriteDec(blk.h_image_cm);
    ConsoleWrite("x");
    WriteDec(blk.v_image_cm);
    ConsoleWrite("cm  features=[");
    if (blk.features.dpms_standby)
        ConsoleWrite("standby ");
    if (blk.features.dpms_suspend)
        ConsoleWrite("suspend ");
    if (blk.features.dpms_active_off)
        ConsoleWrite("off ");
    if (blk.features.srgb_default)
        ConsoleWrite("srgb ");
    if (blk.features.preferred_timing_in_dtd1)
        ConsoleWrite("preferred-dtd1 ");
    if (blk.features.continuous_frequency)
        ConsoleWrite("cont-freq ");
    ConsoleWriteln("]");

    for (u32 i = 0; i < kEdidDtdCount; ++i)
    {
        const EdidDescriptor& dsc = blk.descriptors[i];
        ConsoleWrite("  desc[");
        WriteDec(i);
        ConsoleWrite("] kind=");
        ConsoleWrite(EdidDescriptorKindName(dsc.kind));
        if (dsc.kind == EdidDescriptorKind::Dtd)
        {
            const EdidDtd& t = dsc.dtd;
            ConsoleWrite("  ");
            WriteDec(t.h_active);
            ConsoleWrite("x");
            WriteDec(t.v_active);
            ConsoleWrite(t.interlaced ? "i" : "p");
            ConsoleWrite(" @ ");
            WriteDec(t.refresh_mhz / 1000);
            ConsoleWrite("Hz  pclk=");
            WriteDec(t.pixel_clock_khz / 1000);
            ConsoleWrite(".");
            WriteDec(t.pixel_clock_khz % 1000);
            ConsoleWriteln("MHz");
        }
        else if (dsc.kind == EdidDescriptorKind::MonitorName || dsc.kind == EdidDescriptorKind::SerialNumber ||
                 dsc.kind == EdidDescriptorKind::AsciiString)
        {
            ConsoleWrite("  \"");
            ConsoleWrite(dsc.monitor_descriptor.text);
            ConsoleWriteln("\"");
        }
        else if (dsc.kind == EdidDescriptorKind::RangeLimits)
        {
            const EdidMonitorDescriptor& m = dsc.monitor_descriptor;
            ConsoleWrite("  v=");
            WriteDec(m.v_min_hz);
            ConsoleWrite("-");
            WriteDec(m.v_max_hz);
            ConsoleWrite("Hz  h=");
            WriteDec(m.h_min_khz);
            ConsoleWrite("-");
            WriteDec(m.h_max_khz);
            ConsoleWrite("kHz  pclk<=");
            WriteDec(m.max_pixel_clock_mhz);
            ConsoleWriteln("MHz");
        }
        else
        {
            ConsoleWriteln("");
        }
    }

    if (blk.extension_block_count != 0)
    {
        ConsoleWrite("  extensions=");
        WriteDec(blk.extension_block_count);
        ConsoleWriteln(" (not parsed by v0)");
    }
}

} // namespace duetos::drivers::gpu
