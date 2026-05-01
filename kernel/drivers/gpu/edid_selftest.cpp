#include "drivers/gpu/edid.h"

#include "core/panic.h"
#include "drivers/video/console.h"
#include "log/klog.h"

/*
 * Boot-time self-test for the EDID base-block parser.
 *
 * Three positive fixtures cover the layouts a parser is most
 * likely to break on:
 *
 *   1. A 1.4 digital monitor with a real preferred DTD
 *      (1920x1080@60), DPMS feature flags, sRGB default, and a
 *      monitor-name descriptor.
 *   2. A 1.3 analog monitor (legacy CRT-shaped layout) with a
 *      4:3 standard-timing block populated and only established
 *      timings I+II in use.
 *   3. The same 1.4 digital monitor as fixture #1 but with the
 *      checksum byte deliberately wrong, to confirm
 *      `checksum_valid` flags the corruption without rejecting
 *      the rest of the parse.
 *
 * Each fixture is built byte-by-byte in an u8[128] so the test
 * doubles as a worked example of the spec layout. No on-host
 * EDID dumps are checked in — the bytes here are synthetic and
 * carry no copyrighted vendor data, only the values mandated by
 * the public VESA spec for a parser to emit a consistent decode.
 */

namespace duetos::drivers::gpu
{

namespace
{

constexpr u8 kHeader[8] = {0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00};

void WriteHeader(u8* d)
{
    for (u32 i = 0; i < 8; ++i)
        d[i] = kHeader[i];
}

// Encode "DEL" (0x10AC, classic Dell PnP code) → bytes 8-9.
//   D=4, E=5, L=12  → 5-bit triplet
//   bits = (4<<10)|(5<<5)|12 = 0x10AC
void WriteManufacturerId(u8* d, char a, char b, char c)
{
    auto v = [](char x) -> u16 { return static_cast<u16>((x - 'A' + 1) & 0x1F); };
    const u16 word = static_cast<u16>((v(a) << 10) | (v(b) << 5) | v(c));
    d[8] = static_cast<u8>((word >> 8) & 0xFF);
    d[9] = static_cast<u8>(word & 0xFF);
}

// 18-byte DTD writer.
struct DtdSpec
{
    u32 pixel_clock_khz;
    u16 h_active;
    u16 h_blanking;
    u16 v_active;
    u16 v_blanking;
    u16 h_sync_offset;
    u16 h_sync_pulse;
    u16 v_sync_offset;
    u16 v_sync_pulse;
    u16 h_image_mm;
    u16 v_image_mm;
    bool interlaced;
    bool h_pos;
    bool v_pos;
};

void WriteDtd(u8* d, const DtdSpec& s)
{
    const u16 px = static_cast<u16>(s.pixel_clock_khz / 10u);
    d[0] = static_cast<u8>(px & 0xFF);
    d[1] = static_cast<u8>((px >> 8) & 0xFF);
    d[2] = static_cast<u8>(s.h_active & 0xFF);
    d[3] = static_cast<u8>(s.h_blanking & 0xFF);
    d[4] = static_cast<u8>(((s.h_active >> 4) & 0xF0) | ((s.h_blanking >> 8) & 0x0F));
    d[5] = static_cast<u8>(s.v_active & 0xFF);
    d[6] = static_cast<u8>(s.v_blanking & 0xFF);
    d[7] = static_cast<u8>(((s.v_active >> 4) & 0xF0) | ((s.v_blanking >> 8) & 0x0F));
    d[8] = static_cast<u8>(s.h_sync_offset & 0xFF);
    d[9] = static_cast<u8>(s.h_sync_pulse & 0xFF);
    d[10] = static_cast<u8>(((s.v_sync_offset & 0x0F) << 4) | (s.v_sync_pulse & 0x0F));
    d[11] = static_cast<u8>((((s.h_sync_offset >> 8) & 0x03) << 6) | (((s.h_sync_pulse >> 8) & 0x03) << 4) |
                            (((s.v_sync_offset >> 4) & 0x03) << 2) | ((s.v_sync_pulse >> 4) & 0x03));
    d[12] = static_cast<u8>(s.h_image_mm & 0xFF);
    d[13] = static_cast<u8>(s.v_image_mm & 0xFF);
    d[14] = static_cast<u8>(((s.h_image_mm >> 4) & 0xF0) | ((s.v_image_mm >> 8) & 0x0F));
    d[15] = 0; // h border
    d[16] = 0; // v border
    u8 flags = 0;
    if (s.interlaced)
        flags |= 0x80;
    flags |= (3u << 3); // digital separate sync
    if (s.v_pos)
        flags |= 0x04;
    if (s.h_pos)
        flags |= 0x02;
    d[17] = flags;
}

void WriteMonitorNameDescriptor(u8* d, const char* name)
{
    d[0] = 0;
    d[1] = 0;
    d[2] = 0;
    d[3] = 0xFC; // Monitor name
    d[4] = 0;
    u32 i = 0;
    for (; i < 13 && name[i] != '\0'; ++i)
        d[5 + i] = static_cast<u8>(name[i]);
    if (i < 13)
        d[5 + i++] = 0x0A; // LF terminator
    while (i < 13)
        d[5 + i++] = 0x20; // pad with spaces
}

void WriteRangeLimitsDescriptor(u8* d, u8 vmin, u8 vmax, u8 hmin, u8 hmax, u8 maxpx_x10mhz)
{
    d[0] = 0;
    d[1] = 0;
    d[2] = 0;
    d[3] = 0xFD; // Range limits
    d[4] = 0;
    d[5] = vmin;
    d[6] = vmax;
    d[7] = hmin;
    d[8] = hmax;
    d[9] = maxpx_x10mhz;
    d[10] = 0; // GTF default
    for (u32 i = 11; i < 18; ++i)
        d[i] = 0x20;
}

void StampChecksum(u8* d)
{
    u32 sum = 0;
    for (u32 i = 0; i < 127; ++i)
        sum += d[i];
    d[127] = static_cast<u8>((256u - (sum & 0xFFu)) & 0xFFu);
}

void Build1080pFixture(u8* d)
{
    for (u32 i = 0; i < 128; ++i)
        d[i] = 0;
    WriteHeader(d);
    WriteManufacturerId(d, 'D', 'E', 'L');
    d[10] = 0xC4; // product code low
    d[11] = 0x0A; // product code high (= 0x0AC4)
    d[12] = 0x78; // serial low
    d[13] = 0x56;
    d[14] = 0x34;
    d[15] = 0x12; // 0x12345678
    d[16] = 12;   // week 12
    d[17] = 30;   // year 1990 + 30 = 2020
    d[18] = 1;    // EDID 1
    d[19] = 4;    // .4
    // Digital, 8 bpc, DisplayPort
    d[20] = static_cast<u8>(0x80 | (2 << 4) | 5);
    d[21] = 60;  // 60 cm wide
    d[22] = 34;  // 34 cm tall
    d[23] = 120; // gamma 2.2
    // Features: standby, suspend, off, RGB444, sRGB default, preferred-in-DTD1, no continuous
    d[24] = 0xE0 | 0x04 | 0x02;
    // Chromaticity: leave zero (test doesn't check).
    // Established timings: 640x480@60 + 800x600@60 + 1024x768@60
    d[35] = 0x20 | 0x01; // 640x480@60 + 800x600@60
    d[36] = 0x08;        // 1024x768@60
    d[37] = 0x00;
    // Standard timings: one slot 1280x1024 @ 60 (5:4)
    d[38] = static_cast<u8>((1280u / 8u) - 31u);
    d[39] = static_cast<u8>((2u << 6) | (60 - 60));
    for (u32 i = 1; i < 8; ++i)
    {
        d[38 + i * 2] = 0x01; // unused-slot encoding
        d[39 + i * 2] = 0x01;
    }

    DtdSpec dtd = {};
    dtd.pixel_clock_khz = 148500; // 148.50 MHz
    dtd.h_active = 1920;
    dtd.h_blanking = 280;
    dtd.v_active = 1080;
    dtd.v_blanking = 45;
    dtd.h_sync_offset = 88;
    dtd.h_sync_pulse = 44;
    dtd.v_sync_offset = 4;
    dtd.v_sync_pulse = 5;
    dtd.h_image_mm = 600;
    dtd.v_image_mm = 340;
    dtd.h_pos = true;
    dtd.v_pos = true;
    WriteDtd(&d[54], dtd);

    WriteRangeLimitsDescriptor(&d[72], 50, 75, 30, 80, 17); // up to 170 MHz
    WriteMonitorNameDescriptor(&d[90], "DUET-TEST-1");

    // Slot 4: dummy descriptor
    d[108] = 0;
    d[109] = 0;
    d[110] = 0;
    d[111] = 0x10; // Dummy
    for (u32 i = 4; i < 18; ++i)
        d[108 + i] = 0;

    d[126] = 0; // no extension blocks
    StampChecksum(d);
}

void BuildAnalog1024Fixture(u8* d)
{
    for (u32 i = 0; i < 128; ++i)
        d[i] = 0;
    WriteHeader(d);
    WriteManufacturerId(d, 'D', 'U', 'O');
    d[10] = 0x01;
    d[11] = 0x00;
    d[12] = 0;
    d[13] = 0;
    d[14] = 0;
    d[15] = 0;
    d[16] = 0xFF; // model year flag
    d[17] = 12;   // model year 2002
    d[18] = 1;
    d[19] = 3;
    // Analog, 0.7/0.3 V, BNC, separate+composite+sync-on-green, serration off
    d[20] = 0x6F;
    d[21] = 32;
    d[22] = 24;
    d[23] = 100;
    d[24] = 0xE0 | 0x02; // DPMS all + preferred timing
    d[35] = 0xFF;        // every byte-35 timing on
    d[36] = 0xFF;
    d[37] = 0x00;
    // Standard timings: 4:3 1024x768@75 in slot 0
    d[38] = static_cast<u8>((1024u / 8u) - 31u);
    d[39] = static_cast<u8>((1u << 6) | (75 - 60));
    for (u32 i = 1; i < 8; ++i)
    {
        d[38 + i * 2] = 0x01;
        d[39 + i * 2] = 0x01;
    }

    DtdSpec dtd = {};
    dtd.pixel_clock_khz = 78750;
    dtd.h_active = 1024;
    dtd.h_blanking = 320;
    dtd.v_active = 768;
    dtd.v_blanking = 38;
    dtd.h_sync_offset = 16;
    dtd.h_sync_pulse = 96;
    dtd.v_sync_offset = 1;
    dtd.v_sync_pulse = 3;
    dtd.h_image_mm = 320;
    dtd.v_image_mm = 240;
    WriteDtd(&d[54], dtd);
    WriteMonitorNameDescriptor(&d[72], "DUET-CRT");
    WriteRangeLimitsDescriptor(&d[90], 50, 90, 30, 65, 8);
    d[108] = 0;
    d[109] = 0;
    d[110] = 0;
    d[111] = 0x10;
    for (u32 i = 4; i < 18; ++i)
        d[108 + i] = 0;
    d[126] = 0;
    StampChecksum(d);
}

void Assert(bool cond, const char* name)
{
    if (!cond)
    {
        ::duetos::drivers::video::ConsoleWrite("[selftest] EDID assert FAILED: ");
        ::duetos::drivers::video::ConsoleWriteln(name);
        ::duetos::core::Panic("drivers/gpu/edid", "self-test assertion failed");
    }
}

void RunFixture1()
{
    using ::duetos::drivers::video::ConsoleWrite;
    using ::duetos::drivers::video::ConsoleWriteln;

    u8 buf[128];
    Build1080pFixture(buf);

    auto res = EdidParseBaseBlock(buf, sizeof(buf));
    Assert(res.has_value(), "fixture1: parser returned ok");
    const EdidBaseBlock& blk = res.value();

    Assert(blk.header_valid, "fixture1: header valid");
    Assert(blk.checksum_valid, "fixture1: checksum valid");
    Assert(blk.manufacturer_id[0] == 'D' && blk.manufacturer_id[1] == 'E' && blk.manufacturer_id[2] == 'L' &&
               blk.manufacturer_id[3] == '\0',
           "fixture1: manufacturer = DEL");
    Assert(blk.product_code == 0x0AC4, "fixture1: product = 0x0AC4");
    Assert(blk.serial_number == 0x12345678u, "fixture1: serial = 0x12345678");
    Assert(blk.edid_version == 1, "fixture1: edid_version = 1");
    Assert(blk.edid_revision == 4, "fixture1: edid_revision = 4");
    Assert(blk.video_input.digital, "fixture1: digital input");
    Assert(blk.video_input.digital_bit_depth == 8, "fixture1: 8 bpc");
    Assert(blk.video_input.digital_interface == 5, "fixture1: DisplayPort iface");
    Assert(blk.h_image_cm == 60 && blk.v_image_cm == 34, "fixture1: 60x34 cm");
    Assert(blk.features.dpms_standby && blk.features.dpms_suspend && blk.features.dpms_active_off,
           "fixture1: full DPMS");
    Assert(blk.features.srgb_default, "fixture1: sRGB default");
    Assert(blk.features.preferred_timing_in_dtd1, "fixture1: preferred-in-DTD1");
    Assert(blk.established_timings.t_640x480_60, "fixture1: 640x480@60 set");
    Assert(blk.established_timings.t_800x600_60, "fixture1: 800x600@60 set");
    Assert(blk.established_timings.t_1024x768_60, "fixture1: 1024x768@60 set");
    Assert(!blk.established_timings.t_1280x1024_75, "fixture1: 1280x1024@75 NOT set");
    Assert(blk.standard_timings[0].width == 1280 && blk.standard_timings[0].height == 1024 &&
               blk.standard_timings[0].refresh_hz == 60,
           "fixture1: std timing 0 = 1280x1024@60 (5:4)");
    Assert(blk.standard_timings[1].width == 0, "fixture1: std timing 1 unused");

    Assert(blk.descriptors[0].kind == EdidDescriptorKind::Dtd, "fixture1: DTD0 = real DTD");
    const EdidDtd& t = blk.descriptors[0].dtd;
    Assert(t.pixel_clock_khz == 148500, "fixture1: pclk 148.5 MHz");
    Assert(t.h_active == 1920, "fixture1: h_active 1920");
    Assert(t.v_active == 1080, "fixture1: v_active 1080");
    Assert(t.h_blanking == 280, "fixture1: h_blanking 280");
    Assert(t.v_blanking == 45, "fixture1: v_blanking 45");
    Assert(t.h_sync_offset == 88, "fixture1: h_sync_offset 88");
    Assert(t.v_sync_pulse == 5, "fixture1: v_sync_pulse 5");
    Assert(!t.interlaced, "fixture1: progressive");
    Assert(t.sync_type == 3, "fixture1: digital separate sync");
    Assert(t.h_sync_positive && t.v_sync_positive, "fixture1: positive sync");
    // refresh ≈ 148500*1000 / (2200 * 1125) = 60000 mHz
    Assert(t.refresh_mhz >= 59900 && t.refresh_mhz <= 60100, "fixture1: refresh ≈ 60.000 Hz");

    Assert(blk.descriptors[1].kind == EdidDescriptorKind::RangeLimits, "fixture1: DTD1 range limits");
    Assert(blk.descriptors[1].monitor_descriptor.v_min_hz == 50, "fixture1: vmin 50");
    Assert(blk.descriptors[1].monitor_descriptor.h_max_khz == 80, "fixture1: hmax 80");
    Assert(blk.descriptors[1].monitor_descriptor.max_pixel_clock_mhz == 170, "fixture1: pclk<=170");

    Assert(blk.descriptors[2].kind == EdidDescriptorKind::MonitorName, "fixture1: DTD2 monitor name");
    Assert(blk.descriptors[2].monitor_descriptor.text[0] == 'D', "fixture1: name[0]=D");
    Assert(blk.descriptors[2].monitor_descriptor.text[10] == '1', "fixture1: name[10]=1");

    Assert(blk.descriptors[3].kind == EdidDescriptorKind::Dummy, "fixture1: DTD3 dummy");
    Assert(blk.extension_block_count == 0, "fixture1: 0 ext blocks");

    ConsoleWriteln("[selftest] EDID fixture #1 (1920x1080 digital) decoded OK.");
}

void RunFixture2()
{
    using ::duetos::drivers::video::ConsoleWriteln;

    u8 buf[128];
    BuildAnalog1024Fixture(buf);
    auto res = EdidParseBaseBlock(buf, sizeof(buf));
    Assert(res.has_value(), "fixture2: parser ok");
    const EdidBaseBlock& blk = res.value();

    Assert(blk.header_valid, "fixture2: header");
    Assert(blk.checksum_valid, "fixture2: checksum");
    Assert(blk.manufacturer_id[0] == 'D' && blk.manufacturer_id[1] == 'U' && blk.manufacturer_id[2] == 'O',
           "fixture2: vendor = DUO");
    Assert(blk.model_year, "fixture2: model-year flag");
    Assert(blk.year_of_manufacture == 2002, "fixture2: year 2002");
    Assert(!blk.video_input.digital, "fixture2: analog input");
    Assert(blk.video_input.digital_bit_depth == -1, "fixture2: bit depth N/A on analog");
    Assert(blk.standard_timings[0].width == 1024 && blk.standard_timings[0].height == 768 &&
               blk.standard_timings[0].refresh_hz == 75 && blk.standard_timings[0].aspect_bits == 1,
           "fixture2: 1024x768@75 (4:3) std timing");
    Assert(blk.descriptors[0].kind == EdidDescriptorKind::Dtd, "fixture2: DTD0 timing");
    Assert(blk.descriptors[0].dtd.h_active == 1024, "fixture2: 1024 active");
    Assert(blk.descriptors[1].kind == EdidDescriptorKind::MonitorName, "fixture2: DTD1 name");
    Assert(blk.descriptors[2].kind == EdidDescriptorKind::RangeLimits, "fixture2: DTD2 range");

    ConsoleWriteln("[selftest] EDID fixture #2 (1024x768 analog) decoded OK.");
}

void RunFixture3BadChecksum()
{
    using ::duetos::drivers::video::ConsoleWriteln;

    u8 buf[128];
    Build1080pFixture(buf);
    buf[127] ^= 0xA5; // tamper
    auto res = EdidParseBaseBlock(buf, sizeof(buf));
    Assert(res.has_value(), "fixture3: parser still returns ok");
    const EdidBaseBlock& blk = res.value();
    Assert(blk.header_valid, "fixture3: header still valid");
    Assert(!blk.checksum_valid, "fixture3: checksum flagged invalid");
    Assert(blk.computed_checksum != blk.stored_checksum, "fixture3: stored != computed");
    // Decode of the rest of the block should still succeed.
    Assert(blk.descriptors[0].kind == EdidDescriptorKind::Dtd, "fixture3: payload still parsed");
    ConsoleWriteln("[selftest] EDID fixture #3 (bad checksum) flagged correctly.");
}

void RunFixture4Short()
{
    auto res = EdidParseBaseBlock(reinterpret_cast<const u8*>(""), 0);
    Assert(!res.has_value(), "fixture4: short buffer rejected");
    using ::duetos::drivers::video::ConsoleWriteln;
    ConsoleWriteln("[selftest] EDID fixture #4 (short buffer) rejected as expected.");
}

void RunFixture5BadHeader()
{
    u8 buf[128];
    Build1080pFixture(buf);
    buf[0] = 0xDE; // header now wrong
    StampChecksum(buf);
    auto res = EdidParseBaseBlock(buf, sizeof(buf));
    Assert(res.has_value(), "fixture5: parser still returns block");
    const EdidBaseBlock& blk = res.value();
    Assert(!blk.header_valid, "fixture5: header invalid");
    Assert(blk.checksum_valid, "fixture5: checksum still valid (re-stamped)");
    using ::duetos::drivers::video::ConsoleWriteln;
    ConsoleWriteln("[selftest] EDID fixture #5 (bad header) flagged correctly.");
}

} // namespace

void EdidSelfTest()
{
    using ::duetos::drivers::video::ConsoleWriteln;
    ConsoleWriteln("[selftest] EDID parser — running 5 fixtures.");
    RunFixture1();
    RunFixture2();
    RunFixture3BadChecksum();
    RunFixture4Short();
    RunFixture5BadHeader();
    ConsoleWriteln("[selftest] EDID parser: all fixtures pass.");
}

} // namespace duetos::drivers::gpu
