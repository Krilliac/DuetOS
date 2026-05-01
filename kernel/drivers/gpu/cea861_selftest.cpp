#include "drivers/gpu/cea861.h"

#include "core/panic.h"
#include "drivers/video/console.h"

/*
 * Boot-time self-test for the CEA-861 extension-block parser.
 *
 * Two fixtures:
 *   1. A typical HDMI 2.0 monitor extension block with:
 *        - revision 3
 *        - DTD start at byte 36
 *        - flags: underscan + audio + ycbcr444 + ycbcr422
 *        - 1 native DTD
 *        - Video Data Block: VICs 16 (1080p60 native), 4 (720p60),
 *          31 (1080p50), 19 (720p50), 32 (1080p24)
 *        - Audio Data Block: LPCM 2-channel + AC-3 6-channel
 *        - Speaker Allocation: FL/FR + LFE + FC + RL/RR
 *        - HDMI VSDB OUI 000C03: source phys 0x1000, max TMDS
 *          340 MHz (68×5), flags 0x88
 *        - HDR static metadata: EOTF=PQ+SDR, max-lum-code=180,
 *          min-lum-code=10
 *        - One 1920x1080@60 DTD
 *   2. Same fixture with byte 127 XOR 0xA5 (checksum invalid).
 */

namespace duetos::drivers::gpu
{

namespace
{

void StampChecksum(u8* d)
{
    u32 sum = 0;
    for (u32 i = 0; i < 127; ++i)
        sum += d[i];
    d[127] = static_cast<u8>((256u - (sum & 0xFFu)) & 0xFFu);
}

void Build2160pHdmi2(u8* d)
{
    for (u32 i = 0; i < 128; ++i)
        d[i] = 0;
    d[0] = 0x02;        // CEA-861 tag
    d[1] = 0x03;        // revision 3
    d[2] = 0x36;        // DTD offset = 0x36 (54)
    d[3] = 0xE1 | 0x10; // bits 7,6,5 = under/audio/ycbcr444; bit 4 = ycbcr422; native_dtds=1
    // Note: bit pattern decoded as native_dtd_count=1 with the
    // four feature bits set. We rebuild byte 3 explicitly:
    //   bit 7 underscan, bit 6 audio, bit 5 ycbcr444, bit 4 ycbcr422,
    //   bits 3:0 native dtd count.
    d[3] = static_cast<u8>(0x80 | 0x40 | 0x20 | 0x10 | 0x01);

    u32 off = 4;
    // Video Data Block: tag=2, length=5 (5 SVDs).
    d[off++] = static_cast<u8>((2u << 5) | 5);
    d[off++] = static_cast<u8>(0x80 | 16); // 1080p60 + native flag
    d[off++] = 4;                          // 720p60
    d[off++] = 31;                         // 1080p50
    d[off++] = 19;                         // 720p50
    d[off++] = 32;                         // 1080p24

    // Audio Data Block: tag=1, length=6 (2 SADs × 3 bytes).
    d[off++] = static_cast<u8>((1u << 5) | 6);
    // SAD #1: LPCM, 2 channels, 32+44.1+48 kHz, 16-bit
    d[off++] = static_cast<u8>((1u << 3) | (2u - 1u));
    d[off++] = 0x07; // bits 0..2 set
    d[off++] = 0x01; // 16-bit
    // SAD #2: AC-3, 6 channels, 48 kHz, max 640 kbps (640/8 = 80)
    d[off++] = static_cast<u8>((2u << 3) | (6u - 1u));
    d[off++] = 0x04; // bit 2 = 48 kHz
    d[off++] = 80;

    // Speaker Allocation Data Block: tag=4, length=3.
    d[off++] = static_cast<u8>((4u << 5) | 3);
    d[off++] = static_cast<u8>(0x01 | 0x02 | 0x04 | 0x08); // FL/FR + LFE + FC + RL/RR
    d[off++] = 0;
    d[off++] = 0;

    // HDMI VSDB: tag=3, length=9.
    d[off++] = static_cast<u8>((3u << 5) | 9);
    d[off++] = 0x03; // OUI byte 0
    d[off++] = 0x0C; // OUI byte 1
    d[off++] = 0x00; // OUI byte 2 (LSB-first → 0x000C03)
    d[off++] = 0x10; // source phys hi
    d[off++] = 0x00; // source phys lo (= 0x1000)
    d[off++] = 0x88; // support flags
    d[off++] = 68;   // max TMDS / 5 MHz = 68 → 340 MHz
    d[off++] = 0;    // video latency
    d[off++] = 0;    // audio latency

    // Extended tag — HDR static metadata: tag=7, length=6.
    d[off++] = static_cast<u8>((7u << 5) | 6);
    d[off++] = 0x06; // extended tag = HDR Static Metadata
    d[off++] = 0x05; // EOTF: SDR (bit 0) + PQ (bit 2)
    d[off++] = 0x01; // metadata: type-1
    d[off++] = 180;  // max lum code
    d[off++] = 90;   // max frame avg lum code
    d[off++] = 10;   // min lum code

    // Pad with zeros to DTD start (byte 0x36 = 54).
    while (off < 0x36)
        d[off++] = 0;

    // One DTD: 1920x1080@60 (same shape as the EDID base-block fixture).
    u8 dtd[18] = {};
    const u16 px = 14850;
    dtd[0] = static_cast<u8>(px & 0xFF);
    dtd[1] = static_cast<u8>((px >> 8) & 0xFF);
    dtd[2] = 1920 & 0xFF;
    dtd[3] = 280 & 0xFF;
    dtd[4] = static_cast<u8>(((1920 >> 4) & 0xF0) | ((280 >> 8) & 0x0F));
    dtd[5] = 1080 & 0xFF;
    dtd[6] = 45 & 0xFF;
    dtd[7] = static_cast<u8>(((1080 >> 4) & 0xF0) | ((45 >> 8) & 0x0F));
    dtd[8] = 88;
    dtd[9] = 44;
    dtd[10] = static_cast<u8>(((4 & 0x0F) << 4) | (5 & 0x0F));
    dtd[11] = 0;
    dtd[12] = 600 & 0xFF;
    dtd[13] = 340 & 0xFF;
    dtd[14] = static_cast<u8>(((600 >> 4) & 0xF0) | ((340 >> 8) & 0x0F));
    dtd[17] = static_cast<u8>((3u << 3) | 0x04 | 0x02);
    for (u32 i = 0; i < 18; ++i)
        d[0x36 + i] = dtd[i];

    StampChecksum(d);
}

void Assert(bool cond, const char* name)
{
    if (!cond)
    {
        ::duetos::drivers::video::ConsoleWrite("[selftest] CEA-861 assert FAILED: ");
        ::duetos::drivers::video::ConsoleWriteln(name);
        ::duetos::core::Panic("drivers/gpu/cea861", "self-test assertion failed");
    }
}

} // namespace

void Cea861SelfTest()
{
    using ::duetos::drivers::video::ConsoleWriteln;

    u8 buf[128];
    Build2160pHdmi2(buf);

    auto res = Cea861ParseBlock(buf, sizeof(buf));
    Assert(res.has_value(), "fixture1: parser returned ok");
    const Cea861ExtBlock& blk = res.value();

    Assert(blk.tag_valid, "fixture1: CEA tag");
    Assert(blk.checksum_valid, "fixture1: checksum");
    Assert(blk.revision == 3, "fixture1: revision == 3");
    Assert(blk.dtd_start_offset == 0x36, "fixture1: DTD offset");
    Assert(blk.supports_audio, "fixture1: audio flag");
    Assert(blk.supports_ycbcr_444, "fixture1: YCbCr 4:4:4 flag");
    Assert(blk.supports_ycbcr_422, "fixture1: YCbCr 4:2:2 flag");
    Assert(blk.native_dtd_count == 1, "fixture1: 1 native DTD");

    Assert(blk.vid_count == 5, "fixture1: 5 VICs parsed");
    Assert(blk.vids[0].vic == 16 && blk.vids[0].native, "fixture1: VIC 16 native");
    Assert(blk.vids[1].vic == 4 && !blk.vids[1].native, "fixture1: VIC 4 non-native");
    Assert(blk.vids[2].vic == 31, "fixture1: VIC 31");
    Assert(blk.vids[4].vic == 32, "fixture1: VIC 32");

    Assert(blk.aud_count == 2, "fixture1: 2 SADs parsed");
    Assert(blk.auds[0].format == CeaAudioFormat::Lpcm, "fixture1: SAD 0 = LPCM");
    Assert(blk.auds[0].channels == 2, "fixture1: SAD 0 = 2ch");
    Assert(blk.auds[0].sample_rate_flags == 0x07, "fixture1: SAD 0 rates 32/44.1/48");
    Assert(blk.auds[1].format == CeaAudioFormat::Ac3, "fixture1: SAD 1 = AC-3");
    Assert(blk.auds[1].channels == 6, "fixture1: SAD 1 = 6ch");

    Assert(blk.speaker_allocation.present, "fixture1: speaker block present");
    Assert(blk.speaker_allocation.fl_fr, "fixture1: FL/FR");
    Assert(blk.speaker_allocation.lfe, "fixture1: LFE");
    Assert(blk.speaker_allocation.fc, "fixture1: FC");
    Assert(blk.speaker_allocation.rl_rr, "fixture1: RL/RR");

    Assert(blk.hdmi.present, "fixture1: HDMI VSDB present");
    Assert(blk.hdmi.source_physical_address == 0x1000, "fixture1: HDMI phys 0x1000");
    Assert(blk.hdmi.max_tmds_clock_5mhz == 68, "fixture1: max TMDS 340 MHz");
    Assert(blk.hdmi.support_flags == 0x88, "fixture1: HDMI flags 0x88");

    Assert(blk.hdr_static.present, "fixture1: HDR static present");
    Assert(blk.hdr_static.eotf_supported_bitmap == 0x05, "fixture1: HDR EOTF bitmap");
    Assert(blk.hdr_static.max_luminance_code == 180, "fixture1: HDR max-lum 180");
    Assert(blk.hdr_static.min_luminance_code == 10, "fixture1: HDR min-lum 10");

    Assert(blk.dtd_count == 1, "fixture1: 1 DTD parsed");
    Assert(blk.dtds[0].h_active == 1920, "fixture1: DTD 1920 active");
    Assert(blk.dtds[0].v_active == 1080, "fixture1: DTD 1080 active");
    Assert(blk.dtds[0].pixel_clock_khz == 148500, "fixture1: DTD pclk 148.5");

    ConsoleWriteln("[selftest] CEA-861 fixture #1 (HDMI 2.0 + HDR + audio): all fields decoded.");

    // Fixture 2 — bad checksum.
    Build2160pHdmi2(buf);
    buf[127] ^= 0xA5;
    auto res2 = Cea861ParseBlock(buf, sizeof(buf));
    Assert(res2.has_value(), "fixture2: parser returned ok");
    const Cea861ExtBlock& blk2 = res2.value();
    Assert(blk2.tag_valid, "fixture2: tag still valid");
    Assert(!blk2.checksum_valid, "fixture2: checksum flagged invalid");
    Assert(blk2.vid_count == 5, "fixture2: VIC list still parsed despite bad checksum");
    ConsoleWriteln("[selftest] CEA-861 fixture #2 (bad checksum): flagged correctly.");

    // Fixture 3 — too-short buffer.
    auto res3 = Cea861ParseBlock(buf, 16);
    Assert(!res3.has_value(), "fixture3: short buffer rejected");
    ConsoleWriteln("[selftest] CEA-861 fixture #3 (short buffer): rejected as expected.");
}

} // namespace duetos::drivers::gpu
