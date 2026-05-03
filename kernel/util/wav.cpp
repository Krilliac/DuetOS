#include "util/wav.h"

#include "core/panic.h"

namespace duetos::util
{

namespace
{

inline u16 LoadU16Le(const u8* p)
{
    return u16(u16(p[0]) | (u16(p[1]) << 8));
}

inline u32 LoadU32Le(const u8* p)
{
    return u32(p[0]) | (u32(p[1]) << 8) | (u32(p[2]) << 16) | (u32(p[3]) << 24);
}

inline void StoreU16Le(u8* p, u16 v)
{
    p[0] = u8(v);
    p[1] = u8(v >> 8);
}

inline void StoreU32Le(u8* p, u32 v)
{
    p[0] = u8(v);
    p[1] = u8(v >> 8);
    p[2] = u8(v >> 16);
    p[3] = u8(v >> 24);
}

bool TagEq(const u8* p, const char* tag)
{
    return p[0] == u8(tag[0]) && p[1] == u8(tag[1]) && p[2] == u8(tag[2]) && p[3] == u8(tag[3]);
}

} // namespace

WavInfo WavParse(const u8* src, u32 src_len)
{
    WavInfo info = {};
    if (src_len < kWavRiffHeaderBytes)
        return info;
    if (!TagEq(src + 0, "RIFF"))
        return info;
    // src[4..7] is the RIFF size; trust it for chunk-walk bounding,
    // but never let it claim more than `src_len`.
    const u32 riff_size = LoadU32Le(src + 4);
    const u64 riff_end = u64(8) + riff_size;
    const u64 walk_end = (riff_end < u64(src_len)) ? riff_end : u64(src_len);
    if (!TagEq(src + 8, "WAVE"))
        return info;

    bool fmt_seen = false;
    u32 i = 12;
    while (u64(i) + 8 <= walk_end)
    {
        const u32 chunk_size = LoadU32Le(src + i + 4);
        const u64 next = u64(i) + 8 + chunk_size + (chunk_size & 1u); // pad to even
        if (next > walk_end)
            return info;

        if (TagEq(src + i, "fmt "))
        {
            if (chunk_size < 16)
                return info;
            info.format_tag = LoadU16Le(src + i + 8);
            info.channels = LoadU16Le(src + i + 10);
            info.sample_rate_hz = LoadU32Le(src + i + 12);
            // bytes/sec at i+16, block-align at i+20
            info.bits_per_sample = LoadU16Le(src + i + 22);
            fmt_seen = true;
        }
        else if (TagEq(src + i, "data"))
        {
            if (!fmt_seen)
                return info;
            info.data_offset = i + 8;
            info.data_bytes = chunk_size;

            if (info.format_tag != kWavFormatTagPcm)
                return info;
            if (info.channels < 1 || info.channels > 8)
                return info;
            if (info.bits_per_sample != 8 && info.bits_per_sample != 16 && info.bits_per_sample != 24 &&
                info.bits_per_sample != 32)
                return info;
            if (info.sample_rate_hz < 1000 || info.sample_rate_hz > 384000)
                return info;
            if (u64(info.data_offset) + u64(info.data_bytes) > u64(src_len))
                return info;

            info.ok = true;
            return info;
        }
        // Skip unknown chunks (LIST, INFO, fact, ...).
        i = u32(next);
    }
    return info;
}

u32 WavWriteHeaderPcm(u8 out[44], u16 channels, u32 sample_rate_hz, u16 bits_per_sample, u32 data_bytes)
{
    const u32 byte_rate = sample_rate_hz * u32(channels) * u32(bits_per_sample / 8);
    const u16 block_align = u16(u32(channels) * u32(bits_per_sample / 8));

    // RIFF header.
    out[0] = 'R';
    out[1] = 'I';
    out[2] = 'F';
    out[3] = 'F';
    StoreU32Le(out + 4, 36 + data_bytes); // RIFF chunk size = file size - 8
    out[8] = 'W';
    out[9] = 'A';
    out[10] = 'V';
    out[11] = 'E';

    // fmt chunk.
    out[12] = 'f';
    out[13] = 'm';
    out[14] = 't';
    out[15] = ' ';
    StoreU32Le(out + 16, 16); // PCM 'fmt ' size
    StoreU16Le(out + 20, kWavFormatTagPcm);
    StoreU16Le(out + 22, channels);
    StoreU32Le(out + 24, sample_rate_hz);
    StoreU32Le(out + 28, byte_rate);
    StoreU16Le(out + 32, block_align);
    StoreU16Le(out + 34, bits_per_sample);

    // data chunk header (samples follow at offset 44).
    out[36] = 'd';
    out[37] = 'a';
    out[38] = 't';
    out[39] = 'a';
    StoreU32Le(out + 40, data_bytes);
    return 44;
}

void WavSelfTest()
{
    // ----- Round-trip: write a 16-bit mono 44.1 kHz header for 4
    // bytes of audio data, then parse it back.
    {
        u8 buf[44 + 4];
        const u32 hdr_bytes = WavWriteHeaderPcm(buf, /*channels=*/1, /*sr=*/44100, /*bps=*/16, /*data_bytes=*/4);
        KASSERT(hdr_bytes == 44, "util/wav", "header byte count wrong");
        // Synthetic samples (LE 16-bit pair).
        buf[44] = 0x00;
        buf[45] = 0x80;
        buf[46] = 0xFF;
        buf[47] = 0x7F;

        const WavInfo info = WavParse(buf, sizeof(buf));
        KASSERT(info.ok, "util/wav", "round-trip parse failed");
        KASSERT(info.format_tag == kWavFormatTagPcm, "util/wav", "format_tag wrong");
        KASSERT(info.channels == 1, "util/wav", "channels wrong");
        KASSERT(info.sample_rate_hz == 44100, "util/wav", "sample rate wrong");
        KASSERT(info.bits_per_sample == 16, "util/wav", "bps wrong");
        KASSERT(info.data_offset == 44, "util/wav", "data_offset wrong");
        KASSERT(info.data_bytes == 4, "util/wav", "data_bytes wrong");
    }

    // ----- 24-bit stereo 48 kHz round-trip.
    {
        u8 buf[44 + 12]; // 2 frames at 24-bit stereo = 12 bytes
        WavWriteHeaderPcm(buf, 2, 48000, 24, 12);
        for (u32 i = 44; i < sizeof(buf); ++i)
            buf[i] = u8(i);
        const WavInfo info = WavParse(buf, sizeof(buf));
        KASSERT(info.ok && info.channels == 2 && info.sample_rate_hz == 48000 && info.bits_per_sample == 24, "util/wav",
                "24-bit stereo round-trip wrong");
    }

    // ----- Tolerant parse: a LIST chunk between 'fmt ' and 'data'
    // must be skipped, not flag the file as malformed.
    {
        u8 buf[80] = {};
        WavWriteHeaderPcm(buf, 1, 22050, 8, 4);
        // The above wrote: RIFF/header(12) + fmt(8+16=24) + data(8+4=12) = 48 bytes.
        // We rebuild manually: RIFF/header(12) + fmt(24) + LIST(8 + 4 = 12) + data(8+4=12) = 56 bytes.
        // Easier: build the layout explicitly.
        u8 buf2[64] = {};
        // RIFF
        buf2[0] = 'R';
        buf2[1] = 'I';
        buf2[2] = 'F';
        buf2[3] = 'F';
        StoreU32Le(buf2 + 4, 64 - 8);
        buf2[8] = 'W';
        buf2[9] = 'A';
        buf2[10] = 'V';
        buf2[11] = 'E';
        // fmt
        buf2[12] = 'f';
        buf2[13] = 'm';
        buf2[14] = 't';
        buf2[15] = ' ';
        StoreU32Le(buf2 + 16, 16);
        StoreU16Le(buf2 + 20, kWavFormatTagPcm);
        StoreU16Le(buf2 + 22, 1);
        StoreU32Le(buf2 + 24, 22050);
        StoreU32Le(buf2 + 28, 22050);
        StoreU16Le(buf2 + 32, 1);
        StoreU16Le(buf2 + 34, 8);
        // LIST chunk (8-byte header + 4-byte payload)
        buf2[36] = 'L';
        buf2[37] = 'I';
        buf2[38] = 'S';
        buf2[39] = 'T';
        StoreU32Le(buf2 + 40, 4);
        // 4 bytes of payload at 44..47 (anything)
        // data chunk
        buf2[48] = 'd';
        buf2[49] = 'a';
        buf2[50] = 't';
        buf2[51] = 'a';
        StoreU32Le(buf2 + 52, 4);
        // 4 bytes of audio at 56..59
        const WavInfo info = WavParse(buf2, sizeof(buf2));
        KASSERT(info.ok, "util/wav", "LIST-skip parse failed");
        KASSERT(info.data_offset == 56, "util/wav", "LIST-skip data offset wrong");
        KASSERT(info.data_bytes == 4, "util/wav", "LIST-skip data bytes wrong");
        (void)buf;
    }

    // ----- Negative cases.
    {
        u8 buf[44];
        // Bad RIFF magic.
        WavWriteHeaderPcm(buf, 1, 44100, 16, 0);
        buf[0] = 'X';
        WavInfo info = WavParse(buf, sizeof(buf));
        KASSERT(!info.ok, "util/wav", "bad RIFF magic not rejected");

        // Bad WAVE magic.
        WavWriteHeaderPcm(buf, 1, 44100, 16, 0);
        buf[8] = 'X';
        info = WavParse(buf, sizeof(buf));
        KASSERT(!info.ok, "util/wav", "bad WAVE magic not rejected");

        // Non-PCM format tag.
        WavWriteHeaderPcm(buf, 1, 44100, 16, 0);
        StoreU16Le(buf + 20, 3); // IEEE float — not in v0 scope
        info = WavParse(buf, sizeof(buf));
        KASSERT(!info.ok, "util/wav", "non-PCM not rejected");

        // Too-truncated for fmt chunk.
        WavInfo info2 = WavParse(buf, 11);
        KASSERT(!info2.ok, "util/wav", "truncated not rejected");

        // Out-of-range bits_per_sample.
        WavWriteHeaderPcm(buf, 1, 44100, 12, 0);
        info = WavParse(buf, sizeof(buf));
        KASSERT(!info.ok, "util/wav", "bps=12 not rejected");
    }
}

} // namespace duetos::util
