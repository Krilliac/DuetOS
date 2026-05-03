#pragma once

#include "util/types.h"

/*
 * DuetOS — WAV (RIFF) parser + writer (clean room).
 *
 * Spec:
 *   - Microsoft WAVE / RIFF format reference (publicly published
 *     by Microsoft / IBM since the early 1990s).
 *   - WAVEFORMATEX struct definition (Win32 mmsystem.h).
 *
 * Scope (v0):
 *   - Only PCM (format tag 1, "WAVE_FORMAT_PCM") at 8 / 16 / 24 /
 *     32-bit-per-sample integer.
 *   - Single 'fmt ' chunk + single 'data' chunk. Spec allows
 *     multiple chunks with extension data ('LIST', 'INFO',
 *     'fact'); v0 walks past unknown chunks tolerantly until
 *     'data' or EOF.
 *   - Mono and stereo most common; parser exposes channel count
 *     up to 8 (spec maximum varies by format extension).
 *
 * Out of scope (deliberate):
 *   - WAVE_FORMAT_IEEE_FLOAT (3) — the WAV consumer in DuetOS
 *     today is "future sound effects" and stays integer-PCM
 *     until that lands.
 *   - WAVE_FORMAT_EXTENSIBLE (0xFFFE) — needs the GUID sub-format
 *     dispatch; can land alongside multichannel surround when
 *     real audio hardware brings it up.
 *   - Compressed formats (ADPCM, mu-law, MP3-in-WAV, etc.).
 *
 * Eventual consumer: a sound-effect player once an audio backend
 * (HDA / AC'97) lands. Until then, the boot KAT is the live
 * caller.
 *
 * No allocation, no global state.
 */

namespace duetos::util
{

inline constexpr u32 kWavRiffHeaderBytes = 12;  // "RIFF" + size + "WAVE"
inline constexpr u32 kWavFmtChunkMinBytes = 24; // "fmt " + size + 16 fields
inline constexpr u16 kWavFormatTagPcm = 0x0001;

struct WavInfo
{
    u16 format_tag;      // expected 1 (PCM); other values rejected
    u16 channels;        // 1..8
    u32 sample_rate_hz;  // typical 8000..192000
    u16 bits_per_sample; // 8/16/24/32
    u32 data_offset;     // byte offset within the source where audio samples start
    u32 data_bytes;      // 'data' chunk size in bytes
    bool ok;
};

/// Parse a WAV file in `src` (`src_len` bytes). On success
/// populates `info.ok=true` plus the metadata fields and the
/// byte range where the PCM samples live within `src`.
WavInfo WavParse(const u8* src, u32 src_len);

/// Write the canonical 44-byte RIFF / WAVE / 'fmt ' / 'data'
/// header for a PCM stream into `out`. `out` must have at least
/// 44 bytes available. Caller follows up by writing
/// `data_bytes` bytes of PCM samples after the header.
/// Returns the bytes written (44).
u32 WavWriteHeaderPcm(u8 out[44], u16 channels, u32 sample_rate_hz, u16 bits_per_sample, u32 data_bytes);

void WavSelfTest();

} // namespace duetos::util
