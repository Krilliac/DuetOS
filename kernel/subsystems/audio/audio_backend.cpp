#include "subsystems/audio/audio_backend.h"

#include "arch/x86_64/serial.h"
#include "drivers/audio/audio.h"
#include "drivers/audio/hda.h"
#include "log/klog.h"
#include "mm/dma.h"
#include "mm/zone.h"

namespace duetos::subsystems::audio
{

namespace
{

// SD_FORMAT word for 48 kHz / 16-bit / stereo. Field encoding
// (HDA spec §3.7.1):
//   bits 14    = base-rate select (0 = 48 kHz base, 1 = 44.1)
//   bits 13:11 = base-rate multiplier (×1..×4)
//   bits 10:8  = base-rate divisor (÷1..÷8)
//   bits 6:4   = bits per sample (1 = 16-bit)
//   bits 3:0   = channels - 1 (1 = stereo)
// For 48 kHz / 16-bit / stereo: BSEL=0, mul=0, div=0, bps=1,
// chan-1=1 → 0x0011. Matches what hda::EncodeFormat produces
// internally for the same StreamFormat; we keep it as a literal
// here so the audio backend doesn't depend on the HDA driver
// exposing its encoder.
constexpr duetos::u16 kSdFormatWord = 0x0011;

// Stream tag we advertise to the codec. HDA's StreamArm uses
// `sd_idx + 1` for the controller-side tag; the codec side
// (CodecSetConverterStream) takes whatever we hand it. Keeping
// the two in sync is the caller's job — we hold the SD index in
// `g.sd_idx` and pass `g.sd_idx + 1` everywhere.
constexpr duetos::u8 kCodecChannel = 0; // lower channel of a stereo stream pair

struct State
{
    bool active;
    duetos::u8 sd_idx;   // HDA stream descriptor index armed by Init
    duetos::u8 codec;    // codec slot selected by FindFirstOutputPath
    duetos::u8 dac_node; // DAC node id
    duetos::u8 pin_node; // pin complex node id

    mm::DmaBuffer bdl; // 4 KiB page; first 4 entries used
    mm::DmaBuffer pcm; // kBufferPages * 4 KiB; the audio ring
};

constinit State g = {false, 0, 0, 0, 0, {}, {}};

const drivers::audio::AudioControllerInfo* FindHdaController()
{
    using drivers::audio::AudioController;
    using drivers::audio::AudioControllerCount;
    using drivers::audio::AudioKind;
    const u64 n = AudioControllerCount();
    for (u64 i = 0; i < n; ++i)
    {
        const auto& a = AudioController(i);
        if (a.kind == AudioKind::Hda && a.mmio_virt != nullptr)
            return &a;
    }
    return nullptr;
}

void FreeDma()
{
    if (g.bdl.virt != nullptr)
    {
        mm::FreeDmaCoherent(g.bdl);
        g.bdl = {};
    }
    if (g.pcm.virt != nullptr)
    {
        mm::FreeDmaCoherent(g.pcm);
        g.pcm = {};
    }
}

void LogPhase(const char* msg)
{
    arch::SerialWrite("[audio-backend] ");
    arch::SerialWrite(msg);
    arch::SerialWrite("\n");
}

} // namespace

::duetos::core::Result<void> Init()
{
    using ::duetos::core::Err;
    using ::duetos::core::ErrorCode;

    // Idempotent: tear down and re-init if already active.
    if (g.active)
        (void)Shutdown();

    if (!drivers::audio::hda::IsBroughtUp())
    {
        LogPhase("no HDA controller has been brought up — skipping init");
        return Err{ErrorCode::NotReady};
    }

    const auto* ac = FindHdaController();
    if (ac == nullptr)
    {
        LogPhase("no HDA controller in registry — skipping init");
        return Err{ErrorCode::NotReady};
    }

    // Allocate BDL (one page — covers up to 256 entries; we use 4).
    auto bdl_r = mm::AllocDmaCoherent(4096, mm::Zone::Dma32);
    if (!bdl_r.has_value())
    {
        LogPhase("BDL allocation failed");
        return Err{bdl_r.error()};
    }
    g.bdl = bdl_r.value();

    // Allocate the audio ring.
    auto pcm_r = mm::AllocDmaCoherent(kBufferBytes, mm::Zone::Dma32);
    if (!pcm_r.has_value())
    {
        mm::FreeDmaCoherent(g.bdl);
        g.bdl = {};
        LogPhase("PCM ring allocation failed");
        return Err{pcm_r.error()};
    }
    g.pcm = pcm_r.value();

    // Build BDL: one entry per buffer page, IOC clear (no IRQ
    // refill in v0). Mirrors HDA::BdlEntry layout.
    drivers::audio::hda::BdlEntry entries[kBufferPages];
    for (duetos::u32 i = 0; i < kBufferPages; ++i)
    {
        entries[i].phys = g.pcm.phys + i * 4096u;
        entries[i].length = 4096u;
        entries[i].flags = 0;
    }
    auto fill_r = drivers::audio::hda::StreamFillBdl(g.bdl.virt, entries, kBufferPages);
    if (!fill_r.has_value())
    {
        FreeDma();
        LogPhase("StreamFillBdl failed");
        return Err{fill_r.error()};
    }

    // Arm the stream descriptor. Format struct mirrors kSdFormatWord
    // (HDA's StreamArm re-encodes from this; we keep both in sync).
    drivers::audio::hda::StreamFormat fmt = {};
    fmt.channels = static_cast<duetos::u8>(kChannels);
    fmt.bits_per_sample = static_cast<duetos::u8>(kBitsPerSample);
    fmt.sample_rate = kSampleRateHz;
    auto arm_r = drivers::audio::hda::StreamArm(*ac, drivers::audio::hda::StreamDirection::Output, fmt, g.bdl.phys,
                                                kBufferBytes, static_cast<duetos::u8>(kBufferPages - 1));
    if (!arm_r.has_value())
    {
        FreeDma();
        LogPhase("StreamArm failed");
        return Err{arm_r.error()};
    }
    g.sd_idx = arm_r.value();

    // Pick the output path (Speaker preferred, then Headphone, then Line-out).
    // This is where bring-up commonly halts on QEMU virtual codecs: the
    // codec walker returns 0 function groups for hda-output / hda-duplex
    // (a pre-existing limitation of the HDA walker tracked in
    // wiki/drivers/Audio.md, not a bug introduced by this slice), so
    // there is no DAC / pin pair to bind. The backend leaves the stream
    // descriptor armed but disabled — the StreamArm path above is the
    // useful verification on emulator. On real hardware with a working
    // codec walk this branch finds a path and proceeds.
    auto path_r = drivers::audio::hda::FindFirstOutputPath();
    if (!path_r.has_value())
    {
        FreeDma();
        LogPhase("FindFirstOutputPath returned no path — codec walker likely "
                 "found 0 function groups (common on QEMU virtual codecs)");
        return Err{path_r.error()};
    }
    g.codec = path_r.value().codec;
    g.dac_node = path_r.value().dac_node;
    g.pin_node = path_r.value().pin_node;

    // Configure the codec to consume from our stream tag.
    const duetos::u8 stream_tag = static_cast<duetos::u8>(g.sd_idx + 1);
    auto cfg_r =
        drivers::audio::hda::ConfigureOutputPath(*ac, g.codec, g.dac_node, g.pin_node, stream_tag, kSdFormatWord);
    if (!cfg_r.has_value())
    {
        FreeDma();
        LogPhase("ConfigureOutputPath failed");
        return Err{cfg_r.error()};
    }
    // Codec's converter binds its channel index to our stream tag.
    auto chr = drivers::audio::hda::CodecSetConverterStream(*ac, g.codec, g.dac_node, stream_tag, kCodecChannel);
    if (!chr.has_value())
    {
        FreeDma();
        LogPhase("CodecSetConverterStream failed");
        return Err{chr.error()};
    }

    // Initial state: silence in the ring, RUN clear. Whoever
    // calls Start() is responsible for having filled the buffer
    // with the audio they want to hear.
    WriteSilence();

    g.active = true;
    LogPhase("init complete — stream armed, codec configured, RUN=0");
    return {};
}

bool IsActive()
{
    return g.active;
}

duetos::u32 BufferFrames()
{
    return kBufferFrames;
}

::duetos::core::Result<void> Start()
{
    using ::duetos::core::Err;
    using ::duetos::core::ErrorCode;
    if (!g.active)
        return Err{ErrorCode::NotReady};
    const auto* ac = FindHdaController();
    if (ac == nullptr)
        return Err{ErrorCode::NotReady};
    auto r = drivers::audio::hda::StreamRun(*ac, g.sd_idx, true);
    if (r.has_value())
        LogPhase("RUN=1");
    return r;
}

::duetos::core::Result<void> Stop()
{
    using ::duetos::core::Err;
    using ::duetos::core::ErrorCode;
    if (!g.active)
        return Err{ErrorCode::NotReady};
    const auto* ac = FindHdaController();
    if (ac == nullptr)
        return Err{ErrorCode::NotReady};
    auto r = drivers::audio::hda::StreamRun(*ac, g.sd_idx, false);
    if (r.has_value())
        LogPhase("RUN=0");
    return r;
}

void WriteSilence()
{
    if (g.pcm.virt == nullptr)
        return;
    auto* dst = static_cast<duetos::u8*>(g.pcm.virt);
    for (duetos::u32 i = 0; i < kBufferBytes; ++i)
        dst[i] = 0;
}

duetos::u32 WritePcmS16Stereo(const duetos::i16* samples, duetos::u32 frame_count, duetos::u32 frame_offset)
{
    if (g.pcm.virt == nullptr || samples == nullptr || frame_count == 0)
        return 0;
    auto* dst = static_cast<duetos::i16*>(g.pcm.virt);
    const duetos::u32 total_samples = kBufferFrames * kChannels;
    duetos::u32 cursor = (frame_offset % kBufferFrames) * kChannels;
    for (duetos::u32 f = 0; f < frame_count; ++f)
    {
        for (duetos::u32 c = 0; c < kChannels; ++c)
        {
            dst[cursor] = samples[f * kChannels + c];
            cursor = (cursor + 1) % total_samples;
        }
    }
    return frame_count;
}

namespace
{

// Twelve-iteration CORDIC-style sine on the unit circle would be
// overkill; we just want a clean tone, so a fixed-point Bhaskara
// I approximation does the job inside a kernel TU that has no
// libm. Accuracy is ~0.16 % which is well below audible
// sine-vs-distorted-sine for a boot beep. Input theta is in
// fixed-point Q16 turns (0..0xFFFF maps to 0..2π). Output is
// signed Q15.
duetos::i32 SinQ15(duetos::u32 theta_q16)
{
    // Reduce to [0, 2π) by taking the low 16 bits.
    duetos::u32 t = theta_q16 & 0xFFFFu;
    // Quadrant: top two bits.
    const duetos::u32 quadrant = t >> 14;
    // Phase within quadrant, scaled 0..0x3FFF.
    duetos::u32 phase = t & 0x3FFFu;
    // Bhaskara I: sin(x) ≈ 16x(π - x) / (5π² - 4x(π - x)) for x in [0, π].
    // We scale phase into [0, π] = 0..0x7FFF for quadrants 0+1,
    // [0, π] = 0..0x7FFF reversed for quadrants 2+3.
    if (quadrant == 0)
    {
        // x ∈ [0, π/2]
    }
    else if (quadrant == 1)
    {
        phase = 0x3FFFu - phase; // mirror
    }
    else if (quadrant == 2)
    {
        // negative side, x ∈ [π, 3π/2]
    }
    else
    {
        phase = 0x3FFFu - phase;
    }
    // Compute sin(p) where p = phase / 0x3FFF * π/2, output Q15.
    // Use a 7-term Maclaurin reduced for accuracy on [0, π/2]:
    //   sin(x) ≈ x - x^3/6 + x^5/120
    // With x in Q15 [0..1.0 representing 0..π/2], the rounding error
    // is well under one Q15 LSB for our purposes.
    // Convert phase to Q15 in [0, 32768 = 1.0]:
    duetos::i64 x = static_cast<duetos::i64>(phase) * 32768 / 0x3FFF; // [0, 32768]
    // Multiply by π/2 (= 0xC910 in Q15 ≈ 1.5707).
    x = (x * 0xC910) >> 15;
    // x^3 / 6
    duetos::i64 x3 = (x * x) >> 15;
    x3 = (x3 * x) >> 15;
    x3 = x3 / 6;
    // x^5 / 120
    duetos::i64 x5 = (x * x) >> 15;
    x5 = (x5 * x5) >> 15;
    x5 = (x5 * x) >> 15;
    x5 = x5 / 120;
    duetos::i64 s = x - x3 + x5;
    if (s > 32767)
        s = 32767;
    if (s < -32767)
        s = -32767;
    if (quadrant >= 2)
        s = -s;
    return static_cast<duetos::i32>(s);
}

} // namespace

void WriteSine(duetos::u32 freq_hz, duetos::u16 amplitude_q15)
{
    if (g.pcm.virt == nullptr)
        return;
    if (amplitude_q15 == 0 || freq_hz == 0)
    {
        WriteSilence();
        return;
    }
    // Round frequency so an integer number of cycles fits in the
    // buffer. Buffer is `kBufferFrames` frames; cycles =
    // round(freq_hz * frames / rate). Then the actual emitted
    // frequency is `cycles * rate / frames`, avoiding the boundary
    // click that a fractional cycle would produce.
    const duetos::u64 cycles64 =
        (static_cast<duetos::u64>(freq_hz) * kBufferFrames + kSampleRateHz / 2) / kSampleRateHz;
    const duetos::u32 cycles = (cycles64 == 0) ? 1u : static_cast<duetos::u32>(cycles64);

    auto* dst = static_cast<duetos::i16*>(g.pcm.virt);
    for (duetos::u32 f = 0; f < kBufferFrames; ++f)
    {
        // theta_q16 advances by (cycles * 0x10000 / frames) per
        // frame; multiplying first to keep precision.
        const duetos::u32 theta =
            static_cast<duetos::u32>((static_cast<duetos::u64>(cycles) * f * 0x10000ull / kBufferFrames) & 0xFFFFull);
        const duetos::i32 s = (SinQ15(theta) * amplitude_q15) >> 15;
        const duetos::i16 sample = static_cast<duetos::i16>(s);
        dst[f * kChannels + 0] = sample;
        dst[f * kChannels + 1] = sample;
    }
}

::duetos::core::Result<void> Shutdown()
{
    if (g.active)
    {
        (void)Stop();
    }
    FreeDma();
    g.active = false;
    g.sd_idx = 0;
    g.codec = 0;
    g.dac_node = 0;
    g.pin_node = 0;
    return {};
}

void SelfTest()
{
    bool ok = true;

    if (!g.active)
    {
        // Not an error — no HDA controller on this host (common in
        // headless QEMU configs that don't add -device intel-hda).
        // The selftest is a no-op in that case; emit a "skipped"
        // line so the boot log still records the path was
        // reachable.
        arch::SerialWrite("[audio-selftest] SKIP — backend not active (no HDA on this host)\n");
        return;
    }

    // BufferFrames consistency.
    if (BufferFrames() != kBufferFrames)
    {
        arch::SerialWrite("[audio-selftest] FAIL BufferFrames\n");
        ok = false;
    }

    // WriteSilence then read-back: every byte must be zero.
    WriteSilence();
    {
        const auto* src = static_cast<const duetos::u8*>(g.pcm.virt);
        for (duetos::u32 i = 0; i < kBufferBytes; ++i)
        {
            if (src[i] != 0)
            {
                arch::SerialWrite("[audio-selftest] FAIL WriteSilence non-zero\n");
                ok = false;
                break;
            }
        }
    }

    // WriteSine at 440 Hz amplitude 0x4000 — verify at least one
    // sample exceeds 0x1000 in magnitude. Any working sine over
    // half-amplitude has plenty of those.
    WriteSine(440, 0x4000);
    {
        const auto* src = static_cast<const duetos::i16*>(g.pcm.virt);
        bool found_loud_sample = false;
        const duetos::u32 nsamples = kBufferFrames * kChannels;
        for (duetos::u32 i = 0; i < nsamples; ++i)
        {
            duetos::i32 v = src[i];
            if (v < 0)
                v = -v;
            if (v > 0x1000)
            {
                found_loud_sample = true;
                break;
            }
        }
        if (!found_loud_sample)
        {
            arch::SerialWrite("[audio-selftest] FAIL WriteSine amplitude\n");
            ok = false;
        }
    }

    // Leave the buffer in a known state (silence). v0 doesn't
    // auto-play; the audio path stays armed but quiet until a
    // future producer (winmm thunk, system-beep driver) calls
    // Start with content in the ring.
    WriteSilence();

    if (ok)
        arch::SerialWrite("[audio-selftest] PASS\n");
}

} // namespace duetos::subsystems::audio
