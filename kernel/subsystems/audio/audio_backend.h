#pragma once

#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — In-kernel audio backend (slice 2 of the ToaruOS clean-
 * room port).
 *
 * Sits above the HDA driver (`kernel/drivers/audio/hda*`) and below
 * any future producer of PCM data (`winmm!waveOutWrite` thunks, the
 * `xaudio2` translation layer, native apps that want a system beep).
 *
 * What this layer owns:
 *   - One DMA-coherent BDL (Buffer Descriptor List) and a small ring
 *     of audio buffer pages (`kBufferPages × kPageSize`).
 *   - The HDA stream descriptor armed against that BDL.
 *   - The codec output path (DAC → pin → speaker / headphone /
 *     line-out, selected by `hda::FindFirstOutputPath`).
 *   - The Start/Stop bit on the stream descriptor.
 *
 * What this layer does NOT own (yet — recorded for future slices):
 *   - Per-producer write cursors. v0 producers all choose their
 *     own `frame_offset`; if two producers happen to write at the
 *     same offset, their samples now SUM via saturating-add
 *     (`WritePcmS16Stereo`) instead of overwriting each other.
 *     Staggered-offset concurrent producers — where the kernel
 *     assigns each producer a moving cursor anchored ahead of
 *     LPIB — is the next mixer slice.
 *   - Format conversion or sample-rate conversion. v0 is fixed at
 *     S16LE / 48 kHz / stereo — the HDA consumer default.
 *   - IRQ-driven buffer refill (IOC bits stay clear; the HDA DMA
 *     just loops the BDL forever). A future slice that wants to
 *     stream a longer track than the ring fits adds the IRQ path
 *     and a per-buffer refill callback.
 *   - winmm / xaudio2 thunking. That needs a new `SYS_AUDIO_*`
 *     syscall surface; slice 3 work.
 *
 * Studied ToaruOS modules/hda.c for the BDL-loop pattern (one
 * audio buffer broken into N descriptors, looping forever via
 * LVI). No code copied; this implementation drives the
 * DuetOS-side HDA API (`hda::StreamArm`, `StreamFillBdl`,
 * `StreamRun`, `ConfigureOutputPath`) which is itself in-tree.
 *
 * Context: kernel. `Init` runs once at boot after `AudioInit` +
 * `hda::BringUp` have populated the controller table. Not safe
 * from IRQ context (BDL writes go through `mm::AllocDmaCoherent`
 * helpers that are not IRQ-locked).
 */

namespace duetos::subsystems::audio
{

/// Audio stream format hard-coded for v0. Every consumer is
/// responsible for converting to this shape before calling
/// `WritePcmS16Stereo`. The constants exist as plain `inline
/// constexpr` so producers can pre-allocate buffers correctly
/// sized without referring to HDA internals.
inline constexpr duetos::u32 kSampleRateHz = 48000;
inline constexpr duetos::u32 kBitsPerSample = 16;
inline constexpr duetos::u32 kChannels = 2;
inline constexpr duetos::u32 kBytesPerFrame = (kBitsPerSample / 8) * kChannels;

/// Audio buffer ring. Four 4 KiB pages = 16 KiB = ~85 ms of
/// 48 kHz stereo S16LE PCM. Enough to hold a complete tone for a
/// boot-beep without IRQ-driven refills. Producers that need
/// longer playback will land in a follow-up slice that adds the
/// IOC + refill path.
inline constexpr duetos::u32 kBufferPages = 4;
inline constexpr duetos::u32 kBufferBytes = kBufferPages * 4096u;
inline constexpr duetos::u32 kBufferFrames = kBufferBytes / kBytesPerFrame;

/// Bring the backend up: locate the first HDA controller, allocate
/// the BDL + buffer pages, arm the stream, configure the codec
/// output path. Idempotent (re-init clears state and re-runs).
/// Stream descriptor's RUN bit is LEFT AT 0; call `Start()` once
/// the buffer has been populated.
///
/// Returns `NotReady` if no HDA controller is registered or the
/// HDA driver hasn't been brought up; `OutOfMemory` if the DMA
/// allocation fails; `InvalidArgument` from the underlying HDA
/// arm path if the controller advertises no output streams.
::duetos::core::Result<void> Init();

/// True iff Init configured an audible DAC→pin codec path. When
/// false the stream/DMA byte path is still armed and usable (a
/// producer's samples are DMA'd) but nothing reaches a speaker —
/// the pre-existing HDA codec-walker limitation on QEMU virtual
/// codecs. Real hardware with a working codec walk returns true.
bool CodecRouted();

/// Current HDA stream Link Position In Buffer (bytes consumed by
/// the DMA engine, wrapping at the buffer size). Advancing while
/// the stream is running proves the controller is pulling samples.
duetos::u32 StreamPos();

/// True iff `Init` succeeded since the last `Shutdown`. Consumers
/// check this before submitting samples; submitting to an inactive
/// backend is a silent no-op (the caller's contract is "if active,
/// you got audio; if inactive, the device wasn't there").
bool IsActive();

/// Total frames the active buffer ring holds. Same as
/// `kBufferFrames` — exposed as a function so the caller's code
/// reads as "ask the backend" rather than referring to the
/// kBufferFrames constant directly (the caller doesn't care
/// about the page-count factorisation).
duetos::u32 BufferFrames();

/// Set / clear the stream descriptor's RUN bit. Once RUN=1 the HDA
/// DMA engine reads the buffer ring continuously, looping back to
/// the first entry after the last (LVI). Stopping is graceful: the
/// DMA finishes its current burst, then halts.
///
/// Returns `NotReady` if `Init` hasn't succeeded yet; underlying
/// HDA errors are propagated unchanged.
::duetos::core::Result<void> Start();
::duetos::core::Result<void> Stop();

/// Zero the entire buffer ring. Useful between consumers to avoid
/// leaking the previous producer's audio into the new one's
/// stream.
void WriteSilence();

/// Mix `frame_count` frames of S16LE-stereo PCM into the buffer
/// ring at frame offset `frame_offset`, **saturating-adding** each
/// sample onto whatever is already there. Wraps modulo
/// `BufferFrames()`. `samples` is interpreted as
/// `[L0, R0, L1, R1, ...]` — the same interleaving HDA expects on
/// the wire.
///
/// Two producers writing at the same offset (e.g. two PEs both
/// calling `SYS_AUDIO_WRITE` with frame_offset 0) compose by sum
/// instead of overwriting each other — that's the v0 mixer. To
/// replace ring contents instead of mixing onto them, use
/// `WritePcmS16StereoOverwrite`.
///
/// Returns the number of frames actually written (always equal
/// to `frame_count` for v0; future flow-control variants may
/// return less).
duetos::u32 WritePcmS16Stereo(const duetos::i16* samples, duetos::u32 frame_count, duetos::u32 frame_offset);

/// Replace `frame_count` frames in the buffer ring at frame
/// offset `frame_offset` with the supplied S16LE-stereo PCM. This
/// is the legacy "single-producer overwrite" path retained for
/// fill-the-entire-buffer producers like `WriteSine` and the boot
/// tone generators. Producer code that wants to coexist with
/// other producers should use `WritePcmS16Stereo` (additive).
///
/// Returns the number of frames actually written.
duetos::u32 WritePcmS16StereoOverwrite(const duetos::i16* samples, duetos::u32 frame_count, duetos::u32 frame_offset);

/// Fill the entire buffer with a `freq_hz` sine wave at amplitude
/// `amplitude_q15` (peak absolute value out of 32767). Convenience
/// for system-tone producers and the self-test. amplitude_q15 = 0
/// is equivalent to WriteSilence(). Frequency is rounded to the
/// nearest integer cycle that fits the buffer to avoid clicks at
/// the loop boundary.
void WriteSine(duetos::u32 freq_hz, duetos::u16 amplitude_q15);

/// Master output volume, 0..100 percent (clamped). Applied as a gain to
/// every producer sample written via the WritePcm* paths; the stored
/// level survives mute/un-mute. Default 80. GAP: applied at write time
/// (no kernel hook on the HDA DMA read), and the audible result is
/// unverified on this host (DuetOS audio is QEMU-smoke-only, never heard)
/// — revisit on real HDA hardware.
void AudioSetMasterVolume(duetos::u8 pct);
duetos::u8 AudioGetMasterVolume();

/// Mute / un-mute. While muted the applied gain is 0 regardless of the
/// stored master volume.
void AudioSetMuted(bool muted);
bool AudioIsMuted();

/// Tear down: stop the stream, free DMA, clear state. Idempotent.
::duetos::core::Result<void> Shutdown();

/// Boot self-test. Runs after `Init` would have been called. Pure
/// state-machine exercise — does not call Start (which would play
/// audio that's unwanted on a headless CI boot). Verifies:
///   - WriteSilence zeros the buffer (read-back through the
///     direct-map alias).
///   - WriteSine yields non-zero samples at the expected period.
///   - BufferFrames is consistent with kBufferFrames.
/// Emits `[audio-selftest] PASS` on success.
void SelfTest();

} // namespace duetos::subsystems::audio
