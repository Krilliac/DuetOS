#pragma once

#include "drivers/audio/audio.h"
#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — Intel HDA driver: command/response rings + stream
 * descriptor scaffolding.
 *
 * Split out of `audio.cpp` (which kept growing past the 500-line
 * threshold) so the HDA-specific surface lives next to the audio
 * shell rather than inside it. The audio shell still owns PCI
 * discovery + classification; everything from "controller is
 * out of reset" to "codec walked + stream descriptor armed"
 * lives here.
 *
 * v0 surface:
 *   - `BringUp(controller)` — runs CRST, programs CORB+RIRB,
 *     walks every codec slot reported by STATESTS, records
 *     per-codec DAC / ADC / pin / amp / connection-list totals
 *     into the per-controller record. This was the old
 *     `HdaBringUp` static.
 *   - `IssueVerbAndPoll(controller, codec, node, verb, data)` —
 *     single-verb roundtrip via the CORB / RIRB rings. Public
 *     so a future codec configuration slice can issue
 *     SET_PIN_WIDGET_CONTROL etc. without re-implementing the
 *     ring marshaling.
 *   - `StreamArm(controller, dir, fmt, channels, bdl_phys,
 *     buffer_bytes, last_valid_index)` — programs an output
 *     (SD0..SDn) or input stream descriptor: BDLPL/BDLPU,
 *     CBL, LVI, FORMAT, STREAM_TAG. The ring is left armed but
 *     RUN is NOT set; flipping RUN requires a real BDL backed
 *     by guest memory the audio server has filled, which lives
 *     in the next slice. Returns the stream descriptor index
 *     the controller assigned (useful for tagging the codec
 *     converter that will pull from this stream).
 *   - `Teardown()` — frees the CORB / RIRB DMA region and
 *     clears the bring-up flag.
 *
 * Out of scope (v0):
 *   - IRQ wiring (we poll RIRBWP for verb responses; same
 *     applies to stream-position sync).
 *   - Codec configuration (SET_PIN_WIDGET_CONTROL,
 *     SET_AMP_GAIN_MUTE, SET_CONVERTER_FORMAT) — needs a real
 *     audio routing graph.
 *   - Multi-controller support — the static state is single-
 *     controller. A multi-HDA box logs the gap and skips bring
 *     up of the second controller.
 *
 * Thread-safety:
 *   - All public entry points run from boot context (single-
 *     CPU at the time HDA bring-up happens). After SMP brings
 *     APs online, callers must hold the audio server's mixer
 *     lock when calling StreamArm.
 */

namespace duetos::drivers::audio::hda
{

// Stream direction. The HDA spec puts input streams at SD index
// 0..ISS-1 and output streams at SD index ISS..ISS+OSS-1.
enum class StreamDirection : u8
{
    Input,
    Output,
};

// Stream-descriptor format register (SD_FORMAT) field encoding.
// Refer HDA spec §3.7.1 / §7.2.5. Most consumer setups use
// 16-bit / 48 kHz / 2-channel, which is the default we hard-
// code in the v0 ArmOutputStream() helper.
struct StreamFormat
{
    u8 channels;        // 1..16, encoded as (channels-1) into bits 3:0
    u8 bits_per_sample; // 8/16/20/24/32, encoded into bits 6:4
    u32 sample_rate;    // 48000/44100/96000/...
};

inline constexpr u32 kHdaCorbEntries = 256;
inline constexpr u32 kHdaRirbEntries = 256;
inline constexpr u32 kHdaCorbBytes = kHdaCorbEntries * 4;
inline constexpr u32 kHdaRirbBytes = kHdaRirbEntries * 8;

// 256 BDL entries × 16 bytes/entry = 4 KiB. The HDA spec caps
// LVI at 255 (8-bit field), so 256 is the maximum useful BDL
// size. v0 doesn't fill the BDL — StreamArm just programs the
// pointer. Future audio-server work allocates real audio buffer
// pages and writes BDL entries pointing at them.
inline constexpr u32 kHdaBdlEntries = 256;
inline constexpr u32 kHdaBdlBytes = kHdaBdlEntries * 16;

/// Bring up the controller's CORB / RIRB rings and walk every
/// codec slot the controller's STATESTS reports. Returns Ok on
/// success, Unsupported if a previous BringUp already ran.
::duetos::core::Result<void> BringUp(const AudioControllerInfo& a);

/// Pure-software verb roundtrip via CORB / RIRB. `verb12` is the
/// 12-bit verb id (e.g. 0xF00 = GET_PARAMETER); `data8` is the
/// 8-bit payload. Returns the 32-bit response, or 0 on timeout
/// (callers that care about the timeout-vs-zero ambiguity should
/// snapshot RIRBWP themselves; v0 callers just look for non-zero).
u32 IssueVerbAndPoll(const AudioControllerInfo& a, u8 codec, u8 node, u32 verb12, u8 data8);

/// Arm an HDA stream descriptor. Picks the lowest free SD slot
/// that matches `dir` and programs the BDLPL/BDLPU/CBL/LVI/
/// FORMAT registers. The RUN bit is NOT set — caller does that
/// once the BDL points at real buffer pages. Returns the stream
/// descriptor index (0..ISS+OSS-1) on success.
::duetos::core::Result<u8> StreamArm(const AudioControllerInfo& a, StreamDirection dir, const StreamFormat& fmt,
                                     u64 bdl_phys, u32 buffer_bytes, u8 last_valid_index);

/// Free CORB / RIRB / per-stream BDL DMA regions. Idempotent.
void Teardown();

/// Diagnostic accessors — used by audio shell logging.
bool IsBroughtUp();
u32 CodecVendorId(u8 slot);
u32 CodecDacCount(u8 slot);
u32 CodecAdcCount(u8 slot);
u32 CodecPinCount(u8 slot);
u32 CodecAmpWidgetCount(u8 slot);
u32 CodecConnTotal(u8 slot);
u32 CodecConnWidgetsRead(u8 slot);

/// Number of stream descriptors the controller reports (ISS+OSS).
/// Returns 0 if the controller hasn't been brought up.
u8 TotalStreamCount();

/// Number of stream descriptors `StreamArm` has armed since
/// bring-up. Bumped only on success.
u32 ArmedStreamCount();

} // namespace duetos::drivers::audio::hda
