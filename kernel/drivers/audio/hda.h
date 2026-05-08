#pragma once

#include "drivers/audio/audio.h"
#include "drivers/audio/hda_jack.h"
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

/// Set / clear the RUN bit on stream descriptor `sd_idx`. The
/// caller must have armed the descriptor via StreamArm and
/// populated the BDL with real buffer pages first; setting RUN
/// against an empty BDL produces a stream of silence (or
/// whatever's in the un-initialised buffer). Returns Ok on
/// success.
::duetos::core::Result<void> StreamRun(const AudioControllerInfo& a, u8 sd_idx, bool run);

/// One BDL entry — see HDA spec §3.6.2. Each entry is 16
/// bytes: 8-byte buffer phys address, 4-byte length, 4-byte
/// flags (only IOC = bit 0 in v0).
struct BdlEntry
{
    u64 phys;
    u32 length;
    u32 flags; // bit 0 = IOC (interrupt on completion)
};

/// Populate `count` entries of a BDL at the kernel-virtual
/// address `bdl_virt`. The BDL must be 128-byte aligned and at
/// least `count * 16` bytes; cap is `kHdaBdlEntries`. Returns
/// Ok on success.
::duetos::core::Result<void> StreamFillBdl(void* bdl_virt, const BdlEntry* entries, u32 count);

/// Verb wrappers for codec configuration. Each issues a single
/// verb via IssueVerbAndPoll. v0 callers are the audio server
/// (when it lands) and the per-stream "play a tone" path.
///
/// SET_CONVERTER_FORMAT — programs the codec converter (0x2F00)
/// with the matching SD format value the controller is running.
::duetos::core::Result<void> CodecSetConverterFormat(const AudioControllerInfo& a, u8 codec, u8 node, u16 format);

/// SET_AMP_GAIN_MUTE — verb 0x300. The 16-bit payload encodes
/// (set output amp / set input amp / set left / set right /
/// gain index / mute bit). For "unmute output amp at moderate
/// gain" pass payload = 0xB000 | (gain & 0x7F).
::duetos::core::Result<void> CodecSetAmpGainMute(const AudioControllerInfo& a, u8 codec, u8 node, u16 payload);

/// SET_CONVERTER_STREAM_CHANNEL — verb 0x706. payload = (stream
/// tag << 4) | channel; channel 0 is the right answer for a
/// stereo converter taking the lower channel of a 2-channel
/// stream tag.
::duetos::core::Result<void> CodecSetConverterStream(const AudioControllerInfo& a, u8 codec, u8 node, u8 stream_tag,
                                                     u8 channel);

/// SET_PIN_WIDGET_CONTROL — verb 0x707. payload bits: 6 = output
/// enabled, 5 = input enabled, 7 = headphone amp enabled. For
/// "drive the speaker pin" pass 0x40.
::duetos::core::Result<void> CodecSetPinWidgetControl(const AudioControllerInfo& a, u8 codec, u8 node, u8 payload);

/// Best-effort output routing tuple selected from the codec
/// inventory. `codec`/`dac_node`/`pin_node` are suitable inputs
/// for ConfigureOutputPath once a stream descriptor has been
/// armed; `target` records whether the selector picked Speaker,
/// HpOut, or LineOut.
struct OutputPath
{
    u8 codec;
    u8 dac_node;
    u8 pin_node;
    HdaDefaultDevice target;
};

/// Find the first output path the v0 codec walker can justify:
/// prefer an internal speaker pin, then headphone-out, then
/// line-out, and pair it with the first DAC node recorded on the
/// same codec. This deliberately does not claim full topology
/// solving; it is a safe bootstrap heuristic for system-beep /
/// smoke playback until the codec graph walker parses mixer and
/// selector chains.
::duetos::core::Result<OutputPath> FindFirstOutputPath();

/// Stitched output-path bring-up — issues the five verbs the codec
/// needs to make a DAC drive a speaker pin in tandem with an HDA
/// stream descriptor:
///
///   1. SET_CONVERTER_FORMAT(dac_node, format)  — DAC pulls in the
///      same format the SD is configured for.
///   2. SET_AMP_GAIN_MUTE(dac_node, kAmpUnmuteOutMid) — un-mute the
///      DAC's output amp at moderate gain.
///   3. SET_AMP_GAIN_MUTE(pin_node, kAmpUnmuteOutMid) — un-mute the
///      pin complex's output amp (no-op on pins without one — the
///      codec acks but the verb has no effect; cheaper than walking
///      caps to skip).
///   4. SET_PIN_WIDGET_CONTROL(pin_node, kPinOutputEnable) — drive
///      the physical jack / speaker.
///   5. SET_CONVERTER_STREAM_CHANNEL(dac_node, stream_tag, 0) —
///      bind the DAC to the controller's stream descriptor.
///
/// Call FindFirstOutputPath() for the v0 bootstrap selector. A
/// future graph solver will replace that heuristic with real
/// DAC → mixer / selector → pin topology traversal; this helper
/// remains the verb-sequence facade so a future "play system
/// beep" driver doesn't have to know the order.
///
/// Returns Ok on success, NotReady when the HDA controller hasn't
/// been brought up, InvalidArgument on bad codec / node indices.
::duetos::core::Result<void> ConfigureOutputPath(const AudioControllerInfo& a, u8 codec, u8 dac_node, u8 pin_node,
                                                 u8 stream_tag, u16 format);

/// Common amplifier payload — set output amp, both channels,
/// un-muted, gain index 0x40 (≈ -32 dB on most codecs, audible
/// without being loud). `kAmpUnmuteOutMid` is 0xB040.
inline constexpr u16 kAmpPayloadSetOutBothMid = 0xB040;

/// Pin-widget control payload — output enable bit only.
inline constexpr u8 kPinPayloadOutputEnable = 0x40;

/// Verb-encoder self-test — exercises EncodeVerb (12+8 form) and
/// EncodeVerb16 (4+16 form) against canonical inputs and asserts
/// the bit layout matches HDA spec §7.3. Cheap and runs once at
/// boot. Catches future regressions in the verb-shape helpers.
void VerbEncodingSelfTest();

} // namespace duetos::drivers::audio::hda
