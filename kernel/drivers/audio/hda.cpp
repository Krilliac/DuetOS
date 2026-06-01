/*
 * DuetOS — Intel HDA driver: implementation.
 *
 * See `hda.h` for v0 scope. The bring-up + codec walker code was
 * moved here verbatim from `audio.cpp`; the stream descriptor
 * arming code (`StreamArm`) is new.
 */

#include "drivers/audio/hda.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "drivers/audio/hda_jack.h"
#include "drivers/audio/hda_jack_inventory.h"
#include "log/klog.h"
#include "mm/dma.h"
#include "mm/paging.h"
#include "mm/zone.h"
#include "time/timekeeper.h"

namespace duetos::drivers::audio::hda
{

namespace
{

// ----------------------------------------------------------------------------
// Register offsets and bit fields. See HDA spec §3.3 (controller
// registers) and §3.4 (stream descriptor block).
// ----------------------------------------------------------------------------

// Global control / capability registers.
constexpr u64 kHdaRegGcap = 0x00;
constexpr u64 kHdaRegGctl = 0x08;
constexpr u64 kHdaRegStatests = 0x0E;
constexpr u64 kHdaRegRirbwp = 0x58;

// CORB / RIRB.
constexpr u64 kHdaRegCorblbase = 0x40;
constexpr u64 kHdaRegCorbubase = 0x44;
constexpr u64 kHdaRegCorbwp = 0x48;
constexpr u64 kHdaRegCorbrp = 0x4A;
constexpr u64 kHdaRegCorbctl = 0x4C;
constexpr u64 kHdaRegCorbsize = 0x4E;
constexpr u64 kHdaRegRirblbase = 0x50;
constexpr u64 kHdaRegRirbubase = 0x54;
constexpr u64 kHdaRegRintcnt = 0x5A;
constexpr u64 kHdaRegRirbctl = 0x5C;
constexpr u64 kHdaRegRirbsts = 0x5D;
constexpr u64 kHdaRegRirbsize = 0x5E;

// Immediate Command Interface (HDA spec §3.4.3). The single-verb
// fallback used when the CORB/RIRB DMA engine isn't advancing
// (QEMU's intel-hda only runs the CORB engine once; this is also
// Linux's `single_cmd` path and is implemented by virtually every
// real Intel/AMD HDA controller).
constexpr u64 kHdaRegIcoi = 0x60;    // Immediate Command Output (32-bit)
constexpr u64 kHdaRegIcii = 0x64;    // Immediate Command Input  (32-bit)
constexpr u64 kHdaRegIcis = 0x68;    // Immediate Command Status (16-bit)
constexpr u16 kHdaIcisIcb = 1u << 0; // Immediate Command Busy
constexpr u16 kHdaIcisIrv = 1u << 1; // Immediate Result Valid

constexpr u32 kHdaGctlCrst = 1u << 0;
constexpr u8 kHdaCorbctlRun = 1u << 1;
constexpr u8 kHdaRirbctlDmaen = 1u << 1;
constexpr u8 kHdaSizeSel256 = 0x02;
constexpr u16 kHdaCorbrpRst = 1u << 15;
constexpr u16 kHdaRirbwpRst = 1u << 15;

// Per-stream descriptor offsets. Each SD lives in a 0x20-byte
// block starting at MMIO 0x80. SD0 is at 0x80; SDn is at
// 0x80 + n*0x20.
constexpr u64 kHdaSdBase = 0x80;
constexpr u64 kHdaSdStride = 0x20;
constexpr u64 kHdaSdRegCtl = 0x00;    // 3 bytes (CTL[0..23])
constexpr u64 kHdaSdRegLpib = 0x04;   // 4 bytes — Link Position In Buffer (RO)
constexpr u64 kHdaSdRegCbl = 0x08;    // 4 bytes — Cyclic Buffer Length
constexpr u64 kHdaSdRegLvi = 0x0C;    // 2 bytes — Last Valid Index
constexpr u64 kHdaSdRegFormat = 0x12; // 2 bytes
constexpr u64 kHdaSdRegBdlPl = 0x18;  // 4 bytes — BDL phys low
constexpr u64 kHdaSdRegBdlPu = 0x1C;  // 4 bytes — BDL phys high

// Stream descriptor CTL bits (24-bit field, low byte). SRST
// resets the descriptor; RUN starts the DMA engine pulling from
// the BDL into the link. StreamArm() programs SRST + BDL pointer
// + CBL/LVI/FORMAT + the stream tag, leaving RUN clear; StreamRun()
// flips RUN once the caller's BDL points at real buffer pages.
// STS (interrupt/error status) and FIFOD bits are not consumed
// yet — see the position-buffer / IRQ GAP at StreamPosition().
constexpr u8 kHdaSdCtlSrst = 1u << 0; // Stream reset
constexpr u8 kHdaSdCtlRun = 1u << 1;  // Stream run

constexpr u32 kHdaVerbGetParameter = 0xF00;
constexpr u32 kHdaVerbGetConnListEntry = 0xF02;
constexpr u32 kHdaParamVendorId = 0x00;
constexpr u32 kHdaParamRevisionId = 0x02;
constexpr u32 kHdaParamSubordinateNodeCount = 0x04;
constexpr u32 kHdaParamFunctionGroupType = 0x05;
constexpr u32 kHdaParamAudioWidgetCaps = 0x09;
constexpr u32 kHdaParamAmpCapsInput = 0x0D;
constexpr u32 kHdaParamConnListLength = 0x0E;
constexpr u32 kHdaParamAmpCapsOutput = 0x12;
constexpr u32 kHdaWidgetCapInAmp = 1u << 1;
constexpr u32 kHdaWidgetCapOutAmp = 1u << 2;
constexpr u32 kHdaWidgetCapConnList = 1u << 8;
constexpr u32 kHdaWidgetAudioOutput = 0x0;
constexpr u32 kHdaWidgetAudioInput = 0x1;
constexpr u32 kHdaWidgetPinComplex = 0x4;
constexpr u32 kHdaFunctionGroupAudio = 0x01;
constexpr u32 kHdaFunctionGroupModem = 0x02;

constexpr u64 kHdaCorbOffset = 0;
constexpr u64 kHdaRirbOffset = kHdaCorbBytes;
constexpr u64 kHdaScratchBytes = mm::kPageSize;

// ----------------------------------------------------------------------------
// MMIO accessor helpers. Read-only on null `mmio_virt` returns 0;
// writes silently no-op so an unmapped controller never faults.
// ----------------------------------------------------------------------------
u8 Mmio8(const AudioControllerInfo& a, u64 offset)
{
    if (a.mmio_virt == nullptr)
        return 0;
    return *reinterpret_cast<volatile u8*>(static_cast<u8*>(a.mmio_virt) + offset);
}
u16 Mmio16(const AudioControllerInfo& a, u64 offset)
{
    if (a.mmio_virt == nullptr)
        return 0;
    return *reinterpret_cast<volatile u16*>(static_cast<u8*>(a.mmio_virt) + offset);
}
u32 Mmio32(const AudioControllerInfo& a, u64 offset)
{
    if (a.mmio_virt == nullptr)
        return 0;
    return *reinterpret_cast<volatile u32*>(static_cast<u8*>(a.mmio_virt) + offset);
}
void Mmio8Write(const AudioControllerInfo& a, u64 offset, u8 v)
{
    if (a.mmio_virt == nullptr)
        return;
    *reinterpret_cast<volatile u8*>(static_cast<u8*>(a.mmio_virt) + offset) = v;
}
void Mmio16Write(const AudioControllerInfo& a, u64 offset, u16 v)
{
    if (a.mmio_virt == nullptr)
        return;
    *reinterpret_cast<volatile u16*>(static_cast<u8*>(a.mmio_virt) + offset) = v;
}
void Mmio32Write(const AudioControllerInfo& a, u64 offset, u32 v)
{
    if (a.mmio_virt == nullptr)
        return;
    *reinterpret_cast<volatile u32*>(static_cast<u8*>(a.mmio_virt) + offset) = v;
}

u32 EncodeVerb(u8 codec, u8 node, u32 verb12, u8 data8)
{
    return (static_cast<u32>(codec) << 28) | (static_cast<u32>(node) << 20) | ((verb12 & 0xFFFu) << 8) | data8;
}

// 4-bit-verb / 16-bit-payload encoder. HDA spec §7.3.1: the verb
// id occupies bits 19:16 and the payload occupies bits 15:0.
// Used for SET_CONVERTER_FORMAT (verb 0x2), SET_AMP_GAIN_MUTE
// (verb 0x3), and any other verb whose payload exceeds 8 bits.
// Callers pass verb12 in the same 0x2NN / 0x3NN form they use
// for the 12-bit shape; we extract the high nibble.
u32 EncodeVerb16(u8 codec, u8 node, u32 verb12, u16 payload16)
{
    return (static_cast<u32>(codec) << 28) | (static_cast<u32>(node) << 20) |
           ((static_cast<u32>(verb12) & 0xF00u) << 8) | static_cast<u32>(payload16);
}

// HDA stream FORMAT register layout (HDA spec §3.7.1 / §7.2.5):
//   bits 14    = Sample-base rate (1 = 44.1 kHz, 0 = 48 kHz)
//   bits 13:11 = Base-rate multiplier (×1, ×2, ×3, ×4)
//   bits 10:8  = Base-rate divisor (÷1, ÷2, ÷3, ÷4, ÷5, ÷6, ÷7, ÷8)
//   bits 6:4   = Bits per sample (0=8, 1=16, 2=20, 3=24, 4=32)
//   bits 3:0   = Number of channels - 1
u16 EncodeFormat(const StreamFormat& fmt)
{
    u16 v = static_cast<u16>((fmt.channels == 0 ? 0 : (fmt.channels - 1)) & 0xF);

    u16 bps_field = 0;
    switch (fmt.bits_per_sample)
    {
    case 8:
        bps_field = 0;
        break;
    case 16:
        bps_field = 1;
        break;
    case 20:
        bps_field = 2;
        break;
    case 24:
        bps_field = 3;
        break;
    case 32:
        bps_field = 4;
        break;
    default:
        bps_field = 1;
        break;
    }
    v = static_cast<u16>(v | (bps_field << 4));

    // 48 kHz multiples take base=0; 44.1 kHz multiples take base=1.
    // Divisor field encodes how the base × multiplier maps onto the
    // requested rate. v0 only handles the canonical rates that
    // clear ÷1 with a simple multiplier; anything else falls back to
    // 48 kHz.
    u16 base = 0;
    u16 mult = 0;
    u16 div = 0;
    switch (fmt.sample_rate)
    {
    case 48000:
        base = 0;
        mult = 0;
        div = 0;
        break;
    case 96000:
        base = 0;
        mult = 1;
        div = 0;
        break;
    case 192000:
        base = 0;
        mult = 3;
        div = 0;
        break;
    case 44100:
        base = 1;
        mult = 0;
        div = 0;
        break;
    case 88200:
        base = 1;
        mult = 1;
        div = 0;
        break;
    default:
        base = 0;
        mult = 0;
        div = 0;
        break;
    }
    v = static_cast<u16>(v | (base << 14) | (mult << 11) | (div << 8));
    return v;
}

// One global HDA bring-up state — only one HDA controller is
// expected on consumer hardware. Multi-controller systems would
// need this to become a per-controller record.
struct HdaState
{
    mm::DmaBuffer dma;
    bool live;
    bool use_ici; // sticky: CORB/RIRB stalled, use Immediate Command IF
    u16 corb_wp;
    u32 codec_vendor[15];
    u32 codec_dac_count[15];
    u8 codec_first_dac_node[15];
    u32 codec_adc_count[15];
    u32 codec_pin_count[15];
    u32 codec_amp_widget_count[15];
    u32 codec_conn_total[15];
    u32 codec_conn_widgets_read[15];
    bool brought_up;
    u8 input_stream_count;  // ISS field of GCAP
    u8 output_stream_count; // OSS field of GCAP
    u32 streams_armed;
    // Per-SD bitmap of slots currently armed by StreamArm.
    // Size must match ISS+OSS+BSS upper bound (15+15+30 = 60);
    // a 64-bit mask is the cleanest fit.
    u64 armed_mask;
};
constinit HdaState g = {};

const char* WidgetTypeName(u32 type_code)
{
    switch (type_code)
    {
    case kHdaWidgetAudioOutput:
        return "audio-output";
    case kHdaWidgetAudioInput:
        return "audio-input";
    case kHdaWidgetPinComplex:
        return "pin-complex";
    default:
        return "other";
    }
}

void WalkCodec(const AudioControllerInfo& a, u8 slot);

} // namespace

namespace
{

// Per-verb response timeout. QEMU's intel-hda processes the CORB
// from a controller transfer that is NOT synchronous with the
// CORBWP MMIO write — the response can land tens of microseconds to
// a millisecond later. The old fixed 1024-`pause` bound (a few µs
// on TCG) timed out for every verb after the first warm one, which
// is why the codec walker read SubordinateNodeCount == 0. A
// monotonic-clock deadline is correct regardless of host speed.
constexpr u64 kHdaVerbTimeoutNs = 20ULL * 1000 * 1000; // 20 ms

// Immediate Command Interface single-verb roundtrip (HDA §3.4.3).
// Synchronous: write ICOI, set ICS.ICB, poll ICB clear + IRV set,
// read ICII. Returns the response, or 0 on timeout. This is the
// real-hardware-valid fallback (≈ Linux's `single_cmd`) for when
// the CORB/RIRB DMA engine doesn't advance.
u32 IciDispatch(const AudioControllerInfo& a, u32 verb)
{
    const u64 idle_deadline = time::MonotonicNs() + kHdaVerbTimeoutNs;
    while ((Mmio16(a, kHdaRegIcis) & kHdaIcisIcb) != 0)
    {
        if (time::MonotonicNs() >= idle_deadline)
            return 0;
        arch::Inb(0x80);
    }
    // Clear a stale Immediate-Result-Valid (write-1-to-clear) so we
    // observe THIS command's completion, then issue.
    Mmio16Write(a, kHdaRegIcis, kHdaIcisIrv);
    Mmio32Write(a, kHdaRegIcoi, verb);
    Mmio16Write(a, kHdaRegIcis, kHdaIcisIcb);

    const u64 deadline = time::MonotonicNs() + kHdaVerbTimeoutNs;
    for (;;)
    {
        const u16 ics = Mmio16(a, kHdaRegIcis);
        if ((ics & kHdaIcisIcb) == 0 && (ics & kHdaIcisIrv) != 0)
        {
            const u32 resp = Mmio32(a, kHdaRegIcii);
            Mmio16Write(a, kHdaRegIcis, kHdaIcisIrv); // ack IRV
            return resp;
        }
        if (time::MonotonicNs() >= deadline)
            return 0;
        arch::Inb(0x80);
        asm volatile("pause" ::: "memory");
    }
}

// Shared verb dispatch. Primary path is CORB/RIRB DMA (what real
// hardware prefers). If the CORB engine doesn't advance the RIRB
// within the deadline — QEMU's intel-hda runs the CORB engine only
// once (verified: CORBRP freezes at 1 while CORBWP advances and
// CORBCTL.RUN stays set) — we latch a sticky `use_ici` and serve
// this and all future verbs through the Immediate Command
// Interface. Mirrors Linux's CORB→single_cmd fallback.
u32 DispatchVerb(const AudioControllerInfo& a, u32 verb)
{
    if (!g.live)
        return 0;
    if (g.use_ici)
        return IciDispatch(a, verb);

    auto* corb = static_cast<volatile u32*>(g.dma.virt) + (kHdaCorbOffset / sizeof(u32));
    auto* rirb = reinterpret_cast<volatile u64*>(static_cast<u8*>(g.dma.virt) + kHdaRirbOffset);

    const u16 rirb_wp_before = Mmio16(a, kHdaRegRirbwp) & 0xFFu;
    g.corb_wp = static_cast<u16>((g.corb_wp + 1) % kHdaCorbEntries);
    corb[g.corb_wp] = verb;
    mm::DmaSyncForDevice(g.dma, kHdaCorbOffset, kHdaCorbBytes);
    Mmio16Write(a, kHdaRegCorbwp, g.corb_wp);

    const u64 deadline = time::MonotonicNs() + kHdaVerbTimeoutNs;
    for (;;)
    {
        const u16 rirb_wp_now = Mmio16(a, kHdaRegRirbwp) & 0xFFu;
        if (rirb_wp_now != rirb_wp_before)
        {
            mm::DmaSyncForCpu(g.dma, kHdaRirbOffset, kHdaRirbBytes);
            return static_cast<u32>(rirb[rirb_wp_now] & 0xFFFFFFFFu);
        }
        if (time::MonotonicNs() >= deadline)
        {
            // One-time, kept (gated) diagnostic — the CORB stall
            // fingerprint a future regression in this area needs.
            g.use_ici = true;
            KLOG_WARN_V("drivers/audio/hda", "CORB/RIRB stalled — switching to Immediate Command IF; verb", verb);
            KLOG_DEBUG_V("drivers/audio/hda", "  CORBWP", Mmio16(a, kHdaRegCorbwp) & 0xFFu);
            KLOG_DEBUG_V("drivers/audio/hda", "  CORBRP", Mmio16(a, kHdaRegCorbrp) & 0xFFu);
            KLOG_DEBUG_V("drivers/audio/hda", "  CORBCTL", Mmio8(a, kHdaRegCorbctl));
            KLOG_DEBUG_V("drivers/audio/hda", "  RIRBSTS", Mmio8(a, kHdaRegRirbsts));
            return IciDispatch(a, verb);
        }
        arch::Inb(0x80); // ~1 µs IO-port delay so QEMU advances time
        asm volatile("pause" ::: "memory");
    }
}

u32 IssueVerbRawAndPoll(const AudioControllerInfo& a, u32 verb)
{
    return DispatchVerb(a, verb);
}

} // namespace

u32 IssueVerbAndPoll(const AudioControllerInfo& a, u8 codec, u8 node, u32 verb12, u8 data8)
{
    return DispatchVerb(a, EncodeVerb(codec, node, verb12, data8));
}

namespace
{

void WalkCodec(const AudioControllerInfo& a, u8 slot)
{
    const u32 root_subordinates = IssueVerbAndPoll(a, slot, 0, kHdaVerbGetParameter, kHdaParamSubordinateNodeCount);
    const u32 fg_start = (root_subordinates >> 16) & 0xFF;
    const u32 fg_count = root_subordinates & 0xFF;

    arch::SerialWrite("[hda]   slot=");
    arch::SerialWriteHex(slot);
    arch::SerialWrite(" function-groups: start=");
    arch::SerialWriteHex(fg_start);
    arch::SerialWrite(" count=");
    arch::SerialWriteHex(fg_count);
    arch::SerialWrite("\n");

    if (fg_count == 0 || fg_start == 0)
        return;

    u32 dac = 0;
    u8 first_dac_node = 0;
    u32 adc = 0;
    u32 pin = 0;
    u32 amp_widgets = 0;
    u32 conn_total = 0;
    u32 conn_widgets_read = 0;
    const u32 fg_walk_limit = (fg_count > 4) ? 4 : fg_count;
    for (u32 fg_idx = 0; fg_idx < fg_walk_limit; ++fg_idx)
    {
        const u8 fg_node = static_cast<u8>(fg_start + fg_idx);
        const u32 fg_type = IssueVerbAndPoll(a, slot, fg_node, kHdaVerbGetParameter, kHdaParamFunctionGroupType);
        const u32 fg_type_code = fg_type & 0x7F;
        arch::SerialWrite("[hda]     fg node=");
        arch::SerialWriteHex(fg_node);
        arch::SerialWrite(" type=");
        arch::SerialWriteHex(fg_type_code);
        if (fg_type_code == kHdaFunctionGroupAudio)
            arch::SerialWrite(" (audio)");
        else if (fg_type_code == kHdaFunctionGroupModem)
            arch::SerialWrite(" (modem)");
        arch::SerialWrite("\n");

        if (fg_type_code != kHdaFunctionGroupAudio)
            continue;

        const u32 fg_subnodes = IssueVerbAndPoll(a, slot, fg_node, kHdaVerbGetParameter, kHdaParamSubordinateNodeCount);
        const u32 widget_start = (fg_subnodes >> 16) & 0xFF;
        const u32 widget_count = fg_subnodes & 0xFF;
        const u32 widget_walk_limit = (widget_count > 64) ? 64 : widget_count;
        for (u32 w_idx = 0; w_idx < widget_walk_limit; ++w_idx)
        {
            const u8 widget_node = static_cast<u8>(widget_start + w_idx);
            const u32 caps = IssueVerbAndPoll(a, slot, widget_node, kHdaVerbGetParameter, kHdaParamAudioWidgetCaps);
            const u32 wtype = (caps >> 20) & 0xF;
            switch (wtype)
            {
            case kHdaWidgetAudioOutput:
                if (dac == 0)
                    first_dac_node = widget_node;
                ++dac;
                break;
            case kHdaWidgetAudioInput:
                ++adc;
                break;
            case kHdaWidgetPinComplex:
                ++pin;
                {
                    // Pull the 32-bit Pin Configuration Default
                    // (verb 0xF1C, see hda_jack.h) and stamp the
                    // inventory. The decoder is pure; the
                    // inventory is the kernel-wide table the
                    // `hdajacks` shell command + the audio
                    // server's path-selection consume.
                    const u32 cfg_raw = IssueVerbAndPoll(a, slot, widget_node, kHdaVerbGetConfigDefault, 0);
                    HdaJackInventoryRecord(slot, widget_node, cfg_raw);

                    // Initial presence read. Some pins have no
                    // sense capability — the verb returns 0 in
                    // that case and the cached presence stays
                    // "unknown" until a real response arrives.
                    const u32 sense = IssueVerbAndPoll(a, slot, widget_node, kHdaVerbGetPinSense, 0);
                    if (sense != 0)
                        HdaJackInventoryStampPresence(slot, widget_node, sense);

                    HdaPinConfigDefault decoded = HdaDecodePinConfigDefault(cfg_raw);
                    HdaPinConfigDefaultLog(slot, widget_node, decoded);
                }
                break;
            default:
                break;
            }
            (void)WidgetTypeName(wtype);
            if ((caps & (kHdaWidgetCapInAmp | kHdaWidgetCapOutAmp)) != 0)
            {
                if ((caps & kHdaWidgetCapInAmp) != 0)
                {
                    (void)IssueVerbAndPoll(a, slot, widget_node, kHdaVerbGetParameter, kHdaParamAmpCapsInput);
                }
                if ((caps & kHdaWidgetCapOutAmp) != 0)
                {
                    (void)IssueVerbAndPoll(a, slot, widget_node, kHdaVerbGetParameter, kHdaParamAmpCapsOutput);
                }
                ++amp_widgets;
            }
            if ((caps & kHdaWidgetCapConnList) != 0)
            {
                const u32 conn = IssueVerbAndPoll(a, slot, widget_node, kHdaVerbGetParameter, kHdaParamConnListLength);
                const u32 conn_count = conn & 0x7Fu;
                conn_total += conn_count;
                if (conn_count > 0)
                {
                    const u32 entries = IssueVerbAndPoll(a, slot, widget_node, kHdaVerbGetConnListEntry, 0);
                    if (entries != 0)
                        ++conn_widgets_read;
                }
            }
        }
    }

    g.codec_dac_count[slot] = dac;
    g.codec_first_dac_node[slot] = first_dac_node;
    g.codec_adc_count[slot] = adc;
    g.codec_pin_count[slot] = pin;
    g.codec_amp_widget_count[slot] = amp_widgets;
    g.codec_conn_total[slot] = conn_total;
    g.codec_conn_widgets_read[slot] = conn_widgets_read;
    arch::SerialWrite("[hda]     slot=");
    arch::SerialWriteHex(slot);
    arch::SerialWrite(" widgets: dac=");
    arch::SerialWriteHex(dac);
    arch::SerialWrite(" adc=");
    arch::SerialWriteHex(adc);
    arch::SerialWrite(" pin=");
    arch::SerialWriteHex(pin);
    arch::SerialWrite(" amp=");
    arch::SerialWriteHex(amp_widgets);
    arch::SerialWrite(" conn_entries=");
    arch::SerialWriteHex(conn_total);
    arch::SerialWrite(" conn_widgets_read=");
    arch::SerialWriteHex(conn_widgets_read);
    arch::SerialWrite("\n");
}

} // namespace

::duetos::core::Result<void> BringUp(const AudioControllerInfo& a)
{
    if (a.mmio_virt == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::NotReady};
    if (g.live)
        return ::duetos::core::Err{::duetos::core::ErrorCode::AlreadyExists};

    Mmio32Write(a, kHdaRegGctl, kHdaGctlCrst);
    for (u32 spin = 0; spin < 1024; ++spin)
    {
        if ((Mmio32(a, kHdaRegGctl) & kHdaGctlCrst) != 0)
            break;
        asm volatile("pause" ::: "memory");
    }

    const u16 statests = Mmio16(a, kHdaRegStatests);
    Mmio16Write(a, kHdaRegStatests, statests);

    auto r = mm::AllocDmaCoherent(kHdaScratchBytes, mm::Zone::Dma32);
    if (!r.has_value())
        return ::duetos::core::Err{r.error()};
    g.dma = r.value();
    g.live = true;
    HdaJackInventoryReset();

    // Read GCAP so the StreamArm() helper knows ISS / OSS bounds.
    const u16 gcap = Mmio16(a, kHdaRegGcap);
    g.input_stream_count = static_cast<u8>((gcap >> 8) & 0x0F);
    g.output_stream_count = static_cast<u8>((gcap >> 12) & 0x0F);

    const mm::PhysAddr corb_phys = g.dma.phys + kHdaCorbOffset;
    const mm::PhysAddr rirb_phys = g.dma.phys + kHdaRirbOffset;

    Mmio8Write(a, kHdaRegCorbctl, 0);
    Mmio8Write(a, kHdaRegRirbctl, 0);
    Mmio32Write(a, kHdaRegCorblbase, static_cast<u32>(corb_phys & 0xFFFFFFFFu));
    Mmio32Write(a, kHdaRegCorbubase, static_cast<u32>(corb_phys >> 32));
    Mmio8Write(a, kHdaRegCorbsize, kHdaSizeSel256);
    Mmio16Write(a, kHdaRegCorbrp, kHdaCorbrpRst);
    for (u32 spin = 0; spin < 1024; ++spin)
    {
        if ((Mmio16(a, kHdaRegCorbrp) & kHdaCorbrpRst) != 0)
            break;
        asm volatile("pause" ::: "memory");
    }
    Mmio16Write(a, kHdaRegCorbrp, 0);
    Mmio16Write(a, kHdaRegCorbwp, 0);
    g.corb_wp = 0;

    Mmio32Write(a, kHdaRegRirblbase, static_cast<u32>(rirb_phys & 0xFFFFFFFFu));
    Mmio32Write(a, kHdaRegRirbubase, static_cast<u32>(rirb_phys >> 32));
    Mmio8Write(a, kHdaRegRirbsize, kHdaSizeSel256);
    Mmio16Write(a, kHdaRegRirbwp, kHdaRirbwpRst);
    Mmio16Write(a, kHdaRegRintcnt, 1);

    Mmio8Write(a, kHdaRegCorbctl, kHdaCorbctlRun);
    Mmio8Write(a, kHdaRegRirbctl, kHdaRirbctlDmaen);

    u32 found = 0;
    for (u32 slot = 0; slot < 15; ++slot)
    {
        if ((statests & (1u << slot)) == 0)
            continue;
        const u32 vendor = IssueVerbAndPoll(a, static_cast<u8>(slot), 0, kHdaVerbGetParameter, kHdaParamVendorId);
        g.codec_vendor[slot] = vendor;
        if (vendor != 0)
            ++found;
        arch::SerialWrite("[hda]   codec slot=");
        arch::SerialWriteHex(slot);
        arch::SerialWrite(" vendor_id=");
        arch::SerialWriteHex(vendor);
        if (vendor == 0)
        {
            arch::SerialWrite(" (no response — codec absent or timeout)\n");
            continue;
        }
        const u32 revision = IssueVerbAndPoll(a, static_cast<u8>(slot), 0, kHdaVerbGetParameter, kHdaParamRevisionId);
        arch::SerialWrite(" revision=");
        arch::SerialWriteHex(revision);
        arch::SerialWrite("\n");
        WalkCodec(a, static_cast<u8>(slot));
    }
    core::LogWith2Values(core::LogLevel::Info, "drivers/audio", "  hda bring-up", "rings_phys", g.dma.phys,
                         "codecs_responded", found);
    arch::SerialWrite("[hda]   stream descriptors: iss=");
    arch::SerialWriteHex(g.input_stream_count);
    arch::SerialWrite(" oss=");
    arch::SerialWriteHex(g.output_stream_count);
    arch::SerialWrite(" total=");
    arch::SerialWriteHex(g.input_stream_count + g.output_stream_count);
    arch::SerialWrite("\n");

    g.brought_up = true;
    return {};
}

// GAP: input/capture streams are arm-able here (the SD-slot picker
// handles StreamDirection::Input), but the codec-side capture wiring
// (ADC converter format + SET_CONVERTER_STREAM on an input widget)
// has no caller yet — the only live producer is the output path in
// kernel/subsystems/audio/audio_backend.cpp. Revisit when a capture
// source (mic/line-in) front-end lands.
// GAP: multi-stream mixing is not done — each StreamArm() grabs its
// own SD slot and the controller plays them independently; there is
// no software mixer combining N PCM rings into one output SD.
// Revisit when the audio server grows a mixer.
::duetos::core::Result<u8> StreamArm(const AudioControllerInfo& a, StreamDirection dir, const StreamFormat& fmt,
                                     u64 bdl_phys, u32 buffer_bytes, u8 last_valid_index)
{
    if (!g.brought_up)
        return ::duetos::core::Err{::duetos::core::ErrorCode::NotReady};
    if (a.mmio_virt == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::NotReady};
    if (buffer_bytes == 0 || (buffer_bytes & 0x7F) != 0)
    {
        // CBL must be a multiple of 128 bytes (HDA spec §3.7.4).
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    }

    // Pick the lowest free SD slot that matches the direction.
    u8 sd_lo = 0;
    u8 sd_hi = 0;
    if (dir == StreamDirection::Input)
    {
        sd_lo = 0;
        sd_hi = g.input_stream_count;
    }
    else
    {
        sd_lo = g.input_stream_count;
        sd_hi = static_cast<u8>(g.input_stream_count + g.output_stream_count);
    }
    if (sd_hi == sd_lo)
        return ::duetos::core::Err{::duetos::core::ErrorCode::NoDevice};

    u8 sd_idx = 0xFF;
    for (u8 i = sd_lo; i < sd_hi; ++i)
    {
        if ((g.armed_mask & (1ULL << i)) == 0)
        {
            sd_idx = i;
            break;
        }
    }
    if (sd_idx == 0xFF)
        return ::duetos::core::Err{::duetos::core::ErrorCode::Busy};

    const u64 sd_off = kHdaSdBase + sd_idx * kHdaSdStride;

    // SRST + clear: bring the SD out of any leftover state.
    Mmio8Write(a, sd_off + kHdaSdRegCtl, kHdaSdCtlSrst);
    for (u32 spin = 0; spin < 1024; ++spin)
    {
        if ((Mmio8(a, sd_off + kHdaSdRegCtl) & kHdaSdCtlSrst) != 0)
            break;
        asm volatile("pause" ::: "memory");
    }
    Mmio8Write(a, sd_off + kHdaSdRegCtl, 0);
    for (u32 spin = 0; spin < 1024; ++spin)
    {
        if ((Mmio8(a, sd_off + kHdaSdRegCtl) & kHdaSdCtlSrst) == 0)
            break;
        asm volatile("pause" ::: "memory");
    }

    // Program BDL pointer + cyclic buffer length + last valid
    // index + format. The RUN bit stays clear — caller is
    // responsible for the BDL + buffer pages and decides when
    // to flip RUN.
    Mmio32Write(a, sd_off + kHdaSdRegBdlPl, static_cast<u32>(bdl_phys & 0xFFFFFFFFu));
    Mmio32Write(a, sd_off + kHdaSdRegBdlPu, static_cast<u32>(bdl_phys >> 32));
    Mmio32Write(a, sd_off + kHdaSdRegCbl, buffer_bytes);
    Mmio16Write(a, sd_off + kHdaSdRegLvi, last_valid_index);
    Mmio16Write(a, sd_off + kHdaSdRegFormat, EncodeFormat(fmt));

    // Stream tag goes in CTL bits [23:20]. We use `sd_idx + 1`
    // so the tag is unique per controller (HDA spec recommends
    // tag != 0; 0 is reserved as "unassigned"). The tag also
    // gets written to the codec's converter-stream verb later
    // by the audio server.
    const u8 stream_tag = static_cast<u8>(sd_idx + 1);
    const u8 ctl_byte_2 = static_cast<u8>((stream_tag & 0xF) << 4);
    auto* ctl_lo = static_cast<u8*>(a.mmio_virt) + sd_off + kHdaSdRegCtl;
    *reinterpret_cast<volatile u8*>(ctl_lo + 2) = ctl_byte_2;

    g.armed_mask |= (1ULL << sd_idx);
    ++g.streams_armed;

    arch::SerialWrite("[hda]   stream-arm sd=");
    arch::SerialWriteHex(sd_idx);
    arch::SerialWrite(dir == StreamDirection::Output ? " (out)" : " (in)");
    arch::SerialWrite(" tag=");
    arch::SerialWriteHex(stream_tag);
    arch::SerialWrite(" cbl=");
    arch::SerialWriteHex(buffer_bytes);
    arch::SerialWrite(" lvi=");
    arch::SerialWriteHex(last_valid_index);
    arch::SerialWrite(" fmt=");
    arch::SerialWriteHex(EncodeFormat(fmt));
    arch::SerialWrite(" — RUN not set (caller fills BDL)\n");

    return sd_idx;
}

void Teardown()
{
    if (!g.live)
        return;
    mm::FreeDmaCoherent(g.dma);
    g = {};
}

bool IsBroughtUp()
{
    return g.brought_up;
}

u32 CodecVendorId(u8 slot)
{
    if (slot >= 15)
        return 0;
    return g.codec_vendor[slot];
}
u32 CodecDacCount(u8 slot)
{
    if (slot >= 15)
        return 0;
    return g.codec_dac_count[slot];
}
u32 CodecAdcCount(u8 slot)
{
    if (slot >= 15)
        return 0;
    return g.codec_adc_count[slot];
}
u32 CodecPinCount(u8 slot)
{
    if (slot >= 15)
        return 0;
    return g.codec_pin_count[slot];
}
u32 CodecAmpWidgetCount(u8 slot)
{
    if (slot >= 15)
        return 0;
    return g.codec_amp_widget_count[slot];
}
u32 CodecConnTotal(u8 slot)
{
    if (slot >= 15)
        return 0;
    return g.codec_conn_total[slot];
}
u32 CodecConnWidgetsRead(u8 slot)
{
    if (slot >= 15)
        return 0;
    return g.codec_conn_widgets_read[slot];
}
u8 TotalStreamCount()
{
    return static_cast<u8>(g.input_stream_count + g.output_stream_count);
}
u32 ArmedStreamCount()
{
    return g.streams_armed;
}

::duetos::core::Result<void> StreamRun(const AudioControllerInfo& a, u8 sd_idx, bool run)
{
    if (!g.brought_up || a.mmio_virt == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::NotReady};
    const u8 total = static_cast<u8>(g.input_stream_count + g.output_stream_count);
    if (sd_idx >= total)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    if ((g.armed_mask & (1ULL << sd_idx)) == 0)
        return ::duetos::core::Err{::duetos::core::ErrorCode::NotReady};
    const u64 sd_off = kHdaSdBase + sd_idx * kHdaSdStride;
    u8 ctl = Mmio8(a, sd_off + kHdaSdRegCtl);
    if (run)
        ctl |= kHdaSdCtlRun;
    else
        ctl = static_cast<u8>(ctl & ~kHdaSdCtlRun);
    Mmio8Write(a, sd_off + kHdaSdRegCtl, ctl);
    KLOG_DEBUG_V("drivers/audio/hda", run ? "StreamRun: set RUN sd_idx" : "StreamRun: clear RUN sd_idx", sd_idx);
    return {};
}

// GAP: position reporting reads SD_LPIB directly each call rather than
// the DMA Position-In-Buffer (DPIB) buffer the controller can write to
// host memory, and there is no IRQ-driven refill — the BDL is filled
// once with IOC clear and the producer polls LPIB. A streaming workload
// that needs sample-accurate wrap timing wants DPLBASE/DPUBASE + an SD
// completion IRQ. Revisit when the audio server needs gapless refill.
u32 StreamPosition(const AudioControllerInfo& a, u8 sd_idx)
{
    if (!g.brought_up || a.mmio_virt == nullptr)
        return 0;
    const u8 total = static_cast<u8>(g.input_stream_count + g.output_stream_count);
    if (sd_idx >= total)
        return 0;
    const u64 sd_off = kHdaSdBase + sd_idx * kHdaSdStride;
    return Mmio32(a, sd_off + kHdaSdRegLpib);
}

::duetos::core::Result<void> StreamFillBdl(void* bdl_virt, const BdlEntry* entries, u32 count)
{
    if (bdl_virt == nullptr || entries == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    if (count == 0 || count > kHdaBdlEntries)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    // Each entry is 16 bytes: 8-byte phys address, 4-byte
    // length, 4-byte flags. The descriptor table itself lives
    // in the caller's DMA-coherent allocation.
    auto* bdl = static_cast<volatile u32*>(bdl_virt);
    for (u32 i = 0; i < count; ++i)
    {
        const BdlEntry& e = entries[i];
        bdl[i * 4 + 0] = static_cast<u32>(e.phys & 0xFFFFFFFFu);
        bdl[i * 4 + 1] = static_cast<u32>(e.phys >> 32);
        bdl[i * 4 + 2] = e.length;
        bdl[i * 4 + 3] = e.flags & 0x1u; // only IOC bit defined
    }
    return {};
}

u32 IssueVerbAndPoll16(const AudioControllerInfo& a, u8 codec, u8 node, u32 verb12, u16 payload16)
{
    if (!g.live)
        return 0;
    return IssueVerbRawAndPoll(a, EncodeVerb16(codec, node, verb12, payload16));
}

::duetos::core::Result<OutputPath> FindFirstOutputPath()
{
    if (!g.brought_up)
        return ::duetos::core::Err{::duetos::core::ErrorCode::NotReady};

    constexpr HdaDefaultDevice kPreference[] = {
        HdaDefaultDevice::Speaker,
        HdaDefaultDevice::HpOut,
        HdaDefaultDevice::LineOut,
    };

    const u32 jack_count = HdaJackInventoryCount();
    KLOG_DEBUG_V("drivers/audio/hda", "FindFirstOutputPath: jack_count", jack_count);
    for (u32 pref = 0; pref < sizeof(kPreference) / sizeof(kPreference[0]); ++pref)
    {
        for (u32 idx = 0; idx < jack_count; ++idx)
        {
            HdaJackRecord rec{};
            if (!HdaJackInventoryRead(idx, &rec))
                continue;
            KLOG_DEBUG_V("drivers/audio/hda", "  jack idx", idx);
            KLOG_DEBUG_V("drivers/audio/hda", "    default_device", static_cast<u32>(rec.config.default_device));
            KLOG_DEBUG_V("drivers/audio/hda", "    port_conn", static_cast<u32>(rec.config.port_connectivity));
            KLOG_DEBUG_V("drivers/audio/hda", "    codec_slot", rec.codec_slot);
            KLOG_DEBUG_V("drivers/audio/hda", "    dac_count",
                         rec.codec_slot < 15 ? g.codec_dac_count[rec.codec_slot] : 0xFFFFFFFFu);
            KLOG_DEBUG_V("drivers/audio/hda", "    first_dac_node",
                         rec.codec_slot < 15 ? g.codec_first_dac_node[rec.codec_slot] : 0xFFu);
            if (rec.config.default_device != kPreference[pref])
                continue;
            if (rec.config.port_connectivity == HdaPortConnectivity::NoPhysicalConn)
                continue;
            if (rec.codec_slot >= 15)
                continue;
            if (g.codec_dac_count[rec.codec_slot] == 0 || g.codec_first_dac_node[rec.codec_slot] == 0)
                continue;

            OutputPath path{};
            path.codec = rec.codec_slot;
            path.dac_node = g.codec_first_dac_node[rec.codec_slot];
            path.pin_node = rec.pin_node;
            path.target = kPreference[pref];
            return path;
        }
    }

    return ::duetos::core::Err{::duetos::core::ErrorCode::NoDevice};
}

::duetos::core::Result<void> CodecSetConverterFormat(const AudioControllerInfo& a, u8 codec, u8 node, u16 format)
{
    // Verb 0x2 — Set Converter Format. 4-bit-verb / 16-bit-payload
    // form: verb id 0x2 lives in bits 19:16, full 16-bit format
    // value occupies bits 15:0 (matches the SD_FORMAT register the
    // controller is running). EncodeVerb16 picks the high nibble
    // out of the 12-bit `0x200` constant for back-compat with the
    // existing verb numbering convention.
    (void)IssueVerbAndPoll16(a, codec, node, /*verb12=*/0x200, format);
    return {};
}

::duetos::core::Result<void> CodecSetAmpGainMute(const AudioControllerInfo& a, u8 codec, u8 node, u16 payload)
{
    // Verb 0x3 — Set Amp Gain/Mute. 4-bit-verb / 16-bit-payload
    // form. Payload bit layout:
    //   bit 15 = set output amp
    //   bit 14 = set input amp
    //   bit 13 = set left
    //   bit 12 = set right
    //   bits 11:8 = index (for input amps; 0 for output)
    //   bit 7 = mute
    //   bits 6:0 = gain
    // For "unmute output amp at moderate gain" pass payload =
    // (1<<15) | (1<<13) | (1<<12) | gain ≈ 0xB000 | gain.
    (void)IssueVerbAndPoll16(a, codec, node, /*verb12=*/0x300, payload);
    return {};
}

::duetos::core::Result<void> CodecSetConverterStream(const AudioControllerInfo& a, u8 codec, u8 node, u8 stream_tag,
                                                     u8 channel)
{
    // Verb 0x706 — Set Converter Stream/Channel. Payload bits
    // 7:4 = stream tag, 3:0 = channel.
    const u32 verb = 0x706;
    const u8 payload = static_cast<u8>(((stream_tag & 0xF) << 4) | (channel & 0xF));
    IssueVerbAndPoll(a, codec, node, verb, payload);
    return {};
}

::duetos::core::Result<void> CodecSetPinWidgetControl(const AudioControllerInfo& a, u8 codec, u8 node, u8 payload)
{
    // Verb 0x707 — Set Pin Widget Control.
    const u32 verb = 0x707;
    IssueVerbAndPoll(a, codec, node, verb, payload);
    return {};
}

::duetos::core::Result<void> ConfigureOutputPath(const AudioControllerInfo& a, u8 codec, u8 dac_node, u8 pin_node,
                                                 u8 stream_tag, u16 format)
{
    if (a.mmio_virt == nullptr || !g.live)
        return ::duetos::core::Err{::duetos::core::ErrorCode::NotReady};
    // Reject obviously-bogus inputs early — codec must be in the
    // 4-bit STATESTS slot range, nodes must be non-zero (node 0 is
    // the root node, never a DAC / pin), stream tag must fit in
    // the 4-bit field SET_CONVERTER_STREAM_CHANNEL takes.
    if (codec >= 15 || dac_node == 0 || pin_node == 0 || stream_tag == 0 || stream_tag >= 16)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};

    // Step 1: DAC converter format. Has to match the SD format
    // the controller is running so the codec pulls samples at the
    // same rate / depth / channel count.
    auto r1 = CodecSetConverterFormat(a, codec, dac_node, format);
    if (!r1.has_value())
        return r1;

    // Step 2: un-mute the DAC's output amp at moderate gain.
    auto r2 = CodecSetAmpGainMute(a, codec, dac_node, kAmpPayloadSetOutBothMid);
    if (!r2.has_value())
        return r2;

    // Step 3: un-mute the pin's output amp (no-op for pins without
    // an output amp — the codec acks the verb regardless).
    auto r3 = CodecSetAmpGainMute(a, codec, pin_node, kAmpPayloadSetOutBothMid);
    if (!r3.has_value())
        return r3;

    // Step 4: drive the pin. Without this the speaker stays muted
    // even if the DAC is producing samples — pin widgets gate the
    // physical output independently of amp state.
    auto r4 = CodecSetPinWidgetControl(a, codec, pin_node, kPinPayloadOutputEnable);
    if (!r4.has_value())
        return r4;

    // Step 5: bind the DAC to a stream descriptor's tag. The
    // controller picks the tag at StreamArm time; the codec
    // converter has to match or it sees no samples.
    auto r5 = CodecSetConverterStream(a, codec, dac_node, stream_tag, /*channel=*/0);
    if (!r5.has_value())
        return r5;

    KLOG_DEBUG_V("drivers/audio/hda", "ConfigureOutputPath: dac=", dac_node);
    KLOG_DEBUG_V("drivers/audio/hda", "ConfigureOutputPath: pin=", pin_node);
    KLOG_DEBUG_V("drivers/audio/hda", "ConfigureOutputPath: stream_tag=", stream_tag);
    return {};
}

void VerbEncodingSelfTest()
{
    arch::SerialWrite("[hda] verb-encoding self-test\n");

    // 12-bit-verb / 8-bit-data: GET_PARAMETER on codec 0, node 0,
    // parameter 0x04 (Audio Widget Caps).
    //   bits 31:28 = 0x0 (codec)
    //   bits 27:20 = 0x00 (node)
    //   bits 19:8  = 0xF00 (verb)
    //   bits 7:0   = 0x04 (parameter)
    // = 0x000F0004
    const u32 v_12 = EncodeVerb(/*codec=*/0, /*node=*/0, /*verb12=*/0xF00, /*data8=*/0x04);
    if (v_12 != 0x000F0004u)
    {
        core::PanicWithValue("drivers/audio/hda", "verb encoding 12+8 mismatch", v_12);
    }

    // 4-bit-verb / 16-bit-data: SET_CONVERTER_FORMAT on codec 1,
    // node 5, format 0x4011 (16-bit / 48 kHz / stereo).
    //   bits 31:28 = 0x1 (codec)
    //   bits 27:20 = 0x05 (node)
    //   bits 19:16 = 0x2 (verb id)
    //   bits 15:0  = 0x4011 (payload)
    // = 0x10524011
    const u32 v_16 = EncodeVerb16(/*codec=*/1, /*node=*/5, /*verb12=*/0x200, /*payload16=*/0x4011);
    if (v_16 != 0x10524011u)
    {
        core::PanicWithValue("drivers/audio/hda", "verb encoding 4+16 mismatch", v_16);
    }

    // SET_AMP_GAIN_MUTE on codec 0, node 0x10, payload 0xB040
    // (set out, both channels, mid gain).
    const u32 v_amp = EncodeVerb16(0, 0x10, 0x300, 0xB040);
    if (v_amp != 0x0103B040u)
    {
        core::PanicWithValue("drivers/audio/hda", "verb encoding amp-gain mismatch", v_amp);
    }

    // Boundary: 12-bit form's `data8` upper bits cleared. If a
    // caller accidentally passes data8=0x100 it overflows — the
    // helper's `data8` parameter is u8 so the compiler clamps,
    // but we sanity-check at the encode level.
    const u32 v_clamp = EncodeVerb(0xF, 0xFF, 0xFFF, 0xFF);
    if (v_clamp != 0xFFFFFFFFu)
    {
        core::PanicWithValue("drivers/audio/hda", "verb encoding all-ones mismatch", v_clamp);
    }

    arch::SerialWrite("[hda] verb-encoding self-test OK\n");
}

} // namespace duetos::drivers::audio::hda
