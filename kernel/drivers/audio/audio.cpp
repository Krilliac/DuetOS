#include "drivers/audio/audio.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "drivers/pci/pci.h"
#include "log/klog.h"
#include "mm/dma.h"
#include "mm/paging.h"
#include "mm/zone.h"

namespace duetos::drivers::audio
{

namespace
{

AudioControllerInfo g_acs[kMaxAudioControllers] = {};
u64 g_ac_count = 0;

// Module-scope so `AudioShutdown` can clear it and the next
// `AudioInit` re-walks PCI.
constinit bool g_init_done = false;

AudioKind KindFromSubclass(u8 subclass)
{
    switch (subclass)
    {
    case kPciSubclassLegacyAudio:
        return AudioKind::Legacy;
    case kPciSubclassAc97:
        return AudioKind::Ac97;
    case kPciSubclassHda:
        return AudioKind::Hda;
    case kPciSubclassOther:
        return AudioKind::Other;
    default:
        return AudioKind::Unknown;
    }
}

// Intel HDA register offsets (subset). See HDA spec §4.2.
//
//   GCAP    u16 at 0x00 — OSS/ISS/BSS counts, 64-bit addressing
//   VMIN    u8  at 0x02 — minor version (typically 0x00)
//   VMAJ    u8  at 0x03 — major version (typically 0x01)
//   OUTPAY  u16 at 0x04 — output payload capability (stream size)
//   INPAY   u16 at 0x06 — input payload capability
//   GCTL    u32 at 0x08 — global control (bit 0 = CRST; 1 = out of reset)
//   WAKEEN  u16 at 0x0C — codec wake-enable bits, one per SDI
//   STATESTS u16 at 0x0E — codec state change status (bits set if codec present)
//   INTCTL  u32 at 0x20 — interrupt control
//   INTSTS  u32 at 0x24 — interrupt status
//
// v0 probing here is read-only. A real driver would clear STATESTS
// after latching, program CORB/RIRB base addresses, and run codec
// discovery through the command/response rings. None of that yet.
u16 Mmio16(const AudioControllerInfo& a, u64 offset)
{
    if (a.mmio_virt == nullptr)
        return 0;
    auto* p = reinterpret_cast<volatile u16*>(static_cast<u8*>(a.mmio_virt) + offset);
    return *p;
}
u32 Mmio32(const AudioControllerInfo& a, u64 offset)
{
    if (a.mmio_virt == nullptr)
        return 0;
    auto* p = reinterpret_cast<volatile u32*>(static_cast<u8*>(a.mmio_virt) + offset);
    return *p;
}
u8 Mmio8(const AudioControllerInfo& a, u64 offset)
{
    if (a.mmio_virt == nullptr)
        return 0;
    auto* p = reinterpret_cast<volatile u8*>(static_cast<u8*>(a.mmio_virt) + offset);
    return *p;
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

// HDA register offsets.
constexpr u64 kHdaRegGcap = 0x00;
constexpr u64 kHdaRegVmin = 0x02;
constexpr u64 kHdaRegVmaj = 0x03;
constexpr u64 kHdaRegOutpay = 0x04;
constexpr u64 kHdaRegInpay = 0x06;
constexpr u64 kHdaRegGctl = 0x08;
constexpr u64 kHdaRegWakeen = 0x0C;
constexpr u64 kHdaRegStatests = 0x0E;
constexpr u64 kHdaRegIntctl = 0x20;
constexpr u64 kHdaRegIntsts = 0x24;
constexpr u64 kHdaRegCorblbase = 0x40;
constexpr u64 kHdaRegCorbubase = 0x44;
constexpr u64 kHdaRegCorbwp = 0x48;   // u16
constexpr u64 kHdaRegCorbrp = 0x4A;   // u16, bit 15 = CORBRPRST
constexpr u64 kHdaRegCorbctl = 0x4C;  // u8, bit 1 = CORBRUN, bit 0 = CMEIE
constexpr u64 kHdaRegCorbsize = 0x4E; // u8, low 2 bits select 2/16/256-entry
constexpr u64 kHdaRegRirblbase = 0x50;
constexpr u64 kHdaRegRirbubase = 0x54;
constexpr u64 kHdaRegRirbwp = 0x58;   // u16, bit 15 = RIRBWPRST
constexpr u64 kHdaRegRintcnt = 0x5A;  // u16
constexpr u64 kHdaRegRirbctl = 0x5C;  // u8, bit 1 = RIRBDMAEN, bit 0 = RINTCTL
constexpr u64 kHdaRegRirbsize = 0x5E; // u8

constexpr u32 kHdaGctlCrst = 1u << 0;
constexpr u8 kHdaCorbctlRun = 1u << 1;
constexpr u8 kHdaRirbctlDmaen = 1u << 1;
constexpr u8 kHdaSizeSel256 = 0x02; // bits 1:0 = 10b -> 256-entry ring
constexpr u16 kHdaCorbrpRst = 1u << 15;
constexpr u16 kHdaRirbwpRst = 1u << 15;
constexpr u32 kHdaCorbEntries = 256;
constexpr u32 kHdaRirbEntries = 256;
constexpr u32 kHdaCorbBytes = kHdaCorbEntries * 4; // 1 KiB
constexpr u32 kHdaRirbBytes = kHdaRirbEntries * 8; // 2 KiB
constexpr u64 kHdaCorbOffset = 0;
constexpr u64 kHdaRirbOffset = kHdaCorbBytes;
constexpr u64 kHdaScratchBytes = mm::kPageSize; // CORB + RIRB + 1 KiB pad

// HDA verb encoding: (codec_addr[31:28] << 28) | (node_id[27:20] << 20)
// | (verb[19:8] << 8) | data[7:0].
constexpr u32 kHdaVerbGetParameter = 0xF00;
// GetConnectionListEntry — returns up to 4 ShortForm (1 byte each)
// or 2 LongForm (2 bytes each) entries starting at the data byte's
// offset. The response is a 32-bit packed payload; a single verb
// call covers offsets 0..3 (short) or 0..1 (long).
constexpr u32 kHdaVerbGetConnListEntry = 0xF02;
constexpr u32 kHdaParamVendorId = 0x00;
constexpr u32 kHdaParamRevisionId = 0x02;
constexpr u32 kHdaParamSubordinateNodeCount = 0x04;
constexpr u32 kHdaParamFunctionGroupType = 0x05;
constexpr u32 kHdaParamAudioWidgetCaps = 0x09;
// Per-widget AmplifierCapabilities + ConnectionListLength
// parameters (HDA spec §7.3.4.10/.11/.12). Widgets without an
// amplifier (PinComplex with no input/output amp) return 0; the
// presence bit in AudioWidgetCaps tells us up-front whether to
// even bother querying.
constexpr u32 kHdaParamAmpCapsInput = 0x0D;
constexpr u32 kHdaParamConnListLength = 0x0E;
constexpr u32 kHdaParamAmpCapsOutput = 0x12;
// AudioWidgetCaps bits relevant to amp / conn-list probing.
//   bit 1  = InAmpPresent  (read AMPCAP_INPUT  parameter)
//   bit 2  = OutAmpPresent (read AMPCAP_OUTPUT parameter)
//   bit 8  = ConnListPresent (read CONN_LIST_LENGTH parameter)
constexpr u32 kHdaWidgetCapInAmp = 1u << 1;
constexpr u32 kHdaWidgetCapOutAmp = 1u << 2;
constexpr u32 kHdaWidgetCapConnList = 1u << 8;

// Widget type codes packed into bits [23:20] of AudioWidgetCaps.
constexpr u32 kHdaWidgetAudioOutput = 0x0;
constexpr u32 kHdaWidgetAudioInput = 0x1;
constexpr u32 kHdaWidgetAudioMixer = 0x2;
constexpr u32 kHdaWidgetAudioSelector = 0x3;
constexpr u32 kHdaWidgetPinComplex = 0x4;
constexpr u32 kHdaWidgetPower = 0x5;
constexpr u32 kHdaWidgetVolumeKnob = 0x6;
constexpr u32 kHdaWidgetBeepGen = 0x7;
constexpr u32 kHdaWidgetVendorDefined = 0xF;

// Function-group types reported by GET_PARAMETER(FUNCTION_GROUP_TYPE).
constexpr u32 kHdaFunctionGroupAudio = 0x01;
constexpr u32 kHdaFunctionGroupModem = 0x02;

u32 HdaEncodeVerb(u8 codec, u8 node, u32 verb12, u8 data8)
{
    return (static_cast<u32>(codec) << 28) | (static_cast<u32>(node) << 20) | ((verb12 & 0xFFFu) << 8) | data8;
}

// One global HDA bring-up state — only one HDA controller is
// expected on consumer hardware. If a future board reports two,
// the second bring-up returns Unsupported (real change is making
// this a per-controller record).
struct HdaState
{
    mm::DmaBuffer dma;
    bool live;
    u16 corb_wp;          // mirror of CORBWP after our last write
    u32 codec_vendor[15]; // root-node vendor ID per SDI slot, 0 = absent
    u32 codec_dac_count[15];
    u32 codec_adc_count[15];
    u32 codec_pin_count[15];
    // Per-codec totals across the function-group walk: number of
    // widgets whose AmplifierCapabilities param reported any amp
    // present, and the sum of connection-list lengths over every
    // widget that exposed a ConnectionList. Both are diagnostic
    // counters today; future stream-routing slices will consume
    // the underlying caps when programming a DAC → pin path.
    u32 codec_amp_widget_count[15];
    u32 codec_conn_total[15];
    // Number of widgets whose first conn-list entry walk
    // (verb 0xF02) returned at least one non-zero entry. With
    // the LENGTH probe + the ENTRY walk both landed, the
    // routing slice has the data it needs; this counter is
    // the boot-log signal that the walker actually pulled
    // entry payloads back rather than just the length count.
    u32 codec_conn_widgets_read[15];
    bool brought_up;
};
constinit HdaState g_hda = {};

// Forward declaration — HdaIssueVerbAndPoll is defined further
// down (after the bring-up record) but the codec walker needs
// to call it.
u32 HdaIssueVerbAndPoll(const AudioControllerInfo& a, u8 codec, u8 node, u32 verb12, u8 data8);

const char* HdaWidgetTypeName(u32 type_code)
{
    switch (type_code)
    {
    case kHdaWidgetAudioOutput:
        return "audio-output";
    case kHdaWidgetAudioInput:
        return "audio-input";
    case kHdaWidgetAudioMixer:
        return "mixer";
    case kHdaWidgetAudioSelector:
        return "selector";
    case kHdaWidgetPinComplex:
        return "pin-complex";
    case kHdaWidgetPower:
        return "power";
    case kHdaWidgetVolumeKnob:
        return "volume-knob";
    case kHdaWidgetBeepGen:
        return "beep-gen";
    case kHdaWidgetVendorDefined:
        return "vendor";
    default:
        return "unknown";
    }
}

// Walk a codec's function group + widget tree. Encodes each
// widget's type so the next slice (output stream wiring) can
// pick a DAC + pin pair without re-walking. Returns the count
// of audio function groups discovered (0 means modem-only or
// quiescent codec).
u32 HdaWalkCodec(const AudioControllerInfo& a, u8 slot)
{
    // SUBORDINATE_NODE_COUNT on root node 0 returns
    //   bits [23:16] = starting subnode id
    //   bits [7:0]   = number of function groups
    const u32 root_subordinates = HdaIssueVerbAndPoll(a, slot, 0, kHdaVerbGetParameter, kHdaParamSubordinateNodeCount);
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
        return 0;

    u32 audio_fg_count = 0;
    u32 dac = 0;
    u32 adc = 0;
    u32 pin = 0;
    u32 amp_widgets = 0;       // count of widgets reporting any input or output amp
    u32 conn_total = 0;        // sum of CONN_LIST_LENGTH lengths across the codec
    u32 conn_widgets_read = 0; // count of widgets whose first ENTRY walk returned a non-zero entry
    // Bound the walk: even pathological codecs have ≤ 4 function
    // groups. The whole-tree limit (kept loose at 64) protects
    // against malformed responses.
    const u32 fg_walk_limit = (fg_count > 4) ? 4 : fg_count;
    for (u32 fg_idx = 0; fg_idx < fg_walk_limit; ++fg_idx)
    {
        const u8 fg_node = static_cast<u8>(fg_start + fg_idx);
        const u32 fg_type = HdaIssueVerbAndPoll(a, slot, fg_node, kHdaVerbGetParameter, kHdaParamFunctionGroupType);
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
        ++audio_fg_count;

        const u32 fg_subnodes =
            HdaIssueVerbAndPoll(a, slot, fg_node, kHdaVerbGetParameter, kHdaParamSubordinateNodeCount);
        const u32 widget_start = (fg_subnodes >> 16) & 0xFF;
        const u32 widget_count = fg_subnodes & 0xFF;
        // 64-widget cap matches what mainstream codecs (ALC892,
        // CX20585, IDT 92HD90B etc.) report. A pathological
        // response that claims more is a sign of a stuck RIRB —
        // bail rather than spend the rest of boot polling.
        const u32 widget_walk_limit = (widget_count > 64) ? 64 : widget_count;
        for (u32 w_idx = 0; w_idx < widget_walk_limit; ++w_idx)
        {
            const u8 widget_node = static_cast<u8>(widget_start + w_idx);
            const u32 caps = HdaIssueVerbAndPoll(a, slot, widget_node, kHdaVerbGetParameter, kHdaParamAudioWidgetCaps);
            const u32 wtype = (caps >> 20) & 0xF;
            switch (wtype)
            {
            case kHdaWidgetAudioOutput:
                ++dac;
                break;
            case kHdaWidgetAudioInput:
                ++adc;
                break;
            case kHdaWidgetPinComplex:
                ++pin;
                break;
            default:
                break;
            }
            // Per-widget log only at high verbosity — keep boot
            // log readable. The summary below is enough to
            // diagnose "codec found a DAC vs not".
            (void)HdaWidgetTypeName(wtype);
            // Probe per-widget amplifier + connection-list
            // params. The presence bits in `caps` gate the
            // probes so widgets that explicitly say "no amp"
            // / "no conn list" don't burn CORB/RIRB cycles.
            // The diagnostic counters below are what stream-
            // routing slices will consume; this slice just
            // surfaces the totals so an operator can see "yes,
            // this codec exposes amps + connection lists" as
            // a precondition for the routing work.
            if ((caps & (kHdaWidgetCapInAmp | kHdaWidgetCapOutAmp)) != 0)
            {
                if ((caps & kHdaWidgetCapInAmp) != 0)
                {
                    (void)HdaIssueVerbAndPoll(a, slot, widget_node, kHdaVerbGetParameter, kHdaParamAmpCapsInput);
                }
                if ((caps & kHdaWidgetCapOutAmp) != 0)
                {
                    (void)HdaIssueVerbAndPoll(a, slot, widget_node, kHdaVerbGetParameter, kHdaParamAmpCapsOutput);
                }
                ++amp_widgets;
            }
            if ((caps & kHdaWidgetCapConnList) != 0)
            {
                const u32 conn =
                    HdaIssueVerbAndPoll(a, slot, widget_node, kHdaVerbGetParameter, kHdaParamConnListLength);
                // CONN_LIST_LENGTH layout: bit 7 = LongForm
                // (entries are 2 bytes), bits [6:0] = count.
                const u32 conn_count = conn & 0x7Fu;
                conn_total += conn_count;
                // Pull the first batch of connection entries for any
                // widget that reports a non-zero list. v0 issues
                // exactly one GET_CONNECTION_LIST_ENTRY verb at offset
                // 0; the response packs the first 4 short-form (1 byte
                // each) or 2 long-form (2 bytes each) entries into a
                // 32-bit payload. A non-zero response increments the
                // diagnostic counter so a clean boot prints
                // "conn_widgets_read=N" alongside conn_entries=N — N
                // > 0 confirms the ENTRY walker is working end-to-end
                // through CORB / RIRB and not just reading stale RIRB
                // bytes.
                if (conn_count > 0)
                {
                    const u32 entries = HdaIssueVerbAndPoll(a, slot, widget_node, kHdaVerbGetConnListEntry, 0);
                    if (entries != 0)
                    {
                        ++conn_widgets_read;
                    }
                }
            }
        }
    }

    g_hda.codec_dac_count[slot] = dac;
    g_hda.codec_adc_count[slot] = adc;
    g_hda.codec_pin_count[slot] = pin;
    g_hda.codec_amp_widget_count[slot] = amp_widgets;
    g_hda.codec_conn_total[slot] = conn_total;
    g_hda.codec_conn_widgets_read[slot] = conn_widgets_read;
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
    return audio_fg_count;
}

void DecodeHdaCaps(const AudioControllerInfo& a)
{
    if (a.mmio_virt == nullptr)
        return;
    const u16 gcap = Mmio16(a, kHdaRegGcap);
    const u8 vmin = Mmio8(a, kHdaRegVmin);
    const u8 vmaj = Mmio8(a, kHdaRegVmaj);
    const u16 outpay = Mmio16(a, kHdaRegOutpay);
    const u16 inpay = Mmio16(a, kHdaRegInpay);
    arch::SerialWrite("[hda] ver=");
    arch::SerialWriteHex(vmaj);
    arch::SerialWrite(".");
    arch::SerialWriteHex(vmin);
    arch::SerialWrite(" gcap=");
    arch::SerialWriteHex(gcap);
    arch::SerialWrite(" (iss=");
    arch::SerialWriteHex((gcap >> 8) & 0x0F);
    arch::SerialWrite(" oss=");
    arch::SerialWriteHex((gcap >> 12) & 0x0F);
    arch::SerialWrite(" bss=");
    arch::SerialWriteHex((gcap >> 3) & 0x1F);
    arch::SerialWrite(") outpay=");
    arch::SerialWriteHex(outpay);
    arch::SerialWrite(" inpay=");
    arch::SerialWriteHex(inpay);
    arch::SerialWrite("\n");

    // Controller state + codec presence. STATESTS is a sticky bit
    // per SDI line that the controller sets when a codec signals
    // "state changed" after power-up — the hardware latches this
    // for us the first time BIOS/UEFI brings the controller out of
    // reset. Reading it is non-destructive.
    const u32 gctl = Mmio32(a, kHdaRegGctl);
    const u16 statests = Mmio16(a, kHdaRegStatests);
    const u16 wakeen = Mmio16(a, kHdaRegWakeen);
    const u32 intctl = Mmio32(a, kHdaRegIntctl);
    const u32 intsts = Mmio32(a, kHdaRegIntsts);
    arch::SerialWrite("[hda]   gctl=");
    arch::SerialWriteHex(gctl);
    arch::SerialWrite((gctl & kHdaGctlCrst) ? " (out-of-reset)" : " (in-reset)");
    arch::SerialWrite(" statests=");
    arch::SerialWriteHex(statests);
    arch::SerialWrite(" wakeen=");
    arch::SerialWriteHex(wakeen);
    arch::SerialWrite(" intctl=");
    arch::SerialWriteHex(intctl);
    arch::SerialWrite(" intsts=");
    arch::SerialWriteHex(intsts);
    arch::SerialWrite("\n");

    // Decode STATESTS per-slot. The HDA spec allows up to 15 SDI
    // lines but real chipsets wire 3–4. A bit set means a codec
    // replied at that address and is ready to be addressed over
    // CORB/RIRB. We only log; we don't clear.
    u32 codec_count = 0;
    for (u32 slot = 0; slot < 15; ++slot)
    {
        if ((statests & (1u << slot)) == 0)
            continue;
        ++codec_count;
        arch::SerialWrite("[hda]   codec-present slot=");
        arch::SerialWriteHex(slot);
        arch::SerialWrite("\n");
    }
    if (codec_count == 0)
    {
        arch::SerialWrite("[hda]   no codecs reported by STATESTS (controller "
                          "may still be in reset)\n");
    }
}

// Issue a single CORB verb against `codec_slot` and poll RIRB
// briefly for the response. Returns the 32-bit response on success
// or 0 on timeout — callers that care about the difference should
// snapshot RIRBWP before/after. v0 polls inline because IRQ wiring
// for HDA hasn't landed; the bound is loose (~10 µs of MMIO reads
// per attempt × 100 attempts ≈ 1 ms), well within boot-time slack.
u32 HdaIssueVerbAndPoll(const AudioControllerInfo& a, u8 codec, u8 node, u32 verb12, u8 data8)
{
    if (!g_hda.live)
        return 0;
    auto* corb = static_cast<volatile u32*>(g_hda.dma.virt) + (kHdaCorbOffset / sizeof(u32));
    auto* rirb = reinterpret_cast<volatile u64*>(static_cast<u8*>(g_hda.dma.virt) + kHdaRirbOffset);

    const u16 rirb_wp_before = Mmio16(a, kHdaRegRirbwp) & 0xFFu;
    g_hda.corb_wp = static_cast<u16>((g_hda.corb_wp + 1) % kHdaCorbEntries);
    corb[g_hda.corb_wp] = HdaEncodeVerb(codec, node, verb12, data8);
    mm::DmaSyncForDevice(g_hda.dma, kHdaCorbOffset, kHdaCorbBytes);
    Mmio16Write(a, kHdaRegCorbwp, g_hda.corb_wp);

    for (u32 spin = 0; spin < 1024; ++spin)
    {
        const u16 rirb_wp_now = Mmio16(a, kHdaRegRirbwp) & 0xFFu;
        if (rirb_wp_now != rirb_wp_before)
        {
            mm::DmaSyncForCpu(g_hda.dma, kHdaRirbOffset, kHdaRirbBytes);
            return static_cast<u32>(rirb[rirb_wp_now] & 0xFFFFFFFFu);
        }
        // Tiny delay — pause hint, no time API needed.
        asm volatile("pause" ::: "memory");
    }
    return 0;
}

::duetos::core::Result<void> HdaBringUp(const AudioControllerInfo& a)
{
    if (a.mmio_virt == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::NotReady};
    if (g_hda.live)
        return ::duetos::core::Err{::duetos::core::ErrorCode::AlreadyExists};

    // 1) Take the controller out of reset. Real boot path does this
    // before STATESTS is meaningful; UEFI usually leaves it set.
    Mmio32Write(a, kHdaRegGctl, kHdaGctlCrst);
    for (u32 spin = 0; spin < 1024; ++spin)
    {
        if ((Mmio32(a, kHdaRegGctl) & kHdaGctlCrst) != 0)
            break;
        asm volatile("pause" ::: "memory");
    }

    // 2) Latch + clear STATESTS so a subsequent codec walk sees
    // only fresh state-change bits. We log + remember which slots
    // had a codec at boot.
    const u16 statests = Mmio16(a, kHdaRegStatests);
    Mmio16Write(a, kHdaRegStatests, statests);

    // 3) Allocate the CORB+RIRB DMA region. HDA descriptor pointers
    // are 64-bit-capable per GCAP[0]; we still ask for Dma32 because
    // it's universally addressable and our v0 ring sizes don't need
    // more.
    auto r = mm::AllocDmaCoherent(kHdaScratchBytes, mm::Zone::Dma32);
    if (!r.has_value())
        return ::duetos::core::Err{r.error()};
    g_hda.dma = r.value();
    g_hda.live = true;

    const mm::PhysAddr corb_phys = g_hda.dma.phys + kHdaCorbOffset;
    const mm::PhysAddr rirb_phys = g_hda.dma.phys + kHdaRirbOffset;

    // 4) Stop both rings before reprogramming.
    Mmio8Write(a, kHdaRegCorbctl, 0);
    Mmio8Write(a, kHdaRegRirbctl, 0);

    // 5) Program CORB: base, size = 256-entry, RP reset, WP = 0.
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
    g_hda.corb_wp = 0;

    // 6) Program RIRB: base, size = 256-entry, WP reset.
    Mmio32Write(a, kHdaRegRirblbase, static_cast<u32>(rirb_phys & 0xFFFFFFFFu));
    Mmio32Write(a, kHdaRegRirbubase, static_cast<u32>(rirb_phys >> 32));
    Mmio8Write(a, kHdaRegRirbsize, kHdaSizeSel256);
    Mmio16Write(a, kHdaRegRirbwp, kHdaRirbwpRst);
    Mmio16Write(a, kHdaRegRintcnt, 1); // interrupt every response (when IRQ wired)

    // 7) Start CORB + RIRB DMA.
    Mmio8Write(a, kHdaRegCorbctl, kHdaCorbctlRun);
    Mmio8Write(a, kHdaRegRirbctl, kHdaRirbctlDmaen);

    // 8) For every codec slot the controller saw at boot, issue
    // GET_PARAMETER(VENDOR_ID) on root node 0, then walk the
    // function-group + widget tree to discover DAC/ADC/Pin
    // counts plus the per-widget amp + connection-list params
    // (gated on the corresponding presence bits in the widget's
    // AudioWidgetCaps so we don't probe widgets that report no
    // amp / no conn-list). Stream programming lands as a follow-
    // up slice; this much already lets boot diagnostics
    // distinguish "codec is wired up but mute" from "codec never
    // responded" AND "this codec exposes the amp + conn-list
    // surface stream routing will need".
    //
    // The walker also issues one GET_CONNECTION_LIST_ENTRY (verb
    // 0xF02) at offset 0 per widget that reports a non-zero
    // CONN_LIST_LENGTH, which proves the ENTRY path works through
    // CORB / RIRB end-to-end. The result is logged via
    // codec_conn_widgets_read; storing the actual entry payloads
    // for routing is a follow-up that needs per-widget storage
    // (the current per-codec aggregates only summarise counts).
    u32 found = 0;
    for (u32 slot = 0; slot < 15; ++slot)
    {
        if ((statests & (1u << slot)) == 0)
            continue;
        const u32 vendor = HdaIssueVerbAndPoll(a, static_cast<u8>(slot), 0, kHdaVerbGetParameter, kHdaParamVendorId);
        g_hda.codec_vendor[slot] = vendor;
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
        const u32 revision =
            HdaIssueVerbAndPoll(a, static_cast<u8>(slot), 0, kHdaVerbGetParameter, kHdaParamRevisionId);
        arch::SerialWrite(" revision=");
        arch::SerialWriteHex(revision);
        arch::SerialWrite("\n");
        HdaWalkCodec(a, static_cast<u8>(slot));
    }
    core::LogWith2Values(core::LogLevel::Info, "drivers/audio", "  hda bring-up", "rings_phys", g_hda.dma.phys,
                         "codecs_responded", found);

    g_hda.brought_up = true;
    return {};
}

void HdaTeardown()
{
    if (!g_hda.live)
        return;
    mm::FreeDmaCoherent(g_hda.dma);
    g_hda = {};
}

void LogAc(const AudioControllerInfo& a)
{
    arch::SerialWrite("  audio ");
    arch::SerialWriteHex(a.bus);
    arch::SerialWrite(":");
    arch::SerialWriteHex(a.device);
    arch::SerialWrite(".");
    arch::SerialWriteHex(a.function);
    arch::SerialWrite("  vid=");
    arch::SerialWriteHex(a.vendor_id);
    arch::SerialWrite(" did=");
    arch::SerialWriteHex(a.device_id);
    arch::SerialWrite(" kind=");
    arch::SerialWrite(AudioKindName(a.kind));
    if (a.mmio_size != 0)
    {
        arch::SerialWrite(" bar0=");
        arch::SerialWriteHex(a.mmio_phys);
        arch::SerialWrite("/");
        arch::SerialWriteHex(a.mmio_size);
        if (a.mmio_virt != nullptr)
        {
            arch::SerialWrite(" -> ");
            arch::SerialWriteHex(reinterpret_cast<u64>(a.mmio_virt));
        }
    }
    arch::SerialWrite("\n");
}

} // namespace

const char* AudioKindName(AudioKind k)
{
    switch (k)
    {
    case AudioKind::Legacy:
        return "legacy";
    case AudioKind::Ac97:
        return "ac97";
    case AudioKind::Hda:
        return "hda";
    case AudioKind::Other:
        return "other";
    default:
        return "unknown";
    }
}

void AudioInit()
{
    KLOG_TRACE_SCOPE("drivers/audio", "AudioInit");
    if (g_init_done)
        return;
    g_init_done = true;

    const u64 n = pci::PciDeviceCount();
    for (u64 i = 0; i < n && g_ac_count < kMaxAudioControllers; ++i)
    {
        const pci::Device& d = pci::PciDevice(i);
        if (d.class_code != kPciClassMultimedia)
            continue;

        AudioControllerInfo a = {};
        a.vendor_id = d.vendor_id;
        a.device_id = d.device_id;
        a.bus = d.addr.bus;
        a.device = d.addr.device;
        a.function = d.addr.function;
        a.subclass = d.subclass;
        a.kind = KindFromSubclass(d.subclass);

        const pci::Bar bar0 = pci::PciReadBar(d.addr, 0);
        if (bar0.size != 0 && !bar0.is_io)
        {
            a.mmio_phys = bar0.address;
            a.mmio_size = bar0.size;
            // HDA register files are tiny (~64 KiB). Cap at 256 KiB.
            constexpr u64 kMmioCap = 256ULL * 1024;
            const u64 map_bytes = (bar0.size > kMmioCap) ? kMmioCap : bar0.size;
            a.mmio_virt = mm::MapMmio(bar0.address, map_bytes);
        }

        g_acs[g_ac_count++] = a;
    }

    core::LogWithValue(core::LogLevel::Info, "drivers/audio", "discovered audio controllers", g_ac_count);
    for (u64 i = 0; i < g_ac_count; ++i)
    {
        LogAc(g_acs[i]);
        if (g_acs[i].kind == AudioKind::Hda)
        {
            DecodeHdaCaps(g_acs[i]);
            // Bring up the first HDA controller's CORB / RIRB rings
            // and probe codec vendor IDs. Subsequent HDA controllers
            // (extremely rare on consumer hardware) are logged but
            // not brought up — see HdaState comment.
            if (!g_hda.brought_up)
            {
                auto r = HdaBringUp(g_acs[i]);
                if (!r.has_value())
                    core::LogWithValue(core::LogLevel::Warn, "drivers/audio", "HdaBringUp failed",
                                       static_cast<u64>(r.error()));
            }
        }
    }
    if (g_ac_count == 0)
    {
        core::Log(core::LogLevel::Warn, "drivers/audio", "no PCI audio controllers found (QEMU default q35 is silent)");
    }
}

::duetos::core::Result<void> AudioShutdown()
{
    KLOG_TRACE_SCOPE("drivers/audio", "AudioShutdown");
    HdaTeardown();
    const u64 dropped = g_ac_count;
    g_ac_count = 0;
    g_init_done = false;
    arch::SerialWrite("[drivers/audio] shutdown: dropped ");
    arch::SerialWriteHex(dropped);
    arch::SerialWrite(" controller records (MMIO mappings retained)\n");
    return {};
}

u64 AudioControllerCount()
{
    return g_ac_count;
}

const AudioControllerInfo& AudioController(u64 index)
{
    KASSERT_WITH_VALUE(index < g_ac_count, "drivers/audio", "AudioController index out of range", index);
    return g_acs[index];
}

} // namespace duetos::drivers::audio
