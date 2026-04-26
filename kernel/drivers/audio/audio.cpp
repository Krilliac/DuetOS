#include "drivers/audio/audio.h"

#include "arch/x86_64/serial.h"
#include "log/klog.h"
#include "core/panic.h"
#include "mm/paging.h"
#include "drivers/pci/pci.h"

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

constexpr u32 kHdaGctlCrst = 1u << 0;

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
            DecodeHdaCaps(g_acs[i]);
    }
    if (g_ac_count == 0)
    {
        core::Log(core::LogLevel::Warn, "drivers/audio", "no PCI audio controllers found (QEMU default q35 is silent)");
    }
}

::duetos::core::Result<void> AudioShutdown()
{
    KLOG_TRACE_SCOPE("drivers/audio", "AudioShutdown");
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
