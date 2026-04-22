#include "audio.h"

#include "../../arch/x86_64/serial.h"
#include "../../core/klog.h"
#include "../../core/panic.h"
#include "../../mm/paging.h"
#include "../pci/pci.h"

namespace customos::drivers::audio
{

namespace
{

AudioControllerInfo g_acs[kMaxAudioControllers] = {};
u64 g_ac_count = 0;

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
//   GCAP   u16 at 0x00 — OSS/ISS/BSS counts, 64-bit addressing
//   VMIN   u8  at 0x02 — minor version (typically 0x00)
//   VMAJ   u8  at 0x03 — major version (typically 0x01)
//   OUTPAY u16 at 0x04 — output payload capability (stream size)
//   INPAY  u16 at 0x06 — input payload capability
//   GCTL   u32 at 0x08 — global control (bit 0 = CRST, controller reset)
u16 Mmio16(const AudioControllerInfo& a, u64 offset)
{
    if (a.mmio_virt == nullptr)
        return 0;
    auto* p = reinterpret_cast<volatile u16*>(static_cast<u8*>(a.mmio_virt) + offset);
    return *p;
}
u8 Mmio8(const AudioControllerInfo& a, u64 offset)
{
    if (a.mmio_virt == nullptr)
        return 0;
    auto* p = reinterpret_cast<volatile u8*>(static_cast<u8*>(a.mmio_virt) + offset);
    return *p;
}

void DecodeHdaCaps(const AudioControllerInfo& a)
{
    if (a.mmio_virt == nullptr)
        return;
    const u16 gcap = Mmio16(a, 0x00);
    const u8 vmin = Mmio8(a, 0x02);
    const u8 vmaj = Mmio8(a, 0x03);
    const u16 outpay = Mmio16(a, 0x04);
    const u16 inpay = Mmio16(a, 0x06);
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
    static constinit bool s_done = false;
    KASSERT(!s_done, "drivers/audio", "AudioInit called twice");
    s_done = true;

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

u64 AudioControllerCount()
{
    return g_ac_count;
}

const AudioControllerInfo& AudioController(u64 index)
{
    KASSERT_WITH_VALUE(index < g_ac_count, "drivers/audio", "AudioController index out of range", index);
    return g_acs[index];
}

} // namespace customos::drivers::audio
