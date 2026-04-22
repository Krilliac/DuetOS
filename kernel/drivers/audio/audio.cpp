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
