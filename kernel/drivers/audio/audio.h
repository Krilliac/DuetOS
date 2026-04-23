#pragma once

#include "../../core/result.h"
#include "../../core/types.h"

/*
 * CustomOS — Audio driver shell, v0.
 *
 * Discovery + classification for PCI audio controllers. Walks the
 * `pci::Device` cache for class 0x04 (multimedia controller) and
 * classifies each by subclass:
 *
 *   0x00  Legacy audio device (Sound Blaster-era)
 *   0x01  AC'97 — pre-2004 codec standard
 *   0x03  HDA   — Intel High Definition Audio (every post-2005 PC)
 *   0x80  Other multimedia
 *
 * Scope (v0):
 *   - Discovery + BAR map. No codec init, no DMA setup, no playback.
 *   - The audio server subsystem (subsystems/audio/) is a separate
 *     track entirely — this shell exposes the hardware presence so
 *     that future work doesn't have to re-enumerate.
 *
 * Context: kernel. `AudioInit` runs once at boot after
 * `PciEnumerate`.
 */

namespace customos::drivers::audio
{

inline constexpr u8 kPciClassMultimedia = 0x04;
inline constexpr u8 kPciSubclassLegacyAudio = 0x00;
inline constexpr u8 kPciSubclassAc97 = 0x01;
inline constexpr u8 kPciSubclassHda = 0x03;
inline constexpr u8 kPciSubclassOther = 0x80;

inline constexpr u64 kMaxAudioControllers = 4;

enum class AudioKind : u8
{
    Unknown = 0,
    Legacy,
    Ac97,
    Hda,
    Other,
};

const char* AudioKindName(AudioKind k);

struct AudioControllerInfo
{
    u16 vendor_id;
    u16 device_id;
    u8 bus;
    u8 device;
    u8 function;
    u8 subclass;
    AudioKind kind;
    u64 mmio_phys;
    u64 mmio_size;
    void* mmio_virt;
};

/// Walk PCI, register each audio controller, log the result.
/// Idempotent — early-returns until `AudioShutdown` clears the
/// live flag.
void AudioInit();

/// Drop every controller record + clear the live flag so the next
/// `AudioInit` re-walks PCI. Always succeeds. MMIO mappings are
/// retained (same v0 trade-off as drivers/net).
::customos::core::Result<void> AudioShutdown();

u64 AudioControllerCount();
const AudioControllerInfo& AudioController(u64 index);

} // namespace customos::drivers::audio
