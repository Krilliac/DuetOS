#pragma once

#include "util/types.h"

/*
 * DuetOS — AMD Platform Security Processor (PSP) probe, v0.
 *
 * The PSP is an ARM Cortex-A5 (Zen 1/2) or Cortex-A8 (Zen 3+)
 * core embedded in the AMD SoC. It runs AMD's own firmware,
 * brings up the rest of the SoC before the x86 cores execute
 * their first instruction, and owns SEV (Secure Encrypted
 * Virtualization), fTPM, and Platform Security Boot signing.
 * Like Intel ME, it cannot be turned off by the host OS — its
 * power, clock and lifetime are owned by the platform vendor.
 *
 * The PSP exposes a small set of host-visible interfaces on
 * the PCIe root complex, all under vendor ID 0x1022 (AMD):
 *
 *   - The Cryptographic Co-Processor (CCP) / PSP mailbox
 *     device. This is the mailbox the host driver uses to send
 *     PSP commands (e.g. for SEV launch / measurement). The
 *     well-known device-ID family per generation:
 *       0x1456 — Zen 1 / Zen+ Ryzen (Naples, Pinnacle)
 *       0x1486 — Zen 2 Ryzen (Matisse, Castle Peak)
 *       0x15DF — Zen / Zen+ APU (Raven Ridge)
 *       0x1468 — Zen 2 APU (Renoir / Lucienne)
 *       0x1649 — Zen 3 (Cezanne)
 *       0x14CA — Zen 4 Ryzen / EPYC
 *
 *   - The System Management Unit (SMU) on some platforms also
 *     exposes a host-visible mailbox (0x1537 family on EPYC).
 *     We list it under a sibling enum value because it is a
 *     separate management surface even though it lives in the
 *     same chiplet as the PSP.
 *
 * v0 scope (mirrors drivers/mei/mei.h):
 *   - PCI probe for vendor 0x1022 + a curated device-ID set.
 *     We do NOT match by class code: the PSP CCP advertises
 *     class 0x10 (encryption / decryption), but so do dozens
 *     of unrelated crypto accelerators — vendor + explicit
 *     device-ID list is the lowest-false-positive filter.
 *   - Map BAR0 once so the existence of the register file is
 *     pinned and so any subsequent code path attempting to
 *     re-map it goes through the me_psp_guard deny-list.
 *   - Inventory accessor + boot-log line per device + role tag
 *     ("psp-ccp" / "amd-smu").
 *   - Register every detected device with `security::MePspGuard`
 *     so the kernel-wide MMIO fence covers them.
 *
 * Out of scope (deferred):
 *   - PSP mailbox protocol (CCP commands, SEV interface). We
 *     deliberately do NOT implement these — adding a host-side
 *     SEV driver would re-introduce the very attack surface
 *     the guard is here to remove.
 *   - SMU command interface.
 *   - fTPM disable / replacement. AMD fuses are platform-final.
 *
 * Threading: kernel context only. Probe runs once at boot.
 *
 * Subsystem isolation: freestanding kernel driver. No subsystem
 * (Win32 / Linux ABI) reaches it directly.
 */

namespace duetos::drivers::psp
{

inline constexpr u16 kVendorAmd = 0x1022;
inline constexpr u32 kMaxPspDevices = 4;

enum class PspRole : u8
{
    Unknown = 0,
    Ccp, // PSP / CCP mailbox — the host's PSP control surface
    Smu, // System Management Unit mailbox
};

struct PspDeviceInfo
{
    bool live;
    u16 vendor_id;
    u16 device_id;
    u8 bus;
    u8 device;
    u8 function;
    PspRole role;
    const char* role_tag;
    u64 mmio_phys;
    u64 mmio_size;
    void* mmio_virt;
};

/// Walk the PCI cache, detect AMD PSP / SMU mailbox devices,
/// map each one's primary BAR once, and register them with
/// `security::MePspGuard` so further MMIO mapping is denied.
/// Idempotent — early-returns after the first call.
void PspInit();

/// Number of PSP / SMU devices found.
u32 PspDeviceCount();

/// Accessor for a PSP record. Panics on out-of-range index.
const PspDeviceInfo& PspDevice(u32 index);

/// Map an AMD device-ID to a coarse role tag. Returns
/// PspRole::Unknown for IDs we don't recognise — callers
/// should NOT register Unknown devices (the curated probe
/// already drops them).
PspRole PspClassifyDeviceId(u16 device_id);

/// Short string for a PspRole.
const char* PspRoleTag(PspRole r);

/// Boot self-test. Asserts the classification table is wired
/// up; emits `[psp] selftest pass/fail` and panics on failure.
void PspSelfTest();

} // namespace duetos::drivers::psp
