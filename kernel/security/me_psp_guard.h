#pragma once

#include "util/types.h"

/*
 * DuetOS — Intel ME / AMD PSP fencing policy, v0.
 *
 * Intel's Management Engine (ME / CSME / TXE / GSC) and AMD's
 * Platform Security Processor (PSP / SMU) are independent
 * coprocessors that run their own firmware on dedicated silicon
 * inside the chipset / SoC. They have full DMA reach into host
 * RAM, their own network paths (Intel AMT uses the integrated
 * Ethernet PHY directly, transparent to the host OS), and they
 * remain powered while the host CPU is in S3 / S5. The host OS
 * cannot turn them off — power, firmware and lifetime are owned
 * by the platform vendor.
 *
 * What the OS CAN do — and what this module enforces — is fence
 * the host-side interfaces the coprocessors expose, so that:
 *
 *   1) No code on this kernel can re-map the MEI / PSP MMIO
 *      register file after the (single, audited) kernel driver
 *      has done its one probe-time map. Userland never sees the
 *      BAR; subsystems (Win32 / Linux ABI) cannot mediate access
 *      to it; a compromised driver elsewhere cannot opportunistically
 *      ioremap the management interface and start whispering at it.
 *
 *   2) The well-known AMT / vPro / IPMI management ports are
 *      dropped at the kernel firewall on every interface, so a
 *      remote operator who reaches the box on TCP/IP cannot
 *      simply connect to AMT's web UI / RAS endpoint over the
 *      same network. (AMT can still receive traffic delivered
 *      to it BELOW the OS — that is the architectural limit of
 *      what an OS-side firewall can do — but the OS-visible
 *      attack surface stops here.)
 *
 *   3) Boot-log evidence + a selftest sentinel record what was
 *      detected, what was fenced, and what was deferred, so an
 *      operator can verify the platform's posture without
 *      trusting a vendor BIOS screen.
 *
 * Out of scope (tracked in wiki/security/ME-PSP-Mitigation.md):
 *   - IOMMU (VT-d / AMD-Vi) DMA fencing. No IOMMU code exists
 *     in the tree yet; once it does, this module grows a
 *     "deny-DMA-from-ME/PSP-BDF" hook.
 *   - HAP (Intel "High Assurance Platform") bit detection. That
 *     bit lives in the ME firmware region on the SPI flash; it
 *     is set with external tools (me_cleaner, flashrom) and the
 *     OS only observes whether the ME completed its bring-up.
 *     We can probe its absence indirectly (HFS register), which
 *     a future slice can add.
 *   - PSP fuses / fTPM disable. AMD's fuses are platform-final
 *     and set by AGESA before the OS ever runs.
 *
 * Threading: kernel context only. Registration happens at boot
 * from the MEI / PSP drivers; queries (IsForbiddenMmio) happen
 * on every MapMmio call thereafter. v0 is single-CPU; the
 * lookup is a linear scan over a tiny static table. SMP-safe
 * once the global is upgraded to a seqlock, which is trivial
 * because writes only happen during single-threaded boot.
 *
 * Subsystem isolation: this is a kernel-internal security
 * module. Win32 / Linux subsystem code never reaches it
 * directly; the gate sits behind `mm::MapMmio`, which itself
 * is a kernel-only API.
 */

namespace duetos::security
{

enum class CoProcessor : u8
{
    None = 0,
    IntelMeCsme, // chipset CSME (laptops / desktops / servers)
    IntelMeGsc,  // discrete-GPU Graphics System Controller
    IntelMeTxe,  // Atom Trusted Execution Engine
    IntelMeSps,  // Server Platform Services (Xeon SP)
    AmdPspCcp,   // AMD Cryptographic Co-Processor / PSP mailbox
    AmdSmu,      // AMD System Management Unit
};

const char* CoProcessorTag(CoProcessor c);

/// One fenced device — registered by the MEI or PSP driver
/// immediately after its own probe-time MMIO map succeeds, so
/// that every subsequent MapMmio attempt at the same physical
/// range is refused.
struct FencedDevice
{
    bool live;
    CoProcessor kind;
    u16 vendor_id;
    u16 device_id;
    u8 bus;
    u8 device;
    u8 function;
    u8 _pad;
    u64 mmio_phys;       // page-aligned base of the BAR
    u64 mmio_size;       // total size in bytes (rounded up to a page)
    bool dma_quarantine; // set by IOMMU when it lands; v0 reads as false
};

inline constexpr u32 kMaxFencedDevices = 8;

/// Reset internal state. Idempotent. Called by `MePspGuardInit`
/// at boot before any registration runs.
void MePspGuardInit();

/// Register a coprocessor host interface as forbidden. Called by
/// the MEI / PSP probes right after their own MapMmio of the
/// register file succeeds. After this call, any subsequent
/// `mm::MapMmio` whose [phys, phys+bytes) overlaps the registered
/// range will return nullptr and emit a KLOG_WARN sentinel.
/// Returns the index of the new slot, or `kMaxFencedDevices` if
/// the table is full (which is itself logged as a WARN so the
/// limit can be lifted before it bites silently).
u32 MePspGuardRegister(const FencedDevice& dev);

/// Number of currently-fenced devices.
u32 MePspGuardCount();

/// Accessor — for shell / diagnostic output. Panics on
/// out-of-range index.
const FencedDevice& MePspGuardDevice(u32 index);

/// Return true if the half-open physical range [phys, phys+bytes)
/// overlaps any registered fenced device's BAR. Cheap (linear
/// scan over kMaxFencedDevices). Safe from any kernel context
/// including the panic / trap path.
bool MePspGuardIsForbiddenMmio(u64 phys, u64 bytes);

/// Install AMT / vPro / IPMI port blocks into the kernel
/// firewall. Idempotent — safe to call more than once; duplicate
/// rules are detected and skipped. Returns the number of rules
/// newly installed (0 means "already in place"). Called from
/// `MePspGuardActivate` after the firewall is online.
u32 MePspGuardInstallNetworkBlocks();

/// Final activation step. Called from boot bringup AFTER both
/// `MeiInit` and `PspInit` have registered their devices.
/// Installs the network blocks, emits the boot-log summary
/// line, and primes counters used by the selftest. Idempotent.
void MePspGuardActivate();

/// Number of `MapMmio` calls that were refused because they
/// overlapped a fenced range. Resets to 0 only by `MePspGuardInit`.
u64 MePspGuardRefusalCount();

/// Boot self-test. Asserts:
///   - Tag lookup is wired up for every CoProcessor enumerator.
///   - The forbidden-range check correctly accepts a benign
///     phys range, rejects an overlapping one, and rejects an
///     adjacent-but-non-overlapping range only when it should.
///   - The refusal counter increments on a denied call.
/// Emits `[me-psp-selftest] PASS/FAIL` via the serial port so
/// it shows up in the boot log unconditionally; panics on FAIL.
void MePspGuardSelfTest();

} // namespace duetos::security
