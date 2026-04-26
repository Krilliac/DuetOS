#pragma once

#include "util/types.h"

/*
 * DuetOS — hypervisor / emulator detection, v0.
 *
 * CPUID leaf 0x00000001 bit ECX[31] — "hypervisor present" — is
 * set by every modern VMM (KVM, QEMU/TCG, VirtualBox, VMware,
 * Hyper-V, Xen) to let guest software choose different code paths
 * without trial-and-error feature probing. Leaf 0x40000000 returns
 * a 12-byte vendor string in EBX:ECX:EDX that identifies WHICH
 * hypervisor we're under.
 *
 * This module caches the result once at boot and exposes:
 *   IsBareMetal()   — true iff leaf 1 ECX[31] is clear
 *   IsEmulator()    — true iff running under a VMM (any VMM)
 *   HypervisorKind()— decoded enum
 *   HypervisorName()— human-friendly string for logs
 *
 * Callers use these to gate code paths that only make sense under
 * a specific emulator (e.g. the Bochs-VBE probe in drivers/gpu/),
 * or to log a breadcrumb that helps triage bug reports from real
 * hardware vs. a hypervisor-only regression.
 *
 * Context: kernel. Probe runs once at boot; every query thereafter
 * is a cached read.
 */

namespace duetos::arch
{

enum class HypervisorKind : u8
{
    None = 0,   // bare metal (CPUID leaf 1 ECX[31] == 0)
    Unknown,    // bit set but vendor string didn't match any known VMM
    Kvm,        // "KVMKVMKVM" (Linux/KVM)
    QemuTcg,    // "TCGTCGTCGTCG" (QEMU without KVM)
    VmwareEsx,  // "VMwareVMware"
    VirtualBox, // "VBoxVBoxVBox"
    HyperV,     // "Microsoft Hv"
    Xen,        // "XenVMMXenVMM"
    Parallels,  // " lrpepyh  vr"
    Acrn,       // "ACRNACRNACRN"
    Bhyve,      // "bhyve bhyve "
    Qnx,        // "QNXQVMBSQG"
};

/// Pretty-print the kind enum. Always returns a static string.
const char* HypervisorName(HypervisorKind k);

/// Run CPUID leaves 1 and 0x40000000. Populate the cache. Safe
/// exactly once at boot; double-init is a KASSERT.
void HypervisorProbe();

/// Snapshot of what the probe found.
struct HypervisorInfo
{
    HypervisorKind kind;
    char vendor[13]; // 12-byte CPUID vendor string + NUL
    u32 max_leaf;    // CPUID leaf 0x40000000's EAX (highest supported HV leaf)
    bool valid;      // false until HypervisorProbe() has run
};

/// Accessor for the cached result.
const HypervisorInfo& HypervisorInfoGet();

/// Convenience predicates (cheap reads).
bool IsBareMetal();
bool IsEmulator();

} // namespace duetos::arch
