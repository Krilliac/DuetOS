#pragma once

// Early boot bring-up extracted from kernel_main (core/main.cpp),
// which was well over the project size guideline. This is the
// straight-line, side-effecting prologue: serial/klog online,
// build banner, CPU/hypervisor/SMBIOS/thermal probe, utility
// self-tests, KASLR seed, GDT/IDT/TSS/syscall gate, extable +
// fault-domain registry, driver-domain registrations, and the
// Multiboot2 memory-map parse + FrameAllocator init.
//
// Pure code motion: the block crosses no kernel_main locals — its
// only inputs are the two Multiboot2 handoff parameters and every
// effect lands on global/subsystem state. kernel_main calls this
// at the exact point the block used to run.

#include "util/types.h"

namespace duetos::core
{

void BootBringupEarly(duetos::u32 multiboot_magic, duetos::uptr multiboot_info);

// Memory + paging + debug-subsystem bring-up: FrameAllocator /
// Heap / Paging phase self-tests, KernelHeapInit, RunInitArray,
// PagingInit, ProtectKernelImage, BpInit, ProbeInit,
// FixJournalInit. No inputs, no outputs — pure code motion.
void BootBringupMemPaging();

// Kernel-services bring-up: VFS/ramfs, ACPI + AML namespace,
// APIC/IOAPIC/HPET, clocksource/timekeeper/tick, RTC + wall
// clock, per-CPU BSP + topology, LBR, syscall-cap gate, Linux-ABI
// syscall MSRs, sync-primitive + lockdep self-tests, periodic
// timer + NMI watchdog, scheduler init + idle/reaper, and the
// IPC/KObject/Win32/Linux-fd/soft-lockup self-tests. Inputs are
// the boot cmdline string (init-wedge-panic parse) and the
// Multiboot2 info pointer (AcpiInit); pure code motion otherwise.
void BootBringupKernelServices(const char* cmdline, duetos::uptr multiboot_info);

// Device + late-bring-up: PS/2 kbd/mouse, PCI enumeration,
// VirtIO/MEI, GPU, audio, network + storage stacks, security
// surface, Start-menu app scan, read-only FS shells, the
// bringup-complete metrics checkpoint and the tmpfs log-sink
// sanity check. force_net_smoke is the caller-evaluated
// `netsmoke=force` cmdline match (CmdlineMatches lives in
// main.cpp's anon namespace); pure code motion otherwise.
void BootBringupDevices(bool force_net_smoke);

} // namespace duetos::core
